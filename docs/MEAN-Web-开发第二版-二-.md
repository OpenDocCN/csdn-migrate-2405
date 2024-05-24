# MEAN Web 开发第二版（二）

> 原文：[`zh.annas-archive.org/md5/F817AFC272941F1219C1F4494127A431`](https://zh.annas-archive.org/md5/F817AFC272941F1219C1F4494127A431)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：MongoDB 简介

MongoDB 是一种令人兴奋的新型数据库。作为 NoSQL 运动的领导者，它正在成为世界上最有用的数据库解决方案之一。Mongo 的高吞吐量、独特的 BSON 数据模型和易于扩展的架构为 Web 开发人员提供了更好的工具来存储他们的持久数据。从关系型数据库转移到 NoSQL 解决方案可能是一个令人不知所措的任务，但通过了解 MongoDB 的设计目标可以轻松简化。在本章中，我们将涵盖以下主题：

+   了解 NoSQL 运动和 MongoDB 设计目标

+   MongoDB BSON 数据结构

+   MongoDB 集合和文档

+   MongoDB 查询语言

+   使用 MongoDB shell

# NoSQL 简介

在过去的几年里，Web 应用程序开发通常需要使用关系型数据库来存储持久数据。大多数开发人员已经非常习惯使用众多的 SQL 解决方案之一。因此，使用成熟的关系数据库存储规范化数据模型的方法成为了标准。对象关系映射器开始出现，为开发人员提供了适当的解决方案，以从其应用程序的不同部分整理数据。但随着 Web 的不断扩大，越来越多的开发人员面临更多的扩展问题。为了解决这个问题，社区创建了各种键值存储解决方案，旨在提供更好的可用性、简单的查询和水平扩展。这种新型数据存储变得越来越健壮，提供了许多关系数据库的功能。在这一演变过程中，出现了不同的存储设计模式，包括键值存储、列存储、对象存储和最流行的文档存储。

在常见的关系数据库中，您的数据存储在不同的表中，通常使用主键到外键的关系连接。您的程序将稍后使用各种 SQL 语句重新构建模型，以将数据排列成某种层次化对象表示。文档型数据库处理数据的方式不同。它们不使用表，而是以标准格式（如 JSON 和 XML）存储分层文档。

为了更好地理解这一点，让我们看一个典型博客文章的例子。要使用 SQL 解决方案构建此博客文章模型，您可能至少需要使用两个表。第一个表包含帖子信息，而第二个表包含帖子评论。下图显示了一个示例表结构：

![NoSQL 简介](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mean-webdev-2e/img/B05071_04_01.jpg)

在您的应用程序中，您将使用对象关系映射库或直接 SQL 语句来选择博客文章记录和帖子评论记录，以创建您的博客文章对象。然而，在基于文档的数据库中，博客文章将完全存储为单个文档，以后可以进行查询。例如，在一个以 JSON 格式存储文档的数据库中，您的博客文章文档可能看起来像以下代码片段：

```js
{
  "title": "First Blog Post",
  "comments": [{
    "title": "First Comment"
  }, {
    "title": "Second Comment"
  }]
}
```

这表明了文档型数据库和关系型数据库之间的主要区别。因此，在使用关系型数据库时，您的数据存储在不同的表中，您的应用程序使用表记录组装对象。将数据存储为整体文档将允许更快的读取操作，因为您的应用程序不必在每次读取时重新构建对象。此外，面向文档的数据库还有其他优势。

在开发应用程序时，您经常会遇到另一个问题：模型更改。假设您想要为每篇博客文章添加一个新属性。因此，您可以更改您的帖子表，然后转到应用程序数据层，并将该属性添加到您的博客文章对象中。由于您的应用程序已经包含了几篇博客文章，所有现有的博客文章对象也将发生变化，这意味着您必须在代码中添加额外的验证过程。然而，基于文档的数据库通常是无模式的，这意味着您可以在单个对象集合中存储不同的对象，而无需更改数据库中的任何内容。尽管这对一些有经验的开发人员来说可能听起来像是在寻求麻烦，但无模式存储的自由具有几个优点。

例如，想象一个销售二手家具的电子商务应用程序。在您的“产品”表中，椅子和壁橱可能具有一些共同的特征，比如木材的类型，但客户可能还对壁橱有多少个门感兴趣。将壁橱和椅子对象存储在同一个表中意味着它们可以存储在具有大量空列的表中，或者使用更实用的实体-属性-值模式，其中另一个表用于存储键-值属性。然而，使用无模式存储将允许您在同一集合中为不同的对象定义不同的属性，同时仍然可以使用常见属性查询该集合，比如木材类型。这意味着您的应用程序，而不是数据库，将负责强制执行数据结构，这可以帮助您加快开发过程。

虽然有许多 NoSQL 解决方案解决各种开发问题，通常围绕缓存和规模，但面向文档的数据库正在迅速成为该运动的领导者。文档导向数据库的易用性，以及其独立的持久存储功能，甚至威胁着在某些用例中取代传统的 SQL 解决方案。尽管有一些文档导向数据库，但没有一个像 MongoDB 那样受欢迎。

# 介绍 MongoDB

回到 2007 年，Dwight Merriman 和 Eliot Horowitz 成立了一家名为 10gen 的公司，以创建一个更好的平台来托管 Web 应用程序。他们的想法是创建一个作为服务的托管平台，让开发人员专注于构建他们的应用程序，而不是处理硬件管理和基础设施扩展。很快，他们发现社区不愿意放弃对他们应用程序基础设施的控制。因此，他们将平台的不同部分作为开源项目发布。

有一个这样的项目是一个名为 MongoDB 的基于文档的数据库解决方案。MongoDB 源自于“巨大”的单词，能够支持复杂的数据存储，同时保持其他 NoSQL 存储的高性能方法。社区欣然接受了这种新的范式，使 MongoDB 成为世界上增长最快的数据库之一。拥有 150 多名贡献者和超过 10,000 次提交，它也成为最受欢迎的开源项目之一。

MongoDB 的主要目标是创建一种新类型的数据库，将关系数据库的健壮性与分布式键值数据存储的快速吞吐量相结合。考虑到可扩展的平台，它必须支持简单的水平扩展，同时保持传统数据库的耐久性。另一个关键的设计目标是支持 Web 应用程序开发，以标准 JSON 输出的形式。这两个设计目标最终成为 MongoDB 相对于其他解决方案的最大优势，因为这些与 Web 开发中的其他趋势完美契合，比如几乎无处不在的云虚拟化托管的使用或向水平而不是垂直扩展的转变。

最初被认为是更可行的关系数据库上的另一个 NoSQL 存储层，MongoDB 发展到远远超出了它诞生的平台。它的生态系统发展到支持大多数流行的编程平台，拥有各种社区支持的驱动程序。除此之外，还形成了许多其他工具，包括不同的 MongoDB 客户端、性能分析和优化工具、管理和维护实用程序，以及一些风险投资支持的托管服务。甚至一些大公司，如 eBay 和纽约时报，开始在其生产环境中使用 MongoDB 数据存储。要了解为什么开发人员更喜欢 MongoDB，现在是时候深入了解它的一些关键特性了。

# MongoDB 的关键特性

MongoDB 有一些关键特性，帮助它变得如此受欢迎。正如我们之前提到的，目标是在传统数据库功能和 NoSQL 存储的高性能之间创建一种新的品种。因此，它的大多数关键特性都是为了超越其他 NoSQL 解决方案的限制，同时整合一些关系数据库的能力而创建的。在本节中，您将了解为什么在处理现代 Web 应用程序开发时，MongoDB 可以成为您首选的数据库。

## BSON 格式

MongoDB 最伟大的特性之一是其类似 JSON 的存储格式，名为 BSON。BSON 代表**二进制 JSON**，BSON 格式是 JSON 样式文档的二进制编码序列化，旨在在大小和速度上更高效，从而实现 MongoDB 的高读/写吞吐量。

与 JSON 一样，BSON 文档是对象和数组的简单数据结构表示，采用键值格式。文档由一系列元素组成，每个元素都有一个字符串类型的字段名和一个类型化的字段值。这些文档支持所有 JSON 特定的数据类型以及其他数据类型，例如`Date`类型。

BSON 格式的另一个重要优势是使用`_id`字段作为主键。`_id`字段值通常是一个名为`ObjectId`的唯一标识符类型，它可以由应用程序驱动程序或 mongod 服务生成。如果驱动程序未能提供带有唯一`ObjectId`的`_id`字段，mongod 服务将自动添加它，使用以下方式：

+   一个表示自 Unix 纪元以来的秒数的 4 字节值

+   一个 3 字节的机器标识符

+   一个 2 字节的进程 ID

+   一个 3 字节的计数器，从一个随机值开始

因此，上一个示例中的博客文章对象的 BSON 表示将如下代码片段所示：

```js
{
  "_id": ObjectId("52d02240e4b01d67d71ad577"),
  "title": "First Blog Post",
  "comments": [
  ...
  ]
}
```

BSON 格式使 MongoDB 能够在内部索引和映射文档属性，甚至嵌套文档，从而能够高效地扫描集合，并且更重要的是，能够将对象与复杂的查询表达式匹配。

## MongoDB 的特点

MongoDB 的另一个设计目标是扩展普通键值存储的能力。常见键值存储的主要问题是其有限的查询能力，这通常意味着您的数据只能使用键字段进行查询，而更复杂的查询大多是预定义的。为了解决这个问题，MongoDB 从关系数据库动态查询语言中汲取了灵感。

支持即席查询意味着数据库将立即响应动态结构化的查询，无需预定义每个查询。它能够通过索引 BSON 文档并使用独特的查询语言来实现这一点。让我们看一下以下 SQL 语句示例：

```js
SELECT * FROM Posts WHERE Title LIKE '%mongo%';

```

这个简单的语句是在要求数据库返回所有标题中包含单词`mongo`的帖子记录。在 MongoDB 中复制这个查询将如下所示：

```js
db.posts.find({ title:/mongo/ });

```

在 MongoDB shell 中运行此命令将返回所有`title`字段包含单词`mongo`的帖子。您将在本章后面学习更多关于 MongoDB 查询语言的内容，但现在重要的是要记住它几乎与传统的关系型数据库一样可查询。MongoDB 查询语言很棒，但它引发了一个问题，即当数据库变得更大时，这些查询运行效率如何。像关系型数据库一样，MongoDB 使用称为索引的机制来解决这个问题。

## MongoDB 索引

索引是一种独特的数据结构，使数据库引擎能够高效解析查询。当查询发送到数据库时，它将不得不扫描整个文档集合，以找到与查询语句匹配的文档。这种方式，数据库引擎处理了大量不必要的数据，导致性能不佳。

为了加快扫描速度，数据库引擎可以使用预定义的索引，它映射文档字段，并告诉引擎哪些文档与此查询语句兼容。为了理解索引的工作原理，我们假设我们想检索所有具有超过 10 条评论的帖子。在这种情况下，我们的文档定义如下：

```js
{
  "_id": ObjectId("52d02240e4b01d67d71ad577"),
  "title": "First Blog Post",
  "comments": [
  …
  ],
  "commentsCount": 12
}
```

因此，一个请求超过 10 条评论的文档的 MongoDB 查询将如下所示：

```js
db.posts.find({ commentsCount: { $gt: 10 } });

```

要执行此查询，MongoDB 必须遍历所有帖子，并检查帖子是否具有大于`10`的`commentCount`属性。然而，如果定义了`commentCount`索引，那么 MongoDB 只需检查哪些文档具有大于`10`的`commentCount`属性，然后检索这些文档。以下图表说明了`commentCount`索引的工作原理：

![MongoDB 索引](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mean-webdev-2e/img/B05071_04_02.jpg)

使用`commentsCount`索引检索具有超过`10`条评论的文档

## MongoDB 副本集

为了提供数据冗余和改善可用性，MongoDB 使用一种称为**副本集**的架构。数据库的复制有助于保护数据，以便从硬件故障中恢复并增加读取容量。副本集是一组承载相同数据集的 MongoDB 服务。一个服务被用作主服务，其他服务被称为次服务。所有的实例都支持读操作，但只有主实例负责写操作。当发生写操作时，主实例会通知次实例进行更改，并确保它们已将更改应用到其数据集的复制中。以下图表说明了一个常见的副本集：

![MongoDB 副本集](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mean-webdev-2e/img/B05071_04_03.jpg)

具有一个主和两个次的副本集的工作流程

MongoDB 副本集的另一个强大功能是其自动故障转移。当副本集的一个成员无法在 10 秒内到达主实例时，副本集将自动选举并提升一个次实例为新的主实例。旧的主实例恢复在线后，它将作为次实例重新加入副本集。

副本集的另一个特性是能够添加仲裁节点。仲裁者不维护任何数据；它们的主要目的是在副本集中维护法定人数。这意味着它们参与选举新的主要过程，但不能作为次要功能或被选为主要功能。简而言之，仲裁者有助于以比常规数据节点更低的资源成本在副本集中提供一致性。以下图表说明了一个带有仲裁者的常见副本集：

![MongoDB 副本集](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mean-webdev-2e/img/B05071_04_04.jpg)

具有主、次和仲裁者的副本集的工作流程

MongoDB 的复制是一个非常强大的功能，直接源自其平台起源，是使 MongoDB 达到生产就绪状态的主要功能之一。然而，这并不是唯一的功能。

### 注意

要了解更多关于 MongoDB 副本集的信息，请访问[`docs.mongodb.org/manual/replication/`](http://docs.mongodb.org/manual/replication/)。

## MongoDB 分片

随着 Web 应用程序的增长，扩展性是一个常见的问题。解决这个问题的各种方法可以分为两组：垂直扩展和水平扩展。两者之间的区别在下图中有所说明：

![MongoDB 分片](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mean-webdev-2e/img/B05071_04_05.jpg)

单台机器的垂直扩展与多台机器的水平扩展

垂直扩展更容易，包括增加单台机器的资源，如 RAM 和 CPU。然而，它有两个主要缺点：首先，在某个水平上，增加单台机器的资源相对于在几台较小的机器之间分配负载变得更加昂贵。其次，流行的云托管提供商限制了您可以使用的机器实例的大小。因此，垂直扩展应用程序只能在一定水平上进行。

水平扩展更加复杂，需要使用多台机器。每台机器将处理一部分负载，提供更好的整体性能。水平数据库扩展的问题在于如何正确地在不同的机器之间分配数据，以及如何管理它们之间的读/写操作。

幸运的是，MongoDB 支持水平扩展，它称之为分片。*分片是将数据分割到不同的机器或分片的过程*。每个分片保存一部分数据，并作为一个独立的数据库。几个分片的集合形成了一个单一的逻辑数据库。操作是通过称为查询路由器的服务执行的，它们询问配置服务器如何将每个操作委派给正确的分片。

### 注意

要了解更多关于 MongoDB 分片的信息，请访问[`docs.mongodb.org/manual/sharding/`](http://docs.mongodb.org/manual/sharding/)。

## MongoDB 3.0

2015 年初，MongoDB 团队推出了 MongoDB 数据库的第三个主要版本。最重要的是，这个版本标志着 MongoDB 正在向成为更大更复杂的生产环境的领先数据库解决方案迈进。或者，正如团队所描述的那样，使 MongoDB 成为每个组织的“默认数据库”。为了实现这一目标，团队提出了几个新功能：

+   **存储 API**：在这个版本中，存储引擎层与更高级别的操作解耦。这意味着组织现在可以根据其应用程序需求选择使用哪种存储引擎，从而获得高达 10 倍的性能提升。

+   **增强的查询引擎内省**：这使得数据库管理员能够更好地分析关键查询，确保性能得到优化。

+   **更好的身份验证和审计**：这使得大型组织能够更安全地管理他们的 MongoDB 实例。

+   **更好的日志记录**：更复杂的日志记录功能使开发人员能够更好地跟踪 MongoDB 的操作。

这些功能和许多其他功能使 MongoDB 如此受欢迎。尽管有许多良好的替代方案，但 MongoDB 在开发人员中变得越来越普遍，并且正在成为世界领先的数据库解决方案之一。让我们深入了解如何轻松开始使用 MongoDB。

# MongoDB shell

如果您遵循了第一章, *MEAN 简介*，您应该在本地环境中拥有一个可用的 MongoDB 实例。要与 MongoDB 交互，您将使用 MongoDB shell，这是您在第一章中遇到的。MongoDB shell 是一个命令行工具，它使用 JavaScript 语法查询语言来执行不同的操作。

为了探索 MongoDB 的不同部分，让我们通过运行`mongo`可执行文件来启动 MongoDB shell，如下所示：

```js
$ mongo

```

如果 MongoDB 已正确安装，您应该看到类似于以下截图所示的输出：

![MongoDB shell](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mean-webdev-2e/img/B05071_04_06.jpg)

注意 shell 如何告诉您当前的 shell 版本，并且它已连接到默认的测试数据库。

# MongoDB 数据库

每个 MongoDB 服务器实例可以存储多个数据库。除非特别定义，否则 MongoDB shell 将自动连接到默认的测试数据库。通过执行以下命令切换到另一个名为 mean 的数据库：

```js
> use mean

```

您将看到一个命令行输出，告诉您 shell 已切换到 mean 数据库。请注意，您无需在使用数据库之前创建数据库，因为在 MongoDB 中，当您插入第一个文档时，数据库和集合会懒惰地创建。这种行为与 MongoDB 对数据的动态方法一致。使用特定数据库的另一种方法是以数据库名称作为参数运行 shell 可执行文件，如下所示：

```js
$ mongo mean

```

shell 将自动连接到 mean 数据库。如果您想列出当前 MongoDB 服务器中的所有其他数据库，只需执行以下命令：

```js
> show dbs

```

这将显示当前可用的至少存储了一个文档的数据库列表。

# MongoDB 集合

MongoDB 集合是 MongoDB 文档的列表，相当于关系数据库表。当插入其第一个文档时，将创建一个集合。与表不同，集合不强制执行任何类型的模式，并且可以托管不同结构的文档。

要在 MongoDB 集合上执行操作，您需要使用集合方法。让我们创建一个名为 posts 的集合并插入第一篇文章。为了做到这一点，在 MongoDB shell 中执行以下命令：

```js
> db.posts.insert({"title":"First Post", "user": "bob"})

```

执行上述命令后，它将自动创建 posts 集合并插入第一个文档。要检索集合文档，请在 MongoDB shell 中执行以下命令：

```js
> db.posts.find()

```

您应该看到类似于以下截图所示的命令行输出：

![MongoDB 集合](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mean-webdev-2e/img/B05071_04_07.jpg)

这意味着您已成功创建了 posts 集合并插入了第一个文档。

要显示所有可用的集合，请在 MongoDB shell 中发出以下命令：

```js
> show collections

```

MongoDB shell 将输出可用集合的列表，您的情况下是 posts 集合和另一个名为 system.indexes 的集合，它保存了数据库索引的列表。

如果您想删除 posts 集合，您需要执行 drop()命令，如下所示：

```js
> db.posts.drop()

```

shell 将通过输出 true 来通知您该集合已被删除。

# MongoDB CRUD 操作

**创建-读取-更新-删除**（CRUD）操作是您与数据库执行的基本交互。为了对数据库实体执行 CRUD 操作，MongoDB 提供了各种集合方法。

## 创建新文档

您已经熟悉使用 insert()方法创建新文档的基本方法，就像您之前在早期示例中所做的那样。除了 insert()方法，还有两种方法叫做 update()和 save()来创建新对象。

### 使用 insert()创建文档

创建新文档的最常见方法是使用 insert()方法。insert()方法接受一个表示新文档的单个参数。要插入新的文章，只需在 MongoDB shell 中发出以下命令：

```js
> db.posts.insert({"title":"Second Post", "user": "alice"})

```

### 使用 update()创建文档

update()方法通常用于更新现有文档。您还可以使用 upsert 标志来创建新文档，如果没有文档与查询条件匹配：

```js
> db.posts.update({
 "user": "alice"
}, {
 "title": "Second Post",
 "user": "alice"
}, {
 upsert: true
})

```

在前面的例子中，MongoDB 将查找由`alice`创建的帖子并尝试更新它。考虑到`posts`集合没有由`alice`创建的帖子，以及您已经使用了`upsert`标志，MongoDB 将找不到适当的文档进行更新，而是创建一个新文档。

### 使用 save()创建文档

创建新文档的另一种方法是调用`save()`方法，传递一个没有`_id`字段或在集合中不存在的`_id`字段的文档：

```js
> db.posts.save({"title":"Second Post", "user": "alice"})

```

这将产生与`update()`方法相同的效果，并将创建一个新文档而不是更新现有文档。

## 阅读文档

`find()`方法用于从 MongoDB 集合中检索文档列表。使用`find()`方法，您可以请求集合中的所有文档，或使用查询检索特定文档。

### 查找所有集合文档

要检索`posts`集合中的所有文档，应该将空查询传递给`find()`方法，或者根本不传递任何参数。以下查询将检索`posts`集合中的所有文档：

```js
> db.posts.find()

```

此外，也可以使用以下查询执行相同的操作：

```js
> db.posts.find({})

```

这两个查询基本上是相同的，将返回`posts`集合中的所有文档。

### 使用相等语句

要检索特定文档，可以使用相等条件查询，该查询将抓取符合该条件的所有文档。例如，要检索由`alice`创建的所有帖子，您需要在 shell 中发出以下命令：

```js
> db.posts.find({ "user": "alice" })

```

这将检索具有`user`属性等于`alice`的所有文档。

### 使用查询操作符

使用相等语句可能不够。为了构建更复杂的查询，MongoDB 支持各种查询操作符。使用查询操作符，您可以查找不同类型的条件。例如，要检索由`alice`或`bob`创建的所有帖子，可以使用以下`$in`操作符：

```js
> db.posts.find({ "user": { $in: ["alice", "bob"] } })

```

### 注意

您可以通过访问[`docs.mongodb.org/manual/reference/operator/query/#query-selectors`](http://docs.mongodb.org/manual/reference/operator/query/#query-selectors)了解更多查询操作符。

### 构建 AND/OR 查询

构建查询时，可能需要使用多个条件。就像在 SQL 中一样，您可以使用`AND`/`OR`运算符来构建多条件查询语句。要执行`AND`查询，只需将要检查的属性添加到查询对象中。例如，看一下以下查询：

```js
> db.posts.find({ "user": "alice", "commentsCount": { $gt: 10 }  })

```

它类似于您之前使用的`find()`查询，但添加了另一个条件，验证文档的`commentCount`属性，并且只会抓取由`alice`创建且评论数超过`10`的文档。`OR`查询稍微复杂，因为它涉及`$or`运算符。要更好地理解它，请看上一个例子的另一个版本：

```js
> db.posts.find( { $or: [{ "user": "alice" }, { "user": "bob" }] })

```

与查询操作符示例一样，这个查询也会抓取由`bob`或`alice`创建的所有帖子。

## 更新现有文档

使用 MongoDB，您可以使用`update()`或`save()`方法更新文档。

### 使用 update()更新文档

`update()`方法需要三个参数来更新现有文档。第一个参数是选择条件，指示要更新哪些文档，第二个参数是`update`语句，最后一个参数是`options`对象。例如，在下面的例子中，第一个参数告诉 MongoDB 查找所有由`alice`创建的文档，第二个参数告诉它更新`title`字段，第三个参数强制它在找到的所有文档上执行`update`操作：

```js
> db.posts.update({
 "user": "alice"
}, {
 $set: {
 "title": "Second Post"
 }
}, {
 multi: true
})

```

请注意`multi`属性已添加到`options`对象中。`update()`方法的默认行为是更新单个文档，因此通过设置`multi`属性，您告诉`update()`方法更新符合选择条件的所有文档。

### 使用 save()更新文档

更新现有文档的另一种方法是调用`save()`方法，将包含`_id`字段的文档传递给它。例如，以下命令将更新具有`_id`字段等于`ObjectId("50691737d386d8fadbd6b01d")`的现有文档：

```js
> db.posts.save({
 "_id": ObjectId("50691737d386d8fadbd6b01d"),
 "title": "Second Post",
 "user": "alice"
})

```

重要的是要记住，如果`save()`方法无法找到合适的对象，它将创建一个新对象。

## 删除文档

要删除文档，您需要使用`remove()`方法。`remove()`方法最多可以接受两个参数。第一个是删除条件，第二个是一个布尔参数，指示是否删除多个文档。

### 删除所有文档

要从集合中删除所有文档，您需要调用`remove()`方法，而不需要任何删除条件。例如，要删除所有`posts`文档，您需要执行以下命令：

```js
> db.posts.remove({})

```

请注意，`remove()`方法与`drop()`方法不同，因为它不会删除集合或其索引。要使用不同的索引重建集合，最好使用`drop()`方法。

#### 删除多个文档

要从集合中删除符合条件的多个文档，您需要使用带有删除条件的`remove()`方法。例如，要删除`alice`发布的所有帖子，您需要执行以下命令：

```js
> db.posts.remove({ "user": "alice" })

```

请注意，这将删除`alice`创建的所有文档，因此在使用`remove()`方法时要小心。

#### 删除单个文档

要从集合中删除与条件匹配的单个文档，您需要使用带有删除条件和布尔值的`remove()`方法，指示您只想删除单个文档。例如，要删除`alice`发布的第一篇帖子，您需要执行以下命令：

```js
> db.posts.remove({ "user": "alice" }, true)

```

这将删除由`alice`创建的第一个文档，并且即使它们符合删除条件，也会保留其他文档。

# 摘要

在本章中，您了解了 NoSQL 数据库以及它们在现代 Web 开发中的用途。您还了解了 NoSQL 运动的新兴领导者 MongoDB。您深入了解了使 MongoDB 成为强大解决方案的各种功能，并了解了其基本术语。最后，您一窥了 MongoDB 强大的查询语言以及如何执行所有四个 CRUD 操作。在下一章中，我们将讨论如何使用流行的 Mongoose 模块将 Node.js 和 MongoDB 连接在一起。


# 第五章：Mongoose 简介

Mongoose 是一个强大的 Node.js ODM 模块，为您的 Express 应用程序添加了 MongoDB 支持。它使用模式来对实体进行建模，提供预定义验证以及自定义验证，允许您定义虚拟属性，并使用中间件钩子来拦截操作。Mongoose 的设计目标是弥合 MongoDB 无模式方法与现实世界应用程序开发要求之间的差距。在本章中，您将了解 Mongoose 的以下基本特性：

+   Mongoose 模式和模型

+   模式索引、修饰符和虚拟属性

+   使用模型的方法和执行 CRUD 操作

+   使用预定义和自定义验证器验证您的数据

+   使用中间件拦截模型的方法

# 介绍 Mongoose

Mongoose 是一个 Node.js 模块，为开发人员提供了将对象建模并将其保存为 MongoDB 文档的能力。虽然 MongoDB 是一个无模式的数据库，但在处理 Mongoose 模型时，Mongoose 为您提供了享受严格和宽松模式方法的机会。与任何其他 Node.js 模块一样，在您的应用程序中开始使用它之前，您首先需要安装它。本章中的示例将直接从前几章中的示例继续进行；因此，在本章中，从第三章中复制最终示例，*构建一个 Express Web 应用程序*，然后从那里开始。

## 安装 Mongoose

安装并验证您的 MongoDB 本地实例正在运行后，您将能够使用 Mongoose 模块连接到它。首先，您需要在`node_modules`文件夹中安装 Mongoose，因此将您的`package.json`文件更改为以下代码片段所示的样子：

```js
{
  "name": "MEAN",
  "version": "0.0.5",
  "dependencies": {
    "body-parser": "1.15.2",
    "compression": "1.6.0",
    "ejs": "2.5.2",
    "express": "4.14.0",
    "express-session": "1.14.1",
    "method-override": "2.3.6",
 "mongoose": "4.6.5",
    "morgan": "1.7.0"
}
```

要安装应用程序依赖项，请转到应用程序文件夹，并在命令行工具中发出以下命令：

```js
$ npm install

```

这将在您的`node_modules`文件夹中安装最新版本的 Mongoose。安装过程成功完成后，下一步将是连接到您的 MongoDB 实例。

## 连接到 MongoDB

要连接到 MongoDB，您需要使用 MongoDB 连接 URI。MongoDB 连接 URI 是一个字符串 URL，告诉 MongoDB 驱动程序如何连接到数据库实例。MongoDB URI 通常构造如下：

```js
mongodb://username:password@hostname:port/database

```

由于您正在连接到本地实例，可以跳过用户名和密码，使用以下 URI：

```js
mongodb://localhost/mean-book

```

最简单的方法是直接在您的`config/express.js`配置文件中定义此连接 URI，并使用`mongoose`模块连接到数据库，如下所示：

```js
const uri = 'mongodb://localhost/mean-book';
const db = require('mongoose').connect(uri);
```

但是，由于您正在构建一个真实的应用程序，直接在`config/express.js`文件中保存 URI 是一种不好的做法。存储应用程序变量的正确方法是使用您的环境配置文件。转到您的`config/env/development.js`文件，并将其更改为以下代码片段所示的样子：

```js
module.exports = {
 db: 'mongodb://localhost/mean-book',
  sessionSecret: 'developmentSessionSecret'
};
```

现在在您的`config`文件夹中，创建一个名为`mongoose.js`的新文件，其中包含以下代码片段：

```js
const config = require('./config');
const mongoose = require('mongoose');

module.exports = function() {
 const db = mongoose.connect(config.db);

  return db;
};
```

请注意，您需要`mongoose`模块并使用配置对象的`db`属性连接到 MongoDB 实例。要初始化 Mongoose 配置，请返回到您的`server.js`文件，并将其更改为以下代码片段所示的样子：

```js
process.env.NODE_ENV = process.env.NODE_ENV || 'development';

const configureMongoose = require('./config/mongoose');
const configureExpress = require('./config/express');

const db = configureMongoose();
const app = configureExpress();
app.listen(3000);

module.exports = app;
console.log('Server running at http://localhost:3000/');
```

就是这样；您已经安装了 Mongoose，更新了配置文件，并连接到了 MongoDB 实例。要启动应用程序，请使用命令行工具并导航到应用程序文件夹，执行以下命令：

```js
$ node server

```

您的应用程序应该正在运行并连接到 MongoDB 本地实例。

### 注意

如果您遇到任何问题或出现“错误：无法连接到[localhost:27017]”的输出，请确保您的 MongoDB 实例正常运行。

# 了解 Mongoose 模式

连接到您的 MongoDB 实例是第一步，但 Mongoose 模块的真正魔力在于其定义文档模式的能力。正如您已经知道的，MongoDB 使用集合来存储多个文档，这些文档不需要具有相同的结构。但是，在处理对象时，有时需要文档相似。Mongoose 使用模式对象来定义文档属性列表，每个属性都有自己的类型和约束，以强制执行文档结构。在指定模式之后，您将继续定义一个模型构造函数，用于创建 MongoDB 文档的实例。在本节中，您将学习如何定义用户模式和模型，以及如何使用模型实例来创建、检索和更新用户文档。

## 创建用户模式和模型

要创建您的第一个模式，请转到`app/models`文件夹并创建一个名为`user.server.model.js`的新文件。在此文件中，粘贴以下代码行：

```js
const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const UserSchema = new Schema({
  firstName: String,
  lastName: String,
  email: String,
  username: String,
  password: String
});

mongoose.model('User', UserSchema);
```

在上述代码片段中，您做了两件事：首先，使用`Schema`构造函数定义了您的`UserSchema`对象，然后使用模式实例定义了您的 User 模型。请注意，出于简单起见，我们将密码保存为明文；但是，在实际应用程序中，用户密码应该得到适当的加密。接下来，您将学习如何使用 User 模型在应用程序逻辑层执行 CRUD 操作。

## 注册 User 模型

在您可以开始使用 User 模型之前，您需要在 Mongoose 配置文件中包含`user.server.model.js`文件，以注册 User 模型。为此，请更改您的`config/mongoose.js`文件，使其看起来像以下代码片段中所示：

```js
const config = require('./config');
const mongoose = require('mongoose');

module.exports = function() {
  const db = mongoose.connect(config.db);

 require('../app/models/user.server.model');

  return db;
};
```

确保在`server.js`文件中执行任何其他配置之前加载 Mongoose 配置文件。这很重要，因为在此模块之后加载的任何模块都将能够使用 User 模型，而无需自行加载它。

## 使用 save()创建新用户

您可以立即开始使用 User 模型，但为了保持组织有序，最好创建一个`Users`控制器，用于处理所有与用户相关的操作。在`app/controllers`文件夹中，创建一个名为`users.server.controller.js`的新文件，并粘贴以下代码行：

```js
const User = require('mongoose').model('User');

exports.create = function(req, res, next) {
  const user = new User(req.body);

  user.save((err) => {
    if (err) {
      return next(err);
    } else {
      res.status(200).json(user);
    }
  });
};
```

让我们来看看这段代码。首先，您使用`mongoose`模块调用`model`方法，该方法将返回您之前定义的`User`模型。接下来，您创建了一个名为`create()`的控制器方法，稍后将用于创建新用户。使用`new`关键字，`create()`方法创建一个新的模型实例，该实例使用请求体进行填充。最后，您调用模型实例的`save()`方法，该方法要么保存用户并输出`user`对象，要么失败并将错误传递给下一个中间件。

要测试您的新控制器，让我们添加一组调用控制器方法的与用户相关的路由。首先，在`app/routes`文件夹中创建一个名为`users.server.routes.js`的文件。在这个新创建的文件中，粘贴以下代码行：

```js
const users = require('../../app/controllers/users.server.controller');

module.exports = function(app) {
  app.route('/users').post(users.create);
};
```

由于您的 Express 应用程序主要将作为 AngularJS 应用程序的 RESTful API，因此最佳实践是根据 REST 原则构建路由。在这种情况下，创建新用户的正确方式是使用 HTTP POST 请求到您在此定义的基本`users`路由。更改您的`config/express.js`文件，使其看起来像以下代码片段中所示：

```js
const config = require('./config');
const express = require('express');
const morgan = require('morgan');
const compress = require('compression');
const bodyParser = require('body-parser');
const methodOverride = require('method-override');
const session = require('express-session');

module.exports = function() {
  const app = express();

  if (process.env.NODE_ENV === 'development') {
    app.use(morgan('dev'));
  } else if (process.env.NODE_ENV === 'production') {
    app.use(compress());
  }

  app.use(bodyParser.urlencoded({
    extended: true
  }));
  app.use(bodyParser.json());
  app.use(methodOverride());

  app.use(session({
    saveUninitialized: true,
    resave: true,
    secret: config.sessionSecret
  }));

  app.set('views', './app/views');
  app.set('view engine', 'ejs');

  require('../app/routes/index.server.routes.js')(app);
  require('../app/routes/users.server.routes.js')(app);

  app.use(express.static('./public'));

  return app;
};
```

就是这样！要进行测试，请转到根应用程序文件夹并执行以下命令：

```js
$ node server

```

您的应用程序应该正在运行。要创建新用户，请执行 HTTP POST 请求到基本的`users`路由，并确保请求体包含以下 JSON：

```js
{
  "firstName": "First",
  "lastName": "Last",
  "email": "user@example.com",
  "username": "username",
  "password": "password"
}
```

另一种测试应用程序的方法是在命令行工具中执行以下`curl`命令：

```js
$ curl -X POST -H "Content-Type: application/json" -d '{"firstName":"First", "lastName":"Last","email":"user@example.com","username":"username","password":"password"}' localhost:3000/users

```

### 提示

您将执行许多不同的 HTTP 请求来测试您的应用程序。对于 Mac OS X 和 Linux 用户，`curl`是一个有用的工具，但还有其他几种专门设计用于此任务的工具；我们建议您找到自己喜欢的工具并从现在开始使用它。

## 使用`find()`查找多个用户文档

`find()`方法是一个模型方法，它使用查询检索存储在同一集合中的多个文档，并且是 MongoDB `find()`集合方法的 Mongoose 实现。为了更好地理解这一点，请将以下`list()`方法添加到您的`app/controllers/users.server.controller.js`文件中：

```js
exports.list = function(req, res, next) {
  User.find({}, (err, users) => {
    if (err) {
      return next(err);
    } else {
      res.status(200).json(users);
    }
  });
};
```

注意新的`list()`方法如何使用`find()`方法来检索`users`集合中所有文档的数组。要使用您创建的新方法，您需要为其注册一个路由，因此转到您的`app/routes/users.server.routes.js`文件并更改为以下代码片段所示：

```js
const users = require('../../app/controllers/users.server.controller');

module.exports = function(app) {
  app.route('/users')
    .post(users.create)
    .get(users.list);
};
```

您需要做的就是通过执行以下命令运行应用程序：

```js
$ node server

```

然后，您将能够通过在浏览器中访问`http://localhost:3000/users`来检索用户列表。

### 使用`find()`进行高级查询

在上面的代码示例中，`find()`方法接受了两个参数，一个是 MongoDB 查询对象，另一个是回调函数，但它最多可以接受四个参数：

+   `Query`：这是一个 MongoDB 查询对象

+   `[Fields]`：这是一个可选的字符串对象，表示要返回的文档字段

+   `[Options]`：这是一个可选的`options`对象

+   `[Callback]`：这是一个可选的回调函数

例如，为了仅检索用户的用户名和电子邮件，您需要修改调用，使其类似于以下代码行所示：

```js
User.find({}, 'username email', (err, users) => {
  …
});
```

此外，当调用`find()`方法时，还可以传递一个`options`对象，该对象将操作查询结果。例如，要通过`skip`和`limit`选项分页浏览`users`集合并仅检索`users`集合的子集，可以使用以下方法：

```js
User.find({}, 'username email', {
  skip: 10,
  limit: 10
}, (err, users) => {
  ...
});
```

这将返回最多 10 个用户文档的子集，同时跳过前 10 个文档。

### 注意

要了解更多有关查询选项的信息，建议您访问官方的 Mongoose 文档[`mongoosejs.com/docs/api.html`](http://mongoosejs.com/docs/api.html)。

## 使用`findOne()`读取单个用户文档

使用`findOne()`方法检索单个用户文档，这与`find()`方法非常相似，但它仅检索子集的第一个文档。要开始处理单个用户文档，我们需要添加两个新方法。将以下代码行添加到您的`app/controllers/users.server.controller.js`文件的末尾：

```js
exports.read = function(req, res) {
  res.json(req.user);
};

exports.userByID = function(req, res, next, id) {
  User.findOne({
    _id: id
  }, (err, user) => {
    if (err) {
      return next(err);
    } else {
      req.user = user;
      next();
    }
  });
};
```

`read()`方法很容易理解；它只是用`req.user`对象的 JSON 表示进行响应，但是是谁创建了`req.user`对象呢？嗯，`userById()`方法负责填充`req.user`对象。在执行读取、删除和更新操作时，您将使用`userById()`方法作为中间件来处理单个文档的操作。为此，您需要修改`app/routes/users.server.routes.js`文件，使其类似于以下代码行所示：

```js
const users = require('../../app/controllers/users.server.controller');

module.exports = function(app) {
  app.route('/users')
     .post(users.create)
     .get(users.list);

 app.route('/users/:userId')
 .get(users.read);

 app.param('userId', users.userByID);
};
```

请注意，您添加了包含`userId`的请求路径的`users.read()`方法。在 Express 中，在路由定义中的子字符串前添加冒号意味着该子字符串将被处理为请求参数。为了处理`req.user`对象的填充，您使用`app.param()`方法，该方法定义了在使用该参数的任何其他中间件之前执行的中间件。在这里，`users.userById()`方法将在此情况下`users.read()`中注册的任何其他使用`userId`参数的中间件之前执行。在构建 RESTful API 时，此设计模式非常有用，其中您经常向路由字符串添加请求参数。

要测试这个，使用以下命令运行您的应用程序：

```js
$ node server

```

然后，在浏览器中导航到`http://localhost:3000/users`，获取其中一个用户的`_id`值，并导航到`http://localhost:3000/users/[id]`，将`[id]`部分替换为用户的`_id`值。

## 更新现有用户文档

Mongoose 模型有几种可用的方法来更新现有文档。其中包括`update()`、`findOneAndUpdate()`和`findByIdAndUpdate()`方法。每种方法在可能时都提供了不同级别的抽象，简化了`update`操作。在我们的情况下，由于我们已经使用了`userById()`中间件，更新现有文档的最简单方法是使用`findByIdAndUpdate()`方法。要做到这一点，返回到您的`app/controllers/users.server.controller.js`文件并添加一个新的`update()`方法：

```js
exports.update = function(req, res, next) {
  User.findByIdAndUpdate(req.user.id, req.body, {
    'new': true
  }, (err, user) => {
    if (err) {
      return next(err);
    } else {
      res.status(200).json(user);
    }
  });
};
```

注意您如何使用用户的`id`字段来查找和更新正确的文档。请注意，默认的 Mongoose 行为是在更新文档之前将回调传递给文档；通过将`new`选项设置为`true`，我们确保我们收到更新后的文档。接下来您应该做的是在用户的路由模块中连接您的新的`update()`方法。返回到您的`app/routes/users.server.routes.js`文件并将其更改为以下代码片段所示的样子：

```js
const users = require('../../app/controllers/users.server.controller');

module.exports = function(app) {
  app.route('/users')
     .post(users.create)
     .get(users.list);

  app.route('/users/:userId')
     .get(users.read)
     .put(users.update);

  app.param('userId', users.userByID);
};
```

注意您如何使用之前创建的路由，并如何使用路由的`put()`方法链接`update()`方法。要测试您的`update()`方法，请使用以下命令运行您的应用程序：

```js
$ node server

```

然后，使用您喜欢的 REST 工具发出 PUT 请求，或者使用`curl`并执行此命令，将`[id]`部分替换为实际文档的`_id`属性：

```js
$ curl -X PUT -H "Content-Type: application/json" -d '{"lastName": "Updated"}' localhost:3000/users/[id]

```

## 删除现有用户文档

Mongoose 模型有几种可用的方法来删除现有文档。其中包括`remove()`、`findOneAndRemove()`和`findByIdAndRemove()`方法。在我们的情况下，由于我们已经使用了`userById()`中间件，删除现有文档的最简单方法就是简单地使用`remove()`方法。要做到这一点，返回到您的`app/controllers/users.server.controller.js`文件并添加以下`delete()`方法：

```js
exports.delete = function(req, res, next) {
  req.user.remove(err => {
    if (err) {
      return next(err);
    } else {
      res.status(200).json(req.user);
    }
  })
};
```

注意您如何使用`user`对象来删除正确的文档。接下来您应该做的是在用户的路由文件中使用您的新的`delete()`方法。转到您的`app/routes/users.server.routes.js`文件并将其更改为以下代码片段所示的样子：

```js
const users = require('../../app/controllers/users.server.controller');

module.exports = function(app) { 
  app.route('/users')
    .post(users.create)
    .get(users.list);

  app.route('/users/:userId')
    .get(users.read)
    .put(users.update)
    .delete(users.delete);

  app.param('userId', users.userByID);
};
```

注意您如何使用之前创建的路由，并如何使用路由的`delete()`方法链接`delete()`方法。要测试您的`delete`方法，请使用以下命令运行您的应用程序：

```js
$ node server

```

然后，使用您喜欢的 REST 工具发出`DELETE`请求，或者使用`curl`并执行以下命令，将`[id]`部分替换为实际文档的`_id`属性：

```js
$ curl -X DELETE localhost:3000/users/[id]

```

这完成了四个 CRUD 操作的实现，让您简要了解了 Mongoose 模型的能力。然而，这些方法只是 Mongoose 包含的众多功能的示例。在下一节中，您将学习如何定义默认值，为模式字段提供动态功能，并验证您的数据。

# 扩展您的 Mongoose 模式

进行数据操作是很好的，但为了开发复杂的应用程序，您需要让您的 ODM 模块做更多的事情。幸运的是，Mongoose 支持各种其他功能，帮助您安全地对文档进行建模并保持数据的一致性。

## 定义默认值

定义默认字段值是数据建模框架的常见功能。您可以直接将此功能添加到应用程序的逻辑层，但这样会很混乱，通常是一种不好的做法。Mongoose 提供在模式级别定义默认值的功能，帮助您更好地组织代码并保证文档的有效性。

假设你想要向你的`UserSchema`添加一个创建日期字段。创建日期字段应该在创建时初始化，并且应该保存用户文档最初创建的时间，这是一个完美的例子，你可以利用默认值。为了做到这一点，你需要更改你的`UserSchema`；所以，回到你的`app/models/user.server.model.js`文件，并将其更改为以下代码片段所示的样子：

```js
const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const UserSchema = new Schema({
  firstName: String,
  lastName: String,
  email: String,
  username: String,
  password: String,
  created: {
    type: Date,
    default: Date.now
  }
});

mongoose.model('User', UserSchema);
```

注意`created`字段的添加和其默认值的定义。从现在开始，每个新的用户文档都将被创建一个默认的创建日期，代表文档创建的时刻。你还应该注意，在此模式更改之前创建的每个用户文档都将被分配一个创建字段，代表你查询它的时刻，因为这些文档没有初始化创建字段。

要测试你的新更改，使用以下命令运行你的应用程序：

```js
$ node server

```

然后，使用你喜欢的 REST 工具发出一个 POST 请求，或者使用`curl`并执行以下命令：

```js
$ curl -X POST -H "Content-Type: application/json" -d '{"firstName":"First", "lastName":"Last","email":"user@example.com","username":"username","password":"password"}' localhost:3000/users

```

将会创建一个新的用户文档，其中包含一个默认的创建字段，在创建时初始化。

## 使用模式修饰符

有时，你可能希望在保存或呈现给客户端之前对模式字段进行操作。为此，Mongoose 使用了一个称为*修饰符*的功能。修饰符可以在保存文档之前更改字段的值，也可以在查询时以不同的方式表示它。

### 预定义的修饰符

最简单的修饰符是 Mongoose 附带的预定义修饰符。例如，字符串类型的字段可以有一个修剪修饰符来去除空格，一个大写修饰符来将字段值大写，等等。为了理解预定义修饰符的工作原理，让我们确保你的用户的用户名不包含前导和尾随空格。要做到这一点，你只需要更改你的`app/models/user.server.model.js`文件，使其看起来像以下代码片段所示的样子：

```js
const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const UserSchema = new Schema({
  firstName: String,
  lastName: String,
  email: String,
  username: {
    type: String,
    trim: true
  },
  password: String,
  created: {
    type: Date,
    default: Date.now
  }
});

mongoose.model('User', UserSchema);
```

注意`username`字段中添加的`trim`属性。这将确保你的用户名数据将被保持修剪。

### 自定义 setter 修饰符

预定义的修饰符很棒，但你也可以定义自己的自定义 setter 修饰符来处理保存文档之前的数据操作。为了更好地理解这一点，让我们向你的用户模型添加一个新的`website`字段。`website`字段应该以`http://`或`https://`开头，但是不要强迫你的客户在 UI 中添加这些前缀，你可以简单地编写一个自定义修饰符来验证这些前缀的存在，并在需要时添加它们。要添加你的自定义修饰符，你需要创建一个带有`set`属性的新的`website`字段，如下所示：

```js
const UserSchema = new Schema({
  …
  website: {
    type: String,
    set: function(url) {
      if (!url) {
        return url;
      } else {
        if (url.indexOf('http://') !== 0   &&           url.indexOf('https://') !== 0) {
          url = 'http://' + url;
        }

        return url;
        }
    }
  },
  …
});
```

现在，每个创建的用户都将拥有一个在创建时修改的正确形式的网站 URL。然而，如果你已经有了一个大量的用户文档集合，你当然可以迁移你现有的数据，但是当处理大型数据集时，这将会对性能产生严重影响，所以你可以简单地使用 getter 修饰符。

### 自定义 getter 修饰符

**Getter**修饰符用于在将文档输出到下一层之前修改现有数据。例如，在我们之前的示例中，getter 修饰符有时会更好地通过在查询时修改网站字段来更改已经存在的用户文档，而不是遍历你的 MongoDB 集合并更新每个文档。要做到这一点，你只需要更改你的`UserSchema`，如下面的代码片段所示：

```js
const UserSchema = new Schema({
  ...
  website: {
    type: String,
    get: function(url) {
      if (!url) {
        return url;
      } else {
        if (url.indexOf('http://') !== 0 &&           url.indexOf('https://') !== 0) {
            url = 'http://' + url;
          }

        return url;
     }
    }
  },
  …
});

UserSchema.set('toJSON', { getters: true });

```

你只需通过将`set`属性更改为`get`来将 setter 修改器更改为 getter 修改器。然而，这里需要注意的重要事情是如何使用`UserSchema.set()`配置了你的模式。这将强制 Mongoose 在将 MongoDB 文档转换为 JSON 表示时包含 getter，并允许使用`res.json()`输出文档以包含 getter 的行为。如果你没有包含这个，你的文档的 JSON 表示将忽略 getter 修改器。

### 注意

修改器非常强大，可以节省大量时间，但应谨慎使用，以防止出现意外的应用程序行为。建议您访问[`mongoosejs.com/docs/api.html`](http://mongoosejs.com/docs/api.html)获取更多信息。

## 添加虚拟属性

有时，你可能希望有动态计算的文档属性，这些属性实际上并不在文档中呈现。这些属性称为*虚拟属性*，它们可以用来满足几个常见的需求。例如，假设你想要添加一个新的`fullName`字段，它将表示用户的名和姓的连接。为此，你将需要使用`virtual()`模式方法；因此，修改后的`UserSchema`将包括以下代码片段：

```js
UserSchema.virtual('fullName').get(function(){
  return this.firstName + ' ' + this.lastName;
});

UserSchema.set('toJSON', { getters: true, virtuals: true });
```

在上面的代码示例中，你向`UserSchema`添加了一个名为`fullName`的虚拟属性，为该虚拟属性添加了一个`getter`方法，然后配置了你的模式以在将 MongoDB 文档转换为 JSON 表示时包含虚拟属性。

然而，虚拟属性也可以有 setter，以帮助你保存你的文档，而不仅仅是添加更多字段属性。在这种情况下，假设你想要将输入的`fullName`字段分解为名和姓字段。为此，修改后的虚拟声明将如下代码片段所示：

```js
UserSchema.virtual('fullName').get(function() {
  return this.firstName + ' ' + this.lastName;
}).set(function(fullName) {
 const splitName = fullName.split(' '); 
 this.firstName = splitName[0] || ''; 
 this.lastName = splitName[1] || ''; 
});

```

虚拟属性是 Mongoose 的一个很棒的特性，允许你在文档表示被传递到应用程序的各个层时修改它们，而不会被持久化到 MongoDB 中。

## 使用索引优化查询

正如我们之前讨论的，MongoDB 支持各种类型的索引来优化查询执行。Mongoose 也支持索引功能，甚至允许你定义次要索引。

索引的基本示例是唯一索引，它验证了集合中`document`字段的唯一性。在我们的示例中，保持用户名唯一是很常见的，因此为了传达这一点给 MongoDB，你需要修改你的`UserSchema`定义，包括以下代码片段：

```js
const UserSchema = new Schema({
  ...
  username: {
    type: String,
    trim: true,
    unique: true
  },
  ...
});
```

这将告诉 MongoDB 为`users`集合的`username`字段创建一个唯一索引。Mongoose 还支持使用`index`属性创建次要索引。因此，如果你知道你的应用程序将使用大量涉及`email`字段的查询，你可以通过以下方式优化这些查询，创建一个电子邮件次要索引：

```js
const UserSchema = new Schema({
  …
  email: {
    type: String,
    index: true
  },
  …
});
```

索引是 MongoDB 的一个很棒的特性，但你应该记住它可能会给你带来一些麻烦。例如，如果你在已经存储数据的集合上定义了唯一索引，你可能会在运行应用程序时遇到一些错误，直到你解决了集合数据的问题。另一个常见问题是 Mongoose 在应用程序启动时自动创建索引，这个特性可能会在生产环境中导致严重的性能问题。

# 定义自定义模型方法

Mongoose 模型中既包含静态方法又包含实例预定义方法，其中一些你已经使用过。然而，Mongoose 还允许你定义自己的自定义方法来增强你的模型，为你提供一个模块化的工具来正确分离你的应用程序逻辑。让我们来看一下定义这些方法的正确方式。

## 定义自定义静态方法

模型静态方法使您有自由进行模型级操作，例如添加额外的`find`方法。例如，假设您想通过他们的用户名搜索用户。当然，您可以在控制器中定义`this`方法，但那不是正确的地方。您要找的是静态模型方法。要添加静态方法，您需要将其声明为模式的`statics`属性的成员。在我们的情况下，添加一个`findOneByUsername()`方法将看起来像下面的代码片段所示：

```js
UserSchema.statics.findOneByUsername = function(username, callback) {
    this.findOne({ username: new RegExp(username, 'i') }, 
  callback);
};
```

这种方法使用模型的`findOne()`方法来检索具有特定用户名的用户文档。使用新的`findOneByUsername()`方法类似于直接从`User`模型调用标准的`static`方法，如下所示：

```js
User.findOneByUsername('username', (err, user) => {
  …
});
```

当开发应用程序时，您当然可以想出许多其他静态方法；您可能在开发应用程序时需要它们，所以不要害怕添加它们。

## 定义自定义实例方法

静态方法很棒，但如果您需要执行实例操作的方法怎么办？好吧，Mongoose 也支持这些方法，帮助您精简代码库并正确重用应用程序代码。要添加实例方法，您需要将其声明为模式的`methods`属性的成员。假设您想使用`authenticate()`方法验证用户的密码。添加此方法将类似于下面的代码片段所示：

```js
UserSchema.methods.authenticate = function(password) {
  return this.password === password;
};
```

这将允许您从任何`User`模型实例调用`authenticate()`方法，如下所示：

```js
user.authenticate('password');
```

正如您所看到的，定义自定义模型方法是保持项目正确组织并重用常见代码的好方法。在接下来的章节中，您将发现实例方法和静态方法都非常有用。

# 模型验证

在处理数据编组时的一个主要问题是验证。当用户向您的应用程序输入信息时，您经常需要在将信息传递给 MongoDB 之前验证该信息。虽然您可以在应用程序的逻辑层验证数据，但在模型级别进行此操作更有用。幸运的是，Mongoose 支持简单的预定义验证器和更复杂的自定义验证器。验证器在文档的字段级别定义，并在保存文档时执行。如果发生验证错误，则保存操作将被中止，并将错误传递给回调函数。

## 预定义验证器

Mongoose 支持不同类型的预定义验证器，其中大多数是特定于类型的。当然，任何应用程序的基本验证是值的存在。要在 Mongoose 中验证字段的存在，您需要在要验证的字段中使用`required`属性。假设您想在保存用户文档之前验证`username`字段的存在。为此，您需要对`UserSchema`进行以下更改：

```js
const UserSchema = new Schema({
  ...
  username: {
    type: String,
    trim: true,
    unique: true,
    required: true
  },
  ...
});
```

这将在保存文档时验证`username`字段的存在，从而防止保存不包含该字段的任何文档。

除了`required`验证器之外，Mongoose 还包括基于类型的预定义验证器，例如用于字符串的`enum`和`match`验证器。例如，要验证您的`email`字段，您需要将`UserSchema`更改如下：

```js
const UserSchema = new Schema({
  …
  email: {
    type: String,
    index: true,
    match: /.+\@.+\..+/
  },
  …
});
```

在这里使用`match`验证器将确保`email`字段值与给定的`regex`表达式匹配，从而防止保存任何不符合正确模式的电子邮件的文档。

另一个例子是`enum`验证器，它可以帮助您定义可用于该字段值的一组字符串。假设您添加了一个`role`字段。可能的验证如下所示：

```js
const UserSchema = new Schema({
  ...
  role: {
    type: String,
    enum: ['Admin', 'Owner', 'User']
  },
  ...
});
```

前面的条件将只允许插入这三个可能的字符串，从而防止您保存文档。

### 注意

要了解更多关于预定义验证器的信息，建议您访问[`mongoosejs.com/docs/validation.html`](http://mongoosejs.com/docs/validation.html)。

## 自定义验证器

除了预定义的验证器，Mongoose 还允许您定义自己的自定义验证器。使用`validate`属性来定义自定义验证器。`validate`属性的值应该是一个包含**验证**函数和错误消息的数组。假设您想要验证用户密码的长度。为此，您需要在`UserSchema`中进行以下更改：

```js
const UserSchema = new Schema({
  ...
  password: {
    type: String,
    validate: [
      function(password) {
        return password.length >= 6;
      },
      'Password should be longer'
    ]
  },
  ...
});
```

该验证器将确保您的用户密码至少为六个字符长，否则它将阻止文档的保存并将您定义的错误消息传递给回调函数。

Mongoose 验证是一个强大的功能，允许您控制模型并提供适当的错误处理，您可以用它来帮助用户理解出了什么问题。在接下来的章节中，您将学习如何使用 Mongoose 验证器来处理用户输入并防止常见的数据不一致性。

# 使用 Mongoose 中间件

Mongoose 中间件是可以拦截`init`、`validate`、`save`和`remove`实例方法的函数。中间件在实例级别执行，并且有两种类型：预中间件和后中间件。

## 使用预中间件

预中间件在操作发生前执行。例如，一个预保存中间件将在保存文档之前执行。这个功能使得预中间件非常适合更复杂的验证和默认值分配。

使用`pre()`方法定义预中间件，因此使用预中间件验证模型将如下所示：

```js
UserSchema.pre('save', function(next){
  if (...) {
    next()
  } else {
    next(new Error('An Error Occurred'));
  }
});
```

## 使用后中间件

后中间件在操作发生后执行。例如，一个后保存中间件将在保存文档后执行。这个功能使得后中间件非常适合记录应用程序逻辑。

使用`post()`方法定义后中间件，因此使用后中间件记录模型的`save()`方法将如下所示：

```js
UserSchema.post('save', function(next){
    console.log('The user "' + this.username +  '" details were saved.');
});
```

Mongoose 中间件非常适合执行各种操作，包括日志记录、验证和执行各种数据一致性操作。如果您现在感到不知所措，不要担心，因为在本书的后面，您将更好地理解这些内容。

### 注意

要了解更多关于中间件的信息，建议您访问[`mongoosejs.com/docs/middleware.html`](http://mongoosejs.com/docs/middleware.html)。

# 使用 Mongoose 的 ref 字段

尽管 MongoDB 不支持连接，但它支持使用名为**DBRef**的约定从一个文档到另一个文档的引用。DBRef 使得可以使用一个特殊字段来引用另一个文档，该字段包含集合名称和文档的`ObjectId`字段。Mongoose 实现了类似的行为，支持使用`ObjectID`模式类型和`ref`属性来支持文档引用。它还支持在查询数据库时将父文档与子文档进行关联。

为了更好地理解这一点，假设您为博客文章创建了另一个模式，称为`PostSchema`。因为用户是博客文章的作者，`PostSchema`将包含一个`author`字段，该字段将由`User`模型实例填充。因此，`PostSchema`将如下所示：

```js
const PostSchema = new Schema({
  title: {
    type: String,
    required: true
  },
  content: {
    type: String,
    required: true
  },
  author: {
    type: Schema.ObjectId,
    ref: 'User'
  }
});

mongoose.model('Post', PostSchema);
```

注意`ref`属性告诉 Mongoose`author`字段将使用`User`模型来填充值。

使用这个新模式是一个简单的任务。要创建一个新的博客文章，您需要检索或创建一个`User`模型的实例，创建一个`Post`模型的实例，然后将`post author`属性分配给`user`实例。示例如下：

```js
const user = new User();
user.save();

const post = new Post();
post.author = user;
post.save();
```

Mongoose 将在 MongoDB`post`文档中创建一个引用，并稍后使用它来检索引用的用户文档。

由于它只是对真实文档的`ObjectID`引用，Mongoose 将不得不使用“populate（）”方法来填充`post`实例中的`user`实例。为此，您将需要告诉 Mongoose 在检索文档时使用“populate（）”方法。例如，一个填充`author`属性的“find（）”方法将如下面的代码片段所示：

```js
Post.find().populate('author').exec((err, posts) => {
  ...
});
```

然后，Mongoose 将检索`posts`集合中的所有文档，并填充它们的`author`属性。

Mongoose 对此功能的支持使您能够放心地依赖对象引用来保持数据模型的组织。在本书的后面，您将学习如何引用以支持您的应用程序逻辑。

### 注意

要了解更多关于引用字段和填充的信息，建议您访问[`mongoosejs.com/docs/populate.html`](http://mongoosejs.com/docs/populate.html)。

# 总结

在本章中，您已经了解了强大的 Mongoose 模型。您连接到了您的 MongoDB 实例，并创建了您的第一个 Mongoose 模式和模型。您还学会了如何验证您的数据，并使用模式修改器和 Mongoose 中间件进行修改。您发现了虚拟属性和修改器，并学会了如何使用它们来改变文档的表示。您还发现了如何使用 Mongoose 来实现文档之间的引用。在下一章中，我们将介绍 Passport 身份验证模块，它将使用您的`User`模型来处理用户身份验证。


# 第六章：使用护照管理用户身份验证

护照是一个强大的 Node.js 身份验证中间件，可帮助您对发送到 Express 应用程序的请求进行身份验证。护照使用策略来利用本地身份验证和 OAuth 身份验证提供程序，例如 Facebook、Twitter 和 Google。使用护照策略，您将能够无缝地为用户提供不同的身份验证选项，同时保持统一的用户模型。在本章中，您将了解护照的以下基本功能：

+   了解护照策略

+   将护照集成到用户的 MVC 架构中

+   使用护照的本地策略来验证用户

+   利用护照 OAuth 策略

+   通过社交 OAuth 提供程序提供身份验证

# 介绍护照

身份验证是大多数 Web 应用程序的重要部分。处理用户注册和登录是一个重要的功能，有时可能会带来开发开销。Express 以其精简的方式缺少了这个功能，因此，与 node 一样，需要一个外部模块。护照是一个使用中间件设计模式来验证请求的 Node.js 模块。它允许开发人员使用称为**策略**的机制提供各种身份验证方法，这使您能够实现复杂的身份验证层，同时保持代码清晰简洁。与任何其他 Node.js 模块一样，在应用程序中开始使用它之前，您首先需要安装它。本章中的示例将直接从前几章中的示例继续。因此，在本章中，从第五章*Mongoose 简介*中复制最终示例，然后从那里开始。

## 安装护照

护照使用不同的模块，每个模块代表不同的身份验证策略，但所有这些模块都依赖于基本的护照模块。要安装护照基本模块，请更改您的`package.json`文件如下：

```js
{
  "name": "MEAN",
  "version": "0.0.6",
  "dependencies": {
    "body-parser": "1.15.2",
    "compression": "1.6.0",
    "ejs": "2.5.2",
    "express": "4.14.0",
    "express-session": "1.14.1",
    "method-override": "2.3.6",
    "mongoose": "4.6.5",
    "morgan": "1.7.0",
 "passport": "0.3.2"
  }
}
```

在继续开发应用程序之前，请确保安装新的护照依赖项。要这样做，请转到应用程序的文件夹，并在命令行工具中发出以下命令：

```js
$ npm install

```

这将在您的`node_modules`文件夹中安装指定版本的护照。安装过程成功完成后，您将需要配置应用程序以加载护照模块。

## 配置护照

配置护照需要几个步骤。要创建护照配置文件，请转到`config`文件夹并创建一个名为`passport.js`的新文件。现在先留空；我们一会儿会回来的。接下来，您需要引用刚刚创建的文件，因此更改您的`server.js`文件如下：

```js
process.env.NODE_ENV = process.env.NODE_ENV || 'development';

const configureMongoose = require('./config/mongoose');
const configureExpress = require('./config/express');
const configurePassport = require('./config/passport');

const db = configureMongoose();
const app = configureExpress();
const passport = configurePassport();
app.listen(3000);

module.exports = app;

console.log('Server running at http://localhost:3000/');
```

接下来，您需要在 Express 应用程序中注册 Passport 中间件。要这样做，请更改您的`config/express.js`文件如下：

```js
const config = require('./config');
const express = require('express');
const morgan = require('morgan');
const compress = require('compression');
const bodyParser = require('body-parser');
const methodOverride = require('method-override');
const session = require('express-session');
const passport = require('passport');

module.exports = function() {
  const app = express();

  if (process.env.NODE_ENV === 'development') {
    app.use(morgan('dev'));
  } else if (process.env.NODE_ENV === 'production') {
    app.use(compress());
  }

  app.use(bodyParser.urlencoded({
    extended: true
  }));
  app.use(bodyParser.json());
  app.use(methodOverride());

  app.use(session({
    saveUninitialized: true,
    resave: true,
    secret: config.sessionSecret
  }));
  app.set('views', './app/views');
  app.set('view engine', 'ejs');

 app.use(passport.initialize());
 app.use(passport.session());

  require('../app/routes/index.server.routes.js')(app);
  require('../app/routes/users.server.routes.js')(app);

  app.use(express.static('./public'));

  return app;
};
```

让我们回顾一下您刚刚添加的代码。首先，您需要引用护照模块，然后注册两个中间件：`passport.initialize()`中间件，负责引导护照模块，以及`passport.session()`中间件，使用 Express 会话来跟踪用户的会话。

护照现在已安装和配置，但要开始使用它，您将需要安装至少一个身份验证策略。我们将从本地策略开始，该策略提供了一个简单的用户名/密码身份验证层；但首先，让我们讨论一下护照策略的工作原理。

# 了解护照策略

为了提供各种身份验证选项，Passport 使用单独的模块来实现不同的身份验证策略。每个模块提供不同的身份验证方法，例如用户名/密码身份验证和 OAuth 身份验证。因此，为了提供 Passport 支持的身份验证，您需要安装和配置您想要使用的策略模块。让我们从本地身份验证策略开始。

## 使用 Passport 的本地策略

Passport 的本地策略是一个 Node.js 模块，允许您实现用户名/密码身份验证机制。您需要像安装其他模块一样安装它，并配置它以使用您的 User Mongoose 模型。让我们开始安装本地策略模块。

### 安装 Passport 的本地策略模块

要安装 Passport 的本地策略模块，您需要将`passport-local`添加到您的`package.json`文件中，如下所示：

```js
{
  "name": "MEAN",
  "version": "0.0.6",
  "dependencies": {
    "body-parser": "1.15.2",
    "compression": "1.6.0",
    "ejs": "2.5.2",
    "express": "4.14.0",
    "express-session": "1.14.1",
    "method-override": "2.3.6",
    "mongoose": "4.6.5",
    "morgan": "1.7.0",
    "passport": "0.3.2",
 "passport-local": "1.0.0"
  }
}
```

然后，转到应用程序的`根`文件夹，并在命令行工具中输入以下命令：

```js
$ npm install

```

这将在您的`node_modules`文件夹中安装指定版本的本地策略模块。安装过程成功完成后，您需要配置 Passport 以使用本地策略。

### 配置 Passport 的本地策略

您将使用的每种身份验证策略基本上都是一个允许您定义该策略将如何使用的节点模块。为了保持逻辑的清晰分离，每个策略都应该在其自己的分离文件中进行配置。在您的`config`文件夹中，创建一个名为`strategies`的新文件夹。在这个新文件夹中，创建一个名为`local.js`的文件，其中包含以下代码片段：

```js
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const User = require('mongoose').model('User');

module.exports = function() {
  passport.use(new LocalStrategy((username, password, done) => {
    User.findOne({
      username: username
    }, (err, user) => {
      if (err) {
        return done(err);
      }

      if (!user) {
        return done(null, false, {
          message: 'Unknown user'
        });
      }

      if (!user.authenticate(password)) {
        return done(null, false, {
          message: 'Invalid password'
        });
      }

      return done(null, user);
      });
  }));
};
```

前面的代码首先需要`Passport`模块、本地策略模块的`Strategy`对象和您的`User` Mongoose 模型。然后，您可以使用`passport.use()`方法注册策略，该方法使用`LocalStrategy`对象的实例。请注意`LocalStrategy`构造函数将回调函数作为参数。稍后在尝试对用户进行身份验证时，它将调用此回调。

回调函数接受三个参数——`用户名`、`密码`和一个`完成`回调——当认证过程结束时将被调用。在回调函数内部，您将使用`User` Mongoose 模型来查找具有该用户名的用户并尝试对其进行身份验证。在出现错误时，您将把`error`对象传递给`done`回调。当用户经过身份验证时，您将使用`user Mongoose`对象调用`done`回调。

还记得空的`config/passport.js`文件吗？现在您已经准备好本地策略，可以返回并使用它来配置本地身份验证。为此，请返回到您的`config/passport.js`文件并粘贴以下代码行：

```js
const passport = require('passport');
const mongoose = require('mongoose');

module.exports = function() {
  const User = mongoose.model('User');

  passport.serializeUser((user, done) => {
    done(null, user.id);
  });

  passport.deserializeUser((id, done) => {
    User.findOne({
      _id: id
    }, '-password -salt', (err, user) => {
      done(err, user);
    });
  });

  require('./strategies/local.js')();
};
```

在前面的代码片段中，使用`passport.serializeUser()`和`passport.deserializeUser()`方法来定义 Passport 将如何处理用户序列化。当用户经过身份验证时，Passport 将其`_id`属性保存到会话中。稍后，当需要`user`对象时，Passport 将使用`_id`属性从数据库中获取`user`对象。请注意，我们使用了字段选项参数来确保 Mongoose 不会获取用户的密码和`salt`属性。前面的代码的第二件事是包含本地策略配置文件。这样，您的`server.js`文件将加载 Passport 配置文件，然后加载其策略配置文件。接下来，您需要修改您的`User`模型以支持 Passport 的身份验证。

## 调整用户模型

在上一章中，我们开始讨论`User`模型并创建了其基本结构。为了在您的 MEAN 应用程序中使用`User`模型，您将需要修改它以满足一些认证流程的要求。这些变化将包括修改`UserSchema`，添加一些`pre`中间件和添加一些新的实例方法。要做到这一点，请转到您的`app/models/user.js`文件，并按照以下方式进行更改：

```js
const mongoose = require('mongoose');
const crypto = require('crypto');
const Schema = mongoose.Schema;
const UserSchema = new Schema({
    firstName: String,
    lastName: String,
    email: {
        type: String,
        match: [/.+\@.+\..+/, "Please fill a valid e-mail address"]
    },
    username: {
        type: String,
        unique: true,
        required: 'Username is required',
        trim: true
    },
    password: {
        type: String,
        validate: [(password) => {
            return password && password.length > 6;
        }, 'Password should be longer']
    },
 salt: {
 type: String
 },
 provider: {
 type: String,
 required: 'Provider is required'
 },
 providerId: String,
 providerData: {},
    created: {
        type: Date,
        default: Date.now
    }
});

UserSchema.virtual('fullName').get(function() {
    return this.firstName + ' ' + this.lastName;
}).set(function(fullName) {
    const splitName = fullName.split(' ');
    this.firstName = splitName[0] || '';
    this.lastName = splitName[1] || '';
});

UserSchema.pre('save', function(next) {
 if (this.password) {
 this.salt = new
 Buffer(crypto.randomBytes(16).toString('base64'), 'base64');
 this.password = this.hashPassword(this.password);
 }
 next();
});

UserSchema.methods.hashPassword = function(password) {
 return crypto.pbkdf2Sync(password, this.salt, 10000,
 64).toString('base64');
};

UserSchema.methods.authenticate = function(password) {
 return this.password === this.hashPassword(password);
};

UserSchema.statics.findUniqueUsername = function(username, suffix,
 callback) {
 var possibleUsername = username + (suffix || '');
 this.findOne({
 username: possibleUsername
 }, (err, user) => {
 if (!err) {
 if (!user) {
 callback(possibleUsername);
 } else {
 return this.findUniqueUsername(username, (suffix || 0) +
 1, callback);
 }
 } else {
 callback(null);
 }
 });
};
UserSchema.set('toJSON', {
    getters: true,
    virtuals: true
});

mongoose.model('User', UserSchema);
```

让我们来看看这些变化。首先，您向`UserSchema`对象添加了四个字段：一个`salt`属性，用于对密码进行哈希处理；一个`provider`属性，用于指示注册用户所使用的策略；一个`providerId`属性，用于指示认证策略的用户标识符；以及一个`providerData`属性，稍后您将用它来存储从 OAuth 提供程序检索到的`user`对象。

接下来，您创建了一些`pre-save`中间件来处理用户密码的哈希处理。众所周知，存储用户密码的明文版本是一种非常糟糕的做法，可能导致用户密码泄露。为了解决这个问题，您的`pre-save`中间件执行了两个重要的步骤：首先，它创建了一个自动生成的伪随机哈希盐，然后使用`hashPassword()`实例方法将当前用户密码替换为哈希密码。

您还添加了两个实例方法：一个`hashPassword()`实例方法，用于通过利用 Node.js 的`crypto`模块对密码字符串进行哈希处理；以及一个`authenticate()`实例方法，它接受一个字符串参数，对其进行哈希处理，并将其与当前用户的哈希密码进行比较。最后，您添加了`findUniqueUsername()`静态方法，用于为新用户找到一个可用的唯一用户名。在本章后面处理 OAuth 认证时，您将使用这个方法。

这完成了对您的`User`模型的修改，但在您测试应用程序的认证层之前，还有一些其他事情需要处理。

## 创建认证视图

就像任何 Web 应用程序一样，您需要有注册和登录页面来处理用户认证。我们将使用**EJS**模板引擎创建这些视图，因此在您的`app/views`文件夹中，创建一个名为`signup.ejs`的新文件。在您新创建的文件中，粘贴以下代码片段：

```js
<!DOCTYPE html>
<html>
<head>
  <title>
    <%=title %>
  </title>
</head>
<body>
  <% for(var i in messages) { %>
    <div class="flash"><%= messages[i] %></div>
  <% } %>
  <form action="/signup" method="post">
    <div>
      <label>First Name:</label>
      <input type="text" name="firstName" />
    </div>
    <div>
      <label>Last Name:</label>
      <input type="text" name="lastName" />
    </div>
    <div>
      <label>Email:</label>
      <input type="text" name="email" />
    </div>
    <div>
      <label>Username:</label>
      <input type="text" name="username" />
    </div>
    <div>
      <label>Password:</label>
      <input type="password" name="password" />
    </div>
    <div>
      <input type="submit" value="Sign up" />
    </div>
  </form>
</body>
</html>
```

`signup.ejs`视图只包含一个 HTML 表单；一个 EJS 标签，用于呈现`title`变量；以及一个 EJS 循环，用于呈现`messages`列表变量。返回到您的`app/views`文件夹，并创建另一个文件，命名为`signin.ejs`。在这个文件中，粘贴以下代码片段：

```js
<!DOCTYPE html>
<html>
<head>
  <title>
    <%=title %>
  </title>
</head>
<body>
  <% for(var i in messages) { %>
    <div class="flash"><%= messages[i] %></div>
  <% } %>
  <form action="/signin" method="post">
    <div>
      <label>Username:</label>
      <input type="text" name="username" />
    </div>
    <div>
      <label>Password:</label>
      <input type="password" name="password" />
    </div>
    <div>
      <input type="submit" value="Sign In" />
    </div>
  </form>
</body>
</html>
```

如您所见，`signin.ejs`视图甚至更简单，也包含一个 HTML 表单；一个 EJS 标签，用于呈现`title`变量；以及一个 EJS 循环，用于呈现`messages`列表变量。现在您已经设置了模型和视图，是时候使用您的 Users 控制器将它们连接起来了。

## 修改 Users 控制器

要修改 Users 控制器，转到您的`app/controllers/users.server.controller.js`文件，并按照以下方式更改其内容：

```js
const User = require('mongoose').model('User');
const passport = require('passport');

function getErrorMessage(err) {
  let message = '';

  if (err.code) {
    switch (err.code) {
      case 11000:
      case 11001:
        message = 'Username already exists';
        break;
      default:
        message = 'Something went wrong';
    }
  } else {
    for (var errName in err.errors) {
      if (err.errors[errName].message) message = err.errors[errName].message;
    }
  }

  return message;
};

exports.renderSignin = function(req, res, next) {
  if (!req.user) {
    res.render('signin', {
      title: 'Sign-in Form',
      messages: req.flash('error') || req.flash('info')
    });
  } else {
    return res.redirect('/');
  }
};

exports.renderSignup = function(req, res, next) {
  if (!req.user) {
    res.render('signup', {
      title: 'Sign-up Form',
      messages: req.flash('error')
    });
  } else {
    return res.redirect('/');
  }
};

exports.signup = function(req, res, next) {
  if (!req.user) {
    const user = new User(req.body);
    user.provider = 'local';

    user.save((err) => {
      if (err) {
        const message = getErrorMessage(err);

        req.flash('error', message);
        return res.redirect('/signup');
      }
      req.login(user, (err) => {
        if (err) return next(err);
        return res.redirect('/');
      });
    });
  } else {
    return res.redirect('/');
  }
};

exports.signout = function(req, res) {
  req.logout();
  res.redirect('/');
};
```

`getErrorMessage()`方法是一个私有方法，它从 Mongoose `error`对象返回统一的错误消息。值得注意的是这里有两种可能的错误：使用错误代码处理的 MongoDB 索引错误，以及使用`err.errors`对象处理的 Mongoose 验证错误。

接下来的两个控制器方法非常简单，将用于呈现登录和注册页面。`signout()`方法也很简单，使用了 Passport 模块提供的`req.logout()`方法来使认证会话失效。

`signup()`方法使用您的`User`模型来创建新用户。正如您所看到的，它首先从 HTTP 请求体创建一个用户对象。然后，尝试将其保存到 MongoDB。如果发生错误，`signup()`方法将使用`getErrorMessage()`方法为用户提供适当的错误消息。如果用户创建成功，将使用`req.login()`方法创建用户会话。`req.login()`方法由`Passport`模块公开，并用于建立成功的登录会话。登录操作完成后，用户对象将被签名到`req.user`对象中。

### 注意

`req.login()`方法将在使用`passport.authenticate()`方法时自动调用，因此在注册新用户时主要使用手动调用`req.login()`。

在前面的代码中，使用了一个您尚不熟悉的模块。当身份验证过程失败时，通常会将请求重定向回注册或登录页面。当发生错误时，这里会这样做，但是您的用户如何知道到底出了什么问题？问题在于当重定向到另一个页面时，您无法将变量传递给该页面。解决方案是使用某种机制在请求之间传递临时消息。幸运的是，这种机制已经存在，以一个名为`Connect-Flash`的节点模块的形式存在。 

### 显示闪存错误消息

`Connect-Flash`模块是一个允许您将临时消息存储在会话对象的`flash`区域中的节点模块。存储在`flash`对象上的消息在呈现给用户后将被清除。这种架构使`Connect-Flash`模块非常适合在将请求重定向到另一个页面之前传递消息。

#### 安装 Connect-Flash 模块

要在应用程序的模块文件夹中安装`Connect-Flash`模块，您需要按照以下方式更改您的`package.json`文件：

```js
{
  "name": "MEAN",
  "version": "0.0.6",
  "dependencies": {
    "body-parser": "1.15.2",
    "compression": "1.6.0",
 "connect-flash": "0.1.1",
    "ejs": "2.5.2",
    "express": "4.14.0",
    "express-session": "1.14.1",
    "method-override": "2.3.6",
    "mongoose": "4.6.5",
    "morgan": "1.7.0",
    "passport": "0.3.2",
    "passport-local": "1.0.0"
  }
}
```

通常，在继续开发应用程序之前，您需要安装新的依赖项。转到应用程序文件夹，并在命令行工具中发出以下命令：

```js
$ npm install

```

这将在您的`node_modules`文件夹中安装指定版本的`Connect-Flash`模块。安装过程成功完成后，您的下一步是配置 Express 应用程序以使用`Connect-Flash`模块。

#### 配置 Connect-Flash 模块

要配置您的 Express 应用程序以使用新的`Connect-Flash`模块，您需要在 Express 配置文件中要求新模块，并使用`app.use()`方法将其注册到 Express 应用程序中。为此，请在您的`config/express.js`文件中进行以下更改：

```js
const config = require('./config');
const express = require('express');
const morgan = require('morgan');
const compress = require('compression');
const bodyParser = require('body-parser');
const methodOverride = require('method-override');
const session = require('express-session');
const flash = require('connect-flash');
const passport = require('passport');

module.exports = function() {
  const app = express();

  if (process.env.NODE_ENV === 'development') {
    app.use(morgan('dev'));
  } else if (process.env.NODE_ENV === 'production') {
    app.use(compress());
  }

  app.use(bodyParser.urlencoded({
    extended: true
  }));

  app.use(bodyParser.json());
  app.use(methodOverride());

  app.use(session({
    saveUninitialized: true,
    resave: true,
    secret: config.sessionSecret
  }));
  app.set('views', './app/views');
  app.set('view engine', 'ejs');

 app.use(flash());
  app.use(passport.initialize());
  app.use(passport.session());

  require('../app/routes/index.server.routes.js')(app);
  require('../app/routes/users.server.routes.js')(app);

  app.use(express.static('./public'));

  return app;

};
```

这将告诉您的 Express 应用程序使用`Connect-Flash`模块，并在应用程序会话中创建新的闪存区域。

#### 使用 Connect-Flash 模块

安装后，`Connect-Flash`模块公开了`req.flash()`方法，允许您创建和检索闪存消息。为了更好地理解它，让我们观察您对用户控制器所做的更改。首先，让我们看看负责渲染登录和注册页面的`renderSignup()`和`renderSignin()`方法：

```js
exports.renderSignin = function(req, res, next) {
  if (!req.user) {
    res.render('signin', {
      title: 'Sign-in Form',
 messages: req.flash('error') || req.flash('info')
    });
  } else {
    return res.redirect('/');
  }
};

exports.renderSignup = function(req, res, next) {
  if (!req.user) {
    res.render('signup', {
      title: 'Sign-up Form',
 messages: req.flash('error')
    });
  } else {
    return res.redirect('/');
  }
}; 
```

如您所见，`res.render()`方法使用`title`和`messages`变量执行。messages 变量使用`req.flash()`读取消息写入闪存。现在，如果您查看`signup()`方法，您会注意到以下代码行：

```js
req.flash('error', message);
```

这是如何使用`req.flash()`方法将错误消息写入闪存的方式。在学习如何使用`Connect-Flash`模块之后，您可能已经注意到我们缺少一个`signin()`方法。这是因为 Passport 为您提供了一个身份验证方法，您可以直接在路由定义中使用。最后，让我们继续进行最后需要修改的部分：用户的路由定义文件。

## 连接用户路由

一旦您配置好模型、控制器和视图，剩下的就是定义用户的路由。为此，请在您的`app/routes/users.server.routes.js`文件中进行以下更改：

```js
const users = require('../../app/controllers/users.server.controller');
const passport = require('passport');

module.exports = function(app) {
  app.route('/signup')
     .get(users.renderSignup)
     .post(users.signup);

  app.route('/signin')
     .get(users.renderSignin)
     .post(passport.authenticate('local', {
       successRedirect: '/',
       failureRedirect: '/signin',
       failureFlash: true
     }));

  app.get('/signout', users.signout);
};
```

正如您所看到的，这里的大多数路由定义基本上是指向您的用户控制器中的方法。唯一不同的路由定义是处理发送到`/signin`路径的任何 POST 请求时使用`passport.authenticate()`方法。

当执行`passport.authenticate()`方法时，它将尝试使用其第一个参数定义的策略来验证用户请求。在这种情况下，它将尝试使用本地策略来验证请求。此方法接受的第二个参数是一个`options`对象，其中包含三个属性：

+   `successRedirect`：此属性告诉 Passport 在成功验证用户后将请求重定向到何处

+   `failureRedirect`：此属性告诉 Passport 在未能验证用户时将请求重定向到何处

+   `failureFlash`：此属性告诉 Passport 是否使用闪存消息

您几乎已经完成了基本的身份验证实现。要测试它，请对`app/controllers/index.server.controller.js`文件进行以下更改：

```js
exports.render = function(req, res) {
  res.render('index', {
    title: 'Hello World',
    userFullName: req.user ? req.user.fullName : ''
  });
};
```

这将向您的主页模板传递经过身份验证的用户的全名。您还需要对`app/views/index.ejs`文件进行以下更改：

```js
<!DOCTYPE html>
<html>
  <head>
      <title><%= title %></title>
    </head>
    <body>
      <% if ( userFullName ) { %>
        <h2>Hello <%=userFullName%> </h2> 
        <a href="/signout">Sign out</a>
      <% } else { %>
        <a href="/signup">Signup</a>
        <a href="/signin">Signin</a>
    <% } %>
    <br>
      <img src="img/logo.png" alt="Logo">
    </body>
</html>
```

就是这样！一切都准备好测试您的新身份验证层。转到您的根应用程序文件夹，并使用 node 命令行工具运行您的应用程序，然后输入以下命令：

```js
$ node server

```

通过访问`http://localhost:3000/signin`和`http://localhost:3000/signup`来测试您的应用程序。尝试注册，然后登录，不要忘记返回到您的主页，查看用户详细信息如何通过会话保存。

# 了解 Passport OAuth 策略

OAuth 是一种身份验证协议，允许用户使用外部提供者注册您的 Web 应用程序，而无需输入其用户名和密码。OAuth 主要由社交平台（如 Facebook、Twitter 和 Google）使用，允许用户使用其社交账户注册其他网站。

### 提示

要了解有关 OAuth 的更多信息，请访问[`oauth.net/`](http://oauth.net/)上的 OAuth 协议网站。

## 设置 OAuth 策略

Passport 支持基本的 OAuth 策略，这使您能够实现任何基于 OAuth 的身份验证。但是，它还支持通过主要的 OAuth 提供者进行用户身份验证，使用包装策略来帮助您避免自己实现复杂的机制。在本节中，我们将回顾顶级 OAuth 提供者以及如何实现其 Passport 身份验证策略。

### 注意

在开始之前，您需要联系 OAuth 提供者并创建一个开发者应用程序。此应用程序将具有 OAuth 客户端 ID 和 OAuth 客户端密钥，这将允许您对您的应用程序进行 OAuth 提供者的验证。

### 处理 OAuth 用户创建

OAuth 用户创建应该与本地`signup()`方法有些不同。由于用户是使用其他提供者的配置文件注册的，配置文件详细信息已经存在，这意味着您需要以不同的方式对它们进行验证。为此，请返回到您的`app/controllers/users.server.controller.js`文件，并添加以下方法：

```js
exports.saveOAuthUserProfile = function(req, profile, done) {
  User.findOne({
    provider: profile.provider,
    providerId: profile.providerId
  }, (err, user) => {
    if (err) {
      return done(err);
    } else {
      if (!user) {
        const possibleUsername = profile.username || ((profile.email) ? profile.email.split(@''@')[0] : '');

        User.findUniqueUsername(possibleUsername, null, (availableUsername) => {
          const newUser = new User(profile);
          newUser.username = availableUsername;

          newUser.save((err) => {

            return done(err, newUser);
          });
        });
      } else {
        return done(err, user);
      }
    }
  });
};
```

该方法接受一个用户资料，然后查找具有这些`providerId`和`provider`属性的现有用户。如果找到用户，它将使用用户的 MongoDB 文档调用`done()`回调方法。但是，如果找不到现有用户，它将使用 User 模型的`findUniqueUsername()`静态方法找到一个唯一的用户名，并保存一个新的用户实例。如果发生错误，`saveOAuthUserProfile()`方法将使用`done()`方法报告错误；否则，它将把用户对象传递给`done()`回调方法。一旦弄清楚了`saveOAuthUserProfile()`方法，就是时候实现第一个 OAuth 认证策略了。

### 使用 Passport 的 Facebook 策略

Facebook 可能是世界上最大的 OAuth 提供商。许多现代 Web 应用程序允许用户使用他们的 Facebook 资料注册 Web 应用程序。Passport 支持使用`passport-facebook`模块进行 Facebook OAuth 认证。让我们看看如何通过几个简单的步骤实现基于 Facebook 的认证。

#### 安装 Passport 的 Facebook 策略

要在应用程序的模块文件夹中安装 Passport 的 Facebook 模块，你需要按照以下方式更改你的`package.json`文件：

```js
{
  "name": "MEAN",
  "version": "0.0.6",
  "dependencies": {
    "body-parser": "1.15.2",
    "compression": "1.6.0",
    "connect-flash": "0.1.1",
    "ejs": "2.5.2",
    "express": "4.14.0",
    "express-session": "1.14.1",
    "method-override": "2.3.6",
    "mongoose": "4.6.5",
    "morgan": "1.7.0",
    "passport": "0.3.2",
 "passport-facebook": "2.1.1",
    "passport-local": "1.0.0"
  }
}
```

在继续开发应用之前，你需要安装新的 Facebook 策略依赖。为此，前往你应用的`root`文件夹，并在命令行工具中输入以下命令：

```js
$ npm install

```

这将在你的`node_modules`文件夹中安装指定版本的 Passport 的 Facebook 策略。安装过程成功完成后，你需要配置 Facebook 策略。

#### 配置 Passport 的 Facebook 策略

在开始配置 Facebook 策略之前，你需要前往 Facebook 的开发者主页[`developers.facebook.com/`](https://developers.facebook.com/)，创建一个新的 Facebook 应用，并将本地主机设置为应用域。配置完 Facebook 应用后，你将获得一个 Facebook 应用 ID 和密钥。你需要这些信息来通过 Facebook 对用户进行认证，所以让我们将它们保存在环境配置文件中。前往`config/env/development.js`文件，并进行以下更改：

```js
module.exports = {
  db: 'mongodb://localhost/mean-book',
  sessionSecret: 'developmentSessionSecret',
 facebook: {
 clientID: 'Application Id',
 clientSecret: 'Application Secret',
 callbackURL: 'http://localhost:3000/oauth/facebook/callback'
  }
};
```

不要忘记用你的 Facebook 应用 ID 和密钥替换`Application Id`和`Application Secret`。`callbackURL`属性将被传递给 Facebook OAuth 服务，在认证过程结束后将重定向到该 URL。确保`callbackURL`属性与你在开发者主页设置的回调设置匹配。

现在，前往你的`config/strategies`文件夹，创建一个名为`facebook.js`的新文件，其中包含以下代码片段：

```js
const passport = require('passport');
const url = require('url');
const FacebookStrategy = require('passport-facebook').Strategy;
const config = require('../config');
const users = require('../../app/controllers/users.server.controller');

module.exports = function() {
  passport.use(new FacebookStrategy({
    clientID: config.facebook.clientID,
    clientSecret: config.facebook.clientSecret,
    callbackURL: config.facebook.callbackURL,
    profileFields: ['id', 'name', 'displayName', 'emails'],
    passReqToCallback: true
  }, (req, accessToken, refreshToken, profile, done) => {
    const providerData = profile._json;
    providerData.accessToken = accessToken;
    providerData.refreshToken = refreshToken;

    const providerUserProfile = {
      firstName: profile.name.givenName,
      lastName: profile.name.familyName,
      fullName: profile.displayName,
      email: profile.emails[0].value,
      username: profile.name.givenName + profile.name.familyName,
      provider: 'facebook',
      providerId: profile.id,
      providerData: providerData
    };

    users.saveOAuthUserProfile(req, providerUserProfile, done);
  }));
};
```

让我们稍微回顾一下前面的代码片段。你首先需要引入`passport`模块、Facebook 策略对象、你的环境配置文件、你的`User` Mongoose 模型和 Users 控制器。然后，使用`passport.use()`方法注册策略，并创建一个`FacebookStrategy`对象的实例。`FacebookStrategy`构造函数接受两个参数：Facebook 应用信息和稍后在尝试认证用户时将调用的回调函数。

看一下你定义的回调函数。它接受五个参数：`HTTP 请求`对象，一个`accessToken`对象用于验证未来的请求，一个`refreshToken`对象用于获取新的访问令牌，一个包含用户资料的`profile`对象，以及在认证过程结束时调用的`done`回调函数。

在回调函数内部，你将使用 Facebook 资料信息创建一个新的用户对象，并使用控制器的`saveOAuthUserProfile()`方法对当前用户进行认证。

还记得`config/passport.js`文件吗？现在您已经配置了您的 Facebook 策略，您可以返回到该文件并加载策略文件。为此，返回`config/passport.js`文件并按以下方式更改它：

```js
const passport = require('passport');
const mongoose = require('mongoose');

module.exports = function() {
  const User = mongoose.model('User');

  passport.serializeUser((user, done) => {
    done(null, user.id);
  });

  passport.deserializeUser((id, done) => {
    User.findOne({
      _id: id
    }, '-password -salt', (err, user) => {
      done(err, user);
    });
  });

  require('./strategies/local.js')();
 require('./strategies/facebook.js')();
};
```

这将加载您的 Facebook 策略配置文件。现在，剩下的就是设置通过 Facebook 对用户进行身份验证所需的路由，并在您的登录和注册页面中包含指向这些路由的链接。

#### 连接 Passport 的 Facebook 策略路由

Passport OAuth 策略支持使用`passport.authenticate()`方法直接对用户进行身份验证的能力。要这样做，转到`app/routes/users.server.routes.js`，并在本地策略路由定义之后追加以下代码行：

```js
app.get('/oauth/facebook', passport.authenticate('facebook', {
  failureRedirect: '/signin'
}));

app.get('/oauth/facebook/callback', passport.authenticate('facebook', {
  failureRedirect: '/signin',
  successRedirect: '/'
}));
```

第一个路由将使用`passport.authenticate()`方法启动用户身份验证过程，而第二个路由将在用户链接其 Facebook 个人资料后使用`passport.authenticate()`方法完成身份验证过程。

就是这样！一切都为您的用户通过 Facebook 进行身份验证设置好了。现在您只需要转到您的`app/views/signup.ejs`和`app/views/signin.ejs`文件，并在关闭的`BODY`标签之前添加以下代码行：

```js
<a href="/oauth/facebook">Sign in with Facebook</a>
```

这将允许您的用户点击链接并通过其 Facebook 个人资料注册您的应用程序。

### 使用 Passport 的 Twitter 策略

另一个流行的 OAuth 提供程序是 Twitter，许多 Web 应用程序都提供用户使用其 Twitter 个人资料注册 Web 应用程序的功能。Passport 支持使用`passport-twitter`模块的 Twitter OAuth 身份验证方法。让我们看看如何通过几个简单的步骤实现基于 Twitter 的身份验证。

#### 安装 Passport 的 Twitter 策略

要在应用程序的模块文件夹中安装 Passport 的 Twitter 策略模块，您需要按照以下步骤更改您的`package.json`文件：

```js
{
  "name": "MEAN",
  "version": "0.0.6",
  "dependencies": {
    "body-parser": "1.15.2",
    "compression": "1.6.0",
    "connect-flash": "0.1.1",
    "ejs": "2.5.2",
    "express": "4.14.0",
    "express-session": "1.14.1",
    "method-override": "2.3.6",
    "mongoose": "4.6.5",
    "morgan": "1.7.0",
    "passport": "0.3.2",
    "passport-facebook": "2.1.1",
    "passport-local": "1.0.0",
 "passport-twitter": "1.0.4"
  }
}
```

在继续开发应用程序之前，您需要安装新的 Twitter 策略依赖项。转到您的应用程序的`root`文件夹，并在命令行工具中发出以下命令：

```js
$ npm install

```

这将在您的`node_modules`文件夹中安装指定版本的 Passport 的 Twitter 策略。安装过程成功完成后，您需要配置 Twitter 策略。

#### 配置 Passport 的 Twitter 策略

在开始配置 Twitter 策略之前，您需要转到 Twitter 开发者主页[`dev.twitter.com/`](https://dev.twitter.com/)并创建一个新的 Twitter 应用程序。配置 Twitter 应用程序后，您将获得 Twitter 应用程序 ID 和密钥。您需要它们来通过 Twitter 对用户进行身份验证，因此让我们将它们添加到我们的环境配置文件中。转到`config/env/development.js`文件，并按以下方式更改它：

```js
module.exports = {
  db: 'mongodb://localhost/mean-book',
  sessionSecret: 'developmentSessionSecret',
  facebook: {
    clientID: 'Application Id',
    clientSecret: 'Application Secret',
    callbackURL: 'http://localhost:3000/oauth/facebook/callback'
  },
 twitter: {
 clientID: 'Application Id',
 clientSecret: 'Application Secret',
 callbackURL: 'http://localhost:3000/oauth/twitter/callback'
 }
};
```

不要忘记用您的 Twitter 应用程序的 ID 和密钥替换`Application Id`和`Application Secret`。`callbackURL`属性将被传递给 Twitter OAuth 服务，该服务将在认证过程结束后将用户重定向到该 URL。确保`callbackURL`属性与您在开发者主页中设置的回调设置匹配。

如前所述，在您的项目中，每个策略都应该在自己单独的文件中进行配置，这将帮助您保持项目的组织。转到您的`config/strategies`文件夹，并创建一个名为`twitter.js`的新文件，其中包含以下代码行：

```js
const passport = require('passport');
const url = require('url');
const TwitterStrategy = require('passport-twitter').Strategy;
const config = require('../config');
const users = require('../../app/controllers/users.server.controller');

module.exports = function() {
  passport.use(new TwitterStrategy({
    consumerKey: config.twitter.clientID,
    consumerSecret: config.twitter.clientSecret,
    callbackURL: config.twitter.callbackURL,
    passReqToCallback: true
  }, (req, token, tokenSecret, profile, done) => {
    const providerData = profile._json;
    providerData.token = token;
    providerData.tokenSecret = tokenSecret;

    const providerUserProfile = {
      fullName: profile.displayName,
      username: profile.username,
      provider: 'twitter',
      providerId: profile.id,
      providerData: providerData
    };

    users.saveOAuthUserProfile(req, providerUserProfile, done);
  }));
};
```

您首先需要引入`passport`模块、`Twitter Strategy`对象、您的环境配置文件、您的`User` Mongoose 模型和 Users 控制器。然后，您使用`passport.use()`方法注册策略，并创建`TwitterStrategy`对象的实例。`TwitterStrategy`构造函数接受两个参数：Twitter 应用程序信息和稍后在尝试对用户进行身份验证时将调用的回调函数。

查看您定义的回调函数。它接受五个参数：`HTTP 请求`对象，一个`token`对象和一个`tokenSecret`对象来验证未来的请求，一个包含用户配置文件的`profile`对象，以及在身份验证过程结束时调用的`done`回调。

在回调函数中，您将使用 Twitter 配置文件信息创建一个新的用户对象，并使用您之前创建的控制器的`saveOAuthUserProfile()`方法来验证当前用户。

现在您已经配置了 Twitter 策略，您可以返回`config/passport.js`文件，并按照以下方式加载策略文件：

```js
const passport = require('passport');
const mongoose = require('mongoose');

module.exports = function() {
  const User = mongoose.model('User');

  passport.serializeUser((user, done) => {
    done(null, user.id);
  });

  passport.deserializeUser((id, done) => {
    User.findOne({
      _id: id
    }, '-password -salt, ', (err, user) => {
      done(err, user);
    });
  });

  require('./strategies/local.js')();
  require('./strategies/facebook.js')();
 require('./strategies/twitter.js')();
};
```

这将加载您的 Twitter 策略配置文件。现在，您只需要设置所需的路由来通过 Twitter 对用户进行身份验证，并在登录和注册页面中包含指向这些路由的链接。

#### 连接 Passport 的 Twitter 策略路由

要添加 Passport 的 Twitter 路由，请转到您的`app/routes/users.server.routes.js`文件，并在 Facebook 策略路由之后粘贴以下代码：

```js
app.get('/oauth/twitter', passport.authenticate('twitter', {
  failureRedirect: '/signin'
}));

app.get('/oauth/twitter/callback', passport.authenticate('twitter', {
  failureRedirect: '/signin',
  successRedirect: '/'
}));
```

第一个路由将使用`passport.authenticate()`方法启动用户身份验证过程，而第二个路由将在用户使用其 Twitter 配置文件连接后使用`passport.authenticate()`方法完成身份验证过程。

就是这样！您的用户的 Twitter 身份验证已经设置好了。您需要做的就是转到您的`app/views/signup.ejs`和`app/views/signin.ejs`文件，并在关闭的`BODY`标签之前添加以下代码行：

```js
<a href="/oauth/twitter">Sign in with Twitter</a>
```

这将允许您的用户点击链接，并通过其 Twitter 配置文件注册到您的应用程序。

### 使用 Passport 的 Google 策略

我们将实现的最后一个 OAuth 提供程序是 Google，因为许多 Web 应用程序都允许用户使用其 Google 配置文件注册 Web 应用程序。Passport 支持使用`passport-google-oauth`模块的 Google OAuth 身份验证方法。让我们看看如何通过几个简单的步骤实现基于 Google 的身份验证。

#### 安装 Passport 的 Google 策略

要在应用程序的模块文件夹中安装 Passport 的 Google 策略模块，您需要更改您的`package.json`文件，如下所示：

```js
{
  "name": "MEAN",
  "version": "0.0.6",
  "dependencies": {
    "body-parser": "1.15.2",
    "compression": "1.6.0",
    "connect-flash": "0.1.1",
    "ejs": "2.5.2",
    "express": "4.14.0",
    "express-session": "1.14.1",
    "method-override": "2.3.6",
    "mongoose": "4.6.5",
    "morgan": "1.7.0",
    "passport": "0.3.2",
    "passport-facebook": "2.1.1",    
 "passport-google-oauth": "1.0.0",
    "passport-local": "1.0.0",
    "passport-twitter": "1.0.4"
  }
}

```

在您继续开发应用程序之前，您需要安装新的谷歌策略依赖项。转到应用程序的“根”文件夹，并在命令行工具中输入以下命令：

```js
$ npm install

```

这将在您的`node_modules`文件夹中安装 Passport 的 Google 策略的指定版本。安装过程成功完成后，您需要配置 Google 策略。

#### 配置 Passport 的 Google 策略

在我们开始配置您的 Google 策略之前，您需要转到 Google 开发人员主页[`console.developers.google.com/`](https://console.developers.google.com/)并创建一个新的 Google 应用程序。在应用程序的设置中，将`JAVASCRIPT ORIGINS`属性设置为`http://localhost`，将`REDIRECT URLs`属性设置为`http://localhost/oauth/google/callback`。配置完您的 Google 应用程序后，您将获得 Google 应用程序 ID 和密钥。您需要它们来通过 Google 对用户进行身份验证，因此让我们将它们添加到我们的环境配置文件中。转到`config/env/development.js`文件，并更改如下：

```js
module.exports = {
  db: 'mongodb://localhost/mean-book',
  sessionSecret: 'developmentSessionSecret',
  facebook: {
    clientID: 'Application Id',
    clientSecret: 'Application Secret',
    callbackURL: 'http://localhost:3000/oauth/facebook/callback'
  },
  twitter: {
    clientID: 'Application Id',
    clientSecret: 'Application Secret',
    callbackURL: 'http://localhost:3000/oauth/twitter/callback'
  },
 google: {
 clientID: 'Application Id',
 clientSecret: 'Application Secret',
 callbackURL: 'http://localhost:3000/oauth/google/callback'
 }
};
```

不要忘记用您的 Google 应用程序的 ID 和密钥替换`Application Id`和`Application Secret`。`callbackURL`属性将传递给 Google OAuth 服务，在身份验证过程结束后将用户重定向到该 URL。确保`callbackURL`属性与您在开发人员主页中设置的回调设置匹配。

要实现 Google 身份验证策略，请转到您的`config/strategies`文件夹，并创建一个名为`google.js`的新文件，其中包含以下代码行：

```js
const passport = require('passport');
const url = require('url');,
const GoogleStrategy = require('passport-google-oauth').OAuth2Strategy;
const config = require(../config');
const users = require('../../app/controllers/users.server.controller');

module.exports = function() {
  passport.use(new GoogleStrategy({
    clientID: config.google.clientID,
    clientSecret: config.google.clientSecret,
    callbackURL: config.google.callbackURL,
    passReqToCallback: true
  }, (req, accessToken, refreshToken, profile, done) => {
    const providerData = profile._json;
    providerData.accessToken = accessToken;
    providerData.refreshToken = refreshToken;

    const providerUserProfile = {
      firstName: profile.name.givenName,
      lastName: profile.name.familyName,
      fullName: profile.displayName,
      email: profile.emails[0].value,
      username: profile.username,
      provider: 'google''google',
      providerId: profile.id,
      providerData: providerData
    };

    users.saveOAuthUserProfile(req, providerUserProfile, done);
  }));
};
```

让我们稍微回顾一下前面的代码片段。您首先需要引入`passport`模块、Google 策略对象、您的环境配置文件、`User` Mongoose 模型和用户控制器。然后，使用`passport.use()`方法注册策略，并创建一个`GoogleStrategy`对象的实例。`GoogleStrategy`构造函数接受两个参数：Google 应用程序信息和稍后在尝试对用户进行身份验证时将调用的回调函数。

查看您定义的回调函数。它接受五个参数：`HTTP 请求`对象，用于验证未来请求的`accessToken`对象，用于获取新访问令牌的`refreshToken`对象，包含用户配置文件的`profile`对象，以及在认证过程结束时调用的`done`回调。

在回调函数中，您将使用 Google 配置文件信息和控制器的`saveOAuthUserProfile()`方法创建一个新的用户对象，该方法是您之前创建的，用于验证当前用户。

现在您已经配置了 Google 策略，可以返回到`config/passport.js`文件并加载策略文件，如下所示：

```js
const passport = require('passport');
const mongoose = require('mongoose');

module.exports = function() {
  const User = mongoose.model('User');

  passport.serializeUser((user, done) => {
    done(null, user.id);
  });

  passport.deserializeUser((id, done) => {
    User.findOne({
      _id: id
    }, '-password -salt', function(err, user) => {
      done(err, user);
    });
  });

  require('./strategies/local.js')();
  require('./strategies/facebook.js')();
  require('./strategies/twitter.js')();
 require('./strategies/google.js')();
};
```

这将加载您的 Google 策略配置文件。现在剩下的就是设置所需的路由来通过 Google 对用户进行身份验证，并在您的登录和注册页面中包含指向这些路由的链接。

#### 连接 Passport 的 Google 策略路由

要添加 Passport 的 Google 路由，请转到您的`app/routes/users.server.routes.js`文件，并在 Twitter 策略路由之后粘贴以下代码行：

```js
app.get('/oauth/google', passport.authenticate('google', {
  failureRedirect: '/signin',
  scope: [
    'https://www.googleapis.com/auth/userinfo.profile',
    'https://www.googleapis.com/auth/userinfo.email'
  ],
}));

app.get('/oauth/google/callback', passport.authenticate('google', {
  failureRedirect: '/signin',
  successRedirect: '/'
}));
```

第一个路由将使用`passport.authenticate()`方法启动用户身份验证过程，而第二个路由将使用`passport.authenticate()`方法在用户使用其 Google 配置文件连接后完成身份验证过程。

就是这样！一切都为您的用户基于 Google 的身份验证设置好了。您只需转到您的`app/views/signup.ejs`和`app/views/signin.ejs`文件，并在关闭的`BODY`标签之前添加以下代码行：

```js
<a href="/oauth/google">Sign in with Google</a>
```

这将允许您的用户点击链接并通过其 Google 配置文件注册您的应用程序。要测试您的新身份验证层，转到应用程序的`root`文件夹，并使用 node 命令行工具运行您的应用程序：

```js
$ node server

```

通过访问`http://localhost:3000/signin`和`http://localhost:3000/signup`来测试您的应用程序。尝试使用新的 OAuth 方法进行注册和登录。不要忘记访问您的主页，查看用户详细信息在整个会话期间是如何保存的。

### 提示

Passport 还为许多其他 OAuth 提供程序提供类似的支持。要了解更多信息，建议您访问[`passportjs.org/guide/providers/`](http://passportjs.org/guide/providers/)。

# 总结

在本章中，您了解了 Passport 身份验证模块。您了解了其策略以及如何处理其安装和配置。您还学会了如何正确注册用户以及如何验证其请求。您已经了解了 Passport 的本地策略，并学会了如何使用用户名和密码对用户进行身份验证，以及 Passport 如何支持不同的 OAuth 身份验证提供程序。在下一章中，我们将向您介绍 MEAN 拼图的最后一部分，即**Angular**。
