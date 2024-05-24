# MongoDB 数据建模（一）

> 原文：[`zh.annas-archive.org/md5/3D36993E61CA808CF2348E9B049B1823`](https://zh.annas-archive.org/md5/3D36993E61CA808CF2348E9B049B1823)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

即使在今天，仍然很常见说计算机科学是一个年轻和新的领域。然而，当我们观察其他领域时，这种说法变得有些矛盾。与其他领域不同，计算机科学是一个不断以超出正常速度发展的学科。我敢说，计算机科学现在已经为医学和工程等其他领域的发展设定了进化的路径。在这种情况下，作为计算机科学学科领域的数据库系统不仅促进了其他领域的增长，而且还充分利用了许多技术领域的进化和进步，如计算机网络和计算机存储。

从形式上来说，自 20 世纪 60 年代以来，数据库系统一直是一个活跃的研究课题。从那时起，我们经历了几代，IT 行业中出现了一些大名鼎鼎的人物，并开始主导市场的趋势。

在 2000 年代，随着世界互联网接入的增长，形成了一个新的网络流量模式，社交网络的蓬勃发展，NoSQL 这个术语变得很普遍。许多人认为这是一个矛盾和有争议的话题，有些人认为这是一代新技术，是对过去十年经历的所有变化的回应。

MongoDB 就是其中之一。诞生于 21 世纪初，它成为了世界上最受欢迎的 NoSQL 数据库。不仅是世界上最受欢迎的数据库，自 2015 年 2 月以来，根据 DB-Engines 排名([`db-engines.com/en/`](http://db-engines.com/en/))，MongoDB 成为了第四受欢迎的数据库系统，超过了著名的 PostgreSQL 数据库。

然而，流行度不应该与采用混淆。尽管 DB-Engines 排名显示 MongoDB 在搜索引擎（如 Google）上负责一些流量，有工作搜索活动，并且在社交媒体上有相当大的活动，但我们无法确定有多少应用程序正在使用 MongoDB 作为数据源。事实上，这不仅仅是 MongoDB 的问题，而是每一种 NoSQL 技术都存在的问题。

好消息是采用 MongoDB 并不是一个很艰难的决定。它是开源的，所以你可以免费从 MongoDB Inc. ([`www.mongodb.com`](https://www.mongodb.com))下载，那里有广泛的文档。你也可以依靠一个庞大且不断增长的社区，他们像你一样，总是在书籍、博客和论坛上寻找新的东西；分享知识和发现；并合作推动 MongoDB 的发展。

《MongoDB 数据建模》的撰写目的是为您提供另一个研究和参考来源。在其中，我们将介绍用于创建可扩展数据模型的技术和模式。我们将介绍基本的数据库建模概念，并提供一个专注于 MongoDB 建模的概述。最后，您将看到一个实际的逐步示例，对一个现实问题进行建模。

主要来说，有一些 MongoDB 背景的数据库管理员将受益于《MongoDB 数据建模》。然而，从开发人员到所有下载了 MongoDB 的好奇者都会从中受益。

本书侧重于 MongoDB 3.0 版本。MongoDB 3.0 版本是社区期待已久的版本，被 MongoDB Inc.认为是迄今为止最重要的发布。这是因为在这个版本中，我们被介绍了新的、高度灵活的存储架构 WiredTiger。性能和可扩展性的增强意图加强 MongoDB 在数据库系统技术中的重要性，并将其定位为现代应用程序的标准数据库。

# 本书涵盖的内容

第一章 *介绍数据建模*，向您介绍了基本的数据建模概念和 NoSQL 领域。

第二章，“使用 MongoDB 进行数据建模”，为您提供了 MongoDB 的面向文档的架构概述，并向您展示了文档及其特征以及如何构建它。

第三章，“查询文档”，通过 MongoDB API 引导您查询文档，并向您展示查询如何影响我们的数据建模过程。

第四章，“索引”，解释了如何通过使用索引来改善查询的执行，并因此改变我们建模数据的方式。

第五章，“优化查询”，帮助您使用 MongoDB 的本机工具来优化您的查询。

第六章，“管理数据”，侧重于数据的维护。这将教会你在开始数据建模之前查看数据操作和管理的重要性。

第七章，“扩展”，向您展示了 MongoDB 的自动共享特性有多强大，以及我们如何认为我们的数据模型是分布式的。

第八章，“使用 MongoDB 进行日志记录和实时分析”，带您了解了一个真实问题示例的模式设计。

# 您需要为本书准备什么

要成功理解本书的每一章，您需要访问 MongoDB 3.0 实例。

您可以选择在何处以及如何运行它。我们知道有许多方法可以做到这一点。所以，选择一个。

要执行查询和命令，我建议您在 mongo shell 上执行此操作。每次我在 mongo shell 之外执行此操作时，我都会警告您。

在第八章，“使用 MongoDB 进行日志记录和实时分析”，您需要在计算机上安装 Node.js，并且应该可以访问您的 MongoDB 实例。

# 这本书是为谁准备的

本书假定您已经与 MongoDB 有过初次接触，并且具有一些 JavaScript 经验。本书适用于数据库管理员、开发人员或任何希望了解一些数据建模概念以及它们如何适用于 MongoDB 世界的人。它不会教您 JavaScript 或如何在计算机上安装 MongoDB。如果您是 MongoDB 初学者，您可以找到一些很好的 Packt Publishing 图书，这些图书将帮助您获得足够的经验，以更好地理解本书。

# 约定

在本书中，您将找到许多区分不同类型信息的文本样式。以下是这些样式的一些示例及其含义的解释。

文本中的代码单词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄显示如下：“我们可以将关系存储在`Group`文档中。”

代码块设置如下：

```sql
  collection.update({resource: resource, date: today},
    {$inc : {daily: 1}}, {upsert: true},
    function(error, result){
      assert.equal(error, null);
      assert.equal(1, result.result.n);
      console.log("Daily Hit logged");
      callback(result);
  });
```

当我们希望引起您对代码块的特定部分的注意时，相关的行或项目将以粗体显示：

```sql
var logMinuteHit = function(db, resource, callback) {
 // Get the events collection
  var collection = db.collection('events');
 // Get current minute to update
  var currentDate = new Date();
  var minute = currentDate.getMinutes();
  var hour = currentDate.getHours();
 // We calculate the minute of the day
  var minuteOfDay = minute + (hour * 60);
  var minuteField = util.format('minute.%s', minuteOfDay);
```

任何命令行输入或输出都以以下方式编写：

```sql
db.customers.find(
{"username": "johnclay"},
{_id: 1, username: 1, details: 1}
)

```

**新术语**和**重要单词**以粗体显示。

### 注意

警告或重要说明以这样的框出现。

### 提示

提示和技巧看起来像这样。

# 读者反馈

我们的读者的反馈总是受欢迎的。让我们知道您对本书的看法 - 您喜欢或不喜欢的内容。读者的反馈对我们很重要，因为它可以帮助我们开发您真正能够从中获益的标题。

要向我们发送一般反馈，只需发送电子邮件至`<feedback@packtpub.com>`，并在消息主题中提及书名。

如果您对某个主题有专业知识，并且有兴趣撰写或为一本书做出贡献，请参阅我们的作者指南[www.packtpub.com/authors](http://www.packtpub.com/authors)。

# 客户支持

现在您是 Packt 图书的自豪所有者，我们有一些事情可以帮助您充分利用您的购买。

## 下载示例代码

您可以从您在[`www.packtpub.com`](http://www.packtpub.com)的账户中下载示例代码文件，这适用于您购买的所有 Packt Publishing 图书。如果您在其他地方购买了这本书，您可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)并注册，以便文件直接发送到您的邮箱。

## 勘误表

尽管我们已经非常注意确保内容的准确性，但错误是难免的。如果您在我们的书籍中发现错误——也许是文本或代码中的错误——我们将不胜感激，如果您能向我们报告。通过这样做，您可以帮助其他读者避免挫折，并帮助我们改进本书的后续版本。如果您发现任何勘误，请访问[`www.packtpub.com/submit-errata`](http://www.packtpub.com/submit-errata)，选择您的书，点击**勘误提交表格**链接，并输入您的勘误详情。一旦您的勘误被验证，您的提交将被接受，并且勘误将被上传到我们的网站或添加到该标题的勘误部分的任何现有勘误列表中。

要查看先前提交的勘误表，请访问[`www.packtpub.com/books/content/support`](https://www.packtpub.com/books/content/support)，并在搜索框中输入书名。所需信息将出现在**勘误表**部分下。

## 盗版

互联网上盗版受版权保护的材料是一个持续存在的问题，涉及各种媒体。在 Packt，我们非常重视版权和许可的保护。如果您在互联网上发现我们作品的任何非法副本，请立即向我们提供位置地址或网站名称，以便我们采取补救措施。

请通过`<copyright@packtpub.com>`与我们联系，并附上疑似盗版材料的链接。

我们感谢您帮助我们保护作者和为您提供有价值内容的能力。

## 问题

如果您对本书的任何方面有问题，可以通过`<questions@packtpub.com>`与我们联系，我们将尽力解决问题。


# 第一章：介绍数据建模

数据建模是一个长期讨论的话题。因此，该领域的各种作者可能有不同的观点。不久前，当主要讨论集中在关系数据库上时，数据建模是领域中数据发现和分析过程的一部分。这是一个整体的视野，最终目标是拥有一个能够支持任何类型应用的强大数据库。

由于 NoSQL 数据库的灵活性，数据建模已经成为一个内部过程，您需要事先了解应用程序的需求或性能特征，才能最终得到一个良好的数据模型。

在本章中，我们将简要介绍多年来数据建模过程的历史，向您展示重要的概念。我们将涵盖以下主题：

+   MongoDB 和 NoSQL 的关系

+   介绍 NoSQL

+   数据库设计

# MongoDB 和 NoSQL 的关系

如果你在 Google 上搜索 MongoDB，你会找到大约 10,900,000 个结果。同样，如果你在 Google 上搜索 NoSQL，你会得到不少于 13,000,000 个结果。

现在，在 Google 趋势上，这是一个显示一个术语相对于全球所有搜索术语的搜索频率的工具，我们可以看到对这两个主题的兴趣增长是相当相似的：

![MongoDB 和 NoSQL 之间的关系](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-dt-mdl/img/B04075_01_01.jpg)

自 2009 年以来，NoSQL 和 MongoDB 术语的 Google 趋势搜索比较

但是，除了 MongoDB 是一个 NoSQL 数据库之外，这种关系实际上存在什么？

自 2009 年首次开源发布以来，由一家名为 10gen 的公司发布，MongoDB 成为了 Web 上许多玩家的选择，因此 DB-Engines（[`db-engines.com/en/`](http://db-engines.com/en/)）成为了第四受欢迎的数据库，也是最受欢迎的 NoSQL 数据库系统。

10gen 于 2013 年 8 月 27 日转变为 MongoDB Inc.，显示所有人的目光都集中在 MongoDB 及其生态系统上。向开源项目的转变对这一变化过程至关重要。特别是因为社区的采用量是巨大的。

根据 MongoDB 的现任主席兼联合创始人 Dwight Merriman：

> “我们的开源平台导致 MongoDB 在项目推出后的五年内被下载了 800 万次，这对于社区采用来说是一个非常快的速度。”

此外，MongoDB Inc.推出了产品和服务，以支持这个社区并丰富 MongoDB 生态系统。其中包括：

+   **MongoDB 企业**：MongoDB 的商业支持

+   **MongoDB 管理服务**：一种 SaaS 监控工具

+   **MongoDB 大学**：EdX 合作伙伴，提供免费的在线培训

与 NoSQL 运动一样，MongoDB 的发展也遵循了 Web 2.0 的挑战和机遇，NoSQL 运动已经有了很大的发展。

# 介绍 NoSQL（不仅仅是 SQL）

尽管这个概念是新的，但 NoSQL 是一个备受争议的话题。如果你进行广泛搜索，你可能会找到许多不同的解释。由于我们没有任何意图创造一个新的解释，让我们来看一下最常用的解释。

正如我们今天所知的，NoSQL 这个术语是由 Eric Evans 引入的，是在 Last.fm 的 Johan Oskarsson 组织的一次见面会后引入的。

事实上，Oskarsson 和其他参加 2009 年 6 月 11 日在旧金山举行的历史性会议的人已经讨论了许多今天我们称之为 NoSQL 数据库的数据库，比如 Cassandra、HBase 和 CouchDB。正如 Oskarsson 所描述的，会议是关于开源、分布式、非关系型数据库的，针对那些“…在传统关系数据库方面遇到了限制…”的人，目的是“…弄清楚为什么这些新潮的 Dynamo 克隆和 BigTables 最近变得如此受欢迎。”

四个月后，Evans 在他的博客中写道，除了 NoSQL 运动的增长和正在讨论的一切，他认为它们毫无意义。然而，Neo4J 的创始人兼 CEO Emil Eifren 在将术语命名为“Not Only SQL”时是正确的。

![介绍 NoSQL（不仅仅是 SQL）](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-dt-mdl/img/B04075_01_02.jpg)

Emil Eifrem 在 Twitter 上发布了介绍术语“Not Only SQL”的帖子

比起给 NoSQL 这个术语下一个定义，所有这些事件更重要的是作为讨论 NoSQL 真正含义的起点。如今，人们似乎普遍认为 NoSQL 是作为对关系数据库无法解决的问题的回应而诞生的。

值得注意的是，我们现在可以区分信息系统从 70 年代到今天必须解决的问题。那时，单片架构足以满足需求，与我们现在观察到的情况不同。

你有没有想过你已经在多少网站上拥有账户，比如社交网络、电子邮件提供商、流媒体服务和在线游戏？还有，你家里有多少设备现在连接到互联网？

不用担心如果你不能准确回答上面的问题。你并不孤单。随着每一个新的研究项目，全球范围内拥有互联网访问权限的用户数量增加，移动互联网访问所占的份额也越来越重要。

这意味着每一秒都在世界各地产生大量的非结构化或半结构化数据。数据量无法估计，因为用户是信息的主要来源。因此，越来越难以预测这种数据量何时或为何会发生变化。这只是世界上某个地方发生了不可预测的事件，比如进球、大罢工、大规模示威或飞机失事，就会导致交通变化，从而用户生成的内容增加。

作为对此的回应，NoSQL 技术的发展带来了各种不同的方法。

## NoSQL 数据库类型

正如之前所述，亚马逊和谷歌在 NoSQL 的发展方面处于前沿地位，借助 Amazon DynamoDB 和 Google BigTable。由于风格的多样性，我们不断开发新类型的 NoSQL 数据库。然而，基于数据模型，已知有四种基本类型：键值存储、宽列存储、文档数据库和图数据库，下面对它们进行了解释：

+   **键值存储**：键值是最简单和直接的数据模型之一，每个记录都存储为一个键和它的值。键值存储的例子有 Amazon Dynamo、Riak 和 Redis。

### 提示

Redis 可以被描述为一个高级的键值缓存和存储。由于它的键可以存储许多不同的数据类型并对这些类型运行原子操作，我们可以假设 Redis 是一个数据结构服务器。

+   **宽列存储**：在概念上，最接近关系数据库，因为它的数据是以表格形式表示的。然而，数据库存储的是数据列而不是行。宽列存储的例子有 Google BigTable、Cassandra 和 HBase。

+   **文档数据库**：顾名思义，这个数据库的数据模型以文档为主要概念。文档是存储数据的复杂结构，可以包含许多键值对、键数组对，甚至是嵌套文档。文档数据库的例子有 MongoDB、Apache CouchDB 和 Amazon SimpleDB。

+   **图数据库**：图数据库是存储关系最适合表示为图的数据项的最佳方式，比如网络拓扑和社交网络。节点、边和属性是存储数据的结构。图数据库的例子有 Neo4J 和 HyperGraphDB。

## 动态模式、可扩展性和冗余

尽管如前所述，NoSQL 数据库类型基于不同的数据模型，但它们有一些共同的特点。

为了支持非结构化或半结构化数据，NoSQL 数据库没有预定义的模式。动态模式使得在插入新数据时更容易进行实时更改，并且在需要数据迁移时更具成本效益。

为了处理不可预测的大量数据，NoSQL 数据库使用自动分片进行水平扩展，并确保数据的持续可用性。自动分片允许用户自动将数据和流量分布到多台服务器上。

NoSQL 数据库也支持本地复制，这使得您可以以快速简便的方式实现高可用性和恢复。随着我们分发数据的方式越来越多，我们的恢复策略也在改变，我们可能需要微调我们的一致性级别。

# 数据库设计和数据建模

在我开始写这一章之前（或者也许是在开始写这本书之前），我考虑过如何处理这个主题。首先，因为我猜想这是你的期望之一。其次，因为这是几乎每一本文献中都存在的一个主题，我不想（也不打算）引发这场讨论。

事实上，关于理论与实践的讨论，直到现在，我更倾向于实践方面。因此，我调查了许多不同的来源，希望能够阅读更多关于这个主题的内容，并可能在这本书中总结到目前为止关于这个主题的所有内容。

我在研究初期发现的许多内容都显示了数据库设计和数据建模之间的明显分离。然而，最终我的结论是，这两个概念之间的相似性要大于分歧。为了得出这个结论，我以 C.J. Date 在*数据库系统导论*中提到的一个事实为出发点，*Pearson Education*。

在其中，C.J. Date 说他更喜欢不使用术语数据建模，因为它可能指的是数据模型这个术语，这种关系可能会引起一些混淆。C.J. Date 提醒我们，在文献中术语数据模型有两个含义。第一个是数据模型是一般数据的模型，第二个是数据模型是与特定企业相关的持久数据的模型。Date 在他的书中选择了第一个定义。

正如 C.J. Date 所说：

> *"我们相信，在非关系型系统中进行数据库设计的正确方法是首先进行清晰的关系设计，然后，作为一个单独的后续步骤，将该关系设计映射到目标 DBMS 支持的任何非关系型结构（例如层次结构）中。"*

因此，谈论数据库设计是一个很好的开始。因此，C.J. Date 采用了语义建模或概念建模这个术语，并将这一活动定义为数据库设计过程中的一种辅助。

### 提示

如果你想了解更多，你可以在*数据库系统导论，第 8 版*，*第十四章*，*第 410 页*中找到。

我发现的另一个重要来源，以某种方式补充了 C.J. Date 的论点，是 Graeme Simsion 在*数据管理通讯*上发表的出版物，[`www.tdan.com`](http://www.tdan.com)以及他在书籍*数据建模：理论与实践*中的出版物，*Technics Publications LLC*。Graeme Simsion 是一位数据建模师，撰写了两本数据建模书籍，并且是墨尔本大学的研究员。

在大多数出版物中，Simsion 都在讨论数据库设计和数据建模的主题，并得出结论，数据建模是数据库设计的一门学科，因此数据模型是设计的单一和最重要的组成部分。

我们注意到，与 C.J. Date 不同，Graeme Simsion 使用了数据建模这个术语。

在其中一篇出版物中，Simsion 给我们带来了一个关于数据建模概念作为数据库设计过程的一部分的重要事实。他通过一些历史事实和与直接参与数据建模的人进行的研究来解释这一点。

从历史的角度来看，他提到了 3 模式架构对数据建模概念演变的重要性。

要理解这一演变，我们必须回到 1975 年。在那一年，美国国家标准协会的标准规划和需求委员会，也被称为 ANSI/SPARC/X3 数据管理系统研究小组，由查尔斯·巴赫曼领导，发表了一份报告，提出了一个 DBMS 架构。

这份报告介绍了一个抽象的 DBMS 架构，适用于任何数据模型，即一种方式，可以多重用户视图并感知数据。

3 模式架构是为了描述最终产品——数据库，而不是设计过程。然而，正如前面提到的，3 模式架构引入了直接影响数据库设计过程的概念，包括数据建模。在接下来的部分中，我们将通过 3 模式架构的概念来更好地理解数据建模概念。

## ANSI-SPARC 架构

ANSI-SPARC 架构建议使用三个视图（或三个模式）来：

+   隐藏用户对物理存储实现的细节

+   确保 DBMS 将为用户提供一致的数据访问，这意味着所有用户都有自己的视图

+   允许数据库管理员在不影响用户视图的情况下在物理级别上进行更改

### 外部级别

外部级别，也称为用户视图，详细说明了每个特定用户如何看待数据库。这个级别允许每个用户以不同的方式查看数据。因此，这也是保留用户特定要求信息的适当级别。外部模式描述了数据库为不同用户视图而结构化的方式。因此，我们可以为一个数据库拥有许多外部模式。

### 概念级别

尽管被许多人认为是最重要的级别，概念级别是架构中最后出现的级别。这个级别旨在展示数据库的逻辑结构。我们可以说这是数据库中存储的数据的一个抽象视图。

概念级别充当用户视图和数据库实现之间的层。因此，在这个级别上，不考虑有关物理实现和用户视图的细节和特殊性。

一旦概念级别到位，数据库管理员在这个架构级别中扮演着重要的角色，我们有一个数据库的全局视图。他们有责任定义逻辑结构。

关于概念级别非常有趣的一点是，我们必须记住这个级别与硬件或软件是独立的。概念模式定义了逻辑数据结构以及数据库中数据之间的关系。

### 内部级别

内部级别表示数据的存储方式。该模式定义了物理存储结构，如索引、数据字段和表示。数据库只有一个内部模式，但可能有多个概念模式的内部模式。

![内部级别](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-dt-mdl/img/B04075_01_03.jpg)

ANSI/SPARC/X3 数据库架构

查尔斯·巴赫曼和 ANSI/SPARC/X3 成员所展示的概念的引入非常有意义。他们带来了一种看待数据库的新方式，并引入了有助于发展数据建模学科的概念。

## 数据建模

正如我们之前所述，数据建模不再被视为一个独立的过程。它是数据库设计过程中的一个阶段，必须与业务分析一起完成的步骤。作为建模过程的最终结果，我们应该有逻辑数据模型。

这个建模过程引发了一个有争议的问题，即我们使用哪种方法。这个讨论的核心是什么是学术的，或者我们在实践中看到的。

对于 Matthew West 和 Julian Fowler 来说，看建模过程的一种方式如下图所示：

![数据建模](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-dt-mdl/img/B04075_01_04.jpg)

数据建模过程

Graeme Simsion 有一整篇关于这个讨论的文章。这篇文章展示了学术视角与现实视角对建模过程的不同看法。两者都给建模阶段起了名字，这些名字是完全不同的。

在撰写本章的过程中，我试图呈现的不仅是 Simsion 的研究，还有自从我开始与信息系统一起工作以来所经历的一切，以及对建模概念的广泛研究，以及我在许多其他来源中看到的无数观点。

此外，正如之前所述，并且 Simsion 所观察到的，三模式 ANSI-SPARC 架构在形成我们今天拥有的基本概念方面发挥了关键作用。随着关系模型和基于它的数据库管理系统的传播，支持旧的数据库架构，如分层和基于网络的架构的需求已经过去。然而，我们将建模过程分为两个阶段的方式仍然保留，一个阶段反映了与用户观点非常接近的概念，然后是自动转换为概念模式。

我们可以说，我们现在所知道的数据建模过程的阶段来自于 3 模式架构。不仅是概念，我们用来命名每个阶段的名字也是如此。

因此，我们最常见的是三种数据模型：概念模型、逻辑模型和物理模型。

### 概念模型

概念模型是一个实体和关系的地图，带有一些属性来说明。这是一个高层次的、抽象的视图，其目的是识别基本概念，非常接近用户感知数据的方式，而不是专注于业务的特定想法。

如果我们的受众是商业人士，那就是正确的模型。它经常用于描述通用领域概念，并且应该是与 DBMS 无关的。例如，我们可以提到实体，如人员、商店、产品、讲师、学生和课程。

在学术文献和实践中，广泛使用关系符号来表示概念模型，即使目标实现不是关系型数据库管理系统。事实上，这是一个很好的方法，正如 C.J. Date 所说。

概念模型的常见图形表示是流行的“鸦脚符号”。

![概念模型](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-dt-mdl/img/B04075_01_05.jpg)

鸦脚符号

人们常说，将概念模型限制在一页打印上是最佳实践。概念模型可以是一个图表，也可以是描述您已经确定的一切的文件。

### 逻辑模型

逻辑模型是更加符合业务的模型。这个模型也应该是与 DBMS 无关的，并且是从概念模型中派生出来的。

在这个模型中描述业务需求是很常见的。因此，在这个时候，数据建模者将更多地关注项目的范围。关系属性的基数和可空性以及数据类型和约束等细节也在这个模型中映射。与概念模型一样，通常使用关系符号来表示逻辑模型。数据建模者必须更多地在逻辑模型上工作。这是因为逻辑模型是建模者将探索所有可能性和不同想法的地方。

一般来说，逻辑模型是一个图形表示。最广泛使用的是 1976 年由 Peter Chen 提出的**实体-关系**（**ER**）模型。ER 模型具有符合逻辑模型所有需求的图形符号。

![逻辑模型](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-dt-mdl/img/B04075_01_06.jpg)

实体-关系图

### 物理模型

物理模型是一个更详细、不太通用的数据模型。在这个模型中，我们应该知道应该使用哪种技术。在这里，我们可以包括表、列名、键、索引、安全角色、验证规则，以及您作为数据建模者认为必要的任何细节。

为了清晰地将三级架构与物理模型联系起来，物理模型在某种程度上与架构的内部层级相关，因为在这个层级上，我们处理存储的数据如何呈现给用户。这个阶段的目标是拥有一个已实施的数据库。

# 总结

数据建模是数据库设计过程中的重要步骤。通过让所有利益相关者参与，有许多方法可以确保这个过程的高质量。在对数据进行建模后，您可能会对自己的数据有更好的了解。

话虽如此，我们应该始终考虑我们的数据，并使用一种技术来对其进行建模。

在本章中，您了解了 NoSQL 的历史，并全面探讨了数据库设计和数据建模。我们回顾了数据库架构，您也学习了概念、逻辑和物理模型。

现在您对数据建模有了更多了解，我们将在下一章中深入了解 MongoDB 数据模型及这些概念的应用。


# 第二章：使用 MongoDB 进行数据建模

数据建模是应用程序构思过程中非常重要的一步，因为这一步将帮助您定义数据库构建所需的必要要求。这个定义正是在数据建模过程中获得的数据理解的结果。

如前所述，无论选择的数据模型如何，这个过程通常分为两个阶段：一个非常接近用户视图，另一个是将这个视图转换为概念模式的阶段。在关系数据库建模的场景中，主要挑战是从这两个阶段构建一个强大的数据库，以确保在应用程序生命周期中对其进行任何影响的更新。

与关系数据库相比，NoSQL 数据库在这一点上更灵活，因为它可以使用无模式模型，理论上可以在数据模型需要修改时对用户视图造成较小的影响。

尽管 NoSQL 提供了灵活性，但在建模 NoSQL 数据库时，事先了解如何使用数据是很重要的。即使在 NoSQL 数据库中，也最好不要计划要持久化的数据格式。此外，乍一看，这是数据库管理员，对关系世界非常熟悉的人，变得更加不舒服的地方。

关系数据库标准，如 SQL，通过制定规则、规范和标准，为我们带来了安全感和稳定性。另一方面，我们敢说，这种安全感使数据库设计人员远离了要存储的数据所在的领域。

应用程序开发人员也遇到了同样的问题。他们与数据库管理员之间存在明显的利益分歧，特别是在数据模型方面。

NoSQL 数据库实际上带来了数据库专业人员和应用程序之间的一种接近的需求，也需要开发人员和数据库之间的一种接近。

因此，即使您可能是数据建模师/设计师或数据库管理员，如果我们从现在开始讨论超出您舒适区域的主题，也不要害怕。准备好开始使用应用程序开发人员的观点常见的词汇，并将其添加到您的词汇表中。本章将介绍 MongoDB 数据模型以及用于开发和维护该模型的主要概念和结构。

本章将涵盖以下内容：

+   介绍您的文档和集合

+   文档的特征和结构

+   展示文档的设计和模式

# 介绍文档和集合

MongoDB 将文档作为数据的基本单元。MongoDB 中的文档以**JavaScript 对象表示法**（**JSON**）表示。

集合是文档的组合。打个比方，集合类似于关系模型中的表，文档是该表中的记录。最后，集合属于 MongoDB 中的数据库。

文档以一种称为**二进制 JSON**（**BSON**）的格式序列化在磁盘上，这是 JSON 文档的二进制表示。

文档的示例是：

```sql
{
   "_id": 123456,
   "firstName": "John",
   "lastName": "Clay",
   "age": 25,
   "address": {
      "streetAddress": "131 GEN. Almério de Moura Street",
      "city": "Rio de Janeiro",
      "state": "RJ",
      "postalCode": "20921060"
   },
   "phoneNumber":[
      {
         "type": "home",
         "number": "+5521 2222-3333"
      },
      {
         "type": "mobile",
         "number": "+5521 9888-7777"
      }
   ]
}
```

与关系模型不同，您必须声明表结构，集合不会强制执行文档的特定结构。一个集合可能包含完全不同结构的文档。

例如，在同一个`users`集合中，我们可以有：

```sql
{
   "_id": "123456",
   "username": "johnclay",
   "age": 25,
   "friends":[
      {"username": "joelsant"},
      {"username": "adilsonbat"}
   ],
   "active": true,
   "gender": "male"
}
```

我们还可以有：

```sql
{
   "_id": "654321",
   "username": "santymonty",
   "age": 25,
   "active": true,
   "gender": "male",
   "eyeColor": "brown"
}
```

除此之外，MongoDB 的另一个有趣特性是不仅数据由文档表示。基本上，所有用户与 MongoDB 的交互都是通过文档进行的。除了数据记录，文档还是一种：

+   定义可以在查询中读取、写入和/或更新的数据

+   定义将要更新的字段

+   创建索引

+   配置复制

+   从数据库中查询信息

在我们深入讨论文档的技术细节之前，让我们探索它们的结构。

## JSON

**JSON**是一种用于数据的开放标准表示的文本格式，非常适合数据传输。要深入探索 JSON 格式，您可以查看*ECMA-404 JSON 数据交换标准*，其中对 JSON 格式进行了全面描述。

### 注意

JSON 由两个标准描述：ECMA-404 和 RFC 7159。第一个更注重 JSON 语法和语法，而第二个提供了语义和安全性考虑。

顾名思义，JSON 源自 JavaScript 语言。它作为解决方案出现，用于在 Web 服务器和浏览器之间传输对象状态。尽管它是 JavaScript 的一部分，但几乎所有最流行的编程语言（如 C、Java 和 Python）都可以找到 JSON 的生成器和读取器。

JSON 格式也被认为非常友好和易读。JSON 不依赖于所选择的平台，其规范基于两种数据结构：

+   一组或一组键/值对

+   一个值有序列表

因此，为了澄清任何疑问，让我们谈谈对象。对象是一组非有序的键/值对，由以下模式表示：

```sql
{
   "key" : "value"
}
```

关于值有序列表，集合表示如下：

```sql
["value1", "value2", "value3"]
```

在 JSON 规范中，值可以是：

+   用`" "`括起来的字符串

+   一个带或不带符号的数字，以十进制（基数 10）为基础。这个数字可以有一个由句点（`.`）分隔的小数部分，或者是一个指数部分，后面跟着`e`或`E`

+   布尔值（`true`或`false`）

+   一个`null`值

+   另一个对象

+   另一个值有序数组

以下图表显示了 JSON 值结构：

![JSON](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-dt-mdl/img/B04075_02_01.jpg)

以下是描述一个人的 JSON 代码示例：

```sql
{
   "name" : "Han",
   "lastname" : "Solo",
   "position" : "Captain of the Millenium Falcon",
   "species" : "human",
   "gender":"male",
   "height" : 1.8
}
```

## BSON

**BSON**意味着**Binary JSON**，换句话说，是 JSON 文档的二进制编码序列化。

### 注意

如果您想了解更多关于 BSON 的知识，我建议您查看[`bsonspec.org/`](http://bsonspec.org/)上的 BSON 规范。

如果我们将 BSON 与其他二进制格式进行比较，BSON 具有更灵活的模型优势。此外，其特点之一是它的轻量级-这是 Web 上数据传输非常重要的特性。

BSON 格式被设计为在大多数基于 C 的编程语言中易于导航，并且以非常高效的方式进行编码和解码。这就是为什么 BSON 被选择为 MongoDB 磁盘持久化的数据格式的原因。

BSON 中的数据表示类型有：

+   字符串 UTF-8（`string`）

+   整数 32 位（`int32`）

+   整数 64 位（`int64`）

+   浮点数（`double`）

+   文档（`document`）

+   数组（`document`）

+   二进制数据（`binary`）

+   布尔值 false（`\x00`或字节 0000 0000）

+   布尔值 true（`\x01`或字节 0000 0001）

+   UTC 日期时间（`int64`）- int64 是自 Unix 纪元以来的 UTC 毫秒数

+   时间戳（`int64`）-这是 MongoDB 复制和分片中使用的特殊内部类型；前 4 个字节是增量，最后 4 个字节是时间戳

+   空值（）

+   正则表达式（`cstring`）

+   JavaScript 代码（`string`）

+   JavaScript 代码 w/范围（`code_w_s`）

+   Min key() - 比所有其他可能的 BSON 元素值都要低的特殊类型

+   Max key() - 比所有其他可能的 BSON 元素值都要高的特殊类型

+   对象 ID（`byte`*12）

# 文档的特征

在我们详细讨论如何对文档进行建模之前，我们需要更好地了解一些其特征。这些特征可以决定您对文档建模的决定。

## 文档大小

我们必须记住，BSON 文档的最大长度为 16 MB。根据 BSON 规范，这个长度非常适合通过 Web 进行数据传输，并且可以避免过度使用 RAM。但这只是一个建议。如今，通过使用 GridFS，文档可以超过 16 MB 的长度。

### 注意

GridFS 允许我们将大于 BSON 最大大小的文档存储在 MongoDB 中，方法是将其分成部分或块。每个块都是一个新的文档，大小为 255K。

## 文档中字段的名称和值

有一些关于文档中字段的名称和值的事情你必须知道。首先，文档中任何字段的名称都是一个字符串。通常情况下，我们对字段名称有一些限制。它们是：

+   `_id`字段保留用于主键

+   你不能以字符`$`开头

+   名称不能有空字符，或（`.`）

此外，具有索引字段的文档必须遵守索引字段的大小限制。值不能超过 1,024 字节的最大大小。

## 文档的主键

如前一节所示，`_id`字段保留用于主键。默认情况下，这个字段必须是文档中的第一个字段，即使在插入时它不是第一个要插入的字段。在这种情况下，MongoDB 会将其移动到第一个位置。此外，根据定义，唯一索引将在此字段中创建。

`_id`字段可以有任何 BSON 类型的值，除了数组。此外，如果创建文档时没有指定`_id`字段，MongoDB 将自动创建一个 ObjectId 类型的`_id`字段。但这不是唯一的选择。只要是唯一的，你可以使用任何值来标识你的文档。还有另一种选择，即基于支持集合或乐观循环生成自增值。

## 支持集合

在这种方法中，我们使用一个单独的集合来保存序列中最后使用的值。要增加序列，首先我们应该查询最后使用的值。之后，我们可以使用`$inc`操作符来增加值。

### 注意

有一个名为`system.js`的集合，可以保存 JavaScript 代码以便重用。请注意不要在这个集合中包含应用程序逻辑。

让我们看一个例子：

```sql
db.counters.insert(
 {
 _id: "userid",
 seq: 0
 }
)

function getNextSequence(name) {
 var ret = db.counters.findAndModify(
 {
 query: { _id: name },
 update: { $inc: { seq: 1 } },
 new: true
 }
 );
 return ret.seq;
}

db.users.insert(
 {
 _id: getNextSequence("userid"),
 name: "Sarah C."
 }
)

```

## 乐观循环

通过乐观循环生成`_id`字段是通过递增每次迭代，然后尝试将其插入新文档：

```sql
function insertDocument(doc, targetCollection) {
    while (1) {
        var cursor = targetCollection.find( {}, { _id: 1 } ).sort( { _id: -1 } ).limit(1);
        var seq = cursor.hasNext() ? cursor.next()._id + 1 : 1;
        doc._id = seq;
        var results = targetCollection.insert(doc);
        if( results.hasWriteError() ) {
            if( results.writeError.code == 11000 /* dup key */ )
                continue;
            else
                print( "unexpected error inserting data: " + tojson( results ) );
        }
        break;
    }
}
```

在这个函数中，迭代执行以下操作：

1.  在`targetCollection`中搜索`_id`的最大值。

1.  为`_id`设置下一个值。

1.  设置要插入的文档的值。

1.  插入文档。

1.  在由于重复的`_id`字段而导致的错误情况下，循环会重复自身，否则迭代结束。

### 注意

这里展示的要点是理解这个工具可以提供的所有可能性和方法的基础。但是，尽管我们可以为 MongoDB 使用自增字段，但我们必须避免使用它们，因为这个工具不适用于大数据量的情况。

# 设计文档

在这一点上，我相信你一定会问自己：如果文档的基本结构是 JSON（一种如此简单和文本化的东西），那么创建 NoSQL 数据库会有什么复杂之处呢？

让我们看看！首先，是的！你是对的。NoSQL 数据库可以非常简单。但是，这并不意味着它们的结构会比关系数据库更简单。它会有所不同！

如前所述，集合不会强制你预先定义文档的结构。但这肯定是你必须在某个时候做出的决定。这个决定将影响重要的方面，特别是与查询性能有关的方面。

到目前为止，你可能也问过自己应用程序如何表示文档之间的关系。如果你直到现在才想到这个问题，那不是你的错。我们习惯于思考关系世界，比如想知道学生和他们的课程之间的关系，或者产品和订单之间的关系。

MongoDB 也有自己表示这种关系的方式。事实上，有两种方式：

+   嵌入式文档

+   引用

## 使用嵌入式文档

通过使用子文档，我们可以构建更复杂和优化的数据结构。因此，当我们建模一个文档时，我们可以选择在一个文档中嵌入相关数据。

决定在一个文档中嵌入数据往往与意图获得更好的读取性能有关，因为只需一个查询，我们就可以完全检索所需的信息。

看下面的例子：

```sql
{
   id: 1,
   title: "MongoDB Data Modeling Blog post",
   body: "MongoDB Data Modeling....",
   author: "Wilson da Rocha França",
   date: ISODate("2014-11-19"),
   comments: [
      {
         name: "Mike",
         email : "mike@mike.com",
         comment: "Mike comment...."
      },
      {
         name: "Tom",
         email : "tom@tom.com",
         comment: "Tom comment...."
      },
      {
         name: "Yuri",
         email : "yuri@yuri.com",
         comment: "Yuri comment...."
      }
   ],
   tags: ["mongodb", "modeling", "nosql"]
}
```

正如我们可以推断的，这个文档代表了一篇博客文章。这种文档的优势在于，只需一个查询，我们就可以获得向用户展示所需的所有数据。更新也是一样：只需一个查询，我们就可以修改这个文档的内容。然而，当我们决定嵌入数据时，我们必须确保文档不超过 16MB 的 BSON 大小限制。

在 MongoDB 中嵌入数据没有规则，但总体上，我们应该观察：

+   我们是否在文档之间有一对一的关系。

+   我们是否在文档之间有一对多的关系，以及“多”部分与“一”部分的关系非常依赖于“一”部分。这意味着，例如，每次我们展示“一”部分时，我们也会展示关系的“多”部分。

如果我们的模型符合前述情况之一，我们应该考虑使用嵌入式文档。

## 使用引用

规范化是帮助构建关系数据模型的基本过程。为了最小化冗余，在这个过程中我们将较大的表分成较小的表，并在它们之间定义关系。我们可以说，在 MongoDB 中创建引用是我们“规范化”模型的方式。这个引用将描述文档之间的关系。

你可能会困惑为什么我们在非关系型的世界中考虑关系，尽管这并不意味着在 NoSQL 数据库中不存在关系。我们经常会使用关系建模的概念来解决常见问题。正如前面所述，为了消除冗余，文档可以相互引用。

但等等！现在有一件非常重要的事情你应该知道：MongoDB 不支持连接。这意味着，即使有对另一个文档的引用，你仍然需要至少执行两次查询才能获取完整的所需信息。

看下面的例子：

```sql
{
   _id: 1,
   name : "Product 1",
   description: "Product 1 description",
   price: "$10,00",
   supplier : { 
      name: "Supplier 1", 
      address: "St.1", 
      telephone: "+552199999999" 
   }
}

{
   _id: 2,
   name : "Product 2",
   description: "Product 2 description",
   price: "$10,00",
   supplier : { 
      name: "Supplier 1", 
      address: "St.1", 
      telephone: "+552199999999" 
   }
}

{
   _id: 3,
   name : "Product 3",
   description: "Product 3 description",
   price: "$10,00",
   supplier : { 
      name: "Supplier 1", 
      address: "St.1", 
      telephone: "+552199999999" 
   }
}
```

在前面的例子中，我们有来自`products`集合的文档。我们可以看到，在这三个产品实例中，供应商键的值是相同的。除了这些重复的数据，我们可以有两个集合：`products`和`suppliers`，就像下面的例子中所示：

```sql
suppliers

{
   _id: 1
   name: "Supplier 1", 
   address: "St.1", 
   telephone: "+552199999999",
   products: [1, 2, 3]
}

products 

{
   _id: 1,
   name : "Product 1",
   description: "Product 1 description",
   price: "$10,00"
}

{
   _id: 2,
   name : "Product 2",
   description: "Product 2 description",
   price: "$10,00"
}

{
   _id: 3,
   name : "Product 3",
   description: "Product 3 description",
   price: "$10,00"
}
```

在这种特殊情况下，对于供应商的少量产品，基于供应商引用产品是一个不错的选择。然而，如果情况相反，更好的方法是：

```sql
suppliers

{
   _id: 1
   name: "Supplier 1", 
   address: "St.1", 
   telephone: "+552199999999"
}

products 

{
   _id: 1,
   name : "Product 1",
   description: "Product 1 description",
   price: "$10,00",
   supplier: 1
}

{
   _id: 2,
   name : "Product 2",
   description: "Product 2 description",
   price: "$10,00",
   supplier: 1
}

{
   _id: 3,
   name : "Product 3",
   description: "Product 3 description",
   price: "$10,00",
   supplier: 1
}
```

在 MongoDB 中使用引用没有规则，但总体上，我们应该观察：

+   我们是否在嵌入数据时重复相同的信息多次（这会影响读取性能）

+   我们是否需要表示多对多的关系

+   我们的模型是否是一个层次结构

如果我们的模型符合前述情况之一，我们应该考虑使用引用。

## 原子性

在设计文档时，会影响我们决策的另一个重要概念是原子性。在 MongoDB 中，操作在文档级别是原子的。这意味着我们可以一次修改一个文档。即使我们的操作在集合中的多个文档中进行，这个操作也会一次在一个文档中进行。

因此，当我们决定使用嵌入数据来建模文档时，我们只需编写操作，因为我们需要的所有数据都在同一个文档中。这与选择引用数据时的情况相反，那时我们需要许多不是原子的写操作。

# 常见的文档模式

现在我们了解了如何设计我们的文档，让我们来看一些现实生活中的问题示例，比如如何编写更好地描述实体之间关系的数据模型。

本节将向您展示一些模式，说明何时嵌入或引用文档。到目前为止，我们已经考虑了一个决定性因素：

+   是否一致性是优先级

+   是否读取是优先级

+   是否写入是优先级

+   我们将进行哪些更新查询

+   文档增长

## 一对一

一对一关系比其他关系更简单。大多数情况下，我们将使用嵌入文档来映射这种关系，特别是如果它是一个“包含”关系的话。

以下示例显示了一个客户的文档。在第一种情况下，在`customerDetails`文档中有一个引用；在第二种情况下，我们看到了一个带有嵌入数据的引用：

+   引用数据：

```sql
customer
{ 
   "_id": 5478329cb9617c750245893b
   "username" : "John Clay",
   "email": "johnclay@crgv.com",
   "password": "bf383e8469e98b44895d61b821748ae1"
}
customerDetails
{
   "customer_id": "5478329cb9617c750245893b",
   "firstName": "John",
   "lastName": "Clay",
   "gender": "male",
   "age": 25
}
```

+   使用嵌入数据：

```sql
customer
{ 
   _id: 1
   "username" : "John Clay",
   "email": "johnclay@crgv.com",
   "password": "bf383e8469e98b44895d61b821748ae1"
   "details": {
 "firstName": "John",
 "lastName": "Clay",
 "gender": "male",
 "age": 25
 }
}
```

使用嵌入文档表示关系的优势在于，当我们查询客户时，客户详细数据始终可用。因此，我们可以说客户的详细信息本身并没有意义，只有与客户数据一起才有意义。

## 一对多

一对多关系比一对一关系更复杂。为了决定何时嵌入或引用，我们必须考虑关系的“多”方。如果多方应该与其父级一起显示，那么我们应该选择嵌入数据；否则，我们可以在父级上使用引用。

让我们看一个`customer`和客户的地址的例子：

```sql
customer
{ 
   _id: 1
   "username" : "John Clay",
   "email": "johnclay@crgv.com",
   "password": "bf383e8469e98b44895d61b821748ae1"
   "details": {
      "firstName": "John",
      "lastName": "Clay",
      "gender": "male",
      "age": 25
   }
}

address
{
   _id: 1,
   "street": "Address 1, 111",
   "city": "City One",
   "state": "State One",
   "type": "billing",
   "customer_id": 1
}
{
   _id: 2,
   "street": "Address 2, 222",
   "city": "City Two",
   "state": "State Two",
   "type": "shipping",
   "customer_id": 1
}
{
   _id: 3,
   "street": "Address 3, 333",
   "city": "City Three",
   "state": "State Three",
   "type": "shipping",
   "customer_id": 1
}
```

如果每次您想要显示客户的地址时，还需要显示客户的姓名，那么建议使用嵌入文档：

```sql
customer
{ 
   _id: 1
   "username" : "John Clay",
   "email": "johnclay@crgv.com",
   "password": "bf383e8469e98b44895d61b821748ae1"
   "details": {
      "firstName": "John",
      "lastName": "Clay",
      "gender": "male",
      "age": 25
   }
   "billingAddress": [{
      "street": "Address 1, 111",
      "city": "City One",
      "state": "State One",
      "type": "billing",
   }],

   "shippingAddress": [{
      "street": "Address 2, 222",
      "city": "City Two",
      "state": "State Two",
      "type": "shipping"
   },
   {
      "street": "Address 3, 333",
      "city": "City Three",
      "state": "State Three",
      "type": "shipping"
   }]
}
```

## 多对多

一对多关系并不是一件微不足道的事情，即使在关系型宇宙中也是如此。在关系世界中，这种关系通常被表示为连接表，而在非关系世界中，它可以以许多不同的方式表示。

在以下代码中，我们将看到一个`user`和`group`关系的经典示例：

```sql
user

{
   _id: "5477fdea8ed5881af6541bf1",
   "username": "user_1",
   "password" : "3f49044c1469c6990a665f46ec6c0a41"
}

{
   _id: "54781c7708917e552d794c59",
   "username": "user_2",
   "password" : "15e1576abc700ddfd9438e6ad1c86100"
}

group

{
   _id: "54781cae13a6c93f67bdcc0a",
   "name": "group_1"
}

{
   _id: "54781d4378573ed5c2ce6100",
   "name": "group_2"
}
```

现在让我们在`User`文档中存储关系：

```sql
user

{
   _id: "5477fdea8ed5881af6541bf1",
   "username": "user_1",
   "password" : "3f49044c1469c6990a665f46ec6c0a41",
   "groups": [
      {
         _id: "54781cae13a6c93f67bdcc0a",
         "name": "group_1"
      },
      {
         _id: "54781d4378573ed5c2ce6100",
         "name": "group_2"
      }

   ]
}

{
   _id: "54781c7708917e552d794c59",
   "username": "user_2",
   "password" : "15e1576abc700ddfd9438e6ad1c86100",
   "groups": [
      {
         _id: "54781d4378573ed5c2ce6100",
         "name": "group_2"
      }

   ]
}

group
{
   _id: "54781cae13a6c93f67bdcc0a",
   "name": "group_1"
}

{
   _id: "54781d4378573ed5c2ce6100",
   "name": "group_2"
}
```

或者我们可以在`group`文档中存储关系：

```sql
user
{
   _id: "5477fdea8ed5881af6541bf1",
   "username": "user_1",
   "password" : "3f49044c1469c6990a665f46ec6c0a41"
}
{
   _id: "54781c7708917e552d794c59",
   "username": "user_2",
   "password" : "15e1576abc700ddfd9438e6ad1c86100"
}
group
{
   _id: "54781cae13a6c93f67bdcc0a",
   "name": "group_1",
   "users": [
      {
         _id: "54781c7708917e552d794c59",
         "username": "user_2",
         "password" : "15e1576abc700ddfd9438e6ad1c86100"
      }

   ]
}
{
   _id: "54781d4378573ed5c2ce6100",
   "name": "group_2",
   "users": [
      {
         _id: "5477fdea8ed5881af6541bf1",
         "username": "user_1",
         "password" :  "3f49044c1469c6990a665f46ec6c0a41"
      },
      {
         _id: "54781c7708917e552d794c59",
         "username": "user_2",
         "password" :  "15e1576abc700ddfd9438e6ad1c86100"
      }

   ]
}
```

最后，让我们在两个文档中存储关系：

```sql
user
{
   _id: "5477fdea8ed5881af6541bf1",
   "username": "user_1",
   "password" : "3f49044c1469c6990a665f46ec6c0a41",
   "groups": ["54781cae13a6c93f67bdcc0a", "54781d4378573ed5c2ce6100"]
}
{
   _id: "54781c7708917e552d794c59",
   "username": "user_2",
   "password" : "15e1576abc700ddfd9438e6ad1c86100",
   "groups": ["54781d4378573ed5c2ce6100"]
}
group
{
   _id: "54781cae13a6c93f67bdcc0a",
   "name": "group_1",
   "users": ["5477fdea8ed5881af6541bf1"]
}
{
   _id: "54781d4378573ed5c2ce6100",
   "name": "group_2",
   "users": ["5477fdea8ed5881af6541bf1", "54781c7708917e552d794c59"]
}
```

# 摘要

在本章中，您了解了如何在 MongoDB 中构建文档，检查了它们的特性，并了解了它们是如何组织成集合的。

您现在了解了已经知道应用程序领域对于设计最佳模型有多么重要，您也看到了一些可以帮助您决定如何设计文档的模式。

在下一章中，我们将看到如何查询这些集合并修改其中存储的数据。


# 第三章：查询文档

在 NoSQL 数据库中，比如 MongoDB，规划查询是一项非常重要的任务，根据您要执行的查询，您的文档可能会有很大的变化。

在第二章中，*使用 MongoDB 进行数据建模*，决定在集合中引用或包含文档，在很大程度上是我们规划的结果。确定我们是否偏向于在集合中进行读取或写入是至关重要的。

在这里，我们将看到如何规划查询可以帮助我们更有效地创建文档，我们还将考虑更明智的问题，比如原子性和事务。

本章将重点关注以下主题：

+   读取操作

+   写操作

+   写入关注点

+   批量写入文档

# 理解读取操作

在数据库中，读取是最常见和基本的操作。很难想象一个仅用于写入信息的数据库，这些信息从不被读取。顺便说一句，我从未听说过这种方法。

在 MongoDB 中，我们可以通过`find`接口执行查询。`find`接口可以接受查询作为条件和投影作为参数。这将产生一个游标。游标有可以用作执行查询的修饰符的方法，比如`limit`、`map`、`skip`和`sort`。例如，看一下以下查询：

```sql
db.customers.find({"username": "johnclay"})

```

这将返回以下文档：

```sql
{
 "_id" : ObjectId("54835d0ff059b08503e200d4"),
 "username" : "johnclay",
 "email" : "johnclay@crgv.com",
 "password" : "bf383e8469e98b44895d61b821748ae1",
 "details" : {
 "firstName" : "John",
 "lastName" : "Clay",
 "gender" : "male",
 "age" : 25
 },
 "billingAddress" : [
 {
 "street" : "Address 1, 111",
 "city" : "City One",
 "state" : "State One"
 }
 ],
 "shippingAddress" : [
 {
 "street" : "Address 2, 222",
 "city" : "City Two",
 "state" : "State Two"
 },
 {
 "street" : "Address 3,333",
 "city" : "City Three",
 "state" : "State Three"
 }
 ]
}

```

我们可以使用`find`接口在 MongoDB 中执行查询。`find`接口将选择集合中的文档，并返回所选文档的游标。

与 SQL 语言相比，`find`接口应该被视为`select`语句。类似于`select`语句，我们可以使用表达式和谓词确定子句，`find`接口允许我们使用条件和投影作为参数。

如前所述，我们将在这些`find`接口参数中使用 JSON 文档。我们可以以以下方式使用`find`接口：

```sql
db.collection.find(
 {criteria}, 
 {projection}
)

```

在这个例子中：

+   `criteria`是一个 JSON 文档，将使用一些运算符指定集合中文档的选择条件

+   `projection`是一个 JSON 文档，将指定集合中将作为查询结果返回的文档字段

这两个都是可选参数，我们稍后将更详细地讨论这些。

让我们执行以下示例：

```sql
db.customers.find(
{"username": "johnclay"}, 
{_id: 1, username: 1, details: 1}
)

```

在这个例子中：

+   `{"username": "johnclay"}`是条件

+   `{_id: 1, username: 1, details: 1}`是投影

这个查询将产生这个文档：

```sql
{
 "_id" : ObjectId("54835d0ff059b08503e200d4"),
 "username" : "johnclay",
 "details" : {
 "firstName" : "John",
 "lastName" : "Clay",
 "gender" : "male",
 "age" : 25
 }
}

```

## 选择所有文档

如前所述，在`find`接口中，条件和投影参数都是可选的。在没有任何参数的情况下使用`find`接口意味着选择集合中的所有文档。

### 注意

请注意，查询结果是一个包含所有所选文档的游标。

因此，`products`集合中的查询以这种方式执行：

```sql
db.products.find()

```

它将返回：

```sql
{ 
 "_id" : ObjectId("54837b61f059b08503e200db"), 
 "name" : "Product 1", 
 "description" : "Product 1 description", 
 "price" : 10, 
 "supplier" : { 
 "name" : "Supplier 1", 
 "telephone" : "+552199998888" 
 } 
}
{ 
 "_id" : ObjectId("54837b65f059b08503e200dc"), 
 "name" : "Product 2", 
 "description" : "Product 2 description", 
 "price" : 20, 
 "supplier" : { 
 "name" : "Supplier 2", 
 "telephone" : "+552188887777" 
 } 
}
…

```

## 使用条件选择文档

尽管方便，但选择集合中的所有文档可能会因为集合的长度而变得不切实际。举个例子，如果一个集合中有数百、数千或数百万条记录，就必须创建一个标准，以便只选择我们想要的文档。

然而，没有什么可以阻止查询结果变得非常庞大。在这种情况下，根据执行查询的所选驱动器，我们必须迭代返回的游标。

### 注意

请注意，在 mongo shell 中，返回记录的默认值为 20。

让我们检查以下示例查询。我们想选择属性名称为`Product 1`的文档：

```sql
db.products.find({name: "Product 1"});

```

这将给我们一个结果：

```sql
{
 "_id" : ObjectId("54837b61f059b08503e200db"),
 "name" : "Product 1",
 "description" : "Product 1 description",
 "price" : 10,
 "supplier" : {
 "name" : "Supplier 1",
 "telephone" : "+552199998888"
 }
}

```

上述查询通过相等性`{name: "Product 1"}`选择文档。还可以在条件接口上使用运算符。

以下示例演示了如何选择所有价格大于 10 的文档：

```sql
db.products.find({price: {$gt: 10}});

```

这将产生如下结果：

```sql
{ 
 "_id" : ObjectId("54837b65f059b08503e200dc"), 
 "name" : "Product 2", 
 "description" : "Product 2 description", 
 "price" : 20, 
 "supplier" : { 
 "name" : "Supplier 2", 
 "telephone" : "+552188887777" 
 } 
}
{ 
 "_id" : ObjectId("54837b69f059b08503e200dd"), 
 "name" : "Product 3", 
 "description" : "Product 3 description", 
 "price" : 30, 
 "supplier" : { 
 "name" : "Supplier 3", 
 "telephone" : "+552177776666" 
 }
}

```

当我们使用 `$gt` 运算符执行查询时，只有价格信息大于 10 的文档将作为游标结果返回。

此外，还有其他运算符，如比较、逻辑、元素、评估、地理和数组运算符。

例如，我们从 `products` 集合中选择的文档如下所示：

```sql
{
 "_id" : ObjectId("54837b61f059b08503e200db"),
 "name" : "Product 1",
 "description" : "Product 1 description",
 "price" : 10,
 "supplier" : {
 "name" : "Supplier 1",
 "telephone" : "+552199998888"
 },
 "review" : [
 {
 "customer" : {
 "email" : "customer@customer.com"
 },
 "stars" : 5
 },
 {
 "customer" : {
 "email" : "customer2@customer.com"
 },
 "stars" : 6
 }
 ]
}
{
 "_id" : ObjectId("54837b65f059b08503e200dc"),
 "name" : "Product 2",
 "description" : "Product 2 description",
 "price" : 20,
 "supplier" : {
 "name" : "Supplier 2",
 "telephone" : "+552188887777"
 },
 "review" : [
 {
 "customer" : {
 "email" : "customer@customer.com"
 },
 "stars" : 10
 },
 {
 "customer" : {
 "email" : "customer2@customer.com"
 },
 "stars" : 2
 }
 ]
}
{
 "_id" : ObjectId("54837b69f059b08503e200dd"),
 "name" : "Product 3",
 "description" : "Product 3 description",
 "price" : 30,
 "supplier" : {
 "name" : "Supplier 3",
 "telephone" : "+552177776666"
 },
 "review" : [
 {
 "customer" : {
 "email" : "customer@customer.com"
 },
 "stars" : 5
 },
 {
 "customer" : {
 "email" : "customer2@customer.com"
 },
 "stars" : 9
 }
 ]
}

```

## 比较运算符

MongoDB 为我们提供了一种定义值之间相等关系的方式。通过比较运算符，我们可以比较 BSON 类型的值。让我们看看这些运算符：

+   `$gte` 运算符负责搜索等于或大于查询中指定值的值。如果我们执行查询 `db.products.find({price: {$gte: 20}})`，它将返回：

```sql
{
 "_id" : ObjectId("54837b65f059b08503e200dc"),
 "name" : "Product 2",
 "description" : "Product 2 description",
 "price" : 20,
 "supplier" : {
 "name" : "Supplier 2",
 "telephone" : "+552188887777"
 },
 "review" : [
 {
 "customer" : {
 "email" : "customer@customer.com"
 },
 "stars" : 10
 },
 {
 "customer" : {
 "email" : "customer2@customer.com"
 },
 "stars" : 2
 }
 ]
}
{
 "_id" : ObjectId("54837b69f059b08503e200dd"),
 "name" : "Product 3",
 "description" : "Product 3 description",
 "price" : 30,
 "supplier" : {
 "name" : "Supplier 3",
 "telephone" : "+552177776666"
 },
 "review" : [
 {
 "customer" : {
 "email" : "customer@customer.com"
 },
 "stars" : 5
 },
 {
 "customer" : {
 "email" : "customer2@customer.com"
 },
 "stars" : 9
 }
 ]
}

```

+   使用 `$lt` 运算符，可以搜索小于查询中请求的值的值。查询 `db.products.find({price: {$lt: 20}})` 将返回：

```sql
{
 "_id" : ObjectId("54837b61f059b08503e200db"),
 "name" : "Product 1",
 "description" : "Product 1 description",
 "price" : 10,
 "supplier" : {
 "name" : "Supplier 1",
 "telephone" : "+552199998888"
 },
 "review" : [
 {
 "customer" : {
 "email" : "customer@customer.com"
 },
 "stars" : 5
 },
 {
 "customer" : {
 "email" : "customer2@customer.com"
 },
 "stars" : 6
 }
 ]
}

```

+   `$lte` 运算符搜索小于或等于查询中请求的值的值。如果我们执行查询 `db.products.find({price: {$lte: 20}})`，它将返回：

```sql
{
 "_id" : ObjectId("54837b61f059b08503e200db"),
 "name" : "Product 1",
 "description" : "Product 1 description",
 "price" : 10,
 "supplier" : {
 "name" : "Supplier 1",
 "telephone" : "+552199998888"
 },
 "review" : [
 {
 "customer" : {
 "email" : "customer@customer.com"
 },
 "stars" : 5
 },
 {
 "customer" : {
 "email" : "customer2@customer.com"
 },
 "stars" : 6
 }
 ]
}
{
 "_id" : ObjectId("54837b65f059b08503e200dc"),
 "name" : "Product 2",
 "description" : "Product 2 description",
 "price" : 20,
 "supplier" : {
 "name" : "Supplier 2",
 "telephone" : "+552188887777"
 },
 "review" : [
 {
 "customer" : {
 "email" : "customer@customer.com"
 },
 "stars" : 10
 },
 {
 "customer" : {
 "email" : "customer2@customer.com"
 },
 "stars" : 2
 }
 ]
}

```

+   `$in` 运算符能够搜索任何字段值等于查询中请求的数组中指定的值的文档。执行查询 `db.products.find({price:{$in: [5, 10, 15]}})` 将返回：

```sql
{
 "_id" : ObjectId("54837b61f059b08503e200db"),
 "name" : "Product 1",
 "description" : "Product 1 description",
 "price" : 10,
 "supplier" : {
 "name" : "Supplier 1",
 "telephone" : "+552199998888"
 },
 "review" : [
 {
 "customer" : {
 "email" : "customer@customer.com"
 },
 "stars" : 5
 },
 {
 "customer" : {
 "email" : "customer2@customer.com"
 },
 "stars" : 6
 }
 ]
}

```

+   `$nin` 运算符将匹配不包含在指定数组中的值。执行 `db.products.find({price:{$nin: [10, 20]}})` 查询将产生：

```sql
{
 "_id" : ObjectId("54837b69f059b08503e200dd"),
 "name" : "Product 3",
 "description" : "Product 3 description",
 "price" : 30,
 "supplier" : {
 "name" : "Supplier 3",
 "telephone" : "+552177776666"
 },
 "review" : [
 {
 "customer" : {
 "email" : "customer@customer.com"
 },
 "stars" : 5
 },
 {
 "customer" : {
 "email" : "customer2@customer.com"
 },
 "stars" : 9
 }
 ]
}

```

+   `$ne` 运算符将匹配任何不等于查询中指定值的值。执行 `db.products.find({name: {$ne: "Product 1"}})` 查询将产生：

```sql
{
 "_id" : ObjectId("54837b65f059b08503e200dc"),
 "name" : "Product 2",
 "description" : "Product 2 description",
 "price" : 20,
 "supplier" : {
 "name" : "Supplier 2",
 "telephone" : "+552188887777"
 },
 "review" : [
 {
 "customer" : {
 "email" : "customer@customer.com"
 },
 "stars" : 10
 },
 {
 "customer" : {
 "email" : "customer2@customer.com"
 },
 "stars" : 2
 }
 ]
}
{
 "_id" : ObjectId("54837b69f059b08503e200dd"),
 "name" : "Product 3",
 "description" : "Product 3 description",
 "price" : 30,
 "supplier" : {
 "name" : "Supplier 3",
 "telephone" : "+552177776666"
 },
 "review" : [
 {
 "customer" : {
 "email" : "customer@customer.com"
 },
 "stars" : 5
 },
 {
 "customer" : {
 "email" : "customer2@customer.com"
 },
 "stars" : 9
 }
 ]
}

```

## 逻辑运算符

逻辑运算符是我们在 MongoDB 中定义值之间逻辑关系的方式。这些源自布尔代数，布尔值的真值可以是 `true` 或 `false`。让我们看看 MongoDB 中的逻辑运算符：

+   `$and` 运算符将在表达式数组中执行逻辑 *AND* 操作，并返回匹配所有指定条件的值。执行 `db.products.find({$and: [{price: {$lt: 30}}, {name: "Product 2"}]})` 查询将产生：

```sql
{
 "_id" : ObjectId("54837b65f059b08503e200dc"),
 "name" : "Product 2",
 "description" : "Product 2 description",
 "price" : 20,
 "supplier" : {
 "name" : "Supplier 2",
 "telephone" : "+552188887777"
 },
 "review" : [
 {
 "customer" : {
 "email" : "customer@customer.com"
 },
 "stars" : 10
 },
 {
 "customer" : {
 "email" : "customer2@customer.com"
 },
 "stars" : 2
 }
 ]
}

```

+   `$or` 运算符将在表达式数组中执行逻辑 *OR* 操作，并返回匹配任一指定条件的所有值。执行 `db.products.find({$or: [{price: {$gt: 50}}, {name: "Product 3"}]})` 查询将产生：

```sql
{
 "_id" : ObjectId("54837b69f059b08503e200dd"),
 "name" : "Product 3",
 "description" : "Product 3 description",
 "price" : 30,
 "supplier" : {
 "name" : "Supplier 3",
 "telephone" : "+552177776666"
 },
 "review" : [
 {
 "customer" : {
 "email" : "customer@customer.com"
 },
 "stars" : 5
 },
 {
 "customer" : {
 "email" : "customer2@customer.com"
 },
 "stars" : 9
 }
 ]
}

```

+   `$not` 运算符反转查询效果，并返回不匹配指定运算符表达式的值。它用于否定任何操作。执行 `db.products.find({price: {$not: {$gt: 10}}})` 查询将产生：

```sql
{
 "_id" : ObjectId("54837b61f059b08503e200db"),
 "name" : "Product 1",
 "description" : "Product 1 description",
 "price" : 10,
 "supplier" : {
 "name" : "Supplier 1",
 "telephone" : "+552199998888"
 },
 "review" : [
 {
 "customer" : {
 "email" : "customer@customer.com"
 },
 "stars" : 5
 },
 {
 "customer" : {
 "email" : "customer2@customer.com"
 },
 "stars" : 6
 }
 ]
}

```

+   `$nor` 运算符将在表达式数组中执行逻辑 *NOR* 操作，并返回所有未能匹配数组中所有指定表达式的值。执行 `db.products.find({$nor:[{price:{$gt: 35}}, {price:{$lte: 20}}]})` 查询将产生：

```sql
{
 "_id" : ObjectId("54837b69f059b08503e200dd"),
 "name" : "Product 3",
 "description" : "Product 3 description",
 "price" : 30,
 "supplier" : {
 "name" : "Supplier 3",
 "telephone" : "+552177776666"
 },
 "review" : [
 {
 "customer" : {
 "email" : "customer@customer.com"
 },
 "stars" : 5
 },
 {
 "customer" : {
 "email" : "customer2@customer.com"
 },
 "stars" : 9
 }
 ]
}

```

## 元素运算符

要查询集合关于我们文档字段的信息，我们可以使用元素运算符。

`$exists` 运算符将返回查询中具有指定字段的所有文档。执行 `db.products.find({sku: {$exists: true}})` 将不会返回任何文档，因为它们都没有 `sku` 字段。

## 评估运算符

评估运算符是我们在 MongoDB 中对表达式进行评估的方式。我们必须小心使用这种类型的运算符，特别是如果我们正在使用的字段没有索引。让我们考虑评估运算符：

+   `$regex` 运算符将返回所有匹配正则表达式的值。执行 `db.products.find({name: {$regex: /2/}})` 将返回：

```sql
{
 "_id" : ObjectId("54837b65f059b08503e200dc"),
 "name" : "Product 2",
 "description" : "Product 2 description",
 "price" : 20,
 "supplier" : {
 "name" : "Supplier 2",
 "telephone" : "+552188887777"
 },
 "review" : [
 {
 "customer" : {
 "email" : "customer@customer.com"
 },
 "stars" : 10
 },
 {
 "customer" : {
 "email" : "customer2@customer.com"
 },
 "stars" : 2
 }
 ]
}

```

## 数组运算符

当我们在查询中使用数组时，应该使用数组运算符。让我们考虑数组运算符：

+   `$elemMatch`操作符将返回所有指定数组字段值至少有一个与查询条件匹配的元素的文档。

`db.products.find({review: {$elemMatch: {stars: {$gt: 5}, customer: {email: "customer@customer.com"}}}})`查询将查看所有集合文档，其中`review`字段有文档，`stars`字段值大于`5`，并且`customer email`是`customer@customer.com`：

```sql
{
 "_id" : ObjectId("54837b65f059b08503e200dc"),
 "name" : "Product 2",
 "description" : "Product 2 description",
 "price" : 20,
 "supplier" : {
 "name" : "Supplier 2",
 "telephone" : "+552188887777"
 },
 "review" : [
 {
 "customer" : {
 "email" : "customer@customer.com"
 },
 "stars" : 10
 },
 {
 "customer" : {
 "email" : "customer2@customer.com"
 },
 "stars" : 2
 }
 ]
}

```

### 注意

除了已呈现的操作符外，我们还有：`$mod`，`$text`，`$where`，`$all`，`$geoIntersects`，`$geoWithin`，`$nearSphere`，`$near`，`$size`和`$comment`。您可以在 MongoDB 手册参考中找到更多关于这方面的信息[`docs.mongodb.org/manual/reference/operator/query/`](http://docs.mongodb.org/manual/reference/operator/query/)。

## 投影

到目前为止，我们执行的查询中呈现的结果是文档在 MongoDB 中持久化的样子。但是，为了优化 MongoDB 与其客户端之间的网络开销，我们应该使用投影。

正如您在本章开头看到的，`find`接口允许我们使用两个参数。第二个参数是投影。

通过在上一节中使用的相同示例集合，具有投影的查询示例将是：

```sql
db.products.find({price: {$not: {$gt: 10}}}, {name: 1, description: 1})

```

这个查询产生：

```sql
{
 "_id" : ObjectId("54837b61f059b08503e200db"),
 "name" : "Product 1",
 "description" : "Product 1 description"
}

```

投影是一个 JSON 文档，其中包含我们想要呈现或隐藏的所有字段，后面跟着`0`或`1`，取决于我们的需求。

当一个字段后面跟着`0`，那么这个字段将不会显示在结果文档中。另一方面，如果字段后面跟着`1`，那么这意味着它将显示在结果文档中。

### 注意

默认情况下，`_id`字段的值为`1`。

`db.products.find({price: {$not: {$gt: 10}}}, {_id: 0, name: 1, "supplier.name": 1})`查询将显示以下文档：

```sql
{ "name" : "Product 1", "supplier" : { "name" : "Supplier 1" } }

```

在具有数组值的字段中，我们可以使用`$elemMatch`，`$split`，`$slice`和`$`等操作符。

`db.products.find({price: {$gt: 20}}, {review: {$elemMatch: {stars: 5}}})` 查询将产生：

```sql
{
 "_id" : ObjectId("54837b69f059b08503e200dd"),
 "review" : [
 {
 "customer" : {
 "email" : "customer@customer.com"
 },
 "stars" : 5
 }
 ]
}

```

# 介绍写操作

在 MongoDB 中，我们有三种写操作：插入、更新和删除。为了运行这些操作，MongoDB 提供了三个接口：`db.document.insert`，`db.document.update`和`db.document.remove`。MongoDB 中的写操作针对特定集合，并且在单个文档级别上是原子的。

在 MongoDB 中，当我们对文档进行建模时，写操作和读操作一样重要。单个文档级别的原子性可以决定我们是否嵌入文档。我们将在第七章*扩展*中更详细地讨论这个问题，但选择分片键的活动将决定我们是否写入操作的性能，因为根据键的选择，我们将在一个或多个分片上进行写入。

此外，写操作性能的另一个决定因素与 MongoDB 物理模型有关。10gen 提出了许多建议，但让我们专注于对我们的开发产生最大影响的建议。由于 MongoDB 的更新模型是基于随机 I/O 操作的，建议您使用固态硬盘或 SSD。与旋转硬盘相比，固态硬盘在随机 I/O 操作方面具有更高的性能。尽管旋转硬盘更便宜，基于这种硬件的基础设施扩展成本也不是很昂贵，但使用 SSD 或增加 RAM 仍然更有效。关于这个主题的研究表明，SSD 在随机 I/O 操作方面比旋转硬盘性能提高了 100 倍。

关于写操作的另一个重要事项是了解 MongoDB 如何实际将文档写入磁盘。MongoDB 使用日志记录机制来写入操作，该机制在写入数据文件之前使用日志来写入更改操作。这在发生脏关闭时非常有用。当`mongod`进程重新启动时，MongoDB 将使用日志文件将数据库状态恢复到一致状态。

如第二章中所述，“使用 MongoDB 进行数据建模”，BSON 规范允许我们拥有最大大小为 16MB 的文档。自其 2.6 版本以来，MongoDB 使用了一种名为“二次幂大小分配”的记录或文档的空间分配策略。正如其名称所示，MongoDB 将为每个文档分配一个字节大小，即其大小的二次幂（例如，32、64、128、256、512，...），考虑到文档的最小大小为 32 字节。该策略分配的空间比文档实际需要的空间更多，从而为其提供更多的增长空间。

## 插入

`insert`接口是在 MongoDB 中创建新文档的可能方式之一。`insert`接口具有以下语法：

```sql
db.collection.insert(
 <document or array of documents>, 
 { 
 writeConcern: <document>, 
 ordered: <boolean> 
 }
)

```

在这里：

+   `文档或文档数组`是一个文档或一个包含一个或多个文档的数组，应该在目标集合中创建。

+   `writeConcern`是表示写入关注的文档。

+   `ordered`应该是一个布尔值，如果为 true，将在数组的文档上执行有序过程，如果文档中有错误，MongoDB 将停止处理它。否则，如果值为 false，将执行无序过程，如果发生错误，将不会停止。默认情况下，值为`true`。

在下面的示例中，我们可以看到如何使用`insert`操作：

```sql
db.customers.insert({
 username: "customer1", 
 email: "customer1@customer.com", 
 password: hex_md5("customer1paswd")
})

```

由于我们没有为`_id`字段指定值，它将自动生成具有唯一`ObjectId`值的值。此`insert`操作创建的文档是：

```sql
{ 
 "_id" : ObjectId("5487ada1db4ff374fd6ae6f5"), 
 "username" : "customer1", 
 "email" : "customer1@customer.com", 
 "password" : "b1c5098d0c6074db325b0b9dddb068e1" 
}

```

正如您在本节的第一段中观察到的，`insert`接口不是在 MongoDB 中创建新文档的唯一方式。通过在更新上使用`upsert`选项，我们也可以创建新文档。现在让我们更详细地了解一下这个。

## 更新

`update`接口用于修改 MongoDB 中先前存在的文档，甚至创建新文文档。为了选择要更改的文档，我们将使用条件。更新可以修改文档的字段值或整个文档。

更新操作一次只会修改一个文档。如果条件匹配多个文档，则需要通过`multi`参数为`true`的文档传递给 update 接口。如果条件不匹配任何文档，并且`upsert`参数为`true`，则将创建一个新文档，否则将更新匹配的文档。

`update`接口表示为：

```sql
db.collection.update(
 <query>,
 <update>,
 { 
 upsert: <boolean>, 
 multi: <boolean>, 
 writeConcern: <document> 
 }
)

```

在这里：

+   `query`是条件

+   `update`是包含要应用的修改的文档

+   `upsert`是一个布尔值，如果为 true，则在集合中没有匹配任何文档的情况下创建一个新文档

+   `multi`是一个布尔值，如果为 true，则更新满足条件的每个文档

+   `writeConcern`是表示写入关注的文档

使用上一节中创建的文档，示例更新将是：

```sql
db.customers.update(
 {username: "customer1"}, 
 {$set: {email: "customer1@customer1.com"}}
)

```

修改后的文档是：

```sql
{ 
 "_id" : ObjectId("5487ada1db4ff374fd6ae6f5"), 
 "username" : "customer1", 
 "email" : "customer1@customer1.com", 
 "password" : "b1c5098d0c6074db325b0b9dddb068e1"
}

```

`$set`运算符允许我们仅更新匹配文档的`email`字段。

否则，您可能会有此更新：

```sql
db.customers.update(
 {username: "customer1"}, 
 {email: "customer1@customer1.com"}
)

```

在这种情况下，修改后的文档将是：

```sql
{ 
 "_id" : ObjectId("5487ada1db4ff374fd6ae6f5"), 
 "email" : "customer1@customer1.com" 
}

```

也就是说，没有`$set`运算符，我们使用传递给更新的参数修改旧文档。除了`$set`运算符之外，我们还有其他重要的更新运算符：

+   `$inc`增加具有指定值的字段的值：

```sql
db.customers.update(
 {username: "johnclay"}, 
 {$inc: {"details.age": 1}}
)

```

此更新将在匹配文档中将字段`details.age`增加 1。

+   `$rename`将重命名指定的字段：

```sql
db.customers.update(
 {email: "customer1@customer1.com"}, 
 {$rename: {username: "login"}}
)

```

此更新将在匹配的文档中将字段`username`重命名为`login`。

+   `$unset`将从匹配的文档中删除字段：

```sql
db.customers.update(
 {email: "customer1@customer1.com"}, 
 {$unset: {login: ""}}
)

```

此更新将从匹配的文档中删除`login`字段。

由于写操作在单个文档级别是原子的，我们可以在使用前面的操作符时放心大胆。所有这些操作符都可以安全使用。

## 写关注点

围绕非关系型数据库的许多讨论与 ACID 概念有关。作为数据库专业人员、软件工程师、架构师和开发人员，我们对关系型宇宙非常熟悉，并且花费了大量时间开发而不关心 ACID 问题。

尽管如此，我们现在应该明白为什么我们真的必须考虑这个问题，以及这些简单的四个字母在非关系型世界中是如此重要。在本节中，我们将讨论**D**这个字母，在 MongoDB 中意味着持久性。

数据库系统中的持久性是一个属性，告诉我们写入操作是否成功，事务是否已提交，数据是否已写入非易失性存储器中，例如硬盘。

与关系型数据库系统不同，NoSQL 数据库中对写操作的响应由客户端确定。再次，我们有可能在数据建模上做出选择，满足客户的特定需求。

在 MongoDB 中，成功写入操作的响应可以有多个级别的保证。这就是我们所说的写入关注点。这些级别从弱到强不等，客户端确定保证的强度。在同一个集合中，我们可以有一个需要强写入关注点的客户端，另一个需要弱写入关注点的客户端。

MongoDB 提供给我们的写入关注点级别是：

+   未确认

+   确认

+   已记录

+   副本已确认

### 未确认

顾名思义，使用未确认的写入关注点，客户端将不会尝试响应写入操作。如果可能的话，只会捕获网络错误。以下图表显示驱动程序将不等待 MongoDB 确认接收写入操作：

！[未确认]（img / B04075_03_01.jpg）

在以下示例中，我们在`customers`集合中进行了一个未确认的写入操作：

```sql
db.customers.insert(
{username: "customer1", email: "customer1@customer.com", password: hex_md5("customer1paswd")}, 
{writeConcern: {w: 0}}
)

```

### 确认

使用此写入关注点，客户端将收到写入操作的确认，并看到它已在 MongoDB 的内存视图上写入。在这种模式下，客户端可以捕获网络错误和重复键等问题。自 MongoDB 2.6 版本以来，这是默认的写入关注点。

正如您之前看到的，我们无法保证 MongoDB 的内存视图上的写入将持久保存在磁盘上。如果 MongoDB 发生故障，内存视图中的数据将丢失。以下图表显示驱动程序等待 MongoDB 确认接收写入操作，并将更改应用于数据的内存视图：

！[已确认]（img / B04075_03_02.jpg）

在以下示例中，我们在`customers`集合中进行了一个已确认的写入操作：

```sql
db.customers.insert(
{username: "customer1", email: "customer1@customer.com", password: hex_md5("customer1paswd")}, 
{writeConcert: {w: 1}}
)

```

### 已记录

使用已记录的写入关注点，客户端将收到确认写入操作已在日志中提交的确认。因此，客户端将保证数据将持久保存在磁盘上，即使发生了 MongoDB 的故障。

为了减少使用已记录的写入关注点时的延迟，MongoDB 将将操作提交到日志的频率从默认值 100 毫秒降低到 30 毫秒。以下图表显示驱动程序将等待 MongoDB 确认接收写入操作，只有在将数据提交到日志后才会等待：

！[已记录]（img / B04075_03_03.jpg）

在下面的示例中，我们在`customers`集合中使用了一个日志写关注的`insert`：

```sql
db.customers.insert(
{username: "customer1", email: "customer1@customer.com", password: hex_md5("customer1paswd")}, 
{writeConcern: {w: 1, j: true}} 
)

```

### 副本已确认

当我们使用副本集时，重要的是要确保写操作不仅在主节点上成功，而且还传播到副本集的成员。为此，我们使用了一个副本已确认的写关注。

通过将默认写关注更改为副本已确认，我们可以确定我们希望从副本集的成员中获得写操作确认的数量。下图显示了驱动程序将等待 MongoDB 确认在指定数量的副本集成员上接收写操作：

![副本已确认](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-dt-mdl/img/B04075_03_04.jpg)

在下面的示例中，我们将等待写操作传播到主节点和至少两个辅助节点：

```sql
db.customers.insert(
{username: "customer1", email: "customer1@customer.com", password: hex_md5("customer1paswd")}, 
{writeConcern: {w: 3}}
)

```

我们应该在毫秒级别包含一个超时属性，以避免写操作在节点故障的情况下仍然被阻塞。

在下面的示例中，我们将等待写操作传播到主节点和至少两个辅助节点，并设置了三秒的超时。如果我们期望响应的两个辅助节点中的一个失败，那么该方法将在三秒后超时：

```sql
db.customers.insert(
{username: "customer1", email: "customer1@customer.com", password: hex_md5("customer1paswd")}, 
{writeConcern: {w: 3, wtimeout: 3000}}
)

```

## 批量编写文档

有时，一次插入、更新或删除集合中的多条记录是非常有用的。MongoDB 为我们提供了执行批量写操作的能力。批量操作在单个集合中工作，可以是有序的或无序的。

与`insert`方法一样，有序批量操作的行为是按顺序处理记录，如果发生错误，MongoDB 将返回而不处理任何剩余的操作。

无序操作的行为是并行处理，因此如果发生错误，MongoDB 仍将处理剩余的操作。

我们还可以确定批量写操作所需的确认级别。自其 2.6 版本以来，MongoDB 引入了新的批量方法，我们可以使用这些方法插入、更新或删除文档。但是，我们只能通过在`insert`方法上传递文档数组来进行批量插入。

在下面的示例中，我们使用`insert`方法进行批量插入：

```sql
db.customers.insert(
[
{username: "customer3", email: "customer3@customer.com", password: hex_md5("customer3paswd")}, 
{username: "customer2", email: "customer2@customer.com", password: hex_md5("customer2paswd")}, 
{username: "customer1", email: "customer1@customer.com", password: hex_md5("customer1paswd")}
]
)

```

在下面的示例中，我们使用新的批量方法进行无序批量插入：

```sql
var bulk = db.customers.initializeUnorderedBulkOp();
bulk.insert({username: "customer1", email: "customer1@customer.com", password: hex_md5("customer1paswd")});
bulk.insert({username: "customer2", email: "customer2@customer.com", password: hex_md5("customer2paswd")});
bulk.insert({username: "customer3", email: "customer3@customer.com", password: hex_md5("customer3paswd")});
bulk.execute({w: "majority", wtimeout: 3000});

```

我们应该利用 MongoDB 提供给我们的所有强大工具，但不要忽视任何可能的注意事项。MongoDB 一次最多执行 1,000 个批量操作的限制。因此，如果超过此限制，MongoDB 将把操作分成最多 1,000 个批量操作的组。

# 摘要

在本章中，您希望能够更好地理解 MongoDB 中的读写操作。此外，现在，您还应该明白为什么在文档建模过程之前就已经知道需要执行的查询是很重要的。最后，您学会了如何使用 MongoDB 的属性，比如原子性，在文档级别上，并看到它如何帮助我们生成更好的查询。

在下一章中，您将看到一种称为索引的特殊数据结构如何改进我们查询的执行。
