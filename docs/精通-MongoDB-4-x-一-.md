# 精通 MongoDB 4.x（一）

> 原文：[`zh.annas-archive.org/md5/BEDE8058C8DB4FDEC7B98D6DECC4CDE7`](https://zh.annas-archive.org/md5/BEDE8058C8DB4FDEC7B98D6DECC4CDE7)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

MongoDB 已经发展成为事实上的 NoSQL 数据库，拥有数百万用户，从小型初创公司到财富 500 强公司。解决了基于 SQL 模式的数据库的局限性，MongoDB 开创了 DevOps 关注重点的转变，并提供了分片和复制功能，可以由 DevOps 团队维护。本书基于 MongoDB 4.0，涵盖了从使用 shell、内置驱动程序和流行的 ODM 映射器进行数据库查询，到更高级的主题，如分片、高可用性和与大数据源的集成。

您将了解 MongoDB 的概况，并学习如何发挥其优势，以及相关的用例。之后，您将学习如何有效地查询 MongoDB，并尽可能多地利用索引。接下来的部分涉及 MongoDB 安装的管理，无论是在本地还是在云端。我们在接下来的部分中处理数据库内部，解释存储系统以及它们如何影响性能。本书的最后一部分涉及复制和 MongoDB 扩展，以及与异构数据源的集成。通过本书的学习，您将具备成为认证 MongoDB 开发人员和管理员所需的所有行业技能和知识。

# 这本书适合谁

《掌握 MongoDB 4.0》是一本面向数据库开发人员、架构师和管理员的书，他们想要更有效和更有成效地使用 MongoDB。如果您有使用 NoSQL 数据库构建应用程序和网站的经验，并且对此感兴趣，那么这本书适合您。

# 本书涵盖的内容

第一章，《MongoDB-现代 Web 的数据库》，带领我们穿越网络、SQL 和 NoSQL 技术的旅程，从它们的起源到它们当前的状态。

第二章，《模式设计和数据建模》，教您关系数据库和 MongoDB 的模式设计，以及如何从不同的起点实现相同的目标。

第三章，《MongoDB CRUD 操作》，提供了 CRUD 操作的概览。

第四章，《高级查询》，涵盖了使用 Ruby、Python 和 PHP 进行高级查询的概念，使用官方驱动程序和 ODM。

第五章，《多文档 ACID 事务》，探讨了遵循 ACID 特性的事务，这是 MongoDB 4.0 中引入的新功能。

第六章，《聚合》，深入探讨了聚合框架。我们还讨论了何时以及为什么应该使用聚合，而不是 MapReduce 和查询数据库。

第七章，《索引》，探讨了每个数据库中最重要的属性之一，即索引。

第八章，《监控、备份和安全》，讨论了 MongoDB 的运营方面。监控、备份和安全不应该是事后考虑的问题，而是在将 MongoDB 部署到生产环境之前需要处理的必要流程。

第九章，《存储引擎》，教您有关 MongoDB 中不同存储引擎的知识。我们确定了每种存储引擎的优缺点，以及选择每种存储引擎的用例。

第十章，《MongoDB 工具》，涵盖了我们可以在 MongoDB 生态系统中利用的各种不同工具，无论是在本地还是在云端。

第十一章，《使用 MongoDB 利用大数据》，更详细地介绍了 MongoDB 如何适应更广泛的大数据景观和生态系统。

第十二章，《复制》，讨论了副本集以及如何管理它们。从副本集的架构概述和选举周围的副本集内部开始，我们深入探讨了设置和配置副本集。

第十三章，《分片》，探讨了 MongoDB 最有趣的功能之一，即分片。我们从分片的架构概述开始，然后讨论如何设计分片，特别是如何选择正确的分片键。

第十四章，*容错和高可用性*，试图整合我们在之前章节中未能讨论的信息，并强调了开发人员和数据库管理员应该牢记的安全性和一系列核对表。

# 为了充分利用本书

您需要以下软件才能顺利阅读本书的各章内容：

+   MongoDB 版本 4+

+   Apache Kafka 版本 1

+   Apache Spark 版本 2+

+   Apache Hadoop 版本 2+

# 下载示例代码文件

您可以从您在[www.packt.com](http://www.packt.com)的账户中下载本书的示例代码文件。如果您在其他地方购买了本书，您可以访问[www.packt.com/support](http://www.packt.com/support)并注册，以便直接通过电子邮件接收文件。

您可以按照以下步骤下载代码文件：

1.  登录或在[www.packt.com](http://www.packt.com)注册。

1.  选择“支持”选项卡。

1.  点击“代码下载和勘误”。

1.  在搜索框中输入书名，然后按照屏幕上的说明进行操作。

下载文件后，请确保使用以下最新版本的解压软件解压文件夹：

+   Windows 的 WinRAR/7-Zip

+   Mac 上的 Zipeg/iZip/UnRarX

+   Linux 的 7-Zip/PeaZip

该书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/Mastering-MongoDB-4.x-Second-Edition`](https://github.com/PacktPublishing/Mastering-MongoDB-4.x-Second-Edition)。如果代码有更新，将在现有的 GitHub 存储库上进行更新。

我们还有其他代码包，来自我们丰富的图书和视频目录，可在**[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)**上找到。去看看吧！

# 使用的约定

在本书中，您会发现一些文本样式，用于区分不同类型的信息。以下是这些样式的一些示例及其含义的解释。

文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄都显示如下：“在分片环境中，每个`mongod`都应用自己的锁，从而大大提高了并发性。”

代码块设置如下：

```sql
db.account.find( { "balance" : { $type : 16 } } );
db.account.find( { "balance" : { $type : "integer" } } );
```

任何命令行输入或输出都以以下方式书写：

```sql
> db.types.insert({"a":4})
WriteResult({ "nInserted" : 1 })
```

**粗体**：表示一个新术语、重要单词或您在屏幕上看到的单词。例如，菜单或对话框中的单词会以这种方式出现在文本中。例如：“以下截图显示了区域配置摘要：”

警告或重要说明会以这种方式出现。

提示和技巧会以这种方式出现。

# 保持联系

我们始终欢迎读者的反馈。

**一般反馈**：如果您对本书的任何方面有疑问，请在邮件主题中提及书名，并发送电子邮件至`customercare@packtpub.com`。

**勘误**：尽管我们已经尽最大努力确保内容的准确性，但错误是难免的。如果您在本书中发现了错误，我们将不胜感激地接受您的报告。请访问[www.packt.com/submit-errata](http://www.packt.com/submit-errata)，选择您的书，点击勘误提交表格链接，并输入详细信息。

**盗版**：如果您在互联网上发现我们作品的任何形式的非法副本，请向我们提供位置地址或网站名称。请通过链接联系我们，链接地址为`copyright@packt.com`。

**如果您有兴趣成为作者**：如果您在某个专业领域有专长，并且有兴趣撰写或为一本书做出贡献，请访问[authors.packtpub.com](http://authors.packtpub.com/)。

# 评论

请留下评论。当您阅读并使用了这本书之后，为什么不在购买它的网站上留下评论呢？潜在的读者可以看到并使用您的客观意见来做出购买决定，我们在 Packt 可以了解您对我们产品的看法，我们的作者也可以看到您对他们书籍的反馈。谢谢！

关于 Packt 的更多信息，请访问 [packt.com](http://www.packt.com/)。


# 第一部分：基本 MongoDB - 设计目标和架构

在这一部分，我们将回顾数据库的历史，以及我们如何需要非关系型数据库。我们还将学习如何对数据进行建模，以便在 MongoDB 中进行存储和检索尽可能高效。尽管 MongoDB 是无模式的，但设计数据如何组织成文档可能会对性能产生很大影响。

本节包括以下章节：

+   第一章，*MongoDB - 用于现代 Web 的数据库*

+   第二章，*模式设计和数据建模*


# 第一章：MongoDB - 为现代网络设计的数据库

在本章中，我们将奠定理解 MongoDB 的基础，以及它声称自己是为现代网络设计的数据库。首先学习和知道如何学习同样重要。我们将介绍有关 MongoDB 的最新信息的参考资料，适用于新用户和有经验的用户。我们将涵盖以下主题：

+   SQL 和 MongoDB 的历史和演变

+   从 SQL 和其他 NoSQL 技术用户的角度看 MongoDB

+   MongoDB 的常见用例及其重要性

+   MongoDB 的配置和最佳实践

# 技术要求

您需要安装 MongoDB 版本 4+、Apache Kafka、Apache Spark 和 Apache Hadoop 才能顺利完成本章内容。所有章节中使用的代码可以在以下链接找到：[`github.com/PacktPublishing/Mastering-MongoDB-4.x-Second-Edition`](https://github.com/PacktPublishing/Mastering-MongoDB-4.x-Second-Edition)。

# SQL 和 NoSQL 的演变

**结构化查询语言**（**SQL**）甚至早于万维网出现。E. F. Codd 博士最初在 1970 年 6 月在**计算机协会**（**ACM**）期刊**ACM 通讯**上发表了题为《用于大型共享数据库的关系数据模型》的论文。SQL 最初是由 IBM 的 Chamberlin 和 Boyce 于 1974 年开发的。关系软件（现在是 Oracle 公司）是第一个开发出商业可用的 SQL 实现的公司，目标是美国政府机构。

第一个**美国国家标准学会**（**ANSI**）SQL 标准于 1986 年发布。自那时起，已经进行了八次修订，最近一次是在 2016 年发布的（SQL:2016）。

SQL 在万维网刚开始时并不特别受欢迎。静态内容可以直接硬编码到 HTML 页面中而不费吹灰之力。然而，随着网站功能的增长，网站管理员希望生成由离线数据源驱动的网页内容，以便生成随时间变化而变化的内容，而无需重新部署代码。

**通用网关接口**（**CGI**）脚本，开发 Perl 或 Unix shell，驱动着 Web 1.0 时期的数据库驱动网站。随着 Web 2.0 的出现，网络从直接将 SQL 结果注入浏览器发展到使用两层和三层架构，将视图与业务和模型逻辑分离，使得 SQL 查询可以模块化并与网络应用的其余部分隔离开来。

另一方面，**Not only SQL**（**NoSQL**）是更现代的，是在 Web 2.0 技术兴起的同时出现的。该术语最早由 Carlo Strozzi 于 1998 年创造，用于描述他的开源数据库，该数据库不遵循 SQL 标准，但仍然是关系型的。

这并不是我们当前对 NoSQL 数据库的期望。Johan Oskarsson 在当时是 Last.fm 的开发人员，于 2009 年初重新引入了这个术语，以便对一组正在开发的分布式、非关系型数据存储进行分组。其中许多是基于 Google 的**Bigtable**和**MapReduce**论文，或者是亚马逊的**DynamoDB**，这是一个高度可用的基于键值的存储系统。

NoSQL 的基础建立在放松的**原子性、一致性、隔离性**和**持久性**（**ACID**）属性上，这些属性保证了性能、可伸缩性、灵活性和降低了复杂性。大多数 NoSQL 数据库在提供尽可能多的上述特性方面都有所作为，甚至为开发人员提供可调整的保证。以下图表描述了 SQL 和 NoSQL 的演变：

![](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-mongo-4x/img/c24fbbf9-fe23-43c7-adf2-e5793351149b.png)

# MongoDB 的演变

10gen 于 2007 年开始开发云计算堆栈，并很快意识到最重要的创新是围绕他们构建的面向文档的数据库，即 MongoDB。MongoDB 最初于 2009 年 8 月 27 日发布。

MongoDB 的第 1 版在功能、授权和 ACID 保证方面非常基础，但通过性能和灵活性弥补了这些缺点。

在接下来的章节中，我们将突出 MongoDB 的主要功能，以及它们引入的版本号。

# 版本 1.0 和 1.2 的主要功能集

版本 1.0 和 1.2 的不同特性如下：

+   基于文档的模型

+   全局锁（进程级）

+   集合索引

+   文档的 CRUD 操作

+   无需认证（认证在服务器级别处理）

+   主从复制

+   `MapReduce`（自 v1.2 引入）

+   存储 JavaScript 函数（自 v1.2 引入）

# 第 2 版

第 2.0 版的不同特性如下：

+   后台索引创建（自 v1.4 以来）

+   分片（自 v1.6 以来）

+   更多的查询操作符（自 v1.6 以来）

+   日志记录（自 v1.8 以来）

+   稀疏和覆盖索引（自 v1.8 以来）

+   紧凑命令以减少磁盘使用

+   内存使用更高效

+   并发改进

+   索引性能增强

+   副本集现在更可配置，并且数据中心感知

+   `MapReduce`改进

+   认证（自 2.0 版，用于分片和大多数数据库命令）

+   引入地理空间功能

+   聚合框架（自 v2.2 以来）和增强（自 v2.6 以来）

+   TTL 集合（自 v2.2 以来）

+   并发改进，其中包括 DB 级别锁定（自 v2.2 以来）

+   文本搜索（自 v2.4 以来）和集成（自 v2.6 以来）

+   哈希索引（自 v2.4 以来）

+   安全增强和基于角色的访问（自 v2.4 以来）

+   V8 JavaScript 引擎取代 SpiderMonkey（自 v2.4 以来）

+   查询引擎改进（自 v2.6 以来）

+   可插拔存储引擎 API

+   引入 WiredTiger 存储引擎，具有文档级锁定，而以前的存储引擎（现在称为 MMAPv1）支持集合级锁定

# 第 3 版

3.0 版本的不同特性如下：

+   复制和分片增强（自 v3.2 以来）

+   文档验证（自 v3.2 以来）

+   聚合框架增强操作（自 v3.2 以来）

+   多个存储引擎（自 v3.2 以来，仅适用于企业版）

+   查询语言和索引排序（自 v3.4 以来）

+   只读数据库视图（自 v3.4 以来）

+   线性读关注（自 v3.4 以来）

# 第 4 版

4.0 版本的不同特性如下：

+   多文档 ACID 事务

+   变更流

+   MongoDB 工具（Stitch、Mobile、Sync 和 Kubernetes Operator）

以下图表显示了 MongoDB 的演变：

![](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-mongo-4x/img/1bd46ef6-31be-4038-a331-ec09cedea659.png)

正如我们所看到的，第 1 版非常基础，而第 2 版引入了当前版本中的大多数功能，如分片、可用和特殊索引、地理空间功能以及内存和并发改进。

从第 2 版到第 3 版的过程中，聚合框架被引入，主要作为老化的（并且从未达到专用框架（如 Hadoop）的水平）MapReduce 框架的补充。然后，添加了文本搜索，并且慢慢但确定地，该框架正在改进性能、稳定性和安全性，以适应使用 MongoDB 的客户的不断增加的企业负载。

随着 WiredTiger 在第 3 版中的引入，对于 MongoDB 来说，锁定不再是一个问题，因为它从进程（全局锁）降至文档级别，几乎是可能的最粒度级别。

第 4 版标志着一个重大转变，通过引入多文档 ACID 事务，将 SQL 和 NoSQL 世界联系起来。这使得更广泛范围的应用程序可以使用 MongoDB，特别是需要强大的实时一致性保证的应用程序。此外，引入变更流允许使用 MongoDB 的实时应用程序更快地上市。还引入了一系列工具，以便于无服务器、移动和物联网开发。

在当前状态下，MongoDB 是一个可以处理从初始 MVP 和 POC 到拥有数百台服务器的企业应用程序的数据库。

# SQL 开发人员的 MongoDB

MongoDB 是在 Web 2.0 时代开发的。那时，大多数开发人员一直在使用 SQL 或他们选择的语言中的**对象关系映射**（**ORM**）工具来访问关系型数据库的数据。因此，这些开发人员需要一种从他们的关系背景中轻松了解 MongoDB 的方法。

值得庆幸的是，已经有几次尝试制作 SQL 到 MongoDB 的速查表，解释了 SQL 术语中的 MongoDB 术语。

在更高的层次上，我们有以下内容：

+   数据库和索引（SQL 数据库）

+   集合（SQL 表）

+   文档（SQL 行）

+   字段（SQL 列）

+   嵌入和链接文档（SQL 连接）

以下是一些常见操作的更多示例：

| **SQL** | **MongoDB** |
| --- | --- |
| 数据库 | 数据库 |
| 表 | 集合 |
| 索引 | 索引 |
| 行 | 文档 |
| 列 | 字段 |
| 连接 | 嵌入文档或通过`DBRef`链接 |
| `CREATE TABLE employee (name VARCHAR(100))` | `db.createCollection("employee")` |
| `INSERT INTO employees VALUES (Alex, 36)` | `db.employees.insert({name: "Alex", age: 36})` |
| `SELECT * FROM employees` | `db.employees.find()` |
| `SELECT * FROM employees LIMIT 1` | `db.employees.findOne()` |
| `SELECT DISTINCT name FROM employees` | `db.employees.distinct("name")` |
| `UPDATE employees SET age = 37 WHERE name = 'Alex'` | `db.employees.update({name: "Alex"}, {$set: {age: 37}}, {multi: true})` |
| `DELETE FROM employees WHERE name = 'Alex'` | `db.employees.remove({name: "Alex"})` |
| `CREATE INDEX ON employees (name ASC)` | `db.employees.ensureIndex({name: 1})` |

更多常见操作的示例可在[`s3.amazonaws.com/info-mongodb-com/sql_to_mongo.pd`](http://s3.amazonaws.com/info-mongodb-com/sql_to_mongo.pdf)[f](http://s3.amazonaws.com/info-mongodb-com/sql_to_mongo.pdf)[.](http://s3.amazonaws.com/info-mongodb-com/sql_to_mongo.pdf)中查看。

# NoSQL 开发人员的 MongoDB

随着 MongoDB 从一种小众数据库解决方案发展为 NoSQL 技术的瑞士军刀，越来越多的开发人员从 NoSQL 背景转向它。

将 SQL 转换为 NoSQL 的差异放在一边，面对最大挑战的是列式数据库的用户。随着 Cassandra 和 HBase 成为最受欢迎的列式数据库管理系统，我们将研究它们之间的差异以及开发人员如何将系统迁移到 MongoDB。MongoDB 针对 NoSQL 开发人员的不同特性如下：

+   **灵活性**：MongoDB 的文档概念可以包含在复杂层次结构中嵌套的子文档，这真的很表达和灵活。这类似于 MongoDB 和 SQL 之间的比较，但 MongoDB 更容易地映射到任何编程语言的普通对象，从而实现轻松的部署和维护。 

+   **灵活的查询模型**：用户可以选择性地索引每个文档的某些部分；基于属性值、正则表达式或范围进行查询；并且应用层可以拥有所需的任意多的对象属性。主索引和辅助索引，以及特殊类型的索引（如稀疏索引），可以极大地提高查询效率。使用 JavaScript shell 和 MapReduce 使大多数开发人员（以及许多数据分析师）能够快速查看数据并获得有价值的见解。

+   **本地聚合**：聚合框架为用户提供了一个**提取、转换、加载**（**ETL**）管道，用户可以从 MongoDB 中提取和转换数据，然后将其加载到新格式中，或者将其从 MongoDB 导出到其他数据源。这也可以帮助数据分析师和科学家在执行数据整理时获得他们需要的数据片段。

+   **无模式模型**：这是 MongoDB 设计理念的结果，它赋予应用程序解释集合文档中不同属性的权力和责任。与 Cassandra 或 HBase 的基于模式的方法相比，在 MongoDB 中，开发人员可以存储和处理动态生成的属性。

# MongoDB 的关键特点和用例

在本节中，我们将分析 MongoDB 作为数据库的特点。了解 MongoDB 提供的功能可以帮助开发人员和架构师评估手头的需求以及 MongoDB 如何帮助实现它们。此外，我们将从 MongoDB，Inc.的经验中介绍一些常见的用例，这些用例为其用户带来了最佳结果。

# 关键特点

MongoDB 已经发展成为一个通用的 NoSQL 数据库，提供了关系型数据库管理系统和 NoSQL 世界的最佳特性。一些关键特点如下：

+   **它是一个通用数据库**：与为特定目的（例如图形数据库）构建的其他 NoSQL 数据库相比，MongoDB 可以为应用程序中的异构负载和多个目的提供服务。在 4.0 版本引入多文档 ACID 事务后，这一点变得更加真实，进一步扩展了它可以有效使用的用例。

+   **灵活的模式设计**：文档导向的方法具有非定义属性，可以在运行时修改，这是 MongoDB 与关系数据库之间的关键对比。

+   **从头开始构建高可用性**：在我们这个五个九的可用性时代，这是必须的。配合服务器故障检测后的自动故障转移，这可以帮助实现高可用性。

+   **功能丰富**：提供全面的 SQL 等效操作符，以及诸如 MapReduce、聚合框架、生存时间和封闭集合、次要索引等功能，MongoDB 可以适应许多用例，无论需求多么多样化。

+   **可扩展性和负载平衡**：它被设计为垂直和（主要）水平扩展。使用分片，架构师可以在不同实例之间共享负载，并实现读写可扩展性。数据平衡通过分片平衡器自动发生（对用户透明）。

+   **聚合框架**：在数据库中内置 ETL 框架意味着开发人员可以在数据离开数据库之前执行大部分 ETL 逻辑，从而在许多情况下消除了复杂数据管道的需求。

+   **本地复制**：数据将在不复杂的设置情况下在副本集之间复制。

+   **安全功能**：考虑到了身份验证和授权，因此架构师可以保护他们的 MongoDB 实例。

+   **用于存储和传输文档的 JSON（BSON 和二进制 JSON）对象**：JSON 在网页前端和 API 通信中被广泛使用，因此当数据库使用相同的协议时会更容易。

+   **MapReduce**：尽管 MapReduce 引擎不像专用框架中那样先进，但它仍然是构建数据管道的好工具。

+   **在 2D 和 3D 中查询和地理空间信息**：对于许多应用程序来说可能并不重要，但如果对于您的用例而言，能够在同一个数据库中进行地理空间计算和数据存储是非常方便的。

+   **多文档 ACID 事务**：从 4.0 版本开始，MongoDB 支持跨多个文档的 ACID 事务。

+   **成熟的工具**：MongoDB 的工具已经发展，支持从 DBaaS 到 Sync、Mobile 和无服务器（Stitch）。

# MongoDB 的用例

由于 MongoDB 是一种非常流行的 NoSQL 数据库，因此已经有几个成功的用例，它成功支持了高质量的应用程序，并且交付时间很短。

许多最成功的用例都集中在以下领域：

+   整合孤立的数据，提供它们的单一视图

+   物联网

+   移动应用

+   实时分析

+   个性化

+   目录管理

+   内容管理

所有这些成功案例都有一些共同特点。我们将尝试按相对重要性的顺序来分解它们。

+   模式灵活性可能是最重要的特性。能够在集合中存储具有不同属性的文档可以帮助在开发阶段和从可能具有不同属性的异构来源摄取数据时。这与关系型数据库形成对比，在关系型数据库中，列需要预定义，而稀疏数据可能会受到惩罚。在 MongoDB 中，这是正常的，也是大多数用例共享的特性。能够深度嵌套属性到文档中，并将值数组添加到属性中，同时能够搜索和索引这些字段，有助于应用程序开发人员利用 MongoDB 的无模式特性。

+   扩展和分片是 MongoDB 用例中最常见的模式。使用内置分片轻松扩展，并使用副本集进行数据复制和卸载主服务器的读取负载，可以帮助开发人员有效地存储数据。

+   许多用例还使用 MongoDB 作为存档数据的一种方式。作为纯数据存储（而不需要定义模式），将数据倾倒到 MongoDB 中以供以后由业务分析人员分析，可以很容易地使用 shell 或一些可以轻松集成 MongoDB 的众多 BI 工具。根据时间限制或文档计数进一步分解数据，可以帮助从 RAM 中提供这些数据集，这是 MongoDB 最有效的用例。

+   将数据集保留在 RAM 中有助于性能，这也是实践中常用的方法。MongoDB 在大多数版本中使用 MMAP 存储（称为 MMAPv1），直到最近的版本，它将数据映射委托给底层操作系统。这意味着大多数基于 GNU/Linux 的系统，与可以存储在 RAM 中的集合一起工作，将大大提高性能。随着可插拔存储引擎的引入，如 WiredTiger（在第八章中将有更多介绍，*监控、备份和安全*），这个问题就不那么严重了。

+   封顶集合也是许多用例中使用的一个特性。封顶集合可以通过文档数量或集合的整体大小来限制集合中的文档。在后一种情况下，我们需要估计每个文档的大小，以便计算有多少文档可以适应我们的目标大小。封顶集合是快速而简单的解决方案，可以回答诸如“给我上一个小时的日志概览”之类的请求，而无需进行维护和运行异步后台作业来清理我们的集合。通常情况下，这些可能被用来快速构建和操作一个排队系统。开发人员可以使用集合来存储消息，然后使用 MongoDB 提供的本地可追加游标来迭代结果，以便在结果堆积并向外部系统提供数据时使用。

+   低运营开销也是许多用例中的常见模式。在敏捷团队中工作的开发人员可以操作和维护 MongoDB 服务器集群，而无需专门的数据库管理员。MongoDB 管理服务（MMS）可以极大地帮助减少管理开销，而 MongoDB Atlas，MongoDB 公司提供的托管解决方案，意味着开发人员不需要处理运营方面的问题。

+   在使用 MongoDB 的业务领域中，几乎所有行业都有各种各样的应用。然而，似乎更多的是在需要处理大量数据，但每个数据点的商业价值相对较低的情况下。例如，物联网等领域可以通过利用可用性而非一致性设计来获益，以成本效益的方式存储来自传感器的大量数据。另一方面，金融服务则绝对需要严格的一致性要求，符合适当的 ACID 特性，这使得 MongoDB 更具挑战性。金融交易可能规模较小，但影响巨大，这意味着我们不能不经过适当处理就放任一个消息。

+   基于位置的数据也是 MongoDB 蓬勃发展的领域之一，Foursquare 是最著名的早期客户之一。MongoDB 提供了丰富的二维和三维地理位置数据功能，包括按距离搜索、地理围栏和地理区域之间的交集等功能。

+   总的来说，丰富的功能集是不同用例中的共同模式。通过提供可以在许多不同行业和应用中使用的功能，MongoDB 可以成为所有业务需求的统一解决方案，为用户提供最小化运营开销的能力，同时在产品开发中快速迭代。

# MongoDB 的批评

MongoDB 的批评与以下几点有关：

+   多年来，MongoDB 一直备受批评。许多开发人员对其 Web 规模的主张持怀疑态度。反驳的观点是大多数情况下并不需要规模化，重点应该放在其他设计考虑上。虽然这有时可能是真的，但这是一个虚假的二分法，在理想的世界中，我们应该兼而有之。MongoDB 尽可能地将可伸缩性与功能、易用性和上市时间结合在一起。

+   MongoDB 的无模式特性也是一个很大的争论点。在许多用例中，无模式可以带来很多好处，因为它允许将异构数据倾入数据库，而无需复杂的清洗，也不会导致大量空列或文本块堆积在单个列中。另一方面，这是一把双刃剑，因为开发人员可能会在集合中拥有许多文档，这些文档在字段上具有松散的语义，而在代码级别提取这些语义可能会变得非常困难。如果我们的模式设计不够理想，我们可能最终得到的是一个数据存储，而不是一个数据库。

+   来自关系型数据库世界的一个经常的抱怨是缺乏适当的 ACID 保证。事实上，如果开发人员需要同时访问多个文档，要保证关系型数据库的特性并不容易，因为没有事务。没有事务，也意味着复杂的写操作需要应用级逻辑来回滚。如果需要更新两个集合中的三个文档以标记一个应用级事务完成，但第三个文档由于某种原因没有被更新，应用程序将需要撤销前两次写操作，这可能并不是一件简单的事情。

+   随着在 4.0 版本中引入多文档事务，MongoDB 可以应对 ACID 事务，但速度会受到影响。虽然这并不理想，事务并不适用于 MongoDB 中的每个 CRUD 操作，但它解决了主要的批评来源。

+   不赞成设置 MongoDB 的默认写入行为，但不在生产环境中进行操作。多年来，默认的写入行为是**写入并忘记**；发送写入操作不会在尝试下一个写入操作之前等待确认，导致写入速度极快，在发生故障时行为不佳。认证也是事后考虑，导致成千上万的 MongoDB 数据库在公共互联网上成为任何想要读取存储数据的人的猎物。尽管这些是有意识的设计决策，但它们影响了开发人员对 MongoDB 的看法。

# MongoDB 配置和最佳实践

在本节中，我们将介绍一些关于操作、模式设计、耐久性、复制、分片和安全性的最佳实践。关于何时实施这些最佳实践的进一步信息将在后面的章节中介绍。

# 运营最佳实践

作为数据库，MongoDB 是为开发人员而构建的，并且是在 Web 时代开发的，因此不需要像传统的关系型数据库管理系统那样多的运营开销。尽管如此，仍然需要遵循一些最佳实践，以积极主动并实现高可用性目标。

按重要性顺序，最佳实践如下：

+   **默认情况下打开日志记录**：日志记录使用预写式日志，以便在 MongoDB 服务器突然关闭时能够恢复。对于 MMAPv1 存储引擎，日志记录应始终打开。对于 WiredTiger 存储引擎，日志记录和检查点一起使用，以确保数据的耐久性。无论如何，使用日志记录并调整日志和检查点的大小和频率，以避免数据丢失，是一个好习惯。在 MMAPv1 中，默认情况下，日志每 100 毫秒刷新到磁盘一次。如果 MongoDB 在确认写操作之前等待日志记录，那么日志将在 30 毫秒内刷新到磁盘。

+   **您的工作集应该适合内存**：再次强调，特别是在使用 MMAPv1 时，工作集最好小于底层机器或虚拟机的 RAM。MMAPv1 使用来自底层操作系统的内存映射文件，如果 RAM 和磁盘之间没有太多的交换发生，这可能是一个很大的好处。另一方面，WiredTiger 在使用内存方面效率更高，但仍然极大地受益于相同的原则。工作集最大是由`db.stats()`报告的数据大小加上索引大小。

+   **注意数据文件的位置**：数据文件可以通过使用`--dbpath`命令行选项挂载到任何位置。确保数据文件存储在具有足够磁盘空间的分区中，最好是 XFS，或至少是**Ext4**，这一点非常重要。

+   **保持与版本的更新**：即使是主要编号的版本也是稳定的。因此，3.2 是稳定的，而 3.3 不是。在这个例子中，3.3 是将最终实现为稳定版本 3.4 的开发版本。始终更新到最新的安全更新版本（在撰写本书时为 4.0.2），并在下一个稳定版本发布时考虑更新（在这个例子中为 4.2）是一个好习惯。

+   **使用 Mongo MMS 图形监控您的服务**：免费的 MongoDB，Inc.监控服务是一个很好的工具，可以概览 MongoDB 集群、通知和警报，并积极应对潜在问题。

+   **如果您的指标显示出重度使用，请扩展规模**：不要等到为时已晚。利用超过 65%的 CPU 或 RAM，或开始注意到磁盘交换，都应该是开始考虑扩展的门槛，可以通过垂直扩展（使用更大的机器）或水平扩展（通过分片）。

+   分片时要小心：分片是对分片键的强烈承诺。如果做出错误决定，从操作角度来看可能会非常困难。在设计分片时，架构师需要深入考虑当前的工作负载（读/写）以及当前和预期的数据访问模式。

+   使用由 MongoDB 团队维护的应用程序驱动程序：这些驱动程序得到支持，并且往往比没有官方支持的驱动程序更新得更快。如果 MongoDB 尚不支持您使用的语言，请在 MongoDB 的 JIRA 跟踪系统中提交工单。

+   定期备份计划：无论您使用独立服务器、副本集还是分片，都应该使用定期备份策略作为第二级防止数据丢失的保护。XFS 是一个很好的文件系统选择，因为它可以执行快照备份。

+   手动备份应该避免：在可能的情况下应该使用定期自动备份。如果我们需要进行手动备份，那么我们可以使用副本集中的隐藏成员来进行备份。我们必须确保在该成员上使用`db.fsyncwithlock`，以获得节点的最大一致性，同时打开日志记录。如果这个卷在 AWS 上，我们可以立即进行 EBS 快照备份。

+   启用数据库访问控制：绝对不要在生产系统中放入没有访问控制的数据库。访问控制应该在节点级别实施，通过一个适当的防火墙，只允许特定应用服务器访问数据库，并在数据库级别使用内置角色或定义自定义角色。这必须在启动时使用`--auth`命令行参数进行初始化，并可以通过`admin`集合进行配置。

+   使用真实数据测试部署：由于 MongoDB 是一个无模式、面向文档的数据库，您可能有具有不同字段的文档。这意味着与关系数据库管理系统相比，使用尽可能接近生产数据的数据进行测试更加重要。具有意外值的额外字段的文档可能会导致应用程序在运行时顺利工作或崩溃之间的差异。尝试使用生产级数据部署一个分级服务器，或者至少在分级中使用适当的库（例如 Ruby 的 Faker）伪造生产数据。

# 模式设计最佳实践

MongoDB 是无模式的，您必须设计您的集合和索引以适应这一事实：

+   早期和频繁地建立索引：使用 MMS、Compass GUI 或日志识别常见的查询模式，并在项目开始时尽可能多地建立这些索引。

+   消除不必要的索引：与前面的建议有些相悖，监视数据库的查询模式变化，并删除未被使用的索引。索引将消耗内存和 I/O，因为它需要与数据库中的文档一起存储和更新。使用聚合管道和`$indexStats`，开发人员可以识别很少被使用的索引并将其删除。

+   使用复合索引，而不是索引交集：使用多个谓词（*A*和*B*，*C*或*D*和*E*等）进行查询，通常使用单个复合索引比使用多个简单索引更好。此外，复合索引将其数据按字段排序，我们可以在查询时利用这一点。在字段*A*、*B*和*C*上的索引将用于查询*A*、*(A,B)*、*(A,B,C)*，但不用于查询*(B,C)*或*(C)*。

+   低选择性索引：例如，在性别字段上建立索引，统计上会返回一半的文档，而在姓氏上建立索引只会返回少量具有相同姓氏的文档。

+   **使用正则表达式**：同样，由于索引是按值排序的，使用具有前置通配符的正则表达式（即`/.*BASE/`）将无法使用索引。使用具有尾随通配符的正则表达式（即`/DATA.*/`）可能是有效的，只要表达式中有足够的区分大小写的字符。

+   **避免在查询中使用否定**：索引是对值进行索引，而不是它们的缺失。在查询中使用`NOT`可能导致对整个表的扫描，而不是使用索引。

+   **使用部分索引**：如果我们需要对集合中的一部分文档进行索引，部分索引可以帮助我们最小化索引集并提高性能。部分索引将包括我们在所需查询中使用的过滤器上的条件。

+   **使用文档验证**：使用文档验证来监视插入文档中的新属性，并决定如何处理它们。通过将文档验证设置为警告，我们可以保留在设计阶段未预期插入具有任意属性的文档的日志，并决定这是设计的错误还是特性。

+   **使用 MongoDB Compass**：MongoDB 的免费可视化工具非常适合快速了解我们的数据以及随时间的增长。

+   **尊重 16MB 的最大文档大小**：MongoDB 的最大文档大小为 16MB。这是一个相当慷慨的限制，但在任何情况下都不应违反。允许文档无限增长不应是一个选项，尽管嵌入文档可能是高效的，但我们应始终记住这应该是受控制的。

+   **使用适当的存储引擎**：自 MongoDB 3.2 版本以来，MongoDB 引入了几个新的存储引擎。内存存储引擎应用于实时工作负载，而加密存储引擎应该是在对数据安全性有严格要求时的首选引擎。

# 写入耐久性的最佳实践

在 MongoDB 中，写入耐久性可以进行微调，并且根据我们的应用程序设计，应尽可能严格，而不影响我们的性能目标。

在 WiredTiger 存储引擎中微调数据并将其刷新到磁盘间隔，默认情况下是在最后一个检查点后每 60 秒将数据刷新到磁盘，或者在写入 2GB 数据后。这可以通过使用`--wiredTigerCheckpointDelaySecs`命令行选项进行更改。

在 MMAPv1 中，数据文件每 60 秒刷新到磁盘。这可以通过使用`--syncDelay`命令行选项进行更改。我们还可以执行各种任务，例如以下内容：

+   使用 WiredTiger，我们可以使用 XFS 文件系统进行多磁盘一致的快照

+   我们可以在数据卷中关闭`atime`和`diratime`

+   您可以确保有足够的交换空间（通常是内存大小的两倍）

+   如果在虚拟化环境中运行，可以使用 NOOP 调度程序

+   我们可以将文件描述符限制提高到数万个

+   我们可以禁用透明大页，并启用标准的 4-KVM 页

+   写入安全性应至少记录

+   SSD 读取默认应设置为 16 个块；HDD 应设置为 32 个块

+   我们可以在 BIOS 中关闭 NUMA

+   我们可以使用 RAID 10

+   您可以使用 NTP 同步主机之间的时间，特别是在分片环境中

+   只使用 64 位构建用于生产；32 位构建已过时，只能支持最多 2GB 的内存

# 复制的最佳实践

副本集是 MongoDB 提供冗余、高可用性和更高读取吞吐量的机制，在适当的条件下。在 MongoDB 中，复制易于配置并专注于操作术语：

+   **始终使用副本集**：即使您的数据集目前很小，而且您不指望它呈指数增长，您也永远不知道什么时候会发生。此外，至少有三个服务器的副本集有助于设计冗余，将工作负载分开为实时和分析（使用次要服务器），并从一开始就构建数据冗余。

+   **充分利用副本集**：副本集不仅用于数据复制。我们可以（而且在大多数情况下应该）使用主服务器进行写入，并从其中一个次要服务器进行偏好读取，以卸载主服务器。这可以通过为读取设置读取偏好和正确的写入关注来实现，以确保写入按需传播。

+   在 MongoDB 副本集中使用奇数个副本：如果一个服务器宕机或者与其他服务器失去连接（网络分区），其他服务器必须投票选举出主服务器。如果我们有奇数个副本集成员，我们可以保证每个服务器子集知道它们属于大多数还是少数的副本集成员。如果我们不能有奇数个副本，我们需要设置一个额外的主机作为仲裁者，唯一目的是在选举过程中进行投票。即使是 EC2 中的微型实例也可以完成这个任务。

# 分片的最佳实践

分片是 MongoDB 的水平扩展解决方案。在第八章中，*监控、备份和安全*，我们将更详细地介绍其使用，但以下是一些基于基础数据架构的最佳实践：

+   **考虑查询路由**：根据不同的分片键和技术，`mongos`查询路由器可能会将查询发送到一些（或全部）分片成员。在设计分片时，考虑我们的查询非常重要，这样我们的查询就不会命中所有的分片。

+   **使用标签感知分片**：标签可以在分片之间提供更精细的数据分布。使用每个分片的正确标签集，我们可以确保数据子集存储在特定的分片集中。这对于应用服务器、MongoDB 分片和用户之间的数据接近可能非常有用。

# 安全最佳实践

安全始终是多层次的方法，这些建议只是一些基本的需要在任何 MongoDB 数据库中完成的事项，它们并不构成详尽的清单：

+   应该禁用 HTTP 状态接口。

+   RESTful API 应该被禁用。

+   JSON API 应该被禁用。

+   使用 SSL 连接到 MongoDB。

+   审计系统活动。

+   使用专用系统用户访问 MongoDB，并具有适当的系统级访问权限。

+   如果不需要，禁用服务器端脚本。这将影响 MapReduce、内置的`db.group()`命令和`$where`操作。如果这些在您的代码库中没有使用，最好在启动时使用`--noscripting`参数禁用服务器端脚本。

# AWS 的最佳实践

当我们使用 MongoDB 时，我们可以在数据中心使用自己的服务器，使用 MongoDB Atlas 等 MongoDB 托管解决方案，或者通过 EC2 从亚马逊获取实例。EC2 实例是虚拟化的，并以透明的方式共享资源，在同一物理主机上放置 VM。因此，如果您选择这条路线，还有一些其他考虑因素需要考虑，如下所示：

+   使用 EBS 优化的 EC2 实例。

+   获取具有预留 IOPS 的 EBS 卷，以实现一致的性能。

+   使用 EBS 快照进行备份和恢复。

+   为了实现高可用性，可以使用不同的可用性区域，为了灾难恢复，可以使用不同的地区。在每个亚马逊提供的地区内使用不同的可用性区域可以保证我们的数据具有高可用性。不同的地区应该只用于灾难恢复，以防发生灾难性事件摧毁整个地区。一个地区可能是 EU-West-2（伦敦），而一个可用性区域是地区内的一个细分；目前，伦敦有两个可用性区域。

+   全球部署；本地访问。

+   对于真正的全球应用程序，用户来自不同的时区，我们应该在不同的地区拥有应用服务器，访问距离他们最近的数据，使用正确的读取偏好配置在每个服务器上。

# 参考文档

阅读一本书很棒（阅读这本书更棒），但持续学习是保持与 MongoDB 最新的方式。在接下来的章节中，我们将强调您应该去哪里获取更新和开发/运营参考资料。

# MongoDB 文档

[`docs.mongodb.com/manual/`](https://docs.mongodb.com/manual/)上的在线文档是每个开发人员的起点，无论是新手还是老手。

JIRA 跟踪器是查看已修复的错误和即将推出的功能的好地方：[`jira.mongodb.org/browse/SERVER/`](https://jira.mongodb.org/browse/SERVER/)。

# Packt 参考资料

关于 MongoDB 的其他好书如下：

+   *面向 Java 开发人员的 MongoDB*，Francesco Marchioni 著

+   *MongoDB 数据建模*，Wilson da Rocha França 著

+   Kristina Chodorow 的任何一本书

# 进一步阅读

MongoDB 用户组（[`groups.google.com/forum/#!forum/mongodb-user`](https://groups.google.com/forum/#!forum/mongodb-user)）有一个很好的用户问题存档，涉及功能和长期存在的错误。当某些功能不如预期时，这是一个可以去的地方。

在线论坛（Stack Overflow 和 Reddit 等）始终是知识的来源，但需要注意的是，某些内容可能是几年前发布的，可能已经不适用。在尝试之前一定要检查。

最后，MongoDB 大学是保持您的技能最新并了解最新功能和增加的好地方：[`university.mongodb.com/`](https://university.mongodb.com/)。

# 总结

在本章中，我们开始了我们的网络、SQL 和 NoSQL 技术之旅，从它们的起源到它们的当前状态。我们确定了 MongoDB 如何在多年来塑造 NoSQL 数据库的世界，以及它如何与其他 SQL 和 NoSQL 解决方案相比。

我们探讨了 MongoDB 的关键特性以及 MongoDB 在生产部署中的使用情况。我们确定了设计、部署和操作 MongoDB 的最佳实践。

最初，我们确定了如何通过查阅文档和在线资源来学习，这些资源可以帮助我们了解最新的功能和发展动态。

在下一章中，我们将深入探讨模式设计和数据建模，看看如何通过使用官方驱动程序和对象文档映射（ODM）来连接到 MongoDB，这是一种用于 NoSQL 数据库的对象关系映射器的变体。


# 第二章：模式设计和数据建模

本章将重点讨论无模式数据库（如 MongoDB）的模式设计。尽管这听起来有些违反直觉，但在开发 MongoDB 时，我们应该考虑一些因素。我们将了解 MongoDB 支持的模式考虑因素和数据类型。我们还将学习如何通过连接 Ruby、Python 和 PHP 来为 MongoDB 准备文本搜索的数据。

在本章中，我们将涵盖以下主题：

+   关系模式设计

+   数据建模

+   为原子操作建模数据

+   建模关系

+   连接到 MongoDB

# 关系模式设计

在关系数据库中，我们的设计目标是避免异常和冗余。当我们在多个列中存储相同的信息时，异常可能会发生；我们更新其中一个列，但没有更新其他列，因此最终得到相互冲突的信息。当我们无法删除一行而不丢失我们可能需要的信息时，异常也可能发生，可能是在其他引用它的行中。数据冗余可能发生在我们的数据不在正常形式中，但在不同的表中具有重复数据。这可能导致数据不一致，并且难以维护。

在关系数据库中，我们使用正常形式来规范化我们的数据。从基本的**第一正常形式**（**1NF**）开始，到 2NF、3NF 和 BCNF，我们根据功能依赖关系对我们的数据进行建模，如果我们遵循规则，我们最终可能会得到比领域模型对象更多的表。

实际上，关系数据库建模通常是由我们拥有的数据结构驱动的。在遵循某种**模型-视图-控制器**（**MVC**）模式的 Web 应用程序中，我们将根据我们的模型来设计我们的数据库，这些模型是根据**统一建模语言**（**UML**）图表约定进行建模的。像**Django**的 ORM 或 Rails 的**Active Record**这样的抽象帮助应用程序开发人员将数据库结构抽象为对象模型。最终，很多时候，我们最终设计我们的数据库是基于可用数据的结构。因此，我们是根据我们可以得到的答案来设计的。

# MongoDB 模式设计

与关系数据库相比，在 MongoDB 中，我们必须基于我们特定于应用程序的数据访问模式进行建模。找出我们的用户将会有的问题对于设计我们的实体至关重要。与 RDBMS 相比，数据重复和去规范化更频繁地使用，并且有充分的理由。

MongoDB 使用的文档模型意味着每个文档可以容纳的信息量远远多于或少于下一个文档，即使在同一个集合中也是如此。再加上在嵌入文档级别上 MongoDB 可以进行丰富和详细的查询，这意味着我们可以自由设计我们的文档。当我们了解我们的数据访问模式时，我们可以估计哪些字段需要被嵌入，哪些可以拆分到不同的集合中。

# 读写比

读写比通常是 MongoDB 建模的重要考虑因素。在读取数据时，我们希望避免散布/聚集的情况，即我们必须向多个分片发出随机 I/O 请求才能获取应用程序所需的数据。

另一方面，在写入数据时，我们希望将写入分散到尽可能多的服务器上，以避免过载任何一个服务器。这些目标表面上看起来是相互冲突的，但一旦我们了解我们的访问模式，并结合应用程序设计考虑，比如使用副本集从辅助节点读取，它们可以结合起来。

# 数据建模

在本节中，我们将讨论 MongoDB 使用的不同数据类型，它们如何映射到编程语言使用的数据类型，以及我们如何使用 Ruby、Python 和 PHP 在 MongoDB 中建模数据关系。

# 数据类型

MongoDB 使用 BSON，这是一种用于 JSON 文档的二进制编码序列化。 BSON 扩展了 JSON 数据类型，例如提供了原生数据和二进制数据类型。

与协议缓冲区相比，BSON 允许更灵活的模式，但以空间效率为代价。总的来说，BSON 在编码/解码操作中是空间高效、易于遍历和时间高效的，如下表所示。（请参阅 MongoDB 文档[`docs.mongodb.com/manual/reference/bson-types/`](https://docs.mongodb.com/manual/reference/bson-types/)）：

| **类型** | **数字** | **别名** | **备注** |
| --- | --- | --- | --- |
| 双精度 | 1 | `double` |  |
| String | 2 | `string` |  |
| 对象 | 3 | `object` |  |
| 数组 | 4 | `array` |  |
| 二进制数据 | 5 | `binData` |  |
| ObjectID | 7 | `objectId` |  |
| 布尔 | 8 | `bool` |  |
| 日期 | 9 | `date` |  |
| 空 | 10 | `null` |  |
| 正则表达式 | 11 | `regex` |  |
| JavaScript | 13 | `javascript` |  |
| JavaScript（带作用域） | 15 | `javascriptWithScope` |  |
| 32 位整数 | 16 | `int` |  |
| 时间戳 | 17 | `timestamp` |  |
| 64 位整数 | 18 | `long` |  |
| Decimal128 | 19 | `decimal` | 3.4 版中的新功能 |
| 最小键 | -1 | `minKey` |  |
| 最大键 | 127 | `maxKey` |  |
| 未定义 | 6 | `undefined` | 已弃用 |
| DBPointer | 12 | `dbPointer` | 已弃用 |
| 符号 | 14 | `symbol` | 已弃用 |

在 MongoDB 中，我们可以在给定字段的文档中具有不同值类型，并且在使用`$type`运算符进行查询时，我们对它们进行区分。

例如，如果我们在 GBP 中有一个 32 位整数和`double`数据类型的`balance`字段，如果`balance`中有便士或没有，我们可以轻松查询所有帐户，这些帐户具有任何以下查询中显示的四舍五入的`balance`：

```sql
db.account.find( { "balance" : { $type : 16 } } );
db.account.find( { "balance" : { $type : "integer" } } );
```

我们将在以下部分比较不同的数据类型。

# 比较不同的数据类型

由于 MongoDB 的性质，在同一字段中具有不同数据类型的对象是完全可以接受的。这可能是意外发生的，也可能是有意为之（即，在字段中有空值和实际值）。

不同类型数据的排序顺序，从高到低，如下所示：

1.  内部类型的最大键

1.  正则表达式

1.  时间戳

1.  日期

1.  布尔值

1.  ObjectID

1.  二进制数据

1.  数组

1.  对象

1.  符号，字符串

1.  数字（`int`，`long`，`double`）

1.  空

1.  内部类型的最小键

不存在的字段会按照在相应字段中具有`null`的方式进行排序。比较数组比较字段更复杂。比较的升序（或`<`）将比较每个数组的最小元素。比较的降序（或`>`）将比较每个数组的最大元素。

例如，查看以下情景：

```sql
> db.types.find()
{ "_id" : ObjectId("5908d58455454e2de6519c49"), "a" : [ 1, 2, 3 ] }
{ "_id" : ObjectId("5908d59d55454e2de6519c4a"), "a" : [ 2, 5 ] }
```

按升序排列，如下所示：

```sql
> db.types.find().sort({a:1})
{ "_id" : ObjectId("5908d58455454e2de6519c49"), "a" : [ 1, 2, 3 ] }
{ "_id" : ObjectId("5908d59d55454e2de6519c4a"), "a" : [ 2, 5 ] }
```

然而，按降序排列，如下所示：

```sql
> db.types.find().sort({a:-1})
{ "_id" : ObjectId("5908d59d55454e2de6519c4a"), "a" : [ 2, 5 ] }
{ "_id" : ObjectId("5908d58455454e2de6519c49"), "a" : [ 1, 2, 3 ] }
```

当比较数组与单个数字值时，也是如下示例所示。插入一个整数值为`4`的新文档的操作如下：

```sql
> db.types.insert({"a":4})
WriteResult({ "nInserted" : 1 })
```

以下示例显示了降序`sort`的代码片段：

```sql
> db.types.find().sort({a:-1})
{ "_id" : ObjectId("5908d59d55454e2de6519c4a"), "a" : [ 2, 5 ] }
{ "_id" : ObjectId("5908d73c55454e2de6519c4c"), "a" : 4 }
{ "_id" : ObjectId("5908d58455454e2de6519c49"), "a" : [ 1, 2, 3 ] }
```

以下示例是升序`sort`的代码片段：

```sql
> db.types.find().sort({a:1})
{ "_id" : ObjectId("5908d58455454e2de6519c49"), "a" : [ 1, 2, 3 ] }
{ "_id" : ObjectId("5908d59d55454e2de6519c4a"), "a" : [ 2, 5 ] }
{ "_id" : ObjectId("5908d73c55454e2de6519c4c"), "a" : 4 }
```

在每种情况下，我们都突出显示了要比较的值。

我们将在以下部分了解数据类型。

# 日期类型

日期以毫秒为单位存储，从 1970 年 1 月 1 日（纪元时间）开始生效。它们是 64 位有符号整数，允许在 1970 年之前和之后的 135 百万年范围内。负日期值表示 1970 年 1 月 1 日之前的日期。BSON 规范将`date`类型称为 UTC`DateTime`。

MongoDB 中的日期存储在 UTC 中。与一些关系数据库中的`timestamp`带有`timezone`数据类型不同。需要根据本地时间访问和修改时间戳的应用程序应该将`timezone`偏移量与日期一起存储，并在应用程序级别上偏移日期。

在 MongoDB shell 中，可以使用以下 JavaScript 格式来完成：

```sql
var now = new Date();
db.page_views.save({date: now,
 offset: now.getTimezoneOffset()});
```

然后您需要应用保存的偏移量来重建原始本地时间，就像以下示例中所示：

```sql
var record = db.page_views.findOne();
var localNow = new Date( record.date.getTime() - ( record.offset * 60000 ) );
```

在下一节中，我们将介绍`ObjectId`。

# ObjectId

`ObjectId`是 MongoDB 的特殊数据类型。每个文档从创建到销毁都有一个`_id`字段。它是集合中每个文档的主键，并且必须是唯一的。如果我们在`create`语句中省略了这个字段，它将自动分配一个`ObjectId`。

擅自更改`ObjectId`是不可取的，但我们可以小心使用它来达到我们的目的。

`ObjectId`具有以下区别：

+   它有 12 个字节

+   它是有序的

+   按 _id 排序将按每个文档的创建时间进行排序

+   存储创建时间可以通过在 shell 中使用`.getTimeStamp()`来访问

`ObjectId`的结构如下：

+   一个 4 字节的值，表示自 Unix 纪元以来的秒数

+   一个 3 字节的机器标识符

+   一个 2 字节的进程 ID

+   一个 3 字节的计数器，从一个随机值开始

下图显示了 ObjectID 的结构：

![](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-mongo-4x/img/28e23c3f-309a-4e34-b437-cfbce6e41960.png)

按其结构，`ObjectId`对于所有目的都是唯一的；但是，由于这是在客户端生成的，您应该检查底层库的源代码，以验证实现是否符合规范。

在下一节中，我们将学习有关建模原子操作的数据。

# 建模原子操作的数据

MongoDB 正在放宽许多在关系型数据库中找到的典型**原子性、一致性、隔离性和持久性**（**ACID**）约束。在没有事务的情况下，有时很难在操作中保持状态一致，特别是在发生故障时。

幸运的是，一些操作在文档级别上是原子的：

+   `update()`

+   `findandmodify()`

+   `remove()`

这些都是针对单个文档的原子（全部或无）。

这意味着，如果我们在同一文档中嵌入信息，我们可以确保它们始终同步。

一个示例是库存应用程序，每个库存中的物品都有一个文档，我们需要统计库存中剩余的可用物品数量，购物车中已放置的物品数量，并将这些数据用于计算总可用物品数量。

对于`total_available = 5`，`available_now = 3`，`shopping_cart_count = 2`，这个用例可能如下所示：`{available_now : 3, Shopping_cart_by: ["userA", "userB"] }`

当有人将商品放入购物车时，我们可以发出原子更新，将他们的用户 ID 添加到`shopping_cart_by`字段中，并同时将`available_now`字段减少一个。

此操作将在文档级别上保证是原子的。如果我们需要在同一集合中更新多个文档，更新操作可能会成功完成，而不修改我们打算修改的所有文档。这可能是因为该操作不能保证跨多个文档更新是原子的。

这种模式在某些情况下有所帮助，但并非所有情况都适用。在许多情况下，我们需要对所有文档或甚至集合应用多个更新，要么全部成功，要么全部失败。

一个典型的例子是两个账户之间的银行转账。我们想要从用户 A 那里减去 x 英镑，然后将 x 添加到用户 B 那里。如果我们无法完成这两个步骤中的任何一个，我们将返回到两个余额的原始状态。

这种模式的细节超出了本书的范围，但大致上，想法是实现一个手工编码的两阶段**提交**协议。该协议应该为每个转账创建一个新的事务条目，并在该事务中的每个可能状态（如初始、挂起、应用、完成、取消中、已取消）中创建一个新的事务条目，并根据每个事务留下的状态，对其应用适当的回滚函数。

如果您发现自己不得不在一个旨在避免它们的数据库中实现事务，请退一步，重新思考为什么需要这样做。

# 写隔离

我们可以节约地使用`$isolated`来隔离对多个文档的写入，以防其他写入者或读取者对这些文档进行操作。在前面的例子中，我们可以使用`$isolated`来更新多个文档，并确保在其他人有机会进行双倍花费并耗尽资金源账户之前，我们更新两个余额。

然而，这不会给我们带来原子性，即全有或全无的方法。因此，如果更新只部分修改了两个账户，我们仍然需要检测并取消处于挂起状态的任何修改。

`$isolated`在整个集合上使用独占锁，无论使用哪种存储引擎。这意味着在使用它时会有严重的速度惩罚，特别是对于 WiredTiger 文档级别的锁定语义。

`$isolated`在分片集群中不起作用，当我们决定从副本集转到分片部署时可能会成为一个问题。

# 读取隔离和一致性

在传统的关系数据库管理系统定义中，MongoDB 的读取操作将被描述为*读取未提交*。这意味着，默认情况下，读取可能会获取到最终不会持久到磁盘上的值，例如，数据丢失或副本集回滚操作。

特别是，在使用默认写入行为更新多个文档时，缺乏隔离可能会导致以下问题：

+   读取可能会错过在更新操作期间更新的文档

+   非串行化操作

+   读取操作不是即时的

这些可以通过使用`$isolated`运算符来解决，但会带来严重的性能惩罚。

在某些情况下，不使用`.snapshot()`的游标查询可能会得到不一致的结果。如果查询的结果游标获取了一个文档，而在查询仍在获取结果时该文档接收到更新，并且由于填充不足，最终位于磁盘上的不同物理位置，超出了查询结果游标的位置。`.snapshot()`是这种边缘情况的解决方案，但有以下限制：

+   它不适用于分片

+   它不适用于使用`sort()`或`hint()`来强制使用索引

+   它仍然不会提供即时读取行为

如果我们的集合大部分是静态数据，我们可以在查询字段中使用唯一索引来模拟`snapshot()`，并且仍然能够对其应用`sort()`。

总的来说，我们需要在应用程序级别应用保障措施，以确保我们不会得到意外的结果。

从版本 3.4 开始，MongoDB 提供了可线性化的读关注。通过从副本集的主要成员和大多数写关注中使用线性化的读关注，我们可以确保多个线程可以读取和写入单个文档，就好像单个线程在依次执行这些操作一样。在关系型数据库管理系统中，这被认为是一个线性化的调度，MongoDB 称之为实时顺序。

# 建模关系

在接下来的章节中，我们将解释如何将关系数据库管理系统理论中的关系转换为 MongoDB 的文档集合层次结构。我们还将研究如何在 MongoDB 中为文本搜索建模我们的数据。

# 一对一

从关系数据库世界来看，我们通过它们的关系来识别对象。一个一对一的关系可能是一个人和一个地址。在关系数据库中对其进行建模很可能需要两个表：一个**Person**表和一个**Address**表，**Address**表中有一个`person_id`外键，如下图所示：

![](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-mongo-4x/img/b045cf93-073f-43f2-aeb7-d0831e4e7b68.png)

在 MongoDB 中，完美的类比是两个集合，`Person`和`Address`，如下代码所示：

```sql
> db.Person.findOne()
{
"_id" : ObjectId("590a530e3e37d79acac26a41"), "name" : "alex"
}
> db.Address.findOne()
{
"_id" : ObjectId("590a537f3e37d79acac26a42"),
"person_id" : ObjectId("590a530e3e37d79acac26a41"),
"address" : "N29DD"
}
```

现在，我们可以像在关系数据库中一样使用相同的模式从`address`中查找`Person`，如下例所示：

```sql
> db.Person.find({"_id": db.Address.findOne({"address":"N29DD"}).person_id})
{
"_id" : ObjectId("590a530e3e37d79acac26a41"), "name" : "alex"
}
```

这种模式在关系世界中是众所周知的，并且有效。

在 MongoDB 中，我们不必遵循这种模式，因为有更适合模型这些关系的方式。

在 MongoDB 中，我们通常会通过嵌入来建模一对一或一对多的关系。如果一个人有两个地址，那么同样的例子将如下所示：

```sql
{ "_id" : ObjectId("590a55863e37d79acac26a43"), "name" : "alex", "address" : [ "N29DD", "SW1E5ND" ] }
```

使用嵌入数组，我们可以访问此用户拥有的每个`address`。嵌入查询丰富而灵活，因此我们可以在每个文档中存储更多信息，如下例所示：

```sql
{ "_id" : ObjectId("590a56743e37d79acac26a44"),
"name" : "alex",
"address" : [ { "description" : "home", "postcode" : "N29DD" },
{ "description" : "work", "postcode" : "SW1E5ND" } ] }
```

这种方法的优点如下：

+   无需跨不同集合进行两次查询

+   它可以利用原子更新来确保文档中的更新对于其他读取此文档的读者来说是全有或全无的

+   它可以在多个嵌套级别中嵌入属性，创建复杂的结构

最显著的缺点是文档的最大大小为 16 MB，因此这种方法不能用于任意数量的属性。在嵌入数组中存储数百个元素也会降低性能。

# 一对多和多对多

当关系的*多*方的元素数量可以无限增长时，最好使用引用。引用可以有两种形式：

1.  从关系的*一*方，存储多边元素的数组，如下例所示：

```sql
> db.Person.findOne()
{ "_id" : ObjectId("590a530e3e37d79acac26a41"), "name" : "alex", addresses:
[ ObjectID('590a56743e37d79acac26a44'),
ObjectID('590a56743e37d79acac26a46'),
ObjectID('590a56743e37d79acac26a54') ] }
```

1.  这样我们可以从一方获取`addresses`数组，然后使用`in`查询获取多方的所有文档，如下例所示：

```sql
> person = db.Person.findOne({"name":"mary"})
> addresses = db.Addresses.find({_id: {$in: person.addresses} })
```

将这种一对多转换为多对多就像在关系的两端（即`Person`和`Address`集合）都存储这个数组一样容易。

1.  从关系的多方，存储对一方的引用，如下例所示：

```sql
> db.Address.find()
{ "_id" : ObjectId("590a55863e37d79acac26a44"), "person":  ObjectId("590a530e3e37d79acac26a41"), "address" : [ "N29DD" ] }
{ "_id" : ObjectId("590a55863e37d79acac26a46"), "person":  ObjectId("590a530e3e37d79acac26a41"), "address" : [ "SW1E5ND" ] }
{ "_id" : ObjectId("590a55863e37d79acac26a54"), "person":  ObjectId("590a530e3e37d79acac26a41"), "address" : [ "N225QG" ] }
> person = db.Person.findOne({"name":"alex"})
> addresses = db.Addresses.find({"person": person._id})
```

正如我们所看到的，无论哪种设计，我们都需要对数据库进行两次查询以获取信息。第二种方法的优势在于它不会让任何文档无限增长，因此它可以用于一对多是一对数百万的情况。

# 为关键字搜索建模数据

在许多应用程序中，搜索文档中的关键字是一个常见的操作。如果这是一个核心操作，使用专门的搜索存储，如**Elasticsearch**是有意义的；然而，直到规模要求转移到不同的解决方案之前，MongoDB 可以有效地使用。

关键字搜索的基本需求是能够搜索整个文档中的关键字。例如，在`products`集合中的文档，如下例所示：

```sql
{ name : "Macbook Pro late 2016 15in" ,
  manufacturer : "Apple" ,
  price: 2000 ,
  keywords : [ "Macbook Pro late 2016 15in", "2000", "Apple", "macbook", "laptop", "computer" ]
 }
```

我们可以在`keywords`字段中创建多键索引，如下例所示：

```sql
> db.products.createIndex( { keywords: 1 } )
```

现在我们可以在`keywords`字段中搜索任何名称、制造商、价格，以及我们设置的任何自定义关键字。这不是一种高效或灵活的方法，因为我们需要保持关键字列表同步，我们不能使用词干处理，也不能对结果进行排名（更像是过滤而不是搜索）。这种方法的唯一优点是它实现起来稍微快一些。

自 2.4 版本以来，MongoDB 就有了特殊的文本索引类型。它可以在一个或多个字段中声明，并支持词干处理、标记化、精确短语(`" "`)、否定(`-`)和加权结果。

在三个字段上声明具有自定义`权重`的索引如下例所示：

```sql
db.products.createIndex({
 name: "text",
 manufacturer: "text",
 price: "text"
 },
 {
 weights: { name: 10,
 manufacturer: 5,
 price: 1 },
 name: "ProductIndex"
 })
```

在这个例子中，`name`比`price`重要的程度是`10`倍，但比`manufacturer`只重要两倍。

可以使用通配符声明`text`索引，匹配与模式匹配的所有字段，如下例所示：

```sql
db.collection.createIndex( { "$**": "text" } )
```

这在我们有非结构化数据并且可能不知道它们将带有哪些字段时非常有用。我们可以像处理任何其他索引一样，通过名称删除索引。

然而，最大的优势是，除了所有的功能之外，所有的记录都是由数据库完成的。

在下一节中，我们将学习如何连接到 MongoDB。

# 连接到 MongoDB

有两种连接到 MongoDB 的方式。第一种是使用您的编程语言的驱动程序。第二种是使用 ODM 层以透明的方式将模型对象映射到 MongoDB。在本节中，我们将涵盖使用 Web 应用程序开发中最流行的三种语言：Ruby、Python 和 PHP 的两种方式。

# 使用 Ruby 连接

Ruby 是第一批得到 MongoDB 官方驱动程序支持的语言之一。在 GitHub 上，官方的 MongoDB Ruby 驱动程序是连接到 MongoDB 实例的推荐方式。执行以下步骤使用 Ruby 连接 MongoDB：

1.  安装就像将其添加到 Gemfile 一样简单，如下例所示：

```sql
gem 'mongo', '~> 2.6'
```

您需要安装 Ruby，然后从[`rvm.io/rvm/install`](https://rvm.io/rvm/install)安装 RVM，最后运行`gem install bundler`。

1.  然后，在我们的类中，我们可以连接到数据库，如下例所示：

```sql
require 'mongo'
client = Mongo::Client.new([ '127.0.0.1:27017' ], database: 'test')
```

1.  这是可能的最简单的例子：连接到我们的`localhost`中名为`test`的单个数据库实例。在大多数情况下，我们至少会有一个副本集要连接，如下面的代码片段所示：

```sql
client_host = ['server1_hostname:server1_ip, server2_hostname:server2_ip']
 client_options = {
  database: 'YOUR_DATABASE_NAME',
  replica_set: 'REPLICA_SET_NAME',
  user: 'YOUR_USERNAME',
  password: 'YOUR_PASSWORD'
 }
client = Mongo::Client.new(client_host, client_options)
```

1.  `client_host`服务器正在为客户端驱动程序提供服务器以尝试连接。一旦连接，驱动程序将根据主/次读取或写入配置确定要连接的服务器。`replica_set`属性需要匹配`REPLICA_SET_NAME`才能连接。

1.  `user`和`password`是可选的，但在任何 MongoDB 实例中都强烈建议使用。在`mongod.conf`文件中默认启用身份验证是一个良好的做法，我们将在第八章中了解更多信息，*监控、备份和安全*。

1.  连接到分片集群与连接到副本集类似，唯一的区别是，我们需要连接到充当 MongoDB 路由器的 MongoDB 进程，而不是提供服务器主机/端口。

# Mongoid ODM

使用低级驱动程序连接到 MongoDB 数据库通常不是最有效的方法。低级驱动程序提供的所有灵活性都抵消了更长的开发时间和用于将我们的模型与数据库粘合在一起的代码。

ODM 可以是这些问题的答案。就像 ORM 一样，ODM 弥合了我们的模型和数据库之间的差距。在 Rails 中，作为 Ruby 最广泛使用的 MVC 框架的 Mongoid 可以用于以类似于 Active Record 的方式对我们的数据进行建模。

安装`gem`类似于 Mongo Ruby 驱动程序，通过在 Gemfile 中添加一个文件，如下面的代码所示：

```sql
gem 'mongoid', '~> 7.0'
```

根据 Rails 的版本，我们可能还需要将以下内容添加到`application.rb`中：

```sql
config.generators do |g|
g.orm :mongoid
end
```

通过配置文件`mongoid.yml`连接到数据库，配置选项以语义缩进的键值对形式传递。其结构类似于用于关系数据库的`database.yml`。

我们可以通过`mongoid.yml`文件传递的一些选项如下表所示：

| **选项值** | **描述** |
| --- | --- |
| `Database` | 数据库名称。 |
| `Hosts` | 我们的数据库主机。 |
| `Write`/`w` | 写入关注（默认为 1）。 |
| `Auth_mech` | 认证机制。有效选项包括：`:scram`、`:mongodb_cr`、`:mongodb_x509`和`:plain`。3.0 的默认选项是`:scram`，而 2.4 和 2.6 的默认选项是`:plain`。 |
| `Auth_source` | 我们认证机制的认证源。 |
| `Min_pool_size`/`max_pool_size` | 连接的最小和最大池大小。 |
| `SSL`、`ssl_cert`、`ssl_key`、`ssl_key_pass_phrase`、`ssl_verify` | 一组关于与数据库的 SSL 连接的选项。 |
| `Include_root_in_json` | 在 JSON 序列化中包含根模型名称。 |
| `Include_type_for_serialization` | 在序列化 MongoDB 对象时包含`_type`字段。 |
| `Use_activesupport_time_zone` | 在服务器和客户端之间转换时间戳时使用 active support 的时区。 |

下一步是修改我们的模型以存储在 MongoDB 中。这就像在模型声明中包含一行代码那样简单，如下例所示：

```sql
class Person
  include Mongoid::Document
 End
```

我们还可以使用以下代码：

```sql
include Mongoid::Timestamps
```

我们用它来生成类似于 Active Record 的 `created_at` 和 `updated_at` 字段。在我们的模型中，数据字段不需要按类型声明，但这样做是个好习惯。支持的数据类型如下：

+   `Array`

+   `BigDecimal`

+   `Boolean`

+   `Date`

+   `DateTime`

+   `Float`

+   `Hash`

+   `Integer`

+   `BSON::ObjectId`

+   `BSON::Binary`

+   `Range`

+   `Regexp`

+   `String`

+   `Symbol`

+   `Time`

+   `TimeWithZone`

如果字段的类型未定义，字段将被转换为对象并存储在数据库中。这样稍微快一些，但不支持所有类型。如果我们尝试使用 `BigDecimal`、`Date`、`DateTime` 或 `Range`，将会收到错误信息。

# 使用 Mongoid 模型进行继承

以下代码是使用 Mongoid 模型进行继承的示例：

```sql
class Canvas
  include Mongoid::Document
  field :name, type: String
  embeds_many :shapes
end

class Shape
  include Mongoid::Document
  field :x, type: Integer
  field :y, type: Integer
  embedded_in :canvas
end

class Circle < Shape
  field :radius, type: Float
end

class Rectangle < Shape
  field :width, type: Float
  field :height, type: Float
end
```

现在，我们有一个具有许多嵌入的 `Shape` 对象的 `Canvas` 类。Mongoid 将自动创建一个字段，即 `_type`，以区分父节点和子节点字段。在从字段继承文档的情况下，关系、验证和作用域会复制到其子文档中，但反之则不会。

`embeds_many` 和 `embedded_in` 对将创建嵌入式子文档以存储关系。如果我们想通过引用 `ObjectId` 来存储这些关系，可以通过将它们替换为 `has_many` 和 `belongs_to` 来实现。

# 使用 Python 进行连接

与 Ruby 和 Rails 相媲美的是 Python 和 Django。类似于 Mongoid，还有 MongoEngine 和官方的 MongoDB 低级驱动程序 PyMongo。

使用 `pip` 或 `easy_install` 安装 PyMongo，如下代码所示：

```sql
python -m pip install pymongo
python -m easy_install pymongo
```

然后，在我们的类中，我们可以连接到数据库，如下例所示：

```sql
>>> from pymongo import MongoClient
>>> client = MongoClient()
```

连接到副本集需要一组种子服务器，客户端可以找出集合中的主、从或仲裁节点，如下例所示：

```sql
client = pymongo.MongoClient('mongodb://user:passwd@node1:p1,node2:p2/?replicaSet=rsname')
```

使用连接字符串 URL，我们可以在单个字符串中传递用户名、密码和 `replicaSet` 名称。连接字符串 URL 的一些最有趣的选项在下一节中。

连接到分片需要 MongoDB 路由器的服务器主机和 IP，这是 MongoDB 进程。

# PyMODM ODM

与 Ruby 的 Mongoid 类似，PyMODM 是 Python 的 ODM，紧随 Django 内置的 ORM。通过 `pip` 安装 `pymodm`，如下代码所示：

```sql
pip install pymodm
```

然后我们需要编辑 `settings.py`，将数据库 `ENGINE` 替换为 `dummy` 数据库，如下代码所示：

```sql
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.dummy'
    }
}
```

然后我们在 `settings.py` 的任何位置添加我们的连接字符串，如下代码所示：

```sql
from pymodm import connect
connect("mongodb://localhost:27017/myDatabase", alias="MyApplication")
```

在这里，我们必须使用具有以下结构的连接字符串：

```sql
mongodb://[username:password@]host1[:port1][,host2[:port2],...[,hostN[:portN]]][/[database][?options]]
```

选项必须是`name=value`对，每对之间用`&`分隔。一些有趣的对如下表所示：

| **名称** | **描述** |
| --- | --- |
| `minPoolSize`/`maxPoolSize` | 连接的最小和最大池大小。 |
| `w` | 写关注选项。 |
| `wtimeoutMS` | 写关注操作的超时时间。 |
| `Journal` | 日志选项。 |
| `readPreference` | 用于副本集的读取偏好。可用选项包括：`primary`、`primaryPreferred`、`secondary`、`secondaryPreferred`、`nearest`。 |
| `maxStalenessSeconds` | 指定从主服务器滞后的数据可以在客户端停止使用之前的秒数。 |
| `SSL` | 使用 SSL 连接到数据库。 |
| `authSource` | 与用户名一起使用，指定与用户凭据关联的数据库。当我们使用外部认证机制时，LDAP 或 Kerberos 应该是 `$external`。 |
| `authMechanism` | 可用于连接的身份验证机制。MongoDB 的可用选项有：**SCRAM-SHA-1**，**MONGODB-CR**，**MONGODB-X.509**。MongoDB 企业版（付费版本）提供了两个更多的选项：**GSSAPI**（Kerberos），**PLAIN**（**LDAP SASL**） |

模型类需要继承自`MongoModel`。以下代码显示了一个示例类的样子：

```sql
from pymodm import MongoModel, fields
class User(MongoModel):
    email = fields.EmailField(primary_key=True)
    first_name = fields.CharField()
    last_name = fields.CharField()
```

这里有一个`User`类，有`first_name`，`last_name`和`email`字段，其中`email`是主要字段。

# PyMODM 模型的继承

在 MongoDB 中处理一对一和一对多关系可以使用引用或嵌入。下面的例子展示了两种方式，即用户模型的引用和评论模型的嵌入：

```sql
from pymodm import EmbeddedMongoModel, MongoModel, fields

class Comment(EmbeddedMongoModel):
    author = fields.ReferenceField(User)
    content = fields.CharField()

class Post(MongoModel):
    title = fields.CharField()
    author = fields.ReferenceField(User)
    revised_on = fields.DateTimeField()
    content = fields.CharField()
    comments = fields.EmbeddedDocumentListField(Comment)
```

类似于 Ruby 的 Mongoid，我们可以根据设计决定将关系定义为嵌入式或引用式。

# 使用 PHP 连接

两年前，MongoDB PHP 驱动程序从头开始重写，以支持 PHP 5、PHP 7 和 HHVM 架构。当前的架构如下图所示：

![](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-mongo-4x/img/0e79b102-ba4d-4275-9559-dcb782394764.png)

目前，我们对所有三种架构都有官方驱动程序，完全支持底层功能。

安装是一个两步过程。首先，我们需要安装 MongoDB 扩展。这个扩展依赖于我们安装的 PHP（或 HHVM）的版本，可以使用 macOS 中的`brew`来完成。以下示例是使用 PHP 7.0：

```sql
brew install php70-mongodb
```

然后，像下面的例子一样使用`composer`（PHP 中广泛使用的依赖管理器）：

```sql
composer require mongodb/mongodb
```

可以通过使用连接字符串 URL 或通过传递一个选项数组来连接到数据库。

使用连接字符串 URL，我们有以下代码：

```sql
$client = new MongoDB\Client($uri = 'mongodb://127.0.0.1/', array $uriOptions = [], array $driverOptions = [])
```

例如，要使用 SSL 身份验证连接到副本集，我们使用以下代码：

```sql
$client = new MongoDB\Client('mongodb://myUsername:myPassword@rs1.example.com,rs2.example.com/?ssl=true&replicaSet=myReplicaSet&authSource=admin');
```

或者我们可以使用`$uriOptions`参数来传递参数，而不使用连接字符串 URL，如下面的代码所示：

```sql
$client = new MongoDB\Client(
 'mongodb://rs1.example.com,rs2.example.com/'
 [
 'username' => 'myUsername',
 'password' => 'myPassword',
 'ssl' => true,
 'replicaSet' => 'myReplicaSet',
 'authSource' => 'admin',
 ],
);
```

可用的`$uriOptions`和连接字符串 URL 选项与用于 Ruby 和 Python 的选项类似。

# Doctrine ODM

**Laravel**是 PHP 中最广泛使用的 MVC 框架之一，类似于 Python 和 Ruby 世界中的 Django 和 Rails 的架构。我们将通过配置我们的模型使用 Laravel，Doctrine 和 MongoDB。本节假设 Doctrine 已安装并与 Laravel 5.x 一起使用。

Doctrine 实体是**Plain Old PHP Objects**（**POPO**），与**Eloquent**不同，Laravel 的默认 ORM 不需要继承`Model`类。Doctrine 使用**Data Mapper Pattern**，而 Eloquent 使用 Active Record。跳过`get()`和`set()`方法，一个简单的类将如下所示：

```sql
use Doctrine\ORM\Mapping AS ORM;
use Doctrine\Common\Collections\ArrayCollection;
/**
* @ORM\Entity
* @ORM\Table(name="scientist")
*/
class Scientist
{
   /**
    * @ORM\Id
    * @ORM\GeneratedValue
    * @ORM\Column(type="integer")
    */
   protected $id;
   /**
    * @ORM\Column(type="string")
    */
   protected $firstname;
   /**
    * @ORM\Column(type="string")
    */
   protected $lastname;
   /**
   * @ORM\OneToMany(targetEntity="Theory", mappedBy="scientist", cascade={"persist"})
   * @var ArrayCollection|Theory[]
   */
   protected $theories;
   /**
   * @param $firstname
   * @param $lastname
   */
   public function __construct($firstname, $lastname)
   {
       $this->firstname = $firstname;
       $this->lastname  = $lastname;
       $this->theories = new ArrayCollection;
   }
...
   public function addTheory(Theory $theory)
   {
       if(!$this->theories->contains($theory)) {
           $theory->setScientist($this);
           $this->theories->add($theory);
       }
   }
```

这个基于 POPO 的模型使用注释来定义需要在 MongoDB 中持久化的字段类型。例如，`@ORM\Column(type="string")`定义了 MongoDB 中的一个字段，`string`类型的`firstname`和`lastname`作为属性名称，在相应的行中。

这里有一整套可用的注释：[`doctrine2.readthedocs.io/en/latest/reference/annotations-reference.html`](https://doctrine2.readthedocs.io/en/latest/reference/annotations-reference.html)。

如果我们想要将 POPO 结构与注释分开，我们也可以使用 YAML 或 XML 来定义它们，而不是在我们的 POPO 模型类中使用注释。

# Doctrine 的继承

可以通过注释、YAML 或 XML 来建模一对一和一对多关系。使用注释，我们可以在我们的文档中定义多个嵌入的子文档，如下例所示：

```sql
/** @Document */
class User
{
   // ...
   /** @EmbedMany(targetDocument="Phonenumber") */
   private $phonenumbers = array();
   // ...
}
/** @EmbeddedDocument */
class Phonenumber
{
   // ...
}
```

在这里，一个`User`文档嵌入了许多`phonenumbers`。`@EmbedOne()`将嵌入一个子文档，用于建模一对一关系。

引用与嵌入类似，如下例所示：

```sql
/** @Document */
class User
{
   // ...
   /**
    * @ReferenceMany(targetDocument="Account")
    */
   private $accounts = array();
   // ...
}
/** @Document */
class Account
{
   // ...
}
```

`@ReferenceMany()`和`@ReferenceOne()`用于通过引用到单独的集合来建模一对多和一对一关系。

# 摘要

在本章中，我们学习了关系数据库和 MongoDB 的模式设计，以及如何从不同的起点开始实现相同的目标。

在 MongoDB 中，我们必须考虑读写比例，用户在最常见情况下可能会遇到的问题，以及关系之间的基数。

我们学习了关于原子操作以及如何构建查询，以便在没有事务开销的情况下具有 ACID 属性。

我们还了解了 MongoDB 的数据类型，它们如何进行比较，以及一些特殊的数据类型，比如`ObjectId`，它可以被数据库和我们自己利用。

从建模简单的一对一关系开始，我们经历了一对多关系和多对多关系建模，而无需像在关系数据库中那样使用中间表，可以使用引用或嵌入文档。

我们学习了如何为关键字搜索建模数据，这是大多数应用程序在 Web 环境中需要支持的功能之一。

最后，我们探讨了在三种最流行的 Web 编程语言中使用 MongoDB 的不同用例。我们看到了使用官方驱动程序和 Mongoid ODM 的 Ruby 的示例。然后我们探讨了如何使用官方驱动程序和 PyMODM ODM 连接 Python，最后，我们通过使用官方驱动程序和 Doctrine ODM 在 PHP 中的示例进行了工作。

对于所有这些语言（以及许多其他语言），都有官方驱动程序提供支持和完全访问底层数据库操作功能，还有**对象数据建模**框架，用于轻松建模我们的数据和快速开发。

在下一章中，我们将深入探讨 MongoDB shell 以及我们可以使用它实现的操作。我们还将掌握使用驱动程序对我们的文档进行 CRUD 操作。


# 第二部分：高效查询

在本部分，我们将涵盖更高级的 MongoDB 操作。我们将从 CRUD 操作开始，这是最常用的操作。然后，我们将转向更高级的查询概念，接着是在 4.0 版本中引入的多文档 ACID 事务。接下来要讨论的话题是聚合框架，它可以帮助用户以结构化和高效的方式处理大数据。最后，我们将学习如何对数据进行索引，以使读取速度更快，但不影响写入性能。

本部分包括以下章节：

+   第三章，*MongoDB CRUD 操作*

+   第四章，*高级查询*

+   第五章，*多文档 ACID 事务*

+   第六章，*聚合*

+   第七章，*索引*


# 第三章：MongoDB CRUD 操作

在本章中，我们将学习如何使用 mongo shell 进行数据库管理操作。从简单的**创建**、**读取**、**更新**和**删除**（CRUD）操作开始，我们将掌握从 shell 进行脚本编写。我们还将学习如何从 shell 编写 MapReduce 脚本，并将其与聚合框架进行对比，我们将在第六章中深入探讨聚合。最后，我们将探讨使用 MongoDB 社区及其付费版本企业版进行身份验证和授权。

在本章中，我们将涵盖以下主题：

+   +   使用 shell 进行 CRUD

+   管理

+   聚合框架

+   保护 shell

+   使用 MongoDB 进行身份验证

# 使用 shell 进行 CRUD

mongo shell 相当于关系数据库使用的管理控制台。连接到 mongo shell 就像输入以下代码一样简单：

```sql
$ mongo
```

对于独立服务器或副本集，请在命令行上键入此代码。在 shell 中，您可以通过输入以下代码简单查看可用的数据库：

```sql
$ db
```

然后，您可以通过输入以下代码连接到数据库：

```sql
> use <database_name>
```

mongo shell 可用于查询和更新我们的数据库中的数据。可以通过以下方式将此文档插入到`books`集合中：

```sql
> db.books.insert({title: 'mastering mongoDB', isbn: '101'})
WriteResult({ "nInserted" : 1 })
```

然后，我们可以通过输入以下内容从名为`books`的集合中查找文档：

```sql
> db.books.find()
{ "_id" : ObjectId("592033f6141daf984112d07c"), "title" : "mastering mongoDB", "isbn" : "101" }
```

我们从 MongoDB 得到的结果告诉我们写入成功，并在数据库中插入了一个新文档。

删除这个文档有类似的语法，并导致以下代码的结果：

```sql
> db.books.remove({isbn: '101'})
WriteResult({ "nRemoved" : 1 })
```

您可以尝试按照以下代码块中所示更新相同的文档：

```sql
> db.books.update({isbn:'101'}, {price: 30})
WriteResult({ "nMatched" : 1, "nUpserted" : 0, "nModified" : 1 })
> db.books.find()
{ "_id" : ObjectId("592034c7141daf984112d07d"), "price" : 30 }
```

在这里，我们注意到了一些事情：

+   `update`命令中的类似 JSON 格式的字段是我们搜索要更新的文档的查询

+   `WriteResult`对象通知我们查询匹配了一个文档并修改了一个文档

+   最重要的是，该文档的内容完全被第二个类似 JSON 格式的字段的内容替换，但我们丢失了`title`和`isbn`的信息

默认情况下，MongoDB 中的`update`命令将使用我们在第二个参数中指定的文档替换我们文档的内容。如果我们想要更新文档并向其添加新字段，我们需要使用`$set`运算符，如下所示：

```sql
> db.books.update({isbn:'101'}, {$set: {price: 30}})
WriteResult({ "nMatched" : 1, "nUpserted" : 0, "nModified" : 1 })
```

现在，我们的文档与我们的预期相匹配：

```sql
> db.books.find()
{ "_id" : ObjectId("592035f6141daf984112d07f"), "title" : "mastering mongoDB", "isbn" : "101", "price" : 30 }
```

但是，删除文档可以通过多种方式完成，最简单的方式是通过其唯一的`ObjectId`：

```sql
> db.books.remove("592035f6141daf984112d07f")
WriteResult({ "nRemoved" : 1 })
> db.books.find()
>
```

您可以在这里看到，当没有结果时，mongo shell 除了 shell 提示本身之外不会返回任何内容：`>`。

# 为 mongo shell 编写脚本

使用内置命令管理数据库是有帮助的，但这并不是使用 shell 的主要原因。mongo shell 的真正强大之处在于它是一个 JavaScript shell。

我们可以在 shell 中声明和分配变量，如下所示：

```sql
> var title = 'MongoDB in a nutshell'
> title
MongoDB in a nutshell
> db.books.insert({title: title, isbn: 102})
WriteResult({ "nInserted" : 1 })
> db.books.find()
{ "_id" : ObjectId("59203874141daf984112d080"), "title" : "MongoDB in a nutshell", "isbn" : 102 }
```

在前面的例子中，我们声明了一个名为`title`的新变量，值为`MongoDB in a nutshell`，并使用该变量将一个新文档插入到我们的`books`集合中，如下面的代码所示。

由于它是一个 JavaScript shell，我们可以使用它来生成复杂结果的函数和脚本：

```sql
> queryBooksByIsbn = function(isbn) { return db.books.find({isbn: isbn})}
```

使用这个一行代码，我们创建了一个名为`queryBooksByIsbn`的新函数，它接受一个参数，即`isbn`值。有了我们在集合中的数据，我们可以使用我们的新函数并按`isbn`获取书籍，如下面的代码所示：

```sql
> queryBooksByIsbn("101")
{ "_id" : ObjectId("592035f6141daf984112d07f"), "title" : "mastering mongoDB", "isbn" : "101", "price" : 30 }
```

使用 shell，我们可以编写和测试这些脚本。一旦我们满意，我们可以将它们存储在`.js`文件中，并直接从命令行调用它们：

```sql
$ mongo <script_name>.js
```

以下是关于这些脚本的默认行为的一些有用注释：

+   写操作将使用默认的写关注`1`，这是 MongoDB 当前版本的全局默认值。写关注`1`将请求确认写操作已传播到独立的`mongod`服务器或副本集中的主服务器。

+   要将脚本中的操作结果返回到标准输出，我们必须使用 JavaScript 的内置`print()`函数或 mongo 特定的`printjson()`函数，它以 JSON 格式打印出结果。

# 脚本编写 mongo shell 和直接使用之间的区别

在为 mongo shell 编写脚本时，我们不能使用 shell 助手。MongoDB 的命令，如`use <database_name>`，`show collections`和其他助手内置在 shell 中，因此无法从 JavaScript 上下文中使用，而我们的脚本将在其中执行。幸运的是，有它们的等价物可以从 JavaScript 执行上下文中使用，如下表所示：

| **Shell helpers** | **JavaScript equivalents** |
| --- | --- |
| `show dbs, show databases` | `db.adminCommand('listDatabases')` |
| `use <database_name>` | `db = db.getSiblingDB('<database_name>')` |
| `show collections` | `db.getCollectionNames()` |
| `show users` | `db.getUsers()` |
| `show roles` | `db.getRoles({showBuiltinRoles: true})` |
| `show log <logname>` | `db.adminCommand({ 'getLog' : '<logname>' })` |
| `show logs` | `db.adminCommand({ 'getLog' : '*' })` |

| `it` | `cursor = db.collection.find()` `if ( cursor.hasNext() ){`

` cursor.next();`

`}` |

在上表中，`it`是迭代光标，当我们查询并返回太多结果以显示在一个批处理中时，mongo shell 返回的。

使用 mongo shell，我们可以编写几乎任何我们从客户端编写的脚本，这意味着我们有一个非常强大的原型工具，可以快速了解我们的数据。

# 使用 shell 进行批量插入

在使用 shell 时，我们经常需要以编程方式插入大量文档。由于我们有一个 JavaScript shell，最直接的实现方式是通过循环迭代，逐步生成每个文档，并在每次循环迭代中执行写操作，如下所示：

```sql
> authorMongoFactory = function() {for(loop=0;loop<1000;loop++) {db.books.insert({name: "MongoDB factory book" + loop})}}
function () {for(loop=0;loop<1000;loop++) {db.books.insert({name: "MongoDB factory book" + loop})}}
```

在这个简单的例子中，我们为一个作者创建了一个`authorMongoFactory()`方法，他写了`1000`本关于 MongoDB 的书，每本书的名字略有不同：

```sql
> authorMongoFactory()
```

这将导致向数据库发出`1000`次写入。虽然从开发的角度来看很简单，但这种方法会给数据库带来压力。

相反，使用`bulk`写入，我们可以使用事先准备好的`1000`个文档发出单个数据库`insert`命令，如下所示：

```sql
> fastAuthorMongoFactory = function() {
var bulk = db.books.initializeUnorderedBulkOp();
for(loop=0;loop<1000;loop++) {bulk.insert({name: "MongoDB factory book" + loop})}
bulk.execute();
}
```

最终结果与之前相同，在我们的`books`集合中插入了`1000`个文档，结构如下：

```sql
> db.books.find()
{ "_id" : ObjectId("59204251141daf984112d851"), "name" : "MongoDB factory book0" }
{ "_id" : ObjectId("59204251141daf984112d852"), "name" : "MongoDB factory book1" }
{ "_id" : ObjectId("59204251141daf984112d853"), "name" : "MongoDB factory book2" }
…
{ "_id" : ObjectId("59204251141daf984112d853"), "name" : "MongoDB factory book999" }
```

从用户的角度来看，区别在于执行速度和对数据库的减轻压力。

在前面的例子中，我们使用了`initializeUnorderedBulkOp()`来设置`bulk`操作构建器。我们这样做的原因是因为我们不关心插入的顺序与我们使用`bulk.insert()`命令将它们添加到我们的`bulk`变量的顺序相同。

当我们可以确保所有操作彼此无关或幂等时，这是有意义的。

如果我们关心插入的顺序相同，我们可以使用`initializeOrderedBulkOp()`；通过更改函数的第二行，我们得到以下代码片段：

```sql
var bulk = db.books.initializeOrderedBulkOp();
```

# 使用 mongo shell 进行批量操作

在插入的情况下，我们通常可以期望操作的顺序并不重要。

然而，`bulk`可以用于比插入更多的操作。在下面的例子中，我们在`bookOrders`集合中有一本书，`isbn：101`，`name`为`Mastering MongoDB`，在`available`字段中有可购买的可用副本数量，有`99`本可供购买：

```sql
> db.bookOrders.find()
{ "_id" : ObjectId("59204793141daf984112dc3c"), "isbn" : 101, "name" : "Mastering MongoDB", "available" : 99 }
```

通过一系列操作在单个`bulk`操作中，我们将向库存中添加一本书，然后订购`100`本书，最终总共可用的副本为零：

```sql
> var bulk = db.bookOrders.initializeOrderedBulkOp();
> bulk.find({isbn: 101}).updateOne({$inc: {available : 1}});
> bulk.find({isbn: 101}).updateOne({$inc: {available : -100}});
> bulk.execute();
```

使用代码，我们将得到以下输出：

![](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-mongo-4x/img/be7ce6c2-d39a-4090-953c-aa8830588774.png)

使用`initializeOrderedBulkOp()`，我们可以确保在订购`100`本书之前添加一本书，以便我们永远不会缺货。相反，如果我们使用`initializeUnorderedBulkOp()`，我们就无法得到这样的保证，我们可能会在添加新书之前收到 100 本书的订单，导致应用程序错误，因为我们没有那么多书来满足订单。

在执行有序操作列表时，MongoDB 将操作分成`1000`个批次，并按操作分组。例如，如果我们有`1002`个插入，`998`个更新，`1004`个删除，最后`5`个插入，我们最终会得到以下结果：

```sql
[1000 inserts]
[2 inserts]
[998 updates]
[1000 deletes]
[4 deletes]
[5 inserts] 
```

前面的代码可以解释如下：

![](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-mongo-4x/img/9bce1eca-424e-447a-a0df-5c866a63024f.png)

这不会影响操作系列，但隐含意味着我们的操作将以`1000`的批次离开数据库。这种行为不能保证在将来的版本中保持不变。

如果我们想要检查`bulk.execute()`命令的执行，我们可以在输入`execute()`后立即发出`bulk.getOperations()`。

自 3.2 版本以来，MongoDB 提供了批量写入的替代命令`bulkWrite()`。

`bulkWrite`参数是我们要执行的操作系列。`WriteConcern`（默认值再次为`1`），以及写操作系列是否应按照它们在数组中出现的顺序应用（默认情况下将按顺序排列）：

```sql
> db.collection.bulkWrite(
 [ <operation 1>, <operation 2>, ... ],
 {
 writeConcern : <document>,
 ordered : <boolean>
 }
)
```

以下操作与`bulk`支持的操作相同：

+   `insertOne`

+   `updateOne`

+   `updateMany`

+   `deleteOne`

+   `deleteMany`

+   `replaceOne`

`updateOne`，`deleteOne`和`replaceOne`具有匹配的过滤器；如果它们匹配多个文档，它们只会对第一个文档进行操作。重要的是要设计这些查询，以便它们不匹配多个文档，否则行为将是未定义的。

# 管理

在大多数情况下，使用 MongoDB 应该对开发人员尽可能透明。由于没有模式，因此不需要迁移，通常情况下，开发人员发现自己在数据库世界中花费的时间较少。

也就是说，有几个任务是经验丰富的 MongoDB 开发人员或架构师可以执行以保持 MongoDB 的速度和性能。

管理通常在三个不同的级别上执行，从更通用到更具体：**进程**，**集合**和**索引**。

在进程级别上，有`shutDown`命令来关闭 MongoDB 服务器。

在数据库级别上，我们有以下命令：

+   `dropDatabase`

+   `listCollections`

+   `copyDB`或`clone`以在本地克隆远程数据库

+   `repairDatabase`：当我们的数据库由于不干净的关闭而处于不一致状态时

相比之下，在集合级别上，使用以下命令：

+   `drop`：删除集合

+   `create`：创建集合

+   `renameCollection`：重命名集合

+   `cloneCollection`：将远程集合克隆到我们的本地数据库

+   `cloneCollectionAsCapped`：将集合克隆到新的封顶集合

+   `convertToCapped`：将集合转换为封顶集合

在索引级别上，我们可以使用以下命令：

+   `createIndexes`

+   `listIndexes`

+   `dropIndexes`

+   `reIndex`

我们还将介绍一些更重要的管理命令。

# fsync

MongoDB 通常每 60 秒将所有操作写入磁盘。fsync 将强制数据立即和同步地持久保存到磁盘。

如果我们想备份数据库，我们还需要应用锁。在 fsync 操作时，锁定将阻止所有写入和一些读取。

在几乎所有情况下，最好使用日志记录，并参考我们的备份和恢复技术，这将在第八章*，* *监控、备份和安全*中进行介绍，以获得最大的可用性和性能。

# compact

MongoDB 文档在磁盘上占据指定的空间。如果我们执行一个更新，增加了文档的大小，这可能会导致它被移出存储块的顺序，在存储中创建一个空洞，导致此更新的执行时间增加，并可能导致它在运行查询时被忽略。紧缩操作将对空间进行碎片整理，并减少使用的空间。

我们可以通过添加额外的 10 个字节来更新一个文档，展示它将如何被移动到存储块的末尾，并在物理存储中创建一个空间：

![](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-mongo-4x/img/8e60c62b-f925-4231-9ff6-6e43f60683df.png)

`compact`也可以接受`paddingFactor`参数，如下所示：

```sql
> db.runCommand ( { compact: '<collection>', paddingFactor: 2.0 } )
```

`paddingFactor`是每个文档中预分配的空间，范围从`1.0`（即没有填充，这是默认值）到`4.0`，用于计算每个文档空间的`100`字节所需的`300`字节填充。

添加填充可以帮助缓解更新移动文档的问题，但需要更多的磁盘空间来创建每个文档。通过为每个文档添加填充，我们为其分配了更多的空间，这将防止它被移动到预分配的存储空间的末尾，如果我们更新的文档仍然可以适应预分配的存储空间。

# currentOp 和 killOp

`db.currentOp()`将显示数据库中当前正在运行的操作，并尝试终止它。在运行`killOp()`之前，我们需要运行`use admin`命令。毋庸置疑，不建议或建议使用`killOp()`来终止内部 MongoDB 操作，因为数据库可能会处于未定义的状态。`killOp()`命令可以如下使用：

```sql
> db.runCommand( { "killOp": 1, "op": <operationId> } )
```

# collMod

`collMod`用于通过修改底层数据库的行为来向集合传递标志。

自版本 3.2 以来，我们可以传递给集合的最有趣的一组标志是文档验证。

文档验证可以指定一组规则，应用于对集合的新更新和插入。这意味着如果修改了当前文档，将会对当前文档进行检查。

如果我们将`validationLevel`设置为`moderate`，我们只能对已经有效的文档应用验证。通过指定`validationAction`，我们可以通过将其设置为`warn`来记录无效的文档，或者通过将其设置为`error`来完全阻止更新。

例如，对于之前的`bookOrders`示例，我们可以在每次插入或更新时设置`isbn`和`name`字段的`validator`，如下面的代码所示：

```sql
> db.runCommand( { collMod: "bookOrders",
"validator" : {
 "$and" : [
 {
 "isbn" : {
 "$exists" : true
 }
 },
 {
 "name" : {
 "$exists" : true
 }
 }
 ]
 }
})
```

在这里，我们得到了以下代码：

```sql
{ "ok" : 1 }
```

然后，如果我们尝试插入一个只有`isbn`字段的新文档，我们会收到一个错误：

```sql
> db.bookOrders.insert({isbn: 102})
WriteResult({
"nInserted" : 0,
"writeError" : {
"code" : 121,
"errmsg" : "Document failed validation"
}
})
>
```

我们收到错误是因为我们的验证失败了。从 shell 中管理验证非常有用，因为我们可以编写脚本来管理它，并确保一切就位。

# touch

`touch`命令将从存储中加载数据和/或索引数据到内存中。如果我们的脚本随后将使用这些数据，这通常是有用的，可以加快执行速度：

```sql
> db.runCommand({ touch: "bookOrders", data: true/false, index: true/false })
```

在生产系统中应谨慎使用此命令，因为将数据和索引加载到内存中将会将现有数据从中移除。

# 在 mongo shell 中的 MapReduce

在整个 MongoDB 历史中，一个被低估并且没有得到广泛支持的最有趣的功能之一，是能够在 shell 中原生地编写 MapReduce。

MapReduce 是一种从大量数据中获取聚合结果的数据处理方法。其主要优势在于它本质上是可并行化的，这可以通过 Hadoop 等框架来证明。

当用于实现数据管道时，MapReduce 非常有用。多个 MapReduce 命令可以链接在一起产生不同的结果。一个例子是通过使用不同的报告周期（如小时、天、周、月和年）对数据进行聚合，我们使用每个更精细的报告周期的输出来生成一个不太精细的报告。

在我们的例子中，MapReduce 的一个简单示例是，假设我们的输入书籍集合如下：

```sql
> db.books.find()
{ "_id" : ObjectId("592149c4aabac953a3a1e31e"), "isbn" : "101", "name" : "Mastering MongoDB", "price" : 30 }
{ "_id" : ObjectId("59214bc1aabac954263b24e0"), "isbn" : "102", "name" : "MongoDB in 7 years", "price" : 50 }
{ "_id" : ObjectId("59214bc1aabac954263b24e1"), "isbn" : "103", "name" : "MongoDB for experts", "price" : 40 }
```

我们的 map 和 reduce 函数定义如下：

```sql
> var mapper = function() {
 emit(this.id, 1);
 };
```

在这个`mapper`中，我们只是输出每个文档的`id`键和值`1`：

```sql
> var reducer = function(id, count) {
 return Array.sum(count);
 };
```

在`reducer`中，我们对所有值求和（每个值都是`1`）：

```sql
> db.books.mapReduce(mapper, reducer, { out:"books_count" });
{
"result" : "books_count",
"timeMillis" : 16613,
"counts" : {
"input" : 3,
"emit" : 3,
"reduce" : 1,
"output" : 1
},
"ok" : 1
}
> db.books_count.find()
{ "_id" : null, "value" : 3 }
>
```

我们的最终输出将是一个没有 ID 的文档，因为我们没有输出任何 ID 的值，以及一个值为六的文档，因为输入数据集中有六个文档。

使用 MapReduce，MongoDB 将对每个输入文档应用映射，在映射阶段结束时发出键值对。然后，每个 reducer 将获得具有与输入相同键的键值对，处理所有多个值。reducer 的输出将是每个键的单个键值对。

可选地，我们可以使用`finalize`函数进一步处理`mapper`和`reducer`的结果。MapReduce 函数使用 JavaScript 并在`mongod`进程中运行。MapReduce 可以作为单个文档内联输出，受到 16MB 文档大小限制的限制，或者作为输出集合中的多个文档输出。输入和输出集合可以进行分片。

# MapReduce 并发

MapReduce 操作将放置几个短暂的锁，不应影响操作。然而，在`reduce`阶段结束时，如果我们将数据输出到现有集合，则`merge`、`reduce`和`replace`等输出操作将为整个服务器获取独占全局写锁，阻止对`db`实例的所有其他写入。如果我们想避免这种情况，那么我们应该以以下方式调用`mapReduce`：

```sql
> db.collection.mapReduce(
 mapper,
 reducer,
 {
 out: { merge/reduce: bookOrders, nonAtomic: true  }
 })
```

我们只能将`nonAtomic`应用于`merge`或`reduce`操作。`replace`将只是替换`bookOrders`中文档的内容，这也不会花费太多时间。

使用`merge`操作，如果输出集合已经存在，新结果将与现有结果合并。如果现有文档具有与新结果相同的键，则它将覆盖现有文档。

使用`reduce`操作，如果输出集合已经存在，新结果将与现有结果一起处理。如果现有文档具有与新结果相同的键，则它将对新文档和现有文档应用`reduce`函数，并用结果覆盖现有文档。

尽管 MapReduce 自 MongoDB 的早期版本以来就存在，但它的发展不如数据库的其他部分，导致其使用量不及专门的 MapReduce 框架（如 Hadoop）多，我们将在第十一章中更多地了解有关*利用 MongoDB 进行大数据处理*。

# 增量 MapReduce

增量 MapReduce 是一种模式，我们使用 MapReduce 来聚合先前计算的值。一个例子是对不同的报告周期（即按小时、天或月）中的集合进行计数非不同用户，而无需每小时重新计算结果。

为了设置我们的数据进行增量 MapReduce，我们需要做以下工作：

+   将我们的减少数据输出到不同的集合

+   在每个小时结束时，只查询进入集合的数据

+   使用我们减少的数据输出，将我们的结果与上一个小时的计算结果合并

继续上一个例子，假设我们的输入数据集中每个文档都有一个`published`字段，如下所示：

```sql
> db.books.find()
{ "_id" : ObjectId("592149c4aabac953a3a1e31e"), "isbn" : "101", "name" : "Mastering MongoDB", "price" : 30, "published" : ISODate("2017-06-25T00:00:00Z") }
{ "_id" : ObjectId("59214bc1aabac954263b24e0"), "isbn" : "102", "name" : "MongoDB in 7 years", "price" : 50, "published" : ISODate("2017-06-26T00:00:00Z") }
```

使用我们之前计算书籍数量的例子，我们将得到以下代码：

```sql
var mapper = function() {
 emit(this.id, 1);
 };
var reducer = function(id, count) {
 return Array.sum(count);
 };
> db.books.mapReduce(mapper, reducer, { out: "books_count" })
{
"result" : "books_count",
"timeMillis" : 16700,
"counts" : {
"input" : 2,
"emit" : 2,
"reduce" : 1,
"output" : 1
},
"ok" : 1
}
> db.books_count.find()
{ "_id" : null, "value" : 2 }
```

现在我们在我们的`mongo_book`集合中得到了第三本书，内容如下：

```sql
{ "_id" : ObjectId("59214bc1aabac954263b24e1"), "isbn" : "103", "name" : "MongoDB for experts", "price" : 40, "published" : ISODate("2017-07-01T00:00:00Z") }
> db.books.mapReduce( mapper, reducer, { query: { published: { $gte: ISODate('2017-07-01 00:00:00') } }, out: { reduce: "books_count" } } )
> db.books_count.find()
{ "_id" : null, "value" : 3 }
```

在前面的代码中发生的是，通过查询 2017 年 7 月的文档，我们只得到了查询中的新文档，然后使用它的值将值与我们的`books_count`文档中已经计算的值`2`进行减少，将`1`添加到最终的`3`文档的总和中。

这个例子虽然有些牵强，但展示了 MapReduce 的一个强大特性：能够重新减少结果以逐渐计算聚合。

# 故障排除 MapReduce

多年来，MapReduce 框架的主要缺点之一是与简单的非分布式模式相比，故障排除的固有困难。大多数时候，最有效的工具是使用`log`语句进行调试，以验证输出值是否与我们预期的值匹配。在 mongo shell 中，这是一个 JavaScript shell，只需使用`console.log（）`函数提供输出即可。

深入了解 MongoDB 中的 MapReduce，我们可以通过重载输出值来调试映射和减少阶段。

通过调试`mapper`阶段，我们可以重载“emit（）”函数来测试输出键值将是什么，如下所示：

```sql
> var emit = function(key, value) {
 print("debugging mapper's emit");
 print("key: " + key + "  value: " + tojson(value));
}
```

然后我们可以手动调用它来验证我们得到了预期的键值对：

```sql
> var myDoc = db.orders.findOne( { _id: ObjectId("50a8240b927d5d8b5891743c") } );
> mapper.apply(myDoc);
```

`reducer`函数有点复杂。MapReduce`reducer`函数必须满足以下标准：

+   它必须是幂等的

+   它必须是可交换的

+   来自`mapper`函数的值的顺序对于减少器的结果并不重要

+   `reducer`函数必须返回与`mapper`函数相同类型的结果

我们将分解以下每个要求，以了解它们真正的含义：

+   **它必须是幂等的**：MapReduce 的设计可能会多次调用`reducer`函数，对于来自`mapper`阶段的相同键的多个值。它也不需要减少键的单个实例，因为它只是添加到集合中。无论执行顺序如何，最终值应该是相同的。这可以通过编写我们自己的`verifier`函数并强制`reducer`重新减少，或者像下面的代码片段中所示执行多次`reducer`来验证：

```sql
reduce( key, [ reduce(key, valuesArray) ] ) == reduce( key, valuesArray )
```

+   **它必须是可交换的**：由于对于相同的“键”，可能会多次调用`reducer`函数，如果它有多个值，以下代码应该成立：

```sql
reduce(key, [ C, reduce(key, [ A, B ]) ] ) == reduce( key, [ C, A, B ] )
```

+   **来自 mapper 函数的值的顺序对于 reducer 的结果并不重要**：我们可以测试`mapper`的值的顺序是否改变了`reducer`的输出，通过以不同的顺序将文档传递给`mapper`并验证我们得到了相同的结果：

```sql
reduce( key, [ A, B ] ) == reduce( key, [ B, A ] )
```

+   **减少函数必须返回与映射函数相同类型的结果**：与第一个要求紧密相关，`reduce`函数返回的对象类型应与`mapper`函数的输出相同。

# 聚合框架

自 2.2 版本以来，MongoDB 提供了一种更好的处理聚合的方式，这种方式一直得到支持、采用和定期增强。聚合框架是模仿数据处理管道的。

在数据处理管道中，有三个主要操作：像查询一样操作的过滤器，过滤文档，以及文档转换，以准备好进行下一阶段的转换。

# SQL 到聚合

聚合管道可以在 shell 中替换和增强查询操作。开发的常见模式如下：

+   验证我们是否有正确的数据结构，并使用一系列 shell 中的查询快速获得结果

+   使用聚合框架原型管道结果

+   根据需要进行细化和重构，可以通过 ETL 过程将数据放入专用数据仓库，也可以通过更广泛地使用应用程序层来获得所需的见解

在下表中，我们可以看到 SQL 命令如何映射到聚合框架操作符：

| SQL | 聚合框架 |
| --- | --- |
| WHERE / HAVING | $match |
| 分组 | $group |
| 选择 | $project |
| ORDER BY | $sort |
| LIMIT | $limit |
| sum() / count() | $sum |
| 连接 | $lookup |

# 聚合与 MapReduce

在 MongoDB 中，我们可以通过三种方法从数据库中获取数据：查询、聚合框架和 MapReduce。这三种方法都可以相互链接，很多时候这样做是有用的；然而，重要的是要理解何时应该使用聚合，何时 MapReduce 可能是更好的选择。

我们可以在分片数据库中同时使用聚合和 MapReduce。

聚合基于管道的概念。因此，能够对我们的数据进行建模，从输入到最终输出，在一系列的转换和处理中，可以让我们达到目标，这一点非常重要。当我们的中间结果可以单独使用或者供并行管道使用时，它也是非常有用的。我们的操作受到来自 MongoDB 的可用操作符的限制，因此确保我们可以使用可用的命令计算出所有需要的结果非常重要。

另一方面，MapReduce 可以通过将一个 MapReduce 作业的输出链接到下一个作业的输入，通过一个中间集合来构建管道，但这不是它的主要目的。

MapReduce 最常见的用例是定期计算大型数据集的聚合。有了 MongoDB 的查询，我们可以增量计算这些聚合，而无需每次都扫描整个输入表。此外，它的强大之处在于其灵活性，我们可以使用 JavaScript 定义映射器和减速器，完全灵活地计算中间结果。由于没有聚合框架提供的操作符，我们必须自己实现它们。

在许多情况下，答案不是二选一。我们可以（也应该）使用聚合框架来构建 ETL 管道，并在尚未得到足够支持的部分使用 MapReduce。

在《第六章》《聚合》中提供了一个完整的聚合和 MapReduce 用例。

# 保护 shell

MongoDB 是一个以开发便利性为目标开发的数据库。因此，数据库级别的安全性并不是从一开始就内置的，而是由开发人员和管理员来保护 MongoDB 主机不被外部应用服务器访问。

不幸的是，这意味着早在 2015 年，就发现有 39,890 个数据库对外开放，没有配置安全访问。其中许多是生产数据库，其中一个属于法国电信运营商，包含了超过 800 万条客户记录。

现在，没有任何借口可以让任何 MongoDB 服务器在任何开发阶段都保持默认的关闭认证设置。

# 认证和授权

认证和授权密切相关，有时会引起混淆。认证是验证用户对数据库的身份。认证的一个例子是安全套接字层（SSL），在这里，Web 服务器验证其身份——即它向用户所声称的身份。

授权是确定用户对资源可以执行哪些操作。在接下来的章节中，我们将根据这些定义讨论认证和授权。

# MongoDB 的授权

MongoDB 最基本的授权依赖于用户名/密码方法。默认情况下，MongoDB 不会启用授权。要启用它，我们需要使用`--auth`参数启动服务器。

```sql
$ mongod --auth
```

为了设置授权，我们需要在没有授权的情况下启动服务器以设置用户。设置管理员用户很简单：

```sql
> use admin
> db.createUser(
 {
 user: <adminUser>,
 pwd: <password>,
 roles: [ { role: <adminRole>, db: "admin" } ]
 }
)
```

在这里，`<adminUser>`是我们要创建的用户的名称，`<password>`是密码，`<adminRole>`可以是以下列表中从最强大到最弱的任何一个值：

+   `root`

+   `dbAdminAnyDatabase`

+   `userAdminAnyDatabase`

+   `readWriteAnyDatabase`

+   `readAnyDatabase`

+   `dbOwner`

+   `dbAdmin`

+   `userAdmin`

+   `readWrite`

+   `read`

在这些角色中，`root`是允许访问所有内容的超级用户。除了特殊情况，不建议使用这个角色。

所有的`AnyDatabase`角色都提供对所有数据库的访问权限，其中`dbAdminAnyDatabase`结合了`userAdminAnyDatabase`和`readWriteAnyDatabase`范围，再次成为所有数据库中的管理员。

其余的角色是在我们希望它们应用的数据库中定义的，通过更改前面的`db.createUser()`的角色子文档；例如，要为我们的`mongo_book`数据库创建`dbAdmin`，我们将使用以下代码：

```sql
> db.createUser(
 {
 user: <adminUser>,
 pwd: <password>,
 roles: [ { role: "dbAdmin", db: "mongo_book" } ]
 }
)
```

集群管理还有更多的角色，我们将在第十二章 *复制*中更深入地介绍。

最后，当我们使用`--auth`标志重新启动我们的数据库时，我们可以使用命令行或连接字符串（来自任何驱动程序）作为`admin`连接并创建具有预定义或自定义角色的新用户：

```sql
mongodb://[username:password@]host1[:port1][,host2[:port2],...[,hostN[:portN]]][/[database][?options]]
```

# MongoDB 的安全提示

常见的软件系统安全预防措施也适用于 MongoDB。我们将在这里概述其中一些，并学习如何启用它们。

# 使用 TLS/SSL 加密通信

`mongod`或`mongos`服务器与客户端 mongo shell 或应用程序之间的通信应该是加密的。这在大多数 MongoDB 发行版中从 3.0 版本开始就得到支持；但是，我们需要注意下载具有 SSL 支持的正确版本。

之后，我们需要从受信任的证书颁发机构获取签名证书，或者自己签名。对于预生产系统来说，使用自签名证书是可以的，但在生产中，这将意味着 MongoDB 服务器无法验证我们的身份，使我们容易受到中间人攻击的影响；因此强烈建议使用正确的证书。

要使用 SSL 启动我们的 MongoDB 服务器，我们需要以下代码：

```sql
$ mongod --sslMode requireSSL --sslPEMKeyFile <pem> --sslCAFile <ca>
```

在这里，`<pem>`是我们的`.pem`签名证书文件，`<ca>`是证书颁发机构的`.pem`根证书，其中包含根证书链。

这些选项也可以在我们的配置文件`mongod.conf`或`mongos.conf`中以 YAML 文件格式定义如下：

```sql
net:
  ssl:
     mode: requireSSL
     PEMKeyFile: /etc/ssl/mongodb.pem
     CAFile: /etc/ssl/ca.pem
     disabledProtocols: TLS1_0,TLS1_1,TLS1_2
```

在这里，我们指定了`PEMKeyFile`，`CAFile`，并且我们不允许服务器使用`TLS1_0`，`TLS1_1`或`TLS1_2`版本的证书启动。这些是当前可用的`disabledProtocols`版本。

# 加密数据

使用 WiredTiger 强烈建议用于对数据进行加密，因为它从 3.2 版本开始就原生支持。

对于社区版的用户，可以在他们选择的存储中实现这一点；例如，在**亚马逊网络服务**（**AWS**）中使用**弹性块存储**（**EBS**）加密存储卷。 

此功能仅适用于 MongoDB 企业版。

# 限制网络暴露

保护任何服务器的最古老的安全方法是禁止它接受来自未知来源的连接。在 MongoDB 中，这是在配置文件中通过一行简单的代码完成的，如下所示：

```sql
net:
  bindIp: <string>
```

在这里，`<string>`是 MongoDB 服务器将接受连接的 IP 的逗号分隔列表。

# 防火墙和 VPN

除了在服务器端限制网络暴露之外，我们还可以使用防火墙阻止外部互联网对我们网络的访问。VPN 也可以在我们的服务器之间提供隧道流量，但无论如何，它们都不应该作为我们唯一的安全机制。

# 审计

无论系统有多安全，我们都需要从审计的角度密切关注系统，以确保我们及时发现可能的违规行为并尽快停止它们。

此功能仅适用于 MongoDB 企业版。

对于社区版用户，我们必须通过在应用程序层记录文档和集合的更改来手动设置审计，可能在完全不同的数据库中。这将在下一章中讨论，该章节涵盖了使用客户端驱动程序进行高级查询。

# 使用安全配置选项

毫无疑问，应该使用相同的配置选项。我们必须使用以下之一：

+   MapReduce

+   mongo shell 组操作或来自客户端驱动程序的组操作

+   `$where` JavaScript 服务器评估

如果我们不这样做，我们应该在启动服务器时使用命令行上的`--noscripting`选项来禁用服务器端脚本。

如前面的列表中所述，mongo shell 组操作可能会有些棘手，因为许多驱动程序在发出组命令时可能会使用 MongoDB 的`group()`命令。然而，考虑到`group()`在性能和输出文档方面的限制，我们应该重新考虑我们的设计，使用聚合框架或应用程序端的聚合。

还必须通过不使用以下任何命令来禁用 Web 界面：

+   `net.http.enabled`

+   `net.http.JSONPEnabled`

+   `net.http.RESTInterfaceEnabled`

相反，`wireObjectCheck`需要保持默认启用，以确保`mongod`实例存储的所有文档都是有效的 BSON。

# 使用 MongoDB 进行身份验证

默认情况下，MongoDB 使用 SCRAM-SHA-1 作为默认的挑战和响应身份验证机制。这是一种基于 SHA-1 的用户名/密码身份验证机制。所有驱动程序和 mongo shell 本身都具有内置方法来支持它。

自 MongoDB 3.0 版本以来，MongoDB 中的身份验证协议已经发生了变化。在旧版本中，使用了不太安全的 MONGODB-CR。

# 企业版

MongoDB 的企业版是一种付费订阅产品，提供了更多关于安全性和管理的功能。

# Kerberos 身份验证

MongoDB 企业版还提供 Kerberos 身份验证。Kerberos 是根据希腊神话中的角色 Kerberos（或 Cerberus）命名的，它是地府之神哈迪斯的凶猛的三头看门犬，专注于客户端和服务器之间的相互认证，防止窃听和重放攻击。

Kerberos 在 Windows 系统中广泛使用，通过与微软的 Active Directory 集成。要安装 Kerberos，我们需要启动未设置 Kerberos 的`mongod`，然后连接到`$external`数据库（而不是我们通常用于管理授权的 admin），并创建具有 Kerberos 角色和权限的用户：

```sql
use $external
db.createUser(
  {
    user: "mongo_book_user@packt.net",
    roles: [ { role: "read", db: "mongo_book" } ]
  }
)
```

在上面的示例中，我们授权`mongo_book_user@packt.net`用户读取我们的`mongo_book`数据库，就像我们在管理系统中使用用户一样。

之后，我们需要通过传递`authenticationMechanisms`参数来启动支持 Kerberos 的服务器，如下所示：

```sql
--setParameter authenticationMechanisms=GSSAPI
```

现在我们可以从我们的服务器或命令行连接，如下所示：

```sql
$ mongo.exe --host <mongoserver> --authenticationMechanism=GSSAPI --authenticationDatabase='$external' --username mongo_book_user@packt.net
```

# LDAP 身份验证

与 Kerberos 身份验证类似，我们也只能在 MongoDB 企业版中使用轻量级目录访问协议（LDAP）。用户设置必须在`$external`数据库中完成，并且必须与身份验证 LDAP 名称匹配。名称可能需要经过转换，这可能会导致 LDAP 名称与`$external`数据库中的用户条目不匹配。

设置 LDAP 身份验证超出了本书的范围，但需要考虑的重要事情是 LDAP 服务器的任何更改可能需要对 MongoDB 服务器进行更改，这不会自动发生。

# 摘要

在本章中，我们只是触及了 CRUD 操作的冰山一角。从 mongo shell 开始，我们学习了如何插入、删除、读取和修改文档。我们还讨论了一次性插入和批量插入的性能差异。

接下来，我们讨论了管理任务以及如何在 mongo shell 中执行它们。本章还讨论了 MapReduce 及其后继者聚合框架，包括它们的比较、如何使用它们以及如何将 SQL 查询转换为聚合框架管道命令。

最后，我们讨论了 MongoDB 的安全性和认证。保护我们的数据库至关重要；我们将在第八章《监控、备份和安全》中学到更多内容。

在下一章中，我们将深入探讨使用三种最流行的 Web 开发语言进行 CRUD 操作：Ruby、Python 和 PHP（超文本预处理器）。
