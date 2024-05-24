# Redis 学习手册（一）

> 原文：[`zh.annas-archive.org/md5/5363559C03089BFE85663EC2113016AB`](https://zh.annas-archive.org/md5/5363559C03089BFE85663EC2113016AB)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

《学习 Redis》旨在成为开发人员、架构师、解决方案提供商、顾问、工程师以及计划学习、设计和构建企业解决方案并寻找一种灵活快速且能够扩展其能力的内存数据存储的指南和手册。

本书首先介绍了 NoSQL 不断发展的格局，通过易于理解的示例探索命令，然后在一些示例应用中使用 Redis 作为支撑。书的后面部分着重于管理 Redis 以提高性能和可伸缩性。

本书涵盖了设计和创建快速、灵活和并发应用的核心概念，但不是 Redis 官方文档指南的替代品。 

# 本书涵盖的内容

第一章，“NoSQL 简介”，涵盖了 NoSQL 的生态系统。它讨论了 NoSQL 格局的演变，并介绍了各种类型的 NoSQL 及其特点。

第二章，“开始使用 Redis”，涉及到 Redis 的世界。它还涵盖了在各种平台上安装 Redis 以及在 Java 中运行示例程序连接到 Redis 等领域。

第三章，“Redis 中的数据结构和通信协议”，涵盖了 Redis 中可用的数据结构和通信协议。它还涵盖了用户可以执行并感受其使用的示例。通过本章结束时，您应该对 Redis 的能力有了基本的了解。

第四章，“Redis 服务器中的功能”，从学习命令到 Redis 的各种内置功能。这些功能包括 Redis 中的消息传递、事务以及管道功能，它们之间有所不同。本章还向用户介绍了一种名为 LUA 的脚本语言。

第五章，“Redis 中的数据处理”，着重于 Redis 的深度数据处理能力。这包括主从安排、数据存储方式以及其提供的各种持久化数据选项。

第六章，“Web 应用中的 Redis”，是关于在 Web 应用中定位 Redis 的内容。为了增加趣味性，书中提供了一些示例应用，您可以从中获取有关 Redis 可用的广泛用例的想法。

第七章，“业务应用中的 Redis”，是关于在业务应用中定位 Redis 的内容。为了进一步扩展其在企业解决方案设计领域中的适用性，书中解释了一些示例应用，您可以从中看到其多功能性。

第八章，“集群”，讨论了集群能力，最终用户如何利用 Redis 中的各种集群模式，并相应地在其解决方案中使用这些模式。

第九章，“维护 Redis”，是关于在生产环境中维护 Redis 的内容。

# 本书需要什么

本书需要以下软件：

+   Redis

+   JDK 1.7

+   Jedis（Redis 的 Java 客户端）

+   Eclipse，用于开发的集成开发环境

# 本书适合对象

本书适用于开发人员、架构师、解决方案提供商、顾问和工程师。主要需要 Java 知识，但也可以被任何有一点编程背景的人理解。

除此之外，还有关于如何设计解决方案并在生产中维护它们的信息，不需要编码技能。

# 约定

在本书中，您会发现一些区分不同信息类型的文本样式。以下是这些样式的一些示例及其含义的解释。

文本中的代码单词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄显示如下："以下代码是新的 Hello World 程序，现在称为 `HelloWorld2`："

代码块设置如下：

```sql
package org.learningredis.chapter.two;

public class Helloworld2  {
  JedisWrapper jedisWrapper = null;
  public Helloworld2() {
    jedisWrapper = new JedisWrapper();
  }

  private void test() {
    jedisWrapper.set("MSG", "Hello world 2 ");

    String result = jedisWrapper.get("MSG");
    System.out.println("MSG : " + result);
  }

  public static void main(String[] args) {
    Helloworld2 helloworld2 = new Helloworld2();
    helloworld2.test();
  }
}
```

**新术语** 和 **重要单词** 以粗体显示。例如，屏幕上显示的单词，例如菜单或对话框中的单词，会以这种方式出现在文本中："请注意命令提示符上显示的最后一行：**服务器现在已准备好在端口 6379 上接受连接**"。

### 注意

警告或重要说明会以这样的方式显示在一个框中。

### 提示

提示和技巧会以这样的方式显示。

# 读者反馈

我们始终欢迎读者的反馈。请告诉我们您对这本书的看法——您喜欢或不喜欢的地方。读者的反馈对我们很重要，因为它有助于我们开发您真正能充分利用的标题。

要向我们发送一般反馈，只需发送电子邮件至 `<feedback@packtpub.com>`，并在主题中提及书名。

如果您在某个专题上有专业知识，并且有兴趣撰写或为一本书做出贡献，请参阅我们的作者指南 [www.packtpub.com/authors](http://www.packtpub.com/authors)。

# 客户支持

既然您已经是 Packt 图书的自豪所有者，我们有很多事情可以帮助您充分利用您的购买。

## 下载示例代码

您可以从 [`www.packtpub.com`](http://www.packtpub.com) 的帐户中下载您购买的所有 Packt Publishing 图书的示例代码文件。如果您在其他地方购买了这本书，您可以访问 [`www.packtpub.com/support`](http://www.packtpub.com/support) 并注册，以便文件直接通过电子邮件发送给您。

## 勘误

尽管我们已经尽一切努力确保内容的准确性，但错误确实会发生。如果您在我们的书中发现错误——也许是文本或代码中的错误——我们将不胜感激，如果您能向我们报告。通过这样做，您可以帮助其他读者避免挫折，并帮助我们改进本书的后续版本。如果您发现任何勘误，请访问 [`www.packtpub.com/submit-errata`](http://www.packtpub.com/submit-errata)，选择您的书，点击 **勘误提交表格** 链接，并输入您的勘误详情。一旦您的勘误经过验证，您的提交将被接受，并且勘误将被上传到我们的网站或添加到该标题的勘误列表下的勘误部分。

要查看先前提交的勘误，请转到 [`www.packtpub.com/books/content/support`](https://www.packtpub.com/books/content/support) 并在搜索框中输入书名。所需信息将显示在 **勘误** 部分下。

## 盗版

互联网上的盗版行为是跨所有媒体的持续问题。在 Packt，我们非常重视保护我们的版权和许可。如果您在互联网上发现我们作品的任何非法副本，请立即向我们提供位置地址或网站名称，以便我们采取补救措施。

请通过链接 `<copyright@packtpub.com>` 与我们联系，提供涉嫌盗版材料的链接。

我们感谢您帮助保护我们的作者和我们提供有价值内容的能力。

## 问题

如果您对本书的任何方面有问题，可以通过 `<questions@packtpub.com>` 与我们联系，我们将尽力解决问题。


# 第一章：NoSQL 简介

在本章中，您将了解新兴的 NoSQL 领域，并介绍 NoSQL 领域的各种分类。我们还将了解**Redis**在 NoSQL 领域的位置。我们将涵盖以下主题：

+   企业中的数据

+   NoSQL

+   NoSQL 的用例

# 互联网化的世界

我们生活在一个有趣的时代；在过去的十年里，发生了许多改变，改变了我们体验互联网世界及其周围生态系统的方式。在本章中，我们将重点讨论一些促成进步的原因，并讨论数据存储领域的发展。

下图是对网络空间中发生的演变过程的粗略草图，其数据来自互联网，并大致展示了互联网服务的增长情况：

![互联网化的世界](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/lrn-redis/img/1794_01_01.jpg)

演变：社交媒体、处理器和核心、数据库（NoSQL）

前面的图表表明，硬件行业在第一个十年的中期发生了一场范式转变。新处理器不再以增加时钟速度为目标，而是新一代处理器采用了多核技术，随后发布的处理器数量也在增加。过去，大型机器配备大量内存和强大的处理器可以解决任何问题，或者换句话说，企业依赖垂直扩展来解决性能问题的日子一去不复返。这在某种程度上预示着并行计算是未来，并且将部署在基于商品的机器上。

随着硬件行业预示着并行计算的到来，新一代解决方案必须是分布式和并行的。这意味着它们需要以并行方式执行逻辑，并将数据存储在分布式数据存储中；换句话说，水平扩展是未来的发展方向。此外，随着 Web 2.0 的出现，社交媒体、在线游戏、在线购物、协作计算、云计算等也开始出现。互联网正在成为一个无处不在的平台。

互联网的普及和使用互联网的人数每天都在增加，使用互联网的时间也在增加。需要注意的另一个重要方面是，来自不同地理位置的用户在这个互联网化的世界中聚集在一起。这有很多原因；首先，网站变得更加智能，以一种更有效地吸引终端用户的方式进行交互。另一个使互联网采用速度更快、更容易的因素是创新的手持设备，如智能手机、平板电脑等。如今，这些手持设备具有的计算能力可以与计算机相媲美。在这个动态变化的世界中，基于互联网的软件解决方案和服务正在拓展社交媒体的视野，将人们聚集在一个共同的平台上。这创造了一个新的商业领域，如社交企业媒体，其中社交媒体与企业融合。这肯定会对传统企业解决方案产生影响。

互联网的影响使得企业解决方案经历了一次变革性的转变。企业架构的转变从通常期望的企业解决方案的微妙需求，转向了采纳社交媒体解决方案的新需求。如今，企业解决方案正在与社交媒体网站整合，以了解他们的客户在谈论什么；他们自己也开始创建平台和论坛，让客户可以来贡献他们对产品和服务的印象。所有这些数据交换都是实时进行的，需要一个高并发和可扩展的生态系统。总之，企业解决方案希望采纳社交媒体解决方案的特性，这直接和成比例地影响了他们架构的非功能性需求。故障管理、实时大数据处理、最终一致性、大量读写、响应性、水平扩展性、可管理性、可维护性、灵活性等特性，以及它们对企业架构的影响，都受到了新的关注。社交媒体架构中使用的技术、范例、框架和模式正在被研究和重新应用到企业架构中。

在任何解决方案（社交媒体或企业）中，关键层之一是数据层。数据的排列和管理方式，以及数据存储的选择构成了数据层。从设计师的角度来看，任何数据存储中的数据处理都受到一致性、可用性和分区容忍性等视角的影响，也就是著名的 Eric Brewer 的 CAP 定理。虽然同时拥有这三个视角是可取的，但实际上，任何数据层都可能同时具有两种以上的视角。这意味着解决方案中的数据可能具有多种视角的组合，比如可用性-分区容忍性（这种组合必须放弃数据处理中的一致性），可用性-一致性（这种组合必须放弃分区容忍性，这将影响数据层处理的数据量），以及一致性-分区容忍性（这种组合必须放弃可用性）。

CAP 定理直接影响系统的行为、读写速度、并发性、可维护性、集群模式、容错性、数据负载等。

设计数据模型时最常见的方法是以关系型和规范化的方式排列数据。当数据处于事务模式、需要一致性并且是结构化的时候，这种方法效果很好，也就是说，它有一个固定的模式。但当数据是半结构化的、具有树状结构或者是无模式的时候，这种规范化数据的方法就显得过度设计了，这种情况下一致性可以放松。将半结构化数据适应到结构化数据模型中的结果就是表的爆炸和一个复杂的数据模型来存储简单的数据。

由于缺乏替代方案，解决方案过度依赖关系型数据库管理系统（RDBMS）来解决数据处理方面的问题。这种方法的问题在于 RDBMS 最初是为了解决数据处理的一致性和可用性问题而设计的，但后来也开始存储具有分区容忍性问题的数据。最终的结果是一个臃肿的 RDBMS 和一个非常复杂的数据模型。这开始对解决方案的非功能性需求产生负面影响，包括故障管理、性能、可扩展性、可管理性、可维护性和灵活性等方面。

另一个关注领域是**数据解释**，在设计数据层时非常重要。在一个解决方案中，同一数据被不同的相关团队以不同的方式查看和解释。为了更好地理解，假设我们有一个销售产品的电子商务网站。在设计这个数据层时，有三个基本的功能领域涉及其中，它们是库存管理、账户管理和客户管理。从核心业务的角度来看，所有领域在其数据管理中都需要**原子性、一致性、隔离性、持久性**（**ACID**）属性，从 CAP 定理的角度来看，它们需要一致性和可用性。然而，如果网站需要实时了解其客户，分析团队需要分析来自库存管理、账户管理和客户管理领域的数据。除了实时收集的其他数据。分析团队查看相同数据的方式与其他团队的方式完全不同；对于他们来说，一致性不是一个问题，因为他们更感兴趣的是整体统计数据，一些不一致的数据对整体报告没有影响。如果来自这些领域的所有分析所需数据都保存在与核心业务相同的数据模型中，分析将会遇到困难，因为现在它必须使用这些高度规范化和优化的结构化数据进行业务操作。分析团队还希望将其数据去规范化以加快分析速度。

现在，在 RDBMS 系统上对这些规范化数据进行实时分析将需要大量的计算资源，这将影响核心业务在营业时间的性能。因此，如果为这些领域创建单独的数据模型，一个用于业务，一个用于分析，每个都分开维护，对整体业务更有利。我们将在后续主题中看到为什么 RDBMS 不适合分析和其他用例，以及 NoSQL 如何解决数据爆炸问题。

# NoSQL 入门

**非仅 SQL**或**NoSQL**，正如它被普遍称呼的那样，是由 Carlo Strozzi 在 1998 年创造的，并在 2009 年由 Eric Evans 重新引入。这是数据处理中一个令人兴奋的领域，以某种方式填补了数据处理层中存在的许多空白。在 NoSQL 作为存储数据的备选选择出现之前，面向 SQL 的数据库（RDBMS）是开发人员定位或改装其数据的唯一选择。换句话说，RDBMS 是一把钉所有数据问题的锤子。当 NoSQL 及其不同类别开始出现时，那些不适合 RDBMS 的数据模型和数据大小开始发现 NoSQL 是一个完美的数据存储。还有一个关注点是从一致性的角度转变；从 ACID 转变为 BASE 属性。

ACID 属性代表 CAP 定理的一致性和可用性。这些属性由 RDBMS 展示，并代表以下内容：

+   **原子性**：在事务中，所有操作将完成或全部不会完成（回滚）

+   **一致性**：数据库在事务开始和结束时将处于一致状态，并且不能在中间状态离开

+   **隔离**：并发事务之间不会有干扰

+   **持久性**：一旦事务提交，即使服务器重新启动或失败，它也将保持不变

NoSQL 表现出**BASE**属性；它们代表了 CAP 定理的可用性和分区容忍性。它们基本上放弃了 RDBMS 所显示的强一致性。BASE 代表以下特性：

+   **基本可用**：这保证了对请求的响应，即使数据处于陈旧状态。

+   **软状态**：数据的状态始终处于接受更改的状态，即使没有请求更改其状态。这意味着假设有两个节点持有相同的数据状态（数据的复制），如果有一个请求在一个节点中更改状态，另一个节点中的状态在请求的生命周期内不会更改。另一个节点中的数据将由数据存储触发的异步过程更改其状态，从而使状态变得软化。

+   **最终一致性**：由于节点的分布性，系统最终将变得一致。

### 注意

数据的写入和读取应该更快更容易。

在软件开发领域发生了另一个有趣的发展。垂直可扩展性已经达到了极限，必须设计出具有水平可扩展性的解决方案，因此数据层也必须是分布式和分区容错的。除了社交媒体解决方案外，在线游戏和基于游戏理论的网站（进行目标营销，即根据用户的购买历史奖励用户。这类网站需要实时分析）开始受到关注。社交媒体希望在最短时间内同步来自各地的大量数据，游戏世界对高性能感兴趣。电子商务网站对实时了解他们的客户和产品以及对客户进行概括以在客户意识到需求之前了解他们的需求感兴趣。根据不同数据模型出现的 NoSQL 中的类别如下：

+   面向图形的 NoSQL

+   面向文档的 NoSQL

+   面向键值的 NoSQL

+   面向列的 NoSQL

## 面向图形的 NoSQL

图形数据库是一种特殊类型的 NoSQL 数据库。图形数据库存储的数据模型是图形结构，与其他数据存储有些不同。图形结构由节点、边和属性组成。理解图形数据库的方法是将它们视为具有双向关系的思维导图。这意味着如果 A 与 B 相关，B 与 C 相关，那么 C 与 A 相关。图形数据库倾向于解决在运行时形成的非结构化实体之间形成的关系所引发的问题，这些关系可以是双向的。相比之下，关系型数据库也有一种称为**表连接**的关系概念，但这些关系是在结构化数据上的，不能是双向的。

此外，这些表连接会在数据集随着时间的推移而增长时，对具有外键的数据模型增加复杂性，并对基于表连接的查询产生性能惩罚。一些最有前途的图形数据存储包括 Neo4i、FlockDB、OrientDB 等。

为了更好地理解这一点，让我们来看一个示例用例，并看看如何使用面向图形的 NoSQL 解决复杂的基于图形的业务用例变得多么容易。以下图是一个示例用例，一个电子商务网站可能有兴趣解决。用例是捕获访问者的购买历史和网站微博组件中的人际关系。

![面向图形的 NoSQL](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/lrn-redis/img/1794_01_02.jpg)

图形数据库的示例模块

业务实体，如出版商、作者、客户、产品等，在图中表示为节点。例如，由作者、出版商发布的关系等在图中由边表示。有趣的是，来自博客网站的*用户-1*等非业务节点可以与其关系*关注*一起在图中表示。通过结合业务和非业务实体，网站可以为产品找到目标客户。在图中，节点和边都有在运行分析时使用的属性。

基于关系存储在系统中的图形数据库可以轻松回答以下一组问题：

+   谁是*Learning Redis*的作者？

答案：Vinoo Das

+   Packt Publishing 和*Learning Redis*有什么关系？

答案：发布者

+   谁有自己的 NoSQL 书由 Packt Publishing 出版？

答案：user-2

+   谁正在关注购买了*Learning Redis*并对 NoSQL 感兴趣的客户？

答案：user-1

+   列出所有价格低于 X 美元且可以被 user-2 的关注者购买的 NoSQL 书籍。

答案：*Learning Redis*

## 面向文档的 NoSQL

面向文档的数据存储设计用于存储具有存储文档哲学的数据。简单地说，这里的数据以书的形式排列。一本书可以分为任意数量的章节，每个章节可以分为任意数量的主题，每个主题进一步分为子主题等等。

![面向文档的 NoSQL](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/lrn-redis/img/1794_01_03.jpg)

一本书的组成

如果数据具有类似的结构，即层次化且没有固定深度或模式，则面向文档的数据存储是存储此类数据的完美选择。MongoDB 和 CouchDB（Couchbase）是目前备受关注的两种知名的面向文档的数据存储。就像一本书有索引以进行更快的搜索一样，这些数据存储也有存储在内存中的键的索引以进行更快的搜索。

面向文档的数据存储以 XML、JSON 和其他格式存储数据。它们可以保存标量值、映射、列表和元组作为值。与关系型数据库管理系统（RDBMS）不同，后者将数据视为以表格形式存储的数据行，这里存储的数据是以分层树状结构存储的，其中存储在这些数据存储中的每个值始终与一个键相关联。另一个独特的特点是面向文档的数据存储是无模式的。以下截图显示了一个示例，展示了数据存储在面向文档的数据存储中的方式。数据存储的格式是 JSON。面向文档的数据存储的一个美妙之处在于信息可以以您所想到的数据方式存储。从某种意义上说，这是与关系型数据库管理系统的范式转变，后者将数据分解为各种较小的部分，然后以规范化的方式存储在行和列中。

![面向文档的 NoSQL](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/lrn-redis/img/1794_01_04.jpg)

JASON 格式示例数据的组成

目前使用最广泛的两种面向文档的存储是 MongoDB 和 CouchDB，将它们相互对比将有助于更好地了解它们。

### MongoDB 和 CouchDB 的显著特点

MongoDB 和 CouchDB 都是面向文档的事实已经确立，但它们在各个方面有所不同，这将对想要了解面向文档的数据存储并在其项目中采用它们的人们感兴趣。以下是 MongoDB 和 CouchDB 的一些特点：

+   **插入小型和大型数据集**：MongoDB 和 CouchDB 都非常适合插入小型数据集。在插入大型数据集时，MongoDB 比 CouchDB 稍微更好。总体而言，这两种文档数据存储的速度一致性都非常好。

+   **随机读取**：在读取速度方面，MongoDB 和 CouchDB 都很快。当涉及到读取大数据集时，MongoDB 稍微更好一些。

+   容错性：MongoDB 和 CouchDB 都具有可比较且良好的容错能力。CouchDB 使用 Erlang/OTP 作为其实现的基础技术平台。Erlang 是一种语言和平台，旨在实现容错、可扩展和高并发的系统。Erlang 作为 CouchDB 的支撑使其具有非常好的容错能力。MongoDB 使用 C++作为其底层实现的主要语言。在容错领域的行业采用和其经过验证的记录使 MongoDB 在这一领域具有很好的优势。

+   **分片**：MongoDB 具有内置的分片功能，而 CouchDB 没有。然而，建立在 CouchDB 之上的另一个文档数据存储 Couchbase 具有自动分片功能。

+   **负载平衡**：MongoDB 和 CouchDB 都具有良好的负载平衡能力。然而，由于 CouchDB 中的底层技术，即 Actor 范式，具有良好的负载平衡规定，可以说 CouchDB 的能力胜过 MongoDB 的能力。

+   **多数据中心支持**：CouchDB 具有多数据中心支持，而在撰写本书时，MongoDB 并没有这种支持。然而，我猜想随着 MongoDB 的普及，我们可以期待它在未来具有这种支持。

+   **可扩展性**：CouchDB 和 MongoDB 都具有高度可扩展性。

+   **可管理性**：CouchDB 和 MongoDB 都具有良好的可管理性。

+   **客户端**：CouchDB 使用 JSON 进行数据交换，而 MongoDB 使用 BSON，这是 MongoDB 专有的。

## 列式 NoSQL

列式 NoSQL 的设计理念是将数据存储在列而不是行中。这种存储数据的方式与 RDBMS 中存储数据的方式完全相反，RDBMS 中数据是按行存储的。列式数据库从一开始就被设计为高度可扩展的，因此具有分布式特性。它们放弃了一致性以获得这种大规模的可扩展性。

以下截图描述了基于我们的感知的智能平板电脑的小型库存；在这里，想要展示 RDBMS 中存储的数据与列式数据库中存储的数据的对比：

![列式 NoSQL](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/lrn-redis/img/1794_01_05.jpg)

以列和行的形式呈现数据

上述表格数据以如下格式存储在硬盘的 RDBMS 中：

![列式 NoSQL](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/lrn-redis/img/1794_01_06.jpg)

数据序列化为列

上述截图信息的来源是[`en.wikipedia.org/wiki/Column-oriented_DBMS`](http://en.wikipedia.org/wiki/Column-oriented_DBMS)。

列式数据存储中的相同数据将存储如下图所示；在这里，数据是按列序列化的：

![列式 NoSQL](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/lrn-redis/img/1794_01_07.jpg)

数据序列化为行

在垂直可扩展性达到极限、水平可扩展性是组织希望采用的存储数据方式的世界中，列式数据存储提供了可以以非常具有成本效益的方式存储百万兆字节数据的解决方案。谷歌、雅虎、Facebook 等公司率先采用了列式存储数据的方式，而这些公司存储的数据量是众所周知的事实。HBase 和 Cassandra 是一些以列为基础的知名产品，可以存储大量数据。这两种数据存储都是以最终一致性为目标构建的。在 HBase 和 Cassandra 的情况下，底层语言是 Java；将它们相互对比将会很有趣，以便更好地了解它们。

### HBase 和 Cassandra 的显著特点

HBase 是一种属于列定向数据存储类别的数据存储。这种数据存储在 Hadoop 变得流行之后出现，受到了 2003 年发布的*Google 文件系统*论文的启发。HBase 基于 Hadoop，使其成为数据仓库和大规模数据处理和分析的绝佳选择。HBase 在现有的 Hadoop 生态系统上提供了类似于我们在关系型数据库管理系统中查看数据的 SQL 类型接口，即面向行，但数据在内部以列为导向的方式存储。HBase 根据行键存储行数据，并按行键的排序顺序进行排序。它具有诸如 Region Server 之类的组件，可以连接到 Hadoop 提供的 DataNode。这意味着 Region Server 与 DataNode 共存，并充当与 HBase 客户端交互的网关。在幕后，HBase master 处理 DDL 操作。除此之外，它还管理 Region 分配和与之相关的其他簿记活动。Zookeeper 节点负责集群信息和管理，包括状态管理。HBase 客户端直接与 Region Server 交互以放置和获取数据。诸如 Zookeeper（用于协调主节点和从节点之间的协调）、Name Node 和 HBase 主节点等组件不直接参与 HBase 客户端和 Region Server 节点之间的数据交换。

![HBase 和 Cassandra 的显著特点](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/lrn-redis/img/1794_01_08.jpg)

HBASE 节点设置

Cassandra 是一种属于列定向数据存储类别的数据存储，同时也显示了一些键-值数据存储的特性。Cassandra 最初由 Facebook 启动，但后来分叉到 Apache 开源社区，最适合实时事务处理和实时分析。

Cassandra 和 HBase 之间的一个关键区别在于，与 HBase 依赖于 Hadoop 的现有架构不同，Cassandra 是独立的。Cassandra 受亚马逊的 Dynamo 的启发来存储数据。简而言之，HBase 的架构方法使得 Region Server 和 DataNodes 依赖于其他组件，如 HBase master、Name Node、Zookeeper，而 Cassandra 中的节点在内部管理这些责任，因此不依赖于外部组件。

Cassandra 集群可以被视为一个节点环，其中有一些种子节点。这些种子节点与任何节点相似，但负责最新的集群状态数据。如果种子节点出现故障，可以在可用节点中选举出一个新的种子。数据根据行键的哈希值均匀分布在环上。在 Cassandra 中，数据可以根据其行键进行查询。Cassandra 的客户端有多种类型；也就是说，Thrift 是最原生的客户端之一，可以用来与 Cassandra 环进行交互。除此之外，还有一些客户端暴露了与 SQL 非常相似的 Cassandra 查询语言（CQL）接口。

![HBase 和 Cassandra 的显著特点](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/lrn-redis/img/1794_01_09.jpg)

Cassandra 节点设置

+   **插入小型和大型数据集**：HBase 和 Cassandra 都非常擅长插入小型数据集。事实上，这两种数据存储都使用多个节点来分发写入。它们都首先将数据写入基于内存的存储，如 RAM，这使得其插入性能很好。

+   **随机读取**：在读取速度方面，HBase 和 Cassandra 都很快。在设计架构时，HBase 考虑到了一致性是其中的一个关键特性。在 Cassandra 中，数据一致性是可调的，但为了获得更高的一致性，必须牺牲速度。

+   **最终一致性**：HBase 具有强一致性，Cassandra 具有最终一致性，但有趣的是，Cassandra 中的一致性模型是可调节的。它可以调整为具有更好的一致性，但必须在读写速度上牺牲性能。

+   **负载均衡**：HBase 和 Cassandra 内置了负载均衡。其想法是让许多节点在商品级节点上提供读写服务。一致性哈希用于在节点之间分配负载。

+   **分片**：HBase 和 Cassandra 都具有分片能力。这是必不可少的，因为两者都声称可以从商品级节点获得良好的性能，而商品级节点的磁盘和内存空间有限。

+   **多数据中心支持**：在这两者中，Cassandra 具有多数据中心支持。

+   **可扩展性**：HBase 和 Cassandra 都具有非常好的可扩展性，这是设计要求之一。

+   **可管理性**：在这两者中，Cassandra 的可管理性更好。这是因为在 Cassandra 中，需要管理节点，但在 HBase 中，有许多需要协同工作的组件，如 Zookeeper、DataNode、Name Node、Region Server 等。

+   **客户端**：HBase 和 Cassandra 都有 Java、Python、Ruby、Node.js 等客户端，使其在异构环境中易于使用。

## 键值导向的 NoSQL

键值数据存储可能是最快和最简单的 NoSQL 数据库之一。在其最简单的形式中，它们可以被理解为一个大的哈希表。从使用的角度来看，数据库中存储的每个值都有一个键。键可以用来搜索值，通过删除键可以删除值。在键值数据库中一些受欢迎的选择包括 Redis、Riak、亚马逊的 DynamoDB、voldermort 项目等。

### Redis 在作为键值数据存储的一些非功能性需求方面表现如何？

Redis 是最快的键值存储之一，在整个行业中得到了非常快的采用，涵盖了许多领域。由于本书侧重于 Redis，让我们简要了解一下 Redis 在一些非功能性需求方面的表现。随着本书的进展，我们将会更详细地讨论它们：

+   **数据集的插入**：在键值数据存储中，数据集的插入非常快，Redis 也不例外。

+   **随机读取**：在键值数据存储中，随机读取非常快。在 Redis 中，所有键都存储在内存中。这确保了更快的查找速度，因此读取速度更快。虽然如果所有键和值都保留在内存中将会很好，但这也有一个缺点。这种方法的问题在于内存需求会非常高。Redis 通过引入一种称为*虚拟内存*的东西来解决这个问题。虚拟内存将所有键保留在内存中，但将最近未使用的值写入磁盘。

+   **容错性**：Redis 中的故障处理取决于集群的拓扑结构。Redis 在其集群部署中使用主从拓扑结构。主节点中的所有数据都会异步复制到从节点；因此，如果主节点进入故障状态，其中一个从节点可以通过 Redis sentinel 晋升为主节点。

+   **最终一致性**：键值数据存储具有主从拓扑结构，这意味着一旦主节点更新，所有从节点都会异步更新。这在 Redis 中可以想象，因为客户端使用从节点进行只读模式；可能主节点已经写入了最新值，但在从节点读取时，客户端可能会得到旧值，因为主节点尚未更新从节点。因此，这种滞后可能会导致短暂的不一致性。

+   **负载均衡**：Redis 有一种简单的实现负载均衡的方法。如前所述，主节点用于写入数据，从节点用于读取数据。因此，客户端应该在其内部构建逻辑，将读取请求均匀分布在从节点上，或者使用第三方代理，如 Twemproxy 来实现。

+   **分片**：可能会有比可用内存更大的数据集，这使得在各个对等节点之间预先分片数据成为一种水平可扩展的选择。

+   **多数据中心支持**：Redis 和键值 NoSQL 不提供内在的多数据中心支持，其中复制是一致的。但是，我们可以在一个数据中心拥有主节点，在另一个数据中心拥有从节点，但我们必须接受最终一致性。

+   **可扩展性**：在扩展和数据分区方面，Redis 服务器缺乏相应的逻辑。主要的数据分区逻辑应该由客户端或者使用第三方代理（如 Twemproxy）来实现。

+   **可管理性**：Redis 作为一个键值 NoSQL 数据库，管理起来很简单。

+   **客户端**：Redis 有 Java、Python 和 Node.js 的客户端，实现了**REdis Serialization Protocol**（RESP）。

### NoSQL 的用例

首先了解你的业务；这将帮助你了解你的数据。这也将让你深入了解你需要拥有的数据层的类型。关键是要有一个自上而下的设计方法。首先决定持久性机制，然后将业务用例的数据适配到该持久性机制中是一个不好的想法（自下而上的设计方法）。因此，首先定义你的业务需求，然后决定未来的路线图，然后再决定数据层。在理解业务需求规范时，另一个重要因素是考虑每个业务用例的非功能性需求，我认为这是至关重要的。

如果在业务或功能需求中没有添加非功能性需求，那么当系统进行性能测试或更糟的是上线时会出现问题。如果你觉得从功能需求的角度来看数据模型需要 NoSQL，那么可以问一些问题，如下所示：

+   你的数据模型需要什么类型的 NoSQL？

+   数据可以增长到多大，需要多大的可扩展性？

+   你将如何处理节点故障？它对你的业务用例有什么影响？

+   在数据增长时，数据复制和基础设施投资哪个更好？

+   处理读/写负载的策略是什么，计划的并发量有多大？

+   业务用例需要什么级别的数据一致性？

+   数据将存放在哪里（单个数据中心还是跨地理位置的多个数据中心）？

+   集群策略和数据同步策略是什么？

+   数据备份策略是什么？

+   你计划使用什么样的网络拓扑？网络延迟对性能有什么影响？

+   团队在处理、监控、管理和开发多语言持久性环境方面有多舒适？

以下是一些 NoSQL 数据库及其根据 CAP 定理的放置方式的摘要。以下图表并不是详尽无遗的，但是是最受欢迎的数据库的一个快照：

![NoSQL 的用例](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/lrn-redis/img/1794_01_10.jpg)

根据 CAP 定理放置的 NoSQL 数据库

让我们分析一下公司如何使用 NoSQL，这将给我们一些关于如何有效地在我们的解决方案中使用 NoSQL 的想法：

+   **大数据**：这个术语让人联想到数百甚至数千台服务器处理数据以进行分析。大数据的用例是不言而喻的，很容易证明使用 NoSQL 数据存储的必要性。作为 NoSQL 的一种模式，列式数据库是这种活动的明显选择。由于分布式的特性，这些解决方案也没有单点故障，可以进行并行计算、写入可用性和可扩展性。以下是一些不同类型的用例列表，其中公司已经成功地在他们的业务中使用了列式数据存储：

+   Spotify 使用 Hadoop 进行数据聚合、报告和分析

+   Twitter 使用 Hadoop 处理推文和日志文件

+   Netflix 使用 Cassandra 作为其后端数据存储以提供流媒体服务

+   Zoho 使用 Cassandra 为邮件服务生成收件箱预览

+   Facebook 使用 Cassandra 进行 Instagram 操作

+   Facebook 在其消息基础设施中使用 HBase

+   Su.pr 使用 HBase 进行实时数据存储和分析平台

+   HP IceWall SSO 使用 HBase 存储用户数据，以便为其基于 Web 的单点登录解决方案对用户进行身份验证

+   **大量读/写**：这个非功能性需求立即让我们联想到社交或游戏网站。对于这是一个要求的企业，他们可以从 NoSQL 的选择中获得灵感。

+   LinkedIn 使用 Voldermort（键值数据存储）为数百万读写每天提供服务，在几毫秒内完成

+   Wooga（社交网络游戏和移动开发者）使用 Redis 进行游戏平台；一些游戏每天有超过一百万用户

+   Twitter 每天处理 2 亿条推文，并使用 NoSQL，如 Cassandra、HBase、Memcached 和 FlockDB，还使用关系型数据库，如 MySQL

+   Stack overflow 使用 Redis 为每月 3000 万注册用户提供服务

+   **文档存储**：Web 2.0 采用的增长和互联网内容的增加正在创造无模式的数据。专门设计用于存储这种数据的 NoSQL（文档导向）使开发人员的工作更简单，解决方案的稳定性更强。以下是一些使用不同文档存储的公司的示例：

+   SourceForge 使用 MongoDB 存储首页、项目页面和下载页面；SourceForge 上的 Allura 基于 MongoDB

+   MetLife 使用 MongoDB 作为*the wall*的数据存储，这是一个客户服务平台

+   Semantic News Portal 使用 CouchDB 存储新闻数据

+   佛蒙特公共广播网站的主页使用 CouchDB 存储新闻标题、评论等

+   AOL 广告使用 Couchbase（CouchDB 的新化身）为 10 亿多用户提供每月数十亿次印象

+   **实时体验和电子商务平台**：购物车、用户资料管理、投票、用户会话管理、实时页面计数器、实时分析等是公司提供的服务，以给用户提供实时体验。以下是一些使用实时体验和电子商务平台的公司的示例：

+   Flickr push 使用 Redis 推送实时更新

+   Instagram 使用 Redis 存储数以百万计的媒体内容，并实时提供服务

+   Digg 使用 Redis 进行页面浏览和用户点击的解决方案

+   百思买使用 Riak 进行电子商务平台

# 总结

在本章中，您看到互联网世界正在经历一场范式转变，NoSQL 世界的演变，以及社交媒体如何领导 NoSQL 的采用。您还看到了 NoSQL 世界中的各种替代方案以及它们的等价性。最后，您看到了 Redis 如何在 NoSQL 生态系统中映射。

在下一章中，我们将深入探讨 Redis 的世界。


# 第二章：开始使用 Redis

Redis 是由 Salvatore Sanfilippo 开发的基于键值的 NoSQL 数据存储，于 2009 年推出。Redis 的名称来自于**REmote DIctionary Server**。Redis 是用 C 语言编写的高性能单线程服务器。

Redis 可以安装在所有符合 POSIX 标准的 Unix 系统上。尽管没有 Windows 系统的生产级发布，但仍然可以在 Windows 环境中进行开发目的的安装。在本章中，我们将在 Windows 和 Mac OS 环境中安装 Redis，用 Java 编写程序，并使用分发包中附带的内置客户端进行操作。

# 在 Windows 上安装 Redis

微软开放技术组已经将 Redis 移植并在 win32/win64 机器上进行维护。有两种方法可以在 Windows 上安装 Redis，如下所示：

+   使用预构建的二进制文件

+   在 Microsoft 环境中获取代码并编译它

对于急切的人来说，下载 Redis 2.8 的二进制文件是一个更简单的选择。首先，我们需要按照以下步骤开始：

1.  转到[`github.com/MSOpenTech/redis`](https://github.com/MSOpenTech/redis)并下载**Clone in Desktop**按钮下的 ZIP 文件。在本书中，我们将下载最新版本的 Redis，即`redis-2.8.zip`文件。

1.  右键单击链接并将其保存在 Windows 机器上的适当位置。我已经将其保存在`F:\sw2\redis\redis-2.8.zip`。

1.  右键单击并解压缩压缩文件到适当的文件夹。我将文件夹命名为`redis-2.8`，解压缩后的文件夹结构看起来与以下屏幕截图相似：![在 Windows 上安装 Redis](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/lrn-redis/img/1794_02_01.jpg)

解压缩压缩文件后的文件夹结构

1.  进入`bin`文件夹。您将找到`release`文件夹；单击它，您将看到该文件夹内的文件列表，如下面的屏幕截图所示：![在 Windows 上安装 Redis](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/lrn-redis/img/1794_02_02.jpg)

bin/release 文件夹内的文件夹结构

1.  打开命令提示符并运行`redis-server.exe`。提供`redis-server.exe --maxheap 1024mb`堆大小，您应该会看到一个控制台窗口弹出，类似于以下屏幕截图。在 Windows 7 的情况下，用户可能会被要求信任软件以进一步进行。![在 Windows 上安装 Redis](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/lrn-redis/img/1794_02_03.jpg)

Redis 服务器的默认启动

1.  注意命令提示符上显示的最后一行：**服务器现在准备好在端口 6379 上接受连接**。

1.  现在，让我们启动一个预构建的客户端，该客户端随分发包一起提供，并连接到服务器。我们将执行的客户端是一个命令行解释器，当我们点击它时，客户端程序将被启动：![在 Windows 上安装 Redis](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/lrn-redis/img/1794_02_04.jpg)

Redis 客户端在 Redis 服务器运行时启动

1.  您的简单安装已完成（集群设置和其他管理主题将在后续章节中进行）。

### 提示

**下载示例代码**

您可以从[`www.packtpub.com`](http://www.packtpub.com)的帐户中下载示例代码文件，以获取您购买的所有 Packt Publishing 图书。如果您在其他地方购买了本书，可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)并注册，以便直接通过电子邮件接收文件。

# 在 Mac OS 上安装 Redis

在 Mac OS 上安装 Redis 真的很简单。按照这些步骤，您就可以开始了：

1.  从互联网下载包。为此，您可以使用以下命令：`wget http://download.redis.io/releases/redis-2.8.3.tar.gz`

1.  解压缩`tar xzf redis-2.8.3.tar.gz`文件。

1.  这将创建一个文件夹；通过发出`cd redis-2.8.3`命令进入文件夹。

1.  通过发出`make`命令来编译文件。这将编译二进制文件并创建文件夹结构，如下面的屏幕截图所示：![在 Mac OS 上安装 Redis](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/lrn-redis/img/1794_02_05.jpg)

Mac 分发的文件夹结构

1.  输入`src/redis-server`命令；这将启动服务器，如下截图所示：![在 Mac OS 上安装 Redis](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/lrn-redis/img/1794_02_06.jpg)

在苹果环境中启动 Redis 服务器

1.  您的 Redis 服务器正在运行，并且准备接受端口 6379 上的请求。打开另一个终端并转到安装 Redis 的同一文件夹。输入命令`src/redis-client`；这将启动客户端 shell，如下截图所示：![在 Mac OS 上安装 Redis](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/lrn-redis/img/1794_02_07.jpg)

在苹果环境中启动 Redis 客户端

1.  您的客户端已准备就绪，您已准备好进行 Hello World 程序，但在继续之前，最好先了解一下名为`redis.conf`的配置文件。

## redis.conf 简介

Redis 附带`redis.windows.conf`文件，位于解压分发的 ZIP/tar 文件时创建的父文件夹中。可以通过此配置文件对服务器在启动时需要的任何自定义进行设置。如果需要包含`redis.conf`文件，则在服务器启动时提供文件路径作为参数。

当您在启动时提供配置文件时，命令提示符将显示以下消息：

![redis.conf 简介](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/lrn-redis/img/1794_02_08.jpg)

Redis 服务器在启动时使用配置路径进行启动

如前所述，Redis 是基于 Unix 的软件，已移植到 Windows 环境。许多配置参数是为 Unix 环境而设的；然而，了解在转移到基于 Unix 的环境时对您有益的参数总是好的。这些参数如下所述：

+   **Port 6379**：这个数字表示服务器将监听在端口 6379 上的消息。此端口号可以根据您的项目设置进行更改，并且服务器将在该端口上监听消息。这将需要重新启动服务器。

+   **# bind 127.0.0.1**：这是您希望服务器绑定的 IP 地址。默认情况下，此参数已被注释，这意味着服务器将监听所有接口的消息。

+   **Timeout 0**：这意味着如果客户端处于空闲状态，服务器将不会关闭连接。

+   **tcp-keepalive 0**：这是向服务器发送的命令，以保持与客户端的连接开放。您可以将其设置为`SO_KEEPALIVE`，这将指示服务器向客户端发送`ACK`消息。

+   **loglevel notice**：这是您希望服务器具有的日志级别。您可以拥有的日志级别包括 debug、verbose、notice 和 warning。

+   **logfile stdout**：这是您希望将日志消息发送到的通道，在 Windows 中为命令行，Unix-based 系统中为终端。

+   **syslog-enabled no**：如果更改为*yes*，则会将消息发送到系统日志。

+   **dir**：这应设置为用户希望运行 Redis 服务器的工作目录。这将告诉 Redis 服务器适当地创建文件，如服务器文件。

其余的配置参数可以视为高级参数，在后续章节中需要时我们将使用大部分。

# Redis 中的 Hello World

这一部分将最激发程序员的兴趣。让我们动手写一些代码。但在此之前，我们必须了解 Redis 是基于客户端-服务器模型工作的，并使用 Redis 协议与服务器通信。为了客户端连接到服务器，客户端必须知道服务器的位置。在本节中，我将展示使用 redis-cli 和 Java 客户端的示例。

## 使用 redis-cli 进行 Hello World

启动 Redis 客户端命令提示符（确保服务器正在运行）。输入以下命令，如下截图所示，并查看结果：

![使用 redis-cli 进行 Hello World](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/lrn-redis/img/1794_02_09.jpg)

尝试使用 Redis 客户端进行简单的 Set 和 Get 命令

我们写的命令有三个部分。它们的解释如下：

+   `Set`：此命令用于在 Redis 服务器中设置值

+   `MSG`：这是要存储在 Redis 服务器中的消息的键

+   `Hello World`：这是存储在服务器上`MSG`键的值

因此，这清除了我们在使用 Redis 时必须记住的一个模式。请记住，Redis 是一个键值 NoSQL 数据存储。其语法为`COMMAND <space> KEY <space> VALUE`。

继续进行`Hello world`程序，我们将做更多的事情。让我们输入`set MSG Learning Redis`，我们会收到一个错误消息，当我们输入`set MSG "Hello World"`时，服务器将返回的值是`OK`：

![使用 redis-cli 的 Hello World](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/lrn-redis/img/1794_02_10.jpg)

用新值覆盖键

给定键的旧值被新值覆盖。让我们为这个示例添加另一个维度，即打开另一个客户端以打开我们已经打开的客户端命令提示符。在第二个命令提示符中，让我们将命令和键输入为`get MSG`。它将返回的值再次是`"Hello World"`。如下截图所示：

![使用 redis-cli 的 Hello World](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/lrn-redis/img/1794_02_11.jpg)

在一个客户端中写入并在另一个客户端中读取

此时，人们会想知道如果我们将一个数字作为值写入，也许是为了存储一些时间戳，而不是一个字符串，会发生什么。

让我们将新命令的键值设为`set new_msg 1234`，当我们写入命令键以检索值为`get new_msg`时，我们得到结果`"1234"`。注意值周围的双引号；这告诉我们有关 Redis 以及它存储数据的方式的更多信息，即 Redis 中存储的每个值都是字符串类型：

![使用 redis-cli 的 Hello World](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/lrn-redis/img/1794_02_12.jpg)

将整数值作为字符串获取

redis-cli 工具非常适用于调试解决方案并执行命令以检查系统和解决方案。

需要回答的下一个问题是如何以编程方式访问 Redis。

## 使用 Java 的 Hello World

在上一节中，您学习了如何使用`redis-cli.exe`应用程序来连接到 Redis 服务器。在本节中，我们将介绍一个 Java 客户端 API 来连接到 Redis 服务器并执行一些命令。实际上，要在解决方案中使用 Redis，需要一个 API 来连接服务器。除了连接到服务器、传递命令和命令参数以及返回结果之外，API 还需要一些其他属性，但我们将在后面的章节中进行介绍。

本书中选择的用于演示示例的 Java 客户端 API 是 Jedis。

在 Java 中运行`Hello World`示例有三个步骤。它们将在接下来的章节中进行解释。

### 安装 Jedis 并创建环境

**Jedis**是 Redis 的*Apache 许可 2.0* Java 客户端。本书中演示示例将使用此客户端。因此，最重要的是确保您拥有开发环境。对于本书，我们选择了 Eclipse 作为开发环境（[`www.eclipse.org/downloads/`](http://www.eclipse.org/downloads/)）。如果您没有 Eclipse，可以获取并安装它（它是免费的和有许可的）。本书的示例同样适用于其他集成开发环境。现在，执行以下步骤：

1.  打开 Eclipse 并创建一个名为`learning redis`的项目，如下截图所示：![安装 Jedis 并创建环境](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/lrn-redis/img/1794_02_13.jpg)

在 Eclipse 中创建一个项目

1.  如果您使用 Maven，则为 Jedis 添加以下依赖项：![安装 Jedis 并创建环境](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/lrn-redis/img/1794_02_14.jpg)

Jedis 的 Maven 依赖项

如果您使用其他构建工具，请按照说明相应地添加 Jedis 的依赖项。

### 编写程序

以下 Java 程序是使用 Redis 作为数据存储的：

```sql
 package org.learningredis.chapter.two;

import redis.clients.jedis.*;

public class HelloWorld {
  private JedisPool pool = new JedisPool(new JedisPoolConfig(), "localhost");

  private void test() {
    try 
        { 
            Jedis jedis = pool.getResource(); 
            jedis.set("MSG", "Hello World"); 
            String result = jedis.get("MSG"); 
            System.out.println(" MSG : " + result); 
            pool.returnResource(jedis); 

        } 
        catch (Exception e) 
        { 
            System.err.println(e.toString()); 
        }finally{
             pool.destroy(); 
        }

  } 

    public static void main(String args[]) 
    { 
        HelloWorld helloWorld = new HelloWorld();
        helloWorld.test();
    }

}
```

确保您的 Redis 服务器正在运行。在此示例中，使用的端口是默认端口 6379。

让我们逐步了解程序中正在进行的操作：

1.  我们正在设置一个连接池，以连接到 Redis 服务器。池配置为服务器将绑定到的默认 IP 地址。

1.  我们从池中获取资源（包装连接的客户端存根）。

1.  我们将键值设置到其中。这将推送要插入到 Redis 数据存储中的值。

1.  我们根据键获取值。在这种情况下，是根据前一步中插入的键的值。

1.  我们将资源返回到池中以便重用，并关闭池。

### 关闭服务器

与任何服务器一样，优雅地关闭服务器非常重要。在关闭任何 Redis 服务器之前，需要牢记几件事，这里进行了解释：

1.  关闭所有客户端连接。对于我们的 Java 程序，我们通过编写`"pool.destoy();"`来指示客户端关闭所有连接。

1.  我们需要做的下一件事是转到客户端提示符并命令服务器关闭。

1.  如果您打算将 Redis 用作缓存服务器，则无需保存其持有的数据。在这种情况下，只需键入`shutdown nosave`。这将清除内存中的所有数据并释放它。

1.  如果您打算保存数据以便以后使用，那么您必须传递`shutdown save`命令。即使没有配置保存点，这将使数据持久化在`RDB`文件中，我们将在后面的章节中介绍。

以下图显示了从资源生命周期的角度来看示例中发生的情况：

![关闭服务器](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/lrn-redis/img/1794_02_15.jpg)

为 Jedis 客户端管理资源

在生命周期中，我们必须考虑三种资源。它们的解释如下：

+   **Jedis 连接池**：这是系统/应用程序启动时应该创建的池。这为池分配资源。应用程序服务器生命周期应该管理池的生命周期。

+   **连接**：在 Jedis 中，创建的客户端存根包装了连接并充当 Redis 的客户端。在前面列出的程序中，客户端存根被引用为*Jedis*，它是在`pool.getResource()`语句中获取的。

+   **请求生命周期**：这是命令正在执行的地方。因此，基本上在这里发生的是使用 Redis 协议，将命令和有效负载发送到服务器。有效负载包括键（如果是“getter”）或键和值（如果是“setter”）。生命周期由服务器的积极确认来管理。如果失败，它可能是成功或异常。在某种程度上，我们不需要为此语句进行显式的生命周期管理。

我们如何在 Jedis 中管理连接，如果我们不管理它们会发生什么？

对于问题“如果我们不管理它会发生什么”，答案很简单。池将耗尽连接，客户端应用程序将受到影响。我们在诸如 JDBC 之类的领域中遇到了与连接相关的问题，当客户端没有连接可连接到服务器时，应用程序会受到影响。总是服务器为连接保留内存，并关闭连接是服务器释放内存的指示。

对于问题“我们如何在 Jedis 中管理连接”的答案有点有趣，并且需要一些代码更改。我们将采用先前的代码示例并对其进行更改，其中我们将处理连接资源管理。对于以下示例，我正在添加一个包装器，但在您的应用程序中，您可以使用更奇特的方法来解决提到的问题。也就是说，您可以使用 Spring 来注入连接，或者使用`cglib`动态创建代理，在命令之前设置连接并在命令之后返回连接。

以下代码是新的 Hello World 程序，现在称为`HelloWorld2`：

```sql
package org.learningredis.chapter.two;

public class Helloworld2  {
  JedisWrapper jedisWrapper = null;
  public Helloworld2() {
    jedisWrapper = new JedisWrapper();
  }

  private void test() {
    jedisWrapper.set("MSG", "Hello world 2 ");

    String result = jedisWrapper.get("MSG");
    System.out.println("MSG : " + result);
  }

  public static void main(String[] args) {
    Helloworld2 helloworld2 = new Helloworld2();
    helloworld2.test();
  }
}
```

以下是处理连接的包装器代码：

```sql
package org.learningredis.chapter.two;

import redis.clients.jedis.Jedis;
import redis.clients.jedis.JedisPool;

import redis.clients.jedis.JedisPoolConfig;

public class JedisWrapper {
  static JedisPool pool = new JedisPool(new JedisPoolConfig(), "localhost");");");");");

  public void set(String key,String value){
    Jedis jedis = pool.getResource(); 
        jedis.set(key, value); 
        pool.returnResource(jedis);
  }

  public String get(String key){
    Jedis jedis = pool.getResource(); 
        String result = jedis.get("MSG"); ");");");"); 
        pool.returnResource(jedis);
        return result;
  }
}
```

在这种情况下，有两件事变得清楚，这里进行了解释：

+   我们不必管理连接/资源，因为这将由“包装器”类来处理

+   代码行数减少了，因为我们不必重复资源管理的代码

## 在 Redis 中加载一个测试 Hello World 程序

好吧，您已经看到了 Java 和命令行中的`Hello world`程序的示例。但是为您的`Hello World`程序添加一个负载测试维度总是很好的。Redis 附带了一个名为`redis-benchmark`的工具，可以在发布文件夹中找到。

以下命令将对 Redis 服务器进行 10 万次调用：

![在 Redis 中加载一个测试 Hello World 程序](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/lrn-redis/img/1794_02_17.jpg)

Hello World 的负载测试

结果是您的机器每秒处理的请求总数。这个工具对于负载测试您的目标环境非常有用。这是我在 Windows 机器上执行时得到的结果的快照，这将根据您的机器和操作系统的配置而有所不同：

![在 Redis 中加载一个测试 Hello World 程序](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/lrn-redis/img/1794_02_18.jpg)

工具执行负载测试

这里发生的是`redis-benchmark`打开了 50 个并行连接到 Redis 服务器并发送了 1 万个请求。请求包含 Redis 命令和 3 字节的有效负载。近似结果被打印出来进行分析；在我的情况下，1 万个`Set`命令总共花费了 0.30 秒，也就是说，每秒处理了 33,670 个请求。

# 总结

Redis 是一个简单的面向键值的 NoSQL，可以用作缓存服务器和持久化服务器。本章展示了在多个环境中安装 Redis 是多么简单，包括 Windows（Redis 也可以在云环境中使用，如 Amazon EC2）。Windows 的安装仅用于开发和抽样目的。 

Redis 具有一组有趣的数据结构，有时被称为数据结构服务器。下一章将详细介绍数据结构。


# 第三章：Redis 中的数据结构和通信协议

上一章介绍了安装 Redis 和运行一些简单程序。由于 Redis 是一个数据存储，因此了解 Redis 如何通过提供数据结构来处理和存储数据是很重要的。同样重要的是 Redis 在将数据传输给客户端时如何处理数据，比如通信协议。

# 数据结构

数据结构，顾名思义，意味着用于存储数据的结构。在计算世界中，数据总是以一种对存储它的程序有意义的方式组织的。数据结构可以从简单的字符顺序排列到复杂的地图，其中键不是顺序排列的，而是基于算法的。数据结构通常是复合的，这意味着一个数据结构可以容纳另一个数据结构，这是一个包含另一个地图的地图。

设计数据结构的关键影响因素是数据结构的性能和内存管理。一些常见的数据结构示例包括列表，集合，地图，图和树，元组等。作为程序员，我们一次又一次地在程序中使用数据结构。在面向对象的世界中，一个简单的*对象*也是一个数据结构，因为它包含数据和访问这些数据的逻辑。每个数据结构都受算法的控制，算法决定了其效率和功能能力。因此，如果算法可以分类，那么它将清楚地表明数据结构的性能；当数据被注入数据结构或当数据被读取或从数据结构中删除时。

大 O 表示法是一种对算法（数据结构）在数据增长时性能进行分类的方法。从 Redis 的角度来看，我们将根据以下符号对数据结构进行分类：

+   `O（1）`：命令在数据结构上花费的时间是恒定的，不管它包含多少数据。

+   `O（N）`：命令在数据结构上花费的时间与其包含的数据量成线性比例，其中`N`是元素的数量。

+   `O（log（N））`：命令在数据结构上花费的时间是对数性质的，其中`N`是元素的数量。表现出这种特性的算法非常高效，用于在排序数组中查找元素。这可以解释为随着时间的推移而相当恒定。

+   `O（log（N）+ M）`：命令花费的时间取决于对数值，其中`M`是排序集中的元素总数，`N`是搜索范围。这可以解释为相当依赖于`M`的值。随着`M`值的增加，搜索所需的时间也会增加。

+   `O（M log（M））`：命令花费的时间是对数线性的。

# Redis 中的数据类型

Redis 是一个数据结构服务器，具有许多内置数据类型，这使得它与生态系统中的其他键值 NoSQL 数据存储有所不同。与其他 NoSQL 不同，Redis 为用户提供了许多内置数据类型，这提供了一种语义方式来安排其数据。可以这样想：在设计解决方案时，我们需要领域对象，这些对象在某种程度上塑造了我们的数据层。在决定领域对象之后，我们需要设计要保存在数据存储中的数据的结构，为此我们需要一些预定义的数据结构。这样做的好处是节省了程序员外部创建和管理这些数据的时间和精力。例如，假设在我们的程序中需要一种类似 Set 的数据结构。使用 Java，我们可以轻松地使用内置数据结构，如 Set。如果我们要将这些数据作为键值存储，我们将不得不将整个集合放在一个键值对中。现在，如果我们要对这个集合进行排序，通常的方法是提取数据并以编程方式对数据进行排序，这可能很麻烦。如果数据存储本身提供了内部对数据进行排序的机制，那就太好了。Redis 内置了以下数据类型来存储数据：

+   字符串

+   哈希

+   列表

+   集合

+   有序集合

以下图表示可以映射到键的数据类型。在 Redis 中，键本身是字符串类型，它可以存储其中的任何一个，如下所示：

![Redis 中的数据类型](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/lrn-redis/img/1794_0123OS_03_01.jpg)

键和其可以存储的值的表示

## 字符串数据类型

**字符串**类型是 Redis 中的基本数据类型。尽管术语上有些误导，但在 Redis 中，字符串可以被视为一个可以容纳字符串、整数、图像、文件和可序列化对象的字节数组。这些字节数组在性质上是二进制安全的，它们可以容纳的最大大小为 512MB。在 Redis 中，字符串被称为**Simple Dynamic String**（**SDS**），在 C 语言中实现为`Char`数组，还有一些其他属性，如`len`和`free`。这些字符串也是二进制安全的。SDS 头文件在`sds.h`文件中定义如下：

```sql
struct sdshdr {
            long len;
           long free;
              char buf[];
          };
```

因此，Redis 中的任何字符串、整数、位图、图像文件等都存储在`buf[]`（`Char`数组）中，`len`存储缓冲数组的长度，`free`存储额外的字节以进行存储。Redis 具有内置机制来检测数组中存储的数据类型。有关更多信息，请访问[`redis.io/topics/internals-sds`](http://redis.io/topics/internals-sds)。

Redis 中的命令可以按以下部分对字符串进行分类：

+   **设置器和获取器命令**：这些是用于在 Redis 中设置或获取值的命令。有单个键值和多个键值的命令。对于单个获取和设置，可以使用以下命令：

+   `Get` key：获取键的值。该命令的时间性能为`O（1）`。

+   `Set` key：该键设置一个值。该命令的时间性能为`O（1）`。

+   `SETNX` key：如果键不存在，则该键设置一个值 - 不会覆盖。该命令的时间性能为`O（1）`。

+   `GETSET` key：获取旧值并设置新值。该命令的时间性能为`O（1）`。

+   `MGET key1` key：获取所有键的相应值。该命令的时间性能为`O（N）`。

+   `MSET` key：设置所有键的相应值。该命令的时间性能为`O（N）`，其中`N`是要设置的键的数量。

+   `MSETNX` key：如果所有键都不存在，则设置所有键的相应值，即如果一个键存在，则不设置任何值。该命令的时间性能为`O（N）`，其中`N`是要设置的键的数量。

+   **数据清理命令**：这些是用于管理值的生命周期的命令。默认情况下，密钥的值没有到期时间。但是，如果您有一个值需要具有生命周期的用例，那么请使用以下密钥：

+   `SET PX/ EX`：在到期时间后删除值，密钥在毫秒后过期。该命令的时间性能为`O（1）`。

+   `SETEX`：在到期时间后删除值，密钥在秒后过期。该命令的时间性能为`O（1）`。

+   **实用命令**：以下是一些这些命令：

+   `APPEND`：此命令将附加到现有值，如果不存在则设置。该命令的时间性能为`O（1）`。

+   `STRLEN`：此命令返回存储为字符串的值的长度。该命令的时间性能为`O（1）`。

+   `SETRANGE`：此命令在给定的偏移位置上覆盖字符串。该命令的时间性能为`O（1）`，前提是新字符串的长度不会花费太长时间来复制。

+   `GETRANGE`：此命令从给定的偏移量获取子字符串值。该命令的时间性能为`O（1）`，前提是新子字符串的长度不会太大。

以下是一个演示字符串命令简单用法的示例程序。执行程序并自行分析结果。

```sql
package org.learningredis.chapter.three.datastruct;
import redis.clients.jedis.Jedis;
import redis.clients.jedis.JedisPool;
import redis.clients.jedis.JedisPoolConfig;
public class MyStringTest {
  private JedisPool pool = new JedisPool(new JedisPoolConfig(), "localhost");
  Jedis jedis = null;

  public Jedis getResource() {
    jedis = pool.getResource();
    return jedis;
  }
  public void setResource(Jedis jedis){
    pool.returnResource(jedis);
  }
  public static void main(String[] args) throws InterruptedException {
    MyStringTest myStringTest  = new MyStringTest();
    myStringTest.test();

  }
  private void test() throws InterruptedException {
    Jedis jedis = this.getResource();
    String commonkey = "mykey";
    jedis.set(commonkey, "Hello World");
    System.out.println("1) "+jedis.get("mykey"));
    jedis.append(commonkey, " and this is a bright sunny day ");
    System.out.println("2) "+jedis.get("mykey"));
    String substring=jedis.getrange(commonkey, 0 , 5);
    System.out.println("3) "+"substring value = "+substring);
    String commonkey1 = "mykey1";
    jedis.set(commonkey1, "Let's learn redis");
    for(String value : jedis.mget(commonkey,commonkey1)){
      System.out.println("4) "+" - "+ value);
    }
    jedis.mset("mykey2","let's start with string","mykey3","then we will learn other data types");
    for(String value : jedis.mget(commonkey,commonkey1,"mykey2","mykey3")){
      System.out.println("5) "+"   -- "+ value);
    }
    jedis.msetnx("mykey4","next in line is hashmaps");
    System.out.println("6) "+jedis.get("mykey4"));
    jedis.msetnx("mykey4","next in line is sorted sets");
    System.out.println("7) "+jedis.get("mykey4"));
    jedis.psetex("mykey5", 1000, "this message will self destruct in 1000 milliseconds");
    System.out.println("8) "+jedis.get("mykey5"));
    Thread.currentThread().sleep(1200);
    System.out.println("8) "+jedis.get("mykey5"));
    Long length=jedis.strlen(commonkey);
    System.out.println("9) "+" the length of the string 'mykey' is " + length);
    this.setResource(jedis);
  }
}
```

Redis 中的整数和浮点数的命令可以分为以下部分：

+   **设置器和获取器命令**：命令集与字符串中提到的相同。

+   **数据清理命令**：命令集与字符串中提到的相同。

+   **实用命令**：这里的命令将帮助操作整数和浮点值。对于整数，此操作仅限于 64 位有符号整数：

+   **APPEND**：这将将现有整数与新整数连接。该命令的时间性能为`O（1）`。

+   **DECR**：这将使值减少一。该命令的时间性能为`O（1）`。

+   **DECRBY**：这将使值减少给定的值。该命令的时间性能为`O（1）`。

+   **INCR**：这将使值增加一。该命令的时间性能为`O（1）`。

+   **INCRBY**：这将使值增加给定的值。该命令的时间性能为`O（1）`。

+   **INCRBYFLOAT**：这将使值增加给定的浮点值。该命令的时间性能为`O（1）`。

除了常规数字、字符串等，字符串数据类型可以存储一种称为**BitSet**或**bitmap**的特殊数据结构。让我们更多地了解它们并看看它们的用法。

## BitSet 或位图数据类型

这些是特殊的高效利用空间的数据结构类型，用于存储特殊类型的信息。位图特别用于实时分析工作。尽管位图只能存储二进制值（1 或 0），但它们占用的空间较少，获取值的性能为`O（1）`，这使它们对实时分析非常有吸引力：

![BitSet 或位图数据类型](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/lrn-redis/img/1794_0123OS_03_02.jpg)

位图的表示

密钥可以是任何基于日期的密钥。假设这里的密钥表示了 2014 年 12 月 12 日购买书籍的用户的位图。

例如，`12/12/2014-user_purchased_book_learning_redis`。这里的偏移量表示与用户关联的唯一整数 ID。这里我们有与数字 0、1、2...n 等关联的用户。每当用户购买商品时，我们找到用户的相应唯一 ID，并在该偏移位置将值更改为`1`。

以下问题可以借助这个空间优化、高性能的位图来回答：

+   2014 年 12 月 12 日有多少次购买？

答案：计算位图中的 1 的数量，即进行购买的用户数量，例如 9。

+   与 ID（偏移编号）为 15 的用户是否进行了购买？

答案：偏移量为 15 的值为 0，因此用户没有购买。

这些位图的集合可以用于联合，以找到更复杂的分析答案。让我们向现有样本添加另一个位图，例如称为`12/12/2014-user_browsed_book_learning_redis`。使用这两个位图，我们可以找到以下问题的答案：

+   浏览产品（*学习 Redis*）页面的用户有多少？

+   购买产品（*学习 Redis*）页面的用户有多少？

+   浏览产品页面的用户中有多少人购买了这本书？

+   没有浏览产品页面的用户购买了这本书有多少？

### 使用情况场景

Redis 字符串可用于存储对象 ID。例如，会话 ID、XML、JSON 等配置值。Redis 字符串（存储整数）可用作原子计数器。Redis 字符串（存储位图）可用作实时分析引擎。

## 哈希数据类型

哈希是 Redis 中类似 Java 中的映射的版本。Redis 中的哈希用于存储属性和它们的值的映射。为了更好地理解，假设我们有一个名为*学习 Redis*的对象；这个对象将有许多属性，比如作者、出版商、ISBN 号等。为了在存储系统中表示这些信息，我们可以将信息存储为 XML、JSON 等，并与我们的键*学习 Redis*相关联。如果我们需要某个特定的值，例如存储在*学习 Redis*中的作者，那么就必须检索整个数据集，并筛选出所需的值。以这种方式工作将不高效，因为需要大量数据通过网络传输，并且客户端的处理会增加。Redis 提供了哈希数据结构，可以用于存储这种类型的数据。以下图示出了前面示例的图解表示：

![哈希数据类型](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/lrn-redis/img/1794_0123OS_03_03.jpg)

哈希数据类型

哈希以占用更少的空间存储，Redis 中的每个哈希可以存储多达 2³²个字段-值对，即超过 40 亿。

哈希中的命令以`H`开头，Redis 中哈希的命令可以分为以下几部分：

+   **设置器和获取器命令**：以下是此命令：

+   `HGET`：该命令获取键的字段的值。该命令的基于时间的性能为`O(1)`。

+   `HGETALL`：该命令获取键的所有值和字段。该命令的基于时间的性能为`O(1)`。

+   `HSET`：该命令为键的字段设置值。该命令的基于时间的性能为`O(1)`。

+   `HMGET`：该命令获取键的字段的值。该命令的基于时间的性能为`O(N)`，其中`N`是字段的数量。但是，如果`N`很小，则为`O(1)`。

+   `HMSET`：该命令为键的各个字段设置多个值。该命令的基于时间的性能为`O(N)`，其中`N`是字段的数量。但是，如果`N`很小，则为`O(1)`。

+   `HVALS`：该命令获取键的哈希中的所有值。该命令的基于时间的性能为`O(N)`，其中`N`是字段的数量。但是，如果`N`很小，则为`O(1)`。

+   `HSETNX`：该命令为提供的键设置字段的值，前提是该字段不存在。该命令的基于时间的性能为`O(1)`。

+   `HKEYS`：该命令获取键的哈希中的所有字段。该命令的基于时间的性能为`O(1)`。

+   **数据清理命令**：以下是此命令：

+   `HDEL`：该命令删除键的字段。该命令的基于时间的性能为`O(N)`，其中`N`是字段的数量。但是，如果`N`很小，则为`O(1)`。

+   **实用命令**：以下是此命令：

+   `HEXISTS`：该命令检查键的字段是否存在。该命令的基于时间的性能为`O(1)`。

+   `HINCRBY`：此命令递增键的字段的值（假设该值是整数）。此命令的基于时间的性能为`O(1)`。

+   `HINCRBYFLOAT`：此命令递增键的字段的值（假设该值是浮点数）。此命令的基于时间的性能为`O(1)`。

+   `HLEN`：此命令获取键的字段数。此命令的基于时间的性能为`O(1)`。

以下是一个演示哈希命令简单用法的示例程序。执行程序并自行分析结果。

```sql
  package org.learningredis.chapter.three.datastruct;
import java.util.HashMap;
import java.util.Map;
import redis.clients.jedis.Jedis;
import redis.clients.jedis.JedisPool;
import redis.clients.jedis.JedisPoolConfig;
public class MyHashesTest {
  private JedisPool pool = new JedisPool(new JedisPoolConfig(), "localhost");
  Jedis jedis = null;

  public Jedis getResource() {
    jedis = pool.getResource();
    return jedis;
  }
  public void setResource(Jedis jedis){
    pool.returnResource(jedis);
  }
  public static void main(String[] args) 
throws InterruptedException  {
    MyHashesTest myHashesTest  = new MyHashesTest();
    myHashesTest.test();    
  }
  private void test() {
    Jedis jedis = this.getResource();
    String commonkey = "learning redis";
    jedis.hset(commonkey, "publisher", "Packt Publisher");
    jedis.hset(commonkey, "author", "Vinoo Das");
    System.out.println(jedis.hgetAll(commonkey));
Map<String,String> attributes = new HashMap<String,String>();
    attributes.put("ISBN", "XX-XX-XX-XX");
    attributes.put("tags", "Redis,NoSQL");
    attributes.put("pages", "250");
    attributes.put("weight", "200.56");
    jedis.hmset(commonkey, attributes);
    System.out.println(jedis.hgetAll(commonkey));
    System.out.println(jedis.hget(commonkey,"publisher"));
    System.out.println(jedis.hmget(commonkey,"publisher","author"));
    System.out.println(jedis.hvals(commonkey));
    System.out.println(jedis.hget(commonkey,"publisher"));
    System.out.println(jedis.hkeys(commonkey));
    System.out.println(jedis.hexists(commonkey, "cost"));
    System.out.println(jedis.hlen(commonkey));
    System.out.println(jedis.hincrBy(commonkey,"pages",10));
    System.out.println(jedis.hincrByFloat(commonkey,"weight",1.1) + " gms");
    System.out.println(jedis.hdel(commonkey,"weight-in-gms"));
    System.out.println(jedis.hgetAll(commonkey));
    this.setResource(jedis);
  }
}
```

### 使用案例场景

哈希提供了一种语义接口，用于在 Redis 服务器中存储简单和复杂的数据对象。例如，用户配置文件，产品目录等。

## 列表数据类型

Redis 列表类似于 Java 中的链表。Redis 列表可以在头部或尾部添加元素。执行此操作的性能是恒定的，或者可以表示为`O(1)`。这意味着，假设您有一个包含 100 个元素的列表，添加元素到列表所需的时间等于添加元素到包含 10,000 个元素的列表所需的时间。但另一方面，访问 Redis 列表中的元素将导致整个列表的扫描，这意味着如果列表中的项目数量较多，则性能会下降。

Redis 列表以链表形式实现的优势在于，Redis 列表作为一种数据类型，设计为具有比读取更快的写入速度（这是所有数据存储所显示的特性）。

![列表数据类型](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/lrn-redis/img/1794_0123OS_03_04.jpg)

列表数据类型

Redis 中的列表命令通常以`L`开头。这也可以解释为所有命令将从*列表的左侧或头部*执行，而从*列表的右侧或尾部*执行的命令则以 R 开头。这些命令可以分为以下几个部分：

+   **设置器和获取器命令**：以下是此类命令的示例：

+   `LPUSH`：此命令从列表的左侧添加值。此命令的基于时间的性能为`O(1)`。

+   `RPUSH`：此命令从列表的右侧添加值。此命令的基于时间的性能为`O(1)`。

+   `LPUSHX`：此命令如果键存在，则从列表的左侧添加值。此命令的基于时间的性能为`O(1)`。

+   `RPUSHX`：此命令如果键存在，则从列表的右侧添加值。此命令的基于时间的性能为`O(1)`。

+   `LINSERT`：此命令在*枢轴*位置之后插入一个值。此枢轴位置是从左边计算的。此命令的基于时间的性能为`O(N)`。

+   `LSET`：此命令根据指定的索引在列表中设置元素的值。此命令的基于时间的性能为`O(N)`。

+   `LRANGE`：此命令根据起始索引和结束索引获取元素的子列表。此命令的基于时间的性能为*O(S+N)*。这里*S*是偏移的起始位置，*N*是我们在列表中请求的元素数量。这意味着，如果偏移离头部越远，范围的长度越大，查找元素所需的时间就会增加。

+   **数据清理命令**：以下是此类命令的示例：

+   `LTRIM`：此命令删除指定范围之外的元素。此命令的基于时间的性能为`O(N)`。这里的`N`是列表的长度。

+   `RPOP`：此命令删除最后一个元素。此命令的基于时间的性能为`O(1)`。

+   `LREM`：此命令删除指定索引点的元素。此命令的基于时间的性能为`O(N)`。这里的`N`是列表的长度。

+   `LPOP`：此命令删除列表的第一个元素。此命令的基于时间的性能为`O(1)`。

+   **实用命令**：以下是此类命令的示例：

+   `LINDEX`：此命令根据指定的索引获取列表中的元素。该命令的时间性能为`O（N）`。这里的`N`是要遍历以达到所需索引处的元素数量。

+   `LLEN`：此命令获取列表的长度。该命令的时间性能为`O（1）`。

+   **高级命令**：此类型包括以下命令：

+   `BLPOP`：此命令从所述列表序列中的非空索引处获取元素，如果头部没有值，则阻止调用，直到至少设置一个值或超时发生。`BLPOP`中的字母`B`提示此调用是阻塞的。该命令的时间性能为`O（1）`。

+   `BRPOP`：此命令从所述列表序列中的尾部获取元素，如果头部没有值，则阻止调用，直到至少设置一个值或超时发生。该命令的时间性能为`O（1）`。

+   `RPOPLPUSH`：此命令作用于两个列表。假设源列表和目标列表，它将获取源列表的最后一个元素并将其推送到目标列表的第一个元素。该命令的时间性能为`O（1）`。

+   `BRPOPLPUSH`：此命令是`RPOPLPUSH`命令的*阻塞*变体。在这种情况下，如果源列表为空，则 Redis 将阻止操作，直到将一个值推送到列表中或达到超时。这些命令可用于创建队列。该命令的时间性能为`O（1）`。

以下是一个演示列表命令简单用法的示例程序。执行程序并自行分析结果：

```sql
package org.learningredis.chapter.three.datastruct;
import redis.clients.jedis.Jedis;
import redis.clients.jedis.JedisPool;
import redis.clients.jedis.JedisPoolConfig;
import redis.clients.jedis.BinaryClient.LIST_POSITION;
public class MyListTest {
  private JedisPool pool = new JedisPool(new JedisPoolConfig(), "localhost");
  Jedis jedis = null;
  public Jedis getResource() {
    jedis = pool.getResource();
    return jedis;
  }
  public void setResource(Jedis jedis){
    pool.returnResource(jedis);
  }
  public static void main(String[] args) throws InterruptedException {
    MyListTest myListTest  = new MyListTest();
    myListTest.test();
  }
  private void test() {
    Jedis jedis = this.getResource();
    System.out.println(jedis.del("mykey4list"));
    String commonkey="mykey4list";
    String commonkey1="mykey4list1";
    for(int index=0;index<3;index++){
      jedis.lpush(commonkey, "Message - " + index);
    }
    System.out.println(jedis.lrange(commonkey, 0, -1));
    for(int index=3;index<6;index++){
      jedis.rpush(commonkey, "Message - " + index);
    }
    System.out.println(jedis.lrange(commonkey, 0, -1));
    System.out.println(jedis.lindex(commonkey, 0));
    System.out.println(jedis.linsert(commonkey,LIST_POSITION.AFTER,"Message - 5", "Message - 7"));
    System.out.println(jedis.lrange(commonkey, 0, -1));
    System.out.println(jedis.linsert(commonkey,LIST_POSITION.BEFORE,"Message - 7", "Message - 6"));
    System.out.println(jedis.lrange(commonkey, 0, -1));
    System.out.println(jedis.llen(commonkey));
    System.out.println(jedis.lpop(commonkey));
    System.out.println(jedis.lrange(commonkey, 0, -1));
    System.out.println(jedis.lpush(commonkey,"Message - 2","Message -1.9"));
    System.out.println(jedis.lrange(commonkey, 0, -1));
    System.out.println(jedis.lpushx(commonkey,"Message - 1.8"));
    System.out.println(jedis.lrange(commonkey, 0, -1));
    System.out.println(jedis.lrem(commonkey,0,"Message - 1.8"));
    System.out.println(jedis.lrange(commonkey, 0, -1));
    System.out.println(jedis.lrem(commonkey,-1,"Message - 7"));
    System.out.println(jedis.lrange(commonkey, 0, -1));
    System.out.println(jedis.lset(commonkey,7,"Message - 7"));
    System.out.println(jedis.lrange(commonkey, 0, -1));
    System.out.println(jedis.ltrim(commonkey,2,-4));
    System.out.println(jedis.lrange(commonkey, 0, -1));
    jedis.rpoplpush(commonkey, commonkey1);
    System.out.println(jedis.lrange(commonkey, 0, -1));
    System.out.println(jedis.lrange(commonkey1, 0, -1));
  }
}
```

### 用例场景

列表提供了一个语义接口，用于在 Redis 服务器中按顺序存储数据，其中*写*速度比*读*性能更可取。例如，日志消息。

## 集合数据类型

Redis 集合是无序的 SDS 的数据结构集合。集合中的值是唯一的，不能有重复值。在 Redis 集合的性能方面，一个有趣的方面是，它们在添加、删除和检查元素存在方面显示出恒定的时间。集合中可以有的最大条目数为 2³²，即每个集合最多有 40 亿个条目。这些集合值是无序的。从外观上看，集合可能看起来像列表，但它们有不同的实现，这使它们成为解决集合理论问题的完美候选者。

![集合数据类型](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/lrn-redis/img/1794_0123OS_03_05.jpg)

集合数据类型

Redis 中用于集合的命令可以分为以下几部分：

+   **设置器和获取器命令**：此类型包括以下命令：

+   `SADD`：此命令向集合中添加一个或多个元素。该命令的时间性能为`O（N）`。这里的`N`是需要添加的元素数量。

+   **数据清理命令**：以下是属于此类别的一些命令：

+   `SPOP`：此命令从集合中移除并返回一个随机元素。该命令的时间性能为`O（1）`。

+   `SREM`：此命令从集合中移除并返回指定的元素。该命令的时间性能为`O（N）`。这里的`N`是要移除的元素数量。

+   **实用命令**：以下是属于此类型的命令：

+   `SCARD`：此命令获取集合中的元素数量。该命令的时间性能为`O（1）`。

+   `SDIFF`：此命令从其他所述集合中减去其元素后获取第一个集合的元素列表。该命令的时间性能为`O（N）`。这里的`N`是所有集合中的元素数量。

+   `SDIFFSTORE`：此命令从其他指定的集合中减去第一个集合的元素后获取元素列表。然后将这个集合推送到另一个集合中。该命令的基于时间的性能为`O(N)`。这里的`N`是所有集合中元素的数量。

+   `SINTER`：此命令获取所有指定集合中的公共元素。该命令的基于时间的性能为`O(N*M)`。这里的`N`是最小集合的基数，`M`是集合的数量。基本上是 Redis 将取最小集合，并查找该集合与其他集合之间的公共元素。然后再次比较结果集中的公共元素，如前述过程，直到只剩下一个集合包含所需的结果。

+   `SINTERSTORE`：此命令与`SINTER`命令的工作方式相同，但结果存储在指定的集合中。该命令的基于时间的性能为`O(N*M)`。这里的`N`是最小集合的基数，`M`是集合的数量。

+   `SISMEMBER`：此命令查找值是否是集合的成员。该命令的基于时间的性能为`O(1)`。

+   `SMOVE`：此命令将成员从一个集合移动到另一个集合。该命令的基于时间的性能为`O(1)`。

+   `SRANDMEMBER`：此命令从集合中获取一个或多个随机成员。该命令的基于时间的性能为`O(N)`。这里的`N`是传递的成员数量。

+   `SUNION`：此命令添加多个集合。该命令的基于时间的性能为`O(N)`。这里的`N`是所有集合中元素的数量。

+   `SUNIONSTORE`：此命令将多个集合添加到一个集合中并将结果存储在一个集合中。该命令的基于时间的性能为`O(N)`。这里的`N`是所有集合中元素的数量。

以下是用于集合的简单用法的示例程序。执行程序并自行分析结果：

```sql
package org.learningredis.chapter.three.datastruct;
import redis.clients.jedis.Jedis;
import redis.clients.jedis.JedisPool;
import redis.clients.jedis.JedisPoolConfig;
public class MySetTest {
  private JedisPool pool = new JedisPool(new JedisPoolConfig(), "localhost");
  Jedis jedis = null;
  public Jedis getResource() {
    jedis = pool.getResource();
    return jedis;
  }
  public void setResource(Jedis jedis){
    pool.returnResource(jedis);
  }
  public static void main(String[] args) {
    MySetTest mySetTest = new MySetTest();
    mySetTest.test();
  }
  private void test() {
    Jedis jedis = this.getResource();
    jedis.sadd("follow:cricket", "vinoo.das@junk-mail.com","vinoo.das1@junk-mail.com","vinoo.das3@junk-mail.com");
    System.out.println(jedis.smembers("follow:cricket"));
    System.out.println(jedis.scard("follow:cricket"));
    jedis.sadd("follow:redis", "vinoo.das1@junk-mail.com","vinoo.das2@junk-mail.com");
    System.out.println(jedis.smembers("follow:redis"));
    System.out.println(jedis.scard("follow:redis"));
    // intersect the above sets to give name who is interested in cricket and redis
    System.out.println(jedis.sinter("Cricket:followers","follow:redis"));
    jedis.sinterstore("follow:redis+cricket","follow:cricket","follow:redis");
    System.out.println(jedis.smembers("follow:redis+cricket"));
    System.out.println(jedis.sismember("follow:redis+cricket", "vinoo.das@junk-mail.com"));
    System.out.println(jedis.sismember("follow:redis+cricket", "vinoo.das1@junk-mail.com"));
    jedis.smove("follow:cricket", "follow:redis", "vinoo.das3@junk-mail.com");
    System.out.println(jedis.smembers("follow:redis"));
    System.out.println(jedis.srandmember("follow:cricket"));
    System.out.println(jedis.spop("follow:cricket"));
    System.out.println(jedis.smembers("follow:cricket"));
    jedis.sadd("follow:cricket","wrong-data@junk-mail.com");
    System.out.println(jedis.smembers("follow:cricket"));
    jedis.srem("follow:cricket","wrong-data@junk-mail.com");
    System.out.println(jedis.smembers("follow:cricket"));
    System.out.println(jedis.sunion("follow:cricket","follow:redis"));
    jedis.sunionstore("follow:cricket-or-redis","follow:cricket","follow:redis");
    System.out.println(jedis.smembers("follow:cricket-or-redis"));
    System.out.println(jedis.sdiff("follow:cricket", "follow:redis"));
  }
}
```

### 使用情景

集合提供了一种语义接口，可以将数据存储为 Redis 服务器中的一个集合。这种类型数据的用例更多用于分析目的，例如有多少人浏览了产品页面，有多少最终购买了产品。

## 有序集合数据类型

Redis 有序集合与 Redis 集合非常相似，它们都不存储重复值，但它们与 Redis 集合不同的地方在于，它们的值是根据分数或整数、浮点值进行排序的。在设置集合中的值时提供这些值。有序集合的性能与元素数量的对数成正比。数据始终以排序的方式保存。这个概念在下图中以图表的方式解释：

![有序集合数据类型](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/lrn-redis/img/1794_0123OS_03_06.jpg)

有序集合的概念

Redis 中有关有序集合的命令可以分为以下几个部分：

+   **设置器和获取器命令**：以下是属于此类别的命令：

+   `ZADD`：此命令向有序集合中添加或更新一个或多个成员。该命令的基于时间的性能为`O(log(N))`。这里的`N`是有序集合中的元素数量。

+   `ZRANGE`：此命令根据有序集合中元素的排名获取指定范围。该命令的基于时间的性能为`O(log(N)+M)`。这里的`N`是元素的数量，`M`是返回的元素的数量。

+   `ZRANGEBYSCORE`：此命令根据给定的分数范围从有序集合中获取元素。默认集合中的值是按升序排列的。该命令的基于时间的性能为`O(log(N)+M)`。这里的`N`是元素的数量，`M`是返回的元素的数量。

+   `ZREVRANGEBYSCORE`：此命令根据给定的分数从有序集合中获取元素。该命令的基于时间的性能为`O(log(N)+M)`。这里的`N`是元素的数量，`M`是被移除的元素的数量。

+   `ZREVRANK`：此命令返回有序集合中成员的排名。该命令的基于时间的性能为`O(log(N))`。

+   `ZREVRANGE`：此命令返回有序集合中指定范围的元素。该命令的基于时间的性能为`O(log(N) + M)`。

+   **数据清理命令**：以下是属于此类别的命令：

+   `ZREM`：此命令从有序集合中移除指定的成员。该命令的基于时间的性能为`O(M*log(N))`。这里的`M`是移除的元素数量，`N`是有序集合中的元素数量。

+   `ZREMRANGEBYRANK`：此命令在给定的索引范围内移除有序集合中的成员。该命令的基于时间的性能为`O(log(N)*M)`。这里的`N`是元素数量，`M`是被移除的元素数量。

+   `ZREMRANGEBYSCORE`：此命令在给定分数范围内移除有序集合中的成员。该命令的基于时间的性能为`O(log(N)*M)`。这里的`N`是元素数量，`M`是被移除的元素数量。

+   **实用命令**：以下是属于此类别的命令：

+   `ZCARD`：此命令获取有序集合中成员的数量。该命令的基于时间的性能为`O(1)`。

+   `ZCOUNT`：此命令获取有序集合中在分数范围内的成员数量。该命令的基于时间的性能为`O(log(N)*M)`。这里的`N`是元素数量，`M`是结果。

+   `ZINCRBY`：此命令增加有序集合中元素的分数。该命令的基于时间的性能为`O(log(N))`。这里的`N`是有序集合中的元素数量。

+   `ZINTERSTORE`：此命令计算由指定键给出的有序集合中的公共元素，并将结果存储在目标有序集合中。该命令的基于时间的性能为`O(N*K) + O(M*log(M))`。这里的`N`是最小的有序集合，`K`是输入集的数量，`M`是结果有序集合中的元素数量。

+   `ZRANK`：此命令获取有序集合中元素的索引。该命令的基于时间的性能为`O(log(N))`。

+   `ZSCORE`：此命令返回成员的分数。该命令的基于时间的性能为`O(1)`。

+   `ZUNIONSTORE`：此命令计算给定有序集合中键的并集，并将结果存储在结果有序集合中。该命令的基于时间的性能为`O(N) + O(M log(M))`。这里的`N`是输入有序集合大小的总和，`M`是有序集合中的元素数量。

以下是一个演示有序集合命令简单用法的示例程序。执行程序并自行分析结果：

```sql
package org.learningredis.chapter.three.datastruct;
import redis.clients.jedis.Jedis;
import redis.clients.jedis.JedisPool;
import redis.clients.jedis.JedisPoolConfig;
public class MySortedSetTest {
  private JedisPool pool = new JedisPool(new JedisPoolConfig(), "localhost");
  Jedis jedis = null;
  public Jedis getResource() {
    jedis = pool.getResource();
    return jedis;
  }
  public void setResource(Jedis jedis){
    pool.returnResource(jedis);
  }
  public static void main(String[] args) {
    MySortedSetTest mySortedSetTest = new MySortedSetTest();
    mySortedSetTest.test();
  }
  private void test() {
    Jedis jedis = this.getResource();
    jedis.zadd("purchase", 0, "learning-redis");
    jedis.zadd("purchase", 0, "cassandra");
    jedis.zadd("purchase", 0, "hadoop");
    System.out.println(jedis.zcard("purchase"));
    // purchase a 4 books on redis
    jedis.zincrby("purchase", 1, "learning-redis");
    jedis.zincrby("purchase", 1, "learning-redis");
    jedis.zincrby("purchase", 1, "learning-redis");
    jedis.zincrby("purchase", 1, "learning-redis");
    // purchase a 2 books on cassandra
    jedis.zincrby("purchase", 1, "cassandra");
    jedis.zincrby("purchase", 1, "cassandra");
    // purchase a 1 book on hadoop
    jedis.zincrby("purchase", 1, "hadoop");
    System.out.println(jedis.zcount("purchase", 3, 4));
    System.out.println(jedis.zrange("purchase", 0, 2));
    System.out.println(jedis.zrangeByScore("purchase", 3, 4));
    System.out.println(jedis.zrank("purchase", "learning-redis"));
    System.out.println(jedis.zrank("purchase", "cassandra"));
    System.out.println(jedis.zrank("purchase", "hadoop"));
    System.out.println(jedis.zrevrank("purchase", "learning-redis"));
    System.out.println(jedis.zrevrank("purchase", "cassandra"));
    System.out.println(jedis.zrevrank("purchase", "hadoop"));
    System.out.println(jedis.zscore("purchase", "learning-redis"));
    System.out.println(jedis.zscore("purchase", "cassandra"));
    System.out.println(jedis.zscore("purchase", "hadoop"));
    jedis.zunionstore("purchase:nosql", "purchase");
    System.out.println("-- " + jedis.zrange("purchase:nosql",0,-1));
    System.out.println("-- " + jedis.zrank("purchase:nosql","learning-redis"));
    jedis.zrem("purchase:nosql", "hadoop");
    System.out.println("-- " + jedis.zrange("purchase:nosql",0,-1));
    jedis.zremrangeByRank("purchase:nosql", 0,0);
    System.out.println("-- " + jedis.zrange("purchase:nosql",0,-1));
    jedis.zremrangeByScore("purchase:nosql", 3,4);
    System.out.println("-- " + jedis.zrange("purchase:nosql",0,-1));
    this.setResource(jedis);
  }
}
```

### 使用情景

有序集合提供了一个语义接口，可以将数据存储为 Redis 服务器中的有序集合。这种数据的用例更多地用于分析目的和游戏世界中。例如，有多少人玩了特定的游戏，并根据他们的得分对他们进行分类。

# 通信协议 - RESP

Redis 原则上是基于客户端-服务器模型工作的。因此，就像在每个客户端-服务器模型中一样，客户端和服务器需要有一个通信协议。通信协议可以理解为基于客户端和服务器之间的某种固定协议或规则进行的消息交换。因此，每个通信协议都必须遵循一些语法和语义，这些语法和语义应该由双方（客户端和服务器）遵循，以便通信成功。此外，还有另一个维度的通信协议，即网络层交互，或者更为人所熟知的 TCP/IP 模型。TCP/IP 模型可以分为四个部分：

+   应用层

+   传输层

+   互联网层

+   网络接口

由于两个应用程序之间的通信协议位于应用层，因此我们打算只关注应用层。以下图表是应用层通信协议级别上发生的事情的表示：

![通信协议 - RESP](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/lrn-redis/img/1794_0123OS_03_07.jpg)

应用层通信协议的表示

在任何应用程序协议中，我们都会有头部和主体。头部将包含有关协议的元信息，即协议名称、版本、安全相关细节、关于请求的元信息（参数数量、参数类型）等等，而主体将包含实际的数据。任何服务器的第一件事就是解析头部信息。如果头部成功解析，那么才会处理主体的其余部分。在某种程度上，服务器和客户端需要具有类似管道的架构来处理头部消息。

Redis 使用的协议相当简单易懂。本节将重点介绍 Redis 中使用的通信协议。在本节结束时，我们将了解协议并创建一个连接到 Redis 服务器的客户端，发送请求并从服务器获取响应。与任何其他协议一样，Redis 协议也有一个头部（元信息）和一个主体部分（请求数据）。请求数据部分包括命令和命令数据等信息。在响应中，它将包含元信息（如果请求成功或失败）和实际的响应数据负载。以下解释了这个概念：

![通信协议 - RESP](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/lrn-redis/img/1794_0123OS_03_08.jpg)

元信息和请求数据的表示

Redis 中的任何请求基本上由两部分组成，并且它们如下所述：

+   关于请求的元信息，比如**参数数量**。

+   Body 部分还将有三个更多的信息：

+   每个参数的字节数

+   实际参数

+   **回车和换行**（**CRLF**）

![通信协议 - RESP](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/lrn-redis/img/1794_0123OS_03_09.jpg)

请求的主体部分的表示

因此，我们将在元信息中保存的信息将是两个，因为这是我们将传递的参数的数量，如前图所示。在主体部分，我们将捕获信息，例如我们发送的参数的字节数是多少，即如果参数的名称是`GET`，那么字节数将是`3`。

Redis 中的响应可以分为两种类型：

+   将去添加或操作数据的命令的响应（不期望返回值）：

+   `+`符号表示请求成功

+   `-`符号表示请求失败

+   将去获取数据的命令的响应（期望返回字符串类型的值）：

+   如果错误是响应，则`$-1`将是响应

+   `$`以及如果响应成功则响应的大小，然后是实际的字符串数据

作为练习，让我们用 Java 代码制作一个小型测试客户端，并记录我们与 Redis 服务器的交互。该客户端只是一个示例，用于教育 Redis 协议，并不打算替换我们在本书中将使用的客户端，即 Jedis。让我们简要概述参与小型测试客户端的类。首先，从设计模式的角度来看，我们将为此示例使用命令模式：

+   `Command`：这个类是抽象类，所有的命令类都将从这个类扩展。

+   `GetCommand`：这是一个类，将获取给定键的字符串值并打印服务器响应和响应值。

+   `SetCommand`：这是一个类，将为命令设置键和值数据并打印服务器响应。

+   `ConnectionProperties`：这是将保存主机和端口地址的接口。（这将更像是一个属性文件。）

+   `TestClient`：这是将调用所有命令的类。

以下是简单测试客户端应用程序的领域图。这里命令对象承担了大部分工作：

![通信协议 - RESP](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/lrn-redis/img/1794_0123OS_03_10.jpg)

简单客户端应用程序的领域图

查看代码将更清楚地了解 Redis 的简单测试客户端：

+   `ConnectionProperties.java`：这是将保存主机和端口的配置值的类。

```sql
package org.learningredis.chapter.three;
public interface ConnectionProperties {
  public String host="localhost";
  public int   port =6379;
}
```

+   `TestClient.java`：如图所示，这是客户端，将执行设置值和获取值的命令。

```sql
package org.learningredis.chapter.three;
public class TestClient {
  public void execute(Command command){
      try{
        /*Connects to server*/
        command.excute();
      }catch(Exception e){
        e.printStackTrace();
      }
    }
  public static void main(String... args) {
    TestClient testclient = new TestClient();
    SetCommand set = new  SetCommand("MSG","Hello world : simple test client");
    testclient.execute(set);

    GetCommand get = new GetCommand("MSG");
    testclient.execute(get);
    }
}
```

如果一切顺利，您应该在控制台中看到以下消息。请记住，这是一个成功的操作，您的控制台应该类似于以下截图：

![通信协议 - RESP](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/lrn-redis/img/1794_0123OS_03_11.jpg)

在这个示例中，我们连续执行了两个命令：

+   `SetCommand`

+   `GetCommand`

`SetCommand`的结果是`+OK`。`+`符号表示服务器返回了成功的结果，后跟消息`OK`。

`GetCommand`的结果是多行结果。第一行是字符串`$32`，表示结果的大小为 32 个字节，后跟结果`Hello world : simple test client`。

现在，让我们尝试传递一个在`Get`命令中不存在的键。代码片段将看起来像下面显示的样子（在`wrong-key`中传递的键不存在）：

```sql
package org.learningredis.chapter.three;
public class TestClient {
  public void execute(Command command){
      try{
        /*Connects to server*/
        command.excute();
      }catch(Exception e){
        e.printStackTrace();
      }
    }
  public static void main(String... args) {
    TestClient testclient = new TestClient();
    SetCommand set = new  SetCommand("MSG","Hello world : simple test client");
    testclient.execute(set);

    GetCommand get = new GetCommand("Wrong-key");
    testclient.execute(get);
    }
}
```

前面代码的结果应该看起来像`$-1`命令。这里返回值为 null，因为键不存在。因此长度为`-1`。接下来，我们将用更易读的方式包装这条消息，比如`This key does not exist!`以下是一些讨论过的类：

+   `Command.java`：这是所有命令都将扩展的抽象类。该类负责为实现命令实例化套接字，并创建要发送到 Redis 服务器的适当有效负载。了解这一点将给我们一个提示，即 Redis 服务器实际上是如何接受请求的。![通信协议 - RESP](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/lrn-redis/img/1794_0123OS_03_12.jpg)

Command.java 的表示

第一个字符是`*`字符，后跟**我们将传递的参数数量**。这意味着如果我们打算执行**Set**命令，即**SET MSG Hello**，那么这里的参数总数是三。如果我们打算传递**Get**命令，比如**GET MSG**，那么参数数量是两。在参数数量之后，我们将使用**CRLF**作为分隔符。随后的消息将遵循一个重复的模式。这个模式非常简单易懂，即**$**后跟参数的字节长度，后跟**CRLF**，后跟参数本身。如果有更多的参数，那么将遵循相同的模式，但它们将由 CRLF 分隔符分隔。以下是`Command.java`的代码：

```sql
package org.learningredis.chapter.three;
import java.io.IOException;
import java.net.Socket;
import java.util.ArrayList;
public abstract class Command {
  protected Socket socket;
  public Command() {
    try {
      socket = new Socket(ConnectionProperties.host,
          ConnectionProperties.port);
    } catch (IOException e) {
      e.printStackTrace();
    }
  }
public String createPayload(ArrayList<String> 
messageList) 
{
    int argumentSize = messageList.size();
    StringBuffer payload = new StringBuffer();
    payload.append('*');
    payload.append(argumentSize);
    payload.append("\r\n");
    for (int cursor = 0; cursor < messageList.size(); cursor++) {
      payload.append("$");
      payload.append(messageList.get(cursor).length());
      payload.append("\r\n");
      payload.append(messageList.get(cursor));
      payload.append("\r\n");
    }
    return payload.toString().trim();
  }
  public abstract String createPayload();
  public abstract void execute() throws IOException;
}
```

代码简单易懂，它对消息有效负载进行准备和格式化。`Command`类有两个抽象方法，需要由实现命令来实现。除此之外，`Command`类根据`ConnectionProperties.java`中设置的属性创建一个新的套接字。

+   `GetCommand.java`：这是实现`GET KEY`命令的类。该类扩展了`Command.java`。以下是`GetCommand`的源代码：

```sql
package org.learningredis.chapter.three;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.util.ArrayList;
public class GetCommand extends Command{
  private String key;
  public GetCommand(String key) {
    this.key=key;
  }
  @Override
  public String createPayload() {
    ArrayList<String> messageList = new ArrayList<String>();
    messageList.add("GET");
    messageList.add(key);
    return super.createPayload(messageList);
  }
  @Override
  public void excute() throws IOException  {
    PrintWriter out = null;
    BufferedReader in=null;
    try {
    out = new PrintWriter(super.socket.getOutputStream(),true);
    out.println(this.createPayload());
      //Reads from Redis server
in = new BufferedReader(new 
          InputStreamReader(socket.getInputStream()));
          String msg=in.readLine();
          if (! msg.contains("-1")){
            System.out.println(msg);
            System.out.println(in.readLine());
          }else{
          // This will show the error message since the 
          // server has returned '-1'
          System.out.println("This Key does not exist !");
      }
    } catch (IOException e) {
      e.printStackTrace();
    }finally{
      out.flush();
      out.close();
      in.close();
      socket.close();
    }
  }
}
```

实现类原则上做两件事。首先，它将参数数组传递给超类，并将其格式化为 Redis 能理解的方式，然后将有效负载发送到 Redis 服务器并打印结果。

+   `SetCommand`：这与前一个命令类似，但在这个类中，我们将设置值。该类将扩展`Command.java`类。以下是`SetCommand`的源代码：

```sql
package org.learningredis.chapter.three;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.util.ArrayList;
public class SetCommand extends Command{
  private String key;
  private String value;
  public SetCommand(String key, String value) {
    this.key=key;
    this.value=value;
  }
  public String createPayload(){
ArrayList<String> messageList = new 
                  ArrayList<String>();
    messageList.add("SET");
    messageList.add(key);
    messageList.add(value);
    return super.createPayload(messageList);
  }
  @Override
  public void excute() throws IOException  {
    PrintWriter    out = null;
    BufferedReader in = null;
    try {
      out = new
PrintWriter(super.socket.getOutputStream (), true);
      out.println(this.createPayload());
      //Reads from Redis server
      in = new BufferedReader(new 
      InputStreamReader(socket.getInputStream()));  
      // This is going to be a single line reply..
      System.out.println(in.readLine());
    } catch (IOException e) {
      e.printStackTrace();
    }finally{
      in.close();
      out.flush();
      out.close();
      socket.close();
    }
  }
}
```

这个命令与之前的命令类似，原则上有两个作用。首先，它将参数数组传递给超类，并使用适当的值对其进行格式化，以便 Redis 能够理解，然后将有效负载传递给 Redis 服务器并打印结果。

编译程序并运行它时要玩得开心；添加更多命令并扩展它以满足您的业务需求。我强烈建议使用 Jedis，因为它很稳定，社区非常活跃，并且提供了对 Redis 新版本引入的新命令的实现。

# 总结

在本章中，我们涉及了 Redis 提供的各种数据结构或数据类型。我们还编写了一些程序来查看它们的工作原理，并尝试理解这些数据类型可以如何使用。最后，我们了解了 Redis 如何与客户端进行通信，以及反之亦然。

在下一章中，我们将进一步加深对 Redis 服务器的理解，并尝试理解将处理它的功能。


# 第四章：Redis 服务器中的功能

在前几章中，我们看到了 Redis 服务器的一些特性，使其成为键值 NoSQL。我们还看到 Redis 除了存储原始键值之外，还提供了以结构化方式存储数据的语义。这个特性使 Redis 在众多数据库中脱颖而出，因为大多数其他数据库（关系型数据库和其他 NoSQL）都没有提供程序员可以使用的接口。其他数据存储有固定的存储信息方式，如文档或映射，程序员必须将他们的数据转换为这些语义来保存信息。然而，在 Redis 中，程序员可以以与他们在程序中使用的相同语义存储信息，如映射，列表等。这种方式提供了更好更容易理解程序的方式。除此之外，Redis 提供了功能，使其不仅仅是一个数据存储，更像是一个框架构建者，或者换句话说，更像是一把瑞士军刀。在本章中，我们将探讨这些功能并试图理解它们。

以下是我们将讨论的功能：

+   实时消息传递（发布/订阅）

+   管道

+   事务

+   脚本

+   连接管理

# 实时消息传递（发布/订阅）

企业和社交媒体解决方案以类似的方式使用消息传递，从某种程度上说，这构成了任何框架或解决方案的支柱。消息传递还使我们能够拥有松散耦合的架构，其中组件通过消息和事件进行交互。Redis 提供了在组件之间进行实时消息传递的机制。与其他消息系统不同，Redis 中提供的消息模型的最大区别如下：

+   在传递消息后不会存储消息

+   如果客户端（订阅者）无法消费消息，则不会存储消息

与传统消息系统相比，这可能是一个缺点，但在数据实时重要且无需存储的情况下是有利的。消息始终按顺序发送。除此之外，Redis 消息系统简单易学，没有一些其他消息系统的多余内容。

![实时消息传递（发布/订阅）](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/lrn-redis/img/0123OS_04_01.jpg)

Redis 的发布订阅模型

以下是 Redis 中可用于创建消息框架的命令：

+   `PUBLISH`：这将向给定的频道或模式发布消息。

此命令的时间复杂度由`O（N+M）`给出，其中`N`是订阅此频道的客户端数，`M`是客户端订阅的模式数。

+   `SUBSCRIBE`：这将订阅客户端以接收频道的消息。例如，如果客户端订阅了频道`news.headlines`，那么它将收到为`news.headlines`频道发布的任何消息。

此命令的时间复杂度由`O（N）`给出，其中`N`是客户端订阅的频道数。

+   `PSUBSCRIBE`：这将订阅客户端到模式名称与频道名称匹配的频道。例如，假设频道由以下名称注册：

+   `news.sports.cricket`

+   `news.sports.tennis`

然后，对于像`news.sports.*`这样的模式，订阅者将收到`news.sports.cricket`和`news.sports.tennis`频道的消息。

此命令的时间复杂度为`O（N）`，其中`N`是客户端订阅的模式数。

+   `PUBSUB`：这是一个命令，结合一些子命令，可以帮助了解 Redis 中注册的模式和频道的情况。

### 注意

这仅适用于 Redis 2.8.0 版本。Windows 版本的 Redis 基于 2.6 分支，不支持此命令。

其他与`PUBSUB`相关的命令，可帮助查找有关发布者和订阅者的信息，如下所示：

+   `PUBSUB CHANNELS [pattern]`：这列出当前活动的频道

+   `PUBSUB NUMSUB [channel]`：这将列出订阅指定频道的订阅者数量。

+   发布订阅 NUMPAT：这列出了对所有模式的订阅数量

+   `PUNSUBSCRIBE`：此命令取消订阅客户端的模式

+   `UNSUBSCRIBE`：此命令取消订阅客户端的频道

让我们使用 Jedis 编写一个简单的 Java 程序来演示一个简单的 PUB/SUB 程序。Jedis 公开了发布的接口，并且支持 Redis 的所有功能。订阅消息的接口有点棘手，因为订阅者在发布者发布消息之前应该处于就绪状态。这是因为如果订阅者不可用，Redis 无法存储消息。发布者的代码：`SubscriberProcessor.java`：

```sql
package org.learningRedis.chapter.four.pubsub;
import Redis.clients.jedis.Jedis;
import Redis.clients.jedis.JedisPool;
import Redis.clients.jedis.JedisPoolConfig;
public class SubscriberProcessor implements Runnable{
  private JedisPool pool = new JedisPool(new JedisPoolConfig(), "localhost");
  private Subscriber subscriber = new Subscriber();
  private Thread simpleThread;
  private Jedis jedis = getResource();
  public Jedis getResource() {
    jedis = pool.getResource();
    return jedis;
  }
  public void setResource(Jedis jedis){
    pool.returnResource(jedis);
  }
  @SuppressWarnings("static-access")
  public static void main(String[] args) {
    SubscriberProcessor test = new SubscriberProcessor();
    test.subscriberProcessor();
    try {
      Thread.currentThread().sleep(10000);
    } catch (InterruptedException e) {
      e.printStackTrace();
    }
    test.unsubscribe();
  }
  private void unsubscribe() {
    simpleThread.interrupt();
    if(subscriber.isSubscribed()){
      subscriber.unsubscribe();
  }
  }
  private void subscriberProcessor() {
    simpleThread = new Thread(this);
    simpleThread.start();
  }
  @Override
  public void run() {
    while (!Thread.currentThread().isInterrupted()) {
      jedis.subscribe(subscriber, "news");
      //jedis.psubscribe(subscriber, "news.*");
    }
  }
}
```

订阅者处理器需要订阅一个频道。为此，它需要一个始终处于监听模式的实例。在此示例中，`Subscriber.java`是通过扩展 Jedis PUB/SUB 来实现的类。这个抽象类提供了管理订阅者生命周期的方法。接下来是提供必要钩子来订阅频道模式并监听频道或模式消息的代码。订阅模式的代码已被注释；要看到它的实际效果，我们需要取消注释它并注释订阅频道的代码：

```sql
package org.learningRedis.chapter.four.pubsub;
import Redis.clients.jedis.JedisPubSub;
public class Subscriber extends  JedisPubSub{
  @Override
  public void onMessage(String arg0, String arg1) {
    System.out.println("on message : " + arg0 + " value = " + arg1);
  }
  @Override
  public void onPMessage(String arg0, String arg1, String arg2) {
    System.out.println("on pattern message : " + arg0 + " channel = " + arg1 + " message =" + arg2);
  }
  @Override
  public void onPSubscribe(String arg0, int arg1) {
    System.out.println("on pattern subscribe : " + arg0 + " value = " + arg1);
  }
  @Override
  public void onPUnsubscribe(String arg0, int arg1) {
    System.out.println("on pattern unsubscribe : " + arg0 + " value = " + arg1);
  }
  @Override
  public void onSubscribe(String arg0, int arg1) {
    System.out.println("on subscribe : " + arg0 + " value = " + arg1);
  }
  @Override
  public void onUnsubscribe(String arg0, int arg1) {
    System.out.println("on un-subscribe : " + arg0 + " value = " + arg1);
  }
}
```

在启动发布者发送消息到频道之前，最好先启动订阅者处理器，该处理器将监听发布到其订阅频道或模式的任何消息。在这种情况下，订阅者处理器将监听新闻频道或将订阅模式`[news.*]`。 

在这些示例中使用的一个常见类是连接管理器，其代码如下所示：

```sql
package org.learningredis.chapter.four.pipelineandtx;
import redis.clients.jedis.Jedis;
import redis.clients.jedis.JedisPool;
public class ConnectionManager {
  private static JedisPool jedisPool = new JedisPool("localhost");
  public static Jedis get(){
    return jedisPool.getResource();
  }
  public static void set(Jedis jedis){
    jedisPool.returnResource(jedis);
  }
  public static void close(){
    jedisPool.destroy();
  }
}
```

要触发发布者，请使用以下发布者代码。发布者的代码`Publisher.java`如下：

```sql
package org.learningRedis.chapter.four.pubsub;
import Redis.clients.jedis.Jedis;
import Redis.clients.jedis.JedisPool;
import Redis.clients.jedis.JedisPoolConfig;
public class Publisher {
  private JedisPool pool = new JedisPool(new JedisPoolConfig(), "localhost");
  Jedis jedis = null;
  public Jedis getResource() {
    jedis = pool.getResource();
    return jedis;
  }
  public void setResource(Jedis jedis){
    pool.returnResource(jedis);
  }
  private void publisher() {
    Jedis jedis = this.getResource();
    jedis.publish("news", "Houstan calling texas... message published !!");
  }
  public static void main(String[] args) {
    Publisher test = new Publisher();
    test.publisher();
  }
}
```

在此示例中，该代码将向名为`news`的频道发布消息，要查看其工作情况，请确保订阅者已准备就绪，并且要发布消息到模式，请注释发布到频道的代码，并取消注释发布消息到模式的代码。

# Redis 中的管道

Redis 提供了一种更快执行的机制，称为*管道*。它将所有命令组合成一个命令块，并将其发送到服务器进行执行。所有命令的结果都排队在一个响应块中并发送回来。

将管道工作方式与通过连接发送多个单独命令的方式进行比较，可以让我们了解管道更有效的地方以及需要使用管道的地方。假设我们必须向 Redis 发送三个命令的情况。发送任何命令到 Redis 的时间为*X*秒，因此发送响应需要相同的时间。去程和回程所花费的总时间为*2X*秒。还假设执行所需的时间为另外*X*秒。现在在管道命令中，由于我们将三个命令作为一个块发送，因此去 Redis 所需的时间约为*X*秒，处理所有三个命令所需的时间为*3X*秒，回程所需的时间也为*X*秒。管道命令所需的总时间为*5X*秒。将其与必须发送单独命令的情况进行比较。发送单个命令及其回程所需的时间等于*2X*，包括执行所需的时间为*3X*。由于我们谈论的是三个命令，因此总时间等于*9X*。与*5X*秒相比，*9X*秒的时间证明了它的效率。

我们必须记住的一件事是，管道确保原子性，但只执行多个命令并在一个响应块中返回响应。以下是管道中调用的命令的简单表示：

![Redis 中的管道](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/lrn-redis/img/0123OS_04_02.jpg)

Redis 中的管道

接下来是跨多个连接发送的多个命令的表示。正如我们所看到的，通过使用管道命令，可以节省发送响应的时间：

![Redis 中的管道](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/lrn-redis/img/0123OS_04_03.jpg)

在 Redis 中使用单独连接的多个命令

这种批量发送命令的方式在 RDBMS 中也可以看到，我们可以将批量 JDBC 作为*批处理*发送。为了验证这一点，让我们编写一个程序，并检查在使用管道和不使用管道运行程序之间的时间差异：

```sql
package org.learningRedis.chapter.four.simplepipeline;
import java.util.List;
import Redis.clients.jedis.Jedis;
import Redis.clients.jedis.Pipeline;
public class PipelineCommandTest {
  Jedis jedis = ConnectionManager.get();
  long starttime_withoutpipeline = 0;
  long starttime_withpipeline = 0;
  long endtime_withoutpipeline = 0;
  long endtime_withpipeline = 0;
  public static void main(String[] args) throws InterruptedException {
    PipelineCommandTest test = new PipelineCommandTest();
    test.checkWithoutPipeline();
    Thread.currentThread().sleep(1000);
    test.checkWithPipeline();
    Thread.currentThread().sleep(1000);
    test.getStats();
  }
  private void getStats() {
    System.out.println(" time taken for test without pipeline "+ (endtime_withoutpipeline - starttime_withoutpipeline ));
    System.out.println(" time taken for test with    pipeline "+ (endtime_withpipeline - starttime_withpipeline ));
  }
  private void checkWithoutPipeline() {
    starttime_withoutpipeline = System.currentTimeMillis();
    for(int keys=0;keys<10;keys++){
      for(int nv=0;nv<100;nv++){
        jedis.hset("keys-"+keys, "name"+nv, "value"+nv);
      }
      for(int nv=0;nv<100;nv++){
        jedis.hget("keys-"+keys, "name"+nv);
      }
    }
    endtime_withoutpipeline = System.currentTimeMillis();
    // this will delete all the data.
    jedis.flushDB();
  }
  private void checkWithPipeline() {
    starttime_withpipeline = System.currentTimeMillis();
    for(int keys=0;keys<10;keys++){
      Pipeline commandpipe = jedis.pipelined();
      for(int nv=0;nv<100;nv++){
        commandpipe.hset("keys-"+keys, "name"+nv, "value"+nv);
      }
      List<Object> results = commandpipe.syncAndReturnAll();
      for(int nv=0;nv<results.size();nv++){
        results.get(nv);
      }
    }
    endtime_withpipeline = System.currentTimeMillis();
    jedis.flushDB();
  }
}
```

在我的计算机上的结果如下，当然，这可能会根据所使用的机器配置而有所不同：

```sql
time taken for test without pipeline 4015
time taken for test with    pipeline 250
```

管道提供了更快执行的优势，但也带来了一些限制。这仅在目标 Redis 实例相同时有效，也就是说，在分片环境中不起作用，因为每个 Redis 实例的连接都是不同的。当命令不相互依赖或需要编写自定义逻辑以形成复合命令时，管道也存在不足。在这种情况下，Redis 还提供了一种*脚本*的机制，我们将在本章后面进行介绍。

# Redis 中的事务

作为 NOSQL 数据存储的 Redis 提供了一种宽松的事务。与传统的 RDBMS 一样，事务以`BEGIN`开始，以`COMMIT`或`ROLLBACK`结束。所有这些 RDBMS 服务器都是多线程的，因此当一个线程锁定资源时，除非释放了锁，否则另一个线程无法操作它。Redis 默认使用`MULTI`开始，`EXEC`执行命令。在事务中，第一个命令始终是`MULTI`，之后所有的命令都被存储，当接收到`EXEC`命令时，所有存储的命令都按顺序执行。因此，在内部，一旦 Redis 接收到`EXEC`命令，所有命令都将作为单个隔离的操作执行。以下是 Redis 中可用于事务的命令：

+   `MULTI`：这标志着事务块的开始

+   `EXEC`：这在`MULTI`之后执行管道中的所有命令

+   `WATCH`：这会监视键以条件执行事务

+   `UNWATCH`：这会移除事务的`WATCH`键

+   `DISCARD`：这会刷新管道中之前排队的所有命令

以下图表示了 Redis 中事务的工作原理：

![Redis 中的事务](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/lrn-redis/img/0123OS_04_04.jpg)

Redis 中的事务

## 管道与事务

正如我们在管道中看到的，命令被分组并执行，并且响应被排队并发送。但是在事务中，直到接收到`EXEC`命令，`MULTI`之后接收到的所有命令都会被排队，然后执行。为了理解这一点，重要的是要考虑一个多线程环境，并观察结果。

在第一种情况下，我们使用两个线程向 Redis 发送管道命令。在这个示例中，第一个线程发送了一个管道命令，它将多次更改一个键的值，第二个线程将尝试读取该键的值。以下是将在 Redis 中启动两个线程的类：`MultiThreadedPipelineCommandTest.java`：

```sql
package org.learningRedis.chapter.four.pipelineandtx;
public class MultiThreadedPipelineCommandTest {
  public static void main(String[] args) throws InterruptedException {
    Thread pipelineClient = new Thread(new PipelineCommand());
    Thread singleCommandClient = new Thread(new SingleCommand());
    pipelineClient.start();
    Thread.currentThread().sleep(50);
    singleCommandClient.start();
  }
}
The code for the client which is going to fire the pipeline commands is as follows:
package org.learningRedis.chapter.four.pipelineandtx;
import java.util.Set;
import Redis.clients.jedis.Jedis;
import Redis.clients.jedis.Pipeline;
public class PipelineCommand implements Runnable{
  Jedis jedis = ConnectionManager.get();
  @Override
  public void run() {
      long start = System.currentTimeMillis();
      Pipeline commandpipe = jedis.pipelined();
      for(int nv=0;nv<300000;nv++){
        commandpipe.sadd("keys-1", "name"+nv);
      }
      commandpipe.sync();
      Set<String> data= jedis.smembers("keys-1");
      System.out.println("The return value of nv1 after pipeline [ " + data.size() + " ]");
    System.out.println("The time taken for executing client(Thread-1) "+ (System.currentTimeMillis()-start));
    ConnectionManager.set(jedis);
  }
}
```

当执行管道时，用于读取键的客户端的代码如下：

```sql
package org.learningRedis.chapter.four.pipelineandtx;
import java.util.Set;
import Redis.clients.jedis.Jedis;
public class SingleCommand implements Runnable {
  Jedis jedis = ConnectionManager.get();
  @Override
  public void run() {
    Set<String> data= jedis.smembers("keys-1");
    System.out.println("The return value of nv1 is [ " + data.size() + " ]");
    ConnectionManager.set(jedis);
  }
}
```

结果将根据机器配置而异，但通过更改线程休眠时间并多次运行程序，结果将与下面显示的结果类似：

```sql
The return value of nv1 is [ 3508 ]
The return value of nv1 after pipeline [ 300000 ]
The time taken for executing client(Thread-1) 3718
```

### 注意

请在每次运行测试时执行`FLUSHDB`命令，否则您将看到上一次测试运行的值，即 300,000

现在我们将以事务模式运行示例，其中命令管道将以`MULTI`关键字开头，并以`EXEC`命令结尾。这个客户端类似于之前的示例，其中两个客户端在单独的线程中向 Redis 发送命令。

以下程序是一个测试客户端，它给两个线程，一个处于事务模式的命令，第二个线程将尝试读取和修改相同的资源：

```sql
package org.learningRedis.chapter.four.pipelineandtx;
public class MultiThreadedTransactionCommandTest {
  public static void main(String[] args) throws InterruptedException {
    Thread transactionClient = new Thread(new TransactionCommand());
    Thread singleCommandClient = new Thread(new SingleCommand());
    transactionClient.start();
    Thread.currentThread().sleep(30);
    singleCommandClient.start();
  }
}
```

这个程序将尝试修改资源并在事务进行时读取资源：

```sql
package org.learningRedis.chapter.four.pipelineandtx;
import java.util.Set;
import Redis.clients.jedis.Jedis;
public class SingleCommand implements Runnable {
  Jedis jedis = ConnectionManager.get();
  @Override
  public void run() {
    Set<String> data= jedis.smembers("keys-1");
    System.out.println("The return value of nv1 is [ " + data.size() + " ]");
    ConnectionManager.set(jedis);
  }
}
```

这个程序将以`MULTI`命令开始，尝试修改资源，以`EXEC`命令结束，并稍后读取资源的值：

```sql
package org.learningRedis.chapter.four.pipelineandtx;
import java.util.Set;
import Redis.clients.jedis.Jedis;
import Redis.clients.jedis.Transaction;
import chapter.four.pubsub.ConnectionManager;
public class TransactionCommand implements Runnable {
  Jedis jedis = ConnectionManager.get();
  @Override
  public void run() {
      long start = System.currentTimeMillis();
      Transaction transactionableCommands = jedis.multi();
      for(int nv=0;nv<300000;nv++){
        transactionableCommands.sadd("keys-1", "name"+nv);
      }
      transactionableCommands.exec();
      Set<String> data= jedis.smembers("keys-1");
      System.out.println("The return value nv1 after tx [ " + data.size() + " ]");
    System.out.println("The time taken for executing client(Thread-1) "+ (System.currentTimeMillis()-start));
    ConnectionManager.set(jedis);
  }
}
```

上述程序的结果将根据机器配置而有所不同，但通过更改线程休眠时间并运行程序几次，结果将与下面显示的结果类似：

```sql
The return code is [ 1 ]
The return value of nv1 is [ null ]
The return value nv1 after tx [ 300000 ]
The time taken for executing client(Thread-1) 7078
```

### 注意

每次运行测试时都要执行`FLUSHDB`命令。这个想法是程序不应该获取由于上一次运行程序而获得的值。单个命令程序能够写入键的证据是如果我们看到以下行：`返回代码是[1]`。

让我们分析一下结果。在管道的情况下，一个单独的命令读取该键的值，而管道命令则为该键设置一个新值，如下结果所示：

```sql
The return value of nv1 is [ 3508 ]
```

现在将这与在事务的情况下发生的情况进行比较，当一个单独的命令尝试读取值但因事务而被阻塞时。因此该值将是`NULL`或 300,000。

```sql
  The return value of nv1 after tx [0] or
  The return value of nv1 after tx [300000] 
```

因此，输出结果的差异可以归因于在事务中，如果我们已经开始了`MULTI`命令，并且仍在排队命令的过程中（也就是说，我们还没有给服务器`EXEC`请求），那么任何其他客户端仍然可以进来并发出请求，并且响应将发送给其他客户端。一旦客户端发出`EXEC`命令，那么所有其他客户端在所有排队的事务命令执行时都会被阻止。

## 管道和事务

为了更好地理解，让我们分析一下在管道的情况下发生了什么。当两个不同的连接向 Redis 请求相同的资源时，我们看到了一个结果，即客户端-2 在客户端-1 仍在执行时获取了该值：

![管道和事务](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/lrn-redis/img/0123OS_04_05.jpg)

Redis 中的管道在多连接环境中

它告诉我们的是，来自第一个连接的请求（即管道命令）被堆叠为一个命令在其执行堆栈中，而来自另一个连接的命令则保留在其自己的与该连接相关的堆栈中。Redis 执行线程在这两个执行堆栈之间进行时间切片，这就是为什么当客户端-1 仍在执行时，客户端-2 能够打印一个值的原因。

让我们分析一下在事务的情况下发生了什么。同样，两个命令（事务命令和`GET`命令）被保留在它们自己的执行堆栈中，但当 Redis 执行线程给予`GET`命令时间并去读取值时，看到锁定，它被禁止读取值并被阻塞。Redis 执行线程再次回到执行事务命令，然后再次回到`GET`命令，它再次被阻塞。这个过程一直持续，直到事务命令释放了对资源的锁定，然后`GET`命令才能获取值。如果`GET`命令碰巧在事务锁定之前能够到达资源，它会得到一个空值。

请记住，Redis 在排队事务命令时不会阻止其他客户端的执行，但在执行它们时会阻止。

![管道和事务](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/lrn-redis/img/0123OS_04_06.jpg)

Redis 多连接环境中的事务

这个练习让我们了解了在管道和事务的情况下会发生什么。

# Redis 中的脚本编写

**Lua**是一种性能优越的脚本语言，解释器是用 C 编写的。Redis 提供了一种机制，通过在服务器端提供对 Lua 的支持来扩展 Redis 的功能。由于 Redis 是用 C 实现的，因此 Lua 作为服务器附加组件与 Redis 一起提供是很自然的。随 Redis 一起提供的 Lua 解释器具有有限的功能，并且随其一起提供以下库：

+   `base`库

+   `table`库

+   `string`库

+   `math`库

+   `debug`库

+   `cjson`库

+   `cmsgpack`库

### 注意

不能执行文件 I/O 和网络操作的库未包含在内，因此无法从 REDIS 中的 LUA 脚本向另一个外部系统发送消息。

在开始有趣的事情之前，最好先了解一下这种语言。LUA 有自己专门的网站，并且有大量资源可供 LUA 使用，但下一节专注于了解 Redis 的 LUA 的足够内容。

# Lua 简介

好了，到目前为止，我们都知道 LUA 是一种解释性语言，并且它在 Redis 中得到了支持。为了利用 Redis 的功能，让我们学习一些关于 LUA 的东西。LUA 中支持的类型和值如下：

+   **Nil**：Nil 是具有单个值*nil*的类型。将其与 Java 进行比较，可以将其视为*null*。

+   **布尔值**：这些将具有 true 或 false 作为值。

+   **数字**：这些表示双精度浮点数。因此，我们可以将我们的数字写为 1、1.1、2e+10 等。

+   **字符串**：这些表示字符序列，与大多数脚本和编程语言中的常见情况相同。在 LUA 中，字符串是不可变的；例如，``"Learning Redis"``和`'Learning Redis'`。LUA 提供了字符串库中的方法来查找子字符串，替换字符等。

+   **表**：这些类似于可以使用数字和字符串索引的数组，除了*nil*。

LUA 中的控制语句和循环如下：

+   `if then else`语句：与 Java 中的`if`/`else`类似，LUA 支持类似`if`/`then`/`else`的形式。以下是其代码示例：

```sql
local  myvariable = 4
local  myothervariable = 5
if myvariable >  myothervariable then
  print("4 is greater than 5".."Please add 2 dots to concatenate strings")
else
  print("4 is not greater than 5".."Please add 2 dots to concatenate strings")
end
```

+   `while`循环：这类似于 Java 中的循环，其语法类似：

```sql
local index=1
while index <= 5 do
  print("Looping done interation "..index)
  index=index+1
end
```

+   `repeat`语句：这类似于 Java 中的`do`/`while`。这将保证至少进行一次迭代：

```sql
local index=1
repeat
  print("Looping done interation "..index)
  index=index+1
until index==5 
```

+   `for`循环：这类似于 Java 中的`for`循环：

```sql
for i=1,3 do
  print("Looping in for loop ")
end
```

在执行控制语句时，LUA 中经常使用的两个关键字是`return`和`break`。以下是一个简单的示例，演示了在函数中使用 return 关键字：

```sql
function greaterThanFunction( i , j )
  if i >  j then
    print(i.." is greater than"..j)
    return true
  else
    print(i.." is lesser than"..j)
    return false
  end
end
print(greaterThanFunction(4,5))
```

接下来是一个简单的示例，演示了在函数中使用 break 关键字：

```sql
local mylist={"start","pause","stop","resume"}
function parseList ( k )
  for i=1,#mylist do
    if mylist[i] == "stop" then break end
    print(mylist[i])
  end
end
print(parseList(mylist))
```

有了对 LUA 工作原理的最基本理解，让我们在 Redis 中运行一个示例，然后继续深入了解。但在此之前，让我们了解一下 LUA 在 Redis 中的工作原理。

以下图描述了 LUA 如何与 Redis 一起工作。要了解内部发生的事情，重要的是要记住 Redis 以单线程模型工作，所有 Redis 命令和 LUA 逻辑都将按顺序执行：

![Lua 简介](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/lrn-redis/img/0123OS_04_07.jpg)

Redis 中的 LUA 脚本

当客户端将脚本发送到 Redis 服务器时，脚本会被验证其语法，并存储在 Redis 内部映射中与 SHA-1 摘要对应。SHA-1 摘要会返回给客户端。

让我们尝试在 LUA 中编写一个简单的程序，基本上是读取一个键的值，并检查该值是否等于传递的参数。如果是，则将其设置为传递的第二个参数，否则将其设置为传递给脚本的第三个参数。好的，让我们准备测试环境。打开 Redis 命令行客户端，并将`msg`键的值设置为``"Learning Redis"``：

![Lua 简介](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/lrn-redis/img/0123OS_04_08.jpg)

准备测试执行 LUA 脚本

现在`msg`的值已设置好，让我们执行以下列出的 Java 程序：

```sql
package org.learningRedis.chapter.four.luascripting;
import java.util.Arrays;
import Redis.clients.jedis.Jedis;
import Redis.clients.jedis.JedisPool;
import Redis.clients.jedis.JedisPoolConfig;
public class TestLuaScript {
  public String luaScript = Reader.read("D:\\path\\of\\file\\location\\LuaScript.txt");
  private JedisPool pool = new JedisPool(new JedisPoolConfig(), "localhost");
  Jedis jedis = null;
  public Jedis getResource() {
    jedis = pool.getResource();
    return jedis;
  }
  public void setResource(Jedis jedis){
    pool.returnResource(jedis);
  }
  public static void main(String[] args) {
    TestLuaScript test = new TestLuaScript();
    test.luaScript();
  }
  private void luaScript() {
    Jedis jedis = this.getResource();
    String result = (String) jedis.eval(luaScript,Arrays.asList("msg"),
        Arrays.asList("Learning Redis",
            "Now I am learning Lua for Redis",
            "prepare for the test again"));
    System.out.println(result);
    this.setResource(jedis);
  }
}
```

`Reader`的代码是一个简单的 Java 程序，它从文件位置读取程序：

```sql
package org.learningRedis.chapter.four.luascripting;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
public class Reader {
  public static String read(String filepath) {
    StringBuffer string = new StringBuffer();
    try (BufferedReader br = new BufferedReader(new FileReader(filepath)))
    {
      String currentline;
      while ((currentline = br.readLine()) != null) {
        string.append(currentline);
      }
    } catch (IOException e) {
      e.printStackTrace();
    } 
    return string.toString();
  }
}
```

现在让我们看一下写在文件`LuaScript.txt`中的 LUA 脚本，我们将把它传递给 Java 程序：

```sql
local data= Redis.call('GET',KEYS[1])
if data==ARGV[1] then 
  Redis.call('SET',KEYS[1],ARGV[2])
  return "The value that got sent is = "..ARGV[2]
else
  Redis.call('SET',KEYS[1],ARGV[3])
  return "The value that got sent is = "..ARGV[3]
end
```

程序的第一次运行应该给您以下结果：

```sql
The value that got sent is = Now I am learning Lua for Redis
```

程序的第二次运行应该给您以下结果：

```sql
The value that got sent is = prepare for the test again
```

因此，如果您看到如前面的代码中所示的消息打印，那么您实际上已成功在 Redis 中执行了您的第一个 LUA 程序。以下是我们从这个示例中学到的内容：

+   Redis 将 LUA 脚本视为一个函数。

+   LUA 脚本使用`Redis.call()`方法来触发 Redis 命令。

+   返回值的 Redis 命令可以赋值给本地变量。在这里，我们将值赋给一个名为`data`的变量。

+   LUA 中的数组从`1`开始索引，而不是`0`。因此，您永远不会有数组索引，比如`ARGV[0]`或`KEYS[0]`。

Redis 对 Lua 脚本引擎施加了一些进一步的限制，如下所示：

+   在 Redis 中，LUA 脚本不能有全局变量。

+   在 Redis 中，LUA 脚本不能调用诸如`MULTI`或`EXEC`之类的事务命令。

+   在 Redis 中，LUA 脚本不能使用 LUA 中的 I/O 库访问外部系统。它与外部系统通信的唯一方式是通过诸如`PUBLISH`之类的 Redis 命令。

+   不支持通过 LUA 访问系统时间的脚本。而是使用`TIME`命令，即`Redis.call('TIME')`。

+   诸如`Redis.call('TIME')`之类的函数是非确定性的，因此在`WRITE`命令之前不允许使用。

+   不允许嵌套条件，因为嵌套条件将以`END`关键字结束，这会影响外部条件，外部条件也必须以`END`结束。

以下命令支持在 Redis 中管理 LUA 脚本。让我们来看看它，并了解它们如何使用：

+   `EVAL`：此命令将处理 Redis 脚本，并响应将是执行脚本的结果。

+   `EVALSHA`：此命令将根据脚本的 SHA-1 摘要处理缓存的脚本，并响应将是执行脚本的结果。

+   `SCRIPT EXISTS`：此命令将检查脚本在脚本缓存中的存在。通过传递脚本的 SHA-1 摘要来进行此检查。

+   `SCRIPT FLUSH`：这将从脚本缓存中清除 LUA 脚本。

+   `SCRIPT KILL`：此命令将终止执行时间较长的脚本。

+   `SCRIPT LOAD`：此命令将加载脚本到缓存中，并返回脚本的 SHA-1 摘要。

## 用例 - 可靠的消息传递

通过使用 Redis 的 PUB/SUB 功能，我们可以创建一个实时消息传递框架，但问题是，如果预期的订阅者不可用，那么消息就会丢失。为了解决这个问题，我们可以借助 LUA 脚本来存储消息，如果订阅者不可用。

这个实现将根据解决方案的框架设计而有所不同，但在我们的情况下，我们将采取一种简单的方法，即每个订阅者和发布者都将就一个频道达成一致。当订阅者下线时，发布者将把消息存储在一个唯一的消息框中，以便订阅者再次上线时，它将开始消费丢失的消息，以及来自发布者的实时消息。以下图表示了我们将要遵循的步骤以实现可靠的消息传递：

![用例 - 可靠的消息传递](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/lrn-redis/img/0123OS_04_09.jpg)

简单可靠的消息传递

首先，发布者将向频道 client-1 发送消息，不知道订阅者是否处于接收模式。假设订阅者正在运行，则发布者的消息将实时消耗。然后，如果我们将订阅者关闭一段时间并发布更多消息，在我们的情况下，发布者将足够智能，以知道订阅者是否正在运行，并且感知到订阅者已关闭，它将在`MSGBOX`中存储消息。

与此同时，订阅者运行起来后，它将首先从`MSGBOX`中获取错过的消息，并将其发布给自己。发布者的代码如下：

```sql
package org.learningRedis.chapter.four.pubsub.reliable;
import java.util.Arrays;
import Redis.clients.jedis.Jedis;
import Redis.clients.jedis.JedisPool;
import Redis.clients.jedis.JedisPoolConfig;
import org.learningRedis.chapter.four.luascripting.Reader;
public class Publisher {
  public String luaScript = Reader.read("D:\\pathtoscript \\RELIABLE-MSGING.txt");
  private JedisPool pool = new JedisPool(new JedisPoolConfig(), "localhost");
  Jedis jedis = null;
  public Jedis getResource() {
    jedis = pool.getResource();
    return jedis;
  }
  public void setResource(Jedis jedis){
    pool.returnResource(jedis);
  }
  public static void main(String[] args) {
    Publisher test = new Publisher();
    test.sendingAreliableMessages();
  }
  private void sendingAreliableMessages() {
    Jedis jedis = this.getResource();
    String result = (String) jedis.eval(luaScript,Arrays.asList(""),
        Arrays.asList("{type='channel',publishto='client1',msg='"+System.currentTimeMillis()+"'}"));
    System.out.println(result);
    this.setResource(jedis);
  }
}
```

LUA 脚本的代码如下：

```sql
local payload = loadstring("return"..ARGV[1])()
local result = Redis.call("PUBLISH",payload.publishto,payload.msg)
if result==0 then
  Redis.call('SADD','MSGBOX',payload.msg)
  return 'stored messages:  '..ARGV[1]
else
  return 'consumed messages:  '..ARGV[1]
end
```

以下是 LUA 中编写的步骤的简要解释：

1.  在第一行中，我们获取消息并将其转换为表对象。在 LUA 中，数组索引从`1`开始。

1.  我们在第二行中发布消息并获取结果。结果告诉我们有多少订阅者消费了消息。

1.  如果结果等于`0`，则所有侦听器都已关闭，我们需要将其持久化。此处使用的数据类型是`Set`，随后将消息返回给服务器（此返回是可选的）。

1.  如果消息被订阅者消费，则执行`Else`中的语句。

1.  最后，我们`end`函数。（确保脚本中只有一个`end`。如果有多个`end`，Redis 中的 LUA 将无法编译。）

Redis 将在 LUA 中将代码包装为一个函数。`Subscriber`的代码如下：

```sql
package org.learningRedis.chapter.four.pubsub.reliable;
import java.util.Arrays;
import java.util.Set;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import org.learningRedis.chapter.four.luascripting.Reader;
import Redis.clients.jedis.Jedis;
import Redis.clients.jedis.JedisPubSub;
import chapter.four.pubsub.ConnectionManager;
public class SimpleMsgSubscriber {
  static Thread lostMsgWorker;
  static Thread msgWorker;
  public static void main(String[] args) {
    SimpleMsgSubscriber source = new SimpleMsgSubscriber();
  msgWorker = new Thread(source.new MsgProcessor());
lostMsgWorker = new Thread(source.new LostMsgProcessor());
  msgWorker.start();
lostMsgWorker.start();
  }
public class MsgProcessor extends JedisPubSub implements Runnable {
Jedis jedis = ConnectionManager.get();
@Override
public void run() {
  jedis.subscribe(this, "client1");
}
@Override
public void onMessage(String arg0, String arg1) {
  System.out.println("processing the msg = " + arg1);
}
@Override
public void onPMessage(String arg0, String arg1, String arg2) {
    }
@Override
public void onPSubscribe(String arg0, int arg1) {
    }
@Override
public void onPUnsubscribe(String arg0, int arg1) {
     }
@Override
public void onSubscribe(String arg0, int arg1) {
    }
@Override
public void onUnsubscribe(String arg0, int arg1) {
    }
  }
public class LostMsgProcessor implements Runnable {
    Jedis jedis = ConnectionManager.get();
    @Override
    public void run() {
      String event;
      Jedis jedis = ConnectionManager.get();
      String msg;
      while((msg=jedis.spop("MSGBOX")) != null){
        MessageHandler.push(msg);
      }
    }
  }
  public static class MessageHandler {
    static Jedis jedis = ConnectionManager.get();
        public static void push(String msg)
        {
            String luaScript = "";
            try
            {
                luaScript = read("D:\\path\\to\\file\\RELIABLE-MSGING.txt");
            }
            catch (IOException e)
            {
                e.printStackTrace();
            }
            String result = (String) jedis.eval(luaScript, Arrays.asList(""), Arrays.asList("{type='channel',publishto='client1',msg='" + msg + "'}"));
        }
        private static String read(String luaScriptPath) throws IOException
        {
            Path file = Paths.get(luaScriptPath);
            BufferedReader reader = Files.newBufferedReader(file, Charset.defaultCharset());
            StringBuilder content = new StringBuilder();
            String line = null;
            while ((line = reader.readLine()) != null)
            {
                content.append(line).append("/n");
            }
            System.out.println("Content: " + content.toString());
            return content.toString();
        }
  }
}
```

该程序有以下职责，并对程序进行了简要解释：

+   启动时应检查是否有消息在消息框中，例如`MSGBOX`，当它关闭时。如果有消息，则其工作是将其发布给自己。

+   它应该做的第二件事是监听其订阅的消息。

+   为了获得更好的性能，运行`SCRIPT LOAD`命令，该命令将加载脚本并返回 SHA-1 摘要，而不是使用`EVAL`，使用`EVALSHA`命令，其中传递相同的 SHA-1 摘要。这将防止脚本被检查语法正确性，并将直接执行。

# 连接管理

在本节中，我们将重点关注如何管理与 Redis 的连接。Redis 中提供的连接管理功能帮助我们执行以下操作：

+   `AUTH`：此命令允许请求在密码匹配配置的密码时被处理。Redis 服务器可以在`config`文件中配置`requirepass`以及密码。

+   `ECHO`：此命令将回显发送到 Redis 实例的文本。

+   `PING`：当发送到 Redis 实例时，此命令将回复`PONG`。

+   `QUIT`：此命令将终止 Redis 实例为客户端持有的连接。

+   `SELECT`：此命令有助于在 Redis 中选择要执行命令的数据库。Redis 中的数据可以有关注点的分离，通过创建一个筒仓并将数据存储在其中来实现。每个筒仓中的数据不会相互干扰，而是被隔离的。

## Redis 身份验证

通过 Redis 客户端向 Redis 服务器添加简单密码，并通过 Java 客户端进行测试，具体步骤如下所述：

1.  打开 Redis 客户端并键入`CONFIG SET requirepass "Learning Redis"`。您已将 Redis 服务器的密码设置为`"Learning Redis"`。

1.  使用 Jedis 在 Java 中编写以下程序，该程序将在不对 Redis 服务器进行身份验证的情况下执行一些简单的 getter 和 setter：

```sql
package org.learningRedis.chapter.four.auth;
import Redis.clients.jedis.Jedis;
public class TestingPassword {
  public static void main(String[] args) {
    TestingPassword test = new TestingPassword();
    test.authentication();
  }
  private void authentication() {
    Jedis jedis = new Jedis("localhost");
    jedis.set("foo", "bar");
    System.out.println(jedis.get("foo"));
  }
}
```

1.  控制台中的结果将是`ERR operation not permitted`，或者根据版本，您可能会得到`NOAUTH Authentication required`，这表明由于未在请求中传递密码，无法允许操作。为使程序工作，客户端需要传递密码进行身份验证：

```sql
package org.learningRedis.chapter.four.auth;
import Redis.clients.jedis.Jedis;
public class TestingPassword {
  public static void main(String[] args) {
    TestingPassword test = new TestingPassword();
    test.authentication();
  }
  private void authentication() {
    Jedis jedis = new Jedis("localhost");
    jedis.auth("Learning Redis");
    jedis.set("foo", "bar");
    System.out.println(jedis.get("foo"));
  }
}
```

控制台中程序的结果将是`bar`。

## Redis SELECT

Redis 提供了一种将 Redis 服务器分隔成数据库的机制。在一些数据库中，Redis 没有复杂的命名机制，而是有一个简单的过程将数据库分成单独的键空间，每个键空间由一个整数表示。

![Redis SELECT](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/lrn-redis/img/0123OS_04_10.jpg)

Redis 中的多个数据库

该程序试图将一些数据存储在数据库中，并尝试成功地从中检索数据。然后更改数据库并尝试检索相同的数据，这当然会以失败告终。请记住，为了使此代码运行，请删除之前程序中设置的任何身份验证，或者只需重新启动 Redis 服务器。

```sql
package org.learningRedis.chapter.four.selectdb;
import Redis.clients.jedis.Jedis;
public class TestSelectingDB {
  public static void main(String[] args) {
    TestSelectingDB test = new TestSelectingDB();
    test.commandSelect();
  }
  private void commandSelect() {
    Jedis jedis = new Jedis("localhost");
    jedis.select(1);
    jedis.set("msg", "Hello world");
    System.out.println(jedis.get("msg"));
    jedis.select(2);
    System.out.println(jedis.get("msg"));
  }
}
```

该程序的结果应该如下所示：

```sql
Hello world
null
```

## Redis ECHO 和 PING

Redis 提供了一些实用功能，比如`ECHO`和`PING`，可以用来检查服务器是否响应，以及响应请求所花费的时间。这可以让我们了解网络和 I/O 级别的延迟。

以下程序将演示一个示例用法，当服务器没有其他连接时，将触发`ECHO`和`PING`命令，然后当 Redis 服务器承受 100 个连接的负载时，再次触发这些命令（`ECHO`和`PING`）。没有其他连接时的结果如下：

```sql
PONG in 47 milliseconds
hi Redis  in 0 milliseconds
PONG in 0 milliseconds
hi Redis  in 0 milliseconds
PONG in 0 milliseconds
hi Redis  in 0 milliseconds
PONG in 0 milliseconds
hi Redis  in 0 milliseconds
```

当服务器上有 100 个其他连接在进行活动时，结果如下：

```sql
PONG in 16 milliseconds
hi Redis  in 16 milliseconds
PONG in 0 milliseconds
hi Redis  in 15 milliseconds
PONG in 16 milliseconds
hi Redis  in 0 milliseconds
PONG in 15 milliseconds
```

当服务器上有 50 个其他连接在进行活动时，结果如下：

```sql
PONG in 15 milliseconds
hi Redis  in 0 milliseconds
PONG in 0 milliseconds
hi Redis  in 16 milliseconds
PONG in 0 milliseconds
hi Redis  in 0 milliseconds
PONG in 16 milliseconds
hi Redis  in 0 milliseconds
PONG in 0 milliseconds
hi Redis  in 15 milliseconds
```

这证明了 Redis 服务器的活动量并不重要，而取决于 I/O 和网络资源的可用性。以下程序仅供参考：

```sql
package org.learningRedis.chapter.four.echoandping;
import Redis.clients.jedis.Jedis;
public class TestEchoAndPing {
  public static void main(String[] args) throws InterruptedException {
    TestEchoAndPing echoAndPing = new TestEchoAndPing();
    Thread thread = new Thread(new LoadGenerator());
    thread.start();
    while(true){
      Thread.currentThread().sleep(1000);
      echoAndPing.testPing();
      echoAndPing.testEcho();
    }
  }
  private void testPing() {
    long start = System.currentTimeMillis();
    Jedis jedis = new Jedis("localhost");
    System.out.println(jedis.ping() + " in " + (System.currentTimeMillis()-start) + " milliseconds");
  }
  private void testEcho() {
    long start = System.currentTimeMillis();
    Jedis jedis = new Jedis("localhost");
    System.out.println(jedis.echo("hi Redis ") + " in " + (System.currentTimeMillis()-start) + " milliseconds");
  }
}
```

`LoadGenerator`的代码如下所示，仅供参考：

```sql
package org.learningRedis.chapter.four.echoandping;
import java.util.ArrayList;
import java.util.List;
import Redis.clients.jedis.Jedis;
public class LoadGenerator implements Runnable{
  List<Thread> clients = new ArrayList<Thread>();
  public LoadGenerator() {
    for(int i=0;i<50;i++){
      clients.add(new Thread(new Sample()));
    }
  }
  @Override
  public void run() {
    for(int i=0;i<50;i++){
      clients.get(i).start();
    }
  }
  public class Sample implements Runnable{
    Jedis jedis = new Jedis("localhost");
    @Override
    public void run() {
      int x=0;
      while(!Thread.currentThread().isInterrupted()){
        jedis.sadd(Thread.currentThread().getName(), "Some text"+new Integer(x).toString());
        x++;
      }
    }
  }
}
```

我们可以通过更改线程数量并在`TestEchoAndPing`中注释线程启动代码来玩弄这个程序，并自己看到结果。结果将显示与前面代码中显示的一致性。

# 总结

在本章中，我们看到了如何使用 Redis，不仅仅作为数据存储，还可以作为管道来处理命令，这更像是批量处理。除此之外，我们还涵盖了事务、消息传递和脚本等领域。我们还看到了如何结合消息传递和脚本，并在 Redis 中创建可靠的消息传递。这使得 Redis 的能力与其他一些数据存储解决方案不同。在下一章中，我们将专注于 Redis 的数据处理能力。
