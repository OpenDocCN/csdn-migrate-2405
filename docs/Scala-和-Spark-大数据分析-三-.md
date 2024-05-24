# Scala 和 Spark 大数据分析（三）

> 原文：[`zh.annas-archive.org/md5/39EECC62E023387EE8C22CA10D1A221A`](https://zh.annas-archive.org/md5/39EECC62E023387EE8C22CA10D1A221A)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：解决大数据问题- Spark 加入派对

对正确问题的近似答案比对近似问题的精确答案更有价值。

- 约翰·图基

在本章中，您将了解数据分析和大数据；我们将看到大数据提供的挑战以及如何应对。您将了解分布式计算和函数式编程建议的方法；我们介绍 Google 的 MapReduce，Apache Hadoop，最后是 Apache Spark，并看到它们如何采用这种方法和这些技术。

简而言之，本章将涵盖以下主题：

+   数据分析简介

+   大数据简介

+   使用 Apache Hadoop 进行分布式计算

+   Apache Spark 来了

# 数据分析简介

**数据分析**是在检查数据时应用定性和定量技术的过程，目的是提供有价值的见解。使用各种技术和概念，数据分析可以提供探索数据**探索性数据分析**（**EDA**）以及对数据**验证性数据分析**（**CDA**）的结论的手段。EDA 和 CDA 是数据分析的基本概念，重要的是要理解两者之间的区别。

EDA 涉及用于探索数据的方法、工具和技术，目的是在数据中找到模式和数据各个元素之间的关系。CDA 涉及用于根据假设和统计技术或对数据的简单观察提供关于特定问题的见解或结论的方法、工具和技术。

一个快速的例子来理解这些想法是杂货店，他们要求您提供改善销售和顾客满意度以及保持运营成本低的方法。

以下是一个有各种产品过道的杂货店：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00107.jpeg)

假设杂货店的所有销售数据都存储在某个数据库中，并且您可以访问过去 3 个月的数据。通常，企业会将数据存储多年，因为您需要足够长时间的数据来建立任何假设或观察任何模式。在这个例子中，我们的目标是根据顾客购买产品的方式更好地放置各种过道中的产品。一个假设是，顾客经常购买产品，这些产品既在视线范围内，又彼此靠近。例如，如果牛奶在商店的一个角落，酸奶在商店的另一个角落，一些顾客可能会选择牛奶或酸奶中的任何一种，然后离开商店，导致业务损失。更严重的影响可能导致顾客选择另一家产品摆放更好的商店，因为他们觉得*在这家商店很难找到东西*。一旦这种感觉产生，它也会传播给朋友和家人，最终导致不良的社交影响。这种现象在现实世界中并不罕见，导致一些企业成功，而其他企业失败，尽管它们在产品和价格上似乎非常相似。

有许多方法可以解决这个问题，从客户调查到专业统计学家再到机器学习科学家。我们的方法是仅从销售交易中了解我们可以得到什么。

以下是交易可能看起来像的一个例子：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00111.jpeg)

以下是您可以作为 EDA 的一部分遵循的步骤：

1.  计算*每天购买的产品平均数量=一天内所有售出的产品总数/当天的收据总数*。

1.  重复上一步骤，为过去 1 周、1 个月和 1 个季度。

1.  尝试了解周末和工作日之间以及一天中的时间（早上、中午和晚上）是否有差异

1.  对于每种产品，创建一个所有其他产品的列表，以查看通常一起购买哪些产品（同一张收据）

1.  重复上一步骤，为 1 天、1 周、1 个月和 1 个季度。

1.  尝试通过交易数量（按降序排列）确定哪些产品应该靠近放置。

完成了前面的 6 个步骤后，我们可以尝试得出一些 CDA 的结论。

假设这是我们得到的输出：

| **商品** | **星期几** | **数量** |
| --- | --- | --- |
| 牛奶 | 星期日 | 1244 |
| 面包 | 星期一 | 245 |
| 牛奶 | 星期一 | 190 |

在这种情况下，我们可以说**牛奶**在*周末*购买更多，因此最好在周末增加牛奶产品的数量和种类。看一下下表：

| **商品 1** | **商品 2** | **数量** |
| --- | --- | --- |
| 牛奶 | 鸡蛋 | 360 |
| 面包 | 奶酪 | 335 |
| 洋葱 | 西红柿 | 310 |

在这种情况下，我们可以说**牛奶**和**鸡蛋**在一次购买中被*更多*顾客购买，接着是**面包**和**奶酪**。因此，我们建议商店重新调整通道和货架，将**牛奶**和**鸡蛋***靠近*彼此。

我们得出的两个结论是：

+   **牛奶**在*周末*购买更多，因此最好在周末增加牛奶产品的数量和种类。

+   **牛奶**和**鸡蛋**在一次购买中被*更多*顾客购买，接着是**面包**和**奶酪**。因此，我们建议商店重新调整通道和货架，将**牛奶**和**鸡蛋***靠近*彼此。

结论通常会在一段时间内进行跟踪以评估收益。如果在采纳前述两项建议 6 个月后销售额没有显着影响，那么我们只是投资于无法给您良好投资回报率（ROI）的建议。

同样，您也可以进行一些关于利润率和定价优化的分析。这就是为什么您通常会看到单个商品的成本高于购买多个相同商品的平均成本。购买一瓶洗发水 7 美元，或者两瓶洗发水 12 美元。

考虑一下您可以探索和为杂货店推荐的其他方面。例如，您能否根据这些产品对任何特定产品都没有亲和力这一事实，猜测哪些产品应该靠近结账柜台--口香糖、杂志等。

数据分析举措支持各种各样的业务用途。例如，银行和信用卡公司分析取款和消费模式以防止欺诈和身份盗用。广告公司分析网站流量以确定有高转化可能性的潜在客户。百货商店分析客户数据，以确定更好的折扣是否有助于提高销售额。手机运营商可以制定定价策略。有线电视公司不断寻找可能会流失客户的客户，除非给予一些优惠或促销价格来留住他们的客户。医院和制药公司分析数据，以提出更好的产品，并检测处方药的问题或衡量处方药的表现。

# 在数据分析过程中

数据分析应用不仅涉及数据分析。在计划任何分析之前，还需要投入时间和精力来收集、整合和准备数据，检查数据的质量，然后开发、测试和修订分析方法。一旦数据被认为准备就绪，数据分析师和科学家可以使用统计方法（如 SAS）或使用 Spark ML 的机器学习模型来探索和分析数据。数据本身由数据工程团队准备，数据质量团队检查收集的数据。数据治理也成为一个因素，以确保数据的正确收集和保护。另一个不常为人所知的角色是数据监护人，他专门研究数据到字节的理解，确切地了解数据的来源，所有发生的转换，以及业务真正需要的数据列或字段。

企业中的各种实体可能以不同的方式处理地址，例如**123 N Main St**与**123 North Main Street**。但是，我们的分析取决于获取正确的地址字段；否则上述两个地址将被视为不同，我们的分析将无法达到相同的准确性。

分析过程始于根据分析师可能需要的数据仓库中收集数据，收集组织中各种类型的数据（销售、营销、员工、工资单、人力资源等）。数据监护人和治理团队在这里非常重要，以确保收集正确的数据，并且任何被视为机密或私人的信息都不会被意外地导出，即使最终用户都是员工。

社会安全号码或完整地址可能不适合包含在分析中，因为这可能会给组织带来很多问题。

必须建立数据质量流程，以确保收集和工程化的数据是正确的，并且能够满足数据科学家的需求。在这个阶段，主要目标是发现和修复可能影响分析需求准确性的数据质量问题。常见的技术包括对数据进行概要分析和清洗，以确保数据集中的信息是一致的，并且移除任何错误和重复记录。

来自不同来源系统的数据可能需要使用各种数据工程技术进行合并、转换和规范化，例如分布式计算或 MapReduce 编程、流处理或 SQL 查询，然后存储在 Amazon S3、Hadoop 集群、NAS 或 SAN 存储设备上，或者传统的数据仓库，如 Teradata。数据准备或工程工作涉及操纵和组织数据的技术，以满足计划中的分析需求。

一旦数据准备并经过质量检查，并且可供数据科学家或分析师使用，实际的分析工作就开始了。数据科学家现在可以使用预测建模工具和语言，如 SAS、Python、R、Scala、Spark、H2O 等来构建分析模型。模型最初针对部分数据集进行运行，以测试其在*训练阶段*的准确性。在任何分析项目中，训练阶段的多次迭代是常见且预期的。在模型层面进行调整后，或者有时需要到数据监护人那里获取或修复一些被收集或准备的数据，模型的输出往往会变得越来越好。最终，当进一步调整不会明显改变结果时，我们可以认为模型已经准备好投入生产使用。

现在，模型可以针对完整数据集运行，并根据我们训练模型的方式生成结果或成果。在构建分析时所做的选择，无论是统计还是机器学习，都直接影响模型的质量和目的。你不能仅仅通过杂货销售来判断亚洲人是否比墨西哥人购买更多的牛奶，因为这需要来自人口统计数据的额外元素。同样，如果我们的分析侧重于客户体验（产品退货或换货），那么它所基于的技术和模型与我们试图专注于收入或向客户推销产品时是不同的。

您将在后面的章节中看到各种机器学习技术。

因此，分析应用可以利用多种学科、团队和技能集来实现。分析应用可以用于生成报告，甚至自动触发业务行动。例如，你可以简单地创建每天早上 8 点给所有经理发送的每日销售报告。但是，你也可以与业务流程管理应用程序或一些定制的股票交易应用程序集成，以采取行动，如在股票市场上进行买卖或警报活动。你还可以考虑接收新闻文章或社交媒体信息，以进一步影响要做出的决策。

数据可视化是数据分析的重要组成部分，当你看着大量的指标和计算时，很难理解数字。相反，人们越来越依赖商业智能工具，如 Tableau、QlikView 等，来探索和分析数据。当然，像显示全国所有优步车辆或显示纽约市供水的热力图这样的大规模可视化需要构建更多定制应用程序或专门的工具。

在各行各业的许多不同规模的组织中，管理和分析数据一直是一个挑战。企业一直在努力寻找一个实用的方法来获取有关他们的客户、产品和服务的信息。当公司只有少数客户购买少量商品时，这并不困难。随着时间的推移，市场上的公司开始增长。事情变得更加复杂。现在，我们有品牌信息和社交媒体。我们有在互联网上销售和购买的商品。我们需要提出不同的解决方案。网站开发、组织、定价、社交网络和细分；我们处理的数据有很多不同的类型，这使得处理、管理、组织和尝试从数据中获得一些见解变得更加复杂。

# 大数据介绍

在前面的部分中可以看到，数据分析包括探索和分析数据的技术、工具和方法，以产生业务的可量化结果。结果可能是简单的选择商店外观的颜色，也可能是更复杂的客户行为预测。随着企业的发展，越来越多种类的分析出现在画面中。在 20 世纪 80 年代或 90 年代，我们所能得到的只是 SQL 数据仓库中可用的数据；如今，许多外部因素都在影响企业运营的方式。

Twitter、Facebook、亚马逊、Verizon、Macy's 和 Whole Foods 都是利用数据分析来经营业务并基于数据做出许多决策的公司。想想他们可能收集的数据类型、可能收集的数据量，以及他们可能如何使用这些数据。

让我们看一下之前提到的杂货店的例子。如果商店开始扩大业务，建立数百家店铺，那么销售交易将不可避免地需要以比单一店铺多数百倍的规模进行收集和存储。但是，现在没有任何企业是独立运作的。从当地新闻、推特、yelp 评论、客户投诉、调查活动、其他商店的竞争、人口构成的变化，以及当地经济等方面都有大量信息。所有这些额外的数据都可以帮助更好地理解客户行为和收入模型。

例如，如果我们发现关于商店停车设施的负面情绪在增加，那么我们可以分析这一点，并采取纠正措施，比如提供验证停车或与城市公共交通部门协商，提供更频繁的火车或公交车，以便更好地到达。

这种不断增加的数量和多样性的数据，虽然提供了更好的分析，但也给企业 IT 组织存储、处理和分析所有数据带来了挑战。事实上，看到 TB 级别的数据并不罕见。

每天，我们创造超过 2 百万亿字节的数据（2 艾字节），据估计，超过 90%的数据仅在过去几年内生成。

**1 KB = 1024 字节**

**1 MB = 1024 KB**

**1 GB = 1024 MB**

**1 TB = 1024 GB ~ 1,000,000 MB**

**1 PB = 1024 TB ~ 1,000,000 GB ~ 1,000,000,000 MB**

**1 EB = 1024 PB ~ 1,000,000 TB ~ 1,000,000,000 GB ~ 1,000,000,000,000 MB**

自 20 世纪 90 年代以来的大量数据以及理解和理解数据的需求，催生了“大数据”这个术语。

大数据这个跨越计算机科学和统计/计量经济学的术语，可能起源于 20 世纪 90 年代中期 Silicon Graphics 的午餐桌谈话，John Mashey 在其中扮演了重要角色。

2001 年，当时是咨询公司 Meta Group Inc（后来被 Gartner 收购）的分析师的 Doug Laney 提出了 3V（多样性、速度和数量）的概念。现在，我们提到 4 个 V，而不是 3 个 V，增加了数据的真实性到 3 个 V。

# 大数据的 4 个 V

以下是用于描述大数据属性的 4 个 V。

# 数据的多样性

数据可以来自气象传感器、汽车传感器、人口普查数据、Facebook 更新、推文、交易、销售和营销。数据格式既结构化又非结构化。数据类型也可以不同；二进制、文本、JSON 和 XML。

# 数据的速度

数据可以来自数据仓库、批处理文件存档、近实时更新，或者刚刚预订的 Uber 车程的即时实时更新。

# 数据量

数据可以收集和存储一小时、一天、一个月、一年或 10 年。对于许多公司来说，数据的大小正在增长到数百 TB。

# 数据的真实性

数据可以分析出可操作的见解，但由于来自各种数据源的大量数据被分析，确保正确性和准确性证明是非常困难的。

以下是大数据的 4 个 V：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00115.jpeg)

为了理解所有数据并将数据分析应用于大数据，我们需要扩展数据分析的概念，以在更大的规模上处理大数据的 4 个 V。这不仅改变了分析数据所使用的工具、技术和方法，还改变了我们处理问题的方式。如果在 1999 年业务中使用 SQL 数据库来处理数据，现在为了处理同一业务的数据，我们将需要一个可扩展和适应大数据空间细微差别的分布式 SQL 数据库。

大数据分析应用通常包括来自内部系统和外部来源的数据，例如天气数据或第三方信息服务提供商编制的有关消费者的人口统计数据。此外，流式分析应用在大数据环境中变得常见，因为用户希望对通过 Spark 的 Spark 流模块或其他开源流处理引擎（如 Flink 和 Storm）输入 Hadoop 系统的数据进行实时分析。

早期的大数据系统大多部署在大型组织的内部，这些组织正在收集、组织和分析大量数据。但云平台供应商，如亚马逊网络服务（AWS）和微软，已经让在云中设置和管理 Hadoop 集群变得更加容易，Hadoop 供应商，如 Cloudera 和 Hortonworks，也支持它们在 AWS 和微软 Azure 云上的大数据框架分发。用户现在可以在云中启动集群，运行所需的时间，然后将其下线，使用基于使用量的定价，无需持续的软件许可证。

在大数据分析项目中可能会遇到的潜在问题包括缺乏内部分析技能以及雇佣经验丰富的数据科学家和数据工程师的高成本来填补这些空缺。

通常涉及的数据量及其多样性可能会导致数据管理问题，包括数据质量、一致性和治理；此外，在大数据架构中使用不同平台和数据存储可能会导致数据孤立。此外，将 Hadoop、Spark 和其他大数据工具集成到满足组织大数据分析需求的统一架构中对许多 IT 和分析团队来说是一个具有挑战性的任务，他们必须确定合适的技术组合，然后将各个部分组合在一起。

# 使用 Apache Hadoop 进行分布式计算

我们的世界充满了各种设备，从智能冰箱、智能手表、手机、平板电脑、笔记本电脑、机场的信息亭、向您提供现金的 ATM 等等。我们能够做一些我们几年前无法想象的事情。Instagram、Snapchat、Gmail、Facebook、Twitter 和 Pinterest 是我们现在如此习惯的一些应用程序；很难想象一天没有访问这些应用程序。

随着云计算的出现，我们能够通过几次点击在 AWS、Azure（微软）或 Google Cloud 等平台上启动数百甚至数千台机器，并利用巨大的资源实现各种业务目标。

云计算为我们引入了 IaaS、PaaS 和 SaaS 的概念，使我们能够构建和运营满足各种用例和业务需求的可扩展基础设施。

**IaaS**（基础设施即服务）-提供可靠的托管硬件，无需数据中心、电源线、空调等。

**PaaS**（平台即服务）-在 IaaS 之上，提供 Windows、Linux、数据库等托管平台。

**SaaS**（软件即服务）-在 SaaS 之上，为每个人提供 SalesForce、[Kayak.com](https://www.kayak.co.in/?ispredir=true)等托管服务。

幕后是高度可扩展的分布式计算世界，这使得存储和处理 PB（百万亿字节）数据成为可能。

1 艾克萨字节=1024 百万亿字节（5000 万部蓝光电影）

1 PB=1024 TB（50,000 部蓝光电影）

1 TB=1024 GB（50 部蓝光电影）

电影蓝光光盘的平均大小约为 20 GB

现在，分布式计算范式并不是一个真正全新的话题，几十年来一直在研究机构以及一些商业产品公司主要进行研究和追求。**大规模并行处理**（MPP）是几十年前在海洋学、地震监测和太空探索等领域使用的一种范式。很多公司如 Teradata 也实施了 MPP 平台并提供商业产品和应用。最终，谷歌、亚马逊等科技公司推动了可扩展分布式计算这一小众领域的新阶段，最终导致了伯克利大学创建了 Apache Spark。

谷歌发表了关于**Map Reduce**（MR）以及**Google File System**（GFS）的论文，将分布式计算原理带给了每个人。当然，应该给予 Doug Cutting 应有的赞誉，他通过实施谷歌白皮书中的概念并向世界介绍 Hadoop，使这一切成为可能。

Apache Hadoop 框架是用 Java 编写的开源软件框架。框架提供的两个主要领域是存储和处理。对于存储，Apache Hadoop 框架使用基于 2003 年 10 月发布的 Google 文件系统论文的 Hadoop 分布式文件系统（HDFS）。对于处理或计算，该框架依赖于基于 2004 年 12 月发布的 Google 关于 MR 的论文的 MapReduce。

MapReduce 框架从 V1（基于作业跟踪器和任务跟踪器）发展到 V2（基于 YARN）。

# Hadoop 分布式文件系统（HDFS）

HDFS 是用 Java 实现的软件文件系统，位于本地文件系统之上。HDFS 背后的主要概念是将文件分成块（通常为 128 MB），而不是将整个文件处理。这允许许多功能，例如分布、复制、故障恢复，更重要的是使用多台机器对块进行分布式处理。

块大小可以是 64 MB、128 MB、256 MB 或 512 MB，适合任何目的。对于具有 128 MB 块的 1 GB 文件，将有 1024 MB / 128 MB = 8 个块。如果考虑复制因子为 3，这将使其成为 24 个块。

HDFS 提供了具有容错和故障恢复功能的分布式存储系统。HDFS 有两个主要组件：NameNode 和 DataNode。NameNode 包含文件系统所有内容的所有元数据。DataNode 连接到 NameNode，并依赖于 NameNode 提供有关文件系统内容的所有元数据信息。如果 NameNode 不知道任何信息，DataNode 将无法将其提供给任何想要读取/写入 HDFS 的客户端。

以下是 HDFS 架构：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00120.jpeg)

NameNode 和 DataNode 都是 JVM 进程，因此任何支持 Java 的机器都可以运行 NameNode 或 DataNode 进程。只有一个 NameNode（如果计算 HA 部署，则还会有第二个 NameNode），但有 100 个或 1000 个 DataNode。

不建议拥有 1000 个 DataNode，因为来自所有 DataNode 的所有操作都会倾向于在具有大量数据密集型应用程序的真实生产环境中压倒 NameNode。

在集群中存在一个 NameNode 极大地简化了系统的架构。NameNode 是 HDFS 元数据的仲裁者和存储库，任何想要读取/写入数据的客户端都首先与 NameNode 联系以获取元数据信息。数据永远不会直接流经 NameNode，这允许 1 个 NameNode 管理 100 个 DataNode（PB 级数据）。

HDFS 支持传统的分层文件组织，具有类似于大多数其他文件系统的目录和文件。您可以创建、移动和删除文件和目录。NameNode 维护文件系统命名空间，并记录文件系统的所有更改和状态。应用程序可以指定 HDFS 应该维护的文件副本数量，这些信息也由 NameNode 存储。

HDFS 旨在以分布式方式可靠存储非常大的文件，跨大型数据节点集群中的机器进行存储。为了处理复制、容错以及分布式计算，HDFS 将每个文件存储为一系列块。

NameNode 对块的复制做出所有决定。这主要取决于集群中每个 DataNode 定期在心跳间隔处接收的块报告。块报告包含 DataNode 上所有块的列表，然后 NameNode 将其存储在其元数据存储库中。

NameNode 将所有元数据存储在内存中，并为从/写入 HDFS 的客户端提供所有请求。但是，由于这是维护有关 HDFS 的所有元数据的主节点，因此维护一致且可靠的元数据信息至关重要。如果丢失此信息，则无法访问 HDFS 上的内容。

为此，HDFS NameNode 使用称为 EditLog 的事务日志，该日志持久记录文件系统元数据发生的每个更改。创建新文件会更新 EditLog，移动文件或重命名文件，或删除文件也会如此。整个文件系统命名空间，包括块到文件的映射和文件系统属性，都存储在一个名为`FsImage`的文件中。**NameNode**也将所有内容保存在内存中。当 NameNode 启动时，它加载 EditLog 和`FsImage`，并初始化自身以设置 HDFS。

然而，DataNodes 对于 HDFS 一无所知，完全依赖于存储的数据块。DataNodes 完全依赖于 NameNode 执行任何操作。即使客户端想要连接以读取文件或写入文件，也是 NameNode 告诉客户端要连接到哪里。

# HDFS 高可用性

HDFS 是一个主从集群，其中 NameNode 是主节点，而 DataNodes 是从节点，如果不是数百，就是数千个，由主节点管理。这在集群中引入了**单点故障**（**SPOF**），因为如果主 NameNode 因某种原因而崩溃，整个集群将无法使用。HDFS 1.0 支持另一个称为**Secondary NameNode**的附加主节点，以帮助恢复集群。这是通过维护文件系统的所有元数据的副本来完成的，绝不是一个需要手动干预和维护工作的高可用系统。HDFS 2.0 通过添加对完整**高可用性**（**HA**）的支持将其提升到下一个级别。

HA 通过将两个 NameNode 设置为主备模式来工作，其中一个 NameNode 是活动的，另一个是被动的。当主 NameNode 发生故障时，被动 NameNode 将接管主节点的角色。

以下图表显示了主备 NameNode 对的部署方式：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00123.jpeg)

# HDFS 联邦

HDFS 联邦是使用多个名称节点来分布文件系统命名空间的一种方式。与最初的 HDFS 版本不同，最初的 HDFS 版本仅使用单个 NameNode 管理整个集群，随着集群规模的增长，这种方式并不那么可扩展，HDFS 联邦可以支持规模显著更大的集群，并且可以使用多个联邦名称节点水平扩展 NameNode 或名称服务。请看下面的图表：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00127.jpeg)

# HDFS 快照

Hadoop 2.0 还增加了一个新功能：对存储在数据节点上的文件系统（数据块）进行快照（只读副本和写时复制）。使用快照，可以使用 NameNode 的数据块元数据无缝地对目录进行快照。快照创建是瞬时的，不需要干预其他常规 HDFS 操作。

以下是快照在特定目录上的工作原理的示例：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00131.jpeg)

# HDFS 读取

客户端连接到 NameNode，并使用文件名询问文件。NameNode 查找文件的块位置并将其返回给客户端。然后客户端可以连接到 DataNodes 并读取所需的块。NameNode 不参与数据传输。

以下是客户端的读取请求流程。首先，客户端获取位置，然后从 DataNodes 拉取块。如果 DataNode 在中途失败，客户端将从另一个 DataNode 获取块的副本。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00264.jpeg)

# HDFS 写入

客户端连接到 NameNode，并要求 NameNode 让其写入 HDFS。NameNode 查找信息并计划块、用于存储块的 Data Nodes 以及要使用的复制策略。NameNode 不处理任何数据，只告诉客户端在哪里写入。一旦第一个 DataNode 接收到块，根据复制策略，NameNode 告诉第一个 DataNode 在哪里复制。因此，从客户端接收的 DataNode 将块发送到第二个 DataNode（应该写入块的副本所在的地方），然后第二个 DataNode 将其发送到第三个 DataNode（如果复制因子为 3）。

以下是来自客户端的写入请求的流程。首先，客户端获取位置，然后写入第一个 DataNode。接收块的 DataNode 将块复制到应该保存块副本的 DataNodes。这对从客户端写入的所有块都是如此。如果一个 DataNode 在中间失败，那么块将根据 NameNode 确定的另一个 DataNode 进行复制。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00267.jpeg)

到目前为止，我们已经看到 HDFS 使用块、NameNode 和 DataNodes 提供了分布式文件系统。一旦数据存储在 PB 规模，实际处理数据以满足业务的各种用例也变得非常重要。

MapReduce 框架是在 Hadoop 框架中创建的，用于执行分布式计算。我们将在下一节中进一步讨论这个问题。

# MapReduce 框架

**MapReduce** (**MR**)框架使您能够编写分布式应用程序，以可靠和容错的方式处理来自文件系统（如 HDFS）的大量数据。当您想要使用 MapReduce 框架处理数据时，它通过创建一个作业来运行框架以执行所需的任务。

MapReduce 作业通常通过在多个工作节点上运行**Mapper**任务并行地分割输入数据来工作。此时，无论是在 HDFS 级别发生的任何故障，还是 Mapper 任务的故障，都会自动处理以实现容错。一旦 Mapper 完成，结果就会通过网络复制到运行**Reducer**任务的其他机器上。

理解这个概念的一个简单方法是想象你和你的朋友想要把一堆水果分成盒子。为此，你想要指派每个人的任务是去处理一个原始的水果篮子（全部混在一起），并将水果分成不同的盒子。然后每个人都用同样的方法处理这个水果篮子。

最后，你最终会得到很多盒子水果，都是来自你的朋友。然后，你可以指派一个小组将相同种类的水果放在一起放进一个盒子里，称重，封箱以便运输。

以下描述了将水果篮子拿来按水果类型分类的想法：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00270.jpeg)

MapReduce 框架由一个资源管理器和多个节点管理器组成（通常节点管理器与 HDFS 的数据节点共存）。当应用程序想要运行时，客户端启动应用程序主管，然后与资源管理器协商以获取容器形式的集群资源。

容器表示分配给单个节点用于运行任务和进程的 CPU（核心）和内存。容器由节点管理器监督，并由资源管理器调度。

容器的示例：

1 核+4GB RAM

2 核+6GB RAM

4 核+20GB RAM

一些容器被分配为 Mappers，其他容器被分配为 Reducers；所有这些都由应用程序主管与资源管理器协调。这个框架被称为**Yet Another Resource Negotiator** (**YARN**)

以下是 YARN 的描述：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00276.jpeg)

展示 MapReduce 框架工作的一个经典例子是单词计数示例。以下是处理输入数据的各个阶段，首先是将输入分割到多个工作节点，最后生成单词计数的输出：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00279.jpeg)

尽管 MapReduce 框架在全球范围内非常成功，并且已被大多数公司采用，但它确实遇到了问题，主要是因为它处理数据的方式。已经出现了几种技术来尝试使 MapReduce 更易于使用，例如 Hive 和 Pig，但复杂性仍然存在。

Hadoop MapReduce 有一些限制，例如：

+   由于基于磁盘的处理而导致性能瓶颈

+   批处理无法满足所有需求

+   编程可能冗长复杂

+   任务调度速度慢，因为资源的重复利用不多

+   没有很好的实时事件处理方式

+   机器学习太慢，因为通常 ML 涉及迭代处理，而 MR 对此太慢

Hive 是 Facebook 创建的 MR 的类似 SQL 接口。Pig 是 Yahoo 创建的 MR 的脚本接口。此外，还有一些增强功能，如 Tez（Hortonworks）和 LLAP（Hive2.x），它们利用内存优化来规避 MapReduce 的限制。

在下一节中，我们将看一下 Apache Spark，它已经解决了 Hadoop 技术的一些限制。

# Apache Spark 来了

Apache Spark 是一个统一的分布式计算引擎，可跨不同的工作负载和平台进行连接。Spark 可以连接到不同的平台，并使用各种范例处理不同的数据工作负载，如 Spark 流式处理、Spark ML、Spark SQL 和 Spark GraphX。

Apache Spark 是一个快速的内存数据处理引擎，具有优雅和富有表现力的开发 API，允许数据工作者高效执行流式机器学习或 SQL 工作负载，需要快速交互式访问数据集。Apache Spark 由 Spark 核心和一组库组成。核心是分布式执行引擎，Java、Scala 和 Python API 提供了分布式应用程序开发的平台。在核心之上构建的其他库允许流式、SQL、图处理和机器学习工作负载。例如，Spark ML 专为数据科学而设计，其抽象使数据科学更容易。

Spark 提供实时流式处理、查询、机器学习和图处理。在 Apache Spark 之前，我们必须使用不同的技术来处理不同类型的工作负载，一个用于批量分析，一个用于交互式查询，一个用于实时流处理，另一个用于机器学习算法。然而，Apache Spark 可以只使用 Apache Spark 来完成所有这些工作，而不是使用不一定总是集成的多种技术。

使用 Apache Spark，可以处理各种类型的工作负载，Spark 还支持 Scala、Java、R 和 Python 作为编写客户端程序的手段。

Apache Spark 是一个开源的分布式计算引擎，相对于 MapReduce 范式具有关键优势：

+   尽可能使用内存处理

+   通用引擎用于批处理、实时工作负载

+   与 YARN 和 Mesos 兼容

+   与 HBase、Cassandra、MongoDB、HDFS、Amazon S3 和其他文件系统和数据源良好集成

Spark 是 2009 年在伯克利创建的，是构建 Mesos 的项目的结果，Mesos 是一个支持不同类型的集群计算系统的集群管理框架。看一下下表：

| 版本 | 发布日期 | 里程碑 |
| --- | --- | --- |
| 0.5 | 2012-10-07 | 非生产使用的第一个可用版本 |
| 0.6 | 2013-02-07 | 各种更改的点版本发布 |
| 0.7 | 2013-07-16 | 各种更改的点版本发布 |
| 0.8 | 2013-12-19 | 各种更改的点版本发布 |
| 0.9 | 2014-07-23 | 各种更改的点版本发布 |
| 1.0 | 2014-08-05 | 第一个生产就绪，向后兼容的发布。Spark Batch，Streaming，Shark，MLLib，GraphX |
| 1.1 | 2014-11-26 | 各种变更的点发布 |
| 1.2 | 2015-04-17 | 结构化数据，SchemaRDD（后来演变为 DataFrames） |
| 1.3 | 2015-04-17 | 提供统一的 API 来从结构化和半结构化源读取的 API |
| 1.4 | 2015-07-15 | SparkR，DataFrame API，Tungsten 改进 |
| 1.5 | 2015-11-09 | 各种变更的点发布 |
| 1.6 | 2016-11-07 | 引入数据集 DSL |
| 2.0 | 2016-11-14 | DataFrames 和 Datasets API 作为机器学习、结构化流处理、SparkR 改进的基本层。 |
| 2.1 | 2017-05-02 | 事件时间水印，机器学习，GraphX 改进 |

2.2 已于 2017-07-11 发布，其中有几项改进，特别是结构化流处理现在是 GA。

Spark 是一个分布式计算平台，具有几个特点：

+   通过简单的 API 在多个节点上透明地处理数据

+   具有弹性处理故障

+   根据需要将数据溢出到磁盘，尽管主要使用内存

+   支持 Java，Scala，Python，R 和 SQL API

+   相同的 Spark 代码可以独立运行，在 Hadoop YARN，Mesos 和云中

Scala 的特性，如隐式，高阶函数，结构化类型等，使我们能够轻松构建 DSL，并将其与语言集成。

Apache Spark 不提供存储层，并依赖于 HDFS 或 Amazon S3 等。因此，即使将 Apache Hadoop 技术替换为 Apache Spark，仍然需要 HDFS 来提供可靠的存储层。

Apache Kudu 提供了 HDFS 的替代方案，Apache Spark 和 Kudu 存储层之间已经有集成，进一步解耦了 Apache Spark 和 Hadoop 生态系统。

Hadoop 和 Apache Spark 都是流行的大数据框架，但它们实际上并不提供相同的功能。虽然 Hadoop 提供了分布式存储和 MapReduce 分布式计算框架，但 Spark 则是一个在其他技术提供的分布式数据存储上运行的数据处理框架。

Spark 通常比 MapReduce 快得多，因为它处理数据的方式不同。MapReduce 使用磁盘操作来操作拆分，而 Spark 比 MapReduce 更有效地处理数据集，Apache Spark 性能改进的主要原因是高效的堆外内存处理，而不仅仅依赖于基于磁盘的计算。

如果您的数据操作和报告需求大部分是静态的，并且可以使用批处理来满足您的需求，那么 MapReduce 的处理方式可能足够了，但是如果您需要对流数据进行分析，或者您的处理需求需要多阶段处理逻辑，那么您可能会选择 Spark。

Spark 堆栈中有三层。底层是集群管理器，可以是独立的，YARN 或 Mesos。

使用本地模式，您不需要集群管理器来处理。

在集群管理器之上的中间层是 Spark 核心层，它提供了执行任务调度和与存储交互的所有基础 API。

顶部是在 Spark 核心之上运行的模块，如 Spark SQL 提供交互式查询，Spark streaming 用于实时分析，Spark ML 用于机器学习，Spark GraphX 用于图处理。

这三层分别是：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00283.jpeg)

如前图所示，各种库（如 Spark SQL，Spark streaming，Spark ML 和 GraphX）都位于 Spark 核心之上，而 Spark 核心位于中间层。底层显示了各种集群管理器选项。

现在让我们简要地看一下每个组件：

# Spark 核心

Spark 核心是构建在其上的所有其他功能的基础通用执行引擎。Spark 核心包含运行作业所需的基本 Spark 功能，并且其他组件需要这些功能。它提供了内存计算和引用外部存储系统中的数据集，最重要的是**弹性分布式数据集**（**RDD**）。

此外，Spark 核心包含访问各种文件系统（如 HDFS、Amazon S3、HBase、Cassandra、关系数据库等）的逻辑。Spark 核心还提供了支持网络、安全、调度和数据洗牌的基本功能，以构建一个高可伸缩、容错的分布式计算平台。

我们在第六章 *开始使用 Spark - REPL*和 RDDs 以及第七章 *特殊 RDD 操作*中详细介绍了 Spark 核心。

在许多用例中，构建在 RDD 之上并由 Spark SQL 引入的 DataFrame 和数据集现在正在成为 RDD 的标准。就处理完全非结构化数据而言，RDD 仍然更灵活，但在未来，数据集 API 可能最终成为核心 API。

# Spark SQL

Spark SQL 是 Spark 核心之上的一个组件，引入了一个名为**SchemaRDD**的新数据抽象，它提供对结构化和半结构化数据的支持。Spark SQL 提供了用于操作大型分布式结构化数据集的函数，使用 Spark 和 Hive QL 支持的 SQL 子集。Spark SQL 通过 DataFrame 和数据集简化了对结构化数据的处理，作为 Tungsten 计划的一部分，它在更高的性能水平上运行。Spark SQL 还支持从各种结构化格式和数据源（文件、parquet、orc、关系数据库、Hive、HDFS、S3 等）读取和写入数据。Spark SQL 提供了一个名为**Catalyst**的查询优化框架，以优化所有操作以提高速度（与 RDD 相比，Spark SQL 快几倍）。Spark SQL 还包括一个 Thrift 服务器，可以被外部系统使用，通过经典的 JDBC 和 ODBC 协议通过 Spark SQL 查询数据。

我们在第八章 *引入一点结构 - Spark SQL*中详细介绍了 Spark SQL。

# Spark 流处理

Spark 流处理利用 Spark 核心的快速调度能力，通过从各种来源（如 HDFS、Kafka、Flume、Twitter、ZeroMQ、Kinesis 等）摄取实时流数据来执行流式分析。Spark 流处理使用数据的微批处理来处理数据，并且使用称为 DStreams 的概念，Spark 流处理可以在 RDD 上操作，将转换和操作应用于 Spark 核心 API 中的常规 RDD。Spark 流处理操作可以使用各种技术自动恢复失败。Spark 流处理可以与其他 Spark 组件结合在一个程序中，将实时处理与机器学习、SQL 和图操作统一起来。

我们在第九章 *Stream Me Up, Scotty - Spark Streaming*中详细介绍了 Spark 流处理。

此外，新的 Structured Streaming API 使得 Spark 流处理程序更类似于 Spark 批处理程序，并且还允许在流数据之上进行实时查询，这在 Spark 2.0+之前的 Spark 流处理库中是复杂的。

# Spark GraphX

GraphX 是在 Spark 之上的分布式图形处理框架。图形是由顶点和连接它们的边组成的数据结构。GraphX 提供了用于构建图形的函数，表示为图形 RDD。它提供了一个 API，用于表达可以使用 Pregel 抽象 API 模拟用户定义的图形的图形计算。它还为此抽象提供了优化的运行时。GraphX 还包含图论中最重要的算法的实现，例如 PageRank、连通组件、最短路径、SVD++等。

我们在第十章中详细介绍了 Spark Graphx，*一切都连接在一起-GraphX*。

一个名为 GraphFrames 的新模块正在开发中，它使使用基于 DataFrame 的图形处理变得更加容易。GraphX 对 RDDs 的作用类似于 GraphFrames 对 DataFrame/数据集的作用。此外，目前这与 GraphX 是分开的，并且预计在未来将支持 GraphX 的所有功能，届时可能会切换到 GraphFrames。

# Spark ML

MLlib 是在 Spark 核心之上的分布式机器学习框架，处理用于转换 RDD 形式的数据集的机器学习模型。Spark MLlib 是一个机器学习算法库，提供各种算法，如逻辑回归、朴素贝叶斯分类、支持向量机（SVMs）、决策树、随机森林、线性回归、交替最小二乘法（ALS）和 k 均值聚类。Spark ML 与 Spark 核心、Spark 流、Spark SQL 和 GraphX 集成非常好，提供了一个真正集成的平台，其中数据可以是实时的或批处理的。

我们在第十一章中详细介绍了 Spark ML，*学习机器学习-Spark MLlib 和 ML*。

此外，PySpark 和 SparkR 也可用作与 Spark 集群交互并使用 Python 和 R API 的手段。Python 和 R 的集成真正为数据科学家和机器学习建模者打开了 Spark，因为一般数据科学家使用的最常见的语言是 Python 和 R。这也是 Spark 支持 Python 集成和 R 集成的原因，以避免学习 Scala 这种新语言的成本。另一个原因是可能存在大量用 Python 和 R 编写的现有代码，如果我们可以利用其中的一些代码，那将提高团队的生产力，而不是从头开始构建所有内容。

越来越多的人开始使用 Jupyter 和 Zeppelin 等笔记本技术，这使得与 Spark 进行交互变得更加容易，特别是在 Spark ML 中，预计会有很多假设和分析。

# PySpark

PySpark 使用基于 Python 的`SparkContext`和 Python 脚本作为任务，然后使用套接字和管道来执行进程，以在基于 Java 的 Spark 集群和 Python 脚本之间进行通信。PySpark 还使用`Py4J`，这是一个在 PySpark 中集成的流行库，它让 Python 动态地与基于 Java 的 RDD 进行交互。

在运行 Spark 执行程序的所有工作节点上必须安装 Python。

以下是 PySpark 通过在 Java 进程和 Python 脚本之间进行通信的方式：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00286.jpeg)

# SparkR

`SparkR`是一个 R 包，提供了一个轻量级的前端，用于从 R 中使用 Apache Spark。SparkR 提供了一个分布式数据框架实现，支持诸如选择、过滤、聚合等操作。SparkR 还支持使用 MLlib 进行分布式机器学习。SparkR 使用基于 R 的`SparkContext`和 R 脚本作为任务，然后使用 JNI 和管道来执行进程，以在基于 Java 的 Spark 集群和 R 脚本之间进行通信。

在运行 Spark 执行程序的所有工作节点上必须安装 R。

以下是 SparkR 通过在 Java 进程和 R 脚本之间进行通信的方式：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00289.jpeg)

# 总结

我们探讨了 Hadoop 和 MapReduce 框架的演变，并讨论了 YARN、HDFS 概念、HDFS 读写、关键特性以及挑战。然后，我们讨论了 Apache Spark 的演变，为什么首次创建了 Apache Spark，以及它可以为大数据分析和处理的挑战带来的价值。

最后，我们还瞥见了 Apache Spark 中的各种组件，即 Spark 核心、Spark SQL、Spark 流处理、Spark GraphX 和 Spark ML，以及 PySpark 和 SparkR 作为将 Python 和 R 语言代码与 Apache Spark 集成的手段。

现在我们已经了解了大数据分析、Hadoop 分布式计算平台的空间和演变，以及 Apache Spark 的最终发展，以及 Apache Spark 如何解决一些挑战的高层概述，我们准备开始学习 Spark 以及如何在我们的用例中使用它。

在下一章中，我们将更深入地了解 Apache Spark，并开始深入了解它的工作原理，《第六章》*开始使用 Spark - REPL 和 RDDs*。


# 第六章：开始使用 Spark - REPL 和 RDDs

“所有这些现代技术只是让人们试图一次做所有事情。”

- 比尔·沃特森

在本章中，您将了解 Spark 的工作原理；然后，您将介绍 RDDs，这是 Apache Spark 背后的基本抽象，并且您将了解它们只是暴露类似 Scala 的 API 的分布式集合。然后，您将看到如何下载 Spark 以及如何通过 Spark shell 在本地运行它。

简而言之，本章将涵盖以下主题：

+   深入了解 Apache Spark

+   Apache Spark 安装

+   介绍 RDDs

+   使用 Spark shell

+   操作和转换

+   缓存

+   加载和保存数据

# 深入了解 Apache Spark

Apache Spark 是一个快速的内存数据处理引擎，具有优雅和富有表现力的开发 API，允许数据工作者高效地执行流式机器学习或 SQL 工作负载，这些工作负载需要对数据集进行快速交互式访问。Apache Spark 由 Spark 核心和一组库组成。核心是分布式执行引擎，Java，Scala 和 Python API 提供了分布式应用程序开发的平台。

构建在核心之上的附加库允许流处理，SQL，图处理和机器学习的工作负载。例如，SparkML 专为数据科学而设计，其抽象使数据科学变得更容易。

为了计划和执行分布式计算，Spark 使用作业的概念，该作业在工作节点上使用阶段和任务执行。Spark 由驱动程序组成，该驱动程序在工作节点集群上协调执行。驱动程序还负责跟踪所有工作节点以及每个工作节点当前执行的工作。

让我们更深入地了解一下各个组件。关键组件是 Driver 和 Executors，它们都是 JVM 进程（Java 进程）：

+   **Driver**：Driver 程序包含应用程序，主程序。如果您使用 Spark shell，那就成为了 Driver 程序，并且 Driver 在整个集群中启动执行者，并且还控制任务的执行。

+   **Executor**：接下来是执行者，它们是在集群中的工作节点上运行的进程。在执行者内部，运行单个任务或计算。每个工作节点中可能有一个或多个执行者，同样，每个执行者内部可能有多个任务。当 Driver 连接到集群管理器时，集群管理器分配资源来运行执行者。

集群管理器可以是独立的集群管理器，YARN 或 Mesos。

**集群管理器**负责在形成集群的计算节点之间进行调度和资源分配。通常，这是通过具有了解和管理资源集群的管理进程来完成的，并将资源分配给请求进程，例如 Spark。我们将在接下来的章节中更深入地了解三种不同的集群管理器：独立，YARN 和 Mesos。

以下是 Spark 在高层次上的工作方式：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00292.jpeg)

Spark 程序的主要入口点称为`SparkContext`。 `SparkContext`位于**Driver**组件内部，表示与集群的连接以及运行调度器和任务分发和编排的代码。

在 Spark 2.x 中，引入了一个名为`SparkSession`的新变量。 `SparkContext`，`SQLContext`和`HiveContext`现在是`SparkSession`的成员变量。

当启动**Driver**程序时，使用`SparkContext`向集群发出命令，然后**executors**将执行指令。执行完成后，**Driver**程序完成作业。此时，您可以发出更多命令并执行更多作业。

保持和重用`SparkContext`的能力是 Apache Spark 架构的一个关键优势，与 Hadoop 框架不同，Hadoop 框架中每个`MapReduce`作业或 Hive 查询或 Pig 脚本都需要从头开始进行整个处理，而且使用昂贵的磁盘而不是内存。

`SparkContext`可用于在集群上创建 RDD、累加器和广播变量。每个 JVM/Java 进程只能有一个活动的`SparkContext`。在创建新的`SparkContext`之前，必须`stop()`活动的`SparkContext`。

**Driver**解析代码，并将字节级代码序列化传输到执行者以执行。当我们进行任何计算时，实际上是每个节点在本地级别使用内存处理进行计算。

解析代码并规划执行的过程是由**Driver**进程实现的关键方面。

以下是 Spark **Driver**如何协调整个集群上的计算：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00298.jpeg)

**有向无环图**（**DAG**）是 Spark 框架的秘密武器。**Driver**进程为您尝试使用分布式处理框架运行的代码创建任务的 DAG。然后，任务调度程序通过与**集群管理器**通信以获取资源来运行执行者，实际上按阶段和任务执行 DAG。DAG 代表一个作业，作业被分割成子集，也称为阶段，每个阶段使用一个核心作为任务执行。

一个简单作业的示例以及 DAG 如何分割成阶段和任务的示意图如下两个图示；第一个显示作业本身，第二个图表显示作业中的阶段和任务：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00301.jpeg)

以下图表将作业/DAG 分解为阶段和任务：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00304.jpeg)

阶段的数量和阶段的内容取决于操作的类型。通常，任何转换都会进入与之前相同的阶段，但每个操作（如 reduce 或 shuffle）总是创建一个新的执行阶段。任务是阶段的一部分，与在执行者上执行操作的核心直接相关。

如果您使用 YARN 或 Mesos 作为集群管理器，可以使用动态 YARN 调度程序在需要执行更多工作时增加执行者的数量，以及终止空闲执行者。

因此，Driver 管理整个执行过程的容错。一旦 Driver 完成作业，输出可以写入文件、数据库，或者简单地输出到控制台。

请记住，Driver 程序本身的代码必须完全可序列化，包括所有变量和对象。

经常看到的异常是不可序列化异常，这是由于包含来自块外部的全局变量。

因此，Driver 进程负责整个执行过程，同时监视和管理使用的资源，如执行者、阶段和任务，确保一切按计划进行，并从故障中恢复，如执行者节点上的任务故障或整个执行者节点作为整体的故障。

# Apache Spark 安装

Apache Spark 是一个跨平台框架，可以部署在 Linux、Windows 和 Mac 机器上，只要我们在机器上安装了 Java。在本节中，我们将看看如何安装 Apache Spark。

Apache Spark 可以从[`spark.apache.org/downloads.html`](http://spark.apache.org/downloads.html)下载

首先，让我们看看机器上必须可用的先决条件：

+   Java 8+（作为所有 Spark 软件都作为 JVM 进程运行，因此是必需的）

+   Python 3.4+（可选，仅在使用 PySpark 时使用）

+   R 3.1+（可选，仅在使用 SparkR 时使用）

+   Scala 2.11+（可选，仅用于编写 Spark 程序）

Spark 可以部署在三种主要的部署模式中，我们将会看到：

+   Spark 独立

+   YARN 上的 Spark

+   Mesos 上的 Spark

# Spark 独立

Spark 独立模式使用内置调度程序，不依赖于任何外部调度程序，如 YARN 或 Mesos。要在独立模式下安装 Spark，你必须将 Spark 二进制安装包复制到集群中的所有机器上。

在独立模式下，客户端可以通过 spark-submit 或 Spark shell 与集群交互。在任何情况下，Driver 都会与 Spark 主节点通信，以获取可以为此应用程序启动的工作节点。

与集群交互的多个客户端在 Worker 节点上创建自己的执行器。此外，每个客户端都将有自己的 Driver 组件。

以下是使用主节点和工作节点的独立部署 Spark：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00307.jpeg)

现在让我们下载并安装 Spark 在独立模式下使用 Linux/Mac：

1.  从链接[`spark.apache.org/downloads.html`](http://spark.apache.org/downloads.html)下载 Apache Spark：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00313.jpeg)

1.  在本地目录中解压包：

```scala
 tar -xvzf spark-2.2.0-bin-hadoop2.7.tgz

```

1.  切换到新创建的目录：

```scala
 cd spark-2.2.0-bin-hadoop2.7

```

1.  通过实施以下步骤设置`JAVA_HOME`和`SPARK_HOME`的环境变量：

1.  `JAVA_HOME`应该是你安装 Java 的地方。在我的 Mac 终端上，这是设置为：

```scala
 export JAVA_HOME=/Library/Java/JavaVirtualMachines/
                             jdk1.8.0_65.jdk/Contents/Home/

```

1.  1.  `SPARK_HOME`应该是新解压的文件夹。在我的 Mac 终端上，这是设置为：

```scala
 export SPARK_HOME= /Users/myuser/spark-2.2.0-bin-
                               hadoop2.7

```

1.  运行 Spark shell 来查看是否可以工作。如果不工作，检查`JAVA_HOME`和`SPARK_HOME`环境变量：`./bin/spark-shell`

1.  现在你将看到如下所示的 shell。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00316.jpeg)

1.  你将在最后看到 Scala/Spark shell，现在你已经准备好与 Spark 集群交互了：

```scala
 scala>

```

现在，我们有一个连接到自动设置的本地集群运行 Spark 的 Spark-shell。这是在本地机器上启动 Spark 的最快方式。然而，你仍然可以控制工作节点/执行器，并连接到任何集群（独立/YARN/Mesos）。这就是 Spark 的强大之处，它使你能够快速从交互式测试转移到集群测试，随后在大型集群上部署你的作业。无缝集成提供了许多好处，这是你无法通过 Hadoop 和其他技术实现的。

如果你想了解所有设置，可以参考官方文档[`spark.apache.org/docs/latest/`](http://spark.apache.org/docs/latest/)。

有几种启动 Spark shell 的方式，如下面的代码片段所示。我们将在后面的部分中看到更多选项，更详细地展示 Spark shell：

+   在本地机器上自动选择本地机器作为主节点的默认 shell：

```scala
 ./bin/spark-shell

```

+   在本地机器上指定本地机器为主节点并使用`n`线程的默认 shell：

```scala
 ./bin/spark-shell --master local[n]

```

+   在本地机器上连接到指定的 spark 主节点的默认 shell：

```scala
 ./bin/spark-shell --master spark://<IP>:<Port>

```

+   在本地机器上使用客户端模式连接到 YARN 集群的默认 shell：

```scala
 ./bin/spark-shell --master yarn --deploy-mode client

```

+   在本地机器上连接到 YARN 集群使用集群模式的默认 shell：

```scala
 ./bin/spark-shell --master yarn --deploy-mode cluster

```

Spark Driver 也有一个 Web UI，可以帮助你了解关于 Spark 集群、正在运行的执行器、作业和任务、环境变量和缓存的一切。当然，最重要的用途是监视作业。

在`http://127.0.0.1:4040/jobs/`上启动本地 Spark 集群的 Web UI

Web UI 中的作业选项卡如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00322.jpeg)

以下是显示集群所有执行器的选项卡：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00200.jpeg)

# Spark on YARN

在 YARN 模式下，客户端与 YARN 资源管理器通信，并获取容器来运行 Spark 执行。你可以把它看作是为你部署的一个迷你 Spark 集群。

与集群交互的多个客户端在集群节点（节点管理器）上创建自己的执行器。此外，每个客户端都将有自己的 Driver 组件。

在使用 YARN 时，Spark 可以在 YARN 客户端模式或 YARN 集群模式下运行。

# YARN 客户端模式

在 YARN 客户端模式中，驱动程序在集群外的节点上运行（通常是客户端所在的地方）。驱动程序首先联系资源管理器请求资源来运行 Spark 作业。资源管理器分配一个容器（容器零）并回应驱动程序。然后驱动程序在容器零中启动 Spark 应用程序主节点。Spark 应用程序主节点然后在资源管理器分配的容器上创建执行器。YARN 容器可以在由节点管理器控制的集群中的任何节点上。因此，所有分配都由资源管理器管理。

即使 Spark 应用程序主节点也需要与资源管理器通信，以获取后续容器来启动执行器。

以下是 Spark 的 YARN 客户端模式部署：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00203.jpeg)

# YARN 集群模式

在 YARN 集群模式中，驱动程序在集群内的节点上运行（通常是应用程序主节点所在的地方）。客户端首先联系资源管理器请求资源来运行 Spark 作业。资源管理器分配一个容器（容器零）并回应客户端。然后客户端将代码提交到集群，然后在容器零中启动驱动程序和 Spark 应用程序主节点。驱动程序与应用程序主节点一起运行，然后在资源管理器分配的容器上创建执行器。YARN 容器可以在由节点管理器控制的集群中的任何节点上。因此，所有分配都由资源管理器管理。

即使 Spark 应用程序主节点也需要与资源管理器通信，以获取后续容器来启动执行器。

以下是 Spark 的 Yarn 集群模式部署：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00206.jpeg)

在 YARN 集群模式中没有 shell 模式，因为驱动程序本身正在 YARN 中运行。

# Mesos 上的 Spark

Mesos 部署类似于 Spark 独立模式，驱动程序与 Mesos 主节点通信，然后分配所需的资源来运行执行器。与独立模式一样，驱动程序然后与执行器通信以运行作业。因此，Mesos 部署中的驱动程序首先与主节点通信，然后在所有 Mesos 从节点上保证容器的请求。

当容器分配给 Spark 作业时，驱动程序然后启动执行器，然后在执行器中运行代码。当 Spark 作业完成并且驱动程序退出时，Mesos 主节点会收到通知，并且在 Mesos 从节点上以容器的形式的所有资源都会被回收。

与集群交互的多个客户端在从节点上创建自己的执行器。此外，每个客户端都将有自己的驱动程序组件。就像 YARN 模式一样，客户端模式和集群模式都是可能的

以下是基于 Mesos 的 Spark 部署，描述了**驱动程序**连接到**Mesos 主节点**，该主节点还具有所有 Mesos 从节点上所有资源的集群管理器：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00209.jpeg)

# RDD 介绍

**弹性分布式数据集**（**RDD**）是不可变的、分布式的对象集合。Spark RDD 是具有弹性或容错性的，这使得 Spark 能够在面对故障时恢复 RDD。一旦创建，不可变性使得 RDD 一旦创建就是只读的。转换允许对 RDD 进行操作以创建新的 RDD，但原始 RDD 一旦创建就不会被修改。这使得 RDD 免受竞争条件和其他同步问题的影响。

RDD 的分布式特性是因为 RDD 只包含对数据的引用，而实际数据包含在集群中的节点上的分区中。

在概念上，RDD 是分布在集群中多个节点上的元素的分布式集合。我们可以简化 RDD 以更好地理解，将 RDD 视为分布在机器上的大型整数数组。

RDD 实际上是一个数据集，已经在集群中进行了分区，分区的数据可能来自 HDFS（Hadoop 分布式文件系统）、HBase 表、Cassandra 表、Amazon S3。

在内部，每个 RDD 都具有五个主要属性：

+   分区列表

+   计算每个分区的函数

+   对其他 RDD 的依赖列表

+   可选地，用于键-值 RDD 的分区器（例如，指定 RDD 是哈希分区的）

+   可选地，计算每个分区的首选位置列表（例如，HDFS 文件的块位置）

看一下下面的图表：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00212.jpeg)

在你的程序中，驱动程序将 RDD 对象视为分布式数据的句柄。这类似于指向数据的指针，而不是实际使用的数据，当需要时用于访问实际数据。

RDD 默认使用哈希分区器在集群中对数据进行分区。分区的数量与集群中节点的数量无关。很可能集群中的单个节点有多个数据分区。存在的数据分区数量完全取决于集群中节点的数量和数据的大小。如果你看节点上任务的执行，那么在 worker 节点上执行的执行器上的任务可能会处理同一本地节点或远程节点上可用的数据。这被称为数据的局部性，执行任务会选择尽可能本地的数据。

局部性会显著影响作业的性能。默认情况下，局部性的优先顺序可以显示为

`PROCESS_LOCAL > NODE_LOCAL > NO_PREF > RACK_LOCAL > ANY`

节点可能会得到多少分区是没有保证的。这会影响任何执行器的处理效率，因为如果单个节点上有太多分区在处理多个分区，那么处理所有分区所需的时间也会增加，超载执行器上的核心，从而减慢整个处理阶段的速度，直接减慢整个作业的速度。实际上，分区是提高 Spark 作业性能的主要调优因素之一。参考以下命令：

```scala
class RDD[T: ClassTag]

```

让我们进一步了解当我们加载数据时 RDD 会是什么样子。以下是 Spark 如何使用不同的 worker 加载数据的示例：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00218.jpeg)

无论 RDD 是如何创建的，初始 RDD 通常被称为基础 RDD，而由各种操作创建的任何后续 RDD 都是 RDD 的血统的一部分。这是另一个非常重要的方面要记住，因为容错和恢复的秘密是**Driver**维护 RDD 的血统，并且可以执行血统来恢复任何丢失的 RDD 块。

以下是一个示例，显示了作为操作结果创建的多个 RDD。我们从**Base RDD**开始，它有 24 个项目，并派生另一个 RDD **carsRDD**，其中只包含与汽车匹配的项目（3）：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00227.jpeg)

在这些操作期间，分区的数量不会改变，因为每个执行器都会在内存中应用过滤转换，生成与原始 RDD 分区对应的新 RDD 分区。

接下来，我们将看到如何创建 RDDs

# RDD 创建

RDD 是 Apache Spark 中使用的基本对象。它们是不可变的集合，代表数据集，并具有内置的可靠性和故障恢复能力。从本质上讲，RDD 在进行任何操作（如转换或动作）时会创建新的 RDD。RDD 还存储了用于从故障中恢复的血统。我们在上一章中也看到了有关如何创建 RDD 以及可以应用于 RDD 的操作的一些细节。

可以通过多种方式创建 RDD：

+   并行化集合

+   从外部源读取数据

+   现有 RDD 的转换

+   流式 API

# 并行化集合

通过在驱动程序内部的集合上调用`parallelize()`来并行化集合。当驱动程序尝试并行化集合时，它将集合分割成分区，并将数据分区分布到集群中。

以下是使用 SparkContext 和`parallelize()`函数从数字序列创建 RDD 的 RDD。`parallelize()`函数基本上将数字序列分割成分布式集合，也称为 RDD。

```scala
scala> val rdd_one = sc.parallelize(Seq(1,2,3))
rdd_one: org.apache.spark.rdd.RDD[Int] = ParallelCollectionRDD[0] at parallelize at <console>:24

scala> rdd_one.take(10)
res0: Array[Int] = Array(1, 2, 3)

```

# 从外部源读取数据

创建 RDD 的第二种方法是从外部分布式源（如 Amazon S3、Cassandra、HDFS 等）读取数据。例如，如果您从 HDFS 创建 RDD，则 Spark 集群中的各个节点都会读取 HDFS 中的分布式块。

Spark 集群中的每个节点基本上都在进行自己的输入输出操作，每个节点都独立地从 HDFS 块中读取一个或多个块。一般来说，Spark 会尽最大努力将尽可能多的 RDD 放入内存中。有能力通过在 Spark 集群中启用节点来缓存数据，以减少输入输出操作，避免重复读取操作，比如从可能远离 Spark 集群的 HDFS 块。在您的 Spark 程序中可以使用一整套缓存策略，我们将在缓存部分后面详细讨论。

以下是从文本文件加载的文本行 RDD，使用 Spark Context 和`textFile()`函数。`textFile`函数将输入数据加载为文本文件（每个换行符`\n`终止的部分成为 RDD 中的一个元素）。该函数调用还自动使用 HadoopRDD（在下一章中显示）来检测和加载所需的分区形式的数据，分布在集群中。

```scala
scala> val rdd_two = sc.textFile("wiki1.txt")
rdd_two: org.apache.spark.rdd.RDD[String] = wiki1.txt MapPartitionsRDD[8] at textFile at <console>:24

scala> rdd_two.count
res6: Long = 9

scala> rdd_two.first
res7: String = Apache Spark provides programmers with an application programming interface centered on a data structure called the resilient distributed dataset (RDD), a read-only multiset of data items distributed over a cluster of machines, that is maintained in a fault-tolerant way.

```

# 现有 RDD 的转换

RDD 本质上是不可变的；因此，可以通过对任何现有 RDD 应用转换来创建您的 RDD。过滤器是转换的一个典型例子。

以下是一个简单的整数`rdd`，通过将每个整数乘以`2`进行转换。同样，我们使用`SparkContext`和`parallelize`函数将整数序列分布为分区形式的 RDD。然后，我们使用`map()`函数将 RDD 转换为另一个 RDD，将每个数字乘以`2`。

```scala
scala> val rdd_one = sc.parallelize(Seq(1,2,3))
rdd_one: org.apache.spark.rdd.RDD[Int] = ParallelCollectionRDD[0] at parallelize at <console>:24

scala> rdd_one.take(10)
res0: Array[Int] = Array(1, 2, 3)

scala> val rdd_one_x2 = rdd_one.map(i => i * 2)
rdd_one_x2: org.apache.spark.rdd.RDD[Int] = MapPartitionsRDD[9] at map at <console>:26

scala> rdd_one_x2.take(10)
res9: Array[Int] = Array(2, 4, 6)

```

# 流式 API

RDD 也可以通过 spark streaming 创建。这些 RDD 称为离散流 RDD（DStream RDD）。

我们将在第九章中进一步讨论这个问题，*Stream Me Up, Scotty - Spark Streaming*。

在下一节中，我们将创建 RDD 并使用 Spark-Shell 探索一些操作。

# 使用 Spark shell

Spark shell 提供了一种简单的方式来执行数据的交互式分析。它还使您能够通过快速尝试各种 API 来学习 Spark API。此外，与 Scala shell 的相似性和对 Scala API 的支持还让您能够快速适应 Scala 语言构造，并更好地利用 Spark API。

Spark shell 实现了**读取-求值-打印-循环**（**REPL**）的概念，允许您通过键入要评估的代码与 shell 进行交互。然后在控制台上打印结果，无需编译即可构建可执行代码。

在安装 Spark 的目录中运行以下命令启动它：

```scala
./bin/spark-shell

```

Spark shell 启动时，会自动创建`SparkSession`和`SparkContext`对象。`SparkSession`可作为 Spark 使用，`SparkContext`可作为 sc 使用。

`spark-shell`可以通过以下片段中显示的几个选项启动（最重要的选项用粗体显示）：

```scala
./bin/spark-shell --help
Usage: ./bin/spark-shell [options]

Options:
 --master MASTER_URL spark://host:port, mesos://host:port, yarn, or local.
 --deploy-mode DEPLOY_MODE Whether to launch the driver program locally ("client") or
 on one of the worker machines inside the cluster ("cluster")
 (Default: client).
 --class CLASS_NAME Your application's main class (for Java / Scala apps).
 --name NAME A name of your application.
 --jars JARS Comma-separated list of local jars to include on the driver
 and executor classpaths.
 --packages Comma-separated list of maven coordinates of jars to include
 on the driver and executor classpaths. Will search the local
 maven repo, then maven central and any additional remote
 repositories given by --repositories. The format for the
 coordinates should be groupId:artifactId:version.
 --exclude-packages Comma-separated list of groupId:artifactId, to exclude while
 resolving the dependencies provided in --packages to avoid
 dependency conflicts.
 --repositories Comma-separated list of additional remote repositories to
 search for the maven coordinates given with --packages.
 --py-files PY_FILES Comma-separated list of .zip, .egg, or .py files to place
 on the PYTHONPATH for Python apps.
 --files FILES Comma-separated list of files to be placed in the working
 directory of each executor.

 --conf PROP=VALUE Arbitrary Spark configuration property.
 --properties-file FILE Path to a file from which to load extra properties. If not
 specified, this will look for conf/spark-defaults.conf.

 --driver-memory MEM Memory for driver (e.g. 1000M, 2G) (Default: 1024M).
 --driver-Java-options Extra Java options to pass to the driver.
 --driver-library-path Extra library path entries to pass to the driver.
 --driver-class-path Extra class path entries to pass to the driver. Note that
 jars added with --jars are automatically included in the
 classpath.

 --executor-memory MEM Memory per executor (e.g. 1000M, 2G) (Default: 1G).

 --proxy-user NAME User to impersonate when submitting the application.
 This argument does not work with --principal / --keytab.

 --help, -h Show this help message and exit.
 --verbose, -v Print additional debug output.
 --version, Print the version of current Spark.

 Spark standalone with cluster deploy mode only:
 --driver-cores NUM Cores for driver (Default: 1).

 Spark standalone or Mesos with cluster deploy mode only:
 --supervise If given, restarts the driver on failure.
 --kill SUBMISSION_ID If given, kills the driver specified.
 --status SUBMISSION_ID If given, requests the status of the driver specified.

 Spark standalone and Mesos only:
 --total-executor-cores NUM Total cores for all executors.

 Spark standalone and YARN only:
 --executor-cores NUM Number of cores per executor. (Default: 1 in YARN mode,
 or all available cores on the worker in standalone mode)

 YARN-only:
 --driver-cores NUM Number of cores used by the driver, only in cluster mode
 (Default: 1).
 --queue QUEUE_NAME The YARN queue to submit to (Default: "default").
 --num-executors NUM Number of executors to launch (Default: 2).
 If dynamic allocation is enabled, the initial number of
 executors will be at least NUM.
 --archives ARCHIVES Comma separated list of archives to be extracted into the
 working directory of each executor.
 --principal PRINCIPAL Principal to be used to login to KDC, while running on
 secure HDFS.
 --keytab KEYTAB The full path to the file that contains the keytab for the
 principal specified above. This keytab will be copied to
 the node running the Application Master via the Secure
 Distributed Cache, for renewing the login tickets and the
 delegation tokens periodically.

```

您还可以以可执行的 Java jar 的形式提交 Spark 代码，以便在集群中执行作业。通常，您在使用 shell 达到可行解决方案后才这样做。

在提交 Spark 作业到集群（本地、YARN 和 Mesos）时，请使用`./bin/spark-submit`。

以下是 Shell 命令（最重要的命令用粗体标出）：

```scala
scala> :help
All commands can be abbreviated, e.g., :he instead of :help.
:edit <id>|<line> edit history
:help [command] print this summary or command-specific help
:history [num] show the history (optional num is commands to show)
:h? <string> search the history
:imports [name name ...] show import history, identifying sources of names
:implicits [-v] show the implicits in scope
:javap <path|class> disassemble a file or class name
:line <id>|<line> place line(s) at the end of history
:load <path> interpret lines in a file
:paste [-raw] [path] enter paste mode or paste a file
:power enable power user mode
:quit exit the interpreter
:replay [options] reset the repl and replay all previous commands
:require <path> add a jar to the classpath
:reset [options] reset the repl to its initial state, forgetting all session entries
:save <path> save replayable session to a file
:sh <command line> run a shell command (result is implicitly => List[String])
:settings <options> update compiler options, if possible; see reset
:silent disable/enable automatic printing of results
:type [-v] <expr> display the type of an expression without evaluating it
:kind [-v] <expr> display the kind of expression's type
:warnings show the suppressed warnings from the most recent line which had any

```

使用 spark-shell，我们现在将一些数据加载为 RDD：

```scala
scala> val rdd_one = sc.parallelize(Seq(1,2,3))
rdd_one: org.apache.spark.rdd.RDD[Int] = ParallelCollectionRDD[0] at parallelize at <console>:24

scala> rdd_one.take(10)
res0: Array[Int] = Array(1, 2, 3)

```

如您所见，我们正在逐个运行命令。或者，我们也可以粘贴命令：

```scala
scala> :paste
// Entering paste mode (ctrl-D to finish)

val rdd_one = sc.parallelize(Seq(1,2,3))
rdd_one.take(10)

// Exiting paste mode, now interpreting.
rdd_one: org.apache.spark.rdd.RDD[Int] = ParallelCollectionRDD[10] at parallelize at <console>:26
res10: Array[Int] = Array(1, 2, 3)

```

在下一节中，我们将深入研究这些操作。

# 动作和转换

RDDs 是不可变的，每个操作都会创建一个新的 RDD。现在，你可以在 RDD 上执行的两个主要操作是**转换**和**动作**。

**转换**改变 RDD 中的元素，例如拆分输入元素、过滤元素和执行某种计算。可以按顺序执行多个转换；但是在规划期间不会执行任何操作。

对于转换，Spark 将它们添加到计算的 DAG 中，只有当驱动程序请求一些数据时，这个 DAG 才会实际执行。这被称为*延迟*评估。

延迟评估的原因是，Spark 可以查看所有的转换并计划执行，利用驱动程序对所有操作的理解。例如，如果筛选转换立即应用于其他一些转换之后，Spark 将优化执行，以便每个执行器有效地对数据的每个分区执行转换。现在，只有当 Spark 等待执行时才有可能。

**动作**是实际触发计算的操作。在遇到动作操作之前，Spark 程序内的执行计划以 DAG 的形式创建并且不执行任何操作。显然，在执行计划中可能有各种转换，但在执行动作之前什么也不会发生。

以下是对一些任意数据的各种操作的描述，我们只想删除所有的笔和自行车，只计算汽车的数量**。**每个打印语句都是一个动作，触发 DAG 执行计划中到那一点的所有转换步骤的执行，如下图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00230.jpeg)

例如，对转换的有向无环图执行计数动作会触发执行直到基本 RDD 的所有转换。如果执行了另一个动作，那么可能会发生新的执行链。这清楚地说明了为什么在有向无环图的不同阶段可以进行任何缓存，这将极大地加快程序的下一次执行。另一种优化执行的方式是通过重用上一次执行的洗牌文件。

另一个例子是 collect 动作，它从所有节点收集或拉取所有数据到驱动程序。在调用 collect 时，您可以使用部分函数有选择地拉取数据。

# 转换

**转换**通过将转换逻辑应用于现有 RDD 中的每个元素，从现有 RDD 创建新的 RDD。一些转换函数涉及拆分元素、过滤元素和执行某种计算。可以按顺序执行多个转换。但是，在规划期间不会执行任何操作。

转换可以分为四类，如下所示。

# 通用转换

**通用转换**是处理大多数通用用例的转换函数，将转换逻辑应用于现有的 RDD 并生成新的 RDD。聚合、过滤等常见操作都称为通用转换。

通用转换函数的示例包括：

+   `map`

+   `filter`

+   `flatMap`

+   `groupByKey`

+   `sortByKey`

+   `combineByKey`

# 数学/统计转换

数学或统计转换是处理一些统计功能的转换函数，通常对现有的 RDD 应用一些数学或统计操作，生成一个新的 RDD。抽样是一个很好的例子，在 Spark 程序中经常使用。

此类转换的示例包括：

+   `sampleByKey`

+   ``randomSplit``

# 集合理论/关系转换

集合理论/关系转换是处理数据集的连接和其他关系代数功能（如`cogroup`）的转换函数。这些函数通过将转换逻辑应用于现有的 RDD 并生成新的 RDD 来工作。

此类转换的示例包括：

+   `cogroup`

+   `join`

+   `subtractByKey`

+   `fullOuterJoin`

+   `leftOuterJoin`

+   `rightOuterJoin`

# 基于数据结构的转换

基于数据结构的转换是操作 RDD 的基础数据结构，即 RDD 中的分区的转换函数。在这些函数中，您可以直接在分区上工作，而不直接触及 RDD 内部的元素/数据。这些在任何 Spark 程序中都是必不可少的，超出了简单程序的范围，您需要更多地控制分区和分区在集群中的分布。通常，通过根据集群状态和数据大小以及确切的用例要求重新分配数据分区，可以实现性能改进。

此类转换的示例包括：

+   `partitionBy`

+   `repartition`

+   `zipwithIndex`

+   `coalesce`

以下是最新 Spark 2.1.1 中可用的转换函数列表：

| 转换 | 意义 |
| --- | --- |
| `map(func)` | 通过将源数据的每个元素传递给函数`func`来返回一个新的分布式数据集。 |
| `filter(func)` | 返回一个由源数据集中 func 返回 true 的元素组成的新数据集。 |
| `flatMap(func)` | 类似于 map，但每个输入项可以映射到 0 个或多个输出项（因此`func`应返回`Seq`而不是单个项）。 |
| `mapPartitions(func)` | 类似于 map，但在 RDD 的每个分区（块）上单独运行，因此当在类型为`T`的 RDD 上运行时，`func`必须是`Iterator<T> => Iterator<U>`类型。 |
| `mapPartitionsWithIndex(func)` | 类似于`mapPartitions`，但还为`func`提供一个整数值，表示分区的索引，因此当在类型为`T`的 RDD 上运行时，`func`必须是`(Int, Iterator<T>) => Iterator<U>`类型。 |
| `sample(withReplacement, fraction, seed)` | 使用给定的随机数生成器种子，对数据的一部分进行抽样，可以有或没有替换。 |
| `union(otherDataset)` | 返回一个包含源数据集和参数中元素并集的新数据集。 |
| `intersection(otherDataset)` | 返回一个包含源数据集和参数中元素交集的新 RDD。 |
| `distinct([numTasks]))` | 返回一个包含源数据集的不同元素的新数据集。 |

| `groupByKey([numTasks])` | 当在`(K, V)`对的数据集上调用时，返回一个`(K, Iterable<V>)`对的数据集。注意：如果要对每个键执行聚合（例如求和或平均值），使用`reduceByKey`或`aggregateByKey`将获得更好的性能。

注意：默认情况下，输出中的并行级别取决于父 RDD 的分区数。您可以传递一个可选的`numTasks`参数来设置不同数量的任务。|

| reduceByKey(func, [numTasks]) | 当在`(K, V)`对的数据集上调用时，返回一个`(K, V)`对的数据集，其中每个键的值使用给定的`reduce`函数`func`进行聚合，`func`必须是`(V,V) => V`类型。与`groupByKey`一样，通过可选的第二个参数可以配置 reduce 任务的数量。 |
| --- | --- |
| `aggregateByKey(zeroValue)(seqOp, combOp, [numTasks])` | 当在`(K, V)`对的数据集上调用时，返回使用给定的组合函数和中性“零”值对每个键的值进行聚合的`(K, U)`对的数据集。允许聚合值类型与输入值类型不同，同时避免不必要的分配。与`groupByKey`一样，通过可选的第二个参数可以配置减少任务的数量。 |
| `sortByKey([ascending], [numTasks])` | 当在实现有序的`(K, V)`对的数据集上调用时，返回按键按升序或降序排序的`(K, V)`对的数据集，如布尔值升序参数中指定的那样。 |
| `join(otherDataset, [numTasks])` | 当在类型为`(K, V)`和`(K, W)`的数据集上调用时，返回每个键的所有元素对的`(K, (V, W))`对的数据集。通过`leftOuterJoin`、`rightOuterJoin`和`fullOuterJoin`支持外连接。 |
| `cogroup(otherDataset, [numTasks])` | 当在类型为`(K, V)`和`(K, W)`的数据集上调用时，返回`(K, (Iterable<V>, Iterable<W>))`元组的数据集。此操作也称为`groupWith`。 |
| `cartesian(otherDataset)` | 当在类型为`T`和`U`的数据集上调用时，返回`(T, U)`对的数据集（所有元素的所有对）。 |
| `pipe(command, [envVars])` | 将 RDD 的每个分区通过 shell 命令（例如 Perl 或 bash 脚本）进行管道传输。RDD 元素被写入进程的`stdin`，并且输出到其`stdout`的行将作为字符串的 RDD 返回。 |
| `coalesce(numPartitions)` | 将 RDD 中的分区数减少到`numPartitions`。在筛选大型数据集后更有效地运行操作时非常有用。 |
| `repartition(numPartitions)` | 随机重排 RDD 中的数据，以创建更多或更少的分区并在它们之间平衡。这总是通过网络洗牌所有数据。 |
| `repartitionAndSortWithinPartitions(partitioner)` | 根据给定的分区器重新分区 RDD，并在每个生成的分区内按其键对记录进行排序。这比调用`repartition`然后在每个分区内排序更有效，因为它可以将排序推入洗牌机制中。 |

我们将说明最常见的转换：

# map 函数

`map`将转换函数应用于输入分区，以生成输出 RDD 中的输出分区。

如下面的代码片段所示，这是我们如何将文本文件的 RDD 映射到文本行的长度的 RDD：

```scala
scala> val rdd_two = sc.textFile("wiki1.txt")
rdd_two: org.apache.spark.rdd.RDD[String] = wiki1.txt MapPartitionsRDD[8] at textFile at <console>:24

scala> rdd_two.count
res6: Long = 9

scala> rdd_two.first
res7: String = Apache Spark provides programmers with an application programming interface centered on a data structure called the resilient distributed dataset (RDD), a read-only multiset of data items distributed over a cluster of machines, that is maintained in a fault-tolerant way.

scala> val rdd_three = rdd_two.map(line => line.length)
res12: org.apache.spark.rdd.RDD[Int] = MapPartitionsRDD[11] at map at <console>:2

scala> rdd_three.take(10)
res13: Array[Int] = Array(271, 165, 146, 138, 231, 159, 159, 410, 281)

```

下图解释了`map()`的工作原理。您可以看到 RDD 的每个分区都会在新的 RDD 中产生一个新的分区，从而在 RDD 的所有元素上应用转换：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00236.jpeg)

# flatMap 函数

`flatMap()`将转换函数应用于输入分区，以生成输出 RDD 中的输出分区，就像`map()`函数一样。但是，`flatMap()`还会展平输入 RDD 元素中的任何集合。

```scala
flatMap() on a RDD of a text file to convert the lines in the text to a RDD containing the individual words. We also show map() called on the same RDD before flatMap() is called just to show the difference in behavior:
```

```scala
scala> val rdd_two = sc.textFile("wiki1.txt")
rdd_two: org.apache.spark.rdd.RDD[String] = wiki1.txt MapPartitionsRDD[8] at textFile at <console>:24

scala> rdd_two.count
res6: Long = 9

scala> rdd_two.first
res7: String = Apache Spark provides programmers with an application programming interface centered on a data structure called the resilient distributed dataset (RDD), a read-only multiset of data items distributed over a cluster of machines, that is maintained in a fault-tolerant way.

scala> val rdd_three = rdd_two.map(line => line.split(" "))
rdd_three: org.apache.spark.rdd.RDD[Array[String]] = MapPartitionsRDD[16] at map at <console>:26

scala> rdd_three.take(1)
res18: Array[Array[String]] = Array(Array(Apache, Spark, provides, programmers, with, an, application, programming, interface, centered, on, a, data, structure, called, the, resilient, distributed, dataset, (RDD),, a, read-only, multiset, of, data, items, distributed, over, a, cluster, of, machines,, that, is, maintained, in, a, fault-tolerant, way.)

scala> val rdd_three = rdd_two.flatMap(line => line.split(" "))
rdd_three: org.apache.spark.rdd.RDD[String] = MapPartitionsRDD[17] at flatMap at <console>:26

scala> rdd_three.take(10)
res19: Array[String] = Array(Apache, Spark, provides, programmers, with, an, application, programming, interface, centered)

```

下图解释了`flatMap()`的工作原理。您可以看到 RDD 的每个分区都会在新的 RDD 中产生一个新的分区，从而在 RDD 的所有元素上应用转换：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00239.jpeg)

# filter 函数

`filter` 将转换函数应用于输入分区，以生成输出 RDD 中的过滤后的输出分区。

```scala
Spark:
```

```scala
scala> val rdd_two = sc.textFile("wiki1.txt")
rdd_two: org.apache.spark.rdd.RDD[String] = wiki1.txt MapPartitionsRDD[8] at textFile at <console>:24

scala> rdd_two.count
res6: Long = 9

scala> rdd_two.first
res7: String = Apache Spark provides programmers with an application programming interface centered on a data structure called the resilient distributed dataset (RDD), a read-only multiset of data items distributed over a cluster of machines, that is maintained in a fault-tolerant way.

scala> val rdd_three = rdd_two.filter(line => line.contains("Spark"))
rdd_three: org.apache.spark.rdd.RDD[String] = MapPartitionsRDD[20] at filter at <console>:26

scala>rdd_three.count
res20: Long = 5

```

下图解释了`filter`的工作原理。您可以看到 RDD 的每个分区都会在新的 RDD 中产生一个新的分区，从而在 RDD 的所有元素上应用过滤转换。

请注意，分区不会改变，应用筛选时有些分区可能也是空的

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00242.jpeg)

# coalesce

`coalesce`将转换函数应用于输入分区，以将输入分区合并为输出 RDD 中的较少分区。

如下面的代码片段所示，这是我们如何将所有分区合并为单个分区：

```scala
scala> val rdd_two = sc.textFile("wiki1.txt")
rdd_two: org.apache.spark.rdd.RDD[String] = wiki1.txt MapPartitionsRDD[8] at textFile at <console>:24

scala> rdd_two.partitions.length
res21: Int = 2

scala> val rdd_three = rdd_two.coalesce(1)
rdd_three: org.apache.spark.rdd.RDD[String] = CoalescedRDD[21] at coalesce at <console>:26

scala> rdd_three.partitions.length
res22: Int = 1

```

以下图表解释了`coalesce`的工作原理。您可以看到，从原始 RDD 创建了一个新的 RDD，基本上通过根据需要组合它们来减少分区的数量：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00248.jpeg)

# 重新分区

`repartition`将`transformation`函数应用于输入分区，以将输入重新分区为输出 RDD 中的更少或更多的输出分区。

如下面的代码片段所示，这是我们如何将文本文件的 RDD 映射到具有更多分区的 RDD：

```scala
scala> val rdd_two = sc.textFile("wiki1.txt")
rdd_two: org.apache.spark.rdd.RDD[String] = wiki1.txt MapPartitionsRDD[8] at textFile at <console>:24

scala> rdd_two.partitions.length
res21: Int = 2

scala> val rdd_three = rdd_two.repartition(5)
rdd_three: org.apache.spark.rdd.RDD[String] = MapPartitionsRDD[25] at repartition at <console>:26

scala> rdd_three.partitions.length
res23: Int = 5

```

以下图表解释了`repartition`的工作原理。您可以看到，从原始 RDD 创建了一个新的 RDD，基本上通过根据需要组合/拆分分区来重新分配分区：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00254.jpeg)

# 动作

动作触发到目前为止构建的所有转换的整个**DAG**（**有向无环图**）通过运行代码块和函数来实现。现在，所有操作都按照 DAG 指定的方式执行。

有两种类型的动作操作：

+   **驱动程序**：一种动作是驱动程序动作，例如收集计数、按键计数等。每个此类动作在远程执行器上执行一些计算，并将数据拉回驱动程序。

基于驱动程序的动作存在一个问题，即对大型数据集的操作可能会轻松地压倒驱动程序上可用的内存，从而使应用程序崩溃，因此应谨慎使用涉及驱动程序的动作

+   **分布式**：另一种动作是分布式动作，它在集群中的节点上执行。这种分布式动作的示例是`saveAsTextfile`。由于操作的理想分布式性质，这是最常见的动作操作。

以下是最新的 Spark 2.1.1 中可用的动作函数列表：

| 动作 | 意义 |
| --- | --- |
| `reduce(func)` | 使用函数`func`（接受两个参数并返回一个参数）聚合数据集的元素。该函数应该是可交换和可结合的，以便可以正确并行计算。 |
| `collect()` | 将数据集的所有元素作为数组返回到驱动程序。这通常在过滤或其他返回数据的操作之后非常有用，这些操作返回了数据的足够小的子集。 |
| `count()` | 返回数据集中元素的数量。 |
| `first()` | 返回数据集的第一个元素（类似于`take(1)`）。 |
| `take(n)` | 返回数据集的前`n`个元素的数组。 |
| `takeSample(withReplacement, num, [seed])` | 返回数据集的`num`个元素的随机样本数组，可替换或不可替换，可选择预先指定随机数生成器种子。 |
| `takeOrdered(n, [ordering])` | 使用它们的自然顺序或自定义比较器返回 RDD 的前`n`个元素。 |
| `saveAsTextFile(path)` | 将数据集的元素作为文本文件（或一组文本文件）写入本地文件系统、HDFS 或任何其他支持 Hadoop 的文件系统中的给定目录。Spark 将对每个元素调用`toString`以将其转换为文件中的文本行。 |
| `saveAsSequenceFile(path)`（Java 和 Scala） | 将数据集的元素作为 Hadoop SequenceFile 写入本地文件系统、HDFS 或任何其他支持 Hadoop 的文件系统中的给定路径。这适用于实现 Hadoop 的`Writable`接口的键值对 RDD。在 Scala 中，它也适用于隐式转换为`Writable`的类型（Spark 包括基本类型如`Int`、`Double`、`String`等的转换）。 |
| `saveAsObjectFile(path)`（Java 和 Scala） | 使用 Java 序列化以简单格式写入数据集的元素，然后可以使用`SparkContext.objectFile()`加载。 |
| `countByKey()` | 仅适用于类型为`(K, V)`的 RDD。返回一个`(K, Int)`对的哈希映射，其中包含每个键的计数。 |
| `foreach(func)` | 对数据集的每个元素运行函数`func`。这通常用于诸如更新累加器（[`spark.apache.org/docs/latest/programming-guide.html#accumulators`](http://spark.apache.org/docs/latest/programming-guide.html#accumulators)）或与外部存储系统交互等副作用。注意：在`foreach()`之外修改除累加器之外的变量可能导致未定义的行为。有关更多详细信息，请参见理解闭包（[`spark.apache.org/docs/latest/programming-guide.html#understanding-closures-a-nameclosureslinka`](http://spark.apache.org/docs/latest/programming-guide.html#understanding-closures-a-nameclosureslinka)）。 |

# reduce

`reduce()`将 reduce 函数应用于 RDD 中的所有元素，并将其发送到 Driver。

以下是一个示例代码，用于说明这一点。您可以使用`SparkContext`和 parallelize 函数从整数序列创建一个 RDD。然后，您可以使用 RDD 上的`reduce`函数将 RDD 中所有数字相加。

由于这是一个动作，所以一旦运行`reduce`函数，结果就会被打印出来。

下面显示了从一组小数字构建一个简单 RDD 的代码，然后在 RDD 上执行 reduce 操作：

```scala
scala> val rdd_one = sc.parallelize(Seq(1,2,3,4,5,6))
rdd_one: org.apache.spark.rdd.RDD[Int] = ParallelCollectionRDD[26] at parallelize at <console>:24

scala> rdd_one.take(10)
res28: Array[Int] = Array(1, 2, 3, 4, 5, 6)

scala> rdd_one.reduce((a,b) => a +b)
res29: Int = 21

```

以下图示是`reduce()`的说明。Driver 在执行器上运行 reduce 函数，并在最后收集结果。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00257.jpeg)

# count

`count()`简单地计算 RDD 中的元素数量并将其发送到 Driver。

以下是这个函数的一个例子。我们使用 SparkContext 和 parallelize 函数从整数序列创建了一个 RDD，然后调用 RDD 上的 count 函数来打印 RDD 中元素的数量。

```scala
scala> val rdd_one = sc.parallelize(Seq(1,2,3,4,5,6))
rdd_one: org.apache.spark.rdd.RDD[Int] = ParallelCollectionRDD[26] at parallelize at <console>:24

scala> rdd_one.count
res24: Long = 6

```

以下是`count()`的说明。Driver 要求每个执行器/任务计算任务处理的分区中元素的数量，然后在 Driver 级别将所有任务的计数相加。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00260.jpeg)

# collect

`collect()`简单地收集 RDD 中的所有元素并将其发送到 Driver。

这里展示了 collect 函数的一个例子。当你在 RDD 上调用 collect 时，Driver 会通过将 RDD 的所有元素拉到 Driver 上来收集它们。

在大型 RDD 上调用 collect 会导致 Driver 出现内存不足的问题。

下面显示了收集 RDD 的内容并显示它的代码：

```scala
scala> rdd_two.collect
res25: Array[String] = Array(Apache Spark provides programmers with an application programming interface centered on a data structure called the resilient distributed dataset (RDD), a read-only multiset of data items distributed over a cluster of machines, that is maintained in a fault-tolerant way., It was developed in response to limitations in the MapReduce cluster computing paradigm, which forces a particular linear dataflow structure on distributed programs., "MapReduce programs read input data from disk, map a function across the data, reduce the results of the map, and store reduction results on disk. ", Spark's RDDs function as a working set for distributed programs that offers a (deliberately) restricted form of distributed shared memory., The availability of RDDs facilitates t...

```

以下是`collect()`的说明。使用 collect，Driver 从所有分区中拉取 RDD 的所有元素。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00027.jpeg)

# 缓存

缓存使 Spark 能够在计算和操作之间持久保存数据。事实上，这是 Spark 中最重要的技术之一，可以加速计算，特别是在处理迭代计算时。

缓存通过尽可能多地将 RDD 存储在内存中来工作。如果内存不足，那么根据 LRU 策略会将当前存储中的数据清除。如果要缓存的数据大于可用内存，性能将下降，因为将使用磁盘而不是内存。

您可以使用`persist()`或`cache()`将 RDD 标记为已缓存

`cache()`只是`persist`(MEMORY_ONLY)的同义词

`persist`可以使用内存或磁盘或两者：

```scala
persist(newLevel: StorageLevel) 

```

以下是存储级别的可能值：

| 存储级别 | 含义 |
| --- | --- |
| `MEMORY_ONLY` | 将 RDD 存储为 JVM 中的反序列化 Java 对象。如果 RDD 不适合内存，则某些分区将不会被缓存，并且每次需要时都会在飞行中重新计算。这是默认级别。 |
| `MEMORY_AND_DISK` | 将 RDD 存储为 JVM 中的反序列化 Java 对象。如果 RDD 不适合内存，则将不适合内存的分区存储在磁盘上，并在需要时从磁盘中读取它们。 |
| `MEMORY_ONLY_SER`（Java 和 Scala） | 将 RDD 存储为序列化的 Java 对象（每个分区一个字节数组）。通常情况下，这比反序列化对象更节省空间，特别是在使用快速序列化器时，但读取时更消耗 CPU。 |
| `MEMORY_AND_DISK_SER`（Java 和 Scala） | 类似于`MEMORY_ONLY_SER`，但将不适合内存的分区溢出到磁盘，而不是每次需要时动态重新计算它们。 |
| `DISK_ONLY` | 仅将 RDD 分区存储在磁盘上。 |
| `MEMORY_ONLY_2`，`MEMORY_AND_DISK_2`等 | 与前面的级别相同，但在两个集群节点上复制每个分区。 |
| `OFF_HEAP`（实验性） | 类似于`MEMORY_ONLY_SER`，但将数据存储在堆外内存中。这需要启用堆外内存。 |

选择的存储级别取决于情况

+   如果 RDD 适合内存，则使用`MEMORY_ONLY`，因为这是执行性能最快的选项

+   尝试`MEMORY_ONLY_SER`，如果使用了可序列化对象，以使对象更小

+   除非您的计算成本很高，否则不应使用`DISK`。

+   如果可以承受额外的内存，使用复制存储以获得最佳的容错性。这将防止丢失分区的重新计算，以获得最佳的可用性。

`unpersist()`只是释放缓存的内容。

以下是使用不同类型的存储（内存或磁盘）调用`persist()`函数的示例：

```scala
scala> import org.apache.spark.storage.StorageLevel
import org.apache.spark.storage.StorageLevel

scala> rdd_one.persist(StorageLevel.MEMORY_ONLY)
res37: rdd_one.type = ParallelCollectionRDD[26] at parallelize at <console>:24

scala> rdd_one.unpersist()
res39: rdd_one.type = ParallelCollectionRDD[26] at parallelize at <console>:24

scala> rdd_one.persist(StorageLevel.DISK_ONLY)
res40: rdd_one.type = ParallelCollectionRDD[26] at parallelize at <console>:24

scala> rdd_one.unpersist()
res41: rdd_one.type = ParallelCollectionRDD[26] at parallelize at <console>:24

```

以下是缓存带来的性能改进的示例。

首先，我们将运行代码：

```scala
scala> val rdd_one = sc.parallelize(Seq(1,2,3,4,5,6))
rdd_one: org.apache.spark.rdd.RDD[Int] = ParallelCollectionRDD[0] at parallelize at <console>:24

scala> rdd_one.count
res0: Long = 6

scala> rdd_one.cache
res1: rdd_one.type = ParallelCollectionRDD[0] at parallelize at <console>:24

scala> rdd_one.count
res2: Long = 6

```

您可以使用 WebUI 查看所示的改进，如以下屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00052.jpeg)

# 加载和保存数据

将数据加载到 RDD 和将 RDD 保存到输出系统都支持多种不同的方法。我们将在本节中介绍最常见的方法。

# 加载数据

通过使用`SparkContext`可以将数据加载到 RDD 中。一些最常见的方法是：

+   `textFile`

+   `wholeTextFiles`

+   从 JDBC 数据源加载

# textFile

`textFile()`可用于将 textFiles 加载到 RDD 中，每行成为 RDD 中的一个元素。

```scala
sc.textFile(name, minPartitions=None, use_unicode=True)

```

以下是使用`textFile()`将`textfile`加载到 RDD 中的示例：

```scala
scala> val rdd_two = sc.textFile("wiki1.txt")
rdd_two: org.apache.spark.rdd.RDD[String] = wiki1.txt MapPartitionsRDD[8] at textFile at <console>:24

scala> rdd_two.count
res6: Long = 9

```

# wholeTextFiles

`wholeTextFiles()`可用于将多个文本文件加载到包含对`<filename，textOfFile>`的配对 RDD 中，表示文件名和文件的整个内容。这在加载多个小文本文件时很有用，并且与`textFile` API 不同，因为使用整个`TextFiles()`时，文件的整个内容将作为单个记录加载：

```scala
sc.wholeTextFiles(path, minPartitions=None, use_unicode=True)

```

以下是使用`wholeTextFiles()`将`textfile`加载到 RDD 中的示例：

```scala
scala> val rdd_whole = sc.wholeTextFiles("wiki1.txt")
rdd_whole: org.apache.spark.rdd.RDD[(String, String)] = wiki1.txt MapPartitionsRDD[37] at wholeTextFiles at <console>:25

scala> rdd_whole.take(10)
res56: Array[(String, String)] =
Array((file:/Users/salla/spark-2.1.1-bin-hadoop2.7/wiki1.txt,Apache Spark provides programmers with an application programming interface centered on a data structure called the resilient distributed dataset (RDD), a read-only multiset of data 

```

# 从 JDBC 数据源加载

您可以从支持**Java 数据库连接**（**JDBC**）的外部数据源加载数据。使用 JDBC 驱动程序，您可以连接到关系数据库，如 Mysql，并将表的内容加载到 Spark 中，如下面的代码片段所示：

```scala
 sqlContext.load(path=None, source=None, schema=None, **options)

```

以下是从 JDBC 数据源加载的示例：

```scala
val dbContent = sqlContext.load(source="jdbc",  url="jdbc:mysql://localhost:3306/test",  dbtable="test",  partitionColumn="id")

```

# 保存 RDD

将数据从 RDD 保存到文件系统可以通过以下方式之一完成：

+   `saveAsTextFile`

+   `saveAsObjectFile`

以下是将 RDD 保存到文本文件的示例

```scala
scala> rdd_one.saveAsTextFile("out.txt")

```

在集成 HBase、Cassandra 等时，还有许多其他加载和保存数据的方法。

# 摘要

在本章中，我们讨论了 Apache Spark 的内部工作原理，RDD 是什么，DAG 和 RDD 的血统，转换和操作。我们还看了 Apache Spark 使用独立、YARN 和 Mesos 部署的各种部署模式。我们还在本地机器上进行了本地安装，然后看了 Spark shell 以及如何与 Spark 进行交互。

此外，我们还研究了将数据加载到 RDD 中以及将 RDD 保存到外部系统以及 Spark 卓越性能的秘密武器，缓存功能以及如何使用内存和/或磁盘来优化性能。

在下一章中，我们将深入研究 RDD API 以及它在《第七章》*特殊 RDD 操作*中的全部工作原理。


# 第七章：特殊的 RDD 操作

“它应该是自动的，但实际上你必须按下这个按钮。”

- 约翰·布鲁纳

在本章中，您将了解如何根据不同的需求定制 RDD，以及这些 RDD 如何提供新的功能（和危险！）此外，我们还将研究 Spark 提供的其他有用对象，如广播变量和累加器。

简而言之，本章将涵盖以下主题：

+   RDD 的类型

+   聚合

+   分区和洗牌

+   广播变量

+   累加器

# RDD 的类型

**弹性分布式数据集**（**RDD**）是 Apache Spark 中使用的基本对象。RDD 是不可变的集合，代表数据集，并具有内置的可靠性和故障恢复能力。根据性质，RDD 在任何操作（如转换或动作）时创建新的 RDD。它们还存储血统，用于从故障中恢复。在上一章中，我们还看到了有关如何创建 RDD 以及可以应用于 RDD 的操作的一些详细信息。

以下是 RDD 血统的简单示例：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00056.jpeg)

让我们再次从一系列数字创建最简单的 RDD 开始查看：

```scala
scala> val rdd_one = sc.parallelize(Seq(1,2,3,4,5,6))
rdd_one: org.apache.spark.rdd.RDD[Int] = ParallelCollectionRDD[28] at parallelize at <console>:25

scala> rdd_one.take(100)
res45: Array[Int] = Array(1, 2, 3, 4, 5, 6)

```

前面的示例显示了整数 RDD，对 RDD 进行的任何操作都会产生另一个 RDD。例如，如果我们将每个元素乘以`3`，结果将显示在以下片段中：

```scala
scala> val rdd_two = rdd_one.map(i => i * 3)
rdd_two: org.apache.spark.rdd.RDD[Int] = MapPartitionsRDD[29] at map at <console>:27

scala> rdd_two.take(10)
res46: Array[Int] = Array(3, 6, 9, 12, 15, 18)

```

让我们再做一个操作，将每个元素加`2`，并打印所有三个 RDD：

```scala
scala> val rdd_three = rdd_two.map(i => i+2)
rdd_three: org.apache.spark.rdd.RDD[Int] = MapPartitionsRDD[30] at map at <console>:29

scala> rdd_three.take(10)
res47: Array[Int] = Array(5, 8, 11, 14, 17, 20)

```

一个有趣的事情是使用`toDebugString`函数查看每个 RDD 的血统：

```scala
scala> rdd_one.toDebugString
res48: String = (8) ParallelCollectionRDD[28] at parallelize at <console>:25 []

scala> rdd_two.toDebugString
res49: String = (8) MapPartitionsRDD[29] at map at <console>:27 []
 | ParallelCollectionRDD[28] at parallelize at <console>:25 []

scala> rdd_three.toDebugString
res50: String = (8) MapPartitionsRDD[30] at map at <console>:29 []
 | MapPartitionsRDD[29] at map at <console>:27 []
 | ParallelCollectionRDD[28] at parallelize at <console>:25 []

```

以下是在 Spark web UI 中显示的血统：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00064.jpeg)

RDD 不需要与第一个 RDD（整数）相同的数据类型。以下是一个 RDD，它写入了一个不同数据类型的元组（字符串，整数）。

```scala
scala> val rdd_four = rdd_three.map(i => ("str"+(i+2).toString, i-2))
rdd_four: org.apache.spark.rdd.RDD[(String, Int)] = MapPartitionsRDD[33] at map at <console>:31

scala> rdd_four.take(10)
res53: Array[(String, Int)] = Array((str7,3), (str10,6), (str13,9), (str16,12), (str19,15), (str22,18))

```

以下是`StatePopulation`文件的 RDD，其中每个记录都转换为`upperCase`。

```scala
scala> val upperCaseRDD = statesPopulationRDD.map(_.toUpperCase)
upperCaseRDD: org.apache.spark.rdd.RDD[String] = MapPartitionsRDD[69] at map at <console>:27

scala> upperCaseRDD.take(10)
res86: Array[String] = Array(STATE,YEAR,POPULATION, ALABAMA,2010,4785492, ALASKA,2010,714031, ARIZONA,2010,6408312, ARKANSAS,2010,2921995, CALIFORNIA,2010,37332685, COLORADO,2010,5048644, DELAWARE,2010,899816, DISTRICT OF COLUMBIA,2010,605183, FLORIDA,2010,18849098)

```

以下是前述转换的图表：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00156.jpeg)

# Pair RDD

Pair RDD 是由键值元组组成的 RDD，适用于许多用例，如聚合、排序和连接数据。键和值可以是简单类型，如整数和字符串，也可以是更复杂的类型，如案例类、数组、列表和其他类型的集合。基于键值的可扩展数据模型提供了许多优势，并且是 MapReduce 范式背后的基本概念。

通过对任何 RDD 应用转换来轻松创建`PairRDD`，将 RDD 转换为键值对的 RDD。

让我们使用`SparkContext`将`statesPopulation.csv`读入 RDD，该`SparkContext`可用作`sc`。

以下是一个基本 RDD 的示例，显示了州人口以及相同 RDD 的`PairRDD`是什么样子，将记录拆分为州和人口的元组（对）：

```scala
scala> val statesPopulationRDD = sc.textFile("statesPopulation.csv") statesPopulationRDD: org.apache.spark.rdd.RDD[String] = statesPopulation.csv MapPartitionsRDD[47] at textFile at <console>:25
 scala> statesPopulationRDD.first
res4: String = State,Year,Population

scala> statesPopulationRDD.take(5)
res5: Array[String] = Array(State,Year,Population, Alabama,2010,4785492, Alaska,2010,714031, Arizona,2010,6408312, Arkansas,2010,2921995)

scala> val pairRDD = statesPopulationRDD.map(record => (record.split(",")(0), record.split(",")(2)))
pairRDD: org.apache.spark.rdd.RDD[(String, String)] = MapPartitionsRDD[48] at map at <console>:27

scala> pairRDD.take(10)
res59: Array[(String, String)] = Array((Alabama,4785492), (Alaska,714031), (Arizona,6408312), (Arkansas,2921995), (California,37332685), (Colorado,5048644), (Delaware,899816), (District of Columbia,605183), (Florida,18849098))

```

以下是前面示例的图表，显示了 RDD 元素如何转换为`(键 - 值)`对：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00341.jpeg)

# DoubleRDD

DoubleRDD 是由一系列双精度值组成的 RDD。由于这个属性，许多统计函数可以与 DoubleRDD 一起使用。

以下是我们从一系列双精度数字创建 RDD 的 DoubleRDD 示例：

```scala
scala> val rdd_one = sc.parallelize(Seq(1.0,2.0,3.0))
rdd_one: org.apache.spark.rdd.RDD[Double] = ParallelCollectionRDD[52] at parallelize at <console>:25

scala> rdd_one.mean
res62: Double = 2.0

scala> rdd_one.min
res63: Double = 1.0

scala> rdd_one.max
res64: Double = 3.0

scala> rdd_one.stdev
res65: Double = 0.816496580927726

```

以下是 DoubleRDD 的图表，以及如何在 DoubleRDD 上运行`sum()`函数：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00371.jpeg)

# SequenceFileRDD

`SequenceFileRDD`是从 Hadoop 文件系统中的`SequenceFile`创建的格式。`SequenceFile`可以是压缩或未压缩的。

Map Reduce 进程可以使用 SequenceFiles，这是键和值的对。键和值是 Hadoop 可写数据类型，如 Text、IntWritable 等。

以下是一个`SequenceFileRDD`的示例，显示了如何写入和读取`SequenceFile`：

```scala
scala> val pairRDD = statesPopulationRDD.map(record => (record.split(",")(0), record.split(",")(2)))
pairRDD: org.apache.spark.rdd.RDD[(String, String)] = MapPartitionsRDD[60] at map at <console>:27

scala> pairRDD.saveAsSequenceFile("seqfile")

scala> val seqRDD = sc.sequenceFileString, String
seqRDD: org.apache.spark.rdd.RDD[(String, String)] = MapPartitionsRDD[62] at sequenceFile at <console>:25

scala> seqRDD.take(10)
res76: Array[(String, String)] = Array((State,Population), (Alabama,4785492), (Alaska,714031), (Arizona,6408312), (Arkansas,2921995), (California,37332685), (Colorado,5048644), (Delaware,899816), (District of Columbia,605183), (Florida,18849098))

```

以下是在前面示例中看到的**SequenceFileRDD**的图表：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00013.jpeg)

# CoGroupedRDD

`CoGroupedRDD`是一个 cogroup 其父级的 RDD。这个工作的两个父 RDD 都必须是 pairRDDs，因为 cogroup 实质上生成一个由来自两个父 RDD 的公共键和值列表组成的 pairRDD。看一下下面的代码片段：

```scala
class CoGroupedRDD[K] extends RDD[(K, Array[Iterable[_]])] 

```

以下是一个 CoGroupedRDD 的示例，我们在其中创建了两个 pairRDDs 的 cogroup，一个具有州、人口对，另一个具有州、年份对：

```scala
scala> val pairRDD = statesPopulationRDD.map(record => (record.split(",")(0), record.split(",")(2)))
pairRDD: org.apache.spark.rdd.RDD[(String, String)] = MapPartitionsRDD[60] at map at <console>:27

scala> val pairRDD2 = statesPopulationRDD.map(record => (record.split(",")(0), record.split(",")(1)))
pairRDD2: org.apache.spark.rdd.RDD[(String, String)] = MapPartitionsRDD[66] at map at <console>:27

scala> val cogroupRDD = pairRDD.cogroup(pairRDD2)
cogroupRDD: org.apache.spark.rdd.RDD[(String, (Iterable[String], Iterable[String]))] = MapPartitionsRDD[68] at cogroup at <console>:31

scala> cogroupRDD.take(10)
res82: Array[(String, (Iterable[String], Iterable[String]))] = Array((Montana,(CompactBuffer(990641, 997821, 1005196, 1014314, 1022867, 1032073, 1042520),CompactBuffer(2010, 2011, 2012, 2013, 2014, 2015, 2016))), (California,(CompactBuffer(37332685, 37676861, 38011074, 38335203, 38680810, 38993940, 39250017),CompactBuffer(2010, 2011, 2012, 2013, 2014, 2015, 2016))),

```

下面是通过为每个键创建值对的**pairRDD**和**pairRDD2**的 cogroup 的图表：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00179.jpeg)

# ShuffledRDD

`ShuffledRDD`通过键对 RDD 元素进行洗牌，以便在同一个执行器上累积相同键的值，以允许聚合或组合逻辑。一个很好的例子是看看在 PairRDD 上调用`reduceByKey()`时会发生什么：

```scala
class ShuffledRDD[K, V, C] extends RDD[(K, C)] 

```

以下是对`pairRDD`进行`reduceByKey`操作，以按州聚合记录的示例：

```scala
scala> val pairRDD = statesPopulationRDD.map(record => (record.split(",")(0), 1))
pairRDD: org.apache.spark.rdd.RDD[(String, Int)] = MapPartitionsRDD[82] at map at <console>:27

scala> pairRDD.take(5)
res101: Array[(String, Int)] = Array((State,1), (Alabama,1), (Alaska,1), (Arizona,1), (Arkansas,1))

scala> val shuffledRDD = pairRDD.reduceByKey(_+_)
shuffledRDD: org.apache.spark.rdd.RDD[(String, Int)] = ShuffledRDD[83] at reduceByKey at <console>:29

scala> shuffledRDD.take(5)
res102: Array[(String, Int)] = Array((Montana,7), (California,7), (Washington,7), (Massachusetts,7), (Kentucky,7))

```

以下图表是按键进行洗牌以将相同键（州）的记录发送到相同分区的示例：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00024.jpeg)

# UnionRDD

`UnionRDD`是两个 RDD 的并集操作的结果。Union 简单地创建一个包含来自两个 RDD 的元素的 RDD，如下面的代码片段所示：

```scala
class UnionRDDT: ClassTag extends RDDT

UnionRDD by combining the elements of the two RDDs:
```

```scala
scala> val rdd_one = sc.parallelize(Seq(1,2,3))
rdd_one: org.apache.spark.rdd.RDD[Int] = ParallelCollectionRDD[85] at parallelize at <console>:25

scala> val rdd_two = sc.parallelize(Seq(4,5,6))
rdd_two: org.apache.spark.rdd.RDD[Int] = ParallelCollectionRDD[86] at parallelize at <console>:25

scala> val rdd_one = sc.parallelize(Seq(1,2,3))
rdd_one: org.apache.spark.rdd.RDD[Int] = ParallelCollectionRDD[87] at parallelize at <console>:25

scala> rdd_one.take(10)
res103: Array[Int] = Array(1, 2, 3)

scala> val rdd_two = sc.parallelize(Seq(4,5,6))
rdd_two: org.apache.spark.rdd.RDD[Int] = ParallelCollectionRDD[88] at parallelize at <console>:25

scala> rdd_two.take(10)
res104: Array[Int] = Array(4, 5, 6)

scala> val unionRDD = rdd_one.union(rdd_two)
unionRDD: org.apache.spark.rdd.RDD[Int] = UnionRDD[89] at union at <console>:29

scala> unionRDD.take(10)
res105: Array[Int] = Array(1, 2, 3, 4, 5, 6)

```

下面的图表是两个 RDD 的并集的示例，其中来自**RDD 1**和**RDD 2**的元素被合并到一个新的 RDD **UnionRDD**中：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00305.jpeg)

# HadoopRDD

`HadoopRDD`提供了使用 Hadoop 1.x 库的 MapReduce API 从 HDFS 中读取数据的核心功能。`HadoopRDD`是默认使用的，可以在从任何文件系统加载数据到 RDD 时看到：

```scala
class HadoopRDD[K, V] extends RDD[(K, V)]

```

当从 CSV 加载州人口记录时，底层基本 RDD 实际上是`HadoopRDD`，如下面的代码片段所示：

```scala
scala> val statesPopulationRDD = sc.textFile("statesPopulation.csv")
statesPopulationRDD: org.apache.spark.rdd.RDD[String] = statesPopulation.csv MapPartitionsRDD[93] at textFile at <console>:25

scala> statesPopulationRDD.toDebugString
res110: String =
(2) statesPopulation.csv MapPartitionsRDD[93] at textFile at <console>:25 []
 | statesPopulation.csv HadoopRDD[92] at textFile at <console>:25 []

```

下面的图表是通过将文本文件从文件系统加载到 RDD 中创建的**HadoopRDD**的示例：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00032.jpeg)

# NewHadoopRDD

`NewHadoopRDD`提供了使用 Hadoop 2.x 库的新 MapReduce API 从 HDFS、HBase 表、Amazon S3 中读取数据的核心功能。`NewHadoopRDD`可以从许多不同的格式中读取数据，因此用于与多个外部系统交互。

在`NewHadoopRDD`之前，`HadoopRDD`是唯一可用的选项，它使用了 Hadoop 1.x 的旧 MapReduce API

```scala
class NewHadoopRDDK, V
extends RDD[(K, V)]

NewHadoopRDD takes an input format class, a key class, and a value class. Let's look at examples of NewHadoopRDD.
```

最简单的例子是使用 SparkContext 的`wholeTextFiles`函数创建`WholeTextFileRDD`。现在，`WholeTextFileRDD`实际上扩展了`NewHadoopRDD`，如下面的代码片段所示：

```scala
scala> val rdd_whole = sc.wholeTextFiles("wiki1.txt")
rdd_whole: org.apache.spark.rdd.RDD[(String, String)] = wiki1.txt MapPartitionsRDD[3] at wholeTextFiles at <console>:31

scala> rdd_whole.toDebugString
res9: String =
(1) wiki1.txt MapPartitionsRDD[3] at wholeTextFiles at <console>:31 []
 | WholeTextFileRDD[2] at wholeTextFiles at <console>:31 []

```

让我们看另一个例子，我们将使用`SparkContext`的`newAPIHadoopFile`函数：

```scala
import org.apache.hadoop.mapreduce.lib.input.KeyValueTextInputFormat

import org.apache.hadoop.io.Text

val newHadoopRDD = sc.newAPIHadoopFile("statesPopulation.csv", classOf[KeyValueTextInputFormat], classOf[Text],classOf[Text])

```

# 聚合

聚合技术允许您以任意方式组合 RDD 中的元素以执行一些计算。事实上，聚合是大数据分析中最重要的部分。没有聚合，我们将无法生成报告和分析，比如*按人口排名的州*，这似乎是在给定过去 200 年所有州人口的数据集时提出的一个合乎逻辑的问题。另一个更简单的例子是只需计算 RDD 中元素的数量，这要求执行器计算每个分区中的元素数量并发送给 Driver，然后将子集相加以计算 RDD 中元素的总数。

在本节中，我们的主要重点是聚合函数，用于按键收集和组合数据。正如本章前面所看到的，PairRDD 是一个(key - value)对的 RDD，其中 key 和 value 是任意的，并且可以根据用例进行自定义。

在我们的州人口示例中，PairRDD 可以是`<State，<Population，Year>>`的对，这意味着`State`被视为键，元组`<Population，Year>`被视为值。通过这种方式分解键和值可以生成诸如*每个州人口最多的年份*之类的聚合。相反，如果我们的聚合是围绕年份进行的，比如*每年人口最多的州*，我们可以使用`<Year，<State，Population>>`的`pairRDD`。

以下是从`StatePopulation`数据集生成`pairRDD`的示例代码，其中`State`作为键，`Year`也作为键：

```scala
scala> val statesPopulationRDD = sc.textFile("statesPopulation.csv")
statesPopulationRDD: org.apache.spark.rdd.RDD[String] = statesPopulation.csv MapPartitionsRDD[157] at textFile at <console>:26

scala> statesPopulationRDD.take(5)
res226: Array[String] = Array(State,Year,Population, Alabama,2010,4785492, Alaska,2010,714031, Arizona,2010,6408312, Arkansas,2010,2921995)

```

接下来，我们可以生成一个`pairRDD`，使用`State`作为键，`<Year，Population>`元组作为值，如下面的代码片段所示：

```scala
scala> val pairRDD = statesPopulationRDD.map(record => record.split(",")).map(t => (t(0), (t(1), t(2))))
pairRDD: org.apache.spark.rdd.RDD[(String, (String, String))] = MapPartitionsRDD[160] at map at <console>:28

scala> pairRDD.take(5)
res228: Array[(String, (String, String))] = Array((State,(Year,Population)), (Alabama,(2010,4785492)), (Alaska,(2010,714031)), (Arizona,(2010,6408312)), (Arkansas,(2010,2921995)))

```

如前所述，我们还可以生成一个`PairRDD`，使用`Year`作为键，`<State，Population>`元组作为值，如下面的代码片段所示：

```scala
scala> val pairRDD = statesPopulationRDD.map(record => record.split(",")).map(t => (t(1), (t(0), t(2))))
pairRDD: org.apache.spark.rdd.RDD[(String, (String, String))] = MapPartitionsRDD[162] at map at <console>:28

scala> pairRDD.take(5)
res229: Array[(String, (String, String))] = Array((Year,(State,Population)), (2010,(Alabama,4785492)), (2010,(Alaska,714031)), (2010,(Arizona,6408312)), (2010,(Arkansas,2921995)))

```

现在我们将看看如何在`<State，<Year，Population>>`的`pairRDD`上使用常见的聚合函数：

+   `groupByKey`

+   `reduceByKey`

+   `aggregateByKey`

+   `combineByKey`

# groupByKey

`groupByKey`将 RDD 中每个键的值分组为单个序列。`groupByKey`还允许通过传递分区器来控制生成的键值对 RDD 的分区。默认情况下，使用`HashPartitioner`，但可以作为参数给出自定义分区器。每个组内元素的顺序不能保证，并且每次评估结果 RDD 时甚至可能不同。

`groupByKey`是一个昂贵的操作，因为需要所有的数据洗牌。`reduceByKey`或`aggregateByKey`提供了更好的性能。我们将在本节的后面进行讨论。

`groupByKey`可以使用自定义分区器调用，也可以只使用默认的`HashPartitioner`，如下面的代码片段所示：

```scala
def groupByKey(partitioner: Partitioner): RDD[(K, Iterable[V])] 

def groupByKey(numPartitions: Int): RDD[(K, Iterable[V])] 

```

目前实现的`groupByKey`必须能够在内存中保存任何键的所有键值对。如果一个键有太多的值，可能会导致`OutOfMemoryError`。

`groupByKey`通过将分区的所有元素发送到基于分区器的分区，以便将相同键的所有键值对收集到同一分区中。完成此操作后，可以轻松进行聚合操作。

这里显示了调用`groupByKey`时发生的情况的示例：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00036.jpeg)

# reduceByKey

`groupByKey`涉及大量的数据洗牌，而`reduceByKey`倾向于通过不使用洗牌发送`PairRDD`的所有元素来提高性能，而是使用本地组合器首先在本地进行一些基本的聚合，然后像`groupByKey`一样发送结果元素。这大大减少了数据传输，因为我们不需要发送所有内容。`reduceBykey`通过使用关联和可交换的减少函数合并每个键的值。当然，首先这将

还可以在每个 mapper 上本地执行合并，然后将结果发送到 reducer。

如果您熟悉 Hadoop MapReduce，这与 MapReduce 编程中的组合器非常相似。

`reduceByKey`可以使用自定义分区器调用，也可以只使用默认的`HashPartitioner`，如下面的代码片段所示：

```scala
def reduceByKey(partitioner: Partitioner, func: (V, V) => V): RDD[(K, V)]

def reduceByKey(func: (V, V) => V, numPartitions: Int): RDD[(K, V)] 

def reduceByKey(func: (V, V) => V): RDD[(K, V)] 

```

`reduceByKey`通过将分区的所有元素发送到基于`partitioner`的分区，以便将相同键的所有键值对收集到同一分区中。但在洗牌之前，还进行本地聚合，减少要洗牌的数据。完成此操作后，可以在最终分区中轻松进行聚合操作。

下图是调用`reduceBykey`时发生的情况的示例：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00039.jpeg)

# aggregateByKey

`aggregateByKey`与`reduceByKey`非常相似，只是`aggregateByKey`允许更灵活和定制如何在分区内和分区之间进行聚合，以允许更复杂的用例，例如在一个函数调用中生成所有`<Year, Population>`对的列表以及每个州的总人口。

`aggregateByKey`通过使用给定的组合函数和中性初始/零值对每个键的值进行聚合。

这个函数可以返回一个不同的结果类型`U`，而不是这个 RDD`V`中的值的类型，这是最大的区别。因此，我们需要一个操作将`V`合并为`U`，以及一个操作将两个`U`合并。前一个操作用于在分区内合并值，后一个用于在分区之间合并值。为了避免内存分配，这两个函数都允许修改并返回它们的第一个参数，而不是创建一个新的`U`：

```scala
def aggregateByKeyU: ClassTag(seqOp: (U, V) => U,
 combOp: (U, U) => U): RDD[(K, U)] 

def aggregateByKeyU: ClassTag(seqOp: (U, V) => U,
 combOp: (U, U) => U): RDD[(K, U)] 

def aggregateByKeyU: ClassTag(seqOp: (U, V) => U,
 combOp: (U, U) => U): RDD[(K, U)] 

```

`aggregateByKey`通过在分区内对每个分区的所有元素进行聚合操作，然后在合并分区本身时应用另一个聚合逻辑来工作。最终，相同 Key 的所有（键-值）对都被收集在同一个分区中；然而，与`groupByKey`和`reduceByKey`中的固定输出不同，使用`aggregateByKey`时更灵活和可定制。

下图是调用`aggregateByKey`时发生的情况的示例。与`groupByKey`和`reduceByKey`中添加计数不同，这里我们为每个 Key 生成值列表：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00043.jpeg)

# combineByKey

`combineByKey`与`aggregateByKey`非常相似；实际上，`combineByKey`在内部调用`combineByKeyWithClassTag`，这也被`aggregateByKey`调用。与`aggregateByKey`一样，`combineByKey`也通过在每个分区内应用操作，然后在组合器之间工作。

`combineByKey`将`RDD[K,V]`转换为`RDD[K,C]`，其中`C`是在名称键`K`下收集或组合的 V 的列表。

调用 combineByKey 时期望有三个函数。

+   `createCombiner`，将`V`转换为`C`，这是一个元素列表

+   `mergeValue`将`V`合并到`C`中，将`V`附加到列表的末尾

+   `mergeCombiners`将两个 C 合并为一个

在`aggregateByKey`中，第一个参数只是一个零值，但在`combineByKey`中，我们提供了以当前值作为参数的初始函数。

`combineByKey`可以使用自定义分区器调用，也可以只使用默认的 HashPartitioner，如下面的代码片段所示：

```scala
def combineByKeyC => C, mergeCombiners: (C, C) => C, numPartitions: Int): RDD[(K, C)]

def combineByKeyC => C, mergeCombiners: (C, C) => C, partitioner: Partitioner, mapSideCombine: Boolean = true, serializer: Serializer = null): RDD[(K, C)]

```

`combineByKey`通过在分区内对每个分区的所有元素进行聚合操作，然后在合并分区本身时应用另一个聚合逻辑来工作。最终，相同 Key 的所有（键-值）对都被收集在同一个分区中，但是与`groupByKey`和`reduceByKey`中的固定输出不同，使用`combineByKey`时更灵活和可定制。

下图是调用`combineBykey`时发生的情况的示例：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00045.jpeg)

# groupByKey、reduceByKey、combineByKey 和 aggregateByKey 的比较

让我们考虑 StatePopulation RDD 生成一个`pairRDD`的例子，其中包含`<State, <Year, Population>>`。

`groupByKey`如前面的部分所示，将通过生成键的哈希码对`PairRDD`进行`HashPartitioning`，然后洗牌数据以在同一分区中收集每个键的值。这显然会导致过多的洗牌。

`reduceByKey`通过使用本地组合逻辑改进了`groupByKey`，以最小化在洗牌阶段发送的数据。结果与`groupByKey`相同，但性能更高。

`aggregateByKey`在工作方式上与`reduceByKey`非常相似，但有一个重大区别，这使它成为这三种方法中最强大的一个。`aggregateBykey`不需要在相同的数据类型上操作，并且可以在分区内进行不同的聚合，在分区之间进行不同的聚合。

`combineByKey`在性能上与`aggregateByKey`非常相似，除了用于创建组合器的初始函数。

要使用的函数取决于您的用例，但如果有疑问，只需参考本节关于*聚合*的部分，选择适合您用例的正确函数。此外，要特别关注下一节，因为*分区和洗牌*将在该部分中介绍。

以下是显示通过州计算总人口的四种方法的代码。

第 1 步。初始化 RDD：

```scala
scala> val statesPopulationRDD = sc.textFile("statesPopulation.csv").filter(_.split(",")(0) != "State") 
statesPopulationRDD: org.apache.spark.rdd.RDD[String] = statesPopulation.csv MapPartitionsRDD[1] at textFile at <console>:24

scala> statesPopulationRDD.take(10)
res27: Array[String] = Array(Alabama,2010,4785492, Alaska,2010,714031, Arizona,2010,6408312, Arkansas,2010,2921995, California,2010,37332685, Colorado,2010,5048644, Delaware,2010,899816, District of Columbia,2010,605183, Florida,2010,18849098, Georgia,2010,9713521)

```

第 2 步。转换为成对的 RDD：

```scala
scala> val pairRDD = statesPopulationRDD.map(record => record.split(",")).map(t => (t(0), (t(1).toInt, t(2).toInt)))
pairRDD: org.apache.spark.rdd.RDD[(String, (Int, Int))] = MapPartitionsRDD[26] at map at <console>:26

scala> pairRDD.take(10)
res15: Array[(String, (Int, Int))] = Array((Alabama,(2010,4785492)), (Alaska,(2010,714031)), (Arizona,(2010,6408312)), (Arkansas,(2010,2921995)), (California,(2010,37332685)), (Colorado,(2010,5048644)), (Delaware,(2010,899816)), (District of Columbia,(2010,605183)), (Florida,(2010,18849098)), (Georgia,(2010,9713521)))

```

第 3 步。groupByKey - 分组值，然后添加人口：

```scala
scala> val groupedRDD = pairRDD.groupByKey.map(x => {var sum=0; x._2.foreach(sum += _._2); (x._1, sum)})
groupedRDD: org.apache.spark.rdd.RDD[(String, Int)] = MapPartitionsRDD[38] at map at <console>:28

scala> groupedRDD.take(10)
res19: Array[(String, Int)] = Array((Montana,7105432), (California,268280590), (Washington,48931464), (Massachusetts,46888171), (Kentucky,30777934), (Pennsylvania,89376524), (Georgia,70021737), (Tennessee,45494345), (North Carolina,68914016), (Utah,20333580))

```

第 4 步。reduceByKey - 通过简单地添加人口来减少键的值：

```scala

scala> val reduceRDD = pairRDD.reduceByKey((x, y) => (x._1, x._2+y._2)).map(x => (x._1, x._2._2))
reduceRDD: org.apache.spark.rdd.RDD[(String, Int)] = MapPartitionsRDD[46] at map at <console>:28

scala> reduceRDD.take(10)
res26: Array[(String, Int)] = Array((Montana,7105432), (California,268280590), (Washington,48931464), (Massachusetts,46888171), (Kentucky,30777934), (Pennsylvania,89376524), (Georgia,70021737), (Tennessee,45494345), (North Carolina,68914016), (Utah,20333580))

```

第 5 步。按键聚合 - 聚合每个键下的人口并将它们相加：

```scala
Initialize the array
scala> val initialSet = 0
initialSet: Int = 0

provide function to add the populations within a partition
scala> val addToSet = (s: Int, v: (Int, Int)) => s+ v._2
addToSet: (Int, (Int, Int)) => Int = <function2>

provide funtion to add populations between partitions
scala> val mergePartitionSets = (p1: Int, p2: Int) => p1 + p2
mergePartitionSets: (Int, Int) => Int = <function2>

scala> val aggregatedRDD = pairRDD.aggregateByKey(initialSet)(addToSet, mergePartitionSets)
aggregatedRDD: org.apache.spark.rdd.RDD[(String, Int)] = ShuffledRDD[41] at aggregateByKey at <console>:34

scala> aggregatedRDD.take(10)
res24: Array[(String, Int)] = Array((Montana,7105432), (California,268280590), (Washington,48931464), (Massachusetts,46888171), (Kentucky,30777934), (Pennsylvania,89376524), (Georgia,70021737), (Tennessee,45494345), (North Carolina,68914016), (Utah,20333580))

```

第 6 步。combineByKey - 在分区内进行组合，然后合并组合器：

```scala
createcombiner function
scala> val createCombiner = (x:(Int,Int)) => x._2
createCombiner: ((Int, Int)) => Int = <function1>

function to add within partition
scala> val mergeValues = (c:Int, x:(Int, Int)) => c +x._2
mergeValues: (Int, (Int, Int)) => Int = <function2>

function to merge combiners
scala> val mergeCombiners = (c1:Int, c2:Int) => c1 + c2
mergeCombiners: (Int, Int) => Int = <function2>

scala> val combinedRDD = pairRDD.combineByKey(createCombiner, mergeValues, mergeCombiners)
combinedRDD: org.apache.spark.rdd.RDD[(String, Int)] = ShuffledRDD[42] at combineByKey at <console>:34

scala> combinedRDD.take(10)
res25: Array[(String, Int)] = Array((Montana,7105432), (California,268280590), (Washington,48931464), (Massachusetts,46888171), (Kentucky,30777934), (Pennsylvania,89376524), (Georgia,70021737), (Tennessee,45494345), (North Carolina,68914016), (Utah,20333580))

```

如您所见，所有四种聚合都产生相同的输出。只是它们的工作方式不同。

# 分区和洗牌

我们已经看到 Apache Spark 如何比 Hadoop 更好地处理分布式计算。我们还看到了内部工作，主要是基本数据结构，称为**弹性分布式数据集**（**RDD**）。RDD 是不可变的集合，代表数据集，并具有内置的可靠性和故障恢复能力。RDD 在数据上的操作不是作为单个数据块，而是在整个集群中分布的分区中管理和操作数据。因此，数据分区的概念对于 Apache Spark 作业的正常运行至关重要，并且可能对性能以及资源的利用方式产生重大影响。

RDD 由数据分区组成，所有操作都是在 RDD 的数据分区上执行的。诸如转换之类的几个操作是由执行器在正在操作的特定数据分区上执行的函数。然而，并非所有操作都可以通过在各自的执行器上对数据分区执行孤立的操作来完成。像聚合（在前面的部分中看到）这样的操作需要在整个集群中移动数据，这个阶段被称为**洗牌**。在本节中，我们将更深入地了解分区和洗牌的概念。

让我们通过执行以下代码来查看整数的简单 RDD。Spark 上下文的`parallelize`函数从整数序列创建 RDD。然后，使用`getNumPartitions()`函数，我们可以获取此 RDD 的分区数。

```scala
scala> val rdd_one = sc.parallelize(Seq(1,2,3))
rdd_one: org.apache.spark.rdd.RDD[Int] = ParallelCollectionRDD[120] at parallelize at <console>:25

scala> rdd_one.getNumPartitions
res202: Int = 8

```

RDD 可以如下图所示进行可视化，显示了 RDD 中的 8 个分区：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00136.jpeg)

分区数很重要，因为这个数字直接影响将运行 RDD 转换的任务数量。如果分区数太小，那么我们将在大量数据上只使用少量 CPU/核心，从而导致性能较慢，并且使集群利用不足。另一方面，如果分区数太大，那么您将使用比实际需要更多的资源，在多租户环境中可能会导致为您或您团队中的其他作业运行的资源饥饿。

# 分区器

RDD 的分区是由分区器完成的。分区器为 RDD 中的元素分配分区索引。同一分区中的所有元素将具有相同的分区索引。

Spark 提供了两种分区器`HashPartitioner`和`RangePartitioner`。除此之外，您还可以实现自定义分区器。

# HashPartitioner

`HashPartitioner`是 Spark 中的默认分区器，它通过为 RDD 元素的每个键计算哈希值来工作。所有具有相同哈希码的元素最终都会进入同一个分区，如下面的代码片段所示：

```scala
partitionIndex = hashcode(key) % numPartitions

```

以下是 String `hashCode()`函数的示例，以及我们如何生成`partitionIndex`：

```scala
scala> val str = "hello"
str: String = hello

scala> str.hashCode
res206: Int = 99162322

scala> val numPartitions = 8
numPartitions: Int = 8

scala> val partitionIndex = str.hashCode % numPartitions
partitionIndex: Int = 2

```

默认分区数要么来自 Spark 配置参数`spark.default.parallelism`，要么来自集群中的核心数

以下图示说明了哈希分区的工作原理。我们有一个包含 3 个元素**a**、**b**和**e**的 RDD。使用 String 哈希码，我们可以根据设置的 6 个分区得到每个元素的`partitionIndex`：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00140.jpeg)

# RangePartitioner

`RangePartitioner`通过将 RDD 分区为大致相等的范围来工作。由于范围必须知道任何分区的起始和结束键，因此在使用`RangePartitioner`之前，RDD 需要首先进行排序。

`RangePartitioning` 首先需要根据 RDD 确定合理的分区边界，然后创建一个从键 K 到`partitionIndex`的函数，该函数确定元素所属的分区。最后，我们需要根据`RangePartitioner`重新分区 RDD，以便根据我们确定的范围正确分发 RDD 元素。

以下是我们如何使用`RangePartitioning`对`PairRDD`进行分区的示例。我们还可以看到在使用`RangePartitioner`重新分区 RDD 后分区发生了变化：

```scala
import org.apache.spark.RangePartitioner
scala> val statesPopulationRDD = sc.textFile("statesPopulation.csv")
statesPopulationRDD: org.apache.spark.rdd.RDD[String] = statesPopulation.csv MapPartitionsRDD[135] at textFile at <console>:26

scala> val pairRDD = statesPopulationRDD.map(record => (record.split(",")(0), 1))
pairRDD: org.apache.spark.rdd.RDD[(String, Int)] = MapPartitionsRDD[136] at map at <console>:28

scala> val rangePartitioner = new RangePartitioner(5, pairRDD)
rangePartitioner: org.apache.spark.RangePartitioner[String,Int] = org.apache.spark.RangePartitioner@c0839f25

scala> val rangePartitionedRDD = pairRDD.partitionBy(rangePartitioner)
rangePartitionedRDD: org.apache.spark.rdd.RDD[(String, Int)] = ShuffledRDD[130] at partitionBy at <console>:32

scala> pairRDD.mapPartitionsWithIndex((i,x) => Iterator(""+i + ":"+x.length)).take(10)
res215: Array[String] = Array(0:177, 1:174)

scala> rangePartitionedRDD.mapPartitionsWithIndex((i,x) => Iterator(""+i + ":"+x.length)).take(10)
res216: Array[String] = Array(0:70, 1:77, 2:70, 3:63, 4:71)

```

以下图示说明了`RangePartitioner`，就像在前面的示例中看到的那样：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00143.jpeg)

# 洗牌

无论使用何种分区器，许多操作都会导致 RDD 数据在分区之间进行重新分区。可以创建新分区，也可以合并/压缩多个分区。为了进行重新分区所需的所有数据移动都称为**shuffling**，这是编写 Spark 作业时需要理解的重要概念。洗牌可能会导致性能严重下降，因为计算不再在同一个执行器的内存中进行，而是执行器在网络上传输数据。

一个很好的例子是我们在*聚合*部分早些时候看到的`groupByKey()`的例子。显然，大量数据在执行器之间流动，以确保所有键的值都被收集到同一个执行器上执行`groupBy`操作。

Shuffling 还确定了 Spark 作业的执行过程，并影响作业如何分成阶段。正如我们在本章和上一章中所看到的，Spark 保存了 RDD 的 DAG，它代表了 RDD 的血统，因此 Spark 不仅使用血统来规划作业的执行，而且可以从中恢复任何执行器的丢失。当 RDD 正在进行转换时，会尝试确保操作在与数据相同的节点上执行。然而，通常我们使用连接操作、reduce、group 或聚合等操作，这些操作会有意或无意地导致重新分区。这种洗牌反过来又决定了处理中的特定阶段在哪里结束，新阶段从哪里开始。

以下图示说明了 Spark 作业如何分成阶段。此示例显示了对`pairRDD`进行过滤，使用 map 进行转换，然后调用`groupByKey`，最后使用`map()`进行最后一次转换：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00147.jpeg)

我们进行的洗牌越多，作业执行中就会出现越多的阶段，从而影响性能。Spark Driver 用于确定阶段的两个关键方面是定义 RDD 的两种依赖关系，即窄依赖和宽依赖。

# 窄依赖

当一个 RDD 可以通过简单的一对一转换（如`filter()`函数、`map()`函数、`flatMap()`函数等）从另一个 RDD 派生出来时，子 RDD 被认为是依赖于父 RDD 的一对一基础。这种依赖关系被称为窄依赖，因为数据可以在包含原始 RDD/父 RDD 分区的同一节点上进行转换，而无需在其他执行器之间进行任何数据传输。

窄依赖在作业执行的同一阶段中。

下图是一个窄依赖如何将一个 RDD 转换为另一个 RDD 的示例，对 RDD 元素进行一对一的转换：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00152.jpeg)

# 广泛依赖

当一个 RDD 可以通过在线传输数据或使用函数进行数据重分区或重新分发数据（如`aggregateByKey`、`reduceByKey`等）从一个或多个 RDD 派生出来时，子 RDD 被认为依赖于参与洗牌操作的父 RDD。这种依赖关系被称为广泛依赖，因为数据不能在包含原始 RDD/父 RDD 分区的同一节点上进行转换，因此需要在其他执行器之间通过网络传输数据。

广泛的依赖关系引入了作业执行中的新阶段。

下图是一个广泛依赖如何在执行器之间洗牌数据将一个 RDD 转换为另一个 RDD 的示例：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00155.jpeg)

# 广播变量

广播变量是所有执行器共享的变量。广播变量在驱动程序中创建一次，然后在执行器上只读。虽然理解简单数据类型的广播，比如`Integer`，是很简单的，但广播在概念上比简单的变量要大得多。整个数据集可以在 Spark 集群中广播，以便执行器可以访问广播的数据。在执行器中运行的所有任务都可以访问广播变量。

广播使用各种优化方法使广播的数据对所有执行器都可访问。这是一个重要的挑战，因为如果广播的数据集的大小很大，你不能指望 100 个或 1000 个执行器连接到驱动程序并拉取数据集。相反，执行器通过 HTTP 连接拉取数据，还有一个类似于 BitTorrent 的最近添加的方法，其中数据集本身就像种子一样分布在集群中。这使得将广播变量分发给所有执行器的方法比每个执行器逐个从驱动程序拉取数据更具可伸缩性，这可能会导致驱动程序在有大量执行器时出现故障。

驱动程序只能广播它拥有的数据，你不能使用引用来广播 RDD。这是因为只有驱动程序知道如何解释 RDD，执行器只知道它们正在处理的数据的特定分区。

如果你深入研究广播的工作原理，你会发现这种机制首先由驱动程序将序列化对象分成小块，然后将这些块存储在驱动程序的 BlockManager 中。当代码被序列化以在执行器上运行时，每个执行器首先尝试从自己的内部 BlockManager 中获取对象。如果广播变量之前已经被获取过，它会找到并使用它。然而，如果它不存在，执行器将使用远程获取从驱动程序和/或其他可用的执行器中获取小块。一旦获取了这些块，它就会将这些块放入自己的 BlockManager 中，准备让其他执行器从中获取。这可以防止驱动程序成为发送广播数据的瓶颈（每个执行器一个副本）。

下图是一个 Spark 集群中广播工作的示例：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/scala-spark-bgdt-anlt/img/00006.jpeg)

广播变量既可以创建也可以销毁。我们将研究广播变量的创建和销毁。还有一种方法可以从内存中删除广播变量，我们也将研究。

# 创建广播变量

可以使用 Spark 上下文的`broadcast()`函数在任何数据类型的任何数据上创建广播变量，前提是数据/变量是可序列化的。

让我们看看如何广播一个整数变量，然后在执行程序上执行转换操作时使用广播变量：

```scala
scala> val rdd_one = sc.parallelize(Seq(1,2,3))
rdd_one: org.apache.spark.rdd.RDD[Int] = ParallelCollectionRDD[101] at parallelize at <console>:25

scala> val i = 5
i: Int = 5

scala> val bi = sc.broadcast(i)
bi: org.apache.spark.broadcast.Broadcast[Int] = Broadcast(147)

scala> bi.value
res166: Int = 5

scala> rdd_one.take(5)
res164: Array[Int] = Array(1, 2, 3)

scala> rdd_one.map(j => j + bi.value).take(5)
res165: Array[Int] = Array(6, 7, 8)

```

广播变量也可以创建在不仅仅是原始数据类型上，如下一个示例所示，我们将从 Driver 广播一个`HashMap`。

以下是通过查找 HashMap 将整数 RDD 进行简单转换的示例，将 RDD 的 1,2,3 转换为 1 X 2，2 X 3，3 X 4 = 2,6,12：

```scala
scala> val rdd_one = sc.parallelize(Seq(1,2,3))
rdd_one: org.apache.spark.rdd.RDD[Int] = ParallelCollectionRDD[109] at parallelize at <console>:25

scala> val m = scala.collection.mutable.HashMap(1 -> 2, 2 -> 3, 3 -> 4)
m: scala.collection.mutable.HashMap[Int,Int] = Map(2 -> 3, 1 -> 2, 3 -> 4)

scala> val bm = sc.broadcast(m)
bm: org.apache.spark.broadcast.Broadcast[scala.collection.mutable.HashMap[Int,Int]] = Broadcast(178)

scala> rdd_one.map(j => j * bm.value(j)).take(5)
res191: Array[Int] = Array(2, 6, 12)

```

# 清理广播变量

广播变量在所有执行程序上占用内存，并且根据广播变量中包含的数据的大小，这可能会在某个时刻引起资源问题。有一种方法可以从所有执行程序的内存中删除广播变量。

在广播变量上调用`unpersist()`会从所有执行程序的内存缓存中删除广播变量的数据，以释放资源。如果再次使用变量，则数据将重新传输到执行程序，以便再次使用。但是，Driver 会保留内存，如果 Driver 没有数据，则广播变量将不再有效。

接下来我们将看看如何销毁广播变量。

以下是如何在广播变量上调用`unpersist()`。调用`unpersist`后，如果我们再次访问广播变量，则它会像往常一样工作，但在幕后，执行程序再次获取变量的数据。

```scala
scala> val rdd_one = sc.parallelize(Seq(1,2,3))
rdd_one: org.apache.spark.rdd.RDD[Int] = ParallelCollectionRDD[101] at parallelize at <console>:25

scala> val k = 5
k: Int = 5

scala> val bk = sc.broadcast(k)
bk: org.apache.spark.broadcast.Broadcast[Int] = Broadcast(163)

scala> rdd_one.map(j => j + bk.value).take(5)
res184: Array[Int] = Array(6, 7, 8)

scala> bk.unpersist

scala> rdd_one.map(j => j + bk.value).take(5)
res186: Array[Int] = Array(6, 7, 8)

```

# 销毁广播变量

您还可以销毁广播变量，将其从所有执行程序和 Driver 中完全删除，使其无法访问。这在跨集群有效地管理资源方面非常有帮助。

在广播变量上调用`destroy()`会销毁与指定广播变量相关的所有数据和元数据。一旦广播变量被销毁，就无法再次使用，必须重新创建。

以下是销毁广播变量的示例：

```scala
scala> val rdd_one = sc.parallelize(Seq(1,2,3))
rdd_one: org.apache.spark.rdd.RDD[Int] = ParallelCollectionRDD[101] at parallelize at <console>:25

scala> val k = 5
k: Int = 5

scala> val bk = sc.broadcast(k)
bk: org.apache.spark.broadcast.Broadcast[Int] = Broadcast(163)

scala> rdd_one.map(j => j + bk.value).take(5)
res184: Array[Int] = Array(6, 7, 8)

scala> bk.destroy

```

如果尝试使用已销毁的广播变量，则会抛出异常

以下是尝试重用已销毁的广播变量的示例：

```scala
scala> rdd_one.map(j => j + bk.value).take(5)
17/05/27 14:07:28 ERROR Utils: Exception encountered
org.apache.spark.SparkException: Attempted to use Broadcast(163) after it was destroyed (destroy at <console>:30)
 at org.apache.spark.broadcast.Broadcast.assertValid(Broadcast.scala:144)
 at org.apache.spark.broadcast.TorrentBroadcast$$anonfun$writeObject$1.apply$mcV$sp(TorrentBroadcast.scala:202)
 at org.apache.spark.broadcast.TorrentBroadcast$$anonfun$wri

```

因此，广播功能可以用于大大提高 Spark 作业的灵活性和性能。

# 累加器

累加器是跨执行程序共享的变量，通常用于向 Spark 程序添加计数器。如果您有一个 Spark 程序，并且想要知道错误或总记录数或两者，可以通过两种方式实现。一种方法是添加额外的逻辑来仅计算错误或总记录数，当处理所有可能的计算时变得复杂。另一种方法是保持逻辑和代码流相当完整，并添加累加器。

累加器只能通过将值添加到值来更新。

以下是使用 Spark 上下文和`longAccumulator`函数创建和使用长累加器的示例，以将新创建的累加器变量初始化为零。由于累加器在 map 转换内部使用，因此累加器会递增。操作结束时，累加器保持值为 351。

```scala
scala> val acc1 = sc.longAccumulator("acc1")
acc1: org.apache.spark.util.LongAccumulator = LongAccumulator(id: 10355, name: Some(acc1), value: 0)

scala> val someRDD = statesPopulationRDD.map(x => {acc1.add(1); x})
someRDD: org.apache.spark.rdd.RDD[String] = MapPartitionsRDD[99] at map at <console>:29

scala> acc1.value
res156: Long = 0  /*there has been no action on the RDD so accumulator did not get incremented*/

scala> someRDD.count
res157: Long = 351

scala> acc1.value
res158: Long = 351

scala> acc1
res145: org.apache.spark.util.LongAccumulator = LongAccumulator(id: 10355, name: Some(acc1), value: 351)

```

有内置的累加器可用于许多用例：

+   `LongAccumulator`：用于计算 64 位整数的总和、计数和平均值

+   `DoubleAccumulator`：用于计算双精度浮点数的总和、计数和平均值。

+   `CollectionAccumulator[T]`：用于收集元素列表

所有前面的累加器都是建立在`AccumulatorV2`类之上的。通过遵循相同的逻辑，我们可以潜在地构建非常复杂和定制的累加器来在我们的项目中使用。

我们可以通过扩展`AccumulatorV2`类来构建自定义累加器。以下是一个示例，显示了实现所需函数的必要性。在下面的代码中，`AccumulatorV2[Int, Int]`表示输入和输出都是整数类型：

```scala
class MyAccumulator extends AccumulatorV2[Int, Int] {
  //simple boolean check
 override def isZero: Boolean = ??? //function to copy one Accumulator and create another one override def copy(): AccumulatorV2[Int, Int] = ??? //to reset the value override def reset(): Unit = ??? //function to add a value to the accumulator override def add(v: Int): Unit = ??? //logic to merge two accumulators override def merge(other: AccumulatorV2[Int, Int]): Unit = ??? //the function which returns the value of the accumulator override def value: Int = ???
}

```

接下来，我们将看一个自定义累加器的实际例子。同样，我们将使用`statesPopulation` CSV 文件。我们的目标是在自定义累加器中累积年份的总和和人口的总和。

**步骤 1. 导入包含 AccumulatorV2 类的包：**

```scala
import org.apache.spark.util.AccumulatorV2

```

**步骤 2. 包含年份和人口的 Case 类：**

```scala
case class YearPopulation(year: Int, population: Long)

```

**步骤 3. StateAccumulator 类扩展 AccumulatorV2：**

```scala

class StateAccumulator extends AccumulatorV2[YearPopulation, YearPopulation] { 
      //declare the two variables one Int for year and Long for population
      private var year = 0 
 private var population:Long = 0L

      //return iszero if year and population are zero
      override def isZero: Boolean = year == 0 && population == 0L

      //copy accumulator and return a new accumulator
     override def copy(): StateAccumulator = { 
 val newAcc = new StateAccumulator 
 newAcc.year =     this.year 
 newAcc.population = this.population 
 newAcc 
 }

       //reset the year and population to zero 
       override def reset(): Unit = { year = 0 ; population = 0L }

       //add a value to the accumulator
       override def add(v: YearPopulation): Unit = { 
 year += v.year 
 population += v.population 
 }

       //merge two accumulators
      override def merge(other: AccumulatorV2[YearPopulation, YearPopulation]): Unit = { 
 other match { 
 case o: StateAccumulator => { 
 year += o.year 
 population += o.population 
 } 
 case _ => 
 } 
 }

       //function called by Spark to access the value of accumulator
       override def value: YearPopulation = YearPopulation(year, population)
}

```

**步骤 4. 创建一个新的 StateAccumulator 并在 SparkContext 中注册：**

```scala
val statePopAcc = new StateAccumulator

sc.register(statePopAcc, "statePopAcc")

```

**步骤 5. 将 statesPopulation.csv 作为 RDD 读取：**

```scala

val statesPopulationRDD = sc.textFile("statesPopulation.csv").filter(_.split(",")(0) != "State")

scala> statesPopulationRDD.take(10)
res1: Array[String] = Array(Alabama,2010,4785492, Alaska,2010,714031, Arizona,2010,6408312, Arkansas,2010,2921995, California,2010,37332685, Colorado,2010,5048644, Delaware,2010,899816, District of Columbia,2010,605183, Florida,2010,18849098, Georgia,2010,9713521)

```

**步骤 6. 使用 StateAccumulator：**

```scala
statesPopulationRDD.map(x => { 
 val toks = x.split(",") 
 val year = toks(1).toInt 
 val pop = toks(2).toLong 
 statePopAcc.add(YearPopulation(year, pop)) 
 x
}).count

```

**步骤 7. 现在，我们可以检查 StateAccumulator 的值：**

```scala
scala> statePopAcc
res2: StateAccumulator = StateAccumulator(id: 0, name: Some(statePopAcc), value: YearPopulation(704550,2188669780))

```

在这一部分，我们研究了累加器以及如何构建自定义累加器。因此，使用前面举例的例子，您可以创建复杂的累加器来满足您的需求。

# 总结

在这一章中，我们讨论了许多类型的 RDD，比如`shuffledRDD`，`pairRDD`，`sequenceFileRDD`，`HadoopRDD`等等。我们还看了三种主要的聚合类型，`groupByKey`，`reduceByKey`和`aggregateByKey`。我们研究了分区是如何工作的，以及为什么围绕分区需要一个合适的计划来提高性能。我们还研究了洗牌和窄依赖和宽依赖的概念，这些是 Spark 作业被分成阶段的基本原则。最后，我们看了广播变量和累加器的重要概念。

RDD 的灵活性使其易于适应大多数用例，并执行必要的操作以实现目标。

在下一章中，我们将转向 RDD 的更高抽象层，作为 Tungsten 计划的一部分添加到 RDD 中的 DataFrame 和 Spark SQL，以及它们如何在第八章 *引入一点结构 - Spark SQL*中结合在一起。
