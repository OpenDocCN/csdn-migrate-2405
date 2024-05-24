# Linux 架构实用手册（三）

> 原文：[`zh.annas-archive.org/md5/7D24F1F94933063822D38A8D8705DDE3`](https://zh.annas-archive.org/md5/7D24F1F94933063822D38A8D8705DDE3)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第三部分：弹性堆栈

本节重点介绍如何实现包括 Elasticsearch、Logstash 和 Kibana 的 ELK 堆栈，用于环境日志感知。

本节包括以下章节：

+   第十章，使用 ELK 堆栈进行监控

+   第十一章，设计 ELK 堆栈

+   第十二章，使用 Elasticsearch、Logstash 和 Kibana 管理日志


# 第十章：使用 ELK Stack 进行监控

监控是任何环境的重要组成部分，无论是生产、QA 还是开发；**Elastic Stack**（**ELK Stack**）通过允许来自不同来源的日志、指标和事件聚合到一个可索引的位置：Elasticsearch，有助于简化这一任务。

ELK Stack 是三种不同软件的集合：

+   Elasticsearch

+   Logstash

+   Kibana

在这一章中，我们将解释每个组件的作用。

在本章中，我们将涵盖以下主题：定义 Elasticsearch 的主要功能

+   探索集中日志的概念

+   Kibana 如何帮助整合其他组件

# 技术要求

以下是本章的技术要求列表：

+   Elasticsearch 产品页面：[`www.elastic.co/products/elasticsearch`](https://www.elastic.co/products/elasticsearch)

+   Logstash 概述：[`www.elastic.co/products/logstash`](https://www.elastic.co/products/logstash)

+   Logstash 的可用输入插件：[`www.elastic.co/guide/en/logstash/current/input-plugins.html`](https://www.elastic.co/guide/en/logstash/current/input-plugins.html)

+   Grok 模式匹配：[`www.elastic.co/guide/en/logstash/current/plugins-filters-grok.html`](https://www.elastic.co/guide/en/logstash/current/plugins-filters-grok.html)

+   Kibana 用户指南：[`www.elastic.co/guide/en/kibana/current/index.html`](https://www.elastic.co/guide/en/kibana/current/index.html)

# 了解监控的必要性

想象一下，您被要求向 CIO 提供历史数据，因为一个正在进行的项目需要了解整个生态系统平均使用多少 CPU，但企业从未花时间实施良好的监控系统。因此，您唯一的选择是登录到每个系统并运行本地命令，将结果记录到电子表格中，进行一些数学运算以获得平均结果，之后您意识到数据已不再有效，必须重新进行所有操作。这正是为什么我们有 Elasticsearch 等监控系统的原因。同样的过程可能只需要几分钟。不仅如此，您将获得准确的数据和实时报告。让我们更多地了解监控是什么，以及为什么您作为架构师应该认为它是有史以来最好的东西。

监控是指从任何给定环境中获取原始数据，对其进行聚合、存储和分析，以一种可理解的方式。

所有环境都应该有某种形式的监控，从用于跟踪登录失败的简单日志文件到负责分析来自数千台主机的数据的更健壮的系统。监控数据使系统管理员能够在问题发生之前检测到问题，并使架构师能够基于数据为未来或正在进行的项目做出决策。

您可能还记得第一章中对*设计方法论的介绍*，我们谈到了如何提出正确的问题可以帮助设计更好的解决方案，并且同时给出正确的答案；例如，它可以帮助基于历史使用数据做出大小决策。提供使用数据给架构师有助于正确地确定解决方案的大小。他们不仅利用未来的使用统计数据，还利用过去的实例，例如在周末等高峰时段记录的使用高峰。

让我们试着将为什么我们需要监控压缩成四个主要领域：

+   通过历史数据做出决策

+   主动检测问题

+   了解环境性能

+   预算计划

# 通过历史数据做出决策

监控能够让我们回到过去并分析使用趋势，以帮助识别机会领域。例如，在第一章中提到的情景，客户需要一个能够每秒维持 10,000 次点击量的 Web 服务器解决方案。作为架构师，你请求访问他们现有解决方案的使用数据，并在查看他们的使用趋势后，确定每个月的第一周使用量增加了十倍。

虽然用户在这些日子里可能不会抱怨问题，但你应该考虑到在这些时间内高使用量往往会消耗资源。从监控系统中获取的数据可能会导致一个决定，即服务器需要分配更多资源（例如更多的 CPU 和 RAM）比之前计算的，或者需要向集群中添加更多的服务器（如果可能的话）。

没有这些数据，没有人会知道由于激增而需要更多资源。能够区分正常使用和激增有助于在设计和规模化解决方案时做出正确选择。

从同样的情景中，我们可以从历史数据使用中得出结论，即当前解决方案在过去几个月一直能够维持每秒 10,000 次的点击量。这可能意味着客户一直能够实现期望的性能，但实际上他们需要的是一个能够处理使用激增的解决方案，正如前面提到的。

# 主动检测问题

想象一下，当你准备下班时，突然有人报告数据库服务器无法接收连接。你登录服务器后发现问题比最初报告的严重得多。数据库所在的磁盘现在都被报告为损坏。你仔细查看系统日志，发现过去四个月一直报告磁盘错误；然而，由于没有健壮的监控系统，没有人知道这些错误。现在数据丢失了，你不得不恢复一个旧的备份，需要数小时才能恢复到生产状态。

不幸的是，这种情况并不罕见，大多数时候，IT 工作是被动的，这意味着如果出现问题，有人会报告问题，然后有人会去修复问题。如果实施了监控系统并配置为报告错误，这种情况本来可以完全避免。在磁盘彻底损坏之前就可以更换磁盘。

能够在问题发生之前主动检测问题，在我们看来，是监控系统中最关键的方面之一。在问题发生之前预测问题可能发生的地方有助于通过采取行动来减少停机时间。例如，在前面的情景中，更换磁盘可以防止数据丢失。预测变化还有助于通过防止因停机或故障而导致的业务损失，以及增加生产（或正常运行时间）来降低运营成本。

# 了解环境性能

在第五章中，*在 Gluster 系统中分析性能*，我们对 GlusterFS 实施进行了性能测试。通过监控系统，可以通过汇总历史数据和平均统计数据来简化性能基线的获取过程。

通过查看历史数据，我们可以看到在一定时间内任何给定系统的平均性能，从而让架构师定义什么是正常的，什么是不正常的。通过获得基线，我们可以更深入地了解环境在一天、一周甚至一个月内的行为。例如，我们可以确定存储服务器在一天内的吞吐量大约为 200 MB/s，当用户在一天的开始登录时，吞吐量会增加到 300 MB/s。起初，100 MB/s 的增加可能看起来像是一个问题，但是通过查看数据，这似乎是一个趋势，并且是标准行为。

有了这些信息，我们知道基线大约是 200 MB/s，峰值为 300 MB/s。当解决方案进行基准测试时，预期的性能应该符合这个规格。如果我们得到低于这个数字的结果，我们知道存在问题，需要进行调查以确定性能不佳的原因。这可能是解决方案的重新设计，也可能是配置的实际问题。另一方面，高数字表明解决方案即使在负载高峰时也能按规格运行。

没有这些数据，我们将不知道异常行为是什么样子，也无法确认这是否是一个实际问题，或者了解环境的正常情况。了解解决方案的性能和使用情况可以帮助发现可能看起来并不存在问题的问题。例如，考虑先前的数字情况，用户通常与存储服务器进行正常交互并且具有平均响应时间；然而，通过监控数据，我们观察到即使在正常用户负载下，我们只能获得 50 MB/s 的吞吐量。从用户的角度来看，一切似乎都很好，但当询问时，他们确实报告说即使响应时间良好，传输时间也比平常长，进一步调查发现一个节点需要维护。

在前面的例子中，仅通过查看性能数据，就可以识别出解决方案性能不佳的情况，并采取措施避免业务中断和损失。这就是通过使用数据来理解环境的力量。

# 预算规划

数据使用趋势可以更精细地控制预算规划，因为了解需要多少存储空间可以帮助避免未能提供足够空间的情况。

在第一章中，*设计方法论简介*，我们谈到了企业的采购流程，以及如何坚持时间表对于不同公司来说是至关重要的。了解空间需求和使用情况对于这个过程至关重要，因为它可以帮助预测例如解决方案何时会耗尽空间，并且可以帮助做出关于获取新存储空间的决策。

通过监控系统，了解业务每天消耗的存储量（也称为每日变化率），可以让系统管理员和架构师预测业务可以利用当前可用空间运行多长时间。这也可以让他们预测解决方案何时会耗尽空间，以便在存储空间耗尽之前采取行动，这是每个 IT 部门都应该避免的情况。

了解资源利用率对任何业务都至关重要，因为它可以防止不必要的设备采购。使用数据来决定是否应该向现有环境添加更多资源可以通过选择适当的设备数量来减少成本。当应用由于资源不足（或过时的硬件）而性能不佳时，与当前环境按预期工作并且仍有一些增长空间的数据是不同的。

如今，监控的需求比以往任何时候都更为关键。随着 IT 环境中数据的近乎指数级增长，通过基于数据的决策来预测行为并采取积极的行动只有通过监控系统才能实现，比如 ELK Stack。

# 集中式日志

在深入探讨 ELK Stack 的组成之前，让我们先探讨一下集中式日志的概念。

想象一下以下情景；环境中似乎存在安全漏洞，并且在一些服务器上发现了一些奇怪的文件。查看`/var/log/secure`文件，您会发现来自多个地址的 root 登录，并且您想知道哪些系统受到了影响。只有一个问题——环境中有 5000 多台 Linux 服务器，您必须登录到每个系统并查看日志。每个主机可能需要大约一分钟来 grep；这将需要连续 83 个小时查看系统日志。

这种必须去每个节点的问题可以通过聚合和将日志放在一个集中的位置来解决。虽然其他行业似乎正在走去中心化服务的路线，但将所有环境的日志放在一个位置可以帮助简化任务，比如调查可能影响多个系统的事件。在一个单一位置查找可以减少故障排除所需的时间，并同时允许管理员更有效地在环境中寻找问题。

集中式日志架构如下：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-arch/img/56d1586c-58b4-46c8-be8a-551323da1d85.png)

来自多个应用程序的日志被发送到日志解析器（如 Logstash），然后移动到索引器（如 Elasticsearch）。每个主机都有一个代理负责将日志发送到解析器。

解析器的工作是将数据转换为易于索引的形式，然后将数据发送到索引器。

在下一部分中，我们将看看组成 ELK Stack 的组件。

# Elasticsearch 概述

现在，我们将深入探讨 ELK Stack 的组件，我们将从最重要的组件 Elasticsearch 开始。

Elasticsearch 基于一个名为 Lucene 的 Apache 项目。它的作用是对数据进行索引并存储以便以后检索。Elasticsearch 接收来自不同来源的数据并将其存储在一个集中的位置，或者如果设置为集群，则存储在多个节点上。对于这种设置，我们将使用 Logstash 作为数据源；但是，Elasticsearch 也可以直接从 Beats 接收数据，这是我们稍后将讨论的。在其核心，Elasticsearch 是一个能够非常快速地检索数据的分析和搜索引擎；由于数据一旦存储就被索引，Elasticsearch 将数据存储为 JSON 文档。

定义 Elasticsearch 的一些特点如下：

+   快速

+   可扩展

+   高度可用

# 快速

搜索几乎是实时的；这意味着，当您输入搜索词时，Elasticsearch 几乎立即返回结果。这要归功于索引和数据存储为 JSON。

# 可扩展

通过简单地向集群添加更多节点，可以快速扩展 Elasticsearch 集群。

# 高度可用

当配置为集群时，Elasticsearch 在多个节点之间分配分片，并在一个或多个节点失败时创建分片的副本。

分片是 JSON 文档的一个片段。Elasticsearch 创建分片的副本并将它们分配到集群节点上。这使得集群能够承受灾难性故障，因为数据仍然存在作为副本。

# Logstash

大多数时候，例如日志文件之类的数据是为了让人类能够轻松理解事件的含义而设计的。这种类型的数据是非结构化的，因为机器无法轻松地索引事件，因为它们不遵循相同的结构或格式。例如，系统日志和 Apache。虽然每个日志提供不同类型的事件，但都不遵循相同的格式或结构，对于索引系统来说，这就成了一个问题。这就是 Logstash 的用武之地。

Logstash 数据处理解析器能够同时从多个来源接收数据，然后通过解析将数据转换为结构化形式，然后将其作为索引的易搜索数据发送到 Elasticsearch。

Logstash 的主要特点之一是可用于过滤器的大量插件，例如 Grok，可以更灵活地解析和索引各种类型的数据。

# Grok

Grok 是 Logstash 中可用的插件；它从诸如系统日志、MySQL、Apache 和其他 Web 服务器日志之类的来源获取非结构化数据，并将其转换为结构化和可查询的数据，以便轻松地摄入到 Elasticsearch 中。

Grok 将文本模式组合成与日志匹配的内容，例如数字或 IP 地址。其模式如下：

```
%{SYNTAX:SEMANTIC}
```

在这里，`SYNTAX`是匹配文本的模式的名称，“SEMANTIC”是给文本段落的标识符。

HTTP 的事件示例如下：

```
55.3.244.1 GET /index.html 15824 0.043
```

这可能是用于此的一个模式匹配：

```
%{IP:client} %{WORD:method} %{URIPATHPARAM:request} %{NUMBER:bytes} %{NUMBER:duration}
```

因此，通过将所有内容放在实际的过滤器配置中，它看起来像这样：

```
input {
  file {
    path => "/var/log/http.log"
  }
}
filter {
  grok {
    match => { "message" => "%{IP:client} %{WORD:method} %{URIPATHPARAM:request} %{NUMBER:bytes} %{NUMBER:duration}" }
  }
}
```

# 自定义模式

在运行自定义应用程序时，Logstash 可能没有正确的模式来匹配语法和语义。Logstash 允许创建可以匹配自定义数据的自定义模式。前面示例中的相同逻辑可以用来匹配数据。

# Kibana 将所有内容整合在一起

虽然 Elasticsearch 是 ELK Stack 的重要组成部分，Logstash 是解析和处理部分，但 Kibana 是将所有其他内容聚合在一起的工具。

可视化数据的能力使用户能够赋予其数据意义。仅仅查看原始数据，很难理解其含义。Kibana 通过图表、地图和其他方法来可视化存储在 Elasticsearch 中的数据。

以下是从实时演示中获取的 Kibana 界面的快速浏览：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-arch/img/f1cac6cf-9ffd-4ac3-a0e0-7c0dfbc8cc70.png)

Kibana 仪表板

我们可以看到使用多个模块显示不同指标来解释数据是多么容易。

Kibana 能够轻松理解大型数据集。作为一个基于浏览器的应用程序，它可以从任何地方访问。这也允许轻松与他人共享仪表板和报告。它可以与 Elasticsearch 一起安装；但是，对于更大的部署，将主机分配给 Kibana 是一个很好的做法。此外，Kibana 在 Node.js 上运行，因此几乎可以安装在可以运行 Node.js 的所有系统上，从各种 Linux 到 Windows 和 MacOS。

# 总结

在本章中，我们探讨了监控的需求，并了解了从环境中获取数据、汇总数据并存储数据的过程，以便以后进行进一步分析。通过仅仅瞥一眼数据就能够塑造数据并了解环境行为，有助于提高运营效率。

监控使我们能够在问题发生或变成更大问题之前主动检测问题。这是通过观察趋势来实现的，这绝对是实施和设计监控解决方案的最关键原因之一。我们还谈到了能够主动采取行动，以及这如何有助于减少停机时间和解决问题上的浪费金钱；通过塑造数据可以实现这一点。

性能也是受益于数据分析的领域。您可能还记得之前章节提到的，能够基线和测量性能使得在设计解决方案时能够进行细粒度控制。拥有历史数据可以帮助做出影响设计性能的决策，同时还可以根据来自运行环境的真实数据来规划预算。

我们介绍了拥有集中式日志系统的主要原因，它可以帮助简化管理任务；而不是连接到环境中的每个系统，从单个位置查看所有日志可以节省时间，并且可以进行更快，更高效的调查。

我们还概述了 ELK Stack 的每个组件。 Elasticsearch 是主要组件，用于存储和分析数据。我们注意到它非常快，因为数据存储为 JSON 文档；解决方案可扩展，因为可以轻松添加节点；并且高度可用，因为数据分布在节点之间。

Logstash 通过插件提供数据转换和过滤，例如 GROK，它可以将`SYNTAX`与`SEMANTIC`进行匹配，例如将 IP 与客户端进行匹配。

最后，我们看了 Kibana 如何通过允许数据可视化和通过全面的图形进行分析来连接所有其他组件。

在下一章中，我们将介绍每个组件的要求。

# 问题

1.  监控是什么？

1.  监控如何帮助做出业务决策？

1.  如何主动检测问题？

1.  监控如何允许性能基线？

1.  监控如何帮助识别异常行为？

1.  集中日志的主要需求是什么？

1.  Elasticsearch 是什么？

1.  Elasticsearch 以什么格式存储数据？

1.  Logstash 是什么？

1.  Kibana 是什么？

# 进一步阅读

+   *James Lee, Tao Wei 的《实战大数据建模》：*[`www.packtpub.com/big-data-and-business-intelligence/hands-big-data-modeling`](https://www.packtpub.com/big-data-and-business-intelligence/hands-big-data-modeling)

+   *Hector Cuesta, Dr. Sampath Kumar 的《实用数据分析-第二版》：*[`www.packtpub.com/big-data-and-business-intelligence/practical-data-analysis-second-edition`](https://www.packtpub.com/big-data-and-business-intelligence/practical-data-analysis-second-edition)


# 第十一章：设计一个 ELK Stack

设计一个符合要求规格的**Elastic Stack**需要特别注意。**Elasticsearch，Logstash 和 Kibana**（**ELK**）的每个组件都有特定的要求。正确的大小对于最佳性能和功能至关重要。

本章将介绍在部署 Elastic Stack 时的设计考虑因素，考虑到每个组件的需求以及特定的设置细节。在本章中，我们将描述每个组件如何受不同资源影响，如何处理资源约束，以及如何计划和为不同场景进行大小调整。

在本章中，我们将讨论以下主题：

+   Elasticsearch CPU 大小要求

+   内存大小如何影响 Elasticsearch 性能

+   Elasticsearch 中数据的存储方式以及如何为性能进行大小调整

+   Logstash 和 Kibana 的要求

# 技术要求

尽管在[`www.elastic.co/guide/en/elasticsearch/guide/current/hardware.html`](https://www.elastic.co/guide/en/elasticsearch/guide/current/hardware.html)找到的文档已经过时，但硬件要求可以作为 CPU 大小的起点。有关更有用的文档，请访问以下链接：

+   **索引速度设置指南：**[`www.elastic.co/guide/en/elasticsearch/reference/current/tune-for-indexing-speed.html`](https://www.elastic.co/guide/en/elasticsearch/reference/current/tune-for-indexing-speed.html)

+   **更改 Elasticsearch 的堆配置：**[`www.elastic.co/guide/en/elasticsearch/reference/current/heap-size.html`](https://www.elastic.co/guide/en/elasticsearch/reference/current/heap-size.html)

+   **平均系统内存延迟：**[`www.crucial.com/usa/en/memory-performance-speed-latency`](http://www.crucial.com/usa/en/memory-performance-speed-latency)

+   **Elasticsearch 系统路径：**[`www.elastic.co/guide/en/elasticsearch/reference/master/path-settings.html`](https://www.elastic.co/guide/en/elasticsearch/reference/master/path-settings.html)

+   **Logstash 持久队列：**[`www.elastic.co/guide/en/logstash/current/persistent-queues.html`](https://www.elastic.co/guide/en/logstash/current/persistent-queues.html)

+   **Logstash 目录路径：**[`www.elastic.co/guide/en/logstash/current/dir-layout.html`](https://www.elastic.co/guide/en/logstash/current/dir-layout.html)

# Elasticsearch CPU 要求

与任何软件一样，为正确的 CPU 要求进行大小调整决定了整体应用程序的性能和处理时间。错误的 CPU 配置可能导致应用程序无法使用，因为处理时间太长而使用户感到沮丧，更不用说慢处理时间可能导致应用程序完全失败。

虽然 Elasticsearch 在索引和搜索时并不严重依赖 CPU，但在设计一个性能良好且及时返回结果的 Elastic Stack 时需要考虑几件事情。

尽管 Elastic 没有发布 CPU 的硬性要求，但有一些可以作为经验法则的事情。

# CPU 数量

通常，拥有更多的核心更好，对于大多数工作负载来说可能是这样。Elasticsearch 通过在多个 CPU 上调度任务来利用系统上可用的多个核心；然而，它并不需要大量的 CPU 处理能力，因为大部分操作是在已经索引的文件上执行的。

大多数云提供商（如果您在云上部署）对高 CPU 数量的虚拟机有提高的费率，为了避免不必要的成本，应该选择一个内存比 CPU 更多的 VM 类型。

在为足够的 CPU 资源进行调整时，应允许一定的增长空间，而无需在中途更改设置。对于小型设置，至少需要两个 CPU。对于测试目的和少量索引/来源，甚至一个 CPU 就足够了，但性能会受到影响，特别是如果所有组件（Elasticsearch、Logstash 和 Kibana）都部署在同一系统上。

# CPU 速度

虽然没有关于最低 CPU 速度（时钟速度）要求的硬性文件，但现在很难找到低于 2 GHz 的 CPU。这个低水位似乎是 Elasticsearch 避免问题的最低要求。

即使只有一个 CPU，超过 2 GHz 的性能也是可以接受的；这对于测试目的是足够的。对于生产环境，寻找时钟速度超过 2 GHz 或 2.3 GHz 的 CPU 以避免问题。

# CPU 性能影响

如果在 CPU 方面配置不正确，Elasticsearch 主要会在以下三个方面受到影响：

+   启动时间

+   每秒索引

+   搜索延迟

# 启动

在启动时，CPU 使用率可能会急剧上升，因为 JVM 启动并且 Elasticsearch 从集群中读取数据。较慢的 CPU 配置将导致 Elasticsearch 启动时间较长。

如果 Elasticsearch 节点需要不断重启，正确的 CPU 配置将有助于减少达到运行状态所需的时间。

# 每秒索引

CPU 配置直接影响 Elasticsearch 能够处理的每秒索引数量，因为一旦索引更多文档，CPU 就会耗尽。理想情况下，具有多个核心的 Elasticsearch 可以利用多个 CPU 进行索引，允许更多客户端发送数据而不会丢失任何指标或事件。

# 搜索延迟

性能可能会在搜索返回结果所需的时间方面受到最大影响。请记住，Elasticsearch 的主要特点之一是它可以多快地检索数据并显示数据。

CPU 配置不足会导致搜索时间超出预期，这可能导致用户体验不佳。

在下面的截图中，我们可以看到搜索延迟急剧上升到近 80 毫秒，并在 20 毫秒左右徘徊：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-arch/img/95698154-0f2a-4dad-abf0-75341cd8088d.png)

在 Kibana 中监控延迟

请注意，上述截图是从一个只有一个低于 2 GHz 运行的 CPU 的配置不足的系统中获取的。延迟可能会更糟，但这是从一个运行在快速 NVMe 驱动器上的系统中获取的，这可以使延迟低至 100 微秒。

# 建议

为了获得最佳结果，需要实施正确的 CPU 设置。以下两种主要情况影响 CPU 大小：

+   测试/开发

+   生产

# 测试/开发

对于测试，任何超过一个 CPU 和 2 GHz 的东西对于小型测试都足够了，有几个客户端向 Elasticsearch 发送数据。搜索结果可能会有点慢，但不会出现任何问题。

# 生产

对于生产环境，请确保使用至少 2.3 GHz 或更高的 CPU。CPU 数量并不会对性能产生很大影响，但至少需要两个 CPU 才能确保最佳运行。一旦添加了更多客户端，CPU 数量可能需要进行修改以满足额外需求；如果 CPU 成为约束，可以添加更多的 Elasticsearch 节点。

最后，在核心数量与时钟速度之间进行选择时，Elasticsearch 利用具有多个核心。较少但更快的核心的性能优势并不像拥有更多较慢核心那样令人印象深刻。

在 Azure 上部署时，可以使用 DS2v3 VM 类型进行小型设置，因为它提供了两个 CPU 和足够的 RAM 以满足基本需求。

一旦正确调整了 CPU 大小，我们可以专注于系统内存（RAM）如何影响 Elasticsearch 的性能和可用性。

# Elasticsearch 的内存大小

为 Elasticsearch 分配足够的 RAM 可能是要考虑的最重要的资源因素，以避免问题和性能不佳的设置。

内存是一种资源，拥有大量内存从来不是问题。作为架构师，在调整内存大小时需要考虑几件事情。与 CPU 资源类似，没有关于最低内存要求的硬性文件。

# 文件系统缓存

拥有大量 RAM 总是一个好主意，因为文件系统缓存或 Linux 页面缓存。

内核使用空闲系统内存来缓存、读取或写入请求，通过将一部分 RAM 分配给 I/O 请求，大大加快了 Elasticsearch 的搜索或索引速度。

如下截图所示，内核已分配大约 1.2GB 作为页面缓存：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-arch/img/94cabe7d-acca-4cd1-baec-b009b8ea24e8.png)

利用页面缓存可以帮助减少搜索或传入索引时的响应时间；确保尽可能调整 RAM 大小。有一个点会平衡缓存使用，不会再有更多的 RAM 用于页面缓存。在这一点上，值得监控进程，以尝试识别这个阈值，避免不必要的费用。举个例子，如果一个虚拟机（VM）被调整为 32GB 的 RAM，但只使用大约 10GB 用于缓存，从未超过这个数字，那么调整为更小的 VM 可能是值得的，因为剩余的 RAM 将被闲置。

如下截图所示，在 Kibana 仪表板中，您可以监控 Elasticsearch 的缓存使用情况，这可能有助于确定是否有资源被闲置：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-arch/img/063feca8-d22e-4fc0-8256-d4107c6a8235.png)

监控 Elasticsearch 的缓存使用情况

# 禁用交换

交换是一种机制，允许内核在不经常访问或内存压力（即系统内存不足）时将内存页面移动到磁盘上。交换的主要问题之一是，当内存页面移动到磁盘时，其访问时间比在 RAM 中要慢得多。

DDR4 内存的平均传输速率约为 10GB/s，更令人印象深刻的是，平均响应时间（或延迟）仅为 13 纳秒。将其与市场上甚至最快的 NVMe SSD 驱动器进行比较，后者的传输速率仅为 3.5GB/s，延迟约为 400 微秒。您很快就会意识到这成为一个问题：并非所有的云提供商或本地设置都使用 NVMe 驱动器，甚至交换到速度更慢的旋转介质都可能产生非常糟糕的结果。

因此，Elasticsearch 建议禁用所有形式的交换，而是依赖于正确的系统内存大小。

# 内存不足

错误的内存配置将导致不同的行为。可以归结为两种不同的情况：内存不足但足够运行系统，以及内存不足以至于 Elasticsearch 甚至无法启动。

在第一种情况下，存在内存约束，但有足够的内存让 Elasticsearch 启动和运行，主要问题是没有足够的内存用于页面缓存，导致搜索缓慢，每秒索引减少。在这种情况下，Elasticsearch 能够运行，但整体性能有所降低。

另一种情况可以分为两种不同的情况：一种是没有足够的内存启动 Elasticsearch，另一种是 Elasticsearch 能够启动，但一旦添加了一些索引，就会耗尽内存。为了避免系统崩溃，Linux 有一个称为“内存不足杀手”的机制。

# 无法启动

Elasticsearch 使用 JVM，默认情况下设置为使用至少 1GB 的堆内存。这意味着 Java 需要为 JVM 分配至少 1GB 的 RAM，因此要使 Elasticsearch 以最低配置启动，需要大约 2.5GB 的 RAM。

最简单的方法是通过使用`systemctl status elasticsearch`来验证 Elasticsearch 服务的状态，它将返回类似于以下的错误消息：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-arch/img/57c77d4e-6e95-433b-b5ca-56f62fcf3ec8.png)

在进一步检查错误日志时，我们可以清楚地看到 JVM 未能分配所需的内存，如下面的代码所示：

```
# There is insufficient memory for the Java Runtime Environment to continue.
# Native memory allocation (mmap) failed to map 899284992 bytes for committing reserved memory.
# Possible reasons:
#   The system is out of physical RAM or swap space
#   In 32 bit mode, the process size limit was hit
# Possible solutions:
#   Reduce memory load on the system
#   Increase physical memory or swap space
#   Check if swap backing store is full
#   Use 64 bit Java on a 64 bit OS
#   Decrease Java heap size (-Xmx/-Xms)
#   Decrease number of Java threads
#   Decrease Java thread stack sizes (-Xss)
#   Set larger code cache with -XX:ReservedCodeCacheSize=
# This output file may be truncated or incomplete.
#
#  Out of Memory Error (os_linux.cpp:2760), pid=933, tid=0x00007f1471c0e700
```

使用默认的 1 GB 堆进行测试已经足够。对于生产环境，请确保将堆大小增加到至少 2 GB，并根据需要进行调整。

要增加堆大小，请编辑`/etc/elasticsearch/jvm.options`文件并找到以下选项：

```
-Xms1g
-Xmx1g
```

将这两个选项更改为以下内容：

```
-Xms2g
-Xmx2g
```

`-Xms2g`短语表示 Java 应具有 2 GB 的最小堆，`-Xmx2g`表示 2 GB 的最大堆。

# OOM 杀手

**内存不足杀手**（**OOM killer**）机制的主要目的是通过杀死正在运行的进程来避免系统崩溃。每个进程都有一个`oom_score`值。OOM killer 根据这个分数决定要杀死哪个进程；分数越高，进程在内存饥饿情况下被杀死的可能性就越大。这个分数是根据进程如果被杀死会释放多少内存来计算的。

如果我们以前的情景作为起点，Elasticsearch 能够以最少 2.5 GB 启动，一旦更多的索引/源添加到 Elasticsearch，它将开始需要更多的系统内存，直到没有更多的内存，并且系统接近完全崩溃。在那一刻，OOM killer 将跳入并杀死占用最多内存的进程（或进程）—在我们的情况下，是 Elasticsearch。

当查看`/var/log/messages`下的事件时，我们可以看到 OOM killer 何时启动并杀死 Java 进程，然后 Elasticsearch 服务失败，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-arch/img/e60a2a14-9647-4e00-991c-6ff60d1f572e.png)

# 建议

理想情况下，应为 Elasticsearch 分配足够的内存。内存的最低要求约为 2.5 GB，但这可能会导致系统很快耗尽内存。

对于测试目的，2.5 GB 对于一些源/索引可能足够。性能无疑会受到影响，但它仍然可以使用。

对于生产环境，请确保至少有 4 GB 或更多的系统内存。这应该允许 Elasticsearch 正常启动并运行多个配置的源/索引。确保相应增加 JVM 的堆大小，并考虑为页面缓存留出一些 RAM，以便在与文件系统交互时获得更快的响应时间。

接下来，我们将看一下 Elasticsearch 所需的存储配置。

# Elasticsearch 的存储配置

Elasticsearch 的存储需求相对简单，可以分为两个主要类别：

+   存储容量

+   存储性能

让我们一起看看这两个选项，以及这里做出的决定如何影响整体性能。

# 容量

存储容量直接影响 Elasticsearch 能够存储多少数据。与许多其他情况一样，这是一个需要考虑的重要和复杂的要求，因为它取决于许多其他影响空间利用的变量。

主要变量将是发送到 Elasticsearch 的日志/指标的大小。这取决于每天（或每月）生成的日志数量。例如，如果每天的日志速率为 100 MB，那么这意味着至少需要 3 GB 的可用空间才能存储一个月的日志（100 MB x 30 天 = 3 GB）。

请注意，这是单个来源所需的最小空间。理想情况下，应该考虑一些额外空间，因为数据会经常变化，每天的 100MB 可能不是每个月的所有天都是恒定的，或者其他月份可能由于负载增加而有更高的速率。此外，一旦添加更多来源（或客户端），数据使用量将相应增长。

默认情况下，Elasticsearch 将其数据存储在`/var/lib/elasticsearch`目录下。

# 性能

Elasticsearch 的主要特点之一是其能够非常快速地检索数据。虽然这是通过使用增强的存储文档的机制来实现的，但正确的性能设置肯定有助于实现几乎实时的搜索结果。

Elastic 没有提供存储需求的硬性数字，但在`/var/lib/elasticsearch`目录中使用固态硬盘（SSD）有助于减少搜索时的延迟，因为与 HDD 相比，SSD 的延迟显著较低。SSD 还有助于数据摄入，因为写入会更快得到确认，从而允许更多并发的传入索引。这反映在 Kibana 监控仪表板上可以看到的每秒索引数中。

在云端进行大小设置，这实际上取决于提供商，因为有些提供商将磁盘的性能基于其大小，但其他提供商允许手动配置性能（如 IOPS 和吞吐量）。

拥有较慢的设置将导致搜索时间比预期的长，以及数据摄入速度较慢，因为磁盘设置不可靠且较慢。

# 考虑事项

对于空间，考虑一个大小，可以为意外的数据增长提供足够的空间。例如，如果整个月的预期数据使用量为 500GB，那么至少考虑 700GB 的大小；这样可以给您一个缓冲区，并避免出现没有足够空间留给 Elasticsearch 索引的情况。500GB 是一个很好的起点，因为它为测试/生产提供了足够的空间，同时可以计算实际数据使用量和数据变化（如果之前未知）。

为了提高性能，考虑使用更快的存储解决方案，如 SSD，以实现低延迟搜索和更快的索引。对于云端，大多数提供商都有一些可以与 Elasticsearch 一起使用的 SSD 产品。确保至少为了获得最佳性能而配置了至少 500 IOPS。

对于 Azure，您可以使用 P10 磁盘——这是一种 SSD，可以提供高达 500 IOPS 的性能——或者选择成本更低的 E10 作为替代方案，以达到相同的效果。

现在我们将看看 Logstash 和 Kibana 需要考虑的内容。

# Logstash 和 Kibana 的要求

对于 Logstash 和 Kibana 没有特定的要求，但在设计 Elastic Stack 时要考虑一些事项总是一个好方法。

# Logstash

Logstash 对 CPU 和内存的要求不高，但这完全取决于有多少来源在向 Logstash 提供数据，因为 Logstash 解析每个事件都需要一些额外的开销来完成这个过程。如果 Logstash 要单独安装（没有其他组件在同一系统上），那么一个 vCPU 和 2GB 的 RAM 应该足够小型/测试部署。理想情况下，应该监控实际使用情况并相应地调整系统。Logstash 默认具有用于临时存储事件的内存队列；当处理事件时，这种行为可以更改为使用持久队列。这样可以实现持久一致性，并避免在故障期间丢失数据。此外，持久队列有助于吸收事件的突发增长，充当客户端和 Logstash 之间的缓冲区。

在使用持久队列进行存储容量时，`/var/lib/logstash`目录需要能够在 Logstash 处理事件时存储事件。空间量取决于两个因素：将数据发送到 Elasticsearch 的出口速度和发送到 Logstash 的事件数量。最低要求为 1GB，当来源数量增加时，空间需要相应增加。

# Kibana

Kibana 的要求完全取决于同时访问仪表板的用户数量。分配给 Kibana 的资源量需要根据预期的使用情况来确定，例如，预期的用户群是什么？这些用户中有多少人会同时访问 Kibana？

对于小型部署/测试，最低要求由 JVM 决定。一个 vCPU 和 2GB 的 RAM 对于几个用户来说足够了，但一旦更多用户开始使用仪表板，RAM 将成为第一个资源瓶颈。

一般来说，Elastic Stack 有相当宽松的要求，主要由使用和来源数量决定。在软件方面，主要要求是 Java；由于所有组件都使用 JVM，因此可以使用 open JDK 或官方 JDK。

# 摘要

在本章中，我们介绍了在设计使用 Elasticsearch、Logstash 和 Kibana 的 Elastic Stack 时所需的要求。对于 Elasticsearch，我们确定了小型设置的最低 CPU 要求为两个 vCPU，CPU 速度应保持在 2 GHz 以上。如果不满足这些最低要求，Elasticsearch 将需要更长的时间启动，并且性能将更慢。这表现为每秒索引数量的减少和搜索延迟的增加，这两者都是需要避免的，以便我们能够充分利用 Elasticsearch 提供的几乎即时搜索。

在设计 Elasticsearch 设置时，内存大小可能是最重要的规格。系统内存的一部分将用于文件系统缓存（也称为页面缓存），这有助于搜索和每秒索引。不建议交换，因为与实际的 RAM 访问相比，它被认为是非常慢的，因此应该在 Elasticsearch 节点上禁用交换。如果未满足正确的内存要求，Elasticsearch 将无法启动，因为 JVM 启动时没有足够的内存。另一方面，如果有足够的内存来启动 JVM，但随着时间的推移负载增加，系统耗尽内存，OOM 或内存耗尽杀手将被启用，以避免导致应用程序失败的系统崩溃。所需的最小 RAM 量为 2.5 GB，但资源限制将相对快速地被看到。

在设置 Elasticsearch 时，存储容量和性能起着重要作用。容量取决于需要保留的数据量和配置的来源数量。延迟需要保持在最低水平，以便我们的搜索速度快。理想情况下，应该使用 SSD。

最后，对于 Logstash 和 Kibana，每个组件的最低要求是一个 vCPU 和 2GB 的 RAM。对于 Logstash，持久队列有空间要求。

在下一章中，我们将利用本章学到的知识，跳入使用 Elasticsearch、Logstash 和 Kibana 部署 Elastic Stack。

# 问题

1.  Elasticsearch 建议使用多少个 CPU？

1.  Elasticsearch 的推荐最低 CPU 速度是多少？

1.  拥有错误的 CPU 配置会如何影响 Elasticsearch 的性能？

1.  什么是页面缓存？

1.  为什么建议在 Elasticsearch 节点上禁用交换？

1.  内存不足会如何影响 Elasticsearch？

1.  Elasticsearch 的最低内存要求是多少？

1.  Elasticsearch 默认存储数据的位置在哪里？

1.  为什么建议使用 SSD 来进行 Elasticsearch？

1.  Logstash 的最低要求是什么？

1.  什么是持久队列？

1.  什么影响了 Kibana 的资源使用？

# 进一步阅读

想要了解更多信息，您可以阅读以下书籍：

+   《Linux：强大的服务器管理》，作者 Uday R. Sawant 等人：[`www.packtpub.com/networking-and-servers/linux-powerful-server-administration`](https://www.packtpub.com/networking-and-servers/linux-powerful-server-administration)


# 第十二章：使用 Elasticsearch、Logstash 和 Kibana 管理日志

部署 Elasticsearch、Logstash 和 Kibana（ELK Stack）相对简单，但在安装这些组件时需要考虑几个因素。虽然这不会是 Elastic Stack 的深入指南，但主要的收获将是实施方面、在过程中做出的决策以及作为架构师在做出这些决策时应该考虑的方式。

本章将帮助您作为架构师定义部署 ELK Stack 所需的方面，以及在使用组成 Elastic Stack 的组件时要使用的配置。

在本章中，我们将讨论以下主题：

+   安装和配置 Elasticsearch

+   安装和配置 Logstash 和 Kibana

+   安装和解释 Beats

+   配置 Kibana 仪表板

# 技术要求

本章将使用以下工具和安装：

+   **Elasticsearch 安装指南**: [`www.elastic.co/guide/en/elasticsearch/reference/current/_installation.html`](https://www.elastic.co/guide/en/elasticsearch/reference/current/_installation.html)

+   **XFS 条带大小和条带单元“如何”**: [`xfs.org/index.php/XFS_FAQ#Q:_How_to_calculate_the_correct_sunit.2Cswidth_values_for_optimal_performance`](http://xfs.org/index.php/XFS_FAQ#Q:_How_to_calculate_the_correct_sunit.2Cswidth_values_for_optimal_performance)

+   **XFS 写屏障**: [`access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/storage_administration_guide/writebarrieronoff`](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/storage_administration_guide/writebarrieronoff)

+   **Elasticsearch 配置细节**: [`www.elastic.co/guide/en/elasticsearch/reference/current/settings.html`](https://www.elastic.co/guide/en/elasticsearch/reference/current/settings.html)

+   **避免 Elasticsearch 中的脑裂**: [`www.elastic.co/guide/en/elasticsearch/reference/current/modules-node.html#split-brain`](https://www.elastic.co/guide/en/elasticsearch/reference/current/modules-node.html#split-brain)

+   **Elasticsearch 集群状态 API**: [`www.elastic.co/guide/en/elasticsearch/reference/current/cluster-state.html`](https://www.elastic.co/guide/en/elasticsearch/reference/current/cluster-state.html)

+   **Logstash 安装指南**: [`www.elastic.co/guide/en/logstash/current/installing-logstash.html`](https://www.elastic.co/guide/en/logstash/current/installing-logstash.html)

+   **Kibana 用户指南和安装方法**: [`www.elastic.co/guide/en/kibana/current/rpm.html`](https://www.elastic.co/guide/en/kibana/current/rpm.html)

+   **Beats 模块的 Logstash 过滤器示例**: [`www.elastic.co/guide/en/logstash/current/logstash-config-for-filebeat-modules.html`](https://www.elastic.co/guide/en/logstash/current/logstash-config-for-filebeat-modules.html)

+   **Logstash 配置文件的结构**: [`www.elastic.co/guide/en/logstash/current/configuration-file-structure.html`](https://www.elastic.co/guide/en/logstash/current/configuration-file-structure.html)

+   **Filebeat 安装过程**: [`www.elastic.co/guide/en/beats/filebeat/current/filebeat-installation.html`](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-installation.html)

+   **Metricbeat 安装概述和细节**: [`www.elastic.co/guide/en/beats/metricbeat/current/metricbeat-installation.html`](https://www.elastic.co/guide/en/beats/metricbeat/current/metricbeat-installation.html)

# 部署概述

对于此部署，我们将使用 Elasticsearch 版本 6.5（这是撰写时的最新版本）。这意味着所有后续组件必须是相同的版本。基本操作系统将是 CentOS 7.6。虽然此特定部署将在本地虚拟机（VM）设置上实施，但这些概念仍然可以应用于云。

Elasticsearch 将使用 2 个节点在 2 个 vCPU VM 上部署，每个节点配备 4 GB 的 RAM（在第十一章中，*设计 ELK 堆栈*，我们确定了所需的最小 RAM 约为 2.5 GB）。VM 的底层存储为**非易失性内存表达**（**NVMe**），因此在其他地方复制设置时需要考虑一些因素。就空间而言，Elasticsearch 节点将分别具有 64 GB 的磁盘空间；节点将把 64 GB 磁盘挂载到`/var/lib/elasticsearch`目录。

Logstash 和 Kibana 将在相同的 VM 上部署，使用 2 个 vCPU 和 4 GB 的 RAM。如第十一章所示，*设计 ELK 堆栈*，Logstash 需要持久存储队列。因此，我们将使用一个 32 GB 的专用磁盘。该磁盘将挂载到`/var/lib/logstash`目录以进行持久排队。

我们可以总结部署所需的内容如下：

+   基本操作系统是 CentOS 7.6

+   Elasticsearch v6.5

+   Logstash v6.5

+   Kibana v6.5

+   Elasticsearch 使用 2 个节点在 2 个 vCPU VM 上，每个节点配备 4 GB 的 RAM

+   在单个 VM 上使用 2 个 vCPU 和 4 GB 的 RAM 部署 Logstash 和 Kibana

+   Elasticsearch 节点使用 64 GB 磁盘

+   32 GB 磁盘用于 Logstash 持久队列

以下图表说明了整个实施过程，并将让您了解事物是如何连接的：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-arch/img/a387ec77-f6d5-4e5f-9632-2a9751668a69.png)

# 安装 Elasticsearch

从无到有的功能性 Elasticsearch 设置需要安装软件；这可以通过多种方式和不同平台完成。以下是一些安装选项：

+   从源代码安装

+   为基于 Debian 的 Linux 发行版安装`deb`

+   为**Red Hat Enterprise Linux**（**RHEL**）、CentOS、**嵌入式系统的声音库**（**SLES**）、OpenSLES 和基于 RPM 的发行版安装`rpm`

+   为 Windows 安装`msi`

+   部署 Docker 镜像

对于此设置，我们将使用 RPM 存储库以保持版本一致，并在更新可用时简化目的。

# RPM 存储库

要安装 RHEL 和 CentOS 的 RPM 存储库，我们需要在`/etc/yum.repos.d`目录中创建一个文件。在这里，文件的名称并不重要，但实际上，它需要有意义。文件的内容指示了`yum`将如何搜索软件。

创建一个名为`/etc/yum.repos.d/elastic.repo`的文件，其中包含以下代码细节：

```
[elasticsearch-6.x]
name=Elasticsearch repository for 6.x packages
baseurl=https://artifacts.elastic.co/packages/6.x/yum
gpgcheck=1
gpgkey=https://artifacts.elastic.co/GPG-KEY-elasticsearch
enabled=1
autorefresh=1
type=rpm-md
```

创建了存储库文件后，只需运行以下命令：

```
yum makecache
```

这将刷新所有配置的存储库的元数据。在安装 Elasticsearch 之前，我们需要安装 OpenJDK 版本`1.8.0`；为此，我们可以运行以下命令：

```
yum install java-1.8.0-openjdk
```

接下来，确认已安装`java`，如下所示：

```
java -version
```

然后，您应该看到类似以下输出：

```
[root@elastic1 ~]# java -version
openjdk version "1.8.0_191"
OpenJDK Runtime Environment (build 1.8.0_191-b12)
OpenJDK 64-Bit Server VM (build 25.191-b12, mixed mode)
```

然后，我们可以继续安装`elasticsearch`，如下所示：

```
yum install elasticsearch
```

在启动 Elasticsearch 之前，需要进行一些配置。

# Elasticsearch 数据目录

Elasticsearch 的默认配置将数据目录设置为`/var/lib/elasticsearch`路径。这是通过`/etc/elasticsearch/elasticsearch.yml`文件中的`path.data`配置选项控制的：

```
# ---------------------------------Paths-------------------------------
#
# Path to directory where to store the data (separate multiple locations by comma):
#
path.data: /var/lib/elasticsearch
```

在此设置中，将挂载一个 64 GB 的磁盘到此位置。

在 Azure 部署时，请确保`path.data`选项配置为使用数据磁盘而不是操作系统磁盘。

# 磁盘分区

在创建文件系统之前，需要对磁盘进行分区。为此，我们可以使用`parted`实用程序。

首先，我们需要将磁盘初始化为`gpt`；为此，我们可以使用以下命令：

```
sudo parted /dev/sdX mklabel gpt
```

然后，我们创建分区：

```
sudo parted /dev/sdX mkpart xfs 0GB 64GB
```

在这里，我们告诉`parted`从`0GB`到`64GB`创建一个分区，或者从磁盘的开始到结束。此外，我们使用了`xfs`签名，因为这是将用于数据目录的文件系统。

最后，通过运行以下命令验证分区是否已成功创建并具有正确的边界：

```
sudo parted /dev/sdX print
```

输出应类似于以下代码块：

```
[root@elastic1 ~]# parted /dev/sdb print
Model: ATA VBOX HARDDISK (scsi)
Disk /dev/sdb: 68.7GB
Sector size (logical/physical): 512B/512B
Partition Table: gpt
Disk Flags:
Number  Start End     Size    File system  Name Flags
1      1049kB  64.0GB 64.0GB               xfs
```

# 格式化文件系统

要能够在新创建的分区上存储数据，我们首先需要创建一个文件系统。对于此设置，我们将使用 XFS 文件系统。

要格式化磁盘，请运行`mkfs.xfs`命令，如下所示：

```
[root@elastic1]# mkfs.xfs /dev/sdb1
meta-data=/dev/sdb1              isize=512    agcount=4, agsize=3906176 blks
         =                       sectsz=512   attr=2, projid32bit=1
         =                       crc=1        finobt=0, sparse=0
data     =                       bsize=4096   blocks=15624704, imaxpct=25
         =                       sunit=0      swidth=0 blks
naming   =version 2              bsize=4096   ascii-ci=0 ftype=1
log      =internal log           bsize=4096   blocks=7629, version=2
         =                       sectsz=512   sunit=0 blks, lazy-count=1
realtime =none                   extsz=4096   blocks=0, rtextents=0
```

默认情况下，XFS 使用与内存页大小匹配的 4K 块大小；这也适用于相对较小的文件。

请注意，指定了设备文件的分区，而不是整个磁盘。虽然可以使用磁盘本身，但建议在分区上创建文件系统。此外，如果文件系统将用于 RAID 设置，则更改条带单元和条带大小通常有助于提高性能。

# 使用 fstab 进行持久挂载

现在文件系统已经创建，我们需要确保它在每次重启后都能正确挂载到正确的位置。

通常情况下，不建议使用设备文件挂载文件系统，特别是在云中。这是因为磁盘顺序可能会改变，导致磁盘的设备文件混乱。为了解决这个问题，我们可以使用磁盘的 UUID，这是一个唯一的标识符，即使磁盘移动到另一个系统，它也会持续存在。

获取磁盘的 UUID，请运行`blkid`命令：

```
[root@elastic1 ~]# blkid
/dev/sda1: UUID="58c91edb-c361-470e-9805-a31efd85a472" TYPE="xfs"
/dev/sda2: UUID="H3KcJ3-gZOS-URMD-CD1J-8wIn-f7v9-mwkTWn" TYPE="LVM2_member"
/dev/sdb1: UUID="561fc663-0b63-4d2a-821e-12b6caf1115e" TYPE="xfs" PARTLABEL="xfs" PARTUUID="7924e72d-15bd-447d-9104-388dd0ea4eb0"
```

在这种情况下，`/dev/sdb1`是我们将用于 Elasticsearch 的 64GB 磁盘。有了 UUID，我们可以将其添加到控制在启动时挂载的文件系统的`/etc/fstab`文件中。只需编辑文件并添加以下条目：

```
UUID=561fc663-0b63-4d2a-821e-12b6caf1115e       /var/lib/elasticsearch  xfs     defaults,nobarrier,noatime,nofail       0 0
```

以下是从上述命令中需要注意的一些重要细节：

+   `nobarrier`：这有助于写入性能，因为它禁用了 XFS 用于确认写入是否已经到达持久存储的机制。这通常用于物理存储系统，其中没有电池备份写缓存。

+   `noatime`：当文件被访问或修改时，这会禁用记录机制。启用`atime`时，每次读取都会导致一小部分写入，因为访问时间需要更新。禁用可以帮助读取，因为它不会产生任何不必要的写入。

+   `nofail`：这允许系统在支持挂载点的磁盘丢失时正常启动。这在部署在云上且无法访问控制台时特别有帮助。

接下来，在启动 Elasticsearch 服务之前，验证磁盘是否已挂载到正确的位置：

```
[root@elastic1 /]# df -h
Filesystem               Size  Used Avail Use% Mounted on
/dev/mapper/centos-root   14G  1.6G   12G  12% /
devtmpfs                 1.9G     0  1.9G   0% /dev
tmpfs                    1.9G     0  1.9G   0% /dev/shm
tmpfs                    1.9G  8.5M  1.9G   1% /run
tmpfs                    1.9G     0  1.9G   0% /sys/fs/cgroup
/dev/sdb1                 60G   33M   60G   1% /var/lib/elasticsearch
/dev/sda1               1014M  184M  831M  19% /boot
tmpfs                    379M     0  379M   0% /run/user/0
```

最后，确保正确配置了`/var/lib/elasticsearch`目录的所有权：

```
chown elasticsearch: /var/lib/elasticsearch
```

# 配置 Elasticsearch

在启动 Elasticsearch 服务之前，我们需要定义控制 Elasticsearch 行为的几个参数。配置文件以 YAML 格式存储在`/etc/elasticsearch/elasticsearch.yml`中。让我们探讨需要更改的主要参数。

# Elasticsearch YAML

Elasticsearch 的中央控制是通过`/etc/elasticsearch/elasticsearch.yml`文件完成的，该文件以 YAML 格式存储。默认配置文件有相当完整的文档说明每个参数控制的内容，但作为配置过程的一部分，有一些条目应该被更改。

要查找的主要参数如下：

+   集群名称

+   发现设置

+   节点名称

+   网络主机

+   路径设置

# 集群名称

只有当 Elasticsearch 节点在其配置中指定了相同的集群名称时，它们才能加入集群。这是通过`cluster.name`参数处理的；对于此设置，我们将使用`elastic-cluster`：

```
# --------------------------------Cluster------------------------------
#
# Use a descriptive name for your cluster:
#
cluster.name: elastic-cluster
#
```

应该在两个节点上配置此设置，以便它们具有相同的值。否则，第二个节点将无法加入集群。

# 发现设置

发现参数控制 Elasticsearch 如何管理用于集群和主节点选举的节点内通信。

关于发现的两个主要参数是`discovery.zen.ping.unicast.hosts`和`discovery.zen.minimum_master_nodes`。

`discovery.zen.ping.unicast.hosts`设置控制将用于集群的节点。由于我们的设置将使用两个节点，因此`node1`的配置应具有`node2`的 DNS 名称，而`node2`应具有`node1`的 DNS 名称。

`discovery.zen.minimum_master_nodes`设置控制集群中主节点的最小数量；这用于避免出现多个活动主节点的分裂脑场景。可以根据简单的方程式计算此参数的数量，如下所示：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-arch/img/6f0843de-eade-4bc1-ae57-eac32164ff77.png)

在这里，*N*是集群中节点的数量。对于此设置，由于只需配置`2`个节点，设置应为`2`。两个参数应如下所示：

```
# -----------------------------Discovery-------------------------------
#
# Pass an initial list of hosts to perform discovery when new node is started:
# The default list of hosts is ["127.0.0.1", "[::1]"]
#
discovery.zen.ping.unicast.hosts: ["elastic2"]
#
# Prevent the "split brain" by configuring the majority of nodes (total number of master-eligible nodes / 2 + 1):
#
discovery.zen.minimum_master_nodes: 2
#
# For more information, consult the zen discovery module documentation.
```

对于`node2`，将`discovery.zen.ping.unicast.hosts: ["elastic2"]`更改为`discovery.zen.ping.unicast.hosts: ["elastic1"]`。

# 节点名称

默认情况下，Elasticsearch 使用随机生成的 UUID 作为其节点名称，这不太用户友好。该参数相对简单，因为它控制特定节点的名称。对于此设置，我们将使用`elasticX`，其中`X`是节点编号；`node1`应如下所示：

```
#------------------------------Node---------------------------------
#
# Use a descriptive name for the node:
#
node.name: elastic1
```

将`node2`更改为符合命名约定，因此它是`elastic2`。

# 网络主机

这控制 Elasticsearch 将绑定到哪个 IP 地址并监听请求。默认情况下，它绑定到回环 IP 地址；需要更改此设置以允许来自集群的其他节点或允许其他服务器上的 Kibana 和 Logstash 发送请求。此设置还接受特殊参数，例如网络接口。对于此设置，我们将通过将`network.host`参数设置为`0.0.0.0`来使 Elasticsearch 监听所有地址。

在两个节点上，确保设置如下：

```
#-----------------------------Network-------------------------------
#
# Set the bind address to a specific IP (IPv4 or IPv6):
#
network.host: 0.0.0.0
```

# 路径设置

最后，路径参数控制 Elasticsearch 存储其数据和日志的位置。

默认情况下，它配置为将数据存储在`/var/lib/elasticsearch`下，并将日志存储在`/var/log/elasticsearch`下：

```
#-------------------------------Paths---------------------------------
#
# Path to directory where to store the data (separate multiple locations by comma):
#
path.data: /var/lib/elasticsearch
#
# Path to log files:
#
path.logs: /var/log/elasticsearch
```

该参数的一个关键方面是，在`path.data`设置下，可以指定多个路径。Elasticsearch 将使用此处指定的所有路径来存储数据，从而提高整体性能和可用空间。对于此设置，我们将保留默认设置，即在前面的步骤中挂载数据磁盘到`/var/lib/elasticsearch`目录下。

# 启动 Elasticsearch

现在我们已经配置了 Elasticsearch，我们需要确保服务在启动时能够自动正确地启动。

启动并启用 Elasticsearch 服务，如下所示：

```
systemctl start elasticsearch && systemctl enable elasticsearch
```

然后，通过运行以下命令验证 Elasticsearch 是否正确启动：

```
curl -X GET "elastic1:9200"
```

输出应类似于以下代码块：

```
[root@elastic1 /]# curl -X GET "elastic1:9200"
{
 "name" : "elastic1",
 "cluster_name" : "elastic-cluster",
 "cluster_uuid" : "pIH5Z0yAQoeEGXcDuyEKQA",
 "version" : {
 "number" : "6.5.3",
 "build_flavor" : "default",
 "build_type" : "rpm",
 "build_hash" : "159a78a",
 "build_date" : "2018-12-06T20:11:28.826501Z",
 "build_snapshot" : false,
 "lucene_version" : "7.5.0",
 "minimum_wire_compatibility_version" : "5.6.0",
 "minimum_index_compatibility_version" : "5.0.0"
 },
 "tagline" : "You Know, for Search"
}
```

# 添加 Elasticsearch 节点

此时，我们可以将第二个节点添加到 Elasticsearch 集群中。

应将相同的配置应用于先前的步骤，确保更改设置以反映`node2`的 DNS 名称。

要将节点添加到集群，我们只需简单地启动 Elasticsearch 服务。

服务启动时，消息被记录在`/var/log/elasticsearch`，这表明节点已成功添加到集群中：

```
[2018-12-23T01:39:03,834][INFO ][o.e.c.s.ClusterApplierService] [elastic2] detected_master {elastic1}{XVaIWexSQROVVxYuSYIVXA}{fgpqeUmBRVuXzvlf0TM8sA}{192.168.1.150}{192.168.1.150:9300}{ml.machine_memory=3973599232, ml.max_open_jobs=20, xpack.installed=true, ml.enabled=true}, added {{elastic1}{XVaIWexSQROVVxYuSYIVXA}{fgpqeUmBRVuXzvlf0TM8sA}{192.168.1.150}{192.168.1.150:9300}{ml.machine_memory=3973599232, ml.max_open_jobs=20, xpack.installed=true, ml.enabled=true},}, reason: apply cluster state (from master [master {elastic1}{XVaIWexSQROVVxYuSYIVXA}{fgpqeUmBRVuXzvlf0TM8sA}{192.168.1.150}{192.168.1.150:9300}{ml.machine_memory=3973599232, ml.max_open_jobs=20, xpack.installed=true, ml.enabled=true} committed version [1]])
```

您可以使用以下代码来确认集群正在运行：

```
curl -X GET "elastic1:9200/_cluster/state?human&pretty"
```

输出应类似于以下代码块：

```
{
  "cluster_name" : "elastic-cluster",
  "compressed_size" : "10kb",
  "compressed_size_in_bytes" : 10271,
  "cluster_uuid" : "pIH5Z0yAQoeEGXcDuyEKQA",
  "version" : 24,
  "state_uuid" : "k6WuQsnKTECeRHFpHDPKVQ",
  "master_node" : "XVaIWexSQROVVxYuSYIVXA",
  "blocks" : { },
  "nodes" : {
    "XVaIWexSQROVVxYuSYIVXA" : {
      "name" : "elastic1",
      "ephemeral_id" : "fgpqeUmBRVuXzvlf0TM8sA",
      "transport_address" : "192.168.1.150:9300",
      "attributes" : {
        "ml.machine_memory" : "3973599232",
        "xpack.installed" : "true",
        "ml.max_open_jobs" : "20",
        "ml.enabled" : "true"
      }
    },
    "ncVAbF9kTnOB5K9pUhsvZQ" : {
      "name" : "elastic2",
      "ephemeral_id" : "GyAq8EkiQGqG9Ph-0RbSkg",
      "transport_address" : "192.168.1.151:9300",
      "attributes" : {
        "ml.machine_memory" : "3973599232",
        "ml.max_open_jobs" : "20",
        "xpack.installed" : "true",
        "ml.enabled" : "true"
      }
    }
  },
  "metadata" : {
...(truncated)
```

对于需要添加到集群的任何后续节点，应遵循先前的步骤，确保`cluster.name`参数设置为正确的值。

# 安装 Logstash 和 Kibana

有了 Elasticsearch 集群正在运行，我们现在可以继续安装 Logstash 和 Kibana。

在前面步骤中使用的存储库对于剩余的组件是相同的。因此，应该将之前用于添加存储库的相同过程应用于 Logstash 和 Kibana 节点。

这是一个总结，之前已经探讨过相同的过程：

1.  将存储库添加到`/etc/yum.repos.d/elastic.repo`

1.  更新`yum`缓存为`sudo yum makecache`

1.  使用`sudo yum install logstash kibana`安装 Logstash 和 Kibana

1.  为`/var/lib/logstash`初始化磁盘和`sudo parted /dev/sdX mklabel gpt`

1.  创建`sudo parted /dev/sdX mkpart xfs 0GB 32GB`分区（注意这是一个 32GB 磁盘）

1.  创建`sudo mkfs.xfs /dev/sdX1`文件系统

1.  更新`fstab`

1.  更新`sudo chown logstash: /var/lib/logstash`目录权限

Logstash `systemd`单元默认情况下不会被添加；要这样做，运行 Logstash 提供的脚本：

```
sudo /usr/share/logstash/bin/system-install
```

最后，一个特定的组件是必需的，那就是一个协调的 Elasticsearch 节点。这将作为 Elasticsearch 集群的负载均衡器，Kibana 用于安装 Elasticsearch。

```
sudo yum install elasticsearch
```

有关协调节点配置的更多信息在*配置 Kibana*部分提供。

# 配置 Logstash

与 Elasticsearch 类似，Logstash 的主配置文件位于`/etc/logstash/logstash.yml`下，并且某些设置需要更改以实现所需的功能。

# Logstash YAML

首先，应调整`node.name`参数，以便正确标识 Logstash 节点。默认情况下，它使用机器的主机名作为`node.name`参数。然而，由于我们在同一系统上运行 Logstash 和 Kibana，值得改变这个设置以避免混淆。

接下来，我们需要考虑排队设置；这些控制 Logstash 如何管理队列类型以及它存储队列数据的位置。

第一个设置是`queue.type`，它定义了 Logstash 使用的队列类型。对于这个设置，我们使用持久队列：

```
# ------------ Queuing Settings --------------
#
# Internal queuing model, "memory" for legacy in-memory based queuing and
# "persisted" for disk-based acked queueing. Defaults is memory
#
queue.type: persisted
#
```

由于排队设置为持久，事件需要存储在临时位置，然后再发送到 Elasticsearch；这由`path.queue`参数控制：

```
# If using queue.type: persisted, the directory path where the data files will be stored.
# Default is path.data/queue
#
# path.queue:
#
```

如果保持默认设置，Logstash 将使用`path.data/queue`目录来存储队列中的事件。`path.data`目录默认为`/var/lib/logstash`，这是我们配置 32GB 磁盘的位置；这是期望的配置。如果需要指定另一个位置用于排队，应调整此设置以匹配正确的路径。

在`logstash.yml`文件中需要更改的最后一个设置是`queue.max_bytes`设置，它控制队列允许的最大空间。对于这个设置，由于我们为此目的添加了一个专用的 32GB 磁盘，可以将设置更改为 25GB，以便在需要更多空间时提供缓冲。设置应如下所示：

```
# If using queue.type: persisted, the total capacity of the queue in number of bytes.
# If you would like more unacked events to be buffered in Logstash, you can increase the
# capacity using this setting. Please make sure your disk drive has capacity greater than
# the size specified here. If both max_bytes and max_events are specified, Logstash will pick
# whichever criteria is reached first
# Default is 1024mb or 1gb
#
queue.max_bytes: 25gb
```

作为一个选项，`xpack.monitoring.enabled`设置可以设置为 true，以通过 Kibana 启用监视。

确保`yaml`文件中的参数在行首没有空格，否则可能无法加载配置。

# Logstash 管道

Logstash 输出由通过放置在`/etc/logstash/conf.d/`下的文件配置的管道控制；这些文件控制 Logstash 如何摄取数据，处理数据，然后将其作为 Elasticsearch 的输出返回。管道配置类似于以下代码：

```
# The # character at the beginning of a line indicates a comment. Use
 # comments to describe your configuration.
 input {
 }
 # The filter part of this file is commented out to indicate that it is
 # optional.
 # filter {
 #
 # }
 output {
 }
```

在这里，`input`部分定义要接受的数据以及来源；在这个设置中，我们将使用`beats`作为输入。过滤器部分控制数据在发送到输出之前的转换方式，输出部分定义数据发送到哪里。在这种情况下，我们将数据发送到 Elasticsearch 节点。

让我们为`syslog`消息创建一个配置文件，以便通过 Logstash 进行过滤，然后发送到 Elasticsearch 集群。该文件需要放置在`/etc/logstash/conf.d`中，因为输入将来自`beats`模块；让我们称之为`beats-syslog.conf`文件：

```
sudo vim /etc/logstash/conf.d/beats-syslog.conf
```

文件的内容如下：

```
input {
  beats {
    port => 5044
  }
}
filter {
  if [fileset][module] == "system" {
    if [fileset][name] == "auth" {
      grok {
        match => { "message" => ["%{SYSLOGTIMESTAMP:[system][auth][timestamp]} %{SYSLOGHOST:[system][auth][hostname]} sshd(?:\[%{POSINT:[system][auth][pid]}\])?: %{DATA:[system][auth][ssh][event]} %{DATA:[system][auth][ssh][method]} for (invalid user )?%{DATA:[system][auth][user]} from %{IPORHOST:[system][auth][ssh][ip]} port %{NUMBER:[system][auth][ssh][port]} ssh2(: %{GREEDYDATA:[system][auth][ssh][signature]})?",
                  "%{SYSLOGTIMESTAMP:[system][auth][timestamp]} %{SYSLOGHOST:[system][auth][hostname]} sshd(?:\[%{POSINT:[system][auth][pid]}\])?: %{DATA:[system][auth][ssh][event]} user %{DATA:[system][auth][user]} from %{IPORHOST:[system][auth][ssh][ip]}",
                  "%{SYSLOGTIMESTAMP:[system][auth][timestamp]} %{SYSLOGHOST:[system][auth][hostname]} sshd(?:\[%{POSINT:[system][auth][pid]}\])?: Did not receive identification string from %{IPORHOST:[system][auth][ssh][dropped_ip]}",
                  "%{SYSLOGTIMESTAMP:[system][auth][timestamp]} %{SYSLOGHOST:[system][auth][hostname]} sudo(?:\[%{POSINT:[system][auth][pid]}\])?: \s*%{DATA:[system][auth][user]} :( %{DATA:[system][auth][sudo][error]} ;)? TTY=%{DATA:[system][auth][sudo][tty]} ; PWD=%{DATA:[system][auth][sudo][pwd]} ; USER=%{DATA:[system][auth][sudo][user]} ; COMMAND=%{GREEDYDATA:[system][auth][sudo][command]}",
                  "%{SYSLOGTIMESTAMP:[system][auth][timestamp]} %{SYSLOGHOST:[system][auth][hostname]} groupadd(?:\[%{POSINT:[system][auth][pid]}\])?: new group: name=%{DATA:system.auth.groupadd.name}, GID=%{NUMBER:system.auth.groupadd.gid}",
                  "%{SYSLOGTIMESTAMP:[system][auth][timestamp]} %{SYSLOGHOST:[system][auth][hostname]} useradd(?:\[%{POSINT:[system][auth][pid]}\])?: new user: name=%{DATA:[system][auth][user][add][name]}, UID=%{NUMBER:[system][auth][user][add][uid]}, GID=%{NUMBER:[system][auth][user][add][gid]}, home=%{DATA:[system][auth][user][add][home]}, shell=%{DATA:[system][auth][user][add][shell]}$",
                  "%{SYSLOGTIMESTAMP:[system][auth][timestamp]} %{SYSLOGHOST:[system][auth][hostname]} %{DATA:[system][auth][program]}(?:\[%{POSINT:[system][auth][pid]}\])?: %{GREEDYMULTILINE:[system][auth][message]}"] }
        pattern_definitions => {
          "GREEDYMULTILINE"=> "(.|\n)*"
        }
        remove_field => "message"
      }
      date {
        match => [ "[system][auth][timestamp]", "MMM  d HH:mm:ss", "MMM dd HH:mm:ss" ]
      }
      geoip {
        source => "[system][auth][ssh][ip]"
        target => "[system][auth][ssh][geoip]"
      }
    }
    else if [fileset][name] == "syslog" {
      grok {
        match => { "message" => ["%{SYSLOGTIMESTAMP:[system][syslog][timestamp]} %{SYSLOGHOST:[system][syslog][hostname]} %{DATA:[system][syslog][program]}(?:\[%{POSINT:[system][syslog][pid]}\])?: %{GREEDYMULTILINE:[system][syslog][message]}"] }
        pattern_definitions => { "GREEDYMULTILINE" => "(.|\n)*" }
        remove_field => "message"
      }
      date {
        match => [ "[system][syslog][timestamp]", "MMM  d HH:mm:ss", "MMM dd HH:mm:ss" ]
      }
    }
  }
}
output {
  elasticsearch {
    hosts => ["elastic1", "elastic2"]
    manage_template => false
    index => "%{[@metadata][beat]}-%{[@metadata][version]}-%{+YYYY.MM.dd}"
  }
}

```

确保`output`部分具有 Elasticsearch 节点的 DNS 名称或 IP 地址：

```
output {
 elasticsearch {
    hosts => ["elastic1", "elastic2"]
    manage_template => false
    index => "%{[@metadata][beat]}-%{[@metadata][version]}-%{+YYYY.MM.dd}"
 }
}
```

在此管道配置中，`beats`模块将日志发送到 Logstash 节点。然后 Logstash 将处理数据并在 Elasticsearch 节点之间进行负载均衡输出。现在我们可以继续配置 Kibana。

# 配置 Kibana

Elastic Stack 的最后一部分是 Kibana；配置方式与 Elasticsearch 和 Logstash 类似，由`/etc/kibana/kibana.yml`处理。

# Kibana YAML

默认情况下，Kibana 侦听端口`5601`；这由`server.port`参数控制，如果需要在不同端口访问 Kibana，则可以更改。对于此设置，将使用默认设置。

`server.host`设置控制 Kibana 将侦听请求的地址。由于需要从外部来源（即`localhost`之外）访问，我们可以使用以下设置：

```
# Specifies the address to which the Kibana server will bind. IP addresses and host names are both valid values.
 # The default is 'localhost', which usually means remote machines will not be able to connect.
 # To allow connections from remote users, set this parameter to a non-loopback address.
 server.host: "0.0.0.0"
```

`server.name`参数默认为 Kibana 运行的主机名，但由于 Logstash 与 Kibana 一起运行，我们可以更改此参数以标识 Kibana 部分：

```
# The Kibana server's name.  This is used for display purposes.
server.name: "kibana"
```

最后，`elasticsearch.url`指定了 Kibana 将连接到哪个 Elasticsearch 节点。正如我们之前提到的，我们将使用一个 Elasticsearch 协调节点来充当其他两个节点之间的负载均衡器。

以下是用于所有查询的 Elasticsearch 实例的 URL：

```
elasticsearch.url: "http://localhost:9200"
```

# 协调节点

协调节点是一个 Elasticsearch 节点，不接受输入，不存储数据，也不参与主节点或从节点的选举。

该节点的目标是在集群中的不同 Elasticsearch 节点之间负载均衡 Kibana 的请求。安装过程与之前使用的相同，即确保 Java（open JDK）也已安装。

配置将不同，因为我们想要实现一些目标：

+   禁用主节点角色

+   禁用摄入节点角色

+   禁用数据节点角色

+   禁用跨集群搜索

为此，我们需要在`/etc/elasticsearch/elasticsearch.yml`文件中设置以下设置：

```
cluster.name: elastic-cluster
node.name: coordinate
network.host: 0.0.0.0
node.master: false
node.data: false
node.ingest: false
cluster.remote.connect: false
discovery.zen.ping.unicast.hosts: ["elastic1", "elastic2"]
```

# 启动 Logstash 和 Kibana

所有组件已配置完成后，我们可以启动 Logstash、Kibana 和协调 Elasticsearch 节点。

Logstash 可以首先启动，因为它不需要其他组件中的任何一个处于运行状态：

```
sudo systemctl start logstash && sudo systemctl enable logstash
```

然后，我们可以启动和启用`elasticsearch`协调节点：

```
sudo systemctl start elasticsearch && sudo systemctl enable elasticsearch
```

最后，`kibana`可以通过相同的过程进行：

```
sudo systemctl start kibana && sudo systemctl enable kibana
```

要验证所有内容是否正确启动，请将浏览器指向端口`5601`上的`kibana`地址`http://kibana:5601`。单击监控，然后单击启用监控；几秒钟后，您将看到类似以下屏幕截图的内容：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-arch/img/2668b7d3-4572-4ca6-89db-46168cb206fd.png)

您应该看到所有组件都在线；**黄色**状态是由于未复制的系统索引，但这是正常的。

有了这些，集群已经运行起来，准备好接受来自日志和指标的传入数据。我们将使用 Beats 向集群提供数据，我们将在下一节中探讨。

# Beats 是什么？

Beats 是 Elastic.co（Elasticsearch 背后的公司）的轻量级数据发货人。Beats 旨在易于配置和运行。

Beats 是方程式的客户端部分，驻留在要监视的系统上。Beats 从环境中的服务器捕获指标、日志等，并将它们发送到 Logstash 进行进一步处理，或者发送到 Elasticsearch 进行索引和分析。

有多个官方 Beats（由 Elastic 开发和维护），社区还开发了大量的开源 Beats。

我们将在此设置中使用的主要 Beats 是**Filebeat**和**Metricbeat**。

# Filebeat

Filebeat 功能从来源（如 syslog、Apache 和 Nginx）收集日志，然后将其发送到 Elasticsearch 或 Logstash。

需要在需要数据收集的每台服务器上安装 Filebeat 客户端才能启用。该组件允许将日志发送到集中位置进行无缝搜索和索引。

# Metricbeat

Metricbeat 收集指标，如 CPU 使用率、内存使用率、磁盘 IO 统计和网络统计，然后将其发送到 Elasticsearch 或 Logstash。

实际上，没有必要进一步转换度量数据，因此直接将数据馈送到 Elasticsearch 更有意义。

应在需要监视资源使用情况的所有系统中安装 Metricbeat；在 Elasticsearch 节点上安装 Metricbeat 可以让您更密切地控制资源使用情况，以避免问题。

还有其他 Beats，例如以下内容：

+   **Packetbeat**：用于网络流量监控

+   **Journalbeat**：用于`systemd`日志

+   **Auditbeat**：用于审计数据，如登录

此外，Beats 可以通过模块进一步适应特定需求。例如，Metricbeat 具有一个模块用于收集 MySQL 性能统计信息。

# 让我们不要错过一拍-安装 Beats

通过 Elasticsearch 提供的 Beats 的安装可以通过之前用于安装 Elasticsearch、Logstash 和 Kibana 的 Elastic 存储库来完成。

首先，在 Elasticsearch 节点中安装 Filebeat：

```
sudo yum install -y filebeat
```

安装后，通过运行以下代码确认已完成：

```
filebeat version
```

输出应类似于以下命令块：

```
[root@elastic1 ~]# filebeat version
filebeat version 6.5.4 (amd64), libbeat 6.5.4 [bd8922f1c7e93d12b07e0b3f7d349e17107f7826 built 2018-12-17 20:22:29 +0000 UTC]
```

要安装`metricbeat`，过程与它位于同一存储库相同：

```
sudo yum install metricbeat
```

要在其他客户端上安装 Beats，只需像之前解释的那样添加 Elastic 存储库并通过`yum`安装即可。如果分发中没有可用的存储库，Beats 也可以作为独立软件包提供。

# 配置 Beats 客户端

在 Elasticsearch 节点上安装了 Filebeat 和 Metricbeat 后，我们可以继续配置它们将数据馈送到 Logstash 和 Elasticsearch。

# Filebeat YAML

现在，毫无疑问，大多数 Elastic 组件都是通过 YAML 文件进行配置的。Filebeat 也不例外，其配置由`/etc/filebeat/filebeat.yml`文件处理。

首先，我们需要告诉`filebeat`在哪里查找要发送到 Logstash 的日志文件。在`yaml`文件中，这在`filebeat.inputs`部分中；将`enabled: false`更改为`enabled: true`，如下所示：

```
#=========================== Filebeat inputs =============================
filebeat.inputs:
# Each - is an input. Most options can be set at the input level, so
# you can use different inputs for various configurations.
# Below are the input specific configurations.
- type: log
 # Change to true to enable this input configuration.
 enabled: true
 # Paths that should be crawled and fetched. Glob based paths.
 paths:
    - /var/log/*.log
```

Filebeat 附带了 Kibana 仪表板，便于可视化发送的数据。这允许 Filebeat 加载仪表板，然后将 Kibana 地址添加到`setup.kibana`部分：

```
#==============================Kibana================================
# Starting with Beats version 6.0.0, the dashboards are loaded via the Kibana API.
# This requires a Kibana endpoint configuration.
setup.kibana:
 # Kibana Host
 # Scheme and port can be left out and will be set to the default (http and 5601)
 # In case you specify and additional path, the scheme is required: http://localhost:5601/path
# IPv6 addresses should always be defined as: https://[2001:db8::1]:5601
 host: "kibana:5601"
```

加载`dashboards`，如下所示：

```
filebeat setup --dashboards
```

此配置只需要针对每个新的 Beat 安装执行一次；在进一步安装 Filebeat 时无需更改此设置，因为仪表板已经加载。

由于我们将要将数据发送到 Logstash，因此注释掉`output.elasticsearch`部分；然后取消注释`output.logstash`部分并添加 Logstash 的详细信息：

```
#------------------------ Elasticsearch output ----------------------------
#output.elasticsearch:
 # Array of hosts to connect to.
 # hosts: ["localhost:9200"]
 # Optional protocol and basic auth credentials.
 #protocol: "https"
 #username: "elastic"
 #password: "changeme"
#-------------------------- Logstash output -------------------------------
output.logstash:
 # The Logstash hosts
 hosts: ["logstash:5044"]

```

接下来，我们将使用 Filebeat 的系统模块将输出发送到 Logstash；要启用此功能，只需运行以下命令：

```
filebeat modules enable system
```

然后，加载索引模板到`elasticsearch`，如下所示：

```
filebeat setup --template -E output.logstash.enabled=false -E 'output.elasticsearch.hosts=["elastic1:9200", "elastic2"]'
```

最后，启动并启用`filebeat`，如下所示：

```
sudo systemctl enable filebeat && sudo systemctl start filebeat
```

要验证数据是否已发送，可以使用提供的仪表板之一来可视化`syslog`事件。在 Kibana 上，转到仪表板并在搜索栏中键入`Syslog Dashboard`；您将看到类似以下截图的内容：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-arch/img/9496cac8-0164-4963-aa9f-e1db2d85c59a.png)

Kibana 仪表板显示了`Syslog Dashboard`的搜索结果

# Metricbeat YAML

Metricbeat 遵循与 Filebeat 类似的过程，需要编辑`/etc/metricbeat/metricbeat.yml`文件以将输出发送到 Elasticsearch，并加载 Kibana 仪表板（即，它们需要运行一次）。

为此，编辑`metricbeat.yml`文件以允许 Metricbeat 加载 Kibana 仪表板：

```
setup.kibana:
 host: "kibana:5601"
```

接下来，指定`Elasticsearch`集群：

```
#------------------------ Elasticsearch output ----------------------------
output.elasticsearch:
 # Array of hosts to connect to.
 hosts: ["elastic1:9200", "elastic2:9200"]
```

加载 Kibana `仪表板`，如下：

```
metricbeat setup --dashboards
```

默认情况下，`metricbeat`启用了系统模块，它将捕获 CPU、系统负载、内存和网络的统计信息。

启动并启用`metricbeat`服务，如下：

```
sudo systemctl enable metricbeat && sudo systemctl start metricbeat
```

要确认数据是否被发送到集群，请转到 kibana 屏幕上的`Discover`，然后选择`metricbeat-*`索引模式并验证事件是否被发送：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-arch/img/845a23fb-4fe8-4423-a682-6e72b2404c92.png)

使用`metricbeat-*`索引模式过滤的事件

# 下一步

此时，集群现在已经完全可用。剩下的就是在集群的其他节点上安装 Metricbeat 和 Filebeat，以确保完全可见集群的健康和资源使用情况。

向集群添加更多客户端只是安装适当的 Beat，具体取决于需要监视什么以及需要索引哪些日志。

如果集群的负载增加，可以选择多种选项——要么向集群添加更多节点以平衡负载请求，要么增加每个节点的可用资源数量。在某些情况下，简单地增加更多资源是一种更具成本效益的解决方案，因为它不需要配置新节点。

这样的实现可以用于监视 Kubernetes 设置的性能和事件（例如第十一章中描述的设置，*设计 ELK Stack*）。一些 Beats 具有特定的模块，用于从 Kubernetes 集群中提取数据。

最后，可以对此设置进行的一个增强是让 Beat 客户端指向协调 Elasticsearch 节点，以充当节点之间的负载均衡器；这样可以避免在 Beats 的输出配置中硬编码每个 Elasticsearch 节点，只需要一个单一的地址。

# 总结

在本章中，我们经历了许多步骤来配置 Elastic Stack，这是四个主要组件的集合——Elasticsearch、Logstash、Kibana 和 Beats。对于这个设置，我们使用了三个虚拟机；我们托管了两个 Elasticsearch 节点，然后在单个系统上安装了 Logstash 和 Kibana，每个组件都使用了 6.5 版本。我们使用 Elastic Stack 提供的 RPM 存储库安装了 Elasticsearch；使用`yum`安装了所需的软件包。Elasticsearch 配置是使用`elasticsearch.yml`文件完成的，该文件控制`elasticsearch`的行为。我们定义了一些对于功能性集群是必需的设置，比如`cluster.name`参数和`discovery.zen.minimum_master_nodes`。

通过配置集群名称和发现设置，我们添加了一个新的 Elasticsearch 节点，这允许节点自动加入集群。然后，我们开始安装 Kibana 和 Logstash，它们都在用于 Elasticsearch 的相同 RPM 存储库中提供；通过它们各自的`.yml`文件进行配置 Logstash 和 Kibana。

一旦所有三个主要组件都启动，并且操作准备好接受传入数据，我们就开始安装 Beats，这些是 Elasticsearch 和 Logstash 用来摄取数据的数据传输器。对于日志和事件，我们使用 Filebeat，对于内存使用和 CPU 等系统指标，我们使用 Metricbeat。

在下一章中，我们将学习系统管理的挑战和 Salt 的架构。

# 问题

1.  如何安装 Elasticsearch？

1.  如何分区磁盘？

1.  如何持久地挂载文件系统？

1.  哪个文件控制 Elasticsearch 配置？

1.  `cluster.name` 设置是做什么的？

1.  Elasticsearch 集群中推荐的节点数量是多少？

1.  如何将 Elasticsearch 节点添加到现有集群中？

1.  安装 Logstash 和 Kibana 需要哪些步骤？

1.  什么是持久性排队？

1.  什么是协调节点？

1.  Beats 是什么？

1.  Filebeat 用于什么？

# 进一步阅读

+   **《Linux 基础》作者 Oliver Pelz**: [`www.packtpub.com/networking-and-servers/fundamentals-linux`](https://www.packtpub.com/networking-and-servers/fundamentals-linux)


# 第四部分：使用 Saltstack 进行系统管理

在本节中，读者将能够了解“基础设施即代码”（IaC）的工作原理以及使用 Saltstack 进行系统管理的优势。然后概述一些最佳设计实践。

本节包括以下章节：

+   第十三章，“用咸水解决管理问题”

+   第十四章，“让你的手变咸”

+   第十五章，“设计最佳实践”


# 第十三章：用 Salty 解决管理问题

在本章中，我们将发现并讨论为什么企业需要为其基础设施拥有集中管理工具，包括异构环境带来的高复杂性。我们将讨论解决这个问题的解决方案，以及以下内容：

+   新技术给我们的业务带来复杂性

+   我们如何集中化系统管理。

+   **基础设施即代码**（IaC）如何帮助我们维护系统状态

+   利用 IaC 的工具

+   SaltStack 平台及其组件

让我们开始我们的系统管理之旅。

# 集中化系统管理

理解系统管理背后的原因很容易被忽视。我们经常假设，只因为一个企业拥有庞大的 IT 基础设施，就需要解决其清单管理的问题。虽然这显然是真的，但其中还有更多。我们作为架构师的工作包括倾听客户的问题，并理解他们究竟在寻找什么。

# 新技术和系统管理

在这个不断发展的 IT 世界中，变化迅速。几乎每天都会出现新技术。虚拟化、物联网和云等技术正在塑造和改变我们使用 IT 的方式，通过不断扩大我们的基础设施，这是裸金属时代从未见过的。

所有这些变化和指数级增长意味着 IT 经理有更多的东西要管理，但时间更少来培训他们的员工支持这些技术，因此许多企业几乎无法跟上步伐。这可能导致他们不愿意采用新技术。但许多企业别无选择，只能采用这些技术，因为他们担心变得无关紧要，无法满足客户的需求。如果他们的竞争对手占据优势并提供更好更快的服务，他们很可能会破产。

公司希望尽快采用这些技术，以在竞争对手之上取得优势，但新技术往往伴随着陡峭的学习曲线。在此期间，IT 人员需要学习如何管理和维护新系统，这导致保持关键系统和工作负载可用性成为一项挑战。不遵守我们的 SLA 成为真正的威胁；想象一下，开发人员需要运维团队在我们的开发环境系统中应用库补丁以测试新版本，因为我们的运维人员（或至少一半）正在接受培训，开发人员很容易绕过标准化的变更请求流程并自行应用更新。在这种情况下，影子 IT 非常普遍，我们需要尽一切努力避免。影子 IT 可能使我们的公司不符合监管标准。

虽然 IT 领导者推动采用新技术，但他们往往面临非常有限且日益减少的预算来进行这种转型。这也直接影响我们的关键系统和工作负载，因为对系统管理的投资减少并转向创新。迈向创新并不是坏事，因为最终它将使我们能够提供更好的服务，但重要的是要理解，这也会对我们现有环境的维护产生后果。

随着新技术的出现，新基础设施也随之而来；混合环境变得越来越普遍，了解如何以最佳和最有效的方式管理这些混合环境至关重要。

# 重新掌控我们自己的基础设施

掌控我们的基础设施是系统管理的主要目标。但是拥有控制权意味着什么？清单清单、版本控制、自动打补丁和软件分发都是系统管理的一部分。所有这些都是更大格局的一部分，IT 可以重新掌控其基础设施，并确保无论他们正在运行什么 Linux 发行版，都可以确保其系统的合规性和标准化。

通常我们的系统是分开的；这种分离是因为它们可能在特征上有所不同。我们可能有基于 Red Hat Enterprise Linux 的发行版或基于 Debian 的发行版的系统，具有不同架构的系统，如 x86、功率服务器，甚至 ARM。所有这些系统甚至可能不会相互通信或为相同的目的服务；它们都成为 IT 必须维护和管理的存储。

想象一下，在没有工具来集中和自动化任务的情况下，手动在每个独立的存储中执行系统管理的各种任务。人为错误是这种情况最直接的威胁，其次是 IT 业务必须承担的大量复杂性、时间和成本，包括培训员工、雇佣员工以及为每种不同的系统类型购买特定的管理工具。

# 集中工具分散问题

集中配置管理可以帮助我们以受控、一致和稳定的方式控制系统的变更。对于运行集群或配置为高可用性的系统来说，这是完美的，因为集群中的所有节点都必须具有完全相同的配置。通过配置管理，我们还可以理解某些文件的权限背后的原因，所有系统上安装的软件包，甚至配置文件中的一行代码。

通过配置管理工具实施的这些变更或配置也可以回滚，因为市场上大多数工具都带有版本控制，任何拼写错误、人为错误或不兼容的更新都可以轻松回滚。

随着我们慢慢过渡到云环境，虚拟机和资源变得越来越成为商品和服务。可以帮助我们管理、配置和维护云基础设施的配置管理工具变得非常有价值。通过这些类型的工具，我们可以以更具弹性的方式处理基础设施，并以描述性的方式定义它，这意味着我们可以拥有部署相同基础设施的模板或根据定义实施更改；这就是我们所说的**基础设施即代码**（**IaC**）。

# 编码实现期望状态

IaC 背后的整个理念是在我们的环境中实现一致性和版本控制。IaC 寻求一种更具描述性和标准的资源配置方式，避免独特和特殊的部署，以防止由于每个组件的独特性而重新创建环境变得非常复杂的情况。

IaC 工具通过特定语言或现有语言（如 YAML 或 JSON）定义配置；以下是一个从 Terraform 模板中提取的示例，该模板定义了 Microsoft Azure 中的虚拟机：

```
resource "azurerm_resource_group" "test" {
 name = "example"
 location = "East US 2"
}

resource "azurerm_kubernetes_cluster" "test" {
 name = "exampleaks"
 location = "${azurerm_resource_group.test.location}"
 resource_group_name = "${azurerm_resource_group.test.name}"
 dns_prefix = "acctestagent1"

 agent_pool_profile {
 name = "default"
 count = 1
 vm_size = "Standard_B1_ls"
 os_type = "Linux"
 os_disk_size_gb = 30
 }

 service_principal {
 client_id = "00000000-0000-0000-0000-000000000000"
 client_secret = "00000000000000000000000000000000"
 }

 tags = {
 Environment = "Production"
 }
}

output "client_certificate" {
 value = "${azurerm_kubernetes_cluster.test.kube_config}"
}

output "kube_config" {
 value = "${azurerm_kubernetes_cluster}"
}
```

在云基础设施世界中，弹性是关键。现在我们没有在数据中心等待使用的现有资源。在云中，我们按需付费，拥有虚拟机或存储空间会增加我们的月度账单，这并不理想。通过 IaC，我们可以根据需求扩展或缩减这些环境。例如，我们知道我们有一个应用程序，只在工作时间内消耗最大，并需要额外的实例来支持负载。但在工作时间之外，一个实例就足以支持负载。通过 IaC，我们可以编写脚本在早上创建额外的实例，并在一天结束时减少实例。每个实例都不是唯一的，我们可以利用通过 IaC 使用描述性文件的配置管理工具来实现这一点。

有几种工具可以完成上述示例，但许多工具不仅可以在云中或虚拟化环境中提供基础设施。其他配置管理工具甚至可以做得更多；它们可以推送配置文件，安装软件包，创建用户，甚至文件系统。这些工具执行配置的方式和方法有几种。许多工具需要代理，但还有一些是无代理的。

配置管理工具执行其更改的方式基本上是通过推送或拉取。这将取决于（但并非总是）工具是否使用代理或无代理。大多数无代理工具将您在 IaC 文件中声明的配置更改推送到云中的 API，或者通过 SSH 发送更改，当您通过命令行或脚本执行工具时。

另一方面，拉取几乎总是通过代理进行。代理不断地向配置管理服务器查询定义，验证所需状态，以防有所更改，然后从服务器拉取这些更改并应用到其主机上。

推送和拉取可以以两种不同的方式应用：声明式和命令式。声明式方式指定所需状态是什么，并且更改将按照 IaC 规范文件中定义的方式应用。命令式方式包括按特定顺序运行一组指令或命令，告诉系统如何达到所需状态。

通过 IaC 进行配置管理的一些开源工具如下：

+   Puppet

+   Chef

+   Ansible

+   Terraform

+   盐

+   Vagrant

我们将在第十四章《Getting Your Hands Salty》中深入了解盐及其组件。

# 理解 NaCl

我们了解了 IaC 是什么，以及系统管理背后的困难。但作为未来解决方案的架构师，我们需要知道并了解哪些工具可以帮助我们的客户面对配置管理带来的挑战。

在本节中，我们将讨论如何使用盐，或者称为盐堆平台，来帮助我们实现集中、灵活和弹性的管理基础设施。

# 介绍盐

盐是一个由 Tomas S Hatch 于 2011 年开发的 Python 开源项目。最初，它并不是一个配置管理工具，而是一个数据收集工具和远程命令执行软件，利用了 ZeroMQ 库。同年晚些时候，通过状态添加了配置管理功能，我们稍后将进行审查。

由于盐是用 Python 编写的，因此它具有高度的可扩展性和模块化，可以轻松编写自定义模块以进一步扩展其功能。

理解盐不仅是一个配置管理工具至关重要，但在这些章节中，我们将专注于其配置管理能力，因为这是当前主题的性质。在“进一步阅读”部分，我将添加几本其他书籍推荐，如果您想了解更多关于盐的其他功能。

在盐中定义所需状态的方式，或者换句话说，盐支持的语言是多种多样的。主要和默认语言是 YAML，支持 Jinja 模板。 

创建新用户的 YAML 定义示例如下：

```
doge:
 user.present:
 - fullname: much doge 
 - shell: /bin/bash
 - home: /home/doge
```

YAML 是盐的数据渲染语言；数据渲染将文件中的定义转换为盐消耗的 Python 数据结构。

以下是盐支持的其他数据渲染语言：

+   dson

+   hjson

+   json5

+   json

+   pydsl

+   pyobjects

+   py

+   stateconf

+   yamlex

Salt 有两种渲染类型。第一种是我们刚刚讨论的：数据渲染。第二种是文本渲染，这是`Jinja`所属的类别。这些**文本渲染**不是返回 Python 数据结构，而是返回文本，稍后会为数据渲染进行翻译。

文本渲染对于设置变量或循环非常有用，如果我们需要重复几个具有不同值但相同结构的定义。例如，我们可以创建一个`Jinja`模板，并使用相同的文件创建多个用户，而不是为每个用户创建一个 YAML 文件，如下所示：

```
{% for user in [dsala, eflores, elilu] %}
{{ user }}:
user.present:
 - home: /home/{{ user }}
 - shell: /bin/bash
```

上面的示例将创建三个用户，而不是通过文件或定义创建一个用户。这种方式更有效，因为我们不仅节省了时间和工作，而且不需要一遍又一遍地输入相同的定义，如果需要在数组中添加更多用户，也可以轻松实现，而不必为额外的用户创建全新的文件或定义。

除了`Jinja`，Salt 文本渲染还支持其他模板引擎，例如以下：

+   `Cheetah`

+   `Genshi`

+   `GPG`

+   `Jinja`

+   `Mako`

+   `NaCl`

+   `Pass`

+   `Py`

+   `Wempy`

在接下来的章节中，我们将专注于`Jinja`和 YAML。

# SaltStack 平台

我们之前讨论了 IaC 的不同方法和途径。Salt 非常适合我们理解所有这些，因为 Salt 既使用推送和拉取方法，也同时使用**声明式**和**命令式**的方法。

让我们简要了解一下 Salt 的基本功能：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-arch/img/d1d0cc5a-0093-4414-ae5e-e987537af5bb.png)

与任何其他客户端/服务器集群一样，Salt 由两种基本类型的节点组成：

+   **Master**：这个服务器或服务器组负责协调 minion，并在 minion 查询其所需状态时。主服务器也是发送要在 minion 上执行的命令的服务器。

+   **Minion**：由主服务器管理的服务器。

主服务器从两个 TCP 端口监听：`4505`和`4506`。这两个端口具有非常不同的角色和非常不同的连接类型。

`4505`端口或**发布者**是所有 minion 监听主服务器消息的地方。`4506`端口或**请求服务器**是 minion 通过安全方式直接请求特定文件或数据的地方。Salt 的网络传输利用 ZeroMQ 消息队列系统，该系统使用**椭圆曲线加密**，使用在主服务器和 minion 中生成的 4,096 位 RSA 密钥，我们将在本章后面看到。

Salt 是一种基于代理的工具，主服务器和 minion 之间的所有通信都是通过安装在 minion 上的代理实现的。Minion 负责与主服务器发起通信。

这很重要，因为在可能或可能没有互联网的分段网络中，您的主服务器和 minion 之间会有许多安全边界，并且每个 minion 可能没有为其定义的唯一地址。在主服务器发起通信的情况下，您的堆栈中的所有 minion 可能都必须具有公共 IP 地址，或者每次添加要管理的 minion 时都必须实现大量的网络配置和**网络地址转换**（**NAT**）。

由于 Salt 通信的方式，您可以将主服务器放在 DMZ 区域，具有公共可寻址的 IP 地址，并且所有 minion 连接到这些 IP。您的主服务器将始终少于 minion，因此需要实现的网络配置将大大减少。Salt 是一个高度可扩展的平台，一些堆栈包含数千个 minion；想象一下，必须配置网络以便三四个主服务器可以连接数千个 minion。

拥有公共 IP 的主服务器可能会让人感到害怕，但请记住，只要验证 RSA 密钥指纹，您就可以确保节点之间的所有通信都得到了保护，这要归功于 ZeroMQ 的加密机制。

# Salt 功能

在对 Salt 的架构进行简要概述之后，现在是时候了解其不同的功能和能力了。

# 远程命令执行模块

记住我们说过 Salt 同时使用推送和拉取方法以及声明性和命令性方法。远程命令执行功能是我们如何以命令性方式利用 Salt 的推送方法。

如果你需要在多个随从或特定随从上远程运行命令，你将使用**执行模块**。让我们看一个简单的例子：

```
dsala@master1:~$ salt ‘*’  cmd.run ‘ls /home’
minion-1:
 jdoe
 dev1
master:
 dsala 
 eflores
```

前面的命令向注册到主服务器的随从推送了`ls`。让我们更仔细地看看这些命令：

+   `salt`：这是 Salt 在远程随从上并行执行命令的最基本命令。

+   `'*'`：表示我们将在所有由我们的主服务器管理的服务器上运行该命令；你也可以定义特定的目标。

+   `cmd.run`：要调用的执行模块。

+   `'ls /home'`：执行模块的参数。

+   **输出**：按随从名称排序，后跟该服务器的输出。

执行模块是 Salt 使用其远程执行框架的最基本形式。还记得我们说过 Salt 是用 Python 编写的吗？嗯，执行模块实际上是具有一组服务于共同目的的函数的 Python 模块。Salt 附带了几个预构建模块，你可以使用它们，甚至可以编写自己的模块并将它们添加到你的 SaltStack 平台上。所有执行模块都应该是与发行版无关的，但你可能会遇到一些在某些发行版中不可用的模块。以`win_`开头的函数大多是特定于 Windows 的模块。

在我们之前的例子中，我们使用了`cmd`模块的`run`函数。我们使用模块中的函数的格式涉及定义要导入的模块，后跟一个句点和函数。每当调用一个函数时，Salt 都会按照以下方式进行：

1.  从执行命令的主服务器发送到指定目标的发布者端口（`4505`）。

1.  目标随从评估命令并决定是否要运行该命令。

1.  运行命令的随从格式化输出并将其发送到主服务器的请求服务器端口（`4506`）。

了解执行模块是不够的，我们还需要知道我们可以使用什么。许多预定义模块是最常用的，值得一看它们的主要功能是什么。

# sys 模块

这个模块相当于`man`命令。使用`sys`，我们可以查询、列出，甚至检查每个函数接受哪些参数。你会发现自己主要使用`sys`模块的以下函数：

+   `list_modules`：此函数将列出目标随从可用的模块。重要的是要注意，执行模块是在随从自身上执行的，而不是在执行命令的主服务器上。

+   `list_functions`：使用`list_functions`，你可以列出某个模块可用的函数。

+   `argspec`：列出所需函数的可用参数和默认值。

现在我们可以运行`sys`模块的前述函数之一，看一个真实的例子：

```
dsala@master1:~$ sudo salt 'minion1' sys.argspec pkg.install
minion1:
 ----------
 pkg.install:
 ----------
 args:
 - name
 - refresh
 - fromrepo
 - skip_verify
 - debconf
 - pkgs
 - sources
 - reinstall
 - ignore_epoch
 defaults:
 - None
 - False
 - None
 - False
 - None
 - None
 - None
 - False
 - False
 kwargs:
 True
 varargs:
 None
```

# pkg 模块

现在我们已经使用了`pkg`函数作为`sys`模块的示例，我想谈谈`pkg`模块。这是 Salt 提供的另一个最常用的模块。该模块处理与包相关的所有任务，从安装和升级到删除包。由于 Salt 试图尽可能与发行版无关，`pkg`模块实际上在底层调用一组不同的模块和函数，这些模块和函数特定于调用模块的发行版。例如，如果`pkg.install`针对的是基于 Ubuntu 的系统，当随从收到消息时，实际上会调用`aptpkg`模块。这就是为什么`pkg`被称为**虚拟模块**。

`pkg`调用的一些不同模块如下：

+   `aptpkg`：对于使用`apt-get`软件包管理的 Debian 发行版。

+   `brew`：适用于使用 Homebrew 软件包管理的 macOS。

+   `yumpkg`：使用`yum`或`dnf`作为软件包管理器的基于 Red Hat 的发行版。

+   `zypper`：对于使用`zypper`作为软件包管理器的基于 SUSE 的发行版。

以下是使用`pkg`安装`nginx` web 服务器的示例：

```
dsala@master1:~$ sudo salt 'minion1' pkg.install nginx
minion1:
 ----------
 nginx:
 ----------
 new:
 1.15.10
old:
```

# 测试模块

最后，但同样重要的是，我想和你谈谈**测试模块**。测试模块将允许我们测试我们的 SaltStack 平台。例如，检查 minions 的健康状态、它们正在运行的 Salt 版本，甚至只是让它们发送一个回声，都是可能的。

可以使用`sys.list_functions`函数找到测试模块的不同功能，但值得一提的是，您可能会经常使用一些最常见的功能：

+   **ping**：ping 函数测试 minions 的响应；这不是一个 ICMP ping 命令。

+   **version**：返回您的 minions 的 Salt 版本。

+   **versions_information**：返回所有 Salt 依赖项、内核版本、发行版版本和 Salt 版本的完整列表。

# 盐状态

现在我们已经了解了远程执行框架，我们可以开始探索 Salt 提供的其他系统。远程执行框架是所谓的**状态系统**的基础。状态系统是一种声明性和幂等的方式，利用 IaC 文件来配置 minion 的期望状态。状态系统利用状态模块，这些模块与执行模块非常相似，但不同之处在于 Salt 状态实际上会检查 minion 中是否已经存在所需的配置。例如，让我们看一下以下状态定义：

```
dsala@master:/srv/salt/httpd $ cat httpd.sls
 httpd_package:
 pkg.installed:
 -  name: httpd
```

上述状态将在运行时在目标服务器上安装`httpd`（Apache）软件包，但仅当软件包不存在时。如果软件包不存在，状态模块将调用本地的`pkg.install`执行函数，并在 minion(s)中安装软件包。

看一下我们从`/srv/salt`目录中`cat`文件的事实。这个目录是盐状态目录树的默认位置，状态定义放在这里。在这个目录中，您将创建包含公式的文件夹，这些公式是一组包含部署应用程序所需的所有必要配置的盐状态。例如，我们不仅可以安装`httpd`，还可以配置虚拟主机并下载包含实际网站的 Git 存储库，这些网站将在 Apache web 服务器上运行。

目录树遵循一组规则，以便您调用状态模块并运行公式，但这将是第十四章“Getting Your Hands Salty”的主题，届时我们将深入探讨配置和实际用法。

# 盐的特征

我们已经学会了可以通过定义 minion 名称或通过`*`在所有 minions 上运行执行模块。但是，当您的主服务器管理数百甚至数千个 minions 时，在整个堆栈上或在单个 minions 上运行 Salt 状态和执行模块并不理想。

在这里，Salt 引入了`grains`接口，它允许我们通过特定特征识别 minions，甚至为共享相同目的或特征的 minions 设置自己的标签或角色类型，因此我们可以执行更有针对性的配置管理。

我们可以利用`grains`接口，使用与在 Salt 中执行任何命令相同的语法：

```
dsala@master:~$ salt “minion1” grains.items
```

通过上述命令，我们列出了我们所针对的系统的所有不同的硬件和软件特征。在输出中，我们可以看到诸如操作系统系列、系统架构，甚至我们用来运行 VM 的 hypervisor 等信息。

这将帮助我们创建通过所谓的`top`文件定位特定系统的状态定义，我们将在第十四章中讨论这一点。使用`grains`并定位所有`Debian`系列 VM 的 Salt 状态顶部文件定义示例如下：

```
 base:
 'os_family:Debian:
 - match: grain
 - httpd
```

如前所述，我们还可以在从属服务器中创建自定义的`grains`来定义角色，并使用唯一值对标记我们的从属服务器。这对于将从属服务器分组到特定任务非常有用；例如，所有 QA 团队的 VM 可以使用键值对`departement: qa`进行标记。另一种分组方式可能是按角色，例如`appfoo: frontend`等。有许多使用谷物定位的方法，所有这些都取决于我们想要如何管理或推送和维护所需的状态。

# 盐柱

通过**谷物**，我们可以定位特定的从属服务器，但最终，我们定义了那些在顶层文件中的定位策略，这些文件是公式的一部分。公式通常存储在 Git 存储库中，有时甚至是公共的。这就是为什么我们不能，或者更确切地说，我们不应该在 Salt 状态中声明敏感信息。在我们之前的章节中，Dockerfile 也是如此，Kubernetes 通过**Secrets** API 对象解决了这个问题。Salt 有自己的秘密版本，称为**Pillars**。

与谷物不同，盐柱存储在主服务器中，而不是从属服务器。只有被盐柱定位的从属服务器才能访问盐柱中的信息。这使得它非常适合存储敏感信息。在存储敏感信息时，盐柱也可以在静止状态下加密，而且由于盐的渲染系统，盐柱将在盐柱编译期间解密。

盐柱通过仅在主服务器中存储敏感数据来减少敏感数据的暴露面：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-arch/img/c44ef113-4680-4ff0-9da5-1e8e641f4288.png)

通过 Salt 柱，我们完成了对 SaltStack 平台提供的基本组件的简要概述。我们将在第十四章中更深入地讨论它们，并通过实际示例进行操作，以便通过 Salt 开始管理系统。

# 摘要

在本章中，我们讨论了企业在维护基础设施时面临的不同问题。我们介绍了不同的技术，如 IaC 和集中式系统管理。我们介绍了 IaC 如何将更改**推送**或**拉取**到受控系统中，并了解了几个利用 IaC 的应用程序。

我们还讨论了盐是什么，以及它的不同组件如何帮助我们实现集中式的受控基础设施。

在下一章中，我们将学习如何设计一个 Salt 解决方案并安装软件。

# 问题

1.  什么是系统管理？

1.  系统管理背后的挑战是什么？

1.  什么应用程序可以帮助我们进行系统管理？

1.  什么是基础设施即代码？

1.  我们可以用哪些不同类型的方法来管理我们的系统？

1.  盐是什么？

1.  盐有哪些不同的组件？

# 进一步阅读

+   **Gartner**：'每个预算都是 IT 预算'

+   **Forrester**：[`www.forrester.com/report/Cloud+Investments+Will+Reconfigure+Future+IT+Budgets/-/E-RES83041#`](https://www.forrester.com/report/Cloud+Investments+Will+Reconfigure+Future+IT+Budgets/-/E-RES83041#)

+   **声明式与命令式配置管理模型**：[`www.upguard.com/blog/articles/declarative-vs.-imperative-models-for-configuration-management`](https://www.upguard.com/blog/articles/declarative-vs.-imperative-models-for-configuration-management)

+   **SALTSTACK**：[`s.saltstack.com/beyond-configuration-management/`](https://s.saltstack.com/beyond-configuration-management/)

+   Salt 配置管理：[`red45.wordpress.com/2011/05/29/salt-configuration-management/`](https://red45.wordpress.com/2011/05/29/salt-configuration-management/)

+   渲染器：[`docs.saltstack.com/en/latest/ref/renderers/`](https://docs.saltstack.com/en/latest/ref/renderers/)

+   远程执行：[`docs.saltstack.com/en/getstarted/system/execution.html`](https://docs.saltstack.com/en/getstarted/system/execution.html)

+   使用 grains 进行目标定位：[`docs.saltstack.com/en/latest/topics/targeting/grains.html`](https://docs.saltstack.com/en/latest/topics/targeting/grains.html)

+   Grains：[`docs.saltstack.com/en/latest/topics/grains/`](https://docs.saltstack.com/en/latest/topics/grains/)

+   函数：[`docs.saltstack.com/en/getstarted/config/functions.html`](https://docs.saltstack.com/en/getstarted/config/functions.html)
