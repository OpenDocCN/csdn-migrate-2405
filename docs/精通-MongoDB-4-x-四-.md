# 精通 MongoDB 4.x（四）

> 原文：[`zh.annas-archive.org/md5/BEDE8058C8DB4FDEC7B98D6DECC4CDE7`](https://zh.annas-archive.org/md5/BEDE8058C8DB4FDEC7B98D6DECC4CDE7)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第九章：存储引擎

MongoDB 在 3.0 版本中引入了可插拔存储引擎的概念。在收购 WiredTiger 之后，它首先将其存储引擎作为可选引擎引入，然后作为当前版本 MongoDB 的默认存储引擎。在本章中，我们将深入探讨存储引擎的概念，它们的重要性以及如何根据我们的工作负载选择最佳存储引擎。

我们将涵盖以下主题：

+   可插拔存储引擎

+   WiredTiger

+   加密

+   内存中

+   MMAPv1

+   MongoDB 中的锁定

# 可插拔存储引擎

随着 MongoDB 从 Web 应用程序范式中分离出来进入具有不同要求的领域，存储已成为一个越来越重要的考虑因素。

使用多个存储引擎可以被视为使用基础架构堆栈中不同存储解决方案和数据库的替代方式。这样，我们可以减少操作复杂性，并且应用层对基础存储层是不可知的，从而缩短开发时间。

MongoDB 目前提供了四种不同的存储引擎，我们将在接下来的章节中更详细地讨论。

# WiredTiger

从版本 3.2 开始，WiredTiger 是默认的存储引擎，也是大多数工作负载的最佳选择。通过提供文档级别的锁定，它克服了 MongoDB 早期版本中最显著的缺点之一——在高负载下的锁争用。

我们将在接下来的章节中探讨一些 WiredTiger 的好处。

# 文档级别的锁定

锁定是如此重要，以至于我们将在本节末尾更详细地解释细粒度锁定的性能影响。与 MMAPv1 集合级别锁定相比，具有文档级别锁定可以在许多实际用例中产生巨大的差异，并且是选择 WiredTiger 而不是 MMAPv1 的主要原因之一。

# 快照和检查点

WiredTiger 使用**多版本并发控制**（**MVCC**）。MVCC 基于这样一个概念，即数据库保留对象的多个版本，以便读者能够查看在读取期间不会发生变化的一致数据。

在数据库中，如果我们有多个读者在写入者修改数据的同时访问数据，我们可能会出现读者查看此数据的不一致视图的情况。解决这个问题的最简单和最容易的方法是阻止所有读者，直到写入者完成对数据的修改。

这当然会导致严重的性能下降。MVCC 通过为每个读者提供数据库的快照来解决这个问题。当读取开始时，每个读者都保证查看数据与读取开始时的时间点完全一致。写入者进行的任何更改只有在写入完成后才会被读者看到，或者在数据库术语中，只有在事务提交后读者才能看到。

为了实现这个目标，当写入数据时，更新后的数据将被保存在磁盘的一个单独位置，并且 MongoDB 将标记受影响的文档为过时。MVCC 被认为提供了时点一致的视图。这相当于传统 RDBMS 系统中的读提交隔离级别。

对于每个操作，WiredTiger 将在发生操作的确切时刻对我们的数据进行快照，并为应用程序提供一致的应用程序数据视图。当我们写入数据时，WiredTiger 将在每 2GB 的日志数据或 60 秒内创建一个快照，以先到者为准。在故障情况下，WiredTiger 依赖于其内置日志来恢复最新检查点之后的任何数据。

我们可以使用 WiredTiger 禁用日志记录，但如果服务器崩溃，我们将丢失最后一个检查点之后的任何数据。

# 日志记录

正如在*快照和检查点*部分中所解释的，日志记录是 WiredTiger 崩溃恢复保护的基石。

WiredTiger 使用 snappy 压缩算法压缩日志。我们可以使用以下设置来设置不同的压缩算法：

```sql
storage.wiredTiger.engineConfig.journalCompressor
```

我们还可以通过将以下设置为 `false` 来禁用 WiredTiger 的日志记录：

```sql
storage.journal.enabled
```

如果我们使用副本集，我们可能能够从次要节点中恢复数据，该节点将被选举为主节点并开始接受写入，以防我们的主节点发生故障。建议始终使用日志记录，除非我们了解并能够承受不使用它的后果。

# 数据压缩

MongoDB 默认使用 snappy 压缩算法来压缩数据和索引前缀。索引前缀压缩意味着相同的索引键前缀仅存储一次在内存页中。压缩不仅减少了存储空间，还会增加每秒的 I/O 操作，因为需要存储和从磁盘移动的数据更少。如果我们的工作负载是 I/O 限制而不是 CPU 限制，使用更激进的压缩可以带来性能提升。

我们可以通过将以下参数设置为 `false` 来定义 `.zlib` 压缩而不是 snappy 或无压缩：

```sql
storage.wiredTiger.collectionConfig.blockCompressor
```

数据压缩使用更少的存储空间，但会增加 CPU 的使用。`.zlib` 压缩以牺牲更高的 CPU 使用率来实现更好的压缩，与默认的 snappy 压缩算法相比。

我们可以通过将以下参数设置为 `false` 来禁用索引前缀压缩：

```sql
storage.wiredTiger.indexConfig.prefixCompression
```

我们还可以在创建过程中使用以下参数为每个索引配置存储：

```sql
{ <storage-engine-name>: <options> }
```

# 内存使用

WiredTiger 在使用 RAM 方面与 MMAPv1 有显著不同。MMAPv1 本质上是使用底层操作系统的文件系统缓存来将数据从磁盘分页到内存，反之亦然。

相反，WiredTiger 引入了 WiredTiger 内部缓存的新概念。

WiredTiger 内部缓存默认为以下两者中的较大者：

+   50% 的 RAM 减去 1 GB

+   256 MB

这意味着如果我们的服务器有 8 GB RAM，我们将得到以下结果：

*max(3 GB , 256 MB) = WiredTiger 将使用 3 GB 的 RAM*

如果我们的服务器有 2,512 MB RAM，我们将得到以下结果：

*max(256 MB, 256 MB) = WiredTiger 将使用 256 MB 的 RAM*

基本上，对于任何 RAM 小于 2,512 MB 的服务器，WiredTiger 将使用 256 MB 作为其内部缓存。

我们可以通过设置以下方式改变 WiredTiger 内部缓存的大小：

```sql
storage.wiredTiger.engineConfig.cacheSizeGB
```

我们也可以使用以下命令行来执行此操作：

```sql
--wiredTigerCacheSizeGB
```

除了未压缩以获得更高性能的 WiredTiger 内部缓存外，MongoDB 还使用了压缩的文件系统缓存，就像 MMAPv1 一样，在大多数情况下将使用所有可用内存。

WiredTiger 内部缓存可以提供类似于内存存储的性能。因此，尽可能地扩大它是很重要的。

使用多核处理器时，使用 WiredTiger 可以获得更好的性能。与 MMAPv1 相比，这也是一个很大的优势，因为后者的扩展性不如 WiredTiger。

我们可以，也应该，使用 Docker 或其他容器化技术来隔离 `mongod` 进程，并确保我们知道每个进程在生产环境中可以使用多少内存。不建议将 WiredTiger 内部缓存增加到其默认值以上。文件系统缓存不应少于总 RAM 的 20%。

# readConcern

WiredTiger 支持多个 `readConcern` 级别。就像 `writeConcern` 一样，它被 MongoDB 中的每个存储引擎支持，通过 `readConcern`，我们可以自定义副本集中必须确认查询结果的服务器数量，以便将文档返回到结果集中。

读关注的可用选项如下：

+   `local`：默认选项。将从服务器返回最近的数据。数据可能已经传播到副本集中的其他服务器，也可能没有，我们面临回滚的风险。

+   `线性化`：

+   仅适用于从主节点读取

+   仅适用于返回单个结果的查询

+   数据返回满足两个条件：

+   `majority`, ``writeConcern``

+   数据在读操作开始前已被确认

此外，如果我们将`writeConcernMajorityJournalDefault`设置为`true`，我们可以确保数据不会被回滚。

如果我们将`writeConcernMajorityJournalDefault`设置为`false`，MongoDB 在确认写入之前不会等待`majority`写入变得持久。在这种情况下，如果复制集中的成员丢失，我们的数据可能会被回滚。返回的数据已经从大多数服务器传播和确认后才开始读取。

当使用`linearizable`和`majority`读取关注级别时，我们需要使用`maxTimeMS`，以防我们无法建立`majority writeConcern`而永远等待响应。在这种情况下，操作将返回超时错误。

MMAPv1 是较旧的存储引擎，在许多方面被认为是废弃的，但仍然有许多部署在使用它。

`local`和`linearizable`读取关注对 MMAPv1 也可用。

# WiredTiger 集合级选项

当我们创建一个新的集合时，可以像这样向 WiredTiger 传递选项：

```sql
> db.createCollection(
 "mongo_books",
 { storageEngine: { wiredTiger: { configString: "<key>=<value>" } } }
)
```

这有助于创建我们的`mongo_books`集合，并从 WiredTiger 通过其 API 公开的可用选项中选择一个键值对。一些最常用的键值对如下：

| **键** | **值** |
| --- | --- |
| `block_allocation` | 最佳或首选 |
| `allocation_size` | 512 字节到 4KB；默认 4KB |
| `block_compressor` | 无，`.lz4`，`.snappy`，`.zlib`，`.zstd`，或根据配置的自定义压缩器标识符字符串 |
| `memory_page_max` | 512 字节到 10TB；默认 5MB |
| `os_cache_max` | 大于零的整数；默认为零 |

这直接取自 WiredTiger 文档中的定义，位于[`source.wiredtiger.com/mongodb-3.4/struct_w_t___s_e_s_s_i_o_n.html`](http://source.wiredtiger.com/mongodb-3.4/struct_w_t___s_e_s_s_i_o_n.html)：

```sql
int WT_SESSION::create()
```

集合级选项允许灵活配置存储，但应在开发/暂存环境中经过仔细测试后谨慎使用。

如果应用于复制集中的主要服务器，集合级选项将传播到辅助服务器。`block_compressor`也可以通过使用`--wiredTigerCollectionBlockCompressor`选项全局配置数据库的命令行来进行配置。

# WiredTiger 性能策略

正如本章前面讨论的，WiredTiger 使用内部缓存来优化性能。此外，操作系统（和 MMAPv1）使用文件系统缓存来从磁盘中获取数据。

默认情况下，我们将 50%的 RAM 专用于文件系统缓存，另外 50%专用于 WiredTiger 内部缓存。

文件系统缓存将保持数据在存储在磁盘上时的压缩状态。内部缓存将按如下方式解压缩：

+   **策略 1**：将 80%或更多分配给内部缓存。这样可以将我们的工作集适应 WiredTiger 的内部缓存中。

+   **策略 2**：将 80%或更多分配给文件系统缓存。我们的目标是尽可能避免使用内部缓存，并依赖文件系统缓存来满足我们的需求。

+   **策略 3**：使用 SSD 作为快速搜索时间的基础存储，并将默认值保持在 50-50%的分配。

+   **策略 4**：通过 MongoDB 的配置在我们的存储层启用压缩，以节省存储空间，并通过减小工作集大小来提高性能。

我们的工作负载将决定我们是否需要偏离默认的策略 1。一般来说，我们应该尽可能使用 SSD，并且通过 MongoDB 的可配置存储，我们甚至可以在需要最佳性能的一些节点上使用 SSD，并将 HDD 用于分析工作负载。

# WiredTiger B 树与 LSM 索引

B 树是不同数据库系统中索引的最常见数据结构。WiredTiger 提供了使用**日志结构合并**（**LSM**）树而不是 B 树进行索引的选项。

当我们有随机插入的工作负载时，LSM 树可以提供更好的性能，否则会导致页面缓存溢出，并开始从磁盘中分页数据以保持我们的索引最新。

LSM 索引可以像这样从命令行中选择：

```sql
> mongod --wiredTigerIndexConfigString "type=lsm,block_compressor=zlib"
```

前面的命令选择`lsm`作为`type`，并且在这个`mongod`实例中，`block_compressor`是`zlib`。

# 加密

加密存储引擎是为支持一系列特殊用例而添加的，主要围绕金融、零售、医疗保健、教育和政府。

如果我们必须遵守一系列法规，包括以下内容，我们需要对其余数据进行加密：

+   处理信用卡信息的 PCI DSS

+   医疗保健应用的 HIPAA

+   政府的 NIST

+   政府的 FISMA

+   政府的 STIG

这可以通过几种方式来实现，云服务提供商（如 EC2）提供了内置加密的 EBS 存储卷。加密存储支持英特尔的 AES-NI 配备的 CPU，以加速加密/解密过程。

支持的加密算法如下：

+   AES-256，CBC（默认）

+   AES-256，GCM

+   FIPS，FIPS-140-2

加密支持页面级别的更好性能。当文档中进行更改时，只需修改受影响的页面，而不是重新加密/解密整个底层文件。

加密密钥管理是加密存储安全性的一个重要方面。大多数先前提到的规范要求至少每年进行一次密钥轮换。

MongoDB 的加密存储使用每个节点的内部数据库密钥。这个密钥由一个外部（主）密钥包装，必须用于启动节点的`mongod`进程。通过使用底层操作系统的保护机制，如`mlock`或`VirtualLock`，MongoDB 可以保证外部密钥永远不会因页面错误从内存泄漏到磁盘。

外部（主）密钥可以通过使用**密钥管理互操作性协议**（**KMIP**）或通过使用密钥文件进行本地密钥管理来管理。

MongoDB 可以通过对副本集成员执行滚动重启来实现密钥轮换。使用 KMIP，MongoDB 可以仅轮换外部密钥而不是底层数据库文件。这带来了显著的性能优势。

使用 KMIP 是加密数据存储的推荐方法。加密存储基于 WiredTiger，因此可以使用加密来享受其所有优势。加密存储是 MongoDB 企业版的一部分，这是 MongoDB 的付费产品。

使用 MongoDB 的加密存储可以提高性能，相对于加密存储卷。与第三方加密存储解决方案相比，MongoDB 的加密存储的开销约为 15%，而第三方加密存储解决方案的开销为 25%或更高。

在大多数情况下，如果我们需要使用加密存储，我们将在应用程序设计阶段提前知道，并且可以对不同的解决方案进行基准测试，以选择最适合我们用例的解决方案。

# 内存中

在内存中存储 MongoDB 是一项高风险的任务，但回报很高。将数据保留在内存中的速度可能比在磁盘上持久存储快 100,000 倍。

使用内存存储的另一个优势是，我们在写入或读取数据时可以实现可预测的延迟。一些用例要求延迟不论操作是什么都不偏离正常。

另一方面，通过将数据保留在内存中，我们面临断电和应用程序故障的风险，可能会丢失所有数据。使用副本集可以防范某些类别的错误，但如果我们将数据存储在内存中而不是存储在磁盘上，我们将始终更容易面临数据丢失。

然而，有一些用例，我们可能不太在乎丢失旧数据。例如，在金融领域，我们可能有以下情况：

+   高频交易/算法交易，高流量情况下更高的延迟可能导致交易无法完成

+   在欺诈检测系统中，我们关心的是尽可能快地进行实时检测，并且我们可以安全地将只需要进一步调查的案例或明确的阳性案例存储到持久存储中。

+   信用卡授权、交易订单对账和其他需要实时答复的高流量系统

在 Web 应用程序生态系统中，我们有以下内容：

+   在入侵检测系统中，如欺诈检测，我们关心的是尽可能快地检测入侵，而对假阳性案例并不那么关心。

+   在产品搜索缓存的情况下，数据丢失并不是使命关键，而是从客户的角度来看是一个小不便。

+   对于实时个性化产品推荐来说，数据丢失的风险较低。即使我们遭受数据丢失，我们也可以重新构建索引。

内存存储引擎的一个主要缺点是我们的数据集必须适合内存。这意味着我们必须了解并跟踪我们的数据使用情况，以免超出服务器的内存。

总的来说，在某些边缘用例中使用 MongoDB 内存存储引擎可能是有用的，但在数据库系统中缺乏耐久性可能是其采用的一个阻碍因素。

内存存储是 MongoDB 企业版的一部分，这是 MongoDB 的付费产品。

# MMAPv1

随着 WiredTiger 的引入及其许多好处，如文档级别锁定，许多 MongoDB 用户开始质疑是否还值得讨论 MMAPv1。

实际上，我们应该考虑在以下情况下使用 MMAPv1 而不是 WiredTiger：

+   **传统系统**：如果我们有一个适合我们需求的系统，我们可以升级到 MongoDB 3.0+，而不转换到 WiredTiger。

+   **版本降级**：一旦我们升级到 MongoDB 3.0+并将存储转换为 WiredTiger，我们就无法降级到低于 2.6.8 的版本。如果我们希望在以后有灵活性进行降级，这一点应该牢记在心。

正如前面所示，WiredTiger 比 MMAPv1 更好，我们应该在有机会时使用它。本书以 WiredTiger 为中心，并假设我们将能够使用 MongoDB 的最新稳定版本（写作时为 3.4）。

从 3.4 版本开始，MMAPv1 仅支持集合级别的锁定，而不支持 WiredTiger 支持的文档级别锁定。这可能会导致高争用数据库负载的性能损失，这是我们尽可能使用 WiredTiger 的主要原因之一。

# MMAPv1 存储优化

MongoDB 默认使用二次幂分配策略。创建文档时，它将被分配为二次幂大小。也就是说，`ceiling(document_size)`。

例如，如果我们创建一个 127 字节的文档，MongoDB 将分配 128 字节（*2⁷*），而如果我们创建一个 129 字节的文档，MongoDB 将分配 256 字节（*2⁸*）。这在更新文档时很有帮助，因为我们可以更新它们而不移动底层文档，直到超出分配的空间。

如果文档在磁盘上移动（即向文档的数组中添加一个新的子文档或元素，使其大小超过分配的存储空间），将使用新的二次幂分配大小。

如果操作不影响其大小（即将整数值从一个更改为两个），文档将保持存储在磁盘上的相同物理位置。这个概念被称为**填充**。我们也可以使用紧凑的管理命令来配置填充。

当我们在磁盘上移动文档时，我们存储的是非连续的数据块，实质上是存储中的空洞。我们可以通过在集合级别设置`paddingFactor`来防止这种情况发生。

`paddingFactor`的默认值为`1.0`（无填充），最大值为`4.0`（将文档大小扩展三倍）。例如，`paddingFactor`为`1.4`将允许文档在被移动到磁盘上的新位置之前扩展 40%。

例如，对于我们喜爱的`books`集合，要获得 40%的额外空间，我们将执行以下操作：

```sql
> db.runCommand ( { compact: 'books', paddingFactor: 1.4 } )
```

我们还可以根据每个文档的字节设置填充。这样我们就可以从集合中每个文档的初始创建中获得*x*字节的填充：

```sql
> db.runCommand ( { compact: 'books', paddingBytes: 300 } )
```

这将允许一个在 200 字节时创建的文档增长到 500 字节，而一个在 4000 字节时创建的文档将被允许增长到 4300 字节。

我们可以通过运行`compact`命令来完全消除空洞，但这意味着每次增加文档大小的更新都必须移动文档，从根本上在存储中创建新的空洞。

# 混合使用

当我们的应用程序以 MongoDB 作为基础数据库时，我们可以在应用程序级别为不同操作设置不同的副本集，以满足它们的需求。

例如，在我们的金融应用程序中，我们可以使用一个连接池来进行欺诈检测模块，利用内存节点，并为我们系统的其他部分使用另一个连接池，如下所示：

![](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-mongo-4x/img/2eb80ef3-4570-4763-a401-27e581114ac0.png)

此外，MongoDB 中的存储引擎配置是针对每个节点应用的，这允许一些有趣的设置。

如前面的架构图所示，我们可以在副本集的不同成员中使用不同的存储引擎的混合。在这种情况下，我们在主节点中使用内存引擎以获得最佳性能，而其中一个从节点使用 WiredTiger 以确保数据的持久性。我们可以在内存从节点中使用`priority=1`来确保，如果主节点失败，从节点将立即被选中。如果我们不这样做，我们就有可能在系统负载很高时出现主服务器故障，而从节点没有及时跟上主服务器的内存写入。

混合存储方法广泛应用于微服务架构中。通过解耦服务和数据库，并针对每个用例使用适当的数据库，我们可以轻松地水平扩展我们的基础架构。

所有存储引擎都支持一些共同的基线功能，例如以下内容：

+   查询

+   索引

+   复制

+   分片

+   Ops 和 Cloud Manager 支持

+   认证和授权语义

# 其他存储引擎

模块化的 MongoDB 架构允许第三方开发他们自己的存储引擎。

# RocksDB

RocksDB 是一个用于键值数据的嵌入式数据库。它是`LevelDB`的一个分支，存储任意字节数组中的键值对。它于 2012 年在 Facebook 启动，现在作为名为**CockroachDB**的开源 DB 的后端服务，该 DB 受到 Google Spanner 的启发。

MongoRocks 是由 Percona 和 Facebook 支持的项目，旨在将 RocksDB 后端引入 MongoDB。对于某些工作负载，RocksDB 可以实现比 WiredTiger 更高的性能，并值得研究。

# TokuMX

另一个广泛使用的存储引擎是 Percona 的 TokuMX。TokuMX 是为 MySQL 和 MongoDB 设计的，但自 2016 年以来，Percona 已将其重点放在了 MySQL 版本上，而不是切换到**RocksDB**以支持 MongoDB 存储。

# MongoDB 中的锁定

文档级和集合级锁定在本章中以及本书的其他几章中都有提到。了解锁定的工作原理以及其重要性是很重要的。

数据库系统使用锁的概念来实现 ACID 属性。当有多个读取或写入请求并行进行时，我们需要锁定我们的数据，以便所有读者和写入者都能获得一致和可预测的结果。

MongoDB 使用多粒度锁定。可用的粒度级别按降序排列如下：

+   全局

+   数据库

+   集合

+   文档

MongoDB 和其他数据库使用的锁按粒度顺序如下：

+   *IS*：意向共享

+   *IX*：意向排他

+   *S*：共享

+   *X*：排他

如果我们在粒度级别使用*S*或*X*锁，那么所有更高级别都需要使用相同类型的意向锁进行锁定。

锁的其他规则如下：

+   一个数据库可以同时以*IS*和*IX*模式被锁定

+   排他（*X*）锁不能与任何其他锁共存

+   共享（*S*）锁只能与*IS*锁共存

读取和写入请求锁通常按照**先进先出**（**FIFO**）顺序排队。MongoDB 实际上会做的唯一优化是根据队列中的下一个请求重新排序请求以便服务。

这意味着，如果我们有一个*IS(1)*请求即将到来，而我们当前的队列如下*IS(1)->IS(2)->X(3)->S(4)->IS(5)*，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-mongo-4x/img/eaed832c-b511-4484-a5cc-34840526172f.png)

然后 MongoDB 会重新排序请求，如下，*IS(1)->IS(2)->S(4)->IS(5)->X(3)*，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-mongo-4x/img/ac8c0989-a235-4176-ab63-e60ea5fa7742.png)

如果在服务过程中，*IS(1)*请求、新的*IS*或*S*请求进来，比如*IS(6)*和*S(7)*，它们仍将被添加到队列的末尾，并且在*X(3)*请求完成之前不会被考虑。

我们的新队列现在看起来是*IS(2)->S(4)->IS(5)->X(3)->IS(6)->S(7)*：

![](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-mongo-4x/img/00940bca-eff2-4efe-9fb7-00c1e0ea3676.png)

这是为了防止*X(3)*请求被饿死，因为新的*IS*和*S*请求不断进来而不断被推迟。重要的是要理解意向锁和锁本身之间的区别。WiredTiger 存储引擎只会在全局、数据库和集合级别使用意向锁。

当新请求进来时，它在更高级别（即集合、数据库、全局）使用意向锁，并根据以下兼容性矩阵：

![](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-mongo-4x/img/0bf12ed6-cd4a-4da4-80fd-b0b1df10bca9.png)

MongoDB 在获取文档本身的锁之前，会首先获取所有祖先的意向锁。这样，当新请求进来时，它可以快速确定是否无法基于更少粒度的锁提供服务。

WiredTiger 将在文档级别使用*S*和*X*锁。唯一的例外是通常不频繁和/或短暂的涉及多个数据库的操作。这些操作仍然需要全局锁，类似于 MongoDB 在 2.x 之前版本的行为。

管理操作，例如删除集合，仍然需要独占数据库锁。

正如之前解释的那样，MMAPv1 使用集合级别的锁。跨越单个集合但可能或可能不跨越单个文档的操作仍然会锁定整个集合。这是为什么 WiredTiger 是所有新部署的首选存储解决方案的主要原因。

# 锁报告

我们可以使用以下任何工具和命令来检查锁状态：

+   通过`locks`文档的`db.serverStatus()`

+   通过`locks`字段的`db.currentOp()`

+   `mongotop`

+   `mongostat`

+   MongoDB Cloud Manager

+   MongoDB Ops Manager

锁争用是一个非常重要的指标，因为如果它失控，可能会使我们的数据库陷入困境。

如果我们想终止一个操作，我们必须使用`db.killOp()` shell 命令。

# 锁让渡

具有数据库级别锁的数据库在压力下将不会真正有用，并且最终将大部分时间被锁定。在 MongoDB 早期版本中的一个聪明的解决方案是根据一些启发式原则使操作释放它们的锁。

影响多个文档的`update()`命令将释放它们的*X*锁以提高并发性。

在 MongoDB 早期版本中，MMAPv1 的前身会使用这些启发式方法来预测请求的操作之前数据是否已经在内存中。如果没有，它会释放锁，直到底层操作系统将数据加载到内存中，然后重新获取锁以继续处理请求。

最显著的例外是索引扫描，该操作不会释放其锁，并且会在等待数据从磁盘加载时阻塞。

由于 WiredTiger 仅在集合级别及以上使用意向锁，因此它实际上不需要这些启发式方法，因为意向锁不会阻塞其他读者和写者。

# 常用命令和锁

常用命令和锁如下：

| **命令** | **锁** |
| --- | --- |
| `find()` | *S* |
| `it() (查询游标)` | *S* |
| `insert()` | *X* |
| `remove()` | *X* |
| `update()` | *X* |
| `mapreduce()` | 根据情况为*S*和*X*。一些 MapReduce 块可以并行运行。 |
| `index()` |

+   **前台索引**：数据库锁。

+   **后台索引**：无锁，除了会返回错误的管理命令。此外，后台索引将花费更多的时间。

|

| `aggregate()` | *S* |
| --- | --- |

# 需要数据库锁的命令

以下命令需要数据库锁。在生产环境中发布这些命令之前，我们应该提前计划：

+   `db.collection.createIndex()` 使用（默认）前台模式

+   `reIndex`

+   `compact`

+   `db.repairDatabase()`

+   `db.createCollection()` 如果创建一个多 GB 的固定大小集合

+   `db.collection.validate()`

+   `db.copyDatabase()`，可能会锁定多个数据库

我们还有一些命令会在非常短的时间内锁定整个数据库：

+   `db.collection.dropIndex()`

+   `db.getLastError()`

+   `db.isMaster()`

+   任何`rs.status()`命令

+   `db.serverStatus()`

+   `db.auth()`

+   `db.addUser()`

这些命令不应该花费超过几毫秒的时间，所以我们不用担心，除非我们有使用这些命令的自动化脚本，那么我们必须注意限制它们发生的频率。

在分片环境中，每个`mongod`都会应用自己的锁，从而大大提高并发性。

在副本集中，我们的主服务器必须执行所有写操作。为了正确地将它们复制到辅助节点，我们必须同时锁定保存操作的 oplog 的本地数据库和我们的主要文档/集合/数据库。这通常是一个短暂的锁，我们不用担心。

副本集中的辅助节点将从主要本地数据库的 oplog 中获取写操作，应用适当的*X*锁，并在*X*锁完成后应用服务读取。

从前面的长篇解释中，很明显在 MongoDB 中应该尽量避免锁定。我们应该设计我们的数据库，以尽量避免尽可能多的*X*锁，并且当我们需要在一个或多个数据库上获取*X*锁时，在维护窗口中执行，并制定备份计划以防操作时间超出预期。

# 进一步阅读

您可以参考以下链接以获取更多信息：

+   [`docs.mongodb.com/manual/faq/concurrency/`](https://docs.mongodb.com/manual/faq/concurrency/)

+   [`docs.mongodb.com/manual/core/storage-engines/`](https://docs.mongodb.com/manual/core/storage-engines/)

+   [`www.mongodb.com/blog/post/building-applications-with-mongodbs-pluggable-storage-engines-part-1`](https://www.mongodb.com/blog/post/building-applications-with-mongodbs-pluggable-storage-engines-part-1)

+   [`www.mongodb.com/blog/post/building-applications-with-mongodbs-pluggable-storage-engines-part-2`](https://www.mongodb.com/blog/post/building-applications-with-mongodbs-pluggable-storage-engines-part-2?jmp=docs&_ga=2.154506616.1736193377.1502822527-355279797.1491859629)

+   [`docs.mongodb.com/manual/core/wiredtiger/`](https://docs.mongodb.com/manual/core/wiredtiger/)

+   [`docs.mongodb.com/manual/reference/method/db.collection.createIndex/#createindex-options`](https://docs.mongodb.com/manual/reference/method/db.collection.createIndex/#createindex-options)

+   [`docs.mongodb.com/manual/core/mmapv1/`](https://docs.mongodb.com/manual/core/mmapv1/)

+   [`docs.mongodb.com/manual/reference/method/db.createCollection/#create-collection-storage-engine-options`](https://docs.mongodb.com/manual/reference/method/db.createCollection/#create-collection-storage-engine-options)

+   [`source.wiredtiger.com/mongodb-3.4/struct_w_t___s_e_s_s_i_o_n.html`](http://source.wiredtiger.com/mongodb-3.4/struct_w_t___s_e_s_s_i_o_n.html)

+   [`webassets.mongodb.com/microservices_white_paper.pdf?_ga=2.158920114.90404900.1503061618-355279797.1491859629`](https://webassets.mongodb.com/microservices_white_paper.pdf?_ga=2.158920114.90404900.1503061618-355279797.1491859629)

+   [`webassets.mongodb.com/storage_engines_adress_wide_range_of_use_cases.pdf?_ga=2.125749506.90404900.1503061618-355279797.1491859629`](https://webassets.mongodb.com/storage_engines_adress_wide_range_of_use_cases.pdf?_ga=2.125749506.90404900.1503061618-355279797.1491859629)

+   [`docs.mongodb.com/manual/reference/method/db.createCollection/#create-collection-storage-engine-options`](https://docs.mongodb.com/manual/reference/method/db.createCollection/#create-collection-storage-engine-options)

+   [`source.wiredtiger.com/mongodb-3.4/struct_w_t___s_e_s_s_i_o_n.html`](http://source.wiredtiger.com/mongodb-3.4/struct_w_t___s_e_s_s_i_o_n.html)

+   [`docs.mongodb.com/manual/reference/read-concern/`](https://docs.mongodb.com/manual/reference/read-concern/)

+   [`www.percona.com/live/17/sessions/comparing-mongorocks-wiredtiger-and-mmapv1-performance-and-efficiency`](https://www.percona.com/live/17/sessions/comparing-mongorocks-wiredtiger-and-mmapv1-performance-and-efficiency)

+   [`www.percona.com/blog/2016/06/01/embracing-mongorocks/`](https://www.percona.com/blog/2016/06/01/embracing-mongorocks/)

+   [`www.percona.com/software/mongo-database/percona-tokumx`](https://www.percona.com/software/mongo-database/percona-tokumx)

+   [`www.slideshare.net/profyclub_ru/4-understanding-and-tuning-wired-tiger-the-new-high-performance-database-engine-in-mongodb-henrik-ingo-mongodb`](https://www.slideshare.net/profyclub_ru/4-understanding-and-tuning-wired-tiger-the-new-high-performance-database-engine-in-mongodb-henrik-ingo-mongodb/27)

# 总结

在本章中，我们学习了 MongoDB 中不同的存储引擎。我们确定了每种存储引擎的优缺点以及选择每种存储引擎的用例。

我们学习了如何使用多个存储引擎，我们如何使用它们以及它们的好处。本章的很大一部分也专门讨论了数据库锁定，它可能发生的原因，为什么它是不好的，以及我们如何避免它。

我们根据它们需要的锁将操作分开。这样，当我们设计和实现应用程序时，我们可以确保我们有一个尽可能少锁定我们数据库的设计。

在下一章中，我们将学习 MongoDB 以及如何使用它来摄取和处理大数据。


# 第十章：MongoDB Tooling

功能、稳定性和良好的驱动程序支持都很重要；然而，另一个对软件产品成功至关重要的领域是围绕它构建的生态系统。MongoDB（最初名为 10gen Inc.）在 8 年前的 2011 年推出了 MMS，并当时被视为一项创新。在本章中，我们将介绍 MongoDB 可用的一套不同工具，并探讨它们如何提高生产力：

+   MongoDB 企业 Kubernetes 运算符

+   MongoDB Mobile

+   MongoDB Stitch

+   MongoDB Sync

# 介绍

**MongoDB 监控服务**（**MMS**）是一个大多数免费的**软件即服务**（**SaaS**）解决方案，可以监视和访问任何注册到它的数据库的诊断信息。当它推出时，它极大地帮助了 10gen 的工程师解决客户遇到的任何问题。从那时起，工具已成为 MongoDB 演进的核心。

# MongoDB Atlas

MongoDB Atlas 是 MongoDB 的**数据库即服务**（**DBaaS**）产品。它作为多云产品提供，支持**亚马逊网络服务**（**AWS**）、微软 Azure 和谷歌云平台。

使用 DBaaS，补丁和小版本升级会自动应用，无需任何停机时间。使用**图形用户界面**（**GUI**），开发人员可以部署地理分布式数据库实例，以避免任何单点故障。对于访问量大的网站，这也可以通过将数据库服务器放置在接近访问其数据的用户的地方来帮助。这是 MongoDB 战略和产品的关键部分，因为他们支持让数据靠近用户。

与大多数 DBaaS 产品类似，Atlas 允许用户使用 GUI 扩展部署。每个部署都位于自己的**虚拟专用云**（**VPC**）上，并可以利用 MongoDB 企业服务器的功能，如加密密钥管理、**轻量目录访问协议**（**LDAP**）和审计功能。

实时迁移服务可用于从现有部署（本地部署、三个支持的云提供商之一或其他 DBaaS 服务，如**mLab**、**Compose**和**ObjectRocket**）迁移数据集，使用相同的 GUI。

# 创建新的集群

使用 MongoDB Atlas 创建新的集群就像点击并通过配置选项进行选择一样简单。在下面的屏幕截图中，我们可以看到创建新集群时可用的所有选项：

![](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-mongo-4x/img/dd6861db-5e28-4df0-947d-1c276c700cce.png)

以下屏幕截图显示了区域配置摘要：

![](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-mongo-4x/img/bce328e1-6820-4a6a-a483-919dc3d5e484.png)

MongoDB Atlas 中的一个改变游戏规则的设置是能够立即在不同区域和日期中心（对于三个主要云提供商）之间提供地理分布式服务器，目标是使我们的数据尽可能靠近我们的用户。这对性能和法规原因（如**通用数据保护条例**（**GDPR**）对欧盟）都很有用。

通过启用全局写入，我们可以开始配置此设置。使用任何两个模板——全局性能或优秀的全局性能——管理员可以创建服务器配置，使其距离世界各地的任何用户都不到 120 毫秒或 80 毫秒。管理员还可以定义自己的自定义分配，从区域到数据中心。

在区域配置摘要中，我们可以看到我们的设置将如何影响性能的概述。M30 是启用了分片的 MongoDB Atlas 计划，该配置正在（在幕后）为每个区域创建一个分片。我们可以在每个区域创建更多的分片，但目前不建议这样做。

在所有区域启用本地读取配置将在除了用于写入数据的区域之外的每个区域创建本地只读副本集节点。因此，如果我们有三个区域（*A*，*B*和*C*），我们最终会发现*A*的写入会发送到*A*，但来自*A*的读取将在*A*区域的服务器上进行，或者*B*或*C*，取决于哪个服务器对用户更近。对于*B*和*C*区域也是一样的。

这一部分对于复杂的多区域部署可能是最重要的，应该非常小心对待。

接下来是配置我们想要用于我们集群的服务器：

![](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-mongo-4x/img/3bb9b097-6595-41af-9dfe-06cf6e2bca3f.png)

这类似于我们在 EC2 或 Microsoft Azure 中选择服务器的方式。需要注意的主要点是我们可以选择自定义的 IOPS（每秒 I/O 操作数）性能，并且我们应该选择自动扩展存储选项，以避免磁盘容量不足。除此选项外，始终有必要关注存储分配，以避免在结算周期结束时产生过多费用。

在下一个面板中，我们可以为我们的集群配置备份和高级选项。以下截图显示了连续备份的附加设置：

![](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-mongo-4x/img/56ffb570-80cb-4f6b-aa62-5a39e447282c.png)

以下截图显示了启用 BI 连接器的高级设置选项：

![](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-mongo-4x/img/8ad297ed-73fb-406d-90f0-018948a81e54.png)

以下截图显示了可用的更多配置选项：

![](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-mongo-4x/img/15ca0080-fc75-4d04-b01d-41697b6f5d7a.png)

# 重要提示

MongoDB 在 MongoDB Atlas 中提供了一些有用的提示，包括以下内容：

+   尽可能使用最新版本的 MongoDB。

+   在撰写时，使用最新的**传输层安全性**（**TLS**）版本，即 1.3。

+   静态加密不能与连续备份一起使用。我们需要选择云提供商的快照才能使用此功能。

+   除非我们知道为什么需要，否则最好禁用服务器端 JavaScript，例如当我们有传统的 MapReduce 作业时。

+   对所有查询需要索引可能是有用的，如果我们有一个明确定义的业务案例和对如何使用数据库的要求，和/或者我们预期我们的数据集会非常大，以至于在没有索引的情况下查询几乎是不可能的。

+   最后，我们可以选择我们的集群名称。创建后无法更改，因此在单击“创建集群”按钮之前与团队成员达成一致意见非常重要。

经过一段时间的等待，我们的集群将投入运行，我们将能够通过普通的旧 MongoDB URI 连接到它。

# MongoDB Cloud Manager

Cloud Manager 以前被称为**MongoDB 管理服务**（**MMS**），在此之前被称为**MongoDB 监控服务**（**MMS**），是一个托管的 SaaS，用于本地部署的 MongoDB。

作为 DBaaS 解决方案的 Atlas 可以为数据库管理提供端到端的解决方案。对于许多用例来说，这可能是不可行的。在这种情况下，可能有意义以按需付费的方式使用一些功能。

Cloud Manager 有一个有限的免费层和几个付费层。

以下是 Cloud Manager 的一些关键特性：

+   自动备份

+   超过 100 个数据库指标和**关键绩效指标**（**KPIs**）可用于跟踪 MongoDB 的性能

+   定制的警报，可以与 PagerDuty、电子邮件和短信等第三方系统集成

+   统一的操作视图，可以通过直接查询其 JSON API，或者将其与 New Relic 等流行的性能跟踪解决方案集成

高级计划还提供关于性能和索引的建议。Cloud Manager 的唯一要求是在我们的应用程序中安装所需的代理。

# MongoDB Ops Manager

在许多方面，Ops Manager 与 Cloud Manager 不同。与 Cloud Manager 相比，它是一个可下载的可执行文件，适用于 Windows Server、**Red Hat Enterprise Linux**（**RHEL**）或 Ubuntu。

在此基础上，用户需要在自己的基础设施中安装和管理服务。

除了这个区别，Ops Manager 还可以帮助实现与 Cloud Manager 类似的目标：

+   监控超过 100 个性能指标

+   自动安装和升级集群；加索引维护可以实现零停机

+   用于连续、增量备份和恢复到特定时间点

+   查询优化

+   索引建议

Ops Manager 的一个示例拓扑如下：

![](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-mongo-4x/img/3cfdade5-29d8-4951-b2f9-f9d735320e56.png)

除了 Ops Manager 和 MongoDB 节点，如果启用了备份，我们还需要快照存储。

如果我们需要一个本地解决方案来保障安全性或其他原因，Ops Manager 可能是 Cloud Manager 的更好选择。这是 MongoDB Enterprise Server 付费解决方案的一部分。

# MongoDB Charts

MongoDB Charts 是一个从 MongoDB 数据生成可视化的工具。它使非技术人员可以使用 GUI 查询 MongoDB 数据库，并与同事分享结果。

MongoDB Charts 可以创建一系列图表，包括以下内容：

+   柱状图和条形图参考

+   线性和面积图参考

+   网格图表：

+   热力图参考

+   散点图参考

+   圆环图参考

+   文本图表：数字图表参考

与 Ops Manager 类似，它是一个独立的可执行文件，利用 Docker 在本地安装和管理。

使用副本集辅助节点进行图表查询。理想情况下，使用辅助、隐藏、不可选举节点作为副本集中的分析节点。

# MongoDB Compass

MongoDB Compass 类似于 MongoDB Charts，但在图表功能方面功能较少，更加重视运行临时查询并连接到我们的数据库，而无需使用命令行界面。

Compass 提供了通过 GUI 查询 MongoDB 和可视化构建查询的功能。它可以对结果数据集提供丰富的可视化，并帮助通过点和点击界面构建聚合查询。

Compass 还为大多数围绕查询和索引性能的管理查询提供可视化，因此可以从数据库管理员的角度监视和排除集群。它公开了一个 API，可用于导入或开发插件。

非技术用户的一个有用功能是能够下载一个只读版本，以限制对非破坏性操作的访问。此工具还有一个隔离版本，可用于限制连接到单个选择的服务器。这些请求也将进行 TLS 加密。

Compass 可在 Windows、OSX、Red Hat 和 Ubuntu 上作为可执行下载文件提供。MongoDB Compass 有一个有限的免费版本，完整功能集可通过 MongoDB 订阅包获得。

# MongoDB 业务智能连接器（BI）

MongoDB Connector for BI 是非开发人员最有用的工具之一。它是 MongoDB Enterprise Advanced 订阅的一部分，可以使用标准 SQL 查询与 BI 工具集成。

它使 MongoDB 能够与 Tableau、Qlik、Spotfire、Cognos、MicroStrategy 和 SAP BusinessObjects 等企业工具集成。

它可作为可执行下载文件提供给 Amazon Linux、Debian、OSX、Red Hat、SUSE、Ubuntu 和 Windows 平台，并且可以与本地数据库和 MongoDB Atlas 一起使用。一旦安装和配置正确，它可以提供大多数 BI 工具可以使用的**开放数据库连接**（**ODBC**）**数据源名称**（**DSN**）。

# Kubernetes 简介

Kubernetes ([`kubernetes.io`](https://kubernetes.io))是一个用于自动化部署、扩展和管理容器化应用程序的开源容器编排系统。通俗地说，我们可以使用 Kubernetes（通常称为 k8s）来管理通过容器部署的应用程序。Kubernetes 最初是在 Google 开发的，现在由**Cloud Native Computing Foundation** (**CNCF**)维护。

最广泛使用的容器技术可能是 Docker。我们可以在任何 PC 上下载和安装 Docker，并通过几个命令安装一个与我们的主机系统隔离并包含我们的应用程序代码的 Docker 镜像。Docker 执行操作系统级虚拟化，所有容器都由主机的操作系统内核运行。这导致容器比完整虚拟机（VM）更轻量级。

可以使用**Docker Swarm**来编排多个 Docker 容器。这类似于 Kubernetes，有时这两个系统会直接进行比较。

MongoDB 提供了可以帮助管理员使用 Kubernetes 部署和管理 MongoDB 集群的工具。

# 企业 Kubernetes Operator

从 MongoDB 4.0 开始，**MongoDB Enterprise Operator for Kubernetes**使用户能够直接从 Kubernetes API 部署和管理 MongoDB 集群。这避免了直接连接到 Cloud Manager 或 Ops Manager 的需要，并简化了 Kubernetes 集群的部署和管理。

Cloud Manager 在大多数方面相当于 Ops Manager 的 SaaS 版本。

可以使用 Helm，Kubernetes 的软件包管理器，安装企业 Kubernetes Operator。首先，我们必须从 MongoDB 克隆 GitHub 存储库：[`github.com/mongodb/mongodb-enterprise-kubernetes.git`](https://github.com/mongodb/mongodb-enterprise-kubernetes.git)。

当我们将目录更改为我们的本地副本后，我们可以发出以下命令：

```sql
helm install helm_chart/ --name mongodb-enterprise
```

然后我们将安装本地副本；下一步是配置它。

通过配置我们的本地安装，我们需要应用一个 Kubernetes `ConfigMap`文件。我们需要从 Ops Manager 或 Cloud Manager 复制的配置设置如下：

+   **基本 URL**：Ops Manager 或 Cloud Manager 的 URL。对于 Cloud Manager，这将是[`cloud.mongodb.com`](http://cloud.mongodb.com)；对于 Ops Manager，这应该类似于`http://<MY_SERVER_NAME>:8080/`。

+   **项目 ID**：Ops Manager 项目的 ID，Enterprise Kubernetes Operator 将部署到该项目中。这应该在 Ops Manager 或 Cloud Manager 中创建，并且是用于组织 MongoDB 集群并为项目提供安全边界的唯一 ID。它应该是一个 24 位十六进制字符串。

+   **用户**：现有的 Ops Manager 用户名。这是 Ops Manager 中用户的电子邮件，我们希望 Enterprise Kubernetes Operator 在连接到 Ops Manager 时使用。

+   **公共 API 密钥**：这是 Enterprise Kubernetes Operator 用于连接到 Ops Manager REST API 端点的密钥。

这是通过在 Ops Manager 控制台上点击用户名并选择帐户来创建的。在下一个屏幕上，我们可以点击公共 API 访问，然后点击“生成”按钮并提供描述。下一个屏幕将显示我们需要的公共 API 密钥。

这是我们唯一一次查看此 API 密钥的机会，所以我们需要把它写下来，否则我们将需要重新生成一个新的密钥。

一旦我们有了这些值，我们就可以创建 Kubernetes `ConfigMap`文件，文件名可以任意，只要是`.yaml`文件即可。在我们的情况下，我们将命名为`mongodb-project.yaml`。

其结构将如下所示：

```sql
apiVersion: v1
kind: ConfigMap
metadata:
 name:<<any sample name we choose(1)>>
 namespace: mongodb
data:
 projectId:<<Project ID from above>>
 baseUrl: <<BaseURI from above>>
```

然后我们可以使用以下命令将此文件应用到 Kubernetes：

```sql
kubectl apply -f mongodb-project.yaml
```

我们需要采取的最后一步是创建 Kubernetes 秘钥。可以使用以下命令来完成：

```sql
kubectl -n mongodb create secret generic <<any sample name for credentials we choos>> --from-literal="user=<<User as above>>" --from-literal="publicApiKey=<<our public api key as above>>"
```

我们需要记下凭据名称，因为我们在后续步骤中会用到它。

现在我们准备使用 Kubernetes 部署我们的副本集！我们可以创建一个名为`replica-set.yaml`的文件，其结构如下：

```sql
apiVersion: mongodb.com/v1
kind: MongoDbReplicaSet
metadata:
 name: <<any replica set name we choose>>
 namespace: mongodb
spec:
 members: 3
 version: 3.6.5
persistent: false
project: <<the name value (1) that we chose in metadata.name of ConfigMap file above>>
credentials: <<the name of credentials secret that we chose above>>
```

我们使用`kubectl apply`应用新配置：

```sql
kubectl apply -f replica-set.yaml
```

我们将能够在 Ops Manager 中看到我们的新副本集。

要使用 Kubernetes 对 MongoDB 进行故障排除和识别问题，我们可以使用

`kubectl logs`用于检查日志，`kubectl exec`用于进入运行 MongoDB 的容器之一。

# MongoDB Mobile

MongoDB Mobile 是 MongoDB 数据库的移动版本。它针对智能手机和物联网传感器，通过嵌入式 MongoDB。MongoDB Mobile 有两个核心部分：

+   在设备上本地运行的 MongoDB 数据库服务器，实现对数据的离线访问。该数据库是 MongoDB Server Community Edition 的精简版本，不包含 Mobile 不需要的任何功能（例如复制）。

+   本机 Java 和 Android SDK 提供对数据库的低级访问，并与本地 Mobile 数据库和任何 MongoDB Stitch 后端进行交互。

Mobile SDK 有两种操作模式。在本地模式下，SDK 只允许访问本地 Mobile 数据库，并且无法与 Atlas 中的任何外部源进行同步。在远程模式下，SDK 可以访问 MongoDB Atlas 和 MongoDB Mobile 数据库，并在它们之间进行同步。

以下是 MongoDB Mobile 相对于服务器版本的一些限制：

+   不支持复制

+   不支持分片

+   没有数据库身份验证；但是，MongoDB Mobile 数据库只接受源自应用程序的连接

+   没有 SSL

+   静态加密

+   不支持更改流

+   没有服务器端 JavaScript 评估（出于性能原因）

+   没有多文档 ACID 事务

要设置 MongoDB Mobile，我们需要先下载并安装 MongoDB Stitch SDK。然后，创建和查询本地 MongoDB 数据库就像几行代码一样简单（此示例为 Android）：

```sql
Import packages:
// Base Stitch Packages
import com.mongodb.stitch.android.core.Stitch;
import com.mongodb.stitch.android.core.StitchAppClient;
// Packages needed to interact with MongoDB and Stitch
import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoCollection;
// Necessary component for working with MongoDB Mobile
import com.mongodb.stitch.android.services.mongodb.local.LocalMongoDbService;
```

初始化数据库如下：

```sql
// Create the default Stitch Client
final StitchAppClient client =
  Stitch.initializeDefaultAppClient("<APP ID>");
// Create a Client for MongoDB Mobile (initializing MongoDB Mobile)
final MongoClient mobileClient =
  client.getServiceClient(LocalMongoDbService.clientFactory);
```

接下来，获取对数据库的引用：

```sql
MongoCollection<Document> localCollection =
  mobileClient.getDatabase("my_db").getCollection("my_collection");
```

插入`document`如下：

```sql
localCollection.insertOne(document);
```

然后，使用`first()`找到第一个文档：

```sql
Document doc = localCollection.find().first();
```

与 MongoDB Stitch 一起使用时，MongoDB Mobile 的功能最强大，我们将在下一节中探讨。

# MongoDB Stitch

MongoDB Stitch 是 MongoDB 的无服务器平台。它基于功能的四个不同领域：

+   第一个领域是 QueryAnywhere。QueryAnywhere 允许客户端应用程序使用其查询语言访问 MongoDB。我们可以在 Stitch 服务器上按照每个集合的基础定义数据访问规则，以允许我们根据用户数据（`userId`）过滤结果。

+   第二个领域是 Stitch 函数。这些是简单的 JavaScript 函数，可以在 Stitch 平台内部无需服务器执行。通过使用 Stitch 函数，我们可以实现应用程序逻辑，公开 API，并与第三方服务构建集成。这项服务与亚马逊的 AWS Lambda 非常相似。

+   第三个领域是 Stitch 触发器。类似于 MongoDB 服务器的更改流和触发器，它们用于关系数据库，Stitch 触发器通过响应数据库状态的变化实时执行用户定义的函数。

+   最后，还有 Stitch Mobile Sync，它将 Stitch 无服务器提供与 Mobile MongoDB 的桥接。通过使用它，我们可以开发一个在智能手机上具有本地 MongoDB 数据库的 Mobile 服务，该数据库与我们在云中的 MongoDB Atlas 数据库完美同步。

通过这种方式，我们可以在应用程序中本地查询数据，无需延迟，甚至在离线状态下，依靠 Stitch Mobile Sync 来保持我们的数据存储最新。

Stitch 可用于 Web（JavaScript）、Android 和 macOS（Swift）。

# QueryAnywhere

QueryAnywhere 允许直接从客户端应用程序查询 MongoDB 服务器数据。一个关键的区分和功能，允许我们安全地定义数据访问规则，以根据文档内容或登录用户过滤结果。

# 规则

MongoDB 规则是角色和分配给该角色的权限的组合。角色定义了一组用户，这些用户将具有对文档的相同读/写访问权限。Stitch 中的角色可以使用**apply-when**规则进行定义。

这可以使用`%%`变量表示法来定义：

```sql
{
  "createdBy": "%%user.id"
}
```

每个角色可以有一个或多个权限，定义了他们可以在文档中读取和/或写入哪些字段。

MongoDB Stitch 还提供了四个预定义角色和权限的模板，围绕最常见的用例。

+   用户只能读取和写入自己的数据。

+   用户可以读取所有数据，但只能写入自己的数据。

+   用户只能读取所有数据。

+   用户可以读取和写入自己的数据。属于共享列表的用户可以读取该数据。

授权在规则之前应用。如果用户未经授权访问集合，它们的规则将根本不会被评估。

# 函数

Stitch 函数可用于执行服务器端应用程序逻辑。它们是用 JavaScript ES6+编写的，不需要服务器。

以下是函数的一些关键限制：

+   它们一旦返回就停止执行

+   它们可以运行长达 60 秒，使用高达 256 MB 的内存

+   它们不能导入模块或使用一些核心 JavaScript 功能，例如全局对象类型、数学、数字、字符串、数组和对象 API

Stitch 函数可以通过 CLI 或从 Stitch UI 导入。对于我们命名为`multiply`的简单函数，我们可以在 UI 中添加以下代码：

```sql
exports = function(a, b) {
 return a * b;
};
```

然后我们可以从另一个函数、webhook 或 Stitch 中的触发器调用它：

```sql
context.functions.execute("multiply", a, b);
```

我们还可以在 Stitch JSON 表达式中使用`%function`触发其执行：

```sql
{
 "%%true": {
   "%function": {
     "name": "multiply",
     "arguments": [3,4]
   }
 }
}
```

我们甚至可以使用 Stitch SDK（JavaScript、Android 或 macOS）从我们的客户端应用程序调用此函数：

```sql
const client = Stitch.defaultAppClient;
client.callFunction("multiply", [3, 4]).then(result => {
console.log(result) // Output: 12
});
```

# 触发器

触发器是基于 Stitch 函数构建的，用于在数据库触发器发生数据库集合更改时执行，或者在使用身份验证触发器修改用户时执行身份验证逻辑。

数据库触发器可以在`INSERT`，`UPDATE`，`REPLACE`和`DELETE`数据库操作中执行。

所有这些值都需要区分大小写。

我们需要定义**链接函数**，即触发器触发后将执行的函数。对于`UPDATE`操作的一个有趣选项是`fullDocument`。当设置为`true`时，这将包括操作的完整结果。这始终受到 16 MB 文档大小限制的限制，因此接近 16 MB 限制的文档的更新可能会失败，因为结果将超出限制。

另一方面，身份验证触发器允许我们在身份验证事件上执行自定义代码。这些可以在以下提供程序的`CREATE`，`LOGIN`和`DELETE`操作类型上触发：

+   `oauth2-google`

+   `oauth2-facebook`

+   `custom-token`

+   `local-userpass`

+   `api-key`

+   `anon-user`

身份验证操作类型区分大小写，需要全部大写。最多可以同时执行 50 个触发器。如果我们尝试调用更多，它们将排队等待以**先进先出**（**FIFO**）的方式进行处理。

触发器与 RDBMS 触发器功能非常相似，而且它们易于灵活地通过 Stitch 触发器的 GUI 控制台进行管理。

# Mobile Sync

MongoDB Stitch Mobile Sync 中的最新添加之一可以在 MongoDB Mobile 和服务器后端之间无缝同步数据（在撰写本文时，它必须托管在 MongoDB Atlas 上）。Mobile Sync 还基于更改流来监听本地和远程数据库之间的数据更改。随着本地 Mobile 数据库中的数据更改，我们可能会遇到本地和远程状态之间的冲突。这就是为什么我们需要定义一些处理程序来指定在这种情况下应该发生什么。我们需要为我们的模型实现三个接口：

+   `ConflictHandler`

+   `ErrorListener`

+   `ChangeEventListener`

`ConflictHandler`有一个方法，参数是冲突本地和远程事件的`documentId`，返回冲突的解决方案，如下所示：

```sql
DocumentT resolveConflict(BsonValue documentId,
                         ChangeEvent<DocumentT> localEvent,
                         ChangeEvent<DocumentT> remoteEvent)
```

`ErrorListener`不返回任何内容，并在发生`documentId`和非网络相关异常的错误时调用：

```sql
void onError(BsonValue documentId,Exception error)
```

最后，`ChangeEventListener`也不返回任何值，并在给定`documentId`的任何更改`event`发生时调用：

```sql
void onEvent(BsonValue documentId, ChangeEvent<DocumentT> event)
```

# 总结

在这一章中，我们通过不同的 MongoDB 工具，并学习如何使用它们来提高生产力。从 MongoDB Atlas 开始，这是托管的 DBaaS 解决方案，我们接着介绍了 Cloud Manager 和 Ops Manager，并探讨了它们之间的区别。

然后，我们深入了解了 MongoDB Charts 和 MongoDB Compass——基于 GUI 的 MongoDB 管理工具。我们了解了 MongoDB Connector for BI 以及它如何对我们的目的有用。然后我们讨论了 Kubernetes，它与 Docker 和 Docker Swarm 的比较，以及我们如何将 Kubernetes 与 MongoDB Enterprise Operator 一起使用。接下来的部分专门介绍了 MongoDB Mobile 和 Stitch——MongoDB 4.0 中的两个重大增强。我们介绍了使用 Stitch 功能的实际示例，特别是 QueryAnywhere、触发器和函数。最后，我们简要介绍了 Mobile Sync，这是 MongoDB 武器库中最新的增加之一，并探讨了它如何用于将我们的移动应用程序与基于云的数据库同步。

在下一章中，我们将转变方向，处理如何使用 MongoDB 处理大数据，以摄取和处理大型流式和批处理数据集。


# 第十一章：利用 MongoDB 进行大数据处理

MongoDB 通常与大数据管道一起使用，因为它具有高性能、灵活性和缺乏严格的数据模式。本章将探讨大数据领域以及 MongoDB 如何与消息队列、数据仓库和 ETL 管道配合使用。

我们将在本章讨论以下主题：

+   什么是大数据？

+   消息队列系统

+   数据仓库

+   使用 Kafka、Spark 在 HDFS 上以及 MongoDB 的大数据用例

# 什么是大数据？

在过去的五年里，访问和使用互联网的人数几乎翻了一番，从不到 20 亿增加到约 37 亿。全球一半的人口现在都在网上。

随着互联网用户数量的增加，以及网络的发展，每年都会向现有数据集中添加更多的数据。2016 年，全球互联网流量为 1.2 泽字节（相当于 1.2 亿兆字节），预计到 2021 年将增长到 3.3 泽字节。

每年产生的大量数据意味着数据库和数据存储通常必须能够高效扩展和处理我们的数据。

**大数据**这个术语最早是由 John Mashey 在 1980 年代提出的（[`static.usenix.org/event/usenix99/invited_talks/mashey.pdf`](http://static.usenix.org/event/usenix99/invited_talks/mashey.pdf)），并且在过去的十年中随着互联网的爆炸性增长而开始流行起来。大数据通常指的是那些传统数据处理系统无法处理的过大和复杂的数据集，因此需要一些专门的系统架构来处理。

大数据的定义特征通常如下：

+   容量

+   多样性

+   速度

+   真实性

+   变异性

多样性和变异性指的是我们的数据以不同的形式出现，我们的数据集存在内部不一致性。这些需要通过数据清洗和规范化系统进行平滑处理，然后我们才能实际处理我们的数据。

真实性指的是数据质量的不确定性。数据质量可能会有所不同，对于某些日期来说是完美的数据，而对于其他日期来说则是缺失的数据集。这影响了我们的数据管道以及我们可以投入到数据平台中的数量，因为即使在今天，三分之一的商业领导人也不完全信任他们用来做出商业决策的信息。

最后，速度可能是大数据最重要的定义特征（除了明显的容量属性），它指的是大数据集不仅具有大量数据，而且增长速度加快。这使得传统的存储方式，比如索引，成为一项困难的任务。

# 大数据领域

大数据已经发展成一个影响经济各个领域的复杂生态系统。从炒作到不切实际的期望，再到现实，如今大多数财富 1000 强公司都实施和部署了大数据系统，为企业创造了真正的价值。

如果我们按行业对参与大数据领域的公司进行分段，可能会得出以下几个部分：

+   基础设施

+   分析

+   应用-企业

+   应用-行业

+   跨基础设施分析

+   数据来源和 API

+   数据资源

+   开源

从工程角度来看，我们可能更关心的是底层技术，而不是它们在不同行业领域的应用。

根据我们的业务领域，我们可能会从不同的来源获取数据，比如事务性数据库、物联网传感器、应用服务器日志、通过 Web 服务 API 的其他网站，或者只是纯粹的网页内容提取：

![](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-mongo-4x/img/810c5ec0-b3c4-469b-a7fd-c26d1bc1dadf.png)

# 消息队列系统

在先前描述的大多数流程中，我们有数据被提取、转换、加载（ETL）到企业数据仓库（EDW）。为了提取和转换这些数据，我们需要一个消息队列系统来处理流量激增、临时不可用的端点以及可能影响系统可用性和可伸缩性的其他问题。

消息队列还可以在消息的生产者和消费者之间提供解耦。这通过将我们的消息分成不同的主题/队列来实现更好的可伸缩性。

最后，使用消息队列，我们可以拥有不关心消息生产者所在位置的位置不可知服务，这提供了不同系统之间的互操作性。

在消息队列世界中，目前在生产中最受欢迎的系统是 RabbitMQ、ActiveMQ 和 Kafka。在我们深入研究使用案例之前，我们将对它们进行简要概述。

# Apache ActiveMQ

Apache ActiveMQ 是一个用 Java 编写的开源消息代理，配有完整的 Java 消息服务（JMS）客户端。

它是我们在这里检查的三种实现中最成熟的，有着成功的生产部署的悠久历史。许多公司提供商业支持，包括 Red Hat。

这是一个相当简单的排队系统，可以轻松设置和管理。它基于 JMS 客户端协议，是 Java EE 系统的首选工具。

# RabbitMQ

另一方面，RabbitMQ 是用 Erlang 编写的，基于高级消息队列协议（AMQP）协议。AMQP 比 JMS 更强大和复杂，因为它允许点对点消息传递、请求/响应和发布/订阅模型，用于一对一或一对多的消息消费。

在过去的 5 年中，RabbitMQ 变得越来越受欢迎，现在是搜索量最大的排队系统。

RabbitMQ 的架构概述如下：

![](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-mongo-4x/img/b4473fae-e41f-43d5-b002-2a30e6ff17ba.png)

RabbitMQ 系统的扩展是通过创建一组 RabbitMQ 服务器集群来完成的。集群共享数据和状态，这些数据和状态是复制的，但消息队列在每个节点上是独立的。为了实现高可用性，我们还可以在不同节点中复制队列。

# Apache Kafka

另一方面，Kafka 是由 LinkedIn 首先为其自身内部目的开发的排队系统。它是用 Scala 编写的，从根本上设计为水平可伸缩和尽可能高的性能。

专注于性能是 Apache Kafka 的关键区别因素，但这意味着为了实现性能，我们需要牺牲一些东西。Kafka 中的消息没有唯一的 ID，而是通过它们在日志中的偏移量来寻址。Apache Kafka 消费者不受系统跟踪；这是应用程序设计的责任。消息排序是在分区级别实现的，消费者有责任确定消息是否已经被传递。

语义学是在 0.11 版本中引入的，并且是最新的 1.0 版本的一部分，因此消息现在可以在分区内严格排序，并且每个消费者始终只能到达一次：

![](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-mongo-4x/img/5c856121-fad0-42bb-a2fb-6c572334bbc6.png)

# 数据仓库

使用消息队列系统只是我们数据管道设计的第一步。在消息队列的另一端，我们通常会有一个数据仓库来处理大量到达的数据。那里有很多选择，本书的重点不是讨论这些选择或进行比较。然而，我们将简要介绍 Apache 软件基金会中最广泛使用的两个选项：Apache Hadoop 和 Apache Spark。

# Apache Hadoop

第一个，也可能仍然是最广泛使用的大数据处理框架是 Apache Hadoop。它的基础是**Hadoop 分布式文件系统**（**HDFS**）。在 2000 年代由 Yahoo!开发，最初是作为**Google 文件系统**（**GFS**）的开源替代品，GFS 是谷歌用于分布式存储其搜索索引的文件系统。

Hadoop 还实现了一个 MapReduce 替代方案，用于谷歌专有系统的 Hadoop MapReduce。与 HDFS 一起，它们构成了一个分布式存储和计算的框架。用 Java 编写，具有大多数编程语言的绑定和许多提供抽象和简单功能的项目，有时基于 SQL 查询，这是一个可靠地用于存储和处理几十亿甚至拍它字节数据的系统。

在后续版本中，Hadoop 通过引入**Yet Another Resource Negotiator**（**YARN**）变得更加模块化，为应用程序提供了在 Hadoop 之上开发的抽象。这使得几个应用程序可以部署在 Hadoop 之上，例如**Storm**，**Tez**，**OpenMPI**，**Giraph**，当然还有**Apache Spark**，我们将在接下来的部分中看到。

Hadoop MapReduce 是一个面向批处理的系统，意味着它依赖于批量处理数据，并不适用于实时用例。

# Apache Spark

Apache Spark 是加州大学伯克利分校 AMPLab 的集群计算框架。Spark 并不是完整的 Hadoop 生态系统的替代品，而主要是 Hadoop 集群的 MapReduce 方面。而 Hadoop MapReduce 使用磁盘批处理操作来处理数据，Spark 则同时使用内存和磁盘操作。预期地，对于适合内存的数据集，Spark 更快。这就是为什么它对于实时流应用更有用，但也可以轻松处理不适合内存的数据集。

Apache Spark 可以在 HDFS 上使用 YARN 或独立模式运行，如下图所示：

![](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-mongo-4x/img/72713523-c529-41c1-850c-451605c31865.png)

这意味着在某些情况下（例如我们将在下面的用例中使用的情况），如果我们的问题确实在 Spark 的能力范围内得到了很好的定义和限制，我们可以完全放弃 Hadoop 而选择 Spark。

对于内存操作，Spark 可能比 Hadoop MapReduce 快 100 倍。Spark 为 Scala（其本地语言），Java，Python 和 Spark SQL（SQL92 规范的变体）提供了用户友好的 API。Spark 和 MapReduce 都具有容错性。Spark 使用分布在整个集群中的 RDD。

从总体上看，根据 Spark 的架构，我们可以有几个不同的 Spark 模块一起工作，满足不同的需求，从 SQL 查询到流处理和机器学习库。

# 将 Spark 与 Hadoop MapReduce 进行比较

Hadoop MapReduce 框架更常与 Apache Spark 进行比较，后者是一种旨在解决类似问题空间中问题的新技术。它们最重要的属性总结在下表中：

|  | **Hadoop MapReduce** | **Apache Spark** |
| --- | --- | --- |
| 编写语言 | Java | Scala |
| 编程模型 | MapReduce | RDD |
| 客户端绑定 | 大多数高级语言 | Java，Scala，Python |
| 使用便捷性 | 中等，具有高级抽象（Pig，Hive 等） | 良好 |
| 性能 | 批处理高吞吐量 | 流处理和批处理模式高吞吐量 |
| 使用 | 磁盘（I/O 受限） | 内存，如果需要磁盘会降低性能 |
| 典型节点 | 中等 | 中等大 |

从上述比较可以看出，这两种技术都有优缺点。Spark 在性能方面可能更好，特别是在使用较少节点的问题上。另一方面，Hadoop 是一个成熟的框架，具有出色的工具，几乎可以覆盖每种用例。

# MongoDB 作为数据仓库

Apache Hadoop 经常被描述为大数据框架中的 800 磅大猩猩。另一方面，Apache Spark 更像是一只 200 磅的猎豹，因为它的速度、敏捷性和性能特点，使其能够很好地解决 Hadoop 旨在解决的一部分问题。

另一方面，MongoDB 可以被描述为 NoSQL 世界中的 MySQL 等效物，因为它的采用和易用性。MongoDB 还提供聚合框架、MapReduce 功能和使用分片进行水平扩展，这实质上是在数据库级别进行数据分区。因此，一些人自然会想知道为什么我们不使用 MongoDB 作为我们的数据仓库来简化我们的架构。

这是一个相当有说服力的论点，也许使用 MongoDB 作为数据仓库是有道理的，也可能不是。这样做的优势如下：

+   更简单的架构

+   消息队列的需求减少，减少了系统的延迟

缺点如下：

+   MongoDB 的 MapReduce 框架不能替代 Hadoop 的 MapReduce。尽管它们都遵循相同的理念，但 Hadoop 可以扩展以容纳更大的工作负载。

+   使用分片来扩展 MongoDB 的文档存储将在某个时候遇到瓶颈。尽管 Yahoo!报告称其最大的 Hadoop 集群使用了 42,000 台服务器，但最大的 MongoDB 商业部署仅达到 50 亿（Craigslist），而百度的节点数和数据量达到了 600 个节点和 PB 级数据，这家互联网巨头主导着中国互联网搜索市场等领域。

在扩展方面存在一个数量级的差异。

MongoDB 主要设计为基于磁盘上存储数据的实时查询数据库，而 MapReduce 是围绕使用批处理设计的，Spark 是围绕使用数据流设计的。

# 一个大数据用例

将所有这些付诸实践，我们将开发一个完全工作的系统，使用数据源、Kafka 消息代理、在 HDFS 上运行的 Apache Spark 集群，供应 Hive 表，以及 MongoDB 数据库。我们的 Kafka 消息代理将从 API 摄取数据，为 XMR/BTC 货币对流动市场数据。这些数据将传递给 HDFS 上的 Apache Spark 算法，以根据以下内容计算下一个 ticker 时间戳的价格：

+   已经存储在 HDFS 上的历史价格语料库

+   从 API 到达的流动市场数据

然后，这个预测的价格将使用 MongoDB Connector for Hadoop 存储在 MongoDB 中。MongoDB 还将直接从 Kafka 消息代理接收数据，将其存储在一个特殊的集合中，文档过期日期设置为一分钟。这个集合将保存最新的订单，旨在被我们的系统用来购买或出售，使用来自 Spark ML 系统的信号。

例如，如果价格当前为 10，我们出价为 9.5，但我们预计下一个市场 tick 价格会下降，那么系统会等待。如果我们预计下一个市场 tick 价格会上涨，那么系统会将出价提高到 10.01 以匹配下一个 ticker 的价格。

同样，如果价格为 10，我们出价为 10.5，但预计价格会下降，我们会调整我们的出价为 9.99，以确保我们不会为此支付过多。但是，如果预计价格会上涨，我们会立即购买，以在下一个市场 tick 中获利。

在图表上，我们的架构如下：

![](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-mongo-4x/img/b14f1dcd-50d9-44b7-9902-c3234bb6efa8.png)

API 通过将 JSON 消息发布到名为`xmr_btc`的 Kafka 主题来模拟。另一方面，我们有一个 Kafka 消费者将实时数据导入 MongoDB。

我们还有另一个 Kafka 消费者将数据导入 Hadoop，供我们的算法使用，发送推荐数据（信号）到 Hive 表。最后，我们将数据从 Hive 表导出到 MongoDB。

# 设置 Kafka

建立大数据用例环境的第一步是建立一个 Kafka 节点。Kafka 本质上是一个 FIFO 队列，因此我们将使用最简单的单节点（broker）设置。Kafka 使用主题、生产者、消费者和代理来组织数据。

重要的 Kafka 术语如下：

+   **代理**本质上是一个节点。

+   **生产者**本质上是一个写入数据到消息队列的过程。

+   **消费者**是从消息队列中读取数据的过程。

+   **主题**是我们写入和读取数据的特定队列。

Kafka 主题进一步分为多个分区。我们可以在写入主题时，以及在队列的另一端读取数据时，将特定主题的数据拆分为多个代理（节点）。

在我们的本地机器上安装 Kafka，或者选择任何云提供商（有很好的 EC2 教程可以找到），我们可以使用以下单个命令创建一个主题：

```sql
$ kafka-topics  --create --zookeeper localhost:2181 --replication-factor 1  --partitions 1 --topic xmr-btc
Created topic "xmr-btc".
```

这将创建一个名为`xmr-btc`的新主题。

删除主题与创建主题类似，使用以下命令：

```sql
$ kafka-topics --delete --zookeeper localhost:2181 --topic xmr-btc
```

我们可以通过发出以下命令来获取所有主题的列表：

```sql
$ kafka-topics --list --zookeeper localhost:2181
xmr-btc
```

然后我们可以为我们的主题创建一个命令行生产者，只是为了测试我们是否可以将消息发送到队列，就像这样：

```sql
$ kafka-console-producer --broker-list localhost:9092 --topic xmr-btc
```

每行的数据将作为字符串编码的消息发送到我们的主题，我们可以通过发送`SIGINT`信号（通常是*Ctrl* + *C*）来结束这个过程。

之后，我们可以通过启动一个消费者来查看等待在我们队列中的消息：

```sql
$ kafka-console-consumer --zookeeper localhost:2181 --topic xmr-btc --from-beginning
```

这个消费者将从我们的`xmr-btc`主题中读取所有消息，从历史的开始。这对我们的测试目的很有用，但在实际应用中我们会更改这个配置。

在命令中，除了提到`kafka`，您还会看到`zookeeper`。Apache Zookeeper 与 Apache Kafka 一起使用，是一个集中式服务，由 Kafka 内部用于维护配置信息、命名、提供分布式同步和提供组服务。

现在我们已经设置好了我们的代理，我们可以使用[`github.com/agiamas/mastering-mongodb/tree/master/chapter_9`](https://github.com/agiamas/mastering-mongodb/tree/master/chapter_9)上的代码来开始读取消息并将消息写入队列。对于我们的目的，我们使用了由 Zendesk 开发的`ruby-kafka` gem。

为简单起见，我们使用一个单一的类来从磁盘上存储的文件中读取数据，并将其写入我们的 Kafka 队列。

我们的`produce`方法将用于将消息写入 Kafka，如下所示：

```sql
def produce
  options = { converters: :numeric, headers: true }
   CSV.foreach('xmr_btc.csv', options) do |row|
    json_line = JSON.generate(row.to_hash)
    @kafka.deliver_message(json_line, topic: 'xmr-btc')
  end
end
```

我们的`consume`方法将从 Kafka 中读取消息，如下所示：

```sql
def consume
  consumer = @kafka.consumer(group_id: 'xmr-consumers')
  consumer.subscribe('xmr-btc', start_from_beginning: true)
  trap('TERM') { consumer.stop }
  consumer.each_message(automatically_mark_as_processed: false) do |message|
    puts message.value
    if valid_json?(message.value)
      MongoExchangeClient.new.insert(message.value)
      consumer.mark_message_as_processed(message)
    end
  end
  consumer.stop
end
```

请注意，我们使用了消费者组 API 功能（在 Kafka 0.9 中添加）来使多个消费者通过将每个分区分配给单个消费者来访问单个主题。在消费者故障的情况下，其分区将重新分配给组的其余成员。

下一步是将这些消息写入 MongoDB，如下所示：

1.  首先，我们创建我们的集合，以便我们的文档在一分钟后过期。在`mongo` shell 中输入以下内容：

```sql
> use exchange_data
> db.xmr_btc.createIndex( { "createdAt": 1 }, { expireAfterSeconds: 60 })
{
"createdCollectionAutomatically" : true,
"numIndexesBefore" : 1,
"numIndexesAfter" : 2,
"ok" : 1
}
```

这样，我们创建了一个名为`exchange_data`的新数据库，其中包含一个名为`xmr_btc`的新集合，该集合在一分钟后自动过期。要使 MongoDB 自动过期文档，我们需要提供一个带有`datetime`值的字段，以将其值与当前服务器时间进行比较。在我们的情况下，这是`createdAt`字段。

1.  对于我们的用例，我们将使用低级别的 MongoDB Ruby 驱动程序。`MongoExchangeClient`的代码如下：

```sql
class MongoExchangeClient
 def initialize
   @collection = Mongo::Client.new([ '127.0.0.1:27017' ], database: :exchange_data).database[:xmr_btc]
 end
 def insert(document)
   document = JSON.parse(document)
   document['createdAt'] = Time.now
   @collection.insert_one(document)
 end
end
```

此客户端连接到我们的本地数据库，为 TTL 文档过期设置`createdAt`字段，并将消息保存到我们的集合中。

有了这个设置，我们可以将消息写入 Kafka，在队列的另一端读取它们，并将它们写入我们的 MongoDB 集合。

# 设置 Hadoop

我们可以安装 Hadoop，并使用单个节点来完成本章的用例，使用 Apache Hadoop 网站上的说明[`hadoop.apache.org/docs/stable/hadoop-project-dist/hadoop-common/SingleCluster.html`](https://hadoop.apache.org/docs/stable/hadoop-project-dist/hadoop-common/SingleCluster.html)。

按照这些步骤后，我们可以在本地机器上的`http://localhost:50070/explorer.html#/`上浏览 HDFS 文件。假设我们的信号数据写在 HDFS 的`/user/<username>/signals`目录下，我们将使用 MongoDB Connector for Hadoop 将其导出并导入到 MongoDB 中。

MongoDB Connector for Hadoop 是官方支持的库，允许将 MongoDB 数据文件或 BSON 格式的 MongoDB 备份文件用作 Hadoop MapReduce 任务的源或目的地。

这意味着当我们使用更高级别的 Hadoop 生态系统工具时，例如 Pig（一种过程化高级语言）、Hive（一种类似 SQL 的高级语言）和 Spark（一种集群计算框架）时，我们也可以轻松地导出和导入数据到 MongoDB。

# Hadoop 设置步骤

设置 Hadoop 的不同步骤如下：

1.  从[Maven 库](http://repo1.maven.org/maven2/org/mongodb/mongo-hadoop/mongo-hadoop-core/2.0.2/)下载 JAR。

1.  从[`oss.sonatype.org/content/repositories/releases/org/mongodb/mongodb-driver/3.5.0/`](https://oss.sonatype.org/content/repositories/releases/org/mongodb/mongodb-driver/3.5.0/)下载`mongo-java-driver`。

1.  创建一个目录（在我们的情况下，命名为`mongo_lib`），并使用以下命令将这两个 JAR 复制到其中：

```sql
export HADOOP_CLASSPATH=$HADOOP_CLASSPATH:<path_to_directory>/mongo_lib/
```

或者，我们可以将这些 JAR 复制到`share/hadoop/common/`目录下。由于这些 JAR 需要在每个节点上都可用，对于集群部署，使用 Hadoop 的`DistributedCache`将 JAR 分发到所有节点更容易。

1.  下一步是从[`hive.apache.org/downloads.html`](https://hive.apache.org/downloads.html)安装 Hive。在本例中，我们使用了 MySQL 服务器来存储 Hive 的元数据。这可以是用于开发的本地 MySQL 服务器，但建议在生产环境中使用远程服务器。

1.  一旦我们设置好了 Hive，我们只需运行以下命令：

```sql
> hive
```

1.  然后，我们添加之前下载的三个 JAR（`mongo-hadoop-core`、`mongo-hadoop-driver`和`mongo-hadoop-hive`）：

```sql
hive> add jar /Users/dituser/code/hadoop-2.8.1/mongo-hadoop-core-2.0.2.jar;
Added [/Users/dituser/code/hadoop-2.8.1/mongo-hadoop-core-2.0.2.jar] to class path
Added resources: [/Users/dituser/code/hadoop-2.8.1/mongo-hadoop-core-2.0.2.jar]
hive> add jar /Users/dituser/code/hadoop-2.8.1/mongodb-driver-3.5.0.jar;
Added [/Users/dituser/code/hadoop-2.8.1/mongodb-driver-3.5.0.jar] to class path
Added resources: [/Users/dituser/code/hadoop-2.8.1/mongodb-driver-3.5.0.jar]
hive> add jar /Users/dituser/code/hadoop-2.8.1/mongo-hadoop-hive-2.0.2.jar;
Added [/Users/dituser/code/hadoop-2.8.1/mongo-hadoop-hive-2.0.2.jar] to class path
Added resources: [/Users/dituser/code/hadoop-2.8.1/mongo-hadoop-hive-2.0.2.jar]
hive>
```

然后，假设我们的数据在表交换中：

| **customerid                                             ** | **int** |
| --- | --- |
| `pair` | `String` |
| `time` | `TIMESTAMP` |
| `recommendation` | `int` |

我们还可以使用 Gradle 或 Maven 在我们的本地项目中下载 JAR。如果我们只需要 MapReduce，那么我们只需下载`mongo-hadoop-core` JAR。对于 Pig、Hive、Streaming 等，我们必须从

[`repo1.maven.org/maven2/org/mongodb/mongo-hadoop/`](http://repo1.maven.org/maven2/org/mongodb/mongo-hadoop/)。

一些有用的 Hive 命令包括：`show databases;`和

创建表交换（客户 ID int，对 String，时间时间戳，建议 int）;

1.  现在我们已经准备好了，我们可以创建一个由我们本地 Hive 数据支持的 MongoDB 集合：

```sql
hive> create external table exchanges_mongo (objectid STRING, customerid INT,pair STRING,time STRING, recommendation INT) STORED BY 'com.mongodb.hadoop.hive.MongoStorageHandler' WITH SERDEPROPERTIES('mongo.columns.mapping'='{"objectid":"_id", "customerid":"customerid","pair":"pair","time":"Timestamp", "recommendation":"recommendation"}') tblproperties('mongo.uri'='mongodb://localhost:27017/exchange_data.xmr_btc');
```

1.  最后，我们可以按照以下方式将`exchanges` Hive 表中的所有数据复制到 MongoDB 中：

```sql
hive> Insert into table exchanges_mongo select * from exchanges;
```

这样，我们已经建立了 Hadoop 和 MongoDB 之间的管道，使用 Hive，而不需要任何外部服务器。

# 使用 Hadoop 到 MongoDB 的管道

使用 MongoDB Connector for Hadoop 的替代方法是使用我们选择的编程语言从 Hadoop 中导出数据，然后使用低级驱动程序或 ODM 将数据写入 MongoDB，如前几章所述。

例如，在 Ruby 中，有一些选项：

+   在 GitHub 上的**WebHDFS**，它使用 WebHDFS 或**HttpFS** Hadoop API 从 HDFS 获取数据

+   系统调用，使用 Hadoop 命令行工具和 Ruby 的`system()`调用

而在 Python 中，我们可以使用以下命令：

+   **HdfsCLI**，它使用 WebHDFS 或 HttpFS Hadoop API

+   **libhdfs**，它使用基于 JNI 的本地 C 封装的 HDFS Java 客户端

所有这些选项都需要我们的 Hadoop 基础设施和 MongoDB 服务器之间的中间服务器，但另一方面，允许在导出/导入数据的 ETL 过程中更灵活。

# 设置 Spark 到 MongoDB

MongoDB 还提供了一个工具，可以直接查询 Spark 集群并将数据导出到 MongoDB。Spark 是一个集群计算框架，通常作为 Hadoop 中的 YARN 模块运行，但也可以独立在其他文件系统之上运行。

MongoDB Spark Connector 可以使用 Java、Scala、Python 和 R 从 Spark 读取和写入 MongoDB 集合。它还可以在创建由 Spark 支持的数据集的临时视图后，对 MongoDB 数据进行聚合和运行 SQL 查询。

使用 Scala，我们还可以使用 Spark Streaming，这是构建在 Apache Spark 之上的数据流应用程序的 Spark 框架。

# 进一步阅读

您可以参考以下参考资料获取更多信息：

+   [`www.cisco.com/c/en/us/solutions/collateral/service-provider/visual-networking-index-vni/vni-hyperconnectivity-wp.html`](https://www.cisco.com/c/en/us/solutions/collateral/service-provider/visual-networking-index-vni/vni-hyperconnectivity-wp.html)

+   [`www.ibmbigdatahub.com/infographic/four-vs-big-data`](http://www.ibmbigdatahub.com/infographic/four-vs-big-data)

+   [`spreadstreet.io/database/`](https://spreadstreet.io/database/)

+   [`mattturck.com/wp-content/uploads/2017/05/Matt-Turck-FirstMark-2017-Big-Data-Landscape.png`](http://mattturck.com/wp-content/uploads/2017/05/Matt-Turck-FirstMark-2017-Big-Data-Landscape.png)

+   [`mattturck.com/bigdata2017/`](http://mattturck.com/bigdata2017/)

+   [`dzone.com/articles/hadoop-t-etl`](https://dzone.com/articles/hadoop-t-etl)

+   [`www.cloudamqp.com/blog/2014-12-03-what-is-message-queuing.html`](https://www.cloudamqp.com/blog/2014-12-03-what-is-message-queuing.html)

+   [`www.linkedin.com/pulse/jms-vs-amqp-eran-shaham`](https://www.linkedin.com/pulse/jms-vs-amqp-eran-shaham)

+   [`www.cloudamqp.com/blog/2017-01-09-apachekafka-vs-rabbitmq.html`](https://www.cloudamqp.com/blog/2017-01-09-apachekafka-vs-rabbitmq.html)

+   [`trends.google.com/trends/explore?date=all&q=ActiveMQ,RabbitMQ,ZeroMQ`](https://trends.google.com/trends/explore?date=all&q=ActiveMQ,RabbitMQ,ZeroMQ)

+   [`thenextweb.com/insider/2017/03/06/the-incredible-growth-of-the-internet-over-the-past-five-years-explained-in-detail/#.tnw_ALaObAUG`](https://thenextweb.com/insider/2017/03/06/the-incredible-growth-of-the-internet-over-the-past-five-years-explained-in-detail/#.tnw_ALaObAUG)

+   [`static.googleusercontent.com/media/research.google.com/en//archive/mapreduce-osdi04.pdf`](https://static.googleusercontent.com/media/research.google.com/en//archive/mapreduce-osdi04.pdf)

+   [`en.wikipedia.org/wiki/Apache_Hadoop#Architecture`](https://en.wikipedia.org/wiki/Apache_Hadoop#Architecture)

+   [`wiki.apache.org/hadoop/PoweredByYarn`](https://wiki.apache.org/hadoop/PoweredByYarn)

+   [`www.slideshare.net/cloudera/introduction-to-yarn-and-mapreduce-2?next_slideshow=1`](https://www.slideshare.net/cloudera/introduction-to-yarn-and-mapreduce-2?next_slideshow=1)

+   [`www.mongodb.com/blog/post/mongodb-live-at-craigslist`](https://www.mongodb.com/blog/post/mongodb-live-at-craigslist)

+   [`www.mongodb.com/blog/post/mongodb-at-baidu-powering-100-apps-across-600-nodes-at-pb-scale`](https://www.mongodb.com/blog/post/mongodb-at-baidu-powering-100-apps-across-600-nodes-at-pb-scale)

+   [`www.datamation.com/data-center/hadoop-vs.-spark-the-new-age-of-big-data.html`](http://www.datamation.com/data-center/hadoop-vs.-spark-the-new-age-of-big-data.html)

+   [`www.mongodb.com/mongodb-data-warehouse-time-series-and-device-history-data-medtronic-transcript`](https://www.mongodb.com/mongodb-data-warehouse-time-series-and-device-history-data-medtronic-transcript)

+   [`www.mongodb.com/blog/post/mongodb-debuts-in-gartner-s-magic-quadrant-for-data-warehouse-and-data-management-solutions-for-analytics`](https://www.mongodb.com/blog/post/mongodb-debuts-in-gartner-s-magic-quadrant-for-data-warehouse-and-data-management-solutions-for-analytics)

+   [`www.infoworld.com/article/3014440/big-data/five-things-you-need-to-know-about-hadoop-v-apache-spark.html`](https://www.infoworld.com/article/3014440/big-data/five-things-you-need-to-know-about-hadoop-v-apache-spark.html)

+   [`www.quora.com/What-is-the-difference-between-Hadoop-and-Spark`](https://www.quora.com/What-is-the-difference-between-Hadoop-and-Spark)

+   [`iamsoftwareengineer.wordpress.com/2015/12/15/hadoop-vs-spark/?iframe=true&theme_preview=true`](https://iamsoftwareengineer.wordpress.com/2015/12/15/hadoop-vs-spark/?iframe=true&theme_preview=true)

+   [`www.infoq.com/articles/apache-kafka`](https://www.infoq.com/articles/apache-kafka)

+   [`stackoverflow.com/questions/42151544/is-there-any-reason-to-use-rabbitmq-over-kafka`](https://stackoverflow.com/questions/42151544/is-there-any-reason-to-use-rabbitmq-over-kafka)

+   [`medium.com/@jaykreps/exactly-once-support-in-apache-kafka-55e1fdd0a35f`](https://medium.com/@jaykreps/exactly-once-support-in-apache-kafka-55e1fdd0a35f)

+   [`www.slideshare.net/sbaltagi/apache-kafka-vs-rabbitmq-fit-for-purpose-decision-tree`](https://www.slideshare.net/sbaltagi/apache-kafka-vs-rabbitmq-fit-for-purpose-decision-tree)

+   [`techbeacon.com/what-apache-kafka-why-it-so-popular-should-you-use-it`](https://techbeacon.com/what-apache-kafka-why-it-so-popular-should-you-use-it)

+   [`github.com/zendesk/ruby-kafka`](https://github.com/zendesk/ruby-kafka#producing-messages-to-kafka)

+   [`zhongyaonan.com/hadoop-tutorial/setting-up-hadoop-2-6-on-mac-osx-yosemite.html`](http://zhongyaonan.com/hadoop-tutorial/setting-up-hadoop-2-6-on-mac-osx-yosemite.html)

+   [`github.com/mtth/hdfs`](https://github.com/mtth/hdfs)

+   [`wesmckinney.com/blog/outlook-for-2017/`](http://wesmckinney.com/blog/outlook-for-2017/)

+   [`wesmckinney.com/blog/python-hdfs-interfaces/`](http://wesmckinney.com/blog/python-hdfs-interfaces/)

+   [`acadgild.com/blog/how-to-export-data-from-hive-to-mongodb/`](https://acadgild.com/blog/how-to-export-data-from-hive-to-mongodb/)

+   [`sookocheff.com/post/kafka/kafka-in-a-nutshell/`](https://sookocheff.com/post/kafka/kafka-in-a-nutshell/)

+   [`www.codementor.io/jadianes/spark-mllib-logistic-regression-du107neto`](https://www.codementor.io/jadianes/spark-mllib-logistic-regression-du107neto)

+   [`ondra-m.github.io/ruby-spark/`](http://ondra-m.github.io/ruby-spark/)

+   [`amodernstory.com/2015/03/29/installing-hive-on-mac/`](https://amodernstory.com/2015/03/29/installing-hive-on-mac/)

+   [`www.infoq.com/articles/apache-spark-introduction`](https://www.infoq.com/articles/apache-spark-introduction)

+   [`cs.stanford.edu/~matei/papers/2010/hotcloud_spark.pdf`](https://cs.stanford.edu/~matei/papers/2010/hotcloud_spark.pdf)

# 摘要

在本章中，我们了解了大数据领域以及 MongoDB 与消息队列系统和数据仓库技术的比较和对比。通过一个大数据用例，我们从实际角度学习了如何将 MongoDB 与 Kafka 和 Hadoop 集成。

在下一章中，我们将转向复制和集群操作，并讨论副本集、选举的内部情况以及我们的 MongoDB 集群的设置和管理。


# 第四部分：扩展和高可用性

在本节中，我们将首先介绍复制，以及如何使用它来确保我们不会遭受任何数据丢失。分片是下一个主题，它帮助我们在 MongoDB 中实现水平扩展。最后，我们将学习在使用 MongoDB 时实现高可用性和容错性的最佳实践和技巧。

本节包括以下章节：

+   第十二章，*复制*

+   第十三章，*分片*

+   第十四章，*容错和高可用性*


# 第十二章：复制

自从 MongoDB 的早期以来，复制一直是最有用的功能之一。 一般来说，复制是指在不同服务器之间同步数据的过程。 复制的好处包括防止数据丢失和数据的高可用性。 复制还提供灾难恢复，避免维护停机时间，扩展读取（因为我们可以从多个服务器读取）和扩展写入（只有我们可以写入多个服务器时）。

在本章中，我们将涵盖以下主题：

+   架构概述，选举和复制的用例

+   设置副本集

+   连接到副本集

+   副本集管理

+   使用云提供商部署副本集的最佳实践

+   副本集限制

# 复制

复制有不同的方法。 MongoDB 采取的方法是主从的逻辑复制，我们将在本章后面更详细地解释。

# 逻辑或物理复制

通过复制，我们在多个服务器之间同步数据，提供数据可用性和冗余。 即使由于硬件或软件故障而丢失服务器，通过使用复制，我们将有多个副本可以用来恢复我们的数据。 复制的另一个优点是我们可以使用其中一个服务器作为专用报告或备份服务器。

在逻辑复制中，我们的主/主服务器执行操作； 从/次要服务器从主服务器尾随操作队列，并按相同顺序应用相同的操作。 以 MongoDB 为例，**操作日志**（**oplog**）跟踪主服务器上发生的操作，并按相同顺序在次要服务器上应用它们。

逻辑复制对各种应用非常有用，例如信息共享，数据分析和**在线分析处理**（**OLAP**）报告。

在物理复制中，数据在物理级别上被复制，比数据库操作的更低级别。 这意味着我们不是应用操作，而是复制受这些操作影响的字节。 这也意味着我们可以获得更好的效率，因为我们使用低级结构来传输数据。 我们还可以确保数据库的状态完全相同，因为它们是相同的，逐字节相同。

物理复制通常缺少有关数据库结构的知识，这意味着更难（如果不是不可能）从数据库复制一些集合并忽略其他集合。

物理复制通常适用于更罕见的情况，例如灾难恢复，在这种情况下，一切（包括数据，索引，数据库内部状态在日志中的重做/撤消日志）的完整和精确副本对于将应用程序恢复到确切状态至关重要。

# 不同的高可用性类型

在高可用性中，有几种配置可以使用。 我们的主服务器称为**热服务器**，因为它可以处理每一个请求。 我们的次要服务器可以处于以下任何状态：

+   冷

+   温暖

+   热

**次要冷服务器**是一个服务器，仅在主服务器离线时存在，而不期望它保存主服务器的数据和状态。

**次要温暖服务器**定期从主服务器接收数据更新，但通常不会完全与主服务器同步。 它可以用于一些非实时分析报告，以卸载主服务器，但通常情况下，如果主服务器宕机，它将无法承担事务负载。

**次要热服务器**始终保持与主服务器的数据和状态的最新副本。 它通常处于热备状态，准备在主服务器宕机时接管。

MongoDB 具有热服务器和温服务器功能，我们将在接下来的部分中探讨。

大多数数据库系统都采用类似的主/次服务器概念，因此从概念上讲，MongoDB 的所有内容也适用于那里。

# 架构概述

MongoDB 的复制在以下图表中提供：

![](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-mongo-4x/img/4a5ebcaa-a723-4afe-9e23-054f1d663936.png)

主服务器是唯一可以随时进行写入的服务器。次要服务器处于热备状态，一旦主服务器故障，它们就可以接管。一旦主服务器故障，就会进行选举，确定哪个次要服务器将成为主服务器。

我们还可以有**仲裁节点**。仲裁节点不保存任何数据，它们唯一的目的是参与选举过程。

我们必须始终有奇数个节点（包括仲裁者）。三、五和七都可以，这样在主服务器（或更多服务器）故障时，我们在选举过程中有多数选票。

当副本集的其他成员在 10 秒以上（可配置）没有收到来自主服务器的消息时，一个合格的次要成员将开始选举过程，投票选举出新的主服务器。首个进行选举并赢得多数的次要成员将成为新的主服务器。所有剩余的服务器现在将从新的主服务器复制，保持它们作为次要服务器的角色，但从新的主服务器同步。

从 MongoDB 3.6 开始，客户端驱动程序可以在检测到主服务器宕机时**重试一次**写操作。副本集最多可以有 50 个成员，但其中只有最多七个可以参与选举过程。

新选举后我们副本集的设置如下：

![](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-mongo-4x/img/66b01e77-7539-4d79-a218-813ea11b5d05.png)

在下一节中，我们将讨论选举的工作原理。

# 选举是如何工作的？

副本集中的所有服务器都通过心跳定期与每个其他成员保持通信。心跳是一个小数据包，定期发送以验证所有成员是否正常运行。

次要成员还与主服务器通信，从 oplog 获取最新更新并将其应用于自己的数据。

这里的信息是指最新的复制选举协议，即版本 1，它是在 MongoDB v3.2 中引入的。

从图表中，我们可以看到它是如何工作的。

当主成员下线时，所有次要成员都会错过一个或多个心跳。它们将等待直到`settings.electionTimeoutMillis`时间过去（默认为 10 秒），然后次要成员将开始一轮或多轮选举，以找到新的主服务器。

要从次要服务器中选举出主服务器，它必须具备两个属性：

+   属于拥有*50% + 1*选票的选民组

+   成为这个组中最新的次要

在一个简单的例子中，有三个服务器，每个服务器一票，一旦我们失去主服务器，其他两个服务器将各自有一票（因此总共是三分之二），因此，拥有最新 oplog 的服务器将被选举为主服务器。

现在，考虑一个更复杂的设置，如下：

+   七个服务器（一个主服务器，六个次要服务器）

+   每个节点一票

我们失去了主服务器，剩下的六个服务器出现了网络连接问题，导致网络分区：

![](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-mongo-4x/img/d794932d-b88f-4c1f-8bd7-be491ae4be45.png)

这些分区可以描述如下：

+   北区：三个服务器（每个一票）

+   南区：三个服务器（每个一票）

任何一个分区都不知道其他服务器发生了什么。现在，当它们进行选举时，没有一个分区能够建立多数，因为它们有七票中的三票。没有主服务器会从任何一个分区中被选举出来。这个问题可以通过例如拥有一个拥有三票的服务器来解决。

现在，我们的整体集群设置如下：

+   **服务器＃1**：一票

+   **服务器＃2**：一票

+   **服务器＃3**：一票

+   **服务器＃4**：一票

+   **服务器＃5**：一票

+   **服务器＃6**：一票

+   **服务器＃7**：三票

在失去服务器＃1 后，我们的分区现在如下：

![](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/ms-mongo-4x/img/7841ea05-e5c9-411c-9a9d-b66cbaf99b5f.png)

北分区如下：

+   **服务器＃2**：一票

+   **服务器＃3**：一票

+   **服务器＃4**：一票

南分区如下：

+   **服务器＃5**：一票

+   **服务器＃6**：一票

+   **服务器＃7**：三票

南分区有三个服务器，共有九票中的五票。服务器＃5、＃6 和＃7 中最新（根据其 oplog 条目）的辅助服务器将被选为主服务器。

# 副本集的用例是什么？

MongoDB 提供了使用副本集的大部分优势，其中一些列举如下：

+   防止数据丢失

+   数据的高可用性

+   灾难恢复

+   避免维护停机时间

+   扩展读取，因为我们可以从多个服务器读取

+   帮助设计地理分散服务

+   数据隐私

从列表中缺少的最显着的项目是扩展写入。这是因为在 MongoDB 中，我们只能有一个主服务器，只有这个主服务器才能从我们的应用服务器接收写入。

当我们想要扩展写性能时，通常会设计和实现分片，这将是下一章的主题。MongoDB 复制实现的两个有趣特性是地理分散服务和数据隐私。

我们的应用服务器通常位于全球多个数据中心。使用复制，我们可以尽可能将辅助服务器靠近应用服务器。这意味着我们的读取将很快，就像本地一样，并且我们只会为写入获得延迟性能惩罚。当然，这需要在应用程序级别进行一些规划，以便我们可以维护两个不同的数据库连接池，这可以通过使用官方的 MongoDB 驱动程序或使用更高级别的 ODM 轻松完成。

MongoDB 复制设计的第二个有趣特性是实现数据隐私。当我们在不同数据中心地理分散的服务器上，我们可以启用每个数据库的复制。通过将数据库排除在复制过程之外，我们可以确保我们的数据保持在我们需要的数据中心内。我们还可以在同一个 MongoDB 服务器上为每个数据库设置不同的复制模式，以满足我们的数据隐私需求，如果某些服务器不符合我们的数据隐私规定，可以将其排除在副本集之外。

# 设置副本集

在本节中，我们将介绍设置副本集的最常见部署程序。这些包括将独立服务器转换为副本集或从头开始设置副本集。

# 将独立服务器转换为副本集

要将独立服务器转换为副本集，我们首先需要干净地关闭`mongo`服务器：

```sql
> use admin
> db.shutdownServer()
```

然后，我们通过命令行使用`--replSet`配置选项启动服务器（我们将在这里执行），或者使用配置文件，如我们将在下一节中解释的那样：

1.  首先，我们通过 mongo shell 连接到新的启用了副本集的实例，如下所示：

```sql
> rs.initiate()
```

1.  现在，我们有了副本集的第一个服务器。我们可以使用 mongo shell 添加其他服务器（这些服务器也必须使用`--replSet`启动），如下所示：

```sql
> rs.add("<hostname><:port>")
```

通过使用`rs.conf()`来双重检查副本集配置。通过使用`rs.status()`来验证副本集状态。

# 创建副本集

作为副本集的一部分启动 MongoDB 服务器就像通过命令行在配置中设置它一样容易：

```sql
> mongod --replSet "xmr_cluster"
```

这对开发目的来说是可以的。对于生产环境，建议使用配置文件：

```sql
> mongod --config <path-to-config>
```

在这里，`<path-to-config>`可以如下：

```sql
/etc/mongod.conf
```

此配置文件必须采用 YAML 格式。

YAML 不支持制表符。请使用您选择的编辑器将制表符转换为空格。

一个简单的配置文件示例如下：

```sql
systemLog:
  destination: file
  path: "/var/log/mongodb/mongod.log"
  logAppend: true
storage:
  journal:
     enabled: true
processManagement:
  fork: true
net:
  bindIp: 127.0.0.1
  port: 27017
replication:
  oplogSizeMB: <int>
  replSetName: <string>
```

根级选项通过嵌套定义叶级选项适用于的部分。关于复制，强制选项是`oplogSizeMB`（成员的 oplog 大小，以 MB 为单位）和`replSetName`（副本集名称，例如`xmr_cluster`）。

我们还可以在与`replSetName`相同级别上设置以下内容：

```sql
secondaryIndexPrefetch: <string>
```

这仅适用于 MMAPv1 存储引擎，并且指的是在应用操作之前将加载到内存中的次要服务器上的索引。

它默认为`all`，可用选项为`none`和`_id_only`，以便不将索引加载到内存中，只加载在`_id`字段上创建的默认索引：

```sql
enableMajorityReadConcern: <boolean>
```

这是启用此成员的`majority`读取偏好的配置设置。

在不同节点上启动了所有副本集进程后，我们可以使用适当的`host:port`从命令行使用`mongo`登录到其中一个节点。然后，我们需要从一个成员初始化集群。

我们可以使用以下配置文件：

```sql
> rs.initiate()
```

或者，我们可以将配置作为文档参数传递，如下所示：

```sql
> rs.initiate( {
 _id : "xmr_cluster",
 members: [ { _id : 0, host : "host:port" } ]
})
```

我们可以使用`rs.conf()`在 shell 中验证集群是否已初始化。

接下来，我们通过使用我们在网络设置中定义的`host:port`，将每个其他成员添加到我们的副本集中：

```sql
> rs.add("host2:port2")
> rs.add("host3:port3")
```

我们必须为 HA 副本集使用的最小服务器数量是`3`。我们可以用仲裁者替换其中一个服务器，但这并不推荐。一旦我们添加了所有服务器并等待了一会儿，我们可以使用`rs.status()`来检查我们集群的状态。默认情况下，oplog 将是空闲磁盘空间的 5%。如果我们想在创建副本集时定义它，我们可以通过传递命令行参数`--oplogSizeMB`或在配置文件中使用`replication.oplogSizeMB`来这样做。oplog 大小不能超过 50GB。

# 读取偏好

默认情况下，所有写入和读取都来自主服务器。次要服务器复制数据，但不用于查询。

在某些情况下，更改这一点并开始从次要服务器读取可能是有益的。

MongoDB 官方驱动程序支持五个级别的读取偏好：

| **读取偏好模式** | **描述** |
| --- | --- |
| `primary` | 这是默认模式，其中读取来自副本集的`primary`服务器。 |
| `primaryPreferred` | 使用此模式，应用程序将从`primary`读取数据，除非它不可用，在这种情况下，读取将来自`secondary`成员。 |
| `secondary` | 读取仅来自`secondary`服务器。 |
| `secondaryPreferred` | 使用此模式，应用程序将从`secondary`成员读取数据，除非它们不可用，在这种情况下，读取将来自`primary`成员。 |
| `nearest` | 应用程序将从副本集中在网络延迟方面最接近的成员读取数据，而不考虑成员的类型。 |

除了`primary`之外的任何读取偏好对于非常时间敏感的异步操作可能是有益的。例如，报告服务器可以从次要服务器读取，而不是从主服务器读取，因为我们可能对聚合数据的小延迟可以接受，而又能在主服务器上产生更多的读取负载。

地理分布的应用程序也将受益于从次要服务器读取，因为这些服务器的延迟会显著较低。尽管这可能有违直觉，但仅将读取偏好从`primary`更改为`secondary`不会显著增加集群的总读取容量。这是因为我们集群的所有成员都在承受来自客户端写入的相同写入负载，并分别复制主服务器和次要服务器的数据。

然而，从辅助节点读取可能会返回过期数据，这必须在应用程序级别处理。从可能具有可变复制延迟的不同辅助节点读取（与我们的主要写入相比）可能导致读取文档的插入顺序不一致（**非单调读取**）。

尽管存在所有上述警告，如果我们的应用程序设计支持，从辅助节点读取仍然是一个好主意。可以帮助我们避免读取过期数据的另一个配置选项是`maxStalenessSeconds`。

根据每个辅助节点对于与主节点相比落后程度的粗略估计，我们可以将其设置为 90（秒）或更高的值，以避免读取过期数据。鉴于辅助节点知道它们与主节点的落后程度（但并不准确或积极地估计），这应被视为一种近似，而不是我们设计的基础。

# 写关注

在 MongoDB 副本集中，默认情况下，写操作将在主服务器确认写入后得到确认。如果我们想要更改此行为，可以通过两种不同的方式进行：

+   在某些情况下，我们可以针对每个操作请求不同的写关注，以确保写入在标记为完成之前已传播到我们副本集的多个成员，如下所示：

```sql
> db.mongo_books.insert(
 { name: "Mastering MongoDB", isbn: "1001" },
 { writeConcern: { w: 2, wtimeout: 5000 } }
)
```

在上面的示例中，我们正在等待两个服务器（主服务器加上任何一个辅助服务器）确认写入。我们还设置了`5000`毫秒的超时，以避免在网络速度慢或我们没有足够的服务器来确认请求的情况下阻塞我们的写入。

+   我们还可以通过以下方式更改整个副本集的默认写关注：

```sql
> cfg = rs.conf()
> cfg.settings.getLastErrorDefaults = { w: "majority", wtimeout: 5000 }
> rs.reconfig(cfg)
```

在这里，我们将写关注设置为`majority`，超时为`5`秒。写关注`majority`确保我们的写入将传播到至少*n/2+1*个服务器，其中*n*是我们的副本集成员的数量。

写关注`majority`在我们的读取偏好为`majority`时非常有用，因为它确保每个带有`w: "majority"`的写入也将以相同的读取偏好可见。如果设置了`w>1`，还可以设置`wtimeout: <milliseconds>`。`wtimeout`将在达到超时后从我们的写操作返回，因此不会无限期地阻塞我们的客户端。建议还设置`j: true`。`j: true`将等待我们的写操作在确认之前写入日志。`w>1`与`j: true`一起将等待我们指定的服务器数量在确认之前写入日志。

# 自定义写关注

我们还可以使用不同的标签（即`reporting`，东海岸服务器和总部服务器）标识我们的副本集成员，并针对每个操作指定自定义写关注，如下所示：

1.  使用 mongo shell 连接到主服务器的常规过程如下：

```sql
> conf = rs.conf()
> conf.members[0].tags = { "location": "UK", "use": "production", "location_uk":"true"  }
> conf.members[1].tags = { "location": "UK", "use": "reporting", "location_uk":"true"  }
> conf.members[2].tags = { "location": "Ireland", "use": "production"  }
```

1.  现在，我们可以设置自定义写关注，如下所示：

```sql
> conf.settings = { getLastErrorModes: { UKWrites : { "location_uk": 2} } }
```

1.  应用此设置后，我们使用`reconfig`命令：

```sql
> rs.reconfig(conf)
```

1.  现在，我们可以通过以下方式在我们的写入中设置`writeConcern`：

```sql
> db.mongo_books.insert({<our insert object>}, { writeConcern: { w: "UKWrites" } })
```

这意味着我们的写入只有在满足`UKWrites`写关注时才会得到确认，而`UKWrites`写关注将由至少两个带有`location_uk`标签的服务器验证。由于我们只有两台位于英国的服务器，因此通过此自定义写关注，我们可以确保将数据写入到我们所有的英国服务器。

# 副本集成员的优先级设置

MongoDB 允许我们为每个成员设置不同的优先级级别。这允许实现一些有趣的应用程序和拓扑结构。

在设置完集群后更改优先级，我们必须使用 mongo shell 连接到我们的主服务器并获取配置对象（在本例中为`cfg`）：

```sql
> cfg = rs.conf()
```

然后，我们可以将`members`子文档的`priority`属性更改为我们选择的值：

```sql
> cfg.members[0].priority = 0.778
> cfg.members[1].priority = 999.9999
```

每个成员的默认`priority`为`1`。`priority`可以从`0`（永远不成为主要）设置为`1000`，以浮点精度。

优先级较高的成员将是主服务器下台时首先发起选举的成员，并且最有可能赢得选举。

应该考虑不同网络分区来配置自定义优先级。错误地设置优先级可能导致选举无法选举主服务器，从而停止所有对我们 MongoDB 副本集的写入。

如果我们想要阻止次要服务器成为主服务器，我们可以将其`priority`设置为`0`，如我们将在下一节中解释的那样。

# 零优先级副本集成员

在某些情况下（例如，如果我们有多个数据中心），我们将希望一些成员永远无法成为主服务器。

在具有多个数据中心复制的情况下，我们的主要数据中心可能有一个基于英国的主服务器和一个次要服务器，以及一个位于俄罗斯的次要服务器。在这种情况下，我们不希望我们基于俄罗斯的服务器成为主服务器，因为这将给我们位于英国的应用服务器带来延迟。在这种情况下，我们将设置我们基于俄罗斯的服务器的`priority`为`0`。

`priority`为`0`的副本集成员也不能触发选举。在所有其他方面，它们与副本集中的每个其他成员相同。要更改副本集成员的`priority`，我们必须首先通过连接（通过 mongo shell）到主服务器获取当前的副本集配置：

```sql
> cfg = rs.conf()
```

这将提供包含副本集中每个成员配置的配置文档。在`members`子文档中，我们可以找到`priority`属性，我们必须将其设置为`0`：

```sql
> cfg.members[2].priority = 0
```

最后，我们需要使用更新后的配置重新配置副本集：

```sql
rs.reconfig(cfg)
```

确保每个节点中运行的 MongoDB 版本相同，否则可能会出现意外行为。避免在高流量时期重新配置副本集群。重新配置副本集可能会强制进行新主要选举，这将关闭所有活动连接，并可能导致 10-30 秒的停机时间。尝试识别最低流量时间窗口来运行维护操作，始终在发生故障时有恢复计划。

# 隐藏的副本集成员

隐藏的副本集成员用于特殊任务。它们对客户端不可见，在`db.isMaster()` mongo shell 命令和类似的管理命令中不会显示，并且对客户端不会被考虑（即读取首选项选项）。

它们可以投票选举，但永远不会成为主服务器。隐藏的副本集成员只会同步到主服务器，并不会从客户端读取。因此，它具有与主服务器相同的写入负载（用于复制目的），但自身没有读取负载。

由于前面提到的特性，报告是隐藏成员最常见的应用。我们可以直接连接到此成员并将其用作 OLAP 的数据源。

要设置隐藏的副本集成员，我们遵循与`priority`为`0`类似的过程。在通过 mongo shell 连接到我们的主服务器后，我们获取配置对象，识别在成员子文档中对应于我们想要设置为`hidden`的成员的成员，并随后将其`priority`设置为`0`，将其`hidden`属性设置为`true`。最后，我们必须通过调用`rs.reconfig(config_object)`并将`config_object`作为参数使用来应用新配置：

```sql
> cfg = rs.conf()
> cfg.members[0].priority = 0
> cfg.members[0].hidden = true
> rs.reconfig(cfg)
```

`hidden`副本集成员也可以用于备份目的。然而，正如您将在下一节中看到的，我们可能希望在物理级别或逻辑级别复制数据时使用其他选项。在这些情况下，考虑使用延迟副本集。

# 延迟副本集成员

在许多情况下，我们希望有一个节点在较早的时间点保存我们的数据副本。这有助于从大量人为错误中恢复，比如意外删除集合或升级出现严重问题。

延迟的副本集成员必须是 `priority = 0` 和 `hidden = true`。延迟的副本集成员可以投票进行选举，但永远不会对客户端可见（`hidden = true`），也永远不会成为主服务器（`priority = 0`）。

一个示例如下：

```sql
> cfg = rs.conf()
> cfg.members[0].priority = 0
> cfg.members[0].hidden = true
> cfg.members[0].slaveDelay = 7200
> rs.reconfig(cfg)
```

这将把 `members[0]` 设置为延迟 2 小时。决定主服务器和延迟次要服务器之间时间间隔的两个重要因素如下：

+   主要副本中足够的 oplog 大小

+   在延迟成员开始获取数据之前，足够的维护时间

下表显示了副本集的延迟时间（以小时为单位）：

| **维护窗口，以小时为单位** | **延迟** | **主要副本的 oplog 大小，以小时为单位** |
| --- | --- | --- |
| *0.5* | *[0.5,5)* | *5* |

# 生产考虑

在单独的物理主机上部署每个 `mongod` 实例。如果使用虚拟机，请确保它们映射到不同的基础物理主机。使用 `bind_ip` 选项确保服务器映射到特定的网络接口和端口地址。

使用防火墙阻止对任何其他端口的访问和/或仅允许应用程序服务器和 MongoDB 服务器之间的访问。更好的做法是设置 VPN，以便您的服务器以安全的加密方式相互通信。

# 连接到副本集

连接到副本集与连接到单个服务器本质上没有太大不同。在本节中，我们将展示一些使用官方 `mongo-ruby-driver` 的示例。我们将按以下步骤进行副本集的操作：

1.  首先，我们需要设置我们的 `host` 和 `options` 对象：

```sql
client_host = ['hostname:port']
client_options = {
 database: 'signals',
 replica_set: 'xmr_btc'
}
```

在上述示例中，我们准备连接到 `hostname:port`，在 `replica_set xmr_btc` 数据库中的信号。

1.  在 `Mongo::Client` 上调用初始化器现在将返回一个包含连接到我们的副本集和数据库的 `client` 对象：

```sql
client = Mongo::Client.new(client_host, client_options)
```

`client` 对象在连接到单个服务器时具有相同的选项。

连接到副本集后，MongoDB 在连接到我们的 `client_host` 后使用自动发现来识别副本集的其他成员，无论它们是主服务器还是次要服务器。`client` 对象应该作为单例使用，创建一次并在整个代码库中重复使用。

1.  在某些情况下，可以覆盖使用单例 `client` 对象的规则。如果我们有不同类别的连接到副本集，应该创建不同的 `client` 对象。

例如，对于大多数操作使用一个 `client` 对象，然后对于只从次要服务器读取的操作使用另一个 `client` 对象：

```sql
client_reporting = client.with(:read => { :mode => :secondary })
```

1.  这个 Ruby MongoDB `client` 命令将返回一个包含读取偏好为次要的 `MongoDB:Client` 对象的副本，例如，用于报告目的。

我们在 `client_options` 初始化对象中可以使用的一些最有用的选项如下：

| **选项** | **描述** | **类型** | **默认** |
| --- | --- | --- | --- |
| `replica_set` | 在我们的示例中使用：副本集名称。 | 字符串 | 无 |
| `write` | `write` 关注选项作为 `hash` 对象；可用选项为 `w`、`wtimeout`、`j` 和 `fsync`。也就是说，要指定写入到两个服务器，启用日志记录，刷新到磁盘（`fsync`）为 `true`，并设置超时为 `1` 秒：`{ write: { w: 2, j: true, wtimeout: 1000, fsync: true } }` | 哈希 | `{ w: 1 }` |

| `read` | 读取偏好模式作为哈希。可用选项为 `mode` 和 `tag_sets`。也就是说，限制从具有标签 `UKWrites` 的次要服务器读取：`{ read:` ` { mode: :secondary,`

`   tag_sets: [ "UKWrites" ]`

` }`

`}` | 哈希 | `{ mode: primary }` |

| `user` | 要进行身份验证的用户的名称。 | 字符串 | 无 |
| --- | --- | --- | --- |
| `password` | 要进行身份验证的用户的密码。 | 字符串 | 无 |
| `connect` | 使用`:direct`，我们可以强制将副本集成员视为独立服务器，绕过自动发现。其他选项包括：`:direct`，`:replica_set`和`:sharded`。 | 符号 | 无 |
| `heartbeat_frequency` | 副本集成员定期通信以检查它们是否都存活的频率。 | 浮点数 | `10` |
| `database` | 数据库连接。 | 字符串 | `admin` |

与连接到独立服务器类似，SSL 和身份验证也有相同的选项。

我们还可以通过设置以下代码来配置连接池：

```sql
min_pool_size(defaults to 1 connection),
max_pool_size(defaults to 5),
wait_queue_timeout(defaults to 1 in seconds).
```

如果可用，MongoDB 驱动程序将尝试重用现有连接，否则将打开新连接。一旦达到池限制，驱动程序将阻塞，等待连接被释放以使用它。

# 副本集管理

副本集的管理可能比单服务器部署所需的要复杂得多。在本节中，我们将重点放在一些最常见的管理任务上，而不是试图详尽地涵盖所有不同的情况，以及如何执行这些任务。

# 如何对副本集执行维护

如果我们有一些在副本集的每个成员中都必须执行的维护任务，我们总是从辅助节点开始。我们通过执行以下步骤来执行维护：

1.  首先，我们通过 mongo shell 连接到其中一个辅助节点。然后，我们停止该辅助节点：

```sql
> use admin
> db.shutdownServer()
```

1.  然后，使用在上一步中连接到 mongo shell 的相同用户，我们在不同的端口上将 mongo 服务器重新启动为独立服务器：

```sql
> mongod --port 95658 --dbpath <wherever our mongoDB data resides in this host>
```

1.  下一步是连接到使用`dbpath`的`mongod`服务器：

```sql
> mongo --port 37017
```

1.  在这一点上，我们可以安全地执行所有独立服务器上的管理任务，而不会影响我们的副本集操作。完成后，我们以与第一步相同的方式关闭独立服务器。

1.  然后，我们可以通过使用命令行或我们通常使用的配置脚本来重新启动副本集中的服务器。最后一步是通过连接到副本集服务器并获取其副本集`status`来验证一切是否正常：

```sql
> rs.status()
```

服务器最初应处于`state: RECOVERING`状态，一旦它赶上了辅助服务器，它应该回到`state: SECONDARY`状态，就像在开始维护之前一样。

我们将为每个辅助服务器重复相同的过程。最后，我们必须对主服务器进行维护。主服务器的过程唯一的不同之处在于，在每一步之前，我们将首先将主服务器降级为辅助服务器：

```sql
> rs.stepDown(600)
```

通过使用上述参数，我们可以防止我们的辅助节点在 10 分钟内被选为主节点。这应该足够的时间来关闭服务器并继续进行维护，就像我们对辅助节点所做的那样。

# 重新同步副本集的成员

辅助节点通过重放 oplog 的内容与主节点同步。如果我们的 oplog 不够大，或者如果我们遇到网络问题（分区、网络性能不佳，或者辅助服务器的故障）的时间超过 oplog，那么 MongoDB 将无法使用 oplog 来赶上主节点。

在这一点上，我们有两个选择：

+   更直接的选择是删除我们的`dbpath`目录并重新启动`mongod`进程。在这种情况下，MongoDB 将从头开始进行初始同步。这种选择的缺点是对我们的副本集和网络造成压力。

+   更复杂（从操作角度）的选项是从副本集的另一个表现良好的成员复制数据文件。这回到了第八章的内容，*监控、备份和安全性*。要记住的重要事情是，简单的文件复制可能不够，因为数据文件在我们开始复制到复制结束的时间内已经发生了变化。

因此，我们需要能够在我们的`data`目录下拍摄文件系统的快照副本。

另一个需要考虑的问题是，当我们使用新复制的文件启动次要服务器时，我们的 MongoDB 次要服务器将尝试再次使用 oplog 与主服务器同步。因此，如果我们的 oplog 已经落后于主服务器，以至于它无法在主服务器上找到条目，这种方法也会失败。

保持足够大小的 oplog。不要让任何副本集成员的数据失控。尽早设计、测试和部署分片。

# 更改 oplog 的大小

与前面的操作提示相辅相成，随着数据的增长，我们可能需要重新考虑和调整 oplog 的大小。随着数据的增长，操作变得更加复杂和耗时，我们需要调整 oplog 的大小来适应。更改 oplog 大小的步骤如下：

1.  第一步是将我们的 MongoDB 次要服务器重新启动为独立服务器，这是在*如何对副本集执行维护*部分中描述的操作。

1.  然后我们备份我们现有的 oplog：

```sql
> mongodump --db local --collection 'oplog.rs' --port 37017
```

1.  我们保留这些数据的副本，以防万一。然后我们连接到我们的独立数据库：

```sql
> use local
> db = db.getSiblingDB('local')
> db.temp.drop()
```

到目前为止，我们已连接到`local`数据库并删除了`temp`集合，以防它有任何剩余文档。

1.  下一步是获取我们当前 oplog 的最后一个条目，并将其保存在`temp`集合中：

```sql
> db.temp.save( db.oplog.rs.find( { }, { ts: 1, h: 1 } ).sort( {$natural : -1} ).limit(1).next() )
```

1.  当我们重新启动次要服务器时，将使用此条目，以跟踪它在 oplog 复制中的进度：

```sql
> db = db.getSiblingDB('local')
> db.oplog.rs.drop()
```

1.  现在，我们删除我们现有的 oplog，在下一步中，我们将创建一个大小为`4`GB 的新 oplog：

```sql
> db.runCommand( { create: "oplog.rs", capped: true, size: (4 * 1024 * 1024 * 1024) } )
```

1.  下一步是将我们的`temp`集合中的一个条目复制回我们的 oplog：

```sql
> db.oplog.rs.save( db.temp.findOne() )
```

1.  最后，我们从`admin`数据库中干净地关闭服务器，使用`db.shutdownServer()`命令，然后将我们的次要服务器重新启动为副本集的成员。

1.  我们对所有次要服务器重复此过程，最后一步是对我们的主要成员重复该过程，这是在使用以下命令将主服务器降级之后完成的：

```sql
> rs.stepDown(600)
```

# 在我们失去大多数服务器时重新配置副本集

这只是一个临时解决方案，也是在面临停机和集群操作中断时的最后手段。当我们失去大多数服务器，但仍有足够的服务器可以启动一个副本集（可能包括一些快速生成的仲裁者）时，我们可以强制只使用幸存成员进行重新配置。

首先，我们获取副本集配置文档：

```sql
> cfg = rs.conf()
```

使用`printjson(cfg)`，我们确定仍在运行的成员。假设这些成员是`1`、`2`和`3`：

```sql
> cfg.members = [cfg.members[1] , cfg.members[2] , cfg.members[3]]
> rs.reconfig(cfg, {force : true})
```

通过使用`force：true`，我们强制进行此重新配置。当然，我们需要至少有三个幸存成员在我们的副本集中才能使其工作。

尽快删除故障服务器非常重要，方法是终止进程和/或将它们从网络中移除，以避免意外后果；这些服务器可能认为它们仍然是集群的一部分，而集群已不再承认它们。

# 链式复制

在 MongoDB 中，复制通常发生在主服务器和次要服务器之间。在某些情况下，我们可能希望从另一个次要服务器复制，而不是从主服务器复制。链式复制有助于减轻主服务器的读取负载，但与此同时，它会增加选择从次要服务器复制的次要服务器的平均复制延迟。这是有道理的，因为复制必须从主服务器到次要服务器（1），然后从这台服务器到另一个次要服务器（2）。

可以使用以下`cfg`命令启用（或分别禁用）链式复制：

```sql
> cfg.settings.chainingAllowed = true
```

在`printjson(cfg)`不显示设置子文档的情况下，我们需要首先创建一个空文档：

```sql
> cfg.settings = { }
```

如果已经存在一个`settings`文档，上述命令将导致删除其设置，可能导致数据丢失。

# 副本集的云选项

我们可以从我们自己的服务器上设置和操作副本集，但是我们可以通过使用**数据库即服务**（**DBaaS**）提供商来减少我们的运营开销。最广泛使用的两个 MongoDB 云提供商是 mLab（以前是 MongoLab）和 MongoDB Atlas，后者是 MongoDB, Inc.的原生产品。

在本节中，我们将讨论这些选项以及它们与使用我们自己的硬件和数据中心相比的优劣。

# mLab

mLab 是 MongoDB 最受欢迎的云 DBaaS 提供商之一。自 2011 年以来一直提供，并被认为是一个稳定和成熟的提供商。

注册后，我们可以在一组云服务器上轻松部署副本集群，而无需任何运营开销。配置选项包括 AWS、Microsoft Azure 或 Google Cloud 作为基础服务器提供商。

最新的 MongoDB 版本有多个大小选项。在撰写本书时，MMAPv1 存储引擎没有支持。每个提供商都有多个地区（美国、欧洲和亚洲）。值得注意的是，缺少的地区是 AWS 中国、AWS 美国政府和 AWS 德国地区。

# MongoDB Atlas

MongoDB Atlas 是 MongoDB, Inc.的一个较新的产品，于 2016 年夏季推出。与 mLab 类似，它通过 Web 界面提供单服务器、副本集或分片集群的部署。

它提供了最新的 MongoDB 版本。唯一的存储选项是 WiredTiger。每个提供商都有多个地区（美国、欧洲和亚洲）。

值得注意的是，缺少的地区是 AWS 中国和 AWS 美国政府地区。

在这两个（以及大多数其他）提供商中，我们无法拥有跨区域的副本集。如果我们想要部署一个真正全球的服务，为来自全球多个数据中心的用户提供服务，并且希望我们的 MongoDB 服务器尽可能靠近应用服务器，这是不利的。

云托管服务的运行成本可能会比在我们自己的服务器上设置要高得多。我们在便利性和上市时间上所获得的可能需要以运营成本来支付。

# 副本集的限制

当我们了解为什么需要副本集以及它不能做什么时，副本集就非常好。副本集的不同限制如下：

+   它不会进行水平扩展；我们需要分片来实现。

+   如果我们的网络不稳定，我们将引入复制问题。

+   如果我们使用辅助服务器进行读取，那么调试问题将变得更加复杂，而且这些辅助服务器已经落后于我们的主服务器。

另一方面，正如我们在本章的前几节中所解释的，副本集对于复制、数据冗余、符合数据隐私、备份甚至从人为错误或其他原因引起的错误中恢复来说都是一个很好的选择。

# 总结

在本章中，我们讨论了副本集以及如何对其进行管理。从副本集的架构概述和涉及选举的副本集内部开始，我们深入到了设置和配置副本集。

您学会了如何使用副本集执行各种管理任务，并了解了将操作外包给云 DBaaS 提供商的主要选项。最后，我们确定了 MongoDB 目前副本集存在的一些限制。

在下一章中，我们将继续讨论 MongoDB 中最有趣的概念之一（帮助其实现水平扩展的概念）：分片。
