# Spark 秘籍（一）

> 原文：[`zh.annas-archive.org/md5/BF1FAE88E839F4D0A5A0FD250CEC5835`](https://zh.annas-archive.org/md5/BF1FAE88E839F4D0A5A0FD250CEC5835)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

Hadoop 作为大数据平台的成功提高了用户的期望，无论是在解决不同的分析挑战还是减少延迟方面。随着时间的推移，出现了各种工具，但当 Apache Spark 出现时，它提供了一个单一的运行时来解决所有这些挑战。它消除了将多个工具结合在一起的需要，这些工具都有自己的挑战和学习曲线。通过在计算之外使用内存作为持久存储，Apache Spark 消除了在磁盘上存储中间数据的需要，并将处理速度提高了 100 倍。它还提供了一个单一的运行时，可以使用各种库来满足各种分析需求，如机器学习和使用各种库进行实时流处理。

本书涵盖了安装和配置 Apache Spark 以及使用 Spark Core、Spark SQL、Spark Streaming、MLlib 和 GraphX 库构建解决方案。

### 注意

有关本书食谱的更多信息，请访问[infoobjects.com/spark-cookbook](http://infoobjects.com/spark-cookbook)。

# 本书涵盖的内容

第一章 *开始使用 Apache Spark*，解释了如何在各种环境和集群管理器上安装 Spark。

第二章 *使用 Spark 开发应用程序*，介绍了在不同的 IDE 上开发 Spark 应用程序以及使用不同的构建工具。

第三章 *外部数据源*，介绍了如何读取和写入各种数据源。

第四章 *Spark SQL*，带您了解了 Spark SQL 模块，该模块可帮助您使用 SQL 接口访问 Spark 功能。

第五章 *Spark Streaming*，探讨了 Spark Streaming 库，用于分析来自实时数据源（如 Kafka）的数据。

第六章 *使用 MLlib 开始机器学习*，介绍了机器学习和基本工件（如向量和矩阵）的基本概念。

第七章 *使用 MLlib 进行监督学习-回归*，介绍了当结果变量是连续时的监督学习。

第八章 *使用 MLlib 进行监督学习-分类*，讨论了当结果变量是离散时的监督学习。

第九章 *使用 MLlib 进行无监督学习*，涵盖了 k-means 等无监督学习算法。

第十章 *推荐系统*，介绍了使用各种技术构建推荐系统，如 ALS。

第十一章 *使用 GraphX 进行图处理*，介绍了使用 GraphX 进行各种图处理算法。

第十二章 *优化和性能调优*，涵盖了 Apache Spark 的各种优化和性能调优技术。

# 本书所需内容

您需要 InfoObjects Big Data Sandbox 软件才能继续阅读本书中的示例。此软件可从[`www.infoobjects.com`](http://www.infoobjects.com)下载。

# 本书适合谁

如果您是数据工程师、应用程序开发人员或数据科学家，希望利用 Apache Spark 的强大功能从大数据中获得更好的洞察力，那么这本书适合您。

# 部分

在本书中，您会发现一些经常出现的标题（准备工作、如何做、它是如何工作的、还有更多、另请参阅）。

为了清晰地说明如何完成食谱，我们使用以下部分：

## 准备工作

本节告诉您在食谱中可以期待什么，并描述了为食谱设置任何软件或所需的任何初步设置的步骤。

## 如何做…

本节包含了遵循食谱所需的步骤。

## 工作原理…

本节通常包括对上一节发生的事情的详细解释。

## 还有更多…

本节包括有关食谱的附加信息，以使读者更加了解食谱。

## 另请参阅

本节提供了指向其他有用信息的链接。

# 约定

在本书中，您会发现一些文本样式，用于区分不同类型的信息。以下是一些这些样式的示例及其含义的解释。

文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄会以以下形式显示："Spark 期望 Java 已安装，并且`JAVA_HOME`环境变量已设置。"

代码块设置如下：

```scala
lazy val root = (project in file("."))
  settings(
    name := "wordcount"
  )
```

任何命令行输入或输出都以以下形式编写：

```scala
$ wget http://d3kbcqa49mib13.cloudfront.net/spark-1.4.0-bin-hadoop2.4.tgz

```

**新术语**和**重要单词**以粗体显示。您在屏幕上看到的单词，例如菜单或对话框中的单词，会以这种形式出现在文本中："在右上角的帐户名称下单击**安全凭据**。"

### 注意

警告或重要说明会以这种形式出现在方框中。

### 提示

提示和技巧会以这种形式出现。


# 第一章： 开始使用 Apache Spark

在本章中，我们将设置和配置 Spark。本章分为以下教程：

+   从二进制文件安装 Spark

+   使用 Maven 构建 Spark 源代码

+   在 Amazon EC2 上启动 Spark

+   在独立模式下在集群上部署 Spark

+   在 Mesos 集群上部署 Spark

+   在 YARN 集群上部署 Spark

+   使用 Tachyon 作为离堆存储层

# 介绍

Apache Spark 是一个通用的集群计算系统，用于处理大数据工作负载。Spark 与其前身 MapReduce 的区别在于其速度、易用性和复杂的分析。

Apache Spark 最初是在 2009 年由加州大学伯克利分校的 AMPLab 开发的。它于 2010 年以 BSD 许可证开源，并于 2013 年切换到 Apache 2.0 许可证。在 2013 年后期，Spark 的创造者成立了 Databricks，专注于 Spark 的开发和未来发布。

谈到速度，Spark 可以在大数据工作负载上实现亚秒延迟。为了实现如此低的延迟，Spark 利用内存进行存储。在 MapReduce 中，内存主要用于实际计算。Spark 使用内存来计算和存储对象。

Spark 还提供了一个统一的运行时，连接到各种大数据存储源，如 HDFS、Cassandra、HBase 和 S3。它还提供了丰富的高级库，用于不同的大数据计算任务，如机器学习、SQL 处理、图处理和实时流处理。这些库使开发更快，并且可以以任意方式组合。

尽管 Spark 是用 Scala 编写的，而本书只关注 Scala 中的教程，但 Spark 也支持 Java 和 Python。

Spark 是一个开源社区项目，每个人都使用纯开源的 Apache 发行版进行部署，不像 Hadoop 有多个带有供应商增强的发行版可用。

以下图显示了 Spark 生态系统：

![Introduction](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_01_01.jpg)

Spark 运行时在各种集群管理器上运行，包括 YARN（Hadoop 的计算框架）、Mesos 和 Spark 自己的集群管理器**独立模式**。Tachyon 是一个以内存为中心的分布式文件系统，可以在集群框架之间以内存速度可靠地共享文件。简而言之，它是内存中的离堆存储层，有助于在作业和用户之间共享数据。Mesos 是一个集群管理器，正在演变成数据中心操作系统。YARN 是 Hadoop 的计算框架，具有强大的资源管理功能，Spark 可以无缝使用。

# 从二进制文件安装 Spark

Spark 可以从源代码构建，也可以从[`spark.apache.org`](http://spark.apache.org)下载预编译的二进制文件。对于标准用例，二进制文件已经足够好，本教程将重点介绍使用二进制文件安装 Spark。

## 准备就绪

本书中的所有教程都是在 Ubuntu Linux 上开发的，但在任何 POSIX 环境中都应该可以正常工作。Spark 需要安装 Java，并设置`JAVA_HOME`环境变量。

在 Linux/Unix 系统中，有关文件和目录位置的一些标准，我们将在本书中遵循。以下是一个快速的备忘单：

| 目录 | 描述 |
| --- | --- |
| `/bin` | 基本命令二进制文件 |
| `/etc` | 特定主机系统配置 |
| `/opt` | 附加应用软件包 |
| `/var` | 可变数据 |
| `/tmp` | 临时文件 |
| `/home` | 用户主目录 |

## 如何做...

在撰写本文时，Spark 的当前版本是 1.4。请从 Spark 的下载页面[`spark.apache.org/downloads.html`](http://spark.apache.org/downloads.html)检查最新版本。二进制文件是使用最新和稳定版本的 Hadoop 开发的。要使用特定版本的 Hadoop，推荐的方法是从源代码构建，这将在下一个教程中介绍。

以下是安装步骤：

1.  打开终端并使用以下命令下载二进制文件：

```scala
$ wget http://d3kbcqa49mib13.cloudfront.net/spark-1.4.0-bin-hadoop2.4.tgz

```

1.  解压二进制文件：

```scala
$ tar -zxf spark-1.4.0-bin-hadoop2.4.tgz

```

1.  通过剥离版本信息重命名包含二进制文件的文件夹：

```scala
$ sudo mv spark-1.4.0-bin-hadoop2.4 spark

```

1.  将配置文件夹移动到`/etc`文件夹，以便稍后可以将其创建为符号链接：

```scala
$ sudo mv spark/conf/* /etc/spark

```

1.  在`/opt`目录下创建您公司特定的安装目录。由于本书中的示例在`infoobjects`沙箱上进行了测试，我们将使用`infoobjects`作为目录名称。创建`/opt/infoobjects`目录：

```scala
$ sudo mkdir -p /opt/infoobjects

```

1.  将`spark`目录移动到`/opt/infoobjects`，因为它是一个附加软件包：

```scala
$ sudo mv spark /opt/infoobjects/

```

1.  更改`spark`主目录的所有权为`root`：

```scala
$ sudo chown -R root:root /opt/infoobjects/spark

```

1.  更改`spark`主目录的权限，`0755 = 用户：读-写-执行组：读-执行世界：读-执行`：

```scala
$ sudo chmod -R 755 /opt/infoobjects/spark

```

1.  转到`spark`主目录：

```scala
$ cd /opt/infoobjects/spark

```

1.  创建符号链接：

```scala
$ sudo ln -s /etc/spark conf

```

1.  在`.bashrc`中追加`PATH`：

```scala
$ echo "export PATH=$PATH:/opt/infoobjects/spark/bin" >> /home/hduser/.bashrc

```

1.  打开一个新的终端。

1.  在`/var`中创建`log`目录：

```scala
$ sudo mkdir -p /var/log/spark

```

1.  将`hduser`设置为 Spark `log`目录的所有者。

```scala
$ sudo chown -R hduser:hduser /var/log/spark

```

1.  创建 Spark `tmp`目录：

```scala
$ mkdir /tmp/spark

```

1.  使用以下命令行配置 Spark：

```scala
$ cd /etc/spark
$ echo "export HADOOP_CONF_DIR=/opt/infoobjects/hadoop/etc/hadoop" >> spark-env.sh
$ echo "export YARN_CONF_DIR=/opt/infoobjects/hadoop/etc/Hadoop" >> spark-env.sh
$ echo "export SPARK_LOG_DIR=/var/log/spark" >> spark-env.sh
$ echo "export SPARK_WORKER_DIR=/tmp/spark" >> spark-env.sh

```

# 使用 Maven 构建 Spark 源代码

在大多数情况下，使用二进制文件安装 Spark 效果很好。对于高级情况，例如以下情况（但不限于此），从源代码编译是更好的选择：

+   为特定的 Hadoop 版本编译

+   添加 Hive 集成

+   添加 YARN 集成

## 准备就绪

这个示例的先决条件是：

+   Java 1.6 或更高版本

+   Maven 3.x

## 如何做...

以下是使用 Maven 构建 Spark 源代码的步骤：

1.  增加`MaxPermSize`以扩展堆：

```scala
$ echo "export _JAVA_OPTIONS=\"-XX:MaxPermSize=1G\""  >> /home/hduser/.bashrc

```

1.  打开一个新的终端窗口并从 GitHub 下载 Spark 源代码：

```scala
$ wget https://github.com/apache/spark/archive/branch-1.4.zip

```

1.  解压缩存档：

```scala
$ gunzip branch-1.4.zip

```

1.  转到`spark`目录：

```scala
$ cd spark

```

1.  使用以下标志编译源代码：启用 Yarn，Hadoop 版本 2.4，启用 Hive，并跳过测试以加快编译速度：

```scala
$ mvn -Pyarn -Phadoop-2.4 -Dhadoop.version=2.4.0 -Phive -DskipTests clean package

```

1.  将`conf`文件夹移动到`etc`文件夹，以便稍后可以将其创建为符号链接：

```scala
$ sudo mv spark/conf /etc/

```

1.  将`spark`目录移动到`/opt`，因为它是一个附加软件包：

```scala
$ sudo mv spark /opt/infoobjects/spark

```

1.  更改`spark`主目录的所有权为`root`：

```scala
$ sudo chown -R root:root /opt/infoobjects/spark

```

1.  更改`spark`主目录的权限`0755 = 用户：rwx 组：r-x 世界：r-x`：

```scala
$ sudo chmod -R 755 /opt/infoobjects/spark

```

1.  转到`spark`主目录：

```scala
$ cd /opt/infoobjects/spark

```

1.  创建一个符号链接：

```scala
$ sudo ln -s /etc/spark conf

```

1.  通过编辑`.bashrc`将 Spark 可执行文件放入路径中：

```scala
$ echo "export PATH=$PATH:/opt/infoobjects/spark/bin" >> /home/hduser/.bashrc

```

1.  在`/var`中创建`log`目录：

```scala
$ sudo mkdir -p /var/log/spark

```

1.  将`hduser`设置为 Spark `log`目录的所有者：

```scala
$ sudo chown -R hduser:hduser /var/log/spark

```

1.  创建 Spark `tmp`目录：

```scala
$ mkdir /tmp/spark

```

1.  使用以下命令行配置 Spark：

```scala
$ cd /etc/spark
$ echo "export HADOOP_CONF_DIR=/opt/infoobjects/hadoop/etc/hadoop" >> spark-env.sh
$ echo "export YARN_CONF_DIR=/opt/infoobjects/hadoop/etc/Hadoop" >> spark-env.sh
$ echo "export SPARK_LOG_DIR=/var/log/spark" >> spark-env.sh
$ echo "export SPARK_WORKER_DIR=/tmp/spark" >> spark-env.sh

```

# 在 Amazon EC2 上启动 Spark

**Amazon Elastic Compute Cloud**（**Amazon EC2**）是一种提供可调整大小的云中计算实例的网络服务。Amazon EC2 提供以下功能：

+   通过互联网按需交付 IT 资源

+   提供您喜欢的实例数量

+   按小时支付您使用实例的费用，就像您的水电费一样

+   没有设置费用，没有安装费用，也没有任何额外费用

+   当您不再需要实例时，您可以关闭或终止并离开

+   这些实例在所有熟悉的操作系统上都是可用的

EC2 提供不同类型的实例，以满足所有计算需求，例如通用实例、微型实例、内存优化实例、存储优化实例等。它们有一个免费的微型实例套餐可供尝试。

## 准备就绪

`spark-ec2`脚本与 Spark 捆绑在一起，可以轻松在 Amazon EC2 上启动、管理和关闭集群。

在开始之前，您需要做以下事情：

1.  登录到 Amazon AWS 帐户（[`aws.amazon.com`](http://aws.amazon.com)）。

1.  在右上角的帐户名称下单击**安全凭据**。

1.  单击**访问密钥**和**创建新的访问密钥**：![准备就绪](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_01_02.jpg)

1.  记下访问密钥 ID 和秘密访问密钥。

1.  现在转到**服务** | **EC2**。

1.  在左侧菜单中单击**密钥对**，然后单击**网络和安全**下的**密钥对**。

1.  单击**创建密钥对**，并输入 `kp-spark` 作为密钥对名称：![准备中](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_01_15.jpg)

1.  下载私钥文件并将其复制到 `/home/hduser/keypairs` 文件夹中。

1.  将密钥文件权限设置为 `600`。

1.  设置环境变量以反映访问密钥 ID 和秘密访问密钥（请用您自己的值替换示例值）：

```scala
$ echo "export AWS_ACCESS_KEY_ID=\"AKIAOD7M2LOWATFXFKQ\"" >> /home/hduser/.bashrc
$ echo "export AWS_SECRET_ACCESS_KEY=\"+Xr4UroVYJxiLiY8DLT4DLT4D4sxc3ijZGMx1D3pfZ2q\"" >> /home/hduser/.bashrc
$ echo "export PATH=$PATH:/opt/infoobjects/spark/ec2" >> /home/hduser/.bashrc

```

## 如何做...

1.  Spark 预先捆绑了用于在 Amazon EC2 上启动 Spark 集群的脚本。让我们使用以下命令启动集群：

```scala
$ cd /home/hduser
$ spark-ec2 -k <key-pair> -i <key-file> -s <num-slaves> launch <cluster-name>

```

1.  使用示例值启动集群：

```scala
$ spark-ec2 -k kp-spark -i /home/hduser/keypairs/kp-spark.pem --hadoop-major-version 2  -s 3 launch spark-cluster

```

### 注意

+   `<key-pair>`: 这是在 AWS 中创建的 EC2 密钥对的名称

+   `<key-file>`: 这是您下载的私钥文件

+   `<num-slaves>`: 这是要启动的从节点数量

+   `<cluster-name>`: 这是集群的名称

1.  有时，默认的可用区不可用；在这种情况下，通过指定您正在请求的特定可用区来重试发送请求：

```scala
$ spark-ec2 -k kp-spark -i /home/hduser/keypairs/kp-spark.pem -z us-east-1b --hadoop-major-version 2  -s 3 launch spark-cluster

```

1.  如果您的应用程序需要在实例关闭后保留数据，请将 EBS 卷附加到它（例如，10 GB 空间）：

```scala
$ spark-ec2 -k kp-spark -i /home/hduser/keypairs/kp-spark.pem --hadoop-major-version 2 -ebs-vol-size 10 -s 3 launch spark-cluster

```

1.  如果您使用 Amazon spot 实例，以下是操作方法：

```scala
$ spark-ec2 -k kp-spark -i /home/hduser/keypairs/kp-spark.pem -spot-price=0.15 --hadoop-major-version 2  -s 3 launch spark-cluster

```

### 注意

Spot 实例允许您为 Amazon EC2 计算能力命名自己的价格。您只需对多余的 Amazon EC2 实例进行竞标，并在您的出价超过当前 spot 价格时运行它们，该价格根据供求实时变化（来源：[amazon.com](http://amazon.com)）。

1.  一切都启动后，通过转到最后打印的 web UI URL 来检查集群的状态。![如何做...](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_01_03.jpg)

1.  检查集群的状态：![如何做...](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_01_04.jpg)

1.  现在，要访问 EC2 上的 Spark 集群，让我们使用**安全外壳协议**（**SSH**）连接到主节点：

```scala
$ spark-ec2 -k kp-spark -i /home/hduser/kp/kp-spark.pem  login spark-cluster

```

您应该得到类似以下的内容：

![如何做...](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_01_05.jpg)

1.  检查主节点中的目录并查看它们的作用：

| 目录 | 描述 |
| --- | --- |
| `ephemeral-hdfs` | 这是 Hadoop 实例，其中的数据是暂时的，当您停止或重新启动机器时会被删除。 |
| `persistent-hdfs` | 每个节点都有非常少量的持久存储（大约 3 GB）。如果使用此实例，数据将保留在该空间中。 |
| `hadoop-native` | 这些是支持 Hadoop 的本地库，如 snappy 压缩库。 |
| `Scala` | 这是 Scala 安装。 |
| `shark` | 这是 Shark 安装（Shark 不再受支持，已被 Spark SQL 取代）。 |
| `spark` | 这是 Spark 安装 |
| `spark-ec2` | 这些是支持此集群部署的文件。 |
| `tachyon` | 这是 Tachyon 安装 |

1.  使用以下命令检查暂时实例中的 HDFS 版本：

```scala
$ ephemeral-hdfs/bin/hadoop version
Hadoop 2.0.0-chd4.2.0

```

1.  使用以下命令检查持久实例中的 HDFS 版本：

```scala
$ persistent-hdfs/bin/hadoop version
Hadoop 2.0.0-chd4.2.0

```

1.  更改日志中的配置级别：

```scala
$ cd spark/conf

```

1.  默认的日志级别信息太冗长了，所以让我们将其更改为错误：![如何做...](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_01_06.jpg)

1.  通过重命名模板创建 `log4.properties` 文件：

```scala
$ mv log4j.properties.template log4j.properties

```

1.  在 vi 或您喜欢的编辑器中打开 `log4j.properties`：

```scala
$ vi log4j.properties

```

1.  将第二行从 `| log4j.rootCategory=INFO, console` 更改为 `| log4j.rootCategory=ERROR, console`。

1.  更改后将配置复制到所有从节点：

```scala
$ spark-ec2/copydir spark/conf

```

您应该得到类似以下的内容：

![如何做...](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_01_07.jpg)

1.  销毁 Spark 集群：

```scala
$ spark-ec2 destroy spark-cluster

```

### 另请参阅

+   [`aws.amazon.com/ec2`](http://aws.amazon.com/ec2)

# 在独立模式下的集群部署

在分布式环境中管理计算资源，以便资源利用率高效，并且每个作业都有公平的运行机会。Spark 预先捆绑了其自己的集群管理器，方便地称为**独立模式**。Spark 还支持与 YARN 和 Mesos 集群管理器一起工作。

应该选择的集群管理器主要受到传统问题的驱动，以及其他框架（如 MapReduce）是否共享相同的计算资源池。如果您的集群有传统的 MapReduce 作业运行，并且所有这些作业都无法转换为 Spark 作业，那么使用 YARN 作为集群管理器是一个好主意。Mesos 正在成为一个数据中心操作系统，方便地跨框架管理作业，并且与 Spark 非常兼容。

如果 Spark 框架是集群中唯一的框架，那么独立模式就足够了。随着 Spark 作为技术的发展，您将看到越来越多的 Spark 被用作独立框架来满足所有大数据计算需求的用例。例如，目前可能有一些作业正在使用 Apache Mahout，因为 MLlib 没有特定的机器学习库，而作业需要。一旦 MLlib 获得了这个库，这个特定的作业就可以迁移到 Spark 中。

## 准备就绪

让我们以一个六个节点的集群为例：一个主节点和五个从节点（用集群中实际的节点名称替换它们）：

```scala
Master
m1.zettabytes.com
Slaves
s1.zettabytes.com
s2.zettabytes.com
s3.zettabytes.com
s4.zettabytes.com
s5.zettabytes.com

```

## 如何做...

1.  由于 Spark 的独立模式是默认模式，所以您只需要在主节点和从节点上安装 Spark 二进制文件。在每个节点上将`/opt/infoobjects/spark/sbin`添加到路径中：

```scala
$ echo "export PATH=$PATH:/opt/infoobjects/spark/sbin" >> /home/hduser/.bashrc

```

1.  启动独立的主服务器（首先 SSH 到主节点）：

```scala
hduser@m1.zettabytes.com~] start-master.sh

```

默认情况下，Master 在端口 7077 上启动，从节点使用该端口连接到 Master。它还在端口 8088 上有一个 Web UI。

1.  请 SSH 到主节点并启动从节点：

```scala
hduser@s1.zettabytes.com~] spark-class org.apache.spark.deploy.worker.Worker spark://m1.zettabytes.com:7077

```

| - 参数（用于细粒度配置，以下参数适用于主节点和从节点） | 意义 |
| --- | --- |
| - --- | --- |
| - `-i <ipaddress>,-ip <ipaddress>` | IP 地址/DNS 服务监听的地址 |
| - `-p <port>, --port <port>` | 服务监听的端口 |
| - `--webui-port <port>` | Web UI 的端口（默认情况下，主节点为 8080，从节点为 8081） |
| - `-c <cores>,--cores <cores>` | 机器上可以用于 Spark 应用程序的总 CPU 核心数（仅限 worker） |
| - `-m <memory>,--memory <memory>` | 机器上可以用于 Spark 应用程序的总 RAM（仅限 worker） |
| - `-d <dir>,--work-dir <dir>` | 用于临时空间和作业输出日志的目录 |

1.  与手动在每个节点上启动主和从守护程序相比，也可以使用集群启动脚本来完成。

1.  首先，在主节点上创建`conf/slaves`文件，并添加每个从节点主机名的一行（使用五个从节点的示例，用集群中从节点的 DNS 替换）：

```scala
hduser@m1.zettabytes.com~] echo "s1.zettabytes.com" >> conf/slaves
hduser@m1.zettabytes.com~] echo "s2.zettabytes.com" >> conf/slaves
hduser@m1.zettabytes.com~] echo "s3.zettabytes.com" >> conf/slaves
hduser@m1.zettabytes.com~] echo "s4.zettabytes.com" >> conf/slaves
hduser@m1.zettabytes.com~] echo "s5.zettabytes.com" >> conf/slaves

```

一旦从节点设置好，就可以调用以下脚本来启动/停止集群：

| - 脚本名称 | 目的 |
| --- | --- |
| - --- | --- |
| - `start-master.sh` | 在主机上启动主实例 |
| - `start-slaves.sh` | 在 slaves 文件中的每个节点上启动一个从节点实例 |
| - `start-all.sh` | 启动主节点和从节点 |
| - `stop-master.sh` | 停止主机上的主实例 |
| - `stop-slaves.sh` | 停止 slaves 文件中所有节点上的从节点实例 |
| - `stop-all.sh` | 停止主节点和从节点 |

1.  通过 Scala 代码将应用程序连接到集群：

```scala
val sparkContext = new SparkContext(new SparkConf().setMaster("spark://m1.zettabytes.com:7077")

```

1.  通过 Spark shell 连接到集群：

```scala
$ spark-shell --master spark://master:7077

```

## 它是如何工作的...

在独立模式下，Spark 遵循主从架构，非常类似于 Hadoop、MapReduce 和 YARN。计算主守护程序称为**Spark master**，在一个主节点上运行。Spark master 可以使用 ZooKeeper 实现高可用性。如果需要，还可以在运行时添加更多的备用主节点。

计算从节点守护程序称为**worker**，位于每个从节点上。worker 守护程序执行以下操作：

+   报告从节点上计算资源的可用性，例如核心数、内存等，到 Spark master

+   当 Spark master 要求时，生成执行程序

+   如果执行程序死掉，则重新启动执行程序

每个应用程序每个从节点最多只有一个执行程序。

Spark 的 master 和 worker 都非常轻量级。通常，500 MB 到 1 GB 之间的内存分配就足够了。可以通过在`conf/spark-env.sh`中设置`SPARK_DAEMON_MEMORY`参数来设置这个值。例如，以下配置将为 master 和 worker daemon 设置内存为 1 GB。在运行之前确保你有`sudo`超级用户权限：

```scala
$ echo "export SPARK_DAEMON_MEMORY=1g" >> /opt/infoobjects/spark/conf/spark-env.sh

```

默认情况下，每个从属节点上都有一个工作程序实例在运行。有时，您可能有一些比其他机器更强大的机器。在这种情况下，可以通过以下配置在该机器上生成多个工作程序（仅在这些机器上）：

```scala
$ echo "export SPARK_WORKER_INSTANCES=2" >> /opt/infoobjects/spark/conf/spark-env.sh

```

Spark worker 默认使用从属机器上的所有核心作为其执行器。如果要限制工作程序可以使用的核心数，可以通过以下配置将其设置为该数字（例如 12）：

```scala
$ echo "export SPARK_WORKER_CORES=12" >> /opt/infoobjects/spark/conf/spark-env.sh

```

Spark worker 默认使用所有可用的 RAM（执行器为 1 GB）。请注意，您无法分配每个特定执行器将使用多少内存（您可以从驱动程序配置中控制此操作）。要为所有执行器组合使用的总内存（例如，24 GB）分配另一个值，请执行以下设置：

```scala
$ echo "export SPARK_WORKER_MEMORY=24g" >> /opt/infoobjects/spark/conf/spark-env.sh

```

在驱动程序级别可以进行一些设置：

+   要指定集群中给定应用程序可以使用的最大 CPU 核心数，可以在 Spark submit 或 Spark shell 中设置`spark.cores.max`配置如下：

```scala
$ spark-submit --conf spark.cores.max=12

```

+   要指定每个执行器应分配的内存量（最低建议为 8 GB），可以在 Spark submit 或 Spark shell 中设置`spark.executor.memory`配置如下：

```scala
$ spark-submit --conf spark.executor.memory=8g

```

以下图表描述了 Spark 集群的高级架构：

![工作原理...](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_01_08.jpg)

## 另请参阅

+   [`spark.apache.org/docs/latest/spark-standalone.html`](http://spark.apache.org/docs/latest/spark-standalone.html)查找更多配置选项

# 在具有 Mesos 的集群上部署

Mesos 正在逐渐成为数据中心操作系统，用于管理数据中心中的所有计算资源。Mesos 可以在运行 Linux 操作系统的任何计算机上运行。Mesos 是使用与 Linux 内核相同的原则构建的。让我们看看如何安装 Mesos。

## 如何做...

Mesosphere 提供了 Mesos 的二进制发行版。可以通过执行以下步骤从 Mesosphere 存储库安装 Mesos 的最新软件包：

1.  使用 Ubuntu OS 的 trusty 版本执行 Mesos：

```scala
$ sudo apt-key adv --keyserver keyserver.ubuntu.com --recv E56151BF DISTRO=$(lsb_release -is | tr '[:upper:]' '[:lower:]') CODENAME=$(lsb_release -cs)
$ sudo vi /etc/apt/sources.list.d/mesosphere.list

deb http://repos.mesosphere.io/Ubuntu trusty main

```

1.  更新存储库：

```scala
$ sudo apt-get -y update

```

1.  安装 Mesos：

```scala
$ sudo apt-get -y install mesos

```

1.  将 Spark 连接到 Mesos 以将 Spark 与 Mesos 集成，使 Spark 二进制文件可用于 Mesos，并配置 Spark 驱动程序以连接到 Mesos。

1.  使用第一个配方中的 Spark 二进制文件并上传到 HDFS：

```scala
$ 
hdfs dfs
 -put spark-1.4.0-bin-hadoop2.4.tgz spark-1.4.0-bin-hadoop2.4.tgz

```

1.  单主 Mesos 的主 URL 是`mesos://host:5050`，而 ZooKeeper 管理的 Mesos 集群的主 URL 是`mesos://zk://host:2181`。

1.  在`spark-env.sh`中设置以下变量：

```scala
$ sudo vi spark-env.sh
export MESOS_NATIVE_LIBRARY=/usr/local/lib/libmesos.so
export SPARK_EXECUTOR_URI= hdfs://localhost:9000/user/hduser/spark-1.4.0-bin-hadoop2.4.tgz

```

1.  从 Scala 程序运行：

```scala
val conf = new SparkConf().setMaster("mesos://host:5050")
val sparkContext = new SparkContext(conf)

```

1.  从 Spark shell 运行：

```scala
$ spark-shell --master mesos://host:5050

```

### 注意

Mesos 有两种运行模式：

**细粒度**：在细粒度（默认）模式下，每个 Spark 任务都作为单独的 Mesos 任务运行

**粗粒度**：此模式将在每个 Mesos 机器上启动一个长时间运行的 Spark 任务

1.  要在粗粒度模式下运行，设置`spark.mesos.coarse`属性：

```scala
conf.set("spark.mesos.coarse","true")

```

# 在具有 YARN 的集群上部署

**另一个资源协商者**（**YARN**）是 Hadoop 的计算框架，运行在 HDFS 之上，HDFS 是 Hadoop 的存储层。

YARN 遵循主从架构。主守护程序称为`ResourceManager`，从守护程序称为`NodeManager`。除此应用程序外，生命周期管理由`ApplicationMaster`完成，它可以在任何从节点上生成，并在应用程序的生命周期内保持活动状态。

当 Spark 在 YARN 上运行时，`ResourceManager`扮演 Spark master 的角色，而`NodeManagers`作为执行器节点工作。

在使用 YARN 运行 Spark 时，每个 Spark 执行器都作为 YARN 容器运行。

## 准备就绪

在 YARN 上运行 Spark 需要具有 YARN 支持的 Spark 二进制发行版。在两个 Spark 安装配方中，我们已经注意到了这一点。

## 如何操作...

1.  要在 YARN 上运行 Spark，第一步是设置配置：

```scala
HADOOP_CONF_DIR: to write to HDFS
YARN_CONF_DIR: to connect to YARN ResourceManager
$ cd /opt/infoobjects/spark/conf (or /etc/spark)
$ sudo vi spark-env.sh
export HADOOP_CONF_DIR=/opt/infoobjects/hadoop/etc/Hadoop
export YARN_CONF_DIR=/opt/infoobjects/hadoop/etc/hadoop

```

您可以在以下截图中看到这一点：

![如何操作...](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_01_09.jpg)

1.  以下命令在`yarn-client`模式下启动 YARN Spark：

```scala
$ spark-submit --class path.to.your.Class --master yarn-client [options] <app jar> [app options]

```

这是一个例子：

```scala
$ spark-submit --class com.infoobjects.TwitterFireHose --master yarn-client --num-executors 3 --driver-memory 4g --executor-memory 2g --executor-cores 1 target/sparkio.jar 10

```

1.  以下命令在`yarn-client`模式下启动 Spark shell：

```scala
$ spark-shell --master yarn-client

```

1.  以`yarn-cluster`模式启动的命令如下：

```scala
$ spark-submit --class path.to.your.Class --master yarn-cluster [options] <app jar> [app options]

```

这是一个例子：

```scala
$ spark-submit --class com.infoobjects.TwitterFireHose --master yarn-cluster --num-executors 3 --driver-memory 4g --executor-memory 2g --executor-cores 1 targe
t/sparkio.jar 10

```

## 工作原理...

YARN 上的 Spark 应用程序以两种模式运行：

+   `yarn-client`：Spark Driver 在 YARN 集群之外的客户端进程中运行，`ApplicationMaster`仅用于从 ResourceManager 协商资源

+   `yarn-cluster`：Spark Driver 在由从节点上的`NodeManager`生成的`ApplicationMaster`中运行

`yarn-cluster`模式适用于生产部署，而`yarn-client`模式适用于开发和调试，当您希望立即看到输出时。在任何模式下都不需要指定 Spark 主节点，因为它是从 Hadoop 配置中选择的，主参数是`yarn-client`或`yarn-cluster`。

以下图显示了在客户端模式下如何使用 YARN 运行 Spark：

![工作原理...](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_01_10.jpg)

以下图显示了在集群模式下如何使用 YARN 运行 Spark：

![工作原理...](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_01_11.jpg)

在 YARN 模式下，可以设置以下配置参数：

+   `--num-executors`：配置将分配多少个 executor

+   `--executor-memory`：每个 executor 的 RAM

+   `--executor-cores`：每个 executor 的 CPU 核心

# 使用 Tachyon 作为离堆存储层

Spark RDD 是一种在内存中存储数据集的好方法，同时在不同应用程序中产生相同数据的多个副本。Tachyon 解决了 Spark RDD 管理中的一些挑战。其中一些是：

+   RDD 仅存在于 Spark 应用程序的持续时间内

+   同一进程执行计算和 RDD 内存存储；因此，如果一个进程崩溃，内存存储也会消失

+   即使是针对相同底层数据的不同作业也不能共享 RDD，例如导致 HDFS 块的情况：

+   向磁盘写入速度慢

+   内存中数据的重复，内存占用更高

+   如果一个应用程序的输出需要与另一个应用程序共享，由于磁盘中的复制，速度会很慢

Tachyon 提供了一个离堆内存层来解决这些问题。这一层是离堆的，不受进程崩溃的影响，也不受垃圾回收的影响。这也允许 RDD 在应用程序之间共享，并且在特定作业或会话之外存在；实质上，数据的内存中只有一个副本，如下图所示：

![使用 Tachyon 作为离堆存储层](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_01_12.jpg)

## 如何操作...

1.  让我们下载并编译 Tachyon（默认情况下，Tachyon 配置为 Hadoop 1.0.4，因此需要根据正确的 Hadoop 版本从源代码编译）。将版本替换为当前版本。撰写本书时的当前版本为 0.6.4：

```scala
$ wget https://github.com/amplab/tachyon/archive/v<version>.zip

```

1.  解压源代码：

```scala
$ unzip  v-<version>.zip

```

1.  为方便起见，从`tachyon`源文件夹名称中删除版本：

```scala
$ mv tachyon-<version> tachyon

```

1.  切换到`tachyon`文件夹：

```scala
$ cd tachyon
$ mvn -Dhadoop.version=2.4.0 clean package -DskipTests=true
$ cd conf
$ sudo mkdir -p /var/tachyon/journal
$ sudo chown -R hduser:hduser /var/tachyon/journal
$ sudo mkdir -p /var/tachyon/ramdisk
$ sudo chown -R hduser:hduser /var/tachyon/ramdisk

$ mv tachyon-env.sh.template tachyon-env.sh
$ vi tachyon-env.sh

```

1.  注释以下行：

```scala
export TACHYON_UNDERFS_ADDRESS=$TACHYON_HOME/underfs

```

1.  取消注释以下行：

```scala
export TACHYON_UNDERFS_ADDRESS=hdfs://localhost:9000

```

1.  更改以下属性：

```scala
-Dtachyon.master.journal.folder=/var/tachyon/journal/

export TACHYON_RAM_FOLDER=/var/tachyon/ramdisk

$ sudo mkdir -p /var/log/tachyon
$ sudo chown -R hduser:hduser /var/log/tachyon
$ vi log4j.properties

```

1.  将`${tachyon.home}`替换为`/var/log/tachyon`。

1.  在`conf`目录中创建一个新的`core-site.xml`文件：

```scala
$ sudo vi core-site.xml
<configuration>
<property>
 <name>fs.tachyon.impl</name>
 <value>tachyon.hadoop.TFS</value>
 </property>
</configuration>
$ cd ~
$ sudo mv tachyon /opt/infoobjects/
$ sudo chown -R root:root /opt/infoobjects/tachyon
$ sudo chmod -R 755 /opt/infoobjects/tachyon

```

1.  将`<tachyon home>/bin`添加到路径中：

```scala
$ echo "export PATH=$PATH:/opt/infoobjects/tachyon/bin" >> /home/hduser/.bashrc

```

1.  重新启动 shell 并格式化 Tachyon：

```scala
$ tachyon format
$ tachyon-start.sh local //you need to enter root password as RamFS needs to be formatted

```

Tachyon 的 web 界面是`http://hostname:19999`：

![如何操作...](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_01_13.jpg)

1.  运行示例程序，查看 Tachyon 是否正常运行：

```scala
$ tachyon runTest Basic CACHE_THROUGH

```

![如何操作...](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/3056_01_14.jpg)

1.  您可以随时通过运行以下命令停止 Tachyon：

```scala
$ tachyon-stop.sh

```

1.  在 Tachyon 上运行 Spark：

```scala
$ spark-shell
scala> val words = sc.textFile("tachyon://localhost:19998/words")
scala> words.count
scala> words.saveAsTextFile("tachyon://localhost:19998/w2")
scala> val person = sc.textFile("hdfs://localhost:9000/user/hduser/person")
scala> import org.apache.spark.api.java._
scala> person.persist(StorageLevels.OFF_HEAP)

```

## 另请参阅

+   点击链接[`www.cs.berkeley.edu/~haoyuan/papers/2013_ladis_tachyon.pdf`](http://www.cs.berkeley.edu/~haoyuan/papers/2013_ladis_tachyon.pdf)了解 Tachyon 的起源

+   点击链接[`www.tachyonnexus.com`](http://www.tachyonnexus.com)


# 第二章：使用 Spark 开发应用程序

在本章中，我们将涵盖：

+   探索 Spark shell

+   在 Eclipse 中使用 Maven 开发 Spark 应用程序

+   在 Eclipse 中使用 SBT 开发 Spark 应用程序

+   在 Intellij IDEA 中使用 Maven 开发 Spark 应用程序

+   在 Intellij IDEA 中使用 SBT 开发 Spark 应用程序

# 介绍

要创建生产质量的 Spark 作业/应用程序，使用各种**集成开发环境**（**IDEs**）和构建工具非常有用。本章将涵盖各种 IDE 和构建工具。

# 探索 Spark shell

Spark 自带一个 REPL shell，它是 Scala shell 的包装器。尽管 Spark shell 看起来像是用于简单事务的命令行，但实际上也可以使用它执行许多复杂的查询。本章探讨了可以开发 Spark 应用程序的不同开发环境。

## 如何做...

使用 Spark shell，Hadoop MapReduce 的单词计数变得非常简单。在这个示例中，我们将创建一个简单的一行文本文件，将其上传到**Hadoop 分布式文件系统**（**HDFS**），并使用 Spark 来计算单词的出现次数。让我们看看如何做到：

1.  使用以下命令创建`words`目录：

```scala
$ mkdir words

```

1.  进入`words`目录：

```scala
$ cd words

```

1.  创建一个`sh.txt`文本文件，并在其中输入`"to be or not to be"`：

```scala
$ echo "to be or not to be" > sh.txt

```

1.  启动 Spark shell：

```scala
$ spark-shell

```

1.  将`words`目录加载为 RDD：

```scala
Scala> val words = sc.textFile("hdfs://localhost:9000/user/hduser/words")

```

1.  统计行数（结果：1）：

```scala
Scala> words.count

```

1.  将行（或行）分成多个单词：

```scala
Scala> val wordsFlatMap = words.flatMap(_.split("\\W+"))

```

1.  将`word`转换为（word,1）—即，将`1`作为每个`word`出现的值作为键输出：

```scala
Scala> val wordsMap = wordsFlatMap.map( w => (w,1))

```

1.  使用`reduceByKey`方法将每个单词的出现次数作为键相加（该函数在两个连续值上运行，由`a`和`b`表示）：

```scala
Scala> val wordCount = wordsMap.reduceByKey( (a,b) => (a+b))

```

1.  对结果进行排序：

```scala
Scala> val wordCountSorted = wordCount.sortByKey(true)

```

1.  打印 RDD：

```scala
Scala> wordCountSorted.collect.foreach(println)

```

1.  将所有前述操作合并为一步如下：

```scala
Scala> sc.textFile("hdfs://localhost:9000/user/hduser/words"). flatMap(_.split("\\W+")).map( w => (w,1)). reduceByKey( (a,b) => (a+b)).sortByKey(true).collect.foreach(println)

```

这给我们以下输出：

```scala
(or,1)
(to,2)
(not,1)
(be,2)

```

现在您了解了基础知识，可以加载大量文本（例如故事）到 HDFS 中，看看魔法。

如果文件以压缩格式存在，可以直接在 HDFS 中加载它们。Hadoop 和 Spark 都有用于解压缩的编解码器，它们根据文件扩展名使用。

当`wordsFlatMap`转换为`wordsMap` RDD 时，发生了隐式转换。这将 RDD 转换为`PairRDD`。这是一个隐式转换，不需要做任何事情。如果您在 Scala 代码中执行此操作，请添加以下`import`语句：

```scala
import org.apache.spark.SparkContext._
```

# 在 Eclipse 中使用 Maven 开发 Spark 应用程序

多年来，Maven 作为构建工具已经成为事实上的标准。如果我们深入了解 Maven 所带来的承诺，这并不令人意外。Maven 有两个主要特点，它们是：

+   **约定优于配置**：在 Maven 之前的构建工具中，开发人员可以自由选择放置源文件、测试文件、编译文件等的位置。Maven 取消了这种自由。有了这种自由，所有关于位置的混乱也消失了。在 Maven 中，每样东西都有一个特定的目录结构。以下表格显示了一些最常见的位置：

| `/src/main/scala` | Scala 中的源代码 |
| --- | --- |
| `/src/main/java` | Java 中的源代码 |
| `/src/main/resources` | 源代码使用的资源，如配置文件 |
| `/src/test/scala` | Scala 中的测试代码 |
| `/src/test/java` | Java 中的测试代码 |
| `/src/test/resources` | 测试代码使用的资源，如配置文件 |

+   **声明式依赖管理**：在 Maven 中，每个库都是通过以下三个坐标来定义的：

| `groupId` | 逻辑上将类库分组的一种方式，类似于 Java/Scala 中的包，至少必须是您拥有的域名，例如`org.apache.spark` |
| --- | --- |
| `artifactId` | 项目和 JAR 的名称 |
| `version` | 标准版本号 |

在`pom.xml`中（告诉 Maven 有关项目的所有信息的配置文件）中，依赖关系以这三个坐标的形式声明。无需在互联网上搜索、下载、解压缩和复制库。您只需要提供所需的依赖 JAR 的三个坐标，Maven 将为您完成其余工作。以下是使用 JUnit 依赖项的示例：

```scala
<dependency>
  <groupId>junit</groupId>
  <artifactId>junit</artifactId>
  <version>4.12</version>
</dependency>
```

这使得包括传递依赖关系在内的依赖管理变得非常容易。在 Maven 之后出现的构建工具，如 SBT 和 Gradle，也遵循这两个规则，并在其他方面提供增强功能。

## 准备工作

从这个食谱开始，本章假设您已经安装了 Eclipse。请访问[`www.eclipse.org`](http://www.eclipse.org)获取详细信息。

## 如何做...

让我们看看如何为 Eclipse 安装 Maven 插件：

1.  打开 Eclipse，导航到**帮助** | **安装新软件**。

1.  单击“工作区”下拉菜单。

1.  选择<eclipse 版本>更新站点。

1.  单击**协作工具**。

1.  检查 Maven 与 Eclipse 的集成，如下截图所示：![如何做...](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/B03056_02_01.jpg)

1.  单击**下一步**，然后单击**完成**。

重新启动 Eclipse 后，将会出现提示安装 Maven。

现在让我们看看如何为 Eclipse 安装 Scala 插件：

1.  打开 Eclipse，导航到**帮助** | **安装新软件**。

1.  单击“工作区”下拉菜单。

1.  选择<eclipse 版本>更新站点。

1.  键入`http://download.scala-ide.org/sdk/helium/e38/scala210/stable/site`。

1.  按下*Enter*。

1.  选择**Scala IDE for Eclipse**：![如何做...](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/B03056_02_02.jpg)

1.  单击**下一步**，然后单击**完成**。重新启动 Eclipse 后，将会出现提示安装 Scala。

1.  导航到**窗口** | **打开透视图** | **Scala**。

Eclipse 现在已准备好用于 Scala 开发！

# 在 Eclipse 中使用 SBT 开发 Spark 应用程序

**Simple Build Tool**（**SBT**）是专为基于 Scala 的开发而制作的构建工具。SBT 遵循 Maven 的命名约定和声明性依赖管理。

SBT 相对于 Maven 提供了以下增强功能：

+   依赖关系以`build.sbt`文件中的键值对的形式提供，而不是 Maven 中的`pom.xml`

+   它提供了一个 shell，非常方便执行构建操作

+   对于没有依赖关系的简单项目，甚至不需要`build.sbt`文件

在`build.sbt`中，第一行是项目定义：

```scala
lazy val root = (project in file("."))
```

每个项目都有一个不可变的键值对映射。这个映射通过 SBT 中的设置进行更改，如下所示：

```scala
lazy val root = (project in file("."))
  settings(
    name := "wordcount"
  )
```

设置的每次更改都会导致一个新的映射，因为它是一个不可变的映射。

## 如何做...

以下是如何添加`sbteclipse`插件的方法：

1.  将此添加到全局插件文件中：

```scala
$ mkdir /home/hduser/.sbt/0.13/plugins
$ echo addSbtPlugin("com.typesafe.sbteclipse" % "sbteclipse-plugin" % "2.5.0" )  > /home/hduser/.sbt/0.12/plugins/plugin.sbt

```

或者，您可以将以下内容添加到您的项目中：

```scala
$ cd <project-home>
$ echo addSbtPlugin("com.typesafe.sbteclipse" % "sbteclipse-plugin" % "2.5.0" )  > plugin.sbt

```

1.  不带任何参数启动`sbt` shell：

```scala
$sbt

```

1.  键入`eclipse`，它将创建一个准备好的 Eclipse 项目：

```scala
$ eclipse

```

1.  现在，您可以导航到**文件** | **导入** | **将现有项目导入工作区**，将项目加载到 Eclipse 中。

现在，您可以使用 Eclipse 和 SBT 在 Scala 中开发 Spark 应用程序。

# 在 IntelliJ IDEA 中使用 Maven 开发 Spark 应用程序

IntelliJ IDEA 自带了对 Maven 的支持。我们将看到如何在本食谱中创建一个新的 Maven 项目。

## 如何做...

在 IntelliJ IDEA 上使用 Maven 开发 Spark 应用程序，请执行以下步骤：

1.  在新项目窗口中选择**Maven**，然后单击**下一步**：![如何做...](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/B03056_02_03.jpg)

1.  输入项目的三个维度：![如何做...](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/B03056_02_04.jpg)

1.  输入项目的名称和位置：![如何做...](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/B03056_02_05.jpg)

1.  单击**完成**，Maven 项目已准备就绪。

# 在 IntelliJ IDEA 中使用 SBT 开发 Spark 应用程序

在 Eclipse 成名之前，IntelliJ IDEA 被认为是最优秀的 IDE 之一。IDEA 至今仍然保持着它以前的荣耀，很多开发者喜爱 IDEA。IDEA 也有一个免费的社区版。IDEA 对 SBT 提供了原生支持，这使得它非常适合 SBT 和 Scala 开发。

## 如何做到...

执行以下步骤在 IntelliJ IDEA 上使用 SBT 开发 Spark 应用程序：

1.  添加`sbt-idea`插件。

1.  添加到全局插件文件中：

```scala
$mkdir /home/hduser/.sbt/0.13/plugins
$echo addSbtPlugin("com.github.mpeltone" % "sbt-idea" % "1.6.0" )  > /home/hduser/.sbt/0.12/plugins/plugin.sbt

```

或者，你也可以将其添加到你的项目中：

```scala
$cd <project-home>
$ echo addSbtPlugin("com.github.mpeltone" % "sbt-idea" % "1.6.0" ) > plugin.sbt

```

IDEA 已经准备好与 SBT 一起使用。

现在你可以使用 Scala 开发 Spark 代码，并使用 SBT 构建。


# 第三章：外部数据源

Spark 的一个优点是它提供了一个可以连接各种底层数据源的单一运行时。

在本章中，我们将连接到不同的数据源。本章分为以下几个示例：

+   从本地文件系统加载数据

+   从 HDFS 加载数据

+   使用自定义 InputFormat 从 HDFS 加载数据

+   从亚马逊 S3 加载数据

+   从 Apache Cassandra 加载数据

+   从关系数据库加载数据

# 介绍

Spark 为大数据提供了统一的运行时。HDFS，即 Hadoop 的文件系统，是 Spark 最常用的存储平台，因为它提供了成本效益的存储方式，可以在通用硬件上存储非结构化和半结构化数据。Spark 不仅限于 HDFS，还可以与任何 Hadoop 支持的存储一起使用。

Hadoop 支持的存储意味着可以与 Hadoop 的`InputFormat`和`OutputFormat`接口一起使用的存储格式。`InputFormat`负责从输入数据创建`InputSplits`，并将其进一步划分为记录。`OutputFormat`负责写入存储。

我们将从本地文件系统开始写入，然后转移到从 HDFS 加载数据。在*从 HDFS 加载数据*的示例中，我们将介绍最常见的文件格式：常规文本文件。在下一个示例中，我们将介绍如何在 Spark 中使用任何`InputFormat`接口来加载数据。我们还将探讨如何加载存储在亚马逊 S3 中的数据，这是一个领先的云存储平台。

我们将探索从 Apache Cassandra 加载数据，这是一个 NoSQL 数据库。最后，我们将探索从关系数据库加载数据。

# 从本地文件系统加载数据

尽管本地文件系统不适合存储大数据，因为磁盘大小限制和缺乏分布式特性，但从技术上讲，你可以使用本地文件系统在分布式系统中加载数据。但是你要访问的文件/目录必须在每个节点上都可用。

请注意，如果您计划使用此功能来加载辅助数据，这不是一个好主意。为了加载辅助数据，Spark 有一个广播变量功能，将在接下来的章节中讨论。

在这个示例中，我们将看看如何从本地文件系统中加载数据到 Spark 中。

## 如何做...

让我们从莎士比亚的"to be or not to be"的例子开始：

1.  使用以下命令创建`words`目录：

```scala
$ mkdir words

```

1.  进入`words`目录：

```scala
$ cd words

```

1.  创建`sh.txt`文本文件，并在其中输入`"to be or not to be"`：

```scala
$ echo "to be or not to be" > sh.txt

```

1.  启动 Spark shell：

```scala
$ spark-shell

```

1.  将`words`目录加载为 RDD：

```scala
scala> val words = sc.textFile("file:///home/hduser/words")

```

1.  计算行数：

```scala
scala> words.count

```

1.  将行（或行）分成多个单词：

```scala
scala> val wordsFlatMap = words.flatMap(_.split("\\W+"))

```

1.  将`word`转换为（word,1）—即，将`1`作为每个`word`的出现次数的值输出为键：

```scala
scala> val wordsMap = wordsFlatMap.map( w => (w,1))

```

1.  使用`reduceByKey`方法将每个单词的出现次数作为键添加（此函数一次处理两个连续的值，表示为`a`和`b`）：

```scala
scala> val wordCount = wordsMap.reduceByKey( (a,b) => (a+b))

```

1.  打印 RDD：

```scala
scala> wordCount.collect.foreach(println)

```

1.  在一个步骤中执行所有前面的操作如下：

```scala
scala> sc.textFile("file:///home/hduser/ words"). flatMap(_.split("\\W+")).map( w => (w,1)). reduceByKey( (a,b) => (a+b)).foreach(println)

```

这会产生以下输出：

![如何做...](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/B03056_03_01.jpg)

# 从 HDFS 加载数据

HDFS 是最广泛使用的大数据存储系统。HDFS 被广泛采用的原因之一是模式在读取时。这意味着在写入数据时，HDFS 不会对数据施加任何限制。任何类型的数据都受欢迎并且可以以原始格式存储。这个特性使其成为原始非结构化数据和半结构化数据的理想存储介质。

在读取数据方面，即使是非结构化数据也需要给予一些结构以理解。Hadoop 使用`InputFormat`来确定如何读取数据。Spark 完全支持 Hadoop 的`InputFormat`，因此任何 Hadoop 可以读取的内容也可以被 Spark 读取。

默认的`InputFormat`是`TextInputFormat`。`TextInputFormat`将行的字节偏移量作为键，行的内容作为值。Spark 使用`sc.textFile`方法使用`TextInputFormat`进行读取。它忽略字节偏移量并创建一个字符串的 RDD。

有时文件名本身包含有用的信息，例如时间序列数据。在这种情况下，您可能希望单独读取每个文件。`sc.wholeTextFiles`方法允许您这样做。它创建一个 RDD，其中文件名和路径（例如`hdfs://localhost:9000/user/hduser/words`）作为键，整个文件的内容作为值。

Spark 还支持使用 DataFrame 读取各种序列化和压缩友好的格式，如 Avro、Parquet 和 JSON。这些格式将在接下来的章节中介绍。

在本教程中，我们将学习如何从 HDFS 中的 Spark shell 加载数据。

## 如何做...

让我们进行单词计数，计算每个单词的出现次数。在本教程中，我们将从 HDFS 加载数据。

1.  使用以下命令创建`words`目录：

```scala
$ mkdir words

```

1.  更改目录到`words`：

```scala
$ cd words

```

1.  创建`sh.txt text`文件并在其中输入`"to be or not to be"`：

```scala
$ echo "to be or not to be" > sh.txt

```

1.  启动 Spark shell：

```scala
$ spark-shell

```

1.  将`words`目录加载为 RDD：

```scala
scala> val words = sc.textFile("hdfs://localhost:9000/user/hduser/words")

```

### 注意

`sc.textFile`方法还支持传递用于分区数的额外参数。默认情况下，Spark 为每个`InputSplit`类创建一个分区，这大致对应一个块。

您可以要求更多的分区。这对于计算密集型作业（如机器学习）非常有效。由于一个分区不能包含多个块，因此分区数不能少于块数。

1.  计算行数（结果将为`1`）：

```scala
scala> words.count

```

1.  将行（或行）分成多个单词：

```scala
scala> val wordsFlatMap = words.flatMap(_.split("\\W+"))

```

1.  将单词转换为(word,1)——也就是说，将`word`作为键的每次出现输出`1`作为值：

```scala
scala> val wordsMap = wordsFlatMap.map( w => (w,1))

```

1.  使用`reduceByKey`方法将每个单词的出现次数作为键相加（此函数一次处理两个连续的值，由`a`和`b`表示）：

```scala
scala> val wordCount = wordsMap.reduceByKey( (a,b) => (a+b))

```

1.  打印 RDD：

```scala
scala> wordCount.collect.foreach(println)

```

1.  在一步中执行所有前面的操作如下：

```scala
scala> sc.textFile("hdfs://localhost:9000/user/hduser/words"). flatMap(_.split("\\W+")).map( w => (w,1)). reduceByKey( (a,b) => (a+b)).foreach(println)

```

这将产生以下输出：

![如何做...](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/B03056_03_01.jpg)

## 还有更多...

有时我们需要一次访问整个文件。有时文件名包含有用的数据，比如时间序列。有时您需要将多行作为一个记录进行处理。`sparkContext.wholeTextFiles`在这里派上了用场。我们将查看来自 ftp://ftp.ncdc.noaa.gov/pub/data/noaa/的天气数据集。

顶层目录的样子如下：

![还有更多...](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/B03056_03_02.jpg)

查看特定年份目录，例如 1901 年，如下截图所示：

![还有更多...](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/B03056_03_03.jpg)

这里的数据被划分为每个文件名包含有用信息的方式，即 USAF-WBAN-year，其中 USAF 是美国空军站点编号，WBAN 是天气局陆军海军位置编号。

您还会注意到所有文件都以`.gz`扩展名压缩为 gzip。压缩是自动处理的，所以您只需要将数据上传到 HDFS。我们将在接下来的章节中回到这个数据集。

由于整个数据集并不大，因此也可以在伪分布式模式下上传到 HDFS 中：

1.  下载数据：

```scala
$ wget -r ftp://ftp.ncdc.noaa.gov/pub/data/noaa/

```

1.  在 HDFS 中加载天气数据：

```scala
$ hdfs dfs -put ftp.ncdc.noaa.gov/pub/data/noaa weather/

```

1.  启动 Spark shell：

```scala
$ spark-shell

```

1.  在 RDD 中加载 1901 年的天气数据：

```scala
scala> val weatherFileRDD = sc.wholeTextFiles("hdfs://localhost:9000/user/hduser/weather/1901")

```

1.  将天气缓存在 RDD 中，以便每次访问时不需要重新计算：

```scala
scala> val weatherRDD = weatherFileRDD.cache

```

### 注意

在 Spark 中，RDD 可以持久化在各种 StorageLevels 上。`rdd.cache`是`rdd.persist(MEMORY_ONLY)` StorageLevel 的简写。

1.  计算元素的数量：

```scala
scala> weatherRDD.count

```

1.  由于整个文件的内容被加载为一个元素，我们需要手动解释数据，因此让我们加载第一个元素：

```scala
scala> val firstElement = weatherRDD.first

```

1.  读取第一个 RDD 的值：

```scala
scala> val firstValue = firstElement._2

```

`firstElement`包含以(string, string)形式的元组。元组可以通过两种方式访问：

+   使用从`_1`开始的位置函数。

+   使用`productElement`方法，例如`tuple.productElement(0)`。这里的索引从`0`开始，就像大多数其他方法一样。

1.  通过行来分割`firstValue`：

```scala
scala> val firstVals = firstValue.split("\\n")

```

1.  计算`firstVals`中的元素数量：

```scala
scala> firstVals.size

```

1.  天气数据的模式非常丰富，文本的位置作为分隔符。您可以在国家气象局网站上获取有关模式的更多信息。让我们获取风速，它来自 66-69 节（以米/秒为单位）：

```scala
scala> val windSpeed = firstVals.map(line => line.substring(65,69)

```

# 使用自定义 InputFormat 从 HDFS 加载数据

有时您需要以特定格式加载数据，而`TextInputFormat`不适合。Spark 为此提供了两种方法：

+   `sparkContext.hadoopFile`：支持旧的 MapReduce API

+   `sparkContext.newAPIHadoopFile`：支持新的 MapReduce API

这两种方法支持所有 Hadoop 内置的 InputFormats 接口以及任何自定义`InputFormat`。

## 如何操作...

我们将以键值格式加载文本数据，并使用`KeyValueTextInputFormat`将其加载到 Spark 中：

1.  使用以下命令创建`currency`目录：

```scala
$ mkdir currency
```

1.  将当前目录更改为`currency`：

```scala
$ cd currency
```

1.  创建`na.txt`文本文件，并以制表符分隔的键值格式输入货币值（键：国家，值：货币）：

```scala
$ vi na.txt
United States of America        US Dollar
Canada  Canadian Dollar
Mexico  Peso

```

您可以为每个大陆创建更多的文件。

1.  将`currency`文件夹上传到 HDFS：

```scala
$ hdfs dfs -put currency /user/hduser/currency

```

1.  启动 Spark shell：

```scala
$ spark-shell

```

1.  导入语句：

```scala
scala> import org.apache.hadoop.io.Text
scala> import org.apache.hadoop.mapreduce.lib.input.KeyValueTextInputFormat

```

1.  将`currency`目录加载为 RDD：

```scala
val currencyFile = sc.newAPIHadoopFile("hdfs://localhost:9000/user/hduser/currency",classOf[KeyValueTextInputFormat],classOf[Text],classOf[Text])

```

1.  将其从（Text，Text）元组转换为（String，String）元组：

```scala
val currencyRDD = currencyFile.map( t => (t._1.toString,t._2.toString))

```

1.  计算 RDD 中的元素数量：

```scala
scala> currencyRDD.count

```

1.  打印值：

```scala
scala> currencyRDD.collect.foreach(println)

```

![如何操作...](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/B03056_03_04.jpg)

### 注意

您可以使用此方法加载任何 Hadoop 支持的`InputFormat`接口的数据。

# 从 Amazon S3 加载数据

亚马逊**简单存储服务**（**S3**）为开发人员和 IT 团队提供了一个安全、耐用和可扩展的存储平台。Amazon S3 的最大优势在于没有预先的 IT 投资，公司可以根据需要构建容量（只需点击一个按钮）。

尽管 Amazon S3 可以与任何计算平台一起使用，但它与亚马逊的云服务（如亚马逊**弹性计算云**（**EC2**）和亚马逊**弹性块存储**（**EBS**））结合得非常好。因此，使用**Amazon Web Services**（**AWS**）的公司可能已经在 Amazon S3 上存储了大量数据。

这很好地说明了从 Amazon S3 中加载数据到 Spark 的情况，这正是这个教程要讲的。

## 如何操作...

让我们从 AWS 门户开始：

1.  前往[`aws.amazon.com`](http://aws.amazon.com)并使用您的用户名和密码登录。

1.  登录后，导航至**存储和内容交付** | **S3** | **创建存储桶**：![如何操作...](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/B03056_03_05.jpg)

1.  输入存储桶名称，例如`com.infoobjects.wordcount`。请确保输入唯一的存储桶名称（全球没有两个 S3 存储桶可以具有相同的名称）。

1.  选择**区域**，单击**创建**，然后单击您创建的存储桶名称，您将看到以下屏幕：![如何操作...](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/B03056_03_06.jpg)

1.  单击**创建文件夹**，输入`words`作为文件夹名称。

1.  在本地文件系统上创建`sh.txt`文本文件：

```scala
$ echo "to be or not to be" > sh.txt

```

1.  导航至**Words** | **上传** | **添加文件**，并从对话框中选择`sh.txt`，如下图所示：![如何操作...](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/B03056_03_07.jpg)

1.  单击**开始上传**。

1.  选择**sh.txt**，单击**属性**，它将显示文件的详细信息：![如何操作...](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/B03056_03_08.jpg)

1.  将`AWS_ACCESS_KEY`和`AWS_SECRET_ACCESS_KEY`设置为环境变量。

1.  打开 Spark shell 并从`s3`中的`words`目录加载`words` RDD：

```scala
scala>  val words = sc.textFile("s3n://com.infoobjects.wordcount/words")

```

现在 RDD 已加载，您可以继续对 RDD 进行常规转换和操作。

### 注意

有时会混淆`s3://`和`s3n://`。`s3n://`表示位于 S3 存储桶中的常规文件，但可以被外部世界读取和写入。该文件系统对文件大小有 5GB 的限制。

`s3://`表示位于 S3 存储桶中的 HDFS 文件。这是一个基于块的文件系统。该文件系统要求您为此文件系统专门分配一个存储桶。在此系统中，文件大小没有限制。

# 从 Apache Cassandra 加载数据

Apache Cassandra 是一个无主环集群结构的 NoSQL 数据库。虽然 HDFS 非常适合流数据访问，但对于随机访问效果不佳。例如，当你的平均文件大小为 100MB 并且想要读取整个文件时，HDFS 会很好地工作。但是，如果你经常访问文件中的第 n 行或其他部分作为记录，HDFS 将会太慢。

传统上，关系数据库提供了解决方案，提供低延迟、随机访问，但它们在处理大数据方面效果不佳。Cassandra 等 NoSQL 数据库通过在商品服务器上提供分布式架构中的关系数据库类型访问来填补这一空白。

在本教程中，我们将从 Cassandra 加载数据作为 Spark RDD。为了实现这一点，Cassandra 背后的公司 Datastax 贡献了`spark-cassandra-connector`。这个连接器让你将 Cassandra 表加载为 Spark RDD，将 Spark RDD 写回 Cassandra，并执行 CQL 查询。

## 如何做...

执行以下步骤从 Cassandra 加载数据：

1.  使用 CQL shell 在 Cassandra 中创建一个名为`people`的 keyspace：

```scala
cqlsh> CREATE KEYSPACE people WITH replication = {'class': 'SimpleStrategy', 'replication_factor': 1 };

```

1.  在较新版本的 Cassandra 中创建一个列族（从 CQL 3.0 开始，也可以称为**表**）`person`：

```scala
cqlsh> create columnfamily person(id int primary key,first_name varchar,last_name varchar);

```

1.  在列族中插入几条记录：

```scala
cqlsh> insert into person(id,first_name,last_name) values(1,'Barack','Obama');
cqlsh> insert into person(id,first_name,last_name) values(2,'Joe','Smith');

```

1.  将 Cassandra 连接器依赖项添加到 SBT：

```scala
"com.datastax.spark" %% "spark-cassandra-connector" % 1.2.0

```

1.  您还可以将 Cassandra 依赖项添加到 Maven 中：

```scala
<dependency>
  <groupId>com.datastax.spark</groupId>
  <artifactId>spark-cassandra-connector_2.10</artifactId>
  <version>1.2.0</version>
</dependency>
```

或者，您也可以直接下载`spark-cassandra-connector` JAR 并在 Spark shell 中使用：

```scala
$ wget http://central.maven.org/maven2/com/datastax/spark/spark-cassandra-connector_2.10/1.1.0/spark-cassandra-connector_2.10-1.2.0.jar

```

### 注意

如果您想要构建带有所有依赖项的`uber` JAR，请参考*更多内容...*部分。

1.  现在启动 Spark shell。

1.  在 Spark shell 中设置`spark.cassandra.connection.host`属性：

```scala
scala> sc.getConf.set("spark.cassandra.connection.host", "localhost")

```

1.  导入特定于 Cassandra 的库：

```scala
scala> import com.datastax.spark.connector._

```

1.  将`person`列族加载为 RDD：

```scala
scala> val personRDD = sc.cassandraTable("people","person")

```

1.  计算 RDD 中的记录数：

```scala
scala> personRDD.count

```

1.  打印 RDD 中的数据：

```scala
scala> personRDD.collect.foreach(println)

```

1.  检索第一行：

```scala
scala> val firstRow = personRDD.first

```

1.  获取列名：

```scala
scala> firstRow.columnNames

```

1.  Cassandra 也可以通过 Spark SQL 访问。它在`SQLContext`周围有一个名为`CassandraSQLContext`的包装器；让我们加载它：

```scala
scala> val cc = new org.apache.spark.sql.cassandra.CassandraSQLContext(sc)

```

1.  将`person`数据加载为`SchemaRDD`：

```scala
scala> val p = cc.sql("select * from people.person")

```

1.  检索`person`数据：

```scala
scala> p.collect.foreach(println)

```

## 更多内容...

Spark Cassandra 的连接器库有很多依赖项。连接器本身和它的一些依赖项是 Spark 的第三方，不作为 Spark 安装的一部分提供。

这些依赖项需要在驱动程序和执行器运行时提供。一种方法是捆绑所有传递依赖项，但这是一个费力且容易出错的过程。推荐的方法是将所有依赖项与连接器库一起捆绑。这将产生一个 fat JAR，通常称为`uber` JAR。

SBT 提供了`sb-assembly`插件，可以很容易地创建`uber` JAR。以下是创建`spark-cassandra-connector`的`uber` JAR 的步骤。这些步骤足够通用，可以用来创建任何`uber` JAR：

1.  创建一个名为`uber`的文件夹：

```scala
$ mkdir uber

```

1.  将目录更改为`uber`：

```scala
$ cd uber

```

1.  打开 SBT 提示符：

```scala
$ sbt

```

1.  给这个项目命名为`sc-uber`：

```scala
> set name := "sc-uber"

```

1.  保存会话：

```scala
> session save

```

1.  退出会话：

```scala
> exit

```

这将在`uber`文件夹中创建`build.sbt`，`project`和`target`文件夹，如下面的屏幕截图所示：

![更多内容...](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/B03056_03_09.jpg)

1.  在`build.sbt`的末尾添加`spark-cassandra-driver`依赖项，留下一个空行，如下面的屏幕截图所示：

```scala
$ vi buid.sbt

```

![更多内容...](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/B03056_03_10.jpg)

1.  我们将使用`MergeStrategy.first`作为默认选项。此外，有一些文件，如`manifest.mf`，每个 JAR 都会捆绑用于元数据，我们可以简单地丢弃它们。我们将使用`MergeStrategy.discard`。以下是带有`assemblyMergeStrategy`的`build.sbt`的屏幕截图：![更多内容...](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-cb/img/B03056_03_11.jpg)

1.  现在在`project`文件夹中创建`plugins.sbt`，并为`sbt-assembly`插件输入以下内容：

```scala
addSbtPlugin("com.eed3si9n" % "sbt-assembly" % "0.12.0")

```

1.  我们现在准备构建（装配）一个 JAR：

```scala
$ sbt assembly

```

`uber` JAR 现在创建在`target/scala-2.10/sc-uber-assembly-0.1-SNAPSHOT.jar`中。

1.  将其复制到一个适当的位置，您可以在那里保存所有第三方 JAR 文件，例如`/home/hduser/thirdparty`，并将其重命名为更简单的名称（除非您喜欢更长的名称）：

```scala
$ mv thirdparty/sc-uber-assembly-0.1-SNAPSHOT.jar  thirdparty/sc-uber.jar

```

1.  使用`--jars`加载`uber` JAR 启动 Spark shell：

```scala
$ spark-shell --jars thirdparty/sc-uber.jar

```

1.  要将 Scala 代码提交到集群，可以使用相同的 JARS 选项调用`spark-submit`：

```scala
$ spark-submit --jars thirdparty/sc-uber.jar

```

### sbt-assembly 中的合并策略

如果多个 JAR 具有具有相同名称和相同相对路径的文件，则`sbt-assembly`插件的默认合并策略是验证所有文件的内容是否相同，否则会出错。此策略称为`MergeStrategy.deduplicate`。

sbt-assembly 插件中可用的合并策略如下：

| 策略名称 | 描述 |
| --- | --- |
| `MergeStrategy.deduplicate` | 默认策略 |
| `MergeStrategy.first` | 根据类路径选择第一个文件 |
| `MergeStrategy.last` | 根据类路径选择最后一个文件 |
| `MergeStrategy.singleOrError` | 出错（不期望合并冲突） |
| `MergeStrategy.concat` | 将所有匹配的文件连接在一起 |
| `MergeStrategy.filterDistinctLines` | 连接并排除重复行 |
| `MergeStrategy.rename` | 重命名文件 |

# 从关系数据库加载数据

Spark 需要查询的许多重要数据存储在关系数据库中。JdbcRDD 是一个 Spark 功能，允许将关系表加载为 RDD。本教程将解释如何使用 JdbcRDD。

下一章将介绍的 Spark SQL 包括一个用于 JDBC 的数据源。这应该优先于当前的教程，因为结果将作为 DataFrame（将在下一章中介绍）返回，可以很容易地由 Spark SQL 处理，并与其他数据源连接。

## 准备工作

请确保 JDBC 驱动程序 JAR 在客户端节点和所有执行程序将运行的所有从节点上可见。

## 如何做…

执行以下步骤从关系数据库中加载数据：

1.  使用以下 DDL 在 MySQL 中创建名为`person`的表：

```scala
CREATE TABLE 'person' (
  'person_id' int(11) NOT NULL AUTO_INCREMENT,
  'first_name' varchar(30) DEFAULT NULL,
  'last_name' varchar(30) DEFAULT NULL,
  'gender' char(1) DEFAULT NULL,
  PRIMARY KEY ('person_id');
)
```

1.  插入一些数据：

```scala
Insert into person values('Barack','Obama','M');
Insert into person values('Bill','Clinton','M');
Insert into person values('Hillary','Clinton','F');
```

1.  从[`dev.mysql.com/downloads/connector/j/`](http://dev.mysql.com/downloads/connector/j/)下载`mysql-connector-java-x.x.xx-bin.jar`。

1.  使 MySQL 驱动程序可用于 Spark shell 并启动它：

```scala
$ spark-shell --jars /path-to-mysql-jar/mysql-connector-java-5.1.29-bin.jar

```

### 注意

请注意，`path-to-mysql-jar`不是实际的路径名。您应该使用实际的路径名。

1.  创建用户名、密码和 JDBC URL 的变量：

```scala
scala> val url="jdbc:mysql://localhost:3306/hadoopdb"
scala> val username = "hduser"
scala> val password = "******"

```

1.  导入 JdbcRDD：

```scala
scala> import org.apache.spark.rdd.JdbcRDD

```

1.  导入与 JDBC 相关的类：

```scala
scala> import java.sql.{Connection, DriverManager, ResultSet}

```

1.  创建 JDBC 驱动程序的实例：

```scala
scala> Class.forName("com.mysql.jdbc.Driver").newInstance

```

1.  加载 JdbcRDD：

```scala
scala> val myRDD = new JdbcRDD( sc, () =>
DriverManager.getConnection(url,username,password) ,
"select first_name,last_name,gender from person limit ?, ?",
1, 5, 2, r => r.getString("last_name") + ", " + r.getString("first_name"))

```

1.  现在查询结果：

```scala
scala> myRDD.count
scala> myRDD.foreach(println)

```

1.  将 RDD 保存到 HDFS：

```scala
scala> myRDD.saveAsTextFile("hdfs://localhost:9000/user/hduser/person")

```

## 工作原理… 

JdbcRDD 是一个在 JDBC 连接上执行 SQL 查询并检索结果的 RDD。以下是一个 JdbcRDD 构造函数：

```scala
JdbcRDD( SparkContext, getConnection: () => Connection,
sql: String, lowerBound: Long, upperBound: Long,
numPartitions: Int,  mapRow: (ResultSet) => T =
 JdbcRDD.resultSetToObjectArray)

```

两个?是 JdbcRDD 内部准备语句的绑定变量。第一个?是偏移量（下限），也就是说，我们应该从哪一行开始计算，第二个?是限制（上限），也就是说，我们应该读取多少行。

JdbcRDD 是一种直接从关系数据库中以临时基础加载数据到 Spark 的好方法。如果您想要从 RDBMS 中批量加载数据，还有其他更好的方法，例如，Apache Sqoop 是一个强大的工具，可以将数据从关系数据库导入到 HDFS，并从 HDFS 导出数据。
