# CouchDB 和 PHP Web 开发初学者指南（一）

> 原文：[`zh.annas-archive.org/md5/175c6f9b2383dfb7631db24032548544`](https://zh.annas-archive.org/md5/175c6f9b2383dfb7631db24032548544)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

PHP 和 CouchDB Web 开发将教您结合 CouchDB 和 PHP 的基础知识，从构思到部署创建一个完整的应用程序。本书将指导您开发一个基本的社交网络，并引导您避免与 NoSQL 数据库经常相关的一些常见问题。

# 这本书涵盖了什么

第一章，“CouchDB 简介”，快速定义了 NoSQL 和 CouchDB 的概述。

第二章，“设置您的开发环境”，为使用 PHP 和 CouchDB 开发应用程序的计算机进行设置。

第三章，“开始使用 CouchDB 和 Futon”，定义了 CouchDB 文档，并展示了如何从命令行和 Futon（CouchDB 内置的管理实用程序）中管理它们。

第四章，“启动您的应用程序”，创建一个简单的 PHP 框架来容纳您的应用程序，并将此代码发布到 GitHub。

第五章，“将您的应用程序连接到 CouchDB”，使用各种方法将您的应用程序连接到 CouchDB，并最终为您的应用程序选择合适的解决方案。

第六章，“建模用户”，在您的应用程序中创建用户，并处理使用 CouchDB 进行文档创建和身份验证。

第七章，“用户配置文件和建模帖子”，使用 Bootstrap 完善您的用户配置文件，并将内容发布到 CouchDB。

第八章，“使用设计文档进行视图和验证”，探索了 CouchDB 专门使用设计文档来提高应用程序质量。

第九章，“为您的应用程序添加花里胡哨的东西”，利用现有工具简化和改进您的应用程序。

第十章，“部署您的应用程序”，向世界展示您的应用程序，并教您如何使用各种云服务启动应用程序和数据库。

*额外章节*，“复制您的数据”，了解如何使用 CouchDB 的复制系统来扩展您的应用程序。

您可以从[`www.packtpub.com/sites/default/files/downloads/Replicating_your_Data.pdf`](http://www.packtpub.com/sites/default/files/downloads/Replicating_your_Data.pdf)下载*额外章节*。

# 您需要为本书做些什么

您需要一台安装了 Mac OSX 的现代计算机。第一章，“CouchDB 简介”，将为 Linux 和 Windows 机器提供设置说明，并且本书中编写的代码将在任何机器上运行。但是，本书中使用的大多数命令行语句和应用程序都是特定于 Mac OSX 的。

# 这本书是为谁准备的

这本书适用于初学者和中级 PHP 开发人员，他们有兴趣在项目中使用 CouchDB 开发。高级 PHP 开发人员将欣赏 PHP 架构的熟悉性，并可以轻松学习如何将 CouchDB 纳入其现有的开发经验中。

# 约定

在本书中，您会经常看到几个标题。

为了清晰地说明如何完成某个过程或任务，我们使用：

# 行动时间 - 标题

1.  行动 1

1.  行动 2

1.  行动 3

指示通常需要一些额外的解释，以便它们有意义，因此它们后面跟着：

## 刚刚发生了什么？

这个标题解释了您刚刚完成的任务或指令的工作原理。

您还会在本书中找到其他一些学习辅助工具，包括：

## 小测验 - 标题

这些是简短的多项选择题，旨在帮助您测试自己的理解。

## 尝试一下英雄 — 标题

这些设置了实际的挑战，并为您提供了尝试所学内容的想法。

你还会发现一些文本样式，用于区分不同类型的信息。以下是一些样式的示例，以及它们的含义解释。

文本中的代码单词显示如下：“很难为 Linux 标准化`install`方法，因为有许多不同的风味和配置。”

代码块设置如下：

```php
<Directory />
Options FollowSymLinks
AllowOverride None
Order deny,allow
Allow from all
</Directory>

```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目会以粗体显示：

```php
<Directory />
Options FollowSymLinks
**AllowOverride All** 
Order deny,allow
Allow from all
</Directory>

```

任何命令行输入或输出都是这样写的：

```php
**sudo apt-get install php5 php5-dev libapache2-mod-php5 php5-curl php5-mcrypt** 

```

**新术语**和**重要单词**以粗体显示。例如，屏幕上看到的单词，如菜单或对话框中的单词，会以这种方式出现在文本中：*“通过打开**终端**开始”*。

### 注意

警告或重要提示会以这样的框出现。

### 提示

提示和技巧会以这种方式出现。


# 第一章：CouchDB 简介

> 欢迎来到 CouchDB 和 PHP Web 开发初学者指南。在这本书中，我们将学习使用 CouchDB 和 PHP 构建一个简单但功能强大的网站的方方面面。为了让你理解为什么我们在 CouchDB 中做某些事情，你首先需要了解 NoSQL 数据库的历史，并了解 CouchDB 在数据库历史中的地位是非常重要的。

在本章中，我们将：

+   简要介绍数据库的历史及其在技术中的地位

+   谈论数据库是如何演变成 NoSQL 概念的

+   通过理解 NoSQL 数据库的不同分类、CAP 定理及其避免 ACID 模型来定义 NoSQL 数据库

+   查看 CouchDB 的历史及其主要贡献者

+   谈论 CouchDB 的特殊之处

让我们首先看看数据库的演变以及 NoSQL 是如何出现的。

# NoSQL 数据库的演变

在 20 世纪 60 年代初，术语“数据库”被引入世界，作为信息系统背后的一个简单层。将应用程序与数据分离的简单概念是新颖而令人兴奋的，它为应用程序提供了更加强大的可能性。在这一点上，数据库首先存在于基于磁带的设备上，但很快就变得更加可用，作为系统直接访问磁盘上的存储。

在 1970 年，埃德加·科德提出了一种更有效的存储数据的方式——关系模型。这个模型也将使用 SQL 来允许应用程序找到其表中存储的数据。这个关系模型几乎与我们今天所知的传统关系数据库相同。虽然这个模型被广泛接受，但直到 1980 年代中期才有硬件能够有效地使用它。到了 1990 年，硬件终于赶上了，关系模型成为了存储数据的主要方法。

就像在任何技术领域一样，与关系数据库管理系统（RDBMS）竞争出现了。一些流行的 RDMBS 系统的例子包括 Oracle、Microsoft SQL Server、MySQL 和 PostgreSQL。

随着我们走过 2000 年，应用程序开始通过更复杂的应用程序产生大量的数据。社交网络进入了舞台。公司希望理解可用的大量数据。这种转变引发了关于关系模型似乎无法处理的数据结构、可扩展性和数据可用性的严重关切。面对如何管理这么大量不断变化的数据的不确定性，NoSQL 这个术语出现了。

术语“NoSQL”并不是“不使用 SQL”的缩写；它实际上代表“不仅仅是 SQL”。NoSQL 数据库是一组持久性解决方案，不遵循关系模型，也不使用 SQL 进行查询。除此之外，NoSQL 并不是为了取代关系数据库而引入的，而是为了补充关系数据库的不足之处。

## 什么使 NoSQL 不同

除了 NoSQL 数据库不使用 SQL 来查询数据之外，还有一些关键特征。为了理解这些特征，我们需要涵盖大量的术语和定义。重要的不是你要记住或记住这里的一切，而是你要知道究竟是什么构成了 NoSQL 数据库。

使 NoSQL 数据库与众不同的第一件事是它们的数据结构。有多种不同的方式可以对 NoSQL 数据库进行分类。

### NoSQL 数据库的分类

NoSQL 数据库（在大多数情况下）可以分为四种主要的数据结构：

+   键值存储：它们使用唯一的键和值保存数据。它们的简单性使它们能够非常快速地扩展到巨大的规模。

+   列存储：它们类似于关系数据库，但是不是存储记录，而是将一列中的所有值一起存储在流中。

+   **文档存储：** 它们保存数据而无需在模式中进行结构化，其中包含自包含对象内的键值对桶。这种数据结构让人想起 PHP 中的关联数组。这就是 CouchDB 所在的领域。我们将在第三章中深入探讨这个主题，*开始使用 CouchDB 和 Futon*。

+   **图数据库：** 它们以灵活的图模型存储数据，其中包含每个对象的节点。节点具有属性和与其他节点的关系。

我们不会深入讨论每种数据库的示例，但重要的是要看看现有的不同选项。通过在这个层面上查看数据库，我们可以相对容易地看到（一般来说）数据将如何按规模和复杂性进行扩展，通过查看以下屏幕截图：

![NoSQL 数据库的分类](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/couchdb-php-webdev-bgd/img/3586_01_005.jpg)

如果你看一下这个图表，你会看到我放置��一个**典型的关系数据库**和一个粗糙的性能线。这条性能线给出了一个简单的想法，即数据库可能如何按规模和复杂性进行扩展。NoSQL 数据库在数据规模和复杂性方面表现得如此出色是如何可能的呢？

在大多数情况下，NoSQL 数据库是可扩展的，因为它们依赖于分布式系统并忽略了 ACID 模型。让我们通过分布式系统讨论我们获得了什么，以及我们放弃了什么，然后定义 ACID 模型。

谈到任何分布式系统（不仅仅是存储或数据库），都有一个概念定义了你可以做什么的限制。这就是所谓的 CAP 定理。

### CAP 定理

*Eric Brewer*在 2000 年引入了 CAP 定理。它指出在任何分布式环境中，不可能提供三个保证。

+   **一致性：** 系统中的所有服务器将具有相同的数据。因此，无论用户与分布式系统中的哪个节点交谈，他们都将获得最新的数据。

+   **可用性：** 所有服务器将始终返回数据。

+   **分区容错性：** 即使单个服务器失败或无法访问，系统仍将作为一个整体运行。

通过观察这些选择，你可以知道肯定希望这三个东西都能得到保证，但从理论上讲是不可能的。在现实世界中，每个 NoSQL 数据库选择了三个选项中的两个，并通常开发了某种过程来减轻第三个未处理属性的影响。

我们很快会谈论 CouchDB 采取的方法，但还有一些关于 NoSQL 数据库避免的另一个概念要学习：ACID。

### ACID

**ACID**是适用于数据库事务的一组属性，这些事务是传统关系数据库的核心。虽然事务非常强大，但它们也是使关系数据库的读写变得相当慢的因素之一。

ACID 由四个主要属性组成：

+   **原子性：** 这是一种处理数据的全盘或无。事务中的所有内容必须成功发生，否则所有更改都不会被提交。这是在系统中处理货币或货币时的关键属性，并需要一套检查和平衡系统。

+   **一致性：** 数据只有在通过数据库上的所有验证（如触发器、数据类型和约束）后才会被接受。

+   **隔离性：** 事务不会影响正在发生的其他事务，其他用户也不会看到正在进行的事务的部分结果。

+   **持久性：** 一旦数据保存，它就会在错误、崩溃和其他软件故障中得到保护。

当你阅读 ACID 的定义时，你可能会想：“这些都是必须的！”也许是这样，但请记住，大多数 NoSQL 数据库并没有完全采用 ACID，因为要同时具备所有这些限制并且仍然能够对数据进行快速写入几乎是不可能的。

### 那么所有这些意味着什么呢？

我现在给了你很多定义，但让我们试着把它们整合成几个简单的列表。让我们讨论一下 NoSQL 数据库的优缺点，何时使用，何时避免使用 NoSQL 数据库。

#### NoSQL 数据库的优势

随着 NoSQL 数据库的引入，有很多优势：

+   你可以做一些传统关系数据库的处理和查询能力无法做到的事情。

+   你的数据是可扩展和灵活的，可以更快地适应规模和复杂性，直接开箱即用。

+   有新的数据模型需要考虑。如果没有意义，你不必强迫你的数据适应关系模型。

+   写入数据非常快。

正如你所看到的，NoSQL 数据库有一些明显的优势，但正如我之前提到的，仍然有一些需要考虑的负面影响。

#### NoSQL 数据库的负面影响

然而，除了好处，也存在一些坏处：

+   没有通用标准；每个数据库都有一点点不同的做法

+   查询数据不涉及熟悉的 SQL 模型来查找记录

+   NoSQL 数据库仍然相对不成熟且不断发展

+   有新的数据模型需要考虑；有时让你的数据适应可能会令人困惑

+   因为 NoSQL 数据库避免了 ACID 模型，所以不能保证所有数据都能成功写入。

其中一些负面影响可能对你来说很容易接受，除了 NoSQL 避免 ACID 模型这一点。

#### 你应该使用 NoSQL 数据库的情况

现在我们对优缺点有了很好的了解，让我们谈谈使用 NoSQL 数据库的一些绝佳用例：

+   有大量写入的应用程序

+   数据的模式和结构可能会发生变化的应用

+   大量的非结构化或半结构化数据

+   传统的关系数据库感觉限制很多，你想尝试一些新的东西。

这个列表并不是排他性的，但在何时可以使用 NoSQL 数据库上并没有明确的定义。实际上，你可以在几乎每个项目中使用它们。

#### 你应该避免使用 NoSQL 数据库的情况

然而，有一些明显的领域，你在其中存储数据时应该避免使用 NoSQL。

+   任何涉及金钱或交易的事情。如果由于 NoSQL 避免 ACID 模型或分布式系统的数据不是 100%可用，会发生什么？

+   业务关键数据或业务应用程序，如果丢失一行数据可能会导致巨大问题。

+   需要在关系数据库中实现功能的高度结构化数据。

对于所有这些用例，你应该真正专注于使用关系数据库，以确保你的数据安全可靠。当然，在有意义的情况下，你也可以包含 NoSQL 数据库。

在选择数据库时，重要的是要记住“没有银弹”。这个短语在谈论技术时经常被使用，它意味着没有一种技术可以解决所有问题而没有任何副作用或负面后果。所以要明智选择！

# CouchDB 简介

对于这本书和我的一些项目和创业公司，我选择了 CouchDB。让我们来历史性地看一下 CouchDB，然后快速触及它对 CAP 定理的处理方式，以及它的优势和劣势。

## CouchDB 的历史

2005 年 4 月，*Damien Katz*发布了一篇关于他正在开发的新数据库引擎的博客文章，后来被称为 CouchDB，这是**Cluster Of Unreliable Commodity Hardware**的缩写。Katz 是 IBM 的前 Lotus Notes 开发人员，试图在 C++中创建一个容错的文档数据库，但很快转向**Erlang OTP**平台。随着时间的推移，CouchDB 在 Damien Katz 的自我资助下开始发展，并于 2008 年 2 月被引入 Apache 孵化器项目。最后，2008 年 11 月，它毕业为一个顶级项目。

Damien 的团队**CouchOne**在 2011 年与 Membase 团队合并，组成了一个名为**Couchbase**的新公司。这家公司成立的目的是将**CouchDB**和**Membase**合并成一个新产品，并增加产品的文档和可见性。

2012 年初，Couchbase 宣布将把重点从促进 CouchDB 转移到创建 Couchbase Server 2.0。这个新的数据库采用了与数据库不同的方法，这意味着它将不再为 CouchDB 社区做出贡献。这一消息在 CouchDB 社区引起了一些不安，直到 Cloudant 介入。

**Cloudant**，CouchDB 的主要托管公司和 BigCouch 的创建者，BigCouch 是为 CouchDB 构建的容错和水平可扩展的集群框架，宣布他们将把他们的更改合并回 CouchDB，并承担继续开发 CouchDB 的角色。

2012 年初，在撰写本文时，CouchDB 的最重要的版本是 2011 年 3 月 31 日的 1.1.1 版。但 CouchDB 1.2 即将发布！

## 定义 CouchDB

根据[`couchdb.apache.org/`](http://couchdb.apache.org/)，CouchDB 可以被定义为：

+   一个通过 RESTful JSON API 访问的文档数据库服务器

+   自由式和无模式，具有平面地址空间

+   分布式，具有强大的增量复制和双向冲突检测和管理

+   可查询和可索引，具有使用 JavaScript 作为查询语言的面向表的报告引擎。

你可能能够在行间读出，但 CouchDB 从 CAP 定理中选择了可用性和部分容忍，并专注于使用复制实现最终一致性。

我们可以深入探讨每个这些要点的含义，因为在我们深入讨论它们之前，这将占据本书的剩余部分。在每一章中，我们将开始建立在我们对 CouchDB 的知识之上，直到我们拥有一个完全运行的应用程序。

# 总结

希望你喜欢这一章，并准备深入学习 CouchDB 的方方面面。让我们回顾一下这一章学到的一切。

+   我们谈到了数据库的历史和 NoSQL 数据库的出现

+   我们定义了使用 NoSQL 的优缺点

+   我们看了 CouchDB 的定义和历史

历史课就讲到这里。打开你的电脑。在下一章中，我们将设置好一切，用 CouchDB 和 PHP 开发 Web 应用程序，并确保一切设置正确。


# 第二章：设置你的开发环境

> 在本章中，我们将设置你的计算机，以便你可以使用 PHP 和 CouchDB 开发 Web 应用程序。在开发 Web 应用程序时涉及到很多技术，所以在开始编写代码之前，我们需要确保我们的系统配置正确。

在本章中，我们将：

+   讨论你的操作系统以及如何安装必要的组件

+   了解开发 PHP 和 CouchDB 应用程序所需的工具

+   配置我们的 Web 开发环境

+   了解 Homebrew 并安装 CouchDB

+   使用 Homebrew 来安装 Git 进行版本控制

+   确认你可以向 CouchDB 发出请求

准备好了吗？很好！让我们开始谈论操作系统以及它们在设置你的开发环境中所起的作用。

# 操作系统

本书将主要关注 Mac OS X 操作系统（10.5 及更高版本）。虽然在任何操作系统上都可以开发 PHP 和 CouchDB 应用程序，但为了简单和简洁起见，我将大部分讨论限制在 Mac OS X 上。如果你使用的是 Mac，你可以直接跳到下一节，标题为*在 Mac OS X 上设置你的 Web 开发环境*。

如果你使用的是 Windows 或 Linux，不用担心！我会给你一些设置提示，然后你可以自己操作。值得注意的是，我在本书中使用的命令行语句是为 Mac OS 设计的。因此，一些东西，比如导航到你的工作目录，文件的位置等等可能不会按照描述的方式工作。

## Windows

如果你使用 Windows，有一些简单的步骤需要遵循才能让你的机器正常运行。

### 安装 Apache 和 PHP

你可以使用 WAMP ([`www.wampserver.com/en/`](http://www.wampserver.com/en/))或 XAMPP ([`www.apachefriends.org/en/xampp.html`](http://www.apachefriends.org/en/xampp.html))来简化 Apache 和 PHP 环境的设置。这两个选项都可以让你通过几次鼠标点击轻松设置 Apache 和 PHP。

### 安装 Git

**Git**适用于每个操作系统。要在 Windows 上安装 Git，请转到 Git 的主页（[`git-scm.com/`](http://git-scm.com/)），然后点击 Windows 图标。

### 安装 CouchDB

你可以在这里找到更多关于在 Windows 上使用 Apache 的安装页面安装 CouchDB 的信息：[`wiki.apache.org/couchdb/Installing_on_Windows`](http://wiki.apache.org/couchdb/Installing_on_Windows)。

## Linux

由于 Linux 的不同版本和配置很多，很难标准化 Linux 的`install`方法。但是如果你使用的是通用发行版，比如 Ubuntu，所有必需的工具都可以通过几个简单的命令行语句来安装。

### 安装 Apache 和 PHP

`apt-get`是一个强大的工具，我们将使用它来在你的系统中安装应用程序和实用工具。让我们首先确保`apt-get`是最新的，通过运行以下命令：

```php
**sudo apt-get update** 

```

通过安装 Apache 来确保我们可以托管我们的 PHP 页面：

```php
**sudo apt-get install apache2** 

```

既然我们有了 Apache，让我们安装 PHP 和其他一些运行本书中代码所需的组件：

```php
**sudo apt-get install php5 php5-dev libapache2-mod-php5 php5-curl php5-mcrypt** 

```

我们已经准备好托管网站所需的一切。因此，让我们重新启动 Apache 以使我们的更改生效：

```php
**sudo /etc/init.d/apache2 restart** 

```

### 安装 Git

我们将使用 Git 进行源代码控制；幸运的是，通过我们的朋友`apt-git`的帮助，安装它非常容易。通过运行以下命令来安装 Git：

```php
**sudo apt-get install git-core** 

```

### 安装 CouchDB

CouchDB 是本书中我们将使用的数据库。在本节中，我们将使用命令行安装和启动它。

1.  使用`apt-get`安装 CouchDB：

```php
**sudo apt-get install couchDB** 

```

1.  通过运行以下命令将 CouchDB 作为服务启动：

```php
**sudo /etc/init.d/couchdb start** 

```

是不是很容易？如果你使用的是其他 Linux 发行版，那么你可能需要研究如何安装所有必需的应用程序和工具。

既然我们已经解决了这个问题，让我们讨论一下在 Mac OS X 上设置 Web 开发环境。

# 在 Mac OS X 上设置你的 Web 开发环境

在这一部分，我们将逐步确保我们的开发环境设置正确。从现在开始，我假设你正在使用运行 Mac OS X 的机器，没有对 Apache 或 PHP 进行任何特殊修改。如果你对开发环境进行了很多定制，那么你可能已经知道如何配置你的机器，使一切正常工作。

现在我已经用免责声明把你弄得厌烦了，让我们开始吧！我们旅程的第一部分是认识一个我们将花费大量时间的应用程序：`Terminal`。

## Terminal

`Terminal`是 Mac OS X 内置的命令行实用程序。当你刚开始使用命令行时，可能会有点奇怪的体验，但一旦掌握了，它就非常强大。如果基本命令，如`cd, ls`和`mkdir`对你来说像胡言乱语，那么你可能需要快速了解一下 UNIX 命令行。

这是如何打开`Terminal`的：

1.  打开**Finder**。

1.  点击**应用程序**。

1.  找到名为**实用工具**的文件夹，并打开它。

1.  将**Terminal**图标拖到你的 dock 中；你会经常使用它！

1.  点击你 dock 中的**Terminal**图标。![Terminal](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/couchdb-php-webdev-bgd/img/3586_02_005.jpg)

# 行动时间——使用 Terminal 显示隐藏文件

现在我们已经启动了`Terminal`，让我们通过运行一个快速命令来熟悉它，这个命令会显示你电脑上所有的隐藏文件。不管你知不知道，有各种各样的文件是隐藏的，它们需要可见才能完成我们的开发环境设置。

1.  首先打开**Terminal**。

1.  输入以下命令以允许 Finder 显示隐藏文件，准备好后按*Enter*：

```php
**defaults write com.apple.finder AppleShowAllFiles TRUE** 

```

1.  为了看到文件，你需要重新启动`Finder`，输入以下命令，然后按*Enter*：

```php
**killall Finder** 

```

## 刚刚发生了什么？

我们刚刚使用`Terminal`运行了一个特殊命令，配置了`Finder`显示隐藏文件，然后运行了另一个命令重新启动了`Finder`。你不需要记住这些命令或完全理解它们的含义；你可能永远不需要再次输入这些命令。如果你四处看看你的电脑，你应该会看到很多以前没见过的文件。这是我电脑上的一个快速示例：

![刚刚发生了什么？](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/couchdb-php-webdev-bgd/img/3586OS_02_006.jpg)

### 提示

如果看到这么多文件让你烦恼，你可以在设置完成后再次隐藏隐藏文件。你只需在`Terminal`中运行以下命令：defaults write `com.apple.finder AppleShowAllFiles FALSE`。然后通过运行以下命令重新启动`Finder`：`killall Finder`。

现在我们的机器上所有的文件都显示出来了，让我们谈谈文本编辑器，这将是你查看和编辑开发项目的主要方式。

## 文本编辑器

为了编写代码，你需要一个可靠的文本编辑器。有很多文本编辑器可供选择，你可以使用任何你喜欢的。本书中的所有代码都适用于任何文本编辑器。我个人更喜欢`TextMate`，因为它简单易用。

你可以在这里下载并安装`TextMate`：[`macromates.com/`](http://macromates.com/)。

## Apache

Apache 是一个开源的 Web 服务器，也是将在本书中编写的 PHP 代码运行的引擎。幸运的是，Apache 预装在所有的 Mac OS X 安装中，所以我们只需要使用`Terminal`来启动它。

1.  打开**Terminal**。

1.  运行以下命令启动 Apache：

```php
**sudo apachectl start** 

```

这就是在你的电脑上启动 Apache 所需的全部。如果 Apache 已经在运行，它不会让你启动它。尝试再次输入相同的语句；你的机器会提醒你它已经在运行了：

![Apache](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/couchdb-php-webdev-bgd/img/3586OS_02_008.jpg)

### 注意

这很不可能，但万一您的机器没有安装 Apache，您可以按照 Apache 网站上的说明进行安装：[`httpd.apache.org/docs/2.0/install.html`](http://httpd.apache.org/docs/2.0/install.html)。

## Web 浏览器

您可能每天都在上网时使用 Web 浏览器，但它也可以作为我们强大的调试工具。我将使用 Chrome 作为我的 Web 浏览器，但 Safari、Firefox 或 Internet Explorer 的最新版本也可以正常工作。让我们使用我们的 Web 浏览器来检查 Apache 是否可访问。

# 行动时间-打开您的 Web 浏览器

我们将通过打开 Web 浏览器并导航到 Apache 的 URL 来访问我们机器上的 Apache 服务。

1.  打开您的 Web 浏览器。

1.  在地址栏中输入`http://localhost`，然后按*Enter*键。

1.  您的浏览器将向您显示以下消息：![行动时间-打开您的 Web 浏览器](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/couchdb-php-webdev-bgd/img/3586OS_02_010.jpg)

## 刚刚发生了什么？

我们使用 Web 浏览器访问了 Apache，作为回报，它向我们显示了一个快速的验证，证明一切都正确连接。我们的计算机知道我们正在尝试访问本地 Apache 服务，因为 URL`http://localhost`。URL`http://localhost`实际上映射到地址`http://127.0.0.1:80`，这是 Apache 服务的地址和端口。当我们讨论 CouchDB 时，您将再次看到`127.0.0.1`。

## PHP

`PHP`是本书的标题，因此您知道它将在开发过程中发挥重要作用。PHP 已经安装在您的机器上，因此您无需安装任何内容。让我们通过 Terminal 再次检查您是否可以访问 PHP。

# 行动时间-检查您的 PHP 版本

我们将通过 Terminal 访问您的计算机上的 PHP 来检查 PHP 是否正常工作。

1.  打开**Terminal**。

1.  运行以下命令以返回 PHP 的版本：

```php
**php -v** 

```

1.  **Terminal**将以类似以下内容的方式做出响应：![行动时间-检查您的 PHP 版本](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/couchdb-php-webdev-bgd/img/3586OS_02_015.jpg)

## 刚刚发生了什么？

我们使用**Terminal**确保我们的机器上的 PHP 正确运行。我们不仅检查了 PHP 是否可访问，还要求其版本。您的版本可能与我的略有不同，但只要您的版本是 PHP 5.3 或更高版本即可。

### 注意

如果您的版本低于 PHP 5.3 或无法使 PHP 响应，您可以通过查看 PHP 手册进行安装或升级：[`php.net/manual/en/install.macosx.php`](http://php.net/manual/en/install.macosx.php)。

# 行动时间-确保 Apache 可以连接到 PHP

为了创建一个 Web 应用程序，Apache 需要能够运行 PHP 代码。因此，我们将检查 Apache 是否可以访问 PHP。

1.  使用**Finder**导航到以下文件夹：`/etc/apache2`。

1.  在您的文本编辑器中打开名为`httpd.conf`的文件。

1.  查看文件，并找到以下行（它应该在第 116 行左右）：

```php
**#LoadModule php5_module libexec/apache2/libphp5.so** 

```

1.  删除`config`文件中位于此字符串前面的哈希（#）符号以取消此行的注释。您的配置文件可能已经取消了此注释。如果是这样，那么您无需更改任何内容。无论如何，最终结果应如下所示：

```php
**LoadModule php5_module libexec/apache2/libphp5.so** 

```

1.  打开**Terminal**。

1.  通过运行以下命令重新启动 Apache：

```php
**sudo apachectl restart** 

```

## 刚刚发生了什么？

我们打开了 Apache 的主配置文件`httpd.conf`，并取消了一行的注释，以便 Apache 可以加载 PHP。然后我们重新启动了 Apache 服务器，以便更新的配置生效。

# 行动时间-创建一个快速信息页面

我们将通过快速创建一个`phpinfo`页面来双重检查 Apache 是否能够渲染 PHP 脚本，该页面将显示有关您配置的大量数据。

1.  打开您的文本编辑器。

1.  创建一个包含以下代码的新文件：

```php
<?php phpinfo(); ?>

```

1.  将文件保存为`info.php`，并将该文件保存在以下位置：`/Library/WebServer/Documents/info.php`。

1.  打开您的浏览器。

1.  将浏览器导航到`http://localhost/info.php`。

1.  您的浏览器将显示以下页面：![Time for action — creating a quick info page](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/couchdb-php-webdev-bgd/img/3586OS_02_020.jpg)

## 刚刚发生了什么？

我们使用文本编辑器创建了一个名为`info.php`的文件，其中包含一个名为`phpinfo`的特殊 PHP 函数。我们将`info.php`文件保存到文件夹：`/Library/Webserver/Documents`。这个文件夹是 Apache 服务将显示的所有文件的默认位置（仅适用于 Mac OS X）。当您的浏览器访问`info.php`页面时，`phpinfo`会查看您的 PHP 安装并返回一个包含有关您配置详细信息的 HTML 文件。您可以看到这里有很多事情要做。在我们继续之前，随意浏览并查看一些信息。

## 微调 Apache

我们最终建立了基本的 Web 开发环境。但是，为了构建我们的应用程序，我们需要调整 Apache 中的一些内容；首先是启用一个名为`mod_rewrite`的内置模块。

# 行动时间 — 进一步配置 Apache

`mod_rewrite`将允许我们动态重写请求的 URL，这将帮助我们构建具有清晰 URL 的应用程序。重写本身在另一个名为`.htaccess`的 Apache 配置文件中处理，我们将在第四章 *启动您的应用程序*中介绍。在下一节中，我们将配置 Apache，以便启用`mod_rewrite`。

1.  使用**Finder**导航到以下文件夹：`/etc/apache2`。

1.  在文本编辑器中找到并打开名为`httpd.conf`的文件。

1.  浏览文件，并找到此行（应该是第 114 行）：

```php
**#LoadModule rewrite_module libexec/apache2/mod_rewrite.so** 

```

1.  取消注释行，删除井号（#）符号。您的系统可能已经配置为启用`mod_rewrite`。无论如何，请确保它与以下代码匹配：

```php
**LoadModule rewrite_module libexec/apache2/mod_rewrite.so** 

```

1.  浏览文件，并找到此代码块（应该从第 178-183 行开始）：

```php
<Directory />
Options FollowSymLinks
AllowOverride None
Order deny,allow
Allow from all
</Directory>

```

1.  更改代码行，将`AllowOverride None`更改为`AllowOverride All`。结果部分应如下所示：

```php
<Directory />
Options FollowSymLinks
**AllowOverride All** 
Order deny,allow
Allow from all
</Directory>

```

1.  继续滚动文件，直到找到这段代码（应该从第 210-215 行开始）：

```php
#
# AllowOverride controls what directives may be placed in #.htaccess files.
# It can be —All—, —None—, or any combination of the keywords:
# Options FileInfo AuthConfig Limit
#
AllowOverride None

```

1.  更改此代码行，将`AllowOverride None`更改为`AllowOverride All`。结果部分应如下所示：

```php
#
# AllowOverride controls what directives may be placed in #.htaccess files.
# It can be "All", "None", or any combination of the keywords:
# Options FileInfo AuthConfig Limit
#
AllowOverride All

```

1.  打开**Terminal**。

1.  通过运行以下命令重新启动 Apache：

```php
**sudo apachectl restart** 

```

## 刚刚发生了什么？

我们刚刚配置了 Apache，使其可以更自由地运行，并包括使用`mod_rewrite`模块重写 URL 的能力。然后，我们将`AllowOverride`的配置从`None`更改为`All`。`AllowOverride`告诉服务器在找到`.htaccess`文件时该怎么做。将此设置为`None`时，将忽略`.htaccess`文件。将设置更改为`All`允许在`.htaccess`文件中覆盖设置。这正是我们将在第四章中开始构建应用程序时要做的事情。

## 我们的 Web 开发设置已经完成！

我们现在已经设置好了创建标准 Web 应用程序的一切。我们有 Apache 处理请求。我们已经连接并响应来自 Apache 的 PHP 调用，并且我们的文本编辑器已准备好接受我们可以投入其中的任何代码。

我们还需要一些部分才能拥有完整的开发环境。在下一节中，我们将安装 CouchDB 作为我们的数据库。

## 安装 CouchDB

在本节中，我们将在您的计算机上安装 CouchDB 1.0 并为其进行开发准备。有多种方法可以在您的计算机上安装 CouchDB，因此如果您在以下安装过程中遇到问题，请参考 CouchDB 的网站：[`wiki.apache.org/couchdb/Installation`](http://wiki.apache.org/couchdb/Installation)。

## Homebrew

为了安装本书中将使用的其余组件，我们将使用一个名为**Homebrew**的实用程序。Homebrew 是安装苹果 OSX 中遗漏的 UNIX 工具的最简单方法。在我们可以使用 Homebrew 安装其他工具之前，我们首先需要安装 Homebrew。

# 安装 Homebrew 的时间到了

我们将使用**终端**下载 Homebrew 并将其安装到我们的计算机上。

1.  打开**终端**。

1.  在**终端**中输入以下命令，每行后按*Enter*：

```php
**sudo mkdir -p /usr/local
sudo chown -R $USER /usr/local
curl -Lf http://github.com/mxcl/homebrew/tarball/master | tar xz -- strip 1 -C/usr/local** 

```

1.  **终端**将会显示一个进度条，告诉你安装过程进行得如何。安装完成后，你会收到一个成功的消息，然后你就可以再次控制**终端**了。

## 刚刚发生了什么？

我们添加了目录`/usr/local`，这是 Homebrew 将保存所有文件的位置。然后我们确保该文件夹归我们所有（当前用户）。然后我们使用`cURL`语句从 Github 获取存储库（我将在本章后面介绍`cURL`；我们将经常使用它）。获取存储库后，使用命令行函数`tar`解压缩，并将其放入`/usr/local`文件夹中。

# 安装 CouchDB 的时间到了

现在我们已经安装了 Homebrew，终于可以安装 CouchDB 了。

### 注意

请注意，在 Homebrew 安装 CouchDB 之前，它将安装所有的依赖项，包括：Erlang，Spidermonkey，ICU 等。这一部分可能需要 10-15 分钟才能完成，因为它们是在您的计算机上本地编译的。如果看起来花费的时间太长，不要担心；这是正常的。

我们将使用 Homebrew 安装 CouchDB。

1.  打开终端

1.  运行以下命令：

```php
**brew install couchdb -v** 

```

1.  接下来的几分钟，终端将会回复大量的文本。您将看到它获取每个依赖项，然后安装它。最后，您将收到一个成功的消息。

## 刚刚发生了什么？

我们刚刚从源代码安装了 CouchDB 并下载了所有的依赖项。安装完成后，Homebrew 将所有内容放在正确的文件夹中，并配置了我们使用 CouchDB 所需的一切。

# 检查我们的设置是否完成

在过去的几页中，我们已经完成了很多工作。我们已经设置好了我们的 Web 开发环境并安装了 CouchDB。现在，让我们再次确认我们能否运行和访问 CouchDB。

## 启动 CouchDB

CouchDB 很容易管理。它作为一个服务运行，我们可以使用命令行启动和停止它。让我们用命令行语句启动 CouchDB。

1.  打开**终端**。

1.  运行以下命令：

```php
**couchdb -b** 

```

1.  **终端**将回复以下内容：

```php
**Apache CouchDB has started, time to relax.** 

```

太好了！现在我们已经将 CouchDB 作为后台进程启动，它将在后台处理请求，直到我们关闭它。

# 检查 CouchDB 是否正在运行的时间到了

我们将尝试使用命令行实用程序`cURL`（为了简单起见，我们将其拼写为`curl`）来访问我们机器上的 CouchDB 服务，它允许您发出原始的 HTTP 请求。`curl`是我们与 CouchDB 进行通信的主要方法。让我们从一个`curl`语句开始与 CouchDB 交流。

1.  打开**终端**。

1.  运行以下语句创建一个将访问 CouchDB 的请求：

```php
**curl http://127.0.0.1:5984/** 

```

1.  **终端**将回复以下内容：

```php
**{"couchdb":"Welcome","version":"1.0.2"}** 

```

## 刚刚发生了什么？

我们刚刚使用`curl`通过发出`GET`请求与 CouchDB 服务进行通信。默认情况下，`curl`会假定我们正在尝试发出`GET`请求，除非我们告诉它不是。我们向`http://127.0.0.1:5984`发出了我们的`curl`语句。将这个资源分解成几部分，`http://127.0.0.1`是我们本地计算机的 IP，`5984`是 CouchDB 默认运行的端口。

## 作为后台进程运行 CouchDB

如果我们在这里停止配置，您将不得不在每次开始开发时运行`couchdb b`。这对我们来说很快就会成为一个痛点。因此，让我们将 CouchDB 作为一个系统守护程序运行，即使在重新启动计算机后也会一直在后台运行。为了做到这一点，我们将使用一个名为`launchd`的 Mac OS X 服务管理框架，该框架管理系统守护程序并允许启动和停止它们。

1.  打开**终端**。

1.  通过运行以下命令杀死 CouchDB 的后台进程：

```php
**couchdb -k** 

```

1.  如果 CouchDB 正在运行，它将返回以下文本：

```php
**Apache CouchDB has been killed.** 

```

1.  让我们将 CouchDB 作为一个真正的后台进程运行，并确保每次启动计算机时都会运行它，通过运行以下语句：

```php
**launchctl load -w /usr/local/Cellar/couchdb/1.0.2/Library/LaunchDaemons/org.apache.couchdb.plist** 

```

### 注意

如果您的 CouchDB 版本与我的不同，您将不得不更改此脚本中的版本，该脚本显示为"1.0.2"，以匹配您的版本。

CouchDB 现在在后台运行，即使我们重新启动计算机，也不必担心在尝试使用它之前启动服务。

如果由于某种原因，您决定不希望 CouchDB 在后台运行，您可以通过运行以下命令卸载它：

```php
**launchctl unload /usr/local/Cellar/couchdb/1.0.2/Library/LaunchDaemons/org.apache.couchdb.plist** 

```

您可以通过使用我们之前使用的`curl`语句来双重检查 CouchDB 是否正在运行：

1.  打开**终端**。

1.  运行以下命令：

```php
**curl http://127.0.0.1:5984/** 

```

1.  **终端**将回复以下内容：

```php
**{"couchdb":"Welcome","version":"1.0.2"}** 

```

# 安装版本控制

版本控制系统允许开发人员跟踪代码更改，合并其他开发人员的代码，并回滚任何无意的错误。对于有几个开发人员的项目，版本控制系统是必不可少的，但对于单个开发人员项目也可能是一个救命稻草。把它想象成一个安全网-如果您不小心做了一些您不想做的事情，那么源代码控制就在那里保护您。在版本控制方面有几种选择，但在本书中，我们将使用 Git。

## Git

Git ([`git-scm.com/`](http://git-scm.com/))已经成为更受欢迎和广泛采用的版本控制系统之一，因为它的分布式性和易用性。实际使用 Git 的唯一比安装更容易的事情就是安装它。我们将使用 Homebrew 来安装 Git，就像我们用 CouchDB 一样。

# 行动时间-安装和配置 Git

准备好了！我们将使用 Homebrew 在计算机上安装 Git。

1.  打开**终端**。

1.  运行以下命令使用 Homebrew 安装 Git：

```php
**brew install git** 

```

1.  **终端**将在短短几分钟内为您下载并安装 Git。然后，它将以成功消息回复您，告诉您 Git 已安装。

1.  安装 Git 后，您需要配置它，以便在提交数据更改时知道您是谁。运行以下命令来标识自己，并确保在我放置`Your Name`和`your_email@domain.com`的地方填写您自己的信息：

```php
**git config global user.name "Your Name"
git config global user.email your_email@domain.com** 

```

## 刚刚发生了什么？

我们刚刚使用 Homebrew 从源代码安装了 Git。然后，我们配置了 Git 以使用我们的姓名和电子邮件地址。这些设置将确保从这台机器提交到源代码控制的任何更改都能被识别。

# 你遇到了什么问题吗？

我们已经完成了配置我们的系统！在一个完美的世界中，一切都会顺利安装，但完全有可能有些东西安装不完美。如果似乎有些东西不正常，或者您认为自己可能在某个地方打错了字，我有一个脚本可以帮助您重新回到正轨。这个命令可以通过在**终端**中调用我在 github 上的一个文件来本地执行。您只需在**终端**中运行以下命令，它将运行本章所需的所有必要代码：

**sh <(curl -s https://raw.github.com/timjuravich/environment-setup/master/ configure.sh)**

这个脚本将完成本节中提到的所有工作，并且可以安全地运行多次。我本可以给你这个命令并在几页前结束这一章，但这一章对教会你如何使用我们将在接下来的章节中使用的工具和实用程序是至关重要的。

## 小测验

1.  当我们使用默认的 Apache 安装进行 Web 开发时，默认的工作目录在哪里？

1.  为了在本地开发环境中使用 CouchDB，我们需要确保两个服务正在运行。它们是什么，你如何在**终端**中让它们运行？

1.  你使用什么命令行语句来向 CouchDB 发出`Get`请求？

# 总结

让我们快速回顾一下本章涵盖的所有内容：

+   我们熟悉了**终端**并用它来显示隐藏文件

+   我们安装了一个文本编辑器供我们在开发中使用

+   我们学会了如何配置 Apache 以及如何通过命令行与其交互

+   我们学会了如何创建简单的 PHP 文件，并将它们放在正确的位置，以便 Apache 可以显示它们

+   我们学会了如何安装 Homebrew，然后用它来安装 CouchDB 和 Git

+   我们检查了一下，确保 CouchDB 已经启动运行

在下一章中，我们将更加熟悉 CouchDB，并探索如何在创建我们的 Web 应用程序中使用它。


# 第三章：开始使用 CouchDB 和 Futon

> 在上一章中，我们设置了开发环境，我相信你迫不及待地想知道 CouchDB 对我们有什么作用。在这一点上，我们将花费整整一章的时间来深入了解 CouchDB。

具体来说，我们将：

+   深入了解 CouchDB 的含义，学习它在数据库和文档中的样子

+   学习我们将如何通过其 RESTful JSON API 与 CouchDB 交互

+   使用 CouchDB 内置的管理控制台：Futon

+   学习如何向 CouchDB 数据库添加安全性

# 什么是 CouchDB？

CouchDB 的定义（由[`couchdb.apache.org/)`](http://couchdb.apache.org/)定义）的第一句是：

> CouchDB 是一个文档数据库服务器，可通过 RESTful JSON API 访问。

让我们解剖这个句子，充分理解它的含义。让我们从术语**数据库服务器**开始。

## 数据库服务器

CouchDB 采用了面向文档的数据库管理系统，提供了一组没有模式、分组或层次结构的文档。这是**NoSQL**引入的概念，与关系数据库（如 MySQL）有很大的不同，您会期望在那里看到表、关系和外键。每个开发人员都经历过一个项目，他们不得不将关系数据库模式强加到一个真正不需要表和复杂关系的项目中。这就是 CouchDB 与众不同的地方；它将所有数据存储在一个自包含的对象中，没有固定的模式。下面的图表将有助于说明这一点：

![数据库服务器](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/couchdb-php-webdev-bgd/img/3586_03_005.jpg)

在前面的例子中，我们可能希望方便许多用户属于一对多的组。为了在关系数据库（如 MySQL）中处理这个功能，我们需要创建一个用户表、一个组表，以及一个名为`users_groups`的链接表，允许您将许多用户映射到许多组。这种做法对大多数 Web 应用程序都很常见。

现在看看 CouchDB 文档。这里没有表或链接表，只有文档。这些文档包含与单个对象相关的所有数据。

### 注意

这个图表非常简化。如果我们想在 CouchDB 中创建更多关于组的逻辑，我们将不得不创建**组**文档，并在用户文档和组文档之间建立简单的关系。随着我们深入学习，我们将介绍如何处理这种类型的关系。

在本节中，我们经常看到术语**文档**。所以让我们进一步了解文档是什么，以及 CouchDB 如何使用它们。

## 文档

为了说明你可能如何使用文档，首先想象一下你在填写工作申请表的纸质表格。这个表格包含关于你、你的地址和过去地址的信息。它还包含关于你过去的工作、教育、证书等许多信息。一个文档会将所有这些数据保存下来，就像你在纸质表格上看到的那样 - 所有信息都在一个地方，没有任何不必要的复杂性。

在 CouchDB 中，文档被存储为包含键值对的 JSON 对象。每个文档都有保留字段用于元数据，如`id, revision`和`deleted`。除了保留字段，文档是 100%无模式的，这意味着每个文档可以根据需要格式化和独立处理，有许多不同的变化。

### CouchDB 文档的示例

让我们看一个 CouchDB 文档可能是什么样子的例子：

```php
{
"_id": "431f956fa44b3629ba924eab05000553",
"_rev": "1-c46916a8efe63fb8fec6d097007bd1c6",
"title": "Why I like Chicken",
"author": "Tim Juravich",
"tags": [
"Chicken",
"Grilled",
"Tasty"
],
"body": "I like chicken, especially when it's grilled."
}

```

### 提示

**下载示例代码**

您可以从您在[`www.packtpub.com`](http://www.packtpub.com)的帐户中购买的所有 Packt 图书下载示例代码文件。如果您在其他地方购买了这本书，您可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)并注册，文件将直接通过电子邮件发送给您。

### JSON 格式

你可能注意到的第一件事是文档的奇怪标记，这是 **JavaScript 对象表示法（JSON）**。JSON 是一种基于 JavaScript 语法的轻量级数据交换格式，非常便携。CouchDB 使用 JSON 进行与其所有通信，因此在阅读本书的过程中，您将对其非常熟悉。

### 键值存储

接下来，您可能注意到这个文档中有很多信息。有一些简单易懂的键值对，比如 `"title", "author"` 和 `"body"`，但您还会注意到 `"tags"` 是一个字符串数组。CouchDB 允许您直接将尽可能多的信息嵌入到文档中。这对于习惯于规范化和结构化数据库的关系数据库用户来说可能是一个新概念。

### 保留字段

我们之前提到了保留字段。让我们来看看您在前面的示例文档中看到的两个保留字段：`_id` 和 `_rev`。

`_id` 是文档的唯一标识符。这意味着 `_id` 是必需的，没有两个文档可以具有相同的值。如果在创建文档时没有定义 `_id`，CouchDB 将为您选择一个唯一的值。

`_rev` 是文档的修订版本，是帮助驱动 CouchDB 版本控制系统的字段。每次保存文档时，都需要修订号，以便 CouchDB 知道哪个版本的文档是最新的。这是必需的，因为 CouchDB 不使用锁定机制，这意味着如果两个人同时更新文档，那么先保存更改的人获胜。CouchDB 修订系统的一个独特之处在于，每次保存文档时，原始文档不会被覆盖，而是创建一个新的带有新数据的文档，同时 CouchDB 以其原始形式存储先前文档的备份。旧的修订版本保持可用，直到数据库被压缩或发生某些清理操作。

定义句子的最后一部分是 RESTful JSON API。接下来让我们来介绍它。

## RESTful JSON API

为了理解 REST，让我们首先定义 **超文本传输协议（HTTP）**。HTTP 是互联网的基础协议，它定义了消息的格式和传输方式，以及在使用各种方法时服务应该如何响应。这些方法包括 `GET, PUT, POST` 和 `DELETE` 等四个主要动词。为了充分理解 HTTP 方法的功能，让我们首先定义 REST。

**表述状态转移（REST）** 是一种通过 HTTP 方法访问可寻址资源的无状态协议。**无状态** 意味着每个请求包含了完全理解和使用请求中的数据所需的所有信息，**可寻址资源** 意味着您可以通过 URL 访问对象。

这本身可能并不意味着太多，但是将所有这些想法结合在一起，它就成为了一个强大的概念。让我们通过两个例子来说明 REST 的强大之处：

| 资源 | 获取 | 放置 | 发布 | 删除 |
| --- | --- | --- | --- | --- |
| `http://localhost/collection` | **读取** `collection` 中所有项目的列表 | **更新** 另一个 `collection` | **创建** 一个新的 `collection` | **删除** `collection` |
| `http://localhost/collection/abc123` | **读取** `collection` 中 `abc123` 项目的详细信息 | **更新** `collection` 中 `abc123` 的详细信息 | **创建** `collection` 中的新对象 `abc123` | **从 `collection` 中删除** `abc123` |

通过查看表格，您可以看到每个资源都以 URL 的形式存在。第一个资源是 `collection`，第二个资源是 `abc123`，它位于 `collection` 中。当您对这些资源传递不同的方法时，每个资源会有不同的响应。这就是 REST 和 HTTP 共同工作的美妙之处。

请注意我在表中使用的粗体字：**读取，更新，创建**和**删除**。这些词实际上是另一个概念，当然，它有自己的术语；**CRUD**。这个不太动听的术语 CRUD 代表创建、读取、更新和删除，是 REST 用来定义当 HTTP 方法与 URL 形式的资源结合时发生的情况的概念。因此，如果您要将所有这些都归纳起来，您将得到以下图表：

![RESTful JSON APIRESTexamples](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/couchdb-php-webdev-bgd/img/3586_03_010.jpg)

这个图表的含义是：

+   为了**创建**一个资源，您可以使用**POST**或**PUT**方法

+   为了**读取**一个资源，您需要使用**GET**方法

+   为了**更新**一个资源，您需要使用**PUT**方法

+   为了**删除**一个资源，您需要使用**DELETE**方法

正如您所看到的，CRUD 的这个概念使得清楚地找出您在执行特定操作时需要使用的方法。

现在我们已经了解了 REST 的含义，让我们继续学习术语**API**，它代表**应用程序编程接口**。虽然有很多不同的用例和 API 的概念，但 API 是我们将用来与 CouchDB 进行编程交互的工具。

现在我们已经定义了所有术语，RESTful JSON API 可以定义如下：我们可以通过向 CouchDB API 发出 HTTP 请求并定义资源、HTTP 方法和任何额外数据来与 CouchDB 进行交互。结合所有这些意味着我们正在使用 REST。在 CouchDB 处理我们的 REST 请求后，它将返回一个 JSON 格式的响应，其中包含请求的结果。

当我们逐个浏览每个 HTTP 方法时，所有这些背景知识将开始变得有意义，因为我们将使用 CouchDB 的 RESTful JSON API 进行操作。

我们将使用`curl`（我们在上一章中学习使用的）通过发出原始 HTTP 请求来探索每个 HTTP 方法。

# 执行操作——获取 CouchDB 中所有数据库的列表

在本书的前面，当我们使用`curl`语句：`curl http://localhost:5984`时，您已经看到了一个`GET`请求。

这一次，让我们发出一个`GET`请求来访问 CouchDB 并获取服务器上所有数据库的列表。

1.  在**终端**中运行以下命令：

```php
**curl -X GET http://localhost:5984/_all_dbs** 

```

1.  **终端**将会返回以下内容：

```php
**["_users"]** 

```

## 刚刚发生了什么？

我们使用**终端**触发了一个`GET`请求到 CouchDB 的 RESTful JSON API。我们使用了`curl`的一个选项：`-X`，来定义 HTTP 方法。在这种情况下，我们使用了`GET`。`GET`是默认方法，所以在技术上，如果您愿意，您可以省略`-X`。一旦 CouchDB 处理了请求，它会返回一个包含 CouchDB 服务器中所有数据库列表的响应。目前，只有`_users`数据库，这是 CouchDB 用于验证用户的默认数据库。

# 执行操作——在 CouchDB 中创建新的数据库

在这个练习中，我们将发出一个`PUT`请求，这将在 CouchDB 中创建一个新的数据库。

1.  通过在**终端**中运行以下命令创建一个新的数据库：

```php
**curl -X PUT http://localhost:5984/test-db** 

```

1.  **终端**将会返回以下内容：

```php
**{"ok":true}** 

```

1.  尝试使用**终端**中的以下命令创建另一个同名数据库：

```php
**curl -X PUT http://localhost:5984/test-db** 

```

1.  **终端**将会返回以下内容：

```php
**{"error":"file_exists","reason":"The database could not be created, the file already exists."}** 

```

1.  好吧，那没用。所以让我们尝试通过在**终端**中运行以下命令创建一个不同名称的数据库：

```php
**curl -X PUT http://localhost:5984/another-db** 

```

1.  **终端**将会返回以下内容：

```php
**{"ok":true}** 

```

1.  让我们快速检查`test-db`数据库的详细信息，并查看更多关于它的详细信息。为此，请在**终端**中运行以下命令：

```php
**curl -X GET http://localhost:5984/test-db** 

```

1.  **终端**将会返回类似于以下内容（我重新格式化了我的内容以便阅读）：

```php
**{
"committed_update_seq": 1,
"compact_running": false,
"db_name": "test-db",
"disk_format_version": 5,
"disk_size": 4182,
"doc_count": 0,
"doc_del_count": 0,
"instance_start_time": "1308863484343052",
"purge_seq": 0,
"update_seq": 1
}** 

```

## 刚刚发生了什么？

我们刚刚使用**终端**来触发了一个`PUT`方法，通过 CouchDB 的 RESTful JSON API 来创建数据库，将`test-db`作为我们想要在 CouchDB 根 URL 的末尾创建的数据库的名称。当数据库成功创建时，我们收到了一条一切正常的消息。

接下来，我们发出了一个`PUT`请求来创建另一个同名`test-db`数据库。因为不能有多个同名数据库，我们收到了一个错误消息。

然后我们使用`PUT`请求再次创建一个新的数据库，名为`another-db`。当数据库成功创建时，我们收到了一条一切正常的消息。

最后，我们向我们的`test-db`数据库发出了一个`GET`请求，以了解更多关于数据库的信息。知道每个统计数据的确切含义并不重要，但这是一个了解数据库概况的有用方式。

值得注意的是，在最后的`GET`请求中调用的 URL 与我们创建数据库时调用的 URL 相同。唯一的区别是我们将 HTTP 方法从`PUT`改为了`GET`。这就是 REST 的工作原理！

# 行动时间——删除数据库在 CouchDB

在这个练习中，我们将调用`DELETE`请求来删除`another-db`数据库。

1.  通过在**终端**中运行以下命令删除`another-db`：

```php
**curl -X DELETE http://localhost:5984/another-db** 

```

1.  **终端**将会回复以下内容：

```php
**{"ok":true}** 

```

## 刚刚发生了什么？

我们使用**终端**来触发 CouchDB 的 RESTful JSON API 的`DELETE`方法。我们在根 URL 的末尾传递了我们想要删除的数据库的名称`another-db`。当数据库成功删除时，我们收到了一条一切正常的消息。

# 行动时间——创建 CouchDB 文档

在这个练习中，我们将通过发起`POST`调用来创建一个文档。你会注意到我们的`curl`语句将开始变得有点复杂。

1.  通过在**终端**中运行以下命令在`test-db`数据库中创建一个文档：

```php
**curl -X POST -H "Content-Type:application/json" -d '{"type": "customer", "name":"Tim Juravich", "location":"Seattle, WA"}' http://localhost:5984/test-db** 

```

1.  **终端**将会回复类似以下的内容：

```php
**{"ok":true,"id":"39b1fe3cdcc7e7006694df91fb002082","rev":"1-8cf37e845c61cc239f0e98f8b7f56311"}** 

```

1.  让我们从 CouchDB 中检索新创建的文档。首先复制你在**终端**最后一次响应中收到的 ID 到你的剪贴板；我的是`39b1fe3cdcc7e7006694df91fb002082`，但你的可能不同。然后在**终端**中运行这个命令，将你的 ID 粘贴到 URL 的末尾：

```php
**curl -X GET http://localhost:5984/test-db/41198fc6e20d867525a8faeb7a000015 | python -mjson.tool** 

```

1.  **终端**将会回复类似以下的内容：

```php
**{
"_id": "41198fc6e20d867525a8faeb7a000015",
"_rev": "1-4cee6ca6966fcf1f8ea7980ba3b1805e",
"location": "Seattle, WA",
"name": "Tim Juravich",
"type:": "customer"
}** 

```

## 刚刚发生了什么？

我们使用**终端**来触发 CouchDB 的 RESTful JSON API 的`POST`调用。这一次，我们的`curl`语句增加了一些以前没有使用过的选项。`-H`选项使我们能够设置`POST`方法的 HTTP 请求头。我们需要将`content-type`设置为 JSON，以便 CouchDB 的 RESTful API 知道传入的格式是什么。我们还使用了一个新选项，`-d`选项，代表数据。数据选项允许我们在字符串形式与我们的`curl`语句一起传递数据。

创建完我们的文档后，我们通过向`http://localhost:5984/test-db/41198fc6e20d867525a8faeb7a000015`提交`GET`请求来在**终端**中检索它。作为响应，我们收到了一个包含所有文档数据的 JSON 对象。在这个请求的最后，我们做了一些不同的事情。我们添加了`python mjson.tool`，这是 Python 的内置组件，它使我们能够很好地格式化我们的 JSON 响应，以便我们能更好地理解它们。当我们开始查看更复杂的文档时，这将会很有用。

### 注意

我之前没有提到你需要在书中早些时候安装 Python，因为这是一个很好有的功能。如果你因为缺少 Python 而收到错误，你可以通过这里安装它：[`python.org/download/`](http://python.org/download/)。

我知道这有点烦人，但`curl`将是我们的 PHP 代码与 CouchDB 交流的主要方法，因此熟悉它的工作原理非常重要。幸运的是，有一种更容易的方法可以通过名为**Futon**的工具来访问和管理您的数据。

# Futon

CouchDB 自带一个名为 Futon 的内置基于 Web 的管理控制台。Futon 允许您在一个简单的界面中管理数据库、用户和文档。Futon 最好的部分是它已经安装并准备就绪，因为它已经与 CouchDB 捆绑在一起。

让我们来看看：

1.  打开您的浏览器。

1.  转到`http://localhost:5984/_utils/`。![Futon](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/couchdb-php-webdev-bgd/img/3586_03_015.jpg)

这是 Futon 的**概述**页面。在此页面上，您可以看到 CouchDB 安装中的所有数据库以及创建新数据库的功能。您应该看到我们在之前步骤中创建的数据库`test-db`，还可以看到 CouchDB 默认安装的`_users`数据库。

如果您看窗口右侧，您会看到**工具**。我们将在本书后面介绍*复制器*时使用它。

1.  点击**概述**页面上数据库列表中`test-db`的链接，深入了解我们的数据库`test-db`。![Futon](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/couchdb-php-webdev-bgd/img/3586_03_020.jpg)

您看到的页面是数据库详细信息。在此页面上，您可以看到我们数据库中的所有文档列表，以及一些可以在所选数据库上执行的操作，例如**新文档、安全性、压缩和清理...、删除数据库、搜索**等。值得注意的是，Futon 只是一个辅助工具，所有这些功能也可以通过`curl`来实现。

1.  让我们通过点击文档来深入了解 Futon，您将被转到文档详细信息页面。![Futon](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/couchdb-php-webdev-bgd/img/3586_03_025.jpg)

这些数据应该看起来很熟悉！我们所有的键都列在左边，值都列在右边。

# 行动时间——在 Futon 中更新文档

使用 Futon，您可以轻松更新此文档的值。让我们通过一个快速示例来看看。

1.  确保您在浏览器中打开了文档。

1.  注意文档中`_rev`的值。

1.  双击**位置**字段的值：“西雅图，华盛顿州”，将其更改为“纽约州纽约市”。

1.  点击页面顶部的**保存文档**。

1.  检查一下您文档中`_rev`的值是否已更改，以及“纽约州纽约市”现在是否是位置的值。

## 刚刚发生了什么？

您刚刚使用 Futon 更改了文档中字段的值，然后保存更改以更新文档。当文档刷新时，您应该已经注意到`_rev`字段已更改，并且您对字段的更改已更新。

您可能也注意到“上一个版本”现在看起来是可点击的。点击它，看看会发生什么。Futon 显示了文档的旧版本，其中位置是“华盛顿州西雅图”，而不是新值“纽约州纽约市”。

现在您将看到 CouchDB 的修订版本生效。如果您愿意，可以使用“上一个版本”和“下一个版本”链接循环浏览文档的所有版本。

### 注意

有两件关于 CouchDB 的修订系统需要注意的重要事项：

您无法更新文档的旧版本；如果您尝试保存文档的旧版本，CouchDB 将返回文档更新冲突错误。这是因为文档的唯一真实版本是最新版本。

您的修订历史仅是临时的。如果您的数据库记录了每一次更改，它将开始变得臃肿。因此，CouchDB 有一个名为**压缩**的功能，可以清除任何旧的修订版本。

# 行动时间——在 Futon 中创建文档

我们已经了解了更新现有文档。让我们在 Futon 中从头开始创建一个文档。

1.  通过点击页眉中的数据库名称`test-db`转到数据库概述。

1.  点击“新文档”。

1.  一个空白文档已经创建好，准备让我们放入新的字段。请注意，`_id`已经为我们设置好了（但如果我们愿意，我们可以更改它）。

1.  点击**添加字段**创建一个新字段，并称其为`location`。

1.  双击标签旁边的值，该标签显示为**null**，然后输入您当前的位置。

1.  点击**添加字段**创建一个新字段，并称其为`name`。

1.  双击标签旁边的值，该标签显示为`null`，然后输入您的名字。

1.  点击页面顶部的**保存文档**。

1.  文档已保存。请注意，现在它有一个`_rev`值。

## 刚刚发生了什么？

你刚刚使用 Futon 从头开始创建了一个文档。当文档第一次创建时，CouchDB 为您创建了一个唯一的 ID，以便您将其设置为`_id`字段的值。接下来，您添加了`name`字段，并输入了您的名字作为其值。最后，您保存它以创建一个新文档。我们已经讨论过文档可以有完全不同的字段，但这是我们实际做到的第一次！

# 安全

到目前为止，我们已经创建、读取、更新和删除了文档和数据库，而且所有这些都没有任何安全性。当您的 CouchDB 实例上没有任何管理员时，称为**管理员派对**，这意味着 CouchDB 将处理来自任何人的任何请求。

# 行动时间-将 CouchDB 从管理员派对中带出来

当您在本地编程时，CouchDB 不安全并不是什么坏事，但如果您在公开可访问的服务器上意外地有一个不安全的数据库，那可能是灾难性的。现在让我们简要地添加安全性，以确保您知道将来如何做。

1.  打开 Futon 到**概述**，并查看右下角。您会看到文字说：

```php
**Welcome to Admin Party!
Everyone is admin. Fix this.** 

```

1.  点击**修复此问题**链接。

1.  一个新窗口将弹出，提示您**创建服务器管理员**。![行动时间-将 CouchDB 从管理员派对中带出来](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/couchdb-php-webdev-bgd/img/3586_03_030.jpg)

1.  输入您想要用于管理员帐户的用户名和密码，然后点击**创建**。

## 刚刚发生了什么？

您刚刚使用 Futon 向 CouchDB 安装添加了一个服务器管理员。**创建服务器管理员**弹出窗口说，一旦添加了服务器管理员，您将能够创建和销毁数据库，并执行其他管理功能。所有其他用户（包括匿名用户）仍然可以读取和写入数据库。考虑到这一点，我们也希望在数据库上添加一些安全性。

# 行动时间-匿名访问用户数据库

让我们快速练习一下调用一个`curl`语句到`_users`数据库，看看为什么安全我们的数据很重要。

1.  打开**终端**。

1.  运行以下命令，将`your_username`替换为您刚刚创建的服务器管理员的用户名。

```php
**curl localhost:5984/_users/org.couchdb.user:your_username | python -mjson.tool** 

```

1.  **终端**将会回复类似于：

```php
**{
"_id": "org.couchdb.user:your_username",
"_rev": "1-b9af54a7cdc392c2c298591f0dcd81f3",
"name": "your_username",
"password_sha": "3bc7d6d86da6lfed6d4d82e1e4d1c3ca587aecc8",
"roles": [],
"salt": "9812acc4866acdec35c903f0cc072c1d",
"type": "user"
}** 

```

## 刚刚发生了什么？

你使用**终端**创建了一个`curl`请求来读取包含服务器管理员数据的文档。数据库中的密码是加密的，但有可能有人仍然可以解密密码或使用用户的用户名对他们进行攻击。考虑到这一点，让我们保护数据库，只有管理员才能访问这个数据库。

# 行动时间-保护用户数据库

让我们保护`_users`数据库，以便只有服务器管理员可以读取、写入和编辑系统中的其他用户。

1.  打开 Futon 到**概述**。

1.  点击`_users`数据库。

1.  点击屏幕顶部的**安全**。![行动时间-保护用户数据库](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/couchdb-php-webdev-bgd/img/3586_03_035.jpg)

1.  更改**管理员**和**读者**的**角色**的值为`["admins"]`，使其如下所示：![行动时间-保护用户数据库](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/couchdb-php-webdev-bgd/img/3586_03_040.jpg)

## 刚刚发生了什么？

您刚刚将`_users`数据库的**管理员**和**读者**角色更改为`["admins"]`，这样只有管理员才能读取或更改设计文档和读者列表。我们将角色的格式设置为`["admins"]`，因为它接受数组形式的角色。

# 行动时间 - 检查数据库是否安全

您的`_users`数据库应该是安全的，这样只有管理员才能读取或更改数据库的结构。让我们快速测试一下：

1.  打开**终端**。

1.  通过运行以下命令再次尝试读取用户文档。再次用服务管理员的用户名替换`your_username`：

```php
**curl localhost:5984/_users/org.couchdb.user:your_username** 

```

1.  **终端**将会返回以下内容：

```php
**{"error":"unauthorized","reason":"You are not authorized to access this db."}** 

```

## 刚刚发生了什么？

通过关闭 CouchDB 实例的管理员模式，认证模块开始起作用，以确保匿名用户无法读取数据库。

### 注意

我们将在以后进一步增强数据库的安全性，但这是向数据库添加安全性的最简单方法之一。

如果您再次尝试在命令行上玩耍，您将受到对`_users`数据库的限制，但您还会注意到`test-db`数据库的操作方式与之前一样，非常好！这正是我们想要的。您可能会问，既然启用了安全性，我如何通过命令行访问`_users`数据库？您必须通过将您的凭据传递给 RESTful JSON API 来证明您是管理员。

# 行动时间 - 访问启用了安全性的数据库

让我们尝试快速访问一个启用了安全性的数据库，通过在请求中传递用户名和密码。

1.  打开**终端**。

1.  通过运行以下命令查看在`_users`数据库中保存的所有文档。用您的管理员用户名和密码替换`username`和`password`。

```php
**curl username:password@localhost:5984/_users/_all_docs** 

```

1.  **终端**将会返回您在添加认证之前看到的相同数据。

```php
**{
"_id": "org.couchdb.user:your_username",
"_rev": "1-b9af54a7cdc392c2c298591f0dcd81f3",
"name": "your_username",
"password_sha": "3bc7d6d86da6lfed6d4d82e1e4d1c3ca587aecc8",
"roles": [],
"salt": "9812acc4866acdec35c903f0cc072c1d",
"type": "user"
}** 

```

## 刚刚发生了什么？

您刚刚向`_users`数据库发出了一个`GET`请求，并使用了我们之前创建的服务器管理员的用户名和密码进行了身份验证。一旦经过身份验证，我们就能够正常访问数据。如果您想在安全数据库上执行任何操作，只需在要处理的资源的 URL 之前添加`username:password@`即可。

## 突发测验

1.  根据[`couchdb.apache.org/`](http://couchdb.apache.org/)，CouchDB 的定义的第一句是什么？

1.  HTTP 使用的四个动词是什么，每个动词与 CRUD 的匹配是什么？

1.  访问 Futon 的 URL 是什么？

1.  对 CouchDB 来说，“管理员模式”是什么意思，以及如何将 CouchDB 退出这种模式？

1.  您如何通过命令行对安全数据库进行用户认证？

# 摘要

在本章中，我们学到了很多关于 CouchDB。让我们快速回顾一下

+   我们通过查看数据库、文档和 RESTful JSON API 来定义 CouchDB

+   我们将 CouchDB 与传统的关系型数据库（如 MySQL）进行了比较

+   我们使用`curl`语句与 CouchDB 的 RESTful JSON API 进行交互

+   我们使用 Futon 创建和更改文档

+   我们学会了如何向数据库添加安全性并测试其有效性

准备好了！在下一章中，我们将开始构建 PHP 框架，这将是我们在本书的其余部分中开发的平台。


# 第四章：开始你的应用程序

> 我们准备开始开发我们应用程序的框架！

在本章中，我们将：

+   从头开始创建一个简单的 PHP 框架 - Bones

+   学习如何使用 Git 进行源代码控制

+   添加功能到 Bones 来处理 URL 请求

+   构建视图和布局的支持，以便我们可以为我们的应用程序添加一个前端

+   添加代码以允许我们处理所有的 HTTP 方法

+   设置复杂的路由并将其构建到一个示例应用程序中

+   添加使用公共文件并在我们的框架中使用它们的能力

+   将我们的代码发布到 GitHub，以便我们可以管理我们的源代码

让我们开始吧！

# 在本书中我们将构建什么

在本书的其余部分，我们将创建一个类似 Twitter 的简单社交网络。让我们称之为`Verge`。

`Verge`将允许用户注册、登录和创建帖子。通过构建这个应用程序，我们将跳过大多数开发人员在构建应用程序时遇到的障碍，并学会依赖 CouchDB 来完成一些繁重的工作。

为了构建 Verge，我们将制作一个轻量级的 PHP 包装器，用于处理基本路由和 HTTP 请求，这些在前一章中提到过。让我们称这个框架为`Bones`。

# 骨架

在本书中，我们将构建一个非常轻量级的框架`Bones`来运行我们的应用程序。你可能会想*为什么我们要构建另一个框架？*这是一个合理的问题！有很多 PHP 框架，比如：Zend 框架，Cake，Symfony 等等。这些都是强大的框架，但它们也有一个陡峭的学习曲线，而且在本书中不可能涉及到它们的每一个。相反，我们将创建一个非常轻量级的 PHP 框架，它将帮助简化我们的开发，但不会有很多其他的花里胡哨。通过构建这个框架，你将更好地理解 HTTP 方法以及如何从头开始构建轻量级应用程序。一旦你使用 Bones 开发了这个应用程序，你应该很容易将你的知识应用到另一个框架上，因为我们将使用一些非常标准的流程。

如果你在本章遇到任何问题或渴望看到最终成品，那么你可以在 GitHub 上访问完整的 Bones 框架：[`github.com/timjuravich/bones`](http://https://github.com/timjuravich/bones)。我还将在本章末尾介绍一个简单的方法，让你可以获取所有这些代码。

让我们开始设置我们的项目。

# 项目设置

在本节中，我们将逐步创建用于我们代码的文件夹，并确保我们初始化 Git，以便我们可以跟踪我们向项目添加新功能时的源代码。

# 行动时间 - 为 Verge 创建目录

让我们通过在`/Library/WebServer/Documents`文件夹中创建一个名为`verge`的目录来开始设置我们的项目，并将该目录包含所有项目的代码。为了简洁起见，在本章中，我们将称`/Library/WebServer/Documents/verge`为我们的**工作**目录。

在我们的工作目录中，让我们创建四个新的文件夹，用于存放我们的源文件：

1.  创建一个名为`classes`的文件夹。这个文件夹将包含我们在这个项目中将要使用的 PHP 类对象

1.  创建一个名为`lib`的文件夹。这个文件夹将包含我们的应用程序依赖的 PHP 库，也就是我们的`Bones`框架和将与 CouchDB 通信的类。

1.  创建一个名为`public`的文件夹。这个文件夹将包含我们所有的公共文件，比如**层叠样式表（CSS）**，JavaScript 和我们的应用程序需要的图片。

1.  创建一个名为`views`的文件夹。这个文件夹将包含我们的布局和网页应用程序的不同页面。

如果你查看你的工作目录，本节的最终结果应该类似于以下截图：

![开始行动-为 Verge 创建目录](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/couchdb-php-webdev-bgd/img/3586_04_005.jpg)

## 刚刚发生了什么？

我们快速创建了一些占位符文件夹，用于组织本书其余部分中将添加的代码。

## 使用 Git 进行源代码控制

为了跟踪我们的应用程序、我们的进展，并允许我们在犯错时回滚，我们需要在我们的仓库上运行源代码控制。我们在第二章中安装了 Git，*设置您的开发环境*，所以让我们好好利用它。虽然有一些桌面客户端可以使用，但为了简单起见，我们将使用命令行，以便适用于所有人。

# 开始行动-初始化 Git 仓库

Git 需要在每个开发项目的根目录中初始化，以便跟踪所有项目文件。让我们为我们新创建的`verge`项目做这个！

1.  打开**终端**。

1.  输入以下命令以更改目录到我们的工作目录：

```php
**cd /Library/Webserver/Documents/verge/** 

```

1.  输入以下命令以初始化我们的 Git 目录：

```php
**git init** 

```

1.  Git 将回应以下内容：

```php
**Initialized empty Git repository in /Library/WebServer/Documents/verge/.git/** 

```

1.  保持您的**终端**窗口打开，以便在本章中与 Git 进行交互。

## 刚刚发生了什么？

我们使用**终端**通过在工作目录中使用命令`git init`来初始化我们的 Git 仓库。Git 回应让我们知道一切都进行得很顺利。现在我们已经设置好了 Git 仓库，当创建新文件时，我们需要将每个文件添加到源代码控制中。将文件添加到 Git 的语法很简单，`git add path_to_file`。您还可以通过输入`"git add ."`的通配符语句递归地添加目录中的所有文件。在本章的大部分部分，我们将快速添加文件，因此我们将使用`"git add ."`。

# 实现基本路由

在我们开始创建`Bones`之前，让我们先看看为什么我们需要它的帮助。让我们首先创建一个简单的文件，确保我们的应用程序已经设置好并准备就绪。

# 开始行动-创建我们的第一个文件：index.php

我们将创建的第一个文件是一个名为`index.php`的文件。这个文件将处理我们应用程序的所有请求，并最终将成为主要的应用程序控制器，将与`Bones`进行通信。

1.  在工作目录中创建`index.php`，并添加以下文本：

```php
<?php echo 'Welcome to Verge'; ?>

```

1.  打开您的浏览器，转到网址：`http://localhost/verge/`。

1.  `index.php`文件将显示以下文字：

```php
**Welcome to Verge** 

```

## 刚刚发生了什么？

我们创建了一个简单的 PHP 文件，名为`index.php`，目前只是简单地返回文本给我们。我们只能在直接访问`http://localhost/verge/`或`http://localhost/verge/index.php`时访问这个文件。然而，我们的目标是`index.php`将被我们工作目录中的几乎每个请求所访问（除了我们的`public`文件）。为了做到这一点，我们需要添加一个`.htaccess`文件，允许我们使用 URL 重写。

## .htaccess 文件

`.htaccess`文件被称为分布式配置文件，它允许 Apache 配置在目录基础上被覆盖。如果您记得，在第一章中，*CouchDB 简介*，我们确保可以通过改变一些代码行来使用`.htaccess`文件，以`Override All`。大多数 PHP 框架都以我们将要使用的方式利用`.htaccess`文件，因此您需要熟悉这个过程。

# 开始行动-创建.htaccess 文件

为了处理对目录的所有请求，我们将在工作目录中创建一个`.htaccess`文件。

1.  在工作目录中创建一个名为`.htaccess`的文件。

1.  将以下代码添加到文件中：

```php
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule ^(.*)$ index.php?request=$1 [QSA,L]
</IfModule>

```

1.  在工作目录中打开`index.php`文件。

1.  更改`index.php`中的代码以匹配以下内容：

```php
<?php echo $_GET['request']; ?>

```

1.  打开浏览器，转到`http://localhost/verge/test/abc`，然后转到`http://localhost/verge/test/123`。注意页面会以你在根 URL 末尾输入的相同值回应你。![执行操作-创建.htaccess 文件](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/couchdb-php-webdev-bgd/img/3586_04_007.jpg)

## 刚刚发生了什么？

首先，我们创建了一个`.htaccess`文件，以便启用 URL 重写。第一行`<IfModule mod_rewrite.c>`检查我们是否启用了`mod_rewrite`模块。这将是`true`，因为我们在第二章的`http.conf`文件中启用了`mod_rewrite`。

文件的下一行说`RewriteEngine On`，它确切地做了你认为它会做的事情；它打开了 Apache 的`RewriteEngine`并等待一些条件和规则。接下来，我们设置了两个`RewriteCond`（重写条件）。第一个`RewriteCond`告诉`RewriteEngine`，如果传递的 URL 与现有文件的位置不匹配（这就是`f`的含义），则重写 URL。第二个`RewriteCond`告诉`RewriteEngine`，重写 URL 如果它不是已经存在的目录（这就是`-d`的含义）。最后，我们设置了我们的`RewriteRule`，它表示当输入一个 URL 时，将其转发到第二个值（目标）。这个`RewriteRule`告诉`RewriteEngine`，传递到这个目录的任何 URL 都应该被强制通过索引文件，并将路由传递给`index.php`文件，形成一个名为`request`的查询字符串。

最后，字符串是`[QSA, L]`。让我解释一下这是什么意思。`QSA`表示，如果有任何查询字符串添加到请求中，请将其附加到重写目标。`L`表示，停止尝试查找匹配项，并且不应用任何其他规则。

然后，你打开了`index.php`文件，并更改了代码以输出`request`变量。现在你知道，输入浏览器的路由将以查询字符串的形式传递给`index.php`文件。

有了所有这些代码，我们测试了一切，通过转到 URL`http://localhost/verge/test/abc`，我们的`index.php`文件返回了`test/abc`。当我们将 URL 更改为`http://localhost/verge/test/123`时，我们的`index.php`文件将`test/123`返回给我们。

## 拼凑 URL

在这一点上，我们技术上可以用一堆`if`语句拼凑在一起，让我们的网站提供不同的内容。例如，我们可以根据 URL 显示不同的内容，只需将一些代码添加到`index.php`中，如下所示：

```php
if ($_GET['request'] == '') {
echo －Welcome To Verge－;
} elseif ($_GET['request'] == 'signup') {
echo "Sign Up!";
}

```

在这段代码中，如果用户转到 URL`http://localhost/verge`，他们的浏览器将显示：

```php
**Welcome to Verge** 

```

同样，如果用户转到`http://localhost/verge/signup`，他们的浏览器将显示：

```php
**Sign Up!** 

```

我们可以进一步扩展这种思维方式，通过编写各种`if`语句，将我们的代码串联成一个长文件，并立即开始编写我们的应用程序。然而，这将是一个维护的噩梦，难以调试，并且一般来说是不好的做法。

相反，让我们删除`index.php`文件中的所有代码，专注于以正确的方式构建我们的项目。在本章的其余部分，我们将致力于创建一个名为`Bones`的简单框架，它将为我们处理一些请求的繁重工作。

## 创建 Bones 的骨架

正如我之前提到的，`Bones`是一个非常轻量级的框架，总共只有 100 多行代码，全部都在一个文件中。在本节中，我们将开始形成一个结构，以便在接下来的章节中构建更多的功能。

# 执行操作-将我们的应用程序连接到 Bones

让我们首先创建`Bones`库，然后将我们的`index.php`文件连接到它。

1.  在我们的工作目录的`lib`文件夹中创建一个名为`bones.php`的文件(`/Library/Webserver/Documents/verge/lib/bones.php`)。

1.  将以下代码添加到我们工作目录中的`index.php`文件中，以便我们可以与新创建的`bones.php`文件进行通信：

```php
<?php
include 'lib/bones.php';

```

## 刚刚发生了什么？

这段代码所做的就是包含我们的`lib/bones.php`文件，现在这已经足够了！请注意，我们没有用`?>`结束文件，这可能不是你习惯看到的。`?>`标签实际上是可选的，在我们的情况下，不使用它可以减少不需要的空白，并且在代码后面添加响应头，如果需要的话。

## 使用 Bones 处理请求

为了说明我们计划使用`Bones`类做什么，让我们通过一个快速示例来看看我们希望在本节结束时实现的目标。

+   如果浏览器访问 URL `http://localhost/verge/signup`，我们希望`Bones`拦截调用并将其解释为`http://localhost/verge/index.php?request=signup`。

+   然后，`Bones`将查看我们在`index.php`文件中定义的路由列表，并查看是否有匹配。

+   如果确实有匹配，`Bones`将执行匹配函数的回调并执行该路由内的操作。

如果以上内容有些令人困惑，不用担心。随着我们慢慢构建这个功能，希望它会开始变得有意义。

# 行动时间-创建 Bones 的类结构

让我们通过向我们的工作目录中的`lib/bones.php`文件添加以下代码来开始构建`Bones`类：

`/Library/Webserver/Documents/verge/lib/bones.php`

```php
<?php
class Bones {
private static $instance;
public static $route_found = false;
public $route = '';
public static function get_instance() {
if (!isset(self::$instance)) {
self::$instance = new Bones();
}
return self::$instance;
}

```

## 刚刚发生了什么？

我们刚刚创建了我们的`Bones`类，添加了一些`private`和`public`变量，以及一个名为`get_instance()`的奇怪函数。私有静态变量`$instance`与函数`get_instance()`结合在一起，形成了所谓的**单例模式**。

单例模式允许我们的`Bones`类不仅仅是一个简单的类，还可以是一个对象。这意味着每次调用我们的`Bones`类时，我们都在访问一个现有的对象。但如果对象不存在，它将为我们创建一个新的对象来使用。这是一个有点复杂的想法；然而，我希望随着我们在后面使用它，它开始变得有意义。

### 访问路由

现在我们已经有了我们类的基本概念，让我们添加一些函数来获取和解释路由（传递给`Bones`的 URL）每次创建新请求时。然后我们将在下一节中将结果与每个可能的路由进行比较。

# 行动时间-创建函数以访问 Bones 创建时的路由

为了弄清楚请求中传递了什么路由，我们需要在`lib/bones.php`文件的`get_instance()`函数的结束括号下面添加以下两个函数：

`/Library/Webserver/Documents/verge/lib/bones.php`

```php
public static function get_instance() {
if (!isset(self::$instance)) {
self::$instance = new Bones();
}
return self::$instance;
}
**public function __construct() {
$this->route = $this->get_route();
}
protected function get_route() {
parse_str($_SERVER['QUERY_STRING'], $route);
if ($route) {
return '/' . $route['request'];
} else {
return '/';
}
}** 

```

## 刚刚发生了什么？

在这段代码中，我们添加了一个名为`__construct()`的函数，这是一个在每次创建类时自动调用的函数。我们的`__construct()`函数然后调用另一个名为`get_route()`的函数，它将从我们的请求查询字符串中获取路由（如果有的话）并将其返回给实例的`route`变量。

### 匹配 URL

为了匹配我们应用程序的路由，我们需要将每个可能的路由通过一个名为`register`的函数。

# 行动时间-创建注册函数以匹配路由

`register`函数将是`Bones`类中最重要的函数之一，但我们将从在`lib/bones.php`文件的末尾添加以下代码开始：

`/Library/Webserver/Documents/verge/lib/bones.php`

```php
public static function register($route, $callback) {
$bones = static::get_instance();
if ($route == $bones->route && !static::$route_found) {
static::$route_found = true;
echo $callback($bones);
} else {
return false;
}
}

```

## 刚刚发生了什么？

我们首先创建了一个名为`register`的公共静态函数。这个函数有两个参数：`$route`和`$callback`。`$route`包含我们试图匹配实际路由的路由，`$callback`是如果路由匹配则将被执行的函数。请注意，在`register`函数的开头，我们调用了我们的`Bones`实例，使用`static:get_instance()`函数。这就是单例模式的作用，将`Bones`对象的单一实例返回给我们。

然后`register`函数检查我们通过浏览器访问的路由是否与传入函数的路由匹配。如果匹配，我们的`$route_found`变量将被设置为`true`，这将允许我们跳过查看其余的路由。`register`函数将执行一个回调函数，该函数将执行我们在路由中定义的工作。我们的`Bones`实例也将与回调函数一起传递，这样我们就可以利用它。如果路由不匹配，我们将返回`false`，以便我们知道路由不匹配。

现在我们已经完成了我们在`Bones`中的工作。所以，请确保用以下方式结束你的类：

```php
}

```

## 从我们的应用程序调用`register`函数

我们现在对`Bones`应该做什么有了基本的了解，但我们缺少一个将我们的`index.php`和`lib/bones.php`文件联系在一起的函数。我们最终将创建四个函数来做到这一点，每个函数对应一个 HTTP 方法。但是，现在让我们先创建我们的`get`函数。

# 行动时间——在我们的 Bones 类中创建一个 get 函数

让我们在`lib/bones.php`文件的顶部创建一个`get`函数，在`<?php`标签之后，在我们定义`Bones`类之前：

`/Library/Webserver/Documents/verge/lib/bones.php`

```php
<?php
ini_set('display_errors','On');
error_reporting(E_ERROR | E_PARSE);
**function get($route, $callback) {
Bones::register($route, $callback);
}** 
class Bones {
...
}

```

## 刚刚发生了什么？

这个函数位于`lib/bones.php`文件中，并且被调用来处理你在`index.php`文件中定义的每个`get`路由。这个函数是一个简单的传递函数，将路由和回调传递给`Bones`的`register`函数。

我们是否在同一页面上？

在这一部分我们做了很多事情。让我们仔细检查一下你的代码是否与我的代码匹配：

`/Library/Webserver/Documents/verge/lib/bones.php`

```php
<?php
function get($route, $callback) {
Bones::register($route, $callback);
}
class Bones {
private static $instance;
public static $route_found = false;
public $route = '';
public function __construct() {
$this->route = $this->get_route();
}
public static function get_instance() {
if (!isset(self::$instance)) {
self::$instance = new Bones();
}
return self::$instance;
}
public static function register($route, $callback) {
$bones = static::get_instance();
if ($route == $bones->route && !static::$route_found) {
static::$route_found = true;
echo $callback($bones);
} else {
return false;
}
}
protected function get_route() {
parse_str($_SERVER['QUERY_STRING'], $route);
if ($route) {
return '/' . $route['request'];
} else {
return '/';
}
}
}

```

### 为我们的应用程序添加路由

我们现在已经完成了我们的`lib/bones.php`文件。我们所需要做的就是在我们的`index.php`文件中添加一些路由，调用`lib/bones.php`文件夹中的`get`函数。

# 行动时间——为我们测试`Bones`的路由创建路由

打开`index.php`文件，添加以下两个路由，以便我们可以测试我们的新代码：

```php
<?php
include 'lib/bones.php';
**get('/', function($app) {
echo "Home";
});
get('/signup', function($app) {
echo "Signup!";
});** 

```

## 刚刚发生了什么？

我们刚刚为我们的`Bones`类创建了两个路由，分别处理`/`（即根 URL）和`/signup`。

在我们刚刚添加的代码中有一些需要注意的地方：

+   我们的两个`get`路由现在都是干净的小函数，包括我们的路由和一个将作为回调函数的函数。

+   一旦函数被执行，我们就使用`echo`来显示简单的文本。

+   当一个路由匹配并且从`Bones`执行回调时，`Bones`的实例将作为变量`$app`返回，可以在回调函数中的任何地方使用

## 测试一下！

我们已经准备好测试我们对`Bones`的新添加内容了！打开你的浏览器，然后转到`http://localhost/verge/`。你会看到`Home`这个词。然后将你的浏览器指向`http://localhost/verge/signup`，你会看到`Signup!`这个文本。

虽然我们的应用程序仍然非常基础，但我希望你能看到以这种简单的方式添加路由的强大之处。在继续下一部分之前，随意玩耍并添加一些更多的路由。

## 将更改添加到 Git

在这一部分，我们启动了我们的`lib/bones.php`库，并添加了一些简单的路由。让我们将所有的更改都添加到 Git 中，这样我们就可以跟踪我们的进度了。

1.  打开**终端**。

1.  输入以下命令以更改目录到我们的工作目录：

```php
**cd /Library/Webserver/Documents/verge/** 

```

1.  通过输入以下命令将我们在此目录中创建的所有文件添加进来：

```php
**git add .** 

```

1.  给 Git 一个描述，说明自上次提交以来我们做了什么：

```php
**git commit am 'Created bones.php and added simple support for routing'** 

```

# 处理布局和视图

我们将暂时停止路由的操作，添加一些有趣的前端功能。每个应用程序都由一些页面组成，我们将称之为**视图**。每个视图都有一个标准的布局，这些视图将填充。布局是视图的包装器，可能包含到 CSS 引用、导航或其他你认为对每个视图都是通用的内容。

## 使用 Bones 支持视图和布局

为了支持视图和布局，我们需要向我们的`Bones`类添加一些额外的功能。

# 行动时间-使用常量获取工作目录的位置

我们需要做的第一件事是创建一个名为`ROOT`的命名常量，它将给出我们工作目录的完整位置。到目前为止，我们还没有不得不包含任何额外的文件，但是随着我们的布局和视图，如果我们不添加一些功能来获取工作目录，它将开始变得有点困难。为了支持这一点，让我们在`lib/bones.php`文件的顶部添加一行简单的代码。

```php
<?php
ini_set('display_errors','On');
error_reporting(E_ERROR | E_PARSE);
**define('ROOT', __DIR__ . '/..');** 
function get($route, $callback) {
...
}

```

## 刚刚发生了什么？

这行代码创建了一个名为`ROOT`的常量，我们可以在整个代码中使用它来引用工作目录。`__DIR__`给出了当前文件的根目录(`/Library/Webserver/Documents/verge/lib`)。因此，我们将希望通过在路径后添加`/.`来查看另一个目录。

# 行动时间-允许 Bones 存储变量和内容路径

我们需要能够从`index.php`中设置和接收变量到我们的视图中。因此，让我们将这个支持添加到`Bones`中。

1.  让我们定义一个名为`$vars`的`public`数组，它将允许我们从`index.php`中的路由中存储变量，并且定义一个名为`$content`的字符串，它将存储视图的路径，这些视图将加载到我们的布局中。我们将首先在`lib/bones.php`类中添加两个变量：

```php
class Bones {
public $route = '';
**public $content = '';
public $vars = array();** 
public function __construct() {
...
}

```

1.  为了能够从`index.php`文件中设置变量，我们将创建一个简单的名为`set`的函数，它将允许我们传递一个索引和一个变量的值，并将其保存到当前的`Bones`实例中。让我们在`lib/bones.php`中的`get_route()`函数之后创建一个名为`set`的函数。

```php
protected function get_route() {
...
}
**public function set($index, $value) {
$this->vars[$index] = $value;
}** 

```

## 刚刚发生了什么？

我们向`Bones`类添加了两个新变量`$vars`和`$content`。它们两者将在下一节中被使用。然后我们创建了一个`set`函数，允许我们从`index.php`文件发送变量到我们的`Bones`类，以便我们可以在我们的视图中显示它们。

接下来，我们需要添加能够从`index.php`中调用视图并显示它们的功能。将包含此功能的函数称为`render`。

# 行动时间-通过在 index.php 中调用它来允许我们的应用程序显示视图

我们将首先创建一个名为`render`的`public`函数，它接受两个参数。第一个是`$view`，它是你想要显示的视图的名称（或路径），第二个是`$layout`，它将定义我们用来显示视图的布局。布局也将有一个默认值，以便我们可以保持简单，以处理视图的显示。在`lib/bones.php`文件中的`set`函数之后添加以下代码：

```php
public function set($index, $value) {
$this->vars[$index] = $value;
}
**public function render($view, $layout = "layout") {
$this->content = ROOT. '/views/' . $view . '.php';
foreach ($this->vars as $key => $value) {
$$key = $value;
}
if (!$layout) {
include($this->content);
} else {
include(ROOT. '/views/' . $layout . '.php');
}
}** 

```

## 刚刚发生了什么？

我们创建了`render`函数，它将设置我们想要在布局中显示的视图的路径。所有的视图都将保存在我们在本章前面创建的`views`目录中。然后，代码循环遍历实例的`vars`数组中设置的每个变量。对于每个变量，我们使用一个奇怪的语法`$$`，这使我们能够使用我们在数组中定义的键来设置一个变量。这将允许我们直接在我们的视图中引用这些变量。最后，我们添加了一个简单的`if`语句，用于检查是否定义了一个`layout`文件。如果未定义`$layout`，我们将简单地返回视图的内容。如果定义了`$layout`，我们将包含布局，这将返回我们的视图包裹在定义的布局中。我们这样做是为了以后避免使用布局。例如，在一个 AJAX 调用中，我们可能只想返回视图而不包含布局。

# 行动时间——创建一个简单的布局文件

在这一部分，我们将创建一个名为`layout.php`的简单布局文件。请记住，在我们的`render`函数中，`$layout`有一个默认值，它被设置为`layout`。这意味着，默认情况下，`Bones`将查找`views/layout.php`。所以，现在让我们创建这个文件。

1.  首先，在我们的`views`目录中创建一个名为`layout.php`的新文件。

1.  在新创建的`views/layout.php`中添加以下代码：

```php
<html>
<body>
<h1>Verge</h1>
<?php include($this->content); ?>
</body>
</html>

```

## 刚才发生了什么？

我们创建了一个非常简单的 HTML 布局，它将在应用程序的所有视图中使用。如果你记得，我们在`Bones`的`render`函数中使用了路径设置为`$content`变量，我们在前一个函数中设置了它，并且也包含了它，这样我们就可以显示视图。

## 向我们的应用程序添加视图

现在我们已经把所有的部分都放在了视图中，我们只需要在`index.php`文件中添加几行代码，这样我们就可以呈现视图了。

# 行动时间——在我们的路由中呈现视图

让我们用以下代码替换我们路由中已经输出文本的现有部分，这些代码将实际使用我们的新框架：

```php
get('/', function($app) {
**$app->set('message', 'Welcome Back!');
$app->render('home');** 
});
get('/signup', function($app) {
**$app->render('signup');** 
});

```

## 刚才发生了什么？

对于根路由，我们使用了我们的新函数`set`来传递一个键为`'message'`的变量，并且它的内容是`'Welcome Back!'`，然后我们告诉`Bones`呈现主页视图。对于`signup`路由，我们只是呈现`signup`视图。

# 行动时间——创建视图

我们几乎准备好测试这段新代码了，但我们需要创建实际的视图，这样我们才能显示它们。

1.  首先，在我们的工作目录中的`views`文件夹中创建两个新文件，分别命名为`home.php`和`signup.php`。

1.  通过编写以下代码将以下代码添加到`views/home.php`文件中：

```php
Home Page <br /><br />
<?php echo $message; ?>

```

1.  将以下代码添加到`views/signup.php`文件中：

```php
Signup Now!

```

## 刚才发生了什么？

我们创建了两个简单的视图，它们将由`index.php`文件呈现。`views/home.php`文件中的一行代码`<?php echo $message; ?>`将显示传递给我们的`Bones`库的`index.php`文件中的名称为 message 的变量。试一下吧！

打开你的浏览器，转到`http://localhost/verge/`或`http://localhost/verge/signup`，你会看到我们所有的辛勤工作都得到了回报。我们的布局现在正在呈现，我们的视图正在显示。我们还能够从`index.php`传递一个名为`message`的变量，并在我们的主页视图上输出该值。我希望你能开始看到我们迄今为止为`Bones`添加的功能的强大之处！

## 将更改添加到 Git

到目前为止，我们已经为布局和视图添加了支持，这将帮助我们构建应用程序的所有页面。让我们把所有的改变都添加到 Git 中，这样我们就可以跟踪我们的进展。

1.  打开**终端**。

1.  输入以下命令以更改目录到我们的工作目录：

```php
**cd /Library/Webserver/Documents/verge/** 

```

1.  通过输入以下命令，将我们在该目录中创建的所有文件都添加进去：

```php
**git add .** 

```

1.  给 Git 一个描述，说明我们自上次提交以来做了什么：

```php
**git commit am 'Added support for views and layouts'** 

```

# 添加对其他 HTTP 方法的支持

到目前为止，我们一直在处理`GET`调用，但在 Web 应用程序中，我们将需要支持我们在上一章中讨论过的所有`HTTP`方法：`GET, PUT, POST`和`DELETE`。

# 行动时间-检索请求中使用的 HTTP 方法

我们已经完成了支持、捕获和处理 HTTP 请求所需的大部分繁重工作。我们只需要插入几行额外的代码。

1.  让我们在我们的`Bones`类中添加一个变量`$method`，在我们的`$route`变量之后。这个变量将存储每个请求上执行的`HTTP`方法：

```php
class Bones {
private static $instance;
public static $route_found = false;
public $route = '';
**public $method = '';** 
public $content = '';

```

1.  为了让我们在每个请求中获取方法，我们需要在我们的`__construct()`函数中添加一行代码，名为`get_route()`，并将结果的值保存在我们的实例变量`$method`中。这意味着当`Bones`在每个请求中被创建时，它也将检索方法并将其保存到我们的`Bones`实例中，以便我们以后可以使用它。通过添加以下代码来实现这一点：

```php
public function __construct() {
$this->route = $this->get_route();
**$this->method = $this->get_method();** 
}

```

1.  让我们创建一个名为`get_method()`的函数，这样我们的`__construct()`函数就可以调用它。让我们在我们的`get_route()`方法之后添加它：

```php
protected function get_route() {
parse_str($_SERVER['QUERY_STRING'], $route);
if ($route) {
return '/' . $route['request'];
} else {
return '/';
}
}
protected function get_method() {
**return isset($_SERVER['REQUEST_METHOD']) ? $_SERVER['REQUEST_METHOD'] : 'GET';
}** 

```

## 刚刚发生了什么？

我们在你的`Bones`类中添加了一个变量`$method`。这个变量是由函数`get_route()`设置的，并且每次通过`__construct()`方法向`Bones`发出请求时，都会将一个值返回给实例`$method`变量。这可能听起来非常令人困惑，但请耐心等待。

`get_route()`函数使用一个名为`$_SERVER`的数组，这个数组是由 Web 服务器创建的，并允许我们检索有关请求和执行的信息。这个简单的一行代码是在说，如果`$_SERVER`中设置了`REQUEST_METHOD`，那么就返回它，但如果由于某种原因`REQUEST_METHOD`没有设置，就返回`GET`以确保方法的安全。

# 行动时间-修改注册以支持不同的方法

现在我们在每个请求中检索方法，我们需要修改我们的注册函数，以便我们可以在每个路由中传递`$method`，以便它们能够正确匹配。

1.  在`lib/bones.php`的`register`函数中添加`$method`，以便我们可以将一个方法传递到函数中：

```php
**public static function register($route, $callback, $method) {** 
$bones = static::get_instance();

```

1.  现在，我们需要更新我们在注册函数中的简单路由匹配，以检查传递的路由`$method`是否与我们的实例变量`$bones->method`匹配，这是实际发生在服务器上的方法：

```php
public static function register($route, $callback, $method) {
$bones = static::get_instance();
**if ($route == $bones->route && !static:: $route_found && $bones->method == $method) {** 
static::$route_found = true;
echo $callback($bones);
} else {
return false;
}
}

```

## 刚刚发生了什么？

我们在我们的`register`函数中添加了一个`$method`参数。然后我们在我们的`register`函数中使用这个`$method`变量，通过将它添加到必须为`true`的参数列表中，以便路由被视为匹配。因此，如果路由匹配，但如果它是一个不同于预期的`HTTP`方法，它将被忽略。这将允许您创建具有相同名称但根据传递的方法而有所不同的路由。听起来就像我们在上一章中讨论的`REST`，不是吗？

为了执行`register`函数，让我们回顾一下我们在`lib/bones.php`文件开头的`get`函数：

```php
<?php
ini_set('display_errors','On');
error_reporting(E_ERROR | E_PARSE);
define('ROOT', dirname(dirname(__FILE__)));
function get($route, $callback) {
Bones::register($route, $callback);
}

```

希望很容易看出我们接下来要做什么。让我们扩展我们当前的`get`函数，并创建另外三个函数，分别对应剩下的每种 HTTP 方法，确保我们以大写形式传递每种方法的名称。

```php
<?php
ini_set('display_errors','On');
error_reporting(E_ERROR | E_PARSE);
define('ROOT', dirname(dirname(__FILE__)));
**function get($route, $callback) {
Bones::register($route, $callback, 'GET');
}
function post($route, $callback) {
Bones::register($route, $callback, 'POST');
}
function put($route, $callback) {
Bones::register($route, $callback, 'PUT');
}
function delete($route, $callback) {
Bones::register($route, $callback, 'DELETE');
}** 

```

我们已经在我们的 Bones 库中添加了所有需要的功能，以便我们可以使用其他 HTTP 方法，非常简单对吧？

# 行动时间-向 Bones 添加简单但强大的辅助功能

让我们在我们的`lib/bones.php`文件中添加两个小函数，这将帮助我们使用表单。

1.  添加一个名为`form`的函数，如下所示：

```php
public function form($key) {
return $_POST[$key];
}

```

1.  添加一个名为`make_route`的函数。这个函数将允许我们的`Bones`实例创建干净的链接，以便我们可以链接到应用程序中的其他资源：

```php
public function make_route($path = '') {
$url = explode("/", $_SERVER['PHP_SELF']);
if ($url[1] == "index.php") {
return $path;
} else {
return '/' . $url[1] . $path;
}
}

```

## 刚刚发生了什么？

我们添加了一个名为`form`的简单函数，它作为`$_POST`数组的包装器，这是通过`HTTP POST`方法传递的变量数组。这将允许我们在`POST`后收集值。我们创建的下一个函数叫做`make_route`。这个函数很快将被用于创建干净的链接，以便我们可以链接到应用程序中的其他资源。

## 使用表单测试我们的 HTTP 方法支持

我们在这里添加了一些很酷的东西。让我们继续测试新添加的 HTTP 方法的支持。

打开文件`verge/views/signup.php`，并添加一个简单的表单，类似于以下内容：

```php
Signup
**<form action="<?php echo $this->make_route('/signup') ?>" method="post">
<label for="name">Name</label>
<input id="name" name="name" type="text"> <br />
<input type="Submit" value="Submit">
</form>** 

```

我们通过使用`$this->make_route`设置了表单的`action`属性。`$this->make_route`使用我们的`Bones`实例来创建一个解析为我们的`signup`路由的路由。然后我们定义了使用`post`方法。表单的其余部分都是相当标准的，包括`name`的标签和文本框，以及用于处理表单的`submit`按钮。

如果您在浏览器中输入`http://localhost/verge/signup`，您现在将看到表单，但如果您单击`submit`按钮，您将被发送到一个空白页面。这是因为我们还没有在`index.php`文件中定义我们的`post`方法。

打开`index.php`文件，并添加以下代码：

```php
get('/signup', function($app) {
$app->render('signup');
});
**post('/signup', function($app) {
$app->set('message', 'Thanks for Signing Up ' . $app->form('name') . '!');
$app->render('home');
});** 

```

让我们走过这段代码，确保清楚我们在这里做什么。我们告诉`Bones`查找`/signup`路由，并将`post`方法发送到它。一旦解析了这个路由，回调将使用一些文本设置变量`message`的值。文本包括我们创建的新函数`$app->form('name')`。这个函数正在从具有属性`name`的表单中获取发布的值。然后我们将告诉`Bones`渲染主视图，以便我们可以看到消息。

## 测试一下！

现在让我们试试这些！

1.  打开您的浏览器，转到：`http://localhost/verge/signup`。

1.  您的浏览器应该显示以下内容：![测试一下！](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/couchdb-php-webdev-bgd/img/3586_04_010.jpg)

1.  输入您的名字（我输入了`Tim`），然后单击**提交**。![测试一下！](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/couchdb-php-webdev-bgd/img/3586_04_015.jpg)

## 将更改添加到 Git

在这一部分，我们为所有的 HTTP 方法添加了支持，这将允许我们处理任何类型的请求。让我们将所有的更改添加到 Git，以便我们可以跟踪我们的进展。

1.  打开**终端**。

1.  输入以下命令以更改目录到我们的工作目录：

```php
**cd /Library/Webserver/Documents/verge/** 

```

1.  通过输入以下命令来添加我们在此目录中创建的所有文件：

```php
**git add .** 

```

1.  给 Git 描述我们自上次提交以来所做的工作：

```php
**git commit -am 'Added support for all HTTP methods'** 

```

# 添加对复杂路由的支持

我们的框架在技术上已经准备好让我们开始构建。但是，我们还没有足够的支持来匹配和处理复杂的路由。由于大多数应用程序都需要这个，让我们快速添加它。

## 处理复杂的路由

例如，在`index.php`文件中，我们希望能够为用户配置文件定义路由。这个路由可能是`/user/:username`。在这种情况下，`:username`将是一个我们可以访问的变量。因此，如果您访问 URL`/user/tim`，您可以使用`Bones`来获取 URL 的该部分，并返回其值。

让我们首先在我们的`lib/bones.php`文件的`__construct`函数中添加另一个变量和另一个调用：

```php
public $content = '';
public $vars = array();
**public $route_segments = array();
public $route_variables = array();** 
public function __construct() {
$this->route = $this->get_route();
**$this->route_segments = explode('/', trim($this->route, '/'));** 
$this->method = $this->get_method();
}

```

我们刚刚在我们的`Bones`实例中添加了两个变量，称为`$route_segments`和`$route_variables。$route_segments`每次使用`__construct()`创建`Bones`对象时都会设置。`$route_segments`数组通过在斜杠(/)上分割它们来将`$route`分割成可用的段。这将允许我们检查浏览器发送到`Bones`的 URL，然后决定路由是否匹配。`$route_variables`将是通过路由传递的变量的库，它将使我们能够使用`index.php`文件。

现在，让我们开始修改 `register` 函数，以便处理这些特殊路由。让我们删除所有代码，然后慢慢添加一些代码。

```php
public static function register($route, $callback, $method) {
if (!static::$route_found) {
$bones = static::get_instance();
$url_parts = explode('/', trim($route, '/'));
$matched = null;

```

我们添加了一个 `if` 语句，检查路由是否已经匹配。如果是，我们就忽略 `register` 函数中的其他所有内容。然后，我们添加了 `$url_parts`。这将拆分我们传递到注册函数中的路由，并将帮助我们将此路由与浏览器实际访问的路由进行比较。

### 注意

当我们完成这一部分时，我们将关闭 `if` 语句和注册函数；不要忘记这样做！

让我们开始比较 `$bones->route_segments`（浏览器访问的路由）和 `$url_parts`（我们正在尝试匹配的路由）。首先，让我们检查确保 `$route_segments` 和 `$url_parts` 的长度相同。这将确保我们节省时间，因为我们已经知道它不匹配。

在 `lib/bones.php` 的 `register` 函数中添加以下代码：

```php
if (count($bones->route_segments) == count($url_parts)) {
} else {
// Routes are different lengths
$matched = false;
}

```

现在，在 `if` 语句中添加一个 `for` 循环，循环每个 `$url_parts`，并尝试将其与 `route_segments` 匹配。

```php
if (count($bones->route_segments) == count($url_parts)) {
**foreach ($url_parts as $key=>$part) {
}** 
} else {
// Routes are different lengths
$matched = false;
}

```

为了识别变量，我们将检查冒号（:）的存在。这表示该段包含变量值。

```php
if (count($bones->route_segments) == count($url_parts)) {
foreach ($url_parts as $key=>$part) {
**if (strpos($part, ":") !== false) {
// Contains a route variable
} else {
// Does not contain a route variable
}** 
}
} else {
// Routes are different lengths
$matched = false;
}

```

接下来，让我们添加一行代码，将段的值保存到我们的 `$route_variables` 数组中，以便稍后使用。仅仅因为我们找到一个匹配的变量，并不意味着整个路由就匹配了，所以我们暂时不会设置 `$matched = true`。

```php
if (strpos($part, ":") !== false) {
// Contains a route variable
**$bones->route_variables[substr($part, 1)] = $bones->route_segments[$key];** 
} else {
// Does not contain a route variable
}

```

让我们分解刚刚添加的代码行。第二部分 `$bones->route_segments[$key]` 获取传递给浏览器的段的值，并且具有与我们当前循环的段相同的索引。

然后，`$bones->route_variables[substr($part, 1)]` 将值保存到 `$route_variables` 数组中，索引设置为 `$part` 的值，然后使用 `substr` 确保我们不包括键中的冒号。

这段代码有点混乱。所以，让我们快速通过一个使用案例：

1.  打开你的浏览器，输入 URL `/users/tim`。

1.  这个注册路由开始检查路由 `/users/:username`。

1.  `$bones->route_segments[$key]` 将返回 `tim`。

1.  `$bones->route_variables[substr($part, 1)]` 将保存值，并使我们能够稍后检索值 `tim`。

现在，让我们完成这个 `if` 语句，检查不包含路由变量的段（`if` 语句的 `else` 部分）。在这个区域，我们将检查我们正在检查的段是否与从浏览器的 URL 传递的段匹配。

```php
} else {
// Does not contain a route variable
**if ($part == $bones->route_segments[$key]) {
if (!$matched) {
// Routes match
$matched = true;
}
} else {
// Routes don't match
$matched = false;
}**
}

```

我们刚刚添加的代码检查我们循环遍历的 `$part` 是否与 `$route_segments` 中的并行段匹配。然后，我们检查是否已经标记此路由不匹配。这告诉我们，在先前的段检查中，我们已经标记它为不匹配。如果路由不匹配，我们将设置 `$matched = false`。这将告诉我们 URL 不匹配，并且我们可以忽略路由的其余部分。

让我们为路由匹配谜题添加最后一部分。这个语句看起来与我们旧的匹配语句相似，但实际上会更加简洁。

```php
if (!$matched || $bones->method != $method) {
return false;
} else {
static::$route_found = true;
echo $callback($bones);
}

```

这段代码检查我们的路由是否与上面的匹配语句匹配，查看 `$matched` 变量。然后，我们检查 HTTP 方法是否与我们检查的路由匹配。如果没有匹配，我们返回 `false` 并退出该函数。如果匹配，我们设置 `$route_found = true`，然后对路由执行回调，这将执行 `index.php` 文件中定义的路由内的代码。

最后，让我们关闭`if $route_found`语句和`register`函数，通过添加闭合括号来结束这个函数。

```php
}
}

```

在过去的部分中，我们添加了很多代码。所以，请检查一下你的代码是否和我的一致：

```php
public static function register($route, $callback, $method) {
if (!static::$route_found) {
$bones = static::get_instance();
$url_parts = explode('/', trim($route, '/'));
$matched = null;
if (count($bones->route_segments) == count($url_parts)) {
foreach ($url_parts as $key=>$part) {
if (strpos($part, ":") !== false) {
// Contains a route variable
$bones->route_variables[substr($part, 1)] = $bones-> route_segments[$key];
} else {
// Does not contain a route variable
if ($part == $bones->route_segments[$key]) {
if (!$matched) {
// Routes match
$matched = true;
}
} else {
// Routes don't match
$matched = false;
}
}
}
} else {
// Routes are different lengths
$matched = false;
}
if (!$matched || $bones->method != $method) {
return false;
} else {
static::$route_found = true;
echo $callback($bones);
}
}
}

```

## 访问路由变量

现在我们将路由变量保存到一个数组中，我们需要在`lib/bones.php`文件中添加一个名为`request`的函数：

```php
public function request($key) {
return $this->route_variables[$key];
}

```

这个函数接受一个名为`$key`的变量，并通过返回具有相同键的对象在我们的`route_variables`数组中的值来返回值。

## 在 index.php 中添加更复杂的路由

我们已经做了很多工作。让我们测试一下，确保一切顺利。

让我们在`index.php`中添加一个快速路由来测试路由变量：

```php
get('/say/:message', function($app) {
$app->set('message', $app->request('message'));
$app->render('home');
});

```

我们添加了一个带有路由变量`message`的路由。当路由被找到并通过回调执行时，我们将变量`message`设置为路由变量 message 的值。然后，我们渲染了主页，就像我们之前做了几次一样。

## 测试一下！

如果你打开浏览器并访问 URL `http://localhost/verge/say/hello`，浏览器将显示：`hello`。

如果你将值更改为任何不同的值，它将把相同的值显示回给你。

## 将更改添加到 Git

这一部分添加了更详细的路由匹配，并允许我们在 URL 中使用路由变量。让我们把所有的改变都添加到 Git 中，这样我们就可以跟踪我们的进展。

1.  打开**终端**。

1.  输入以下命令以更改目录到我们的工作目录：

```php
**cd /Library/Webserver/Documents/verge/** 

```

1.  通过输入以下命令，将我们在这个目录中创建的所有文件都添加进去：

```php
**git add .** 

```

1.  给 Git 一个描述，说明我们自上次提交以来做了什么：

```php
**git commit am 'Refactored route matching to handle more complex URLs and allow for route variables'** 

```

# 添加对公共文件的支持

开发 Web 应用程序的一个重要部分是能够使用 CSS 和 JS 文件。目前，我们真的没有一个很好的方法来使用和显示它们。让我们改变这一点！

# 行动时间——修改.htaccess 以支持公共文件

我们需要修改`.htaccess`文件，这样对`public`文件的请求不会被传递到`index.php`文件，而是进入`public`文件夹并找到请求的资源。

1.  首先打开我们项目根目录中的.htaccess 文件。

1.  添加以下突出显示的代码：

```php
<IfModule mod_rewrite.c>
RewriteEngine On
**RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule ^css/([^/]+) public/css/$1 [L]
RewriteRule ^js/([^/]+) public/js/$1 [L]** 
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule ^(.*)$ index.php?request=$1 [QSA,L]
</IfModule>

```

## 刚才发生了什么？

我们刚刚添加了`RewriteRule`来绕过我们的“捕获所有”规则，如果是`public`文件的话，就将所有请求定向。然后我们简化路由，允许 URL 解析为`/css`和`/js`，而不是`/public/css`和`/public/js`。

我们准备好使用公共文件了。我们只需要实现它们，这应该和设置一样容易。

# 行动时间——为应用程序创建一个样式表

让我们首先添加一个样式表来改变我们应用程序的外观。

1.  打开`views/layout.php`。这个文件目前驱动着我们项目中所有页面的布局。我们只需要添加代码来包含我们的样式表：

```php
<html>
**<head>
<link href="<?php echo $this->make_route('/css/master.css') ?>" rel="stylesheet" type="text/css" />
</head>** 
<body>
<?php include($this->view_content); ?>
</body>
</html>

```

1.  创建一个名为`master.css`的新文件，并将其放在我们工作目录的`public/css`文件夹中。

1.  在`public/css/master.css`中添加一小段代码，以显示不同颜色的背景，这样我们就可以测试所有这些是否有效。

```php
body {background:#e4e4e4;}

```

## 刚才发生了什么？

我们添加了一个新的应用程序样式表`master.css`的引用。我们使用标准标记来包含样式表，并使用`Bones, make_route`的一个函数来正确创建文件的路径。

让我们测试一下，确保我们的样式表现在被正确显示。

1.  打开你的浏览器，然后转到`http://localhost/verge/`。

1.  你的浏览器应该显示以下内容：![What just happened?](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/couchdb-php-webdev-bgd/img/3586_04_020.jpg)

1.  注意我们页面的背景颜色已经变成了灰色，显示出样式表已经生效了！

## 将更改添加到 Git

在这一部分，我们添加了对样式表、JavaScript 和图像等公共文件的支持。然后我们通过创建一个`master.css`文件来测试它。让我们把所有的改变都添加到 Git 中，这样我们就可以跟踪我们的进展。

1.  打开**终端**。

1.  通过键入以下命令，将目录更改为我们的工作目录：

```php
**cd /Library/Webserver/Documents/verge/** 

```

1.  通过键入以下命令，将我们在此目录中创建的所有文件添加进来：

```php
**git add .** 

```

1.  给 Git 一个描述，说明自上次提交以来我们所做的工作：

```php
**git commit am 'Added clean routes for public files, created a master.css file, linked to master.css in layout.php'** 

```

# 将您的代码发布到 GitHub

现在我们已经创建了我们的框架和所有底层代码，我们可以将我们的代码推送到任何支持 Git 的服务提供商。在本书中，我们将使用**GitHub**。

您可以通过访问以下网址在 GitHub 上创建一个帐户：[`github.com/plans`](http://https://github.com/plans)。GitHub 有各种不同的计划供您选择，但我建议您选择免费帐户，这样您就不必在此时支付任何费用。如果您已经有帐户，可以登录并跳过创建新帐户的步骤。

![将您的代码发布到 GitHub](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/couchdb-php-webdev-bgd/img/3586_04_025.jpg)

点击**创建免费帐户**。

### 注意

重要的是要注意，选择免费帐户后，您的所有存储库都将是“公共”的。这意味着任何人都可以看到您的代码。现在这样做没问题，但随着开发的进展，您可能希望注册一个付费帐户，以便它不是公开可用的。

![将您的代码发布到 GitHub](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/couchdb-php-webdev-bgd/img/3586_04_030.jpg)

您将看到一个快速注册表单。填写完整，并在完成后点击**创建帐户**。

创建完帐户后，您将看到您的帐户仪表板。在此屏幕上，您将看到您的帐户或您正在关注的存储库的任何活动。由于我们还没有任何存储库，因此应该首先点击**新存储库**。

![将您的代码发布到 GitHub](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/couchdb-php-webdev-bgd/img/3586_04_035.jpg)

**创建新存储库**页面将允许您创建一个新的存储库来存放您的代码。

![将您的代码发布到 GitHub](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/couchdb-php-webdev-bgd/img/3586_04_040.jpg)

通过填写每个字段来完成此表单的其余部分。

+   **项目名称：**`verge`

+   **描述：**`使用 Bones 构建的名为 verge 的社交网络`

+   **主页 URL：**现在您可以将其留空

+   点击**创建存储库**

您的存储库现在已创建并准备好推送您的代码。您只需要在**终端**中运行几条语句。

1.  打开**终端**。

1.  键入以下命令以更改目录到我们的工作目录：

```php
**cd /Library/WebServer/Documents/verge/** 

```

1.  通过输入以下命令并将**用户名**替换为您的 GitHub 用户名，将 GitHub 添加为您的远程存储库：

```php
**git remote add origin git@github.com:username/verge.git** 

```

1.  将您的本地存储库推送到 GitHub。

```php
**git push -u origin master** 

```

1.  Git 将返回一大堆文本，并在完成时停止。

如果刷新您在[`github.com`](https://github.com)上的 Git 存储库的 URL（我的 URL 是[`github.com/timjuravich/verge`](https://github.com/timjuravich/verge)），您将看到所有文件，如果点击**历史记录**，您将看到我们在本章中进行的每个部分中添加的所有更改。

![将您的代码发布到 GitHub](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/couchdb-php-webdev-bgd/img/3586_04_045.jpg)

随着您不断添加更多的代码，您必须手动每次将代码推送到 GitHub，执行命令`git push origin master`。在我们继续阅读本书的过程中，我们将继续向此存储库添加内容。

# 从 GitHub 获取完整的代码

如果您在某个地方迷失了方向，或者无法使一切都像应该的那样工作，您可以轻松地从 GitHub 的 Git 存储库中克隆 Bones，并且您将获得一个包含我们在本章中所做的所有更改的新副本。

1.  打开**终端**。

1.  使用以下命令将目录更改为我们的工作目录：

```php
**cd /Library/WebServer/Documents** 

```

1.  通过键入以下命令，将存储库克隆到您的本地计算机：

```php
**git clone git@github.com:timjuravich/bones.git** 

```

1.  Git 将从 GitHub 获取所有文件，并将它们移动到您的本地计算机。

# 摘要

在本章中，我们已经做了大量的工作！我们已经：

+   从头开始创建一个 PHP 框架来处理 Web 请求

+   添加了清晰的 URL、路由变量、HTTP 方法支持、简单的视图和布局引擎，以及一个用于显示`public`文件（如样式表、JavaScript 和图像）的系统

+   用我们的浏览器测试了框架的每个部分，以确保我们能够访问我们的更改

+   将我们的代码发布到 GitHub，这样我们就可以看到我们的更改并管理我们的代码。

准备好了！在下一章中，我们将直奔主题，将我们新创建的应用程序连接到 CouchDB。
