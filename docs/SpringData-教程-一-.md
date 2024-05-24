# SpringData 教程（一）

> 原文：[`zh.annas-archive.org/md5/28DD94223A475A77126C29F9DB046845`](https://zh.annas-archive.org/md5/28DD94223A475A77126C29F9DB046845)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

Spring 框架一直对不同的数据访问技术有很好的支持。然而，有一件事长期保持不变：开发人员必须使用特定于技术的 API 来实现其数据访问层，而且这些 API 通常不是很简洁。这导致了这样一种情况：为了实现期望的结果，人们不得不编写大量样板代码。听起来很熟悉，对吧？

Spring Data 项目诞生是为了解决这些问题。它的目标是为使用 Spring 框架的应用程序提供更简单的创建方式，无论是使用关系数据库还是较新的数据访问技术，如非关系数据库、映射-减少框架或基于云的存储技术。它本质上是一个父项目，将数据存储特定的子项目收集到一个品牌下。Spring Data 项目的所有子项目的完整列表可以从 Spring Data 项目的主页上找到：[`www.springsource.org/spring-data/`](http://www.springsource.org/spring-data/)。

本书集中在两个特定的子项目上：Spring Data JPA 和 Spring Data Redis。您将学习一种更简单的方法来管理实体并使用 Spring Data JPA 创建数据库查询。本书还演示了如何向存储库添加自定义功能。您还将学习如何使用 Redis 键值存储作为数据存储，并利用其其他功能来增强应用程序的性能。

这本实用指南证明了实现 JPA 存储库可以很有趣，并帮助您在应用程序中利用 Redis 的性能。

# 本书涵盖的内容

第一章《入门》简要介绍了本书中描述的技术。本章分为两部分：第一部分描述了 Java 持久性 API 背后的动机，概述了其主要概念，并展示了如何使用它构建数据库查询。第二部分确定了 Redis 键值存储的关键特性。

第二章《使用 Spring Data JPA 入门》帮助您开始使用 Spring Data JPA 构建应用程序。您将学习如何设置一个使用 Spring Data JPA 的项目，并通过编程配置来配置您的应用程序。您还将学习一种简单的方法来为您的实体创建存储库，并使用 Spring Data JPA 实现一个简单的联系人管理应用程序。

第三章《使用 Spring Data JPA 构建查询》描述了您可以使用的技术来构建数据库查询。阅读本章后，您将了解如何使用查询方法、JPA Criteria API 和 Querydsl 来构建数据库查询。您还将通过向其添加搜索功能来继续实现联系人管理应用程序。

第四章《向 JPA 存储库添加自定义功能》教会您如何自定义存储库。您将学习如何将自定义功能添加到单个存储库或所有存储库。本章讨论的原则是通过自定义联系人管理应用程序的存储库来演示的。

第五章《使用 Spring Data Redis 入门》将指导您完成安装和配置阶段，这是在您的应用程序中使用 Spring Data Redis 之前所必需的。它描述了如何在运行类 Unix 操作系统的计算机上安装 Redis。然后您可以设置一个使用 Spring Data Redis 的项目。在本章的最后部分，您将学习如何配置 Redis 连接并比较支持的连接器库的特性。

第六章，*使用 Spring Data Redis 构建应用程序*，教您如何在 Spring 应用程序中使用 Redis。它描述了 Spring Data Redis 的关键组件，并教您如何使用它们。当您将 Redis 用作联系人管理应用程序的数据存储时，您还将看到 Spring Data Redis 的实际应用。本章的最后部分描述了如何将 Spring Data Redis 用作 Spring 3.1 缓存抽象的实现。您还将在本章中看到如何利用 Redis 的发布/订阅消息模式实现。

# 您需要为这本书做些什么

为了运行本书的代码示例，您需要安装以下软件：

+   Java 1.6

+   Maven 3.0.X

+   Redis 2.6.0-rc6

+   一个网络浏览器

如果您想尝试代码示例，您还需要：

+   诸如 Eclipse、Netbeans 或 IntelliJ Idea 之类的 IDE

+   每章的完整源代码包（请参阅下面的*下载示例代码*部分）

# 这本书适合谁

这本书非常适合正在使用 Spring 应用程序的开发人员，并且正在寻找一种更容易的方式来编写使用关系数据库的数据访问代码。此外，如果您有兴趣了解如何在应用程序中使用 Redis，那么这本书适合您。这本书假定您已经从 Spring 框架和 Java 持久性 API 中获得了一些经验。不需要来自 Redis 的先前经验。

# 约定

在本书中，您将找到许多文本样式，用于区分不同类型的信息。以下是一些示例以及它们的含义解释。

文本中的代码单词显示如下：“我们可以通过使用`@EnableJpaRepositories`注释的`repositoryFactoryBeanClass`属性来实现这一点。”

代码块设置如下：

```java
@Override
protected RepositoryFactorySupport createRepositoryFactory(EntityManager entityManager) {
    return new BaseRepositoryFactory(entityManager);
}
```

当我们希望引起您对代码块的特定部分的注意时，相关的行或项目将以粗体显示：

```java
@CachePut(value = "contacts", key="#p0.id")
@Transactional(rollbackFor = NotFoundException.class)
@Override
public Contact update(ContactDTO updated) throws NotFoundException {
    //Implementation remains unchanged.
}
```

**新术语**和**重要单词**以粗体显示。

### 注意

警告或重要说明会出现在这样的框中。

### 提示

提示和技巧会出现在这样。 


# 第一章：入门

在本书中，我们将集中讨论两个特定的子项目，它们支持 Java 持久化 API 2.0 和 Redis 键值存储。但在我们深入讨论之前，我们需要对这两种技术进行简要介绍。我们需要这样做有两个原因：

首先，如果我们想真正理解 Spring Data JPA 的好处，我们需要了解在使用标准 API 时如何创建数据库查询。一旦我们将这些代码示例与使用 Spring Data JPA 的查询创建代码进行比较，它的好处就会显露出来。

其次，对 Redis 键值存储的基本了解将有助于我们理解本书的第二部分，其中描述了我们如何在应用程序中使用它。毕竟，我们应该熟悉我们在应用程序中使用的任何技术。对吧？

本章中，我们将涵盖以下主题：

+   Java 持久化 API 背后的动机

+   Java 持久化 API 的主要组件

+   我们如何使用 Java 持久化 API 创建数据库查询

+   Redis 键值存储支持的数据类型。

+   Redis 键值存储的主要特性。

# Java 持久化 API

在引入**Java 持久化 API**（**JPA**）之前，我们有以下三种替代技术可用于实现持久化层：

+   **企业 JavaBean**（**EJB**）2.x 规范提供的持久化机制

+   **JDBC** API

+   第三方**对象关系映射**（**ORM**）框架，如 Hibernate。

这给了我们在选择最适合工作的工具时一些自由，但像往常一样，这些选项都不是没有问题的。

EJB 2.x 的问题在于它太过沉重和复杂。它的配置依赖于复杂的 XML 文档，其编程模型需要大量样板代码。此外，EJB 要求应用程序部署到**Java EE**应用服务器。

针对 JDBC API 的编程相当简单，我们可以在任何 servlet 容器中部署我们的应用程序。但是，当我们将领域模型的信息转换为查询或从查询结果构建领域模型对象时，我们必须编写大量样板代码。

第三方 ORM 框架通常是一个不错的选择，因为它们使我们摆脱了编写不必要的代码，用于构建查询或从查询结果构造领域对象。这种自由是有代价的：对象和关系数据不兼容，即使 ORM 框架可以解决大部分由**对象关系不匹配**引起的问题，但它们无法高效解决的问题是我们最头疼的问题。

Java 持久化 API 提供了一种标准机制，用于实现使用关系数据库的持久化层。它的主要动机是取代 EJB 2.x 的持久化机制，并为对象关系映射提供了标准化方法。它的许多特性最初是由第三方 ORM 框架引入的，后来成为 Java 持久化 API 的实现。以下部分介绍了其关键概念，并描述了我们如何使用它创建查询。

## 关键概念

**实体**是持久化的领域对象。每个**实体类**通常表示一个数据库表，并且这样的类的实例包含单个表行的数据。每个实体实例始终具有唯一的对象标识符，这对于实体来说就像主键对于数据库表一样。

**实体管理器工厂**创建**实体管理器**实例。由同一实体管理器工厂创建的所有实体管理器实例将使用相同的配置和数据库。如果需要访问多个数据库，则必须为每个使用的数据库配置一个实体管理器工厂。实体管理器工厂的方法由`EntityManagerFactory`接口指定。

实体管理器管理应用程序的实体。实体管理器可用于对实体执行 CRUD（创建、读取、更新和删除）操作，并针对数据库运行复杂查询。实体管理器的方法由`EntityManager`接口声明。

**持久化单元**指定了所有实体类，这些类由应用程序的实体管理器管理。每个持久化单元包含表示存储在单个数据库中的数据的所有类。

**持久化上下文**包含实体实例。在持久化上下文中，每个对象标识符只能有一个实体实例。每个持久化上下文与管理持久化上下文中包含的实体实例的特定实体管理器相关联。

## 创建数据库查询

Java 持久化 API 引入了两种创建数据库查询的新方法：**Java 持久化查询语言**（**JPQL**）和**标准查询 API**。使用这些技术编写的查询不直接处理数据库表，而是针对应用程序的实体及其持久状态编写。这在理论上确保创建的查询是可移植的，不与特定的数据库模式或数据库提供程序绑定。

也可以使用 SQL 查询，但这会将应用程序与特定的数据库模式绑定。如果使用了特定于数据库提供程序的扩展，我们的应用程序也将与数据库提供程序绑定。

接下来，我们将看看如何使用 Java 持久化 API 通过使用 SQL、JPQL 和标准查询 API 构建数据库查询。我们的示例查询将从数据库中获取所有名字为“John”的联系人。这个例子使用了一个简单的实体类`Contact`，表示了`contacts`表中存储的数据。以下表将实体的属性映射到数据库的列：

| 联系人 | 联系人 |
| --- | --- |
| `firstName` | `first_name` |

### 本地 SQL 查询

SQL 是一种标准化的查询语言，旨在管理存储在关系数据库中的数据。以下代码示例描述了如何使用 SQL 实现指定的查询：

```java
//Obtain an instance of the entity manager
EntityManager em = ...

//Build the SQL query string with a query parameter
String getByFirstName="SELECT * FROM contacts c WHERE c.first_name = ?1";

//Create the Query instance
Query query = em.createNativeQuery(getByFirstName, Contact.class);

//Set the value of the query parameter
query.setParameter(1, "John");

//Get the list of results
List contacts = query.getResultList();
```

这个例子教会我们三件事：

+   我们不必学习新的查询语言来构建 JPA 查询。

+   创建的查询不是类型安全的，我们必须在使用之前对结果进行转换。

+   我们必须在验证查询的拼写或语法错误之前运行应用程序。这增加了开发人员反馈循环的长度，降低了生产率。

因为 SQL 查询与特定的数据库模式（或使用的数据库提供程序）绑定，所以只有在绝对必要时才应使用它们。通常使用 SQL 查询的原因是性能，但我们可能还有其他使用它的原因。例如，我们可能正在将传统应用程序迁移到 JPA，而一开始没有时间做得很好。

### Java 持久化查询语言

JPQL 是一种基于字符串的查询语言，其语法类似于 SQL。因此，只要您具有一些 SQL 经验，学习 JPQL 就相当容易。执行指定查询的代码示例如下：

```java
//Obtain an instance of the entity manager
EntityManager em = ...

//Build the JPQL query string with named parameter
String getByFirstName="SELECT c FROM Contact c WHERE c.firstName = :firstName";

//Create the Query instance
TypedQuery<Contact> query = em.createQuery(getByFirstName, Contact.class);

//Set the value of the named parameter
query.setParameter("firstName", "John");

//Get the list of results
List<Contact> contacts = query.getResultList();
```

这个例子告诉我们三件事：

+   创建的查询是类型安全的，我们不必对查询结果进行转换。

+   JPQL 查询字符串非常易读且易于解释。

+   创建的查询字符串无法在编译期间进行验证。验证查询字符串的拼写或语法错误的唯一方法是运行我们的应用程序。不幸的是，这意味着开发人员反馈循环的长度增加，从而降低了生产率。

JPQL 是静态查询的不错选择。换句话说，如果查询参数的数量始终相同，JPQL 应该是我们的首选。但是，使用 JPQL 实现动态查询通常很麻烦，因为我们必须手动构建查询字符串。

### 标准查询 API

Criteria API 是为了解决在使用 JPQL 时发现的问题并标准化第三方 ORM 框架的标准化努力而引入的。它用于构建查询定义对象，这些对象被转换为执行的 SQL 查询。下面的代码示例演示了我们可以通过使用 Criteria API 来实现我们的查询：

```java
//Obtain an instance of entity manager
EntityManager em = ...
//Get criteria builder
CriteriaBuilder cb = em.getCriteriaBuilder();

//Create criteria query
CriteriaQuery<Contact> query = cb.greateQuery(Contact.class);

//Create query root
Root<Contact> root = query.from(Contact.class);

//Create condition for the first name by using static meta
//model. You can also use "firstName" here.
Predicate firstNameIs = cb.equal(root.get(Contact_.firstName, "John");

//Specify the where condition of query
query.where(firstNameIs);

//Create typed query and get results
TypedQuery<Contact> q = em.createQuery(query);
List<Contact> contacts = q.getResultList();
```

我们可以从这个例子中看到三件事：

+   创建的查询是类型安全的，可以在不进行强制转换的情况下获得结果

+   代码不像使用 SQL 或 JPQL 的相应代码那样可读

+   由于我们正在处理 Java API，Java 编译器确保不可能创建语法不正确的查询

如果我们必须创建动态查询，Criteria API 是一个很好的工具。创建动态查询更容易，因为我们可以处理对象而不是手动构建查询字符串。不幸的是，当创建的查询复杂性增加时，创建查询定义对象可能会很麻烦，代码变得更难理解。

# Redis

Redis 是一个将整个数据集保存在内存中并仅将磁盘空间用作辅助持久存储的内存数据存储。因此，Redis 可以提供非常快速的读写操作。问题在于 Redis 数据集的大小不能超过内存量。Redis 的其他特性包括：

+   支持复杂数据类型

+   多种持久化机制

+   主从复制

+   实现发布/订阅消息模式

这些特性在以下小节中描述。

## 支持的数据类型

Redis 存储的每个值都有一个键。键和值都是二进制安全的，这意味着键或存储的值可以是字符串或二进制文件的内容。然而，Redis 不仅仅是一个简单的键值存储。它支持多种二进制安全的数据类型，这对每个程序员来说应该是熟悉的。这些数据类型如下：

+   **字符串**：这是一种数据类型，其中一个键始终指向单个值。

+   **列表**：这是一种数据类型，其中一个键引用多个字符串值，这些值按插入顺序排序。

+   **集合**：这是一个无序字符串的集合，不能包含相同的值超过一次。

+   **有序集合**：这类似于一个集合，但它的每个值都有一个分数，用于将有序集合的值从最低分数到最高分数排序。相同的分数可以分配给多个值。

+   **哈希**：这是一种数据类型，其中一个哈希键始终指向特定的字符串键和值的映射。

## 持久化

Redis 支持两种持久化机制，可用于将数据集存储在磁盘上。它们如下：

+   RDB 是 Redis 最简单的持久化机制。它在配置的间隔时间内从内存数据集中获取快照，并将快照存储在磁盘上。服务器启动时，它将从快照文件中读取数据集到内存中。这是 Redis 的默认持久化机制。

RDB 最大化了 Redis 服务器的性能，其文件格式非常紧凑，这使得它成为灾难恢复的非常有用的工具。此外，如果你想使用主从复制，你必须使用 RDB，因为在主从之间同步数据时会使用 RDB 快照。

然而，如果你必须在所有情况下最小化数据丢失的机会，RDB 不是适合你的解决方案。因为 RDB 在配置的间隔时间内持久化数据，你总是可以在最后一个快照保存到磁盘后丢失存储在 Redis 实例中的数据。

+   **追加模式文件**（**AOF**）是一种持久化模型，它将改变内存数据集状态的每个操作记录到特定的日志文件中。当 Redis 实例启动时，它将通过执行从日志文件中找到的所有操作来重建数据集。

AOF 的优势在于它最大程度地减少了在所有情况下的数据丢失的机会。此外，由于日志文件是追加日志，它不会被不可逆地损坏。另一方面，与相同数据相比，AOF 日志文件通常比 RDB 文件大，并且如果服务器正在经历大量写入负载，AOF 可能比 RDB 慢。

您还可以启用两种持久性机制，并兼得两全。您可以使用 RDB 来创建数据集的备份，并确保数据的安全。在这种情况下，Redis 将使用 AOF 日志文件在服务器启动时构建数据集，因为它很可能包含最新的数据。

如果您将 Redis 用作临时数据存储并且不需要持久性，您可以禁用两种持久性机制。这意味着当服务器关闭时，数据集将被销毁。

## 复制

Redis 支持主从复制，其中单个主机可以有一个或多个从机。每个从机都是其主机的精确副本，并且可以连接到主机和其他从机。换句话说，从机可以是其他从机的主机。自 Redis 2.6 以来，每个从机默认为只读，并且拒绝对从机的所有写操作。如果我们需要将临时信息存储到从机，我们必须配置该从机以允许写操作。

复制在双方都是非阻塞的。即使从机或从机在第一次同步数据时，也不会阻塞对主机的查询。从机可以配置为在同步数据时提供旧数据。然而，当旧数据被新数据替换时，对从机的传入连接将被短暂地阻塞。

如果从机与主机失去连接，它将继续提供旧数据或向客户端返回错误，这取决于其配置。当主机和从机之间的连接丢失时，从机将自动重新打开连接并向主机发送同步请求。

## 发布/订阅消息模式

发布/订阅消息模式是一种消息模式，其中消息发送者（发布者）不直接向接收者（订阅者）发送消息。相反，使用一个名为**通道**的附加元素来传输从发布者到订阅者的消息。发布者可以向一个或多个通道发送消息。订阅者可以选择感兴趣的通道，并通过订阅这些通道来接收发送到这些通道的消息。

让我们想象一个情况，一个单一的发布者正在向两个通道发布消息，通道 1 和通道 2。通道 1 有两个订阅者：订阅者 1 和订阅者 2。通道 2 也有两个订阅者：订阅者 2 和订阅者 3。这种情况在下图中有所说明：

![发布/订阅消息模式](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprdt/img/9045_01_01.jpg)

发布/订阅模式确保发布者不知道订阅者，反之亦然。这使我们有可能将应用程序分成更小的模块，它们之间的耦合度较低。这使得模块更容易维护和替换。

然而，发布/订阅模式的最大优势也是它的最大弱点。首先，我们的应用程序不能依赖于特定组件已订阅特定通道的事实。其次，我们没有办法清楚地验证是否是这种情况。事实上，我们的应用程序不能假设有人在听。

Redis 为发布/订阅模式提供了坚实的支持。其发布/订阅实现的主要特点包括：

+   发布者可以同时向一个或多个通道发布消息

+   订阅者可以通过使用通道的名称或包含通配符的模式订阅感兴趣的通道

+   取消订阅通道也支持名称和模式匹配

# 总结

在本章中，我们已经了解到：

+   Java 持久化 API 被引入是为了解决与 EJB 2.x 相关的问题，并提供对象关系映射的标准方法。它的特性是从最流行的第三方持久化框架的特性中选择的。

+   Redis 是一个内存数据存储，它将整个数据集保留在内存中，支持复杂数据类型，可以使用磁盘作为持久存储，并支持主从复制。它还实现了发布/订阅消息模式。

在下一章中，我们将学习如何设置一个使用 Spring Data JPA 的 Web 应用程序项目，并使用它来实现一个简单的联系人管理应用程序。


# 第二章：开始使用 Spring Data JPA

本章为我们提供了设置 Web 应用程序项目并使用 Spring Data JPA 管理实体所需的基本知识。在本章的过程中，我们将学习：

+   如何使用**Maven**下载所需的依赖项

+   如何使用**编程配置**配置 Spring **应用程序上下文**

+   如何配置我们的 Web 应用程序以通过编程方式配置（而不使用`web.xml`）加载 Spring 应用程序上下文

+   如何使用 Spring Data JPA 为实体类实现**CRUD**（**创建**、**读取**、**更新**和**删除**）功能

# 使用 Maven 下载依赖项

本书涵盖了 Spring Data JPA 的 1.2.0.RELEASE 版本，这是在撰写本书时可用的最新版本。Spring Data JPA 所需的其他组件在以下表中描述：

| 组件 | 描述 | 版本 |
| --- | --- | --- |
| 数据源 | BoneCP 是一个快速连接池库，用作我们应用程序的数据源。 | 0.7.1.RELEASE |
| JPA 提供程序 | JPA 提供程序是实现 Java 持久化 API 的库。我们将使用 Hibernate 作为 JPA 提供程序。 | 4.1.4.Final |
| Spring 框架 | Spring 框架用于开发现代企业应用程序的 Java。 | 3.1.2.RELEASE |
| 数据库 | H2 是一个支持标准 SQL 和 JDBC API 的内存中嵌入式数据库。 | 1.3.166 |

我们将使用我们应用程序的其他依赖项的最新可用版本。

我们可以通过在`POM`文件中声明它们来使用 Maven 下载所需的依赖项。为此，我们必须将以下依赖项声明添加到`pom.xml`文件的依赖项部分：

```java
<!-- Spring Data JPA -->
<dependency>
  <groupId>org.springframework.data</groupId>
  <artifactId>spring-data-jpa</artifactId>
  <version>1.2.0.RELEASE</version>
</dependency>
<!-- Hibernate -->
<dependency>
  <groupId>org.hibernate</groupId>
  <artifactId>hibernate-core</artifactId>
  <version>4.1.4.Final</version>
</dependency>
<dependency>
  <groupId>org.hibernate</groupId>
  <artifactId>hibernate-entitymanager</artifactId>
  <version>4.1.4.Final</version>
</dependency>
<!-- H2 Database -->
<dependency>
  <groupId>com.h2database</groupId>
  <artifactId>h2</artifactId>
  <version>1.3.166</version>
</dependency>
<!-- BoneCP -->
<dependency>
  <groupId>com.jolbox</groupId>
  <artifactId>bonecp</artifactId>
  <version>0.7.1.RELEASE</version>
</dependency>
```

### 提示

**下载示例代码**

您可以从您在[`www.packtpub.com`](http://www.packtpub.com)的帐户中下载您购买的所有 Packt 图书的示例代码文件。如果您在其他地方购买了本书，您可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)并注册以直接通过电子邮件接收文件。

# 配置 Spring 应用程序上下文

传统上，我们会使用 XML 配置文件进行声明式配置，但在 Spring Framework 3.0 发布后，可以使用编程配置来配置 Spring 应用程序上下文。这是我们在配置应用程序上下文时的首选方法。

我们可以通过以下步骤配置 Spring 应用程序上下文：

1.  为配置参数的值创建一个属性文件。

1.  创建应用程序上下文配置类。

## 创建属性文件

配置参数的实际值存储在一个名为`application.properties`的属性文件中。该文件包含数据库连接详细信息、Hibernate 配置以及我们实体的基本包。该文件的内容如下：

```java
#Database Configuration
db.driver=org.h2.Driver
db.url=jdbc:h2:mem:datajpa
db.username=sa
db.password=

#Hibernate Configuration
hibernate.dialect=org.hibernate.dialect.H2Dialect
hibernate.format_sql=true
hibernate.hbm2ddl.auto=create-drop
hibernate.ejb.naming_strategy=org.hibernate.cfg.ImprovedNamingStrategy
hibernate.show_sql=true

#EntityManager
entitymanager.packages.to.scan=com.packtpub.springdata.jpa.model

#General Spring configuration is added here.
```

## 创建应用程序上下文配置类

我们可以通过以下步骤创建应用程序上下文配置类：

1.  创建一个包含应用程序的一般配置的应用程序上下文配置骨架。

1.  配置数据源 bean。

1.  配置实体管理器工厂 bean。

1.  配置事务管理器 bean。

### 创建应用程序上下文配置骨架

创建 Spring 应用程序上下文配置类的骨架配置类所需的步骤如下：

1.  `@Configuration`注解将该类标识为应用程序上下文配置类。

1.  组件扫描指令使用`@ComponentScan`注解进行配置。在我们的示例中，Spring IoC 容器配置为扫描包含我们控制器和服务类的包。

1.  `@EnableJpaRepositories`注解用于启用 Spring Data JPA 并配置我们的存储库的基本包。

1.  `@EnableTransactionManagement`注解启用了 Spring Framework 的基于注解的事务管理。

1.  `@EnableWebMcv`注解导入了 Spring MVC 的默认配置。

1.  包含配置参数值的属性文件是通过使用`@PropertySource`注解导入的。我们可以通过使用 Spring IoC 容器注入的`Environment`接口的实现来访问存储在此文件中的属性值。

我们的应用程序上下文配置骨架的源代码如下所示：

```java
@Configuration
@ComponentScan(basePackages = {
        "com.packtpub.springdata.jpa.controller",
        "com.packtpub.springdata.jpa.service"
})
@EnableJpaRepositories("com.packtpub.springdata.jpa.repository")
@EnableTransactionManagement
@EnableWebMvc
@PropertySource("classpath:application.properties")
public class ApplicationContext extends WebMvcConfigurerAdapter {

    @Resource
    private Environment env;

//Add configuration here
}

```

### 注意

我们还可以通过使用 XML 配置 Spring Data JPA。我们可以通过向应用程序上下文配置文件添加 Spring Data JPA 的`repositories`命名空间元素来实现这一点。

### 配置数据源 bean

我们将通过向`ApplicationContext`类添加一个名为`dataSource()`的方法并用`@Bean`注解对该方法进行注解来开始配置数据源 bean。该方法的实现如下：

1.  创建`BoneCPDataSource`类的实例。

1.  设置数据库连接详细信息。

1.  返回创建的对象。

数据源 bean 的配置如下所示：

```java
@Bean
public DataSource dataSource() {
  BoneCPDataSource ds = new BoneCPDataSource();   

  ds.setDriverClass(env.getRequiredProperty("db.driver")); 
  ds.setJdbcUrl(env.getRequiredProperty("db.url")); 
  ds.setUsername(env.getRequiredProperty("db.username"));  
  ds.setPassword(env.getRequiredProperty("db.password"));

  return ds;
}
```

### 配置实体管理器工厂 bean

我们可以通过向`ApplicationContext`类添加一个名为`entityManagerFactory()`的方法并用`@Bean`注解对该方法进行注解来配置实体管理器工厂 bean。该方法的实现如下：

1.  创建`LocalContainerEntityManagerFactoryBean`类的实例。

1.  将所使用的数据源 bean 的引用传递给创建的对象。

1.  将 Hibernate 的默认配置设置为实体管理器工厂 bean。我们可以通过创建一个新的`HibernateJpaVendorAdapter`对象并将其传递给实体管理器工厂 bean 来实现这一点。

1.  设置我们实体的基本包。

1.  设置从我们的属性文件中获取的附加配置。

1.  返回创建的对象。

创建方法的源代码如下所示：

```java
@Bean
public LocalContainerEntityManagerFactoryBean entityManagerFactory() {
    LocalContainerEntityManagerFactoryBean em = new LocalContainerEntityManagerFactoryBean();

    em.setDataSource(dataSource());
    em.setJpaVendorAdapter(new HibernateJpaVendorAdapter());em.setPackagesToScan(env.getRequiredProperty("entitymanager.packages.to.scan"));

    Properties p = new Properties();
    p.put("hibernate.dialect", env.getRequiredProperty("hibernate.dialect"));
    p.put("hibernate.format_sql", env.getRequiredProperty("hibernate.format_sql"));
    p.put("hibernate.hbm2ddl.auto", env.getRequiredProperty("hibernate.hbm2ddl.auto"));
    p.put("hibernate.ejb.naming_strategy", env.getRequiredProperty("hibernate.ejb.naming_strategy"));
    p.put("hibernate.show_sql", env.getRequiredProperty("hibernate.show_sql");
    em.setJpaProperties(p);

    return em;
}
```

### 配置事务管理器 bean

我们可以通过向`ApplicationContext`类添加一个名为`transactionManager()`的方法并用`@Bean`注解对该方法进行注解来配置事务管理器 bean。该方法的实现如下：

1.  创建一个新的`JpaTransactionManager`对象。

1.  设置所使用的实体管理器工厂的引用。

1.  返回创建的对象。

事务管理器 bean 配置的源代码如下所示：

```java
@Bean
public JpaTransactionManager transactionManager() {
    JpaTransactionManager transactionManager = new JpaTransactionManager();
    transactionManager.setEntityManagerFactory(entityManagerFactory().getObject());
    return transactionManager;
}
```

# 加载应用程序上下文配置

加载我们应用程序的应用程序上下文配置的旧方法是使用更常见的`web.xml`文件，也就是更常见的**web 应用程序部署描述符**文件。然而，因为我们在 Servlet 3.0 环境中使用 Spring Framework 3.1，我们可以通过实现`WebApplicationInitializer`接口来创建一个 Web 应用程序配置类。这样可以确保 Spring Framework 在启动 Servlet 容器时自动检测到我们的配置类。

我们将使用我们的 Web 应用程序配置类来：

1.  加载我们的应用程序上下文配置类。

1.  配置**调度程序 servlet**。

1.  创建**上下文加载程序监听器**并将其添加到我们的**servlet 上下文**中。

我们的配置类的源代码如下所示：

```java
public class DataJPAExampleInitializer implements WebApplicationInitializer {

    @Override
    public void onStartup(ServletContext servletContext) throws ServletException {
        //Loading application context
        AnnotationConfigWebApplicationContext rootContext = new AnnotationConfigWebApplicationContext();
        rootContext.register(ApplicationContext.class);

        //Dispatcher servlet
        ServletRegistration.Dynamic dispatcher = servletContext.addServlet("dispatcher", new DispatcherServlet(rootContext));
        dispatcher.setLoadOnStartup(1);
        dispatcher.addMapping("/");

        //Context loader listener
        servletContext.addListener(new ContextLoaderListener(rootContext));
    }
}
```

# 为实体实现 CRUD 功能

我们现在已经配置了 Spring 应用程序上下文并配置了我们的 Web 应用程序在启动时加载它。我们现在将为一个简单的实体实现 CRUD 功能。我们的示例应用程序用于查看和管理联系信息，我们可以通过以下步骤来实现它：

1.  创建领域模型。

1.  为实体创建一个存储库。

1.  实现 CRUD 功能。

### 注意

本章仅描述了我们应用程序中理解 Spring Data JPA 工作所需的部分。

## 领域模型

我们的应用程序的领域模型由两个类组成：`Contact`和`Address`。本小节将涉及以下事项：

+   每个类的信息内容

+   我们如何使用**建造者模式**创建新对象（参见：*Effective Java*（*第二版*），*Joshua Bloch*，*Addison-Wesley*）

+   我们如何更新对象的信息

### 联系人

`Contact`类是我们领域模型中唯一的实体，它包含单个联系人的信息。这些信息主要由简单的属性组成。唯一的例外是`Address`类，用于存储地址信息。`Contact`类源代码的相关部分如下所示：

```java
@Entity
@Table(name = "contacts")
public class Contact {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;

    private Address address;

    @Column(name = "email_address", length = 100)
    private String emailAddress;

    @Column(name = "first_name", nullable=false, length = 50)
    private String firstName;

    @Column(name = "last_name", nullable=false, length = 100)
    private String lastName;

    @Column(name = "phone_number", length = 30)
    private String phoneNumber;

    @Version
    private long version;

//Getters and other methods
}
```

让我们继续找出如何创建新联系人并更新联系人信息。

#### 创建新的联系人对象

我们将使用建造者模式来创建新的联系人。为了做到这一点，我们必须按照以下步骤进行：

1.  实现一个用于构建新`Contact`对象的静态内部类。

1.  在`Contact`类中添加一个静态的`getBuilder()`方法。此方法用于获取对所使用的构建器的引用。

我们将首先通过以下步骤向`Contact`类添加一个静态内部类：

1.  实现一个以所需属性作为参数的构造函数。联系人的必需属性是名字和姓氏。

1.  为可选属性实现属性方法。这些属性包括电子邮件地址、电话号码和地址信息。每个属性方法都返回对所使用的构建器对象的引用。

1.  实现一个`build()`方法，返回构建的对象。

`Contact.Builder`类的源代码如下所示：

```java
public static class Builder {

        private Contact built;

        public Builder (String firstName, String lastName) {
            built = new Contact();
            built.firstName = firstName;
            built.lastName = lastName;
        }

        public Builder address(String streetAddress, String postCode, String postOffice, String state, String country) {
            Address address = Address.getBuilder(streetAddress, postCode, postOffice)
                    .state(state)
                    .country(country)
                    .build();
            built.address = address;
            return this;
        }

        public Builder emailAddress(String emailAddress) {
            built.emailAddress = emailAddress;
            return this;
        }

        public Builder phoneNumber(String phoneNumber) {
            built.phoneNumber = phoneNumber;
            return this;
        }

        public Contact build() {
            return built;
        }
    }
}
```

我们还必须在`Contact`类中添加一个静态的`getBuilder()`方法。我们的实现非常简单。我们创建一个新的`Contact.Builder`对象并返回创建的对象。此方法的源代码如下所示：

```java
public static Builder getBuilder(String firstName, String lastName) {
    return new Builder(firstName, lastName);
}
```

#### 更新联系人信息

`Contact`类有两个方法可用于更新联系人信息：`update()`方法用于更新联系人信息，`updateAddress()`方法用于更新联系人的地址信息。这些方法的源代码如下所示：

```java
public void update(final String firstName, final String lastName, final String emailAddress, final String phoneNumber) {
    this.firstName = firstName;
    this.lastName = lastName;
    this.emailAddress = emailAddress;
    this.phoneNumber = phoneNumber;
}

public void updateAddress(final String streetAddress, final String postCode, final String postOffice, final String state, final String country) {
    if (address == null) {
        address = new Address();
    }
    address.update(streetAddress, postCode, postOffice, state, country);
}
```

### 地址

`Address`类是一个嵌入类，用于存储地址信息。**嵌入类**是一个只能与其父类一起持久化的类。嵌入类通常用于呈现领域模型的常见概念，并强调其面向对象的特性。`Address`类的源代码如下所示：

```java
@Embeddable
public class Address {

    @Column(name = "country", length = 20)
    private String country;

    @Column(name = "street_address", length =150)
    private String streetAddress;

    @Column(name = "post_code", length = 10)
    private String postCode;

    @Column(name = "post_office", length = 40)
    private String postOffice;

    @Column(name = "state", length = 20)
    private String state;

  //The default constructor and other methods
}
```

接下来，我们将找出如何创建新的`Address`对象并更新现有对象的地址信息。

#### 创建新的地址

我们将通过建造者模式创建新的`Address`对象。我们可以通过以下步骤实现建造者模式：

1.  实现一个用于构建新`Address`对象的静态内部类。

1.  在`Address`类中添加一个静态的`getBuilder()`方法。此方法用于获取对所使用的构建器的引用。

我们可以通过以下步骤实现静态内部类： 

1.  为`Address`类实现一个以所需属性作为参数的构造函数。`Address`类的必需属性是`streetAddress`、`postCode`和`postOffice`。

1.  实现用于设置可选地址信息的属性方法。这些信息包括州和国家。每个属性方法都返回对所使用的构建器的引用。

1.  实现一个`build()`方法，返回构建的对象。

`Address.Builder`类的源代码如下所示：

```java
public static class Builder {

  private Address built;

  public Builder(String streetAddress, String postCode, String postOffice) {
    built = new Address();
    built.streetAddress = streetAddress;
    built.postCode = postCode;
    built.postOffice = postOffice;
  }

  public Builder country(String country) {
    built.country = country;
    return this;
  }

  public Builder state(String state) {
    built.state = state;
    return this;
  }

  public Address build() {
    return built;
   }
}
```

我们还必须实现一个方法，用于获取对所使用的构建器对象的引用。我们可以通过简单地创建一个新的`Address.Builder`对象并返回创建的对象来实现这一点。`Address`类的静态`getBuilder()`方法的源代码如下所示：

```java
public static Builder getBuilder(String streetAddress, String postCode, String postOffice) {
    return new Builder(streetAddress, postCode, postOffice);
}
```

#### 更新地址信息

我们可以通过调用其`update()`方法来更新`Address`对象的信息。该方法的源代码如下：

```java
public void update(final String streetAddress, final String postCode, final String postOffice, final String state, final String country) {
    this.streetAddress = streetAddress;
    this.postCode = postCode;
    this.postOffice = postOffice;
    this.state = state;
    this.country = country;
}
```

## 创建一个自定义存储库

为了真正理解 Spring Data JPA 的简单性，我们必须回顾一下不太久远的过去，了解在 Spring Data JPA 发布之前如何创建具体存储库。这应该让我们清楚地了解 Spring Data JPA 的好处。

### 以老式方式创建自定义存储库

传统上，创建具体存储库是一个包括六个步骤的过程。它们如下：

1.  创建一个为其子类提供属性映射的基类。通常用于为我们的实体提供 ID、版本和时间戳映射。

1.  创建一个声明所有存储库共享方法的通用存储库接口。通常，这些方法为我们的实体提供 CRUD 操作。

1.  创建一个通用存储库。

1.  创建一个实体类。

1.  创建一个特定实体的存储库接口。

1.  创建一个特定实体的具体存储库。

首先，我们必须创建一个抽象基类，每个实体类都要扩展这个基类。我们可以通过以下步骤创建这个类：

1.  创建一个抽象类，将实体 ID 类型作为类型参数。

1.  用`@MappedSuperclass`注解注释创建的类。它用于说明从这个类中找到的映射应用于它的子类。

1.  创建一个抽象的`getId()`方法，返回具体类的 ID。

`BaseEntity`类的源代码如下：

```java
@MappedSuperclass
public abstract class BaseEntity<ID> {

    @Version
    private Long version;

    public abstract ID getId();
}
```

其次，我们必须创建一个声明所有具体存储库共享方法的通用存储库接口。我们可以通过以下步骤创建这个接口：

1.  添加实体类型和实体 ID 类型作为类型参数。

1.  声明所有具体存储库共享的方法。

`BaseRepository`接口的源代码如下：

```java
public interface BaseRepository<T extends BaseEntity, ID extends Serializable> {

    public T deleteById(ID id);
    public List<T> findAll();
    public T findById(ID id);
    public void persist(T entity);
}
```

第三，我们必须创建一个抽象的通用存储库。我们可以通过以下步骤实现这一点：

1.  创建一个抽象类，将具体实体的类型和实体 ID 类型作为类型参数。

1.  使用`@PersistenceContext`注解获取对使用的实体管理器的引用。

1.  实现`BaseRepository`接口。

1.  实现一个构造函数，从类型参数中获取实体类的类型。

1.  提供一个`getEntityManager()`方法，返回一个用于引用的实体管理器。这个类的子类将使用这个方法来获取用于构建数据库查询的实体管理器引用。

1.  提供一个`getEntityClass()`方法，返回实体的类型。子类使用这个方法来通过使用 Criteria API 构建数据库查询。

`BaseRepositoryImpl`类的源代码如下：

```java
public abstract class BaseRepositoryImpl<T extends BaseEntity, ID extends Serializable> implements BaseRepository<T, ID> {

    private Class<T> entityClass;

    @PersistenceContext(unitName = "pu")
    private EntityManager em;

    public BaseDAOImpl() {
        this.entityClass = ((Class<T>) ((ParameterizedType) getClass().getGenericSuperclass()).getActualTypeArguments()[0]);
    }

    @Override
    @Transactional(propagation = Propagation.REQUIRED)
    public T deleteById(ID id) {
        T entity = findById(id);
        if (entity != null) {
            em.remove(entity);
        }
        return entity;
    }

    @Override
    public List<T> findAll() {
        CriteriaBuilder cb = em.getCriteriaBuilder();
        CriteriaQuery<T> query = cb.createQuery(entityClass);
        Root<T> root = query.from(entityClass);
        return em.createQuery(query).getResultList();
    }

    @Override
    public T findById(ID id) {
        return em.find(getEntityClass(), id);
    }

    @Override
    @Transactional(propagation = Propagation.REQUIRED)
    public void persist(T entity) {
        em.persist(entity);
    }

    protected Class<T> getEntityClass() {
        return entityClass;
    }

    protected EntityManager getEntityManager() {
        return em;
    }
}
```

接下来，我们必须创建一个实体类。我们可以通过以下步骤创建这个类：

1.  扩展`BaseEntity`类，并将实体 ID 类型作为类型参数。

1.  实现`getId()`方法，返回实体的 ID。

`Contact`类的源代码如下：

```java
@Entity
@Table(name = "contacts")
public class Contact extends BaseEntity<Long> {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO) private Long id;

    @Override
    public Long getId() {
        return id;
    }
}
```

接下来，我们必须为我们的实体特定存储库创建一个接口。我们可以通过扩展`BaseRepository`接口并提供实体类型和其 ID 类型作为类型参数来实现这一点。`ContactRepository`接口的源代码如下：

```java
public interface ContactRepository extends BaseRepository<Contact, Long> {
//Declare custom methods here.
}
```

接下来，我们必须创建特定实体的具体存储库。我们可以通过以下步骤创建一个具体的存储库：

1.  用`@Repository`注解注释具体的存储库类，将创建的类标识为存储库类。

1.  扩展`BaseRepositoryImpl`类，并将实体类型和实体 ID 类型作为类型参数。

1.  实现`ContactRepository`接口。

`ContactRepositoryImpl`类的源代码如下：

```java
@Repository
public class ContactRepositoryImpl extends BaseRepositoryImpl<Contact, Long> implements ContactRepository {
  //Add custom query methods here
}
```

恭喜！我们现在以传统方式创建了一个具体的存储库。我们的存储库实现结构如下图所示：

![以传统方式创建自定义存储库](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprdt/img/9045_02_01.jpg)

正如我们注意到的，实现具体存储库是一个复杂的过程，需要花费大量时间，而我们本可以用来实际生产。幸运的是，这不是为我们的实体创建存储库的唯一方法。接下来我们将学习一种更简单、更容易的创建自定义存储库的方法。当然，我们说的是 Spring Data JPA。

### 使用 Spring Data JPA 创建自定义存储库

Spring Data JPA 能够从特殊的存储库接口自动创建具体的存储库实现。这种能力简化了自定义存储库的创建过程。

我们可以通过创建一个接口来为实体创建一个 JPA 存储库，该接口扩展了`JpaRepository`接口。当我们扩展`JpaRepository`接口时，我们必须提供两个类型参数：实体的类型和实体的对象标识符的类型。

在我们的情况下，我们需要为`Contact`实体创建一个存储库。其对象标识符的类型是`Long`。因此，`ContactRepository`接口的源代码应该如下所示：

```java
public interface ContactRepository extends JpaRepository<Contact, Long> {
}
```

就是这样。我们现在已经为`Contact`实体创建了一个存储库。我们的存储库实现结构如下图所示：

![使用 Spring Data JPA 创建自定义存储库](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprdt/img/9045_02_02.jpg)

正如我们所看到的，创建自定义存储库的过程不可能比这更简单了。Spring Data JPA 减少了我们需要编写和维护的代码量，以及编写所需的时间。换句话说，我们可以通过更简单的代码在更短的时间内获得相同的功能。这个优势相当难以超越。

通过扩展`JpaRepository`接口，我们现在已经获得了实现 CRUD 应用程序所需的四种方法。这些方法在下表中描述：

| 方法 | 描述 |
| --- | --- |
| `Void delete(Contact contact)` | 从数据库中删除单个联系人。 |
| `Contact findOne(Long id)` | 返回单个联系人，如果找不到联系人则返回 null。 |
| `List<Contact> findAll()` | 返回存储在数据库中的所有联系人。 |
| `Contact save(Contact contact)` | 将给定的联系人保存到数据库并返回保存的联系人。 |

## CRUD

我们现在已经配置了 Spring 应用程序上下文，实现了应用程序的领域模型，并为`Contact`实体创建了存储库。我们终于准备好为`Contact`实体提供 CRUD 功能的服务类的源代码。

让我们从为我们的服务创建一个接口开始。它的作用是声明用于处理联系信息的方法。让我们称这个接口为`ContactService`。我们的接口的源代码如下所示：

```java
public interface ContactService {

    public Contact add(ContactDTO added);
    public Contact deleteById(Long id) throws NotFoundException;
    public List<Contact> findAll();
    public Contact findById(Long id) throws NotFoundException;
    public Contact update(ContactDTO updated) throws NotFoundException;
}
```

`ContactService`接口提到了一个名为`ContactDTO`的类。它是用于将信息传递给我们的服务实现的**数据传输对象**（**DTO**）。这个 DTO 在我们应用程序的 Web 层中用作表单对象，它只包含添加或更新联系信息所需的信息。换句话说，它里面没有逻辑。这就是为什么它的源代码在这里没有讨论。

### 注意

数据传输对象的概念在[`martinfowler.com/eaaCatalog/dataTransferObject.html`](http://martinfowler.com/eaaCatalog/dataTransferObject.html)中有描述。

我们的下一步是创建一个实现`ContactService`接口的实现。让我们首先创建一个虚拟实现，稍后再添加实际逻辑。虚拟服务实现描述如下：

1.  `@Service`注解用于标记我们的实现为服务类。通过添加这个注解，我们确保该类将在类路径扫描期间自动检测到。

1.  我们使用`@Resource`注解告诉 Spring **IoC 容器**必须将创建的存储库实现注入到服务的`repository`字段中。

### 注意

通过使用`@Transactional`注解，服务类的每个方法都被标记为事务性。`rollbackFor`配置选项确保如果抛出了任何配置的异常，则事务将被回滚。

我们的虚拟服务类的源代码如下所示：

```java
@Service
public class RepositoryContactService implements ContactService {

    @Resource
    private ContactRepository repository;

    //Empty method skeletons
}
```

接下来我们将动手学习如何使用 Spring Data JPA 创建、读取、更新和删除实体。

### 创建

我们可以通过以下步骤创建一个新的实体：

1.  使用构建器模式创建一个新的`Contact`对象。

1.  将创建的对象传递给我们存储库的`save()`方法。

1.  返回创建的对象。

`add()`方法的源代码如下所示：

```java
@Transactional
@Override
public Contact add(ContactDTO added) {
    //Creates an instance of a Contact by using the builder pattern
    Contact contact = Contact.getBuilder(added.getFirstName(), added.getLastName())
            .address(added.getStreetAddress(), added.getPostCode(), added.getPostOffice(), added.getState(), added.getCountry())
            .emailAddress(added.getEmailAddress())
            .phoneNumber(added.getPhoneNumber())
            .build();
    return repository.save(contact);
}
```

### 读取

我们的应用程序必须向用户提供所有联系人的列表以及单个联系人的信息。`ContactService`接口声明了两个与这些用例相关的方法。这些方法是：`findAll()`和`findById()`。

我们的`findAll()`方法的实现非常简单。我们只是将方法调用委托给存储库。`findAll()`方法的源代码如下所示：

```java
@Transactional(readOnly = true)
@Override
public List<Contact> findAll() {
    return repository.findAll();
}
```

现在我们必须创建`findById()`方法的实现。我们的实现包含以下步骤：

1.  通过调用我们存储库的`findOne()`方法来查找联系人。

1.  如果找不到联系人，则抛出`NotFoundException`。

1.  返回找到的联系人。

`findById()`方法的源代码如下所示：

```java
@Transactional(readOnly = true)
@Override
public Contact findById(Long id) throws NotFoundException {
    Contact found = repository.findOne(id);

    if (found == null) {
        throw new NotFoundException("No contact found with id: " + id);
    }

    return found;
}
```

### 更新

我们可以通过以下步骤更新联系人的信息：

1.  使用服务的`findById()`方法查找更新后的联系人。因此，如果找不到联系人，则会抛出`NotFoundException`。

1.  更新联系信息。

1.  更新地址信息。

1.  返回更新后的联系人。

`update()`方法的源代码如下所示：

```java
@Transactional(rollbackFor = NotFoundException.class)
@Override
public Contact update(ContactDTO updated) throws NotFoundException {
    Contact found = findById(updated.getId());

    found.update(updated.getFirstName(), updated.getLastName(), updated.getEmailAddress(), updated.getPhoneNumber());

    found.updateAddress(updated.getStreetAddress(), updated.getPostCode(), updated.getPostOffice(), updated.getState(), updated.getCountry());

    return found;
}
```

### 注意

如果我们在读写事务中，更新实体信息后不需要显式调用存储库的`save()`方法。当事务提交时，对持久实体所做的所有更改都会自动更新到数据库中。

### 删除

我们可以通过以下步骤删除联系人：

1.  通过调用`findById()`方法来查找已删除的联系人，如果找不到联系人，则抛出`NotFoundException`。

1.  将联系人作为参数传递给我们存储库的`delete()`。

1.  返回已删除的联系人。

`deleteById()`方法的源代码如下所示：

```java
@Transactional(rollbackFor = NotFoundException.class)
@Override
public Contact deleteById(Long id) throws NotFoundException {
    Contact deleted = findById(id);
    repository.delete(deleted);
    return deleted;
}
```

# 摘要

在本章中，我们已经学到了：

+   Maven 提供了一种简单的方法来设置 Spring Data JPA 项目

+   如果我们使用 Spring Framework 3.0 或更新版本，可以通过编程配置来配置应用程序的应用程序上下文

+   如果我们在 Servlet 3.0 环境中使用 Spring Framework 3.1，可以在没有`web.xml`的情况下配置我们的 Web 应用程序

+   Spring Data JPA 简化了自定义存储库的创建，因为它可以自动创建我们存储库接口的具体实现。

构建 CRUD 应用程序是一个很好的开始，但它并不能帮助我们创建现实生活中的应用程序。在下一章中，我们将解决这个问题，并描述如何使用 Spring Data JPA 创建数据库查询。


# 第三章：使用 Spring Data JPA 构建查询

我们已经学会了如何配置 Spring Data JPA 并实现了一个简单的 CRUD 应用程序。现在是时候学习一些技能，这些技能将帮助我们实现真实的应用程序。在本章中，我们将涵盖：

+   我们如何使用查询方法创建查询

+   我们如何使用 JPA Criteria API 创建动态查询

+   我们如何使用 Querydsl 创建动态查询

+   我们如何对查询结果进行排序和分页

在本章中，我们将通过向联系人管理应用程序添加搜索功能来扩展它。搜索功能的要求如下：

+   搜索功能必须返回所有名字或姓氏以给定搜索词开头的联系人

+   搜索必须不区分大小写

+   搜索结果必须按姓氏和名字按升序排序

+   搜索功能必须能够对搜索结果进行分页

我们还将学习如何对应用程序主页上显示的联系人列表进行排序和分页。

# 构建查询

我们可以使用 Spring Data JPA 构建查询的三种选项：查询方法，JPA Criteria API 和 Querydsl。在本节中，我们将学习如何使用它们并开始实现我们的搜索功能。我们还将看一下每个选项的优缺点，并得到关于选择正确的查询创建技术的具体建议。

在我们继续之前，我们必须向`ContactService`接口添加一个`search()`方法，该方法用作我们搜索功能的起点。`search()`方法的签名如下代码片段所示：

```java
public List<Contact> search(String searchTerm);
```

## 查询方法

使用 Spring Data JPA 创建查询的最简单方法是使用查询方法。**查询方法**是在存储库接口中声明的方法。我们可以使用三种技术来创建查询方法：

+   **从方法名称生成查询**

+   **命名查询**

+   `@Query`注解

### 从方法名称生成查询

从方法名称生成查询是一种查询生成策略，其中执行的查询是从查询方法的名称中解析出来的。用于创建查询方法名称的命名约定有三个重要组件：**方法前缀**，**属性表达式**和**关键字**。接下来，我们将学习这些组件的基本用法并实现我们的搜索功能。我们还将看一下这种方法的优缺点。

#### 方法前缀

每个方法的名称必须以特殊前缀开头。这确保该方法被识别为查询方法。支持的前缀是`findBy`，`find`，`readBy`，`read`，`getBy`和`get`。所有前缀都是同义词，对解析的查询没有影响。

#### 属性表达式

属性表达式用于引用托管实体的直接属性或嵌套属性。我们将使用`Contact`实体来演示以下表中属性表达式的用法：

| 属性表达式 | 引用的属性 |
| --- | --- |
| `LastName` | `Contact`类的`lastName`属性。 |
| `AddressStreetAddress` | `Address`类的`streetAddress`属性。 |

让我们通过使用`AddressStreetAddress`属性表达式来了解属性解析算法是如何工作的。该算法有三个阶段：

1.  首先，它将检查实体类是否具有与属性表达式匹配的名称的属性，当属性表达式的第一个字母转换为小写时。如果找到匹配项，则使用该属性。如果在`Contact`类中找不到名为`addressStreetAddress`的属性，则算法将移至下一个阶段。

1.  属性表达式从右向左按驼峰命名部分分割为头部和尾部。完成后，算法尝试从实体中找到匹配的属性。如果找到匹配，算法会尝试按照属性表达式的部分从头到尾找到引用的属性。在这个阶段，我们的属性表达式被分成两部分：`AddressStreet`和`Address`。由于`Contact`实体没有匹配的属性，算法继续到第三阶段。

1.  分割点向左移动，算法尝试从实体中找到匹配的属性。属性表达式被分成两部分：`Address`和`StreetAddress`。从`Contact`类中找到匹配的属性`address`。此外，由于`Address`类有一个名为`streetAddress`的属性，也找到了匹配。

### 注意

如果`Contact`类有一个名为`addressStreetAddress`的属性，属性选择算法会选择它而不是`Address`类的`streetAddress`属性。我们可以通过在属性表达式中使用下划线字符手动指定遍历点来解决这个问题。在这种情况下，我们应该使用属性表达式`Address_StreetAddress`。

#### 关键词

关键词用于指定针对属性值的约束，这些属性由属性表达式引用。有两条规则用于将属性表达式与关键词组合在一起：

+   我们可以通过在属性表达式后添加关键字来创建**约束**

+   我们可以通过在它们之间添加**And**或**Or**关键字来组合约束

Spring Data JPA 的参考手册（[`static.springsource.org/spring-data/data-jpa/docs/current/reference/html/`](http://static.springsource.org/spring-data/data-jpa/docs/current/reference/html/)）描述了如何使用属性表达式和关键词创建查询方法：

| 关键词 | 示例 | JPQL 片段 |
| --- | --- | --- |
| `And` | `findByLastNameAndFirstName` | `where x.lastname = ?1 and x.firstname = ?2` |
| `Or` | `findByLastNameOrFirstName` | `where x.lastname = ?1 or x.firstname = ?2` |
| `Between` | `findByStartDateBetween` | `where x.startDate between 1? and ?2` |
| `LessThan` | `findByAgeLessThan` | `where x.age < ?1` |
| `GreaterThan` | `findByAgeGreaterThan` | `where x.age > ?1` |
| `After` | `findByStartDateAfter` | `where x.startDate > ?1` |
| `Before` | `findByStartDateBefore` | `where x.startDate < ?1` |
| `IsNull` | `findByAgeIsNull` | `where x.age is null` |
| `IsNotNull`, `NotNull` | `findByAge`(`Is`)`NotNull` | `where x.age is not null` |
| `Like` | `findByFirstNameLike` | `where x.firstname like ?1` |
| `NotLike` | `findByFirstNameNotLike` | `where x.firstname not like ?1` |
| `StartingWith` | `findByFirstNameStartingWith` | `where x.firstname like ?1`（参数绑定为附加`%`） |
| `EndingWith` | `findByFirstNameEndingWith` | `where x.firstname like ?1`（参数绑定为前置`%`） |
| `Containing` | `findByFirstNameContaining` | `where x.firstname like ?1`（参数绑定包裹在`%`中） |
| `OrderBy` | `findByAgeOrderByLastNameDesc` | `where x.age = ?1 order by x.lastname desc` |
| `Not` | `findByLastNameNot` | `where x.lastname <> ?1` |
| `In` | `findByAgeIn`（Collection<Age> ages） | `where x.age in ?1` |
| `NotIn` | `findByAgeNotIn`（Collection<Age> ages） | `where x.age not in ?1` |
| `True` | `findByActiveTrue` | `where x.active = true` |
| `False` | `findByActiveFalse` | `where x.active = false` |

#### 实现搜索功能

现在是时候运用我们学到的技能，为我们的联系人管理应用程序添加搜索功能了。我们可以通过以下步骤来实现搜索功能：

1.  我们按照描述的命名约定向`ContactRepository`接口添加查询方法。

1.  我们实现一个使用查询方法的服务方法。

首先，我们必须创建查询方法。我们的查询方法的签名如下：

```java
public List<Contact> findByFirstNameStartingWithOrLastNameStartingWith(String firstName, String lastName);
```

其次，我们必须将`search()`方法添加到`RepositoryContactService`类中。这个方法简单地将方法调用委托给存储库，并将使用的搜索词作为参数。实现方法的源代码如下：

```java
@Transactional(readOnly = true)
@Override
public List<Contact> search(String searchTerm) {
  return repository.findByFirstNameStartingWithOrLastNameStartingWith(searchTerm, searchTerm);
}
```

#### 优点和缺点

我们现在已经学会了如何使用方法名称策略生成查询。这种策略的优缺点在下表中描述：

| 优点 | 缺点 |
| --- | --- |

|

+   这是创建简单查询的快速方法

+   它为方法名称提供了一致的命名策略

|

+   方法名称解析器的特性决定了我们可以创建什么样的查询

+   复杂查询方法的方法名称又长又难看

+   查询在运行时进行验证

+   不支持动态查询

|

方法名称解析器的限制的一个很好的例子是缺少`Lower`关键字。这意味着我们无法通过使用这种策略来实现不区分大小写的搜索。接下来我们将学习创建不受此限制的查询的替代策略。

### 命名查询

使用 Spring Data JPA 创建查询方法的第二种方法是使用命名查询。如果我们想要使用命名查询创建查询方法，我们必须：

1.  创建一个命名查询。

1.  创建执行命名查询的查询方法。

1.  创建一个使用创建的查询方法的服务方法。

这些步骤在下一节中有更详细的描述。我们还将讨论命名查询的优缺点。

#### 创建命名查询

Spring Data JPA 支持使用 JPQL 或 SQL 创建的命名查询。所使用的查询语言的选择决定了创建的命名查询是如何声明的。

我们可以通过以下步骤创建一个 JPA 命名查询：

1.  将`@NamedQueries`注解添加到实体类中。这个注解以`@NamedQuery`注解的数组作为其值，并且如果我们指定了多个命名查询，必须使用它

1.  我们使用`@NamedQuery`注解来创建命名查询。这个注解有两个对我们有关系的属性：`name`属性存储了命名查询的名称，`query`属性包含了执行的 JPQL 查询。

我们的使用 JPQL 的命名查询的声明如下：

```java
@Entity
@NamedQueries({
@NamedQuery(name = "Contact.findContacts",
        query = "SELECT c FROM Contact c WHERE LOWER(c.firstName) LIKE LOWER(:searchTerm) OR LOWER(c.lastName) LIKE LOWER(:searchTerm)")
})
@Table(name = "contacts")
public class Contact
```

### 注意

我们也可以使用 XML 声明命名查询。在这种情况下，我们必须使用`named-query`元素，并在实体映射 XML 文件中声明查询。

我们可以通过以下步骤创建一个命名的本地查询：

1.  我们将`@NamedNativeQueries`注解添加到实体类中。这个注解接受`@NamedNativeQuery`注解的数组作为其值，并且如果我们指定了多个本地命名查询，必须使用它。

1.  我们通过使用`@NamedNativeQuery`注解来创建本地命名查询。创建的本地命名查询的名称存储在`name`属性中。`query`属性的值是执行的 SQL 查询。`resultClass`属性包含了查询返回的实体类。

### 注意

如果命名本地查询不返回实体或实体列表，我们可以使用`@SqlResultSetMapping`注解将查询结果映射到正确的返回类型。

我们的命名本地查询的声明如下代码片段：

```java
@Entity
@NamedNativeQueries({
@NamedNativeQuery(name = "Contact.findContacts",
        query = "SELECT * FROM contacts c WHERE LOWER(c.first_name) LIKE LOWER(:searchTerm) OR LOWER(c.last_name) LIKE LOWER(:searchTerm)",
        resultClass = Contact.class)
})
@Table(name = "contacts")
public class Contact
```

### 注意

我们也可以使用 XML 创建命名本地查询。在这种情况下，我们必须使用`named-native-query`元素，并在实体映射 XML 文件中声明 SQL 查询。

#### 创建查询方法

我们的下一步是将查询方法添加到联系人存储库中。我们将不得不：

1.  确定查询方法的正确名称。Spring Data JPA 通过假装托管实体的简单名称和方法名称之间的点来将方法名称解析回命名查询。我们的命名查询的名称是`Contact.findContacts`。因此，我们必须在`ContactRepository`接口中添加一个名为`findContacts`的方法。

1.  使用`@Param`注解将方法参数标识为我们查询中使用的命名参数的值。

添加的查询方法的签名如下所示：

```java
public List<Contact> findContacts(@Param("searchTerm") String searchTerm);
```

#### 创建服务方法

接下来，我们必须将`search()`方法添加到`RepositoryContactService`类中。我们的实现包括以下步骤：

1.  构建使用的 like 模式。

1.  通过调用创建的查询方法来获取搜索结果。

`search()`方法的源代码如下：

```java
@Transactional(readOnly = true)
@Override
public List<Contact> search(String searchTerm) {
String likePattern = buildLikePattern(searchTerm);
   return repository.findContacts(likePattern);
}

private String buildLikePattern(String searchTerm) {
   return searchTerm + "%";
}
```

#### 优缺点

现在我们可以使用命名查询来创建查询方法。这种方法的优缺点在下表中描述：

| 优点 | 缺点 |
| --- | --- |

|

+   支持 JPQL 和 SQL

+   使得迁移现有应用程序使用命名查询到 Spring Data JPA 更容易

+   本地查询的返回类型不限于实体或实体列表

|

+   查询验证在运行时完成

+   不支持动态查询

+   查询逻辑使我们的实体类的代码混乱

|

### @Query 注解

`@Query`注解用于指定调用查询方法时执行的查询。我们可以使用`@Query`注解来实现 JPQL 和 SQL 查询：

1.  向存储库添加一个新的方法，并用`@Query`注解进行注释。

1.  创建使用查询方法的服务方法。

### 注意

如果使用`@Query`注解的方法名称与命名查询的名称冲突，则将执行注解的查询。

接下来，我们将得到具体的指导说明，以指导我们完成所描述的步骤，并了解这种技术的优缺点。

#### 创建查询方法

首先我们必须将查询方法添加到`ContactRepository`类中。正如我们已经知道的，我们可以使用 JPQL 或 SQL 来创建实际的查询。使用的查询语言对查询方法的创建有一些影响。

我们可以通过以下方式创建使用 JPQL 的查询方法：

1.  向`ContactRepository`接口添加一个新的方法。

1.  使用`@Param`注解将方法的参数标识为命名参数的值。

1.  用`@Query`注解注释方法，并将执行的 JPQL 查询设置为其值。

我们的查询方法的声明，满足搜索功能的要求，如下所示：

```java
@Query("SELECT c FROM Contact c WHERE LOWER(c.firstName) LIKE LOWER(:searchTerm) OR LOWER(c.lastName) LIKE LOWER(:searchTerm)")
public Page<Contact> findContacts(@Param("searchTerm") String searchTerm);
```

为了创建一个使用 SQL 的查询方法，我们必须：

1.  向`ContactRepository`接口添加一个新的方法。

1.  使用`@Param`注解将方法参数标识为 SQL 查询中使用的命名参数的值。

1.  用`@Query`注解注释创建的方法，并将 SQL 查询设置为其值。将`nativeQuery`属性的值设置为 true。

### 注意

使用`@Query`注解创建的本地查询只能返回实体或实体列表。如果我们需要不同的返回类型，必须使用命名查询，并使用`@SqlResultSetMapping`注解映射查询结果。

实现满足搜索功能要求的查询方法的声明如下代码片段所示：

```java
@Query(value = "SELECT * FROM contacts c WHERE LOWER(c.first_name) LIKE LOWER(:searchTerm) OR LOWER(c.last_name) LIKE LOWER(:searchTerm), nativeQuery = true)
public List<Contact> findContacts(@Param("searchTerm") String searchTerm);
```

### 注意

Spring Data JPA 不支持使用`@Query`注解创建的本地查询的动态排序或分页支持，因为没有可靠的方法来操作 SQL 查询。

#### 创建服务方法

我们的下一步是向`RepositoryContactService`类添加`search()`方法的实现。我们可以通过以下方式实现：

1.  获取使用的 like 模式。

1.  通过调用创建的查询方法来获取搜索结果。

实现的`search()`方法的源代码如下： 

```java
@Transactional(readOnly = true)
@Override
public List<Contact> search(String searchTerm) {
   String likePattern = buildLikePattern(searchTerm);
   return repository.findContacts(likePattern);
}

private String buildLikePattern(String searchTerm) {
   return searchTerm + "%";
}
```

#### 优缺点

我们现在已经学会了如何使用`@Query`注解来创建查询方法。这种方法自然地具有优缺点，如下表所述：

| 优点 | 缺点 |
| --- | --- |

|

+   支持 JPQL 和 SQL

+   方法名称没有命名约定

|

+   本地查询只能返回实体或实体列表

+   不支持动态查询

+   查询验证在运行时完成

|

## JPA Criteria API

JPA Criteria API 为我们提供了以面向对象的方式创建动态和类型安全查询的方法。我们可以通过以下步骤创建**条件查询**：

1.  我们向存储库添加 JPA Criteria API 支持。

1.  我们创建了执行的条件查询。

1.  我们创建了一个执行创建的查询的服务方法。

这些步骤以及使用 JPA Criteria API 的优缺点将在以下部分中描述。

### 将 JPA Criteria API 支持添加到存储库

我们可以通过扩展`JpaSpecificationExecutor<T>`接口向存储库添加 JPA Criteria API 支持。当我们扩展这个接口时，我们必须将受管实体的类型作为类型参数给出。`ContactRepository`接口的源代码如下所示：

```java
public interface ContactRepository extends JpaRepository<Contact, Long>, JpaSpecificationExecutor<Contact> {

}
```

扩展`JpaSpecificationExecutor<T>`接口使我们可以访问以下方法，这些方法可用于执行条件查询：

| 方法 | 描述 |
| --- | --- |
| 返回与给定搜索条件匹配的实体数量。 |
| `List<Contact> findAll(Specification<Contact> s)` | 返回与给定搜索条件匹配的所有实体。 |
| 返回与给定搜索条件匹配的单个联系人。 |

### 创建条件查询

正如我们所学的，Spring Data JPA 使用`Specification<T>`接口来指定条件查询。这个接口声明了`Predicate toPredicate(Root<T> root, CriteriaQuery<?> query, CriteriaBuilder cb)`方法，我们可以使用它来创建执行的条件查询。

为了为`Contact`实体创建条件查询，我们必须：

1.  为`Contact`实体创建一个静态元模型类。

1.  创建构建`Specification<Contact>`对象的方法。

#### 创建静态元模型类

静态元模型类提供对描述实体属性的元数据的静态访问，并用于使用 JPA Criteria API 创建类型安全查询。静态元模型类通常是自动生成的，但在这里，我们将为了示例而手动创建一个。我们可以通过遵循以下规则创建一个静态元模型类：

+   静态元模型类应放置在与相应实体相同的包中

+   静态元模型类的名称是通过在相应实体的简单名称后附加下划线字符来创建的

由于我们在构建条件查询时只使用`Contact`实体的`firstName`和`lastName`属性，我们可以忽略其他属性。`Contact_`类的源代码如下所示：

```java
@StaticMetamodel(Contact.class)
public class Contact_ {
    public static volatile SingularAttribute<Contact, String> firstName;
    public static volatile SingularAttribute<Contact, String> lastName;
}
```

#### 创建规范

我们可以通过创建一个规范构建器类并使用静态方法来构建实际的规范，以清晰的方式创建规范。用于构建所需 like 模式的逻辑也移动到了这个类中。我们规范构建器类的实现在以下步骤中解释：

1.  我们创建了一个`getLikePattern()`方法，用于从搜索词创建 like 模式。

1.  我们创建一个静态的`firstOrLastNameStartsWith()`方法，返回一个新的`Specification<Contact>`对象。

1.  我们在`Specification<Contact>`的`toPredicate()`方法中构建条件查询。

我们的规范构建器类的源代码如下所示：

```java
public class ContactSpecifications {

    public static Specification<Contact> firstOrLastNameStartsWith(final String searchTerm) {
        return new Specification<Contact>() {
        //Creates the search criteria
        @Override
        public Predicate toPredicate(Root<Contact> root, CriteriaQuery<?> criteriaQuery, cb cb) {
            String likePattern = getLikePattern(searchTerm);
            return cb.or(
            //First name starts with given search term
            cb.like(cb.lower(root.<String>get(Contact_.firstName)), likePattern),
            //Last name starts with the given search term

            cb.like(cb.lower(root.<String>get(Contact_.lastName)), likePattern)
                );
            }

      private String getLikePattern(final String searchTerm) {
          return searchTerm.toLowerCase() + "%";
            }
        };
    }
}
```

### 创建服务方法

我们`RepositoryContactService`类的`search()`方法的实现包含以下两个步骤：

1.  我们通过使用我们的规范构建器获得`Specification<Contact>`对象。

1.  我们通过调用存储库的`findAll()`方法并将`Specification<Contact>`对象作为参数传递来获取搜索结果。

我们的实现的源代码如下所示：

```java
@Transactional(readOnly = true)
@Override
public List<Contact> search(String searchTerm) {
Specification<Contact> contactSpec = firstOrLastNameStartsWith(searchTerm);
    return repository.findAll(contactSpec);
}
```

### 优缺点

我们现在已经学会了如何使用 JPA Criteria API 实现动态查询。在我们可以在实际应用程序中使用这些技能之前，我们应该了解这种方法的优缺点。这些在下表中描述：

| 优点 | 缺点 |
| --- | --- |

|

+   支持动态查询

+   语法验证在编译期间完成

+   使得迁移使用 JPA Criteria API 的应用程序到 Spring Data JPA 更容易

|

+   复杂查询难以实现和理解

|

## Querydsl

**Querydsl**是一个框架，通过类似 SQL 的 API 实现类型安全的动态查询的构建（要了解更多关于 Querydsl 的信息，请访问[`www.querydsl.com/`](http://www.querydsl.com/)）。如果我们想使用 Querydsl 创建查询，我们必须：

1.  配置 Querydsl Maven 集成。

1.  生成 Querydsl 查询类型。

1.  向存储库添加 Querydsl 支持。

1.  创建执行的查询。

1.  执行创建的查询。

我们将在下一节中更详细地解释这些步骤，并且我们还将看一下 Querydsl 的优缺点。

### 配置 Querydsl-Maven 集成

Querydsl-Maven 集成的配置包括两个步骤：

1.  我们配置所需的依赖项。

1.  我们配置用于代码生成的 APT Maven 插件。

#### 配置 Querydsl Maven 依赖项

因为我们正在使用 Querydsl 与 JPA，所以必须在`pom.xml`文件中声明以下依赖项：

+   提供 Querydsl 核心，提供 Querydsl 的核心功能

+   Querydsl APT，提供基于 APT 的代码生成支持

+   Querydsl JPA，为 JPA 注解添加支持

我们正在使用 Querydsl 版本 2.8.0。因此，我们必须将以下依赖声明添加到`pom.xml`文件的依赖项部分：

```java
<dependency>
  <groupId>com.mysema.querydsl</groupId>
  <artifactId>querydsl-core</artifactId>
  <version>2.8.0<version>
</dependency>
<dependency>
  <groupId>com.mysema.querydsl</groupId>
  <artifactId>querydsl-apt</artifactId>
  <version>2.8.0</version>
</dependency>
<dependency>
  <groupId>com.mysema.querydsl</groupId>
  <artifactId>querydsl-jpa</artifactId>
  <version>2.8.0</version>
</dependency>
```

#### 配置代码生成 Maven 插件

我们的下一步是配置 Java 6 的注解处理工具的 Maven 插件，用于生成 Querydsl 查询类型。我们可以通过以下方式配置此插件：

1.  配置插件以在 Maven 的`generate-sources`生命周期阶段执行其`process`目标。

1.  指定生成查询类型的目标目录。

1.  配置代码生成器以查找实体类的 JPA 注解。

Maven APT 插件的配置如下：

```java
<plugin>
  <groupId>com.mysema.maven</groupId>
    <artifactId>maven-apt-plugin</artifactId>
  <version>1.0.4</version>
  <executions>
      <execution>
          <phase>generate-sources</phase>
      <goals>
        <goal>process</goal>
      </goals>
      <configuration>
        <outputDirectory>target/generated-sources</outputDirectory>
  <processor>com.mysema.query.apt.jpa.JPAAnnotationProcessor</processor>
      </configuration>
    </execution>
  </executions>
</plugin>
```

### 生成 Querydsl 查询类型

如果我们的配置正常工作，使用 Maven 构建项目时，Querydsl 查询类型应该会自动生成。

### 注意

Maven APT 插件存在一个已知问题，阻止直接从 Eclipse 使用它。Eclipse 用户必须通过在命令提示符下运行命令`mvn generate-sources`来手动创建 Querydsl 查询类型。

查询类型可以从`target/generated-sources`目录中找到。生成的查询类型将适用以下规则：

+   每个查询类型都生成在与相应实体相同的包中。

+   查询类型类的名称是通过将实体类的简单名称附加到字母"`Q`"来构建的。例如，由于我们的实体类的名称是`Contact`，相应的 Querydsl 查询类型的名称是`QContact`。

### 注意

在我们的代码中使用查询类型之前，我们必须将`target/generated-sources`目录添加为项目的源目录。

### 向存储库添加 Querydsl 支持

我们可以通过扩展`QueryDslPredicateExecutor<T>`接口来向存储库添加 Querydsl 支持。当我们扩展此接口时，必须将托管实体的类型作为类型参数给出。`ContactRepository`接口的源代码如下：

```java
public interface ContactRepository extends JpaRepository<Contact, Long>, QueryDslPredicateExecutor<Contact> {
}
```

在我们扩展了`QueryDslPredicateExecutor<T>`接口之后，我们可以访问以下方法：

| 方法 | 描述 |
| --- | --- |
| `long count(Predicate p)` | 返回与给定搜索条件匹配的实体数量。 |
| `Iterable<Contact> findAll(Predicate p)` | 返回与给定搜索条件匹配的所有实体。 |
| `Contact findOne(Predicate p)` | 返回与给定搜索条件匹配的单个实体。 |

### 创建执行的查询

每个查询必须实现 Querydsl 提供的`Predicate`接口。幸运的是，我们不必手动实现这个接口。相反，我们可以使用查询类型来创建实际的查询对象。一个清晰的方法是创建一个特殊的 predicate 构建器类，并使用静态方法来创建实际的 predicates。让我们称这个类为`ContactPredicates`。我们实现了创建满足搜索功能要求的 predicates 的静态方法，如下所述：

1.  我们实现了一个静态的`firstOrLastNameStartsWith()`方法，返回`Predicate`接口的实现。

1.  我们获得了`QContact`查询类型的引用。

1.  我们使用`QContact`查询类型构建我们的查询。

我们的 predicate 构建器类的源代码如下：

```java
public class ContactPredicates {

    public static Predicate firstOrLastNameStartsWith(final String searchTerm) {
        QContact contact = QContact.contact;
        return contact.firstName.startsWithIgnoreCase(searchTerm)
                .or(contact.lastName.startsWithIgnoreCase(searchTerm));
    }
}
```

### 执行创建的查询

我们通过以下方式实现了`RepositoryContactService`类的`search()`方法：

1.  通过调用`ContactPredicates`类的静态`firstOrLastNAmeStartsWith()`方法获取使用的 predicate。

1.  通过调用我们的存储库方法并将 predicate 作为参数传递来获取结果。

1.  使用`Commons Collections`库中的`CollectionUtils`类将每个联系人添加到返回的列表中。

我们的实现源代码如下：

```java
@Transactional(readOnly = true)
@Override
public List<Contact> search(String searchTerm) {
  Predicate contactPredicate = firstOrLastNameStartsWith(searchTerm);

  Iterable<Contact> contacts = repository.findAll(contactPredicate);
  List<Contact> contactList = new ArrayList<Contact>();
  CollectionUtils.addAll(contactList, contacts.iterator());

  return contactList;
}
```

### 优点和缺点

现在我们能够使用 Spring Data JPA 和 Querydsl 创建查询。Querydsl 的优缺点如下表所述：

| 优点 | 缺点 |
| --- | --- |

|

+   支持动态查询

+   清晰易懂的 API

+   语法验证在编译期间完成

|

+   需要代码生成

+   Eclipse 集成工作不正常

|

## 我们应该使用哪种技术？

在本节中，我们已经讨论了使用 Spring Data JPA 创建查询的不同方法。我们也意识到了每种描述的技术的优缺点。这些信息被细化为以下列表中给出的具体指南：

+   我们应该使用查询方法创建静态查询。

+   如果创建的查询简单且方法名解析器支持所需的关键字，我们可以使用方法名策略生成查询。否则，我们应该使用`@Query`注解，因为它灵活，并且不强制我们使用冗长且丑陋的方法名。

+   如果我们无法使用方法策略生成查询或`@Query`注解创建查询方法，命名查询是有用的。这种方法也可以在将现有应用程序迁移到 Spring Data JPA 时使用。然而，当我们创建新应用程序时，应该谨慎使用它们，因为它们倾向于在我们的实体中添加查询逻辑。

+   如果我们无法使用其他描述的技术创建查询，或者需要调整单个查询的性能，原生查询是有用的。然而，我们必须理解使用原生查询会在我们的应用程序和使用的数据库模式之间创建依赖关系。此外，如果我们使用特定于提供程序的 SQL 扩展，我们的应用程序将与使用的数据库提供程序绑定。

+   如果我们正在将使用 criteria 查询的现有应用程序迁移到 Spring Data JPA，应该使用 JPA Criteria API 来创建动态查询。如果我们无法忍受 Querydsl-Eclipse 集成的问题，JPA Criteria API 也是一个有效的选择。

+   Querydsl 是创建动态查询的绝佳选择。它提供了一个清晰易懂的 API，这是 JPA Criteria API 的巨大优势。Querydsl 应该是我们从头开始创建动态查询的首选。笨拙的 Eclipse 集成自然是 Eclipse 用户的缺点。

# 排序查询结果

在本节课程中，我们将学习使用 Spring Data JPA 对查询结果进行排序的不同技术。我们还将学习可以用于为每种情况选择适当排序方法的准则。

## 使用方法名进行排序

如果我们使用从方法名生成查询的策略构建查询，我们可以按照以下步骤对查询结果进行排序：

1.  创建查询方法

1.  修改现有的服务方法以使用新的查询方法。

### 创建查询方法

当我们使用从方法名生成查询的策略构建查询时，我们可以使用`OrderBy`关键字来对查询结果进行排序，当我们：

1.  将`OrderBy`关键字附加到方法名。

1.  将与实体属性对应的属性表达式附加到方法名，用于对查询结果进行排序。

1.  将描述排序顺序的关键字附加到方法名。如果查询结果按升序排序，则应使用关键字`Asc`。当查询结果按降序排序时，使用`Desc`关键字。

1.  如果使用多个属性对查询结果进行排序，则重复步骤 2 和步骤 3。

我们可以通过在查询方法的名称后附加字符串`OrderByLastNameAscFirstNameAsc`来满足搜索功能的新要求。查询方法的签名如下：

```java
public List<Contact> findByFirstNameStartingWithOrLastNameStartingWithOrderByLastNameAscFirstNameAsc(String firstName, String lastName);
```

### 修改服务方法

我们必须修改`RepositoryContactService`类的`search()`方法，以将方法调用委托给新的查询方法。该方法的源代码如下：

```java
@Transactional(readOnly = true)
@Override
public List<Contact> search(String searchTerm) {
    return repository.findByFirstNameStartingWithOrLastNameStartingWithOrderByLastNameAscFirstNameAsc(searchTerm, searchTerm);
}
```

## 使用查询字符串进行排序

在某些情况下，我们必须将排序逻辑添加到实际的查询字符串中。如果我们使用带有`@Query`注解的命名查询或本地查询，我们必须在实际查询中提供排序逻辑。当我们使用带有 JPQL 查询的`@Query`注解时，也可以将排序逻辑添加到实际查询中。

### JPQL 查询

当我们想对 JPQL 查询的查询结果进行排序时，必须使用 JPQL 的`ORDER BY`关键字。满足搜索功能的 JPQL 查询如下所示：

```java
SELECT c FROM Contact c WHERE LOWER(c.firstName) LIKE LOWER(:searchTerm) OR LOWER(c.lastName) LIKE LOWER(:searchTerm) ORDER BY c.lastName ASC, c.firstName ASC
```

### SQL 查询

当我们想对本地 SQL 查询的查询结果进行排序时，必须使用 SQL 的`ORDER BY`关键字。满足搜索功能的 SQL 查询如下所示：

```java
SELECT * FROM contacts c WHERE LOWER(c.first_name) LIKE LOWER(:searchTerm) OR LOWER(c.last_name) LIKE LOWER(:searchTerm) ORDER BY c.last_name ASC, c.first_name ASC
```

## 使用 Sort 类进行排序

如果我们使用`JpaRepository<T,ID>`接口的方法、查询方法或 JPA Criteria API，我们可以使用`Sort`类对查询结果进行排序。如果我们决定使用这种方法，我们必须：

1.  创建`Sort`类的实例。

1.  将创建的实例作为参数传递给所使用的存储库方法。

### 注意

我们不能使用`Sort`类对带有`@Query`注解声明的命名查询或本地查询的查询结果进行排序。

由于后面描述的所有技术都需要获得`Sort`类的实例，我们将不得不为`RepositoryContactService`类添加一种创建这些对象的方法。我们将通过创建一个私有的`sortByLastNameAndFirstNameAsc()`方法来实现这一点。该方法的源代码如下：

```java
private Sort sortByLastNameAndFirstNameAsc() {
  return new Sort(new Sort.Order(Sort.Direction.ASC, "lastName"),
        new Sort.Order(Sort.Direction.ASC, "firstName")
    );
}
```

### JpaRepository

我们使用了`JpaRepository<T,ID>`接口的`findAll()`方法来获取存储在数据库中的所有实体的列表。然而，当我们扩展了`JpaRepository<T,ID>`接口时，我们还可以访问`List<Contact> findAll(Sort sort)`方法，我们可以使用它来对存储在数据库中的实体列表进行排序。

举例来说，我们将按照姓氏和名字的字母顺序对所有实体的列表进行排序。我们可以通过以下方式实现：

1.  获取一个新的`Sort`对象。

1.  通过调用我们的存储库的`findAll()`方法并将创建的`Sort`对象作为参数传递来获取排序后的实体列表。

`RepositoryContactService`的`findAll()`方法的源代码如下：

```java
@Transactional(readOnly = true)
@Override
public List<Contact> findAll() {
  Sort sortSpec = sortByLastNameAndFirstNameAsc();
  return repository.findAll(sortSpec);
}
```

### 从方法名生成查询

我们还可以使用这种方法来对使用方法名称生成查询的查询结果进行排序。如果我们想使用这种技术，我们必须修改查询方法的签名，以接受`Sort`对象作为参数。我们的查询方法的签名，实现了搜索功能的新排序要求，如下所示：

```java
public Page<Contact> findByFirstNameStartingWithOrLastNameStartingWith(String firstName, String lastName, Sort sort);
```

我们的下一步是更改`RepositoryContactService`类的`search()`方法的实现。新的实现在以下步骤中解释：

1.  我们获得一个`Sort`对象的引用。

1.  我们调用我们的新存储库方法并提供所需的参数。

我们实现的源代码如下所示：

```java
@Transactional(readOnly = true)
@Override
public List<Contact> search(String searchTerm) {
  Sort sortSpec = sortByLastNameAndFirstNameAsc();
  return repository.findByFirstNameStartingWithOrLastNameStartingWith(searchTerm, searchTerm, sortSpec);
}
```

### @Query 注解

如果我们使用`@Query`注解来使用 JPQL 构建查询，我们不必将排序逻辑添加到实际查询中。我们还可以修改查询方法的签名，以接受`Sort`对象作为参数。我们的查询方法的声明如下所示：

```java
@Query("SELECT c FROM Contact c WHERE LOWER(c.firstName) LIKE LOWER(:searchTerm) OR LOWER(c.lastName) LIKE LOWER(:searchTerm)")
public Page<Contact> findContacts(@Param("searchTerm") String searchTerm, Sort sort);
```

下一步是修改`RepositoryContactService`类的`search()`方法。我们对该方法的实现如下所述：

1.  我们创建所使用的 like 模式。

1.  我们获得一个`Sort`对象的引用。

1.  我们调用我们的存储库方法并提供所需的参数。

`search()`方法的源代码如下所示：

```java
@Transactional(readOnly = true)
@Override
public List<Contact> search(String searchTerm) {
    String likePattern = buildLikePattern(dto.getSearchTerm());
    Sort sortSpec = sortByLastNameAndFirstNameAsc();
    return repository.findContacts(likePattern, sortSpec);
}
```

### JPA Criteria API

为了使用 JPA Criteria API 创建查询，我们必须修改`ContactRepository`接口以扩展`JpaSpecificationExecutor<T>`接口。这使我们可以访问`List<Contact> findAll(Specification spec, Sort sort)`方法，该方法返回与给定搜索条件匹配的实体的排序列表。

我们对`RepositoryContactService`类的`search()`方法的实现如下所述：

1.  我们通过使用我们的规范构建器类获取所使用的搜索条件。

1.  我们获取所使用的`Sort`对象。

1.  我们将调用`ContactRepository`的`findAll()`方法并提供必要的参数。

我们的`search()`方法如下所示：

```java
@Transactional(readOnly = true)
@Override
public List<Contact> search(String searchTerm) {
    Specification<Contact> contactSpec = firstOrLastNameStartsWith(searchTerm);
    Sort sortSpec = sortByLastNameAndFirstNameAsc();
    return repository.findAll(contactSpec, sortSpec);
}
```

## 使用 Querydsl 进行排序

在我们的联系人存储库中扩展`QuerydslPredicateExecutor<T>`接口使我们可以访问`Iterable<Contact> findAll(Predicate predicate, OrderSpecifier<?>... orders)`方法，该方法返回与给定搜索条件匹配的所有实体的排序列表。

首先，我们必须创建一个服务方法，该方法创建一个`OrderSpecifier`对象数组。`sortByLastNameAndFirstNameAsc()`方法的源代码如下所示：

```java
private OrderSpecifier[] sortByLastNameAndFirstNameAsc() {
  OrderSpecifier[] orders = {QContact.contact.lastName.asc(), QContact.contact.firstName.asc()};
  return orders;
}
```

我们的下一步是修改`RepositoryContactService`类的`search()`方法的实现，以满足给定的要求。我们对`search()`方法的实现如下所述：

1.  我们获取所使用的搜索条件。

1.  我们通过调用我们之前创建的`sortByLastNameAndFirstNameAsc()`方法来获取所使用的`OrderSpecifier`数组。

1.  我们调用`ContactRepository`的`findAll()`方法并提供所需的参数。

1.  我们使用从`Commons Collections`库中找到的`CollectionUtils`类将所有联系人添加到返回的列表中。

`search()`方法的源代码如下所示：

```java
@Transactional(readOnly = true)
@Override
public List<Contact> search(String searchTerm) {
  Predicate contactPredicate = firstOrLastNameStartsWith(searchTerm);
  OrderSpecifier[] orderSpecs = sortByLastNameAndFirstNameAsc();

  Iterable<Contact> contacts = repository.findAll(contactPredicate, orderSpecs);
  List<Contact> contactList = new ArrayList<Contact>();
  CollectionUtils.addAll(contactList, contacts.iterator());

  return contactList;
}
```

## 我们应该使用什么技术？

最好的方法是尽可能将查询生成和排序逻辑放在同一个地方。这样，我们只需查看一个地方，就可以检查我们查询的实现。这个一般指导方针可以细化为以下具体说明：

+   如果我们正在使用方法名称生成查询，我们应该使用这种方法来对查询结果进行排序。如果方法名称变得太长或太丑，我们总是可以使用`Sort`类来对查询结果进行排序，但这不应该是我们的首选。相反，我们应该考虑使用`@Query`注解来构建我们的查询。

+   如果我们使用 JPQL 或 SQL，我们应该在查询字符串中添加排序逻辑。这样我们就可以从同一个地方检查我们的查询逻辑和排序逻辑。

+   如果我们使用带有`@Query`注解的命名查询或本地查询，我们必须将排序逻辑添加到我们的查询字符串中。

+   当我们使用 JPA Criteria API 构建查询时，我们必须使用`Sort`类，因为这是`JpaSpecificationExecutor<T>`接口提供的唯一方法。

+   当我们使用 Querydsl 构建查询时，我们必须使用`OrderSpecifier`类来对查询结果进行排序，因为这是`QueryDslPredicateExecutor<T>`接口所要求的。

# 分页查询结果

对于几乎每个呈现某种数据的应用程序来说，对查询结果进行分页是一个非常常见的需求。Spring Data JPA 分页支持的关键组件是`Pageable`接口，它声明了以下方法：

| 方法 | 描述 |
| --- | --- |
| `int getPageNumber()` | 返回请求页面的编号。页面编号是从零开始的。因此，第一页的编号是零。 |
| `int getPageSize()` | 返回单个页面上显示的元素数量。页面大小必须始终大于零。 |
| `int getOffset()` | 根据给定的页码和页面大小返回所选偏移量。 |
| `Sort getSort()` | 返回用于对查询结果进行排序的排序参数。 |

我们可以使用这个接口来通过 Spring Data JPA 对查询结果进行分页：

1.  创建一个新的`PageRequest`对象。我们可以使用`PageRequest`类，因为它实现了`Pageable`接口。

1.  将创建的对象作为参数传递给存储库方法。

如果我们使用查询方法来创建我们的查询，我们有两种选项可以作为查询方法的返回类型：

+   如果我们需要访问请求页面的元数据，我们可以使我们的查询方法返回`Page<T>`，其中`T`是受管理实体的类型。

+   如果我们只对获取请求页面的联系人感兴趣，我们应该使我们的查询方法返回`List<T>`，其中`T`是受管理实体的类型。

为了向我们的联系人管理应用程序添加分页，我们必须对应用程序的服务层进行更改，并实现分页。这两个任务在以下子节中有更详细的描述。

## 改变服务层

由于 Spring Data JPA 存储库只是接口，我们必须在服务层创建`PageRequest`对象。这意味着我们必须找到一种方法将分页参数传递到服务层，并使用这些参数创建`PageRequest`对象。我们可以通过以下步骤实现这个目标：

1.  我们创建了一个存储分页参数和搜索词的类。

1.  改变服务接口的方法签名。

1.  我们实现了创建`PageRequest`对象的方法。

### 创建一个用于分页参数的类

首先，我们必须创建一个用于存储分页参数和使用的搜索词的类。Spring Data 提供了一个名为`PageableArgumentResolver`的自定义参数解析器，它将通过解析请求参数自动构建`PageRequest`对象。有关这种方法的更多信息，请访问[`static.springsource.org/spring-data/data-jpa/docs/current/reference/html/#web-pagination`](http://static.springsource.org/spring-data/data-jpa/docs/current/reference/html/#web-pagination)。

我们不会使用这种方法，因为我们不想在我们的 Web 层和 Spring Data 之间引入依赖关系。相反，我们将使用一个只有几个字段、getter 和 setter 的简单 DTO。`SearchDTO`的源代码如下：

```java
public class SearchDTO {

    private int pageIndex;
    private int pageSize;
    private String searchTerm;

   //Getters and Setters
}
```

### 改变服务接口

我们需要修改示例应用程序的`ContactService`接口，以便为联系人列表和搜索结果列表提供分页支持。所需的更改如下所述：

+   我们必须用`findAllForPage()`方法替换`findAll()`方法，并将页码和页面大小作为参数传递

+   我们必须修改`search()`方法的签名，以将`SearchDTO`作为参数

变更方法的签名如下：

```java
public List<Contact> findAllForPage(int pageIndex, int pageSize);

public List<Contact> search(SearchDTO dto);
```

### 创建 PageRequest 对象

在我们可以继续实际实现之前，我们必须向`RepositoryContactService`类添加一个新方法。这个方法用于创建作为参数传递给我们的存储库的`PageRequest`对象。`buildPageSpecification()`方法的实现如下所述：

1.  我们使用`sortByLastNameAndFirstNameAsc()`方法来获取对使用的`Sort`对象的引用。

1.  我们使用页码、页面大小和 Sort 对象来创建一个新的`PageRequest`对象。

相关方法的源代码如下：

```java
private Pageable buildPageSpecification(int pageIndex, int pageSize) {
  Sort sortSpec = sortByLastNameAndFirstNameAsc();
  return new PageRequest(pageIndex, pageSize, sortSpec);
}

private Sort sortByLastNameAndFirstNameAsc() {
  return new Sort(new Sort.Order(Sort.Direction.ASC, "lastName"),
        new Sort.Order(Sort.Direction.ASC, "firstName")
    );
}
```

## 实现分页

为了对查询结果进行分页，我们必须将创建的`PageRequest`对象传递给正确的存储库方法。这个方法取决于我们用来构建查询的方法。这些方法中的每一种都在本小节中描述。

### JpaRepository

因为`ContactRepository`扩展了`JpaRepository<T,ID>`接口，我们可以访问`Page<Contact> findAll(Pageable page)`方法，用于对所有实体的列表进行分页。`RepositoryContactService`类的`findAllForPage()`方法的实现如下所述：

1.  我们得到了使用的`PageRequest`对象。

1.  通过调用存储库方法并将`PageRequest`对象作为参数传递来获取`Page<Contact>`的引用。

1.  我们返回一个联系人列表。

我们的`findAllForPage()`方法的源代码如下：

```java
@Transactional(readOnly = true)
@Override
public List<Contact> findAllForPage(int pageIndex, int pageSize) {
  Pageable pageSpecification = buildPageSpecification(pageIndex, pageSize); 

  Page<Contact> page = repository.findAll(pageSpecification);

  return page.getContent();
}
```

### 从方法名生成查询

如果我们使用从方法名生成查询的策略来构建查询，我们可以对查询结果进行分页：

1.  为查询方法添加分页支持。

1.  从服务方法调用查询方法。

#### 为查询方法添加分页支持

为我们的查询方法添加分页支持相当简单。我们只需要对查询方法的签名进行以下更改：

1.  将`Pageable`接口添加为查询方法的参数。

1.  确定查询方法的返回类型。

因为我们对页面元数据不感兴趣，所以我们的查询方法的签名如下所示：

```java
public List<Contact> findByFirstNameStartingWithOrLastNameStartingWith(String firstName, String lastName, Pageable page);
```

#### 修改服务类

`RepositoryContactService`的`search()`方法需要的修改相当简单。我们得到一个`PageRequest`对象的引用，并将其作为参数传递给我们的查询方法。修改后的方法源代码如下：

```java
@Transactional(readOnly = true)
@Override
public List<Contact> search(SearchDTO dto) {
    Pageable pageSpecification = buildPageSpecification(dto.getPageIndex(), dto.getPageSize());

    return repository.findByFirstNameStartingWithOrLastNameStartingWith(dto.getSearchTerm(), dto.getSearchTerm(), pageSpecification);
}
```

### 命名查询

如果我们想要对命名查询的查询结果进行分页，我们必须：

1.  为查询方法添加分页支持。

1.  从服务方法调用查询方法。

#### 为查询方法添加分页支持

我们可以通过将`Pageable`接口作为查询方法的参数来为命名查询支持分页。此时，我们不需要页面元数据。因此，我们的查询方法的签名如下所示：

```java
public List<Contact> findContacts(@Param("searchTerm") String searchTerm, Pageable page);
```

#### 修改服务类

我们对`RepositoryContactService`类的`search()`方法的实现如下所述：

1.  我们得到了使用的模式。

1.  我们得到所需的`PageRequest`对象。

1.  通过调用修改后的查询方法来获取联系人列表。

我们修改后的`search()`方法的源代码如下：

```java
@Transactional(readOnly = true)
@Override
public List<Contact> search(SearchDTO dto) {
    String likePattern = buildLikePattern(dto.getSearchTerm());

    Pageable pageSpecification = buildPageSpecification(dto.getPageIndex(), dto.getPageSize());

    return repository.findContacts(likePattern, pageSpecification);
}
```

### @Query 注解

我们可以通过`@Query`注解构建的 JPQL 查询来对查询结果进行分页：

1.  为查询方法添加分页支持。

1.  从服务方法调用查询方法。

#### 为查询方法添加分页支持

我们可以通过对方法签名进行以下更改，为使用`@Query`注解注释的查询方法添加分页支持：

1.  我们将`Pageable`接口添加为方法的参数。

1.  我们确定方法的返回类型。

在这一点上，我们对返回页面的元数据不感兴趣。因此，查询方法的声明如下所示：

```java
@Query("SELECT c FROM Contact c WHERE LOWER(c.firstName) LIKE LOWER(:searchTerm) OR LOWER(c.lastName) LIKE LOWER(:searchTerm)")
public List<Contact> findContacts(@Param("searchTerm") String searchTerm, Pageable page);
```

#### 修改服务方法

`RepositoryContactService`类的`search()`方法的实现如下所述：

1.  我们得到了使用的 like 模式。

1.  我们得到了使用过的`PageRequest`对象的引用。

1.  通过调用查询方法并将 like 模式和创建的`PageRequest`对象作为参数，我们可以得到联系人列表。

`search()`方法的源代码如下所示：

```java
@Transactional(readOnly = true)
@Override
public List<Contact> search(SearchDTO dto) {
    String likePattern = buildLikePattern(dto.getSearchTerm());

    Pageable pageSpecification = buildPageSpecification(dto.getPageIndex(), dto.getPageSize());

    return repository.findContacts(likePattern, pageSpecification);
}
```

### JPA Criteria API

为了使用 JPA Criteria API 构建查询，`ContactRepository`接口必须扩展`JpaSpecificationExecutor<T>`接口。这使我们可以访问`Page<Contact> findAll(Specification spec, Pageable page)`方法，该方法可用于对标准查询的查询结果进行分页。我们唯一需要做的就是修改`RepositoryContactService`类的`search()`方法。我们的实现如下所述：

1.  我们得到了使用过的规范。

1.  我们得到了使用过的`PageRequest`对象。

1.  通过调用存储库方法并将规范和`PageRequest`对象作为参数传递，我们得到了`Page`的实现。

1.  通过调用`Page`类的`getContent()`方法，我们返回了请求的联系人列表。

我们的搜索方法的源代码如下所示：

```java
@Transactional(readOnly = true)
@Override
public List<Contact> search(SearchDTO dto) {
    Specification<Contact> contactSpec = firstOrLastNameStartsWith(dto.getSearchTerm());
    Pageable pageSpecification = buildPageSpecification(dto.getPageIndex(), dto.getPageSize());

    Page<Contact> page = repository.findAll(contactSpec, pageSpecification);

    return page.getContent();
}
```

### Querydsl

由于`ContactRepository`接口扩展了`QueryDslPredicateExecutor<T>`接口，我们可以访问`Page<Contact> findAll(Predicate predicate, Pageable page)`方法，我们可以用它来对查询结果进行分页。为了为我们的搜索函数添加分页支持，我们必须对`RepositoryContactService`类的现有`search()`方法进行一些更改。这个方法的新实现在以下步骤中描述：

1.  我们得到了使用过的`Predicate`的引用。

1.  我们得到了使用过的`PageRequest`对象。

1.  通过调用存储库方法并将`Predicate`和`PageRequest`对象作为参数传递，我们得到了一个`Page`引用。

1.  我们返回请求的联系人。

我们的新`search()`方法的源代码如下所示：

```java
@Transactional(readOnly = true)
@Override
public List<Contact> search(SearchDTO dto) {
    Predicate contactPredicate = firstOrLastNameStartsWith(dto.getSearchTerm());
    Pageable pageSpecification = buildPageSpecification(dto.getPageIndex(), dto.getPageSize());

    Page<Contact> page = repository.findAll(contactPredicate, pageSpecification);

    return page.getContent();
}
```

# 总结

在本章中，我们已经学到了：

+   我们可以使用方法名称的查询生成，命名查询或`@Query`注解来创建 Spring Data JPA 的查询方法

+   我们可以通过使用 JPA Criteria API 或 Querydsl 来创建动态查询

+   有三种不同的方法可以用来对查询结果进行排序

+   如果我们对查询方法的查询结果进行分页，方法的返回类型可以是`List`或`Page`

+   每种查询创建方法都有其优势和劣势，我们在选择当前问题的正确解决方案时必须考虑这些。

有时我们需要向我们的存储库添加自定义函数。这个问题在下一章中解决。
