# SpringMVC：设计现实世界的 Web 应用（五）

> 原文：[`zh.annas-archive.org/md5/AB3510E97B9E20602840C849773D49C6`](https://zh.annas-archive.org/md5/AB3510E97B9E20602840C849773D49C6)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十章：使用 Java 持久性和实体

在本章中，我们将开发以下配方：

+   在 Spring 中配置**Java 持久性 API**（**JPA**）

+   定义有用的 EJB3 实体和关系

+   利用 JPA 和 Spring Data JPA

# 介绍

**Java 持久化 API**（**JPA**）是一个规范，从 2006 年（JPA 1.0）到 2013 年（JPA 2.1）由一组各种专家发布了不同版本。从历史上看，它是 EJB 3.0 规范的三个部分之一，它随 JEE5 一起出现。

JPA 不仅仅是**企业 JavaBean**（**EJB**）的升级，它在很大程度上是一次完全的重新设计。当时，领先的对象关系映射解决方案提供商（如 Hibernate）和 J2EE 应用服务器提供商（如 WebSphere，JBoss）都参与其中，全局结果无疑更简单。所有类型的 EJB（有状态的，无状态的和实体）现在都是简单的**普通的旧 Java 对象**（**POJOs**），它们被特定的元数据丰富，这些元数据以注解的形式呈现。

## 实体的好处

实体在 EJB3 模型中扮演着关键角色。作为简单的 POJO，它们可以在应用程序的每一层中使用。

理想情况下，一个实体代表着业务领域内可识别的功能单元。通常是使一个实体代表数据库表行。作为简单的 POJO，实体可以依赖继承（IS-A 关系）并且可以有属性（HAS-A 关系），就像数据库模式通常描述的那样。通过这些关系，实体与其他实体建立连接。这些连接用`@Annotations`描述，这些注解构成了实体的元数据。

实体必须被视为数据库表行的应用程序等价元素。JPA 允许操作这个元素及其整个生态系统作为 Java 对象层次结构，并将其持久化为这样的对象。

实体已经带来了对持久化层的惊人革新（通过减少需要维护的硬编码 SQL 查询的数量），以及对服务和转换层的简化。能够通过所有层级（甚至在视图中使用），它们极大地驱动了应用程序中使用的领域特定名称和概念（方法，类和属性）。它们间接地专注于基本要素，并在应用程序概念和数据库概念之间强加一致性。

从一开始就拥有一个坚实而深思熟虑的模式显然是一个加分项。

### 注意

JPA 在 UI 应用程序上带来了惊人的性能和可维护性结果。然而，如果用于执行批处理或大量数据库操作，它可能并不总是符合性能期望。有时候，考虑直接使用 JDBC 访问可能更明智。

## 实体管理器及其持久化上下文

我们已经看到实体可以与其他实体有关系。为了我们能够对实体进行操作（从数据库中读取，更新，删除和持久化），有一个后台 API 生成 SQL 查询的准备工作。这个 API 在持久化提供者（Hibernate，Toplink 等）中被称为 EntityManager。一旦它为应用程序加载了对象，我们就可以信任它来管理其生命周期。

在继续之前，我们需要回顾一下与 EntityManager 相关的一些概念。一旦 EntityManager 从数据库读取（显式或隐式）获取了实体的实例，该实体就被管理。JPA 持久化上下文由整个受管理实体集的概念聚合形成。持久化上下文始终只携带一个实体的实例，通过其标识符（`@Id`或唯一 ID 类）进行区分。

如果由于某种原因，一个实体没有被管理，那么它被称为脱管（即脱离持久化上下文）。

# 在 Spring 中配置 Java 持久化 API

现在我们已经介绍了 JPA，它的作用以及使用实体的好处，我们现在可以专注于如何配置我们的 Spring 应用程序来处理它们。

## 准备工作

正如我们之前所说，JPA 是一个规范。选择持久性提供程序（Hibernate、OpenJPA、TopLink 等）或应用程序的数据库提供程序不会成为承诺，只要它们符合标准。

我们将看到，在 Spring 中，我们的 JPA 配置是通过定义两个 bean 来完成的：**dataSource**和**entityManagerFactory**。然后，可选的`Spring Data JPA`库提供了一个`JPA`存储库抽象，能够令一些数据库操作出人意料地简化。

## 如何做...

1.  从 Eclipse 的**Git Perspective**中，检出`v3.x.x`分支的最新版本。

1.  如前所介绍的，我们已经在 Spring 配置文件（核心模块中的`csmcore-config.xml`）中添加了一些 bean：

```java
<jpa:repositories base-package="edu.zc.csm.core.daos" />
<bean id="dataSource" class="org.sfw.jdbc.datasource.DriverManagerDataSource>
  <property name="driverClassName">
  <value>org.hsqldb.jdbcDriver</value>
  </property>
  <property name="url">
  <value>jdbc:hsqldb:mem:csm</value>
  </property>
  <property name="username">
  <value>sa</value>
  </property>
</bean>

<bean id="entityManagerFactory" class="org.sfw.orm.jpa.LocalContainerEntityManagerFactoryBean">
      <property name="persistenceUnitName" value="jpaData"/>
      <property name="dataSource" ref="dataSource" />
      <property name="jpaVendorAdapter">
      <beanclass="org.sfw.orm.jpa.vendor.HibernateJpaVendorAdapter"/>
      </property>
      <property name="jpaProperties">
      <props>
          <prop key="hibernate.dialect">
            org.hibernate.dialect.HSQLDialect
          </prop>
          <prop key="hibernate.show_sql">true</prop>
          <prop key="hibernate.format_sql">false</prop>
          <prop key="hibernate.hbm2ddl.auto">create-drop</prop>
          <prop key="hibernate.default_schema">public</prop>
      </props>
    </property>
</bean>
```

1.  最后，以下依赖项已添加到父项目和核心项目中：

+   `org.springframework.data:spring-data-jpa` (1.0.2.RELEASE)

+   `org.hibernate.javax.persistence:hibernate-jpa-2.0-api` (1.0.1.Final)

+   `org.hibernate:hibernate-core` (4.1.5.SP1)

添加此依赖项会导致 Maven 强制执行插件与`jboss-logging`引发版本冲突。这就是为什么 jboss-logging 已从这个第三方库中排除，并作为自己的依赖项引用的原因：

+   `org.hibernate:hibernate-entitymanager` (4.1.5.SP1)

`jboss-logging`也已从这个第三方库中排除，因为它现在被引用为自己的依赖项：

+   `org.jboss.logging:jboss-logging` (3.1.0.CR1)

+   `org.hsqldb:hsqldb` (2.3.2)

+   `org.javassist:javassist` (3.18.2-GA)

+   `org.apache.commons:commons-dbcp2` (2.0.1)

## 它是如何工作的...

我们将审查这三个配置点：**dataSource** bean、**entityManagerFactory** bean 和 Spring Data JPA。

### 由 Spring 管理的 DataSource bean

因为创建数据库连接是耗时的，特别是通过网络层，而且共享和重用已打开的连接或连接池是明智的，**数据源**有责任优化这些连接的使用。它是一个可扩展性指标，也是数据库和应用程序之间高度可配置的接口。

在我们的示例中，Spring 管理数据源就像管理任何其他 bean 一样。数据源可以通过应用程序创建，也可以通过 JNDI 查找远程访问（如果选择放弃连接管理给容器）。在这两种情况下，Spring 将管理配置的 bean，提供我们的应用程序所需的代理。

在我们的示例中，我们正在使用于 2014 年发布的 Apache Common DBCP 2 数据源。

### 提示

在生产环境中，切换到基于 JNDI 的数据源，例如本机 Tomcat JDBC 池，可能是一个好主意。

Tomcat 网站明确建议，在高并发系统上，使用 Tomcat JDBC 池而不是 DBCP1.x 可以显著提高性能。

### EntityManagerFactory bean 及其持久单元

正如其名称所示，`EntityManagerFactory` bean 生成实体管理器。`EntityManagerFactory`的配置条件了实体管理器的行为。

`EntityManagerFactory` bean 的配置反映了一个持久单元的配置。在 Java EE 环境中，可以在`persistence.xml`文件中定义和配置一个或多个持久单元，该文件在应用程序存档中是唯一的。

在 Java SE 环境中（我们的情况），使用 Spring 可以使`persistence.xml`文件的存在变得可选。`EntityManagerFactory` bean 的配置几乎完全覆盖了持久单元的配置。

持久单元的配置，因此`EntityManagerFactory` bean 的配置，可以声明覆盖的实体，也可以扫描包以找到它们。

### 注意

持久性单元可以被视为水平扩展生态系统中的一个子区域。产品可以被分解为每个功能区域的 war（web 存档）。功能区域可以用持久性单元限定的一组实体来表示。

主要的重点是避免创建与不同持久性单元重叠的实体。

### Spring Data JPA 配置

我们将使用 Spring Data JPA 项目中的一些非常有用的工具。这些工具旨在简化持久性层的开发（和维护）。最有趣的工具可能是存储库抽象。您将看到，为一些数据库查询提供实现可能是可选的。如果它们的声明符合标准，存储库接口的实现将在运行时从方法签名中生成。

例如，Spring 将推断以下方法`signature`的实现（如果`User`实体具有`String userName`字段）：

```java
List<User> findByUserName(String username);

```

Spring Data JPA 上我们的 bean 配置的更详细的例子可能是以下内容：

```java
<jpa:repositories base-package="edu.zipcloud.cloudstreetmarket.core.daos" 
    entity-manager-factory-ref="entityManagerFactory"
    transaction-manager-ref="transactionManager"/>
```

正如您所看到的，Spring Data JPA 包含一个自定义命名空间，允许我们定义以下存储库 bean。可以按照以下方式配置此命名空间：

+   在这个命名空间中提供`base-package`属性是强制性的，以限制 Spring Data repositories 的查找。

+   提供`entity-manager-factory-ref`属性是可选的，如果在`ApplicationContext`中只配置了一个`EntityManagerFactory` bean。它明确地连接`EntityManagerFactory`，用于检测到的 repositories。

+   如果在`ApplicationContext`中只配置了一个`PlatformTransactionManager` bean，提供`transaction-manager-ref`属性也是可选的。它明确地连接`PlatformTransactionManager`，用于检测到的 repositories。

有关此配置的更多详细信息，请访问项目网站：

[`docs.spring.io/spring-data/jpa/docs/1.4.3.RELEASE/reference/html/jpa.repositories.html`](http://docs.spring.io/spring-data/jpa/docs/1.4.3.RELEASE/reference/html/jpa.repositories.html)。

## 另请参阅

+   **HikariCP DataSource**：HikariCP（从其 BoneCP 祖先）是一个开源的 Apache v2 许可项目。它似乎在速度和可靠性方面表现比任何其他数据源都要好。在选择数据源时，现在可能应该考虑这个产品。有关更多信息，请参阅[`brettwooldridge.github.io/HikariCP`](https://brettwooldridge.github.io/HikariCP)。

# 定义有用的 EJB3 实体和关系

这个主题很重要，因为良好设计的映射可以防止错误，节省大量时间，并对性能产生重大影响。

## 准备工作

在本节中，我们将介绍大部分我们应用程序所需的实体。这里选择了一些实现技术（从继承类型到关系案例），并且为了示例目的进行了突出显示。

*它是如何工作的…*部分将解释为什么以及如何定义它们的方式，以及是什么思想驱使我们朝着我们所做的实体定义的方向前进。

## 如何做…

以下步骤将帮助您在应用程序中创建实体：

1.  这个配方的所有更改都位于新包`edu.zipcloud.cloudstreetmarket.core.entities`中。首先，按照这里所示创建了三个简单的实体：

+   `User`实体：

```java
  @Entity
  @Table(name="user")
  public class User implements Serializable{
    private static final long serialVersionUID = 1990856213905768044L;
    @Id
    @Column(nullable = false)
    private String loginName;
    private String password;
    private String profileImg;

  @OneToMany(mappedBy="user", cascade = {CascadeType.ALL}, fetch = FetchType.LAZY)
  @OrderBy("id desc")
  private Set<Transaction> transactions = new LinkedHashSet< >();
  ...
  }
```

+   `Transaction`实体：

```java
  @Entity
  @Table(name="transaction")
  public class Transaction implements Serializable{
    private static final long serialVersionUID = -6433721069248439324L;
    @Id
    @GeneratedValue
    private int id;

    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "user_name")
    private User user;

    @Enumerated(EnumType.STRING)
    private Action type;

    @OneToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "stock_quote_id")
    private StockQuote quote;
    private int quantity;
  ...
  }
```

+   还有`Market`实体：

```java
  @Entity
  @Table(name="market")
  public class Market implements Serializable {
    private static final long serialVersionUID = -6433721069248439324L;
    @Id
  private String id;
  private String name;

  @OneToMany(mappedBy = "market", cascade = { CascadeType.ALL }, fetch = FetchType.EAGER)
  private Set<Index> indices = new LinkedHashSet<>();
  ...
  }
```

1.  然后，我们创建了一些更复杂的实体类型，比如抽象的`Historic`实体：

```java
@Entity
@Inheritance(strategy = InheritanceType.SINGLE_TABLE)
@DiscriminatorColumn(name = "historic_type")
@Table(name="historic")
public abstract class Historic {

  private static final long serialVersionUID = -802306391915956578L;

  @Id
  @GeneratedValue
  private int id;

  private double open;

  private double high;

  private double low;

  private double close;

  private double volume;

  @Column(name="adj_close")
  private double adjClose;

  @Column(name="change_percent")
  private double changePercent;

  @Temporal(TemporalType.TIMESTAMP)
  @Column(name="from_date")
  private Date fromDate;

  @Temporal(TemporalType.TIMESTAMP)
  @Column(name="to_date")
  private Date toDate;

  @Enumerated(EnumType.STRING)
  @Column(name="interval")
private QuotesInterval interval;
...
  }
```

我们还创建了两个 Historic 子类型，`HistoricalIndex`和`HistoricalStock`：

```java
  @Entity
  @DiscriminatorValue("idx")
  public class HistoricalIndex extends Historic implements Serializable {

  private static final long serialVersionUID = -802306391915956578L;

  @ManyToOne(fetch = FetchType.EAGER)
  @JoinColumn(name = "index_code")
  private Index index;
...
}
@Entity
@DiscriminatorValue("stk")
public class HistoricalStock extends Historic implements Serializable {

  private static final long serialVersionUID = -802306391915956578L;

  @ManyToOne(fetch = FetchType.LAZY)
  @JoinColumn(name = "stock_code")
  private StockProduct stock;

  private double bid;
  private double ask;
  ...
    }
```

1.  然后，我们还创建了带有其 StockProduct 子类型的`Product`实体：

```java
    @Entity
    @Inheritance(strategy = InheritanceType.TABLE_PER_CLASS)
    public abstract class Product {
      private static final long serialVersionUID = -    802306391915956578L;
      @Id
      private String code;
      private String name;
      ...
    }

    @Entity
    @Table(name="stock")
    public class StockProduct extends Product implements Serializable{
      private static final long serialVersionUID = 1620238240796817290L;
      private String currency;
      @ManyToOne(fetch = FetchType.EAGER)
      @JoinColumn(name = "market_id")
      private Market market;
      ...
    }
```

1.  实际上，在金融世界中，指数（标普 500 或纳斯达克）不能直接购买；因此，指数没有被视为产品：

```java
@Entity
@Table(name="index_value")
public class Index implements Serializable{
  private static final long serialVersionUID = -2919348303931939346L;
  @Id
  private String code;
  private String name;

  @ManyToOne(fetch = FetchType.EAGER)
  @JoinColumn(name = "market_id", nullable=true)
  private Market market;

  @ManyToMany(fetch = FetchType.LAZY)
  @JoinTable(name = "stock_indices", joinColumns={@JoinColumn(name = "index_code")}, inverseJoinColumns={@JoinColumn(name ="stock_code")})
  private Set<StockProduct> stocks = new LinkedHashSet<>();
  ...
}
```

1.  最后，具有两个子类型`StockQuote`和`IndexQuote`的`Quote`抽象实体已经创建（指数不是产品，但我们仍然可以从中获得即时快照，并且稍后将调用 Yahoo!财务数据提供商来获取这些即时报价）：

```java
@Entity
@Inheritance(strategy = InheritanceType.TABLE_PER_CLASS)
public abstract class Quote {
  @Id
  @GeneratedValue(strategy = GenerationType.TABLE)
  protected Integer id;
  private Date date;
  private double open;

  @Column(name = "previous_close")
  private double previousClose;
  private double last;
  ...
}

@Entity
@Table(name="stock_quote")
public class StockQuote extends Quote implements Serializable{
  private static final long serialVersionUID = -8175317254623555447L;
  @ManyToOne(fetch = FetchType.EAGER)
  @JoinColumn(name = "stock_code")
  private StockProduct stock;
  private double bid;
  private double ask;
  ...
}

@Entity
@Table(name="index_quote")
public class IndexQuote extends Quote implements Serializable{
  private static final long serialVersionUID = -8175317254623555447L;

  @ManyToOne(fetch = FetchType.EAGER)
  @JoinColumn(name = "index_code")
  private Index index;
  ...
}
```

## 工作原理...

我们将介绍一些基本和更高级的概念，这些概念我们用来构建我们的关系映射。

### 实体要求

要被 API 视为实体，实体需要满足以下条件：

+   它必须在类型级别上用`@Entity`注解进行注释。

+   它需要具有已定义的**标识符**，可以是基本类型或复杂类型。在大多数情况下，基本标识符就足够了（在特定实体字段上的`@Id`注解）。

+   它必须被定义为 public 并且不能声明为 final。

+   它需要有一个默认构造函数（隐式或非隐式）。

### 映射模式

数据库和 Java 对象都有特定的概念。实体的元数据注解以及默认配置描述了关系映射。

#### 映射表

实体类映射一个表。在类型级别上不指定`@Table(name="xxx")`注解将实体类映射到以实体名称命名的表（这是默认命名）。

### 注意

Java 的类命名标准是驼峰式命名，首字母大写。这种命名方案实际上并不符合数据库表命名标准。因此，经常使用`@Table`注解。

`@Table`注解还具有一个可选的`schema`属性，允许我们在 SQL 查询中将表绑定到模式（例如`public.user.ID`）。这个`schema`属性将覆盖默认的模式 JPA 属性，可以在持久性单元上定义。

#### 映射列

与表名一样，将字段映射到列名是使用`@Column(name="xxx")`注解指定的。同样，这个注解是可选的，不指定将使映射回退到默认命名方案，即字段的大小写名称（在单词的情况下，这通常是一个不错的选择）。

实体类的字段不能定义为 public。还要记住，几乎可以持久化所有标准的 Java 类型（原始类型、包装器、字符串、字节或字符数组和枚举）以及大型数值类型，如`BigDecimals`或`BigIntegers`，还有 JDBC 时间类型（`java.sql.Date`、`java.sql.TimeStamp`）甚至可序列化对象。

#### 注释字段或 getter

实体的字段（如果未标记为`@Transient`）对应于数据库行每列将具有的值。还可以从 getter 中定义列映射（而不一定要有相应的字段）。

`@Id`注解定义了实体标识符。同时，在字段或 getter 上定义这个`@Id`注解会定义表列是应该由字段还是 getter 映射的。

当使用 getter 访问模式时，如果未指定`@Column`注解，则列名的默认命名方案使用 JavaBeans 属性命名标准（例如，`getUser()` getter 对应于`user`列）。

#### 映射主键

正如我们已经看到的，`@Id`注解定义了实体的标识符。持久性上下文将始终管理具有单个标识符的实体的不超过一个实例。

`@Id`注解在实体类上必须映射表的持久标识符，即主键。

#### 标识符生成

`@GeneratedValue`注解允许从 JPA 级别生成 ID。在对象持久化之前，这个值可能不会被填充。

`@GeneratedValue`注解具有`strategy`属性，用于配置生成方法（例如，依赖于现有的数据库序列）。

### 定义继承

我们已经为“产品”、“历史”和“报价”的子类型定义了实体继承。当两个实体足够接近以被分组为单一概念，并且如果它们实际上可以与应用程序中的父实体关联，那么值得使用 JPA 继承。

根据特定数据的持久化策略，可以考虑不同的存储选项来进行继承映射。

JPA 允许我们从不同的策略中配置继承模型。

#### 单表策略

这种策略期望或创建一个带有模式上的鉴别器字段的大表。这个表包含父实体字段；这些字段对所有子实体都是通用的。它还包含所有子实体类的字段。因此，如果一个实体对应于一个子类型或另一个子类型，它将填充特定字段并留下其他字段为空。

以下表格代表了具有其`HISTORIC_TYPE`鉴别器的`Historic`表：

![单表策略](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00838.jpeg)

#### 表格每类策略

这种策略针对具体实体使用特定的表。这里没有涉及鉴别器，只是针对子类型的特定表。这些表包含通用和特定字段。

例如，我们已经为“报价”实体及其具体的“股票报价”和“指数报价”实体实施了这种策略：

![表格每类策略](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00839.jpeg)

### 定义关系

实体具有反映其类属性中的数据库外键和表与表之间关系的能力。

在应用程序端，由于这些关系是由实体管理器透明地构建的，因此可以绕过大量的开发工作。

#### 实体之间的关系是如何选择的

在讨论实体之间的关系之前，有必要了解我们计划在*cloudstreet-market*应用程序中做什么。

正如在第一章中介绍的，企业 Spring 应用程序的设置例程，我们将从开放其 API 的提供者（实际上是 Yahoo!）那里获取财务数据。为此，始终需要牢记每个 IP 或经过身份验证的用户的调用频率方面的限制。我们的应用程序还将在其内部拥有社区，其中将共享财务数据。对于财务数据提供者来说，当谈论给定股票时，股票的历史视图和股票的即时报价是两个不同的概念。我们必须处理这两个概念来构建我们自己的数据集。

在我们的应用程序中，用户将能够通过执行“交易”来购买和出售“产品”（股票、基金、期权等）：

+   首先，让我们考虑用户/交易关系的以下截图：![实体之间的关系是如何选择的](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00840.jpeg)

+   一个“用户”实体可以有多个“交易”实体。

### 注意

在用户类中，`@OneToMany`关系注解的第二部分（`Many`元素）驱动我们正在创建的属性类型。将`Many`指定为第二部分声明了起源实体（`User`）可以有多个目标实体（`Transactions`）。这些目标将必须包含在一个集合类型中。如果起源实体不能有多个目标，则关系的第二部分必须是`One`。

+   一个“交易”只能有一个“用户”实体。

### 注意

在用户类中，`@OneToMany`关系的第一部分（`@One`元素）是目标实体中定义的关系注解的第二部分（如果已定义）。必须知道目标实体是否可以有多个起源，以便完成起源中的注解。

+   然后我们可以推断出两个注解：`User`中的`@OneToMany`和`Transactions`中的`@ManyToOne`。

+   如果我们不是`@ManyToMany`关系的情况，我们谈论的是单向关系。从数据库的角度来看，这意味着两个表中的一个具有指向另一个表的连接列。在 JPA 中，具有这个连接列的表是关系的**所有者**。

### 提示

关系的所有者实体必须在关系上指定一个`@JoinColumn`注解。不是所有者的实体必须为其关系注解提供一个`mappedBy`属性，该属性指向相对实体中的相应 Java 字段名称。

+   这可以解释`Transaction`中的关系：

```java
@ManyToOne(fetch = FetchType.EAGER)
@JoinColumn(name = "user_name")
private User user;
```

`user_name`列预期（或自动添加）在交易表中。我们将在*还有更多……部分*中讨论 fetch 类型。

+   `User`实体中的关系定义如下：

```java
  @OneToMany(mappedBy="user", cascade ={CascadeType.ALL}, fetch = FetchType.LAZY)
  @OrderBy("id desc")
  private Set<Transaction> transactions = new LinkedHashSet<>();
```

### 提示

`@OrderBy`注解告诉 JPA 实现在其 SQL 查询中添加一个`ORDER BY`子句。

一个`Index`实体有一个`Market`实体。我们决定市场是地理区域（欧洲、美国、亚洲等）。一个市场有几个具体的指数。

这看起来又像是`@OneToMany`/`@ManyToOne`关系。关系的所有者是`Index`实体，因为我们期望在`Index`表中有一个`Market`列（而不是`Market`表中的`Index`列）。

在具体的`Product`（如`StockProduct`）和`Market`实体之间，情况与之前类似，只是因为在应用程序中直接从`Market`检索股票看起来不是必需的，关系没有在`Market`实体方面声明。我们只保留了所有者方面。

关于具体的`Quotes`实体（如`StockQuote`）和具体的`Products`实体（如`StockProduct`），一个报价将有一个产品。如果我们有兴趣从`Product`实体中检索`Quote`，一个产品将有多个报价。关系的所有者是具体的`Quote`实体。

对于`IndexQuote`和`Index`，情况与之前的点相同。

在`Index`和`StockProduct`之间，实际上，指数（标普 500、纳斯达克等）有组成部分，组成部分的值之和构成指数值。因此，一个`Index`实体有几个潜在的`StockProduct`实体。同样，一个`StockProduct`可以属于几个`Indices`。这看起来像是一个双向关系。我们在这里展示了`Index`方面：

```java
@ManyToMany(fetch = FetchType.LAZY)
@JoinTable(name = "stock_indices", joinColumns={@JoinColumn(name = "index_code")}, inverseJoinColumns={@JoinColumn(name ="stock_code")})
private Set<StockProduct> stocks = new LinkedHashSet<>();
```

这个关系指定了一个额外的连接表（JPA 预期或生成的）。基本上是一个具有两个连接列指向各自实体的`@Ids`字段的表。

## 还有更多...

我们将讨论两个尚未解释的元数据属性：`FetchType`属性和`Cascade`属性。

### FetchType 属性

我们已经看到关系注解`@OneToOne`、`@OneToMany`和`@ManyToMany`可以在 fetch 属性中指定，可以是`FetchType.EAGER`或`FetchType.LAZY`。

当选择`FetchType.EAGER`属性时，当实体被管理时，关系会被`entityManager`自动加载。JPA 执行的 SQL 查询总量显著增加，特别是因为一些可能每次都不需要的相关实体仍然被加载。如果我们有两个、三个或更多级别的实体绑定到根实体，我们可能应该考虑将一些字段本地切换到`FetchType.LAZY`。

`FetchType.LAZY`属性指定 JPA 实现在实体加载的 SQL 查询中不填充字段值。当程序明确要求时（例如，在`HistoricalStock`实体的情况下调用`getStock()`时），JPA 实现会生成额外的异步 SQL 查询来填充`LAZY`字段。在使用 Hibernate 作为实现时，`FetchType.LAZY`被视为关系的默认获取类型。

重要的是要考虑减轻关系加载的负担，特别是在集合上。

### 级联属性

在关系注解中要提到的另一个属性是 Cascade 属性。这个属性可以取值`CascadeType.DETACH`、`CascadeType.MERGE`、`CascadeType.PERSIST`、`CascadeType.REFRESH`、`CascadeType.REMOVE`和`CascadeType.ALL`。

这个属性指定了 JPA 实现在被要求对主实体执行操作（如持久化、更新、删除、查找等）时应该如何处理相关实体。这是一个可选属性，通常默认为**不进行级联操作**。

## 另请参阅

有第三种定义实体继承的策略：

+   **联接表继承策略**：我们还没有实现它，但这个策略与表对应的类策略有些相似。它与之不同之处在于，JPA 不会在具体的表中重复父实体字段（列），而是创建或期望一个只包含父实体列的额外表，并通过这个表透明地管理连接。

# 利用 JPA 和 Spring Data JPA

在本节中，我们将为我们的应用程序连接所需的业务逻辑。

因为我们已经为 JPA 和 Spring Data JPA 设置了配置，并且已经定义了我们的实体及其关系，现在我们可以使用这个模型来节省时间和精力。

## 如何做...

以下步骤将指导您完成这些更改：

1.  在`edu.zipcloud.cloudstreetmarket.core.daos`包中，我们可以找到以下两个接口：

```java
public interface HistoricalIndexRepository {
  Iterable<HistoricalIndex> findIntraDay(String code, Date of);
  Iterable<HistoricalIndex> findLastIntraDay(String code);
  HistoricalIndex findLastHistoric(String code);
}
public interface TransactionRepository {
  Iterable<Transaction> findAll();
  Iterable<Transaction> findByUser(User user);
  Iterable<Transaction> findRecentTransactions(Date from);
  Iterable<Transaction> findRecentTransactions(int nb);
}
```

1.  这两个接口都带有各自的实现。其中两个中的`HistoricalIndexRepositoryImpl`实现定义如下：

```java
@Repository
public class HistoricalIndexRepositoryImpl implements HistoricalIndexRepository{

  @PersistenceContext 
  private EntityManager em;

  @Override
  public Iterable<HistoricalIndex> findIntraDay(String code,Date of){
    TypedQuery<HistoricalIndex> sqlQuery = em.createQuery("from HistoricalIndex h where h.index.code = ? and h.fromDate >= ? and h.toDate <= ? ORDER BY h.toDate asc", HistoricalIndex.class);

    sqlQuery.setParameter(1, code);
    sqlQuery.setParameter(2, DateUtil.getStartOfDay(of));
    sqlQuery.setParameter(3, DateUtil.getEndOfDay(of));

    return sqlQuery.getResultList();
  }

  @Override
  public Iterable<HistoricalIndex> findLastIntraDay(String code) {
    return findIntraDay(code,findLastHistoric(code).getToDate());
  }

  @Override
  public HistoricalIndex findLastHistoric(String code){
     TypedQuery<HistoricalIndex> sqlQuery =  em.createQuery("from HistoricalIndex h where h.index.code = ? ORDER BY h.toDate desc", HistoricalIndex.class);

  sqlQuery.setParameter(1, code);

    return sqlQuery.setMaxResults(1).getSingleResult();
  }
}
```

`TransactionRepositoryImpl`的实现如下：

```java
@Repository
public class TransactionRepositoryImpl implements TransactionRepository{
  @PersistenceContext 
  private EntityManager em;
  @Autowired
  private TransactionRepositoryJpa repo;
  @Override
  public Iterable<Transaction> findByUser(User user) {
    TypedQuery<Transaction> sqlQuery = em.createQuery("from Transaction where user = ?", Transaction.class);
    return sqlQuery.setParameter(1, user).getResultList();
  }
  @Override
  public Iterable<Transaction> findRecentTransactions(Date from) {
    TypedQuery<Transaction> sqlQuery = em.createQuery("from Transaction t where t.quote.date >= ?", Transaction.class);
    return sqlQuery.setParameter(1, from).getResultList();
  }
  @Override
  public Iterable<Transaction> findRecentTransactions(int nb) {
  TypedQuery<Transaction> sqlQuery = em.createQuery("from Transaction t ORDER BY t.quote.date desc", Transaction.class);
    return sqlQuery.setMaxResults(nb).getResultList();
  }
  @Override
  public Iterable<Transaction> findAll() {
    return repo.findAll();
  }
}
```

1.  `dao`包中的所有其他接口都没有明确定义的实现。

1.  以下 bean 已经添加到 Spring 配置文件中：

```java
  <jdbc:initialize-database data-source="dataSource">
      <jdbc:script location="classpath:/META-INF/db/init.sql"/>
  </jdbc:initialize-database>
```

1.  这个最后的配置允许应用在启动时执行创建的`init.sql`文件。

1.  您会注意到`cloudstreetmarket-core`模块已经在其`pom.xml`文件中添加了一个依赖项，即我们创建的`zipcloud-core`的`DateUtil`类。

1.  为了替换我们在第二章中创建的两个虚拟实现，*使用 Spring MVC 设计微服务架构*，已经创建了`CommunityServiceImpl`和`MarketServiceImpl`的实现。

### 注意

我们使用`@Autowired`注解在这些实现中注入了存储库依赖。

另外，我们使用声明的`value`标识符为这两个实现添加了 Spring `@Service`注解：

```java
@Service(value="marketServiceImpl")
@Service(value="communityServiceImpl")
```

1.  在`cloudstreetmarket-webapp`模块中，`DefaultController`已经在其`@Autowired`字段中修改为针对这些新实现，而不再是虚拟的。这是通过在`@Autowired`字段上指定`@Qualifier`注解来实现的。

1.  启动服务器并调用主页 URL，`http://localhost:8080/portal/index`，应该在控制台中记录一些 SQL 查询：![如何做...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00841.jpeg)

另外，**欢迎**页面应该保持不变。

## 它是如何工作的...

让我们通过以下几个部分来分解这个配方。

### 注入 EntityManager 实例

我们在本章的第一个配方中看到，`entityManagerFactory` bean 的配置反映了持久化单元的配置。

由容器历史创建的 EntityManagers 需要处理事务（用户或容器管理器事务）。

`@PersistenceContext`注解是一个 JPA 注解。它允许我们注入一个由容器管理生命周期的 EntityManager 实例。在我们的情况下，Spring 处理了这个角色。有了 EntityManager，我们可以与持久化上下文交互，获取受管理或分离的实体，并间接地查询数据库。

### 使用 JPQL

使用**Java 持久化查询语言**（**JPQL**）是一种标准化的查询持久化上下文和间接地查询数据库的方式。JPQL 在语法上类似于 SQL，但是操作的是 JPA 管理的实体。

你一定注意到了存储库中的以下查询：

```java

from Transaction where user = ?

```

查询的选择部分是可选的。参数可以注入到查询中，这一步由持久性提供者的实现来管理。这些实现提供了防止 SQL 注入的保护（使用预编译语句）。通过这个例子，看看过滤子实体属性有多实用：

```java

from Transaction t where t.quote.date >= ?

```

在适当的情况下，它避免了声明连接。尽管如此，我们仍然可以声明`JOIN`：

```java

from HistoricalIndex h where h.index.code = ? ORDER BY h.toDate desc

```

一些关键字（如`ORDER`）可以作为 JPQL 的一部分来操作通常在 SQL 中可用的函数。在 JavaEE 6 教程的 JPQL 语法中找到关键字的完整列表：[`docs.oracle.com/javaee/6/tutorial/doc/bnbuf.html`](http://docs.oracle.com/javaee/6/tutorial/doc/bnbuf.html)。

JPQL 受到早期创建的**Hibernate 查询语言**（**HQL**）的启发。

### 使用 Spring Data JPA 减少样板代码

我们在*如何做…*部分讨论了一些我们的存储库接口没有明确定义实现的情况。这是 Spring Data JPA 非常强大的功能。

#### 查询创建

我们的`UserRepository`接口定义如下：

```java
@Repository
public interface UserRepository extends JpaRepository<User, String>{
  User findByUserName(String username);
  User findByUserNameAndPassword(String username, String password);
}
```

我们让它扩展了`JpaRepository`接口，通过通用类型`User`（这个存储库将关联的实体类型）和`String`（用户标识字段的类型）。

通过扩展`JpaRepository`，`UserRepository`从 Spring Data JPA 获得了定义查询方法的能力，只需声明它们的方法签名。我们已经在方法`findByUserName`和`findByUserNameAndPassword`中这样做了。

Spring Data JPA 会在运行时透明地创建我们的`UserRepository`接口的实现。它会根据我们在接口中命名方法的方式推断 JPA 查询。关键字和字段名用于这种推断。

从 Spring Data JPA 文档中找到以下关键字表：

![查询创建](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00842.jpeg)

在不指定任何配置的情况下，我们已经默认回到了 JPA 存储库的配置，它会注入我们单一的`EntityManagerFactory` bean 的实例和我们单一的`TransactionManager` bean 的实例。

我们的自定义`TransactionRepositoryImpl`是一个示例，它同时使用自定义的 JPQL 查询和`JpaRepository`实现。正如你可能猜到的那样，在`TransactionRepositoryImpl`中自动装配的`TransactionRepositoryJpa`实现继承了用于保存、删除和查找`Transaction`实体的多个方法。

我们还将使用这些方法提供的有趣的分页功能。我们提取的`findAll()`方法就是其中之一。

#### 持久化实体

Spring Data JPA 还指定了以下内容：

可以通过`CrudRepository.save(…)`方法来保存实体。它将使用底层的 JPA EntityManager 来持久化或合并给定的实体。如果实体尚未持久化，Spring Data JPA 将通过调用`entityManager.persist(…)`方法来保存实体；否则，将调用`entityManager.merge(…)`方法。

这是一个有趣的行为，我们将再次使用它来减少大量样板代码。

## 还有更多...

还有更多可以探索的方面。

### 使用本地 SQL 查询

我们还没有使用原生 SQL 查询，但我们将会使用。了解如何实现它们很重要，因为有时绕过 JPA 层在性能上可能是更好的选择。

以下链接指向 Oracle 网站的一篇文章，与原生 SQL 查询相关，非常有趣。

[`www.oracle.com/technetwork/articles/vasiliev-jpql-087123.html`](http://www.oracle.com/technetwork/articles/vasiliev-jpql-087123.html)

### 交易

我们还没有对我们的存储库实现应用任何特定的事务配置。有关事务的更多详细信息，请参阅第七章，“开发 CRUD 操作和验证”。

## 另请参阅

+   Spring Data 存储库的自定义实现：通过重新定义我们从 TransactionRepositoryJpa 中需要的方法的示例 TransactionRepositoryImpl，我们提出了创建数据存储库的自定义实现的模式。这在某种程度上迫使我们维护一个中间代理。相关的 Spring 文档提出了解决这个问题的不同技术。这种技术在[`docs.spring.io/spring-data/jpa/docs/current/reference/html/#repositories.custom-implementations`](http://docs.spring.io/spring-data/jpa/docs/current/reference/html/#repositories.custom-implementations)上有详细介绍。



# 第十一章：为无状态架构构建 REST API

本章将介绍以下配方：

+   绑定请求和编组响应

+   配置内容协商（`json`、`xml`等）

+   添加分页、过滤和排序功能

+   全局处理异常

+   使用 Swagger 文档化和公开 API

# 介绍

在本章中，将实施相当多的变化。实际上，这一章真正加速了我们的应用程序开发。

在深入了解代码之前，我们需要复习一下关于 REST 的一些概念。

## REST 的定义

REST 是一种架构风格。它的名称是表述状态转移的缩写。这个术语是由 HTTP 规范的主要作者之一 Roy Fielding 发明的。REST 架构围绕着一些标记设计：

+   可识别资源：资源定义了领域。资源必须通过 URI 进行标识。这个 URI 必须尽可能清晰地使用资源类别和层次结构。我们的资源将是指数快照、股票快照、历史指数数据、历史股票数据、用户等等。

+   HTTP 作为通信协议：我们使用有限数量的 HTTP 方法（`GET`、`POST`、`PUT`、`DELETE`、`HEAD`和`OPTIONS`）与资源进行交互。

+   资源表示：资源以特定的表示形式呈现。表示通常对应于媒体类型（`application/json`、`application/xml`、`text/html`）和/或文件扩展名（`*.json`、`*.xml`、`*.html`）。

+   无状态对话：服务器不得保留对话的痕迹。禁止使用 HTTP 会话，而是通过资源提供的链接（超媒体）进行导航。客户端身份验证在每个请求中都会重复。

+   可扩展性：无状态设计意味着易于扩展。一个请求可以分派到一个或另一个服务器。这是负载均衡器的作用。

+   超媒体：正如我们刚才提到的，资源带来了链接，这些链接驱动了对话的转换。

## RESTful CloudStreetMarket

从本章开始，所有实现的数据检索现在都使用 AngularJS 通过 REST 处理。我们使用 Angular 路由来完成单页应用程序设计（从服务器加载一次）。还有一些新的服务，支持关于股票和指数的三个新屏幕。

尽管 REST 实现仍然是部分的。我们只实现了数据检索（`GET`）；我们还没有有效的身份验证，超媒体也将在以后介绍。

# 绑定请求和编组响应

这个配方解释了如何配置 Spring MVC 以使 REST 处理程序尽可能与其业务领域集成。我们专注于设计自解释的方法处理程序，外部化类型转换以及抽象响应编组（序列化为特定格式，如`json`，`xml`，`csv`等）。

## 准备工作

我们将审查应用于`cloudstreetmarket-api` webapp 的配置更改，以便从请求参数或 URI 模板变量设置类型转换。

我们将看到如何配置自动编组（用于响应）为`json`。我们将专注于为本章创建的两个非常简单的方法处理程序。

## 如何做...

以下步骤描述了与请求绑定和响应编组配置相关的代码库更改：

1.  在 Eclipse 的**Git Perspective**中，检出分支`v4.x.x`的最新版本。然后在`cloudstreetmarket-parent`模块上运行`maven clean install`命令。要这样做，右键单击模块，选择**Run as...** | **Maven Clean**，然后再次选择**Run as...** | **Maven Install**。之后，选择**Maven Update Project**以将 Eclipse 与 Maven 配置同步。要这样做，右键单击模块，然后选择**Maven** | **Update Project...**。

1.  主要的配置更改在`dispatcher-context.xml`文件中（在**cloudstreetmarket-api**模块中）。已定义`RequestMappingHandlerAdapter` bean 的三个`webBindingInitializer`，`messageConverters`和`customArgumentResolvers`属性：

```java
<bean class="org.sfw.web...
  method.annotation.RequestMappingHandlerAdapter">
  <property name="webBindingInitializer">
    <bean class="org.sfw...
     support.ConfigurableWebBindingInitializer">
      <property name="conversionService" ref="conversionService"/>
    </bean>
    </property>
  <property name="messageConverters">
    <list>
        <ref bean="jsonConverter"/>
      </list>
  </property>
  <property name="customArgumentResolvers">
    <list>
      <bean class="net.kaczmarzyk.spring.data.jpa.web.
      SpecificationArgumentResolver"/>
      <bean	class="org.sfw.data.web.PageableHandlerMethodArgumentResolver">
          <property name="pageParameterName" value="pn"/>
          <property name="sizeParameterName" value="ps"/>
          </bean>
    </list>
  </property>
  <property name="requireSession" value="false"/>
</bean>

<bean id="jsonConverter" class="org.sfw...
    converter.json.MappingJackson2HttpMessageConverter">
    <property name="supportedMediaTypes" value="application/json"/>
  <property name="objectMapper">
    <bean class="com.fasterxml.jackson. databind.ObjectMapper">
      <property name="dateFormat">
     <bean class="java.text.SimpleDateFormat">
       <constructor-arg type="java.lang.String" value="yyyy-MM-dd HH:mm"/>
       </bean>
      </property>
    </bean>
    </property>
</bean>
<bean id="conversionService" class="org.sfw.format.support.FormattingConversionServiceFactoryBean">
  <property name="converters">
    <list>
      <bean class="edu.zc.csm.core. converters.StringToStockProduct"/>
    </list>
  </property>
</bean>
```

1.  以下 Maven 依赖项已添加到父项目（间接添加到核心和 API 项目）中：

```java
      <dependency>
         <groupId>com.fasterxml.jackson.core</groupId>
             <artifactId>jackson-annotations</artifactId>
             <version>2.5.1</version>
       </dependency>
         <dependency>
             <groupId>com.fasterxml.jackson.core</groupId>
             <artifactId>jackson-databind</artifactId>
             <version>2.5.1</version>
         </dependency>
         <dependency>
             <groupId>commons-collections</groupId>
             <artifactId>commons-collections</artifactId>
             <version>3.2</version>
         </dependency>
         <dependency>
             <groupId>net.kaczmarzyk</groupId>
             <artifactId>specification-arg-resolver</artifactId>
             <version>0.4.1</version>
         </dependency>
```

1.  在我们控制器的超类`CloudstreetApiWCI`中，使用`@InitBinder`注解创建了`allowDateBinding`方法：

```java
  private DateFormat df = new SimpleDateFormat("yyyy-MM-dd");

  @InitBinder
  public void allowDateBinding ( WebDataBinder binder ){
    binder.registerCustomEditor( Date.class, new CustomDateEditor( df, true ));
  }
```

1.  所有这些配置使我们能够定义自解释和无逻辑的方法处理程序，例如`IndexController`中的`getHistoIndex()`方法：

```java
  @RequestMapping(value="/{market}/{index}/histo", method=GET)
  public HistoProductDTO getHistoIndex(
    @PathVariable("market") MarketCode market, 
    @PathVariable("index") String indexCode,
    @RequestParam(value="fd",defaultValue="") Date fromDate,
    @RequestParam(value="td",defaultValue="") Date toDate,
    @RequestParam(value="i",defaultValue="MINUTE_30") QuotesInterval interval){
    return marketService.getHistoIndex(indexCode, market, fromDate, toDate, interval);
  }
```

1.  现在部署`cloudstreetmarket-api`模块并重新启动服务器。要这样做，首先在**服务器**选项卡中右键单击 Tomcat 服务器：![操作步骤...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00843.jpeg)

1.  然后从右键菜单中选择**添加和删除...**。在添加和删除...窗口中，确保已设置以下配置，并启动服务器。![操作步骤...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00844.jpeg)

1.  尝试调用 URL `http://localhost:8080/api/indices/EUROPE/^GDAXI/histo.json`。

1.  此 URL 针对所呈现的`getHistoIndex`方法处理程序，并生成以下`json`输出：![操作步骤...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00845.jpeg)

1.  现在让我们看看`StockProductController`。它托管以下方法处理程序：

```java
@RequestMapping(value="/{code}", method=GET)
@ResponseStatus(HttpStatus.OK)
public StockProductOverviewDTO getByCode(
@PathVariable(value="code") StockProduct stock){
  return StockProductOverviewDTO.build(stock);
}
```

### 提示

这里没有对任何服务层进行显式调用。方法处理程序的返回类型是`StockProductOverviewDTO`，这是一个简单的 POJO。响应主体的编组是透明进行的。

1.  在**cloudstreetmarket-core**模块中，必须呈现`StringToStockProduct`转换器，因为它是实现前一步所需的：

```java
@Component
public class StringToStockProduct implements Converter<String, StockProduct> {

@Autowired
private ProductRepository<StockProduct> productRepository;

@Override
public StockProduct convert(String code) {
  StockProduct stock = productRepository.findOne(code);
  if(stock == null){
    throw new NoResultException("No result has been found for the value "+ code +" !");
  }
  return stock;
}
}
```

### 提示

此转换器已在*步骤 2*中注册到`conversionService`。

1.  尝试调用 URL `http://localhost:8080/api/products/stocks/NXT.L.json`。这应该针对所呈现的`getByCode`处理程序，并生成以下`json`响应：![操作步骤...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00846.jpeg)

## 它是如何工作的...

要了解前面的元素如何一起工作，我们必须介绍`RequestMappingHandlerAdapter`的关键作用。

### 一个超级 RequestMappingHandlerAdapter bean

我们在第二章中简要介绍了`RequestMappingHandlerAdapter`，*使用 Spring MVC 设计微服务架构*。这个 bean 实现了高级的`HandlerAdapter`接口，允许自定义 MVC 核心工作流实现。`RequestMappingHandlerAdapter`是框架自带的原生实现。

我们提到`RequestMappingHandlerAdapter`和`RequestMappingHandlerMapping`分别是现在已经弃用的`AnnotationMethodHandlerAdapter`和`DefaultAnnotationHandlerMapping`的两个替代类。

实际上，`RequestMappingHandlerAdapter`为所有方法处理程序提供了更好的集中化。此外，一些新的功能已经为`HandlerInterceptors`和`HandlerExceptionResolver`打开。

### 提示

实际上，在`preHandle`、`postHandle`和`afterCompletion`方法的签名中可以找到的处理程序参数（`WebContentInterceptors`）可以被转换为`HandlerMethod`对象。`HandlerMethod`类型提供了一些有趣的检查方法，比如`getReturnType`、`getMethodAnnotation`、`getMethodParameters`。

此外，关于`RequestMappingHandlerAdapter`和`RequestMappingHandlerMapping`，Spring 文档指定：

|   | *"MVC 命名空间和 MVC Java 配置默认情况下启用了新的支持类，但如果不使用这两者，则必须显式配置。"* |   |
| --- | --- | --- |
|   | --*JavaDoc* |

在我们的 web 应用程序中，我们都使用了`<mvc:annotation-driven/>`元素来特别使用 MVC 命名空间。

这个元素很受欢迎，因为它在一些 web 功能上激活了默认配置功能。然而，在许多情况下，可能仍然期望不同的行为。

在大多数情况下，自定义定义要么在命名空间本身上，要么在`RequestMappingHandlerAdapter`上。

#### @RequestMapping 注解得到了广泛的支持

`RequestMappingHandlerAdapter`的主要作用是为`HandlerMethod`类型的处理程序提供支持和定制。这些处理程序与`@RequestMapping`注解绑定。

|   | *"HandlerMethod 对象封装了有关处理程序方法的信息，包括方法和 bean。提供了对方法参数、方法返回值、方法注解的便捷访问。"* |   |
| --- | --- | --- |
|   | --*JavaDoc* |

`RequestMappingHandlerAdapter`大部分的支持方法都来自于历史悠久的`DefaultAnnotationHandlerMapping`。让我们更仔细地看看特别让我们感兴趣的方法。

##### setMessageConverters

`messageConverters`模板可以通过`setMessageConverters` setter 注册为`List<HttpMessageConverter>`。Spring 将为我们执行将 HTTP 请求体解组成 Java 对象和将 Java 资源组成 HTTP 响应体的编组。

重要的是要记住，框架为主要的媒体类型提供了转换器实现。这些默认情况下与`RequestMappingHandlerAdapter`和`RestTemplate`（在客户端上）注册。

以下表格总结了我们可以利用的原生转换器：

| 提供的实现 | 默认支持的媒体类型 | (默认)行为 |
| --- | --- | --- |
| `StringHttpMessageConverter` | `text/*` | 使用`text/plain`内容类型进行写入。 |
| `FormHttpMessageConverter` | `application/x-www-form-urlencoded` | 表单数据从`MultiValueMap<String, String>`中读取和写入。 |
| `ByteArrayHttpMessageConverter` | `*/*` | 使用`application/octet-stream`内容类型进行写入（可以被覆盖）。 |
| `MarshallingHttpMessageConverter` | `text/xml 和 application/xml` | 需要`org.springframework.oxm`和`Marshaller`/`Unmarshaller`。 |
| `MappingJackson2HttpMessageConverter` | `application/json` | 可以使用 Jackson 注解自定义 JSON 映射。如果需要映射特定类型，必须注入自定义的`ObjectMapper`属性。 |
| `MappingJackson2XmlHttpMessageConverter` | `application/xml` | XML 映射可以使用 JAXB 或 Jackson 注解进行自定义。如果需要映射特定类型，必须将自定义的`XmlMapper`属性注入到`ObjectMapper`属性中。 |
| `SourceHttpMessageConverter` | `text/xml 和 application/xml` | 可以从 HTTP 请求和响应中读取和写入`javax.xml.transform`.`Source`。只支持`DOMSource`、`SAXSource`和`StreamSource`。 |
| `BufferedImageHttpMessageConverter` |   | 可以从 HTTP 请求和响应中读取和写入`java.awt.image.BufferedImage`。 |

请查看以下地址，获取有关使用 Spring 进行远程和 Web 服务的信息：[`docs.spring.io/spring/docs/current/spring-framework-reference/html/remoting.html`](http://docs.spring.io/spring/docs/current/spring-framework-reference/html/remoting.html)。

在我们的应用程序中，我们已经重写了两个本地`MappingJackson2HttpMessageConverter`和`MarshallingHttpMessageConverter`类的定义。

##### setCustomArgumentResolvers

`setCustomArgumentResolvers` setter 为`RequestMappingHandlerAdapter`提供了对自定义参数的支持。如果你还记得第二章中的内容，*使用 Spring MVC 支持响应式设计*，第一个配方谈到了支持参数的注解。当时，我们看到了`@PathVariable`、`@MatrixVariable`、`@RequestBody`、`@RequestParam`等。

所有这些注解都是内置的`ArgumentResolver`。它们被映射到注册的实现，以从不同的来源外部预填充参数。

我们有可能定义自己的注解，并根据所需的业务逻辑预填充我们的方法参数。这些解析器必须实现`HandlerMethodArgumentResolver`接口。

我们的应用程序开发并没有特别需要开发`customArgumentResolver`。但是，我们已经注册了其中两个：

+   `net.kaczmarzyk.spring.data.jpa.web.SpecificationArgumentResolver`：这个解析器是一个第三方库，我们将在本章的第 3 个配方中进行解释

+   `org.springframework.data.web.PageableHandlerMethodArgumentResolver`：这将允许自动解析分页参数，以使用原生 Spring Data 分页支持

##### setWebBindingInitializer

`WebBindingInitializer`接口是一个回调接口，用于全局初始化`WebDataBinder`并在 web 请求的上下文中执行数据绑定。

在继续之前，我们必须停下来重新访问配方的第 4 步，定义了以下方法：

```java
  @InitBinder
  public void allowDateBinding(WebDataBinder binder){
    binder.registerCustomEditor(Date.class, new CustomDateEditor( df, true ));
  }
```

我们在控制器中定义了这个方法，以注册使用`PropertyEditor`进行抽象日期转换绑定。

现在让我们专注于`WebDataBinder`参数。在这一部分，我们谈论的是初始化部分。`WebDataBinder`接口提供了一些有趣的方法。这些方法大多与验证相关（`validate`、`setRequiredFields`、`isAllowed`、`getErrors`等）和转换相关（`getTypeConverter`、`registerCustomEditor`、`setBindingErrorProcessor`、`getBindingResult`等）。

`WebDataBinder`参数也可以设置为`ConversionService`对象。我们将使用全局和声明性初始化，而不是在我们的`allowDateBinding`方法中本地执行（使用`WebDataBinder.setConversion` setter）。

我们选择的`WebBindingInitializer`实现是 Spring 的`ConfigurableWebBindingInitializer` bean。这确实是一个在 Spring 应用程序上下文中进行声明性配置的方便类。它使得预配置的初始化器可以在多个控制器/处理程序上重复使用。

在我们的情况下，`WebBindingInitializer`将有助于全局初始化注册的类型转换器，比如`StringToStockProduct`，同时也可以实现我们的全局异常处理目标。

#### ConversionService API

第 11 步定义了一个`StringToStockProduct`转换器，允许定义一个简洁清晰的`getByCode`方法处理程序：

```java
@RequestMapping(value="/{code}", method=GET)
@ResponseStatus(HttpStatus.OK)
public StockProductOverviewDTO getByCode(
@PathVariable(value="code") StockProduct stock){
  return StockProductOverviewDTO.build(stock);
}
```

这些转换器可以在 Spring 应用程序中广泛使用，而不限于请求范围。它们的泛型使用可能非常有益。它们绑定到`conversionService` bean，没有特定的方法可以避免它们的单独声明。

#### 在`PropertyEditors`和转换器之间进行选择

`PropertyEditors`和`ConversionService`中的转换器在它们的字符串到类型使用中可能看起来是彼此的替代品。

Spring 在设置 bean 属性时大量使用`PropertyEditors`的概念。在 Spring MVC 中，它们用于解析 HTTP 请求。它们在 Spring MVC 中的声明与请求范围相关。

即使它们可以在全局初始化，你必须将`PropertyEditors`视为最初受限范围的元素。以这种方式看待它们合法地将它们附加到`@InitBinder`方法和`WebBinderData`上。它们比转换器更不通用。

在使用`PropertyEditors`处理枚举时，Spring 提供了一种命名约定，可以避免单独声明枚举。我们稍后将利用这个方便的约定。

## 还有更多...

我们将在下一个示例中查看其他`RequestMappingHandlerAdapter`属性。目前，还有更多关于`PropertyEditors`特别是内置编辑器的讨论。

### 内置的 PropertyEditor 实现

以下`PropertyEditors`实现是 Spring 原生支持的。它们可以在所有控制器中手动应用以进行绑定。你可能会认出`CustomDateEditor`，它已在`CloudstreetApiWCI`中注册。

| 提供的实现 | 默认行为 |
| --- | --- |
| `ByteArrayPropertyEditor` | 这是字节数组的编辑器。字符串将简单地转换为它们对应的字节表示。默认情况下由`BeanWrapperImpl`注册。 |
| `ClassEditor` | 将字符串表示的类解析为实际类，反之亦然。当找不到类时，会抛出`IllegalArgumentException`异常。默认情况下由`BeanWrapperImpl`注册。 |
| `CustomBooleanEditor` | 这是一个可定制的布尔属性编辑器。默认情况下由`BeanWrapperImpl`注册，但可以通过注册自定义实例来覆盖它。 |
| `CustomCollectionEditor` | 这是集合的属性编辑器，将任何源集合转换为给定的目标集合类型。 |
| `CustomDateEditor` | 这是一个可定制的`java.util.Date`属性编辑器，并支持自定义的`DateFormat`。默认情况下未注册。用户必须根据需要以适当的格式注册它。 |
| `CustomNumberEditor` | 这是任何数字子类（如`Integer`、`Long`、`Float`或`Double`）的可定制属性编辑器。默认情况下由`BeanWrapperImpl`注册，但可以通过注册自定义实例来覆盖它。 |
| `FileEditor` | 这个编辑器能够将字符串解析为`java.io.File`对象。默认情况下由`BeanWrapperImpl`注册。 |
| `InputStreamEditor` | 这是一个单向属性编辑器，能够接受文本字符串并生成`InputStream`（通过中间的`ResourceEditor`和`Resource`）。`InputStream`属性可以直接设置为字符串。默认情况下不会关闭`InputStream`属性。它默认由`BeanWrapperImpl`注册。 |

### Spring IO 参考文档

在 Spring IO 参考文档中查找有关类型转换和`PropertyEditors`的更多详细信息，请访问：[`docs.spring.io/spring/docs/3.0.x/spring-framework-reference/html/validation.html`](http://docs.spring.io/spring/docs/3.0.x/spring-framework-reference/html/validation.html)。

# 配置内容协商（JSON、XML 等）

在这个示例中，我们将看到如何配置系统根据客户端的期望来决定渲染格式的方式。

## 准备工作

我们主要将在这里审查 XML 配置。然后，我们将使用不同的请求测试 API，以确保对 XML 格式提供支持。

## 如何做...

1.  `RequestMappingHandlerAdapter`配置已在`dispatcher-context.xml`中更改。已添加了`contentNegotiationManager`属性，以及一个`xmlConverter` bean：

```java
<bean class="org.sfw.web...
  method.annotation.RequestMappingHandlerAdapter">
  <property name="messageConverters">
    <list>
      <ref bean="xmlConverter"/>
      <ref bean="jsonConverter"/>
      </list>
  </property>
  <property name="customArgumentResolvers">
    <list>
      <bean class="net.kaczmarzyk.spring.data.jpa. web.SpecificationArgumentResolver"/>
    <bean class="org.sfw.data.web. PageableHandlerMethodArgumentResolver">
      <property name="pageParameterName" value="pn"/>
      <property name="sizeParameterName" value="ps"/>
      </bean>
    </list>
  </property>
  <property name="requireSession" value="false"/>
  <property name="contentNegotiationManager" ref="contentNegotiationManager"/>
</bean>

<bean id="contentNegotiationManager" class="org.sfw.web.accept. ContentNegotiationManagerFactoryBean">
  <property name="favorPathExtension" value="true" />
  <property name="favorParameter" value="false" />
  <property name="ignoreAcceptHeader" value="false"/>
  <property name="parameterName" value="format" />
  <property name="useJaf" value="false"/>
  <property name="defaultContentType" value="application/json" />
  <property name="mediaTypes">
    <map>
      <entry key="json" value="application/json" />
      <entry key="xml" value="application/xml" />
   </map>
  </property>
</bean>
<bean id="xmlConverter" class="org.sfw.http...xml.MarshallingHttpMessageConverter">
  <property name="marshaller">
    <ref bean="xStreamMarshaller"/>
  </property>
  <property name="unmarshaller">
    <ref bean="xStreamMarshaller"/>
  </property>
</bean>
<bean id="xStreamMarshaller" class="org.springframework.oxm.xstream.XStreamMarshaller">
  <property name="autodetectAnnotations" value="true"/>
</bean>
```

1.  已添加了`XStream`的 Maven 依赖项如下：

```java
    <dependency>
      <groupId>com.thoughtworks.xstream</groupId>
       <artifactId>xstream</artifactId>
      <version>1.4.3</version>
    </dependency>
```

1.  调用 URL：`http://localhost:8080/api/indices/EUROPE/^GDAXI/histo.json`应该像以前一样定位`getHistoIndex()`处理程序，您应该收到相同的`json`响应：![如何做...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00845.jpeg)

1.  此外，现在调用 URL `http://localhost:8080/api/indices/EUROPE/^GDAXI/histo.xml`应该生成以下 XML 格式的响应：![如何做...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00847.jpeg)

## 它是如何工作的...

我们已经添加了对 XML 的支持，使用了`MarshallingHttpMessageConverter` bean，定义了默认媒体类型(`application/json`)，并定义了全局内容协商策略。

### 支持 XML 编组

正如我们在上一个示例中所说的，`MarshallingHttpMessageConverter`随框架提供，但它需要`spring-oxm`依赖项，以及编组器和解组器的定义。`spring-oxm`是要引用的 Maven 构件：

```java
<dependency>
  <groupId>org.springframework</groupId>
  <artifactId>spring-oxm</artifactId>
  <version>${spring.version}</version>
</dependency>
```

#### XStream 编组器

我们选择`XStreamMarshaller`作为 XML 编组操作的提供者：

```java
<bean class="org.springframework.oxm.xstream.XStreamMarshaller">
  <property name="autodetectAnnotations" value="true"/>
</bean>
```

`XStream`编组器是`spring-oxm`项目的一部分。即使它*不建议*用于外部源解析（这*不*是我们的意图），它非常好，并且默认情况下需要非常少的配置（不需要特定的类注册或初始映射策略）。

类型和字段可以被注释以自定义默认行为。您可以在这里找到一些来自他们文档的例子：

+   `@XStreamAlias`：用于类型、字段或属性

+   `@XStreamImplicit`：用于集合或数组

+   `@XStreamAsAttribute`：用于将字段标记为属性

+   `@XStreamConverter`：为字段指定特定的转换器

在我们的情况下，我们在 DTO 中应用了最小的编组自定义。

您可以在官方网站[`xstream.codehaus.org`](http://xstream.codehaus.org)上找到有关`XStream`的更多信息。

### ContentNegotiationManager 中的协商策略

在这里，我们谈论的是我们配置系统选择响应的媒体类型的方式。客户端在其请求中显示期望，服务器会尽力满足这些期望，以最大程度地满足可用的分辨率。

客户端有三种方式来指定其媒体类型的期望。我们将在以下部分讨论它们。

#### 接受标头

客户端请求指定 mime 类型或 mime 类型列表（`application/json`、`application/xml`等）作为`Accept`标头的值。这是 Spring MVC 的默认选择。

Web 浏览器可以发送各种`Accept`标头，因此完全依赖这些标头是有风险的。因此，至少支持一种替代方案是很好的。

这些标头甚至可以完全忽略`ContentNegotiationManager`中的`ignoreAcceptHeader`布尔属性。

#### URL 路径中的文件扩展名后缀

在 URL 路径中允许指定文件扩展名后缀是一种替代方案。这是我们配置中的判别器选项。

为此，`ContentNegotiationManager`中的`favorPathExtension`布尔属性已设置为 true，我们的 AngularJS 工厂实际上请求`.json`路径。

#### 请求参数

如果您不喜欢路径扩展选项，可以定义特定的查询参数。此参数的默认名称是`format`。它可以通过`parameterName`属性进行自定义，并且可能的预期值是已注册的格式后缀（`xml`、`html`、`json`、`csv`等）。

这个选项可以作为`favorParameter`布尔属性的判别器选项设置。

#### Java 激活框架

将`useJaf`布尔属性设置为 true，配置为依赖于 Java 激活框架，而不是 Spring MVC 本身，用于后缀到媒体类型的映射（`json`对应`application/json`，`xml`对应`application/xml`等）。

### @RequestMapping 注解作为最终过滤器

最后，带有`@RequestMapping`注解的控制器，特别是`produces`属性，应该对将呈现的格式有最终决定权。

## 还有更多...

现在我们将看一下 JAXB2 作为 XML 解析器的实现和`ContentNegotiationManagerFactoryBean`的配置。

### 使用 JAXB2 实现作为 XML 解析器

JAXB2 是当前的 Java XML 绑定规范。我们使用`XStream`的示例只是一个示例，当然可以使用另一个 XML 编组器。Spring 支持 JAXB2。它甚至在`spring-oxm`包中提供了默认的 JAXB2 实现：`org.springframework.oxm.jaxb.Jaxb2Marshaller`。

在 DTO 中使用 JAXB2 注解可能是可移植性更好的选择。访问`Jaxb2Marshaller`的 JavaDoc 以获取有关其配置的更多详细信息：[`docs.spring.io/autorepo/docs/spring/4.0.4.RELEASE/javadoc-api/org/springframework/oxm/jaxb/Jaxb2Marshaller.html`](http://docs.spring.io/autorepo/docs/spring/4.0.4.RELEASE/javadoc-api/org/springframework/oxm/jaxb/Jaxb2Marshaller.html)。

### ContentNegotiationManagerFactoryBean JavaDoc

`ContentNegotiationManagerFactoryBean`的完整配置在其 JavaDoc 中再次可访问：

[`docs.spring.io/spring/docs/current/javadoc-api/org/springframework/web/accept/ContentNegotiationManagerFactoryBean.html`](http://docs.spring.io/spring/docs/current/javadoc-api/org/springframework/web/accept/ContentNegotiationManagerFactoryBean.html)

# 添加分页、过滤和排序功能

现在我们已经介绍了 Spring MVC 的 REST 配置的基础，我们将通过添加分页、过滤和排序功能来改进我们的 REST 服务。

## 做好准备

分页是 Spring Data 项目中开发的一个概念。为了添加分页，我们将引入`Pageable`接口，用于从请求中填充的包装器实现。这些接口随后被 Spring Data 识别和处理。

`Page`接口，特别是`PageImpl`实例，可以由 Spring Data 生成以格式化其结果。我们将使用它们，因为它们非常适合于 REST 呈现。

最后，我们将详细介绍这里使用的两个数据绑定工具，以将过滤和分页从我们的控制器逻辑中抽象出来。

## 如何做到这一点...

1.  对于方法处理程序，我们已经添加了我们希望它们支持的参数。`IndexController`中的以下处理程序现在提供分页和排序：

```java
import org.springframework.data.domain.PageRequest;

    @RequestMapping(value="/{market}", method=GET)
    public Page<IndexOverviewDTO> getIndicesPerMarket(
      @PathVariable MarketCode market,
      @PageableDefault(size=10, page=0, sort={"dailyLatestValue"}, direction=Direction.DESC) Pageable pageable){
        return marketService. getLastDayIndicesOverview(market, pageable);
}
```

1.  在相应的服务层实现中，将`pageable`实例传递给 Spring Data JPA 的抽象实现：

```java
@Override
public Page<IndexOverviewDTO> getLastDayIndicesOverview(Pageable pageable) {
    Page<Index> indices = indexProductRepository.findAll(pageable);
    List<IndexOverviewDTO> result = new LinkedList<>();
    for (Index index : indices) {
      result.add(IndexOverviewDTO.build(index));
    }
    return new PageImpl<>(result, pageable,   indices.getTotalElements());
}
```

这基本上就是关于分页和排序模式的全部内容！所有样板代码都是透明的。它使我们能够神奇地检索一个包装在页面元素中的资源，该元素携带了前端可能需要的分页工具。对于我们特定的方法处理程序，调用 URL：

`http://localhost:8080/api/indices/US.json?size=2&page=0&sort=dailyLatestValue`,`asc`的结果是以下 JSON 响应：

![如何做到这一点...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00848.jpeg)

1.  我们还将此模式应用于动态检索带有分页的索引，即使它几乎是相同的方法处理程序定义。

1.  我们还将相同的模式应用于检索用户活动（在`CommunityController`中）：

```java
@RequestMapping(value="/activity", method=GET)
@ResponseStatus(HttpStatus.OK)
public Page<UserActivityDTO> getPublicActivities(
  @PageableDefault(size=10, page=0, sort={"quote.date"},direction=Direction.DESC) Pageable pageable){
  return communityService.getPublicActivity(pageable);
}
```

1.  现在我们已经调整了 AngularJS 层（在本配方的*另请参阅...*部分有详细介绍），我们已经能够完全重构我们的欢迎页面，使用 REST 服务，并为用户活动提供无限滚动：![如何做...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00849.jpeg)

1.  为了充分利用 REST 服务的功能，现在有一个名为*INDICES BY MARKET*的新屏幕，可以从**价格和市场**菜单访问：![如何做...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00850.jpeg)

这里呈现的表格是完全自主的，因为它具有完全的 angular 化（AngularJS）和异步分页/排序功能。

1.  `StockProductController`对象在其`search()`方法处理程序中实现了分页和排序模式，还提供了一个过滤功能，允许用户操作`LIKE` SQL 操作符与`AND`限制相结合：

```java
@RequestMapping(method=GET)
@ResponseStatus(HttpStatus.OK)
public Page<ProductOverviewDTO> search(
@And(value = { @Spec(params = "mkt", path="market.code",spec = EqualEnum.class)},
   and = { @Or({
@Spec(params="cn", path="code", spec=LikeIgnoreCase.class),
@Spec(params="cn", path="name", spec=LikeIgnoreCase.class)})}
  ) Specification<StockProduct> spec,
@RequestParam(value="mkt", required=false) MarketCodeParam market, 
@RequestParam(value="sw", defaultValue="") String startWith, 
@RequestParam(value="cn", defaultValue="") String contain, 
@PageableDefault(size=10, page=0, sort={"dailyLatestValue"}, direction=Direction.DESC) Pageable pageable){
  return productService.getProductsOverview(startWith, spec, pageable);
}
```

1.  `productService`实现，在其`getProductsOverview`方法中（如所示），引用了一个创建的`nameStartsWith`方法：

```java
@Override
public Page<ProductOverviewDTO> getProductsOverview(String startWith, Specification<T> spec, Pageable pageable) {
  if(StringUtils.isNotBlank(startWith)){
    spec = Specifications.where(spec).and(new ProductSpecifications<T>().nameStartsWith(startWith);
  }
  Page<T> products = productRepository.findAll(spec, pageable);
  List<ProductOverviewDTO> result = new LinkedList<>();
  for (T product : products) {
    result.add(ProductOverviewDTO.build(product));
  }
  return new PageImpl<>(result, pageable, products.getTotalElements());
}
```

1.  `nameStartsWith`方法是位于核心模块内的`ProductSpecifications`类中的规范工厂：

```java
public class ProductSpecifications<T extends Product> {
public Specification<T> nameStartsWith(final String searchTerm) {
  return new Specification<T>() {
  private String startWithPattern(final String searchTerm) {
    StringBuilder pattern = new StringBuilder();
	pattern.append(searchTerm.toLowerCase());
    pattern.append("%");
    return pattern.toString();
  }
    @Override
      public Predicate toPredicate(Root<T> root,CriteriaQuery<?> query, CriteriaBuilder cb) {    
      return cb.like(cb.lower(root.<String>get("name")), startWithPattern(searchTerm));
}
    };
  }
}
```

1.  总的来说，`search()` REST 服务广泛地用于与股票检索相关的三个新屏幕。这些屏幕可以通过**价格和市场**菜单访问。这是新的**ALL PRICES SEARCH**表单：![如何做...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00851.jpeg)

1.  以下截图对应于**SEARCH BY MARKET**表单：![如何做...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00852.jpeg)

1.  最后，找到以下新的**Risers and Fallers**屏幕：![如何做...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00853.jpeg)

## 它是如何工作的...

再次强调，这个配方主要是关于 Spring Data 以及如何让 Spring MVC 为我们支持 Spring Data。

### Spring Data 分页支持（你会喜欢它！）

我们已经在上一章中看到了 Spring Data 存储库抽象的一些好处。

在本节中，我们将看到 Spring Data 如何在其抽象的存储库中支持分页概念。Spring MVC 还提供了一个非常有益的扩展，通过特定的参数解析器来防止任何自定义适配逻辑。

#### 存储库中的分页和排序

你可以注意到我们的存储库接口的方法中使用了 Pageable 参数。例如下面是`IndexRepositoryJpa`存储库：

```java
public interface IndexRepositoryJpa extends JpaRepository<Index, 
  String>{
  List<Index> findByMarket(Market market);
  Page<Index> findByMarket(Market market, Pageable pageable);
  List<Index> findAll();
  Page<Index> findAll(Pageable pageable);
  Index findByCode(MarketCode code);
}
```

Spring Data 将`org.springframework.data.domain.Pageable`类型识别为方法参数。当不需要完整的`Pageable`实例时，它还识别`org.springframework.data.domain.Sort`类型。它动态地应用分页和排序到我们的查询中。

你可以在这里看到更多例子（摘自 Spring 参考文档）：

```java
Page<User> findByLastname(String lastname, Pageable pageable);
Slice<User> findByLastname(String lastname, Pageable pageable);
List<User> findByLastname(String lastname, Sort sort);
List<User> findByLastname(String lastname, Pageable pageable);
```

### 提示

请记住，排序选项也是通过`Pageable`处理的。顺便说一句，这就是我们在应用程序中进行排序的方式。

从这些额外的例子中，你可以看到 Spring Data 可以返回一个`Page`（`org.springframework.data.domain.Page`）、一个`Slice`（`org.springframework.data.domain.Slice`）或者简单的`List`。

但是这里有一个惊人的部分：`Page`对象包含了构建强大分页工具所需的一切！之前，我们看到了提供了一个`Page`元素的`json`响应。

通过以下请求：`http://localhost:8080/api/indices/US.json?size=2&page=0&sort=dailyLatestValue,asc`，我们要求第一页，并收到一个`Page`对象告诉我们这一页是不是第一页或最后一页（`firstPage: true/false`，`lastPage: true/false`），页面内的元素数量（`numberOfElements: 2`），总页数和总元素数量（`totalPages: 2`，`totalElements: 3`）。

### 提示

这意味着 Spring Data 首先执行了我们想要执行的查询，然后透明地执行了一个不带分页过滤的计数查询。

`Slice`对象是`Page`的超级接口，不包含`numberOfElements`和`totalElements`的计数。

#### PagingAndSortingRepository<T,ID>

如果一个仓库还没有扩展`JpaRepository<T,ID>`，我们可以让它扩展`PagingAndSortingRepository<T,ID>`，这是`CrudRepository<T,ID>`的扩展。它将提供额外的方法来使用分页和排序抽象检索实体。这些方法包括：

```java

Iterable<T> findAll(Sort sort);
  Page<T> findAll(Pageable pageable);
```

#### Web 部分 - PageableHandlerMethodArgumentResolver

正如我们之前介绍的，我们已经将`org.springframework.data.web.PageableHandlerMethodArgumentResolver` bean 添加到我们的`RequestMappingHandlerAdapter`中作为`customArgumentResolver`。这样做使我们能够依赖 Spring 数据绑定来透明地预填充一个作为方法处理程序参数可用的`Pageable`实例（在本教程的第一步中以粗体显示）。

以下是关于我们可以用于绑定的请求参数的更多信息：

| 参数名称 | 目的/用法 | 默认值 |
| --- | --- | --- |
| `page` | 我们想要检索的页面。 | 0 |
| `size` | 我们想要检索的页面大小。 | 10 |
| `sort` | 应该按照`property,property(,ASC | DESC)`格式进行排序的属性。如果我们想要切换方向，例如：`?sort=firstname&sort=lastname,asc`，我们应该使用多个`sort`参数。 | 默认排序方向是升序。 |

正如我们在第一步中实现的那样，在特定参数缺失的情况下，可以自定义默认值。这是通过`@PageableDefault`注解实现的：

```java
@PageableDefault(
size=10, page=0, sort={"dailyLatestValue"}, direction=Direction.DESC
)
```

### 提示

页面、大小和排序参数名称可以通过在 Spring 配置中设置适当的`PageableHandlerMethodArgumentResolver`属性来进行覆盖。

如果由于某种原因我们不使用`PageableHandlerMethodArgumentResolver`，我们仍然可以捕获我们自己的请求参数（用于分页），并从中构建一个`PageRequest`实例（例如，`org.springframework.data.domain.PageRequest`是一个`Pageable`实现）。

### 一个有用的规范参数解析器

在引入这个有用的规范参数解析器之前，我们必须介绍规范的概念。

#### JPA2 criteria API 和 Spring Data JPA 规范

Spring Data 参考文档告诉我们，JPA 2 引入了一个可以用于以编程方式构建查询的 criteria API。在编写`criteria`时，我们实际上为域类定义了查询的 where 子句。

Spring Data JPA 从 Eric Evans 的书*Domain Driven Design*中引入了规范的概念，遵循相同的语义，并提供了使用 JPA criteria API 定义这些规范的 API。

为了支持规范，我们可以在我们的仓库接口中扩展`JpaSpecificationExecutor`接口，就像我们在我们的`ProductRepository`接口中所做的那样：

```java
@Repository
public interface ProductRepository<T extends Product> extends JpaRepository<T, String>, JpaSpecificationExecutor<T> {
  Page<T> findByMarket(Market marketEntity, Pageable pageable);
  Page<T> findByNameStartingWith(String param, Pageable pageable);
  Page<T> findByNameStartingWith(String param, Specification<T> spec, Pageable pageable);
}
```

在我们的示例中，`findByNameStartingWith`方法检索特定类型（`StockProduct`）的所有产品，这些产品的名称以`param`参数开头，并且与`spec`规范匹配。

#### 规范参数解析器

正如我们之前所说，这个`CustomArgumentResolver`还没有绑定到官方的 Spring 项目中。它的使用可以适用于一些用例，比如本地搜索引擎，以补充 Spring Data 动态查询、分页和排序功能。

与我们从特定参数构建`Pageable`实例的方式相同，这个参数解析器也允许我们从特定参数透明地构建一个`Specification`实例。

它使用`@Spec`注解来定义`like`、`equal`、`likeIgnoreCase`、`in`等`where`子句。这些`@Spec`注解可以通过`@And`和`@Or`注解的帮助组合在一起，形成`AND`和`OR`子句的组。一个完美的用例是开发我们的搜索功能，作为分页和排序功能的补充。

您应该阅读以下文章，这是该项目的介绍。这篇文章的标题是“使用 Spring MVC 和 Spring Data JPA 过滤数据的另一种 API”：

[`blog.kaczmarzyk.net/2014/03/23/alternative-api-for-filtering-data-with-spring-mvc-and-spring-data`](http://blog.kaczmarzyk.net/2014/03/23/alternative-api-for-filtering-data-with-spring-mvc-and-spring-data)

此外，使用以下地址找到项目的存储库和文档：

[`github.com/tkaczmarzyk/specification-arg-resolver`](https://github.com/tkaczmarzyk/specification-arg-resolver)

### 提示

尽管这个库的用户数量远远低于 Spring 社区，但它仍然非常有用。

## 还有更多...

到目前为止，我们一直在关注 Spring MVC。然而，随着呈现的新屏幕，前端（AngularJS）也发生了变化。

### Spring Data

要了解更多关于 Spring Data 功能的信息，请查看官方参考文档：

[`docs.spring.io/spring-data/jpa/docs/1.8.0.M1/reference/html`](http://docs.spring.io/spring-data/jpa/docs/1.8.0.M1/reference/html)

### Angular 路由

如果在**主页**和**价格和市场**菜单之间导航，您会发现整个页面从未完全刷新。所有内容都是异步加载的。

为了实现这一点，我们使用了 AngularJS 路由。`global_routes.js`文件是为此目的而创建的：

```java
cloudStreetMarketApp.config(function($locationProvider, $routeProvider) {
  $locationProvider.html5Mode(true);
  $routeProvider
    .when('/portal/index', {
      templateUrl: '/portal/html/home.html', 
      controller: 'homeMainController'
    })
  .when('/portal/indices-:name', {
    templateUrl: '/portal/html/indices-by-market.html', 
    controller: 'indicesByMarketTableController' 
  })
    .when('/portal/stock-search', {
      templateUrl: '/portal/html/stock-search.html', 
      controller:  'stockSearchMainController'
    })
    .when('/portal/stock-search-by-market', {
      templateUrl: '/portal/html/stock-search-by-market.html', 
      controller:  'stockSearchByMarketMainController'
    })
    .when('/portal/stocks-risers-fallers', {
      templateUrl: '/portal/html/stocks-risers-fallers.html', 
      controller:  'stocksRisersFallersMainController'
    })
    .otherwise({ redirectTo: '/' });
});
```

在这里，我们定义了路由（应用程序通过`href`标签的 URL 路径查询的一部分）和 HTML 模板（作为公共静态资源在服务器上可用）之间的映射表。我们为这些模板创建了一个`html`目录。

然后，AngularJS 在每次请求特定 URL 路径时异步加载一个模板。通常情况下，AngularJS 通过 transclusions 来操作这一点（它基本上删除并替换整个 DOM 部分）。由于模板只是模板，它们需要绑定到控制器，这些控制器通过我们的工厂操作其他 AJAX 请求，从我们的 REST API 中提取数据，并呈现预期的内容。

在前面的例子中：

+   `/portal/index`是一个路由，也就是一个请求的路径

+   `/portal/html/home.html`是映射的模板

+   `homeMainController`是目标控制器

## 另请参阅

您可以在以下网址了解更多关于 AngularJS 路由的信息：

[`docs.angularjs.org/tutorial/step_07`](https://docs.angularjs.org/tutorial/step_07)

### 使用 Angular UI 实现 Bootstrap 分页

我们使用了来自 AngularUI 团队（[`angular-ui.github.io`](http://angular-ui.github.io)）的 UI Bootstrap 项目（[`angular-ui.github.io/bootstrap`](http://angular-ui.github.io/bootstrap)）的分页组件。该项目提供了一个与 AngularJS 一起操作的`Boostrap`组件。

在分页的情况下，我们获得了一个`Bootstrap`组件（与 Bootstrap 样式表完美集成），由特定的 AngularJS 指令驱动。

我们的分页组件之一可以在`stock-search.html`模板中找到：

```java
<pagination page="paginationCurrentPage" 
  ng-model="paginationCurrentPage" 
  items-per-page="pageSize" 
  total-items="paginationTotalItems"
  ng-change="setPage(paginationCurrentPage)">   
</pagination>
```

`page`，`ng-model`，`items-per-page`，`total-items`和`ng-change`指令使用变量（`paginationCurrentPage`，`pageSize`和`paginationTotalItems`），这些变量附加到`stockSearchController`范围。

### 提示

要了解有关该项目的更多信息，请访问其文档：

[`angular-ui.github.io/bootstrap`](http://angular-ui.github.io/bootstrap)

# 全局处理异常

本教程介绍了在 Web 应用程序中全局处理异常的技术。

## 准备工作

在 Spring MVC 中处理异常有不同的方法。我们可以选择定义特定于控制器的`@ExceptionHandler`，或者我们可以选择在`@ControllerAdvice`类中全局注册`@ExceptionHandler`。

我们在 REST API 中开发了第二个选项，即使我们的`CloudstreetApiWCI`超类可以在其控制器之间共享`@ExceptionHandler`。

现在我们将看到如何自动将自定义和通用异常类型映射到 HTTP 状态代码，以及如何将正确的错误消息包装在通用响应对象中，该对象可被任何客户端使用。

## 如何做...

1.  当发生错误时，我们需要一个包装对象发送回客户端：

```java
public class ErrorInfo {
    public final String error;
    public int status;
    public final String date;

    private static final DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
    public ErrorInfo(Throwable throwable, HttpStatus status){
      this.error = ExceptionUtil.getRootMessage(throwable);
      this.date = dateFormat.format(new Date());
      this.status = status.value();
   }
   public ErrorInfo(String message, HttpStatus status) {
      this.error = message;
      this.date = dateFormat.format(new Date());
      this.status = status.value();
   }
  @Override
  public String toString() {
    return "ErrorInfo [status="+status+", error="+error+ ", date=" + date + "]";
  }
}
```

1.  我们创建了一个带有`@ControllerAdvice`注释的`RestExceptionHandler`类。这个`RestExceptionHandler`类还继承了`ResponseEntityExceptionHandler`支持类，这使我们可以访问一个默认的映射异常/响应状态，可以被覆盖：

```java
@ControllerAdvice
public class RestExceptionHandler extends ResponseEntityExceptionHandler {

   @Override
protected ResponseEntity<Object> handleExceptionInternal(Exception ex, Object body, HttpHeaders headers, HttpStatus status, WebRequest request) {
if(body instanceof String){
return new ResponseEntity<Object>(new ErrorInfo((String) body, status), headers, status);
   }
  return new ResponseEntity<Object>(new ErrorInfo(ex, status), headers, status);
}

    // 400
    @Override
protected ResponseEntity<Object> handleHttpMessageNotReadable(final HttpMessageNotReadableException ex, final HttpHeaders headers, final HttpStatus status, final WebRequest request) {
return handleExceptionInternal(ex, "The provided request body is not readable!", headers, HttpStatus.BAD_REQUEST, request);
}

@Override
protected ResponseEntity<Object> handleTypeMismatch(TypeMismatchException ex, HttpHeaders headers, HttpStatus status, WebRequest request) {
  return handleExceptionInternal(ex, "The request parameters were not valid!", headers, HttpStatus.BAD_REQUEST, request);
  }
(...)

@ExceptionHandler({ InvalidDataAccessApiUsageException.class, DataAccessException.class , IllegalArgumentException.class })
protected ResponseEntity<Object> handleConflict(final RuntimeException ex, final WebRequest request) {
    return handleExceptionInternal(ex, "The request parameters were not valid!", new HttpHeaders(), HttpStatus.BAD_REQUEST, request);
}
(...)

// 500
@ExceptionHandler({ NullPointerException.class, IllegalStateException.class })
public ResponseEntity<Object> handleInternal(final RuntimeException ex, final WebRequest request) {
return handleExceptionInternal(ex,  "An internal 	error happened during the request! Please try 	again or contact an administrator.", new HttpHeaders(), HttpStatus.INTERNAL_SERVER_ERROR, request);
}
}
```

### 提示

`ErrorInfo`包装器和`RestExceptionHandler`都将支持国际化。这将在第七章中进行演示，*开发 CRUD 操作和验证*。

1.  我们为 MarketCode 和 QuotesInterval Enums 创建了以下两个属性编辑器：

```java
public class MarketCodeEditor extends PropertyEditorSupport{
public void setAsText(String text) {
    try{
      setValue(MarketCode.valueOf(text));
    } catch (IllegalArgumentException e) {
      throw new IllegalArgumentException("The provided value for the market code variable is invalid!");
    }
    }
}
public class QuotesIntervalEditor extends PropertyEditorSupport {
    public void setAsText(String text) {
    try{
       setValue(QuotesInterval.valueOf(text));
    } catch (IllegalArgumentException e) {
      throw new IllegalArgumentException("The provided value for the quote-interval variable is invalid!");
    }
  }
}
```

### 提示

这两个属性编辑器会自动注册，因为它们满足命名和位置约定。由于`MarketCode`和`QuotesInterval`是枚举值，Spring 会在枚举包中查找`MarketCodeEditor`（Editor 后缀）和`QuotesIntervalEditor`。

1.  就是这样！您可以通过在 AngularJS 工厂的`getHistoIndex`方法中提供一个不正确的市场代码来测试它（在`home_financial_graph.js`文件中）。将调用从`$http.get("/api/indices/"+market+"wrong/"+index+"/histo.json")`更改为`$http.get("/api/indices/"+market+"/"+index+"/histo.json")`。

1.  重新启动整个应用程序（**cloudstreetmarket-webapp**和**cloudstreetmarket-api**）后，对`http://localhost:8080/portal/index`的调用将导致**Ajax GET**请求加载索引的结果为**400**状态码：![操作步骤...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00854.jpeg)

1.  有关此失败请求的更多详细信息将显示在`json`响应中：![操作步骤...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00855.jpeg)

接收到的错误消息——**提供的市场变量值无效！**现在是可以接受的。

1.  在获得这个结果后，您可以重置`home_financial_graph.js`文件。

## 工作原理...

在这里，我们关注的是在 REST 环境中处理异常的方式。期望与纯 Web 应用程序略有不同，因为直接用户可能不一定是人类。因此，REST API 必须保持标准、一致和自解释的通信，即使过程生成了错误或失败。

这种一致性是通过始终向客户端返回适当的 HTTP 状态码反馈来实现的，服务器关于请求处理，并始终以客户端期望的格式返回响应主体（与 HTTP 请求的**Accept**头中列出的 MIME 类型之一匹配的格式）。

### 使用@ControllerAdvice 进行全局异常处理

Spring 3.2 带来了一种比以前的异常处理机制更适合 REST 环境的解决方案。使用这种解决方案，使用`@ControllerAdvice`注释的类可以在 API 的不同位置注册。这些注释通过类路径扫描查找，并自动注册到一个公共存储库中，以支持所有控制器（默认情况下）或控制器的子集（使用注释选项）。

在我们的情况下，我们定义了一个单一的`@ControllerAdvice`来监视整个 API。这个想法是在`@ControllerAdvice`注释的`class(es)`中定义相关的方法，这些方法可以将特定的异常类型匹配到特定的 ResponseEntity。一个 ResponseEntity 携带一个主体和一个响应状态码。

这些方法的定义都带有`@ExceptionHandler`注释。此注释的选项允许您针对特定的异常类型。在定义`@ControllerAdvice`时的一个常见模式是使其扩展支持类`ResponseEntityExceptionHandler`。

#### 支持 ResponseEntityExceptionHandler 类

支持`ResponseEntityExceptionHandler`类提供了本机异常（如`NoSuchRequestHandlingMethodException`、`ConversionNotSupportedException`、`TypeMismatchException`等）和 HTTP 状态码之间的预定义映射。

`ResponseEntityExceptionHandler`实现了响应呈现的常见模式。它调用了声明为受保护的特定情况呈现方法，比如下面的`handleNoSuchRequestHandlingMethod`。

```java
protected ResponseEntity<Object> handleNoSuchRequestHandlingMethod(NoSuchRequestHandlingMethod Exception ex, HttpHeaders headers, HttpStatus status, WebRequest request) {
    pageNotFoundLogger.warn(ex.getMessage());
  return handleExceptionInternal(ex, null, headers, status, request);
}
```

这些方法显然可以在`@ControllerAdvice`注解的类中完全重写。重要的是返回`handleExceptionInternal`方法。

这个`handleExceptionInternal`方法也被定义为受保护的，然后可以被重写。这就是我们所做的——返回一个统一的`ErrorInfo`实例：

```java
@Override
protected ResponseEntity<Object> handleExceptionInternal(Exception ex, Object body, HttpHeaders headers, HttpStatus status, WebRequest request) {
  return new ResponseEntity<Object>(new ErrorInfo(ex, (body!=null)? body.toString() : null, status), headers, status);
}
```

#### 统一的错误响应对象

关于统一错误响应对象应该公开的字段，没有具体的标准实践。我们决定为`ErrorInfo`对象提供以下结构：

```java
{
  error: "Global categorization error message",
  message: "Specific and explicit error message",
  status: 400,
  date: "yyyy-MM-dd HH:mm:ss.SSS"
}
```

使用两个不同级别的消息（来自异常类型的全局错误消息和特定情况的消息）允许客户端选择更合适的消息（甚至两者都选择！）在每种情况下呈现在应用程序中。

正如我们已经说过的，这个`ErrorInfo`对象目前还不支持国际化。我们将在第七章 *开发 CRUD 操作和验证*中进行改进。

## 还有更多...

我们在这里提供了一系列与 Web 环境中异常处理相关的资源：

### HTTP 状态码

**万维网联盟**为 HTTP/1.1 指定了明确的响应状态码。比错误消息本身更重要的是，对于 REST API 来说，实现它们至关重要。您可以在这里阅读更多相关信息：

[`www.w3.org/Protocols/rfc2616/rfc2616-sec010.html`](http://www.w3.org/Protocols/rfc2616/rfc2616-sec010.html)

### Spring MVC 异常处理的官方文章

spring.io 博客中的一篇文章是一个非常有趣的资源。它不仅限于 REST 用例。可以从这个地址访问：[`spring.io/blog/2013/11/01/exception-handling-in-spring-mvc`](http://spring.io/blog/2013/11/01/exception-handling-in-spring-mvc)。

### JavaDocs

在这里，我们提供了两个 JavaDoc 资源的 URL，用于配置或简单使用：

ExceptionHandlerExceptionResolver：

[`docs.spring.io/spring/docs/current/javadoc-api/org/springframework/web/servlet/mvc/method/annotation/ExceptionHandlerExceptionResolver.html`](http://docs.spring.io/spring/docs/current/javadoc-api/org/springframework/web/servlet/mvc/method/annotation/ExceptionHandlerExceptionResolver.html)

ResponseEntityExceptionHandler：

[`docs.spring.io/spring/docs/current/javadoc-api/org/springframework/web/servlet/mvc/method/annotation/ResponseEntityExceptionHandler.html`](http://docs.spring.io/spring/docs/current/javadoc-api/org/springframework/web/servlet/mvc/method/annotation/ResponseEntityExceptionHandler.html)

## 另请参阅

+   查看官方演示网站，展示了 Spring MVC 不同类型异常的呈现方式：[`mvc-exceptions-v2.cfapps.io`](http://mvc-exceptions-v2.cfapps.io)

# 使用 Swagger 文档化和公开 API

本节详细介绍了如何使用 Swagger 提供和公开关于 REST API 的元数据。

## 准备工作

我们经常需要为用户和客户文档化 API。在文档化 API 时，根据我们使用的工具，我们经常会得到一些额外的功能，比如能够从 API 元数据生成客户端代码，甚至生成 API 的集成测试工具。

目前还没有公认的和通用的 API 元数据格式标准。这种标准的缺乏导致了市场上有很多不同的 REST 文档解决方案。

我们选择了 Swagger，因为它拥有最大和最活跃的社区。它自 2011 年以来一直存在，并且默认提供了非常好的 UI/测试工具和出色的配置。

## 如何做...

本节详细介绍了在已检出的 v4.x.x 分支的代码库中可以做什么，以及我们已经做了什么。

1.  我们已经为**cloudstreetmarket-core**和**cloudstreetmarket-parent**添加了`swagger-springmvc`项目（版本 0.9.5）的 Maven 依赖：

```java
<dependency>
  <groupId>com.mangofactory</groupId>
  <artifactId>swagger-springmvc</artifactId>
  <version>${swagger-springmvc.version}</version>
</dependency> 
```

1.  已创建以下 swagger `configuration`类：

```java
@Configuration
@EnableSwagger //Loads the beans required by the framework
public class SwaggerConfig {

  private SpringSwaggerConfig springSwaggerConfig;
  @Autowired
    public void setSpringSwaggerConfig(SpringSwaggerConfig springSwaggerConfig) {
    this.springSwaggerConfig = springSwaggerConfig;
    }
  @Bean
  public SwaggerSpringMvcPlugin customImplementation(){
      return new SwaggerSpringMvcPlugin( this.springSwaggerConfig)
          .includePatterns(".*")
          .apiInfo(new ApiInfo(
          "Cloudstreet Market / Swagger UI",
          "The Rest API developed with Spring MVC Cookbook [PACKT]",
          "",
          "alex.bretet@gmail.com",
          "LGPL",
          "http://www.gnu.org/licenses/gpl-3.0.en.html"
      ));
  }
}
```

1.  以下配置已添加到`dispatch-context.xml`中：

```java
<bean class="com.mangofactory.swagger.configuration.SpringSwaggerConfig"/>

<bean class="edu.zc.csm.api.swagger.SwaggerConfig"/>
<context:property-placeholder location="classpath*:/META-INF/properties/swagger.properties" />
```

1.  根据先前的配置，在路径`src/main/resources/META-INF/properties`添加了一个 swagger.properties 文件，内容如下：

```java
  documentation.services.version=1.0
  documentation.services.basePath=http://localhost:8080/api
```

1.  我们的三个控制器已经添加了基本文档。请参阅添加到`IndexController`的以下文档注释：

```java
@Api(value = "indices", description = "Financial indices") 
@RestController
@RequestMapping(value="/indices", produces={"application/xml", "application/json"})
public class IndexController extends CloudstreetApiWCI {

@RequestMapping(method=GET)
@ApiOperation(value = "Get overviews of indices", notes = "Return a page of index-overviews")
public Page<IndexOverviewDTO> getIndices(
@ApiIgnore @PageableDefault(size=10, page=0, sort={"dailyLatestValue"}, direction=Direction.DESC) Pageable pageable){
    return 
    marketService.getLastDayIndicesOverview(pageable);
}

@RequestMapping(value="/{market}", method=GET)
@ApiOperation(value = "Get overviews of indices filtered by market", notes = "Return a page of index-overviews")
public Page<IndexOverviewDTO> getIndicesPerMarket(
  @PathVariable MarketCode market,
  @ApiIgnore 
@PageableDefault(size=10, page=0, sort={"dailyLatestValue"}, direction=Direction.DESC) Pageable pageable){
    return 
    marketService.getLastDayIndicesOverview(market, pageable);
}

@RequestMapping(value="/{market}/{index}/histo", method=GET)
@ApiOperation(value = "Get historical-data for one index", notes = "Return a set of historical-data from one index")
public HistoProductDTO getHistoIndex(
  @PathVariable("market") MarketCode market, 
  @ApiParam(value="Index code: ^OEX") 
  @PathVariable("index") String 
  indexCode,@ApiParam(value="Start date: 2014-01-01") @RequestParam(value="fd",defaultValue="") Date fromDate,
  @ApiParam(value="End date: 2020-12-12") 
  @RequestParam(value="td",defaultValue="") Date toDate,
  @ApiParam(value="Period between snapshots") @RequestParam(value="i",defaultValue="MINUTE_30") QuotesInterval interval){
    return marketService.getHistoIndex(indexCode, market, fromDate, toDate, interval);
  }
}
```

1.  我们从[`github.com/swagger-api/swagger-ui`](https://github.com/swagger-api/swagger-ui)下载了 swagger UI 项目。这是一个静态文件集合（JS、CSS、HTML 和图片）。它已经被粘贴到我们的**cloudstreetmarket-api**项目的 webapp 目录中。

1.  最后，以下 mvc 命名空间配置再次添加到`dispatch-context.xml`中，以便 Spring MVC 打开项目中的静态文件的访问权限：

```java
<!-- Serve static content-->
<mvc:default-servlet-handler/>
```

1.  当我们有了这个配置，访问服务器上的以下 URL `http://localhost:8080/api/index.html` 就会打开 Swagger UI 文档门户：![如何做...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00856.jpeg)

不仅仅是一个 REST 文档存储库，它也是一个方便的测试工具：

![如何做...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00857.jpeg)

## 它是如何工作的...

Swagger 有自己的控制器，发布我们的 API 的元数据。Swagger UI 针对此元数据，解析它，并将其表示为可用的接口。

### 一个公开的元数据

在服务器端，通过将`com.mangofactory/swagger-springmvc`依赖添加到`swagger-springmvc`项目，并使用提供的`SwaggerConfig`类，该库在根路径上创建一个控制器：`/api-docs`，并在那里发布整个元数据供 REST API 使用。

如果您访问`http://localhost:8080/api/api-docs`，您将到达我们的 REST API 文档的根目录：

![一个公开的元数据](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00858.jpeg)

这个内容是实现 Swagger 规范的公开元数据。元数据是一个可导航的结构。在 XML 内容的`<path>`节点中可以找到到元数据其他部分的链接。

### Swagger UI

Swagger UI 只由静态文件（CSS、HTML、JavaScript 等）组成。JavaScript 逻辑实现了 Swagger 规范，并递归解析了整个公开的元数据。然后动态构建 API 文档网站和测试工具，挖掘出每个端点及其元数据。

## 还有更多...

在这一部分，我们建议您进一步了解 Swagger 及其 Spring MVC 项目的实现。

### Swagger.io

访问框架的网站和规范：[`swagger.io`](http://swagger.io)。

### swagger-springmvc 文档

swagger-springmvc 项目正在发生变化，因为它正在成为一个名为 SpringFox 的更大的项目的一部分。SpringFox 现在还支持 Swagger 规范的第二个版本。我们建议您访问他们当前的参考文档：

[`springfox.github.io/springfox/docs/current`](http://springfox.github.io/springfox/docs/current)

他们还提供了一个迁移指南，从我们实现的 swagger 规范 1.2 迁移到 swagger 规范 2.0：

[`github.com/springfox/springfox/blob/master/docs/transitioning-to-v2.md`](https://github.com/springfox/springfox/blob/master/docs/transitioning-to-v2.md)

## 另请参阅

本节指导您使用 Swagger 的替代工具和规范：

### 不同的工具，不同的标准

我们已经提到还没有一个明确合法化一个工具胜过另一个的共同标准。因此，可能很好地承认除了 Swagger 之外的工具，因为在这个领域事情发展得非常快。在这里，您可以找到两篇很好的比较文章：

+   [`www.mikestowe.com/2014/07/raml-vs-swagger-vs-api-blueprint.php`](http://www.mikestowe.com/2014/07/raml-vs-swagger-vs-api-blueprint.php)

+   [`apiux.com/2013/04/09/rest-metadata-formats`](http://apiux.com/2013/04/09/rest-metadata-formats)

