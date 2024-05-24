# SpringData 教程（二）

> 原文：[`zh.annas-archive.org/md5/28DD94223A475A77126C29F9DB046845`](https://zh.annas-archive.org/md5/28DD94223A475A77126C29F9DB046845)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：向 JPA 存储库添加自定义功能

我们已经学会了如何使用 Spring Data JPA 管理实体并创建数据库查询。我们还学会了如何对查询结果进行排序和分页。然而，如果我们从纯粹的架构观点出发，我们会注意到所描述的解决方案并没有遵循**关注点分离**原则。事实上，我们的服务层包含了揭示存储库层内部工作原理的代码。

这是架构纯度和生产力之间的权衡。和往常一样，这个选择有一些后果。如果我们必须将我们的应用程序迁移到 Spring Data JPA 之外，我们必须对服务和存储库层进行更改。然而，我们有多少次听说过应用程序的存储库层必须发生如此根本性的变化？确切地说，这种情况非常罕见。因此，当回报很高时，这种风险是值得承担的。

本章描述的技术可以用来隐藏服务层的实现细节，但它们还有其他应用。在本章中，我们将涵盖以下主题：

+   如何向单个存储库添加自定义功能

+   如何向所有存储库添加自定义功能

我们将使用第三章*使用 Spring Data JPA 构建查询*中创建的 Querydsl 示例应用程序作为起点。让我们首先刷新一下记忆，并花一点时间审查我们示例应用程序的结构。我们的服务层由一个名为`RepositoryPersonService`的单个类组成，该类使用我们的名为`ContactRepository`的存储库接口。我们应用程序的分页和查询构建逻辑位于服务层。这种情况在以下图表中有所说明：

![向 JPA 存储库添加自定义功能](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprdt/img/9045_04_01.jpg)

# 向单个存储库添加自定义功能

向单个存储库添加自定义功能是一个有用的功能，当添加的功能只与单个实体相关时。在本节中，我们将探讨如何实现这一点，并将分页和搜索逻辑从服务层移动到存储库层。

如果我们想向单个存储库添加自定义功能，我们必须遵循以下步骤：

1.  创建声明自定义方法的自定义接口。

1.  实现创建的接口。

1.  创建存储库接口。

1.  创建使用自定义功能的服务实现。

## 创建自定义接口

我们的第一步是创建一个声明自定义存储库方法的接口。由于我们的目标是将分页和搜索逻辑移动到存储库层，我们必须向创建的接口添加以下方法：

| 方法 | 描述 |
| --- | --- |
| `List<Contact> findAllForPage(int pageIndex, int pageSize)` | 返回属于请求页面的所有联系人。 |
| `List<Contact> findContactsForPage(String searchTerm, int pageIndex, int pageSize)` | 返回与给定搜索词匹配并属于请求页面的所有联系人。 |

`PaginatingContactRepository`接口的源代码如下：

```java
public interface PaginatingContactRepository {

    public List<Contact> findAllForPage(int pageIndex, int pageSize);

    public List<Contact> findContactsForPage(String searchTerm, int pageIndex, int pageSize);
}
```

## 实现创建的接口

我们现在已经创建了一个指定自定义存储库方法的接口。我们的下一步是创建这个接口的实现，并将所有分页和查询构建代码从服务层移动到这个类中。

存储库基础设施会从与接口位于同一包中的位置寻找我们自定义接口的实现。它正在寻找一个类，其名称与实际存储库接口的简单名称附加一个后缀后创建的字符串匹配。默认情况下，此后缀的值为`Impl`。

### 注意

我们可以使用 Spring Data JPA 的`repositories`命名空间元素的`repository-impl-postfix`属性或`@EnableJpaRepositories`注解的`repositoryImplementationPostfix`属性来设置后缀。

目前我们对默认后缀非常满意。因此，实现我们自定义接口的类的名称必须是`ContactRepositoryImpl`。我们可以按照以下步骤实现这个类：

1.  编写一些必要的管道代码来配置`QueryDslJpaRepository<T, ID>`类，用于执行我们的查询。

1.  实现自定义接口中声明的方法。

### 配置存储库类

在这个阶段，我们将编写获取`QueryDslJpaRepository<Contact, Long>`类实例所需的代码。这个过程有以下步骤：

1.  使用`@PersistenceContext`注解获取对使用的实体管理器的引用。

1.  创建一个`init()`方法，并用`@PostConstruct`注解进行注释。这样可以确保在 bean 构造后调用该方法，并注入实体管理器引用。

1.  实现`init()`方法并创建一个新的`QueryDslJpaRepository<Contact, Long>`对象。

我们的实现源代码如下：

```java
public class ContactRepositoryImpl implements PaginatingContactRepository {

    @PersistenceContext
    private EntityManager entityManager;

    private QueryDslJpaRepository<Contact, Long> repository;

    //Add methods here

    @PostConstruct
    public void init() {
        JpaEntityInformation<Contact, Long> contactEntityInfo = new JpaMetamodelEntityInformation<Contact, Long>(Contact.class, entityManager.getMetamodel());
        repository = new QueryDslJpaRepository<Contact, Long>(contactEntityInfo, entityManager);
    }
}
```

### 实现自定义方法

目前创建的类无法编译，因为我们还没有实现自定义方法。在实现这些方法之前，我们必须将分页逻辑从服务层移动到`ContactRepositoryImpl`类。因此，这个过程有以下两个步骤：

1.  将分页相关的代码添加到我们的存储库实现中。

1.  实现自定义存储库方法。

首先，我们必须将分页相关的代码添加到我们的存储库中。这意味着我们必须将`sortByLastNameAndFirstNameAsc()`和`buildPageSpecification()`方法添加到`ContactRepositoryImpl`类中。这些方法的实现保持不变，如下所示：

```java
private Pageable buildPageSpecification(int pageIndex, int pageSize) {
  return new PageRequest(pageIndex, pageSize, sortByLastNameAndFirstNameAsc());
}

private Sort sortByLastNameAndFirstNameAsc() {
  return new Sort(new Sort.Order(Sort.Direction.ASC, "lastName"),
        new Sort.Order(Sort.Direction.ASC, "firstName")
  );
}
```

下一步是编写`findAllForPage()`方法的实现，该方法用于获取所请求页面上的联系人列表。这意味着我们必须：

1.  使用私有的`buildPageSpecification()`方法获取页面规范。

1.  通过调用存储库的`findAll()`方法并将页面规范作为参数传递，获取所请求页面的内容。

1.  返回联系人列表。

`findAllForPage()`方法的源代码如下：

```java
@Override
public List<Contact> findAllForPage(int pageIndex, int pageSize) {
    Pageable pageSpec = buildPageSpecification(pageIndex, pageSize);
    Page wanted = repository.findAll(pageSpec);

    return wanted.getContent();
}
```

我们的最后一个任务是为`findContactsForPage()`方法提供实现。这个方法的实现有以下步骤：

1.  通过调用`ContactPredicates`类的静态`firstOrLastNameStartsWith()`方法获取使用的搜索条件。

1.  通过调用私有的`buildPageSpecification()`方法获取页面规范。

1.  通过调用存储库的`findAll()`方法并提供必要的参数，获取所请求页面的内容。

1.  返回联系人列表。

`findContactsForPage()`方法的源代码如下：

```java
@Override
public List<Contact> findContactsForPage(String searchTerm, int pageIndex, int pageSize) {
    Predicate searchCondition = firstOrLastNameStartsWith(searchTerm);
    Pageable pageSpec = buildPageSpecification(pageIndex, pageSize);
    Page wanted = repository.findAll(searchCondition, pageSpec);

    return wanted.getContent();
}
```

## 创建存储库接口

我们现在已经实现了自定义功能，是时候将这个功能添加到我们的存储库中了。我们需要对现有的`ContactRepository`接口进行两处更改。具体如下：

1.  通过扩展`PaginatingContactRepository`接口，我们可以使自定义方法对我们存储库的用户可用。

1.  因为服务层不再需要 Querydsl 库的特定方法，我们可以从扩展接口列表中移除`QueryDslPredicateExecutor`接口。

我们的新存储库接口的源代码如下：

```java
public interface ContactRepository extends JpaRepository<Contact, Long>, PaginatingContactRepository {
}
```

## 创建服务实现

最后一步是修改`RepositoryContactService`类以使用自定义功能。这一步有以下两个阶段：

1.  移除`buildPageSpecification()`和`sortByLastNameAndFirstNameAsc()`方法。

1.  修改`findAllForPage()`和`search()`方法，将方法调用委托给我们的存储库。

修改后的方法的源代码如下：

```java
@Transactional(readOnly = true)
@Override
public List<Contact> findAllForPage(int pageIndex, int pageSize) {
    return repository.findAllForPage(pageIndex, pageSize);
}

@Transactional(readOnly = true)
@Override
public List<Contact> search(SearchDTO dto) {
    return repository.findContactsForPage(dto.getSearchTerm(), dto.getPageIndex(), dto.getPageSize());
}

```

## 我们刚刚做了什么？

我们刚刚将分页和搜索逻辑从`RepositoryContactService`类移动到`ContactRepositoryImpl`类，并消除了我们的服务层与 Querydsl 之间的依赖。我们行动的结果如下图所示：

![我们刚刚做了什么？](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprdt/img/9045_04_02.jpg)

# 向所有存储库添加自定义功能

有时我们必须向所有存储库添加自定义功能。在本节中，我们将学习如何做到这一点，并创建一个用于通过 ID 删除实体的自定义存储库方法。

我们可以通过以下步骤向所有存储库添加自定义功能：

1.  创建一个声明自定义方法的基础接口。

1.  实现创建的接口。

1.  创建一个存储库工厂 bean。

1.  配置 Spring Data JPA 以使用我们的存储库工厂 bean。

1.  创建一个存储库接口。

1.  实现使用自定义功能的服务类。

## 创建基础存储库接口

首先创建一个声明了实际存储库中可用方法的基础存储库接口。我们可以通过以下方式实现：

1.  创建一个接口，将受管实体的类型和其 ID 的类型作为类型参数。

1.  在我们的基础存储库接口中同时扩展`JpaRepository<T, ID>`和`QueryDslPredicateExecutor<T>`接口。

1.  用`@NoRepositoryBean`注解标注接口。这可以确保 Spring Data JPA 不会为该接口创建存储库实现。另一个解决方案是将该接口从存储库基础包中移出，但由于很难找到一个合适的逻辑位置，我们暂时不这样做。

1.  向该接口添加一个`T deleteById(ID id)`方法。该方法返回被删除的实体，并且如果没有找到给定 ID 的实体，则抛出`NotFoundException`。

让我们称这个接口为`BaseRepository`。其源代码如下：

```java
@NoRepositoryBean
public interface BaseRepository<T, ID extends Serializable> extends JpaRepository<T, ID>, QueryDslPredicateExecutor<T> {

    public T deleteById(ID id) throws NotFoundException;
}
```

## 实现基础存储库接口

接下来我们必须编写`BaseRepository<T, ID>`接口的实现。这个过程包括以下步骤：

1.  创建一个实现`BaseRepository<T, ID>`接口并扩展`QueryDslJpaRepository<T, ID>`类的类。这确保了该类可以访问`JpaRepository<T, ID>`接口提供的方法，并且可以使用 Querydsl。

1.  添加一个构造函数，用于简单地将所需的信息传递给超类。

1.  实现`deleteById()`方法。首先，该方法获取被删除的实体。如果找不到实体，该方法会抛出`NotFoundException`。否则，该方法会删除找到的实体并返回被删除的实体。

创建的`GenericBaseRepository`类的源代码如下：

```java
public class GenericBaseRepository<T, ID extends Serializable> extends QueryDslJpaRepository<T, ID> implements BaseRepository<T, ID> {

    public GenericBaseRepository(JpaEntityInformation<T, ID> entityMetadata, EntityManager entityManager) {
        super(entityMetadata, entityManager);
    }

    @Override
    public T deleteById(ID id) throws NotFoundException {
        T deleted = findOne(id);
        if (deleted == null) {
            throw new NotFoundException();
        }

        delete(deleted);
        return deleted;
    }
}
```

## 创建存储库工厂 bean

现在我们已经实现了自定义功能，我们必须确保在创建具体存储库实现时使用它。这意味着我们必须创建一个自定义存储库工厂 bean 来替换默认的存储库工厂 bean。我们的存储库工厂 bean 有一个单一目的：它将`GenericBaseRepository`作为`Repository`接口的所有扩展接口的实现。我们可以通过以下步骤创建一个自定义存储库工厂 bean：

1.  创建存储库工厂 bean 类的框架。

1.  创建一个存储库工厂类。

1.  创建一个用于构建新存储库工厂的构建方法。

### 创建存储库工厂 bean 类的框架

首先，我们必须创建存储库工厂 bean 类。这个类必须扩展 Spring Data JPA 的默认存储库工厂 bean`JpaRepositoryFactoryBean<R, T, I>`类。这个类有三个类型参数：存储库的类型，实体的类型和实体的 ID 的类型。类骨架的源代码如下：

```java
public class BaseRepositoryFactoryBean <R extends JpaRepository<T, I>, T, I extends Serializable> extends JpaRepositoryFactoryBean<R, T, I> {

}
```

### 创建存储库工厂内部类

第二步是创建实际的存储库工厂类。这个类的实现包括以下步骤：

1.  将`BaseRepositoryFactory`类作为`BaseRepositoryFactoryBean`类的受保护内部类添加进去。

1.  使创建的类扩展`JpaRepositoryFactory`类。

1.  重写`JpaRepositoryFactory`类的`getTargetRepository()`方法。这个方法负责创建实际的存储库实现。

1.  重写`JpaRepositoryFactory`类的`getRepositoryBaseClass()`方法，该方法简单地返回基本存储库实现的类。我们可以忽略作为参数给出的元数据，因为该信息由`JpaRepositoryFactory`用于决定它是否应该返回`SimpleJpaRepository`或`QueryDslJpaRepository`类。

存储库工厂内部类的源代码如下：

```java
protected static class BaseRepositoryFactory<T, I extends Serializable> extends JpaRepositoryFactory {

  private EntityManager entityManager;

    public BaseRepositoryFactory(EntityManager entityManager) {
      super(entityManager);
        this.entityManager = entityManager;
  }

    @Override
    protected Object getTargetRepository(RepositoryMetadata metadata) {
      return new GenericBaseRepository<T, I>((JpaEntityInformation<T,I>) getEntityInformation(metadata.getDomainType()), entityManager);
  }

    @Override
    protected Class<?> getRepositoryBaseClass(RepositoryMetadata metadata) {
        return GenericBaseRepository.class;
  }
}
```

### 为存储库工厂创建构建方法

我们可以通过重写`BaseRepositoryFactoryBean`类中的`createRepositoryFactory()`方法来创建我们自定义存储库工厂类的新实例。这个方法简单地创建了`BaseRepositoryFactory`类的一个新实例，并将实体管理器引用作为构造函数参数传递。重写方法的源代码如下：

```java
@Override
protected RepositoryFactorySupport createRepositoryFactory(EntityManager entityManager) {
    return new BaseRepositoryFactory(entityManager);
}
```

## 配置 Spring Data JPA

接下来，我们必须配置 Spring Data JPA 在创建存储库接口的具体实现时使用自定义存储库工厂 bean。我们可以通过使用`@EnableJpaRepositories`注解的`repositoryFactoryBeanClass`属性来实现这一点。换句话说，我们必须将以下注解添加到`ApplicationContext`类中：

```java
@EnableJpaRepositories(basePackages = {"com.packtpub.springdata.jpa.repository"}, repositoryFactoryBeanClass = BaseRepositoryFactoryBean.class)
```

### 注意

如果我们在使用 XML 配置我们的应用程序，我们可以使用 Spring Data JPA 的`repositories`命名空间元素的`factory-class`属性。

## 创建存储库接口

现在我们已经使自定义功能对所有存储库可用。现在我们必须为`Contact`实体创建一个存储库接口。我们可以按照以下步骤来做到这一点：

1.  从扩展接口的列表中移除`JpaRepository`和`QueryDslPredicateExecutor`接口。

1.  扩展`BaseRepository<T, ID>`接口。

`ContactRepository`接口的源代码如下：

```java
public interface ContactRepository extends BaseRepository<Contact, Long> {
}
```

## 实现服务层

因为`RepositoryContactService`类的`delete()`方法的旧实现包含与我们的新`deleteById()`存储库方法相同的功能，所以我们必须将`RepositoryContactService`类的`delete()`方法更改为将方法调用委托给新的存储库方法。我们的新`delete()`方法的源代码如下：

```java
@Transactional(rollbackFor = NotFoundException.class)
@Override
public Contact deleteById(Long id) throws NotFoundException {
    return repository.deleteById(id);
}
```

## 我们刚刚做了什么？

我们实现了一个通用的删除方法，该方法自动对我们应用程序的所有存储库可用。这消除了将特定于实体的删除逻辑添加到服务层的需要，并减少了代码重复。我们还创建了一个自定义存储库工厂，为我们的存储库接口提供`GenericBaseRepository`作为实现。我们的工作结果如下图所示：

![我们刚刚做了什么？](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprdt/img/9045_04_03.jpg)

# 总结

在本章中，我们已经学会了如何向单个存储库或所有存储库添加自定义功能。然而，本章还有另一个非常重要的教训。我们注意到，向存储库添加自定义功能会增加应用程序的复杂性，并迫使我们编写样板代码，这可能会让实现和维护都变得繁琐。这就是为什么我们应该只在绝对必要的时候使用本章描述的技术。

这是最后一章，描述了 Spring Data JPA 的用法。在下一章中，我们将学习如何在运行类 Unix 操作系统的计算机上安装 Redis，并设置一个使用 Redis 作为数据存储的 Web 应用项目。


# 第五章：使用 Spring Data Redis 入门

在 Spring Data Redis 项目诞生之前，与 Redis 通信的常规方式是使用可以与关系数据库的 JDBC 驱动程序进行比较的客户端库。不同之处在于这些客户端没有实现使得从一个连接器切换到另一个连接器变得困难的标准 API。显然，百万美元的问题是，Spring Data Redis 如何使我们的生活更轻松？

Spring Data Redis 将不同客户端库的 API 隐藏在一个干净且易于使用的单一 API 后面。理论上，这确保我们可以在不对应用程序进行任何更改的情况下更改所使用的 Redis 连接器。尽管这确实是一个有用的功能，如果我们必须更改所使用的连接器，但如果仅因为这个功能就开始使用 Spring Data Redis，这将是天真的。我们必须记住，我们很可能会在应用程序的生命周期中坚持使用一个 Redis 连接器。

然而，我们必须记住，应用程序基本上是通过将不同组件组合在一起构建的。Spring Data Redis 与 Spring 框架提供了无缝集成，后者是用于创建企业应用程序的流行工具。这对于任何使用 Redis 的 Spring 应用程序的开发人员来说自然是一个巨大的好处。

### 注意

有关 Spring Data Redis 及其功能的更多信息，请访问[`www.springsource.org/spring-data/redis/`](http://www.springsource.org/spring-data/redis/)。

本章将指导我们通过初始配置阶段，并帮助我们设置一个使用 Spring Data Redis 的 Web 应用程序项目。在本章中，我们将涵盖以下主题：

+   如何在运行类 Unix 操作系统的计算机上安装 Redis

+   如何使用 Maven 获取 Spring Data Redis 所需的依赖

+   如何通过使用编程配置来配置我们应用程序的应用程序上下文

+   如何在应用程序上下文配置类中配置我们的 Redis 连接

# 安装 Redis

Spring Data Redis 要求使用 Redis 2.0 或更高版本，并建议使用 Redis 2.2。但是，即使可能使用更新的 Redis 版本，新功能可能尚不受支持。本书假定我们使用的是 Redis 版本 2.6.0-rc6。

目前 Redis 并不正式支持 Windows，但有一些非官方的端口可用。如果要将 Redis 安装到 Windows 计算机上，请下载其中一个非官方源包，并按照其安装说明进行操作。非官方 Windows 端口的下载链接可在[`redis.io/download`](http://redis.io/download)上找到。

### 注意

Redis 的唯一依赖是一个可用的 GCC 编译器和 libc。安装这些依赖的最佳方法是使用所用 Linux 发行版的软件包管理器。如果在使用 OS X 操作系统的计算机上编译 Redis，则应确保安装了 Xcode 及其命令行工具。

我们可以通过以下步骤将 Redis 安装到运行类 Unix 操作系统的计算机上：

1.  下载 Redis 源包。我们使用一个称为`wget`的命令行实用程序来检索源包。

1.  解压源包。

1.  编译 Redis。

我们可以通过在命令行上运行以下命令来完成安装过程：

```java
wget http://redis.googlecode.com/files/redis-2.6.0-rc6.tar.gz
tar xzf redis-2.6.0-rc6.tar.gz
cd redis-2.6.0-rc6
make

```

### 注意

目前，源包托管在 Google Code 上。如果包被移动到不同的主机上，或者安装了不同的 Redis 版本，这些命令必须相应地进行修改。

编译成功后，我们可以通过在命令提示符下运行以下命令来启动 Redis 服务器：

```java
./src/redis-server

```

如果我们的安装成功，我们应该看到如下截图所示的输出：

![安装 Redis](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprdt/img/9045_05_01.jpg)

### 注意

官方 Redis 主页有全面的文档，提供有关 Redis 的使用和配置的更多信息。此文档可在[`redis.io/documentation`](http://redis.io/documentation)上找到。

# 获取所需的依赖项

获取 Spring Data Redis 所需的依赖项相当容易。唯一需要的依赖项是 Spring Data Redis，我们可以通过将以下依赖声明添加到`pom.xml`文件中来获取它：

```java
<dependency>
  <groupId>org.springframework.data</groupId>
  <artifactId>spring-data-redis</artifactId>
  <version>1.0.1.RELEASE</version>
</dependency>
```

# 配置 Spring 应用程序上下文

我们将使用 Java 配置来配置我们应用程序的应用程序上下文。我们应用程序上下文配置类的名称是`ApplicationContext`，其实现在以下几点中进行了解释：

1.  `@Configuration`注解用于将类标识为应用程序上下文配置类。

1.  `@ComponentScan`注解用于配置我们控制器的基本包。

1.  `@EnableWebMvc`注解用于启用 Spring MVC。

1.  配置参数的值是从一个属性文件中获取的，该文件是通过使用`@PropertySource`注解导入的。`Environment`接口用于访问存储在该文件中的属性值。

1.  `redisConnectionFactory()`方法用于配置 Redis 连接工厂 bean。此方法的实现取决于所使用的 Redis 连接器。

我们应用程序上下文配置骨架类的源代码如下：

```java
@Configuration
@ComponentScan(basePackages = {
        "com.packtpub.springdata.redis.controller"
})
@EnableWebMvc
@PropertySource("classpath:application.properties")
public class ApplicationContext extends WebMvcConfigurerAdapter {

    @Resource
    private Environment env;

    @Bean
    public RedisConnectionFactory redisConnectionFactory() {
      //Add implementation
    }

    //Add other configuration here   
}
```

`application.properties`文件的内容如下：

```java
redis.host = localhost
redis.port = 6379
```

# 配置 Redis 连接

Spring Data Redis 支持四种不同的连接器，可用于与 Redis 服务器交互。这些连接器在以下表格中描述：

| 连接器 | 描述 |
| --- | --- |
| Jedis | Jedis 是与 Redis 2.0.0 命令完全兼容的 Redis 连接器。该项目托管在 GitHub 上，有关更多信息，请访问[`github.com/xetorthio/jedis`](https://github.com/xetorthio/jedis)。 |
| JRedis | JRedis 是一个 Redis 连接器，尚未正式支持 Redis 2.x。但是，可以使用此库的分支版本添加对 Redis 2.x 的支持。JRedis 库的分支版本托管在 GitHub 上，其主页位于[`github.com/anthonylauzon/jredis`](https://github.com/anthonylauzon/jredis)。 |
| RJC | RJC 是与 Redis 2.X 兼容的 Redis 连接器。有关 RJC 连接器的更多信息，请访问[`github.com/e-mzungu/rjc`](https://github.com/e-mzungu/rjc)。 |
| SRP | SRP 是支持 Redis 2.6 命令的 Redis 连接器。该项目的主页位于[`github.com/spullara/redis-protocol`](https://github.com/spullara/redis-protocol)。 |

不幸的是，目前一些支持的连接器处于早期开发阶段，它们不支持 Redis 的所有可用功能。如果底层连接器不支持执行的操作，则会抛出异常`UnsupportedOperationException`。

此外，我们可以使用的 Spring Data Redis 的配置选项取决于所使用的连接器。以下表格描述了支持的 Redis 连接器之间的差异（X 表示支持配置选项，-表示不支持）：

| 连接器 | 密码 | 连接池 |
| --- | --- | --- |
| Jedis | X | X |
| JRedis | X | X |
| RJC | X | X |
| SRP | - | - |

Jedis 是 Spring Data Redis 的默认连接器，目前应该是我们的首选，因为它是支持的连接器中最成熟的，并且正在积极开发。但是，我们将查看每个支持的连接器的配置过程，因为情况可能会在将来发生变化，如果发生变化，我们也应该知道我们还有其他选择。

每个支持的 Redis 连接器的配置始终有以下两个步骤：

1.  配置正确的 Maven 依赖项。

1.  在`ApplicationContext`类的`redisConnectionFactory()`方法中配置正确的 Redis 连接工厂 bean。

## 配置 Jedis 连接器

因为 Jedis 是 Spring Data Redis 的默认连接器，我们不必对我们的`pom.xml`文件进行任何更改。我们唯一需要做的是在应用程序上下文配置中添加 Redis 连接工厂 bean。Jedis 连接器的正确 Redis 连接工厂 bean 类是`JedisConnectionFactory`类，它具有以下配置属性：

| 属性 | 描述 |
| --- | --- |
| `dataBase` | 使用的数据库的索引。 |
| `hostName` | 使用的 Redis 服务器的主机名。 |
| `password` | 用于与 Redis 服务器进行身份验证的密码。 |
| `poolConfig` | 通过使用`redis.clients.jedis.JedisPoolConf`类给出的连接池配置。 |
| `port` | 使用的 Redis 服务器的端口。 |
| `shardInfo` | 配置`JedisConnectionFactory`对象的替代方法。通过使用`redis.clients.jedis.JedisShardInfo`类给出配置。此方法优先于其他冲突的配置属性。 |
| `timeout` | 连接超时。 |
| `usePool` | 描述是否使用连接池的`boolean`值。 |

我们将在`ApplicationContext`类的`redisConnectionFactory()`方法中配置 Redis 连接工厂 bean。我们的实现包括以下步骤：

1.  创建一个新的`JedisConnectionFactory`对象。

1.  配置 Redis 连接工厂 bean。

1.  返回创建的对象。

实现的`redisConnectionFactory()`方法的源代码如下：

```java
@Bean
public RedisConnectionFactory redisConnectionFactory() {
  JedisConnectionFactory cf = new JedisConnectionFactory();

  cf.setHostName(env.getRequiredProperty("redis.host"));
  cf.setPort(Integer.parseInt(env.getRequiredProperty("redis.port")));

  return cf;
}
```

## 配置 JRedis 连接器

第一步是配置 JRedis 的 Maven 依赖项。我们可以通过以下步骤配置所需的依赖项：

1.  从我们的构建中排除传递的 Jedis 依赖项。

1.  将分叉的 JRedis 连接器作为依赖项添加。

在我们按照描述的步骤进行之后，我们应该在`pom.xml`文件中有以下依赖声明：

```java
<dependency>
    <groupId>org.springframework.data</groupId>
    <artifactId>spring-data-redis</artifactId>
    <version>1.0.1.RELEASE</version>
    <exclusions>
        <exclusion>
            <groupId>redis.clients</groupId>
            <artifactId>jedis</artifactId>
        </exclusion>
    </exclusions>
</dependency>
<dependency>
    <groupId>org.jredis</groupId>
    <artifactId>jredis-anthonylauzon</artifactId>
    <version>03122010</version>
</dependency>
```

第二步是配置使用的 Redis 连接工厂 bean。因为我们想要使用 JRedis 连接器，我们必须使用`JRedisConnectionFactory`类。该类的配置属性在下表中描述：

| 属性 | 描述 |
| --- | --- |
| `dataBase` | 使用的数据库的索引。 |
| `hostName` | 使用的 Redis 服务器的主机名。 |
| `password` | 用于与 Redis 服务器进行身份验证的密码。 |
| `poolSize` | 连接池的大小。 |
| `port` | 使用的 Redis 服务器的端口。 |
| `usePool` | 描述是否使用连接池的`boolean`值。 |

为了配置 Redis 连接器，我们必须将`redisConnectionFactory()`方法的实现添加到`ApplicationContext`类中。我们可以通过以下步骤来实现：

1.  创建一个新的`JRedisConnectionFactory`对象。

1.  配置 Redis 连接工厂 bean。

1.  返回创建的对象。

我们的 Redis 连接工厂 bean 配置的源代码如下：

```java
@Bean
public RedisConnectionFactory redisConnectionFactory() {
    JredisConnectionFactory cf = new JredisConnectionFactory();

    cf.setHostName(env.getRequiredProperty("redis.host"));   
    cf.setPort(Integer.parseInt(env.getRequiredProperty("redis.port")));

    return cf;
}
```

## 配置 RJC 连接器

首先，我们必须配置所需的 Maven 依赖项。此过程包括以下步骤：

1.  从我们的构建中排除传递的 Jedis 依赖项。

1.  将 RJC 连接器作为依赖项添加。

必须添加到我们的`pom.xml`文件的依赖声明如下：

```java
<dependency>
    <groupId>org.springframework.data</groupId>
    <artifactId>spring-data-redis</artifactId>
    <version>1.0.1.RELEASE</version>
    <exclusions>
        <exclusion>
            <groupId>redis.clients</groupId>
            <artifactId>jedis</artifactId>
        </exclusion>
    </exclusions>
</dependency>
<dependency>
    <groupId>org.idevlab</groupId>
    <artifactId>rjc</artifactId>
    <version>0.7</version>
</dependency>
```

最后一步是将使用的 Redis 连接工厂 bean 的配置添加到我们的应用程序上下文配置类中。因为我们使用的是 RJC 连接器，正确的 Redis 连接工厂类是`RjcConnectionFactory`。该类具有以下配置属性：

| 属性 | 描述 |
| --- | --- |
| `dataBase` | 使用的数据库的索引。 |
| `hostName` | 使用的 Redis 服务器的主机名。 |
| `password` | 用于与 Redis 服务器进行身份验证的密码。 |
| `port` | 所使用的 Redis 服务器的端口。 |
| `timeout` | 连接超时的值。 |
| `usePool` | 描述是否使用连接池的`boolean`值。 |

我们的`redisConnectionFactory()`方法的实现包括以下步骤：

1.  创建一个新的`RjcConnectionFactory`对象。

1.  配置 Redis 连接工厂 bean。

1.  返回创建的对象。

我们的 Redis 连接工厂 bean 配置的源代码如下：

```java
@Bean
public RedisConnectionFactory redisConnectionFactory() {
    RjcConnectionFactory cf = new RjcConnectionFactory();

    cf.setHostName(env.getRequiredProperty("redis.host"));    
    cf.setPort(Integer.parseInt(env.getRequiredProperty("redis.port")));

    return cf;
}
```

## 配置 SRP 连接器

第一步是配置 SRP Redis 连接器的 Maven 依赖项。我们可以通过以下步骤配置所需的依赖项：

1.  从我们的构建中排除传递的 Jedis 依赖项。

1.  将 SRP 连接器添加为依赖项。

这导致以下依赖声明：

```java
<dependency>
    <groupId>org.springframework.data</groupId>
    <artifactId>spring-data-redis</artifactId>
    <version>1.0.1.RELEASE</version>
    <exclusions>
        <exclusion>
            <groupId>redis.clients</groupId>
            <artifactId>jedis</artifactId>
        </exclusion>
    </exclusions>
</dependency>
<dependency>
    <groupId>com.github.spullara.redis</groupId>
    <artifactId>client</artifactId>
    <version>0.2</version>
</dependency>
```

第二步是配置 Redis 连接工厂 bean。SRP 连接器的正确连接工厂 bean 类是`SrpConnectionFactory`，它具有以下配置属性：

| 属性 | 描述 |
| --- | --- |
| `hostName` | 所使用的 Redis 服务器的主机名。 |
| `port` | 所使用的 Redis 服务器的端口。 |

我们可以通过编写一个实现`redisConnectionFactory()`方法的实现来配置 SRP 连接器。我们的实现有以下步骤：

1.  创建一个新的`SrpConnectionFactory`对象。

1.  配置 Redis 连接工厂 bean。

1.  返回创建的对象。

我们的 Redis 连接工厂 bean 配置的源代码如下：

```java
@Bean
public RedisConnectionFactory redisConnectionFactory() {
    SrpConnectionFactory cf = new SrpConnectionFactory();

    cf.setHostName(env.getRequiredProperty("redis.host"));
    cf.setPort(Integer.parseInt(env.getRequiredProperty("redis.port")));

    return cf;
}
```

# 摘要

在本章中，我们已经学到：

+   Redis 没有复杂的依赖关系，很容易将 Redis 安装到运行类 Unix 操作系统的计算机上

+   一些支持的连接器尚不支持 Redis 的所有功能

+   在配置 Redis 连接时，我们可以使用的配置选项取决于所使用的连接器

+   当我们使用 Spring Data Redis 编写应用程序时，应该使用 Jedis 连接器

我们现在已经学会了如何设置使用 Spring Data Redis 的 Web 应用程序项目。在下一章中，我们将编写一些代码，并使用 Spring Data Redis 实现联系人管理应用程序。


# 第六章：使用 Spring Data Redis 构建应用程序

我们已经学会了如何设置我们的项目并配置所使用的 Redis 连接。现在是扩展我们的知识并学习如何在应用程序中使用 Spring Data Redis 的时候了。我们还将证明可以将 Redis 用作 Web 应用程序的数据存储。

### 注意

*Salvatore Sanfilippo*是 Redis 项目的贡献者，他写了一篇精彩的博客文章，描述了我们如何在应用程序中使用 Redis。这篇博客文章可以在[`antirez.com/post/take-advantage-of-redis-adding-it-to-your-stack.html`](http://antirez.com/post/take-advantage-of-redis-adding-it-to-your-stack.html)找到。

在本章中，我们将涵盖：

+   Redis 数据模型的基本设计原则

+   Spring Data Redis 的关键组件

+   我们如何可以实现 CRUD 应用程序

+   我们如何可以使用发布/订阅消息模式

+   我们如何可以使用 Spring Data Redis 作为 Spring Framework 3.1 提供的缓存抽象的实现

# 设计 Redis 数据模型

设计 Redis 数据模型的最重要规则是：Redis 不支持特设查询，也不支持关系数据库中的关系。因此，设计 Redis 数据模型与设计关系数据库的数据模型完全不同。Redis 数据模型设计的基本指导原则如下：

+   我们不仅要对存储在数据模型中的信息进行建模，还要考虑如何从中搜索信息。这经常导致我们不得不复制数据以满足给定的要求。不要害怕这样做。

+   我们不应该专注于规范化我们的数据模型。相反，我们应该将需要处理的数据作为一个单元合并成一个聚合。

+   由于 Redis 不支持关系，我们必须使用支持的数据结构来设计和实现这些关系。这意味着当这些关系发生变化时，我们必须手动维护这些关系。因为这可能需要大量的工作和代码，所以简单地复制信息而不使用关系可能是明智的。

+   花一点时间验证我们是否使用了正确的工具总是明智的。

### 提示

*NoSQL Distilled*，由*Martin Fowler*编写，解释了不同的 NoSQL 数据库及其用例，可以在[`martinfowler.com/books/nosql.html`](http://martinfowler.com/books/nosql.html)找到。

正如我们在第一章中学到的，*入门*，Redis 支持多种数据结构。然而，一个问题仍然没有得到解答：我们应该使用哪种数据结构来存储我们的数据？这个问题在下表中得到了解答：

| 数据类型 | 描述 |
| --- | --- |
| 字符串 | 字符串是存储已转换为文本形式的信息的好选择。例如，如果我们想存储 HTML、JSON 或 XML，字符串应该是我们的选择。 |
| 列表 | 如果我们只会在开始或结束附近访问它，列表是一个不错的选择。这意味着我们应该用它来表示队列或堆栈。 |
| 集合 | 如果我们需要获取集合的大小或检查某个项目是否属于它，我们应该使用集合。此外，如果我们想表示关系，集合是一个很好的选择（例如，“约翰的朋友是谁？”）。 |
| 有序集合 | 当项目的排序对我们很重要时，应该在与集合相同的情况下使用有序集合。 |
| 哈希 | 哈希是表示复杂对象的完美数据结构。 |

# 关键组件

Spring Data Redis 提供了一些组件，它们是使用它的每个应用程序的基石。本节简要介绍了我们稍后将用来实现示例应用程序的组件。

## 原子计数器

原子计数器对于 Redis 来说就像序列对于关系数据库一样。原子计数器保证客户端接收的值是唯一的。这使得这些计数器成为在 Redis 中创建唯一 ID 的完美工具。目前，Spring Data Redis 提供了两种原子计数器：`RedisAtomicInteger`和`RedisAtomicLong`。这些类为整数和长整数提供了原子计数器操作。

## RedisTemplate

`RedisTemplate<K,V>`类是 Spring Data Redis 的核心组件。它提供了我们可以用来与 Redis 实例通信的方法。在实例化时，这个类要求给定两个类型参数：用于 Redis 键的类型和 Redis 值的类型。

### 操作

`RedisTemplate`类提供了两种我们可以用来存储、获取和删除 Redis 实例中的数据的操作：

1.  需要每次操作都提供键和值的操作。当我们必须使用键和值执行单个操作时，这些操作非常方便。

1.  绑定到只给定一次的特定键的操作。当我们必须使用相同的键执行多个操作时，应该使用这种方法。

需要每次操作都提供键和值的方法在以下列表中描述：

+   `HashOperations<K,HK,HV> opsForHash()`: 此方法返回对哈希执行的操作

+   `ListOperations<K,V> opsForList()`: 此方法返回对列表执行的操作

+   `SetOperations<K,V> opsForSet()`: 此方法返回对集合执行的操作

+   `ValueOperations<K,V> opsForValue()`: 此方法返回对简单值执行的操作

+   `ZSetOperations<K,HK,HV> opsForZSet()`: 此方法返回对有序集合执行的操作

`RedisTemplate`类的方法允许我们使用相同的键执行多个操作，在以下列表中描述：

+   `BoundHashOperarations<K,HK,HV> boundHashOps(K key)`: 此方法返回绑定到给定键的哈希操作

+   `BoundListOperations<K,V> boundListOps(K key)`: 此方法返回绑定到给定键的列表操作

+   `BoundSetOperations<K,V> boundSetOps(K key)`: 此方法返回绑定到给定键的集合操作

+   `BoundValueOperations<K,V> boundValueOps(K key)`: 此方法返回绑定到给定键的简单值的操作

+   `BoundZSetOperations<K,V> boundZSetOps(K key)`: 此方法返回绑定到给定键的有序集合的操作

当我们开始构建示例应用程序时，这些操作之间的差异就变得清晰起来了。

### 序列化器

因为数据以字节形式存储在 Redis 中，我们需要一种方法将数据转换为字节，反之亦然。Spring Data Redis 提供了一个名为`RedisSerializer<T>`的接口，用于序列化过程。这个接口有一个类型参数，描述了序列化对象的类型。Spring Data Redis 提供了这个接口的几种实现。这些实现在下表中描述：

| 序列化器 | 描述 |
| --- | --- |
| `GenericToStringSerializer<T>` | 将字符串序列化为字节，反之亦然。使用 Spring 的`ConversionService`将对象转换为字符串，反之亦然。 |
| `JacksonJsonRedisSerializer<T>` | 将对象转换为 JSON，反之亦然。 |
| `JdkSerializationRedisSerializer` | 为对象提供基于 Java 的序列化。 |
| `OxmSerializer` | 使用 Spring Framework 3 的对象/XML 映射支持。 |
| `StringRedisSerializer` | 将字符串转换为字节，反之亦然。 |

我们可以使用描述的序列化器来自定义`RedisTemplate`类的序列化过程。`RedisTemplate`类提供了灵活的配置选项，可用于设置用于序列化值键、值、哈希键、哈希值和字符串值的序列化器。

`RedisTemplate`类的默认序列化器是`JdkSerializationRedisSerializer`。但是，字符串序列化器是一个例外。`StringRedisSerializer`是默认用于序列化字符串值的序列化器。

# 实现 CRUD 应用程序

本节描述了实现用于管理联系信息的 CRUD 应用程序的两种不同方式。首先，我们将学习如何使用`RedisTemplate`类的默认序列化器来实现 CRUD 应用程序。其次，我们将学习如何使用值序列化器并实现以 JSON 格式存储数据的 CRUD 应用程序。

这两个应用程序还将共享相同的领域模型。这个领域模型包括两个类：`Contact`和`Address`。这些类的信息内容已经在第二章中描述，*使用 Spring Data JPA 入门*。但是，我们对这些类进行了以下更改：

+   我们从中删除了 JPA 特定的注解

+   我们在我们的 Web 层中使用这些类作为表单对象，它们不再具有除了 getter 和 setter 之外的任何其他方法

领域模型不是这些示例共享的唯一内容。它们还共享了声明`Contact`类的服务方法的接口。`ContactService`接口的源代码如下：

```java
public interface ContactService {
    public Contact add(Contact added);
    public Contact deleteById(Long id) throws NotFoundException;
    public List<Contact> findAll();
    public Contact findById(Long id) throws NotFoundException;
    public Contact update(Contact updated) throws NotFoundException;
}
```

这两个应用程序将使用在第五章中描述的 Jedis 连接器与所使用的 Redis 实例进行通信，*使用 Spring Data Redis 入门*。

无论用户的方法如何，我们都可以通过以下步骤实现使用 Spring Data Redis 的 CRUD 应用程序：

1.  配置应用程序上下文。

1.  实现 CRUD 功能。

让我们开始并找出如何实现联系信息的 CRUD 功能。

## 使用默认序列化器

本小节描述了如何使用`RedisTemplate`类的默认序列化器来实现 CRUD 应用程序。这意味着`StringRedisSerializer`用于序列化字符串值，而`JdkSerializationRedisSerializer`用于序列化其他对象。

### 配置应用程序上下文

我们可以通过对`ApplicationContext`类进行以下更改来配置我们应用程序的应用程序上下文：

1.  配置 Redis 模板 bean。

1.  配置 Redis 原子长整型 bean。

#### 配置 Redis 模板 bean

我们可以通过向`ApplicationContext`类添加一个`redisTemplate()`方法并使用`@Bean`注解对该方法进行注解来配置 Redis 模板 bean。我们可以通过以下步骤实现此方法：

1.  创建一个新的`RedisTemplate`对象。

1.  将使用的连接工厂设置为创建的`RedisTemplate`对象。

1.  返回创建的对象。

`redisTemplate()`方法的源代码如下：

```java
@Bean
public RedisTemplate redisTemplate() {
  RedisTemplate<String, String> redis = new RedisTemplate<String, String>();

  redis.setConnectionFactory(redisConnectionFactory());

  return redis;
}
```

#### 配置 Redis 原子长整型 bean

我们通过向`ApplicationContext`类添加一个名为`redisAtomicLong()`的方法，并使用`@Bean`注解对该方法进行注解来开始配置 Redis 原子长整型 bean。我们的下一个任务是通过以下步骤实现此方法：

1.  创建一个新的`RedisAtomicLong`对象。将所使用的 Redis 计数器的名称和 Redis 连接工厂作为构造函数参数传递。

1.  返回创建的对象。

`redisAtomicLong()`方法的源代码如下：

```java
@Bean
public RedisAtomicLong redisAtomicLong() {
  return new RedisAtomicLong("contact", redisConnectionFactory());
}
```

### 注意

如果我们需要为不同类的实例创建 ID，我们可以使用相同的 Redis 计数器。因此，我们只需配置一个 Redis 原子长整型 bean。

### CRUD

在我们可以开始为`Contact`类实现 CRUD 函数之前，我们必须先讨论一下我们应用程序的 Redis 数据模型。我们使用两种不同的数据类型来将联系人信息存储到 Redis 中。单个联系人的信息存储在哈希中，因为我们知道，哈希是存储复杂对象信息的很好的结构。此外，我们将每个联系人的密钥存储在一个集合中，因为集合在检查联系人是否存在时为我们提供了快速的能力。当我们从 Redis 中获取所有联系人的列表时，我们也使用这个集合。

我们的下一步是实现`ContactService`接口，该接口声明了联系人的 CRUD 操作。让我们首先创建一个虚拟服务实现，然后稍后添加实际的 CRUD 方法。该类的实现包括以下步骤：

1.  实现`ContactService`接口。

1.  用`@Service`注解创建的类。

1.  将所需的依赖项添加为创建的类的私有成员，并使用`@Resource`注解对这些成员进行注解。我们需要引用`RedisTemplate`和`RedisAtomicLong`对象。

我们虚拟实现的源代码如下：

```java
@Service
public class RedisContactService implements ContactService {

    @Resource
    private RedisAtomicLong contactIdCounter;

    @Resource
    private RedisTemplate<String, String> redisTemplate;

    //Add methods here.
}
```

下一步是实现`ContactService`接口声明的方法所使用的通用方法。这些私有方法在下表中描述：

| 方法 | 描述 |
| --- | --- |
| `String buildKey(Long contactId)` | 返回联系人的密钥。 |
| `Contact buildContact(String key)` | 获取联系人的信息并返回找到的联系人。 |
| `Contact buildContact(Long id)` | 获取联系人的信息并返回找到的联系人。 |
| `boolean contactDoesNotExist(Long id)` | 如果找到具有给定 ID 的联系人，则返回 false，否则返回 true。 |
| `String persist(Contact persisted)` | 保存联系人信息并返回联系人的密钥。 |

首先，我们必须实现用于构建联系人密钥的方法。我们的`buildKey()`方法的实现非常简单。我们通过将作为参数给定的联系人 ID 附加到字符串`contact`并返回结果字符串来构建密钥。`buildKey()`方法的源代码如下：

```java
private String buildKey(Long contactId) {
    return "contact" + contactId;
}
```

其次，我们必须实现使用联系人密钥获取联系人信息的方法。我们可以通过以下步骤实现`buildContact(String key)`方法：

1.  创建一个新的`Contact`对象。

1.  从哈希中获取联系人的信息。

### 注意

我们使用绑定的哈希操作，因为这样我们只需要提供一次密钥。

1.  返回创建的对象。

实现方法的源代码如下：

```java
private Contact buildContact(String key) {
    Contact contact = new Contact();

    BoundHashops ops = redisTemplate.boundHashOps(key);

    contact.setId((Long) ops.get("id"));
    contact.setEmailAddress((String) ops.get("emailAddress"));
    contact.setFirstName((String) ops.get("firstName"));
    contact.setLastName((String) ops.get("lastName"));
    contact.setPhoneNumber((String) ops.get("phoneNumber"));

    Address address = new Address();
    address.setStreetAddress((String) ops.get("streetAddress"));
    address.setPostCode((String) ops.get("postCode"));
    address.setPostOffice((String) ops.get("postOffice"));
    address.setState((String) ops.get("state"));
    address.setCountry((String) ops.get("country"));
    contact.setAddress(address);

    return contact;
}
```

第三，我们必须实现使用联系人 ID 获取联系人信息的方法。我们的`buildContact(Long id)`方法相当简单，包括以下步骤：

1.  构建联系人的密钥。

1.  使用创建的密钥获取联系人。

1.  返回找到的联系人。

该方法的源代码如下：

```java
private Contact buildContact(Long id) {
    String key = buildKey(id);
    return buildContact(key);
}
```

第四，我们必须实现用于验证所讨论的联系人是否存在的方法。我们的`contactDoesNotExist()`方法的实现包括以下步骤：

1.  创建联系人的密钥。

1.  通过调用`SetOperations`类的`isMember()`方法，并传递集合的名称和密钥作为参数，检查密钥是否在联系人集合中找到。

### 注意

我们使用`setOperations`因为我们只执行一个命令。

1.  反转`isMember()`方法的返回值并返回反转后的值。

该方法的源代码如下：

```java
private boolean contactDoesNotExist(Long id) {
    String key = buildKey(id);
    return !redisTemplate.opsForSet().isMember("contacts", key);
}
```

第五，我们必须实现保存单个联系人信息的方法。我们的`persist()`方法的实现包括以下步骤：

1.  如果持久化的`Contact`对象没有 ID，则调用`RedisAtomicLong`类的`incrementAndGet()`方法创建一个 ID，并将接收到的`Long`对象设置为联系人 ID。

1.  为持久化的联系人构建一个键。

1.  将联系人保存在哈希中。

1.  返回持久化的联系人。

`persist()`方法的源代码如下：

```java
private String persist(Contact persisted) {
    Long id = persisted.getId();
    if (id == null) {
        id = contactIdCounter.incrementAndGet();
        persisted.setId(id);
    }

    String contactKey = buildKey(id);

    BoundHashops ops = redisTemplate.boundHashOps(contactKey);

    ops.put("id", persisted.getId());
    ops.put("emailAddress", persisted.getEmailAddress());
    ops.put("firstName", persisted.getFirstName());
    ops.put("lastName", persisted.getLastName());
    ops.put("phoneNumber", persisted.getPhoneNumber());

    Address address = persisted.getAddress();

    ops.put("streetAddress", address.getStreetAddress());
    ops.put("postCode", address.getPostCode());
    ops.put("postOffice", address.getPostOffice());
    ops.put("state", address.getState());
    ops.put("country", address.getCountry());

    return contactKey;
}
```

我们现在已经实现了`RedisContactService`类的常用方法。让我们继续找出如何为联系信息提供 CRUD 操作。

#### 创建

我们可以通过以下步骤创建一个新的联系人：

1.  将添加的联系人保存到哈希中。

1.  将联系人的键添加到我们的联系人集合中。

1.  返回添加的联系人。

`add()`方法的源代码如下：

```java
@Override
public Contact add(Contact added) {
  String key = persist(added);
  redisTemplate.opsForSet().add("contacts", key);
  return added;
}
```

#### 读取

我们必须提供两种方法，用于从 Redis 中获取联系人信息。第一种方法用于返回现有联系人的列表，第二种方法用于查找单个联系人的信息。

首先，我们必须实现一个方法，用于返回现有联系人的列表。我们可以通过以下步骤实现`findAll()`方法：

1.  创建一个新的`ArrayList`对象，用于存储找到的`Contact`对象。

1.  从联系人集合中获取现有联系人的键。

1.  从哈希中获取每个现有联系人的信息，并将它们添加到创建的`ArrayList`对象中。

1.  返回联系人列表。

实现方法的源代码如下：

```java
@Override
public List<Contact> findAll() {
  List<Contact> contacts = new ArrayList<Contact>();

  Collection<String> keys = redisTemplate.opsForSet().members("contacts");

  for (String key: keys) {
    Contact contact = buildContact(key);
    contacts.add(contact);
  }

  return contacts;
}
```

其次，我们必须实现一个方法，用于返回单个联系人的信息。我们可以通过以下步骤实现`findById()`方法：

1.  检查联系人是否存在。如果联系人不存在，则抛出`NotFoundException`。

1.  从哈希中获取联系人。

1.  返回找到的联系人。

我们方法的源代码如下：

```java
@Override
public Contact findById(Long id) throws NotFoundException {
  if (contactDoesNotExist(id)) {
    throw new NotFoundException("No contact found with id: " + id);
    }
  return buildContact(id);
}
```

#### 更新

我们可以通过以下步骤更新现有联系人的信息：

1.  检查该联系人是否存在。如果找不到联系人，则抛出`NotFoundException`。

1.  将更新后的联系信息保存在哈希中。

1.  返回更新后的联系人。

`update()`方法的源代码如下：

```java
@Override
public Contact update(Contact updated) throws NotFoundException {
  if (contactDoesNotExist(updated.getId())) {
    throw new NotFoundException("No contact found with id: " + updated.getId());
  }
  persist(updated);
  return updated;
}
```

#### 删除

我们可以通过以下步骤删除联系人的信息：

1.  获取已删除联系人的引用。

### 注意

我们使用`findById()`方法，因为如果找不到联系人，它会抛出`NotFoundException`。

1.  构建已删除联系人的键。

1.  从我们的联系人集合中删除联系人。

1.  从哈希中删除联系人的信息。

1.  返回已删除的联系人。

`deleteById()`方法的源代码如下：

```java
@Override
public Contact deleteById(Long id) throws NotFoundException {
  Contact deleted = findById(id);
  String key = buildKey(id);

  redisTemplate.opsForSet().remove("contacts", key);

  BoundHashOperations operations = redisTemplate.boundHashOps(key);

  operations.delete("id");
  operations.delete("emailAddress");
  operations.delete("firstName");
  operations.delete("lastName");
  operations.delete("phoneNumber");

  operations.delete("streetAddress");
  operations.delete("postCode");
  operations.delete("postOffice");
  operations.delete("state");
  operations.delete("country");

  return deleted;
}
```

## 将数据存储为 JSON

如果我们将对象信息存储在哈希中，我们必须编写大量样板代码，用于保存、读取和删除联系人信息。本小节描述了我们如何减少所需代码量并实现一个以 JSON 格式存储联系人信息的 CRUD 应用程序。这意味着`StringRedisSerializer`用于序列化字符串值，而`JacksonJsonRedisSerializer`将我们的`Contact`对象转换为 JSON。

### 配置应用程序上下文

我们可以通过以下步骤配置应用程序的应用程序上下文：

1.  配置值序列化器 bean。

1.  配置 Redis 模板。

1.  配置 Redis 原子长整型 bean。

#### 配置值序列化器 bean

我们可以通过向`ApplicationContext`类添加`contactSerializer()`方法并用`@Bean`注解对其进行注释来配置值序列化器 bean。我们可以通过以下步骤实现此方法：

1.  创建一个新的`JacksonJsonRedisSerializer`对象，并将`Contact`类的类型作为构造函数参数传递。

1.  返回创建的对象。

`contactSerializer()`方法的源代码如下：

```java
@Bean
public RedisSerializer<Contact> valueSerializer() {
    return new JacksonJsonRedisSerializer<Contact>(Contact.class);
}
```

#### 配置 Redis 模板 bean

我们可以通过向`ApplicationContext`类添加`redisTemplate()`方法，对其进行`@Bean`注解，并在其实现中配置 Redis 模板来配置 Redis 模板。我们可以按照以下步骤实现此方法：

1.  创建一个新的`RedisTemplate`对象，并将我们的键和值的类型作为类型参数。

1.  设置使用的连接工厂。

1.  设置使用的值序列化程序。

1.  返回创建的对象。

`redisTemplate()`方法的源代码如下所示：

```java
@Bean
public RedisTemplate redisTemplate() {
    RedisTemplate<String, Contact> redisTemplate = new RedisTemplate<String, Contact>();
    redisTemplate.setConnectionFactory(redisConnectionFactory());
    redisTemplate.setValueSerializer(valueSerializer());

    return redisTemplate;
}
```

#### 配置 Redis 原子长整型 bean

我们将通过向`ApplicationContext`类添加`redisAtomicLong()`方法并使用`@Bean`注解对其进行注解来开始配置 Redis 原子长整型 bean。我们的下一步是按照以下步骤实现此方法：

1.  创建一个新的`RedisAtomicLong`对象。将使用的 Redis 计数器的名称和 Redis 连接工厂作为构造函数参数传递。

1.  返回创建的对象。

`redisAtomicLong()`方法的源代码如下所示：

```java
@Bean
public RedisAtomicLong redisAtomicLong() {
    return new RedisAtomicLong("contact", redisConnectionFactory());
}
```

### CRUD

首先，我们必须谈论一下我们的 Redis 数据模型。我们使用两种不同的数据类型将联系人信息存储到 Redis 中。我们将单个联系人的信息存储到 Redis 中作为字符串值。这是有道理的，因为在保存之前，联系人信息会被转换为 JSON 格式。我们还将使用一个包含`Contact`对象的 JSON 表示的集合。我们必须复制信息，否则我们将无法显示联系人列表。

我们可以通过实现`ContactService`接口为`Contact`对象提供 CRUD 操作。让我们开始创建一个虚拟服务实现，并稍后添加或实现实际的 CRUD 操作。创建虚拟服务实现所需的步骤如下所述：

1.  实现`ContactService`接口。

1.  用`@Service`注解注释创建的类。

1.  将所需的依赖项作为创建的类的私有成员添加，并使用`@Resource`注解对这些成员进行注解。我们需要引用`RedisTemplate`和`RedisAtomicLong`对象。

我们的虚拟服务实现的源代码如下所示：

```java
@Service
public class RedisContactService implements ContactService {

    @Resource
    private RedisAtomicLong contactIdCounter;

    @Resource
    private RedisTemplate<String, Contact> redisTemplate;

    //Add methods here
}
```

我们还必须实现一些实用方法，这些方法由`ContactService`接口声明的方法使用。这些私有方法在以下表中描述：

| 方法 | 描述 |
| --- | --- |
| `String buildKey(Long contactId)` | 返回联系人的键。 |
| `void persist(Contact persisted)` | 将联系人信息保存为字符串值。 |

首先，我们必须实现一个用于构建持久化`Contact`对象键的方法。`buildKey()`方法的实现很简单。我们通过将作为参数给定的联系人 ID 附加到字符串`contact`并返回结果字符串来构建键。`buildKey()`方法的源代码如下所示：

```java
private String buildKey(Long contactId) {
    return "contact" + contactId;
}
```

其次，我们必须实现一个`persist()`方法来保存联系人信息。我们可以通过执行以下步骤来实现这一点：

1.  如果联系人 ID 为空，则获取新 ID 并将接收到的`Long`对象设置为`Contact`对象的 ID。

1.  为联系人创建一个键。

1.  将联系人信息保存为字符串值。

### 注意

我们使用值操作，因为我们只需要执行一个操作。

`persist()`方法的源代码如下所示：

```java
private void persist(Contact persisted) {
  Long id = persisted.getId();
  if (id == null) {
      id = contactIdCounter.incrementAndGet();
      persisted.setId(id);
    }
  String key = buildKey(persisted.getId());
  redisTemplate.opsForValue().set(key, persisted);
}
```

我们现在准备开始为联系人实现 CRUD 操作。让我们继续并找出如何完成。

#### 创建

我们可以通过以下步骤实现一个添加新联系人的方法：

1.  保存添加的联系人。

1.  将联系人信息添加到联系人集合中。

1.  返回添加的联系人。

`add()`方法的源代码如下所示：

```java
@Override
public Contact add(Contact added) {
    persist(added);
    redisTemplate.opsForSet().add("contacts", added);
    return added;
}
```

#### 读取

我们的应用程序有两个视图，显示联系人信息：第一个显示联系人列表，第二个显示单个联系人的信息。

首先，我们必须实现一个从 Redis 获取所有联系人的方法。我们可以按照以下步骤实现`findAll()`方法：

1.  从联系人集合中获取所有联系人。

1.  创建一个新的`ArrayList`对象并返回该对象。

`findAll()`方法的源代码如下：

```java
@Override
public List<Contact> findAll() {
    Collection<Contact> contacts = redisTemplate.opsForSet().members("contacts");
    return new ArrayList<Contact>(contacts);
}
```

其次，我们必须实现一个返回单个联系人信息的方法。我们的`findById()`方法的实现包括以下步骤：

1.  创建联系人的键。

1.  从 Redis 获取`Contact`对象。

1.  如果未找到联系人，则抛出`NotFoundException`。

1.  返回找到的对象。

`findById()`方法的源代码如下：

```java
@Override
public Contact findById(Long id) throws NotFoundException {
    String key = buildKey(id);
    Contact found = redisTemplate.opsForValue().get(key);

    if (found == null) {
        throw new NotFoundException("No contact found with id: {}" + id);
    }

    return found;
}
```

#### 更新

我们可以按照以下步骤更新现有联系人的信息：

1.  从 Redis 获取旧的联系人信息。

1.  保存更新后的联系人信息。

1.  从联系人集合中删除旧的联系人信息。这样可以确保我们的集合不包含相同联系人的重复条目。

1.  将更新后的联系人信息添加到联系人集合中。

1.  返回更新后的联系人。

`update()`方法的源代码如下：

```java
@Override
public Contact update(Contact updated) throws NotFoundException {
    Contact old = findById(updated.getId());

    persist(updated);
    redisTemplate.opsForSet().remove("contacts", old);
    redisTemplate.opsForSet().add("contacts", updated);

    return updated;
}
```

#### 删除

我们可以按照以下步骤删除联系人信息：

1.  通过调用`findById()`方法找到已删除的联系人。这样可以确保如果联系人未找到，则会抛出`NotFoundException`。

1.  构建用于获取联系人信息的键。

1.  从联系人集合中删除已删除的联系人。

1.  删除已删除联系人的 JSON 表示。

1.  返回已删除的联系人。

`delete()`方法的源代码如下：

```java
@Override
public Contact deleteById(Long id) throws NotFoundException {
    Contact deleted = findById(id);

    String key = buildKey(id);
    redisTemplate.opsForSet().remove("contacts", deleted);
    redisTemplate.opsForValue().set(key, null);

    return deleted;
}
```

# 发布/订阅消息模式

Redis 还包括发布/订阅消息模式的实现。本节演示了我们如何使用 Spring Data Redis 来发送和接收消息。例如，我们将修改将联系人信息存储为 JSON 的 CRUD 应用程序，以便在添加新联系人时发送通知，更新联系人信息以及删除联系人时发送通知。

我们可以通过执行以下步骤来实现此要求：

1.  创建处理接收到的消息的消息监听器。

1.  配置我们应用程序的应用程序上下文。

1.  使用`RedisTemplate`类发送消息。

本节还描述了我们如何确保我们的实现工作正常。

## 创建消息监听器

使用 Spring Data Redis 创建消息监听器有两种方法：我们可以实现`MessageListener`接口，或者我们可以创建一个 POJO 消息监听器并使用`MessageListenerAdapter`类将消息委派给它。这两种方法都在本小节中讨论。

### 实现 MessageListener 接口

创建消息监听器的第一种方法是实现`MessageListener`接口。我们的实现包括以下步骤：

1.  创建一个用于记录接收到的消息的新`Logger`对象。

1.  创建一个用于将字节数组转换为`String`对象的新`StringRedisSerializer`对象。

1.  实现`MessageListener`接口声明的`onMessage()`方法。此方法简单地记录接收到的消息。

`ContactListener`类的源代码如下：

```java
public class ContactMessageListener implements MessageListener {

    private final static Logger LOGGER = LoggerFactory.getLogger(ContactMessageListener.class);

    private RedisSerializer<String> stringSerializer = new StringRedisSerializer();

    @Override
    public void onMessage(Message message, byte[] pattern) {
        LOGGER.debug("MessageListener - received message: {} on channel: {}", stringSerializer.deserialize(message.getBody()), stringSerializer.deserialize(message.getChannel()));
    }
}
```

### 创建一个 POJO 消息监听器

创建消息监听器的第二种方法是创建一个普通的 Java 类。我们可以按照以下步骤来做到这一点：

1.  创建一个用于记录接收到的消息的新`Logger`对象。

1.  创建一个名为`handleMessage()`的消息处理方法，该方法接受`Contact`对象和`String`对象作为参数。

1.  实现`handleMessage()`方法。此方法记录接收到的消息。

`ContactPOJOMessageListener`类的源代码如下：

```java
public class ContactPOJOMessageListener {

    private static final Logger LOGGER = LoggerFactory.getLogger(ContactPOJOMessageListener.class);

    public void handleMessage(Contact contact, String channel) {
        LOGGER.debug("Received contact: {} on channel: {}", contact, channel);
    }
}
```

## 配置应用程序上下文

我们必须对应用程序上下文配置进行以下更改：

1.  配置消息监听器 bean。

1.  配置消息监听适配器 bean。

1.  配置消息监听器容器 bean。

### 配置消息监听器 bean

首先，我们必须配置我们的消息监听器 bean。配置相当简单。我们只需创建新的消息监听器对象并返回创建的对象。消息监听器 bean 配置的源代码如下：

```java
@Bean
public ContactMessageListener contactMessageListener() {
    return new ContactMessageListener();
}

@Bean
public ContactPOJOMessageListener contactPOJOMessageListener() {
    return new ContactPOJOMessageListener();
}
```

### 配置消息监听器适配器 bean

接下来，我们必须配置消息监听器适配器 bean，该 bean 用于将消息转发给我们的 POJO 消息监听器。我们可以通过以下步骤配置此 bean：

1.  创建一个新的`MessageListenerAdapter`对象，并将`ContactPOJOMessageListener`对象作为构造函数参数传递。

1.  设置用于将接收到的消息转换为`Contact`对象的序列化器。

1.  返回创建的对象。

`messageListenerAdapter()`方法的源代码如下：

```java
@Bean
public MessageListenerAdapter messageListenerAdapter() {
    MessageListenerAdapter adapter = new MessageListenerAdapter(contactPOJOMessageListener());
    adapter.setSerializer(contactSerializer());
    return adapter;
}
```

### 注意

`MessageListenerAdapter`类的`defaultListenerMethod`属性用于配置消息处理程序方法的名称。此属性的默认值为`handleMessage`。

### 配置消息监听器容器 bean

**消息监听器容器**是一个组件，它监听通过不同通道发送的消息，并将这些消息转发给注册的消息监听器。我们可以通过以下步骤配置此组件：

1.  创建一个新的`RedisMessageListenerContainer`对象。

1.  设置已使用的 Redis 连接工厂。

1.  注册消息监听器并指定订阅的通道。

1.  返回创建的对象。

我们的配置源代码如下：

```java
@Bean
public RedisMessageListenerContainer redisMessageListenerContainer() {
    RedisMessageListenerContainer container = new RedisMessageListenerContainer();

    container.setConnectionFactory(redisConnectionFactory());
    container.addMessageListener(messageListenerAdapter(), 
    Arrays.asList(
            new ChannelTopic("newContacts"),
            new ChannelTopic("updatedContacts"),
            new ChannelTopic("removedContacts")
    ));
    container.addMessageListener(contactMessageListener(), 
    Arrays.asList(
            new ChannelTopic("newContacts"),
            new ChannelTopic("updatedContacts"),
            new ChannelTopic("removedContacts")
    ));

    return container;
}
```

## 使用 RedisTemplate 发送消息

我们可以使用`RedisTemplate`类的`convertAndSend(String channel, Object message)`方法向不同的通道发送发布消息。本小节描述了如何使用此方法发送有关新联系人、更新联系人和删除联系人的通知。

### 创建

为了发送有关新联系人的更改通知，我们必须修改`RedisContactService`类的`add()`方法，在成功保存新联系人信息后调用`RedisTemplate`类的`convertAndSend()`方法。我们的新`add()`方法的源代码如下：

```java
@Override
public Contact add(Contact added) {
    persist(added);
    redisTemplate.opsForSet().add("contacts", added);
 redisTemplate.convertAndSend("newContacts", added);

    return added;
}
```

### 更新

通过修改`RedisContactService`类的`update()`方法，我们可以发送关于更新联系人的通知。在联系信息更新后，我们只需调用`RedisTemplate`类的`convertAndSend()`方法。新`update()`方法的源代码如下：

```java
@Override
public Contact update(Contact updated) throws NotFoundException {
    Contact old = findById(updated.getId());

    persist(updated);
    redisTemplate.opsForSet().remove("contacts", old);
    redisTemplate.opsForSet().add("contacts", updated);
 redisTemplate.convertAndSend("updatedContacts", updated);

    return updated;
}
```

### 删除

通过对`RedisContactService`类的`deleteById()`方法进行小修改，我们可以发送有关已删除联系人的通知。在联系信息被删除后，我们将调用`RedisTemplate`类的`convertAndSend()`方法，该方法发送通知消息。修改后的`deleteById()`方法的源代码如下：

```java
@Override
public Contact deleteById(Long id) throws NotFoundException {
    Contact deleted = findById(id);

    String key = buildKey(id);

    redisTemplate.opsForSet().remove("contacts", deleted);
    redisTemplate.opsForValue().set(key, null);
 redisTemplate.convertAndSend("removedContacts", deleted);

    return deleted;
}
```

## 验证所需的行为

我们现在已经实现了我们的消息监听器，并修改了我们的应用程序，以便在联系信息更改时每次发送通知消息。我们的下一步是验证我们的实现是否按预期工作。

我们可以通过更改联系信息并确保我们的消息监听器写入应用程序日志中的日志行来确认这一点。当添加新联系人时写入的日志行如下：

```java
DEBUG - ContactMessageListener     - Received message: {"id":9,"address":{"country":"","streetAddress":"","postCode":"","postOffice":"","state":""},"emailAddress":"","firstName":"Foo","lastName":"Bar","phoneNumber":""} on channel: newContacts
DEBUG - ContactPOJOMessageListener - Received contact: com.packtpub.springdata.redis.model.Contact@543d8ee8[id=9,address=com.packtpub.springdata.redis.model.Address@15714c8d[country=,streetAddress=,postCode=,postOffice=,state=],emailAddress=,firstName=Foo,lastName=Bar,phoneNumber=] on channel: null
```

### 注意

请注意，传递给 POJO 消息处理程序的通道信息始终为`null`。这是 Spring Data Redis 的已知错误。有关更多信息，请访问[`jira.springsource.org/browse/DATAREDIS-98`](https://jira.springsource.org/browse/DATAREDIS-98)。

# 使用 Spring Data Redis 的 Spring 缓存抽象

Spring Framework 3.1 的缓存抽象将缓存应用于 Java 方法。当调用缓存的方法时，缓存抽象将从缓存中检查该方法是否早期使用相同的参数调用过。如果是这种情况，则从缓存中获取返回值，并且不执行该方法。否则，执行该方法并将其返回值存储在缓存中。

### 注意

Spring Framework 3.1 的缓存抽象在[`static.springsource.org/spring/docs/3.1.x/spring-framework-reference/html/cache.html`](http://static.springsource.org/spring/docs/3.1.x/spring-framework-reference/html/cache.html)中有更详细的解释。

Spring Data Redis 提供了 Spring 缓存抽象的实现。使用 Redis 作为缓存比使用 Ehcache 等本地缓存实现有两个好处：

+   它可以作为一个集中的缓存，被运行我们的应用程序的每个 servlet 容器或应用程序服务器共享。这减少了数据库查询的总体数量，减少了数据库服务器的负载，并提高了所有服务器的性能。

+   缓存不会被清空，直到我们清空它。这意味着我们可以重新启动我们的 servlet 容器或应用程序服务器，而不会丢失缓存中存储的信息。在服务器重新启动后，它可以立即充分利用缓存的信息。无需预热缓存。

本节描述了我们如何使用 Spring Data Redis 来为使用 JPA Criteria API 的应用程序添加缓存支持。该应用程序最初是在第三章中介绍的，*使用 Spring Data JPA 构建查询*。我们缓存示例的要求如下：

+   从数据库中查找单个联系人信息的方法调用必须被缓存

+   当联系人的信息被更新时，缓存中存储的信息也必须更新

+   当联系人被删除时，必须从缓存中删除已删除的联系人

我们可以通过以下步骤为我们的示例应用程序添加缓存支持：

1.  配置 Spring 缓存抽象。

1.  识别缓存的方法。

我们还将学习如何验证 Spring 缓存抽象是否正常工作。

## 配置 Spring 缓存抽象

我们可以通过对应用程序的应用程序上下文配置进行以下更改来配置 Spring 缓存抽象：

1.  启用缓存注解。

1.  在所使用的属性文件中配置所使用的 Redis 实例的主机和端口。

1.  配置 Redis 连接工厂 bean。

1.  配置 Redis 模板 bean。

1.  配置缓存管理器 bean。

### 启用缓存注解

我们可以通过使用`@EnableCaching`注解来注解我们的应用程序上下文配置类来启用缓存注解。`ApplicationContext`类的相关部分如下所示：

```java
@Configuration
@ComponentScan(basePackages = {
        "com.packtpub.springdata.jpa.controller",
        "com.packtpub.springdata.jpa.service"
})
@EnableCaching
@EnableTransactionManagement
@EnableWebMvc
@EnableJpaRepositories("com.packtpub.springdata.jpa.repository")
@PropertySource("classpath:application.properties")
public class ApplicationContext extends WebMvcConfigurerAdapter {

    @Resource
    private Environment env;

    //Bean declarations
}
```

### 配置所使用的 Redis 实例的主机和端口

为了配置所使用的 Redis 实例的主机和端口，我们必须在`application.properties`文件中添加以下行：

```java
redis.host = localhost
redis.port = 6379
```

### 配置 Redis 连接工厂 bean

我们可以通过在`ApplicationContext`类中添加一个`redisConnectionFactory()`方法，并用`@Bean`注解对该方法进行注解来配置 Redis 连接工厂 bean。我们可以通过以下步骤实现这个方法：

1.  创建一个新的`JedisConnectionFactory`对象。

1.  配置所使用的 Redis 实例的主机和端口。

1.  返回创建的对象。

给出`redisConnectionFactory()`方法的源代码如下：

```java
@Bean
public RedisConnectionFactory redisConnectionFactory() {
    JedisConnectionFactory cf = new JedisConnectionFactory();

    cf.setHostName(env.getRequiredProperty("redis.host")); cf.setPort(Integer.parseInt(env.getRequiredProperty("redis.port")));

    return cf;
}
```

### 配置 Redis 模板 bean

为了配置 Redis 模板 bean，我们必须在`ApplicationContext`类中添加一个`redisTemplate()`方法，并用`@Bean`注解对该方法进行注解。我们对这个方法的实现包括以下步骤：

1.  创建一个新的`RedisTemplate`对象。

1.  设置使用的 Redis 连接工厂。

1.  返回创建的对象。

`redisTemplate()`方法的源代码如下：

```java
@Bean
public RedisTemplate redisTemplate() {
    RedisTemplate<String, String> redisTemplate = new RedisTemplate<String, String>();
    redisTemplate.setConnectionFactory(redisConnectionFactory());

    return redisTemplate;
}
```

### 配置缓存管理器 bean

我们的最后一步是配置缓存管理器 bean。我们可以通过在`ApplicationContext`类中添加`cacheManager()`方法，并用`@Bean`注解对此方法进行注释来实现这一点。我们可以通过以下步骤实现这个方法：

1.  创建一个新的`RedisCacheManager`对象，并将使用的 Redis 模板作为构造函数参数。

1.  返回创建的对象。

`cacheManager()`方法的源代码如下：

```java
@Bean
public RedisCacheManager cacheManager() {
    return new RedisCacheManager(redisTemplate());
}
```

## 识别缓存方法

我们现在已经配置了 Spring 缓存抽象，并且准备好识别缓存方法。本小节描述了我们如何在缓存中添加联系信息，更新已经存储在缓存中的联系信息，并从缓存中删除联系信息。

### 将联系信息添加到缓存

为了将联系信息添加到缓存中，我们必须缓存`RepositoryContactService`类的`findById()`方法的方法调用。我们可以通过使用`@Cacheable`注解对方法进行注释并提供缓存的名称来实现这一点。这告诉缓存抽象应该使用提供的 ID 作为键，将返回的联系人添加到`contacts`缓存中。`findById()`方法的源代码如下：

```java
@Cacheable("contacts")
@Transactional(readOnly = true)
@Override
public Contact findById(Long id) throws NotFoundException {
    //Implementation remains unchanged.
}
```

### 将联系信息更新到缓存

我们可以通过在`RepositoryContactService`类的`update()`方法上注释`@CachePut`注解来更新存储在缓存中的联系信息。我们还必须提供缓存的名称，并指定当此方法的返回值更新到缓存时，`ContactDTO`对象的`id`属性将被用作键。`update()`方法的源代码如下：

```java
@CachePut(value = "contacts", key="#p0.id")
@Transactional(rollbackFor = NotFoundException.class)
@Override
public Contact update(ContactDTO updated) throws NotFoundException {
    //Implementation remains unchanged.
}
```

### 从缓存中删除联系信息

我们可以通过在`deleteById()`方法上注释`@CacheEvict`注解并提供缓存的名称作为其值来从缓存中删除联系信息。这意味着在方法执行后，缓存抽象会从缓存中删除已删除的联系人。被删除的联系人由作为方法参数给定的 ID 标识。`deleteById()`方法的源代码如下：

```java
@CacheEvict("contacts")
@Transactional(rollbackFor = NotFoundException.class)
@Override
public Contact deleteById(Long id) throws NotFoundException {
  //Implementation remains unchanged
}
```

## 验证 Spring 缓存抽象是否正常工作

我们现在已经成功地将缓存添加到我们的示例应用程序中。我们可以通过使用缓存方法并查找我们应用程序的日志文件中的以下行来验证 Spring 缓存抽象是否正常工作：

```java
DEBUG - RedisConnectionUtils       - Opening Redis Connection
DEBUG - RedisConnectionUtils       - Closing Redis Connection
```

如果在日志文件中找到这些行，可能意味着：

+   从缓存中获取联系信息而不是使用的数据库

+   联系信息已更新到缓存

+   联系信息已从缓存中删除

# 总结

在本章中，我们已经学到：

+   设计 Redis 数据模型与设计关系数据库的数据模型完全不同

+   我们可以将 Redis 用作 Web 应用程序的数据存储

+   Spring Data Redis 与 Redis 发布/订阅实现提供了清晰的集成

+   我们可以通过使用 Spring 缓存抽象将 Redis 作为我们应用程序的集中式缓存来使用
