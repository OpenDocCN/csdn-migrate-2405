# Spring5 学习手册（三）

> 原文：[`zh.annas-archive.org/md5/6DF1C981F26DA121DCB8C1B33E7DE022`](https://zh.annas-archive.org/md5/6DF1C981F26DA121DCB8C1B33E7DE022)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

## 第五章．保持一致性：事务管理

在上一章中，我们深入讨论了使用日志机制作为交叉技术的面向方面编程。事务管理是另一种交叉技术，在处理持久性时在应用程序中扮演着非常重要的角色。在本章中，我们将通过讨论以下几点来探索事务管理：

+   事务管理是什么？

+   事务管理的重要性。

+   事务管理的类型

+   Spring 和事务管理

+   Spring 框架中基于注解的事务管理

许多开发者经常谈论这个花哨的术语“事务管理”。我们中有多少人觉得自己在使用它或其自定义时感到舒适呢？它真的那么难以理解吗？在代码中添加事务是否需要添加大量的复杂代码？不是的！！实际上，它是最容易理解的事情之一，也是最容易开发的。在讨论、设计、开发与数据库进行数据处理的“持久层”时，事务管理非常普遍。事务是序列化多个数据库操作的基本单位，其中要么所有操作成功执行，要么一个都不执行。事务管理是处理事务的技术，通过管理其参数来处理事务。事务根据给定的事务参数保持数据库的一致性，以便要么事务单位成功，要么失败。事务绝不可能部分成功或失败。

现在你可能在想，如果其中的任何一个失败了会有什么大不了的？为什么这如此重要？让我们通过一个实际的场景来理解交易。我们想在某个网上购物网站上开设一个账户。我们需要填写一个表格，提供一些个人信息，并选择一个用户名来进行我们的网上购物。这些信息将由应用程序收集，然后保存在两个表中。一个是以用户名为主键的用户表，第二个是 user_info 表，用于存储用户的个人信息。在从用户那里收集数据后，开发者会对 user_info 表执行插入操作，然后将数据插入到用户表中。现在考虑这样一个场景：从用户那里收集的数据成功插入到 user_info 表中，但不幸的是，用户名在表中已经存在，所以第二个操作失败了。数据库处于不一致的状态。从逻辑上讲，数据应该要么同时添加到两个表中，要么一个都不添加。但在我们的案例中，数据只插入了一个表，而没有插入第二个表。这是因为我们在检查行是否插入成功之前就执行了永久的插入操作，现在即使第二个操作失败了也无法撤销。事务管理帮助开发者通过在数据库表中正确反映所有操作，或者一个都不反映来维护数据库的一致性和完整性。如果在单元操作中任何一个操作失败，所有在失败之前所做的更改都将被取消。当然，这不会自动发生，但开发者需要发挥关键作用。在 JDBC 中，开发者选择不使用自动提交操作，而是选择提交事务或回滚，如果其中任何一个操作失败。这两个术语在事务管理中非常重要。提交将更改永久反映到数据库中。回滚撤销所有在失败发生之前的操作所做的更改，使数据库恢复到原始状态。

以下是 Jim Gray 在 1970 年代定义的 ACID 属性，用于描述事务。这些属性后来被称为 ACID 属性。Gray 还描述了实现 ACID 属性的方法。让我们逐一讨论它们：

+   **原子性**：在数据库上连续执行多个操作时，要么所有操作都会成功执行，要么一个都不会执行。开发者可以控制是否通过提交它们来永久更改数据库，或者回滚它们。回滚将撤销所有操作所做的更改。一旦数据被提交，它就不能再次回滚。

+   **一致性**：为了将数据保存成适当排列且易于维护的格式，在创建数据库表时设置了规则、数据类型、关联和触发器。一致性确保在从一种状态转换到另一种状态获取数据时，将保持所有设置在其上的规则不变。

+   **隔离性**：在并发中，多个事务同时发生导致数据管理问题。隔离性通过锁定机制保持数据的一致状态。除非正在处理数据的事务完成，否则它将保持锁定。一旦事务完成其操作，另一个事务将被允许使用数据。

以下是 ANSI 或 ISO 标准定义的隔离级别：

+   **脏读**：考虑两个事务 A 和 B 正在运行的数据集。事务 A 进行了某些更改但尚未提交。与此同时，事务 B 读取了数据以及未提交更改的数据。如果事务 A 成功完成其操作，两个事务具有相同的数据状态。但如果事务 A 失败，它所做的数据更改将被回滚。由于 B 读取了未提交的数据，A 和 B 的数据集将不同。事务 B 使用了过时的数据，导致应用程序的业务逻辑失败。

+   **非可重复读**：再次考虑事务 A 和 B 正在完成一些操作。它们都读取了数据，事务 A 更改了一些值并成功提交。事务 B 仍在处理旧数据，导致不良影响。这种情况可以通过在第一个事务完成之前保持数据锁定来避免。

+   **幻读**：事务 A 和 B 拥有同一组数据。假设事务 A 已经执行了搜索操作，比如，A 根据书名搜索数据。数据库返回了 8 行数据给事务 A。此时事务 B 在表中插入了一行具有与 A 搜索的书名相同值的数据。实际上表中有 9 行数据，但 A 只得到了 8 行。

+   **可串行化**：这是最高的隔离级别，它锁定选定的使用数据，以避免幻读问题。

+   以下是数据库支持的默认隔离级别：

| 数据库 | 默认隔离级别 |
| --- | --- |
| Oracle | READ_COMMITTED |
| Microsoft SQL Server | READ_COMMITTED |
| MySQL | REPEATABLE_READ |
| PostgreSQL | READ_COMMITTED |
| DB2 | CURSOR STABILITY |

+   **持久性**：事务通过多种操作同时进行更改。持久性指定一旦数据库中的数据被更改、添加或更新，它必须是永久的。

一旦我们了解了描述事务的属性，了解事务进展的阶段将有助于我们有效地使用事务管理。

## 事务管理的生命周期

***

以下图表展示了每个事务进展的阶段：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/lrn-spr5/img/image_05_001.png)

新启动的事务将经历以下阶段：

1.  **活动**：事务刚刚开始并且正在向前推进。

1.  **部分提交**：一旦操作成功执行，生成的值将被存储在易失性存储中。

1.  **失败**：在失败之前生成的值不再需要，将通过回滚从易失性存储区中删除它们。

1.  **中止**：操作已失败且不再继续。它将被停止或中止。

1.  **已提交**：所有成功执行的操作以及操作期间生成的所有临时值，一旦事务提交，将被永久存储。

1.  **终止**：当事务提交或中止时，它达到了其最终阶段——终止。

要处理与生命周期步骤和属性相关的事务，不能忽视一个非常重要的事实，即了解事务的类型。事务可以划分为本地事务或全局事务。

### 本地事务

本地事务允许应用程序连接到单个数据库，一旦事务中的所有操作成功完成，它将被提交。本地事务特定于资源，不需要服务器处理它们。配置的数据源对象将返回连接对象。此连接对象进一步允许开发人员根据需要执行数据库操作。默认情况下，此类连接是自动提交的。为了掌握控制权，开发人员可以使用提交或回滚手动处理事务。JDBC 连接是本地事务的最佳示例。

### 全局或分布式事务

全局事务由应用服务器如 Weblogic、WebSphere 管理。全局事务能够处理多个资源和服务器。全局事务由许多访问资源的本地事务组成。EJB 的容器管理事务使用全局事务。

### Spring 和事务管理

Spring 框架卓越地支持事务管理器的集成。它支持 Java 事务 API，JDBC，Hibernate 和 Java 持久化 API。框架支持称为事务策略的抽象事务管理。事务策略是通过服务提供者接口（SPI）通过 PlatformTransactionManager 接口定义的。该接口有提交和回滚事务的方法。它还有获取由 TransactionDefinition 指定的事务的方法。所有这些方法都会抛出 TransactionException，这是一个运行时异常。

`getTransaction()`方法根据 TransactionDefinition 参数返回 TransactionStatus。该方法返回的 TransactionStatus 代表一个新事务或现有事务。以下参数可以指定以定义 TransactionDefinition：

+   **传播行为**：当一个事务方法调用另一个方法时，传播行为就会讨论。在这种情况下，传播行为指明它将如何执行事务行为。调用方法可能已经启动了事务，那么被调用方法在这种情况下应该做什么？被调用方法是启动一个新事务，使用当前事务还是不支持事务？传播行为可以通过以下值来指定：

    +   **REQUIRED**：它表示必须有事务。如果没有事务存在，它将创建一个新的事务。

    +   **REQUIRES_NEW**：它指定每次都要有一个新的事务。当前事务将被挂起。如果没有事务存在，它将创建一个新的事务。

    +   **强制**：它表示当前事务将被支持，但如果没有进行中的事务，将抛出异常。

    +   **嵌套**：它表明，如果当前事务存在，方法将在嵌套事务中执行。如果没有事务存在，它将作为 PROPAGATION_REQUIRED 行事。

    +   **永不**：不支持事务，如果存在，将抛出异常。

    +   **不支持**：它表示该交易是不被支持的。如果交易与**永不**相反存在，它不会抛出异常，但会挂起交易。

+   **隔离性**：我们已经在深度讨论隔离级别。

+   **超时**：事务中提到的超时值，以秒为单位。

+   **只读**：该属性表示事务将只允许读取数据，不支持导致更新数据的操作。

以下是用 Spring 框架进行事务管理的优点：

Spring 通过以下两种方式简化事务管理：

+   编程事务管理。

+   声明式事务管理。

无论我们使用程序化事务还是声明式事务，最重要的是使用依赖注入（DI）定义`PlatformTransactionManager`。一个人应该清楚地知道是使用本地事务还是全局事务，因为定义`PlatformTransactionManager`是必不可少的。以下是一些可以用来定义`PlatformTransactionManager`的配置：

+   使用 DataSource PlatformTransactionManager 可以定义为：

```java
      <bean id="dataSource" 
        <!-DataSource configuration --> 
      </bean> 
      <bean id="transactionManager" 
        class="org.springframework.jdbc.datasource.DataSourceTransactionManager"> 
        <property name="dataSource" ref="dataSource"/>    
      </bean> 

```

+   使用 JNDI 和 JTA 定义 PlatformTransactionManager，如下所示：

```java
      <jee: jndi-lookup id="dataSource' jndi-name="jdbc/books"/> 
        <bean id="transactionManager"
          class="org.springframework.transaction.jta.JtaTransactionManager"> 
        </bean> 

```

+   使用 HibernateTransactionManager 定义 PlatformTransactionManager 为：

```java
      <bean id="sessionFactory" 
         class="org.springframework.orm.hibernate5.LocalSessionfactoryBean" 
         <!-define parameters for session factory --> 
      </bean> 

      <bean id=" transactionManager"
         class="org.springframework.orm.hibernate5.HibernateTransactionManager"> 
         <property name="sessionFactory" ref="sessionFactory"/> 
      </bean> 

```

让我们逐一开始使用 Spring 中的事务管理，

#### 程序化事务管理

在 Spring 中，可以通过使用 TransactionTemplate 或 PlatformTransactionManager 来实现程序化事务管理。

##### 使用 PlatformTransactionManager

PlatformTransactionManager 是讨论 Spring 事务管理 API 的中心。它具有提交、回滚的功能。它还提供了一个返回当前活动事务的方法。由于它是一个接口，因此可以在需要时轻松模拟或垫片。Spring 提供了 DataSourceTransactionManager、HibernateTransactionManager、CciLocalTransactionManager、JtaTransactionManager 和 OC4JJtaTransactionManager 作为 PlatformTransactionManager 的几种实现。要使用 PlatformTransactionManager，可以在 bean 中注入其任何实现以用于事务管理。此外，TransactionDefinition 和 TransactionStatus 对象的可以使用来回滚或提交事务。

在前进之前，我们需要讨论一个非常重要的点。通常，应用程序需求决定是否将事务应用于服务层或 DAO 层。但是，是否将事务应用于 DAO 层或服务层仍然是一个有争议的问题。尽管将事务应用于 DAO 层可以使事务更短，但最大的问题将是多事务的发生。并且必须非常小心地处理并发，不必要的复杂性会增加。当将事务应用于服务层时，DAO 将使用单个事务。在我们的应用程序中，我们将事务应用于服务层。

为了在应用程序中应用事务管理，我们可以考虑以下几点，

+   是将事务应用于 DAO 层还是服务层？

+   决定是使用声明式事务还是程序化事务管理

+   在 bean 配置中定义要使用的 PlatformtransactionManager。

+   决定事务属性，如传播行为、隔离级别、只读、超时等，以定义事务。

+   根据程序化或声明式事务管理，在代码中添加事务属性。

让我们使用事务来更好地理解。我们将使用第三章中开发的`Ch03_JdbcTemplate`应用程序作为基础应用程序，并使用`PlatformTransactionManager`遵循步骤来使用事务，

1.  创建一个名为`Ch05_PlatformTransactionManager`的新 Java 应用程序，并添加所有必需的 jar 文件，包括 Spring 核心、Spring-jdbc、Spring-transaction、Spring-aop、commons-logging 和 mysql-connector。

1.  在`com.packt.ch03.beans`包中复制或创建`Book.java`文件。

1.  在`com.packt.ch03.dao`包中复制或创建`BookDAO.java`和`BookDAO_JdbcTemplate.java`文件。应用程序的最终结构如下所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/lrn-spr5/img/image_05_002.png)

1.  我们将在`BookDAO`中添加一个新的方法来搜索书籍，因为在添加之前，我们需要找出'Book'表中是否有具有相同 ISBN 的书籍。如果已经存在，我们不希望不必要的再次进行添加。新添加的方法将如下所示：

```java
      public Book serachBook(long ISBN); 

```

1.  `BookDAO_JdbcTemplate.java`需要覆盖接口中 newly added method，如下所示：

```java
      @Override 
      public Book serachBook(long ISBN) { 
        // TODO Auto-generated method stub 
        String SEARCH_BOOK = "select * from book where ISBN=?"; 
        Book book_serached = null; 
        try { 
          book_serached = jdbcTemplate.queryForObject(SEARCH_BOOK,  
            new Object[] { ISBN },  
            new RowMapper<Book>(){ 
            @Override 
              public Book mapRow(ResultSet set, int rowNum)  
              throws SQLException { 
                Book book = new Book(); 
                book.setBookName(set.getString("bookName")); 
                book.setAuthor(set.getString("author")); 
                book.setDescription(set.getString("description")); 
                book.setISBN(set.getLong("ISBN")); 
                book.setPrice(set.getInt("price")); 
                book.setPublication(set.getString("publication")); 
                return book; 
              } 
            }); 
            return book_serached; 
          } catch (EmptyResultDataAccessException ex) { 
          return new Book(); 
        } 
      } 

```

我们添加了一个匿名内部类，它实现了`RowMapper`接口，使用`queryForObject()`方法将从数据库检索的对象绑定到`Book`对象的数据成员。代码正在搜索书籍，然后将`ResultSet`中的列值绑定到`Book`对象。我们返回了一个具有默认值的对象，仅为我们的业务逻辑。

1.  在`com.packt.ch05.service`包中添加`BookService`接口作为服务层，并具有以下方法签名：

```java
      public interface BookService { 
        public Book searchBook(long ISBN); 
        public boolean addBook(Book book); 
        public boolean updateBook(long ISBN, int price); 
        public boolean deleteBook(long ISBN); 
      } 

```

1.  创建`BookServiceImpl`实现`BookService`。因为这是服务，用`@Service`注解类。

1.  首先向类中添加两个数据成员，第一个类型为`PlatformTransactionManager`以处理事务，第二个类型为`BookDAO`以执行 JDBC 操作。使用`@Autowired`注解对它们进行依赖注入。

1.  首先，让我们分两步为服务层开发`searchBook()`方法，以处理只读事务：

    +   创建一个`TransactionDefinition`实例。

    +   创建一个`TransactionStatus`实例，该实例从使用上一步创建的`TransactionDefinition`实例的`TransactionManager`中获取。`TransactionStatus`将提供事务的状态信息，该信息将用于提交或回滚事务。

在这里，将事务设置为只读，将属性设置为`true`，因为我们只是想要搜索书籍，并不需要在数据库端执行任何更新。至此步骤开发出的代码将如下所示：

```java
      @Service(value = "bookService") 
      public class BookServiceImpl implements BookService { 
        @Autowired 
        PlatformTransactionManager transactionManager; 

        @Autowired  
        BookDAO bookDAO; 

        @Override 
        public Book searchBook(long ISBN) { 
          TransactionDefinition definition = new  
            DefaultTransactionDefinition(); 
          TransactionStatus transactionStatus =  
            transactionManager.getTransaction(definition); 
          //set transaction as read-only 
          ((DefaultTransactionDefinition)  
          definition).setReadOnly(true); 
          Book book = bookDAO.serachBook(ISBN); 
          return book; 
        } 
        // other methods from BookService     
      }   

```

我们更新只读事务属性的方式，也可以同样设置其他属性，如隔离级别、传播、超时。

1.  让我们向服务层添加`addBook()`方法，以找出是否已有具有相同 ISBN 的书籍，如果没有，则在表中插入一行。代码将如下所示：

```java
      @Override 
      public boolean addBook(Book book) { 
        // TODO Auto-generated method stub 
        TransactionDefinition definition = new  
          DefaultTransactionDefinition(); 
        TransactionStatus transactionStatus =  
          transactionManager.getTransaction(definition); 

        if (searchBook(book.getISBN()).getISBN() == 98564567l) { 
          System.out.println("no book"); 
          int rows = bookDAO.addBook(book); 
          if (rows > 0) { 
            transactionManager.commit(transactionStatus); 
            return true; 
          } 
        } 
        return false; 
      } 

```

`transactionManager.commit()`将永久将数据提交到书籍表中。

1.  以同样的方式，让我们添加`deleteBook`和`updateBook()`方法，如下所示，

```java
      @Override 
      public boolean updateBook(long ISBN, int price) { 
        TransactionDefinition definition = new  
          DefaultTransactionDefinition(); 
        TransactionStatus transactionStatus =  
          transactionManager.getTransaction(definition); 
        if (searchBook(ISBN).getISBN() == ISBN) { 
          int rows = bookDAO.updateBook(ISBN, price); 
          if (rows > 0) { 
            transactionManager.commit(transactionStatus); 
            return true; 
          } 
        } 
        return false; 
      } 

      @Override 
      public boolean deleteBook(long ISBN)  
      { 
        TransactionDefinition definition = new  
          DefaultTransactionDefinition(); 
        TransactionStatus transactionStatus =  
          transactionManager.getTransaction(definition); 
        if (searchBook(ISBN).getISBN() != 98564567l) { 
          boolean deleted = bookDAO.deleteBook(ISBN); 
          if (deleted) { 
            transactionManager.commit(transactionStatus); 
            return true; 
          } 
        } 
        return false; 
      } 

```

1.  复制或创建 connection_new.xml 以进行 bean 配置。添加一个 DataSourceTransactionManager 的 bean，正如我们在讨论如何使用 DataSource 配置 PlatformTransactionManager 时所看到的。

1.  更新从 XML 中扫描包，因为我们还想考虑新添加的包。更新后的配置如下：

```java
      <context:component-scan base- package="com.packt.*">
      </context:component-scan> 

```

1.  最后一步将是把主代码添加到 MainBookService_operation.java 中，该文件将使用 BookServiceImpl 对象调用服务层的方法，就像我们之前对 BookDAO_JdbcTemplate 对象所做的那样。代码如下所示：

```java
      public static void main(String[] args) { 
        // TODO Auto-generated method stub 
        ApplicationContext context = new   
          ClassPathXmlApplicationContext("connection_new.xml"); 
        BookService service = (BookService)    
          context.getBean("bookService"); 
        // add book 
        boolean added = service.addBook(new Book("Java EE 7  
          Developer Handbook", 97815674L, "PacktPub  
          publication", 332,  "explore the Java EE7  
          programming", "Peter pilgrim")); 
        if (added) { 
          System.out.println("book inserted successfully"); 
        } else 
        System.out.println("SORRY!cannot add book"); 
        // update the book 
        boolean updated = service.updateBook(97815674L, 800); 
        if (updated) { 
          System.out.println("book updated successfully"); 
        } else 
        System.out.println("SORRY!cannot update book"); 
        // delete the book 
        boolean deleted = service.deleteBook(97815674L); 
        if (deleted) { 
          System.out.println("book deleted successfully"); 
        } else 
        System.out.println("SORRY!cannot delete book"); 
      } 

```

##### TransactionTemplate

使用线程安全的 TransactionTemplate 可以帮助开发者摆脱重复的代码，正如我们已经讨论过的 JdbcTemplate。它通过回调方法使程序化事务管理变得简单而强大。使用 TransactionTemplate 变得容易，因为它有各种事务属性的不同设置方法，如隔离级别、传播行为等。使用 Transaction 模板的第一步是通过提供事务管理器来获取其实例。第二步将是获取 TransactionCallback 的实例，该实例将传递给 execute 方法。以下示例将演示如何使用模板，我们不需要像早期应用程序中那样创建 TransactionDefinition，

1.  创建一个名为 Ch05_TransactionTemplate 的 Java 应用程序，并复制早期应用程序中所需的所有 jar 文件。

1.  我们将保持应用程序的结构与 Ch05_PlatformTransactionManager 应用程序相同，因此您可以复制 bean、dao 和服务包。我们唯一要做的改变是在 BookServiceImpl 中使用 TransactionTemplate 而不是 PlatformTransactionManager。

1.  从 BookServiceImpl 中删除 PlatformTransactionManager 数据成员并添加 TransactionTemplate。

1.  使用@Autowired 注解来使用 DI。

1.  我们将更新 searchBook()方法，使其使用 TransactionTemplate，并通过 setReadOnly(true)将其设置为只读事务。TransactionTemplate 有一个名为'execute()'的回调方法，可以在其中编写业务逻辑。该方法期望一个 TransactionCallback 的实例，并返回搜索到的书籍。代码如下所示：

```java
      @Service(value = "bookService") 
      public class BookServiceImpl implements BookService { 
        @Autowired 
        TransactionTemplate transactionTemplate; 

        @Autowired 
        BookDAO bookDAO; 

        public Book searchBook(long ISBN) { 
          transactionTemplate.setReadOnly(true);   
          return transactionTemplate.execute(new  
            TransactionCallback<Book>()  
          { 
            @Override 
            public Book doInTransaction(TransactionStatus status) { 
              // TODO Auto-generated method stub 
              Book book = bookDAO.serachBook(ISBN); 
              return book; 
          }     
        });  
      }  

```

为了执行任务，我们通过内部类的概念创建了 TransactionCallback 的实例。这里指定的泛型类型是 Book，因为它是 searchBook()方法的返回类型。这个类重写了 doInTransaction()方法，以调用 DAO 的 searchBook()方法中的业务逻辑。

还可以再实现一个 TransactionCallback 的版本，使用 TransactionCallbackWithoutResult。这种情况下可以用于服务方法没有返回任何内容，或者其返回类型为 void。

1.  现在让我们添加`addBook()`。我们首先必须使用`searchBook()`查找书籍是否存在于表中。如果书籍不存在，则添加书籍。但由于`searchBook()`使事务变为只读，我们需要更改行为。由于`addBook()`有布尔值作为其返回类型，我们将使用布尔类型的`TransactionCallBack`。代码将如下所示：

```java
      @Override 
      public boolean addBook(Book book) { 
        // TODO Auto-generated method stub 
        if (searchBook(book.getISBN()).getISBN() == 98564567l)  
        { 
          transactionTemplate.setReadOnly(false); 
          return transactionTemplate.execute(new  
            TransactionCallback<Boolean>()  
          { 
            @Override 
            public boolean doInTransaction(TransactionStatus status) { 
              try { 
                int rows = bookDAO.addBook(book); 
                if (rows > 0) 
                  return true; 
              } catch (Exception exception) { 
                status.setRollbackOnly(); 
              } 
              return false; 
            } 
          }); 
        } 
        return false; 
      } 

```

代码清楚地显示了 TransactionTemplate 赋予我们更改尚未内部管理的事务属性的能力，而无需编写 PlatformTransactionManager 所需的模板代码。

1.  同样，我们可以为`deleteBook`和`updateBook()`添加代码。你可以在线源代码中找到完整的代码。

1.  从`Ch05_PlatformTransactionmanager`类路径中复制`connection_new.xml`文件，并添加一个`TransactionTemplate`的 bean，如下所示：

```java
      <bean id="transactionTemplate"
        class="org.springframework.transaction.support.TransactionTemplate"> 
        <property name="transactionManager"  
          ref="transactionManager"></property> 
      </bean> 

```

我们已经有了一个事务管理器的 bean，所以我们在这里不会再次添加它。

1.  将`MainBookService_operations.java`文件复制到默认包中以测试代码。我们会发现代码成功执行。

1.  在继续前进之前，请按照如下方式修改`searchBook()`方法中的`doInTransaction()`代码；

```java
      public Book doInTransaction(TransactionStatus status) { 
        //Book book = bookDAO.serachBook(ISBN); 
        Book book=new Book(); 
        book.setISBN(ISBN); 
        bookDAO.addBook(book); 
        return book; 
      } 

```

1.  执行后，我们会得到一个堆栈跟踪，如下所示，它表示只读操作不允许修改数据：

```java
      Exception in thread "main" 
      org.springframework.dao.TransientDataAccessResourceException:  
      PreparedStatementCallback; SQL [insert into book values(?,?,?,?,?,?)];  
      Connection is read-only. Queries leading to data modification are not
      allowed; nested exception is java.sql.SQLException:
      Connection is read- only.  

```

#### 声明式事务管理

Spring 框架使用 AOP 来简化声明式事务管理。声明式事务管理最好的地方在于，它不一定需要由应用服务器管理，并且可以应用于任何类。该框架还通过使用 AOP，使开发者能够定制事务行为。声明式事务可以是基于 XML 的，也可以是基于注解的配置。

##### 基于 XML 的声明式事务管理：

该框架提供了回滚规则，用于指定事务将在哪种异常类型下回滚。回滚规则可以在 XML 中如下指定，

```java
<tx:advise id=:transactionAdvise" transaction-manager="transactionamanager">  
  <tx:attributes> 
     <tx:method name="find*" read-only="true" 
       rollback- for ="NoDataFoundException'> 
    </tx:attributes> 
  </tx:advise> 

```

配置甚至可以指定属性，例如，

+   '**no-rollback-for**' - 用以指定我们不想回滚事务的异常。

+   **传播** - 用以指定事务的传播行为，其默认值为'REQUIRED'。

+   **隔离** - 用以指定隔离级别。

+   **超时** - 以秒为单位的事务超时值，默认值为'-1'。

由于现在我们更倾向于使用注解事务管理，而不浪费时间，让我们继续讨论注解事务管理。

##### 基于注解的事务管理

`@Transaction`注解有助于开发基于注解的声明式事务管理，它可以应用于接口级别、类级别以及方法级别。要启用注解支持，需要配置以下配置以及事务管理器，

```java
<bean id="transactionManager" class=" your choice of transaction manager"> 
  <!-transaction manager configuration - -> 
</bean> 
<tx:annotation-driven transaction-manager="transcationManager"/> 

```

如果为 PlatformTransactionManager 编写的 bean 名称是'transactionManager'，则可以省略'transaction-manager'属性。

以下是可以用来自定义事务行为的属性，

+   **值** - 用于指定要使用的事务管理器。

+   **传播行为** - 用于指定传播行为。

+   **隔离级别** - 用于指定隔离级别。

+   **只读** - 用于指定读或写行为。

+   **超时** - 用于指定事务超时。

+   **rollbackForClassName** - 用于指定导致事务回滚的异常类数组。

+   **rollbackFor** - 用于指定导致事务回滚的异常类数组。

+   **noRollbackFor** - 用于指定不导致事务回滚的异常类数组。

+   **noRollbackForClassName** - 用于指定不导致事务回滚的异常类数组。

让我们使用@Transactional 来演示应用程序中的声明式事务管理，而不是使用以下步骤的帮助进行程序化事务管理：

1.  创建 Ch05_Declarative_Transaction_Management 并添加所需的 jar，就像在早期的应用程序中一样。

1.  从 Ch05_PlatformTransactionManager 应用程序中复制 com.packt.ch03.beans 和 com.packt.ch03.dao。

1.  在 com.packt.ch05.service 包中复制 BookService.java 接口。

1.  在 com.packt.ch05.service 包中创建 BookServiceImpl 类，并添加一个类型为 BookDAO 的数据成员。

1.  用@Autowired 注解类型为 BookDAO 的数据成员。

1.  用@Transactional(readOnly=true)注解 searchBook()，并编写使用 JdbcTemplate 搜索数据的代码。类如下：

```java
      @Service(value = "bookService") 
      public class BookServiceImpl implements BookService { 

        @Autowired 
        BookDAO bookDAO; 

        @Override 
        @Transactional(readOnly=true) 
        public Book searchBook(long ISBN)  
        { 
          Book book = bookDAO.serachBook(ISBN); 
          return book; 
        } 

```

1.  从 classpath 中的 Ch05_PlatformTransactionManager 复制 connection_new.xml。

1.  现在，我们需要告诉 Spring 找到所有被@Trasnactional 注解的 bean。通过在 XML 中添加以下配置即可简单完成：

```java
      <tx:annotation-driven /> 

```

1.  要添加上述配置，我们首先要在 XML 中添加'tx'作为命名空间。从 connection_new.xml 更新模式配置如下：

```java
      <beans xmlns="http://www.springframework.org/schema/beans" 
        xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"  
        xmlns:context="http://www.springframework.org/schema/context" 
        xmlns:tx="http://www.springframework.org/schema/tx" 
        xsi:schemaLocation="http://www.springframework.org/schema/beans 
        http://www.springframework.org/schema/beans/spring-beans.xsd  
        http://www.springframework.org/schema/context  
        http://www.springframework.org/schema/context/spring-context.xsd  
        http://www.springframework.org/schema/tx  
        http://www.springframework.org/schema/tx/spring-tx.xsd"> 

```

1.  现在，我们可以添加以下配置：

```java
      <tx:annotation-driven /> 

```

1.  复制 MainBookService_operation.java 并执行它以获得输出。

1.  现在添加 addBook()方法以理解 readOnly=true。代码如下：

```java
      @Transactional(readOnly=true) 
      public boolean addBook(Book book) { 
        if (searchBook(book.getISBN()).getISBN() == 98564567l) { 
          System.out.println("no book"); 
          int rows = bookDAO.addBook(book); 

          if (rows > 0) { 
            return true; 
          } 
        } 
        return false;  
      } 

```

1.  执行 MainBookService_operation.java，并执行它以获得以下输出，指定不允许读取事务修改数据：

```java
      Exception in thread "main" 
      org.springframework.dao.TransientDataAccessResourceException:  
      PreparedStatementCallback; SQL [insert into book values(?,?,?,?,?,?)];
      Connection is read-only. Queries leading to data modification are not
      allowed; nested exception is java.sql.SQLException:Connection is read-only.
      Queries leading to data modification are not allowed 

```

1.  编辑 addBook()方法，通过指定 read-only=false 来移除只读事务，这是事务的默认行为。

1.  主要代码将成功执行操作。

### 注意

如果应用程序具有少量事务操作，可以使用 TransactionTemplate 进行程序化事务管理。在拥有大量事务操作的情况下，为了保持简单和一致，选择声明式事务管理。

## 总结

****

在这一章中，我们讨论了事务以及为什么它很重要。我们还讨论了事务管理及其生命周期。我们讨论了事务属性，如只读、隔离级别、传播行为和超时。我们看到了声明性和编程性作为处理事务的两种方式，其中一种使另一种摆脱了管道代码，而另一种提供了对操作的精细控制。我们还通过一个应用程序讨论了这两种技术，以更好地理解。到目前为止，我们讨论了如何处理想象中的数据。我们需要一种方法将其实际地提供给用户。

在下一章中，我们将探索如何开发一个应用程序的 Web 层，以便让我们进行用户交互。


## 第六章。探索 Spring MVC

到目前为止，我们已经讨论了如何使用 Spring 框架来处理、初始化和使用数据，同时将控制台作为我们的输出。我们还没有在呈现或用户交互方面付出任何努力。在当今世界，使用老式的基于窗口的、非常单调的呈现方式工作似乎非常无聊。我们希望有更有趣、更令人兴奋的东西。互联网是使世界比以往任何时候都更加紧密和有趣的“东西”。当今的世界是网络的世界，那么我们如何能与之脱节呢？让我们深入到一个令人惊叹的互联网世界，借助以下几点来探索 Spring 的强大功能：

+   为什么有必要学习使用 Spring 进行网络应用程序开发？

+   如何使用 Spring MVC 开发网络应用程序？

+   Spring MVC 的不同组件有哪些？

+   如何预填充表单并将数据绑定到对象？

+   我们还将讨论如何在 Spring 中执行验证。

在 20 世纪 90 年代，互联网为我们打开了一个完全新世界的大门。这是一个前所未有的数据海洋。在互联网之前，数据只能通过硬拷贝获得，主要是书籍和杂志。在早期，互联网只是用来分享静态数据，但随着时间的推移，互联网的维度、意义和用途发生了很大变化。如今，我们无法想象没有互联网的世界。这几乎是不可思议的。它已经成为我们日常生活中的一部分，也是我们业务行业的一个非常重要的来源。对于我们开发者来说，了解网络应用程序、其开发、挑战以及如何克服这些挑战也非常重要。

在 Java 中，可以使用 Servlet 和 JSP 创建基本网络应用程序，但随后发生了许多演变。这些演变主要是由于不断变化的世界对高需求的时间紧迫。不仅是呈现方式，而且整个网络体验也因 HTML5、CSS、JavaScript、AJAX、Jquery 等类似技术的使用而发生了变化。Servlet 处理网络请求并使用请求参数中的数据提取动态网络应用程序的数据。

在使用 Servlet 和 JSP 时，开发者必须付出很多努力来执行数据转换并将数据绑定到对象。除了执行业务逻辑的主要角色外，他们现在还必须处理额外的负担，即处理请求和响应呈现。

开发者主要在 web 应用程序中处理从请求提取的数据。他们根据规则开发复杂、较长的业务逻辑来执行任务。但如果从请求参数中提取的数据不正确，这一切都是徒劳的。这显然不是开发者的错，但他们的业务逻辑仍然受到影响，使用这样的数据值进行业务逻辑是没有意义的。开发者现在需要特别注意，在执行业务逻辑之前，首先要找出从请求中提取的数据是否正确。开发者还必须 extensively 参与数据呈现到响应中。首先，开发者需要将数据绑定到响应中，然后进一步如何在呈现方面提取它。

上述讨论的每一个任务都在有限的时间内给开发方增加了额外的负担。Spring 框架通过以下特性方便开发者进行简单和快速的开发：

+   Spring 框架支持 MVC 架构，实现了模型、视图和控制器的清晰分离。

+   该框架通过将请求参数绑定到命令对象，为开发者提供了豆子的力量，以便轻松处理数据。

+   它提供了对请求参数的简单验证，执行验证 either with Validator interface or using annotations. 它还可以支持自定义验证规则。

+   它提供了如@RequestParam、@RequestHeader 等注解，这些注解使请求数据绑定到方法参数而不涉及 Servlet API。

+   它支持广泛的视图模板，如 JSTL、Freemarker、Velocity 等。

+   通过使用 ModelMap 对象，使数据从控制器传输到视图变得容易。

+   它可以轻松地与其他框架集成，如 Apache Struts2.0、JSF 等。

通常，web 应用程序部署在 web 服务器上。应用程序中的每个资源都与 URL 映射，用户使用这些 URL 来访问资源。Servlet 或 JSP 从请求对象中读取数据，对其执行业务逻辑，然后将响应作为结果返回。我们都知道，在任何 web 应用程序中，都会发生这种一般的流程。在这个流程中，最重要的是这些 web 应用程序没有任何 Servlet 或控制器来管理整个应用程序的流程。是的，第一个到达者缺席了。整个应用程序及其流程必须由开发方维护。这就是 Servlet 和 Spring 之间的主要区别所在。

****

Spring 框架采用 MVC 设计模式，提供了一个前端控制器，处理或获取应用程序接收到的每个请求。以下图表显示了 Spring MVC 如何处理请求以及所有组件都是 Spring MVC 的一部分：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/lrn-spr5/img/image_06_001.jpg)

以下步骤为我们提供了 Spring MVC 网络应用程序流程的方向：

+   每个传入请求首先会击中应用程序的心脏——前端控制器。前端控制器将请求分发到处理器，并允许开发者使用框架的不同功能。

+   前端控制器有自己的 WebApplicationContext，它是从根 WebApplicationContext 继承而来的。根上下文配置的 bean 可以在应用的上下文和 Servlet 实例之间访问和共享。类似于所有 Servlet，前端控制器在第一次请求时进行初始化。

+   一旦前端控制器初始化完成，它会寻找位于 WEB-INF 文件夹下名为`servlet_name-servlet.xml`的 XML 文件。该文件包含了 MVC 特定的组件。

+   这个配置文件默认命名为`XXX-servlet.xml`，位于 WEB-INF 文件夹下。这个文件包含了 URL 到可以处理传入请求的控制器的映射信息。在 Spring 2.5 之前，映射是发现处理器的必须步骤，现在我们不再需要。我们现在可以直接使用基于注解的控制器。

+   `RequestMappingHandlerMapping`会搜索所有控制器，查找带有`@RequestMapping`注解的@Controller。这些处理器可以用来自定义 URL 的搜索方式，通过自定义拦截器、默认处理器、顺序、总是使用完整路径、URL 解码等属性。

+   在扫描所有用户定义的控制器之后，会根据 URL 映射选择合适的控制器并调用相应的方法。方法的选择是基于 URL 映射和它支持的 HTTP 方法进行的。

+   在执行控制器方法中编写的业务逻辑后，现在是生成响应的时候了。这与我们通常的 HTTPResponse 不同，它不会直接提供给用户。相反，响应将被发送到前端控制器。在这里，响应包含视图的逻辑名称、模型数据的逻辑名称和实际的数据绑定。通常，`ModelAndView`实例会被返回给前端控制器。

+   逻辑视图名在前端控制器中，但它不提供有关实际视图页面的任何信息。在`XXX-servlet.xml`文件中配置的`ViewResolver`bean 将作为中介，将视图名称映射到实际页面。框架支持广泛的视图解析器，我们将在稍后讨论它们。

+   视图解析器帮助获取前端控制器可以作为响应返回的实际视图。前端控制器通过从绑定的模型数据中提取值来渲染它，然后将其返回给用户。

在我们讨论的流程中，我们使用了诸如前端控制器、ModelAndView、ViewResolver、ModelMap 等许多名称。让我们深入讨论这些类。

### 分发器 Servlet

`DispacherServlet`在 Spring MVC 应用程序中充当前端控制器，首先接收每个传入请求。它基本上用于处理 HTTP 请求，因为它从`HTTPServlet`继承而来。它将请求委托给控制器，解决要作为响应返回的视图。以下配置显示了在`web.xml`（部署描述符）中的调度器映射：

```java
<servlet>
  <servlet-name>books</servlet-name>
    <servlet-class>
      org.springframework.web.servlet.DispatcherServlet
    </servlet-class>
</servlet>
<servlet-mapping>
  <servlet-name>books</servlet-name>
  <url-pattern>*.htm</url-pattern>
</servlet-mapping>
```

上述配置说明所有以`.htm`为 URL 模式的请求将由名为`books`的 Servlet 处理。

有时应用程序需要多个配置文件，其中一些位于根`WebApplicationContext`中，处理数据库的 bean，一些位于 Servlet 应用程序上下文中，包含在控制器中使用的 bean。以下配置可用于初始化来自多个`WebApplicationContext`的 bean。以下配置可用于从上下文中加载多个配置文件，例如：

```java
<servlet>
  <servlet-name>books</servlet-name>
    <servlet-class>
      org.springframework.web.servlet.DispatcherServlet
    </servlet-class>
</servlet>
<servlet-mapping>
  <servlet-name>books</servlet-name>
  <url-pattern>*.htm</url-pattern>
</servlet-mapping>
```

### 控制器

Spring 控制器用于处理执行业务逻辑的请求，这些控制器也可以被称为'处理器'，其方法称为处理器方法。Spring 提供了`AbstarctUrlViewController`、`ParameterizableViewContoller`、`ServletForwardingConroller`、`ServletWrappingControllerBefore`作为控制器。在 Spring 2.5 基于 web 的应用程序中，需要对这些控制器进行子类化以自定义控制器。但现在，Spring 通过`@Controller`注解支持注解驱动的控制器。以下配置启用了基于注解的控制器：

```java
<mvc:annotation-driven />
```

需要发现基于注解的控制器以执行处理器方法。以下配置提供了关于框架应扫描哪些包以发现控制器的信息：

```java
<context:component-scan base-package="com.packt.*">
</context:component-scan>
```

`@RequestMapping`注解用于标注类或方法，以声明它能处理的特定 URL。有时同一个 URL 可以注解多个方法，这些方法支持不同的 HTTP 方法。`@RequestMapping`的'method=RequestMethod.GET'属性用于指定哪个 HTTP 方法将由该方法处理。

### `ModelAndView`

`ModelAndView`在生成响应中扮演着重要角色。`ModelAndView`实例使得可以将模型数据绑定到其逻辑名称、逻辑视图名称。在视图中使用的数据对象通常称为模型数据。以下代码段清楚地说明了绑定是如何发生的：

```java
new ModelAndView(logical_name_of_view,logical_name_of_model_data,
  actual_value_of_model_data);
```

我们甚至可以使用以下代码段：

```java
ModelAndView mv=new ModelAndView();
mv.setViewName("name_of_the_view");
mv.setAttribute(object_to_add);
```

### `ModelMap`

`ModelMap`接口是`LinkedHashMap`的子类，在构建使用键值对的模型数据时使用。它有`addAttribute()`方法，提供模型和模型逻辑名称的绑定。在`ModelMap`中设置的属性可以在表单提交时由视图用于表单数据绑定。我们稍后会深入讨论这一点。

### 视图解析器

用户定义的控制器返回的逻辑视图名称和其他详细信息。视图名称是一个需要由 ViewResolver 解析的字符串。

以下是一些可以用于渲染视图的 ViewResolvers：

+   **XmlViewResolver**：XmlViewResolver 用于查看编写为 XML 的文件。它使用位于 WEB-INF/views.xml 的默认配置，该配置文件包含与 Spring beans 配置文件相同的 DTD 的视图 bean。配置可以如下所示编写：

```java
      <bean id="myHome"  
        class="org.springframework.web.servlet.view.JstlView"> 
        <property name="url" value="WEB-INF/jsp/home.jsp"/> 
      <bean> 

```

+   逻辑视图名 '`myHome`' 被映射到实际的视图 '`WEB-INF/jsp/home.jsp`'。

+   一个 bean 也可以引用映射到另一个 bean 的视图，如下所示：

```java
      <bean id="logout"  
        class="org.springframework.web.servlet.view.RenderView"> 
        <property name="url" value="myHome"/> 
      <bean> 

```

+   `'logout'` bean 没有映射到任何实际的视图文件，但它使用 '`myHome'` bean 来提供实际的视图文件。

+   **UrlBasedViewResolver:** 它将 URL 直接映射到逻辑视图名称。当逻辑名称与视图资源相匹配时，它将被优先考虑。它的前缀和后缀作为其属性，有助于获取带有其位置的实际视图名称。该类无法解析基于当前区域设置的视图。为了启用 URLBasedViewResolver，可以编写以下配置：

```java
      <bean id="viewResolver" 
  class="org.springframework.web.servlet.view.UrlBasedViewResolver"> 
        <property name="viewClass" value=   
          "org.springframework.web.servlet.view.JstlView"/> 
        <property name="prefix" value="WEB-INF/jsp/"/> 
        <property name="suffix" value=".jsp"/> 
      <bean> 

```

+   `JstlView` 用于渲染视图页面。在我们的案例中，页面名称和位置是 'prefix+ view_name_from_controller+suffix'。

+   **InternalResourceViewResolver:** InternalResourceViewresolver 是 UrlBasedViewResolver 的子类，用于解析内部资源，这些资源可以作为视图使用，类似于其父类的前缀和后缀属性。AlwaysInclude、ExposeContextBeansAsAttributes、ExposedContextBeanNames 是该类的几个额外属性，使其比父类更频繁地使用。以下配置与之前示例中配置 UrlBasedViewResolver 的方式类似：

```java
      <bean id="viewResolver" class=  
  "org.springframework.web.servlet.view.InternalResourceViewResolver"> 
        <property name="viewClass" value=                
          "org.springframework.web.servlet.view.JstlView"/> 
        <property name="prefix" value="WEB-INF/jsp/"/> 
        <property name="suffix" value=".jsp"/> 
      <bean> 

```

+   它只能在到达页面时验证页面的存在，在此之前不会进行验证。

+   **ResourceBundleViewResolver:** ResourceBundleViewResolver 使用配置中指定的 ResourceBundle 的定义。默认文件用于定义配置的是 views.properties。配置将如下所示：

```java
      <bean id="viewResolver" class= 
  "org.springframework.web.servlet.view.ResourceViewResolver"> 
        <property name="base" value="web_view"/> 
      </bean> 

```

+   视图.properties 将指定要使用的视图类的详细信息以及实际视图的 URL 映射，如下所示：

```java
      home.(class)= org.springframework.wev.servlet.view.JstlView 

```

+   下面的行指定了名为 homepage 的视图的映射：

```java
       homepage.url= /WEB-INF/page/welcome.jsp 

```

+   **TilesViewResolver:** Tiles 框架用于定义可以重用并保持应用程序一致的外观和感觉的页面布局模板。在 'tiles.def' 文件中定义的页面定义作为 tile、header、footer、menus，在运行时组装到页面中。控制器返回的逻辑名称与视图解析器将渲染的 tiles 模板名称匹配。

除了上面讨论的视图解析器之外，Spring 还具有 FreeMarkerViewResolver、TileViewResolver、VelocityLayoutViewResolver、VelocityViewResolver、XsltViewResolver。

在继续讨论之前，让我们首先开发一个示例演示，以详细了解应用程序的流程，并通过以下步骤了解上述讨论的方向：

1.  创建一个名为 Ch06_Demo_SpringMVC 的动态网页应用程序。

1.  按照以下项目结构复制 spring-core、spring-context、commons-logging、spring-web 和 spring-webmvc 的 jar 文件：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/lrn-spr5/img/image_06_002.png)

1.  在**`WebContent`**文件夹中创建 index.jsp，作为主页。可以根据你的需求自定义名称，就像我们在任何 Servlet 应用程序中所做的那样。

1.  在`index.jsp`中添加一个链接，该链接提供导航到控制器，如下所示：

```java
      <center> 
        <img alt="bookshelf" src="img/img1.png" height="180" 
          width="350"> 
        <br> 
      </center> 
      <a href="welcomeController.htm">Show welcome message</a> 

```

1.  每当用户点击链接时，系统会生成一个带有'welcomeCointroller.htm' URL 的请求，该请求将由前端控制器处理。

1.  是时候在`web.xml`中配置前端控制器了：

```java
      <servlet> 
        <servlet-name>books</servlet-name> 
        <servlet-class>    
          org.springframework.web.servlet.DispatcherServlet 
        </servlet-class> 
      </servlet> 
      <servlet-mapping> 
        <servlet-name>books</servlet-name> 
        <url-pattern>*.htm</url-pattern> 
      </servlet-mapping> 

```

1.  前端控制器查找 WEB-INF 中名为`servlet_name-servlet.xml`的文件来查找和调用控制器的的方法。在我们的案例中，Servlet 的名称是'`books`'。所以让我们在 WEB-INF 文件夹下创建一个名为'`books-servlet.xml`'的文件。

1.  该文件应包含 Spring 容器将扫描以查找控制器的包的配置。配置将如下所示：

```java
      <context:component-scan base-package=     
        "com.packt.*"></context:component-scan> 

```

上述配置说明将扫描'`com.packt`'包中的所有控制器。

1.  在 com.packt.ch06.controllers 包中创建一个`MyMVCController`类。

1.  通过`@Controller`注解类。注解类使其能够使用处理请求的功能。

1.  让我们通过如下所示的`@RequestMapping`注解添加`welome()`方法来处理请求：

```java
      @Controller 
      public class MyMVCController { 
        @RequestMapping(value="welcomeController.htm") 
        public ModelAndView welcome() 
        { 
          String welcome_message="Welcome to the wonderful  
          world of Books"; 
          return new ModelAndView("welcome","message",welcome_message); 
        } 
      } 

```

控制器可以有多个方法，这些方法将根据 URL 映射被调用。在这里，我们声明了将被`welcomeController.htm'` URL 调用的方法。

该方法通过`ModelAndView`生成欢迎信息并生成响应，如下所示：

```java
      new ModelAndView("welcome","message",welcome_message); 
      The ModelAndView instance is specifying, 
      Logical name of the view -  welcome 
      Logical name of the model data -  message  
      Actual value of the model data - welcome_message 

```

以上代码的替代方案，你可以使用如下代码：

```java
      ModelAndView mv=new ModelAndView(); 
      mv.setViewName("welcome"); 
      mv.addObject("message", welcome_message); 
      return mv; 

```

我们可以将多个方法映射到相同的 URL，支持不同的 HTTP 方法，如下所示：

```java
      @RequestMapping(value="welcomeController.htm", 
        method=RequestMethod.GET) 
      public ModelAndView welcome(){ 
        //business logic  
      } 
      @RequestMapping(value="welcomeController.htm", 
        method=RequestMethod.POST) 
      public ModelAndView welcome_new()  { 
        //business logic 
      } 

```

1.  如以下所示，在`books-servlet.xml`中配置`ViewResolver` bean：

```java
      <bean id="viewResolver" class=
   "org.springframework.web.servlet.view.InternalResourceViewResolver"> 
        <property name="prefix" value="/WEB-INF/jsps/"></property> 
        <property name="suffix" value=".jsp"></property> 
      </bean> 

```

`ViewResolver`帮助前端控制器获取实际的视图名称和位置。在前端控制器返回给浏览器的响应页面中，在我们的案例中将是：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/lrn-spr5/img/image_06_003.png)

1.  在 WebContent 中创建一个名为 jsps 的文件夹。

1.  在 jsps 文件夹中创建一个 welcome.jsp 页面，使用表达式语言显示欢迎信息：

```java
      <body> 
        <center> 
          <img alt="bookshelf" src="img/img1.png" height="180" 
            width="350"> 
          <br> 
        </center> 
        <center> 
          <font color="green" size="12"> ${message } </font> 
        </center> 
      </body>
```

在 EL 中使用属性'`message'`，因为这是我们控制器方法中用于`ModelAndView`对象逻辑模型名称。

1.  配置好 tomcat 服务器并运行应用程序。在浏览器中将显示链接。点击链接我们将看到如下截图的输出：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/lrn-spr5/img/image_06_004.png)

该演示向我们介绍了 Spring MVC 流程。现在让我们逐步开发书籍应用程序，涵盖以下案例：

+   读取请求参数

+   处理表单提交

### 案例 1：读取请求参数

让我们开始通过以下步骤读取请求参数：

1.  创建 ReadMyBooks 作为动态网络应用程序，并像我们之前那样添加所有必需的 jar 文件。

1.  每个应用程序都有一个主页。所以，让我们将之前的应用程序中的 index.jsp 作为主页添加进去。您可以直接复制和粘贴。

1.  从之前的应用程序中复制 images 文件夹。

1.  在下面所示的位置添加一个链接，用于搜索按作者姓名查找书籍，

```java
      <a href="searchByAuthor.jsp">Search Book By Author</a> 

```

1.  让我们添加一个名为 searchByAuthor.jsp 的页面，使用户可以输入作者姓名来请求书籍列表，如下所示：

```java
      <body> 
        <center> 
          <img alt="bookshelf" src="img/img1.png" height="180"  
            width="350"> 
          <br> 

          <h3>Add the Author name to search the book List</h3> 

          <form action="/searchBooks.htm"> 
            Author Name:<input type="text" name="author"> 
            <br>  
            <input  type="submit" value="Search Books"> 
          </form> 
        </center> 
      </body>
```

1.  如我们之前所做的那样，在 web.xml 中为 DispachetServlet 作为前端控制器添加配置，并将 servlet 命名为'books'。

1.  创建或复制 books-servlet.xml，用于从早期应用程序配置处理映射和其他网络组件映射。

1.  使用'context'命名空间添加扫描控制器的配置。

1.  我们需要 Book bean 来处理数据往返于控制器。因此，在开发控制器代码之前，请将 Book.java 添加到我们之前应用的 com.packt.ch06.beans 包中，数据成员如下所示：

```java
      public class Book { 
        private String bookName; 
        private long ISBN; 
        private String publication; 
        private int price; 
        private String description; 
        private String author; 
        //getters and setters 
      } 

```

1.  现在在 com.packt.ch06.controllers 包中创建一个名为 SearchBookController 的类作为控制器，并用@Controller 注解它。

1.  为了搜索书籍，需要添加一个名为 searchBookByAuthor()的方法，并用@RequestMapping 注解为'searchBooks.htm'的 URL。我们可以使用 Servlet API 或 Spring API，但在这里我们将使用 Spring API。

1.  现在让我们为`searchBookByAuthor()`添加以下代码：

+   阅读请求参数

+   搜索书籍列表

1.  创建 ModelAndView 实例以将书籍列表作为模型数据，逻辑模型名称和逻辑视图名称一起绑定。

代码将如下所示：

```java
      @Controller 
      public class SearchBookController { 
        @RequestMapping(value = "searchBooks.htm") 
        public ModelAndView searchBookByAuthor( 
          @RequestParam("author") String author_name)  
        { 
          // the elements to list generated below will be added by      
          business logic  
          List<Book> books = new ArrayList<Book>(); 
          books.add(new Book("Learning Modular Java Programming",  
            9781235, "packt pub publication", 800, 
            "Explore the Power of Modular Programming ",  
            "T.M.Jog")); 
          books.add(new Book("Learning Modular Java Programming",  
            9781235, "packt pub publication", 800, 
            "Explore the Power of Modular Programming ",   
            "T.M.Jog")); 
          mv.addObject("auth_name",author); 
          return new ModelAndView("display", "book_list", books); 
        } 
      } 

```

`@RequestParam`用于读取请求参数并将它绑定到方法参数。'author'属性的值被绑定到 author_name 参数，而不会暴露 servlet API。

在这里，我们添加了一个虚拟列表。稍后，可以将其替换为从持久层获取数据的实际代码。

1.  是时候在 books-servlet.xml 中配置视图解析器和包扫描，就像我们之前在早期应用程序中做的那样。我们可以将 books-servlet.xml 从早期应用程序的 WEB-INF 中复制粘贴过来。

1.  在 WebContent 下创建 jsps 文件夹，该文件夹将包含 jsp 页面。

1.  在 jsps 文件夹中创建 display.jsp，使用 JSTL 标签显示书籍列表，如下所示：

```java
      <%@ taglib prefix="jstl"  
        uri="http://java.sun.com/jsp/jstl/core"%> 
      <html> 
        <head> 
          <meta http-equiv="Content-Type" content="text/html; 
            charset=ISO-8859-1"> 
          <title>Book List</title> 
        </head> 
        <body> 
          <center> 
            <img alt="bookshelf" src="img/img1.png"   
              height="180" width="350"> 
            <br> 
          </center> 
          <jstl:if test="${not empty book_list }"> 
            <h1 align="center"> 
              <font color="green"> 
                Book List of ${auth_name } 
              </font> 
            </h1> 
            <table align="center" border="1"> 
            <tr> 
              <th>Book Name</th> 
              <th>ISBN</th> 
              <th>Publication</th> 
              <th>Price</th> 
              <th>Description</th> 
            </tr> 
            <jstl:forEach var="book_data"  
              items="${book_list}" varStatus="st"> 
              <tr> 
                <td> 
                  <jstl:out value="${ book_data.bookName }"> 
                  </jstl:out> 
                </td> 
                <td> 
                  <jstl:out value="${ book_data.ISBN }"> 
                  </jstl:out> 
                </td> 
                <td> 
                  <jstl:out value="${ book_data.publication }"> 
                  </jstl:out> 
                </td> 
                <td> 
                  <jstl:out value="${ book_data.price }"> 
                  </jstl:out></td> 
                <td> 
                  <jstl:out value="${ book_data.description }"> 
                  </jstl:out> 
                </td> 
              </tr> 
            </jstl:forEach> 
          </table> 
        </jstl:if> 
        <jstl:if test="${empty book_list }"> 
          <jstl:out value="No Book Found"></jstl:out> 
        </jstl:if> 
      </body>
```

如果列表没有元素，就没有显示该列表的必要。jstl:if 标签用于决定是否显示列表，而 jstl:forEach 标签用于通过迭代列表显示书籍信息。

1.  运行应用程序，点击主页上的链接以加载表单以输入作者名称。如果作者名称存在，则在表单提交时我们将获得以下书籍列表：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/lrn-spr5/img/image_06_005.png)

这里，我们使用了`@RequestParam`将个别请求参数绑定到方法参数。但是，如果请求参数的名称与方法参数的名称匹配，则无需使用注解。更新后的代码可以如下所示：

```java
@RequestMapping(value = "searchBooks.htm") 
public ModelAndView searchBookByAuthor( String author) { 
  List<Book> books = new ArrayList<Book>(); 
  books.add(new Book("Learning Modular Java Programming",  
    9781235, "packt pub publication", 800, 
    "explore the power of modular Programming ",    
    author)); 
  books.add(new Book("Learning Modular Java Programming",  
    9781235, "packt pub publication", 800, 
    "explore the power of modular Programming ",  
    author)); 
  ModelAndView mv= 
    new ModelAndView("display", "book_list", books); 
    mv.addObject("auth_name",author); 
    return mv; 
} 

```

逐一读取个别请求参数，然后将它们绑定到 bean 对象，变得繁琐而不必要冗长。框架通过处理“表单后盾对象”提供了更好的选项。

### 情况 2：处理表单提交

表单提交是应用程序开发中非常常见的任务。每次表单提交时，开发者都需要执行以下步骤：

1.  读取请求参数

1.  将请求参数值转换为所需数据类型

1.  将值设置到 bean 对象中。

上述步骤可以省略，直接在表单提交时获取 bean 实例。我们将讨论两种情况的表单处理：

+   表单提交

+   表单预处理

#### 表单提交

在普通的网络应用程序中，用户点击一个链接后，表单会被加载，然后手动执行上述讨论的步骤。由于需要自动化这个过程，而不是直接显示表单，因此应该从控制器加载表单，而该控制器已经有一个 bean 实例。在表单提交时，用户输入的值会被绑定到这个实例。现在，这个实例可以在控制器中用于执行业务逻辑。从 Spring 2.0 开始，提供了一组标签，这些标签在视图中处理表单绑定，从而使开发变得容易。

让我们在 ReadMyBooks 应用程序中添加一个表单，以了解使用 Spring 提供的表单标签进行表单提交。我们将分两步进行，第一步显示表单，第二步处理提交的表单。

##### 显示表单

由于表单必须从控制器加载，让我们按照以下步骤添加代码，

1.  在主页上添加一个链接以加载表单。获取表单的代码如下所示：

```java
      <a href="showBookForm.htm">Show Form to add new Book</a> 

```

1.  在`AddBookController`中添加`showBookForm()`方法，该方法将在步骤 1 中点击的链接上被调用。该方法将返回一个表单页面，使用 Book 对象，其中输入的数据将被绑定。该方法的代码如下，

```java
      @RequestMapping("/showBookForm.htm") 
      public ModelAndView showBookForm(ModelMap map)  
      throws Exception { 
        Book book=new Book(); 
        map.addAttribute(book); 
        return new ModelAndView("bookForm"); 
      } 

```

该方法应该有一个`ModelMap`作为其参数之一，以添加一个 bean 实例，该实例可以被视图使用。在这里，我们添加了'book'属性，其值为 book 实例。默认情况下，引用名将被用作属性名。'book'实例也可以被称为“表单后盾”对象。为了自定义在视图中使用的表单后盾对象的名称，我们可以使用以下代码：

```java
      map.addAttribute("myBook",book); 

```

1.  因为视图名称'`bookForm'`由控制器返回，所以在 jsps 文件夹中添加`bookForm.jsp`，该文件包含显示表单的表单。

1.  用户输入的值需要绑定到表单。Spring 框架提供了强大的标签来处理用户输入。为了使 Spring 标签生效，我们需要添加如下所示的'taglib'指令：

```java
      <%@ taglib prefix="form"  
        uri="http://www.springframework.org/tags/form"%> 

```

1.  Spring 提供了与 html 类似的标签来处理表单、输入、复选框、按钮等，主要区别在于它们的值隐式绑定到 bean 数据成员。以下代码将允许用户输入书籍名称，并在表单提交时将其绑定到 Book bean 的'bookName'数据成员：

```java
      <form:input path="bookName" size="30" /> 

```

'path'属性将输入值映射到 bean 数据成员。值必须按照数据成员的名称指定。

1.  让我们在 bookForm.jsp 中添加以下表单，以便用户输入新书籍的值：

```java
      <form:form modelAttribute="book" method="POST"  
        action="addBook.htm"> 
        <h2> 
          <center>Enter the Book Details</center> 
        </h2> 

        <table width="100%" height="150" align="center" border="0"> 
         <tr> 
           <td width="50%" align="right">Name of the Book</td> 
           <td width="50%" align="left"> 
             <form:input path="bookName" size="30" /> 
           </td> 
         </tr> 
         <tr> 
           <td width="50%" align="right">ISBN number</td> 
           <td width="50%" align="left"> 
             <form:input path="ISBN" size="30" /> 
           </td> 
         </tr> 
         <tr> 
           <td width="50%" align="right">Name of the Author</td> 
           <td width="50%" align="left"> 
             <form:input path="author" size="30" /> 
           </td> 
         </tr> 
         <tr> 
           <td width="50%" align="right">Price of the Book</td> 
           <td width="50%" align="left"> 
             <form:select path="price"> 
               <!- 
                 We will add the code to have  
                 predefined values here  
               -->             
             </form:select> 
           </td> 
         </tr> 
         <tr> 
           <td width="50%" align="right">Description of the  
             Book</td> 
           <td width="50%" align="left"> 
             <form:input path="description"  size="30" /> 
           </td> 
         </tr> 
         <tr> 
           <td width="50%" align="right">Publication of the  
             Book</td> 
           <td width="50%" align="left"> 
             <form:input path="publication"  size="30" /> 
           </td> 
         </tr> 
         <tr> 
           <td colspan="2" align="center"><input type="submit"  
             value="Add Book"></td> 
          </tr> 
        </table> 
      </form:form>
```

属性'modelAttribute'接收由控制器设置的 ModelMap 逻辑属性的值。

1.  运行应用程序并点击'**`Show Form to add new book`**'。

1.  您将被导航到 bookForm.jsp 页面，在那里您可以输入自己的值。提交后，您将得到 404 错误，因为没有资源被我们编写来处理请求。别担心！！在接下来的步骤中我们将处理表单。

##### 表单后处理

1.  让我们在 AddController 中添加一个方法，该方法将在表单提交时通过 url 'addBook.htm'调用，如下所示：

```java
      @RequestMapping("/addBook.htm") 
      public ModelAndView addBook(@ModelAttribute("book") Book book) 
      throws Exception { 
          ModelAndView modelAndView = new ModelAndView(); 
          modelAndView.setViewName("display"); 
          //later on the list will be fetched from the table 
          List<Book>books=new ArrayList(); 
          books.add(book); 
          modelAndView.addObject("book_list",books); 
          return modelAndView; 
      } 

```

当用户提交表单时，他输入的值将被绑定到 bean 数据成员，生成一个 Book bean 的实例。通过@ModelAttribute 注解'book'参数使开发者可以使用绑定值的 bean 实例。现在，无需读取单个参数，进一步获取和设置 Book 实例。

因为我们已经有了 display.jsp 页面来显示书籍，所以我们在这里只是重用它。用户输入的书籍详情稍后可以添加到书籍表中。

1.  运行应用程序，点击链接获取表单。填写表单并提交以获得以下输出：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/lrn-spr5/img/image_06_006.png)

输出列表显示了书籍的详细信息，但没有价格，因为价格目前没有设置。我们想要一个带有预定义值的价格列表。让我们继续讨论表单的预处理。

#### 表单预处理

在某些情况下，表单包含一些预定义值，如国家名称或书籍类别的下拉菜单、可供选择的颜色的单选按钮等。这些值可以硬编码，导致频繁更改要显示的值。相反，可以使用常量值，值可以被渲染并在表单中填充。这通常称为表单预处理。预处理可以在两个步骤中完成。

##### 定义要在视图中添加的属性的值

`@ModelAttribute`用于将模型数据的实例添加到 Model 实例中。每个用@ModelAttribute 注解的方法在其他 Controller 方法之前和执行时都会被调用，并在执行时将模型数据添加到 Spring 模型中。使用该注解的语法如下：

```java
@ModelAttribute("name_of_the_attribute") 
access_specifier return_type name_of_method(argument_list) {  // code   } 

```

以下代码添加了一个名为'hobbies'的属性，该属性可在视图中使用：

```java
@ModelAttribute("hobbies") 
public List<Hobby> addAttribute() { 
  List<Hobby> hobbies=new ArrayList<Hobby>(); 
  hobbies.add(new Hobby("reading",1)); 
  hobbies.add(new Hobby("swimming",2)); 
  hobbies.add(new Hobby("dancing",3)); 
  hobbies.add(new Hobby("paining",4)); 
  return hobbies; 
} 

```

Hobby 是一个用户定义的类，其中包含 hobbyName 和 hobbyId 作为数据成员。

##### 在表单中填充属性的值

表单可以使用复选框、下拉菜单或单选按钮向用户显示可用的选项列表。视图中的值可以使用列表、映射或数组为下拉菜单、复选框或单选按钮的值。

标签的一般语法如下所示：

```java
<form:name-of_tag path="name_of_data_memeber_of_bean"  
  items="name_of_attribute" itemLable="value_to display"  
  itemValue="value_it_holds"> 

```

以下代码可用于使用'hobbies'作为模型属性绑定值到 bean 的 hobby 数据成员，在复选框中显示用户的爱好：

```java
<form:checkboxes path="hobby" items="${hobbies}"    
  itemLabel="hobbyName" itemValue="hobbyId"/>                 

```

同样，我们可以在运行时为选择标签生成下拉菜单和选项。

### 注意

当处理字符串值时，可以省略`itemLabel`和`itemValue`属性。

完整的示例可以参考应用程序`Ch06_Form_PrePopulation`。

让我们更新`ReadMyBooks`应用程序，在`bookForm.jsp`中预定义一些价格值，并使用'`ModelAttribute`'讨论以下步骤中的表单预处理：

1.  因为表单是由`AddController`返回到前端控制器，我们想在其中设置预定义的值，因此在`addPrices()`方法中添加注解。如下所示使用`@ModelAttribute`注解：

```java
      @ModelAttribute("priceList") 
      public List<Integer> addPrices() { 
        List<Integer> prices=new ArrayList<Integer>(); 
        prices.add(300); 
        prices.add(350); 
        prices.add(400); 
        prices.add(500); 
        prices.add(550); 
        prices.add(600); 
        return prices; 
      } 

```

上述代码创建了一个名为'`pricelist`'的属性，该属性可用于视图。

1.  现在，`pricelist`属性可以在视图中显示预定义的值。在我们这个案例中，是一个用于添加新书籍的表单，更新`bookForm.jsp`以显示如下所示的价格列表：

```java
      <form:select path="price"> 
        <form:options items="${priceList}" />   
      </form:select>
```

1.  运行应用程序并点击链接，您可以观察到预定义的价格将出现在下拉列表中，如下所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/lrn-spr5/img/image_06_007.png)

用户将在表单中输入值并提交它。

值可以在处理程序方法中获取。但是，我们仍然不能确定只有有效值会被输入并提交。在错误值上执行的业务逻辑总是会失败。此外，用户可能会输入错误数据类型值，导致异常。让我们以电子邮件地址为例。电子邮件地址总是遵循特定的格式，如果格式错误，业务逻辑最终会失败。无论什么情况，我们必须确信只提交有效值，无论是它们的数据类型、范围还是形成。验证正确数据是否会被提交的过程是“表单验证”。表单验证在确保正确数据提交方面起着关键作用。表单验证可以在客户端和服务器端进行。Java Script 用于执行客户端验证，但它可以被禁用。在这种情况下，服务器端验证总是更受欢迎。

****

Spring 具有灵活的验证机制，可以根据应用程序要求扩展以编写自定义验证器。Spring MVC 框架默认支持在应用程序中添加 JSR303 实现依赖项时的 JSR 303 规范。以下两种方法可用于在 Spring MVC 中验证表单字段，

+   基于 JSR 303 规范的验证

+   基于 Spring 的实现，使用 Validator 接口。

### 基于 Spring Validator 接口的自定义验证器

Spring 提供了 Validator 接口，该接口有一个 validate 方法，在该方法中会检查验证规则。该接口不仅支持 web 层的验证，也可以在任何层使用以验证数据。如果验证规则失败，用户必须通过显示适当的信息性消息来了解这一点。BindingResult 是 Errors 的子类，在执行 validate()方法对模型进行验证时，它持有由 Errors 绑定的验证结果。错误的可绑定消息将使用<form:errors>标签在视图中显示，以使用户了解它们。

让我们通过以下步骤在我们的 ReadMyBooks 应用程序中添加一个自定义验证器：

1.  在应用程序的 lib 文件夹中添加 validation-api-1.1.0.final.api.jar 文件。

1.  在 com.packt.ch06.validators 包中创建 BookValidator 类。

1.  类实现了 org.springframework.validation.Validator 接口。

1.  如代码所示，重写 supports()方法，

```java
      public class BookValidator implements Validator { 
        public boolean supports(Class<?> book_class) { 
          return book_class.equals(Book.class); 
        } 
      } 

```

支持方法确保对象与 validate 方法验证的对象匹配

1.  现在重写 validate()方法，根据规则检查数据成员。我们将分三步进行：

    1.  设置验证规则

我们将核对以下规则：

+   书籍名称的长度必须大于 5。

+   作者的名字必须不为空。

+   描述必须不为空。

+   描述的长度必须至少为 10 个字符，最多为 40 个字符。

+   国际标准书号（ISBN）不应该少于 150。

+   价格不应该少于 0。

+   出版物必须不为空。

    1.  编写条件以检查验证规则。

    1.  如果验证失败，使用`rejectValue()`方法将消息添加到`errors`实例中

使用上述步骤的方法可以如下所示编写：

```java
      public void validate(Object obj, Errors errors) { 
        // TODO Auto-generated method stub 
        Book book=(Book) obj; 
        if (book.getBookName().length() < 5) { 
          errors.rejectValue("bookName", "bookName.required", 
          "Please Enter the book Name"); 
        } 
        if (book.getAuthor().length() <=0) { 
          errors.rejectValue("author", "authorName.required", 
          "Please Enter Author's Name"); 
        } 
        if (book.getDescription().length() <= 0) 
        { 
          errors.rejectValue("description",  
            "description.required", 
            "Please enter book description"); 
        } 
        else if (book.getDescription().length() < 10 ||  
          book.getDescription().length() <  40) { 
            errors.rejectValue("description", "description.length", 
            Please enter description within 40 charaters only"); 
         } 
         if (book.getISBN()<=150l) { 
           errors.rejectValue("ISBN", "ISBN.required", 
           "Please Enter Correct ISBN number"); 
         }   
         if (book.getPrice()<=0 ) { 
           errors.rejectValue("price", "price.incorrect",  "Please  
           enter a Correct correct price"); 
         } 
        if (book.getPublication().length() <=0) { 
          errors.rejectValue("publication",  
            "publication.required", 
            "Please enter publication "); 
        } 
      } 

```

`Errors`接口用于存储有关数据验证的绑定信息。`errors.rejectValue()`是它提供的一个非常有用的方法，它为对象及其错误消息注册错误。以下是来自`Error`接口的`rejectValue()`方法的可用签名，

```java
      void rejectValue(String field_name, String error_code); 
      void rejectValue(String field_name, String error_code, String  
        default_message); 
      void rejectValue(String field_name, String error_code, 
        Object[] error_Args,String default_message); 

```

1.  在`AddBookController`中添加一个类型为`org.springframework.validation.Validator`的数据成员，并用`@Autowired`注解进行注释，如下所示：

```java
      @Autowired 
      Validator validator; 

```

1.  更新`AddController`的`addBook()`方法以调用验证方法并检查是否发生了验证错误。更新后的代码如下所示：

```java
      public ModelAndView addBook(@ModelAttribute("book") Book book,   
        BindingResult bindingResult)   throws Exception { 
        validator.validate(book, bindingResult); 
      if(bindingResult.hasErrors()) 
      { 
        return new ModelAndView("bookForm"); 
      } 
      ModelAndView modelAndView = new ModelAndView(); 
      modelAndView.setViewName("display"); 
      //later on the list will be fetched from the table 
      List<Book>books=new ArrayList(); 
      books.add(book); 
      modelAndView.addObject("book_list",books); 
      modelAndView.addObject("auth_name",book.getAuthor()); 
      return modelAndView; 
    } 

```

`addBook()`方法的签名应该有一个`BindingResult`作为其参数之一。`BindingResult`实例包含在执行验证时发生错误的消息列表。`hasErrors()`方法在数据成员上验证失败时返回 true。如果`hasErrors()`返回 true，我们将返回'`bookForm`'视图，使用户可以输入正确的值。在没有验证违规的情况下，将'display'视图返回给前端控制器。

1.  在`books-servlet.xml`中如下所示注册`BookValdator`作为 bean：

```java
      <bean id="validator"  
        class="com.packt.ch06.validators.BookValidator" /> 

```

您还可以使用`@Component`代替上述配置。

1.  通过更新`bookForm.jsp`，如下的代码所示，显示验证违规消息给用户：

```java
      <tr> 
        <td width="50%" align="right">Name of the Book</td> 
        <td width="50%" align="left"> 
          <form:input path="bookName" size="30" /> 
          <font color="red"> 
            <form:errors path="bookName" /> 
          </font> 
        </td> 
      </tr> 

```

只需在`bookForm.jsp`中添加下划线代码，以将消息显示为红色。

`<form:errors>`用于显示验证失败时的消息。它采用以下所示的语法：

```java
      <form:errors path="name of the data_member" /> 

```

1.  通过为所有输入指定数据成员的名称作为路径属性的值来更新`bookForm.jsp`。

1.  运行应用程序。点击添加新书籍的“显示表单”链接。

1.  不输入任何文本字段中的数据提交表单。我们将得到显示违反哪些验证规则的消息的表单，如下所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/lrn-spr5/img/image_06_008.png)

上述用于验证的代码虽然可以正常工作，但我们没有充分利用 Spring 框架。调用验证方法是显式的，因为框架不知道隐式地执行验证。`@Valid`注解向框架提供了使用自定义验证器隐式执行验证的信息。框架支持将自定义验证器绑定到 WebDataBinder，使框架知道使用`validate()`方法。

#### 使用@InitBinder 和@Valid 进行验证

让我们逐步更新`AddController.java`的代码，如下所示：

1.  在`AddBookController`中添加一个方法来将验证器绑定到`WebDataBinder`，并用`@InitBinder`注解进行注释，如下所示：

```java
      @InitBinder 
      private void initBinder(WebDataBinder webDataBinder) 
      { 
        webDataBinder.setValidator(validator); 
      } 

```

`@InitBinder`注解有助于识别执行 WebDataBinder 初始化的方法。

1.  为了使框架考虑注解，book-servelt.xml 必须更新如下：

1.  添加 mvc 命名空间，如下所示：

```java
      <beans xmlns="http://www.springframework.org/schema/beans" 
        xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"  
        xmlns:context="http://www.springframework.org/schema/context" 
        xmlns:mvc="http://www.springframework.org/schema/mvc" 
        xsi:schemaLocation="http://www.springframework.org/schema/beans 
          http://www.springframework.org/schema/beans/spring-beans.xsd  
          http://www.springframework.org/schema/context  
          http://www.springframework.org/schema/context/
      spring-context.xsd 
          http://www.springframework.org/schema/mvc 
          http://www.springframework.org/schema/mvc/spring-mvc.xsd"> 

```

你只能复制现有代码中下划线的声明。

1.  添加如下所示的配置：

```java
      <mvc:annotation-driven/> 

```

1.  更新`addBook()`方法以添加`@Valid`注解执行书籍验证并删除`validator.validate()`调用，因为它将隐式执行。更新后的代码如下所示：

```java
      @RequestMapping("/addBook.htm") 
      public ModelAndView addBook(@Valid @ModelAttribute("book")  
      Book book,BindingResult bindingResult) 
      throws Exception { 
        //validator.validate(book, bindingResult); 
        if(bindingResult.hasErrors()) 
        { 
          return new ModelAndView("bookForm"); 
        } 
        ModelAndView modelAndView = new ModelAndView(); 
        modelAndView.setViewName("display"); 
        //later on the list will be fetched from the table 
        // rest of the code is same as the earlier implemenation 
      } 

```

1.  运行应用程序，当你提交空白表单时，你会得到类似的结果。消息将在`rejectValue()`方法中硬编码的视图中显示。框架提供了对属性文件中外部化消息的支持。让我们更新用于外部化消息的验证器。

##### 外部化消息

我们将使用以下步骤的外部化消息，而不改变验证逻辑：

1.  在 com.packt.ch06.validators 包中添加一个新类 BookValidator1，实现 Validator 接口。

1.  像早期应用程序一样覆盖 supports 方法。

1.  覆盖我们没有提供默认错误消息的 validate 方法。我们只提供 bean 属性的名称和与之关联的错误代码，如下所示：

```java
      public void validate(Object obj, Errors errors) { 
        Book book=(Book) obj; 
        if (book.getBookName().length() < 5) { 
          errors.rejectValue("bookName", "bookName.required"); 
        } 

        if (book.getAuthor().length() <=0) { 
          errors.rejectValue("author", "authorName.required");           
        } 

        if (book.getDescription().length() <= 0){ 
          errors.rejectValue("description","description.required");             } 

        if (book.getDescription().length() < 10 ||   
          book.getDescription().length() <  40) { 
          errors.rejectValue("description", "description.length");               } 

        if (book.getISBN()<=150l) { 
          errors.rejectValue("ISBN", "ISBN.required"); 
        } 

        if (book.getPrice()<=0 ) { 
          errors.rejectValue("price", "price.incorrect"); 
        } 

        if (book.getPublication().length() <=0) { 
          errors.rejectValue("publication", "publication.required");             } 
      } 

```

1.  让我们在 WEB-INF 中添加 messages_book_validation.properties 文件，以映射错误代码到其相关的消息，如下所示：

```java
      bookName.required=Please enter book name 
      authorName.required=Please enter name of the author 
      publication.required=Please enter publication 
      description.required=Please enter description 
      description.length=Please enter description of minimum 10 and        maximum 40 characters 
      ISBN.required=Please enter ISBN code 
      price.incorrect= Please enter correct price 

```

编写属性文件以映射键值对的语法如下：

```java
      name_of_Validation_Class . name_of_model_to_validate   
        .name_of_data_memeber  = message_to_display 

```

1.  更新 books-servlet.xml 如下：

1.  注释掉为 BookValidator 编写的 bean，因为我们不再使用它

1.  为 BookValidator1 添加一个新的 bean，如下所示：

```java
      <bean id="validator"  
        class="com.packt.ch06.validators.BookValidator1" /> 

```

1.  为 MessagSource 添加一个 bean，以从属性文件中加载消息，如下所示：

```java
      <bean id="messageSource" 
        class="org.springframework.context.support. 
        ReloadableResourceBundleMessageSource"> 
        <property name="basename"  
          value="/WEB-INF/messages_book_validation" /> 
      </bean> 

```

1.  无需更改 AddController.java。运行应用程序，提交空白表单后，将显示从属性文件中拉取的消息。

我们成功外部化了消息，恭喜 !!!

但这不是认为验证代码在这里不必要的执行基本验证吗？框架提供了 ValidationUtils 作为一个工具类，使开发人员能够执行基本验证，如空或 null 值。

##### 使用 ValidationUtils

让我们添加 BookValidator2，它将使用 ValidationUtils 如下：

1.  在 com.packt.ch06.validators 包中添加 BookValidator2 作为一个类，在 ReadMyBooks 应用程序中实现 Validator。

1.  像以前一样覆盖 supports()方法。

1.  覆盖 validate()，使用 ValidationUtils 类执行验证，如下所示：

```java
      public void validate(Object obj, Errors errors) { 
        Book book = (Book) obj; 
        ValidationUtils.rejectIfEmptyOrWhitespace(errors,  
          "bookName", "bookName.required"); 
        ValidationUtils.rejectIfEmptyOrWhitespace(errors, "author",  
          "authorName.required"); 
        ValidationUtils.rejectIfEmptyOrWhitespace(errors,  
          "description", "description.required"); 
        if (book.getDescription().length() < 10 ||  
          book.getDescription().length() < 40) { 
          errors.rejectValue("description", "description.length", 
            "Please enter description within 40 charaters only"); 
        } 
        if (book.getISBN() <= 150l) { 
          errors.rejectValue("ISBN", "ISBN.required", "Please 
          Enter Correct ISBN number"); 
        } 
        ValidationUtils.rejectIfEmptyOrWhitespace(errors, "price",  
          "price.incorrect"); 
        ValidationUtils.rejectIfEmptyOrWhitespace(errors,  
          "publication", "publication.required"); 
      } 

```

1.  由于我们重复使用相同的错误代码，因此无需在属性文件中再次添加它们。

1.  注释掉 BookVlidator1 的 bean，并在 books-servlet.xml 中添加 BookVlidator2 的 bean，如下所示：

```java
      <bean id="validator"  
        class="com.packt.ch06.validators.BookValidator2" /> 

```

1.  执行应用程序并提交空白表单，以从属性文件中获取验证消息显示。

### JSR 注解 based 验证

JSR 303 是一个 bean 规范，定义了在 J2EE 应用程序中验证 bean 的元数据和 API。市场上最新的是 JSR 349，它是 JSR 303 的扩展，提供了开放性、依赖注入和 CDI、方法验证、分组转换、与其他规范集成的特性。Hibernate Validator 是一个知名的参考实现。javax.validation.*包提供了验证目的的 API。

以下是一些在验证中常用的注解：

+   @NotNull: 检查注解的值不为空，但它不能检查空字符串。

+   @Null: 它检查注解的值是否为空。

+   @Pattern: 它检查注解的字符串是否与给定的正则表达式匹配。

+   @Past: 检查注解的值是过去的日期。

+   @Future: 检查注解的值是未来的日期。

+   @Min: 它确保注解的元素是一个数字，其值等于或大于指定的值。

+   @Max: 它确保注解的元素是一个数字，其值等于或小于指定的值。

+   @AssertFalse: 它确保注解的元素为假。

+   @AssertTrue: 它确保注解的元素为真。

+   @Size: 它确保注解的元素在最大值和最小值之间。

除了由 Bean Validation API 定义的上述注解之外，Hibernate Validator 还提供了以下附加注解：

+   @CreditCardNumber: 它检查注解的值是否遵循传递给它的字符序列。

+   @Email: 用于根据指定表达式检查特定字符是否为有效的电子邮件地址。

+   @Length: 它检查注解的元素的字符数是否受 min 和 max 属性指定的限制。

+   @NotBlank: 它检查注解的元素是否不为空且长度大于零。

+   @NotEmpty: 它确保注解的元素既不是空也不是空。

让我们通过以下步骤复制 ReadMyBooks 应用程序来实现基于 JSR 的验证：

#### 第一部分：创建基本应用程序

1.  创建一个名为 ReadMyBooks_JSR_Validation 的动态网页应用程序。

1.  添加我们之前应用程序中添加的所有必需的 jar 文件。

1.  除了这些 jar 文件外，还添加 hibernate-validator-5.0.1.final.jar、classmate-0.5.4.jar、jboss-logging-3.1.0.GA.jar 和 validation-api-1.1.0.final.jar。

1.  复制 com.packt.ch06.beans 和 com.packt.ch06.controllers 包及其内容。

1.  在 WebContent 目录下复制 index.jsp 和 searchByAuthor.jsp 文件。

1.  在 web.xml 文件中添加 DispatcherServlet 映射。

1.  在 WEB-INF 目录下复制 books-servlet.xml 文件。

1.  复制 WEB-INF 目录下的 WebContent 和 jsps 文件夹及其内容。

#### 第二部分：应用验证

1.  让我们在 Book.java 上应用由 hibernate-validator API 提供的验证，如下所示：

```java
      public class Book { 
        @NotEmpty 
        @Size(min = 2, max = 30) 
        private String bookName; 

        @Min(150) 
        private long ISBN; 

        @NotEmpty 
        @Size(min = 2, max = 30) 
        private String publication; 

        @NotNull 
        private int price; 

        @NotEmpty 
        @Size(min = 10, max = 50) 
        private String description; 

        @NotEmpty 
        private String author; 

        //default and parameterized constructor 
        //getters and setters 
      } 

```

1.  让我们更新 AddBookController，如下所示：

1.  删除 Validator 数据成员。

1.  删除 initBinderMethod。

1.  保持@Valid 注解应用于 addBook()方法的 Book 参数上。

1.  从 books-servlet.xml 中删除 validator bean，因为现在它不再需要。

1.  对 messageResource bean 进行注释，稍后我们将会使用它。

1.  确保在 book-servlet.xml 中包含`<mvc:annotation-driven />`入口，以便使框架能够考虑控制器中的注解。

1.  运行应用程序。在提交空白表单时，您将得到以下响应，显示默认的验证消息：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/lrn-spr5/img/image_06_009.png)

消息的自定义可以通过使用'message'属性来实现，或者我们可以使用属性文件外部化消息。我们逐一进行。

##### 使用'message'属性

在 bean 类中用于验证数据的每个注解都有'message'属性。开发人员可以使用它来传递适当的消息，如下面的代码所示：

```java
public class Book { 
  @NotEmpty(message="The book name should be entered") 
  private String bookName; 

  @Min(value=150,message="ISBN should be greater than 150") 
  private long ISBN; 

  @Size(min = 2, max = 30, message="Enter Publication between   
    limit of 2 to 30 only") 
  private String publication; 

  @NotNull(message="Enter the price") 
  private int price; 
  @Size(min = 10, max = 50,message="Enter Publication between limit of
    10 to 50 only") 
  private String description; 

  @NotEmpty(message="Enter the price") 
  private String author; 
  /default and parameterized constructor 
  //getters and setters 
} 

```

保持其他代码不变，按照上面所示更改 Book.java，然后运行应用程序。如果发生任何验证规则的违反，将为'message'属性配置的消息显示。

##### 使用属性文件

开发人员可以从属性文件外部化消息，一旦验证违反，它将从中加载，就像在之前的应用程序中一样。

让我们按照以下步骤在应用程序中添加属性文件：

1.  在 WEB-INF 中创建一个名为 messages_book_validation.properties 的文件，并添加违反规则和要显示的消息的映射，如下所示：

```java
      NotEmpty.book.bookName=Please enter the book name F1\. 
      NotEmpty.book.author=Please enter book author F1\. 
      Min.book.ISBN= Entered ISBN must be greater than 150 F1 
      Size.book.description=Please enter book description having  
        minimum 2 and maximum 30charatcters only F1\. 
      NotNull.book.price=Please enter book price F1\. 

```

在每个文件的末尾故意添加了 F1，以知道消息是从 bean 类还是属性文件中拉取的。您不必在实际文件中添加它们。我们故意没有为'publication'数据成员添加任何消息，以理解消息的拉取。

编写属性文件的语法如下：

```java
      Name_of_validator_class.name_of_model_attribute_to_validate. 
        name_of_data_member= message_to_display 

```

1.  取消对 book-servlet.xml 中 bean '`messageResource'`的注释，或者如果您没有，请添加一个，如下所示：

```java
      <bean id="messageSource" 
        class="org.springframework.context.support. 
        ReloadableResourceBundleMessageSource"> 
        <property name="basename"  
          value="/WEB-INF/messages_book_validation" /> 
      </bean> 

```

1.  运行应用程序，在提交空白表单时，将加载属性文件中的消息，除了'publication'之外，如下所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/lrn-spr5/img/image_06_010.png)

## 总结

* * *

我们讨论了在这款应用程序中的网络层。我们讨论了如何使用 Spring MVC 框架声明自定义控制器。我们讨论了视图如何使用从 ModelAndView 中的模型对象来显示值。我们还讨论了框架是如何发现视图，以及它们是如何通过 ViewResolvers 根据在 ModelAndView 中设置的逻辑名称进行渲染的。讨论继续深入到表单处理，我们深入讨论了如何通过使用表单支持对象和@ModelAttribute 注解来实现表单提交和预填充表单。包含错误值的表单可能会导致异常或业务逻辑失败。解决这个问题的方法是表单验证。我们通过 Spring 自定义验证器和由 Hibernate Validator 提供的基于注解的验证来讨论了表单验证。我们还发现了如何使用 messageresource 捆绑包进行外部化消息传递的方法。在下一章中，我们将继续讨论如何对应用程序进行测试，以最小化应用程序上线时失败的风险。
