# Spring5 学习手册（二）

> 原文：[`zh.annas-archive.org/md5/6DF1C981F26DA121DCB8C1B33E7DE022`](https://zh.annas-archive.org/md5/6DF1C981F26DA121DCB8C1B33E7DE022)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

## 第三章。使用 Spring DAO 加速

在第二章节中，我们深入讨论了依赖注入。显然，我们讨论了在配置文件中以及使用注解的各种使用 DI 的方法，但由于缺乏实时应用程序，这些讨论仍然不完整。我们没有其他选择，因为这些都是每个 Spring 框架开发者都应该了解的最重要的基础知识。现在，我们将开始处理数据库，这是应用程序的核心。

我们将讨论以下配置：

+   我们将讨论关于 DataSource 及其使用 JNDI、池化 DataSource 和 JDBCDriver based DataSource 的配置。

+   我们将学习如何使用 DataSource 和 JDBCTemplate 将数据库集成到应用程序中。

+   接下来我们将讨论如何使用 SessionFactory 在应用程序中理解 ORM 及其配置。

+   我们将配置 HibernateTemplate 以使用 ORM 与数据库通信。

+   我们将讨论如何配置缓存管理器以支持缓存数据。

我们都知道，数据库为数据提供了易于结构化的方式，从而可以使用各种方法轻松访问。不仅有许多可用的方法，市场上还有许多不同的数据库。一方面，拥有多种数据库选项是好事，但另一方面，因为每个数据库都需要单独处理，所以这也使得事情变得复杂。在 Java 应用程序的庞大阶段，需要持久性来访问、更新、删除和添加数据库中的记录。JDBC API 通过驱动程序帮助访问这些记录。JDBC 提供了诸如定义、打开和关闭连接，创建语句，通过 ResultSet 迭代获取数据，处理异常等低级别的数据库操作。但是，到了某个点，这些操作变得重复且紧密耦合。Spring 框架通过 DAO 设计模式提供了一种松耦合、高级、干净的解决方案，并有一系列自定义异常。

## Spring 如何处理数据库？

* * *

在 Java 应用程序中，开发者通常使用一个工具类概念来创建、打开和关闭数据库连接。这是一种非常可靠、智能且可重用的连接管理方式，但应用程序仍然与工具类紧密耦合。如果数据库或其连接性（如 URL、用户名、密码或模式）有任何更改，需要在类中进行更改。这需要重新编译和部署代码。在这种情况下，外部化连接参数将是一个好的解决方案。我们无法外部化 Connection 对象，这仍然需要开发者来管理，同样处理它时出现的异常也是如此。Spring 有一种优雅的方式来管理连接，使用位于中心的 DataSource。

### DataSource

数据源是数据源连接的工厂，类似于 JDBC 中的 DriverManager，它有助于连接管理。以下是一些可以在应用程序中使用的实现，以获取连接对象：

+   **DriverManagerDataSource**：该类提供了一个简单的 DataSource 实现，用于在测试或独立应用程序中，每次请求通过 getConnection()获取一个新的 Connection 对象。

+   **SingleConnectionDataSource**：这个类是 SmartDatSource 的一个实现，它提供了一个不会在使用后关闭的单一 Connection 对象。它只适用于单线程应用程序，以及在应用程序服务器之外简化测试。

+   **DataSourceUtils**：这是一个辅助类，它有静态方法用于从 DataSource 获取数据库连接。

+   **DataSourceTransactionManager**：这个类是 PlatformTransactionManager 的一个实现，用于每个数据源的连接。

#### 配置数据源

数据源可以通过以下方式在应用程序中配置：

+   **从 JNDI 查找获取**：Spring 有助于维护在应用程序服务器（如 Glassfish、JBoss、Wlblogic、Tomcat）中运行的大型 Java EE 应用程序。所有这些服务器都支持通过 Java 命名目录接口（JNDI）查找配置数据源池的功能，这有助于提高性能。可以使用以下方式获取在应用程序中配置的数据源：

```java
      <beans xmlns="http://www.springframework.org/schema/beans" 
        xmlns:jee="http://www.springframework.org/schema/jee" 
        xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" 
        xsi:schemaLocation="http://www.springframework.org/schema/
        beans  http://www.springframework.org/schema/beans/
        spring-beans.xsd http://www.springframework.org/schema/jee
        http://www.springframework.org/schema/jee/spring-jee.xsd"> 

        <bean id="dataSource"  
          class="org.springframework.jndi.JndiObjectFactoryBean"> 
          <property name="jndiName"   
            value="java:comp/env/jdbc/myDataSource"/> 
        </bean> 

        <jee:jndi-lookup jndi-name="jdbc/myDataSource" id="dataSource" 
          resource-ref="true"/> 
      </beans> 

```

+   其中：

+   **jndi-name**：指定在 JNDI 中配置的服务器上的资源名称。

+   **id**：bean 的 id，提供 DataSource 对象。

+   **resource-ref**：指定是否需要前缀 java:comp/env。

+   从池中获取连接：Spring 没有池化数据源，但是，我们可以配置由 Jakarta Commons Database Connection Pooling 提供的池化数据源。DBCP 提供的 BasicDataSource 可以配置为，

```java
      <bean id="dataSource"               
         class="org.apache.commons.dbcp.BasicDataSource">        
        <property name="driverClassName"                 
          value="org.hsqldb.jdbcDriver"/> 
        <property name="url"    
            value="jdbc:hsqldb:hsql://locahost/name_of_schama"/> 
        <property name="username"      
            value="credential_for_username"/> 
        <property name="password"      
            value="credential_for_password"/> 
        <property name="initialSize"      
            value=""/> 
        <property name="maxActive"      
            value=""/> 
      </bean> 

```

+   其中：

+   **initialSize**：指定了当池启动时应创建的连接数量。

+   **maxActive**：指定可以从池中分配的连接数量。

+   除了这些属性，我们还可以指定等待连接从池中返回的时间（maxWait），连接可以在池中空闲的最大/最小数量（maxIdle/minIdle），可以从语句池分配的最大预处理语句数量（maxOperationPreparedStatements）。

+   使用 JDBC 驱动器：可以利用以下类以最简单的方式获取 DataSource 对象：

* **SingleConnectionDataSource**：正如我们已经在讨论中提到的，它返回一个连接。

* **DriverManagerDataSource**：它在一个请求中返回一个新的连接对象。

+   可以按照以下方式配置 DriverMangerDataSource：

```java
      <bean id="dataSource"
        class="org.springframework.jdbc.datasource.
        DriverManagerDataSource">        
        <property name="driverClassName"                 
          value="org.hsqldb.jdbcDriver"/> 
        <property name="url"    
          value="jdbc:hsqldb:hsql://locahost/name_of_schama"/> 
        <property name="username"      
          value="credential_for_username"/> 
        <property name="password"      
          value="credential_for_password"/> 
      </bean> 

```

### 注意

单连接数据源适用于小型单线程应用程序。驱动管理数据源支持多线程应用程序，但由于管理多个连接，会损害性能。建议使用池化数据源以获得更好的性能。

让我们开发一个使用松耦合模块的示例 demo，以便我们了解 Spring 框架应用程序开发的实际方面。

数据源有助于处理与数据库的连接，因此需要在模块中注入。使用 setter DI 或构造函数 DI 的选择完全由您决定，因为您很清楚这两种依赖注入。我们将使用 setter DI。我们从考虑接口开始，因为这是根据合同进行编程的最佳方式。接口可以有多个实现。因此，使用接口和 Spring 配置有助于实现松耦合模块。我们将声明数据库操作的方法，您可以选择签名。但请确保它们可以被测试。由于松耦合是框架的主要特性，应用程序也将演示为什么我们一直在说松耦合模块可以使用 Spring 轻松编写？您可以使用任何数据库，但本书将使用 MySQL。无论您选择哪种数据库，都要确保在继续之前安装它。让我们按照步骤开始！

##### 案例 1：使用 DriverManagerDataSource 的 XML 配置

1.  创建一个名为 Ch03_DataSourceConfiguration 的核心 Java 应用程序，并添加 Spring 和 JDBC 的 jar，如下所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/lrn-spr5/img/image_03_001.png)

1.  在 com.ch03.packt.beans 包中创建一个 Book POJO，如下所示：

```java
      public class Book { 
        private String bookName; 
        private long ISBN; 
        private String publication; 
        private int price; 
        private String description; 
        private String [] authors; 

        public Book() { 
          // TODO Auto-generated constructor stub 
          this.bookName="Book Name"; 
          this.ISBN =98564567l; 
          this.publication="Packt Publication"; 
          this.price=200; 
          this.description="this is book in general"; 
          this.author="ABCD"; 
        } 

        public Book(String bookName, long ISBN, String  
          publication,int price,String description,String  
          author)  
       { 
          this.bookName=bookName; 
          this.ISBN =ISBN; 
          this.publication=publication; 
          this.price=price; 
          this.description=description; 
           this.author=author; 
        } 
        // getters and setters 
        @Override 
        public String toString() { 
          // TODO Auto-generated method stub 
          return bookName+"\t"+description+"\t"+price; 
        } 
      }
```

1.  在 com.ch03.packt.dao 包中声明一个 BookDAO 接口。（DAO 表示数据访问对象）。

1.  在数据库中添加书籍的方法如下所示：

```java
      interface BookDAO 
      { 
        public int addBook(Book book); 
      } 

```

1.  为 BookDAO 创建一个实现类 BookDAOImpl，并在类中添加一个 DataSource 类型的数据成员，如下所示：

```java
      private DataSource dataSource; 

```

+   不要忘记使用标准的 bean 命名约定。

1.  由于我们采用 setter 注入，请为 DataSource 编写或生成 setter 方法。

1.  覆盖的方法将处理从 DataSource 获取连接，并使用 PreaparedStatement 将 book 对象插入表中，如下所示：

```java
      public class BookDAOImpl implements BookDAO { 
        private DataSource dataSource; 

        public void setDataSource(DataSource dataSource) { 
          this.dataSource = dataSource; 
        } 

      @Override
      public int addBook(Book book) { 
          // TODO Auto-generated method stub 
          int rows=0; 
          String INSERT_BOOK="insert into book values(?,?,?,?,?,?)"; 
          try { 
            Connection connection=dataSource.getConnection(); 
            PreparedStatement ps=  
                   connection.prepareStatement(INSERT_BOOK); 
            ps.setString(1,book.getBookName()); 
            ps.setLong(2,book.getISBN()); 
            ps.setString(3,book.getPublication()); 
            ps.setInt(4,book.getPrice()); 
            ps.setString(5,book.getDescription()); 
            ps.setString(6,book.getAuthor()); 
            rows=ps.executeUpdate(); 
          } catch (SQLException e) { 
            // TODO Auto-generated catch block 
            e.printStackTrace(); 
          } 
          return rows; 
        } 
      } 

```

1.  在类路径中创建 connection.xml 以配置 beans。

1.  现在问题变成了需要声明多少个 bean 以及它们各自的 id 是什么？

### 注意

一个非常简单的经验法则：首先找出要配置的类，然后找出它的依赖关系是什么？

以下是：

**一个 BookDAOImpl 的 bean。**

**BookDAOImpl 依赖于 DataSource，因此需要一个 DataSource 的 bean。**

您可能会惊讶 DataSource 是一个接口！那么我们是如何创建并注入其对象的呢？是的，这就是我们观点所在！这就是我们所说的松耦合模块。在这里使用的 DataSource 实现是 DriverManagerDataSource。但如果我们直接注入 DriverManagerDataSource，那么类将与它紧密耦合。此外，如果明天团队决定使用其他实现而不是 DriverManagerDataSource，那么代码必须更改，这导致重新编译和重新部署。这意味着更好的解决方案将是使用接口，并从配置中注入其实现。

id 可以是开发者的选择，但不要忽略利用自动装配的优势，然后相应地设置 id。这里我们将使用自动装配'byName'，所以请选择相应的 id。（如果您困惑或想深入了解自动装配，可以参考上一章。）因此，XML 中的最终配置将如下所示：

```java
<bean id="dataSource" 
  class= 
   "org.springframework.jdbc.datasource.DriverManagerDataSource"> 
    <property name="driverClassName"    
        value="com.mysql.jdbc.Driver" /> 
    <property name="url"  
        value="jdbc:mysql://localhost:3306/bookDB" /> 
    <property name="username" value="root" /> 
    <property name="password" value="mysql" /> 
  </bean> 

  <bean id="bookDao" class="com.packt.ch03.dao.BookDAOImpl" 
     autowire="byname"> 
  </bean> 

```

您可能需要根据您的连接参数自定义 URL、用户名和密码。

1.  通常，DAO 层将由服务层调用，但在这里我们不处理它，因为随着应用程序的进行，我们将添加它。由于我们还没有讨论测试，我们将编写带有 main 函数的代码来找出它的输出。main 函数将获取 BookDAO bean 并在其上调用插入 Book 的方法。如果实现代码返回的行值大于零，则书籍成功添加，否则不添加。创建一个名为 MainBookDAO 的类，并向其添加以下代码：

```java
      public static void main(String[] args) { 
        // TODO Auto-generated method stub 
        ApplicationContext context=new  
          ClassPathXmlApplicationContext("connection.xml"); 
        BookDAO bookDAO=(BookDAO) context.getBean("bookDao"); 
        int rows=bookDAO.addBook(new Book("Learning Modular     
          Java Programming", 9781234,"PacktPub   
          publication",800,"explore the power of   
          Modular programming","T.M.Jog"));        
        if(rows>0) 
        { 
          System.out.println("book inserted successfully"); 
        } 
        else 
          System.out.println("SORRY!cannot add book"); 
      }  

```

如果你仔细观察我们会配置 BookDAOImpl 对象，我们是在 BookDAO 接口中接受它，这有助于编写灵活的代码，在这种代码中，主代码实际上不知道是哪个对象在提供实现。

1.  打开你的 MYSQL 控制台，使用凭据登录。运行以下查询创建 BookDB 架构和 Book 表：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/lrn-spr5/img/image_03_002.png)

1.  一切都准备好了，执行代码以在控制台获得“book inserted successfully”（书籍插入成功）的提示。你也可以在 MySQL 中运行“select * from book”来获取书籍详情。

##### Case2：使用注解 DriverManagerDataSource

我们将使用在 Case1 中开发的同一个 Java 应用程序 Ch03_DataSourceConfiguration：

1.  声明一个类 BookDAO_Annotation，在 com.packt.ch03.dao 包中实现 BookDAO，并用@Repository 注解它，因为它处理数据库，并指定 id 为'bookDAO_new'。

1.  声明一个类型为 DataSource 的数据成员，并用@Autowired 注解它以支持自动装配。

+   不要忘记使用标准的 bean 命名约定。

+   被覆盖的方法将处理数据库将书籍插入表中。代码将如下所示：

```java
      @Repository(value="bookDAO_new") 
      public class BookDAO_Annotation implements BookDAO { 
        @Autowired 
        private DataSource dataSource; 

        @Override 
        public int addBook(Book book) { 
          // TODO Auto-generated method stub 
          int rows=0; 
          // code similar to insertion of book as shown in     
          Case1\. 
          return rows; 
        } 
      } 

```

1.  我们可以编辑 Case1 中的同一个 connection.xml，但这可能会使配置复杂。所以，让我们在类路径中创建 connection_new.xml，以配置容器考虑注解并搜索如下立体注解：

```java
      <context:annotation-config/> 
 <context:component-scan base- 
        package="com.packt.ch03.*"></context:component-scan> 

      <bean id="dataSource" 
        class="org.springframework.jdbc.datasource.
        DriverManagerDataSo urce"> 
        <!-add properties similar to Case1 -- > 
      </bean> 

```

+   要找出如何添加上下文命名空间和使用注解，请参考第二章。

1.  是时候通过以下代码找到输出：

```java
      public class MainBookDAO_Annotation { 
          public static void main(String[] args) { 
          // TODO Auto-generated method stub 
          ApplicationContext context=new  
            ClassPathXmlApplicationContext("connection_new.xml"); 

          BookDAO bookDAO=(BookDAO) context.getBean("bookDAO_new"); 
          int rows=bookDAO.addBook(new Book("Learning Modular Java  
             Programming", 9781235L,"PacktPub  
             publication",800,"explore the power of  
             Modular programming","T.M.Jog")); 
          if(rows>0) 
          { 
            System.out.println("book inserted successfully"); 
          } 
          else 
          System.out.println("SORRY!cannot add book"); 
        } 
      } 

```

执行代码以将书籍添加到数据库中。

您可能已经注意到，我们从未知道是谁提供了 JDBC 代码的实现，并且由于配置，注入是松耦合的。尽管如此，我们还是能够将数据插入数据库，但仍然需要处理 JDBC 代码，例如获取连接、从它创建语句，然后为表的列设置值，以插入记录。这是一个非常初步的演示，很少在 JavaEE 应用程序中使用。更好的解决方案是使用 Spring 提供的模板类。

### 使用模板类执行 JDBC 操作

模板类提供了一种抽象的方式来定义操作，通过摆脱常见的打开和维护连接、获取 Statement 对象等冗余代码的问题。Spring 提供了许多这样的模板类，使得处理 JDBC、JMS 和事务管理变得比以往任何时候都容易。JdbcTemplate 是 Spring 的这样一个核心组件，它帮助处理 JDBC。要处理 JDBC，我们可以使用以下三种模板之一。

#### JDBCTemplate

JdbcTemplate 帮助开发者专注于应用程序的核心业务逻辑，而无需关心如何打开或管理连接。他们不必担心如果忘记释放连接会怎样？所有这些事情都将由 JdbcTemplate 为您优雅地完成。它提供了指定索引参数以在 SQL 查询中使用 JDBC 操作的方法，就像我们在 PreparedStatements 中通常做的那样。

#### SimpleJdbcTemplate

这与 JDBCTemplate 非常相似，同时具有 Java5 特性的优势，如泛型、可变参数、自动装箱。

#### NamedParameterJdbcTemplate

JdbcTemplate 使用索引来指定 SQL 中参数的值，这可能使记住参数及其索引变得复杂。如果您不习惯数字或需要设置更多参数，我们可以使用 NamedParamterJdbcTemplate，它允许使用命名参数来指定 SQL 中的参数。每个参数都将有一个以冒号(:)为前缀的命名。我们将在开发代码时看到语法。

让我们逐一演示这些模板。

##### 使用 JdbcTemplate

我们将使用与 Ch03_DataSourceConfiguration 中相似的项目结构，并按照以下步骤重新开发它，

1.  创建一个名为 Ch03_JdbcTemplate 的新 Java 应用程序，并添加我们在 Ch03_DataSourceIntegration 中使用的 jar 文件。同时添加 spring-tx-5.0.0.M1.jar。

1.  在 com.packt.ch03.beans 包中创建或复制 Book。

1.  在 com.packt.ch03.dao 包中创建或复制 BookDAO。

1.  在 com.packt.ch03.dao 包中创建 BookDAOImpl_JdbcTemplate，并向其添加 JdbcTemplate 作为数据成员。

1.  分别用@Repository 注解类，用@Autowired 注解数据成员 JdbcTemplate。

1.  覆盖的方法将处理表中书籍的插入。但我们不需要获取连接。同时，我们也不会创建并设置 PreparedStatement 的参数。JdbcTemplate 会为我们完成这些工作。从下面的代码中，事情会变得相当清晰：

```java
      @Repository (value = "bookDAO_jdbcTemplate") 
      public class BookDAO_JdbcTemplate implements BookDAO { 

        @Autowired 
        JdbcTemplate jdbcTemplate; 

        @Override 
        public int addBook(Book book) { 
          // TODO Auto-generated method stub 
          int rows = 0; 
          String INSERT_BOOK = "insert into book  
             values(?,?,?,?,?,?)"; 

          rows=jdbcTemplate.update(INSERT_BOOK, book.getBookName(),                              book.getISBN(), book.getPublication(),   
            book.getPrice(),book.getDescription(),  
            book.getAuthor()); 
          return rows; 
        } 
      } 

```

+   JdbcTemplate 有一个 update()方法，开发人员需要在该方法中传递 SQL 查询以及查询参数的值。因此，我们可以用它来插入、更新和删除数据。其余的都由模板完成。如果你仔细观察，我们没有处理任何异常。我们忘记了吗？不，我们不关心处理它们，因为 Spring 提供了 DataAccessException，这是一个未检查的异常。所以放心吧。在接下来的页面中，我们将讨论 Spring 提供的异常。

+   在代码中添加一个更新书籍价格以及删除书籍的方法。不要忘记首先更改接口实现。代码如下：

```java
      @Override 
      public int updateBook(long ISBN, int price) { 
        // TODO Auto-generated method stub 
        int rows = 0; 
        String UPDATE_BOOK = "update book set price=? where ISBN=?"; 

        rows=jdbcTemplate.update(UPDATE_BOOK, price,ISBN); 
        return rows; 
      } 

      @Override 
      public boolean deleteBook(long ISBN) { 
        // TODO Auto-generated method stub 
        int rows = 0; 
        boolean flag=false; 
        String DELETE_BOOK = "delete from book where ISBN=?"; 

        rows=jdbcTemplate.update(DELETE_BOOK, ISBN); 
        if(rows>0) 
        flag=true; 

        return flag; 
      } 

```

1.  我们在 connection_new.xml 中添加一个 beans 配置文件。你可以简单地从 Ch03_DataSourceIntegration 项目中复制它。我们使用的是 JdbcTemplate，它依赖于 DataSource。因此，我们需要像下面所示配置两个 bean，一个用于 DataSource，另一个用于 JdbcTemplate：

```java
      <context:annotation-config/> 
      <context:component-scan base- 
        package="com.packt.ch03.*"></context:component-scan> 

      <bean id="dataSource" 
        class="org.springframework.jdbc.datasource.
        DriverManagerDataSource"> 
        <property name="driverClassName"  
          value="com.mysql.jdbc.Driver" /> 
        <property name="url"  
          value="jdbc:mysql://localhost:3306/bookDB" /> 
        <property name="username" value="root" /> 
        <property name="password" value="mysql" /> 
      </bean> 

      <bean id="jdbcTemplate"  
        class="org.springframework.jdbc.core.JdbcTemplate"> 
        <property name="dataSource" ref="dataSource"></property> 
      </bean> 

```

1.  编写代码以获取'bookDAO_jdbcTemplate' bean，并在 MainBookDAO_operations 中执行操作，如下所示：

```java
      public class MainBookDAO_operations { 
        public static void main(String[] args) { 
          // TODO Auto-generated method stub 
          ApplicationContext context=new  
            ClassPathXmlApplicationContext("connection_new.xml"); 
          BookDAO bookDAO=(BookDAO)  
            context.getBean("bookDAO_jdbcTemplate"); 
          //add book 
          int rows=bookDAO.addBook(new Book("Java EE 7 Developer  
             Handbook", 97815674L,"PacktPub  
             publication",332,"explore the Java EE7  
             programming","Peter pilgrim")); 
          if(rows>0) 
          { 
            System.out.println("book inserted successfully"); 
          } 
          else 
            System.out.println("SORRY!cannot add book"); 
          //update the book 
          rows=bookDAO.updateBook(97815674L,432); 
          if(rows>0) 
          { 
            System.out.println("book updated successfully"); 
          } 
          else 
            System.out.println("SORRY!cannot update book"); 
          //delete the book 
          boolean deleted=bookDAO.deleteBook(97815674L); 
          if(deleted) 
          { 
            System.out.println("book deleted successfully"); 
          } 
          else 
            System.out.println("SORRY!cannot delete book"); 
        } 
      } 

```

##### 使用 NamedParameterJdbc 模板

我们将使用 Ch03_JdbcTemplates 来添加一个新的类进行此次演示，具体步骤如下。

1.  在 com.packt.ch03.dao 包中添加 BookDAO_NamedParameter 类，它实现了 BookDAO，并用我们之前所做的@Repository 注解。

1.  在其中添加一个 NamedParameterJdbcTemplate 作为数据成员，并用@Autowired 注解它。

1.  使用 update()实现覆盖方法以执行 JDBC 操作。NamedParameterJdbcTemplate 支持在 SQL 查询中给参数命名。找到以下查询以添加书籍：

```java
      String INSERT_BOOK = "insert into book
        values(:bookName,:ISBN,:publication,:price,:description,
        : author)";
```

### 注意

每个参数都必须以前缀冒号：name_of_parameter。

+   如果这些是参数的名称，那么这些参数需要注册，以便框架将它们放置在查询中。为此，我们必须创建一个 Map，其中这些参数名称作为键，其值由开发者指定。以下代码将给出清晰的概念：

```java
      @Repository(value="BookDAO_named") 
      public class BookDAO_NamedParameter implements BookDAO { 

        @Autowired 
        private NamedParameterJdbcTemplate namedTemplate; 

        @Override 
        public int addBook(Book book) { 
          // TODO Auto-generated method stub 
          int rows = 0; 
          String INSERT_BOOK = "insert into book  
            values(:bookName,:ISBN,:publication,:price, 
            :description,:author)"; 
          Map<String,Object>params=new HashMap<String,Object>(); 
          params.put("bookName", book.getBookName()); 
          params.put("ISBN", book.getISBN()); 
          params.put("publication", book.getPublication()); 
          params.put("price",book.getPrice()); 
          params.put("description",book.getDescription()); 
          params.put("author", book.getAuthor()); 
          rows=namedTemplate.update(INSERT_BOOK,params);  

          return rows; 
        } 

        @Override 
        public int updateBook(long ISBN, int price) { 
          // TODO Auto-generated method stub 
          int rows = 0; 
          String UPDATE_BOOK =  
           "update book set price=:price where ISBN=:ISBN"; 

          Map<String,Object>params=new HashMap<String,Object>(); 
          params.put("ISBN", ISBN); 
          params.put("price",price); 
          rows=namedTemplate.update(UPDATE_BOOK,params); 
          return rows; 
        } 

        @Override 
        public boolean deleteBook(long ISBN) { 
          // TODO Auto-generated method stub 
          int rows = 0; 
          boolean flag=false; 
          String DELETE_BOOK = "delete from book where ISBN=:ISBN"; 

          Map<String,Object>params=new HashMap<String,Object>(); 
          params.put("ISBN", ISBN); 
          rows=namedTemplate.update(DELETE_BOOK, params); 
          if(rows>0) 
            flag=true; 
          return flag; 
        } 
      } 

```

1.  在 connection_new.xml 中为 NamedParameterJdbcTemplate 添加一个 bean，如下所示：

```java
      <bean id="namedTemplate" 
        class="org.springframework.jdbc.core.namedparam. 
          NamedParameterJdbcTemplate">   
        <constructor-arg ref="dataSource"/> 
      </bean> 

```

+   在其他所有示例中我们都使用了 setter 注入，但在这里我们无法使用 setter 注入，因为该类没有默认构造函数。所以，只使用构造函数依赖注入。

1.  使用开发的 MainBookDAO_operations.java 来测试 JdbcTemplate 的工作。你只需要更新将获取**BookDAO_named** bean 以执行操作的语句。更改后的代码将是：

```java
      BookDAO bookDAO=(BookDAO) context.getBean("BookDAO_named"); 

```

+   你可以在 MainBookDAO_NamedTemplate.java 中找到完整的代码。

1.  执行代码以获取成功消息。

在小型 Java 应用程序中，代码将具有较少的 DAO 类。因此，对于每个 DAO 使用模板类来处理 JDBC，对开发人员来说不会很复杂。这也导致了代码的重复。但是，当处理具有更多类的企业应用程序时，复杂性变得难以处理。替代方案将是，不是在每个 DAO 中注入模板类，而是选择一个具有模板类能力的父类。Spring 具有 JdbcDaoSupport，NamedParameterJdbcSupport 等支持性 DAO。这些抽象支持类提供了一个公共基础，避免了代码的重复，在每个 DAO 中连接属性。

让我们继续同一个项目使用支持 DAO。我们将使用 JdbcDaoSupport 类来了解实际方面：

1.  在 com.packt.ch03.dao 中添加 BookDAO_JdbcTemplateSupport.java，它继承了 JdbcDaoSupport 并实现了 BookDAO。

1.  从接口覆盖方法，这些方法将处理数据库。BookDAO_JdbcTemplateSupport 类从 JdbcDaoSupport 继承了 JdbcTemplate。所以代码保持不变，就像我们使用 JdbcTemplate 时一样，稍作改动。必须通过下面的代码中加粗的 getter 方法访问 JdbcTemplate：

```java
      @Repository(value="daoSupport") 
      public class BookDAO_JdbcTemplateSupport extends JdbcDaoSupport  
        implements BookDAO 
      { 
        @Autowired 
        public BookDAO_JdbcTemplateSupport(JdbcTemplate jdbcTemplate) 
        { 
          setJdbcTemplate(jdbcTemplate); 
        } 

        @Override 
        public int addBook(Book book) { 
          // TODO Auto-generated method stub 
          int rows = 0; 
          String INSERT_BOOK = "insert into book values(?,?,?,?,?,?)"; 

          rows=getJdbcTemplate().update(INSERT_BOOK,  
            book.getBookName(), book.getISBN(),  
            book.getPublication(), book.getPrice(), 
            book.getDescription(), book.getAuthor()); 

          return rows; 
        } 

        @Override 
        public int updateBook(long ISBN, int price) { 
          // TODO Auto-generated method stub 
          int rows = 0; 
          String UPDATE_BOOK = "update book set price=? where ISBN=?"; 

          rows=getJdbcTemplate().update(UPDATE_BOOK, price,ISBN); 
          return rows; 
        } 

        @Override 
        public boolean deleteBook(long ISBN) { 
          // TODO Auto-generated method stub 
          int rows = 0; 
          boolean flag=false; 
          String DELETE_BOOK = "delete from book where ISBN=?"; 

          rows=getJdbcTemplate().update(DELETE_BOOK, ISBN); 
          if(rows>0) 
            flag=true; 

          return flag; 
        } 
      } 

```

### 注意

使用 DAO 类时，依赖将通过构造函数注入。

我们之前在几页中讨论了关于简短处理异常的内容。让我们更详细地了解它。JDBC 代码强制通过检查异常处理异常。但是，它们是泛化的，并且仅通过 DataTrucationException，SQLException，BatchUpdateException，SQLWarning 处理。与 JDBC 相反，Spring 支持各种未检查异常，为不同场景提供专门的信息。以下表格显示了我们可能需要频繁使用的其中一些：

| **Spring 异常** | **它们什么时候被抛出？** |
| --- | --- |
| 数据访问异常 | 这是 Spring 异常层次结构的根，我们可以将其用于所有情况。 |
| 权限被拒数据访问异常 | 当尝试在没有正确授权的情况下访问数据时 |
| 空结果数据访问异常 | 从数据库中没有返回任何行，但至少期望有一个。 |
| 结果大小不匹配数据访问异常 | 当结果大小与期望的结果大小不匹配时。 |
| 类型不匹配数据访问异常 | Java 和数据库之间的数据类型不匹配。 |
| 无法获取锁异常 | 在更新数据时未能获取锁 |
| 数据检索失败异常 | 当使用 ORM 工具通过 ID 搜索和检索数据时 |

在使用 Spring DataSource，模板类，DAOSupport 类处理数据库操作时，我们仍然涉及使用 SQL 查询进行 JDBC 操作，而不进行面向对象的操作。处理数据库操作的最简单方法是使用对象关系映射将对象置于中心。

## 对象关系映射

* * *

JDBC API 提供了执行关系数据库操作的手段以实现持久化。Java 开发人员积极参与编写 SQL 查询以进行此类数据库操作。但是 Java 是一种面向对象编程语言（OOP），而数据库使用 **顺序查询语言**（**SQL**）。OOP 的核心是对象，而 SQL 有数据库。OOP 没有主键概念，因为它有身份。OOP 使用继承，但 SQL 没有。这些以及许多其他不匹配之处使得没有深入了解数据库及其结构的情况下，JDBC 操作难以执行。一些优秀的 ORM 工具已经提供了解决方案。ORM 处理数据库操作，将对象置于核心位置，而无需开发者处理 SQL。市场上的 iBATIS、JPA 和 Hibernate 都是 ORM 框架的例子。

### Hibernate

Hibernate 是开发者在 ORM 解决方案中使用的高级中间件工具之一。它以一种简单的方式提供了细粒度、继承、身份、关系关联和导航问题的解决方案。开发者无需手动编写 SQL 查询，因为 Hibernate 提供了丰富的 API 来处理 CRUD 数据库操作，使得系统更易于维护和开发。SQL 查询依赖于数据库，但在 Hibernate 中无需编写 SQL 语句，因为它提供了数据库无关性。它还支持 Hibernate 查询语言（HQL）和原生 SQL 支持，通过编写查询来自定义数据库操作。使用 Hibernate，开发者可以缩短开发时间，从而提高生产力。

#### Hibernate 架构

下面的图表展示了 Hibernate 的架构及其中的接口：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/lrn-spr5/img/image_03_003.png)

**Hibernate** 拥有 Session、SessionFactory、Configuration、Transaction、Query 和 Criteria 接口，为核心提供了 ORM 支持，帮助开发者进行对象关系映射。

##### Configuration 接口

使用 Configuration 实例来指定数据库属性，如 URL、用户名和密码，映射文件的路径或包含数据成员与表及其列映射信息的类。这个 Configuration 实例随后用于获取 SessionFactory 的实例。

##### SessionFactory 接口

SessionFactory 是重量级的，每个应用程序通常只有一个实例。但是有时一个应用程序会使用多个数据库，这就导致每个数据库都有一个实例。SessionFactory 用于获取 Session 的实例。它非常重要，因为它缓存了生成的 SQL 语句和数据，这些是 Hibernate 在一个工作单元内运行时使用的，作为第一级缓存。

##### Session 接口

Session 接口是每个使用 Hibernate 的应用程序用来执行数据库操作的基本接口，这些接口是从 SessionFactory 获取的。Session 是轻量级、成本低的组件。因为 SessionFactory 是针对每个应用程序的，所以开发者为每个请求创建一个 Session 实例。

##### Transaction 接口

事务帮助开发人员将多个操作作为工作单元。JTA、JDBC 提供事务实现的实现。除非开发者提交事务，否则数据不会反映在数据库中。

##### 查询接口

查询接口提供使用 Hibernate 查询语言（HQL）或原生 SQL 来执行数据库操作的功能。它还允许开发人员将值绑定到 SQL 参数，指定查询返回多少个结果。

##### 条件接口

条件接口与查询接口类似，允许开发人员编写基于某些限制或条件的条件查询对象以获取结果。

在 Spring 框架中，开发者可以选择使用 SessionFactory 实例或 HibernateTemplate 进行 Hibernate 集成。SessionFactory 从数据库连接参数配置和映射位置获取，然后使用 DI 可以在 Spring 应用程序中使用。`SessionFactory`可以如下配置：

```java
<bean id="sessionFactory" 
    class="org.springframework.orm.hibernate5.LocalSessionFactoryBean"> 
    <property name="dataSource" ref="dataSource" /> 
    <property name="mappingResources"> 
      <list> 
        <value>book.hbm.xml</value> 
      </list> 
    </property> 
    <property name="hibernateProperties"> 
      <props> 
        <prop key=    
          "hibernate.dialect">org.hibernate.dialect.MySQLDialect 
        </prop> 
        <prop key="hibernate.show_sql">true</prop> 
        <prop key="hibernate.hbm2ddl.auto">update</prop> 
      </props> 
    </property> 
  </bean> 

```

+   **dataSource** - 提供数据库属性的信息。

+   **mappingResource** - 指定提供数据成员到表及其列映射信息的文件名称。

+   **hibernateProperties** - 提供关于 hibernate 属性的信息

**方言** - 它用于生成符合底层数据库的 SQL 查询。

**show_sql** - 它显示框架在控制台上发出的 SQL 查询。

**hbm2ddl.auto** - 它提供了是否创建、更新表以及要执行哪些操作的信息。

在使用 SessionFactory 时，开发人员不会编写使用 Spring API 的代码。但我们之前已经讨论过模板类。HibenateTemplate 是这样一个模板，它帮助开发人员编写松耦合的应用程序。HibernateTemplate 配置如下：

```java
<bean id="hibernateTemplate" \
  class="org.springframework.orm.hibernate5.HibernateTemplate"> 
    <property name="sessionFactory" ref="sessionFactory"></property> 
</bean> 

```

让我们按照以下步骤逐一将 SessionFactory 集成到我们的 Book 项目中。

##### 案例 1：使用 SessionFactory

1.  创建一个名为 Ch03_Spring_Hibernate_Integration 的 Java 应用程序，并添加 Spring、JDBC 和 hibernate 的 jar 文件，如下 outline 所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/lrn-spr5/img/image_03_004.png)

+   您可以从 Hibernate 的官方网站下载包含 hibernate 框架 jar 的 zip 文件。

1.  在 com.packt.ch03.beans 包中复制或创建 Book.java。

1.  在类路径中创建 book.hbm.xml，将 Book 类映射到 book_hib 表，如下配置所示：

```java
      <hibernate-mapping> 
        <class name="com.packt.ch03.beans.Book" table="book_hib"> 
          <id name="ISBN" type="long"> 
            <column name="ISBN" /> 
            <generator class="assigned" /> 
          </id> 
          <property name="bookName" type="java.lang.String"> 
            <column name="book_name" /> 
          </property>               
          <property name="description" type="java.lang.String"> 
            <column name="description" /> 
          </property> 
          <property name="author" type="java.lang.String"> 
            <column name="book_author" /> 
          </property> 
          <property name="price" type="int"> 
            <column name="book_price" /> 
          </property> 
        </class> 

      </hibernate-mapping>
```

+   其中标签配置如下：

**id** - 定义从表到图书类的主键映射

**属性** - 提供数据成员到表中列的映射

1.  像在 Ch03_JdbcTemplate 应用程序中一样添加 BookDAO 接口。

1.  通过 BookDAO_SessionFactory 实现 BookDAO 并覆盖方法。用@Repository 注解类。添加一个类型为 SessionFactory 的数据成员，并用@Autowired 注解。代码如下所示：

```java
      @Repository(value = "bookDAO_sessionFactory") 
      public class BookDAO_SessionFactory implements BookDAO { 

        @Autowired 
        SessionFactory sessionFactory; 

        @Override 
        public int addBook(Book book) { 
          // TODO Auto-generated method stub 
          Session session = sessionFactory.openSession(); 
          Transaction transaction = session.beginTransaction(); 
          try { 
            session.saveOrUpdate(book); 
            transaction.commit(); 
            session.close(); 
            return 1; 
          } catch (DataAccessException exception) { 
            exception.printStackTrace(); 
          } 
          return 0; 
        } 

        @Override 
        public int updateBook(long ISBN, int price) { 
          // TODO Auto-generated method stub 
          Session session = sessionFactory.openSession(); 
          Transaction transaction = session.beginTransaction(); 
          try { 
            Book book = session.get(Book.class, ISBN); 
            book.setPrice(price); 
            session.saveOrUpdate(book); 
            transaction.commit(); 
            session.close(); 
            return 1; 
          } catch (DataAccessException exception) { 
            exception.printStackTrace(); 
          } 
          return 0; 
        } 

        @Override 
        public boolean deleteBook(long ISBN) { 
          // TODO Auto-generated method stub 
          Session session = sessionFactory.openSession(); 
          Transaction transaction = session.beginTransaction(); 
          try { 
            Book book = session.get(Book.class, ISBN); 
            session.delete(book); 
            transaction.commit(); 
            session.close(); 
            return true; 
          } catch (DataAccessException exception) { 
            exception.printStackTrace(); 
          } 
          return false; 
        } 
      } 

```

1.  添加 connection_new.xml 以配置 SessionFactory 和其他详细信息，如下所示：

```java
      <context:annotation-config /> 
      <context:component-scan base-package="com.packt.ch03.*"> 
      </context:component-scan> 

      <bean id="dataSource" 
        class="org.springframework.jdbc.datasource. 
        DriverManagerDataSource"> 
        <!-properties for dataSourceà 
      </bean> 

      <bean id="sessionFactory" class=  
        "org.springframework.orm.hibernate5.LocalSessionFactoryBean"> 
        <property name="dataSource" ref="dataSource" /> 
        <property name="mappingResources"> 
          <list> 
            <value>book.hbm.xml</value> 
          </list> 
        </property> 
        <property name="hibernateProperties"> 
          <props> 
            <prop key=      
              "hibernate.dialect">org.hibernate.dialect.MySQLDialect 
            </prop> 
            <prop key="hibernate.show_sql">true</prop> 
            <prop key="hibernate.hbm2ddl.auto">update</prop> 
          </props> 
        </property> 
      </bean> 

```

1.  将 MainBookDAO_operations.java 创建或复制以获取 bean 'bookDAO_sessionFactory'以测试应用程序。代码将是：

```java
      public static void main(String[] args) { 
       // TODO Auto-generated method stub 
       ApplicationContext context=new  
         ClassPathXmlApplicationContext("connection_new.xml"); 
       BookDAO bookDAO=(BookDAO)  
         context.getBean("bookDAO_sessionFactory"); 
       //add book
       int rows=bookDAO.addBook(new Book("Java EE 7 Developer  
         Handbook", 97815674L,"PacktPub  
         publication",332,"explore the Java EE7  
         programming","Peter pilgrim")); 
       if(rows>0) 
       { 
         System.out.println("book inserted successfully"); 
       } 
       else
        System.out.println("SORRY!cannot add book"); 

      //update the book
      rows=bookDAO.updateBook(97815674L,432); 
      if(rows>0) 
      { 
        System.out.println("book updated successfully"); 
      }
      else
        System.out.println("SORRY!cannot update book"); 
        //delete the book
        boolean deleted=bookDAO.deleteBook(97815674L); 
        if(deleted) 
        { 
          System.out.println("book deleted successfully"); 
        }
        else
          System.out.println("SORRY!cannot delete book"); 
      } 

```

我们已经看到了如何配置 HibernateTemplate 在 XML 中。它与事务广泛工作，但我们还没有讨论过什么是事务，它的配置以及如何管理它？我们将在接下来的几章中讨论它。

实时应用在每个步骤中处理大量数据。比如说我们想要找一本书。使用 hibernate 我们只需调用一个返回书籍的方法，这个方法取决于书籍的 ISBN。在日常生活中，这本书会被搜索无数次，每次数据库都会被访问，导致性能问题。相反，如果有一种机制，当再次有人索求这本书时，它会使用前一次查询的结果，那就太好了。Spring 3.1 引入了有效且最简单的方法——'缓存'机制来实现它，并在 4.1 中添加了 JSR-107 注解支持。缓存的结果将存储在缓存库中，下次将用于避免不必要的数据库访问。你可能想到了缓冲区，但它与缓存不同。缓冲区是用于一次性写入和读取数据的临时中间存储。但缓存是为了提高应用程序的性能而隐藏的，数据在这里被多次读取。

缓存库是对象从数据库获取后保存为键值对的位置。Spring 支持以下库，

**基于 JDK 的 ConcurrentMap 缓存：**

在 JDK ConcurrentMap 中用作后端缓存存储。Spring 框架具有 SimpleCacheManager 来获取缓存管理器并给它一个名称。这种缓存最适合相对较小的数据，这些数据不经常更改。但它不能用于 Java 堆之外存储数据，而且没有内置的方法可以在多个 JVM 之间共享数据。

**基于 EhCache 的缓存：**

EhcacheChacheManager 用于获取一个缓存管理器，其中配置 Ehcache 配置规范，通常配置文件名为 ehcache.xml。开发者可以为不同的数据库使用不同的缓存管理器。

**Caffeine 缓存：**

Caffeine 是一个基于 Java8 的缓存库，提供高性能。它有助于克服 ConcurrentHashMap 的重要缺点，即它直到显式移除数据才会持久化。除此之外，它还提供数据的自动加载、基于时间的数据过期以及被驱逐的数据条目的通知。

Spring 提供了基于 XML 以及注解的缓存配置。最简单的方法是使用注解 based 配置。从 Spring 3.1 开始，版本已启用 JSR-107 支持。为了利用 JSR-107 的缓存，开发人员需要首先进行缓存声明，这将帮助识别要缓存的方法，然后配置缓存以通知数据存储在哪里。

#### 缓存声明

缓存声明可以使用注解以及基于 XML 的方法。以下开发人员可以使用注解进行声明：

##### `@Cacheable`:

该注解用于声明这些方法的结果将被存储在缓存中。它带有与之一致的缓存名称。每次开发人员调用方法时，首先检查缓存以确定调用是否已经完成。

##### `@Caching`:

当需要在同一个方法上嵌套多个 `@CacheEvict`、`@CachePut` 注解时使用该注解。

##### `@CacheConfig`:

使用注解 `@CacheConfig` 来注解类。对于使用基于缓存的注解 annotated 的类方法，每次指定缓存名称。如果类有多个方法，则使用 `@CacheConfig` 注解允许我们只指定一次缓存名称。

##### `@CacheEvict`:

用于从缓存区域删除未使用数据。

##### `@CachePut`

该注解用于在每次调用被其注解的方法时更新缓存结果。该注解的行为与 `@Cacheable` 正好相反，因为它强制调用方法以更新缓存，而 `@Cacheable` 跳过执行。

#### 缓存配置：

首先，为了启用基于注解的配置，Spring 必须使用缓存命名空间进行注册。以下配置可用于声明缓存命名空间并注册注解：

```java
<beans xmlns="http://www.springframework.org/schema/beans" 
  xmlns:cache="http://www.springframework.org/schema/cache" 
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"  
xsi:schemaLocation="http://www.springframework.org/schema/beans 
    http://www.springframework.org/schema/beans/spring-beans.xsd  
  http://www.springframework.org/schema/cache 
  http://www.springframework.org/schema/cache/spring-cache.xsd"> 
        <cache:annotation-driven /> 
</beans> 

```

注册完成后，现在是提供配置以指定存储库的名称以及使用哪个缓存管理器存储库结果的时候了。我们将在 `SimpleCacheManager` 的示例演示中很快定义这些配置。

让我们在我们的 Book 应用程序中集成 JDK 基于的 `ConcurrentMap` 存储库。我们将使用 `Ch03_Spring_Hibernate_Integration` 作为演示的基础项目。按照集成的步骤操作，

1.  创建一个名为 `Ch03_CacheManager` 的新 Java 应用程序，并添加 Spring、JDBC 和 hibernate 的 jar 文件。你也可以参考 `Ch03_Spring_Hibernate_Integration` 应用程序。

1.  在 `com.packt.ch03.beans` 包中创建或复制 `Book.java` 文件。

1.  在 `com.packt.ch03.dao` 包中创建或复制 `BookDAO` 接口，并向其添加一个使用 ISBN 从数据库中搜索书籍的方法。该方法的签名如下所示：

```java
      public Book getBook(long ISBN); 

```

1.  在 `BookDAO_SessionFactory_Cache` 中实现方法，正如我们在 Hibernate 应用程序中的 `BookDAO_SessionFactory.java` 中所做的那样。从数据库获取书籍的方法将是：

```java
      public Book getBook(long ISBN) { 
        // TODO Auto-generated method stub 
        Session session = sessionFactory.openSession(); 
        Transaction transaction = session.beginTransaction(); 
        Book book = null; 
        try { 
          book = session.get(Book.class, ISBN); 
          transaction.commit(); 
          session.close(); 
        } catch (DataAccessException exception) { 
          exception.printStackTrace(); 
          book; 
      } 

```

该方法将使用'repo'存储库来缓存结果。

1.  将 book.hbm.xml 复制到类路径中。

1.  添加带有主函数的 MainBookDAO_Cache.java，以从数据库获取数据，但故意我们会如下的获取两次数据：

```java
      public static void main(String[] args) { 
        // TODO Auto-generated method stub 
        ApplicationContext context=new  
          ClassPathXmlApplicationContext("connection_new.xml"); 
        BookDAO bookDAO=(BookDAO)   
          context.getBean("bookDAO_sessionFactory"); 
        Book book=bookDAO.getBook(97815674L);    

        System.out.println(book.getBookName()+ 
          "\t"+book.getAuthor()); 
        Book book1=bookDAO.getBook(97815674L); 
        System.out.println(book1.getBookName()+ 
          "\t"+book1.getAuthor()); 
      } 

```

1.  在执行之前，请确保我们要搜索的 ISBN 已经存在于数据库中。我们将得到以下输出：

```java
      Hibernate: select book0_.ISBN as ISBN1_0_0_, book0_.book_name as        book_nam2_0_0_, book0_.description as descript3_0_0_,
      book0_.book_author as book_aut4_0_0_, book0_.book_price as
      book_pri5_0_0_ from book_hib book0_ where book0_.ISBN=? 
      book:-Java EE 7 Developer Handbook  Peter pilgrim 

      Hibernate: select book0_.ISBN as ISBN1_0_0_, book0_.book_name as        book_nam2_0_0_, book0_.description as descript3_0_0_,  
      book0_.book_author as book_aut4_0_0_, book0_.book_price as 
      book_pri5_0_0_ from book_hib book0_ where book0_.ISBN=? 
      book1:-Java EE 7 Developer Handbook  Peter pilgrim 

```

上述输出清楚地显示了搜索书籍的查询执行了两次，表示数据库被访问了两次。

现在让我们配置 Cache manager 以缓存搜索书籍的结果，如下所示，

1.  使用@Cacheable 注解来标记那些结果需要被缓存的方法，如下所示：

```java
      @Cacheable("repo") 
      public Book getBook(long ISBN) {// code will go here } 

```

1.  在 connection_new.xml 中配置缓存命名空间，正如我们已经在讨论中提到的。

1.  在 XML 中注册基于注解的缓存，如下所示：

```java
      <cache:annotation-driven /> 

```

1.  为设置存储库为'repo'添加 CacheManger，如下配置所示：

```java
      <bean id="cacheManager"  
        class="org.springframework.cache.support.SimpleCacheManager"> 
        <property name="caches"> 
          <set> 
            <bean class="org.springframework.cache.concurrent.
              ConcurrentMapCache FactoryBean"> 
              <property name="name" value="repo"></property> 
            </bean> 
          </set> 
        </property> 
      </bean> 

```

1.  不更改地执行 MainBookDAO_Cache.java 以得到以下输出：

```java
      Hibernate: select book0_.ISBN as ISBN1_0_0_, book0_.book_name as        book_nam2_0_0_, book0_.description as descript3_0_0_,  
      book0_.book_author as book_aut4_0_0_, book0_.book_price as 
      book_pri5_0_0_ from book_hib book0_ where book0_.ISBN=? 
      book:-Java EE 7 Developer Handbook  Peter pilgrim 

      book1:-Java EE 7 Developer Handbook  Peter pilgrim 

```

控制台输出显示，即使我们两次搜索了书籍，查询也只执行了一次。由`getBook()`第一次获取的书籍结果被缓存起来，下次有人请求这本书而没有加热数据库时，会使用这个缓存结果。

## 总结

****

在本章中，我们深入讨论了持久层。讨论使我们了解了如何通过 Spring 使用 DataSource 将 JDBC 集成到应用程序中。但使用 JDBC 仍然会让开发者接触到 JDBC API 及其操作，如获取 Statement、PreparedStatement 和 ResultSet。但 JdbcTemplate 和 JdbcDaoSupport 提供了一种在不涉及 JDBC API 的情况下执行数据库操作的方法。我们还看到了 Spring 提供的异常层次结构，可以根据应用程序的情况使用它。我们还讨论了 Hibernate 作为 ORM 工具及其在框架中的集成。缓存有助于最小化对数据库的访问并提高性能。我们讨论了缓存管理器以及如何将 CacheManger 集成到应用程序中。

在下一章中，我们将讨论面向方面的编程，它有助于处理交叉技术。


## 第四章。面向切面编程

上一章关于 Spring DAO 的内容为我们提供了很好的实践，了解了 Spring 如何通过松耦合方式处理 JDBC API。但是，我们既没有讨论 JDBC 事务，也没有探讨 Spring 如何处理事务。如果你已经处理过事务，你了解其步骤，而且更加清楚这些步骤是重复的，并且分散在代码各处。一方面，我们提倡使用 Spring 来避免代码重复，另一方面，我们却在编写这样的代码。Java 强调编写高内聚的模块。但是在我们的代码中编写事务管理将不允许我们编写内聚的模块。此外，编写代码的目的并非是为了事务。它只是提供支持，以确保应用程序的业务逻辑不会产生任何不期望的效果。我们还没有讨论过如何处理这种支持功能以及应用程序开发的主要目的。除了事务之外，还有哪些功能支持应用程序的工作？本章将帮助我们编写没有代码重复的高度内聚的模块，以处理这些支持功能。在本章中，我们将讨论以下几点：

+   交叉技术是什么？

+   交叉技术在应用程序开发中扮演什么角色？

+   我们将讨论关于面向切面编程（AOP）以及 AOP 在处理交叉技术中的重要作用。

+   我们将深入探讨 AOP 中的方面、建议和切点是什么。

软件应用程序为客户的问题提供了一个可靠的解决方案。尽管我们说它是可靠的，但总是有可能出现一些运行时问题。因此，在开发过程中，软件的维护同样重要。每当应用程序中出现问题时，客户都会回来找开发者寻求解决方案。除非客户能够准确地说明问题的原因，否则开发者是无能为力的。为了防止问题的再次发生，开发者必须重新创建相同的情况。在企业应用程序中，由于模块数量众多，重新创建相同的问题变得复杂。如果有一个人能够持续跟踪用户在做什么，那就太好了。这个跟踪器的跟踪帮助开发者了解出了什么问题，以及如何轻松地重新创建它。是的，我在谈论日志记录机制。

让我们考虑另一个非常常见的铁路票务预订情况。在票务预订时，我们从图表中选择可用的座位并继续进行资金转账。有时资金成功转账，票也预订了。但不幸的是，有时由于资金交易时间过长，填写表格延迟或一些服务器端问题可能会导致资金转账失败而无法预订票。资金被扣除而没有发行票。客户将不高兴，而且对于退款来说会更加紧张。这种情况需要借助事务管理谨慎处理，以便如果未发行票，资金应退还到客户账户中。手动操作将是繁琐的任务，而事务管理则优雅地处理了这个问题。

我们可以编写不包含日志记录或事务管理的可运行代码，因为这两者都不属于您的业务逻辑。Java 应用程序的核心是提供一种定制化的、简单的解决方案来解决企业问题。业务逻辑位于中心，提供应用程序的主要功能，有时被称为“主要关注点”。但它还必须支持其他一些功能或服务，这一点不容忽视。这些服务在应用程序中扮演着重要的角色。要么应用程序的迁移会耗时，要么在运行时回溯问题将变得困难。这些关注点大多伴随着重复的代码散布在应用程序中。这些次要关注点被称为“横切关注点”，有时也称为“水平关注点”。日志记录、事务管理和安全机制是开发者在应用程序中使用的横切关注点。

下面的图表展示了横切关注点（如日志记录和事务管理）如何在应用程序代码中散布：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/lrn-spr5/img/image_04_001.png)

## 面向切面编程（AOP）

****

与面向对象编程类似，面向切面编程也是一种编程风格，它允许开发者通过将横切关注点与业务逻辑代码分离来编写连贯的代码。AOP 概念是由 Gregor KicZales 及其同事开发的。它提供了编写横切关注点的不同方法或工具。

在 AOP 中处理横切关注点，可以在一个地方编写，从而实现以下好处：

+   减少代码重复以实现编写整洁的代码。

+   有助于编写松耦合的模块。

+   有助于实现高度凝聚的模块。

+   开发者可以专注于编写业务逻辑。

+   在不更改现有代码的情况下，轻松更改或修改代码以添加新功能。

要理解 AOP，我们必须了解以下常见术语，没有它们我们无法想象 AOP。

### 连接点

连接点是应用程序中可以插入方面以执行一些杂项功能的位置，而不会成为实际业务逻辑的一部分。每段代码都有无数的机会，可以被视为连接点。在应用程序中最小的单元类有数据成员、构造函数、设置器和获取器，以及其他功能类。每个都可以是应用方面的机会。Spring 只支持方法作为连接点。

### 切点（Pointcut）

连接点是应用方面的机会，但并非所有机会都被考虑在内。切点是开发者决定应用方面以对横切关注执行特定动作的地方。切点将使用方法名、类名、正则表达式来定义匹配的包、类、方法，在这些地方可以应用方面。

### 建议

在切点处方面所采取的动作称为“建议”（advice）。建议包含为相应的横切关注点执行的代码。如果我们把方法作为连接点，方面可以在方法执行之前或之后应用，也可能是方法有异常处理代码，方面可以插入其中。以下是 Spring 框架中可用的建议。

#### 前置（Before）

前置（Before）建议包含在匹配切点表达式的业务逻辑方法执行之前应用的实现。除非抛出异常，否则将继续执行该方法。可以使用@Before 注解或<aop:before>配置来支持前置建议。

#### 后抛出（After）

在后置（After）建议中，实现将在业务逻辑方法执行之后应用，无论方法执行成功还是抛出异常。可以使用@After 注解或<aop:after>配置来支持后置建议，将其应用于一个方法。

#### 后返回（After returning）

后返回（After Returning）建议的实现仅在业务逻辑方法成功执行后应用。可以使用@AfterReturning 注解或<aop:after-returning>配置来支持后返回建议。后返回建议方法可以使用业务逻辑方法返回的值。

#### 后抛出（After throwing）

后抛出（After Throwning）建议的实现应用于业务逻辑方法抛出异常之后。可以使用@AfterThrowing 注解或<aop:throwing>配置来支持后抛出建议，将其应用于一个方法。

#### 环绕（Around）

环绕通知是所有通知中最重要的一种，也是唯一一种在业务逻辑方法执行前后都会应用的通知。它可用于通过调用 ProceedingJoinPoint 的 proceed()方法来选择是否继续下一个连接点。proceed()通过返回其自身的返回值来帮助选择是否继续到连接点。它可用于开发人员需要执行预处理、后处理或两者的场景。计算方法执行所需时间就是一个这样的场景。可以使用@Around 注解或<aop:around>配置通过将其应用于一个方法来支持环绕通知。

### Aspect（方面）

方面通过切入点表达式和通知来定义机会，以指定动作何时何地被执行。使用@Aspect 注解或<aop:aspect>配置将一个类声明为方面。

### Introduction（介绍）

介绍可以帮助在不需要更改现有代码的情况下，在现有类中声明额外的方法和字段。Spring AOP 允许开发人员向任何被方面通知的类引入新的接口。

### Target object（目标对象）

目标对象是被应用了方面的类的对象。Spring AOP 在运行时创建目标对象的代理。从类中覆盖方法并将通知包含进去以获得所需结果。

### AOP proxy（AOP 代理）

默认情况下，Spring AOP 使用 JDK 的动态代理来获取目标类的代理。使用 CGLIB 进行代理创建也非常常见。目标对象始终使用 Spring AOP 代理机制进行代理。

### Weaving（编织）

我们作为开发者将业务逻辑和方面代码写在两个分开的模块中。然后这两个模块必须合并为一个被代理的目标类。将方面插入业务逻辑代码的过程称为“编织”。编织可以在编译时、加载时或运行时发生。Spring AOP 在运行时进行编织。

让我们通过一个非常简单的例子来理解所讨论的术语。我的儿子喜欢看戏剧。所以我们去看了一场。我们都知道，除非我们有入场券，否则我们不能进入。显然，我们首先需要收集它们。一旦我们有了票，我的儿子把我拉到座位上，兴奋地指给我看。演出开始了。这是一场给孩子们看的有趣戏剧。所有孩子们都在笑笑话，为对话鼓掌，在戏剧场景中感到兴奋。休息时，观众中的大多数人去拿爆米花、小吃和冷饮。每个人都喜欢戏剧，并快乐地从出口离开。现在，我们可能认为我们都知道这些。我们为什么要讨论这个，它与方面有什么关系。我们是不是偏离了讨论的主题？不，我们正在正确的轨道上。再等一会儿，你们所有人也会同意。这里看戏剧是我们的主要任务，让我们说这是我们的业务逻辑或核心关注。购买门票，支付钱，进入剧院，戏剧结束后离开是核心关注的一部分功能。但我们不能安静地坐着，我们对正在发生的事情做出反应？我们鼓掌，笑，有时甚至哭。但这些是主要关注点吗？不！但没有它们，我们无法想象观众看戏剧。这些将是每个观众自发执行的支持功能。正确！！！这些是交叉关注点。观众不会为交叉关注点单独收到指示。这些反应是方面建议的一部分。有些人会在戏剧开始前鼓掌，少数人在戏剧结束后鼓掌，最兴奋的是当他们感到的时候。这只是方面的前置、后置或周围建议。如果观众不喜欢戏剧，他们可能会在中间离开，类似于抛出异常。在非常不幸的日子里，演出可能会被取消，甚至可能在中间停止，需要组织者作为紧急情况介绍。希望现在你知道了这些概念以及它们的实际方法。我们将在演示中简要介绍这些以及更多内容。

在继续演示之前，让我们首先讨论市场上的一些 AOP 框架如下。

#### AspectJ

AspectJ 是一个易于使用和学习的 Java 兼容框架，用于集成跨切实现的交叉。AspectJ 是在 PARC 开发的。如今，由于其简单性，它已成为一个著名的 AOP 框架，同时具有支持组件模块化的强大功能。它可用于对静态或非静态字段、构造函数、私有、公共或受保护的方法应用 AOP。

#### AspectWertz

AspectWertz 是另一个与 Java 兼容的轻量级强大框架。它很容易集成到新旧应用程序中。AspectWertz 支持基于 XML 和注解的方面编写和配置。它支持编译时、加载时和运行时编织。自 AspectJ5 以来，它已被合并到 AspectJ 中。

#### JBoss AOP

JBoss AOP 支持编写方面以及动态代理目标对象。它可以用于静态或非静态字段、构造函数、私有、公共或受保护的方法上使用拦截器。

#### Dynaop

Dynaop 框架是一个基于代理的 AOP 框架。该框架有助于减少依赖性和代码的可重用性。

#### CAESAR

CASER 是一个与 Java 兼容的 AOP 框架。它支持实现抽象组件以及它们的集成。

#### Spring AOP

这是一个与 Java 兼容、易于使用的框架，用于将 AOP 集成到 Spring 框架中。它提供了与 Spring IoC 紧密集成的 AOP 实现，是基于代理的框架，可用于方法执行。

Spring AOP 满足了大部分应用交叉关注点的需求。但以下是一些 Spring AOP 无法应用的限制，

+   Spring AOP 不能应用于字段。

+   我们无法在一个方面上应用任何其他方面。

+   私有和受保护的方法不能被建议。

+   构造函数不能被建议。

Spring 支持 AspectJ 和 Spring AOP 的集成，以减少编码实现交叉关注点。Spring AOP 和 AspectJ 都用于实现交叉技术，但以下几点有助于开发者在实现时做出最佳选择：

+   Spring AOP 基于动态代理，支持方法连接点，但 AspectJ 可以应用于字段、构造函数，甚至是私有、公共或受保护的，支持细粒度的建议。

+   Spring AOP 不能用于调用同一类方法的方法、静态方法或最终方法，但 AspectJ 可以。

+   AspectJ 不需要 Spring 容器来管理组件，而 Spring AOP 只能用于由 Spring 容器管理的组件。

+   Spring AOP 支持基于代理模式的运行时编织，而 AspectJ 支持编译时编织，不需要创建代理。对象的代理将在应用程序请求 bean 时创建一次。

+   由 Spring AOP 编写的方面是基于 Java 的组件，而用 AspectJ 编写的方面是扩展 Java 的语言，所以开发者在使用之前需要学习它。

+   Spring AOP 通过使用@Aspect 注解标注类或简单的配置来实现非常简单。但是，要使用 AspectJ，则需要创建*.aj 文件。

+   Spring AOP 不需要任何特殊的容器，但方面需要使用 AspectJ 编译。

+   AspectJ 是现有应用程序的最佳选择。

    ### 注意

    如果没有 final，静态方法的简单类，则可以直接使用 Spring AOP，否则选择 AspectJ 来编写切面。

让我们深入讨论 Spring AOP 及其实现方式。Spring AOP 可以通过基于 XML 的切面配置或 AspectJ 风格的注解实现。基于 XML 的配置可以分成几个点，使其变得稍微复杂。在 XML 中，我们无法定义命名切点。但由注解编写的切面位于单个模块中，支持编写命名切点。所以，不要浪费时间，让我们开始基于 XML 的切面开发。

### 基于 XML 的切面配置

以下是在开发基于 XML 的切面时需要遵循的步骤，

1.  选择要实现的重叠关注点

1.  编写切面以满足实现重叠关注点的需求。

1.  在 Spring 上下文中注册切面作为 bean。

1.  切面配置写为：

* 在 XML 中添加 AOP 命名空间。

* 添加切面配置，其中将包含切点表达式和建议。

* 注册可以应用切面的 bean。

开发人员需要从可用的连接点中决定跟踪哪些连接点，然后需要使用表达式编写切点以针对它们。为了编写这样的切点，Spring 框架使用 AspectJ 的切点表达式语言。我们可以在表达式中使用以下设计器来编写切点。

#### 使用方法签名

可以使用方法签名从可用连接点定义切点。表达式可以使用以下语法编写：

```java
expression(<scope_of_method>    <return_type><fully_qualified_name_of_class>.*(parameter_list)
```

Java 支持 private，public，protected 和 default 作为方法范围，但 Spring AOP 只支持公共方法，在编写切点表达式时。参数列表用于指定在匹配方法签名时要考虑的数据类型。如果开发人员不想指定参数数量或其数据类型，可以使用两个点(..)。

让我们考虑以下表达式，以深入理解表达式的编写，从而决定哪些连接点将受到建议：

+   `expression(* com.packt.ch04.MyClass.*(..))` - 指定 com.packt.cho3 包内 MyClass 的具有任何签名的所有方法。

+   `expression(public int com.packt.ch04.MyClass.*(..))` - 指定 com.packt.cho3 包内 MyClass 中返回整数值的所有方法。

+   `expression(public int com.packt.ch04.MyClass.*(int,..))` - 指定返回整数及其第一个整数类型参数的 MyClass 中所有方法，该类位于 com.packt.cho3 包内。

+   `expression(* MyClass.*(..))` - 指定所有来自 MyClass 的具有任何签名的方法都将受到建议。这是一个非常特殊的表达式，只能在与建议的类在同一包中使用。

#### 使用类型

类型签名用于匹配具有指定类型的连接点。我们可以使用以下语法来指定类型：

```java
within(type_to_specify) 

```

这里类型将是包或类名。以下是一些可以编写以指定连接点的表达式：

+   `within(com.packt.ch04.*)` - 指定属于 com.packt.ch04 包的所有类的所有方法

+   `within(com.packt.ch04..*)` - 指定属于 com.packt.ch04 包及其子包的所有类的所有方法。我们使用了两个点而不是一个点，以便同时跟踪子包。

+   `within(com.packt.ch04.MyClass)` - 指定属于 com.packt.ch04 包的 MyClass 的所有方法

+   `within(MyInterface+)` - 指定实现 MyInterface 的所有类的所有方法。

#### 使用 Bean 名称

Spring 2.5 及以后的所有版本都支持在表达式中使用 bean 名称来匹配连接点。我们可以使用以下语法：

```java
bean(name_of_bean) 

```

考虑以下示例：

`bean(*Component)` - 这个表达式指定要匹配的连接点属于名称以 Component 结尾的 bean。这个表达式不能与 AspectJ 注解一起使用。

#### 使用 this

'this'用于匹配目标点的 bean 引用是指定类型的实例。当表达式指定类名而不是接口时使用。当 Spring AOP 使用 CGLIB 进行代理创建时使用。

#### 5.sing target

目标用于匹配目标对象是指定类型的接口的连接点。当 Spring AOP 使用基于 JDK 的代理创建时使用。仅当目标对象实现接口时才使用目标。开发者甚至可以配置属性'proxy target class'设置为 true。

让我们考虑以下示例以了解表达式中使用 this 和 target：

```java
package com.packt.ch04; 
Class MyClass implements MyInterface{ 
  // method declaration 
} 

```

我们可以编写表达式来针对方法：

`target( com.packt.ch04.MyInterface)` 或

`this(com.packt.ch04.MyClass)`

#### 用于注解跟踪

开发者可以编写不跟踪方法而是跟踪应用于注解的连接点表达式。让我们以下示例了解如何监控注解。

**使用 with execution:**

execution(@com.packt.ch03.MyAnnotation) - 指定被 MyAnnotation 注解标记的方法或类。

execution(@org.springframework.transaction.annotation.Transactional) - 指定被 Transactional 注解标记的方法或类。

**使用 with @target:**

它用于考虑被特定注解标记的类的连接点。以下示例解释得很清楚，

@target(com.packt.ch03.MyService) - 用于考虑被 MyService 注解标记的连接点。

**使用@args:**

表达式用于指定参数被给定类型注解的连接点。

@args(com.packt.ch04.annotations.MyAnnotation)

上述表达式用于考虑其接受的对象被@Myannotation 注解标记的连接点。

**使用@within:**

表达式用于指定由给定注解指定的类型的连接点。

@within(org.springframework.stereotype.Repository)

上述表达式有助于为被@Repository 标记的连接点提供通知。

**使用@annotation:**

@annotation 用于匹配被相应注解标记的连接点。

@annotation(com.packt.ch04.annotations.Annotation1)

表达式匹配所有由 Annotation1 标记的连接点。

让我们使用切点表达式、通知来实现日志方面，以理解实时实现。我们将使用上一章开发的 Ch03_JdbcTemplates 应用程序作为基础，将其与 Log4j 集成。第一部分我们将创建一个主应用程序的副本，第二部分将其与 log4j 集成，第三部分将应用自定义日志方面。

## 第一部分：创建核心关注点（JDBC）的应用程序

****

按照以下步骤创建基础应用程序：

1.  创建一个名为 Ch04_JdbcTemplate_LoggingAspect 的 Java 应用程序，并添加 Spring 核心、Spring JDBC、spring-aop、aspectjrt-1.5.3 和 aspectjweaver-1.5.3.jar 文件所需的 jar。

1.  将所需源代码文件和配置文件复制到相应的包中。应用程序的最终结构如下所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/lrn-spr5/img/image_04_002.png)

1.  从 Ch03_JdbcTemplates 复制 connection_new.xml 到应用程序的类路径中，并编辑它以删除 id 为'namedTemplate'的 bean。

## 第二部分：Log4J 的集成

****

Log4j 是最简单的事情。让我们按照以下步骤进行集成：

1.  要集成 Log4J，我们首先必须将 log4j-1.2.9.jar 添加到应用程序中。

1.  在类路径下添加以下配置的 log4j.xml 以添加控制台和文件监听器：

```java
      <!DOCTYPE log4j:configuration SYSTEM "log4j.dtd"> 
      <log4j:configuration  
         xmlns:log4j='http://jakarta.apache.org/log4j/'> 
        <appender name="CA"  
          class="org.apache.log4j.ConsoleAppender"> 
          <layout class="org.apache.log4j.PatternLayout"> 
            <param name="ConversionPattern" value="%-4r [%t]  
              %-5p %c %x - %m%n" /> 
          </layout> 
        </appender> 
        <appender name="file"  
          class="org.apache.log4j.RollingFileAppender"> 
          <param name="File" value="C:\\log\\log.txt" /> 
          <param name="Append" value="true" /> 
          <param name="MaxFileSize" value="3000KB" /> 
          <layout class="org.apache.log4j.PatternLayout"> 
            <param name="ConversionPattern" value="%d{DATE}  
              %-5p %-15c{1}: %m%n" /> 
          </layout> 
        </appender> 
        <root> 
          <priority value="INFO" /> 
          <appender-ref ref="CA" /> 
          <appender-ref ref="file" /> 
        </root> 
      </log4j:configuration> 

```

您可以根据需要修改配置。

1.  现在，为了记录消息，我们将添加获取日志记录器和记录机制的代码。我们可以将代码添加到 BookDAO_JdbcTemplate.java，如下所示：

```java
      public class BookDAO_JdbcTemplate implements BookDAO {  
        Logger logger=Logger.getLogger(BookDAO_JdbcTemplate.class); 
        public int addBook(Book book) { 
          // TODO Auto-generated method stub 
          int rows = 0; 
          String INSERT_BOOK = "insert into book  
            values(?,?,?,?,?,?)"; 
          logger.info("adding the book in table"); 

          rows=jdbcTemplate.update(INSERT_BOOK, book.getBookName(),  
            book.getISBN(), book.getPublication(),  
            book.getPrice(), 
            book.getDescription(), book.getAuthor()); 

            logger.info("book added in the table successfully"+  
              rows+"affected"); 
          return rows; 
        } 

```

不要担心，我们不会在每个类和每个方法中添加它，因为我们已经讨论了复杂性和重复代码，让我们继续按照以下步骤编写日志机制方面，以获得与上面编写的代码相同的结果。

## 第三部分：编写日志方面。

****

1.  在 com.packt.ch04.aspects 包中创建一个名为 MyLoggingAspect 的 Java 类，该类将包含一个用于前置通知的方法。

1.  在其中添加一个类型为 org.apache.log4j.Logger 的数据成员。

1.  在其中添加一个 beforeAdvise()方法。方法的签名可以是任何东西，我们在这里添加了一个 JoinPoint 作为参数。使用这个参数，我们可以获取有关方面应用的类的信息。代码如下：

```java
      public class MyLoggingAspect { 
        Logger logger=Logger.getLogger(getClass()); 
        public void beforeAdvise(JoinPoint joinPoint) { 
          logger.info("method will be invoked :- 
            "+joinPoint.getSignature());   
        }       
      } 

```

1.  现在必须在 XML 中分三步配置方面：

*****为 AOP 添加命名空间：

```java
      <beans xmlns="http://www.springframework.org/schema/beans"     
        xmlns:aop="http://www.springframework.org/schema/aop"  
        xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" 
      xsi:schemaLocation="http://www.springframework.org/schema/beans 
        http://www.springframework.org/schema/beans/spring-beans.xsd  
        http://www.springframework.org/schema/aop 
        http://www.springframework.org/schema/aop/spring-aop.xsd">
```

1.  现在我们可以使用 AOP 的标签，通过使用'aop'命名空间：

*****添加一个方面 bean。

1.  在 connection_new.xml 中添加我们想在应用程序中使用的方面的 bean，如下所示：

```java
<bean id="myLogger"
  class="com.packt.ch04.aspects.MyLoggingAspect" />
```

配置切面。

1.  每个<aop:aspect>允许我们在<aop:config>标签内编写切面。

1.  每个切面都将有 id 和 ref 属性。'ref'指的是将调用提供建议的方法的 bean。

1.  为切点表达式配置建议，以及要调用的方法。可以在<aop:aspect>内使用<aop:before>标签配置前置建议。

1.  让我们编写一个适用于'myLogger'切面的前置建议，该建议将在 BookDAO 的 addBook()方法之前调用。配置如下：

```java
      <aop:config>
        <aop:aspect id="myLogger" ref="logging">
          <aop:pointcut id="pointcut1"
            expression="execution(com.packt.ch03.dao.BookDAO.addBook
            (com.packt.ch03.beans.Book))" />
          <aop:before pointcut-ref="pointcut1" 
            method="beforeAdvise"/>
        </aop:aspect>
      </aop:config>
```

1.  执行 MainBookDAO_operation.java 以在控制台获得以下输出：

```java
      0 [main] INFO       org.springframework.context.support.ClassPathXmlApplicationContext -       Refreshing       org.springframework.context.support.ClassPathXmlApplicationContext@5      33e64: startup date [Sun Oct 02 23:44:36 IST 2016]; root of       context hierarchy
      66 [main] INFO       org.springframework.beans.factory.xml.XmlBeanDefinitionReader -       Loading XML bean definitions from class path resource       [connection_new.xml]
      842 [main] INFO       org.springframework.jdbc.datasource.DriverManagerDataSource - Loaded       JDBC driver: com.mysql.jdbc.Driver
      931 [main] INFO com.packt.ch04.aspects.MyLoggingAspect - method       will be invoked :-int com.packt.ch03.dao.BookDAO.addBook(Book)
      book inserted successfully
      book updated successfully
      book deleted successfully
```

BookDAO_JdbTemplate 作为目标对象运行，其代理将在运行时通过编织 addBook()和 beforeAdvise()方法代码来创建。现在既然我们知道了过程，让我们逐一在应用程序中添加不同的切点和建议，并按照以下步骤操作。

### 注意

可以在同一个连接点上应用多个建议，但为了简单地理解切点和建议，我们将每次保留一个建议，并注释掉已经写入的内容。

### 添加返回建议。

让我们为 BookDAO 中的所有方法添加后置建议。

1.  在 MyLoggingAspect 中添加一个后置建议的方法 afterAdvise()，如下所示：

```java
      public void afterAdvise(JoinPoint joinPoint) { 
       logger.info("executed successfully :- 
         "+joinPoint.getSignature()); 
      } 

```

1.  配置切点表达式，以目标 BookDAO 类中的所有方法以及在'myLogger'切面中的 connection_new.xml 中的后置建议。

```java
      <aop:pointcut id="pointcut2"   
        expression="execution(com.packt.ch03.dao.BookDAO.*(..))" /> 
      <aop:after pointcut-ref="pointcut2" method="afterAdvise"/>
```

1.  执行 MainBookDAO_operations.java 以获得以下输出：

```java
999 [main] INFO com.packt.ch04.aspects.MyLoggingAspect - method will be invoked :-int com.packt.ch03.dao.BookDAO.addBook(Book)
1360 [main] INFO com.packt.ch04.aspects.MyLoggingAspect - executed successfully :-int com.packt.ch03.dao.BookDAO.addBook(Book)
book inserted successfully
1418 [main] INFO com.packt.ch04.aspects.MyLoggingAspect - executed successfully :-int com.packt.ch03.dao.BookDAO.updateBook(long,int)
book updated successfully
1466 [main] INFO com.packt.ch04.aspects.MyLoggingAspect - executed successfully :-boolean com.packt.ch03.dao.BookDAO.deleteBook(long)
book deleted successfully
```

下划线的语句清楚地表明建议在所有方法之后被调用。

### 在返回后添加建议。

虽然我们编写了后置建议，但我们无法得到业务逻辑方法返回的值。后返回将帮助我们在以下步骤中获取返回值。

1.  在 MyLoggingAspect 中添加一个返回建议的方法 returnAdvise()，该方法将在返回后调用。代码如下：

```java
      public void returnAdvise(JoinPoint joinPoint, Object val) { 
        logger.info(joinPoint.getSignature()+ " returning val" + val); 
      } 

```

参数'val'将持有返回值。

1.  在'myLogger'下配置建议。我们不需要配置切点，因为我们将会重用已经配置的。如果你想要使用不同的连接点集，首先你需要配置一个不同的切点表达式。我们的配置如下所示：

```java
      <aop:after-returning pointcut-ref="pointcut2"
        returning="val" method="returnAdvise" />
```

其中，

返回-表示要指定返回值传递到的参数的名称。在我们这个案例中，这个名称是'val'，它已在建议参数中绑定。

1.  为了使输出更容易理解，注释掉前置和后置建议配置，然后执行 MainBookDAO_operations.java 以在控制台输出获得以下行：

```java
      1378 [main] INFO  com.packt.ch04.aspects.MyLoggingAspect  - int       com.packt.ch03.dao.BookDAO.addBook(Book)  
      returning val:-1 
      1426 [main] INFO  com.packt.ch04.aspects.MyLoggingAspect  - int       com.packt.ch03.dao.BookDAO.updateBook(long,int) returning val:-1 
      1475 [main] INFO  com.packt.ch04.aspects.MyLoggingAspect  -
      boolean com.packt.ch03.dao.BookDAO.deleteBook(long)
      returning val:-true 

```

每个语句显示了连接点的返回值。

### 添加环绕建议。

如我们之前讨论的，环绕建议在业务逻辑方法前后调用，只有当执行成功时。让我们在应用程序中添加环绕建议：

1.  在`MyLoggingAspect`中添加一个`aroundAdvise()`方法。该方法必须有一个参数是`ProceedingJoinPoint`，以方便应用程序流程到达连接点。代码如下：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/lrn-spr5/img/image_04_003.png)

在`proceed()`之前的部分将在我们称为'Pre processing'的 B.L.方法之前被调用。`ProceedingJoinPoint`的`proceed()`方法将流程导向相应的连接点。如果连接点成功执行，将执行`proceed()`之后的部分，我们称之为'Post processing'。在这里，我们通过在'Pre processing'和'Post processing'之间取时间差来计算完成过程所需的时间。

我们想要编织切面的连接点返回 int，因此 aroundAdvise()方法也返回相同类型的值。如果万一我们使用 void 而不是 int，我们将得到以下异常：

```java
      Exception in thread "main" 
      org.springframework.aop.AopInvocationException: Null return value       from advice does not match primitive return type for: public   
      abstract int  
      com.packt.ch03.dao.BookDAO.addBook(com.packt.ch03.beans.Book) 

```

1.  现在让我们在'myLogger'中添加 around advice，如下所示：

```java
      <aop:around pointcut-ref="pointcut1" method="aroundAdvise" />
```

1.  在注释掉之前配置的 advice 的同时，在控制台执行`MainBookDAO`以下日志，

```java
      1016 [main] INFO com.packt.ch04.aspects.MyLoggingAspect - around       advise before int com.packt.ch03.dao.BookDAO.addBook(Book)  
      B.L.method getting invoked
      1402 [main] INFO com.packt.ch04.aspects.MyLoggingAspect - number       of rows affected:-1
      1402 [main] INFO com.packt.ch04.aspects.MyLoggingAspect - around
      advise after int com.packt.ch03.dao.BookDAO.addBook(Book)
      B.L.method getting invoked
      1403 [main] INFO com.packt.ch04.aspects.MyLoggingAspect - int
      com.packt.ch03.dao.BookDAO.addBook(Book) took 388 to complete
```

### 添加 after throwing advice

正如我们所知，一旦匹配的连接点抛出异常，after throwing advice 将被触发。在执行 JDBC 操作时，如果我们尝试在 book 表中添加重复的条目，将抛出 DuplicateKeyException，我们只需要使用以下步骤，借助 after throwing advice 进行日志记录：

1.  在`MyLoggingAspect`中添加`throwingAdvise()`方法，如下所示：

```java
      public void throwingAdvise(JoinPoint joinPoint,  
        Exception exception) 
      { 
        logger.info(joinPoint.getTarget().getClass().getName()+"  
          got and exception" + "\t" + exception.toString()); 
      } 

```

开发人员可以自由选择签名，但由于连接点方法将抛出异常，为 advice 编写的方法将有一个参数是 Exception 类型，这样我们就可以记录它。我们还在参数中添加了 JoinPoint 类型，因为我们想要处理方法签名。

1.  在'myLogger'配置中的`connection_new.xml`中添加配置。要添加的配置是：

```java
      <aop:after-throwing pointcut-ref="pointcut1"
        method="throwingAdvise" throwing="exception" />
```

<aop:after-throwing> 将采取：

* **pointcut-ref** - 我们想要编织连接点的 pointcut-ref 的名称。

* **method** - 如果抛出异常，将调用的方法名称。

* **throwing** - 从 advise 方法签名绑定到的参数名称，异常将被传递给它。我们使用的签名中的参数名称是'exception'。

1.  执行`MainBookDAO_operations`，并故意添加一个 ISBN 已存在于 Book 表中的书籍。在执行前，注释掉为其他 advice 添加的先前配置。我们将得到以下输出：

```java
      1322 [main] ERROR com.packt.ch04.aspects.MyLoggingAspect  - int 
      com.packt.ch03.dao.BookDAO.addBook(Book) got and exception  
      org.springframework.dao.DuplicateKeyException: 
      PreparedStatementCallback; SQL [insert into book 
      values(?,?,?,?,?,?)]; Duplicate entry '9781235' for key 1; nested 
      exception is 
      com.mysql.jdbc.exceptions.jdbc4.MySQLIntegrityConstraintViolation
      Exception: Duplicate entry '9781235' for key 1 

```

1.  如果您使用不同的 ISBN 添加书籍，该 ISBN 不在 book 表中，上述 ERROR 日志将不会显示，因为没有异常，也没有 advice 会被触发。

上述示例清楚地展示了如何使用 XML 编写和配置切面。接下来，让我们来编写基于注解的切面。

## 基于注解的切面。

* * *

方面可以声明为用 AspectJ 注解支持的 Java 类，以支持编写切点和建议。Spring AspectJ OP 实现提供了以下注解，用于编写方面：

+   **@Aspect** - 用于将 Java 类声明为方面。

+   **@Pointcut** - 使用 AspectJ 表达式语言声明切点表达式。

+   **@Before** - 用于声明在业务逻辑（B.L.）方法之前应用的前置建议。@Before 支持以下属性，

    +   **value** - 被@Pointcut 注解的方法名称

    +   **argNames** - 指定连接点处的参数名称

+   **@After** - 用于声明在 B.L.方法返回结果之前应用的后建议。@After 也支持与@Before 建议相同的属性。

+   **@AfterThrowing** - 用于声明在 B.L.方法抛出异常之后应用的后抛出建议。@AfterThrowing 支持以下属性：

    +   **pointcut**- 选择连接点的切点表达式

    +   **throwing**- 与 B.L.方法抛出的异常绑定在一起的参数名称。

+   **@AfterReturning** - 用于声明在 B.L.方法返回结果之前但返回结果之后应用的后返回建议。该建议有助于从 B.L.方法获取返回结果的值。@AfterReturning 支持以下属性，

    +   **pointcut**- 选择连接点的切点表达式

    +   **returning**- 与 B.L.方法返回的值绑定的参数名称。

+   **@Around** - 用于声明在 B.L.方法之前和之后应用的环绕建议。@Around 支持与@Before 或@After 建议相同的属性。

我们必须在 Spring 上下文中声明配置，以禁用 bean 的代理创建。AnnotationAwareAspectJAutoproxyCreator 类在这方面有帮助。我们可以通过在 XML 文件中包含以下配置来简单地为@AspectJ 支持注册类：

```java
<aop:aspectj-autoproxy/> 

```

在 XML 中添加命名空间'aop'，该命名空间已经讨论过。

我们可以按照以下步骤声明和使用基于注解的方面：

1.  声明一个 Java 类，并用@Aspect 注解它。

1.  添加被@Pointcut 注解的方法以声明切点表达式。

1.  根据需求添加建议的方法，并用@Before、@After、@Around 等注解它们。

1.  为命名空间'aop'添加配置。

1.  在配置中作为 bean 添加方面。

1.  在配置中禁用自动代理支持。

让我们在 JdbcTemplate 应用程序中添加基于注解的方面。按照第一部分和第二部分步骤创建名为 Ch04_JdbcTemplate_LoggingAspect_Annotation 的基础应用程序。您可以参考 Ch04_JdbcTemplate_LoggingAspect 应用程序。现在使用以下步骤开发基于注解的日志方面：

1.  在 com.packt.ch04.aspects 包中创建 MyLoggingAspect 类。

1.  用@Aspect 注解它。

1.  在其中添加类型为 org.apache.log4j.Logger 的数据成员。

1.  为应用建议之前的业务逻辑方法 addBook()添加 beforeAdvise()方法。用@Before 注解它。代码如下所示：

```java
      @Aspect 
      public class MyLoggingAspect {
        Logger logger=Logger.*getLogger*(getClass());
        @Before("execution(*  
          com.packt.ch03.dao.BookDAO.addBook(
          com.packt.ch03.beans.Book))") 

        public void beforeAdvise(JoinPoint joinPoint) {
          logger.info("method will be invoked :- 
          "+joinPoint.getSignature()); 
        }
      }
```

1.  如果你还没有做过，编辑 connection_new.xml 以添加'aop'命名空间。

1.  如下的示例中添加 MyLoggingAspect 的 bean：

```java
      <bean id="logging" 
        class="com.packt.ch04.aspects.MyLoggingAspect" />
```

上述配置的替代方案是通过使用@Component 注解来注释 MyLoggingAspect。

1.  通过在 connection_new.xml 中添加配置来禁用 AspectJ 自动代理，如下所示：

```java
      <aop:aspectj-autoproxy/>
```

1.  运行 MainBookDAO-operation.java 以在控制台获取日志：

```java
      23742 [main] INFO  com.packt.ch04.aspects.MyLoggingAspect  - 
      method will be invoked :-int 
      com.packt.ch03.dao.BookDAO.addBook(Book) 

```

为每个建议编写切点表达式可能是一个繁琐且不必要的重复任务。我们可以在标记方法中单独声明切点，如下所示：

```java
      @Pointcut(value="execution(* 
      com.packt.ch03.dao.BookDAO.addBook(com.packt.ch03.beans.Book))") 
        public void selectAdd(){} 

```

然后从建议方法中引用上述内容。我们可以将 beforeAdvise()方法更新为：

```java
      @Before("selectAdd()") 
      public void beforeAdvise(JoinPoint joinPoint) { 
        logger.info("method will be invoked :- 
        "+joinPoint.getSignature()); 
      }
```

1.  一旦我们了解了方面声明的基础，接下来让我们为其他方面和切点添加方法，这些已经在方面声明中使用 XML 讨论过了。方面将如下所示：

```java
      @Aspect 
      public class MyLoggingAspect { 

        Logger logger=Logger.getLogger(getClass()); 
        @Pointcut(value="execution(*com.packt.ch03.dao.BookDAO.addBook(
        com.packt.ch03.beans.Book))") 
        public void selectAdd(){   } 

        @Pointcut(value="execution(*   
          com.packt.ch03.dao.BookDAO.*(..))")

        public void selectAll(){    } 

        // old configuration
        /*
        @Before("execution(* 
        com.packt.ch03.dao.BookDAO.addBook(
        com.packt.ch03.beans.Book))")
        public void beforeAdvise(JoinPoint joinPoint) {
          logger.info("method will be invoked :-
          "+joinPoint.getSignature());
        }
        */
        @Before("selectAdd()") 
        public void beforeAdvise(JoinPoint joinPoint) { 
          logger.info("method will be invoked :- 
          "+joinPoint.getSignature()); 
        }
        @After("selectAll()") 
        public void afterAdvise(JoinPoint joinPoint) { 
          logger.info("executed successfully :- 
          "+joinPoint.getSignature()); 
        }
        @AfterThrowing(pointcut="execution(*
          com.packt.ch03.dao.BookDAO.addBook(
          com.packt.ch03.beans.Book))",  
          throwing="exception") 
        public void throwingAdvise(JoinPoint joinPoint,
          Exception exception)
        {
          logger.error(joinPoint.getSignature()+" got and exception"  
            + "\t" + exception.toString()); 
        }
        @Around("selectAdd()") 
        public int aroundAdvise(ProceedingJoinPoint joinPoint) { 
          long start_time=System.*currentTimeMillis*();
          logger.info("around advise before
          "+joinPoint.getSignature()
          +" B.L.method getting invoked");
        Integer o=null;
        try {
          o=(Integer)joinPoint.proceed();
          logger.info("number of rows affected:-"+o);
        } catch (Throwable e) {
          // TODO Auto-generated catch block
          e.printStackTrace();
        }
        logger.info("around advise after
        "+joinPoint.getSignature()+
        " B.L.method getting invoked");
        long end_time=System.*currentTimeMillis*();
        logger.info(joinPoint.getSignature()+" took " +
        (end_time-start_time)+" to complete");
        return o.intValue();  } 

        @AfterReturning(pointcut="selectAll()", returning="val") 
        public void returnAdvise(JoinPoint joinPoint, Object val) { 
          logger.info(joinPoint.getSignature()+
          " returning val:-" + val); 
        }
      }
```

1.  运行 MainBookDAO.java 以在控制台获取日志消息。

默认情况下，JDK 的动态代理机制将用于创建代理。但是有时目标对象没有实现接口，JDK 的代理机制将失败。在这种情况下，可以使用 CGLIB 来创建代理。为了启用 CGLIB 代理，我们可以编写以下配置：

```java
<aop:config proxy-target-class="true"> 
  <!-aspect configuration à 
</aop:config> 

```

此外，为了强制使用 AspectJ 和自动代理支持，我们可以编写以下配置：

```java
<aop:aspect-autoproxy proxy-target-=class="true"/> 

```

## 引入

* * *

在企业应用程序中，有时开发者会遇到需要引入一组新功能，但又不改变现有代码的情况。使用引入不一定需要改变所有的接口实现，因为这会变得非常复杂。有时开发者会与第三方实现合作，而源代码不可用，引入起到了非常重要的作用。开发者可能有使用装饰器或适配器设计模式的选项，以便引入新功能。但是，方法级 AOP 可以帮助在不编写装饰器或适配器的情况下实现新功能的引入。

引入是一种顾问，它允许在处理交叉关注点的同时引入新的功能。开发者必须使用基于架构的配置的<aop:declare-partents>，或者如果使用基于注解的实现，则使用@DeclareParents。

使用架构添加引入时，<aop:declare-parent>为被建议的 bean 声明一个新的父级。配置如下：

```java
<aop:aspect> 
  <aop:declare-parents types-matching="" implement-interface=" 
    default-impl="" /> 
</aop:aspect> 

```

其中，

+   **类型匹配** - 指定被建议的 been 的匹配类型

+   **实现** - 接口 -  newly introduced interface

+   **默认实现** - 实现新引入接口的类

在使用注解的情况下，开发者可以使用@DeclareParents，它相当于<aop:declare-parents>配置。@DeclareParents 将应用于新引入的接口的属性。@DeclareParents 的语法如下所示：

```java
@DeclareParents(value=" " , defaultImpl=" ") 

```

在哪里，

+   **value** - 指定要与接口引入的 bean

+   **defaultImpl** - 与<aop:declare-parent>属性中的 default-impl 等效，它指定了提供接口实现的类。

让我们在 JdbcTemplate 应用程序中使用介绍。BookDAO 没有获取书籍描述的方法，所以让我们添加一个。我们将使用 Ch03_JdbcTemplate 作为基础应用程序。按照以下步骤使用介绍：

1.  创建一个新的 Java 应用程序，并将其命名为 Ch04_Introduction。

1.  添加所有 Spring 核心、Spring -jdbc、Spring AOP 所需的 jar，正如早期应用程序中所做的那样。

1.  复制 com.packt.ch03.beans 包。

1.  创建或复制 com.packt.ch03.dao，带有 BookDAO.java 和 BookDAO_JdbcTemplate.java 类。

1.  将 connection_new.xml 复制到类路径中，并删除 id 为'namedTemplate'的 bean。

1.  在 com.packt.ch03.dao 包中创建新的接口 BookDAO_new，如下所示，以声明 getDescription()方法：

```java
      public interface BookDAO_new { 
        String getDescription(long ISBN); 
      }
```

1.  创建实现 BookDAO_new 接口的类 BookDAO_new_Impl，它将使用 JdbcTemplate 处理 JDBC。代码如下所示：

```java
      @Repository 
      public class BookDAO_new_Impl implements BookDAO_new { 
        @Autowired 
        JdbcTemplate jdbcTemplate; 
        @Override 
        public String getDescription(long ISBN) { 
          // TODO Auto-generated method stub 
          String GET_DESCRIPTION=" select description from book where           ISBN=?"; 
          String description=jdbcTemplate.queryForObject(
            GET_DESCRIPTION, new Object[]{ISBN},String.class);
          return description; 
        }
      }
```

1.  在 com.packt.ch04.aspects 包中创建一个方面类 MyIntroductionAspect，它将向使用 getDescription()方法的新接口介绍。代码如下所示：

```java
      @Aspect 
      public class MyIntroductionAspect { 
        @DeclareParents(value="com.packt.ch03.dao.BookDAO+",
        defaultImpl=com.packt.ch03.dao.BookDAO_new_Impl.class)
        BookDAO_new bookDAO_new; 
      }
```

注解提供了 BookDAO_new 的介绍，它比 BookDAO 接口中可用的方法多。要用于介绍的默认实现是 BookDAO-new_Impl。

1.  在 connection_new.xml 中注册方面，如下：

```java
      <bean class="com.packt.ch04.aspects.MyIntroductionAspect"></bean>
```

1.  添加以下配置以启用自动代理，

```java
      <aop:aspectj-autoproxy proxy-target-class="true"/>
```

代理目标类用于强制代理成为我们类的子类。

1.  复制或创建 MainBookDAO_operation.java 以测试代码。使用 getDescription()方法查找代码描述。以下代码中的下划线语句是需要添加的额外语句：

```java
      public class MainBookDAO_operations { 
        public static void main(String[] args) { 
          // TODO Auto-generated method stub 
          ApplicationContext context=new  
            ClassPathXmlApplicationContext("connection_new.xml"); 
          BookDAO bookDAO=(BookDAO)  
            context.getBean("bookDAO_jdbcTemplate"); 
          //add book
          int rows=bookDAO.addBook(new Book("Java EE 7 Developer  
          Handbook", 97815674L,"PacktPub
          publication",332,"explore the Java EE7
          programming","Peter pilgrim"));
          if(rows>0) 
          { 
            System.out.println("book inserted successfully"); 
          } 
          else
            System.out.println("SORRY!cannot add book"); 

          //update the book
          rows=bookDAO.updateBook(97815674L,432); 
          if(rows>0) 
          { 
            System.out.println("book updated successfully"); 
          }else 
          System.out.println("SORRY!cannot update book"); 
          String desc=((BookDAO_new)bookDAO).getDescription(97815674L); 
          System.out.println(desc); 

          //delete the book
          boolean deleted=bookDAO.deleteBook(97815674L); 
          if(deleted) 
          { 
            System.out.println("book deleted successfully"); 
          }else 
          System.out.println("SORRY!cannot delete book"); 
        } 
      } 

```

由于 BookDAO 没有 getDescription()方法，为了使用它，我们需要将获得的对象转换为 BookDAO_new。

1.  执行后，我们将在控制台获得以下输出：

```java
      book inserted successfully 
      book updated successfully 
      explore the Java EE7 programming 
      book deleted successfully 

```

输出清楚地显示，尽管我们没有改变 BookDAO 及其实现，就能引入 getDescription()方法。
