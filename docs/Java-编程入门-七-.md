# Java 编程入门（七）

> 原文：[`zh.annas-archive.org/md5/C2294D9F4E8891D4151421288379909B`](https://zh.annas-archive.org/md5/C2294D9F4E8891D4151421288379909B)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十六章：数据库编程

本章介绍如何编写 Java 代码，可以操作数据库中的数据——插入、读取、更新、删除。它还提供了 SQL 语言和基本数据库操作的简要介绍。

在本章中，我们将涵盖以下主题：

+   什么是**Java 数据库连接**（**JDBC**）？

+   如何创建/删除数据库

+   **结构化查询语言**（**SQL**）简要概述

+   如何创建/删除/修改数据库表

+   **创建、读取、更新和删除**（**CRUD**）数据库数据

+   练习-选择唯一的名字

# 什么是 Java 数据库连接（JDBC）？

**Java 数据库连接**（**JDBC**）是 Java 功能，允许我们访问和修改数据库中的数据。它由 JDBC API（`java.sql`、`javax.sql`和`java.transaction.xa`包）和数据库特定的接口实现（称为数据库驱动程序）支持，每个数据库供应商都提供了与数据库访问的接口。

当人们说他们正在使用 JDBC 时，这意味着他们编写代码，使用 JDBC API 的接口和类以及知道如何将应用程序与特定数据库连接的数据库特定驱动程序来管理数据库中的数据。使用此连接，应用程序可以发出用**结构化查询语言**（**SQL**）编写的请求。当然，我们这里只谈论了理解 SQL 的数据库。它们被称为关系（或表格）数据库，并且占当前使用的数据库的绝大多数，尽管也使用一些替代方案——如导航数据库和 NoSql。

`java.sql`和`javax.sql`包包含在 Java 平台标准版（Java SE）中。从历史上看，`java.sql`包属于 Java 核心，而`javax.sql`包被认为是核心扩展。但后来，`javax.sql`包也被包含在核心中，名称没有更改，以避免破坏使用它的现有应用程序。`javax.sql`包包含支持语句池、分布式事务和行集的`DataSource`接口。我们将在本章的后续部分更详细地讨论这些功能。

与数据库一起工作包括八个步骤：

1.  按照供应商的说明安装数据库。

1.  创建数据库用户、数据库和数据库模式——表、视图、存储过程等。

1.  在应用程序上添加对`.jar`的依赖项，其中包含特定于数据库的驱动程序。

1.  从应用程序连接到数据库。

1.  构造 SQL 语句。

1.  执行 SQL 语句。

1.  使用执行结果。

1.  释放（关闭）在过程中打开的数据库连接和其他资源。

步骤 1-3 只在应用程序运行之前的数据库设置时执行一次。步骤 4-8 根据需要由应用程序重复执行。步骤 5-7 可以重复多次使用相同的数据库连接。

# 连接到数据库

以下是连接到数据库的代码片段：

```java
String URL = "jdbc:postgresql://localhost/javaintro";
Properties prop = new Properties( );
//prop.put( "user", "java" );
//prop.put( "password", "secretPass123" );
try {
  Connection conn = DriverManager.getConnection(URL, prop);
} catch(SQLException ex){
  ex.printStackTrace();
}
```

注释行显示了如何使用`java.util.Properties`类为连接设置用户和密码。上述只是一个示例，说明如何直接使用`DriverManger`类获取连接。传入属性的许多键对于所有主要数据库都是相同的，但其中一些是特定于数据库的。因此，请阅读您的数据库供应商文档以获取此类详细信息。

或者，仅传递用户和密码，我们可以使用重载版本`DriverManager.getConnection（String url，String user，String password）`。

保持密码加密是一个好的做法。我们不会告诉你如何做，但是互联网上有很多指南可用。

另一种连接到数据库的方法是使用`DataSource`接口。它的实现包含在与数据库驱动程序相同的`.jar`中。在 PostgreSQL 的情况下，有两个实现了`DataSource`接口的类：`org.postgresql.ds.PGSimpleDataSource`和`org.postgresql.ds.PGConnectionPoolDataSource`。我们可以使用它们来代替`DriverManager`。以下是使用`org.postgresql.ds.PGSimpleDataSource`类创建数据库连接的示例：

```java
PGSimpleDataSource source = new PGSimpleDataSource();
source.setServerName("localhost");
source.setDatabaseName("javaintro");
source.setLoginTimeout(10);
Connection conn = source.getConnection();
```

要使用`org.postgresql.ds.PGConnectionPoolDataSource`类连接到数据库，我们只需要用以下内容替换前面代码中的第一行：

```java
PGConnectionPoolDataSource source = new PGConnectionPoolDataSource();
```

使用`PGConnectionPoolDataSource`类允许我们在内存中创建一个`Connection`对象池。这是一种首选的方式，因为创建`Connection`对象需要时间。池化允许我们提前完成这个过程，然后根据需要重复使用已经创建的对象。池的大小和其他参数可以在`postgresql.conf`文件中设置。

但无论使用何种方法创建数据库连接，我们都将把它隐藏在`getConnection()`方法中，并在所有的代码示例中以相同的方式使用它。

有了`Connection`类的对象，我们现在可以访问数据库来添加、读取、删除或修改存储的数据。

# 关闭数据库连接

保持数据库连接活动需要大量的资源内存和 CPU-因此关闭连接并释放分配的资源是一个好主意，一旦你不再需要它们。在池化的情况下，`Connection`对象在关闭时会返回到池中，消耗更少的资源。

在 Java 7 之前，关闭连接的方法是通过在`finally`块中调用`close()`方法，无论是否有 catch 块：

```java
Connection conn = getConnection();
try {
  //use object conn here 
} finally {
  if(conn != null){
    conn.close();
  }
}
```

`finally`块中的代码总是会被执行，无论 try 块中的异常是否被抛出。但自 Java 7 以来，`try...with...resources`结构可以很好地处理实现了`java.lang.AutoCloseable`或`java.io.Closeable`接口的任何对象。由于`java.sql.Connection`对象实现了`AutoCloseable`，我们可以将上一个代码片段重写如下：

```java
try (Connection conn = getConnection()) {
  //use object conn here
}
catch(SQLException ex) {
  ex.printStackTrace();
}
```

捕获子句是必要的，因为可自动关闭的资源会抛出`java.sql.SQLException`。有人可能会说，这样做并没有节省多少输入。但是`Connection`类的`close()`方法也可能会抛出`SQLException`，所以带有`finally`块的代码应该更加谨慎地编写：

```java
Connection conn = getConnection();
try {
  //use object conn here 
} finally {
  if(conn != null){
    try {
      conn.close();
    } catch(SQLException ex){
      //do here what has to be done
    }
  }
}
```

前面的代码块看起来确实像是更多的样板代码。更重要的是，如果考虑到通常在`try`块内，一些其他代码也可能抛出`SQLException`，那么前面的代码应该如下所示：

```java
Connection conn = getConnection();
try {
  //use object conn here 
} catch(SQLException ex) {
  ex.printStackTrace();
} finally {
  if(conn != null){
    try {
      conn.close();
    } catch(SQLException ex){
      //do here what has to be done
    }
  }
}
```

样板代码增加了，不是吗？这还不是故事的结束。在接下来的章节中，您将了解到，要发送数据库请求，还需要创建一个`java.sql.Statement`，它会抛出`SQLException`，也必须关闭。然后前面的代码会变得更多：

```java
Connection conn = getConnection();
try {
  Statement statement = conn.createStatement();
  try{
    //use statement here
  } catch(SQLException ex){
    //some code here
  } finally {
    if(statement != null){
      try {
      } catch (SQLException ex){
        //some code here
      }
    } 
  }
} catch(SQLException ex) {
  ex.printStackTrace();
} finally {
  if(conn != null){
    try {
      conn.close();
    } catch(SQLException ex){
      //do here what has to be done
    }
  }
}
```

现在我们可以充分欣赏`try...with...resources`结构的优势，特别是考虑到它允许我们在同一个子句中包含多个可自动关闭的资源：

```java
try (Connection conn = getConnection();
  Statement statement = conn.createStatement()) {
  //use statement here
} catch(SQLException ex) {
  ex.printStackTrace();
}
```

自 Java 9 以来，我们甚至可以使其更简单：

```java
Connection conn = getConnection();
try (conn; Statement statement = conn.createStatement()) {
  //use statement here
} catch(SQLException ex) {
  ex.printStackTrace();
}
```

现在很明显，`try...with...resources`结构是一个无可争议的赢家。

# 结构化查询语言（SQL）

SQL 是一种丰富的语言，我们没有足够的空间来涵盖其所有特性。我们只想列举一些最受欢迎的特性，以便您了解它们的存在，并在需要时查找它们。

与 Java 语句类似，SQL 语句表达了像英语句子一样的数据库请求。每个语句都可以在数据库控制台中执行，也可以通过使用 JDBC 连接在 Java 代码中执行。程序员通常在控制台中测试 SQL 语句，然后再在 Java 代码中使用它，因为在控制台中的反馈速度要快得多。在使用控制台时，无需编译和执行程序。

有 SQL 语句可以创建和删除用户和数据库。我们将在下一节中看到此类语句的示例。还有其他与整个数据库相关的语句，超出了本书的范围。

创建数据库后，以下三个 SQL 语句允许我们构建和更改数据库结构 - 表、函数、约束或其他数据库实体：

+   `CREATE`：此语句创建数据库实体

+   `ALTER`：此语句更改数据库实体

+   `DROP`：此语句删除数据库实体

还有各种 SQL 语句，允许我们查询每个数据库实体的信息，这也超出了本书的范围。

并且有四种 SQL 语句可以操作数据库中的数据：

+   `INSERT`：此语句向数据库添加数据

+   `SELECT`：此语句从数据库中读取数据

+   `UPDATE`：此语句更改数据库中的数据

+   `DELETE`：此语句从数据库中删除数据

可以向前述语句添加一个或多个不同的子句，用于标识请求的数据（`WHERE`-子句）、结果返回的顺序（`ORDER`-子句）等。

JDBC 连接允许将前述 SQL 语句中的一个或多个组合包装在提供数据库端不同功能的三个类中：

+   `java.sql.Statement`：只是将语句发送到数据库服务器以执行

+   `java.sql.PreparedStatement`：在数据库服务器上的某个执行路径中缓存语句，允许以高效的方式多次执行具有不同参数的语句

+   `java.sql.CallableStatement`：在数据库中执行存储过程

我们将从创建和删除数据库及其用户的语句开始我们的演示。

# 创建数据库及其结构

查找如何下载和安装您喜欢的数据库服务器。数据库服务器是一个维护和管理数据库的软件系统。对于我们的演示，我们将使用 PostgreSQL，一个免费的开源数据库服务器。

安装数据库服务器后，我们将使用其控制台来创建数据库及其用户，并赋予相应的权限。有许多方法可以构建数据存储和具有不同访问级别的用户系统。在本书中，我们只介绍基本方法，这使我们能够演示主要的 JDBC 功能。

# 创建和删除数据库及其用户

阅读数据库说明，并首先创建一个`java`用户和一个`javaintro`数据库（或选择任何其他您喜欢的名称，并在提供的代码示例中使用它们）。以下是我们在 PostgreSQL 中的操作方式：

```java
CREATE USER java SUPERUSER;
CREATE DATABASE javaintro OWNER java;
```

如果您犯了一个错误并决定重新开始，您可以使用以下语句删除创建的用户和数据库：

```java
DROP USER java;
DROP DATABASE javaintro;
```

我们为我们的用户选择了`SUPERUSER`角色，但是良好的安全实践建议只将这样一个强大的角色分配给管理员。对于应用程序，建议创建一个用户，该用户不能创建或更改数据库本身——其表和约束——但只能管理数据。此外，创建另一个逻辑层，称为**模式**，该模式可以具有自己的一组用户和权限，也是一个良好的实践。这样，同一数据库中的几个模式可以被隔离，每个用户（其中一个是您的应用程序）只能访问特定的模式。在企业级别上，通常的做法是为数据库模式创建同义词，以便没有应用程序可以直接访问原始结构。

但是，正如我们已经提到的，对于本书的目的，这是不需要的，所以我们把它留给数据库管理员，他们为每个企业的特定工作条件建立规则和指导方针。

现在我们可以将我们的应用程序连接到数据库。

# 创建、修改和删除表

表的标准 SQL 语句如下：

```java
CREATE TABLE tablename (
  column1 type1,
  column2 type2,
  column3 type3,
  ....
);
```

表名、列名和可以使用的值类型的限制取决于特定的数据库。以下是在 PostgreSQL 中创建表 person 的命令示例：

```java
CREATE TABLE person (
  id SERIAL PRIMARY KEY,
  first_name VARCHAR NOT NULL,
  last_name VARCHAR NOT NULL,
  dob DATE NOT NULL
);
```

正如您所看到的，我们已经将`dob`（出生日期）列设置为不可为空。这对我们的`Person` Java 类施加了约束，该类将表示此表的记录：其`dob`字段不能为`null`。这正是我们在第六章中所做的，当时我们创建了我们的`Person`类，如下所示：

```java
class Person {
  private String firstName, lastName;
  private LocalDate dob;
  public Person(String firstName, String lastName, LocalDate dob) {
    this.firstName = firstName == null ? "" : firstName;
    this.lastName = lastName == null ? "" : lastName;
    if(dob == null){
      throw new RuntimeException("Date of birth is null");
    }
    this.dob = dob;
  }
  public String getFirstName() { return firstName; }
  public String getLastName() { return lastName; }
  public LocalDate getDob() { return dob; }
}
```

我们没有设置`VARCHAR`类型的列的大小，因此允许这些列存储任意长度的值，而整数类型允许它们存储从公元前 4713 年到公元 5874897 年的数字。添加了`NOT NULL`，因为默认情况下列将是可空的，而我们希望确保每条记录的所有列都被填充。我们的`Person`类通过将名字和姓氏设置为空的`String`值来支持它，如果它们是`null`，作为`Person`构造函数的参数。

我们还将`id`列标识为`PRIMARY KEY`，这表示该列唯一标识记录。`SERIAL`关键字表示我们要求数据库在添加新记录时生成下一个整数值，因此每条记录将有一个唯一的整数编号。或者，我们可以从`first_name`、`last_name`和`dob`的组合中创建`PRIMARY KEY`：

```java
CREATE TABLE person (
  first_name VARCHAR NOT NULL,
  last_name VARCHAR NOT NULL,
  dob DATE NOT NULL,
  PRIMARY KEY (first_name, last_name, dob)
);
```

但有可能有两个人有相同的名字，并且出生在同一天，所以我们决定不这样做，并添加了`Person`类的另一个字段和构造函数：

```java
public class Person {
  private String firstName, lastName;
  private LocalDate dob;
  private int id;
  public Person(int id, String firstName, 
                                  String lastName, LocalDate dob) {
    this(firstName, lastName, dob);
    this.id = id;
  }   
  public Person(String firstName, String lastName, LocalDate dob) {
    this.firstName = firstName == null ? "" : firstName;
    this.lastName = lastName == null ? "" : lastName;
    if(dob == null){
      throw new RuntimeException("Date of birth is null");
    }
    this.dob = dob;
  }
  public String getFirstName() { return firstName; }
  public String getLastName() { return lastName; }
  public LocalDate getDob() { return dob; }
}
```

我们将使用接受`id`的构造函数来基于数据库中的记录构建对象，而另一个构造函数将用于在插入新记录之前创建对象。

我们在数据库控制台中运行上述 SQL 语句并创建这个表：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/00af477d-66c8-4e49-941b-8a8ddbaf76f0.png)

如果必要，可以通过`DROP`命令删除表：

```java
DROP table person;
```

可以使用`ALTER`命令更改现有表。例如，我们可以添加一个`address`列：

```java
ALTER table person add column address VARCHAR;
```

如果您不确定这样的列是否已经存在，可以添加 IF EXISTS 或 IF NOT EXISTS：

```java
ALTER table person add column IF NOT EXISTS address VARCHAR;
```

但这种可能性只存在于 PostgreSQL 9.6 之后。

数据库表创建的另一个重要考虑因素是是否必须添加索引。索引是一种数据结构，可以加速表中的数据搜索，而无需检查每条表记录。索引可以包括一个或多个表的列。例如，主键的索引会自动生成。如果您已经创建了表的描述，您将看到：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/b447b61b-1d4f-4578-a9be-778d1c6c8ec9.png)

如果我们认为（并通过实验已经证明）它将有助于应用程序的性能，我们也可以自己添加任何索引。例如，我们可以通过添加以下索引来允许不区分大小写的搜索名字和姓氏：

```java
CREATE INDEX idx_names ON person ((lower(first_name), lower(last_name));
```

如果搜索速度提高，我们会保留索引。如果没有，可以删除它：

```java
drop index idx_names;
```

我们删除它，因为索引会增加额外的写入和存储空间开销。

我们也可以从表中删除列：

```java
ALTER table person DROP column address;
```

在我们的示例中，我们遵循了 PostgreSQL 的命名约定。如果您使用不同的数据库，建议您查找其命名约定并遵循，以便您创建的名称与自动创建的名称对齐。

# 创建，读取，更新和删除（CRUD）数据

到目前为止，我们已经使用控制台将 SQL 语句发送到数据库。可以使用 JDBC API 从 Java 代码执行相同的语句，但是表只创建一次，因此没有必要为一次性执行编写程序。

但是管理数据是另一回事。这是我们现在要编写的程序的主要目的。为了做到这一点，首先我们将以下依赖项添加到`pom.xml`文件中，因为我们已经安装了 PostgreSQL 9.6：

```java
<dependency>
  <groupId>org.postgresql</groupId>
  <artifactId>postgresql</artifactId>
  <version>42.2.2</version>
</dependency>
```

# INSERT 语句

在数据库中创建（填充）数据的 SQL 语句具有以下格式：

```java
INSERT INTO table_name (column1,column2,column3,...)
   VALUES (value1,value2,value3,...);
```

当必须添加多个表记录时，它看起来像这样：

```java
INSERT INTO table_name (column1,column2,column3,...)
 VALUES (value1,value2,value3,...), (value11,value21,value31,...), ...;
```

在编写程序之前，让我们测试我们的`INSERT`语句：

！[]（img/c87f8461-b463-4dcb-a806-01b2bac288c7.png）

它没有错误，返回的插入行数为 1，所以我们将创建以下方法：

```java
void executeStatement(String sql){
  Connection conn = getConnection();
  try (conn; Statement st = conn.createStatement()) {
    st.execute(sql);
  } catch (SQLException ex) {
    ex.printStackTrace();
  }
}
```

我们可以执行前面的方法并插入另一行：

```java
executeStatement("insert into person (first_name, last_name, dob)" +
                             " values ('Bill', 'Grey', '1980-01-27')");
```

我们将在下一节中看到此前`INSERT`语句执行的结果以及`SELECT`语句的演示。

与此同时，我们想讨论`java.sql.Statement`接口的最受欢迎的方法：

+   `boolean execute（String sql）`：如果执行的语句返回数据（作为`java.sql.ResultSet`对象），则返回`true`，可以使用`java.sql.Statement`接口的`ResultSet getResultSet（）`方法检索数据。如果执行的语句不返回数据（SQL 语句可能正在更新或插入某些行），则返回`false`，并且随后调用`java.sql.Statement`接口的`int getUpdateCount（）`方法返回受影响的行数。例如，如果我们在`executeStatement（）`方法中添加了打印语句，那么在插入一行后，我们将看到以下结果：

```java
        void executeStatement(String sql){
          Connection conn = getConnection();
          try (conn; Statement st = conn.createStatement()) {
            System.out.println(st.execute(sql));      //prints: false
            System.out.println(st.getResultSet());    //prints: null
            System.out.println(st.getUpdateCount());  //prints: 1
          } catch (SQLException ex) {
            ex.printStackTrace();
          }
        }
```

+   `ResultSet executeQuery（String sql）`：它将数据作为`java.sql.ResultSet`对象返回（预计执行的 SQL 语句是`SELECT`语句）。可以通过随后调用`java.sql.Statement`接口的`ResultSet getResultSet（）`方法检索相同的数据。`java.sql.Statement`接口的`int getUpdateCount（）`方法返回`-1`。例如，如果我们更改我们的`executeStatement（）`方法并使用`executeQuery（）`，则`executeStatement（"select first_name from person"）`的结果将是：

```java
        void executeStatement(String sql){
          Connection conn = getConnection();
          try (conn; Statement st = conn.createStatement()) {
             System.out.println(st.executeQuery(sql)); //prints: ResultSet
             System.out.println(st.getResultSet());    //prints: ResultSet
             System.out.println(st.getUpdateCount());  //prints: -1
          } catch (SQLException ex) {
             ex.printStackTrace();
          }
        }
```

+   `int executeUpdate(String sql)`: 它返回受影响的行数（执行的 SQL 语句预期为`UPDATE`语句）。`java.sql.Statement`接口的`int getUpdateCount()`方法的后续调用返回相同的数字。`java.sql.Statement`接口的`ResultSet getResultSet()`方法的后续调用返回`null`。例如，如果我们更改我们的`executeStatement()`方法并使用`executeUpdate()`，`executeStatement("update person set first_name = 'Jim' where last_name = 'Adams'")`的结果将是：

```java
        void executeStatement4(String sql){
          Connection conn = getConnection();
          try (conn; Statement st = conn.createStatement()) {
            System.out.println(st.executeUpdate(sql));//prints: 1
            System.out.println(st.getResultSet());    //prints: null
            System.out.println(st.getUpdateCount());  //prints: 1
          } catch (SQLException ex) {
            ex.printStackTrace();
          }
        }
```

# SELECT 语句

`SELECT`语句的格式如下：

```java
SELECT column_name, column_name
FROM table_name WHERE some_column = some_value;
```

当需要选择所有列时，格式如下：

```java
SELECT * FROM table_name WHERE some_column=some_value;
```

这是`WHERE`子句的更一般的定义：

```java
WHERE column_name operator value
Operator:
   =   Equal
   <>  Not equal. In some versions of SQL, !=
   >   Greater than
   <   Less than
   >=  Greater than or equal
   <=  Less than or equal
   IN  Specifies multiple possible values for a column
   LIKE  Specifies the search pattern
   BETWEEN  Specifies the inclusive range of vlaues in a column
```

`column_name` operator value 构造可以使用`AND`和`OR`逻辑运算符组合，并用括号`( )`分组。

在前面的语句中，我们执行了一个`select first_name from person`的`SELECT`语句，返回了`person`表中记录的所有名字。现在让我们再次执行它并打印出结果：

```java
Connection conn = getConnection();
try (conn; Statement st = conn.createStatement()) {
  ResultSet rs = st.executeQuery("select first_name from person");
  while (rs.next()){
    System.out.print(rs.getString(1) + " "); //prints: Jim Bill
  }
} catch (SQLException ex) {
  ex.printStackTrace();
}
```

`ResultSet`接口的`getString(int position)`方法从位置`1`（`SELECT`语句中列的第一个）提取`String`值。对于所有原始类型，如`getInt()`和`getByte()`，都有类似的获取器。

还可以通过列名从`ResultSet`对象中提取值。在我们的情况下，它将是`getString("first_name")`。当`SELECT`语句如下时，这是特别有用的：

```java
select * from person;
```

但请记住，通过列名从`ResultSet`对象中提取值效率较低。性能差异非常小，只有在操作发生多次时才变得重要。只有实际的测量和测试才能告诉您这种差异对您的应用程序是否重要。通过列名提取值尤其有吸引力，因为它提供更好的代码可读性，在应用程序维护期间可以得到很好的回报。

`ResultSet`接口中还有许多其他有用的方法。如果您的应用程序从数据库中读取数据，我们强烈建议您阅读`SELECT`语句和`ResultSet`接口的文档。

# UPDATE 语句

数据可以通过`UPDATE`语句更改：

```java
UPDATE table_name SET column1=value1,column2=value2,... WHERE-clause;
```

我们已经使用这样的语句来改变记录中的名字，将原始值`John`改为新值`Jim`：

```java
update person set first_name = 'Jim' where last_name = 'Adams'
```

稍后，使用`SELECT`语句，我们将证明更改是成功的。没有`WHERE`子句，表的所有记录都将受到影响。

# DELETE 语句

数据可以通过`DELETE`语句删除：

```java
DELETE FROM table_name WHERE-clause;
```

没有`WHERE`子句，表的所有记录都将被删除。在`person`表的情况下，我们可以使用`delete from person` SQL 语句删除所有记录。以下语句从`person`表中删除所有名为 Jim 的记录：

```java
delete from person where first_name = 'Jim';
```

# 使用 PreparedStatement 类

`PreparedStatement`对象——`Statement`接口的子接口——旨在被缓存在数据库中，然后用于有效地多次执行 SQL 语句，以适应不同的输入值。与`Statement`对象类似（由`createStatement()`方法创建），它可以由同一`Connection`对象的`prepareStatement()`方法创建。

生成`Statement`对象的相同 SQL 语句也可以用于生成`PreparedStatement`对象。事实上，考虑使用`PreparedStatement`来调用多次的任何 SQL 语句是一个好主意，因为它的性能优于`Statement`。要做到这一点，我们只需要更改前面示例代码中的这两行：

```java
try (conn; Statement st = conn.createStatement()) {
  ResultSet rs = st.executeQuery(sql);
```

或者，我们可以以同样的方式使用`PreparedStatement`类：

```java
try (conn; PreparedStatement st = conn.prepareStatement(sql)) {
  ResultSet rs = st.executeQuery();
```

但是`PreparedStatement`的真正用处在于它能够接受参数-替换（按照它们出现的顺序）`?`符号的输入值。例如，我们可以创建以下方法：

```java
List<Person> selectPersonsByFirstName(String sql, String searchValue){
  List<Person> list = new ArrayList<>();
  Connection conn = getConnection();
  try (conn; PreparedStatement st = conn.prepareStatement(sql)) {
    st.setString(1, searchValue);
    ResultSet rs = st.executeQuery();
    while (rs.next()){
      list.add(new Person(rs.getInt("id"),
               rs.getString("first_name"),
               rs.getString("last_name"),
               rs.getDate("dob").toLocalDate()));
    }
  } catch (SQLException ex) {
    ex.printStackTrace();
  }
  return list;
}
```

我们可以使用前面的方法从`person`表中读取与`WHERE`子句匹配的记录。例如，我们可以找到所有名为`Jim`的记录：

```java
String sql = "select * from person where first_name = ?";
List<Person> list = selectPersonsByFirstName(sql, "Jim");
for(Person person: list){
  System.out.println(person);
}
```

结果将是：

```java
Person{firstName='Jim', lastName='Adams', dob=1999-08-23, id=1}
```

`Person`对象以这种方式打印，因为我们添加了以下`toString()`方法：

```java
@Override
public String toString() {
  return "Person{" +
          "firstName='" + firstName + '\'' +
          ", lastName='" + lastName + '\'' +
          ", dob=" + dob +
          ", id=" + id +
          '}';
}
```

我们可以通过运行以下代码获得相同的结果：

```java
String sql = "select * from person where last_name = ?";
List<Person> list = selectPersonsByFirstName(sql, "Adams");
for(Person person: list){
    System.out.println(person);
}
```

总是使用准备好的语句进行 CRUD 操作并不是一个坏主意。如果只执行一次，它们可能会慢一点，但您可以测试看看这是否是您愿意支付的代价。使用准备好的语句可以获得一致的（更易读的）代码、更多的安全性（准备好的语句不容易受到 SQL 注入攻击的影响）以及少做一个决定-只需在任何地方重用相同的代码。

# 练习-选择唯一的名字

编写一个 SQL 语句，从人员表中选择所有的名字，而不重复。例如，假设人员表中有三条记录，这些记录有这些名字：`Jim`，`Jim`和`Bill`。您编写的 SQL 语句必须返回`Jim`和`Bill`，而不重复两次的`Jim`。

我们没有解释如何做; 您必须阅读 SQL 文档，以找出如何选择唯一的值。

# 答案

使用`distinct`关键字。以下 SQL 语句返回唯一的名字：

```java
select distinct first_name from person;
```

# 摘要

本章介绍了如何编写能够操作数据库中的数据的 Java 代码。它还对 SQL 语言和基本数据库操作进行了简要介绍。读者已经学会了 JDBC 是什么，如何创建和删除数据库和表，以及如何编写一个管理表中数据的程序。

在下一章中，读者将学习函数式编程的概念。我们将概述 JDK 附带的功能接口，解释如何在 lambda 表达式中使用它们，并了解如何在数据流处理中使用 lambda 表达式。


# 第十七章：Lambda 表达式和函数式编程

本章解释了函数式编程的概念。它提供了 JDK 附带的功能接口的概述，解释了如何在 Lambda 表达式中使用它们，以及如何以最简洁的方式编写 Lambda 表达式。

在本章中，我们将介绍以下主题：

+   函数式编程

+   函数式接口

+   Lambda 表达式

+   方法引用

+   练习——使用方法引用创建一个新对象

# 函数式编程

函数式编程允许我们像处理对象一样处理一段代码（一个函数），将其作为参数传递或作为方法的返回值。这个特性存在于许多编程语言中。它不需要我们管理对象状态。这个函数是无状态的。它的结果只取决于输入数据，不管它被调用多少次。这种风格使结果更可预测，这是函数式编程最具吸引力的方面。

没有函数式编程，Java 中将功能作为参数传递的唯一方式是通过编写一个实现接口的类，创建其对象，然后将其作为参数传递。但即使是最简单的样式——使用匿名类——也需要编写太多的样板代码。使用函数式接口和 Lambda 表达式使代码更短、更清晰、更具表现力。

将其添加到 Java 中增加了并行编程的能力，将并行性的责任从客户端代码转移到库中。在此之前，为了处理 Java 集合的元素，客户端代码必须遍历集合并组织处理。在 Java 8 中，添加了新的（默认）方法，接受一个函数（函数式接口的实现）作为参数，然后根据内部处理算法并行或顺序地将其应用于集合的每个元素。因此，组织并行处理是库的责任。

在本章中，我们将定义和解释这些 Java 特性——函数式接口和 Lambda 表达式，并演示它们在代码示例中的适用性。它们将函数作为语言中与对象同等重要的一等公民。

# 什么是函数式接口？

实际上，您在我们的演示代码中已经看到了函数式编程的元素。一个例子是`forEach(Consumer consumer)`方法，适用于每个`Iterable`，其中`Consumer`是一个函数式接口。另一个例子是`removeIf(Predicate predicate)`方法，适用于每个`Collection`对象。传入的`Predicate`对象是一个函数——函数式接口的实现。类似地，`List`接口中的`sort(Comparator comparator)`和`replaceAll(UnaryOperator uo)`方法以及`Map`中的几个`compute()`方法都是函数式编程的例子。

一个函数接口是一个只有一个抽象方法的接口，包括那些从父接口继承的方法。

为了帮助避免运行时错误，在 Java 8 中引入了`@FunctionalInterface`注解，告诉编译器关于意图，因此编译器可以检查被注解接口中是否真正只有一个抽象方法。让我们一起审查下面的与同一继承线的接口：

```java
@FunctionalInterface
interface A {
  void method1();
  default void method2(){}
  static void method3(){}
}

@FunctionalInterface
interface B extends A {
  default void method4(){}
}

@FunctionalInterface
interface C extends B {
  void method1();
}

//@FunctionalInterface  //compilation error
interface D extends C {
  void method5();
}
```

接口`A`是一个函数接口，因为它只有一个抽象方法：`method1()`。接口`B`也是一个函数接口，因为它也只有一个抽象方法 - 从接口`A`继承的同一个`method1()`。接口`C`是一个函数接口，因为它只有一个抽象方法，`method1()`，它覆盖了父接口`A`的抽象`method1()`方法。接口`D`不能是一个函数接口，因为它有两个抽象方法 - 从父接口`A`继承的`method1()`和`method5()`。

当使用`@FunctionalInterface`注解时，它告诉编译器只检查存在一个抽象方法，并警告程序员读取代码时，这个接口只有一个抽象方法是有意的。否则，程序员可能会浪费时间完善接口，最后发现无法完成。

出于同样的原因，自 Java 早期版本以来存在的`Runnable`和`Callable`接口在 Java 8 中被注释为`@FunctionalInterface`。这明确表明了这种区别，并提醒其用户以及可能尝试添加另一个抽象方法的人：

```java
@FunctionalInterface
interface Runnable { 
  void run(); 
} 
@FunctionalInterface
interface Callable<V> { 
  V call() throws Exception; 
}
```

可以看到，创建一个函数接口很容易。但在这之前，考虑使用`java.util.function`包中提供的 43 个函数接口之一。

# 准备好使用的标准函数接口

`java.util.function`包中提供的大多数接口都是以下四个接口的专业化：`Function`，`Consumer`，`Supplier`和`Predicate`。让我们对它们进行审查，然后简要概述其余 39 个标准函数接口。

# Function<T, R>

这个和其他函数接口的标记包括输入数据类型(`T`)和返回数据类型(`R`)的列举。因此，`Function<T, R>`表示该接口的唯一抽象方法接受类型为`T`的参数并产生类型为`R`的结果。您可以通过阅读在线文档找到该抽象方法的名称。在`Function<T, R>`接口的情况下，它的方法是`R apply(T)`。

在学习所有内容后，我们可以使用匿名类创建该接口的实现：

```java
Function<Integer, Double> multiplyByTen = new Function<Integer, Double>(){
  public Double apply(Integer i){
    return i * 10.0;
  }
};
```

由程序员决定`T`（输入参数）将是哪种实际类型，以及`R`（返回值）将是哪种类型。在我们的示例中，我们已经决定输入参数将是`Integer`类型，结果将是`Double`类型。正如你现在可能已经意识到的那样，类型只能是引用类型，并且原始类型的装箱和拆箱会自动执行。

现在我们可以按照需要使用我们新的`Function<Integer, Double> multiplyByTen`函数。我们可以直接使用它，如下所示：

```java
System.out.println(multiplyByTen.apply(1)); //prints: 10.0
```

或者我们可以创建一个接受这个函数作为参数的方法：

```java
void useFunc(Function<Integer, Double> processingFunc, int input){
  System.out.println(processingFunc.apply(input));
}
```

然后我们可以将我们的函数传递给这个方法，并让方法使用它：

```java
useFunc(multiplyByTen, 10);     //prints: 100.00

```

我们还可以创建一个方法，每当我们需要一个函数时就会生成一个函数：

```java
Function<Integer, Double> createMultiplyBy(double num){
  Function<Integer, Double> func = new Function<Integer, Double>(){
    public Double apply(Integer i){
      return i * num;
    }
  };
  return func;
}
```

使用前述方法，我们可以编写以下代码：

```java
Function<Integer, Double> multiplyByFive = createMultiplyBy(5);
System.out.println(multiplyByFive.apply(1)); //prints: 5.0
useFunc(multiplyByFive, 10);                 //prints: 50.0

```

在下一节中，我们将介绍 lambda 表达式，并展示如何使用它们以更少的代码来表示函数接口实现。

# `Consumer<T>`

通过查看`Consumer<T>`接口的定义，你可以猜到这个接口有一个接受`T`类型参数的抽象方法，而且不返回任何东西。从`Consumer<T>`接口的文档中，我们了解到它的抽象方法是`void accept(T)`，这意味着，例如，我们可以这样实现它：

```java
Consumer<Double> printResult = new Consumer<Double>() {
  public void accept(Double d) {
    System.out.println("Result=" + d);
  }
};
printResult.accept(10.0);         //prints: Result=10.0

```

或者我们可以创建一个生成函数的方法：

```java
Consumer<Double> createPrintingFunc(String prefix, String postfix){
  Consumer<Double> func = new Consumer<Double>() {
    public void accept(Double d) {
      System.out.println(prefix + d + postfix);
    }
  };
  return func;
}
```

现在我们可以像下面这样使用它：

```java
Consumer<Double> printResult = createPrintingFunc("Result=", " Great!");
printResult.accept(10.0);    //prints: Result=10.0 Great!

```

我们还可以创建一个新方法，不仅接受一个处理函数作为参数，还接受一个打印函数：

```java
void processAndConsume(int input, 
                       Function<Integer, Double> processingFunc, 
                                          Consumer<Double> consumer){
  consumer.accept(processingFunc.apply(input));
}
```

然后我们可以编写以下代码：

```java
Function<Integer, Double> multiplyByFive = createMultiplyBy(5);
Consumer<Double> printResult = createPrintingFunc("Result=", " Great!");
processAndConsume(10, multiplyByFive, printResult); //Result=50.0 Great! 
```

正如我们之前提到的，在下一节中，我们将介绍 lambda 表达式，并展示如何使用它们以更少的代码来表示函数接口实现。

# `Supplier<T>`

这是一个诡计问题：猜猜`Supplier<T>`接口的抽象方法的输入和输出类型。答案是：它不接受参数，返回`T`类型。正如你现在理解的那样，区别在于接口本身的名称。它应该给你一个提示：消费者只消耗而不返回任何东西，而供应者只提供而不需要任何输入。`Supplier<T>`接口的抽象方法是`T get()`。

与前面的函数类似，我们可以编写生成供应者的方法：

```java
Supplier<Integer> createSuppplier(int num){
  Supplier<Integer> func = new Supplier<Integer>() {
    public Integer get() { return num; }
  };
  return func;
}
```

现在我们可以编写一个只接受函数的方法：

```java
void supplyProcessAndConsume(Supplier<Integer> input, 
                             Function<Integer, Double> process, 
                                      Consumer<Double> consume){
  consume.accept(processFunc.apply(input.get()));
}
```

注意`input`函数的输出类型与`process`函数的输入类型相同，返回类型与`consume`函数消耗的类型相同。这使得以下代码成为可能：

```java
Supplier<Integer> supply7 = createSuppplier(7);
Function<Integer, Double> multiplyByFive = createMultiplyBy(5);
Consumer<Double> printResult = createPrintingFunc("Result=", " Great!");
supplyProcessAndConsume(supply7, multiplyByFive, printResult); 
                                            //prints: Result=35.0 Great!

```

到此为止，我们希望你开始欣赏函数式编程带来的价值。它允许我们传递功能块，可以插入到算法的中间而不需要创建对象。静态方法也不需要创建对象，但它们由于在 JVM 中是唯一的，所以会被所有应用线程共享。与此同时，每个函数都是一个对象，可以在 JVM 中是唯一的（如果赋值给静态变量），或者为每个处理线程创建一个（这通常是情况）。它几乎没有编码开销，并且在 lambda 表达式中使用时可以更少地使用管道 - 这是我们下一节的主题。

到目前为止，我们已经演示了如何将函数插入现有的控制流表达式中。现在我们将描述最后一个缺失的部分 - 一个表示决策构造的函数，也可以作为对象传递。

# Predicate<T>

这是一个表示具有单个方法`boolean test(T)`的布尔值函数的接口。这里是一个创建`Predicate<Integer>`函数的方法示例：

```java
Predicate<Integer> createTestSmallerThan(int num){
  Predicate<Integer> func = new Predicate<Integer>() {
    public boolean test(Integer d) {
      return d < num;
    }
  };
  return func;
}
```

我们可以使用它来为处理方法添加一些逻辑：

```java
void supplyDecideProcessAndConsume(Supplier<Integer> input, 
                                  Predicate<Integer> test, 
                                   Function<Integer, Double> process, 
                                            Consumer<Double> consume){
  int in = input.get();
  if(test.test(in)){
    consume.accept(process.apply(in));
  } else {
    System.out.println("Input " + in + 
                     " does not pass the test and not processed.");
  }
}
```

下面的代码演示了它的使用方法：

```java
Supplier<Integer> input = createSuppplier(7);
Predicate<Integer> test = createTestSmallerThan(5);
Function<Integer, Double> multiplyByFive = createMultiplyBy(5);
Consumer<Double> printResult = createPrintingFunc("Result=", " Great!");
supplyDecideProcessAndConsume(input, test, multiplyByFive, printResult);
             //prints: Input 7 does not pass the test and not processed.
```

例如，让我们将输入设置为 3：

```java
Supplier<Integer> input = createSuppplier(3)
```

前面的代码将导致以下输出：

```java
Result=15.0 Great!
```

# 其他标准的函数式接口

`java.util.function`包中的其他 39 个函数接口是我们刚刚审查的四个接口的变体。这些变体是为了实现以下目的之一或任意组合：

+   通过明确使用整数、双精度或长整型原始类型来避免自动装箱和拆箱，从而获得更好的性能

+   允许两个输入参数

+   更简短的记法

这里只是一些例子：

+   `IntFunction<R>`提供了更简短的记法（不需要输入参数类型的泛型）并且避免了自动装箱，因为它要求参数为`int`原始类型。

+   `BiFunction<T,U,R>`的`R apply(T,U)`方法允许两个输入参数

+   `BinaryOperator<T>`的`T apply(T,T)`方法允许两个`T`类型的输入参数，并返回相同的`T`类型的值

+   `IntBinaryOperator`的`int applAsInt(int,int)`方法接受两个`int`类型的参数，并返回`int`类型的值

如果你打算使用函数接口，我们鼓励你学习`java.util.functional`包中接口的 API。

# 链接标准函数

`java.util.function`包中的大多数函数接口都有默认方法，允许我们构建一个函数链（也称为管道），将一个函数的结果作为另一个函数的输入参数传递，从而组合成一个新的复杂函数。例如：

```java
Function<Double, Long> f1 = d -> Double.valueOf(d / 2.).longValue();
Function<Long, String> f2 = l -> "Result: " + (l + 1);
Function<Double, String> f3 = f1.andThen(f2);
System.out.println(f3.apply(4.));            //prints: 3

```

如您从前面的代码中所见，我们通过使用 `andThen()` 方法将 `f1` 和 `f2` 函数组合成了一个新的 `f3` 函数。这就是我们将要在本节中探讨的方法的思想。首先，我们将函数表示为匿名类，然后在以下部分中，我们介绍了前面示例中使用的 lambda 表达式。

# 链两个 Function<T,R>

我们可以使用 `Function` 接口的 `andThen(Function after)` 默认方法。我们已经创建了 `Function<Integer, Double> createMultiplyBy()` 方法：

```java
Function<Integer, Double> createMultiplyBy(double num){
  Function<Integer, Double> func = new Function<Integer, Double>(){
    public Double apply(Integer i){
      return i * num;
    }
  };
  return func; 
```

我们还可以编写另一个方法，该方法创建具有 `Double` 输入类型的减法函数，以便我们可以将其链接到乘法函数：

```java
private static Function<Double, Long> createSubtractInt(int num){
  Function<Double, Long> func = new Function<Double, Long>(){
    public Long apply(Double dbl){
      return Math.round(dbl - num);
    }
  };
  return func;
}

```

现在我们可以编写以下代码：

```java
Function<Integer, Double> multiplyByFive = createMultiplyBy(5);
System.out.println(multiplyByFive.apply(2));  //prints: 10.0

Function<Double, Long> subtract7 = createSubtractInt(7);
System.out.println(subtract7.apply(11.0));   //prints: 4

long r = multiplyByFive.andThen(subtract7).apply(2);
System.out.println(r);                          //prints: 3

```

如您所见，`multiplyByFive.andThen(subtract7)` 链有效地作为 `Function<Integer, Long> multiplyByFiveAndSubtractSeven`。

`Function` 接口还有另一个默认方法 `Function<V,R> compose(Function<V,T> before)`，它也允许我们链两个函数。必须先执行的函数可以作为 `before` 参数传递到第二个函数的 `compose()` 方法中：

```java
boolean r = subtract7.compose(multiplyByFive).apply(2);
System.out.println(r);                          //prints: 3         

```

# 链两个 Consumer<T>

`Consumer` 接口也有 `andThen(Consumer after)` 方法。我们已经编写了创建打印函数的方法：

```java
Consumer<Double> createPrintingFunc(String prefix, String postfix){
  Consumer<Double> func = new Consumer<Double>() {
    public void accept(Double d) {
      System.out.println(prefix + d + postfix);
    }
  };
  return func;
}
```

现在我们可以创建和链两个打印函数，如下所示：

```java
Consumer<Double> print21By = createPrintingFunc("21 by ", "");
Consumer<Double> equalsBy21 = createPrintingFunc("equals ", " by 21");
print21By.andThen(equalsBy21).accept(2d);  
//prints: 21 by 2.0 
//        equals 2.0 by 21

```

如您在 `Consumer` 链中所见，两个函数按链定义的顺序消耗相同的值。

# 链两个 Predicate<T>

`Supplier` 接口没有默认方法，而 `Predicate` 接口有一个静态方法 `isEqual(Object targetRef)` 和三个默认方法：`and(Predicate other)`、`negate()` 和 `or(Predicate other)`。为了演示 `and(Predicate other)` 和 `or(Predicate other)` 方法的用法，例如，让我们编写创建两个 `Predicate<Double>` 函数的方法。一个函数检查值是否小于输入：

```java
Predicate<Double> testSmallerThan(double limit){
  Predicate<Double> func = new Predicate<Double>() {
    public boolean test(Double num) {
      System.out.println("Test if " + num + " is smaller than " + limit);
      return num < limit;
    }
  };
  return func;
}
```

另一个函数检查值是否大于输入：

```java
Predicate<Double> testBiggerThan(double limit){
  Predicate<Double> func = new Predicate<Double>() {
    public boolean test(Double num) {
      System.out.println("Test if " + num + " is bigger than " + limit);
      return num > limit;
    }
  };
  return func;
}
```

现在我们可以创建两个 `Predicate<Double>` 函数并将它们链在一起：

```java
Predicate<Double> isSmallerThan20 = testSmallerThan(20d);
System.out.println(isSmallerThan20.test(10d));
     //prints: Test if 10.0 is smaller than 20.0
     //        true

Predicate<Double> isBiggerThan18 = testBiggerThan(18d);
System.out.println(isBiggerThan18.test(10d));
    //prints: Test if 10.0 is bigger than 18.0
    //        false

boolean b = isSmallerThan20.and(isBiggerThan18).test(10.);
System.out.println(b);
    //prints: Test if 10.0 is smaller than 20.0
    //        Test if 10.0 is bigger than 18.0
    //        false

b = isSmallerThan20.or(isBiggerThan18).test(10.);
System.out.println(b);
    //prints: Test if 10.0 is smaller than 20.0
    //        true

```

如您所见，`and()` 方法需要执行每个函数，而 `or()` 方法在链中的第一个函数返回 `true` 后就不执行第二个函数。

# identity() 和其他默认方法

`java.util.function` 包的功能接口有其他有用的默认方法。其中一个显著的是 `identity()` 方法，它返回一个始终返回其输入参数的函数：

```java
Function<Integer, Integer> id = Function.identity();
System.out.println(id.apply(4));          //prints: 4

```

`identity()`方法在某些过程需要提供特定函数，但你不希望提供的函数改变任何东西时非常有用。在这种情况下，你可以创建一个具有必要输出类型的身份函数。例如，在我们之前的代码片段中，我们可能决定`multiplyByFive`函数在`multiplyByFive.andThen(subtract7)`链中不改变任何东西：

```java
Function<Double, Double> multiplyByFive = Function.identity();
System.out.println(multiplyByFive.apply(2.));  //prints: 2.0

Function<Double, Long> subtract7 = createSubtractInt(7);
System.out.println(subtract7.apply(11.0));    //prints: 4

long r = multiplyByFive.andThen(subtract7).apply(2.);
System.out.println(r);                       //prints: -5

```

正如你所看到的，`multiplyByFive`函数未对输入参数`2`做任何操作，因此结果（减去`7`后）是`-5`。

其他默认方法大多涉及转换和装箱和拆箱，但也提取两个参数的最小值和最大值。如果你感兴趣，可以查看`java.util.function`包接口的 API，并了解可能性。

# Lambda 表达式

前一节中的例子（使用匿名类实现函数接口）看起来庞大，并且显得冗长。首先，无需重复接口名称，因为我们已经将其声明为对象引用的类型。其次，在只有一个抽象方法的功能接口的情况下，不需要指定需要实现的方法名称。编译器和 Java 运行时可以自行处理。我们所需做的就是提供新的功能。Lambda 表达式就是为了这个目的而引入的。

# 什么是 Lambda 表达式？

术语 lambda 来自于 lambda 演算——一种通用的计算模型，可用于模拟任何图灵机。它是数学家阿隆佐·丘奇在 20 世纪 30 年代引入的。Lambda 表达式是一个函数，在 Java 中实现为匿名方法，还允许我们省略修饰符、返回类型和参数类型。这使得它具有非常简洁的表示。

Lambda 表达式的语法包括参数列表、箭头符号`->`和主体部分。参数列表可以是空的`()`，没有括号（如果只有一个参数），或者用括号括起来的逗号分隔的参数列表。主体部分可以是单个表达式或语句块。

让我们看几个例子：

+   `() -> 42;` 总是返回`42`

+   `x -> x + 1;` 将变量`x`增加`1`

+   `(x, y) -> x * y;` 将`x`乘以`y`并返回结果

+   `(char x) -> x == '$';` 比较变量`x`和符号`$`的值，并返回布尔值

+   `x -> {  System.out.println("x=" + x); };` 打印带有`x=`前缀的`x`值

# 重新实现函数

我们可以使用 lambda 表达式重新编写前一节中创建的函数，如下所示：

```java
Function<Integer, Double> createMultiplyBy(double num){
  Function<Integer, Double> func = i -> i * num;
  return func;
}
Consumer<Double> createPrintingFunc(String prefix, String postfix){
  Consumer<Double> func = d -> System.out.println(prefix + d + postfix);
  return func;
}
Supplier<Integer> createSuppplier(int num){
  Supplier<Integer> func = () -> num;
  return func;
}
Predicate<Integer> createTestSmallerThan(int num){
  Predicate<Integer> func = d -> d < num;
  return func;
}
```

我们不重复实现接口的名称，因为它在方法签名中指定为返回类型。我们也不指定抽象方法的名称，因为它是唯一必须实现的接口方法。编写这样简洁高效的代码变得可能是因为 lambda 表达式和函数接口的组合。

通过前面的例子，你可能意识到不再需要创建函数的方法了。让我们修改调用`supplyDecideProcessAndConsume()`方法的代码：

```java
void supplyDecideProcessAndConsume(Supplier<Integer> input, 
                                   Predicate<Integer> test, 
                                   Function<Integer, Double> process, 
                                            Consumer<Double> consume){
  int in = input.get();
  if(test.test(in)){
    consume.accept(process.apply(in));
  } else {
    System.out.println("Input " + in + 
                 " does not pass the test and not processed.");
  }
}
```

让我们重新审视以下内容：

```java
Supplier<Integer> input = createSuppplier(7);
Predicate<Integer> test = createTestSmallerThan(5);
Function<Integer, Double> multiplyByFive = createMultiplyBy(5);
Consumer<Double> printResult = createPrintingFunc("Result=", " Great!");
supplyDecideProcessAndConsume(input, test, multiplyByFive, printResult);
```

我们可以将前面的代码更改为以下内容而不改变功能：

```java
Supplier<Integer> input = () -> 7;
Predicate<Integer> test = d -> d < 5.;
Function<Integer, Double> multiplyByFive = i -> i * 5.;;
Consumer<Double> printResult = 
                     d -> System.out.println("Result=" + d + " Great!");
supplyDecideProcessAndConsume(input, test, multiplyByFive, printResult); 

```

我们甚至可以内联前面的函数，并像这样一行写出前面的代码：

```java
supplyDecideProcessAndConsume(() -> 7, d -> d < 5, i -> i * 5., 
                    d -> System.out.println("Result=" + d + " Great!")); 

```

注意定义打印函数的透明度提高了多少。这就是 lambda 表达式与函数接口结合的力量和美丽所在。在第十八章，*流和管道*，你将看到 lambda 表达式实际上是处理流数据的唯一方法。

# Lambda 的限制

有两个我们想指出和澄清的 lambda 表达式方面，它们是：

+   如果 lambda 表达式使用在其外部创建的局部变量，则此局部变量必须是 final 或有效 final（在同一上下文中不可重新赋值）

+   lambda 表达式中的 `this` 关键字引用的是封闭上下文，而不是 lambda 表达式本身

# 有效 final 局部变量

与匿名类一样，创建在 lambda 表达式外部并在内部使用的变量将变为有效 final，并且不能被修改。你可以编写以下内容：

```java
int x = 7;
//x = 3;       //compilation error
int y = 5;
double z = 5.;
supplyDecideProcessAndConsume(() -> x, d -> d < y, i -> i * z,
            d -> { //x = 3;      //compilation error
                   System.out.println("Result=" + d + " Great!"); } );

```

但是，正如你所看到的，我们不能改变 lambda 表达式中使用的局部变量的值。这种限制的原因在于函数可以被传递并在不同的上下文中执行（例如，不同的线程），尝试同步这些上下文会破坏状态无关函数和表达式的独立分布式评估的原始想法。这就是为什么 lambda 表达式中使用的所有局部变量都是有效 final 的原因，这意味着它们可以明确声明为 final，也可以通过它们在 lambda 表达式中的使用变为 final。

这个限制有一个可能的解决方法。如果局部变量是引用类型（但不是 `String` 或原始包装类型），即使该局部变量用于 lambda 表达式中，也可以更改其状态：

```java
class A {
  private int x;
  public int getX(){ return this.x; }
  public void setX(int x){ this.x = x; }
}
void localVariable2(){
  A a = new A();
  a.setX(7);
  a.setX(3);
  int y = 5;
  double z = 5.;
  supplyDecideProcessAndConsume(() -> a.getX(), d -> d < y, i -> i * z,
               d -> { a.setX(5);
    System.out.println("Result=" + d + " Great!"); } );
}
```

但是，只有在真正需要的情况下才应该使用这种解决方法，并且必须谨慎进行，因为存在意外副作用的危险。

# 关于 this 关键字的解释

匿名类和 lambda 表达式之间的一个主要区别是对`this`关键字的解释。在匿名类内部，它引用匿名类的实例。在 lambda 表达式内部，`this`引用包围表达式的类实例，也称为*包围实例*、*包围上下文*或*包围范围*。

让我们编写一个演示区别的`ThisDemo`类：

```java
class ThisDemo {
  private String field = "ThisDemo.field";
  public void useAnonymousClass() {
    Consumer<String> consumer = new Consumer<>() {
      private String field = "AnonymousClassConsumer.field";
      public void accept(String s) {
        System.out.println(this.field);
      }
    };
    consumer.accept(this.field);
  }
  public void useLambdaExpression() {
    Consumer<String> consumer = consumer = s -> {
      System.out.println(this.field);
    };
    consumer.accept(this.field);
  }

}
```

正如您所看到的，匿名类中的`this`指的是匿名类实例，而 lambda 表达式中的`this`指的是包围表达式的类实例。Lambda 表达式确实没有字段，也不能有字段。 如果执行前面的方法，输出将确认我们的假设：

```java
ThisDemo d = new ThisDemo();
d.useAnonymousClass();   //prints: AnonymousClassConsumer.field
d.useLambdaExpression(); //prints: ThisDemo.field

```

Lambda 表达式不是类的实例，不能通过`this`引用。根据 Java 规范，这种方法*通过将[this]与所在上下文中的相同方式来处理，* *允许更多实现的灵活性*。

# 方法引用

让我们再看一下我们对`supplyDecidePprocessAndConsume()`方法的最后一个实现：

```java
supplyDecideProcessAndConsume(() -> 7, d -> d < 5, i -> i * 5., 
                    d -> System.out.println("Result=" + d + " Great!")); 
```

我们使用的功能相当琐碎。在现实代码中，每个都可能需要多行实现。在这种情况下，将代码块内联会使代码几乎不可读。在这种情况下，引用具有必要实现的方法是有帮助的。让我们假设我们有以下的`Helper`类：

```java
public class Helper {
  public double calculateResult(int i){
    // Maybe many lines of code here
    return i* 5;
  }
  public static void printResult(double d){
    // Maybe many lines of code here
    System.out.println("Result=" + d + " Great!");
  }
}
```

`Lambdas`类中的 lambda 表达式可以引用`Helper`和`Lambdas`类的方法，如下所示：

```java
public class Lambdas {
  public void methodReference() {
    Supplier<Integer> input = () -> generateInput();
    Predicate<Integer> test = d -> checkValue(d);
    Function<Integer, Double> multiplyByFive = 
                                  i -> new Helper().calculateResult(i);
    Consumer<Double> printResult = d -> Helper.printResult(d);
    supplyDecideProcessAndConsume(input, test, 
                                           multiplyByFive, printResult);
  }
  private int generateInput(){
    // Maybe many lines of code here
    return 7;
  }
  private static boolean checkValue(double d){
    // Maybe many lines of code here
    return d < 5;
  }
}
```

前面的代码已经更易读了，函数还可以再次内联：

```java
supplyDecideProcessAndConsume(() -> generateInput(), d -> checkValue(d), 
            i -> new Helper().calculateResult(i), Helper.printResult(d));
```

但在这种情况下，表示法可以做得更紧凑。当一个单行 lambda 表达式由对现有方法的引用组成时，可以通过使用不列出参数的方法引用进一步简化表示法。

方法引用的语法为`Location::methodName`，其中`Location`表示`methodName`方法所在的位置（对象或类），两个冒号(`::`)用作位置和方法名之间的分隔符。如果在指定位置有多个同名方法（因为方法重载的原因），则通过 lambda 表达式实现的函数接口抽象方法的签名来标识引用方法。

使用方法引用，`Lambdas`类中`methodReference()`方法下的前面代码可以重写为：

```java
Supplier<Integer> input = this::generateInput;
Predicate<Integer> test = Lambdas::checkValue;
Function<Integer, Double> multiplyByFive = new Helper()::calculateResult;;
Consumer<Double> printResult = Helper::printResult;
supplyDecideProcessAndConsume(input, test, multiplyByFive, printResult);

```

内联这样的函数更有意义：

```java
supplyDecideProcessAndConsume(this::generateInput, Lambdas::checkValue, 
                    new Helper()::calculateResult, Helper::printResult);

```

您可能已经注意到，我们有意地使用了不同的位置和两个实例方法以及两个静态方法，以展示各种可能性。

如果觉得记忆负担过重，好消息是现代 IDE（例如 IntelliJ IDEA）可以为您执行此操作，并将您正在编写的代码转换为最紧凑的形式。

# 练习 - 使用方法引用创建一个新对象

使用方法引用来表示创建一个新对象。假设我们有`class A{}`。用方法引用替换以下的`Supplier`函数声明，以另一个使用方法引用的声明替代：

```java
Supplier<A> supplier = () -> new A();

```

# 答案

答案如下：

```java
Supplier<A> supplier = A::new;

```

# 摘要

本章介绍了函数式编程的概念。它提供了 JDK 提供的函数式接口的概述，并演示了如何使用它们。它还讨论并演示了 lambda 表达式，以及它们如何有效地提高代码可读性。

下一章将使读者熟悉强大的数据流处理概念。它解释了什么是流，如何创建它们和处理它们的元素，以及如何构建处理流水线。它还展示了如何轻松地将流处理组织成并行处理。


# 第十八章：流和管道

在前一章描述和演示的 lambda 表达式以及功能接口中，为 Java 增加了强大的函数式编程能力。它允许将行为（函数）作为参数传递给针对数据处理性能进行优化的库。这样，应用程序员可以专注于开发系统的业务方面，将性能方面留给专家：库的作者。这样的一个库的例子是`java.util.stream`包，它将成为本章的重点。

我们将介绍数据流处理的概念，并解释流是什么，如何处理它们以及如何构建处理管道。我们还将展示如何轻松地组织并行流处理。

在本章中，将涵盖以下主题：

+   什么是流？

+   创建流

+   中间操作

+   终端操作

+   流管道

+   并行处理

+   练习 - 将所有流元素相乘

# 什么是流？

理解流的最好方法是将其与集合进行比较。后者是存储在内存中的数据结构。在将元素添加到集合之前，会计算每个集合元素。相反，流发出的元素存在于其他地方（源）并且根据需要进行计算。因此，集合可以是流的源。

在 Java 中，流是`java.util.stream`包的`Stream`、`IntStream`、`LongStream`或`DoubleStream`接口的对象。`Stream`接口中的所有方法也可以在`IntStream`、`LongStream`或`DoubleStream`专门的*数值*流接口中使用（相应类型更改）。一些数值流接口有一些额外的方法，例如`average()`和`sum()`，专门用于数值。

在本章中，我们将主要讨论`Stream`接口及其方法。但是，所介绍的一切同样适用于数值流接口。在本章末尾，我们还将回顾一些在数值流接口中可用但在`Stream`接口中不可用的方法。

流代表一些数据源 - 例如集合、数组或文件 - 并且按顺序生成（产生、发出）一些值（与流相同类型的流元素），一旦先前发出的元素被处理。

`java.util.stream`包允许以声明方式呈现可以应用于发出元素的过程（函数），也可以并行进行。如今，随着机器学习对大规模数据处理的要求以及对操作的微调变得普遍，这一特性加强了 Java 在少数现代编程语言中的地位。

# 流操作

`Stream`接口的许多方法（具有函数接口类型作为参数的方法）被称为操作，因为它们不是作为传统方法实现的。它们的功能作为函数传递到方法中。方法本身只是调用分配为方法参数类型的函数接口的方法的外壳。

例如，让我们看一下`Stream<T> filter (Predicate<T> predicate)`方法。它的实现基于对`Predicate<T>`函数的`boolean test(T)`方法的调用。因此，程序员更喜欢说，“我们应用`filter`操作，允许一些流元素通过，跳过其他元素”，而不是说“我们使用`Stream`对象的`filter()`方法来选择一些流元素并跳过其他元素”。这听起来类似于说“我们应用加法操作”。它描述了动作（操作）的性质，而不是特定的算法，直到方法接收到特定函数为止。

因此，`Stream`接口中有三组方法：

+   创建`Stream`对象的静态工厂方法。

+   中间操作是返回`Stream`对象的实例方法。

+   终端操作是返回`Stream`之外的某种类型的实例方法。

流处理通常以流畅（点连接）的方式组织（参见*流管道*部分）。`Stream`工厂方法或另一个流源开始这样的管道，终端操作产生管道结果或副作用，并结束管道（因此得名）。中间操作可以放置在原始`Stream`对象和终端操作之间。它处理流元素（或在某些情况下不处理），并返回修改的（或未修改的）`Stream`对象，以便应用下一个中间或终端操作。

中间操作的示例如下：

+   `filter()`: 这将选择与条件匹配的元素。

+   `map()`: 这将根据函数转换元素。

+   `distinct()`: 这将删除重复项。

+   `limit()`: 这将限制流的元素数量。

+   `sorted()`: 这将把未排序的流转换为排序的流。

还有一些其他方法，我们将在*中间操作*部分讨论。

流元素的处理实际上只有在开始执行终端操作时才开始。然后，所有中间操作（如果存在）开始处理。流在终端操作完成执行后关闭（并且无法重新打开）。终端操作的示例包括`forEach()`、`findFirst()`、`reduce()`、`collect()`、`sum()`、`max()`和`Stream`接口的其他不返回`Stream`的方法。我们将在*终端操作*部分讨论它们。

所有的 Stream 方法都支持并行处理，这在多核计算机上处理大量数据时特别有帮助。必须确保处理管道不使用可以在不同处理环境中变化的上下文状态。我们将在*并行处理*部分讨论这一点。

# 创建流

有许多创建流的方法——`Stream`类型的对象或任何数字接口。我们已经按照创建 Stream 对象的方法所属的类和接口对它们进行了分组。我们之所以这样做是为了方便读者，提供更好的概览，这样读者在需要时更容易找到它们。

# 流接口

这组`Stream`工厂由属于`Stream`接口的静态方法组成。

# empty(), of(T t), ofNullable(T t)

以下三种方法创建空的或单个元素的`Stream`对象：

+   `Stream<T> empty()`: 创建一个空的顺序`Stream`对象。

+   `Stream<T> of(T t)`: 创建一个顺序的单个元素`Stream`对象。

+   `Stream<T> ofNullable(T t)`: 如果`t`参数非空，则创建一个包含单个元素的顺序`Stream`对象；否则，创建一个空的 Stream。

以下代码演示了前面方法的用法：

```java
Stream.empty().forEach(System.out::println);    //prints nothing
Stream.of(1).forEach(System.out::println);      //prints: 1

List<String> list = List.of("1 ", "2");
//printList1(null);                             //NullPointerException
printList1(list);                               //prints: 1 2

void printList1(List<String> list){
    list.stream().forEach(System.out::print);;
}
```

注意，当列表不为空时，第一次调用`printList1()`方法会生成`NullPointerException`并打印`1 2`。为了避免异常，我们可以将`printList1()`方法实现如下：

```java
void printList1(List<String> list){
     (list == null ? Stream.empty() : list.stream())
                                         .forEach(System.out::print);
}
```

相反，我们使用了`ofNullable(T t)`方法，如下面的`printList2()`方法的实现所示：

```java
printList2(null);                                //prints nothing
printList2(list);                                //prints: [1 , 2]

void printList2(List<String> list){
      Stream.ofNullable(list).forEach(System.out::print);
}
```

这就是激发`ofNullable(T t)`方法创建的用例。但是您可能已经注意到，`ofNullable()`创建的流将列表作为一个对象发出：它被打印为`[1 , 2]`。

在这种情况下处理列表的每个元素，我们需要添加一个中间的`Stream`操作`flatMap()`，将每个元素转换为`Stream`对象：

```java
Stream.ofNullable(list).flatMap(e -> e.stream())
                       .forEach(System.out::print);      //prints: 1 2

```

我们将在*Intermediate operations*部分进一步讨论`flatMap()`方法。

在前面的代码中传递给`flatMap()`操作的函数也可以表示为方法引用：

```java
Stream.ofNullable(list).flatMap(Collection::stream)
                       .forEach(System.out::print);      //prints: 1 2
```

# iterate(Object, UnaryOperator)

`Stream`接口的两个静态方法允许我们使用类似传统`for`循环的迭代过程生成值流：

+   `Stream<T> iterate(T seed, UnaryOperator<T> func)`: 根据第一个`seed`参数的迭代应用第二个参数（`func`函数）创建一个**无限**顺序`Stream`对象，生成`seed`、`f(seed)`和`f(f(seed))`值的流。

+   `Stream<T> iterate(T seed, Predicate<T> hasNext, UnaryOperator<T> next)`: 根据第三个参数（`next`函数）对第一个`seed`参数的迭代应用，生成`seed`、`f(seed)`和`f(f(seed))`值的有限顺序`Stream`对象，只要第三个参数（`hasNext`函数）返回`true`。

以下代码演示了这些方法的用法：

```java
Stream.iterate(1, i -> ++i).limit(9)
        .forEach(System.out::print);        //prints: 123456789

Stream.iterate(1, i -> i < 10, i -> ++i)
        .forEach(System.out::print);        //prints: 123456789

```

请注意，我们被迫在第一个管道中添加一个`limit()`中间操作，以避免生成无限数量的值。

# concat(Stream a, Stream b)

`Stream<T>` concatenate (`Stream<> a`, `Stream<T> b`) `Stream` 接口的静态方法基于传递的两个`Stream`对象`a`和`b`创建一个值流。新创建的流由第一个参数`a`的所有元素组成，后跟第二个参数`b`的所有元素。以下代码演示了`Stream`对象创建的这种方法：

```java
Stream<Integer> stream1 = List.of(1, 2).stream();
Stream<Integer> stream2 = List.of(2, 3).stream();

Stream.concat(stream1, stream2)
        .forEach(System.out::print);        //prints: 1223
```

请注意，原始流中存在`2`元素，并且因此在生成的流中出现两次。

# generate(Supplier)

`Stream<T> generate(Supplier<T> supplier)` `Stream` 接口的静态方法创建一个无限流，其中每个元素由提供的`Supplier<T>`函数生成。以下是两个示例：

```java
Stream.generate(() -> 1).limit(5)
        .forEach(System.out::print);       //prints: 11111

Stream.generate(() -> new Random().nextDouble()).limit(5)
        .forEach(System.out::println);     //prints: 0.38575117472619247
                                           //        0.5055765386778835
                                           //        0.6528038976983277
                                           //        0.4422354489467244
                                           //        0.06770955839148762
```

由于流是无限的，我们已经添加了`limit()`操作。

# of(T... values)

`Stream<T> of(T... values)` 方法接受可变参数或值数组，并使用提供的值作为流元素创建`Stream`对象：

```java
    Stream.of("1 ", 2).forEach(System.out::print);      //prints: 1 2
    //Stream<String> stringStream = Stream.of("1 ", 2); //compile error

    String[] strings = {"1 ", "2"};
    Stream.of(strings).forEach(System.out::print);      //prints: 1 2

```

请注意，在上述代码的第一行中，如果在`Stream`引用声明的泛型中没有指定类型，则`Stream`对象将接受不同类型的元素。在下一行中，泛型将`Stream`对象的类型定义为`String`，相同的元素类型混合会生成编译错误。泛型绝对有助于程序员避免许多错误，并且应该在可能的地方使用。

`of(T... values)`方法也可用于连接多个流。例如，假设我们有以下四个流，并且我们想要将它们连接成一个：

```java
Stream<Integer> stream1 = Stream.of(1, 2);
Stream<Integer> stream2 = Stream.of(2, 3);
Stream<Integer> stream3 = Stream.of(3, 4);
Stream<Integer> stream4 = Stream.of(4, 5);

```

我们期望新流发出值`1`、`2`、`2`、`3`、`3`、`4`、`4`和`5`。首先，我们尝试以下代码：

```java
Stream.of(stream1, stream2, stream3, stream4)
     .forEach(System.out::print); 
           //prints: java.util.stream.ReferencePipeline$Head@58ceff1j
```

上述代码并没有达到我们的期望。它将每个流都视为`java.util.stream.ReferencePipeline`内部类的对象，该内部类用于`Stream`接口实现。因此，我们添加了一个`flatMap()`操作，将每个流元素转换为流（我们将在*中间操作*部分中描述它）：

```java
Stream.of(stream1, stream2, stream3, stream4)
     .flatMap(e -> e).forEach(System.out::print);   //prints: 12233445
```java

我们将作为参数传递给`flatMap()`的函数（`e -> e`）可能看起来好像什么都没做，但这是因为流的每个元素已经是一个流，所以我们不需要对其进行转换。通过将元素作为`flatMap()`操作的结果返回，我们已经告诉管道将其视为`Stream`对象。已经完成了这一点，并且显示了预期的结果。

# Stream.Builder 接口

`Stream.Builder<T> builder()`静态方法返回一个内部（位于`Stream`接口中的）`Builder`接口，可用于构造`Stream`对象。`Builder`接口扩展了`Consumer`接口，并具有以下方法：

+   `void accept(T t)`: 将元素添加到流中（此方法来自`Consumer`接口）。

+   `default Stream.Builder<T> add(T t)`: 调用`accept(T)`方法并返回`this`，从而允许以流畅的点连接样式链接`add(T)`方法。

+   `Stream<T> build()`: 将此构建器从构造状态转换为构建状态。调用此方法后，无法向流中添加新元素。

使用`add()`方法很简单：

```java
Stream.<String>builder().add("cat").add(" dog").add(" bear")
        .build().forEach(System.out::print);  //prints: cat dog bear
```

只需注意我们在`builder()`方法前面添加的`<String>`泛型。这样，我们告诉构建器我们正在创建的流将具有`String`类型的元素。否则，它将将它们添加为`Object`类型。

当构建器作为`Consumer`对象传递时，或者不需要链接添加元素的方法时，使用`accept()`方法。例如，以下是构建器作为`Consumer`对象传递的方式：

```java
Stream.Builder<String> builder = Stream.builder();
List.of("1", "2", "3").stream().forEach(builder);
builder.build().forEach(System.out::print);        //prints: 123

```

还有一些情况不需要在添加流元素时链接方法。以下方法接收`String`对象的列表，并将其中一些对象（包含字符`a`的对象）添加到流中：

```java
Stream<String> buildStream(List<String> values){
    Stream.Builder<String> builder = Stream.builder();
    for(String s: values){
        if(s.contains("a")){
            builder.accept(s);
        }
    }
    return builder.build();
}
```

请注意，出于同样的原因，我们为`Stream.Builder`接口添加了`<String>`泛型，告诉构建器我们添加的元素应该被视为`String`类型。

当调用前面的方法时，它会产生预期的结果：

```java
List<String> list = List.of("cat", " dog", " bear");
buildStream(list).forEach(System.out::print);        //prints: cat bear
```

# 其他类和接口

在 Java 8 中，`java.util.Collection`接口添加了两个默认方法：

+   `Stream<E> stream()`: 返回此集合的元素流。

+   `Stream<E> parallelStream()`: 返回（可能）此集合元素的并行流。这里的可能是因为 JVM 会尝试将流分成几个块并并行处理它们（如果有几个 CPU）或虚拟并行处理（使用 CPU 的时间共享）。这并非总是可能的；这在一定程度上取决于所请求处理的性质。

这意味着扩展此接口的所有集合接口，包括`Set`和`List`，都有这些方法。这是一个例子：

```java
List<Integer> list = List.of(1, 2, 3, 4, 5);
list.stream().forEach(System.out::print);    //prints: 12345

```

我们将在*并行处理*部分进一步讨论并行流。

`java.util.Arrays`类还添加了八个静态重载的`stream()`方法。它们从相应的数组或其子集创建不同类型的流：

+   `Stream<T> stream(T[] array)`: 从提供的数组创建`Stream`。

+   `IntStream stream(int[] array)`: 从提供的数组创建`IntStream`。

+   `LongStream stream(long[] array)`: 从提供的数组创建`LongStream`。

+   `DoubleStream stream(double[] array)`: 从提供的数组创建`DoubleStream`。

+   `Stream<T> stream(T[] array, int startInclusive, int endExclusive)`: 从提供的数组的指定范围创建`Stream`。

+   `IntStream stream(int[] array, int startInclusive, int endExclusive)`: 从提供的数组的指定范围创建`IntStream`。

+   `LongStream stream(long[] array, int startInclusive, int endExclusive)`: 从提供的数组的指定范围创建`LongStream`。

+   `DoubleStream stream(double[] array, int startInclusive, int endExclusive)`: 从提供的数组的指定范围创建`DoubleStream`。

这是一个从数组的子集创建流的示例：

```java
int[] arr = {1, 2, 3, 4, 5};
Arrays.stream(arr, 2, 4).forEach(System.out::print);    //prints: 34

```

请注意，我们使用了`Stream<T> stream(T[] array, int startInclusive, int endExclusive)`方法，这意味着我们创建了`Stream`而不是`IntStream`，尽管创建的流中的所有元素都是整数，就像`IntStream`一样。不同之处在于，`IntStream`提供了一些数字特定的操作，而`Stream`中没有（请参阅*数字流接口*部分）。

`java.util.Random`类允许我们创建伪随机值的数字流：

+   `IntStream ints()` 和 `LongStream longs()`: 创建相应类型的无限伪随机值流。

+   `DoubleStream doubles()`: 创建一个无限流的伪随机双精度值，每个值都介于零（包括）和一（不包括）之间。

+   `IntStream ints(long streamSize)` 和 `LongStream longs(long streamSize)`: 创建指定数量的相应类型的伪随机值流。

+   `DoubleStream doubles(long streamSize)`: 创建指定数量的伪随机双精度值流，每个值都介于零（包括）和一（不包括）之间。

+   `IntStream ints(int randomNumberOrigin, int randomNumberBound)`, `LongStream longs(long randomNumberOrigin, long randomNumberBound)`, 和 `DoubleStream doubles(long streamSize, double randomNumberOrigin, double randomNumberBound)`: 创建一个无限流，包含对应类型的伪随机值，每个值大于或等于第一个参数，小于第二个参数。

以下是前述方法的示例之一：

```java
new Random().ints(5, 8)
            .limit(5)
            .forEach(System.out::print);    //prints: 56757
```

`java.nio.File`类有六个静态方法，用于创建行和路径流：

+   `Stream<String> lines(Path path)`: 从提供的路径指定的文件创建一行流。

+   `Stream<String> lines(Path path, Charset cs)`: 从提供的路径指定的文件创建一行流。使用提供的字符集将文件的字节解码为字符。

+   `Stream<Path> list(Path dir)`: 创建指定目录中的条目流。

+   `Stream<Path> walk(Path start, FileVisitOption... options)`: 创建以给定起始文件为根的文件树条目流。

+   `Stream<Path> walk(Path start, int maxDepth, FileVisitOption... options)`: 创建以给定起始文件为根的文件树条目流，到指定深度。

+   `Stream<Path> find(Path start, int maxDepth, BiPredicate<Path, BasicFileAttributes> matcher, FileVisitOption... options)`: 创建以给定起始文件为根的文件树条目流，到指定深度匹配提供的谓词。

其他创建流的类和方法包括：

+   `IntStream stream()` of the `java.util.BitSet` class: 创建一个索引流，其中`BitSet`包含设置状态的位。

+   `Stream<String> lines()` of the `java.io.BufferedReader` class: 创建从`BufferedReader`对象读取的行流，通常来自文件。

+   `Stream<JarEntry> stream()` of the `java.util.jar.JarFile` class: 创建 ZIP 文件条目的流。

+   `IntStream chars()` of the `java.lang.CharSequence` interface: 从此序列创建`int`类型的流，零扩展`char`值。

+   `IntStream codePoints()` of the `java.lang.CharSequence` interface: 从此序列创建代码点值的流。

+   `Stream<String> splitAsStream(CharSequence input)` of the `java.util.regex.Pattern` class: 创建一个围绕此模式匹配的提供序列的流。

还有`java.util.stream.StreamSupport`类，其中包含库开发人员的静态低级实用方法。这超出了本书的范围。

# 中间操作

我们已经看到了如何创建代表源并发出元素的`Stream`对象。正如我们已经提到的，`Stream`接口提供的操作（方法）可以分为三组：

+   基于源创建`Stream`对象的方法。

+   接受函数并生成发出相同或修改的值的`Stream`对象的中间操作。

+   终端操作完成流处理，关闭它并生成结果。

在本节中，我们将回顾中间操作，这些操作可以根据其功能进行分组。

# 过滤

此组包括删除重复项、跳过一些元素和限制处理元素数量的操作，仅选择所需的元素：

+   `Stream<T> distinct()`: 使用`Object.equals(Object)`方法比较流元素，并跳过重复项。

+   `Stream<T> skip(long n)`: 忽略前面提供的数量的流元素。

+   `Stream<T> limit(long maxSize)`: 仅允许处理提供的流元素数量。

+   `Stream<T> filter(Predicate<T> predicate)`: 仅允许通过提供的`Predicate`函数处理的结果为`true`的元素。

+   默认`Stream<T> dropWhile(Predicate<T> predicate)`: 跳过流的第一个元素，该元素在通过提供的`Predicate`函数处理时结果为`true`。

+   默认`Stream<T> takeWhile(Predicate<T> predicate)`: 仅允许流的第一个元素在通过提供的`Predicate`函数处理时结果为`true`。

以下代码演示了前面的操作是如何工作的：

```java
Stream.of("3", "2", "3", "4", "2").distinct()
                            .forEach(System.out::print);  //prints: 324
List<String> list = List.of("1", "2", "3", "4", "5");
list.stream().skip(3).forEach(System.out::print);         //prints: 45
list.stream().limit(3).forEach(System.out::print);        //prints: 123
list.stream().filter(s -> Objects.equals(s, "2"))
                            .forEach(System.out::print);  //prints: 2
list.stream().dropWhile(s -> Integer.valueOf(s) < 3)
                            .forEach(System.out::print);  //prints: 345
list.stream().takeWhile(s -> Integer.valueOf(s) < 3)
                            .forEach(System.out::print);  //prints: 12

```

请注意，我们能够重用`List<String>`源对象，但无法重用`Stream`对象。一旦关闭，就无法重新打开。

# Mapping

这组包括可能是最重要的中间操作。它们是唯一修改流元素的中间操作。它们*map*（转换）原始流元素值为新值：

+   `Stream<R> map(Function<T, R> mapper)`: 将提供的函数应用于此流的`T`类型的每个元素，并生成`R`类型的新元素值。

+   `IntStream mapToInt(ToIntFunction<T> mapper)`: 将此流转换为`Integer`值的`IntStream`。

+   `LongStream mapToLong(ToLongFunction<T> mapper)`: 将此流转换为`Long`值的`LongStream`。

+   `DoubleStream mapToDouble(ToDoubleFunction<T> mapper)`: 将此流转换为`Double`值的`DoubleStream`。

+   `Stream<R> flatMap(Function<T, Stream<R>> mapper)`: 将提供的函数应用于此流的`T`类型的每个元素，并生成一个发出`R`类型元素的`Stream<R>`对象。

+   `IntStream flatMapToInt(Function<T, IntStream> mapper)`: 使用提供的函数将`T`类型的每个元素转换为`Integer`值流。

+   `LongStream flatMapToLong(Function<T, LongStream> mapper)`: 使用提供的函数将`T`类型的每个元素转换为`Long`值流。

+   `DoubleStream flatMapToDouble(Function<T, DoubleStream> mapper)`: 使用提供的函数将`T`类型的每个元素转换为`Double`值流。

以下是这些操作的用法示例：

```java
List<String> list = List.of("1", "2", "3", "4", "5");
list.stream().map(s -> s + s)
             .forEach(System.out::print);        //prints: 1122334455
list.stream().mapToInt(Integer::valueOf)
             .forEach(System.out::print);             //prints: 12345
list.stream().mapToLong(Long::valueOf)
             .forEach(System.out::print);             //prints: 12345
list.stream().mapToDouble(Double::valueOf)
             .mapToObj(Double::toString)
             .map(s -> s + " ")
             .forEach(System.out::print);//prints: 1.0 2.0 3.0 4.0 5.0 
list.stream().mapToInt(Integer::valueOf)
             .flatMap(n -> IntStream.iterate(1, i -> i < n, i -> ++i))
             .forEach(System.out::print);        //prints: 1121231234
list.stream().map(Integer::valueOf)
             .flatMapToInt(n -> 
                           IntStream.iterate(1, i -> i < n, i -> ++i))
             .forEach(System.out::print);        //prints: 1121231234
list.stream().map(Integer::valueOf)
             .flatMapToLong(n ->  
                          LongStream.iterate(1, i -> i < n, i -> ++i))
             .forEach(System.out::print);        //prints: 1121231234;
list.stream().map(Integer::valueOf)
             .flatMapToDouble(n -> 
                        DoubleStream.iterate(1, i -> i < n, i -> ++i))
             .mapToObj(Double::toString)
             .map(s -> s + " ")
             .forEach(System.out::print);  
                    //prints: 1.0 1.0 2.0 1.0 2.0 3.0 1.0 2.0 3.0 4.0 

```

在前面的示例中，对于`Double`值，我们将数值转换为`String`，并添加空格，因此结果将以空格分隔的形式打印出来。这些示例非常简单——只是进行最小处理的转换。但是在现实生活中，每个`map`或`flatMap`操作都可以接受一个（任何复杂程度的函数）来执行真正有用的操作。

# 排序

以下两个中间操作对流元素进行排序。自然地，这样的操作直到所有元素都被发射完毕才能完成，因此会产生大量的开销，降低性能，并且必须用于小型流：

+   `Stream<T> sorted()`: 按照它们的`Comparable`接口实现的自然顺序对流元素进行排序。

+   `Stream<T> sorted(Comparator<T> comparator)`: 按照提供的`Comparator<T>`对象的顺序对流元素进行排序。

以下是演示代码：

```java
List<String> list = List.of("2", "1", "5", "4", "3");
list.stream().sorted().forEach(System.out::print);  //prints: 12345
list.stream().sorted(Comparator.reverseOrder())
             .forEach(System.out::print);           //prints: 54321

```

# Peeking

`Stream<T> peek(Consumer<T> action)`中间操作将提供的`Consumer`函数应用于每个流元素，并且不更改此`Stream`（返回它接收到的相同元素值），因为`Consumer`函数返回`void`，并且不能影响值。此操作用于调试。

以下代码显示了它的工作原理：

```java
List<String> list = List.of("1", "2", "3", "4", "5");
list.stream().peek(s-> {
    if("3".equals(s)){
        System.out.print(3);
    }
}).forEach(System.out::print);  //prints: 123345
```

# 终端操作

终端操作是流管道中最重要的操作。不需要任何其他操作就可以轻松完成所有操作。我们已经使用了`forEach(Consumer<T>)`终端操作来打印每个元素。它不返回值；因此，它用于其副作用。但是`Stream`接口还有许多更强大的终端操作，它们会返回值。其中最重要的是`collect()`操作，它有两种形式，`R collect(Collector<T, A, R> collector)`和`R collect(Supplier<R> supplier, BiConsumer<R, T> accumulator, BiConsumer<R, R> combiner)`。这些允许我们组合几乎可以应用于流的任何过程。经典示例如下：

```java
List<String> asList = stringStream.collect(ArrayList::new, 
                                           ArrayList::add, 
                                           ArrayList::addAll);
```

如您所见，它是为并行处理而实现的。它使用第一个函数基于流元素生成值，使用第二个函数累积结果，然后结合处理流的所有线程累积的结果。

然而，只有一个这样的通用终端操作会迫使程序员重复编写相同的函数。这就是为什么 API 作者添加了`Collectors`类，它可以生成许多专门的`Collector`对象，而无需为每个`collect()`操作创建三个函数。除此之外，API 作者还添加了更多专门的终端操作，这些操作更简单，更容易使用`Stream`接口。

在本节中，我们将回顾`Stream`接口的所有终端操作，并在`Collecting`子部分中查看`Collectors`类生成的大量`Collector`对象的种类。

我们将从最简单的终端操作开始，它允许逐个处理流的每个元素。

# 处理每个元素

这个组中有两个终端操作：

+   `void forEach(Consumer<T> action)`: 对流的每个元素应用提供的操作（处理）。

+   `void forEachOrdered(Consumer<T> action)`: 对流的每个元素应用提供的操作（处理），其顺序由源定义，无论流是顺序的还是并行的。

如果您的应用程序对需要处理的元素的顺序很重要，并且必须按照源中值的排列顺序进行处理，那么使用第二种方法是很重要的，特别是如果您可以预见到您的代码将在具有多个 CPU 的计算机上执行。否则，使用第一种方法，就像我们在所有的例子中所做的那样。

这种操作被用于*任何类型*的流处理是很常见的，特别是当代码是由经验不足的程序员编写时。对于下面的例子，我们创建了`Person`类：

```java
class Person {
    private int age;
    private String name;
    public Person(int age, String name) {
        this.name = name;
        this.age = age;
    }
    public String getName() { return this.name; }
    public int getAge() {return this.age; }
    @Override
    public String toString() {
        return "Person{" + "name='" + this.name + "'" +
                         ", age=" + age + "}";
    }
}
```

我们将在终端操作的讨论中使用这个类。在这个例子中，我们将从文件中读取逗号分隔的值（年龄和姓名），并创建`Person`对象。我们已经将以下`persons.csv`文件（**逗号分隔值（CSV）**）放在`resources`文件夹中：

```java
 23 , Ji m
 2 5 , Bob
15 , Jill
 17 , Bi ll
```

请注意我们在值的外部和内部添加的空格。我们这样做是为了借此机会向您展示一些简单但非常有用的处理现实数据的技巧。以下是一个经验不足的程序员可能编写的代码，用于读取此文件并创建`Person`对象列表：

```java
List<Person> persons = new ArrayList<>();
Path path = Paths.get("src/main/resources/persons.csv");
try (Stream<String> lines = Files.newBufferedReader(path).lines()) {
    lines.forEach(s -> {
        String[] arr = s.split(",");
        int age = Integer.valueOf(StringUtils.remove(arr[0], ' '));
        persons.add(new Person(age, StringUtils.remove(arr[1], ' ')));
    });
} catch (IOException ex) {
    ex.printStackTrace();
}
persons.stream().forEach(System.out::println);  
                                 //prints: Person{name='Jim', age=23}
                                 //        Person{name='Bob', age=25}
                                 //        Person{name='Jill', age=15}
                                 //        Person{name='Bill', age=17}

```

您可以看到我们使用了`String`方法`split()`，通过逗号分隔每一行的值，并且我们使用了`org.apache.commons.lang3.StringUtils`类来移除每个值中的空格。前面的代码还提供了`try-with-resources`结构的真实示例，用于自动关闭`BufferedReader`对象。

尽管这段代码在小例子和单核计算机上运行良好，但在长流和并行处理中可能会产生意外的结果。也就是说，lambda 表达式要求所有变量都是 final 的，或者有效地是 final 的，因为相同的函数可以在不同的上下文中执行。

相比之下，这是前面代码的正确实现：

```java
List<Person> persons = new ArrayList<>();
Path path = Paths.get("src/main/resources/persons.csv");
try (Stream<String> lines = Files.newBufferedReader(path).lines()) {
    persons = lines.map(s -> s.split(","))
       .map(arr -> {
          int age = Integer.valueOf(StringUtils.remove(arr[0], ' '));
          return new Person(age, StringUtils.remove(arr[1], ' '));
       }).collect(Collectors.toList());
} catch (IOException ex) {
    ex.printStackTrace();
}
persons.stream().forEach(System.out::println);

```

为了提高可读性，可以创建一个执行映射工作的方法：

```java
public List<Person> createPersons() {
   List<Person> persons = new ArrayList<>();
   Path path = Paths.get("src/main/resources/persons.csv");
   try (Stream<String> lines = Files.newBufferedReader(path).lines()) {
        persons = lines.map(s -> s.split(","))
                .map(this::createPerson)
                .collect(Collectors.toList());
   } catch (IOException ex) {
        ex.printStackTrace();
   }
   return persons;
}
private Person createPerson(String[] arr){
    int age = Integer.valueOf(StringUtils.remove(arr[0], ' '));
    return new Person(age, StringUtils.remove(arr[1], ' '));
}
```

正如你所看到的，我们使用了`collect()`操作和`Collectors.toList()`方法创建的`Collector`函数。我们将在*Collect*子部分中看到更多由`Collectors`类创建的`Collector`函数。

# 计算所有元素

`long count()`终端操作的`Stream`接口看起来很简单，也很温和。它返回这个流中的元素数量。习惯于使用集合和数组的人可能会毫不犹豫地使用`count()`操作。下面是一个例子，证明它可以正常工作：

```java
long count = Stream.of("1", "2", "3", "4", "5")
        .peek(System.out::print)
        .count();
System.out.print(count);                 //prints: 5

```

正如你所看到的，实现计数方法的代码能够确定流的大小，而不需要执行整个管道。元素的值并没有被`peek()`操作打印出来，这证明元素并没有被发出。但是并不总是能够在源头确定流的大小。此外，流可能是无限的。因此，必须谨慎使用`count()`。

既然我们正在讨论计算元素的话，我们想展示另一种可能的确定流大小的方法，使用`collect()`操作：

```java
int count = Stream.of("1", "2", "3", "4", "5")
        .peek(System.out::print)         //prints: 12345
        .collect(Collectors.counting());
System.out.println(count);                //prints: 5

```

你可以看到`collect()`操作的实现甚至没有尝试在源头计算流的大小（因为，正如你所看到的，管道已经完全执行，并且每个元素都被`peek()`操作打印出来）。这是因为`collect()`操作不像`count()`操作那样专门化。它只是将传入的收集器应用于流，而收集器则计算由`collect()`操作提供给它的元素。你可以将这看作是官僚近视的一个例子：每个操作符都按预期工作，但整体性能仍然有所欠缺。

# 匹配所有、任意或没有

有三个（看起来非常相似的）终端操作，允许我们评估流中的所有、任意或没有元素是否具有特定值：

+   `boolean allMatch(Predicate<T> predicate)`: 当流中的每个元素返回`true`时，作为提供的`Predicate<T>`函数的参数时返回`true`。

+   `boolean anyMatch(Predicate<T> predicate)`: 当流中的一个元素返回`true`时，作为提供的`Predicate<T>`函数的参数时返回`true`。

+   `boolean noneMatch(Predicate<T> predicate)`: 当流中没有元素返回`true`时，作为提供的`Predicate<T>`函数的参数时返回`true`。

以下是它们的使用示例：

```java
List<String> list = List.of("1", "2", "3", "4", "5");
boolean found = list.stream()
        .peek(System.out::print)          //prints: 123
        .anyMatch(e -> "3".equals(e));
System.out.print(found);                  //prints: true   <= line 5
found = list.stream()
        .peek(System.out::print)          //prints: 12345
        .anyMatch(e -> "0".equals(e));
System.out.print(found);                  //prints: false  
boolean noneMatches = list.stream()       
        .peek(System.out::print)          //prints: 123
        .noneMatch(e -> "3".equals(e));
System.out.print(noneMatches);            //prints: false
noneMatches = list.stream()
        .peek(System.out::print)          //prints: 12345
        .noneMatch(e -> "0".equals(e));
System.out.print(noneMatches);            //prints: true  <= line 17
boolean allMatch = list.stream()          
        .peek(System.out::print)          //prints: 1
        .allMatch(e -> "3".equals(e));
System.out.print(allMatch);               //prints: false

```

让我们更仔细地看一下前面示例的结果。这些操作中的每一个都触发了流管道的执行，每次至少处理流的一个元素。但是看看`anyMatch()`和`noneMatch()`操作。第 5 行说明至少有一个元素等于`3`。结果是在*处理了前三个元素之后*返回的。第 17 行说明在*处理了流的所有元素*之后，没有元素等于`0`。

问题是，当您想要知道流*不包含*`v`值时，这两个操作中的哪一个应该使用？如果使用`noneMatch()`，*所有元素都将被处理*。但是如果使用`anyMatch()`，只有在流中没有`v`*值*时，所有元素才会被处理。似乎`noneMatch()`操作是无用的，因为当`anyMatch()`返回`true`时，它的含义与`noneMatch()`返回`false`相同，而`anyMatch()`操作只需处理更少的元素即可实现。随着流大小的增长和存在`v`值的机会增加，这种差异变得更加重要。似乎`noneMatch()`操作的唯一原因是代码可读性，当处理时间不重要时，因为流大小很小。

`allMatch()`操作没有替代方案，与`anyMatch()`类似，当遇到第一个不匹配的元素时返回，或者需要处理所有流元素。

# 查找任何或第一个

以下终端操作允许我们找到流的任何元素或第一个元素：

+   `Optional<T> findAny()`: 返回流的任何元素的值的`Optional`，如果流为空，则返回一个空的`Optional`。

+   `Optional<T> findFirst()`: 返回流的第一个元素的值的`Optional`，如果流为空，则返回一个空的`Optional`。

以下示例说明了这些操作：

```java
List<String> list = List.of("1", "2", "3", "4", "5");

Optional<String> result = list.stream().findAny();
System.out.println(result.isPresent());    //prints: true
System.out.println(result.get());          //prints: 1

result = list.stream().filter(e -> "42".equals(e)).findAny();
System.out.println(result.isPresent());    //prints: true
//System.out.println(result.get());        //NoSuchElementException

result = list.stream().findFirst();
System.out.println(result.isPresent());    //prints: true
System.out.println(result.get());          //prints: 1
```

如您所见，它们返回相同的结果。这是因为我们在单个线程中执行管道。这两个操作之间的差异在并行处理中更加显著。当流被分成几个部分进行并行处理时，如果流不为空，`findFirst()`操作总是返回流的第一个元素，而`findAny()`操作只在一个处理线程中返回第一个元素。

让我们更详细地讨论`java.util.Optional`类。

# Optional 类

`java.util.Optional`对象用于避免返回`null`，因为它可能会导致`NullPointerException`。相反，`Optional`对象提供了可以用来检查值是否存在并在没有值的情况下替换它的方法。例如：

```java
List<String> list = List.of("1", "2", "3", "4", "5");

String result = list.stream().filter(e -> "42".equals(e))
       .findAny().or(() -> Optional.of("Not found")).get();
System.out.println(result);                       //prints: Not found

result = list.stream().filter(e -> "42".equals(e))
                            .findAny().orElse("Not found");
System.out.println(result);                        //prints: Not found

Supplier<String> trySomethingElse = () -> {
    //Code that tries something else
    return "43";
};
result = list.stream().filter(e -> "42".equals(e))
                   .findAny().orElseGet(trySomethingElse);
System.out.println(result);                          //prints: 43

list.stream().filter(e -> "42".equals(e))
    .findAny().ifPresentOrElse(System.out::println, 
            () -> System.out.println("Not found"));  //prints: Not found
```


如您所见，如果`Optional`对象为空，则：

+   `Optional`类的`or()`方法允许返回另一个带有值的`Optional`对象。

+   `orElse()`方法允许返回一种替代值。

+   `orElseGet()`方法允许提供`Supplier`函数，该函数返回一种替代值。

+   `ifPresentOrElse()`方法允许提供两个函数：一个从`Optional`对象中消费值，另一个在`Optional`对象为空时执行某些操作。

# 最小值和最大值

以下终端操作如果存在则返回流元素的最小或最大值：

+   `Optional<T> min`(Comparator<T> comparator)：使用提供的 Comparator 对象返回此流的最小元素。

+   `Optional<T> max`(Comparator<T> comparator)：使用提供的 Comparator 对象返回此流的最大元素。

下面是演示代码：

```java
List<String> list = List.of("a", "b", "c", "c", "a");
String min = list.stream().min(Comparator.naturalOrder()).orElse("0");
System.out.println(min);     //prints: a

String max = list.stream().max(Comparator.naturalOrder()).orElse("0");
System.out.println(max);     //prints: c

```

如您所见，在非数值值的情况下，最小元素是从左到右排序时的第一个元素，根据提供的比较器；相应地，最大值是最后一个元素。在数值值的情况下，最小值和最大值就是流元素中的最大数和最小数：

```java
int mn = Stream.of(42, 33, 77).min(Comparator.naturalOrder()).orElse(0);
System.out.println(mn);    //prints: 33
int mx = Stream.of(42, 33, 77).max(Comparator.naturalOrder()).orElse(0);
System.out.println(mx);    //prints: 77

```

让我们看另一个例子，假设有一个`Person`类：

```java
class Person {
    private int age;
    private String name;
    public Person(int age, String name) {
        this.age = age;
        this.name = name;
    }
    public int getAge() { return this.age; }
    public String getName() { return this.name; }
    @Override
    public String toString() {
        return "Person{name:" + this.name + ",age:" + this.age + "}";
    }
}
```

任务是在以下列表中找到最年长的人：

```java
List<Person> persons = List.of(new Person(23, "Bob"),
                               new Person(33, "Jim"),
                               new Person(28, "Jill"),
                               new Person(27, "Bill"));
```

为了做到这一点，我们可以创建以下的`Compartor<Person>`：

```java
Comparator<Person> perComp = (p1, p2) -> p1.getAge() - p2.getAge();
```

然后，使用这个比较器，我们可以找到最年长的人：

```java
Person theOldest = persons.stream().max(perComp).orElse(null);
System.out.println(theOldest);  //prints: Person{name:Jim,age:33}
```

# toArray()操作

这两个终端操作生成一个包含流元素的数组：

+   `Object[] toArray()`：创建一个包含该流每个元素的对象数组。

+   `A[] toArray(IntFunction<A[]> generator)`: 使用提供的函数创建流元素的数组。

让我们看一个例子：

```java
List<String> list = List.of("a", "b", "c");
Object[] obj = list.stream().toArray();
Arrays.stream(obj).forEach(System.out::print);    //prints: abc

String[] str = list.stream().toArray(String[]::new);
Arrays.stream(str).forEach(System.out::print);    //prints: abc

```

第一个例子很直接。它将元素转换为相同类型的数组。至于第二个例子，`IntFunction`作为`String[]::new`的表示可能不够明显，所以让我们逐步来看一下。

`String[]::new`是一个方法引用，代表以下 lambda 表达式：


```java
String[] str = list.stream().toArray(i -> new String[i]);
Arrays.stream(str).forEach(System.out::print);    //prints: abc

```

这已经是`IntFunction<String[]>`，根据其文档，它接受一个`int`参数并返回指定类型的结果。可以通过使用匿名类来定义，如下所示：

```java
IntFunction<String[]> intFunction = new IntFunction<String[]>() {
    @Override
    public String[] apply(int i) {
        return new String[i];
    }
};

```

您可能还记得（来自第十三章，*Java 集合*）我们如何将集合转换为数组：

```java
str = list.toArray(new String[list.size()]);
Arrays.stream(str).forEach(System.out::print);    //prints: abc

```

您可以看到`Stream`接口的`toArray()`操作具有非常相似的签名，只是它接受一个函数，而不仅仅是一个数组。

# reduce 操作

这个终端操作被称为*reduce*，因为它处理所有流元素并产生一个值。它将所有流元素减少为一个值。但这不是唯一的操作。*collect*操作也将流元素的所有值减少为一个结果。而且，在某种程度上，所有终端操作都会减少。它们在处理所有元素后产生一个值。

因此，您可以将*reduce*和*collect*视为帮助为`Stream`接口中提供的许多操作添加结构和分类的同义词。此外，*reduce*组中的操作可以被视为*collect*操作的专门版本，因为`collect()`也可以被定制以提供相同的功能。

有了这个，让我们看看*reduce*操作组：

+   `Optional<T> reduce(BinaryOperator<T> accumulator)`: 使用提供的定义元素聚合逻辑的可关联函数来减少此流的元素。如果可用，返回带有减少值的`Optional`。

+   `T reduce(T identity, BinaryOperator<T> accumulator)`: 提供与先前`reduce()`版本相同的功能，但使用`identity`参数作为累加器的初始值，或者如果流为空则使用默认值。

+   `U reduce(U identity, BiFunction<U,T,U> accumulator, BinaryOperator<U> combiner)`: 提供与先前`reduce()`版本相同的功能，但另外使用`combiner`函数在应用于并行流时聚合结果。如果流不是并行的，则不使用组合器函数。

为了演示`reduce()`操作，我们将使用之前的`Person`类：

```java
class Person {
    private int age;
    private String name;
    public Person(int age, String name) {
        this.age = age;
        this.name = name;
    }
    public int getAge() { return this.age; }
    public String getName() { return this.name; }
    @Override
    public String toString() {
        return "Person{name:" + this.name + ",age:" + this.age + "}";
    }
}
```

我们还将使用相同的`Person`对象列表作为我们流示例的来源：

```java
List<Person> list = List.of(new Person(23, "Bob"),
                            new Person(33, "Jim"),
                            new Person(28, "Jill"),
                            new Person(27, "Bill"));

```

现在，使用`reduce()`操作，让我们找到此列表中年龄最大的人：

```java
Person theOldest = list.stream()
  .reduce((p1, p2) -> p1.getAge() > p2.getAge() ? p1 : p2).orElse(null);
System.out.println(theOldest);         //prints: Person{name:Jim,age:33}

```

这个实现有点令人惊讶，不是吗？我们在谈论“累加器”，但我们没有累加任何东西。我们只是比较了所有的流元素。显然，累加器保存了比较的结果，并将其作为下一个比较（与下一个元素）的第一个参数提供。可以说，在这种情况下，累加器累积了所有先前比较的结果。无论如何，它完成了我们希望它完成的工作。

现在，让我们明确地累积一些东西。让我们将人员名单中的所有名称组合成一个逗号分隔的列表：

```java
String allNames = list.stream().map(p->p.getName())
                      .reduce((n1, n2) -> n1 + ", " + n2).orElse(null);
System.out.println(allNames);            //prints: Bob, Jim, Jill, Bill

```

在这种情况下，积累的概念更有意义，不是吗？

现在，让我们使用身份值提供一个初始值：

```java
String allNames = list.stream().map(p->p.getName())
                    .reduce("All names: ", (n1, n2) -> n1 + ", " + n2);
System.out.println(allNames);       //All names: , Bob, Jim, Jill, Bill

```

请注意，这个版本的`reduce()`操作返回值，而不是`Optional`对象。这是因为通过提供初始值，我们保证该值将出现在结果中，即使流为空。

但是，结果字符串看起来并不像我们希望的那样漂亮。显然，提供的初始值被视为任何其他流元素，并且累加器创建的后面添加了逗号。为了使结果再次看起来漂亮，我们可以再次使用`reduce()`操作的第一个版本，并通过这种方式添加初始值：

```java
String allNames = "All names: " + list.stream().map(p->p.getName())
                      .reduce((n1, n2) -> n1 + ", " + n2).orElse(null);
System.out.println(allNames);         //All names: Bob, Jim, Jill, Bill

```

我们决定使用空格作为分隔符，而不是逗号，以进行演示：

```java
String allNames = list.stream().map(p->p.getName())
                     .reduce("All names:", (n1, n2) -> n1 + " " + n2);
System.out.println(allNames);        //All names: Bob, Jim, Jill, Bill

```

现在，结果看起来更好了。在下一小节中演示`collect()`操作时，我们将向您展示另一种使用前缀创建逗号分隔值列表的方法。

现在，让我们看看如何使用`reduce()`操作的第三种形式——具有三个参数的形式，最后一个称为组合器。将组合器添加到前面的`reduce()`操作中不会改变结果：

```java
String allNames = list.stream().map(p->p.getName())
                      .reduce("All names:", (n1, n2) -> n1 + " " + n2, 
                                            (n1, n2) -> n1 + " " + n2 );
System.out.println(allNames);          //All names: Bob, Jim, Jill, Bill

```

这是因为流不是并行的，并且组合器仅与并行流一起使用。

如果我们使流并行，结果会改变：

```java
String allNames = list.parallelStream().map(p->p.getName())
                      .reduce("All names:", (n1, n2) -> n1 + " " + n2, 
                                            (n1, n2) -> n1 + " " + n2 );
System.out.println(allNames);   
         //All names: Bob All names: Jim All names: Jill All names: Bill

```

显然，对于并行流，元素序列被分成子序列，每个子序列都是独立处理的；它们的结果由组合器聚合。这样做时，组合器将初始值（身份）添加到每个结果中。即使我们删除组合器，并行流处理的结果仍然是相同的，因为提供了默认的组合器行为：

```java
String allNames = list.parallelStream().map(p->p.getName())
                      .reduce("All names:", (n1, n2) -> n1 + " " + n2);
System.out.println(allNames);   
        //All names: Bob All names: Jim All names: Jill All names: Bill

```

在前两种`reduce()`操作中，标识值被累加器使用。在第三种形式中，使用了`U reduce(U identity, BiFunction<U,T,U> accumulator, BinaryOperator<U> combiner)`签名，标识值被组合器使用（注意，`U`类型是组合器类型）。

为了消除结果中重复的标识值，我们决定从 combiner 的第二个参数中删除它：

```java
allNames = list.parallelStream().map(p->p.getName())
    .reduce("All names:", (n1, n2) -> n1 + " " + n2,
        (n1, n2) -> n1 + " " + StringUtils.remove(n2, "All names:"));
System.out.println(allNames);       //All names: Bob, Jim, Jill, Bill

```

如您所见，结果现在看起来好多了。

到目前为止，我们的例子中，标识不仅起到了初始值的作用，还起到了结果中的标识（标签）的作用。当流的元素是数字时，标识看起来更像是初始值。让我们看下面的例子：

```java
List<Integer> ints = List.of(1, 2, 3);
int sum = ints.stream().reduce((i1, i2) -> i1 + i2).orElse(0);
System.out.println(sum);                          //prints: 6

sum = ints.stream().reduce(Integer::sum).orElse(0);
System.out.println(sum);                          //prints: 6

sum = ints.stream().reduce(10, Integer::sum);
System.out.println(sum);                         //prints: 16

sum = ints.stream().reduce(10, Integer::sum, Integer::sum);
System.out.println(sum);                         //prints: 16
```

前两个流管道完全相同，只是第二个管道使用了方法引用而不是 lambda 表达式。第三个和第四个管道也具有相同的功能。它们都使用初始值 10。现在第一个参数作为初始值比标识更有意义，不是吗？在第四个管道中，我们添加了一个组合器，但它没有被使用，因为流不是并行的。

让我们并行处理一下，看看会发生什么：

```java
List<Integer> ints = List.of(1, 2, 3);
int sum = ints.parallelStream().reduce(10, Integer::sum, Integer::sum);
System.out.println(sum);                                   //prints: 36

```

结果为 36，因为初始值 10 被添加了三次-每次都有部分结果。显然，流被分成了三个子序列。但情况并非总是如此，随着流的增长和计算机上 CPU 数量的增加而发生变化。因此，不能依赖于一定数量的子序列，最好不要在这种情况下使用它，如果需要，可以添加到结果中：

```java
List<Integer> ints = List.of(1, 2, 3);

int sum = ints.parallelStream().reduce(0, Integer::sum, Integer::sum);
System.out.println(sum);                                   //prints: 6

sum = 10 + ints.parallelStream().reduce(0, Integer::sum, Integer::sum);
System.out.println(sum);                                   //prints: 16
```

# 收集操作

`collect()`操作的一些用法非常简单，适合任何初学者，而其他情况可能复杂，即使对于经验丰富的程序员也难以理解。除了已经讨论过的操作之外，我们在本节中介绍的`collect()`的最受欢迎的用法已经足够满足初学者的所有需求。再加上我们将在*数字流接口*部分介绍的数字流操作，覆盖的内容可能很容易是未来主流程序员所需的一切。

正如我们已经提到的，collect 操作非常灵活，允许我们自定义流处理。它有两种形式：

+   `R collect(Collector<T, A, R> collector)`:使用提供的`Collector`处理此`T`类型的流的元素，并通过`A`类型的中间累积产生`R`类型的结果

+   `R collect(Supplier<R> supplier, BiConsumer<R, T> accumulator, BiConsumer<R, R> combiner)`: 使用提供的函数处理`T`类型的流的元素：

+   `Supplier<R>`: 创建一个新的结果容器

+   `BiConsumer<R, T> accumulator`: 一个无状态的函数，将一个元素添加到结果容器中

+   `BiConsumer<R, R> combiner`：一个无状态的函数，将两个部分结果容器合并在一起，将第二个结果容器的元素添加到第一个结果容器中。

让我们看看`collect()`操作的第二种形式。它与`reduce()`操作非常相似，具有我们刚刚演示的三个参数。最大的区别在于`collect()`操作中的第一个参数不是标识或初始值，而是容器——一个对象，将在函数之间传递，并维护处理的状态。对于以下示例，我们将使用`Person1`类作为容器：

```java
class Person1 {
    private String name;
    private int age;
    public Person1(){}
    public String getName() { return this.name; }
    public void setName(String name) { this.name = name; }
    public int getAge() {return this.age; }
    public void setAge(int age) { this.age = age;}
    @Override
    public String toString() {
        return "Person{name:" + this.name + ",age:" + age + "}";
    }
}
```

正如你所看到的，容器必须有一个没有参数的构造函数和 setter，因为它应该能够接收和保留部分结果——迄今为止年龄最大的人的姓名和年龄。`collect()`操作将在处理每个元素时使用这个容器，并且在处理完最后一个元素后，将包含年龄最大的人的姓名和年龄。这是人员名单，你应该很熟悉：

```java
List<Person> list = List.of(new Person(23, "Bob"),
                            new Person(33, "Jim"),
                            new Person(28, "Jill"),
                            new Person(27, "Bill"));

```

这是应该在列表中找到最年长的人的`collect()`操作：

```java
Person1 theOldest = list.stream().collect(Person1::new,
    (p1, p2) -> {
        if(p1.getAge() < p2.getAge()){
            p1.setAge(p2.getAge());
            p1.setName(p2.getName());
        }
    },
    (p1, p2) -> { System.out.println("Combiner is called!"); });

```

我们尝试在操作调用中内联函数，但看起来有点难以阅读，所以这是相同代码的更好版本：

```java
BiConsumer<Person1, Person> accumulator = (p1, p2) -> {
    if(p1.getAge() < p2.getAge()){
        p1.setAge(p2.getAge());
        p1.setName(p2.getName());
    }
};
BiConsumer<Person1, Person1> combiner = (p1, p2) -> {
    System.out.println("Combiner is called!");        //prints nothing
};
theOldest = list.stream().collect(Person1::new, accumulator, combiner);
System.out.println(theOldest);        //prints: Person{name:Jim,age:33}

```

`Person1`容器对象只创建一次——用于第一个元素的处理（在这个意义上，它类似于`reduce()`操作的初始值）。然后将其传递给比较器，与第一个元素进行比较。容器中的`age`字段被初始化为零的默认值，因此，迄今为止，容器中设置了第一个元素的年龄和姓名作为年龄最大的人的参数。

当流的第二个元素（`Person`对象）被发出时，它的`age`字段与容器（`Person1`对象）中当前存储的`age`值进行比较，依此类推，直到处理完流的所有元素。结果如前面的注释所示。

组合器从未被调用，因为流不是并行的。但是当我们并行时，我们需要实现组合器如下：

```java
BiConsumer<Person1, Person1> combiner = (p1, p2) -> {
    System.out.println("Combiner is called!");   //prints 3 times
    if(p1.getAge() < p2.getAge()){
        p1.setAge(p2.getAge());
        p1.setName(p2.getName());
    }
};
theOldest = list.parallelStream()
                .collect(Person1::new, accumulator, combiner);
System.out.println(theOldest);  //prints: Person{name:Jim,age:33}
```

组合器比较了所有流子序列的部分结果，并得出最终结果。现在我们看到`Combiner is called!`消息打印了三次。但是，与`reduce()`操作一样，部分结果（流子序列）的数量可能会有所不同。

现在让我们来看一下`collect()`操作的第一种形式。它需要一个实现`java.util.stream.Collector<T,A,R>`接口的类的对象，其中`T`是流类型，`A`是容器类型，`R`是结果类型。可以使用`Collector`接口的`of()`方法来创建必要的`Collector`对象：

+   `static Collector<T,R,R> of(Supplier<R> supplier, BiConsumer<R,T> accumulator, BinaryOperator<R> combiner, Collector.Characteristics... characteristics)`

+   `static Collector<T,A,R> of(Supplier<A> supplier, BiConsumer<A,T> accumulator, BinaryOperator<A> combiner, Function<A,R> finisher, Collector.Characteristics... characteristics)`.

前面方法中必须传递的函数与我们已经演示过的函数类似。但我们不打算这样做有两个原因。首先，这涉及的内容更多，超出了本入门课程的范围，其次，在这之前，必须查看提供了许多现成收集器的`java.util.stream.Collectors`类。正如我们已经提到的，加上本书讨论的操作和我们将在*数字流接口*部分介绍的数字流操作，它们涵盖了主流编程中绝大多数处理需求，很可能你根本不需要创建自定义收集器。

# 类收集器

`java.util.stream.Collectors`类提供了 40 多种方法来创建`Collector`对象。我们将仅演示最简单和最流行的方法：

+   `Collector<T,?,List<T>> toList()`：创建一个收集器，将流元素收集到一个`List`对象中。

+   `Collector<T,?,Set<T>> toSet()`：创建一个收集器，将流元素收集到一个`Set`对象中。

+   `Collector<T,?,Map<K,U>> toMap (Function<T,K> keyMapper, Function<T,U> valueMapper)`：创建一个收集器，将流元素收集到一个`Map`对象中。

+   `Collector<T,?,C> toCollection (Supplier<C> collectionFactory)`：创建一个收集器，将流元素收集到由集合工厂指定类型的`Collection`对象中。

+   `Collector<CharSequence,?,String> joining()`：创建一个收集器，将元素连接成一个`String`值。

+   `Collector<CharSequence,?,String> joining (CharSequence delimiter)`：创建一个收集器，将元素连接成一个以提供的分隔符分隔的`String`值。

+   `Collector<CharSequence,?,String> joining (CharSequence delimiter, CharSequence prefix, CharSequence suffix)`：创建一个收集器，将元素连接成一个以提供的前缀和后缀分隔的`String`值。

+   `Collector<T,?,Integer> summingInt(ToIntFunction<T>)`：创建一个计算由提供的函数应用于每个元素生成的结果的总和的收集器。相同的方法也适用于`long`和`double`类型。

+   `Collector<T,?,IntSummaryStatistics> summarizingInt(ToIntFunction<T>)`：创建一个收集器，计算由提供的函数应用于每个元素生成的结果的总和、最小值、最大值、计数和平均值。相同的方法也适用于`long`和`double`类型。

+   `Collector<T,?,Map<Boolean,List<T>>> partitioningBy (Predicate<? super T> predicate)`：创建一个收集器，根据提供的`Predicate`函数将元素分区。

+   `Collector<T,?,Map<K,List<T>>> groupingBy(Function<T,U>)`：创建一个收集器，将元素分组到由提供的函数生成的`Map`中。

The following demo code shows how to use the collectors created by these methods. First, we demonstrate usage of the  `toList()`, `toSet()`, `toMap()`, and `toCollection()` methods:

```java
List<String> ls = Stream.of("a", "b", "c").collect(Collectors.toList());
System.out.println(ls);                //prints: [a, b, c]

Set<String> set = Stream.of("a", "a", "c").collect(Collectors.toSet());
System.out.println(set);                //prints: [a, c]

List<Person> persons = List.of(new Person(23, "Bob"),
                               new Person(33, "Jim"),
                               new Person(28, "Jill"),
                               new Person(27, "Bill"));
Map<String, Person> map = persons.stream()
    .collect(Collectors.toMap(p->p.getName() + "-" + p.getAge(), p->p));
System.out.println(map); //prints: {Bob-23=Person{name:Bob,age:23}, 
                                    Bill-27=Person{name:Bill,age:27}, 
                                    Jill-28=Person{name:Jill,age:28}, 
                                    Jim-33=Person{name:Jim,age:33}}
Set<Person> personSet = persons.stream()
                        .collect(Collectors.toCollection(HashSet::new));
System.out.println(personSet);  //prints: [Person{name:Bill,age:27}, 
                                           Person{name:Jim,age:33}, 
                                           Person{name:Bob,age:23}, 
                                           Person{name:Jill,age:28}]

```

The `joining()` method allows concatenating the `Character` and `String` values in a delimited list with a prefix and suffix:

```java
List<String> list = List.of("a", "b", "c", "d");
String result = list.stream().collect(Collectors.joining());
System.out.println(result);           //abcd

result = list.stream().collect(Collectors.joining(", "));
System.out.println(result);           //a, b, c, d

result = list.stream()
             .collect(Collectors.joining(", ", "The result: ", ""));
System.out.println(result);          //The result: a, b, c, d

result = list.stream()
      .collect(Collectors.joining(", ", "The result: ", ". The End."));
System.out.println(result);          //The result: a, b, c, d. The End.

```

The `summingInt()` and `summarizingInt()` methods create collectors that calculate the sum and other statistics of the `int` values produced by the provided function applied to each element:

```java
List<Person> list = List.of(new Person(23, "Bob"),
                            new Person(33, "Jim"),
                            new Person(28, "Jill"),
                            new Person(27, "Bill"));
int sum = list.stream().collect(Collectors.summingInt(Person::getAge));
System.out.println(sum);  //prints: 111

IntSummaryStatistics stats = 
      list.stream().collect(Collectors.summarizingInt(Person::getAge));
System.out.println(stats);     //IntSummaryStatistics{count=4, sum=111, 
                               //    min=23, average=27.750000, max=33}
System.out.println(stats.getCount());    //4
System.out.println(stats.getSum());      //111
System.out.println(stats.getMin());      //23
System.out.println(stats.getAverage());  //27.750000
System.out.println(stats.getMax());      //33

```

There are also `summingLong()`, `summarizingLong()` , `summingDouble()`, and `summarizingDouble()` methods.

The `partitioningBy()` method creates a collector that groups the elements by the provided criteria and put the groups (lists) in a `Map` object with a `boolean` value as the key:

```java
List<Person> list = List.of(new Person(23, "Bob"),
                            new Person(33, "Jim"),
                            new Person(28, "Jill"),
                            new Person(27, "Bill"));
Map<Boolean, List<Person>> map = 
   list.stream().collect(Collectors.partitioningBy(p->p.getAge() > 27));
System.out.println(map);  
              //{false=[Person{name:Bob,age:23}, Person{name:Bill,age:27}], 
              //  true=[Person{name:Jim,age:33}, Person{name:Jill,age:28}]}
```

As you can see, using the `p.getAge() > 27` criteria, we were able to put all the people in two groups—one is below or equals 27 years of age (the key is `false`), and the other is above 27 (the key is `true`).

And, finally, the `groupingBy()` method allows us to group elements by a value and put the groups (lists) in a `Map` object with this value as a key:

```java
List<Person> list = List.of(new Person(23, "Bob"),
                            new Person(33, "Jim"),
                            new Person(23, "Jill"),
                            new Person(33, "Bill"));
Map<Integer, List<Person>> map = 
           list.stream().collect(Collectors.groupingBy(Person::getAge));
System.out.println(map);  
              //{33=[Person{name:Jim,age:33}, Person{name:Bill,age:33}], 
              // 23=[Person{name:Bob,age:23}, Person{name:Jill,age:23}]}

```

为了演示前面的方法，我们通过将每个人的年龄设置为 23 或 33 来改变了`Person`对象的列表。结果是按年龄分成两组。

还有重载的`toMap()`、`groupingBy()`和`partitioningBy()`方法，以及以下通常也重载的方法，它们创建相应的`Collector`对象：

+   `counting()`

+   `reducing()`

+   `filtering()`

+   `toConcurrentMap()`

+   ``collectingAndThen()``

+   `maxBy()` 和 `minBy()`

+   `mapping()` 和 `flatMapping()`

+   `averagingInt()`, `averagingLong()`, 和 `averagingDouble()`

+   `toUnmodifiableList()`、`toUnmodifiableMap()`和 `toUnmodifiableSet()`

如果在本书中找不到所需的操作，请先搜索`Collectors`API，然后再构建自己的`Collector`对象。

# 数字流接口

正如我们已经提到的，所有三个数字接口，`IntStream`、`LongStream`和`DoubleStream`，都有类似于`Stream`接口的方法，包括`Stream.Builder`接口的方法。这意味着我们在本章中讨论的所有内容同样适用于任何数字流接口。因此，在本节中，我们只会讨论`Stream`接口中不存在的那些方法：

+   `IntStream`和`LongStream`接口中的`range(lower,upper)`和`rangeClosed(lower,upper)`方法。它们允许我们从指定范围内的值创建流。

+   `boxed()`和`mapToObj()`中间操作，将数字流转换为`Stream`。

+   `mapToInt()`、`mapToLong()`和`mapToDouble()`中间操作，将一个类型的数字流转换为另一个类型的数字流。

+   `flatMapToInt()`、`flatMapToLong()`和`flatMapToDouble()`中间操作，将流转换为数字流。

+   `sum()`和`average()`终端操作，计算数字流元素的和和平均值。

# 创建流

除了创建流的`Stream`接口方法外，`IntStream`和`LongStream`接口还允许我们从指定范围内的值创建流。

# range()，rangeClosed()

`range(lower, upper)`方法按顺序生成所有值，从`lower`值开始，以`upper`值之前的值结束：

```java
IntStream.range(1, 3).forEach(System.out::print);  //prints: 12
LongStream.range(1, 3).forEach(System.out::print);  //prints: 12

```

`rangeClosed(lower, upper)` 方法按顺序生成所有值，从`lower`值开始，以`upper`值结束：

```java
IntStream.rangeClosed(1, 3).forEach(System.out::print);  //prints: 123
LongStream.rangeClosed(1, 3).forEach(System.out::print);  //prints: 123

```

# 中间操作

除了`Stream`中间操作外，`IntStream`、`LongStream`和`DoubleStream`接口还具有特定于数字的中间操作：`boxed()`、`mapToObj()`、`mapToInt()`、`mapToLong()`、`mapToDouble()`、`flatMapToInt()`、`flatMapToLong()`和`flatMapToDouble()`。

# boxed()和 mapToObj()

`boxed()` 中间操作将原始数值类型的元素转换（装箱）为相应的包装类型：

```java
//IntStream.range(1, 3).map(Integer::shortValue)        //compile error
//                     .forEach(System.out::print);  
IntStream.range(1, 3).boxed().map(Integer::shortValue)
                             .forEach(System.out::print);  //prints: 12
//LongStream.range(1, 3).map(Long::shortValue)          //compile error
//                      .forEach(System.out::print);  
LongStream.range(1, 3).boxed().map(Long::shortValue)
                              .forEach(System.out::print);  //prints: 12
//DoubleStream.of(1).map(Double::shortValue)            //compile error
//                  .forEach(System.out::print);  
DoubleStream.of(1).boxed().map(Double::shortValue)
                          .forEach(System.out::print);      //prints: 1

```

在上述代码中，我们已经注释掉了生成编译错误的行，因为`range()`方法生成的元素是原始类型。通过添加`boxed()`操作，我们将原始值转换为相应的包装类型，然后可以将它们作为引用类型进行处理。

`mapToObj()`中间操作进行了类似的转换，但它不像`boxed()`操作那样专门化，并且允许使用原始类型的元素来生成任何类型的对象：

```java
IntStream.range(1, 3).mapToObj(Integer::valueOf)
                     .map(Integer::shortValue)
                     .forEach(System.out::print);       //prints: 12
IntStream.range(42, 43).mapToObj(i -> new Person(i, "John"))
                       .forEach(System.out::print);  
                                   //prints: Person{name:John,age:42}
LongStream.range(1, 3).mapToObj(Long::valueOf)
                      .map(Long::shortValue)
                      .forEach(System.out::print);      //prints: 12
DoubleStream.of(1).mapToObj(Double::valueOf)
                  .map(Double::shortValue)
                  .forEach(System.out::print);          //prints: 1

```

在上述代码中，我们添加了`map()`操作，只是为了证明`mapToObj()`操作可以按预期执行工作并创建包装类型对象。此外，通过添加生成`Person`对象的流管道，我们演示了如何使用`mapToObj()`操作来创建任何类型的对象。

# mapToInt()、mapToLong()和 mapToDouble()

`mapToInt()`、`mapToLong()`、`mapToDouble()`中间操作允许我们将一个类型的数值流转换为另一种类型的数值流。在演示代码中，我们通过将每个`String`值映射到其长度，将`String`值列表转换为不同类型的数值流：

```java
list.stream().mapToInt(String::length)
                   .forEach(System.out::print); //prints: 335
list.stream().mapToLong(String::length)
                   .forEach(System.out::print); //prints: 335
list.stream().mapToDouble(String::length)
    .forEach(d -> System.out.print(d + " "));   //prints: 3.0 3.0 5.0

```

创建的数值流的元素是原始类型的：

```java
//list.stream().mapToInt(String::length)
//             .map(Integer::shortValue)   //compile error
//             .forEach(System.out::print); 

```

既然我们在这个话题上，如果您想将元素转换为数值包装类型，`map()`中间操作就是这样做的方法（而不是`mapToInt()`）：

```java
list.stream().map(String::length)
             .map(Integer::shortValue)
             .forEach(System.out::print);  //prints: 335

```

# flatMapToInt()、flatMapToLong()和 flatMapToDouble()

`flatMapToInt()`、`flatMapToLong()`、`flatMapToDouble()`中间操作会生成相应类型的数值流：

```java
List<Integer> list = List.of(1, 2, 3);

list.stream().flatMapToInt(i -> IntStream.rangeClosed(1, i))
                        .forEach(System.out::print);    //prints: 112123
list.stream().flatMapToLong(i -> LongStream.rangeClosed(1, i))
                        .forEach(System.out::print);    //prints: 112123
list.stream().flatMapToDouble(DoubleStream::of)
        .forEach(d -> System.out.print(d + " "));  //prints: 1.0 2.0 3.0

```

如您所见，在上述代码中，我们在原始流中使用了`int`值。但它可以是任何类型的流：

```java
List<String> str = List.of("one", "two", "three");
str.stream().flatMapToInt(s -> IntStream.rangeClosed(1, s.length()))
                      .forEach(System.out::print);  //prints: 12312312345

```

# 终端操作

数值流的附加终端操作非常简单。它们中有两个：

+   `sum()`: 计算数值流元素的总和

+   `average()`: 计算数值流元素的平均值

# sum()和 average()

如果您需要计算数值流元素的总和或平均值，则流的唯一要求是它不应该是无限的。否则，计算永远不会完成：

```java
int sum = IntStream.empty().sum();
System.out.println(sum);          //prints: 0

sum = IntStream.range(1, 3).sum();
System.out.println(sum);          //prints: 3

double av = IntStream.empty().average().orElse(0);
System.out.println(av);           //prints: 0.0

av = IntStream.range(1, 3).average().orElse(0);
System.out.println(av);           //prints: 1.5

long suml = LongStream.range(1, 3).sum();
System.out.println(suml);         //prints: 3

double avl = LongStream.range(1, 3).average().orElse(0);
System.out.println(avl);          //prints: 1.5

double sumd = DoubleStream.of(1, 2).sum();
System.out.println(sumd);         //prints: 3.0

double avd = DoubleStream.of(1, 2).average().orElse(0);
System.out.println(avd);          //prints: 1.5

```

正如您所看到的，对空流使用这些操作不是问题。

# 并行处理

我们已经看到，从顺序流切换到并行流可能会导致不正确的结果，如果代码没有为处理并行流而编写和测试。以下是与并行流相关的一些其他考虑。

# 无状态和有状态的操作

有无状态的操作，比如`filter()`、`map()`和`flatMap()`，在从一个流元素的处理转移到下一个流元素的处理时不会保留数据（不维护状态）。还有有状态的操作，比如`distinct()`、`limit()`、`sorted()`、`reduce()`和`collect()`，可能会将先前处理的元素的状态传递给下一个元素的处理。

无状态操作通常在从顺序流切换到并行流时不会造成问题。每个元素都是独立处理的，流可以被分成任意数量的子流进行独立处理。

对于有状态的操作，情况是不同的。首先，对无限流使用它们可能永远无法完成处理。此外，在讨论`reduce()`和`collect()`有状态操作时，我们已经演示了如果初始值（或标识）在没有考虑并行处理的情况下设置，切换到并行流可能会产生不同的结果。

而且还有性能方面的考虑。有状态的操作通常需要使用缓冲区多次处理所有流元素。对于大流，这可能会消耗 JVM 资源并减慢甚至完全关闭应用程序。

这就是为什么程序员不应该轻易从顺序流切换到并行流。如果涉及有状态的操作，代码必须被设计和测试，以便能够在没有负面影响的情况下执行并行流处理。

# 顺序或并行处理？

正如我们在前一节中所指出的，并行处理可能会产生更好的性能，也可能不会。在决定使用之前，必须测试每个用例。并行处理可能会产生更好的性能，但代码必须被设计和可能被优化。每个假设都必须在尽可能接近生产环境的环境中进行测试。

然而，在决定顺序处理和并行处理之间可以考虑一些因素：

+   通常情况下，小流在顺序处理时处理速度更快（对于您的环境来说，“小”是通过测试和测量性能来确定的）

+   如果有状态的操作无法用无状态的操作替换，那么必须仔细设计代码以进行并行处理，或者完全避免它。

+   考虑对需要大量计算的程序进行并行处理，但要考虑将部分结果合并为最终结果

# 练习 - 将所有流元素相乘

使用流来将以下列表的所有值相乘：

```java
List<Integer> list = List.of(2, 3, 4);
```

# 答案

```java
int r = list.stream().reduce(1, (x, y) -> x * y);
System.out.println(r);     //prints: 24
```

# 总结

本章介绍了数据流处理的强大概念，并提供了许多函数式编程使用示例。它解释了流是什么，如何处理它们以及如何构建处理管道。它还演示了如何可以并行组织流处理以及一些可能的陷阱。

在下一章中，我们将讨论反应式系统，它们的优势以及可能的实现。您将了解异步非阻塞处理、反应式编程和微服务，所有这些都有代码示例，演示了这些反应式系统所基于的主要原则。
