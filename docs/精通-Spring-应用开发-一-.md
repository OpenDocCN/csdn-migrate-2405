# 精通 Spring 应用开发（一）

> 原文：[`zh.annas-archive.org/md5/A95A09924E8304BAE696F70C7C92A54C`](https://zh.annas-archive.org/md5/A95A09924E8304BAE696F70C7C92A54C)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

Spring 是一个开源的 Java 应用程序开发框架，用于构建和部署在 JVM 上运行的系统和应用程序。它通过使用模型-视图-控制器范式和依赖注入，使得构建模块化和可测试的 Web 应用程序变得更加高效。它与许多框架（如 Hibernate、MyBatis、Jersey 等）无缝集成，并在使用标准技术（如 JDBC、JPA 和 JMS）时减少样板代码。

本书的目的是教会中级 Spring 开发人员掌握使用高级概念和额外模块来扩展核心框架，从而进行 Java 应用程序开发。这样可以开发更高级、更强大的集成应用程序。

# 本书涵盖的内容

第一章，“Spring 与 Mongo 集成”，演示了 Spring MVC 与 MongoDB 的集成，以及安装 MongoDB 来创建数据库和集合。

第二章，“使用 Spring JMS 进行消息传递”，教你安装 Apache ActiveMQ 和不同类型的消息传递。本章还演示了创建多个队列，并使用 Spring 模板与这些队列进行通信，同时提供了屏幕截图的帮助。

第三章，“使用 Spring Mail 进行邮件发送”，创建了一个邮件服务，并使用 Spring API 进行配置，演示了如何使用 MIME 消息发送带附件的邮件。

第四章，“使用 Spring Batch 进行作业”，说明了如何使用 Spring Batch 读取 XML 文件，以及如何创建基于 Spring 的批处理应用程序来读取 CSV 文件。本章还演示了如何使用 Spring Batch 编写简单的测试用例。

第五章，“Spring 与 FTP 集成”，概述了不同类型的适配器，如入站和出站适配器，以及出站网关及其配置。本章还研究了两个重要的类，FTPSessionFactory 和 FTPsSessionFactory，使用 getter 和 setter。

第六章，“Spring 与 HTTP 集成”，介绍了使用多值映射来填充请求并将映射放入 HTTP 标头的用法。此外，它还提供了关于 HTTP 和 Spring 集成支持的信息，可用于访问 HTTP 方法和请求。

第七章，“Spring 与 Hadoop”，展示了 Spring 如何与 Apache Hadoop 集成，并提供 Map 和 Reduce 过程来搜索和计算数据。本章还讨论了在 Unix 机器上安装 Hadoop 实例以及在 Spring 框架中配置 Hadoop 作业。

第八章，“Spring 与 OSGI”，开发了一个简单的 OSGI 应用程序，并演示了 Spring 动态模块如何支持 OSGI 开发，并减少文件的创建，从而使配置变得更加简单。

第九章，“使用 Spring Boot 引导应用程序”，从设置一个简单的 Spring Boot 项目开始，以及使用 Spring Boot 引导应用程序的过程。本章还介绍了 Spring Boot 如何支持云铁路服务器，并帮助在云上部署应用程序。

第十章，“Spring 缓存”，实现了我们自己的缓存算法，并教你制作一个通用算法。本章还讨论了在 Spring 框架中支持缓存机制的类和接口。

第十一章, *Spring 与 Thymeleaf 集成*，将 Thymeleaf 模板引擎集成到 Spring MVC 应用程序中，并使用 Spring Boot 启动 Spring 与 Thymeleaf 应用程序。

第十二章, *Spring 与 Web 服务集成*，将 JAX_WS 与 Spring Web 服务集成。它演示了如何创建 Spring Web 服务和端点类，通过访问 WSDL URL 来访问 Web 服务。

# 你需要什么来阅读这本书

需要一台安装有 Mac OS、Ubuntu 或 Windows 的计算机。为了构建 Spring 应用程序，你至少需要安装 Java 和 Maven 3。

# 这本书适合谁

如果你是一名有 Spring 应用开发经验的 Java 开发者，那么这本书非常适合你。建议具备良好的 Spring 编程约定和依赖注入的知识，以充分利用本书。

# 约定

在本书中，你会发现许多文本样式，用于区分不同类型的信息。以下是一些样式的示例及其含义的解释。

文本中的代码、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 用户名都显示如下：“我们使用`@Controller`注解来表示`ProductController.java`类是一个控制器类。”

一块代码设置如下：

```java
@Controller
public class ProductController {
  @Autowired
  private ProductRepository respository;
  private List <Product>productList;
  public ProductController() {
    super();
  }
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项将以粗体显示：

```java
public class MailAdvice {
  public void advice (final ProceedingJoinPoint proceedingJoinPoint) {
    new Thread(new Runnable() {
    public void run() {
```

任何命令行的输入或输出都是这样写的：

```java
cd E:\MONGODB\mongo\bin
mongod -dbpath e:\mongodata\db

```

**新术语**和**重要单词**以粗体显示。屏幕上看到的单词，例如菜单或对话框中的单词，会以这种方式出现在文本中：“下一步是创建一个 rest 控制器来发送邮件；为此，请单击**提交**。”

### 注意

警告或重要提示会以这样的方式出现在一个框中。

### 提示

技巧和窍门是这样出现的。


# 第一章：Spring Mongo 集成

MongoDB 是一种流行的 NoSQL 数据库，也是基于文档的。它是使用流行且强大的 C++语言编写的，这使得它成为一种面向文档的数据库。查询也是基于文档的，它还提供了使用 JSON 样式进行存储和检索数据的索引。MongoDB 基于**集合**和**文档**的概念工作。

让我们来看看 MySQL 和 MongoDB 之间的一些术语差异：

| MySQL | MongoDB |
| --- | --- |
| 表 | 集合 |
| 行 | 文档 |
| 列 | 字段 |
| 连接 | 嵌入式文档链接 |

在 MongoDB 中，集合是一组文档。这与 RDBMS 表相同。

在本章中，我们将首先设置 MongoDB NoSQL 数据库，并将集成 Spring 应用程序与 MongoDB 以执行 CRUD 操作。第一个示例演示了更新单个文档值。第二个示例考虑了一个订单用例，其中需要在集合中存储两个文档引用。它演示了使用`objectId`引用引用 MongoDB 的不同文档的灵活性。

只有当应用程序具有大量写操作时，我们才需要使用 NoSQL 数据库。MongoDB 也非常适合云环境，我们可以轻松地复制数据库。

在下一节中，我们将看到如何开始使用 MongoDB，从安装开始，使用 Spring 框架，并集成 MongoDB。为了开始，我们将展示各种用例中的基本**创建、检索、更新和删除**（**CRUD**）操作。

# 安装 MongoDB 并创建数据库

在本节中，我们将安装 MongoDB 并创建一个数据库：

1.  在[`www.mongodb.org/downloads`](http://www.mongodb.org/downloads)下载 MongoDB 数据库。

1.  通过在`bin`文件夹中执行以下命令来配置数据文件夹：

```java
>mongod.exe -dbpath e:\mongodata\db 

```

1.  在另一个命令提示符中启动`mongod.exe`。

1.  执行以下命令：

```java
>show databaseExecute

```

`>show dbs`命令在 MongoDB 中也可以正常工作。

1.  执行以下命令以创建一个名为`eshopdb`的新数据库。

```java
>use new-eshopdb

```

1.  执行`> show dbs`仍然会显示`eshopdb`尚未创建，这是因为它不包含任何集合。一旦添加了集合，我们将在下一步中添加一些集合。

1.  在命令提示符中执行以下代码片段。以下代码片段将向集合中插入示例文档：

```java
db.eshopdb.insert({cust_id:1,name:"kishore",address:"jayangar"})
db.eshopdb.insert({cust_id:2,name:"bapi",address:"HAL Layout"})
db.eshopdb.insert({cust_id:3,name:"srini",address:"abbigere street"})
db.eshopdb.insert({cust_id:4,name:"sangamesha",address: "Kattarigupee layout"})

```

# 为 MongoDB 设置批处理文件

创建批处理文件来启动 MongoDB 总是很容易，最好创建一个脚本文件来启动 Mongo。这样，我们就不会出现配置错误。这也会节省我们很多时间。

1.  创建一个`mongodbstart.bat`文件。

1.  编辑文件并输入以下命令，然后保存：

```java
cd E:\MONGODB\mongo\bin
mongod -dbpath e:\mongodata\db 

```

下次要启动 MongoDB 时，只需单击批处理文件。

## Spring 和 MongoDB 的订单用例

让我们看一下订单用例，以使用 Spring 和 MongoDB 执行简单的 CRUD 操作。我们正在对产品、客户和订单文档执行 CRUD 操作。情景是这样的：客户选择产品并下订单。

以下是订单用例。操作者是应用程序用户，将有以下选项：

+   对产品文档进行 CRUD 操作

+   对客户文档进行 CRUD 操作

+   通过选择产品和客户对订单执行 CRUD 操作

+   在订单文档中保存产品文档对象 ID 和客户文档对象 ID

# 将 Mongo 文档映射到 Spring Bean

Spring 提供了一种简单的方法来映射 Mongo 文档。以下表格描述了 Bean 与 MongoDB 集合的映射：

| Bean | Mongo 集合 |
| --- | --- |
| `Customer.java` | `db.customer.find()` |
| `Order.java` | `db.order.find()` |
| `Product.java` | `db.product.find()` |

# 设置 Spring-MongoDB 项目

我们需要使用 Maven 创建一个简单的 Web 应用程序项目。

1.  在 Maven 命令提示符中执行以下命令：

```java
mvn archetype:generate -DgroupId=com.packtpub.spring -DartifactId=spring-mongo -DarchetypeArtifactId=maven-archetype-webapp

```

1.  创建一个简单的 Maven 项目，使用 web 应用原型。添加最新的 `4.0.2.RELEASE` spring 依赖。

1.  以下是 `pom.xml` 文件的一部分。这些是必须添加到 `pom.xml` 文件中的依赖项。

```java
<!-- Spring dependencies -->
<dependency>
<groupId>org.mongodb</groupId>
<artifactId>mongo-java-driver</artifactId>
<version>2.9.1</version>
</dependency>
<dependency>
<groupId>org.springframework.data</groupId>
<artifactId>spring-data-mongodb</artifactId>
<version>1.2.0.RELEASE</version>
</dependency>
<dependency>
<groupId>org.springframework.data</groupId>
<artifactId>spring-data-mongodb</artifactId>
<version>1.2.0.RELEASE</version>
</dependency>
<dependency>
<groupId>org.springframework</groupId>
<artifactId>spring-core</artifactId>
<version>${spring.version}</}</version>
<scope>runtime</scope>
</dependency>
<dependency>
<groupId>org.springframework</groupId>
<artifactId>spring-context</artifactId>
<version>4.0.2.RELEASE </version>
<scope>runtime</scope>
</dependency>
<dependency>
<groupId>org.springframework</groupId>
<artifactId>spring-context-support</artifactId>
<version>4.0.2.RELEASE </version>
<scope>runtime</scope>
</dependency>
<dependency>
<groupId>org.springframework</groupId>
<artifactId>spring-beans</artifactId>
<version>4.0.2.RELEASE </version>
<scope>runtime</scope>
</dependency>
<dependency>
<groupId>org.springframework</groupId>
<artifactId>spring-web</artifactId>
<version>4.0.2.RELEASE </version>
<scope>runtime</scope>
</dependency>
<dependency>
<groupId>org.springframework</groupId>
<artifactId>spring-webmvc</artifactId>
<version>4.0.2.RELEASE </version>
<scope>runtime</scope>
</dependency>
```

## 应用程序设计

以下表包含用于开发简单 CRUD 应用程序的类。请求从控制器流向模型，然后返回。Repository 类标有 `@Repository` 注解，并使用 `mongoTemplate` 类连接到 MongoDB。

| 控制器 | 模型 | JSP | Bean |
| --- | --- | --- | --- |
| `Customer Controller.java` | `Customer Repository.java` | `customer.jsp``editcutomer.jsp``allcustomers.jsp` | `Customer.java` |
| `Order Controller.java` | `Order Repository.java` | `order.jsp``editorder.jsp``allorders.jsp` | `Order.java` |
| `Product Controller.java` | `Product Repository.java` | `product.jsp``editproduct.jsp``allproducts.jsp` | `Product.java` |

### Spring 与 MongoDB 的应用实现

以下是实现 `Spring4MongoDB_Chapter1` 应用程序的步骤：

1.  创建一个名为 `Spring4MongoDB_Chapter1` 的基于 web 的 Maven 项目。

1.  将项目导入 Eclipse 进行实现。我使用的是 Eclipse Juno。

我们需要创建控制器来映射请求。

控制器请求映射到 `GET` 和 `POST` 方法，如下表所示：

| 请求 | 请求方法 | 模型属性 |
| --- | --- | --- |
| `/product` | `GET` | `productList` |
| `/product/save` | `POST` | `productList` |
| `/product/update` | `POST` | `productList` |
| `/product/geteditproduct` | `GET` | `productAttribute` |
| `/product/deleteproduct` | `GET` | `productAttribute` |
| `/product/getallproducts` | `GET` | `productList` |

以下是 `ProductController.java` 的实现。我们使用 `@Controller` 注解来指示 `ProductController.java` 类是一个控制器类。`@Autowired` 注解将 `ProductRepository` 类与 `ProductController.java` 文件绑定。

`productList` 属性是一个 `Product` 类型的列表，保存要在屏幕上显示的产品。`@PostConstruct` 注解将调用由它装饰的方法。一旦类的构造函数被调用并且所有属性被设置，在调用任何业务方法之前，值得注意的是它只被调用一次。

```java
@Controller
public class ProductController {
  @Autowired
  private ProductRepository respository;
  private List <Product>productList;
  public ProductController() {
    super();
  }
  @PostConstruct
  public void init(){
    this.productList=respository.getAllObjects();
  }
  //to get the list of products
  @RequestMapping(value="/product", method = RequestMethod.GET)
  public String getaddproduct(Model model) {
    model.addAttribute("productList", productList);
    model.addAttribute("productAttribute", new Product());
    return "product";
  }
  //to save the product
  @RequestMapping(value="/product/save", method = RequestMethod.POST)
  public String addproduct(@ModelAttribute Product prod,Model model) {
    if(StringUtils.hasText(prod.getProdid())) {
      respository.updateObject(prod);
    } else {
      respository.saveObject(prod);
    }
    this.productList=respository.getAllObjects();
    model.addAttribute("productList", productList);
    return "product";
  }
  //to update the edited product
  @RequestMapping(value="/product/update", method = RequestMethod.POST)
  public String updatecustomer(@ModelAttribute Product prod,Model model) {
    respository.updateObject(prod);
    this.productList=respository.getAllObjects();
    model.addAttribute("productList", productList);
    return "product";
  }
  //to edit a product based on ID
  @RequestMapping(value = "/product/geteditproduct", method = RequestMethod.GET)
  public String geteditproduct(
  @RequestParam(value = "prodid", required = true) String prodid,
  Model model) {
    model.addAttribute("productList", productList);
    model.addAttribute("productAttribute", respository.getObject(prodid));
    return "editproduct";
  }
  //to delete a product based on ID
  @RequestMapping(value="/product/deleteproduct", method = RequestMethod.GET)
  public String deleteproduct(
  @RequestParam(value = "prodid", required = true) String prodid,Model model) {
    respository.deleteObject(prodid);
    this.productList=respository.getAllObjects();
    model.addAttribute("productList", this.productList);
    return "product";
  }
  //to get all the products
  @RequestMapping(value = "/product/getallproducts", method = RequestMethod.GET)
  public String getallproducts(Model model) {
    this.productList=respository.getAllObjects();
    model.addAttribute("productList", this.productList);
    return "allproducts";
  }
}
```

`Product.java` 文件有一个 `@Document` 注解和一个 `@ID` 注解，它被识别为 MongoDB 集合，将 `Product` 实体映射到 MongoDB 中的产品集合。

```java
@Document
public class Product {
  /*Bean class product with getter and setters*/
  @Id
  private String prodid;
  private Double price;
  private String name;
  public Product() {
    super();
  }
  public String getProdid() {
    return prodid;
  }
  public void setProdid(String prod_id) {
    this.prodid = prod_id;
  }
  public Double getPrice() {
    return price;
  }
  public void setPrice(Double price) {
    this.price = price;
  }
  public String getName() {
    return name;
  }
  public void setName(String name) {
    this.name = name;
  }
}
```

`ProducRepository.java` 文件有 `@Repository` 注解。这是持久层，并告诉 Spring 这个类在数据库上执行操作。连接到 Mongo 在 Mongo 模板中设置。

**ProductRepository.java**

```java
@Repository
public class ProductRepository {
  @Autowired
  MongoTemplate mongoTemplate;
  public void setMongoTemplate(MongoTemplate mongoTemplate) {
    this.mongoTemplate = mongoTemplate;
  }

  public List<Product> getAllObjects() {
    return mongoTemplate.findAll(Product.class);
  }

  /**
  * Saves a {@link Product}.
  */
  public void saveObject(Product Product) {
    Product.setProdid(UUID.randomUUID().toString());
    mongoTemplate.insert(Product);
  }

  /**
  * Gets a {@link Product} for a particular id.
  */
  public Product getObject(String id) {
    return mongoTemplate.findOne(new Query(Criteria.where("_id").is(id)),
    Product.class);
  }

  /**
  * Updates a {@link Product} name for a particular id.
  */
  public void updateObject(Product object) {
    Query query = new Query();
    query.addCriteria(Criteria.where("_id").is(object.getProdid()));
    Product prod_tempObj = mongoTemplate.findOne(query, Product.class);
    System.out.println("cust_tempObj - " + prod_tempObj);
    //modify and update with save()
    prod_tempObj.setName(object.getName());
    prod_tempObj.setPrice(object.getPrice());
    mongoTemplate.save(prod_tempObj);
  }

  /**
  * Delete a {@link Product} for a particular id.
  */
  public void deleteObject(String id) {
    mongoTemplate.remove(new Query(Criteria.where("_id").is(id)),Product.class);
  }

  /**
  * Create a {@link Product} collection if the collection does not already
  * exists
  */
  public void createCollection() {
    if (!mongoTemplate.collectionExists(Product.class)) {
      mongoTemplate.createCollection(Product.class);
    }
  }

  /**
  * Drops the {@link Product} collection if the collection does already exists
  */
  public void dropCollection() {
    if (mongoTemplate.collectionExists(Product.class)) {
      mongoTemplate.dropCollection(Product.class);
    }
  }
}
```

`.jsp` 文件显示可用的产品，并允许用户对 `Product` bean 执行 CRUD 操作。以下截图是使用存储在 MongoDB 中的产品 `ObjectId` 编辑产品信息的输出。

![Spring 与 MongoDB 的应用实现](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr-app-dev/img/7320OS__01_01.jpg)

**Product.jsp 文件**

这个文件作为用户的视图层。它包含产品创建表单，并包括一个列出 MongoDB 中存储的所有产品的文件。

```java
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ taglib uri="http://www.springframework.org/tags/form" prefix="form" %>
<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<title>Register Product</title>
</head>
<body>

<h1>Register Product</h1>
<ul>
<li><a href="/Spring4MongoDB_Chapter1/customer">Customer</a>
</li>
<li>r<a href="/Spring4MongoDB_Chapter1/order">Product</a>
</li></ul>
<form  method="post" action="/Spring4MongoDB_Chapter1/product/save">
  <table>
    <tr>
      <td> Name:</td>
      <td><input type=text name="name"/></td>
    </tr>
    <tr>
      <td>Price</td>
      <td><input type=text name="price"/></td>
    </tr>
      </table>
  <input type="hidden" name="prod_id"  >
  <input type="submit" value="Save" />
</form>
<%@ include file="allproducts.jsp" %>
</body>
</html>
```

如果一切顺利，您应该看到以下屏幕，您可以在其中玩转产品。以下截图是使用 Spring 和 MongoDB 实现的 **注册产品** 和列出产品功能的输出。

![Spring 与 MongoDB 的应用实现](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr-app-dev/img/7320OS__01_02.jpg)

以下的 `dispatcher-servlet.xml` 文件显示了组件扫描和 MongoDB 模板的配置。它还显示了 MongoDB 数据库名称的配置。

**dispatcher-servlet.xml**

```java
<?xml version="1.0" encoding="UTF-8"?>
<beans 

  xsi:schemaLocation="http://www.springframework.org/schema/beans
  http://www.springframework.org/schema/beans/spring-beans-4.0.xsd
  http://www.springframework.org/schema/data/mongo
  http://www.springframework.org/schema/data/mongo/spring-mongo-1.0.xsd

  http://www.springframework.org/schema/context 
  http://www.springframework.org/schema/context/spring-context-4.0.xsd">

  <context:component-scan base-package="com.packt" />

  <!-- Factory bean that creates the Mongo instance -->
    <bean id="mongo" class="org.springframework.data.mongodb.core.MongoFactoryBean">
      <property name="host" value="localhost" />
    </bean>
    <mongo:mongo host="127.0.0.1" port="27017" />
    <mongo:db-factory dbname="eshopdb" />

  <bean id="mongoTemplate" class="org.springframework.data.mongodb.core.MongoTemplate">
    <constructor-arg name="mongoDbFactory" ref="mongoDbFactory" />
  </bean>

  <!-- Use this post processor to translate any MongoExceptions thrown in @Repository annotated classes -->
    <bean class="org.springframework.dao.annotation.PersistenceExceptionTranslationPostProcessor" />
    <bean id="jspViewResolver" class="org.springframework.web.servlet.view.InternalResourceViewResolver"
      p:prefix="/WEB-INF/myviews/"
      p:suffix=".jsp" /> 

</beans>
```

您可以看到`mongoDbFactory` bean 已配置 MongoDB 数据库详细信息。您还会注意到`mongoTemplate`也已配置。`mongoTemplate` bean 的属性是`mongoDbFactory` bean，因此在调用模板时连接会建立。

只需在 MongoDB 数据库中运行以下命令以测试订单用例：

+   `db.order.find()`

+   `db.order.remove()`

### 提示

`RoboMongo`是一个免费工具，类似于`Toad`，用于访问 MongoDB 数据库。

# 订单管理用例

让我们考虑这一部分的一个复杂场景。在我们考虑的用例中，订单用例在类中具有客户和产品对象。当用户下订单时，用户将选择产品和客户。

我们的目标是直接将`customer`和`product`类存储在 MongoDB 的`Order`集合中。让我们首先实现具有 getter 和 setter 的`OrderBean`类。

**Order.java**

```java
package com.packt.bean;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

@Document
public class Order {
  private String order_id;
  private Customer customer;
  private Product product;
  private String date;
  private String order_status;
  private int quantity;

  public Order() {
    super();
  // TODO Auto-generated constructor stub
  }

  @Id
  public String getOrder_id() {
    return order_id;
  }
  public void setOrder_id(String order_id) {
    this.order_id = order_id;
  }

  public String getDate() {
    return date;
  }
  public void setDate(String date) {
    this.date = date;
  }
  public int getQuantity() {
    return quantity;
  }
  public void setQuantity(int quantity) {
    this.quantity = quantity;
  }
  public String getOrder_status() {
    return order_status;
  }
  public void setOrder_status(String order_status) {
    this.order_status = order_status;
  }

  public Customer getCustomer() {
    return customer;
  }
  public void setCustomer(Customer customer) {
    this.customer = customer;
  }
  public Product getProduct() {
    return product;
  }
  public void setProduct(Product product) {
    this.product = product;
  }
}
```

下一步是在`OrderRepository.java`文件中定义方法。

![订单管理用例](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr-app-dev/img/7320OS__01_03.jpg)

以下是`repository`类中`update`和`save`方法的代码片段。

## 创建和插入订单

我们看到更新`Order`方法接受`Order`对象。我们使用`addCriteria()`方法根据对象 ID 获取特定订单。检索到的`Order`对象存储在`temp`对象中。然后根据传递给方法的对象设置值到`temp`对象。然后调用`mongoTemplate.save(Object)`方法来更新保存的对象。

```java
public void updateObject(Order order) {
  Query query = new Query();
  query.addCriteria(Criteria.where("_id").is(order.getOrder_id()));
  Order order_tempObj = mongoTemplate.findOne(query, Order.class);
    order_tempObj.setCustomer(order.getCustomer());
    order_tempObj.setProduct(order.getProduct());
    order_tempObj.setQuantity(order.getQuantity());
    mongoTemplate.save(order_tempObj);
}
```

`saveObject`方法只接受`Order`对象并在保存之前将 ID 设置为`Order`对象。

我们已经看到如何执行更新和插入。调用以下方法保存订单详情。这表明`mongoTemplate`具有`insert()`和`save()`方法。

```java
public void saveObject(Order Order) {
  Order.setOrder_id(UUID.randomUUID().toString());
  mongoTemplate.insert(Order);
}
```

## 控制器处理请求

`controller`类根据用例具有客户存储库和产品存储库的引用。应用程序用户需要选择客户和产品来下订单。

`OrderController`的初始 Skelton 如下所示：

```java
@Controller
public class OrderController {
  @Autowired
  private OrderRepository respository;
  @Autowired
  private CustomerRepository customerRespository;
  @Autowired
  private ProductRepository productRespository;
  private List<Order> orderList;
  private List<Customer> customerList;
  private List<Product> productList;

  public OrderController() {
    super();
  }
}
```

### 在方法级别添加`@Modelattribute`注解

`controller`类用于处理`Order`请求。在方法中添加了`@ModelAttribute`注解。产品列表和客户列表始终作为模型属性可用于控制器。以下是`OrderController`类的代码片段：

```java
@ModelAttribute("orderList")
  public List<Order> populateOrderList() {
    this.orderList = respository.getAllObjects();
    return this.orderList;
  }
  @ModelAttribute("productList")
  public List<Product> populateProductList() {
    this.productList = productRespository.getAllObjects();
    return this.productList;
  }
  @ModelAttribute("customerList")
  public List<Customer> populateCstomerList() {
    this.customerList = customerRespository.getAllObjects();
    return this.customerList;
  }
```

## OrderController 类的 CRUD 操作

这些方法映射到特定请求，`@ModelAttribute("Order")`，以便在 JSP 级别轻松访问订单对象。您可以观察到在方法级别使用`@ModelAttribute`，这将最小化添加`@ModelAttribute`到方法中。

```java
@RequestMapping(value = "/order", method = RequestMethod.GET)
  // request show add order page
  public String addOrder(@ModelAttribute("Order") Order order,Map<String, Object> model) {
    model.put("customerList", customerList);
    model.put("productList", productList);
    return "order";
  }
  @RequestMapping(value = "/order/save", method = RequestMethod.POST)
  // request to insert the record
  public String addorder(@ModelAttribute("Order") Order order,Map<String, Object> model) {
    order.setCustomer(customerRespository.getObject(order.getCustomer().getCust_id()));
    order.setProduct(product_respository.getObject(order.getProduct().getProdid()));
    respository.saveObject(order);
    model.put("customerList", customerList);
    model.put("productList", productList);
    return "order";
  }

  @RequestMapping(value = "/orde`r/update", method = RequestMethod.POST)
  public String updatecustomer(@ModelAttribute("Order") Order order,
    Map<String, Object> model) {
    order.setCustomer(customerRespository.getObject(order.getCustomer().getCust_id()));
    order.setProduct(product_respository.getObject(order.getProduct().getProdid()));
    respository.updateObject(order);
    model.put("customerList", customerList);
    model.put("productList", productList);
    return "order";
  }
  @RequestMapping(value = "/order/geteditorder", method = RequestMethod.GET)
  public String editOrder(@RequestParam(value = "order_id", required = true) String order_id, @ModelAttribute("Order") Order order,Map<String, Object> model) {
    model.put("customerList", customerList);
    model.put("productList", productList);
    model.put("Order",respository.getObject(order_id));
    return "editorder";
  }
  @RequestMapping(value = "/order/deleteorder", method = RequestMethod.GET)
  public String deleteorder(@RequestParam(value = "order_id", required = true) String order_id, @ModelAttribute("Order") Order order,Map<String, Object> model) {
    respository.deleteObject(order_id);
    model.put("customerList", customerList);
    model.put("productList", productList);
    return "order";
  }
}
```

### JSP 文件

`Order.jsp`文件演示了`@ModelAttribute`的用法，它映射到控制器类中定义的模型订单。setter 方法将值设置给对象，从而最小化了编码。这展示了 Spring 中简化编码过程的功能。

**Orders.jsp**

```java
<h1>Orders </h1>
<ul>
<li><a href="/Spring4MongoDB_Chapter1/customer">Customer</a>
</li>
<li>r<a href="/Spring4MongoDB_Chapter1/product">Product</a>
</li></ul>

<form:form action="/Spring4MongoDB_Chapter1/order/save" modelAttribute="Order"> 
  <table>
    <tr>
      <td>Add your Order:</td>
      <td><form:input path="quantity" size="3"/></td>
    </tr>
    <tr>
      <td>Select Product:</td>
      <td> 
        <form:select path="product.prodid">
        <form:option value="" label="--Please Select"/>
        <form:options items="${productList}" itemValue="prodid" itemLabel="name"/>
        </form:select>
      </td>
    </tr>
    <tr>
      <td>Select Customer:</td>
      <td> 
        <form:select path="customer.cust_id">
        <form:option value="" label="--Please Select"/>
        <form:options items="${customerList}" itemValue="cust_id" itemLabel="name"/>
        </form:select>
      </td>
    </tr>
    <tr>
      <td colspan="2" align="center">
        <input type="submit" value="Submit" />	
      </td>
    </tr>
  </table>
</form:form>

<%@ include file="allorders.jsp" %>
</body>
</html>
```

`allorders.jsp`文件显示订单列表并提供编辑选项。使用 MongoDB 使得显示`orderList`更简单。

**Allorders.jsp**

```java
<h1> E-shop Orders</h1>
<table style="border: 1px solid; width: 500px; text-align:center">
  <thead style="background:#fffcc">
    <tr>
      <th>Order Id</th>
      <th>Customer Name</th>
      <th>Customer Address</th>
      <th>Product Address</th>
      <th>Product Price</th>
      <th>Product Quantity</th>
      <th colspan="2"></th>
    </tr>
  </thead>
  <tbody>

  <c:forEach items="${orderList}" var="order">
    <c:url var="editUrl" value="/order/geteditorder?order_id=${order.order_id}" />
    <c:url var="deleteUrl" value="/order/deleteorder?order_id=${order.order_id}" />
    <c:url var="addUrl" value="/order/" />	
    <tr>
    <td><c:out value="${order.order_id}" /></td>
      <td><c:out value="${order.customer.name}" /></td>
      <td><c:out value="${order.customer.address}" /></td>
        <td><c:out value="${order.product.name}" /></td>
        <td><c:out value="${order.product.price}" /></td>
        <td><c:out value="${order.quantity}" /></td>
      <td><a href="${editUrl}">Edit</a></td>
      <td><a href="${deleteUrl}">Delete</a></td>
      <td><a href="${addUrl}">Add</a></td>
    </tr>
  </c:forEach>
  </tbody>
```

以下是添加订单页面的截图：

![JSP files](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr-app-dev/img/7320OS__01_04.jpg)

以下是编辑订单页面的截图：

![JSP files](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr-app-dev/img/7320OS__01_05.jpg)

# 摘要

在本章中，我们学习了如何安装 MongoDB 并创建数据库和集合。在编写本章时，我们使用了最新版本的 Spring。我们还学习了如何将 Spring MVC 与 MongoDB 集成。我们已经构建了 CRUD 操作。我们还看到了诸如`@Repository`、`@Document`和`@Controller`等注解的用法。在下一章中，让我们看看如何使用`jms`模板集成 Spring 消息代理。


# 第二章：使用 Spring JMS 进行消息传递

**Java 消息服务**（**JMS**）是用于在应用程序组件之间或应用程序之间进行通信的 API。消息可以在应用程序和组件之间发送和接收。消息代理就像中间人一样创建、接收、读取和发送消息。消息消费者不需要始终可用以接收消息。消息代理存储消息，可以在需要时读取。

架构师会选择 JMS 来实现松耦合的设计。消息是异步的，它们一到达就被传递，不需要为消息发送请求。它还可以防止冗余，并确保特定消息只传递一次。

# 消息类型

根据需求，有两种选择消息域：

+   点对点消息传递：

+   每条消息只有一个消费者

+   没有时间依赖性

+   发布-订阅消息传递：

+   每条消息有许多消费者

+   消息具有时间依赖性-当应用程序向消息代理发送消息时，消费者需要订阅并保持活动状态以接收消息

## 消息消费者

这些是 JMS API 提供的消息消费方式：

+   消息监听器

+   它们提供了异步消息模型

+   监听器就像事件观察者/监听器；每当有消息可用时，监听器确保它到达目的地

+   监听器将调用`onMessage()`方法

+   `receive()`方法

+   它提供同步消息`model()`

+   消息通过显式调用连接工厂的`receive()`方法来消费

## 消息结构

消息由三部分组成：

+   **头部**：包含有关目的地和时间戳的信息，并且有`messageID`，由`send()`或`publish()`方法设置。

+   **属性**：可以为消息设置一些属性。

+   **主体**：消息主体可以是以下五种类型之一：

+   `TextMessage`：用于发送字符串对象作为消息

+   `ObjectMessage`：用于将可序列化对象作为消息发送

+   `MapMessage`：用于发送具有键值对的映射

+   `BytesMessage`：用于在消息中发送字节

+   `StreamMessage`：用于在消息中发送 I/O 流

## 基于消息的 POJO 和监听器

众所周知，**企业 JavaBean**（**EJB**）提供了一个消息驱动的 bean 来与 EJB 容器进行通信。与此类似，Spring 也提供了消息驱动的 Pojo，它使用消息监听器容器与消息中间件进行通信。

消息监听器容器在消息驱动的 Pojo 和消息提供者之间进行通信。它注册消息，并通过获取和释放消息资源来帮助处理事务和异常处理。

以下是 Spring JMS 包提供的消息监听器容器列表：

+   **简单消息监听器容器**：提供固定数量的 JMS 会话，并且不参与外部管理的事务。

+   **默认消息监听器容器**：参与外部管理的事务，并提供良好的性能。这个监听器容器被广泛使用。

+   **服务器消息监听器容器**：提供基于提供程序的运行时调优，并提供消息会话池并参与事务。

## 开源消息工具

以下是一些可在开源许可下使用的开源消息中间件：

+   Glassfish OpenMQ

+   Apache ActiveMQ

+   JORAM

+   Presumo

# Apache ActiveMQ

Apache ActiveMQ 具有许多功能，使其成为消息传递的选择。最新版本是 5.10。使用 ActiveMQ 的优势如下：

+   它支持 REST API

+   它支持 CXF Web 服务

+   它支持 AJAX 实现

+   它完全支持 Spring 框架

+   它可以与所有主要应用服务器一起使用，如 JBoss、Tomcat、Weblogic 和 Glassfish 服务器

## 设置 ApacheMQ 以进行点对点消息传递

设置 ApacheMQ 的步骤如下：

1.  从[`activemq.apache.org/download.html`](http://activemq.apache.org/download.html)下载最新的`Apache ActiveMQ.zip`。

1.  将 ZIP 文件解压缩到`E:\apachemq\`。

1.  在命令提示符中，转到位置`E:\apachemq\apache-activemq-5.10-SNAPSHOT\bin\win32`，然后单击`apachemq.bat`启动 Apache ActiveMQ。

1.  Apache ActiveMQ 将在 Jetty 服务器上运行，因此可以通过 URL 访问。

1.  点击链接`http://localhost:8161/admin/index.jsp`。

1.  第一次这样做时，会要求您输入凭据；输入`admin/admin`。

1.  在控制台中，您将看到**欢迎**部分和**代理**部分。

1.  **代理**部分提供了有关 Apache 消息代理的以下信息：

+   名称：`localhost`或服务器的名称

+   版本 5.10 快照

+   ID：`ID:BLRLANJANA-55074-1397199950394-0:1`

+   正常运行时间：1 小时 24 分钟

+   存储百分比使用：0

+   内存百分比使用：0

+   临时百分比使用：0

1.  单击**队列**。

1.  在**队列名称**字段中输入`orderQueue`，然后单击**创建**。

## 使用 Spring JmsTemplate 的 ApacheMq 用例

在上一章中，我们演示了使用 MongoDB 进行订单管理。假设从一个应用程序下的订单需要被读取到不同的应用程序并存储在不同的数据库中。

**订单管理消息代理**的设计如下：

![使用 Spring JmsTemplate 的 ApacheMq 用例](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr-app-dev/img/7320OS_02_01.jpg)

让我们使用**消息代理**的相同用例。请求从控制器流出，当用户输入订单详细信息并单击**保存**时，订单 bean 设置在控制器中，控制器将请求发送到 JMS 发送器，即订单发送器。

订单发送者以 map 的形式将消息发送到队列。接收者读取消息并将消息保存到 MongoDB 数据库中。接收者也可以是不同的应用程序；所有应用程序只需要知道队列名称，以防应用程序中配置了多个队列。

## Spring 依赖

使用与第一章相同的源代码，*Spring Mongo Integration*，以及`pom.xml`文件。使用 Spring JMS 依赖项更新`pom.xml`文件。对于本章，我们有 Spring 4.0.3 版本可用，这是迄今为止最新的版本。以下是`Pom.xml`文件的代码：

```java
<project  
  xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/maven-v4_0_0.xsd">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.packt.web</groupId>
  <artifactId>Spring4JMS_Chapter2</artifactId>
  <packaging>war</packaging>
  <version>0.0.1-SNAPSHOT</version>
  <name>Spring4JMS_Chapter2</name>
  <url>http://maven.apache.org</url>
  <properties>
  <spring.version>4.0.3.RELEASE</spring.version>
  </properties>

  <dependencies>

  <!-- Spring JMS dependencies -->
    <dependency>
    <groupId>org.springframework</groupId>
    <artifactId>spring-jms</artifactId>
    <version>${spring.version}</version>
    <scope>runtime</scope>
    </dependency>

    <dependency>
    <groupId>org.apache.activemq</groupId>
    <artifactId>activemq-core</artifactId>
    <version>5.3.1</version>
    <scope>runtime</scope>
    </dependency>
    <dependency>
    <groupId>org.apache.xbean</groupId>
    <artifactId>xbean-spring</artifactId>
    <version>3.5</version>
    <scope>runtime</scope>
    </dependency>
    <dependency>
    <groupId>org.apache.geronimo.specs</groupId>
    <artifactId>geronimo-jms_1.1_spec</artifactId>
    <version>1.1.1</version>
    <scope>runtime</scope>
    </dependency> 
  </dependencies>
  <build>
    <finalName>Spring4JMS_Chapter2</finalName>
  </build>
</project>
```

# 使用 SpringJMS 和 ActiveMQ 实现订单管理消息系统

在前面关于 Apache ActiveMQ 的部分中，我们讨论了创建消息队列所需的步骤，并创建了一个订单队列。现在，让我们从应用程序向队列发送消息。

以下表格描述了集成了 JMS 的应用程序的组件。

请求从 JSP 流向 Spring 控制器，该控制器设置订单 bean 对象并将其发送给`orderSender`（这是一个 JMS 消息发送器类）。该类将订单对象放入队列。

JMS 接收器是从队列中读取消息的类。读取的对象被发送到`OrderRepository`类，这是一个 Mongo Repository 类，并将消息发布到 MongoDB 数据库。

![使用 SpringJMS 和 ActiveMQ 实现订单管理消息系统](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr-app-dev/img/7320OS_02_02.jpg)

以下表格为我们提供了一个关于在 Spring MVC 应用程序中使用 JMS 进行通信的类的概述：

| JSP | 控制器 | Bean | JMS 发送器 | JMS 接收器 | MongoRepository |
| --- | --- | --- | --- | --- | --- |
| `order.jsp``allorders.jsp` | `Order Controller.java` | `Order.java` | `OrderSender` | `OrderReceiver` | `OrderRepository` |

## 配置 dispatcherservlet.xml 以使用 JMS

您可以看到我们在 XML 文件中配置了以下内容：

+   `connectionFactory`：它创建一个`jmsconnection`对象。这个`jmsconnection`对象连接到**消息导向中间件**（**MOM**），即 Apache ActiveMQ。`jmsconnection`对象提供了一个 JMS 会话对象，应用程序使用该对象与 Apache ActiveMQ 交互。代理 URL 提供了有关消息代理接口正在侦听的主机和端口的信息。

+   `destination`：这是应用程序需要通信的队列的名称。

```java
<bean id="destination" class="org.apache.activemq.command.ActiveMQQueue">
  <constructor-arg value="orderQueue"/>
</bean>
```

+   `jmstemplate`：它以目的地和`connectionFactory` bean 作为参数。

```java
  <bean id="jmsTemplate" class="org.springframework.jms.core.JmsTemplate">
    <property name="connectionFactory" ref="connectionFactory" />
    <property name="defaultDestination" ref="destination" />
  </bean>
```

+   `orderSender`：这是使用`jms`模板向队列发送消息的类。

```java
<bean id="orderSender" class="com.packt.jms.OrderSender" />
```

+   `orderReceiver`：这个类从队列中读取消息。它有`connectionFactory`，以便可以连接到 JMS 提供程序来读取消息。

```java
<bean id="orderReceiver" class="com.packt.jms.OrderReceiver" />

<jms:listener-container  connection-factory="connectionFactory">
<jms:listener destination="orderQueue" ref="orderReceiver" method="orderReceived" />
</jms:listener-container>
```

以下是`dispacherservlet.xml`的完整配置。我们将观察到配置文件已更新为`activemq`配置。

**dispatcherservlet.xml**

```java
<?xml version="1.0" encoding="UTF-8"?>
<beans 

  xsi:schemaLocation="http://www.springframework.org/schema/beans 
  http://www.springframework.org/schema/beans/spring-beans-3.2.xsd 
  http://www.springframework.org/schema/data/mongo
  http://www.springframework.org/schema/data/mongo/spring-mongo-1.0.xsd

  http://www.springframework.org/schema/context 
  http://www.springframework.org/schema/context/spring-context-3.2.xsd 
  http://www.springframework.org/schema/jms 
  http://www.springframework.org/schema/jms/spring-jms.xsd
  http://activemq.apache.org/schema/core 
  http://activemq.apache.org/schema/core/activemq-core.xsd">
  <context:component-scan base-package="com.packt" />
    <!-- JMS Active MQQueue configuration -->
    <bean id="connectionFactory" class="org.apache.activemq.ActiveMQConnectionFactory">
    <property name="brokerURL">
      <value>tcp://localhost:61616</value>
    </property>
    </bean>

    <bean id="destination" class="org.apache.activemq.command.ActiveMQQueue">
    <constructor-arg value="orderQueue"/>
    </bean>

    <bean id="jmsTemplate" class="org.springframework.jms.core.JmsTemplate">
    <property name="connectionFactory" ref="connectionFactory" />
    <property name="defaultDestination" ref="destination" />
    </bean>
  <bean id="orderSender" class="com.packt.jms.OrderSender" />
  <bean id="orderReceiver" class="com.packt.jms.OrderReceiver" />
  <jms:listener-container  connection-factory="connectionFactory">
  <jms:listener destination="orderQueue" ref="orderReceiver" method="orderReceived" />
  </jms:listener-container>

  <!-- Factory bean that creates the Mongo instance -->
  <bean id="mongo" class="org.springframework.data.mongodb.core.MongoFactoryBean">
    <property name="host" value="localhost" />
  </bean>
  <mongo:mongo host="127.0.0.1" port="27017" />
  <mongo:db-factory dbname="eshopdb" />

  <bean id="mongoTemplate" class="org.springframework.data.mongodb.core.MongoTemplate">
    <constructor-arg name="mongoDbFactory" ref="mongoDbFactory" />
  </bean>
  <!-- Use this post processor to translate any MongoExceptions thrown in @Repository annotated classes -->
  <bean class="org.springframework.dao.annotation.PersistenceExceptionTranslationPostProcessor" />

    <bean id="jspViewResolver" class="org.springframework.web.servlet.view.InternalResourceViewResolver"
      p:prefix="/WEB-INF/myviews/"
      p:suffix=".jsp" /> 
</beans>
```

**Order.java**

```java
package com.packt.bean;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

@Document
public class Order {
  private String order_id;
  private Customer customer;
  private Product product;
  private String date;
  private String order_status;
  private int quantity;

  public Order() {
    super();
    // TODO Auto-generated constructor stub
  }

  @Id
  public String getOrder_id() {
    return order_id;
  }
  public void setOrder_id(String order_id) {
    this.order_id = order_id;
  }

  public String getDate() {
    return date;
  }
  public void setDate(String date) {
    this.date = date;
  }
  public int getQuantity() {
    return quantity;
  }
  public void setQuantity(int quantity) {
    this.quantity = quantity;
  }
  public String getOrder_status() {
    return order_status;
  }
  public void setOrder_status(String order_status) {
    this.order_status = order_status;
  }

  public Customer getCustomer() {
    return customer;
  }
  public void setCustomer(Customer customer) {
    this.customer = customer;
  }
  public Product getProduct() {
    return product;
  }
  public void setProduct(Product product) {
    this.product = product;
  }
}
```

`OrderController`类调用发送器将订单发送到消息代理队列。控制器使用 MongoDB 执行一些基本的 CRUD 操作。以下代码仅演示了`Create`操作。

当调用`/order/save`时，控制器将订单对象发送到`orderSender`，后者将订单详细信息保存在队列中。

OrderCOntroller.java

```java
Order details is saved with JMS.The Order Object is passed to orderSender, which will store the order details in the queue.
@RequestMapping(value = "/order/save", method = RequestMethod.POST)
  // request insert order recordhrecord
  public String addorder(@ModelAttribute("Order") Order order,Map<String, Object> model) {
    orderSender.sendOrder(order);
    model.put("customerList", customerList);
    model.put("productList", productList);
    return "order";
  }
```

让我们来看看 JMS 发送器和接收器类。这两个类都使用 Spring JMS 模板来接收和发送消息。`org.springframework.jms.core.MessageCreator`类创建要放入队列中的消息。

以下是`orderSender`的代码，它获取需要传递到队列的对象。`JMSTemplate`准备消息格式，以便它可以被队列接受。

**OrderSender**

```java
package com.packt.jms;

import javax.jms.JMSException;
import javax.jms.MapMessage;
import javax.jms.Message;
import javax.jms.Session;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jms.core.JmsTemplate;
import org.springframework.jms.core.MessageCreator;
import com.packt.bean.Order;

public class OrderSender {

  @Autowired
  private JmsTemplate jmsTemplate;
  public void sendOrder(final Order order){
    jmsTemplate.send(
    new MessageCreator() {
      public Message createMessage(Session session) throws JMSException {
        MapMessage mapMessage = session.createMapMessage();
        mapMessage.setInt("quantity", order.getQuantity());
        mapMessage.setString("customerId", order.getCustomer().getCust_id());
        mapMessage.setString("productId", order.getProduct().getProdid());
        return mapMessage;

      }
    }
    );
    System.out.println("Order: "+ order);
  }
}
```

以下是在添加订单案例时的屏幕截图：

![配置 dispatcherservlet.xml 以使用 JMS](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr-app-dev/img/7320OS_02_03.jpg)

# 在 ApacheMQ 中使用多个队列

在前面的部分中，我们演示了使用 Map Message 将消息发送到 Order Queue。现在，我们可以看看如何在 ApacheMQ 中使用多个队列：

1.  启动 Apache ActiveMQ 服务器，在控制台上点击**Queues**并创建两个队列。

1.  让我们创建两个队列，并将队列命名如下：

+   `PacktTestQueue1`

+   `PacktTestQueue2`

![在 ApacheMQ 中使用多个队列](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr-app-dev/img/7320OS_02_04.jpg)

1.  使用与本章第一个示例相同的依赖项创建一个新的 Spring 项目。

1.  创建一个`PacktMessageListener`类，实现`MessageListener`接口。该类覆盖`onMessage(Message message)`方法。

1.  Spring 的`DefaultMessageListener`从队列中消费消息并调用`onMessage(Message message)`方法。

```java
PacktMessageListener:
package com.packt.jms;

import javax.jms.JMSException;
import javax.jms.Message;
import javax.jms.MessageListener;
import javax.jms.TextMessage;

public class  PacktMessageListener implements MessageListener{
  private PacktMessageSender packtmessagesender;
  public void onMessage(Message message){
    if (message instanceof TextMessage){
      try{
        String msgText = ((TextMessage) message).getText();
        packtmessagesender.sendMessage(msgText);
      }
      catch (JMSException jmsexception){
        System.out.println(jmsexception.getMessage());
      }
    }
    else{
      throw new RuntimeException("exception runtime");  
    }
  }

  public void setTestMessageSender(PacktMessageSender packtmessagesender){
    this.packtmessagesender = packtmessagesender;
  }
}
```

1.  现在让我们来看看消息发送器类，它使用`JmsTemplate`将文本消息发送到队列。

在这里，我们为`JmsTemplate`对象和`queue`对象提供了 setter，并定义了一个发送消息的方法。该类已在 XML 文件中进行了配置。

**PacktMessageSender**

```java
package com.packt.jms;
import javax.jms.MessageListener;
import javax.jms.Queue;
import org.springframework.jms.core.JmsTemplate;

public class PacktMessageSender {
  private JmsTemplate jmsTemplate;
  private Queue queue;
  public void setJmsTemplate(JmsTemplate jmsTemplate){
    this.jmsTemplate = jmsTemplate;
  }
  public void setQueue(Queue queue) {
    this.queue = queue;
  }
  public void sendMessage(String msgText) {
  jmsTemplate.convertAndSend(queue, msgText);
  }
}
```

1.  让我们首先在`meta-inf`文件夹下的`context.xml`文件中创建资源引用。这是我们将为 JMS 配置**Java 命名和目录接口**（**JNDI**）的地方。

```java
<?xml version="1.0" encoding="UTF-8"?>
<Context>
<!—connection factory details-->
<Resource name="jms/mqConnectionFactory" auth="Container" type="org.apache.activemq.ActiveMQConnectionFactory" description="JMS Connection Factory" factory="org.apache.activemq.jndi.JNDIReferenceFactory" brokerURL="tcp://localhost:61616" />

<!—queue details-->

<Resource name="jms/PacktTestQueue1" auth="Container" type="org.apache.activemq.command.ActiveMQQueue" factory="org.apache.activemq.jndi.JNDIReferenceFactory" physicalName="PacktTestQueue1"/>

<!—queue details-->

<Resource name="jms/PacktTestQueue2" auth="Container" type="org.apache.activemq.command.ActiveMQQueue" factory="org.apache.activemq.jndi.JNDIReferenceFactory" physicalName="PacktTestQueue2"/>
</Context>
```

1.  以下是在`spring-configuration.xml`文件中需要进行的配置更改，以配置多个队列：

+   使用 Spring JNDI 查找`queueNames`和 JMS`connectionFactory`

+   将`ConnectionFactory`引用传递给`JmsTemplate`

+   配置`MessageSender`和`MessageListener`类

+   `MessageSender`类将具有`JmsTemplate`和`queue`对象作为属性

+   `MessageListener`将具有`MessageSender`作为属性

+   配置`DefaultMessageListenerContainer`类，该类从队列中消费消息

1.  以下是配置文件的代码：

**Spring-configuration.xml**

```java
<?xml version="1.0" encoding="UTF-8"?>
<beans 

  xsi:schemaLocation="http://www.springframework.org/schema/beans
  http://www.springframework.org/schema/beans/spring-beans-4.0.xsd
  http://www.springframework.org/schema/context
  http://www.springframework.org/schema/context/spring-context-4.0.xsd
  http://www.springframework.org/schema/beans
  http://www.springframework.org/schema/beans/spring-beans-4.0.xsd
  http://www.springframework.org/schema/jee
  http://www.springframework.org/schema/jee/spring-jee-4.0.xsd">

  <jee:jndi-lookup id="apachemqConnectionFactory" jndi-name="java:comp/env/jms/mqConnectionFactory" />
  <jee:jndi-lookup id="PacktTestQueue1" jndi-name="java:comp/env/jms/PacktTestQueue1" />
  <jee:jndi-lookup id="PacktTestQueue2" jndi-name="java:comp/env/jms/PacktTestQueue2" />

  <bean id="packtMessageListener" class="com.packt.jms.PacktMessageListener">
    <property name="packtMessageSender" ref ="packtMessageSender" />
  </bean>

  <bean id="defaultMessageListenerContainer" class="org.springframework.jms.listener.DefaultMessageListenerContainer">
    <property name="connectionFactory" ref ="apachemqConnectionFactory" />
    <property name="destination" ref ="PacktTestQueue1"/>
    <property name="messageListener" ref ="packtMessageListener"/>
    <property name="concurrentConsumers" value="2" />
  </bean>

  <bean id="packtMessageSender" class="com.packt.jms.PacktMessageSender">
    <property name="jmsTemplate" ref="jmsTemplate"/>
    <property name="queue" ref="PacktTestQueue2"/>
  </bean>

  <bean id="jmsTemplate" class="org.springframework.jms.core.JmsTemplate">
    <property name="connectionFactory" ref="apachemqConnectionFactory" />
  </bean>

</beans>
```

1.  以下代码将配置`web.xml`文件。在`web.xml`中，我们实际上提供了关于`spring-configuration.xml`文件位置的信息，以便 Web 容器可以加载它。

```java
<?xml version="1.0" encoding="UTF-8"?>
<web-app 

  xsi:schemaLocation="http://java.sun.com/xml/ns/javaee
  http://java.sun.com/xml/ns/javaee/web-app_2_5.xsd"
  id="WebApp_ID"
  version="2.5">
  <context-param>
    <param-name>contextConfigLocation</param-name>
    <param-value>
      /WEB-INF/configuration/spring-configuration.xml
    </param-value>
  </context-param>
  <listener>
    <listener-class>org.springframework.web.context.ContextLoaderListener</listener-class>
  </listener>
</web-app>
```

1.  如果您使用 Maven 作为构建工具，请确保编译源代码并在 Tomcat 或其他您选择的服务器上运行应用程序。同时保持 Apache ActiveMQ 服务器控制台处于运行状态。

1.  在 ActiveMQ 控制台中，点击**队列**。

1.  点击**发送**按钮以链接到`PacktTestQueue1`行。![在 ApacheMQ 中使用多个队列](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr-app-dev/img/7320OS_02_05.jpg)

1.  输入一些消息文本，然后点击**发送**按钮。

1.  在控制台中，您会看到从队列 1 发送了一条消息到队列 2。我们的应用程序从`PacktTestQueue1`消费消息并将其推送到`PacktTestQueue2`。![在 ApacheMQ 中使用多个队列](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr-app-dev/img/7320OS_02_06.jpg)

1.  现在，让我们增加要发送的消息数量，看看它的行为。![在 ApacheMQ 中使用多个队列](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr-app-dev/img/7320OS_02_07.jpg)

1.  点击**PacktTestQueue2**，您将看到所有消息都被推送到`PacktTestQueue2`。![在 ApacheMQ 中使用多个队列](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr-app-dev/img/7320OS_02_08.jpg)

## 配置 JMS 事务

当我们使用事务时，我们可以更好地处理前面的情景。消息将在事务中处理，在监听器中出现异常的情况下，将为完整的源代码回滚。参考`repository-Spring4JMS_TransactionChapter2`中的源代码。

包括事务在消息传递中需要以下步骤：

1.  将以下属性添加到 ActiveMQ 连接工厂 bean 配置中：

```java
<property name="redeliveryPolicy">
  <bean class="org.apache.activemq.RedeliveryPolicy">
<property name="maximumRedeliveries" value="3"/>
  </bean>
</property>
```

1.  更新监听器定义如下：

```java
<jms:listener-container connection-factory="connectionFactory" acknowledge="transacted">
  <jms:listener destination="orderQueue" ref="orderReceiver" method="orderReceived" />
</jms:listener-container>
```

让我们重新审视情景，了解在`jmsTemplate`中添加事务后发生了什么：

+   **场景 1**：成功场景

+   **场景 2**：消息生产者向队列发送信息，消费者读取并将其处理到数据库中；然后出现错误。![配置 JMS 事务](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr-app-dev/img/B02116_02_09.jpg)

添加事务后，代理将三次发送消息。在第四次尝试时，它将发送到新队列，以便消息不会丢失。

+   **场景 3**：消息生产者向队列发送信息，消费者读取并将其处理到数据库中；然后出现错误。![配置 JMS 事务](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr-app-dev/img/B02116_02_10.jpg)

添加事务后，如果在完成处理之前监听器执行失败，消息代理将重新发送信息。

## 配置多个 JMS 监听器和适配器

我们可能会遇到需要有更多 JMS 监听器和适配器的情况。当我们需要使用 Spring 模板轻松处理多个队列时，我们可以配置多个监听器。为了处理多个监听器，我们还需要适配器，它将委托给不同的监听器。

```java
<bean id="jmsMessageAdapter" class="org.springframework.jms.listener.adapter.MessageListenerAdapter">
<property name="delegate" ref="jmsMessageReceiverDelegate" />
<property name="defaultListenerMethod" value="processMessage" />
</bean>

<jms:listener-container container-type="default"
  connection-factory="connectionFactory" acknowledge="auto"> 
<jms:listener destination="queue1"
  ref="jmsMessageReceiverDelegate" method="processMessage" /> 
<jms:listener destination="queue2"
  ref="jmsMessageReceiverDelegate" method="processMessage" /> 
</jms:listener-container>
```

# JMS 事务

在本节中，让我们看看如何在消息传递中包含事务。我们将首先演示不使用事务的消息传递，使用几种情景。我们将首先描述情景并编写一个测试用例。然后，我们将围绕它开发一个应用程序。我们将演示使用`convertandsendmessage()`方法发送消息。

+   **场景 1**：这是一个正面的用例，在之前的部分中我们也看到了。![JMS 事务](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr-app-dev/img/B02116_02_11.jpg)

```java
@Test
public void testCorrectMessage() throws InterruptedException {
  Order order = new Order(0, "notification to deliver correctly");
  ordersender.convertAndSendMessage(QUEUE_INCOMING, order);

  Thread.sleep(6000);
  printResults();

  assertEquals(1, getSavedOrders());
  assertEquals(0, getMessagesInQueue(QUEUE_INCOMING));
  assertEquals(0, getMessagesInQueue(QUEUE_DLQ));
}
```

+   **场景 2**：在这里，让我们使用一个负面情景。消息生产者向队列发送信息，消费者读取，但在到达数据库之前发生异常。![JMS 事务](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr-app-dev/img/B02116_02_12.jpg)

```java
@Test
public void testFailedAfterReceiveMessage() throws InterruptedException {
  Order order = new Order(1, "ordernotification to fail after receiving");
  ordersender.convertAndSendMessage(QUEUE_INCOMING, order);
  Thread.sleep(6000);
  printResults();
  assertEquals(0, getSavedOrders());
  assertEquals(0, getMessagesInQueue(QUEUE_INCOMING));
  assertEquals(1, getMessagesInQueue(QUEUE_DLQ));
  //Empty the dead letter queue
  jmsTemplate.receive(QUEUE_DLQ);
}
```

在这种情况下，我们丢失了消息。

+   **场景 3**：在这里，让我们使用另一个负面情景。消息生产者向队列发送信息，消费者读取并将其处理到数据库中；然后出现错误。![JMS 事务](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr-app-dev/img/B02116_02_13.jpg)

```java
@Test
public void testFailedAfterProcessingMessage() throws InterruptedException {
  Order order = new Order(2, "ordernotification to fail after processing");
  ordersender.convertAndSendMessage(QUEUE_INCOMING, order);
  Thread.sleep(6000);
  printResults();
  assertEquals(2, getSavedOrders());
  assertEquals(0, getMessagesInQueue(QUEUE_INCOMING));
  assertEquals(0, getMessagesInQueue(QUEUE_DLQ));
}
```

消息在失败之前被传递并存储在数据库中。

# 摘要

在本章中，我们学习了安装 Apache ActiveMQ 和不同类型的消息传递所需的步骤。我们演示了如何将 Spring 的`jms`模板与应用程序集成。我们还通过截图演示了如何创建多个队列以及如何使用 Spring 模板与队列进行通信。在下一章中，我们将研究 Spring JAVA 邮件 API。


# 第三章：使用 Spring 邮件发送邮件

邮件 API 是所有现代 Web 应用的一部分。最终用户更喜欢通过邮件收到有关与应用程序执行的交易的详细信息。

Spring 已经让为任何 Java 应用程序提供邮件功能变得更加容易。在本章中，我们将看到如何使用 Spring 邮件模板向电子邮件接收者发送电子邮件。在上一章中，我们使用消息作为中间件将消息存储在队列中，现在在本章中，我们将演示使用不同场景下的 Spring 邮件模板配置。

# Spring 邮件消息处理流程

以下图表描述了 Spring 邮件消息处理的流程。通过这个图表，我们可以清楚地了解使用 Spring 邮件模板发送邮件的过程。

创建并发送消息到与互联网协议交互的传输协议，然后消息被接收者接收。

![Spring 邮件消息处理流程](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr-app-dev/img/7320OS_03_01.jpg)

Spring 邮件框架需要邮件配置或 SMTP 配置作为输入，以及需要发送的消息。邮件 API 与互联网协议交互以发送消息。在下一节中，我们将看一下 Spring 邮件框架中的类和接口。

# 使用 Spring 发送邮件的接口和类

`org.springframework.mail`包用于 Spring 应用程序中的邮件配置。

![使用 Spring 发送邮件的接口和类](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr-app-dev/img/7320OS_03_02.jpg)

以下是用于发送邮件的三个主要接口：

+   `MailSender`：这个接口用于发送简单的邮件消息。

+   `JavaMailSender`：这个接口是`MailSender`接口的子接口，支持发送邮件消息。

+   `MimeMessagePreparator`：这个接口是一个回调接口，支持`JavaMailSender`接口准备邮件消息。

以下类用于使用 Spring 发送邮件：

+   `SimpleMailMessage`：这是一个类，具有`to`、`from`、`cc`、`bcc`、`sentDate`等属性。`SimpleMailMessage`接口使用`MailSenderImp`类发送邮件。![使用 Spring 发送邮件的接口和类](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr-app-dev/img/7320OS_03_03.jpg)

+   `JavaMailSenderImpl`：这个类是`JavaMailSender`接口的实现类。![使用 Spring 发送邮件的接口和类](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr-app-dev/img/7320OS_03_04.jpg)

+   `MimeMessageHelper`：这个类帮助准备 MIME 消息。

# 使用@Configuration 注解发送邮件

我们将在这里演示如何使用 Spring 邮件 API 发送邮件。

1.  首先，我们在`.properties`文件中提供所有 SMTP 详细信息，并使用`@Configuration`注解将其读取到类文件中。类的名称是`MailConfiguration`。

`mail.properties`文件内容如下：

```java
mail.protocol=smtp
mail.host=localhost
mail.port=25
mail.smtp.auth=false
mail.smtp.starttls.enable=false
mail.from=me@localhost
mail.username=
mail.password=

@Configuration
@PropertySource("classpath:mail.properties")
public class MailConfiguration {
  @Value("${mail.protocol}")
  private String protocol;
  @Value("${mail.host}")
  private String host;
  @Value("${mail.port}")
  private int port;
  @Value("${mail.smtp.auth}")
  private boolean auth;
  @Value("${mail.smtp.starttls.enable}")
  private boolean starttls;
  @Value("${mail.from}")
  private String from;
  @Value("${mail.username}")
  private String username;
  @Value("${mail.password}")
  private String password;

  @Bean
  public JavaMailSender javaMailSender() {
    JavaMailSenderImpl mailSender = new JavaMailSenderImpl();
    Properties mailProperties = new Properties();
    mailProperties.put("mail.smtp.auth", auth);
    mailProperties.put("mail.smtp.starttls.enable", starttls);
    mailSender.setJavaMailProperties(mailProperties);
    mailSender.setHost(host);
    mailSender.setPort(port);
    mailSender.setProtocol(protocol);
    mailSender.setUsername(username);
    mailSender.setPassword(password);
    return mailSender;
  }
}
```

1.  下一步是创建一个 REST 控制器来发送邮件；为此，请单击**提交**。我们将使用`SimpleMailMessage`接口，因为我们没有任何附件。

```java
@RestController
class MailSendingController {
  private final JavaMailSender javaMailSender;
  @Autowired
  MailSubmissionController(JavaMailSender javaMailSender) {
    this.javaMailSender = javaMailSender;
  }
  @RequestMapping("/mail")
  @ResponseStatus(HttpStatus.CREATED)
  SimpleMailMessage send() { 
    SimpleMailMessage mailMessage = new SimpleMailMessage();
    mailMessage.setTo("packt@localhost");
    mailMessage.setReplyTo("anjana@localhost");
    mailMessage.setFrom("Sonali@localhost");
    mailMessage.setSubject("Vani veena Pani");
    mailMessage.setText("MuthuLakshmi how are you?Call Me Please [...]");
    javaMailSender.send(mailMessage);
    return mailMessage;
  }
}
```

# 使用 MailSender 和 SimpleMailMessage 以及 XML 配置发送邮件

“简单邮件消息”意味着发送的电子邮件只是基于文本，没有 HTML 格式，没有图像，也没有附件。在本节中，考虑一个场景，即在用户在应用程序中下订单后，我们会向用户发送欢迎邮件。在这种情况下，邮件将在数据库插入操作成功后发送。

为邮件服务创建一个名为`com.packt.mailService`的单独文件夹。以下是使用`MailSender`接口和`SimpleMailMessage`类发送邮件的步骤。

1.  创建一个名为`Spring4MongoDB_MailChapter3`的新 Maven Web 项目。

1.  本例中使用了第一章中创建的 MongoDB 数据库，*Spring Mongo Integration*。我们还在 MongoDB 的 Eshop db 数据库上使用了相同的 CRUD 操作`Customer`、`Order`和`Product`。我们还使用了相同的`mvc`配置和源文件。

1.  使用与第二章中使用的相同的依赖项，*Spring JMS 消息*。

1.  我们需要在`pom.xml`文件中添加依赖项：

```java
<dependency>
  <groupId>org.springframework.integration</groupId>
  <artifactId>spring-integration-mail</artifactId>
  <version>3.0.2.RELEASE</version>
  <scope>runtime</scope>
</dependency>
<dependency>
  <groupId>javax.activation</groupId>
  <artifactId>activation</artifactId>
  <version>1.1-rev-1</version>
  <scope>runtime</scope>
</dependency>
<dependency>
  <groupId>javax.mail</groupId>
  <artifactId>mail</artifactId>
  <version>1.4.3</version>
</dependency>

```

1.  编译 Maven 项目。为邮件服务创建一个名为`com.packt.mailService`的单独文件夹。

1.  创建一个名为`MailSenderService`的简单类，并自动装配`MailSender`和`SimpleMailMessage`类。基本框架如下所示：

```java
public class MailSenderService {
  @Autowired
  private MailSender mailSender;
  @AutoWired 
  private SimpleMailMessage simplemailmessage;
  public void sendmail(String from, String to, String subject, String body){
    /*Code */
  }

}
```

1.  接下来，创建一个`SimpleMailMessage`对象，并设置邮件属性，如`from`、`to`和`subject`。

```java
public void sendmail(String from, String to, String subject, String body){
  SimpleMailMessage message=new SimpleMailMessage();
  message.setFrom(from);
  message.setSubject(subject);
  message.setText(body);
  mailSender.send(message);
}
```

1.  我们需要配置 SMTP 详细信息。Spring 邮件支持提供了在 XML 文件中配置 SMTP 详细信息的灵活性。

```java
<bean id="mailSender" class="org.springframework.mail.javamail.JavaMailSenderImpl">
  <property name="host" value="smtp.gmail.com" />
  <property name="port" value="587" />
  <property name="username" value="username" />
  <property name="password" value="password" />

  <property name="javaMailProperties">
  <props>
    <prop key="mail.smtp.auth">true</prop>
    <prop key="mail.smtp.starttls.enable">true</prop>
  </props>
</property>
</bean>

<bean id="mailSenderService" class=" com.packt.mailserviceMailSenderService ">
  <property name="mailSender" ref="mailSender" />
</bean>

</beans>
```

在订单成功在 MongoDB 数据库中放置后，我们需要向客户发送邮件。更新`addorder()`方法如下：

```java
@RequestMapping(value = "/order/save", method = RequestMethod.POST)
  // request insert order recordh
  public String addorder(@ModelAttribute("Order") Order order,Map<String, Object> model) {
    Customer cust=new Customer();
    cust=customer_respository.getObject(order.getCustomer().getCust_id());

    order.setCustomer(cust);
    order.setProduct(product_respository.getObject(order.getProduct().getProdid()));
    respository.saveObject(order);
    mailSenderService.sendmail("anjana.mprasad@gmail.com",cust.getEmail(),
      "Dear"+cust.getName()+"Your order details",order.getProduct().getName()+"-price-"+order.getProduct().getPrice());
    model.put("customerList", customerList);
    model.put("productList", productList);
    return "order";
  }
```

## 向多个收件人发送邮件

如果您想通知用户应用程序中的最新产品或促销活动，可以创建一个邮件发送组，并使用 Spring 邮件发送支持向多个收件人发送邮件。

我们在同一个类`MailSenderService`中创建了一个重载方法，它将接受字符串数组。类中的代码片段将如下所示：

```java
public class MailSenderService {
  @Autowired
  private MailSender mailSender;
  @AutoWired 
  private SimpleMailMessage simplemailmessage;
  public void sendmail(String from, String to, String subject, String body){
    /*Code */
  }

  public void sendmail(String from, String []to, String subject, String body){
    /*Code */
  }

}
```

以下是从 MongoDB 中列出已订阅促销邮件的用户集合的代码片段：

```java
  public List<Customer> getAllObjectsby_emailsubscription(String status) {
    return mongoTemplate.find(query(where("email_subscribe").is("yes")), Customer.class);
  }
```

# 发送 MIME 消息

**多用途互联网邮件扩展**（**MIME**）允许在互联网上发送附件。如果您不发送任何附件，使用 MIME 消息发送器类型类是不可取的。在下一节中，我们将详细了解如何发送带附件的邮件。

使用 MIME 消息准备程序并重写准备`method()`以设置邮件属性来更新`MailSenderService`类。

```java
public class MailSenderService {
  @Autowired
  private MailSender mailSender;
  @AutoWired 
  private SimpleMailMessage simplemailmessage;

  public void sendmail(String from, String to, String subject, String body){
    /*Code */
  }
  public void sendmail(String from, String []to, String subject, String body){
    /*Code */
  }
  public void sendmime_mail(final String from, final String to, final String subject, final String body) throws MailException{
    MimeMessagePreparator message = new MimeMessagePreparator() {
      public void prepare(MimeMessage mimeMessage) throws Exception {
        mimeMessage.setRecipient(Message.RecipientType.TO,new InternetAddress(to));
        mimeMessage.setFrom(new InternetAddress(from));
        mimeMessage.setSubject(subject);
        mimeMessage.setText(msg);
    }
  };
  mailSender.send(message);
}
```

# 发送邮件附件

我们还可以在邮件中附加各种类型的文件。这个功能由`MimeMessageHelper`类支持。如果您只想发送一个没有附件的 MIME 消息，可以选择`MimeMesagePreparator`。如果要求附件与邮件一起发送，我们可以选择带有文件 API 的`MimeMessageHelper`类。

Spring 提供了一个名为`org.springframework.core.io.FileSystemResource`的文件类，它具有一个接受文件对象的参数化构造函数。

```java
public class SendMailwithAttachment {
  public static void main(String[] args) throws MessagingException {
    AnnotationConfigApplicationContext ctx = new AnnotationConfigApplicationContext();
    ctx.register(AppConfig.class);
    ctx.refresh();
    JavaMailSenderImpl mailSender = ctx.getBean(JavaMailSenderImpl.class);
    MimeMessage mimeMessage = mailSender.createMimeMessage();
    //Pass true flag for multipart message
    MimeMessageHelper mailMsg = new MimeMessageHelper(mimeMessage, true);
    mailMsg.setFrom("ANJUANJU02@gmail.com");
    mailMsg.setTo("RAGHY03@gmail.com");
    mailMsg.setSubject("Test mail with Attachment");
    mailMsg.setText("Please find Attachment.");
    //FileSystemResource object for Attachment
    FileSystemResource file = new FileSystemResource(new File("D:/cp/ GODGOD. jpg"));
    mailMsg.addAttachment("GODGOD.jpg", file);
    mailSender.send(mimeMessage);
    System.out.println("---Done---");
  }

}
```

# 发送预配置的邮件

在这个例子中，我们将提供一条要发送的邮件，并在 XML 文件中进行配置。有时在 Web 应用程序中，您可能需要在维护时发送消息。想象一下邮件内容发生变化，但发件人和收件人是预先配置的情况。在这种情况下，您可以向`MailSender`类添加另一个重载方法。

我们已经固定了邮件的主题，内容可以由用户发送。可以将其视为“一个应用程序，每当构建失败时向用户发送邮件”。

```java
<?xml version="1.0" encoding="UTF-8"?>
<beans    xsi:schemaLocation="http://www.springframework.org/schema/beans
http://www.springframework.org/schema/beans/spring-beans-3.0.xsd
http://www.springframework.org/schema/context
http://www.springframework.org/schema/context/spring-context-3.0.xsd">
<context:component-scan base-package="com.packt" />
<!-- SET default mail properties -->
<bean id="mailSender" class="org.springframework.mail.javamail.JavaMailSenderImpl">
  <property name="host" value="smtp.gmail.com"/>
  <property name="port" value="25"/>
  <property name="username" value="anju@gmail.com"/>
  <property name="password" value="password"/>
  <property name="javaMailProperties">
  <props>
    <prop key="mail.transport.protocol">smtp</prop>
    <prop key="mail.smtp.auth">true</prop>
    <prop key="mail.smtp.starttls.enable">true</prop>
    <prop key="mail.debug">true</prop>
  </props>
  </property>
</bean>

<!-- You can have some pre-configured messagess also which are ready to send -->
<bean id="preConfiguredMessage" class="org.springframework.mail.SimpleMailMessage">
  <property name="to" value="packt@gmail.com"></property>
  <property name="from" value="anju@gmail.com"></property>
  <property name="subject" value="FATAL ERROR- APPLICATION AUTO MAINTENANCE STARTED-BUILD FAILED!!"/>
</bean>
</beans>
```

现在我们将为主题发送两个不同的正文。

```java
public class MyMailer {
  public static void main(String[] args){
    try{
      //Create the application context
      ApplicationContext context = new FileSystemXmlApplicationContext("application-context.xml");
        //Get the mailer instance
      ApplicationMailer mailer = (ApplicationMailer) context.getBean("mailService");
      //Send a composed mail
      mailer.sendMail("nikhil@gmail.com", "Test Subject", "Testing body");
    }catch(Exception e){
      //Send a pre-configured mail
      mailer.sendPreConfiguredMail("build failed exception occured check console or logs"+e.getMessage());
    }
  }
}
```

# 使用 Spring 模板和 Velocity 发送 HTML 邮件

Velocity 是 Apache 提供的模板语言。它可以很容易地集成到 Spring 视图层中。本书中使用的最新 Velocity 版本是 1.7。在前一节中，我们演示了如何使用`@Bean`和`@Configuration`注解来使用 Velocity 发送电子邮件。在本节中，我们将看到如何配置 Velocity 以使用 XML 配置发送邮件。

需要做的就是将以下 bean 定义添加到`.xml`文件中。在`mvc`的情况下，可以将其添加到`dispatcher-servlet.xml`文件中。

```java
<bean id="velocityEngine" class="org.springframework.ui.velocity.VelocityEngineFactoryBean">
  <property name="velocityProperties">
  <value>
    resource.loader=class    class.resource.loader.class=org.apache.velocity.runtime.resource.loader.ClasspathResourceLoader
  </value>
  </property>
</bean>
```

1.  创建一个名为`Spring4MongoDB_Mail_VelocityChapter3`的新的 Maven web 项目。

1.  创建一个名为`com.packt.velocity.templates`的包。

1.  创建一个名为`orderconfirmation.vm`的文件。

```java
<html>
<body>
<h3> Dear Customer,<h3>
<p>${customer.firstName} ${customer.lastName}</p>
<p>We have dispatched your order at address.</p>
${Customer.address}
</body>
</html>
```

1.  使用我们在前几节中添加的所有依赖项。

1.  向现有的 Maven 项目中添加此依赖项：

```java
<dependency>
  <groupId>org.apache.velocity</groupId>
  <artifactId>velocity</artifactId>
  <version>1.7</version>
</dependency>
```

1.  为了确保 Velocity 在应用程序启动时被加载，我们将创建一个类。让我们把这个类命名为`VelocityConfiguration.java`。我们已经在这个类中使用了注解`@Configuration`和`@Bean`。

```java
import java.io.IOException;
import java.util.Properties;

import org.apache.velocity.app.VelocityEngine;
import org.apache.velocity.exception.VelocityException;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.ui.velocity.VelocityEngineFactory;
@Configuration
public class VelocityConfiguration {
  @Bean
  public VelocityEngine getVelocityEngine() 
  throws VelocityException, IOException{
    VelocityEngineFactory velocityEngineFactory = new VelocityEngineFactory();
    Properties props = new Properties();
    props.put("resource.loader", "class");
    props.put("class.resource.loader.class", "org.apache.velocity.runtime.resource.loader." + "ClasspathResourceLoader");
    velocityEngineFactory.setVelocityProperties(props);
    return factory.createVelocityEngine();
  }
}
```

1.  使用相同的`MailSenderService`类，并在类中添加另一个重载的`sendMail()`方法。

```java
public void sendmail(final Customer customer){
  MimeMessagePreparator preparator = new MimeMessagePreparator() {
    public void prepare(MimeMessage mimeMessage) 
    throws Exception {
      MimeMessageHelper message = new MimeMessageHelper(mimeMessage);
      message.setTo(user.getEmailAddress());
      message.setFrom("webmaster@packt.com"); // could be parameterized
      Map model = new HashMap();
      model.put("customer", customer);
      String text = VelocityEngineUtils.mergeTemplateIntoString(velocityEngine, "com/packt/velocity/templates/orderconfirmation.vm", model);
      message.setText(text, true);
    }
  };
  this.mailSender.send(preparator);
}
```

1.  更新控制器类以使用 Velocity 模板发送邮件。

```java
@RequestMapping(value = "/order/save", method = RequestMethod.POST)
// request insert order recordh
public String addorder(@ModelAttribute("Order") Order order,Map<String, Object> model) {
  Customer cust=new Customer();
  cust=customer_respository.getObject(order.getCustomer().getCust_id());

  order.setCustomer(cust);
  order.setProduct(product_respository.getObject(order.getProduct().getProdid()));
  respository.saveObject(order);
  // to send mail using velocity template.
  mailSenderService.sendmail(cust);

  return "order";
}
```

# 通过不同的线程发送 Spring 邮件

还有其他异步发送 Spring 邮件的选项。一种方法是为邮件发送工作创建一个单独的线程。Spring 带有`taskExecutor`包，它为我们提供了线程池功能。

1.  创建一个名为`MailSenderAsyncService`的类，该类实现`MailSender`接口。

1.  导入`org.springframework.core.task.TaskExecutor`包。

1.  创建一个名为`MailRunnable`的私有类。以下是`MailSenderAsyncService`的完整代码：

```java
public class MailSenderAsyncService implements MailSender{
  @Resource(name = "mailSender")
  private MailSender mailSender;

  private TaskExecutor taskExecutor;

  @Autowired
  public MailSenderAsyncService(TaskExecutor taskExecutor){
    this.taskExecutor = taskExecutor;
  }
  public void send(SimpleMailMessage simpleMessage) throws MailException {
    taskExecutor.execute(new MailRunnable(simpleMessage));
  }

  public void send(SimpleMailMessage[] simpleMessages) throws MailException {
    for (SimpleMailMessage message : simpleMessages) {
      send(message);
    }
  }

  private class SimpleMailMessageRunnable implements Runnable {
    private SimpleMailMessage simpleMailMessage;
    private SimpleMailMessageRunnable(SimpleMailMessage simpleMailMessage) {
      this.simpleMailMessage = simpleMailMessage;
    }

    public void run() {
    mailSender.send(simpleMailMessage);
    }
  }
  private class SimpleMailMessagesRunnable implements Runnable {
    private SimpleMailMessage[] simpleMessages;
    private SimpleMailMessagesRunnable(SimpleMailMessage[] simpleMessages) {
      this.simpleMessages = simpleMessages;
    }

    public void run() {
      mailSender.send(simpleMessages);
    }
  }
}
```

1.  在`.xml`文件中配置`ThreadPool`执行器。

```java
<bean id="taskExecutor" class="org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor" p:corePoolSize="5"
  p:maxPoolSize="10" p:queueCapacity="100" p:waitForTasksToCompleteOnShutdown="true"/>
```

1.  测试源代码。

```java
import javax.annotation.Resource;

import org.springframework.mail.MailSender;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.test.context.ContextConfiguration;

@ContextConfiguration
public class MailSenderAsyncService {
  @Resource(name = " mailSender ")
  private MailSender mailSender;
  public void testSendMails() throws Exception {
    SimpleMailMessage[] mailMessages = new SimpleMailMessage[5];

    for (int i = 0; i < mailMessages.length; i++) {
      SimpleMailMessage message = new SimpleMailMessage();
      message.setSubject(String.valueOf(i));
      mailMessages[i] = message;
    }
    mailSender.send(mailMessages);
  }
  public static void main (String args[]){
    MailSenderAsyncService asyncservice=new MailSenderAsyncService();
    Asyncservice. testSendMails();
  }
}
```

# 使用 AOP 发送 Spring 邮件

我们还可以通过将邮件功能与**面向切面编程**（**AOP**）集成来发送邮件。这可以用于在用户注册应用程序后发送邮件。想象一下用户在注册后收到激活邮件的情景。这也可以用于发送关于应用程序上下订单的信息。使用以下步骤使用 AOP 创建一个`MailAdvice`类：

1.  创建一个名为`com.packt.aop`的包。

1.  创建一个名为`MailAdvice`的类。

```java
public class MailAdvice {
  public void advice (final ProceedingJoinPoint proceedingJoinPoint) {
    new Thread(new Runnable() {
    public void run() {
      System.out.println("proceedingJoinPoint:"+proceedingJoinPoint);
      try {
        proceedingJoinPoint.proceed();
      } catch (Throwable t) {
        // All we can do is log the error.
        System.out.println(t);
      }
    }
  }).start();
  }
}
```

这个类创建一个新的线程并启动它。在`run`方法中，调用了`proceedingJoinPoint.proceed()`方法。`ProceddingJoinPoint`是`AspectJ.jar`中可用的一个类。

1.  使用`aop`配置更新`dispatcher-servlet.xml`文件。使用以下代码更新`xlmns`命名空间：

```java
xmlns:aop=http://www.springframework.org/schema/aop
```

1.  还要更新`xsi:schemalocation`，如下所示：

```java
xsi:schemaLocation="http://www.springframework.org/
  schema/aop http://www.springframework.org/
  schema/aop/spring-aop-2.5.xsd

```

1.  更新`.xml`文件中的 bean 配置：

```java
<aop:config>
  <aop:aspect ref="advice">
  <aop:around method="fork" pointcut="execution(* org.springframework.mail.javamail.JavaMailSenderImpl.send(..))"/>
  </aop:aspect>
</aop:config>
```

# 总结

在本章中，我们演示了如何使用 Spring API 创建邮件服务并进行配置。我们还演示了如何使用 MIME 消息发送带附件的邮件。我们还演示了如何使用`ExecutorService`为发送邮件创建一个专用线程。我们看到了一个示例，可以将邮件发送给多个收件人，并看到了使用 Velocity 引擎创建模板并将邮件发送给收件人的实现。在最后一节中，我们演示了 Spring 框架支持如何使用 Spring AOP 和线程发送邮件。

在下一章中，我们将介绍 Spring Batch 框架。
