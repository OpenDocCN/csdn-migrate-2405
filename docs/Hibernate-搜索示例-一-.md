# Hibernate 搜索示例（一）

> 原文：[`zh.annas-archive.org/md5/5084F1CE5E9C94A43DE0A69E72C391F6`](https://zh.annas-archive.org/md5/5084F1CE5E9C94A43DE0A69E72C391F6)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 序言

在过去的十年里，用户已经期望在搜索数据时软件能够高度智能。仅仅使搜索不区分大小写、作为子字符串查找关键词或其他基本的 SQL 技巧已经不够了。

如今，当用户在电子商务网站上搜索产品目录时，他或她期望关键词能在所有数据点上进行评估。无论一个术语与电脑的型号号还是书的 ISBN 相匹配，搜索都应该找到所有可能性。为了帮助用户筛选大量结果，搜索应该足够智能，以某种方式按相关性对它们进行排名。

搜索应该能够解析单词并理解它们可能如何相互连接。如果你搜索单词`development`，那么搜索应该能够理解这个词与`developer`有关联，尽管这两个单词都不是彼此的子字符串。

最重要的是，搜索应该要友好。当我们在网上论坛中发布东西，把“there”、“they're”和“their”这几个单词弄错了，人们可能只会批评我们的语法。相比之下，搜索应该能够理解我们的拼写错误，并且对此保持冷静！当搜索能够令人愉快地给我们带来惊喜，似乎比我们自己更理解我们在寻找的真实含义时，搜索表现得最好。

这本书的目的是介绍和探索**Hibernate Search**，这是一个用于向我们的自定义应用程序添加现代搜索功能的软件包，而无需从头开始发明。因为程序员通常通过查看真实代码来学习最佳，所以这本书围绕一个示例应用程序展开。我们将随着书的进展而坚持这个应用程序，并在每个章节中引入新概念时丰富它。

# **Hibernate Search** 是什么？

这个搜索功能的真正大脑是 Apache Lucene，这是一个用于数据索引和搜索的开源软件库。Lucene 是一个有着丰富创新历史的成熟 Java 项目，尽管它也被移植到了其他编程语言中。它被广泛应用于各行各业，从迪士尼到推特的知名用户都采用了它。

Lucene 经常与另一个相关项目 Apache Solr 交替讨论。从一个角度来看，Solr 是基于 Lucene 的独立搜索服务器。然而，依赖关系可以双向流动。Solr 的子组件通常与 Lucene 捆绑在一起，以便在嵌入其他应用程序时增强其功能。

### 注意

**Hibernate Search** 是 Lucene 和可选 Solr 组件的薄层封装。它扩展了核心的 Hibernate ORM，这是 Java 持久性最广泛采用的对象/关系映射框架。

下面的图表展示了所有这些组件之间的关系：

![Hibernate Search 是什么？](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hbn-srch-ex/img/9205_08_01.jpg)

最终，Hibernate Search 扮演两个角色：

+   首先，它将 Hibernate 数据对象转换为 Lucene 可以用来构建搜索索引的信息

+   朝着相反的方向前进，它将 Lucene 搜索的结果转换成熟悉的 Hibernate 格式

从一个程序员的角度来看，他或她正以通常的方式使用 Hibernate 映射数据。搜索结果以与正常 Hibernate 数据库查询相同的格式返回。Hibernate Search 隐藏了与 Lucene 的大部分底层管道。

# 本书涵盖内容

第一章, *你的第一个应用*, 直接深入创建一个 Hibernate Search 应用，一个在线软件应用目录。我们将创建一个实体类并为其准备搜索，然后编写一个 Web 应用来执行搜索并显示结果。我们将逐步了解如何设置带有服务器、数据库和构建系统的应用程序，并学习如何用其他选项替换这些组件。

第二章, *映射实体类*, 在示例应用程序中添加了更多的实体类，这些类通过注解来展示 Hibernate Search 映射的基本概念。在本章结束时，您将了解如何为 Hibernate Search 使用映射最常见的实体类。

第三章, *执行查询*, 扩展了示例应用程序的查询，以使用新的映射。在本章结束时，您将了解 Hibernate Search 查询的最常见用例。到这个阶段，示例应用程序将具备足够的功能，类似于许多 Hibernate Search 生产环境的用途。

第四章, *高级映射*, 解释了 Lucene 和 Solr 分析器之间的关系，以及如何为更高级的搜索配置分析器。它还涵盖了在 Lucene 索引中调整字段的权重，以及在运行时确定是否索引实体。在本章结束时，您将了解如何精细调整实体索引。您将品尝到 Solr 分析器框架，并掌握如何自行探索其功能。示例应用程序现在将支持忽略 HTML 标签的搜索，以及查找相关单词的匹配。

第五章, *高级查询*, 更深入地探讨了在第第三章，*执行查询*中介绍的查询概念，解释了如何通过投影和结果转换获得更快的性能。本章探讨了分面搜索，以及原生 Lucene API 的介绍。到本章结束时，您将对 Hibernate Search 提供的查询功能有更坚实的基础。示例市场应用程序现在将使用更轻量级的、基于投影的搜索，并支持按类别组织搜索结果。

第六章，*系统配置和索引管理*，介绍了 Lucene 索引管理，并提供了一些高级配置选项的概览。本章详细介绍了其中一些更常见的选项，并提供了足够的背景知识，使我们能够独立探索其他选项。在本章结束时，你将能够执行标准的管理任务，对 Hibernate Search 使用的 Lucene 索引进行管理，并理解通过配置选项为 Hibernate Search 提供额外功能的能力。

第七章，*高级性能策略*，重点关注通过代码以及服务器架构来提高 Hibernate Search 应用程序的运行时性能。在本章结束时，你将能够做出明智的决定，关于如何按需对 Hibernate Search 应用程序进行扩展。

# 本书需要什么

使用本书中的示例代码，你需要一台安装有 Java 开发工具包（版本 1.6 或更高）的计算机。你还需要安装 Apache Maven，或者安装有 Maven 插件的 Java 集成开发环境（IDE），如 Eclipse。

# 本书适合谁

本书的目标读者是希望为他们的应用程序添加搜索功能的 Java 开发者。本书的讨论和代码示例假设读者已经具备了 Java 编程的基本知识。对**Hibernate ORM**、**Java Persistence API**（**JPA 2.0**）或 Apache Maven 的先验知识会有帮助，但不是必需的。

# 约定

在本书中，你会发现有几种不同信息的文本样式。以下是一些这些样式的示例及其含义的解释。

文本中的代码词汇如下所示："`id`字段被同时注解为`@Id`和`@GeneratedValue`"。

一段代码如下所示：

```java
public App(String name, String image, String description) {
   this.name = name;
   this.image = image;
   this.description = description;
}
```

当我们希望引起你对代码块中的某个特定部分的关注时，相关的行或项目被设置为粗体：

```java
@Column(length=1000)
@Field
private String description;
```

任何命令行输入或输出如下所示：

```java
mvn archetype:generate -DgroupId=com.packpub.hibernatesearch.chapter1 -DartifactId=chapter1 -DarchetypeArtifactId=maven-archetype-webapp 
```

### 注意

警告或重要说明以这样的盒子出现。

### 提示

小贴士和小技巧如下所示。

# 读者反馈

来自我们读者的反馈总是受欢迎的。让我们知道你对这本书的看法——你喜欢或可能不喜欢的地方。读者反馈对我们开发您真正能从中获得最大收益的标题非常重要。

如果您想给我们发送一般性反馈，只需发送一封电子邮件到`<feedback@packtpub.com>`，并在消息主题中提及书名。

如果你在某个主题上有专业知识，并且对撰写或贡献书籍感兴趣，请查看我们在[www.packtpub.com/authors](http://www.packtpub.com/authors)上的作者指南。

# 客户支持

既然你已经拥有了一本 Packt 书籍，我们有很多东西可以帮助你充分利用你的购买。

## 下载示例代码

您可以在 Packt 出版社购买的任何书籍的示例代码文件，可以通过您账户中的[`www.packtpub.com`](http://www.packtpub.com)下载。如果您在其他地方购买了这本书，您可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)注册，以便将文件直接通过电子邮件发送给您。

## 勘误表

虽然我们已经尽一切努力确保我们内容的准确性，但是错误在所难免。如果您在我们的书中发现任何错误——可能是文本或代码中的错误——我们将非常感谢您能向我们报告。这样做，您可以节省其他读者的挫折感，并帮助我们改进本书的后续版本。如果您发现任何勘误，请通过访问[`www.packtpub.com/support`](http://www.packtpub.com/support)，选择您的书籍，点击**勘误表提交****表单**链接，并输入您的勘误详情。一旦您的勘误得到验证，您的提交将被接受，勘误将被上传到我们的网站，或添加到该标题的勘误表部分现有的勘误列表中。

## 盗版问题

互联网上版权材料的盗版是一个持续存在的问题，涵盖所有媒体。在 Packt，我们对保护我们的版权和许可证非常重视。如果您在互联网上发现我们作品的任何非法副本，无论以何种形式，请立即提供给我们位置地址或网站名称，以便我们可以寻求解决方案。

如果您发现有侵犯版权的材料，请联系我们`<copyright@packtpub.com>`，并提供涉嫌侵权材料的位置链接。

我们感谢您在保护我们的作者和我们提供有价值内容的能力方面所提供的帮助。

## 问题反馈

如果您在阅读本书的过程中遇到任何问题，可以通过`<questions@packtpub.com>`联系我们，我们会尽最大努力解决问题。


# 第一章：你的第一个应用程序

为了探索**Hibernate Search**的能力，我们将使用对经典“Java 宠物店”示例应用程序的一个变化。我们版本，“VAPORware Marketplace”，将是一个在线软件应用程序目录。想想苹果、谷歌、微软、Facebook 以及……好吧，现在几乎所有其他公司都在运营这样的商店。

我们的应用程序市场将给我们提供大量以不同方式搜索数据的机会。当然，像大多数产品目录一样，有标题和描述。然而，软件应用程序涉及一组更广泛的数据点，如类型、版本和支持的设备。这些不同的方面将让我们看看 Hibernate Search 提供的许多功能。

在高层次上，在应用程序中整合 Hibernate Search 需要以下三个步骤：

1.  向你的实体类中添加信息，以便 Lucene 知道如何索引它们。

1.  在应用程序的相关部分编写一个或多个搜索查询。

1.  设置你的项目，以便在最初就拥有 Hibernate Search 所需的依赖和配置。

在未来的项目中，在我们有了相当基本的了解之后，我们可能从这个第三个项目点开始。然而，现在，让我们直接进入一些代码！

# 创建实体类

为了保持简单，我们这个应用程序的第一个版本将只包括一个实体类。这个`App`类描述了一个软件应用程序，是所有其他实体类都将与之关联的中心实体。不过，现在，我们将给一个“应用程序”提供三个基本数据点：

+   一个名称

+   marketplace 网站上显示的图片

+   一段长描述

下面的 Java 代码：

```java
package com.packtpub.hibernatesearch.domain;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;

@Entity
public class App {

 @Id
 @GeneratedValue
   private Long id;

 @Column
   private String name;

 @Column(length=1000)
   private String description;

 @Column
   private String image;

   public App() {}

   public App(String name, String image, String description) {
      this.name = name;
      this.image = image;
      this.description = description;
   }

   public Long getId() {
      return id;
   }
   public void setId(Long id) {
      this.id = id;
   }
   public String getName() {
      return name;
   }
   public void setName(String name) {
      this.name = name;
   }
   public String getDescription() {
      return description;
   }
   public void setDescription(String description) {
      this.description = description;
   }
   public String getImage() {
      return image;
   }
   public void setImage(String image) {
      this.image = image;
   }
}
```

这个类是一个基本的**普通旧 Java 对象**（**POJO**），只有成员变量和用于处理它们的 getter/setter 方法。然而，请注意突出显示的注解。

### 注意

如果你习惯了 Hibernate 3.x，请注意版本 4.x 废弃了许多 Hibernate 自己的映射注解，转而使用它们的**Java 持久化 API**（**JPA**）2.0 对应物。我们将在第三章，*执行查询*中进一步讨论 JPA。现在，只需注意这里的 JPA 注解与它们的本地 Hibernate 注解基本相同，除了属于`javax.persistence`包。

该类本身用`@Entity`注解标记，告诉 Hibernate 将该类映射到数据库表。由于我们没有明确指定一个表名，默认情况下，Hibernate 将为`App`类创建一个名为`APP`的表。

`id`字段被注释为`@Id`和`@GeneratedValue`。前者简单地告诉 Hibernate 这个字段映射到数据库表的主键。后者声明当新行被插入时值应该自动生成。这就是为什么我们的构造方法不填充`id`的值，因为我们期待 Hibernate 为我们处理它。

最后，我们用`@Column`注解我们的三个数据点，告诉 Hibernate 这些变量与数据库表中的列相对应。通常，列名与变量名相同，Hibernate 会关于列长度、是否允许空值等做出一些合理的假设。然而，这些设置可以显式声明（就像我们在这里做的那样），通过将描述的列长度设置为 1,000 个字符。

# 为 Hibernate Search 准备实体

现在 Hibernate 知道了我们的领域对象，我们需要告诉 Hibernate Search 插件如何用**Lucene**管理它。

我们可以使用一些高级选项来充分利用 Lucene 的的全部力量，随着这个应用程序的发展，我们会的。然而，在基本场景下使用 Hibernate Search 只需添加两个注解那么简单。

首先，我们将添加`@Indexed`注解到类本身：

```java
...
import org.hibernate.search.annotations.Indexed;
...
@Entity
@Indexed
public class App implements Serializable {
...
```

这简单地声明了 Lucene 应该为这个实体类建立并使用索引。这个注解是可选的。当你编写一个大规模的应用程序时，其中许多实体类可能与搜索无关。Hibernate Search 只需要告诉 Lucene 那些可搜索的类型。

其次，我们将用`@Field`注解声明可搜索的数据点：

```java
...
import org.hibernate.search.annotations.Field;
...
@Id
@GeneratedValue
private Long id;
@Column
@Field
private String name;

@Column(length=1000)
@Field
private String description;

@Column
private String image;
...
```

注意我们只把这个注解应用到`name`和`description`成员变量上。我们没有注释`image`，因为我们不在乎通过图片文件名搜索应用程序。同样，我们也没有注释`id`，因为你要找一个数据库表行通过它的主键，你不需要一个强大的搜索引擎！

### 注意

决定注解什么是一个判断 call。你注释的索引实体越多，作为字段注释的成员变量越多，你的 Lucene 索引就会越丰富、越强大。然而，如果我们仅仅因为可以就注解多余的东西，那么我们就让 Lucene 做不必要的功，这可能会影响性能。

在第七章，*高级性能策略*，我们将更深入地探讨这些性能考虑。现在，我们已经准备好通过名称或描述来搜索应用程序。

# 加载测试数据

为了测试和演示目的，我们将使用一个内嵌数据库，每次启动应用程序时都应该清除并刷新它。在 Java Web 应用程序中，调用启动时间内的代码的一个简单方法是使用`ServletContextListener`。我们只需创建一个实现此接口的类，并用`@WebListener`注解它：

```java
package com.packtpub.hibernatesearch.util;

import javax.servlet.ServletContextEvent;
import javax.servlet.annotation.WebListener;
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.hibernate.cfg.Configuration;
import org.hibernate.service.ServiceRegistry;
import org.hibernate.service.ServiceRegistryBuilder;
import com.packtpub.hibernatesearch.domain.App;

@WebListener
public class StartupDataLoader implements ServletContextListener {
   /** Wrapped by "openSession()" for thread-safety, and not meant to be accessed directly. */
   private static SessionFactorysessionFactory;

 /** Thread-safe helper method for creating Hibernate sessions. */
   public static synchronized Session openSession() {
      if(sessionFactory == null) {
         Configuration configuration = new Configuration();
         configuration.configure();
         ServiceRegistryserviceRegistry = new
           ServiceRegistryBuilder().applySettings(
              configuration.getProperties()).buildServiceRegistry();
         sessionFactory =
            configuration.buildSessionFactory(serviceRegistry);
      }
      return sessionFactory.openSession();
   }

   /** Code to run when the server starts up. */
   public void contextInitialized(ServletContextEvent event) {
      // TODO: Load some test data into the database
   }

   /** Code to run when the server shuts down. */
   public void contextDestroyed(ServletContextEvent event) {
      if(!sessionFactory.isClosed()) {
         sessionFactory.close();
      }
   }
}

```

现在，`contextInitialized` 方法将在服务器启动时自动调用。我们将使用此方法设置 Hibernate 会话工厂，并向数据库填充一些测试数据。`contextDestroyed` 方法同样会在服务器关闭时自动调用。我们将使用这个方法在完成时显式关闭我们的会话工厂。

我们应用程序中的多个地方将需要一个简单且线程安全的手段来打开到数据库的连接（即，Hibernate `Session` 对象）。因此，我们还添加了一个名为 `openSession()` 的 `public static synchronized` 方法。该方法作为创建单例 `SessionFactory` 的线程安全守门员。

### 注意

在更复杂的应用程序中，您可能会使用依赖注入框架，如 Spring 或 CDI。这在我们的小型示例应用程序中有些分散注意力，但这些框架为您提供了一种安全机制，用于无需手动编码即可注入 `SessionFactory` 或 `Session` 对象。

在具体化 `contextInitialized` 方法时，我们首先获取一个 Hibernate 会话并开始一个新事务：

```java
...
Session session = openSession();
session.beginTransaction();
...
App app1 = new App("Test App One", "image.jpg",
 "Insert description here");
session.save(app1);

// Create and persist as many other App objects as you like…
session.getTransaction().commit();
session.close();
...

```

在事务内部，我们可以通过实例化和持久化 `App` 对象来创建所有我们想要的数据样本。为了可读性，这里只创建了一个对象。然而，在 [`www.packtpub.com`](http://www.packtpub.com) 可下载的源代码中包含了一个完整的测试示例集合。

# 编写搜索查询代码

我们的 VAPORware Marketplace 网络应用程序将基于 Servlet 3.0 控制器/模型类，呈现 JSP/JSTL 视图。目标是保持事情简单，这样我们就可以专注于 Hibernate Search 方面。在审阅了这个示例应用程序之后，应该很容易将相同的逻辑适配到 JSF 或 Spring MVC，甚至更新的基于 JVM 的框架，如 Play 或 Grails。

首先，我们将编写一个简单的 `index.html` 页面，包含一个用户输入搜索关键词的文本框：

```java
<html >
<head>
   <title>VAPORware Marketplace</title>
</head>
<body>
   <h1>Welcome to the VAPORware Marketplace</h1>
   Please enter keywords to search:
   <form action="search" method="post">
      <div id="search">
         <div>
         <input type="text" name="searchString" />
         <input type="submit" value="Search" />
         </div>
      </div>
   </form>
</body>
</html>
```

这个表单通过 CGI 参数 `searchString` 收集一个或多个关键词，并将其以相对 `/search` 路径提交给一个 URL。我们现在需要注册一个控制器 servlet 来响应这些提交：

```java
package com.packtpub.hibernatesearch.servlet;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@WebServlet("search")
public class SearchServletextends HttpServlet {
   protected void doPost(HttpServletRequest request,
         HttpServletResponse response) throws ServletException,
         IOException {

      // TODO: Process the search, and place its results on
      // the "request" object

      // Pass the request object to the JSP/JSTL view
      // for rendering
 getServletContext().getRequestDispatcher(
 "/WEB-INF/pages/search.jsp").forward(request, response);
   }

   protected void doGet(HttpServletRequest request,
         HttpServletResponse response) throws ServletException,
         IOException {
      this.doPost(request, response);
   }

}
```

`@WebServlet` 注解将这个 servlet 映射到相对 URL `/search`，这样提交到这个 URL 的表单将调用 `doPost` 方法。这个方法将处理一个搜索，并将请求转发给一个 JSP 视图进行渲染。

现在，我们来到了问题的核心——执行搜索查询。我们创建了一个 `FullTextSession` 对象，这是 Hibernate Search 的一个扩展，它用 Lucene 搜索功能包装了一个普通的 `Session`。

```java
...
import org.hibernate.Session;
import org.hibernate.search.FullTextSession;
import org.hibernate.search.Search;
...
Session session = StartupDataLoader.openSession();
FullTextSessionfullTextSession =   
   Search.getFullTextSession(session);
fullTextSession.beginTransaction();
...
```

现在我们有了 Hibernate `Search` 会话可以使用，我们可以获取用户的关键词并执行 Lucene 搜索：

```java
...
import org.hibernate.search.query.dsl.QueryBuilder;
...
String searchString = request.getParameter("searchString");

QueryBuilderqueryBuilder =
fullTextSession.getSearchFactory()
   .buildQueryBuilder().forEntity( App.class ).get();
org.apache.lucene.search.QueryluceneQuery =
 queryBuilder
 .keyword()
 .onFields("name", "description")
 .matching(searchString)
   .createQuery();
...
```

正如其名称所示，`QueryBuilder` 用于构建涉及特定实体类的查询。在这里，我们为我们的 `App` 实体创建了一个构建器。

请注意，在前面的代码的第三行中，有一个很长的方法调用链。从 Java 的角度来看，我们是在调用一个方法，在对象返回后调用另一个方法，并重复这个过程。然而，从简单的英语角度来看，这个方法调用链就像一个句子：

> **构建**一个**关键词**类型的查询，在实体**字段**"name"和"description"上，**匹配**"searchString"中的关键词。

这种 API 风格是有意为之的。因为它本身就像是一种语言，所以被称为 Hibernate Search **DSL**（**领域特定语言**）。如果你曾经使用过 Hibernate ORM 中的条件查询，那么这里的视觉感受对你来说应该是非常熟悉的。

现在我们已经创建了一个`org.apache.lucene.search.Query`对象，Hibernate Search 在幕后将其转换为 Lucene 搜索。这种魔力是双向的！Lucene 搜索结果可以转换为标准的`org.hibernate.Query`对象，并且像任何正常的数据库查询一样使用：

```java
...
org.hibernate.Query hibernateQuery =
   fullTextSession.createFullTextQuery(luceneQuery, App.class);
List<App> apps = hibernateQuery.list();
request.setAttribute("apps", apps);
...
```

使用`hibernateQuery`对象，我们获取了在搜索中找到的所有`App`实体，并将它们放在 servlet 请求中。如果你还记得，我们方法的最后一行将这个请求转发到一个`search.jsp`视图以供显示。

这个 JSP 视图将始于非常基础的内容，使用 JSTL 标签从请求中获取`App`结果并遍历它们：

```java
<%@ page language="java" contentType="text/html;
   charset=UTF-8" pageEncoding="UTF-8"%>
<%@ tagliburi="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<html>
<head>
   <title>VAPORware Marketplace</title>
</head>
<body>
   <h1>Search Results</h1>
   <table>
   <tr>
      <td><b>Name:</b></td>
      <td><b>Description:</b></td>
   </tr>
 <c:forEachvar="app" items="${apps}">
   <tr>
      <td>${app.name}</td>
      <td>${app.description}</td>
   </tr>
   </c:forEach>
</table>
</body>
</html>
```

# 选择一个构建系统

到目前为止，我们以某种逆序的方式对待我们的应用程序。我们基本上跳过了初始项目设置，直接进入代码，这样一旦到达那里，所有的管道都会更有意义。

好了，现在我们已经到达目的地！我们需要将所有这些代码整合到一个有序的项目结构中，确保所有的 JAR 文件依赖项都可用，并建立一个运行 Web 应用程序或将其打包为 WAR 文件的过程。我们需要一个项目构建系统。

一种我们不会考虑的方法是全部手动完成。对于一个使用原始 Hibernate ORM 的小型应用程序，我们可能只需要依赖六个半的 JAR 文件。在这个规模上，我们可能会考虑在我们的首选 IDE（例如 Eclipse、NetBeans 或 IntelliJ）中设置一个标准项目。我们可以从 Hibernate 网站获取二进制分发，并手动复制必要的 JAR 文件，让 IDE 从这里开始。

问题是 Hibernate Search 在幕后有很多东西。等你完成了 Lucene 甚至最基本的 Solr 组件的依赖项添加，依赖项列表会被扩大几倍。即使在这里的第一章，我们的非常基础的 VAPORware Marketplace 应用程序已经需要编译和运行超过三十六个 JAR 文件。这些库之间高度相互依赖，如果你升级了它们中的一个，避免冲突可能真的是一场噩梦。

在这个依赖管理级别，使用自动化构建系统来解决这些问题变得至关重要。在本书中的代码示例中，我们将主要使用 Apache Maven 进行构建自动化。

Maven 的两个主要特点是对基本构建的约定优于配置的方法，以及管理项目 JAR 文件依赖的强大系统。只要项目符合标准结构，我们甚至不必告诉 Maven 如何编译它。这被认为是模板信息。另外，当我们告诉 Maven 项目依赖于哪些库和版本时，Maven 会为我们找出整个依赖层次结构。它确定依赖项本身依赖于哪些库，依此类推。为 Maven 创建了标准仓库格式（参见 [`search.maven.org`](http://search.maven.org) 获取最大的公共示例），这样常见的库都可以自动检索，而无需寻找它们。

Maven 确实有自己的批评者。默认情况下，它的配置是基于 XML 的，这在最近几年已经不再流行了。更重要的是，当开发者需要做超出模板基础的事情时，有一个学习曲线。他或她必须了解可用的插件、Maven 构建的生命周期以及如何为适当的生命周期阶段配置插件。许多开发者都有过在学习曲线上的沮丧经历。

最近创建了许多其他构建系统，试图以更简单的形式 harness Maven 的相同力量（例如，基于 Groovy 的 Gradle，基于 Scala 的 SBT，基于 Ruby 的 Buildr 等）。然而，重要的是要注意，所有这些新系统仍然设计为从标准 Maven 仓库获取依赖项。如果您希望使用其他依赖管理和构建系统，那么本书中看到的概念将直接适用于这些其他工具。

为了展示一种更加手动、非 Maven 的方法，从 Packt Publishing 网站下载的示例代码包括本章示例应用程序的基于 Ant 的版本。寻找与基于 Maven 的 `chapter1` 示例对应的子目录 `chapter1-ant`。这个子目录的根目录中有一个 `README` 文件，强调了不同之处。然而，主要收获是书中展示的概念应该很容易翻译成任何现代的 Java 应用程序构建系统。

# 设置项目并导入 Hibernate Search

我们可以使用我们选择的 IDE 创建 Maven 项目。Eclipse 通过可选的 `m2e` 插件与 Maven 配合使用，NetBeans 使用 Maven 作为其本地构建系统。如果系统上安装了 Maven，您还可以选择从命令行创建项目：

```java
mvn archetype:generate -DgroupId=com.packpub.hibernatesearch.chapter1 -DartifactId=chapter1 -DarchetypeArtifactId=maven-archetype-webapp
```

在任何情况下，使用 Maven `archetype`都可以节省时间，`archetype`基本上是给定项目类型的一个模板。在这里，`maven-archetype-webapp`为我们提供了一个空白的网络应用程序，配置为打包成 WAR 文件。`groupId`和`artifactId`可以是任何我们希望的。如果我们将构建输出存储在 Maven 仓库中，它们将用于识别我们的构建输出。

我们新创建项目的`pom.xml` Maven 配置文件开始看起来类似于以下内容：

```java
<?xml version="1.0"?>
<project xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 
      http://maven.apache.org/xsd/maven-4.0.0.xsd"  

         >

   <modelVersion>4.0.0</modelVersion>
   <groupId>com.packpub.hibernatesearch.chapter1</groupId>
   <artifactId>chapter1</artifactId>
   <version>0.0.1-SNAPSHOT</version>
   <packaging>war</packaging>
   <name>chapter1</name>
   <url>http://maven.apache.org</url>

   <dependencies>
      <dependency>
         <groupId>junit</groupId>
         <artifactId>junit</artifactId>
         <version>3.8.1</version>
         <scope>test</scope>
      </dependency>
   </dependencies>

   <build>
 <!-- This controls the filename of the built WAR file -->
      <finalName>vaporware</finalName>
   </build>
</project>
```

我们首要的任务是声明编译和运行所需的依赖关系。在`<dependencies>`元素内，让我们添加一个 Hibernate Search 的条目：

```java
...
<dependency>
   <groupId>org.hibernate</groupId>
   <artifactId>hibernate-search</artifactId>
   <version>4.2.0.Final</version>
</dependency>
...
```

等等，我们之前不是说这需要超过三个小时的依赖项吗？是的，那是真的，但这并不意味着你必须处理它们全部！当 Maven 到达仓库并抓取这个依赖项时，它还将收到有关所有其依赖项的信息。Maven 沿着梯子一路下滑，每一步都解决任何冲突，并计算出一个依赖层次结构，以便您不必这样做。

我们的应用程序需要一个数据库。为了简单起见，我们将使用 H2 ([www.h2database.com](http://www.h2database.com))，一个嵌入式数据库系统，整个系统只有一个 1 MB 的 JAR 文件。我们还将使用**Apache Commons** **数据库连接池** ([commons.apache.org/dbcp](http://commons.apache.org/dbcp))以避免不必要的打开和关闭数据库连接。这些只需要声明每个依赖关系：

```java
...
<dependency>
  <groupId>com.h2database</groupId>
  <artifactId>h2</artifactId>
  <version>1.3.168</version>
</dependency>
<dependency>
  <groupId>commons-dbcp</groupId>
  <artifactId>commons-dbcp</artifactId>
  <version>1.4</version>
</dependency>
...
```

最后但同样重要的是，我们想要指定我们的网络应用程序正在使用 JEE Servlet API 的 3.x 版本。在下面的依赖关系中，我们将作用域指定为`provided`，告诉 Maven 不要将这个 JAR 文件打包到我们的 WAR 文件中，因为反正我们期望我们的服务器会提供：

```java
...
<dependency>
  <groupId>javax.servlet</groupId>
  <artifactId>javax.servlet-api</artifactId>
  <version>3.0.1</version>
  <scope>provided</scope>
</dependency>
...
```

有了我们的 POM 文件完备之后，我们可以将之前创建的源文件复制到我们的项目中。这三个 Java 类列在`src/main/java`子目录下。`src/main/webapp`子目录代表我们网络应用程序的文档根。`index.html`搜索页面及其`search.jsp`结果对应页面放在这里。下载并检查项目示例的结构。

# 运行应用程序

运行一个 Servlet 3.0 应用程序需要 Java 6 或更高版本，并且需要一个兼容的 Servlet 容器，如 Tomcat 7。然而，如果您使用嵌入式数据库以使测试和演示更简单，那么为什么不用嵌入式应用程序服务器呢？

**Jetty web** **服务器** ([www.eclipse.org/jetty](http://www.eclipse.org/jetty))有一个非常适合 Maven 和 Ant 的插件，它让开发者可以在不安装服务器的情况下从构建脚本中启动他们的应用程序。Jetty 8 或更高版本支持 Servlet 3.0 规范。

要向您的 Maven POM 中添加 Jetty 插件，请在`root`元素内插入一小块 XML：

```java
<project>
...
<build>
   <finalName>vaporware</finalName>
   <plugins>
      <plugin>
         <groupId>org.mortbay.jetty</groupId>
         <artifactId>jetty-maven-plugin</artifactId>
         <version>8.1.7.v20120910</version>
 <configuration>
 <webAppConfig>
 <defaultsDescriptor>
 ${basedir}/src/main/webapp/WEB-INF/webdefault.xml
 </defaultsDescriptor>
 </webAppConfig>
 </configuration>
      </plugin>
   </plugins>
</build>
</project>
```

高亮显示的`<configuration>`元素是可选的。在大多数操作系统上，在 Maven 启动一个嵌入式 Jetty 实例之后，你可以在不重新启动的情况下立即进行更改并看到它们生效。然而，由于 Microsoft Windows 在处理文件锁定方面的问题，你有时无法在 Jetty 实例运行时保存更改。

所以，如果你正在使用 Windows 并且希望有实时进行更改的能力，那么就复制一份`webdefault.xml`的定制副本，并将其保存到前面片段中引用的位置。这个文件可以通过下载并使用解压缩工具打开一个`jetty-webapp` JAR 文件来找到，或者简单地从 Packt Publishing 网站下载这个示例应用程序。对于 Windows 用户来说，关键是要找到`useFileMappedBuffer`参数，并将其值更改为`false`。

既然你已经有了一个 Web 服务器，那么让我们让它为我们创建和管理一个 H2 数据库。当 Jetty 插件启动时，它将自动寻找文件`src/main/webapp/WEB-INF/jetty-env.xml`。让我们创建这个文件，并使用以下内容填充它：

```java
<?xml version="1.0"?>
<!DOCTYPE Configure PUBLIC "-//Mort Bay Consulting//DTD
   Configure//EN" "http://jetty.mortbay.org/configure.dtd">

<Configure class="org.eclipse.jetty.webapp.WebAppContext">
   <New id="vaporwareDB" class="org.eclipse.jetty.plus.jndi.Resource">
      <Arg></Arg>
      <Arg>jdbc/vaporwareDB</Arg>
      <Arg>
      <New class="org.apache.commons.dbcp.BasicDataSource">
         <Set name="driverClassName">org.h2.Driver</Set>
         <Set name="url">
 jdbc:h2:mem:vaporware;DB_CLOSE_DELAY=-1
         </Set>
      </New>
      </Arg>
   </New>
</Configure>
```

这使得 Jetty 生成一个 H2 数据库连接池，JDBC URL 指定的是内存中的数据库，而不是文件系统上的持久数据库。我们将这个数据源以`jdbc/vaporwareDB`的名称注册到 JNDI 中，所以我们的应用程序可以通过这个名字来访问它。我们在应用程序的`src/main/webapp/WEB-INF/web.xml`文件中添加一个相应的引用：

```java
<!DOCTYPE web-app PUBLIC
      "-//Sun Microsystems, Inc.//DTD Web Application 2.3//EN"
      "http://java.sun.com/dtd/web-app_2_3.dtd" >
<web-app 

      xsi:schemaLocation="http://java.sun.com/xml/ns/javaee   
      http://java.sun.com/xml/ns/javaee/web-app_3_0.xsd"      
      version="3.0">
   <display-name>VAPORware Marketplace</display-name>
   <resource-ref>
      <res-ref-name>jdbc/vaporwareDB</res-ref-name>
      <res-type>javax.sql.DataSource</res-type>
      <res-auth>Container</res-auth>
   </resource-ref>
</web-app>
```

最后，我们需要通过一个标准的`hibernate.cfg.xml`文件将这个数据库资源与 Hibernate 绑定，这个文件我们将创建在`src/main/resources`目录下：

```java
<?xml version='1.0' encoding='utf-8'?>
<!DOCTYPE hibernate-configuration PUBLIC
      "-//Hibernate/Hibernate Configuration DTD 3.0//EN"
      "http://www.hibernate.org/dtd/hibernate-configuration-
      3.0.dtd">
<hibernate-configuration>
   <session-factory>
      <property name="connection.datasource">
         jdbc/vaporwareDB
      </property>
      <property name="hibernate.dialect">
         org.hibernate.dialect.H2Dialect
      </property>
      <property name="hibernate.hbm2ddl.auto">
         update
      </property>
      <property name="hibernate.show_sql">
         false
      </property>
      <property name=hibernate.search.default.directory_provider">
         filesystem
      </property>
      <property name="hibernate.search.default.indexBase">
         target/lucenceIndex
      </property>

      <mapping class=
              "com.packtpub.hibernatesearch.domain.App"/>
   </session-factory>
</hibernate-configuration>
```

第一行高亮显示的代码将 Hibernate 会话工厂与 Jetty 管理的`jdbc/vaporwareDBdata`数据源关联起来。最后一行高亮显示的代码将`App`声明为一个与这个会话工厂绑定的实体类。目前我们只有这个一个实体，但随着后面章节中更多实体的引入，我们将在这里添加更多的`<class>`元素。

在此之间，`<properties>`元素的大部分与核心设置相关，这些对于有经验的 Hibernate 用户来说可能很熟悉。然而，高亮显示的属性是针对 Hibernate Search 附加组件的。`hibernate.search.default.directory_provider`声明我们希望在文件系统上存储我们的 Lucene 索引，而不是在内存中。`hibernate.search.default.indexBase`指定索引的位置，在我们项目的子目录中，Maven 在构建过程期间会为我们清理这个目录。

好的，我们有一个应用程序，一个数据库，还有一个服务器将这两者结合在一起。现在，我们可以实际部署和启动，通过运行带有`jetty:run`目标的 Maven 命令来实现：

```java
mvn clean jetty:run

```

`clean`目标消除了先前构建的痕迹，然后因为`jetty:run`的暗示，Maven 组装我们的 Web 应用程序。我们的代码很快被编译，并在`localhost:8080`上启动了一个 Jetty 服务器：

![运行应用程序](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hbn-srch-ex/img/9205_01_02.jpg)

我们上线了！现在我们可以使用我们喜欢的任何关键词搜索应用程序。一个小提示：在可下载的示例代码中，所有测试数据记录的描述中都包含单词`app`：

![运行应用程序](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hbn-srch-ex/img/9205_01_03.jpg)

可下载的示例代码让 HTML 看起来更加专业。它还将在每个应用程序的名称和描述旁边添加应用程序的图片：

![运行应用程序](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hbn-srch-ex/img/9205_01_04.jpg)

Maven 命令`mvn clean package`允许我们将应用程序打包成 WAR 文件，因此我们可以将其部署到 Maven Jetty 插件之外的独立服务器上。只要你知道如何为 JNDI 名称`jdbc/vaporwareDB`设置数据源，就可以使用任何符合 Servlet 3.0 规范的 Java 服务器（例如，Tomcat 7+），所以你都可以这样做。

事实上，你可以将`H2`替换为你喜欢的任何独立数据库。只需将适当的 JDBC 驱动添加到你的 Maven 依赖项中，并在`persistence.xml`中更新设置。

# 摘要

在本章中，我们学习了 Hibernate ORM、Hibernate Search 扩展和底层 Lucene 搜索引擎之间的关系。我们了解了如何将实体和字段映射以使它们可供搜索。我们使用 Hibernate Search DSL 编写跨多个字段的全文搜索查询，并且像处理正常数据库查询一样处理结果。我们使用自动构建过程来编译我们的应用程序，并将其部署到一个带有实时数据库的 Web 服务器上。

仅凭这些工具，我们就可以将 Hibernate Search 立即集成到许多实际应用程序中，使用任何其他服务器或数据库。在下一章中，我们将深入探讨 Hibernate Search 为映射实体对象到 Lucene 索引提供的选项。我们将了解如何处理扩展的数据模型，将我们的 VAPORware 应用程序与设备和客户评论关联起来。


# 第二章：映射实体类

在第一章，*你的第一个应用*中，我们使用了核心 Hibernate ORM 来将一个实体类映射到数据库表，然后使用 Hibernate Search 将它的两个字段映射到一个 Lucene 索引。仅凭这一点，就提供了很多搜索功能，如果从头开始编写将会非常繁琐。

然而，实际应用通常涉及许多实体，其中许多应该可供搜索使用。实体可能相互关联，我们的查询需要理解这些关联，这样我们才能一次性搜索多个实体。我们可能希望声明某些映射对于搜索来说比其他映射更重要，或者在某些条件下我们可能希望跳过索引数据。

在本章中，我们将开始深入探讨 Hibernate Search 为映射实体提供的选项。作为一个第一步，我们必须查看 Hibernate ORM 中的 API 选项。我们如何将实体类映射到数据库，这将影响 Hibernate Search 如何将它们映射到 Lucene。

# 选择 Hibernate ORM 的 API

当 Hibernate Search 文档提到 Hibernate ORM 的不同 API 时，可能会令人困惑。在某些情况下，这可能指的是是否使用 `org.hibernate.Session` 或者 `javax.persistence.EntityManager` 对象（下一章的重要部分）来执行数据库查询。然而，在实体映射的上下文中，这指的是 Hibernate ORM 提供的三种不同的方法：

+   使用经典 Hibernate 特定注解的基于注解的映射

+   使用 Java 持久化 API（JPA 2.0）的基于注解的映射

+   使用 `hbm.xml` 文件的基于 XML 的映射

如果你只使用过 Hibernate ORM 的经典注解或基于 XML 的映射，或者如果你是 Hibernate 的新手，那么这可能是你第一次接触到 JPA。简而言之，JPA 是一个规范，旨在作为对象关系映射和其他类似功能的官方标准。

想法是提供 ORM 所需的类似于 JDBC 提供的低级数据库连接。一旦开发者学会了 JDBC，他们就可以快速使用任何实现 API 的数据库驱动程序（例如，Oracle、PostgreSQL、MySQL 等）。同样，如果你理解了 JPA，那么你应该能够轻松地在 Hibernate、EclipseLink 和 Apache OpenJPA 等 ORM 框架之间切换。

实际上，不同的实现通常有自己的怪癖和专有扩展，这可能会导致过渡性头痛。然而，一个共同的标准可以大大减少痛苦和学习曲线。

使用 Hibernate ORM 原生 API 与使用 JPA 进行实体映射的比较如下图所示：

![选择 Hibernate ORM 的 API](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hbn-srch-ex/img/9205_01_01.jpg)

对长期使用 Hibernate 的开发人员来说好消息是，JPA 实体映射注解与 Hibernate 自己的注解非常相似。实际上，Hibernate 的创始人参与了 JPA 委员会的开发，这两个 API 相互之间有很强的影响。

取决于你的观点，不那么好的消息是 Hibernate ORM 4.x 弃用自己的映射注解，以支持其 JPA 对应物。这些较旧的注解计划在 Hibernate ORM 5.x 中删除。

### 提示

如今使用这种已弃用的方法编写新代码没有意义，因此我们将忽略 Hibernate 特定的映射注解。

第三种选择，基于 XML 的映射，在遗留应用程序中仍然很常见。它正在失去青睐，Hibernate Search 文档甚至开玩笑说 XML 不适合 21 世纪！当然，这有点开玩笑，考虑到基本的 Hibernate 配置仍然存储在`hibernate.cfg.xml`或`persistence.xml`文件中。尽管如此，大多数 Java 框架的趋势很明显，对于与特定类绑定的配置使用注解，对于全局配置使用某种形式的文本文件。

即使你使用`hbm.xml`文件将实体映射到数据库，你仍然可以使用 Hibernate Search 注解将这些实体映射到 Lucene 索引。这两个完全兼容。如果你想在最小努力的情况下将 Hibernate Search 添加到遗留应用程序中，或者即使在开发新应用程序时也有哲学上的偏好使用`hbm.xml`文件，这很方便。

本章包含 VAPORware Marketplace 应用程序的三种版本示例代码：

+   `chapter2`子目录继续第一章, *你的第一个应用程序*的讲解，使用 JPA 注解将实体同时映射到数据库和 Lucene。

+   `chapter2-xml`子目录是相同代码的一个变体，修改为将基于 XML 的数据库映射与基于 JPA 的 Lucene 映射混合。

+   `chapter2-mapping`子目录使用一个特殊的 API 来完全避免注解。这在本章末尾的*程序化映射 API*部分中进一步讨论。

你应该详细探索这些示例代码，以了解可用的选项。然而，除非另有说明，本书中的代码示例将重点介绍使用 JPA 注解对数据库和 Lucene 进行映射。

### 注意

当使用 JPA 注解进行数据库映射时，Hibernate Search 会自动为用`@Id`注解的字段创建一个 Lucene 标识符。

出于某种原因，Hibernate Search 无法与 Hibernate ORM 自身的映射 API 相同。因此，当你不使用 JPA 将实体映射到数据库时，你也必须在应该用作 Lucene 标识符的字段上添加`@DocumentId`注解（在 Lucene 术语中，实体被称为**文档**）。

# 字段映射选项

在第一章*你的第一个应用*中，我们看到了 Hibernate 管理的类上的成员变量可以通过`@Field`注解变得可搜索。Hibernate Search 会将关于注解字段的信息放入一个或多个 Lucene 索引中，使用一些合理的默认值。

然而，你可以以无数种方式自定义索引行为，其中一些是`@Field`注解本身的可选元素。本书将进一步探讨这些元素，但在这里我们将简要介绍它们：

+   `analyze`：这告诉 Lucene 是存储字段数据原样，还是将其进行分析、解析，并以各种方式处理。它可以设置为`Analyze.YES`（默认）或`Analyze.NO`。我们将在第三章*执行查询*中再次看到这一点。

+   `index`：这控制是否由 Lucene 索引字段。它可以设置为`Index.YES`（默认）或`Index.NO`。在第五章*高级查询*中介绍基于投影的搜索后，使用`@Field`注解但不索引字段听起来可能没有意义，但这将更有意义。

+   `indexNullAs`：这声明了如何处理空字段值。默认情况下，空值将被简单忽略并从 Lucene 索引中排除。然而，在第四章*高级映射*中，你可以强制将空字段索引化为某个默认值。

+   `name`：这是一个自定义名称，用于描述字段在 Lucene 索引中的名称。默认情况下，Hibernate Search 将使用注解的成员变量的名称。

+   `norms`：这决定了是否存储用于提升（boosting）或调整搜索结果默认相关性的索引时间信息。它可以设置为`Norms.YES`（默认）或`Norms.NO`。索引时间提升将在第四章*高级映射*中介绍。

+   `store`：通常，字段以优化搜索的方式进行索引，但这可能不允许以原始形式检索数据。此选项使原始数据以这种方式存储，以至于你可以在稍后直接从 Lucene 而不是数据库中检索它。它可以设置为`Store.NO`（默认）、`Store.YES`或`Store.COMPRESS`。我们将在第五章*高级查询*中与基于投影的搜索一起使用这个选项。

## 相同字段的多重映射

有时，你需要用一组选项对字段进行某些操作，用另一组选项进行其他操作。我们将在第三章*执行查询*中看到这一点，当我们使一个字段既可搜索又可排序。

暂时先说这么多，你可以在同一个字段上有尽可能多的自定义映射。只需包含多个 `@Field` 注解，用复数的 `@Fields` 包裹起来即可：

```java
...
@Column
@Fields({
   @Field,
   @Field(name="sorting_name", analyze=Analyze.NO)
})
private String name;
...
```

现在不用担心这个例子。只需注意，当你为同一个字段创建多个映射时，你需要通过 `name` 元素给它们赋予不同的名称，这样你以后才能正确引用。

## 数值字段映射

在第一章，*你的第一个应用程序*中，我们的实体映射示例仅涉及字符串属性。同样，使用相同的 `@Field` 注解与其他基本数据类型也是完全没问题的。

然而，这种方式映射的字段被 Lucene 以字符串格式索引。这对于我们稍后探讨的技术（如排序和范围查询）来说非常低效。

为了提高此类操作的性能，Hibernate Search 提供了一个用于索引数值字段的特殊数据结构。当映射 `Integer`、`Long`、`Float` 和 `Double`（或它们的原始类型）类型的字段时，此选项是可用的。

要为数值字段使用这个优化的数据结构，你只需在正常的 `@Field` 注解之外添加 `@NumericField` 注解。作为一个例子，让我们在 VAPORware Marketplace 应用程序的 `App` 实体中添加一个价格字段：

```java
...
@Column
@Field
@NumericField
private float price;
...
```

如果你将此注解应用于已经多次映射到 `@Fields` 的属性，你必须指定*哪个*映射应使用特殊的数据结构。这通过给 `@NumericField` 注解一个可选的 `forField` 元素来实现，该元素设置为所需 `@Field` 的相同名称。

# 实体间的关系

每当一个实体类被 `@Indexed` 注解标记时，默认情况下 Hibernate Search 将为该类创建一个 Lucene 索引。我们可以有尽可能多的实体和单独的索引。然而，单独搜索每个索引将是一种非常笨拙和繁琐的方法。

大多数 Hibernate ORM 数据模型已经捕捉了实体类之间的各种关联。当我们搜索实体的 Lucene 索引时，Hibernate Search 难道不应该跟随这些关联吗？在本节中，我们将了解如何使其这样做。

## 关联实体

到目前为止，我们示例应用程序中的实体字段一直是很简单的数据类型。`App` 类代表了一个名为 `APP` 的表，它的成员变量映射到该表的列。现在让我们添加一个复杂类型的字段，用于关联第二个数据库表的一个外键。

在线应用商店通常支持一系列不同的硬件设备。因此，我们将创建一个名为 `Device` 的新实体，代表有 `App` 实体可用的设备。

```java
@Entity
public class Device {

   @Id
   @GeneratedValue
   private Long id;

   @Column
   @Field
   private String manufacturer;

   @Column
   @Field
   private String name;

 @ManyToMany(mappedBy="supportedDevices",
 fetch=FetchType.EAGER,
 cascade = { CascadeType.ALL }
 )
 @ContainedIn
 private Set<App> supportedApps;

   public Device() {
   }

   public Device(String manufacturer, String name,
         Set<App>supportedApps) {
      this.manufacturer = manufacturer;
      this.name = name;
      this.supportedApps = supportedApps;
   }

   //
   // Getters and setters for all fields...
   //

}
```

此类的大多数细节应该从第一章 *你的第一个应用程序* 中熟悉。`Device`用`@Entity`注解标记，因此 Hibernate Search 将为它创建一个 Lucene 索引。实体类包含可搜索的设备名称和制造商名称字段。

然而，`supportedApps`成员变量引入了一个新注解，用于实现这两个实体之间的双向关联。一个`App`实体将包含一个它所支持的所有设备的列表，而一个`Device`实体将包含一个它所支持的所有应用的列表。

### 提示

如果没有其他原因，使用双向关联可以提高 Hibernate Search 的可靠性。

Lucene 索引包含来自关联实体的非规范化数据，但这些实体仍然主要与它们自己的 Lucene 索引相关联。长话短说，当两个实体的关联是双向的，并且变化被设置为级联时，那么当任一实体发生变化时，您都可以确信两个索引都会被更新。

Hibernate ORM 参考手册描述了几种双向映射类型和选项。在这里我们使用`@ManyToMany`，以声明`App`和`Device`实体之间的多对多关系。`cascade`元素被设置以确保此端关联的变化正确地更新另一端。

### 注意

通常，Hibernate 是“懒加载”的。它实际上直到需要时才从数据库中检索关联实体。

然而，这里我们正在编写一个多层应用程序，当我们的搜索结果 JSP 接收到这些实体时，控制器 servlet 已经关闭了 Hibernate 会话。如果视图尝试在会话关闭后检索关联，将会发生错误。

这个问题有几个解决方法。为了简单起见，我们还在`@ManyToMany`注解中添加了一个`fetch`元素，将检索类型从“懒加载”更改为“ eager”。现在当我们检索一个 Device 实体时，Hibernate 会在会话仍然开启时立即获取所有关联的`App`实体。

然而，在大量数据的情况下，积极检索是非常低效的，因此，在第五章 *高级查询* 中，我们将探讨一个更高级的策略来处理这个问题。

迄今为止，关于`supportedApps`的一切都是在 Hibernate ORM 的范畴内。所以最后但并非最不重要的是，我们将添加 Hibernate Search 的`@ContainedIn`注解，声明`App`的 Lucene 索引应包含来自`Device`的数据。Hibernate ORM 已经将这两个实体视为有关联。Hibernate Search 的`@ContainedIn`注解也为 Lucene 设置了双向关联。

双向关联的另一面涉及向`App`实体类提供一个支持`Device`实体类的列表。

```java
...
@ManyToMany(fetch=FetchType.EAGER, cascade = { CascadeType.ALL })
@IndexedEmbedded(depth=1)
private Set<Device>supportedDevices;
...
// Getter and setter methods
...
```

这与关联的`Device`方面非常相似，不同之处在于这里的`@IndexedEmbedded`注解是`@ContainedIn`的反向。

### 注意

如果你的关联对象本身就包含其他关联对象，那么你可能会索引比你想要的更多的数据。更糟糕的是，你可能会遇到循环依赖的问题。

为了防止这种情况，将`@IndexEmbedded`注解的可选`depth`元素设置为一个最大限制。在索引对象时，Hibernate Search 将不会超过指定层数。

之前的代码指定了一层深度。这意味着一个应用将带有关于它支持设备的信息进行索引，但*不包括*设备支持的其他应用的信息。

### 查询关联实体

一旦为 Hibernate Search 映射了关联实体，它们很容易被包含在搜索查询中。以下代码片段更新了`SearchServlet`以将`supportedDevices`添加到搜索字段列表中：

```java
...
QueryBuilderqueryBuilder =
fullTextSession.getSearchFactory().buildQueryBuilder()
      .forEntity(App.class ).get();
org.apache.lucene.search.QueryluceneQuery = queryBuilder
   .keyword()
 .onFields("name", "description", "supportedDevices.name")
   .matching(searchString)
   .createQuery();
org.hibernate.QueryhibernateQuery =
   fullTextSession.createFullTextQuery(luceneQuery, App.class);
...
```

复杂类型与我们迄今为止处理过的简单数据类型略有不同。对于复杂类型，我们实际上并不太关心字段本身，因为字段实际上只是一个对象引用（或对象引用的集合）。

我们真正希望搜索匹配的是复杂类型中的简单数据类型字段。换句话说，我们希望搜索`Device`实体的`name`字段。因此，只要关联类字段已被索引（即使用`@Field`注解），它就可以使用[实体字段].[嵌套字段]格式进行查询，例如之前的代码中的`supportedDevices.name`。

在本章的示例代码中，`StartupDataLoader`已经扩展以在数据库中保存一些`Device`实体并将它们与`App`实体关联。这些测试设备中的一个名为 xPhone。当我们运行 VAPORware Marketplace 应用并搜索这个关键词时，搜索结果将包括与 xPhone 兼容的应用，即使这个关键词没有出现在应用的名称或描述中。

## 嵌入对象

关联实体是完整的实体。它们通常对应自己的数据库表和 Lucene 索引，并且可以独立于它们的关联存在。例如，如果我们删除了在 xPhone 上支持的应用实体，那并不意味着我们想要删除 xPhone 的`Device`。

还有一种不同的关联类型，其中关联对象的生存周期取决于包含它们的实体。如果 VAPORware Marketplace 应用有客户评论，并且一个应用从数据库中被永久删除，那么我们可能期望与它一起删除所有客户评论。

### 注意

经典 Hibernate ORM 术语将这些对象称为**组件**（有时也称为**元素**）。在新版 JPA 术语中，它们被称为**嵌入对象**。

嵌入对象本身并不是实体。Hibernate Search 不会为它们创建单独的 Lucene 索引，并且它们不能在没有包含它们的实体的上下文中被搜索。否则，它们在外观和感觉上与关联实体非常相似。

让我们给示例应用程序添加一个客户评论的嵌入对象类型。`CustomerReview`实例将包括提交评论的人的用户名，他们给出的评分（例如，五颗星），以及他们写的任何附加评论。

```java
@Embeddable
public class CustomerReview {

 @Field
   private String username;

   private int stars;

 @Field
   private String comments;

   publicCustomerReview() {
   }

   public CustomerReview(String username,
         int stars, String comments) {
      this.username = username;
      this.stars = stars;
      this.comments = comments;
   }

   // Getter and setter methods...

}
```

这个类被注解为`@Embeddable`而不是通常的`@Entity`注解，告诉 Hibernate ORM`CustomerReview`实例的生命周期取决于包含它的哪个实体对象。

`@Field`注解仍然应用于可搜索的字段。然而，Hibernate Search 不会为`CustomerReview`创建独立的 Lucene 索引。这个注解只是向包含这个嵌入类其他实体的索引中添加信息。

在我们的案例中，包含类将是`App`。给它一个客户评论作为成员变量：

```java
...
@ElementCollection(fetch=FetchType.EAGER)
@Fetch(FetchMode.SELECT)
@IndexedEmbedded(depth=1)
private Set<CustomerReview>customerReviews;
...
```

而不是使用通常的 JPA 关系注解（例如，`@OneToOne`，`@ManyToMany`等），此字段被注解为 JPA `@ElementCollection`。如果这个字段是一个单一对象，则不需要任何注解。JPA 会简单地根据该对象类具有`@Embeddable`注解来推断出来。然而，当处理嵌入元素的集合时，需要`@ElementCollection`注解。

### 提示

当使用基于经典 XML 的 Hibernate 映射时，`hbm.xml`文件等效物是`<component>`用于单个实例，`<composite-element>`用于集合。请参阅可下载示例应用程序源代码的`chapter2-xml`变体。

`@ElementCollection`注解有一个`fetch`元素设置为使用 eager fetching，原因与本章前面讨论的原因相同。

在下一行，我们使用 Hibernate 特定的`@Fetch`注解，以确保通过多个`SELECT`语句而不是单个`OUTER JOIN`来获取`CustomerReview`实例。这避免了由于 Hibernate ORM 的怪癖而在下载源代码中的注释中进一步讨论而导致的客户评论重复。不幸的是，当处理非常大的集合时，这种模式效率低下，因此在这种情况下你可能希望考虑另一种方法。

查询嵌入对象与关联实体相同。以下是从`SearchServlet`中修改的查询代码片段，以针对嵌入的`CustomerReview`实例的注释字段进行搜索：

```java
...
QueryBuilderqueryBuilder =
fullTextSession.getSearchFactory().buildQueryBuilder()
   .forEntity(App.class ).get();
org.apache.lucene.search.QueryluceneQuery = queryBuilder
   .keyword()
   .onFields("name", "description", "supportedDevices.name",
      "customerReviews.comments")
   .matching(searchString)
   .createQuery();
org.hibernate.QueryhibernateQuery = fullTextSession.createFullTextQuery(
   luceneQuery, App.class);
...
```

现在我们有一个真正进行搜索的查询！`chapter2`版本的`StartupDataLoader`已扩展以加载所有测试应用的客户评论。当在客户评论中找到匹配项时，搜索现在将产生结果，尽管关键词本身没有出现在`App`中。

市场应用中的 VAPORware HTML 也得到了更新。现在每个搜索结果都有一个**完整详情**按钮，它会弹出一个包含支持设备和对该应用的客户评论的模态框。注意在这个截图中，搜索关键词是与客户评论相匹配，而不是与实际的应用描述相匹配：

![嵌入对象](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hbn-srch-ex/img/9205_02_02.jpg)

# 部分索引

关联实体每个都有自己的 Lucene 索引，并在彼此的索引中存储一些数据。对于嵌入对象，搜索信息存储在*专有*的包含实体的索引中。

然而，请注意，这些类可能在不止一个地方被关联或嵌入。例如，如果你的数据模型中有`Customer`和`Publisher`实体，它们可能都有一个`Address`类型的嵌入对象。

通常，我们使用`@Field`注解来告诉 Hibernate Search 哪些字段应该被索引和搜索。但是，如果我们想要这个字段随着相关或嵌入的对象而变化呢？如果我们想要一个字段根据包含它的其他实体是否被索引呢？Hibernate Search 通过`@IndexedEmbedded`注解的可选元素提供了这种能力。这个`includePaths`元素表明在*这个*包含实体的 Lucene 索引中，只应该包含关联实体或嵌入对象的某些字段。

在我们的示例应用程序中，`CustomerReview`类将其`username`和`comments`变量都注解为可搜索的字段。然而，假设对于`App`内的`customerReviews`，我们只关心在评论上进行搜索。`App`的变化如下所示：

```java
...
@ElementCollection(fetch=FetchType.EAGER)
@Fetch(FetchMode.SELECT)
@IndexedEmbedded(depth=1, includePaths = { "comments" })
private Set<CustomerReview>customerReviews;
...
```

尽管`CustomerReview.username`被注解为`@Field`，但这个字段不会添加到`App`的 Lucene 索引中。这节省了空间，通过不必要的索引来提高性能。唯一的权衡是，为了防止错误，我们必须记得在我们的查询代码中避免使用任何未包含的字段。

# 程序化映射 API

在本章开头，我们说过，即使你使用`hbm.xml`文件将实体映射到数据库，你仍然可以使用 Hibernate Search 注解映射到 Lucene。然而，如果你真的想完全避免在实体类中放置注解，有一个 API 可以在运行时以程序化的方式声明你的 Lucene 映射。

如果你需要在运行时根据某些情况更改搜索配置，这可能会有所帮助。这也是如果你不能出于某种原因更改实体类，或者如果你是坚定的配置与 POJO 分离主义者，这是唯一可用的方法。

程序化映射 API 的核心是`SearchMapping`类，它存储了通常从注解中提取的 Hibernate Search 配置。典型的使用方式看起来像我们在前一章看到的查询 DSL 代码。你在`SearchMapping`对象上调用一个方法，然后调用返回对象上的方法，以此类推，形成一个长长的嵌套系列。

每一步可用的方法都直观地类似于你已经见过的搜索注解。`entity()`方法替代了`@Entity`注解，`indexed()`替代了`@Indexed`，`field()`替代了`@Field`，等等。

### 提示

如果你需要在应用程序中使用程序化映射 API，那么你可以在[`www.hibernate.org/subprojects/search/docs`](http://www.hibernate.org/subprojects/search/docs)找到更多详细信息，该链接提供了*参考手册*和*Javadocs*，它们都可供查阅。

在 Javadocs 的起点是`org.hibernate.search.cfg.SearchMapping`类，其他相关的类也都位于`org.hibernate.search.cfg`包中。

从 Packt Publishing 网站下载的源代码中，`chapter2-mapping`子目录包含了一个使用程序化映射 API 的 VAPORware Marketplace 应用程序版本。

这个示例应用的版本包含一个工厂类，其中有一个方法根据需求配置并返回一个`SearchMapping`对象。无论你给这个类或方法起什么名字，只要这个方法用`@org.hibernate.search.annotations.Factory`注解标记即可：

```java
public class SearchMappingFactory {

 @Factory
 public SearchMapping getSearchMapping() {

      SearchMapping searchMapping = new SearchMapping();

      searchMapping
         .entity(App.class)
            .indexed()
            .interceptor(IndexWhenActiveInterceptor.class)
            .property("id", ElementType.METHOD).documentId()
            .property("name", ElementType.METHOD).field()
            .property("description", ElementType.METHOD).field()
            .property("supportedDevices",
               ElementType.METHOD).indexEmbedded().depth(1)
            .property("customerReviews",
               ElementType.METHOD).indexEmbedded().depth(1)

         .entity(Device.class)
            .property("manufacturer", ElementType.METHOD).field()
            .property("name", ElementType.METHOD).field()
            .property("supportedApps",   
               ElementType.METHOD).containedIn()
         .entity(CustomerReview.class)
            .property("stars", ElementType.METHOD).field()
            .property("comments", ElementType.METHOD).field();

      return searchMapping;
   }

}
```

请注意，这个工厂方法严格来说只有三行长。它的主要部分是一个从`SearchMapping`对象开始的连续一行链式方法调用，这个调用将我们的三个持久化类映射到 Lucene。

为了将映射工厂集成到 Hibernate Search 中，我们在主要的`hibernate.cfg.xml`配置文件中添加了一个属性：

```java
...
<property name="hibernate.search.model_mapping">
   com.packtpub.hibernatesearch.util.SearchMappingFactory
</property>
...
```

现在，无论何时 Hibernate ORM 打开一个`Session`，Hibernate Search 以及所有的 Lucene 映射都会随之而来！

# 总结

在本章中，我们扩展了如何为搜索映射类的知识。现在，我们可以使用 Hibernate Search 将实体和其他类映射到 Lucene，无论 Hibernate ORM 如何将它们映射到数据库。如果我们任何时候需要将类映射到 Lucene 而不添加注解，我们可以在运行时使用程序化映射 API 来处理。

我们现在已经知道了如何跨相关实体以及其生命周期依赖于包含实体的嵌入对象管理 Hibernate Search。在这两种情况下，我们都涵盖了一些可能会让开发者绊倒的隐蔽怪癖。最后，我们学习了如何根据包含它们的实体来控制关联或嵌入类的哪些字段被索引。

在下一章中，我们将使用这些映射来处理各种搜索查询类型，并探索它们都共有的重要特性。


# 第三章：执行查询

在上一章中，我们创建了各种类型的持久化对象，并将它们以各种方式映射到 Lucene 搜索索引中。然而，到目前为止，示例应用程序的所有版本基本上都使用了相同的关键词查询。

在本章中，我们将探讨 Hibernate Search DSL 提供的其他搜索查询类型，以及所有它们共有的重要特性，如排序和分页。

# 映射 API 与查询 API

到目前为止，我们已经讨论了使用 Hibernate ORM 将类映射到数据库的各种 API 选项。你可以使用 XML 或注解来映射你的类，运用 JPA 或传统的 API，只要注意一些细微的差异，Hibernate Search 就能正常工作。

然而，当我们谈论一个 Hibernate 应用程序使用哪个 API 时，答案有两个部分。不仅有一个以上的方法将类映射到数据库，还有运行时查询数据库的选项。Hibernate ORM 有其传统的 API，基于`SessionFactory`和`Session`类。它还提供了一个对应 JPA 标准的实现，围绕`EntityManagerFactory`和`EntityManager`构建。

你可能会注意到，在迄今为止的示例代码中，我们一直使用 JPA 注解将类映射到数据库，并使用传统的 Hibernate `Session`类来查询它们。这可能一开始看起来有些令人困惑，但映射和查询 API 实际上是可互换的。你可以混合使用！

那么，在 Hibernate Search 项目中你应该使用哪种方法呢？尽可能坚持常见标准是有优势的。一旦你熟悉了 JPA，这些技能在你从事使用不同 JPA 实现的其他项目时是可以转移的。

另一方面，Hibernate ORM 的传统 API 比通用的 JPA 标准更强大。此外，Hibernate Search 是 Hibernate ORM 的扩展。在没有找到其他的搜索策略之前，你不能将一个项目迁移到一个不同的 JPA 实现。

### 注意

所以简而言之，尽可能使用 JPA 标准的论据是很强的。然而，Hibernate Search 本来就需要 Hibernate ORM，所以过于教条是没有意义的。在这本书中，大多数示例代码将使用 JPA 注解来映射类，并使用传统的 Hibernate `Session`类来进行查询。

# 使用 JPA 进行查询

虽然我们将重点放在传统的查询 API 上，但可下载的源代码还包含一个不同版本的示例应用程序，在`chapter3-entitymanager`文件夹中。这个 VAPORware Marketplace 变体展示了 JPA 全面使用的情况，用于映射和查询。

在搜索控制器 servlet 中，我们没有使用 Hibernate `SessionFactory`对象来创建`Session`对象，而是使用 JPA `EntityManagerFactory`实例来创建`EntityManager`对象：

```java
...
// The "com.packtpub.hibernatesearch.jpa" identifier is declared
// in "META-INF/persistence.xml"
EntityManagerFactory entityManagerFactory =
   Persistence.createEntityManagerFactory(
   "com.packtpub.hibernatesearch.jpa");
EntityManager entityManager =
   entityManagerFactory.createEntityManager();
...
```

我们已经看到了使用传统查询 API 的代码示例。在之前的示例中，Hibernate ORM 的`Session`对象被包裹在 Hibernate Search 的`FullTextSession`对象中。这些然后生成了实现核心`org.hibernate.Query`接口的 Hibernate `SearchFullTextQuery`对象：

```java
...
FullTextSession fullTextSession = Search.getFullTextSession(session);
...
org.hibernate.search.FullTextQuery hibernateQuery =
   fullTextSession.createFullTextQuery(luceneQuery, App.class);
...
```

与 JPA 相比，常规的`EntityManager`对象同样被`FullTextEntityManager`对象包装。这些创建了实现标准`javax.persistence.Query`接口的`FullTextQuery`对象：

```java
...
FullTextEntityManager fullTextEntityManager =
      org.hibernate.search.jpa.Search.getFullTextEntityManager(
      entityManager);
...
org.hibernate.search.jpa.FullTextQuery jpaQuery =
      fullTextEntityManager.createFullTextQuery(luceneQuery, App.class);
...
```

传统的`FullTextQuery`类及其 JPA 对应类非常相似，但它们是来自不同 Java 包的分开的类。两者都提供了大量我们迄今为止所看到的 Hibernate Search 功能的钩子，并将进一步探索。

### 小贴士

任何`FullTextQuery`版本都可以被强制转换为其相应的查询类型，尽管这样做会失去对 Hibernate Search 方法的直接访问。所以，在转换之前一定要调用任何扩展方法。

如果你在将 JPA 查询强制转换后需要访问非标准方法，那么你可以使用该接口的`unwrap()`方法回到底层的`FullTextQuery`实现。

# 为 Hibernate Search 和 JPA 设置项目

当你的基于 Maven 的项目包含了`hibernate-search`依赖时，它会自动为你拉取三十多个相关依赖。不幸的是，JPA 查询支持并不是其中之一。为了使用 JPA 风格的查询，我们必须自己声明一个额外的`hibernate-entitymanager`依赖。

它的版本需要与已经在依赖层次中`hibernate-core`的版本匹配。这不会总是与`hibernate-search`版本同步。

你的 IDE 可能提供了一种以视觉方式展示依赖层次的方法。无论如何，你总是可以用命令行 Maven 来用这个命令得到相同的信息：

```java
mvn dependency:tree
```

![为 Hibernate Search 和 JPA 设置项目](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hbn-srch-ex/img/9205_03_02.jpg)

如本输出所示，Hibernate Search 4.2.0.Final 使用核心 Hibernate ORM 4.1.9.Final 版本。因此，应该在 POM 中添加一个`hibernate-entitymanager`依赖，使用与核心相同的版本：

```java
...
<dependency>
   <groupId>org.hibernate</groupId>
   <artifactId>hibernate-entitymanager</artifactId>
   <version>4.1.9.Final</version>
</dependency>
...
```

# Hibernate Search DSL

第一章, *你的第一个应用程序*, 介绍了 Hibernate Search DSL，这是编写搜索查询的最直接方法。在使用 DSL 时，方法调用是以一种类似于编程语言的方式链接在一起的。如果你有在 Hibernate ORM 中使用标准查询的经验，那么这种风格会看起来非常熟悉。

无论你是使用传统的`FullTextSession`对象还是 JPA 风格的`FullTextEntityManager`对象，每个都传递了一个由`QueryBuilder`类生成的 Lucene 查询。这个类是 Hibernate Search DSL 的起点，并提供了几种 Lucene 查询类型。

## 关键字查询

我们已经简要了解的最基本的搜索形式是**关键词查询**。正如名称所暗示的，这种查询类型搜索一个或多个特定的单词。

第一步是获取一个`QueryBuilder`对象，该对象配置为对给定实体进行搜索：

```java
...
QueryBuilderqueryBuilder =
   fullTextSession.getSearchFactory().buildQueryBuilder()
      .forEntity(App.class ).get();
...
```

从那里，以下图表描述了可能的流程。虚线灰色箭头代表可选的侧路径：

![关键词查询](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hbn-srch-ex/img/9205OS_03_03.jpg)

关键词查询流程（虚线灰色箭头代表可选路径）

在实际的 Java 代码中，关键词查询的 DSL 将类似于以下内容：

```java
...
org.apache.lucene.search.Query luceneQuery =
 queryBuilder
 .keyword()
 .onFields("name", "description", "supportedDevices.name",
         "customerReviews.comments")
 .matching(searchString)
 .createQuery();
...
```

`onField`方法采用一个索引了相关实体的字段名称。如果该字段不包括在那个 Lucene 索引中，那么查询将失败。还可以搜索相关或内嵌对象字段，使用`"[container-field-name].[field-name]"`格式（例如，`supportedDevices.name`）。

选择性地，可以使用一个或多个`andField`方法来搜索多个字段。它的参数与`onField`完全一样工作。或者，您可以一次性通过`onFields`声明多个字段，如前面的代码片段所示。

匹配方法采用要进行查询的关键词。这个值通常是一个字符串，尽管从技术上讲，参数类型是一个泛型对象，以防您使用字段桥（下一章讨论）。假设您传递了一个字符串，它可能是一个单独的关键词或由空白字符分隔的一系列关键词。默认情况下，Hibernate Search 将分词字符串并分别搜索每个关键词。

最后，`createQuery`方法终止 DSL 并返回一个 Lucene 查询对象。该对象然后可以由`FullTextSession`（或`FullTextEntityManager`）用来创建最终的 Hibernate Search `FullTextQuery`对象：

```java
...
FullTextQuery hibernateQuery =
   fullTextSession.createFullTextQuery(luceneQuery, App.class);
...
```

### 模糊搜索

当我们今天使用搜索引擎时，我们默认它会智能到足以在我们“足够接近”正确拼写时修正我们的拼写错误。向 Hibernate Search 添加这种智能的一种方法是将普通关键词查询**模糊化**。

使用模糊搜索，关键词即使相差一个或多个字符也能与字段匹配。查询运行时有一个介于`0`到`1`之间的**阈值**，其中`0`意味着一切都匹配，而`1`意味着只接受精确匹配。查询的模糊度取决于您将阈值设置得多接近于零。

DSL 以相同的关键词方法开始，最终通过`onField`或`onFields`继续关键词查询流程。然而，在这两者之间有一些新的流程可能性，如下所示：

![模糊搜索](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hbn-srch-ex/img/9205OS_03_04.jpg)

模糊搜索流程（虚线灰色箭头代表可选路径）

模糊方法只是使普通关键词查询变得“模糊”，默认阈值值为`0.5`（例如，平衡两个极端之间）。您可以从那里继续常规关键词查询流程，这将完全没问题。

然而，您可以选择调用`withThreshold`来指定不同的模糊度值。在本章中，VAPORware Marketplace 应用程序的版本为关键词查询增加了模糊度，阈值设置为`0.7`。这个值足够严格以避免过多的假阳性，但足够模糊，以至于现在拼写错误的搜索“rodio”将匹配“Athena Internet Radio”应用程序。

```java
...
luceneQuery = queryBuilder
   .keyword()
 .fuzzy()
 .withThreshold(0.7f)
   .onFields("name", "description", "supportedDevices.name",
      "customerReviews.comments")
   .matching(searchString)
   .createQuery();
...
```

除了（或代替）`withThreshold`，您还可以使用`withPrefixLength`来调整查询的模糊度。这个整数值是在每个单词的开头您想要从模糊度计算中排除的字符数。

### 通配符搜索

关键词查询的第二个变体不涉及任何高级数学算法。如果您曾经使用过像`*.java`这样的模式来列出目录中的所有文件，那么您已经有了基本概念。

添加**通配符**方法使得普通关键词查询将问号（`?`）视为任何单个字符的有效替代品。例如，关键词`201?`将匹配字段值`2010`、`2011`、`2012`等。

星号（`*`）成为任何零个或多个字符序列的替代品。关键词`down*`匹配`download`、`downtown`等词汇。

Hibernate Search DSL 的通配符搜索与常规关键词查询相同，只是在最前面增加了零参数的`wildcard`方法。

![通配符搜索](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hbn-srch-ex/img/9205OS_03_05.jpg)

通配符搜索流程（虚线灰色箭头代表可选路径）

## 精确短语查询

当你在搜索引擎中输入一组关键词时，你期望看到匹配其中一个或多个关键词的结果。每个结果中可能不都包含所有关键词，它们可能不会按照你输入的顺序出现。

然而，现在已经习惯于当你将字符串用双引号括起来时，你期望搜索结果包含这个确切的短语。

Hibernate Search DSL 为这类搜索提供了**短语查询**流程。

![精确短语查询](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hbn-srch-ex/img/9205OS_03_06.jpg)

精确短语查询流程（虚线灰色箭头代表可选路径）

`onField`和`andField`方法的行为与关键词查询相同。`sentence`方法与`matching`的区别在于，其输入必须是`String`。

短语查询可以通过使用可选的`withSlop`子句来实现一种模糊性。该方法接受一个整数参数，代表在短语内可以找到的“额外”单词数，在达到这个数量之前，短语仍被视为匹配。

本章中 VAPORware Marketplace 应用程序的版本现在会检查用户搜索字符串周围是否有双引号。当输入被引号括起来时，应用程序将关键词查询替换为短语查询：

```java
...
luceneQuery = queryBuilder
 .phrase()
   .onField("name")
   .andField("description")
   .andField("supportedDevices.name")
   .andField("customerReviews.comments")
   .sentence(searchStringWithQuotesRemoved)
   .createQuery();
...
```

## 范围查询

短语查询和各种关键词搜索类型，都是关于将字段匹配到搜索词。**范围查询**有点不同，因为它寻找被一个或多个搜索词限定的字段。也就是说，一个字段是大于还是小于给定值，还是在大于或小于两个值之间？

![范围查询](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hbn-srch-ex/img/9205OS_03_07.jpg)

范围查询流程（虚线灰色箭头代表可选路径）

当使用前述方法时，查询的字段必须大于或等于输入参数的值。这个参数是通用的`Object`类型，以增加灵活性。通常使用日期和数字值，尽管字符串也非常合适，并且会根据字母顺序进行比较。

正如你可能会猜到的，下一个方法是一个对应的方法，其中的值必须小于或等于输入参数。要声明匹配必须在两个参数之间，包括这两个参数，你就得使用`from`和`to`方法（它们必须一起使用）。

可以对这些子句中的任何一个应用`excludeLimit`子句。它的作用是将范围变为排他而非包含。换句话说，`from(5).to(10).excludeLimit()`匹配一个`5 <= x < 10`的范围。修改器可以放在`from`子句上，而不是`to`，或者同时放在两个上。

在我们的 VAPORware Marketplace 应用程序中，我们之前拒绝为`CustomerReview.stars`标注索引。然而，如果我们用`@Field`标注它，那么我们就可以用类似于以下的查询来搜索所有 4 星和 5 星的评论：

```java
...
luceneQuery = queryBuilder
   .range()
   .onField("customerReviews.stars")
   .above(3).excludeLimit()
   .createQuery();
...
```

## 布尔（组合）查询

如果你有一个高级用例，其中关键词、短语或范围查询本身不够，但两个或更多组合在一起能满足你的需求，那怎么办？Hibernate Search 允许你用布尔逻辑混合任何查询组合：

![布尔（组合）查询](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hbn-srch-ex/img/9205OS_03_08.jpg)

布尔查询流程（虚线灰色箭头代表可选路径）

`bool`方法声明这将是一个组合查询。它后面至少跟着一个`onemust`或应该`clause`，每一个都接受一个前面讨论过的各种类型的 Lucene 查询对象。

当使用`must`子句时，一个字段必须与嵌套查询匹配，才能整体匹配查询。可以应用多个`must`子句，它们以**逻辑与**的方式操作。它们都必须成功，否则就没有匹配。

可选的`not`方法用于逻辑上否定一个`must`子句。效果是，整个查询只有在那个嵌套查询不匹配时才会匹配。

`should`子句大致相当于**逻辑或**操作。当一个组合只由`should`子句组成时，一个字段不必匹配它们全部。然而，为了使整个查询匹配，至少必须有一个匹配。

### 注意

你可以组合`must`和`should`子句。然而，如果你这样做，那么`should`嵌套查询就变得完全可选了。如果`must`子句成功，整体查询无论如何都会成功。如果`must`子句失败，整体查询无论如何都会失败。当两种子句类型一起使用时，`should`子句只起到帮助按相关性排名搜索结果的作用。

这个例子结合了一个关键词查询和一个范围查询，以查找拥有 5 星客户评价的"xPhone"应用程序：

```java
...
luceneQuery = queryBuilder
 .bool()
 .must(
      queryBuilder.keyword().onField("supportedDevices.name")
      .matching("xphone").createQuery()
   )
 .must(
      queryBuilder.range().onField("customerReviews.stars")
      .above(5).createQuery()
   )
   .createQuery();
...
```

# 排序

默认情况下，搜索结果按照它们的“相关性”排序返回。换句话说，它们是根据它们与查询的匹配程度进行排名的。我们将在接下来的两章中进一步讨论这一点，并学习如何调整这些相关性计算。

然而，我们有选项可以完全改变排序的其他标准。在典型情况下，你可能会按照日期或数字字段，或者按照字母顺序的字符串字段进行排序。在 VAPORware Marketplace 应用程序的的所有版本中，用户现在可以按照应用程序名称对他们的搜索结果进行排序。

要对一个字段进行排序，当这个字段被映射为 Lucene 索引时，需要特别考虑。通常当一个字符串字段被索引时，默认分析器（在下一章中探讨）会将字符串分词。例如，如果一个`App`实体的`name`字段是"Frustrated Flamingos"，那么在 Lucene 索引中会为"frustrated"和"flamingos"创建单独的条目。这允许进行更强大的查询，但我们希望基于原始未分词的值进行排序。

支持这种情况的一个简单方法是将字段映射两次，这是完全可行的！正如我们在第二章中看到的，*映射实体类*，Hibernate Search 提供了一个复数`@Fields`注解。它包含一个由逗号分隔的`@Field`注解列表，具有不同的分析器设置。

在下面的代码片段中，一个`@Field`被声明为默认的分词设置。第二个则将它的`analyze`元素设置为`Analyze.NO`，以禁用分词，并在 Lucene 索引中给它自己的独立字段名称：

```java
...
@Column
@Fields({
   @Field,
 @Field(name="sorting_name", analyze=Analyze.NO)
})
private String name;
...
```

这个新字段名称可以用如下方式来构建一个 Lucene `SortField`对象，并将其附加到一个 Hibernate Search `FullTextQuery`对象上：

```java
import org.apache.lucene.search.Sort;
import org.apache.lucene.search.SortField;
...
Sort sort = new Sort(
   new SortField("sorting_name", SortField.STRING));
hibernateQuery.setSort(sort);  // a FullTextQuery object
```

当`hibernateQuery`后来返回一个搜索结果列表时，这个列表将按照应用程序名称进行排序，从 A 到 Z 开始。

反向排序也是可能的。`SortField`类还提供了一个带有第三个`Boolean`参数的构造函数。如果这个参数被设置为`true`，排序将以完全相反的方式进行（例如，从 Z 到 A）。

# 分页

当一个搜索查询返回大量的搜索结果时，一次性将它们全部呈现给用户通常是不受欢迎的（或者可能根本不可能）。一个常见的解决方案是分页，或者一次显示一个“页面”的搜索结果。

一个 Hibernate Search `FullTextQuery`对象有方法可以轻松实现分页：

```java
…
hibernateQuery.setFirstResult(10);
hibernateQuery.setMaxResults(5);
List<App> apps = hibernateQuery.list();
…
```

`setMaxResults` 方法声明了页面的最大大小。在前面的代码片段的最后一行，即使查询有数千个匹配项，apps 列表也将包含不超过五个 `App` 对象。

当然，如果代码总是抓取前五个结果，分页将不会很有用。我们还需要能够抓取下一页，然后是下一页，依此类推。因此 `setFirstResult` 方法告诉 Hibernate Search 从哪里开始。

例如，前面的代码片段从第十一个结果项开始（参数是 `10`，但结果是零索引的）。然后将查询设置为抓取下一个五个结果。因此，下一个传入请求可能会使用 `hibernateQuery.setFirstResult(15)`。

拼图的最后一片是知道有多少结果，这样你就可以为正确数量的页面进行规划：

```java
…
intresultSize = hibernateQuery.getResultSize();
…
```

`getResultSize` 方法比乍一看要强大，因为它只使用 Lucene 索引来计算数字。跨所有匹配行的常规数据库查询可能是一个非常资源密集的操作，但对于 Lucene 来说是一个相对轻量级的事务。

### 注意

本章示例应用程序的版本现在使用分页来显示搜索结果，每页最多显示五个结果。查看 `SearchServlet` 和 `search.jsp` 结果页面，了解它们如何使用结果大小和当前起始点来构建所需的“上一页”和“下一页”链接。

以下是 VAPORware Marketplace 更新的实际操作情况：

![分页](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hbn-srch-ex/img/9205_03_09.jpg)

# 总结

在本章中，我们探讨了 Hibernate Search 查询中最常见的用例。现在，无论 JPA 是整体使用、部分使用还是根本不使用，我们都可以与 Hibernate Search 一起工作。我们了解了 Hibernate Search DSL 提供的核心查询类型，并可以轻松地访问到它们的全部可能流程，而不是不得不浏览 Javadocs 来拼凑它们。

现在我们知道如何按特定字段对搜索结果进行升序或降序排序。对于大型结果集，我们可以现在对结果进行分页，以提高后端性能和前端用户体验。我们 VAPORware Marketplace 示例中的搜索功能现在大于或等于许多生产 Hibernate Search 应用程序。

在下一章中，我们将探讨更高级的映射技术，例如处理自定义数据类型和控制 Lucene 索引过程的详细信息。


# 第四章：高级映射

到目前为止，我们已经学习了将对象映射到 Lucene 索引的基本知识。我们看到了如何处理与相关实体和嵌入对象的关系。然而，可搜索的字段大多是简单的字符串数据。

在本章中，我们将探讨如何有效地映射其他数据类型。我们将探讨 Lucene 为索引分析实体以及可以自定义该过程的 Solr 组件的过程。我们将了解如何调整每个字段的重要性，使按相关性排序更有意义。最后，我们将根据运行时实体的状态条件性地确定是否索引实体。

# 桥梁

Java 类中的成员变量可能是无数的自定义类型。通常，您也可以在自己的数据库中创建自定义类型。使用 Hibernate ORM，有数十种基本类型，可以构建更复杂的类型。

然而，在 Lucene 索引中，一切最终都归结为字符串。当你为搜索映射其他数据类型的字段时，该字段被转换为字符串表示。在 Hibernate Search 术语中，这种转换背后的代码称为桥梁。默认桥梁为您处理大多数常见情况，尽管您有能力为自定义场景编写自己的桥梁。

## 一对一自定义转换

最常见的映射场景是一个 Java 属性与一个 Lucene 索引字段绑定。`String`变量显然不需要任何转换。对于大多数其他常见数据类型，它们作为字符串的表达方式相当直观。

### 映射日期字段

`Date`值被调整为 GMT 时间，然后以`yyyyMMddHHmmssSSS`的格式存储为字符串。

尽管这一切都是自动发生的，但你确实可以选择显式地将字段注解为`@DateBridge`。当你不想索引到确切的毫秒时，你会这样做。这个注解有一个必需的元素`resolution`，让你从`YEAR`、`MONTH`、`DAY`、`HOUR`、`MINUTE`、`SECOND`或`MILLISECOND`（正常默认）中选择一个粒度级别。

可下载的`chapter4`版本的 VAPORware Marketplace 应用现在在`App`实体中添加了一个`releaseDate`字段。它被配置为仅存储日期，而不存储具体的一天中的任何时间。

```java
...
@Column
@Field
@DateBridge(resolution=Resolution.DAY)
private Date releaseDate;
...
```

### 处理 null 值

默认情况下，无论其类型如何，带有 null 值的字段都不会被索引。然而，您也可以自定义这种行为。`@Field`注解有一个可选元素`indexNullAs`，它控制了映射字段的 null 值的处理。

```java
...
@Column
@Field(indexNullAs=Field.DEFAULT_NULL_TOKEN)
private String description;
...
```

此元素的默认设置是`Field.DO_NOT_INDEX_NULL`，这导致 null 值在 Lucene 索引中被省略。然而，当使用`Field.DEFAULT_NULL_TOKEN`时，Hibernate Search 将使用一个全局配置的值索引该字段。

这个值的名称是`hibernate.search.default_null_token`，它是在`hibernate.cfg.xml`（对于传统的 Hibernate ORM）或`persistence.xml`（对于作为 JPA 提供者的 Hibernate）中设置的。如果这个值没有配置，那么空字段将被索引为字符串`"_null_"`。

### 注意

您可以使用这个机制对某些字段进行空值替换，而保持其他字段的行为。然而，`indexNullAs`元素只能与在全局级别配置的那个替代值一起使用。如果您想要为不同的字段或不同的场景使用不同的空值替代，您必须通过自定义桥接实现那个逻辑（在下一小节中讨论）。

### 自定义字符串转换

有时您需要在将字段转换为字符串值方面具有更多的灵活性。而不是依赖内置的桥接自动处理，您可以创建自己的自定义桥接。

#### StringBridge

要将对单个 Java 属性的映射映射到一个索引字段上，您的桥接可以实现 Hibernate Search 提供的两个接口中的一个。第一个，`StringBridge`，是为了在属性和字符串值之间进行单向翻译。

假设我们的`App`实体有一个`currentDiscountPercentage`成员变量，表示该应用程序正在提供的任何促销折扣（例如，*25% 折扣!*）。为了更容易进行数学运算，这个字段被存储为浮点数(*0.25f*)。然而，如果我们想要使折扣可搜索，我们希望它们以更易读的百分比格式(*25*)进行索引。

为了提供这种映射，我们首先需要创建一个桥接类，实现`StringBridge`接口。桥接类必须实现一个`objectToString`方法，该方法期望将我们的`currentDiscountPercentage`属性作为输入参数：

```java
import org.hibernate.search.bridge.StringBridge;

/** Converts values from 0-1 into percentages (e.g. 0.25 -> 25) */
public class PercentageBridge implements StringBridge {
   public String objectToString(Object object) {
      try {
         floatfieldValue = ((Float) object).floatValue();
         if(fieldValue< 0f || fieldValue> 1f) return "0";
         int percentageValue = (int) (fieldValue * 100);
 return Integer.toString(percentageValue);
      } catch(Exception e) {
         // default to zero for null values or other problems
 return "0";
      }
   }

}
```

`objectToString`方法按照预期转换输入，并返回其`String`表示。这将是由 Lucene 索引的值。

### 注意

请注意，当给定一个空值时，或者当遇到任何其他问题时，这个方法返回一个硬编码的`"0"`。自定义空值处理是创建字段桥接的另一个可能原因。

要在索引时间调用这个桥接类，请将`@FieldBridge`注解添加到`currentDiscountPercentage`属性上：

```java
...
@Column
@Field
@FieldBridge(impl=PercentageBridge.class)
private float currentDiscountPercentage;
...

```

### 注意

这个实体字段是一个原始`float`，然而桥接类却在与一个`Float`包装对象一起工作。为了灵活性，`objectToString`接受一个泛型`Object`参数，该参数必须转换为适当的类型。然而，多亏了自动装箱，原始值会自动转换为它们的对象包装器。

#### TwoWayStringBridge

第二个接口用于将单个变量映射到单个字段，`TwoWayStringBridge`，提供双向翻译，在值及其字符串表示之间进行翻译。

实现`TwoWayStringBridge`的方式与刚刚看到的常规`StringBridge`接口类似。唯一的区别是，这个双向版本还要求有一个`stringToObject`方法，用于反向转换：

```java
...
public Object stringToObject(String stringValue) {
   return Float.parseFloat(stringValue) / 100;
}
...
```

### 提示

只有在字段将成为 Lucene 索引中的`ID`字段（即，用`@Id`或`@DocumentId`注解）时，才需要双向桥。

#### 参数化桥

为了更大的灵活性，可以向桥接类传递配置参数。为此，您的桥接类应该实现`ParameterizedBridge`接口，以及`StringBridge`或`TwoWayStringBridge`。然后，该类必须实现一个`setParameterValues`方法来接收这些额外的参数。

为了说明问题，假设我们想让我们的示例桥接能够以更大的精度写出百分比，而不是四舍五入到整数。我们可以传递一个参数，指定要使用的小数位数：

```java
public class PercentageBridge implements StringBridge,
 ParameterizedBridge {

 public static final String DECIMAL_PLACES_PROPERTY =
 "decimal_places";
 private int decimalPlaces = 2;  // default

   public String objectToString(Object object) {
      String format = "%." + decimalPlaces + "g%n";
      try {
         float fieldValue = ((Float) object).floatValue();
         if(fieldValue< 0f || fieldValue> 1f) return "0";
         return String.format(format, (fieldValue * 100f));
      } catch(Exception e) {
         return String.format(format, "0");
      }
   }
 public void setParameterValues(Map<String, String> parameters) {
      try {
         this.decimalPlaces = Integer.parseInt(
            parameters.get(DECIMAL_PLACES_PROPERTY) );
      } catch(Exception e) {}
   }

}
```

我们桥接类的这个版本期望收到一个名为`decimal_places`的参数。它的值存储在`decimalPlaces`成员变量中，然后在`objectToString`方法中使用。如果没有传递这样的参数，那么将使用两个小数位来构建百分比字符串。

`@FieldBridge`注解中的`params`元素是实际传递一个或多个参数的机制：

```java
...
@Column
@Field
@FieldBridge(
   impl=PercentageBridge.class,
 params=@Parameter(
 name=PercentageBridge.DECIMAL_PLACES_PROPERTY, value="4")
)
private float currentDiscountPercentage;
...
```

### 注意

请注意，所有`StringBridge`或`TwoWayStringBridge`的实现都必须是线程安全的。通常，您应该避免任何共享资源，并且只通过`ParameterizedBridge`参数获取额外信息。

## 使用 FieldBridge 进行更复杂的映射

迄今为止所涵盖的桥接类型是将 Java 属性映射到字符串索引值的最简单、最直接的方法。然而，有时您需要更大的灵活性，因此有一些支持自由形式的字段桥接变体。

### 将单个变量拆分为多个字段

有时，类属性与 Lucene 索引字段之间的期望关系可能不是一对一的。例如，假设一个属性表示文件名。然而，我们希望能够不仅通过文件名搜索，还可以通过文件类型（即文件扩展名）搜索。一种方法是从文件名属性中解析文件扩展名，从而使用这个变量创建两个字段。

`FieldBridge`接口允许我们这样做。实现必须提供一个`set`方法，在这个例子中，它从文件名字段中解析文件类型，并将其分别存储：

```java
import org.apache.lucene.document.Document;
import org.hibernate.search.bridge.FieldBridge;
import org.hibernate.search.bridge.LuceneOptions;

public class FileBridge implements FieldBridge {

 public void set(String name, Object value, 
 Document document, LuceneOptionsluceneOptions) {
      String file = ((String) value).toLowerCase();
      String type = file.substring(
      file.indexOf(".") + 1 ).toLowerCase();
 luceneOptions.addFieldToDocument(name+".file", file, document);
 luceneOptions.addFieldToDocument(name+".file_type", type, 
 document);
   }

}
```

`luceneOptions`参数是与 Lucene 交互的帮助对象，`document`表示我们正在添加字段的 Lucene 数据结构。我们使用`luceneOptions.addFieldToDocument()`将字段添加到索引，而不必完全理解 Lucene API 的细节。

传递给`set`的`name`参数代表了被索引的实体名称。注意我们用这个作为基础来声明要添加的两个实体的名称（也就是说，对于文件名，使用`name+".file"`；对于文件类型，使用`name+".file_type"`）。

最后，`value` 参数是指当前正在映射的字段。就像在`Bridges`部分看到的`StringBridge`接口一样，这里的函数签名使用了一个通用的`Object`以提高灵活性。必须将值转换为其适当的类型。

要应用`FieldBridge`实现，就像我们已经看到的其他自定义桥接类型一样，使用`@FieldBridge`注解：

```java
...
@Column
@Field
@FieldBridge(impl=FileBridge.class)
private String file;
...
```

### 将多个属性合并为一个字段

实现`FieldBridge`接口的自定义桥接也可以用于相反的目的，将多个属性合并为一个索引字段。为了获得这种灵活性，桥接必须应用于*类*级别而不是*字段*级别。当以这种方式使用`FieldBridge`接口时，它被称为**类桥接**，并替换了整个实体类的常规映射机制。

例如，考虑我们在 VAPORware Marketplace 应用程序中处理`Device`实体时可以采取的另一种方法。而不是将`manufacturer`和`name`作为单独的字段进行索引，我们可以将它们合并为一个`fullName`字段。这个类桥接仍然实现`FieldBridge`接口，但它会将两个属性合并为一个索引字段，如下所示：

```java
public class DeviceClassBridge implements FieldBridge {

   public void set(String name, Object value, 
         Document document, LuceneOptionsluceneOptions) {
      Device device = (Device) value;
      String fullName = device.getManufacturer()
         + " " + device.getName();
 luceneOptions.addFieldToDocument(name + ".name", 
 fullName, document);
   }

}
```

而不是在`Device`类的任何特定字段上应用注解，我们可以在类级别应用一个`@ClassBridge`注解。注意字段级别的 Hibernate Search 注解已经被完全移除，因为类桥接将负责映射这个类中的所有索引字段。

```java
@Entity
@Indexed
@ClassBridge(impl=DeviceClassBridge.class)
public class Device {

   @Id
   @GeneratedValue
   private Long id;

   @Column
   private String manufacturer;

   @Column
   private String name;

   // constructors, getters and setters...
}

```

### TwoWayFieldBridge

之前我们看到了简单的`StringBridge`接口有一个`TwoWayStringBridge`对应接口，为文档 ID 字段提供双向映射能力。同样，`FieldBridge`接口也有一个`TwoWayFieldBridge`对应接口出于相同原因。当你将字段桥接接口应用于 Lucene 用作 ID 的属性（即，用`@Id`或`@DocumentId`注解）时，你必须使用双向变体。

`TwoWayStringBridge`接口需要与`StringBridge`相同的`objectToString`方法，以及与`FieldBridge`相同的`set`方法。然而，这个双向版本还需要一个`get`对应方法，用于从 Lucene 检索字符串表示，并在真实类型不同时进行转换：

```java
...
public Object get(String name, Object value, Document document) {
   // return the full file name field... the file type field
   // is not needed when going back in the reverse direction
   return = document.get(name + ".file");
}
public String objectToString(Object object) {
   // "file" is already a String, otherwise it would need conversion
      return object;
}
...
```

# 分析

当一个字段被 Lucene 索引时，它会经历一个称为**分析**的解析和转换过程。在第三章《执行查询》中，我们提到了默认的**分析器**会分词字符串字段，如果你打算对该字段进行排序，则应该禁用这种行为。

然而，在分析过程中可以实现更多功能。Apache Solr 组件可以组装成数百种组合。 它们可以在索引过程中以各种方式操纵文本，并打开一些非常强大的搜索功能的大门。

为了讨论可用的 Solr 组件，或者如何将它们组装成自定义分析器定义，我们首先必须了解 Lucene 分析的三个阶段：

+   字符过滤

+   标记化

+   标记过滤

分析首先通过应用零个或多个**字符过滤器**进行，这些过滤器在处理之前去除或替换字符。 过滤后的字符串然后进行**标记化**，将其拆分为更小的标记，以提高关键字搜索的效率。 最后，零个或多个**标记过滤器**在将它们保存到索引之前去除或替换标记。

### 注意

这些组件由 Apache Solr 项目提供，总共有三十多个。 本书无法深入探讨每一个，但我们可以查看三种类型的一些关键示例，并了解如何一般地应用它们。

所有这些 Solr 分析器组件的完整文档可以在[`wiki.apache.org/solr/AnalyzersTokenizersTokenFilters`](http://wiki.apache.org/solr/AnalyzersTokenizersTokenFilters)找到，Javadocs 在[`lucene.apache.org/solr/api-3_6_1`](http://lucene.apache.org/solr/api-3_6_1)。

## 字符过滤

定义自定义分析器时，字符过滤是一个可选步骤。如果需要此步骤，只有三种字符过滤类型可用：

+   `MappingCharFilterFactory`：此过滤器将字符（或字符序列）替换为特定定义的替换文本，例如，您可能会将*1*替换为*one*，*2*替换为*two*，依此类推。

    字符（或字符序列）与替换值之间的映射存储在一个资源文件中，该文件使用标准的`java.util.Properties`格式，位于应用程序的类路径中的某个位置。对于每个属性，键是查找的序列，值是映射的替换。

    这个映射文件相对于类路径的位置被传递给`MappingCharFilterFactory`定义，作为一个名为`mapping`的参数。传递这个参数的确切机制将在*定义和选择分析器*部分中详细说明。

+   `PatternReplaceCharFilter`：此过滤器应用一个通过名为`pattern`的参数传递的正则表达式。 任何匹配项都将用通过`replacement`参数传递的静态文本字符串替换。

+   `HTMLStripCharFilterFactory`：这个极其有用的过滤器移除 HTML 标签，并将转义序列替换为其通常的文本形式（例如，`&gt;`变成`>`）。

## 标记化

在定义自定义分析器时，字符和标记过滤器都是可选的，您可以组合多种过滤器。然而，`tokenizer`组件是唯一的。分析器定义必须包含一个，最多一个。

总共有 10 个`tokenizer`组件可供使用。一些说明性示例包括：

+   `WhitespaceTokenizerFactory`：这个组件只是根据空白字符分割文本。例如，*hello world* 被分词为 *hello* 和 *world*。

+   `LetterTokenizerFactory`：这个组件的功能与`WhitespaceTokenizrFactory`类似，但这个分词器还会在非字母字符处分割文本。非字母字符完全被丢弃，例如，*please don't go*被分词为*please*, *don*, *t*, 和 *go*。

+   `StandardTokenizerFactory`：这是默认的`tokenizer`，在未定义自定义分析器时自动应用。它通常根据空白字符分割，丢弃多余字符。例如，*it's 25.5 degrees outside!!!* 变为 *it's*, *25.5*, *degrees*, 和 *outside*。

### 小贴士

当有疑问时，`StandardTokenizerFactory`几乎总是合理的选择。

## 分词过滤器

到目前为止，分析器功能的最大多样性是通过分词过滤器实现的，Solr 提供了二十多个选项供单独或组合使用。以下是更有用的几个示例：

+   `StopFilterFactory`：这个过滤器简单地丢弃“停用词”，或者根本没有人想要对其进行关键词查询的极其常见的词。列表包括 *a*, *the*, *if*, *for*, *and*, *or* 等（Solr 文档列出了完整列表）。

+   `PhoneticFilterFactory`：当你使用主流搜索引擎时，你可能会注意到它在处理你的拼写错误时非常智能。这样做的一种技术是寻找与搜索关键字听起来相似的单词，以防它被拼写错误。例如，如果你本想搜索*morning*，但误拼为*mourning*，搜索仍然能匹配到意图的词条！这个分词过滤器通过与实际分词一起索引音似字符串来实现这一功能。该过滤器需要一个名为`encoder`的参数，设置为支持的字符编码算法名称（`"DoubleMetaphone"`是一个合理的选择）。

+   `SnowballPorterFilterFactory`：词干提取是一个将分词转化为其根形式的过程，以便更容易匹配相关词汇。Snowball 和 Porter 指的是词干提取算法。例如，单词 *developer* 和 *development* 都可以被分解为共同的词干 *develop*。因此，Lucene 能够识别这两个较长词汇之间的关系（即使没有一个词汇是另一个的子串！）并能返回两个匹配项。这个过滤器有一个参数，名为 `language`（例如，`"English"`）。

## 定义和选择分析器

**分析器定义**将一些这些组件的组合成一个逻辑整体，在索引实体或单个字段时可以引用这个整体。分析器可以在静态方式下定义，也可以根据运行时的一些条件动态地组装。

### 静态分析器选择

定义自定义分析器的任何方法都以在相关持久类上的`@AnalyzerDef`注解开始。在我们的`chapter4`版本的 VAPORware Marketplace 应用程序中，让我们定义一个自定义分析器，用于与`App`实体的`description`字段一起使用。它应该移除任何 HTML 标签，并应用各种分词过滤器以减少杂乱并考虑拼写错误：

```java
...
@AnalyzerDef(
 name="appAnalyzer",
 charFilters={    
      @CharFilterDef(factory=HTMLStripCharFilterFactory.class) 
   },
 tokenizer=@TokenizerDef(factory=StandardTokenizerFactory.class),
 filters={ 
      @TokenFilterDef(factory=StandardFilterFactory.class),
      @TokenFilterDef(factory=StopFilterFactory.class),
      @TokenFilterDef(factory=PhoneticFilterFactory.class, 
            params = {
         @Parameter(name="encoder", value="DoubleMetaphone")
            }),
      @TokenFilterDef(factory=SnowballPorterFilterFactory.class, 
            params = {
      @Parameter(name="language", value="English") 
      })
   }
)
...
```

`@AnalyzerDef`注解必须有一个名称元素设置，正如之前讨论的，分析器必须始终包括一个且只有一个分词器。

`charFilters`和`filters`元素是可选的。如果设置，它们分别接收一个或多个工厂类列表，用于字符过滤器和分词过滤器。

### 提示

请注意，字符过滤器和分词过滤器是按照它们列出的顺序应用的。在某些情况下，更改顺序可能会影响最终结果。

`@Analyzer`注解用于选择并应用一个自定义分析器。这个注解可以放在个别字段上，或者放在整个类上，影响每个字段。在这个例子中，我们只为`desciption`字段选择我们的分析器定义：

```java
...
@Column(length = 1000)
@Field
@Analyzer(definition="appAnalyzer")
private String description;
...
```

在一个类中定义多个分析器是可能的，通过将它们的`@AnalyzerDef`注解包裹在一个复数`@AnalyzerDefs`中来实现：

```java
...
@AnalyzerDefs({
   @AnalyzerDef(name="stripHTMLAnalyzer", ...),
   @AnalyzerDef(name="applyRegexAnalyzer", ...)
})
...
```

显然，在后来应用`@Analyzer`注解的地方，其定义元素必须与相应的`@AnalyzerDef`注解的名称元素匹配。

### 注意

`chapter4`版本的 VAPORware Marketplace 应用程序现在会从客户评论中移除 HTML。如果搜索包括关键词*span*，例如，不会在包含`<span>`标签的评论中出现假阳性匹配。

Snowball 和音译过滤器被应用于应用描述中。关键词*mourning*找到包含单词*morning*的匹配项，而*development*的搜索返回了描述中包含*developers*的应用程序。

### 动态分析器选择

可以等到运行时为字段选择一个特定的分析器。最明显的场景是一个支持不同语言的应用程序，为每种语言配置了分析器定义。您希望根据每个对象的言语属性选择适当的分析器。

为了支持这种动态选择，对特定的字段或整个类添加了`@AnalyzerDiscriminator`注解。这个代码段使用了后者的方法：

```java
@AnalyzerDefs({
   @AnalyzerDef(name="englishAnalyzer", ...),
   @AnalyzerDef(name="frenchAnalyzer", ...)
})
@AnalyzerDiscriminator(impl=CustomerReviewDiscriminator.class)
public class CustomerReview {
   ...
   @Field
   private String language;
   ...
}
```

有两个分析器定义，一个是英语，另一个是法语，类`CustomerReviewDiscriminator`被宣布负责决定使用哪一个。这个类必须实现`Discriminator`接口，并它的`getAnalyzerDefinitionName`方法：

```java
public class LanguageDiscriminator implements Discriminator {

 public String getAnalyzerDefinitionName(Object value, 
 Object entity, String field) {
      if( entity == null || !(entity instanceofCustomerReview) ) {
         return null;
      }
      CustomerReview review = (CustomerReview) entity;
      if(review.getLanguage() == null) {
         return null;
       } else if(review.getLanguage().equals("en")) {
         return "englishAnalyzer";
       } else if(review.getLanguage().equals("fr")) {
         return "frenchAnalyzer";
       } else {
         return null;
      }
   }

}
```

如果`@AnalyzerDiscriminator`注解放在字段上，那么其当前对象的值会自动作为第一个参数传递给`getAnalyzerDefinitionName`。如果注解放在类本身上，则传递`null`值。无论如何，第二个参数都是当前实体对象。

在这种情况下，鉴别器应用于类级别。所以我们将第二个参数转换为`CustomerReview`类型，并根据对象的`language`字段返回适当的分析器名称。如果语言未知或存在其他问题，则该方法简单地返回`null`，告诉 Hibernate Search 回退到默认分析器。

# 提升搜索结果的相关性

我们已经知道，搜索结果的默认排序顺序是按相关性，即它们与查询匹配的程度。如果一个实体在两个字段上匹配，而另一个只有一个字段匹配，那么第一个实体是更相关的结果。

Hibernate Search 允许我们通过在索引时调整实体或字段的相对重要性来调整相关性**提升**。这些调整可以是静态和固定的，也可以是动态的，由运行时数据状态驱动。

## 索引时间的静态提升

固定的提升，无论实际数据如何，都像注解一个类或字段一样简单，只需要使用`@Boost`。这个注解接受一个浮点数参数作为其相对权重，默认权重为 1.0\。所以，例如，`@Boost(2.0f)`会将一个类或字段的权重相对于未注解的类和字段加倍。

我们的 VAPORware Marketplace 应用程序在几个字段和关联上进行搜索，比如支持设备的名称，以及客户评论中的评论。然而，文本应该比来自外部各方的文本更重要，这难道不是合情合理的吗？（每个应用的名称和完整描述）

为了进行此调整，`chapter4`版本首先注释了`App`类本身：

```java
...
@Boost(2.0f)
public class App implements Serializable {
...
```

这实际上使得`App`的权重是`Device`或`CustomerReview`的两倍。接下来，我们对名称和完整描述字段应用字段级提升：

```java
...
@Boost(1.5f)
private String name;
...
@Boost(1.2f)
private String description;
...
```

我们在这里声明`name`的权重略高于`description`，并且它们相对于普通字段都带有更多的权重。

### 注意

请注意，类级别和字段级别的提升是级联和结合的！当给定字段应用多个提升因子时，它们会被乘以形成总因子。

在这里，因为已经对`App`类本身应用了 2.0 的权重，`name`的总有效权重为 3.0，`description`为 2.4。

## 索引时间的动态提升

让我们假设我们希望在评论者给出五星评价时，给`CustomerReview`对象更多的权重。为此，我们在类上应用一个`@DynamicBoost`注解：

```java
...
@DynamicBoost(impl=FiveStarBoostStrategy.class)
public class CustomerReview {
...
```

这个注解必须传递一个实现`BoostStrategy`接口的类，以及它的`defineBoost`方法：

```java
public class FiveStarBoostStrategy implements BoostStrategy {

 public float defineBoost(Object value) {
      if(value == null || !(value instanceofCustomerReview)) {
         return 1;
      }
      CustomerReviewcustomerReview = (CustomerReview) value;
      if(customerReview.getStars() == 5) {
         return 1.5f;
      } else {
         return 1;
      }
   }

}
```

当`@DynamicBoost`注解应用于一个类时，传递给`defineBoost`的参数自动是该类的一个实例（在这个例子中是一个`CustomerReview`对象）。如果注解是应用于一个特定的字段，那么自动传递的参数将是那个字段的值。

`defineBoost`返回的`float`值变成了被注解的类或字段的权重。在这个例子中，当`CustomerReview`对象代表一个五星评论时，我们将它的权重增加到 1.5。否则，我们保持默认的 1.0。

# 条件索引

字段索引有专门的处理方式，比如使用类桥接或程序化映射 API。总的来说，当一个属性被注解为`@Field`时，它就会被索引。因此，避免索引字段的一个明显方法就是简单地不应用这个注解。

然而，如果我们希望一个实体类通常可被搜索，但我们需要根据它们数据在运行时的状态排除这个类的某些实例怎么办？

`@Indexed`注解有一个实验性的第二个元素`interceptor`，它给了我们条件索引的能力。当这个元素被设置时，正常的索引过程将被自定义代码拦截，这可以根据实体的当前状态阻止实体被索引。

让我们给我们的 VAPORware Marketplace 添加使应用失效的能力。失效的应用仍然存在于数据库中，但不应该向客户展示或进行索引。首先，我们将向`App`实体类添加一个新属性：

```java
...
@Column
private boolean active;
...
public App(String name, String image, String description) {
   this.name = name;
   this.image = image;
   this.description = description;
 this.active = true;
}
...
public booleanisActive() {
   return active;
}
public void setActive(boolean active) {
   this.active = active;
}
...
```

这个新的`active`变量有标准的 getter 和 setter 方法，并且在我们的正常构造函数中被默认为`true`。我们希望在`active`变量为`false`时，个别应用被排除在 Lucene 索引之外，所以我们给`@Indexed`注解添加了一个`interceptor`元素：

```java
...
import com.packtpub.hibernatesearch.util.IndexWhenActiveInterceptor;
...
@Entity
@Indexed(interceptor=IndexWhenActiveInterceptor.class)
public class App {
...
```

这个元素必须绑定到一个实现`EntityIndexingInterceptor`接口的类上。由于我们刚刚指定了一个名为`IndexWhenActiveInterceptor`的类，所以我们现在需要创建这个类。

```java
package com.packtpub.hibernatesearch.util;

import org.hibernate.search.indexes.interceptor.EntityIndexingInterceptor;
import org.hibernate.search.indexes.interceptor.IndexingOverride;
import com.packtpub.hibernatesearch.domain.App;

public class IndexWhenActiveInterceptor
 implementsEntityIndexingInterceptor<App> {

   /** Only index newly-created App's when they are active */
 public IndexingOverrideonAdd(App entity) {
      if(entity.isActive()) {
         return IndexingOverride.APPLY_DEFAULT;
      }
      return IndexingOverride.SKIP;
   }
 public IndexingOverrideonDelete(App entity) {
      return IndexingOverride.APPLY_DEFAULT;
   }

   /** Index active App's, and remove inactive ones */
 public IndexingOverrideonUpdate(App entity) {
      if(entity.isActive()) {
         return IndexingOverride.UPDATE;
            } else {
         return IndexingOverride.REMOVE;
      }
   }

   public IndexingOverrideonCollectionUpdate(App entity) {
      retur nonUpdate(entity);
   }

}
```

`EntityIndexingInterceptor`接口声明了**四个方法**，Hibernate Search 会在实体对象的生命周期的不同阶段调用它们：

+   `onAdd()`: 当实体实例第一次被创建时调用。

+   `onDelete()`: 当实体实例从数据库中被移除时调用。

+   `onUpdate()`: 当一个现有实例被更新时调用。

+   `onCollectionUpdate()`: 当一个实体作为其他实体的批量更新的一部分被修改时使用这个版本。通常，这个方法的实现简单地调用`onUpdate()`。

这些方法中的每一个都应该返回`IndexingOverride`枚举的四种可能值之一。可能的**返回值**告诉 Hibernate Search 应该做什么：

+   `IndexingOverride.SKIP`：这告诉 Hibernate Search 在当前时间不要修改此实体实例的 Lucene 索引。

+   `IndexingOverride.REMOVE`：如果实体已经在索引中，Hibernate Search 将删除该实体；如果实体没有被索引，则什么也不做。

+   `IndexingOverride.UPDATE`：实体将在索引中更新，或者如果它还没有被索引，将被添加。

+   `IndexingOverride.APPLY_DEFAULT`：这等同于自定义拦截器根本没有被使用。Hibernate Search 将索引实体，如果这是一个`onAdd()`操作；如果这是一个`onDelete()`，则将其从索引中移除；或者如果这是`onUpdate()`或`onCollectionUpdate()`，则更新索引。

尽管这四种方法在逻辑上暗示了某些返回值，但实际上如果你处理的是异常情况，可以任意组合它们。

在我们的示例应用程序中，我们的拦截器在`onAdd()`和`onDelete()`中检查实体。当创建一个新的`App`时，如果其`active`变量为 false，则跳过索引。当`App`被更新时，如果它变得不活跃，它将被从索引中移除。

# 总结

在本章中，我们全面了解了为搜索而映射持久对象所提供的所有功能。现在我们可以调整 Hibernate Search 内置类型桥接的设置，并且可以创建高度先进的自定义桥接。

现在我们对 Lucene 分析有了更深入的了解。我们使用了一些最实用的自定义分析器组件，并且知道如何独立获取数十个其他 Solr 组件的信息。

我们现在可以通过提升来调整类和字段的相对权重，以在按相关性排序时提高我们的搜索结果质量。最后但同样重要的是，我们学会了如何使用条件索引动态地阻止某些数据根据其状态变得可搜索。

在下一章中，我们将转向更高级的查询概念。我们将学习如何过滤和分类搜索结果，并从 Lucene 中提取数据，而不需要数据库调用。
