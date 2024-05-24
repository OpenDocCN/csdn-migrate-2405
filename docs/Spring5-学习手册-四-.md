# Spring5 学习手册（四）

> 原文：[`zh.annas-archive.org/md5/6DF1C981F26DA121DCB8C1B33E7DE022`](https://zh.annas-archive.org/md5/6DF1C981F26DA121DCB8C1B33E7DE022)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

## 第七章。放心，试驾一下

应用开发是一个漫长、耗时且成本高昂的过程。开发依赖于从客户和市场收集的需求。但是，如果在工作完成后出了问题，一切都会崩溃呢？冲突并非由于解决方案错误，而是因为开发者在工作开始前基于错误的假设。这种冲突恰好在向客户交付日期前发生。现在什么都无法挽回了！我们不必深究为什么会出现问题和具体情况。但我感兴趣的是，这种情况可以避免吗？有没有什么方法可以在最后一刻避免这种冲突呢？我们总是听说“预防胜于治疗”。这个原则也适用于应用开发。通过开发人员逐步付出的少许额外努力，可以避免失败的状况。开发人员开发的代码进行交叉检查，以满足需求，这有助于确保代码的正确运行。这种交叉检查称为应用测试。在本章中，我们将通过以下几点深入讨论测试：

+   为什么测试？

+   测试 Spring 控制器的问题。

+   模拟测试。

+   春季测试上下文框架。

+   使用 Mokitoto 测试 Spring 控制器。

+   使用 Arquillian 介绍 Spring 控制器测试。

## 测试是一个重要的步骤

***

应用开发是一个昂贵且耗时长的过程。在最后的部署中出现的错误和失误会导致非常严重的后果。开发者根据需求编写的代码基于一些可能基于一些假设的规则。作为人类，我们可能在需求收集或假设制定上犯错误。如果这是我们完成的工作，还有谁比我们更了解它呢？单元测试测试代码，并帮助确保其正常运行。

开发者完成了开发。他们的开发基于一些假设，他们可能也会遗漏一些盲点。开发之后，他们进行测试。由同一个人进行测试是高风险的，因为他们可能会重复同样的错误。理想情况下，应该是其他人来做检查，确保他们知道他们在测试什么。

以下是一些使测试成为应用开发中难忘的一部分的主要因素：

+   它有助于尽早发现开发过程中产生的缺陷和错误。

+   它确保应用程序执行中的失败次数最少

+   它有助于提高应用程序的一致性

+   它有助于确保更好的应用程序质量

+   它通过检查认证和授权来提高安全性

+   帮助节省金钱，更重要的是节省时间

每个应用程序在发布之前都要经过严格的测试，以确保应用程序符合要求并确保其所有功能正确无误。单元测试、集成测试、系统测试和验收测试是每个应用程序必须通过的四个主要阶段。

### 单元测试

单元测试关注组件的单元，确保功能的正确性。单元可以指单个函数或过程。单元测试的主要目的是确保单元按设计工作。它允许快速解决提出的问题。由于单元是应用程序的最小部分，因此代码可以很容易地修改。通常由编写代码的开发者进行。

### 集成测试

一旦单元测试成功完成，测试单元时出现的大部分问题都已经修改以符合要求。集成测试提供了在程序执行内测试这些单元组的机会。它有助于确定多个单元是如何一起运行的。单元可能运行良好，但当与其他单元结合时，相同的单元可能会导致一些副作用，需要解决。集成测试有助于捕获此类错误，并有机会进行更正。

### 系统测试

在前两个阶段，已经对单个单元或单元之间的相互交互进行了测试。这是第一次全面测试完整应用程序的阶段。系统测试通常由独立测试员在接近生产环境中进行。系统测试确保应用程序开发的所有功能和业务要求是否已经满足。

### 用户验收测试

这是测试的最后阶段，它确定系统是否准备好最终发布。验收测试通常由最终用户执行，以确定应用程序符合要求并涵盖了所有必要的功能以给出最终验收。它使最终应用程序在生产环境中有了预览。

本章我们将分三个阶段进行单元测试、集成测试和系统测试。但在前进之前，让我们先了解一下市场上可用的测试工具的概况。

## 测试工具

* * *

以下是适用于 Java 平台的可用测试工具，

### JTest

JTest 是由 Parasoft 自 1997 年以来为 Java 平台开发的自动化软件测试、编码标准合规工具。该工具利用单元测试以及集成测试。该工具便于分析类，以与 JUnit 测试用例相同的格式生成和执行测试用例。

以下是一些 JTest 功能：

+   除了测试之外，它还涵盖了正常情况下开发者无法捕获的运行时异常。

+   该工具还验证类是否遵循**契约式设计**（**DbC**）基础。

+   它确保代码遵循 400 个标准编码规则，并将代码与 200 个违规规则进行比对。

+   它还可以识别功能错误、内存泄漏和安全漏洞等问题。

+   **Jcontract** 是 JTest 工具的一部分，它在集成测试期间验证功能需求，而不会影响应用程序的性能。

### **Grinder**

**Grinder** 是一个为 Java 编程语言设计的负载测试工具，遵循 BSD 风格的开放源代码许可。它的目标是简化使用负载注入机器进行的分布式测试。它具备负载测试、能力测试、功能测试和压力测试的能力。它对系统资源的要求最低，同时在其测试上下文中管理自己的线程，如果需要可以将其分割到不同的进程。

以下是 Grinder 的特点：

+   易于使用的基于 Java Swing 的用户界面

+   它可以用于具有 Java API 的任何负载测试。它可以用于 Web 服务器、基于 SOAP 和 Rest API 的 Web 服务、应用服务器等。

+   Jython 和 Clojure 语言支持编写灵活、动态的测试脚本。

+   它还管理客户端连接和 cookie。

### **JWalk**

**JWalk** 是一个为 Java 平台设计的单元测试工具，支持懒惰系统性单元测试范式。它由 Anthony Simons 开发。JWalk 通过“懒惰规格”和“系统性测试”的概念来测试单个类并生成测试报告。它更适合敏捷开发，在这种开发中不需要产生正式的规格说明。通过构建和展示自动化测试用例，它能节省大量时间和精力。

以下是 JWalk 的特点：

+   系统性地提出所有可能的测试用例。

+   测试人员无需确认测试结果的子集。

+   可以预测测试结果。

+   如果类被修改，它会生成新的测试用例。

+   适用于软件开发中的极限编程的 TDD。

### **PowerMock**

**PowerMock** 是一个开源项目，作为 EasyMock 和 Mokito 框架的扩展，通过添加一些方法和注解来实现。它允许从 Java 代码中创建模拟对象的实现。有时应用程序的架构是这样设计的，它使用最终类、私有方法或静态方法来设计类。这些方法或类无法测试，因为无法创建它们的模拟对象。开发者可以选择良好的设计或可测试性。PowerMock 通过使用自定义类加载器和字节码操作，使静态方法和最终类可以被模拟。

### **TestNG**

TestNG 是一个受 JUnit 和 NUnit 测试启发的强大测试框架，适用于单元测试、功能测试和集成测试。它支持参数化测试，这是 JUnit 不可能实现的。它配备了诸如每个测试方法（@BeforeMethod, @AfterMethod）和每个类（@BeforeClass, @AfterClass）之前和之后的数据预处理等许多有用注解。

以下 是 TestNG 的功能：

+   易于编写测试用例

+   它可以生成 HTML 报告

+   它可以生成日志

+   良好的集成测试支持

### Arquillian Framework

Arquillian 是一个针对 Java 应用程序的测试框架。该框架使开发人员能够在运行时环境部署应用程序，以使用 JUnit 和 TestNG 执行测试用例。由于 Arquillian 管理以下测试生命周期管理事物，因此可以在测试内部管理运行时环境：

+   它可以管理多个容器

+   它使用 ShrinkWrap 捆绑类、资源和测试用例

+   它将归档部署到容器中

+   在容器内执行测试用例

+   将结果返回给测试运行器

#### ShrinkWrap

该框架由三个主要组件组成，

##### 测试运行器

执行测试用例时，JUnit 或 TestNG 使用 Arquillian 测试运行器。这使得在测试用例中使用组件模型成为可能。它还管理容器生命周期和依赖注入，使模型可供使用。

##### Java 容器

Java 容器是测试环境的主要组件。Arquillian 测试可以在任何兼容的容器中执行。Arquillian 选择容器以确定在类路径中可用的哪个容器适配器。这些容器适配器控制并帮助与容器通信。Arquillian 测试用例甚至可以在没有基于 JVM 的容器的情况下执行。我们可以使用**@RunsClientto**注解在 Java 容器外部执行测试用例。

##### 将测试用例集成到 Java 容器中

该框架使用名为 ShrinkWrap 的外部依赖。它有助于定义要加载到 Java 容器中的应用程序的部署和描述符。测试用例针对这些描述符运行。Shrinkwrap 支持生成动态 Java 归档文件，类型为 JAR、WAR 和 EAR。它还可以用于添加部署描述符以及创建 DD 程序化。

Arquillian 可以在以下场景中使用，

+   您要测试的应用程序部分需要在内嵌服务器中部署

+   测试应在每小时、一定时间间隔后或有人提交代码时执行

+   通过外部工具自动化应用程序的验收测试

### JUnit

JUnit 是用于 Java 测试驱动开发的最受欢迎的开源框架。JUnit 有助于对组件进行单元测试。它还广泛支持诸如 ANT、Maven、Eclipse IDE 等工具。单元测试类是像其他任何类一样的普通类，主要区别在于使用**@Test**注解。@Test 注解让 JUnit 测试运行器知道需要执行这个注解的方法来进行测试。

org.junit.Assert 类提供了一系列静态的 assertXXX()方法，这些方法通过比较被测试方法的预期输出和实际输出来进行测试。如果测试的比较返回正常，表示测试通过了。但是，如果比较失败，执行停止，表示测试失败。

单元测试类通常被称为单元测试用例。测试用例可以有多个方法，这些方法将按照编写顺序一个接一个地执行。JUnit 为公共单元测试提供设置测试数据的功能，并针对它进行测试。数据的初始化可以在`setUp()`方法中完成，或者在用@Before 注解标记的方法中完成。默认情况下，它使用 JUnit 运行器来运行测试用例。但它还有 Suite、Parameterised 和 Categories 等几个内置的运行器。除了这些运行器之外，JUnit 还支持第三方运行器，如 SpringJUnit4ClassRunner、MokitoJUnitRunner、HierarchicalContextRunner。它还支持使用@RunWith 注解，以便使用自定义运行器。我们将在稍后详细讨论这个注解以及 Spring 测试框架。

以下是一些通过比较进行测试的断言方法，

+   assertEquals : 这个方法通过调用 equals()方法来测试两个对象的相等性。

+   assertTrue 和 assertFalse : 它用于将布尔值与 true 或 false 条件进行比较。

+   assertNull 和 assetNotNull : 这个方法测试值的 null 或非 null。

+   assertSame 和 assertNotSame : 它用于测试传递给它的两个引用是否指向同一个对象。

+   assertArrayEquals : 它用于测试两个数组是否包含相等的元素，并且数组中每个元素与另一个数组中相同索引的元素相等。

+   assertThat : 它用于测试对象是否与 org.hamcrest.Matcher 中的对象匹配。

## 第一阶段 单元测试 DAO 使用 JUnit 进行单元测试

* * *

现在，是编写实际测试用例的时候了。我们将从单元测试 DAO 层开始。以下是为编写基于注解的测试用例而遵循的一般步骤，

1.  创建一个类，该类的名称以'Test'为前缀，紧跟被测试类的名称。

1.  为初始化我们所需的数据和释放我们使用的资源分别编写`setUp()`和`testDown()`方法。

1.  进行测试的方法将它们的名称命名为被测试方法名称前加上'test'。

1.  `4.` 测试运行器应该认识的方法的需用`@Test`注解标记。

1.  使用`assertXXX()`方法根据测试的数据比较值。

让我们为第三章中开发的 DAO 层编写测试。我们将使用 Ch03_JdbcTemplates 作为基础项目。您可以创建一个新的项目，或者通过仅添加测试包来使用 Ch03_JdbcTemplates。让我们按照以下步骤操作：

### 创建基本应用程序。

1.  创建 Ch07_JdbcTemplates_Testing 作为 Java 项目。

1.  为 Spring 核心、Spring JDBC 和 JDBC 添加所有必需的 jar 文件，这些文件我们已经为 Ch03_JdbcTemplates 项目添加了。

1.  从基础项目中复制 com.packt.ch03.beans 和 com.packt.ch03.dao 包。我们只对 BookDAO_JdbcTemplate 类进行测试。

1.  将`connection_new.xml`复制到类路径中

### 执行测试

1.  创建`com.packt.ch07.tests`包

1.  使用 Eclipse IDE 中的 JUnit 测试用例模板：

    1.  输入测试用例的名称 TestBookDAO_JdbcTemplate

    1.  为初始化和释放测试用例组件选择 setUp 和 teardown 复选框。

    1.  点击浏览按钮，选择 BookDAO_JdbcTemplate 作为测试类。

    1.  点击下一步按钮

    1.  在测试方法对话框中选择 BookDAO_JdbcTemplate 类中的所有方法。

    1.  点击完成。

    1.  将出现一个对话框，询问是否在构建路径上添加 JUnit4。点击确定按钮。

以下图表总结了这些步骤：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/lrn-spr5/img/image_07_001.png)

1.  点击下一步按钮后，您将看到下一个对话框：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/lrn-spr5/img/image_07_002.png)

1.  在测试用例中声明一个数据成员作为`BookDAO_JdbcTemplate`。

1.  更新`setUp()`方法，使用 ApplicationContext 容器初始化测试用例的数据成员。

1.  更新`tearDown()`以释放资源。

1.  更新`testAddBook()`如下：

1.  创建一个 Book 类型的对象，并确保 ISBN 的值在 Book 表中不可用。

1.  从`BookDAO_JdbcTemplate`类调用`addBook()`。

1.  使用以下代码中的`assertEquals()`方法测试结果：

```java
      public classTestBookDAO_JdbcTemplate { 
        BookDAO_JdbcTemplatebookDAO_JdbcTemplate; 

        @Before 
        publicvoidsetUp() throws Exception { 
          ApplicationContextapplicationContext = new 
          ClassPathXmlApplicationContext("connection_new.xml"); 
          bookDAO_JdbcTemplate = (BookDAO_JdbcTemplate)  
          applicationContext.getBean("bookDAO_jdbcTemplate"); 
        } 
        @After 
        publicvoidtearDown() throws Exception { 
          bookDAO_JdbcTemplate = null; 
        } 

        @Test 
        publicvoidtestAddBook() { 
          Book book = newBook("Book_Test", 909090L, "Test  
          Publication", 1000, "Test Book description", "Test  
          author"); 
          introws_insert= bookDAO_JdbcTemplate.addBook(book); 
          assertEquals(1, rows_insert); 
        } 
      } 

```

1.  选择`testAddBook()`方法并将其作为 JUnit 测试运行。

1.  如以下图表所示，JUnit 窗口将显示一个绿色标记，表示代码已通过单元测试：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/lrn-spr5/img/image_07_003.png)

1.  在 Book 表中，ISBN 是一个主键，如果你重新运行相同的`testAddBook()`，它将显示红色而不是绿色，从而失败。尽管如此，这证明了代码是根据逻辑工作的。如果测试条件之一失败，测试用例执行将停止，并显示断言错误。

### 注意

尝试编写一个总是通过的测试条件。

1.  让我们添加`TestAddBook_Negative ()`以测试如果我们尝试添加具有相同 ISBN 的书籍会发生什么。不要忘记通过`@Test`注解 annotate the method。代码将如下所示：

```java
      @Test(expected=DuplicateKeyException.class) 
      publicvoidtestAddBook_Negative() { 
        Book book = newBook("Book_Test", 909090L, "Test  
        Publication", 1000, "Test Book description", "Test  
        author"); 
        introws_insert= bookDAO_JdbcTemplate.addBook(book); 
        assertEquals(0, rows_insert); 
      } 

```

### 注意

如果添加重复键，代码将抛出 DuplicateKeyException。在`@Test`注解中，我们添加了`DuplicateKey`Exception 作为期望的结果，指示 JUnit 运行器这是期望的行为。

1.  同样，让我们将以下代码添加到其他测试方法中：

```java
      @Test 
      publicvoidtestUpdateBook() { 
        //with ISBN which does exit in the table Book 
        longISBN = 909090L; 
        intupdated_price = 1000; 
        introws_insert = bookDAO_JdbcTemplate.updateBook(ISBN,  
          updated_price); 
        assertEquals(1, rows_insert); 
      } 
      @Test 
      publicvoidtestUpdateBook_Negative() { 
        // code for deleting the book with ISBN not in the table 
      } 
      @Test 
      publicvoidtestDeleteBook() { 
        // with ISBN which does exit in the table Book 
        longISBN = 909090L; 
        booleandeleted = bookDAO_JdbcTemplate.deleteBook(ISBN); 
        assertTrue(deleted); 
      } 
      @Test 
      publicvoidtestDeleteBook_negative() { 
        // deleting the book with no iSBN present in the table. 
      } 
      @Test 
      publicvoidtestFindAllBooks() { 
        List<Book>books =  
        bookDAO_JdbcTemplate.findAllBooks(); 
        assertTrue(books.size()>0); 
        assertEquals(4, books.size()); 
        assertEquals("Learning Modular Java  
        Programming",books.get(3).getBookName()); 
      } 
      @Test 
      publicvoidtestFindAllBooks_Author() { 
        List<Book>books =  
          bookDAO_JdbcTemplate.findAllBooks("T.M.Jog"); 
        assertEquals("Learning Modular Java  
          Programming",books.get(1).getBookName()); 
      } 

```

上述代码构建了几个对象，如 `BookDAO_JdbcTemplate`，这些对象是使用 Spring 容器构建的。在代码中，我们使用了在 `setUp()` 中通过 Spring 容器获得的 `BookDAO_JdbcTemplate` 对象。我们不能手动完成，而有更好的选择吗？是的，我们可以通过使用 Spring 提供的自定义运行器来实现。SprinJUnit4ClassRunner 是一个自定义运行器，它是 JUnit4Runner 类的扩展，提供了一个使用 Spring TestContext Framework 的设施，消除了复杂性。

### Spring TestContext Framework

Spring 为开发者提供了丰富的 Spring TestContext Framework，该框架为单元测试和集成测试提供了强大的支持。它支持基于 API 的和基于注解的测试用例创建。该框架强烈支持 JUnit 和 TestNG 作为测试框架。TestContext 封装了将执行测试用例的 spring 上下文。如果需要，它还可以用于加载 ApplicationContext。TestContextManager 是管理 TestContext 的主要组件。TestContextManager 通过事件发布，而 TestExecutionListener 为发布的事件提供采取的动作。

类级注解 @RunWith 指示 JUnit 调用其引用的类来运行测试用例，而不是使用内置的运行器。Spring 提供的 SpringJUnit4ClassRunner 使 JUnit 能够使用 TestContextManager 提供的 Spring 测试框架功能。org.springframework.test.context 包提供了测试的注解驱动支持。以下注解用于初始化上下文，

#### @ContextConfiguration

类级注解加载了构建 Spring 容器的定义。上下文是通过引用一个类或 XML 文件来构建的。让我们逐一讨论它们：

+   使用单个 XML 文件：

```java
      @ContextConfiguration("classpath:connection_new.xml") 
      publicclassTestClass{ 
        //code to test 
      } 

```

+   使用配置类：

```java
      @ContextConfiguration(class=TestConfig.class) 
      publicclassTestClass{ 
        //code to test 
      } 

```

+   使用配置类以及 XML 文件：

```java
      @ContextConfiguration(locations="connection_new.xml", 
      loader=TestConfig.class) 
      publicclassTestClass{ 
        //code to test 
      } 

```

+   使用上下文初始化器：

```java
      @ContextConfiguration(initializers = 
        TestContextInitializer.class) 
      publicclassTestClass{ 
        //code to test 
      } 

```

#### @WebAppConfiguration

类级注解用于指示如何加载 ApplicationContext，并由默认位置的 WebApplicationContext（WAC）使用，文件路径为 "file:/src/main/webapp"。以下代码段显示了加载资源以初始化用于测试的 WebApplicationContext：

```java
@WebAppConfiguration("classpath: myresource.xml") 
publicclassTestClass{ 
 //code to test 
} 

```

之前开发的测试用例使用显式初始化 Spring 上下文。在这个示例中，我们将讨论如何使用 SprinJUnit4ClassRunner 和 @RunWith。我们将使用 Ch07_JdbcTemplates_Testing 项目和测试 BookDAO_JdbcTemplates 的测试方法，步骤如下，

1.  下载 spring-test-5.0.0.M1.jar 文件以使用 Spring 测试 API。

1.  在 com.packt.ch07.tests 包中创建一个名为 SpringRunner_TestBookDAO_JdbcTemplate 的 JUnit 测试用例。选择 BookDAO_JdbcTemplate 作为测试类和其所有测试方法。

1.  使用以下代码中的 @RunWith 和 @ContextConfiguration 注解注释类。

1.  在代码中添加一个类型为 BookDAO 的数据成员，并应用自动装配注解，如下所示：

```java
      @RunWith(SpringJUnit4ClassRunner.class) 
      @ContextConfiguration("classpath:connection_new.xml") 
      publicclassSpringRunner_TestBookDAO_JdbcTemplate { 
        @Autowired 
        @Qualifier("bookDAO_jdbcTemplate") 
        BookDAObookDAO_JdbcTemplate; 

        @Test 
        publicvoidtestAddBook() { 
          Book book = newBook("Book_Test", 909090L, "Test  
          Publication", 1000, "Test Book description", "Test  
          author"); 
          introws_insert = bookDAO_JdbcTemplate.addBook(book); 
          assertEquals(1, rows_insert); 
        } 
      } 

```

1.  `@RunWith`注解接受`SpringJUnit4ClassRunner`。`@ContextConfiguration`接受文件以初始化容器。此外，我们使用基于注解的自动装配来测试 BookDAO 实例，而不是像早期演示中那样在`setUp()`方法中使用 Spring API。`testAddBook()`中的测试代码保持不变，因为我们没有更改逻辑。

1.  将其作为 JUnit 测试执行，如果您的 ISBN 尚未在书籍表中可用，则测试将通过。

上述代码我们对实际数据库进行了测试，这使得它变得更慢，并且始终如此。这些测试与环境不是孤立的，并且它们总是依赖于外部依赖，在我们的案例中是数据库。单元测试案例总是根据实时值基于几个假设来编写的，以便理解处理实时值时的问题和复杂性。

我们有一个更新书籍详情的函数。要更新书籍，该函数有两个参数，第一个是接受 ISBN，第二个是使用指定的 ISBN 更新书籍的价格，如下所示：

```java
publicintupdateBook(long ISBN, intupdated_price() 
{ 
   // code which fires the query to database and update the price     
   of the book whose ISBN has specified 
   // return 1 if book updated otherwise 0 
} 

```

我们编写了以下测试用例，以确定书籍是否已更新：

```java
@Test 
public void testUpdatedBook() 
{ 
  long ISBN=2;   // isbn exists in the table 
  intupdated_price=200; 
  introws_updated=bookDAO.updateBook( ISBN, updated_price); 
  assertEquals(1, rows_updated); 
} 

```

我们假设 ISBN 存在于数据库中以更新书籍详情。所以，测试用例执行成功。但是，如果在其中有人更改了 ISBN，或者有人删除了具有该 ISBN 的行怎么办？我们编写的测试用例将失败。问题不在我们的测试用例中，唯一的问题是我们假设 ISBN 存在。

另外，有时实时环境可能无法访问。控制器层测试高度依赖于请求和响应对象。这些请求和响应将在应用程序部署到服务器后由容器初始化。要么服务器不适合部署，要么控制器编码所依赖的层尚未开发。所有这些问题使得测试越来越困难。这些问题使用模拟对象测试可以轻松解决。

## 模拟测试

***

模拟测试涉及使用假对象进行测试，这些对象不是真实的。这些假对象返回进行测试所需的数据。在实际对象操作中可以节省大量工作。这些假对象通常被称为“模拟对象”。模拟对象用于替换实际对象，以避免不必要的复杂性和依赖，如数据库连接。这些模拟对象与环境隔离，导致执行速度更快。通过设置数据然后指定方法的的行为来创建模拟对象。行为包括在特定场景下返回的数据。Mockito 是使用模拟对象的一个著名的测试框架。

### Mockito

Mockito 是一个开源的 Java 基础应用程序测试框架，发布在 MIT 许可证下。它允许开发人员为**测试驱动开发**（**TDD**）创建模拟对象，使其与框架隔离。它使用 Java 反射 API 来创建模拟对象，并具有编写测试用例的简单 API。它还允许开发人员检查方法被调用的顺序。

Mockito 有一个静态的`mock()`方法，可以用来创建模拟对象。它还通过使用@Mock 注解来创建模拟对象。`methodMockitoAnnotations.initMocks(this)`指示初始化所有由@Mock 注解的注解字段。如果我们忘记这样做，对象将是 null。`@RunWith(MokitoJUnitRunner.class)`也做同样的事情。MockitoJUnitRunner 是 JUnit 使用的自定义运行器。

Mockito 的工作原理是在调用函数时返回预定义的值，**Mokito**，when()方法提供了关于将调用哪个方法的信息，Mokito，thenXXX()用于指定函数将返回的值。以下是用以来指定要返回的值的方法，

+   `thenReturn` - 用于返回一个指定的值

+   `thenThrow`- 抛出指定的异常

+   `then`和`thenAnswer`通过用户定义的代码返回一个答案

+   `thenCallRealMethod`- 调用真实的方法

模拟测试是一个简单的三个步骤的过程，如下所示，

1.  通过模拟对象初始化被测试类的依赖项

1.  执行测试操作

1.  编写测试条件以检查操作是否给出了预期的结果

让我们逐步使用 Mockito 创建`BookDAO`的模拟对象并在测试步骤中使用它，

1.  下载 mokito-all-1.9.5.jar 并将其添加到我们用作基础项目的 Ch07_JdbeTemplate_Testing 项目中。

1.  在 com.packt.ch07.unit_tests 包中创建`Spring_Mokito_TestBookDAO_JdbcTemplate`作为一个 Junit 测试用例。

1.  添加一个类型为`BookDAO`的数据成员并使用@Mock 注解标注它。

1.  在`setup()`方法中调用 Mockito 的`initMocks()`方法来初始化模拟对象，如下所示：

```java
      publicclassSpring_Mokito_TestBookDAO_JdbcTemplate { 
        @Mock 
        BookDAObookDAO_JdbcTemplate; 

        @Before 
        publicvoidsetUp()throws Exception 
        { 
          MockitoAnnotations.initMocks(this); 
        } 
      } 

```

1.  现在让我们添加代码来测试`addBook()`函数，我们首先定义期望测试函数返回的值。然后我们使用`assertXXX()`方法来测试以下行为：

```java
      @Test 
      publicvoidtestAddBook() { 
        Book book = newBook("Book_Test", 909090L, "Test  
        Publication", 1000, "Test Book description",  
        "Test author"); 
        //set the behavior for values to return in our case addBook() 
        //method 
        Mockito.when(bookDAO_JdbcTemplate.addBook(book)).thenReturn(1); 

        // invoke the function under test 
        introws_insert = bookDAO_JdbcTemplate.addBook(book); 

        // assert the actual value return by the method under test to        
        //the expected behaiour by mock object 
        assertEquals(1, rows_insert); 
      } 

```

1.  执行测试用例并测试行为。我们将得到所有测试用例成功执行。

1.  接下来让我们也添加`findAllBooks(String)`和`deleteBook()`方法的其他代码：

```java
      @Test 
      publicvoidtestDeleteBook() { 

        //with ISBN which does exit in the table Book 
        longISBN = 909090L; 
        Mockito.when(bookDAO_JdbcTemplate.deleteBook(ISBN)). 
          thenReturn(true); 
        booleandeleted = bookDAO_JdbcTemplate.deleteBook(ISBN); 
        assertTrue(deleted); 
      } 

      @Test 
      publicvoidtestFindAllBooks_Author() { 
        List<Book>books=newArrayList(); 
        books.add(new Book("Book_Test", 909090L, "Test  
          Publication", 1000, "Test Book description", "Test  
          author") ); 

        Mockito.when(bookDAO_JdbcTemplate.findAllBooks("Test  
          author")).thenReturn(books); 
        assertTrue(books.size()>0); 
        assertEquals(1, books.size()); 
        assertEquals("Book_Test",books.get(0).getBookName()); 
      } 

```

在之前的示例中，我们讨论了在实时环境以及在使用模拟对象时 DAO 层的单元测试。现在让我们在接下来的部分使用 Spring MVC 测试框架来测试控制器。

#### 使用 Spring TestContext 框架进行 Spring MVC 控制器测试

Mockito 为开发人员提供了创建 DAO 层模拟对象的功能。在前面的讨论中，我们没有 DAO 对象，但即使没有它，测试也是可能的。没有模拟对象，Spring MVC 层测试是不可能的，因为它们高度依赖于初始化由容器完成的请求和响应对象。spring-test 模块支持创建 Servlet API 的模拟对象，使在不实际部署容器的情况下测试 Web 组件成为可能。以下表格显示了由 Spring TestContext 框架提供的用于创建模拟对象包列表：

| **包名** | **提供模拟实现** |
| --- | --- |
| org.springframework.mock.env | 环境和属性源 |
| org.springframework.mock.jndi | JNDI SPI |
| org.springframework.mock.web | Servlet API |
| org.springframework.mock.portlet | Portlet API |

org.springframework.mock.web 提供了 MockHttpServletRequest，MockHttpServletResponse，MockHttpSession 作为 HttpServletRequest，HttpServletResponse 和 HttpSession 的模拟对象，供使用。它还提供了 ModelAndViewAssert 类，以测试 Spring MVC 框架中的 ModelAndView 对象。让我们逐步测试我们的 SearchBookController 如下：

1.  将 spring-test.jar 添加到`ReadMyBooks`应用程序中，我们将在测试中使用它。

1.  创建`com.packt.ch06.controllers.test_controllers`包，以添加控制器的测试用例。

1.  在先前步骤创建的包中创建`TestSearchBookController`作为 JUnit 测试用例。

1.  使用`@WebAppConfiguration`进行注解。

1.  声明类型为 SearchBookController 的数据成员并如代码所示自动注入：

```java
      @WebAppConfiguration 
      @ContextConfiguration({ "file:WebContent/WEB-INF/book- 
        servlet.xml" }) 
      @RunWith(value = SpringJUnit4ClassRunner.class) 
      publicclassTestSearchBookController { 
         @Autowired 
        SearchBookControllersearchBookController; 
      } 

```

1.  让我们测试 add testSearchBookByAuthor()以测试 searchBookByAuthor()方法。该方法接受用户在 Web 表单中输入的作者名称，并返回该作者所写的书籍列表。代码将如下所示：

    1.  初始化测试方法所需的数据

    1.  调用测试方法

    1.  断言值。

1.  最终代码将如下所示：

```java
      @Test 
      publicvoidtestSearchBookByAuthor() { 

        String author_name="T.M.Jog"; 
        ModelAndViewmodelAndView =   
          searchBookController.searchBookByAuthor(author_name); 
        assertEquals("display",modelAndView.getViewName()); 
      } 

```

1.  我们正在测试名为'display'的视图名称，该视图是从控制器方法中编写出来的。

1.  Spring 提供了 ModelAndViewAssert，提供了一个测试控制器方法返回的 ModelAndView 的方法，如下面的代码所示：

```java
      @Test 
      publicvoidtestSerachBookByAuthor_New() 
      { 
        String author_name="T.M.Jog"; 
        List<Book>books = newArrayList<Book>(); 
        books.add(new Book("Learning Modular Java Programming",  
          9781235, "packt pub publication", 800, 
          "explore the power of modular Programming ", author_name)); 
        books.add(new Book("Learning Modular Java Programming",  
          9781235, "packt pub publication", 800, 
          "explore the power of modular Programming ", author_name)); 
        ModelAndViewmodelAndView = 
          searchBookController.searchBookByAuthor(author_name); 
        ModelAndViewAssert.assertModelAttributeAvailable( 
          modelAndView, "book_list"); 
      } 

```

1.  执行测试用例，绿色表示测试用例已通过。

1.  我们成功测试了 SearchBookController，其具有无需任何表单提交、表单模型属性绑定、表单验证等简单编码。我们刚刚处理的这些复杂的代码测试变得更加复杂。

#### Spring MockMvc

Spring 提供了 MockMVC，作为主要的入口点，并配备了启动服务器端测试的方法。将使用 MockMVCBuilder 接口的实现来创建一个 MockMVC 对象。MockMVCBuilders 提供了以下静态方法，可以获取 MockMVCBuilder 的实现：

+   xmlConfigSetUp(String ...configLocation) - 当使用 XML 配置文件来配置应用程序上下文时使用，如下所示：

```java
      MockMvcmockMVC=   
      MockMvcBuilders.xmlConfigSetUp("classpath:myConfig.xml").build(); 

```

+   annotationConfigSetUp(Class ... configClasses) - 当使用 Java 类来配置应用程序上下文时使用。以下代码显示了如何使用 MyConfig.java 作为一个配置类：

```java
      MockMvcmockMVC=  
         MockMvcBuilders.annotationConfigSetUp(MyConfiog.class). 
                                                         build(); 

```

+   standaloneSetUp(Object ... controllers) - 当开发者配置了测试控制器及其所需的 MVC 组件时使用。以下代码显示了使用 MyController 进行配置：

```java
      MockMvcmockMVC= MockMvcBuilders.standaloneSetUp( 
        newMyController()).build(); 

```

+   webApplicationContextSetUp(WebApplicationContext context) - 当开发者已经完全初始化 WebApplicationContext 实例时使用。以下代码显示了如何使用该方法：

```java
      @Autowired 
      WebApplicationContextwebAppContext; 
      MockMvcmockMVC= MockMVCBuilders.webApplicationContextSetup( 
        webAppContext).build(); 

```

MockMvc has `perform()` method which accepts the instance of RequestBuilder and returns the ResultActions. The `MockHttpServletRequestBuilder` is an implementation of RequestBuilder who has methods to build the request by setting request parameters, session. The following table shows the methods which facilitate building the request,

| **Method name** | **The data method description** |
| --- | --- |
| accept | 用于将“Accept”头设置为给定的媒体类型 |
| buildRequest | 用于构建 MockHttpServletRequest |
| createServletRequest | 根据 ServletContext，该方法创建一个新的 MockHttpServletRequest |
| Param | 用于将请求参数设置到 MockHttpServletRequest。 |
| principal | 用于设置请求的主体。 |
| locale . | 用于设置请求的区域设置。 |
| requestAttr | 用于设置请求属性。 |
| Session, sessionAttr, sessionAttrs | 用于设置会话或会话属性到请求 |
| characterEncoding | 用于将字符编码设置为请求 |
| content and contentType | 用于设置请求的正文和内容类型头。 |
| header and headers | 用于向请求添加一个或所有头信息。 |
| contextPath | 用于指定表示请求 URI 的上下文路径部分 |
| Cookie | 用于向请求添加 Cookie。 |
| flashAttr | 用于设置输入的闪存属性。 |
| pathInfo | 用于指定表示请求 URI 的 pathInfo 部分。 |
| Secure | 用于设置 ServletRequest 的安全属性，如 HTTPS。 |
| servletPath | 用于指定表示 Servlet 映射路径的请求 URI 部分。 |

The `perfom()` method of MockMvc returns the ResultActions, which facilitates the assertions of the expected result by following methods:

| **Method name** | **Description** |
| --- | --- |
| andDo | 它接受一个通用操作。 |
| andExpect | 它接受预期的操作 |
| annReturn | 它返回预期请求的结果，可以直接访问。 |

Let's use MockMvc to test AddBookController step by step:

1.  Add TestAddBookController as JUnit test case in `com.packt.ch06.controllers.test_controllers package`.

1.  像早期代码中一样，用`@WebAppConfiguration`、`@ContextConfiguration`和`@RunWith`注解类。

1.  添加类型为 WebApplicationContext 和`AddBookController`的数据成员，并用`@Autowired`注解两者。

1.  添加类型为 MockMvc 的数据成员，并在 setup()方法中初始化它，如以下所示释放内存：

```java
      @WebAppConfiguration 
      @ContextConfiguration( 
        { "file:WebContent/WEB-INF/books-servlet.xml"}) 
      @RunWith(value = SpringJUnit4ClassRunner.class) 
      publicclassTestAddBookController { 
        @Autowired 
        WebApplicationContextwac; 

        MockMvcmockMVC; 

        @Autowired 
        AddBookControlleraddBookController; 

        @Before 
        publicvoidsetUp() throws Exception { 
          mockMVC= 
            MockMvcBuilders.standaloneSetup(addBookController).build(); 
        } 
      } 

```

+   让我们在 testAddBook()中添加测试 addBook()方法的代码：

    1.  通过设置以下值初始化请求：

+   模型属性'book'使用默认值

+   将表单提交结果设置为内容类型

+   方法将被调用的 URI

+   表单的请求参数：

    1.  通过检查测试结果：

+   视图名称

+   模型属性名称

    1.  使用 andDo()在控制台上打印测试动作的结果

测试 AddBook()方法的代码如下：

```java
      @Test 
      publicvoidtestAddBook() { 
        try { 
          mockMVC.perform(MockMvcRequestBuilders.post("/addBook.htm") 
          .contentType(MediaType.APPLICATION_FORM_URLENCODED) 
          .param("bookName", "Book_test") 
          .param("author", "author_test") 
          .param("description", "adding book for test") 
          .param("ISBN", "1234") 
          .param("price", "9191") 
          .param("publication", "This is the test publication") 
          .requestAttr("book", new Book())) 
          .andExpect(MockMvcResultMatchers.view().name("display")) 
          .andExpect(MockMvcResultMatchers.model(). 
            attribute("auth_name","author_test")) 
          .andDo(MockMvcResultHandlers.print()); 
        } catch (Exception e) { 
          // TODO: handle exception 
          fail(e.getMessage()); 
        } 
      } 

```

在 andExpect( )中的预期行为匹配由 ResultMatcher 提供。MockMvcResultMatcher 是 ResultMatcher 的一个实现，提供了匹配视图、cookie、header、模型、请求和其他许多参数的方法。andDo()方法将 MvcResult 打印到 OutputStream。

1.  运行测试用例，令人惊讶的是它会失败。输出的一部分如下所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/lrn-spr5/img/image_07_004.png)

1.  它显示了验证错误，但我们已经根据验证规则给出了所有输入。哪个验证失败了从输出中看不清楚。不，没必要惊慌，也不需要逐个检查验证。

1.  与其制造更多混乱，不如添加使用 attributeHasErrors()的验证测试代码，如下划线语句所示：

```java
      @Test 
publicvoidtestAddBook_Form_validation() { 
        try { 
          mockMVC.perform(MockMvcRequestBuilders.post("/addBook.htm")                        .contentType(MediaType.APPLICATION_FORM_URLENCODED) 
          .param("bookName", "Book_test") 
          .param("author", "author_test") 
          .param("description", "adding book for test") 
          .param("ISBN", "12345") 
          .param("price", "9191") 
          .param("publication", "This is the test publication") 
          .requestAttr("book", new Book())) 
          .andExpect(MockMvcResultMatchers.view().name("bookForm")) 
          .andExpect(MockMvcResultMatchers .model(). 
            attributeHasErrors("book")) 
          .andDo(MockMvcResultHandlers.print()); 
        }  
        catch (Exception e) { 
          fail(e.getMessage()); 
          e.printStackTrace(); 
        } 
      }  

```

1.  测试运行成功，证明输入存在验证错误。我们可以在控制台输出的'errors'中获取到验证失败的字段：

```java
      MockHttpServletRequest: 
        HTTP Method = POST 
        Request URI = /addBook.htm 
        Parameters = {bookName=[Book_test],  
      author=[author_test], 
      description=[adding book for test],  
      ISBN=[1234],  
      price=[9191], 
      publication=[This is the test publication]} 
      Headers = { 
        Content-Type=[application/x-www-form-urlencoded]} 
      Handler: 
        Type = com.packt.ch06.controllers.AddBookController 
        Method = public  
      org.springframework.web.servlet.ModelAndView 
      com.packt.ch06.controllers.AddBookController. 
      addBook(com.packt.ch06.beans.Book,org. 
      springframework.validation.BindingResult)       
      throwsjava.lang.Exception 
      Async: 
      Async started = false 
      Async result = null 

      Resolved Exception: 
        Type = null 
      ModelAndView: 
        View name = bookForm 
        View = null 
        Attribute = priceList 
        value = [300, 350, 400, 500, 550, 600] 
        Attribute = book 
        value = Book_test  adding book for test  9191 
        errors = [Field error in object 'book' on field  
          'description':  
          rejected value [adding book for test];  
          codes 
          [description.length.book.description, 
          description.length.description,description. 
          length.java.lang.String,description.length]; 
          arguments []; 
          default message [Please enter description  
          within 40 charaters only]] 
      FlashMap: 
        Attributes = null 
      MockHttpServletResponse: 
        Status = 200 
      Error message = null 
      Headers = {} 
      Content type = null 
      Body =  
      Forwarded URL = bookForm 
      Redirected URL = null 
      Cookies = [] 

```

1.  尽管描述符中的字符在 10 到 40 个指定字符的限制内。让我们找出在 Validator2 中犯错的规则。

1.  设置发布验证规则的 validate 方法中的代码是：

```java
      if (book.getDescription().length() < 10 ||   
        book.getDescription().length() < 40)  
      { 
        errors.rejectValue("description", "description.length", 
          "Please enter description within 40 charaters only"); 
      } 

```

1.  是的，我们将发布长度设置为小于 40 的验证，导致失败。我们犯了一个错误。让我们更改代码，以设置规则，长度大于 40 将不允许。以下是更新的代码：

```java
      if (book.getDescription().length() < 10 ||
        book.getDescription().length() > 40)  
      { 
        errors.rejectValue("description", "description.length", 
        "Please enter description within 40 charaters only"); 
      } 

```

1.  现在重新运行 testAddController 以查看发生了什么。

1.  测试用例成功通过。这就是我们进行测试用例的原因。

1.  现在让我们在 testAddBook_Form_validation()中添加测试字段验证的代码：

```java
      @Test 
      publicvoidtestAddBook_Form_Field_Validation() 
      { 
        try { 
          mockMVC.perform(MockMvcRequestBuilders.post("/addBook.htm") 
          .param("bookName", "") 
          .param("author", "author_test") 
          .param("description"," no desc") 
          .param("ISBN", "123") 
          .param("price", "9191") 
          .param("publication", " ") 
          .requestAttr("book", new Book())) 
          .andExpect(MockMvcResultMatchers.view().name("bookForm"))  
          .andExpect(MockMvcResultMatchers.model() 
          .attributeHasFieldErrors("book", "description")).andExpect(
            MockMvcResultMatchers.model() 
          .attributeHasFieldErrors("book", "ISBN")).andExpect( 
            MockMvcResultMatchers.model() 
          .attributeHasFieldErrors("book", "bookName")). 
            andDo(MockMvcResultHandlers.print()); 
        }catch(Exception ex) 
        { 
          fail(ex.getMessage()); 
        } 
      } 

```

1.  运行测试用例，其中验证错误失败。

控制器和 DAO 正常工作。服务层使用 DAO，所以让我们对服务层进行集成测试。您可以按照我们讨论的和对 DAO 层测试进行模拟对象测试。我们将进入服务层集成测试的下一阶段。

## 第二阶段 集成测试

* * *

### 服务和 DAO 层的集成测试

让我们逐步进行应用程序的集成测试，Ch05_Declarative_Transaction_Management 如下：

1.  创建 com.packt.ch05.service.integration_tests 包。

1.  创建 JUnit 测试用例 TestBookService_Integration，将 BookServiceImpl 作为测试类。选择其所有方法进行测试。

1.  声明类型为 BookService 的数据成员，并用@Autowired 注解注释它，如下所示：

```java
      @RunWith(SpringJUnit4ClassRunner.class) 
      @ContextConfiguration("classpath:connection_new.xml") 
      publicclassTestBookService_Integration 
      { 
        @Autowired 
        BookServicebookService; 
      }   

```

1.  让我们测试 addBook()方法，就像我们之前在 JUnit 测试中做的那样。你可以参考下面的代码：

```java
      @Test 
      publicvoidtestAddBook() { 
        // Choose ISBN which is not there in book table 
        Book book = newBook("Book_Test", 909098L, "Test  
        Publication", 1000, "Test Book description", "Test  
        author"); 
        booleanflag=bookService.addBook(book); 
        assertEquals(true, flag); 
      } 

```

1.  你可以运行测试用例，它将成功运行。

### 注意

BookService 中的所有其他测试方法可以从源代码中参考。

我们开发的两个层次都在按我们的预期工作。我们分别开发了控制器、服务和 DAO，并进行了测试。现在，我们将它们组合到单个应用程序中，这样我们就会有一个完整的应用程序，然后通过集成测试，我们将检查它是否如预期般工作。

### 控制器和 Service 层的集成测试

让我们将以下三个层次从 Ch05_Declarative_Transaction_Management 中组合到 ReadMyBooks 中：

1.  在 ReadMyBooks 的 lib 文件夹中添加 jdbc 和 spring-jdbc 以及其他所需的 jar 文件。

1.  从 Ch05_Declarative_Transaction_Management 中将 com.packt.ch03.dao 和 com.packt.ch05.service 包复制到 ReadMyBooks 应用程序。

1.  在 ReadMyBooks 应用程序的类路径中复制 connection_new.xml。

1.  在 Book 类的表单提交中，我们注释了默认构造函数，服务中的 addBook 逻辑是检查 98564567las 的默认值。

1.  如下所示，通过下划线修改 BookService，其余代码保持不变：

```java
      @Override 
      @Transactional(readOnly=false) 
      publicbooleanaddBook(Book book) { 
        // TODO Auto-generated method stub 

        if (searchBook(book.getISBN()).getISBN() == 0) { 
          // 
        } 
      } 

```

1.  控制器需要更新以与底层层进行通信，如下所示：

    +   在控制器中添加类型为 BookService 的自动装配数据成员。

    +   根据业务逻辑要求，在控制器的 method 中调用服务层的 method。

1.  下面将更新 addBook()方法：

```java
      @RequestMapping("/addBook.htm") 
      publicModelAndViewaddBook(@Valid@ModelAttribute("book") 
      Book book, BindingResultbindingResult) 
      throws Exception { 
        // same code as developed in the controller 
        // later on the list will be fetched from the table 
        List<Book>books = newArrayList(); 

        if (bookService.addBook(book)) { 
          books.add(book); 
        } 
        modelAndView.addObject("book_list", books);   
        modelAndView.addObject("auth_name", book.getAuthor());  
        returnmodelAndView; 
      } 

```

### 注意

同样，我们可以更新所有控制器中的方法。你可以参考完整的源代码。

让我们执行测试用例 TestAddBookController.java 以获取结果。

代码将执行并给出成功消息。同时在表中添加了一行，包含了我们指定的 ISBN 和其他值。

我们已经成功测试了所有组件。现在我们可以直接开始系统测试。

但是要有耐心，因为我们将在测试框架“Arquillian”中讨论新的条目。

## 第三阶段系统测试

* * *

现在所有层次都按照预期工作，是时候通过网络测试应用程序了，即逐一检查功能，同时非常注意逐步进行，不仅要关注结果，还要观察演示，这将接近实际的部署环境。让我们部署应用程序，以检查所有功能是否正常工作，并在数据库和演示方面给出正确的结果，通过以下任一方式进行：

### 使用 Eclipse IDE 进行部署

在 Eclipse 中，一旦开发完成，配置服务器并从项目浏览器中选择项目以选择**`Run on server`**选项，如下面的箭头所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/lrn-spr5/img/image_07_005.png)

IDE 会将应用程序包装在战争文件中，并将其部署到容器中。现在，你可以逐一检查功能，以确保一切按预期进行。我们还将关注演示文稿、外观和准确性的数据，这些数据由演示文稿显示。

### 手动部署应用程序

手动部署应用程序可以通过以下步骤进行：

1.  首先，我们需要获取它的 jar 文件。我们可以使用 Eclipse IDE 通过右键点击应用程序并选择**`Export`**来轻松获取战争文件，如下面的箭头所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/lrn-spr5/img/image_07_006.png)

1.  选择你想要创建战争文件的目标位置。如果你想的话，可以更改战争文件的名字。我将保持 ReadMyBooks 不变。

1.  点击**`finish`**完成过程。你将在选定的目标位置得到一个战争文件。

1.  复制我们在上一步创建的 WAR 文件，并将其粘贴到 Tomcat 目录下的'webapps'文件夹中。

1.  通过点击**`bin`**文件夹中的`startup.bat`文件来启动 tomcat。

1.  一旦 tomcat 启动，打开浏览器并输入主页 URL，格式为[`host_name:port_number_of_tomcat/war_file_name`](http://host_name:port_number_of_tomcat/war_file_name)。在我们的案例中，它是[`locathost:8080/ReadMyBooks`](http://locathost:8080/ReadMyBooks)。

1.  在继续之前，请确保数据库参数已正确设置，否则应用程序将失败。

1.  主页将打开，我们可以在这里测试应用程序的功能和外观。

## 摘要

* * *

在本章中，我们讨论了什么是测试以及为什么它如此重要。我们还讨论了单元测试、集成测试和用户接受测试作为测试的阶段。市场上有很多测试工具，我们对此进行了概述，以便您明智地选择工具。测试中一个非常重要的工具是'Junit 测试'，我们使用它来执行 DAO 层的单元测试，这是测试阶段 1 的开始。但是 JUnit 使用实时数据库，我们讨论了在外部参数上测试的困难。我们通过使用模拟对象解决了这个问题。Mokito 是创建模拟对象的工具之一，我们探索它来测试 DAO 层。在 DAO 层之后，我们测试了 Web 层，这也依赖于 Web 容器来初始化请求和响应对象。我们深入讨论了 Spring TestContext 框架，其 MockMVC 模块便于创建 Web 相关组件（如请求和响应）的模拟对象。我们还使用该框架进行表单验证测试。在单元测试之后，我们执行了 DAO 和 Service 层的集成测试，然后是 Web 和 Service 层的集成测试。故事不会在这里结束，我们通过进行系统测试来成功部署并最终检查产品。我们所开发的的所有组件都在正常工作，我们通过成功执行系统测试证明了这一点！！

在下一章中，我们将进一步讨论安全性在应用程序中的角色以及 Spring 框架提供的实现安全性的方法。请继续阅读！！！


## 第八章.探索 Restful 网络服务的强大功能

在之前的章节中，我们讨论了关于构建 Spring MVC 应用程序。这些应用程序通过网络只为 Java 平台提供服务。如果其他平台想要使用我们开发的功能会怎样？是的，我们需要平台无关的功能。在本章中，我们将讨论如何使用 Restful 网络服务开发此类平台无关的服务，以解决以下主题：

+   网络服务是什么？

+   网络服务的重要性。

+   网络服务类型

+   Restful 网络服务

+   开发 Spring restful 网络服务。

+   如何使用 RestTemplate 和 POSTMAN 测试网络服务？

+   使用消息转换器和内容协商来展示数据。

## 网络服务

****

网络服务是两个或更多为不同平台开发的应用程序之间的通信方式。这些服务不受浏览器和操作系统的限制，使得通信更加容易，性能得到增强，能够吸引更多用户。这种服务可以是一个函数，一系列标准或协议，部署在服务器上。它是客户端和服务器之间或通过网络两个设备之间的通信。比如说我们用 Java 开发了一个服务并将其发布到互联网上。现在这个服务可以被任何基于 Java 的应用程序消费，但更重要的是，任何基于.NET 或 Linux 的应用程序也可以同样轻松地消费它。这种通信是通过基于 XML 的消息和 HTTP 协议进行的。

### 为什么我们需要网络服务？

互操作性是网络服务可以实现的最佳功能之一，除此之外，它们还提供以下功能

#### 可用性

许多应用程序在开发已经存在于其他应用程序中的复杂功能时投入了宝贵的时间。 Instead of redeveloping it, 网络服务允许开发人员探索通过网络暴露的此类服务。它还允许开发人员复用 Web 服务，节省宝贵的时间，并开发定制的客户端逻辑。

#### 复用已开发的应用程序

技术市场变化如此之快，开发者必须不断跟上客户需求。在开发中，重新开发一个应用以支持新特性是非常常见的，只需`20 min`就能深入理解知识点，而且记忆深刻，*难以遗忘*。 Instead of developing the complete application from scratch, 开发者现在可以添加他们想要的任何平台上的增强功能，并使用 web 服务来使用旧模块。

#### 松耦合模块

每个作为网络服务开发的服务的完全独立性，支持轻松修改它们，而不会影响应用程序的其他部分。

#### 部署的便捷性

网络服务部署在服务器上，通过互联网使用。网络服务可以通过互联网部署在防火墙后面，与在本地服务器上部署一样方便。

### 网络服务类型

#### SOAP 网络服务

#### RESTful 网络服务

面向对象状态转换（RESTful）网络服务是一种架构风格。RESTful 资源是围绕数据的某种表示形式进行转换。REST 资源将采用适合消费者的形式。它可以是 XML、JSON 或 HTML 等表示形式。在 RESTful 网络服务中，资源的状态比针对资源采取的动作更重要。

RESTful 网络服务的优点：

+   RESTful 网络服务因其消耗较少资源而快速。

+   它可以编写并在任何平台上执行。

+   最重要的是，它允许不同的平台，如 HTML、XML、纯文本和 JSON。

### 在 Spring 中使用 RESTful 网络服务

Spring 支持编写 RestController，该控制器可以使用@RestController 注解处理 HTTP 请求。它还提供了@GetMapping、@PostMapping、@DeleteMapping、@PutMapping 注解来处理 HTTP get、post、delete 和 put 方法。@PathVariable 注解有助于从 URI 模板访问值。目前，大多数浏览器支持使用 GET 和 POST 作为 HTTP 方法和 html 动作方法。HiddenHttpMethodFilter 现在允许使用<form:form>标签提交 PUT 和 DELETE 方法的表单。Spring 使用 ContentNegotiatingViewResolver 根据请求的媒体类型选择合适的视图。它实现了已经用于 Spring MVC 的 ViewResolver。它自动将请求委托给适当的视图解析器。Spring 框架引入了@ResponseBody 和@RequestBody，以将方法参数绑定到请求或响应。客户端与服务器之间的请求和响应通信读写多种格式的数据，可能需要消息转换器。Spring 提供了许多消息转换器，如 StringHttpMessageConverter、FormHttpMessageConverter、MarshallingHttpMessageConverter，以执行读写操作。RestTemplate 提供了易于消费 RESTful 网络服务的客户端端。

在继续前进之前，让我们通过以下步骤开发一个 RESTController，以理解流程和 URI 消耗：

1.  创建 Ch09_Spring_Restful 动态网络应用程序，并添加为 Spring web MVC 应用程序添加的 jar 文件。

1.  在 web.xml 文件中将 DispatcherServlet 作为前端控制器映射，如下所示，以映射所有 URL：

```java
        <servlet> 
          <servlet-name>books</servlet-name> 
            <servlet-class>     
              org.springframework.web.servlet.DispatcherServlet 
            </servlet-class> 
          </servlet> 
        <servlet-mapping> 
          <servlet-name>books</servlet-name> 
          <url-pattern>/*</url-pattern> 
        </servlet-mapping> 

```

1.  在每一个 Spring web MVC 应用程序中添加 books-servlet.xml，以配置基本包名，以便扫描控制器和服务器视图解析器，这是我们添加的。

1.  在 com.packt.ch09.controllers 包中创建`MyRestController`类。

1.  使用@RestController 注解标注类。

1.  为消耗'/welcome' URI 添加`getData()`方法，如下面的代码所示：

```java
@RestController 
public class MyRestController { 

  @RequestMapping(value="/welcome",method=RequestMethod.GET) 
  public String getData() 
  { 
    return("welcome to web services"); 
  } 
} 

```

`getData()`方法将为'/welcome' URL 的 GET HTTP 方法提供服务，并返回一个字符串消息作为响应。

1.  将应用程序部署到容器中，一旦服务成功部署，是时候通过创建客户端来测试应用程序了。

1.  让我们使用 Spring 提供的`RestTemplate`编写客户端，如下所示：

```java
        public class Main { 
          public static void main(String[] args) { 
           // TODO Auto-generated method stub 
           String URI=    
             "http://localhost:8080/Ch09_Spring_Restful/welcome" 
           RestTemplate template=new RestTemplate(); 
           System.out.println(template.getForObject(URI,String.class)); 
          } 
        } 

```

执行主函数将在您的控制台显示“欢迎来到 Web 服务”。

### RestTemplate

与许多其他模板类（如 JdbcTemplate 和 HibernateTemplate）类似，RestTemplate 类也设计用于执行复杂功能，以调用 REST 服务。以下表格总结了 RestTemplate 提供的映射 HTTP 方法的方法：

| **RestTemplate 方法** | **HTTP 方法** | **描述** |
| --- | --- | --- |
| getForEntity 和 getForObject | GET | 它检索指定 URI 上的表示 |
| postForLocation 和 postForObject | POST | 它通过在指定的 URI 位置发布新对象来创建新资源，并返回值为 Location 的头部 |
| put | PUT | 它在指定的 URI 上创建或更新资源 |
| delete | DELETE | 它删除由 URI 指定的资源 |
| optionsForAllow | OPTIONS | 该方法返回指定 URL 的允许头部的值。 |
| execute 和 exchange | 任何 | 执行 HTTP 方法并返回作为 ResponseEntity 的响应 |

我们将在接下来的演示中覆盖大部分内容。但在深入 RESTful Web 服务之前，让我们讨论 RESTful Web 服务的最重要部分——URL。RestContollers 仅处理通过正确 URL 请求的请求。Spring MVC 控制器也处理参数化和查询参数的 Web 请求，而由 RESTful Web 服务处理的 URL 是面向资源的。通过没有查询参数的整个基本 URL 来完成对要映射的资源的识别。

所写的 URL 基于其中的复数名词，并尝试避免使用动词或查询参数，就像我们在 Spring MVC 早期演示中一样。让我们讨论 URL 是如何形成的。以下是一个资源的 RESTful URL，它是 Servlet 上下文、要获取的资源名词和路径变量的组合：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/lrn-spr5/img/image_09_001.png)

观察以下表格以了解更多关于 RESTful URL 的信息：

| **支持的 HTTP 方法** **要获取的资源** | **GET 方法** | **POST 方法** | **PUT 方法** | **DELETE 方法** |
| --- | --- | --- | --- | --- |
| /books | 返回书籍列表 | 添加新书 | 更新书籍或书籍 | 删除书籍 |
| /books/100 | 返回书籍 | 405 | 更新书籍 | 删除书籍 |

让我们通过以下步骤开发一个应用程序，使用不同的 HTTP 方法和 URL 以更好地理解。在这个应用程序中，我们将使用 Ch03_JdbcTemplate 作为我们的数据访问层，从这里你可以直接复制所需的代码。

1.  创建 Ch09_Restful_JDBC 文件夹，并添加所有必需的 jar 包，如 WebContent 文件夹大纲所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/lrn-spr5/img/image_09_002.png)

1.  像在早期应用程序中一样，在 web.xml 和 books-servlet.xml 中添加前端控制器和 web 组件映射文件。您可以从早期应用程序中复制相同的文件。不要忘记添加 'contextConfigLocation'，因为我们正在编写多个 bean 配置文件。

1.  在 com.ch03.beans 中添加 Book.java 作为 POJO，这是我们所有 JDBC 应用程序中使用过的。

1.  添加包含 BookDAO 和 BookDAO_JdbcTemplate 类的 com.packt.cho3.dao 包。

1.  在类路径中添加 connection_new.xml。

1.  在 com.packt.ch09.controllers 包中创建 MyBookController 类，并用 @RestController 注解标记它。

1.  将 BookDAO 作为数据成员添加，并用 @Autowired 注解标记它。

1.  现在，我们将添加 getBook() 方法来处理搜索书籍的网络服务请求。用 @GetMapping 注解 URL '/books/{ISBN}' 的方法，如下代码所示：

```java
        @RestController 
        @EnableWebMvc 
        public class MyBookController { 

          @Autowired 
          BookDAO bookDAO; 
          @GetMapping("/books/{ISBN}") 
          public ResponseEntity getBook(@PathVariable long ISBN) { 

            Book book = bookDAO.getBook(ISBN); 
            if (null == book) { 
              return new ResponseEntity<Book>(HttpStatus.NOT_FOUND); 
            } 

            return new ResponseEntity(book, HttpStatus.OK); 
          } 
        } 

```

`@GetMapping` 设置方法来处理以 'books/{ISBN}' 形式的 URL 的 GET 请求。{name_of_variable} 作为占位符，以便将数据传递给方法以供使用。我们还使用了应用于方法签名中的第一个参数的 `@PathVariable` 注解。它有助于将 URL 变量的值绑定到参数。在我们的案例中，ISBN 有通过 URL 的 ISBN 传递的值。

`HttpStatus.NO_CONTENT` 状态表示要设置响应的状态，指示资源已被处理，但数据不可用。

`ResponseEntity` 是 HttpEntity 的扩展，其中包含了关于 HttpStatus 的响应的附加信息。

让我们添加使用 RestTemplate 访问映射资源的客户端代码，如下所示：

```java
        public class Main_Get_Book { 
          public static void main(String[] args) { 
            // TODO Auto-generated method stub 

            RestTemplate template=new RestTemplate(); 
            Book book=   
             template.getForObject( 
               "http://localhost:8081/Ch09_Spring_Rest_JDBC/books/14", 
               Book.class); 
            System.out.println(book.getAuthor()+"\t"+book.getISBN()); 
          } 
        } 

```

在这里，我们获取 ISBN=14 的书籍。确保表中存在此 ISBN，如果没有，您可以添加自己的值。

执行 Main_Get_Book 以在控制台获取书籍详细信息。

我们可以使用以下步骤使用 POSTMAN 工具测试 Google Chrome 中的 RESTful web 服务：

1.  您可以在 Google Chrome 中安装 Postman REST 客户端，网址为 [`chrome.google.com/webstore/detail/postman-rest-client/fdmmgilgnpjigdojojpjoooidkmcomcm`](https://chrome.google.com/webstore/detail/postman-rest-client/fdmmgilgnpjigdojojpjoooidkmcomcm)

1.  一旦安装，通过点击 Postman 图标来启动它。

1.  现在，从下拉菜单中选择 GET 方法，并在文本字段中输入 URL http://localhost:8081/Ch09_Spring_Rest_JDBC/books/13。

1.  点击**“发送”**按钮。

1.  通过下面的图片显示的身体中的列表，我们将获得如下所示的数据：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/lrn-spr5/img/image_09_003.png)

URL 只指定了处理请求的处理程序方法，但它不能决定对资源采取什么行动。正如在讨论的示例中，我们使用处理的 HTTP GET 方法来获取数据。

一旦我们知道了如何获取数据，接下来让我们通过以下步骤更新数据：

1.  在 MyBookController 中添加 updateBook() 方法，它将被 `@PutMapping` 注解标记，以处理如下 URL：

```java
        @PutMapping("/books/{ISBN}") 
          public ResponseEntity<Book> updateBook(@PathVariable long  
          ISBN, @RequestBody Book book)  
        { 
          Book book_searched = bookDAO.getBook(ISBN); 
          if (book_searched == null) { 
            return new ResponseEntity(HttpStatus.NOT_FOUND); 
          } 
          bookDAO.updateBook(ISBN, book.getPrice()); 

          book_searched.setPrice(book.getPrice()); 
          return new ResponseEntity(book_searched, HttpStatus.OK); 
        } 

```

在这里，URL 被映射为 `PUT` 方法。

`updateBook()` 方法包括：

+   该参数是 ISBN，已通过`@PathVariable`注解绑定其值。

+   第二个参数是类型为 Book 并注解为`@ResponseBody`的对象。`@ResponseBody`注解是用于绑定 HTTP 响应体的标记，它用于将 HTTP 响应体绑定到领域对象。此注解使用 Spring 框架的标准 HTTP 消息转换器将响应体转换为相应的领域对象。

在这种情况下，`MappingJacksonHttpMessageConverter`将被选择将到达的 JSON 消息转换为 Book 对象。为了使用转换器，我们在 lib 文件夹中添加了相关库。我们将在后面的页面详细讨论消息转换器。

1.  如下面的代码所示，更新书籍的客户端代码：

```java
        public class Main_Update { 
          public static void main(String[] args) { 
            // TODO Auto-generated method stub 
            RestTemplate template = new RestTemplate(); 

            Map<String,Long> request_parms=new HashMap<>(); 
            request_parms.put("ISBN",13l); 

            Book book=new Book(); 
            book.setPrice(200); 
            template.put 
              ("http://localhost:8081/Ch09_Spring_Rest_JDBC/books/13", 
                book,request_parms); 
          } 
        } 

```

PUT 方法的签名如下：

```java
        void put(URL_for_the_resource, Object_to_update,Map_of_variable) 

```

1.  现在让我们通过 POSTMAN 进行测试，输入 URL，从下拉菜单中选择 PUT 方法，输入正文值，如下所示，然后点击发送：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/lrn-spr5/img/image_09_004.png)

获取和更新数据后，现在让我们添加以下步骤的代码以添加书籍资源：

1.  在控制器中添加一个`addBook()`方法，用@PostMapping 注解。

1.  我们将使用`@RequestBody`注解将 HTTP 请求体绑定到`book`领域对象，如下面的代码所示：

```java
        @PostMapping("/books") 
        public ResponseEntity<Book> addBook(@RequestBody Book book) { 
          System.out.println("book added" + book.getDescription()); 
          if (book == null) { 
            return new ResponseEntity<Book>(HttpStatus.NOT_FOUND); 
          } 
          int data = bookDAO.addBook(book); 
          if (data > 0) 
            return new ResponseEntity(book, HttpStatus.OK); 
          return new ResponseEntity(book, HttpStatus.NOT_FOUND); 
        } 

```

`@RequestBody`注解将请求体绑定到领域对象，在我们这个案例中是 Book 对象。

1.  现在让我们添加如下所示的客户端代码：

```java
        public class Main_AddBook { 
          public static void main(String[] args) { 
            // TODO Auto-generated method stub 
            RestTemplate template = new RestTemplate(); 

            Book book=new Book("add book",1234l,"adding  
              book",1000,"description adding","abcd"); 
            book.setDescription("new description"); 
            Book book2= template.postForObject( 
              "http://localhost:8081/Ch09_Spring_Rest_JDBC/books",   
              book,Book.class); 
            System.out.println(book2.getAuthor()); 
          } 
        } 

```

POST 方法取**`资源 URL`**、要在资源中添加的对象以及对象类型作为参数。

1.  在 POSTMAN 中，我们可以添加资源 URL 并选择 POST 方法，如图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/lrn-spr5/img/image_09_005.png)

1.  同样，我们将添加一个获取所有书籍的资源，如下所示：

```java
          @GetMapping("/books") 
          public ResponseEntity getAllBooks() { 

            List<Book> books = bookDAO.findAllBooks(); 
            return new ResponseEntity(books, HttpStatus.OK); 
          } 

```

为了测试 getAllBook，请按照以下方式添加客户端代码：

```java
        public class Main_GetAll { 

          public static void main(String[] args) { 
            RestTemplate template = new RestTemplate(); 
            ResponseEntity<Book[]> responseEntity=   
              template.getForEntity( 
                "http://localhost:8081/Ch09_Spring_Rest_JDBC/books",   
                Book[].class); 
            Book[] books=responseEntity.getBody(); 
            for(Book book:books) 
            System.out.println(book.getAuthor()+"\t"+book.getISBN()); 
          } 
        } 

```

响应是 JSON 类型，包含书籍数组，我们可以从响应体中获取。

1.  让我们通过 POSTMAN 获取列表，通过添加 URL [`localhost:8081/Ch09_Spring_Rest_JDBC/books`](http://localhost:8081/Ch09_Spring_Rest_JDBC/books)并选择 GET 方法。我们将以 JSON 格式获取书籍列表，如图快照所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/lrn-spr5/img/image_09_006.png)

同样，我们可以编写一个通过 ISBN 删除书籍的方法。你可以找到代码

### 数据展示

在讨论的示例中，我们使用 JSON 来表示资源，但在实践中，消费者可能更喜欢其他资源格式，如 XML、PDF 或 HTML。无论消费者想要哪种表示格式，控制器都最不关心。Spring 提供了以下两种方式来处理响应，将其转换为客户端将消费的表现状态。

+   HTTP based message converters

+   基于视图的视图渲染协商。

#### Http-based message converters

控制器执行它们的主要任务，产生数据，这些数据将在视图部分展示。有多种方法可以识别用于表示的视图，但有一种直接的方法，其中从控制器返回的对象数据隐式转换为适合客户端的适当表示。隐式转换的工作由 HTTP 消息转换器完成。以下是由 Spring 提供的处理消息和 Java 对象之间常见转换的消息转换器：

+   ByteArrayHttpMessageConverter - 它转换字节数组

+   StringHttpMessageConverter - 它转换字符串

+   ResourceHttpMessageConverter - 它转换 org.springframework.core.io.Resource 为任何类型的字节流

+   SourceHttpMessageConverter - 它转换 javax.xml.transform.Source

+   FormHttpMessageConverter - 它转换表单数据到/自 MultiValueMap<String, String>的值。

+   Jaxb2RootElementHttpMessageConverter - 它将 Java 对象转换为/从 XML

+   MappingJackson2HttpMessageConverter - 它转换 JSON

+   MappingJacksonHttpMessageConverter - 它转换 JSON

+   AtomFeedHttpMessageConverter - 它转换 Atom 源

+   RssChannelHttpMessageConverter - 它转换 RSS 源

+   MarshallingHttpMessageConverter - 它转换 XML

#### 基于协商视图的视图渲染

我们已经深入讨论了 Spring MVC，以处理数据并展示数据。ModelAndView 有助于设置视图名称和其中要绑定的数据。视图名称随后将由前端控制器使用，通过 ViewResolver 的帮助从确切位置定位实际视图。在 Spring MVC 中，仅解析名称并在其中绑定数据就足够了，但在 RESTful Web 服务中，我们需要比这更多。在这里，仅仅匹配视图名称是不够的，选择合适的视图也很重要。视图必须与客户端所需的代表状态相匹配。如果用户需要 JSON，则必须选择能够将获取的消息渲染为 JSON 的视图。

Spring 提供 ContentNegotiatingViewResolver 以根据客户端所需的内容类型解析视图。以下是我们需要添加以选择视图的 bean 配置：

配置中引用了 ContentNegotiationManagerFacrtoryBean，通过'cnManager'引用。我们将在讨论演示时进行其配置。在这里，我们配置了两个 ViewResolvers，一个用于 PDF 查看器，另一个用于 JSP。

从请求路径中检查的第一个事情是其扩展名以确定媒体类型。如果没有找到匹配项，则使用请求的文件名使用 FileTypeMap 获取媒体类型。如果仍然不可用，则检查接受头。一旦知道媒体类型，就需要检查是否支持视图解析器。如果可用，则将请求委派给适当的视图解析器。在开发自定义视图解析器时，我们需要遵循以下步骤：

1.  开发自定义视图。这个自定义视图将是 AbstractPdfView 或 AbstractRssFeedView 或 AbstractExcelView 的子视图。

+   根据视图，需要编写 ViewResolver 实现。

+   在上下文中注册自定义视图解析器。

+   让我们使用自定义视图解析器和示例数据逐步生成 PDF 文件。

1.  添加 boo-servlet.xml 处理器映射文件，其中将包含注解配置和发现控制器的配置。你可以从之前的应用程序中复制这个。

1.  在 web.xml 中添加前端控制器，就像在之前的应用程序中一样。

1.  下载并添加 itextpdf-5.5.6.jar 以处理 PDF 文件。

1.  创建 Ch09_Spring_Rest_ViewResolver 作为动态网络应用程序，并添加所有必需的 jar 文件。

1.  将`MyBookController`作为 RestController 添加到 com.packt.ch09.controller 包中。处理'books/{author}' URL 的方法。该方法有一个 ModelMap 参数，用于添加'book list'模型。这里我们添加了一个书目列表的占位符，但你也可以添加从数据库获取数据的代码。代码如下所示：

```java
        @RestController 
         public class MyBookController { 
         @RequestMapping(value="/books/{author}", method =   
           RequestMethod.GET) 
         public String getBook(@PathVariable String author,  
           ModelMap model)  
           { 
             List<Book> books=new ArrayList<>(); 
            books.add(new    
              Book("Book1",10l,"publication1",100, 
              "description","auuthor1")); 
            books.add(new Book("Book2",11l,"publication1",200,    
              "description","auuthor1")); 
            books.add(new Book("Book3",12l,"publication1",500, 
              "description","auuthor1")); 

            model.addAttribute("book", books); 
             return "book"; 
          } 
        } 

```

我们稍后将在'book'作为视图名称的情况下添加 JSP 视图，这是由处理器方法返回的。

1.  让我们添加一个`AbstarctPdfView`的子视图 PDFView，如下所示的代码：

```java
        public class PdfView extends AbstractPdfView { 
          @Override 
          protected void buildPdfDocument(Map<String, Object> model,  
            Document document, PdfWriter writer, 
              HttpServletRequest request, HttpServletResponse    
                response) throws Exception  
          { 
            List<Book> books = (List<Book>) model.get("book"); 
            PdfPTable table = new PdfPTable(3); 
              table.getDefaultCell().setHorizontalAlignment 
            (Element.ALIGN_CENTER); 
            table.getDefaultCell(). 
              setVerticalAlignment(Element.ALIGN_MIDDLE); 
            table.getDefaultCell().setBackgroundColor(Color.lightGray); 

            table.addCell("Book Name"); 
            table.addCell("Author Name"); 
            table.addCell("Price"); 

            for (Book book : books) { 
              table.addCell(book.getBookName()); 
              table.addCell(book.getAuthor()); 
              table.addCell("" + book.getPrice()); 
            } 
            document.add(table); 

          } 
        } 

```

`pdfBuildDocument()`方法将使用 PdfTable 帮助设计 PDF 文件的外观，作为具有表头和要显示的数据的文档。`.addCell()`方法将表头和数据绑定到表中。

1.  现在让我们添加一个实现`ViewResolver`的 PdfViewResolver，如下所示：

```java
        public class PdfViewResolver implements ViewResolver{ 

          @Override 
          public View resolveViewName(String viewName, Locale locale)  
            throws Exception { 
            PdfView view = new PdfView(); 
            return view; 
          } 
        } 

```

1.  现在我们需要将视图解析器注册到上下文。这可以通过在配置中添加内容协商视图解析器 bean 来完成。

1.  内容协商视图解析器 bean 引用内容协商管理器工厂 bean，因此让我们再添加一个 bean，如下所示：

```java
        <bean id="cnManager"  class= "org.springframework.web.accept. 
            ContentNegotiationManagerFactoryBean"> 
            <property name="ignoreAcceptHeader" value="true" /> 
            <property name="defaultContentType" value="text/html" /> 
        </bean>
```

1.  我们已经添加了自定义视图，但我们也将添加 JSP 页面作为我们的默认视图。让我们在/WEB-INF/views 下添加 book.jsp。你可以检查 InternalResourceViewResolver 的配置以获取 JSP 页面的确切位置。以下是用以下步骤显示的代码：

```java
        <html> 
        <%@ taglib prefix="c"   
                 uri="http://java.sun.com/jsp/jstl/core"%> 
        <title>Book LIST</title> 
        </head> 
        <body> 
          <table border="1"> 
            <tr> 
              <td>Book NAME</td> 
              <td>Book AUTHOR</td> 
              <td>BOOK PRICE</td> 
            </tr> 
            <tr> 
              <td>${book.bookName}</td> 
              <td>${book.author}</td> 
              <td>${book.price}</td> 
            </tr> 
          </table> 
        </body> 
        </html>
```

1.  是的，我们已经完成了应用程序的编写，现在该是测试应用程序的时候了。在服务器上运行应用程序，在浏览器中输入`http://localhost:8080/Ch09_Spring_Rest_ViewResolver/books/author1.pdf`。

`auuthor1`是作者的名字，我们想要获取他的书籍列表，扩展名 PDF 显示消费者期望的视图类型。

在浏览器中，我们将得到以下输出：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/lrn-spr5/img/image_09_007.png)

## 摘要

* * *

在本章的开头，我们讨论了网络服务以及网络服务的重要性。我们还讨论了 SOAP 和 RESTful 网络服务。我们深入讨论了如何编写处理 URL 的 RestController。RestController 围绕 URL 展开，我们概述了如何设计 URL 以映射到处理方法。我们开发了一个在客户端请求到来时处理所有 CRUD 方法的 RestController，该控制器与数据库交互。我们还深入讨论了 RestTemplate，这是一种简单且复杂度较低的测试 RESTful 网络服务的方法，该方法适用于不同类型的 HTTP 方法。进一步地，我们还使用 POSTMAN 应用程序测试了开发的网络服务。无论消费者需要什么，开发网络服务都是一种单向交通。我们还探讨了消息转换器和内容协商，以通过不同的视图服务于消费者。

在下一章中，我们将探讨最具讨论性的话题，以及一个正在改变网络体验的 Spring 新入门。我们将讨论关于 WebSocket 的内容。


## 第九章。交换消息：消息传递

到目前为止，我们已经讨论了很多关于基于传统 HTTP 通信的双向网络应用程序。这些基于浏览器的应用程序通过打开多个连接提供双向通信。**WebSocket 协议**提供了一种基于 TCP 的消息传递方式，不依赖于打开多个 HTTP 连接。在本章中，我们将通过以下几点讨论 WebSocket 协议：

+   **消息传递简介**

+   **WebSocket 协议简介**

+   **WebSocket API**

+   **STOMP 概览**

在网络应用程序中，客户端和服务器之间的双向通信是同步的，其中客户端请求资源，服务器发送 HTTP 调用通知。它解决了以下问题：

+   必须打开多个连接以发送信息并收集传入消息

+   跟踪将外出连接映射到进入连接，以便跟踪请求及其回复

更好的解决方案是维护一个用于发送和接收的单一 TCP 连接，这正是 WebSocket 作为无头部的低层协议所提供的。由于没有添加头部，传输网络的数据量减少，从而降低了负载。这是通过称为拉取技术的过程来实现的，而不是 AJAX 中使用的长拉取的推技术。现在，开发者们正在使用**XMLHttpRequest（XHR）**进行异步 HTTP 通信。WebSocket 使用 HTTP 作为传输层，以支持使用 80、443 端口的基础设施。在这种双向通信中，成功的连接数据传输是独立于他们的意愿进行的。

《RFC 6455》将 WebSocket 协议定义为，一种在客户端运行在受控环境中与远程主机通信的客户端和服务器之间的双向通信协议，该远程主机已允许接受邮件、电子邮件或任何直接从代码发出的通信。该协议包括打开握手，随后是基本的报文框架，该框架建立在 TCP 协议之上。如果服务器同意，它会发送 HTTP 状态码 101，表示成功的握手。现在连接将保持开放，可以进行消息交换。以下图表给出了通信如何进行的大致概念：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/lrn-spr5/img/image_10_001.png)

WebSocket 在 TCP 之上执行以下操作：

+   它向浏览器添加了网络安全模型。

+   由于一个端口需要支持多个主机名和多个服务，因此它增加了地址和命名机制以提供这种支持。

+   它在 TCP 之上形成了一层框架机制，以促进 IP 包机制。

+   关闭握手机制。

在 WebSocket 中的数据传输使用一系列的帧。这样的数据帧可以在打开握手之后，在端点发送 Close 帧之前，由任一方随时传输。

## Spring 和消息传递

* * *

从 Spring 4.0 开始，就有对 WebSocket 的支持，引入了 spring-websocket 模块，该模块与 Java WebSocket API（JSR-356）兼容。HTTPServlet 和 REST 应用程序使用 URL、HTTP 方法在客户端和服务器之间交换数据。但与这种相反，WebSocket 应用程序可能使用单个 URL 进行初始握手，这是异步的、消息传递的，甚至是基于 JMS 或 AMQP 的架构。Spring 4 包括 spring-messaging 模块，以集成消息、消息通道、消息处理器，一系列注解用于将消息映射到方法，以及许多其他功能以支持基本的消息传递架构。@Controller 和@RestController 我们已经用来创建 Spring MVC 网络应用程序和 RESTful 网络服务，它允许处理 HTTP 请求也支持 WebSocket 消息的处理方法。此外，控制器中的处理方法可以将消息广播给所有感兴趣的用户特定的 WebSocket 客户端。

### 使用

WebSocket 架构适用于所有那些需要频繁交换事件的网络应用程序，在这些应用程序中，数据交换到目标的时间是非常重要的，例如：

+   社交媒体目前在日常生活中扮演着非常重要的角色，并且对于与家人和朋友保持联系起着至关重要的作用。用户总是喜欢实时接收他们圈子内完成的 Feed 更新。

+   如今，许多在线多人游戏都可以在网络上找到。在这样的游戏中，每个玩家总是急于知道他的对手正在做什么。没有人希望在对手采取行动时发现对手的举动。

+   在开发过程中，版本控制工具如 Tortoise SVN、Git 有助于跟踪文件。这样，在代码交换时就不会发生冲突，变得更加容易。但在这里，我们无法实时获取谁正在处理哪个文件的信息。

+   在金融投资中，人们总是希望知道他所感兴趣公司的实时股价，而不是之前的某个时间的股价。

## WebSocket API 概述

* * *

springframework 框架通过提供采用各种 WebSocket 引擎的 API，实现了 WebSocket 的创建。如今 Tomcat7.0.47+、Jetty 9.1+、WebLogic 12.1.3+、GlassFish 4.1+为 WebSocket 提供了运行环境。

### WebSocket 处理器的创建

我们可以通过实现 WebSocketHandler 接口或从 TextWebSocketHandler 或 BinaryWebSocketHandler 继承来创建 WebSocketHandler，如下代码片段所示：

```java
public class MyWebSocketHandler extends TextWebSocketHandler{ 
@Override 
   public void handleTextMessage(WebSocketSession session,     
     TextMessage message) 
   { 
       // code goes here 
   } 
} 

```

可以使用 WebSocketDecorator 类来装饰 WebSocketHandler。Spring 提供了一些装饰器类来处理异常、日志机制和处理二进制数据。`ExceptionWebSocketHandler`是一个异常处理的 WebSocketHandlerDecorator，它可以帮助处理所有 Throwable 实例。`LoggingWebSocketHandlerDecorator`为 WebSocket 生命周期中发生的事件添加日志记录。

### 注册 WebSocketHandler

WebSocket 处理器被映射到特定的 URL 以注册此映射。此框架可以通过 Java 配置或 XML 基础配置来完成。

#### 基于 Java 的配置

`WebSocketConfigurer` 用于在`registerWebSocketHandlers()`方法中将处理器与其特定的 URL 映射，如下面的代码所示：

```java
@Configuration 
@EnableWebSocket 
public class WebSocketConfig implements WebSocketConfigurer { 
  @Override 
  public void registerWebSocketHandlers(WebSocketHandlerRegistry   
     registry)  
  { 
     registry.addHandler(createHandler(), "/webSocketHandler"); 
  } 
  @Bean 
  public WebSocketHandler createMyHandler() { 
    return new MyWebSocketHandler(); 
  } 
} 

```

在此处，我们的 WebSocketHandler 被映射到了`/webSocketHandler` URL。

自定义 WebSocketHandler 以自定义握手的操作可以如下进行：

```java
@Configuration 
@EnableWebSocket 
public class MyWebSocketConfig implements WebSocketConfigurer { 
  @Override 
  public void registerWebSocketHandlers(WebSocketHandlerRegistry   
    registry)  
  { 
    registry.addHandler(createHandler(),     
       "/webSocketHandler").addInterceptors 
       (new HttpSessionHandshakeInterceptor()); 
  } 
  @Bean 
  public WebSocketHandler createMyHandler() { 
    return new MyWebSocketHandler(); 
  } 
} 

```

握手拦截器暴露了`beforeHandshake()`和`afterhandshake()`方法，以自定义 WebSocket 握手。`HttpSessionHandshakeInterceptor`促进了将 HtttpSession 中的信息绑定到名为`HTTP_SESSION_ID_ATTR_NAME`的握手属性下。这些属性可以用作`WebSocketSession.getAttributes()`方法。

#### XML 基础配置

上述 Java 代码片段中的注册也可以用 XML 完成。我们需要在 XML 中注册 WebSocket 命名空间，然后如以下所示配置处理器：

```java
<beans xmlns="http://www.springframework.org/schema/beans" 
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" 
  xmlns:websocket= 
http://www.springframework.org/schema/websocket 
   xsi:schemaLocation= 
    "http://www.springframework.org/schema/beans 
  http://www.springframework.org/schema/beans/spring-beans.xsd 
    http://www.springframework.org/schema/websocket 
http://www.springframework.org/schema/websocket/spring- 
    websocket.xsd"> 
  <websocket:handlers> 
    <websocket:mapping path="/myWebSocketHandler"  
     handler="myWebSocketHandler"/> 
     </websocket:handlers> 
   <bean id="myWebSocketHandler"   
    class="com.packt.ch10.WebsocketHandlers. MyWebSocketHandler"       
    /> 
</beans> 

```

在 XML 中自定义的 WebSocketConfigurer 可以写成如下形式：

```java
<websocket:handlers> 
    <websocket:mapping path="/myWebSocketHandler"  
       handler="myWebSocketHandler"/> 
    <websocket:handshake-interceptors> 
      <bean class= 
         "org.springframework.web.socket.server.support. 
         HttpSessionHandshakeInterceptor"/> 
    </websocket:handshake-interceptors> 
     </websocket:handlers> 
  <!-bean for MyWebSocketHandler -à 
</beans>  

```

#### WebSocket 引擎配置

Tomcat7.0.47+, Jetty 9.1+,WebLogic 12.1.3+, GlassFish 4.1+ 为 WebSocket 提供运行环境。可以通过添加 WebSocketConfigurer 的 bean 来为 Tomcat 运行环境配置消息缓冲区大小、超时等特性，如下所示：

```java
@Bean 
public ServletServerContainerFactoryBean  
  createWebSocketContainer()  
{ 
  ServletServerContainerFactoryBean webSocketcontainer =  
    new ServletServerContainerFactoryBean(); 
    webSocketcontainer .setMaxTextMessageBufferSize(9000); 
    webSocketcontainer .setMaxBinaryMessageBufferSize(9000); 
  return webSocketcontainer ; 
  } 
} 

```

等效的 XML 配置可以写成：

```java
<bean class= "org.springframework.web.socket.server.standard. 
  ServletServerContainerFactoryBean"> 
  <property name="maxTextMessageBufferSize" value="9000"/> 
  <property name="maxBinaryMessageBufferSize" value="9000"/> 
</bean> 

```

##### 允许的来源配置

`origin`是代理商的特权范围。由众多作者以各种格式创建的内容存在其中，其中一些可能是有害的。由一个来源创建的内容可以自由地与其他来源的内容进行交互。代理商有设置规则的权限，其中一个内容与其他内容交互，称为**“同源策略”**。

让我们以 HTML 为例，其中有表单提交。每当用户代理输入数据时，输入的数据会被导出到 URI。在此处，URI 声明了对脚本文件通过 URI 接收的信息的完整性信任。

`http://packt.com/`, `http://packt.com:8080/`, `http://www.packt.com/`, `https://packt.com:80/`, `https://packt.com/`, `http://packt.org/` 是不同的 URI。

配置来源有三种方式：

+   允许同源

+   允许指定的来源列表。

+   允许所有来源

让我们首先详细讨论关于客户端服务器通信中 WebSocket 的创建和使用：

1.  WebSocket 的创建：

```java
      WebSocket socket=  new WebSocket( URL, protocols); 

```

+   URL 包含的内容：

    +   **协议**：URL 必须包含`ws`，表示不安全连接，或`wss`，表示安全连接。

    +   **主机名：**这是服务器的一个名称或 IP 地址。

    +   **端口**：我们要连接的远程端口，ws 连接默认使用端口'80'，而 wss 使用 443。

    +   **资源名称**：要获取的资源的路径 URL。

+   我们可以将 WebSocket 的 URL 写为：

    +   协议://主机名:端口号/资源路径

    +   ws://主机名:端口号/资源路径

    +   wss://主机名:端口号/资源路径

1.  关闭 WebSocket：

关闭连接时，我们使用`close()`方法，如`close(code, reason)`。

### 注意

代码：这是一个发送给服务器的数值状态。1000 表示正常关闭连接。

1.  WebSocket 的状态：

以下是 WebSocket 的连接状态，提供它处于哪种状态的信息：

+   **连接中**：构造 WebSocket，并尝试连接到指定 URL。这个状态被认为是连接状态，准备状态值为 0。

+   **打开**：一旦 WebSocket 成功连接到 URL，它将进入打开状态。只有在 WebSocket 处于打开状态时，数据才能在网络之间发送和接收。打开状态的准备状态值是"1"。

+   **关闭**：WebSocket 不会直接关闭，它必须与服务器通信，通知它正在断开连接。这个状态被认为是关闭状态。"open"状态的准备状态值是"2"。

+   **已关闭**：从服务器成功断开连接后，WebSocket 进入关闭状态。处于关闭状态的 WebSocket 有一个"readyState"值为 3。

1.  在 WebSocket 中的事件处理：

WebSocket 基于事件处理原理工作，其中回调方法被调用以完成过程。以下是 WebSocket 生命周期中发生的事件：

+   **onopen**：当 WebSocket 过渡到开放状态时，"onopen"事件处理程序会被调用。

+   **onmessage**：当 WebSocket 从服务器接收数据时，"onmessage"事件处理程序会被调用。接收到的数据将存储在"message"事件的"data"字段中。

数据字段有参数：

+   **onclose**：当 WebSocket 关闭时，"onclose"事件处理程序会被调用。事件对象将传递给"onclose"。它有三个字段：

+   **代码**：服务器提供的数值状态值。

+   **原因**：这是一个描述关闭事件的字符串。

+   **wasClean**：有一个布尔值，表示连接是否没有问题地关闭。在正常情况下，"wasClean"是 true。

+   **onerror**：当 WebSocket 遇到任何问题时，"onerror"事件处理程序会被调用。传递给处理程序的事件将是一个标准错误对象，包括"name"和"message"字段。

1.  发送数据：

数据传输通过`send()`方法进行，该方法处理 UTF-8 文本数据、ArrayBuffer 类型的数据以及 blob 类型的数据。'bufferedAmount'属性值为零确保数据发送成功。

让我们通过以下步骤开发一个 WebSocket 演示来查找国家首都：

1.  创建 Ch10_Spring_Message_Handler 作为动态网络应用程序。

1.  添加 Spring 核心、Spring 网络、spring-websocket、spring-messaging 模块的 jar 文件。还要添加 Jackson 的 jar 文件。

1.  让我们在 compackt.ch10.config 包中添加 MyMessageHandler 作为 TextWebSocketHandler 的子项。覆盖处理消息、WebSocket 连接、连接关闭的方法，如下所示：

```java
public class MyMessageHandler extends TextWebSocketHandler { 

        List<WebSocketSession> sessions = new CopyOnWriteArrayList<>(); 

          @Override 
          public void handleTextMessage(WebSocketSession session,  
            TextMessage message) throws IOException { 
            String country = message.getPayload(); 
            String reply="No data available"; 
            if(country.equals("India"))  { 
              reply="DELHI"; 
            } 
            else if(country.equals("USA"))  { 
                  reply="Washington,D.C";     
             } 
            System.out.println("hanlding message"); 

            for(WebSocketSession webSsession:sessions){ 
              session.sendMessage(new TextMessage(reply));   
            } 
          } 
          @Override 
          public void afterConnectionEstablished(WebSocketSession  
             session) throws IOException { 
            // Handle new connection here 
            System.out.println("connection establieshed:hello"); 
            sessions.add(session); 
            session.sendMessage(new TextMessage("connection  
              establieshed:hello")); 
            } 
          @Override 
          public void afterConnectionClosed(WebSocketSession session,   
            CloseStatus status) throws IOException { 
            // Handle closing connection here 
            System.out.println("connection closed : BYE"); 
          } 
          @Override 
          public void handleTransportError(WebSocketSession session,  
            Throwable exception) throws IOException { 
              session.sendMessage(new TextMessage("Error!!!!!!")); 
            } 
        } 

```

这个 MessageHandler 需要注册到 WebSocketConfigurer，为所有源的 URL'/myHandler'，如下所示：

```java
        @Configuration 
        @EnableWebSocket 
        public class MyWebSocketConfigurer extends  
        WebMvcConfigurerAdapter implements WebSocketConfigurer
        { 
          @Override 
          public void
          registerWebSocketHandlers(WebSocketHandlerRegistry  
            registry) { 
            registry.addHandler(myHandler(),  
            "/myHandler").setAllowedOrigins("*"); 
          } 
          @Bean 
          public WebSocketHandler myHandler() { 
            return new MyMessageHandler(); 
          } 
          // Allow the HTML files through the default Servlet 
          @Override 
           public void configureDefaultServletHandling 
             (DefaultServletHandlerConfigurer configurer) { 
            configurer.enable(); 
          } 
        } 

```

1.  在 web.xml 中添加前端控制器映射，就像在之前的应用程序中一样，servlet 名称是'books'。

1.  为了添加`viewResolver`的 bean，请添加 books-servlet.xml 文件。你可以根据应用程序的需求决定是否添加它作为一个 bean。

1.  还要添加配置以启用 Spring Web MVC，如下所示：

```java
        <mvc:annotation-driven /> 

```

1.  添加 country.jsp 作为一个 JSP 页面，其中包含一个国家列表，用户可以从下拉列表中选择国家以获取其首都名称：

```java
        <div> 
          <select id="country"> 
                <option value="India">INDIA</option> 
                <option value="USA">U.S.A</option> 
          </select><br> 
          <br> <br> 
           <button id="show" onclick="connect();">Connect</button> 
              <br /> <br /> 
            </div> 
          <div id="messageDiv"> 
              <p>CAPITAL WILL BE DISPLAYED HERE</p> 
              <p id="msgResponse"></p> 
          </div> 
        </div> 

```

1.  通过在你的资源中添加 sockjs-0.3.4.js，或者通过添加以下代码来添加 SockJS 支持：

```java
        <script type="text/javascript"  
          src="img/sockjs-0.3.4.js"></script>
```

1.  在表单提交时，会调用一个 JavaScript 方法，我们在前面讨论过的 onopen、onmessage 等 WebSocket 事件上处理该方法。

```java
        <script type="text/javascript"> 
          var stompClient = null; 
          function setConnected(connected) { 
            document.getElementById('show').disabled = connected; 
          } 
          function connect() { 
            if (window.WebSocket) { 
              message = "supported"; 
              console.log("BROWSER SUPPORTED"); 
            } else { 
              console.log("BROWSER NOT SUPPORTED"); 
            } 
            var country = document.getElementById('country').value; 
            var socket = new WebSocket( 
              "ws://localhost:8081/Ch10_Spring_Message_Handler 
              /webS/myHandler"); 
                socket.onmessage=function(data){ 
                  showResult("Message Arrived"+data.data)        
                }; 
                setConnected(true); 
                socket.onopen = function(e) { 
                    console.log("Connection established!"); 
                    socket.send(country); 
                    console.log("sending data"); 
                };     
          } 
          function disconnect() { 
              if (socket != null) { 
                socket.close(); 
              } 
              setConnected(false); 
              console.log("Disconnected"); 
          } 
          function showResult(message) { 
            var response = document.getElementById('messageDiv'); 
            var p = document.createElement('p'); 
            p.style.wordWrap = 'break-word'; 
            p.appendChild(document.createTextNode(message)); 
            response.appendChild(p); 
          } 
        </script>
```

我们已经讨论过如何编写 WebSocket URL 和事件处理机制。

部署应用程序并访问页面。从下拉列表中选择国家，然后点击显示首都按钮。将显示首都名称的消息。

以下图表显示了应用程序的流程：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/lrn-spr5/img/image_10_002.png)

我们添加了控制台日志以及警告消息，以了解进度和消息的往返。根据需求，你可以自定义它，也可以完全省略。

在之前的示例中，我们使用了 WebSocket 进行通信，但其支持仍然有限。SockJS 是一个 JavaScript 库，它提供了类似于 WebSocket 的对象。

## SockJS

****

SockJS 库提供跨浏览器、JavaScript API，以实现浏览器和服务器之间的低延迟、跨域通信。它旨在支持以下目标：

+   使用 SockJS 实例，而不是 WebSocket 实例。

+   这些 API 对于服务器和客户端的 API 来说都非常接近 WebSocket API。

+   支持更快的通信

+   客户端的 JavaScript

+   它带有支持跨域通信的一些选择性协议

以下代码显示了如何为 WebSocketConfigurer 启用 SockJS 支持：

```java
@Override 
public void registerWebSocketHandlers(WebSocketHandlerRegistry  
  registry)  
{ 
  registry.addHandler(myHandler(),  
    "/myHandler_sockjs").setAllowedOrigins("*").withSockJS(); 
} 

```

或者我们可以在 XML 中配置：

```java
<websocket:handlers> 
   <websocket:mapping path="/myHandler"  
     handler="myHandler_sockjs"/> 
   <websocket:sockjs/> 
</websocket:handlers> 

```

我们可以将前面开发的 Capital 演示更新以支持 SockJS，如下所示：

1.  在 WebContent 中添加 country_sockjs.jsp，以便与 SockJS 一起使用，如下所示：

```java
        var socket = new SockJS( 
              "http://localhost:8080/Ch10_Spring_Message_Handler 
        /webS/myHandler_sockjs"); 

```

1.  在 com.packt.ch10.config 包中添加 MyWebSocketConfigurer_sockjs 以配置 WebSocket，就像我们之前做的那样。为了启用 SockJS 支持，我们必须修改`registerWebSocketHandlers()`方法，像上面配置中显示的那样使用`withSockJS()`。

1.  运行应用程序并请求 country_sockjs.jsp 以使用 SockJS。你也可以观察控制台日志。

在上述示例中，我们使用了 WebSocket 来获取连接并处理事件。这里还引入了新的 WebSocket 协议用于通信。它使用更少的带宽。它没有 HTTP 那样的头部，使得通信更简单、高效。我们也可以使用 STOMP 进行通信。

## STOMP

***

**简单（或流式）文本导向消息协议（STOMP）**通过 WebSocket 为 STOMP 帧到 JavaScript 对象的直接映射提供了支持。WebSocket 是最快的协议，但仍然不被所有浏览器支持。浏览器在支持代理和协议处理方面存在问题。所有浏览器广泛支持还需要一段时间，与此同时我们需要找到一些替代方案或实时解决方案。SockJS 支持 STOMP 协议，通过脚本语言与任何消息代理进行通信，是 AMQP 的一个替代方案。STOMP 在客户端和服务器端都很容易实现，并且提供了可靠地发送单条消息的功能，然后断开连接或从目的地消费所有消息。它定义了以下不同的帧，这些帧映射到 WebSocket 帧：

+   **CONNECT（连接客户端和服务器）**：

+   **SUBSCRIBE（用于注册，可以监听给定目的地）**：

+   **UNSUBSCRIBE（用于移除现有订阅）**：

+   **SEND（发送给服务器的消息）**：该帧将消息发送到目的地。

+   **MESSAGE（来自服务器的消息）**：它将来自订阅的消息传递给客户端。

+   **BEGIN（开始事务）**：

+   **COMMIT（提交进行中的事务）**：

+   **ABORT（回滚进行中的事务）**：

+   **DISCONNECT（使客户端与服务器断开连接）**：

它还支持以下标准头：

+   **内容长度（content-length）**：SEND、MESSAGE 和 ERROR 帧包含内容长度头，其值为消息体的内容长度。

+   **内容类型（content-type）**：SEND、MESSAGE 和 ERROR 帧包含内容类型。它在 Web 技术中类似于 MIME 类型。

+   **收据（receipt）**：CONNECT 帧可能包含收据作为头属性，以确认服务器收到 RECEIPT 帧。

+   **心跳（heart-beat）**：它由 CONNECT 和 CONNECTED 帧添加。它包含两个由逗号分隔的正整数值。

+   第一个值代表外出心跳。'0'指定它不能发送心跳。

+   第二个值表示进入心跳。'0'表示不愿意接收心跳。

### Spring STOMP 支持

Spring WebSocket 应用程序作为 STOMP 代理对所有客户端工作。每个消息将通过 Spring 控制器进行路由。这些控制器通过@RequestMapping 注解处理 HTTP 请求和响应。同样，它们也通过@Messaging 注解处理 WebSocket 消息。Spring 还提供了将 RabbitMQ、ActiveMQ 作为 STOMP 代理以进行消息广播的集成。

让我们逐步开发一个使用 STOMP 的应用程序：

1.  创建 Ch10_Spring_Messaging_STOMP 作为一个动态网络应用程序，并添加我们之前添加的 jar 文件。

1.  在 web.xml 中为 DispatcherServlet 添加映射，其名称为 books，URL 模式为'webS'。

1.  添加 books-servlet.xml 以注册`viewResolver`bean。注册以发现控制器，并考虑所有 MVC 注解。

1.  在 com.packt.ch10.config 包中添加 WebSocketConfig_custom 作为一个类，以将`'/book'`作为 SockJS 的端点，将`'/topic'`作为`'/bookApp'`前缀的 SimpleBroker。代码如下：

```java
        @Configuration 
        @EnableWebSocketMessageBroker 
        public class WebSocketConfig_custom extends 
          AbstractWebSocketMessageBrokerConfigurer { 
          @Override 
          public void configureMessageBroker(
            MessageBrokerRegistry config) { 
            config.enableSimpleBroker("/topic"); 
            config.setApplicationDestinationPrefixes("/bookApp"); 
          } 
          @Override 
          public void registerStompEndpoints(
            StompEndpointRegistry registry) { 
            registry.addEndpoint("/book").withSockJS(); 
          } 
        } 

```

`@EnableWebSocketMessageBroker`使类能够作为消息代理。

1.  在 com.packt.ch10.model 包中添加具有 bookName 作为数据成员的 MyBook POJO。

1.  类似地，添加一个结果为数据成员的 Result POJO，其具有 getOffer 方法如下：

```java
        public void getOffer(String bookName) { 
          if (bookName.equals("Spring 5.0")) { 
            result = bookName + " is having offer of having 20% off"; 
            } else if (bookName.equals("Core JAVA")) { 
              result = bookName + " Buy two books and get 10% off"; 
            } else if (bookName.equals("Spring 4.0")) { 
              result = bookName + " is having for 1000 till month  
            end"; 
            } 
            else 
              result = bookName + " is not available on the list"; 
          } 

```

1.  添加 index.html 以从控制器获取'`bookPage`'链接如下：

```java
        <body> 
               <a href="webS/bookPage">CLICK to get BOOK Page</a> 
        </body>
```

1.  在 com.packt.ch10.controller 包中添加 WebSocketController 类，并用@Controller("webs")注解它。

1.  添加注解为@RequestMapping 的`bookPage()`方法，以将 bookPage.jsp 发送给客户端，如下所示：

```java
        @Controller("/webS") 
        public class WebSocketController { 
          @RequestMapping("/bookPage") 
          public String bookPage() { 
            System.out.println("hello"); 
            return "book"; 
        } 

```

1.  在 jsps 文件夹中添加 bookPage.jsp。该页面将显示获取相关优惠的书籍名称。代码如下：

```java
        <body> 
        <div> 
           <div> 
              <button id="connect" 
                onclick="connect();">Connect</button> 
              <button id="disconnect" disabled="disabled"   
                 onclick="disconnect();">Disconnect</button><br/><br/> 
            </div> 
            <div id="bookDiv"> 
                <label>SELECT BOOK NAME</label> 
                 <select id="bookName" name="bookName"> 
                     <option> Core JAVA </option>     
                     <option> Spring 5.0 </option> 
                     <option> Spring 4.0 </option> 
                 </select> 
                <button id="sendBook" onclick="sendBook();">Send to                 Add</button> 
                <p id="bookResponse"></p> 
            </div> 
          </div> 
        </body>
```

1.  一旦客户端点击按钮，我们将处理回调方法，并添加 sockjs 和 STOMP 的脚本如下：

```java
        <script type="text/javascript"                 
         src="img/sockjs-0.3.4.js"></script>            <script type="text/javascript"  
         src="https://cdnjs.cloudflare.com/ajax/libs/stomp.js/2.3.3/ 
        stomp.js"/> 

```

1.  现在我们将逐一添加连接、断开连接、发送、订阅的方法。让我们首先添加如下获取 STOMP 连接的连接方法：

```java
        <script type="text/javascript"> 
           var stompClient = null;  
           function connect() { 
             alert("connection"); 
           if (window.WebSocket){ 
             message="supported"; 
             console.log("BROWSER SUPPORTED"); 
           } else { 
             console.log("BROWSER NOT SUPPORTED"); 
           }                  
           alert(message); 
           var socket = new SockJS('book'); 
           stompClient = Stomp.over(socket); 
           stompClient.connect({}, function(frame) { 
           alert("in client"); 
           setConnected(true); 
           console.log('Connected: ' + frame); 
           stompClient.subscribe('/topic/showOffer',   
             function(bookResult){ 
             alert("subscribing"); 
            showResult(JSON.parse(bookResult.body).result);}); 
          }); 
        } 

```

连接方法创建了一个 SockJS 对象，并使用`Stomp.over()`为 STOMP 协议添加支持。连接添加了`subscribe()`来订阅`'topic/showOffer'`处理器的消息。我们在 WebSocketConfig_custom 类中添加了`'/topic'`作为 SimpleBroker。我们正在处理、发送和接收 JSON 对象。由 Result JSON 对象接收的优惠将以`result: value_of_offer`的形式出现。

1.  添加断开连接的方法如下：

```java
        function disconnect() { 
            stompClient.disconnect(); 
            setConnected(false); 
            console.log("Disconnected"); 
        } 

```

1.  添加 sendBook 以发送获取优惠的请求如下：

```java
        function sendBook()  
        { 
          var bookName =  
          document.getElementById('bookName').value; 
          stompClient.send("/bookApp/book", {},   
            JSON.stringify({ 'bookName': bookName })); 
        } 

```

`send()`向处理程序`/bookApp/book`发送请求，该处理程序将接受具有`bookName`数据成员的 JSON 对象。我们注册了目的地前缀为'`bookApp`'，我们在发送请求时使用它。

1.  添加显示优惠的方法如下：

```java
        function showResult(message) { 
           //similar to country.jsp 
        } 

```

1.  现在让我们在控制器中为'`/book`'添加处理程序方法。此方法将以下面所示的方式注解为`@SendTo("/topic/showOffer'`：

```java
        @MessageMapping("/book") 
          @SendTo("/topic/showOffer") 
          public Result showOffer(MyBook myBook) throws Exception { 
            Result result = new Result(); 
            result.getOffer(myBook.getBookName()); 
            return result; 
        } 

```

1.  部署应用程序。然后点击链接获取优惠页面。

1.  点击“连接”以获取服务器连接。选择书籍以了解优惠并点击发送。与书籍相关的优惠将显示出来。

以下图表解释了应用程序流程：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/lrn-spr5/img/image_10_003.png)

在控制台上，日志将以下面的形式显示，展示了 STOMP 的不同帧：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/lrn-spr5/img/image_10_004.png)

## 摘要

* * *

在本章中，我们深入讨论了使用 WebSocket 进行消息传递。我们概述了 WebSocket 的重要性以及它与传统网络应用程序以及基于 XMLHttpRequest 的 AJAX 应用程序的区别。我们讨论了 WebSocket 可以发挥重要作用的领域。Spring 提供了与 WebSocket 一起工作的 API。我们看到了 WebSocketHandler、WebSocketConfigurer 以及它们的使用，既使用了 Java 类，也使用了基于 XML 的配置，这些都使用国家首都应用程序来完成。SockJS 库提供了跨浏览器、JavaScript API，以实现浏览器和服务器之间低延迟、跨域通信。我们在 XML 和 Java 配置中都启用了 SockJS。我们还深入了解了 STOMP，它是用于 SockJS 上的 WebSocket 以及如何启用它及其事件处理方法。

在下一章节中，我们将探索反应式网络编程。

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/lrn-spr5/img/image_01_038.png)

如果您对这本电子书有任何反馈，或者我们在*未覆盖*的方面遇到了困难，请在调查[链接](https://goo.gl/y7BQfO)处告诉我们。

如果您有任何疑虑，您还可以通过以下方式与我们联系：

customercare@packtpub.com

我们会在准备好时发送给您下一章节........!

希望您喜欢我们呈现的内容。
