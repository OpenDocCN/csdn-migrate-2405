# Spring5 软件架构（二）

> 原文：[`zh.annas-archive.org/md5/45D5A800E85F86FC16332EEEF23286B1`](https://zh.annas-archive.org/md5/45D5A800E85F86FC16332EEEF23286B1)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：模型-视图-控制器架构

在本章中，我们将深入研究当今框架中使用的最常见的架构模式之一。

**模型-视图-控制器**（**MVC**）架构模式是由 Trygve Reenskaug 于 1979 年制定的。这是对图形用户界面进行组织化工作的最早尝试之一。尽管从那时起已经过去了许多年，但这种模式在最现代的 UI 框架中仍然非常受欢迎。这是因为它旨在构建几乎任何类型的应用程序，包括最常见的应用程序类型，如移动应用程序、桌面应用程序和 Web 应用程序。

这种模式的流行主要归结于易于理解。MVC 提供了一种将应用程序分成三个不同组件的绝佳方法，我们将在本章中进行审查。

在本章中，我们将涵盖以下主题：

+   MVC 的元素：

+   模型

+   查看

+   控制器

+   使用 MVC 架构的好处

+   常见陷阱

+   使用 MVC 实现应用程序：

+   Spring MVC

+   测试

+   UI 框架：Thymeleaf

+   保护 MVC 应用程序：

+   基本身份验证

+   HTTP 和 HTTPS

# MVC

支持 MVC 模式的想法是作为 Trygve Reenskaug 研究的一部分而发展的，他得出了以下关键思想：

“MVC 被构想为解决用户控制大型和复杂数据集的问题的一般解决方案。最困难的部分是找到不同架构组件的良好名称。模型-视图-编辑器是第一套。”

- [`heim.ifi.uio.no/~trygver/themes/mvc/mvc-index.html`](http://heim.ifi.uio.no/~trygver/themes/mvc/mvc-index.html)

计算机科学中最大的问题之一与命名有关，这就是为什么最初的名称是模型-视图-编辑器。后来演变成了 MVC，如前面的链接中所述：

“经过长时间的讨论，特别是与 Adele Goldberg 的讨论，我们最终确定了模型-视图-控制器这些术语。”

MVC 是一种软件架构模式，可以在应用程序的领域对象（业务逻辑所在的地方）和用于构建 UI 的元素之间建立明确的分离。

牢记这个概念，这些部分之间的隔离和关注点的分离非常重要。它们也构成了使用这种模式构建应用程序的基本原则。在接下来的章节中，让我们来看看应用程序的业务逻辑和表示层如何适应 MVC 模式。

# 模型（M）

在这种情况下，**模型**代表了表达支持应用程序固有要求的业务逻辑所需的领域对象。在这里，所有用例都被表示为现实世界的抽象，并且一个明确定义的 API 可供任何一种交付机制（如 Web）使用。

关于传统应用程序，与数据库或中间件交互的所有逻辑都是在模型中实现的。然而，模型（MVC 中的 M）应该暴露易于理解的功能（从业务角度）。我们还应该避免构建贫血模型，这些模型只允许与数据库交互，并且对于项目其他成员来说很难理解。

一旦应用程序的这一部分被编码，我们应该能够创建任何允许用户与模型交互的 UI。此外，由于 UI 可能彼此不同（移动应用程序、Web 和桌面应用程序），模型应该对所有这些都是不可知的。

在理想的世界中，一个独立的团队将能够构建应用程序的这一部分，但在现实生活中，这种假设完全是错误的。需要与负责构建 GUI 的团队进行交互，以创建一个能够满足所有业务需求并公开全面 API 的有效模型。

# 视图（V）

**视图**是模型（MVC 中的 M）的视觉表示，但有一些细微的差异。作为这些差异的一部分，视图倾向于删除、添加和/或转换特定的模型属性，目的是使模型对与视图交互的用户可理解。

由于模型有时很复杂，可以使用多个视图来表示其一部分，反之亦然，模型的许多部分可以作为视图的一部分。

# 控制器（C）

**控制器**是应用程序的最终用户和模型实现的业务逻辑之间的链接。控制器是负责接受用户输入并确定应调用模型的哪个部分以实现定义的业务目标的对象。作为这种交互的结果，模型经常会发生变化，并且应该使用控制器将这些变化传播到视图中。

视图和模型之间绝对不能直接通信，因为这构成了对这种模式工作方式的违反。

牢记前面的提示，所有通信应按照 MVC 模式的特定顺序进行，从视图传递信息到控制器，从控制器传递信息到模型，而不是直接从模型到视图，如下面的交互图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/0396a5e1-c22c-4a1b-8c43-23e0f91f3043.png)

MVC 交互图

为了传播这些变化，视图元素与控制器中的表示绑定在一起，这样就可以根据需要对其进行操作。当模型更新时，更新视图的过程会发生，并且通常涉及重新加载数据或在视图中隐藏/显示某些元素。

当需要将更改传播到视图中的多个元素时，各种控制器可以协同工作以实现目标。在这些情况下，观察者设计模式的简单实现通常可以有助于避免纠缠的代码。

以下图表是这种模式中的部分如何排列的图形表示，无论是在演示层还是业务逻辑层：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/b43675b9-a457-4b7c-a7ea-498fd0ead679.png)

MVC 图形表示

# 使用 MVC 的好处

MVC 为使用它实现的应用程序提供了许多好处；主要好处是关注点的清晰分离，每个应用程序部分都有单一的责任，从而避免混乱的代码并使代码易于理解。

虽然控制器和视图在使用 MVC 构建应用程序的可视表示时是相互关联的，但模型是绝对隔离的。这使得可以重用相同的模型来创建不同类型的应用程序，包括但不限于以下内容：

+   移动

+   网络

+   桌面

你可能会认为使用这种模型开发的项目可以依靠在开发阶段同时但分别工作的团队，这在某些情况下是正确的，但并不是普遍规则。如前所述，跨团队的有效沟通仍然对整体构建应用程序是必要的。

# 常见陷阱

当我们使用 MVC 开发应用程序时，通常会发现项目按照 MVC 首字母缩写结构化，如下图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/dad7ede6-b98c-4094-b684-939f57a30d17.png)

MVC 项目结构

此目录结构表示以下内容：

+   项目名称是**abc-web**

+   这是一个 Web 应用程序

+   该应用程序使用 MVC 架构（结构）

不幸的是，这些观点都没有为负责创建或维护应用程序的团队提供有意义的信息。这是因为一个项目的团队并不关心文件组织。相反，根据业务规则、用例或与业务本身相关的其他因素来组织代码要更有用得多，而不是技术方面。

考虑到这个想法，我们建议一个更有用的目录结构如下：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/98cc2f43-58d8-4774-ba84-3624b3095bf4.png)

可理解的项目结构

从这个图表中，我们可以推断出以下几点：

+   这是一个**会计**系统。

+   项目的主要特点与以下内容相关：

+   Income

+   Expenses

+   报告

使用前面图表中显示的项目布局，如果我们被要求修复一个不再工作的报告，我们可以考虑审查报告文件夹。这种方法有助于减少完成项目任务所需的时间和精力。

我们可以得出结论，第二个项目结构提供的信息比第一个更有用和实用，因为第一个根本没有提供有关业务的信息。

项目的每个部分都应该传达有关业务的信息，而不是关于使用的交付机制或模式。

这些细节很小，但很重要。在本书的开头，我们提到一个良好的架构是围绕业务需求构建的，架构追求的任何目标都应该被整个团队理解。我们应该以实现这个目标为目标来处理每一个细节。记住：细节很重要。

# 使用 MVC 实现应用程序

现在你已经了解了 MVC 架构背后的理论，是时候将你学到的概念付诸实践，看看 Spring 框架如何实现它们。我们将从回顾 Spring MVC 开始，这是一个允许我们实现这种架构风格的项目。

# Spring MVC

Spring 通过 Spring MVC 提供对 MVC 架构模式的支持。这个 Spring 项目允许整合大量的 UI 框架，以构建表单和相关组件，使用户能够与应用程序进行交互。

Spring MVC 是建立在 servlet API 之上的，它旨在创建 Web 应用程序。没有办法使用它来创建桌面或任何其他类型的应用程序。尽管 MVC 架构模式可以应用于所有这些应用程序，但 Spring MVC 只专注于 Web。

Spring MVC 正式称为 Spring Web MVC。

尽管 Spring MVC 支持大量的视图技术，但最常用的技术往往是 Thymeleaf，因为它的集成非常顺畅。但是，你也可以使用其他框架，比如以下的：

+   JSF

+   FreeMarker

+   Struts

+   GWT

Spring MVC 是围绕前端控制器模式设计的，它依赖于一个对象来处理所有传入的请求并提供相应的响应。在 Spring MVC 的情况下，这个对象由`Servlet`实现，由`org.springframework.web.servlet.DispatcherServlet`类表示。

这个`Servlet`负责将请求委托给控制器，并在屏幕上呈现相应的页面，带有所需的数据。以下图表显示了`DispatcherServlet`如何处理请求：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/b206a811-4848-457e-9e13-199f9655a0ec.png)

DispatcherServlet 请求处理

在前面的图表中，我们可以看到`Controller`是一个 Java 类，`View`是一个 HTML 文件。在后一种情况下，我们还可以使用任何`tag-library/template-engine`标签，它将被编译为在 Web 浏览器中呈现的 HTML 代码。

在 Spring 中，使用`@Controller`注解在类名上创建一个控制器，如下面的代码片段所示：

```java
import org.springframework.stereotype.Controller;

@Controller
public class DemoController 
{
  ...
}
```

现在，这个类被标记为一个控制器，我们需要指示将处理什么请求映射，并作为请求处理的一部分需要执行什么操作。为了支持这个功能，我们需要使用`@RequestMapping`注解编写一个简单的方法，如下面的代码所示：

```java
@RequestMapping(value = "/ABC", method = RequestMethod.GET)
public String handleRequestForPathABC() {
    // do something
    return "ui-template";
}
```

正如您所看到的，前面的方法处理来自`/ABC`路径的传入请求，一旦处理完成，将提供一个`ui-template`，以在浏览器上呈现。

这个操作是由 Spring MVC 使用视图解析器完成的，它将查找渲染名为`ui-template.html`的文件。如果需要，您还可以编写自定义解析器来为视图添加后缀或前缀。

当我们需要从控制器传递数据到视图时，我们可以使用`Model`对象，由 Spring 视图解析器启用。这个对象可以填充任何您想在视图中使用的数据。同样，当用户从视图提交数据时，这个对象将填充输入的信息，控制器可以使用它来执行任何所需的逻辑。

为了从控制器发送数据到视图，我们需要在处理请求的方法中将`Model`对象作为参数包含，如下所示：

```java
@RequestMapping(value = "/ABC", method = RequestMethod.GET)
public String passDataToTheView(Model Model) {
    Model.addAttribute("attributeName", "attributeValue");
    // do something
    return "ui-template";
}
```

所有模板都可以使用`${...}`语法（称为表达式语言）读取从控制器传递的属性：

```java
<!DOCTYPE html>
<html lang="en">
    <head>
        <title>Title</title>
    </head>
```

```java
    <body>
        ${attributeName} 
    </body>
</html>
```

或者，如果您想要将数据从视图组件传递到控制器，您必须在视图中填充一个对象（例如使用表单），如下所示：

```java
<!DOCTYPE html>
<html lang="en">
    <head>
        <title>Title</title>
    </head>
    <body>
        <form action="#" th:action="@{/process}"   
        th:object="${myObject}">
            <label for="name">Name:</label>
            <input type="text" id="name" th:field="*{name}"/>
            <button type="submit">OK</button>
         </form>
    </body>
</html>
```

一旦对象字段被填充并且提交按钮被按下，请求将被发送，以便我们可以声明一个方法来处理请求：

```java
@RequestMapping(value = "/process", method = POST)
public String processForm(@ModelAttribute MyObject myObject) {
    String name = myObject.getName();
    // do something
    return "ui-template";
}
```

在这种情况下，您可能已经注意到我们使用`@ModelAttribute`来捕获请求中发送的数据。

# 测试

测试对我们的应用程序至关重要。当我们使用 Spring MVC 时，我们可以依赖`spring-test`模块来添加对上下文感知的单元测试和集成测试的支持，这意味着我们可以依赖注解来连接依赖项。我们还可以使用`@Autowired`注解来测试特定组件。

以下是一个示例，演示了编写一个上下文感知的测试有多简单：

```java
@RunWith(SpringRunner.class)
@SpringBootTest
public class ContextAwareTest {

    @Autowired
    ClassUnderTest classUnderTest;

    @Test
    public void validateAutowireWorks() throws Exception {
        Assert.assertNotNull(classUnderTest);
    }
}
```

让我们回顾一下粗体字的代码，以了解它是如何工作的：

+   前两个注解为我们完成了所有的工作；它们将允许我们在 Servlet 容器内运行我们的测试，并且用于测试的 Spring Boot 注解将以与在生产中运行的代码相同的方式连接所有类。

+   由于我们添加了前面提到的注解，现在我们可以使用`@Autowired`注解来连接我们想要测试的组件。

+   代码验证了被测试的类已成功实例化，并且准备好被使用。这也意味着类中的所有依赖项都已成功连接。

这是一个测试代码的简单方法，该代码必须与数据库、消息代理服务器或任何其他中间件进行交互。用于验证与数据库服务器交互的方法使用内存数据库，例如 H2，用于传统 SQL 数据库（如 PostgreSQL 或 MySQL）；还有用于 NoSQL 数据库的选项，例如嵌入式 Cassandra 或 Mongo。

另一方面，当您需要测试与其他第三方软件的集成时，一个很好的方法是使用沙盒。沙盒是一个类似于生产环境的环境，供软件供应商用于测试目的。这些沙盒通常部署在生产环境中，但它们也有一些限制。例如，与支付相关的操作不会在最后阶段处理。

当您没有任何方法在自己的环境中部署应用程序时，这种测试方法是有用的，但当然，您需要测试集成是否与您的应用程序正常工作。

假设您正在构建一个与 Facebook 集成的应用程序。在这种情况下，显然不需要进行任何更改，以便在自己的测试环境中部署 Facebook 实例。这是沙盒环境适用的完美例子。

请记住，沙盒测试集成使用第三方软件。如果您是软件供应商，您需要考虑提供允许客户以测试模式尝试您的产品的沙盒。

Spring MVC 测试还具有流畅 API，可以编写高度表达性的测试。该框架提供了一个`MockMvc`对象，可用于模拟最终用户请求，然后验证提供的响应。常见用例包括以下内容：

+   验证 HTTP 代码状态

+   验证响应中的预期内容

+   URL 重定向

以下代码片段使用`MockMvc`对象来测试先前描述的示例：

```java
@RunWith(SpringRunner.class)
@SpringBootTest
@AutoConfigureMockMvc
public class RedirectionTest 
{
  @Autowired
 private MockMvc mockMvc;
  @Test
  public void contentAndRedirectionTest() throws Exception 
  {
 this.mockMvc.perform(get("/urlPage"))
 .andExpect(redirectedUrl("/expectedUrlPage") .andDo(print()).andExpect(status().isOk())
    .andExpect(
      content().string(containsString("SomeText")))
    );
  }
}
```

让我们快速审查粗体字中的代码，以了解其工作原理：

+   `AutoConfigureMockMvc`注解生成了在测试中使用`MockMvc`对象所需的所有基础代码。

+   `MockMvc`对象已自动装配并准备就绪。

+   `MockMvc`提供的流畅 API 用于验证响应的预期状态代码。我们还在测试简单的重定向，以及重定向完成后页面上预期的内容。

# 测试覆盖率

当我们讨论测试时，经常会听到术语**测试覆盖率**。这是一个用于检查测试套件执行了多少代码的度量标准，有助于确定未经测试的代码的替代路径，并因此容易出现错误。

假设您正在编写一个具有`if`语句的方法。在这种情况下，您的代码有两条可选路径要遵循；因此，如果您想实现 100%的覆盖率，您需要编写测试来验证代码可以遵循的所有可选路径。

有许多有用的库可用于测量代码的覆盖率。在本章中，我们将介绍 Java 世界中最流行的库之一；该库称为 JaCoCo（[`www.eclemma.org/jacoco/`](http://www.eclemma.org/jacoco/)）。

为了使 JaCoCo 成为我们应用程序的一部分，我们需要将其作为插件包含在内，使用我们首选的构建工具。

以下是使用 Gradle 包含 JaCoCo 所需的配置：

```java
apply plugin: "jacoco"
jacoco 
{
  toolVersion = "VERSION"
} 
```

以下是使用 Maven 包含 JaCoCo 所需的配置：

```java
<plugin>
  <groupId>org.jacoco</groupId>
  <artifactId>jacoco-maven-plugin</artifactId>
  <version>VERSION</version>
</plugin>
```

一旦 JaCoCo 作为项目的一部分被包含进来，我们将有新的任务可用于测量我们的代码覆盖率。通过执行以下 Gradle 任务来生成覆盖率报告：

```java
$ ./gradlew test jacocoTestReport
```

生成的覆盖率报告将以 HTML 格式提供，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/f775fbe3-e0a6-4894-82eb-af5a787e702f.png)

JaCoCo 报告

尽管我们确实希望为我们的代码实现高覆盖率，但我们需要小心编写什么类型的测试，因为考虑到这种方法，我们可能会被诱使编写无用的测试，只是为了实现 100%的覆盖率。

为了充分理解我在这里谈论的内容，让我们审查 JaCoCo 为域包中的一个类生成的报告：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/9caf22ac-ecd6-4807-84a1-0bf87ae0062d.png)

域类的测试覆盖率报告

报告显示，某些方法根本没有测试。其中一些方法对于任何 Java 对象都是标准的，其他方法只是 getter 和 setter（访问器），不需要进行测试。编写 getter 和 setter 通常会导致构建贫血的领域模型，并且大多数情况下，这仅用于使代码与依赖于 Java Beans 约定的框架兼容。因此，没有必要编写测试来覆盖 getter 和 setter。

我看到有人仅为这些方法编写测试，以实现 100%的覆盖率，但这是一个无用且不切实际的过程，应该避免，因为它对代码或编写的测试质量没有任何价值。

现在，让我们来审查一下具有一些值得测试逻辑的类的报告：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/beb5e7a9-44a0-4193-90c2-eb28d15de1ba.png)

服务类的 JaCoCo 覆盖率报告

令人惊讶的是，这个类有 100%的覆盖率。让我们回顾一下这个类的相关测试，如下所示：

```java
@RunWith(MockitoJUnitRunner.class)
public class BankingUserDetailServiceTest 
{
  @Mock
  CustomerRepository customerRepository;
  @InjectMocks
  BankingUsersDetailService bankingUsersDetailService;
 @Test(expected = UsernameNotFoundException.class)
  public void whenTheUserIsNotFoundAnExceptionIsExpected() 
  throws Exception 
  {
    String username = "foo";
    Mockito.when(customerRepository.findByUsername(username))
    .thenReturn(Optional.empty());
    bankingUsersDetailService.loadUserByUsername(username);
  }
  @Test
  public void theUserDetailsContainsTheInformationFromTheFoundCustomer
  () throws Exception 
  {
    String username = "foo";
    String password = "bar";
    Customer customer = 
    new Customer(username, password, NotificationType.EMAIL);
    Mockito.when(customerRepository.findByUsername(username))
    .thenReturn(Optional.of(customer));
    UserDetails userDetails = bankingUsersDetailService
    .loadUserByUsername(username);
 Assert.assertEquals(userDetails.getUsername(), username);
    Assert.assertEquals(userDetails.getPassword(), password);
    Assert.assertEquals(userDetails.getAuthorities()
 .iterator().next().getAuthority(), "ROLE_CUSTOMER");
  }
}
```

我们并不总是能够达到 100%的覆盖率，就像在这个例子中一样。然而，一个很好的度量标准往往是 80%。您必须将之前提到的百分比视为建议，而不是规则；如果您验证您的测试是否涵盖了所有需要的逻辑，有时低于 80%的值也是可以接受的。

您需要聪明地使用生成的报告来弄清楚需要测试的逻辑，然后着手解决，而不是为结果感到沮丧。

使用这种工具的好处之一是，您可以将其集成为持续集成服务器的一部分，以生成始终可见的报告。通过这种方式，报告可以用于不断检查覆盖率是增加还是下降，并采取行动。我们将在第十一章 *DevOps 和发布管理*中更详细地讨论这个话题。

# UI 框架

当您使用 Spring MVC 时，您可以选择从大量的技术中构建您的网页。根据您选择的框架，您需要添加相应的配置，以便让 Spring 知道您的选择。

正如我们所知，Spring 支持代码配置，因此您需要添加一些注解和/或配置类来使您的框架工作。如果您想避免这些步骤，您可以使用 Thymeleaf；这个框架可以很容易地集成到现有的 Spring 应用程序中，包括 Thymeleaf starter 依赖项。根据所使用的工具，需要使用不同的代码行，如下所示：

+   在使用 Gradle 时，依赖项如下：

```java
compile('org.springframework.boot:spring-boot-starter-thymeleaf')
```

+   在使用 Maven 时，依赖项如下：

```java
<dependency>
  <groupId>org.springframework.boot</groupId>
  <artifactId>spring-boot-starter-thymeleaf</artifactId>
</dependency>
```

应用程序启动后，Spring Boot 将为您完成所有无聊的工作，为您的应用程序准备使用 Thymeleaf。

# Thymeleaf

Thymeleaf 是一个相对较新的模板引擎；第一个版本于 2011 年发布。Thymeleaf 与 HTML 非常相似，不需要任何 servlet 容器即可在浏览器中预览内容。这被利用来允许设计人员在不部署应用程序的情况下工作应用程序的外观和感觉。

让我们回顾一下如何将使用 HTML 和 Bootstrap 构建的 Web 模板转换为 Thymeleaf 模板，以便看到这个模板引擎并不具有侵入性。以下代码代表一个非常基本的 HTML 模板：

```java
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8"/>
    <title>Default title</title>
    <meta name="viewport" content="width=device-width, 
    initial-scale=1"/>
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/
    bootstrap/3.3.7/css/bootstrap.min.css"/>
    <script src="img/jquery.min.js"></script>
    <script src="img/bootstrap.min.js"></script>
  </head>
  <body>
    <nav class="navbar navbar-inverse">
      <div class="container-fluid">
        <div class="navbar-header">
          <a class="navbar-brand" href="#">MVC Demo</a>
        </div>
        <ul class="nav navbar-nav">
          <li><a href="/index">Home</a></li>
          <li><a href="/notifications">My notification channels</a> 
          </li>
        </ul>
        <ul class="nav navbar-nav navbar-right">
          <li>
            <a href="/login"><span class="glyphicon glyphicon-user"> 
            </span>  Login</a>
          </li>
          <li>
            <a href="/logout">
              <span class="glyphicon glyphicon-log-in"></span>
                Logout
            </a>
          </li>
        </ul>
      </div>
    </nav>
    <div class="container">
      <div class="row">
        <div class="col-md-3"></div>
        <div class="col-md-6">
          Page content goes here
        </div>
        <div class="col-md-3"></div>
      </div>
    </div>
  </body>
</html>
```

由于这是一个常规的 HTML 文件，您可以在浏览器中打开它，看看它的样子：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/bf74150a-6dcd-4e30-bddf-d45e3775f9d4.png)

HTML 和 Bootstrap 模板

现在，让我们实现一些要求，使我们的模板以更现实的方式工作：

+   仅当用户登录时，注销选项才应出现

+   如果用户未登录，则不应出现“我的通知渠道”选项

+   一旦用户登录，登录选项就不应该出现

+   一旦用户登录，主页选项应该显示一个欢迎消息，使用他们的用户名

在创建 Web 应用程序时，这些要求是微不足道的，幸运的是，它们也很容易使用 Thymeleaf 实现。

为了在用户登录后显示/隐藏网页中的某些元素，我们需要包含一个额外的库来处理这些内容。

要使用 Gradle 包含库，请使用以下命令：

```java
compile('org.thymeleaf.extras:thymeleaf-extras-springsecurity4')
```

要使用 Maven 包含库，请使用以下命令：

```java
<dependency>
    <groupId>org.thymeleaf.extras</groupId>
    <artifactId>thymeleaf-extras-springsecurity4</artifactId>
</dependency>
```

现在，我们需要在 HTML 文件中添加一个标签声明，以便使用 Thymeleaf 和新增加的新扩展：

```java
<html lang="en"

      >
```

一旦我们包含了这些标签，我们将能够使用提供的内置功能。当您需要根据用户是否已登录来隐藏/显示某个元素时，您可以使用`isAuthenticated()`条件，如下所示：

```java
<ul class="nav navbar-nav navbar-right">
    <li sec:authorize="!isAuthenticated()">
        <a href="/login"><span class="glyphicon glyphicon-user"></span>  Login</a>
    </li>
    <li sec:authorize="isAuthenticated()">
        <a href="/logout">
            <span class="glyphicon glyphicon-log-in"></span>
              Logout
        </a>
    </li>
</ul>
```

根据分配的用户角色限制访问也是相当常见的。使用添加的扩展来实现这些检查也很容易，如下面的代码所示：

```java
<li sec:authorize="hasRole('ROLE_ADMIN')"><a href="/a">Admins only</a></li>
<li sec:authorize="hasRole('ROLE_EDITOR')"><a href="/b">Editors only</a></li>
```

最后，如果您需要在 Web 页面上显示用户名，您可以在 HTML 文件中使用以下标签：

```java
<p>Hello, <span sec:authentication="name"></span>!</p>
```

另外，一旦模板由我们的设计师或前端专家创建完成，我们将希望在整个应用程序中使用它，以保持一致的外观和感觉。为了实现这个目标，我们需要定义模板中哪些部分将使用`layout`标签来替换特定内容：

```java
<div class="col-md-6" layout:fragment="content">
    Page content goes here
</div>
```

然后页面将需要定义模板名称和应该显示在定义片段中的内容，如下所示：

```java
<!DOCTYPE html>
<html lang="en"

 layout:decorator="default-layout">
<head>
    <title>Home</title>
</head>
<body>
<div layout:fragment="content">
    // Content here
</div>
</body>
</html>
```

我们之前提到 Thymeleaf 根本不具有侵入性，我们将向您展示为什么。一旦使用 Thymeleaf 标签实现了所有期望的逻辑，您可以再次使用常规浏览器打开模板，而无需将应用程序部署在 Servlet 容器中。您将得到以下结果：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/4575d939-9029-4f25-8eba-bfcbbe75a622.png)

Thymeleaf 和 Bootstrap 模板

我们有重复的菜单选项，我们仍然可以看到登录和注销选项，因为浏览器无法解释 Thymeleaf 标签。然而，好消息是，引入的代码并没有对模板造成任何伤害。这正是为什么您的 Web 设计师可以继续工作并在浏览器中预览的原因。无论您在模板中引入了多少 Thymeleaf 标签，这些标签对现有的 HTML 代码都不具有侵入性。

# 保护 MVC 应用程序

安全是软件开发中的关键方面，如果我们想要避免将我们的应用程序暴露给常见的攻击，我们需要认真对待它。此外，我们可能希望限制非授权人员的访问。我们将在第十三章 *安全*中审查一些保持软件安全的技术。与此同时，您将学习如何使用 Spring Security 保护 MVC 应用程序。

到目前为止，我们已经审查了如何使用 Thymeleaf 和 Spring MVC 构建 Web 应用程序。在处理 Web 应用程序时，最常见的身份验证机制之一是基本身份验证。让我们更详细地讨论一下这个问题。

# 基本身份验证

基本身份验证，或基本访问验证，是用于限制或提供对服务器中特定资源的访问的机制。在 Web 应用程序中，这些资源通常是网页，但这种机制也可以用于保护 RESTful Web 服务。然而，这种方法并不常见；基于令牌的不同机制更受青睐。

当网站使用基本身份验证进行保护时，用户需要在请求网站页面之前提供他们的凭据。用户凭据仅仅是用户名和密码的简单组合，使用 Base64 算法进行编码，计算出应该在**身份验证**标头中的值。服务器稍后将使用这个值来验证用户是否经过身份验证并获得访问所请求资源的授权。如果用户经过身份验证，这意味着提供的用户名和密码组合是有效的；被授权意味着经过身份验证的用户有权限执行特定操作或查看单个页面。

使用这种身份验证机制的一个问题是，当用户在身份验证过程中将凭据发送到服务器时，凭据是以明文形式发送的。如果请求被拦截，凭据就会暴露出来。以下截图清楚地显示了这个问题；在这种情况下，使用了一个名为 Wireshark 的工具来拦截请求（[`www.wireshark.org`](https://www.wireshark.org)）：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/36c8691f-7520-44ff-926d-543720bf1767.png)

拦截的 HTTP 请求

可以通过使用安全版本的 HTTP 来轻松解决此问题，其中需要证书来加密服务器和浏览器之间交换的数据。证书应由受信任的**证书颁发机构**（**CA**）颁发，并应位于服务器上。浏览器有一个受信任的 CA 根证书列表，在建立安全连接时进行验证。一旦证书验证通过，地址栏将显示一个挂锁，如下图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/cff6d101-4299-4113-980a-1bdf54daa13d.png)

地址栏中显示的挂锁

如下图所示，HTTPS 协议使用`8443`端口，而不是标准的`80`端口，后者用于 HTTP：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/da4775b6-747a-4489-86b8-7c06a2f29c7e.png)

地址栏使用 HTTPS

出于开发目的，您可以生成自己的证书，但浏览器会显示警告，指示无法验证证书；您可以添加异常以使用 HTTPS 打开请求的页面。

以下图表显示了使用 HTTPS 协议建立连接的过程：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/a15cc8b0-106c-4136-abee-4ac95febbe38.png)

HTTPS 连接

中间的挂锁代表了数据在计算机网络中传输时的加密，使其无法阅读。以下截图显示了使用 Wireshark 拦截数据的样子：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/19bc0593-e13d-4981-85da-13041ff93ff1.png)

拦截的 HTTPS 请求

正如您所看到的，这些拦截的数据很难理解。通过这种方式，发送的所有信息都受到保护，即使在传输过程中被捕获，也不能轻易阅读。这种攻击被称为中间人攻击，是最常见的攻击类型之一。

# 实施基本身份验证

现在您已经了解了与基本身份验证相关的基础知识以及其工作原理，让我们来看看如何在 Spring MVC 应用程序中实现它。

首先，我们需要包含 Spring Security 的起始依赖项。

可以在 Gradle 中包含如下：

```java
compile('org.springframework.boot:spring-boot-starter-security')
```

可以在 Maven 中包含如下：

```java
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-security</artifactId>
</dependency>
```

添加了这个依赖项后，Spring Boot 将为我们完成所有繁琐的工作，我们不需要做任何事情来保护应用程序。如果我们不添加任何额外的配置，Spring 将为测试生成一个用户，并且密码将打印在控制台上。这种情况在开发的早期阶段非常完美。

另一方面，如果我们需要自定义的方式来允许或限制用户访问，我们只需要实现`loadUserByUsername`方法，该方法是`UserDetailsService`接口的一部分。

实现相当简单；该方法检索提供的`username`，并且使用该用户名，您需要返回一个带有用户信息的`UserDetails`对象。

让我们来看一个例子，如下所示：

```java
@Service
public class MyCustomUsersDetailService implements UserDetailsService {

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<Customer> customerFound = findByUsername(username);
        if (customerFound.isPresent()) {
            Customer customer = customerFound.get();
            User.UserBuilder builder = User
                    .withUsername(username)
                    .password(customer.getPassword())
                    .roles(ADD_YOUR_ROLES_HERE);
            return builder.build();
        } else {
            throw new UsernameNotFoundException("User not found.");
        }
    }
}
```

`findByUsername`方法负责在数据库或其他存储中查找您需要的用户。一旦您定制了用户的位置，您就必须处理网页的授权。这可以通过实现`WebSecurityConfigurerAdapter`接口来完成，如下面的代码所示：

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity httpSecurity) throws Exception {
         httpSecurity.authorizeRequests()
             .antMatchers("/index").permitAll()
             .antMatchers("/guest/**").permitAll()
 .antMatchers("/customers/**").hasAuthority("ROLE_CUSTOMER")
             .anyRequest().authenticated()
             .and()
             .formLogin()
 .loginPage("/login")
            .failureUrl("/login?error")
            .successForwardUrl("/home")
             .usernameParameter("username").passwordParameter("password")
                .permitAll()
             .and()
 .logout().logoutSuccessUrl("/logout")
             .and()
             .csrf(); 
    }
}
```

让我们来审查加粗显示的代码：

+   我们正在配置一个路径来授予任何用户访问权限，无论请求是否经过身份验证

+   为`CUSTOMER`角色的用户限制访问的配置已添加到`customers`路径下的所有页面

+   配置了登录页面，以及成功和失败的认证尝试的页面转发

+   提供了`/logout` URL，用于在注销过程发生后重定向用户

如您所见，一旦实现了前面的配置类，您将拥有所有必要的内容来保护应用程序中的网页。

我们之前提到，一个好的方法是使用 HTTPS 来加密在浏览器和服务器之间发送的数据。为了实现这个目标，Spring Boot 提供了将以下配置属性添加到`application.properties`文件中的能力：

```java
server.port: 8443
server.ssl.key-store: keystore.p12
server.ssl.key-store-password: spring
server.ssl.keyStoreType: PKCS12
server.ssl.keyAlias: tomcat
```

让我们回顾一下这个文件中的配置：

+   如前所述，HTTPS 使用`8443`端口。

+   下一个参数允许指定数字证书名称。

+   密钥库密码也应提供。请注意，当执行应用程序时，可以将此值作为参数提供。更好的方法是从配置服务器获取这些值，而不是将它们硬编码在`application.properties`文件中。

+   此参数用于指定生成证书时使用的存储类型。

+   最后一个参数对应于数字证书的别名。

请注意，代码不应该被修改以在应用程序中启用 HTTPS。

为了测试的目的，可以使用标准 Java 安装的一部分的密钥工具来创建自签名证书，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/6c5311c1-ec7b-4fee-bf15-ef64ef56e6a0.png)

自签名证书创建

# 摘要

在本章中，我们探讨了与 MVC 架构及其工作相关的概念。我们还讨论了人们在使用这种架构风格构建应用程序时容易犯的错误。

然后，我们回顾了如何使用 Spring MVC 创建应用程序，查看了不同的测试以及如何使用 Spring 提供的功能来实现它们。我们还回顾了如何在 Spring MVC 中使用 Thymeleaf 来构建 Web 应用程序的用户界面。为了完成本章，我们讨论了一些安全概念，包括如何在 Spring MVC 应用程序中应用它们。

在下一章中，您将了解事件驱动架构，这种架构变得非常流行。


# 第六章：事件驱动架构

**事件驱动架构**（**EDA**）基于每次应用程序更改状态时创建的命令和事件。根据 Martin Fowler 的说法，有四种模式用于使用这种方法构建软件系统。

在本章中，我们将学习这四种模式，并看看如何将消息传递联系在一起，以充分利用基于消息的编程模型。即使这不是一个要求，消息传递也可以用来为使用基于事件驱动的架构风格构建的应用程序增加更多功能。

在本章中，我们将讨论以下主题：

+   事件驱动架构的基本概念和关键方面：

+   命令

+   事件

+   在事件驱动架构中使用的常见模式：

+   事件通知

+   事件携带状态传输

+   事件溯源

+   CQRS

# 基本概念和关键方面

在深入了解事件驱动架构的细节之前，我们将首先学习一些围绕它们的关键方面。

使用这种方法创建的应用程序是根据两个不同但相关的概念开发的：

+   命令

+   事件

让我们简要定义一下这些概念。

# 命令

命令是在应用程序中执行的操作，作为成功或失败执行的结果会发出一个或多个事件。我们可以将这些操作看作是旨在修改系统状态的操作。

命令被称为操作。如果我们考虑到它们的预期用途，这是非常合理的。以下列表显示了一些此类命令的示例：

+   转账

+   更新用户信息

+   创建一个账户

强烈建议您使用现在时态的动词来命名命令，就像这些例子所示。

# 事件

事件是应用程序中命令执行的结果。这些事件用作订阅者接收通知的机制。事件是不可变的，不应该被修改，因为它们被设计为保留应用程序状态如何随时间变化的日志信息。

在命名事件时，经验法则是使用过去时态，例如以下内容：

+   资金转移

+   用户信息已更新

+   账户已创建

事件不关心它们创建后将执行什么操作。这使得可以解耦系统但仍通知订阅者。这样，我们可以解耦应用程序，因为订阅者负责根据需要执行一个或多个操作，一旦他们被通知事件的创建。

在这一点上，我们可以得出结论，我们可以解耦应用程序，因为订阅者负责根据需要执行一个或多个操作，一旦他们被通知事件的创建。我们还可以推断，事件是通过将责任委托给其他系统来逆转依赖关系的绝佳方式。

以下图表显示了命令如何发出事件以及这些事件的订阅者如何被通知：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/8ddc799d-645a-4f18-b6ba-1a55ee131efb.png)

事件的创建和传播

现在我们对事件有了更好的理解，让我们回顾一下本章开头提到的四种模式，以便使用基于事件驱动的架构风格创建应用程序。

# 事件驱动架构的模式

当人们谈论事件驱动架构时，他们经常提到以下模式之一：

+   事件通知

+   事件携带状态传输

+   事件溯源

+   CQRS

有时，在同一系统中会同时使用多个模式，具体取决于业务需求。让我们回顾每种模式，以便确定可以使用它们的场景。

# 事件通知

事件通知模式通过在执行命令后向订阅者发出事件来工作。这可以与观察者模式进行比较，观察者模式中，您观察到一个具有许多监听器或订阅者列表的主题，在观察对象的状态发生变化时会自动通知它们。

这种行为被事件总线库广泛使用，允许应用程序中的组件之间进行发布-订阅通信。这些库的最常见用例是针对 UI，但它们也适用于后端系统的其他部分。下图演示了事件如何发送到总线，然后传播到之前注册的所有订阅者：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/a065abde-ec41-4828-ab21-9c8f33600082.png)

事件总线

使用此事件通知机制有两个主要好处：

+   解耦的系统和功能

+   倒置的依赖关系

为了更好地理解这些好处，让我们想象一下我们的银行应用程序需要处理以下需求：

*银行希望为使用移动应用的客户提供转账的机会。这将包括在我们银行拥有的账户之间转账，或者转账到外部银行。一旦执行此交易，我们需要使用客户首选的通知渠道通知客户有关交易状态。*

*银行还有一个应用程序，由呼叫中心工作人员使用，通知我们的代理客户的余额。当客户的账户余额高于预定金额时，呼叫中心系统将提醒代理，然后代理将致电客户，让他们意识到可以将他们的钱投资到银行。最后，如果交易涉及外部银行，我们也需要通知他们交易状态。*

使用经典方法编写应用程序，我们可以正确构建一个系统，在转账发生后，所有在转账应用程序边界内列出的后置条件都得到执行，如下图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/c789f88c-e8ac-4e36-8e46-10290e86a8c9.png)

耦合的转账应用程序

正如我们从上图中看到的，转账应用程序需要知道一旦交易发生，必须满足的所有后置条件；使用这种方法，我们最终将编写所有必要的代码与其他系统进行交互，这将导致应用程序与其他系统耦合。

另一方面，使用事件通知模式，我们可以解耦转账应用程序，如下图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/dc5708c0-6293-4467-bfa9-dc7c7be9cf3d.png)

解耦的转账应用程序

在上图中，我们可以看到一旦执行`<Transfer money>`命令，就会发出`<Money transferred>`事件，并通知所有订阅的系统。通过这样做，我们可以摆脱系统之间的耦合。

这里需要注意的重要一点是，转账应用程序甚至不需要知道其他软件系统的存在，并且所有后置条件都在该应用程序的边界之外得到满足。换句话说，解耦的系统导致我们倒置依赖关系。

解耦的系统和倒置的依赖关系听起来很棒，但这种方法的隐含缺点是您会失去可见性。这是因为发出事件的应用程序对于发布事件后执行的进程一无所知，也没有用于读取其他系统的代码。

通常无法识别下游依赖关系，并且通常使用一些技术来在不同日志之间关联事件，以减轻这一噩梦。

耦合的系统提供有关下游依赖的所有信息，并且难以演变。相反，解耦的系统对下游依赖一无所知，但它们提供了独立演变系统的机会。

现在我们已经了解了支持事件通知模式的基本概念，我们可以说，实现这种应用程序最显而易见的技术是使用 RabbitMQ、AWS SQS/SNS、MSMQ 等消息系统。这些都是 Spring Cloud Stream 项目下的 Spring 支持的。在我们的案例中，我们将使用 RabbitMQ，可以通过添加以下依赖来支持：

```java
<dependency>
   <groupId>org.springframework.cloud</groupId> 
   <artifactId>spring-cloud-stream-binder-rabbit</artifactId> </dependency>
```

为了使 RabbitMQ 的设置过程可访问，本章提供的代码包括一个 Docker Compose 文件，应使用`docker-compose up`命令执行。我们将在第十章中看到 Docker Compose 是什么以及它是如何工作的，*容器化您的应用程序*。

Spring Cloud Stream 建立在 Spring Integration 之上，提供了轻松生产和消费消息的机会，以及使用 Spring Integration 的所有内置功能的机会。我们将使用这个项目来实现前面提到的银行应用程序的示例，因此我们需要添加以下依赖项：

```java
<dependency> 
    <groupId>org.springframework.cloud</groupId> 
    <artifactId>spring-cloud-stream</artifactId> 
</dependency>
```

转账应用程序将公开一个端点，允许转账。一旦完成这笔交易，就需要向其他应用程序发送事件通知。Spring Cloud Stream 使得可以使用`@Output`注解定义消息通道，如下所示：

```java
public interface EventNotificationChannel 
{
 @Output  MessageChannel moneyTransferredChannel();
}
```

这个接口可以被注释并在任何地方使用。让我们看看如何在控制器中使用它，以公开转账功能：

```java
@RestController
public class TransferController 
{
  private final MessageChannel moneyTransferredChannel;
  public TransferController(EventNotificationChannel channel) 
  {
    this.moneyTransferredChannel = channel.moneyTransferredChannel();
  }
  @PostMapping("/transfer")
  public void doTransfer(@RequestBody TransferMoneyDetails
  transferMoneyDetails) 
  {
    log.info("Transferring money with details: " +
    transferMoneyDetails);
    Message<String> moneyTransferredEvent = MessageBuilder
 .withPayload
    ("Money transferred for client with id: " + transferMoneyDetails.getCustomerId()).build();
    this.moneyTransferredChannel.send(moneyTransferredEvent);
  }
}
```

当我们使用事件通知模式时要记住的一件事是，发出事件的应用程序只提供关于执行的命令的非常基本的信息。在这种情况下，<转账完成>事件包含应该稍后用于查询更多信息并确定是否需要执行其他操作的客户端 ID。这个过程总是涉及与其他系统、数据库等的一个或多个额外交互。

订阅者也可以利用 Spring Cloud Stream。在这种情况下，应该使用`@Input`注解如下：

```java
public interface EventNotificationChannel 
{
  @Input
  SubscribableChannel subscriptionOnMoneyTransferredChannel();
}
```

使用 Spring Integration，可以执行完整的集成流程来处理传入的消息：

```java
@Bean
IntegrationFlow integrationFlow(
            EventNotificationChannel eventNotificationChannel) {
    return IntegrationFlows.from
        (eventNotificationChannel
            .subscriptionOnMoneyTransferredChannel()).
                handle(String.class, new GenericHandler<String>() {
            @Override
            public Object handle(String payload, 
            Map<String, Object> headers) {

 // Use the payload to find the transaction and determine
            // if a notification should be sent to external banks 
     }
         }).get();
}
```

一旦检索到消息，就应该用它来查询有关交易的其他信息，并确定是否应该向外部银行发送通知。这种方法有助于减少有效负载的大小。它还有助于避免发送通常是不必要的和对其他系统无用的信息，但会增加源应用程序检索的流量。

在最坏的情况下，每个产生的事件都将至少检索一个额外的请求，要求交易详情，如下图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/b81c2556-b001-40b5-9827-887c498492a8.png)

下游依赖请求交易详情

在我们的示例中，每个产生的事件都将至少有三个来自依赖系统的其他请求。

# 事件携带状态传输

与之前讨论的事件通知模式相比，事件携带状态传输模式有一个小的变化。在这里，事件包含与执行的命令相关的非常基本的信息。在这种情况下，事件包含有关执行的命令的所有信息，用于避免通过依赖系统进一步处理而联系源应用程序。

这种模式为我们带来了以下好处：

+   提高应用程序性能

+   减少源应用程序的负载

+   增加系统的可用性

让我们在接下来的部分讨论每个要点。

# 提高应用程序性能

在前面的例子中，一旦事件被下游系统产生和检索，就需要执行额外的操作来获取与交易相关的详细信息。这决定了作为流程的一部分需要执行的操作。这个额外的操作涉及与源应用程序建立通信。在某些情况下，这一步可能只需要几毫秒，但响应时间可能会更长，这取决于网络流量和延迟。这将影响依赖系统的性能。

因此，源应用程序提供的负载大小增加，但需要的流量减少。

# 减少对源应用程序的负载

由于作为产生事件的一部分包含了与执行命令相关的所有信息，因此无需再向源应用程序请求更多信息。因此，请求减少，减轻了源应用程序的负载。

在最佳情况下，产生的事件与检索到的请求之间的关系是 1:1。换句话说，一个请求会产生一个事件，但根据依赖系统需要在检索事件时请求多少额外信息，情况可能更糟。

为了避免这种额外负载，所有下游系统通常都有自己的数据存储，其中事件信息被持久化，如下图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/94465532-3b0f-4da2-816a-c233a82f9d2c.png)

下游依赖持久化事件数据

使用这种方法时，每个下游系统只存储与自身相关的数据，提供的其余信息会被忽略，因为对于系统来说是无用的，根本不会被使用。

# 增加系统的可用性

在消除了一旦检索到事件就需要请求额外数据的需要之后，可以自然地假设系统的可用性已经提高，因为无论其他系统是否可用，事件都将被处理。引入这一好处的间接后果是现在系统中的最终一致性。

最终一致性是一种模型，用于在系统中实现高可用性，如果给定数据没有进行新的更新，一旦检索到一条信息，所有访问该数据的实例最终将返回最新更新的值。

下图显示了系统如何在不将这些更改传播到下游依赖项的情况下改变其数据：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/ee803ce8-493c-4991-9b50-5f7e8bdb2b73.png)

数据更新不会传播

为了使前面的例子遵循这种方法，我们只需要在负载的一部分中包含额外的信息。以前，我们只发送了一个带有`clientId`的`String`；现在我们将以以下方式涵盖完整的`TransactionMoneyDetails`：

```java
@RestController
public class TransferController 
{
  private final MessageChannel moneyTransferredChannel;
  public TransferController(EventNotificationChannel channel) 
  {
    this.moneyTransferredChannel = channel.moneyTransferredChannel();
  }
  @PostMapping("/transfer")
  public void doTransfer(@RequestBody TransferMoneyDetails 
  transferMoneyDetails) 
  {
    // Do something
 Message<TransferMoneyDetails> moneyTransferredEvent = 
 MessageBuilder.withPayload(transferMoneyDetails).build();
 this.moneyTransferredChannel.send(moneyTransferredEvent);
  }
}
```

`Message`类可以支持任何应该在`<>`中指定的对象，因为这个类是使用 Java 的泛型类型特性实现的。

下游依赖系统也应该被修改，使它们能够检索对象而不是简单的字符串。由于处理传入消息的`Handler`也支持泛型，我们可以通过对代码进行小的更改来实现这个功能，如下所示：

```java
@Bean
IntegrationFlow integrationFlow(EventNotificationChannel eventNotificationChannel) 
{
  return IntegrationFlows
  .from(eventNotificationChannel
  .subscriptionOnMoneyTransferredChannel())
  .handle(TransferMoneyDetails.class, new GenericHandler
  <TransferMoneyDetails>() 
  {
    @Override
    public Object handle(TransferMoneyDetails payload, Map<String, 
    Object> map) 
    {
      // Do something with the payload
      return null;
    }
  }).get();
}
```

# 事件溯源

事件溯源是另一种使用基于事件驱动方法实现应用程序的方式，其中功能的核心基于产生事件的命令，一旦处理完毕，这些事件将改变系统状态。

我们可以将命令看作是在系统内执行的交易的结果。这个交易会因以下因素而不同：

+   用户操作

+   来自其他应用程序的消息

+   执行的定期任务

使用事件源方法创建的应用程序存储与执行命令相关的事件。还值得存储产生事件的命令。这样可以将它们全部相关联，以便了解所创建的边界。

存储事件的主要原因是在任何时间点重建系统状态时使用它们。使这项任务变得更容易的方法是定期为存储系统状态的数据库生成备份，这有助于避免重新处理应用程序开始工作以来创建的所有事件的需要。相反，我们只需要处理在生成数据库快照之后执行的事件集。

让我们回顾以下一系列图表，以了解这是如何工作的。第一个图表显示一旦执行`Command A`，就会创建三个“事件”，并且在处理每个事件后生成一个新的“状态”：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/f6c21ae3-3c05-481c-9dd0-bdad5e083381.png)

一旦执行 Command A，生成的事件和应用程序状态

下一个图表代表了一个相似的过程。在这种情况下，由于`Command B`的执行，创建了两个“事件”：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/ec22155e-8a04-4229-8737-b9c760246dfa.png)

作为 Command B 执行的结果生成的事件和应用程序状态

到目前为止，我们的应用程序有五个状态：

+   状态 A

+   状态 B

+   状态 C

+   状态 D

+   状态 E

假设我们对“事件 b-1”感兴趣，因为在执行时应用程序崩溃了。为了实现这个目标，我们有两个选择：

+   逐个处理事件，并在“事件 b-1”执行期间研究应用程序行为，如下图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/f60ed164-0460-4e56-b547-166613859f2a.png)

处理所有事件重建应用程序状态

+   在恢复数据库快照后处理其余事件，并在“事件 b-1”执行期间研究应用程序行为，如下图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/f946d555-0508-4806-9395-bfc09324b89a.png)

从数据库快照重建应用程序状态

显然，第二种方法更有效。定期任务通常负责在一定时间后创建数据库快照，并且应该建立一个管理现有快照的策略。例如，您可以建立一个策略，在每天午夜创建一个新的快照，并在最适合您业务的时间后清除旧的快照。

正如您可能已经意识到的那样，我们系统的真相来源是事件存储，这使我们能够随时重建应用程序状态。由于事件被用来生成系统状态，我们可以完全依赖事件存储。然而，我们还应该考虑一个事实，即系统内的事件执行也需要与另一个应用程序进行交互。在这种情况下，如果重放该事件，您应该考虑其他系统将如何受到影响。在这里，我们将得到以下两种情况之一：

+   在其他应用程序中执行的操作是幂等的

+   其他应用程序将受到影响，因为将生成新的事务

在第一种情况下，由于操作是幂等的，我们根本不必担心。这是因为另一个执行不会影响其他系统。在第二种情况下，我们应该考虑创建补偿操作的方法或者忽略这些交互的方法，以避免影响其他系统。

在遵循这种方法后，我们将获得以下固有的好处：

+   可用于审计目的的数据存储

+   一个很好的日志级别

+   调试应用程序将更容易

+   历史状态

+   回到以前的状态的能力

事件溯源应用程序的典型示例是版本控制系统（VCS），如 Git、Apache 子版本、CVS 或任何其他版本控制系统，其中存储了应用于源代码文件的所有更改。此外，提交代表了允许我们在需要时撤消/重做更改的事件。

为了尽可能简单地理解，您可以将事件溯源应用程序视为以与版本控制系统管理文件更改相同的方式管理数据更改。您还可以将`git push`操作视为事件溯源系统中的命令。

现在我们已经解释了事件溯源背后的概念，是时候深入了解允许我们理解如何按照这种方法实现系统的细节了。虽然有不同的方法来创建事件溯源应用程序，但我将在这里解释一种通用的方法。重要的是要记住，这种方法应根据您的业务的特定需求或假设进行更改。

我们提到事件溯源系统应该*至少*有两个存储数据的地方。其中一个将用于保存事件和命令信息，另一个将用于保存应用程序状态——我们说*至少两个*，因为有时需要多个存储选项来持久化应用程序的系统状态。由于系统检索的输入以执行其业务流程非常不同，我们应该考虑使用支持使用 JSON 格式存储数据的数据库。按照这种方法，应作为事件溯源系统中执行的命令的一部分存储的最基本数据如下：

+   唯一标识符

+   时间戳

+   以 JSON 格式检索的输入数据

+   用于关联命令的任何附加数据

另一方面，应存储的建议数据事件如下：

+   唯一标识符

+   时间戳

+   事件的相关数据以 JSON 格式

+   生成事件的命令的标识符

正如我们之前提到的，根据您的业务需求，您可能需要添加更多字段，但前面提到的字段在任何情况下都是必要的。关键在于确保您的数据稍后能够被处理以在需要时重新创建应用程序状态。几乎任何 NoSQL 数据库都支持将数据存储为 JSON，但一些 SQL 数据库，如 PostgreSQL，也可以很好地处理这种格式的数据。

关于系统状态的决定，选择 SQL 或 NoSQL 技术完全取决于您的业务；您不必因为应用程序将使用事件溯源方法而改变主意。此外，您的数据模型结构也应该取决于业务本身，而不是取决于生成将存储在那里的数据的事件和命令。还值得一提的是，一个事件将生成将存储在系统状态数据模型的一个或多个表中的数据，并且在这些方面根本没有限制。

当我们考虑命令、事件和状态时，通常会提出一个问题，即信息持久化的顺序。这一点可能是一个有趣的讨论，但您不必太担心数据持久化的顺序。您可以选择在任何数据存储实例中同步或异步地持久化数据。

异步方法有时会让我们认为我们最终会得到不一致的信息，但事实是两种方法都可能导致这一点。我们应该考虑从这些崩溃中恢复我们的应用程序的机制，例如适当的日志记录。良好的日志记录对于恢复我们系统的数据非常有帮助，就像我们为使用事件源以外的任何方法构建的应用程序一样。

现在是时候回顾一些代码，把我们之前讨论过的概念付诸实践了。让我们构建一个应用程序，允许我们开设一个新的银行账户。所需的输入数据如下：

+   客户姓名

+   客户姓氏

+   开设账户的初始金额

+   账户类型（储蓄/活期）

创建账户后，我们的应用程序状态应该反映出一个新的客户和一个新创建的银行账户。

作为我们应用程序的一部分，我们将有一个命令：`CreateCustomerCommand`。这将生成两个事件，名为`CustomerCreated`和`AccountCreated`，如下图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/5fed95d8-d882-458b-95b7-a620e8cca665.png)

命令执行

执行此命令后，需要发生一些事情：

+   应保存命令

+   上述事件应该使用相关信息创建

+   应保存事件

+   应处理事件

这个过程的相关代码如下所示：

```java
public class CreateCustomerCommand extends Command {

    public void execute() {

        String commandId = UUID.randomUUID().toString();
        CommandMetadata commandMetadata 
            = new CommandMetadata(commandId, getName(), this.data);
 commandRepository.save(commandMetadata);

        String customerUuid = UUID.randomUUID().toString();

        JSONObject customerInformation = getCustomerInformation();
        customerInformation.put("customer_id", customerUuid);

        // CustomerCreated event creation EventMetadata customerCreatedEvent 
 = new EventMetadata(customerInformation, ...);        // CustomerCreated event saved eventRepository.save(customerCreatedEvent);        // CustomerCreated event sent to process eventProcessor.process(customerCreatedEvent);

        JSONObject accountInformation = getAccountInformation();
        accountInformation.put("customer_id", customerUuid);

        // AccountCreated event creation
 EventMetadata accountCreatedEvent 
 = new EventMetadata(accountInformation, ...);        // AccountCreated event saved eventRepository.save(accountCreatedEvent);        // AccountCreated event sent to process eventProcessor.process(accountCreatedEvent);

    }
    ...
}
```

事件处理完毕后，应生成系统状态。在这种情况下，意味着应创建一个新的客户和一个新的账户，如下图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/81d1803c-8298-447b-8c39-f0c895be5c6b.png)

处理事件后生成的系统状态

为了实现这个目标，我们有一个非常基本的实现，根据`事件名称`执行代码指令，如下所示：

```java
@Component
public class EventProcessor {

    public void process(EventMetadata event) {
        if ("CustomerCreated".equals(event.getEventName())) {
            Customer customer = new Customer(event);
            customerRepository.save(customer);
        } else if ("AccountCreated".equals(event.getEventName())) {
            Account account = new Account(event);
            accountRepository.save(account);
        }
    }
    ...
}
```

如果您想看看应用程序的工作原理，可以执行以下`CURL`命令：

```java
$ curl -H "Content-Type: application/json" \
 -X POST \
 -d '{"account_type": "savings", "name": "Rene", "last_name": "Enriquez", "initial_amount": 1000}' \
 http://localhost:8080/customer
```

您将在控制台中看到以下消息：

```java
COMMAND INFORMATION
id: 8782e12e-92e5-41e0-8241-c0fd83cd3194 , name: CreateCustomer , data: {"account_type":"savings","name":"Rene","last_name":"Enriquez","initial_amount":1000} 
EVENT INFORMATION
id: 71931e1b-5bce-4fe7-bbce-775b166fef55 , name: CustomerCreated , command id: 8782e12e-92e5-41e0-8241-c0fd83cd3194 , data: {"name":"Rene","last_name":"Enriquez","customer_id":"2fb9161e-c5fa-44b2-8652-75cd303fa54f"} 
id: 0e9c407c-3ea4-41ae-a9cd-af0c9a76b8fb , name: AccountCreated , command id: 8782e12e-92e5-41e0-8241-c0fd83cd3194 , data: {"account_type":"savings","account_id":"d8dbd8fd-fa98-4ffc-924a-f3c65e6f6156","balance":1000,"customer_id":"2fb9161e-c5fa-44b2-8652-75cd303fa54f"}
```

您可以通过在 URL：`http://localhost:8080/h2-console`中使用 H2 web 控制台执行 SQL 语句来检查系统状态。

以下截图显示了查询账户表的结果：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/6d25011b-0d29-4562-ae98-4001cb3b9e9a.png)

从账户表中查询结果

以下截图显示了查询客户表的结果：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/3b0f50a8-6983-46bb-aaf7-caef238a3c68.png)

从客户表中查询结果

事件源应用程序的最关键测试是在数据被删除后能够重新创建`状态`。您可以通过使用以下 SQL 语句从表中删除数据来运行此测试：

```java
DELETE FROM CUSTOMER;
DELETE FROM ACCOUNT;
```

在 H2 控制台中执行这些操作后，可以通过运行以下`CURL`命令重新创建状态：

```java
$ curl -X POST http://localhost:8080/events/<EVENT_ID> 
```

请注意，您需要用前面 URL 中列出的`<EVENT_ID>`替换控制台中执行命令时列出的值。

# CQRS

**命令查询职责分离**（**CQRS**）是一种模式，其主要思想是通过创建分离的接口来与系统的数据存储交互，从而创建用于读取和写入数据的分离数据结构和操作。

CQRS 实际上并不是基于事件，但由于它经常与事件源实现一起使用，因此值得提到它适用的场景。有三种主要用例，其中处理和查询信息的接口分离将会很有用：

+   复杂的领域模型

+   查询和持久化信息的不同路径

+   独立扩展

# 复杂的领域模型

这种情景指的是检索到的输入在数据库中简单管理和持久化的系统。然而，在将信息提供给用户之前，需要进行许多转换，使数据对业务有用和全面。

想象一个系统，其中代码由大量实体对象组成，这些对象使用 ORM 框架将数据库表映射为持久化信息。这种系统涉及许多使用 ORM 执行的写入和读取操作，以及作为系统一部分运行的一些操作，用于将检索到的数据（以实体对象的形式）转换为数据传输对象（DTO），以便以有意义的方式为业务提供信息。

以下图表显示了从数据库到业务服务的数据流，设计遵循这种方法：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/c07aa513-2d26-423b-a48a-81d0d1bb2d37.png)

使用实体对象和 DTO 的数据流

转换数据并不是什么大问题。在使用 ORM 的系统中，最大的问题是实体对象带来包含在转换过程中被忽略的无用信息的列，这会给数据库和网络带来不必要的开销。另一方面，在上图中，我们可以看到在实际获取所请求的数据之前，需要一个大的过程将数据库表映射为对象。解决这个问题的一个好方法是用存储过程或纯查询语句替换 ORM 框架执行的读操作，从数据库中仅检索所需的数据。

以下图表显示了如何用 DOTs 替换实体对象：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/08280105-b441-4ee5-b9e8-7e9b1a1d03eb.png)

使用 DTO 的数据流

很明显，这种方法更简单，更容易实现。所需的代码量甚至大大减少。我并不是在得出 ORM 框架不好的结论——实际上，其中许多都非常棒，像 Spring Data 这样的项目提供了大量内置功能。然而，根据业务需求，纯 JDBC 操作有时对系统更有益。

# 查询和持久化信息的不同路径

在构建应用程序时，我们经常发现自己在使用系统提供的信息之前对检索到的输入进行大量验证。

应用于检索数据的常见验证包括以下内容：

+   验证非空值

+   特定文本格式，如电子邮件

+   检查以验证字符串长度

+   数字中允许的最大小数位数

有许多机制可用于在我们的代码中实现这种验证。其中最流行的是基于第三方库的，依赖于可以使用正则表达式进行扩展以适用于特定场景的注解。甚至有一个作为平台的一部分可以用于验证类字段的规范，称为 Bean Validation。这目前是**Java 规范请求**（**JSR**）**380**的一部分（[`beanvalidation.org/`](http://beanvalidation.org/)）。

当用户或外部系统提供数据时，有必要进行所有这些验证，但是当从数据库中读取信息并返回给用户时，就没有必要继续执行这些检查。此外，在某些情况下，例如事件溯源，一旦检索到数据，会执行一些命令，创建事件，最终持久化信息。

在这些场景中，显然持久化和读取信息的过程是不同的，它们需要分开的路径来实现它们的目标。

以下图表显示了应用程序如何使用不同路径来持久化和检索数据：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/7abf67f1-4d20-4321-a20c-9d332f8adaf3.png)

使用不同路径持久化和查询的数据

从上图可以快速注意到有多少处理是不必要的，因为它绝对是不必要的。此外，用于查询和处理信息的领域模型通常不同，因为它们旨在实现不同的目标。

# 独立扩展

如今，常常听到开发人员、软件架构师和技术人员讨论创建独立服务来解决不同的需求。创建独立服务支持独立扩展的方法，因为它使得可以分别扩展创建的服务。

在这种情况下，主要的想法是创建可以独立构建和部署的独立系统。这些不同应用程序的数据源可以是相同的，也可以是不同的，这取决于需求是什么。这里最常见的情况是两个系统使用相同的数据存储，因为应用的更改应该立即反映出来。否则，延迟的数据可能会在应用程序的正常运行过程中引起混乱或错误。

让我们想象一个在线商店。假设你向购物车中添加了许多商品，在结账后，你意识到支付的金额比所需的金额要低，因为在结账过程中并未考虑所有商品。这是应用程序中不希望出现的行为。

另一方面，在某些情况下，使用不同的数据存储是可以接受的，因为检索延迟数小时或数天的数据已足以满足应用程序相关的业务需求。想象一下，你的任务是创建一个报告，显示人们倾向于在哪些月份请假。当然，一个数据库如果没有最新的更改，稍微落后于应用程序的当前状态，也可以完美地工作。当我们有这种需求时，我们可以使用报告数据库（有关更多详细信息，请参见[`martinfowler.com/bliki/ReportingDatabase.html`](https://martinfowler.com/bliki/ReportingDatabase.html)）来检索信息。这种方法通常用于当应用程序旨在提供执行报告信息以做出战略决策时，而不是获取数据库表中所有现有记录的列表。

拥有独立的系统来查询和处理信息使我们能够在两个系统上实现独立的扩展能力。当其中一个系统需要更多资源进行处理时，这是非常有用的。让我们以前面提到的在线商店为例，人们总是在寻找要购买的商品，进行比较，检查尺寸、价格、品牌等等。

在前面的例子中，检查订单的请求次数少于检查商品信息的请求次数。因此，在这种情况下，拥有独立的系统可以避免不必要地浪费资源，并且可以只增加更多资源或服务实例，以处理流量最大的服务。

# 总结

在本章中，我们介绍了事件驱动架构以及用于实现使用这种架构风格的应用程序的四种常见模式。我们详细解释了每种模式，并编写了一些代码来理解它们如何使用 Spring Framework 实现。同时，我们还研究了一些可以利用它们的用例，并学习了它们如何帮助我们减少作为系统需求一部分引入的复杂性。

作为这些模式的一部分，我们谈到了事件溯源，在微服务世界中越来越受欢迎，我们将在《微服务》的第八章中学习更多相关内容。


# 第七章：管道和过滤器架构

在本章中，我们将回顾一个有用的范式架构，名为管道和过滤器，并学习如何使用 Spring 框架实现应用程序。

我们还将解释如何构建一个封装了独立任务链的管道，旨在过滤和处理大量数据，重点放在使用 Spring Batch 上。

本章将涵盖以下主题：

+   管道和过滤器概念介绍

+   上船管道和过滤器架构

+   管道和过滤器架构的用例

+   Spring Batch

+   使用 Spring Batch 实现管道

我们将首先介绍管道和过滤器架构及其相关概念。

# 介绍管道和过滤器概念

管道和过滤器架构是指上世纪 70 年代初引入的一种架构风格。在本节中，我们将介绍管道和过滤器架构，以及过滤器和管道等概念。

Doug McIlroy 于 1972 年在 Unix 中引入了管道和过滤器架构。这些实现也被称为管道，它们由一系列处理元素组成，排列在一起，以便每个元素的输出是下一个元素的输入，如下图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/72e9d906-04fa-4277-863c-d16d09d749f1.png)

如前图所示，管道和过滤器架构由几个组件组成，称为过滤器，它们可以在整个过程中转换（或过滤）数据。然后，数据通过连接到每个组件的管道传递给其他组件（过滤器）。

# 过滤器

过滤器是用于转换（或过滤）从前一个组件通过管道（连接器）接收的输入数据的组件。如下图所示，每个过滤器都有一个输入管道和一个输出管道：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/b6f677e9-e5e4-4cc9-be84-8213f26ccacb.png)

这个概念的另一个特点是，过滤器可以有多个输入管道和多个输出管道，如下图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/6d11a37d-2672-4163-9080-39e43a9c171c.png)

# 管道

管道是过滤器的连接器。管道的作用是在过滤器和组件之间传递消息或信息。我们必须记住的是，流动是单向的，数据应该被存储，直到过滤器可以处理它。如下图所示，在过滤器之间可以看到连接器：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/935a5bdf-989f-416b-88c6-15c36e458657.png)

管道和过滤器架构风格用于将较大的过程、任务或数据分解为一系列由管道连接的小而独立的步骤（或过滤器）。

# 上船管道和过滤器架构

基于我们最近在企业应用领域介绍的管道和过滤器概念，我们在多种场景中使用这种架构，以处理需要处理的大量数据（或大文件）触发的多个步骤（或任务）。当我们需要对数据进行大量转换时，这种架构非常有益。

为了理解管道和过滤器的工作原理，我们将回顾一个经典的例子，即处理工资单记录。在这个例子中，一条消息通过一系列过滤器发送，每个过滤器在不同的事务中处理消息。

当我们应用管道和过滤器方法时，我们将整个过程分解为一系列可以重复使用的独立任务。使用这些任务，我们可以改变接收到的消息的格式，然后我们可以将其拆分以执行单独的事务。通过这样做，我们可以提高过程的性能、可伸缩性和可重用性。

这种架构风格使得创建递归过程成为可能。在这种情况下，一个过滤器可以包含在自身内部。在过程内部，我们可以包含另一个管道和过滤器序列，如下图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/6e4ab34b-f85e-43cd-87fa-82e0320aa32b.png)

在这种情况下，每个过滤器通过管道接收输入消息。然后，过滤器处理消息并将结果发布到下一个管道。这个可重复的过程将根据我们的业务需求继续多次。我们可以添加过滤器，接受或省略接收到的输入，并根据我们的业务需求将任务重新排序或重新排列成新的顺序。在下一节中，我们将详细介绍应用管道和过滤器架构风格的最常见用例。

# 管道和过滤器架构的用例

管道和过滤器架构的最常见用例如下：

+   将一个大的过程分解为几个小的独立步骤（过滤器）

+   通过多个过滤器以并行处理来扩展可以独立扩展的进程的系统

+   转换输入或接收到的消息

+   将过滤应用于**企业服务总线**（**ESB**）组件作为集成模式

# Spring Batch

Spring Batch 是一个完整的框架，用于创建强大的批处理应用程序（[`projects.spring.io/spring-batch/`](https://projects.spring.io/spring-batch/)）。我们可以创建可重用的函数来处理大量数据或任务，通常称为批量处理。

Spring Batch 提供了许多有用的功能，例如以下内容：

+   日志记录和跟踪

+   事务管理

+   作业统计

+   管理过程；例如，通过重新启动作业，跳过步骤和资源管理

+   管理 Web 控制台

该框架旨在通过使用分区功能管理大量数据并实现高性能的批处理过程。我们将从一个简单的项目开始，以解释 Spring Batch 的每个主要组件。

如 Spring Batch 文档中所述（[`docs.spring.io/spring-batch/trunk/reference/html/spring-batch-intro.html`](https://docs.spring.io/spring-batch/trunk/reference/html/spring-batch-intro.html)），使用该框架的最常见场景如下：

+   定期提交批处理

+   并发批处理用于并行处理作业

+   分阶段的企业消息驱动处理

+   大规模并行批处理

+   故障后手动或定时重新启动

+   依赖步骤的顺序处理（具有工作流驱动批处理的扩展）

+   部分处理：跳过记录（例如，在回滚时）

+   整批事务：适用于批量大小较小或现有存储过程/脚本的情况

在企业应用程序中，需要处理数百万条记录（数据）或从源中读取是非常常见的。该源可能包含具有多个记录的大文件（例如 CSV 或 TXT 文件）或数据库表。在每条记录上，通常会应用一些业务逻辑，执行验证或转换，并完成任务，将结果写入另一种输出格式（例如数据库或文件）。

Spring Batch 提供了一个完整的框架来实现这种需求，最大程度地减少人工干预。

我们将回顾 Spring 批处理的基本概念，如下所示：

+   作业封装了批处理过程，必须由一个或多个步骤组成。每个步骤可以按顺序运行，并行运行，或进行分区。

+   步骤是作业的顺序阶段。

+   JobLauncher 负责处理正在运行的作业的 JobExecution。

+   JobRepository 是 JobExecution 的元数据存储库。

让我们创建一个简单的使用 Spring Batch 的作业示例，以了解其工作原理。首先，我们将创建一个简单的 Java 项目并包含`spring-batch`依赖项。为此，我们将使用其初始化程序创建一个 Spring Boot 应用程序（[`start.spring.io`](https://start.spring.io)），如下截图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/635128b7-d76c-44ac-abbf-4d58edf657c7.png)

请注意，我们添加了 Spring Batch 的依赖项。您可以通过在依赖项框中的搜索栏中输入`Spring Batch`并点击*Enter*来执行此操作。在所选的依赖项部分将出现一个带有 Batch 字样的绿色框。完成后，我们将点击生成项目按钮。

项目的结构将如下所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/ed6c7e59-d80d-4fc7-9cd5-5c241f5f6e0e.png)

如果我们查看初始化器添加的依赖项部分，我们将在`pom.xml`文件中看到`spring-batch`启动器，如下所示：

```java
<dependency>
  <groupId>org.springframework.boot</groupId>
  <artifactId>spring-boot-starter-batch</artifactId>
</dependency>
<dependency>
  <groupId>org.springframework.boot</groupId>
  <artifactId>spring-boot-starter-test</artifactId>
  <scope>test</scope>
</dependency>
<dependency>
  <groupId>org.springframework.batch</groupId>
  <artifactId>spring-batch-test</artifactId>
  <scope>test</scope>
</dependency>
```

如果我们不使用 Spring Boot，我们可以显式添加`spring-batch-core`作为项目依赖项。以下是使用 Maven 的样子：

`<dependencies>`

`  <dependency>`

`    <groupId>org.springframework.batch</groupId>`

`    <artifactId>spring-batch-core</artifactId>`

`    <version>4.0.1.RELEASE</version>`

`  </dependency>`

`</dependencies>`

或者，我们可以使用 Gradle 来完成这个过程，如下所示：

`dependencies`

`{`

`  compile 'org.springframework.batch:spring-batch-core:4.0.1.RELEASE'`

`}`

项目将需要一个数据源；如果我们尝试在没有数据源的情况下运行应用程序，我们将在控制台中看到错误消息，如下所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/0bf0640b-3a2e-4f50-92a7-78ba3922defe.png)

为了解决这个问题，我们将在`pom.xml`文件中添加一个依赖项，以配置嵌入式数据源。为了测试目的，我们将使用 HSQL（[`hsqldb.org/`](http://hsqldb.org/)）如下所示：

```java
<dependency>
   <groupId>org.hsqldb</groupId>
   <artifactId>hsqldb</artifactId>
   <scope>runtime</scope>
</dependency>
```

现在，我们需要将`@EnabledBatchProcessing`和`@Configuration`注解添加到应用程序中：

```java

@SpringBootApplication
@EnableBatchProcessing @Configuration
public class SimpleBatchApplication {

```

接下来，我们将使用`JobBuildFactory`类设置我们的第一个作业，其中包含一个基于 Spring Batch 的任务流程，使用`StepBuilderFactory`类：

```java
@Autowired
private JobBuilderFactory jobBuilderFactory;

@Autowired
private StepBuilderFactory stepBuilderFactory;
```

`Job`方法将显示它正在启动，如下所示：

```java
@Bean
public Job job(Step ourBatchStep) throws Exception {
   return jobBuilderFactory.get("jobPackPub1")
         .incrementer(new RunIdIncrementer())
         .start(ourBatchStep)
         .build();
}
```

一旦`Job`被创建，我们将向`Job`添加一个新的任务（`Step`），如下所示：

```java
@Bean
public Step ourBatchStep() {
   return stepBuilderFactory.get("stepPackPub1")
         .tasklet(new Tasklet() {
            public RepeatStatus execute(StepContribution contribution, 
            ChunkContext chunkContext) {
               return null;
```

```java
            }
         })
         .build();
}
```

以下代码显示了应用程序类的样子：

```java
@EnableBatchProcessing
@SpringBootApplication
@Configuration
public class SimpleBatchApplication {

   public static void main(String[] args) {
      SpringApplication.run(SimpleBatchApplication.class, args);
   }

   @Autowired
   private JobBuilderFactory jobBuilderFactory;

   @Autowired
   private StepBuilderFactory stepBuilderFactory;

   @Bean
   public Step ourBatchStep() {
      return stepBuilderFactory.get("stepPackPub1")
            .tasklet(new Tasklet() {
               public RepeatStatus execute
                (StepContribution contribution, 
                    ChunkContext chunkContext) {
                  return null;
               }
            })
            .build();
   }

   @Bean
   public Job job(Step ourBatchStep) throws Exception {
      return jobBuilderFactory.get("jobPackPub1")
            .incrementer(new RunIdIncrementer())
            .start(ourBatchStep)
            .build();
   }
}
```

为了检查一切是否正常，我们将运行应用程序。为此，我们将在命令行上执行以下操作：

```java
$ mvn spring-boot:run
```

或者，我们可以通过运行 maven 来构建应用程序，如下所示：

```java
$ mvn install
```

接下来，我们将在终端上运行我们最近构建的 jar，如下所示：

```java
$ java -jar target/simple-batch-0.0.1-SNAPSHOT.jar
```

不要忘记在构建或运行应用程序之前安装 Maven 或 Gradle 和 JDK 8。

最后，我们将在控制台中看到以下输出：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/5ff94ceb-126a-4103-927b-bf3cee72df11.png)

注意控制台输出。为此，我们运行名为`jobPackPub1`的作业，并执行名为`stepPackPub1`的 bean。

现在，我们将更详细地查看以下步骤背后的组件：

+   ItemReader 代表了步骤输入的检索

+   ItemProcessor 代表了对项目的业务处理

+   ItemWriter 代表了步骤的输出

以下图表显示了 Spring Batch 主要元素的整体情况：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/e1644f90-82c2-47be-b282-d8f417628856.png)

现在，我们将通过使用 ItemReader、ItemProcessor 和 ItemWriter 来完成我们的示例。通过使用和解释这些组件，我们将向您展示如何使用 Spring Batch 实现管道和过滤器架构。

# 使用 Spring Batch 实现管道

现在我们已经说明了 Spring Batch 是什么，我们将通过以下步骤实现工资文件处理用例（如前一节中定义的）：

+   编写一个从 CSV 电子表格导入工资数据的流程

+   使用业务类转换文件元组

+   将结果存储在数据库中

以下图表说明了我们的实现：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/8ab5bee2-11ea-4098-9146-9eae1634813c.png)

首先，我们将使用 Spring 初始化器（[`start.spring.io`](https://start.spring.io)）创建一个新的干净项目，就像我们在上一节中所做的那样：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/ceeb8140-bd2f-4f36-ac75-ffcf3cd01e0c.png)

记得像之前的例子一样，将`Batch`引用添加到我们的项目中。

不要忘记在`pom.xml`文件中将数据库驱动程序添加为依赖项。出于测试目的，我们将使用 HSQL（[`hsqldb.org/`](http://hsqldb.org/)）。

```java
<dependency>
   <groupId>org.hsqldb</groupId>
   <artifactId>hsqldb</artifactId>
   <scope>runtime</scope>
</dependency>
```

如果您想使用其他数据库，可以参考 Spring Boot 文档中提供的详细说明（[`docs.spring.io/spring-boot/docs/current/reference/html/boot-features-sql.html`](https://docs.spring.io/spring-boot/docs/current/reference/html/boot-features-sql.html)）。

现在，我们将创建输入数据作为文件，将输出结构作为数据库表，如下图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/261d7e09-3198-4318-978e-f4422763d4bc.png)

我们将在资源文件夹（`src/main/resources/payroll-data.csv`）中添加一个 CSV 文件，内容如下：

```java
0401343844,USD,1582.66,SAVING,3550891500,PAYROLL MARCH 2018,JAIME PRADO
1713430133,USD,941.21,SAVING,2200993002,PAYROLL MARCH 2018,CAROLINA SARANGO
1104447619,USD,725.20,SAVING,2203128508,PAYROLL MARCH 2018,MADALAINE RODRIGUEZ
0805676117,USD,433.79,SAVING,5464013600,PAYROLL MARCH 2018,BELEN CALERO
1717654933,USD,1269.10,SAVING,5497217100,PAYROLL MARCH 2018,MARIA VALVERDE
1102362626,USD,1087.80,SAVING,2200376305,PAYROLL MARCH 2018,VANESSA ARMIJOS
1718735793,USD,906.50,SAVING,6048977500,PAYROLL MARCH 2018,IGNACIO BERRAZUETA
1345644970,USD,494.90,SAVING,6099018000,PAYROLL MARCH 2018,ALBERTO SALAZAR
0604444602,USD,1676.40,SAVING,5524707700,PAYROLL MARCH 2018,XIMENA JARA
1577777593,USD,3229.75,SAVING,3033235300,PAYROLL MARCH 2018,HYUN WOO
1777705472,USD,2061.27,SAVING,3125662300,PAYROLL MARCH 2018,CARLOS QUIROLA
1999353121,USD,906.50,SAVING,2203118265,PAYROLL MARCH 2018,PAUL VARELA
1878363820,USD,1838.30,SAVING,4837838200,PAYROLL MARCH 2018,LEONARDO VASQUEZ
```

我们项目的结构如下所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/5b84cab7-de91-4058-b591-a7dbda6390ee.png)

这个电子表格包含交易的标识、货币、账号、账户类型、交易描述、受益人电话和受益人姓名。这些内容以逗号分隔显示在每一行上。这是一个常见的模式，Spring 可以直接处理。

现在，我们将创建数据库结构，用于存储工资单处理的结果。我们将在资源文件夹（`src/main/resources/schema-all.sql`）中添加以下内容：

```java
DROP TABLE PAYROLL IF EXISTS;

CREATE TABLE PAYROLL  (
    transaction_id BIGINT IDENTITY NOT NULL PRIMARY KEY,
    person_identification VARCHAR(20),
    currency VARCHAR(20),
    tx_ammount DOUBLE,
    account_type VARCHAR(20),
    account_id VARCHAR(20),
    tx_description VARCHAR(20),
    first_last_name VARCHAR(20)
);
```

我们将创建的文件将遵循此模式名称：`schema-@@platform@@.sql`。Spring Boot 将在启动期间运行 SQL 脚本；这是所有平台的默认行为。

到目前为止，我们已经创建了输入数据作为`.csv`文件，以及输出存储库，用于存储我们完整的工资单流程。因此，我们现在将创建过滤器，并使用 Spring Batch 带来的默认管道。

首先，我们将创建一个代表我们业务数据的类，包括我们将接收的所有字段。我们将命名为`PayRollTo.java`（**工资单传输对象**）：

```java
package com.packpub.payrollprocess;

public class PayrollTo {

    private Integer identification;

    private String currency;

    private Double ammount;

    private String accountType;

    private String accountNumber;

    private String description;

    private String firstLastName;

    public PayrollTo() {
    }

    public PayrollTo(Integer identification, String currency, Double ammount, String accountType, String accountNumber, String description, String firstLastName) {
        this.identification = identification;
        this.currency = currency;
        this.ammount = ammount;
        this.accountType = accountType;
        this.accountNumber = accountNumber;
        this.description = description;
        this.firstLastName = firstLastName;
    }

    // getters and setters

    @Override
    public String toString() {
        return "PayrollTo{" +
                "identification=" + identification +
                ", currency='" + currency + '\'' +
                ", ammount=" + ammount +
                ", accountType='" + accountType + '\'' +
                ", accountNumber='" + accountNumber + '\'' +
                ", description='" + description + '\'' +
                ", firstLastName='" + firstLastName + '\'' +
                '}';
    }
}
```

现在，我们将创建我们的过滤器，它在 Spring Batch 中表示为处理器。与框架提供的开箱即用行为类似，我们首先将专注于转换输入数据的业务类，如下图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/46caf14e-96c6-4720-b172-9d69f42c60cb.png)

在每一行包括我们的文件表示为`PayrollTo`类之后，我们需要一个过滤器，将每个数据文件转换为大写。使用 Spring Batch，我们将创建一个处理器，将转换数据文件，然后将数据发送到下一步。因此，让我们创建一个`PayRollItemProcessor.java`对象，实现`org.springframework.batch.item.ItemProcessor<InputObject, OutputObjet>`接口，如下所示：

```java
package com.packpub.payrollprocess;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.batch.item.ItemProcessor;

public class PayRollItemProcessor implements 
                    ItemProcessor<PayrollTo, PayrollTo> {

    private static final Logger log = LoggerFactory
                    .getLogger(PayRollItemProcessor.class);

    @Override
    public PayrollTo process(PayrollTo payrollTo) throws Exception {

        final PayrollTo resultTransformation = new PayrollTo();
        resultTransformation.setFirstLastName
            (payrollTo.getFirstLastName().toUpperCase());
        resultTransformation.setDescription
            (payrollTo.getDescription().toUpperCase());
        resultTransformation.setAccountNumber
            (payrollTo.getAccountNumber());
        resultTransformation.setAccountType(payrollTo.getAccountType());
        resultTransformation.setCurrency(payrollTo.getCurrency());
        resultTransformation.setIdentification
            (payrollTo.getIdentification());

        // Data Type Transform
        final double ammountAsNumber = payrollTo.getAmmount()
                                                    .doubleValue();
        resultTransformation.setAmmount(ammountAsNumber);

        log.info
            ("Transforming (" + payrollTo + ") into (" 
                                + resultTransformation + ")");
        return resultTransformation;
    }
}
```

根据 API 接口，我们将接收一个传入的`PayrollTo`对象，然后将其转换为大写的`PayrollTo`，用于`firstLastName`和`description`属性。

输入对象和输出对象的类型不同并不重要。在许多情况下，一个过滤器将接收一种消息或数据，需要为下一个过滤器提供不同类型的消息或数据。

现在，我们将创建我们的批处理作业，并使用一些 Spring Batch 的开箱即用功能。例如，**ItemReader**具有一个有用的 API 来处理文件，**ItemWriter**可用于指定如何存储生成的数据：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/a205ec9d-6a82-406d-952d-02dbeb251edb.png)

最后，我们将使用作业连接所有流数据。

使用 Spring Batch，我们需要专注于我们的业务（就像在`PayRollItemProcessor.java`类中所做的那样），然后将所有部分连接在一起，如下所示：

```java
@Configuration
@EnableBatchProcessing
public class BatchConfig {

    @Autowired
    public JobBuilderFactory jobBuilderFactory;

    @Autowired
    public StepBuilderFactory stepBuilderFactory;

 // READ THE INPUT DATA
    @Bean
    public FlatFileItemReader<PayrollTo> reader() {
        return new FlatFileItemReaderBuilder<PayrollTo>()
                .name("payrollItemReader")
                .resource(new ClassPathResource("payroll-data.csv"))
                .delimited()
                .names(
                    new String[]{
                        "identification", "currency", "ammount",
                        "accountType", "accountNumber", "description",
                        "firstLastName"})
                .fieldSetMapper(
                    new BeanWrapperFieldSetMapper<PayrollTo>() {{
                    setTargetType(PayrollTo.class);
                }})
                .build();
    }

 // PROCESS THE DATA
    @Bean
    public PayRollItemProcessor processor() {
        return new PayRollItemProcessor();
    }

 // WRITE THE PRODUCED DATA
    @Bean
    public JdbcBatchItemWriter<PayrollTo> writer(DataSource dataSource) {
        return new JdbcBatchItemWriterBuilder<PayrollTo>()
                .itemSqlParameterSourceProvider(
                    new BeanPropertyItemSqlParameterSourceProvider<>())
                .sql(
                    "INSERT INTO PAYROLL (PERSON_IDENTIFICATION,
                        CURRENCY, TX_AMMOUNT, ACCOUNT_TYPE, ACCOUNT_ID, 
                        TX_DESCRIPTION, FIRST_LAST_NAME) VALUES 
                    (:identification,:currenxcy,:ammount,:accountType,
                     :accountNumber, :description, :firstLastName)")
                .dataSource(dataSource)
                .build();
    }

    @Bean
    public Job importPayRollJob(JobCompletionPayRollListener listener, Step step1) {
        return jobBuilderFactory.get("importPayRollJob")
                .incrementer(new RunIdIncrementer())
                .listener(listener)
                .flow(step1)
                .end()
                .build();
    }

    @Bean
    public Step step1(JdbcBatchItemWriter<PayrollTo> writer) {
        return stepBuilderFactory.get("step1")
                .<PayrollTo, PayrollTo> chunk(10)
                .reader(reader())
                .processor(processor())
                .writer(writer)
                .build();
    }
}
```

有关 Spring Batch ItemReaders 和 ItemWriters 的详细说明，请访问[`docs.spring.io/spring-batch/trunk/reference/html/readersAndWriters.html`](https://docs.spring.io/spring-batch/trunk/reference/html/readersAndWriters.html)。

让我们来看一下`Step` bean 的工作原理：

```java
@Bean
    public Step step1(JdbcBatchItemWriter<PayrollTo> writer)
 {
        return stepBuilderFactory.get("step1")
                .<PayrollTo, PayrollTo> chunk(10)
                .reader(reader())
 .processor(processor())
 .writer(writer)
                .build();
 }
```

首先，它配置步骤以每次读取**10 条记录**的数据块，然后配置步骤与相应的`reader`、`processor`和`writer`对象。

我们现在已经实现了我们计划的所有管道和过滤器，如下图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/5c35ddfa-d6de-47dc-9200-e654e36f7119.png)

最后，我们将添加一个监听器，以检查我们处理的工资单数据。为此，我们将创建一个`JobCompletionPayRollListener.java`类，该类扩展了`JobExecutionListenerSupport`类，并实现了`afterJob(JobExecution jobExecution)`方法。

现在，我们将回顾我们从处理的数据中处理了多少`insert`操作：

```java

@Component
public class JobCompletionPayRollListener 
            extends JobExecutionListenerSupport {

    private static final Logger log = 
        LoggerFactory.getLogger(JobCompletionPayRollListener.class);

    private final JdbcTemplate jdbcTemplate;

    @Autowired
    public JobCompletionPayRollListener(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @Override
    public void afterJob(JobExecution jobExecution) {
        if (jobExecution.getStatus() == BatchStatus.COMPLETED) {
 log.info(">>>>> PAY ROLL JOB FINISHED! ");

            jdbcTemplate
            .query(
                "SELECT PERSON_IDENTIFICATION, CURRENCY, TX_AMMOUNT,                          ACCOUNT_TYPE, ACCOUNT_ID, TX_DESCRIPTION, 
                        FIRST_LAST_NAME FROM PAYROLL",
                    (rs, row) -> new PayrollTo(
                            rs.getInt(1),
                            rs.getString(2),
                            rs.getDouble(3),
                            rs.getString(4),
                            rs.getString(5),
                            rs.getString(6),
                            rs.getString(7))
            ).forEach(payroll -> 
                log.info("Found <" + payroll + "> in the database.")
                );
        }
    }
}
```

为了检查一切是否正常，我们将执行应用程序，使用以下命令：

```java
$ mvn spring-boot:run
```

或者，我们可以使用 maven 构建应用程序，如下所示：

```java
$ mvn install
```

接下来，我们将在终端上运行最近构建的`jar`：

```java
$ java -jar target/payroll-process-0.0.1-SNAPSHOT.jar
```

最后，我们将在控制台上看到以下输出。该输出代表已实现为 ItemProcessor 的过滤器，用于转换数据：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/36450a60-601e-423c-8e43-3271e7dcd895.png)

我们还可以通过监听器来验证我们的流程，该监听器实现为`JobExecutionListenerSupport`，打印存储在数据库中的结果：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/73968333-28d8-4d8c-b1cd-f91618785939.png)

我们可以将 Spring Batch 应用程序打包成 WAR 文件，然后运行一个 servlet 容器（如 Tomcat）或任何 JEE 应用程序服务器（如 Glassfish 或 JBoss）。要将`.jar`文件打包成 WAR 文件，请使用`spring-boot-gradle-plugin`或`spring-boot-maven-plugin`。对于 Maven，您可以参考 Spring Boot 文档（[`docs.spring.io/spring-boot/docs/current/reference/htmlsingle/#build-tool-plugins-maven-packaging`](https://docs.spring.io/spring-boot/docs/current/reference/htmlsingle/#build-tool-plugins-maven-packaging)）。对于 Gradle，您可以参考[`docs.spring.io/spring-boot/docs/current/gradle-plugin/reference/html/#packaging-executable-wars`](https://docs.spring.io/spring-boot/docs/current/gradle-plugin/reference/html/#packaging-executable-wars)。

# 摘要

在本章中，我们讨论了管道和过滤器架构的概念，其实施的主要用例，以及如何在企业应用程序中使用它。此外，您还学会了如何使用 Spring Batch 实现架构，以及如何管理不同数量的数据并将流程拆分为较小的任务。

在下一章中，我们将回顾容器化应用程序的重要性。
