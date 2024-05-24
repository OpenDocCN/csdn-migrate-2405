# SpringMVC：设计现实世界的 Web 应用（九）

> 原文：[`zh.annas-archive.org/md5/AB3510E97B9E20602840C849773D49C6`](https://zh.annas-archive.org/md5/AB3510E97B9E20602840C849773D49C6)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)


# 第三部分：精通 Spring MVC 4

*掌握使用 Spring MVC 框架设计真实世界的 Web 应用程序的专业知识*



#  第十七章：掌握 MVC 架构

在本章中，我们将讨论 MVC 架构原则，并了解 Spring MVC 如何实现这些原则。

我们的目标是设计一个简单的页面，用户可以在其中搜索符合某些条件的推文，并将它们显示给我们的用户。

为了实现这一点，我们将使用 Spring Social Twitter 项目，该项目可在[`projects.spring.io/spring-social-twitter/`](http://projects.spring.io/spring-social-twitter/)上找到。

我们将看到如何使 Spring MVC 与现代模板引擎 Thymeleaf 配合工作，并尝试理解框架的内部机制。我们将引导用户通过不同的视图，最后，我们将使用 WebJars 和 Materialize（[`materializecss.com`](http://materializecss.com)）为我们的应用程序提供出色的外观。

# MVC 架构

我希望 MVC 首字母缩略词的含义对大多数人来说是熟悉的。它代表模型视图控制器，被认为是一种非常流行的通过解耦数据和表示层构建用户界面的方式。

![MVC 架构](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00928.jpeg)

MVC 模式在从 Smalltalk 世界中出现并进入 Ruby on Rails 框架后变得非常流行。

这种架构模式包括三个层：

+   **模型**：这包括应用程序了解的数据的各种表示形式。

+   **视图**：这由将显示给用户的数据的几种表示形式组成。

+   **控制器**：这是应用程序处理用户交互的部分。它是模型和视图之间的桥梁。

MVC 背后的理念是将视图与模型解耦。模型必须是自包含的，并且对 UI 一无所知。这基本上允许相同的数据在多个视图中重复使用。这些视图是查看数据的不同方式。深入或使用不同的渲染器（HTML，PDF）是这一原则的很好的例证。

控制器充当用户和数据之间的中介。它的作用是控制最终用户可用的操作，以及在应用程序的不同视图之间进行路由。

# MVC 的批评和最佳实践

虽然 MVC 仍然是设计 UI 的首选方法，但随着其流行，出现了许多批评。大多数批评者实际上是在指责模式的错误使用。

## 贫血领域模型

Eric Evans 的具有影响力的书籍《领域驱动设计》，也缩写为**DDD**，定义了一组架构规则，以实现更好地将业务领域整合到代码中。

其中一个核心思想是利用领域对象内的面向对象范例。违背这一原则有时被称为**贫血领域模型**。这个问题的一个很好的定义可以在 Martin Fowler 的博客上找到（[`www.martinfowler.com/bliki/AnemicDomainModel.html`](http://www.martinfowler.com/bliki/AnemicDomainModel.html)）。

贫血模型通常表现出以下症状：

+   模型由非常简单的**普通的 Java 对象**（**POJO**）组成，只有 getter 和 setter

+   所有业务逻辑都在服务层内处理

+   模型的验证在模型之外，例如在控制器中

这取决于您的业务领域的复杂性，这可能是一种不良实践。一般来说，领域驱动设计（DDD）实践需要额外的努力来将领域与应用程序逻辑隔离开来。

架构始终是一种权衡。值得注意的是，设计 Spring 应用程序的典型方式可能会导致在某个时候出现复杂的维护。

如何避免领域贫血在这里有解释：

+   服务层适用于应用级抽象，如事务处理，而不是业务逻辑。

+   您的领域应始终处于有效状态。使用验证器或 JSR-303 的验证注释将验证留在表单对象内。

+   将输入转化为有意义的领域对象。

+   将数据层视为具有领域查询的存储库（例如参考 Spring Data 规范）

+   将领域逻辑与底层持久性框架解耦

+   尽可能使用真实对象。例如，操作`FirstName`类而不是字符串。

领域驱动设计比这些简单的规则要复杂得多：实体、值类型、通用语言、有界上下文、洋葱架构和防腐层。我强烈鼓励您自行研究这些原则。就我们而言，通过本书，我们将努力记住前面列出的指导方针，因为我们打造我们的 Web 应用程序时，这些问题将变得更加熟悉。

## 从源代码中学习

如果您熟悉 Spring，您可能已经访问过 Spring 的网站[`spring.io`](http://spring.io)。它完全由 Spring 制作，好消息是它是开源的。

该项目的代号是 sagan。它有许多有趣的特性：

+   一个 gradle 多模块项目

+   安全集成

+   Github 集成

+   Elasticsearch 集成

+   一个 JavaScript 前端应用程序

与该项目相关的 GitHub 维基非常详细，将帮助您轻松开始使用该项目。

### 注意

如果您对 Spring 的真实世界应用程序架构感兴趣，请访问以下网址：

[`github.com/spring-io/sagan`](https://github.com/spring-io/sagan)

# Spring MVC 1-0-1

在 Spring MVC 中，模型是 Spring MVC 的`Model`或`ModelAndView`类中封装的简单映射。它可以来自数据库、文件、外部服务等。由您定义如何获取数据并将其放入模型。与数据层交互的推荐方式是通过 Spring Data 库：Spring Data JPA、Spring Data MongoDB 等。有数十个与 Spring Data 相关的项目，我鼓励您查看[`projects.spring.io/spring-data`](http://projects.spring.io/spring-data)。

Spring MVC 的控制器端通过使用`@Controller`注解来处理。在 Web 应用程序中，控制器的作用是响应 HTTP 请求。使用`@Controller`注解标记的类将被 Spring 捕获，并有机会处理即将到来的请求。

通过`@RequestMapping`注解，控制器声明处理特定请求，基于它们的 HTTP 方法（例如`GET`或`POST`方法）和它们的 URL。然后控制器决定是直接在 Web 响应中写入内容，还是将应用程序路由到视图并将属性注入该视图。

一个纯粹的 RESTful 应用程序将选择第一种方法，并使用`@ResponseBody`注解直接在 HTTP 响应中公开模型的 JSON 或 XML 表示。在 Web 应用程序的情况下，这种类型的架构通常与前端 JavaScript 框架（如 Backbone.js、AngularJS 或 React）相关联。在这种情况下，Spring 应用程序将仅处理 MVC 模型的模型层。我们将在第三章中学习这种类型的架构，*文件上传和错误处理*。

通过第二种方法，模型被传递到视图，由模板引擎呈现，然后写入响应。

视图通常与模板方言相关联，这将允许在模型内进行导航。用于模板的流行方言包括 JSP、FreeMarker 或 Thymeleaf。

混合方法可以利用模板引擎与应用程序的某些方面进行交互，然后将视图层委托给前端框架。

# 使用 Thymeleaf

Thymeleaf 是一个模板引擎，受到 Spring 社区的特别关注。

它的成功主要归功于其友好的语法（它几乎看起来像 HTML）和它可以轻松扩展的特性。

Spring Boot 有各种可用的扩展和集成：

| 支持 | 依赖 |
| --- | --- |
| 布局 | `nz.net.ultraq.thymeleaf:thymeleaf-layout-dialect` |
| HTML5 data-* 属性 | `com.github.mxab.thymeleaf.extras:thymeleaf-extras-data-attribute` |
| Internet Explorer 条件注释 | `org.thymeleaf.extras:thymeleaf-extras-conditionalcomments` |
| 支持 spring 安全 | `org.thymeleaf.extras:thymeleaf-extras-springsecurity3` |

Thymeleaf 与 Spring 集成的非常好的教程可以在[`www.thymeleaf.org/doc/tutorials/2.1/thymeleafspring.html`](http://www.thymeleaf.org/doc/tutorials/2.1/thymeleafspring.html)找到。

不多说了，让我们添加`spring-boot-starter-thymeleaf`依赖项来启动 thymeleaf 模板引擎：

```java
buildscript {
    ext {
        springBootVersion = '1.2.5.RELEASE'
    }
    repositories {
        mavenCentral()
    }
    dependencies {
        classpath("org.springframework.boot:spring-boot-gradle-plugin:${springBootVersion}") 
        classpath("io.spring.gradle:dependency-management-plugin:0.5.1.RELEASE")
    }
}

apply plugin: 'java'
apply plugin: 'eclipse'
apply plugin: 'idea'
apply plugin: 'spring-boot' 
apply plugin: 'io.spring.dependency-management' 

jar {
    baseName = 'masterSpringMvc'
    version = '0.0.1-SNAPSHOT'
}
sourceCompatibility = 1.8
targetCompatibility = 1.8

repositories {
    mavenCentral()
}

dependencies {
    compile 'org.springframework.boot:spring-boot-starter-web'
    compile 'org.springframework.boot:spring-boot-starter-thymeleaf'
    testCompile 'org.springframework.boot:spring-boot-starter-test'
}

eclipse {
    classpath {
         containers.remove('org.eclipse.jdt.launching.JRE_CONTAINER')
         containers 'org.eclipse.jdt.launching.JRE_CONTAINER/org.eclipse.jdt.internal.debug.ui.launcher.StandardVMType/JavaSE-1.8'
    }
}

task wrapper(type: Wrapper) {
    gradleVersion = '2.3'
}
```

## 我们的第一个页面

现在我们将第一个页面添加到我们的应用程序中。它将位于`src/main/resources/templates`。让我们把文件命名为`resultPage.html`：

```java
<!DOCTYPE html>
<html >
<head lang="en">
    <meta charset="UTF-8"/>
    <title>Hello thymeleaf</title>
</head>
<body>
    <span th:text="|Hello thymeleaf|">Hello html</span>
</body>
</html>
```

我们从一开始就可以看到 Thymeleaf 与 html 完美地集成在一起，它的语法几乎感觉自然。

`th:text`的值放在管道符号之间。这意味着文本中的所有值将被连接起来。

起初可能有点尴尬，但实际上，在我们的页面中很少会硬编码文本；因此，Thymeleaf 在这里做出了一个有见地的设计决定。

Thymeleaf 对于网页设计师有一个很大的优势：模板中的所有动态内容都可以在没有运行服务器的情况下回退到默认值。资源 URL 可以相对指定，每个标记都可以包含占位符。在我们之前的例子中，当视图在我们的应用程序的上下文中呈现时，文本"Hello html"将不会被显示，但如果文件直接在 Web 浏览器中打开，它将会被显示。

为了加快开发速度，将这个属性添加到你的`application.properties`文件中：

```java
spring.thymeleaf.cache=false
```

这将禁用视图缓存，并导致模板在每次访问时重新加载。

当然，当我们进入生产阶段时，这个设置将需要被禁用。我们将在第七章中看到这一点，*优化您的请求*。

### 提示

**重新加载视图**

禁用缓存后，只需在 eclipse 中保存你的视图，或者在 IntelliJ 中使用`Build > Make Project`操作来在更改后刷新视图。

最后，我们需要修改我们的`HelloController`类。现在，它不再显示纯文本，而是必须路由到我们新创建的视图。为了实现这一点，我们将删除`@ResponseBody`注解。这样做并且仍然返回一个字符串将告诉 Spring MVC 将这个字符串映射到一个视图名称，而不是直接在响应中显示特定的模型。

我们的控制器现在看起来像这样：

```java
@Controller
public class HelloController {

    @RequestMapping("/")
    public String hello() {
        return "resultPage";
    }
}
```

在这个例子中，控制器将重定向用户到视图名称`resultPage`。`ViewResolver`接口将把这个名称与我们的页面关联起来。

让我们再次启动我们的应用程序，然后转到`http://localhost:8080`。

你将看到以下页面：

![我们的第一个页面](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00929.jpeg)

# Spring MVC 架构

让我们从这个令人惊叹的新的"Hello World"中退一步，试着理解我们的 Web 应用程序内部发生了什么。为了做到这一点，我们将追溯浏览器发送的 HTTP 请求的旅程，以及它从服务器得到的响应。

## DispatcherServlet

每个 Spring Web 应用程序的入口点是`DispatcherServlet`。下图说明了 Dispatcher Servlet 的架构：

![DispatcherServlet](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00930.jpeg)

这是一个经典的`HttpServlet`类，它将 HTTP 请求分派给 HandlerMapping。**HandlerMapping**是资源（URL）和控制器的关联。

然后在 Controller 上调用带有`@RequestMapping`注解的适当方法。在这个方法中，控制器设置模型数据并返回视图名称给分派程序。

`DispatcherServlet`然后将询问`ViewResolver`接口以找到视图的相应实现。

在我们的情况下，`ThymeleafAutoConfiguration`类已经为我们设置了视图解析器。

您可以在`ThymeleafProperties`类中看到，我们视图的默认前缀是`classpath:/templates/`，默认后缀是`.html`。

这意味着，鉴于视图名称`resultPage`，视图解析器将在我们类路径的模板目录中查找名为`resultPage.html`的文件。

在我们的应用程序中，`ViewResolver`接口是静态的，但更高级的实现可以根据请求标头或用户的区域设置返回不同的结果。

视图最终将被呈现，并将结果写入响应。

## 将数据传递给视图

我们的第一个页面完全是静态的；它实际上并没有充分利用 Spring MVC 的强大功能。让我们稍微调整一下。如果“Hello World”字符串不是硬编码的，而是来自服务器呢？

你说这仍然是一个无聊的“hello world”？是的，但它将开启更多的可能性。让我们修改我们的`resultPage.html`文件，以显示来自模型的消息：

```java
<!DOCTYPE html>
<html >
<head lang="en">
    <meta charset="UTF-8"/>
    <title>Hello thymeleaf</title>
</head>
<body>
    <span th:text="${message}">Hello html</span>
</body>
</html>
```

然后，让我们修改我们的控制器，以便将此消息放入此模型中：

```java
@Controller
public class HelloController {

    @RequestMapping("/")
    public String hello(Model model) {
        model.addAttribute("message", "Hello from the controller");
        return "resultPage";
    }
}
```

我知道，悬念让你着急！让我们看看`http://localhost:8080`是什么样子。

![将数据传递给视图](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00931.jpeg)

首先要注意的是，我们向控制器的方法传递了一个新的参数，`DispatcherServlet`为我们提供了正确的对象。实际上，控制器的方法可以注入许多对象，例如`HttpRequest`或`HttpResponse`，`Locale`，`TimeZone`和`Principal`，代表经过身份验证的用户。此类对象的完整列表可在文档中找到，网址为[`docs.spring.io/spring/docs/current/spring-framework-reference/html/mvc.html#mvc-ann-arguments`](http://docs.spring.io/spring/docs/current/spring-framework-reference/html/mvc.html#mvc-ann-arguments)。

# Spring 表达式语言

使用`${}`语法时，实际上使用的是**Spring 表达式语言**（**SpEL**）。在野外有几种变体的 EL 可用；SpEl 是最强大的变体之一。

以下是其主要特点的概述：

| 功能 | 语法 | 解释 |
| --- | --- | --- |
| 访问列表元素 | `list[0]` |   |
| 访问映射条目 | `map[key]` |   |
| 三元运算符 | `condition ? 'yes' : 'no'` |   |
| Elvis 运算符 | `person ?: default` | 如果 person 的值为 null，则返回 default |
| 安全导航 | `person?.name` | 如果 person 或她的姓名为 null，则返回 null |
| 模板化 | `'Your name is #{person.name}'` | 将值注入到字符串中 |
| 投影 | `${persons.![name]}` | 提取所有人的姓名并将它们放入列表中 |
| 选择 | `persons.?[name == 'Bob']'` | 从列表中检索姓名为 Bob 的人 |
| 函数调用 | `person.sayHello()` |   |

### 注意

有关完整参考，请查看[`docs.spring.io/spring/docs/current/spring-framework-reference/html/expressions.html`](http://docs.spring.io/spring/docs/current/spring-framework-reference/html/expressions.html)的手册。

SpEl 的用法不仅限于视图。您还可以在 Spring 框架内的各个地方使用它，例如，在使用`@Value`注解将属性注入到 bean 中时。

## 使用请求参数获取数据

我们能够在视图中显示来自服务器的数据。但是，如果我们想要从用户那里获取输入怎么办？使用 HTTP 协议，有多种方法可以做到这一点。最简单的方法是将查询参数传递给我们的 URL。

### 注意

**查询参数**

您肯定知道查询参数。它们在 URL 中的`?`字符之后找到。它们由名称和值的列表组成，由&符号（和号）分隔，例如，`page?var1=value1&var2=value2`。

我们可以利用这种技术来询问用户的姓名。让我们再次修改我们的`HelloController`类：

```java
@Controller
public class HelloController {

    @RequestMapping("/")
    public String hello(@RequestParam("name") String userName, Model model) {
        model.addAttribute("message", "Hello, " + userName);
        return "resultPage";
    }
}
```

如果我们导航到`localhost:8080/?name=Geoffroy`，我们可以看到以下内容：

![使用请求参数获取数据](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00932.jpeg)

默认情况下，请求参数是必需的。这意味着如果我们导航到`localhost:8080`，我们将看到错误消息。

查看`@RequestParam`代码，我们可以看到除了值参数之外，还有两个可能的属性：`required`和`defaultValue`。

因此，我们可以更改我们的代码，并为我们的参数指定默认值，或指示它不是必需的：

```java
@Controller
public class HelloController {

    @RequestMapping("/")
    public String hello(@RequestParam(defaultValue = "world") String name, Model model) {
        model.addAttribute("message", "Hello, " + name);
        return "resultPage";
    }
}
```

### 提示

在 Java 8 中，可以不指定值参数。在这种情况下，将使用带注释的方法参数的名称。

# 够了，Hello World，让我们获取推文！

好了，这本书的名字毕竟不是“精通 Hello Worlds”。使用 Spring，查询 Twitter 的 API 真的很容易。

## 注册您的应用程序

在开始之前，您必须在 Twitter 开发者控制台中注册您的应用程序。

转到[`apps.twitter.com`](https://apps.twitter.com)并创建一个新应用程序。

随便给它起个名字。在网站和回调 URL 部分，只需输入`http://127.0.0.1:8080`。这将允许您在本地开发环境中测试应用程序。

![注册您的应用程序](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00933.jpeg)

现在，转到密钥，访问令牌，并复制**Consumer Key**和**Consumer Secret**。我们马上会用到这个。看一下下面的屏幕截图：

![注册您的应用程序](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00934.jpeg)

默认情况下，我们的应用程序具有只读权限。这对我们的应用程序足够了，但如果您愿意，可以进行调整。

## 设置 Spring Social Twitter

我们将在我们的`build.gradle`文件中添加以下依赖项：

```java
compile 'org.springframework.boot:spring-boot-starter-social-twitter'
```

### 注意

**Spring Social**是一组项目，提供对各种社交网络的公共 API 的访问。Spring Boot 默认提供与 Twitter、Facebook 和 LinkedIn 的集成。Spring Social 总共包括约 30 个项目，可以在[`projects.spring.io/spring-social/`](http://projects.spring.io/spring-social/)找到。

将以下两行添加到`application.properties`中：

```java
spring.social.twitter.appId= <Consumer Key>
spring.social.twitter.appSecret= <Consumer Secret>
```

这些是与我们刚创建的应用程序相关联的密钥。

您将在第五章中了解有关 OAuth 的更多信息，*保护您的应用程序*。目前，我们将只使用这些凭据代表我们的应用程序向 Twitter 的 API 发出请求。

## 访问 Twitter

现在我们可以在我们的控制器中使用 Twitter。让我们将其名称更改为`TweetController`，以便更好地反映其新的责任：

```java
@Controller
public class HelloController {

    @Autowired
    private Twitter twitter;

    @RequestMapping("/")
    public String hello(@RequestParam(defaultValue = "masterSpringMVC4") String search, Model model) {
        SearchResults searchResults = twitter.searchOperations().search(search);
        String text = searchResults.getTweets().get(0).getText();
        model.addAttribute("message", text);
        return "resultPage";
    }
}
```

如您所见，该代码搜索与请求参数匹配的推文。如果一切顺利，您将在屏幕上看到第一条推文的文本被显示出来：

![访问 Twitter](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00935.jpeg)

当然，如果搜索没有结果，我们笨拙的代码将会出现`ArrayOutOfBoundException`错误。所以，不要犹豫，发推文来解决问题！

如果我们想要显示一系列推文怎么办？让我们修改`resultPage.html`文件：

```java
<!DOCTYPE html>
<html >
<head lang="en">
    <meta charset="UTF-8"/>
    <title>Hello twitter</title>
</head>
<body>
    <ul>
 <li th:each="tweet : ${tweets}" th:text="${tweet}">Some tweet</li>
 </ul>
</body>
</html>
```

### 注意

`th:each`是 Thymeleaf 中定义的一个标签，允许它遍历集合并将每个值分配给循环内的变量。

我们还需要更改我们的控制器：

```java
@Controller
public class TweetController {

    @Autowired
    private Twitter twitter;

    @RequestMapping("/")
    public String hello(@RequestParam(defaultValue = "masterSpringMVC4") String search, Model model) {
        SearchResults searchResults = twitter.searchOperations().search(search);
        List<String> tweets =
 searchResults.getTweets()
 .stream()
 .map(Tweet::getText)
 .collect(Collectors.toList());
 model.addAttribute("tweets", tweets);
        return "resultPage";
    }
}
```

请注意，我们正在使用 Java 8 流来仅收集推文中的消息。`Tweet`类包含许多其他属性，例如发送者、转发计数等。但是，目前我们将保持简单，如下面的屏幕截图所示：

![访问 Twitter](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00936.jpeg)

# Java 8 流和 lambda

你可能还不熟悉 lambda。在 Java 8 中，每个集合都有一个默认方法`stream()`，它可以访问函数式操作。

这些操作可以是返回流的中间操作，从而允许链接，也可以是返回值的终端操作。

最著名的中间操作如下：

+   `map`：这将对列表中的每个元素应用一个方法，并返回结果列表

+   `filter`：这返回与谓词匹配的每个元素的列表

+   `reduce`：这使用操作和累加器将列表投影到单个值

Lambda 是函数表达式的简写语法。它们可以被强制转换为 Single Abstract Method，即只有一个函数的接口。

例如，您可以按照以下方式实现`Comparator`接口：

```java
Comparator<Integer> c = (e1, e2) -> e1 - e2;
```

在 lambda 中，return 关键字隐式地是其最后的表达式。

我们之前使用的双冒号运算符是获取类上函数引用的快捷方式，

```java
Tweet::getText
```

上述等同于以下内容：

```java
(Tweet t) -> t.getText()
```

`collect`方法允许我们调用终端操作。`Collectors`类是一组终端操作，它将结果放入列表、集合或映射中，允许分组、连接等。

调用`collect(Collectors.toList())`方法将产生一个包含流中每个元素的列表；在我们的例子中，是推文名称。

# 使用 WebJars 的 Material 设计

我们的应用程序已经很棒了，但在美学方面确实还有些不足。您可能听说过 Material 设计。这是谷歌对扁平设计的看法。

我们将使用 Materialize ([`materializecss.com`](http://materializecss.com))，一个外观极佳的响应式 CSS 和 JavaScript 库，就像 Bootstrap 一样。

![使用 WebJars 的 Material 设计](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00937.jpeg)

我们现在将使用 WebJars。将 jQuery 和 Materialize CSS 添加到我们的依赖项中：

```java
compile 'org.webjars:materializecss:0.96.0'
compile 'org.webjars:jquery:2.1.4'
```

WebJar 的组织方式是完全标准化的。您将在`/webjars/{lib}/{version}/*.js`中找到任何库的 JS 和 CSS 文件。

例如，要将 jQuery 添加到我们的页面，可以在网页中添加以下内容：

```java
<script src="img/jquery.js"></script>
```

让我们修改我们的控制器，以便它给我们一个所有推文对象的列表，而不是简单的文本：

```java
package masterSpringMvc.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.social.twitter.api.SearchResults;
import org.springframework.social.twitter.api.Tweet;
import org.springframework.social.twitter.api.Twitter;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.List;

@Controller
public class TweetController {

    @Autowired
    private Twitter twitter;

    @RequestMapping("/")
    public String hello(@RequestParam(defaultValue = "masterSpringMVC4") String search, Model model) {
        SearchResults searchResults = twitter.searchOperations().search(search);
        List<Tweet> tweets = searchResults.getTweets();
        model.addAttribute("tweets", tweets);
        model.addAttribute("search", search);
        return "resultPage";
    }
}
```

让我们在视图中包含 materialize CSS：

```java
<!DOCTYPE html>
<html >
<head lang="en">
    <meta charset="UTF-8"/>
    <title>Hello twitter</title>

    <link href="/webjars/materializecss/0.96.0/css/materialize.css" type="text/css" rel="stylesheet" media="screen,projection"/>
</head>
<body>
<div class="row">

    <h2 class="indigo-text center" th:text="|Tweet results for ${search}|">Tweets</h2>

    <ul class="collection">
        <li class="collection-item avatar" th:each="tweet : ${tweets}">
            <img th:src="img/${tweet.user.profileImageUrl}" alt="" class="circle"/>
            <span class="title" th:text="${tweet.user.name}">Username</span>
            <p th:text="${tweet.text}">Tweet message</p>
        </li>
    </ul>

</div>

<script src="img/jquery.js"></script>
<script src="img/materialize.js"></script>
</body>
</html>
```

结果看起来已经好多了！

![使用 WebJars 的 Material 设计](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00938.jpeg)

## 使用布局

我们想要做的最后一件事是将我们的 UI 的可重用部分放入模板中。为此，我们将使用`thymeleaf-layout-dialect`依赖项，该依赖项包含在我们项目的`spring-boot-starter-thymeleaf`依赖项中。

我们将在`src/main/resources/templates/layout`中创建一个名为`default.html`的新文件。它将包含我们将从页面到页面重复的代码：

```java
<!DOCTYPE html>
<html 
      >
<head>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8"/>
    <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1.0, user-scalable=no"/>
    <title>Default title</title>

    <link href="/webjars/materializecss/0.96.0/css/materialize.css" type="text/css" rel="stylesheet" media="screen,projection"/>
</head>
<body>

<section layout:fragment="content">
    <p>Page content goes here</p>
</section>

<script src="img/jquery.js"></script>
<script src="img/materialize.js"></script>
</body>
</html>
```

我们现在将修改`resultPage.html`文件，使其使用布局，这将简化其内容：

```java
<!DOCTYPE html>
<html 

      layout:decorator="layout/default">
<head lang="en">
    <title>Hello twitter</title>
</head>
<body>
<div class="row" layout:fragment="content">

    <h2 class="indigo-text center" th:text="|Tweet results for ${search}|">Tweets</h2>

    <ul class="collection">
        <li class="collection-item avatar" th:each="tweet : ${tweets}">
            <img th:src="img/${tweet.user.profileImageUrl}" alt="" class="circle"/>
            <span class="title" th:text="${tweet.user.name}">Username</span>

            <p th:text="${tweet.text}">Tweet message</p>
        </li>
    </ul>
</div>
</body>
</html>
```

`layout:decorator="layout/default"`将指示我们的布局的位置。然后我们可以将内容注入到布局的不同`layout:fragment`部分中。请注意，每个模板都是有效的 HTML 文件。您也可以非常容易地覆盖标题。

## 导航

我们有一个很好的推文显示应用程序，但是我们的用户应该如何找出他们需要提供一个“搜索”请求参数呢？

如果我们为我们的应用程序添加一个小表单会很好。

让我们做一些类似这样的事情：

![导航](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00939.jpeg)

首先，我们需要修改我们的`TweetController`，以在我们的应用程序中添加第二个视图。搜索页面将直接在我们的应用程序的根目录下可用，当在`search`字段中按下回车时，结果页面将可用：

```java
@Controller
public class TweetController {

    @Autowired
    private Twitter twitter;

    @RequestMapping("/")
    public String home() {
        return "searchPage";
    }

    @RequestMapping("/result")
    public String hello(@RequestParam(defaultValue = "masterSpringMVC4") String search, Model model) {
        SearchResults searchResults = twitter.searchOperations().search(search);
        List<Tweet> tweets = searchResults.getTweets();
        model.addAttribute("tweets", tweets);
        model.addAttribute("search", search);
        return "resultPage";
    }
}
```

我们将在`templates`文件夹中添加另一个页面，名为`searchPage.html`文件。它将包含一个简单的表单，通过`get`方法将搜索词传递到结果页面：

```java
<!DOCTYPE html>
<html 

      layout:decorator="layout/default">
<head lang="en">
    <title>Search</title>
</head>
<body>

<div class="row" layout:fragment="content">

    <h4 class="indigo-text center">Please enter a search term</h4>

    <form action="/result" method="get" class="col s12">
        <div class="row center">
            <div class="input-field col s6 offset-s3">
                <i class="mdi-action-search prefix"></i>
                <input id="search" name="search" type="text" class="validate"/>
                <label for="search">Search</label>
            </div>
        </div>
    </form>
</div>

</body>
</html>
```

这是非常简单的 HTML，它完美地工作。您现在可以尝试一下。

如果我们想要禁止某些搜索结果怎么办？假设我们想要在用户输入`struts`时显示错误消息。

实现这一点的最佳方法是修改表单以发布数据。在控制器中，我们可以拦截所发布的内容，并相应地实现这个业务规则。

首先，我们需要更改`searchPage`中的表单，如下所示：

```java
<form action="/result" method="get" class="col s12">
```

现在，我们将表单更改为：

```java
<form action="/postSearch" method="post" class="col s12">
```

我们还需要在服务器上处理这个发布。将这个方法添加到`TweetController`中：

```java
@RequestMapping(value = "/postSearch", method = RequestMethod.POST)
public String postSearch(HttpServletRequest request,
    RedirectAttributes redirectAttributes) {
        String search = request.getParameter("search");
        redirectAttributes.addAttribute("search", search);
        return "redirect:result";
}
```

这里有几个新奇之处：

+   在请求映射注解中，我们指定了要处理的 HTTP 方法，即`POST`。

+   我们直接将两个属性作为方法参数注入。它们是请求和`RedirectAttributes`。

+   我们检索请求上发布的值，并将其传递给下一个视图。

+   我们不再返回视图的名称，而是重定向到一个 URL。

`RedirectAttributes`是一个 Spring 模型，将专门用于在重定向场景中传播值。

### 注意

**重定向/转发**是 Java Web 应用程序上下文中的经典选项。它们都会改变用户浏览器上显示的视图。不同之处在于`Redirect`将发送一个触发浏览器内导航的 302 标头，而`Forward`不会导致 URL 更改。在 Spring MVC 中，您可以通过简单地在方法返回字符串前加上`redirect:`或`forward:`来使用任一选项。在这两种情况下，您返回的字符串不会像我们之前看到的那样解析为视图，而是会触发导航到特定的 URL。

前面的例子有点牵强，我们将在下一章中看到更智能的表单处理。如果您在`postSearch`方法中设置断点，您将看到它将在我们的表单发布后立即被调用。

那么错误消息呢？

让我们修改`postSearch`方法：

```java
@RequestMapping(value = "/postSearch", method = RequestMethod.POST)
public String postSearch(HttpServletRequest request,
    RedirectAttributes redirectAttributes) {
        String search = request.getParameter("search");
        if (search.toLowerCase().contains("struts")) {
                redirectAttributes.addFlashAttribute("error", "Try using spring instead!");
                return "redirect:/";
        }
        redirectAttributes.addAttribute("search", search);
        return "redirect:result";
}
```

如果用户的搜索词包含"struts"，我们将重定向他们到`searchPage`并使用 flash 属性添加一条小错误消息。

这些特殊类型的属性仅在请求的时间内存在，并且在刷新页面时会消失。当我们使用`POST-REDIRECT-GET`模式时，这是非常有用的，就像我们刚才做的那样。

我们需要在`searchPage`结果中显示这条消息：

```java
<!DOCTYPE html>
<html 

      layout:decorator="layout/default">
<head lang="en">
    <title>Search</title>
</head>
<body>

<div class="row" layout:fragment="content">

    <h4 class="indigo-text center">Please enter a search term</h4>

 <div class="col s6 offset-s3">
 <div id="errorMessage" class="card-panel red lighten-2" th:if="${error}">
 <span class="card-title" th:text="${error}"></span>
 </div>

        <form action="/postSearch" method="post" class="col s12">
            <div class="row center">
                <div class="input-field">
                    <i class="mdi-action-search prefix"></i>
                    <input id="search" name="search" type="text" class="validate"/>
                    <label for="search">Search</label>
                </div>
            </div>
        </form>
    </div>
</div>

</body>
</html>
```

现在，如果用户尝试搜索"struts2"的推文，他们将得到一个有用且合适的答案：

![导航](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00940.jpeg)

# 检查点

在本章结束时，您应该有一个控制器，`TweetController`，处理搜索和未经修改的生成配置类`MasterSpringMvcApplication`，在`src/main/java`目录中：

![检查点](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00941.jpeg)

在`src/main/resources`目录中，您应该有一个默认布局和两个使用它的页面。

在`application.properties`文件中，我们添加了 Twitter 应用程序凭据，以及一个属性告诉 Spring 不要缓存模板以便开发：

![检查点](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00942.jpeg)

# 摘要

在本章中，您了解了构建良好的 MVC 架构需要什么。我们看到了 Spring MVC 的一些内部工作原理，并且使用了 Spring Social Twitter，几乎没有配置。现在，我们可以设计一个美丽的 Web 应用程序，这要归功于 WebJars。

在下一章中，我们将要求用户填写他们的个人资料，以便我们可以自动获取他们可能喜欢的推文。这将让您有机会了解更多关于表单、格式化、验证和国际化的知识。



# 第十八章：处理表单和复杂的 URL 映射

我们的应用程序，尽管看起来很漂亮，但会受益于更多关于我们用户的信息。

我们可以要求他们提供他们感兴趣的主题。

在本章中，我们将构建一个个人资料页面。它将具有服务器端和客户端验证以及用于个人资料图片上传的文件上传。我们将保存该信息在用户会话中，并通过将应用程序翻译成多种语言来确保我们的受众尽可能广泛。最后，我们将显示与用户口味匹配的 Twitter 活动摘要。

听起来不错吧？让我们开始吧，我们有一些工作要做。

# 个人资料页面 - 一个表单

表单是每个 Web 应用程序的基石。自互联网诞生以来，它们一直是获取用户输入的主要方式！

我们在这里的第一个任务是创建一个像这样的个人资料页面：

![个人资料页面 - 一个表单](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00943.jpeg)

它将允许用户输入一些个人信息以及一系列口味。然后，这些口味将被提供给我们的搜索引擎。

让我们在`templates/profile/profilePage.html`中创建一个新页面：

```java
<!DOCTYPE html>
<html 

      layout:decorator="layout/default">
<head lang="en">
    <title>Your profile</title>
</head>
<body>
<div class="row" layout:fragment="content">

    <h2 class="indigo-text center">Personal info</h2>

    <form th:action="@{/profile}" method="post" class="col m8 s12 offset-m2">

        <div class="row">
            <div class="input-field col s6">
                <input id="twitterHandle" type="text"/>
                <label for="twitterHandle">Last Name</label>
            </div>
            <div class="input-field col s6">
                <input id="email" type="text"/>
                <label for="email">Email</label>
            </div>
        </div>
        <div class="row">
            <div class="input-field col s6">
                <input id="birthDate" type="text"/>
                <label for="birthDate">Birth Date</label>
            </div>
        </div>
        <div class="row s12">
            <button class="btn waves-effect waves-light" type="submit" name="save">Submit
                <i class="mdi-content-send right"></i>
            </button>
        </div>
    </form>
</div>
</body>
</html>
```

请注意`@{}`语法，它将通过将服务器上下文路径（在我们的情况下为`localhost:8080`）前置到其参数来构造资源的完整路径。

我们还将在`profile`包中创建名为`ProfileController`的相关控制器：

```java
package masterspringmvc4.profile;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class ProfileController {

    @RequestMapping("/profile")
    public String displayProfile() {
        return "profile/profilePage";
    }
}
```

现在，您可以转到`http://localhost:8080`，看到一个漂亮的表单，什么也不做。这是因为我们没有将任何操作映射到 post URL。

让我们在与我们的控制器相同的包中创建一个**数据传输对象**（**DTO**）。我们将其命名为`ProfileForm`。它的作用将是映射我们的 Web 表单字段并描述验证规则：

```java
package masterSpringMvc.profile;

import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;

public class ProfileForm {
    private String twitterHandle;
    private String email;
    private LocalDate birthDate;
    private List<String> tastes = new ArrayList<>();

    // getters and setters
}
```

这是一个常规的**普通旧 Java 对象**（**POJO**）。不要忘记生成 getter 和 setter，否则我们的数据绑定将无法正常工作。请注意，我们有一个口味列表，我们现在不会填充，稍后再填充。

由于我们使用的是 Java 8，我们的用户的出生日期将使用新的 Java 日期时间 API（JSR 310）。这个 API 比旧的`java.util.Date` API 要好得多，因为它在人类日期的所有细微差别之间做出了明确的区分，并使用了流畅的 API 和不可变的数据结构。

在我们的示例中，`LocalDate`类是一个简单的没有与之关联的时间的日期。它可以与`LocalTime`类区分开，后者表示一天内的时间，`LocalDateTime`类表示两者，或者`ZonedDateTime`类使用时区。

### 注意

如果您想了解更多关于 Java 8 日期时间 API 的信息，请参考 Oracle 教程，网址为[`docs.oracle.com/javase/tutorial/datetime/TOC.html`](https://docs.oracle.com/javase/tutorial/datetime/TOC.html)。

### 提示

一个好的建议是始终生成我们的数据对象的`toString`方法，就像这个表单一样。这对于调试非常有用。

为了指示 Spring 将我们的字段绑定到此 DTO，我们必须在`profilePage`中添加一些元数据：

```java
<!DOCTYPE html>
<html 

      layout:decorator="layout/default">
<head lang="en">
    <title>Your profile</title>
</head>
<body>
<div class="row" layout:fragment="content">

    <h2 class="indigo-text center">Personal info</h2>

    <form th:action="@{/profile}" th:object="${profileForm}" method="post" class="col m8 s12 offset-m2">

        <div class="row">
            <div class="input-field col s6">
                <input th:field="${profileForm.twitterHandle}" id="twitterHandle" type="text"/>
                <label for="twitterHandle">Last Name</label>
            </div>
            <div class="input-field col s6">
                <input th:field="${profileForm.email}" id="email" type="text"/>
                <label for="email">Email</label>
            </div>
        </div>
        <div class="row">
            <div class="input-field col s6">
                <input th:field="${profileForm.birthDate}" id="birthDate" type="text"/>
                <label for="birthDate">Birth Date</label>
            </div>
        </div>
        <div class="row s12">
            <button class="btn waves-effect waves-light" type="submit" name="save">Submit
                <i class="mdi-content-send right"></i>
            </button>
        </div>
    </form>
</div>
</body>
</html>
```

您会注意到两件事：

+   表单中的`th:object`属性

+   所有字段中的`th:field`属性

第一个将通过其类型将对象绑定到控制器。第二个将将实际字段绑定到我们的表单 bean 属性。

为了使`th:object`字段起作用，我们需要在我们的请求映射方法中添加一个`ProfileForm`类型的参数：

```java
@Controller
public class ProfileController {

    @RequestMapping("/profile")
    public String displayProfile(ProfileForm profileForm) {
        return "profile/profilePage";
    }

    @RequestMapping(value = "/profile", method = RequestMethod.POST)
    public String saveProfile(ProfileForm profileForm) {
        System.out.println("save ok" + profileForm);
        return "redirect:/profile";
    }
}
```

我们还添加了一个`POST`方法的映射，当表单提交时将被调用。此时，如果您尝试使用日期（例如 1980 年 10 月 10 日）提交表单，它将完全不起作用，并且会给您一个 400 错误和没有有用的日志信息。

### 提示

**Spring Boot 中的日志记录**

使用 Spring Boot，日志配置非常简单。只需在`application.properties`文件中添加`logging.level.{package} = DEBUG`，其中`{package}`是应用程序中一个类或包的完全限定名称。当然，您可以将 debug 替换为任何您想要的日志级别。您还可以添加经典的日志配置。有关更多信息，请参阅[`docs.spring.io/spring-boot/docs/current/reference/html/howto-logging.html`](http://docs.spring.io/spring-boot/docs/current/reference/html/howto-logging.html)。

我们需要稍微调试我们的应用程序以了解发生了什么。将此行添加到您的文件`application.properties`中：

```java
logging.level.org.springframework.web=DEBUG
```

`org.springframework.web`包是 Spring MVC 的基本包。这将允许我们查看 Spring web 生成的调试信息。如果您再次提交表单，您将在日志中看到以下错误：

```java
Field error in object 'profileForm' on field 'birthDate': rejected value [10/10/1980]; codes [typeMismatch.profileForm.birthDate,typeMismatch.birthDate,typeMismatch.java.time.LocalDate,typeMismatch]; … nested exception is org.springframework.core.convert.ConversionFailedException: Failed to convert from type java.lang.String to type java.time.LocalDate for value '10/10/1980'; nested exception is java.time.format.DateTimeParseException: Text '10/10/1980' could not be parsed, unparsed text found at index 8]
```

为了了解发生了什么，我们需要查看 Spring 的`DateTimeFormatterRegistrar`类。

在这个类中，您将看到半打 JSR 310 的解析器和打印机。它们都将回退到短格式日期格式，如果您住在美国，则为`MM/dd/yy`，否则为`dd/MM/yy`。

这将指示 Spring Boot 在我们的应用程序启动时创建一个`DateFormatter`类。

在我们的情况下，我们需要做同样的事情，并创建我们自己的格式化程序，因为用两位数写年份有点奇怪。

Spring 中的`Formatter`是一个可以同时`print`和`parse`对象的类。它将用于解码和打印值从和到字符串。

我们将在`date`包中创建一个非常简单的格式化程序，名为`USLocalDateFormatter`：

```java
public class USLocalDateFormatter implements Formatter<LocalDate> {
    public static final String US_PATTERN = "MM/dd/yyyy";
    public static final String NORMAL_PATTERN = "dd/MM/yyyy";

    @Override public LocalDate parse(String text, Locale locale) throws ParseException {
        return LocalDate.parse(text, DateTimeFormatter.ofPattern(getPattern(locale)));
    }

    @Override public String print(LocalDate object, Locale locale) {
        return DateTimeFormatter.ofPattern(getPattern(locale)).format(object);
    }

    public static String getPattern(Locale locale) {
        return isUnitedStates(locale) ? US_PATTERN : NORMAL_PATTERN;
    }

    private static boolean isUnitedStates(Locale locale) {
        return Locale.US.getCountry().equals(locale.getCountry());
    }
}
```

这个小类将允许我们以更常见的格式（年份为四位数）解析日期，根据用户的语言环境。

让我们在`config`包中创建一个名为`WebConfiguration`的新类：

```java
package masterSpringMvc.config;

import masterSpringMvc.dates.USLocalDateFormatter;
import org.springframework.context.annotation.Configuration;
import org.springframework.format.FormatterRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;

import java.time.LocalDate;

@Configuration
public class WebConfiguration extends WebMvcConfigurerAdapter {

    @Override public void addFormatters(FormatterRegistry registry) {
        registry.addFormatterForFieldType(LocalDate.class, new USLocalDateFormatter());
    }
}
```

这个类扩展了`WebMvcConfigurerAdapter`，这是一个非常方便的类，可以自定义 Spring MVC 配置。它提供了许多常见的扩展点，您可以通过覆盖方法来访问，比如`addFormatters()`方法。

这一次，提交我们的表单不会导致任何错误，除非您没有使用正确的日期格式输入日期。

目前，用户无法看到他们应该输入出生日期的格式，所以让我们将这些信息添加到表单中。

在`ProfileController`中，让我们添加一个`dateFormat`属性：

```java
@ModelAttribute("dateFormat")
public String localeFormat(Locale locale) {
    return USLocalDateFormatter.getPattern(locale);
}
```

`@ModelAttribute`注释将允许我们将属性暴露给网页，就像我们在上一章中看到的`model.addAttribute()`方法一样。

现在，我们可以通过为我们的日期字段添加占位符来在我们的页面中使用这些信息：

```java
<div class="row">
    <div class="input-field col s6">
        <input th:field="${profileForm.birthDate}" id="birthDate" type="text" th:placeholder="${dateFormat}"/>
        <label for="birthDate">Birth Date</label>
    </div>
</div>
```

这些信息现在将显示给用户：

![个人资料页面-表单](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00944.jpeg)

# 验证

我们不希望用户输入无效或空信息，这就是为什么我们需要向我们的`ProfileForm`添加一些验证逻辑。

```java
package masterspringmvc4.profile;

import org.hibernate.validator.constraints.Email;
import org.hibernate.validator.constraints.NotEmpty;

import javax.validation.constraints.NotNull;
import javax.validation.constraints.Past;
import javax.validation.constraints.Size;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class ProfileForm {
    @Size(min = 2)
    private String twitterHandle;

    @Email
    @NotEmpty
    private String email;

   @NotNull
    private Date birthDate;

    @NotEmpty
    private List<String> tastes = new ArrayList<>();
}
```

如您所见，我们添加了一些验证约束。这些注释来自 JSR-303 规范，该规范指定了 bean 验证。这个规范最流行的实现是`hibernate-validator`，它包含在 Spring Boot 中。

您可以看到，我们使用来自`javax.validation.constraints`包（在 API 中定义）的注释和一些来自`org.hibernate.validator.constraints`包（附加约束）的注释。两者都有效，我鼓励您查看这些包中在`validation-api`和`hibernate-validator`中可用的内容。

您还可以在[`docs.jboss.org/hibernate/stable/validator/reference/en-US/html_single/#section-builtin-constraints`](http://docs.jboss.org/hibernate/stable/validator/reference/en-US/html_single/#section-builtin-constraints)的文档中查看 hibernate 验证器中可用的约束。

我们需要添加一些其他内容才能使验证工作。首先，控制器需要声明它希望在表单提交时获得一个有效的模型。通过向表示表单的参数添加`javax.validation.Valid`注释来实现这一点：

```java
@RequestMapping(value = "/profile", method = RequestMethod.POST)
public String saveProfile(@Valid ProfileForm profileForm, BindingResult bindingResult) {
    if (bindingResult.hasErrors()) {
        return "profile/profilePage";
    }

    System.out.println("save ok" + profileForm);
    return "redirect:/profile";
}
```

请注意，如果表单包含任何错误，我们不会重定向用户。这将允许我们在同一网页上显示它们。

说到这一点，我们需要在网页上添加一个地方来显示这些错误。

在`profilePage.html`的表单标签的开头添加以下行：

```java
<ul th:if="${#fields.hasErrors('*')}" class="errorlist">
    <li th:each="err : ${#fields.errors('*')}" th:text="${err}">Input is incorrect</li>
</ul>
```

这将遍历表单中发现的每个错误，并在列表中显示它们。如果您尝试提交空表单，您将看到一堆错误：

![验证](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00945.jpeg)

请注意，对于口味的`@NotEmpty`检查将阻止表单被提交。事实上，我们还没有提供一种方法来提供它们。

## 自定义验证消息

这些错误消息对我们的用户来说还不是很有用。我们需要做的第一件事是将它们正确地与它们各自的字段关联起来。让我们修改`profilePage.html`：

```java
<!DOCTYPE html>
<html 

      layout:decorator="layout/default">
<head lang="en">
    <title>Your Profile</title>
</head>
<body>
<div class="row" layout:fragment="content">

    <h2 class="indigo-text center">Personal info</h2>

    <form th:action="@{/profile}" th:object="${profileForm}" method="post" class="col m8 s12 offset-m2">

        <div class="row">
            <div class="input-field col s6">
                <input th:field="${profileForm.twitterHandle}" id="twitterHandle" type="text" th:errorclass="invalid"/>
                <label for="twitterHandle">Twitter handle</label>

                <div th:errors="*{twitterHandle}" class="red-text">Error</div>
            </div>
            <div class="input-field col s6">
                <input th:field="${profileForm.email}" id="email" type="text" th:errorclass="invalid"/>
                <label for="email">Email</label>

                <div th:errors="*{email}" class="red-text">Error</div>
            </div>
        </div>
        <div class="row">
            <div class="input-field col s6">
                <input th:field="${profileForm.birthDate}" id="birthDate" type="text" th:errorclass="invalid" th:placeholder="${dateFormat}"/>
                <label for="birthDate">Birth Date</label>

                <div th:errors="*{birthDate}" class="red-text">Error</div>
            </div>
        </div>
        <div class="row s12">
            <button class="btn indigo waves-effect waves-light" type="submit" name="save">Submit
                <i class="mdi-content-send right"></i>
            </button>
        </div>
    </form>
</div>
</body>
</html>
```

您会注意到我们在表单中的每个字段下面添加了一个`th:errors`标签。我们还为每个字段添加了一个`th:errorclass`标签。如果字段包含错误，则相关的 css 类将添加到 DOM 中。

验证看起来已经好多了：

自定义验证消息

我们需要做的下一件事是自定义错误消息，以更好地反映我们应用程序的业务规则。

记住，Spring Boot 会为我们创建一个消息源 bean？这个消息源的默认位置在`src/main/resources/messages.properties`中。

让我们创建这样一个包，并添加以下文本：

```java
Size.profileForm.twitterHandle=Please type in your twitter user name
Email.profileForm.email=Please specify a valid email address
NotEmpty.profileForm.email=Please specify your email address
PastLocalDate.profileForm.birthDate=Please specify a real birth date
NotNull.profileForm.birthDate=Please specify your birth date

typeMismatch.birthDate = Invalid birth date format.
```

### 提示

在开发中，将消息源配置为始终重新加载我们的包可能非常方便。在`application.properties`中添加以下属性：

`spring.messages.cache-seconds=0`

0 表示始终重新加载，而-1 表示永不重新加载。

在 Spring 中负责解析错误消息的类是`DefaultMessageCodesResolver`。在字段验证的情况下，该类尝试按照给定的顺序解析以下消息：

+   代码+“。”+对象名称+“。”+字段

+   代码+“。”+字段

+   代码+“。”+字段类型

+   代码

在前面的规则中，代码部分可以是两种情况：注释类型，如`Size`或`Email`，或异常代码，如`typeMismatch`。还记得我们因日期格式不正确而引发异常吗？相关的错误代码确实是`typeMismatch`。

在前面的消息中，我们选择了非常具体的方式。一个好的做法是定义默认消息如下：

```java
Size=the {0} field must be between {2} and {1} characters long
typeMismatch.java.util.Date = Invalid date format.
```

注意占位符；每个验证错误都有与之关联的一些参数。

声明错误消息的最后一种方式将涉及直接在验证注释中定义错误消息，如下所示：

```java
@Size(min = 2, message = "Please specify a valid twitter handle")
private String twitterHandle;
```

然而，这种方法的缺点是它与国际化不兼容。

## 自定义验证的自定义注释

对于 Java 日期，有一个名为`@Past`的注释，它确保日期是过去的日期。

我们不希望我们的用户假装他们来自未来，所以我们需要验证出生日期。为此，我们将在`date`包中定义我们自己的注释：

```java
package masterSpringMvc.date;

import javax.validation.Constraint;
import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;
import javax.validation.Payload;
import java.lang.annotation.*;
import java.time.LocalDate;

@Target({ElementType.FIELD})
@Retention(RetentionPolicy.RUNTIME)
@Constraint(validatedBy = PastLocalDate.PastValidator.class)
@Documented
public @interface PastLocalDate {
    String message() default "{javax.validation.constraints.Past.message}";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};

    class PastValidator implements ConstraintValidator<PastLocalDate, LocalDate> {
        public void initialize(PastLocalDate past) {
        }

        public boolean isValid(LocalDate localDate, ConstraintValidatorContext context) {
            return localDate == null || localDate.isBefore(LocalDate.now());
        }
    }
}
```

简单吧？这段代码将验证我们的日期确实是过去的日期。

现在我们可以将其添加到个人资料表单中的`birthDate`字段中：

```java
@NotNull
@PastLocalDate
private LocalDate birthDate;
```

# 国际化

国际化，通常缩写为 i18n，是设计可以翻译成各种语言的应用程序的过程。

通常，这涉及将翻译放在名称后缀为目标区域设置的属性包中，例如，`messages_en.properties`，`messages_en_US.properties`和`messages_fr.properties`文件。

正确的属性包是通过首先尝试最具体的区域设置，然后回退到不太具体的区域设置来解析的。

对于美国英语，如果尝试从名为`x`的包中获取翻译，应用程序首先会查找`x_en_US.properties`文件，然后是`x_en.properties`文件，最后是`x.properties`文件。

我们要做的第一件事是将我们的错误消息翻译成法语。为此，我们将现有的`messages.properties`文件重命名为`messages_en.properties`。

我们还将创建一个名为`messages_fr.properties`的第二个包：

```java
Size.profileForm.twitterHandle=Veuillez entrer votre identifiant Twitter
Email.profileForm.email=Veuillez spécifier une adresse mail valide
NotEmpty.profileForm.email=Veuillez spécifier votre adresse mail
PastLocalDate.profileForm.birthDate=Veuillez donner votre vraie date de naissance
NotNull.profileForm.birthDate=Veuillez spécifier votre date de naissance

typeMismatch.birthDate = Date de naissance invalide.
```

默认情况下，Spring Boot 使用固定的`LocaleResolver`接口。`LocaleResolver`是一个简单的接口，有两个方法：

```java
public interface LocaleResolver {

    Locale resolveLocale(HttpServletRequest request);

    void setLocale(HttpServletRequest request, HttpServletResponse response, Locale locale);
}
```

Spring 提供了一堆这个接口的实现，比如`FixedLocaleResolver`。这个本地解析器非常简单；我们可以通过属性配置应用程序的区域设置，一旦定义就无法更改。要配置我们应用程序的区域设置，让我们在`application.properties`文件中添加以下属性：

```java
spring.mvc.locale=fr
```

这将在法语中添加我们的验证消息。

如果我们看一下 Spring MVC 中捆绑的不同`LocaleResolver`接口，我们会看到以下内容：

+   `FixedLocaleResolver`：这会固定在配置中定义的区域设置。一旦固定，就无法更改。

+   `CookieLocaleResolver`：这允许从 cookie 中检索和保存区域设置。

+   `AcceptHeaderLocaleResolver`：这使用用户浏览器发送的 HTTP 标头来查找区域设置。

+   `SessionLocaleResolver`：这在 HTTP 会话中查找并存储区域设置。

这些实现涵盖了许多用例，但在更复杂的应用程序中，可以直接实现`LocaleResolver`以允许更复杂的逻辑，例如从数据库获取区域设置并回退到浏览器区域设置。

## 更改区域设置

在我们的应用程序中，区域设置与用户相关联。我们将在会话中保存他们的个人资料。

我们将允许用户使用一个小菜单更改站点的语言。这就是为什么我们将使用`SessionLocaleResolver`。让我们再次编辑`WebConfiguration`：

```java
package masterSpringMvc.config;

import masterSpringMvc.date.USLocalDateFormatter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.format.FormatterRegistry;
import org.springframework.web.servlet.LocaleResolver;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;
import org.springframework.web.servlet.i18n.LocaleChangeInterceptor;
import org.springframework.web.servlet.i18n.SessionLocaleResolver;

import java.time.LocalDate;

@Configuration
public class WebConfiguration extends WebMvcConfigurerAdapter {

    @Override
    public void addFormatters(FormatterRegistry registry) {
        registry.addFormatterForFieldType(LocalDate.class, new USLocalDateFormatter());
    }

    @Bean
    public LocaleResolver localeResolver() {
        return new SessionLocaleResolver();
    }

    @Bean
    public LocaleChangeInterceptor localeChangeInterceptor() {
        LocaleChangeInterceptor localeChangeInterceptor = new LocaleChangeInterceptor();
        localeChangeInterceptor.setParamName("lang");
        return localeChangeInterceptor;
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(localeChangeInterceptor());
    }
}
```

我们声明了一个`LocaleChangeInterceptor` bean 作为 Spring MVC 拦截器。它将拦截对`Controller`的任何请求，并检查`lang`查询参数。例如，导航到`http://localhost:8080/profile?lang=fr`将导致区域设置更改。

### 提示

**Spring MVC 拦截器**可以与 Web 应用程序中的 Servlet 过滤器进行比较。拦截器允许自定义预处理，跳过处理程序的执行以及自定义后处理。过滤器更强大，例如，它们允许交换传递给链的请求和响应对象。过滤器在`web.xml`文件中配置，而拦截器在应用程序上下文中声明为 bean。

现在，我们可以通过输入正确的 URL 来更改区域设置，但最好是添加一个导航栏，允许用户更改语言。我们将修改默认布局（`templates/layout/default.html`）以添加一个下拉菜单：

```java
<!DOCTYPE html>
<html 
      >
<head>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8"/>
    <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1.0, user-scalable=no"/>
    <title>Default title</title>

    <link href="/webjars/materializecss/0.96.0/css/materialize.css" type="text/css" rel="stylesheet" media="screen,projection"/>
</head>
<body>

<ul id="lang-dropdown" class="dropdown-content">
    <li><a href="?lang=en_US">English</a></li>
    <li><a href="?lang=fr">French</a></li>
</ul>
<nav>
    <div class="nav-wrapper indigo">
        <ul class="right">
            <li><a class="dropdown-button" href="#!" data-activates="lang-dropdown"><i class="mdi-action-language right"></i> Lang</a></li>
        </ul>
    </div>
</nav>

<section layout:fragment="content">
    <p>Page content goes here</p>
</section>

<script src="img/jquery.js"></script>
<script src="img/materialize.js"></script>
<script type="text/javascript">
    $(".dropdown-button").dropdown();
</script>
</body>
</html>
```

这将允许用户在两种支持的语言之间进行选择。

![更改区域设置](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00947.jpeg)

## 翻译应用程序文本

为了使我们的应用程序完全支持双语，我们需要做的最后一件事是翻译应用程序的标题和标签。为此，我们将编辑我们的网页并使用`th:text`属性，例如在`profilePage.html`中：

```java
<!DOCTYPE html>
<html 

      layout:decorator="layout/default">
<head lang="en">
    <title>Your profile</title>
</head>
<body>
<div class="row" layout:fragment="content">

    <h2 class="indigo-text center" th:text="#{profile.title}">Personal info</h2>

    <form th:action="@{/profile}" th:object="${profileForm}" method="post" class="col m8 s12 offset-m2">

        <div class="row">
            <div class="input-field col s6">
                <input th:field="${profileForm.twitterHandle}" id="twitterHandle" type="text" th:errorclass="invalid"/>
                <label for="twitterHandle" th:text="#{twitter.handle}">Twitter handle</label>

                <div th:errors="*{twitterHandle}" class="red-text">Error</div>
            </div>
            <div class="input-field col s6">
                <input th:field="${profileForm.email}" id="email" type="text" th:errorclass="invalid"/>
                <label for="email" th:text="#{email}">Email</label>

                <div th:errors="*{email}" class="red-text">Error</div>
            </div>
        </div>
        <div class="row">
            <div class="input-field col s6">
                <input th:field="${profileForm.birthDate}" id="birthDate" type="text" th:errorclass="invalid"/>
                <label for="birthDate" th:text="#{birthdate}" th:placeholder="${dateFormat}">Birth Date</label>

                <div th:errors="*{birthDate}" class="red-text">Error</div>
            </div>
        </div>
        <div class="row s12 center">
            <button class="btn indigo waves-effect waves-light" type="submit" name="save" th:text="#{submit}">Submit
                <i class="mdi-content-send right"></i>
            </button>
        </div>
    </form>
</div>
</body>
</html>
```

`th:text`属性将使用表达式替换 HTML 元素的内容。在这里，我们使用`#{}`语法，表示我们要显示来自属性源（如`messages.properties`）的消息。

让我们向我们的英语包中添加相应的翻译：

```java
NotEmpty.profileForm.tastes=Please enter at least one thing
profile.title=Your profile
twitter.handle=Twitter handle
email=Email
birthdate=Birth Date
tastes.legend=What do you like?
remove=Remove
taste.placeholder=Enter a keyword
add.taste=Add taste
submit=Submit
```

现在是法语的：

```java
NotEmpty.profileForm.tastes=Veuillez saisir au moins une chose
profile.title=Votre profil
twitter.handle=Pseudo twitter
email=Email
birthdate=Date de naissance
tastes.legend=Quels sont vos goûts ?
remove=Supprimer
taste.placeholder=Entrez un mot-clé
add.taste=Ajouter un centre d'intérêt
submit=Envoyer
```

一些翻译尚未使用，但很快就会用到。Et voilà！法国市场已经准备好迎接 Twitter 搜索风暴。

## 表单中的列表

现在，我们希望用户输入一个“品味”列表，实际上是一个我们将用于搜索推文的关键字列表。

将显示一个按钮，允许用户输入新关键字并将其添加到列表中。该列表的每个项目将是可编辑的输入文本，并且可以通过删除按钮进行删除：

![表单中的列表](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00948.jpeg)

在表单中处理列表数据可能是一项繁琐的工作，但是使用 Spring MVC 和 Thymeleaf 相对来说比较简单，只要你理解了原则。

在`profilePage.html`文件中添加以下行，就在包含出生日期的行下方，正好在提交按钮上方：

```java
<fieldset class="row">
    <legend th:text="#{tastes.legend}">What do you like?</legend>
    <button class="btn teal" type="submit" name="addTaste" th:text="#{add.taste}">Add taste
        <i class="mdi-content-add left"></i>
    </button>

    <div th:errors="*{tastes}" class="red-text">Error</div>

    <div class="row" th:each="row,rowStat : *{tastes}">
        <div class="col s6">
            <input type="text" th:field="*{tastes[__${rowStat.index}__]}" th:placeholder="#{taste.placeholder}"/>
        </div>

        <div class="col s6">
            <button class="btn red" type="submit" name="removeTaste" th:value="${rowStat.index}" th:text="#{remove}">Remove
                <i class="mdi-action-delete right waves-effect"></i>
            </button>
        </div>
    </div>
</fieldset>
```

此片段的目的是对我们的`LoginForm`的`tastes`变量进行迭代。这可以通过`th:each`属性实现，它看起来很像 Java 中的`for…in`循环。

与我们之前看到的搜索结果循环相比，迭代存储在两个变量中而不是一个。第一个变量实际上将包含数据的每一行。`rowStat`变量将包含有关迭代当前状态的附加信息。

新代码片段中最奇怪的事情是：

```java
th:field="*{tastes[__${rowStat.index}__]}"
```

这是一个相当复杂的语法。你可以自己想出一些更简单的东西，比如：

```java
th:field="*{tastes[rowStat.index]}"
```

好吧，那行不通。`${rowStat.index}`变量代表迭代循环的当前索引，需要在表达式的其余部分之前进行评估。为了实现这一点，我们需要使用预处理。

双下划线包围的表达式将被预处理，这意味着它将在正常处理阶段之前进行处理，允许它被评估两次。

现在我们的表单上有两个新的提交按钮。它们都有一个名称。我们之前有的全局提交按钮称为`save`。两个新按钮分别称为`addTaste`和`removeTaste`。

在控制器端，这将使我们能够轻松区分来自我们表单的不同操作。让我们在`ProfileController`中添加两个新的操作：

```java
@Controller
public class ProfileController {

    @ModelAttribute("dateFormat")
    public String localeFormat(Locale locale) {
        return USLocalDateFormatter.getPattern(locale);
    }

    @RequestMapping("/profile")
    public String displayProfile(ProfileForm profileForm) {
        return "profile/profilePage";
    }

    @RequestMapping(value = "/profile", params = {"save"}, method = RequestMethod.POST)
    public String saveProfile(@Valid ProfileForm profileForm, BindingResult bindingResult) {
        if (bindingResult.hasErrors()) {
            return "profile/profilePage";
        }
        System.out.println("save ok" + profileForm);
        return "redirect:/profile";
    }

    @RequestMapping(value = "/profile", params = {"addTaste"})
    public String addRow(ProfileForm profileForm) {
        profileForm.getTastes().add(null);
        return "profile/profilePage";
    }

    @RequestMapping(value = "/profile", params = {"removeTaste"})
    public String removeRow(ProfileForm profileForm, HttpServletRequest req) {
        Integer rowId = Integer.valueOf(req.getParameter("removeTaste"));
        profileForm.getTastes().remove(rowId.intValue());
        return "profile/profilePage";
    }
}
```

我们为每个提交操作添加了一个`param`参数以加以区分。我们之前使用的那个现在绑定到`save`参数。

当我们单击按钮时，其名称将自动添加到浏览器发送的表单数据中。请注意，我们在删除按钮中指定了一个特定值：`th:value="${rowStat.index}"`。该属性将指示相关参数应具体采用哪个值。如果不存在此属性，将发送空值。这意味着当我们单击删除按钮时，将向`POST`请求添加一个`removeTaste`参数，其中包含我们想要删除的行的索引。然后我们可以在`Controller`中使用以下代码获取它：

```java
Integer rowId = Integer.valueOf(req.getParameter("removeTaste"));
```

这种方法的唯一缺点是每次单击按钮时都会发送整个表单数据，即使并不严格需要。我们的表单足够小，因此可以接受这种折衷方案。

就是这样！表单现在已经完成，可以添加一个或多个口味。

# 客户端验证

作为额外的奖励，客户端验证现在变得非常容易，因为 HTML5 表单验证规范。如果你的目标浏览器是 Internet Explorer 10 及以上版本，添加客户端验证就像指定正确的输入类型一样容易，而不仅仅是使用文本。

通过添加客户端验证，我们可以预先验证表单，并避免向服务器发送我们知道是不正确的请求。有关客户端验证规范的更多信息，请访问[`caniuse.com/#search=validation`](http://caniuse.com/#search=validation)。

我们可以修改我们的输入以启用简单的客户端验证。之前的输入，如下面的代码所示：

```java
<input th:field="${profileForm.twitterHandle}" id="twitterHandle" type="text" th:errorclass="invalid"/>
<input th:field="${profileForm.email}" id="email" type="text" th:errorclass="invalid"/>
<input th:field="${profileForm.birthDate}" id="birthDate" type="text" th:errorclass="invalid"/>
<input type="text" th:field="*{tastes[__${rowStat.index}__]}" th:placeholder="#{taste.placeholder}"/>
```

变成了：

```java
<input th:field="${profileForm.twitterHandle}" id="twitterHandle" type="text" required="required" th:errorclass="invalid"/>
<input th:field="${profileForm.email}" id="email" type="email" required="required" th:errorclass="invalid"/>
<input th:field="${profileForm.birthDate}" id="birthDate" type="text" required="required" th:errorclass="invalid"/>
<input type="text" required="required" th:field="*{tastes[__${rowStat.index}__]}" th:placeholder="#{taste.placeholder}"/>
```

通过这种方法，您的浏览器将在提交表单时检测并根据其类型验证每个属性。`required`属性强制用户输入非空值。`email`类型对相应字段强制执行基本的电子邮件验证规则。

![客户端验证](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00949.jpeg)

还有其他类型的验证器。请查看[`www.the-art-of-web.com/html/html5-form-validation`](http://www.the-art-of-web.com/html/html5-form-validation)。

这种方法的缺点是我们的添加口味和删除口味按钮现在会触发验证。为了解决这个问题，我们需要在默认布局的底部包含一个脚本，就在 jQuery 声明之后。

然而，最好只在个人资料页面上包含它。为了做到这一点，我们可以在`layout/default.html`页面中，在 body 标签结束之前添加一个新的片段部分：

```java
<script type="text/javascript" layout:fragment="script">
</script>
```

这将允许我们在需要时在每个页面上包含额外的脚本。

现在，我们可以在个人资料页面中添加以下脚本，就在关闭 body 标签之前：

```java
<script layout:fragment="script">
    $('button').bind('click', function(e) {
        if (e.currentTarget.name === 'save') {
            $(e.currentTarget.form).removeAttr('novalidate');
        } else {
            $(e.currentTarget.form).attr('novalidate', 'novalidate');
        }
    });
</script>
```

当表单上存在`novalidate`属性时，表单验证不会被触发。这个小脚本将动态地移除`novalidate`属性，如果表单的操作名称是`save`，如果输入的名称不同，`novalidate`属性将始终被添加。因此，验证只会被保存按钮触发。

# 检查点

在进入下一章之前，让我们检查一下是否一切就绪。

在 Java 源代码中，你应该有以下内容：

+   一个新的控制器，`ProfileController`

+   与日期相关的两个新类：日期格式化程序和验证`LocalDate`的注释

+   一个新的`WebConfiguration`文件夹来自定义 Spring MVC 的配置

![检查点](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00950.jpeg)

在资源中，你应该有一个新的模板在 profile 目录下和两个新的包：

![检查点](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00951.jpeg)

# 摘要

在本章中，您学会了如何制作一个完整的表单。我们使用 Java 8 日期创建了一个模型，并学会了如何格式化来自用户的信息并相应地显示它。

我们确保表单填写了有效的信息，包括我们自己的验证器注解。此外，我们通过包括一些客户端验证非常容易地阻止明显不正确的信息甚至触及服务器。

最后，我们甚至将整个应用程序翻译成了英语和法语，包括日期格式！

在下一章中，我们将建立一个空间，用户将能够上传他们的图片，并了解更多关于 Spring MVC 应用程序中的错误处理。



# 第十九章：文件上传和错误处理

在本章中，我们将使用户能够上传个人资料图片。我们还将看到如何在 Spring MVC 中处理错误。

# 上传文件

我们现在将使用户能够上传个人资料图片。这将在以后的个人资料页面上可用，但现在，我们将简化事情，并在`profile/uploadPage.html`目录下的模板目录中创建一个新页面：

```java
<!DOCTYPE html>
<html 

      layout:decorator="layout/default">
<head lang="en">
    <title>Profile Picture Upload</title>
</head>
<body>
<div class="row" layout:fragment="content">

    <h2 class="indigo-text center">Upload</h2>

    <form th:action="@{/upload}" method="post" enctype="multipart/form-data" class="col m8 s12 offset-m2">

        <div class="input-field col s6">
            <input type="file" id="file" name="file"/>
        </div>

        <div class="col s6 center">
            <button class="btn indigo waves-effect waves-light" type="submit" name="save" th:text="#{submit}">Submit
                <i class="mdi-content-send right"></i>
            </button>
        </div>
    </form>
</div>
</body>
</html>
```

除了表单上的`enctype`属性外，没有什么可看的。文件将通过`POST`方法发送到`upload` URL。我们现在将在`profile`包中的`ProfileController`旁边创建相应的控制器：

```java
package masterSpringMvc.profile;

import org.apache.tomcat.util.http.fileupload.IOUtils;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.multipart.MultipartFile;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

@Controller
public class PictureUploadController {
    public static final Resource PICTURES_DIR = new FileSystemResource("./pictures");

    @RequestMapping("upload")
    public String uploadPage() {
        return "profile/uploadPage";
    }

    @RequestMapping(value = "/upload", method = RequestMethod.POST)
    public String onUpload(MultipartFile file) throws IOException {
        String filename = file.getOriginalFilename();
        File tempFile = File.createTempFile("pic", getFileExtension(filename), PICTURES_DIR.getFile());

        try (InputStream in = file.getInputStream();
             OutputStream out = new FileOutputStream(tempFile)) {
            IOUtils.copy(in, out);
        }

        return "profile/uploadPage";
    }

    private static String getFileExtension(String name) {
        return name.substring(name.lastIndexOf("."));
    }
}
```

这段代码将做的第一件事是在`pictures`目录中创建一个临时文件，该目录位于项目的根目录内；因此，请确保它存在。在 Java 中，临时文件只是一个方便的方法，用于在文件系统上获取唯一的文件标识符。用户可以选择删除它。

在项目的根目录下创建一个 pictures 目录，并添加一个名为`.gitkeep`的空文件，以确保您可以在 Git 中提交它。

### 提示

**Git 中的空目录**

Git 是基于文件的，不可能提交一个空目录。一个常见的解决方法是在目录中提交一个空文件，比如`.gitkeep`，以强制 Git 将其纳入版本控制。

用户上传的文件将作为`MultipartFile`接口注入到我们的控制器中。该接口提供了几种方法来获取文件的名称、大小和内容。

这里特别感兴趣的方法是`getInputStream()`。我们确实将复制这个流到一个`fileOutputStream`方法，感谢`IOUtils.copy`方法。将输入流写入输出流的代码非常无聊，所以在类路径中有 Apache Utils 很方便（它是`tomcat-embedded-core.jar`文件的一部分）。

我们大量使用了相当酷的 Spring 和 Java 7 NIO 功能：

+   字符串的资源类是一个实用类，表示可以以不同方式找到的资源的抽象

+   `try…with`块将自动关闭我们的流，即使出现异常，删除了编写`finally`块的样板

通过上述代码，用户上传的任何文件都将被复制到`pictures`目录中。

Spring Boot 中有一些可用的属性来自定义文件上传。看一下`MultipartProperties`类。

最有趣的是：

+   `multipart.maxFileSize`：这定义了上传文件的最大文件大小。尝试上传更大的文件将导致`MultipartException`类。默认值为`1Mb`。

+   `multipart.maxRequestSize`：这定义了多部分请求的最大大小。默认值为`10Mb`。

默认值对我们的应用程序已经足够好了。经过几次上传后，我们的图片目录将如下所示：

![上传文件](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00952.jpeg)

等等！有人上传了一个 ZIP 文件！我简直不敢相信。我们最好在我们的控制器中添加一些检查，以确保上传的文件是真实的图片：

```java
package masterSpringMvc.profile;

import org.apache.tomcat.util.http.fileupload.IOUtils;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.io.*;

@Controller
public class PictureUploadController {
    public static final Resource PICTURES_DIR = new FileSystemResource("./pictures");

    @RequestMapping("upload")
    public String uploadPage() {
        return "profile/uploadPage";
    }

    @RequestMapping(value = "/upload", method = RequestMethod.POST)
    public String onUpload(MultipartFile file, RedirectAttributes redirectAttrs) throws IOException {

 if (file.isEmpty() || !isImage(file)) {
 redirectAttrs.addFlashAttribute("error", "Incorrect file. Please upload a picture.");
 return "redirect:/upload";
 }

        copyFileToPictures(file);

        return "profile/uploadPage";
    }

    private Resource copyFileToPictures(MultipartFile file) throws IOException {
        String fileExtension = getFileExtension(file.getOriginalFilename());
        File tempFile = File.createTempFile("pic", fileExtension, PICTURES_DIR.getFile());
        try (InputStream in = file.getInputStream();
             OutputStream out = new FileOutputStream(tempFile)) {

            IOUtils.copy(in, out);
        }
        return new FileSystemResource(tempFile);
    }

    private boolean isImage(MultipartFile file) {
 return file.getContentType().startsWith("image");
 }

    private static String getFileExtension(String name) {
        return name.substring(name.lastIndexOf("."));
    }
}
```

很简单！`getContentType()`方法返回文件的**多用途互联网邮件扩展**（**MIME**）类型。它将是`image/png`，`image/jpg`等等。因此，我们只需检查 MIME 类型是否以"image"开头。

我们在表单中添加了一个错误消息，因此我们应该在我们的网页中添加一些内容来显示它。将以下代码放在`uploadPage`标题下方：

```java
<div class="col s12 center red-text" th:text="${error}" th:if="${error}">
    Error during upload
</div>
```

下次您尝试上传 ZIP 文件时，将会收到错误！如下截图所示：

![上传文件](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00953.jpeg)

## 将图像写入响应

上传的图片不是从静态目录中提供的。我们需要采取特殊措施来在我们的网页中显示它们。

让我们在我们的上传页面上方添加以下行，就在表单上方：

```java
<div class="col m8 s12 offset-m2">
    <img th:src="img/uploadedPicture}" width="100" height="100"/>
</div>
```

这将尝试从我们的控制器获取图像。让我们在`PictureUploadController`类中添加相应的方法：

```java
@RequestMapping(value = "/uploadedPicture")
public void getUploadedPicture(HttpServletResponse response) throws IOException {
    ClassPathResource classPathResource = new ClassPathResource("/images/anonymous.png");
    response.setHeader("Content-Type", URLConnection.guessContentTypeFromName(classPathResource.getFilename()));
    IOUtils.copy(classPathResource.getInputStream(), response.getOutputStream());
}
```

这段代码将直接将`src/main/resources/images/anonymous.png`目录中找到的图像写入响应！多么令人兴奋！

如果我们再次转到我们的页面，我们会看到以下图片：

![将图像写入响应](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00954.jpeg)

### 提示

我在 iconmonstr（[`iconmonstr.com/user-icon`](http://iconmonstr.com/user-icon)）上找到了匿名用户图片，并将其下载为 128 x 128 的 PNG 文件。

## 管理上传属性

在这一点上，一个好的做法是允许通过`application.properties`文件配置上传目录和匿名用户图片的路径。

让我们在新创建的`config`包内创建一个`PicturesUploadProperties`类：

```java
package masterSpringMvc.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.Resource;

import java.io.IOException;
@ConfigurationProperties(prefix = "upload.pictures")
public class PicturesUploadProperties {
    private Resource uploadPath;
    private Resource anonymousPicture;

    public Resource getAnonymousPicture() {
        return anonymousPicture;
    }

    public void setAnonymousPicture(String anonymousPicture) {
        this.anonymousPicture = new DefaultResourceLoader().getResource(anonymousPicture);
    }

    public Resource getUploadPath() {
        return uploadPath;
    }

    public void setUploadPath(String uploadPath) {
        this.uploadPath = new DefaultResourceLoader().getResource(uploadPath);
    }
}
```

在这个类中，我们使用了 Spring Boot 的`ConfigurationProperties`。这将告诉 Spring Boot 以类型安全的方式自动映射类路径中发现的属性（默认情况下，在`application.properties`文件中）。

请注意，我们定义了以'String'作为参数的 setter，但可以自由地让 getter 返回任何类型是最有用的。

现在我们需要将`PicturesUploadProperties`类添加到我们的配置中：

```java
@SpringBootApplication
@EnableConfigurationProperties({PictureUploadProperties.class})
public class MasterSpringMvc4Application extends WebMvcConfigurerAdapter {
  // code omitted
}
```

现在我们可以在`application.properties`文件中添加属性值：

```java
upload.pictures.uploadPath=file:./pictures
upload.pictures.anonymousPicture=classpath:/images/anonymous.png
```

因为我们使用了 Spring 的`DefaultResourceLoader`类，我们可以使用诸如`file:`或`classpath:`之类的前缀来指定我们的资源可以被找到的位置。

这相当于创建一个`FileSystemResource`类或`ClassPathResource`类。

这种方法还有一个优点，就是可以对代码进行文档化。我们可以很容易地看到图片目录将在应用程序根目录中找到，而匿名图片将在类路径中找到。

就是这样。我们现在可以在我们的控制器中使用我们的属性。以下是`PictureUploadController`类的相关部分：

```java
package masterSpringMvc.profile;

import masterSpringMvc.config.PictureUploadProperties;
import org.apache.tomcat.util.http.fileupload.IOUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.net.URLConnection;

@Controller
public class PictureUploadController {
    private final Resource picturesDir;
 private final Resource anonymousPicture;

 @Autowired
 public PictureUploadController(PictureUploadProperties uploadProperties) {
 picturesDir = uploadProperties.getUploadPath();
 anonymousPicture = uploadProperties.getAnonymousPicture();
 }

    @RequestMapping(value = "/uploadedPicture")
    public void getUploadedPicture(HttpServletResponse response) throws IOException {
        response.setHeader("Content-Type", URLConnection.guessContentTypeFromName(anonymousPicture.getFilename()));
 IOUtils.copy(anonymousPicture.getInputStream(), response.getOutputStream());
    }

  private Resource copyFileToPictures(MultipartFile file) throws IOException {
       String fileExtension = getFileExtension(file.getOriginalFilename());
       File tempFile = File.createTempFile("pic", fileExtension, picturesDir.getFile());
       try (InputStream in = file.getInputStream();
            OutputStream out = new FileOutputStream(tempFile)) {

           IOUtils.copy(in, out);
       }
       return new FileSystemResource(tempFile);
   }    
// The rest of the code remains the same
}
```

此时，如果您再次启动应用程序，您会发现结果并没有改变。匿名图片仍然显示，用户上传的图片仍然会出现在项目根目录的`pictures`目录中。

## 显示上传的图片

现在，我们需要向我们的`PictureUploadController`类添加一个模型属性来显示用户的图片：

```java
@ModelAttribute("picturePath")
public Resource picturePath() {
  return anonymousPicture;
}
```

现在我们可以注入它以在提供上传的图片时检索其值：

```java
@RequestMapping(value = "/uploadedPicture")
public void getUploadedPicture(HttpServletResponse response, @ModelAttribute("picturePath") Path picturePath) throws IOException {
    response.setHeader("Content-Type", URLConnection.guessContentTypeFromName(picturePath.toString()));
    Files.copy(picturePath, response.getOutputStream());
}
```

`@ModelAttribute`注解是一种方便的方法，可以使用带注解的方法创建模型属性。然后可以使用相同的注解将它们注入到控制器方法中。使用此代码，只要我们没有重定向到另一个页面，模型中就会有一个`picturePath`参数。它的默认值是我们在属性中定义的匿名图片。

当文件上传时，我们需要更新此值。更新`onUpload`方法：

```java
@RequestMapping(value = "/upload", method = RequestMethod.POST)
public String onUpload(MultipartFile file, RedirectAttributes redirectAttrs, Model model) throws IOException {

    if (file.isEmpty() || !isImage(file)) {
        redirectAttrs.addFlashAttribute("error", "Incorrect file. Please upload a picture.");
        return "redirect:/upload";
    }

    Resource picturePath = copyFileToPictures(file);
 model.addAttribute("picturePath", picturePath);

    return "profile/uploadPage";
}
```

通过注入模型，我们可以在上传完成后更新`picturePath`参数。

现在，问题是我们的两个方法`onUpload`和`getUploadedPicture`将出现在不同的请求中。不幸的是，模型属性将在每次之间重置。

这就是为什么我们将`picturePath`参数定义为会话属性。我们可以通过向我们的控制器类添加另一个注解来实现这一点：

```java
@Controller
@SessionAttributes("picturePath")
public class PictureUploadController {
}
```

哎呀！这么多注解只是为了处理一个简单的会话属性。您将获得以下输出：

![显示上传的图片](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00955.jpeg)

这种方法使代码组合变得非常容易。此外，我们没有直接使用`HttpServletRequest`或`HttpSession`。此外，我们的对象可以很容易地进行类型化。

## 处理文件上传错误

我的细心读者一定会想到我们的代码可能会抛出两种异常：

+   `IOException`: 如果在将文件写入磁盘时发生了不好的情况，就会抛出此错误。

+   `MultipartException`: 如果上传文件时发生错误，则会抛出此错误。例如，当超过最大文件大小时。

这将为我们提供一个很好的机会来看一下在 Spring 中处理异常的两种方式：

+   在控制器方法中使用`@ExceptionHandler`注解

+   使用在 Servlet 容器级别定义的全局异常处理程序

让我们通过在我们的`PictureUploadController`类中使用`@ExceptionHandler`注解来处理`IOException`，添加以下方法：

```java
@ExceptionHandler(IOException.class)
public ModelAndView handleIOException(IOException exception) {
    ModelAndView modelAndView = new ModelAndView("profile/uploadPage");
    modelAndView.addObject("error", exception.getMessage());
    return modelAndView;
}
```

这是一种简单而强大的方法。每当我们的控制器中抛出`IOException`时，将调用此方法。

为了测试异常处理程序，由于使 Java IO 代码抛出异常可能会很棘手，只需在测试期间替换`onUpload`方法体：

```java
@RequestMapping(value = "/upload", method = RequestMethod.POST)
public String onUpload(MultipartFile file, RedirectAttributes redirectAttrs, Model model) throws IOException {
    throw new IOException("Some message");
}
```

更改后，如果我们尝试上传图片，将在上传页面上看到此异常的错误消息显示：

![处理文件上传错误](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00956.jpeg)

现在，我们将处理`MultipartException`。这需要在 Servlet 容器级别（即在 Tomcat 级别）进行，因为此异常不是直接由我们的控制器抛出的。

我们需要向我们的配置中添加一个新的`EmbeddedServletContainerCustomizer` bean。将此方法添加到`WebConfiguration`类中：

```java
@Bean
public EmbeddedServletContainerCustomizer containerCustomizer() {
    EmbeddedServletContainerCustomizer 
embeddedServletContainerCustomizer = new EmbeddedServletContainerCustomizer() {
        @Override
        public void customize(ConfigurableEmbeddedServletContainer container) {
            container.addErrorPages(new ErrorPage(MultipartException.class, "/uploadError"));
        }
    };
    return embeddedServletContainerCustomizer;
}
```

这有点啰嗦。请注意，`EmbeddedServletContainerCustomizer`是一个包含单个方法的接口；因此，它可以被 lambda 表达式替换：

```java
@Bean
public EmbeddedServletContainerCustomizer containerCustomizer() {
    EmbeddedServletContainerCustomizer embeddedServletContainerCustomizer
            = container -> container.addErrorPages(new ErrorPage(MultipartException.class, "/uploadError"));
    return embeddedServletContainerCustomizer;
}
```

因此，我们只需编写以下内容：

```java
@Bean
public EmbeddedServletContainerCustomizer containerCustomizer() {
    return container -> container.addErrorPages(new ErrorPage(MultipartException.class, "/uploadError"));
}
```

此代码创建了一个新的错误页面，当发生`MultipartException`时将调用该页面。它还可以映射到 HTTP 状态。`EmbeddedServletContainerCustomizer`接口还具有许多其他功能，将允许自定义我们的应用程序运行的 Servlet 容器。有关更多信息，请访问[`docs.spring.io/spring-boot/docs/current/reference/html/boot-features-developing-web-applications.html#boot-features-customizing-embedded-containers`](http://docs.spring.io/spring-boot/docs/current/reference/html/boot-features-developing-web-applications.html#boot-features-customizing-embedded-containers)。

现在，我们需要在我们的`PictureUploadController`类中处理这个`uploadError` URL：

```java
@RequestMapping("uploadError")
public ModelAndView onUploadError(HttpServletRequest request) {
    ModelAndView modelAndView = new ModelAndView("uploadPage");
    modelAndView.addObject("error", request.getAttribute(WebUtils.ERROR_MESSAGE_ATTRIBUTE));
    return modelAndView;
}
```

在 Servlet 环境中定义的错误页面包含许多有助于调试错误的有趣属性：

| 属性 | 描述 |
| --- | --- |
| `javax.servlet.error.status_code` | 这是错误的 HTTP 状态码。 |
| `javax.servlet.error.exception_type` | 这是异常类。 |
| `javax.servlet.error.message` | 这是抛出的异常的消息。 |
| `javax.servlet.error.request_uri` | 这是发生异常的 URI。 |
| `javax.servlet.error.exception` | 这是实际的异常。 |
| `javax.servlet.error.servlet_name` | 这是捕获异常的 Servlet 的名称。 |

所有这些属性都可以方便地在 Spring Web 的`WebUtils`类上访问。

如果有人试图上传太大的文件，他们将收到非常明确的错误消息。

您现在可以通过上传一个非常大的文件（> 1Mb）或将`multipart.maxFileSize`属性设置为较低的值（例如 1kb）来测试错误是否被正确处理：

![处理文件上传错误](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00957.jpeg)

# 翻译错误消息

对于开发人员来说，看到应用程序抛出的异常是非常好的。然而，对于我们的用户来说，它们的价值很小。因此，我们将对它们进行翻译。为了做到这一点，我们必须将我们应用程序的`MessageSource`类注入到我们控制器的构造函数中：

```java

private final MessageSource messageSource;

@Autowired
public PictureUploadController(PictureUploadProperties uploadProperties, MessageSource messageSource) {
    picturesDir = uploadProperties.getUploadPath();
    anonymousPicture = uploadProperties.getAnonymousPicture();
    this.messageSource = messageSource;
}
```

现在，我们可以从消息包中检索消息：

```java
@ExceptionHandler(IOException.class)
public ModelAndView handleIOException(Locale locale) {
    ModelAndView modelAndView = new ModelAndView("profile/uploadPage");
    modelAndView.addObject("error", messageSource.getMessage("upload.io.exception", null, locale));
    return modelAndView;
}

@RequestMapping("uploadError")
public ModelAndView onUploadError(Locale locale) {
    ModelAndView modelAndView = new ModelAndView("profile/uploadPage");
    modelAndView.addObject("error", messageSource.getMessage("upload.file.too.big", null, locale));
    return modelAndView;
}
```

以下是英文消息：

```java
upload.io.exception=An error occurred while uploading the file. Please try again.
upload.file.too.big=Your file is too big.
```

现在，法语消息：

```java
upload.io.exception=Une erreur est survenue lors de l'envoi du fichier. Veuillez réessayer.
upload.file.too.big=Votre fichier est trop gros.
```

# 将配置文件放入会话中

我们希望的下一步是将配置文件存储在会话中，以便每次进入配置文件页面时都不会被重置。这对一些用户来说可能会很烦人，我们必须解决这个问题。

### 提示

**HTTP 会话**是在请求之间存储信息的一种方式。HTTP 是一种无状态协议，这意味着没有办法将来自同一用户的两个请求联系起来。大多数 Servlet 容器所做的是将名为`JSESSIONID`的 cookie 与每个用户关联起来。该 cookie 将在请求头中传输，并允许您在一个称为`HttpSession`的抽象中存储任意对象。这样的会话通常会在用户关闭或切换 Web 浏览器或预定义的不活动期之后结束。

我们刚刚看到了一种使用`@SessionAttributes`注解将对象放入会话中的方法。这在控制器内部效果很好，但在多个控制器之间共享数据时会变得困难。我们必须依赖字符串来从其名称解析属性，这很难重构。出于同样的原因，我们不希望直接操作`HttpSession`。另一个阻止直接使用会话的论点是，依赖于它的控制器很难进行单元测试。

在使用 Spring 保存会话中的内容时，还有另一种流行的方法：使用`@Scope("session")`为 bean 添加注释。

然后，您将能够在控制器和其他 Spring 组件中注入会话 bean，以设置或检索其中的值。

让我们在`profile`包中创建一个`UserProfileSession`类：

```java
package masterSpringMvc.profile;

import org.springframework.context.annotation.Scope;
import org.springframework.context.annotation.ScopedProxyMode;
import org.springframework.stereotype.Component;
import java.io.Serializable;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;

@Component
@Scope(value = "session", proxyMode = ScopedProxyMode.TARGET_CLASS)
public class UserProfileSession implements Serializable {
    private String twitterHandle;
    private String email;
    private LocalDate birthDate;
    private List<String> tastes = new ArrayList<>();

    public void saveForm(ProfileForm profileForm) {
        this.twitterHandle = profileForm.getTwitterHandle();
        this.email = profileForm.getEmail();
        this.birthDate = profileForm.getBirthDate();
        this.tastes = profileForm.getTastes();
    }

    public ProfileForm toForm() {
        ProfileForm profileForm = new ProfileForm();
        profileForm.setTwitterHandle(twitterHandle);
        profileForm.setEmail(email);
        profileForm.setBirthDate(birthDate);
        profileForm.setTastes(tastes);
        return profileForm;
    }
}
```

我们已经方便地提供了一种从`ProfileForm`对象转换的方法。这将帮助我们从`ProfileController`构造函数中存储和检索表单数据。我们需要在控制器的构造函数中注入我们的`UserProfileSession`变量并将其存储为字段。我们还需要将`ProfileForm`公开为模型属性，这将消除在`displayProfile`方法中注入它的需要。最后，一旦验证通过，我们就可以保存配置文件：

```java
@Controller
public class ProfileController {

    private UserProfileSession userProfileSession;
    @Autowired
    public ProfileController(UserProfileSession userProfileSession) {
        this.userProfileSession = userProfileSession;
    }

    @ModelAttribute
    public ProfileForm getProfileForm() {
        return userProfileSession.toForm();
    }

    @RequestMapping(value = "/profile", params = {"save"}, method = RequestMethod.POST)
    public String saveProfile(@Valid ProfileForm profileForm, BindingResult bindingResult) {
        if (bindingResult.hasErrors()) {
            return "profile/profilePage";
        }
        userProfileSession.saveForm(profileForm);
        return "redirect:/profile";
    }

    // the rest of the code is unchanged
}
```

这就是使用 Spring MVC 在会话中保存数据所需的全部内容。

现在，如果您完成了配置文件表单并刷新页面，数据将在请求之间持久保存。

在进入下一章之前，我想详细介绍一些我们刚刚使用的概念。

首先是通过构造函数进行注入。`ProfileController`构造函数使用`@Autowired`进行注释，这意味着 Spring 将在实例化 bean 之前从应用程序上下文中解析构造函数参数。另一种稍微不那么冗长的替代方法是使用字段注入：

```java
@Controller
public class ProfileController {

    @Autowired
    private UserProfileSession userProfileSession;
}
```

构造函数注入可能更好，因为如果我们要远离`spring-test`框架，它会使我们的控制器的单元测试更容易，并且它会使我们的 bean 的依赖关系更加明确。

有关字段注入和构造函数注入的详细讨论，请参阅 Oliver Gierke 在[`olivergierke.de/2013/11/why-field-injection-is-evil/`](http://olivergierke.de/2013/11/why-field-injection-is-evil/)上的出色博客文章。

可能需要澄清的另一件事是`Scope`注解上的`proxyMode`参数：

```java
@Scope(value = "session", proxyMode = ScopedProxyMode.TARGET_CLASS)
```

Spring 有三个`proxyMode`参数可用，如果不计算默认值：

+   `TARGET_CLASS`：这使用 CGI 代理

+   `INTERFACES`：这将创建一个 JDK 代理

+   `NO`：这不会创建任何代理

代理的优势通常在将某些东西注入到长期存在的组件中（如单例）时发挥作用。因为注入只发生一次，当 bean 被创建时，对注入的 bean 的后续调用可能不会反映其实际状态。

在我们的情况下，会话 bean 的实际状态存储在会话中，而不是直接存储在 bean 中。这解释了为什么 Spring 必须创建代理：它需要拦截对我们 bean 方法的调用，并监听其变化。这样，bean 的状态可以透明地存储和检索到底层的 HTTP 会话中。

对于会话 bean，我们被迫使用代理模式。CGI 代理将对您的字节码进行检测，并在任何类上工作，而 JDK 方法可能会更轻量级一些，但需要您实现一个接口。

最后，我们使`UserProfileSession` bean 实现了`Serializable`接口。这并不是严格要求的，因为 HTTP 会话可以在内存中存储任意对象，但是使最终存储在会话中的对象可序列化确实是一个好习惯。

实际上，我们可能会更改会话的持久化方式。事实上，我们将在第七章中将会话存储在 Redis 数据库中，*优化您的请求*，在那里 Redis 必须使用`Serializable`对象。最好始终将会话视为通用数据存储。我们必须提供一种从该存储系统中写入和读取对象的方法。

为了使我们的 bean 上的序列化正常工作，我们还需要使其每个字段都可序列化。在我们的情况下，字符串和日期是可序列化的，所以我们可以继续。

# 自定义错误页面

Spring Boot 允许您定义自己的错误视图，而不是我们之前看到的 Whitelabel 错误页面。它必须具有名称`error`，其目的是处理所有异常。默认的`BasicErrorController`类将公开许多有用的模型属性，您可以在此页面上显示这些属性。

让我们在`src/main/resources/templates`中创建一个自定义错误页面。让我们称之为`error.html`：

```java
<!DOCTYPE html>
<html >
<head lang="en">
    <meta charset="UTF-8"/>
    <title th:text="${status}">404</title>

    <link href="/webjars/materializecss/0.96.0/css/materialize.css" type="text/css" rel="stylesheet"
          media="screen,projection"/>
</head>
<body>
<div class="row">
    <h1 class="indigo-text center" th:text="${error}">Not found</h1>

    <p class="col s12 center" th:text="${message}">
        This page is not available
    </p>
</div>
</body>
</html>
```

现在，如果我们导航到我们的应用程序未处理的 URL，我们会看到我们的自定义错误页面：

![自定义错误页面](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00958.jpeg)

处理错误的更高级选项是定义自己的`ErrorController`类的实现，这是负责全局处理所有异常的控制器。查看`ErrorMvcAutoConfiguration`类和`BasicErrorController`类，它是默认实现。

# 使用矩阵变量的 URL 映射

我们现在知道我们的用户对什么感兴趣。改进我们的 Tweet 控制器，以便它允许从关键字列表中进行搜索，这是一个好主意。

在 URL 中传递键值对的一个有趣方式是使用矩阵变量。这与请求参数非常相似。考虑以下代码：

```java
someUrl/param?var1=value1&var2=value2
```

矩阵变量理解前面的参数：

```java
someUrl/param;var1=value1;var2=value2
```

它们还允许每个参数都是一个列表：

```java
someUrl/param;var1=value1,value2;var2=value3,value4
```

矩阵变量可以映射到控制器内的不同对象类型：

+   `Map<String, List<?>>`：这处理多个变量和多个值

+   `Map<String, ?>`：这处理每个变量只有一个值的情况

+   `List<?>`：如果我们对一个可以配置名称的单个变量感兴趣，就会使用这个

在我们的情况下，我们想要处理这样的情况：

```java
http://localhost:8080/search/popular;keywords=scala,java
```

第一个参数`popular`是 Twitter 搜索 API 已知的结果类型。它可以取以下值：`mixed`、`recent`或`popular`。

我们 URL 的其余部分是关键字列表。因此，我们将它们映射到一个简单的`List<String>`对象。

默认情况下，Spring MVC 会删除 URL 中分号后面的每个字符。我们需要做的第一件事是关闭这种行为，以启用我们应用程序中的矩阵变量。

让我们在`WebConfiguration`类中添加以下代码：

```java
@Override
public void configurePathMatch(PathMatchConfigurer configurer) {
    UrlPathHelper urlPathHelper = new UrlPathHelper();
    urlPathHelper.setRemoveSemicolonContent(false);
    configurer.setUrlPathHelper(urlPathHelper);
}
```

让我们在`search`包中创建一个新的控制器，我们将其称为`SearchController`。它的作用是处理以下请求：

```java
package masterSpringMvc.search;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.social.twitter.api.Tweet;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.MatrixVariable;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;

import java.util.List;

@Controller
public class SearchController {
    private SearchService searchService;
    @Autowired
    public SearchController(SearchService searchService) {
        this.searchService = searchService;
    }

    @RequestMapping("/search/{searchType}")
    public ModelAndView search(@PathVariable String searchType, @MatrixVariable List<String> keywords) {
        List<Tweet> tweets = searchService.search(searchType, keywords);
        ModelAndView modelAndView = new ModelAndView("resultPage");
        modelAndView.addObject("tweets", tweets);
        modelAndView.addObject("search", String.join(",", keywords));
        return modelAndView;
    }
}
```

正如你所看到的，我们能够重用现有的结果页面来显示推文。我们还希望将搜索委托给另一个名为`SearchService`的类。我们将在与`SearchController`相同的包中创建这个服务：

```java
package masterSpringMvc.search;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.social.twitter.api.Tweet;
import org.springframework.social.twitter.api.Twitter;
import org.springframework.stereotype.Service;
import java.util.List;

@Service
public class SearchService {
    private Twitter twitter;

    @Autowired
    public SearchService(Twitter twitter) {
        this.twitter = twitter;
    }

    public List<Tweet> search(String searchType, List<String> keywords) {
        return null;
    }
}
```

现在，我们需要实现`search()`方法。

`twitter.searchOperations().search(params)`上可访问的搜索操作以`searchParameters`作为高级搜索的参数。这个对象允许我们根据十几个标准进行搜索。我们对`query`、`resultType`和`count`属性感兴趣。

首先，我们需要创建一个`ResultType`构造函数，其中包含`searchType`路径变量。`ResultType`是一个枚举，所以我们可以迭代它的不同值，并找到与输入匹配的值，忽略大小写：

```java
private SearchParameters.ResultType getResultType(String searchType) {
    for (SearchParameters.ResultType knownType : SearchParameters.ResultType.values()) {
        if (knownType.name().equalsIgnoreCase(searchType)) {
            return knownType;
        }
    }
    return SearchParameters.ResultType.RECENT;
}
```

现在我们可以创建一个带有以下方法的`SearchParameters`构造函数：

```java
private SearchParameters createSearchParam(String searchType, String taste) {

    SearchParameters.ResultType resultType = getResultType(searchType);
    SearchParameters searchParameters = new SearchParameters(taste);
    searchParameters.resultType(resultType);
    searchParameters.count(3);
    return searchParameters;
}
```

现在，创建`SearchParameters`构造函数的列表就像进行映射操作一样简单（获取关键字列表并为每个关键字返回一个`SearchParameters`构造函数）：

```java
List<SearchParameters> searches = keywords.stream()
        .map(taste -> createSearchParam(searchType, taste))
        .collect(Collectors.toList());
```

现在，我们想要为每个`SearchParameters`构造函数获取推文。你可能会想到这样的东西：

```java
List<Tweet> tweets = searches.stream()
        .map(params -> twitter.searchOperations().search(params))
        .map(searchResults -> searchResults.getTweets())
        .collect(Collectors.toList());
```

然而，如果你仔细想想，这将返回一个推文列表。我们想要的是将所有推文展平，以便得到一个简单的列表。原来调用`map`然后展平结果的操作称为`flatMap`。所以我们可以写：

```java
List<Tweet> tweets = searches.stream()
        .map(params -> twitter.searchOperations().search(params))
        .flatMap(searchResults -> searchResults.getTweets().stream())
        .collect(Collectors.toList());
```

`flatMap`函数的语法，它以流作为参数，一开始有点难以理解。让我向你展示`SearchService`类的整个代码，这样我们就可以退一步看看：

```java
package masterSpringMvc.search;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.social.twitter.api.SearchParameters;
import org.springframework.social.twitter.api.Tweet;
import org.springframework.social.twitter.api.Twitter;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
public class SearchService {
    private Twitter twitter;

    @Autowired
    public SearchService(Twitter twitter) {
        this.twitter = twitter;
    }

    public List<Tweet> search(String searchType, List<String> keywords) {
        List<SearchParameters> searches = keywords.stream()
                .map(taste -> createSearchParam(searchType, taste))
                .collect(Collectors.toList());

        List<Tweet> results = searches.stream()
                .map(params -> twitter.searchOperations().search(params))
                .flatMap(searchResults -> searchResults.getTweets().stream())
                .collect(Collectors.toList());

        return results;
    }

    private SearchParameters.ResultType getResultType(String searchType) {
        for (SearchParameters.ResultType knownType : SearchParameters.ResultType.values()) {
            if (knownType.name().equalsIgnoreCase(searchType)) {
                return knownType;
            }
        }
        return SearchParameters.ResultType.RECENT;
    }

    private SearchParameters createSearchParam(String searchType, String taste) {
        SearchParameters.ResultType resultType = getResultType(searchType);
        SearchParameters searchParameters = new SearchParameters(taste);
        searchParameters.resultType(resultType);
        searchParameters.count(3);
        return searchParameters;
    }
}
```

现在，如果我们导航到`http://localhost:8080/search/mixed;keywords=scala,java`，我们会得到预期的结果。首先搜索 Scala 关键字，然后搜索 Java：

![带矩阵变量的 URL 映射](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00959.jpeg)

# 把它放在一起

现在，一切都可以单独工作，是时候将一切组合起来了。我们将分三步完成这个过程：

1.  将上传表单移动到个人资料页面，并删除旧的上传页面。

1.  将个人资料页面上的提交按钮更改为直接触发口味搜索。

1.  更改我们应用程序的主页。它应该立即显示与我们用户口味匹配的搜索结果。如果不可用，转到个人资料页面。

我鼓励你尝试自己做。你会在途中遇到一些很容易解决的问题，但你应该知道足够的知识来自己解决它们。我相信你。

好了，现在你已经完成了工作（你已经完成了，对吧？），让我们来看看我的解决方案。

第一步是删除旧的`uploadPage`标题。不要回头，就这么做。

接下来，将这些行放在`profilePage`标题的下方：

```java
<div class="row">

    <div class="col m8 s12 offset-m2">
        <img th:src="img/uploadedPicture}" width="100" height="100"/>
    </div>

    <div class="col s12 center red-text" th:text="${error}" th:if="${error}">
        Error during upload
    </div>

    <form th:action="@{/profile}" method="post" enctype="multipart/form-data" class="col m8 s12 offset-m2">

        <div class="input-field col s6">
            <input type="file" id="file" name="file"/>
        </div>

        <div class="col s6 center">
            <button class="btn indigo waves-effect waves-light" type="submit" name="upload" th:text="#{upload}">Upload
                <i class="mdi-content-send right"></i>
            </button>
        </div>
    </form>
</div>
```

这与以前的`uploadPage`的内容非常相似。我们只是删除了标题，并更改了提交按钮的标签。将相应的翻译添加到包中。

在英语中：

```java
upload=Upload
```

用法语：

```java
Upload=Envoyer
```

我们还将提交按钮的名称更改为`upload`。这将帮助我们在控制器端识别这个操作。

现在，如果我们尝试上传我们的图片，它会将我们重定向到旧的上传页面。我们需要在`PictureUploadController`类的`onUpload`方法中修复这个问题：

```java
@RequestMapping(value = "/profile", params = {"upload"}, method = RequestMethod.POST)
public String onUpload(@RequestParam MultipartFile file, RedirectAttributes redirectAttrs) throws IOException {

    if (file.isEmpty() || !isImage(file)) {
        redirectAttrs.addFlashAttribute("error", "Incorrect file. Please upload a picture.");
        return "redirect:/profile";
    }

    Resource picturePath = copyFileToPictures(file);
    userProfileSession.setPicturePath(picturePath);

    return "redirect:profile";
}
```

请注意，我们更改了处理 POST 的 URL。现在是`/profile`而不是`/upload`。当`GET`和`POST`请求具有相同的 URL 时，表单处理会更简单，并且在处理异常时会节省我们很多麻烦。这样，我们就不必在错误发生后重定向用户。

我们还删除了模型属性`picturePath`。因为我们现在在会话中有一个代表用户的 bean，`UserProfileSession`，我们决定将其添加在那里。我们在`UserProfileSession`类中添加了一个`picturePath`属性以及相关的 getter 和 setter。

不要忘记在我们的`PictureUploadController`类中注入`UserProfileSession`类，并将其作为字段可用。

请记住，我们会话 bean 的所有属性都必须是可序列化的，与资源不同。因此我们需要以不同的方式存储它。URL 类似乎是一个很好的选择。它是可序列化的，而且很容易使用`UrlResource`类从 URL 创建资源：

```java
@Component
@Scope(value = "session", proxyMode = ScopedProxyMode.TARGET_CLASS)
public class UserProfileSession implements Serializable {
    private URL picturePath;

    public void setPicturePath(Resource picturePath) throws IOException {
        this.picturePath = picturePath.getURL();
    }

    public Resource getPicturePath() {
        return picturePath == null ? null : new UrlResource(picturePath);
    }
}
```

我需要做的最后一件事是在错误后将`profileForm`作为模型属性可用。这是因为在呈现`profilePage`时需要它。

总之，这是`PictureUploadController`类的最终版本：

```java
package masterSpringMvc.profile;

import masterSpringMvc.config.PictureUploadProperties;
import org.apache.tomcat.util.http.fileupload.IOUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.net.URLConnection;
import java.util.Locale;

@Controller
public class PictureUploadController {
    private final Resource picturesDir;
    private final Resource anonymousPicture;
    private final MessageSource messageSource;
    private final UserProfileSession userProfileSession;

    @Autowired
    public PictureUploadController(PictureUploadProperties uploadProperties,
                                   MessageSource messageSource,
                                   UserProfileSession userProfileSession) {
        picturesDir = uploadProperties.getUploadPath();
        anonymousPicture = uploadProperties.getAnonymousPicture();
        this.messageSource = messageSource;
        this.userProfileSession = userProfileSession;
    }

    @RequestMapping(value = "/uploadedPicture")
    public void getUploadedPicture(HttpServletResponse response) throws IOException {
        Resource picturePath = userProfileSession.getPicturePath();
        if (picturePath == null) {
            picturePath = anonymousPicture;
        }
        response.setHeader("Content-Type", URLConnection.guessContentTypeFromName(picturePath.getFilename()));
        IOUtils.copy(picturePath.getInputStream(), response.getOutputStream());
    }

    @RequestMapping(value = "/profile", params = {"upload"}, method = RequestMethod.POST)
    public String onUpload(@RequestParam MultipartFile file, RedirectAttributes redirectAttrs) throws IOException {

        if (file.isEmpty() || !isImage(file)) {
            redirectAttrs.addFlashAttribute("error", "Incorrect file. Please upload a picture.");
            return "redirect:/profile";
        }

        Resource picturePath = copyFileToPictures(file);
        userProfileSession.setPicturePath(picturePath);

        return "redirect:profile";
    }

    private Resource copyFileToPictures(MultipartFile file) throws IOException {
        String fileExtension = getFileExtension(file.getOriginalFilename());
        File tempFile = File.createTempFile("pic", fileExtension, picturesDir.getFile());
        try (InputStream in = file.getInputStream();
             OutputStream out = new FileOutputStream(tempFile)) {

            IOUtils.copy(in, out);
        }
        return new FileSystemResource(tempFile);
    }

    @ExceptionHandler(IOException.class)
    public ModelAndView handleIOException(Locale locale) {
        ModelAndView modelAndView = new ModelAndView("profile/profilePage");
        modelAndView.addObject("error", messageSource.getMessage("upload.io.exception", null, locale));
        modelAndView.addObject("profileForm", userProfileSession.toForm());
        return modelAndView;
    }

    @RequestMapping("uploadError")
    public ModelAndView onUploadError(Locale locale) {
        ModelAndView modelAndView = new ModelAndView("profile/profilePage");
        modelAndView.addObject("error", messageSource.getMessage("upload.file.too.big", null, locale));
        modelAndView.addObject("profileForm", userProfileSession.toForm());
        return modelAndView;
    }

    private boolean isImage(MultipartFile file) {
        return file.getContentType().startsWith("image");
    }

    private static String getFileExtension(String name) {
        return name.substring(name.lastIndexOf("."));
    }
}
```

因此，现在我们可以转到个人资料页面，上传我们的图片，并提供个人信息，如下截图所示：

![将其放在一起](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00960.jpeg)

现在，让我们在个人资料完成后将用户重定向到搜索页面。为此，我们需要修改`ProfileController`类中的`saveProfile`方法：

```java
@RequestMapping(value = "/profile", params = {"save"}, method = RequestMethod.POST)
public String saveProfile(@Valid ProfileForm profileForm, BindingResult bindingResult) {
    if (bindingResult.hasErrors()) {
        return "profile/profilePage";
    }
    userProfileSession.saveForm(profileForm);
    return "redirect:/search/mixed;keywords=" + String.join(",", profileForm.getTastes());
}
```

现在我们能够从我们的个人资料搜索推文，我们不再需要之前创建的`searchPage`或`TweetController`。只需删除`searchPage.html`页面和`TweetController`。

最后，我们可以修改我们的主页，这样如果我们已经完成了我们的个人资料，它就会重定向我们到一个符合我们口味的搜索页面。

让我们在控制器包中创建一个新的控制器。它负责将访问我们网站根目录的用户重定向到他们的个人资料（如果资料不完整）或`resultPage`（如果他们的口味可用）：

```java
package masterSpringMvc.controller;

import masterSpringMvc.profile.UserProfileSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

import java.util.List;

@Controller
public class HomeController {
    private UserProfileSession userProfileSession;

    @Autowired
    public HomeController(UserProfileSession userProfileSession) {
        this.userProfileSession = userProfileSession;
    }

    @RequestMapping("/")
    public String home() {
        List<String> tastes = userProfileSession.getTastes();
        if (tastes.isEmpty()) {
            return "redirect:/profile";
        }
        return "redirect:/search/mixed;keywords=" + String.join(",", tastes);
    }
}
```

# 检查点

在本章中，我们添加了两个控制器，`PictureUploadController`负责将上传的文件写入磁盘并处理上传错误，`SearchController`可以使用矩阵参数从关键字列表中搜索推文。

然后，该控制器将搜索委托给一个新的服务，`SearchService`。

我们删除了旧的`TweetController`。

我们创建了一个会话 bean，`UserProfileSession`，来存储关于用户的信息。

最后，我们在`WebConfiguration`中添加了两个内容。我们为 Servlet 容器添加了错误页面，并支持矩阵变量。

![检查点](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00961.jpeg)

在资源方面，我们添加了一个代表匿名用户的图片和一个处理错误的静态页面。我们将文件上传到`profilePage`，并且删除了旧的`searchPage`。

![检查点](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00962.jpeg)

# 总结

在本章中，我们讨论了文件上传和错误处理。上传文件并不是很复杂。然而，一个重要的设计决定是如何处理上传的文件。我们本可以将图片存储在数据库中，但我们选择将其写入磁盘，并将每个用户的图片位置保存在他们的会话中。

我们看到了在控制器级别和 Servlet 容器级别处理异常的典型方法。有关 Spring MVC 错误处理的其他资源，您可以参考[`spring.io/blog/2013/11/01/exception-handling-in-spring-mvc`](https://spring.io/blog/2013/11/01/exception-handling-in-spring-mvc)上的博客文章。

我们的应用程序已经看起来相当不错，但我们需要编写的代码量非常合理。

敬请关注下一章，我们将看到 Spring MVC 也是构建 REST 应用程序的强大框架。

