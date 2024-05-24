# Spring5 高性能实用指南（二）

> 原文：[`zh.annas-archive.org/md5/40194AF6586468BFD8652280B650BA1F`](https://zh.annas-archive.org/md5/40194AF6586468BFD8652280B650BA1F)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：Spring MVC 优化

在上一章中，我们学习了 Spring **面向切面编程**（**AOP**）模块，AOP 概念，其各种术语，以及如何实现建议。我们还了解了代理概念及其使用代理模式的实现。我们通过最佳实践来实现 Spring AOP 的质量和性能。

Spring MVC 现在是最流行的 Java Web 应用程序框架。它由 Spring 自身提供。Spring Web MVC 有助于开发灵活和松散耦合的基于 Web 的应用程序。Spring MVC 遵循**模型-视图-控制器**（**MVC**）模式，它将输入逻辑、业务逻辑和表示逻辑分开，同时提供组件之间的松散耦合。Spring MVC 模块允许我们在 Web 应用程序中编写测试用例而不使用请求和响应对象。因此，它消除了在企业应用程序中测试 Web 组件的开销。Spring MVC 还支持多种新的视图技术，并允许扩展。Spring MVC 为控制器、视图解析器、处理程序映射和 POJO bean 提供了清晰的角色定义，使得创建 Java Web 应用程序变得简单。

在本章中，我们将学习以下主题：

+   Spring MVC 配置

+   Spring 异步处理，`@Async`注解

+   使用 Spring Async 的`CompletableFuture`

+   Spring 安全配置

+   认证缓存

+   使用 Spring Security 进行快速和无状态的 API 身份验证

+   使用 JMX 监视和管理 Tomcat

+   Spring MVC 性能改进

# Spring MVC 配置

Spring MVC 架构设计了一个前端控制器 Servlet，即`DispatcherServlet`，它是前端控制器模式的实现，并充当所有 HTTP 请求和响应的入口点。`DispatcherServlet`可以使用 Java 配置或部署描述符文件`web.xml`进行配置和映射。在进入配置部分之前，让我们了解 Spring MVC 架构的流程。

# Spring MVC 架构

在 Spring MVC 框架中，有多个核心组件来维护请求和响应执行的流程。这些组件被清晰地分开，并且具有不同的接口和实现类，因此可以根据需求使用。这些核心组件如下：

| **组件** | **摘要** |
| --- | --- |
| `DispatcherServlet` | 它作为 Spring MVC 框架的前端控制器，负责 HTTP 请求和响应的生命周期。 |
| `HandlerMapping` | 当请求到来时，这个组件负责决定哪个控制器将处理 URL。 |
| `Controller` | 它执行业务逻辑并映射`ModelAndView`中的结果数据。 |
| `ModelAndView` | 它以执行结果和视图对象的形式保存模型数据对象。 |
| `ViewResolver` | 它决定要呈现的视图。 |
| `View` | 它显示来自模型对象的结果数据。 |

以下图表说明了 Spring MVC 架构中前面组件的流程：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-hiperf-spr5/img/742e69c4-d5cc-407c-aa61-c4a201de15e2.png)

Spring MVC 架构

让我们了解架构的基本流程：

1.  当传入的**请求**到来时，它被前端控制器`DispatcherServlet`拦截。在拦截**请求**后，前端控制器找到适当的`HandlerMapping`。

1.  `HandlerMapping`将客户端**请求**调用映射到适当的`Controller`，根据配置文件或注解`Controller`列表，并将`Controller`信息返回给前端控制器。

1.  `DispatcherServlet`将**请求**分派到适当的`Controller`。

1.  `Controller`执行在`Controller`方法下定义的业务逻辑，并将结果数据以`ModelAndView`的形式返回给前端控制器。

1.  前端控制器根据`ModelAndView`中的值获取**视图名称**并将其传递给`ViewResolver`以根据配置的视图解析器解析实际视图。

1.  **视图**使用**模型**对象来呈现屏幕。输出以`HttpServletResponse`的形式生成并传递给前端控制器。

1.  前端控制器将**响应**发送回 Servlet 容器，以将输出发送回用户。

现在，让我们了解 Spring MVC 配置方法。Spring MVC 配置可以通过以下方式进行设置：

+   基于 XML 的配置

+   基于 Java 的配置

在使用上述方法进行配置之前，让我们定义设置 Spring MVC 应用程序所涉及的步骤：

1.  配置前端控制器

1.  创建 Spring 应用程序上下文

1.  配置`ViewResolver`

# 基于 XML 的配置

在基于 XML 的配置中，我们将使用 XML 文件来进行 Spring MVC 配置。让我们按照上述步骤继续进行配置。

# 配置前端控制器

要在基于 XML 的配置中配置前端控制器 Servlet`DispatcherServlet`，我们需要在`web.xml`文件中添加以下 XML 代码：

```java
  <servlet>
    <servlet-name>spring-mvc</servlet-name>
    <servlet-class>
      org.springframework.web.servlet.DispatcherServlet
    </servlet-class>
    <init-param>
      <param-name>contextConfigLocation</param-name>
      <param-value>/WEB-INF/spring-mvc-context.xml</param-value>
    </init-param>
    <load-on-startup>1</load-on-startup>
  </servlet>

  <servlet-mapping>
    <servlet-name>spring-mvc</servlet-name>
    <url-pattern>/</url-pattern>
  </servlet-mapping>
```

在上述 XML 代码中，我们首先配置了`DispatcherServlet`。然后，我们提到了上下文配置位置`/WEB-INF/spring-mvc-context.xml`。我们将`load-on-startup`值设置为`1`，因此 Servlet 容器将在启动时加载此 Servlet。在第二部分中，我们定义了`servlet-mapping`标签，将 URL`/`映射到`DispatcherServlet`。现在，我们将在下一步中定义 Spring 应用程序上下文。

在`DispatcherServlet`配置下配置`load-on-startup`元素是一个好习惯，以便在集群环境中，如果 Spring 没有启动并且一旦部署就会有大量的调用命中您的 Web 应用程序，您可能会面临超时问题。

# 创建 Spring 应用程序上下文

在`web.xml`中配置`DispatcherServlet`之后，让我们继续创建一个 Spring 应用程序上下文。为此，我们需要在`spring-mvc-context.xml`文件中添加以下 XML 代码：

```java
<beans>
<!-- Schema definitions are skipped. -->
<context:component-scan base-            package="com.packt.springhighperformance.ch4.controller" />
<mvc:annotation-driven />
</beans>
```

在上述 XML 代码中，我们首先为`com.packt.springhighperformance.ch4.controller`包定义了一个组件扫描标签`<context:component-scan />`，以便所有的 bean 和控制器都能被创建和自动装配。

然后，我们使用了`<mvc:annotation-driven />`来自动注册不同的 bean 和组件，包括请求映射、数据绑定、验证和使用`@ResponseBody`进行自动转换功能。

# 配置 ViewResolver

要配置`ViewResolver`，我们需要在`spring-mvc-context.xml`文件中为`InternalResourceViewResolver`类指定一个 bean，在`<mvc:annotation-driven />`之后。让我们这样做：

```java
<beans>
<!-- Schema definitions are skipped. -->
<context:component-scan base- package="com.packt.springhighperformance.ch4.controller" />
<mvc:annotation-driven />

<bean
 class="org.springframework.web.servlet.view.InternalResourceViewResolv  er">
    <property name="prefix">
      <value>/WEB-INF/views/</value>
    </property>
    <property name="suffix">
      <value>.jsp</value>
    </property>
  </bean>
</beans>
```

在配置`ViewResolver`之后，我们将创建一个`Controller`来测试配置。但是，在继续之前，让我们看看基于 Java 的配置。

# 基于 Java 的配置

对于基于 Java 的 Spring MVC 配置，我们将按照与基于 XML 的配置相同的步骤进行。在基于 Java 的配置中，所有配置都将在 Java 类下完成。让我们按照顺序进行。

# 配置前端控制器

在 Spring 5.0 中，有三种方法可以通过实现或扩展以下三个类来以编程方式配置`DispatcherServlet`：

+   `WebAppInitializer` 接口

+   `AbstractDispatcherServletInitializer` 抽象类

+   `AbstractAnnotationConfigDispatcherServletInitializer` 抽象类

我们将使用`AbstractDispatcherServletInitializer`类，因为它是使用基于 Java 的 Spring 配置的应用程序的首选方法。它是首选的，因为它允许我们启动一个 Servlet 应用程序上下文，以及一个根应用程序上下文。

我们需要创建以下类来配置`DispatcherServlet`：

```java
import org.springframework.web.servlet.support.AbstractAnnotationConfigDispatcherServletInitializer;

public class SpringMvcWebInitializer extends AbstractAnnotationConfigDispatcherServletInitializer {

  @Override
  protected Class<?>[] getRootConfigClasses() {
    return null;
  }

  @Override
  protected Class<?>[] getServletConfigClasses() {
    return new Class[] { SpringMvcWebConfig.class };
  }

  @Override
  protected String[] getServletMappings() {
    return new String[] { "/" };
  }
}
```

前面的类代码等同于我们在*基于 XML 的配置*部分创建的`web.xml`文件配置。在前面的类中，`getRootConfigClasses()`方法用于指定根应用程序上下文配置类（如果不需要，则为`null`）。`getServletConfigClasses()`用于指定 Web 应用程序配置类（如果不需要，则为`null`）。`getServletMappings()`方法用于指定`DispatcherServlet`的 Servlet 映射。首先加载根配置类，然后加载 Servlet 配置类。根配置类将创建一个`ApplicationContext`，它将作为父上下文，而 Servlet 配置类将创建一个`WebApplicationContext`，它将作为父上下文的子上下文。

# 创建一个 Spring 应用程序上下文并配置 ViewResolver

在 Spring 5.0 中，要使用 Java 配置创建 Spring 应用程序上下文并配置`ViewResolver`，需要在类中添加以下代码：

```java
@Configuration
@EnableWebMvc
@ComponentScan({ "com.packt.springhighperformance.ch4.bankingapp.controller"})
public class SpringMvcWebConfig implements WebMvcConfigurer {

  @Bean
  public InternalResourceViewResolver resolver() {
    InternalResourceViewResolver resolver = new 
    InternalResourceViewResolver();
    resolver.setPrefix("/WEB-INF/views/");
    resolver.setSuffix(".jsp");
    return resolver;
  }

}
```

在前面的代码中，我们创建了一个类`SpringMvcWebConfig`，实现了`WebMvcConfigurer`接口，该接口提供了自定义 Spring MVC 配置的选项。`@EnableWebMvc`对象启用了 Spring MVC 的默认配置。`@ComponentScan`对象指定了要扫描控制器的基本包。这两个注解`@EnableWebMvc`和`@ComponentScan`等同于我们在*基于 XML 的配置*部分中创建的`spring-mvc-context.xml`中的`<context:component-scan />`和`<mvc:annotation-driven />`。`resolve()`方法返回`InternalResourceViewResolver`，它有助于从预配置的目录中映射逻辑视图名称。

# 创建一个控制器

现在，让我们创建一个控制器类来映射`/home`请求，如下所示：

```java
package com.packt.springhighperformance.ch4.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class BankController {

  @RequestMapping(value = "/home")
  public String home() {
    return "home";
  }
}
```

在前面的代码中，`@Controller`定义了一个包含请求映射的 Spring MVC 控制器。`@RequestMapping(value = "home")`对象定义了一个映射 URL`/home`到一个方法`home()`。因此，当浏览器发送一个`/home`请求时，它会执行`home()`方法。

# 创建一个视图

现在，让我们在`src/main/webapp/WEB-INF/views/home.jsp`文件夹中创建一个视图`home.jsp`，其中包含以下 HTML 内容：

```java
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=ISO-8859-1">
<title>Spring MVC</title>
</head>
<body>
  <h2>Welcome to Bank</h2>
</body>
</html>
```

现在，当我们运行这个应用程序时，它将显示以下输出：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-hiperf-spr5/img/777d9599-35dd-4ca1-bb09-689f78e850d1.png)

在下一节中，我们将学习关于 Spring 异步处理的内容。

# Spring 异步处理，@Async 注解

Spring 提供了对异步方法执行的支持。这也可以使用线程来实现，但会使代码更复杂，有时会导致更多的错误和 bug。当我们需要以异步方式执行简单操作时，使用线程来处理会是一个繁琐的过程。有些情况下需要异步执行操作，比如从一台机器发送消息到另一台机器。异步处理的主要优势在于调用者不必等待被调用方法的完成。为了在单独的线程中执行方法，需要使用`@Async`注解对方法进行注解。

可以通过使用`@EnableAsync`注解来启用异步处理，以在后台线程池中运行`@Async`方法。以下是启用异步处理的 Java 配置示例：

```java
@Configuration
@EnableAsync
public class SpringAppAsyncConfig { ... }
```

异步处理也可以通过使用 XML 配置来启用，如下所示：

```java
<task:executor id="myappexecutor" pool-size="10" />
<task:annotation-driven executor="myappexecutor"/>
```

# @Async 注解模式

`@Async`注解处理方法有两种模式：

+   发送并忘记模式

+   结果检索模式

# 发送并忘记模式

在这种模式下，方法将配置为`void`类型，以异步运行：

```java
@Async
public void syncCustomerAccounts() {
    logger.info("Customer accounts synced successfully.");
}
```

# 结果检索模式

在这种模式下，方法将配置一个返回类型，通过`Future`类型来包装结果：

```java
@Service
public class BankAsyncService {

  private static final Logger LOGGER = 
  Logger.getLogger(BankAsyncService.class);

  @Async
    public Future<String> syncCustomerAccount() throws 
    InterruptedException {
    LOGGER.info("Sync Account Processing Started - Thread id: " + 
    Thread.currentThread().getId());

    Thread.sleep(2000);

    String processInfo = String.format("Sync Account Processing 
    Completed - Thread Name= %d, Thread Name= %s", 
    Thread.currentThread().getId(), 
    Thread.currentThread().getName());

    LOGGER.info(processInfo);

    return new AsyncResult<String>(processInfo);
    }
}
```

Spring 还提供了对`AsyncResult`类的支持，该类实现了`Future`接口。它可以用于跟踪异步方法调用的结果。

# @Async 注解的限制

`@Async`注解有以下限制：

+   方法需要是`public`，这样它才能被代理

+   异步方法的自我调用不起作用，因为它会绕过代理直接调用底层方法

# 线程池执行程序

你可能想知道我们如何声明异步方法将使用的线程池。默认情况下，对于线程池，Spring 将尝试在上下文中找到一个名为`TaskExecutor`的唯一 bean，或者一个名为`TaskExecutor`的`Executor` bean。如果前两个选项都无法解析，Spring 将使用`SimpleAsyncTaskExecutor`来处理异步方法处理。

然而，有时我们不想为应用程序的所有任务使用相同的线程池。我们可以为每个方法使用不同的线程池，并为每个方法配置不同的线程池。为此，我们只需要将执行器名称传递给每个方法的`@Async`注解。

为了启用异步支持，`@Async`注解是不够的；我们需要在配置类中使用`@EnableAsync`注解。

在 Spring MVC 中，当我们使用`AbstractAnnotationConfigDispatcherServletInitializer`初始化类配置`DispatcherServlet`时，它默认启用了`isAsyncSupported`标志。

现在，我们需要为异步方法调用声明一个线程池定义。在 Spring MVC 基于 Java 的配置中，可以通过在 Spring Web MVC 配置类中覆盖`WebMvcConfigurer`接口的`configureAsyncSupport()`方法来实现。让我们按照以下方式覆盖这个方法：

```java
@Override
public void configureAsyncSupport(AsyncSupportConfigurer configurer) {
    ThreadPoolTaskExecutor t = new ThreadPoolTaskExecutor();
        t.setCorePoolSize(10);
        t.setMaxPoolSize(100);
        t.setThreadNamePrefix("BankAccountSync");
        t.initialize();
        configurer.setTaskExecutor(t);
}
```

在前面的方法中，我们通过覆盖`configureAsyncSupport()`方法配置了线程池执行程序。现在，让我们通过控制器类调用服务类`BankAsyncService`中创建的异步方法，如下所示：

```java
@Controller
public class BankController {

  private static final Logger LOGGER = Logger.getLogger(BankAsyncService.class);

  @Autowired
  BankAsyncService syncService;

  @RequestMapping(value = "/syncacct")
  @ResponseBody
  public Callable<String> syncAccount() {
    LOGGER.info("Entering in controller");

    Callable<String> asyncTask = new Callable<String>() {

      @Override
      public String call() throws Exception {
        Future<String> processSync = syncService.syncCustomerAccount();
        return processSync.get();
      }
    };

    LOGGER.info("Leaving from controller");
    return asyncTask;
  }
}
```

在前面的示例中，当我们请求`/syncacct`时，它将调用`syncAccount()`并在单独的线程中返回异步方法的结果。

# Spring 异步的 CompletableFuture

`CompletableFuture`类是在 Java 8 中引入的，它提供了一种简单的方式来编写异步、多线程、非阻塞的代码。在 Spring MVC 中，也可以在使用`@Async`注解的公共方法的控制器、服务和存储库中使用`CompletableFuture`。`CompletableFuture`实现了`Future`接口，该接口提供了异步计算的结果。

我们可以通过以下简单方式创建`CompletableFuture`：

```java
CompletableFuture<String> completableFuture = new CompletableFuture<String>();
```

要获取这个`CompletableFuture`的结果，我们可以调用`CompletableFuture.get()`方法。该方法将被阻塞，直到`Future`完成。为此，我们可以手动调用`CompletableFuture.complete()`方法来`complete` `Future`：

```java
completableFuture.complete("Future is completed")
```

# runAsync() - 异步运行任务

当我们想要异步执行后台活动任务，并且不想从该任务中返回任何东西时，我们可以使用`CompletableFuture.runAsync()`方法。它以`Runnable`对象作为参数，并返回`CompletableFuture<Void>`类型。

让我们尝试通过在我们的`BankController`类中创建另一个控制器方法来使用`runAsync()`方法，如下所示：

```java
@RequestMapping(value = "/synccust")
  @ResponseBody
  public CompletableFuture<String> syncCustomerDetails() {
    LOGGER.info("Entering in controller");

    CompletableFuture<String> completableFuture = new 
    CompletableFuture<>();
    CompletableFuture.runAsync(new Runnable() {

      @Override
      public void run() {
        try {           
           completableFuture.complete(syncService.syncCustomerAccount()
           .get());
        } catch (InterruptedException | ExecutionException e) {
          completableFuture.completeExceptionally(e);
        }

      }
    }); 
      LOGGER.info("Leaving from controller");
      return completableFuture;
  }
```

在前面的示例中，当请求使用`/synccust`路径时，它将在单独的线程中运行`syncCustomerAccount()`，并在不返回任何值的情况下完成任务。

# supplyAsync() - 异步运行任务，带有返回值

当我们想要在异步完成任务后返回结果时，我们可以使用`CompletableFuture.supplyAsync()`。它以`Supplier<T>`作为参数，并返回`CompletableFuture<T>`。

让我们通过在我们的`BankController`类中创建另一个控制器方法来检查`supplyAsync()`方法，示例如下：

```java
@RequestMapping(value = "/synccustbal")
  @ResponseBody
  public CompletableFuture<String> syncCustomerBalance() {
    LOGGER.info("Entering in controller");

    CompletableFuture<String> completableFuture = 
    CompletableFuture.supplyAsync(new Supplier<String>() {

      @Override
      public String get() {
        try {
          return syncService.syncCustomerBalance().get();
        } catch (InterruptedException | ExecutionException e) {
          LOGGER.error(e);
        }
        return "No balance found";
      }
    }); 
      LOGGER.info("Leaving from controller");
      return completableFuture;
  }
```

`CompletableFuture`对象使用全局线程池`ForkJoinPool.commonPool()`在单独的线程中执行任务。我们可以创建一个线程池并将其传递给`runAsync()`和`supplyAsync()`方法。

以下是`runAsync()`和`supplyAsync()`方法的两种变体：

```java
CompletableFuture<Void> runAsync(Runnable runnable)
CompletableFuture<Void> runAsync(Runnable runnable, Executor executor)
CompletableFuture<U> supplyAsync(Supplier<U> supplier)
CompletableFuture<U> supplyAsync(Supplier<U> supplier, Executor executor)
```

# 将回调附加到 CompletableFuture

`CompletableFuture.get()`会阻塞对象，并等待`Future`任务完成并返回结果。要构建一个异步系统，应该有一个回调，在`Future`任务完成时自动调用。我们可以使用`thenApply()`、`thenAccept()`和`thenRun()`方法将回调附加到`CompletableFuture`。

# Spring Security 配置

Spring Security 是 Java EE 企业应用程序广泛使用的安全服务框架。在认证级别上，Spring Security 提供了不同类型的认证模型。其中一些模型由第三方提供，一些认证功能集由 Spring Security 自身提供。Spring Security 提供了以下一些认证机制：

+   基于表单的认证

+   OpenID 认证

+   LDAP 专门用于大型环境

+   容器管理的认证

+   自定义认证系统

+   JAAS

让我们看一个示例来在 Web 应用程序中激活 Spring Security。我们将使用内存配置。

# 配置 Spring Security 依赖项

要在 Web 应用程序中配置 Spring Security，我们需要将以下 Maven 依赖项添加到我们的**项目对象模型**（**POM**）文件中：

```java
<!-- spring security -->
<dependency>
    <groupId>org.springframework.security</groupId>
    <artifactId>spring-security-web</artifactId>
    <version>${spring.framework.version}</version>
</dependency>
<dependency>
    <groupId>org.springframework.security</groupId>
    <artifactId>spring-security-config</artifactId>
    <version>${spring.framework.version}</version>
</dependency>
```

# 为传入请求配置安全过滤器

在 Web 应用程序中实现安全性时，最好验证所有传入的请求。在 Spring Security 中，框架本身查看传入的请求并验证用户以执行操作，基于提供的访问权限。为了拦截 Web 应用程序的所有传入请求，我们需要配置`filter`，`DelegatingFilterProxy`，它将把请求委托给 Spring 管理的`FilterChainProxy`：

```java
<filter>
    <filter-name>springSecurityFilterChain</filter-name>
    <filter-class>
        org.springframework.web.filter.DelegatingFilterProxy
    </filter-class>
</filter>
<filter-mapping>
    <filter-name>springSecurityFilterChain</filter-name>
    <url-pattern>/*</url-pattern>
</filter-mapping>
```

基于`filter`配置，所有请求将通过此`filter`。现在，让我们配置与安全相关的内容，如身份验证、URL 安全和角色访问。

# 配置 Spring Security

现在，我们将通过创建 Spring Security 配置类来配置 Spring Security 身份验证和授权，如下所示：

```java
@EnableWebSecurity
public class SpringMvcSecurityConfig extends WebSecurityConfigurerAdapter {

  @Autowired
  PasswordEncoder passwordEncoder;

  @Override
  protected void configure(AuthenticationManagerBuilder auth)       
  throws   
  Exception {
    auth
    .inMemoryAuthentication()
    .passwordEncoder(passwordEncoder)
    .withUser("user").password(passwordEncoder.encode("user@123"))
    .roles("USER")
    .and()
    .withUser("admin").password(passwordEncoder.
    encode("admin@123")        
    ).roles("USER", "ADMIN");
  }

  @Bean
  public PasswordEncoder passwordEncoder() {
      return new BCryptPasswordEncoder();
  }

  @Override
  protected void configure(HttpSecurity http) throws Exception {
     http.authorizeRequests()
    .antMatchers("/login").permitAll()
    .antMatchers("/admin/**").hasRole("ADMIN")
    .antMatchers("/**").hasAnyRole("ADMIN","USER")
    .and().formLogin()
    .and().logout().logoutSuccessUrl("/login").permitAll()
    .and()
    .csrf().disable();
  }
}
```

让我们理解上述配置：

+   @EnableWebSecurity：它启用了 Spring Security 的 Web 安全支持，并提供了 Spring MVC 集成。

+   `WebSecurityConfigurerAdapter`：它提供了一组方法，用于启用特定的 Web 安全配置。

+   `protected void configure(AuthenticationManagerBuilder auth)`: 在本示例中，我们使用了内存认证。它可以用于使用`auth.jdbcAuthentication()`连接到数据库，或者使用`auth.ldapAuthentication()`连接到**轻量级目录访问协议**（**LDAP**）。

+   `.passwordEncoder(passwordEncoder)`: 我们使用了密码编码器`BCryptPasswordEncoder`。

+   `.withUser("user").password(passwordEncoder.encode("user@123"))`: 为认证设置用户 ID 和编码密码。

+   `.roles("USER")`: 为用户分配角色。

+   `protected void configure(HttpSecurity http)`: 用于保护需要安全性的不同 URL。

+   `.antMatchers("/login").permitAll()`: 允许所有用户访问登录页面。

+   `.antMatchers("/admin/**").hasRole("ADMIN")`: 允许具有`ADMIN`角色的用户访问管理员面板。

+   `.antMatchers("/**").anyRequest().hasAnyRole("ADMIN", "USER")`: 这意味着对于带有`"/"`的任何请求，您必须使用`ADMIN`或`USER`角色登录。

+   `.and().formLogin()`: 它将提供一个默认的登录页面，带有用户名和密码字段。

+   `.and().logout().logoutSuccessUrl("/login").permitAll()`: 当用户注销时，设置注销成功页面。

+   `.csrf().disable()`: 默认情况下，**跨站请求伪造**（**CSRF**）标志是启用的。在这里，我们已经从配置中禁用了它。

# 添加一个控制器

我们将使用以下`BankController`类进行 URL 映射：

```java
@Controller
public class BankController {

  @GetMapping("/")
  public ModelAndView home(Principal principal) {
    ModelAndView model = new ModelAndView();
    model.addObject("title", "Welcome to Bank");
    model.addObject("message", "Hi " + principal.getName());
    model.setViewName("index");
    return model;
  }

  @GetMapping("/admin**")
  public ModelAndView adminPage() {
    ModelAndView model = new ModelAndView();
    model.addObject("title", "Welcome to Admin Panel");
    model.addObject("message", "This is secured page - Admin 
    Panel");
    model.setViewName("admin");
    return model;
  }

  @PostMapping("/logout")
  public String logout(HttpServletRequest request, 
  HttpServletResponse 
  response) {
    Authentication auth = 
    SecurityContextHolder.getContext().getAuthentication();
    if (auth != null) {
      new SecurityContextLogoutHandler().logout(request, response, 
      auth);
      request.getSession().invalidate();
    }
    return "redirect:/login";
  }
}
```

现在，当我们运行这个例子时，它将首先显示由 Spring 框架提供的登录身份验证表单，然后再尝试访问 Web 应用程序的任何 URL。如果用户使用`USER`角色登录并尝试访问管理员面板，他们将被限制访问。如果用户使用`ADMIN`角色登录，他们将能够访问用户面板和管理员面板。

# 身份验证缓存

当应用程序受到最大数量的调用时，Spring Security 的性能成为一个主要关注点。默认情况下，Spring Security 为每个新请求创建一个新会话，并每次准备一个新的安全上下文。在维护用户身份验证时，这会成为一个负担，从而降低性能。

例如，我们有一个 API，每个请求都需要身份验证。如果对该 API 进行多次调用，将会影响使用该 API 的应用程序的性能。因此，让我们在没有缓存实现的情况下了解这个问题。看一下以下日志，我们使用`curl`命令调用 API，没有缓存实现：

```java
curl -sL --connect-timeout 1 -i http://localhost:8080/authentication-cache/secure/login -H "Authorization: Basic Y3VzdDAwMTpUZXN0QDEyMw=="
```

看一下以下日志：

```java
21:53:46.302 RDS DEBUG JdbcTemplate - Executing prepared SQL query
21:53:46.302 RDS DEBUG JdbcTemplate - Executing prepared SQL statement [select username,password,enabled from users where username = ?]
21:53:46.302 RDS DEBUG DataSourceUtils - Fetching JDBC Connection from DataSource
21:53:46.302 RDS DEBUG SimpleDriverDataSource - Creating new JDBC Driver Connection to [jdbc:h2:mem:testdb;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=false]
21:53:46.307 RDS DEBUG DataSourceUtils - Returning JDBC Connection to DataSource
21:53:46.307 RDS DEBUG JdbcTemplate - Executing prepared SQL query
21:53:46.307 RDS DEBUG JdbcTemplate - Executing prepared SQL statement [select username,authority from authorities where username = ?]
21:53:46.307 RDS DEBUG DataSourceUtils - Fetching JDBC Connection from DataSource
21:53:46.307 RDS DEBUG SimpleDriverDataSource - Creating new JDBC Driver Connection to [jdbc:h2:mem:testdb;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=false]
21:53:46.307 RDS DEBUG DataSourceUtils - Returning JDBC Connection to DataSource
```

每次调用此 API 时，它将使用数据库值对用户名和密码进行身份验证。这会影响应用程序的性能，并且如果用户频繁调用，可能会导致不必要的负载。

克服这个问题的一个体面的解决方案之一是缓存用户身份验证一段特定的时间。我们将使用带有正确配置的`AuthenticationProvider`的`UserCache`的实现，并将其传递给`AuthenticationManagerBuilder`。我们将使用`EhCache`来操作缓存对象。我们可以通过以下步骤来使用这个解决方案：

1.  实现缓存配置类

1.  向`AuthenticationProvider`提供`UserCache`

1.  向`AuthenticationManagerBuilder`提供`AuthenticationProvider`

# 实现缓存配置类

我们创建了以下类，它将提供`UserCache` bean，并将其提供给`AuthenticationProvider`：

```java
@Configuration
@EnableCaching
public class SpringMvcCacheConfig {

  @Bean
  public EhCacheFactoryBean ehCacheFactoryBean() {
    EhCacheFactoryBean ehCacheFactory = new EhCacheFactoryBean();
    ehCacheFactory.setCacheManager(cacheManagerFactoryBean()
    .getObject());
    return ehCacheFactory;
  }

  @Bean
  public CacheManager cacheManager() {
    return new         
    EhCacheCacheManager(cacheManagerFactoryBean().getObject());
  }

  @Bean
  public EhCacheManagerFactoryBean cacheManagerFactoryBean() {
    EhCacheManagerFactoryBean cacheManager = new 
    EhCacheManagerFactoryBean();
    return cacheManager;
  }

  @Bean
  public UserCache userCache() {
    EhCacheBasedUserCache userCache = new EhCacheBasedUserCache();
    userCache.setCache(ehCacheFactoryBean().getObject());
    return userCache;
  }
}
```

在上述类中，`@EnableCaching`启用了缓存管理。

# 向 AuthenticationProvider 提供 UserCache

现在，我们将创建的`UserCache` bean 提供给`AuthenticationProvider`：

```java
@Bean
public AuthenticationProvider authenticationProviderBean() {
     DaoAuthenticationProvider authenticationProvider = new              
     DaoAuthenticationProvider();
     authenticationProvider.setPasswordEncoder(passwordEncoder);
     authenticationProvider.setUserCache(userCache);
     authenticationProvider.
     setUserDetailsService(userDetailsService());
     return authenticationProvider;
}
```

# 向 AuthenticationManagerBuilder 提供 AuthenticationProvider

现在，在 Spring Security 配置类中向`AuthenticationManagerBuilder`提供`AuthenticationProvider`：

```java
@Autowired
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws     
    Exception {

       auth
         .eraseCredentials(false)
         //Providing AuthenticationProvider to 
          AuthenticationManagerBuilder.
         .authenticationProvider(authenticationProviderBean())
         .jdbcAuthentication()
         .dataSource(dataSource); 
    }
```

现在，让我们调用该 API 并检查身份验证的性能。如果我们调用 API 四次，将生成以下日志：

```java
22:46:55.314 RDS DEBUG EhCacheBasedUserCache - Cache hit: false; username: cust001
22:46:55.447 RDS DEBUG JdbcTemplate - Executing prepared SQL query
22:46:55.447 RDS DEBUG JdbcTemplate - Executing prepared SQL statement [select username,password,enabled from users where username = ?]
22:46:55.447 RDS DEBUG DataSourceUtils - Fetching JDBC Connection from DataSource
22:46:55.447 RDS DEBUG SimpleDriverDataSource - Creating new JDBC Driver Connection to [jdbc:h2:mem:testdb;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=false]
22:46:55.463 RDS DEBUG DataSourceUtils - Returning JDBC Connection to DataSource
22:46:55.463 RDS DEBUG JdbcTemplate - Executing prepared SQL query
22:46:55.463 RDS DEBUG JdbcTemplate - Executing prepared SQL statement [select username,authority from authorities where username = ?]
22:46:55.463 RDS DEBUG DataSourceUtils - Fetching JDBC Connection from DataSource
22:46:55.463 RDS DEBUG SimpleDriverDataSource - Creating new JDBC Driver Connection to [jdbc:h2:mem:testdb;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=false]
22:46:55.479 RDS DEBUG DataSourceUtils - Returning JDBC Connection to DataSource
22:46:55.603 RDS DEBUG EhCacheBasedUserCache - Cache put: cust001
22:47:10.118 RDS DEBUG EhCacheBasedUserCache - Cache hit: true; username: cust001
22:47:12.619 RDS DEBUG EhCacheBasedUserCache - Cache hit: true; username: cust001
22:47:14.851 RDS DEBUG EhCacheBasedUserCache - Cache hit: true; username: cust001
```

正如您在前面的日志中所看到的，最初，`AuthenticationProvider`从缓存中搜索`UserDetails`对象；如果它无法从缓存中获取，`AuthenticationProvider`将查询数据库以获取`UserDetails`，并将更新后的对象放入缓存中，以便以后的所有调用都将从缓存中检索`UserDetails`对象。

如果您更新用户的密码并尝试使用新密码对用户进行身份验证，但与缓存中的值不匹配，则它将从数据库中查询`UserDetails`。

# 使用 Spring Security 实现快速和无状态的 API 身份验证

Spring Security 还提供了用于保护非浏览器客户端（如移动应用程序或其他应用程序）的无状态 API。我们将学习如何配置 Spring Security 来保护无状态 API。此外，我们将找出在设计安全解决方案和提高用户身份验证性能时需要考虑的重要点。

# API 身份验证需要 JSESSIONID cookie

对于 API 客户端使用基于表单的身份验证并不是一个好的做法，因为需要在请求链中提供`JSESSIONID` cookie。Spring Security 还提供了使用 HTTP 基本身份验证的选项，这是一种较旧的方法，但效果很好。在 HTTP 基本身份验证方法中，用户/密码详细信息需要与请求头一起发送。让我们看一下以下 HTTP 基本身份验证配置的示例：

```java
@Override
protected void configure(HttpSecurity http) throws Exception {
      http
        .authorizeRequests()
        .anyRequest().authenticated()
        .and()
        .httpBasic();
}
```

在上面的示例中，`configure()`方法来自`WebSecurityConfigurerAdapter`抽象类，该类提供了此方法的默认实现。子类应该通过调用`super`来调用此方法，因为它可能会覆盖它们的配置。这种配置方法有一个缺点；每当我们调用受保护的端点时，它都会创建一个新的会话。让我们使用`curl`命令来调用端点来检查一下：

```java
C:\>curl -sL --connect-timeout 1 -i http://localhost:8080/fast-api-spring-security/secure/login/ -H "Authorization: Basic Y3VzdDAwMTpDdXN0QDEyMw=="
HTTP/1.1 200 OK
Server: Apache-Coyote/1.1
Set-Cookie: JSESSIONID=B85E9773E6C1E71CE0EC1AD11D897529; Path=/fast-api-spring-security; HttpOnly
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
Pragma: no-cache
Expires: 0
X-Frame-Options: DENY
Content-Type: text/plain;charset=ISO-8859-1
Content-Length: 19
Date: Tue, 27 Mar 2018 18:07:43 GMT

Welcome to the Bank
```

我们有一个会话 ID cookie；让我们再次调用它：

```java
C:\>curl -sL --connect-timeout 1 -i http://localhost:8080/fast-api-spring-security/secure/login/ -H "Authorization: Basic Y3VzdDAwMTpDdXN0QDEyMw=="
HTTP/1.1 200 OK
Server: Apache-Coyote/1.1
Set-Cookie: JSESSIONID=14FEB3708295324482BE1DD600D015CC; Path=/fast-api-spring-security; HttpOnly
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
Pragma: no-cache
Expires: 0
X-Frame-Options: DENY
Content-Type: text/plain;charset=ISO-8859-1
Content-Length: 19
Date: Tue, 27 Mar 2018 18:07:47 GMT

Welcome to the Bank
```

正如您所看到的，每个响应中都有两个不同的会话 ID。在上面的示例中，为了测试目的，我们发送了带有编码的用户名和密码的`Authorization`头。当您提供用户名和密码进行身份验证时，您可以从浏览器中获取`Basic Y3VzdDAwMTpDdXN0QDEyMw==`头值。

# API 身份验证不需要 JSESSIONID cookie

由于 API 客户端身份验证不需要会话，我们可以通过以下配置轻松摆脱会话 ID：

```java
@Override
protected void configure(HttpSecurity http) throws Exception {
      http
      .sessionManagement()
        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        .and()
        .authorizeRequests()
        .anyRequest().authenticated()
        .and()
        .httpBasic();
}
```

正如您所看到的，在前面的配置中，我们使用了`SessionCreationPolicy.STATELESS`。通过这个选项，在响应头中不会添加会话 cookie。让我们看看在这个改变之后会发生什么：

```java
C:\>curl -sL --connect-timeout 1 -i http://localhost:8080/fast-api-spring-security/secure/login/ -H "Authorization: Basic Y3VzdDAwMTpDdXN0QDEyMw=="
HTTP/1.1 200 OK
Server: Apache-Coyote/1.1
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
Pragma: no-cache
Expires: 0
X-Frame-Options: DENY
Content-Type: text/plain;charset=ISO-8859-1
Content-Length: 19
Date: Tue, 27 Mar 2018 18:24:32 GMT

Welcome to the Bank
```

在上面的示例中，在响应头中找不到会话 cookie。因此，通过这种方式，我们可以使用 Spring Security 管理 API 的无状态身份验证。

# 使用 JMX 监控和管理 Tomcat

**Java 管理扩展**（**JMX**）提供了一种强大的机制来监视和管理 Java 应用程序。它可以在 Tomcat 中启用，以监视线程、CPU 使用率和堆内存，并配置**MBeans**。Spring 提供了开箱即用的 JMX 支持，我们可以使用它轻松地将我们的 Spring 应用程序集成到 JMX 架构中。

JMX 支持提供以下核心功能：

+   轻松灵活地支持控制 bean 的管理接口

+   声明支持通过远程连接器公开 MBean

+   将 Spring bean 自动注册为 JMX MBean

+   简化支持代理本地和远程 MBean 资源

JMX 功能有三个级别：

+   **仪器级别：**这个级别包含由一个或多个 Java bean 表示的组件和资源，这些组件和资源被称为**托管 bean**或 MBean。

+   **代理级别：**这被称为中间代理，称为**MBean 服务器**。它从远程管理级别获取请求，并将其传递给适当的 MBean。它还可以接收来自 MBean 的与状态更改相关的通知，并将其转发回远程管理级别。

+   **远程管理级别：**这一层由连接器、适配器或客户端程序组成。它向代理级别发送请求，并接收请求的响应。用户可以使用连接器或客户端程序（如 JConsole）连接到 MBean 服务器，使用**远程方法调用**（**RMI**）或**Internet 互操作对象协议**（**IIOP**）等协议，并使用适配器。

简而言之，远程管理级别的用户向代理级别发送请求，代理级别在仪器级别找到适当的 MBean，并将响应发送回用户。

# 连接 JMX 以监视 Tomcat

要在 Tomcat 上配置 JMX，我们需要在 JVM 启动时设置相关的系统属性。我们可以使用以下方法。

我们可以在`{tomcat-folder}\bin\`中更新`catalina.sh`或`catalina.bat`文件，添加以下值：

```java
-Dcom.sun.management.jmxremote 
-Dcom.sun.management.jmxremote.port={port to access} 
-Dcom.sun.management.jmxremote.authenticate=false 
-Dcom.sun.management.jmxremote.ssl=false
```

例如，我们可以在`{tomcat-folder}\bin\catalina.bat`中添加以下值：

```java
set JAVA_OPTS="-Dcom.sun.management.jmxremote
-Dcom.sun.management.jmxremote.port=8990
-Dcom.sun.management.jmxremote.authenticate=false
-Dcom.sun.management.jmxremote.ssl=false"
```

如果您想在 Eclipse 中为 Tomcat 配置 JMX，您需要执行以下操作：

1.  转到“窗口”|“显示视图”|“服务器”。

1.  双击 localhost 上的 Tomcat v8.0 服务器，打开 Tomcat 概述配置窗口。

1.  在“常规信息”下，单击“打开启动配置”。

1.  选择“编辑启动配置属性”的参数选项卡。

1.  在 VM 参数中，添加以下属性，然后单击“确定”：

```java
-Dcom.sun.management.jmxremote
-Dcom.sun.management.jmxremote.port=8990
-Dcom.sun.management.jmxremote.authenticate=false
-Dcom.sun.management.jmxremote.ssl=false
```

做出这些更改后，我们需要重新启动 Tomcat 服务器。之后，我们需要使用 JConsole 测试连接。打开 JConsole 后，我们需要提供远程进程的主机名和端口号，如下所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-hiperf-spr5/img/971e79e2-6a7a-4f18-9236-1ec792804c7e.png)

在上面的截图中，我们已经提供了主机名为`localhost`，端口号为`8990`。当您单击“连接”时，将会弹出一个对话框，您需要单击“不安全连接”，然后您将连接到 JConsole。

# 创建 MBean

要创建 MBean，我们可以使用`@Managed`注解将任何类转换为 MBean。类`BankTransferService`将金额从一个账户转移到另一个账户。我们将使用此示例进行进一步理解：

```java
@Component
@ManagedResource(objectName = "com.packt.springhighperformance.ch4.mbeans : name=BankMoneyTransferService", description = "Transfers money from one account to another")
public class BankMoneyTransferService {

  private Map<String, Integer> accountMap = new HashMap<String, 
  Integer>();
   {
    accountMap.put("12345", 20000);
    accountMap.put("54321", 10000);
   };

  @ManagedOperation(description = "Amount transfer")
  @ManagedOperationParameters({
      @ManagedOperationParameter(name = "sourceAccount", description = 
       "Transfer from account"),
      @ManagedOperationParameter(name = "destinationAccount",         
        description = "Transfer to account"),
      @ManagedOperationParameter(name = "transferAmount", 
      description = 
        "Amount to be transfer") })
  public void transfer(String sourceAccount, String     
  destinationAccount, int transferAmount) {
    if (transferAmount == 0) {
      throw new IllegalArgumentException("Invalid amount");
    }
    int sourceAcctBalance = accountMap.get(sourceAccount);
    int destinationAcctBalance = accountMap.get(destinationAccount);

    if ((sourceAcctBalance - transferAmount) < 0) {
      throw new IllegalArgumentException("Not enough balance.");
    }
    sourceAcctBalance = sourceAcctBalance - transferAmount;
    destinationAcctBalance = destinationAcctBalance + transferAmount;

    accountMap.put(sourceAccount, sourceAcctBalance);
    accountMap.put(destinationAccount, destinationAcctBalance);
  }

  @ManagedOperation(description = "Check Balance")
  public int checkBalance(String accountNumber) {
    if (StringUtils.isEmpty(accountNumber)) {
      throw new IllegalArgumentException("Enter account no.");
    }
    if (!accountMap.containsKey(accountNumber)) {
      throw new IllegalArgumentException("Account not found.");
    }
    return accountMap.get(accountNumber);
  }

}
```

在上述类中，`@ManagedResource`注解将标记类为 MBean，`@ManagedAttribute`和`@ManagedOperation`注解可用于公开任何属性或方法。`@Component`注解将确保所有带有`@Component`、`@Service`或`@Repository`注解的类将被添加到 Spring 上下文中。

# 在 Spring 上下文中导出 MBean

现在，我们需要在 Spring 应用程序上下文中创建一个`MBeanExporter`。我们只需要在 Spring 上下文 XML 配置中添加以下标签：

```java
<context:mbean-export/>
```

我们需要在“‹context:mbean-export/›”元素之前添加`component-scan`元素；否则，JMX 服务器将无法找到任何 bean。

因此，我们的 Spring 上下文配置将如下所示：

```java
<?xml version="1.0" encoding="UTF-8"?>
<beans><!-- Skipped schema definitions -->

  <context:component-scan base-
   package="com.packt.springhighperformance.ch4.mbeans" /> 

<context:mbean-export/>

</beans>
```

现在，我们只需要启动 Tomcat 服务器并打开 JConsole 来查看我们的 MBean。连接到 JConsole 后，转到“MBeans”选项卡，在那里您可以看到我们的包文件夹，其中包含我们的`BankMoneyTransferService` MBean，列在侧边栏中：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-hiperf-spr5/img/fb0dd8cb-79e4-4ea8-b8e7-d43d3b5e9989.png)

如您在前面的示例中所见，我们的 MBean 已生成并列在 JConsole 中。现在，我们可以通过单击“转账”按钮，调用我们在 MBean 中创建的`transfer()`方法，从一个账户向另一个账户转账。当我们单击“查看余额”按钮时，它将根据输入的账号号码在弹出窗口中显示当前余额。在后台，它将调用`BankMoneyTransferService`类的`checkBalance()`方法。

# Spring MVC 性能改进

Spring MVC 应用程序的性能可以通过多种策略和技巧进行改进。在这里，我们列出了一些可以极大改善性能的策略：

+   使用连接池实现高性能

+   Hibernate 改进

+   测试改进

+   适当的服务器维护

+   使用 Spring Security 的身份验证缓存

+   实现 Executor 服务框架

# 使用连接池实现高性能

在 Spring MVC 中提高性能的最重要特性之一是**连接池**。在这种机制中，创建和管理了*N*个数据库连接池，以提高应用程序的性能。当应用程序需要使用连接时，它只需请求一个连接，使用它，然后将其返回到池中。这个过程的主要优点是连接池中有连接立即可用，因此可以立即使用。池本身处理连接的生命周期，因此开发人员不必等待连接建立。

# Hibernate 改进

另一个提高性能的主要点是关于 Hibernate。脏检查是 Hibernate 提供的一个功能。在脏检查中，Hibernate 会自动识别对象是否被修改并需要更新。Hibernate 会在需要时进行脏检查，以保持性能成本。当特定实体具有对应的具有大量列的表时，成本会增加。为了最小化脏检查成本，我们可以将事务设置为`readOnly`，这将提高性能并消除任何脏检查的需要。

```java
@Transactional(readOnly=true)
public void performanceTestMethod() {
    ....
}
```

另一个与 Hibernate 相关的改进是定期刷新和清理 Hibernate 会话。当数据被插入/修改到数据库时，Hibernate 会在会话中存储已经持久化的实体的一个版本，以防它们在会话关闭之前再次更新。我们可以限制 Hibernate 在会话中存储实体的时间，一旦数据被插入，我们就不需要再将实体存储在持久状态中。因此，我们可以安全地刷新和清理`entityManager`，以使实体的状态与数据库同步，并从缓存中删除实体。这将使应用程序远离内存限制，并肯定会对性能产生积极影响。

```java
entityManager.flush();
entityManager.clear();
```

另一个改进可以通过使用**延迟初始化**来实现。如果我们使用 Hibernate，我们应该确保延迟初始化功能被正确使用。我们应该只在需要时才使用实体的延迟加载。例如，如果我们有一个自定义实体集合，如`Set<Employee>`，配置为延迟初始化，那么该集合的每个实体将使用单独的查询分别加载。因此，如果在集合中延迟初始化了多个实体，那么将会按顺序执行大量查询，这可能会严重影响性能。

# 测试改进

对于测试改进，我们可以构建一个测试环境，可以在其中执行应用程序，并在其中获取结果。我们可以编写可重复的性能测试脚本，关注绝对性能（如页面渲染时间）和规模上的性能（如负载时的性能下降）。我们可以在测试环境中使用分析器。

# 适当的服务器维护

一个与适当的服务器维护相关的主要性能方面（如果性能是主要关注点）。以下是一些应该考虑的重要点，以改善性能：

+   通过创建定期的自动化脚本来清理临时文件。

+   当多个服务器实例正在运行时使用负载均衡器。

+   根据应用程序的需求优化配置。例如，在 Tomcat 的情况下，我们可以参考 Tomcat 的配置建议。

# 使用 Spring Security 的身份验证缓存

在使用 Spring Security 时，可以找到提高性能的重要观点。当请求处理时间被认为是不理想的时候，应该正确配置 Spring Security 以提高性能。可能存在这样一种情况，实际请求处理时间大约为 100 毫秒，而 Spring Security 认证额外增加了 400-500 毫秒。我们可以使用 Spring Security 的认证缓存来消除这种性能成本。

# 实施 Executor 服务框架

通过所有可能的改进，如果在请求处理方面保持并发性，性能可以得到改善。可能存在这样一种情况，即对我们的应用程序进行多个并发访问的负载测试，这可能会影响我们应用程序的性能。在这种情况下，我们应该调整 Tomcat 服务器上的线程默认值。如果存在高并发性，HTTP 请求将被暂停，直到有一个线程可用来处理它们。

通过在业务逻辑中使用 Executor 框架来扩展默认的服务器线程实现，可以实现并发异步调用。

# 总结

在本章中，我们对 Spring MVC 模块有了清晰的了解，并学习了不同的配置方法。我们还学习了 Spring 异步处理概念，以及`CompletableFeature`的实现。之后，我们学习了 Spring Security 模块的配置。我们还了解了 Spring Security 的认证部分和无状态 API。然后，我们学习了 Tomcat 的监控部分和 JMX。最后，我们看了 Spring MVC 的性能改进。

在下一章中，我们将学习关于 Spring 数据库交互的知识。我们将从 Spring JDBC 配置和最佳数据库设计和配置开始。然后，我们将介绍最佳连接池配置。我们还将涵盖`@Transactional`概念以提高性能。最后，我们将介绍数据库设计的最佳实践。


# 第五章：理解 Spring 数据库交互

在之前的章节中，我们学习了 Spring 核心特性，如**依赖注入**（DI）及其配置。我们还看到了如何利用 Spring **面向切面编程**（**AOP**）实现可重用的代码。我们学习了如何利用 Spring **模型-视图-控制器**（**MVC**）开发松耦合的 Web 应用程序，以及如何通过异步特性、多线程和认证缓存来优化 Spring MVC 实现以获得更好的结果。

在本章中，我们将学习 Spring 框架与数据库交互。数据库交互是应用程序性能中最大的瓶颈。Spring 框架支持所有主要的数据访问技术，如**Java 数据库连接**（**JDBC**）直接，任何**对象关系映射**（**ORM**）框架（如 Hibernate），**Java 持久化 API**（**JPA**）等。我们可以选择任何数据访问技术来持久化我们的应用程序数据。在这里，我们将探讨 Spring JDBC 的数据库交互。我们还将学习 Spring JDBC 的常见性能陷阱和最佳的数据库设计实践。然后我们将看一下 Spring 事务管理和最佳的连接池配置。

本章将涵盖以下主题：

+   Spring JDBC 配置

+   为了获得最佳性能的数据库设计

+   事务管理

+   使用`@Transactional`进行声明性 ACID

+   最佳的隔离级别

+   最佳的获取大小

+   最佳的连接池配置

+   Tomcat JDBC 连接池与 HikariCP

+   数据库设计最佳实践

# Spring JDBC 配置

如果不使用 JDBC，我们无法仅使用 Java 连接到数据库。JDBC 将以直接或间接的方式涉及到连接数据库。但是，如果 Java 程序员直接使用核心 JDBC，会面临一些问题。让我们看看这些问题是什么。

# 核心 JDBC 的问题

当我们使用核心 JDBC API 时，我们将面临以下问题：

```java
    String query = "SELECT COUNT(*) FROM ACCOUNT";

    try (Connection conn = dataSource.getConnection();
        Statement statement = conn.createStatement(); 
        ResultSet rsltSet = statement.executeQuery(query)) 
        {
        if(rsltSet.next()){ 
 int count = rsltSet.getInt(1); System.out.println("count : " + count);
        }
      } catch (SQLException e) {
        // TODO Auto-generated catch block
            e.printStackTrace();
      }      
  }
```

在前面的例子中，我已经突出显示了一些代码。只有粗体格式的代码是重要的；其余是冗余的代码。因此，我们必须每次都写这些冗余的代码来执行数据库操作。

让我们看看核心 JDBC 的其他问题：

+   JDBC API 异常是被检查的，这迫使开发人员处理错误，增加了应用程序的代码和复杂性

+   在 JDBC 中，我们必须关闭数据库连接；如果开发人员忘记关闭连接，那么我们的应用程序就会出现一些连接问题

# 使用 Spring JDBC 解决问题

为了克服核心 JDBC 的前述问题，Spring 框架提供了与 Spring JDBC 模块的出色数据库集成。Spring JDBC 提供了`JdbcTemplate`类，它帮助我们去除冗余代码，并且帮助开发人员只专注于 SQL 查询和参数。我们只需要配置`JdbcTemplate`与`dataSource`，并编写如下代码：

```java
jdbcTemplate = new JdbcTemplate(dataSource);
int count = jdbcTemplate.queryForObject("SELECT COUNT(*) FROM CUSTOMER", Integer.class);
```

正如我们在前面的例子中看到的，Spring 通过使用 JDBC 模板简化了处理数据库访问的过程。JDBC 模板在内部使用核心 JDBC 代码，并提供了一种新的高效的处理数据库的方式。与核心 JDBC 相比，Spring JDBC 模板具有以下优势：

+   JDBC 模板通过释放数据库连接自动清理资源

+   它将核心 JDBC 的`SQLException`转换为`RuntimeExceptions`，从而提供更好的错误检测机制

+   JDBC 模板提供了各种方法来直接编写 SQL 查询，因此节省了大量的工作和时间

以下图表显示了 Spring JDBC 模板的高级概述：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-hiperf-spr5/img/b5608665-5489-4ffc-b7cd-fef724395459.png)

Spring JDBC 提供的用于访问数据库的各种方法如下：

+   `JdbcTemplate`

+   `NamedParameterJdbcTemplate`

+   `SimpleJdbcTemplate`

+   `SimpleJdbcInsert`

+   `SimpleJdbcCall`

# Spring JDBC 依赖项

Spring JDBC 依赖项在`pom.xml`文件中可用如下：

+   以下代码是 Spring JDBC 的依赖项：

```java
 <dependency>
   <groupId>org.springframework</groupId>
   <artifactId>spring-jdbc</artifactId>
   <version>${spring.framework.version}</version>
 </dependency>
```

+   以下代码是 PostgreSQL 依赖项：

```java
 <dependency>
   <groupId>org.postgresql</groupId>
   <artifactId>postgresql</artifactId>
   <version>42.2.1</version>
 </dependency>
```

在上面的代码中，我们分别指定了 Spring JDBC 和 PostgreSQL 的依赖项。其余的依赖项将由 Maven 自动解析。在这里，我正在使用 PostgreSQL 数据库进行测试，所以我添加了一个 PostgreSQL 依赖项。如果您使用其他 RDBMS，则应相应地更改依赖项。

# Spring JDBC 示例

在这个例子中，我们使用的是 PostgreSQL 数据库。表结构如下：

```java
CREATE TABLE account
(
  accountNumber numeric(10,0) NOT NULL, 
  accountName character varying(60) NOT NULL,
  CONSTRAINT accountNumber_key PRIMARY KEY (accountNumber)
)
WITH (
  OIDS=FALSE
);
```

我们将使用 DAO 模式进行 JDBC 操作，因此让我们创建一个 Java bean 来模拟我们的`Account`表：

```java
package com.packt.springhighperformance.ch5.bankingapp.model;

public class Account {
  private String accountName;
  private Integer accountNumber;

  public String getAccountName() {
    return accountName;
  }

  public void setAccountName(String accountName) {
    this.accountName = accountName;
  }

  public Integer getAccountNumber() {
    return accountNumber;
  }

  public void setAccountNumber(Integer accountNumber) {
    this.accountNumber = accountNumber;
  }
  @Override
  public String toString(){
    return "{accountNumber="+accountNumber+",accountName
    ="+accountName+"}";
  }
}
```

以下的`AccountDao`接口声明了我们要实现的操作：

```java
public interface AccountDao { 
    public void insertAccountWithJdbcTemplate(Account account);
    public Account getAccountdetails();    
}
```

Spring bean 配置类如下。对于 bean 配置，只需使用`@Bean`注解注释一个方法。当`JavaConfig`找到这样的方法时，它将执行该方法并将返回值注册为`BeanFactory`中的 bean。在这里，我们注册了`JdbcTemplate`、`dataSource`和`AccountDao` beans。

```java
@Configuration
public class AppConfig{
  @Bean
  public DataSource dataSource() {
    DriverManagerDataSource dataSource = new DriverManagerDataSource();
    // PostgreSQL database we are using...
    dataSource.setDriverClassName("org.postgresql.Driver");
    dataSource.setUrl("jdbc:postgresql://localhost:5432/TestDB");
    dataSource.setUsername("test");
    dataSource.setPassword("test");
    return dataSource;
  }

  @Bean
  public JdbcTemplate jdbcTemplate() {
    JdbcTemplate jdbcTemplate = new JdbcTemplate();
    jdbcTemplate.setDataSource(dataSource());
    return jdbcTemplate;
  }

  @Bean
  public AccountDao accountDao() {
    AccountDaoImpl accountDao = new AccountDaoImpl();
    accountDao.setJdbcTemplate(jdbcTemplate());
    return accountDao;
  }

}
```

在上一个配置文件中，我们创建了`DriverManagerDataSource`类的`DataSource`对象。这个类提供了一个我们可以使用的`DataSource`的基本实现。我们还将 PostgreSQL 数据库的 URL、用户名和密码作为属性传递给`dataSource` bean。此外，`dataSource` bean 设置为`AccountDaoImpl` bean，我们的 Spring JDBC 实现已经准备就绪。该实现是松散耦合的，如果我们想要切换到其他实现或移动到另一个数据库服务器，那么我们只需要在 bean 配置中进行更改。这是 Spring JDBC 框架提供的主要优势之一。

这是`AccountDAO`的实现，我们在这里使用 Spring 的`JdbcTemplate`类将数据插入表中：

```java
@Repository
public class AccountDaoImpl implements AccountDao {
  private static final Logger LOGGER = 
  Logger.getLogger(AccountDaoImpl.class);

  private JdbcTemplate jdbcTemplate;

  public void setJdbcTemplate(JdbcTemplate jdbcTemplate) {
    this.jdbcTemplate = jdbcTemplate;
  }

  @Override
  public void insertAccountWithJdbcTemplate(Account account) {
    String query = "INSERT INTO ACCOUNT (accountNumber,accountName) 
    VALUES (?,?)";

    Object[] inputs = new Object[] { account.getAccountNumber(), 
    account.getAccountName() };
    jdbcTemplate.update(query, inputs);
    LOGGER.info("Inserted into Account Table Successfully");
  }

  @Override
  public Account getAccountdetails() {
    String query = "SELECT accountNumber, accountName FROM ACCOUNT 
    ";
    Account account = jdbcTemplate.queryForObject(query, new 
    RowMapper<Account>(){
      public Account mapRow(ResultSet rs, int rowNum)
          throws SQLException {
            Account account = new Account();
            account.setAccountNumber(rs.getInt("accountNumber"));
            account.setAccountName(rs.getString("accountName")); 
            return account;
      }});
    LOGGER.info("Account Details : "+account);
    return account; 
  }
}
```

在上一个例子中，我们使用了`org.springframework.jdbc.core.JdbcTemplate`类来访问持久性资源。Spring 的`JdbcTemplate`是 Spring JDBC 核心包中的中心类，提供了许多方法来执行查询并自动解析`ResultSet`以获取对象或对象列表。

以下是上述实现的测试类：

```java
public class MainApp {

  public static void main(String[] args) throws SQLException {
    AnnotationConfigApplicationContext applicationContext = new                             
    AnnotationConfigApplicationContext(
    AppConfig.class);
    AccountDao accountDao = 
    applicationContext.getBean(AccountDao.class);
    Account account = new Account();
    account.setAccountNumber(101);
    account.setAccountName("abc");
    accountDao.insertAccountWithJdbcTemplate(account);
    accountDao.getAccountdetails();
    applicationContext.close();
  }
}
```

当我们运行上一个程序时，我们会得到以下输出：

```java
May 15, 2018 7:34:33 PM org.springframework.context.support.AbstractApplicationContext prepareRefresh
INFO: Refreshing org.springframework.context.annotation.AnnotationConfigApplicationContext@6d5380c2: startup date [Tue May 15 19:34:33 IST 2018]; root of context hierarchy
May 15, 2018 7:34:33 PM org.springframework.jdbc.datasource.DriverManagerDataSource setDriverClassName
INFO: Loaded JDBC driver: org.postgresql.Driver
2018-05-15 19:34:34 INFO AccountDaoImpl:36 - Inserted into Account Table Successfully
2018-05-15 19:34:34 INFO AccountDaoImpl:52 - Account Details : {accountNumber=101,accountName=abc}
May 15, 2018 7:34:34 PM org.springframework.context.support.AbstractApplicationContext doClose
INFO: Closing org.springframework.context.annotation.AnnotationConfigApplicationContext@6d5380c2: startup date [Tue May 15 19:34:33 IST 2018]; root of context hierarchy
```

# 为了实现最佳性能的数据库设计

现在，使用现代工具和流程设计数据库非常容易，但我们必须知道这是我们应用程序的一个非常关键的部分，它直接影响应用程序的性能。一旦应用程序实施了不准确的数据库设计，要修复它就太晚了。我们别无选择，只能购买昂贵的硬件来应对问题。因此，我们应该了解一些数据库表设计、数据库分区和良好索引的基本概念和最佳实践，这些可以提高我们应用程序的性能。让我们看看开发高性能数据库应用程序的基本规则和最佳实践。

# 表设计

表设计类型可以是规范化的或非规范化的，但每种类型都有其自身的好处。如果表设计是规范化的，意味着冗余数据被消除，数据以主键/外键关系逻辑存储，从而提高了数据完整性。如果表设计是非规范化的，意味着增加了数据冗余，并创建了表之间不一致的依赖关系。在非规范化类型中，查询的所有数据通常存储在表中的单行中；这就是为什么检索数据更快，提高了查询性能。在规范化类型中，我们必须在查询中使用连接来从数据库中获取数据，并且由于连接的存在，查询的性能受到影响。我们是否应该使用规范化或非规范化完全取决于我们应用的性质和业务需求。通常，为在线事务处理（OLTP）计划的数据库通常比为在线分析处理（OLAP）计划的数据库更规范化。从性能的角度来看，规范化通常用于需要更多的 INSERT/UPDATE/DELETE 操作的地方，而非规范化用于需要更多 READ 操作的地方。

# 表的垂直分区

在使用垂直分区时，我们将具有许多列的表分割为具有特定列的多个表。例如，我们不应该在很少查询的表中定义非常宽的文本或二进制大对象（BLOB）数据列，因为性能问题。这些数据必须放置在单独的表结构中，并且可以在查询的表中使用指针。

接下来是一个简单的示例，说明我们如何在 customer 表上使用垂直分区，并将二进制数据类型列 customer_Image 移入单独的表中：

```java
CREATE TABLE customer
(
  customer_ID numeric(10,0) NOT NULL, 
  accountName character varying(60) NOT NULL,
  accountNumber numeric(10,0) NOT NULL,
  customer_Image bytea
);
```

垂直分区数据如下：

```java
CREATE TABLE customer
(
  customer_Id numeric(10,0) NOT NULL, 
  accountName character varying(60) NOT NULL,
  accountNumber numeric(10,0) NOT NULL
);

CREATE TABLE customer_Image
(
  customer_Image_ID numeric(10,0) NOT NULL, 
  customer_Id numeric(10,0) NOT NULL, 
  customer_Image bytea
);
```

在 JPA/Hibernate 中，我们可以很容易地将前面的示例映射为表之间的延迟一对多关系。customer_Image 表的数据使用不频繁，因此我们可以将其设置为延迟加载。当客户端请求关系的特定列时，其数据将被检索。

# 使用索引

我们应该为大表上频繁使用的查询使用索引，因为索引功能是改善数据库模式读性能的最佳方式之一。索引条目以排序顺序存储，这有助于处理 GROUP BY 和 ORDER BY 子句。没有索引，数据库在查询执行时必须执行排序操作。通过索引，我们可以最小化查询执行时间并提高查询性能，但在创建表上的索引时，我们应该注意，也有一些缺点。

我们不应该在频繁更新的表上创建太多索引，因为在表上进行任何数据修改时，索引也会发生变化。我们应该在表上最多使用四到五个索引。如果表是只读的，那么我们可以添加更多索引而不必担心。

以下是为您的应用程序构建最有效索引的指南，对每个数据库都适用：

+   为了实现索引的最大效益，我们应该在适当的列上使用索引。索引应该用于那些在查询的 WHERE、ORDER BY 或 GROUP BY 子句中频繁使用的列。

+   始终选择整数数据类型列进行索引，因为它们比其他数据类型列提供更好的性能。保持索引小，因为短索引在 I/O 方面处理更快。

+   对于检索一系列行的查询，聚集索引通常更好。非聚集索引通常更适合点查询。

# 使用正确的数据类型

数据类型确定可以存储在数据库表列中的数据类型。当我们创建表时，应根据其存储需求为每个列定义适当的数据类型。例如，`SMALLINT`占用 2 个字节的空间，而`INT`占用 4 个字节的空间。当我们定义`INT`数据类型时，这意味着我们必须每次将所有 4 个字节存储到该列中。如果我们存储像 10 或 20 这样的数字，那么这是字节的浪费。这最终会使您的读取速度变慢，因为数据库必须读取磁盘的多个扇区。此外，选择正确的数据类型有助于我们将正确的数据存储到列中。例如，如果我们为列使用日期数据类型，则数据库不允许在不表示日期的列中插入任何字符串和数字数据。

# 定义列约束

列约束强制执行对表中可以插入/更新/删除的数据或数据类型的限制。约束的整个目的是在`UPDATE`/`DELETE`/`INSERT`到表中时维护数据完整性。但是，我们应该只在适当的地方定义约束；否则，我们将对性能产生负面影响。例如，定义`NOT NULL`约束在查询处理过程中不会产生明显的开销，但定义`CHECK`约束可能会对性能产生负面影响。

# 使用存储过程

通过使用存储过程在数据库服务器中处理数据来减少网络开销，以及通过在应用程序中缓存数据来减少访问次数，可以调整数据访问性能。

# 事务管理

数据库事务是任何应用程序的关键部分。数据库事务是一系列被视为单个工作单元的操作。这些操作应该完全完成或根本不产生任何效果。对操作序列的管理称为事务管理。事务管理是任何面向 RDBMS 的企业应用程序的重要部分，以确保数据完整性和一致性。事务的概念可以用四个关键属性来描述：原子性、一致性、隔离性和持久性（ACID）。

事务被描述为 ACID，代表以下内容：

+   原子性：事务应被视为单个操作单元，这意味着要么整个操作序列完成，要么根本不起作用

+   一致性：一旦事务完成并提交，那么您的数据和资源将处于符合业务规则的一致状态

+   隔离：如果同时处理同一数据集的许多事务，则每个事务应该与其他事务隔离开，以防止数据损坏

+   持久性：一旦事务完成，事务的结果将被写入持久存储，并且由于系统故障无法从数据库中删除

# 在 Spring 中选择事务管理器

Spring 提供了不同的事务管理器，基于不同的平台。这里，不同的平台意味着不同的持久性框架，如 JDBC、MyBatis、Hibernate 和 Java 事务 API（JTA）。因此，我们必须相应地选择 Spring 提供的事务管理器。

以下图表描述了 Spring 提供的特定于平台的事务管理：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-hiperf-spr5/img/dc325c62-bd48-4502-8b86-fc0af3e09694.jpg)

Spring 支持两种类型的事务管理：

+   程序化：这意味着我们可以直接使用 Java 源代码编写我们的事务。这给了我们极大的灵活性，但很难维护。

+   声明性：这意味着我们可以通过使用 XML 以集中的方式或者通过使用注释以分布式的方式来管理事务。

# 使用@Transactional 声明性 ACID

强烈建议使用声明式事务，因为它们将事务管理从业务逻辑中分离出来，并且易于配置。让我们看一个基于注解的声明式事务管理的示例。

让我们使用在 Spring JDBC 部分中使用的相同示例。在我们的示例中，我们使用`JdbcTemplate`进行数据库交互。因此，我们需要在 Spring 配置文件中添加`DataSourceTransactionManager`。

以下是 Spring bean 配置类：

```java
@Configuration
@EnableTransactionManagement
public class AppConfig {
    @Bean
    public DataSource dataSource() {
        DriverManagerDataSource dataSource = new 
        DriverManagerDataSource(); 
        dataSource.setDriverClassName("org.postgresql.Driver");
        dataSource.setUrl("jdbc:postgresql:
        //localhost:5432/TestDB");
        dataSource.setUsername("test");
        dataSource.setPassword("test");
        return dataSource;
    }

    @Bean
    public JdbcTemplate jdbcTemplate() {
        JdbcTemplate jdbcTemplate = new JdbcTemplate();
        jdbcTemplate.setDataSource(dataSource());
        return jdbcTemplate;
    }

    @Bean
    public AccountDao accountDao(){
      AccountDaoImpl accountDao = new AccountDaoImpl();
      accountDao.setJdbcTemplate(jdbcTemplate());
      return accountDao;
    }

    @Bean
    public PlatformTransactionManager transactionManager() {
        DataSourceTransactionManager transactionManager = new                                             
        DataSourceTransactionManager();
        transactionManager.setDataSource(dataSource());
        return transactionManager;
    }

}
```

在之前的代码中，我们创建了一个`dataSource` bean。它用于创建`DataSource`对象。在这里，我们需要提供数据库配置属性，比如`DriverClassName`、`Url`、`Username`和`Password`。您可以根据您的本地设置更改这些值。

我们正在使用 JDBC 与数据库交互；这就是为什么我们创建了一个`transactionManager`类型为`org.springframework.jdbc.datasource.DataSourceTransactionManager`的 bean。

`@EnableTransactionManagement`注解用于在我们的 Spring 应用程序中启用事务支持。

以下是一个`AccountDao`实现类，用于在`Account`表中创建记录：

```java
@Repository
public class AccountDaoImpl implements AccountDao {
  private static final Logger LOGGER =             
  Logger.getLogger(AccountDaoImpl.class);  
  private JdbcTemplate jdbcTemplate; 

  public void setJdbcTemplate(JdbcTemplate jdbcTemplate) {
    this.jdbcTemplate = jdbcTemplate;
  }

  @Override
  @Transactional
  public void insertAccountWithJdbcTemplate(Account account) {
    String query = "INSERT INTO ACCOUNT (accountNumber,accountName) 
    VALUES (?,?)";    
    Object[] inputs = new Object[] { account.getAccountNumber(),                                 
    account.getAccountName() };
    jdbcTemplate.update(query, inputs);
    LOGGER.info("Inserted into Account Table Successfully");
    throw new RuntimeException("simulate Error condition");
  }
}
```

在前面的代码中，我们通过在`insertAccountWithJdbcTemplate()`方法上注释`@Transactional`提供了声明式事务管理。`@Transactional`注解可以用于方法，也可以用于类级别。在前面的代码中，我在插入`Account`后抛出了`RuntimeException`异常，以检查在生成异常后事务将如何回滚。

以下是用于检查我们的事务管理实现的`main`类：

```java
public class MainApp {

  private static final Logger LOGGER = Logger.getLogger(MainApp.class);

  public static void main(String[] args) throws SQLException {
    AnnotationConfigApplicationContext applicationContext = new 
    AnnotationConfigApplicationContext(
    AppConfig.class);

    AccountDao accountDao = 
    applicationContext.getBean(AccountDao.class); 
    Account account = new Account();
    account.setAccountNumber(202);
    account.setAccountName("xyz");
    accountDao.insertAccountWithJdbcTemplate(account); 
    applicationContext.close();
  }
}
```

现在，当我们运行上面的代码时，我们会得到以下输出：

```java
INFO: Loaded JDBC driver: org.postgresql.Driver
2018-04-09 23:24:09 INFO AccountDaoImpl:36 - Inserted into Account Table Successfully
Exception in thread "main" java.lang.RuntimeException: simulate Error condition at com.packt.springhighperformance.ch5.bankingapp.dao.Impl.AccountDaoImpl.insertAccountWithJdbcTemplate(AccountDaoImpl.java:37)
```

在前面的日志中，数据成功插入到`Account`表中。但是，如果您检查`Account`表，您将找不到一行数据，这意味着在`RuntimeException`之后事务完全回滚。Spring 框架仅在方法成功返回时才提交事务。如果出现异常，它将回滚整个事务。

# 最佳隔离级别

正如我们在前一节中学到的，事务的概念是用 ACID 描述的。事务隔离级别是一个概念，不仅适用于 Spring 框架，而且适用于与数据库交互的任何应用程序。隔离级别定义了一个事务对某个数据存储库所做的更改如何影响其他并发事务，以及更改的数据何时以及如何对其他事务可用。在 Spring 框架中，我们与`@Transaction`注解一起定义事务的隔离级别。

以下片段是一个示例，说明我们如何在事务方法中定义`隔离`级别：

```java
@Autowired
private AccountDao accountDao;

@Transactional(isolation=Isolation.READ_UNCOMMITTED)
public void someTransactionalMethod(User user) {

  // Interact with accountDao

} 
```

在上面的代码中，我们定义了一个具有`READ_UNCOMMITTED`隔离级别的事务方法。这意味着该方法中的事务是以该隔离级别执行的。

让我们在以下部分详细看一下每个`隔离`级别。

# 读取未提交

读取未提交是最低的隔离级别。这种隔离级别定义了事务可以读取其他事务仍未提交的数据，这意味着数据与表或查询的其他部分不一致。这种隔离级别确保了最快的性能，因为数据直接从表块中读取，不需要进一步处理、验证或其他验证；但可能会导致一些问题，比如脏读。

让我们看一下以下图表：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-hiperf-spr5/img/ec6551f4-f0be-4a36-b21d-0bce9c32033e.png)

在上图中，**事务 A**写入数据；与此同时，**事务 B**在**事务 A**提交之前读取了相同的数据。后来，**事务 A**由于某些异常决定**回滚**。现在，**事务 B**中的数据是不一致的。在这里，**事务 B**运行在`READ_UNCOMMITTED`隔离级别，因此它能够在提交之前从**事务 A**中读取数据。

请注意，`READ_UNCOMMITTED`也可能会产生不可重复读和幻读等问题。当事务隔离级别选择为`READ_COMMITTED`时，就会出现不可重复读。

让我们详细看看`READ_COMMITTED`隔离级别。

# 读已提交

读已提交隔离级别定义了事务不能读取其他事务尚未提交的数据。这意味着脏读不再是一个问题，但可能会出现其他问题。

让我们看看以下的图表：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-hiperf-spr5/img/9d62954e-612a-4509-9657-0faac6ad332c.png)

在这个例子中，**事务 A**读取了一些数据。然后，**事务 B**写入了相同的数据并提交。后来，**事务 A**再次读取相同的数据，可能会得到不同的值，因为**事务 B**已经对数据进行了更改并提交。这就是不可重复读。

请注意，`READ_COMMITTED`也可能会产生幻读等问题。幻读发生在选择`REPEATABLE_READ`作为事务隔离级别时。

让我们详细看看`REPEATABLE_READ`隔离级别。

# 可重复读

`REPEATABLE_READ`隔离级别定义了如果一个事务多次从数据库中读取一条记录，那么所有这些读取操作的结果必须相同。这种隔离有助于防止脏读和不可重复读等问题，但可能会产生另一个问题。

让我们看看以下的图表：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-hiperf-spr5/img/d654c888-d00c-4dbe-b0cd-22b71cb75d56.png)

在这个例子中，**事务 A**读取了一段数据。与此同时，**事务 B**在相同的范围内插入了新数据，**事务 A**最初获取并提交了。后来，**事务 A**再次读取相同的范围，也会得到**事务 B**刚刚插入的记录。这就是幻读。在这里，**事务 A**多次从数据库中获取了一系列记录，并得到了不同的结果集。

# 可串行化

可串行化隔离级别是所有隔离级别中最高和最严格的。它可以防止脏读、不可重复读和幻读。事务在所有级别（读、范围和写锁定）上都会执行锁定，因此它们看起来就像是以串行方式执行的。在可串行化隔离中，我们将确保不会发生问题，但同时执行的事务会被串行执行，从而降低了应用程序的性能。

以下是隔离级别和读现象之间关系的总结：

| **级别** | **脏读** | **不可重复读** | **幻读** |
| --- | --- | --- | --- |
| `READ_UNCOMMITTED` | 是 | 是 | 是 |
| `READ_COMMITTED` | 否 | 是 | 是 |
| `REPEATABLE_READ` | 否 | 否 | 是 |
| `SERIALIZABLE` | 否 | 否 | 否 |

如果隔离级别没有被明确设置，那么事务将使用默认的隔离级别，根据相关数据库的设置。

# 最佳的获取大小

应用程序与数据库服务器之间的网络流量是应用程序性能的关键因素之一。如果我们能减少流量，将有助于提高应用程序的性能。获取大小是一次从数据库中检索的行数。它取决于 JDBC 驱动程序。大多数 JDBC 驱动程序的默认获取大小为 10。在正常的 JDBC 编程中，如果要检索 1000 行，那么您将需要在应用程序和数据库服务器之间进行 100 次网络往返以检索所有行。这将增加网络流量，也会影响性能。但是，如果我们将获取大小设置为 100，那么网络往返的次数将为 10。这将极大地提高您的应用程序性能。

许多框架，如 Spring 或 Hibernate，为您提供非常方便的 API 来执行此操作。如果我们不设置获取大小，那么它将采用默认值并提供较差的性能。

以下是使用标准 JDBC 调用设置`FetchSize`的方法：

```java
PreparedStatement stmt = null;
ResultSet rs = null;

try 
{
  stmt = conn. prepareStatement("SELECT a, b, c FROM TABLE");
  stmt.setFetchSize(200);

  rs = stmt.executeQuery();
  while (rs.next()) {
    ...
  }
}
```

在上述代码中，我们可以在每个`Statement`或`PreparedStatement`上设置获取大小，甚至在`ResultSet`上设置。默认情况下，`ResultSet`使用`Statement`的获取大小；`Statement`和`PreparedStatement`使用特定 JDBC 驱动程序的获取大小。

我们还可以在 Spring 的`JdbcTemplate`中设置`FetchSize`：

```java
JdbcTemplate jdbc = new JdbcTemplate(dataSource);
jdbc.setFetchSize(200);
```

设置获取大小时应考虑以下几点：

+   确保您的 JDBC 驱动程序支持配置获取大小。

+   获取大小不应该是硬编码的；保持可配置，因为它取决于 JVM 堆内存大小，在不同环境中会有所不同

+   如果获取的大小很大，应用程序可能会遇到内存不足的问题

# 最佳连接池配置

JDBC 在访问数据库时使用连接池。**连接池**类似于任何其他形式的对象池。连接池通常涉及很少或没有代码修改，但它可以在应用程序性能方面提供显着的好处。数据库连接在创建时执行各种任务，例如在数据库中初始化会话、执行用户身份验证和建立事务上下文。创建连接不是零成本的过程；因此，我们应该以最佳方式创建连接，并减少对性能的影响。连接池允许重用物理连接，并最小化创建和关闭会话的昂贵操作。此外，对于数据库管理系统来说，维护许多空闲连接是昂贵的，连接池可以优化空闲连接的使用或断开不再使用的连接。

为什么连接池有用？以下是一些原因：

+   频繁打开和关闭连接可能很昂贵；最好进行缓存和重用。

+   我们可以限制对数据库的连接数。这将阻止在连接可用之前访问连接。这在分布式环境中特别有帮助。

+   根据我们的需求，我们可以为常见操作使用多个连接池。我们可以为 OLAP 设计一个连接池，为 OLAP 设计另一个连接池，每个连接池都有不同的配置。

在本节中，我们将看到最佳的连接池配置是什么，以帮助提高性能。

以下是用于 PostgreSQL 的简单连接池配置：

```java
<Resource type="javax.sql.DataSource"
            name="jdbc/TestDB"
            factory="org.apache.tomcat.jdbc.pool.DataSourceFactory"
            driverClassName="org.postgresql.Driver"
            url="jdbc:postgresql://localhost:5432/TestDB"
            username="test"
            password="test"
/>
```

# 调整连接池的大小

我们需要使用以下属性来调整连接池的大小：

+   `initialSize`：`initialSize`属性定义了连接池启动时将建立的连接数。

+   `maxActive`：`maxActive`属性可用于限制与数据库建立的最大连接数。

+   `maxIdle`：`maxIdeal`属性用于始终保持池中空闲连接的最大数量。

+   `minIdle`：`minIdeal`属性用于始终保持池中空闲连接的最小数量。

+   `timeBetweenEvictionRunsMillis`：验证/清理线程每隔`timeBetweenEvictionRunsMillis`毫秒运行一次。这是一个后台线程，可以测试空闲的废弃连接，并在池处于活动状态时调整池的大小。该线程还负责检测连接泄漏。此值不应设置为低于 1 秒。

+   `minEvictableIdleTimeMillis`：对象在池中空闲的最短时间。

# 验证连接

设置此配置的优势是无效的连接永远不会被使用，并且有助于防止客户端错误。此配置的缺点是性能会有一些损失，因为要验证连接，需要向数据库发送一次往返的查询来检查会话是否仍然活动。验证是通过向服务器发送一个小查询来完成的，但此查询的成本可能较低。

用于验证连接的配置参数如下：

+   `testOnBorrow`：当定义`testOnBorrow`属性为 true 时，在使用连接对象之前会对其进行验证。如果验证失败，连接对象将被放回池中，然后选择另一个连接对象。在这里，我们需要确保`validationQuery`属性不为空；否则，配置不会产生任何效果。

+   `validationInterval`：`validationInterval`属性定义验证连接的频率。它不应超过 34 秒。如果设置一个较大的值，将提高应用程序的性能，但也会增加应用程序中存在陈旧连接的机会。

+   `validationQuery`：在将连接发送到服务请求之前，使用`SELECT 1` PostgreSQL 查询来验证连接池中的连接。

# 连接泄漏

以下配置设置可以帮助我们检测连接泄漏：

+   `removeAbandoned`：此标志应为 true。这意味着如果连接超过`removeAbandonedTimeout`，则会删除废弃的连接。

+   `removeAbandonedTimeout`：以秒为单位。如果连接运行时间超过`removeAbandonedTimeout`，则认为连接已被废弃。该值取决于应用程序中运行时间最长的查询。

因此，为了获得最佳的池大小，我们需要修改我们的配置以满足以下条件之一：

```java
<Resource type="javax.sql.DataSource"
            name="jdbc/TestDB"
            factory="org.apache.tomcat.jdbc.pool.DataSourceFactory"
            driverClassName="org.postgresql.Driver"
            url="jdbc:postgresql://localhost:5432/TestDB"
            username="test"
            password="test"
            initialSize="10"
            maxActive="100"
            maxIdle="50"
            minIdle="10"
            suspectTimeout="60"
            timeBetweenEvictionRunsMillis="30000"
            minEvictableIdleTimeMillis="60000"
            testOnBorrow="true"
            validationInterval="34000"
            validationQuery="SELECT 1"
            removeAbandoned="true"
            removeAbandonedTimeout="60"
            logAbandoned="true"
/>
```

# Tomcat JDBC 连接池与 HikariCP

有许多开源连接池库可用，如 C3P0、Apache Commons DBCP、BoneCP、Tomcat、Vibur 和 Hikari。但要使用哪一个取决于某些标准。以下标准将帮助决定使用哪个连接池。

# 可靠性

性能总是很好，但是库的可靠性总是比性能更重要。我们不应该选择一个性能更高但不可靠的库。在选择库时应考虑以下事项：

+   它被广泛使用吗？

+   代码是如何维护的？

+   库中尚未解决的 bug 数量。

+   开发者和用户的社区。

+   库的开发活跃程度如何？

# 性能

性能也被视为重要标准。库的性能取决于其配置方式以及测试环境。我们需要确保我们选择的库在我们自己的环境中，以我们自己的配置具有良好的性能。

# 功能

查看库提供的功能也很重要。我们应该检查所有参数，还要检查参数的默认值（如果我们没有提供）。此外，我们需要查看一些连接策略，如自动提交、隔离级别和语句缓存。

# 易用性

使用库时如何轻松配置连接池也很重要。此外，它应该有良好的文档和经常更新。

以下表列出了 Tomcat JDBC 连接池和 HikariCP 之间的区别：

| **Tomcat JDBC** | **HikariCP** |
| --- | --- |
| 默认情况下不在`getConnection()`上测试连接。 | 在`getConnection()`上测试连接。 |
| 不关闭被遗弃的打开语句。 | 跟踪并关闭被遗弃的连接。 |
| 默认情况下不重置连接池中连接的自动提交和事务级别；用户必须配置自定义拦截器来执行此操作。 | 重置自动提交、事务隔离和只读状态。 |
| 不使用池准备语句属性。 | 我们可以使用池准备语句属性。 |
| 默认情况下不在连接返回到池中执行`rollback()`。 | 默认情况下在连接返回到池中执行`rollback()`。 |

# 数据库交互最佳实践

本节列出了开发人员在开发任何应用程序时应该注意的一些基本规则。不遵循这些规则将导致性能不佳的应用程序。

# 使用 Statement 与 PreparedStatement 与 CallableStatement

选择`Statement`、`PreparedStatement`和`CallableStatement`接口之间的区别；这取决于你计划如何使用接口。`Statement`接口针对单次执行 SQL 语句进行了优化，而`PreparedStatement`对象针对将被多次执行的 SQL 语句进行了优化，`CallableStatement`通常用于执行存储过程：

+   `Statement`：`PreparedStatement`用于执行普通的 SQL 查询。当特定的 SQL 查询只需执行一次时，它是首选的。该接口的性能非常低。

+   `PreparedStatement`：`PreparedStatement`接口用于执行参数化或动态 SQL 查询。当特定查询需要多次执行时，它是首选的。该接口的性能优于`Statement`接口（用于多次执行相同查询时）。

+   `CallableStatement`：当要执行存储过程时，首选`CallableStatement`接口。该接口的性能很高。

# 使用批处理而不是 PreparedStatement

向数据库插入大量数据通常是通过准备一个`INSERT`语句并多次执行该语句来完成的。这会增加 JDBC 调用的次数并影响性能。为了减少 JDBC 调用的次数并提高性能，可以使用`PreparedStatement`对象的`addBatch`方法一次向数据库发送多个查询。

让我们看下面的例子：

```java
PreparedStatement ps = conn.prepareStatement(
"INSERT INTO ACCOUNT VALUES (?, ?)");
for (n = 0; n < 100; n++) {
    ps.setInt(accountNumber[n]);
    ps.setString(accountName[n]);
    ps.executeUpdate();
}
```

在前面的例子中，`PreparedStatement`用于多次执行`INSERT`语句。为了执行前面的`INSERT`操作，需要 101 次网络往返：一次是为了准备语句，其余 100 次是为了执行`INSERT` SQL 语句。因此，插入和更新大量数据实际上会增加网络流量，并因此影响性能。

让我们看看如何通过使用“批处理”来减少网络流量并提高性能：

```java
PreparedStatement ps = conn.prepareStatement(
"INSERT INTO ACCOUNT VALUES (?, ?)");
for (n = 0; n < 100; n++) {
    ps.setInt(accountNumber[n]);
    ps.setString(accountName[n]);
    ps.addBatch();
}
ps.executeBatch();
```

在前面的例子中，我使用了`addBatch()`方法。它将所有 100 个`INSERT` SQL 语句合并并仅使用两次网络往返来执行整个操作：一次是为了准备语句，另一次是为了执行合并的 SQL 语句批处理。

# 最小化数据库元数据方法的使用

尽管几乎没有 JDBC 应用程序可以在没有数据库元数据方法的情况下编写，但与其他 JDBC 方法相比，数据库元数据方法很慢。当我们使用元数据方法时，`SELECT`语句会使数据库进行两次往返：一次是为了元数据，另一次是为了数据。这是非常耗费性能的。我们可以通过最小化元数据方法的使用来提高性能。

应用程序应该缓存所有元数据，因为它们不会改变，所以不需要多次执行。

# 有效使用 get 方法

JDBC 提供了不同类型的方法来从结果集中检索数据，如`getInt`，`getString`和`getObject`；`getObject`方法是通用的，可以用于所有数据类型。但是，我们应该始终避免使用`getObject`，因为它的性能比其他方法差。当我们使用`getObject`获取数据时，JDBC 驱动程序必须执行额外的处理来确定正在获取的值的类型，并生成适当的映射。我们应该始终使用特定数据类型的方法；这比使用`getObject`等通用方法提供更好的性能。

我们还可以通过使用列号而不是列名来提高性能；例如，`getInt(1)`，`getString(2)`和`getLong(3)`。如果我们使用列名而不是列号（例如，`getString("accountName")`），那么数据库驱动程序首先将列名转换为大写（如果需要），然后将`accountName`与结果集中的所有列进行比较。这个处理时间直接影响性能。我们应该通过使用列号来减少处理时间。

# 避免连接池的时机

在某些类型的应用程序上使用连接池肯定会降低性能。如果您的应用程序具有以下任何特征，则不适合连接池：

+   如果一个应用程序每天重新启动多次，我们应该避免连接池，因为根据连接池的配置，每次启动应用程序时都可能会填充连接，这将导致前期性能损失。

+   如果您有单用户应用程序，比如只生成报告的应用程序（在这种类型的应用程序中，用户每天只使用应用程序三到四次，用于生成报告），则应避免连接池。与与连接池相关的数据库连接相比，每天建立数据库连接的内存利用率较低。在这种情况下，配置连接池会降低应用程序的整体性能。

+   如果一个应用程序只运行批处理作业，则使用连接池没有任何优势。通常，批处理作业是在一天、一个月或一年的结束时运行，在性能不那么重要的时候运行。

# 谨慎选择提交模式

当我们提交事务时，数据库服务器必须将事务所做的更改写入数据库。这涉及昂贵的磁盘输入/输出和驱动程序需要通过套接字发送请求。

在大多数标准 API 中，默认的提交模式是自动提交。在自动提交模式下，数据库对每个 SQL 语句（如`INSERT`，`UPDATE`，`DELETE`和`SELECT`语句）执行提交。数据库驱动程序在每个 SQL 语句操作后向数据库发送提交请求。这个请求需要一个网络往返。即使 SQL 语句的执行对数据库没有做出任何更改，也会发生与数据库的往返。例如，即使执行`SELECT`语句，驱动程序也会进行网络往返。自动提交模式通常会影响性能，因为需要大量的磁盘输入/输出来提交每个操作。

因此，我们将自动提交模式设置为关闭，以提高应用程序的性能，但保持事务活动也是不可取的。保持事务活动可能会通过长时间持有行锁并阻止其他用户访问行来降低吞吐量。以允许最大并发性的间隔提交事务。

将自动提交模式设置为关闭并进行手动提交对于某些应用程序也是不可取的。例如，考虑一个银行应用程序，允许用户将资金从一个账户转移到另一个账户。为了保护这项工作的数据完整性，需要在更新两个账户的新金额后提交交易。

# 摘要

在本章中，我们清楚地了解了 Spring JDBC 模块，并学习了 Spring JDBC 如何帮助我们消除在核心 JDBC 中使用的样板代码。我们还学习了如何设计我们的数据库以获得最佳性能。我们看到了 Spring 事务管理的各种好处。我们学习了各种配置技术，如隔离级别、获取大小和连接池，这些技术可以提高我们应用程序的性能。最后，我们看了数据库交互的最佳实践，这可以帮助我们提高应用程序的性能。

在下一章中，我们将看到使用 ORM 框架（如 Hibernate）进行数据库交互，并学习 Spring 中的 Hibernate 配置、常见的 Hibernate 陷阱和 Hibernate 性能调优。


# 第六章：Hibernate 性能调优和缓存

在上一章中，我们学习了如何使用 JDBC 在我们的应用程序中访问数据库。我们学习了如何优化设计我们的数据库、事务管理和连接池，以获得应用程序的最佳性能。我们还学习了如何通过使用 JDBC 中的准备语句来防止 SQL 注入。我们看到了如何通过使用 JDBC 模板来消除传统的管理事务、异常和提交的样板代码。

在本章中，我们将向一些高级的访问数据库的方式迈进，使用**对象关系映射**（**ORM**）框架，比如 Hibernate。我们将学习如何通过使用 ORM 以最佳的方式改进数据库访问。通过 Spring Data，我们可以进一步消除实现**数据访问对象**（**DAO**）接口的样板代码。

本章我们将学习以下主题：

+   Spring Hibernate 和 Spring Data 简介

+   Spring Hibernate 配置

+   常见的 Hibernate 陷阱

+   Hibernate 性能调优

# Spring Hibernate 和 Spring Data 简介

正如我们在之前的章节中看到的，**Java 数据库连接**（**JDBC**）暴露了一个 API，隐藏了特定于数据库供应商的通信。然而，它存在以下限制：

+   即使对于琐碎的任务，JDBC 开发也非常冗长

+   JDBC 批处理需要特定的 API，不是透明的

+   JDBC 不提供内置支持显式锁定和乐观并发控制

+   需要显式处理事务，并且有很多重复的代码

+   连接查询需要额外的处理来将`ResultSet`转换为领域模型，或者**数据传输对象**（**DTO**）

几乎所有 JDBC 的限制都被 ORM 框架所覆盖。ORM 框架提供对象映射、延迟加载、急切加载、资源管理、级联、错误处理和其他数据访问层的服务。其中一个 ORM 框架是 Hibernate。**Spring Data**是由 Spring 框架实现的一层，用于提供样板代码并简化应用程序中使用的不同类型的持久性存储的访问。让我们在接下来的章节中看一下 Spring Hibernate 和 Spring Data 的概述。

# Spring Hibernate

Hibernate 起源于 EJB 的复杂性和性能问题。Hibernate 提供了一种抽象 SQL 的方式，并允许开发人员专注于持久化对象。作为 ORM 框架，Hibernate 帮助将对象映射到关系数据库中的表。Hibernate 在引入时有自己的标准，代码与其标准实现紧密耦合。因此，为了使持久性通用化并且与供应商无关，**Java 社区进程**（**JCP**）制定了一个名为**Java 持久化 API**（**JPA**）的标准化 API 规范。所有 ORM 框架都开始遵循这一标准，Hibernate 也是如此。

Spring 并没有实现自己的 ORM；但是，它支持任何 ORM 框架，比如 Hibernate、iBatis、JDO 等。通过 ORM 解决方案，我们可以轻松地将数据持久化并以**普通的 Java 对象**（**POJO**）的形式从关系数据库中访问。Spring 的 ORM 模块是 Spring JDBC DAO 模块的扩展。Spring 还提供了 ORM 模板，比如我们在第五章中看到的基于 JDBC 的模板，*理解 Spring 数据库交互*。

# Spring Data

正如我们所知，在过去几年中，非结构化和非关系型数据库（称为 NoSQL）变得流行。通过 Spring JPA，与关系数据库交流变得容易；那么，我们如何与非关系型数据库交流？Spring 开发了一个名为 Spring Data 的模块，以提供一种通用的方法来与各种数据存储进行交流。

由于每种持久性存储都有不同的连接和检索/更新数据的方式，Spring Data 提供了一种通用的方法来从每个不同的存储中访问数据。

Spring Data 的特点如下：

+   通过各种存储库轻松集成多个数据存储。Spring Data 为每个数据存储提供了通用接口，以存储库的形式。

+   根据存储库方法名称提供的约定解析和形成查询的能力。这减少了需要编写的代码量来获取数据。

+   基本的审计支持，例如由用户创建和更新。

+   与 Spring 核心模块完全集成。

+   与 Spring MVC 集成，通过 Spring Data REST 模块公开**REpresentational State Transfer** (**REST**)控制器。

以下是 Spring Data 存储库的一个小示例。我们不需要实现此方法来编写查询并按 ID 获取帐户；Spring Data 将在内部完成：

```java
public interface AccountRepository extends CrudRepository<Account, Long> {
   Account findByAccountId(Long accountId);
}
```

# Spring Hibernate 配置

我们知道 Hibernate 是一个持久性框架，它提供了对象和数据库表之间的关系映射，并且具有丰富的功能来提高性能和资源的最佳使用，如缓存、急切和延迟加载、事件监听器等。

Spring 框架提供了完整的支持，以集成许多持久性 ORM 框架，Hibernate 也是如此。在这里，我们将看到 Spring 与 JPA，使用 Hibernate 作为持久性提供程序。此外，我们将看到 Spring Data 与使用 Hibernate 的 JPA 存储库。

# 使用 Hibernate 的 Spring 与 JPA

正如我们所知，JPA 不是一个实现；它是持久性的规范。Hibernate 框架遵循所有规范，并且还具有其自己的附加功能。在应用程序中使用 JPA 规范使我们可以在需要时轻松切换持久性提供程序。

要单独使用 Hibernate 需要`SessionFactory`，要使用 Hibernate 与 JPA 需要`EntityManager`。我们将使用 JPA，以下是基于 Spring 的 Hibernate JPA 配置：

```java
@Configuration
@EnableTransactionManagement
@PropertySource({ "classpath:persistence-hibernate.properties" })
@ComponentScan({ "com.packt.springhighperformance.ch6.bankingapp" })
public class PersistenceJPAConfig {

  @Autowired
  private Environment env;

  @Bean
  public LocalContainerEntityManagerFactoryBean entityManagerFactory() {
    LocalContainerEntityManagerFactoryBean em = new 
    LocalContainerEntityManagerFactoryBean();
    em.setDataSource(dataSource());
    em.setPackagesToScan(new String[] { 
    "com.packt.springhighperformance
    .ch6.bankingapp.model" });

    JpaVendorAdapter vendorAdapter = new HibernateJpaVendorAdapter();
    em.setJpaVendorAdapter(vendorAdapter);
    em.setJpaProperties(additionalProperties());

    return em;
  }

  @Bean
  public BeanPostProcessor persistenceTranslation() {
    return new PersistenceExceptionTranslationPostProcessor();
  }

  @Bean
  public DataSource dataSource() {
    DriverManagerDataSource dataSource = new DriverManagerDataSource();
    dataSource.setDriverClassName(this.env.get
    Property("jdbc.driverClassName"));
    dataSource.setUrl(this.env.getProperty("jdbc.url"));
    dataSource.setUsername(this.env.getProperty("jdbc.user"));
    dataSource.setPassword(this.env.getProperty("jdbc.password"));
    return dataSource;
  }

  @Bean
  public PlatformTransactionManager 
  transactionManager(EntityManagerFactory emf) {
      JpaTransactionManager transactionManager = new         
      JpaTransactionManager();
      transactionManager.setEntityManagerFactory(emf);
      return transactionManager;
  }

  @Bean
  public PersistenceExceptionTranslationPostProcessor 
    exceptionTranslation() {
    return new PersistenceExceptionTranslationPostProcessor();
  }

  private Properties additionalProperties() {
    Properties properties = new Properties();
    properties.setProperty("hibernate.hbm2ddl.auto", 
    this.env.getProperty("hibernate.hbm2ddl.auto"));
    properties.setProperty("hibernate.dialect", 
    this.env.getProperty("hibernate.dialect"));
    properties.setProperty("hibernate.generate_statistics", 
    this.env.getProperty("hibernate.generate_statistics"));
    properties.setProperty("hibernate.show_sql", 
    this.env.getProperty("hibernate.show_sql"));
    properties.setProperty("hibernate.cache.use_second_level_cache", 
    this.env.getProperty("hibernate.cache.use_second_level_cache"));
    properties.setProperty("hibernate.cache.use_query_cache", 
    this.env.getProperty("hibernate.cache.use_query_cache"));
    properties.setProperty("hibernate.cache.region.factory_class", 
    this.env.getProperty("hibernate.cache.region.factory_class"));

    return properties;
  }
}
```

在前面的配置中，我们使用`LocalContainerEntityManagerFactoryBean`类配置了`EntityManager`。我们设置了`DataSource`来提供数据库的位置信息。由于我们使用的是 JPA，这是一个由不同供应商遵循的规范，我们通过设置`HibernateJpaVendorAdapter`和设置特定供应商的附加属性来指定我们在应用程序中使用的供应商。

既然我们已经在应用程序中配置了基于 JPA 的 ORM 框架，让我们看看在使用 ORM 时如何在应用程序中创建 DAO。

以下是`AbstractJpaDAO`类，具有所有 DAO 所需的基本公共方法：

```java
public abstract class AbstractJpaDAO<T extends Serializable> {

    private Class<T> clazz;

    @PersistenceContext
    private EntityManager entityManager;

    public final void setClazz(final Class<T> clazzToSet) {
        this.clazz = clazzToSet;
    }

    public T findOne(final Integer id) {
        return entityManager.find(clazz, id);
    }

    @SuppressWarnings("unchecked")
    public List<T> findAll() {
        return entityManager.createQuery("from " + 
        clazz.getName()).getResultList();
    }

    public void create(final T entity) {
        entityManager.persist(entity);
    }

    public T update(final T entity) {
        return entityManager.merge(entity);
    }

    public void delete(final T entity) {
        entityManager.remove(entity);
    }

    public void deleteById(final Long entityId) {
        final T entity = findOne(entityId);
        delete(entity);
    }
}
```

以下是`AccountDAO`类，管理与`Account`实体相关的方法：

```java
@Repository
public class AccountDAO extends AbstractJpaDAO<Account> implements IAccountDAO {

  public AccountDAO() {
    super();
    setClazz(Account.class);
  }
}
```

前面的 DAO 实现示例非常基本，这通常是我们在应用程序中做的。如果 DAO 抛出诸如`PersistenceException`之类的异常，而不是向用户显示异常，我们希望向最终用户显示正确的可读消息。为了在发生异常时提供可读的消息，Spring 提供了一个翻译器，我们需要在我们的配置类中定义如下：

```java
@Bean
  public BeanPostProcessor persistenceTranslation() {
    return new PersistenceExceptionTranslationPostProcessor();
  }
```

当我们用`@Repository`注解我们的 DAO 时，`BeanPostProcessor`命令会起作用。`PersistenceExceptionTranslationPostProcessor` bean 将作为对使用`@Repository`注解的 bean 的顾问。请记住，我们在第三章中学习了关于建议的内容，*调整面向方面的编程*。在受到建议时，它将重新抛出在代码中捕获的 Spring 特定的未检查数据访问异常。

因此，这是使用 Hibernate 的 Spring JPA 的基本配置。现在，让我们看看 Spring Data 配置。

# Spring Data 配置

正如我们在介绍中学到的，Spring Data 提供了连接不同数据存储的通用方法。Spring Data 通过 `Repository` 接口提供基本的抽象。Spring Data 提供的基本存储库如下：

+   `CrudRepository` 提供基本的 CRUD 操作

+   `PagingAndSortingRepository` 提供了对记录进行分页和排序的方法

+   `JpaRepository` 提供了与 JPA 相关的方法，如批量刷新和插入/更新/删除等

在 Spring Data 中，`Repository` 消除了 DAO 和模板的实现，如 `HibernateTemplate` 或 `JdbcTemplate`。Spring Data 是如此抽象，以至于我们甚至不需要为基本的 CRUD 操作编写任何方法实现；我们只需要基于 `Repository` 定义接口，并为方法定义适当的命名约定。Spring Data 将负责根据方法名创建查询，并将其执行到数据库中。

Spring Data 的 Java 配置与我们在使用 Hibernate 的 Spring JPA 中看到的相同，只是添加了定义存储库。以下是声明存储库到配置的片段：

```java
@Configuration
@EnableTransactionManagement
@PropertySource({ "classpath:persistence-hibernate.properties" })
@ComponentScan({ "com.packt.springhighperformance.ch6.bankingapp" })
 @EnableJpaRepositories(basePackages = "com.packt.springhighperformance.ch6.bankingapp.repository")
public class PersistenceJPAConfig {

}
```

在本章中，我们不会深入探讨 Hibernate 和 Spring Data 特定的开发。但是，我们将深入探讨在我们的应用程序中不适当使用 Hibernate 或 JPA 以及正确配置时所面临的问题，并提供解决问题的解决方案，以及实现高性能的最佳实践。让我们看看在我们的应用程序中使用 Hibernate 时常见的问题。

# 常见的 Hibernate 陷阱

JPA 和 Hibernate ORM 是大多数 Java 应用中使用的最流行的框架，用于与关系数据库交互。它们的流行度增加是因为它们使用面向对象域和底层关系数据库之间的映射来抽象数据库交互，并且非常容易实现简单的 CRUD 操作。

在这种抽象下，Hibernate 使用了许多优化，并将所有数据库交互隐藏在其 API 后面。通常情况下，我们甚至不知道 Hibernate 何时会执行 SQL 语句。由于这种抽象，很难找到低效和潜在性能问题。让我们看看我们应用中常见的 Hibernate 问题。

# Hibernate n + 1 问题

在使用 JPA 和 Hibernate 时，获取类型对应用程序的性能产生了很大影响。我们应该始终获取我们需要满足给定业务需求的数据。为此，我们将关联实体的 `FetchType` 设置为 `LAZY`。当我们将这些关联实体的获取类型设置为 `LAZY` 时，我们在我们的应用程序中实现了嵌套查询，因为我们不知道在 ORM 框架提供的抽象下这些关联是如何获取的。嵌套查询只是两个查询，其中一个是外部或主查询（从表中获取结果），另一个是针对主查询的每一行结果执行的（从其他表中获取相应或相关数据）。

以下示例显示了我们无意中实现了嵌套查询的情况：

```java
Account account = this.em.find(Account.class, accountNumber);
List<Transaction> lAccountTransactions = account.getTransaction();
for(Transaction transaction : lAccountTransactions){
  //.....
}
```

大多数情况下，开发人员倾向于编写像前面的示例一样的代码，并且不会意识到像 Hibernate 这样的 ORM 框架可能在内部获取数据。在这里，像 Hibernate 这样的 ORM 框架执行一个查询来获取 `account`，并执行第二个查询来获取该 `account` 的交易。两个查询是可以接受的，并且不会对性能产生太大影响。这两个查询是针对实体中的一个关联。

假设我们在`Account`实体中有五个关联：`Transactions`，`UserProfile`，`Payee`等等。当我们尝试从`Account`实体中获取每个关联时，框架会为每个关联执行一个查询，导致 1 + 5 = 6 个查询。六个查询不会有太大影响，对吧？这些查询是针对一个用户的，那么如果我们的应用程序的并发用户数量是 100 呢？那么我们将有 100 * (1 + 5) = 600 个查询。现在，这将对性能产生影响。在获取`Account`时的这 1 + 5 个查询被称为 Hibernate 中的**n + 1**问题。在本章的*Hibernate 性能调优*部分，我们将看到一些避免这个问题的方法。

# 在视图中打开会话的反模式

我们在前面的部分中看到，为了推迟获取直到需要关联实体时，我们将关联实体的获取类型设置为`LAZY`。当我们在呈现层尝试访问这些关联实体时（如果它们在我们的业务（服务）层中没有被初始化），Hibernate 会抛出一个异常，称为`LazyInitializationException`。当服务层方法完成执行时，Hibernate 提交事务并关闭会话。因此，在呈现视图时，活动会话不可用于获取关联实体。

为了避免`LazyInitializationException`，其中一个解决方案是在视图中保持一个开放的会话。这意味着我们在视图中保持 Hibernate 会话处于打开状态，以便呈现层可以获取所需的关联实体，然后关闭会话。

为了启用这个解决方案，我们需要向我们的应用程序添加一个 web 过滤器。如果我们只使用 Hibernate，我们需要添加`filter`，`OpenSessionInViewFilter`；如果我们使用 JPA，那么我们需要添加`filter` `OpenEntityManagerInViewFilter`。由于在本章中我们使用的是 JPA 与 Hibernate，以下是添加`filter`的片段：

```java
<filter>
    <filter-name>OpenEntityManagerInViewFilter</filter-name>
    <filter-class>org.springframework.orm.jpa.support.OpenEntityManagerInViewFilter</filter-class>
   ....
</filter>
...
<filter-mapping>
    <filter-name>OpenEntityManagerInViewFilter</filter-name>
    <url-pattern>/*</url-pattern>
</filter-mapping>
```

**开放会话在视图**（**OSIV**）模式提供的解决方案乍看起来可能不那么糟糕；然而，使用 OSIV 解决方案存在一些问题。让我们来看看 OSIV 解决方案的一些问题：

1.  服务层在其方法被调用时打开事务，并在方法执行完成时关闭它。之后，就没有显式的打开事务了。从视图层执行的每个额外查询都将在自动提交模式下执行。自动提交模式在安全和数据库方面可能是危险的。由于自动提交模式，数据库需要立即将所有事务日志刷新到磁盘，导致高 I/O 操作。

1.  这将违反 SOLID 原则中的单一责任，或者关注点分离，因为数据库语句由服务层和呈现层都执行。

1.  这将导致我们在前面*Hibernate n + 1 问题*部分看到的 n + 1 问题，尽管 Hibernate 提供了一些解决方案来应对这种情况：`@BatchSize`和`FetchMode.SUBSELECT`，但是，这些解决方案将适用于所有的业务需求，不管我们是否想要。

1.  数据库连接保持到呈现层完成渲染。这会增加整体数据库连接时间并影响事务吞吐量。

1.  如果在获取会话或在数据库中执行查询时发生异常，它将发生在呈现视图时，因此不可行地向用户呈现一个干净的错误页面。

# 未知的 Id.generator 异常

大多数情况下，我们希望为我们的表主键使用数据库序列。为了做到这一点，我们知道我们需要在我们的实体上的`@GeneratedValue`注解中添加`generator`属性。`@GeneratedValue`注解允许我们为我们的主键定义一个策略。

以下是我们在实体中添加的代码片段，用于为我们的主键设置数据库序列：

```java
@Id
@GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "accountSequence")
private Integer id;
```

在这里，我们认为`accountSequence`是提供给`generator`的数据库序列名称；然而，当应用程序运行时，它会产生异常。为了解决这个异常，我们使用`@SequenceGenerator`注解我们的实体，并给出名称为`accountSequence`，以及 Hibernate 需要使用的数据库序列名称。以下是如何设置`@SequenceGenerator`注解的示例：

```java
@Id
@GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "accountSequence")
@SequenceGenerator(name = "accountSequence", sequenceName = "account_seq", initialValue = 100000)
private Long accountId;
```

我们看到了在实现过程中遇到的常见问题。现在，让我们看看如何调优 Hibernate 以实现高性能。

# Hibernate 性能调优

在前面的部分中，我们看到了常见的 Hibernate 陷阱或问题。这些问题并不一定意味着 Hibernate 的错误；有时是由于框架的错误使用，有时是 ORM 框架本身的限制。在接下来的部分中，我们将看到如何提高 Hibernate 的性能。

# 避免 n + 1 问题的方法

我们已经在*Hibernate n + 1 问题*部分看到了 n + 1 问题。太多的查询会减慢我们应用的整体性能。因此，为了避免懒加载导致的额外查询，让我们看看有哪些可用的选项。

# 使用 JPQL 进行 Fetch join

通常，我们调用 DAO 的`findById`方法来获取外部或父实体，然后调用关联的 getter 方法。这样做会导致 n + 1 查询，因为框架会为每个关联执行额外的查询。相反，我们可以使用`EntityManager`的`createQuery`方法编写一个 JPQL 查询。在这个查询中，我们可以使用`JOIN FETCH`来连接我们想要与外部实体一起获取的关联实体。以下是如何获取`JOIN FETCH`实体的示例：

```java
Query query = getEntityManager().createQuery("SELECT a FROM Account AS a JOIN FETCH a.transactions WHERE a.accountId=:accountId", Account.class);
query.setParameter("accountId", accountId);
return (Account)query.getSingleResult();
```

以下是记录表明只执行了一个查询的日志：

```java
2018-03-14 22:19:29 DEBUG ConcurrentStatisticsImpl:394 - HHH000117: HQL: SELECT a FROM Account AS a JOIN FETCH a.transactions WHERE a.accountId=:accountId, time: 72ms, rows: 3
Transactions:::3
2018-03-14 22:19:29 INFO StatisticalLoggingSessionEventListener:258 - Session Metrics {
    26342110 nanoseconds spent acquiring 1 JDBC connections;
    0 nanoseconds spent releasing 0 JDBC connections;
    520204 nanoseconds spent preparing 1 JDBC statements;
    4487788 nanoseconds spent executing 1 JDBC statements;
    0 nanoseconds spent executing 0 JDBC batches;
    0 nanoseconds spent performing 0 L2C puts;
    0 nanoseconds spent performing 0 L2C hits;
    0 nanoseconds spent performing 0 L2C misses;
    13503978 nanoseconds spent executing 1 flushes (flushing a total of 
    4 entities and 1 collections);
    56615 nanoseconds spent executing 1 partial-flushes (flushing a 
    total of 0 entities and 0 collections)
}
```

`JOIN FETCH`告诉`entityManager`在同一个查询中加载所选实体以及关联的实体。

这种方法的优点是 Hibernate 在一个查询中获取所有内容。从性能的角度来看，这个选项很好，因为所有内容都在一个查询中获取，而不是多个查询。这减少了每个单独查询对数据库的往返。

这种方法的缺点是我们需要编写额外的代码来执行查询。如果实体有许多关联，并且我们需要为每个不同的用例获取不同的关联，那么情况就会变得更糟。因此，为了满足每个不同的用例，我们需要编写不同的查询，带有所需的关联。对于每个用例编写太多不同的查询会变得非常混乱，也很难维护。

如果需要不同的连接获取组合的查询数量较少，这个选项将是一个很好的方法。

# 在 Criteria API 中的连接获取

这种方法和 JPQL 中的`JOIN FETCH`一样；但是这次我们使用的是 Hibernate 的 Criteria API。以下是如何在 Criteria API 中使用`JOIN FETCH`的示例：

```java
CriteriaBuilder criteriaBuilder = 
    getEntityManager().getCriteriaBuilder();
    CriteriaQuery<?> query = 
    criteriaBuilder.createQuery(Account.class);
    Root root = query.from(Account.class);
    root.fetch("transactions", JoinType.INNER);
    query.select(root);
    query.where(criteriaBuilder.equal(root.get("accountId"), 
    accountId));

    return (Account)this.getEntityManager().createQuery(query)
   .getSingleResult();
```

这个选项和 JPQL 一样有优点和缺点。大多数情况下，当我们使用 Criteria API 编写查询时，它是特定于用例的。因此，在这些情况下，这个选项可能不是一个很大的问题，它是减少执行的查询数量的一个很好的方法。

# 命名实体图

然后命名实体图是 JPA 2.1 中引入的一个新特性。在这种方法中，我们可以定义需要从数据库查询的实体图。我们可以通过使用`@NamedEntityGraph`注解在我们的实体类上定义实体图。

以下是如何在实体类上使用`@NamedEntityGraph`定义图的示例：

```java
@Entity
@NamedEntityGraph(name="graph.transactions", attributeNodes= @NamedAttributeNode("transactions"))
public class Account implements Serializable {

  private static final long serialVersionUID = 1232821417960547743L;

  @Id
  @GeneratedValue(strategy = GenerationType.AUTO)
  @Column(name = "account_id", updatable = false, nullable = false)
  private Long accountId;
  private String name;

  @OneToMany(mappedBy = "account", fetch=FetchType.LAZY)
  private List<Transaction> transactions = new ArrayList<Transaction>
  ();
.....
}
```

实体图定义独立于查询，并定义从数据库中获取哪些属性。实体图可以用作加载或提取图。如果使用加载图，则未在实体图定义中指定的所有属性将继续遵循其默认的`FetchType.`如果使用提取图，则只有实体图定义指定的属性将被视为`FetchType.EAGER`，而所有其他属性将被视为`LAZY`。以下是如何将命名实体图用作`fetchgraph`的示例：

```java
EntityGraph<?> entityGraph = getEntityManager().createEntityGraph("graph.transactions");
Query query = getEntityManager().createQuery("SELECT a FROM Account AS a WHERE a.accountId=:accountId", Account.class);

query.setHint("javax.persistence.fetchgraph", entityGraph);
query.setParameter("accountId", accountId);
return (Account)query.getSingleResult();
```

我们不打算在本书中详细介绍命名实体图。这是解决 Hibernate 中 n + 1 问题的最佳方法之一。这是`JOIN FETCH`的改进版本。与`JOIN FETCH`相比的优势是它将被用于不同的用例。这种方法的唯一缺点是我们必须为我们想要在单个查询中获取的每种关联组合注释命名实体图。因此，如果我们有太多不同的组合要设置，这可能会变得非常混乱。

# 动态实体图

动态实体图类似于命名实体图，不同之处在于我们可以通过 Java API 动态定义它。以下是使用 Java API 定义实体图的示例：

```java
EntityGraph<?> entityGraph = getEntityManager().createEntityGraph(Account.class);
entityGraph.addSubgraph("transactions");
Map<String, Object> hints = new HashMap<String, Object>();
hints.put("javax.persistence.fetchgraph", entityGraph);

return this.getEntityManager().find(Account.class, accountId, hints);
```

因此，如果我们有大量特定于用例的实体图，这种方法将优于命名实体图，在这种方法中，为每个用例在我们的实体上添加注释会使代码难以阅读。我们可以将所有特定于用例的实体图保留在我们的业务逻辑中。使用这种方法的缺点是我们需要编写更多的代码，并且为了使代码可重用，我们需要为每个相关的业务逻辑编写更多的方法。

# 使用 Hibernate 统计信息查找性能问题

大多数情况下，我们在生产系统上面临缓慢的响应，而我们的本地或测试系统运行良好。这些情况大多是由于数据库查询缓慢引起的。在本地实例中，我们不知道我们在生产中有多少请求和数据量。那么，我们如何找出哪个查询导致问题，而不向我们的应用程序代码添加日志？答案是 Hibernate `generate_statistics`配置。

我们需要将 Hibernate 属性`generate_statistics`设置为 true，因为默认情况下此属性为 false。此属性会影响整体性能，因为它记录所有数据库活动。因此，只有在要分析缓慢查询时才启用此属性。此属性将生成总结的多行日志，显示在数据库交互上花费了多少总时间。

如果我们想要记录每个查询的执行，我们需要在日志配置中将`org.hibernate.stat`启用为`DEBUG`级别；同样，如果我们想要记录 SQL 查询（带时间），我们需要将`org.hibernate.SQL`启用为`DEBUG`级别。

以下是打印日志的示例：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-hiperf-spr5/img/b8713ce6-c5b1-47e8-bd83-65dc3a0024f0.png)

Hibernate 生成统计日志

总体统计信息日志显示了使用的 JDBC 连接数、语句、缓存和执行的刷新次数。我们总是需要首先检查语句的数量，以查看是否存在 n + 1 问题。

# 使用特定于查询的获取

始终建议仅选择我们用例所需的列。如果使用`CriteriaQuery`，请使用投影选择所需的列。当表具有太多列时，获取整个实体会降低应用程序的性能，因此数据库需要浏览存储页面的每个块来检索它们，而且我们在用例中可能并不需要所有这些列。此外，如果我们使用实体而不是 DTO 类，持久性上下文必须管理实体，并在需要时获取关联/子实体。这会增加额外开销。而不是获取整个实体，只获取所需的列：

```java
SELECT a FROM Account a WHERE a.accountId= 123456;
```

按如下方式获取特定列：

```java
SELECT a.accountId, a.name FROM Account a WHERE a.accountId = 123456;
```

使用特定查询获取的更好方法是使用 DTO 投影。我们的实体由持久性上下文管理。因此，如果我们想要更新它，将`ResultSet`获取到实体会更容易。我们将新值设置给 setter 方法，Hibernate 将负责更新它的 SQL 语句。这种便利性是以性能为代价的，因为 Hibernate 需要对所有受管理的实体进行脏检查，以找出是否需要将任何更改保存到数据库。DTO 是 POJO 类，与我们的实体相同，但不受持久性管理。

我们可以通过使用构造函数表达式在 JPQL 中获取特定列，如下所示：

```java
entityManager.createQuery("SELECT new com.packt.springhighperformance.ch6.bankingapp.dto.AccountDto(a.id, a.name) FROM Account a").getResultList();
```

同样，我们可以通过使用`CriteriaQuery`和`JPAMetamodel`来做同样的事情，如下所示：

```java
CriteriaBuilder cb = em.getCriteriaBuilder();
CriteriaQuery q = cb.createQuery(AccountDTO.class);
Root root = q.from(Account.class);
q.select(cb.construct(AccountDTO.class, root.get(Account_.accountNumber), root.get(Account_.name)));

List authors = em.createQuery(q).getResultList();
```

# 缓存及其最佳实践

我们已经看到了 Spring 中缓存是如何工作的，在第三章中，*调整面向方面的编程*。在这里，我们将看到 Hibernate 中缓存是如何工作的，以及 Hibernate 中有哪些不同类型的缓存。在 Hibernate 中，有三种不同类型的缓存，如下所示：

+   一级缓存

+   二级缓存

+   查询缓存

让我们了解 Hibernate 中每种缓存机制是如何工作的。

# 一级缓存

在一级缓存中，Hibernate 在会话对象中缓存实体。Hibernate 一级缓存默认启用，我们无法禁用它。但是，Hibernate 提供了方法，通过这些方法我们可以从缓存中删除特定对象，或者完全清除会话对象中的缓存。

由于 Hibernate 在会话对象中进行一级缓存，任何缓存的对象对另一个会话是不可见的。当会话关闭时，缓存被清除。我们不打算详细介绍这种缓存机制，因为它默认可用，没有办法调整或禁用它。有一些方法可以了解这个级别的缓存，如下所示：

+   使用会话的`evict()`方法从 Hibernate 一级缓存中删除单个对象

+   使用会话的`clear()`方法完全清除缓存

+   使用会话的`contains()`方法检查对象是否存在于 Hibernate 缓存中

# 二级缓存

数据库抽象层（例如 ORM 框架）的一个好处是它们能够透明地缓存数据：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-hiperf-spr5/img/2dae2d40-0d0d-4fef-b6dd-23bcd4e3a988.jpg)

在数据库和应用程序级别进行缓存

对于许多大型企业应用程序来说，应用程序缓存并不是一个选项。通过应用程序缓存，我们可以减少从数据库缓存中获取所需数据的往返次数。应用程序级缓存存储整个对象，这些对象是根据哈希表键检索的。在这里，我们不打算讨论应用程序级缓存；我们将讨论二级缓存。

在 Hibernate 中，与一级缓存不同，二级缓存是`SessionFactory`范围的；因此，它由同一会话工厂内创建的所有会话共享。当启用二级缓存并查找实体时，以下内容适用：

1.  如果实例可用，它将首先在一级缓存中进行检查，然后返回。

1.  如果一级缓存中不存在实例，它将尝试在二级缓存中查找，如果找到，则组装并返回。

1.  如果在二级缓存中找不到实例，它将前往数据库并获取数据。然后将数据组装并返回。

Hibernate 本身不进行任何缓存。它提供了接口`org.hibernate.cache.spi.RegionFactory`，缓存提供程序对此接口进行实现。在这里，我们将讨论成熟且最广泛使用的缓存提供程序 Ehcache。为了启用二级缓存，我们需要将以下两行添加到我们的持久性属性中：

```java
hibernate.cache.use_second_level_cache=true
hibernate.cache.region.factory_class=org.hibernate.cache.ehcache.EhCacheRegionFactory
```

启用二级缓存后，我们需要定义要缓存的实体；我们需要使用`@org.hibernate.annotations.Cache`对这些实体进行注释，如下所示：

```java
@Entity
@Cacheable
@org.hibernate.annotations.Cache(usage = CacheConcurrencyStrategy.READ_WRITE)
public class Account implements Serializable {

}
```

Hibernate 使用单独的缓存区域来存储实体实例的状态。区域名称是完全限定的类名。Hibernate 提供了不同的并发策略，我们可以根据需求使用。以下是不同的并发策略：

+   `READ_ONLY`：仅用于从不修改的实体；在修改时会抛出异常。用于一些静态参考数据，不会更改。

+   `NONSTRICT_READ_WRITE`：在影响缓存数据的事务提交时更新缓存。在更新缓存时，有可能从缓存中获取陈旧的数据。此策略适用于可以容忍最终一致性的要求。此策略适用于很少更新的数据。

+   `READ_WRITE`：为了在更新缓存时避免获取陈旧数据，此策略使用软锁。当缓存的实体被更新时，缓存中的实体被锁定，并在事务提交后释放。所有并发事务将直接从数据库中检索相应的数据。

+   `TRANSACTIONAL`：事务策略主要用于 JTA 环境中的分布式缓存。

如果未定义过期和驱逐策略，缓存可能会无限增长，并最终消耗所有内存。我们需要设置这些策略，这取决于缓存提供程序。在这里，我们使用 Ehcache，并且以下是在`ehcache.xml`中定义过期和驱逐策略的方法：

```java
<ehcache>
    <cache 
    name="com.packt.springhighperformance.ch6.bankingapp.model.Account"     
    maxElementsInMemory="1000" timeToIdleSeconds="0"     
    timeToLiveSeconds="10"/>
</ehcache>
```

我们中的许多人认为缓存存储整个对象。但是，它并不存储整个对象，而是以分解状态存储它们：

+   主键不存储，因为它是缓存键

+   瞬态属性不存储

+   默认情况下不存储集合关联

+   除关联之外的所有属性值都以其原始形式存储

+   `@ToOne`关联的外键仅存储 ID

# 查询缓存

可以通过添加以下 Hibernate 属性来启用查询缓存：

```java
hibernate.cache.use_query_cache=true
```

启用查询缓存后，我们可以指定要缓存的查询，如下所示：

```java
Query query = entityManager.createQuery("SELECT a FROM Account a WHERE a.accountId=:accountId", Account.class);
query.setParameter("accountId", 7L);
query.setHint(QueryHints.HINT_CACHEABLE, true);
Account account = (Account)query.getSingleResult();
```

如果我们再次执行已被查询缓存缓存的相同查询，则在`DEBUG`模式下打印以下日志：

```java
2018-03-17 15:39:07 DEBUG StandardQueryCache:181 - Returning cached query results
2018-03-17 15:39:07 DEBUG SQL:92 - select account0_.account_id as account_1_0_0_, account0_.name as name2_0_0_ from Account account0_ where account0_.account_id=?
```

# 批量执行更新和删除

正如我们所知，ORM 框架（如 Hibernate）在更新或删除实体时会执行两个或更多查询。如果我们要更新或删除少量实体，这是可以接受的，但是想象一下我们要更新或删除 100 个实体的情况。Hibernate 将执行 100 个`SELECT`查询来获取实体，然后执行另外 100 个查询来更新或删除实体。

为了实现任何应用程序的更好性能，需要执行更少的数据库语句。如果我们使用 JPQL 或本地 SQL 执行相同的更新或删除操作，可以在单个语句中完成。Hibernate 作为 ORM 框架提供了许多好处，可以帮助我们专注于业务逻辑，而不是数据库操作。在 Hibernate 可能昂贵的情况下，例如批量更新和删除，我们应该使用本地数据库查询来避免开销并实现更好的性能。

以下是我们可以执行本机查询以将银行收件箱中所有用户的电子邮件更新为“已读”的方法：

```java
entityManager.createNativeQuery("UPDATE mails p SET read = 'Y' WHERE user_id=?").setParameter(0, 123456).executeUpdate();
```

我们可以通过记录`System.currentTimeMillis()`来测量使用 Hibernate 方法和本机查询更新大量数据的性能差异。本机查询的性能应该显著提高，比 Hibernate 方法快 10 倍。

本地查询肯定会提高批量操作的性能，但与此同时，它会带来一级缓存的问题，并且不会触发任何实体生命周期事件。众所周知，Hibernate 将我们在会话中使用的所有实体存储在一级缓存中。这对于写后优化很有好处，并且避免在同一会话中为相同的实体执行重复的选择语句。但是，对于本地查询，Hibernate 不知道哪些实体已更新或删除，并相应地更新一级缓存。如果我们在同一会话中在执行本地查询之前获取实体，则它将继续在缓存中使用实体的过时版本。以下是使用本地查询时一级缓存的问题示例：

```java
private void performBulkUpdateIssue(){
    Account account = this.entityManager.find(Account.class, 7L);

    entityManager.createNativeQuery("UPDATE account a SET name = 
    name 
    || '-updated'").executeUpdate();
    _logger.warn("Issue with Account Name: "+account.getName());

    account = this.entityManager.find(Account.class, 7L);
    _logger.warn("Issue with Account Name: "+account.getName());
  }
```

解决这个问题的方法是在本地查询执行之前手动更新一级缓存，通过在本地查询执行之前分离实体，然后在本地查询执行后重新附加它。为此，请执行以下操作：

```java
private void performBulkUpdateResolution(){
    //make sure you are passing right account id    
    Account account = this.entityManager.find(Account.class, 7L);

 //remove from persistence context
 entityManager.flush();
 entityManager.detach(account);
    entityManager.createNativeQuery("UPDATE account a SET name = 
    name 
    || '-changed'").executeUpdate();
    _logger.warn("Resolution Account Name: "+account.getName());

    account = this.entityManager.find(Account.class, 7L);
    _logger.warn("Resolution Account Name: "+account.getName());
  }
```

在执行本地查询之前，请调用`flush()`和`detach()`方法。`flush()`方法告诉 Hibernate 将一级缓存中的更改实体写入数据库。这是为了确保我们不会丢失任何更新。

# Hibernate 编程实践

到目前为止，我们看到了当 Hibernate 没有被最佳利用时出现的问题，以及如何使用 Hibernate 来实现更好的性能。以下是在使用 JPA 和 Hibernate 时遵循的最佳实践（在缓存和一般情况下）以实现更好的性能。

# 缓存

以下是关于 Hibernate 不同缓存级别的一些编程提示：

+   确保使用与 Hibernate 版本相同的`hibernate-ehcache`版本。

+   由于 Hibernate 将所有对象缓存到会话的一级缓存中，因此在运行批量查询或批量更新时，有必要定期清除缓存以避免内存问题。

+   在使用二级缓存缓存实体时，默认情况下不会缓存实体内的集合。为了缓存集合，需要在实体内用`@Cacheable`和`@org.hibernate.annotations.Cache(usage = CacheConcurrencyStrategy.READ_WRITE)`注释集合。每个集合都存储在二级缓存中的单独区域中，区域名称是实体类的完全限定名称加上集合属性的名称。为每个缓存的集合单独定义过期和驱逐策略。

+   当使用 JPQL 执行 DML 语句时，Hibernate 将更新/驱逐这些实体的缓存；然而，当使用本地查询时，整个二级缓存将被驱逐，除非在使用 Hibernate 与 JPA 时添加以下细节到本地查询执行中：

```java
Query nativeQuery = entityManager.createNativeQuery("update Account set name='xyz' where name='abc'");

nativeQuery.unwrap(org.hibernate.SQLQuery.class).addSynchronizedEntityClass(Account.class);

nativeQuery.executeUpdate();
```

+   在查询缓存的情况下，每个查询和参数值的组合将有一个缓存条目，因此对于预期有不同参数值组合的查询，不适合缓存。

+   在查询缓存的情况下，对于从数据库中频繁更改的实体类进行抓取的查询不适合缓存，因为当涉及查询的任何实体发生更改时，缓存将被作废。

+   所有查询缓存结果都存储在`org.hibernate.cache.internal.StandardQueryCache`区域。我们可以为这个区域指定过期和驱逐策略。此外，如果需要，我们可以使用查询提示`org.hibernate.cacheRegion`为特定查询设置不同的缓存区域。

+   Hibernate 在名为`org.hibernate.cache.spi.UpdateTimestampsCache`的区域中保留了所有查询缓存表的最后更新时间戳。Hibernate 使用这个来验证缓存的查询结果是否过时。最好关闭此缓存区域的自动驱逐和过期，因为只要缓存结果区域中有缓存的查询结果，这个缓存中的条目就不应该被驱逐/过期。

# 杂项

以下是实现应用程序更好性能的一般 Hibernate 最佳实践：

+   避免在生产系统上启用`generate_statistics`；而是通过在生产系统的暂存或副本上启用`generate_statistics`来分析问题。

+   Hibernate 始终更新所有数据库列，即使我们只更新一个或几个列。`UPDATE`语句中的所有列将比少数列花费更多时间。为了实现高性能并避免在`UPDATE`语句中使用所有列，只包括实际修改的列，并在实体上使用`@DynamicUpdate`注释。此注释告诉 Hibernate 为每个更新操作生成一个新的 SQL 语句，仅包含修改的列。

+   将默认的`FetchType`设置为`LAZY`以用于所有关联，并使用特定于查询的获取，使用`JOIN FETCH`，命名实体图或动态实体图，以避免 n + 1 问题并提高性能。

+   始终使用绑定参数以避免 SQL 注入并提高性能。与绑定参数一起使用时，如果多次执行相同的查询，Hibernate 和数据库会优化查询。

+   在大型列表中执行`UPDATE`或`DELETE`，而不是逐个执行它们。我们已经在*在大量中执行更新和删除*部分中讨论过这一点。

+   不要对只读操作使用实体；而是使用 JPA 和 Hibernate 提供的不同投影。我们已经看到的一个是 DTO 投影。对于只读需求，将实体更改为`SELECT`中的构造函数表达式非常容易，并且将实现高性能。

+   随着 Java 8.0 中 Stream API 的引入，许多人使用其功能来处理从数据库检索的大量数据。Stream 旨在处理大量数据。但是数据库可以做一些事情比 Stream API 更好。不要对以下要求使用 Stream API：

+   过滤数据：数据库可以更有效地过滤数据，而我们可以使用`WHERE`子句来实现

+   限制数据：当我们想要限制要检索的数据的数量时，数据库提供比 Stream API 更有效的结果

+   排序数据：数据库可以通过使用`ORDER BY`子句更有效地进行排序，而不是 Stream API

+   使用排序而不是排序，特别是对于大量关联数据的实体。排序是 Hibernate 特定的，不是 JPA 规范：

+   Hibernate 使用 Java 比较器在内存中进行排序。但是，可以使用关联实体上的`@OrderBy`注释从数据库中检索相同所需顺序的数据。

+   如果未指定列名，则将在主键上执行`@OrderBy`。

+   可以在`@OrderBy`中指定多个列，以逗号分隔。

+   数据库比在 Java 中实现排序更有效地处理`@OrderBy`。以下是一个代码片段，作为示例：

```java
@OneToMany(mappedBy = "account", fetch=FetchType.LAZY)
@OrderBy("created DESC")
private List<Transaction> transactions = new ArrayList<Transaction>();
```

+   Hibernate 定期对与当前`PersistenceContext`关联的所有实体执行脏检查，以检测所需的数据库更新。对于从不更新的实体，例如只读数据库视图或表，执行脏检查是一种开销。使用`@Immutable`对这些实体进行注释，Hibernate 将在所有脏检查中忽略它们，从而提高性能。

+   永远不要定义单向的一对多关系；总是定义双向关系。如果定义了单向的一对多关系，Hibernate 将需要一个额外的表来存储两个表的引用，就像在多对多关系中一样。在单向方法的情况下，会执行许多额外的 SQL 语句，这对性能不利。为了获得更好的性能，在实体的拥有方上注释`@JoinColumn`，并在实体的另一侧使用`mappedby`属性。这将减少 SQL 语句的数量，提高性能。需要明确处理从关系中添加和删除实体；因此，建议在父实体中编写辅助方法，如下所示：

```java
@Entity
public class Account {

    @Id
    @GeneratedValue
    private Integer id;

 @OneToMany(mappedBy = "account")
    private List<Transaction> transactions = new ArrayList<>();

    public void addTransaction(Transaction transaction) {
 transactions.add(transaction);
 transaction.setPost(this);
 }

 public void removeTransaction(Transaction transaction) {
 transactions.remove(transaction);
 transaction.setPost(null);
 }
}

@Entity
public class Transaction {

    @Id
    @GeneratedValue
    private Integer id;

    @ManyToOne(fetch = FetchType.LAZY)
 @JoinColumn(name = "account_id")
    private Account account;
}

```

# 摘要

我们从基本配置 ORM 框架 Hibernate 开始了本章，使用 JPA 和 Spring Data。我们关注了在生产中遇到的常见 ORM 问题。在本章中，我们学习了在使用 Hibernate 进行数据库操作和实现高性能时所面临的常见问题的最佳解决方案。我们学习了在基于 ORM 的框架上工作时要遵循的最佳实践，以在开发阶段就实现高性能，而不是在生产系统中面对问题时解决它们。

与优化和高性能一致，下一章提供了关于 Spring 消息优化的信息。正如您所知，消息框架企业应用程序连接多个客户端，并提供可靠性、异步通信和松散耦合。框架被构建为提供各种好处；然而，如果我们不以最佳方式使用它们，就会面临问题。同样，如果有效使用与队列配置和可伸缩性相关的某些参数，将最大化我们企业应用程序的 Spring 消息框架的吞吐量。
