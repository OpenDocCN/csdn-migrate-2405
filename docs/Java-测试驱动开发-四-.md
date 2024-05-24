# Java 测试驱动开发（四）

> 原文：[`zh.annas-archive.org/md5/ccd393a1b3d624be903cafab189c1930`](https://zh.annas-archive.org/md5/ccd393a1b3d624be903cafab189c1930)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十章：功能切换-部分完成功能的部署到生产环境

“不要让环境控制你。你改变你的环境。”

- 成龙

到目前为止，我们已经看到 TDD 如何使开发过程更容易，并减少了编写高质量代码所花费的时间。但还有另一个特殊的好处。随着代码被测试并且其正确性得到证明，我们可以进一步假设一旦所有测试都通过，我们的代码就已经准备好投入生产了。

有一些基于这个想法的软件生命周期方法。一些极限编程（XP）实践，如持续集成（CI）、持续交付和持续部署（CD）将被介绍。代码示例可以在[`bitbucket.org/alexgarcia/packt-tdd-java/src/`](https://bitbucket.org/alexgarcia/packt-tdd-java/src/)的`10-feature-toggles`文件夹中找到。

本章将涵盖以下主题：

+   持续集成、交付和部署

+   在生产环境中测试应用程序

+   功能切换

# 持续集成、交付和部署

TDD 与 CI、持续交付或 CD 密切相关。除了区别之外，这三种技术都有相似的目标。它们都试图促进对我们的代码的生产准备状态进行持续验证。在这方面，它们与 TDD 非常相似。它们都倡导非常短的开发周期，持续验证我们正在生产的代码，并持续保持我们的应用程序处于生产准备状态的意图。

本书的范围不允许我们详细介绍这些技术。事实上，整本书都可以写关于这个主题。我们只是简要解释一下这三者之间的区别。实践持续集成意味着我们的代码（几乎）始终与系统的其他部分集成在一起，如果出现问题，它将很快显现出来。如果发生这样的事情，首要任务是修复问题的原因，这意味着任何新的开发必须降低优先级。你可能已经注意到这个定义与 TDD 的工作方式之间的相似之处。主要区别在于，TDD 的主要重点不是与系统的其他部分集成。其他方面都是一样的。TDD 和 CI 都试图快速检测问题并将修复它们作为最高优先级，将其他一切搁置。CI 并没有整个流程自动化，需要在代码部署到生产环境之前进行额外的手动验证。

持续交付与持续集成非常相似，只是前者走得更远，整个流程都是自动化的，除了实际部署到生产环境。每次推送到仓库并通过所有验证的代码都被视为可以部署到生产环境的有效代码。然而，部署的决定是手动进行的。需要有人选择其中一个构建版本并将其推广到生产环境。选择是政治性的或功能性的。这取决于我们想要用户在什么时候接收到什么内容，尽管每个版本都已经准备好投入生产。

“持续交付是一种软件开发纪律，通过这种方式构建软件，软件可以随时发布到生产环境。”

- 马丁·福勒

最后，当关于部署什么的决定也被自动化时，CD 就完成了。在这种情况下，通过了所有验证的每次提交都会被部署到生产环境，没有例外。

为了持续将我们的代码集成或交付到生产环境，不能存在分支，或者创建分支和将其与主线集成的时间必须非常短（一天以内，最好是几个小时）。如果不是这样，我们就不能持续验证我们的代码。

与 TDD 的真正联系来自于在提交代码之前创建验证的必要性。如果这些验证没有提前创建，推送到存储库的代码就没有伴随着测试，流程就会失败。没有测试，我们对自己的工作没有信心。没有 TDD，就没有测试来伴随我们的实现代码。或者，推送提交到存储库直到创建测试，但在这种情况下，流程中就没有连续的部分。代码一直停留在某人的计算机上，直到其他人完成测试。停留在某处的代码没有持续地针对整个系统进行验证。

总之，持续集成、交付和部署依赖于测试来伴随集成代码（因此依赖于 TDD），并且不使用分支或使它们的生命周期非常短暂（很频繁地合并到主线）。问题在于一些功能无法那么快地开发。无论我们的功能有多小，在某些情况下可能需要几天来开发它们。在这段时间内，我们不能推送到存储库，因为这个流程会将它们交付到生产环境。用户不想看到部分功能。例如，交付登录流程的一部分是没有意义的。如果有人看到一个带有用户名、密码和登录按钮的登录页面，但是按钮后面的流程实际上并没有存储这些信息并提供，比如，认证 cookie，那么最好我们只会让用户感到困惑。在其他一些情况下，一个功能离开另一个功能是无法工作的。按照同样的例子，即使登录功能完全开发，没有注册就是没有意义的。一个功能离开另一个功能是无法使用的。

想象一下玩拼图。我们需要对最终图片有一个大致的想法，但我们专注于一次只处理一个拼图。我们挑选一个我们认为最容易放置的拼图，并将它与它的邻居组合在一起。只有当它们全部就位时，图片才完整，我们才完成了。

同样适用于 TDD。我们通过专注于小单元来开发我们的代码。随着我们的进展，它们开始相互配合，直到它们全部集成。当我们等待这种情况发生时，即使我们的所有测试都通过了，我们处于绿色状态，代码也还没有准备好交付给最终用户。

解决这些问题并且不妥协 TDD 和 CI/CD 的最简单方法是使用功能切换。

# 功能切换

你可能也听说过这个叫做**功能翻转**或**功能标志**。无论我们使用哪种表达方式，它们都基于一种机制，允许你打开和关闭应用程序的功能。当所有代码合并到一个分支时，你必须处理部分完成（或集成）的代码时，这是非常有用的。使用这种技术，未完成的功能可以被隐藏，以便用户无法访问它们。

由于其性质，这个功能还有其他可能的用途。例如，当特定功能出现问题时，作为断路器，提供应用程序的优雅降级，关闭次要功能以保留硬件资源用于业务核心操作等。在某些情况下，功能切换甚至可以更进一步。我们可以使用它们仅向特定用户启用功能，例如基于地理位置或他们的角色。另一个用途是我们可以仅为我们的测试人员启用新功能。这样，最终用户将继续对一些新功能的存在毫不知情，而测试人员将能够在生产服务器上验证它们。

此外，在使用功能切换时，还有一些需要记住的方面：

+   只有在完全部署并被证明有效之前才使用切换。否则，你可能最终会得到充满旧的切换的意大利面代码，其中包含不再使用的`if`/`else`语句。

+   不要花太多时间测试切换。在大多数情况下，确认某个新功能的入口点不可见就足够了。例如，这可以是指向新功能的链接。

+   不要过度使用切换。当不需要时不要使用它们。例如，您可能正在开发一个可以通过主页上的链接访问的新屏幕。如果该链接是在最后添加的，可能没有必要有一个隐藏它的切换。

有许多用于应用程序特性处理的良好框架和库。其中两个是以下：

+   **Togglz** ([`www.togglz.org/`](http://www.togglz.org/))

+   **FF4J** ([`ff4j.org/`](http://ff4j.org/))

这些库提供了一种复杂的方式来管理特性，甚至添加基于角色或规则的特性访问。在许多情况下，您可能不需要它，但这些功能使我们有可能在生产中测试新功能而不向所有用户开放。但是，实现自定义基本解决方案以进行特性切换非常简单，我们将通过一个示例来说明这一点。

# 特性切换示例

我们来看看我们的演示应用程序。这一次，我们将构建一个简单而小的**REpresentational State Transfer**（**REST**）服务，以按需计算 Fibonacci 序列的具体 N^(th)位置。我们将使用文件跟踪启用/禁用的特性。为简单起见，我们将使用 Spring Boot 作为我们的框架选择，并使用 Thymeleaf 作为模板引擎。这也包含在 Spring Boot 依赖项中。在[`projects.spring.io/spring-boot/`](http://projects.spring.io/spring-boot/)上找到有关 Spring Boot 和相关项目的更多信息。此外，您可以访问[`www.thymeleaf.org/`](http://www.thymeleaf.org/)了解有关模板引擎的更多信息。

这是`build.gradle`文件的样子：

```java
apply plugin: 'java' 
apply plugin: 'application' 

sourceCompatibility = 1.8 
version = '1.0' 
mainClassName = "com.packtpublishing.tddjava.ch09.Application" 

repositories { 
    mavenLocal() 
    mavenCentral() 
} 

dependencies { 
    compile group: 'org.springframework.boot', 
            name: 'spring-boot-starter-thymeleaf', 
            version: '1.2.4.RELEASE' 

    testCompile group: 'junit', 
    name: 'junit', 
    version: '4.12' 
} 
```

请注意，应用程序插件存在，因为我们希望使用 Gradle 命令`run`运行应用程序。这是应用程序的`main`类：

```java
@SpringBootApplication 
public class Application { 
    public static void main(String[] args) { 
        SpringApplication.run(Application.class, args); 
    } 
} 
```

我们将创建属性文件。这一次，我们将使用**YAML Ain't Markup Language**（**YAML**）格式，因为它非常全面和简洁。在`src/main/resources`文件夹中添加一个名为`application.yml`的文件，内容如下：

```java
features: 
    fibonacci: 
        restEnabled: false 
```

Spring 提供了一种自动加载这种属性文件的方法。目前只有两个限制：名称必须是`application.yml`和/或文件应包含在应用程序的类路径中。

这是我们对特性`config`文件的实现：

```java
@Configuration 
@EnableConfigurationProperties 
@ConfigurationProperties(prefix = "features.fibonacci") 
public class FibonacciFeatureConfig { 
    private boolean restEnabled; 

    public boolean isRestEnabled() { 
        return restEnabled; 
    } 

    public void setRestEnabled(boolean restEnabled) { 
        this.restEnabled = restEnabled; 
    } 
} 
```

这是`fibonacci`服务类。这一次，计算操作将始终返回`-1`，只是为了模拟一个部分完成的功能：

```java
@Service("fibonacci") 
public class FibonacciService { 

    public int getNthNumber(int n) { 
        return -1; 
    } 
} 
```

我们还需要一个包装器来保存计算出的值：

```java
public class FibonacciNumber { 
    private final int number, value; 

    public FibonacciNumber(int number, int value) { 
        this.number = number; 
        this.value = value; 
    } 

    public int getNumber() { 
        return number; 
    } 

    public int getValue() { 
        return value; 
    } 
} 
```

这是`FibonacciRESTController`类，负责处理`fibonacci`服务查询：

```java
@RestController 
public class FibonacciRestController { 
    @Autowired 
    FibonacciFeatureConfig fibonacciFeatureConfig; 

    @Autowired 
    @Qualifier("fibonacci") 
    private FibonacciService fibonacciProvider; 

    @RequestMapping(value = "/fibonacci", method = GET) 
    public FibonacciNumber fibonacci( 
            @RequestParam( 
                    value = "number", 
                    defaultValue = "0") int number) { 
        if (fibonacciFeatureConfig.isRestEnabled()) { 
            int fibonacciValue = fibonacciProvider 
                    .getNthNumber(number); 
            return new FibonacciNumber(number, fibonacciValue); 
        } else throw new UnsupportedOperationException(); 
    } 

    @ExceptionHandler(UnsupportedOperationException.class) 
    public void unsupportedException(HttpServletResponse response) 
            throws IOException { 
        response.sendError( 
                HttpStatus.SERVICE_UNAVAILABLE.value(), 
                "This feature is currently unavailable" 
        ); 
    } 

    @ExceptionHandler(Exception.class) 
    public void handleGenericException( 
            HttpServletResponse response, 
            Exception e) throws IOException { 
        String msg = "There was an error processing " + 
                "your request: " + e.getMessage(); 
        response.sendError( 
                HttpStatus.BAD_REQUEST.value(), 
                msg 
        ); 
    } 
} 
```

请注意，`fibonacci`方法正在检查`fibonacci`服务是否应启用或禁用，在最后一种情况下为方便抛出`UnsupportedOperationException`。还有两个错误处理函数；第一个用于处理`UnsupportedOperationException`，第二个用于处理通用异常。

现在所有组件都已设置好，我们需要做的就是执行 Gradle 的

`run`命令：

```java
    $> gradle run

```

该命令将启动一个进程，最终将在以下地址上设置服务器：`http://localhost:8080`。这可以在控制台输出中观察到：

```java
    ...
    2015-06-19 03:44:54.157  INFO 3886 --- [           main] o.s.w.s.handler.SimpleUrlHandlerMapping  : Mapped URL path [/webjars/**] onto handler of type [class org.springframework.web.servlet.resource.ResourceHttpRequestHandler]
    2015-06-19 03:44:54.160  INFO 3886 --- [           main] o.s.w.s.handler.SimpleUrlHandlerMapping  : Mapped URL path [/**] onto handler of type [class org.springframework.web.servlet.resource.ResourceHttpRequestHandler]
    2015-06-19 03:44:54.319  INFO 3886 --- [           main] o.s.w.s.handler.SimpleUrlHandlerMapping  : Mapped URL path [/**/favicon.ico] onto handler of type [class org.springframework.web.servlet.resource.ResourceHttpRequestHandler]
    2015-06-19 03:44:54.495  INFO 3886 --- [           main] o.s.j.e.a.AnnotationMBeanExporter        : Registering beans for JMX exposure on startup
    2015-06-19 03:44:54.649  INFO 3886 --- [           main] s.b.c.e.t.TomcatEmbeddedServletContainer : Tomcat started on port(s): 8080 (http)
    2015-06-19 03:44:54.654  INFO 3886 --- [           main] c.p.tddjava.ch09.Application             : Started Application in 6.916 seconds (JVM running for 8.558)
    > Building 75% > :run

```

应用程序启动后，我们可以使用常规浏览器执行查询。查询的 URL 是`http://localhost:8080/fibonacci?number=7`。

这给我们以下输出：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/test-dvn-java-dev/img/9da0fbdc-44da-432f-a293-4782b2751e9f.png)

正如您所看到的，收到的错误对应于 REST API 在禁用特性时发送的错误。否则，返回值应为`-1`。

# 实现 Fibonacci 服务

你们大多数人可能都熟悉斐波那契数。无论如何，这里还是一个简要的解释，供那些不知道它们是什么的人参考。

斐波那契数列是一个整数序列，由递推*f(n) = f(n-1) - f(n - 2)*得出。该序列以*f(0) = 0*和*f(1) = 1*开始。所有其他数字都是通过多次应用递推生成的，直到可以使用 0 或 1 个已知值进行值替换为止。

即：0, 1, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144,...有关斐波那契数列的更多信息可以在这里找到：[`www.wolframalpha.com/input/?i=fibonacci+sequence`](http://www.wolframalpha.com/input/?i=fibonacci+sequence)

作为额外功能，我们希望限制值计算所需的时间，因此我们对输入施加约束；我们的服务只会计算从`0`到`30`的斐波那契数（包括这两个数字）。

这是一个计算斐波那契数的可能实现类：

```java
@Service("fibonacci") 
public class FibonacciService { 
    public static final int LIMIT = 30; 

    public int getNthNumber(int n) { 
        if (isOutOfLimits(n) { 
        throw new IllegalArgumentException( 
        "Requested number must be a positive " + 
           number no bigger than " + LIMIT); 
        if (n == 0) return 0; 
        if (n == 1 || n == 2) return 1; 
        int first, second = 1, result = 1; 
        do { 
            first = second; 
            second = result; 
            result = first + second; 
            --n; 
        } while (n > 2); 
        return result; 
    } 

    private boolean isOutOfLimits(int number) { 
        return number > LIMIT || number < 0; 
    } 
} 
```

为了简洁起见，TDD 红-绿-重构过程没有在演示中明确解释，但在开发过程中一直存在。只呈现了最终实现和最终测试：

```java
public class FibonacciServiceTest { 
    private FibonacciService tested; 
    private final String expectedExceptionMessage = 
         "Requested number " + 
            "must be a positive number no bigger than " +  
            FibonacciService.LIMIT; 

    @Rule 
    public ExpectedException exception = ExpectedException.none(); 

    @Before 
    public void beforeTest() { 
        tested = new FibonacciService(); 
    } 

    @Test 
    public void test0() { 
        int actual = tested.getNthNumber(0); 
        assertEquals(0, actual); 
    } 

    @Test 
    public void test1() { 
        int actual = tested.getNthNumber(1); 
        assertEquals(1, actual); 
    } 

    @Test 
    public void test7() { 
        int actual = tested.getNthNumber(7); 
        assertEquals(13, actual); 
    } 

    @Test 
    public void testNegative() { 
        exception.expect(IllegalArgumentException.class); 
        exception.expectMessage(is(expectedExceptionMessage)); 
        tested.getNthNumber(-1); 
    } 

    @Test 
    public void testOutOfBounce() { 
        exception.expect(IllegalArgumentException.class); 
        exception.expectMessage(is(expectedExceptionMessage)); 
        tested.getNthNumber(31); 
    } 
} 
```

现在，我们可以在`application.yml`文件中打开`fibonacci`功能，用浏览器执行一些查询，并检查它的运行情况：

```java
features: 
    fibonacci: 
        restEnabled: true 
```

执行 Gradle 的`run`命令：

```java
    $>gradle run
```

现在我们可以使用浏览器完全测试我们的 REST API，使用一个介于`0`和`30`之间的数字：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/test-dvn-java-dev/img/aa63d9c5-147d-49a5-95ad-99b9cb66c21d.png)

然后，我们用一个大于`30`的数字进行测试，最后用字符代替数字进行测试：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/test-dvn-java-dev/img/554eb35c-9550-4abf-8bb8-2a88ef7eaae9.png)

# 使用模板引擎

我们正在启用和禁用`fibonacci`功能，但还有许多其他情况下，功能切换可以非常有用。其中之一是隐藏链接到未完成功能的网页链接。这是一个有趣的用法，因为我们可以使用其 URL 测试我们发布到生产环境的内容，但对于其他用户来说，它将被隐藏，只要我们想要。

为了说明这种行为，我们将使用已经提到的 Thymeleaf 框架创建一个简单的网页。

首先，我们添加一个新的`control`标志：

```java
features: 
    fibonacci: 
        restEnabled: true 
        webEnabled: true 
```

接下来，在配置类中映射这个新的标志：

```java
    private boolean webEnabled; 
    public boolean isWebEnabled() { 
        return webEnabled; 
    } 

    public void setWebEnabled(boolean webEnabled) { 
        this.webEnabled = webEnabled; 
    } 
```

我们将创建两个模板。第一个是主页。它包含一些链接到不同的斐波那契数计算。这些链接只有在启用功能时才可见，因此有一个可选的块来模拟这种行为：

```java
<!DOCTYPE html> 
<html > 
<head lang="en"> 
    <meta http-equiv="Content-Type" 
          content="text/html; charset=UTF-8" /> 
    <title>HOME - Fibonacci</title> 
</head> 
<body> 
<div th:if="${isWebEnabled}"> 
    <p>List of links:</p> 
    <ul th:each="number : ${arrayOfInts}"> 
        <li><a 
            th:href="@{/web/fibonacci(number=${number})}" 
            th:text="'Compute ' + ${number} + 'th fibonacci'"> 
        </a></li> 
    </ul> 
</div> 
</body> 
</html> 
```

第二个模板只显示计算出的斐波那契数的值，还有一个链接返回主页：

```java
<!DOCTYPE html> 
<html > 
<head lang="en"> 
    <meta http-equiv="Content-Type" 
          content="text/html; charset=UTF-8" /> 
    <title>Fibonacci Example</title> 
</head> 
<body> 
<p th:text="${number} + 'th number: ' + ${value}"></p> 
<a th:href="@{/}">back</a> 
</body> 
</html> 
```

为了使这两个模板都能正常工作，它们应该放在特定的位置。它们分别是`src/main/resources/templates/home.html`和`src/main/resources/templates/fibonacci.html`。

最后，这是连接所有内容并使其工作的控制器的杰作：

```java
@Controller 
public class FibonacciWebController { 
    @Autowired 
    FibonacciFeatureConfig fibonacciFeatureConfig; 

    @Autowired 
    @Qualifier("fibonacci") 
    private FibonacciService fibonacciProvider; 

    @RequestMapping(value = "/", method = GET) 
    public String home(Model model) { 
        model.addAttribute( 
            "isWebEnabled", 
            fibonacciFeatureConfig.isWebEnabled() 
        ); 
        if (fibonacciFeatureConfig.isWebEnabled()) { 
            model.addAttribute( 
                "arrayOfInts", 
                Arrays.asList(5, 7, 8, 16) 
            ); 
        } 
        return "home"; 
    } 

    @RequestMapping(value ="/web/fibonacci", method = GET) 
    public String fibonacci( 
            @RequestParam(value = "number") Integer number, 
            Model model) { 
        if (number != null) { 
            model.addAttribute("number", number); 
            model.addAttribute( 
                "value", 
                fibonacciProvider.getNthNumber(number)); 
        } 
        return "fibonacci"; 
    } 
} 
```

请注意，这个控制器和之前在 REST API 示例中看到的控制器有一些相似之处。这是因为两者都是用相同的框架构建的，并且使用相同的资源。但是，它们之间有一些细微的差异；一个被注释为`@Controller`，而不是两者都是`@RestController`。这是因为 Web 控制器提供带有自定义信息的模板页面，而 REST API 生成 JSON 对象响应。

让我们看看这个工作，再次使用这个 Gradle 命令：

```java
    $> gradle clean run

```

这是生成的主页：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/test-dvn-java-dev/img/e9b8caa6-9e02-4fc0-876b-ed6f62e03ca4.png)

当访问斐波那契数链接时，会显示这个：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/test-dvn-java-dev/img/5aaee666-9dbf-4a26-ad4e-40880a149824.png)

但我们使用以下代码关闭该功能：

```java
features: 
    fibonacci: 
        restEnabled: true 
        webEnabled: false 
```

重新启动应用程序，我们浏览到主页，看到那些链接不再显示，但如果我们已经知道 URL，我们仍然可以访问页面。如果我们手动输入`http://localhost:8080/web/fibonacci?number=15`，我们仍然可以访问页面：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/test-dvn-java-dev/img/56aced76-f40d-47b9-9178-488ff47cf1bc.png)

这种实践非常有用，但通常会给您的代码增加不必要的复杂性。不要忘记重构代码，删除您不再使用的旧切换。这将使您的代码保持清晰和可读。另外，一个很好的点是在不重新启动应用程序的情况下使其工作。有许多存储选项不需要重新启动，数据库是最受欢迎的。

# 总结

功能切换是在生产环境中隐藏和/或处理部分完成的功能的一种不错的方式。对于那些按需部署代码到生产环境的人来说，这可能听起来很奇怪，但在实践持续集成、交付或部署时，发现这种情况是相当常见的。

我们已经介绍了这项技术并讨论了其利弊。我们还列举了一些典型情况，说明切换功能可以帮助解决问题。最后，我们实现了两种不同的用例：一个具有非常简单的 REST API 的功能切换，以及一个 Web 应用中的功能切换。

尽管本章中介绍的代码是完全功能的，但通常不常使用基于文件的属性系统来处理此事。有许多更适合生产环境的库可以帮助我们实现这种技术，提供许多功能，例如使用 Web 界面处理功能、将偏好存储在数据库中或允许访问具体用户配置文件。

在下一章中，我们将把书中描述的 TDD 概念整合在一起。我们将提出一些编程 TDD 方式时非常有用的良好实践和建议。


# 第十一章：将所有内容整合在一起

“如果你总是做你一直做的事情，那么你将永远得到你一直得到的东西。”

- 阿尔伯特·爱因斯坦

我们经历了大量的理论，然后进行了更多的实践。整个过程就像一辆飞驰的火车，我们几乎没有机会重复所学的知识。没有休息的时间。

好消息是，现在是反思的时候了。我们将总结我们学到的一切，并学习 TDD 的最佳实践。其中一些已经提到，而其他一些将是新的。

本章涵盖的主题包括：

+   TDD 简而言之

+   命名测试的常见约定和良好实践

+   工具

+   下一步

# TDD 简而言之

**红-绿-重构**是 TDD 的支柱，将其包装成一个简短且可重复的循环。简短意味着非常短。每个阶段的时间通常以分钟甚至秒计算。编写测试，看到它失败，编写足够的实现代码使最后一个测试通过，运行所有测试，并进入绿色阶段。一旦编写了最少的代码，以便我们通过测试获得安全性，就是重构代码的时候了，直到它变得像我们希望的那样好。在这个阶段，测试应该始终通过。在重构过程中不能引入新功能或新测试。在如此短的时间内完成所有这些往往是可怕的，或者听起来可能是不可能的。我们希望通过我们一起做的练习，你的技能已经得到了提高，你的信心和速度也得到了提高。

虽然 TDD 中有“测试”一词，但这并不是主要的好处或目标。TDD 首先是一个更好的设计代码的概念。除此之外，我们最终得到的测试应该用于不断检查应用程序是否按预期继续工作。

之前经常提到速度的重要性。虽然我们在 TDD 方面变得更加熟练是其中的一部分，另一个贡献者是测试替身（模拟、存根、间谍等）。有了这些，我们可以消除对数据库、文件系统、第三方服务等外部依赖的需求。

TDD 的其他好处是什么？文档是其中之一。由于代码本身是我们正在处理的应用程序的唯一准确且始终是最新的表示，使用 TDD 编写的规范（同样也是代码）是我们需要更好地理解代码作用时应该首先去查看的地方。

设计呢？你注意到 TDD 产生了更好设计的代码。与事先定义设计不同，使用 TDD 设计往往是在我们从一个规范进展到另一个规范时逐渐出现的。同时，易于测试的代码就是设计良好的代码。测试迫使我们应用一些编码最佳实践。

我们还了解到 TDD 不仅需要在小单元（方法）上进行。它也可以在更高层次上使用，重点是一个可以跨越多个方法、类，甚至应用程序和系统的特性或行为。在这样一个高层次上实践 TDD 的形式之一是**行为驱动开发**（**BDD**）。与 TDD 不同，它是基于开发人员为开发人员进行的单元测试，BDD 可以被组织中的几乎所有人使用。由于它涉及行为，并且是用自然（无处不在的）语言编写的，测试人员、经理、业务代表等都可以参与其创建，并在以后将其用作参考。

我们将遗留代码定义为没有测试的代码。我们面对了遗留代码给我们带来的一些挑战，并学习了一些可以用来使其可测试的技术。

牢记这一切，让我们一起学习 TDD 的最佳实践。

# 最佳实践

编码最佳实践是软件开发社区随着时间发展出的一套非正式规则，可以帮助提高软件的质量。虽然每个应用都需要一定程度的创造力和原创性（毕竟，我们试图构建一些新的或更好的东西），编码实践可以帮助我们避免一些其他人在我们之前遇到的问题。如果你刚开始使用 TDD，应用一些（如果不是全部）由他人生成的最佳实践是一个好主意。

为了更容易分类 TDD 最佳实践，我们将它们分为四类：

+   命名约定

+   流程

+   开发实践

+   工具

正如你将看到的，它们并不都是 TDD 专用的。由于 TDD 的很大一部分包括编写测试，因此以下部分介绍的许多最佳实践适用于一般测试，而其他一些则与一般编码最佳实践相关。无论起源如何，当练习 TDD 时，所有这些都是有用的。

以一定的怀疑态度接受建议。成为一名优秀的程序员不仅仅是知道如何编码，还包括能够决定哪种实践、框架或风格最适合项目和团队。灵活并不是指遵循别人的规则，而是知道如何适应环境并选择最适合团队和项目的最佳工具和实践。

# 命名约定

命名约定有助于更好地组织测试，使开发人员更容易找到他们正在寻找的内容。另一个好处是许多工具期望遵循这些约定。目前有许多使用中的命名约定，这里介绍的只是冰山一角。逻辑是任何命名约定都比没有好。最重要的是团队中的每个人都知道正在使用哪些约定并且对其感到舒适。选择更流行的约定的优势在于，团队的新成员可以快速上手，因为他们可以利用现有知识找到自己的方向。

将实现与测试代码分开。

好处：它避免了意外地将测试与生产二进制文件一起打包；许多构建工具期望测试位于特定的源目录中。

常见做法是至少有两个源目录。实现代码应该位于`src/main/java`，测试代码应该位于`src/test/java`。在更大的项目中，源目录的数量可能会增加，但是实现和测试之间的分离应该保持不变。

像 Gradle 和 Maven 这样的构建工具期望源目录分离以及命名约定。

你可能已经注意到，我们在整本书中使用的`build.gradle`文件并没有明确指定要测试什么，也没有指定要使用哪些类来创建`.jar`文件。Gradle 假定测试位于`src/test/java`，应该打包到 JAR 文件中的实现代码位于`src/main/java`。

将测试类放在与实现相同的包中。

好处：知道测试与代码在同一个包中有助于更快地找到代码。

如前面的做法所述，尽管包是相同的，但类位于不同的源目录中。

本书中的所有练习都遵循了这一惯例。

以与它们测试的类类似的方式命名测试类。

好处：知道测试与它们所测试的类有相似的名称有助于更快地找到类。

一个常用的做法是将测试命名为与实现类相同的名称，后缀为`Test`。例如，如果实现类是`TickTackToe`，测试类应该是`TickTackToeTest`。

然而，在所有情况下，除了我们在重构练习中使用的情况外，我们更喜欢后缀`Spec`。它有助于清晰地区分测试方法主要是作为规定将要开发的内容。测试是这些规范的一个很好的附产品。

为测试方法使用描述性名称。

好处：它有助于理解测试的目标。

在尝试弄清楚为什么某些测试失败或者测试覆盖率应该增加更多测试时，使用描述测试的方法名称是有益的。在测试之前应该清楚地了解设置了什么条件，执行了什么操作，以及预期的结果是什么。

有许多不同的方法来命名测试方法，我们首选的方法是使用 BDD 场景中使用的`Given`/`When`/`Then`语法来命名它们。`Given`描述（前）条件，`When`描述操作，`Then`描述预期结果。如果测试没有前提条件（通常使用`@Before`和`@BeforeClass`注释设置），则可以跳过`Given`。

让我们来看看我们为井字游戏应用程序创建的规范之一：

```java
    @Test 
    public void whenPlayAndWholeHorizontalLineThenWinner() { 
        ticTacToe.play(1, 1); // X 
        ticTacToe.play(1, 2); // O 
        ticTacToe.play(2, 1); // X 
        ticTacToe.play(2, 2); // O 
        String actual = ticTacToe.play(3, 1); // X 
        assertEquals("X is the winner", actual); 
    } 
```

仅通过读取方法的名称，我们就可以理解它是关于什么的。当我们玩游戏并且整个水平或垂直和对角线都被填满时，我们就有了一个赢家。

不要仅依赖注释来提供有关测试目标的信息。当从您喜爱的 IDE 执行测试时，注释不会出现，也不会出现在 CI 或构建工具生成的报告中。

# 流程

TDD 流程是一组核心实践。TDD 的成功实施取决于本节中描述的实践。

在编写实现代码之前编写测试。

好处：它确保编写了可测试的代码；它确保为每一行代码编写了测试。

通过首先编写或修改测试，开发人员在开始编写实现代码之前专注于需求。这与在实现完成后编写测试的方式相比是主要的区别。额外的好处是，通过先编写测试，我们避免了测试作为质量检查（QC）而不是质量保证（QA）的危险。我们试图确保质量内置，而不是稍后检查是否达到了质量目标。

只有在测试失败时才编写新代码。

好处：它确认了测试在没有实现的情况下不起作用。

如果测试通过而无需编写或修改实现代码，那么要么功能已经实现，要么测试有问题。如果确实缺少新功能，那么测试总是通过，因此是无用的。测试应该因为预期的原因而失败。尽管无法保证测试是否验证了正确的事情，但通过首先失败并因为预期的原因，对验证正确性的信心应该很高。

每次实现代码发生变化时重新运行所有测试。

好处：它确保代码更改没有引起意外的副作用。

每当实现代码的任何部分发生变化时，都应该运行所有测试。理想情况下，测试执行速度快，可以由开发人员在本地运行。一旦代码提交到版本控制，应该再次运行所有测试，以确保由于代码合并而没有问题。当有多个开发人员在代码上工作时，这一点尤为重要。应该使用持续集成（CI）工具从存储库中拉取代码，编译它，并运行测试，例如：

+   Jenkins（https://jenkins.io/）

+   Hudson（http://hudson-ci.org/）

+   Travis（https://travis-ci.org/）

+   Bamboo（https://www.atlassian.com/software/bamboo）

在编写新测试之前，所有测试都应该通过。

好处：它保持专注在一个小单位的工作上；实现代码（几乎）总是处于工作状态。

有时候在实际实现之前编写多个测试是很诱人的。在其他情况下，开发人员会忽略现有测试检测到的问题，转向新功能。尽量避免这种情况。在大多数情况下，违反这个规则只会引入技术债务，需要付出更多的利息。TDD 的一个目标是，实现代码（几乎）总是按预期工作的。一些项目由于压力要达到交付日期或保持预算，违反这个规则并且将时间用于新功能，留下修复与失败测试相关的代码的任务。这些项目通常最终会推迟不可避免的事情。

只有在所有测试都通过之后才进行重构。

好处：这种重构是安全的。

如果所有可能受到影响的实现代码都有测试，并且它们都通过了，那么重构是相对安全的。在大多数情况下，不需要新的测试。对现有测试进行小的修改应该就足够了。重构的预期结果是在修改代码之前和之后都通过所有测试。

# 开发实践

本节列出的实践着重于编写测试的最佳方式。编写最简单的代码来通过测试，因为这样可以确保更清晰和更干净的设计，并避免不必要的功能。

这个想法是，实现越简单，产品就越好、维护也更容易。这个想法遵循“保持简单，愚蠢”（KISS）原则。这个原则指出，大多数系统如果保持简单而不是复杂，就能发挥最佳作用；因此，简单性应该是设计的一个关键目标，不必要的复杂性应该被避免。先写断言，后行动，因为它能够在早期澄清需求和测试的目的。

一旦断言被写出来，测试的目的就清楚了，开发人员可以集中精力在实现这个断言的代码上，然后是实际的实现。在每个测试中最小化断言，避免断言轮盘赌；它允许执行更多的断言。

如果在一个测试方法中使用了多个断言，可能很难确定哪个导致了测试失败。当测试作为 CI 过程的一部分执行时，这种情况尤其常见。如果问题无法在开发人员的机器上重现（如果问题是由环境问题引起的情况可能是这样），修复问题可能会很困难和耗时。

当一个断言失败时，该测试方法的执行就会停止。如果该方法中有其他断言，它们将不会被运行，导致丢失了可以用于调试的信息。

最后但同样重要的是，多个断言会让测试的目标变得模糊。

这种做法并不意味着每个测试方法中应该总是只有一个`assert`。如果有其他断言来测试相同的逻辑条件或功能单元，它们可以在同一个方法中使用。

让我们通过一些例子来看：

```java
@Test 

public final void whenOneNumberIsUsedThenReturnValueIsThatSameNumber() { 
    Assert.assertEquals(3, StringCalculator.add("3")); 
} 

@Test 
public final void whenTwoNumbersAreUsedThenReturnValueIsTheirSum() { 
    Assert.assertEquals(3+6, StringCalculator.add("3,6")); 
} 
```

前面的代码包含了两个明确定义了测试目标的规范。通过阅读方法名称和查看`assert`，应该清楚地知道正在测试什么。考虑以下例子：

```java
@Test 
public final void whenNegativeNumbersAreUsedThenRuntimeExceptionIsThrown() { 
    RuntimeException exception = null; 
    try { 
        StringCalculator.add("3,-6,15,-18,46,33"); 
    } catch (RuntimeException e) { 
        exception = e; 
    } 
    Assert.assertNotNull("Exception was not thrown", exception); 
    Assert.assertEquals("Negatives not allowed: [-6, -18]",  
            exception.getMessage()); 
} 
```

这个规范有多个`assert`，但它们都在测试相同的逻辑功能单元。第一个`assert`确认异常存在，第二个确认它的消息是正确的。当在一个测试方法中使用多个断言时，它们都应该包含解释失败的消息。这样，调试失败的`assert`就更容易了。在每个测试方法中只有一个`assert`的情况下，消息是可以的，但不是必需的，因为从方法名称中应该清楚地知道测试的目标是什么：

```java
@Test 
public final void whenAddIsUsedThenItWorks() { 
    Assert.assertEquals(0, StringCalculator.add("")); 
    Assert.assertEquals(3, StringCalculator.add("3")); 
    Assert.assertEquals(3+6, StringCalculator.add("3,6")); 
    Assert.assertEquals(3+6+15+18+46+33, 
            StringCalculator.add("3,6,15,18,46,33")); 
    Assert.assertEquals(3+6+15, StringCalculator.add("3,6n15")); 
    Assert.assertEquals(3+6+15, 
            StringCalculator.add("//;n3;6;15"));    Assert.assertEquals(3+1000+6, 
            StringCalculator.add("3,1000,1001,6,1234")); 
} 
```

这个测试有很多断言。不清楚功能是什么，如果其中一个失败，不知道其余的是否会工作。当通过一些 CI 工具执行此测试时，可能很难理解失败。

不要在测试之间引入依赖关系。

好处：测试以任何顺序独立运行，无论是运行所有还是只运行一个子集。

每个测试都应该独立于其他测试。开发人员应该能够执行任何单独的测试，一组测试或所有测试。通常，由于测试运行器的设计，不能保证测试将按任何特定顺序执行。如果测试之间存在依赖关系，它们可能很容易在引入新的依赖关系时被破坏。

测试应该运行得快。

好处：这些测试经常被使用。

如果运行测试需要很长时间，开发人员将停止使用它们，或者只运行与他们正在进行的更改相关的一小部分测试。快速测试的好处，除了促进它们的使用，还包括快速反馈。问题被检测到得越早，修复起来就越容易。对产生问题的代码的了解仍然很新鲜。如果开发人员在等待测试执行完成时已经开始处理下一个功能，他们可能会决定推迟修复问题，直到开发了新功能。另一方面，如果他们放弃当前的工作来修复错误，那么在上下文切换中会浪费时间。

测试应该如此迅速，以至于开发人员可以在每次更改后运行所有测试而不感到无聊或沮丧。

使用测试替身。

好处：这减少了代码依赖性，测试执行将更快。

模拟是测试快速执行和专注于单个功能单元的先决条件。通过模拟被测试方法外部的依赖关系，开发人员能够专注于手头的任务，而不必花时间设置它们。在更大的团队中，这些依赖关系甚至可能尚未开发。此外，没有模拟的测试执行往往很慢。模拟的良好候选对象包括数据库、其他产品、服务等。

使用设置和拆卸方法。

好处：这允许在类或每个方法之前和之后执行设置和拆卸代码。

在许多情况下，一些代码需要在测试类之前或在类中的每个方法之前执行。为此，JUnit 有`@BeforeClass`和`@Before`注解，应该被用作设置阶段。`@BeforeClass`在类加载之前（在第一个测试方法运行之前）执行关联的方法。

`@Before`在每个测试运行之前执行关联的方法。当测试需要特定的前提条件时，应该使用这两个注解。最常见的例子是在（希望是内存中的）数据库中设置测试数据。

在相对的另一端是`@After`和`@AfterClass`注解，它们应该被用作拆卸阶段。它们的主要目的是销毁在设置阶段或测试本身创建的数据或状态。正如在先前的一个实践中所述，每个测试都应该独立于其他测试。此外，没有测试应该受到其他测试的影响。拆卸阶段有助于保持系统，就好像之前没有执行任何测试一样。

不要在测试中使用基类。

好处：它提供了测试的清晰度。

开发人员通常以与实现相同的方式处理测试代码。常见的错误之一是创建被测试类扩展的基类。这种做法避免了代码重复，但牺牲了测试的清晰度。在可能的情况下，应该避免或限制用于测试的基类。必须从测试类导航到其父类，再到父类的父类等，以便理解测试背后的逻辑，这经常会引入不必要的混乱。测试的清晰度应该比避免代码重复更重要。

# 工具

TDD、编码和测试一般都严重依赖于其他工具和流程。其中一些最重要的工具如下。它们每一个都是一个太大的主题，无法在本书中进行探讨，所以它们只会被简要描述。

代码覆盖率和 CI。

好处：它确保了一切都经过了测试。

代码覆盖率实践和工具在确定所有代码、分支和复杂性都经过测试方面非常有价值。其中一些工具如下：

+   JaCoCo ([`www.eclemma.org/jacoco/`](http://www.eclemma.org/jacoco/))

+   Clover ([`www.atlassian.com/software/clover`](https://www.atlassian.com/software/clover))

+   Cobertura ([`cobertura.github.io/cobertura/`](http://cobertura.github.io/cobertura/))

CI 工具对于除了最琐碎的项目之外的所有项目都是必不可少的。一些最常用的工具包括：

+   Jenkins ([`jenkins.io/`](https://jenkins.io/))

+   Hudson ([`hudson-ci.org/`](http://hudson-ci.org/))

+   Travis ([`travis-ci.org/`](https://travis-ci.org/))

+   Bamboo ([`www.atlassian.com/software/bamboo`](https://www.atlassian.com/software/bamboo)).

使用 TDD 和 BDD。

好处：开发人员单元测试和功能客户端测试都得到了覆盖。

虽然 TDD 与单元测试是一种很好的实践，但在许多情况下，它并不能提供项目所需的所有测试。TDD 开发速度快，有助于设计过程，并通过快速反馈提供信心。另一方面，BDD 更适合集成和功能测试，通过叙述提供了更好的需求收集过程，并且通过场景与客户沟通的方式更好。两者都应该被使用，它们共同提供了一个涉及所有利益相关者和团队成员的完整流程。TDD（基于单元测试）和 BDD 应该推动开发过程。我们建议使用 TDD 来实现高代码覆盖率和快速反馈，以及 BDD 作为自动化验收测试。虽然 TDD 大多是面向白盒测试，BDD 通常旨在进行黑盒测试。TDD 和 BDD 都试图专注于质量保证而不是质量控制。

# 总结

在本章中，我们首先简要概述了 TDD。我们了解了四种可以帮助提高软件质量的最佳实践。

在进入最后一章之前，我们将介绍 CI 和持续交付的概念，并通过一个例子强调 TDD 在整个流程中的重要性。


# 第十二章：通过实施持续交付来利用 TDD

“没有什么比结果更有说服力。如果你想建立与人们联系的可信度，那么在传达信息之前先交付结果。走出去做你建议别人做的事情。从经验中交流。”

- 约翰·C·麦克斯韦

在整本书中，概念和良好的实践已经通过孤立的例子进行了介绍。本章的目标是将这些概念中的一些付诸实践，通过将它们应用于更现实的场景。

为了实现这一目标，我们引入了一个名为“牛逼赌博公司”的虚构公司。这家公司在软件开发生命周期中遇到了一些问题，这些问题可以通过应用我们在本书中学到的一些方法来轻松解决。免责声明，与真实公司的任何相似之处纯属巧合。此外，为了简洁起见，代码库并不是很庞大，一些问题已经夸大，以更好地代表需要解决的问题。

涉及的主题不一定按顺序包括：

+   持续集成

+   持续交付

+   测试驱动开发的好处

+   识别快速成功

# 案例研究-牛逼赌博公司

你是爱丽丝，一名软件开发人员，刚刚加入了“牛逼赌博公司”的软件开发团队。你的队友们正在尽可能短的时间内让你跟上进度。这是你的第一天，你的队友约翰被指定为你的导师，在公司的最初几个小时里将指导你。

在愉快的一杯咖啡之后，他迅速将你的谈话话题转向了组成你日常工作的所有任务和程序。你的团队正在开发和维护一个非常简单的`thimblerig-service`。一听到“thimblerig”这个词，你羞愧地承认这是你第一次听到这个词。约翰笑着说，两年前加入公司时他也不知道这个词。

Thimblerig 游戏，也被称为“三个壳和一个豌豆”，是一种古老的赌博游戏。规则非常简单，有三个壳，豌豆被其中一个盖住。这三个壳以非常高的速度洗牌，完成后，玩家必须猜出哪个壳藏着豌豆。

解释完毕后，他友好地提议帮助你从存储库下载代码项目，并简要向你解释了整体概念。

一旦他解释完毕，他要求你自己阅读代码。他还告诉你，如果你有任何问题或疑虑，他就是你要去找的人。你对他的时间表示感谢，开始浏览项目。

# 探索代码库

当你开始浏览项目时，你意识到这个应用并不是很复杂。事实上，项目包含大约十几个 Java 类，当你开始打开并查看文件时，你会注意到没有一个文件超过一百行。这很不错，代码库很小，所以你将能够在很短的时间内开发新功能。

鉴于这是一个 Gradle 项目，你迅速打开`build.gradle`文件，以了解项目中使用的框架和库：

```java
apply plugin: 'java'
apply plugin: 'org.springframework.boot'

sourceCompatibility = 1.8
targetCompatibility = 1.8

bootRepackage.executable = true

repositories {
  mavenLocal()
  mavenCentral()
}

dependencies {
  compile 'org.springframework.boot:spring-boot-starter-actuator'
  compile 'org.springframework.boot:spring-boot-starter-web'

  testCompile 'junit:junit:4.12'
  testCompile 'org.hamcrest:hamcrest-all:1.3'
  testCompile 'org.mockito:mockito-core:1.10.19'
}
```

Gradle 构建字段看起来不错。你要工作的项目是基于 Spring 的 Web 服务。它使用`spring-boot-starter-web`，所以很可能你可以在本地轻松运行它。此外，还有一些测试依赖项，这意味着测试文件夹中应该也有一些测试。

几分钟后，你已经在脑海中有了应用的地图。有一个名为`ThimblerigService`的类，它处理游戏的逻辑。它依赖于`RandomNumberGenerator`，并且只有一个公共方法，即`placeBet`。方法和类都有一个可理解的名称，所以很容易弄清楚它们的作用：

```java
@Service
public class ThimblerigService {
  private RandomNumberGenerator randomNumberGenerator;

  @Autowired
  ThimblerigService(RandomNumberGenerator randomNumberGenerator) {
    this.randomNumberGenerator = randomNumberGenerator;
  }

  public BetResult placeBet(int position, BigDecimal betAmount) {
    ...
  }
}
```

除了那个类，只有一个控制器类实现了一个 API：它是`ThimblerigAPI`。它只公开了一个方法，即`placeBet`。其他公司服务调用该`POST`方法以在该服务中玩一场游戏。该服务解决赌注并在响应中包括诸如是否赢得奖品、金额等详细信息：

```java
@RestController
@RequestMapping("/v1/thimblerig")
public class ThimblerigAPI {
  private ThimblerigService thimblerigService;

  @Autowired
  public ThimblerigAPI(ThimblerigService thimblerigService) {
    this.thimblerigService = thimblerigService;
  }

  @ResponseBody
  @PostMapping(value = "/placeBet",
      consumes = MediaType.APPLICATION_JSON_VALUE)
  public BetReport placeBet(@RequestBody NewBet bet) {
    BetResult betResult =
        thimblerigService.placeBet(bet.getPick(), bet.getAmount());
    return new BetReport(betResult);
  }
}
```

这是一个相当简单的设置，一切都很清晰，所以你决定继续并开始查看测试。

当你打开`test`文件夹并开始寻找测试时，当你发现只有一个测试类`ThimblerigServiceTest`时，你感到非常惊讶。一个好的测试胜过一百个坏的，但你仍然认为这个应用程序的单元测试做得很差：

```java
public class ThimblerigServiceTest {
  @Test
  public void placingBetDoesNotAcceptPositionsLessThanOne() {
    ...
  }

  @Test
  public void placingBetDoesNotAcceptPositionsGreaterThan3() {
    ...
  }

  @Test
  public void placingBetOnlyAcceptsAmountsGreaterThanZero() {
    ...
  }

  @Test
  public void onFailedBetThePrizeIsZero() {
    ...
  }

  @Test
  public void whenThePositionIsGuessedCorrectlyThePrizeIsDoubleTheBet() {
    ...
  }
}
```

打开类并检查其中包含的所有测试后，你的印象略微好转。这些测试完全覆盖了核心服务，并且它们似乎是有意义且详尽的。但尽管如此，你还是忍不住转过头去问约翰为什么只有一个测试。他告诉你，他们没有太多时间来创建测试，因为他们很匆忙，所以只有关键部分有测试。一个代码片段是否关键是非常主观的，但你理解这种情况；事实上，你也曾多次处于这种情况。

仅仅一秒后，在你还来不及回到自己的任务之前，约翰又在他的回答中加入了另一个有趣的观点：**质量保证**（**QA**）部门。该部门的目标是在发布候选版本到达生产环境之前对其进行测试。他们的任务是查找可能影响应用程序的错误和缺陷并报告它们。在某些情况下，如果发现的任何错误非常关键，发布将被停止，永远不会部署到生产环境。这个流程通常需要三到五天的时间。你认为在某些情况下这可能是一个瓶颈，所以你要求他进一步详细说明发布流程。

# 发布流程

只要项目是一个简单的**表现状态转移**（**REST**）服务，发布的创建就一点也不复杂。根据当前的流程，开发人员编译代码并将构件发送给负责所有部署的团队。该团队与客户和质量保证部门协调测试和部署到生产环境。

你决定问约翰是否满意这个流程。甚至在得到答案之前，你就知道约翰对此一点也不满意。你可以从他的脸上看出，他正在努力掩饰自己的感受。约翰咽下自己的情绪，开始描述团队的当前情况。

事实证明，开发团队并非一切都是愉快和甜蜜的。所有开发人员在开始编码时都会从代码库的主分支创建自己的分支。这并不是坏事，但有时会出现一些分支在很多周后才合并回主分支。问题在于自那时以来主分支发生了很大变化，代码库分叉很多，这意味着合并非常困难、令人不愉快且容易出错。

除了偶尔出现的合并问题，有时会发生某个开发人员错误地编译了他的本地分支，并将其部署到生产环境，导致一段时间内的混乱、破坏和不确定性。

此外，客户对于实现新功能所需的时间并不满意。他们不时地抱怨，说每一个微小的变化至少需要一周的时间才能应用。

你对这种情况如何发生在一个非常微小的 REST 服务上感到困惑，但约翰当然是在指公司中的其他更大的项目。你知道通过实施持续集成（CI）和持续交付，这种问题可以得到解决或至少得到缓解。事实上，尽可能自动化流程可以让你摆脱那些琐碎的问题，从而专注于其他问题。

经过这样的思考，你现在知道你需要更多关于部署程序的信息，你也知道约翰愿意给你详细信息。

# 部署到生产环境

在讨论发布流程后，约翰开始向你解释服务是如何部署到生产环境的。这是非常手动的工作：IT 部门的基础设施团队的一名成员将构件复制到服务器并执行一些命令来使其运行。

约翰还借此机会补充了一些他们过去遭受的错误故事，比如有一次，基础设施操作员错误地重新部署了旧版本，而不是部署最新版本。一堆旧的错误重新出现并一直停留在生产环境中，直到有人发现发生了什么。

在听这些故事的同时，你不禁开始思考你从以往项目和公司中学到的东西。你知道将代码部署到生产环境可能是一个非常简单直接的任务，一个永无止境的噩梦，或者介于两者之间。这取决于许多因素，有时我们无法改变它。在某些情况下，将应用程序部署到生产环境需要得到有权决定何时以及部署什么的人的承认。在其他情况下，严格的规定将本应简单的程序变成了一个冗长而啰嗦的任务。

此外，自动化部署是减少人为干预可能带来的风险的一种方式。创建可重复的流程可以像编写脚本并安排其执行一样简单。众所周知，任何单个脚本都无法完全取代人类，但毋庸置疑，目标并不是用脚本取代人类。这样做的主要目的是提供一个可以自主执行的工具，人类可以监督它，只有在必要时才进行手动干预。因此，实施持续交付非常合适。

在约翰简短但激烈的介绍之后，你觉得自己已经准备好开始工作了。你脑海中有许多可能的改进，你肯定渴望实施它们。

# 增加测试覆盖率

在衡量代码质量的指标中，有一个特别难以理解的指标，那就是测试覆盖率。测试覆盖率是一个危险的指标，因为非常高的覆盖率并不意味着代码经过了充分的测试。正如其名称所示，它只是考虑了一段代码是否被触发并因此被测试执行。因此，测试的目标基本上是良好的测试和良好的覆盖率的结合。总之，重要的是测试的质量，代码覆盖率是次要的。

然而，有些情况下代码覆盖率确实是一个很好的指标。这些情况是当测试覆盖率非常低时。在这些情况下，这个数字意味着代码库的很大一部分没有被测试，因此测试并没有确保我们没有引入错误。

此外，创建良好的自动化测试可以减少 QA 团队在执行回归测试上所花费的时间。这很可能会减少他们反复测试相同代码的时间，从而提高团队的交付速度。

# 结论

尽管为了教学目的而夸大了这家公司的情况，但仍然有一些公司在努力解决这些问题。事实上，爱丽丝知道令人敬畏的赌博公司的软件开发人员的工作方式并不理想。有许多技术，其中一些在本书中有所涵盖，可以帮助公司停止专注于无意识的错误，并开始专注于其他可以为最终产品增加更多价值的事情。

在接下来的部分中，我们将通过提出一种可能的解决方案来解决爱丽丝故事中描述的一些问题。这不是唯一的解决方案；实际上，所提出的解决方案包括一些工具，每个工具都有许多选项。此外，每家公司都有自己的文化和限制，因此提出的解决方案可能并不完全适用。

# 可能的改进

在本节和接下来的子节中，我们将解决爱丽丝故事中描述的一些问题。由于我们从示例中继承的代码已经实施，因此我们无法在这里应用 TDD。相反，我们将奠定基础并为将来的开发做好准备，在那里应用 TDD 将非常有用。

尽管总是有许多可以改进的地方，但正在解决的痛点是代码合并问题、大量手动测试、手动发布以及开发更改或新功能所花费的时间。

对于前两个问题，我们将增加应用程序的测试覆盖率并实施 CI。将配置 Jenkins 服务器来解决第三个问题，即手动发布。最后，通过实施其余的解决方案来缓解长时间的**上市时间**（**TTM**）。

# 实施持续集成

在大型公司中，有多个团队并行工作，很常见出现大量集成冲突。当代码库在大规模开发时，这种情况更频繁发生。

为了缓解这一问题，强烈建议使用 CI。主要思想是开发分支不应该与主分支相差太大。一种方法是将更改或新功能分成非常小的块，这样它们可以很快完成并合并回来。另一种方法是定期合并；当功能难以分解成小功能时，这更合适。

面对不可分割的功能，如架构更改，功能切换非常有帮助。使用功能切换，未完成的功能可以合并，并且在打开标志之前将无法访问。

# 走向持续交付

故事中开发人员面临的问题之一是手动创建发布。有许多工具可以帮助自动化这些任务，例如 Jenkins、Travis 或 Bamboo，仅举几例。作为提出的解决方案的一部分，我们将配置一个 Jenkins 实例，以自动运行所有这些任务。在每次执行 Jenkins 作业时，将创建`thimblerig-service`的新版本。

此外，由于我们已经转移到 CI，主分支的状态应始终准备好投入生产。而且，如果一些未完成的功能已经合并，由于功能切换，它们将被隐藏。

在这一点上，为了解决发布的问题，我们可以实施持续交付或**持续部署**（**CD**），但为了简单起见，我们将实施持续交付。让我们开始吧。

# Jenkins 安装

Jenkins 是一个非常强大且易于学习的工具。在这一部分，我们将准备环境，其中包括运行 Jenkins Docker 镜像的虚拟机。这个设置是为了演示目的；对于真实场景，最好安装在具有更多资源的专用服务器上，或者从 CloudBees 等公司获得服务。在这种情况下，所有配置都位于`Vagrantfile`中：

```java
Vagrant.configure("2") do |config|

  config.vm.box = "ubuntu/trusty64"
  config.vm.box_check_update = false

  config.vm.network "forwarded_port", guest: 8080, host: 9090

  config.vm.provider "virtualbox" do |vb|
    vb.gui = false
    vb.memory = 2048
  end

  config.vm.provision "docker" do |d|
    d.run "jenkins/jenkins",
      args: "-p 8080:8080 -p 50000:50000 -v jenkins_home:/var/jenkins_home"
  end
end
```

因此，要使其运行起来，我们只需要执行以下命令：

```java
$> vagrant up
```

如果在重新启动或其他原因后，Jenkins 显示为离线或无法访问它，尝试使用 provision 标志运行相同的命令：

**`$> vagrant up --provision`**

完成后，我们可以在我们喜欢的浏览器中打开`http://localhost:9090`来继续设置：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/test-dvn-java-dev/img/a8247d8e-7789-417c-809b-4756225fd22b.png)

由于我们没有在服务器上安装它，而是在 Docker 镜像中运行它，这个密码有点难以获取。可能最简单的方法是访问 Docker 机器并从文件中获取密码，可以这样做：

```java
$> vagrant ssh
$> docker exec jenkins-jenkins cat /var/jenkins_home/secrets/initialAdminPassword
```

复制密码，粘贴到密码字段中，然后我们进入下一步，配置插件。现在，我们只安装推荐的插件。其他插件可以稍后在管理面板中安装：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/test-dvn-java-dev/img/4625e47e-6b32-47c3-9248-f4ebcb2f8c72.png)

然后，当设置完成安装插件后，会显示另一个屏幕。这是配置的最后一步，创建一个管理员用户。建议创建一个密码容易记住的用户：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/test-dvn-java-dev/img/4813c0e2-3788-4b9c-b3c0-c0afd69eede4.png)

这一步可以跳过，但是管理员密码将保持与初始密码相同，这样很难记住。现在我们已经准备好使用我们全新的 Jenkins 安装了。

# 自动化构建

一旦我们启动并运行了 Jenkins，就是开始使用它的时候了。我们将在 Jenkins 上创建一个任务，下载`thimblerig-service`主分支，执行测试，构建它，并存档生成的构件。

让我们从创建一个自由风格项目开始：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/test-dvn-java-dev/img/a96c0105-a5d6-4d7c-8bc3-2c7fcb48dda6.png)

我们必须告诉 Jenkins 存储库的位置。在这个例子中，我们不需要认证，但在实际情况下，我们很可能需要认证：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/test-dvn-java-dev/img/e9381291-d946-4358-b59a-16a0c8819c62.png)

`thimblerig-service`项目是一个 Gradle 项目。我们将使用 Jenkins Gradle 插件来编译、测试和构建我们的服务：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/test-dvn-java-dev/img/7ed034a8-733d-4a2b-aa08-3f9910537fac.png)

最后，我们必须指定测试报告和构建的构件位置：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/test-dvn-java-dev/img/38a7c9cf-6c7f-4a91-b3e3-929fcadf5194.png)

我们完成了。与我们在本地环境中通常做的事情并没有太大的不同。它从主分支下载代码，并使用 Gradle 构建服务，就像 John 在故事中所说的那样。

# 首次执行

在 Jenkins 中创建了我们的项目，现在是测试的时候了。我们从未配置过触发执行，所以 Jenkins 并没有监视存储库中的更改。在这个例子中，手动启动构建已经足够了，但在实际情况下，我们希望它在主分支中的每次更改时自动触发：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/test-dvn-java-dev/img/ca7d372b-66b3-47fb-a703-48ba7393aefc.png)

构建已经成功完成；我们可以在摘要中看到测试已经执行，但没有一个失败。我们准备下载这个构件并尝试在本地执行它：

```java
$> chmod u+x thimblerig-service.jar
$> ./thimblerig-service.jar 
```

在某个时候，日志将显示类似`Tomcat started on port(s): 8080 (http)`的消息。这意味着我们的服务已经准备就绪，我们可以开始使用它。为了确保，我们可以随时通过运行来检查服务的健康状况：

```java
$> curl http://localhost:8080/health
{"status":"UP"}
```

这就结束了持续交付的示例。虽然这个示例是完全可用的，但 Jenkins 并不是存储服务版本的最佳位置。对于实际应用场景，有更强大的替代方案，比如 Artifactory，或者简单地将服务 Docker 化并推送新版本到私有 Docker 注册表。

# 接下来是什么？

这里的例子纯粹是学术性的，解决方案的部分有点巧妙。在一个真实的公司中，Jenkins 将安装在专用服务器上，并且将有更多的任务来构建和发布。为了协调所有这些，需要对生成的构件进行适当的管理。正如前面提到的，一些公司采用的解决方案是像 Artifactory 或 Docker Registry 的私有实例来存储服务的 Docker 镜像。无论选择哪种存储方式，程序都将保持不变——编译，测试，构建，存档。这只是一个配置问题。

为了简洁起见，一些需要新代码的部分已被省略，留给读者作为练习完成。以下是一些继续的想法：

+   为 REST 控制器创建一些测试。

+   随机数生成器存在问题——根本不是随机的。分叉`thimblerig-service`项目，创建一个测试来重现问题，修复它，并通过最近创建的 Jenkins 构建项目发布服务的新版本。

+   使用 Docker。

所有代码片段和其他所需的项目文件都可以在以下存储库中在线找到：[`bitbucket.org/alexgarcia/tdd-java-thimblerig-service`](https://bitbucket.org/alexgarcia/tdd-java-thimblerig-service)

# 这只是个开始

也许你期望在读完本书时，你会对测试驱动开发（TDD）了如指掌。如果是这样，我们很抱歉要让你失望。要掌握任何技艺都需要大量的时间和实践，TDD 也不例外。继续将你所学应用到项目中。与同事分享知识。最重要的是，练习，练习，再练习。就像空手道一样，只有通过持续的练习和重复，才能完全掌握 TDD。我们已经使用它很长时间了，但我们仍然经常面临新的挑战，并学到改进我们技艺的新方法。

# 这并不一定是结束

写这本书是一个充满许多冒险的漫长旅程。我们希望你喜欢阅读它，就像我们喜欢写它一样。

我们在博客[`technologyconversations.com`](http://technologyconversations.com)上分享了我们在各种主题上的经验。

# 总结

在 Alice 的虚构故事中，介绍了一些当今公司面临的常见问题。其中之一是缺乏时间。在这种特殊情况下，以及在大多数情况下，人们缺乏时间是因为他们被困在不增加价值的重复任务中，因此会产生这种不断的感觉，即不可能实现更雄心勃勃的目标。开发人员在被问及为什么不练习 TDD 时，最主要的借口之一是没有时间写测试。

本章介绍了一个可能的解决方案，即使用 Jenkins。配置了一个带有 Jenkins 实例的虚拟机，以自动化一些重复的任务，这些任务正在耗费团队的时间。

一旦问题得到解决，TDD 就会变得非常方便。以 TDD 方式开发的每个新功能都将被测试覆盖，然后对该功能的未来更改将针对测试套件运行，如果其中一个测试未满足，则会失败。
