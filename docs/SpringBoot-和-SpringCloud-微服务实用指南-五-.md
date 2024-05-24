# SpringBoot 和 SpringCloud 微服务实用指南（五）

> 原文：[`zh.annas-archive.org/md5/328F7FCE73118A0BA71B389914A67B52`](https://zh.annas-archive.org/md5/328F7FCE73118A0BA71B389914A67B52)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十三章：使用 Resilience4j 提高弹性

在本章中，我们将学习如何使用 Resilience4j 使我们的微服务更具弹性，也就是说，如何减轻和恢复错误。正如我们在第一章*微服务介绍*，"断路器"部分，和第八章*Spring Cloud 介绍*，"Resilience4j 以提高弹性"部分，所讨论的，断路器可以用来自动减少一个慢速或无响应的后端微服务在一个大规模的同步微服务景观中所造成的损害。我们将看到 Resilience4j 中的断路器如何与超时和重试机制一起使用，以防止我经验中最为常见的两个错误情况：

+   响应缓慢或根本不响应的微服务

+   请求偶尔会因临时网络问题而失败

本章将涵盖以下主题：

+   介绍 Resilience4j 断路器和重试机制

+   向源代码添加**断路器**和**重试机制**

+   尝试使用**断路器**和**重试机制**

# 技术要求

本书中描述的所有命令都是在 MacBook Pro 上使用 macOS Mojave 运行的，但如果你想在其他平台（如 Linux 或 Windows）上运行它们，应该是非常直接的。

在本章中不需要安装任何新工具。

本章的源代码可以在本书的 GitHub 仓库中找到：[`github.com/PacktPublishing/Hands-On-Microservices-with-Spring-Boot-and-Spring-Cloud/tree/master/Chapter13`](https://github.com/PacktPublishing/Hands-On-Microservices-with-Spring-Boot-and-Spring-Cloud/tree/master/Chapter13)。

为了能够运行本书中描述的命令，将源代码下载到一个文件夹中，并设置一个环境变量`$BOOK_HOME`，该变量指向该文件夹。一些示例命令如下：

```java
export BOOK_HOME=~/Documents/Hands-On-Microservices-with-Spring-Boot-and-Spring-Cloud
git clone https://github.com/PacktPublishing/Hands-On-Microservices-with-Spring-Boot-and-Spring-Cloud $BOOK_HOME
cd $BOOK_HOME/Chapter13
```

Java 源代码是为 Java 8 编写的，并在 Java 12 上进行了测试。本章使用 Spring Cloud 2.1.0, SR1（也被称为**Greenwich**版本），Spring Boot 2.1.4 和 Spring 5.1.6，即在撰写本章时可用的 Spring 组件的最新版本。

所有 Dockerfile 中都使用了`openjdk:12.0.2`基础 Docker 镜像。

源代码包含以下 Gradle 项目：

+   `api`

+   `util`

+   `microservices/product-service`

+   `microservices/review-service`

+   `microservices/recommendation-service`

+   `microservices/product-composite-service`

+   `spring-cloud/eureka-server`

+   `spring-cloud/gateway`

+   `spring-cloud/authorization-server`

+   `spring-cloud/config-server`

配置文件可以在 config 仓库中找到，`config-repo`。

本章中的所有源代码示例均来自`$BOOK_HOME/Chapter13`中的源代码，但在某些情况下，去除了源代码中不相关部分，例如注释、导入和日志语句。

如果你想查看本章中应用于源代码的变化，即了解使用 Resilience4j 添加弹性所需的内容，你可以与第十二章的*集中配置*源代码进行比较。你可以使用你喜欢的`diff`工具，比较两个文件夹，`$BOOK_HOME/Chapter12`和`$BOOK_HOME/Chapter13`。

# 介绍 Resilience4j 电路断路器和重试机制

重试和电路断路器在两个软件组件之间的任何同步通信中都有潜在的用处，例如微服务。由于 Spring Cloud Gateway 目前只支持较旧的断路器 Netflix Hystrix，我们的所有微服务都可以使用 Resilience4j，除了边缘服务器。在本章中，我们将在一个地方应用电路断路器和重试机制，即从`product-composite`服务调用`product`服务。以下图表说明了这一点：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/1242dd3a-010d-4a6d-8ce2-edc8fd88c290.png)

请注意，在前面的图表中没有显示其他微服务对发现和配置服务器的同步调用（为了更容易阅读）。

随着本章的写作，一直在进行的工作是为 Spring Cloud 添加一个电路断路器的抽象层，这对 Spring Cloud Gateway 可能是有益的。详情请参阅[`spring.io/blog/2019/04/16/introducing-spring-cloud-circuit-breaker`](https://spring.io/blog/2019/04/16/introducing-spring-cloud-circuit-breaker)。

# 介绍电路断路器

让我们快速回顾一下来自第八章的*Spring Cloud 简介*中的*Resilience4j 改进弹性*部分的电路断路器状态图：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/87b2c812-ab46-45fe-a6d7-0f06a030d556.png)

电路断路器的键特性如下：

+   如果电路断路器检测到太多故障，它将打开其电路，即不允许新的调用。

+   当电路处于断开状态时，电路断路器将执行快速失败逻辑。这意味着它不是等待新的故障发生，例如超时，在后续调用中发生。相反，它直接将调用重定向到一个**回退** **方法**。回退方法可以应用各种业务逻辑以产生最佳努力响应。例如，回退方法可以从本地缓存返回数据，或者简单地返回一个立即的错误消息。这可以防止微服务在它依赖的服务停止正常响应时变得无响应。在高负载下，这特别有用。

+   过了一段时间后，断路器将变为半开放*状态*，允许新的调用查看导致失败的问题是否已解决。如果断路器检测到新的失败，它将再次打开电路并回到快速失败逻辑。否则，它将关闭电路并恢复正常操作。这使得微服务能够抵抗故障，而在与其他微服务同步通信的系统架构中，这种能力是不可或缺的！

Resilience4j 以多种方式在运行时暴露有关断路器的信息：

+   可以通过微服务的 actuator`health`端点监控断路器的当前状态，即`/actuator/health`。

+   断路器还会在`actuator`端点上发布事件，例如，状态转换、`/actuator/circuitbreakerevents`。

+   最后，断路器与 Spring Boot 的度量系统集成，并可以使用它将指标发布到监控工具，例如 Prometheus。

在本章中，我们将尝试使用`health`和`event`端点。在第二十章“微服务监控”中，我们将看到 Prometheus 的实际应用情况，以及它如何收集由 Spring Boot 暴露出来的指标，例如，我们的断路器中的指标。

为了控制断路器中的逻辑，Resilience4J 可以使用标准 Spring Boot 配置文件进行配置。我们将使用以下配置参数：

+   `ringBufferSizeInClosedState`：在关闭状态中的调用次数，用于确定电路是否应打开。

+   `failureRateThreshold`：导致电路打开的失败调用百分比阈值。

+   `waitInterval`：指定电路保持开放状态的时间长度，即，在过渡到半开放状态之前。

+   `ringBufferSizeInHalfOpenState`：在半开放状态下用于确定电路是否应再次打开或回到正常、关闭状态的调用次数。

+   `automaticTransitionFromOpenToHalfOpenEnabled`：确定电路在等待期结束后是否自动变为半开放状态，或者在等待期间等待第一个调用直到变为半开放状态。

+   `ignoreExceptions`：可以用来指定不应被计为错误的异常。例如，找不到或输入无效的业务异常通常是断路器应该忽略的异常，即，搜索不存在的数据或输入无效输入的用户不应该导致电路打开。

Resilience4j 在关闭状态和半开放状态下使用环形缓冲区跟踪成功和失败的调用，因此有了参数名`ringBufferSizeInClosedState`和`ringBufferSizeInHalfOpenState`。

本章将使用以下设置：

+   `ringBufferSizeInClosedState = 5`和`failureRateThreshold = 50%`，意味着如果最后五个调用中有三个或更多是故障，那么电路将打开。

+   `waitInterval = 10000`和`automaticTransitionFromOpenToHalfOpenEnabled = true`，意味着断路器将保持电路开启 10 秒，然后过渡到半开状态。

+   `ringBufferSizeInHalfOpenState = 3`，意味着断路器将基于断路器过渡到半开状态后的三个首次调用来决定是否打开或关闭电路。由于`failureRateThreshold`参数设置为 50%，如果两个或所有三个调用失败，电路将再次打开。否则，电路将关闭。

+   `ignoreExceptions = InvalidInputException`和`NotFoundException`，意味着我们的两个业务异常在断路器中不会被视为故障。

# 引入重试机制

重试机制对于随机和偶尔出现的故障非常有用，例如暂时的网络问题。重试机制可以简单地尝试失败请求多次，每次尝试之间有可配置的延迟。使用重试机制的一个非常重要的限制是，它重试的服务必须是**幂等的**，也就是说，用相同的请求参数调用服务一次或多次会得到相同的结果。例如，读取信息是幂等的，但创建信息通常不是。你不希望重试机制因为第一次创建订单的响应在网络中丢失而意外地创建两个订单。

当涉及到事件和指标时，Resilience4j 以与断路器相同的方式暴露重试信息，但不提供任何健康信息。重试事件可以在`actuator`端点，`/actuator/retryevents`上访问。为了控制重试逻辑，可以使用标准的 Spring Boot 配置文件配置 Resilience4J。我们将使用以下配置参数：

+   `maxRetryAttempts`: 包括第一次调用在内的重试次数上限

+   `waitDuration`: 下次重试尝试之前的等待时间

+   `retryExceptions`: 需要触发重试的异常列表

在本章中，我们将使用以下值：

+   `maxRetryAttempts = 3`: 我们将最多尝试两次重试。

+   `waitDuration= 1000`: 我们将在重试之间等待一秒钟。

+   `retryExceptions = InternalServerError`: 我们只会在遇到`InternalServerError`异常时触发重试，也就是说，当 HTTP 请求响应码为 500 时。

配置重试和断路器设置时要小心，例如，确保断路器在预期的重试次数完成之前不要打开电路！

# 在源代码中添加断路器和重试机制

在向源代码中添加断路器和重试机制之前，我们将添加代码，使其能够强制发生错误——要么是延迟，要么是随机故障。然后，我们将添加一个断路器来处理慢速或无响应的 API，以及一个可以处理随机发生故障的重试机制。从 Resilience4j 添加这些功能遵循传统的 Spring Boot 方式：

+   在构建文件中添加一个针对 Resilience4j 的启动依赖。

+   在源代码中添加注解，以在断路器和重试机制应适用的位置使用。

+   添加控制断路器和重试机制行为的配置。

一旦我们实施了断路器和重试机制，我们将扩展我们的测试脚本`test-em-all.bash`，以包含断路器的测试。

# 添加可编程延迟和随机错误

为了能够测试我们的断路器和重试机制，我们需要一种控制错误发生时间的方法。实现这一目标的一种简单方法是在 API 中添加可选的查询参数，以检索产品和组合产品。组合产品 API 将参数传递给产品 API。以下查询参数已添加到两个 API 中：

+   `delay`：导致`product` 微服务的`getProduct` API 延迟其响应。参数以秒为单位指定。例如，如果参数设置为`3`，它将在返回响应之前造成三秒的延迟。

+   `faultPercentage`：导致`product` 微服务的`getProduct` API 以查询参数指定的概率随机抛出异常，从 0 到 100%。例如，如果参数设置为`25`，它将使平均每四次 API 调用中的第四次失败并抛出异常。在这些情况下，它将返回 HTTP 错误 500 内部服务器错误。

# API 定义的更改

我们之前引入的两个查询参数`delay`和`faultPercentage`，已在`api`项目中的以下两个 Java 接口中定义：

+   `se.magnus.api.composite.product.ProductCompositeService`：

```java
Mono<ProductAggregate> getCompositeProduct(
    @PathVariable int productId,
    @RequestParam(value = "delay", required = false, defaultValue = 
    "0") int delay,
    @RequestParam(value = "faultPercent", required = false, 
    defaultValue = "0") int faultPercent
);
```

+   `se.magnus.api.core.product.ProductService`：

```java
Mono<Product> getProduct(
     @PathVariable int productId,
     @RequestParam(value = "delay", required = false, defaultValue
     = "0") int delay,
     @RequestParam(value = "faultPercent", required = false, 
     defaultValue = "0") int faultPercent
);
```

# 产品组合微服务的更改

`product-composite` 微服务只是将参数传递给产品 API。服务实现接收到 API 请求，并将参数传递给调用产品 API 的集成组件：

+   对`se.magnus.microservices.composite.product.services.ProductCompositeServiceImpl` 类的调用：

```java
public Mono<ProductAggregate> getCompositeProduct(int productId, int delay, int faultPercent) {
    return Mono.zip(
        ...
        integration.getProduct(productId, delay, faultPercent),
        ....
```

+   对`se.magnus.microservices.composite.product.services.ProductCompositeIntegration` 类的调用：

```java
public Mono<Product> getProduct(int productId, int delay, int faultPercent) {
    URI url = UriComponentsBuilder
        .fromUriString(productServiceUrl + "/product/{pid}?delay=
         {delay}&faultPercent={fp}")
        .build(productId, delay, faultPercent);
    return getWebClient().get().uri(url)...
```

# 产品微服务的更改

`product` 微服务在`se.magnus.microservices.core.product.services.ProductServiceImpl`中实现实际延迟和随机错误生成器，如下所示：

```java
public Mono<Product> getProduct(int productId, int delay, int faultPercent) {
    if (delay > 0) simulateDelay(delay);
    if (faultPercent > 0) throwErrorIfBadLuck(faultPercent);
    ...
}
```

延迟函数`simulateDelay()`使用`Thread.sleep()`函数来模拟延迟：

```java
private void simulateDelay(int delay) {
    LOG.debug("Sleeping for {} seconds...", delay);
    try {Thread.sleep(delay * 1000);} catch (InterruptedException e) {}
    LOG.debug("Moving on...");
}
```

随机错误生成器`throwErrorIfBadLuck()`创建一个在`1`和`100`之间的随机数，如果它等于或大于指定的故障百分比，则抛出异常：

```java
private void throwErrorIfBadLuck(int faultPercent) {
    int randomThreshold = getRandomNumber(1, 100);
    if (faultPercent < randomThreshold) {
        LOG.debug("We got lucky, no error occurred, {} < {}", 
        faultPercent, randomThreshold);
    } else {
        LOG.debug("Bad luck, an error occurred, {} >= {}", 
        faultPercent, randomThreshold);
        throw new RuntimeException("Something went wrong...");
    }
}

private final Random randomNumberGenerator = new Random();
private int getRandomNumber(int min, int max) {
    if (max < min) {
        throw new RuntimeException("Max must be greater than min");
    }
    return randomNumberGenerator.nextInt((max - min) + 1) + min;
}
```

# 添加断路器

正如我们之前提到的，我们需要添加依赖项、注解和配置。我们还需要添加一些处理超时和回退逻辑的代码。我们将在接下来的章节中看到如何进行操作。

# 向构建文件添加依赖项

要在电路中添加断路器，我们必须在构建文件`build.gradle`中添加对适当 Resilience4j 库的依赖：

```java
ext {
   resilience4jVersion = "0.14.1"
}
dependencies {
   implementation("io.github.resilience4j:resilience4j-spring-
    boot2:${resilience4jVersion}")
   implementation("io.github.resilience4j:resilience4j-
    reactor:${resilience4jVersion}")
   ...
```

# 添加断路器和超时逻辑

断路器可以通过在期望其保护的方法上使用`@CircuitBreaker(name="nnn")`注解来应用，这里是指`se.magnus.microservices.composite.product.services.ProductCompositeIntegration`类中的`getProduct()`方法。断路器是由异常触发的，而不是由超时本身触发的。为了能够在超时后触发断路器，我们必须添加在超时后生成异常的代码。使用基于 Project Reactor 的`WebClient`，我们可以通过使用其`timeout(Duration)`方法方便地做到这一点。源代码如下所示：

```java
@CircuitBreaker(name = "product")
public Mono<Product> getProduct(int productId, int delay, int faultPercent) {
    ...
    return getWebClient().get().uri(url)
        .retrieve().bodyToMono(Product.class).log()
        .onErrorMap(WebClientResponseException.class, ex -> 
         handleException(ex))
        .timeout(Duration.ofSeconds(productServiceTimeoutSec));
}
```

断路器的名称`"product"`用于标识我们将要通过的配置。超时参数`productServiceTimeoutSec`作为可配置参数值注入到构造函数中：

```java
private final int productServiceTimeoutSec;

@Autowired
public ProductCompositeIntegration(
    ...
    @Value("${app.product-service.timeoutSec}") int productServiceTimeoutSec
) {
    ...
    this.productServiceTimeoutSec = productServiceTimeoutSec;
}
```

要激活断路器，必须作为 Spring Bean 调用注解方法。在我们的情况下，是 Spring 将集成类注入到服务实现类中，因此作为 Spring Bean 使用：

```java
private final ProductCompositeIntegration integration;

@Autowired
public ProductCompositeServiceImpl(... ProductCompositeIntegration integration) {
    this.integration = integration;
}

public Mono<ProductAggregate> getCompositeProduct(int productId, int delay, int faultPercent) {
    return Mono.zip(..., integration.getProduct(productId, delay, faultPercent), ...
```

# 添加快速失败回退逻辑

为了在断路器打开时应用回退逻辑，即在请求快速失败时，我们可以捕获断路器打开时抛出的`CircuitBreakerOpenException`异常，并调用回退方法。这必须在断路器之外完成，即在调用者中。在我们的情况下，是`product-composite`服务的实现调用集成类。

在这里，我们使用`onErrorReturn`方法在捕获`CircuitBreakerOpenException`时调用`getProductFallbackValue()`方法：

```java
public Mono<ProductAggregate> getCompositeProduct(int productId, int delay, int faultPercent) {
    return Mono.zip(
        ...
        integration.getProduct(productId, delay, faultPercent)
           .onErrorReturn(CircuitBreakerOpenException.class, 
            getProductFallbackValue(productId)),
        ...
```

回退逻辑可以根据从替代来源获取的产品`productId`查找信息，例如，内部缓存。在我们的情况下，除非`productId`是`13`，否则我们返回一个硬编码的值；否则，我们抛出一个未找到异常：

```java
private Product getProductFallbackValue(int productId) {
    if (productId == 13) {
        throw new NotFoundException("Product Id: " + productId + " not 
        found in fallback cache!");
    }
    return new Product(productId, "Fallback product" + productId, 
    productId, serviceUtil.getServiceAddress());
}
```

# 添加配置

最后，断路器的配置添加到配置存储库中的`product-composite.yml`文件中，如下所示：

```java
app.product-service.timeoutSec: 2

resilience4j.circuitbreaker:
  backends:
    product:
      registerHealthIndicator: true
      ringBufferSizeInClosedState: 5
      failureRateThreshold: 50
      waitInterval: 10000
      ringBufferSizeInHalfOpenState: 3
      automaticTransitionFromOpenToHalfOpenEnabled: true
      ignoreExceptions:
        - se.magnus.util.exceptions.InvalidInputException
        - se.magnus.util.exceptions.NotFoundException
```

配置中的大多数值已经在*介绍断路器*部分中描述过，除了以下内容：

+   `app.product-service.timeoutSec`：用于配置我们之前引入的超时。这个设置为两秒。

+   `registerHealthIndicator`：决定熔断器是否在`health`端点显示信息。这设置为`true`。

# 添加重试机制

与熔断器类似，通过添加依赖项、注解和配置来设置重试机制。依赖项已经在之前添加，所以我们只需要添加注解并设置一些配置。然而，由于重试机制会抛出特定的异常，我们还需要添加一些错误处理逻辑。

# 添加重试注解

重试机制可以通过注解`@Retry(name="nnn")`应用于方法，其中`nnn`是用于此方法的配置条目的名称。关于配置的详细信息，请参见*添加配置*部分。在我们这个案例中，与熔断器相同，是`se.magnus.microservices.composite.product.services.ProductCompositeIntegration`类中的`getProduct()`方法：

```java
@Retry(name = "product")
@CircuitBreaker(name = "product")
public Mono<Product> getProduct(int productId, int delay, int faultPercent) {
```

# 处理重试特定异常

通过`@Retry`注解的方法抛出的异常可以被重试机制用`RetryExceptionWrapper`异常包装。为了能够处理方法抛出的实际异常，例如在抛出`CircuitBreakerOpenException`时应用备用方法，调用者需要添加解包`RetryExceptionWrapper`异常并将它们替换为实际异常的逻辑。

在我们的案例中，是`ProductCompositeServiceImpl`类中的`getCompositeProduct`方法使用 Project Reactor API 对`Mono`对象进行调用。`Mono` API 有一个方便的方法`onErrorMap`，可以用来解包`RetryExceptionWrapper`异常。它被用在`getCompositeProduct`方法中，如下所示：

```java
public Mono<ProductAggregate> getCompositeProduct(int productId, int delay, int faultPercent) {
    return Mono.zip(
        ...
        integration.getProduct(productId, delay, faultPercent)
            .onErrorMap(RetryExceptionWrapper.class, retryException -> 
             retryException.getCause())
            .onErrorReturn(CircuitBreakerOpenException.class, 
             getProductFallbackValue(productId)),
```

# 添加配置

重试机制的配置是以与熔断器相同的方式添加的，即在配置存储库中的`product-composite.yml`文件中，如下所示：

```java
resilience4j.retry:
  backends:
    product:
      maxRetryAttempts: 3
      waitDuration: 1000
      retryExceptions:
      - org.springframework.web.reactive.function.client.WebClientResponseException$InternalServerError
```

实际值在*介绍重试机制*部分进行了讨论。

# 添加自动化测试

已经向`test-em-all.bash`测试脚本中的单独函数`testCircuitBreaker()`添加了电路 breaker 的自动化测试：

```java
...
function testCircuitBreaker() {
    echo "Start Circuit Breaker tests!"
    ...
}
...
testCircuitBreaker
echo "End, all tests OK:" `date`
```

为了能够进行一些必要的验证，我们需要访问`product-composite`微服务的`actuator`端点，这些端点不会通过边缘服务器暴露。因此，我们将通过一个独立的 Docker 容器访问`actuator`端点，这个容器将连接到由 Docker Compose 为我们的微服务设置的内部网络。

默认情况下，网络名称基于放置 Docker Compose 文件的文件夹名称。为了避免这种不确定的依赖关系，在`docker-compose`文件中定义了一个显式的网络名称`my-network`。所有容器定义都已更新，以指定它们应附加到`my-network`网络。以下是来自`docker-compose.yml`的一个例子：

```java
...
  product:
    build: microservices/product-service
    networks:
      - my-network
...
networks:
  my-network:
    name: my-network
```

由于容器附属于内部网络，它可以直接访问产品组合的`actuator`端点，而不需要通过边缘服务器。我们将使用 Alpine 作为 Docker 镜像，并使用`wget`而不是`curl`，因为`curl`默认不包括在 Alpine 发行版中。例如，为了能够找出名为`product`的电路 breaker 在`product-composite`微服务中的状态，我们可以运行以下命令：

```java
docker run --rm -it --network=my-network alpine wget product-composite:8080/actuator/health -qO - | jq -r .details.productCircuitBreaker.details.state
```

命令预期返回值为`CLOSED`。

由于我们使用`--rm`标志创建了 Docker 容器，`wget`命令完成后，Docker 引擎将停止并销毁它。

测试开始执行正好这一点，即在执行测试之前验证断路器是否关闭：

```java
EXEC="docker run --rm -it --network=my-network alpine"
assertEqual "CLOSED" "$($EXEC wget product-composite:8080/actuator/health -qO - | jq -r .details.productCircuitBreaker.details.state)"

```

接下来，测试将依次运行三个命令，迫使断路器打开，所有这些命令都将因为`product`服务响应缓慢而失败：

```java
for ((n=0; n<3; n++))
do
    assertCurl 500 "curl -k https://$HOST:$PORT/product-
    composite/$PROD_ID_REVS_RECS?delay=3 $AUTH -s"
    message=$(echo $RESPONSE | jq -r .message)
 assertEqual "Did not observe any item or terminal signal within 
    2000ms" "${message:0:57}"
done
```

**快速重复配置**：`product`服务的超时设置为两秒，因此三秒的延迟将导致超时。当电路断开时，断路器配置为评估最后五个调用。脚本中先于断路器特定测试的测试已经执行了几次成功的调用。失败阈值设置为 50%，即，三次带有三秒延迟的调用足以打开电路。

在电路断开的情况下，我们期望快速失败，也就是说，我们不需要等待超时就能得到响应。我们还期望调用回退方法返回尽力而为的响应。这也适用于正常调用，即，没有请求延迟。以下代码验证了这一点：

```java
assertCurl 200 "curl -k https://$HOST:$PORT/product-composite/$PROD_ID_REVS_RECS?delay=3 $AUTH -s"
assertEqual "Fallback product2" "$(echo "$RESPONSE" | jq -r .name)"

assertCurl 200 "curl -k https://$HOST:$PORT/product-composite/$PROD_ID_REVS_RECS $AUTH -s"
assertEqual "Fallback product2" "$(echo "$RESPONSE" | jq -r .name)"

```

我们还可以验证模拟未找到错误逻辑在回退方法中按预期工作，即回退方法返回`404`、`NOT_FOUND`对于产品 ID `13`：

```java
assertCurl 404 "curl -k https://$HOST:$PORT/product-composite/$PROD_ID_NOT_FOUND $AUTH -s"
assertEqual "Product Id: $PROD_ID_NOT_FOUND not found in fallback cache!" "$(echo $RESPONSE | jq -r .message)"
```

如配置所示，断路器在`10`秒后会将其状态更改为半打开。为了能够验证这一点，测试等待`10`秒：

```java
echo "Will sleep for 10 sec waiting for the CB to go Half Open..."
sleep 10

```

在验证预期状态（半关闭）后，测试运行三个正常请求，使断路器回到正常状态，这也得到了验证：

```java
assertEqual "HALF_OPEN" "$($EXEC wget product-composite:8080/actuator/health -qO - | jq -r .details.productCircuitBreaker.details.state)"

for ((n=0; n<3; n++))
do
    assertCurl 200 "curl -k https://$HOST:$PORT/product-
    composite/$PROD_ID_REVS_RECS $AUTH -s"
    assertEqual "product name C" "$(echo "$RESPONSE" | jq -r .name)"
done

assertEqual "CLOSED" "$($EXEC wget product-composite:8080/actuator/health -qO - | jq -r .details.productCircuitBreaker.details.state)"
```

**快速重复配置：**断路器在半打开状态下配置为评估前三个调用。因此，我们需要运行三个请求，其中超过 50%的成功率，然后电路才会关闭。

测试通过使用由断路器暴露出的`/actuator/circuitbreakerevents`actuator API 结束，该 API 用于揭示内部事件。例如，它可以用来找出断路器执行了哪些状态转换。我们期望最后三个状态转换如下：

+   首先状态转换：从关闭到开放

+   下一个状态转换：从开放到半关闭

+   最后状态转换：从半关闭到关闭

这由以下代码验证：

```java
assertEqual "CLOSED_TO_OPEN"      "$($EXEC wget product-composite:8080/actuator/circuitbreakerevents/product/STATE_TRANSITION -qO - | jq -r .circuitBreakerEvents[-3].stateTransition)"
assertEqual "OPEN_TO_HALF_OPEN"   "$($EXEC wget product-composite:8080/actuator/circuitbreakerevents/product/STATE_TRANSITION -qO - | jq -r .circuitBreakerEvents[-2].stateTransition)"
assertEqual "HALF_OPEN_TO_CLOSED" "$($EXEC wget product-composite:8080/actuator/circuitbreakerevents/product/STATE_TRANSITION -qO - | jq -r .circuitBreakerEvents[-1].stateTransition)"
```

`jq`表达式`circuitBreakerEvents[-1]`意味着数组中的最后一个事件`[-2]`是倒数第二个事件，而`[-3 ]`是倒数第三个事件。它们一起是三个最新的事件，即我们感兴趣的事件。默认情况下，Resilience4j 为每个断路器保持最后 100 个事件。这可以通过`eventConsumerBufferSize`配置参数进行自定义。

我们在测试脚本中添加了许多步骤，但有了这个，我们可以自动验证我们断路器预期的基本行为是否到位。在下一节，我们将尝试它！

# 尝试断路器和重试机制

现在，是尝试断路器和重试机制的时候了。我们将像往常一样开始，构建 Docker 镜像并运行测试脚本`test-em-all.bash`。之后，我们将手动运行我们之前描述的测试，以确保我们了解发生了什么！我们将执行以下手动测试：

+   断路器的快乐日测试，也就是说，验证在正常操作中断路器是关闭的

+   断路器的负面测试，也就是说，当事情开始出错时，验证断路器是否会打开

+   恢复正常操作，也就是说，一旦问题解决，验证断路器是否回到了关闭状态

+   尝试带有随机错误的的重试机制

# 构建和运行自动化测试

为了构建和运行自动化测试，我们需要做以下工作：

1.  首先，使用以下命令构建 Docker 镜像：

```java
cd $BOOK_HOME/Chapter13
./gradlew build && docker-compose build
```

1.  接下来，在 Docker 中启动系统架构并使用以下命令运行常规测试：

```java
./test-em-all.bash start
```

当测试脚本打印出`Start Circuit Breaker tests!`时，我们之前描述的测试被执行！

# 验证在正常操作中断路器是关闭的

在我们能够调用 API 之前，我们需要一个访问令牌。运行以下命令以获取访问令牌：

```java
unset ACCESS_TOKEN
ACCESS_TOKEN=$(curl -k https://writer:secret@localhost:8443/oauth/token -d grant_type=password -d username=magnus -d password=password -s | jq -r .access_token)
echo $ACCESS_TOKEN
```

尝试一个正常请求并验证它返回 HTTP 响应代码`200`：

```java
curl -H "Authorization: Bearer $ACCESS_TOKEN" -k https://localhost:8443/product-composite/2 -w "%{http_code}\n" -o /dev/null -s
```

`-w "%{http_code}\n"`选项用于打印 HTTP 返回状态。只要命令返回`200`，我们就对响应体不感兴趣，因此使用该选项抑制它，即`-o /dev/null`。

使用`health`API 验证断路器是否关闭：

```java
docker run --rm -it --network=my-network alpine wget product-composite:8080/actuator/health -qO - | jq -r .details.productCircuitBreaker.details.state
```

我们期望它响应`CLOSED`。

# 当事情出错时强制打开断路器

现在，是让事情变糟的时候了！我的意思是，是时候尝试一些负测试，以验证当事情开始出错时电路是否会打开。调用 API 三次，并将`product`服务导致超时，即每次调用延迟`3`秒的响应。这应该足以触发断路器：

```java
curl -H "Authorization: Bearer $ACCESS_TOKEN" -k https://localhost:8443/product-composite/2?delay=3 -s | jq .
```

我们期望每次都得到如下响应：

```java
{
  "timestamp": "2019-05-03T15:12:57.554+0000",
  "path": "/product-composite/2",
  "status": 500,
  "error": "Internal Server Error",
  "message": "Did not observe any item or terminal signal within 2000ms 
   in 'onErrorResume' (and no fallback has been configured)"
}
```

断路器现在打开了，所以如果你在`waitInterval`内尝试第四次（即`10`秒），你会看到快速失败的响应和回退方法的行动。你将立即得到响应，而不是在`2`秒超时触发后得到错误消息：

```java
{
  "productId": 2,
  "name": "Fallback product2",
  ...
}
```

响应将来自回退方法。这可以通过查看 name 字段中的值来识别，即`Fallback product2`。

快速失败和回退方法是断路器的关键能力！

鉴于我们的配置中设置的等待时间仅为 10 秒，这要求你必须非常迅速，才能看到快速失败和回退方法在行动中！处于半开启状态时，你总是可以提交三个新的请求导致超时，迫使断路器回到开启状态，然后迅速尝试第四个请求。然后，你应该从回退方法中得到一个快速失败的响应！你也可以将等待时间增加到一两分钟，但等待这么长时间才能看到电路切换到半开启状态可能会相当无聊。

等待 10 秒钟，让断路器切换到半开启状态，然后运行以下命令验证电路现在是否处于半开启状态：

```java
docker run --rm -it --network=my-network alpine wget product-composite:8080/actuator/health -qO - | jq -r .details.productCircuitBreaker.details.state
```

预期它会响应`HALF_OPEN`。

# 再次关闭断路器

一旦断路器处于半开启状态，它等待三个调用以确定它应该再次打开电路还是恢复正常，即关闭它。

让我们提交三个普通请求来关闭断路器：

```java
curl -H "Authorization: Bearer $ACCESS_TOKEN" -k https://localhost:8443/product-composite/2 -w "%{http_code}\n" -o /dev/null -s
```

它们都应该响应`200`。通过使用`health` API 验证电路是否再次关闭：

```java
docker run --rm -it --network=my-network alpine wget product-composite:8080/actuator/health -qO - | jq -r .details.productCircuitBreaker.details.state
```

我们期望它响应为`CLOSED`。

用以下命令列出最后三个状态转换：

```java
docker run --rm -it --network=my-network alpine wget product-composite:8080/actuator/circuitbreakerevents/product/STATE_TRANSITION -qO - | jq -r '.circuitBreakerEvents[-3].stateTransition, .circuitBreakerEvents[-2].stateTransition, .circuitBreakerEvents[-1].stateTransition'
```

预期它会响应以下命令：

```java
CLOSED_TO_OPEN
OPEN_TO_HALF_OPEN
HALF_OPEN_TO_CLOSED
```

这个响应告诉我们，我们已经将我们的断路器带遍了它的状态图：

+   当错误开始阻止请求成功时，从关闭状态变为开启状态

+   从开启状态变为半开启状态，以查看错误是否消失

+   当错误消失时，即当我们恢复正常操作时，从半开启状态变为关闭状态

# 尝试由随机错误引起的重试

让我们模拟我们的`product`服务或与其通信存在一个-希望是暂时的-随机问题。

我们可以通过使用`faultPercent`参数来实现。如果我们将其设置为`25`，我们期望每个第四个请求都会失败。我们希望重试机制会自动重试请求来帮助我们。注意到重试机制已经启动的一个方法是测量`curl`命令的响应时间。正常响应应该不会超过 100 毫秒。由于我们配置了重试机制等待一秒钟（参见前面的重试机制中的`waitDuration`参数），我们期望每次重试尝试的响应时间会增加一秒钟。要强制发生随机错误，多次运行以下命令：

```java
time curl -H "Authorization: Bearer $ACCESS_TOKEN" -k https://localhost:8443/product-composite/2?faultPercent=25 -w "%{http_code}\n" -o /dev/null -s
```

命令应当返回`200`状态码，表示请求成功。响应时间前缀为`real`的，例如`real 0m0.078s`，意味着响应时间为 0.078 秒或 78 毫秒。正常的响应，即没有进行任何重试的响应，应该如下所示：

```java
200
real 0m0.078s
...
```

一次重试后的响应应该如下所示：

```java
200
real 0m1.077s
```

HTTP 状态码 200 表示请求已经成功，即使它需要重试一次才能成功！

在你注意到响应时间为一秒之后，即请求需要重试一次才能成功时，运行以下命令来查看最后的两次重试事件：

```java
docker run --rm -it --network=my-network alpine wget product-composite:8080/actuator/retryevents -qO - | jq '.retryEvents[-2], .retryEvents[-1]'
```

你应该能够看到失败的请求和下一次成功的尝试。`creationTime`时间戳预计会相差一秒钟。期待如下的响应：

```java
{
  "retryName": "product",
  "type": "RETRY",
  "creationTime": "2019-05-01T05:40:18.458858Z[Etc/UTC]",
  "errorMessage": "org.springframework.web.reactive.
    function.client.WebClientResponseException$InternalServerError: 500 
    Internal Server Error",
  "numberOfAttempts": 1
}
{
  "retryName": "product",
  "type": "SUCCESS",
  "creationTime": "2019-05-01T05:40:19.471136Z[Etc/UTC]",
  "numberOfAttempts": 1
}
```

如果你真的非常倒霉，你会连续得到两个错误，然后你的响应时间会变成两秒而不是一秒。如果你重复执行前面的命令，你可以看到`numberOfAttempts`字段对每次重试尝试进行计数，在本例中设置为`2`：`"numberOfAttempts": 2`。如果调用继续失败，熔断器将启动并打开其电路，即后续的调用将会快速失败并应用回退方法！

**就是这么简单！**

随意发挥配置中的参数，以更好地了解熔断器和重试机制！

# 总结

在本章中，我们看到了 Resilience4j 及其熔断器和重试机制的实际应用。

当熔断器打开时，使用快速失败和`fallback`方法，可以防止微服务在它依赖的正常响应的同步服务停止响应时变得无响应。熔断器还可以通过在半开状态下允许请求来使微服务具有弹性，以查看失败的服务是否再次正常运行并关闭电路。

重试机制可以使微服务具有弹性，通过重试偶尔由于临时网络问题而失败的请求。非常重要的一点是，只有对幂等性服务应用重试请求，也就是说，可以处理相同请求发送两次或多次的服务。

断路器和重试机制遵循 Spring Boot 约定实现，即声明依赖项，并添加注解和配置。Resilience4j 在运行时通过`actuator`端点暴露有关其断路器和重试机制的信息，包括断路器和事件以及重试的事件和度量指标。

在本章中，我们看到了健康和事件端点的使用，但我们必须等到第二十章，*监控微服务*，我们才能使用任何度量指标。

在下一章中，我们将涵盖使用 Spring Cloud 的最后部分，届时我们将学习如何使用 Spring Cloud Sleuth 和 Zipkin 通过一组协作的微服务跟踪调用链。前往第十四章，*理解分布式跟踪*，开始学习吧！

# 问题

+   断路器有哪些状态，它们是如何使用的？

+   我们如何处理断路器中的超时错误？

+   当断路器快速失败时，我们如何应用回退逻辑？

+   重试机制和断路器如何相互干扰？

+   提供一个无法应用重试机制的服务示例。


# 第十四章：理解分布式追踪

在本章中，我们将学习如何使用分布式追踪更好地了解我们的微服务如何协作，例如，对外部 API 发送请求。能够利用分布式追踪对于能够管理相互协作的微服务系统架构至关重要。如已在第八章, *Spring Cloud 简介*中提到的*Spring Cloud Sleuth 和 Zipkin 进行分布式追踪*部分所述，Spring Cloud Sleuth 将用于收集追踪信息，而 Zipkin 将用于存储和可视化所述追踪信息。

在本章中，我们将学习以下主题：

+   使用 Spring Cloud Sleuth 和 Zipkin 引入分布式追踪

+   如何将分布式追踪添加到源代码中

+   如何进行分布式追踪：

    +   我们将学习如何使用 Zipkin 可视化追踪信息，并与以下内容相关：

        +   成功和失败的 API 请求

        +   API 请求的同步和异步处理

    +   我们将同时使用 RabbitMQ 和 Kafka 将微服务中的追踪事件发送到 Zipkin 服务器

# 技术要求

本书中描述的所有命令都是在 MacBook Pro 上使用 macOS Mojave 运行的，但应该很容易修改，以便它们可以在其他平台（如 Linux 或 Windows）上运行。

在本章中不需要安装任何新工具。

本章的源代码可以在 GitHub 上找到，地址为[`github.com/PacktPublishing/Hands-On-Microservices-with-Spring-Boot-and-Spring-Cloud/tree/master/Chapter14`](https://github.com/PacktPublishing/Hands-On-Microservices-with-Spring-Boot-and-Spring-Cloud/tree/master/Chapter14)。

为了能够按照书中描述运行命令，将源代码下载到一个文件夹中，并设置一个环境变量`$BOOK_HOME`，使其指向该文件夹。一些示例命令如下：

```java
export BOOK_HOME=~/Documents/Hands-On-Microservices-with-Spring-Boot-and-Spring-Cloud
git clone https://github.com/PacktPublishing/Hands-On-Microservices-with-Spring-Boot-and-Spring-Cloud $BOOK_HOME
cd $BOOK_HOME/Chapter14
```

该 Java 源代码是为 Java 8 编写的，并在 Java 12 上进行了测试。本章使用 Spring Cloud 2.1.0, SR1（也称为**Greenwich**版本），Spring Boot 2.1.4 和 Spring 5.1.6，即在撰写本章时可用的 Spring 组件的最新版本。

所有 Dockerfile 中均使用基础 Docker 镜像`openjdk:12.0.2`。

本章中的所有示例代码均来自`$BOOK_HOME/Chapter14`的源代码，但在许多情况下，为了删除源代码中不相关部分，例如注释和导入以及日志声明，对其进行了编辑。

如果你想查看本章源代码所做的更改，即了解添加 Spring Cloud Sleuth 和 Zipkin 进行分布式追踪所需的内容，你可以将其与第十三章, *使用 Resilience4j 提高弹性*的源代码进行比较。你可以使用你喜欢的`diff`工具，比较两个文件夹——`$BOOK_HOME/Chapter13`和`$BOOK_HOME/Chapter14`。

# 使用 Spring Cloud Sleuth 和 Zipkin 引入分布式跟踪。

回顾第八章，*Spring Cloud 简介*，在*分布式跟踪的 Spring Cloud Sleuth 和 Zipkin*部分，整个工作流程的跟踪信息称为一个**跟踪**或一个**跟踪树**，树的子部分，例如工作基本单元，称为一个**跨度**。跨度可以包括子跨度，形成跟踪树。Zipkin UI 可以如下可视化跟踪树和其跨度：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/c486eb1c-6ecf-4f66-9783-fdecfe33f7dc.png)

Spring Cloud Sleuth 可以通过 HTTP 同步发送跟踪信息到 Zipkin，或者使用 RabbitMQ 或 Kafka 等消息代理异步发送。为了避免在微服务中创建对 Zipkin 服务器的运行时依赖，最好使用 RabbitMQ 或 Kafka 异步发送跟踪信息到 Zipkin。以下图表说明了这一点：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/0006d41f-9f89-4f39-a1ca-8d3971451602.png)

Zipkin 支持本地存储跟踪信息，存储在内存中，或存储在 Apache Cassandra、Elasticsearch 或 MySQL 中。此外，还有许多扩展可用。具体信息请参考[`zipkin.apache.org/pages/extensions_choices.html`](https://zipkin.apache.org/pages/extensions_choices.html)。在本章中，我们将把跟踪信息存储在内存中。

# 向源代码添加分布式跟踪。

在本节中，我们将学习如何更新源代码，使用 Spring Cloud Sleuth 和 Zipkin 启用分布式跟踪。可以通过以下步骤完成：

1.  向构建文件添加依赖项，以引入 Spring Cloud Sleuth 和将跟踪信息发送到 Zipkin 的能力。

1.  为之前未使用过的项目（即 Spring Cloud 项目的`authorization-server`、`eureka-server`和`gateway`）添加 RabbitMQ 和 Kafka 依赖项。

1.  配置微服务使用 RabbitMQ 或 Kafka 将跟踪信息发送到 Zipkin。

1.  在 Docker Compose 文件中添加一个 Zipkin 服务器。

1.  在`docker-compose-kafka.yml`中为 Spring Cloud 项目的`authorization-server`、`eureka-server`和`gateway`添加`kafka` Spring 配置文件。

添加 Zipkin 服务器将通过使用 Docker Hub 上由 Zipkin 项目发布的 Docker 镜像来实现。具体细节请参考[`hub.docker.com/r/openzipkin/zipkin`](https://hub.docker.com/r/openzipkin/zipkin)。

Zipkin 本身是一个 Spring Boot 应用程序，在撰写本文时，它正在 Apache 软件基金会（ASF）下孵化。更多信息请参考[`zipkin.apache.org/`](https://zipkin.apache.org/)。

# 向构建文件添加依赖项。

为了能够使用 Spring Cloud Sleuth 并发送跟踪信息到 Zipkin，我们需要在 Gradle 项目的构建文件`build.gradle`中添加几个依赖项：

这通过添加以下两行来实现：

```java
implementation('org.springframework.cloud:spring-cloud-starter-sleuth')   implementation('org.springframework.cloud:spring-cloud-starter-zipkin')
```

对于尚未使用过 RabbitMQ 和 Kafka 的 Gradle 项目，即 Spring Cloud 项目`authorization-server`、`eureka-server`和`gateway`，需要添加以下依赖项：

```java
implementation('org.springframework.cloud:spring-cloud-starter-stream-rabbit')
implementation('org.springframework.cloud:spring-cloud-starter-stream-kafka')
```

# 为 Spring Cloud Sleuth 和 Zipkin 添加配置

在公共配置文件`config-repo/application.yml`中添加了使用 Spring Cloud Sleuth 和 Zipkin 的配置。在默认配置文件中，指定跟踪信息应通过 RabbitMQ 发送到 Zipkin：

```java
spring.zipkin.sender.type: rabbit
```

默认情况下，Spring Cloud Sleuth 只将 10%的跟踪信息发送到 Zipkin。为了确保所有跟踪信息都发送到 Zipkin，在默认配置文件中添加了以下属性：

```java
spring.sleuth.sampler.probability: 1.0
```

当使用 Kafka 将跟踪信息发送到 Zipkin 时，将使用`kafka`Spring 配置文件。在前几章中，`kafka`Spring 配置文件是在特定于组合和核心微服务的配置文件中定义的。在本章中，Spring Cloud 服务也将使用 Kafka 将跟踪信息发送到 Zipkin，因此将`kafka`Spring 配置文件移动到公共配置文件`config-repo/application.yml`中。在`kafka`Spring 配置文件中还添加了以下两个属性：

+   `spring.zipkin.sender.type: kafka`告诉 Spring Cloud Sleuth 使用 Kafka 将跟踪信息发送到 Zipkin。

+   `spring.kafka.bootstrap-servers: kafka:9092`指定了 Kafka 服务器的所在位置。

总的来说，`kafka`Spring 配置文件如下所示：

```java
--- 
spring.profiles: kafka

management.health.rabbit.enabled: false
spring.cloud.stream.defaultBinder: kafka
spring.zipkin.sender.type: kafka
spring.kafka.bootstrap-servers: kafka:9092
```

# 将 Zipkin 添加到 Docker Compose 文件中

正如我们之前提到的，Zipkin 服务器是通过使用已经存在的 Docker 镜像`openzipkin/zipkin`添加到 Docker Compose 文件中的，该镜像是由 Zipkin 项目发布的。在`docker-compose.yml`和`docker-compose-partitions.yml`中，其中使用 RabbitMQ 时，Zipkin 服务器的定义如下所示：

```java
zipkin:
  image: openzipkin/zipkin:2.12.9
  networks:
    - my-network
  environment:
    - RABBIT_ADDRESSES=rabbitmq
    - STORAGE_TYPE=mem
  mem_limit: 512m
  ports:
    - 9411:9411
  depends_on:
    rabbitmq:
      condition: service_healthy
```

让我们解释一下前面的源代码：

+   Docker 镜像`openzipkin/zipkin`的版本被指定为`2.12.19`版本。

+   环境变量`RABBIT_ADDRESSES=rabbitmq`用于指定 Zipkin 使用 RabbitMQ 接收跟踪信息，并且 Zipkin 使用主机名`rabbitmq`连接到 RabbitMQ。

+   环境变量`STORAGE_TYPE=mem`用于指定 Zipkin 将所有跟踪信息保存在内存中。

+   Zipkin 的内存限制增加到 512 MB，而其他容器的内存限制为 350 MB。这是因为 Zipkin 被配置为将所有跟踪信息保存在内存中，所以过了一段时间后，它将比其他容器消耗更多的内存。

+   Zipkin 暴露出 HTTP 端口`9411`，供浏览器访问其 Web 用户界面。

+   Docker 将等待启动 Zipkin 服务器，直到 RabbitMQ 服务向 Docker 报告自己运行正常。

虽然这对于将跟踪信息存储在 Zipkin 内存中以进行开发和测试活动来说是可行的，但在生产环境中，Zipkin 应配置为将跟踪信息存储在数据库中，例如 Apache Cassandra、Elasticsearch 或 MySQL。

在`docker-compose-kafka.yml`中，其中使用了 Kafka，Zipkin 服务器的定义如下所示：

```java
zipkin:
  image: openzipkin/zipkin:2.12.9  
  networks: 
    - my-network 
  environment:
    - KAFKA_BOOTSTRAP_SERVERS=kafka:9092
    - STORAGE_TYPE=mem 
  mem_limit: 512m
  ports: 
    - 9411:9411 
  depends_on: 
    - kafka
```

让我们详细解释一下前面的源代码：

+   使用 Zipkin 和 Kafka 的配置与之前使用 Zipkin 和 RabbitMQ 的配置相似。

+   主要区别在于使用`KAFKA_BOOTSTRAP_SERVERS=kafka:9092`环境变量，该变量用于指定 Zipkin 应使用 Kafka 接收跟踪信息，并且 Zipkin 应通过主机名`kafka`和端口`9092`连接到 Kafka。

在`docker-compose-kafka.yml`中，为 Spring Cloud 服务`eureka`、`gateway`和`auth-server`添加了`kafka` Spring 配置文件：

```java
    environment:
      - SPRING_PROFILES_ACTIVE=docker,kafka
```

这就是使用 Spring Cloud Sleuth 和 Zipkin 添加分布式跟踪所需的一切，所以在下一节让我们试试吧！

# 尝试分布式跟踪

在源代码中进行了必要的更改后，我们可以尝试分布式跟踪！我们将通过执行以下步骤来实现：

1.  构建、启动并验证使用 RabbitMQ 作为队列管理器的系统架构。

1.  发送一个成功的 API 请求，看看我们可以找到与这个 API 请求相关的 Zipkin 中的跟踪信息。

1.  发送一个失败的 API 请求，看看 Zipkin 中的跟踪信息是什么样子。

1.  发送一个成功的 API 请求，触发异步处理，并查看其在 Zipkin 中的跟踪信息表示。

1.  调查如何监控通过 RabbitMQ 传递给 Zipkin 的跟踪信息。

1.  将队列管理器切换到 Kafka，并重复前面的步骤。

我们将在接下来的部分详细讨论这些步骤。

# 使用 RabbitMQ 作为队列管理器启动系统架构

让我们启动系统架构。使用以下命令构建 Docker 镜像：

```java
cd $BOOK_HOME/Chapter14
./gradlew build && docker-compose build
```

使用 Docker 启动系统架构，并使用以下命令运行常规测试：

```java
./test-em-all.bash start
```

在我们可以调用 API 之前，我们需要一个访问令牌。运行以下命令以获取访问令牌：

```java
unset ACCESS_TOKEN
ACCESS_TOKEN=$(curl -k https://writer:secret@localhost:8443/oauth/token -d grant_type=password -d username=magnus -d password=password -s | jq -r .access_token)
echo $ACCESS_TOKEN
```

# 发送一个成功的 API 请求

现在，我们准备发送一个正常的 API 请求。运行以下命令：

```java
curl -H "Authorization: Bearer $ACCESS_TOKEN" -k https://localhost:8443/product-composite/2 -w "%{http_code}\n" -o /dev/null -s
```

期望命令返回成功的 HTTP 状态码，即 200。

现在我们可以启动 Zipkin UI，查看已经发送到 Zipkin 的跟踪信息：

1.  在您的网络浏览器中打开以下 URL：`http://localhost:9411/zipkin/`。

1.  为了找到我们请求的跟踪信息，请执行以下步骤：

    1.  选择“服务名称”：gateway。

    1.  设置排序顺序：最新优先。

    1.  点击“查找跟踪”按钮。

查找跟踪的响应应如下所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/ee509be8-dcc5-41bb-b758-361379f8fe94.png)

我们之前的 API 请求的跟踪信息是列表中的第一个。点击它以查看与跟踪相关的详细信息：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/8fa726b9-d1b5-424a-ade5-c5324f925c2c.png)

在详细的跟踪信息视图中，我们可以观察到以下内容：

1.  请求被网关服务接收。

1.  它将请求的处理委托给了`product-composite`服务。

1.  `product-composite`服务反过来向核心服务发送了三个并行请求：`product`、`recommendation`和`review`。

1.  一旦`product-composite`服务收到了所有三个核心服务的响应，它就创建了一个复合响应。

1.  复合响应通过网关服务返回到调用者。

当使用 Safari 时，我注意到跟踪树并不总是正确渲染。切换到 Chrome 或 Firefox 可以解决此问题。

如果我们点击第一个跨度，网关，我们可以看到更多细节：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/f6f693ce-7cea-43ea-ba6c-8faa8db74269.png)

这里，我们可以看到我们实际发送的请求：`product-composite/2`。这在我们分析例如长时间完成的跟踪时非常有价值！

# 发送一个失败的 API 请求

让我们看看如果我们发起一个失败的 API 请求会怎样，例如，搜索一个不存在的产品：

1.  为产品 ID `12345`发送 API 请求，并验证它返回了未找到的 HTTP 状态码，即 404：

```java
curl -H "Authorization: Bearer $ACCESS_TOKEN" -k https://localhost:8443/product-composite/12345 -w "%{http_code}\n" -o /dev/null -s
```

1.  在 Zipkin UI 中，回到搜索页面（在网页浏览器中使用后退按钮）并点击“查找跟踪”按钮。你应该会在返回列表的顶部看到失败的请求，用红色标出：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/3b7bf196-16fe-4277-8e51-3f393696278f.png)

1.  点击标记为红色的顶部跟踪：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/4ca53dfa-35ad-4c3c-b50f-8e3a3c357f61.png)

1.  在详细跟踪视图中，我们可以通过颜色编码看到产品服务在调用`product-composite`时出了错。点击产品跨度以查看出错详情：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/b33855c9-3b3e-4aaf-81ed-8a080c05dec7.png)

这里，我们可以看到导致错误的请求`product/12345`以及返回的错误代码和原因：404 Not Found。这在我们分析故障的根本原因时非常有用！

# 发送一个触发异步处理的 API 请求

在 Zipkin UI 中看到的第三种有趣的请求类型是一个部分处理异步的请求。让我们尝试一个删除请求，其中核心服务中的删除过程是异步完成的。`product-composite`服务向消息代理的每个核心服务发送一个删除事件，并且每个核心服务都会拾取该删除事件并异步处理它。得益于 Spring Cloud Sleuth，发送到消息代理的事件中添加了跟踪信息，从而实现了对删除请求整体处理的连贯视图。

运行以下命令删除具有产品 ID`12345`的产品，并验证它返回成功的 HTTP 状态码，200：

```java
curl -X DELETE -H "Authorization: Bearer $ACCESS_TOKEN" -k https://localhost:8443/product-composite/12345 -w "%{http_code}\n" -o /dev/null -s
```

记住删除操作是幂等的，即即使产品不存在，它也会成功！

在 Zipkin UI 中，回到搜索页面（在 Web 浏览器中使用后退按钮）并点击`Find Traces`按钮。你应该在返回列表的顶部看到删除请求的跟踪：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/c8304d85-6234-4bf4-9470-e18b2f92a68a.png)

点击第一个跟踪以查看其跟踪信息：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/b06714c3-aec0-4166-a066-2001d3c14c3d.png)

在这里，我们可以看到处理删除请求的跟踪信息：

1.  请求被`gateway`服务接收。

1.  它将请求的处理委托给了`product-composite`服务。

1.  反过来，`product-composite`服务在消息代理（本例中为 RabbitMQ）上发布了三个事件。

1.  `product-composite`服务现在完成并返回一个成功的 HTTP 状态码，200，通过网关服务返回到调用者。

1.  核心服务`product`、`recommendation`和`review`接收到删除事件并开始异步处理它们，即彼此独立处理。

要查看更详细的信息，点击产品跨度：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/7fd269c2-3bc7-4c83-91cd-6a16c6010757.png)

在这里，我们可以看到产品服务被输入通道的事件触发，该事件是从消息代理发送的。

Zipkin UI 包含更多查找感兴趣跟踪的功能！

为了更熟悉 Zipkin UI，尝试使用`Annotation Query`参数；例如，使用`http.path=/product-composite/214`或`error=401`查找因授权失败而失败的请求。注意默认设置为`10`的`Limit`参数，这可能会隐藏感兴趣的结果。还要确保`Lookback`参数不会删除感兴趣的跟踪！

# 监控通过 RabbitMQ 发送到 Zipkin 的跟踪信息

要监控通过 RabbitMQ 发送到 Zipkin 的跟踪信息，我们可以使用 RabbitMQ 管理 Web UI。在 Web 浏览器中打开以下 URL：`http://localhost:15672/#/queues/%2F/zipkin`。如果需要，使用用户名`guest`和密码`guest`登录。期待一个看起来像以下的网页：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/0ebbf762-280a-457c-b52e-7344c666c249.png)

在名为`Message Rates`的图表中，我们可以看到跟踪消息正在以每秒 1.2 条消息的平均速率发送到 Zipkin。

使用以下命令结束 RabbitMQ 的分布式跟踪测试，关闭系统架构：

```java
docker-compose down
```

# 使用 Kafka 作为消息代理

让我们也验证一下我们可以使用 Kafka 而不是 RabbitMQ 向 Zipkin 发送跟踪信息！

使用以下命令启动系统架构：

```java
export COMPOSE_FILE=docker-compose-kafka.yml
./test-em-all.bash start
```

重复我们在前面章节中执行的命令，当时我们使用 RabbitMQ，并验证您可以在使用 Kafka 时在 Zipkin UI 中看到相同的跟踪信息：

Kafka 不提供像 RabbitMQ 那样的管理 Web UI。因此，我们需要运行一些 Kafka 命令来验证跟踪事件实际上是通过 Kafka 发送到 Zipkin 服务器的：

要在 Docker 容器中运行 Kafka 命令，请参阅第七章 *《开发响应式微服务》* 中的“每个主题使用两个分区”部分。

1.  首先，列出 Kafka 中可用的主题：

```java
docker-compose exec kafka /opt/kafka/bin/kafka-topics.sh --zookeeper zookeeper --list
```

1.  问题：

跟踪事件的具体细节并不重要。Zipkin 服务器为我们整理了信息，并在 Zipkin UI 中使其易于查看。这里的关键是我们可以看到通过 Kafka 发送到 Zipkin 服务器的跟踪事件。

1.  接下来，询问发送到`zipkin`话题的跟踪事件：

```java
docker-compose exec kafka /opt/kafka/bin/kafka-console-consumer.sh --bootstrap-server localhost:9092 --topic zipkin --from-beginning --timeout-ms 1000
```

1.  期待很多与以下类似的长时间运行的请求：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/8fcdde07-be13-497a-8b95-1b56e4fe3a95.png)

在下一章中，我们将学习容器编排器，特别是 Kubernetes。我们将学习如何使用 Kubernetes 部署和管理微服务，同时提高重要的运行时特性，如可伸缩性、高可用性和弹性。

现在，请关闭系统架构并取消设置`COMPOSE_FILE`环境变量：

```java
docker-compose down
unset COMPOSE_FILE
```

这结束了关于分布式跟踪的章节！

# 摘要

期待找到一个名为`zipkin`的话题：

Zipkin UI 使识别复杂工作流中的哪个部分导致意外的长时间响应或错误变得非常容易。无论是同步还是异步工作流，都可以通过 Zipkin UI 进行可视化。

在本章中，我们学习了如何使用分布式跟踪来了解微服务如何协同工作。我们还学习了如何使用 Spring Cloud Sleuth 收集跟踪信息，以及如何使用 Zipkin 存储和可视化跟踪信息。

# `spring.sleuth.sampler.probability`配置参数的目的是什么？

1.  控制跟踪信息发送到 Zipkin 的配置参数是什么？

1.  如何在执行`test-em-all.bash`测试脚本后识别最长的运行请求？

1.  如何推广运行时组件的解耦？我们已经了解到如何在构建文件中添加几个依赖项，并设置一些配置参数。

1.  我们如何在第十三章 *使用 Resilience4j 提高弹性* 中找到被超时中断的请求？

1.  当第十三章中引入的断路器*Improving Resilience Using Resilience4j*打开时，API 请求的跟踪日志是什么样的？

1.  我们如何定位因调用者未获得授权而失败的 API？


# 第三部分：使用 Kubernetes 开发轻量级微服务

本节将帮助你理解 Kubernetes 作为容器化工作负载的运行时平台的重要性。你将学习如何在本地开发环境中设置 Kubernetes，并在 Kubernetes 上部署微服务。最后，你将学习如何使用 Kubernetes 的一些最重要的特性，而不是相应的 Spring Cloud 特性，以提供一个更轻量级的微服务系统架构（例如，更容易维护和管理）。

本节包括以下章节：

+   第十五章，*Kubernetes 简介*

+   第十六章，*在 Kubernetes 中部署我们的微服务*

+   第十七章，*作为替代实现 Kubernetes 特性*

+   第十八章，*使用服务网格提高可观测性和管理*

+   第十九章，*使用 EFK 堆栈进行集中日志管理*

+   第二十章，*监控微服务*


# 第十五章：介绍 Kubernetes

在本章中，我们将开始学习 Kubernetes，这是在撰写本书时最受欢迎和广泛使用的容器编排器。由于一般容器编排器以及 Kubernetes 本身的内容太多，无法在一章中覆盖，我将重点介绍在我过去几年使用 Kubernetes 时发现最重要的内容。

本章将涵盖以下主题：

+   介绍 Kubernetes 概念

+   介绍 Kubernetes API 对象

+   介绍 Kubernetes 运行时组件

+   创建本地 Kubernetes 集群

+   尝试一个示例部署并熟悉`kubectl` Kubernetes 命令行工具：

+   管理一个 Kubernetes 集群

# 技术要求

为了在本地与 Kubernetes 合作，我们将使用在 VirtualBox 上运行的 Minikube。我们还将大量使用名为`kubectl`的 Kubernetes CLI 工具。`kubectl`随 Docker for macOS 提供，但不幸的是，版本太旧（至少在撰写本章时）。因此，我们需要安装一个新版本。总共我们需要以下内容：

+   Minikube 1.2 或更高版本

+   `kubectl` 1.15 或更高版本

+   VirtualBox 6.0 或更高版本

这些工具可以使用 Homebrew 以下命令安装：

```java
brew install kubectl
brew cask install minikube
brew cask install virtualbox
```

在安装`kubectl`后，运行以下命令确保使用新版本的`kubectl`：

```java
brew link --overwrite kubernetes-cli
```

安装 VirtualBox 时，它会要求你依赖 VirtualBox 附带的系统扩展：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/d6ccf0f8-41b0-4145-8956-2f97719b5556.png)

点击对话框中的“确定”按钮，然后点击下一个对话窗口中的“允许”按钮：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/23dd883f-5cb1-4078-be74-65f77336496c.png)

通过以下命令验证安装工具的版本：

```java
kubectl version --client --short
minikube version
vboxmanage --version
```

期望得到如下响应：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/860bf0d5-1a10-4dc4-9a58-95c7651f5921.png)

本章的源代码可以在本书的 GitHub 仓库中找到：[`github.com/PacktPublishing/Hands-On-Microservices-with-Spring-Boot-and-Spring-Cloud/tree/master/Chapter15`](https://github.com/PacktPublishing/Hands-On-Microservices-with-Spring-Boot-and-Spring-Cloud/tree/master/Chapter15)。

为了能够运行本书中描述的命令，你需要将源代码下载到一个文件夹中，并设置一个环境变量`$BOOK_HOME`，该变量指向该文件夹。一些示例命令如下：

```java
export BOOK_HOME=~/Documents/Hands-On-Microservices-with-Spring-Boot-and-Spring-Cloud
git clone https://github.com/PacktPublishing/Hands-On-Microservices-with-Spring-Boot-and-Spring-Cloud $BOOK_HOME
cd $BOOK_HOME/Chapter15
```

本章中的所有源代码示例都来自`$BOOK_HOME/Chapter15`的源代码，并使用 Kubernetes 1.15 进行了测试。

# 介绍 Kubernetes 概念

在较高层面上，作为容器编排器，Kubernetes 使得运行容器的服务器集群（物理或虚拟）呈现为一个运行容器的巨大逻辑服务器。作为操作员，我们通过使用 Kubernetes API 创建对象来向 Kubernetes 集群声明期望状态。Kubernetes 持续将期望状态与当前状态进行比较。如果检测到差异，它会采取行动确保当前状态与期望状态一致。

Kubernetes 集群的主要目的之一是部署和运行容器，同时也支持使用绿色/蓝色和金丝雀部署等技术实现零停机滚动升级。Kubernetes 可以安排容器，即包含一个或多个并列容器的**豆荚**，到集群中可用的节点。为了能够监控运行中容器的健康状况，Kubernetes 假定容器实现了**存活探针**。如果存活探针报告了一个不健康的容器，Kubernetes 将重新启动该容器。容器可以在集群中手动或自动扩展，使用水平自动扩展器。为了优化集群中可用硬件资源的使用，例如内存和 CPU，容器可以配置**配额**，指明容器需要多少资源。另一方面，可以在**命名空间**级别指定关于一组容器允许消耗多少资源的上限。随着本章的进行，将介绍命名空间。如果多个团队共享一个 Kubernetes 集群，这尤为重要。

Kubernetes 的另一个主要目的是提供运行豆荚及其容器的服务发现。Kubernetes `Service` 对象可以定义为服务发现，并且还会负载均衡传入请求到可用的豆荚。`Service` 对象可以暴露在 Kubernetes 集群的外部。然而，正如我们将看到的，在许多情况下，Ingress 对象更适合处理一组服务的外部传入流量。为了帮助 Kubernetes 查明一个容器是否准备好接受传入请求，容器可以实现一个**就绪探针**。

内部而言，Kubernetes 集群提供了一个大的扁平化 IP 网络，每个豆荚获得自己的 IP 地址，并且可以独立于它们运行的节点到达所有其他豆荚。为了支持多个网络供应商，Kubernetes 允许使用符合**容器网络接口**（**CNI**）规范的网络插件([`github.com/containernetworking/cni`](https://github.com/containernetworking/cni))。豆荚默认情况下是不隔离的，也就是说，它们接受所有传入请求。支持使用网络策略定义的网络插件可以用来锁定对豆荚的访问，例如，只允许来自同一命名空间中豆荚的流量。

为了使多个团队能够安全地在同一个 Kubernetes 集群上工作，可以应用**基于角色的访问控制**（**RBAC**，[`kubernetes.io/docs/reference/access-authn-authz/rbac`](https://kubernetes.io/docs/reference/access-authn-authz/rbac)/）。例如，管理员可以被授权访问集群级别的资源，而团队成员的访问可以被限制在他们团队拥有的命名空间中创建的资源。

总的来说，这些概念为运行容器提供了一个可扩展、安全、高可用性和弹性的平台。

让我们更深入地了解一下 Kubernetes 中可用的 API 对象，然后看看组成 Kubernetes 集群的运行时组件是什么。

# 介绍 Kubernetes API 对象

Kubernetes 定义了一个 API，用于管理不同类型的*对象*或*资源*，在 API 中也被称为*种类*。根据我的经验，一些最常用的类型或*种类*如下：

+   **节点：** 节点代表集群中的一个服务器，可以是**虚拟的**或**物理的**。

+   **Pod：** Pod 是 Kubernetes 中可部署的最小组件，由一个或多个共置的容器组成。通常，一个 Pod 包含一个容器，但有一些用例通过在 Pod 中运行第二个容器来扩展主容器的功能。在第十八章，*使用服务网格提高可观测性和管理*，将在 Pod 中运行第二个容器，运行一个边车使主容器加入服务网格。

+   **部署**：部署用于部署和升级 Pod。部署对象将创建和监控 Pod 的责任交给了副本集。第一次创建部署时，部署对象所做的工作并不多，只是创建了副本集对象。在执行部署的滚动升级时，部署对象的角色更加复杂。

+   **副本集**：副本集用于确保始终运行指定数量的 Pod。如果一个 Pod 被删除，副本集会用一个新的 Pod 来替换它。

+   **服务（Service）**：服务是一个稳定的网络端点，您可以使用它来连接一个或多个 Pod。服务在 Kubernetes 集群的内部网络中被分配一个 IP 地址和 DNS 名称。服务的 IP 地址在其生命周期内保持不变。发送到服务的请求将通过轮询负载均衡转发到可用的 Pod 之一。默认情况下，服务只通过集群 IP 地址在集群内部暴露。还可以将服务暴露在集群外部，要么在每个节点上专用端口上，要么——更好的方法——通过一个意识到 Kubernetes 的外部负载均衡器，也就是说，它可以自动为服务分配一个公共 IP 地址和/或 DNS 名称。通常，提供 Kubernetes 作为服务的云提供商支持这种负载均衡器。

+   **入口（Ingress）**：入口可以管理 Kubernetes 集群中服务的对外访问，通常使用 HTTP。例如，它可以根据 URL 路径或 HTTP 头（如主机名）将流量路由到底层服务。与其在外部暴露多个服务，使用节点端口或负载均衡器，通常在服务前设置一个入口更为方便。为了处理 Ingress 对象定义的实际通信，必须在集群中运行一个 Ingress 控制器。我们将在后面看到一个 Ingress 控制器的示例。

+   **命名空间（Namespace）**：命名空间用于将资源分组并在某些层面上隔离在 Kubernetes 集群中。资源在其命名空间内的名称必须是唯一的，但命名空间之间不需要唯一。

+   **配置映射（ConfigMap）**：ConfigMap 用于存储容器使用的配置。ConfigMaps 可以映射到运行中的容器作为环境变量或文件。

+   **密钥（Secret）**：此功能用于存储容器使用的敏感数据，例如凭据。密钥可以像 ConfigMaps 一样供容器使用。任何具有对 API 服务器完全访问权限的人都可以访问创建的密钥的值，因此它们并不像名称暗示的那样安全。

+   **守护进程集（DaemonSet）**：这确保在集群的一组节点中每个节点上运行一个 Pod。在第十九章，*使用 EFK 堆栈进行集中日志记录*，我们将看到一个日志收集器 Fluentd 的示例，它将在每个工作节点上运行。

有关 Kubernetes API 在 v1.15 中涵盖的资源对象列表，请参阅[`kubernetes.io/docs/reference/generated/kubernetes-api/v1.15/`](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.15/)。

以下图表总结了处理传入请求的 Kubernetes 资源：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/cdf2a486-253b-4f11-abc7-2ee25e3694e6.png)

在前面的图表中，我们可以看到以下内容：

+   两个部署，**Deployment A** 和 **Deployment B**，已经部署在具有两个节点的集群上，分别是**Node 1**和**Node 2**。

+   **Deployment A** 包含两个 Pod，**Pod A1** 和 **Pod A2**。

+   **Deployment B** 包含一个 **Pod** **B1**。

+   **Pod A1** 被调度到**节点 1**。

+   **Pod A2** 和 **Pod B1** 被调度到**节点 2**。

+   每个部署都有一个对应的服务，**服务 A** 和 **服务 B**，它们在所有节点上都可用。

+   定义了一个 Ingress 以将传入请求路由到两个服务。

+   客户端通常通过外部负载均衡器向集群发送请求。

这些对象本身并不是运行中的组件；相反，它们是不同类型期望状态的定义。为了将期望状态反映到集群的当前状态，Kubernetes 包含一个由多个运行时组件组成的架构，如下一节所述。

# 介绍 Kubernetes 运行时组件

一个 Kubernetes 集群包含两种类型的节点：主节点和工作节点。主节点负责管理集群，而工作节点的的主要用途是运行实际的工作负载，例如我们在集群中部署的容器。Kubernetes 由多个运行时组件构成。最重要的组件如下：

+   在主节点上运行的组件构成了控制平面：

    +   `api-server`，控制平面的入口点。它暴露一个 RESTful API，例如，Kubernetes CLI 工具 `kubectl` 使用该 API。

    +   `etcd`，一个高可用性和分布式键/值存储，用作所有集群数据的数据库。

    +   一个控制器管理器，其中包含多个控制器，这些控制器不断地评估对象在 `etcd` 数据库中定义的期望状态与当前状态。

    +   每当期望状态或当前状态发生变化时，负责该类型状态的控制器会采取行动将当前状态移动到期望状态。例如，负责管理 Pod 的复制控制器如果通过 API 服务器添加新的 Pod 或者运行中的 Pod 停止运行，会做出反应并确保新的 Pod 被启动。控制器的一个其他例子是节点控制器。如果一个节点变得不可用，它负责确保在失败节点上运行的 Pod 被重新调度到集群中的其他节点。

    +   一个**调度器**，负责将新创建的 Pod 分配给具有可用能力的节点，例如，在内存和 CPU 方面。可以使用亲和规则来控制 Pod 如何分配到节点。例如，执行大量磁盘 I/O 的 Pod 可以将分配给拥有快速 SSD 磁盘的一组工作节点。可以定义反亲和规则来分离 Pod，例如，避免将来自同一部署的 Pod 调度到同一工作节点。

+   在所有节点上运行构成数据平面的组件如下：

    +   `kubelet`，这是一个在节点操作系统中直接作为进程执行而不是作为容器的节点代理。它负责在分配给 `kubelet` 运行的节点上运行的 pod 中的容器运行和启动。它充当 `api-server` 和其节点上的容器运行时之间的通道。

    +   `kube-proxy`，这是一个网络代理，它使 Kubernetes 中的服务概念成为可能，并能够将请求转发到适当的 pod，通常如果有多个 pod 可用，就会以轮询方式转发。`kube-proxy` 作为 DaemonSet 部署。

    +   **容器运行时**，运行在节点上的容器的软件。通常这是 Docker，但任何实现 Kubernetes **容器运行时接口**（**CRI**）的都可以使用，例如 `cri-o` ([`cri-o.io`](https://cri-o.io))、`containerd` ([`containerd.io/`](https://containerd.io/)) 或 `rktlet` ([`github.com/kubernetes-incubator/rktlet`](https://github.com/kubernetes-incubator/rktlet))。

    +   **Kubernetes DNS**，这是一个在集群内部网络中使用的 DNS 服务器。服务和 pod 会被分配一个 DNS 名称，而 pod 会被配置使用这个 DNS 服务器来解析内部 DNS 名称。DNS 服务器作为部署对象和服务对象部署。

以下图表总结了 Kubernetes 运行时组件：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/6d8bfda7-c2b2-4b85-b4d7-5f30250bc9b9.png)

既然我们已经了解了 Kubernetes 运行时组件以及它们支持什么和运行在什么上，那么接下来让我们使用 Minikube 创建一个 Kubernetes 集群。

# 使用 Minikube 创建 Kubernetes 集群

现在，我们准备创建一个 Kubernetes 集群！我们将使用 Minikube 创建一个在 VirtualBox 上运行的本地单节点集群。

在创建 Kubernetes 集群之前，我们需要了解一下 Minikube 配置文件、被称为 `kubectl` 的 Kubernetes CLI 工具以及其使用的上下文。

# 使用 Minikube 配置文件工作

为了在本地运行多个 Kubernetes 集群，Minikube 带有一个配置文件的概念。例如，如果你想与多个版本的 Kubernetes 一起工作，可以使用 Minikube 创建多个 Kubernetes 集群。每个集群将被分配一个单独的 Minikube 配置文件。Minikube 的大部分命令都接受一个 `--profile` 标志（或 `-p` 的简写），可以用来指定哪个 Kubernetes 集群应应用该命令。如果你计划与一个特定的配置文件工作一段时间，还有一个更方便的替代方案，你通过以下命令指定当前配置文件：

```java
minikube profile my-profile
```

上述命令会将 `my-profile` 配置文件设置为当前配置文件。

要获取当前配置文件，请运行以下命令：

```java
minikube config get profile
```

如果没有指定配置文件，既没有使用 `minikube profile` 命令也没有使用 `--profile` 选项，那么将使用名为 `minikube` 的默认配置文件。

有关现有配置文件的信息可以在 `~/.minikube/profiles` 文件夹中找到。

# 使用 Kubernetes CLI，kubectl

`kubectl` 是 Kubernetes 的命令行工具。一旦建立了一个集群，这通常是管理集群所需的所有工具！

为了管理本章前面描述的 API 对象，`kubectl apply`命令是您需要了解的唯一命令。它是一个声明性命令，也就是说，作为操作员，我们要求 Kubernetes 应用我们给出的对象定义到命令中。然后由 Kubernetes 决定实际需要执行哪些操作。

许多阅读本书的读者可能熟悉的另一个声明性命令是一个`SQL SELECT`语句，它从几个数据库表中连接信息。我们只在 SQL 查询中声明期望的结果，而数据库查询优化器则负责决定按什么顺序访问表以及使用哪些索引以最有效的方式检索数据。

在某些情况下，显式告诉 Kubernetes 做什么的命令式语句更受欢迎。一个例子是`kubectl delete`命令，我们明确告诉 Kubernetes 删除一些 API 对象。也可以使用显式的`kubectl create namespace`命令方便地创建一个命名空间对象。

重复使用命令式语句会导致它们失败，例如，使用`kubectl delete`删除两次相同的 API 对象，或者使用`kubectl create`创建两次相同的命名空间。声明性命令，即使用`kubectl apply`，在重复使用时不会失败——它只会声明没有变化并退出，不采取任何行动。

以下是一些用于获取关于 Kubernetes 集群信息的一些常用命令：

+   `kubectl get`显示指定 API 对象的信息。

+   `kubectl describe`为指定的 API 对象提供更多详细信息。

+   `kubectl logs`显示容器的日志输出。

我们将在本章及接下来的章节中看到许多这些以及其他`kubectl`命令的示例！

如果您对如何使用`kubectl`工具感到困惑，`kubectl help`和`kubectl <command> --help`命令始终可用，并提供有关如何使用`kubectl`工具非常有用的信息。

# 使用 kubectl 上下文工作

为了能够与多个 Kubernetes 集群一起工作，使用本地 Minikube 或者在本地服务器或云上设置的 Kubernetes 集群，`kubectl` 带来了上下文（contexts）的概念。上下文是以下内容的组合：

+   Kubernetes 集群

+   用户认证信息

+   默认命名空间

默认情况下，上下文保存在`~/.kube/config`文件中，但可以通过`KUBECONFIG`环境变量来更改该文件。在这本书中，我们将使用默认位置，因此我们将使用`unset KUBECONFIG`命令来取消设置`KUBECONFIG`。

当在 Minikube 中创建 Kubernetes 集群时，会创建一个与 Minikube 配置文件同名上下文，并将其设置为当前上下文。因此，在 Minikube 中创建集群后发布的`kubectl`命令将会发送到该集群。

要列出可用的上下文，请运行以下命令：

```java
kubectl config get-contexts
```

以下是一个示例响应：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/9f432d73-d57a-4227-bdf6-880fe1b7a39a.png)

第一列中的通配符`*`标记当前上下文。

只有在集群创建完成后，你才会在前面的响应中看到`handson-spring-boot-cloud`上下文，下面我们将进行描述。

如果你想要将当前上下文切换到另一个上下文，即与其他 Kubernetes 集群一起工作，请运行以下命令：

```java
kubectl config use-context my-cluster
```

在前面的示例中，当前上下文将更改为`my-cluster`。

要更新上下文，例如，切换`kubectl`使用的默认命名空间，请使用`kubectl config set-context`命令。

例如，要将当前上下文的默认命名空间更改为`my-namespace`，请使用以下命令：

```java
kubectl config set-context $(kubectl config current-context) --namespace my-namespace
```

在前面的命令中，`kubectl config current-context`用于获取当前上下文的名字。

# 创建 Kubernetes 集群

要使用 Minikube 创建 Kubernetes 集群，我们需要运行几个命令：

+   取消设置`KUBECONFIG`环境变量，以确保`kubectl`上下文创建在默认配置文件`~/.kube/config`中。

+   指定要用于集群的 Minikube 配置文件。我们将使用`handson-spring-boot-cloud`作为配置文件名。

+   使用`minikube start`命令创建集群，我们还可以指定要分配给集群的硬件资源量。为了能够完成本书剩余章节中的示例，请至少为集群分配 10 GB 内存，即 10,240 MB。

+   集群创建完成后，我们将使用 Minikube 的插件管理器来启用 Minikube 自带的 Ingress 控制器和指标服务器。Ingress 控制器和指标将在接下来的两章中使用。

在使用 Minikube 创建 Kubernetes 集群之前，关闭 macOS 上的 Docker 可能是个好主意，以避免内存不足。

运行以下命令来创建 Kubernetes 集群：

```java
unset KUBECONFIG 
minikube profile handson-spring-boot-cloud

minikube start \
 --memory=10240 \
 --cpus=4 \
 --disk-size=30g \
 --kubernetes-version=v1.15.0 \
 --vm-driver=virtualbox

minikube addons enable Ingress
minikube addons enable metrics-server
```

在前面的命令完成后，你应该能够与集群通信。尝试运行`kubectl get nodes`命令。它应该响应与以下内容相似的东西：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/da7ecf41-9129-4e4a-8eb1-c37936e83aa6.png)

创建后，集群将在后台初始化自己，在`kube-system`命名空间中启动多个系统 pods。我们可以通过以下命令监控其进度：

```java
kubectl get pods --namespace=kube-system
```

一旦启动完成，之前的命令应该报告所有 pods 的状态为`运行中`，并且 READY 计数应该是`1/1`，这意味着每个 pods 中的单个容器都在运行中。

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/91deb3a4-1969-4c58-a0bf-6c7bab49fd86.png)

我们现在准备采取一些行动！

# 尝试一个示例部署

那么我们应该如何进行以下操作呢？

+   在我们的 Kubernetes 集群中部署一个基于 NGINX 的简单 web 服务器。

+   对部署应用一些更改：

    +   删除一个 pods 并验证 ReplicaSet 创建一个新的。

    +   将 web 服务器扩展到三个 pods，以验证 ReplicaSet 填充差距。

+   使用具有节点端口的服务的路由将外部流量指向它。

首先，创建一个名为`first-attempts`的命名空间，并更新`kubectl`上下文，使其默认使用此命名空间：

```java
kubectl create namespace first-attempts
kubectl config set-context $(kubectl config current-context) --namespace=first-attempts
```

我们现在可以使用`kubernetes/first-attempts/nginx-deployment.yaml`文件在命名空间中创建一个 NGINX 部署。这个文件如下所示：

```java
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx-deploy
spec:
  replicas: 1
  selector:
    matchLabels:
    app: nginx-app
  template:
    metadata:
      labels:
        app: nginx-app
    spec:
      containers:
      - name: nginx-container
        image: nginx:latest
        ports:
        - containerPort: 80
```

让我们更详细地解释前面的源代码：

+   `kind`和`apiVersion`属性用于指定我们正在声明一个部署对象。

+   `metadata`部分用于描述部署对象，例如，当我们给它一个名字`nginx-deploy`时。

+   接下来是一个`spec`部分，它定义了部署对象的期望状态：

    +   `replicas: 1`指定我们希望运行一个 pods。

    +   `selector`部分指定部署如何查找其管理的 pods。在这种情况下，部署将查找具有`app`标签设置为`nginx-app`的 pods。

    +   `template`部分用于指定如何创建 pods：

        +   `metadata`部分指定了`label`，`app: nginx-app`，用于标识 pods，从而匹配选择器。

        +   `spec`部分指定单个容器在 pods 中的创建细节，即`name`和`image`以及它使用哪些`ports`。

使用以下命令创建部署：

```java
cd $BOOK_HOME/Chapter15
kubectl apply -f kubernetes/first-attempts/nginx-deployment.yaml
```

让我们看看使用`kubectl get all`命令我们能得到什么：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/b598f9f8-8904-434f-8927-9e2ff0860e89.png)

如预期那样，我们得到了一个部署、ReplicaSet 和 pods 对象。在短暂的时间后，这主要取决于下载 NGINX Docker 镜像所需的时间，pods 将启动并运行，期望的状态将等于当前状态！

通过以下命令删除 pods 来改变当前状态：

```java
kubectl delete pod --selector app=nginx-app
```

由于 pods 有一个随机名称（在前面的示例中为`nginx-deploy-59b8c5f7cd-mt6pg`），pods 是基于设置为`nginx-app`的`app`标签来选择的。

运行随后的`kubectl get all`命令将揭示 ReplicaSet 在几秒钟内检测到期望状态和当前状态之间的差异并处理，即几乎立即启动一个新的 pods。

通过在`kubernetes/first-attempts/nginx-deployment.yaml`部署文件中将期望的 pods 数量设置为三个副本来改变期望状态。只需重复之前的`kubectl apply`命令，就可以将更改应用到期望的状态。

快速运行几次`kubectl get all`命令，以监控 Kubernetes 如何采取行动确保当前状态满足新的期望状态。几秒钟后，将会有两个新的 NGINX pod 启动并运行。期望的状态再次等于具有三个运行中的 NGINX pod 的当前状态。期待看到的响应类似于以下内容：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/45d803cd-745b-4d3f-9d25-79df6eadfeb1.png)

为了使外部通信能够与 Web 服务器通信，请使用`kubernetes/first-attempts/nginx-service.yaml`文件创建服务：

```java
apiVersion: v1
kind: Service
metadata:
  name: nginx-service
spec:
  type: NodePort
  selector:
    app: nginx-app
  ports:
    - targetPort: 80
      port: 80
      nodePort: 30080
```

让我们更详细地解释前面的源代码：

+   `kind`和`apiVersion`属性用于指定我们正在声明一个`Service`对象。

+   `metadata`部分用于描述`Service`对象，例如，给它一个名字：`nginx-service`。

+   接下来是`spec`部分，它定义了`Service`对象的期望状态：

    +   使用`type`字段，我们指定我们希望是`NodePort`，即在每个集群节点上的专用端口上可访问的外部服务。这意味着外部调用者可以使用这个端口访问集群中的任何节点的 pods，而不依赖于 pods 实际运行在哪些节点上。

    +   选择器由服务用来查找可用的 pods，在我们的案例中，是标记有`app: nginx-app`的 pods。

    +   最后，`ports`如下声明：

        +   `port: 80`指定服务将在哪个端口上内部可访问，即在集群内部。

        +   `nodePort: 30080`指定服务将在哪个端口上使用集群中的任何节点对外部可访问。默认情况下，节点端口必须在`30000`到`32767`的范围内。

        +   `targetPort: 80`指定请求将在哪个端口上转发到 pods 中。

此端口范围用于最小化与其他正在使用的端口冲突的风险。在生产系统中，通常会在 Kubernetes 集群前放置一个负载均衡器，保护外部用户既不知道这些端口，也不知道 Kubernetes 集群中节点的 IP 地址。参见第十八章、*使用服务网格提高可观测性和管理*节的*设置 Istio 所需的端口转发*，了解有关`LoadBalanced` Kubernetes 服务的使用。

使用以下命令创建服务：

```java
kubectl apply -f kubernetes/first-attempts/nginx-service.yaml
```

要查看我们得到了什么，运行`kubectl get svc`命令。期待如下的响应：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/987abb3e-e317-4cb1-8169-63a163c2ac1c.png)

`kubectl`支持许多 API 对象的简称，作为其全名的替代。例如，在前面的命令中使用了`svc`而不是完整名称`service`。

为了尝试这个，我们需要知道我们集群中单个节点的 IP 地址。我们可以通过运行 `minikube ip` 命令来获取。在我的情况下，它是 `192.168.99.116`。使用这个 IP 地址和节点端口 `30080`，我们可以将网页浏览器定向到部署的 Web 服务器。在我的情况下，地址是 `http://192.168.99.116:30080`。预期如下的响应：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/2f710472-8b21-4b04-ba91-1496388ec643.png)

太好了！但是内部集群 IP 地址和端口又如何呢？

验证的一种方法是，在集群内部启动一个小型 pod，我们可以用它从内部运行 `curl`，也就是说，我们能够使用集群内部的 IP 地址和端口。我们不需要使用 IP 地址，相反，我们可以使用为服务在内部 DNS 服务器上创建的 DNS 名称。DNS 名称的短名称与服务的名称相同，即 `nginx-service`。

运行以下命令：

```java
kubectl run -i --rm --restart=Never curl-client --image=tutum/curl:alpine --command -- curl -s 'http://nginx-service:80'
```

前一个命令看起来有点复杂，但它只会做以下事情：

1.  基于 `tutum/curl:alpine` Docker 镜像创建一个小型容器，该镜像包含 `curl` 命令。

1.  在容器内运行 `curl -s 'http://nginx-service:80'` 命令，并使用 `-i` 选项将输出重定向到终端。

1.  使用 `--rm` 选项删除 pod。

预期前面命令的输出将包含以下信息（我们这里只展示了响应的一部分）：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/da13fcf8-bed7-49e3-ac2a-5013a5d3621f.png)

这意味着 Web 服务器也可以在集群内部访问！

这基本上是我们需要了解的，以便能够部署我们的系统架构。

通过删除包含 `nginx` 部署的命名空间来结束：

```java
kubectl delete namespace first-attempts
```

在我们结束关于 Kubernetes 的入门章节之前，我们需要学习如何管理我们的 Kubernetes 集群。

# 管理 Kubernetes 集群

运行中的 Kubernetes 集群会消耗大量资源，主要是内存。因此，当我们完成在 Minikube 中与 Kubernetes 集群的工作时，我们必须能够挂起它，以释放分配给它的资源。我们还需要知道如何恢复集群，当我们想继续工作时。最终，我们也必须能够永久删除集群，当我们不想再在磁盘上保留它时。

Minikube 带有一个 `stop` 命令，可以用来挂起一个 Kubernetes 集群。我们用来最初创建 Kubernetes 集群的 `start` 命令也可以用来从挂起状态恢复集群。要永久删除一个集群，我们可以使用 Minikube 的 `delete` 命令。

# 挂起和恢复 Kubernetes 集群

运行以下命令来挂起（即 `stop`）Kubernetes 集群：

```java
minikube stop
```

运行以下命令来恢复（即 `start`）Kubernetes 集群：

```java
minikube start
```

当恢复一个已经存在的集群时，`start` 命令会忽略你在创建集群时使用的开关。

在恢复 Kubernetes 集群后，`kubectl` 上下文将更新为使用此集群，当前使用的命名空间设置为 `default`。如果你正在使用另一个命名空间，例如我们将在下一章使用的 `hands-on` 命名空间，即 第十六章，*将我们的微服务部署到 Kubernetes*，你可以使用以下命令更新 `kubectl` 上下文：

```java
kubectl config set-context $(kubectl config current-context) --namespace=hands-on

```

随后的 `kubectl` 命令将在适用的情况下应用于 `hands-on` 命名空间。

# 销毁 Kubernetes 集群

运行以下命令以终止 Kubernetes 集群：

```java
minikube delete --profile handson-spring-boot-cloud 
```

你实际上可以不指定配置文件运行 `delete` 命令，但我发现指明配置文件更安全。否则，你可能会意外地删除错误的 Kubernetes 集群！

neither the Minikube profile definition under `~/.minikube/profiles/` nor the `kubectl` context in `~/.kube/config` is deleted by this command. If they are no longer required, they can be deleted with the following commands:

```java
rm -r ~/.minikube/profiles/handson-spring-boot-cloud
kubectl config delete-context handson-spring-boot-cloud
```

`kubectl config delete-context` 命令会警告你关于删除活动上下文的内容，但是没关系。

我们已经成功学会了如何管理在 Minikube 中运行的 Kubernetes 集群。我们现在知道如何挂起和恢复集群，当不再需要时，我们知道如何永久删除它。

# 总结

在本章中，我们已经介绍了 Kubernetes 作为容器编排器。Kubernetes 使得运行容器的集群服务器看起来像一个大的逻辑服务器。作为操作员，我们向集群声明一个期望状态，Kubernetes 持续将期望状态与当前状态进行比较。如果它检测到差异，它将采取行动确保当前状态与期望状态相同。

期望的状态通过使用 Kubernetes API 服务器创建资源来声明。Kubernetes 控制器管理器和其控制器对由 API 服务器创建的各种资源做出反应，并采取行动确保当前状态满足新的期望状态。调度器为新生成的容器分配节点，即包含一个或多个容器的 pod。在每个节点上，都有一个代理，`kubelet` 运行并确保调度到其节点的 pod 正在运行。`kube-proxy` 充当网络代理，通过将发送到服务的请求转发到集群中可用的 pod，实现服务抽象。外部请求可以由指定节点上可用的节点端口的服务处理，或者通过专用的 Ingress 资源处理。

我们还通过使用 Minikube 和 VirtualBox 创建了一个本地单节点集群来尝试 Kubernetes。使用名为 `kubectl` 的 Kubernetes CLI 工具，我们部署了一个基于 NGINX 的简单 Web 服务器。我们通过删除 Web 服务器来尝试弹性能力，并观察它自动重建以及通过请求在 Web 服务器上运行三个 Pod 来扩展它。最后，我们创建了一个具有节点端口的服务的服务，并验证了我们可以从集群内外访问它。

最后，我们学会了如何管理在 VirtualBox 上运行的 Minikube 中的 Kubernetes 集群，包括如何休眠、恢复和终止 Kubernetes 集群。

我们现在准备将前面章节中的系统架构部署到 Kubernetes 中。翻到下一章，了解如何进行部署！

# 问题

1.  如果你两次运行相同的 `kubectl create` 命令会发生什么？

1.  如果你两次运行相同的 `kubectl apply` 命令会发生什么？

1.  关于问题 *1* 和 *2*，为什么它们第二次运行时行为不同？

1.  ReplicaSet 的目的是什么，还有哪些资源会创建 ReplicaSet？

1.  在 Kubernetes 集群中 `etcd` 的作用是什么？

1.  容器如何找出同一 Pod 中运行的另一容器的 IP 地址？

1.  如果你创建了两个名称相同但在不同命名空间中的部署会发生什么？

1.  如果你在两个不同的命名空间中创建了两个名称相同的服务，你会使得这两个服务的创建失败。


# 第十六章：将我们的微服务部署到 Kubernetes

在本章中，我们将把本书中的微服务部署到 Kubernetes。我们还将学习 Kubernetes 的一些核心特性，例如使用**Kustomize**为不同的运行时环境配置部署，以及使用 Kubernetes 部署对象进行滚动升级。在那之前，我们需要回顾一下我们如何使用服务发现。由于 Kubernetes 内置了对服务发现的支持，因此似乎没有必要部署我们自己的服务发现，毕竟我们到目前为止一直在使用 Netflix Eureka。

本章将涵盖以下主题：

+   用 Kubernetes `Service`对象和`kube-proxy`替换 Netflix Eureka 进行服务发现

+   使用 Kustomize 准备在不同环境中部署的微服务

+   使用测试脚本的某个版本来测试部署，`test-em-all.bash`

+   执行滚动升级

+   学习如何回滚一个失败的升级

# 技术要求

本书中描述的所有命令都是在一个 MacBook Pro 上使用 macOS Mojave 运行的，但如果你想在其他平台（如 Linux 或 Windows）上运行它们，应该很容易进行修改。

本章所需的一个新工具是`siege`命令行工具，用于基于 HTTP 的负载测试和基准测试。在我们执行滚动升级时，我们将使用`siege`给 Kubernetes 集群施加一些负载。该工具可以通过 Homebrew 使用以下命令安装：

```java
brew install siege
```

本章的源代码可以在本书的 GitHub 仓库中找到：[`github.com/PacktPublishing/Hands-On-Microservices-with-Spring-Boot-and-Spring-Cloud/tree/master/Chapter16`](https://github.com/PacktPublishing/Hands-On-Microservices-with-Spring-Boot-and-Spring-Cloud/tree/master/Chapter16)。

为了能够运行本书中描述的命令，你需要将源代码下载到一个文件夹中，并设置一个环境变量，`$BOOK_HOME`，该变量指向该文件夹。一些示例命令如下：

```java
export BOOK_HOME=~/Documents/Hands-On-Microservices-with-Spring-Boot-and-Spring-Cloud
git clone https://github.com/PacktPublishing/Hands-On-Microservices-with-Spring-Boot-and-Spring-Cloud $BOOK_HOME
cd $BOOK_HOME/Chapter16
```

本章中的所有源代码示例都来自`$BOOK_HOME/Chapter16`的源代码，并且已经使用 Kubernetes 1.15 进行了测试。

如果你想要查看在本章中应用到源代码的变化，也就是说，查看部署到 Kubernetes 上的微服务所需的变化，你可以与第十五章的*Kubernetes 入门*源代码进行对比。你可以使用你喜欢的`diff`工具，比较两个文件夹，`$BOOK_HOME/Chapter15`和`$BOOK_HOME/Chapter16`。

# 用 Kubernetes 服务替换 Netflix Eureka

如前章所示，第十五章，*Kubernetes 简介*，Kubernetes 带有一个基于 Kubernetes `Service`对象和`kube-proxy`运行时组件的内置发现服务。这使得不需要部署一个单独的发现服务，如我们前几章中使用的 Netflix Eureka。使用 Kubernetes 发现服务的一个优点是，它不需要像我们与 Netflix Eureka 一起使用的 Netflix Ribbon 这样的客户端库。这使得 Kubernetes 发现服务易于使用，且与微服务基于哪种语言或框架无关。使用 Kubernetes 发现服务的缺点是，它只能在 Kubernetes 环境中运行。然而，由于发现服务基于`kube-proxy`，后者接受对服务对象 DNS 名称或 IP 地址的请求，因此应该相当简单地用类似的服务替换它，例如另一个容器编排器的捆绑服务。

总结来说，我们将从我们的微服务架构中移除基于 Netflix Eureka 的发现服务器，如图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/8b8eed5f-e4b6-4d3a-85a1-e0df126462ee.png)

为了将基于 Netflix Eureka 的发现服务器替换为 Kubernetes 内置的发现服务，已对源代码应用了以下更改：

+   我们已经从配置仓库`config-repo`中移除了 Netflix Eureka 和 Ribbon 特定的配置（客户端和服务器）。

+   网关服务中的路由规则已从`config-repo/gateway.yml`文件中移除。

+   我们已经移除了 Eureka 服务器项目，即移除了`spring-cloud/eureka-server`文件夹。

+   我们已经从 Docker Compose 文件和`settings.gradle`Gradle 文件中移除了 Eureka 服务器。

+   我们已经在所有 Eureka 客户端的构建文件中移除了对`spring-cloud-starter-netflix-eureka-client`的依赖，即`build.gradle`文件。

+   我们已经从所有 Eureka 客户端集成测试中移除了不再需要的`eureka.client.enabled=false`属性设置。

+   网关服务不再使用基于客户端负载均衡器的 Spring Cloud 路由，使用`lb`协议。例如，`lb://product-composite`路由目的地已替换为`http://product-composite`在`config-repo/gateway.yml`文件中。

+   微服务和授权服务器使用的 HTTP 端口已从端口`8080`（在授权服务器的情况下为端口`9999`）更改为默认的 HTTP 端口`80`。这在受影响的每个服务的`config-repo`中进行了配置，如下所示：

```java
spring.profiles: docker
server.port: 80
```

我们使用的所有 HTTP 地址都不会因将 Netflix Eureka 替换为 Kubernetes 服务而受到影响。例如，复合服务使用的地址不受影响：

```java
private final String productServiceUrl = "http://product";
private final String recommendationServiceUrl = "http://recommendation";
private final String reviewServiceUrl = "http://review";
```

这是通过改变微服务和授权服务器所使用的 HTTP 端口为默认的 HTTP 端口`80`，如前所述来实现的。

使用 Docker Compose 仍然可行，尽管 Netflix Eureka 已经被移除。这可以用来在不将微服务部署到 Kubernetes 的情况下运行其功能测试，例如，与 macOS 上的 Docker 一起运行`test-em-all.bash`，就像前几章中一样。然而，移除 Netflix Eureka 意味着当我们仅使用 Docker 和 Docker Compose 时，我们不再有一个发现服务。因此，只有在部署到 Kubernetes 时，微服务才能进行扩展。

现在我们已经熟悉了 Kubernetes 服务，接下来让我们看看 Kustomize，这是一个用于自定义 Kubernetes 对象的工具有。

# 介绍 Kustomize

**Kustomize**是一个用于创建 Kubernetes 定义文件（即 YAML 文件）的环境特定自定义的工具，例如，用于开发、测试、暂存和生产环境。常见的定义文件存储在一个`base`文件夹中，而环境特定的添加内容则保存在特定的`overlay`文件夹中。环境特定的信息可以是以下任意一种：

+   要使用哪个版本的 Docker 镜像

+   要运行的副本数量

+   关于 CPU 和内存的资源配额

每个文件夹中都包含一个`kustomization.yml`文件，它描述了其内容给 Kustomize。当部署到特定环境时，Kustomize 将从`base`文件夹和环境特定的`overlay`文件夹中获取内容，并将组合后的结果发送给`kubectl`。来自`overlay`文件夹中的文件属性将覆盖`base`文件夹中相应的属性，如果有的话。

在本章中，我们将为两个示例环境设置自定义：开发和生产。

`$BOOK_HOME/Chapter16`下的文件夹结构如下所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/a62901e6-d94d-49e1-be8f-22ba37d810c2.png)

自 Kubernetes 1.14 起，`kubectl`自带了对 Kustomize 的内置支持，使用`-k`标志。正如我们将继续看到的，使用 Kustomize 将服务部署到开发环境，将由`kubectl apply -k kubernetes/services/overlays/dev`命令完成。

# 在基础文件夹中设置常见定义

在`base`文件夹中，我们将为每个微服务都有一个定义文件，但对于资源管理器（MongoDB、MySQL 和 RabbitMQ）则没有。资源管理器只在开发环境中部署到 Kubernetes，并预期在生产环境中运行在 Kubernetes 之外——例如，作为现有本地数据库和消息队列管理服务的一部分，或者作为云上的托管服务。

`base` 文件夹中的定义文件包含每个微服务的部署对象和服务对象。让我们来看一下 `kubernetes/services/base/product.yml` 中的典型部署对象。它旨在满足开发环境的需求。它从以下代码开始：

```java
apiVersion: apps/v1
kind: Deployment
metadata:
  name: product
spec:
  replicas: 1
  selector:
    matchLabels:
      app: product
  template:
    metadata:
      labels:
        app: product
    spec:
      containers:
      - name: pro
```

这部分看起来与前一章中使用的 NGINX 部署完全一样，因此我们不需要再次讨论。第十五章 *Kubernetes 简介*中的*尝试样本部署*部分，所以我们不需要再次讨论。

下一部分看起来有点不同：

```java
        image: hands-on/product-service
        imagePullPolicy: Never
        env:
        - name: SPRING_PROFILES_ACTIVE
          value: "docker"
        envFrom:
        - secretRef:
            name: config-client-credentials
        ports:
        - containerPort: 80
        resources:
          limits:
            memory: 350Mi
```

让我们更详细地解释前面的源代码：

+   指定的 Docker 镜像 `hands-on/product-service` 将在我们构建微服务时创建。有关更多信息，请参阅*构建 Docker 镜像*部分。

+   `imagePullPolicy: Never` 声明告诉 Kubernetes 不要尝试从 Docker 注册表下载 Docker 镜像。有关更多信息，请参阅*构建 Docker 镜像*部分。

+   `SPRING_PROFILES_ACTIVE` 环境变量被定义为告诉 Spring 应用程序在配置存储库中使用 `docker` Spring 配置文件。

+   使用秘密 `config-client-credentials` 为容器提供访问配置服务器的凭据。

+   使用的 HTTP 端口是默认的 HTTP 端口 `80`。

+   定义了资源限制，以将可用内存最大化到 350 MB，这与前面章节中使用 Docker Compose 的方式相同。

部署对象的最后一部分包含存活和就绪探针：

```java
        livenessProbe:
          httpGet:
            scheme: HTTP
            path: /actuator/info
            port: 80
          initialDelaySeconds: 10
          periodSeconds: 10
          timeoutSeconds: 2
          failureThreshold: 20
          successThreshold: 1
        readinessProbe:
          httpGet:
            scheme: HTTP
            path: /actuator/health
            port: 80
          initialDelaySeconds: 10
          periodSeconds: 10
          timeoutSeconds: 2
          failureThreshold: 3
          successThreshold: 1
```

让我们更详细地解释前面的源代码：

+   **存活探针**是基于发送到 Spring Boot Actuator `info` 端点的 HTTP 请求。这意味着，如果微服务实例处于如此糟糕的状态，以至于无法对发送到轻量级 `info` 端点的请求返回 200（OK）状态码，那么是时候让 Kubernetes 重新启动微服务实例了。

+   **就绪探针**是基于发送到 Spring Boot Actuator `health` 端点的 HTTP 请求。Kubernetes 只会在微服务实例的 `health` 端点返回 HTTP 状态码 200（OK）时发送请求到微服务实例。如果没有返回 200（OK）状态码，通常意味着微服务实例在访问其所依赖的一些资源时存在问题，因此在微服务实例没有在 `health` 端点返回 200（OK）时，不向其发送任何请求是有意义的。

+   存活和就绪探针可以通过以下属性进行配置：

    +   `initialDelaySeconds` 指定 Kubernetes 在容器启动后等待探针的时间。

    +   `periodSeconds` 指定 Kubernetes 发送探针请求之间的时间。

    +   `timeoutSeconds` 指定 Kubernetes 等待响应的时间，如果在规定时间内没有响应，则认为探针失败。

    +   `failureThreshold`指定 Kubernetes 在放弃之前尝试失败的次数。对于存活探针，这意味着重启容器。对于就绪探针，这意味着 Kubernetes 将不再向容器发送任何请求。

    +   `successThreshold`指定探针在失败后需要成功尝试的次数才能被认为是成功的。这仅适用于就绪探针，因为如果为存活探针指定，它们必须设置为`1`。

为探针寻找最佳设置可能具有挑战性，也就是说，找到当探针的可用性发生变化时 Kubernetes 能够快速反应以及不过度加载探针请求之间的适当平衡。特别是如果为存活探针配置的值过低，可能导致 Kubernetes 重启刚刚需要一些时间启动的容器，即不需要重启的容器。如果为存活探针设置的值过低，启动大量容器可能会导致很多不必要的重启。在探针上设置配置值过高（除了`successThreshold`值）会使 Kubernetes 反应变慢，这在开发环境中可能会很烦人。适当的值还取决于可用硬件，这会影响容器的启动时间。对于本书的范围，存活探针的`failureThreshold`设置为一个高值`20`，以避免在硬件资源有限的计算机上进行不必要的重启。

`kubernetes/services/base/product.yml`文件中的服务对象如下所示：

```java
apiVersion: v1
kind: Service
metadata:
  name: product
spec:
  selector:
    app: product
  ports:
  - port: 80
    targetPort: 80
```

服务对象与我们在上一章第十五章、*Kubernetes 简介*中的*尝试样本部署*部分使用的 NGINX 服务对象类似。不同之处在于服务类型是`ClusterIP`（这是默认类型，因此没有指定）。服务对象将接收端口`80`上的内部请求，并将它们转发到所选容器的目标端口`80`。这个规则的唯一例外是通过宿主机的端口`NodePort`暴露的外部网关微服务，即`31443`：

```java
apiVersion: v1
kind: Service
metadata:
 name: gateway
spec:
 type: NodePort
 selector:
 app: gateway
 ports:
 - port: 443
 nodePort: 31443
 targetPort: 8443
```

最后，我们在`base`文件夹中有一个将所有内容结合在一起的 Kustomize 文件：

```java
resources:
- auth-server.yml
- config-server.yml
- gateway.yml
- product-composite.yml
- product.yml
- recommendation.yml
- review.yml
- zipkin-server.yml
```

它简单地列出了 Kustomize 将在`base`文件夹中使用的 YAML 定义文件。

现在，我们将看看我们如何可以使用这些基本定义与`overlay`文件夹中的定义一起使用，并了解它们是如何使用`kubectl apply`命令的`-k`选项应用的。

# 将应用程序部署到 Kubernetes 以供开发和测试使用

在本节中，我们将部署用于开发和测试活动的微服务环境，例如系统集成测试。这种环境主要用于功能测试，因此配置为使用最少的系统资源。

由于`base`文件夹中的部署对象是为开发环境配置的，因此它们在开发的上层叠加中不需要进一步的细化。我们只需要像使用 Docker Compose 一样为 RabbitMQ、MySQL 和 MongoDB 的三个资源管理器添加部署和服务对象。我们将在这三个资源管理器中部署与微服务相同的 Kubernetes 命名空间。下面的图表展示了这一点：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/c5ebe638-fb4c-4344-ab1d-2cd3b1698480.png)

资源管理器的定义文件可以在`kubernetes/services/overlays/dev`文件夹中找到。

`kustomization.yml`文件看起来像这样：

```java
bases:
- ../../base
resources:
- mongodb-dev.yml
- rabbitmq-dev.yml
- mysql-dev.yml
```

它定义了`base`文件夹作为基础，并添加了我们之前提到的三个资源。

# 构建 Docker 镜像

通常，我们需要将镜像推送到 Docker 注册表，并配置 Kubernetes 从注册表中拉取镜像。在我们的案例中，我们有一个本地的单节点集群，我们可以通过将 Docker 客户端指向 Minikube 中的 Docker 引擎，然后运行`docker-compose build`命令，来简化这个过程。这将使 Docker 镜像立即可供 Kubernetes 使用。对于开发，我们将使用`latest`作为微服务的 Docker 镜像版本。

您可能想知道我们如何更新使用`latest` Docker 镜像的 pods。

从 Kubernetes 1.15 开始，这非常简单。只需更改代码并重新构建 Docker 镜像，例如使用这里描述的`build`命令。然后，使用`kubectl rollout restart`命令更新一个 pods。

例如，如果`product`服务已更新，运行`kubectl rollout restart deploy product`命令。

您可以从源代码构建 Docker 镜像，如下所示：

```java
cd $BOOK_HOME/Chapter16
eval $(minikube docker-env)
./gradlew build && docker-compose build
```

`eval $(minikube docker-env)`命令使本地 Docker 客户端与 Minikube 中的 Docker 引擎通信，例如，在构建 Docker 镜像时。

`docker-compose.yml`文件已更新以指定构建的 Docker 镜像的名称。例如，对于`product`服务，我们有如下内容：

```java
  product:
    build: microservices/product-service
    image: hands-on/product-service
```

`latest`是 Docker 镜像名称的默认标签，因此不需要指定。

构建 Docker 镜像后，我们可以开始创建 Kubernetes 资源对象！

# 部署到 Kubernetes

在我们将微服务部署到 Kubernetes 之前，我们需要创建一个命名空间，所需的 config maps 和 secrets。部署完成后，我们将等待部署运行起来，并验证我们在部署的 pods 和每个 pod 中使用的 Docker 镜像是否符合预期。

创建一个命名空间，`hands-on`，并将其设置为`kubectl`的默认命名空间：

```java
kubectl create namespace hands-on
kubectl config set-context $(kubectl config current-context) --namespace=hands-on
```

所有应用程序配置都保存在由配置服务器管理的配置仓库中。唯一需要存储在配置仓库外的配置信息是连接到配置服务器的凭据和一个加密密钥。加密密钥由配置服务器使用，以保持配置仓库中的敏感信息在磁盘上加密。

我们将把配置仓库存储在一个带有所有敏感信息加密的 config map 中；具体请参阅第十二章，*集中配置*。连接配置服务器和加密密钥的凭据将存储在两个秘密中，一个用于配置服务器，一个用于其客户端。

为了验证这一点，请执行以下步骤：

1.  基于`config-repo`文件夹中的文件，使用以下命令创建 config map：

```java
kubectl create configmap config-repo --from-file=config-repo/ --save-config
```

1.  使用以下命令创建配置服务器秘密：

```java
kubectl create secret generic config-server-secrets \
  --from-literal=ENCRYPT_KEY=my-very-secure-encrypt-key \
  --from-literal=SPRING_SECURITY_USER_NAME=dev-usr \
  --from-literal=SPRING_SECURITY_USER_PASSWORD=dev-pwd \
  --save-config
```

1.  使用以下命令为配置服务器的客户端创建秘密：

```java
kubectl create secret generic config-client-credentials \
--from-literal=CONFIG_SERVER_USR=dev-usr \
--from-literal=CONFIG_SERVER_PWD=dev-pwd --save-config
```

由于我们刚刚输入了包含敏感信息的明文命令，例如密码和加密密钥，清除`history`命令是一个好主意。要清除内存和磁盘上的`history`命令，请运行`history -c; history -w`命令。

有关`history`命令的详细信息，请参阅[`unix.stackexchange.com/a/416831`](https://unix.stackexchange.com/a/416831)的讨论。

1.  为了避免由于 Kubernetes 下载 Docker 镜像而导致部署缓慢（可能会导致我们之前描述的存活探针重启我们的 pods），请运行以下`docker pull`命令以下载镜像：

```java
docker pull mysql:5.7
docker pull mongo:3.6.9
docker pull rabbitmq:3.7.8-management
docker pull openzipkin/zipkin:2.12.9
```

1.  基于`dev`覆盖层，使用`-k`开关激活 Kustomize，如前所述部署开发环境的微服务：

```java
kubectl apply -k kubernetes/services/overlays/dev
```

1.  通过运行以下命令等待部署及其 pods 启动并运行：

```java
kubectl wait --timeout=600s --for=condition=ready pod --all
```

期望每个命令的响应为`deployment.extensions/... condition met`。`...`将被实际部署的名称替换。

1.  要查看用于开发的 Docker 镜像，请运行以下命令：

```java
kubectl get pods -o json | jq .items[].spec.containers[].image
```

响应应类似于以下内容：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/42300572-7769-4a8b-9b4d-5efd9d361dab.png)

我们现在准备好测试我们的部署！

但在我们能做到这一点之前，我们需要经历测试脚本中必须与 Kubernetes 一起使用的更改。

# 用于与 Kubernetes 一起使用的测试脚本的更改

为了测试部署，我们将像往常一样运行测试脚本，即`test-em-all.bash`。为了与 Kubernetes 配合工作，电路断路器测试做了一些微小修改。详情请查看`testCircuitBreaker()`函数。电路断路器测试调用`product-composite`服务上的`actuator`端点，以检查其健康状态并获得电路断路器事件访问权限。`actuator`端点并未对外暴露，因此当使用 Docker Compose 和 Kubernetes 时，测试脚本需要使用不同的技术来访问内部端点：

+   当使用 Docker Compose 时，测试脚本将使用简单的`docker run`命令启动一个 Docker 容器，该命令从 Docker Compose 创建的网络内部调用`actuator`端点。

+   当使用 Kubernetes 时，测试脚本将启动一个 Kubernetes pod，它可以在 Kubernetes 内部运行相应的命令。

让我们看看在使用 Docker Compose 和 Kubernetes 时是如何做到的。

# 使用 Docker Compose 访问内部 actuator 端点

为 Docker Compose 定义的基本命令如下：

```java
EXEC="docker run --rm -it --network=my-network alpine"
```

请注意，在每次执行测试命令后，使用`--rm`选项将容器杀死。

# 使用 Kubernetes 访问内部 actuator 端点

由于在 Kubernetes 中启动 pod 比启动容器慢，测试脚本将启动一个名为`alpine-client`的单个 pod，该 pod 将在`testCircuitBreaker()`函数的开始处启动，并且测试将使用`kubectl exec`命令在这个 pod 中运行测试命令。这将比为每个测试命令创建和删除一个 pod 要快得多。

启动单个 pod 是在`testCircuitBreaker()`函数的开始处处理的：

```java
echo "Restarting alpine-client..."
local ns=$NAMESPACE
if kubectl -n $ns get pod alpine-client > /dev/null ; then
    kubectl -n $ns delete pod alpine-client --grace-period=1
fi
kubectl -n $ns run --restart=Never alpine-client --image=alpine --command -- sleep 600
echo "Waiting for alpine-client to be ready..."
kubectl -n $ns wait --for=condition=Ready pod/alpine-client

EXEC="kubectl -n $ns exec alpine-client --"
```

在电路断路器测试的最后，使用以下命令删除 pod：

```java
kubectl -n $ns delete pod alpine-client --grace-period=1
```

# 选择 Docker Compose 和 Kubernetes

为了使测试脚本能够与 Docker Compose 和 Kubernetes 一起工作，它假定如果`HOST`环境变量设置为`localhost`，则将使用 Docker Compose；否则，它假定将使用 Kubernetes。如下代码所示：

```java
if [ "$HOST" = "localhost" ]
then
    EXEC="docker run --rm -it --network=my-network alpine"
else
    echo "Restarting alpine-client..."
    ...
    EXEC="kubectl -n $ns exec alpine-client --"
fi
```

测试脚本中`HOST`环境变量的默认值是`localhost`。

一旦设置了`EXEC`变量，根据测试是在 Docker Compose 还是 Kubernetes 上运行，它将在`testCircuitBreaker()`测试函数中使用。测试首先通过以下语句验证电路断路器是关闭的：

```java
assertEqual "CLOSED" "$($EXEC wget product-composite:${MGM_PORT}/actuator/health -qO - | jq -r .details.productCircuitBreaker.details.state)"
```

测试脚本中的最后一步更改是因为我们的服务现在可以在集群内的`80`端口访问；也就是说，它们不再在`8080`端口。

如果我们使用过的各种端口看起来令人困惑，请回顾*在基础文件夹中设置常用定义*部分中服务定义。

# 测试部署

在启动测试脚本时，我们必须给它运行 Kubernetes 的主机的地址，即我们的 Minikube 实例，以及我们的网关服务监听外部请求的外部端口。可以使用 `minikube ip` 命令来查找 Minikube 实例的 IP 地址，正如在 *在基础文件夹中设置公共定义* 部分提到的，我们已经将网关服务的外部 `NodePort 31443` 分配给了网关服务。

使用以下命令开始测试：

```java
HOST=$(minikube ip) PORT=31443 ./test-em-all.bash
```

从脚本的输出中，我们将看到 Minikube 实例的 IP 地址的使用，以及如何创建和销毁 `alpine-client` 容器：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/97c12d92-177b-46e9-9f35-57cef2157850.png)

在我们继续查看如何为阶段和生产使用设置相应的环境之前，让我们清理一下我们在开发环境中安装的内容，以节省 Kubernetes 集群中的资源。我们可以通过简单地删除命名空间来实现这一点。删除命名空间将递归删除命名空间中存在的所有资源。

使用以下命令删除命名空间：

```java
kubectl delete namespace hands-on
```

移除了开发环境之后，我们可以继续设置一个针对阶段和生产的环境。

# 将微服务部署到 Kubernetes 用于阶段和生产

在这一节中，我们将把微服务部署到一个用于阶段和生产环境的系统中。阶段环境用于进行**质量保证**（**QA**）和**用户验收测试**（**UAT**），这是将新版本投入生产之前的最后一步。为了验证新版本不仅满足功能性需求，还包括性能、健壮性、可伸缩性和弹性等非功能性需求，阶段环境应尽可能与生产环境相似。

当将服务部署到用于阶段或生产的环境时，与开发或测试相比需要进行许多更改：

+   **资源管理器应运行在 Kubernetes 集群之外**：从技术上讲，将数据库和队列管理器作为有状态容器在 Kubernetes 上运行以供生产使用是可行的，可以使用 `StatefulSets` 和 `PersistentVolumes`。在撰写本章时，我建议不要这样做，主要是因为对有状态容器的支持相对较新，在 Kubernetes 中尚未得到验证。相反，我建议使用本地或云上的现有数据库和队列管理服务，让 Kubernetes 做它最擅长的事情，即运行无状态容器。对于本书的范围，为了模拟生产环境，我们将使用现有的 Docker Compose 文件，将 MySQL、MongoDB 和 RabbitMQ 作为普通的 Docker 容器在 Kubernetes 之外运行。

+   **锁定**：

    +   出于安全原因，诸如 `actuator` 端点和日志级别等事物需要在生产环境中受到限制。

    +   外部暴露的端点也应从安全角度进行审查。例如，配置服务器的访问在生产环境中很可能需要受到限制，但为了方便起见，我们将在本书中将其暴露出来。

    +   Docker 镜像标签必须指定，才能跟踪已部署微服务的哪些版本。

+   **扩大可用资源规模**：为了满足高可用性和更高负载的需求，每个部署至少需要运行两个 pods。我们可能还需要增加每个 pods 允许使用的内存和 CPU。为了避免 Minikube 实例中内存耗尽，我们将在每个部署中保留一个 pods，但在生产环境中增加允许的最大内存。

+   **建立一个生产就绪的 Kubernetes 集群**：这超出了本书的范围，但如果可行，我建议使用领先云服务提供商提供的托管 Kubernetes 服务。在本书的范围内，我们将部署到我们的本地 Minikube 实例。

这并不是在设置生产环境时需要考虑的详尽列表，但这是一个不错的开始。

我们的模拟生产环境将如下所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/3ddfcf4d-89dd-4007-a19c-4568e6cb2220.png)

# 源代码中的更改：

以下更改已应用于源代码，以准备在用于生产的环境中部署：

+   在`config-repo`配置仓库中添加了一个名为`prod`的 Spring 配置文件：

```java
spring.profiles: prod
```

+   在`prod`配置文件中，已添加以下内容：

+   运行为普通 Docker 容器的资源管理器 URL：

```java
spring.rabbitmq.host: 172.17.0.1
spring.data.mongodb.host: 172.17.0.1
spring.datasource.url: jdbc:mysql://172.17.0.1:3306/review-db
```

我们使用`172.17.0.1`IP 地址来访问 Minikube 实例中的 Docker 引擎。这是在创建 Minikube 时，至少对于版本 1.2 的 Minikube，Docker 引擎的默认 IP 地址。

正在开展的工作是建立一个标准的 DNS 名称，供容器在需要访问它们正在运行的 Docker 主机时使用，但在撰写本章时，这项工作尚未完成。

+   日志级别已设置为警告或更高，即错误或致命。例如：

```java
logging.level.root: WARN
```

+   通过 HTTP 暴露的`actuator`端点仅有`info`和`health`端点，这些端点被 Kubernetes 中的存活和就绪探针使用，以及被测试脚本`test-em-all.bash`使用的`circuitbreakerevents`端点：

```java
management.endpoints.web.exposure.include: health,info,circuitbreakerevents
```

+   在生产`overlay`文件夹`kubernetes/services/overlays/prod`中，为每个微服务添加了一个部署对象，并具有以下内容，以便与基本定义合并：

+   对于所有微服务，`v1`被指定为 Docker `image`标签，并且`prod`配置文件被添加到活动 Spring 配置文件中。例如，对于`product`服务，我们有以下内容：

```java
image: hands-on/product-service:v1
env:
- name: SPRING_PROFILES_ACTIVE
  value: "docker,prod"
```

+   对于不将其配置保存在配置仓库中的 Zipkin 和配置服务器，在它们的部署定义中添加了相应的环境变量：

```java
env:
- name: LOGGING_LEVEL_ROOT
  value: WARN
- name: MANAGEMENT_ENDPOINTS_WEB_EXPOSURE_INCLUDE
  value: "health,info"
- name: RABBIT_ADDRESSES
  value: 172.17.0.1
```

+   最后，`kustomization.yml` 文件定义了将 `prod overlay` 文件夹中的文件合并的 `patchesStrategicMerge` 补丁机制，并在 `base` 文件夹中指定相应的定义：

```java
bases:
- ../../base
patchesStrategicMerge:
- auth-server-prod.yml
- ...
```

在实际的生产环境中，我们还应该将 `imagePullPolicy: Never` 设置更改为 `IfNotPresent`，即从 Docker 仓库下载 Docker 镜像。但是，由于我们将把生产设置部署到 Minikube 实例，我们在那里手动构建和打标签 Docker 镜像，所以不会更新此设置。

# 部署到 Kubernetes

为了模拟生产级别的资源管理器，MySQL、MongoDB 和 RabbitMQ 将使用 Docker Compose 在 Kubernetes 外运行。我们像前几章一样启动它们：

```java
eval $(minikube docker-env)
docker-compose up -d mongodb mysql rabbitmq
```

我们还需要使用以下命令将现有的 Docker 镜像标记为 `v1`：

```java
docker tag hands-on/auth-server hands-on/auth-server:v1
docker tag hands-on/config-server hands-on/config-server:v1
docker tag hands-on/gateway hands-on/gateway:v1 
docker tag hands-on/product-composite-service hands-on/product-composite-service:v1 
docker tag hands-on/product-service hands-on/product-service:v1
docker tag hands-on/recommendation-service hands-on/recommendation-service:v1
docker tag hands-on/review-service hands-on/review-service:v1
```

从这里开始，命令与部署到开发环境非常相似。

我们将使用另一个 Kustomize 覆盖层，并为配置服务器使用不同的凭据，但是，除此之外，它将保持不变（这当然是一件好事！）。我们将使用相同的配置仓库，但配置 Pod 以使用 `prod` Spring 配置文件，如前所述。按照以下步骤进行操作：

1.  创建一个名为 `hands-on` 的命名空间，并将其设置为 `kubectl` 的默认命名空间：

```java
kubectl create namespace hands-on
kubectl config set-context $(kubectl config current-context) --namespace=hands-on
```

1.  使用以下命令基于 `config-repo` 文件夹中的文件为配置仓库创建配置映射：

```java
kubectl create configmap config-repo --from-file=config-repo/ --save-config
```

1.  使用以下命令为配置服务器创建密钥：

```java
kubectl create secret generic config-server-secrets \
  --from-literal=ENCRYPT_KEY=my-very-secure-encrypt-key \
  --from-literal=SPRING_SECURITY_USER_NAME=prod-usr \
  --from-literal=SPRING_SECURITY_USER_PASSWORD=prod-pwd \
  --save-config
```

1.  使用以下命令为配置服务器的客户端创建密钥：

```java
kubectl create secret generic config-client-credentials \
--from-literal=CONFIG_SERVER_USR=prod-usr \
--from-literal=CONFIG_SERVER_PWD=prod-pwd --save-config
```

1.  将明文加密密钥和密码从命令历史中删除：

```java
history -c; history -w
```

1.  基于 `prod` 覆盖层，使用 `-k` 选项激活 Kustomize，如前所述，部署开发环境中的微服务：

```java
kubectl apply -k kubernetes/services/overlays/prod
```

1.  等待部署运行起来：

```java
kubectl wait --timeout=600s --for=condition=ready pod --all
```

1.  为了查看当前用于生产的 Docker 镜像，运行以下命令：

```java
kubectl get pods -o json | jq .items[].spec.containers[].image
```

响应应该类似于以下内容：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/3f3b0b67-78f2-4815-8c42-3f67a8931783.png)

注意 Docker 镜像的 `v1` 版本！

还要注意，MySQL、MongoDB 和 RabbitMQ 的资源管理器 Pod 已经消失了；这些可以通过 `docker-compose ps` 命令找到。

运行测试脚本 `thest-em-all.bash` 以验证模拟的生产环境：

```java
HOST=$(minikube ip) PORT=31443 ./test-em-all.bash
```

期望得到与针对开发环境运行测试脚本时相同的输出。

# 执行滚动升级

历史上，更新往往导致被更新组件的短暂停机。在具有越来越多的独立更新彼此的其他组件的系统架构中，由于频繁更新微服务而导致的重复停机是不可接受的。能够在不停机的情况下部署更新变得至关重要。

在本节中，我们将了解如何执行滚动升级，即在不需要任何停机的情况下将微服务更新为其 Docker 镜像的新版本。执行滚动升级意味着 Kubernetes 首先在新 pods 中启动微服务的新版本，当它报告为健康时，Kubernetes 将终止旧的 pods。这确保了在升级期间始终有一个 pods 在运行，准备处理传入的请求。滚动升级能够工作的前提是升级是向后兼容的，这包括与其他服务和数据库结构通信时使用的 API 和消息格式。如果微服务的新版本需要对外部 API、消息格式或数据库结构进行更改，而旧版本无法处理，则无法应用滚动升级。默认情况下，部署对象被配置为执行任何更新作为滚动升级。

为了尝试这个，我们将为`product`服务创建一个 v2 版本的 Docker 镜像，然后启动一个测试客户端`siege`，在滚动升级期间每秒提交一个请求。假设测试客户端在升级期间发送的所有请求都会报告 200（OK）。

# 准备滚动升级

为了准备滚动升级，首先验证我们已经部署了`v1`版本的产品 pods：

```java
kubectl get pod -l app=product -o jsonpath='{.items[*].spec.containers[*].image} '
```

预期的输出应该显示 Docker 镜像的`v1`版本正在使用：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/8ba120f8-86f6-4b8e-9f5c-88e9e66e05cf.png)

使用以下命令在 Docker 镜像上为`product`服务创建一个`v2`标签：

```java
docker tag hands-on/product-service:v1 hands-on/product-service:v2
```

为了从 Kubernetes 的角度尝试滚动升级，我们不需要在`product`服务中更改任何代码。部署一个不同于现有版本的 Docker 镜像将启动滚动升级。

为了能够观察到升级期间是否发生停机，我们将使用`siege`启动低负载负载测试。以下命令启动了一个模拟一个用户（`-c1`）平均每秒提交一个请求的负载测试（`-d1`）：

```java
siege https://$(minikube ip):31443/actuator/health -c1 -d1
```

由于测试调用网关的健康端点，它验证了所有服务都是健康的。

你应该收到如下所示的输出：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/2a9f905e-809b-4146-9b64-208c924649cb.png)

响应中的有趣部分是 HTTP 状态码，我们期望它始终为`200`。

也要监控产品 pods 状态的变化，可以使用以下命令：

```java
kubectl get pod -l app=product -w
```

# 从 v1 升级到 v2 的产品服务

-   要升级`product`服务，请编辑`kubernetes/services/overlays/prod/product-prod.yml`文件，将`image: hands-on/product-service:v1`更改为`image: hands-on/product-service:v2`。

-   使用以下命令应用更新：

```java
kubectl apply -k kubernetes/services/overlays/prod
```

-   期望命令的响应报告大多数对象保持不变，除了产品部署应报告为更新到`deployment.apps/product configured`。

-   Kubernetes 提供了一些简写命令。例如，`kubectl set image deployment/product pro=hands-on/product-service:v2`可以用来执行与更新定义文件并运行`kubectl apply`命令相同的更新。使用`kubectl apply`命令的一个主要好处是我们可以通过将更改推送到 Git 等版本控制系统的源代码来跟踪更改。如果我们想能够以代码方式处理我们的基础设施，这非常重要。在测试 Kubernetes 集群时，只使用它来测试简写命令，因为这将非常有用。

-   在*准备滚动升级*部分中启动的`kubectl get pod -l app=product -w`命令的输出中，我们将看到一些动作发生。请看以下截图：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/e395b5c0-fc40-43f1-b8ec-f85a9ce86628.png)

-   在这里，我们可以看到现有的 Pod（`ffrdh`）最初报告它正在运行，并在启动新的 Pod（`t8mcl`）后也报告为健康。经过一段时间（在我的案例中是`16s`），它也被报告为正在运行。在一段时间内，两个 Pod 都会运行并处理请求。经过一段时间，第一个 Pod 被终止（在我的案例中是 2 分钟）。

-   当查看`siege`输出时，有时可以在`503`服务不可用错误方面找到一些错误：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/3caab39b-4d02-4f93-ace5-5402b72aac09.png)

-   这通常发生在旧 Pod 被终止时。在旧 Pod 被 readiness 探针报告为不健康之前，它可以在终止过程中接收到几个请求，即它不再能够处理任何请求时。

-   在第十八章《使用服务网格提高可观测性和管理能力》中，我们将了解如何设置路由规则，以更平滑地将流量从旧容器移动到新容器，而不会导致 503 错误。我们还将了解如何应用重试机制，以防止临时故障影响到最终用户。

-   通过验证 Pod 是否正在使用 Docker 镜像的新`v2`版本来完成更新：

```java
kubectl get pod -l app=product -o jsonpath='{.items[*].spec.containers[*].image} '
```

-   期望的输出显示 Docker 镜像的`v2`版本正在使用：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/bd38e1cd-b695-49b8-991b-63e395ee577d.png)

-   在执行此升级后，我们可以继续学习当事情失败时会发生什么。在下一节中，我们将了解如何回滚一个失败的部署。

# -   回滚失败的部署

有时，事情并不会按照计划进行，例如，部署和 pods 的升级可能会因各种原因失败。为了演示如何回滚失败的升级，让我们尝试在不创建`v3`标签的 Docker 镜像的情况下升级到`v3`！

让我们尝试使用以下简写命令来执行更新：

```java
kubectl set image deployment/product pro=hands-on/product-service:v3
```

预期`kubectl get pod -l app=product -w`命令会报告以下变化（在“准备滚动升级”部分启动）：

<q>![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/290f3cd4-de45-4a31-8abb-495b8f20c15e.png)</q>

我们可以清楚地看到，新部署的 pods（在我的案例中以`m2dtn`结尾）因为找不到 Docker 镜像而无法启动，这是预期的。如果我们查看`siege`测试工具的输出，没有错误报告，只有 200（OK）！在这里，部署挂起，因为它找不到请求的 Docker 镜像，但终端用户没有受到任何影响，因为新 pods 甚至没有启动。

让我们查看 Kubernetes 关于产品部署的历史记录。运行以下命令：

```java
kubectl rollout history deployment product
```

你将收到如下类似输出：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/f5e3c16a-efab-43df-a5a5-04dda9c5c4c9.png)

我们可以猜测修订 2 是最新成功部署的，也就是 Docker 镜像的`v2`。让我们用以下命令来验证：

```java
kubectl rollout history deployment product --revision=2
```

在响应中，我们可以看到`revision #2`带有 Docker 镜像`v2`：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/4e3d11c8-a112-40c0-be6b-29631e196c19.png)

以下命令可以将部署回滚到`revision=2`：

```java
kubectl rollout undo deployment product --to-revision=2
```

预期会有一个确认回滚的响应，如下所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/936308fe-f3a2-45aa-949b-2fe8fe52cbe5.png)

在“准备滚动升级”部分启动的`kubectl get pod -l app=product -w`命令会报告新（不可用）pods 已被`rollback`命令移除：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/0f0d45ea-cb69-4f32-a2fa-55edca821532.png)

我们可以通过验证当前镜像版本仍为`v2`来结束本章：

```java
kubectl get pod -l app=product -o jsonpath='{.items[*].spec.containers[*].image} '
```

# 清理

为了删除我们使用的资源，请运行以下命令：

1.  停止`kubectl get pod -l app=product -w`命令（用于监控）和`siege`负载测试程序。

1.  删除命名空间：

```java
kubectl delete namespace hands-on
```

1.  关闭运行在 Kubernetes 之外的资源管理器：

```java
eval $(minikube docker-env)
docker-compose down
```

`kubectl delete namespace`命令将递归删除命名空间中存在的所有 Kubernetes 资源，`docker-compose down`命令将停止 MySQL、MongoDB 和 RabbitMQ。删除生产环境后，我们结束了这一章。

# 摘要

在本章中，我们学习了如何在 Kubernetes 上部署本书中的微服务。我们还介绍了 Kubernetes 的一些核心功能，例如使用 Kustomize 为不同的运行时环境配置部署，使用 Kubernetes 部署对象进行滚动升级，以及如果需要如何回滚失败的更新。为了帮助 Kubernetes 了解何时需要重新启动微服务以及它们是否准备好接收请求，我们实现了生存和就绪探针。

最后，为了能够部署我们的微服务，我们必须用 Kubernetes 内置的发现服务替换 Netflix Eureka。更改发现服务时，没有进行任何代码更改——我们所需要做的就是应用构建依赖项和一些配置的变化。

在下一章中，我们将了解如何进一步利用 Kubernetes 来减少我们需要在 Kubernetes 中部署的支持服务的数量。翻到下一章，了解我们如何消除配置服务器的需求，以及我们的边缘服务器如何被 Kubernetes 入口控制器所替代。

# 问题

1.  为什么我们在将微服务部署到 Kubernetes 时删除了 Eureka 服务器？

1.  我们用什么替换了 Eureka 服务器，这次变更如何影响了微服务的源代码？

1.  Kustomize 中 base 和 overlay 文件夹是如何使用的？

1.  我们如何将配置映射（config map）或机密（secret）中的更改应用到正在运行的 Pod？

1.  如果我们正在使用 Docker 镜像的最新标签，那么如何使用新的 Docker 镜像构建来运行正在运行的 Pod？

1.  我们可以使用哪些命令来回滚一个失败的部署？

1.  存活探针（liveness probes）和就绪探针（readiness probes）的目的是什么？

1.  以下服务定义中使用了哪些不同的端口？

```java
apiVersion: v1
kind: Service
spec:
  type: NodePort
  ports:
    - port: 80
      nodePort: 30080
      targetPort: 8080
```
