# 精通 SpringCloud（二）

> 原文：[`zh.annas-archive.org/md5/3341AF3ECE66B2253A7F83A5D112367C`](https://zh.annas-archive.org/md5/3341AF3ECE66B2253A7F83A5D112367C)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：微服务间的通信

在过去的两章中，我们讨论了与微服务架构中非常重要的元素相关的细节——服务发现和配置服务器。然而，值得记住的是，它们存在于系统中的主要原因只是为了帮助管理整个独立、独立的应用程序集合。这种管理的一个方面是微服务间的通信。在这里，服务发现扮演着特别重要的角色，它负责存储和提供所有可用应用程序的网络位置。当然，我们可以想象我们的系统架构没有服务发现服务器。本章也将呈现这样一个示例。

然而，参与服务间通信最重要的组件是 HTTP 客户端和客户端负载均衡器。在本章中，我们将只关注它们。

本章我们将覆盖的主题包括：

+   使用 Spring `RestTemplate`进行带服务发现和不带服务发现的微服务间通信

+   自定义 Ribbon 客户端

+   描述 Feign 客户端提供的 main 特性，如与 Ribbon 客户端的集成、服务发现、继承和区域支持

# 不同的通信风格

我们可以识别出微服务间通信的不同风格。可以将它们分为两个维度进行分类。第一个维度是同步通信和异步通信协议的区分。异步通信的关键点是，客户端在等待响应时不应该阻塞线程。对于这种类型的通信，最流行的协议是 AMQP，我们在上一章的末尾已经有了使用该协议的示例。然而，服务间通信的主要方式仍然是同步 HTTP 协议。我们本章只讨论这个。

第二个维度是基于是否有单一的消息接收者或多个接收者来进行不同的通信类型区分。在一对一的通信中，每个请求都由一个确切的服务实例处理。在一对多的通信中，每个请求可能被多个不同的服务处理。这将在第十一章 *消息驱动的微服务* 中讨论。

# 使用 Spring Cloud 进行同步通信

Spring Cloud 提供了一系列组件，帮助你实现微服务之间的通信。第一个组件是 `RestTemplate`，它总是用于客户端消费 RESTful web 服务。它包含在 Spring Web 项目中。为了在一个微服务环境中有效地使用它，它应该用 `@LoadBalanced` 注解标记。得益于这一点，它会自动配置为使用 Netflix Ribbon，并能够利用服务发现，通过使用服务名称而不是 IP 地址。Ribbon 是客户端负载均衡器，它提供了一个简单的接口，允许控制 HTTP 和 TCP 客户端的行为。它可以轻松地与其他 Spring Cloud 组件集成，如服务发现或断路器，而且对开发者完全透明。下一个可用的组件是 Feign，来自 Netflix OSS 堆栈的声明式 REST 客户端。Feign 已经使用 Ribbon 进行负载均衡和从服务发现获取数据。它可以通过在接口方法上使用 `@FeignClient` 注解轻松声明。在本章中，我们将详细查看这里列出的所有组件。

# 使用 Ribbon 进行负载均衡

围绕 Ribbon 的主要概念是一个命名的 **客户端**。这就是为什么我们可以使用服务名称而不是带有主机名和端口的全地址来调用其他服务，而无需连接到服务发现。在这种情况下，地址列表应该在 `application.yml` 文件内的 Ribbon 配置设置中提供。

# 使用 Ribbon 客户端启用微服务之间的通信

让我们来看一个例子。这个例子包含四个独立的微服务。其中一些可能会调用其他微服务暴露的端点。应用程序源代码可以在以下链接找到：

链接：[`github.com/piomin/sample-spring-cloud-comm.git`](https://github.com/piomin/sample-spring-cloud-comm.git)。

在这个例子中，我们将尝试开发一个简单的订单系统，顾客可以购买产品。如果顾客决定确认购买的选定产品列表，`POST`请求将被发送到`order-service`。它由 REST 控制器内的`Order prepare(@RequestBody Order order) {...}`方法处理，该方法负责订单准备。首先，它通过调用`customer-service`中的适当 API 方法计算最终价格，考虑列表中每个产品的价格、顾客订单历史以及他们在系统中的类别。然后，它通过调用账户服务验证顾客的账户余额是否足够执行订单，并最终返回计算出的价格。如果顾客确认该操作，将调用`PUT /{id}`方法。请求由 REST 控制器内的`Order accept(@PathVariable Long id) {...}`方法处理。它更改订单状态并从顾客账户中提取资金。系统架构如以下所示分解为单独的微服务：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/5c7304e2-7612-4327-94a6-eaaaec6c0fd5.png)

# 静态负载均衡配置

我们的`order-service`必须与示例中的所有其他微服务通信以执行所需操作。因此，我们需要定义三个不同的 Ribbon 客户端，并使用`ribbon.listOfServers`属性设置网络地址。示例中的第二件重要的事情是禁用默认启用的 Eureka 发现服务。以下是`order-service`在其`application.yml`文件中定义的所有属性：

```java
server:
 port: 8090

account-service:
 ribbon:
   eureka:
     enabled: false
   listOfServers: localhost:8091
customer-service:
 ribbon:
   eureka:
     enabled: false
   listOfServers: localhost:8092
product-service:
 ribbon:
   eureka:
     enabled: false
   listOfServers: localhost:8093
```

为了与 Ribbon 客户端一起使用`RestTemplate`，我们应该在项目中包含以下依赖关系：

```java
<dependency>
 <groupId>org.springframework.cloud</groupId>
 <artifactId>spring-cloud-starter-ribbon</artifactId>
</dependency>
<dependency>
 <groupId>org.springframework.boot</groupId>
 <artifactId>spring-boot-starter-web</artifactId>
</dependency>
```

然后，我们应该通过声明在`application.yml`中配置的名称列表来启用 Ribbon 客户端。为了实现这一点，您可以注解主类或任何其他 Spring 配置类为`@RibbonClients`。您还应该注册`RestTemplate`bean，并将其注解为`@LoadBalanced`，以启用与 Spring Cloud 组件的交互：

```java
@SpringBootApplication
@RibbonClients({
 @RibbonClient(name = "account-service"),
 @RibbonClient(name = "customer-service"),
 @RibbonClient(name = "product-service")
})
public class OrderApplication {

 @LoadBalanced
 @Bean
 RestTemplate restTemplate() {
     return new RestTemplate();
 } 

 public static void main(String[] args) {
     new SpringApplicationBuilder(OrderApplication.class).web(true).run(args);
 }
 // ...
}
```

# 调用其他服务

最后，我们可以开始实现负责提供微服务外暴露的 HTTP 方法的`OrderController`。它注入了`RestTemplate`bean，以便能够调用其他 HTTP 端点。您可以在以下代码片段中看到使用了在`application.yml`中配置的 Ribbon 客户端名称，而不是 IP 地址或主机名。使用相同的`RestTemplate`bean，我们可以与三个不同的微服务进行通信。让我们在这里讨论一下控制器中可用的方法。在实现的方法中，我们调用`product-service`的`GET`端点，它返回所选产品的详细信息列表。然后，我们调用`customer-service`暴露的`GET /withAccounts/{id}`方法。它返回带有其账户列表的客户详细信息。

现在，我们已经有了计算最终订单价格和验证客户在他们主账户中是否有足够资金所需的所有信息。`PUT`方法调用`account-service`的端点从客户账户中提取资金。我花了很多时间讨论了`OrderController`中可用的方法。然而，我认为这是必要的，因为同一个示例将用于展示提供微服务间同步通信机制的 Spring Cloud 组件的主要特性：

```java
@RestController
public class OrderController {

 @Autowired
 OrderRepository repository; 
 @Autowired
 RestTemplate template;

 @PostMapping
 public Order prepare(@RequestBody Order order) {
     int price = 0;
     Product[] products = template.postForObject("http://product-service/ids", order.getProductIds(), Product[].class);
     Customer customer = template.getForObject("http://customer-service/withAccounts/{id}", Customer.class, order.getCustomerId());
     for (Product product : products) 
         price += product.getPrice();
     final int priceDiscounted = priceDiscount(price, customer);
     Optional<Account> account = customer.getAccounts().stream().filter(a -> (a.getBalance() > priceDiscounted)).findFirst();
     if (account.isPresent()) {
         order.setAccountId(account.get().getId());
         order.setStatus(OrderStatus.ACCEPTED);
         order.setPrice(priceDiscounted);
     } else {
         order.setStatus(OrderStatus.REJECTED);
     }
     return repository.add(order);
 }

 @PutMapping("/{id}")
 public Order accept(@PathVariable Long id) {
     final Order order = repository.findById(id);
     template.put("http://account-service/withdraw/{id}/{amount}", null, order.getAccountId(), order.getPrice());
     order.setStatus(OrderStatus.DONE);
     repository.update(order);
     return order;
 }
 // ...
}
```

有趣的是，`customer-service`中的`GET /withAccounts/{id}`方法，它被`order-service`调用，也使用 Ribbon 客户端与另一个微服务`account-service`进行通信。以下是`CustomerController`中实现上述方法的片段：

```java
@GetMapping("/withAccounts/{id}")
public Customer findByIdWithAccounts(@PathVariable("id") Long id) {
 Account[] accounts = template.getForObject("http://account-service/customer/{customerId}", Account[].class, id);
 Customer c = repository.findById(id);
 c.setAccounts(Arrays.stream(accounts).collect(Collectors.toList()));
 return c;
}
```

首先，使用 Maven 命令`mvn clean install`构建整个项目。然后，您可以使用没有任何额外参数的`java -jar`命令以任何顺序启动所有微服务。可选地，您还可以从您的 IDE 中运行应用程序。每个微服务在启动时都会准备测试数据。没有持久化存储，所以重启后所有对象都会被清除。我们可以通过调用`order-service`暴露的`POST`方法来测试整个系统。以下是一个示例请求：

```java
$ curl -d '{"productIds": [1,5],"customerId": 1,"status": "NEW"}' -H "Content-Type: application/json" -X POST http://localhost:8090
```

如果您尝试发送这个请求，您将能够看到 Ribbon 客户端打印出以下日志：

```java
DynamicServerListLoadBalancer for client customer-service initialized: DynamicServerListLoadBalancer:{NFLoadBalancer:name=customer-service,current list of Servers=[localhost:8092],Load balancer stats=Zone stats: {unknown=[Zone:unknown; Instance count:1; Active connections count: 0; Circuit breaker tripped count: 0; Active connections per server: 0.0;]
},Server stats: [[Server:localhost:8092; Zone:UNKNOWN; Total Requests:0; Successive connection failure:0; Total blackout seconds:0; Last connection made:Thu Jan 01 01:00:00 CET 1970; First connection made: Thu Jan 01 01:00:00 CET 1970; Active Connections:0; total failure count in last (1000) msecs:0; average resp time:0.0; 90 percentile resp time:0.0; 95 percentile resp time:0.0; min resp time:0.0; max resp time:0.0; stddev resp time:0.0]
]}ServerList:com.netflix.loadbalancer.ConfigurationBasedServerList@7f1e23f6
```

本节描述的方法有一个很大的缺点，这使得它在由几个微服务组成的系统中不太可用。如果您有自动扩展，问题会更严重。很容易看出，所有服务的网络地址都必须手动管理。当然，我们可以将配置设置从每个胖 JAR 内的`application.yml`文件移动到配置服务器。然而，这并没有改变管理大量交互仍然会麻烦的事实。这种问题可以通过客户端负载均衡和服务发现之间的互动轻易解决。

# 使用与服务发现一起的 RestTemplate

实际上，与服务发现集成是 Ribbon 客户端的默认行为。正如您可能记得的，我们通过将`ribbon.eureka.enabled`属性设置为`false`来禁用客户端负载均衡的 Eureka。服务发现的存在简化了 Spring Cloud 组件在服务间通信时的配置，本节的示例就是如此。

# 构建示例应用程序

系统架构与之前的示例相同。要查看当前练习的源代码，你必须切换到`ribbon_with_discovery`分支 ([`github.com/piomin/shown here-spring-cloud-comm/tree/ribbon_with_discovery`](https://github.com/piomin/sample-spring-cloud-comm/tree/ribbon_with_discovery)).在那里，你首先看到的是一个新模块，`discovery-service`。我们在第四章，*服务发现*中详细讨论了与 Eureka 几乎所有相关方面，所以你应该不会有任何问题启动它。我们运行一个带有非常基本设置的单一独立 Eureka 服务器。它可在默认端口`8761`上访问。

与之前示例相比，我们应该删除所有严格与 Ribbon 客户端相关的配置和注解。取而代之的是，必须使用`@EnableDiscoveryClient`启用 Eureka 发现客户端，并在`application.yml`文件中提供 Eureka 服务器地址。现在，`order-service`的主类看起来像这样：

```java
@SpringBootApplication
@EnableDiscoveryClient
public class OrderApplication {

 @LoadBalanced
 @Bean
 RestTemplate restTemplate() {
 return new RestTemplate();
 }

 public static void main(String[] args) {
     new SpringApplicationBuilder(OrderApplication.class).web(true).run(args);
 }
 // ...
}
```

这是当前的配置文件。我用`spring.application.name`属性设置了服务的名称：

```java
spring: 
 application:
   name: order-service

server:
 port: ${PORT:8090}

eureka:
 client:
   serviceUrl:
     defaultZone: ${EUREKA_URL:http://localhost:8761/eureka/}
```

这就是之前的内容；我们同样启动所有的微服务。但是，这次`account-service`和`product-service`将各增加两个实例。启动每个服务的第二个实例时，默认的服务器端口可以通过`-DPORT`或`-Dserver.port`参数来覆盖，例如，`java -jar -DPORT=9093 product-service-1.0-SNAPSHOT.jar`。所有实例都已注册到 Eureka 服务器中。这可以通过其 UI 仪表板轻松查看：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/deb2c9a7-afca-421d-993c-84c3189fed0c.png)

这是本书中第一次看到负载均衡的实际例子。默认情况下，Ribbon 客户端将流量平均分配到微服务的所有注册实例。这种算法叫做**轮询**。实际上，这意味着客户端记得它上一次将请求转发到哪里，然后将当前请求发送到队列中的下一个服务。这种方法可以被我接下来详细介绍的其他规则覆盖。负载均衡也可以为前面没有服务发现的例子进行配置，通过在`ribbon.listOfServers`中设置一个以逗号分隔的服务地址列表，例如，`ribbon.listOfServers=localhost:8093,localhost:9093`。回到例子应用程序，`order-service`发送的请求将在`account-service`和`product-service`的两个实例之间进行负载均衡。这与上面截图中显示的`customer-service`类似，后者将在两个`account-service`实例之间分配流量。如果你启动了上一截图中 Eureka 仪表板上可见的所有服务实例，并向`order-service`发送一些测试请求，你肯定会看到我贴出的以下日志。我突出了 Ribbon 客户端显示目标服务找到的地址列表的片段：

```java
DynamicServerListLoadBalancer for client account-service initialized: DynamicServerListLoadBalancer:{NFLoadBalancer:name=account-service,current list of Servers=[minkowp-l.p4.org:8091, minkowp-l.p4.org:9091],Load balancer stats=Zone stats: {defaultzone=[Zone:defaultzone; Instance count:2; Active connections count: 0; Circuit breaker tripped count: 0; Active connections per server: 0.0;]
 },Server stats: [[Server:minkowp-l.p4.org:8091; Zone:defaultZone; Total Requests:0; Successive connection failure:0; Total blackout seconds:0; Last connection made:Thu Jan 01 01:00:00 CET 1970; First connection made: Thu Jan 01 01:00:00 CET 1970; Active Connections:0; total failure count in last (1000) msecs:0; average resp time:0.0; 90 percentile resp time:0.0; 95 percentile resp time:0.0; min resp time:0.0; max resp time:0.0; stddev resp time:0.0]
 , [Server:minkowp-l.p4.org:9091; Zone:defaultZone; Total Requests:0; Successive connection failure:0; Total blackout seconds:0; Last connection made:Thu Jan 01 01:00:00 CET 1970; First connection made: Thu Jan 01 01:00:00 CET 1970; Active Connections:0; total failure count in last (1000) msecs:0; average resp time:0.0; 90 percentile resp time:0.0; 95 percentile resp time:0.0; min resp time:0.0; max resp time:0.0; stddev resp time:0.0]
 ]}ServerList:org.springframework.cloud.netflix.ribbon.eureka.DomainExtractingServerList@3e878e67
```

# 使用 Feign 客户端

`RestTemplate`是 Spring 的一个组件，特别适用于与 Spring Cloud 和微服务进行交互。然而，Netflix 开发了自己的工具，作为 web 服务客户端，提供给独立的 REST 服务之间开箱即用的通信。Feign 客户端，在其中，通常与`RestTemplate`的`@LoadBalanced`注解做相同的事情，但以更优雅的方式。它是一个通过处理注解将其转换为模板化请求的 Java 到 HTTP 客户端绑定器。当使用 Open Feign 客户端时，你只需要创建一个接口并注解它。它与 Ribbon 和 Eureka 集成，提供一个负载均衡的 HTTP 客户端，从服务发现中获取所有必要的网络地址。Spring Cloud 为 Spring MVC 注解添加支持，并使用与 Spring Web 相同的 HTTP 消息转换器。

# 支持不同区域

让我回退一下，回到上一个例子。我打算对我们的系统架构做些改动以使其稍微复杂一些。当前的架构在下面的图表中有可视化展示。微服务之间的通信模型仍然是相同的，但现在我们启动每个微服务的两个实例并将它们分为两个不同的区域。关于区域划分机制已经在第四章、*服务发现*中讨论过，在讨论使用 Eureka 进行服务发现时，所以我想你们已经很熟悉了。这次练习的主要目的不仅是展示如何使用 Feign 客户端，还有微服务实例间通信中区域划分机制是如何工作的。那么我们从基础知识开始：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/0afef3be-1670-4898-98c6-3c8c6f421485.png)

# 启用 Feign 应用程序

为了在项目中包含 Feign，我们必须添加依赖`spring-cloud-starter-feign`artifact 或`spring-cloud-starter-openfeign`对于 Spring Cloud Netflix 的最小版本 1.4.0：

```java
<dependency>
 <groupId>org.springframework.cloud</groupId>
 <artifactId>spring-cloud-starter-feign</artifactId>
</dependency>
```

下一步是启用应用程序中的 Feign，通过用`@EnableFeignClients`注解主类或配置类来实现。这个注解会导致搜索应用程序中所有实现的客户端。我们也可以通过设置`clients`或`basePackages`注解属性来减少使用的客户端数量，例如，`@EnableFeignClients(clients = {AccountClient.class, Product.class})`。这是`order-service`应用程序的主类：

```java
@SpringBootApplication
@EnableDiscoveryClient
@EnableFeignClients
public class OrderApplication {

    public static void main(String[] args) {
        new SpringApplicationBuilder(OrderApplication.class).web(true).run(args);
    }

    @Bean
    OrderRepository repository() {
        return new OrderRepository();
    }

}
```

# 构建 Feign 接口

一种只需要创建带有某些注解的接口来提供组件的方法是 Spring Framework 的标准做法。对于 Feign，必须用`@FeignClient(name = "...")`注解接口。它有一个必需的属性名，如果启用了服务发现，则对应于被调用的微服务名称。否则，它与`url`属性一起使用，我们可以设置一个具体的网络地址。`@FeignClient`并不是这里需要使用的唯一注解。我们客户端接口中的每个方法都通过用`@RequestMapping`或更具体的注解如`@GetMapping`、`@PostMapping`或`@PutMapping`来标记，与特定的 HTTP API 端点相关联，正如这个例子源代码片段中所示：

```java
@FeignClient(name = "account-service")
public interface AccountClient {
    @PutMapping("/withdraw/{accountId}/{amount}")
    Account withdraw(@PathVariable("accountId") Long id, @PathVariable("amount") int amount);
}

@FeignClient(name = "customer-service")
public interface CustomerClient {
    @GetMapping("/withAccounts/{customerId}")
    Customer findByIdWithAccounts(@PathVariable("customerId") Long customerId);
}

@FeignClient(name = "product-service")
public interface ProductClient {
    @PostMapping("/ids")
    List<Product> findByIds(List<Long> ids);
}
```

这样的组件可以被注入到控制器 bean 中，因为它们也是 Spring Beans。然后，我们只需调用它们的方法。以下是`order-service`中当前 REST 控制器的实现：

```java
@Autowired
OrderRepository repository;
@Autowired
AccountClient accountClient;
@Autowired
CustomerClient customerClient;
@Autowired
ProductClient productClient;

@PostMapping
public Order prepare(@RequestBody Order order) {
    int price = 0;
    List<Product> products = productClient.findByIds(order.getProductIds());
    Customer customer = customerClient.findByIdWithAccounts(order.getCustomerId());
    for (Product product : products)
        price += product.getPrice();
    final int priceDiscounted = priceDiscount(price, customer);
    Optional<Account> account = customer.getAccounts().stream().filter(a -> (a.getBalance() > priceDiscounted)).findFirst();
    if (account.isPresent()) {
        order.setAccountId(account.get().getId());
        order.setStatus(OrderStatus.ACCEPTED);
        order.setPrice(priceDiscounted);
    } else {
        order.setStatus(OrderStatus.REJECTED);
    }
    return repository.add(order);
}
```

# 启动微服务

我已经在`application.yml`中更改了所有微服务的配置。现在，有两个不同的配置文件，第一个用于将应用程序分配给`zone1`，第二个用于`zone2`。你可以从`feign_with_discovery`分支查看版本（[`github.com/piomin/shown here-spring-cloud-comm/tree/feign_with_discovery`](https://github.com/piomin/sample-spring-cloud-comm/tree/feign_with_discovery)）。然后，使用`mvn clean install`命令构建整个项目。应用应该使用`java -jar --spring.profiles.active=zone[n]`命令启动，其中`[n]`是区域编号。因为你要启动很多实例来执行那个测试，考虑通过设置`-Xmx`参数限制堆大小是有价值的，例如，`-Xmx128m`。以下是其中一个微服务当前的配置设置：

```java
spring: 
 application:
     name: account-service

---
spring:
 profiles: zone1
eureka:
 instance:
     metadataMap:
         zone: zone1
 client:
     serviceUrl:
        defaultZone: http://localhost:8761/eureka/
        preferSameZoneEureka: true
server: 
 port: ${PORT:8091}

---
spring:
 profiles: zone2
eureka:
 instance:
     metadataMap:
        zone: zone2
 client:
     serviceUrl:
        defaultZone: http://localhost:8761/eureka/
        preferSameZoneEureka: true
server: 
 port: ${PORT:9091}
```

我们将每个区域启动每一个微服务的一个实例。所以，有九个正在运行的 Spring Boot 应用程序，包括服务发现服务器，如图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/0333d3f0-6041-4b5e-98cc-a474b4c5a072.png)

如果你向在`zone1`运行的`order-service`实例（`http://localhost:8090`）发送测试请求，所有流量都将转发到该区域的其他服务，`zone2`（`http://localhost:9090`）也是如此。我突出了 Ribbon 客户端在该区域注册的目标服务找到的地址列表的片段：

```java
DynamicServerListLoadBalancer for client product-service initialized: DynamicServerListLoadBalancer:{NFLoadBalancer:name=product-service,current list of Servers=[minkowp-l.p4.org:8093],Load balancer stats=Zone stats: {zone1=[Zone:zone1; Instance count:1; Active connections count: 0; Circuit breaker tripped count: 0; Active connections per server: 0.0;]...
```

# 继承支持

你可能已经注意到，控制器实现内部的注解和为该控制器服务的 REST 服务的 Feign 客户端实现是相同的。我们可以创建一个包含抽象 REST 方法定义的接口。这个接口可以被控制器类实现或者被 Feign 客户端接口扩展：

```java
public interface AccountService {

    @PostMapping
    Account add(@RequestBody Account account);

    @PutMapping
    Account update(@RequestBody Account account);

    @PutMapping("/withdraw/{id}/{amount}")
    Account withdraw(@PathVariable("id") Long id, @PathVariable("amount") int amount); 

    @GetMapping("/{id}")
    Account findById(@PathVariable("id") Long id); 

    @GetMapping("/customer/{customerId}")
    List<Account> findByCustomerId(@PathVariable("customerId") Long customerId); 

    @PostMapping("/ids")
    List<Account> find(@RequestBody List<Long> ids); 

    @DeleteMapping("/{id}")
    void delete(@PathVariable("id") Long id);

}
```

现在，控制器类为基本接口提供了所有方法的实现，但并未包含任何 REST 映射注解，而只用了`@RestController`。以下是`account-service`控制器的片段：

```java
@RestController
public class AccountController implements AccountService {

    @Autowired
    AccountRepository repository;

    public Account add(@RequestBody Account account) {
        return repository.add(account);
    }
    // ...
}
```

调用`account-service`的 Feign 客户端接口不提供任何方法。它只是扩展了基础接口，`AccountService`。要查看基于接口和 Feign 继承的全实现，切换到`feign_with_inheritance`分支：

[`github.com/piomin/shown here-spring-cloud-comm/tree/feign_with_inheritance`](https://github.com/piomin/sample-spring-cloud-comm/tree/feign_with_inheritance)

以下是一个带有继承支持的 Feign 客户端声明示例。它扩展了`AccountService`接口，因此处理了所有由`@RestController`暴露的方法：

```java
@FeignClient(name = "account-service")
public interface AccountClient extends AccountService {
}
```

# 手动创建客户端

如果你不喜欢注解式的风格，你总是可以手动创建一个 Feign 客户端，使用 Feign Builder API。Feign 有多个可以自定义的功能，比如消息的编码器和解码器或 HTTP 客户端实现：

```java
AccountClient accountClient = Feign.builder().client(new OkHttpClient())
    .encoder(new JAXBEncoder())
    .decoder(new JAXBDecoder())
    .contract(new JAXRSContract())
    .requestInterceptor(new BasicAuthRequestInterceptor("user", "password"))
    .target(AccountClient.class, "http://account-service");
```

# 客户端定制

客户端定制不仅可以使用 Feign Builder API 完成，还可以通过使用注解风格来进行。我们可以通过设置`@FeignClient`的`configuration`属性来提供一个配置类：

```java
@FeignClient(name = "account-service", configuration = AccountConfiguration.class)
```

以下是一个配置 bean 的示例：

```java
@Configuration
public class AccountConfiguration {
 @Bean
 public Contract feignContract() {
     return new JAXRSContract();
 }

 @Bean
 public Encoder feignEncoder() {
     return new JAXBEncoder();
 }

 @Bean
 public Decoder feignDecoder() {
     return new JAXBDecoder();
 }

 @Bean
 public BasicAuthRequestInterceptor basicAuthRequestInterceptor() {
     return new BasicAuthRequestInterceptor("user", "password");
 }
}
```

Spring Cloud 支持以下属性通过声明 Spring Beans 来覆盖：

+   `Decoder`：默认是`ResponseEntityDecoder`。

+   `Encoder`：默认是`SpringEncoder`。

+   `Logger`：默认是`Slf4jLogger`。

+   `Contract`：默认是`SpringMvcContract`。

+   `Feign.Builder`：默认是`HystrixFeign.Builder`。

+   `Client`：如果启用了 Ribbon，则是`LoadBalancerFeignClient`；否则，使用默认的 Feign 客户端。

+   `Logger.Level`：它为 Feign 设置了默认日志级别。你可以选择`NONE`、`BASIC`、`HEADERS`和`FULL`之间的一种。

+   `Retryer`：它允许在通信失败时实现重试算法。

+   `ErrorDecoder`：它允许将 HTTP 状态码映射为特定于应用程序的异常。

+   `Request.Options`：它允许为请求设置读取和连接超时。

+   `Collection<RequestInterceptor>`：已注册的`RequestInterceptor`实现集合，根据从请求中获取的数据执行某些操作。

Feign 客户端也可以通过配置属性进行定制。通过在`feign.client.config`属性前缀后提供其名称，可以覆盖所有可用客户端的设置，或仅覆盖单个选定客户端的设置。如果我们设置名为`default`而不是特定客户端名称，它将应用于所有 Feign 客户端。当使用`@EnableFeignClients`注解及其`defaultConfiguration`属性时，也可以在`appplication.yml`文件中指定默认配置。提供的设置始终优先于`@Configuration` bean。如果想要改变这种方法，优先使用`@Configuration`而不是 YAML 文件，你应该将`feign.client.default-to-properties`属性设置为`false`。以下是一个为`account-service`设置连接超时、HTTP 连接的读取超时和日志级别的 Feign 客户端配置示例：

```java
feign:
 client:
   config:
     account-service:
       connectTimeout: 5000
       readTimeout: 5000
       loggerLevel: basic
```

# 摘要

在本章中，我们已经启动了几个相互通信的微服务。我们讨论了诸如 REST 客户端的不同实现、多个实例之间的负载均衡以及与服务发现集成等主题。在我看来，这些方面是如此重要，以至于我决定用两章的篇幅来描述它们。本章应被视为微服务间通信主题的介绍，以及对微服务架构中其他重要组件集成的讨论。下一章将展示负载均衡器和 REST 客户端的高级使用，特别关注网络和通信问题。阅读完本章后，您应该能够在自己的应用程序中正确使用 Ribbon、Feign，甚至`RestTemplate`，并将它们连接到 Spring Cloud 的其他组件。

在大多数情况下，这些知识已经足够。然而，有时您可能需要自定义客户端负载均衡器配置，或者启用像断路器或回退这样的更高级的通信机制。理解这些解决方案及其对您系统中微服务间通信的影响是很重要的。我们将在下一章中讨论它们。


# 第七章：高级负载均衡和断路器

在本章中，我们将继续讨论前一章中讨论的主题，即服务间通信。我们将扩展到更高级的负载均衡、超时和断路示例。

Spring Cloud 提供了使微服务间通信简单而优雅的功能。然而，我们绝不能忘记，这样的通信所面临的的主要困难涉及所涉及系统的处理时间。如果您系统中有很多微服务，您需要处理的第一个问题之一是延迟问题。在本章中，我想讨论一些 Spring Cloud 功能，帮助我们避免由于服务间处理单个输入请求时的许多跃点、多个服务的缓慢响应或服务的暂时不可用而引起的延迟问题。处理部分失败有几种策略，包括设置网络超时、限制等待请求的数量、实现不同的负载均衡方法，或设置断路器模式和回退实现。

我们还将再次讨论 Ribbon 和 Feign 客户端，这次重点关注它们更高级的配置功能。在这里将介绍一个全新的库，即 Netflix Hystrix。这个库实现了断路器模式。

本章我们将覆盖以下主题：

+   使用 Ribbon 客户端的不同负载均衡算法

+   启用应用程序的断路器

+   使用配置属性自定义 Hystrix

+   使用 Hystrix 仪表板监控服务间通信

+   使用 Hystrix 和 Feign 客户端一起

# 负载均衡规则

Spring Cloud Netflix 提供了不同的负载均衡算法，以向用户提供不同的好处。您支持的方法选择取决于您的需求。在 Netflix OSS 命名法中，此算法称为**规则**。自定义规则类应实现`IRule`基础接口。以下实现默认情况下在 Spring Cloud 中可用：

+   `RoundRobinRule`：此规则简单地使用众所周知的轮询算法选择服务器，其中传入请求按顺序分配到所有实例。它通常用作默认规则或更高级规则的回退，例如`ClientConfigEnabledRoundRobinRule`和`ZoneAvoidanceRule`。`ZoneAvoidanceRule`是 Ribbon 客户端的默认规则。

+   `AvailabilityFilteringRule`：This rule will skip servers that are marked as circuit tripped or with a high number of concurrent connections. It also uses `RoundRobinRule` as a base class. By default, an instance is circuit tripped if an HTTP client fails to establish a connection with it three times in a row. This approach may be customized with the `niws.loadbalancer.<clientName>.connectionFailureCountThreshold` property. Once an instance is circuit tripped, it will remain in this state for the next 30 seconds before the next retry. This property may also be overridden in the configuration settings.

+   `WeightedResponseTimeRule`： with this implementation, a traffic volume forwarder to the instance is inversely proportional to the instance's average response time. In other words, the longer the response time, the less weight it will get. In these circumstances, a load balancing client will record the traffic and response time of every instance of the service.

+   `BestAvailableRule`：According to the description from the class documentation, this rule skips servers with *tripped* circuit breakers and picks the server with the lowest concurrent requests.

跳闸断路器是一个来自电气工程的术语，指的是电路中没有电流流动。在 IT 术语中，它指的是发送给服务器的连续请求失败次数过多，因此客户端软件会立即中断对远程服务的进一步调用，以减轻服务器端应用程序的负担。

# 权重响应时间规则

直到现在，我们通常还通过从网页浏览器或 REST 客户端调用服务来手动测试服务。目前的更改不允许采用这种方法，因为我们需要为服务设置模拟延迟，以及生成许多 HTTP 请求。

# 介绍 Hoverfly 用于测试

在此阶段，我想介绍一个可能完美解决这类测试的有趣框架。我指的是 Hoverfly，一个轻量级的服务虚拟化工具，用于模拟或虚拟 HTTP 服务。它最初是用 Go 编写的，但还为您提供了用于管理 Hoverfly 的 Java 语言的丰富 API。由 SpectoLabs 维护的 Hoverfly Java 提供了用于抽象二进制和 API 调用、创建模拟的 DSL 以及与 JUnit 测试框架集成的类。我喜欢这个框架的一个功能。您可以通过在 DSL 定义中调用一个方法，轻松地为每个模拟服务添加延迟。为了使 Hoverfly 适用于您的项目，您必须在 Maven `pom.xml`中包含以下依赖项：

```java
<dependency>
    <groupId>io.specto</groupId>
    <artifactId>hoverfly-java</artifactId>
    <version>0.9.0</version>
    <scope>test</scope>
</dependency>
```

# 测试规则

我们在这里讨论的样本可以在 GitHub 上找到。要访问它，你必须切换到`weighted_lb`分支（[`github.com/piomin/sample-spring-cloud-comm/tree/weighted_lb`](https://github.com/piomin/sample-spring-cloud-comm/tree/weighted_lb)）。我们的 JUnit 测试类，名为`CustomerControllerTest`，位于`src/test/Java`目录下。为了在测试中启用 Hoverfly，我们应该定义 JUnit `@ClassRule`。`HoverflyRule`类提供了一个 API，允许我们模拟具有不同地址、特性和响应的许多服务。在下面的源代码片段中，你可以看到我们的示例微服务`account-service`的两个实例被声明在`@ClassRule`中。正如你可能记得的，那个服务已经被`customer-service`和`order-service`调用过。

让我们来看一下`customer-service`模块中的一个测试类。它模拟了`GET /customer/*`方法，并为`account-service`的两个实例（分别监听端口`8091`和`9091`）定义了一个预定义的响应。其中第一个实例延迟了`200`毫秒，而第二个实例延迟了`50`毫秒：

```java
@ClassRule
public static HoverflyRule hoverflyRule = HoverflyRule
 .inSimulationMode(dsl(
 service("account-service:8091")
     .andDelay(200, TimeUnit.MILLISECONDS).forAll()
     .get(startsWith("/customer/"))
     .willReturn(success("[{\"id\":\"1\",\"number\":\"1234567890\",\"balance\":5000}]", "application/json")),
 service("account-service:9091")
     .andDelay(50, TimeUnit.MILLISECONDS).forAll()
     .get(startsWith("/customer/"))
     .willReturn(success("[{\"id\":\"2\",\"number\":\"1234567891\",\"balance\":8000}]", "application/json"))))
 .printSimulationData();
```

在运行测试之前，我们还应该修改`ribbon.listOfServers`配置文件，将其更改为`listOfServers: account-service:8091, account-service:9091`。我们只有在使用 Hoverfly 时才应该进行这样的修改。

这是一个调用`customer-service`暴露的`GET /withAccounts/ {id}`端点的`test`方法，调用次数为一千次。反过来，它调用了`account-service`的`GET customer/{customerId}`端点，带有客户拥有的账户列表。每个请求都使用`WeightedResponseTimeRule`在`account-service`的两个实例之间进行负载均衡：

```java
@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = WebEnvironment.DEFINED_PORT)
public class CustomerControllerTest {

    private static Logger LOGGER = LoggerFactory.getLogger(CustomerControllerTest.class);

    @Autowired
    TestRestTemplate template; 
    // ...

    @Test
    public void testCustomerWithAccounts() {
        for (int i = 0; i < 1000; i++) {
            Customer c = template.getForObject("/withAccounts/{id}", Customer.class, 1);
            LOGGER.info("Customer: {}", c);
        }
    }

}
```

使用加权响应规则实现的工作方法真的很有趣。就在开始测试后，传入的请求在`account-service`的两个实例之间以 50:50 的比例进行了负载均衡。但是，过了一段时间后，大部分请求都被转发到了延迟较小的实例。

最后，在我的本地机器上启动的 JUnit 测试中，端口`9091`上的实例处理了 731 个请求，端口`8091`上的实例处理了 269 个请求。然而，在测试结束时，比例看起来有点不同，并且倾向于延迟较小的实例，其中传入流量在两个实例之间以 4:1 的比例进行了加权。

现在，我们将稍微改变一下我们的测试用例，通过添加一个延迟大约 10 秒的`account-service`的第三个实例。这个改动旨在模拟 HTTP 通信中的超时。以下是 JUnit `@ClassRule`定义中的一个片段，最新的服务实例监听在端口`10091`上：

```java
service("account-service:10091")
    .andDelay(10000, TimeUnit.MILLISECONDS).forAll()
    .get(startsWith("/customer/"))
    .willReturn(success("[{\"id\":\"3\",\"number\":\"1234567892\",\"balance\":10000}]", "application/json"))
```

我们应该相应地在 Ribbon 配置中进行更改，以启用对`account-service`最新实例的负载均衡：

```java
listOfServers: account-service:8091, account-service:9091, account-service:10091
```

最后一个需要更改的东西，但在之前的测试用例中保持不变，就是`RestTemplate`bean 的声明。在这个实例中，我将读取和连接超时都设置为 1 秒，因为测试中启动的`account-service`的第三个实例延迟了 10 秒。每发送一个请求都会在 1 秒后因超时而终止：

```java
@LoadBalanced
@Bean
RestTemplate restTemplate(RestTemplateBuilder restTemplateBuilder) {
    return restTemplateBuilder
        .setConnectTimeout(1000)
        .setReadTimeout(1000)
        .build();
}
```

如果您像以前那样运行相同的测试，结果将不令人满意。所有声明的实例之间的分布将是 420，由端口`8091`上的实例处理（延迟 200 毫秒），468，由端口`9091`上的实例处理（延迟 50 毫秒），而 112 发送到第三个实例，由超时终止。我为什么引用这些统计数据？我们可以将默认负载均衡规则从`WeightedResponseTimeRule`更改为`AvailabilityFilteringRule`，并重新运行测试。如果我们这样做，496 个请求将发送给第一个和第二个实例，而只有 8 个请求将发送给第三个实例，有一个 1 秒的超时。有趣的是，如果您将`BestAvailableRule`设置为默认规则，所有请求都将发送到第一个实例。

现在您阅读了此示例，可以轻松地看到 Ribbon 客户端所有可用负载均衡规则之间的区别。

# 自定义 Ribbon 客户端

Ribbon 客户端的几个配置设置可以通过 Spring bean 声明来覆盖。与 Feign 一样，它应该在名为 configuration 的客户端注解字段中声明，例如，`@RibbonClient(name = "account-service", configuration = RibbonConfiguration.class)`。使用这种方法可以自定义以下功能：

+   `IClientConfig`：此接口的默认实现是`DefaultClientConfigImpl`。

+   `IRule`：此组件用于从列表中确定应选择哪个服务实例。`ZoneAvoidanceRule`实现类是自动配置的。

+   `IPing`：这是一个在后台运行的组件。它负责确保服务实例正在运行。

+   `ServerList<Server>`：这可以是静态的或动态的。如果是动态的（如`DynamicServerListLoadBalancer`所使用），后台线程将在预定义的间隔刷新和过滤列表。默认情况下，Ribbon 使用从配置文件中获取的服务器静态列表。它由`ConfigurationBasedServerList`实现。

+   `ServerListFilter<Server>`：`ServerListFilter`是`DynamicServerListLoadBalancer`用来过滤`ServerList`实现返回的服务器的组件。该接口有两个实现——自动配置的`ZonePreferenceServerListFilter`和`ServerListSubsetFilter`。

+   `ILoadBalancer`：此组件负责在客户端侧对服务的可用实例进行负载均衡。默认情况下，Ribbon 使用`ZoneAwareLoadBalancer`。

+   `ServerListUpdater`：它负责更新给定应用程序可用的实例列表。默认情况下，Ribbon 使用 `PollingServerListUpdater`。

让我们来看一个定义 `IRule` 和 `IPing` 组件默认实现的配置类示例。这样的配置可以定义为单个 Ribbon 客户端，也可以定义为应用程序类路径中可用的所有 Ribbon 客户端，通过提供 `@RibbonClients(defaultConfiguration = RibbonConfiguration.class)` 注解来实现：

```java
@Configuration
public class RibbonConfiguration {

    @Bean
    public IRule ribbonRule() {
        return new WeightedResponseTimeRule();
    }

    @Bean
    public IPing ribbonPing() {
        return new PingUrl();
    }

}
```

即使你没有 Spring 的经验，你可能也已经猜到（根据之前的示例），配置也可以通过使用 `properties` 文件进行自定义。在这种情况下，Spring Cloud Netflix 与 Netflix 提供的 Ribbon 文档中描述的属性兼容。以下类是支持的属性，它们应该以 `<clientName>.ribbon` 开头，或者如果它们适用于所有客户端，以 `ribbon` 开头：

+   `NFLoadBalancerClassName`：`ILoadBalancer` 默认实现类

+   `NFLoadBalancerRuleClassName`：`IRule` 默认实现类

+   `NFLoadBalancerPingClassName`：`IPing` 默认实现类

+   `NIWSServerListClassName`：`ServerList` 默认实现类

+   `NIWSServerListFilterClassName`：`ServerListFilter` 默认实现类

以下是一个与前面 `@Configuration` 类相似的示例，它覆盖了 Spring Cloud 应用程序使用的 `IRule` 和 `IPing` 默认实现：

```java
account-service:
 ribbon:
   NFLoadBalancerPingClassName: com.netflix.loadbalancer.PingUrl
   NFLoadBalancerRuleClassName: com.netflix.loadbalancer.WeightedResponseTimeRule
```

# Hystrix 电路断路器模式

我们已经讨论了 Spring Cloud Netflix 中负载均衡算法的不同实现。其中一些是基于监控实例响应时间或失败次数。在这些情况下，负载均衡器根据这些统计数据来决定调用哪个实例。电路断路器模式应被视为该解决方案的扩展。电路断路器背后的主要想法非常简单。一个受保护的函数调用被包装在一个电路断路器对象中，该对象负责监控失败调用次数。如果失败次数达到阈值，电路将打开，所有后续调用都将自动失败。通常，如果电路断路器触发，也希望有一种监控警报。应用程序中使用电路断路器模式的一些关键好处是，当相关服务失败时能够继续运行，防止级联失败，并给失败的服务时间来恢复。

# 使用 Hystrix 构建应用程序

Netflix 在他们的库中提供了一个名为 **Hystrix** 的断路器模式的实现。这个库也被作为 Spring Cloud 的默认断路器实现。Hystrix 还有一些其他有趣的特性，也应该被视为一个用于处理分布式系统延迟和容错的综合工具。重要的是，如果打开断路器，Hystrix 将所有调用重定向到指定的回退方法。回退方法被设计为提供一个不依赖于网络的通用响应，通常从内存缓存中读取或简单实现为静态逻辑。如果需要执行网络调用，建议您使用另一个 `HystrixCommand` 或 `HystrixObservableCommand` 来实现。为了在您的项目中包含 Hystrix，您应该使用 `spring-cloud-starter-netflix-hystrix` 或 `spring-cloud-starter-hystrix` 作为 Spring Cloud Netflix 1.4.0 版本之前的启动器：

```java
<dependency>
    <groupId>org.springframework.cloud</groupId>
    <artifactId>spring-cloud-starter-hystrix</artifactId>
</dependency>
```

# 实现 Hystrix 的命令

Spring Cloud Netflix Hystrix 会寻找带有 `@HystrixCommand` 注解的方法，然后将其包装在连接到断路器的代理对象中。正因为如此，Hystrix 能够监控这类方法的所有的调用。这个注解目前只对标记有 `@Component` 或 `@Service` 的类有效。这对我们来说是很重要的信息，因为我们已经在带有 `@RestController` 注解的 REST 控制器类中实现了与其它服务调用相关的所有逻辑。所以，在 `customer-service` 应用程序中，所有那部分逻辑都被移动到了新创建的 `CustomerService` 类中，然后将其注入到控制器 bean 中。负责与 `account-service` 通信的方法已经被标记为 `@HystrixCommand`。我还实现了一个回退方法，其名称传递到 `fallbackMethod` 注解的字段中。这个方法只返回一个空列表：

```java
@Service
public class CustomerService {

    @Autowired
    RestTemplate template;
    @Autowired
    CustomerRepository repository;
    // ...

    @HystrixCommand(fallbackMethod = "findCustomerAccountsFallback")
    public List<Account> findCustomerAccounts(Long id) {
        Account[] accounts = template.getForObject("http://account-service/customer/{customerId}", Account[].class, id);
        return Arrays.stream(accounts).collect(Collectors.toList());
    }

    public List<Account> findCustomerAccountsFallback(Long id) {
        return new ArrayList<>();
    }

}
```

不要忘记用`@EnableHystrix`标记你的主类，这是告诉 Spring Cloud 应该为应用程序使用断路器所必需的。我们也可以选择性地用`@EnableCircuitBreaker`注解一个类，它也能起到同样的作用。为了测试目的，`account-service.ribbon.listOfServers`属性应该包含`localhost:8091, localhost:9091`服务两个实例的网络地址。虽然我们为 Ribbon 客户端声明了两个`account-service`实例，但我们将在`8091`端口上启动唯一可用的一个。如果你调用`customer-service`方法的`GET http://localhost:8092/withAccounts/{id}`，Ribbon 将尝试将在两个声明的实例之间平衡每个传入请求，即，一旦你收到包含账户列表的响应，第二次收到空账户列表，或相反。以下应用日志的片段说明了这一点。以下是对应用日志的一个片段。要访问示例应用程序的源代码，你应该切换到与前章示例相同的 GitHub 仓库中的`hystrix_basic`分支：（https://github.com/piomin/sample-spring-cloud-comm/tree/hystrix_basic）

```java
{"id":1,"name":"John Scott","type":"NEW","accounts":[]}
{"id":1,"name":"John Scott","type":"NEW","accounts":[{"id":1,"number":"1234567890","balance":5000},{"id":2,"number":"1234567891","balance":5000},{"id":3,"number":"1234567892","balance":0}]}
```

# 实现带有缓存数据的回退

前面示例中呈现的回退实现非常简单。对于在生产环境中运行的应用程序来说，返回一个空列表并没有多大意义。在请求失败时，例如从缓存中读取数据时，在应用程序中使用回退方法更有意义。这样的缓存可以在客户端应用程序内部实现，也可以使用第三方工具实现，如 Redis、Hazelcast 或 EhCache。最简单的实现是在 Spring 框架内部提供的，在将`spring-boot-starter-cache` artifact 包含在依赖项之后可以使用。要为 Spring Boot 应用程序启用缓存，你应该用`@EnableCaching`注解标注主类或配置类，并提供以下上下文中的`CacheManager` bean：

```java
@SpringBootApplication
@RibbonClient(name = "account-service")
@EnableHystrix
@EnableCaching
public class CustomerApplication {

    @LoadBalanced
    @Bean
    RestTemplate restTemplate() {
        return new RestTemplate();
    }

    public static void main(String[] args) {
        new SpringApplicationBuilder(CustomerApplication.class).web(true).run(args);
    }

    @Bean
    public CacheManager cacheManager() {
        return new ConcurrentMapCacheManager("accounts");
    }
    // ...

}
```

然后，你可以使用`@CachePut`注解标记被电路 breaker 包裹的方法。这会将调用方法的返回结果添加到缓存映射中。在这种情况下，我们的映射名为`accounts`。最后，您可以在回退方法实现内部直接调用`CacheManager` bean 来读取数据。如果你多次重试同一个请求，你会看到空账户列表不再作为响应返回。相反，服务总是返回在第一次成功调用期间缓存的数据：

```java
@Autowired
CacheManager cacheManager;
@CachePut("accounts")
@HystrixCommand(fallbackMethod = "findCustomerAccountsFallback")
public List<Account> findCustomerAccounts(Long id) {
    Account[] accounts = template.getForObject("http://account-service/customer/{customerId}", Account[].class, id);
    return Arrays.stream(accounts).collect(Collectors.toList());
}

public List<Account> findCustomerAccountsFallback(Long id) {
    ValueWrapper w = cacheManager.getCache("accounts").get(id);
    if (w != null) {
        return (List<Account>) w.get();
    } else {
    return new ArrayList<>();
    }
}
```

# 触发断路器

让我给你提个练习题。到目前为止，你已经学会了如何使用 Hystrix，结合 Spring Cloud，在应用程序中启用和实现断路器，以及如何使用回退方法从缓存中获取数据。但你还没有使用过触发断路器来防止负载均衡器调用失败实例。现在，我想配置 Hystrix，在失败率超过`30`%的情况下，在三次失败的调用尝试后打开电路，并在接下来的 5 秒钟内防止 API 方法被调用。测量时间窗口大约是`10`秒。为了满足这些要求，我们必须重写几个默认的 Hystrix 配置设置。这可以在`@HystrixCommand`内的`@HystrixProperty`注解中执行。

以下是`customer-service`中获取账户列表方法的当前实现：

```java
@CachePut("accounts")
@HystrixCommand(fallbackMethod = "findCustomerAccountsFallback",
 commandProperties = {
    @HystrixProperty(name = "execution.isolation.thread.timeoutInMilliseconds", value = "500"),
    @HystrixProperty(name = "circuitBreaker.requestVolumeThreshold", value = "10"),
    @HystrixProperty(name = "circuitBreaker.errorThresholdPercentage", value = "30"),
    @HystrixProperty(name = "circuitBreaker.sleepWindowInMilliseconds", value = "5000"),
    @HystrixProperty(name = "metrics.rollingStats.timeInMilliseconds", value = "10000")
 }
)
public List<Account> findCustomerAccounts(Long id) {
    Account[] accounts = template.getForObject("http://account-service/customer/{customerId}", Account[].class, id);
    return Arrays.stream(accounts).collect(Collectors.toList());
}
```

关于 Hystrix 配置属性的完整列表，可以在 Netflix 的 GitHub 网站上找到，网址为[`github.com/Netflix/Hystrix/wiki/Configuration`](https://github.com/Netflix/Hystrix/wiki/Configuration)。我不会讨论所有属性，只讨论微服务间通信最重要的属性。以下是我们在示例中使用的属性列表及其描述：

+   `execution.isolation.thread.timeoutInMilliseconds`：此属性设置在发生读取或连接超时的时间（以毫秒为单位），之后客户端将离开命令执行。Hystrix 将此类方法调用标记为失败，并执行回退逻辑。可以通过将`command.timeout.enabled`属性设置为`false`来完全关闭超时。默认值为 1,000 毫秒。

+   `circuitBreaker.requestVolumeThreshold`：此属性设置在滚动窗口中触发电路的最小请求数量。默认值是 20。在我们的示例中，此属性设置为`10`，这意味着前九个请求不会触发电路，即使它们都失败了。我设置这个值是因为我们假设如果`30`%的传入请求失败，电路应该被打开，但最少传入请求数量是三个。

+   `circuitBreaker.errorThresholdPercentage`：此属性设置最小的错误百分比。超过此百分比将导致打开电路，系统开始短路请求以执行回退逻辑。默认值是 50。我将其设置为`30`，因为在我们示例中，我希望`30`%的失败请求应该打开电路。

+   `circuitBreaker.sleepWindowInMilliseconds`：此属性设置在触发电路和允许尝试以确定是否应再次关闭电路之间的时间间隔。在这段时间内，所有传入请求都被拒绝。默认值是`5,000`。因为我们希望电路打开后在`10`秒内等待第一次调用被退休，所以我将其设置为`10,000`。

+   `metrics.rollingStats.timeInMilliseconds`：这个属性设置了统计滚动窗口的持续时间，单位为毫秒。Hystrix 就是用这个时间来保持电路断路器使用的指标和发布用的。

使用这些设置，我们可以运行与之前例子相同的 JUnit 测试。我们使用`HoverflyRule`启动两个`account-service`的存根。其中的第一个会被延迟 200 毫秒，而第二个延迟 2000 毫秒的会超过`@HystrixCommand`中`execution.isolation.thread.timeoutInMilliseconds`属性的设置。运行 JUnit`CustomerControllerTest`后，查看打印的日志。我插入了我机器上运行的测试的日志。`customer-service`的第一个请求会被负载均衡到第一个延迟 200 毫秒的实例`(1)`。发送到`9091`端口可用的实例的每个请求，在一秒后都会超时完成。在发送 10 个请求后，第一个失败触发了电路的断开`(2)`。然后，在接下来的 10 秒内，每个请求都由回退方法处理，返回缓存数据`(3)`、`(4)`。10 秒后，客户端再次尝试调用`account-service`的实例并成功`(5)`，因为它击中了延迟 200 毫秒的实例。这次成功导致电路关闭。不幸的是，`account-service`的第二个实例仍然响应缓慢，所以整个场景再次重演，直到 JUnit 测试结束`(6)`和`(7)`。这个详细的描述准确地展示了 Spring Cloud 中的 Hystrix 电路断路器是如何工作的：

```java
16:54:04+01:00 Found response delay setting for this request host: {account-service:8091 200} // (1)
16:54:05+01:00 Found response delay setting for this request host: {account-service:9091 2000}
16:54:05+01:00 Found response delay setting for this request host: {account-service:8091 200}
16:54:06+01:00 Found response delay setting for this request host: {account-service:9091 2000}
16:54:06+01:00 Found response delay setting for this request host: {account-service:8091 200}
...
16:54:09+01:00 Found response delay setting for this request host: {account-service:9091 2000} // (2)
16:54:10.137 Customer [id=1, name=John Scott, type=NEW, accounts=[Account [id=1, number=1234567890, balance=5000]]] // (3)
...
16:54:20.169 Customer [id=1, name=John Scott, type=NEW, accounts=[Account [id=1, number=1234567890, balance=5000]]] // (4)
16:54:20+01:00 Found response delay setting for this request host: {account-service:8091 200} // (5)
16:54:20+01:00 Found response delay setting for this request host: {account-service:9091 2000}
16:54:21+01:00 Found response delay setting for this request host: {account-service:8091 200}
...
16:54:25+01:00 Found response delay setting for this request host: {account-service:8091 200} // (6)
16:54:26.157 Customer [id=1, name=John Scott, type=NEW, accounts=[Account [id=1, number=1234567890, balance=5000]]] // (7)
```

# 监控延迟和容错

如我前面所提到的，Hystrix 不仅仅是一个实现断路器模式的简单工具。它是一个解决方案，用于处理分布式系统中的延迟和容错。Hystrix 提供的一个有趣功能是可以暴露与服务间通信相关的最重要的指标，并通过 UI 仪表板显示出来。这个功能适用于用 Hystrix 命令包装的客户端。

在之前的某些示例中，我们分析了我们系统的一部分，以模拟`customer-service`和`account-service`之间的通信延迟。当测试高级负载均衡算法或不同的断路器配置设置时，这是一种非常好的方法，但现在我们将回到分析我们示例系统的整体设置，作为一个独立的 Spring Boot 应用程序集合。这使我们能够观察到 Spring Cloud 与 Netflix OSS 工具结合在一起，如何帮助我们监控和响应微服务之间的通信延迟问题和故障。示例系统以一种简单的方式模拟了一个故障。它有一个静态配置，包含了两个实例`account-service`和`product-service`的网络地址，但每个服务只运行一个实例。

为了使您记忆犹新，以下是我们样本系统的架构，考虑到关于失败的假设：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/ce848d7e-8834-48f2-885f-273126e8aa5c.png)

这次，我们将以一种稍微不同方式开始，进行一个测试。以下是正在循环调用测试方法的片段。首先，它调用来自`order-service`的`POST http://localhost:8090/`端点，发送一个`Order`对象，并收到具有`id`、`status`和`price`设置的响应。在该请求中，如前一个图中所标记的`(1)`，`order-service`与`product-service`和`customer-service`通信，并且，除此之外，`customer-service`调用来自`account-service`的端点。如果订单被接受，测试客户端调用`PUT http://localhost:8090/{id}`方法，带有订单的`id`来接受它并从账户中提取资金。在服务器端，在那情况下只有一次服务间通信，如前一个图中所标记的`(2)`。在运行这个测试之前，你必须启动我们系统中的所有微服务：

```java
Random r = new Random();
Order order = new Order();
order.setCustomerId((long) r.nextInt(3)+1);
order.setProductIds(Arrays.asList(new Long[] {(long) r.nextInt(10)+1,(long) r.nextInt(10)+1}));
order = template.postForObject("http://localhost:8090", order, Order.class); // (1)
if (order.getStatus() != OrderStatus.REJECTED) {
    template.put("http://localhost:8090/{id}", null, order.getId()); // (2)
}
```

# 暴露 Hystrix 的指标流

每个使用 Hystrix 在与其他微服务通信中可能暴露每个封装在 Hystrix 命令中的集成指标的微服务。要启用这样的指标流，你应该包括对`spring-boot-starter-actuator`的依赖。这将把`/hystrix.stream`对象作为管理端点暴露出来。还需要包括`spring-cloud-starter-hystrix`，这已经添加到我们的示例应用程序中：

```java
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-actuator</artifactId>
</dependency>
```

生成的流作为进一步的 JSON 条目暴露，包含描述单一调用内方法的指标。以下是来自`customer-service`的`GET /withAccounts/{id}`方法的一个调用条目：

```java
{"type":"HystrixCommand","name":"customer-service.findWithAccounts","group":"CustomerService","currentTime":1513089204882,"isCircuitBreakerOpen":false,"errorPercentage":0,"errorCount":0,"requestCount":74,"rollingCountBadRequests":0,"rollingCountCollapsedRequests":0,"rollingCountEmit":0,"rollingCountExceptionsThrown":0,"rollingCountFailure":0,"rollingCountFallbackEmit":0,"rollingCountFallbackFailure":0,"rollingCountFallbackMissing":0,"rollingCountFallbackRejection":0,"rollingCountFallbackSuccess":0,"rollingCountResponsesFromCache":0,"rollingCountSemaphoreRejected":0,"rollingCountShortCircuited":0,"rollingCountSuccess":75,"rollingCountThreadPoolRejected":0,"rollingCountTimeout":0,"currentConcurrentExecutionCount":0,"rollingMaxConcurrentExecutionCount":1,"latencyExecute_mean":5,"latencyExecute":{"0":0,"25":0,"50":0,"75":15,"90":16,"95":31,"99":47,"99.5":47,"100":62},"latencyTotal_mean":5,"latencyTotal":{"0":0,"25":0,"50":0,"75":15,"90":16,"95":31,"99":47,"99.5":47,"100":62},"propertyValue_circuitBreakerRequestVolumeThreshold":10,"propertyValue_circuitBreakerSleepWindowInMilliseconds":10000,"propertyValue_circuitBreakerErrorThresholdPercentage":30,"propertyValue_circuitBreakerForceOpen":false,"propertyValue_circuitBreakerForceClosed":false,"propertyValue_circuitBreakerEnabled":true,"propertyValue_executionIsolationStrategy":"THREAD","propertyValue_executionIsolationThreadTimeoutInMilliseconds":2000,"propertyValue_executionTimeoutInMilliseconds":2000,"propertyValue_executionIsolationThreadInterruptOnTimeout":true,"propertyValue_executionIsolationThreadPoolKeyOverride":null,"propertyValue_executionIsolationSemaphoreMaxConcurrentRequests":10,"propertyValue_fallbackIsolationSemaphoreMaxConcurrentRequests":10,"propertyValue_metricsRollingStatisticalWindowInMilliseconds":10000,"propertyValue_requestCacheEnabled":true,"propertyValue_requestLogEnabled":true,"reportingHosts":1,"threadPool":"CustomerService"}
```

# Hystrix 仪表板

Hystrix 仪表板可视化了以下信息：

+   健康和流量体积以一个随着传入统计数据变化而改变颜色和大小的圆形显示

+   过去 10 秒内的错误百分比

+   过去两分钟内的请求速率，通过数字显示结果在图表上

+   断路器状态（开启/关闭）

+   服务主机数量

+   过去一分钟内的延迟百分比

+   服务的线程池

# 构建带有仪表板的应用程序

Hystrix 仪表板与 Spring Cloud 集成。在系统内实现仪表板的最佳方法是将仪表板分离为一个独立的 Spring Boot 应用程序。要将在项目中包含 Hystrix 仪表板，请使用`spring-cloud-starter-hystrix-netflix-dashboard`启动器或对于旧于 1.4.0 的 Spring Cloud Netflix 版本使用`spring-cloud-starter-hystrix-dashboard`：

```java
<dependency>
    <groupId>org.springframework.cloud</groupId>
    <artifactId>spring-cloud-starter-hystrix-dashboard</artifactId>
</dependency>
```

应用程序的主类应使用`@EnableHystrixDashboard`注解。启动后，Hystrix 仪表板在`/hystrix`上下文路径下可用：

```java
@SpringBootApplication
@EnableHystrixDashboard
public class HystrixApplication {

    public static void main(String[] args) {
        new SpringApplicationBuilder(HystrixApplication.class).web(true).run(args);
    }

}
```

我在我们示例系统中的 Hystrix 应用程序中配置了端口`9000`作为默认端口，该应用程序在`hystrix-dashboard`模块中实现。所以，在启动`hystrix-dashboard`后，用网络浏览器调用`http://localhost:9000/hystrix`地址，它会显示如下截图中的页面。在那里，您应提供 Hystrix 流端点的地址，可选提供一个标题。如果您想要为从`order-service`调用所有端点显示指标，请输入地址`http://localhost:8090/hystrix.stream`，然后点击监控流按钮：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/0aa6b722-29ff-47e5-a8f4-34ea62bc2944.png)

# 在仪表板上监控指标

在本节中，我们将查看从`customer-service`调用`GET /withAccounts/{id}`方法。它被包裹在`@HystrixCommand`中。它显示在 Hystrix 仪表板上，标题为`customer-service.findWithAccounts`，来自一个`commandKey`属性。此外，UI 仪表板还显示了分配给每个提供 Hystrix 命令封装方法实现的 Spring Bean 的线程池信息。在此案例中，它是`CustomerService`：

```java
@Service
public class CustomerService {

    // ...
    @CachePut("customers")
    @HystrixCommand(commandKey = "customer-service.findWithAccounts", fallbackMethod = "findCustomerWithAccountsFallback",
        commandProperties = {
            @HystrixProperty(name = "execution.isolation.thread.timeoutInMilliseconds", value = "2000"),
            @HystrixProperty(name = "circuitBreaker.requestVolumeThreshold", value = "10"),
            @HystrixProperty(name = "circuitBreaker.errorThresholdPercentage", value = "30"),
            @HystrixProperty(name = "circuitBreaker.sleepWindowInMilliseconds", value = "10000"),
            @HystrixProperty(name = "metrics.rollingStats.timeInMilliseconds", value = "10000")
        })
    public Customer findCustomerWithAccounts(Long customerId) {
        Customer customer = template.getForObject("http://customer-service/withAccounts/{id}", Customer.class, customerId);
        return customer;
    }

    public Customer findCustomerWithAccountsFallback(Long customerId) {
        ValueWrapper w = cacheManager.getCache("customers").get(customerId);
        if (w != null) {
            return (Customer) w.get();
        } else {
            return new Customer();
        }
    }

}
```

这是 Hystrix 仪表板在 JUnit 测试开始后的屏幕。我们监控了三个用`@HystrixCommand`包裹的方法的状态。`product-service`的`findByIds`方法的电路如预期般已被打开。几秒钟后，`account-service`的`withdraw`方法的电路也已打开：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/fe9084d4-8482-4bd7-aad2-470cd1af41ad.png)

片刻之后，情况将稳定下来。所有电路都保持关闭状态，因为只有少量的流量被发送到应用程序的不活动实例。这展示了 Spring Cloud 结合 Hystrix 和 Ribbon 的力量。系统能够自动重新配置自己，以便基于负载均衡器和断路器生成的指标，将大部分传入请求重定向到工作实例：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/9a1a4f33-d388-46a9-a060-05d87303eb6c.png)

# 使用 Turbine 聚合 Hystrix 的流

您可能已经注意到，我们在 Hystrix 仪表板上只能查看服务的一个实例。当我们显示`order-service`命令的状态时，没有从`customer-service`和`account-service`之间的通信指标，反之亦然。我们可能还会想象`order-service`有不止一个实例在运行，这使得在 Hystrix 仪表板上定期切换不同的实例或服务变得必要。幸运的是，有一个名为**Turbine**的应用程序可以将所有相关的`/hystrix.stream`端点聚合到一个组合的`/turbine.stream`中，使我们能够监控整个系统的整体健康状况。

# 启用 Turbine

在为我们的应用程序启用 Turbine 之前，我们首先应该启用服务发现，这是在这里必需的。切换到`hystrix_with_turbine`分支，以访问支持通过 Eureka 进行服务发现并使用 Turbine 聚合 Hystrix 流的一个版本我们的示例系统。要为项目启用 UI 仪表板，只需在依赖项中包含`spring-cloud-starter-turbine`，并用`@EnableTurbine`注解主应用类：

```java
<dependency>
    <groupId>org.springframework.cloud</groupId>
    <artifactId>spring-cloud-starter-turbine</artifactId>
</dependency>
```

`turbine.appConfig`配置属性是 Turbine 将要查找实例的 Eureka 服务名称列表。然后，在`http://localhost:9000/turbine.stream` URL 下，Hystrix 仪表板中的 Turbine 流即可使用。地址也由`turbine.aggregator.clusterConfig`属性的值决定，`http://localhost:9000/turbine.stream?cluster=<clusterName>`。如果集群名称为`default`，则可以省略集群参数。以下 Turbine 配置将所有 Hystrix 的可视化指标整合到单个 UI 仪表板上：

```java
turbine:
 appConfig: order-service,customer-service
   clusterNameExpression: "'default'"
```

现在，整个示例系统的所有 Hystrix 指标都可以在一个仪表板网站上显示出来。要显示它们，我们只需要监控位于`http://localhost:9000/turbine.stream`下的统计流：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/1426d797-14f8-4198-8bc0-0090718a565c.png)

另外，我们可以为每个服务配置一个集群，通过提供`turbine.aggregator.clusterConfig`属性的服务列表来实现。在这种情况下，您可以通过提供服务名称`cluster`以及`http://localhost:9000/turbine.stream?cluster=ORDER-SERVICE`参数，在集群之间进行切换。因为 Eureka 服务器返回的值是大写的，所以集群名称必须是大写的：

```java
turbine:
  aggregator:
    clusterConfig: ORDER-SERVICE,CUSTOMER-SERVICE
  appConfig: order-service,customer-service
```

默认情况下，Turbine 在其 Eureka 注册实例的`homePageUrl`地址下寻找`/hystrix.stream`端点。然后，它在该 URL 后附加`/hystrix.stream`。我们的示例应用`order-service`在端口`8090`上启动，因此我们应该也覆盖默认的管理端口为`8090`。下面是`order-service`的当前配置代码片段。另外，您还可以通过`eureka.instance.metadata-map.management.port`属性来更改端口：

```java
spring: 
 application:
   name: order-service 

server:
 port: ${PORT:8090} 

eureka:
 client:
   serviceUrl:
     defaultZone: ${EUREKA_URL:http://localhost:8761/eureka/}

management:
 security:
   enabled: false
     port: 8090
```

# 启用 Turbine 流式处理

经典 Turbine 模型从所有分布式 Hystrix 命令中提取指标，并不总是一个好的选择。例如，收集 HTTP 端点的指标也可以通过消息代理异步实现。要使 Turbine 支持流式处理，我们应该在项目中包含以下依赖项，然后用`@EnableTurbineStream`注解主应用。下面的示例使用 RabbitMQ 作为默认消息代理，但您可以通过包含`spring-cloud-starter-stream-kafka`来使用 Apache Kafka：

```java
<dependency>
 <groupId>org.springframework.cloud</groupId>
 <artifactId>spring-cloud-starter-turbine-stream</artifactId>
</dependency>
<dependency>
 <groupId>org.springframework.cloud</groupId>
 <artifactId>spring-cloud-starter-stream-rabbit</artifactId>
</dependency>
```

前面代码中可见的依赖项应该包含在服务器端。对于客户端应用程序，这些是`order-service`和`customer-service`，我们还需要添加`spring-cloud-netflix-hystrix-stream`库。如果你在本地运行了消息代理，它应该在自动配置的设置上成功工作。你也可以使用 Docker 容器运行 RabbitMQ，正如我们在第五章中描述的 Spring Cloud Config 与 AMQP 总线一样，*分布式配置与 Spring Cloud Config*。然后，你应该在客户端和服务器端应用程序的`application.yml`文件中覆盖以下属性：

```java
spring:
 rabbitmq:
   host: 192.168.99.100
   port: 5672
   username: guest
   password: guest
```

如果你登录到 RabbitMQ 管理控制台，该控制台可通过`http://192.168.99.100:15672`访问，你会看到在我们的示例应用程序启动后创建了一个名为`springCloudHystrixStream`的新交换机。现在，剩下要做的就是运行与之前部分中描述的经典 Turbine 方法的示例相同的 JUnit 测试。所有指标都通过消息代理发送，并可以在`http://localhost:9000`端点下观察。如果你想要亲自尝试，请切换到`hystrix_with_turbine_stream`分支（更多信息请参见[`github.com/piomin/sample-spring-cloud-comm/tree/hystrix_with_turbine_stream`](https://github.com/piomin/sample-spring-cloud-comm/tree/hystrix_with_turbine_stream)）。

# 使用 Feign 的失败和断路器模式

默认情况下，Feign 客户端与 Ribbon 和 Hystrix 集成。这意味着，如果你愿意，你可以在使用该库时应用不同的方法来处理系统的延迟和超时。这些方法中的第一种是由 Ribbon 客户端提供的连接重试机制。第二种是在 Hystrix 项目中提供的断路器模式和回退实现，这在本书的上一节中已经讨论过了。

# 使用 Ribbon 重试连接

当使用 Feign 库时，应用程序默认启用 Hystrix。这意味着如果你不想使用它，你应该在配置设置中禁用它。为了测试带有 Ribbon 的重试机制，我建议你禁用 Hystrix。为了使 Feign 具有连接重试功能，你只需要设置两个配置属性—`MaxAutoRetries`和`MaxAutoRetriesNextServer`。在此情况下，重要的设置还包括`ReadTimeout`和`ConnectTimeout`。它们都可以在`application.yml`文件中覆盖。以下是 Ribbon 设置中最重要的一些：

+   `MaxAutoRetries`：这是在同一服务器或服务实例上进行重试的最大次数。第一次尝试不包括在内。

+   `MaxAutoRetriesNextServer`：这是要重试的最大下一个服务器或服务实例次数，不包括第一个服务器。

+   `OkToRetryOnAllOperations`：这表示此客户端的所有操作都可以重试。

+   `ConnectTimeout`：这是等待与服务器或服务实例建立连接的最大时间。

+   `ReadTimeout`：这是在建立连接后等待服务器响应的最大时间。

假设我们有一个目标服务的两个实例。第一个实例的连接已经建立，但它响应太慢并且发生了超时。根据`MaxAutoRetries=1`属性，客户端对该实例进行一次重试。如果仍然不成功，它尝试连接该服务的第二个可用实例。在失败的情况下，这一动作根据`MaxAutoRetriesNextServer=2`属性重复两次。如果描述的机制最终*不成功*，超时将被返回到外部客户端。在这种情况下，即使在四秒以上之后也可能会发生。请查看以下配置：

```java
ribbon:
 eureka:
   enabled: true
 MaxAutoRetries: 1
 MaxAutoRetriesNextServer: 2
 ConnectTimeout: 500
 ReadTimeout: 1000

feign:
 hystrix:
   enabled: false
```

这个解决方案是为微服务环境实现的标准重试机制。我们还可以看看与 Ribbon 的超时和重试不同配置设置相关的其他场景。我们没有理由不使用这个机制与 Hystrix 的断路器一起。然而，我们必须记住`ribbon.ReadTimeout`应该小于 Hystrix 的`execution.isolation.thread.timeoutInMilliseconds`属性的值。

我建议您测试我们刚才描述的配置设置作为一个练习。您可以使用之前介绍的 Hoverfly JUnit 规则来模拟服务实例的延迟和存根。

# Hystrix 对 Feign 的支持

首先，我想重申一下，当使用 Feign 库时，Hystrix 默认对应用程序是启用的，但只适用于 Spring Cloud 的旧版本。根据最新版本 Spring Cloud 的文档，我们应该将`feign.hystrix.enabled`属性设置为`true`，这强制 Feign 包装所有方法为一个断路器。

在 Spring Cloud Dalston 版本之前，如果 Hystrix 在类路径上，Feign 会默认包装所有方法为一个断路器。这一默认行为在 Spring Cloud Dalston 版本中为了采用可选参与方式而改变。

当使用 Hystrix 和 Feign 客户端一起时，提供之前用`@HystrixProperty`在`@HystrixCommand`内部设置的配置属性的最简单方法是通过`application.yml`文件。以下是之前示例的等效配置：

```java
hystrix:
 command:
   default:
     circuitBreaker:
       requestVolumeThreshold: 10
       errorThresholdPercentage: 30
       sleepWindowInMilliseconds: 10000
     execution:
       isolation:
         thread:
           timeoutInMilliseconds: 1000
     metrics:
       rollingStats:
         timeInMilliseconds: 10000
```

Feign 支持回退的表示。要为给定的`@FeignClient`启用回退，我们应该将`fallback`属性设置为提供回退实现的类名。实现类应该被定义为一个 Spring Bean：

```java
@FeignClient(name = "customer-service", fallback = CustomerClientFallback.class)
public interface CustomerClient {

    @CachePut("customers")
    @GetMapping("/withAccounts/{customerId}")
    Customer findByIdWithAccounts(@PathVariable("customerId") Long customerId);

}
```

回退实现基于缓存，并实现了带有`@FeignClient`注解的接口：

```java
@Component
public class CustomerClientFallback implements CustomerClient {

    @Autowired
    CacheManager cacheManager;

    @Override 
    public Customer findByIdWithAccountsFallback(Long customerId) {
        ValueWrapper w = cacheManager.getCache("customers").get(customerId);
        if (w != null) {
            return (Customer) w.get();
        } else {
            return new Customer();
        }
    }

}
```

选择性地，我们可以实现一个`FallbackFactory`类。这种方法有一个很大的优点，它让你能够访问触发回退的原因。要为 Feign 声明一个`FallbackFactory`类，只需在`@FeignClient`内部使用`fallbackFactory`属性：

```java
@FeignClient(name = "account-service", fallbackFactory = AccountClientFallbackFactory.class)
public interface AccountClient {

    @CachePut
    @GetMapping("/customer/{customerId}")
    List<Account> findByCustomer(@PathVariable("customerId") Long customerId); 

}
```

自定义的`FallbackFactory`类需要实现一个`FallbackFactory`接口，该接口声明了一个必须重写的`T create(Throwable cause)`方法：

```java
@Component
public class AccountClientFallbackFactory implements FallbackFactory<AccountClient> {

    @Autowired
    CacheManager cacheManager;

    @Override
    public AccountClient create(Throwable cause) {
        return new AccountClient() {
            @Override
            List<Account> findByCustomer(Long customerId) {
                ValueWrapper w = cacheManager.getCache("accounts").get(customerId);
                if (w != null) {
                    return (List<Account>) w.get();
                } else {
                    return new Customer();
                }
            }
        }
    }
}
```

# 摘要

如果你已经使用自动配置的客户端进行服务间通信，你可能不知道本章中描述的配置设置或工具。然而，我认为即使它们可以在后台运行，甚至可以开箱即用，了解一些高级机制也是值得的。在本章中，我试图通过演示它们如何使用简单示例来让你更接近主题，如负载均衡器、重试、回退或断路器。阅读本章后，你应该能够根据需要在微服务之间的通信中自定义 Ribbon、Hystrix 或 Feign 客户端。你也应该理解在系统中使用它们的何时何地。通过本章，我们结束了关于微服务架构内部核心元素的讨论。现在，我们需要关注的是系统外部的一个重要组件，即网关。它将系统复杂性隐藏在外部客户端之外。


# 第八章：使用 API 网关进行路由和过滤

在本章中，我们将讨论微服务架构中的下一个重要元素——API 网关。在实践中，这并不是我们第一次遇到这个元素。我们已经在第四章，*服务发现*中实现了一个简单的网关模式，以展示如何在 Eureka 中使用分区机制进行服务发现。我们使用了 Netflix 的 Zuul 库，它是一个基于 JVM 的路由和服务器端负载均衡器。Netflix 设计 Zuul 以提供诸如认证、压力和金丝雀测试、动态路由以及活动/活动多区域流量管理等功能。虽然这没有明确说明，但它也在微服务架构中充当网关，并其主要任务是隐藏系统的外部客户端复杂性。

直到现在，Zuul 在 Spring Cloud 框架内部实现 API 网关模式时实际上并没有任何竞争。然而，随着一个名为 Spring Cloud Gateway 的新项目的不断发展，这种情况正在动态变化。它基于 Spring Framework 5、Project Reactor 和 Spring Boot 2.0。该库的最后稳定版本是 1.0.0，但目前正在开发的版本 2.0.0 中有很多关键变化，目前仍处于里程碑阶段。Spring Cloud Gateway 旨在提供一种简单、有效的方式来路由 API 并提供与它们相关的交叉关注点，例如安全性、监控/度量以及弹性。尽管这个解决方案相对较新，但它绝对值得关注。

本章我们将涉及的主题包括：

+   根据 URL 的静态路由和负载均衡

+   将 Zuul 与 Spring Cloud Gateway 集成并实现服务发现

+   使用 Zuul 创建自定义过滤器

+   使用 Zuul 自定义路由配置

+   在路由失败的情况下提供 Hystrix 回退

+   Spring Cloud Gateway 中包含的主要组件的描述——预测器和网关过滤器

# 使用 Spring Cloud Netflix Zuul

Spring Cloud 实现了一个内嵌的 Zuul 代理，以便前端应用程序能够代理调用后端服务。这个特性对于外部客户端来说非常有用，因为它隐藏了系统复杂性，并帮助避免为所有微服务独立管理 CORS 和认证问题。要启用它，你应该用 `@EnableZuulProxy` 注解标注一个 Spring Boot 主类，然后它将传入的请求转发到目标服务。当然，Zuul 与 Ribbon 负载均衡器、Hystrix 断路器以及服务发现集成，例如与 Eureka。

# 构建网关应用程序

让我们回到前一章节的示例，以添加微服务架构的最后一步，API 网关。我们还没有考虑的是外部客户端如何调用我们的服务。首先，我们不希望暴露系统内所有微服务的网络地址。我们还可以在单一位置执行一些操作，例如请求认证或设置跟踪头。解决方案是只共享一个边缘网络地址，该地址将所有传入请求代理到适当的服务。当前示例的系统架构在下图中说明：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/f535ba1e-68e6-4411-9d7d-d75bf828c6bf.png)

为了满足我们当前示例的需求，让我回到前一章节中已经讨论过的项目。它可以在 GitHub 上找到（[`github.com/piomin/sample-spring-cloud-comm.git`](https://github.com/piomin/sample-spring-cloud-comm.git)），在`master`分支中。现在，我们将向该项目添加一个名为`gateway-service`的新模块。第一步是使用 Maven 依赖项包含 Zuul：

```java
<dependency>
    <groupId>org.springframework.cloud</groupId>
    <artifactId>spring-cloud-starter-zuul</artifactId>
</dependency>
```

在 Spring Boot 主类上使用`@EnableZuulProxy`注解后，我们可以继续进行路由配置，该配置位于`application.yml`文件中。默认情况下，Zuul 启动器 artifact 不包含服务发现客户端。路由是使用`url`属性静态配置的，该属性设置为服务的网络地址。现在，如果您启动了所有微服务和网关应用程序，您可以尝试通过网关调用它们。每个服务都可以在为每个路由配置的`path`属性设置的路径下访问，例如，`http://localhost:8080/account/1`将被转发到`http://localhost:8091/1`：

```java
server:
 port: ${PORT:8080}

zuul:
 routes:
  account:
   path: /account/**
   url: http://localhost:8091
  customer:
   path: /customer/**
   url: http://localhost:8092
  order:
   path: /order/**
   url: http://localhost:8090
  product:
   path: /product/**
   url: http://localhost:8093
```

# 与服务发现集成

前面示例中呈现的静态路由配置对于基于微服务的系统来说是不够的。API 网关的主要要求是与服务发现的内置集成。为了使 Zuul 与 Eureka 集成，我们必须在项目依赖项中包含`spring-cloud-starter-eureka`启动器，并通过注释应用程序的主类来启用客户端`@EnableDiscoveryClient`。实际上，让网关自己在发现服务器上注册是没有意义的，它只能获取当前注册的服务列表。因此，我们将通过将`eureka.client.registerWithEureka`属性设置为`false`来禁用该注册。`application.yml`文件中的路由定义非常简单。每个路由的名称映射到 Eureka 中的应用程序服务名称：

```java
zuul:
 routes:
  account-service:
   path: /account/**
  customer-service:
   path: /customer/**
  order-service:
   path: /order/**
  product-service:
   path: /product/**
```

# 自定义路由配置

有一些配置设置，允许我们自定义 Zuul 代理的行为。其中一些与服务发现集成密切相关。

# 忽略注册的服务

默认情况下，Spring Cloud Zuul 会暴露 Eureka 服务器中注册的所有服务。如果您想跳过每个服务的自动添加，您必须使用与发现服务器中所有忽略的服务名称匹配的模式设置`zuul.ignored-services`属性。实际工作中它是如何工作的呢？即使您没有提供任何`zuul.routes.*`属性的配置，Zuul 也会从 Eureka 获取服务列表并将它们自动绑定到服务名称的路径下。例如，`account-service`将在网关地址`http://localhost:8080/account-service/**`下可用。现在，如果您在`application.yml`文件中设置了以下配置，它将忽略`account-service`并返回一个 HTTP 404 状态码：

```java
zuul:
  ignoredServices: 'account-service'
```

您还可以通过将`zuul.ignored-services`设置为`'*'`来忽略所有注册的服务。如果一个服务与被忽略的模式匹配，但同时也包含在路由映射配置中，那么 Zuul 将会包含它。在这种情况下，只有`customer-service`会被处理：

```java
zuul:
 ignoredServices: '*'
  routes:
   customer-service: /customer/**
```

# 显式设置服务名称

从发现服务器获取的服务名称也可以在配置中使用`serviceId`属性进行设置。它使你能够对路由进行细粒度控制，因为你可以独立指定路径和`serviceId`。以下是路由的等效配置：

```java
zuul:
  routes:
   accounts:
    path: /account/**
    serviceId: account-service
   customers:
    path: /customer/**
    serviceId: customer-service
   orders:
    path: /order/**
    serviceId: order-service
   products:
    path: /product/**
    serviceId: product-service
```

# 带有 Ribbon 客户端的路由定义

还有另一种配置路由的方法。我们可以禁用 Eureka 发现，以便只依赖于 Ribbon 客户端提供的`listOfServers`属性的网络地址列表。网关的所有传入请求默认通过 Ribbon 客户端在所有服务实例之间进行负载均衡。即使您启用了或禁用了服务发现，以下示例代码也是正确的：

```java
zuul:
 routes:
  accounts:
   path: /account/**
   serviceId: account-service

ribbon:
 eureka:
  enabled: false

account-service:
 ribbon:
  listOfServers: http://localhost:8091,http://localhost:9091
```

# 为路径添加前缀

有时，为了让通过网关调用的服务设置不同的路径，而不是直接可用，这是必要的。在这种情况下，Zuul 提供了为所有定义的映射添加前缀的能力。这可以通过`zuul.prefix`属性轻松配置。默认情况下，Zuul 在将请求转发给服务之前截断该前缀。然而，通过将`zuul.stripPrefix`属性设置为`false`，可以禁用这种行为。`stripPrefix`属性不仅可以为所有定义的路由全局配置，还可以为每个单独的路由配置。

以下示例为所有转发请求添加了`/api`前缀。现在，例如，如果您想从`account-service`调用`GET /{id}`端点，您应该使用地址`http://localhost:8080/api/account/1`：

```java
zuul:
 prefix: /api
 routes:
   accounts:
    path: /account/**
    serviceId: account-service
   customers:
    path: /customer/**
    serviceId: customer-service
```

如果我们提供了`stripPrefix`设置为`false`的配置会发生什么？Zuul 将尝试在目标服务的上下文路径`/api/account`和`/api/customer`下查找端点：

```java
zuul:
 prefix: /api
 stripPrefix: false
```

# 连接设置和超时

**Spring Cloud Netflix Zuul 的主要任务**是将传入请求路由到下游服务。因此，它必须使用一个 HTTP 客户端实现与这些服务的通信。Zuul 目前默认使用的 HTTP 客户端是由 Apache HTTP Client 支持的，而不是已被弃用的 Ribbon `RestClient`。如果你想要使用 Ribbon，你应该将`ribbon.restclient.enabled`属性设置为`true`。你也可以通过将`ribbon.okhttp.enabled`属性设置为`true`来尝试`OkHttpClient`。

我们可以为 HTTP 客户端配置基本设置，如连接或读取超时以及最大连接数。根据我们是否使用服务发现，此类配置有两大选项。如果你通过`url`属性定义了具有指定网络地址的 Zuul 路由，那么你应该设置`zuul.host.connect-timeout-millis`和`zuul.host.socket-timeout-millis`。为了控制最大连接数，你应该覆盖默认值为`200`的`zuul.host.maxTotalConnections`属性。你也可以通过设置默认值为`20`的`zuul.host.maxPerRouteConnections`属性来定义每个单一路径的最大连接数。

如果 Zuul 配置为从发现服务器获取服务列表，你需要使用与 Ribbon 客户端属性`ribbon.ReadTimeout`和`ribbon.SocketTimeout`相同的超时配置。最大连接数可以通过`ribbon.MaxTotalConnections`和`ribbon.MaxConnectionsPerHost`进行自定义。

# 安全头

如果你在请求中设置了例如`Authorization` HTTP 头，但它没有被转发到下游服务，你可能会有些惊讶。这是因为 Zuul 定义了一个默认的敏感头列表，在路由过程中会移除这些头。这些头包括`Cookie`、`Set-Cookie`和`Authorization`。这一特性是为了与外部服务器通信而设计的。虽然对于同一系统中的服务之间共享头没有反对意见，但出于安全原因，不建议与外部服务器共享。可以通过覆盖`sensitiveHeaders`属性的默认值来自定义这种方法。它可以为所有路由或单个路由全局设置。`sensitiveHeaders`不是一个空的黑名单，所以为了使 Zuul 转发所有头，你应该明确将其设置为空列表：

```java
zuul:
 routes:
  accounts:
   path: /account/**
   sensitiveHeaders:
   serviceId: account-service
```

# 管理端点

Spring Cloud Netflix Zuul 暴露了两个用于监控的额外管理端点：

+   **路由**：打印出定义的路由列表

+   **过滤器**：打印出实现过滤器的列表（自 Spring Cloud Netflix 版本`1.4.0.RELEASE`起可用）

要启用管理端点功能，我们必须（像往常一样）在项目依赖中包含`spring-boot-starter-actuator`。为了测试目的，禁用端点安全是一个好主意，通过将`management.security.enabled`属性设置为`false`。现在，你可以调用`GET /routes`方法，它将打印出我们示例系统的以下 JSON 响应：

```java
{
  "/api/account/**": "account-service",
  "/api/customer/**": "customer-service",
  "/api/order/**": "order-service",
  "/api/product/**": "product-service",
}
```

要获取更多详细信息，必须在`/routes`路径上添加`?format=details`查询字符串。这个选项从 Spring Cloud 版本 1.4.0（Edgware 发布列车）也开始提供。还有一个`POST /route`方法，可以强制刷新当前存在的路由。另外，您可以通过将`endpoints.routes.enabled`设置为`false`来禁用整个端点：

```java
"/api/account/**": {
  "id": "account-service",
  "fullPath": "/api/account/**",
  "location": "account-service",
  "path": "/**",
  "prefix": "/api/account",
  "retryable": false,
  "customSensitiveHeaders": false,
  "prefixStripped": true
}
```

`/filters`端点的响应结果非常有趣。你可以看到 Zuul 网关默认提供了多少种过滤器和过滤器类型。以下是带有选定过滤器的一个响应片段。它包含完整的类名，调用顺序和状态。关于过滤器的更多信息，你可以参考*Zuul 过滤器*部分：

```java
"route": [{
 "class": "org.springframework.cloud.netflix.zuul.filters.route.RibbonRoutingFilter",
 "order": 10,
 "disabled": false,
 "static": true
}, { 
... 
]
```

# 提供 Hystrix 回退

我们可能需要为 Zuul 配置中定义的每个单独的路由提供一个回退响应，以防电路被打开。为此，我们应该创建一个类型为`ZuulFallbackProvider`（目前已被弃用）或`FallbackProvider`的 bean。在这个实现中，我们必须指定路由 ID 模式，以匹配所有应该由回退 bean 处理的路由。第二步是在`fallbackResponse`方法中返回`ClientHttpResponse`接口的实现作为响应。

这是一个简单的回退 bean，它将每个异常映射到 HTTP 状态`200 OK`，并在 JSON 响应中设置`errorCode`和`errorMessage`。仅针对`account-service`路由执行回退。

```java
public class AccountFallbackProvider implements FallbackProvider {

    @Override
    public String getRoute() {
        return "account-service";
    }

    @Override
    public ClientHttpResponse fallbackResponse(Throwable cause) {
        return new ClientHttpResponse() {

            @Override
            public HttpHeaders getHeaders() {
                HttpHeaders headers = new HttpHeaders();
                headers.setContentType(MediaType.APPLICATION_JSON);
                return headers;
            } 

            @Override
            public InputStream getBody() throws IOException {
                AccountFallbackResponse response = new AccountFallbackResponse("1.2", cause.getMessage());
                return new ByteArrayInputStream(new ObjectMapper().writeValueAsBytes(response));
            }

            @Override
            public String getStatusText() throws IOException {
                return "OK";
            } 

            @Override
            public HttpStatus getStatusCode() throws IOException {
                return HttpStatus.OK;
            } 

            @Override
            public int getRawStatusCode() throws IOException {
                return 200;
            } 

            @Override
            public void close() {

            } 
        };
    }
    // ...
}
```

# Zuul 过滤器

如我前面已经提到的，Spring Cloud Zuul 默认提供了一些 bean，这些 bean 是`ZuulFilter`接口的实现。每个内置过滤器都可以通过将`zuul.<SimpleClassName>.<filterType>.disable`属性设置为`true`来禁用。例如，要禁用`org.springframework.cloud.netflix.zuul.filters.post.SendResponseFilter`，你必须设置`zuul.SendResponseFilter.post.disable=true`。

HTTP 过滤机制你可能已经很熟悉了。过滤器动态地拦截请求和响应以转换，或者只是使用，从 HTTP 消息中获取的信息。它可能在 incoming request 或 outgoing response 之前或之后触发。我们可以识别出由 Zuul 为 Spring Cloud 提供的几种类型的过滤器：

+   **预过滤器**：它用于在`RequestContext`中准备初始数据，以在下游过滤器中使用。主要责任是设置路由过滤器所需的信息。

+   **路由过滤器**：它在预过滤器之后调用，负责创建到其他服务的请求。使用它的主要原因是需要适应客户端所需的请求或响应模型。

+   **后过滤器**：最常见的是操作响应。它甚至可以转换响应体。

+   **错误过滤器**：它仅在其他过滤器抛出异常时执行。只有一个内置的错误过滤器实现。如果`RequestContext.getThrowable()`不为空，则执行`SendErrorFilter`。

# 预定义过滤器

如果你用`@EnableZuulProxy`注解主类，Spring Cloud Zuul 会加载`SimpleRouteLocator`和`DiscoveryClientRouteLocator`使用的过滤器 bean。这是作为普通 Spring Bean 安装的一些最重要的实现列表：

+   `ServletDetectionFilter`：这是一个**预过滤器**。它检查请求是否通过 Spring Dispatcher。设置了一个布尔值，键为`FilterConstants.IS_DISPATCHER_SERVLET_REQUEST_KEY`。

+   `FormBodyWrapperFilter`：这是一个**预过滤器**。它解析表单数据并重新编码以供下游请求使用。

+   `PreDecorationFilter`：这是一个**预过滤器**。它根据提供的`RouteLocator`确定路由的位置和方式。它还负责设置与代理相关的头信息。

+   `SendForwardFilter`：这是一个**路由过滤器**。它使用`RequestDispatcher`转发请求。

+   `RibbonRoutingFilter`：这是一个**路由过滤器**。它使用 Ribbon、Hystrix 和外部 HTTP 客户端，如 Apache `HttpClient`、`OkHttpClient`或 Ribbon HTTP 客户端来发送请求。服务 ID 从请求上下文中获取。

+   `SimpleHostRoutingFilter`：这是一个**路由过滤器**。它通过 Apache HTTP 客户端将请求发送到 URL。 URL 在请求上下文中找到。

+   `SendResponseFilter`：这是一个**后过滤器**。它将代理请求的响应写入当前响应。

# 自定义实现

除了默认安装的过滤器之外，我们还可以创建自己的自定义实现。 每个实现都必须实现`ZuulFilter`接口及其四个方法。 这些方法负责设置过滤器的类型（`filterType`）、确定与其他具有相同类型的过滤器执行的顺序（`filterOrder`）、启用或禁用过滤器（`shouldFilter`）以及最后过滤逻辑实现（`run`）。 以下是一个示例实现，它向响应中添加了`X-Response-ID`头：

```java
public class AddResponseIDHeaderFilter extends ZuulFilter {

    private int id = 1;

    @Override
    public String filterType() {
        return "post";
    }

    @Override
    public int filterOrder() {
        return 10;
    }

    @Override
    public boolean shouldFilter() {
        return true;
    }

    @Override
    public Object run() {
        RequestContext context = RequestContext.getCurrentContext();
        HttpServletResponse servletResponse = context.getResponse();
        servletResponse.addHeader("X-Response-ID",
         String.valueOf(id++));
        return null;
    }

}
```

还有很多工作要做。自定义过滤器实现也应该在主类或 Spring 配置类中声明为`@Bean`：

```java
@Bean 
AddResponseIDHeaderFilter filter() {
    return new AddResponseIDHeaderFilter();
}
```

# 使用 Spring Cloud Gateway

围绕 Spring Cloud Gateway 有三个基本概念：

+   **路由**：这是网关的基本构建块。它包括一个用于标识路由的唯一 ID、一个目标 URI、一个断言列表和一个过滤器列表。只有在所有断言都已满足时，才会匹配路由。

+   **断言**：这是在处理每个请求之前执行的逻辑。它负责检测 HTTP 请求的不同属性，如头和参数，是否与定义的 criteria 匹配。实现基于 Java 8 接口`java.util.function.Predicate<T>`。输入类型反过来基于 Spring 的`org.springframework.web.server.ServerWebExchange`。

+   **过滤器**：它们允许修改传入的 HTTP 请求或 outgoing HTTP 响应。它们可以在发送下游请求之前或之后进行修改。路由过滤器针对特定的路由。它们实现 Spring 的`org.springframework.web.server.GatewayFilter`。

# 启用 Spring Cloud Gateway

Spring Cloud Gateway 建立在 Netty 网络容器和 Reactor 框架之上。Reactor 项目和 Spring Web Flux 可以与 Spring Boot 2.0 一起使用。到目前为止，我们使用的是 1.5 版本，因此 parent 项目版本声明不同。目前，Spring Boot 2.0 仍然处于里程碑阶段。以下是继承自`spring-boot-starter-parent`项目的 Maven `pom.xml`片段：

```java
<parent>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-parent</artifactId>
    <version>2.0.0.M7</version>
</parent>
```

与之前的示例相比，我们还需要更改 Spring Cloud 的发布列车。最新可用的里程碑版本是`Finchley.M5`：

```java
<properties>
    <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
    <project.reporting.outputEncoding>UTF-8</project.reporting.outputEncoding>
    <java.version>1.8</java.version>
    <spring-cloud.version>Finchley.M5</spring-cloud.version>
</properties>
<dependencyManagement>
    <dependencies>
        <dependency>
            <groupId>org.springframework.cloud</groupId>
            <artifactId>spring-cloud-dependencies</artifactId>
            <version>${spring-cloud.version}</version>
            <type>pom</type>
            <scope>import</scope>
        </dependency>
    </dependencies>
</dependencyManagement>
```

在设置正确的 Spring Boot 和 Spring Cloud 版本之后，我们终于可以在项目依赖中包含`spring-cloud-starter-gateway`启动器：

```java
<dependency>
    <groupId>org.springframework.cloud</groupId>
    <artifactId>spring-cloud-starter-gateway</artifactId>
</dependency>
```

# 内置断言和过滤器

Spring Cloud Gateway 包括许多内置的路由断言和网关过滤器工厂。每个路由可以通过`application.yml`文件中的配置属性或使用 Fluent Java Routes API 以编程方式定义。可用的断言工厂列表如下表所示。多个工厂可以组合用于单一路由定义，使用逻辑`and`关系。过滤器的集合可以在`application.yml`文件中，在`spring.cloud.gateway.routes`属性下，每个定义的路由的`predicates`属性下进行配置：

| **名称** | **描述** | **示例** |
| --- | --- | --- |
| `After` 路由 | 它接受一个日期时间参数，并匹配在其之后发生的请求 | `After=2017-11-20T...` |
| `Before` 路由 | 它接受一个日期时间参数，并匹配在其之前的请求 | `Before=2017-11-20T...` |
| `Between` 路由 | 它接受两个日期时间参数，并匹配在这些日期之间的请求 | `Between=2017-11-20T..., 2017-11-21T...` |
| `Cookie` 路由 | 它接受一个 cookie 名称和正则表达式参数，在 HTTP 请求的头中找到 cookie，并将其值与提供的表达式匹配 | `Cookie=SessionID, abc.` |
| `Header` 路由 | 它接受头名称和正则表达式参数，在 HTTP 请求的头中找到一个特定的头，并将其值与提供的表达式匹配 | `Header=X-Request-Id, \d+` |
| `Host` 路由 | 它接受一个以`.`分隔符的主机名 ANT 风格模式作为参数，并与`Host`头匹配 | `Host=**.example.org` |
| `Method` 路由 | 它接受一个 HTTP 方法作为参数以进行匹配 | `Method=GET` |
| `Path` 路由 | 它接受一个请求上下文路径模式作为参数 | `Path=/account/{id}` |
| `Query` 路由 | 它接受两个参数——一个必需的参数和一个可选的正则表达式，并与查询参数匹配 | `Query=accountId, 1.` |
| `RemoteAddr` 路由 | 它接受一个 CIDR 表示法的 IP 地址列表，如`192.168.0.1/16`，并与请求的远程地址匹配 | `RemoteAddr=192.168.0.1/16` |

还有几个网关过滤器模式的内置实现。以下表格还提供了可用工厂列表。每个`filters`属性下定义的路线可以在`application.yml`文件的`spring.cloud.gateway.routes`属性下配置过滤器集合：

| **名称** | **描述** | **示例** |
| --- | --- | --- |
| `AddRequestHeader` | 在 HTTP 请求中添加一个头，参数中提供了名称和值 | `AddRequestHeader=X-Response-ID, 123` |
| `AddRequestParameter` | 在 HTTP 请求中添加一个查询参数，参数中提供了名称和值 | `AddRequestParameter=id, 123` |
| `AddResponseHeader` | 在 HTTP 响应中添加一个头，参数中提供了名称和值 | `AddResponseHeader=X-Response-ID, 123` |
| `Hystrix` | 它接受一个参数，该参数是 HystrixCommand 的名称 | `Hystrix=account-service` |
| `PrefixPath` | 在参数中定义的 HTTP 请求路径前添加一个前缀 | `PrefixPath=/api` |
| `RequestRateLimiter` | 它根据三个输入参数限制单个用户的处理请求数量，包括每秒最大请求数、突发容量和一个返回用户键的 bean | `RequestRateLimiter=10, 20, #{@userKeyResolver}` |
| `RedirectTo` | 它接受一个 HTTP 状态和一个重定向 URL 作为参数，将其放入`Location` HTTP 头中以执行重定向 | `RedirectTo=302, http://localhost:8092` |
| `RemoveNonProxyHeaders` | 它从转发请求中移除一些跳过头的头信息，如 Keep-Alive、Proxy-Authenticate 或 Proxy-Authorization | - |
| `RemoveRequestHeader` | 它接受一个头名称作为参数，并将其从 HTTP 请求中移除 | `RemoveRequestHeader=X-Request-Foo` |
| `RemoveResponseHeader` | 它接受一个头名称作为参数，并将其从 HTTP 响应中移除 | `RemoveResponseHeader=X-Response-ID` |
| `RewritePath` | 它接受一个路径正则表达式参数和一个替换参数，然后重写请求路径 | `RewritePath=/account/(?<path>.*), /$\{path}` |
| `SecureHeaders` | 它在响应中添加一些安全头 | - |
| `SetPath` | 它接受一个带有路径模板参数的单参数，并更改请求路径 | `SetPath=/{segment}` |
| `SetResponseHeader` | 它接受名称和值参数，在 HTTP 响应中设置一个头 | `SetResponseHeader=X-Response-ID, 123` |
| `SetStatus` | 它接受一个单独的状态参数，该参数必须是一个有效的 HTTP 状态，并在响应中设置它 | `SetStatus=401` |

这是一个带有两个谓词和两个过滤器设置的简单示例。每个传入的`GET /account/{id}`请求都会被转发到`http://localhost:8080/api/account/{id}`，并包含新的 HTTP 头`X-Request-ID`：

```java
spring:
  cloud:
    gateway:
      routes:
      - id: example_route
        uri: http://localhost:8080
        predicates:
        - Method=GET
        - Path=/account/{id}
        filters:
        - AddRequestHeader=X-Request-ID, 123
        - PrefixPath=/api

```

相同的配置可以使用定义在`Route`类中的流利 API 提供。这种风格给我们更多的灵活性。虽然使用 YAML 可以组合使用逻辑`and`的谓词，但流利 Java API 允许你在`Predicate`类上使用`and()`、`or()`和`negate()`操作符。以下是使用流利 API 实现的替代路由：

```java
@Bean
public RouteLocator customRouteLocator(RouteLocatorBuilder routeBuilder) {
    return routeBuilder.routes()
        .route(r -> r.method(HttpMethod.GET).and().path("/account/{id}")
            .addRequestHeader("X-Request-ID", "123").prefixPath("/api")
            .uri("http://localhost:8080"))
        .build();
}
```

# 微服务网关

让我们回到我们的基于微服务的系统示例。我们已经在基于 Spring Cloud Netflix Zuul 的 API 网关配置部分讨论了这个示例。我们希望能够为基于 Zuul 代理的应用程序准备相同的静态路由定义。然后，每个服务都可以在网关地址和特定路径下可用，例如`http://localhost:8080/account/**`。使用 Spring Cloud Gateway 声明此类配置的最合适方式是通过路径路由谓词工厂和重写路径网关过滤器工厂。重写路径机制通过取其一部分或添加某些模式来改变请求路径。在我们的案例中，每个传入的请求路径都被重写，例如，从`account/123`变为`/123`。以下是网关的`application.yml`文件：

```java
server:
 port: ${PORT:8080}

spring:
 application:
  name: gateway-service

cloud:
 gateway:
   routes:
   - id: account-service
     uri: http://localhost:8091
     predicates:
     - Path=/account/**
     filters:
     - RewritePath=/account/(?<path>.*), /$\{path}
   - id: customer-service
     uri: http://localhost:8092
     predicates:
     - Path=/customer/**
     filters:
     - RewritePath=/customer/(?<path>.*), /$\{path}
   - id: order-service
     uri: http://localhost:8090
     predicates:
     - Path=/order/**
     filters:
     - RewritePath=/order/(?<path>.*), /$\{path}
   - id: product-service
     uri: http://localhost:8093
     predicates:
     - Path=/product/**
     filters:
     - RewritePath=/product/(?<path>.*), /$\{path}
```

令人惊讶的是，这就足够了。我们不需要提供任何与使用 Eureka 或 Config Server 等其他 Spring Cloud 组件时相比额外的注解。所以，我们网关应用程序的主类如下面的代码片段所示。你必须使用`mvn clean install`构建项目，并使用`java -jar`启动它，或者直接从你的 IDE 运行主类。示例应用程序的源代码可以在 GitHub 上找到([`github.com/piomin/sample-spring-cloud-gateway.git`](https://github.com/piomin/sample-spring-cloud-gateway.git)):

```java
@SpringBootApplication
public class GatewayApplication {

    public static void main(String[] args) {
        SpringApplication.run(GatewayApplication.class, args);
    }

}
```

# 服务发现集成

网关可以配置为基于服务发现中注册的服务列表创建路由。它可以与那些具有与`DiscoveryClient`兼容的服务注册解决方案集成的解决方案，例如 Netflix Eureka、Consul 或 Zookeeper。要启用`DiscoveryClient`路由定义定位器，你应该将`spring.cloud.gateway.discovery.locator.enabled`属性设置为`true`，并在类路径上提供一个`DiscoveryClient`实现。我们使用 Eureka 客户端和服务器进行发现。请注意，随着 Spring Cloud 最新里程碑版本`Finchley.M5`的发布，所有 Netflix 构件的名称都发生了变化，现在例如使用`spring-cloud-starter-netflix-eureka-client`而不是`spring-cloud-starter-eureka`:

```java
<dependency>
    <groupId>org.springframework.cloud</groupId>
    <artifactId>spring-cloud-starter-netflix-eureka-client</artifactId>
</dependency>
```

主类对 Eureka 客户端应用程序来说应该是相同的，用`@DiscoveryClient`注解。这是带有路由配置的`application.yml`文件。与之前的示例相比，唯一的变化是每个定义的路由的`uri`属性。我们不是提供它们的网络地址，而是使用从发现服务器中带有`lb`前缀的名称，例如`lb://order-service`:

```java
spring:
 application:
  name: gateway-service
 cloud:
  gateway:
   discovery:
    locator:
     enabled: true
   routes:
   - id: account-service
     uri: lb://account-service
     predicates:
     - Path=/account/**
     filters:
     - RewritePath=/account/(?<path>.*), /$\{path}
   - id: customer-service
     uri: lb://customer-service
     predicates:
     - Path=/customer/**
     filters:
     - RewritePath=/customer/(?<path>.*), /$\{path}
   - id: order-service
     uri: lb://order-service
     predicates:
     - Path=/order/**
     filters:
     - RewritePath=/order/(?<path>.*), /$\{path}
   - id: product-service
     uri: lb://product-service
     predicates:
     - Path=/product/**
     filters:
     - RewritePath=/product/(?<path>.*), /$\{path}
```

# 总结

有了 API 网关，我们在 Spring Cloud 中实现微服务架构核心元素的讨论已经结束。阅读了本书这部分内容后，你应该能够定制并使用 Eureka、Spring Cloud Config、Ribbon、Feign、Hystrix 以及最后基于 Zuul 和 Spring Cloud Gateway 的网关。

将这一章节视为两种可用的解决方案——老版本的 Netflix Zuul 和最新版本的 Spring Cloud Gateway 之间的比较。其中一个新的解决方案正在动态变化。它的当前版本 2.0，可能只与 Spring 5 一起使用，并且还没有在发行版中提供。而第一个解决方案，Netflix Zuul，是稳定的，但它不支持异步、非阻塞连接。它仍然基于 Netflix Zuul 1.0，尽管有一个新的 Zuul 版本支持异步通信。不管它们之间的差异如何，我都描述了如何使用这两种解决方案提供简单和更高级的配置。我还根据前面章节的示例，展示了与服务发现、客户端负载均衡器和断路器的集成。


# 第九章：分布式日志记录和追踪

当将单体应用拆分为微服务时，我们通常会花很多时间思考业务边界或应用逻辑的划分，但我们忘记了日志。根据我自己作为开发者和软件架构师的经验，我可以说明开发者通常不会支付太多注意力到日志上。另一方面，负责应用程序维护的操作团队主要依赖日志。无论你的专业领域是什么，毫无疑问，日志是所有应用程序都必须做的工作，无论它们是有单体架构还是微服务架构。然而，微服务在设计和安排应用程序日志方面增加了一个全新的维度。有许多小型的、独立的、水平扩展的、相互通信的服务在多台机器上运行。请求通常由多个服务处理。我们必须关联这些请求，并将所有日志存储在单一的、中心位置，以便更容易查看它们。Spring Cloud 引入了一个专门的库，实现了分布式追踪解决方案，即 Spring Cloud Sleuth。

在这里还应该讨论一件事情。日志记录不同于追踪！指出它们之间的区别是值得的。追踪是跟随你的程序的数据流。它通常被技术支持团队用来诊断问题出现的位置。你要追踪你的系统流程以发现性能瓶颈或错误发生的时间。日志记录用于错误报告和检测。与追踪相比，它应该始终是启用的。当你设计一个大型系统，并且你希望跨机器有良好的、灵活的错误报告时，你肯定应该考虑以集中式方式收集日志数据。实现这一目标的推荐和最受欢迎的解决方案是**ELK**栈（**Elasticsearch** + **Logstash** + **Kibana**）。Spring Cloud 中没有为这个栈提供专门的库，但是可以通过 Java 日志框架（如 Logback 或 Log4j）来实现集成。在本章中还将讨论另一个工具，Zipkin。它是一个典型的追踪工具，帮助收集可以用来解决微服务架构中延迟问题的计时数据。

本章我们将要覆盖的主题包括以下内容：

+   微服务基础系统日志的最佳实践

+   使用 Spring Cloud Sleuth 向消息添加追踪信息并关联事件

+   将 Spring Boot 应用程序与 Logstash 集成

+   使用 Kibana 显示和筛选日志条目

+   使用 Zipkin 作为分布式追踪工具，并通过 Spring Cloud Sleuth 与应用程序集成

# 微服务最佳的日志实践

处理日志最重要的最佳实践之一是跟踪所有传入请求和传出响应。这可能对你来说很显然，但我见过几个不符合这一要求的应用程序。如果你满足这个需求，微服务架构有一个后果。与单片应用程序相比，系统的日志总数会增加，其中没有消息传递。这反过来又要求我们比以前更加关注日志记录。我们应该尽最大努力生成尽可能少的信息，尽管这些信息可以告诉我们很多情况。我们如何实现这一点？首先，拥有所有微服务相同的日志消息格式是很好的。例如，考虑如何在应用程序日志中打印变量。我建议你使用 JSON 表示法，因为通常，微服务之间交换的消息格式是 JSON。这种格式有一个非常直接的标准化，使得你的日志容易阅读和解析，如下面的代码片段所示：

```java
17:11:53.712   INFO   Order received: {"id":1,"customerId":5,"productId":10}
```

前面的格式比以下内容更容易分析：

```java
17:11:53.712   INFO   Order received with id 1, customerId 5 and productId 10.
```

但通常，这里最重要的是标准化。无论你选择哪种格式，关键是在到处使用它。你还应该小心确保你的日志是有意义的。尽量避免不包含任何信息的句子。例如，从以下格式来看，不清楚哪个顺序正在处理：

```java
17:11:53.712   INFO   Processing order
```

然而，如果你真的想要这种日志条目格式，尽量把它分配给不同的日志级别。将所有内容都以`INFO`相同的级别记录，真的是一种糟糕的做法。有些信息比其他信息更重要，所以这里的困难在于决定日志条目应该记录在哪个级别。以下是一些建议：

+   `TRACE`：这是非常详细的信息，仅用于开发。你可能会在部署到生产环境后短时间内保留它，但将其视为临时文件。

+   `DEBUG`：在这个级别，记录程序中发生的任何事件。这主要用于开发人员的调试或故障排除。`DEBUG`和`TRACE`之间的区别可能是最难的。

+   `INFO`：在这个级别，你应该记录操作期间最重要的信息。这些信息必须易于理解，不仅对开发者，对管理员或高级用户也是如此，让他们能够快速找出应用程序正在做什么。

+   `WARN`：在这个级别，记录所有可能变成错误的潜在事件。这样的过程可以继续进行，但你应该对此特别小心。

+   `ERROR`：通常，你会在这个级别打印异常。这里的关键不是到处都抛出异常，例如，如果只有一个业务逻辑执行没有成功的话。

+   `FATAL`：这个 Java 日志级别表示非常严重的错误事件，可能会导致应用程序停止运行。

还有其他一些好的日志实践，但我已经提到了在基于微服务的系统中使用的一些最重要的实践。还值得提到日志的一个方面，即规范化。如果您想轻松理解和解释您的日志，您肯定要知道它们是在何时何地收集的，它们包含什么，以及为什么要发出它们。在所有微服务中特别重要的特性应该进行规范化，例如`Time`（何时）、`Hostname`（何地）和`AppName`（何人）。正如您将在本章的下一部分看到的，这种规范化在系统中实现集中日志收集方法时非常有用。

# 使用 Spring Boot 进行日志记录

Spring Boot 内部日志使用 Apache Commons Logging，但如果您包含启动器中的依赖项，默认情况下您的应用程序将使用 Logback。它以任何方式都不妨碍使用其他日志框架的可能性。还提供了 Java Util Logging、Log4J2 和 SLF4J 的默认配置。日志设置可以在`application.yml`文件中使用`logging.*`属性进行配置。默认日志输出包含日期和时间（毫秒）、日志级别、进程 ID、线程名称、发出条目的类的全名和消息。可以通过分别使用`logging.pattern.console`和`logging.pattern.file`属性为控制台和文件附加器来覆盖它。

默认情况下，Spring Boot 只向控制台记录日志。为了允许除了控制台输出之外还写入日志文件，您应该设置`logging.file`或`logging.path`属性。如果您指定`logging.file`属性，日志将被写入确切位置或当前位置的文件。如果您设置`logging.path`，它将在指定目录中创建一个`spring.log`文件。日志文件在达到 10 MB 后会被轮换。

在`application.yml`设置文件中可以自定义的最后一件事情是日志级别。默认情况下，Spring Boot 记录`ERROR`、`WARN`和`INFO`级别的消息。我们可以使用`logging.level.*`属性为每个单独的包或类覆盖此设置。还可以使用`logging.level.root`配置根日志记录器。以下是在`application.yml`文件中的一个示例配置，它更改了默认模式格式，以及一些日志级别，并设置了日志文件的存储位置：

```java
logging:
 file: logs/order.log
 level:
  com.netflix: DEBUG
  org.springframework.web.filter.CommonsRequestLoggingFilter: DEBUG
 pattern:
  console: "%d{HH:mm:ss.SSS} %-5level %msg%n"
  file: "%d{HH:mm:ss.SSS} %-5level %msg%n"
```

正如您在之前的示例中所看到的，这样的配置相当简单，但在某些情况下，这并不足够。如果您想要定义额外的 appender 或过滤器，您肯定应该包括其中一个可用的日志系统的配置——Logback(`logback-spring.xml`)，Log4j2(`log4j2-spring.xml`)，或 Java Util Logging(`logging.properties`)。正如我之前提到的，Spring Boot 默认使用 Logback 来记录应用程序日志。如果您在类路径的根目录提供`logback-spring.xml`文件，它将覆盖`application.yml`中定义的所有设置。例如，您可以创建每日轮转日志的文件 appender，并保留最多 10 天的历史记录。这个功能在应用程序中非常常用。在本章的下一节中，您还将了解到，要集成您的微服务与 Logstash，需要一个自定义的 appender。以下是一个设置`logs/order.log`文件每日轮转策略的 Logback 配置文件片段的例子：

```java
<configuration>
 <appender name="FILE" class="ch.qos.logback.core.rolling.RollingFileAppender">
  <file>logs/order.log</file>
  <rollingPolicy class="ch.qos.logback.core.rolling.TimeBasedRollingPolicy">
   <fileNamePattern>order.%d{yyyy-MM-dd}.log</fileNamePattern>
   <maxHistory>10</maxHistory>
   <totalSizeCap>1GB</totalSizeCap>
  </rollingPolicy>
  <encoder>
   <pattern>%d{HH:mm:ss.SSS} %-5level %msg%n</pattern>
  </encoder>
 </appender>
 <root level="DEBUG">
  <appender-ref ref="FILE" />
 </root>
</configuration>
```

值得一提的是，Spring 建议使用`logback-spring.xml`而不是默认的`logback.xml`对 Logback 进行配置。Spring Boot 包含对 Logback 的一些扩展，这些扩展对于高级配置可能很有帮助。它们不能用在标准的`logback.xml`中，只能与`logback-spring.xml`一起使用。我们已经列出了其中一些扩展，这些扩展将允许您定义特定于配置文件或从 Spring Environment 公开属性的配置：

```java
<springProperty scope="context" name="springAppName" source="spring.application.name" />
<property name="LOG_FILE" value="${BUILD_FOLDER:-build}/${springAppName}"/>​

<springProfile name="development">
...
</springProfile>

<springProfile name="production">
 <appender name="flatfile" class="ch.qos.logback.core.rolling.RollingFileAppender">
  <file>${LOG_FILE}</file>
  <rollingPolicy class="ch.qos.logback.core.rolling.TimeBasedRollingPolicy">
   <fileNamePattern>${LOG_FILE}.%d{yyyy-MM-dd}.gz</fileNamePattern>
   <maxHistory>7</maxHistory>
  </rollingPolicy>
  <encoder>
   <pattern>${CONSOLE_LOG_PATTERN}</pattern>
   <charset>utf8</charset>
  </encoder>
 </appender>
 ...
</springProfile>
```

# 使用 ELK 栈集中日志

ELK 是三个开源工具的缩写——Elasticsearch、Logstash 和 Kibana。它也被称为**Elastic Stack**。这个系统的核心是**Elasticsearch**，一个基于另一个开源 Java 项目 Apache Lucene 的搜索引擎。这个库特别适合于需要在跨平台环境中进行全文搜索的应用程序。Elasticsearch 流行的主要原因是它的性能。当然，它还有一些其他优势，如可扩展性、灵活性和通过提供基于 RESTful、JSON 格式的 API 来搜索存储的数据，易于集成。它有一个庞大的社区和许多用例，但对我们来说最有趣的是它存储和搜索应用程序生成的日志的能力。日志是包含 Logstash 在 ELK 栈中的主要原因。这个开源数据处理管道允许我们收集、处理并将数据输入到 Elasticsearch 中。

**Logstash**支持许多输入，这些输入可以从外部来源提取事件。有趣的是，它有许多输出，而 Elasticsearch 只是其中之一。例如，它可以将事件写入 Apache Kafka、RabbitMQ 或 MongoDB，并且可以将指标写入 InfluxDB 或 Graphite。它不仅接收并将数据转发到它们的目的地，还可以实时解析和转换它们。

**Kibana** 是 ELK 堆栈的最后一个元素。它是一个开源的数据可视化插件，用于 Elasticsearch。它允许您可视化、探索和发现来自 Elasticsearch 的数据。我们可以通过创建搜索查询轻松地显示和筛选我们应用程序收集的所有日志。在此基础上，我们可以将数据导出为 PDF 或 CSV 格式以提供报告。

# 在机器上设置 ELK 堆栈

在我们将应用程序的任何日志发送到 Logstash 之前，我们必须在本地机器上配置 ELK 堆栈。最合适的方法是使用 Docker 容器运行它。堆栈中的所有产品都可以作为 Docker 镜像使用。ELastic Stack 的供应商提供了一个专用的 Docker 注册表。可以在[www.docker.elastic.co](http://www.docker.elastic.co)找到所有发布镜像和标签的完整列表。它们都使用`centos:7`作为基础镜像。

我们将从 Elasticsearch 实例开始。其开发可以通过以下命令启动：

```java
docker run -d --name es -p 9200:9200 -p 9300:9300 -e "discovery.type=single-node" docker.elastic.co/elasticsearch/elasticsearch:6.1.1
```

在开发模式下运行 Elasticsearch 是最方便的，因为我们不需要提供任何其他配置。如果您想要在生产模式下启动它，`vm.max_map_count` Linux 内核设置至少需要设置为`262144`。根据不同的操作系统平台，修改它的过程是不同的。对于带有 Docker Toolbox 的 Windows，必须通过`docker-machine`来设置：

```java
docker-machine ssh
sudo sysctl -w vm.max_map_count=262144
```

下一步是运行带有 Logstash 的容器。除了启动带有 Logstash 的容器外，我们还应该定义一个输入和一个输出。输出是显而易见的——Elasticsearch，现在在默认的 Docker 机器地址`192.168.99.100`下可用。作为输入，我们定义了与我们的示例应用程序中用作日志附加器的`LogstashTcpSocketAppender`兼容的简单 TCP 插件`logstash-input-tcp`。我们所有的微服务日志都将以 JSON 格式发送。现在，重要的是为该插件设置`json`编码器。每个微服务都将以其名称和`micro`前缀在 Elasticsearch 中索引。以下是 Logstash 配置文件`logstash.conf`：

```java
input {
  tcp {
    port => 5000
    codec => json
  }
}

output {
  elasticsearch {
    hosts => ["http://192.168.99.100:9200"]
    index => "micro-%{appName}"
  }
}
```

这是一个运行 Logstash 并将其暴露在端口`5000`上的命令。它还将带有前述设置的文件复制到容器中，并覆盖 Logstash 配置文件的默认位置：

```java
docker run -d --name logstash -p 5000:5000 -v ~/logstash.conf:/config-dir/logstash.conf docker.elastic.co/logstash/logstash-oss:6.1.1 -f /config-dir/logstash.conf
```

最后，我们可以运行堆栈的最后一个元素，Kibana。默认情况下，它暴露在端口`5601`上，并连接到端口`9200`上的 Elasticsearch API，以便能够从那里加载数据：

```java
docker run -d --name kibana -e "ELASTICSEARCH_URL=http://192.168.99.100:9200" -p 5601:5601 docker.elastic.co/kibana/kibana:6.1.1
```

如果您想在带有 Docker 的 Windows 机器上运行 Elastic Stack 的所有产品，您可能需要将 Linux 虚拟机图像的默认 RAM 内存增加到至少 2 GB。在启动所有容器后，您最终可以通过`http://192.168.99.100:5601`访问可用的 Kibana 仪表板，然后继续将您的应用程序与 Logstash 集成。

# 将应用程序与 ELK 堆栈集成

有多种方法可以通过 Logstash 将 Java 应用程序与 ELK 堆栈集成。其中一种方法涉及到使用 Filebeat，它是一个用于本地文件的日志数据传输器。这种方法需要为 Logstash 实例配置一个 beats（`logstash-input-beats`）输入，实际上这就是默认选项。你还需要在服务器机器上安装并启动一个 Filebeat 守护进程。它负责将日志传递给 Logstash。

个人而言，我更喜欢基于 Logback 和专用追加器的配置。这似乎比使用 Filebeat 代理简单。除了需要部署一个附加服务外，Filebeat 还要求我们使用诸如 Grok 过滤器的解析表达式。使用 Logback 追加器时，你不需要任何日志传输器。这个追加器可在项目中的 Logstash JSON 编码器内使用。你可以通过在`logback-spring.xml`文件内声明`net.logstash.logback.appender.LogstashSocketAppender`追加器来为你的应用程序启用它。

我们还将讨论一种将数据发送到 Logstash 的替代方法，使用消息代理。在我们即将研究的示例中，我将向你展示如何使用 Spring `AMQPAppender`将日志事件发布到 RabbitMQ 交换。在这种情况下，Logstash 订阅该交换并消费发布的消息。

# 使用 LogstashTCPAppender

库`logstash-logback-encoder`提供了三种类型的追加器——UDP、TCP 和异步。TCP 追加器最常用。值得一提的是，TCP 追加器是异步的，所有的编码和通信都委托给一个线程。除了追加器，该库还提供了一些编码器和布局，以使你能够以 JSON 格式记录日志。因为 Spring Boot 默认包含一个 Logback 库，以及`spring-boot-starter-web`，我们只需在 Maven `pom.xml`中添加一个依赖项：

```java
<dependency>
 <groupId>net.logstash.logback</groupId>
 <artifactId>logstash-logback-encoder</artifactId>
 <version>4.11</version>
</dependency>
```

下一步是在 Logback 配置文件中定义带有`LogstashTCPAppender`类的追加器。每个 TCP 追加器都需要你配置一个编码器。你可以选择`LogstashEncoder`和`LoggingEventCompositeJsonEncoder`之间。`LoggingEventCompositeJsonEncoder`给你更多的灵活性。它由一个或多个映射到 JSON 输出的 JSON 提供者组成。默认情况下，没有提供者被配置。`LogstashTCPAppender`不是这样。默认情况下，它包括几个标准字段，如时间戳、版本、日志器名称和堆栈跟踪。它还添加了来自**映射诊断上下文**（**MDC**）和上下文的所有条目，除非你通过将`includeMdc`或`includeContext`属性设置为`false`来禁用它：

```java
<appender name="STASH" class="net.logstash.logback.appender.LogstashTcpSocketAppender">
 <destination>192.168.99.100:5000</destination>
 <encoder class="net.logstash.logback.encoder.LoggingEventCompositeJsonEncoder">
  <providers>
   <mdc />
   <context />
   <logLevel />
   <loggerName />
   <pattern>
    <pattern>
    {
    "appName": "order-service"
    }
    </pattern>
   </pattern>
   <threadName />
   <message />
   <logstashMarkers />
   <stackTrace />
  </providers>
 </encoder>
</appender>
```

现在，我想回到我们的示例系统片刻。我们仍然在同一个 Git 仓库([`github.com/piomin/sample-spring-cloud-comm.git`](https://github.com/piomin/sample-spring-cloud-comm.git))的`feign_with_discovery`分支([`github.com/piomin/sample-spring-cloud-comm/tree/feign_with_discovery`](https://github.com/piomin/sample-spring-cloud-comm/tree/feign_with_discovery))。我在源代码中添加了一些日志条目，按照*微服务最佳日志实践*部分描述的建议。以下是`order-service`内部的`POST`方法的当前版本。我通过从`org.slf4j.LoggerFactory`调用`getLogger`方法，使用 Logback over SLF4J 作为日志记录器：

```java
@PostMapping
public Order prepare(@RequestBody Order order) throws JsonProcessingException {
    int price = 0;
    List<Product> products = productClient.findByIds(order.getProductIds());
    LOGGER.info("Products found: {}", mapper.writeValueAsString(products));
    Customer customer = customerClient.findByIdWithAccounts(order.getCustomerId());
    LOGGER.info("Customer found: {}", mapper.writeValueAsString(customer));

    for (Product product : products) 
        price += product.getPrice();
    final int priceDiscounted = priceDiscount(price, customer);
    LOGGER.info("Discounted price: {}", mapper.writeValueAsString(Collections.singletonMap("price", priceDiscounted)));

    Optional<Account> account = customer.getAccounts().stream().filter(a -> (a.getBalance() > priceDiscounted)).findFirst();
    if (account.isPresent()) {
        order.setAccountId(account.get().getId());
        order.setStatus(OrderStatus.ACCEPTED);
        order.setPrice(priceDiscounted);
        LOGGER.info("Account found: {}", mapper.writeValueAsString(account.get()));
    } else {
        order.setStatus(OrderStatus.REJECTED);
        LOGGER.info("Account not found: {}", mapper.writeValueAsString(customer.getAccounts()));
    }

    return repository.add(order);
}
```

让我们看看 Kibana 仪表板。它可通过`http://192.168.99.100:5601`访问。应用程序日志在那里可以轻松发现和分析。你可以在页面左侧的菜单中选择所需的索引名称（在以下屏幕快照中标记为**1**）。日志统计信息以时间线图的形式展示（**2**）。你可以通过点击具体柱状图或选择一组柱状图来缩小搜索参数所花费的时间。给定时间段内的所有日志都显示在图表下方的面板中（**3**）：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/3e56b172-f8c5-4a8a-84c3-0bece490c7a5.png)

每个条目都可以扩展以查看其详细信息。在详细表格视图中，我们可以看到，例如，Elasticsearch 索引的名称（`_index`）和微服务的级别或名称（`appName`）。大多数这些字段都是由`LoggingEventCompositeJsonEncoder`设置的。我只定义了一个应用程序特定的字段，`appName`：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/032646e3-4508-404b-b1cc-9ad63012db02.png)

Kibana 赋予我们搜索特定条目的强大能力。我们只需点击选中的条目即可定义过滤器，以定义一组搜索条件。在前面的屏幕快照中，你可以看到我过滤掉了所有进入 HTTP 请求的条目。正如你可能记得的，`org.springframework.web.filter.CommonsRequestLoggingFilter`类负责记录它们。我只是定义了一个名称与完全限定日志类名相等的过滤器。以下是我 Kibana 仪表板上的屏幕截图，它只显示由`CommonsRequestLoggingFilter`生成的日志：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/f1b536fc-7f08-4f9a-b12a-cc92d8fe5ebc.png)

# 使用 AMQP appender 和消息代理

使用 Spring AMQP appender 和消息代理的配置比使用简单的 TCP appender 的方法要复杂一些。首先，你需要在你的本地机器上启动一个消息代理。我在第五章，*与 Spring Cloud Config 的分布式配置*中描述了这一过程，其中我介绍了使用 Spring Cloud Bus 的 RabbitMQ 进行动态配置重载。假设你已经在本地下启动了一个 RabbitMQ 实例或作为 Docker 容器启动，你可以继续进行配置。我们必须为发布传入事件创建一个队列，然后将其绑定到交换机。为此，你应该登录到 Rabbit 管理控制台，然后单击队列部分。我创建了一个名为`q_logstash`的队列。我定义了一个名为`ex_logstash`的新交换机，如下面的屏幕截图所示。该队列已使用所有示例微服务的路由键绑定到交换机：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/6af1e4a9-b02d-4c4f-9e24-dea67478f24b.png)

在我们启动和配置了 RabbitMQ 实例之后，我们可以在应用程序方面开始集成。首先，你必须将`spring-boot-starter-amqp`包含在项目依赖项中，以提供 AMQP 客户端和 AMQP appender 的实现：

```java
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-amqp</artifactId>
</dependency>
```

然后，你唯一需要做的是在 Logback 配置文件中定义具有`org.springframework.amqp.rabbit.logback.AmqpAppender`类的 appender。需要设置的最重要属性是 RabbitMQ 网络地址（`host`，`port`），声明的交换机名称（`exchangeName`）和路由键（`routingKeyPattern`），它必须与为交换机绑定声明的其中一个键匹配。与 TCP appender 相比，这种方法的缺点是需要自己准备发送给 Logstash 的 JSON 消息。以下是`order-service`的 Logback 配置片段：

```java
<appender name="AMQP"
 class="org.springframework.amqp.rabbit.logback.AmqpAppender">
 <layout>
  <pattern>
  {
  "time": "%date{ISO8601}",
  "thread": "%thread",
  "level": "%level",
  "class": "%logger{36}",
  "message": "%message"
  }
  </pattern>
 </layout>
 <host>192.168.99.100</host>
 <port>5672</port>
 <username>guest</username>
 <password>guest</password> 
 <applicationId>order-service</applicationId>
 <routingKeyPattern>order-service</routingKeyPattern>
 <declareExchange>true</declareExchange>
 <exchangeType>direct</exchangeType>
 <exchangeName>ex_logstash</exchangeName>
 <generateId>true</generateId>
 <charset>UTF-8</charset>
 <durable>true</durable>
 <deliveryMode>PERSISTENT</deliveryMode>
</appender>
```

通过声明`rabbitmq`（`logstash-input-rabbitmq`）输入，Logstash 可以轻松集成 RabbitMQ：

```java
input {
  rabbitmq {
    host => "192.168.99.100"
    port => 5672
    durable => true
    exchange => "ex_logstash"
  }
}

output { 
  elasticsearch { 
    hosts => ["http://192.168.99.100:9200"]
  } 
}
```

# Spring Cloud Sleuth

Spring Cloud Sleuth 是一个相当小型的、简单的项目，但它提供了一些对日志记录和跟踪有用的功能。如果你参考*使用 LogstashTCPAppender*部分中讨论的示例，你可以很容易地看出，没有可能过滤出与单个请求相关的所有日志。在基于微服务的环境中，关联应用程序在处理进入系统的请求时交换的消息也非常重要。这是创建 Spring Cloud Sleuth 项目的主要动机。

如果为应用程序启用了 Spring Cloud Sleuth，它会向请求中添加一些 HTTP 头，这允许您将请求与响应以及独立应用程序之间交换的消息链接起来，例如，通过 RESTful API。它定义了两个基本工作单位——跨度（span）和跟踪（trace）。每个都有一个独特的 64 位 ID。跟踪 ID 的值等于跨度 ID 的初始值。跨度指的是一个单独的交换，其中响应是作为对请求的反应发送的。跟踪通常被称为**上下文关联**（correlation IT），它帮助我们链接系统处理传入请求时不同应用程序生成的所有日志。

每个跟踪和跨度 ID 都添加到 Slf4J **MDC**（**映射诊断上下文**）中，因此您将能够在日志聚合器中提取具有给定跟踪或跨度的所有日志。MDC 只是一个存储当前线程上下文数据的映射。每个到达服务器的客户端请求都是由不同的线程处理的。得益于这一点，每个线程在其线程生命周期内都可以访问其 MDC 的值。除了`spanId`和`traceId`之外，Spring Cloud Sleuth 还将在 MDC 中添加以下两个跨度：

+   `appName`：生成日志条目的应用程序名称

+   `exportable`：这指定了日志是否应导出到 Zipkin

除了前面的特性外，Spring Cloud Sleuth 还提供了：

+   一种对常见分布式跟踪数据模型的抽象，允许与 Zipkin 集成。

+   记录时间信息以帮助进行延迟分析。它还包括不同的抽样策略来管理导出到 Zipkin 的数据量。

+   与参与通信的常见 Spring 组件集成，如 servlet 过滤器、异步端点、RestTemplate、消息通道、Zuul 过滤器和 Feign 客户端。

# 将 Sleuth 集成到应用程序中

为了在应用程序中启用 Spring Cloud Sleuth 功能，只需将`spring-cloud-starter-sleuth`启动器添加到依赖项中：

```java
<dependency>
    <groupId>org.springframework.cloud</groupId>
    <artifactId>spring-cloud-starter-sleuth</artifactId>
</dependency>
```

包含此依赖项后，应用程序生成的日志条目的格式已更改。您可以通过以下方式看到这一点：

```java
2017-12-30 00:21:31.639 INFO [order-service,9a3fef0169864e80,9a3fef0169864e80,false] 49212 --- [nio-8090-exec-6] p.p.s.order.controller.OrderController : Products found: [{"id":2,"name":"Test2","price":1500},{"id":9,"name":"Test9","price":2450}]
2017-12-30 00:21:31.683 INFO [order-service,9a3fef0169864e80,9a3fef0169864e80,false] 49212 --- [nio-8090-exec-6] p.p.s.order.controller.OrderController : Customer found: {"id":2,"name":"Adam Smith","type":"REGULAR","accounts":[{"id":4,"number":"1234567893","balance":5000},{"id":5,"number":"1234567894","balance":0},{"id":6,"number":"1234567895","balance":5000}]}
2017-12-30 00:21:31.684 INFO [order-service,9a3fef0169864e80,9a3fef0169864e80,false] 49212 --- [nio-8090-exec-6] p.p.s.order.controller.OrderController : Discounted price: {"price":3752}
2017-12-30 00:21:31.684 INFO [order-service,9a3fef0169864e80,9a3fef0169864e80,false] 49212 --- [nio-8090-exec-6] p.p.s.order.controller.OrderController : Account found: {"id":4,"number":"1234567893","balance":5000}
2017-12-30 00:21:31.711 INFO [order-service,58b06c4c412c76cc,58b06c4c412c76cc,false] 49212 --- [nio-8090-exec-7] p.p.s.order.controller.OrderController : Order found: {"id":4,"status":"ACCEPTED","price":3752,"customerId":2,"accountId":4,"productIds":[9,2]}
2017-12-30 00:21:31.722 INFO [order-service,58b06c4c412c76cc,58b06c4c412c76cc,false] 49212 --- [nio-8090-exec-7] p.p.s.order.controller.OrderController : Account modified: {"accountId":4,"price":3752}
2017-12-30 00:21:31.723 INFO [order-service,58b06c4c412c76cc,58b06c4c412c76cc,false] 49212 --- [nio-8090-exec-7] p.p.s.order.controller.OrderController : Order status changed: {"status":"DONE"}
```

# 使用 Kibana 搜索事件

Spring Cloud Sleuth 自动向所有请求和响应添加 HTTP 头`X-B3-SpanId`和`X-B3-TraceId`。这些字段也包括在 MDC 中作为`spanId`和`traceId`。但在移到 Kibana 仪表板之前，我想让您看一下下面的图表。这是一个顺序图，展示了样本微服务之间的通信流程：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/d8eb077a-8417-4960-9e12-f67cb2cf2070.png)

`order-service`暴露了两种可用方法。第一种是创建新订单，第二种是确认它。第一个`POST /`方法，实际上，直接从`customer-service`、`product-service`和`account-service`通过`customer-service`调用所有其他服务的端点。第二个`PUT /{id}`方法只与`account-service`的一个端点集成。

前述流程现在可以通过存储在 ELK Stack 中的日志条目进行映射。当使用 Kibana 作为日志聚合器，结合由 Spring Cloud Sleuth 生成的字段时，我们可以通过使用 trace 或 span ID 过滤它们来轻松找到条目。这是一个例子，我们发现所有与从`order-service`调用`POST /`端点有关的事件，其`X-B3-TraceId`字段等于`103ec949877519c2`:

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/c108158a-5db0-419a-88dd-a10b8f87d796.png)

下面是一个与前一个例子类似的例子，但是在这个例子中，所有在处理请求期间存储的事件都被发送到`PUT /{id}`端点。这些条目也通过`X-B3-TraceId`字段过滤出来，该字段的值等于`7070b90bfb36c961`:

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/4587b4f2-9b08-4ba3-8f56-662bdf8ee49a.png)

在这里，你可以看到已经发送到 Logstash 的微服务应用程序的完整字段列表。带有`X-`前缀的字段已经被 Spring Cloud Sleuth 库包含在消息中：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/dda5a4be-8e5e-4cc0-aa93-eb13883dbcbb.png)

# 将 Sleuth 与 Zipkin 集成

Zipkin 是一个流行的、开源的分布式追踪系统，它帮助收集分析微服务架构中延迟问题的所需时序数据。它能够使用 UI web 控制台收集、查询和可视化数据。Zipkin UI 提供了一个依赖关系图，显示了系统内所有应用程序处理了多少追踪请求。Zipkin 由四个元素组成。我已经提到了其中一个，Web UI。第二个是 Zipkin 收集器，负责验证、存储和索引所有传入的追踪数据。Zipkin 使用 Cassandra 作为默认的后端存储。它还原生支持 Elasticsearch 和 MySQL。最后一个元素是查询服务，它为查找和检索追踪提供了简单的 JSON API。它主要由 Web UI 消费。

# 运行 Zipkin 服务器

我们可以通过几种方式在本地运行 Zipkin 服务器。其中一种方式是使用 Docker 容器。以下命令启动一个内存中的服务器实例：

```java
docker run -d --name zipkin -p 9411:9411 openzipkin/zipkin
```

在运行 Docker 容器之后，Zipkin API 在`http://192.168.99.100:9411`可用。或者，你可以使用 Java 库和 Spring Boot 应用程序来启动它。为了启用 Zipkin，你应该在你的 Maven `pom.xml`文件中包含以下依赖项，如下面的代码片段所示。默认版本由`spring-cloud-dependencies`管理。在我们的示例应用程序中，我使用了`Edgware.RELEASE` Spring Cloud Release Train:

```java
<dependency>
    <groupId>io.zipkin.java</groupId>
    <artifactId>zipkin-server</artifactId>
</dependency>
<dependency>
    <groupId>io.zipkin.java</groupId>
    <artifactId>zipkin-autoconfigure-ui</artifactId>
</dependency>
```

我在我们的示例系统中增加了一个新的`zipkin-service`模块。它非常简单。必须实现的唯一事情是应用的主类，它用`@EnableZipkinServer`注解标记。得益于这一点，Zipkin 实例被嵌入到 Spring Boot 应用程序中：

```java
@SpringBootApplication
@EnableZipkinServer
public class ZipkinApplication {

    public static void main(String[] args) {
        new SpringApplicationBuilder(ZipkinApplication.class).web(true).run(args);
    }

}
```

为了在默认端口上启动 Zipkin 实例，我们必须在`application.yml`文件中覆盖默认服务器端口。启动应用程序后，Zipkin API 在`http://localhost:9411`处可用：

```java
spring: 
 application:
  name: zipkin-service

server: 
 port: ${PORT:9411}
```

# 构建客户端应用程序

如果你想在项目中同时使用 Spring Cloud Sleuth 和 Zipkin，只需在依赖项中添加`spring-cloud-starter-zipkin`启动器。它通过 HTTP API 实现了与 Zipkin 的集成。如果你已经在 Spring Boot 应用程序内部以内嵌实例启动了 Zipkin 服务器，你不需要提供包含连接地址的任何附加配置。如果你使用 Docker 容器，你应该在`application.yml`中覆盖默认 URL：

```java
spring:
 zipkin:
  baseUrl: http://192.168.99.100:9411/
```

你总是可以利用与服务发现的集成。如果你通过`@EnableDiscoveryClient`为带有内嵌 Zipkin 服务器的应用程序启用了发现客户端，你只需将属性`spring.zipkin.locator.discovery.enabled`设置为`true`即可。在这种情况下，即使它不在默认端口上可用，所有应用程序都可以通过注册名称来定位它。你还应该用`spring.zipkin.baseUrl`属性覆盖默认的 Zipkin 应用程序名称：

```java
spring:
 zipkin:
  baseUrl: http://zipkin-service/
```

默认情况下，Spring Cloud Sleuth 只发送一些选定的传入请求。这是由属性`spring.sleuth.sampler.percentage`决定的，其值必须是一个在 0.0 和 1.0 之间的双精度值。采样解决方案已经实现，因为分布式系统之间交换的数据量有时可能非常高。Spring Cloud Sleuth 提供了采样器接口，可以实现来控制采样算法。默认实现位于`PercentageBasedSampler`类中。如果你想追踪你应用程序之间交换的所有请求，只需声明`AlwaysSampler`bean。这对于测试目的可能是有用的：

```java
@Bean
public Sampler defaultSampler() {
    return new AlwaysSampler();
}
```

# 使用 Zipkin UI 分析数据

让我们回到我们的示例系统一会儿。如我之前提到的，新的`zipkin-service`模块已经增加。我还为所有微服务（包括`gateway-service`）启用了 Zipkin 跟踪。默认情况下，Sleuth 将`spring.application.name`的值作为跨度服务名称。你可以用`spring.zipkin.service.name`属性覆盖那个名称。

为了成功使用 Zipkin 测试我们的系统，我们必须启动微服务、网关、发现和 Zipkin 服务器。为了生成并发送一些测试数据，你可以运行由`pl.piomin.services.gateway.GatewayControllerTest`类实现的 JUnit 测试。它通过`gateway-service`向`order-service`发送 100 条消息，`gateway-service`可通过`http://localhost:8080/api/order/**`访问。

让我们分析 Zipkin 从所有服务收集的数据。你可以通过其 Web 控制台 UI 轻松查看。所有跟踪都被标记为服务的名称跨度。如果一个条目有五个跨度，这意味着进入系统的请求被五个不同的服务处理。你可以在以下屏幕截图中看到这一点：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/22f22dfd-2f85-4951-a595-58f9d9f2e542.png)

你可以用不同的标准过滤条目，比如服务名称、跨度名称、跟踪 ID、请求时间或持续时间。Zipkin 还可视化失败的请求并按持续时间降序或升序排序：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/838af6f7-c7cb-4894-8a9e-1f13a49baa51.png)

你可以查看每个条目的详细信息。Zipkin 可视化了所有参与通信的微服务之间的流程。它考虑了每个传入请求的时间数据。你可以揭示系统延迟的原因：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/c8eef8c1-15f9-4bd9-8ea3-41cc319da73a.png)

Zipkin 提供了一些额外有趣的功能。其中之一是能够可视化应用程序之间的依赖关系。以下屏幕截图说明了我们的示例系统的通信流程：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/7ac3b51e-bbae-409f-8fd2-515abf55c6ea.png)

你可以通过点击相关元素来查看服务之间交换了多少消息：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/6d479575-78db-4869-8be4-77bc371c36e3.png)

# 通过消息代理进行集成

通过 HTTP 集成 Zipkin 并不是唯一选项。正如 Spring Cloud 通常所做的那样，我们可以使用消息代理作为代理。有两个可用的代理商—RabbitMQ 和 Kafka。第一个可以通过使用`spring-rabbit`依赖项包含在项目中，而第二个可以通过`spring-kafka`包含。这两个代理商的默认目的地名称都是`zipkin`：

```java
<dependency>
 <groupId>org.springframework.cloud</groupId>
 <artifactId>spring-cloud-starter-zipkin</artifactId>
</dependency>
<dependency>
 <groupId>org.springframework.amqp</groupId>
 <artifactId>spring-rabbit</artifactId>
</dependency>
```

这个功能还要求 Zipkin 服务器端进行更改。我们配置了一个消费者，它正在监听来自 RabbitMQ 或 Kafka 队列的数据。为了实现这一点，只需在你的项目中包含以下依赖项。你仍然需要将`zipkin-server`和`zipkin-autoconfigure-ui`工件包含在类路径中：

```java
<dependency>
 <groupId>org.springframework.cloud</groupId>
 <artifactId>spring-cloud-sleuth-zipkin-stream</artifactId>
</dependency>
<dependency>
 <groupId>org.springframework.cloud</groupId>
 <artifactId>spring-cloud-starter-stream-rabbit</artifactId>
</dependency>
```

你应该用`@EnableZipkinStreamServer`而不是`@EnableZipkinServer`注解主应用类。幸运的是，`@EnableZipkinStreamServer`也注解有`@EnableZipkinServer`，这意味着你也可以使用标准的 Zipkin 服务器端点通过 HTTP 收集跨度，以及使用 Web 控制台查找它们：

```java
@SpringBootApplication
@EnableZipkinStreamServer
public class ZipkinApplication {

    public static void main(String[] args) {
        new SpringApplicationBuilder(ZipkinApplication.class).web(true).run(args);
    }

}
```

# 摘要

在开发过程中，日志记录和跟踪通常并不是非常重要，但这些是系统维护中的关键特性。在本章中，我重点介绍了开发和运维领域。我向您展示了如何以几种不同的方式将 Spring Boot 微服务应用程序与 Logstash 和 Zipkin 集成。我还向您展示了如何启用 Spring Cloud Sleuth 功能的一些示例，以便更容易监视许多微服务之间的调用。阅读完本章后，您还应该能够有效地使用 Kibana 作为日志聚合工具，以及使用 Zipkin 作为跟踪工具，发现系统内部通信的瓶颈。

Spring Cloud Sleuth 与 Elastic Stack 和 Zipkin 结合使用，似乎是一个非常强大的生态系统，它消除了您可能对由许多独立微服务组成的监控系统存在问题的任何疑虑。
