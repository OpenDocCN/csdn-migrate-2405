# 精通 SpringCloud（四）

> 原文：[`zh.annas-archive.org/md5/3341AF3ECE66B2253A7F83A5D112367C`](https://zh.annas-archive.org/md5/3341AF3ECE66B2253A7F83A5D112367C)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十三章：测试 Java 微服务

在开发新应用程序时，我们永远不要忘记自动化测试。如果考虑基于微服务的架构，这些尤其重要。测试微服务需要与为单体应用程序创建的测试不同的方法。就单体而言，主要关注的是单元测试和集成测试，以及数据库层。在微服务的情况下，最重要的事情是以尽可能细粒度的覆盖每个通信。尽管每个微服务都是独立开发和发布的，但其中一个服务的更改可能会影响所有与之交互的其他服务。它们之间的通信是通过消息实现的。通常，这些消息是通过 REST 或 AMQP 协议发送的。

本章我们将覆盖以下主题：

+   Spring 对自动化测试的支持

+   Spring Boot 微服务中组件测试与集成测试的区别

+   使用 Pact 实施合同测试

+   使用 Spring Cloud Contract 实施合同测试

+   使用 Gatling 实施性能测试

# 测试策略

有五种不同的微服务测试策略。其中前三种与单体应用相同：

+   **单元测试**：单元测试中，我们测试代码的最小单元，例如，一个单独的方法或组件，并模拟其他方法和组件的每次调用。有许多流行的 Java 框架支持单元测试，如 JUnit、TestNG 和 Mockito（用于模拟）。这类测试的主要任务是确认实现符合需求。单元测试尤其是一个强大的工具，尤其是在与测试驱动开发结合使用时。

+   **集成测试**：仅使用单元测试并不能保证您将验证整个系统的行为。集成测试取模块并尝试将它们一起测试。这种方法为您提供了在子系统中锻炼通信路径的机会。我们根据模拟的外部服务接口测试组件之间的交互和通信。在基于微服务的系统中，集成测试可以用于包括其他微服务、数据源或缓存。

+   **端到端测试**：端到端测试也称为**功能测试**。这些测试的主要目标是验证系统是否符合外部要求。这意味着我们应该设计测试场景，以测试参与该过程的所有微服务。设计一个好的端到端测试并不是一件简单的事。由于我们需要测试整个系统，因此特别重视测试场景的设计非常重要。

+   **契约测试**：契约测试用于确保微服务的显式和隐式契约如预期般工作。当消费者集成并使用组件的接口时，总是形成契约。在微服务系统中，通常有一个组件被多个消费者使用。每个消费者通常需要一个满足其需求的不同的契约。基于这些假设，每个消费者都负责源组件接口的行为。

+   **组件测试**：在我们完成了微服务中所有对象和方法的单元测试之后，我们应该孤立地测试整个微服务。为了在孤立环境中运行测试，我们需要模拟或替换其他微服务的调用。外部数据存储应被等效的内存数据存储所替代，这也显著提高了测试性能。

契约测试与组件测试的区别是显而易见的。以下图表在我们的示例`order-service`微服务中说明了这些差异：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/ce6b981a-9c68-4f29-926f-f51f4ca22502.png)

现在，有一个问题是我们是否真的需要为基于微服务的系统测试添加两个额外的策略。通过适当的单元和集成测试，我们可能对构成微服务的一部分的单个组件的实现的正确性有信心。然而，如果没有为微服务制定更具体的测试策略，我们不能确定它们如何共同工作以满足我们的业务需求。因此，增加了组件和契约测试。这是帮助我们理解组件、契约和集成测试之间差异的一个非常重要的变化。因为组件测试是在与外界隔离的情况下进行的，所以集成测试负责验证与那个世界的交互。这就是为什么我们应该为集成测试提供存根，而不是为组件测试。契约测试与集成测试类似，强调微服务之间的交互，但它们将它们视为黑盒，仅验证响应的格式。

一旦你为你的微服务提供了功能测试，你也应该考虑性能测试。我们可以区分出以下性能测试策略：

+   **负载测试**：这些测试用于确定系统在正常和预期负载条件下的行为。这里的主要想法是识别一些弱点，例如响应时间延迟、异常中断或如果网络超时设置不正确则尝试次数过多。

+   **压力测试**：这些测试检查系统的上限，以观察在极端重载下系统的表现。除了负载测试之外，它还检查内存泄漏、安全问题以及数据损坏。它可能使用与负载测试相同的工具。

以下图表说明了在您的系统上执行所有测试策略的逻辑顺序。我们从最简单的单元测试开始，该测试验证小块软件，然后继续下一阶段，最后完成压力测试，将整个系统推向极限：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/79c6864e-6185-4be3-8573-fe3fdcd8330e.png)

# 测试 Spring Boot 应用程序

正如您在上一节可能已经读到的，您的应用程序中有不同的测试策略和方法。我简要提到了它们的所有内容，所以现在我们可以继续实践方面的问题。Spring Boot 提供了一系列工具，有助于实现自动化测试。为了在项目中启用这些特性，您必须将 `spring-boot-starter-test` 启动器添加到依赖项中。它不仅导入了 `spring-test` 和 `spring-boot-test` 工件，还导入了其他一些有用的测试库，如 JUnit、Mockito 和 AssertJ：

```java
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-test</artifactId>
    <scope>test</scope>
</dependency>
```

# 构建示例应用程序

在我们开始自动化测试之前，我们需要为测试目的准备一个示例业务逻辑。我们可以使用前几章中的同一个示例系统，但它必须稍作修改。到目前为止，我们从未使用过外部数据源来存储和收集测试数据。在本章中，为了说明不同的策略如何处理持久性测试问题，这样做将很有帮助。现在，每个服务都有自己的数据库尽管，通常，选择哪个数据库并不重要。Spring Boot 支持大量解决方案，包括关系型和 NoSQL 数据库。我决定使用 Mongo。让我们回顾一下示例系统的架构。以下图表所示的当前模型考虑了关于每个服务专用数据库的先前描述的假设：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/2b538768-b0e9-4e90-bc9e-df506778371a.png)

# 数据库集成

为了在 Spring Boot 应用程序中启用 Mongo 支持，请在依赖项中包含 `spring-boot-starter-data-mongo` 启动器。这个项目提供了一些有趣的特性来简化与 MongoDB 的集成。在这些特性中，特别值得一提的是丰富的对象映射、`MongoTemplate`，当然还有对仓库编写风格的支持，这是其他 Spring Data 项目所熟知的。以下是 `pom.xml` 中所需的依赖声明：

```java
<dependency>
 <groupId>org.springframework.boot</groupId>
 <artifactId>spring-boot-starter-data-mongodb</artifactId>
</dependency>
```

可以使用 MongoDB 的 Docker 镜像轻松启动 MongoDB 的实例。运行以下命令以启动一个容器，该容器在端口 `27017` 上暴露 Mongo 数据库：

```java
docker run --name mongo -p 27017:27017 -d mongo
```

为了将应用程序与之前启动的数据源连接，我们应该覆盖 `application.yml` 中的 `auto-configured` 设置。这可以通过 `spring.data.mongodb.*` 属性来实现：

```java
spring: 
 application:
  name: account-service
 data:
  mongodb:
   host: 192.168.99.100
   port: 27017
   database: micro
   username: micro 
   password: micro123
```

我已经提到了对象映射功能。Spring Data Mongo 提供了一些可用于此的注解。存储在数据库中的每个对象都应该用`@Document`注解。目标集合的主键是一个 12 字节的字符串，应该在 Spring Data 的`@Id`中每个映射类中指示。以下是`Account`对象实现的片段：

```java
@Document
public class Account {

    @Id
    private String id;
    private String number;
    private int balance;
    private String customerId;
    // ...

}
```

# 单元测试

我花了很长时间描述与 MongoDB 的集成。然而，测试持久性是自动化测试的关键点之一，所以正确配置它非常重要。现在，我们可以进行测试的实现。Spring Test 为最典型的测试场景提供支持，例如通过 REST 客户端与其他服务集成或与数据库集成。我们有一套库可供我们轻松模拟与外部服务的交互，这对于单元测试尤为重要。

下面的测试类是一个典型的 Spring Boot 应用程序的单元测试实现。我们使用了 JUnit 框架，这是 Java 事实上的标准。在这里，我们使用 Mockito 库用它们的存根替换真实的仓库和控制器。这种方法允许我们轻松验证`@Controller`类实现的每个方法的正确性。测试在与外部组件隔离的环境中进行，这是单元测试的主要假设：

```java
@RunWith(SpringRunner.class)
@WebMvcTest(AccountController.class)
public class AccountControllerUnitTest {

    ObjectMapper mapper = new ObjectMapper();

    @Autowired
    MockMvc mvc;
    @MockBean
    AccountRepository repository;

    @Test
    public void testAdd() throws Exception {
        Account account = new Account("1234567890", 5000, "1");
        when(repository.save(Mockito.any(Account.class))).thenReturn(new Account("1","1234567890", 5000, "1"));
        mvc.perform(post("/").contentType(MediaType.APPLICATION_JSON).content(mapper.writeValueAsString(account)))
 .andExpect(status().isOk());
 }

    @Test
    public void testWithdraw() throws Exception {
        Account account = new Account("1", "1234567890", 5000, "1");
        when(repository.findOne("1")).thenReturn(account);
        when(repository.save(Mockito.any(Account.class))).thenAnswer(new Answer<Account>() {
            @Override
            public Account answer(InvocationOnMock invocation) throws Throwable {
                Account a = invocation.getArgumentAt(0, Account.class);
                return a;
             }
        });
        mvc.perform(put("/withdraw/1/1000"))
            .andExpect(status().isOk())
            .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8))
            .andExpect(jsonPath("$.balance", is(4000)));
    }

}
```

尤其是在微服务的背景下，我们可以很容易地模拟 Feign 客户端通信。下面的例子测试类验证了`order-service`中用于提款的端点，通过调用`account-service`暴露的端点。正如你可能已经注意到的，那个端点已经被之前介绍的测试类测试过了。这是`order-service`的带有单元测试实现的类：

```java
@RunWith(SpringRunner.class)
@WebMvcTest(OrderController.class)
public class OrderControllerTest {

    @Autowired
    MockMvc mvc;
    @MockBean
    OrderRepository repository;
    @MockBean
    AccountClient accountClient;

    @Test
    public void testAccept() throws Exception {
        Order order = new Order("1", OrderStatus.ACCEPTED, 2000, "1", "1", null);
        when(repository.findOne("1")).thenReturn(order);
        when(accountClient.withdraw(order.getAccountId(), order.getPrice())).thenReturn(new Account("1", "123", 0));
        when(repository.save(Mockito.any(Order.class))).thenAnswer(new Answer<Order>() {
            @Override
            public Order answer(InvocationOnMock invocation) throws Throwable {
                Order o = invocation.getArgumentAt(0, Order.class);
                return o;
            }
        });

        mvc.perform(put("/1"))
            .andExpect(status().isOk())
            .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8))
            .andExpect(jsonPath("$.status", is("DONE")));
    }

}
```

# 组件测试

如果你为应用程序中的所有关键类和接口提供了单元测试，你可以继续进行组件测试。组件测试的主要思想是使用内存中的测试替身和数据存储实例化完整的微服务。这允许我们跳过网络连接。而在单元测试中，我们模拟了所有的数据库或 HTTP 客户端，在这里我们不模拟任何东西。我们为数据库客户端提供内存中的数据源，并为 REST 客户端模拟 HTTP 响应。

# 使用内存数据库运行测试

我选择 MongoDB 的一个原因是因为它很容易与 Spring Boot 应用程序集成以用于测试目的。为了为你的项目启用嵌入式 MongoDB，请在 Maven 的`pom.xml`中包含以下依赖项：

```java
<dependency>
    <groupId>de.flapdoodle.embed</groupId>
    <artifactId>de.flapdoodle.embed.mongo</artifactId>
    <scope>test</scope>
</dependency>
```

Spring Boot 为内嵌 MongoDB 提供了自动配置，所以我们除了在`application.yml`中设置本地地址和端口外，不需要做任何事情。因为默认情况下，我们使用运行在 Docker 容器上的 Mongo，所以我们应该在一个额外的 Spring 配置文件中声明这样的配置。这个特定的配置文件在测试用例执行期间通过在测试类上使用`@ActiveProfiles`注解来激活。下面是`application.yml`文件的一个片段，我们定义了两个配置文件`dev`和`test`，它们具有不同的 MongoDB 连接设置：

```java
---
spring:
 profiles: dev
 data:
  mongodb:
   host: 192.168.99.100
   port: 27017
   database: micro
   username: micro 
   password: micro123

---
spring:
 profiles: test
 data:
  mongodb:
   host: localhost
   port: 27017
```

如果你使用的是除 MongoDB 之外的数据库，例如 MySQL 或 Postgres，你可以很容易地将它们替换为替代的、基于内存的、内嵌的关系型数据库，如 H2 或 Derby。Spring Boot 支持它们，并为可能通过`@DataJpaTest`激活的测试提供自动配置。除了使用`@SpringBootTest`之外，你还可以使用`@DataMongoTest`注解来进行内嵌 MongoDB 的测试。这不仅会配置一个基于内存的内嵌 MongoDB，还会配置一个`MongoTemplate`，扫描带有`@Document`注解的类，并配置 Spring Data MongoDB 仓库。

# 处理 HTTP 客户端和服务发现

有关使用内嵌数据库测试持久化的 issue 已经解决。然而，我们仍然需要考虑测试的其他方面，例如模拟来自其他服务的 HTTP 响应或与服务发现集成。当你为微服务实现一些测试时，你可以选择服务发现的两种典型方法。第一种是在测试用例执行期间将发现服务器嵌入到应用程序中，第二种只是禁用在客户端上的发现。第二种选项通过 Spring Cloud 相对容易地进行配置。对于 Eureka Server，可以通过设置`eureka.client.enabled=false`属性来禁用它。

这只是练习的第一部分。我们还应该禁用 Ribbon 客户端的服务发现功能，它负责服务间通信的负载均衡。如果有多个目标服务，我们必须给每个客户端打上服务名称的标签。下面配置文件中最后一个属性的值`listOfServers`与用于自动化测试实现的框架密切相关。我将向你展示一个基于 Hoverfly Java 库的示例，该库在第七章《高级负载均衡和断路器》中已经介绍过，用于模拟调用目标服务时的延迟，以展示 Ribbon 客户端和 Hystrix 如何处理网络超时。在这里，我们只是使用它来返回预制的响应，使我们的组件测试涉及到网络通信。下面是配置文件的一个片段，其中包含负责禁用 Eureka 发现和设置 Ribbon 客户端测试属性的配置文件。该配置文件还应通过用`@ActiveProfiles`注解来激活测试类：

```java
---
spring:
 profiles: no-discovery
eureka:
 client:
  enabled: false
account-service:
 ribbon:
  eureka:
   enable: false
  listOfServers: account-service:8080
customer-service:
 ribbon:
  eureka:
   enable: false
  listOfServers: customer-service:8080
product-service:
 ribbon:
  eureka:
   enable: false
  listOfServers: product-service:8080
```

我不想深入讲解 Hoverfly 的使用细节，因为这在第七章《高级负载均衡和断路器》中已经讨论过了，*理查德·费曼*。正如你可能记得的，Hoverfly 可以通过声明`@ClassRule`和`HoverflyRule`来为 JUnit 测试激活，通过定义需要模拟的服务和端点的列表来实现。每个服务的名称必须与其在`listOfServers`属性中定义的地址相同。下面是一个定义 Hoverfly 测试规则的示例，该规则模拟来自三个不同服务的响应：

```java
@ClassRule
public static HoverflyRule hoverflyRule = HoverflyRule
 .inSimulationMode(dsl(
 service("account-service:8080")
 .put(startsWith("/withdraw/"))
 .willReturn(success("{\"id\":\"1\",\"number\":\"1234567890\",\"balance\":5000}", "application/json")),
 service("customer-service:8080")
 .get("/withAccounts/1")
 .willReturn(success("{\"id\":\"{{ Request.Path.[1] }}\",\"name\":\"Test1\",\"type\":\"REGULAR\",\"accounts\":[{\"id\":\"1\",\"number\":\"1234567890\",\"balance\":5000}]}", "application/json")),
 service("product-service:8080")
 .post("/ids").anyBody()
 .willReturn(success("[{\"id\":\"1\",\"name\":\"Test1\",\"price\":1000}]", "application/json"))))
 .printSimulationData();
```

# 实现示例测试

为了总结前两节所讲的内容，我们现在将准备一个使用内存内嵌入的 MongoDB、Hoverfly（用于模拟 HTTP 响应）和服务发现禁用的组件测试。专门为我们测试目的准备的正确配置设置位于`test`和`no-discovery`配置文件中。每个组件测试都是通过`TestRestTemplate`初始化的，它调用`order-service`的 HTTP 端点。测试结果的验证可以基于 HTTP 响应或存储在嵌入式 MongoDB 中的数据。下面是针对`order-service`的组件测试的一个示例实现：

```java
@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@ActiveProfiles({"test", "no-discovery"})
public class OrderComponentTest {

    @Autowired
    TestRestTemplate restTemplate;
    @Autowired
    OrderRepository orderRepository;

    // ...

    @Test
    public void testAccept() {
        Order order = new Order(null, OrderStatus.ACCEPTED, 1000, "1", "1", Collections.singletonList("1"));
        order = orderRepository.save(order);
        restTemplate.put("/{id}", null, order.getId());
        order = orderRepository.findOne(order.getId());
        Assert.assertEquals(OrderStatus.DONE, order.getStatus());
    }

    @Test
    public void testPrepare() {
        Order order = new Order(null, OrderStatus.NEW, 1000, "1", "1", Collections.singletonList("1"));
        order = restTemplate.postForObject("/", order, Order.class);
        Assert.assertNotNull(order);
        Assert.assertEquals(OrderStatus.ACCEPTED, order.getStatus());
        Assert.assertEquals(940, order.getPrice());
    }

}
```

# 集成测试

在创建单元和组件测试之后，我们已经验证了微服务中的所有功能。然而，我们仍然需要测试与其他服务、外部数据存储和缓存的交互。在基于微服务的架构集成测试中，测试的处理方式与单体应用程序中的处理方式不同。因为所有内部模块之间的关系都通过组件测试进行了测试，所以我们只测试了与外部组件交互的模块。

# 分类测试

把集成测试分离到 CI 管道中也是有意义的，这样外部故障就不会阻塞或破坏项目的构建。你应该通过用`@Category`注解标记它们来分类你的测试。你可以为集成测试创建一个特别的接口，例如`IntegrationTest`：

```java
public interface IntegrationTest  { }
```

然后，你可以使用`@Category`注解标记你的测试：

```java
@Category(IntegrationTest.class)
public class OrderIntegrationTest { ... }
```

最后，你可以配置 Maven 只运行选定的测试类型，例如，使用`maven-failsafe-plugin`：

```java
<plugin>
  <artifactId>maven-failsafe-plugin</artifactId>
  <dependencies>
    <dependency>
      <groupId>org.apache.maven.surefire</groupId>
      <artifactId>surefire-junit47</artifactId>
    </dependency>
  </dependencies>
  <configuration>
    <groups>pl.piomin.services.order.IntegrationTest</groups>
  </configuration>
  <executions>
    <execution>
      <goals>
        <goal>integration-test</goal>
      </goals>
      <configuration>
        <includes>
          <include>**/*.class</include>
        </includes>
      </configuration>
    </execution>
  </executions>
</plugin>
```

# 捕获 HTTP 流量

分类是处理自动化测试期间与外部微服务通信问题的方法之一。另一种流行的方法涉及记录外出请求和进入响应，以便在未来不建立与外部服务的连接的情况下使用它们。

在之前的示例中，我们只是使用了 Hoverfly 的模拟模式。然而，它也可以以捕获模式运行，这意味着请求将像往常一样发送到真实服务，但它们将被 Hoverfly 拦截、记录并存储在文件中。存储在 JSON 格式的捕获流量文件随后可以在模拟模式下使用。你可以在你的 JUnit 测试类中创建一个 Hoverfly 规则，如果模拟文件不存在，它将以捕获模式启动，如果存在，则以模拟模式启动。它总是存储在`src/test/resources/hoverfly`目录中。

这是一种简单的方法，用于打破对外部服务的依赖。例如，如果你知道那里没有发生变化，那么与真实服务交互就不是必要的。如果这样的服务被修改了，你可以删除 JSON 模拟文件，从而切换到捕获模式。如果你的测试失败了，这意味着修改影响到了你的服务，你需要在回到捕获模式之前进行一些修复。

这是一个位于`order-service`内的集成测试示例。它添加了一个新账户，然后调用从该账户取款的的方法。由于使用了`inCaptureOrSimulationMode`方法，只有在`account.json`文件不存在或你更改了传递给服务的输入数据时，才会调用真实服务：

```java
@RunWith(SpringRunner.class)
@SpringBootTest
@ActiveProfiles("dev")
@Category(IntegrationTest.class)
public class OrderIntegrationTest {

    @Autowired
    AccountClient accountClient;
    @Autowired
    CustomerClient customerClient;
    @Autowired
    ProductClient productClient;
    @Autowired
    OrderRepository orderRepository;

    @ClassRule
    public static HoverflyRule hoverflyRule = HoverflyRule.inCaptureOrSimulationMode("account.json").printSimulationData();

    @Test
    public void testAccount() {
        Account account = accountClient.add(new Account(null, "123", 5000));
        account = accountClient.withdraw(account.getId(), 1000);
        Assert.notNull(account);
        Assert.equals(account.getBalance(), 4000);
    }

}
```

# 合同测试

有一些有趣的工具专门用于合同测试。我们将通过查看最受欢迎的两个工具——Pact 和 Spring Cloud Contract——来讨论这个概念。

# 使用 Pact

正如我们已经在前面提到的，合同测试的主要概念是定义消费者和提供者之间的合同，然后独立地为每个服务验证它。由于创建和维护合同的责任主要在消费者端，这种类型的测试通常被称为消费者驱动的测试。在 Pact JVM 中，消费者和提供者端的分界是非常明显的。它提供了两个分离的库，第一个以`pact-jvm-consumer`为前缀，第二个以`pact-jvm-provider`为前缀。当然，合同是由消费者与提供商共同创建和维护的，这在下面的图表中已经说明：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/f33b5f96-1fa5-40cf-a968-da07cb4ad39e.png)

Pact 实际上是一组提供支持消费者驱动合同测试的框架集合。这些实现适用于不同的语言和框架。幸运的是，Pact 可以与 JUnit 和 Spring Boot 一起使用。考虑我们在示例系统中实现的一个集成，即`customer-service`和`account-service`之间的集成。名为`customer-service`的微服务使用 Feign 客户端与`account-service`进行通信。消费者端的 Feign 客户端定义实际上代表我们的合同：

```java
@FeignClient(name = "account-service")
public interface AccountClient {

    @GetMapping("/customer/{customerId}")
    List<Account> findByCustomer(@PathVariable("customerId") String customerId);

}
```

# 消费者端

要在消费者端启用带有 JUnit 支持的 Pact，请将以下依赖项包含在你的项目中：

```java
<dependency>
    <groupId>au.com.dius</groupId>
    <artifactId>pact-jvm-consumer-junit_2.12</artifactId>
    <version>3.5.12</version>
    <scope>test</scope>
</dependency>
```

现在我们只需要创建一个 JUnit 测试类。我们可以通过用`@SpringBootTest`注解它并使用 Spring Runner 运行它来实现一个标准的 Spring Boot 测试。为了成功执行创建的测试，我们首先需要禁用发现客户端，并确保 Ribbon 客户端将使用`@Rule` `PactProviderRuleMk2`与`account-service`的存根进行通信。测试的关键点是`callAccountClient`方法，它用`@Pact`注解并返回一个`RequestResponsePact`。它定义了请求的格式和响应的内容。在测试用例执行期间，Pact 会自动生成该定义的 JSON 表示，该表示位于`target/pacts/addressClient-customerServiceProvider.json`文件中。最后，在用`@PactVerification`注解的测试方法中调用 Feign 客户端实现的方法，并验证 Pact `@Rule`返回的响应。下面是针对`customer-service`的消费者端合同测试的一个示例实现：

```java
@RunWith(SpringRunner.class)
@SpringBootTest(properties = { 
 "account-service.ribbon.listOfServers: localhost:8092",
 "account-service.ribbon.eureka.enabled: false",
 "eureka.client.enabled: false",
})
public class CustomerConsumerContractTest {

    @Rule
    public PactProviderRuleMk2 stubProvider = new PactProviderRuleMk2("customerServiceProvider", "localhost", 8092, this);
    @Autowired
    private AccountClient accountClient;

    @Pact(state = "list-of-3-accounts", provider = "customerServiceProvider", consumer = "accountClient")
    public RequestResponsePact callAccountClient(PactDslWithProvider builder) {
        return builder.given("list-of-3-accounts").uponReceiving("test-account-service")
            .path("/customer/1").method("GET").willRespondWith().status(200)
            .body("[{\"id\":\"1\",\"number\":\"123\",\"balance\":5000},{\"id\":\"2\",\"number\":\"124\",\"balance\":5000},{\"id\":\"3\",\"number\":\"125\",\"balance\":5000}]", "application/json").toPact();
    }

    @Test
    @PactVerification(fragment = "callAccountClient")
    public void verifyAddressCollectionPact() {
        List<Account> accounts = accountClient.findByCustomer("1");
        Assert.assertEquals(3, accounts.size());
    }

}
```

在`target/pacts`目录中生成的 JSON 测试结果文件必须在提供者一侧可用。最简单的解决方案假设它可以通过使用`@PactFolder`注解来访问生成的文件。当然，这需要提供者能够访问`target/pacts`目录。尽管这对我们的示例有效，因为其源代码存储在同一个 Git 仓库中，但这不是我们的目标解决方案。幸运的是，我们可以使用 Pact Broker 在网络上发布 Pact 测试结果。Pact Broker 是一个提供 HTTP API 用于发布和消费 Pact 文件的存储库服务器。我们可以使用其 Docker 镜像启动 Pact Broker。它需要一个 Postgres 数据库作为后端存储，所以我们还需要启动带有 Postgres 的容器。以下是所需的 Docker 命令：

```java
docker run -d --name postgres -p 5432:5432 -e POSTGRES_USER=oauth -e POSTGRES_PASSWORD=oauth123 -e POSTGRES_DB=oauth postgres
docker run -d --name pact-broker --link postgres:postgres -e PACT_BROKER_DATABASE_USERNAME=oauth -e PACT_BROKER_DATABASE_PASSWORD=oauth123 -e PACT_BROKER_DATABASE_HOST=postgres -e PACT_BROKER_DATABASE_NAME=oauth -p 9080:80 dius/pact_broker
```

在 Docker 上运行 Pact Broker 后，我们必须在那里发布我们的测试报告。我们可以使用`pact-jvm-provider-maven_2.12`插件轻松地执行此操作。如果您运行`mvn clean install pack:publish`命令，所有放置在`/target/pacts`目录中的文件都将发送到代理的 HTTP API：

```java
<plugin>
    <groupId>au.com.dius</groupId>
    <artifactId>pact-jvm-provider-maven_2.12</artifactId>
    <version>3.5.12</version>
    <configuration>
        <pactBrokerUrl>http://192.168.99.100:9080</pactBrokerUrl>
    </configuration>
</plugin>
```

已发布 Pact 的完整列表可以通过在`http://192.168.99.100:9080`上可用的 web 控制台显示。它还提供了列表中每个 Pact 的最后验证日期和详细信息，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/55c94e0d-75da-45aa-a98f-2d8af546530e.png)

# 生产者一侧

假设消费者已经在代理上创建了一个 Pact 并发布了它，我们可以在提供者一侧继续实现验证测试。要在提供者一侧启用支持 Pact 的 JUnit，请在项目中包含`pact-jvm-provider-junit`依赖项。还有一个可用的框架，`pact-jvm-provider-spring`。这个库允许您使用 Spring 和 JUnit 对提供者运行合同测试。所需依赖项如下面的 Maven `pom.xml`片段所示：

```java
<dependency>
    <groupId>au.com.dius</groupId>
    <artifactId>pact-jvm-provider-junit_2.12</artifactId>
    <version>3.5.12</version>
    <scope>test</scope>
</dependency>
<dependency>
    <groupId>au.com.dius</groupId>
    <artifactId>pact-jvm-provider-spring_2.12</artifactId>
    <version>3.5.12</version>
    <scope>test</scope>
</dependency>
```

由于有专门针对 Spring 的库，我们可以使用`SpringRestPactRunner`而不是默认的`PactRunner`。这反过来又允许您使用 Spring 测试注解，如`@MockBean`。在下面的 JUnit 测试中，我们模拟了`AccountRepository`bean。它返回测试消费者一侧期望的三个对象。测试自动启动 Spring Boot 应用程序并调用`/customer/{customerId}`端点。还有另外两个重要的事情。通过使用`@Provider`和`@State`注解，我们需要在`@Pact`注解中设置与消费者一侧测试相同的名称。最后，通过在测试类上声明`@PactBroker`，我们提供了连接到 Pact 存储库的设置。以下是使用 Pact 的示例测试，验证由`customer-service`发布的合同：

```java
@RunWith(SpringRestPactRunner.class)
@Provider("customerServiceProvider")
@PactBroker(host = "192.168.99.100", port = "9080")
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.DEFINED_PORT, properties = { "eureka.client.enabled: false" })
public class AccountProviderContractTest {

    @MockBean
    private AccountRepository repository;
    @TestTarget
    public final Target target = new HttpTarget(8091);

    @State("list-of-3-accounts")
    public void toDefaultState() {
        List<Account> accounts = new ArrayList<>();
        accounts.add(new Account("1", "123", 5000, "1"));
        accounts.add(new Account("2", "124", 5000, "1"));
        accounts.add(new Account("3", "125", 5000, "1"));
        when(repository.findByCustomerId("1")).thenReturn(accounts);
    }

}
```

# 使用 Spring Cloud Contract

-   Spring Cloud Contract 在合同测试方面提出了与 Pack 略有不同的方法。在 Pack 中，消费者负责发布合同，而在 Spring Cloud Contract 中，这一行动的发起者是提供者。合同作为 JAR 存储在 Maven 仓库中，其中包含基于合同定义文件自动生成的存根。这些定义可以使用 Groovy DSL 语法创建。每个定义都包含两部分：请求和响应规格。基于这些文件，Spring Cloud Contract 生成 JSON 存根定义，这些定义由 WireMock 用于客户端方面的集成测试。与用作支持 REST API 的消费者驱动合同测试工具的 Pact 相比，它特别设计用于测试基于 JVM 的微服务。它包含三个子项目：

+   -   Spring Cloud Contract Verifier

+   Spring Cloud Contract Stub Runner

+   -   Spring Cloud Contract WireMock

-   让我们分析如何根据之前在 Pact 框架部分描述的相同示例来使用它们进行合同测试。

-   WireMock 是一个基于 HTTP 的 API 模拟器。有些人可能认为它是一个服务虚拟化工具或模拟服务器。它可以通过捕获现有 API 的流量快速启动。

# -   定义合同并生成存根

-   正如我已经在前面提到的，与 Pact 相比，在 Spring Cloud Contract 中，提供者（服务器端）负责发布合同规格。因此，我们将从`account-service`开始实现，该服务是`customer-service`调用的端点。但在继续实现之前，看看下面的图表。它描述了在我们测试过程中参与的主要组件。示例应用程序的源代码可在 GitHub 仓库中的上一个示例的不同分支 contract 中找到：

-   ![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/03bc1e16-89eb-4c5a-bc68-a00382569392.png)

-   为了在提供者端应用程序中启用 Spring Cloud Contract 的功能，首先你必须将 Spring Cloud Contract Verifier 添加到你的项目依赖中：

```java
<dependency>
    <groupId>org.springframework.cloud</groupId>
    <artifactId>spring-cloud-starter-contract-verifier</artifactId>
    <scope>test</scope>
</dependency>
```

-   下一步是添加 Spring Cloud Contract Verifier Maven 插件，该插件生成并运行你的合同测试。它还会生成并安装存根到本地 Maven 仓库中。你必须为它定义的唯一参数是生成的测试类所扩展的基本类所在的包：

```java
<plugin>
    <groupId>org.springframework.cloud</groupId>
    <artifactId>spring-cloud-contract-maven-plugin</artifactId>
    <version>1.2.0.RELEASE</version>
    <extensions>true</extensions>
    <configuration>
        <packageWithBaseClasses>pl.piomin.services.account</packageWithBaseClasses>
    </configuration>
</plugin>
```

现在，我们必须为合同测试创建一个基类。它应该放在`pl.piomin.services.account`包内。在下面的基类中，我们用`@SpringBootTest`设置了 Spring Boot 应用程序，然后模拟了`AccountRepository`。我们还使用`RestAssured`来模拟 Spring MVC，只向我们的控制器发送请求。由于所有的模拟，测试不与任何外部组件（如数据库或 HTTP 端点）交互，只测试合同：

```java
@RunWith(SpringRunner.class)
@SpringBootTest(classes = {AccountApplication.class})
public abstract class AccountProviderTestBase {

    @Autowired
    private WebApplicationContext context;
    @MockBean
    private AccountRepository repository;

    @Before
    public void setup() {
        RestAssuredMockMvc.webAppContextSetup(context);
        List<Account> accounts = new ArrayList<>();
        accounts.add(new Account("1", "123", 5000, "1"));
        accounts.add(new Account("2", "124", 5000, "1"));
        accounts.add(new Account("3", "125", 5000, "1"));
        when(repository.findByCustomerId("1")).thenReturn(accounts);
    }

}
```

我们已经提供了所有运行与 Spring Cloud Contract 一起的测试所需的配置和基类。因此，我们可以进行最重要的部分，使用 Spring Cloud Contract Groovy DSL 定义合同。所有合同的规格都应该位于`/src/test/resources/contracts`目录下。这个目录下具体的位置，包含存根定义，被视为基测试类名。每个存根定义代表一个单独的合同测试。根据这个规则，`spring-cloud-contract-maven-plugin`会自动找到合同并将其分配给基测试类。在我们当前讨论的示例中，我把我的存根定义放在了`/src/test/resources/contracts/accountService`目录下。因此生成的测试类名是`AccountServiceTest`，并且它也继承了`AccountServiceBase`类。

这是返回属于客户账户列表的示例合同规格。这个合同并不简单，所以有些东西需要解释。你可以使用正则表达式来编写你的请求 Contract DSL。你还可以为每个属性提供不同的值，这取决于通信方（消费者或生产者）。Contract DSL 还允许你通过使用`fromRequest`方法来引用请求。下面的合同返回了三个账户列表，从请求路径中获取`customerId`字段和由五位数字组成的`id`字段：

```java
org.springframework.cloud.contract.spec.Contract.make {
 request {
  method 'GET'
  url value(consumer(regex('/customer/[0-9]{3}')), producer('/customer/1'))
 }
 response {
  status 200
  body([
   [
    id: $(regex('[0-9]{5}')),
    number: '123',
    balance: 5000,
    customerId: fromRequest().path(1)
   ], [
    id: $(regex('[0-9]{5}')),
    number: '124',
    balance: 5000,
    customerId: fromRequest().path(1)
   ], [
    id: $(regex('[0-9]{5}')),
    number: '125',
    balance: 5000,
    customerId: fromRequest().path(1)
   ]
  ])
  headers {
   contentType(applicationJson())
  }
 }
}
```

测试类在 Maven 构建的测试阶段会在`target/generated-test-sources`目录下生成。下面是早先描述的合同规格生成的类：

```java
public class AccountServiceTest extends AccountServiceBase {

    @Test
    public void validate_customerContract() throws Exception {

        // given:
        MockMvcRequestSpecification request = given();

        // when:
        ResponseOptions response = given().spec(request)
 .get("/customer/1");

        // then:
        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.header("Content-Type")).matches("application/json.*");

        // and:
        DocumentContext parsedJson = JsonPath.parse(response.getBody().asString());
        assertThatJson(parsedJson).array().contains("['number']").isEqualTo("123");
        assertThatJson(parsedJson).array().contains("['balance']").isEqualTo(5000);
        assertThatJson(parsedJson).array().contains("['number']").isEqualTo("124");
        assertThatJson(parsedJson).array().contains("['customerId']").isEqualTo("1");
        assertThatJson(parsedJson).array().contains("['id']").matches("[0-9]{5}");
     }

 }
```

# 在消费者侧验证合同

假设我们已经成功在提供者侧构建并运行了测试，存根将会被生成，然后发布在我们的本地 Maven 仓库中。为了能够在消费者应用程序测试时使用它们，我们应该将 Spring Cloud Contract Stub Runner 添加到项目依赖中：

```java
<dependency>
    <groupId>org.springframework.cloud</groupId>
    <artifactId>spring-cloud-starter-contract-stub-runner</artifactId>
    <scope>test</scope>
</dependency>
```

然后我们应该用`@AutoConfigureStubRunner`注解我们的测试类。它接受两个输入参数—`ids`和`workOffline`。`Ids`字段是`artifactId`、`groupId`、版本号、`stubs`限定符和端口号的组合，通常指出提供者发布的存根的 JAR。`workOffline`标志指示存根仓库的位置。默认情况下，消费者尝试自动从 Nexus 或 Artifactory 下载工件。如果你想要强制 Spring Cloud Contract Stub Runner 只从本地 Maven 仓库下载存根，可以将`workOffline`参数的值切换为`true`。

以下是一个使用 Feign 客户端调用由提供方发布的存根的端点的 JUnit 测试类。Spring Cloud Contract 查找`pl.piomin.services:account-service`工件的最新版本。这通过在`@AutoConfigureStubRunner`注解中传递`+`作为存根的版本来指示。如果你想要使用该工件的具体版本，你可以在`pom.xml`文件中设置当前版本而不是`+`，例如，`@AutoConfigureStubRunner(ids = {"pl.piomin.services:account-service:1.0-SNAPSHOT:stubs:8091"})`：

```java
@RunWith(SpringRunner.class)
@SpringBootTest(properties = {
 "eureka.client.enabled: false"
})
@AutoConfigureStubRunner(ids = {"pl.piomin.services:account-service:+:stubs:8091"}, workOffline = true)
public class AccountContractTest {

    @Autowired
    private AccountClient accountClient;

    @Test
    public void verifyAccounts() {
        List<Account> accounts = accountClient.findByCustomer("1");
        Assert.assertEquals(3, accounts.size());
    }

}
```

剩下要做的就是使用`mvn clean install`命令来构建整个项目，以验证测试是否成功运行。然而，我们应该记住，之前创建的测试只覆盖了`customer-service`和`account-service`之间的集成。在我们的示例系统中，还有其他一些微服务之间的集成应该被验证。我会再给你一个例子，它测试了整个系统。它测试了`order-service`中暴露的方法，该服务与其他所有微服务进行通信。为此，我们将使用 Spring Cloud Contract 场景的另一个有趣特性。

# 场景

使用 Spring Cloud Contract 定义场景并不困难。你只需要在做合同创建时提供合适的命名约定。这个约定假设每个场景中的合同名称都由一个序号和一个下划线前缀。一个场景中包含的所有合同必须位于同一个目录中。Spring Cloud Contract 场景基于 WireMock 的场景。以下是一个包含为创建和接受订单需求定义的合同的目录结构：

```java
src\main\resources\contracts
 orderService\
  1_createOrder.groovy
  2_acceptOrder.groovy
```

以下是为此场景生成的测试源代码：

```java
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class OrderScenarioTest extends OrderScenarioBase {

    @Test
    public void validate_1_createOrder() throws Exception {
        // ...
    }

    @Test
    public void validate_2_acceptOrder() throws Exception {
        // ...
    }

}
```

现在，让我们想象一下我们有很多微服务，其中大多数都与其他一个或多个微服务进行通信。所以，即使你测试了一个单一的合约，你也不能确保所有其他在服务间通信过程中的合约都能如预期般工作。然而，借助 Spring Cloud Contract，你完全可以轻松地将所有必需的存根（stubs）包含到你的测试类中。这赋予了你验证所有合约在定义场景中的能力。为此，你必须将`spring-cloud-starter-contract-verifier`和`spring-cloud-starter-contract-stub-runner`这两个依赖项包含到项目中。下面的类定义作为 Spring Cloud Contract 测试类的基类，并包含了由其他微服务生成的存根。为`order-service`端点生成的存根可以被任何其他需要与`order-service`验证合约的外部服务使用。如下面的测试代码不仅会验证本服务与`order-service`之间的合约，还会验证`order-service`与其他被该服务使用的服务之间的合约：

```java
@RunWith(SpringRunner.class)
@SpringBootTest(properties = {
    "eureka.client.enabled: false"
})
@AutoConfigureStubRunner(ids = {
        "pl.piomin.services:account-service:+:stubs:8091",
        "pl.piomin.services:customer-service:+:stubs:8092",
        "pl.piomin.services:product-service:+:stubs:8093"
}, workOffline = true)
public class OrderScenarioBase {

    @Autowired
    private WebApplicationContext context;
    @MockBean
    private OrderRepository repository;

    @Before
    public void setup() {
        RestAssuredMockMvc.webAppContextSetup(context);
        when(repository.countByCustomerId(Matchers.anyString())).thenReturn(0);
        when(repository.save(Mockito.any(Order.class))).thenAnswer(new Answer<Order>() {
            @Override
            public Order answer(InvocationOnMock invocation) throws Throwable {
                Order o = invocation.getArgumentAt(0, Order.class);
                o.setId("12345");
                return o;
            }
        });
    }

}
```

# 性能测试

我们还需要讨论一种自动化测试的最后类型。在本章的开头已经提到了它。我当然是在谈论性能测试。有一些非常有趣的工具和框架可以帮助你创建和运行这类测试。如果我们谈论的是 HTTP API 测试，特别是在仪器选择上有很多选择。我不想讨论它们全部，但我将讨论一个可能会有帮助的框架。它就是 Gatling。让我们更仔细地看看它。

# Gatling

Gatling 是一个用 Scala 编写的开源性能测试工具。它允许你使用一种易于阅读和编写的**领域特定语言**（**DSL**）来开发测试。它通过生成详尽、图表化的负载报告，展示了测试过程中收集的所有指标，从而区别于其他竞争对手。还有插件可用于将 Gatling 与 Gradle、Maven 和 Jenkins 集成。

# 启用 Gatling

为了使项目启用 Gatling 框架，我们应该在依赖项中包含`io.gatling.highcharts:gatling-charts-highcharts`这个构件。

# 定义测试场景

每个 Gatling 测试套件都应该扩展`Simulation`类。在每一个测试类中，我们可以使用 Gatling Scala DSL 声明一系列场景。我们通常会声明可以同时调用 HTTP 端点的线程数以及每个线程发送的请求总数。在 Gatling 的术语中，线程数是由使用`atOnceUsers`方法设置的用户数决定的。测试类应该放在`src/test/scala`目录中。

假设我们想要测试由`order-service`暴露的两个端点，在该服务上运行 20 个客户端，每个客户端按顺序发送 500 个请求，总共将发送 20,000 个请求。通过在短时间内发送它们全部，我们能够测试我们应用程序的性能。

下面的测试场景是用 Scala 编写的。让我们仔细看看。在运行这个测试之前，我通过调用`account-service`和`product-service`暴露的 HTTP API 创建了一些账户和产品。因为它们连接到一个外部数据库，所以 ID 是自动生成的。为了提供一些测试数据，我将它们复制到了测试类中。账户和产品 ID 的列表都被传递到测试场景作为数据源。然后，在每次迭代中，都会从列表中随机选择所需值。我们的测试场景名为`AddAndConfirmOrder`。它由两个`exec`方法组成。第一个方法通过调用`POST /order`HTTP 方法创建一个新订单。订单 ID 由服务自动生成，因此应该作为属性保存。然后，它可以用在下一个`exec`方法中，通过调用`PUT /order/{id}`端点确认订单。测试后验证的唯一事情是 HTTP 状态：

```java
class OrderApiGatlingSimulationTest extends Simulation {

    val rCustomer = Iterator.continually(Map("customer" -> List("5aa8f5deb44f3f188896f56f", "5aa8f5ecb44f3f188896f570", "5aa8f5fbb44f3f188896f571", "5aa8f620b44f3f188896f572").lift(Random.nextInt(4)).get))
    val rProduct = Iterator.continually(Map("product" -> List("5aa8fad2b44f3f18f8856ac9","5aa8fad8b44f3f18f8856aca","5aa8fadeb44f3f18f8856acb","5aa8fae3b44f3f18f8856acc","5aa8fae7b44f3f18f8856acd","5aa8faedb44f3f18f8856ace","5aa8faf2b44f3f18f8856acf").lift(Random.nextInt(7)).get))

    val scn = scenario("AddAndConfirmOrder").feed(rCustomer).feed(rProduct).repeat(500, "n") {
        exec(
            http("AddOrder-API")
                .post("http://localhost:8090/order")
                .header("Content-Type", "application/json")
                .body(StringBody("""{"productIds":["${product}"],"customerId":"${customer}","status":"NEW"}"""))
                .check(status.is(200), jsonPath("$.id").saveAs("orderId"))
        )
        .
        exec(
            http("ConfirmOrder-API")
                .put("http://localhost:8090/order/${orderId}")
                .header("Content-Type", "application/json")
                .check(status.is(200))
        )
    }

    setUp(scn.inject(atOnceUsers(20))).maxDuration(FiniteDuration.apply(10, "minutes"))

}
```

# 运行一个测试场景

有几种不同的方法可以在你的机器上运行 Gatling 性能测试。其中一种是通过可用的 Gradle 插件之一，它提供在项目构建过程中运行测试的支持。你也可以使用 Maven 插件，或者尝试从你的 IDE 中运行它。如果你用 Gradle 构建你的项目，你还可以定义简单的任务，只需通过启动`io.gatling.app.Gatling`主类来运行测试。下面是在`gradle.build`文件中此类任务的定义：

```java
task loadTest(type: JavaExec) {
    dependsOn testClasses
    description = "Load Test With Gatling"
    group = "Load Test"
    classpath = sourceSets.test.runtimeClasspath
    jvmArgs = [
        "-Dgatling.core.directory.binaries=${sourceSets.test.output.classesDir.toString()}"
    ]
    main = "io.gatling.app.Gatling"
    args = [
        "--simulation", "pl.piomin.services.gatling.OrderApiGatlingSimulationTest",
        "--results-folder", "${buildDir}/gatling-results",
        "--binaries-folder", sourceSets.test.output.classesDir.toString(),
        "--bodies-folder", sourceSets.test.resources.srcDirs.toList().first().toString() + "/gatling/bodies",
    ]
}
```

现在你可以通过调用`gradle loadTest`命令来运行该任务。当然，在运行这些测试之前，你需要启动所有示例微服务、MongoDB 和`discovery-service`。默认情况下，Gatling 会打印发送的所有请求、收到的响应以及最终的测试结果，包括时间统计和成功与失败的 API 调用次数。如果你需要更详细的信息，你应该参考测试后生成的文件，这些文件可以在`build/gatling-results`目录下找到。你可能会发现那里的 HTML 文件以图表和图形的形式提供了可视化。其中的第一个（如图所示）显示了生成的请求总数以及按百分位数划分的最大响应时间。例如，你可能看到`AddOrder` API 的 95%响应中的最大响应时间是 835 毫秒：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/b0a26700-2d21-4154-a8c2-59a74a404800.png)

还有一些其他有趣的统计数据进行了可视化。让我们特别关注以下两个报告。第一个报告显示了一个图表，显示按平均响应时间分组的请求百分比，而第二个报告则显示了按百分位数显示的平均响应时间的时间线：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/94bc93b4-1e8f-465f-9ff6-ba27c5f7f418.png)

# 总结

在本章中，我介绍了一些框架，这些框架可以帮助您有效地测试用 Java 编写的基于 REST 的应用程序。每个解决方案都被分配到一种特定的测试类型。我专注于与微服务直接相关的测试，例如契约测试和组件测试。本章的主要目标是比较两种最流行的用于契约测试的框架，即 Pact 和 Spring Cloud Contract。尽管它们看起来很相似，但实际上它们之间有一些显著的区别。我试图向您展示基于我们在前几章中查看的相同示例应用程序的最重要相似之处和差异。

微服务与自动化密切相关。请记住，从单体迁移到微服务为您提供了一个机会来重构您的代码，而且更重要的是，提高自动化测试的质量和代码覆盖率。当一起使用时，如 Mockito、Spring Test、Spring Cloud Contract 和 Pact 这样的框架为您提供了一个非常强大的解决方案，用于开发基于 REST 的 Java 微服务的测试。自动化测试是 CI/CD 过程的一个重要组成部分，下一章将讨论这一点。


# 第十四章：Docker 支持

我们已经在本书的第一部分讨论了微服务架构的基础和 Spring Cloud 项目。在第二部分中，我们研究了该架构的最常见元素，并讨论了如何使用 Spring Cloud 实现它们。到目前为止，我们已经谈到了与微服务迁移有关的一些重要主题，例如集中日志记录、分布式追踪、安全和自动化测试。现在，由于我们掌握了这些知识，我们可以继续讨论书的最后一部分，那里我们将讨论微服务作为一种云原生开发方法的真正力量。使用容器化工具将应用程序彼此隔离、在软件交付过程中实现持续部署以及轻松扩展应用程序的能力，所有这些都有助于微服务的迅速普及。

正如您可能还记得早前的章节，我们使用了 Docker 镜像在本地机器上运行第三方工具和解决方案。有了这个前提，我想向您介绍 Docker 的主要概念，比如其基本命令和使用场景。这些信息将帮助您运行前几章中呈现的示例。然后，我们将讨论如何使用我们的示例 Spring Boot 应用程序来构建镜像，以及如何在本地机器上的容器内运行它们。为此，我们将使用简单的 Docker 命令，以及更高级的工具，如 Jenkins 服务器，它帮助您执行完整的、持续的交付，并在您的组织中启用持续集成流程。最后，我们将介绍用于自动化部署、扩展和管理容器化应用程序的最受欢迎的工具之一：Kubernetes。我们所有的示例都将在通过 Minikube 运行的单节点 Kubernetes 集群上本地运行。

本章我们将覆盖的主题如下：

+   最有用的 Docker 命令

+   使用 Spring Boot 微服务构建 Docker 容器

+   在 Docker 上运行 Spring Cloud 组件

+   使用 Jenkins 和 Docker 进行持续集成/持续交付

+   在 Minikube 上部署和运行微服务

# 介绍 Docker

Docker 是一个帮助你通过容器创建、部署和运行应用程序的工具。它旨在根据 DevOps 哲学，同时造福开发人员和系统管理员。Docker 通过解决与软件交付相关的一些重要问题来改进软件交付过程。其中一个关注点是不可变交付的概念，这与所谓的“**对我有效**”有关。当在 Docker 中工作时，尤其是重要的，开发者使用与生产中相同的镜像进行测试。唯一应该看到的不同是在配置上。在不可变交付模式下，软件交付对于微服务基础系统尤为重要，因为有很多独立部署的应用程序。多亏了 Docker，开发者现在可以专注于编写代码，而不用担心目标操作系统（应用程序将被启动的地方）。因此，操作人员可以使用相同的接口来部署、启动和维护所有应用程序。

还有许多其他原因促使 Docker 越来越受欢迎。毕竟，容器化概念在信息技术世界中并不是什么新事物。Linux 容器多年前就已经被引入，并自 2008 年起成为内核的一部分。然而，Docker 引入了几项其他技术和解决方案，这是其他技术所没有的。首先，它提供了一个简单的接口，允许你轻松地将应用程序及其依赖打包到一个容器中，然后在不同的 Linux 内核版本和实现中运行。容器可以在本地或远程的任何启用了 Docker 的服务器上运行，每个容器都在几秒钟内启动。我们还可以轻松地在容器外部对其执行每个命令。此外，Docker 镜像的共享和分发机制允许开发人员像分享源代码一样提交更改、推送和拉取镜像，例如使用 Git。目前，几乎所有最受欢迎的软件工具都在 Docker 中心以镜像的形式发布，有些我们已经成功用于运行我们样本应用程序所需的工具。

有一些基本的定义和元素构成了 Docker 架构，最重要的是容器。容器在单一机器上运行，并与该机器共享操作系统内核。它们包含运行特定软件所需的一切，包括运行时、系统工具、系统库和设置。容器是由 Docker 镜像中发现的指令创建的。镜像就像一种食谱或模板，定义了在容器上安装和运行必要软件的步骤。容器还可以与虚拟机相比较，因为它们具有类似的资源隔离和分配优势。然而，它们虚拟化操作系统而不是硬件，使它们比虚拟机更便携、更高效。以下图表展示了 Docker 容器与虚拟机之间的架构差异：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/5c4496c4-a46a-4400-a77d-9e5fff6d99ca.png)

所有容器都部署在一个称为**Docker 主机**的物理或虚拟机上。Docker 主机反过来运行一个 Docker 守护进程，该守护进程通过 Docker API 监听 Docker 客户端发送的命令。Docker 客户端可能是命令行工具或其他软件，如 Kinematic。除了运行守护进程，Docker 主机还负责存储从这些镜像创建的缓存镜像和容器。每个镜像都是由一系列层构建的。每个层仅包含与父层相比的增量差异。这样的镜像不是很小，需要存储在其他地方。这个地方称为**Docker 仓库**。你可以创建自己的私有仓库，或者使用网络上的现有公共仓库。最受欢迎的仓库是 Docker Hub，其中包含几乎所有必需的镜像。

# 安装 Docker

Linux 下的 Docker 安装步骤因发行版而异([`docs.docker.com/install/#supported-platforms`](https://docs.docker.com/install/#supported-platforms))。然而，有时在安装后你不得不运行 Docker 守护进程，你可以通过调用以下命令来实现：

```java
dockerd --host=unix:///var/run/docker.sock --host=tcp://0.0.0.0:2375
```

在本节中，我们将重点关注 Windows 平台的指令。通常，当你在 Windows 或 Mac 上安装 Docker Community Edition (CE)时有两种可用的选项。最快最简单的方法是使用 Docker for Windows，你可以在[`www.docker.com/docker-windows`](https://www.docker.com/docker-windows)找到它。这是一个原生的 Windows 应用程序，为构建、部署和运行容器化应用程序提供了易于使用的开发环境。这绝对是利用最好的选择，因为它使用了 Windows 本地的 Hyper-V 虚拟化和网络。然而，有一个缺点——它仅适用于 Microsoft Windows 10 专业版或企业版 64 位。更早的 Windows 版本应该使用 Docker Toolbox，你可以在[`docs.docker.com/toolbox/toolbox_install_windows/`](https://docs.docker.com/toolbox/toolbox_install_windows/)下载到它。这包括 Docker 平台、带有 Docker Machine 的命令行、Docker Compose、Kitematic 和 VirtualBox。请注意，你不能在 Windows 上使用 Docker Toolbox 本地运行 Docker Engine，因为它使用了特定于 Linux 的内核功能。相反，你必须使用 Docker Machine 命令（`docker-machine`），它在本机上创建一个 Linux 虚拟机，并使用 Virtual Box 运行它。这个虚拟机可以通过默认的虚拟地址`192.168.99.100`被你的机器访问。所有之前讨论的示例都是与那个 IP 地址上可用的 Docker 工具集成的。

# 常用的 Docker 命令

在 Windows 上安装 Docker Toolbox 后，你应该运行 Docker 快速启动终端。它会完成所有需要做的事情，包括创建和启动 Docker Machine 以及提供命令行界面。如果你输入一个没有参数的 Docker 命令，你现在应该能够看到完整的可用 Docker 客户端命令列表及其描述。我们将要查看的就是这类命令：

+   运行和停止容器

+   列出并删除容器

+   拉取和推送镜像

+   构建镜像

+   网络配置

# 运行和停止容器

安装后通常运行的第一个 Docker 命令是`docker run`。正如您可能记得的，这个命令在前面的示例中是最常用的命令之一。这个命令做两件事：它从注册表中拉取和下载镜像定义，以防它没有在本地缓存，然后启动容器。对这个命令可以设置很多选项，您可以通过运行`docker run --help`来轻松查看这些选项。有些选项有一个字母的简写，这些通常是使用最频繁的选项。选项`–d`让容器在后台运行，而`–i`即使在未附加的情况下也保持`stdin`打开。如果您需要在容器外部暴露任何端口，您可以使用带有定义`<port_outside_container>:<port_inside_container>`的激活选项`–p`。一些镜像需要额外的配置，这通常通过环境变量完成，这些环境变量可以通过`–e`选项覆盖。为了轻松运行其他命令，设置容器的好友名称也很有用，使用`--name`选项。看看这里可见的示例 Docker 命令。它启动了带有 Postgres 的容器，创建了一个具有密码的数据库用户，并在端口`55432`上暴露它。现在，Postgres 数据库可以在地址`192.168.99.100:55432`上访问：

```java
$ docker run -d --name pg -e POSTGRES_PASSWORD=123456 -e POSTGRES_USER=piomin -e POSTGRES_DB=example -p 55432:5432 postgres
```

带有 Postgres 的容器持久化数据。建议通过卷机制来存储外部应用程序访问的数据的容器。可以通过`–v`选项将卷传递给容器，其中值由冒号分隔的字段组成，`:`。第一个字段是卷的名称，第二个字段是在容器中挂载文件或目录的路径。下一个有趣的选项是使用`–m`选项限制容器分配的最大 RAM 量。以下是为新卷创建并挂载到启动的容器的命令。最大 RAM 设置为 500 MB。容器在停止后自动删除，使用激活的选项`--rm`，如下所示：

```java
$ docker volume create pgdata
$ docker run --rm -it -e -m 500M -v pgdata:/var/lib/postgresql/data -p 55432:5432 postgres
```

每个运行中的容器都可以使用`docker stop`命令来停止。我们已经为我们的容器设置了一个名字，因此我们可以很容易地将其作为标签使用，如下所示：

```java
$ docker stop pg
```

容器的整个状态都会写入磁盘，因此我们可以用完全相同的数据再次运行它，例如：

```java
$ docker start pg
```

如果您只想重新启动容器，而不是停止/启动容器，您可以使用以下命令：

```java
$ docker restart  pg
```

# 列出和删除容器

如果你已经启动了一些容器，你可能想考虑显示你 Docker 机器上所有正在运行的容器列表。应该使用`docker ps`命令来实现。这个命令显示关于容器的一些基本信息，比如暴露的端口列表和源镜像的名称。这个命令只打印当前启动的容器。如果你想看到已停止或未活跃的容器，请在 Docker 命令中使用`-a`选项，如下所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/cce5a0a7-6103-4def-af56-718b3cd98812.png)

如果一个容器不再需要，可以使用`docker rm`命令将其删除。有时你可能需要删除一个正在运行的容器，但默认情况下这是不允许的。要强制这个选项，请在 Docker 上使用以下命令设置`-f`选项：

```java
$ docker rm -f pg
```

你应该记得`docker ps`命令只删除容器。它创建的镜像仍然在本地下缓存。这类镜像可能会占用相当大的空间，从兆字节到几百兆字节不等。你可以使用以下参数使用`docker rmi`命令删除每个镜像：

```java
$ docker rmi 875263695ab8
```

我们还没有创建任何 Docker 镜像，但在创建镜像过程中很容易产生大量不需要或未命名的镜像。这些镜像很容易识别，因为它们的名称是`<none>`。在 Docker 的术语中，这些被称为**悬空镜像**，可以通过以下命令轻松删除。当前缓存的所有镜像列表可以使用`docker images`命令显示，如下所示：

```java
$ docker rmi $(docker images -q -f dangling=true)
```

# 拉取和推送镜像

我们已经讨论过 Docker Hub。它是网络上最大的最受欢迎的 Docker 仓库。它位于[`hub.docker.com`](https://hub.docker.com)。Docker 客户端默认会尝试拉取该仓库的所有镜像。有许多经过认证的官方镜像，如 Redis、Java、Nginx 或 Mongo，但您也可以找到数十万人创建的镜像。如果您使用`docker run`命令，则镜像会在本地没有缓存的情况下从仓库拉取。您还可以运行以下`docker pull`命令，它只负责下载镜像：

```java
$ docker pull postgres
```

前一个命令下载了一个镜像的最新版本（具有最新标签的名称）。如果你想要使用一个较老版本的 Postgres Docker 镜像，你应该在标签后加上具体版本的数字。通常，可用的所有版本列表会发布在镜像的网站上，这个情况也不例外。访问[`hub.docker.com/r/library/postgres/tags/`](https://clicktime.symantec.com/a/1/Im1LdWl8NQ4ddISjfwL_OxcUojdkW-H3fP-oquj1vZs=?d=zKV7R9H5uhYC7J5kAN4WlSdYuV7w56mec0MwOxbVt-onFGmsM6Sx37HIaVHJUb3QiEeB2UoRmfzGJLL2nbKFa0anD4Lnn9-ximh393HGo36BjpeP0FoTIe_ikOi5QeJ1AeoMYVgQp_eESUZZNBRlDtcfYxSSkGpgZ_sGge1ts1DBD0AiZXddlCKygZL3ttJma9imoX-dIYGhyIi7l13N-8Y_5N5OYuthQeHXR4cE3e6ZicVVMyrnPGOm4nPLOHZiFzLZsTnDT0QQgFKRuqd4dsZekUaglgG9Y90wlN16gLc1DewmmCqRs_KiE1hwsBfCnFIku3QSPBvVa8e7YWJmMEGwuCxlybf2ywMx81HkC4uMHvQfq1EiVA0PYg5arA%3D%3D&u=https%3A%2F%2Fhub.docker.com%2Fr%2Flibrary%2Fpostgres%2Ftags%2F)获取可用标签的列表。

```java
$ docker pull postgres:9.3
```

一旦你运行并验证了你的镜像，你应该考虑将其远程保存。当然，最合适的地方是 Docker Hub。然而，有时你可能想将镜像存储在其他存储中，比如私有仓库。在推送镜像之前，你必须使用你的注册表用户名、镜像名称和其版本号来标记它。以下命令从 Postgres 源镜像创建了一个名为`piomin/postgres`和`1.0`版本标签的新镜像：

```java
$ docker tag postgres piomin/postgres:1.0
```

现在，如果你运行`docker images`命令，你会发现有两个具有相同 ID 的镜像。第一个镜像的名称是 Postgres，并且是最新的标签，而第二个镜像的名称是`piomin/postgres`，标签是`1.0`。重要的是`piomin`是我的 Docker Hub 用户名。因此，在进一步操作之前，我们首先应该在那里注册这个镜像。之后，我们还应该使用`docker login`命令登录到我们的 Docker 客户端。在这里，系统会提示你输入用户名、密码和用于注册的电子邮件地址。最后，你可以使用以下`docker push`命令推送一个带标签的镜像：

```java
$ docker push piomin/postgres:1.0
```

现在剩下的所有事情就是使用网络浏览器登录到你的 Docker Hub 账户，以检查推送到那里的镜像是否出现。如果一切工作正常，你将在网站上看到一个新的公开仓库和你的镜像。下面的屏幕截图显示了我 Docker Hub 账户中当前推送的镜像：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/8ab7815a-c6bc-47e4-bc66-9c939ad920e2.png)

# 构建镜像

在上一节中，我们将 Postgres 的 Docker 镜像副本推送到 Docker Hub 仓库。通常，我们会将基于文件`Dockerfile`创建的自己的镜像推送到仓库，`Dockerfile`中定义了安装和配置软件所需的所有指令。关于`Dockerfile`结构的细节将在后面讨论。现在重要的是构建 Docker 镜像时使用的命令，即`docker build`。这个命令应该在`Dockerfile`所在的同一个目录中运行。构建新镜像时，建议使用`-t`选项为其设置名称和标签。以下命令创建了名为`piomin/order-service`的镜像，版本标记为`1.0`。您可以像之前推送 Postgres 镜像一样，将此镜像推送到您的 Docker Hub 账户中，如下所示：

```java
$ docker build -t piomin/order-service:1.0 .
```

# 网络配置

网络配置是 Docker 架构的一个重要方面，因为我们必须经常在不同容器上运行的应用程序之间提供通信。一个常见的用例可能是一个需要访问数据库的 web 应用程序。现在我们将参考在第十一章中已经介绍过的另一个例子，即*消息驱动的微服务*。这是 Apache Kafka 与 ZooKeeper 之间的通信。Kafka 需要 ZooKeeper，因为它将各种配置作为键/值对存储在 ZK 数据树中，并在整个集群中使用它。正如您可能记得的，我们首先必须创建一个自定义网络并在那里运行这两个容器。以下命令用于在 Docker 主机上创建一个用户定义的网络：

```java
$ docker network create kafka-network
```

在上一个命令运行完成后，您可以使用以下命令查看可用的网络列表。默认情况下，Docker 为您创建了三个网络，所以您应该看到四个网络，名称分别为 bridge、host、none 和`kafka-network`：

```java
$ docker network ls
```

下一步是向使用`docker run`命令创建的容器传递网络名称。这可以通过`--network`参数实现，正如您在以下示例中看到的那样。如果您为两个不同的容器设置相同的网络名称，它们将在同一个网络中启动。让我们实际分析一下这意味着什么。如果您在一个容器内，可以用它的名字而不是 IP 地址来调用它，这就是为什么在启动带有 Apache Kafka 的容器时，我们可以将环境变量`ZOOKEEPER_IP`设置为 ZooKeeper 的原因。Kafka 在这个容器内启动，如下所示连接到默认端口的 ZooKeeper 实例：

```java
$ docker run -d --name zookeeper --network kafka-net zookeeper:3.4
$ docker run -d --name kafka --network kafka-net -e ZOOKEEPER_IP=zookeeper ches/kafka
```

# 创建带有微服务的 Docker 镜像

我们已经讨论了可用于运行、创建和管理容器的基本 Docker 命令。现在是我们创建和构建第一个 Docker 镜像的时候了，这个镜像启动了我们在上一章中介绍的示例微服务。为此，我们应该回到地址[`github.com/piomin/sample-spring-cloud-comm.git`](https://github.com/piomin/sample-spring-cloud-comm.git)可用的仓库，然后切换到`feign_with_discovery`分支上[`github.com/piomin/sample-spring-cloud-comm/tree/feign_with_discovery`](https://github.com/piomin/sample-spring-cloud-comm/tree/feign_with_discovery)。在那里，你可以找到每个微服务、网关和发现模块的`Dockerfile`。然而，在讨论这些示例之前，我们应该参考`Dockerfile`参考资料，以了解我们可以在其中放置的基本命令。实际上，`Dockerfile`不是构建 Docker 镜像的唯一方法；我们还将向您展示如何使用 Maven 插件创建包含微服务的镜像。

# Dockerfiles

Docker 可以通过读取`Dockerfile`中提供的指令来自动构建镜像，这是一个包含所有在命令行中调用以组装镜像的命令的文档。`Dockerfile`中的所有命令都必须由`Dockerfile`规范中定义的关键字前缀。以下是最常用的指令列表。它们按照在`Dockerfile`中找到的顺序执行。在这里，我们还可以添加一些以`#`字符开头的注释：

| **指令** | **描述** |
| --- | --- |
| `FROM` | 这初始化一个新的构建阶段并设置后续指令的基础镜像。实际上，每个有效的`Dockerfile`都必须以`FROM`指令开始。 |
| `MAINTAINER` | 这设置了生成镜像的作者身份。这个指令已经过时，所以你可能会在许多旧镜像中找到它。我们应该使用`LABEL`指令代替`MAINTAINER`，如下所示：`LABEL maintainer="piotr.minkowski@gmail.com"`。 |
| `RUN` | 这执行 Linux 命令，用于在新的层上配置和安装当前镜像所需的应用程序，然后提交结果。它可以有两种形式:`RUN <命令>`或`RUN ["可执行文件", "参数 1", "参数 2"]`。 |
| `ENTRYPOINT` | 这配置了一个最终脚本，用于引导作为可执行文件的容器。它覆盖了所有使用`CMD`指定的元素，并有两个形式:`ENTRYPOINT ["可执行文件", "参数 1", "参数 2"]`和`ENTRYPOINT`命令`参数 1 参数 2`。值得注意的是，`Dockerfile`中最后一个`ENTRYPOINT`指令才会生效。 |
| `CMD` | `Dockerfile`中只能包含一个`CMD`指令。这个指令通过 JSON 数组格式为`ENTRYPOINT`提供默认参数。 |
| `ENV` | 这为容器设置环境变量，以键/值形式。 |
| `COPY` | 这个指令会将给定源路径的新文件或目录复制到容器文件系统内的目标路径。它的格式如下：`COPY [--chown=<用户>:<组>] <源>... <目标>`。 |
| `ADD` | 这是`COPY`指令的一个替代选项。它比`COPY`指令多做了一些事情，例如，它允许`<src>`是一个 URL 地址。 |
| `WORKDIR` | 这个指令为`RUN`、`CMD`、`ENTRYPOINT`、`COPY`和`ADD`设置工作目录。 |
| `EXPOSE` | 这个指令负责告知 Docker 容器在运行时监听指定的网络端口。它实际上并不发布端口。端口的发布是通过`docker run`命令的`-p`选项来实现的。 |
| `VOLUME` | 这个指令创建了指定名称的挂载点。卷是 Docker 容器内持久化数据的首选机制。 |
| `USER` | 这个指令为运行镜像以及`RUN`、`CMD`和`ENTRYPOINT`指令设置用户名和可选的用户组。 |

让我们看看实际操作中它是如何工作的。我们应该为每个微服务定义一个`Dockerfile`，并将其放在其 Git 项目的根目录中。下面是为`account-service`创建的`Dockerfile`：

```java
FROM openjdk:8u151-jdk-slim-stretch
MAINTAINER Piotr Minkowski <piotr.minkowski@gmail.com>
ENV SPRING_PROFILES_ACTIVE zone1
ENV EUREKA_DEFAULT_ZONE http://localhost:8761/eureka/
ADD target/account-service-1.0-SNAPSHOT.jar app.jar
ENTRYPOINT ["java", "-Xmx160m", "-jar", "-Dspring.profiles.active=${SPRING_PROFILES_ACTIVE}", "-Deureka.client.serviceUrl.defaultZone=${EUREKA_DEFAULT_ZONE}", "/app.jar"]
EXPOSE 8091
```

前面的例子并不复杂。它只是将微服务生成的胖 JAR 文件添加到 Docker 容器中，并将`java -jar`命令作为`ENTRYPOINT`。即便如此，让我们逐一分析它。我们示例中的`Dockerfile`执行了以下指令：

+   该镜像扩展了一个现有的 OpenJDK 镜像，这是一个官方的、开源的 Java 平台标准版实现。OpenJDK 镜像有很多版本。可用的镜像变体之间的主要区别在于它们的大小。标记为`8u151-jdk-slim-stretch`的镜像提供了 JDK 8，并包括运行 Spring Boot 微服务所需的所有库。它也比这个版本的 Java（`8u151-jdk`）的基本镜像小得多。

+   在这里，我们定义了两个可以在运行时覆盖的环境变量，它们是通过`docker run`命令的`-e`选项来设置的。第一个是活动的 Spring 配置文件名，默认初始化为`zone1`值。第二个是发现服务器的地址，默认等于`[`localhost:8761/eureka/`](http://localhost:8761/eureka/)`。

+   胖 JAR 文件包含了所有必需的依赖项以及应用程序的二进制文件。因此，我们必须使用`ADD`指令将生成的 JAR 文件放入容器中。

+   我们将容器配置为执行 Java 应用程序。定义的`ENTRYPOINT`相当于在本地机器上运行以下命令：

```java
java -Xmx160m -jar –Dspring.profiles.active=zone1 -Deureka.client.serviceUrl.defaultZone=http://localhost:8761/eureka/ app.jar
```

+   我们使用`EXPOSE`指令告知 Docker 可能会暴露容器内部应用程序的 HTTP API，该 API 可通过端口`8091`访问。

# 运行容器化的微服务

假设我们已经为每个服务准备了一个有效的`Dockerfile`，下一步是在为每个服务构建 Docker 镜像之前，使用`mvn clean install`命令构建整个 Maven 项目。

构建 Docker 镜像时，你应该始终位于每个微服务源代码的`root`目录。在我们基于微服务的系统中，需要运行的第一个容器是一个发现服务器。其 Docker 镜像被命名为`piomin/discovery-service`。在运行 Docker 的`build`命令之前，请转到模块`discovery-service`。这个`Dockerfile`比其他微服务要简单一些，因为容器内部不需要设置环境变量，如下所示：

```java
FROM openjdk:8u151-jdk-slim-stretch
MAINTAINER Piotr Minkowski <piotr.minkowski@gmail.com>
ADD target/discovery-service-1.0-SNAPSHOT.jar app.jar
ENTRYPOINT ["java", "-Xmx144m", "-jar", "/app.jar"]
EXPOSE 8761
```

在这里只需要执行五个步骤，你可以在构建目标镜像时生成的日志中看到，在运行`docker build`命令之后。如果一切正常，你应该看到`Dockerfile`中定义的所有五个步骤的进度，以及以下告诉您镜像已成功构建和标记的最终消息：

```java
$ docker build -t piomin/discovery-service:1.0 .
Sending build context to Docker daemon 39.9MB
Step 1/5 : FROM openjdk:8u151-jdk-slim-stretch
8u151-jdk-slim-stretch: Pulling from library/openjdk
8176e34d5d92: Pull complete
2208661344b7: Pull complete
99f28966f0b2: Pull complete
e991b55a8065: Pull complete
aee568884a84: Pull complete
18b6b371c215: Pull complete
Digest: sha256:bd394fdc76e8aa73adba2a7547fcb6cde3281f70d6b3cae6fa62ef1fbde327e3
Status: Downloaded newer image for openjdk:8u151-jdk-slim-stretch
 ---> 52de5d98a41d
Step 2/5 : MAINTAINER Piotr Minkowski <piotr.minkowski@gmail.com>
 ---> Running in 78fc78cc21f0
 ---> 0eba7a369e43
Removing intermediate container 78fc78cc21f0
Step 3/5 : ADD target/discovery-service-1.0-SNAPSHOT.jar app.jar
 ---> 1c6a2e04c4dc
Removing intermediate container 98138425b5a0
Step 4/5 : ENTRYPOINT java -Xmx144m -jar /app.jar
 ---> Running in 7369ba693689
 ---> c246470366e4
Removing intermediate container 7369ba693689
Step 5/5 : EXPOSE 8761
 ---> Running in 74493ae54220
 ---> 06af6a3c2d41
Removing intermediate container 74493ae54220
Successfully built 06af6a3c2d41
Successfully tagged piomin/discovery-service:1.0
```

一旦我们成功构建了一个镜像，我们就应该运行它。我们建议创建一个网络，在该网络中启动所有我们的微服务容器。要在新创建的网络中启动容器，我们需要使用`--network`参数将容器名称传递给`docker run`命令。为了检查容器是否已成功启动，运行`docker logs`命令。此命令将应用程序打印到控制台的所有日志行输出到控制台，如下所示：

```java
$ docker network create sample-spring-cloud-network
$ docker run -d --name discovery -p 8761:8761 --network sample-spring-cloud-network piomin/discovery-service:1.0
de2fac673806e134faedee3c0addaa31f2bbadcffbdff42a53f8e4ee44ca0674
$ docker logs -f discovery
```

下一步是使用我们的四个微服务—`account-service`、`customer-service`、`order-service`和`product-service`—构建和运行容器。每个服务的步骤都相同。例如，如果你想构建`account-service`，首先需要进入示例项目源代码中的那个目录。这里的`build`命令与发现服务相同；唯一的区别在于镜像名称，如下所示片段：

```java
$ docker build -t piomin/account-service:1.0 .
```

对于`discovery-service`，运行 Docker 镜像的命令要稍微复杂一些。在这种情况下，我们必须将 Eureka 服务器的地址传递给启动容器。因为此容器与发现服务容器在同一网络中运行，我们可以使用其名称而不是其 IP 地址或其他任何标识符。可选地，我们还可以使用`-m`参数设置容器的内存限制，例如，设置为 256 MB。最后，我们可以使用以下方式使用`docker logs`命令查看容器上运行的应用程序生成的日志：

```java
$ docker run -d --name account -p 8091:8091 -e EUREKA_DEFAULT_ZONE=http://discovery:8761/eureka -m 256M --network sample-spring-cloud-network piomin/account-service:1.0
$ docker logs -f account
```

与之前描述的步骤相同，应对所有其他微服务重复这些步骤。最终结果是五个正在运行的容器，可以使用`docker ps`命令来显示，如下所示截图：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/2638f3f5-f1ee-446e-8090-25e5c1622119.png)

所有的微服务都注册在 Eureka 服务器上。Eureka 仪表板可在地址`http://192.168.99.100:8761/`找到，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/da00480d-f780-4d73-a76d-7f1055e5e176.png)

这里再提一个有趣的 Docker 命令：`docker stats`。这个命令打印了一些关于启动容器的统计信息，比如内存或 CPU 使用情况。如果你使用该命令的`--format`参数，你可以自定义它打印统计信息的方式；例如，你可以打印容器名称而不是它的 ID。在运行那个命令之前，你可能需要进行一些测试，以检查一切是否按预期工作。检查微服务之间的通信是否成功完成是很值得的。你可能还想尝试从`customer-service`调用端点`GET /withAccounts/{id}`，该端点由`account-service`暴露出来。我们运行以下命令：

```java
docker stats --format "table {{.Name}}\t{{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}" 
```

以下截图可见：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/4eb480b3-3149-4c73-bdc3-7885ad46bf71.png)

# 使用 Maven 插件构建镜像

如我们之前提到的，`Dockerfile`不是创建和构建容器的唯一方式。还有其他一些方法可用，例如，通过使用 Maven 插件。我们有多个用于构建镜像的插件，它们与`mvn`命令一起使用。其中比较流行的是`com.spotify:docker-maven-plugin`。这个插件在其配置中有与`Dockerfile`指令相当的标签。`account-service`的`pom.xml`中插件的配置如下：

```java
<plugin>
 <groupId>com.spotify</groupId>
 <artifactId>docker-maven-plugin</artifactId>
 <version>1.0.0</version>
 <configuration>
 <imageName>piomin/${project.artifactId}</imageName>
 <imageTags>${project.version}</imageTags>
 <baseImage>openjdk:8u151-jdk-slim-stretch</baseImage>
 <entryPoint>["java", "-Xmx160m", "-jar", "-Dspring.profiles.active=${SPRING_PROFILES_ACTIVE}", "-Deureka.client.serviceUrl.defaultZone=${EUREKA_DEFAULT_ZONE}", "/${project.build.finalName}.jar"] </entryPoint>
 <env>
  <SPRING_PROFILES_ACTIVE>zone1</SPRING_PROFILES_ACTIVE>
  <EUREKA_DEFAULT_ZONE>http://localhost:8761/eureka/</EUREKA_DEFAULT_ZONE>
 </env>
 <exposes>8091</exposes>
 <maintainer>piotr.minkowski@gmail.com</maintainer>
 <dockerHost>https://192.168.99.100:2376</dockerHost>
 <dockerCertPath>C:\Users\Piotr\.docker\machine\machines\default</dockerCertPath>
 <resources>
  <resource>
   <directory>${project.build.directory}</directory>
   <include>${project.build.finalName}.jar</include>
  </resource>
 </resources>
 </configuration>
</plugin>
```

这个插件可以在 Maven 的`build`命令期间被调用。如果你想在构建应用程序之后立即构建一个 Docker 镜像，可以使用以下的 Maven 命令：

```java
$ mvn clean install docker:build   
```

另外，你也可以设置`dockerDirectory`标签，以便基于`Dockerfile`进行构建。无论你选择哪种方法，效果都是一样的。任何用应用程序构建的新镜像都会在你的 Docker 机器上可用。在使用`docker-maven-plugin`时，你可以通过将`pushImage`设置为`true`来强制自动镜像推送到仓库，如下所示：

```java
<plugin>
 <groupId>com.spotify</groupId>
 <artifactId>docker-maven-plugin</artifactId>
 <version>1.0.0</version>
 <configuration>
  <imageName>piomin/${project.artifactId}</imageName>
  <imageTags>${project.version}</imageTags>
  <pushImage>true</pushImage>
  <dockerDirectory>src/main/docker</dockerDirectory>
  <dockerHost>https://192.168.99.100:2376</dockerHost>
  <dockerCertPath>C:\Users\Piotr\.docker\machine\machines\default</dockerCertPath>
  <resources>
   <resource>
    <directory>${project.build.directory}</directory>
    <include>${project.build.finalName}.jar</include>
   </resource>
  </resources>
 </configuration>
</plugin>
```

# 高级 Docker 镜像

到目前为止，我们已经构建了一些相当简单的 Docker 镜像。然而，有时需要创建一个更高级的镜像。我们将需要这样一个镜像来进行持续交付演示。这个 Docker 镜像将作为 Jenkins 奴隶运行，并连接到作为 Docker 容器启动的 Jenkins 主节点。我们在 Docker Hub 上没有找到这样的镜像，所以我们自己创建了一个。在这里，镜像必须包含 Git、Maven、JDK8 和 Docker。这些都是构建我们的示例微服务的 Jenkins 奴隶所需的全部工具。我将在本章的后面部分给你一个关于使用 Jenkins 服务器进行持续交付的基本概述。现在，我们将重点关注 just building the required image。以下是`Dockerfile`中提供的镜像的完整定义：

```java
FROM docker:18-dind
MAINTAINER Piotr Minkowski <piotr.minkowski@gmail.com>
ENV JENKINS_MASTER http://localhost:8080
ENV JENKINS_SLAVE_NAME dind-node
ENV JENKINS_SLAVE_SECRET ""
ENV JENKINS_HOME /home/jenkins
ENV JENKINS_REMOTING_VERSION 3.17
ENV DOCKER_HOST tcp://0.0.0.0:2375

RUN apk --update add curl tar git bash openjdk8 sudo

ARG MAVEN_VERSION=3.5.2
ARG USER_HOME_DIR="/root"
ARG SHA=707b1f6e390a65bde4af4cdaf2a24d45fc19a6ded00fff02e91626e3e42ceaff
ARG BASE_URL=https://apache.osuosl.org/maven/maven-3/${MAVEN_VERSION}/binaries
RUN mkdir -p /usr/share/maven /usr/share/maven/ref \
 && curl -fsSL -o /tmp/apache-maven.tar.gz ${BASE_URL}/apache-maven-${MAVEN_VERSION}-bin.tar.gz \
 && echo "${SHA} /tmp/apache-maven.tar.gz" | sha256sum -c - \
 && tar -xzf /tmp/apache-maven.tar.gz -C /usr/share/maven --strip-components=1 \
 && rm -f /tmp/apache-maven.tar.gz \
 && ln -s /usr/share/maven/bin/mvn /usr/bin/mvn
ENV MAVEN_HOME /usr/share/maven
ENV MAVEN_CONFIG "$USER_HOME_DIR/.m2"

RUN adduser -D -h $JENKINS_HOME -s /bin/sh jenkins jenkins && chmod a+rwx $JENKINS_HOME
RUN echo "jenkins ALL=(ALL) NOPASSWD: /usr/local/bin/dockerd" > /etc/sudoers.d/00jenkins && chmod 440 /etc/sudoers.d/00jenkins
RUN echo "jenkins ALL=(ALL) NOPASSWD: /usr/local/bin/docker" > /etc/sudoers.d/01jenkins && chmod 440 /etc/sudoers.d/01jenkins
RUN curl --create-dirs -sSLo /usr/share/jenkins/slave.jar http://repo.jenkins-ci.org/public/org/jenkins-ci/main/remoting/$JENKINS_REMOTING_VERSION/remoting-$JENKINS_REMOTING_VERSION.jar && chmod 755 /usr/share/jenkins && chmod 644 /usr/share/jenkins/slave.jar

COPY entrypoint.sh /usr/local/bin/entrypoint
VOLUME $JENKINS_HOME
WORKDIR $JENKINS_HOME
USER jenkins
ENTRYPOINT ["/usr/local/bin/entrypoint"]
```

让我们分析一下发生了什么。在这里，我们扩展了 Docker 基础镜像。这是一个相当智能的解决方案，因为现在这个镜像提供了 Docker 内的 Docker。尽管通常不建议在 Docker 内运行 Docker，但有一些期望的使用案例，比如使用 Docker 的持续交付。除了 Docker 之外，还使用`RUN`指令在镜像上安装了其他软件，如 Git、JDK、Maven 或 Curl。我们还添加了一个 OS 用户，在`dockerd`脚本中有`sudoers`权限，负责在机器上运行 Docker 守护进程。这不是在运行容器中必须启动的唯一进程；启动 JAR 与 Jenkins 奴隶也是必须的。这两个命令在`entrypoint.sh`中执行，作为镜像的`ENTRYPOINT`。这个 Docker 镜像的完整源代码可以在 GitHub 上找到，地址为[`github.com/piomin/jenkins-slave-dind-jnlp.git`](https://github.com/piomin/jenkins-slave-dind-jnlp.git)。你可以省略从源代码构建它，只需使用以下命令从我的 Docker Hub 账户下载一个现成的镜像：

```java
docker pull piomin/jenkins-slave-dind-jnlp
```

这里是在 Docker 镜像中的`entrypoint.sh`脚本，它启动了 Docker 守护进程和 Jenkins 奴隶：

```java
#!/bin/sh
set -e
echo "starting dockerd..."
sudo dockerd --host=unix:///var/run/docker.sock --host=tcp://0.0.0.0:2375 --storage-driver=vfs &
echo "starting jnlp slave..."
exec java -jar /usr/share/jenkins/slave.jar \
 -jnlpUrl $JENKINS_URL/computer/$JENKINS_SLAVE_NAME/slave-agent.jnlp \
 -secret $JENKINS_SLAVE_SECRET
```

# 持续交付

迁移到基于微服务的架构的关键好处之一就是能够快速交付软件。这应该是你在组织中实施持续交付或持续部署流程的主要动机。简而言之，持续交付流程是一种尝试自动化软件交付的所有阶段的方法，比如构建、测试代码和发布应用程序。有许多工具可以赋能这个过程。其中之一就是 Jenkins，这是一个用 Java 编写的开源自动化服务器。Docker 能够将你的**持续集成**（**CI**）或**持续交付**（**CD**）流程提升到一个新的水平。例如，不可变交付是 Docker 最重要的优势之一。

# 将 Jenkins 与 Docker 集成

这里的主要目标是使用 Jenkins 和 Docker 在本地设计和运行持续交付过程。这个过程涉及到四个元素。其中第一个元素已经准备好了：我们的微服务源代码仓库，它位于 GitHub 上。第二个元素，Jenkins，需要运行和配置。Jenkins 是我们持续交付系统的一个关键元素。它必须从 GitHub 仓库下载应用程序的源代码，构建它，然后将生成的 JAR 文件放入 Docker 镜像中，将该镜像推送到 Docker Hub，最后运行带有微服务的容器。这个过程中所有的任务都是直接在 Jenkins 主节点上执行的，但是是在其从节点上。Jenkins 及其从节点都是作为 Docker 容器启动的。这个解决方案的架构如下所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/f069db09-864d-4eb4-b61a-e56760ded97d.png)

值得一提的是，Jenkins 是基于插件概念构建的。核心是一个过于简单的自动化构建引擎。Jenkins 的真正力量在于其插件，并且在更新中心有数百个插件。现在，我们将只讨论一些感谢 Jenkins 服务器为我们提供的机会。我们需要安装以下插件才能在 Docker 容器中构建和运行我们的微服务：

+   **流水线**：这是一套插件，可以让您使用 Groovy 脚本创建自动化，遵循**流水线即代码**的理念 ([`wiki.jenkins.io/display/JENKINS/Pipeline+Plugin`](https://clicktime.symantec.com/a/1/4g9YbrLxE43FYJrIE5v0J-RjoqlfXZm5h2piohXV60o=?d=GiSMteljxw-3ox0rf3cMazK9IOHzeSrn0vm9sus4y_n0hehkoAHvPijqT9dNXanC2Z3KtWbAm0BF-YDyp2HFvxXpFa6IkS_tvoddqdWrcb2R6vx-7YEpFHbt4IzErozigZnPecmyLha58i_mX_GOqw8nGcIkFmptcNTdFqB6DA-shedWhYxMv5VpzsTWPmDZA52S7fjMHuYvrTP5MOqqgejXYWvZr4d9OaWe0jeXJ-MEIccIx-UiD_tYy9OK2eYpd4eiaegTQb9XhbUR0ZNPGlpo4vSShb3yAI2Kf9JPcQ4hOSXoj5JpZSvnKhm1C9Yn68IsYCIBmwjYZZYyuS3y9uUI9zHbgSpVOx8ehvCmMWx0MAwCJ5gDR1ZIXXNcnw%3D%3D&u=https%3A%2F%2Fwiki.jenkins.io%2Fdisplay%2FJENKINS%2FPipeline%2BPlugin))

+   **Docker 流水线**：这允许您在流水线中构建 Docker 容器 ([`wiki.jenkins.io/display/JENKINS/Docker+Pipeline+Plugin`](https://clicktime.symantec.com/a/1/3BcsCubSP1UZ0ssSZFCe2iSCQQ_b1asMBhlt_0nQFKI=?d=GiSMteljxw-3ox0rf3cMazK9IOHzeSrn0vm9sus4y_n0hehkoAHvPijqT9dNXanC2Z3KtWbAm0BF-YDyp2HFvxXpFa6IkS_tvoddqdWrcb2R6vx-7YEpFHbt4IzErozigZnPecmyLha58i_mX_GOqw8nGcIkFmptcNTdFqB6DA-shedWhYxMv5VpzsTWPmDZA52S7fjMHuYvrTP5MOqqgejXY

+   -   **Git**: 该插件将 Git 与 Jenkins 集成([https://wiki.jenkins.io/display/JENKINS/Git+Plugin](https://clicktime.symantec.com/a/1/Zbv8hM_2L26s_PMbntThO-9W_A4uUxsqo7UyU5nbae8=?d=GiSMteljxw-3ox0rf3cMazK9IOHzeSrn0vm9sus4y_n0hehkoAHvPijqT9dNXanC2Z3KtWbAm0BF-YDyp2HFvxXpFa6IkS_tvoddqdWrcb2R6vx-7YEpFHbt4IzErozigZnPecmyLha58i_mX_GOqw8nGcIkFmptcNTdFqB6DA-shedWhYxMv5VpzsTWPmDZA52S7fjMHuYvrTP5MOqqgejXYWvZr4d9OaWe0jeXJ-MEIccIx-UiD_tYy9OK2eYpd4eiaegTQb9XhbUR0ZNPGlpo4vSShb3yAI2Kf9JPcQ4hOSXoj5JpZSvnKhm1C9Yn68IsYCIBmwjYZZYyuS3y9uUI9zHbgSpVOx8ehvCmMWx0MAwCJ5gDR1ZIXXNcnw%3D%3D&u=https%3A%2F%2Fwiki.jenkins.io%2Fdisplay%2FJENKINS%2FGit%2BPlugin))

+   -   **Maven 集成**: 当使用 Maven 和 Jenkins 构建应用程序时，该插件提供了一些有用的命令([`plugins.jenkins.io/maven-plugin`](https://clicktime.symantec.com/a/1/jmIwLdZZ-wtodkRm1Goje_nuKFV98VcZYPHn5cWj1KM=?d=GiSMteljxw-3ox0rf3cMazK9IOHzeSrn0vm9sus4y_n0hehkoAHvPijqT9dNXanC2Z3KtWbAm0BF-YDyp2HFvxXpFa6IkS_tvoddqdWrcb2R6vx-7YEpFHbt4IzErozigZnP

-   所需插件可以通过 UI 仪表盘进行配置，可以在启动后或通过管理 Jenkins *|* 管理插件进行配置。为了在本地运行 Jenkins，我们将使用其 Docker 镜像。下面的命令将创建一个名为`jenkins`的网络，并启动 Jenkins 主容器，在端口`38080`上暴露 UI 仪表盘。注意，当你启动 Jenkins 容器并首次使用其 Web 控制台时，需要使用生成的初始密码进行设置。你可以通过调用`docker logs jenkins`命令轻松地从 Jenkins 日志中获取此密码，如下所示：

```java
$ docker network create jenkins
$ docker run -d --name jenkins -p 38080:8080 -p 50000:50000 --network jenkins jenkins/jenkins:lts
```

-   一旦我们成功配置了 Jenkins 主节点及其所需插件，我们需要添加新的奴隶节点。为此，你应该前往管理 Jenkins *|* 管理节点部分，然后选择新建节点。在显示的表单中，你必须将`/home/jenkins`设置为远程根目录，并通过 Java Web Start 将启动代理作为启动方法。现在你可以按照之前讨论的启动带有 Jenkins 奴隶的 Docker 容器。请注意，你必须覆盖两个环境变量，指示奴隶的名称和密钥。`name`参数在节点创建时设置，而密钥由服务器自动生成。你可以查看节点的详细信息页面以获取更多信息，如下所示的屏幕截图：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/a171112c-7bfe-4bd0-a491-1746adc35d68.png)

-   以下是在 Docker 中使用 Docker 的 Jenkins 奴隶容器启动的 Docker 命令：

```java
$ docker run --privileged -d --name slave --network jenkins -e JENKINS_SLAVE_SECRET=5664fe146104b89a1d2c78920fd9c5eebac3bd7344432e0668e366e2d3432d3e -e JENKINS_SLAVE_NAME=dind-node-1 -e JENKINS_URL=http://jenkins:38080 piomin/jenkins-slave-dind-jnlp
```

这篇关于 Jenkins 配置的简短介绍应该可以帮助你在自己的机器上重复讨论的持续交付过程。记住，我们只查看了与 Jenkins 相关的几个方面，包括设置，这允许你为你的微服务基础系统设置 CI 或 CD 环境。如果你对深入研究这个话题感兴趣，你应该参考可用的文档，具体请访问 [`jenkins.io/doc`](https://jenkins.io/doc)。

# 构建流水线

在 Jenkins 服务器的旧版本中，工作单位是作业。目前，其主要特性是能够将流水线定义为代码。这种变化与 IT 架构中更现代的趋势有关，该趋势认为应用程序交付与正在交付的应用程序一样重要。由于应用程序堆栈的所有组件已经自动化，并以代码的形式在版本控制系统中表示，因此可以利用同样的好处来定义 CI 或 CD 流水线。

Jenkins Pipeline 提供了一套用于将简单和更高级的交付流水线建模为代码的工具。这样的流水线的定义通常写入一个名为 `Jenkinsfile` 的文本文件中。它支持通过 *共享库* 功能提供的特定步骤的领域特定语言。流水线支持两种语法：声明式（在 Pipeline 2.5 中引入）和脚本化流水线。无论使用哪种语法，它都会逻辑上分为阶段和步骤。步骤是流水线的最基本部分，因为它们告诉 Jenkins 需要做什么。阶段逻辑上分组了几个步骤，然后在流水线的结果屏幕上显示。下面的代码是一个脚本化流水线的示例，为 `account-service` 定义了一个构建过程。对于其他微服务也需要创建类似的定义。所有这些定义都位于每个应用程序源代码的 `root` 目录中的 `Jenkinsfile`：

```java
node('dind-node-1') {
 withMaven(maven:'M3') {
  stage('Checkout') {
   git url: 'https://github.com/piomin/sample-spring-cloud-comm.git', credentialsId: 'github-piomin',   branch: 'master'
  }

  stage('Build') {
   dir('account-service') {
    sh 'mvn clean install'
   }
   def pom = readMavenPom file:'pom.xml'
   print pom.version
   env.version = pom.version
   currentBuild.description = "Release: ${env.version}"
  }

  stage('Image') {
   dir ('account-service') {
    def app = docker.build "piomin/account-service:${env.version}"
    app.push()
   }
  }

  stage ('Run') {
   docker.image("piomin/account-service:${env.version}").run('-p 8091:8091 -d --name account --network sample-spring-cloud-network')
  }

 }
}
```

之前的定义被分为四个阶段。在第一个阶段，`Checkout`，我们克隆包含所有示例应用程序源代码的 Git 仓库。在第二个阶段，`Build`，我们从 `account-service` 模块构建一个应用程序，然后从 `root` 的 `pom.xml` 中读取整个 Maven 项目的版本号。在 `Image` 阶段，我们从 `Dockerfile` 构建一个镜像，并将其推送到 Docker 仓库。最后，在 `Run` 阶段我们在 `dind-node-1` 上运行一个包含 `account-service` 应用程序的容器。所有描述的阶段都按照节点元素的定义在 `dind-node-1` 上执行，节点元素是流水线定义中所有其他元素的根。

现在我们可以继续在 Jenkins 的网页控制台中定义流水线。选择新建项目，然后检查管道项目类型并输入其名称。确认后，你应该会被重定向到管道的配置页面。在那里你唯一需要做的是提供 Git 仓库中`Jenkinsfile`的位置，然后按照下面的屏幕截图设置 SCM 认证凭据：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/de3445e9-d691-4ca5-8344-ac9a2cd9cc06.png)

保存更改后，管道的配置就准备好了。为了启动构建，点击“立即构建”按钮。在这个阶段，有两件事需要澄清。在生产模式下，你可以使用由最流行的 Git 托管提供商（包括 GitHub、BitBucket 和 GitLab）提供的`webhook`机制。这个机制可以在将更改推送到仓库后自动触发 Jenkins 中的构建。为了演示这个，我们本应运行一个本地的版本控制系统，例如使用 GitLab 和 Docker。还有一种更简单的测试方法。容器化的应用程序直接在 Jenkins 的 Docker in Docker 奴隶上运行；在正常情况下，我们会在专门用于应用程序部署的分离远程机器上启动。下面的屏幕截图是 Jenkins 的网页控制台，展示了`product-service`的构建过程，分为不同的阶段：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/389420f0-9f82-4ff8-94f3-50dc772ae4c8.png)

我们应该现在为每个微服务创建一个管道。创建的所有管道的列表如下：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/6f01811b-9091-425b-90cf-e19bdbffef91.png)

# 与 Kubernetes 一起工作

我们已经在我们本地的 Docker 容器上启动了我们的示例微服务。我们甚至使用了 CI 和 CD 自动化管道，以便在本地机器上运行它们。然而，你可能有一个重要的问题。我们如何在大规模和生产模式下组织我们的环境，在那里我们必须在多台机器上运行多个容器呢？好吧，这正是我们在根据云原生开发的观念实现微服务时必须做的。然而，在这个实例中，仍然存在许多挑战。假设我们在多个实例中启动了许多微服务，将有很多容器需要管理。在正确的时间启动正确的容器，处理存储考虑，进行扩展或缩放，以及手动处理故障将是一场噩梦。幸运的是，有一些平台可以帮助在大规模上进行 Docker 容器的集群和编排。目前，在这个领域的领导者是 Kubernetes。

Kubernetes 是一个用于管理容器化工作负载和服务的开源平台。它可以作为容器平台，微服务平台，云平台，还有更多。它自动化了在不同机器上运行容器、扩展、缩减、在容器之间分配负载，以及在应用程序的多个实例之间保持存储一致性等操作。它还有许多其他功能，包括服务发现、负载均衡、配置管理、服务命名和滚动更新。然而，这些功能并非都对我们有用，因为许多类似的功能由 Spring Cloud 提供。

值得一提的是，Kubernetes 并不是市面上唯一的容器管理工具。还有 Docker Swarm，这是 Docker 自带的本地工具。然而，由于 Docker 已经宣布对 Kubernetes 提供原生支持，似乎这是一个自然的选择。在深入实践之前，我们应该了解几个关于 Kubernetes 的重要概念和组件。

# 概念和组件

使用 Kubernetes 时，您可能首先要处理的第一个术语是 pod，这是 Kubernetes 中的基本构建块。pod 表示集群中的运行进程。它可以由一个或多个容器组成，这些容器保证在主机机器上共同定位，并将共享相同的资源。每个 pod 中只有一个容器是最常见的 Kubernetes 用例。每个 pod 在集群中都有一个唯一的 IP 地址，但部署在同一 pod 中的所有容器可以通过 `localhost` 与彼此通信。

另一个常见的组件是服务。服务逻辑上组了一组 pod，并定义了对其访问的策略；有时它被称为微服务。默认情况下，服务是在集群内部暴露的，但它也可以暴露在外的 IP 地址上。我们可以使用四种可用行为之一来暴露服务：`ClusterIP`、`NodePort`、`LoadBalancer` 和 `ExternalName`。默认选项是 `ClusterIP`。这将在集群内部 IP 上暴露服务，使其仅可在集群内部访问。`NodePort` 将在每个节点的 IP 上以静态端口暴露服务，并自动创建 `ClusterIP` 以在集群内部暴露服务。反过来，`LoadBalancer` 使用云提供商的负载均衡器在外部暴露服务，而 `ExternalName` 将服务映射到 `externalName` 字段的内容。我们还应该花点时间讨论 Kubernetes 的复制控制器。此控制器通过在集群中运行指定数量的 pod 副本来处理复制和扩展。如果底层节点失败，它还负责替换 pod。Kubernetes 中的每个控制器都是由 `kube-controller-manager` 运行的独立进程。你还可以在 Kubernetes 中找到节点控制器、端点控制器以及服务账号和令牌控制器。

Kubernetes 使用一个 `etcd` 键/值存储作为所有集群数据的后端存储。在集群中的每个节点都有一个名为 **kubelet** 的代理，它负责确保容器在 pod 中运行。用户发送给 Kubernetes 的每个命令都由 `kubeapi-server` 暴露的 Kubernetes API 处理。

当然，这是对 Kubernetes 架构的一个非常简化的解释。为了成功运行高可用的 Kubernetes 集群，还有更多组件和工具需要正确配置。执行此任务并非易事，它需要对这个平台有大量的了解。幸运的是，有一个工具可以使在本地运行 Kubernetes 集群变得容易——Minikube。

# 通过 Minikube 在本地运行 Kubernetes

Minikube 是一个使在本地运行 Kubernetes 变得简单的工具。它在一个本地机器上的 VM 中运行一个单节点 Kubernetes 集群。在开发模式下，它绝对是最佳选择。当然，Minikube 不支持 Kubernetes 提供的所有功能；只包括最重要的功能，包括 DNS、NodePorts、Config Map、Dashboard 和 Ingress。

要在 Windows 上运行 Minikube，我们需要安装一个虚拟化工具。然而，如果您已经运行了 Docker，您可能已经安装了 Oracle VM VirtualBox。在这种情况下，您只需要下载并安装 Minikube 的最新版本，您可以查看 [`github.com/kubernetes/minikube/releases`](https://clicktime.symantec.com/a/1/eXr_fIrvCIRYzEHt0YvbtkptTqcVd9nJzBV28fxoaTY=?d=7tChM-hIl54SsiVoHKrovXbmLIi8ouu38bfWFa5LjYebKneJvW_c2_HMgDdoq431rSiEnNRRoWc7WI40qLP-zxO_svn7BtB5YkP7_3z6XE1bc9UDw_gg4B_LUQLmxfklfTjgbs0J-dnBHLc3GOsVYjvBMyOE-nmJR1SuKthIzdMfxP8oasaAGIamKBmwy-pKxDOZYKGzKE4iEAO1nFo15LHQ7enPYrMhvcEhb3LDIMsYYwnwVTe52q36t77MaAeAFdq7DgkU1BLlVMydfq9vglCYhLnhnOOzSDesZnjGR3spuBjVhNyCD3pcc73yC-ARPXPUpScKDxqUYA8pZg40QrbDOyzuC95KNm-9vIqcPXR6iDgu8QK_SscvFxnDi4A%3D&u=https%3A%2F%2Fgithub.com%2Fkubernetes%2Fminikube%2Freleases) ，并 `kubectl.exe` ，如 [`storage.googleapis.com/kubernetes-release/release/stable.txt`](https://storage.googleapis.com/kubernetes-release/release/stable.txt) 描述。文件 `minikube.exe` 和 `kubectl.exe` 应该包括在 `PATH` 环境变量中。此外，Minikube 提供自己的安装程序 `minikube-installer.exe` ，它将自动将 `minikube.exe` 添加到您的路径中。然后，您可以从命令行通过运行以下命令启动 Minikube：

```java
$ minikube start
```

前一个命令初始化了一个名为`minikube`的`kubectl`上下文。它包含了允许你与 Minikube 集群通信的配置。现在你可以使用`kubectl`命令来维护由 Minikube 创建的本地集群，并在其中部署容器。命令行界面的替代方案是 Kubernetes 仪表板。通过调用`minikube` dashboard，可以为你的节点启用 Kubernetes 仪表板。您可以使用这个仪表板创建、更新或删除部署，以及列出和查看所有 pods、服务、ingress 和复制控制器的配置。通过以下命令可以轻松停止和删除本地集群：

```java
$ minikube stop
$ minikube delete
```

# 部署应用程序

Kubernetes 集群上存在的每个配置都由 Kubernetes 对象表示。这些对象可以通过 Kubernetes API 进行管理，并且应该以 YAML 格式表达。你可能会直接使用那个 API，但可能会决定利用`kubectl`命令行界面为你做所有必要的调用。在 Kubernetes 上新建对象的描述必须提供描述其期望状态的规格，以及关于对象的一些基本信息。以下是在 YAML 配置文件中应始终设置的一些必需字段：

+   `apiVersion`：这指示了用于创建对象的 Kubernetes API 的版本。API 在请求中总是需要 JSON 格式，但`kubectl`会自动将 YAML 输入转换为 JSON。

+   `kind`：这设置了要创建的对象的种类。有一些预定义的类型可供选择，例如 Deployment、Service、Ingress 或 ConfigMap。

+   `metadata`：这允许你通过名称、UID 或可选的命名空间来标识对象。

+   `spec`：这是对象的正确定义。规格的精确格式取决于对象的类型，并包含特定于该对象的嵌套字段。

通常，在 Kubernetes 上创建新对象时，其`kind`是部署。在下面的`Deployment` YAML 文件中，有两个重要的字段被设置。首先是`replicas`，它指定了期望的 pods 数量。实际上，这意味着我们将运行容器化应用程序的两个实例。第二个是`spec.template.spec.containers.image`，它设置了将在 pods 内部启动的 Docker 镜像的名称和版本。容器将在端口`8090`上暴露，`order-service`在此端口监听 HTTP 连接：

```java
apiVersion: apps/v1
kind: Deployment
metadata:
  name: order-service
spec:
  replicas: 2
  selector:
    matchLabels:
      app: order-service
  template:
    metadata:
      labels:
        app: order-service
    spec:
      containers:
      - name: order-service
        image: piomin/order-service:1.0
        env:
        - name: EUREKA_DEFAULT_ZONE
          value: http://discovery-service:8761/eureka
        ports:
        - containerPort: 8090
          protocol: TCP
```

假设前面的代码存储在文件`order-deployment.yaml`中，我们现在可以使用以下命令基于 imperative management 在 Kubernetes 上部署我们的容器化应用程序：

```java
$ kubectl create -f order-deployment.yaml
```

另外，你可以基于声明式管理方法执行相同的操作，如下所示：

```java
$ kubectl apply -f order-deployment.yaml
```

我们现在必须为所有微服务和`discovery-service`创建相同的部署文件。`discovery-service`的主题是一个非常好奇的事情。我们有使用基于 pods 和服务的内置 Kubernetes 发现的选项，但我们的主要目标是在这个平台上部署和运行 Spring Cloud 组件。所以，在部署任何微服务之前，我们首先应该部署、运行并暴露 Eureka 在 Kubernetes 上。以下是`discovery-service`的部署文件，也可以通过调用`kubectl apply`命令应用于 Kubernetes：

```java
apiVersion: apps/v1
kind: Deployment
metadata:
 name: discovery-service
 labels:
  run: discovery-service
spec:
 replicas: 1
 selector:
  matchLabels:
   app: discovery-service
 template:
  metadata:
   labels:
    app: discovery-service
  spec:
   containers:
   - name: discovery-service
     image: piomin/discovery-service:1.0
   ports:
   - containerPort: 8761
     protocol: TCP
```

如果你创建了一个 Deployment，Kubernetes 会自动为你创建 pods。它们的数量等于`replicas`字段中设置的值。一个 pods 不能暴露部署在容器上的应用程序提供的 API，它只是代表集群上运行的一个进程。为了访问运行在 pods 内的微服务提供的 API，我们必须定义一个服务。让我们回顾一下服务是什么。服务是一个定义了逻辑集合 of pods 和访问它们的策略的抽象。服务针对的 pods 集合通常由一个标签选择器确定。Kubernetes 中提供了四种服务类型。最简单且默认的是`ClusterIP`，它在一个内部暴露服务。如果你希望从集群外部访问一个服务，你应该定义类型为`NodePort`的服务。这个选项已经在下面的 YAML 文件示例中设置；现在，所有微服务都可以使用其 Kubernetes 服务名称与 Eureka 通信：

```java
apiVersion: v1
kind: Service
metadata:
 name: discovery-service
  labels:
   app: discovery-service
spec:
 type: NodePort
 ports:
   - protocol: TCP
     port: 8761
     targetPort: 8761
 selector:
   app: discovery-service
```

实际上，我们部署在 Minikube 上的所有微服务都应该能在集群外部访问，因为我们需要访问它们暴露的 API。为此，你需要提供与前面示例类似的 YAML 配置，只更改服务的名称、标签和端口。

我们架构中只有一个组件应该存在：API 网关。我们可以部署一个带有 Zuul 代理的容器，但是我们需要引入流行的 Kubernetes 对象，Ingress。这个组件负责管理通常通过 HTTP 暴露的服务的外部访问。Ingress 提供负载均衡、SSL 终止和基于名称的虚拟托管。Ingress 配置的 YAML 文件如下所示；注意所有服务可以在不同 URL 路径上的相同端口`80`上访问：

```java
apiVersion: extensions/v1beta1
kind: Ingress
metadata:
 name: gateway-ingress
spec:
 backend:
  serviceName: default-http-backend
  servicePort: 80
 rules:
 - host: microservices.example.pl
   http:
   paths:
   - path: /account
     backend:
       serviceName: account-service
       servicePort: 8091
   - path: /customer
     backend:
       serviceName: customer-service
       servicePort: 8092 
   - path: /order
     backend:
       serviceName: order-service
       servicePort: 8090 
   - path: /product
     backend:
       serviceName: product-service
       servicePort: 8093 
```

# 维护集群

维护 Kubernetes 集群是非常复杂的。在本节中，我们将向您展示如何使用一些基本命令和 UI 仪表板来查看集群上当前存在的对象。首先，我们列出为运行我们的微服务 based 系统而创建的元素。首先，我们通过运行`kubectl get deployments`命令来显示部署列表，这应该会导致以下结果：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/2e7394a7-2440-45a6-abdb-b4bb42eec586.png)

一个部署可以创建多个 pods。您可以如下调用`kubectl get pods`命令来查看 pods 列表：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/3603bc5a-2cef-41ac-a82e-3b2a96cfbeeb.png)

可以使用 UI 仪表板查看相同的列表。通过点击选中的行或者点击每行右侧的图标来查看这些详细信息，如下图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/82fecacc-7077-472a-b216-14d941e30e55.png)

可以使用命令`kubectl get services`显示所有可用服务的完整列表。这里有一些有趣的字段，包括一个指示集群内部可用服务 IP 地址的字段（CLUSTER-IP），以及服务内部和外部暴露的一对端口（PORT(S)）。我们还可以通过`http://192.168.99.100:31099`调用`account-service`上暴露的 HTTP API，或者通过`http://192.168.99.100:31931`调用 Eureka UI 仪表板，如下所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/0307a557-39dc-4f7d-98af-f49d8c3c73a7.png)

与之前的对象类似，服务也可以使用 Kubernetes 仪表板显示，如下所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/6d5eb014-3315-437a-861c-69c44ff7a67b.png)

# 概要

在本章中，我们讨论了许多与 Spring Cloud 明显不相关的主题，但本章解释的工具将使您能够利用迁移到基于微服务的架构。在使用 Docker、Kubernetes 或 CI/CD 工具时，采用 Spring Cloud 进行云原生开发具有明显的优势。当然，所有示例都已在本机上启动，但您可以参考这些示例来想象该过程如何在远程机器集群的生产环境中设计。

在本章中，我们想向您展示将 Spring 微服务手动运行在本地机器转变为完全自动化的过程是多么简单和快速，该过程从源代码构建应用程序，创建包含应用程序的 Docker 镜像，并在由多台机器组成的集群上部署它。在一章中很难描述 Docker、Kubernetes 或 Jenkins 等复杂工具提供的所有功能。取而代之的是，这里的主要目的是为您提供如何基于容器化、自动化部署、扩展和私有、本地云等概念设计和维护现代架构的更广阔视野。

现在，我们离书的结尾已经非常近了。我们已经讨论了与 Spring Cloud 框架相关的计划主题的大部分。在下一章中，我们将向您展示如何使用两个最受欢迎的在线云平台，使您能够持续交付 Spring Cloud 应用程序。


# 第十五章：云平台上的 Spring 微服务

Pivotal 将 Spring Cloud 定义为一个加速云原生应用程序开发的框架。今天，当我们谈论云原生应用程序时，首先想到的是快速交付软件的能力。为了满足这些需求，我们应该能够快速构建新的应用程序并设计可扩展、可移植且准备频繁更新的架构。提供容器化和编排机制的工具帮助我们设置和维护此类架构。实际上，像 Docker 或 Kubernetes 这样的工具，我们在之前的章节中已经探讨过，允许我们创建自己的私有云并在其上运行 Spring Cloud 微服务。尽管应用程序不必部署在公共云上，但它包含了云软件最重要的特性。

在公共云上部署您的 Spring 应用程序只是一个可能性，而不是必需的。然而，确实有一些非常有趣的云平台，可以让您在几分钟内轻松运行微服务并将它们暴露在网络上。其中一个平台是**Pivotal Cloud Foundry**（**PCF**）；它与其他平台相比的优势在于其对 Spring Cloud 服务的原生支持，包括使用 Eureka 的发现、Config Server 以及使用 Hystrix 的断路器。您还可以通过启用 Pivotal 提供的托管服务轻松设置完整的微服务环境。

我们还应该提到的另一个云平台是 Heroku。与 PCF 相比，它不偏爱任何编程框架。Heroku 是一个全托管的、多语言平台，可以让您快速交付软件。一旦您将存储在 GitHub 仓库中的源代码更改推送到 Heroku，它就可以自动构建和运行应用程序。它还提供许多可以单命令部署和扩展的附加服务。

本章涵盖的主题如下：

+   Pivotal Web Services 平台简介

+   使用 CLI、Maven 插件和 UI 仪表板在 Pivotal Cloud Foundry 上部署和管理应用程序

+   使用 Spring Cloud Foundry 库准备应用程序以在平台上正确运行

+   在 Heroku 平台上部署 Spring Cloud 微服务

+   管理托管服务

# Pivotal Cloud Foundry

尽管 Pivotal 平台可以运行用多种语言编写的应用程序，包括 Java、.NET、Ruby、JavaScript、Python、PHP 和 Go，但它对 Spring Cloud Services 和 Netflix OSS 工具的支持最为出色。这是有道理的，因为它们是开发 Spring Cloud 的人。看看下面的图表，也可在 Pivotal 的官方网站上找到。下面的图表说明了 Pivotal Cloud 平台提供的基于微服务的架构。你可以在 Cloud Foundry 上使用 Spring Cloud 快速利用常见的微服务模式，包括分布式配置管理、服务发现、动态路由、负载均衡和容错：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/5b400ae4-44d3-4476-9425-dfe2194be84e.png)

# 使用模型

你可以以三种不同的模型使用 Pivotal 平台。模型是根据宿主区分，这是应用程序被部署的地方。以下是可用的解决方案列表：

+   **PCF Dev**: 这个 Pivotal 平台的实例可以在单个虚拟机上本地运行。它旨在满足实验和开发的需求。它并不提供所有可能的特性和服务。例如，它只有一些内置服务，如 Redis、MySQL 和 RabbitMQ。然而，PCF Dev 也支持**Spring Cloud Services**（**SCS**），以及 PCF 完整版本中支持的所有语言。需要注意的是，如果你想本地运行带有 SCS 的 PCF Dev，你需要有超过 6GB 的可用 RAM。

+   **Pivotal Web Services**: 这是一个在线的云原生平台，网址为[`run.pivotal.io/`](https://run.pivotal.io/)。它就像 Pivotal Cloud Foundry，但有由 SaaS 合作伙伴提供的服务，以及按小时计费的托管服务。它并不提供 Pivotal Cloud Foundry 中可用的所有特性和服务。Pivotal Web Services 最适合初创公司或个人团队。在本书接下来的部分，我们将使用这个 Pivotal 平台托管模型进行展示。

+   **Pivotal Cloud Foundry**：这是一个功能全面的云原生平台，可以在任何主要的公共 IaaS 上运行，包括 AWS、Azure 和 Google Cloud Platform，或者基于 OpenStack 或 VMware vSphere 的私有云上运行。这是一个针对大型企业环境的商业解决方案。

# 准备应用程序

由于 Pivotal Web Services 对 Spring Cloud 应用有本地支持，所以部署过程非常简单。但是，它需要在应用程序方面指定特定的依赖项和配置—特别是如果你的微服务必须与 Pivotal 平台提供的内置服务（如服务注册表、配置服务器或断路器）集成。除了 Spring Cloud 的标准依赖管理外，我们还应该在`pom.xml`中包括`spring-cloud-services-dependencies`，并且是与`Edgware.SR2`发布列车一起工作的最新版本，如下所示：

```java
<dependencyManagement>
    <dependencies>
        <dependency>
            <groupId>org.springframework.cloud</groupId>
            <artifactId>spring-cloud-dependencies</artifactId>
            <version>Edgware.SR2</version>
            <type>pom</type>
            <scope>import</scope>
        </dependency>
        <dependency>
            <groupId>io.pivotal.spring.cloud</groupId>
            <artifactId>spring-cloud-services-dependencies</artifactId>
            <version>1.6.1.RELEASE</version>
            <type>pom</type>
            <scope>import</scope>
        </dependency>
    </dependencies>
</dependencyManagement>
```

根据所选的集成服务，您可能希望将以下工件包括在您的项目中。我们决定使用 Pivotal 平台提供的所有 Spring Cloud 功能，因此我们的微服务从配置服务器获取属性，在 Eureka 中注册自己，并将服务间通信封装在 Hystrix 命令中。以下是为在 Pivotal 平台上部署的应用程序启用发现客户端、配置客户端和断路器所需的依赖项：

```java
<dependency>
    <groupId>io.pivotal.spring.cloud</groupId>
    <artifactId>spring-cloud-services-starter-circuit-breaker</artifactId>
</dependency>
<dependency>
    <groupId>io.pivotal.spring.cloud</groupId>
    <artifactId>spring-cloud-services-starter-config-client</artifactId>
</dependency>
<dependency>
    <groupId>io.pivotal.spring.cloud</groupId>
    <artifactId>spring-cloud-services-starter-service-registry</artifactId>
</dependency>
```

我们将为我们的示例微服务提供另一个集成。它们都将将数据存储在 MongoDB 中，该 MongoDB 也作为 Pivotal 平台上的服务提供。为了实现这一点，我们首先应该在项目依赖项中包括启动器`spring-boot-starter-data-mongodb`：

```java
<dependency>
 <groupId>org.springframework.boot</groupId>
 <artifactId>spring-boot-starter-data-mongodb</artifactId>
</dependency>
```

在配置设置中应使用`spring.data.mongodb.uri`属性提供 MongoDB 地址。为了允许应用程序与 MongoDB 连接，我们必须创建一个 Pivotal 的服务 mLab，然后将其绑定到应用程序。默认情况下，与绑定服务相关的元数据作为环境变量`$VCAP_SERVICES`暴露给应用程序。这种方法的主要动机是，Cloud Foundry 被设计为多语言的，这意味着任何语言和平台都可以作为构建包支持。所有 Cloud Foundry 属性都可以使用`vcap`前缀注入。如果您想访问 Pivotal 的服务，您应该使用`vcap.services`前缀，然后传递如下所示的服务名称：

```java
spring:
 data:
  mongodb:
   uri: ${vcap.services.mlab.credentials.uri}
```

实际上，应用程序方面需要做的就是与在 Pivotal 平台上创建的组件正确配合。现在我们只需要像对用 Spring 编写的标准微服务一样启用 Spring Cloud 功能，如下例所示：

```java
@SpringBootApplication
@EnableDiscoveryClient
@EnableFeignClients
@EnableCircuitBreaker
public class OrderApplication {

    public static void main(String[] args) {
        SpringApplication.run(OrderApplication.class, args);
    }

}
```

# 部署应用程序

应用程序可以通过三种不同的方式在**Pivotal Web Service**（**PWS**）平台上进行管理。第一种是通过位于[`console.run.pivotal.io`](https://console.run.pivotal.io)的 web 控制台。我们可以通过这种方式监控、扩展、重新启动部署的应用程序，启用和禁用服务，定义新的配额，更改账户设置。然而，使用 web 控制台无法完成这项工作——也就是说，初始应用程序部署。这可以通过**CLI**（**命令行界面**）完成。您可以从[pivotal.io](https://pivotal.io)网站下载所需的安装程序。安装后，您应该能够在您的机器上通过输入`cf`来调用 Cloud Foundry CLI，例如，`cf help`。

# 使用 CLI

CLI 提供了一组命令，允许您管理在 Cloud Foundry 上的应用程序、有偿服务、空间、域和其他组件。让我向您展示一些最重要的命令，您需要了解这些命令才能在 PWS 上运行您的应用程序：

1.  为了部署应用程序，你首先必须导航到其目录。然后使用以下`cf login`命令登录 PWS：

```java
$ cf login -a https://api.run.pivotal.io 
```

1.  下一步是使用`cf push`命令将应用程序推送到 PWS，并传递服务的名称：

```java
$ cf push account-service -p target/account-service-1.0.0-SNAPSHOT.jar
```

1.  另外，你可以在应用程序的根目录下提供`manifest.yml`文件，其中包含所有必需的部署设置。在这种情况下，你只需要运行没有任何额外参数的`cf push`命令，如下所示：

```java
---
applications:
- name: account-service
  memory: 300M
  random-route: true
  path: target/account-service-1.0-SNAPSHOT.jar
```

1.  使用`manifest.yml`中提供的配置设置部署将失败。要了解原因，请运行命令`cf logs`。原因是堆内存限制不足：

```java
$ cf logs account-service --recent
```

默认情况下，平台为代码缓存分配了 240 MB，为元空间分配了 140 MB，并为每个线程分配了 1 MB，假设 Tomcat 连接器最多有 200 个线程。很容易计算出，根据这些设置，每个应用程序需要大约 650 MB 的分配内存。我们可以通过调用`cf set-env`命令并传递`JAVA_OPTS`参数来更改这些设置，如您在以下示例中看到的。这样的内存限制在生产模式中是不够的，但在测试目的上应该是可以的。为确保这些更改生效，使用以下`cf restage`命令：

```java
$ cf set-env account-service JAVA_OPTS "-Xmx150M -Xss250K -XX:ReservedCodeCacheSize=70M -XX:MaxMetaspaceSize=90M"
$ cf restage account-service
```

分配的内存很重要，特别是如果只有 2 GB RAM 可供免费账户使用。应用默认的内存设置，我们只能在 Pivotal 平台上部署两个应用程序，因为每个应用程序都会占用 1 GB 的 RAM。尽管我们解决了前面描述的问题，但我们的应用程序仍然无法正常工作。

# 绑定服务

在启动过程中，应用程序无法与所需服务连接。问题发生是因为服务默认情况下不会绑定到应用程序。你可以通过运行命令`cf services`来显示你在你的空间中创建的所有服务，并通过调用命令`cf bind-service`将每个服务绑定到给定的微服务。在以下命令执行示例中，我们将 Eureka、配置服务器和 MongoDB 绑定到`account-service`。最后，我们再次运行`cf restage`，一切应该都能正常工作，如下所示：

```java
$ cf bind-service account-service discovery-service
$ cf bind-service account-service config-service
$ cf bind-service account-service sample-db
```

# 使用 Maven 插件

正如我们之前提到的，CLI 和 Web 控制台并不是在 Pivotal 平台上管理应用程序的唯一方式。Cloud Foundry 团队已经实现了 Maven 插件，以促进和加快应用程序的部署。有趣的是，同一个插件可以用来管理任何 Cloud Foundry 实例的推送和更新，不仅仅是由 Pivotal 提供的实例。

当使用 Cloud Foundry 的 Maven 插件时，你可以轻松地将云部署集成到他们的 Maven 项目的生命周期中。这允许你在 Cloud Foundry 中推送、删除和更新项目。如果你想要与 Maven 一起推送你的项目，只需运行以下命令：

```java
$ mvn clean install cf:push
```

通常，Maven 插件提供的命令与 CLI 提供的命令非常相似。例如，你可以通过执行命令`mvn cf:apps`来显示应用程序列表。要删除一个应用程序，请运行以下命令：

```java
$ mvn cf:delete -Dcf.appname=product-service
```

如果你想要上传一些更改到现有应用程序，请使用以下`cf:update`命令：

```java
$ mvn clean install cf:update
```

在运行任何命令之前，我们必须正确配置插件。首先，需要传递 Cloud Foundry 登录凭据。建议将它们单独存储在 Maven 的`settings.xml`中。服务器标签内的典型条目可能如下所示：

```java
<settings>
    ...
    <servers>
        <server>
            <id>cloud-foundry-credentials</id>
            <username>piotr.minkowski@play.pl</username>
            <password>123456</password>
        </server>
    </servers>
    ...
</settings>
```

使用 Maven 插件而不是 CLI 命令有一个重要的优势：你可以在一个地方配置所有必要的配置设置，并在应用构建时使用一个命令应用它们。插件的完整配置如下所示。除了包括空间、内存和实例数量等一些基本设置外，还可以通过`JAVA_OPTS`环境变量和将所需服务绑定到应用程序来改变内存限制。在运行`cf:push`命令后，`product-service`可以在`https://product-service-piomin.cfapps.io/`地址上使用：

```java
<plugin>
    <groupId>org.cloudfoundry</groupId>
    <artifactId>cf-maven-plugin</artifactId>
    <version>1.1.3</version>
    <configuration>
        <target>http://api.run.pivotal.io</target>
        <org>piotr.minkowski</org>
        <space>development</space>
        <appname>${project.artifactId}</appname>
        <memory>300</memory>
        <instances>1</instances>
        <server>cloud-foundry-credentials</server>
        <url>https://product-service-piomin.cfapps.io/</url>
        <env>
            <JAVA_OPTS>-Xmx150M -Xss250K -XX:ReservedCodeCacheSize=70M -XX:MaxMetaspaceSize=90M</JAVA_OPTS>
        </env>
        <services>
            <service>
                <name>sample-db</name>
                <label>mlab</label>
                <plan>sandbox</plan>
            </service>
            <service>
                <name>discovery-service</name>
                <label>p-service-registry</label>
                <plan>standard</plan>
            </service>
            <service>
                <name>config-service</name>
                <label>p-config-server</label>
                <plan>standard</plan>
            </service>
        </services>
    </configuration>
</plugin>
```

# 维护

假设我们已经成功部署了构成我们示例微服务系统的所有应用程序，我们可以使用 Pivotal Web Services 仪表板轻松地管理和监控它们，甚至只需使用 CLI 命令。Pivotal 平台提供的免费试用为我们维护应用程序提供了许多可能性和工具，所以让我们探索它的一些最有趣的功能。

# 访问部署详情

我们可以通过运行`cf apps`命令或通过在 Web 控制台中导航到我们空间的主页来列出所有已部署的应用程序。你可以在下面的屏幕截图中看到这个列表。表格的每一行代表一个单独的应用程序。除了它的名称外，还有关于其状态、实例数量、分配的内存、部署时间和平台外可访问服务的外部 URL 的信息。如果你在应用部署时没有指定一个 URL 地址，它会自动生成：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/d7008b6a-1a4a-48f7-ae30-e023ba2cdea5.png)

你可以点击每一行以发现有关应用程序的详细信息。使用 CLI 命令`cf app <app-name>`或`cf app order-service`也可以获取类似的信息。下面的屏幕截图显示了一个应用程序详细视图的主要面板，其中包含事件历史、摘要以及每个实例的内存、磁盘和 CPU 使用情况。在这个面板中，你可以通过点击缩放按钮来扩展应用程序。还有几个其他标签可用。通过切换到其中一个，你可以查看所有绑定服务（服务）、分配的外部 URL（规则）、显示日志（日志）和传入请求历史（追踪）：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/c7138419-e97b-4074-ba2a-8d63462ee396.png)

当然，你总是可以使用 CLI 来收集前例中显示的相同细节。如果你执行命令`cf logs <app-name>`，你会附加到由应用程序生成的`stdout`。你还可以显示已激活的 Pivotal 管理服务的列表，以及绑定应用程序的列表，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/49fb545e-aaf7-4097-ac10-3b696d072ac7.png)

# 管理应用程序生命周期

Pivotal Web Services 提供的另一个非常有用的功能是管理应用程序生命周期的能力。换句话说，我们只需点击一次就可以轻松地停止、启动和重新启动一个应用程序。在执行请求的命令之前，你会被提示确认，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/39623686-56f6-4fc7-896d-fdea0b62651c.png)

以下任一 CLI 命令运行可以达到相同的效果：

```java
$ cf stop <app-name>
$ cf restart <app-name>
$ cf start <app-name>
```

# 扩展

使用云解决方案最重要的原因之一是能够轻松扩展应用程序。Pivotal 平台以非常直观的方式处理这些问题。首先，你可能决定在每个部署阶段启动应用程序的实例数量。例如，如果你决定使用`manifest.yml`并使用`cf push`命令部署它，创建的实例数量将由字段实例决定，如下面的代码片段所示：

```java
---
applications:
- name: account-service
  memory: 300M
  instances: 2
  host: account-service-piomin
  domain: cfapps.io
  path: target/account-service-1.0-SNAPSHOT.jar
```

运行实例的数量，以及内存和 CPU 的限制，可以在启动的应用程序中进行修改。实际上，有两种可用的扩展方法。你可以手动设置应该启动多少实例，或者启用自动扩展，你只需要基于选定指标的阈值定义一个标准。Pivotal 平台上的自动扩展是通过一个名为**PCF App Autoscaler**的工具实现的。我们可以从以下五个可用的规则中选择，如下所示：

+   CPU 利用率

+   内存利用率

+   HTTP 延迟

+   HTTP 吞吐量

+   RabbitMQ 深度

你可以定义多个活跃规则。每个这些规则都有每个单一指标缩放 down 的最小值和缩放 up 的最大值。`customer-service`的自动扩展设置如下面的截图所示。在这里，我们决定应用 HTTP 吞吐量和 HTTP 延迟规则。如果 99%的流量延迟低于`20`毫秒，应该禁用一个应用程序实例，以防有多个实例。类似地，如果延迟超过`200`毫秒，平台应该附加一个更多的实例：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/f2434974-9f83-409d-a93e-9c1aec8cc445.png)

我们也可以手动控制运行实例的数量。自动扩展有很多优点，但手动方法能让你对这个过程有更多的控制权。由于每个应用程序的内存有限，仍有多余的空间用于其他实例。我们示例系统中压力最大的应用程序是`account-service`，因为它在订单创建以及订单确认时都会被调用。所以，让我们为这个微服务添加一个实例。为此，请前往`account-service`详情面板，点击进程和实例下的扩展。然后，你应该增加实例数量并应用必要的更改；你应该会看到`account-service`有两个实例可用，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/869909e6-33a2-4151-84d1-ecfae35dad37.png)

# 托管服务的部署

我们已经查看了如何使用`cf bind-service`命令和 Maven 插件将应用程序绑定到服务。然而，我们现在应该看看如何启用和配置我们的服务。你可以轻松显示所有可用服务的列表，然后使用 Pivotal 的仪表板启用它们；这可以在市场下找到。

使用 Pivotal Web Services 提供的托管服务非常简单。安装后，一些服务无需任何额外配置即可使用。我们只需要将它们绑定到选定的应用程序，并在应用程序的设置中正确传递它们的网络地址。每个应用程序都可以通过 UI 仪表板轻松绑定到服务。首先，导航到服务的主页面。在那里，你会看到当前已绑定应用程序的列表。你可以通过点击绑定应用并从显示的列表中选择一个来将新应用程序绑定到服务，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/035ead31-9dd9-40a4-9da5-ba408e11c627.png)

你只需要在市场上下启用注册表服务并将其绑定到应用程序，就可以在 Pivotal Web Services 上启用发现功能。当然，如果需要，你可以在客户端覆盖一些配置设置。可以在服务的主要配置面板下的管理中显示注册的所有应用程序的完整列表。由于我们在上一节中扩展了它，`account-service`有两个运行实例；其他微服务只有一个运行实例，如下所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/ef76969f-c91d-408d-806f-f8a65b90e841.png)

与发现服务相比，配置服务器需要包括额外的设置。像以前一样，你应该导航到它的主面板，然后选择“管理”。在这里，你会被重定向到配置表单。配置参数必须以 JSON 对象的形式提供在那里。`count`参数指定了需要预配的节点的数量，如果实例可以升级的升级选项，以及`force`即使实例已经是可用的最新版本也强制升级。其他配置参数取决于用于存储属性源的后端类型。正如您可能还记得第五章，*使用 Spring Cloud Config 进行分布式配置*，Spring Cloud Config Server 最受欢迎的解决方案是基于 Git 仓库的。我们在 GitHub 上创建了一个示例仓库，其中提交了所有所需的源代码。以下是在 Pivotal Web Services 上为 Config Server 提供的 JSON 格式的参数：

```java
{
    "count": 1,
    "git": {
        "password": "****",
        "uri": "https://github.com/piomin/sample-spring-cloud-pcf-config.git",
        "username": "piomin"
    }
}
```

示例应用程序使用的最后一个代理服务托管了一个 MongoDB 实例。在服务的管理主面板中导航到“管理”，你应该会被重定向到[`mlab.com/home`](https://mlab.com/home)，在那里你可以使用数据库节点。

# Heroku 平台

Heroku 是使用**PaaS**（**平台即服务**）模型创建的最古老的云平台之一。与 Pivotal Cloud Foundry 相比，Heroku 没有内置的对 Spring Cloud 应用程序的支持。这使我们的模型稍微复杂了一些，因为我们不能使用平台的服务的典型微服务组件，包括服务发现、配置服务器或断路器。尽管如此，Heroku 包含了一些 Pivotal Web Services 没有的非常有趣的功能。

# 部署方法

我们可以使用 CLI、网络控制台或专用的 Maven 插件来管理我们的应用程序。在 Heroku 上部署应用程序与在 Pivotal 平台上部署非常相似，但方法有些不同。主要方法假设你是通过从本地 Git 仓库或 GitHub 存储的源代码构建应用程序的。构建完成后，Heroku 平台会自动执行，当你向仓库的分支推送了一些更改，或者从选定分支的最新版本中按需执行。部署应用程序的另一种有趣方式是将你的 Docker 镜像推送到 Heroku 的容器注册表。

# 使用 CLI

你可以从[`cli-assets.heroku.com/heroku-cli/channels/stable/heroku-cli-x64.exe`](https://cli-assets.heroku.com/heroku-cli/channels/stable/heroku-cli-x64.exe)下载**Heroku 命令行界面**（**CLI**），这是为 Windows 用户提供的（对于 Windows 用户）。为了使用 CLI 在 Heroku 上部署和运行你的应用程序，你必须按照以下步骤进行：

1.  安装后，你可以在 shell 中使用`Heroku`命令。首先，使用你的凭据登录到 Heroku，如下所示：

```java
$ heroku login
Enter your Heroku credentials:
Email: piotr.minkowski@play.pl
Password: ********
Logged in as piotr.minkowski@play.pl 
```

1.  接下来，导航到应用的`root`目录并在 Heroku 上创建一个应用。在运行以下命令后，不仅会创建应用，还会创建一个名为`heroku`的 Git 远程。这与你本地的 Git 仓库相关联，如下所示：

```java
$ heroku create
Creating app... done, aqueous-retreat-66586
https://aqueous-retreat-66586.herokuapp.com/ | https://git.heroku.com/aqueous-retreat-66586.git
Git remote heroku added 
```

1.  现在你可以通过将代码推送到 Heroku 的 Git 远程来部署你的应用。Heroku 会为你完成所有工作，具体如下：

```java
$ git push heroku master
```

1.  如果应用启动成功，你将能够使用一些基本命令来管理它。根据以下顺序，你可以显示日志、更改运行中的 dyno 数量（换句话说，扩展应用）、分配新的附加组件，以及列出所有启用的附加组件：

```java
$ heroku logs --tail
$ heroku ps:scale web=2
$ heroku addons:create mongolab
$ heroku addons
```

# 连接到 GitHub 仓库

个人而言，我更喜欢通过连接到项目的 GitHub 仓库来将我的应用部署到 Heroku。关于这种部署方法有两种可能的方法：手动和自动。你可以通过导航到应用详情面板上的**部署**标签，然后将其连接到指定的 GitHub 仓库，如以下屏幕截图所示。如果你点击“部署分支”按钮，将在给定的 Git 分支上立即开始构建和部署。另外，你也可以通过点击**启用自动部署**来在选定的分支上启用自动部署。此外，如果你为你的 GitHub 仓库启用了持续集成，你还可以配置 Heroku 等待持续集成构建结果；这是一个非常有用的功能，因为它允许你在推送之前运行项目的自动化测试：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/af757b79-ef60-441e-8b89-735019c51cf2.png)

# Docker 容器注册表

紧跟最新趋势，Heroku 允许你使用 Docker 部署容器化应用。为了做到这一点，你应该在你的本地机器上安装 Docker 和 Heroku CLI：

1.  首先，通过运行命令`heroku login`登录到 Heroku 云。下一步是登录到容器注册表：

```java
$ heroku container:login
```

1.  接下来，确保你的当前目录包含`Dockerfile`。如果存在，你可以通过执行以下命令来构建并在 Heroku 容器注册表中推送镜像：

```java
$ heroku container:push web
```

1.  如果你有一个现有的构建镜像，你可能只对给镜像打标签并推送到 Heroku 感兴趣。为了做到这一点，你需要使用 Docker 的命令行，通过执行以下命令来实现（假设你的应用名称是`piomin-order-service`）：

```java
$ docker tag piomin/order-service registry.heroku.app/piomin-order-service/web
$ docker push registry.heroku.app/piomin-order-service/web
```

成功推送镜像后，新应用应该在 Heroku 仪表板上可见。

# 准备应用

当将基于 Spring Cloud 组件的应用程序部署到 Heroku 时，我们不再需要对其源代码进行任何额外的更改或添加任何额外的库，这是我们本地在本地运行它时所需要做的。这里唯一的不同在于配置设置，我们需要设置一个地址以便将应用程序与服务发现、数据库或任何其他可以为您微服务启用的附加组件集成。当前的示例，与 Pivotal 的部署示例相同，是将数据存储在分配给应用程序作为 mLab 服务的 MongoDB 中。另外，在这里，每个客户端都会在作为`piomin-discovery-service`部署的 Eureka 服务器上注册自己。下面的屏幕截图显示了部署在 Heroku 上的我们示例中的应用程序列表：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/1493f39a-d047-4aea-82b9-a8f65138f866.png)

我将前面的应用程序通过连接 GitHub 仓库部署到 Heroku。这要求你为每个微服务创建一个单独的仓库。例如，`order-service`的仓库可在[`github.com/piomin/sample-heroku-order-service.git;`](https://clicktime.symantec.com/a/1/T35T4GHVxyO3_yEnmgYJzEOMwTYVoyfmLx2ONL0JOmM=?d=Em-4WZBG8KjUF8i64GiOj94xj1zxN6a1uB0eVZ0nPiAMBASzKXYmiNLpRNEcgxEQ7bHQ6AzvMbnrWHqhusJvYyZqTNMHlShDuReFC57yByy3O9bujQaWuS_jFkuW-GXlbAc9l9L2CmOU0k0c7iCbz4TP6gxYzTpi3F2ZhiR4yOGU_aIfM0-ImE4VjE3Zwu5hcRLW6fRjQIpA00TbvIfq03qKyXpN4rOeSy-uW8xOD3AifhkEun4HB33yo6UpNlLAVK45YxrUxZn2iT_VdnO336VCgrUe4QGzCEoQEtzN_eTC5eSH0FHDXyXwW0Aj4Px9YTY5asaj9oWluYR6xuKHwLEyHqyAWSKmRhRVXDNsi3pF13hLo94F&u=https%3A%2F%2Fgithub.com%2Fpiomin%2Fsample-heroku-order-service.git)进行测试。

现在让我们来看看为其中一个示例应用程序提供的配置设置：`account-service`。首先，我们必须覆盖 MongoDB 的自动配置地址，使用 Heroku 平台提供的`MONGODB_URI`环境变量。还必须提供正确的 Eureka 服务器地址，以及覆盖注册时发现客户端发送的主机名和端口。这是因为默认情况下，每个应用程序都会尝试使用对其他应用程序不可用的内部地址进行注册。如果不覆盖这些值，使用 Feign 客户端的服务间通信将失败：

```java
spring:  
   application:
     name: account-service
   data:
     mongodb:
       uri: ${MONGODB_URI}
 eureka:
   instance:
     hostname: ${HEROKU_APP_NAME}.herokuapp.com
     nonSecurePort: 80
   client:
     serviceUrl:
       defaultZone: http://piomin-discovery-service.herokuapp.com/eureka
```

请注意，环境变量`HEROKU_APP_NAME`是部署在 Heroku 上的当前应用程序的名称，如前面的片段中所见。这并非默认可用。要为您的应用程序启用变量，例如`customer-service`，请运行以下命令并使用实验性附加组件`runtime-dyno-metadata`：

```java
$ heroku labs:enable runtime-dyno-metadata -a piomin-customer-service
```

# 测试部署

-   部署后，每个应用程序都可以在其名称和平台域名组成的地址上访问，例如，[`piomin-order-service.herokuapp.com`](http://piomin-order-service.herokuapp.com)。您可以使用 URL 调用 Eureka 仪表板，即 [`piomin-discovery-service.herokuapp.com/`](http://piomin-discovery-service.herokuapp.com/)，这将允许您检查我们的示例微服务是否已注册。如果一切工作正常，您应该会看到类似于以下屏幕截图的东西：

-   ![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/bb34151b-5ecb-4d64-a7da-81f5952e4964.png)

-   每个微服务都暴露了由 Swagger2 自动生成的 API 文档，所以你可以通过从`/swagger-ui.html`获取的 Swagger UI 仪表板轻松地测试每个端点；例如，[`piomin-order-service.herokuapp.com/swagger-ui.html`](http://piomin-order-service.herokuapp.com/swagger-ui.html)。`order-service`的 HTTP API 视图如下：

-   ![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/60d46f83-d38c-463b-ba49-0b43c99810e9.png)

-   每个微服务都在 MongoDB 中存储数据。这个数据库可以通过向 Heroku 项目添加插件来启用，例如 mLab。正如您可能记得的，我们已经在 Pivotal 平台上部署的应用程序中使用过相同服务的示例来存储数据。插件可以通过在应用程序的详细信息面板的资源标签中为其选择计划来为应用程序启用。完成后，您可以简单地点击它来管理每个插件。对于 mLab，您将被重定向到 mLab 网站([mlab.com](https://mlab.com/))，在那里您可以查看所有集合、用户和生成的统计信息的列表。以下屏幕截图说明了我们的示例的 mLab 仪表板：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/d791eac0-4a61-4ca2-a7a2-016a446821af.png)

# -   总结

-   我们的 Spring Cloud 微服务之旅已经结束！我们的练习始于在本地机器上的简单部署，但在上一章中，我们的微服务部署在完全由云供应商管理的环境中，该环境还自动构建、启动并在指定域名上暴露 HTTP API。我个人认为，我们能够如此轻松地使用任何一种流行的编程语言或第三方工具（如数据库或消息代理）运行、扩展和将数据暴露于应用程序之外，这是非常惊人的。事实上，我们中的每一个人现在都可以在几小时内实施并将一个生产就绪的应用程序部署到网上，而无需担心必须安装的软件。

本章向你们展示了如何在不同的平台上轻松运行 Spring Cloud 微服务。所给示例说明了云原生应用的真正力量。无论你是在自己的笔记本电脑上本地启动应用，还是在 Docker 容器内，使用 Kubernetes，或是在如 Heroku 或 Pivotal Web Services 这样的在线云平台上启动应用，你都不需要在应用的源代码中做任何更改；修改只需要在其属性中进行。（假设你在你的架构中使用 Config Server，这些更改是非侵入性的。）

在过去的两章中，我们探讨了 IT 世界中的一些最新趋势。如持续集成和持续部署（CI 和 CD）、使用 Docker 的容器化、使用 Kubernetes 的编成以及云平台等主题正被越来越多的组织所使用。实际上，这些解决方案在微服务的日益普及中起到了部分作用。目前，在这个编程领域有一个领导者——Spring Cloud。没有其他 Java 框架有如此多的功能，或者能够实现与微服务相关的如此多的模式，如 Spring Cloud。我希望这本书能帮助你在构建和精炼你的基于微服务的企业系统时有效地使用这个框架。
