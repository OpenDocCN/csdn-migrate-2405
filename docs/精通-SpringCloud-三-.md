# 精通 SpringCloud（三）

> 原文：[`zh.annas-archive.org/md5/3341AF3ECE66B2253A7F83A5D112367C`](https://zh.annas-archive.org/md5/3341AF3ECE66B2253A7F83A5D112367C)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十章：额外的配置和发现功能

我们在第四章*服务发现*和第五章*使用 Spring Cloud Config 进行分布式配置*中详细讨论了服务发现和分布式配置。我们讨论了两个解决方案。第一个，Eureka，由 Netflix OSS 提供，并被 Spring Cloud 用于服务发现。第二个是仅致力于分布式配置的 Spring Cloud Config 项目。然而，市场上有一些有趣的产品，它们有效地结合了这两项功能。目前，Spring Cloud 支持其中的两个：

+   **Consul**：这个产品是由 HashiCorp 构建的。它是一个高可用的分布式解决方案，旨在连接和配置跨动态、分布式基础设施的应用程序。Consul 是一个相当复杂的产品，具有多个组件，但其主要功能是在任何基础设施上发现和配置服务。

+   **Zookeeper**：这个产品是由 Apache 软件基金会构建的。它是一个用 Java 编写的分布式、层次化的键/值存储。它旨在维护配置信息、命名和分布式同步。与 Consul 相比，它更像是原始的键/值存储，而不是现代的服务发现工具。然而，Zookeeper 仍然非常受欢迎，特别是对于基于 Apache 软件栈的解决方案。

支持该领域内的另外两个流行产品仍处于开发阶段。以下项目尚未添加到官方 Spring Cloud 发行版中：

+   **Kubernetes**：这是一个开源解决方案，旨在自动化容器化应用程序的部署、扩展和管理，最初由 Google 创建。目前这个工具非常受欢迎。最近，Docker 平台开始支持 Kubernetes。

+   **Etcd**：这是一个用 Go 编写的分布式可靠键/值存储，用于存储分布式系统中最关键的数据。许多公司和软件产品在生产环境中使用它，例如 Kubernetes。

在本章中，我将只介绍官方支持的两个解决方案，即 Consul 和 Zookeeper。Kubernetes，它不仅仅是键/值存储或服务注册表，将在第十四章*Docker 支持*中讨论。

# 使用 Spring Cloud Consul

Spring Cloud Consul 项目通过自动配置为 Consul 和 Spring Boot 应用程序提供集成。通过使用众所周知的 Spring Framework 注解风格，我们可以在微服务环境中启用和配置常见模式。这些模式包括使用 Consul 代理的服务发现，使用 Consul 键/值存储的分布式配置，使用 Spring Cloud Bus 的分布式事件，以及 Consul 事件。该项目还支持基于 Netflix 的 Ribbon 的客户端负载均衡器和一个基于 Netflix 的 Zuul 的 API 网关。在我们讨论这些特性之前，我们首先必须运行和配置 Consul 代理。

# 运行 Consul 代理

我们将从在本地机器上以最简单的方式启动 Consul 代理开始。使用 Docker 容器独立开发模式可以很容易地设置。以下是命令，它将从一个在 Docker Hub 上可用的官方 HashiCorp 镜像启动 Consul 容器：

```java
docker run -d --name consul -p 8500:8500 consul
```

启动后，Consul 可以在地址`http://192.168.99.100:8500`下访问。它暴露了 RESTful HTTP API，即主要接口。所有 API 路由都带有`/v1/`前缀。当然，不直接使用 API 也是可以的。还有一些编程库可以更方便地消费 API。其中之一是`consul-api`，这是用 Java 编写的客户端，也是 Spring Cloud Consul 内部使用的。还有由 Consul 提供的 web UI 仪表板，在相同的地址下，但上下文路径不同，为`/ui/`。它允许查看所有注册的服务和节点，查看所有健康检查及其当前状态，以及读取和设置键/值数据。

如我在本节前言中提到的，我们将使用 Consul 的三个不同功能——代理、事件和 KV 存储。每个功能都由一组端点代表，分别是`/agent`、`/event`和`/kv`。最有趣的代理端点是与服务注册相关的那些。以下是这些端点的列表：

| **方法** | **路径** | **描述** |
| --- | --- | --- |
| `GET` | `/agent/services` | 它返回已注册到本地代理的服务列表。如果 Consul 以集群模式运行，该列表可能与在集群成员之间执行同步之前由`/catalog`端点报告的列表不同。 |
| `PUT` | `/agent/service/register` | 它向本地代理添加了一个新服务。代理负责管理本地服务，并向服务器发送更新以执行全局目录的同步。 |
| `PUT` | `/agent/service/deregister/:service_id` | 它从本地代理中移除具有`service_id`的服务。代理负责在全球目录中注销该服务。 |

`/kv`端点用于管理简单的键/值存储，这对于存储服务配置或其他元数据特别有用。值得注意的是，每个数据中心都有自己的 KV 存储，因此为了在多个节点之间共享它，我们应该配置 Consul 复制守护进程。无论如何，这里是为管理键/值存储列出的三个端点：

| **方法** | **路径** | **描述** |
| --- | --- | --- |
| `GET` | `/kv/:key` | 它返回给定键名的值。如果请求的键不存在，则返回 HTTP 状态 404 作为响应。 |
| `PUT` | `/kv/:key` | 它用于向存储中添加新键，或者只是用键名更新现有键。 |
| `DELETE` | `/kv/:key` | 它是用于删除单个键或具有相同前缀的所有键的最后 CRUD 方法。 |

Spring Cloud 使用 Consul 事件来提供动态配置重载。其中有两个简单的 API 方法。第一个，`PUT /event/fire/:name`，触发一个新的事件。第二个，`GET /event/list`，返回一个事件列表，可能通过名称、标签、节点或服务名称进行过滤。

# 客户端集成

要在您的项目中激活 Consul 服务发现，您应该将启动器`spring-cloud-starter-consul-discovery`包含在依赖项中。如果您希望启用与 Consul 的分布式配置，只需包含`spring-cloud-starter-consul-config`。在某些情况下，您可能在客户端应用程序中使用这两个功能。然后，您应该声明对`spring-cloud-starter-consul-all`工件的依赖关系：

```java
<dependency>
    <groupId>org.springframework.cloud</groupId>
    <artifactId>spring-cloud-starter-consul-all</artifactId>
</dependency>
```

默认情况下，Consul 代理预计将在`localhost:8500`地址下可用。如果对于您的应用程序不同，您应该在`application.yml`或`bootstrap.yml`文件中提供适当的地址：

```java
spring:
 cloud:
  consul:
   host: 192.168.99.100
   port: 18500
```

# 服务发现

通过在主类上使用泛型的 Spring Cloud `@EnableDiscoveryClient`注解，可以使应用程序启用 Consul 发现。你应该记得从第四章，*服务发现*，因为与 Eureka 相比没有区别。默认服务名称也来自`${spring.application.name}`属性。在 GitHub 上的[`github.com/piomin/sample-spring-cloud-consul.git`](https://github.com/piomin/sample-spring-cloud-consul.git)存储库中提供了使用 Consul 作为发现服务器的微服务示例。系统的架构与前几章中的示例相同。有四个微服务，`order-service`、`product-service`、`customer-service`和`account-service`，并且 API 网关在`gateway-service`模块中实现。对于服务间通信，我们使用 Feign 客户端和 Ribbon 负载均衡器：

```java
@SpringBootApplication
@EnableDiscoveryClient
@EnableFeignClients
public class CustomerApplication {

    public static void main(String[] args) {
        new SpringApplicationBuilder(CustomerApplication.class).web(true).run(args);
    }

}
```

默认情况下，Spring Boot 应用程序在 Consul 中注册，实例 ID 是`spring.application.name`、`spring.profiles.active`、`server.port`属性值的拼接。在大多数情况下，确保 ID 是唯一的就足够了，但如果需要自定义模式，可以通过`spring.cloud.consul.discovery.instanceId`属性轻松设置：

```java
spring:
 cloud:
  consul:
   discovery:
    instanceId: ${spring.application.name}:${vcap.application.instance_id:${spring.application.instance_id:${random.value}}}
```

启动所有示例微服务后，查看 Consul UI 控制台。您应该会在那里看到四个不同的服务注册，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/8fa25939-b447-4d22-af84-19dab28e9745.png)

另外，您可以使用 RESTful HTTP API 端点`GET /v1/agent/services`查看已注册服务的列表。这是 JSON 响应的一个片段：

```java
"customer-service-zone1-8092": {
 "ID": "customer-service-zone1-8092",
 "Service": "customer-service",
 "Tags": [],
 "Address": "minkowp-l.p4.org",
 "Port": 8092,
 "EnableTagOverride": false,
 "CreateIndex": 0,
 "ModifyIndex": 0
},
"order-service-zone1-8090": {
 "ID": "order-service-zone1-8090",
 "Service": "order-service",
 "Tags": [],
 "Address": "minkowp-l.p4.org",
 "Port": 8090,
 "EnableTagOverride": false,
 "CreateIndex": 0,
 "ModifyIndex": 0
}
```

现在，您可以轻松地通过使用`pl.piomin.services.order.OrderControllerTest` JUnit 测试类向`order-service`发送一些测试请求来测试整个系统。一切应该都会正常工作，与使用 Eureka 进行发现相同。

# 健康检查

Consul 通过调用`/health`端点检查每个注册实例的健康状态。如果您不想在类路径中提供 Spring Boot Actuator 库，或者您的服务存在一些问题，它将会在网页控制台上显示出来：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/208a2cee-71ec-4469-b222-39572887b4ea.png)

如果出于任何原因健康检查端点在不同的上下文路径下可用，您可以通过`spring.cloud.consul.discovery.healthCheckPath`属性覆盖该路径。还可以通过定义`healthCheckInterval`属性来更改状态刷新间隔，例如，使用`10s`表示秒或`2m`表示分钟。

```java
spring:
 cloud:
  consul:
   discovery:
    healthCheckPath: admin/health
    healthCheckInterval: 20s
```

# 区域

我假设您还记得我们在第四章《服务发现》中关于 Eureka 的分区机制的讨论。当主机位于不同位置时，它很有用，您希望实例在同一区域之间进行通信。Spring Cloud Consul 的官方文档（[`cloud.spring.io/spring-cloud-static/spring-cloud-consul/1.2.3.RELEASE/single/spring-cloud-consul.html`](http://cloud.spring.io/spring-cloud-static/spring-cloud-consul/1.2.3.RELEASE/single/spring-cloud-consul.html)）没有提到这种解决方案，幸运的是这意味着它没有实现。Spring Cloud 提供了一个基于 Consul 标签的分区机制。应用程序的默认区域可以通过`spring.cloud.consul.discovery.instanceZone`属性进行配置。它设置了在`spring.cloud.consul.discovery.defaultZoneMetadataName`属性中配置的标签，并传递给传入的值。默认的元数据标签名是`zone`。

让我们回到示例应用程序。我将所有配置文件扩展了两个配置文件，`zone1`和`zone2`。这是`order-service`的`bootstrap.yml`文件：

```java
spring: 
 application:
  name: order-service
 cloud:
  consul:
   host: 192.168.99.100
   port: 8500

---
spring:
 profiles: zone1
 cloud:
  consul:
   discovery:
    instanceZone: zone1
server: 
 port: ${PORT:8090}

---
spring:
 profiles: zone2
  cloud:
   consul:
    discovery:
     instanceZone: zone2
server: 
 port: ${PORT:9090}
```

每个微服务在两个不同的区域都有两个运行实例。在用`mvn clean install`命令构建整个项目后，你应该使用`zone1`或`zone2`活动配置启动 Spring Boot 应用程序，例如，`java -jar --spring.profiles.active=zone1 target/order-service-1.0-SNAPSHOT.jar`。您可以在节点部分查看带有区域标签的注册实例的完整列表。Consul 仪表板的观点在以下屏幕快照中可见：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/a1a34b42-27d3-46d1-814b-fc20ffd77a3e.png)

我们架构的最后一部分是一个基于 Zuul 的 API 网关。我们还在不同的区域运行两个`gateway-service`实例。我们想省略在 Consul 中的注册，并只允许获取配置，该配置由 Ribbon 客户端在执行负载均衡时使用。以下是`gateway-service`的`bootstrap.yml`文件的一个片段。通过设置属性`spring.cloud.

consul.discovery.register`和`spring.cloud.consul.discovery.

registerHealthCheck`设置为`false`：

```java
---
spring:
 profiles: zone1
 cloud:
 consul:
 discovery:
 instanceZone: zone1
 register: false
 registerHealthCheck: false
server: 
 port: ${PORT:8080}

---
spring:
 profiles: zone2
 cloud:
 consul:
 discovery:
 instanceZone: zone2
 register: false
 registerHealthCheck: false
server: 
 port: ${PORT:9080}
```

# 客户端设置自定义

可以通过配置文件中的属性自定义 Spring Cloud Consul 客户端。本章前面部分已经介绍了其中一些设置。其他有用设置列在下面的表格中。它们都带有`spring.cloud.consul.discovery`前缀：

| **属性** | **默认值** | **描述** |
| --- | --- | --- |
| `enabled` | `true` | 它设置应用程序是否启用 Consul 发现 |
| `failFast` | `true` | 如果为真，则在服务注册时抛出异常；否则，记录警告 |
| `hostname` | - | 它在 Consul 中注册实例时设置实例的主机名 |
| `preferIpAddress` | `false` | 它强制应用程序在注册时发送其 IP 地址，而不是主机名 |
| `scheme` | `http` | 它设置服务是否通过 HTTP 或 HTTPS 协议可用 |
| `serverListQueryTags` | - | 它允许通过单个标签过滤服务 |
| `serviceName` | - | 它覆盖了服务名称，默认情况下从`spring.application.name`属性中获取 |
| `tags` | - | 它设置在注册服务时使用的标签及其值的列表 |

# 运行在集群模式下

到目前为止，我们总是启动一个独立的 Consul 实例。虽然在开发模式下这是一个合适的解决方案，但在生产环境中是不够的。在那里，我们希望能够有一个可扩展的、生产级别的服务发现基础设施，由一些在集群内部协同工作的节点组成。Consul 提供了基于八卦协议的集群支持，该协议用于成员之间的通信，以及基于 Raft 共识协议的领导选举。我不想深入了解这个过程，但关于 Consul 架构的一些基本知识应该澄清。

我们已经谈论过 Consul 代理，但它到底是什么以及它的作用并没有被解释。代理是 Consul 集群上每个成员上的长运行守护进程。它可以在客户端或服务器模式下运行。所有代理都负责运行检查并保持服务在不同节点上注册并全局同步。

我们在本节中的主要目标是使用 Docker 镜像设置和配置 Consul 集群。首先，我们将启动一个容器，它作为集群的领导者。与独立的 Consul 服务器相比，当前使用的 Docker 命令只有一个区别。我们设置了环境变量`CONSUL_BIND_INTERFACE=eth0`，以将集群代理的网络地址从`127.0.0.1`更改为对其他成员容器可用的地址。我的 Consul 服务器现在在内部地址`172.17.0.2`上运行。要查看您的地址（它应该相同），您可以运行命令`docker logs consul`。容器启动后立即记录了适当的信息：

```java
docker run -d --name consul-1 -p 8500:8500 -e CONSUL_BIND_INTERFACE=eth0 consul
```

了解这个地址非常重要，因为现在我们必须将其作为集群加入参数传递给每个成员容器的启动命令。通过将`0.0.0.0`设置为客户端地址，我们还将其绑定到所有接口。现在，我们可以使用`-p`参数轻松地将客户端代理 API 暴露在容器外：

```java
docker run -d --name consul-2 -p 8501:8500 consul agent -server -client=0.0.0.0 -join=172.17.0.2
docker run -d --name consul-3 -p 8502:8500 consul agent -server -client=0.0.0.0 -join=172.17.0.2
```

在两个容器中运行 Consul 代理后，您可以在领导者的容器上执行以下命令，以查看集群成员的完整列表：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/62ad9459-eb41-4770-8035-f2a23dee1e42.png)

Consul 服务器代理暴露在`8500`端口上，而成员代理在`8501`和`8502`端口上。即使微服务实例将自己注册到一个成员代理上，它对集群中的所有成员都是可见的：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/0003cbac-7ff3-4286-ac65-3c13cf98a2ad.png)

我们可以通过更改配置属性轻松地更改 Spring Boot 应用程序的默认 Consul 代理地址：

```java
spring: 
 application:
  name: customer-service
 cloud:
  consul:
   host: 192.168.99.100
   port: 8501
```

# 分布式配置

使用 Spring Cloud Consul Config 库在类路径中的应用程序在引导阶段从 Consul 键/值存储中获取配置。也就是说，默认存储在`/config`文件夹中。当我们创建一个新的键时，我们必须设置一个文件夹路径。然后，该路径用于识别键并将它分配给应用程序。Spring Cloud Config 尝试根据应用程序名称和活动配置文件解析存储在文件夹中的属性。假设我们在`bootstrap.yml`文件中将`spring.application.name`属性设置为`order-service`，并且将`spring.profiles.active`运行参数设置为`zone1`，它将按照以下顺序查找属性源：`config/order-service,zone1/`, `config/order-service/`, `config/application,zone1/`, `config/application/`。所有前缀为`config/application`的文件夹都是为所有没有服务特定属性源的应用程序提供的默认配置。

# 管理 Consul 中的属性

将一个键添加到 Consul 中最舒适的方式是通过它的网页控制台。另一种方式是使用`/kv` HTTP 端点，这在章节的开始部分已经描述过了。当使用网页控制台时，你必须去到 KEY/VALUE 部分。然后，你可以查看所有当前存在的键，也可以通过提供其完整路径和值（任何格式）来创建一个新的。这个功能在下面的截图中可视化：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/f0b420c2-a7db-4403-9a36-107311c5d2ac.png)

每一个键可能被更新或删除：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/85ffa69a-6da9-49aa-b8fc-ef419d3a28ce.png)

为了访问使用存储在 Consul 中的属性源的示例应用程序，你应该切换到与之前示例相同的仓库中的配置分支。我为每个微服务创建了键`server.port`和`spring.cloud.consul.discovery.instanceZone`，而不是在`application.yml`或`bootstrap.yml`文件中定义它。

# 客户端自定义

Consul Config 客户端可以通过以下属性进行自定义，这些属性前面带有`spring.cloud.consul.config`前缀：

+   `enabled`：通过将此属性设置为`false`，您可以禁用 Consul Config。如果您包含`spring-cloud-starter-consul-all`，它启用了发现和分布式配置，这个属性很有用。

+   `fail-fast`：这设置了在配置查找期间是否抛出异常或连接失败时是否记录警告。设置为`true`可以让应用程序正常启动。

+   `prefix`：这设置了所有配置值的基础文件夹。默认是`/config`。

+   `defaultContext`：这设置了所有没有特定配置的应用程序使用的文件夹名称。默认是`/application`。例如，如果你重写它为`app`，属性应该在`/config/apps`文件夹中搜索。

+   `profileSeparator`：默认情况下，一个配置文件使用逗号和一个应用名称进行分隔。这个属性允许你覆盖那个分隔符的值。例如，如果你设置它为`::`，你应该创建文件夹`/config/order-service::zone1/`。这是一个例子：

```java
spring:
 cloud:
  consul:
   config:
    enabled: true
    prefix: props
    defaultContext: app
    profileSeparator: '::'
```

有时，您可能希望将创建在 YAML 或 Properties 格式的属性块，与单独的键/值对相对比。在这种情况下，你应该将`spring.cloud.consul.config.format`属性设置为`YAML`或`PROPERTIES`。然后，应用程序会在带有数据键的文件夹中查找配置属性，例如，`config/order-service,zone1/data`，`config/order-service/data`，`config/application,zone1/data`或`config/application/data`。默认数据键可以通过`spring.cloud.consul.config.data-key`属性进行更改。

# 观察配置更改

在前一部分讨论的示例中，应用程序启动时加载配置。如果你希望重新加载配置，你应该向`/refresh`端点发送 HTTP `POST`请求。为了查看我们应用程序的刷新如何工作，我们修改了负责创建一些测试数据的应用程序代码片段。到目前为止，它作为带有硬编码内存对象的存储库（`@Bean`）提供。请看以下代码：

```java
@Bean
CustomerRepository repository() {
    CustomerRepository repository = new CustomerRepository();
    repository.add(new Customer("John Scott", CustomerType.NEW));
    repository.add(new Customer("Adam Smith", CustomerType.REGULAR));
    repository.add(new Customer("Jacob Ryan", CustomerType.VIP));
    return repository;
}
```

我们的目标是将此处可见的代码移动到使用 Consul 键/值功能的配置存储中。为了实现这一点，我们必须为每个对象创建三个键，键名分别为`id`、`name`和`type`。配置从带有`repository`前缀的属性加载：

```java
@RefreshScope
@Repository
@ConfigurationProperties(prefix = "repository")
public class CustomerRepository {

    private List<Customer> customers = new ArrayList<>();

    public List<Customer> getCustomers() {
        return customers;
    }

    public void setCustomers(List<Customer> customers) {
        this.customers = customers;
    }
    // ...
}
```

下一步是在 Consul web 仪表板上为每个服务定义适当的键。以下是为包含`Customer`对象的列表的示例配置。列表在应用程序启动时初始化：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/bffd5327-fdb1-4ea1-9e4f-8dd99169c30a.png)

你可以更改每个属性的值。由于 Consul 具有监视键前缀的能力，更新事件会自动发送到应用程序。如果有新的配置数据，则会发布刷新事件到队列中。所有队列和交换机都在应用程序启动时由 Spring Cloud Bus 创建，该组件作为`spring-cloud-starter-consul-all`项目的依赖项包含在内。如果你的应用程序接收到此类事件，它将在日志中打印以下信息：

```java
Refresh keys changed: [repository.customers[1].name]
```

# 使用 Spring Cloud Zookeeper

Spring Cloud 支持各种作为微服务架构一部分的产品。在阅读本章时，你可以了解到 Consul 作为发现工具与 Eureka 进行了比较，与 Spring Cloud Config 作为分布式配置工具进行了比较。Zookeeper 是另一个可能作为前面列出的选择之一替代的解决方案。与 Consul 一样，它可用于服务发现和分布式配置。为了在项目中启用 Spring Cloud Zookeeper，你应该包含用于服务发现功能的`spring-cloud-starter-zookeeper-discovery`启动器，或用于配置服务器功能的`spring-cloud-starter-zookeeper-config`。或者，您可以声明一个`spring-cloud-starter-zookeeper-all`依赖项，为应用程序激活所有功能。不要忘记包含`spring-boot-starter-web`，它仍然需要提供 web 功能：

```java
<dependency>
    <groupId>org.springframework.cloud</groupId>
    <artifactId>spring-cloud-starter-zookeeper-all</artifactId>
</dependency>
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-web</artifactId>
</dependency>
```

Zookeeper 连接设置是自动配置的。默认情况下，客户端尝试连接到`localhost:2181`。为了覆盖它，你应该定义`spring.cloud.zookeeper.connect-string`属性，并使用当前服务器网络地址：

```java
spring:
 cloud:
  zookeeper:
   connect-string: 192.168.99.100:2181
```

正如 Spring Cloud Consul 一样，Zookeeper 支持 Spring Cloud Netflix 提供的所有最受欢迎的通信库，如 Feign、Ribbon、Zuul 或 Hystrix。在我们开始样本实现之前，首先必须启动 Zookeeper 实例。

# 运行 Zookeeper

正如你可能会猜到的，我将使用 Docker 镜像在本地机器上启动 Zookeeper。下面的命令启动了 Zookeeper 服务器实例。由于它<q>快速失败</q>，最好的方法总是重新启动它：

```java
docker run -d --name zookeeper --restart always -p 2181:2181 zookeeper
```

与本领域之前讨论的解决方案，如 Consul 或 Eureka 相比，Zookeeper 没有提供简单的 RESTful API 或一个 web 管理控制台，使我们能够轻松管理它。它有一个官方的 API 绑定用于 Java 和 C。我们还可以使用其命令行界面，这可以在 Docker 容器内轻松启动。这里显示的命令使用命令行客户端启动容器，并将其连接到 Zookeeper 服务器容器：

```java
docker run -it --rm --link zookeeper:zookeeper zookeeper zkCli.sh -server zookeeper
```

Zookeeper CLI 允许执行一些有用的操作，如下所示：

+   **创建 znode**：要使用给定路径创建 znode，请使用命令`create /path /data`。

+   **获取数据**：命令`get /path`返回与 znode 相关的数据和元数据。

+   **监控 znode 的变化**：如果 znode 或 znode 的子节点数据发生变化，这将显示一个通知。监控只能与`get`命令一起设置。

+   **设置数据**：要设置 znode 数据，请使用命令`set /path /data`。

+   **创建 znode 的子节点**：这个命令与创建单个 znode 的命令类似。唯一的区别是子 znode 的路径包括了父路径`create /parent/path/subnode/path /data`。

+   **列出 znode 的子节点**：这可以通过`ls /path`命令来显示。

+   **检查状态**：这可以通过命令`stat /path`来查看。状态描述了指定 znode 的元数据，如时间戳或版本号。

+   **删除/删除 znode**：命令`rmr /path`删除了所有子节点的 znode。

在那个片段中，术语*znode*第一次出现。在存储数据时，Zookeeper 使用树状结构，每个节点称为**znode**。这些 znode 的名称基于从根节点开始的路径。每个节点都有一个名字。可以使用从根节点开始的绝对路径来访问它。这个概念与 Consul 文件夹类似，并已用于在键/值存储中创建键。

# 服务发现

最受欢迎的 Apache Zookeeper 的 Java 客户端库是 Apache Curator。它提供了一个 API 框架和工具，使使用 Apache Zookeeper 变得更容易。它还包括常见用例和扩展的食谱，例如服务发现或 Java 8 异步 DSL。Spring Cloud Zookeeper 利用了其中一个扩展来实现服务发现。Curator 库在 Spring Cloud Zookeeper 中的使用对开发者完全透明，因此我在这里不想再详细描述。

# 客户端实现

客户端的使用与其他与服务发现相关的 Spring Cloud 项目相同。应用程序的主类或`@Configuration`类应使用`@EnableDiscoveryClient`注解。默认的服务名称、实例 ID 和端口分别从`spring.application.name`、Spring 上下文 ID 和`server.port`获取。

示例应用程序的源代码可以在 GitHub 仓库中找到，网址为[`github.com/piomin/sample-spring-cloud-zookeeper.git`](https://github.com/piomin/sample-spring-cloud-zookeeper.git)。本质上，它与为 Consul 引入的示例系统没有区别，除了依赖 Spring Cloud Zookeeper 发现。它仍然由四个微服务组成，它们相互通信。现在，在克隆仓库后，使用`mvn clean install`命令来构建它。然后，使用`java -jar`命令运行每个服务的活动配置文件名称，例如，`java -jar --spring.profiles.active=zone1 order-service/target/order-service-1.0-SNAPSHOT.jar`。

您可以通过使用 CLI 命令`ls`和`get`来查看已注册服务和实例的列表。Spring Cloud Zookeeper 默认将在`/services`根目录下注册所有实例。这可以通过设置`spring.cloud.zookeeper.discovery.root`属性来更改。您可以通过使用带有命令行客户端的 Docker 容器来查看当前注册的服务列表：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/fdbd83d4-a14c-43f6-8302-5a761da38a9d.png)

# Zookeeper 依赖项

Spring Cloud Zookeeper 具有一项额外的功能，称为**Zookeeper 依赖项**。依赖项是指在 Zookeeper 中注册的其他应用程序，它们通过 Feign 客户端或 Spring `RestTemplate`进行调用。这些依赖项可以作为应用程序的属性提供。在包含`spring-cloud-starter-zookeeper-discovery`启动器到项目后，通过自动配置启用此功能。通过将`spring.cloud.zookeeper.dependency.enabled`属性设置为`false`可以禁用它。

Zookeeper 依赖机制的配置由`spring.cloud.zookeeper.dependencies.*`属性提供。以下是`order-service`中的`bootstrap.yml`文件的一个片段。这个服务与所有其他可用服务集成：

```java
spring: 
 application:
  name: order-service
 cloud:
  zookeeper:
   connect-string: 192.168.99.100:2181
  dependency:
   resttemplate:
    enabled: false
  dependencies:
   account:
    path: account-service
    loadBalancerType: ROUND_ROBIN
    required: true
   customer:
    path: customer-service
    loadBalancerType: ROUND_ROBIN
    required: true
   product:
    path: product-service
    loadBalancerType: ROUND_ROBIN
    required: true
```

让我们仔细看看前面的配置。每个调用服务的主属性是别名，然后可以被 Feign 客户端或`@LoadBalanced RestTemplate`用作服务名称：

```java
@FeignClient(name = "customer")
public interface CustomerClient {

    @GetMapping("/withAccounts/{customerId}")
    Customer findByIdWithAccounts(@PathVariable("customerId") Long customerId); 

}
```

配置中的下一个非常重要的字段是路径。它设置了在 Zookeeper 中注册依赖项的路径。所以，如果该属性的值为`customer-service`，这意味着 Spring Cloud Zookeeper 尝试在路径`/services/customer-service`下查找适当的服务 znode。还有一些其他属性可以自定义客户端的行为。其中之一是`loadBalancerType`，用于应用负载均衡策略。我们可以选择三种可用的策略——`ROUND_ROBIN`、`RANDOM`和`STICKY`。我还为每个服务映射设置了`required`属性为`true`。现在，如果您的应用程序在启动时无法检测到所需的依赖项，它将无法启动。Spring Cloud Zookeeper 依赖项还允许管理 API 版本（`contentTypeTemplate`和`versions`属性）和请求头（`headers`属性）。

默认情况下，Spring Cloud Zookeeper 为与依赖项的通信启用`RestTemplate`。在可用的分支依赖中([`github.com/piomin/sample-spring-cloud-zookeeper/tree/dependencies`](https://github.com/piomin/sample-spring-cloud-zookeeper/tree/dependencies))，我们使用 Feign 客户端而不是`@LoadBalanced RestTemplate`。为了禁用该功能，我们应该将属性`spring.cloud.zookeeper.dependency.resttemplate.enabled`设置为`false`。

# 分布式配置

配置管理使用 Zookeeper 与 Spring Cloud Consul Config 中描述的配置非常相似。默认情况下，所有的属性源都存储在`/config`文件夹中（在 Zookeeper 的术语中叫做 znode）。让我再强调一次。假设我们在`bootstrap.yml`文件中将`spring.application.name`属性设置为`order-service`，并且将`spring.profiles.active`运行参数设置为`zone1`，它将按照以下顺序尝试定位属性源：`config/order-service,zone1/`、`config/order-service/`、`config/application,zone1/`、`config/application/`。存储在以`config/application`为前缀的命名空间中的文件夹中的属性，可供所有使用 Zookeeper 进行分布式配置的应用程序使用。

要访问示例应用程序，你需要切换到[`github.com/piomin/sample-spring-cloud-zookeeper.git`](https://github.com/piomin/sample-spring-cloud-zookeeper.git)仓库的分支配置。这里可见的本地`application.yml`或`bootstrap.yml`文件中定义的配置，现在已移动到 Zookeeper 中：

```java
---
spring:
 profiles: zone1
server: 
 port: ${PORT:8090}

---
spring:
 profiles: zone2
server: 
 port: ${PORT:9090}
```

必须使用 CLI 创建所需的 znode。以下是创建给定路径的 znode 的 Zookeeper 命令列表。我使用了`create /path /data`命令：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/7494c667-24b5-4a33-aef6-fbb27e519e61.png)

# 摘要

在本章中，我引导你了解了两个 Spring Cloud 项目——Consul 和 Zookeeper 的主要功能。我不仅关注 Spring Cloud 的功能，还向你讲解了如何启动、配置和维护其工具的实例。我们甚至讨论了更高级的场景，比如使用 Docker 设置由多个成员组成的集群。在那里，你有机会看到 Docker 作为开发工具真正的力量。它允许我们仅通过三个简单命令初始化一个由三个成员组成的集群，而无需任何其他配置。

当使用 Spring Cloud 时，Consul 似乎是 Eureka 的一个重要的发现服务器替代品。对于 Zookeeper 我无法这么说。正如你可能已经注意到的，我写了很多关于 Consul 而不是 Zookeeper 的内容。此外，Spring Cloud 将 Zookeeper 视为第二选择。它仍然没有实现区域机制或监视配置变化的能力，这与 Spring Cloud Consul 不同。你不应该对此感到惊讶。Consul 是为满足最新架构的需求而设计的现代解决方案，如基于微服务的系统，而 Zookeeper 是一个作为分布式环境中运行的应用程序的服务发现工具的关键/值存储。然而，如果你在你的系统中使用 Apache Foundation 堆栈，考虑这个工具是有价值的。借助这一点，你可以利用 Zookeeper 与其他 Apache 组件（如 Camel 或 Karaf）的集成，并轻松发现使用 Spring Cloud 框架创建的服务。

总之，在阅读了本章之后，你应该能够在你基于微服务的架构中使用 Spring Cloud Consul 和 Spring Cloud Zookeeper 的主要功能。你还应该知道 Spring Cloud 中所有可用发现和配置工具的主要优点和缺点，以便为你的系统选择最合适的解决方案。


# 第十一章：消息驱动的微服务

我们已经讨论了围绕由 Spring Cloud 提供的微服务架构的许多特性。然而，我们一直都在考虑基于同步、RESTful 的跨服务通信。正如您可能从第一章，《微服务简介》中记忆的那样，还有一些其他流行的通信方式，如发布/订阅或异步、事件驱动的点对点消息传递。在本章中，我想介绍一种与前几章中介绍的微服务不同的方法。我们将更详细地讨论如何使用 Spring Cloud Stream 来构建消息驱动的微服务。

本章我们将覆盖的主题包括：

+   与 Spring Cloud Stream 相关的术语和概念

+   使用 RabbitMQ 和 Apache Kafka 消息代理作为绑定器

+   Spring Cloud Stream 编程模型

+   绑定、生产者和消费者的高级配置

+   实现缩放、分组和分区机制

+   支持多个绑定器

# 学习 Spring Cloud Stream

Spring Cloud Stream 是建立在 Spring Boot 之上的。它允许我们创建独立的、生产级别的 Spring 应用程序，并使用 Spring Integration 来实现与消息代理的通信。使用 Spring Cloud Stream 创建的每个应用程序通过输入和输出通道与其他微服务集成。这些通道通过特定于中间件的绑定器实现与外部消息代理的连接。内置的绑定器实现有两个——Kafka 和 Rabbit MQ。

Spring Integration 将 Spring 编程模型扩展以支持著名的**企业集成模式**（**EIP**）。EIP 定义了一系列通常用于分布式系统中的编排的组件。您可能已经听说过诸如消息通道、路由器、聚合器或端点之类的模式。Spring Integration 框架的主要目标是提供一个简单的模型，用于构建基于 EIP 的 Spring 应用程序。如果您对 EIP 的更多细节感兴趣，请访问[`www.enterpriseintegrationpatterns.com/patterns/messaging/toc.html`](http://www.enterpriseintegrationpatterns.com/patterns/messaging/toc.html)网站。

# 构建消息系统

我认为介绍 Spring Cloud Stream 的主要特性的最适合方式是通过一个基于微服务的示例系统。我们将轻微修改一下在前几章中讨论过的系统架构。让我回顾一下那个架构。我们的系统负责处理订单。它由四个独立的微服务组成。`order-service` 微服务首先与 `product-service` 通信，以收集所选产品的详细信息，然后与 `customer-service` 通信，以获取有关客户和他的账户的信息。现在，发送到 `order-service` 的订单将被异步处理。仍然有一个暴露的 RESTful HTTP API 端点，用于客户端提交新订单，但它们不被应用程序处理。它只保存新订单，将其发送到消息代理，然后向客户端回应订单已被批准处理。目前讨论的示例的主要目标是展示点对点通信，所以消息只会被一个应用程序，`account-service` 接收。以下是说明示例系统架构的图表：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/6d470d32-4e38-49ef-a0b8-56cc3408ded5.png)

在接收到新消息后，`account-service` 调用 `product-service` 暴露的方法，以找出其价格。它从账户中提取资金，然后将当前订单状态的响应发送回 `order-service`。该消息也是通过消息代理发送的。`order-service` 微服务接收到消息并更新订单状态。如果外部客户想要检查当前订单状态，它可以通过调用暴露 `find` 方法的端点来提供订单详情。示例应用程序的源代码可以在 GitHub 上找到（[`github.com/piomin/sample-spring-cloud-messaging.git`](https://github.com/piomin/sample-spring-cloud-messaging.git)）。

# 启用 Spring Cloud Stream

将 Spring Cloud Stream 包含在项目中的推荐方法是使用依赖管理系统。Spring Cloud Stream 在整个 Spring Cloud 框架方面有独立的发布列车管理。然而，如果我们已经在 `dependencyManagement` 部分声明了 `Edgware.RELEASE` 版本的 `spring-cloud-dependencies`，我们不必在 `pom.xml` 中声明其他内容。如果您更喜欢只使用 Spring Cloud Stream 项目，您应该定义以下部分：

```java
<dependencyManagement>
 <dependencies>
  <dependency>
   <groupId>org.springframework.cloud</groupId>
   <artifactId>spring-cloud-stream-dependencies</artifactId>
   <version>Ditmars.SR2</version>
   <type>pom</type>
   <scope>import</scope>
  </dependency>
 </dependencies>
</dependencyManagement>
```

下一步是向项目依赖中添加 `spring-cloud-stream`。我还建议您至少包含 `spring-cloud-sleuth` 库，以提供与通过 Zuul 网关传入 `order-service` 的源请求相同的 `traceId` 发送消息：

```java
<dependency>
 <groupId>org.springframework.cloud</groupId>
 <artifactId>spring-cloud-stream</artifactId>
</dependency>
<dependency>
 <groupId>org.springframework.cloud</groupId>
 <artifactId>spring-cloud-sleuth</artifactId>
</dependency>
```

为了使应用程序能够连接到消息代理，请用`@EnableBinding`注解标记主类。`@EnableBinding`注解需要一个或多个接口作为参数。您可以选择 Spring Cloud Stream 提供的三个接口之一：

+   `Sink`：这用于标记接收来自入站通道消息的服务。

+   `Source`：用于向出站通道发送消息。

+   `Processor`：如果您需要入站通道和出站通道，可以使用它，因为它扩展了`Source`和`Sink`接口。因为`order-service`发送消息，以及接收消息，所以它的主类被用`@EnableBinding(Processor.class)`注解标记。

这是`order-service`的`main`类，它启用了 Spring Cloud Stream 绑定：

```java
@SpringBootApplication
@EnableDiscoveryClient
@EnableBinding(Processor.class)
public class OrderApplication {

    public static void main(String[] args) {
        new SpringApplicationBuilder(OrderApplication.class).web(true).run(args);
    }

}
```

# 声明和绑定通道

得益于 Spring Integration 的使用，应用程序与项目中包含的消息代理实现是独立的。Spring Cloud Stream 会自动检测并使用类路径中找到的绑定器。这意味着我们可以选择不同类型的中间件，并用相同的代码使用它。所有中间件特定的设置都可以通过 Spring Boot 支持的格式（如应用程序参数、环境变量，或仅仅是`application.yml`文件）的外部配置属性来覆盖。正如我之前提到的，Spring Cloud Stream 为 Kafka 和 Rabbit MQ 提供了绑定器实现。要包括对 Kafka 的支持，您需要将以下依赖项添加到项目中：

```java
<dependency>
 <groupId>org.springframework.cloud</groupId>
 <artifactId>spring-cloud-starter-stream-kafka</artifactId>
</dependency>
```

个人而言，我更喜欢 RabbitMQ，但在这章节，我们将为 RabbitMQ 和 Kafka 都创建一个示例。因为我们已经讨论过 RabbitMQ 的功能，我将从基于 RabbitMQ 的示例开始：

```java
<dependency>
 <groupId>org.springframework.cloud</groupId>
 <artifactId>spring-cloud-starter-stream-rabbit</artifactId>
</dependency>
```

在启用 Spring Cloud Stream 并包括绑定器实现之后，我们可以创建发送者和监听者。让我们从负责将新订单消息发送到代理的生产者开始。这通过`order-service`中的`OrderSender`实现，它使用`Output`bean 来发送消息：

```java
@Service
public class OrderSender {

    @Autowired
    private Source source;

    public boolean send(Order order) {
        return this.source.output().send(MessageBuilder.withPayload(order).build());
    }

}
```

这个 bean 被控制器调用，控制器暴露了一个允许提交新订单的 HTTP 方法：

```java
@RestController
public class OrderController {

    private static final Logger LOGGER = LoggerFactory.getLogger(OrderController.class); 
    private ObjectMapper mapper = new ObjectMapper();

    @Autowired
    OrderRepository repository;
    @Autowired
    OrderSender sender;

    @PostMapping
    public Order process(@RequestBody Order order) throws JsonProcessingException {
        Order o = repository.add(order);
        LOGGER.info("Order saved: {}", mapper.writeValueAsString(order));
        boolean isSent = sender.send(o);
        LOGGER.info("Order sent: {}",     mapper.writeValueAsString(Collections.singletonMap("isSent", isSent)));
        return o;
    }

}
```

包含关于订单信息的消息已经发送到消息代理。现在，它应该被`account-service`接收。使这成为可能，我们必须声明接收者，它正在监听来自消息代理上创建的队列的消息。为了接收带有订单数据的消息，我们只需用`@StreamListener`注解来标记接受`Order`对象作为参数的方法：

```java
@SpringBootApplication
@EnableDiscoveryClient
@EnableBinding(Processor.class)
public class AccountApplication { 

    @Autowired
    AccountService service;

    public static void main(String[] args) {
        new SpringApplicationBuilder(AccountApplication.class).web(true).run(args);
    }

    @Bean
    @StreamListener(Processor.INPUT)
    public void receiveOrder(Order order) throws JsonProcessingException {
        service.process(order);
    }

}
```

现在您可以启动示例应用程序了。但是，还有一个重要细节尚未提到。这两个应用程序都尝试连接到运行在 localhost 上的 RabbitMQ，并且它们都将相同的交换机作为输入或输出。这是一个问题，因为`order-service`将消息发送到输出交换机，而`account-service`监听其输入交换机传入的消息。这些是不同的交换机，但首先事情要一件一件来做。让我们先从运行一个消息代理开始。

# 使用 RabbitMQ 代理自定义连接

在之前的章节中，我们已经使用 RabbitMQ 的 Docker 镜像启动了 RabbitMQ 代理，因此值得提醒这个命令。它启动了一个带有 RabbitMQ 的独立 Docker 容器，端口为`5672`，以及其 UI 网页控制台，端口为`15672`：

```java
docker run -d --name rabbit -p 15672:15672 -p 5672:5672 rabbitmq:management
```

默认的 RabbitMQ 地址应该在`application.yml`文件中使用`spring.rabbit.*`属性进行覆盖：

```java
spring:
 rabbitmq:
  host: 192.168.99.100
  port: 5672
```

默认情况下，Spring Cloud Stream 为通信创建了一个主题交换机。这种类型的交换机更适合发布/订阅交互模型。我们可以使用`exchangeType`属性来覆盖它，如`application.yml`的片段所示：

```java
spring:
 cloud:
  stream:
   rabbit:
    bindings:
     output:
      producer:
       exchangeType: direct
     input:
      consumer:
       exchangeType: direct
```

相同的配置设置应该提供给`order-service`和`account-service`。您不需要手动创建任何交换机。如果不存在，应用程序在启动时会自动创建。否则，应用程序只是绑定到该交换机。默认情况下，它为`@Input`通道创建名为 input 的交换机，为`@Output`通道创建名为 output 的交换机。这些名称可以通过`spring.cloud.stream.bindings.output.destination`和`spring.cloud.stream.bindings.input.destination`属性进行覆盖，其中 input 和 output 是通道的名称。这个配置选项不仅仅是 Spring Cloud Stream 功能的一个很好的补充，而且是用于跨服务通信中关联输入和输出目的地的一个关键设置。解释为什么会出现这种情况非常简单。在我们的示例中，`order-service`是消息源应用程序，因此它将消息发送到输出通道。另一方面，`account-service`监听输入通道传入的消息。如果`order-service`输出通道和`account-service`输入通道不指向代理上的相同目的地，它们之间的通信将失败。总之，我决定使用名为`orders-out`和`orders-in`的目标，并为`order-service`提供了以下配置：

```java
spring:
 cloud: 
  stream:
   bindings:
    output:
     destination: orders-out
    input:
     destination: orders-in
```

对于`account-service`，类似的配置设置是反向的：

```java
spring:
 cloud: 
  stream:
   bindings:
    output:
     destination: orders-in
    input:
     destination: orders-out
```

两个应用程序启动后，您可以通过访问 `http://192.168.99.100:15672`（`quest`/`guest`）的 RabbitMQ 代理的 Web 管理控制台，轻松查看声明的交换机列表。以下是为测试目的创建的两个目的地：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/972692ab-4ae9-4f45-ab16-7987f69b003a.png)

默认情况下，Spring Cloud Stream 提供了一个输入消息通道和一个输出消息通道。我们可以想象一种情况，我们的系统需要为每种类型的消息通道设置多个目的地。让我们回到示例系统架构中一会儿，考虑每个订单都由两个其他微服务异步处理的情况。到目前为止，只有 `account-service` 在监听来自 `order-service` 的传入事件。在当前示例中，`product-service` 将是传入订单的接收者。在该场景中，其主要目标是管理可用产品的数量，并根据订单详情减少产品数量。它需要我们在 `order-service` 内部定义两个输入和输出消息通道，因为基于直接 RabbitMQ 交换的点对点通信，每个消息可能由一个消费者处理。

在这种情况下，我们应该声明两个带有 `@Input` 和 `@Output` 方法的接口。每个方法都必须返回一个 `channel` 对象。Spring Cloud Stream 为出站通信提供了一个可绑定消息组件——`MessageChannel`，以及其扩展，`SubscribableChannel`，用于入站通信。以下是与 `product-service` 交互的接口定义。已经为与 `account-service` 消息通信创建了类似接口：

```java
public interface ProductOrder {

    @Input
    SubscribableChannel productOrdersIn();

    @Output
    MessageChannel productOrdersOut();
}
```

下一步是通过对主类使用 `@EnableBinding(value={AccountOrder.class, ProductOrder.class})` 注解来激活应用程序中声明的组件。现在，您可以使用它们的名称在配置属性中引用这些通道，例如，`spring.cloud.stream.bindings.productOrdersOut.destination=product-orders-in`。每个通道名称可以通过在使用 `@Input` 和 `@Output` 注解时指定通道名称来自定义，如下例所示：

```java
public interface ProductOrder {

    @Input("productOrdersIn")
    SubscribableChannel ordersIn();

    @Output("productOrdersOut")
    MessageChannel ordersOut();
}
```

基于自定义接口的声明，Spring Cloud Stream 将生成实现该接口的 bean。但是，它仍然必须在负责发送消息的 bean 中被访问。与之前的示例相比，直接注入绑定通道会更方便。以下是当前产品订单发送者的 bean 实现。还有一个类似的实现，用于向 `account-service` 发送消息：

```java
@Service
public class ProductOrderSender {

    @Autowired
    private MessageChannel output;

    @Autowired
    public SendingBean(@Qualifier("productOrdersOut") MessageChannel output) {
        this.output = output;
    }

    public boolean send(Order order) {
        return this.output.send(MessageBuilder.withPayload(order).build());
    }

}
```

每个消息通道的自定义接口也应提供给目标服务。监听器应绑定到消息代理上的正确消息通道和目的地：

```java
@StreamListener(ProductOrder.INPUT)
public void receiveOrder(Order order) throws JsonProcessingException {
    service.process(order);
}
```

# 与其他 Spring Cloud 项目的集成

你可能已经注意到，示例系统混合了不同的服务间通信风格。有些微服务使用典型的 RESTful HTTP API，而其他的则使用消息代理。也没有反对在单个应用程序中混合不同的通信风格。例如，你可以将`spring-cloud-starter-feign`添加到带有 Spring Cloud Stream 的项目中，并用`@EnableFeignClients`注解启用它。在我们的示例系统中，这两种不同的通信风格结合了`account-service`，它通过消息代理与`order-service`集成，并通过 REST API 与`product-service`通信。以下是`account-service`模块中`product-service`的 Feign 客户端实现：

```java
@FeignClient(name = "product-service")
public interface ProductClient {

    @PostMapping("/ids")
    List<Product> findByIds(@RequestBody List<Long> ids); 
}
```

还有其他好消息。得益于 Spring Cloud Sleuth，通过网关进入系统的一个单一请求期间交换的所有消息都有相同的`traceId`。无论是同步的 REST 通信，还是异步的消息传递，你都可以很容易地使用标准日志文件，或像 Elastic Stack 这样的日志聚合工具，在微服务之间跟踪和关联日志。

我认为现在是一个运行和测试我们的示例系统的好时机。首先，我们必须使用`mvn clean install`命令构建整个项目。要访问包含两个微服务，分别在两个不同的交换机上监听消息的代码示例，你应该切换到`advanced`分支([`github.com/piomin/sample-spring-cloud-messaging/tree/advanced`](https://github.com/piomin/sample-spring-cloud-messaging/tree/advanced)). 你应该启动那里所有的应用程序——网关、发现以及三个微服务(`account-service`, `order-service`, `product-service`)。目前讨论的案例假设我们已经使用 Docker 容器启动了 RabbitMQ、Logstash、Elasticsearch 和 Kibana。关于如何使用 Docker 镜像在本地运行 Elastic Stack 的详细说明，请参考第九章，*分布式日志和跟踪*。下面的图表详细显示了系统的架构：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/1a3ef3e9-bd8e-45fb-8b75-b8050e1e4560.png)

在运行所有必要的应用程序和工具后，我们可以进行测试。以下是可以通过 API 网关发送到`order-service`的示例请求：

```java
curl -H "Content-Type: application/json" -X POST -d '{"customerId":1,"productIds":[1,3,4],"status":"NEW"}' http://localhost:8080/api/order
```

当我第一次运行测试时，按照前几节的描述配置应用程序，它不起作用。我可以理解，你们中的一些人可能会有些困惑，因为通常它是用默认设置进行测试的。为了使其正常运行，我还需要在`application.yml`中添加以下属性：`spring.cloud.stream.rabbit.bindings.output.producer.routingKeyExpression: '"#"'`. 它将默认生产者的路由键设置为自动在应用程序启动期间创建的交换机路由键，以符合输出交换定义。在下面的屏幕截图中，你可以看到输出交换定义之一：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/d568e23a-9c65-4fb4-beb0-483c8755debb.png)

在前面描述的修改之后，测试应该成功完成。微服务打印的日志通过 `traceId` 相互关联。我在 `logback-spring.xml` 中稍微修改了默认的 Sleuth 日志格式，现在它是这样配置的——`%d{HH:mm:ss.SSS} %-5level [%X{X-B3-TraceId:-},%X{X-B3-SpanId:-}] %msg%n`。在发送 `order-service` 测试请求后，记录以下信息：

```java
12:34:48.696 INFO [68038cdd653f7b0b,68038cdd653f7b0b] Order saved: {"id":1,"status":"NEW","price":0,"customerId":1,"accountId":null,"productIds":[1,3,4]}
12:34:49.821 INFO [68038cdd653f7b0b,68038cdd653f7b0b] Order sent: {"isSent":true}
```

正如您所看到的，`account-service` 也使用相同的日志格式，并打印出与 `order-service` 相同的 `traceId`：

```java
12:34:50.079 INFO [68038cdd653f7b0b,23432d962ec92f7a] Order processed: {"id":1,"status":"NEW","price":0,"customerId":1,"accountId":null,"productIds":[1,3,4]}
12:34:50.332 INFO [68038cdd653f7b0b,23432d962ec92f7a] Account found: {"id":1,"number":"1234567890","balance":50000,"customerId":1}
12:34:52.344 INFO [68038cdd653f7b0b,23432d962ec92f7a] Products found: [{"id":1,"name":"Test1","price":1000},{"id":3,"name":"Test3","price":2000},{"id":4,"name":"Test4","price":3000}]
```

在单个事务期间生成的所有日志可以使用 Elastic Stack 进行聚合。例如，您可以根据 `X-B3-TraceId` 字段过滤条目，例如 `9da1e5c83094390d`：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/a2061976-3bb0-4367-ba21-2b8b76e7e2b4.png)

# 发布/订阅模型

创建 Spring Cloud Stream 项目的主要动机实际上是为了支持持久的发布/订阅模型。在前面的部分，我们已经讨论了微服务之间的点对点通信，这只是额外的特性。然而，无论我们决定使用点对点还是发布/订阅模型，编程模型都是相同的。

在发布/订阅通信中，数据通过共享主题进行广播。它简化了生产者和消费者的复杂性，并且允许在没有更改流程的情况下，轻松地向现有拓扑添加新应用程序。这一点在前面展示的系统示例中可以明显看到，我们决定向由源微服务生成的事件添加第二个应用程序。与初始架构相比，我们不得不为每个目标应用程序定义自定义消息通道。通过队列进行直接通信，消息只能被一个应用程序实例消费，因此，这种解决方案是必要的。发布/订阅模型的使用简化了架构。

# 运行示例系统

对于发布/订阅模型，示例应用程序的开发比点对点通信要简单。我们不需要重写任何默认消息通道以实现与多个接收者的交互。与最初示例相比，我们只需要稍改配置设置。因为 Spring Cloud Stream 默认绑定到主题，所以我们不需要重写输入消息通道的 `exchangeType`。如您在下面的配置片段中所见，我们仍然在使用点对点通信发送对 `order-service` 的响应。如果我们仔细想想，这是有道理的。`order-service` 微服务发送的消息必须被 `account-service` 和 `product-service` 接收，而它们的响应只针对 `order-service`：

```java
spring: 
 application:
  name: product-service
 rabbitmq:
  host: 192.168.99.100
  port: 5672
 cloud: 
  stream:
   bindings:
    output:
     destination: orders-in
    input:
     destination: orders-out
   rabbit:
    bindings:
     output:
      producer:
       exchangeType: direct
       routingKeyExpression: '"#"'
```

产品-服务的主要处理方法的逻辑非常简单。它只需要从接收到的订单中找到所有的`productIds`，为每一个它们改变存储产品的数量，然后将响应发送给`order-service`：

```java
@Autowired
ProductRepository productRepository;
@Autowired
OrderSender orderSender;

public void process(final Order order) throws JsonProcessingException {
 LOGGER.info("Order processed: {}", mapper.writeValueAsString(order));
 for (Long productId : order.getProductIds()) {
     Product product = productRepository.findById(productId);
     if (product.getCount() == 0) {
         order.setStatus(OrderStatus.REJECTED);
         break;
     }
     product.setCount(product.getCount() - 1);
     productRepository.update(product);
     LOGGER.info("Product updated: {}", mapper.writeValueAsString(product));
 }
 if (order.getStatus() != OrderStatus.REJECTED) {
     order.setStatus(OrderStatus.ACCEPTED);
 }
 LOGGER.info("Order response sent: {}", mapper.writeValueAsString(Collections.singletonMap("status", order.getStatus())));
 orderSender.send(order);
}
```

要访问当前示例，您只需切换到`publish_subscribe`分支，可在[`github.com/piomin/sample-spring-cloud-messaging/tree/publish_subscribe`](https://github.com/piomin/sample-spring-cloud-messaging/tree/publish_subscribe)找到。然后，您应该构建父项目并像前一个示例一样运行所有服务。如果您想测试，直到您只有一个运行的`account-service`和`product-service`实例，所有都正常工作。让我们来讨论那个问题。

# 扩展和分组

当谈论基于微服务的架构时，可扩展性总是作为其主要优点之一被提出。通过创建给定应用程序的多个实例来扩展系统的能力非常重要。这样做时，应用程序的不同实例被放置在竞争性消费者关系中，其中只有一个实例预期处理给定消息。对于点对点通信，这不是问题，但在发布-订阅模型中，消息被所有接收者消费，这可能是一个挑战。

# 运行多个实例

对于扩展微服务实例的数量，Spring Cloud Stream 的可用性是围绕其主要概念之一。然而，这个想法背后并没有魔法。使用 Spring Cloud Stream 运行应用程序的多个实例非常容易。其中一个原因是消息代理的原生支持，它被设计用来处理许多消费者和大量流量。

在我们的案例中，所有的消息微服务也都暴露了 RESTful HTTP API，因此首先我们必须为每个实例定制服务器端口。我们之前已经进行了这样的操作。我们还可以考虑设置两个 Spring Cloud Stream 属性，`spring.cloud.stream.instanceCount`和`spring.cloud.stream.instanceIndex`。得益于它们，每个微服务实例都能够接收到关于有多少其他相同应用程序的实例被启动以及它自己的实例索引的信息。只有在您想要启用分区特性时，才需要正确配置这些属性。我稍后会详细讲解这个机制。现在，让我们来看看扩展应用程序的配置设置。`account-service`和`product-service`都为运行应用程序的多个实例定义了两个配置文件。我们在那里定制了服务器的 HTTP 端口、数量和实例索引：

```java
---
spring:
 profiles: instance1
 cloud:
  stream:
   instanceCount: 2
   instanceIndex: 0
server: 
 port: ${PORT:8091}

---
spring:
 profiles: instance2
 cloud:
  stream:
   instanceCount: 2
   instanceIndex: 1
server: 
 port: ${PORT:9091}
```

构建父项目后，您可以运行应用程序的两个实例。每个实例在启动时都分配有属性，例如，`java -jar --spring.profiles.active=instance1 target/account-service-1.0-SNAPSHOT.jar`。如果您向`order-service`端点`POST /`发送测试请求，新订单将被转发到 RabbitMQ 主题交换，以便被连接到该交换的`account-service`和`product-service`接收。问题在于，消息被每个服务的所有实例接收，这并不是我们想要实现的效果。在这里，分组机制提供了帮助。

# 消费者组

我们的目标很明确。我们有多个微服务消费同一个主题的消息。应用程序的不同实例处于竞争性消费者关系中，但只有一个实例应该处理给定的消息。Spring Cloud Stream 引入了消费者组的概念来模拟这种行为。要激活这种行为，我们应该设置一个名为`spring.cloud.stream.bindings.<channelName>.group`的属性，并指定一个组名。设置后，所有订阅给定目的地的组都会接收到发布的数据副本，但每个组中只有一个成员会从那个目的地接收并处理消息。在我们这个案例中，有两个组。首先，为所有`account-service`实例命名 account，其次，为名为 product 的`product-service`。

这是`account-service`当前的绑定配置。`orders-in`目的地是为与`order-service`直接通信而创建的队列，所以只有`orders-out`按服务名称分组。为`product-service`准备了类似的配置：

```java
spring:
 cloud: 
  stream:
   bindings:
    output:
     destination: orders-in
    input:
     destination: orders-out
     group: account
```

第一个区别体现在为 RabbitMQ 交换自动创建的队列的名称上。现在，它不是一个随机生成的名称，如`orders-in.anonymous.qNxjzDq5Qra-yqHLUv50PQ`，而是一个由目的地和组名组成的确定字符串。下面的屏幕截图显示了目前在 RabbitMQ 上存在的所有队列：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/ea66ddab-9c35-40be-9bb6-9b858aa41305.png)

您可以自行重新测试以验证消息是否仅被同一组中的一个应用程序接收。然而，您无法确定哪个实例会处理传入的消息。为了确定这一点，您可以使用分区机制。

# 分区

Spring Cloud Stream 为应用程序的多个实例之间的数据分区提供了支持。在典型用例中，目的地被视为被分成不同的分区。每个生产者，在向多个消费者实例发送消息时，确保数据通过配置的字段来标识，以强制由同一个消费者实例处理。

为了启用您应用程序的分区功能，您必须在生产者配置设置中定义`partitionKeyExpression`或`partitionKeyExtractorClass`属性，以及`partitionCount`。以下是为您的应用程序可能提供的示例配置：

```java
spring.cloud.stream.bindings.output.producer.partitionKeyExpression=payload.customerId
spring.cloud.stream.bindings.output.producer.partitionCount=2
```

分区机制还需要在消费者侧设置`spring.cloud.stream.instanceCount`和`spring.cloud.stream.instanceIndex`属性。它还需要通过将`spring.cloud.stream.bindings.input.consumer.partitioned`属性设置为`true`来显式启用。实例索引负责识别特定实例从哪个唯一分区接收数据。通常，生产者侧的`partitionCount`和消费者侧的`instanceCount`应该相等。

让我来向您介绍由 Spring Cloud Stream 提供的分区机制。首先，它根据`partitionKeyExpression`计算分区键，该表达式针对出站消息或实现`PartitionKeyExtractorStrategy`接口的实现进行评估，该接口定义了提取消息键的算法。一旦计算出消息键，目标分区就被确定为零到`partitionCount - 1`之间的一个值。默认的计算公式是`key.hashCode() % partitionCount`。可以通过设置`partitionSelectorExpression`属性，或通过实现`org.springframework.cloud.stream.binder.PartitionSelectorStrategy`接口来定制它。计算出的键与消费者侧的`instanceIndex`相匹配。

我认为分区的主要概念已经解释清楚了。接下来让我们看一个示例。以下是`product-service`的输入通道当前的配置（与`account-service`设置账户组名相同）：

```java
spring:
 cloud: 
  stream:
   bindings:
    input:
     consumer:
      partitioned: true
     destination: orders-out
     group: product
```

在我们每个从主题交换中消费数据的微服务中，都有两个运行实例。在`order-service`内部也为生产者设置了两个分区。消息键是基于`Order`对象中的`customerId`字段计算得出的。索引为`0`的分区专门用于`customerId`字段中偶数的订单，而索引为`1`的分区则用于奇数。

实际上，RabbitMQ 并没有对分区提供原生支持。有趣的是，Spring Cloud Stream 是如何使用 RabbitMQ 实现分区过程的。下面是一张说明在 RabbitMQ 中创建的交换器绑定的列表的屏幕截图。正如你所看到的，为交换器定义了两个路由键——`orders-out-0`和`orders-out-1`：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/e699f2a7-dbb7-46fd-bb9d-3b1952b257c6.png)

例如，如果你在一个 JSON 消息中发送一个`customerId`等于 1 的订单，例如`{"customerId": 1,"productIds": [4],"status": "NEW"}`，它总是会由`instanceIndex=1`的实例处理。可以通过应用程序日志或使用 RabbitMQ 网页控制台进行检查。下面是一个每个队列的消息率的图表，其中`customerId=1`的消息已经发送了几次：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/683097cd-7210-4c3b-973c-bea138878ac4.png)

# 配置选项

Spring Cloud Stream 的配置设置可以通过 Spring Boot 支持的任何机制进行覆盖，例如应用程序参数、环境变量以及 YAML 或属性文件。它定义了一系列通用的配置选项，可以应用于所有绑定器。然而，还有一些特定于应用程序使用的消息代理的其他属性。

# Spring Cloud Stream 属性

当前组的属性适用于整个 Spring Cloud Stream 应用程序。以下所有属性都带有`spring.cloud.stream`前缀：

| 名称 | 默认值 | 描述 |
| --- | --- | --- |
| `instanceCount` | `1` | 应用程序正在运行的实例数量。有关详细信息，请参阅*扩展和分组*部分。 |
| `instanceIndex` | `0` | 应用程序的实例索引。有关详细信息，请参阅*扩展和分组*部分。 |
| `dynamicDestinations` | - | 可以动态绑定的目的地列表。 |
| `defaultBinder` | - | 如果有多个绑定器定义，则使用的默认绑定器。有关详细信息，请参阅*多个绑定器*部分。 |
| `overrideCloudConnectors` | `false` | 仅当云处于活动状态且 Spring Cloud Connectors 在类路径上时才使用。当设置为`true`时，绑定器完全忽略已绑定的服务，并依赖于`spring.rabbitmq.*`或`spring.kafka.*`的 Spring Boot 属性。 |

# 绑定属性

下一组属性与消息通道有关。在 Spring Cloud 命名法中，这些是绑定属性。它们只能分配给消费者、生产者，或同时分配给两者。以下是这些属性及其默认值和描述：

| 名称 | 默认值 | 描述 |
| --- | --- | --- |
| `destination` | - | 配置为消息通道的消息代理的目标目的地名称。如果通道只被一个消费者使用，它可以被指定为以逗号分隔的目的地列表。 |
| `group` | `null` | 通道的消费者组。有关详细信息，请参阅*扩展和分组*部分。 |
| `contentType` | `null` | 给定通道上交换消息的内容类型。例如，我们可以将其设置为`application/json`。然后，从该应用程序发送的所有对象都会自动转换为 JSON 字符串。 |
| `binder` | `null` | 通道使用的默认绑定器。有关详细信息，请参阅*多个绑定器*部分。 |

# 消费者

下面的属性列表仅适用于输入绑定，并且必须以`spring.cloud.stream.bindings.<channelName>.consumer`为前缀。我将只指示其中最重要的几个：

| **名称** | **默认值** | **描述** |
| --- | --- | --- |
| `concurrency` | `1` | 每个单一输入通道的消费者数量 |
| `partitioned` | `false` | 它使能够从分区生产者接收数据 |
| `headerMode` | `embeddedHeaders` | 如果设置为`raw`，则禁用输入上的头部解析 |
| `maxAttempts` | `3` | 如果消息处理失败，则重试的次数。将此选项设置为`1`将禁用重试机制 |

# 生产者

下面的属性绑定仅适用于输出绑定，并且必须以`spring.cloud.stream.bindings.<channelName>.producer`为前缀。我也会只指示其中最重要的几个：

| **名称** | **默认值** | **描述** |
| --- | --- | --- |
| `requiredGroups` | - | 必须在与消息代理上创建的分隔的组列表 |
| `headerMode` | `embeddedHeaders` | 如果设置为`raw`，则禁用输入上的头部解析 |
| `useNativeEncoding` | `false` | 如果设置为`true`，则出站消息由客户端库直接序列化 |
| `errorChannelEnabled` | `false` | 如果设置为`true`，则将失败消息发送到目的地的错误通道 |

# 高级编程模型

Spring Cloud Stream 编程模型的基础知识已经介绍过了，还包括点对点和发布/订阅通信的示例。让我们讨论一些更高级的示例特性。

# 发送消息

在本章中 presented 的所有示例中，我们通过 RESTful API 发送订单以进行测试。然而，我们很容易通过在应用程序内部定义消息源来创建一些测试数据。下面是一个使用`@Poller`每秒生成一条消息并将其发送到输出通道的 bean：

```java
@Bean
@InboundChannelAdapter(value = Source.OUTPUT, poller = @Poller(fixedDelay = "1000", maxMessagesPerPoll = "1"))
public MessageSource<Order> ordersSource() {
    Random r = new Random();
    return () -> new GenericMessage<>(new Order(OrderStatus.NEW, (long) r.nextInt(5), Collections.singletonList((long) r.nextInt(10))));
}
```

# 转换

正如您可能记得的，`account-service`和`product-service`一直在从`order-service`接收事件，然后发送回响应消息。我们创建了`OrderSender`bean，它负责准备响应载荷并将其发送到输出通道。结果是，如果我们在方法中返回响应对象并将其注解为`@SentTo`，则实现可能更简单：

```java
@StreamListener(Processor.INPUT)
@SendTo(Processor.OUTPUT)
public Order receiveAndSendOrder(Order order) throws JsonProcessingException {
    LOGGER.info("Order received: {}", mapper.writeValueAsString(order));
    return service.process(order);
}
```

我们甚至可以想象这样一个实现，比如下面的实现，而不使用`@StreamListener`。变换器模式负责改变对象的形式。在这种情况下，它修改了两个`order`字段—`status`和`price`：

```java
@EnableBinding(Processor.class)
public class OrderProcessor {

    @Transformer(inputChannel = Processor.INPUT, outputChannel = Processor.OUTPUT)
    public Order process(final Order order) throws JsonProcessingException {
        LOGGER.info("Order processed: {}", mapper.writeValueAsString(order));
        // ...

        products.forEach(p -> order.setPrice(order.getPrice() + p.getPrice()));
        if (order.getPrice() <= account.getBalance()) {
            order.setStatus(OrderStatus.ACCEPTED);
            account.setBalance(account.getBalance() - order.getPrice());
        } else {
            order.setStatus(OrderStatus.REJECTED);
        }
        return order;
    }

}
```

# 条件性地接收消息

假设我们希望对同一消息通道传入的消息进行不同的处理，我们可以使用条件分发。Spring Cloud Stream 支持根据条件将消息分发到输入通道上注册的多个`@StreamListener`方法。这个条件是一个**Spring 表达式语言**（**SpEL**）表达式，定义在`@StreamListener`注解的`condition`属性中：

```java
public boolean send(Order order) {
    Message<Order> orderMessage = MessageBuilder.withPayload(order).build();
    orderMessage.getHeaders().put("processor", "account");
    return this.source.output().send(orderMessage);
}
```

这是一个定义了两个注有`@StreamListener`注解的方法的示例，它们监听同一个主题。其中一个只处理来自`account-service`的消息，而第二个只处理`product-service`的消息。传入的消息根据其头部的`processor`名称进行分发：

```java
@SpringBootApplication
@EnableDiscoveryClient
@EnableBinding(Processor.class)
public class OrderApplication {

    @StreamListener(target = Processor.INPUT, condition = "headers['processor']=='account'")
    public void receiveOrder(Order order) throws JsonProcessingException {
        LOGGER.info("Order received from account: {}", mapper.writeValueAsString(order));
        // ...
    }

    @StreamListener(target = Processor.INPUT, condition = "headers['processor']=='product'")
    public void receiveOrder(Order order) throws JsonProcessingException {
        LOGGER.info("Order received from product: {}", mapper.writeValueAsString(order));
        // ...
    }

}
```

# 使用 Apache Kafka

在讨论 Spring Cloud 与消息代理的集成时，我提到了 Apache Kafka 几次。然而，到目前为止，我们还没有基于该平台运行任何示例。事实上，当与 Spring Cloud 项目一起使用时，RabbitMQ 往往是最受欢迎的选择，但 Kafka 也值得我们关注。它相对于 RabbitMQ 的一个优势是对分区的大力支持，这是 Spring Cloud Stream 最重要的特性之一。

Kafka 不是一个典型的消息代理。它更像是一个分布式流处理平台。它的主要特性是允许您发布和订阅记录流。它特别适用于实时流应用程序，这些应用程序转换或对数据流做出反应。它通常作为由一个或多个服务器组成的集群运行，并将记录流存储在主题中。

# 运行 Kafka

不幸的是，没有官方的 Apache Kafka Docker 镜像。然而，我们可以使用一个非官方的镜像，例如 Spotify 共享的镜像。与其他可用的 Kafka Docker 镜像相比，这个镜像在同一个容器中同时运行 Zookeeper 和 Kafka。以下是启动 Kafka 并将其暴露在端口`9092`上的 Docker 命令。Zookeeper 也外部可访问端口`2181`：

```java
docker run -d --name kafka -p 2181:2181 -p 9092:9092 --env ADVERTISED_HOST=192.168.99.100 --env ADVERTISED_PORT=9092 spotify/kafka
```

# 定制应用程序设置

要为应用程序启用 Apache Kafka，请将`spring-cloud-starter-stream-kafka`启动器包括在依赖项中。我们当前的示例与在*发布/订阅模型*章节中介绍的 RabbitMQ 的发布/订阅、带分组和分区的示例非常相似。唯一的区别在于依赖项和配置设置。

Spring Cloud Stream 会自动检测并使用类路径中找到的绑定器。连接设置可以通过`spring.kafka.*`属性进行覆盖。在我们的案例中，我们只需要将自动配置的 Kafka 客户端地址更改为 Docker 机器的地址`192.168.99.100`。对于由 Kafka 客户端使用的 Zookeeper 也应进行相同的修改：

```java
spring: 
 application:
  name: order-service
  kafka:
   bootstrap-servers: 192.168.99.100:9092
 cloud: 
  stream:
   bindings:
    output:
     destination: orders-out
     producer:
      partitionKeyExpression: payload.customerId
      partitionCount: 2
    input:
     destination: orders-in
   kafka:
    binder:
     zkNodes: 192.168.99.100
```

启动发现、网关以及所有必需的微服务实例之后，您可以执行与之前示例相同的测试。如果配置正确，您在应用启动过程中在日志中应看到以下片段。测试结果与基于 RabbitMQ 的示例完全相同：

```java
16:58:30.008 INFO [,] Discovered coordinator 192.168.99.100:9092 (id: 2147483647 rack: null) for group account.
16:58:30.038 INFO [,] Successfully joined group account with generation 1
16:58:30.039 INFO [,] Setting newly assigned partitions [orders-out-0, orders-out-1] for group account
16:58:30.081 INFO [,] partitions assigned:[orders-out-0, orders-out-1]
```

# 支持 Kafka Streams API

Spring Cloud Stream Kafka 提供了一个专门为 Kafka Streams 绑定设计的绑定器。通过这个绑定器，应用程序可以利用 Kafka Streams API。为了为您的应用程序启用此功能，请在您的项目中包含以下依赖项：

```java
<dependency>
 <groupId>org.springframework.cloud</groupId>
 <artifactId>spring-cloud-stream-binder-kstream</artifactId>
</dependency>
```

Kafka Streams API 提供了高级流 DSL。可以通过声明接收 `KStream` 接口作为参数的 `@StreamListener` 方法来访问它。KStream 为流处理提供了些有用的方法，这些方法在其他流式 API 中也很知名，如 `map`、`flatMap`、`join` 或 `filter`。还有一些 Kafka Stream 特有的方法，例如 `to(...)`（用于将流发送到主题）或 `through(...)`（与 `to` 相同，但还会从主题创建一个新的 `KStream` 实例）：

```java
@SpringBootApplication
@EnableBinding(KStreamProcessor.class)
public class AccountApplication {

    @StreamListener("input")
    @SendTo("output")
    public KStream<?, Order> process(KStream<?, Order> input) {
        // ..
    }

    public static void main(String[] args) {
        SpringApplication.run(AccountApplication.class, args);
    }

}
```

# 配置属性

一些 Spring Cloud 针对 Kafka 的配置设置在讨论示例应用程序实现时已经介绍过。下面是一个包含为自定义 Apache Kafka 绑定器设置的最重要属性的表格，所有这些属性都带有 `spring.cloud.stream.kafka.binder` 前缀：

| Name | 默认值 | 描述 |
| --- | --- | --- |
| `brokers` | `localhost` | 带或不带端口信息的经纪人列表，以逗号分隔。 |
| `defaultBrokerPort` | `9092` | 如果没有使用`brokers`属性定义端口，则设置默认端口。 |
| `zkNodes` | `localhost` | 带或不带端口信息的 ZooKeeper 节点列表，以逗号分隔。 |
| `defaultZkPort` | `2181` | 如果没有使用 `zkNodes` 属性定义端口，则设置默认 ZooKeeper 端口。 |
| `configuration` | - | Kafka 客户端属性的键/值映射。它适用于绑定器创建的所有客户端。 |
| `headers` | - | 将由绑定器传递的自定义头列表。 |
| `autoCreateTopics` | `true` | 如果设置为`true`，则绑定器会自动创建新主题。 |
| `autoAddPartitions` | `false` | 如果设置为`true`，则绑定器会自动创建新的分区。 |

# 多个绑定器

在 Spring Cloud Stream 命名约定中，可以实现以提供对外部中间件的物理目的地连接的接口称为**绑定器**。目前，有两大内置绑定器实现——Kafka 和 RabbitMQ。如果您想要提供一个自定义的绑定器库，关键的接口是一个将输入和输出连接到外部中间件的策略的抽象，称为 `Binder`，有两个方法——`bindConsumer` 和 `bindProducer`。有关更多详细信息，请参考 Spring Cloud Stream 规范。

对我们来说重要的是，能够在单个应用程序中使用多个绑定器。你甚至可以混合不同的实现，例如，RabbitMQ 和 Kafka。Spring Cloud Stream 在绑定过程中依赖于 Spring Boot 的自动配置。可用的实现自动使用。如果您想要同时使用默认的绑定器，请将以下依赖项包含在项目中：

```java
<dependency>
 <groupId>org.springframework.cloud</groupId>
 <artifactId>spring-cloud-stream-binder-rabbit</artifactId>
</dependency>
<dependency>
 <groupId>org.springframework.cloud</groupId>
 <artifactId>spring-cloud-stream-binder-kafka</artifactId>
</dependency>
```

如果在类路径中找到了多个绑定器，应用程序必须检测出哪个应该用于特定的通道绑定。我们可以通过`spring.cloud.stream.defaultBinder`属性全局配置默认的绑定器，或者每个通道分别通过`spring.cloud.stream.bindings.<channelName>.binder`属性配置。现在，我们回到我们的示例中，在那里配置多个绑定器。我们为`account-service`和`order-service`之间的直接通信定义 RabbitMQ，为`order-service`与其他微服务之间的发布/订阅模型定义 Kafka。

以下是在`publish_subscribe`分支中为`account-service`提供的等效配置([`github.com/piomin/sample-spring-cloud-messaging/tree/publish_subscribe`](https://github.com/piomin/sample-spring-cloud-messaging/tree/publish_subscribe)),但基于两种不同的绑定器：

```java
spring:
 cloud:
  stream:
   bindings:
    output:
     destination: orders-in
     binder: rabbit1
    input:
     consumer:
      partitioned: true
     destination: orders-out
     binder: kafka1
     group: account
   rabbit:
    bindings:
     output:
      producer:
       exchangeType: direct
       routingKeyExpression: '"#"'
   binders:
    rabbit1:
     type: rabbit
     environment:
      spring:
       rabbitmq:
        host: 192.168.99.100
    kafka1:
     type: kafka
     environment:
      spring:
       kafka:
        bootstrap-servers: 192.168.99.100:9092
```

# 概要

Spring Cloud Stream 与其他所有 Spring Cloud 项目相比可以被视为一个单独的类别。它经常与其他项目关联，而这些项目目前由 Pivotal Spring Cloud Data Flow 强烈推广。这是一个用于构建数据集成和实时数据处理管道的工具包。然而，这是一个庞大的主题，更是一个需要单独讨论的书本内容。

更具体地说，Spring Cloud Stream 提供了异步消息传递的支持，这可以通过使用 Spring 注解风格轻松实现。我认为对于你们中的某些人来说，这种服务间通信的风格不如 RESTful API 模型明显。因此，我专注于向你们展示使用 Spring Cloud Stream 的点对点和发布/订阅通信的示例。我还描述了这两种消息传递风格之间的区别。

发布/订阅模型并非新事物，但得益于 Spring Cloud Stream，它可以轻松地包含在基于微服务的系统中。本章中还描述了一些关键概念，例如消费者组或分区。阅读后，你应该能够实现基于消息模型的微服务，并将它们与 Spring Cloud 库集成，以提供日志记录、跟踪，或者只是将它们作为现有 REST-based 微服务系统的一部分部署。


# 第十二章：保护 API

安全性是关于微服务架构的最常讨论的问题之一。对于所有安全关注，总是有一个主要问题——网络。在微服务中，通常网络通信比单体应用程序多，因此应该重新考虑认证和授权的方法。传统的系统通常在边界处进行安全保护，然后允许前端服务完全访问后端组件。微服务的迁移迫使我们改变这种委托访问管理的方法。

Spring Framework 是如何解决基于微服务的架构的安全问题的？它提供了几个项目，实现了关于认证和授权的不同模式。这些项目中的第一个是 Spring Security，它是基于 Spring 的 Java 应用程序的安全事实标准。它包括几个子模块，可以帮助你开始使用 SAML、OAuth2 或 Kerberos。还有 Spring Cloud Security 项目。它提供了几个组件，允许你将 Spring Security 的基本功能与微服务架构的主要元素（如网关、负载均衡器和 REST HTTP 客户端）集成。

在本章中，我将向您展示如何保护您基于微服务的系统中的所有主要组件。我将描述与主题相关的特定元素，按照构成本书第二部分的章节的顺序。所以，我们将从使用 Eureka 的服务发现开始，然后转移到 Spring Cloud Config Server 和跨服务通信，最后讨论 API 网关安全。

在本章中，我们将探讨以下内容：

+   为单个 Spring Boot 应用程序配置安全连接

+   为微服务架构的最重要元素启用 HTTPS 通信

+   在 Config Server 上存储的配置文件中加密和解密属性值

+   为微服务使用基于 OAuth2 的简单内存身份验证

+   使用 JDBC 后端存储和 JWT 令牌进行更高级的 OAuth2 配置

+   在 Feign 客户端中使用 OAuth2 授权进行服务间通信

但是首先，让我们从基础知识开始。我将向您展示如何创建第一个安全微服务，该微服务通过 HTTPS 暴露 API。

# 为 Spring Boot 启用 HTTPS

如果您想要使用 SSL 并为您提供 RESTful API 的 HTTPS 服务，您需要生成一个证书。实现这一目标最快的途径是通过自签名证书，这对于开发模式来说已经足够了。JRE 提供了一个简单的证书管理工具——`keytool`。它位于您的`JRE_HOME\bin`目录下。以下代码中的命令生成一个自签名证书并将其放入 PKCS12 KeyStore 中。除了 KeyStore 的类型之外，您还需要设置其有效期、别名以及文件名。在开始生成过程之前，`keytool`会要求您输入密码和一些其他信息，如下所示：

```java
keytool -genkeypair -alias account-key -keyalg RSA -keysize 2048 -storetype PKCS12 -keystore account-key.p12 -validity 3650

Enter keystore password:
Re-enter new password:
What is your first and last name?
 [Unknown]: localhost
What is the name of your organizational unit?
 [Unknown]: =
What is the name of your organization?
 [Unknown]: piomin
What is the name of your City or Locality?
 [Unknown]: Warsaw
What is the name of your State or Province?
 [Unknown]: mazowieckie
What is the two-letter country code for this unit?
 [Unknown]: PL
Is CN=localhost, OU=Unknown, O=piomin, L=Warsaw, ST=mazowieckie, C=PL correct?
 [no]: yes
```

我已经将生成的证书复制到了 Spring Boot 应用程序内的`src/main/resources`目录中。在构建并运行应用程序后，它将出现在类路径上。为了启用 SSL，我们必须在`application.yml`文件中提供一些配置设置。通过设置各种`server.ssl.*`属性，可以为 Spring 自定义 SSL：

```java
server: 
 port: ${PORT:8090}

ssl:
 key-store: classpath:account-key.p12
 key-store-password: 123456
 key-store-type: PKCS12
 key-alias: account-key

security:
 require-ssl: true
```

# 安全发现

正如您所看到的，为微服务应用程序配置 SSL 并不是一个非常困难的任务。然而，现在是提高难度级别的时候了。我们已经启动了一个单一的微服务，它通过 HTTPS 提供 RESTful API。现在我们想要这个微服务与发现服务器集成。由此产生的两个问题，首先是需要在 Eureka 中发布关于安全微服务实例的信息。第二个问题是如何通过 HTTPS 暴露 Eureka，并强制发现客户端使用私钥对发现服务器进行身份验证。让我们详细讨论这些问题。

# 注册安全应用程序

如果您的应用程序通过安全的 SSL 端口暴露，您应该将`EurekaInstanceConfig`中的两个标志更改为`nonSecurePortEnabled`为`false`和`securePortEnabled`为`true`。这使得 Eureka 发布显式偏好安全通信的实例信息。对于这样配置的服务，Spring Cloud `DiscoveryClient`总是会返回一个以 HTTPS 开头的 URL，并且 Eureka 实例信息将有一个安全的健康检查 URL：

```java
eureka:
 instance:
  nonSecurePortEnabled: false
  securePortEnabled: true
  securePort: ${PORT:8091}
  statusPageUrl: https://localhost:${eureka.instance.securePort}/info
  healthCheckUrl: https://localhost:${eureka.instance.securePort}/health
  homePageUrl: https://localhost:${eureka.instance.securePort}
```

# 通过 HTTPS 提供 Eureka

当使用 Spring Boot 启动 Eureka 服务器时，它部署在嵌入式 Tomcat 容器中，因此 SSL 配置与标准微服务相同。区别在于我们必须考虑客户端应用程序，它通过 HTTPS 与发现服务器建立安全连接。发现客户端应该对自己进行身份验证，以对抗 Eureka 服务器，并且还应该验证服务器的证书。客户端和服务器之间的这种通信过程称为**双向 SSL**或**相互认证**。还有一种单向认证，实际上是默认选项，其中只有客户端验证服务器的公钥。Java 应用程序使用 KeyStore 和 trustStore 来存储与公钥对应的私钥和证书。trustStore 和 KeyStore 之间的唯一区别在于它们存储的内容和目的。当客户端和服务器之间执行 SSL 握手时，trustStore 用于验证凭据，而 KeyStore 用于提供凭据。换句话说，KeyStore 为给定应用程序保存私钥和证书，而 trustStore 保存用于从第三方识别它的证书。开发者在配置安全连接时通常不会过多关注这些术语，但正确理解它们可以帮助您轻松了解接下来会发生什么。

在典型的基于微服务的架构中，有大量的独立应用程序和一个发现服务器。每个应用程序都有自己的私钥存储在 KeyStore 中，以及对应于发现服务器公钥的证书存储在 trustStore 中。另一方面，服务器保留了为客户端应用程序生成的所有证书。现在我们已经有了足够多的理论。让我们看看下面的图表。它说明了我们在前几章中用作示例的系统的当前情况：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/4bdd8fff-ba4d-4694-82b7-5cd6658b7582.png)

# Keystore 生成

在讨论了 Java 安全性的基础知识之后，我们可以继续生成微服务的私钥和公钥。像以前一样，我们将使用 JRE 下的命令行工具——`keytool`。让我们从一个生成`keystore`文件的键对的知名命令开始。一个 KeyStore 为发现服务器生成，另一个为选定的微服务生成，在本例中，为`account-service`生成：

```java
keytool -genkey -alias account -store  type JKS -keyalg RSA -keysize 2048 -keystore account.jks -validity 3650
keytool -genkey -alias discovery -storetype JKS -keyalg RSA -keysize 2048 -keystore discovery.jks -validity 3650
```

然后，必须将自签名证书从 KeyStore 导出到文件中——例如，具有`.cer`或`.crt`扩展名。然后系统会提示您输入在生成 KeyStore 时提供的密码：

```java
keytool -exportcert -alias account -keystore account.jks -file account.cer
keytool -exportcert -alias discovery -keystore discovery.jks -file discovery.cer
```

从 KeyStore 中提取了与公钥对应的证书，因此现在它可以分发给所有感兴趣的各方。`account-service`的公共证书应该包含在发现服务器的 trustStore 中，反之亦然：

```java
keytool -importcert -alias discovery -keystore account.jks -file discovery.cer
keytool -importcert -alias account -keystore discovery.jks -file account.cer
```

对`account-service`执行的相同步骤也必须重复应用于每个随后注册自己的 Eureka 服务器的微服务。以下是`order-service`生成 SSL 密钥和证书时使用的`keytool`命令：

```java
keytool -genkey -alias order -storetype JKS -keyalg RSA -keysize 2048 -keystore order.jks -validity 3650
keytool -exportcert -alias order -keystore order.jks -file order.cer
keytool -importcert -alias discovery -keystore order.jks -file discovery.cer
keytool -importcert -alias order -keystore discovery.jks -file order.cer
```

# 为微服务和 Eureka 服务器配置 SSL

每个`keystore`文件都被放置在每个安全微服务和服务发现`src/main/resources`目录中。每个微服务的 SSL 配置设置与*启用 Spring Boot HTTPS*节中的示例非常相似。唯一的区别是当前使用的 KeyStore 类型，现在是 JKS 而不是 PKCS12。然而，早期示例与服务发现配置之间还有更多区别。首先，我通过将`server.ssl.client-auth`属性设置为`need`来启用了客户端证书认证。这反过来要求我们提供一个`server.ssl.trust-store`属性的 trustStore。以下是`discovery-service`的`application.yml`中的当前 SSL 配置设置：

```java
server: 
 port: ${PORT:8761}
 ssl:
  enabled: true
  client-auth: need
  key-store: classpath:discovery.jks
  key-store-password: 123456
  trust-store: classpath:discovery.jks
  trust-store-password: 123456
  key-alias: discovery
```

如果您使用前面的配置运行 Eureka 应用程序，然后尝试访问其可通过`https://localhost:8761/`访问的网络仪表板，您可能会得到一个错误代码，如`SSL_ERROR_BAD_CERT_ALERT`。出现这个错误是因为您的网络浏览器中没有导入可信证书。为此，我们可以导入一个客户端应用程序的 KeyStore，例如`account-service`的。但首先，我们需要将其从 JKS 格式转换为受网络浏览器支持的另一种格式，例如 PKCS12。以下是`keytool`命令，用于将 KeyStore 从 JKS 格式转换为 PKCS12 格式：

```java
keytool -importkeystore -srckeystore account.jks -srcstoretype JKS -deststoretype PKCS12 -destkeystore account.p12
```

PKCS12 格式被所有主流的网络浏览器支持，比如 Google Chrome 和 Mozilla Firefox。您可以通过导航到设置*|*显示高级设置...|HTTPS/SSL*|*管理证书部分，在 Google Chrome 中导入 PKCS12 KeyStore。如果您再次尝试访问 Eureka 网络仪表板，您应该能够成功认证，并能够看到已注册服务列表。然而，在那里注册的应用程序将不存在。为了在发现客户端和服务器之间提供安全的通信，我们需要为每个微服务创建一个`@Bean`类型的`DiscoveryClientOptionalArgs`，覆盖发现客户端的实现。有趣的是，Eureka 使用 Jersey 作为 REST 客户端。使用`EurekaJerseyClientBuilder`，我们可以轻松地构建一个新的客户端实现，并传递`keystore`和`truststore`文件的路径。以下是从`account-service`中获取的代码片段，我们创建了一个新的`EurekaJerseyClient`对象，并将其设置为`DiscoveryClientOptionalArgs`的参数：

```java
@Bean
public DiscoveryClient.DiscoveryClientOptionalArgs discoveryClientOptionalArgs() throws NoSuchAlgorithmException {
 DiscoveryClient.DiscoveryClientOptionalArgs args = new DiscoveryClient.DiscoveryClientOptionalArgs();
 System.setProperty("javax.net.ssl.keyStore",             
    "src/main/resources/account.jks");
 System.setProperty("javax.net.ssl.keyStorePassword", "123456");
 System.setProperty("javax.net.ssl.trustStore", 
    "src/main/resources/account.jks");
 System.setProperty("javax.net.ssl.trustStorePassword", "123456");
 EurekaJerseyClientBuilder builder = new EurekaJerseyClientBuilder();
 builder.withClientName("account-client");
 builder.withSystemSSLConfiguration();
 builder.withMaxTotalConnections(10);
 builder.withMaxConnectionsPerHost(10);
 args.setEurekaJerseyClient(builder.build());
 return args;
}
```

我们示例系统中的每个微服务都应该提供类似的实现。一个示例应用程序的源代码可以在 GitHub 上找到([`github.com/piomin/sample-spring-cloud-security.git`](https://github.com/piomin/sample-spring-cloud-security.git))。你可以克隆它，并用你的 IDE 运行所有的 Spring Boot 应用程序。如果一切正常，你应该在 Eureka 仪表板上看到与以下屏幕截图相同的注册服务列表。如果 SSL 连接有任何问题，尝试在应用程序启动时设置`-Djava.net.debug=ssl` VM 参数，以能够查看 SSL 握手过程的完整日志：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/450b5cda-04ec-455d-acc3-8fc21cf2d768.png)

# 安全配置服务器

在我们架构中还有一个关键要素需要在讨论安全时考虑——Spring Cloud Config 配置服务器。我觉得保护配置服务器甚至比保护发现服务更为重要。为什么？因为我们通常将它们的认证凭据存储在外部系统上，还有其他一些不应该被未授权访问和使用的数据。有几种方法可以妥善保护你的配置服务器。你可以配置 HTTP 基本认证，安全的 SSL 连接，加密/解密敏感数据，或者使用第三方工具，如在第五章中介绍的，使用 Spring Cloud Config 进行分布式配置。让我们 closer 看看其中的一些。

# 加密和解密

在开始之前，我们必须下载并安装由 Oracle 提供的**Java Cryptography Extension**（**JCE**）。它包括两个 JAR 文件（`local_policy.jar`和`US_export_policy.jar`），需要覆盖 JRE lib/security 目录中现有的策略文件。

如果配置服务器上存储的远程属性源包含加密数据，它们的值应该以`{cipher}`为前缀，并用引号括起来，以表示它是一个 YAML 文件。对于`.properties`文件，不需要用引号括起来。如果无法解密这样的值，它将被替换为同样的键前缀`invalid`的附加值（通常是`<n/a>`）。

在我们上一个示例中，我们在应用程序配置设置中存储了用于保护`keystore`文件的密码短语。将其保存在纯文本文件中可能不是最好的主意，所以它是加密的第一候选。问题是，我们如何加密它？幸运的是，Spring Boot 提供了两个 RESTful 端点可以帮助实现。

让我们看看它是如何工作的。首先，我们需要启动一个配置服务器实例。最简单的方法是激活`--spring.profiles.active=native`配置文件，该配置文件会使用来自本地类路径或文件系统的属性源来启动服务器。现在我们可以调用两个 POST 端点`/encrypt`和`/decrypt`。`/encrypt`方法接受我们的明文密码作为参数。我们可以通过使用逆操作`/decrypt`，它接受一个加密密码作为参数，来检查结果：

```java
$ curl http://localhost:8888/encrypt -d 123456
AQAzI8jv26K3n6ff+iFzQA9DUpWmg79emWu4ndEXyvjYnKFSG7rBmJP0oFTb8RzjZbTwt4ehRiKWqu5qXkH8SAv/8mr2kdwB28kfVvPj/Lb5hdUkH1TVrylcnpZaKaQYBaxlsa0RWAKQDk8MQKRw1nJ5HM4LY9yjda0YQFNYAy0/KRnwUFihiV5xDk5lMOiG4b77AVLmz+9aSAODKLO57wOQUzM1tSA7lO9HyDQW2Hzl1q93uOCaP5VQLCJAjmHcHvhlvM442bU3B29JNjH+2nFS0RhEyUvpUqzo+PBi4RoAKJH9XZ8G7RaTOeWIcJhentKRf0U/EgWIVW21NpsE29BHwf4F2JZiWY2+WqcHuHk367X21vk11AVl9tJk9aUVNRk=
```

加密使用公钥，而解密使用私钥。因此，如果你只进行加密，那么在服务器上只需提供公钥即可。出于测试目的，我们可以使用`keytool`创建 KeyStore。我们之前已经创建了一些 KeyStores，所以在这方面你不会有任何问题。生成的文件应该放在类路径中，然后在`config-service`配置设置中使用`encrypt.keyStore.*`属性：

```java
encrypt:
 keyStore:
  location: classpath:/config.jks
  password: 123456
  alias: config
  secret: 123456
```

现在，如果你将每个微服务的配置设置移动到配置服务器，你可以像下面示例片段中那样加密每个密码：

```java
server: 
 port: ${PORT:8091}
 ssl:
 enabled: true
 key-store: classpath:account.jks
 key-store-password: '{cipher}AQAzI8jv26K3n6ff+iFzQA9DUpWmg79emWu4ndEXyvjYnKFSG7rBmJP0oFTb8RzjZbTwt4ehRiKWqu5qXkH8SAv/8mr2kdwB28kfVvPj/Lb5hdUkH1TVrylcnpZaKaQYBaxlsa0RWAKQDk8MQKRw1nJ5HM4LY9yjda0YQFNYAy0/KRnwUFihiV5xDk5lMOiG4b77AVLmz+9aSAODKLO57wOQUzM1tSA7lO9HyDQW2Hzl1q93uOCaP5VQLCJAjmHcHvhlvM442bU3B29JNjH+2nFS0RhEyUvpUqzo+PBi4RoAKJH9XZ8G7RaTOeWIcJhentKRf0U/EgWIVW21NpsE29BHwf4F2JZiWY2+WqcHuHk367X21vk11AVl9tJk9aUVNRk='
 key-alias: account
```

# 为客户端和服务器配置认证

Spring Cloud Config 服务器的认证实现与 Eureka 服务器的认证实现完全一样。我们可以使用基于标准 Spring 安全机制的 HTTP 基本认证。首先，我们需要确保`spring-security`工件在类路径上。然后我们应该使用`security.basic.

将`enabled`设置为`true`并定义用户名和密码。示例配置设置如下代码片段所示：

```java
security:
 basic:
  enabled: true
 user:
  name: admin
  password: admin123
```

基本认证必须在客户端也启用。这可以通过两种不同的方式实现。第一种是通过配置服务器的 URL：

```java
spring:
 cloud:
  config:
   uri: http://admin:admin123@localhost:8888
```

第二种方法基于独立的`username`和`password`属性：

```java
spring:
 cloud:
  config:
   uri: http://localhost:8888
   username: admin
   password: admin123
```

如果你想设置 SSL 认证，你需要遵循*安全发现*部分描述的步骤。在生成带有私钥和证书的 KeyStores 并设置正确的配置之后，我们可以运行配置服务器。现在，它通过 HTTPS 暴露其 RESTful API。唯一的区别在于客户端的实现。这是因为 Spring Cloud Config 使用的是与 Spring Cloud Netflix Eureka 不同的 HTTP 客户端。正如你可能猜到的，它利用了`RestTemplate`，因为它是完全在 Spring Cloud 项目中创建的。

为了强制客户端应用程序使用双向 SSL 认证而不是标准的、不安全的 HTTP 连接，我们首先应该创建一个实现`PropertySourceLocator`接口的`@Configuration`bean。在那里，我们可以构建一个自定义的`RestTemplate`，它使用一个安全的 HTTP 连接工厂：

```java
@Configuration
public class SSLConfigServiceBootstrapConfiguration {

    @Autowired
    ConfigClientProperties properties;

    @Bean
    public ConfigServicePropertySourceLocator configServicePropertySourceLocator() throws Exception {
        final char[] password = "123456".toCharArray();
        final File keyStoreFile = new File("src/main/resources/discovery.jks");
        SSLContext sslContext = SSLContexts.custom()
                .loadKeyMaterial(keyStoreFile, password, password)
                .loadTrustMaterial(keyStoreFile).build();
        CloseableHttpClient httpClient = HttpClients.custom().setSSLContext(sslContext).build();
        HttpComponentsClientHttpRequestFactory requestFactory = new HttpComponentsClientHttpRequestFactory(httpClient);
        ConfigServicePropertySourceLocator configServicePropertySourceLocator = new ConfigServicePropertySourceLocator(properties);
        configServicePropertySourceLocator.setRestTemplate(new RestTemplate(requestFactory));
        return configServicePropertySourceLocator;
    }

}
```

然而，默认情况下，这个 bean 在应用程序尝试与配置服务器建立连接之前不会被创建。要改变这种行为，我们还应该在`/src/main/resources/META-INF`中创建`spring.factories`文件，并指定自定义的引导配置类：

```java
org.springframework.cloud.bootstrap.BootstrapConfiguration = pl.piomin.services.account.SSLConfigServiceBootstrapConfiguration
```

# 使用 OAuth2 进行授权

我们已经讨论了一些与微服务环境中的认证相关的概念和解决方案。我向您展示了微服务之间以及微服务与服务发现和配置服务器之间的基本和 SSL 认证的例子。在服务间通信中，授权似乎比认证更重要，而认证则实现在系统的边缘。理解认证和授权之间的区别是值得的。简单地说，认证验证你是谁，而授权验证你被授权做什么。

目前最流行的 RESTful HTTP API 授权方法是 OAuth2 和**Java Web Tokens**（**JWT**）。它们可以混合使用，因为它们互补性比其他解决方案要强。Spring 为 OAuth 提供商和消费者提供了支持。借助 Spring Boot 和 Spring Security OAuth2，我们可以快速实现常见的 security patterns，如单点登录、令牌传递或令牌交换。但在我们深入了解这些项目以及其他开发细节之前，我们需要先掌握前面解决方案的基本知识。

# OAuth2 简介

OAuth2 是目前几乎所有主要网站所使用的标准，它允许您通过共享 API 访问他们的资源。它将用户认证委托给一个独立的服务，该服务存储用户凭据并授权第三方应用程序访问关于用户账户的共享信息。OAuth2 用于在保护用户账户凭据的同时给予您的用户访问数据的能力。它为 web、桌面和移动应用程序提供了流程。以下是与 OAuth2 相关的一些基本术语和角色：

+   **资源所有者**：这个角色管理对资源的访问。这种访问受授予授权的范围限制。

+   **授权许可**：它授予访问权限。您可以选择以各种方式确认访问——授权代码、隐式、资源所有者密码凭据和客户端凭据。

+   **资源服务器**：这是一个存储可以使用特殊令牌共享所有者资源的服务器。

+   **授权服务器**：它管理密钥、令牌和其他临时资源访问代码的分配。它还需要确保授予相关用户的访问权限。

+   **访问令牌**：这是一个允许访问资源的钥匙。

为了更好地理解这些术语和实践中的角色，请看下面的图表。它通过 OAuth 协议可视化了一个典型的授权过程流程：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/fb8ff8a6-c870-4ff5-a776-a7f0aedcc84a.png)

让我们回顾一下前面列出个别组件之间交互的进一步步骤。应用程序请求资源所有者的授权，以便能够访问所请求的服务。资源以授权授予作为响应发送，应用程序将其与自身的身份一起发送到授权服务器。授权服务器验证应用程序身份凭据和授权授予，然后发送访问令牌。应用程序使用收到的访问令牌从资源服务器请求资源。最后，如果访问令牌有效，应用程序能够调用请求服务。

# 构建授权服务器

从单体应用程序移动到微服务后，明显的解决方案似乎是通过创建一个授权服务来集中授权努力。使用 Spring Boot 和 Spring Security，你可以轻松地创建、配置和启动一个授权服务器。首先，我们需要将以下`starters`包括到项目依赖中：

```java
<dependency>
    <groupId>org.springframework.cloud</groupId>
    <artifactId>spring-cloud-starter-oauth2</artifactId>
</dependency>
<dependency>
    <groupId>org.springframework.cloud</groupId>
    <artifactId>spring-cloud-starter-security</artifactId>
</dependency>
```

使用 Spring Boot 实现授权服务器模式非常简单。我们只需要将主类或配置类注解为`@EnableAuthorizationServer`，然后提供`security.oauth2.client.client-id`和`security.oauth2.client.client-secret`属性在`application.yml`文件中。当然，这个变体尽可能简单，因为它定义了客户端详情服务的内存实现。

一个示例应用程序在同一存储库中，本章之前的示例中([`github.com/piomin/sample-spring-cloud-security.git`](https://github.com/piomin/sample-spring-cloud-security.git))，但在不同的分支，`oauth2` ([`github.com/piomin/sample-spring-cloud-security/tree/oauth2`](https://github.com/piomin/sample-spring-cloud-security/tree/oauth2))。授权服务器在`auth-service`模块下可用。以下是`auth-service`的主类：

```java
@SpringBootApplication
@EnableAuthorizationServer
public class AuthApplication {

    public static void main(String[] args) {
        new SpringApplicationBuilder(AuthApplication.class).web(true).run(args);
    }

}
```

以下是应用程序配置设置的片段。除了客户端的 ID 和密钥外，我还设置了它的默认范围并在整个项目中启用了基本安全：

```java
security:
  user:
    name: root
    password: password
  oauth2:
    client:
      client-id: piotr.minkowski
      client-secret: 123456
      scope: read
```

在我们运行授权服务之后，我们可以进行一些测试。例如，我们可以调用`POST /oauth/token`方法，使用资源所有者密码凭证来创建访问令牌，就像以下命令一样：

```java
$ curl piotr.minkowski:123456@localhost:9999/oauth/token -d grant_type=password -d username=root -d password=password
```

我们还可以通过从你的网络浏览器调用`GET /oauth/authorize`端点来使用授权码授权类型：

```java
http://localhost:9999/oauth/authorize?response_type=token&client_id=piotr.minkowski&redirect_uri=http://example.com&scope=read
```

然后，你将被重定向到批准页面。你可能确认这个动作，最后得到你的访问令牌。它将被发送到初始请求中`redirect_uri`参数传递的回调 URL。以下是我测试后收到的示例响应：

```java
http://example.com/#access_token=dd736a4a-1408-4f3f-b3ca-43dcc05e6df0&token_type=bearer&expires_in=43200.
```

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-sprcld/img/7e5e41f0-0bd3-4691-aea9-a93b0ecf709a.png)

在`application.yml`文件内提供的相同的 OAuth2 配置也可以以编程方式实现。为了实现这一点，我们应该声明任何实现`AuthorizationServerConfigurer`的`@Beans`。其中的一个是`AuthorizationServerConfigurerAdapter`适配器，它提供空方法，允许您创建以下分离配置器的自定义定义：

+   `ClientDetailsServiceConfigurer`：这定义了客户端详情服务。客户端详情可以初始化，或者你可以简单地引用一个现有的存储。

+   `AuthorizationServerSecurityConfigurer`：这定义了在`/oauth/token_key`和`/oauth/check_token`令牌端点上的安全约束。

+   `AuthorizationServerEndpointsConfigurer`：这定义了授权和令牌端点以及令牌服务。

这种对授权服务器实现的方法为我们提供了更多的机会。例如，我们可以定义一个带有 ID 和密钥的多个客户端，如下面的代码片段所示。我将在本章的下一部分展示一些更高级的示例：

```java
@Configuration
@EnableAuthorizationServer
public class AuthServerConfig extends AuthorizationServerConfigurerAdapter {

    @Override
    public void configure(AuthorizationServerSecurityConfigurer oauthServer) throws     Exception {
      oauthServer
        .tokenKeyAccess("permitAll()")
        .checkTokenAccess("isAuthenticated()");
    }

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.inMemory()
            .withClient("piotr.minkowski").secret("123456")
                .scopes("read")
                .authorities("ROLE_CLIENT")
                .authorizedGrantTypes("authorization_code", "refresh_token", "implicit")
                .autoApprove(true)
            .and()
            .withClient("john.smith").secret("123456")
                .scopes("read", "write")
                .authorities("ROLE_CLIENT")
                .authorizedGrantTypes("authorization_code", "refresh_token", "implicit")
                .autoApprove(true);
    }

}
```

我们必须为我们的授权服务器配置的最后一件事情是网络安全。在扩展了`WebSecurityConfigurerAdapter`的类中，我们定义了一个内存中的用户凭据存储和访问特定资源的权限，例如登录页面：

```java
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter { 

    @Autowired
    private AuthenticationManager authenticationManager; 

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.requestMatchers()
         .antMatchers("/login", "/oauth/authorize")
         .and()
         .authorizeRequests()
         .anyRequest().authenticated()
         .and()
         .formLogin().permitAll();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.parentAuthenticationManager(authenticationManager)
            .inMemoryAuthentication()
            .withUser("piotr.minkowski").password("123456").roles("USERS");
    }

}
```

# 客户端配置

您的应用程序可以使用配置的 OAuth2 客户端以两种不同的方式。这两种方式中的第一种是通过`@EnableOAuth2Client`注解，它创建了一个 ID 为`oauth2ClientContextFilter`的过滤器 bean，负责存储请求和上下文。它还负责管理您应用程序与授权服务器之间的通信。然而，我们将查看 OAuth2 客户端端实现的第二种方法，通过`@EnableOAuth2Sso`。**单点登录**（**SSO**）是一个众所周知的安全模式，允许用户使用一组登录凭据访问多个应用程序。这个注解提供了两个特性——OAuth2 客户端和认证。认证部分使您的应用程序与典型的 Spring Security 机制（如表单登录）对齐。客户端部分具有与`@EnableOAuth2Client`提供的功能相同的功能。因此，我们可以将`@EnableOAuth2Sso`视为比`@EnableOAuth2Client`更高层次的注解。

在下面的示例代码片段中，我用`@EnableOAuth2Sso`注解了扩展了`WebSecurityConfigurerAdapter`的类。得益于这个扩展，Spring Boot 配置了携带 OAuth2 身份处理器的网络安全过滤链。在这种情况下，允许访问`/login`页面，而所有其他请求都需要认证。表单登录页面路径可以通过`security.oauth2.sso.login-path`属性进行覆盖。在覆盖它之后，我们还应该记得在`WebSecurityConfig`内部更改路径模式：

```java
@Configuration
@EnableOAuth2Sso
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.antMatcher("/**")
            .authorizeRequests()
            .antMatchers("/login**")
                .permitAll()
            .anyRequest()
                .authenticated();
    }

}
```

还有一些需要设置的配置设置。首先，我们应该禁用基本认证，因为我们使用了与`@EnableOAuth2Sso`注解一起启用的表单登录方法。然后，我们必须提供一些基本的 OAuth2 客户端属性，例如客户端凭据和授权服务器公开的 HTTP API 端点的地址：

```java
security:
 basic:
  enabled: false
 oauth2:
  client:
   clientId: piotr.minkowski
   clientSecret: 123456
   accessTokenUri: http://localhost:9999/oauth/token
   userAuthorizationUri: http://localhost:9999/oauth/authorize
  resource:
   userInfoUri: http://localhost:9999/user
```

`application.yml`文件片段中的最后一个属性是`security.oauth2.resource.userInfoUri`，这需要在服务器端实现一个额外的端点。`UserController`实现的端点返回`java.security.Principal`对象，表示当前认证的用户：

```java
@RestController
public class UserController {

    @RequestMapping("/user")
    public Principal user(Principal user) {
        return user;
    }

}
```

现在，如果您调用我们微服务中公开的任何端点，您将自动重定向到登录页面。由于我们为内存中的客户端详细信息存储设置了`autoApprove`选项，因此授权授予和访问令牌无需用户任何交互即可自动生成。在登录页面提供您的凭据后，您应该能够获得请求资源的响应。

# 使用 JDBC 后端存储

在前几节中，我们配置了一个认证服务器和客户端应用程序，它授予访问受资源服务器保护的资源的权限。然而，整个授权服务器配置都提供在内存存储中。这种解决方案在开发过程中满足我们的需求，但在生产模式下并不是最理想的方法。目标解决方案应该将所有的认证凭据和令牌存储在数据库中。我们可以选择 Spring 支持的关系数据库之一。在此案例中，我决定使用 MySQL。

所以，第一步是在本地启动 MySQL 数据库。最舒适的方法是使用 Docker 容器。除了启动数据库，下面的命令还将创建一个名为`oauth2`的架构和用户：

```java
docker run -d --name mysql -e MYSQL_DATABASE=oauth2 -e MYSQL_USER=oauth2 -e MYSQL_PASSWORD=oauth2 -e MYSQL_ALLOW_EMPTY_PASSWORD=yes -p 33306:3306 mysql
```

一旦我们启动了 MySQL，现在必须在客户端提供连接设置。如果您在 Windows 机器上运行 Docker，则 MySQL 可在主机地址`192.168.99.100`上访问，端口为`33306`。数据源属性应在`auth-service`的`application.yml`中设置。Spring Boot 还能够在应用程序启动时在选定的数据源上运行一些 SQL 脚本。这对我们来说是个好消息，因为我们必须在为我们的 OAuth2 过程专用的架构上创建一些表：

```java
spring:
 application:
  name: auth-service
 datasource:
  url: jdbc:mysql://192.168.99.100:33306/oauth2?useSSL=false
  username: oauth2
  password: oauth2
  driver-class-name: com.mysql.jdbc.Driver
  schema: classpath:/script/schema.sql
  data: classpath:/script/data.sql
```

创建的架构包含一些用于存储 OAuth2 凭据和令牌的表——`oauth_client_details`、`oauth_client_token`、`oauth_access_token`、`oauth_refresh_token`、`oauth_code`和`oauth_approvals`。包含 SQL 创建命令的完整脚本可在`/src/main/resources/script/schema.sql`中找到。还有一个第二个 SQL 脚本，`/src/main/resources/script/data.sql`，其中有一些用于测试目的的`insert`命令。最重要的是要添加一些客户端 ID/客户端密钥对：

```java
INSERT INTO `oauth_client_details` (`client_id`, `client_secret`, `scope`, `authorized_grant_types`, `access_token_validity`, `additional_information`) VALUES ('piotr.minkowski', '123456', 'read', 'authorization_code,password,refresh_token,implicit', '900', '{}');
INSERT INTO `oauth_client_details` (`client_id`, `client_secret`, `scope`, `authorized_grant_types`, `access_token_validity`, `additional_information`) VALUES ('john.smith', '123456', 'write', 'authorization_code,password,refresh_token,implicit', '900', '{}');
```

当前认证服务器版本与基本示例中描述的版本在实现上有一些不同。这里的第一件重要事情是设置默认令牌存储到数据库，通过提供 `JdbcTokenStore` bean 作为默认数据源的参数。尽管现在所有令牌都存储在数据库中，但我们仍然希望以 JWT 格式生成它们。这就是为什么在类中必须提供第二个 bean，`JwtAccessTokenConverter`。通过重写从基类继承的不同 `configure` 方法，我们可以为 OAuth2 客户端详情设置默认存储，并配置授权服务器始终验证在 HTTP 头中提交的 API 密钥：

```java
@Configuration
@EnableAuthorizationServer
public class OAuth2Config extends AuthorizationServerConfigurerAdapter { 

    @Autowired
    private DataSource dataSource;
    @Autowired
    private AuthenticationManager authenticationManager; 

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        endpoints.authenticationManager(this.authenticationManager)
            .tokenStore(tokenStore())
            .accessTokenConverter(accessTokenConverter());
 }

    @Override
    public void configure(AuthorizationServerSecurityConfigurer oauthServer) throws Exception {
        oauthServer.checkTokenAccess("permitAll()");
    }

    @Bean
    public JwtAccessTokenConverter accessTokenConverter() {
        return new JwtAccessTokenConverter();
    }

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.jdbc(dataSource);
    } 

    @Bean
    public JdbcTokenStore tokenStore() {
        return new JdbcTokenStore(dataSource);
    }

}
```

Spring 应用程序提供了一个自定义的认证机制。要在应用程序中使用它，我们必须实现 `UserDetailsService` 接口并重写其 `loadUserByUsername` 方法。在我们示例应用程序中，用户凭据和权限也存储在数据库中，因此我们向自定义 `UserDetailsService` 类注入 `UserRepository` bean：

```java
@Component("userDetailsService")
public class UserDetailsServiceImpl implements UserDetailsService { 

    private final Logger log = LoggerFactory.getLogger(UserDetailsServiceImpl.class); 

    @Autowired
    private UserRepository userRepository; 

    @Override
    @Transactional
    public UserDetails loadUserByUsername(final String login) { 
        log.debug("Authenticating {}", login);
        String lowercaseLogin = login.toLowerCase(); 
        User userFromDatabase;
        if(lowercaseLogin.contains("@")) {
            userFromDatabase = userRepository.findByEmail(lowercaseLogin);
        } else {
            userFromDatabase = userRepository.findByUsernameCaseInsensitive(lowercaseLogin);
        } 
        if (userFromDatabase == null) {
            throw new UsernameNotFoundException("User " + lowercaseLogin + " was not found in the database");
        } else if (!userFromDatabase.isActivated()) {
            throw new UserNotActivatedException("User " + lowercaseLogin + " is not activated");
        } 
        Collection<GrantedAuthority> grantedAuthorities = new ArrayList<>();
        for (Authority authority : userFromDatabase.getAuthorities()) {
            GrantedAuthority grantedAuthority = new SimpleGrantedAuthority(authority.getName());
            grantedAuthorities.add(grantedAuthority);
        } 
        return new org.springframework.security.core.userdetails.User(userFromDatabase.getUsername(), userFromDatabase.getPassword(), grantedAuthorities);
 }

}
```

# 服务间授权

我们示例中的服务间通信是使用 Feign 客户端实现的。以下是所选实现之一——在这种情况下，来自 `order-service` ——它调用 `customer-service` 的端点：

```java
@FeignClient(name = "customer-service")
public interface CustomerClient {

    @GetMapping("/withAccounts/{customerId}")
    Customer findByIdWithAccounts(@PathVariable("customerId") Long customerId);

}
```

与其它服务一样，`customer-service` 中所有可用方法都基于 OAuth 令牌作用域的保护预授权机制。它允许我们用 `@PreAuthorize` 注解标记每个方法，定义所需的作用域：

```java
@PreAuthorize("#oauth2.hasScope('write')")
@PutMapping
public Customer update(@RequestBody Customer customer) {
    return repository.update(customer);
}

@PreAuthorize("#oauth2.hasScope('read')")
@GetMapping("/withAccounts/{id}")
public Customer findByIdWithAccounts(@PathVariable("id") Long id) throws JsonProcessingException {
    List<Account> accounts = accountClient.findByCustomer(id);
    LOGGER.info("Accounts found: {}", mapper.writeValueAsString(accounts));
    Customer c = repository.findById(id);
    c.setAccounts(accounts);
    return c;
}
```

预授权默认是禁用的。要为 API 方法启用它，我们应该使用 `@EnableGlobalMethodSecurity` 注解。我们还应指示这种预授权将基于 OAuth2 令牌作用域：

```java
@Configuration
@EnableResourceServer
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class OAuth2ResourceServerConfig extends GlobalMethodSecurityConfiguration {

    @Override
    protected MethodSecurityExpressionHandler createExpressionHandler() {
        return new OAuth2MethodSecurityExpressionHandler();
    }

}
```

如果您通过 Feign 客户端调用账户服务端点，将会得到以下异常：

```java
feign.FeignException: status 401 reading CustomerClient#findByIdWithAccounts(); content:{"error":"unauthorized","error_description":"Full authentication is required to access this resource"}
```

为什么会出现这样的异常呢？当然，`customer-service` 是通过 OAuth2 令牌授权进行保护的，但是 Feign 客户端在请求头中没有发送授权令牌。解决这个问题的一种方法是为 Feign 客户端定义一个自定义配置类。它允许我们声明一个请求拦截器。在这种情况下，我们可以使用 Spring Cloud OAuth2 库中提供的 `OAuth2FeignRequestInterceptor` 实现的 OAuth2。出于测试目的，我决定使用资源所有者密码授权类型：

```java
public class CustomerClientConfiguration {

    @Value("${security.oauth2.client.access-token-uri}")
    private String accessTokenUri;
    @Value("${security.oauth2.client.client-id}")
    private String clientId;
    @Value("${security.oauth2.client.client-secret}")
    private String clientSecret;
    @Value("${security.oauth2.client.scope}")
    private String scope;

    @Bean
    RequestInterceptor oauth2FeignRequestInterceptor() {
        return new OAuth2FeignRequestInterceptor(new DefaultOAuth2ClientContext(), resource());
    }

    @Bean
    Logger.Level feignLoggerLevel() {
        return Logger.Level.FULL;
    }

    private OAuth2ProtectedResourceDetails resource() {
        ResourceOwnerPasswordResourceDetails resourceDetails = new ResourceOwnerPasswordResourceDetails();
        resourceDetails.setUsername("root");
        resourceDetails.setPassword("password");
        resourceDetails.setAccessTokenUri(accessTokenUri);
        resourceDetails.setClientId(clientId);
        resourceDetails.setClientSecret(clientSecret);
        resourceDetails.setGrantType("password");
        resourceDetails.setScope(Arrays.asList(scope));
        return resourceDetails;
    }

}
```

最后，我们可以测试所实现的解决方案。这次，我们将创建一个 JUnit 自动化测试，而不是在网页浏览器中点击它或使用其他工具发送请求。以下代码片段显示了测试方法。我们使用`OAuth2RestTemplate`和`ResourceOwnerPasswordResourceDetails`执行资源所有者凭据授予操作，并调用来自`order-service`的`POST /` API 方法，请求头中发送了 OAuth2 令牌。当然，在运行那个测试之前，您必须启动所有微服务以及发现和授权服务器：

```java
@Test
public void testClient() {
    ResourceOwnerPasswordResourceDetails resourceDetails = new ResourceOwnerPasswordResourceDetails();
    resourceDetails.setUsername("root");
    resourceDetails.setPassword("password");
    resourceDetails.setAccessTokenUri("http://localhost:9999/oauth/token");
    resourceDetails.setClientId("piotr.minkowski");
    resourceDetails.setClientSecret("123456");
    resourceDetails.setGrantType("password");
    resourceDetails.setScope(Arrays.asList("read"));
    DefaultOAuth2ClientContext clientContext = new DefaultOAuth2ClientContext();
    OAuth2RestTemplate restTemplate = new OAuth2RestTemplate(resourceDetails, clientContext);
    restTemplate.setMessageConverters(Arrays.asList(new MappingJackson2HttpMessageConverter()));
    Random r = new Random();
    Order order = new Order();
    order.setCustomerId((long) r.nextInt(3) + 1);
    order.setProductIds(Arrays.asList(new Long[] { (long) r.nextInt(10) + 1, (long) r.nextInt(10) + 1 }));
    order = restTemplate.postForObject("http://localhost:8090", order, Order.class);
    if (order.getStatus() != OrderStatus.REJECTED) {
        restTemplate.put("http://localhost:8090/{id}", null, order.getId());
    }
}
```

# 在 API 网关上启用单点登录

您可以通过在主类上添加`@EnableOAuth2Sso`注解来仅通过注解在 API 网关上启用单点登录功能。确实，这是强制 Zuul 生成或获取当前认证用户的访问令牌的最佳选择，对于您的微服务架构来说：

```java
@SpringBootApplication
@EnableOAuth2Sso
@EnableZuulProxy
public class GatewayApplication {

    public static void main(String[] args) {
        new SpringApplicationBuilder(GatewayApplication.class).web(true).run(args);
    }

}
```

通过包含`@EnableOAuth2Sso`，你可以触发一个对 ZuulFilter 可用的自动配置。这个过滤器负责从当前已认证的用户中提取访问令牌，然后将其放入转发到微服务网关后面的请求头中。如果对这些服务启用了`@EnableResourceServer`，它们将会在`Authorization` HTTP 头中收到预期的令牌。`@EnableZuulProxy`下游的授权行为可以通过声明`proxy.auth.*`属性来控制。

当在您的架构中使用网关时，您可能在其后面隐藏一个授权服务器。在这种情况下，您应该在 Zuul 的配置设置中提供额外的路由—例如，`uaa`。然后，OAuth2 客户端与服务器之间交换的所有消息都通过网关。这是在网关的`application.yml`文件中的正确配置：

```java
security:
  oauth2:
    client:
      accessTokenUri: /uaa/oauth/token
      userAuthorizationUri: /uaa/oauth/authorize
      clientId: piotr.minkowski
      clientSecret: 123456
    resource:
      userInfoUri: http://localhost:9999/user

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
    uaa:
      sensitiveHeaders:
      path: /uaa/**
      url: http://localhost:9999
  add-proxy-headers: true
```

# 摘要

如果在本书的第二部分每个章节中都包含一个安全部分，那也不会有什么问题。但我决定专门用一章来介绍这个主题，以便向您展示如何逐步为基于微服务架构的关键元素提供安全保护的步骤。与安全相关的主题通常比其他主题更高级，所以我花了一些时间来解释该领域的一些基本概念。我向您展示了示例，说明了双向 SSL 认证、敏感数据的加密/解密、Spring Security 认证以及使用 JWT 令牌的 OAuth2 授权。您需要决定在您的系统架构中使用哪个来提供您所需的安全级别。

阅读本章后，你应该能够为你的应用程序设置基本和更高级的安全配置。你还应该能够保护你系统架构中的每一个组件。当然，我们只讨论了一些可能的解决方案和框架。例如，你不必仅依赖于 Spring 作为授权服务器提供者。我们可以使用第三方工具，如 Keycloak，它可以在基于微服务的系统中作为授权和认证服务器。它还可以轻松地与 Spring Boot 应用程序集成。它支持所有最流行的协议，如 OAuth2、OpenId Connect 和 SAML。因此，实际上，Keycloak 是一个非常强大的工具，应该被视为 Spring 授权服务器的替代品，特别是在大型企业系统和其他更高级的使用场景中。

在下一章中，我们将讨论微服务测试的不同策略。
