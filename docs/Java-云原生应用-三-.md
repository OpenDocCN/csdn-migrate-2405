# Java 云原生应用（三）

> 原文：[`zh.annas-archive.org/md5/3AA62EAF8E1B76B168545ED8887A16CF`](https://zh.annas-archive.org/md5/3AA62EAF8E1B76B168545ED8887A16CF)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第八章：云原生应用程序运行时

在本章中，我们将研究我们的应用程序或服务运行的运行时生态系统。我们将涵盖以下主题：

+   全面运行时的需求，包括操作和管理大量服务中的问题的总结

+   实施参考运行时架构，包括：

+   服务注册表

+   配置服务器

+   服务前端、API 网关、反向代理和负载均衡器

+   以 Zuul 作为反向代理的介绍

+   通过 Kubernetes 和 Minikube 进行容器管理和编排

+   在**平台即服务**（PaaS）上运行：

+   PaaS 平台如何帮助实现我们在前一章讨论的服务运行时参考架构

+   安装 Cloud Foundry 并在 Cloud Foundry 上运行我们的`product`服务

# 运行时的需求

我们已经开发了我们的服务，为它们编写了测试，自动化了持续集成，并在容器中运行它们。我们还需要什么？

在生产环境中运行许多服务并不容易。随着更多服务在生产环境中发布，它们的管理变得复杂。因此，这里是对在微服务生态系统中讨论的问题的总结，并在前一章的一些代码示例中得到解决：

+   **在云中运行的服务：**传统的大型应用程序托管在应用服务器上，并在 IP 地址和端口上运行。另一方面，微服务在多个容器中以各种 IP 地址和端口运行，因此跟踪生产服务可能会变得复杂。

+   **服务像打地鼠游戏中的鼹鼠一样上下运行：**有数百个服务，它们的负载被平衡和故障转移实例在云空间中运行。由于 DevOps 和敏捷性，许多团队正在部署新服务并关闭旧服务。因此，正如我们所看到的，基于微服务的云环境非常动态。

服务注册表跟踪服务来解决这两个问题。因此，客户端可以查找与名称对应的服务在哪里运行，使用客户端负载平衡模式。然而，如果我们想要将客户端与查找分离，那么我们使用服务器端负载平衡模式，其中负载均衡器（如 Nginx）、API 网关（如 Apigee）或反向代理或路由器（如 Zuul）将客户端与服务的实际地址抽象出来。

+   **跨微服务管理我的配置：**如果部署单元已分解为多个服务，那么打包的配置项（如连接地址、用户 ID、日志级别等）也会分解为属性文件。因此，如果我需要更改一组服务或流程的日志级别，我是否需要在所有应用程序的属性文件中进行更改？在这里，我们将看到如何通过 Spring Config Server 或 Consul 将属性文件集中化，以按层次结构管理属性。

+   **处理如此多的日志文件：**每个微服务都会生成一个（或多个）日志文件，如`.out`和`.err`以及 Log4j 文件。我们如何在多个服务的多个日志文件中搜索日志消息？

解决这个问题的模式是日志聚合，使用商业工具（如 Splunk）或开源工具（如 Logstash 或 Galaxia）实现。它们也默认存在于 PaaS 提供的工具中，如 Pivotal Cloud Foundry。

另一个选项是将日志流式传输到聚合器（如 Kafka），然后可以在其中进行集中存储。

+   **来自每个服务的指标：**在第二章中，*编写您的第一个云原生应用程序*，我们添加了 Spring 执行器指标，这些指标会暴露为端点。还有许多其他指标，如 Dropwizard 指标，可以被捕获和暴露。

要么一个代理必须监视所有服务执行器指标，要么它们可以被导出，然后在监控和报告工具中进行聚合。

另一个选项是应用程序监控工具，如 Dynatrace、AppDynamics 来监控应用程序，并在 Java 级别提取指标。我们将在下一章中介绍这些。

# 实施运行时参考架构

前一节讨论的问题由以下参考运行时架构解决：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/49927155-cba6-4fad-a513-b546c7d4fffb.png)

所有这些组件已经在第一章中讨论过，*云原生简介*。现在，我们继续选择技术并展示实现。

# 服务注册表

运行服务注册表 Eureka 在第二章中已经讨论过，*编写您的第一个云原生应用程序*。请参考该章节，回顾一下`product`服务如何在 Eureka 中注册自己以及客户端如何使用 Ribbon 和 Eureka 找到`product`服务。

如果我们使用 Docker 编排（如 Kubernetes），服务注册表的重要性会稍微降低。在这种情况下，Kubernetes 本身管理服务的注册，代理查找并重定向到服务。

# 配置服务器

配置服务器以分层方式存储配置。这样，应用程序只需要知道配置服务器的地址，然后连接到它以获取其余的配置。

有两个流行的配置服务器。一个是 Hashicorp 的 Consul，另一个是 Spring Config Server。我们将使用 Spring Config Server 来保持堆栈与 Spring 一致。

让我们来看看启动使用配置服务器的步骤。使用外部化配置有两个部分：服务器（提供属性）和客户端。

# 配置服务器的服务器部分

有许多选项可以通过 HTTP 连接提供属性，Consul 和 Zookeeper 是流行的选项之一。然而，对于 Spring 项目，Spring Cloud 提供了一个灵活的配置服务器，可以连接到多个后端，包括 Git、数据库和文件系统。鉴于最好将属性存储在版本控制中，我们将在此示例中使用 Spring Cloud Config 的 Git 后端。

Spring Cloud Config 服务器的代码、配置和运行时与 Eureka 非常相似，像我们在第二章中为 Eureka 做的那样，很容易启动一个实例，*编写您的第一个云原生应用程序*。

按照以下步骤运行服务注册表：

1.  创建一个新的 Maven 项目，将 artifact ID 设置为`config-server`。

1.  编辑 POM 文件并添加以下内容：

1\. 父项为`spring-boot-starter-parent`

2\. 依赖项为`spring-cloud-config-server`

3\. 依赖管理为`spring-cloud-config`

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/f3b5ae42-0431-4516-97ee-0e3b8c44f1a7.png)

1.  创建一个`ConfigServiceApplication`类，该类将有注解来启动配置服务器：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/a37f8d13-eb00-4a4f-aa5f-b9a7f9c47c46.png)

1.  在应用程序的`config-server/src/main/resources`文件夹中创建一个`application.yml`文件，并添加以下内容：

```java
server: 
  port: 8888 
spring: 
  cloud: 
    config: 
      server: 
        git: 
          uri: file:../.. 
```

端口号是配置服务器将在 HTTP 连接上监听配置请求的地方。

`spring.cloud.config.server.git.uri`的另一个属性是 Git 的位置，我们已经为开发配置了一个本地文件夹。这是 Git 应该在本地机器上运行的地方。如果不是，请在此文件夹上运行`git init`命令。

我们在这里不涵盖 Git 身份验证或加密。请查看 Spring Cloud Config 手册（[`spring.io/guides/gs/centralized-configuration/`](https://spring.io/guides/gs/centralized-configuration/)）了解更多详情。

1.  在`product.properties`文件中，我们将保存最初保存在实际`product`项目的`application.properties`文件中的属性。这些属性将由配置服务器加载。我们将从一个小属性开始，如下所示：

```java
testMessage=Hi There 
```

此属性文件应该存在于我们刚刚在上一步中引用的 Git 文件夹中。请使用以下命令将属性文件添加到 Git 文件夹中：

```java
git add product.properties and then commit.
```

1.  在应用程序的`resources`文件夹中创建一个`bootstrap.yml`文件，并输入此项目的名称：

```java
spring: 
  application: 
    name: configsvr 
```

1.  构建 Maven 项目，然后运行它。

1.  您应该看到一个`Tomcat started`消息，如下所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/a4aa6729-ccc4-4b69-9a14-a99dbe98bef7.png)`ConfigurationServiceApplication`已启动，并在端口`8888`上监听

让我们检查我们添加的属性是否可供使用。

打开浏览器，检查`product.properties`。有两种方法可以做到这一点。第一种是将属性文件视为 JSON，第二种是将其视为文本文件：

1.  `http://localhost:8888/product/default`:

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/a2e7f686-89d5-4e86-8cf4-b7daf8ae13c0.png)

1.  `http://localhost:8888/product-default.properties`:

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/23b88c7c-b0fe-44a4-8ca1-62516d6ec7c1.png)

如果您在想，默认是配置文件名称。Spring Boot 应用程序支持配置文件覆盖，例如，用于测试和用户验收测试（UAT）环境，其中可以用`product-test.properties`文件替换生产配置。因此，配置服务器支持以下形式的 URL 读取：`http://configsvrURL/{application}/{profile}`或`http://configsvrURL/{application-profile}.properties`或`.yml`。

在生产环境中，我们几乎不太可能直接访问配置服务器，就像之前展示的那样。将是客户端访问配置服务器；我们将在下面看到这一点。

# 配置客户端

我们将使用先前开发的`product`服务代码作为基线，开始将属性从应用程序中提取到配置服务器中。

1.  从 eclipse 中复制`product`服务项目，创建一个新的项目用于本章。

1.  将`spring-cloud-starter-config`依赖项添加到 POM 文件的依赖项列表中：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/2dd748c2-9e31-4aba-b8c0-67ffad5887eb.png)

1.  我们的主要工作将在资源上进行。告诉`product`服务使用运行在`http://localhost:8888`的配置服务器。

`failFast`标志表示如果找不到配置服务器，我们不希望应用程序继续加载。这很重要，因为它将确保`product`服务在找不到配置服务器时不应假定默认值：

```java
spring: 
  application: 
    name: product 

  cloud: 
    config: 
      uri: http://localhost:8888 
      failFast: true 
```

1.  将`product`服务的`resources`文件夹中的`application.properties`部分中的所有属性转移到我们在上一节中定义的`git`文件夹的`product.properties`中。

您的`product.properties`文件现在将具有有用的配置，除了我们之前放入进行测试的`Hi There`消息之外：

```java
server.port=8082 
eureka.instance.leaseRenewalIntervalInSeconds=15 
logging.level.org.hibernate.tool.hbm2ddl=DEBUG 
logging.level.org.hibernate.SQL=DEBUG 
testMessage=Hi There 
```

1.  现在可以删除`product`服务的`resources`文件夹中存在的`application.properties`文件。

1.  让我们向`product`服务添加一个测试方法，以检查从配置服务器设置的属性：

```java
    @Value("${testMessage:Hello default}") 
    private String message; 

   @RequestMapping("/testMessage") 
   String getTestMessage() { 
         return message ; 
   }
```

1.  启动 Eureka 服务器，就像在之前的章节中所做的那样。

1.  确保上一节中的配置服务器仍在运行。

1.  现在，从`ProductSpringApp`的主类开始启动`product`服务。在日志的开头，您将看到以下语句：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/90a0ed0d-cd2a-4bfe-a79c-5ba82e82a130.png)

当 ProductSpringApp 启动时，它首先从运行在 8888 端口的外部配置服务获取配置

在`bootstrap.yml`文件中，选择`name=product`的环境作为我们的应用程序名称。

`product`服务应该监听的端口号是从这个配置服务器中获取的，还有其他属性，比如我们现在将看到的测试消息：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/8d347e80-79b2-445a-99d5-7c95034216f5.png)`ProductSpringApp`在端口`8082`上启动，从外部化配置中获取。

使用以下两个 URL 测试应用程序：

+   `http://localhost:8082/testMessage`：这将返回我们配置的消息`Hi There`

运行其他 REST 服务之一，例如产品视图。您将看到所需的产品信息，以表明我们的服务正常运行。

+   `http://localhost:8082/product/1`：这将返回`{"id":1,"name":"Apples","catId":1}`

# 刷新属性

现在，如果您想要在所有服务上集中反映属性的更改，该怎么办？

1.  您可以将`product.properties`文件中的消息更改为新消息，例如`Hi Spring`。

1.  您会注意到配置服务器在下一次读取时接收到了这一更改，如下所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/9879ad35-2cef-452e-b850-506ab2f3d11c.png)

但是，该属性不会立即被服务接收，因为调用`http://localhost:8082/testMessage`会导致旧的`Hi There`消息。我们如何在命令行上刷新属性？

这就是执行器命令`/refresh`派上用场的地方。我们配置这些 bean 作为`@RefreshScope`注解的一部分。当从 Postman 应用程序执行`POST`方法调用`http://localhost:8082/refresh`时，这些 bean 将被重新加载。查看以下日志，以查看调用刷新会导致重新加载属性的结果：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/b15ea384-b8cd-4120-8087-a6660da3fc11.png)

第一行显示了`product`服务在执行`http://localhost:8082/refresh`时刷新其属性的日志

您可以查看，在标记线之后，属性加载重新开始，并在调用`http://localhost:8082/testMessage`后反映出消息。 

# 微服务前端

使用反向代理、负载均衡器、边缘网关或 API 网关来作为微服务的前端是一种流行的模式，复杂度逐渐增加。

+   **反向代理**：反向代理被定义为使下游资源可用，就好像它是自己发出的一样。在这方面，Web 服务器前端和应用服务器也充当反向代理。反向代理在云原生应用中非常有用，因为它确保客户端无需像我们在第二章中所做的那样查找服务然后访问它们。他们必须访问反向代理，反向代理查找微服务，调用它们，并使响应可用于客户端。

+   **负载均衡器**：负载均衡器是反向代理的扩展形式，可以平衡来自客户端的请求，使其分布在多个服务之间。这增加了服务的可用性。负载均衡器可以与服务注册表一起工作，找出哪些是活动服务，然后在它们之间平衡请求。Nginx 和 HAProxy 是可以用于微服务前端的负载均衡器的良好例子。

+   **边缘网关**：顾名思义，边缘网关是部署在企业或部门边缘的高阶组件，比负载均衡器具有更多功能，如身份验证、授权、流量控制和路由功能。Netfix Zuul 是这种模式的一个很好的例子。我们将在本节中介绍使用 Zuul 的代码示例。

+   **API 网关**：随着移动和 API 的流行，这个组件提供了更复杂的功能，比如将请求分发到多个服务之间进行编排，拦截和增强请求或响应，或转换它们的格式，对请求进行复杂的分析。也可以同时使用 API 网关和负载均衡器、反向代理或边缘在一个流中。这种方法有助于责任的分离，但也会因为额外的跳跃而增加延迟。我们将在后面的章节中看到 API 网关。

# Netflix Zuul

Netflix Zuul 是 Netflix 推广的一种流行的边缘网关，后来作为 Spring Cloud 的一部分提供。Zuul 意味着守门人，并执行所有这些功能，包括身份验证、流量控制，最重要的是路由，正如前面讨论的那样。它与 Eureka 和 Hystrix 很好地集成，用于查找服务和报告指标。企业或域中的服务可以由 Zuul 前端化。

让我们在我们的`product`服务前面放一个 Zuul 网关：

1.  创建一个新的 Maven 项目，并将其 artifact ID 设置为`zuul-server`。

1.  编辑 POM 文件并添加以下内容：

1. 将父级设置为`spring-boot-starter-parent`

2. 在`spring-cloud-starter-zuul`，`-eureka`和`-web`项目上设置依赖管理

3. 在`spring-cloud-starter-netflix`上设置依赖管理。

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/874b6f33-752e-4d1f-a421-1e97b627db71.png)

1.  创建一个带有注释以启用 Zuul 代理的应用程序类：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/19a8af5c-bdd0-4f89-8ab1-9fdc1b91353b.png)

`application.yml`中的配置信息对于 Zuul 非常重要。这是我们配置 Zuul 的路由能力以将其重定向到正确的微服务的地方。

1.  由于 Zuul 与 Eureka 的交互良好，我们将利用这一点：

```java
eureka: 
  client: 
    serviceUrl: 
defaultZone: http://127.0.0.1:8761/eureka/ 
```

这告诉 Zuul 在运行该端口的 Eureka 注册表中查找服务。

1.  将端口配置为`8080`。

1.  最后，配置路由。

这些是 REST 请求中 URL 到相应服务的映射：

```java
zuul: 
  routes: 
    product: 
      path: /product*/** 
      stripPrefix: false 
```

# 幕后发生了什么

让我们来看看幕后发生了什么：

1.  路由定义中的`product`部分告诉 Zuul，配置在`/product*/**`之后的路径应该被重定向到`product`服务，如果它在 Zuul 服务器中配置的 Eureka 注册表中存在。

1.  路径配置为`/product*/**`。为什么有三个`*`？如果您记得，我们的`product`服务可以处理两种类型的 REST 服务：`/product/1 GET`和`/product PUT`，`DELETE`，`POST`请求。`/products?id=1 GET`请求要求它返回给定类别 ID 的产品列表。因此，`product*`映射到 URL 中的`/product`和`/products`。

1.  `stripPrefix`的`false`设置允许`/product/`传递到`product`服务。如果未设置该标志，则仅在`/product*/`之后的 URL 的其余部分将传递给微服务。我们的`product`微服务包括`/product`，因此我们希望在转发到`product`服务时保留前缀。

# 一次性运行它们

现在让我们尝试运行我们的`product`服务，以及其他生态系统的其余部分：

1.  按照依赖关系的相反顺序启动服务。

1.  通过运行项目的主类或通过 Maven 启动配置服务器和 Eureka 服务器。

1.  启动`product`服务。

1.  启动 Zuul 服务。

观察日志窗口，并等待所有服务器启动。

1.  现在，在浏览器中运行以下请求：

+   `http://localhost:8080/product/3`

+   `http://localhost:8080/products?id=1`

您应该在第一个请求中看到产品`3`，在第二个请求中看到与类别`1`对应的产品。

让我们来看看 Zuul 和`product`服务的日志：

+   在 Zuul 中，您可以看到`/product*/**`的映射已经解析，并且从 Eureka 注册表中获取了指向`product`服务的端点：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/24bb51b3-7381-4e33-804a-df7c8fa71fdd.png)

Zuul 边缘现在已注册以映射对`product`服务的请求，并将其转发到 Eureka 指向的服务地址

+   在`product`服务中，通过在数据库上运行查询来执行服务：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/52c0c7ce-1671-49fe-8722-fd28fa7b3c6d.png)

# Kubernetes - 容器编排

到目前为止，我们一直在单独部署诸如 Eureka、配置服务器、`product`服务和 Zuul 等服务。

从上一章中可以看出，我们可以通过 CI（如 Jenkins）自动化部署它们。我们还看到了如何使用 Docker 容器进行部署。

然而，在运行时，容器仍然独立运行。没有机制来扩展容器，或者在其中一个容器失败时重新启动它们。此外，手动决定将哪个服务部署在哪个 VM 上，这意味着服务始终部署在静态 VM 上，而不是智能地混合部署。简而言之，管理我们应用服务的编排层缺失。

Kubernetes 是一种流行的编排机制，使部署和运行时管理变得更加容易。

# Kubernetes 架构和服务

Kubernetes 是由 Google 主导的开源项目。它试图实现一些在其内部容器编排系统 Borg 中实现的经过验证的想法。Kubernetes 架构由两个组件组成：主节点和从节点。主节点具有以下组件：

+   **控制器**：管理节点、副本和服务

+   **API 服务器**：提供`kubectl`客户端和从节点使用的 REST 端点

+   **调度程序**：决定特定容器必须生成的位置

+   **Etcd**：用于存储集群状态和配置

从节点包含两个组件：

+   **Kubelet**：与主节点通信资源可用性并启动调度程序指定的容器的代理

+   **代理**：将网络请求路由到 kubernetes 服务

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/5d4b9703-fa3e-4db5-a199-03ea0c786a63.png)

Kubernetes 是一个容器调度程序，使用两个基本概念，即 Pod 和 Service。Pod 是一组相关容器，可以使用特定的标签进行标记；服务可以使用这些标签来定位 Pod 并公开端点。以下图示了这个概念：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/41cab5e8-0a49-4c89-9726-46c9fd266bda.png)

Pods are considered ephemeral in kubernetes and may be killed. However, if the Pods were created using a `ReplicaSet`, where we can specify how many replicas or instances of a certain Pod have to be present in the system, then the kubernetes scheduler will automatically schedule new instances of the Pod and once the Pod becomes available, the service will start routing traffic to it. As you may notice that a Pod may be targeted by multiple services provided the labels match, this feature is useful to do rolling deployments.

我们现在将看看如何在 kubernetes 上部署一个简单的 API 并进行滚动升级。

# Minikube

Minikube 是一个项目，可以在虚拟机上运行一个工作的单节点 Kubernetes。

您可以按照以下说明安装 Minikube：[`github.com/kubernetes/minikube`](https://github.com/kubernetes/minikube)。

对于 Windows，请确保已完成以下步骤：

+   kubectl 二进制文件也需要下载并放置在路径中，以便一旦 Minikube 运行 kubernetes，我们可以从命令提示符通信和管理 kubernetes 资源。您可以从以下网址下载：[`storage.googleapis.com/kubernetes-release/release/v1.9.0/bin/windows/amd64/kubectl.exe.`](https://storage.googleapis.com/kubernetes-release/release/v1.9.0/bin/windows/amd64/kubectl.exe)

+   您必须从与`Users`目录位于同一驱动器（例如`C:`）上运行 Minikube。

# 在 Kubernetes 中运行产品服务

让我们将现有的`product`服务更改为通过 Kubernetes 容器编排运行：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/f01f2726-0de2-4bfd-87d7-0f8cf6e4e413.png)

1.  您可以通过运行它来测试配置是否有效，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/19de38b0-2e91-45bd-ae55-83c6ba149d05.png)

1.  设置 Docker 客户端以连接到在 Minikube VM 中运行的 Docker 守护程序，如下所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/84475ab0-4a51-42ae-b1e4-98c7e510e0b4.png)

1.  根据我们在前几章中创建 Docker 镜像的说明构建 Docker 镜像：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/d987e67b-6356-4a15-b07e-c2f3c3bb0399.png)

1.  创建一个`deployment`文件（请注意，`imagePullPolicy`设置为`never`，因为否则，Kubernetes 的默认行为是从 Docker 注册表中拉取）：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/30100249-a874-4443-ab31-f3181c8231c5.png)

1.  验证三个实例是否正在运行：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/91f1f85e-0fb3-41e5-ab63-c0c77010337a.png)

1.  创建一个`service.yml`文件，以便我们可以访问 Pods：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/0b2f2649-3ddf-42bd-aa5e-03d1c68cb9e8.png)

现在，按照以下方式运行`service.yml`文件：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/ef8eb953-aca4-49d1-b4be-74afbec0f24c.png)

现在，您可以获取服务的地址：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/d34e0441-3d00-4e5a-83b5-ca4fd0ba12fe.png)

现在，您可以访问 API，该 API 将路由请求到所有三个 Pod：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/92706603-f244-4aec-85a9-7ed96aa943e3.png)

您可以使用`-v`来获取以下详细信息的单个命令：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/ac351569-8874-4233-a5b9-c9c170c309e7.png)

1.  更改代码如下：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/5cccf822-15ce-4697-b58d-f8c4f8b289ea.png)

1.  使用新标签构建 Docker 镜像：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/de76ca1a-c146-4a34-a441-4f337b4f8b36.png)

1.  更新`deployment.yml`文件：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/29c79439-0779-47a2-902c-956032ec8497.png)

1.  应用更改：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/1ef3e6a9-e013-4f80-8ef7-2e97781e9176.png)

# 平台即服务（PaaS）

云原生应用程序的另一个流行运行时是使用 PaaS 平台，具体来说是应用程序 PaaS 平台。PaaS 提供了一种轻松部署云原生应用程序的方式。它们提供了额外的服务，如文件存储、加密、键值存储和数据库，可以轻松绑定到应用程序上。PaaS 平台还提供了一种轻松的机制来扩展云原生应用程序。现在让我们了解一下为什么 PaaS 平台为云原生应用程序提供了出色的运行时。

# PaaS 的案例

在运行时架构实现中，我们看到许多组件，例如配置服务器、服务注册表、反向代理、监控、日志聚合和指标，必须共同实现可扩展的微服务架构。除了`ProductService`中的业务逻辑外，其余的服务和组件都是纯粹的支持组件，因此涉及大量的平台构建和工程。

如果我们构建的所有组件都是作为服务提供的平台的一部分，会怎么样？因此，PaaS 是对容器编排的更高级抽象。PaaS 提供了我们在容器编排中讨论的所有基本基础设施服务，例如重新启动服务、扩展服务和负载平衡。此外，PaaS 还提供了补充开发、扩展和维护云原生应用程序的其他服务。这种方法的折衷之处在于它减少了在选择和微调组件方面的选择。然而，对于大多数专注于业务问题的企业来说，这将是一个很好的折衷。

因此，使用 PaaS，开发人员现在可以专注于编写代码，而不必担心他/她将部署在哪个基础设施上。所有的工程现在都变成了开发人员和运维团队可以配置的配置。

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/b373ec4d-7682-4bd1-b02e-ffad352f4447.png)

PaaS 的另外一些优势包括：

+   **运行时**：为开发人员提供各种运行时，如 Java、Go、Node.js 或.NET。因此，开发人员专注于生成部署，可以在 PaaS 环境提供的各种运行时中运行。

+   **服务**：PaaS 提供应用程序服务，如数据库和消息传递，供应用程序使用。这是有益的，因为开发人员和运营人员不必单独安装或管理它们。

+   **多云**：PaaS 将开发人员与基础架构（或 IaaS）抽象出来。因此，开发人员可以为 PaaS 环境开发，而不必担心将其部署在数据中心或各种云提供商（如 AWS、Azure 或 Google Cloud Platform）上，如果 PaaS 在这些基础设施上运行。这避免了对基础设施或云环境的锁定。

PaaS 环境的权衡是它们可能会限制并降低灵活性。默认选择的服务和运行时可能不适用于所有用例。然而，大多数 PaaS 提供商提供插入点和 API 来包含更多服务和配置，并提供策略来微调运行时行为，以减轻权衡。

# Cloud Foundry

Cloud Foundry 是 Cloud Foundry 基金会拥有的最成熟的开源 PaaS 之一。

它主要由以下部分组成：

+   **应用程序运行时**：开发人员部署 Java 或 Node.js 应用程序等应用程序工作负载的基础平台。应用程序运行时提供应用程序生命周期、应用程序执行和支持功能，如路由、身份验证、平台服务，包括消息传递、指标和日志记录。

+   **容器运行时**：容器运行的运行时抽象。这提供了基于 Kubernetes 的容器的部署、管理和集成，应用程序运行在其上，它基于 Kubo 项目。

+   **应用程序服务**：这些是应用程序绑定的数据库等服务。通常由第三方提供商提供。

+   **Cloud Foundry 组件**：有很多，比如 BOSH（用于容器运行时）、Diego（用于应用程序运行时）、**公告板系统**（**BBS**）、NATS、Cloud Controller 等等。然而，这些组件负责提供 PaaS 的各种功能，并可以从开发人员中抽象出来。它们与运营和基础设施相关且感兴趣。

# 组织、帐户和空间的概念

Cloud Foundry 具有详细的**基于角色的访问控制**（**RBAC**）来管理应用程序及其各种资源：

+   **组织**：这代表一个组织，可以将多个用户绑定到其中。一个组织共享应用程序、服务可用性、资源配额和计划。

+   **用户帐户**：用户帐户代表可以在 Cloud Foundry 中操作应用程序或操作的个人登录。

+   **空间**：每个应用程序或服务都在一个空间中运行，该空间绑定到组织，并由用户帐户管理。一个组织至少有一个空间。

+   **角色和权限**：属于组织的用户具有可以执行受限操作（或权限）的角色。详细信息已记录在：[`docs.cloudfoundry.org/concepts/roles.html`](https://docs.cloudfoundry.org/concepts/roles.html)。

# Cloud Foundry 实施的需求

在安装和运行原始 Cloud Foundry 中涉及了大量的工程工作。因此，有许多 PaaS 实现使用 Cloud Foundry 作为基础，并提供额外的功能，最流行的是 IBM 的 Bluemix、Redhat 的 OpenShift 和 Pivotal 的**Pivotal Cloud Foundry**（PCF）。

# Pivotal Cloud Foundry（PCF）

Pivotal 的 Cloud Foundry 旨在提高开发人员的生产力和运营效率，并提供安全性和可用性。

尽管本书的读者可以自由选择基于 Cloud Foundry 的 PaaS 实现，但我们选择 Pivotal 有几个原因：

+   Pivotal 一直以来都支持 Spring Framework，我们在书中广泛使用了它。Pivotal 的 Cloud Foundry 实现原生支持 Spring Framework 及其组件，如 Spring Boot 和 Spring Cloud。因此，我们创建的 Spring Boot 可部署文件可以直接部署到 Cloud Foundry 的应用运行时并进行管理。

+   Pivotal 的服务市场非常丰富，涵盖了大多数合作伙伴提供的平台组件，包括 MongoDB、PostgreSQL、Redis，以及 Pivotal 开发的 MySQL 和 Cloud Cache 的原生支持服务。

+   Pivotal 在这个领域进行了多次发布，因此服务提供频繁更新。

# PCF 组件

Pivotal 网站[pivotal.io/platform](https://pivotal.io/platform)提供了一个非常简单的 Cloud Foundry 实现图表，与我们之前的讨论相对应：

+   Pivotal 应用程序服务（PAS）：这是一个应用程序的抽象，对应于 Cloud Foundry 中的应用程序运行时。在内部，它使用 Diego，但这对开发人员来说是隐藏的。PAS 对 Spring Boot 和 Spring Cloud 有很好的支持，但也可以运行其他 Java、.NET 和 Node 应用程序。它适用于运行自定义编写的应用程序工作负载。

+   Pivotal 容器服务（PKS）：这是一个容器的抽象，与 Cloud Foundry 中的容器运行时相对应。它在内部使用 BOSH。它适用于运行作为容器提供的工作负载，即独立服务供应商（ISV）应用程序，如 Elasticsearch。

+   Pivotal Function Service（PFS）：这是 Pivotal 在 Cloud Foundry 平台之外的新产品。它提供了函数的抽象。它推动了无服务器计算。这些函数在 HTTP 请求（同步）或消息到达时（异步）被调用。

+   **市场**：这对应于 Cloud Foundry 中的应用程序服务。鉴于 PCF 的流行，市场上有很多可用的服务。

+   **共享组件**：这些包括运行函数、应用程序和容器所需的支持服务，如身份验证、授权、日志记录、监控（PCF watch）、扩展、网络等。

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/adf88116-bf09-47c7-94da-654596b2450f.jpg)

PCF 可以在包括 Google Compute Platform、Azure、AWS 和 Open Stack（IaaS）在内的大多数热门云上运行，并托管在数据中心。

虽然 PCF 及其组件非常适合服务器端负载，但对于在本地机器上构建软件的开发人员来说可能会很麻烦。我们现在就处于这个阶段。我们已经开发了`product`服务，并通过各个阶段成熟，以达到云原生运行时。

整个 PCF 及其运行时组件难以适应笔记本电脑进行开发。

# PCF Dev

PCF Dev 是一个精简的 PCF 发行版，可以在台式机或笔记本电脑上本地运行。它承诺能够在开发人员主要 PCF 环境上拥有相同的环境，因此当为 PCF Dev 设计的应用程序在主要 PCF 环境上运行时不会有任何差异。请参考[`docs.pivotal.io/pcf-dev/index.html`](https://docs.pivotal.io/pcf-dev/index.html)中的表格，了解 PCF Dev 与完整 PCF 和 Cloud Foundry（CF）提供的大小和功能的确切比较：

+   它支持 Java、Ruby、PHP 和 Python 的应用程序运行时。

+   它具有 PAS 的迷你版本，为我们迄今为止讨论的服务开发提供了必要的功能，如日志记录和指标、路由、Diego（Docker）支持、应用程序服务、扩展、监控和故障恢复。

+   它还内置了四个应用程序服务，它们是：Spring Cloud Services（SCS）、Redis、RabbitMQ 和 MySQL。

+   但是，它不适用于生产。它没有 BOSH，它在基础架构层上进行编排。

如果您的台式机/笔记本内存超过 8GB，磁盘空间超过 25GB，让我们开始吧。

# 安装

PCF Dev 可以在 Mac、Linux 或 Windows 环境中运行。按照说明，例如，[`docs.pivotal.io/pcf-dev/install-windows.html`](https://docs.pivotal.io/pcf-dev/install-windows.html) for Windows，来在您的机器上运行 PCF Dev。这基本上分为三个步骤：

+   获取 Virtual Box

+   CF 命令行界面

+   最后，PCF Dev

# 启动 PCF Dev

第一次使用 cf dev start 时，下载 VM 映像（4GB）、提取它（20GB），然后启动 PCF 的各种服务需要很长时间。因此，一旦 VM 下载并运行，我们将暂停和恢复带有 Cloud Foundry 服务的 VM。

启动 PCF Dev 的命令行选项如下：

1.  假设您有多核机器，您可以为该 VM 分配一半的核心，例如对于四核机器，可以使用`-c 2`。

1.  SCS 版本将使用 8GB 内存；为了保持缓冲区，让我们在命令行上使用以 MB 表示的 10GB 内存。

1.  在下一章中，我们将需要 MySQL 和 SCS 的服务。在内部，SCS 需要 RabbitMQ 来运行。因此，在运行实例时，让我们包括所有服务器。

1.  给出域和 IP 地址是可选的，因此我们将跳过`-d`和`-i`选项。

1.  将环境变量`PCFDEV_HOME`设置为具有足够空间的特定驱动器上的特定文件夹，以便它不会默认为主文件夹。我们建议主文件夹是像 SSD 这样的快速驱动器，因为 Cloud Foundry 的启动和停止操作非常 I/O 密集。

因此，我们的启动命令将如下所示：

```java
cf dev start -c 2 -s all -m 10000 
```

这将花费很长时间，直到您的 PCF Dev 环境准备就绪。

**加快开发时间**

每次启动整个 PCF Dev 环境时等待 20 分钟是很困难的。一旦您完成了当天的工作或在关闭笔记本电脑之前，您可以使用`cf dev suspend`来暂停 PCF Dev，并在第二天使用`cf dev resume`命令来恢复它。

其他有用的命令包括：

+   默认的 PCF Dev 创建了两个用户—admin 和 user。要安装或管理应用程序，您应该登录为其中一个用户。命令`cf dev target`会将您登录为默认用户。

+   `cf dev trust`命令安装证书以启用 SSL 通信，因此您无需每次在命令行或浏览器中的应用程序管理器上登录时使用参数`-skip ssl`。

+   `cf marketplace`命令（一旦您以用户身份登录）显示可以在组织和空间中安装的各种服务。

让我们看一下迄今为止讨论的命令的输出：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/46e17970-de5f-4b07-a292-77961ee32592.png)

正如我们在市场中看到的，由于我们使用了所有服务选项启动 PCF Dev，我们可以看到市场已准备好了七项服务。

# 在 PCF 上创建 MySQL 服务

从列表中，在本章中，我们将配置我们的`product`服务以与 MySQL 数据库一起工作，并在下一章中查看 Spring Cloud 服务，例如断路器仪表板和其他服务。

运行以下命令：

```java
cf create-service p-mysql 512mb prod-db 
```

检查服务是否正在运行：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/bcb84930-b49d-4642-b4a1-0f83e00a4ed1.png)

# 在 PCF Dev 上运行产品服务

让我们创建`product`服务的简化版本，它只是连接到我们之前创建的 MySQL 服务以运行查询。

您可以从第三章的练习代码*设计您的云原生应用程序*中编写练习代码，也可以从 Git 下载文件到您的 Eclipse 环境。值得注意的工件有：

+   在 Maven 文件中：

+   请注意，在下面的截图中，我们已将我们的工件重命名为`pcf-product`。

+   一个值得注意的新依赖是`spring-cloud-cloudfoundry-connector`。它发现了绑定到 Cloud Foundry 应用程序的服务，比如 MySQL 配置，并使用它们。

+   我们已经为 JPA 包含了一个 MySQL 连接器，用于连接到 MySQL 数据库：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/d4741437-8ef6-4cd0-9131-b22e87c22639.png)

+   在`application.properties`文件中：

+   请注意，我们没有提供任何 MySQL 连接属性，比如数据库、用户或密码。当应用程序上传到 Cloud Foundry 并与 MySQL 数据库服务绑定时，这些属性会被 Spring 应用程序自动获取。

+   在 MySQL 的自动创建设置中，仅在开发目的下应该为`true`，因为它会在每次应用程序部署时重新创建数据库。在 UAT 或生产配置文件中，此设置将为`none`：

```java
management.security.enabled=false
logging.level.org.hibernate.tool.hbm2ddl=DEBUG 
logging.level.org.hibernate.SQL=DEBUG 
spring.jpa.hibernate.ddl-auto=create 
```

+   `ProductSpringApp`类被简化为一个普通的 Spring Boot 启动应用程序。我们将在下一章中增强这一点，包括指标、查找、负载平衡、监控和管理：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/39007215-027d-4e62-be46-f8704956ab5c.png)

+   `ProductRepository`类只有一个名为`findByCatId`的方法。其余的方法，比如`get`、`save`、`delete`和`update`都是在存储库中自动派生的。

+   `ProductService`、`product`和其他类与第三章中的相同，*设计您的云原生应用程序*。

+   在`manifest.yml`文件中：

+   这是一个包含部署到云 Foundry 的说明的新文件

+   我们将编写最基本的版本，包括应用程序名称、分配 1GB 内存空间以及与 CloudFoundry 中的 MySQL 服务绑定

+   随机路由允许应用程序在没有冲突的情况下获取 URL 的路由，以防多个版本的情况发生：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/ea27a340-3fdf-41f8-84bd-a380bb139f74.png)

一旦项目准备好，运行`mvn install`来在`target`目录中创建全面的`.jar`文件。它的名称应该与`manifest.yml`文件中的`.jar`文件的名称匹配。

# 部署到 Cloud Foundry

部署到 Cloud Floundry 很简单，使用命令`cf push pcf-product`，如下所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/51738f77-7096-4b77-8a42-a027d0256861.png)

Cloud Foundry 在空间中创建应用程序、创建路由以到达应用程序，然后将各种服务与应用程序绑定时做了很多工作。如果你对底层发生的事情感兴趣，也许应该多了解一下 Cloud Foundry。

部署完成后，您将看到以下成功方法：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/61d3c1bf-dda6-43d5-bc43-9285ba8913b7.png)

注意在前面截图中生成的 URL。

它是`http://pcf-product-undedicated-spirketting.local.pcfdev.io`。我们将在下一章中看到如何缩短这个 URL。

如果在启动时出现错误，例如配置错误或缺少一些步骤，您可以通过在命令行中输入以下命令来查看日志：

```java
cf logs pcf-product --recent 
```

现在是时候测试我们的服务了。在浏览器窗口中，运行通常运行的两个服务：

+   `http://pcf-product-undedicated-spirketting.local.pcfdev.io/product/1`

+   `http://pcf-product-undedicated-spirketting.local.pcfdev.io/products?id=1`

您将看到来自数据库的响应，即输出和日志，如下所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/47e191d7-5992-4cff-ba9b-fffafa2822d3.png)

这完成了将我们简单的`product`服务部署到 PCF 上的 PCF Dev。

# 总结

在本章中，我们看到了支持云原生应用程序的各种运行时组件，并在各种运行时环境中运行了我们的应用程序，比如 Kubernetes 和 Cloud Foundry。

在下一章中，我们将在 AWS Cloud 上部署我们的服务。


# 第九章：平台部署 - AWS

在本章中，我们将介绍亚马逊 AWS 平台提供的一些部署选项。 AWS 平台是云服务提供商中最古老和最成熟的之一。它于 2002 年推出，并自那时以来一直是该领域的领导者。 AWS 还不断创新，并推出了几项新服务，这些服务在广泛的客户群中得到了广泛的采用，从单人创业公司到企业。

在本章中，我们将涵盖以下主题：

+   AWS 平台

+   AWS 平台部署选项

# AWS 平台

亚马逊 AWS 是云计算的先驱，并自那时起一直在扩展其云服务，以保持其领先地位。以下图表提供了 AWS 平台为应用程序开发人员提供的服务的指示性列表：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/efc34941-6e16-428a-a07d-c08cdc5dc74e.jpg)

这只是一个指示性列表，绝不是详尽的列表；请参阅亚马逊 AWS 门户网站获取完整列表。

类别如下：

+   基础设施：这可能是 AWS 平台的核心，使其能够提供大量其他服务。这些可以进一步分类为：

+   计算：诸如 EC2，Lambda，ECS 和 ELB 之类的服务。我们将演示使用主要计算服务部署我们的示例应用程序，但是将它们与 AWS 提供的其他服务相结合相对容易。

+   存储：诸如 S3，EBS 和 CloudFront 之类的服务。

+   网络：诸如 VPC，Route53 和 DirectConnect 之类的服务。

+   应用程序：这些服务可用作构建和支持应用程序的组件。

+   数据库：这些服务针对数据库，提供对不同的关系数据库管理系统（RDBMS）和 NoSQL 数据存储的访问。

+   DevOps：这些服务提供了构建流水线和启用持续交付的能力。这些包括源代码托管，持续集成工具以及云和软件供应工具。

+   安全性：这些服务为 AWS 提供了基于角色的访问控制（RBAC），并提供了一种机制来指定配额并强制执行它们，密钥管理和秘密存储。

+   移动：这些服务旨在为移动应用程序和通知等服务提供后端。

+   分析：这些服务包括 MapReduce 等批处理系统，以及 Spark 等流处理系统，可用于构建分析平台。

# AWS 平台部署选项

在 AWS 平台提供的各种服务中，我们将重点关注本章涵盖的一些部署选项，这些选项专门针对我们一直作为示例使用的 Web API 类型。因此，我们将介绍部署到以下内容：

+   AWS Elastic Beanstalk

+   AWS 弹性容器服务

+   AWS Lambda

由于我们将在云环境中运行应用程序，因此我们将不需要直接管理基础设施，也就是说，我们将不会启动虚拟机并在其中安装应用程序，因此我们将不需要服务发现，因为弹性负载均衡器将自动路由到所有正在运行的应用程序实例。因此，我们将使用不使用 Eureka 发现客户端的“产品”API 的版本：

```java
package com.mycompany.product;

 import org.springframework.boot.SpringApplication;
 import org.springframework.boot.autoconfigure.SpringBootApplication;

 @SpringBootApplication
 public class ProductSpringApp {

    public static void main(String[] args) throws Exception {
       SpringApplication.run(ProductSpringApp.class, args);
    }

 }
```

# 将 Spring Boot API 部署到 Beanstalk

AWS Elastic Beanstalk（AEB）是 AWS 提供的一项服务，可在 AWS 上托管 Web 应用程序，而无需直接提供或管理 IaaS 层。 AEB 支持流行的语言，如 Java，.NET，Python，Ruby，Go 和 PHP。最近，它还提供了运行 Docker 容器的支持。我们将采用我们迄今为止在旅程中构建的“产品”服务的简化版本，并将其部署在 AEB 中作为可运行的 JAR 文件，也作为 Docker 容器。

# 部署可运行的 JAR

登录到 AWS 控制台，选择计算类别下的弹性 Beanstalk 服务，并点击“开始”按钮：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/b572ac6b-6c97-4e58-a2b2-88e582e21ae1.png)

在下一个屏幕中填写应用程序详细信息：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/560dd240-24b2-400f-a8a6-c83ad680c952.png)

上传`target`文件夹中的`product.jar`，然后点击“配置更多选项”按钮。您将看到不同的类别，可以通过选择软件，在环境属性下，添加一个名为`SERVER_PORT`的新环境变量，并将值设置为`5000`。这是必要的，因为默认情况下，AEB 环境创建的 NGINX 服务器将代理所有请求到这个端口，通过设置变量，我们确保我们的 Spring Boot 应用将在端口`5000`上运行：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/39e95de8-1379-47e4-a8d0-2455339e0eb3.png)

现在，AWS 将提供一个新的环境，我们的应用程序将在其中运行：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/c31356a5-b7c7-4e21-ab0d-4a3a5e0158a7.png)

环境创建完成后，AEB 将为应用程序生成一个 URL：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/1bebd5f7-5986-40b7-b578-f6fe06d55583.png)

我们可以使用此 URL 访问 API 端点：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/2451c2fd-4a87-4755-94d3-544a8d0996f4.png)

# 部署 Docker 容器

现在我们已经学会了如何将可运行的 JAR 部署到弹性 Beanstalk 服务，让我们也看一下相同的变体，我们将部署运行相同应用程序的 Docker 容器。使用 Docker 容器的优势在于，我们可以使用 AWS 弹性 Beanstalk 服务尚未支持的语言和平台，并且仍然可以在云中部署它们，从而获得该服务提供的好处。

对于此部署，我们将使用**弹性容器服务**（**ECS**）提供的 Docker 注册表来存储我们从应用程序构建的 Docker 容器。当我们部署到 ECS 时，我们将介绍如何将本地 Docker 容器推送到 ECS 存储库。现在，让我们假设我们要部署的 Docker 容器在名为`<aws-account-id>.dkr.ecr.us-west-2.amazonaws.com/product-api`的存储库中可用。由于我们需要访问此存储库，我们需要将 AmazonEC2ContainerRegistryReadOnly 策略添加到默认的弹性 Beanstalk 角色 aws-elasticbeanstalk-ec2-role。

这可以在 IAM 控制台的角色部分完成：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/df0c9e42-5a70-4c5d-815e-458437dfef96.png)

创建一个名为`Dockerfile.aws.json`的文件，内容如下：

```java
{ 
  "AWSEBDockerrunVersion": "1", 
  "Image": { 
    "Name": "<aws-account-id>.dkr.ecr.us-west-2.amazonaws.com/product-api", 
    "Update": "true" 
  }, 
  "Ports": [ 
    { 
      "ContainerPort": "8080" 
    } 
  ] 
} 
```

现在我们准备部署我们的 Docker 容器。在弹性 Beanstalk 控制台中，我们将选择单个 Docker 容器而不是 Java，并创建一个新的应用程序：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/8a07d769-e612-486c-8d5e-9d1619d4d81a.png)

选择并上传`Dockerfile.aws.json`以创建环境：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/db25cea9-3dd0-4102-8643-40ef14503fe7.png)

我们可以测试我们的 API 端点，以验证我们的 Docker 容器是否正常运行。我们还可以配置容器使用 Amazon CloudWatch 日志记录和监控，以更好地监视我们的应用程序：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/72b589b2-40fd-439c-aaee-774137effd99.png)

# 将 Spring Boot 应用程序部署到弹性容器服务

AWS **弹性容器服务**（**ECS**）是一项允许用户使用托管的 Docker 实例部署应用程序的服务。在这里，AWS ECS 服务负责提供虚拟机和 Docker 安装。我们可以通过以下步骤部署我们的应用程序：

1.  启动 ECS，点击“继续”：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/9c5dd2c2-6787-4539-91ca-bdb9b28e8b9f.png)

1.  创建名为`product-api`的 ECS 存储库，然后点击“下一步”：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/2be15da6-f07b-4c03-9688-e1148fc1d326.png)

1.  构建并推送 Docker 容器到存储库，按照屏幕上给出的说明进行：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/a35fb748-ff23-4d25-b394-590ea2f14536.png)

1.  GUI 生成的 Docker 登录命令多了一个`http://`，应该去掉：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/e843f488-de3c-4c27-9d49-c59bc9ad4c70.png)

1.  我们现在可以构建并推送 Docker 容器到创建的存储库：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/e8072215-a0ca-40b5-9e1c-8a015e9d383b.png)

1.  在配置任务定义时，我们将使用此容器存储库：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/39e6452a-6c6f-485b-b71c-f4fb03a62bcd.png)

1.  在高级选项中，我们可以配置 AWS CloudWatch 日志记录，以捕获来自 Docker 容器的日志，在存储和日志记录部分下：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/7a1d2053-56e2-4371-8b5a-5100beb71a59.png)

1.  我们需要在 CloudWatch 控制台中创建相应的日志组，以捕获从我们的应用程序创建的日志：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/302e0cad-c1ff-4f58-ad4b-e635e80d89a9.png)

1.  我们可以创建一个服务映射到容器中公开的端口，即`8080：`

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/16a2d1fc-b921-41d6-8b8f-e987a1201dff.png)

1.  可选地，我们可以描绘 EC2 实例类型并配置密钥对，以便我们能够登录到 ECS 将为我们的应用程序创建的 EC2 实例中：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/b96f9480-7312-4b84-9a4d-79e12335d242.png)

1.  一旦我们审查配置并提交，ECS 将开始创建 EC2 实例并将我们的应用程序部署到其中：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/bd112413-b82d-47df-add8-b3c08c6bd29c.png)

1.  我们可以点击自动扩展组并找到已启动的实例：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/8be45561-dffd-4b6a-873e-e73cf39ff2cc.png)

1.  找到实例：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/66100781-e44f-4520-b946-4bc202fc41fa.png)

1.  找到实例主机名：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/eecd2566-2434-4c5a-ba2d-4e70088f4358.png)

1.  通过实例主机名访问应用程序：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/d76205d8-b879-47e8-a636-a304f16d3050.png)

但是逐个通过它们的主机名访问应用程序是不可行的，因此，我们将创建一个弹性负载均衡器，它将路由请求到实例，从而允许我们在扩展或缩减时拥有稳定的端点：

1.  我们将转到 EC2 控制台，并在应用程序负载均衡器下选择创建：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/93c7bf88-f0f4-4a01-a16e-54f6b6baa465.png)

1.  配置负载均衡器端口：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/4a349305-fd46-46b9-b707-cd4ef596de84.png)

1.  配置目标组和健康检查端点：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/570e525d-cd1c-419d-b3e0-19e5713b62ba.png)

1.  将目标实例注册到我们的集群定义创建的实例：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/0dc9ccdb-c7b7-4bb6-8b7b-7cd70c4b5b05.png)

1.  找到负载均衡器的 DNS 记录：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/21b3b419-d99c-4c84-8884-989aa0532e6f.png)

1.  连接到负载均衡器端点并验证应用程序是否正常工作：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/25bb98e1-320c-4504-953d-0bbc2c88468f.png)

# 部署到 AWS Lambda

AWS Lambda 服务允许部署简单函数以在事件触发器上调用。这些事件触发器可以分为四种类型，即：

+   数据存储（例如，AWS DyanmoDB）

+   队列和流（例如，AWS Kinesis）

+   Blob 存储（例如，AWS S3）

+   API 数据门户：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/bc0e31ba-40c8-477a-a75a-ced5421df4fd.jpg)

AWS Lamda 支持的事件源的完整列表可以在[`docs.aws.amazon.com/lambda/latest/dg/invoking-lambda-function.html#api-gateway-with-lambda.`](https://docs.aws.amazon.com/lambda/latest/dg/invoking-lambda-function.html#api-gateway-with-lambda)找到

与之前讨论的其他部署选项不同，AWS Lambda 提供了最透明的扩展选项，AWS 平台根据需求自动扩展所需的实例。我们无需配置实例、负载均衡器等，而是可以专注于应用程序逻辑。

我们现在将构建一个简单的 AWS Lambda 函数，并将其绑定到 API 端点以调用它。

我们将首先创建一个新的 Spring Boot 应用程序，具有以下依赖项。我们还将使用`maven-shade-plugin`创建可运行的 JAR：

```java
<project  
          xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
   <modelVersion>4.0.0</modelVersion>
   <groupId>com.mycompany</groupId>
   <artifactId>hello-lambda</artifactId>
   <version>0.0.1-SNAPSHOT</version>

   <dependencies>
     <dependency>
       <groupId>junit</groupId>
       <artifactId>junit</artifactId>
       <version>4.12</version>
       <scope>test</scope>
     </dependency>
     <dependency>
       <groupId>com.amazonaws</groupId>
       <artifactId>aws-lambda-java-core</artifactId>
       <version>1.1.0</version>
     </dependency>
     <dependency>
       <groupId>com.amazonaws</groupId>
       <artifactId>aws-lambda-java-events</artifactId>
       <version>2.0.1</version>
     </dependency>
     <dependency>
       <groupId>com.amazonaws</groupId>
       <artifactId>aws-lambda-java-log4j2</artifactId>
       <version>1.0.0</version>
     </dependency>
   </dependencies>

   <build>
     <finalName>hello-lambda</finalName>
     <plugins>
       <plugin>
         <groupId>org.apache.maven.plugins</groupId>
         <artifactId>maven-compiler-plugin</artifactId>
         <configuration>
           <source>1.8</source>
           <target>1.8</target>
         </configuration>
       </plugin>
       <plugin>
         <groupId>org.apache.maven.plugins</groupId>
         <artifactId>maven-shade-plugin</artifactId>
         <version>3.0.0</version>
         <configuration>
           <createDependencyReducedPom>false</createDependencyReducedPom>
         </configuration>
         <executions>
           <execution>
             <phase>package</phase>
             <goals>
               <goal>shade</goal>
             </goals>
           </execution>
         </executions>
       </plugin>
     </plugins>
   </build>

 </project>
```

现在创建`HelloHandler.java`，内容如下：

```java
package com.mycompany;

 import com.amazonaws.services.lambda.runtime.Context;
 import com.amazonaws.services.lambda.runtime.RequestHandler;
 import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
 import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;

 import java.net.HttpURLConnection;

 public class HelloHandler implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

   @Override
   public APIGatewayProxyResponseEvent handleRequest(APIGatewayProxyRequestEvent request, Context context) {
     String who = "World";
     if ( request.getPathParameters() != null ) {
       String name  = request.getPathParameters().get("name");
       if ( name != null && !"".equals(name.trim()) ) {
         who = name;
       }
     }
     return new APIGatewayProxyResponseEvent().withStatusCode(HttpURLConnection.HTTP_OK).withBody(String.format("Hello %s!", who));
   }

 }
```

由于 lambda 函数是简单的函数，我们可以通过使用函数的输入和输出很容易地测试它们。例如，一个示例测试用例可能是：

```java
package com.mycompany;

 import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
 import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
 import org.junit.Before;
 import org.junit.Test;
 import org.junit.runner.RunWith;
 import org.junit.runners.BlockJUnit4ClassRunner;

 import java.util.Collections;
 import java.util.HashMap;
 import java.util.Map;

 import static org.junit.Assert.*;

 @RunWith(BlockJUnit4ClassRunner.class)
 public class HelloHandlerTest {

   HelloHandler handler;
   APIGatewayProxyRequestEvent input;
   @Before
   public void setUp() throws Exception {
     handler = new HelloHandler();
     Map<String, String> pathParams = new HashMap<>();
     pathParams.put("name", "Universe");
     input = new APIGatewayProxyRequestEvent().withPath("/hello").withPathParamters(pathParams);
   }

   @Test
   public void handleRequest() {
     APIGatewayProxyResponseEvent res = handler.handleRequest(input, null);
     assertNotNull(res);
     assertEquals("Hello Universe!", res.getBody());
   }
   @Test
   public void handleEmptyRequest() {
     input.withPathParamters(Collections.emptyMap());
     APIGatewayProxyResponseEvent res = handler.handleRequest(input, null);
     assertNotNull(res);
     assertEquals("Hello World!", res.getBody());
   }
 }
```

现在我们可以使用 Maven 构建 lambda 函数：

```java
$ mvn clean package 
[INFO] Scanning for projects... 
[WARNING] 
[WARNING] Some problems were encountered while building the effective model for com.mycompany:hello-lambda:jar:0.0.1-SNAPSHOT 
[WARNING] 'build.plugins.plugin.version' for org.apache.maven.plugins:maven-compiler-plugin is missing. @ line 35, column 15 
[WARNING] 
[WARNING] It is highly recommended to fix these problems because they threaten the stability of your build. 
[WARNING] 
[WARNING] For this reason, future Maven versions might no longer support building such malformed projects. 
[WARNING] 
[INFO] 
[INFO] ------------------------------------------------------------------------ 
[INFO] Building hello-lambda 0.0.1-SNAPSHOT 
[INFO] ------------------------------------------------------------------------ 
[INFO] 
[INFO] --- maven-clean-plugin:2.5:clean (default-clean) @ hello-lambda --- 
[INFO] Deleting /Users/shyam/workspaces/msa-wsp/CloudNativeJava/chapter-09/hello-lambda/target 
[INFO] 
[INFO] --- maven-resources-plugin:2.6:resources (default-resources) @ hello-lambda --- 
[WARNING] Using platform encoding (UTF-8 actually) to copy filtered resources, i.e. build is platform dependent! 
[INFO] skip non existing resourceDirectory /Users/shyam/workspaces/msa-wsp/CloudNativeJava/chapter-09/hello-lambda/src/main/resources 
[INFO] 
[INFO] --- maven-compiler-plugin:3.1:compile (default-compile) @ hello-lambda --- 
[INFO] Changes detected - recompiling the module! 
[WARNING] File encoding has not been set, using platform encoding UTF-8, i.e. build is platform dependent! 
[INFO] Compiling 1 source file to /Users/shyam/workspaces/msa-wsp/CloudNativeJava/chapter-09/hello-lambda/target/classes 
[INFO] 
[INFO] --- maven-resources-plugin:2.6:testResources (default-testResources) @ hello-lambda --- 
[WARNING] Using platform encoding (UTF-8 actually) to copy filtered resources, i.e. build is platform dependent! 
[INFO] skip non existing resourceDirectory /Users/shyam/workspaces/msa-wsp/CloudNativeJava/chapter-09/hello-lambda/src/test/resources 
[INFO] 
[INFO] --- maven-compiler-plugin:3.1:testCompile (default-testCompile) @ hello-lambda --- 
[INFO] Changes detected - recompiling the module! 
[WARNING] File encoding has not been set, using platform encoding UTF-8, i.e. build is platform dependent! 
[INFO] Compiling 1 source file to /Users/shyam/workspaces/msa-wsp/CloudNativeJava/chapter-09/hello-lambda/target/test-classes 
[INFO] 
[INFO] --- maven-surefire-plugin:2.12.4:test (default-test) @ hello-lambda --- 
[INFO] Surefire report directory: /Users/shyam/workspaces/msa-wsp/CloudNativeJava/chapter-09/hello-lambda/target/surefire-reports 

------------------------------------------------------- 
 T E S T S 
------------------------------------------------------- 
Running com.mycompany.HelloHandlerTest 
Tests run: 2, Failures: 0, Errors: 0, Skipped: 0, Time elapsed: 0.055 sec 

Results : 

Tests run: 2, Failures: 0, Errors: 0, Skipped: 0 

[INFO] 
[INFO] --- maven-jar-plugin:2.4:jar (default-jar) @ hello-lambda --- 
[INFO] Building jar: /Users/shyam/workspaces/msa-wsp/CloudNativeJava/chapter-09/hello-lambda/target/hello-lambda.jar 
[INFO] 
[INFO] --- maven-shade-plugin:3.0.0:shade (default) @ hello-lambda --- 
[INFO] Including com.amazonaws:aws-lambda-java-core:jar:1.1.0 in the shaded jar. 
[INFO] Including com.amazonaws:aws-lambda-java-events:jar:2.0.1 in the shaded jar. 
[INFO] Including joda-time:joda-time:jar:2.6 in the shaded jar. 
[INFO] Including com.amazonaws:aws-lambda-java-log4j2:jar:1.0.0 in the shaded jar. 
[INFO] Including org.apache.logging.log4j:log4j-core:jar:2.8.2 in the shaded jar. 
[INFO] Including org.apache.logging.log4j:log4j-api:jar:2.8.2 in the shaded jar. 
[INFO] Replacing original artifact with shaded artifact. 
[INFO] Replacing /Users/shyam/workspaces/msa-wsp/CloudNativeJava/chapter-09/hello-lambda/target/hello-lambda.jar with /Users/shyam/workspaces/msa-wsp/CloudNativeJava/chapter-09/hello-lambda/target/hello-lambda-0.0.1-SNAPSHOT-shaded.jar 
[INFO] ------------------------------------------------------------------------ 
[INFO] BUILD SUCCESS 
[INFO] ------------------------------------------------------------------------ 
[INFO] Total time: 2.549 s 
[INFO] Finished at: 2018-02-12T13:52:14+05:30 
[INFO] Final Memory: 25M/300M 
[INFO] ------------------------------------------------------------------------ 
```

我们现在已经构建了`hello-lambda.jar`，我们将上传到 AWS 控制台中创建的 AWS Lambda 函数。

1.  我们将首先转到 API Gateway 控制台，该控制台出现在 AWS 控制台的网络和内容交付类别中，并创建一个新的 API：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/334bc46e-e18e-404b-88d5-dc128fed3166.png)

1.  我们将为路径`/hello`添加一个名为`hello`的新资源：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/fa8a523f-d9d8-4c20-b099-165ea8f92079.png)

1.  我们还将创建一个带有路径参数的子资源：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/f55c4fd3-9201-4afb-844b-5b0b314462ae.png)

1.  现在，我们将附加 HTTP `GET`方法：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/8ceae71e-6427-4b32-8373-2ea5946d2b3a.png)

1.  创建一个具有以下详细信息的 Lambda 函数：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/fde71ba7-3782-4c20-b3e3-fc912d621c42.png)

1.  上传可运行的 JAR 并设置处理程序方法：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/36753b3c-d25b-4226-9c6d-54ecd4efa730.png)

1.  现在将此 Lambda 函数添加到 API 方法中：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/8d953143-4597-431a-ad81-ade0d5a06fde.png)

1.  确保选择使用 Lambda 代理集成，以便我们可以使用特定的`RequestHandler`接口，而不是使用通用的`RequestStreamHandler`。这也将使 API Gateway 获得对 Lambda 函数的权限：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/aba7b22e-dfa9-4368-b3bc-978479ca4ea9.png)

1.  使用 Lambda 函数调用完成 API 定义：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/a9a15393-71ec-4d46-a7e5-77d41ab348a6.png)

1.  我们可以从控制台测试 API 端点：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/400e475d-1e2c-451a-8ff9-01a6f1ff1f2e.png)

1.  现在我们可以部署 API：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/d90a2915-d03f-4fa9-ad68-97edba4fa417.png)

1.  成功部署 API 将导致 API 端点：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/439bb781-b264-4f30-9f52-5a81dff1e1aa.png)

1.  现在我们可以使用为此部署环境生成的 API 端点来访问应用程序：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/c2afc5c0-6922-48c9-8f82-1cde13ab4ed5.png)

# 总结

在本章中，我们介绍了 AWS 平台提供的一些选项，以及我们如何可以从弹性 Beanstalk 部署我们的应用程序，这是针对 Web 应用程序的。我们部署到 ECS，用于部署容器化工作负载，不限于 Web 应用程序工作负载。然后，我们部署了一个 AWS Lambda 函数，无需配置底层硬件。在接下来的章节中，我们将看一下使用 Azure 进行部署，以了解它为部署云原生应用程序提供的一些服务。


# 第十章：平台部署 - Azure

本章讨论了 Azure 的应用程序设计和部署——这是微软的公共云平台。云原生开发的本质是能够将您的应用程序与云提供商提供的 PaaS 平台集成。作为开发人员，您专注于创造价值（解决客户问题），并允许云提供商为您的应用程序的基础设施进行繁重的工作。

在本章中，我们将学习以下内容：

+   Azure 提供的不同类别的 PaaS 服务。我们将深入研究将被我们的样例应用程序使用的服务。

+   将我们的样例应用程序迁移到 Azure，并了解各种可用选项。我们还将评估所有选项，并了解每个选项的利弊。

我们正在介绍 Azure 平台，目的是展示如何构建和部署应用程序。我们不打算深入研究 Azure，并期望读者使用 Azure 文档（[`docs.microsoft.com/en-us/azure/`](https://docs.microsoft.com/en-us/azure/)）来探索其他选项。

Azure 支持多种编程语言，但出于本书的目的，我们将关注 Azure 对 Java 应用程序的支持。

# Azure 平台

Azure 提供了越来越多的 PaaS 和 IaaS，涵盖了各种技术领域。对于我们的目的，我们将关注直接适用于我们应用程序的子集领域和服务。

为了方便使用，我已经在最相关的技术领域中创建了这个服务分类模型：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/0be37779-2ac3-4fe6-b8b0-0177c19149f4.jpg)

*这只是一个指示性列表，绝不是一个详尽的列表。请参考 Azure 门户以获取完整列表。*

在前述分类模型中，我们将服务分为以下领域：

+   **基础设施**：这是 Azure 提供的一系列服务，用于部署和托管我们的应用程序。我们已经将计算、存储和网络等服务结合在这个类别中。为了我们样例 Java 应用程序的目的，我们将研究以下一系列服务。

+   **应用服务**：我们如何将现有的 Spring Boot 应用程序部署到我们的 Azure 平台？这更像是一个搬迁和部署的场景。在这里，应用程序没有重构，但依赖项被部署在应用服务上。使用其中一个数据库服务，应用程序可以被部署和托管。Azure 提供了 PostgreSQL 和 MySQL 作为托管数据库模型，还有其他各种选项。

+   **容器服务**：对于打包为 Docker 容器的应用程序，我们可以探索如何将 Docker 容器部署到平台上。

+   **函数**：这是无服务器平台模型，您无需担心应用程序的托管和部署。您创建一个函数，让平台为您进行繁重的工作。截至目前，基于 Java 的 Azure 云函数处于测试阶段。我们将探讨如何在开发环境中创建一个函数并进行本地测试。

+   **服务布局**：服务布局是一个用于部署和管理微服务和容器应用程序的分布式系统平台。我们将探讨如何在服务布局中部署我们的样例“产品”API。

+   **应用程序**：这是一个帮助构建分布式应用程序的服务列表。随着我们转向分布式微服务模型，我们需要解耦我们的应用程序组件和服务。队列、事件中心、事件网格和 API 管理等功能有助于构建一组稳健的 API 和服务。

+   **数据库**：这是 Azure 平台提供的数据存储选项列表。其中包括关系型、键值、Redis 缓存和数据仓库等。

+   **DevOps**：对于在云中构建和部署应用程序，我们需要强大的 CI/CD 工具集的支持。Visual Studio 团队服务用于托管代码、问题跟踪和自动构建。同样，开源工具在 Azure 门户中仍然不是一流的公民。您可以随时使用所需软件的托管版本。

+   **安全**：云应用程序的另一个关键因素是安全服务。在这一领域，提供了 Active Directory、权限管理、密钥保管库和多重身份验证等关键服务。

+   **移动**：如果您正在构建移动应用程序，该平台提供了关键服务，如移动应用程序服务、媒体服务和移动参与服务等。

+   **分析**：在分析领域，该平台通过 HDInsight 和数据湖服务提供了 MapReduce、Storm、Spark 等领域的强大服务，用于分析和数据存储库。

此外，Azure 还提供了多个其他技术领域的服务——**物联网**（**IoT**）、监控、管理、**人工智能**（**AI**）以及认知和企业集成领域。

# Azure 平台部署选项

正如我们在前一节中看到的，Azure 提供了许多选项来构建和部署平台上的应用程序。我们将使用我们的“产品”API REST 服务的示例来检查 Azure 提供的各种选项，以部署和运行我们的应用程序。

在我们开始之前，我假设您熟悉 Azure 平台，并已经在门户中注册。

Azure 支持多种编程语言，并提供 SDK 以支持各自领域的开发。对于我们的目的，我们主要探索 Azure 平台内对 Java 应用程序的支持。

我们将在以下四个领域探索应用程序托管服务：

+   应用服务

+   容器服务

+   服务织物

+   功能

有关更多详细信息和入门，请参考以下链接：[`azure.microsoft.com/en-in/downloads/`](https://azure.microsoft.com/en-in/downloads/)。

# 将 Spring Boot API 部署到 Azure 应用服务

在本节中，我们将把我们的“产品”API 服务迁移到 Azure 应用服务。我们将查看应用程序为满足 Azure 应用服务的要求所做的额外更改。

我已经拿取了我们在第三章中构建的“产品”API REST 服务，*设计您的云原生应用程序*。在服务中，我们做出以下更改：

在项目的根文件夹中添加一个名为`web.config`的文件：

```java
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>
    <handlers>
      <add name="httpPlatformHandler" path="*" verb="*" 
       modules="httpPlatformHandler" resourceType="Unspecified"/>
    </handlers>
    <httpPlatform processPath="%JAVA_HOME%binjava.exe"
     arguments="-Djava.net.preferIPv4Stack=true -            
     Dserver.port=%HTTP_PLATFORM_PORT% -jar &quot;
     %HOME%sitewwwrootproduct-0.0.1-SNAPSHOT.jar&quot;">
    </httpPlatform>
  </system.webServer>
</configuration>
```

文件添加了以下更改，`product-0.0.1-SNAPSHOT.jar`，这是我们应用程序的包名称。如果您的应用程序名称不同，您将需要进行更改。

我们首先检查这里的“产品”API 代码：[`azure.microsoft.com/en-in/downloads/`](https://azure.microsoft.com/en-in/downloads/)。

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/698bfbdf-e24d-4703-83cb-1b21d38d35d6.png)

我们运行`mvn clean package`命令将项目打包为一个 fat JAR：

```java
[INFO] Scanning for projects... 
[INFO]                                                                          
[INFO] ------------------------------------------------------------------------ 
[INFO] Building product 0.0.1-SNAPSHOT 
[INFO] ------------------------------------------------------------------------ 
[INFO]  
[INFO] ...... 
[INFO]  
[INFO] --- maven-jar-plugin:2.6:jar (default-jar) @ product --- 
[INFO] Building jar: /Users/admin/Documents/workspace/CloudNativeJava/ch10-product/target/product-0.0.1-SNAPSHOT.jar 
[INFO]  
[INFO] --- spring-boot-maven-plugin:1.4.3.RELEASE:repackage (default) @ product --- 
[INFO] ------------------------------------------------------------------------ 
[INFO] BUILD SUCCESS 
[INFO] ------------------------------------------------------------------------ 
[INFO] Total time: 14.182 s 
[INFO] Finished at: 2018-01-15T15:06:56+05:30 
[INFO] Final Memory: 40M/353M 
[INFO] ------------------------------------------------------------------------ 
```

接下来，我们登录到 Azure 门户（[`portal.azure.com/`](https://portal.azure.com/)）。

1.  在左侧列中单击“应用服务”菜单项，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/5c64f4a0-c9ab-449a-b532-60689a27ebee.png)

在 Azure 门户中选择应用服务

1.  单击“添加”链接：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/e6202b0e-c4fd-4cfa-a12d-ee7ccaea74c1.png)

1.  接下来，单击所示的“Web 应用”链接：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/57ceb8b3-0323-43aa-a803-952ff68d76b0.png)

通过 Azure 门户 | 应用服务 | 添加导航选择 Web 应用。

1.  单击“创建”按钮链接，您应该会看到以下页面

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/96ccf874-4146-47f3-a6ab-61dea5d877f9.png)

1.  我们填写我们的“产品”API 的详细信息。我已经填写了应用程序名称为`ch10product`，并将其他选项保留为默认。

1.  接下来，单击页面底部的“创建”按钮。

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/528a954f-768a-4c27-b9bf-621c7a73c88a.png)

这将创建应用服务。

1.  我们点击 App Services 下的`ch10product`，这将带我们到菜单：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/0b09eccf-5511-4d37-afbc-0dccd115d72d.png)

1.  注意部署应用程序的 URL 和 FTP 主机名。我们需要在两个地方进行更改——应用程序设置和部署凭据：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/9ee26222-3971-4748-9a66-eb98829c466e.png)

1.  我们点击“应用程序设置”链接，并在下拉菜单中选择以下选项：

1.  选择 Java 8 作为 Java 版本

1.  选择 Java 次要版本为最新

1.  选择最新的 Tomcat 9.0 作为 Web 容器（实际上不会使用此容器；Azure 使用作为 Spring Boot 应用程序一部分捆绑的容器。）

1.  点击保存

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/4f3d3759-f319-4833-8895-7cb58e3e9f81.png)

1.  接下来，我们点击左侧的“部署凭据”链接。在这里，我们捕获 FTP/部署用户名和密码，以便能够将我们的应用程序推送到主机，并点击保存，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/58881a11-bdbb-4016-af39-bc577133c1e6.png)

1.  连接到我们在*步骤 8*中看到的 FTP 主机名，并使用*步骤 10*中保存的凭据登录：

```java
ftp  
open ftp://waws-prod-dm1-035.ftp.azurewebsites.windows.net 
user ch10productwrite2munish 
password *******
```

1.  接下来，我们切换到远程服务器上的`site/wwwroot`目录，并将 fat JAR 和`web.config`传输到该文件夹：

```java
cd site/wwwroot 
put product-0.0.1-SNAPSHOT.jar 
put web.config 
```

1.  我们返回到概述部分并重新启动应用程序。我们应该能够启动应用程序并看到我们的 REST API 正常工作。

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/e713d0dd-11a7-45b5-8ed9-c05e45d445be.png)

在本节中，我们看到了如何将现有的 REST API 应用程序部署到 Azure。这不是部署的最简单和最佳方式。这个选项更多的是一种搬迁，我们将现有的应用程序迁移到云中。对于部署 Web 应用程序，Azure 提供了一个 Maven 插件，可以直接将您的应用程序推送到云中。有关更多详细信息，请参阅以下链接：[`docs.microsoft.com/en-in/java/azure/spring-framework/deploy-spring-boot-java-app-with-maven-plugin`](https://docs.microsoft.com/en-in/java/azure/spring-framework/deploy-spring-boot-java-app-with-maven-plugin)。

REST API 部署在 Windows Server VM 上。Azure 正在增加对 Java 应用程序的支持，但它们的长处仍然是.NET 应用程序。

如果您想使用 Linux 并部署 REST API 应用程序，您可以选择使用基于 Docker 的部署。我们将在下一节介绍基于 Docker 的部署。

# 将 Docker 容器部署到 Azure 容器服务

让我们部署我们的 Docker 容器应用程序。我已经为上一节中使用的“产品”API 示例创建了 Docker 镜像。可以通过以下命令从 Docker hub 拉取 Docker 镜像：

```java
docker pull cloudnativejava/ch10productapi 
```

让我们开始并登录到 Azure 门户。我们应该看到以下内容：

1.  点击左侧栏的“应用服务”菜单项。我们应该看到以下屏幕。点击“新建”，如截图所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/ddabfc10-2db1-410f-b43b-25921443cd22.png)

1.  在“新建”中搜索`Web App for Containers`：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/22d28f9f-ef11-48b2-864d-19bb66be4724.png)

1.  选择 Web App for Containers 后，点击“创建”如指示的那样：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/72ab0c88-bdfe-4b2c-9cf0-f4f6a8e158ea.png)

通过 App Services | 添加 | Web App 导航选择创建

1.  我们将填写我们的`product` API 容器的详细信息：

1.  我已经填写了应用程序名称和资源组为`ch10productContainer`，并将其他选项保持默认。

1.  在“配置容器”部分，我们选择容器存储库。如果 Docker hub 中已经有 Docker 镜像，请提供镜像拉取标签`cloudnativejava/ch10productapi`。

1.  点击页面底部的“确定”。它会验证图像。

1.  接下来，我们点击页面底部的“创建”：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/6112a303-5635-4575-91b3-cad71f75e9b7.png)

通过 Azure 门户导航选择创建|新建|搜索`Web App for Containers`

1.  这将创建应用服务：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/3e41b4f7-c4cf-400e-ae94-2a12bdd29694.png)

通过 Azure 门户导航选择新创建的应用程序容器|应用服务

1.  我们点击 App Services 下的`ch10productcontainer`，这将带我们到菜单，我们可以看到标记的 URL，`https://ch10productcontainer.azurewebsites.net`，容器可用的地方。

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/94c17e67-6c28-4522-be1d-2fd4c65f88d9.png)

主机 Docker 应用程序可以访问的 URL

1.  我们可以在浏览器中看到我们的`product` API 正在运行：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/b933045b-f5a6-4d37-8d26-f7c24d7e92e4.png)

这是将您的应用程序部署到云平台的一种简单方法。在前面的两种情况下，我们都没有使用任何专门的应用程序或数据存储服务。对于真正的云原生应用程序，我们需要利用提供者提供的平台服务。整个想法是应用程序的可扩展性和可用性方面的重要工作由本地平台处理。我们作为开发人员，专注于构建关键的业务功能和与其他组件的集成。

# 将 Spring Boot API 部署到 Azure Service Fabric

构建和部署应用程序到基础 IaaS 平台是大多数组织开始与公共云提供商合作的方式。随着云流程的舒适度和成熟度的提高，应用程序开始具备 PaaS 功能。因此，应用程序开始包括排队、事件处理、托管数据存储、安全性和其他平台服务的功能。

但是，关于非功能需求，一个关键问题仍然存在。谁会考虑应用程序的能力？

+   如何确保有足够的应用程序实例在运行？

+   当实例宕机时会发生什么？

+   应用程序如何根据流量的增减而扩展/缩减？

+   我们如何监视所有运行的实例？

+   我们如何管理分布式有状态服务？

+   我们如何对部署的服务执行滚动升级？

编排引擎登场。诸如 Kubernetes、Mesos 和 Docker Swarm 等产品提供了管理应用程序容器的能力。Azure 发布了 Service Fabric，这是用于应用程序/容器管理的软件。它可以在本地或云中运行。

Service Fabric 提供以下关键功能：

+   允许您部署可以大规模扩展并提供自愈平台的应用程序

+   允许您安装/部署有状态和无状态的基于微服务的应用程序

+   提供监视和诊断应用程序健康状况的仪表板

+   定义自动修复和升级的策略

在当前版本中，Service Fabric 支持两种基础操作系统——Windows Server 和 Ubuntu 16.04 的版本。最好选择 Windows Server 集群，因为支持、工具和文档是最好的。

为了演示 Service Fabric 的功能和用法，我将使用 Ubuntu 镜像进行本地测试，并使用 Service Fabric party 集群将我们的`product` API 示例在线部署到 Service Fabric 集群。我们还将研究如何扩展应用程序实例和 Service Fabric 的自愈功能。

# 基本环境设置

我使用的是 macOS 机器。我们需要设置以下内容：

1.  本地 Service Fabric 集群设置——拉取 Docker 镜像：

```java
docker pull servicefabricoss/service-fabric-onebox 
```

1.  在主机上更新 Docker 守护程序配置，并重新启动 Docker 守护程序：

```java
{ 
    "ipv6": true, 
    "fixed-cidr-v6": "fd00::/64" 
}
```

1.  启动从 Docker Hub 拉取的 Docker 镜像：

```java
docker run -itd -p 19080:19080 servicefabricoss/service-fabric-onebox bash 
```

1.  在容器 shell 中添加以下命令：

```java
./setup.sh      
./run.sh        
```

完成最后一步后，将启动一个可以从浏览器访问的开发 Service Fabric 集群，地址为`http://localhost:19080`。

现在我们需要为容器和客户可执行文件设置 Yeoman 生成器：

1.  首先，我们需要确保 Node.js 和 Node Package Manager（NPM）已安装。可以使用 HomeBrew 安装该软件，如下所示：

```java
brew install node node -v npm -v 
```

1.  接下来，我们从 NPM 安装 Yeoman 模板生成器：

```java
npm install -g yo 
```

1.  接下来，我们安装将用于使用 Yeoman 创建 Service Fabric 应用程序的 Yeoman 生成器。按照以下步骤进行：

```java
# for Service Fabric Java Applications npm install -g generator-azuresfjava # for Service Fabric Guest executables npm install -g generator-azuresfguest # for Service Fabric Container Applications npm install -g generator-azuresfcontainer
```

1.  要在 macOS 上构建 Service Fabric Java 应用程序，主机机器必须安装 JDK 版本 1.8 和 Gradle。可以使用 Homebrew 安装该软件，方法如下：

```java
brew update 
brew cask install java 
brew install gradle 
```

这样就完成了环境设置。接下来，我们将把我们的`product` API 应用程序打包为 Service Fabric 应用程序，以便在集群中进行部署。

# 打包产品 API 应用程序

我们登录到`product` API 项目（完整代码可在[`github.com/PacktPublishing/Cloud-Native-Applications-in-Java`](https://github.com/PacktPublishing/Cloud-Native-Applications-in-Java)找到），并运行以下命令：

```java
yo azuresfguest
```

我们应该看到以下屏幕：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/c73b090b-cac7-4dc8-97cf-82ac59cb3602.png)

我们输入以下值：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/6d4da0c7-148a-496c-b4c4-5ee8fa099559.png)

这将创建一个包含一组文件的应用程序包：

```java
ProductServiceFabric/ProductServiceFabric/ApplicationManifest.xml 
ProductServiceFabric/ProductServiceFabric/ProductAPIPkg/ServiceManifest.xml 
ProductServiceFabric/ProductServiceFabric/ProductAPIPkg/config/Settings.xml 
ProductServiceFabric/install.sh 
ProductServiceFabric/uninstall.sh 
```

接下来，我们转到`/ProductServiceFabric/ProductServiceFabric/ProductAPIPkg`文件夹。

创建一个名为`code`的目录，并在其中创建一个名为`entryPoint.sh`的文件，其中包含以下内容：

```java
#!/bin/bash 
BASEDIR=$(dirname $0) 
cd $BASEDIR 
java -jar product-0.0.1-SNAPSHOT.jar 
```

还要确保将我们打包的 JAR（`product-0.0.1-SNAPSHOT.jar`）复制到此文件夹中。

`Number of instances of guest binary`的值应该是`1`，用于本地环境开发，对于云中的 Service Fabric 集群，可以是更高的数字。

接下来，我们将在 Service Fabric 集群中托管我们的应用程序。我们将利用 Service Fabric party 集群。

# 启动 Service Fabric 集群

我们将使用我们的 Facebook 或 GitHub ID 登录[`try.servicefabric.azure.com`](https://try.servicefabric.azure.com)：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/762646ef-8399-4f28-bdfc-49974a7a83d8.png)

加入 Linux 集群：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/af50ebad-5369-40ef-8aa6-ff410a3c9442.png)

我们将被引导到包含集群详细信息的页面。该集群可用时间为一小时。

默认情况下，某些端口是开放的。当我们部署我们的`product` API 应用程序时，我们可以在端口`8080`上访问相同的应用程序：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/35514f7b-5a6a-4802-9d95-b424e11c1b36.png)

Service Fabric 集群资源管理器可在先前提到的 URL 上找到。由于集群使用基于证书的身份验证，您需要将 PFX 文件导入到您的钥匙链中。

如果您访问该 URL，您可以看到 Service Fabric 集群资源管理器。默认情况下，该集群有三个节点。您可以将多个应用程序部署到集群中。根据应用程序设置，集群将管理您的应用程序可用性。

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/87f2fbfc-96ce-4174-8c61-ad8d59454d50.png)

Azure Party 集群默认视图

# 将产品 API 应用程序部署到 Service Fabric 集群

要将我们的应用程序部署到为应用程序创建的 Service Fabric 脚手架的`ProductServiceFabric`文件夹中，我们需要登录。

# 连接到本地集群

我们可以使用以下命令在此处连接到本地集群：

```java
sfctl cluster select --endpoint http://localhost:19080 
```

这将连接到在 Docker 容器中运行的 Service Fabric 集群。

# 连接到 Service Fabric party 集群

由于 Service Fabric party 集群使用基于证书的身份验证，我们需要在`/ProductServiceFabric`工作文件夹中下载 PFX 文件。

运行以下命令：

```java
openssl pkcs12 -in party-cluster-1496019028-client-cert.pfx -out party-cluster-1496019028-client-cert.pem -nodes -passin pass: 
```

接下来，我们将使用**隐私增强邮件**（**PEM**）文件连接到 Service Fabric party 集群：

```java
sfctl cluster select --endpoint https://zlnxyngsvzoe.westus.cloudapp.azure.com:19080 --pem ./party-cluster-1496019028-client-cert.pem --no-verify 
```

一旦我们连接到 Service Fabric 集群，我们需要通过运行以下命令来安装我们的应用程序：

```java
./install.sh 
```

我们应该看到我们的应用程序被上传并部署到集群中：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/8fbdad95-5b1d-4667-903d-c8739bc29670.png)

安装并启动 Docker 容器中的 Service Fabric 集群

一旦应用程序被上传，我们可以在 Service Fabric 资源管理器中看到应用程序，并且可以访问应用程序的功能：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/6c70ae23-b56c-4978-a32f-19a49107ff02.png)

观察在 Azure Party Cluster 中部署的应用程序

API 功能可在以下网址找到：`http://zlnxyngsvzoe.westus.cloudapp.azure.com:8080/product/2`。

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/3e6a7184-3987-4437-a48d-e06478a47f92.png)

验证 API 是否正常工作

我们可以看到应用程序当前部署在一个节点（`_lnxvm_2`）上。如果我们关闭该节点，应用程序实例将自动部署在另一个节点实例上：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/75c02b81-c7ec-4d6d-b0e6-d8f13f672cf3.png)

观察应用程序部署在三个可用主机中的单个节点上

通过选择节点菜单中的选项（在下面的截图中突出显示）来关闭节点（`_lnxvm_2`）：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/4a64c641-6097-46c4-9b4f-e070cbce95a3.png)

观察在 Azure Party Cluster 上禁用主机的选项

立即，我们可以看到应用程序作为集群的自愈模型部署在节点`_lnxvm_0`上：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/89ca78f9-b18d-40fb-b61f-8d350178b27f.png)

在一个节点上禁用应用程序后，它会在 Service Fabric Cluster 的另一个节点上启动

再次，我希望读者足够好奇，继续探索集群的功能。对 Java 应用程序和多个版本的 Linux 的支持有限。Azure 正在努力增加对平台的额外支持，以支持各种类型的应用程序。

# Azure 云函数

随着我们将应用程序迁移到云端，我们正在使用平台服务来提高我们对业务功能的关注，而不用担心应用程序的可伸缩性。无服务器应用程序是下一个前沿。开发人员的重点是构建应用程序，而不用担心服务器的配置、可用性和可伸缩性。

Java 函数目前处于测试阶段，不在 Azure 门户上提供。

我们可以下载并尝试在本地机器上创建 Java 函数。我们将看到功能的简要预览。

# 环境设置

Azure Functions Core Tools SDK 为编写、运行和调试 Java Azure Functions 提供了本地开发环境：

```java
npm install -g azure-functions-core-tools@core 
```

# 创建一个新的 Java 函数项目

让我们创建一个示例 Java 函数项目。我们将利用以下 Maven 原型来生成虚拟项目结构：

```java
mvn archetype:generate  -DarchetypeGroupId=com.microsoft.azure  -DarchetypeArtifactId=azure-functions-archetype 
```

我们运行`mvn`命令来提供必要的输入：

```java
Define value for property 'groupId': : com.mycompany.product 
Define value for property 'artifactId': : mycompany-product 
Define value for property 'version':  1.0-SNAPSHOT: :  
Define value for property 'package':  com.mycompany.product: :  
Define value for property 'appName':  ${artifactId.toLowerCase()}-${package.getClass().forName("java.time.LocalDateTime").getMethod("now").invoke(null).format($package.Class.forName("java.time.format.DateTimeFormatter").getMethod("ofPattern", $package.Class).invoke(null, "yyyyMMddHHmmssSSS"))}: : productAPI 
Define value for property 'appRegion':  ${package.getClass().forName("java.lang.StringBuilder").getConstructor($package.getClass().forName("java.lang.String")).newInstance("westus").toString()}: : westus 
Confirm properties configuration: 
groupId: com.mycompany.product 
artifactId: mycompany-product 
version: 1.0-SNAPSHOT 
package: com.mycompany.product 
appName: productAPI 
appRegion: westus 
 Y: : y 
```

# 构建和运行 Java 函数

让我们继续构建包：

```java
mvn clean package 
```

接下来，我们可以按以下方式运行函数：

```java
mvn azure-functions:run 
```

我们可以在以下图像中看到函数的启动：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/e4fbf658-89f7-4ef1-91c7-c66006a45afa.png)

构建您的 Java 云函数

默认函数可在以下网址找到：

```java
http://localhost:7071/api/hello 
```

如果我们访问`http://localhost:7071/api/hello?name=cloudnative`，我们可以看到函数的输出：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/dcabf483-0ca5-42dc-8ca1-0ad0a1bf313b.png)

# 深入代码

如果我们深入代码，我们可以看到主要的代码文件，其中定义了默认函数`hello`：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/7bf8fd82-eea1-4f5f-915e-4dc7ccf22afd.png)

该方法使用`@HttpTrigger`进行注释，我们在其中定义了触发器的名称、允许的方法、使用的授权模型等。

当函数编译时，会生成一个`function.json`文件，其中定义了函数绑定。

```java
{ 
  "scriptFile" : "../mycompany-product-1.0-SNAPSHOT.jar", 
  "entryPoint" : "productAPI.Function.hello", 
  "bindings" : [ { 
    "type" : "httpTrigger", 
    "name" : "req", 
    "direction" : "in", 
    "authLevel" : "anonymous", 
    "methods" : [ "get", "post" ] 
  }, { 
    "type" : "http", 
    "name" : "$return", 
    "direction" : "out" 
  } ], 
  "disabled" : false 
} 
```

您可以看到输入和输出数据绑定。函数只有一个触发器。触发器会携带一些相关数据触发函数，通常是触发函数的有效负载。

输入和输出绑定是一种声明性的方式，用于在代码内部连接数据。绑定是可选的，一个函数可以有多个输入和输出绑定。

您可以通过 Azure 门户开发函数。触发器和绑定直接在`function.json`文件中配置。

Java 函数仍然是一个预览功能。功能集仍处于测试阶段，文档很少。我们需要等待 Java 在 Azure Functions 的世界中成为一流公民。

这就是我们使用 Azure 进行平台开发的结束。

# 总结

在本章中，我们看到了 Azure 云平台提供的各种功能和服务。当我们将应用程序转移到云原生模型时，我们从应用服务|容器服务|服务布置|无服务器模型（云函数）中转移。当我们构建全新的应用程序时，我们跳过初始步骤，直接采用平台服务，实现自动应用程序可伸缩性和可用性管理。

在下一章中，我们将介绍各种类型的 XaaS API，包括 IaaS、PaaS、iPaaS 和 DBaaS。我们将介绍在构建自己的 XaaS 时涉及的架构和设计问题。


# 第十一章：作为服务集成

本章讨论了各种 XaaS 类型，包括基础设施即服务（IaaS）、平台即服务（PaaS）、集成平台即服务（iPaaS）和数据库即服务（DBaaS），以及在将基础设施或平台元素公开为服务时需要考虑的一切。在云原生模式下，您的应用程序可能正在集成社交媒体 API 或 PaaS API，或者您可能正在托管其他应用程序将使用的服务。本章涵盖了构建自己的 XaaS 模型时需要处理的问题。

本章将涵盖以下主题：

+   构建自己的 XaaS 时的架构和设计问题

+   构建移动应用程序时的架构和设计问题

+   各种后端作为服务提供商——数据库、授权、云存储、分析等

# XaaS

云计算开创了弹性、按需、IT 托管服务的分发模式。任何作为服务交付的 IT 部分都宽泛地归入云计算的范畴。

在云计算主题中，根据 IT 服务的类型，云的特定服务有各种术语。大多数术语是 XaaS 的不同变体，其中 X 是一个占位符，可以更改以代表多种事物。

让我们看看云计算的最常见交付模式：

+   IaaS：当计算资源（计算、网络和存储）作为服务提供以部署和运行操作系统和应用程序时，被称为 IaaS。如果组织不想投资于建立数据中心和购买服务器和存储，这是一种正确的选择。亚马逊网络服务（AWS）、Azure 和谷歌云平台（GCP）是 IaaS 提供商的主要例子。在这种模式下，您负责以下事项：

+   管理、打补丁和升级所有操作系统、应用程序和相关工具、数据库系统等。

+   从成本优化的角度来看，您将负责启动和关闭环境。

+   计算资源的供应几乎是即时的。计算资源的弹性是 IaaS 供应商的最大卖点之一。

+   通常，服务器镜像可以由云提供商备份，因此在使用云提供商时备份和恢复很容易管理。

+   PaaS：一旦计算、网络和存储问题解决，接下来就需要开发平台和相关环境来构建应用程序。PaaS 平台提供了整个软件开发生命周期（SDLC）的服务。运行时（如 Java 和.NET）、数据库（MySQL 和 Oracle）和 Web 服务器（如 Tomcat 和 Apache Web 服务器）等服务被视为 PaaS 服务。云计算供应商仍将管理运行时、中间件、操作系统、虚拟化、服务器、存储和网络的基础运营方面。在这种模式下，您将负责以下事项：

+   开发人员的关注将局限于管理应用程序和相关数据。应用程序的任何更改/更新都需要由您管理。

+   PaaS 的抽象层级较高（消息传递、Lambda、容器等），使团队能够专注于核心能力，满足客户需求。

+   **SaaS**：接下来是您租用整个应用程序的模式。您不需要构建、部署或维护任何东西。您订阅应用程序，提供商将为您或您的组织提供一个应用程序实例供您使用。您可以通过浏览器访问应用程序，或者可以集成提供商提供的公共 API。Gmail、Office 365 和 Salesforce 等服务就是 SaaS 服务的例子。在这种模式下，提供商为所有租户提供标准版本的功能/功能，定制能力非常有限。SaaS 供应商可能提供一个安全模型，您可以使用**轻量级目录访问协议**（**LDAP**）存储库与供应商集成，使用**安全断言标记语言**（**SAML**）或 OAuth 模型。这种模式非常适用于定制需求较低的标准软件。Office365 和 Salesforce 是 SaaS 供应商的典范：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/c2e2b5bf-878a-4c64-995b-c57c9611f9b7.jpg)

在构建您的组织及其应用程序组合时，您可能会订阅不同供应商提供的各种类型的服务。现在，如果您试图构建下一个 Facebook 或 Instagram 或 Uber，您将需要解决特定的架构问题，以满足全球数十亿用户的各种需求。

# 构建 XaaS 时的关键设计问题

让我们回顾一下在构建 XaaS 并为其提供消费服务时需要解决的关键设计问题：

+   **多租户**：当您开始为公众使用设计您的服务时，首要要求之一是能够支持多个租户或客户。随着人们开始注册使用您的服务，服务需要能够为客户数据提供安全边界。通常，SaaS 是多租户设计问题的一个很好的候选者。对于每个租户，数据和应用程序工作负载可能需要进行分区。租户请求在租户数据的范围内。要在应用程序中设计多租户，您需要查看以下内容：

+   **隔离**：数据应该在租户之间隔离。一个租户不应该能够访问任何其他租户的数据。这种隔离不仅限于数据，还可以扩展到底层资源（包括计算、存储、网络等）和为每个租户标记的操作过程（备份、恢复、DevOps、管理员功能、应用程序属性等）。

+   **成本优化**：下一个重要问题是如何优化设计以降低云资源的总体成本，同时仍然满足各种客户的需求。您可以考虑多种技术来管理成本。例如，对于免费层客户，您可以基于租户 ID 的租赁模型。这种模型允许您优化数据库许可证、整体计算和存储成本、DevOps 流程等。同样，对于大客户，甚至可以考虑专用基础设施以提供保证的**服务级别协议**（**SLA**）。有许多小公司从少数大客户那里获得数百万美元的业务。另一方面，有大公司为数百万小客户提供服务。

+   **DevOps 流水线**：如果您最终为客户构建同一服务的多个实例，当客户要求为他们提供特定功能时，您将遇到问题。这很快会导致代码碎片化，并成为一个难以管理的代码问题。问题在于如何平衡为所有客户推出新功能/功能的能力，同时仍能够提供每个客户所需的定制或个性化水平。DevOps 流程需要支持多租户隔离，并维护/监视每个租户的流程和数据库架构，以在所有服务实例中推出更改。除非 DevOps 得到简化，否则在整个服务中推出更改可能会变得非常复杂和令人望而却步。所有这些都会导致成本增加和客户满意度降低。

+   **可扩展性**：其中一个基本要求是能够注册新客户并扩展服务。随着客户规模的增长，预期成本/服务或整体服务成本应该下降。除非我们的服务考虑到前面三种租户类型，否则服务将无法扩展并在您的业务模型周围提供人为的壕沟。

接下来，当您开始设计多租户服务时，您有以下设计选项：

+   +   **每个租户一个数据库**：每个租户都有自己的数据库。这种模型为租户数据提供了完全隔离。

+   **共享数据库（单一）**：所有租户都托管在单个数据库中，并由租户 ID 标识。

+   **共享数据库（分片）**：在这种模型中，单个数据库被分片成多个数据库。通常，分片键是从哈希、范围或列表分区派生的。租户分布在分片中，并且可以通过租户 ID 和分片的组合访问：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/0cdc78ca-0629-4b6a-a86f-80d7ba247228.png)

+   **更快的配置**：在构建 XaaS 模型时，另一个关键问题是能够为新客户提供配置的能力，这意味着客户的入职应该是自助的。注册后，客户应立即能够开始使用服务。所有这些都需要一个模型，其中新租户可以轻松快速地配置。提供基础计算资源、任何数据库架构创建和/或特定的 DevOps 流水线的能力应该非常高效和完全自动化。从客户体验的角度来看，能够为用户提供正在运行的应用程序版本也是有帮助的。对于任何旨在成为大众市场的服务，更快的配置都是必须的。但是，如果您提供的是非常特定的服务，并且需要与企业客户的本地数据中心集成，那么可能无法提供分秒级的配置。在这种情况下，我们应该构建可以尽快解决一些常见集成场景的工具/脚本，以尽快为客户提供服务。

+   **审计**：安全性周围的另一个关键问题是审计对服务和基础数据存储的访问和更改的能力。所有审计跟踪都需要存储，以用于任何违规行为、安全问题或合规目的。将需要一个集中的审计存储库，用于跟踪系统中生成的事件。您应该能够在审计存储库之上运行分析，以标记任何异常行为并采取预防或纠正措施：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/368b83b4-4d0c-4cf3-8615-ca7ed56c3c74.jpg)

您可以利用 Lambda 架构，它同时使用实时流和从历史数据生成的模型来标记异常行为。一些公共云提供商提供此服务。

+   **安全性**: 根据服务的性质，租户需要安全访问其数据。服务需要包含身份验证和授权的基本要求。所有客户都有安全密钥和密码短语来连接和访问其信息。可能需要企业访问和多个用户。在这种情况下，您可能需要为企业构建委托管理模型。您还可以使用 OAuth 等安全机制（通过 Google、Facebook 等）来启用对服务的访问。

+   **数据存储**: 您的服务可能需要存储不同类型的数据；根据数据类型，存储需求将不同。存储需求通常分为以下几个领域：

+   **关系数据存储**: 租户数据可能是关系型的，我们谈到了各种多租户策略来存储这些数据。租户特定的应用程序配置数据可能需要存储在关系模型中。

+   **NoSQL 存储**: 租户数据可能并非始终是关系型的；它可能是列式的、键值对的、图形的或面向文档的模型。在这种情况下，需要设计并构建适当的数据存储。

+   **Blob 存储**: 如果您的服务需要 Blob 存储或二进制数据存储，那么您将需要访问对象文件存储。您可以利用 AWS 或 Azure 等提供的 Blob 存储来存储您的二进制文件。

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/9f6701a3-550b-4ae4-922d-9815cbeeb589.jpg)

+   **监控**: 需要监控整个应用程序堆栈。您可能会为客户签署严格的 SLA。在这种情况下，监控不仅仅是关于服务或系统的可用性，还涉及任何成本惩罚和声誉损失。有时，个别组件可能具有冗余和高可用性，但在堆栈级别，所有故障率可能会相互叠加，从而降低堆栈的整体可用性。跨堆栈监控资源变得重要，并且是管理可用性和定义的 SLA 的关键。监控涵盖硬件和软件。需要检测任何异常行为并自动执行纠正响应。通常，监控和自动修复需要多次迭代才能成熟。

+   **错误处理**: 服务的关键方面之一将是处理故障的能力以及如何响应服务消费者。故障可能发生在多个级别；数据存储不可用、表被锁定、查询超时、服务实例宕机、会话数据丢失等都是您将遇到的一些问题。您的服务需要强大到能够处理所有这些以及更多的故障场景。诸如 CQRS、断路器、隔离、响应式等模式需要纳入到您的服务设计中。

+   **自动化构建/部署**: 随着服务消费者数量的增加，推出新功能和修复错误将需要自动化的构建和部署模型。这类似于在汽车行驶时更换轮胎。升级软件并发布补丁/安全修复，而不会对消费者的调用产生任何影响，这是一门微妙的艺术，需要时间来掌握。以前，我们可以在夜间系统流量减少时寻找一些系统停机时间，但是随着来自世界各地的客户，再也没有这样的时间了。蓝绿部署是一种技术，可以帮助在对客户造成最小影响的情况下发布新变更，并降低整体风险：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/11b5d90d-def5-4d0b-a9bb-186ed8175b75.jpg)

+   **客户层**：另一个关键问题是如何为不同的客户群建立和定价您的服务。公司一直在创建多个层次来满足众多客户的需求。这些需求帮助公司确定客户层，然后开始定价服务成本。这些因素如下：

+   **计算**：限制每小时/每天/每月的调用次数。这使您能够预测租户所需的容量以及网络带宽要求。

+   **存储**：另一个参数是底层数据存储所需的存储空间。这使您可以适当平衡数据库分片。

+   **安全性**：对于企业客户，可能存在与 SAML 使用企业安全模型集成的单独要求。这可能需要额外的硬件和支持。

+   **SLA/支持模型**：这是另一个需要考虑的领域，当决定客户层时需要考虑。支持模型——社区、值班、专用等——具有不同的成本结构。根据目标市场——消费者或企业——您可以评估哪种支持模型最适合您的服务。

+   **功能标志**：在构建 XaaS 模型时，一个关键问题是如何处理多个租户的代码更改、功能发布等。我应该为每个客户拥有多个代码分支，还是应该在所有客户之间使用一个代码库？如果我使用一个代码库，如何发布特定于一个租户的功能/功能？如果您的目标市场是 8-10 个客户，那么为每个客户拥有特定的代码分支是一个潜在的可行选项。但如果目标市场是数百个客户，那么代码分支是一个糟糕的选择。代码分支通常是一个糟糕的主意。为了处理不同客户的功能/功能差异或管理尚未准备发布的新功能，功能标志是处理此类要求的一个很好的方法。

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/3f68ffe8-fb34-4ffb-a032-d4fc1fc5141b.jpg)

功能标志允许您在生产中发布代码，而不立即为用户发布功能。您可以使用功能标志根据客户购买的服务级别为应用程序的不同客户提供/限制某些功能。您还可以与 A/B 测试结合使用功能标志，向部分用户发布新功能/功能，以检查其响应和功能正确性，然后再向更广泛的受众发布。

+   自助服务门户：您的服务的一个关键方面将是一个自助服务门户，用户可以在那里注册、提供服务，并管理应用程序数据和服务的所有方面。该门户允许用户管理企业方面，如身份验证/授权（使用委托管理员模型）、监视已提供的服务的可用性，在服务的关键指标上设置自定义警报/警报，并解决可能在服务器端出现的任何问题。精心设计的门户有助于增加用户对服务性能的整体信心。您还可以为付费客户构建基于客户层的高级监控和分析服务。请记住，任何人都可以复制您的服务提供的功能/功能，但围绕您的服务构建附加值功能成为您服务的独特差异化因素。

+   软件开发工具包（SDKs）：作为启用用户采纳性的关键措施之一，您可能希望为您的消费者构建并提供 SDK。这不是必须的，但是是一个可取的特性，特别是当客户在应用程序代码级别与您的服务集成时。在这种情况下，SDK 应该支持多种语言，并提供良好的示例和文档，以帮助客户端的开发人员上手。如果您的应用程序或服务很复杂，那么拥有一个解释如何调用您的服务或与现有服务集成（如 SAML、OAuth 等）的 SDK 对于更快地采用您的服务至关重要。

+   文档和社区支持：服务可采纳性的另一个方面是产品/服务的文档水平以及社区对其的支持。文档应该至少涵盖以下几点：

+   如何注册该服务

+   如何调用和使用服务

+   如何将服务整合到客户的景观中以及可用于集成的 SDK

+   如何批量导入或批量导出您的数据

+   如何与企业 LDAP/Active Directory（AD）服务器进行安全整合进行身份验证/授权

接下来你需要考虑的是建立一个积极的社区支持。你需要为人们互动提供适当的论坛。你需要有积极的专业主题专家来回答来自各个论坛（内部和外部）的问题。像 Stack Overflow 这样的网站会收到很多问题；你应该设置警报，监控帖子，并帮助回答用户的问题/查询。一个积极的社区是对你的产品感兴趣的一个迹象。许多组织也利用这个论坛来识别早期采用者，并在产品路线图中寻求他们的反馈。

+   产品路线图：一个好的产品可能从一个最小可行产品（MVP）开始，但通常都有一个坚实的愿景和产品路线图作为支持。当你从客户那里收到反馈时，你可以不断更新产品路线图并重新排列优先级。一个好的路线图表明了产品愿景的力量。当你遇到外部利益相关者——客户、合作伙伴、风险投资者等等——他们首先要求的是一个产品路线图。

路线图通常包括战略重点和计划发布，以及高层功能和维护/错误修复发布的计划，等等：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/2bb52c14-3aa7-4d57-b65a-fc95e8abc652.jpg)

我们已经涵盖了一些在尝试构建您的 XaaS 模型时需要考虑的设计问题。我们已经涵盖了每个问题的基础知识。每个问题都需要至少一个章节。希望这能让您了解在尝试围绕 XaaS 构建业务模型时需要考虑的其他非服务方面。服务的实际设计和开发是基于我们从第二章开始涵盖的问题。

# 与第三方 API 的集成

在前一节中，我们看到了构建自己的服务提供商时的设计问题。在本节中，我们将看到，如果您正在尝试构建一个消费者应用程序，如何利用第三方公司提供的 REST 服务。例如，您正在尝试构建一个漂亮的移动应用程序，您的核心竞争力是构建视觉设计和创建移动应用程序。您不想被管理托管/管理应用程序数据的所有复杂性所拖累。该应用程序将需要包括存储、通知、位置、社交集成、用户管理、聊天功能和分析等服务。所有这些提供商都被归类为**后端即服务**（**BaaS**）提供商。没有必要为这些服务注册单一供应商；您可以挑选符合您业务需求和预算的提供商。每个提供商通常都采用免费模式，每月提供一定数量的免费 API 调用，以及商业模式，您需要付费。这也属于构建无服务器应用程序的范畴，作为开发人员，您不需要维护任何运行软件的服务器。

在这方面，我们将看看构建一个完整的无服务器应用程序所需的第三方服务：

+   **身份验证服务**：任何应用程序需要的第一件事情之一是能够注册用户。注册用户为应用程序开发人员提供了提供个性化服务并了解他的喜好/不喜欢的机会。这些数据使他能够优化用户体验并提供必要的支持，以从应用程序中获得最大价值。

身份验证作为服务专注于围绕用户身份验证的业务功能的封装。身份验证需要一个身份提供者。这个提供者可以映射到您的应用程序或企业，或者您可以使用一些消费者公司，如谷歌、Facebook、Twitter 等。有多个可用的身份验证服务提供商，如 Auth0、Back&、AuthRocket 等。这些提供商应该提供至少以下功能：

+   **多因素身份验证**（**MFA**）（包括对社交身份提供者的支持）：作为主要要求之一，提供商应该提供身份提供者实例，应用程序可以在其中管理用户。功能包括用户注册，通过短信或电子邮件进行两因素身份验证，以及与社交身份提供者的集成。大多数提供商使用 OAuth2/OpenID 模型。

+   **用户管理**：除了 MFA，身份验证提供商应该提供用户界面，允许对已注册应用程序的用户进行管理。您应该能够提取电子邮件和电话号码，以向客户发送推送通知。您应该能够重置用户凭据并通过使用安全领域或根据应用程序的需求将用户添加到某些预定义角色来保护资源。

+   **插件/小部件**：最后但并非最不重要的是，提供商应该提供可以嵌入应用程序代码中以提供用户身份验证的小部件/插件作为无缝服务：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/12f53ae6-2636-4c9d-a7cd-b48af79c4772.jpg)

+   **无服务器服务**：过去，您需要管理应用程序服务器和底层 VM 来部署代码。抽象级别已经转移到所谓的业务功能。您编写一个接受请求、处理请求并输出响应的函数。没有运行时，没有应用程序服务器，没有 Web 服务器，什么都没有。只有一个函数！提供商将自动提供运行时来运行该函数，以及服务器。作为开发人员，您不需要担心任何事情。您根据对函数的调用次数和函数运行时间的组合收费，这意味着在低谷时期，您不会产生任何费用。

通过函数，您可以访问数据存储并管理用户和应用程序特定数据。两个函数可以使用队列模型相互通信。函数可以通过提供商的 API 网关公开为 API。

所有公共云供应商都有一个无服务器模型的版本——AWS 有 Lamda，Azure 有 Azure Functions，Google 有 Cloud Functions，Bluemix 有 Openwhisk 等：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/b0c0629b-0fbf-47fd-914b-abd93b959c75.jpg)

+   **数据库/存储服务**：应用程序通常需要存储空间来管理客户数据。这可以是简单的用户配置文件信息（例如照片、姓名、电子邮件 ID、密码和应用程序首选项）或用户特定数据（例如消息、电子邮件和应用程序数据）。根据数据的类型和存储格式，可以选择适当的数据库/存储服务。对于二进制存储，我们有 AWS S3 和 Azure Blob Storage 等服务，适用于各种二进制文件。要直接从移动应用程序中以 JSON 格式存储数据，您可以使用 Google Firebase 等云提供商，或者您可以使用 MongoDB 作为服务（[www.mlab.com](https://mlab.com/)）。AWS、Azure 和 GCP 提供了多种数据库模型，可用于管理各种不同的存储需求。您可能需要使用 AWS Lambda 或 Google Cloud Functions 来访问存储数据。例如，如果应用程序请求在存储数据之前需要进行一些验证或处理，您可以编写一个 Lambda 函数，该函数可以公开为 API。移动应用程序访问调用 Lambda 函数的 API，在请求处理后，数据存储在数据存储中。

+   **通知服务**：应用程序通常会注册用户和设备，以便能够向设备发送通知。AWS 提供了一项名为 Amazon **Simple Notification Service** (**SNS**)的服务，可用于从您的移动应用程序注册和发送通知。AWS 服务支持向 iOS、Android、Fire OS、Windows 和基于百度的设备发送推送通知。您还可以向 macOS 桌面和 iOS 设备上的**VoIP**应用程序发送推送通知，向超过 200 个国家/地区的用户发送电子邮件和短信。

+   **分析服务**：一旦客户开始采用该应用程序，您将想要了解应用程序的哪些功能正在使用，用户在哪些地方遇到问题或挑战，以及用户在哪些地方退出。为了了解所有这些，您需要订阅一个分析服务，该服务允许您跟踪用户的操作，然后将其汇总到一个中央服务器。您可以访问该中央存储库并深入了解用户的活动。您可以利用这些对客户行为的洞察来改善整体客户体验。Google Analytics 是这一领域中的一项热门服务。您可以跟踪用户的多个整体参数，包括位置、使用的浏览器、使用的设备、时间、会话详细信息等。您还可以通过添加自定义参数来增强它。这些工具通常提供一定数量的预定义报告。您还可以添加/设计自己的报告模板。

+   位置服务：应用程序使用的另一个服务是位置服务。你的应用程序可能需要功能，需要根据给定的上下文进行策划（在这种情况下，位置可以是上下文属性之一）。上下文感知功能允许你个性化地将功能/服务适应最终客户的需求，并有助于改善整体客户体验。Google Play 服务位置 API 提供了这样的功能。围绕位置服务有一整套服务/应用程序。例如，像 Uber、Lyft 和 Ola（印度）这样的公司是围绕位置服务构建的商业案例的很好的例子。大多数物流企业（特别是最后一英里）都利用位置服务进行路线优化和交付等工作。

+   社交整合服务：你的应用程序可能需要与流行的社交网络（Facebook、Twitter、Instagram 等）进行社交整合。你需要能够访问已登录用户的社交动态，代表他们发布内容，和/或访问他们的社交网络。有多种方式可以访问这些社交网络。大多数这些网络为其他应用程序提供访问，并公开一组 API 来连接它们。然后还有聚合器，允许你提供与一组社交网络的整合。

+   广告服务：应用程序使用的另一个关键服务，特别是移动应用程序，是向用户提供广告。根据应用程序模型（免费/付费），你需要决定应用程序的货币化模式。为了向用户提供广告（称为应用内广告），你需要注册广告网络提供商并调用他们的 API 服务。谷歌的 AdMob 服务是这一领域的先驱之一。

在构建应用程序时，可能还有其他许多服务提供商值得关注。我们已经涵盖了主要突出的类别。根据你的应用程序需求，你可能想在特定需求领域搜索提供者。我相信已经有人在提供这项服务。还有一些综合性的提供商被称为 BaaS。这些 BaaS 提供商通常提供多种服务供使用，并减少了应用程序端的整体集成工作。你不必与多个提供者打交道；相反，你只需与一个提供者合作。这个提供者会满足你的多种需求。

BaaS 作为一个市场细分是非常竞争的。由于多个提供者的竞争，你会发现在这个领域也有很多的并购。最近发生了以下情况：

+   Parse：被 Facebook 收购。Parse 提供了一个后端来存储你的数据，推送通知到多个设备的能力，以及整合你的应用程序的社交层。

+   GoInstant：被 Salesforce 收购。GoInstant 提供了一个 JavaScript API，用于将实时的多用户体验集成到任何 Web 或移动应用程序中。它易于使用，并提供了所需的完整堆栈，从客户端小部件到发布/订阅消息到实时数据存储。

有提供特定领域服务或 API 的垂直和水平 BaaS 提供商。在电子商务领域、游戏领域、分析领域等都有提供者。

在注册之前记得检查提供者的可信度。记住，如果提供者倒闭，你的应用程序也会陷入困境。确保你了解他们的商业模式，产品路线图，资金模式（特别是对于初创公司），以及他们对客户的倾听程度。你希望与愿意全程帮助你的合作伙伴合作。

# 总结

在本章中，我们涵盖了在尝试构建您的 XaaS 提供商时的一些关键问题。我们还涵盖了光谱的另一面，我们看到了可用于构建应用程序的典型服务。

在下一章中，我们将涵盖 API 最佳实践，我们将看到如何设计以消费者为中心的 API，这些 API 是细粒度和功能导向的。我们还将讨论 API 设计方面的最佳实践，例如如何识别将用于形成 API 的资源，如何对 API 进行分类，API 错误处理，API 版本控制等等。
