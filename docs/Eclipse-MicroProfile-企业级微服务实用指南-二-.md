# Eclipse MicroProfile 企业级微服务实用指南（二）

> 原文：[`zh.annas-archive.org/md5/90EEB03D96FBA880C6AA42B87707D53C`](https://zh.annas-archive.org/md5/90EEB03D96FBA880C6AA42B87707D53C)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：MicroProfile OpenAPI 和类型安全的 REST 客户端

Eclipse MicroProfile 为 Java 微服务提供了一系列丰富的规范。其中两个，Eclipse MicroProfile OpenAPI 和 Eclipse MicroProfile REST Client，分别帮助您微服务的 API 文档化，并为 REST 端点提供类型安全的调用 API。OpenAPI 简化了微服务端点的文档化，并使此元数据可供第三方开发者查阅。类型安全的 REST 客户端简化了对象到 HTTP 或 JSON 的编解码。

本章将涵盖以下主题：

+   每个这些规范提供的能力。

+   一些这些能力的简单代码示例

+   如何获取关于这些规范的更多信息

# MicroProfile OpenAPI 及其能力的介绍

推动数字经济的移动力量导致企业需要建立一个全渠道开发方法，以优化成本、提高效率和改善客户体验。这种方法的促进者是 API，这导致了 API 经济和 API 引导或 API 优先的开发实践等概念。此外，微服务架构已成为现代开发的架构选择。微服务之间的 API（即 RESTful）通信已被采用为事实上的标准，因为它与微服务的*智能端点和大管道*、*去中心化治理*和*去中心化数据管理*特征相契合。

然而，随着微服务数量的增加，微服务架构的管理可能会变得难以控制。然而，您可以通过 API 管理您的微服务。您可以将管理、安全、负载均衡和节流策略应用于面向您的微服务的 API。

Eclipse MicroProfile OpenAPI 为开发者提供 Java 接口，用于从他们的 Java RESTful Web Services (JAX-RS)应用程序生成 OpenAPI v3 文档。规范要求在根 URL `/openapi` 上提供一个完全处理的 OpenAPI 文档，作为 HTTP `GET`操作，如下所示：

```java
GET http://myHost:myPort/openapi
```

所需的协议是`http`。然而，规范的实现者强烈鼓励也支持`https`协议，以便安全地连接到 OpenAPI 端点。

OpenAPI 文档是从以下三个来源创建的。这三个来源（在本章后面的部分中介绍）如下：

+   通过处理应用程序中发现的 JAX-RS 注解（和可选的 OpenAPI 注解）生成。

+   通过提供一个实现`OasModelReader`的 Java 类，应用程序程序化地构建。

+   应用程序部署中包含的静态 OpenAPI 文档。

这三个来源（任意组合）结合产生一个 OpenAPI 文档，该文档可以通过提供实现`OasFilter`接口的 Java 类进行过滤，然后在前面的`/openapi`端点提供服务。

# 配置

MicroProfile OpenAPI 规范利用 MicroProfile 配置规范来配置其参数和值。例如，用于注入配置值，MicroProfile OpenAPI 可以使用默认和自定义 ConfigSources。

关于 ConfigSources 的更多信息，你可以访问[`github.com/eclipse/microprofile-config/blob/master/spec/src/main/asciidoc/configsources.asciidoc`](https://github.com/eclipse/microprofile-config/blob/master/spec/src/main/asciidoc/configsources.asciidoc)。

有很多可配置的项目。以下表格包含它们的子集：

| **配置项** | **描述** |
| --- | --- |
| `mp.openapi.scan.disable` | 禁用注解扫描的配置属性。默认值是`false`。 |
| `mp.openapi.servers` | 指定全局服务器列表的配置属性，用于... |

# 生成 OpenAPI 文档

如前所述，MicroProfile OpenAPI 规范要求从三个来源的组合生成 OpenAPI 文档。

然后你有几个选择：

+   使用 MicroProfile OpenAPI 注解扩展由 JAX-RS 注解生成的 OpenAPI 文档。

+   利用从`/openapi`的初始输出，你可以将其作为参考开始记录你的 API。在这种情况下，你可以在编写任何代码之前编写静态 OpenAPI 文件（在本章后面的部分介绍），这是组织通常采用的方法来锁定 API 的合同，即它是 API 优先的开发实践。

+   通过编程使用编程模型来启动或完成 OpenAPI 模型树。这部分内容将在本章后面介绍。

此外，你可以使用一个过滤器在构建 OpenAPI 模型后更新它。

# MicroProfile OpenAPI 注解

可能是 OpenAPI 信息最常见来源的是组成标准 JAX-RS 应用程序定义的一组注解。这些注解，加上由 MicroProfile OpenAPI 规范定义的额外（可选）注解，可以被 MicroProfile 平台扫描和处理，以产生一个 OpenAPI 文档。

MP OpenAPI 规范要求从纯 JAX-RS 2.0 应用程序生成有效的 OpenAPI 文档。如果你对 OpenAPI 不熟悉，你可以简单地将你的现有 JAX-RS 应用程序部署到 MicroProfile OpenAPI 运行时，并查看`/openapi`的输出。

为了填写生成的 OpenAPI 文档的额外详细信息，你可以进一步注解你的...

# 使用示例

以下是 MicroProfile OpenAPI 注解的一些使用示例：

示例 1 – 简单操作描述（缩写）：

```java
@GET
@Path("/findByMake")
@Operation(summary = "Finds cars by make",
           description = "Find cars by their manufacturer")
public Response findCarsByMake(...)
{ ... }
```

以下是示例 1 的输出：

```java
/car/findByMake:
 get:
 summary: Finds cars by make
 description: Find cars by their manufacturer
```

示例 2 – 具有不同响应的操作（简化）：

```java
@GET
@Path("/{name}")
@Operation(summary = "Get customer by name")
  @APIResponse(description = "The customer",
             content = @Content(mediaType = "application/json",
                                schema = @Schema(implementation = Customer.class))),
@APIResponse(responseCode = "400", description = "Customer not found")
public Response getCustomerByName(
        @Parameter(description = "The name of the customer to be fetched", required = true) @PathParam("name") String name)

{...}
```

以下是示例 2 的输出：

```java
/customer/{name}:
 get:
 summary: Get customer by name
 operationId: getCutomerByName
 parameters:
 - name: name
 in: path
 description: 'The name of the customer to be fetched'
 required: true
 schema:
 type: string
 responses:
 default:
 description: The customer
 content:
 application/json:
 schema:
 $ref: '#/components/schemas/Customer'
 400:
 description: Customer not found
```

更多示例，请参考 MicroProfile OpenAPI 规范的 wiki 页面：[`github.com/eclipse/microprofile-open-api/wiki`](https://github.com/eclipse/microprofile-open-api/wiki)。

# 静态 OpenAPI 文件

如本章前面提到的，静态 OpenAPI 文件是创建 OpenAPI 文档的三个来源之一。在下面，我们给你一个简短的介绍，告诉你如何生成一个以及如何将其包含在你的部署中。许多组织使用 API 优先的开发实践，这涉及到在为它们实现任何代码之前，甚至定义静态 OpenAPI 文件。

首先，你可以通过使用开源编辑器如 Swagger Editor（[`editor.swagger.io`](https://editor.swagger.io)）来创建一个 OpenAPI 文档。下面是一个显示这个过程的屏幕截图：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-etp-java-msvc-eclp-mprf/img/db11ee83-6eab-4cfd-a4c1-089959d1e197.png)

使用这个编辑器，你可以从样本...开始。

# 编程模型

你可以通过使用 MicroProfile OpenAPI 编程模型，通过 Java POJOs（Plain Old Java Objects）提供 OpenAPI 元素。完整的模型集在`org.eclipse.microprofile.openapi.models`包中描述。你可以在[`github.com/eclipse/microprofile-open-api/tree/master/api/src/main/java/org/eclipse/microprofile/openapi/models`](https://github.com/eclipse/microprofile-open-api/tree/master/api/src/main/java/org/eclipse/microprofile/openapi/models)了解更多。

你可以使用`OASFactory`创建一个 OpenAPI 树。以下是一个示例的代码块：

```java
OASFactory.createObject(Info.class).title("Weather")
          .description("Weather APIs").version("1.0.0");
```

为了引导 OpenAPI 模型树，你可以使用`OASModelReader`接口。然后，你可以创建这个接口的一个实现，并使用`mp.openapi.model.reader`配置键进行注册。

以下是全局地在`META-INF/microprofile-config.properties`中它的定义示例：

```java
mp.openapi.model.reader=com.mypackage.MyModelReader
```

与静态文件类似，模型读取器可以用来提供完整的或部分的模型树。要提供一个完整的 OpenAPI 模型树，你应该将`mp.openapi.scan.disable`配置设置为`true`。否则，将假设这是部分模型。

# 使用过滤器进行更新

要更新或删除 OpenAPI 文档的某些元素和字段，你可以使用一个过滤器。OASFilter([`github.com/eclipse/microprofile-open-api/blob/master/api/src/main/java/org/eclipse/microprofile/openapi/OASFilter.java`](https://github.com/eclipse/microprofile-open-api/blob/master/api/src/main/java/org/eclipse/microprofile/openapi/OASFilter.java))接口允许你为各种 OpenAPI 元素接收回调。它允许你覆盖你关心的方法。你可以创建这个接口的一个实现，并使用`mp.openapi.filter`配置键来注册它。

下面是在`META-INF/microprofile-config.properties`中其定义的样子：

```java
mp.openapi.filter=com.mypackage.MyFilter
```

已注册的过滤器对每个模型元素调用一次。例如，`filterPathItem`方法是...

# 介绍 MicroProfile REST Client 及其功能

**MicroProfile REST Client**（**MP-RC**）提供了一个 API，用于对 REST 端点的类型安全调用。它可以被应用程序用来执行对其他服务的远程调用。

它利用 Java 接口上的 JAX-RS 注解来描述与远程服务实际的合同。这些接口随后被用来创建客户端代理，隐藏了大部分底层的 HTTP 通信。

MP-RC 规范定义了在 Java 接口上使用 JAX-RS 注解的要求，以及 MP-RC 特定的注解来增强行为，包括如何传播进入请求头，如何使用提供者增强 JAX-RS 行为，异常映射，CDI 支持，与其他 MicroProfile 规范的集成。我们从定义一个类型安全的端点接口开始，更详细地查看 MP-RC。

# 定义端点接口

为了定义一个类型安全的端点接口，我们创建一个 Java 接口，利用 JAX-RS 注解将接口方法映射到它们代理的 REST 端点。一个基本的示例在下述的`WorldClockApi`接口中说明：

```java
package io.pckt.restc.contract;import javax.ws.rs.GET;import javax.ws.rs.Path;import javax.ws.rs.PathParam;import javax.ws.rs.Produces;import javax.ws.rs.core.MediaType;@Path("/api/json")public interface WorldClockApi { static final String BASE_URL = "http://worldclockapi.com/api/json"; @GET @Path("/utc/now") @Produces(MediaType.APPLICATION_JSON) Now utc(); @GET @Path("{tz}/now") @Produces(MediaType.APPLICATION_JSON) Now tz(@PathParam("tz") String tz);}public class Now ...
```

# MicroProfile REST Client 编程 API 使用

MP-RC 支持编程查找和 CDI 注入两种使用方法。以下是一个使用`org.eclipse.microprofile.rest.client.RestClientBuilder`的 REST 服务示例，它创建了一个类型安全的客户端，用于`WorldClockApi`接口，作为`WorldClockUser.java`列出：

```java
package io.pckt.restc.contract;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

@Path("/api")
@ApplicationScoped
public class WorldClockUser {
 @GET
 @Path("/now-utc")
 @Produces(MediaType.TEXT_PLAIN)
 public String getCurrentDateTime() {
 WorldClockApi remoteApi = RestClientBuilder.newBuilder()
 .baseUri(URI.create(WorldClockApi.BASE_URL))
 .build(WorldClockApi.class);
 Now now = remoteApi.utc();
 return now.getCurrentDateTime();
 }
}
```

`baseUri()`方法用于指定与`WorldClockApi`方法路径解析相对的服务器 URI。`build()`方法接收要构建的类型安全客户端的 Java 接口。`RestClientBuilder`的其他方法包括以下内容：

+   `baseUrl(URL)`：与`baseUri`类似，但接受`java.net.URL`类型。

+   `connectTimeout(long timeout, TimeUnit unit)`：等待连接到远程服务器的时长。值为 0 表示需要无限等待。

+   `readTimeout(long timeout, TimeUnit unit)`：在远程服务器连接的读取上等待的时间量。0 的值表示需要无限等待。

+   `executorService(ExecutorService executor)`：用于异步请求。我们将在异步部分回到这个。

# MicroProfile REST Client CDI 使用

MP-RC 类型安全的接口可以作为 CDI bean 注入。运行时必须为每个用`@RegisterRestClient`注解标记的接口创建一个 CDI bean。CDI 客户端注入创建的 bean 将包括一个限定符，`@RestClient`，以区分作为 MP-RC 注入点的使用。以下是我们`WorldClockApi`接口的更新示例，使用了`@RegisterRestClient`注解：

```java
import javax.ws.rs.GET;import javax.ws.rs.Path;import javax.ws.rs.PathParam;import javax.ws.rs.Produces;import javax.ws.rs.core.MediaType;import org.eclipse.microprofile.rest.client.inject.RegisterRestClient;@Path("/api/json")@RegisterRestClient()public interface WorldClockApi { static final String BASE_URL = "http://worldclockapi.com/api/json"; ...
```

# MicroProfile Config 集成

对于 CDI 定义的接口，可以使用 MicroProfile Config 属性来定义通过`RestClientBuilder` API 可用的附加行为。给定我们的`io.pckt.restc.contract.WorldClockApi`接口，以下 MicroProfile Config 属性可用于控制生成的代理行为：

+   `io.pckt.restc.contract.WorldClockApi/mp-rest/url`：用于此服务的基 URL，相当于`RestClientBuilder#baseUrl`方法。

+   `io.pckt.restc.contract.WorldClockApi/mp-rest/scope`：用于注入的 CDI 作用域的全限定类名；默认为`javax.enterprise.context.Dependent`。

+   `io.pckt.restc.contract.WorldClockApi/mp-rest/providers`：一个由逗号分隔的全限定提供者类名列表，用于包含在客户端中，相当于`RestClientBuilder#register`方法或`@RegisterProvider`注解。

+   `io.pckt.restc.contract.WorldClockApi/mp-rest/providers/com.mycompany.MyProvider/priority`：这将覆盖`com.mycompany.MyProvider`提供者在此接口上的优先级。

+   `io.pckt.restc.contract.WorldClockApi/mp-rest/connectTimeout`：等待连接到远程端点的超时时间，以毫秒为单位。

+   `io.pckt.restc.contract.WorldClockApi/mp-rest/readTimeout`：等待远程端点响应的超时时间，以毫秒为单位。

# 简化配置键

由于默认的 MP Config 属性名由于包含接口包名而可能较长，MP-RC 规范支持使用`@RegisterRestClient`注解的`configKey`属性来简化属性名前缀：

```java
@Path("/api/json")@RegisterRestClient(baseUri = WorldClockApi.BASE_URL, configKey = "worldClock")public interface WorldClockApi { static final String BASE_URL = "http://worldclockapi.com/api/json";...}
```

使用`worldClock`配置键，之前的属性名列表简化为以下内容：

+   `worldClock/mp-rest/url`

+   `worldClock/mp-rest/uri`

+   `worldClock/mp-rest/scope`

+   `worldClock/mp-rest/providers`

+   `worldClock/mp-rest/providers/com.mycompany.MyProvider/priority ...`

# 处理客户端头

假设您想要在 HTTP 授权头中为安全的远程服务指定凭据，但不想在客户端接口方法中有一个`authHeader`字符串参数。MP-RC 的`@ClientHeaderParam`注解可以用来指定应该发送而不改变客户端接口方法签名的 HTTP 头部。

以下示例展示了使用`@ClientHeaderParam`注解提供`User-Agent` HTTP 头的`WorldClockApi`接口的两种用法：

```java
WorldClockApiWithHeaders.java
public interface WorldClockApiWithHeaders {
 static final String BASE_URL = "http://worldclockapi.com/api/json";

 default String lookupUserAgent() {
 Config config = ConfigProvider.getConfig();
 String userAgent = config.getValue("WorldClockApi.userAgent", String.class);
 if(userAgent == null) {
 userAgent = "MicroProfile REST Client 1.2";
 }
 return userAgent;
 }

 @GET
 @Path("/utc/now")
 @Produces(MediaType.APPLICATION_JSON)
 @ClientHeaderParam(name = "User-Agent", value = "{lookupUserAgent}")
 Now utc();

 @GET
 @Path("{tz}/now")
 @Produces(MediaType.APPLICATION_JSON)
 @ClientHeaderParam(name = "User-Agent", value = "MicroProfile REST Client 1.2")
 Now tz(@PathParam("tz") String tz);
}

```

还可以使用`ClientHeadersFactory`实现批量添加或传播头部：

```java
package org.eclipse.microprofile.rest.client.ext;

public interface ClientHeadersFactory {
 MultivaluedMap<String, String> update(
    MultivaluedMap<String, String> incomingHeaders,
    MultivaluedMap<String, String> clientOutgoingHeaders);
}
```

在前面的代码片段中，`incomingHeaders`和`clientOutgoingHeaders`参数的使用方式如下：

+   `incomingHeaders`：表示入站请求的头部映射

+   `clientOutgoingHeaders`：代表在客户端接口上指定的只读头部值映射，是`@ClientHeaderParam`、`@HeaderParam`等头部值的并集

`update`方法应该返回一个`MultivaluedMap`，其中包含要与`clientOutgoingHeaders`映射合并的头部，以便将完整的头部映射发送到出站请求。提供者（如过滤器、拦截器和消息体写入器）仍然可以在发送 HTTP 请求之前修改最终的头部映射。

要启用`ClientHeadersFactory`，客户端接口必须用`@RegisterClientHeaders`注解标注。如果此注解指定了一个值，客户端实现必须调用指定`ClientHeadersFactory`实现类的实例。如果没有指定值，那么客户端实现必须调用`DefaultClientHeadersFactoryImpl`。这个默认工厂将把从入站 JAX-RS 请求中指定的头部传播到出站请求——这些头部是用逗号分隔的列表在 MicroProfile Config 属性`org.eclipse.microprofile.rest.client.propagateHeaders`中指定的。

# 高级用法的提供商注册

`RestClientBuilder`接口扩展了来自 JAX-RS 的`Configurable`接口，允许用户在构建过程中注册自定义提供商。支持的提供者的行为由 JAX-RS 客户端 API 规范定义。MP-RC 实现将支持 JAX-RS 的`ClientResponseFilter`、`ClientRequestFilter`、`MessageBodyReader`、`MessageBodyWriter`、`ParamConverter`、`ReaderInterceptor`和`WriterInterceptor`。

对于具有`ClientRequestContext`参数的`filter`方法的`ClientResponseFilter`和`ClientRequestFilter`接口，MP-RC 实现添加了一个名为`org.eclipse.microprofile.rest.client.invokedMethod`的属性，其值是一个`java.lang.reflect.Method`对象...

# 提供商优先级

提供者可以通过注解和`RestClientBuilder`进行注册。通过构建器注册的提供者将优先于`@RegisterProvider`注解。`@RegisterProvider`注解的优先级值优先于类上的任何`@javax.annotation.Priority`注解。使用`RestClientBuilder`接口上的注册方法可以覆盖提供者优先级，因为它允许优先级设置。

# 特性注册

如果注册的提供者类型是 JAX-RS`特性`，那么该`特性`设置的优先级也将作为构建器的一部分。实现维护注册提供者的总体优先级，无论它们是如何注册的。`特性`用于在运行时注册附加提供者，可以通过`@RegisterProvider`、配置或通过`RestClientBuilder`进行注册。`特性`将立即执行。因此，不考虑其优先级（特性总是执行）。

# 默认提供者

MP-RC 实现必须提供一组最小提供者，包括以下内容：

+   `*/json`类型：

    +   JSON-P, `javax.json.JsonValue`

    +   JSON-B, `javax.json.bind`

+   `*`类型：

    +   `byte[]`

    +   `java.lang.String`

    +   `java.io.InputStream`

    +   `java.io.Reader`

+   `text/plain`类型：

    +   `java.lang.Number 和其子类型`

    +   `int, long, float 和 double`

    +   `java.lang.Character 和 char`

    +   `java.lang.Boolean 和 boolean`

# 异常映射

MP-RC 为通过`org.eclipse.microprofile.rest.client.ext.ResponseExceptionMapper`接口将调用响应映射到异常提供支持：

```java
import javax.annotation.Priority;import javax.ws.rs.Priorities;import javax.ws.rs.core.MultivaluedMap;import javax.ws.rs.core.Response;import java.util.Optional;public interface ResponseExceptionMapper<T extends Throwable> {    int DEFAULT_PRIORITY = Priorities.USER;    T toThrowable(Response response);    default boolean handles(int status, MultivaluedMap<String, Object> headers) {        return status >= 400;    }    default int getPriority() {        return Optional.ofNullable(getClass().getAnnotation(Priority.class))            .map(Priority::value)            .orElse(DEFAULT_PRIORITY);    }}
```

考虑以下情况...

# 默认异常映射

每个实现提供了一个默认的`ResponseExceptionMapper`实现，当响应状态码 >= 400 时，它会将响应映射并调用`javax.ws.rs.WebApplicationException`。它的优先级为`Integer.MAX_VALUE`，旨在用作遇到错误时的回退。此映射器默认注册到所有客户端接口，但可以通过将 MP 配置属性`microprofile.rest.client.disable.default.mapper`设置为`true`来禁用它。它还可以通过在构建客户端时使用相同属性来在每个客户端上禁用：

```java
RestClientBuilder.newBuilder().property("microprofile.rest.client.disable.default.mapper",true)
```

# 异步支持

MP-RC 支持异步方法调用。当客户端接口方法返回类型为`java.util.concurrent.CompletionStage<?>`类型时，该方法是异步的。`WorldClockApi`接口的异步方法声明的替代版本，称为`WorldClockApiAsync.java`，如下所示：

```java
import java.util.concurrent.CompletionStage;import javax.ws.rs.GET;import javax.ws.rs.Path;import javax.ws.rs.PathParam;import javax.ws.rs.Produces;import javax.ws.rs.core.MediaType;@Path("/api/json")public interface WorldClockApiAsync { String BASE_URL = "http://worldclockapi.com/api/json"; @GET @Path("/utc/now") @Produces(MediaType.APPLICATION_JSON) CompletionStage<Now> utc(); @GET @Path("{tz}/now") @Produces(MediaType.APPLICATION_JSON) ...
```

# 总结

在本章中，我们学习了两个 Eclipse MicroProfile 规范，分别是 Eclipse MicroProfile OpenAPI 和 Eclipse MicroProfile REST Client。前者提供了一个规范，用于生成符合 OpenAPI 的微服务文档，后者提供了一个规范，用于以类型安全的方式调用 REST 端点。在本章中，我们介绍了这些规范的具体功能，提供了一些示例代码，并指出了如何获取关于这些规范的更多信息。您已经学习了 Eclipse MicroProfile OpenAPI 和 Eclipse MicroProfile REST Client 规范的功能和能力，如何使用它们的注解和程序化接口，以及如何将它们集成到您的应用程序中。

在下一章中，我们将讨论并深入研究市场上目前存在的 Eclipse MicroProfile 的开源实现。

# 问题

1.  您需要对提供给`/openapi`端点的信息做任何事情吗？

1.  我能否仅通过添加一两个额外的注解来增强 OpenAPI 输出？

1.  使用静态 OpenAPI 文件有什么意义？

1.  我是否需要我想要使用的 REST 端点微服务来提供 MP-REST 接口？

1.  您如何为类型安全的接口外部化基础 URL？

1.  如果需要传播传入请求头，该怎么办？


# 第三部分：MicroProfile 实现和路线图

本节将概述当前市场的实施情况以及未来项目的可能路线图。

本节包含以下章节：

+   第七章，*MicroProfile 实现、Quarkus 和通过会议应用程序实现的互操作性*


# 第八章：MicroProfile 实现、Quarkus 以及通过会议应用程序实现互操作性

Eclipse MicroProfile 的好处之一是它提供了一个规范，使得许多实现之间可以相互操作。这个好处激励了许多供应商和社区组织将 Eclipse MicroProfile 规范作为开源实现。目前市场上共有八个 Eclipse MicroProfile 实现，第九个实现者是 Quarkus。

本章将涵盖以下主题：

+   对 Eclipse MicroProfile 的八个实现以及如何找到每个实现的进一步信息的描述

+   如何为这些实现中的每一个生成 Eclipse MicroProfile 示例代码...

# 当前 MicroProfile 实现

截至编写本书时，共有八个 Eclipse MicroProfile 实现，所有这些都是开源的。以下是这些实现的表格：

| **开源项目基础** | **项目位置** | **支持供应商** |
| --- | --- | --- |
| Thorntail ([`thorntail.io/`](http://thorntail.io/)) | [`github.com/thorntail/thorntail`](https://github.com/thorntail/thorntail) | Red Hat |
| Open Liberty ([`openliberty.io/`](https://openliberty.io/)) | [`github.com/openliberty`](https://github.com/openliberty) | IBM |
| Apache TomEE ([`tomee.apache.org/`](http://tomee.apache.org/)) | [`github.com/apache/tomee`](https://github.com/apache/tomee) | Tomitribe |
| Payara Micro ([`www.payara.fish/payara_micro`](https://www.payara.fish/payara_micro)) | [`github.com/payara/Payara`](https://github.com/payara/Payara) | Payara Services Ltd. |
| Hammock ([`hammock-project.github.io/`](https://hammock-project.github.io/)) | [`github.com/hammock-project`](https://github.com/hammock-project) | Hammock |
| KumuluzEE ([`ee.kumuluz.com/`](https://ee.kumuluz.com/)) | [`github.com/kumuluz`](https://github.com/kumuluz) | KumuluzEE |
| 启动器 ([`github.com/fujitsu/launcher`](https://github.com/fujitsu/launcher)) | [`github.com/fujitsu/launcher`](https://github.com/fujitsu/launcher) | Fujitsu |
| Helidon ([`helidon.io/#`](https://helidon.io/#)) | [`github.com/oracle/helidon`](https://github.com/oracle/helidon) | Oracle |

这些实现中有一些是基于*应用程序服务器*的，如 Payara 和 Open Liberty，而其他则是基于*应用程序组装器*，只包括应用程序需要的功能，而不是要求运行一个应用程序服务器，并且通常生成可执行 JAR。然而，基于应用程序服务器的实现也具备生成可执行 JAR 的能力。

应用程序组装器可以生成一个*uberjar*，一个自包含的可运行 JAR 文件，或者一个将其运行时依赖位于子目录中的*应用程序 jar*，例如，伴随的`lib`或`libs`子目录。

符合 Eclipse MicroProfile 标准的实现通过整个伞状发布版本的**测试兼容性套件**（**TCK**），或者特定版本的 MicroProfile API 的实现，列表可在[`wiki.eclipse.org/MicroProfile/Implementation`](https://wiki.eclipse.org/MicroProfile/Implementation)找到。目前，这个列表采用荣誉制度，因为它不需要证明 TCK 的结果；它只需要发布者声明他们的实现已经通过了 TCK。

该项目还有一个网站，组织/团体可以自行加入 MicroProfile 生产部署列表。这个列表可以在[`wiki.eclipse.org/MicroProfile/Adoptions`](https://wiki.eclipse.org/MicroProfile/Adoptions)找到。

在下一节中，我们提供了这些实现简要介绍以及如何获取关于它们的更多信息。

# Thorntail

红帽公司是开源 Thorntail 项目的赞助商，该项目实现了 Eclipse MicroProfile 规范。Thorntail 是一个应用程序组装器，它只包含您的应用程序所需的服务器运行时组件，并创建一个可执行的 JAR（即 uberjar），您可以通过调用以下命令来执行：

```java
$ java -jar <executable JAR file>
```

不仅 Thorntail 符合 MicroProfile，它还可以在您的应用程序中包含超出 MicroProfile 的功能。它有一个分数的概念，这是一个包含您想要包含在应用程序中的功能的特定库。分数作为您应用程序的 Maven POM 文件的一个依赖项。超出 MicroProfile ...

# Open Liberty

IBM 是开源 Open Liberty 项目的赞助商，该项目实现了 Eclipse MicroProfile 规范。Open Liberty 是 IBM WebSphere Liberty 应用服务器的上游开源项目。Open Liberty 是一个能够生成 uberjar 的应用服务器，其中包含您的应用程序以及内嵌的 Open Liberty 服务器。要运行 uberjar，您需要输入以下命令：

```java
$ java -jar <executable JAR file>
```

此命令将把 JAR 文件解压到您的用户名临时目录中，然后从那里执行应用程序。

确保 JAR 文件路径中没有空格，否则启动过程将失败。

生成的 uberjar 只能包含`server.xml`文件中包含的功能的子集。要使用这些最小功能集构建 uberjar，您需要在运行 Maven 时使用`minify-runnable-package`配置文件。

Open Liberty 文档非常全面，充满了指南和参考文献。

您可以在[`openliberty.io/docs/`](https://openliberty.io/docs/)找到 Open Liberty 文档。

在他们的文档中，他们有一个专门介绍 MicroProfile 指南的部分，提供了文档齐全的教程。

# Apache TomEE

托米部落（Tomitribe）是开源 TomEE 项目的赞助商，该项目实现了 Eclipse MicroProfile 规范。Apache TomEE 是由 Apache Tomcat 组装而成，增加了 Java EE 特性。TomEE 是 Java EE 6 Web Profile 认证的。正如其 GitHub 所描述的，*Apache TomEE 是一个轻量级但功能强大的 Java EE 应用服务器，拥有丰富的功能工具*。您可以下载几个不同版本的 TomEE，例如 TomEE、TomEE+、TomEE WebApp，但我们感兴趣的是 TomEE MicroProfile。对于 MicroProfile，TomEE 为您生成了一个 uberjar，您可以像以下这样运行：

```java
$ java -jar <executable JAR file>
```

尽管 TomEE MicroProfile 文档不多，但有一套详尽的...

# 帕雅拉（Payara）

帕雅拉（Payara）是开源 Payara Micro 项目的赞助商，该项目实现了 Eclipse MicroProfile 规范。Payara 服务器基于开源应用服务器 GlassFish。Payara Micro 是基于 Payara Server 的一个精简版本。正如他们的网站所描述的，*Payara Micro 是 Payara Server 的适用于微服务的版本*。

Payara Micro 的工作方式是 Payara Micro 实例启动，然后将 MicroProfile 微服务作为 WAR 文件部署到其中。例如，要启动一个 Payara Micro 实例，您将输入以下命令：

```java
$ java -jar payara-micro.jar
```

要启动 Payara Micro 实例并将您的应用程序部署到其中，您将输入以下命令：

```java
$ java -jar payara-micro.jar --deploy <WAR file>
```

Payara Micro 支持 Java EE 应用程序部署，并且与 Eclipse MicroProfile 兼容。

对于 Payara Micro 文档，请参考[`docs.payara.fish/documentation/payara-micro/payara-micro.html`](https://docs.payara.fish/documentation/payara-micro/payara-micro.html)。

最后，Payara Micro 通过使用第三方内存内数据网格产品支持自动集群。

# 吊床

约翰·阿门特（John Ament）是开源 Hammock 项目的赞助商，该项目实现了 Eclipse MicroProfile 规范。与 Thorntail 相似，Hammock 是一个应用程序组装器，生成 uberjars。要运行 uberjar，您需要输入以下命令：

```java
$ java -jar <executable JAR file>
```

吊床是一个有观点的微服务框架，用于构建应用程序。它是一个基于 CDI 的框架，意味着它是基于 CDI 容器的，CDI 基于的 bean 在其中运行。它支持两种 CDI 实现（JBoss Weld 和 Apache OpenWebBeans），三种 JAX-RS 实现（Apache CXF、Jersey 和 JBoss RestEasy），以及三种不同的 servlet 容器（Apache Tomcat、JBoss Undertow 和 Eclipse Jetty）。除此之外，Hammock 还...

# 库穆鲁兹（KumuluzEE）

Sunesis 是开源 KumuluzEE 项目的赞助商，该项目实现了 Eclipse MicroProfile 规范。KumuluzEE 定义了自己作为一个使用 Java 和 Java EE 技术的轻量级微服务框架，并且是 Eclipse MicroProfile 兼容的实现。KumuluzEE 允许你使用仅需要的组件来引导一个 Java EE 应用程序，并且还支持将微服务打包和作为 uberjars 运行。与其他支持 uberjars 的实现一样，你可以通过输入以下命令来运行你的微服务：

```java
$ java -jar <executable JAR file>
```

KumuluzEE 还提供了一个 POM 生成器，它可以创建一个带有所选选项和功能的 `pom.xml`，用于你计划开发的微服务。POM 生成器提供了由 KumuluzEE 支持的可选的清晰和组织的列表，包括在 `pom.xml` 文件中。

KumuluzEE 为不同的 MicroProfile API 提供了一些示例。

有关 KumuluzEE 实现 Eclipse MicroProfile 的文档，请参考 [`ee.kumuluz.com/microprofile`](https://ee.kumuluz.com/microprofile)。

最后，KumuluzEE 提供了一些有趣的教程在 [`ee.kumuluz.com/tutorials/`](https://ee.kumuluz.com/tutorials/)。

# 启动器

Fujitsu 是开源 Launcher 项目的赞助商，该项目实现了 Eclipse MicroProfile 规范。Launcher 利用了内嵌的 GlassFish 服务器和 Apache Geronimo MicroProfile API 实现。你可以将你的微服务作为 WAR 文件运行，如下所示：

```java
$ java -jar launcher-1.0.jar --deploy my-app.war
```

此外，Launcher 可以创建 uberjars。要创建并运行你的微服务作为 uberjar，首先生成 uberjar，然后使用 `java -jar` 调用它，如下所示：

```java
$ java -jar launcher-1.0.jar --deploy my-app.war --generate my-uber.jar$ java -jar my-uber.jar
```

有关 Launcher 的文档非常稀少且有限。你可以找到有关 Launcher 的使用信息在 [`github.com/fujitsu/launcher/blob/master/doc/Usage.adoc ...`](https://github.com/fujitsu/launcher/blob/master/doc/Usage.adoc)。

# Helidon

Oracle Corporation 是开源 Helidon 项目的赞助商，该项目实现了 Eclipse MicroProfile 规范。Helidon 是一组 Java 库，可让开发者编写微服务。它利用了 Netty，一个非阻塞的 I/O 客户端服务器框架。Helidon 是一个应用程序组装器，因为它可以生成应用程序 JAR。一旦你构建了应用程序 JAR，你可以使用以下命令执行它：

```java
$ java -jar <executable JAR file>
```

Helidon 有两种版本：SE 和 MP。Helidon SE 是由所有 Helidon 库提供的功能编程风格，它提供了一个名为 MicroFramework 的微服务框架。Helidon MP 实现了微服务的 MicroProfile 规范，并建立在 Helidon 库之上。没有样本项目生成工具，但 Helidon 提供了一组丰富且详尽的文档手册。

Helidon 的文档可以在 [`helidon.io/docs/latest/#/about/01_overview`](https://helidon.io/docs/latest/#/about/01_overview) 找到。

Helidon SE 提供了一个 WebServer，这是一个用于创建 Web 应用程序的异步和反应式 API。Helidon MP 提供了一个封装 Helidon WebServer 的 MicroProfile 服务器实现。

# 为当前实现生成示例代码

如前几节所述，大多数 MicroProfile 实现并没有提供自己的示例项目生成器。相反，它们只提供文档。这时 MicroProfile Starter 就派上用场了！

MicroProfile Starter 由 MicroProfile 社区赞助，是一个为所有通过 MicroProfile TCK 的 MicroProfile 规范生成示例项目和源代码的工具。在第二章*治理和贡献*中，我们为您提供了 MicroProfile Starter 的概览。为了避免重复，我们只想指出您可以在下拉菜单中选择 MicroProfile 版本如下：...

# 其他实现 MicroProfile 的项目

小型 Rye 是一个开源项目，它开发了任何供应商或项目都可以使用的 Eclipse MicroProfile 实现。这是一个社区努力，每个人都可以参与和贡献给小型 Rye,[`smallrye.io`](https://smallrye.io)。作为一个例子，社区最近将微服务扩展项目贡献给了小型 Rye，从而使其通过配置源、OpenAPI、健康、JAX-RS 和 REST 客户端扩展丰富了其功能。

微服务扩展项目网站是[`www.microprofile-ext.org`](https://www.microprofile-ext.org)，其 GitHub 是[`github.com/microprofile-extensions`](https://github.com/microprofile-extensions)。

小型 Rye 实现已经通过了 Eclipse MicroProfile TCKs 的测试。

消费小型 Rye 的开源项目有 Thorntail([`thorntail.io`](https://thorntail.io))、WildFly([`wildfly.org`](https://wildfly.org))和 Quarkus([`quarkus.io`](https://quarkus.io))。

# Quarkus

开源的 Quarkus 项目于 2019 年首次亮相。Quarkus 是一个可以编译成原生机器语言或构建到 HotSpot（OpenJDK）的 Kubernetes 本地 Java 栈。使用 Quarkus 时，您的应用程序消耗非常少的内存，具有出色的性能，可以处理高调用吞吐量，并且启动时间非常快（即引导加上首次响应时间），使 Quarkus 成为容器、云本地和无服务器部署的绝佳运行时。Quarkus 还提供了一个扩展框架，允许将库和项目*quarking*（注：此处应为“转化为 Quarkus 兼容的形式”），使它们与 Quarkus 无缝协作。

Quarkus 的使命是将您的整个应用程序及其使用的库转换为最优...

# 如何将生成的 MicroProfile 项目*quarking*

在我们开始讲解如何使用 MicroProfile Starter*quark*生成 MicroProfile 项目的步骤之前，我们首先需要确保已经在您的环境中安装、定义和配置了 GRAALVM_HOME。为此，请按照以下步骤操作：

1.  访问`https://github.com/oracle/graal/releases`，并根据您的操作系统下载 GraalVM 的最新版本。

1.  将下载的文件解压缩到您选择的子目录中。顺便说一下，解压缩将创建一个 GraalVM 子目录，例如：

```java
$ cd $HOME
$ tar -xzf graalvm-ce-1.0.0-rc16-macos-amd64.tar.gz
```

1.  打开一个终端窗口，创建一个名为`GRAALVM_HOME`的环境变量，例如：

```java
$ export GRAALVM_HOME=/Users/[YOUR HOME DIRECTORY]/graalvm-ce-1.0.0-rc13/Contents/Home
```

既然我们已经安装了 GraalVM，我们可以继续讲解如何使用 MicroProfile Starter*quark*生成 MicroProfile 项目的步骤：

1.  首先，将您的浏览器指向[`start.microprofile.io`](https://start.microprofile.io)并选择 Thorntail 作为 MicroProfile 服务器。

您可以利用以下步骤将任何现有的 Java 应用程序*quark*化。

如果您不记得如何进行此操作，请转到第二章，*治理和贡献*，并遵循*MicroProfile Starter 快速入门*部分中的说明，直到第 5 步，其中`demo.zip`文件下载到您的本地`Downloads`目录。

1.  使用您喜欢的解压缩工具展开`demo.zip`文件。如果您没有自动展开`demo.zip`文件，请使用以下命令（假设是 Linux；对于 Windows，请使用等效命令）：

```java
$ cd $HOME/Downloads
$ unzip demo.zip
```

这将创建一个名为`demo`的子目录，在其下有一个完整的目录树结构，包含所有使用 Maven 构建和运行 Thorntail 示例 MicroProfile 项目的源文件。

1.  与其在`demo`子目录中进行更改，不如让我们创建一个名为`Qproj4MP`的第二个目录，与`demo`子目录并列，如下所示：

```java
$ mkdir $HOME/Downloads/Qproj4MP
```

这将在您`Downloads`目录中现有`demo`子目录的同级创建一个名为`Qproj4MP`的子目录。

1.  将您的目录更改到`Qproj4MP`，并通过输入以下命令创建一个空的 Quarkus 项目：

```java
$ cd $HOME/Downloads/Qproj4MP
$ mvn io.quarkus:quarkus-maven-plugin:0.12.0:create \
 -DprojectGroupId=com.example \
 -DprojectArtifactId=demo \
 -Dextensions="smallrye-health, smallrye-metrics, smallrye-openapi, smallrye-fault-tolerance, smallrye-jwt, resteasy, resteasy-jsonb, arc"
```

1.  在`Qproj4MP`目录中，删除`src`子目录并用以下命令替换为 Thorntail 示例 MicroProfile 项目的`src`子目录：

```java
$ cd $HOME/Downloads/Qproj4MP  # ensuring you are in the Qproj4MP sub-directory
$ rm -rf ./src
$ cp -pR $HOME/Downloads/demo/src .
```

1.  Quarkus 和 Thorntail 对某些配置和 web 应用程序相关文件的位置有不同的期望。因此，为了使 Quarkus 满意，让我们通过输入以下命令来复制一些文件：

```java
$ cd $HOME/Downloads/Qproj4MP # ensuring you are in the Qproj4MP sub-directory
$ mkdir src/main/resources/META-INF/resources
$ cp /Users/csaavedr/Downloads/demo/src/main/webapp/index.html src/main/resources/META-INF/resources
$ cp -p src/main/resources/META-INF/microprofile-config.properties src/main/resources/application.properties
```

我们本可以将这些文件从它们原来的位置移动，但我们选择在这个示例中只是复制它们。

1.  MicroProfile Starter 生成的 Thorntail 示例 MicroProfile 项目，其`src`子目录的内容你已经复制到了`Qproj4MP`，使用了一个名为`bouncycastle`的安全库。这是因为生成的代码包含了一个 MicroProfile JWT Propagation 规范的示例，该规范允许你在微服务之间传播安全性。因此，我们还需要在 Quarkus 项目的 POM 文件中再添加两个依赖，一个是`bouncycastle`，另一个是`nimbusds`。

下一个 sprint 版本的 MicroProfile Starter 将不再包含 Thorntail 服务器代码生成中的`bouncycastle`依赖。

为了添加这些依赖项，请编辑你`$HOME/Downloads/Qproj4MP`目录下的`pom.xml`文件，并在`<dependencies>`部分输入以下代码块：

```java
 <dependency>
 <groupId>org.bouncycastle</groupId>
 <artifactId>bcpkix-jdk15on</artifactId>
 <version>1.53</version>
 <scope>test</scope>
 </dependency>
 <dependency>
 <groupId>com.nimbusds</groupId>
 <artifactId>nimbus-jose-jwt</artifactId>
 <version>6.7</version>
 <scope>test</scope>
 </dependency>
```

现在我们准备编译 quarked 的 MicroProfile 项目。

1.  除了支持构建可以在 OpenJDK 上运行的 Java 项目外，Quarkus 还支持将 Java 项目编译到底层机器码。输入以下命令来编译 quarked 示例项目到原生代码：

```java
$ cd $HOME/Downloads/Qproj4MP # ensuring you are in the Qproj4MP sub-directory
$ ./mvnw package -Pnative
```

1.  要运行应用程序，请输入以下命令：

```java
$./target/demo-1.0-SNAPSHOT-runner
```

要测试应用程序，请遵循*Quick tour of MicroProfile Starter*章节中*治理和贡献*部分的说明，从第 10 步开始。

1.  如果你想要在开发模式下运行 quarked 项目，首先停止正在运行的进程，然后输入以下命令：

```java
$ cd $HOME/Downloads/Qproj4MP # ensuring you are in the Qproj4MP sub-directory
$ ./mvnw compile quarkus:dev
```

在此阶段，你可以选择一个 IDE，比如 Visual Studio Code 或 Eclipse IDE，来打开项目，并开始修改源代码。Quarkus 支持热重载，这意味着，只要你对源代码做了任何更改，Quarkus 会在后台重新构建并重新部署你的应用程序，这样你就可以立即看到并测试更改的效果。此外，如果你在源代码中犯了语法错误，Quarkus 会将有意义的错误信息传播到网页应用程序中，帮助你修复错误，提高你的工作效率。

1.  如果你想要生成一个可执行的应用程序 JAR，请输入以下命令：

```java
$ cd $HOME/Downloads/Qproj4MP # ensuring you are in the Qproj4MP sub-directory
$ ./mvn clean package
```

1.  要运行可执行的应用程序 JAR，请输入以下命令：

```java
$ java -jar target/demo-1.0-SNAPSHOT-runner.jar
```

创建一个与应用程序 JAR 并列的 lib 目录，其中包含运行所需的所有库文件。

我们向您展示了使用 MicroProfile Starter 生成的 MicroProfile 项目的*quark*步骤。尽管这些步骤适用于特定的生成项目，但您可以使用相同的说明来*quark*一个现有的 Java 应用程序或微服务，以便您可以利用 Quarkus 提供的好处，如低内存消耗、快速的启动时间以及对 Java 代码的原生编译，以便您可以在容器、云和函数即服务环境中高效运行。无论您使用 MicroProfile 的哪个实现，MicroProfile 为最终用户提供的很大好处就是互操作性。这意味着您可以设计一个使用不同 MicroProfile 实现的微服务应用程序，这是下一节的主题。

# MicroProfile 互操作性——会议应用程序

**会议应用程序**，首次介绍（[`www.youtube.com/watch?v=iG-XvoIfKtg`](https://www.youtube.com/watch?v=iG-XvoIfKtg)）于 2016 年 11 月在比利时 Devoxx 上，是一个展示不同 MicroProfile 供应商实现集成和互操作性的 MicroProfile 演示。这很重要，因为它展示了规范的实现和接口之间的分离，提供了一个允许供应商开发并提供自己的实现的平台，这些实现可以与其他竞争性实现共存。所有实现中的通用接口还为最终用户提供了使用任何 MicroProfile 实现...的好处。

# 总结

在本章中，我们了解了市场上现有的开源 MicroProfile 实现，它们是什么类型的实现，如何获取关于它们的更多信息，以及如何使用 MicroProfile Starter 为这些实现生成示例代码。我们还介绍了最新的 MicroProfile 实现参与者 Quarkus，它显著提高了 Java 在解释和编译模式下的启动时间和内存消耗，进一步优化了适用于云原生微服务和无服务器环境的 MicroProfile。您还了解了 The Conference Application，它展示了 MicroProfile 在不同实现之间的互操作性。

作为 Eclipse MicroProfile 的消费者，其跨实现互操作的特性，您有自由选择对您的组织最有意义或最适合您环境的实现，最终给您提供选择正确工具的正确任务的选项。此外，您不必局限于单一供应商的商业支持版 Eclipse MicroProfile，因此，您可以根据自己的条件进行谈判，并从不同供应商提供的丰富的 MicroProfile 特性中进行选择。

在下一章，我们将涵盖整个 MicroProfile API 集的全代码示例。

# 问题

1.  目前市场上存在多少种 MicroProfile 实现？请列出它们。

1.  应用服务器与应用组装器之间有什么区别？

1.  描述市场上存在的八种 MicroProfile 实现。

1.  什么是 Quarkus？

1.  编译时启动是什么？

1.  Quarkus 适用于哪种类型的部署？

1.  什么是 Quarkus 扩展框架？

1.  会议应用程序展示了什么关键优势？


# 第四部分：一个工作的 MicroProfile 示例

本部分将介绍一个展示 MicroProfile 的应用程序。

本部分包含以下章节：

+   第八章，*一个工作的 Eclipse MicroProfile 代码示例*


# 第九章：一个工作的 Eclipse MicroProfile 代码示例

在本章中，我们将讨论一个使用本书前面介绍的各种 MicroProfile 功能的示例应用程序。在本章中，我们将使用的 MicroProfile 运行时是 Quarkus 运行时，这是一个为 GraalVM 和 OpenJDK HotSpot 量身定制的 Kubernetes 原生 Java 堆栈，由最佳的 Java 库和标准组成。我们将要涵盖的关键主题包括以下内容：

+   应用程序和 MicroProfile 容器行为的使用配置

+   现实的健康检查

+   使用外部 JWT 安全提供程序保护应用程序

+   使用 Jaeger 实例集成并查看跟踪信息

+   使用 Swagger 检查微服务端点信息

+   查看个体...

# 技术要求

为本章，我们需要以下内容：

+   一个集成开发环境（IDE）

+   JDK 1.8+安装并配置了`JAVA_HOME`

+   Apache Maven 3.5.3+

+   一个运行中的 Docker 环境

本章的代码可以在[`github.com/PacktPublishing/Hands-On-Enterprise-Java-Microservices-with-Eclipse-MicroProfile/tree/master/Chapter08-mpcodesample`](https://github.com/PacktPublishing/Hands-On-Enterprise-Java-Microservices-with-Eclipse-MicroProfile/tree/master/Chapter08-mpcodesample)找到。

本章中的示例可以通过 GraalVM([`github.com/oracle/graal/releases/tag/vm-1.0.0-rc16`](https://github.com/oracle/graal/releases/tag/vm-1.0.0-rc16))与 Quarkus 的集成编译成原生二进制。这需要安装 1.0-RC16 版本的 Graal VM 和一个运行中的 C 开发环境，以及一个工作环境。关于生成原生镜像的详细要求，可以在[`quarkus.io/guides/building-native-image-guide`](https://quarkus.io/guides/building-native-image-guide)找到。

# 多服务 MicroProfile 应用程序的示例架构

本章我们将要介绍的示例应用程序由一个 HTML 前端、两个基于 MicroProfile 的微服务、两个我们使用 Docker 启动的外部服务以及一个我们无法控制的网络上的外部时间服务组成。我们示例应用程序的架构如下所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-etp-java-msvc-eclp-mprf/img/fa068f6a-caf2-45db-b56f-b288d4bf73db.png)

此图中的关键元素包括以下内容：

+   **Svcs1 Image**：这是一个使用 Quarkus 运行时的 REST 端点的集合，其中包括了 MP-HC、MP-Metrics、MP-OT、MP-JWT、MP-OAPI、MP-FT 和 MP-RC。

+   **Svcs2 Image**：这是一组使用...的 REST 端点集合

# 运行示例应用程序

示例应用程序设计为从四个不同的 shell 运行，让我们将它们组织成四个 shell 窗口，如图所示：

| Docker Shell | Web Shell |
| --- | --- |
| Svcs1 Shell | Svcs2 Shell |

在每一个 shell 中，运行以下相应命名的部分中概述的命令。

# Docker shell 命令

提供预配置的服务器/服务的一种常见方法是使用包含服务和所有依赖项的 Docker 镜像。在这个例子中，我们使用 Docker 来运行 KeyCloak 和 Jaeger 镜像。如果你不熟悉 Docker 或者没有安装`docker`命令，请参阅安装 Docker 的说明，针对你的平台[`docs.docker.com/v17.12/install/`](https://docs.docker.com/v17.12/install/)。

本项目依赖于 KeyCloak 生成 MP-JWT 令牌。要启动 KeyCloak Docker 容器，请在你的壳中运行以下命令：

```java
docker run -d --name keycloak -e KEYCLOAK_USER=admin -e KEYCLOAK_PASSWORD=admin -p 8180:8180 -v `pwd`/packt-mp-realm.json:/config/quarkus-packt.json -it jboss/keycloak:6.0.1 -b 0.0.0.0 ...
```

# 服务 1 壳命令

接下来，在你之前被要求打开的 Svcs1 终端窗口中，导航到项目的`svcs1`子目录，然后运行以下命令以在开发模式下执行`svcs1`镜像：

```java
mvn compile quarkus:dev
```

你将看到以下输出：

```java
Scotts-iMacPro:svcs1 starksm$ mvn compile quarkus:dev
[INFO] Scanning for projects...
...
20:56:27 INFO [io.quarkus]] (main) Quarkus 0.15.0 started in 2.492s. Listening on: http://[::]:8081
20:56:27 INFO [io.quarkus]] (main) Installed features: [cdi, jaeger, resteasy, resteasy-jsonb, security, smallrye-fault-tolerance, smallrye-health, smallrye-jwt, smallrye-metrics, smallrye-openapi, smallrye-opentracing, smallrye-rest-client, swagger-ui]
```

在输出中，我们看到这个实例正在监听`8081`端口的 HTTP 请求，并且我们看到了各种支持我们微服务特征使用的 Quarkus 特性。

# 服务 2 壳命令

接下来，在你之前被要求打开的 Svcs2 终端窗口中，切换到项目的`svcs2`子目录，然后运行以下命令以构建`svcs2`镜像：

```java
mvn clean package
```

构建完成后，要运行`svcs2` JAR，请输入以下命令：

```java
 java -jar target/sample-svcs2-runner.jar
```

你会得到以下输出：

```java
Scotts-iMacPro:svcs2 starksm$ java -jar target/sample-svcs2-runner.jar...20:58:55 INFO [io.quarkus]] (main) Quarkus 0.15.0 started in 0.936s. Listening on: http://[::]:808220:58:55 INFO [io.quarkus]] (main) Installed features: [cdi, jaeger, resteasy, resteasy-jsonb, security, smallrye-health, smallrye-jwt, smallrye-metrics, smallrye-opentracing, smallrye-rest-client]
```

在这里，我们...

# 网页壳命令

接着，在你之前被要求打开的 Web 壳终端窗口中，克隆这个项目到你的电脑，切换到`web`子目录，然后运行以下命令以在开发模式下执行 Web 应用程序：

```java
mvn clean package

```

构建完成后，要运行 Web 子项目 JAR，请输入以下命令：

```java
java -jar target/sample-web-runner.jar

```

一旦应用程序启动运行，将你的浏览器指向[`localhost:8080/index.html`](http://localhost:8080/index.html)的 Web 应用程序。在下一节中，我们将回顾 Web 应用程序的详细信息。

# 示例应用程序的详细信息

让我们详细讨论我们应用程序中的各种标签页。

# 配置标签页

应用程序的初始视图显示了配置标签页，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-etp-java-msvc-eclp-mprf/img/c919e34a-eaea-4f7e-9ae8-2dfba21c976e.png)

页面上的三个链接指的是`Chapter08-mpcodesample/svcs1`子项目中的`io.packt.sample.config.ConfigTestController`类中的参考端点。点击各个链接会显示 MP-Config 值。前一个屏幕截图中显示的值对应于第二个链接和`injected.piValue`配置值。以下是`Chapter08-mpcodesample/svcs1/src/main/resources/application.properties`中的相关设置：

```java
# MP Config values for ConfigTestController
injected.value=Injected value
injected.piValue=3.1415926532
lookup.value=A Lookup value
```

此处值得注意的是，通过在`ConfigTestController`中的`@ConfigProperty(name = "injected.piValue", defaultValue = "pi5=3.14159")`注解中覆盖了默认的五位数字值，设置为前一个屏幕截图中显示的完整 10 位π值。

# 健康标签页

点击应用的“健康”标签页会显示如下页面：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-etp-java-msvc-eclp-mprf/img/13372fe8-e683-4dde-8cad-a06d611177b2.png)

页面上的链接对应于`svcs1`和`svcs2`镜像的`health`检查端点。选择任何一个都会显示该镜像的`health`检查输出。`svcs1`镜像的`health`检查由`io.packt.sample.health.ServiceHealthCheck`和`io.packt.sample.health.CheckDiskspace`组成。此外，`ServiceHealthCheck`只是一个总是返回运行状态的模拟实现。`CheckDiskspace`健康检查程序查看使用 MP-Config `health.pathToMonitor`属性设置的路径，然后根据...设置程序状态为运行/停止。

# “指标”选项卡

“指标”选项卡显示以下包含三个链接的视图：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-etp-java-msvc-eclp-mprf/img/18e4884e-02d6-4796-ac68-4c560d3d8e7e.png)

第一个链接访问`io.packt.sample.metric.MetricController`类中的以下端点：

```java
@Path("timed")
@Timed(name = "timed-request")
@GET
@Produces(MediaType.TEXT_PLAIN)
public String timedRequest() {
    long start = System.currentTimeMillis();
    // Demo, not production style
    int wait = new Random().nextInt(1000);
    try {
        Thread.sleep(wait);
    } catch (InterruptedException e) {
        // Demo
        e.printStackTrace();
    }
    long end = System.currentTimeMillis();
    long delay = end - start;

    doIncrement();
    long count = getCustomerCount();
    return String.format("MetricController#timedRequest, delay[0-1000]=%d, 
    count=%d", delay, count);
}
```

这使用`@Timed(name = "timed-request")`注解注解了`timed`路径端点。该方法使用 0-1000 毫秒之间的随机延迟生成响应时间分布。下一个链接是直接链接到`timedRequest()`方法的应用程序级指标。MP-Metrics 规范将路径定义为`metrics/application/io.packt.sample.metric.MetricController.timed-request`。在访问第一个链接生成一系列响应时间之后，通过访问第二个链接获取`timedRequest()`方法指标将显示如下：

```java
# TYPE application:io_packt_sample_metric_metric_controller_timed_request_rate_per_second gauge
application:io_packt_sample_metric_metric_controller_timed_request_rate_per_second 0.4434851530761856
# TYPE application:io_packt_sample_metric_metric_controller_timed_request_one_min_rate_per_second gauge
application:io_packt_sample_metric_metric_controller_timed_request_one_min_rate_per_second 0.552026648777594
...
# TYPE application:io_packt_sample_metric_metric_controller_timed_request_seconds summary
application:io_packt_sample_metric_metric_controller_timed_request_seconds_count 6.0
application:io_packt_sample_metric_metric_controller_timed_request_seconds{quantile="0.5"} 0.923901552
...
application:io_packt_sample_metric_metric_controller_timed_request_seconds{quantile="0.999"} 0.970502841
```

这是`@Timed`样式指标生成的信息范围。最后一个链接访问返回镜像中所有可用指标的`metrics`端点。

# “OpenTracing”选项卡

“OpenTracing”选项卡显示以下带有两个链接的视图：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-etp-java-msvc-eclp-mprf/img/fdac27b8-b33b-4f90-aa6f-b0a3d6863ff4.png)

第一个链接访问以下`io.packt.sample.tracing.TracedEndpoint`方法：

```java
@GET@Path("/randomDelay")@Produces(MediaType.TEXT_PLAIN)@Traced(operationName = "TracedEndpoint#demoRandomDelay")public String randomDelay() {    long start = System.currentTimeMillis();    // 0-5 seconds random sleep    long sleep = Math.round(Math.random() * 5000);    try {        Thread.sleep(sleep);    } catch (InterruptedException e) {        e.printStackTrace();    }    long end = System.currentTimeMillis();    return String.format("TracedEndpoint.randomDelay[0-5000], elapsed=%d",     (end - start));}
```

方法...

# “OpenAPI”选项卡

“OpenAPI”选项卡视图包含两个链接，如下屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-etp-java-msvc-eclp-mprf/img/1313c2c2-2ebb-4ca9-81b5-0a8cbcdf3c96.png)

第一个链接生成一个 OpenAPI 文档，一个包含应用程序中所有端点描述的 YAML 文件。这可以输入到其他能够消费 OpenAPI 格式的程序或应用程序中。第二个链接是此类应用程序的一个示例，即 Swagger UI。打开该链接将打开一个类似于以下的新窗口：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-etp-java-msvc-eclp-mprf/img/176d8da0-5532-4a16-aac2-fd92224543d4.png)

此示例应用视图包含三个部分。第一部分是在 JAX-RS 应用 bean 上通过 OpenAPI 注解指定的信息，如下代码片段所示：

```java
@ApplicationPath("/demo1")
@LoginConfig(authMethod = "MP-JWT", realmName = "quarkus-quickstart")
@OpenAPIDefinition(
    info = @Info(
        title = "Quarkus MicroProfile 2.2 Extensions Demo",
        version = "1.0",
        contact = @Contact(
            name = "QUARKUS - COMMUNITY",
            url = "https://quarkus.io/community/",
            email = "quarkus-dev+subscribe@googlegroups.com"),
        license = @License(
            name = "Apache 2.0",
            url = "http://www.apache.org/licenses/LICENSE-2.0.html")
    ),
    servers = {
        @Server(url = "http://localhost:8080/", description = "demo1 host"),
        @Server(url = "http://localhost:8081/", description = "demo2 host")
    },
    externalDocs = @ExternalDocumentation(url="http://microprofile.io", description = 
    "Eclipse MicroProfile Homepage")
)
public class DemoRestApplication extends Application {
...
```

将此信息与 Swagger UI 中显示的信息进行比较，可以看出所有`@OpenAPIDefinition`注解的信息都已经被整合到了 UI 顶部。Swagger UI 的下一个部分，带有`time`和`default`子标题的部分对应于从应用程序 REST 端点获取的操作信息。`default`部分对应于没有包含任何 OpenAPI 规范注解的端点。对于应用程序中发现的任何 JAX-RS 端点，都会有一个默认行为来创建一个 OpenAPI 端点定义。

`time`部分对应于以下`io.packt.sample.restclient.TimeService`端点代码片段，该片段包含了`@Tag`、`@ExternalDocumentation`和`@Operation` MP-OpenAPI 注解：

```java
@GET
@Path("/now")
@Produces(MediaType.APPLICATION_JSON)
@Tag(name = "time", description = "time service methods")
@ExternalDocumentation(description = "Basic World Clock API Home.",
    url = "http://worldclockapi.com/")
@Operation(summary = "Queries the WorldClockApi using the MP-RestClient",
    description = "Uses the WorldClockApi type proxy injected by the 
    MP-RestClient to access the worldclockapi.com service")
public Now utc() {
    return clockApi.utc();
}
```

如果您展开时间部分下的第一个操作，您将获得一个这样的视图：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-etp-java-msvc-eclp-mprf/img/6b5ab70d-40c6-4a23-9cd7-6fbee406239b.png)

您可以看到`@Tag`已经定义了时间部分及其描述，而`@Operation`注解已经增强了操作摘要和描述部分。这显示了您可以如何使用 MP-OAPI 注解和像 Swagger UI 这样的 OpenAPI 感知应用程序为您的端点的消费者提供更多信息。

# 密钥保管库标签

接下来我们跳到密钥保管库标签，因为 RestClient 和 JWT 标签包括需要 JWT 才能访问端点的受保护调用。当你第一次访问密钥保管库标签时，它应该看起来像这样：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-etp-java-msvc-eclp-mprf/img/75d20658-d086-43be-8eef-324fcae0bea6.png)

它不会显示任何令牌信息，状态行应在刷新复选框下方指示（未认证）。点击绿色的登录按钮，将出现以下登录屏幕：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-etp-java-msvc-eclp-mprf/img/fc49cde6-aa33-4c09-8c30-6beca3e6a967.png)

分别输入以下内容作为用户名和密码字段：

+   `packt-mp-book`

+   `password`

这...

# JWT 标签

在点击 JWT 标签后，您应该看到一个类似于以下内容的视图，其中有两个端点链接：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-etp-java-msvc-eclp-mprf/img/d7875e8b-4474-48c4-b850-279881c58802.png)

第一个链接向一个未受保护的端点发起请求，如果存在的话，它将打印 JWT 中的名称以及`upn`声明。

然而，由于 Web 前端没有为这个请求提供 JWT，输出部分将显示以下内容：

```java
Hello[open] user=anonymous, upn=no-upn
```

点击第二个链接可以访问该端点的受保护版本，其中包含此代码片段：

```java
public class JwtEndpoint {
    @Inject
    private JsonWebToken jwt;
    @Inject
    @Claim(standard = Claims.raw_token)
    private ClaimValue<String> jwtString;
    @Inject
    @Claim(standard = Claims.upn)
    private ClaimValue<String> upn;
    @Context
    private SecurityContext context;
...
    @GET
    @Path("/secureHello")
    @Produces(MediaType.TEXT_PLAIN)
    @RolesAllowed("user") // 1
    public String secureHello() {
        String user = jwt == null ? "anonymous" : jwt.getName(); // 2
        String scheme = context.getAuthenticationScheme(); // 3
        boolean isUserInRole = context.isUserInRole("PacktMPUser"); // 4
        return String.format("Hello[secure] user=%s, upn=%s, scheme=%s, 
        isUserInRole(PacktMPUser)=%s", user, upn.getValue(), 
        scheme, isUserInRole);
    }
```

让我们讨论重要的行：

1.  `@RolesAllowed("user")`注解表明该端点是受保护的，调用者需要`user`角色。我们之前看到的 JWT`groups`声明就是这个角色。

1.  用户通过`getName()`方法从 JWT 获取。如 MP-JWT 章节中所解释，这映射到 JWT 中的`upn`声明。

1.  当前的安全认证方案是从注入的`SecurityContext`中获取的。

1.  通过检查调用者是否具有`PacktMPUser`角色来进行程序安全检查。由于我们之前看到的 JWT 群组声明具有此角色，因此检查将返回真。

这些信息被组合成一个字符串，它是`secureHello`方法的返回值。点击 demo1/jwt/secureHello 链接按钮，在响应区域产生以下输出字符串：

```java
Hello[secure] user=packt-mp-book, upn=packt-mp-book, scheme=MP-JWT, isUserInRole(PacktMPUser)=true
```

通过使用`@RolesAllowed`注解和与 MP-JWT 功能的集成，我们可以看到我们如何既能保护微服务端点的安全，又能根据认证 JWT 中的内容引入应用程序行为。接下来，让我们回到 RestClient 标签页。

# RestClient 标签页

RestClient 标签页包含三个链接，如图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-etp-java-msvc-eclp-mprf/img/994277da-2795-4b3f-99c0-783f2ae4b6f6.png)

这些链接对应于使用外部世界时钟公共端点来返回有关当前时间的信息的端点。以下 MP-RC 接口已创建以封装外部端点：

```java
@RegisterRestClient(baseUri = WorldClockApi.BASE_URL)public interface WorldClockApi {    static final String BASE_URL = "http://worldclockapi.com/api/json";    @GET    @Path("/utc/now")    @Produces(MediaType.APPLICATION_JSON)    Now utc();    @GET    @Path("{tz}/now")    @Produces(MediaType.APPLICATION_JSON)    Now tz(@PathParam("tz") String tz);}
```

# 总结

本章带我们了解了由一个 web 应用程序、两个使用 MP 功能的微服务镜像组成的新 Quarkus 实现、一个外部 web 服务以及两个基于 Docker 的服务组成的示例服务网格。这展示了各种 MP 功能与外部服务在云环境中的交互，以及与本地网格环境外部的 web 服务的集成。这应该让您了解到使用 MicroProfile API 和实现编写微服务的步骤。

在下一章中，我们将查看正在开发中的 MicroProfile 规范，以了解正在探索的方向。虽然这些规范目前不在 MicroProfile 核心功能集之外，但它们是未来可能包含在内的候选项，并且查看它们将让我们了解 MicroProfile 可能的发展方向。

# 问题

1.  MP-Config 设置是否影响应用程序代码、MP 功能代码，还是两者都会影响？

1.  您能够更新`health.pathToMonitor`到一个有效的路径并看到一个更新的健康状态回复吗？

1.  健康标签页上的`Svcs2`健康状态链接（`http://localhost:8082/health`）显示的是什么输出？如果您停止 KeyCloak Docker 镜像并再次点击链接，输出会发生变化吗？

1.  如果您在没有至少先点击`Timed`端点链接（`http://localhost:8080/demo1/metric/timed`）的情况下选择 Metrics 标签页中的`MetricController.timed-request`链接（`http://localhost:8080/metrics/application/io.packt.sample.metric.MetricController.timed-request`），会发生什么？

1.  转到 RestClient 标签页并点击链接，确保您有一个有效的...

# 进一步阅读

审查代码、尝试修改，然后与更新后的代码互动，这是了解示例服务背后更多细节的好方法。Quarkus MicroProfile 实现支持实时重新加载功能，允许您在不重新构建的情况下进行更改。关于这一主题的更多信息，请参阅 Quarkus 网站上的 Maven 工具文档（[`quarkus.io/guides/maven-tooling.html`](https://quarkus.io/guides/maven-tooling.html)）。


# 第五部分：未来展望

本节介绍了不属于当前范畴的一些现有项目，例如候选 API，并讨论了 MicroProfile 如何适应多云环境。

本节包含以下章节：

+   第九章，*响应式编程与未来发展*

+   第十章，*MicroProfile 在多云环境中的应用*


# 第十章：反应式编程与未来发展

事件驱动架构已经存在很长时间，异步方法调用、消息驱动 bean、事件控制逻辑等是开发者熟悉的构造。然而，随着云资源和按需可扩展性的普及和采用，组织对可以利用无服务器和函数即服务类型环境的反应式编程方法重新产生了兴趣。Eclipse MicroProfile 还包括目前不在 Eclipse MicroProfile 伞/平台发布中的反应式编程相关项目规范。

除了这些，Eclipse MicroProfile 沙盒中还有社区目前正在讨论、实施和评估的项目，以决定它们是否应升级为正式的 MicroProfile 项目。本章将帮助您了解与反应式编程相关的当前 MicroProfile 规范，并为您提供一些已经在进行中和即将到来的项目，这些项目位于伞下/平台发布之外以及 MicroProfile 沙盒中。本章将涵盖以下主题：

+   反应式消息传递的概述

+   解释 Eclipse MicroProfile 内的反应式消息传递架构

+   描述与反应式编程相关的 Eclipse MicroProfile 规范

+   使用 Eclipse MicroProfile 反应式消息规范的示例

+   概述不在 Eclipse MicroProfile 伞下或平台发布中的 MicroProfile 项目/规范

+   描述位于 Eclipse MicroProfile 沙盒中的项目

+   深入了解 Eclipse MicroProfile 与 Jakarta EE 当前的关系以及它们可能的未来分析

# Eclipse MicroProfile 中的响应式编程工作

在撰写本文时，属于 Eclipse MicroProfile 的反应式相关规范包括 Reactive Streams Operators、Reactive Messaging 和 Context Propagation。Eclipse MicroProfile 社区内的反应式工作仍在不断发展，未来可能会有新的规范出现，同时现有反应式相关规范也会有新的版本发布。

# 反应式消息传递概述

《反应式宣言](https://www.reactivemanifesto.org/)定义了反应式系统的特性，包括一个用于构建弹性、恢复性系统的异步消息核心。这通常通过以下图表进行说明：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-etp-java-msvc-eclp-mprf/img/a5e7920f-3372-4247-a4d6-a9e52c974d3f.png)

想法是通过异步消息交互促进弹性、弹性，进而提高响应性。

**MicroProfile 反应式消息**（**MP-RM**）规范旨在通过事件驱动的微服务使基于微服务的应用程序具有反应式系统的特性。该规范关注多样性，适用于构建不同类型的架构和应用程序。

可以使用反应式消息实现与不同服务和资源的不对称交互。通常，异步数据库驱动可以与反应式消息一起使用，以非阻塞和非同步的方式读写数据存储。

在构建微服务时，**命令查询责任分离**（**CQRS**）和事件源模式为微服务之间的数据共享提供了答案([`martinfowler.com/bliki/CQRS.html`](https://martinfowler.com/bliki/CQRS.html))。反应式消息也可以作为 CQRS 和事件源机制的基础，因为这些模式拥抱消息传递作为核心通信模式。

# MicroProfile 反应式消息架构

使用反应式消息的应用程序由消费、生产和处理消息的 CDI Bean 组成。这些消息可以是应用程序内部的，也可以是通过外部消息代理发送和接收的，如下面的图表所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-etp-java-msvc-eclp-mprf/img/8aec63b4-925c-414e-97b0-409c29421e65.png)

这个图表展示了一个 Kafka 主题向第一个 Bean 发布消息，该 Bean 进行一些处理后又将其发布给第二个 Bean，第二个 Bean 进行自己的处理/过滤，最后将消息作为 AMQP 主题发布。

正如我们在查看 MP-RM 示例时将看到的，应用 Bean 包含用 `@Incoming` 和/或 `@Outgoing ...` 注解的方法。

# 消息形状

MP-RM 规范定义了许多受支持的签名类型，Bean 可以使用它们来定义发布和订阅行为。这些签名依赖于以下列表中概述的几个关键类型：

+   `org.reactivestreams.Publisher`：一个 Reactive Streams `Publisher<T>` 是提供潜在无限数量序列元素的提供者，根据从其链接订阅者接收的需求发布它们。

+   `org.reactivestreams.Subscriber`：一个用于向 `Publisher` 信号需求的 Reactive Stream `Subscriber<T>` 接口。它提供了订阅信息事件、零个或多个数据事件以及错误和完成事件。

+   `org.reactivestreams.Processor`：这个 Reactive Stream `Processor<T,R>` 接口简单地扩展了 `Subscriber<T>` 和 `Publisher<R>` 两个接口。

+   `org.eclipse.microprofile.reactive.streams.operators.PublisherBuilder`：MP Reactive Streams 操作符 `PublisherBuilder` 接口允许你从各种源构建 Reactive Streams `Publisher` 并应用操作来转换/过滤最终发布的消息。

+   `org.eclipse.microprofile.reactive.streams.operators.ProcessorBuilder`：微 Profile 反应流操作符`ProcessorBuilder`接口允许你从各种来源构建反应流`Processor`并应用操作来转换/过滤最终发布的消息。

+   `org.eclipse.microprofile.reactive.streams.operators.SubscriberBuilder`：微 Profile 反应流操作符`SubscriberBuilder`接口允许你从各种来源构建反应流`Subscriber`并应用操作来转换/过滤最终发布的消息。

+   `java.util.concurrent.CompletionStage`：这个 JDK 并发`util`包接口定义了一个通常是异步的计算阶段，并计算一个动作或值。`CompletionStage`可以组合使用，以便执行阶段图以产生最终结果。

+   `org.eclipse.microprofile.reactive.messaging.Message<T>`：一个提供类型为`T`的载荷包装器并有一个`ack`方法来确认收到消息的 MP-RM 接口。

定义了这些类型后，我们可以查看 MP-RM 支持的各种方法，这些方法通过将消息推送到出站通道来产生数据。所有发布者方法类型都有`@Outgoing("channel-name")`注解，并支持如下签名：

+   `Publisher<Message<T>> 方法()`

+   `Publisher<T> 方法()`

+   `PublisherBuilder<Message<T>> 方法()`

+   `PublisherBuilder<T> 方法()`

+   `T 方法()`

+   `CompletionStage<T> 方法()`

消费者方法都有一个`@Incoming("channel-name")`注解，并支持如下签名：

+   `Subscriber<Message<T>> 方法()`

+   `Subscriber<T> 方法()`

+   `SubscriberBuilder<Message<T>>`

+   `SubscriberBuilder<T>`

+   `void 方法(Message<T> 载荷)`

+   `void 方法(T 载荷)`

+   `CompletionStage<?> 方法(Message<T> 载荷)`

+   `CompletionStage<?> 方法(T 载荷)`

既消耗数据又产生数据的方法被称为处理器，并将具有`@Incoming("channel-in")`和`@Outgoing("channel-out")`注解。支持的签名如下：

+   `Processor<Message<I>, Message<O>> 方法()`

+   `Processor<I, O> 方法();`

+   `ProcessorBuilder<Message<I>, Message<O>>方法()`

+   `ProcessorBuilder<I, O> 方法();`

+   `Publisher<Message<O>> 方法(Message<I> msg)`

+   `Publisher<O> 方法(I 载荷)`

+   `PublisherBuilder<Message<O>> 方法(Message<I> msg)`

+   `PublisherBuilder<O> 方法(I 载荷)`

+   `Message<O> 方法(Message<I> msg)`

+   `O 方法(I 载荷)`

+   `CompletionStage<Message<O>> 方法(Message<I> msg)`

+   `CompletionStage<O> 方法(I 载荷)`

+   `Publisher<Message<O>> 方法(Publisher<Message<I>> pub)`

+   `PublisherBuilder<Message<O>> 方法(PublisherBuilder<Message<I>> pub)`

+   `Publisher<O> 方法(Publisher<I> pub)`

+   `PublisherBuilder<O> 方法(PublisherBuilder<I> pub)`

现在，我们将查看一些使用这些签名构建消息处理链的示例。

# 微 Profile 反应流操作符

反应式流不仅仅是将发布者连接到订阅者。通常，一个流需要以某种方式进行操作，比如应用包括 `map`、`filter` 和 `flatMap` 的操作。反应式流和 JDK 都没有提供执行这些操作的 API。由于用户不需要自己实现反应式流，这意味着目前进行这些操作的唯一方式是依赖于第三方库提供操作符，如 Akka Streams、RxJava 或 Reactor。

MicroProfile 反应式流操作符 API 旨在填补这一空白，使得 MicroProfile 应用开发者能够无需引入第三方依赖即可操作反应式流。...

# MicroProfile 上下文传播

这个规范位于 MicroProfile 平台发布之外的范畴，目前仍处于提议或草稿状态。我们将在本章后面的 *MicroProfile 未来发展趋势* 部分更详细地讨论这个规范，但在这里我们先给出一个高层次的介绍。

MicroProfile 上下文传播规范引入了 API，用于在无线程关联的工作单元之间传播上下文。它使得能够将传统与当前线程相关联的上下文传播到各种工作单元，如 `CompletionStage`、`CompletableFuture`、`Function` 和 `Runnable`，无论最终是哪个特定的线程执行它们。

# MicroProfile 反应式消息示例

在本节中，我们将介绍一些使用 MP-RM 创建产生和消费消息的 CDI 豆子的示例。

假设你想让一个 CDI 豆子作为 `Message<String>` 的来源，这样每当调用其 `publishMessage(String)` 方法时，就会向某个 MP-RM 通道发布 MP-RM 消息。为此，我们需要定义一个连接器，它将 CDI 豆子与 MP-RM 层连接起来。下面代码示例展示了一个实现此功能的传入消息连接器：

```java
package io.pckt.reactive;import javax.enterprise.context.ApplicationScoped;import javax.inject.Inject;import org.eclipse.microprofile.config.Config;import org.eclipse.microprofile.reactive.messaging.Message;import org.eclipse.microprofile.reactive.messaging.spi. ...
```

# MicroProfile 未来发展趋势

如第二章 *治理和贡献* 中所述，带到 Eclipse MicroProfile 项目的新想法首先在 MicroProfile 沙箱中尝试，遵循实现优先的创新方法。沙箱练习为实施者和社区提供了讨论、分析和评估新想法如何融入 MicroProfile 项目的机会。如果在沙箱练习结束时，社区认为这个新想法值得添加到项目中，就会为它创建一个特定的 MicroProfile 子项目。子项目在至少发布一个版本之前，才能考虑加入到 MicroProfile 伞/平台发布中。在非常高层次上，这是新想法和未来发展趋势在 MicroProfile 项目下遵循的过程。

在下一节中，我们将讨论两种类型的项目，这些项目目前是 MicroProfile 的子项目，目前不在 MicroProfile 伞下/平台发布（将这些视为已经从 MicroProfile 沙箱毕业的项目），以及仍在 MicroProfile 沙箱中的项目。最后，我们将讨论 Eclipse MicroProfile 和 Jakarta EE 之间的当前关系，以及它们的路线图可能满足也可能不满足。

# 伞下项目

在本节中，我们将介绍在 Eclipse MicroProfile 伞下发布之外的项目，当然，在撰写本文时。这些如下：

+   响应式流操作符

+   响应式消息传递

+   长期运行动作

+   上下文传播

+   GraphQL

本章的前几节已经讨论了响应式流操作符和响应式消息传递项目，因此在本节中我们只覆盖长期运行动作、上下文传播和 GraphQL。

# 长期运行动作

在松耦合的服务环境中，**长期运行动作**（**LRA**）规范背后的动机是为许多微服务的调用组成的业务流程提供一致的结果，而无需锁定数据。思考 LRA 的一种方式是将其视为*微服务的事务*。需要 LRA 的情况包括以下几种：

+   在网上订购一本书将需要从库存中退役一本书，处理支付，最后是发货。所有这些任务都需要原子性地完成，换句话说，它们需要一起处理，也就是说，如果任何任务失败，那么所有任务都必须被撤销。

+   预订航班将需要从飞机可用的座位列表中移除一个座位，为旅客选择并分配一个特定的座位，处理支付，以及创建一个记录定位器。同样，所有这些任务必须在同一个长期运行动作中完成。

不仅上述示例需要原子性地完成，而且它们还需要生成一个结果，即使它们的中间步骤中有任何失败，数据也是一致的。

微概要 LRA 当前提出的解决方案受到了*OASIS Web 服务组合应用框架技术委员会*的启发（[`www.oasis-open.org/committees/tc_home.php?wg_abbrev=ws-caf`](https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=ws-caf)），即*Web 服务**长期运行动作事务模型*（[`www.oasis-open.org/committees/document.php?document_id=12794`](https://www.oasis-open.org/committees/document.php?document_id=12794)），但已更新以更适用于微服务架构。

有关 MicroProfile LRA 规范的更多信息，请参考[`github.com/eclipse/microprofile-lra/blob/master/spec/src/main/asciidoc/microprofile-lra-spec.adoc`](https://github.com/eclipse/microprofile-lra/blob/master/spec/src/main/asciidoc/microprofile-lra-spec.adoc)。

MicroProfile 长期运行动作规范模型包括三个主要实体：补偿器、逻辑协调器和客户端。客户端可以通过两种不同的方式显式启动新的 LRA：

+   通过注解，或者

+   通过 API 调用

要么创建一个新的 LRA。如果一个服务可能需要稍后撤销某事，那么客户端需要为 LRA 注册一个补偿器。如果客户端选择关闭或取消 LRA，补偿器将撤销服务在 LRA 范围内执行的工作，或者对未完成的工作进行补偿。

以下是一些主要的 LRA 注解：

+   `@LRA`控制 LRA 的生命周期。

+   `@Compensate`表示如果 LRA 被取消，则应调用该方法。

+   `@Complete`表示如果 LRA 关闭，则应调用该方法。

+   `@Forget`表示该方法可能释放为这次 LRA 分配的任何资源。

+   `@Leave`表示这个类不再对这次 LRA 感兴趣。

+   `@Status`在调用注解方法时报告状态。

你可以将这些注解与 JAX-RS 和非 JAX-RS 方法一起使用。此外，该规范支持 JAX-RS 的异步和反应式特性，LRA 嵌套和超时功能。最后，值得一提的是，LRA 规范通过对接口参与实体提出某些要求，确保事务性和最终一致性。作为一个 MicroProfile 项目，MicroProfile LRA 规范，在撰写本文时，处于提议或草稿状态。

# 上下文传播

MicroProfile 上下文传播规范的目标是在线程无关的工作单元之间传播上下文。在一个反应式模型中，逻辑的执行被拆分为相互链式组装的反应式流水线的工作单元。每个工作单元在上下文中执行，这通常是不可预测的，并取决于正在使用的特定反应式引擎。一些单元可能在与线程等待完成上下文的情况下运行，或者在完成并触发依赖单元的前一个单元的上下文中运行，或者根本没有任何上下文。MicroProfile 上下文传播规范使得线程上下文传播可以轻松地以类型安全的方式完成，保持了样板代码...

# GraphQL

GraphQL 是一个开源的数据查询和操作语言，用于 API，以及用于用现有数据满足查询的运行时。它解释客户端的字符串并以可理解、可预测和预定义的方式返回数据。GraphQL 是 REST 的替代方案，但不一定是替代品。MicroProfile GraphQL 规范的目标是为用户提供一套 API，使用户能够快速在 Java 中开发可移植的 GraphQL 基础应用程序。作为一个 MicroProfile 项目，MicroProfile GraphQL 规范在撰写本文时，处于提议或草稿状态。

GraphQL 基于 Facebook 的规范。关于这一点，请参阅`https://graphql.github.io/graphql-spec`。有关 GraphQL 的更全面概述，请访问[`graphql.org/`](https://graphql.org/)。

GraphQL 和 REST 有许多相似之处，都在现代微服务应用中得到广泛使用。

# GraphQL 与 REST 的区别

以下是与 REST 相比 GraphQL 的主要区别性特征：

+   **基于架构**：架构作为服务器及其客户端之间的合同。

+   **单一 HTTP 端点**：通过查询语言实现单一端点和数据及操作的访问。

+   **灵活的数据检索**：允许客户端以细粒度的方式选择响应中的数据，从而避免过度或不足地获取数据。

+   **减少服务器请求**：该语言允许客户端将预期的数据聚合成单个请求。

+   **更简单的版本管理**：在创建新数据的同时，使旧数据过时。

+   **部分结果**：结果由数据和错误组成。客户端负责...

# GraphQL 和数据库

GraphQL 不是数据库技术。相反，它是用于 API 的数据查询和操作工具，不依赖于任何数据库或存储技术。但是，它可以用于任何后端之前，并能够通过单个 API 从多个后端数据源聚合数据。

# 沙盒中的项目

MicroProfile 项目沙盒是社区可以提出想法的地方，通过尝试实现功能和特性的实现，从社区成员那里获得反馈、讨论和评估，以决定是否将想法变成 MicroProfile 项目的新 API/规范。

MicroProfile 沙盒位于[`github.com/eclipse/microprofile-sandbox`](https://github.com/eclipse/microprofile-sandbox)。

从沙盒毕业成为正式 MicroProfile 项目的过去项目建议包括 GraphQL 和 Reactive Streams Operators。在撰写本文时，沙盒中只有一个建议项目，即 Boost。

# MicroProfile Boost

在撰写本文时，MicroProfile Boost 在 MicroProfile 沙盒中处于社区评估阶段。Boost 是一个 Maven 插件，可增强为您的 MicroProfile 应用程序构建的过程。

有关 Boost 的更多信息，请访问[`github.com/eclipse/microprofile-sandbox/tree/master/proposals/boost`](https://github.com/eclipse/microprofile-sandbox/tree/master/proposals/boost)。

Boost 为 MicroProfile API 定义了 Maven 依赖项，称为**启动器**，例如为 MicroProfile Config 定义的`mpConfig`，以及为 Java EE API。此外，它还为实现不同 MicroProfile API 的运行时定义了依赖项，例如`openliberty`。还有一个作为 BOM（物料清单）指定的 Boost 定义的 Maven 依赖项，它指示在构建有关 MicroProfile API 的 maven 时使用 MicroProfile 伞项目的哪个版本。BOM 内容由插件管理。作为 Boost 的用户，您将把这些依赖项包含在您的`pom.xml`文件中，以简化 MicroProfile 应用程序的构建过程。

# Eclipse MicroProfile 和 Jakarta EE

Eclipse Jakarta Enterprise Java 项目和 Eclipse MicroProfile 项目之间的关系是什么？简而言之：尚未可知。详细答案：让我们开始。

Eclipse MicroProfile 项目旨在解决在**Java Community Process**（**JCP**）下 Java EE 规范缺乏进展的问题。

有关 Java 社区过程的更多信息，请访问`https://jcp.org/en/home/index`。

自 MicroProfile 项目移至 Eclipse 基金会以来已经过去了两年多时间。大约一年后，Oracle 宣布计划将 Java EE 移至 Eclipse 基金会并将其重命名为 Jakarta EE。移至 Jakarta 的过程是一个漫长的过程，而且还在继续...

# 摘要

在本章中，我们了解了 MicroProfile 规范的未来发展，包括 Long Running Actions、Context Propagation 和 GraphQL 项目，它们都不在伞发布之外，以及仍在 MicroProfile 沙箱中的 Boost 项目。此外，您还了解了反应式消息传递的概念、MicroProfile 反应式消息传递架构，以及如何使用代码示例通过 Eclipse MicroProfile 反应式构件实现反应式微服务。您还获得了这些项目的背景知识、它们的 capabilities、注解（annotation）和在适用情况下的代码示例，以及它们当前的状态。最后，我们介绍了两个类似但不同的项目：Eclipse MicroProfile 和 Jakarta EE 之间的关系，并讨论了它们可能在未来如何发展。

在下一章中，我们将学习在多云环境和部署中关于 Eclipse MicroProfile 的知识。

# 问题

1.  如果我们有一个消息源，我该如何将其集成到我的 MicroProfile 应用程序中？

1.  MicroProfile Context Propagation 最佳支持现有 MicroProfile 规范中的哪一个？

1.  目前支持反应式编程的 MicroProfile 规范有哪些？

1.  目前哪些 MicroProfile 规范位于伞/平台 MicroProfile 发布之外？

1.  为什么要有 MicroProfile 沙盒呢？

1.  目前哪些项目位于 MicroProfile 沙盒中？

1.  当前 Eclipse MicroProfile 与 Jakarta EE 之间的关系是什么？

1.  未来 Eclipse MicroProfile 与 Jakarta EE 之间的关系将如何发展？

# 进一步阅读

+   对于 MicroProfile 响应式消息传递，[`reactivex.io/`](http://reactivex.io/)网站提供了动机、教程、语言绑定等内容。

+   学习 GraphQL 的一个好起点是[`graphql.org/`](https://graphql.org/)网站，该网站提供了更多关于其背后的动机，以及许多用于探索如何使用它的资源。


# 第十一章：在多云环境中使用 MicroProfile

微服务和微服务架构是云和多云环境的理想开发方法，包括混合云部署，您的应用程序包括本地逻辑以及运行在云中的逻辑。Eclipse MicroProfile 是一个优化 Java 适用于微服务架构的规范，因此提供了构造，使您可以使用 Java 和云实现微服务。这些主题将帮助您了解为什么 Eclipse MicroProfile 适用于开发混合和多云环境中的应用程序，以及在这些类型的部署中使用它时必须考虑的因素。

在本章中，我们将讨论以下内容...

# 使用 Eclipse MicroProfile 进行云原生应用开发

什么是云原生应用？通常，对于**云原生**的定义包括以下特征：

+   设计为松耦合服务，如微服务

+   松耦合的服务，通过语言无关的通信协议进行交互，这使得微服务可以采用不同的编程语言和框架实现

+   可以按需或通过资源利用率指标进行扩展轻量级容器

+   通过敏捷 DevOps 流程管理，每个云原生应用程序的微服务都经历一个独立的生命周期，该生命周期通过使用**持续集成/持续交付**（**CI/CD**）管道进行敏捷管理

然而，Eclipse MicroProfile 的目标是优化 Java 适用于微服务架构，那么它是否适合云原生应用开发呢？容器原生开发又如何？微服务、云原生开发和容器原生开发之间的关系是什么？它们之间有什么区别或比较？让我们来找出答案！

# 微服务与云原生与容器原生

首先，让我们绘制这三个术语在应用程序开发方面的区别。正如我们在第一章中讨论的，*Eclipse MicroProfile 简介*，企业 Java 微服务具有以下特征：

+   这是一个使用 Java 语言编写的微服务。

+   它可以使用任何 Java 框架。

+   它可以使用任何 Java API。

+   它必须是企业级的，这意味着它必须具有高可靠性、可用性、可扩展性、安全性、健壮性和性能。

+   它必须满足微服务的所有特征，这些特征列在[`martinfowler.com/microservices/`](https://martinfowler.com/microservices/)上。

根据其定义，微服务不规定底层的具体细节...

# 那 12 因子应用又如何呢？

就像微服务和微服务架构的定义一样，12 因子应用不会规定底层技术，例如编程语言、数据库、缓存等，或应使用它们实现的框架。12 因子应用是一种用于实施应用程序的方法。这十二个因素如下：

+   一个代码库在版本控制中跟踪，多个部署

+   明确声明和隔离依赖项

+   在环境中存储配置

+   将后端服务视为附加资源

+   严格区分构建和运行阶段

+   将应用程序作为无状态进程之一或多个执行

+   通过端口绑定导出服务

+   通过进程模型进行扩展

+   通过快速启动和优雅关机最大化健壮性

+   尽可能保持开发、暂存和生产环境相似

+   将日志视为事件流

+   将管理任务作为一次性流程运行

使用这种方法实施应用程序可以帮助我们做到以下几点：

+   最小化新开发者加入项目的时间和成本

+   提供在执行环境之间可移植性

+   轻松将应用程序部署到云平台

+   最小化开发和生产之间的差异

+   无需更改即可扩展

您可以在[`12factor.net`](https://12factor.net)上阅读到关于 12 个因素的全部内容。

12 因子应用是一种开发者可以在设计和实现微服务和应用程序时遵循的方法，与实现它们的编程语言或框架无关。开发者可以使用 12 因子应用框架实现微服务，这个框架是 Eclipse MicroProfile。12 因子应用和 Eclipse MicroProfile 并不是相互排斥的，而是相辅相成的。

但是，除了 12 因子应用之外，还有没有其他设计和实现应用程序的方法呢？无服务器和**功能即服务**（**FaaS**）技术又如何呢？Eclipse MicroProfile 在这些更新的云原生技术中如何定位？

# 那么无服务器和 FaaS 呢？

无服务器和 FaaS 作为云原生技术，在市场上一直保持着稳定的兴趣和增长，这一点从所有主要云服务提供商的产品中可以看出，即 AWS Lambda、Azure Functions、Oracle Functions 和 Google Cloud Functions。在组织越来越多地使用云进行开发和生产负载的时代，计算和内存成本是必须跟踪和监控的操作费用，FaaS 之所以吸引人，是因为它将计算和内存管理从用户手中抽象出来，使用户能够专注于开发业务逻辑，从而比以往任何时候都更加高效。

使用 FaaS，开发人员无需设置虚拟机和内存，...

# 云原生应用开发

云原生应用开发有两个互补的方面或组件：应用服务和基础设施服务。应用服务加快了云原生应用的业务逻辑开发，而基础设施服务则加快了其交付和部署。这两个方面是互补的，并构成了云原生应用开发的一部分。没有另一个，你无法拥有。它们本质上是云原生应用开发的阴阳两面，如下面的图表所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-etp-java-msvc-eclp-mprf/img/5396deb8-7e59-4be5-9b20-a31287abeed3.png)

正如我们在这章节前面提到的，云原生应用开发是一种构建和运行应用程序的方法，它充分利用了云计算模型，该模型基于四个核心原则：

+   基于服务架构（微服务、微服务、SOA 服务等）

+   服务间通信的 API 驱动方法

+   基于容器的底层基础设施

+   DevOps 流程

下面的图表展示了云原生应用开发的四个核心原则：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-etp-java-msvc-eclp-mprf/img/5994cf8f-77e2-4906-b576-0a8742fe81b5.png)

如图所示，前一个图表中，架构和通信方面与云原生应用的开发关注点相关，而基础设施和流程方面则与它们的交付/部署相关。

正在采用云原生应用开发的组织可以从八个步骤中受益，这些步骤在电子书中有所描述，书名为 *The path to cloud-native applications: **8 steps to guide your journey*.

要获取电子书 *The path to cloud-native applications: **8 steps to guide your journey*, 请参考 [`www.redhat.com/en/resources/path-to-cloud-native-applications-ebook`](https://www.redhat.com/en/resources/path-to-cloud-native-applications-ebook).

让我们讨论一下 Eclipse MicroProfile 在这八个步骤中可以发挥什么作用：

1.  **发展和实践 DevOps 文化**：“*利用新技术、更快的方法以及更紧密的协作，通过采纳 DevOps 的原则和文化价值观，围绕这些价值观组织你的组织.*” 尽管这是一个与组织和工作流程相关的步骤，但作为微服务规范的 Eclipse MicroProfile 可以很好地适应这种文化和流程的改变，因为微服务由于其特性，紧密支持 DevOps 流程。

1.  **使用快速单体加速现有应用**：“*通过迁移到现代、基于容器的平台来加速现有应用——并将单体应用分解为微服务或小型服务，以获得额外的效率提升。*” 在将单体应用分解为微服务时，Eclipse MicroProfile 可以提供很大帮助。 当你在单体应用中识别出边界上下文时，可以考虑使用 Eclipse MicroProfile 来实现每个微服务，这些微服务实现每个边界上下文的逻辑。

1.  **使用应用服务加快开发速度**：“*通过可重用性加快软件开发。云原生应用服务是即用的开发者工具。然而，这些可重用组件必须优化并集成到云原生基础架构中，以最大化其效益。*”**内存数据网格**（**IMDG**）和消息代理是应用服务，它们有助于加快业务逻辑的开发。使用 Eclipse MicroProfile 开发的微服务，可以通过其方法体内部调用这些应用服务。Eclipse MicroProfile 在集成应用服务，如 IMDG 或消息代理时，不会施加任何限制。

1.  **为每项任务选择合适的工具**：“*使用基于容器的应用平台，支持正确的框架、语言和架构的混合——并可根据您的特定业务应用需求进行定制。*” 当选择合适的工具来完成任务时，开发者可以使用 Eclipse MicroProfile 这样的工具。例如，Red Hat Application Runtimes 是一组运行时和工具的集合，其中包括 Eclipse MicroProfile、Node.js、Spring Boot 和 Vertex。

1.  **为开发者提供自助、按需的基础设施**：“*使用容器和容器编排技术简化对底层基础设施的访问，赋予 IT 运营团队控制和可见性，并在各种基础设施环境中，如数据中心、私有云和公有云，提供健壮的应用生命周期管理。*” 使用 Eclipse MicroProfile 开发的微服务可以部署到一个或多个容器中。 通过轻松管理这些容器以及在其上运行的微服务架构，您可以加快开发周期，更快地向业务交付价值。

1.  **自动化 IT 以加速应用交付**：“*创建自动化沙盒，以学习自动化语言和流程，跨组织建立协作对话以定义服务需求，创建自助服务目录以赋予用户权力并加快交付，以及使用度量、监控和计费回策略和流程。*” Eclipse MicroProfile 提供了度量、容错和健康检查等功能，这些都可以作为 IT 自动化过程的输入。

1.  **实施持续交付和高级部署技术**："*使用自动化交付、CI/CD 管道、滚动蓝/绿和金丝雀部署以及 A/B 测试，加速你的云原生应用程序的交付。*" 微服务与 CI/CD 的结合可以促进高级部署技术。例如，你可以作为一个蓝/绿或金丝雀部署的一部分，将具有新功能的 MicroProfile 基础微服务引入生产中，一旦你证明了新的功能如预期般工作，就可以将所有流量切换到它。

1.  **进化成更模块化的架构**： "*选择一种适合你特定需求的模块化设计，使用微服务、单体优先方法或迷你服务——或它们的组合。*" 在这一步，你可以使用 Eclipse MicroProfile 来为新的应用程序开发微服务，或者在你将单体的特定有限上下文拆分为微服务时使用。

既然我们已经讨论了 Eclipse MicroProfile 如何促进云原生应用程序的开发，以及它如何在八个步骤中帮助引导你走向云原生应用程序，现在让我们转向在云之间运行基于 MicroProfile 的应用程序的主题。

# 在云之间开发和运行 MicroProfile 应用程序

MicroProfile 提供了哪些特性来支持在云之间开发？微服务和基于 HTTP REST API 的语言无关通信是支持的两个主要特性。此外，MicroProfile Config 支持将云环境变量集成到定义与云环境集成的集成中。MicroProfile Health Check 支持与云环境健康检查的集成。MicroProfile Metrics 和 MicroProfile OpenTracing 支持与 DevOps 监控任务的集成。最后，MicroProfile 容错支持独立微服务之间的回退和恢复行为。

Eclipse MicroProfile ...

# 裸机机器与虚拟机与容器

是否在裸机机器、虚拟机或容器上运行基于 MicroProfile 的微服务或应用程序取决于你的应用程序的具体要求。实际上，确定哪种底层云计算资源完全取决于你的应用程序需求，而不是用于其开发的框架，即 Eclipse MicroProfile。例如，如果你的应用程序或微服务需要实时或接近实时的响应时间，那么你很可能会偏好裸机或容器（运行在裸机上）部署。这个决定与你正在使用来编写业务逻辑的框架无关，无论是 Eclipse MicroProfile 还是其他框架。

由于 Eclipse MicroProfile 支持微服务和基于 HTTP REST 的语言无关通信，你的微服务之间的通信不受运行微服务的底层计算类型的影响；例如，你可以有一个运行在 VM 上的微服务通过 REST 与另一个运行在裸机上的微服务进行通信。但是，如果你的应用程序由在本地运行的微服务和在云上运行的另一个微服务组成，也称为混合云应用程序，你需要考虑什么？

# 在混合云部署中使用 MicroProfile 时的考虑

混合云应用程序包括本地逻辑以及云逻辑。换句话说，如果你的应用程序逻辑的一部分在本地运行，另一部分在云中运行，你实际上拥有一个混合云应用程序。当在这个类型的部署中使用 Eclipse MicroProfile 时，以下是你需要考虑的事情：

+   配置云环境与本地环境之间的通信路由需要使用云环境支持的所有 DNS 支持

+   配置 MicroProfile OpenTracing 以在云环境之间捕获跟踪

+   在云环境和本地环境之间分割 MicroProfile Metrics 信息进行监控...

# 在多云部署中使用 MicroProfile OpenTracing 时的挑战

在多云环境中进行分布式跟踪可能会很有挑战性。我们希望能够实现与单一云环境相同的目标，即可视化与请求相关联的单个端到端跟踪，以及它穿过每个云中的服务，但在处理不同的上下文传播格式和每个云存储跟踪数据的不同格式时可能会遇到复杂问题。

第一个挑战是要确保跟踪可以在不同的云环境中持续进行。这是一个问题，因为截至撰写本书时，还没有被广泛采用或标准化的跟踪上下文格式。通常，每个跟踪系统都使用不同的头文件和格式来传播跟踪上下文。例如，Zipkin 使用 B3 传播，Jaeger 使用 `ber-trace-id` 头文件，Amazon X-Ray 使用 `X-Amzn-Trace-Id`，Google 使用 `X-Cloud-Trace-Context`。因此，如果一个请求需要在不同的跟踪系统之间进行跟踪，每次它离开或进入不同的环境时，都需要转换跟踪上下文。这通常可以通过配置带有自定义注入器或提取器实现的跟踪器来完成。然而，这目前超出了 MicroProfile OpenTracing 项目的范围。将来，跟踪上下文格式可能会在 W3C 跟踪上下文项目下得到标准化([`www.w3.org/TR/trace-context/`](https://www.w3.org/TR/trace-context/)).

第二个挑战，即使在同质追踪环境中，也是可视化多云环境中的追踪数据。这可能很成问题，因为每个云中的追踪数据可能存储在不同的数据库或不同的格式中。这可以通过将数据复制到单一统一存储，或者使用适当的数据格式调整，在系统之间按需发送缺失的追踪数据来克服。

接下来，我们将讨论在像 Istio 这样的服务网格中使用 Eclipse MicroProfile 遇到的挑战。

# 在服务网格中使用 Eclipse MicroProfile 的考虑

像 Istio 或 LinkerD 这样的服务网格在 Kubernetes 之上的平台级别提供服务，涵盖发现、路由和故障容限等领域。其中一些服务也可以在 MicroProfile 中找到。当你将 MicroProfile 应用程序部署在这样的服务网格中时，你需要考虑是否想使用 MicroProfile 版本或网格中的版本。

受影响的 MicroProfile 特性最可能是故障容限，尤其是重试逻辑。

# 重试

在故障容限中的重试允许在第一个请求失败时重试对另一个服务的请求（更多信息请参见第三章，*MicroProfile Config 和 Fault Tolerance*）。现在，考虑你有以下代码：

```java
@Retry (maxRetries = 3)
void aMethod() {
    callBackend();
}
```

尽管这告诉 Istio 重试 5 次，但最终可能导致`aMethod`以错误结束，共进行 15 次重试（Istio 会在返回错误之前为您的代码中的 3 次重试各重试 5 次）。你可能考虑关闭代码中的重试，因为可以通过不需要重启 pod 的方式，随时在 Istio 中更改重试次数。

# 回退

另一方面，Istio 没有在所有重试失败时调用回退策略——不可能让 Istio 调用您工作负载的另一个版本。当你在前面的代码上添加`@Fallback`注解时，在原始调用失败的情况下可以执行另一个动作：

```java
@Fallback(fallbackMethod = "fallbackForA")@Retry (maxRetries = 3)string aMethod() {   callBackend();}void String fallbackForA() {    return "A cached string";}
```

在这种情况下，一旦 Istio 和 MicroProfile 的所有重试都耗尽，将会调用`fallbackForA`回退方法。如果你从前面示例中移除了`@Retry`注解，当 Istio 的重试耗尽时会调用回退方法...

# 服务网格中的故障注入

Istio 可以很容易地在结果中注入故障。这听起来开始时有些适得其反，但这是一个非常好的测试您是否正确处理了故障容限的方式。以下是为 Istio 定义故障注入的`VirtualService`：

```java
apiVersion: networking.istio.io/v1alpha3
kind: VirtualService
metadata:
  name: fault-injection-service
spec:
  hosts:
  - myTarget
  http:
  - route:
    - destination:
      host: myTarget
    fault:
      abort:
        httpStatus: 404
        percent: 20
     delay:
       percent: 50
       fixedDelay: 200ms
```

Istio 将监听对目标主机`myTarget`的调用，并对 20%的调用发送 404 响应，而不是真实的响应代码。此外，它还会将其他每个响应延迟 200 毫秒。

# 结论

MicroProfile 在容错领域定义了原语，这些原语也可以通过其他方式提供，例如在服务网格中。如果这是你的情况，你必须考虑激活哪一个。同时激活两个可能会导致意外行为。

# 总结

在本章中，你已经学习了 Eclipse MicroProfile 如何促进云原生应用程序开发，无论是混合云还是多云应用程序。我们还讨论了微服务、云原生开发和容器原生开发之间的关系，以及运行在容器上的微服务是云原生开发的理想选择。你也学习了 Eclipse MicroProfile 与 12 因子应用程序以及无服务器和函数即服务环境的关系。

我们覆盖了八个步骤，指导你进入云原生应用程序的旅程，以及 Eclipse MicroProfile 如何在每一步帮助。此外，我们还讨论了在使用 Eclipse MicroProfile 跨云应用程序时需要考虑的内容，何时在裸机机器上运行 Eclipse MicroProfile 与在虚拟机上运行 Eclipse MicroProfile 与在容器上运行 Eclipse MicroProfile，以及在运行 Eclipse MicroProfile 微服务时需要考虑的内容在混合云应用程序中，在运行 Eclipse MicroProfile OpenTracing 时需要意识到的多云部署挑战，以及最后在使用 Eclipse MicroProfile 时需要考虑的内容在服务网格中。

在这本书中，我们已经介绍了 MicroProfile 的起源，这是一个针对 Java 微服务的规范，以及它背后的历史。我们介绍了开源项目，它的使命、治理、好处、如何为其做出贡献以及其子项目的生命周期。然后我们深入探讨了构成伞式/平台发布的每个 MicroProfile API/子项目，以及不在伞式发布的子项目。

我们同样覆盖了市场上当前的 MicroProfile 实现，包括 Quarkus，并展示了如何使用 MicroProfile Starter 生成的 MicroProfile 项目来“quark”项目。我们讨论了会议应用程序，这是一个社区样本项目，展示了 MicroProfile 在不同供应商实现之间的互操作性。我们还在整个文档中提供了代码示例，以便参考和讨论，并且还提供了一个带有源代码的完整可工作项目，实现了所有 MicroProfile API，您可以自由访问、下载、编译并在您的开发努力中重用，以及开始使用 MicroProfile。后来，我们讨论了 MicroProfile 提供的响应式功能及其未来发展，例如管道中的子项目和对 MicroProfile 沙盒的子项目，以及它可能与 Jakarta EE 的未来关系。

最后，我们讨论了基于**MicroProfile**的应用程序和微服务如何适合在容器、云以及无服务器/FaaS 部署中实现解决方案。无论您是 Java 微服务的新手还是有经验的 Java 开发者，您都可以利用本书中获得的所有知识来开始开发基于这一新型的、创新的社区驱动规范的微服务，以创建可观察、可扩展、安全和高可用的混合和多云应用，从而您可以更快地为您的企业提供价值。

# 问题

1.  **Eclipse MicroProfile**如何促进云原生应用开发？

1.  云原生应用开发的两个互补关注点是什么？**Eclipse MicroProfile**如何融入这些关注点？

1.  云原生应用开发的四个关键原则是什么？**Eclipse MicroProfile**与这些原则有何关联？

1.  **Eclipse MicroProfile**如何为引导您通过云原生应用开发的八个步骤做出贡献？

1.  **Eclipse MicroProfile**与 12 因子应用有何关联？

1.  **Eclipse MicroProfile**如何促进无服务器和 FaaS 环境？

1.  在跨云实施和运行**Eclipse MicroProfile**时，您应该考虑哪些问题？

1.  使用**Eclipse MicroProfile**时会遇到哪些挑战...


# 第十二章：评估

# 第一章

1.  企业 Java 微服务具有以下特性：

    +   它是使用 Java 语言编写的。

    +   它可以使用任何 Java 框架。

    +   它可以使用任何 Java API。

    +   它必须是企业级的：可靠、可用、可扩展、安全、健壮和性能良好。

    +   它必须满足微服务架构的特性，如[`martinfowler.com/microservices/`](https://martinfowler.com/microservices/)所列，这些特性如下：

        +   通过服务实现组件化

        +   围绕业务能力组织

        +   产品而非项目

        +   智能端点和愚蠢的管道

        +   去中心化治理

        +   去中心化数据管理

        +   基础设施自动化

        +   设计失败

        +   进化式设计

1.  数字经济和数字转型的术语描述了四个不同力量的汇合...

# 第二章

1.  微 Profile 社区的主要沟通方式是他们的 Google 组，称为*Eclipse MicroProfile*。您可以通过向`microprofile@googlegroups.com`发送电子邮件来发送消息给它。另一种很好的方式来让你的声音被听到是参加每两周一次的 MicroProfile Hangout 通话。请查看 MicroProfile Google 日历以获取确切的日期、时间和会议信息以加入。

1.  微 Profile Hangout 通话作为一个论坛，讨论与会者提出的话题并做出决定，包括子项目状态、发布内容、发布日期和子项目创建批准。

1.  子项目（MicroProfile 规范）负责人或一组负责人通常是所在主题的专家，并指定为其提供便利。需要指出的重要一点是，工作组的负责人（或子项目）并不是单独塑造或决定规范的演变，或者包括哪些功能以及不包括哪些功能。他们没有否决权或在有关其规范的决策上没有最终决定权。通过分享观点、专业知识、过去经验、现有技术的分析和最佳实践，工作组将提出他们最好的建议。

1.  在 MicroProfile Google 组和/或 MicroProfile Hangout 通话中详细讨论新想法之后，如果确定值得进一步辩论，社区决定为这个新想法创建一个工作组，并指定一个负责人或一组负责人，他们通常是处理主题的专家，担任其促进者。工作组将建立一个定期每周或每两周的会议，并记录在 MicroProfile Google 日历中。任何人都可以参加会议，但通常有一小群人作为主题专家参加这些电话会议。经过几次会议，工作组决定是否将新功能带到 MicroProfile Hangout 电话中讨论其成为 MicroProfile 子项目的提案。在 MicroProfile Hangout 电话中，子项目提案可能会被拒绝或接受。接受子项目意味着它有效地解决了一个需求，丰富了规范，使其朝着优化企业 Java 以适应微服务架构的目标迈进。此刻，子项目成为正式的 MicroProfile API。一旦子项目成为 MicroProfile API，然后决定它是否应该作为独立子项目在外部或作为 MicroProfile 发布伞下的子项目。

1.  Eclipse MicroProfile 遵循时间盒的快速逐步发布计划，该计划是公开的，列在 Eclipse 基金会 MicroProfile 项目页面上。例如，从 1.x 到 2.x 的主要 Eclipse MicroProfile 发布，包括对 MicroProfile API 的重大更新，可能会引入破坏性变化。次要发布，即点发布，包括对小型 API 的更新或新的 API，以确定发布日期。目前，MicroProfile 社区的发布窗口每年在二月、六月和十一月，适用于次要和/或主要发布。

1.  沙盒仓库是一个 GitHub 仓库，用于孵化最终将成为独立仓库的想法和代码示例，为新的规范做出贡献。任何人都可以打开拉取请求，并使用沙盒进行新想法的实验，以及分享代码和文档，这些可以作为社区 Google 组、MicroProfile Hangout 通话或工作组会议讨论的一部分使用。

1.  将子项目发布在 MicroProfile 伞下/平台之外的原因是，它给了社区和最终用户一个机会来使用和测试新技术，因此在将其纳入伞下之前，在真实应用中证明它。MicroProfile 项目鼓励在将其纳入伞下/平台发布之前，新的子项目规范至少在外部发布一个版本。

1.  微服务启动器是一个样本源代码生成器，其目标是帮助开发者快速开始使用和利用企业 Java 微服务社区驱动的开源规范 Eclipse MicroProfile，通过在 Maven 项目中生成工作样本代码。

# 第三章

1.  配置属性的默认来源是环境变量、Java 系统属性和`META-INF`/`microprofile-config.properties`文件。

1.  你可以提供一个自定义 ConfigSource 实现，该实现将属性名称映射到自定义源中的值。

1.  字符串并不是唯一支持的数据类型，因为 MP-Config 通过可插拔的 SPI 支持类型转换，并且默认提供几种转换。

1.  如果你已经给了一个`defaultValue`，或者已经将属性作为`Optional<?>`值注入，你不需要为注入的属性提供一个值。

1.  复杂的属性类型可以使用自定义`Converter<?>`实现来处理，该实现接受一个字符串并返回复杂类型。

1.  当在类上指定一个注解时...

# 第四章

1.  线缆格式在只查看 HTTP 状态码来确定 HC 状态的环境中不可用。

1.  一个 MP-HC 响应可以通过使用`HealthCheckResponse#withData()`方法包括任意属性。

1.  你可以为每个服务创建一个 HealthCheck 实现，MP-HC 功能将逻辑上组合它们以产生总体状态响应。

1.  JWT 是一个 JSON Web Token，一个具有头部、载荷和签名组件的 JSON 格式的对象。

1.  声明是 JWT 载荷中的一个单独命名的值。

1.  任何可以表示为 JSON 的东西都可以用在 JWT 中。

1.  验证 JWT 的一个主要步骤是验证它是否基于配置的公钥使用 RS256 算法进行签名。

1.  可以查看除了组声明以外的其他声明来添加应用程序特定的授权决策。

# 第五章

1.  分布式跟踪提供了从端到端请求的微观视图，而指标则暴露了单个组件的标量数值。

1.  分布式跟踪系统通常提供诸如根因分析和关键路径分析、上下文化日志记录、分布式上下文传播和服务依赖关系图等功能。

1.  自动跟踪 JAX-RS 服务器端点和 MicroProfile Rest 客户端。一些供应商还可以自动跟踪 JAX-RS 客户端。

1.  这些标签对每个 REST 请求`http.method`、`http.status_code`、`http.url`、`component`、`span.kind`和`error`（如果抛出异常）进行添加。

1.  可以通过使用`@Traced`注解或注入追踪器并创建...来实现显式 instrumentation。

# 第六章

1.  不是的：默认情况下，即使没有使用任何一个 MP OpenAPI 注解，任何 REST 端点都会有 OpenAPI 生成。

1.  是的：你可以选择使用多少个或多少少的 MP OpenAPI 注解来表示你的微服务中的 REST 端点。

1.  这种观念是你预先定义好你的端点的预期合同，并将其封装在 OpenAPI 文档中，这些文档可以与你的微服务一起打包。

1.  不需要：你只需要知道请求和响应的格式，然后你就可以创建你自己的类型安全接口。

1.  通过使用`.../mp-rest/url` MP Config 设置，其中`...`是类型安全接口的接口名或传递给`RegisterRestClient`注解的 configKey。

1.  一种方法是注册一个`ClientHeadersFactory`实现。另一种方法是将标头列在`org.eclipse.microprofile.rest.client.propagateHeaders` MP-Config 属性中。

# 第七章

1.  在撰写本书时，有八个 Eclipse MicroProfile 的实现，全部都是开源的。它们是 Thorntail、Open Liberty、Apache TomEE、Payara Micro、Hammock、KumuluzEE、Launcher 和 Helidon。还有 Quarkus 作为最新加入者。

1.  应用服务器是 Java EE 应用程序的容器。应用组装器只包括应用程序需要的功能，而不是要求应用服务器运行，并且通常生成可执行的 JAR 文件。应用组装器可以生成 uberjar，一个自包含的可运行 JAR 文件，或者一个带有其运行时依赖位于子目录中的应用 jar，例如，伴随的`lib`或`libs`子目录。...

# 第八章

1.  我们在整本书以及本章中看到了许多示例，MP-Config 设置会影响应用程序和 MP 特性。

1.  只要你提供的路径存在，你应该能够看到带有关于该路径信息的成功的健康检查。

1.  它显示了关于 KeyCloak 服务器的信息。如果 KeyCloak 停止了，它会显示一个错误。

1.  因为它是在第一次请求时延迟生成的，所以找不到这个指标。

1.  待定。

1.  对于未加密的方法，行为应该相似。对于加密的方法，Swagger-UI 调用失败。

1.  你会看到错误响应。

1.  那就是编码后的 MP-JWT。你可以在 curl 命令中使用它作为`*Authorization: Bearer ...*`头值，其中你需要用在 Access Base64 Token 字段中找到的字符串替换...。

# 第九章

1.  MicroProfile Reactive Messaging 是通过连接器处理消息源的一个很好的选择，特别是在消息源以高频率生成消息且异步处理这些消息最合适的情况。

1.  MicroProfile Context Propagation 最佳支持 MicroProfile Reactive Streams Operators 和 MicroProfile Reactive Messaging，因为它允许将传统与当前线程相关联的上下文 propagate across 各种工作单元。

1.  当前支持反应式编程的规范包括 MicroProfile Reactive Streams Operators、MicroProfile Reactive Messaging 和 MicroProfile Context Propagation。

1.  在撰写本书时，那些位于...的项目...

# 第十章

1.  Eclipse MicroProfile 为使用企业级 Java 开发微服务提供了最佳方法之一。反过来，使用容器作为部署单元的微服务为在云和本地部署的高度分布式系统开发提供了最佳方法，即云原生应用。因此，基于 MicroProfile 的微服务有助于云原生应用的开发。

1.  云原生应用开发有两个互补的方面或组件：应用服务和基础设施服务。应用服务加快了云原生应用的业务逻辑开发，基础设施服务加快了其交付和部署。这两个方面是互补的，是云原生应用开发的重要组成部分。

1.  云原生应用开发是一种构建和运行应用程序的方法，它充分利用了基于四个关键信条的云计算模型：a) 基于服务的架构（微服务、微小服务、SOA 服务等等）；b) 用于服务间通信的 API 驱动方法；c) 基于容器的底层基础设施；d) DevOps 流程。 架构和通信方面与云原生应用的开发关切相关，基础设施和流程方面与它们的交付/部署相关。 Eclipse MicroProfile 与这些信条相关，因为它支持实现可以使用容器作为其底层基础设施的架构的微服务，其中微服务使用它们的 API 进行相互通信，并且使用 DevOps 流程进行开发。

1.  以下是 Eclipse MicroProfile 如何贡献于指导你向云原生应用迈进的每个八步：

    1.  发展 DevOps 文化和实践：“利用新技术、更快的方法和更紧密的协作，采纳 DevOps 的原则和文化遗产，并围绕这些价值观组织你的组织。” 虽然这是一个与组织和工作流程有关的步骤，但基于微服务的 Eclipse MicroProfile 规范可以很好地适应这种文化和流程的改变，因为微服务由于其特性，紧密支持 DevOps 流程。

    1.  使用快速微服务加速现有应用：“通过迁移到现代、基于容器的平台来加速现有应用的开发——并将单体应用拆分为微服务或微小服务以获得额外的效率提升。” 当您将单体应用拆分为微服务时，Eclipse MicroProfile 能提供很大帮助。 随着您在单体应用中识别出边界上下文，考虑使用 Eclipse MicroProfile 为每个实现边界上下文逻辑的微服务进行实现。

+   1.  使用应用服务加速开发：“通过复用性加速软件开发。云原生应用服务是即用的开发者工具。然而，为了最大化收益，这些可复用的组件必须优化并集成到 underlying 云原生基础设施中。”内存中数据网格（IMDG）和消息代理是帮助加速业务逻辑开发的应用服务。使用 Eclipse MicroProfile 开发的微服务可以通过在其方法体中调用这些应用服务来利用它们。当集成到应用服务，如 IMDG 或消息代理时，Eclipse MicroProfile 不会施加任何限制。

    1.  选择合适的工具完成合适的任务：“使用支持正确混合的框架、语言和架构的基于容器的应用平台——并且可以根据您的特定业务应用需求进行定制。”当开发者选择合适的工具来完成合适的任务时，Eclipse MicroProfile 就是这些工具之一。例如，Red Hat Application Runtimes 是一组运行时和工具的集合，其中包括 Eclipse MicroProfile、Node.js、Spring Boot 和 Vert.x。

    1.  为开发者提供自助式按需的基础设施服务：“利用容器和容器编排技术简化对底层基础设施的访问，赋予 IT 运维团队控制力和可见性，并在数据中心、私有云和公有云等各种基础设施环境中提供健壮的应用生命周期管理。”您用 Eclipse MicroProfile 开发的微服务可以部署到一个或多个容器中。通过轻松管理这些容器以及在其上运行的微服务架构，您可以加快开发周期，更快地向企业交付价值。

    1.  自动化 IT 以加速应用交付：“创建用于学习自动化语言和流程的自动化沙盒，建立跨组织协作对话以定义服务需求，创建赋予用户权力并加快交付的自助服务目录，以及使用计量、监控和计费回策略和流程。”Eclipse MicroProfile 提供了度量、容错和健康检查等功能，所有这些都可以作为 IT 自动化流程的输入。

+   1.  实现持续交付和先进的部署技术：“利用自动化交付、持续集成/持续交付（CI/CD）流水线、滚动蓝绿部署和金丝雀部署、以及 A/B 测试，加速您的云原生应用的交付。”微服务与 CI/CD 的结合可以促进先进的部署技术。例如，您可以作为蓝绿部署或金丝雀部署的一部分，将具有新功能的基于 MicroProfile 的微服务引入生产环境，一旦验证新功能按预期工作，即可将所有流量切换到它。

    1.  发展更加模块化的架构：“选择一种适合您特定需求的模块化设计，使用微服务、单体优先方法或 miniservices—或它们的组合。”在这个步骤中，您可以使用 Eclipse MicroProfile 为新的应用程序开发微服务，或者将您的单体的特定有限上下文拆分为微服务。

1.  十二因子应用是一种方法，开发者在设计和实现微服务和应用程序时可以遵循，而不受实现它们的编程语言或框架的限制。开发者可以使用 Eclipse MicroProfile 实现微服务的十二因子应用框架。十二因子应用和 Eclipse MicroProfile 不是相互排斥的，而是相互补充的。

1.  大多数，如果不是全部，市场 FaaS 提供支持 Java。因此，开发人员可以编写函数体，使用 Eclipse MicroProfile 的许多实现中的一种，这些实现都是用 Java 编写的。Eclipse MicroProfile 的易用性和丰富功能与 FaaS 平台的简单性相结合，可以大大提高开发人员向企业交付价值的速度。此外，实现 Eclipse MicroProfile 的 Quarkus 等技术，占用内存少，启动时间快，是 FaaS 的理想运行时。

1.  在使用 Eclipse MicroProfile 进行跨云部署时，您需要考虑以下事项：

    +   需要在云环境提供的基础上，配置云环境与本地环境之间的通信路由。

    +   配置 MicroProfile OpenTracing 以启用跨云环境的跟踪捕获。

+   +   监控跨云环境的 MicroProfile Metrics 信息拆分

    +   设置 CI 任务以针对适当的云环境，以维护正确的微服务。

1.  在多云环境中的分布式追踪可能会遇到挑战。我们希望实现与单云环境相同的目标，即可视化一个请求在穿过每个云中的服务以及跨云时所关联的单一路径，但处理不同的上下文传播格式和每个云中追踪数据的存储格式时可能会遇到复杂问题。第一个挑战是要确保追踪可以在不同的云环境中持续进行。这是一个问题，因为截至目前，还没有广泛采用或标准的追踪上下文格式。通常，每个追踪系统使用不同的头和格式来传播追踪上下文。第二个挑战，即使在同构追踪环境中，也要可视化来自多云环境的追踪数据。这可能是个问题，因为每个云中的追踪数据可能存储在不同的数据库中或以不同的格式存储。这可以通过将数据复制到单一统一存储中或根据需要发送缺失的追踪数据并在适当的数据格式调整后，在系统之间发送来克服。

1.  服务网格，如 Istio 或 LinkerD，在 Kubernetes 之上提供平台级别的服务，涵盖发现、路由和故障容限等领域。其中一些服务也可以在 MicroProfile 中找到。当你将 MicroProfile 应用程序部署到这样的服务网格中时，你需要考虑是否想使用 MicroProfile 中的版本还是网格中的版本。在此受影响最大的 MicroProfile 功能是故障容限，尤其是重试逻辑。
