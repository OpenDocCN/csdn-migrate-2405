# 精通 Spring 应用开发（三）

> 原文：[`zh.annas-archive.org/md5/A95A09924E8304BAE696F70C7C92A54C`](https://zh.annas-archive.org/md5/A95A09924E8304BAE696F70C7C92A54C)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：Spring 集成与 HTTP

在本章中，让我们看看 Spring 集成包如何支持 HTTP 协议。我们还将深入了解 HTTP 及其特性，以更好地理解如何使用 Spring 框架执行 HTTP 操作。

**HTTP**代表**超文本传输协议**，它又代表安全连接。该协议属于用于数据传输的应用层。它使用**传输控制** **协议/互联网协议**（**TCP/IP**）通信进行数据传输。HTTP 是一种无连接和无状态的协议，因为服务器和客户端只在请求和响应时相互知晓。只要服务器和客户端能够处理，任何类型的数据都可以通过 HTTP 发送。请求通过 Web URL 发送，即统一资源定位符。URL 包含以下部分：`http://www.domainname.com/path/?abc=xyz`

+   协议：`http://`或`https://`

+   主机：`www.domainname.com`

+   资源路径：`path`

+   查询：`abc=xyz`

# HTTP 方法和状态代码

让我们来看看 HTTP 方法和状态代码。HTTP 方法是 HTTP 协议上执行操作的通信渠道。

以下是使用的 HTTP 方法：

+   `GET`：这获取给定标识符的现有资源。

+   `PUT`：这放置一个新资源。

+   `POST`：这将更新现有资源。

+   `DELETE`：这将删除现有资源。

状态代码是关于 HTTP 消息的人类可读的诊断信息。

以下表格显示了所有可用状态代码及其含义：

| 状态代码 | 含义 |
| --- | --- |
| 200 | 请求成功 |
| 201 | POST 方法成功执行 |
| 202 | 请求已被接受进行处理 |
| 203 | 未授权查看信息 |
| 204 | 服务器没有响应 |
| 301 | 请求的数据已移至新 URL |
| 302 | 请求需要进行前向操作才能完全实现 |
| 303 | 所有 3XX 代码都指向不同的 URL，用于不同的操作，如转发 |
| 304 | 缓存未正确修改 |
| 400 | 语法错误 |
| 401 | 未经授权的请求 |
| 402 | 头部收费不匹配 |
| 403 | 禁止请求 |
| 404 | 根据提供的 URL 未找到资源 |
| 500 | 服务器发生意外错误 |
| 501 | 服务器不支持该操作 |
| 502 | 服务器负载过重 |
| 503 | 网关超时。服务器正在尝试从其他资源或服务访问数据，但未收到所需的响应。 |

## HTTP 标头

这些标头在 HTTP 请求和响应的消息中找到。它们只是由冒号分隔的名称值字符串。内容类型、缓存、响应类型等信息可以直接在标头中给出。标头通常没有任何大小限制，但服务器对标头大小有限制。

## HTTP 超时

这是一个 408 状态代码，当服务器尝试访问数据太多次而没有得到任何响应时，它会出现在网页上。即使服务器运行缓慢，也会出现这种错误。

超时可能发生在两种情况下，一种是与 Spring 集成通道交互时，可以是入站通道或出站通道，另一种是与远程位置的 HTTP 服务器交互时。

超时支持是使用 Spring 框架中可用的`RestTemplate`类完成的。以下是可用于与 Spring 集成中的 HTTP 网关和出站适配器的示例配置。

```java
<bean id="requestFactory"
      class="org.springframework.http.client.SimpleClientHttpRequestFactory">
    <property name="connectTimeout" value="5000"/>
    <property name="readTimeout"    value="5000"/>
</bean>
```

## Java 中的 HTTP 代理设置

代理设置由 Java 系统属性支持。这些属性可以设置为使用具有代理设置的服务器。以下是可以设置的属性：

+   `http.proxyHost`：代理服务器的主机名。

+   `http.proxyPort`：端口号，默认值为 80。

+   `http.nonProxyHosts`：应直接到达的主机列表，绕过代理。这是一个由`|`字符分隔的模式列表。这些模式可以以`*`字符开始或结束，用作通配符。匹配这些模式之一的任何主机将通过直接连接而不是通过代理到达。

以下是用于安全 HTTP 的代理设置：

+   `https.proxyHost`：代理服务器的主机名。

+   `https.proxyPort`：端口号，默认值为 80。

# Spring 中的代理配置支持

Spring 支持代理配置。我们只需要配置`SimpleClientHttpRequestFactory` bean，它具有一个带有`java.net.Proxy` bean 的代理属性。以下代码显示了一个示例配置：

```java
<bean id="requestFactory" class="org.springframework.http.client.SimpleClientHttpRequestFactory">
  <property name="proxy">
  <bean id="proxy" class="java.net.Proxy">
    <constructor-arg>
    <util:constant static-field="java.net.Proxy.Type.HTTP"/>
    </constructor-arg>
    <constructor-arg>
    <bean class="java.net.InetSocketAddress">
      <constructor-arg value="123.0.0.1"/>
      <constructor-arg value="8080"/>
    </bean>
    </constructor-arg>
  </bean>
  </property>
</bean>
```

## Spring 集成对 HTTP 的支持

Spring 通过适配器扩展了对 HTTP 的支持，就像 FTP 一样，其中包括网关实现。Spring 支持 HTTP 使用以下两种网关实现：

+   `HttpInboundEndpoint`：要通过 HTTP 接收消息，我们需要使用适配器或可用的网关。入站适配器称为 HTTP 入站适配器，网关称为 HTTP 入站网关。适配器需要一个 servlet 容器，比如 Tomcat 服务器或 Jetty 服务器。我们需要制作一个带有 servlet 配置的 web 应用程序，并将其部署到 web 服务器上。Spring 本身提供了一个名为的 servlet。

+   HttpRequestHandlerServlet：这个类扩展了普通的`HttpServlet`，并且位于`org.springframework.web.context.support.HttpRequestHandlerServlet`包下。由于它扩展了`HttpServlet`，它还覆盖了`init()`和`service()`方法。

以下是`web.xml`文件中的 servlet 配置：

```java
<servlet>
  <servlet-name>inboundGateway</servlet-name>
  <servlet-class>o.s.web.context.support.HttpRequestHandlerServlet</servlet-class>
</servlet>
```

以下是处理入站 HTTP 请求的网关配置。该网关接受一系列消息转换器，这些转换器将从`HttpServletRequest`转换为消息：

```java
<bean id="httpInbound" class="org.springframework.integration.http.inbound.HttpRequestHandlingMessagingGateway">
  <property name="requestChannel" ref="httpRequestChannel" />
  <property name="replyChannel" ref="httpReplyChannel" />
</bean>
```

## Spring 集成对多部分 HTTP 请求的支持

如果 HTTP 请求被包装，`MultipartHttpServletRequest`转换器将把请求转换为消息载荷，这只是一个`MultiValueMap`。这个映射将有值，这些值是 Spring 的多部分的实例。值是根据内容类型决定的。值也可以是字节数组或字符串。默认情况下，如果有一个名为`MultipartResolver`的 bean，它会被 Spring 的集成框架识别；如果有一个名为`multipartResolver`的 bean，它反过来会启用上下文。这将启用入站请求映射。

## Spring 集成对 HTTP 响应的支持

对 HTTP 请求的响应通常以 200Ok 状态码发送。要进一步自定义响应，可以使用 Spring MVC 框架。在 Spring MVC 应用程序中，我们有一个选项来自定义响应。我们可以为响应提供一个`viewName`，这个`viewName`会被 Spring MVC 的`ViewResolver`解析。我们可以配置网关以像 Spring 控制器一样运行，它返回一个视图名称作为框架的响应，我们还可以配置 HTTP 方法。

在以下配置中，您可以看到我们使用了一个集成包，并配置了`HttpRequestHandlingController` bean 的以下属性：

+   `HttpRequestChannel`

+   `HttpReplyChannel`

+   `viewName`

+   `SupportedMedthodNames`

+   以下代码片段显示了`HttpInbound` bean 的配置。

+   我们还可以配置支持的 HTTP 方法。

```java
<bean id="httpInbound" class="org.springframework.integration.http.inbound.HttpRequestHandlingController">
  <constructor-arg value="true" /> <!-- indicates that a reply is expected -->
  <property name="requestChannel" ref="httpRequestChannel" />
  <property name="replyChannel" ref="httpReplyChannel" />
  <property name="viewName" value="jsonView" />
  <property name="supportedMethodNames" >
    <list>
      <value>GET</value>
      <value>DELETE</value>
    </list>
  </property>
</bean>
```

# 配置出站 HTTP 消息

Spring 提供了`HttpRequestExecutingMessageHandler`，它以字符串 URL 作为构造函数参数。该类有一个名为`ReponseChannel`的属性，也需要进行配置。

该 bean 将通过读取构造函数中配置的 URL 调用`RestTemplate`类，`RestTemplate`调用`HttpMessageConverters`。读取`HttpMessageConverters`列表，并生成`HttpRequest`主体。

转换器和`HttpRequestExecutingMessageHandler`在以下代码中显示：

```java
<bean id="httpOutbound" class="org.springframework.integration.http.outbound.HttpRequestExecutingMessageHandler">
  <constructor-arg value="http://localhost:8080/myweb" />
  <property name="outputChannel" ref="responseChannel" />
</bean>
```

或者

```java
<bean id="httpOutbound" class="org.springframework.integration.http.outbound.HttpRequestExecutingMessageHandler">
  <constructor-arg value="http://localhost:8080/myweb" />
  <property name="outputChannel" ref="responseChannel" />
  <property name="messageConverters" ref="messageConverterList" />
  <property name="requestFactory" ref="customRequestFactory" />
</bean>
```

## 配置出站网关的 cookies

`OutboundGateway`具有传输 cookies 属性，接受 true 或 false 的布尔值。响应中的标头包含一个设置 cookies 参数，如果`transfer-cookie`属性设置为`True`，则将响应转换为 cookie。

# 配置既无响应又有响应的入站网关

使用以下代码配置无响应的`InboundGateway`请求：

```java
<int-http:inbound-channel-adapter id="httpChannelAdapter" channel="requests"
    supported-methods="PUT, DELETE"/>
```

对于需要响应的请求：

```java
<int-http:inbound-gateway id="inboundGateway"
    request-channel="requests"
    reply-channel="responses"/>
```

# 入站通道适配器或网关的 RequestMapping 支持

`requestmapping`配置可以用于入站通道适配器或网关，如下所示：

```java
<inbound-gateway id="inboundController"
    request-channel="requests"
    reply-channel="responses"
    path="/foo/{fooId}"
    supported-methods="GET"
    view-name="foo"
    error-code="oops">
   <request-mapping headers="User-Agent"
<!—-headers=""-->
     params="myParam=myValue"
     consumes="application/json"
     produces="!text/plain"/>
</inbound-gateway>
```

基于此配置，命名空间解析器将创建`IntegrationRequestMappingHandlerMapping`的实例（如果尚不存在），`HttpRequestHandlingController` bean，并与之关联`RequestMapping`的实例，然后将其转换为 Spring MVC 的`RequestMappingInfo`。

使用路径和支持的方法，`<http:inbound-channel-adapter>`或`<http:inbound-gateway>`的属性，`<request-mapping>`直接转换为 Spring MVC 中`org.springframework.web.bind.annotation.RequestMapping`注解提供的相应选项。

`<request-mapping>`子元素允许您配置多个 Spring 集成 HTTP 入站端点到相同的路径（甚至相同的支持方法），并根据传入的 HTTP 请求提供不同的下游消息流。

## 使用 HTTP 入站端点配置 RequestMapping

我们还可以声明一个 HTTP 入站端点，并在 Spring 集成流程中应用路由和过滤逻辑，以实现相同的结果。这允许您尽早将消息传递到流程中，例如：

```java
<int-http:inbound-gateway request-channel="httpMethodRouter"
    supported-methods="GET,DELETE"
    path="/process/{entId}"
    payload-expression="#pathVariables.entId"/>
<int:router input-channel="httpMe
thodRouter" expression="headers.http_requestMethod">
    <int:mapping value="GET" channel="in1"/>
    <int:mapping value="DELETE" channel="in2"/>
</int:router>
<int:service-activator input-channel="in1" ref="service" method="getEntity"/>
<int:service-activator input-channel="in2" ref="service" method="delete"/>
```

## 配置入站通道适配器以从 URL 读取请求信息

我们还可以配置入站通道适配器以接受使用 URI 的请求。

URI 可以是`/param1/{param-value1}/param2/{param-value2}`。 URI 模板变量通过有效负载表达式属性与消息有效负载进行映射。 URI 路径中的某些变量也可以与标头进行映射：

```java
<int-http:inbound-channel-adapter id="inboundAdapterWithExpressions"
    path="/var-1/{phone}/var-2/{username}"
    channel="requests"
    payload-expression="#pathVariables.firstName">
    <int-http:header name="var-2" expression="#pathVariables.username"/>
</int-http:inbound-channel-adapter>
```

以下是可以在配置中使用的有效负载表达式列表：

+   `#requestParams`：来自`ServletRequest`参数映射的`MultiValueMap`。

+   `#pathVariables`：URI 模板占位符及其值的映射。

+   `#matrixVariables`：`MultiValueMap`的映射。

+   `#requestAttributes`：与当前请求关联的`org.springframework.web.context.request.RequestAttributes`。

+   `#requestHeaders`：当前请求的`org.springframework.http.HttpHeaders`对象。

+   `#cookies`：当前请求的`javax.servlet.http.Cookies`的`<String，Cookie>`映射。

# 为 HTTP 响应配置出站网关

出站网关或出站通道适配器配置与 HTTP 响应相关，并提供配置响应的选项。 HTTP 请求的默认响应类型为 null。响应方法通常为 POST。如果响应类型为 null 且 HTTP 状态代码为 null，则回复消息将具有`ResponseEntity`对象。在以下示例配置中，我们已配置了预期：

```java
<int-http:outbound-gateway id="example"
    request-channel="requests"
    URL="http://localhost/test"
    http-method="POST"
    extract-request-payload="false"
    expected-response-type="java.lang.String"
    charset="UTF-8"
    request-factory="requestFactory"
    reply-timeout="1234"
    reply-channel="replies"/>
```

## 为不同的响应类型配置出站适配器

现在，我们将向您展示两个配置出站适配器的示例，使用不同的响应类型。

在这里，使用预期的响应类型表达式与值有效负载：

```java
<int-http:outbound-gateway id="app1"
    request-channel="requests"
    URL="http://localhost/myapp"
    http-method-expression="headers.httpMethod"
    extract-request-payload="false"
    expected-response-type-expression="payload"
    charset="UTF-8"
    request-factory="requestFactory"
    reply-timeout="1234"
    reply-channel="replies"/>
```

现在，配置出站通道适配器以提供字符串响应：

```java
<int-http:outbound-channel-adapter id="app1"
    url="http://localhost/myapp"
    http-method="GET"
    channel="requests"
    charset="UTF-8"
    extract-payload="false"
    expected-response-type="java.lang.String"
    request-factory="someRequestFactory"
    order="3"
    auto-startup="false"/>
```

# 将 URI 变量映射为 HTTP 出站网关和出站通道适配器的子元素

在本节中，我们将看到 URI 变量和 URI 变量表达式的用法，作为 HTTP 出站网关配置的子元素。

如果您的 URL 包含 URI 变量，可以使用 Uri-variable 子元素进行映射。此子元素适用于 HTTP 出站网关和 HTTP 出站通道适配器：

```java
<int-http:outbound-gateway id="trafficGateway"
    url="http://local.yahooapis.com/trafficData?appid=YdnDemo&amp;zip={zipCode}"
    request-channel="trafficChannel"
    http-method="GET"
    expected-response-type="java.lang.String">
    <int-http:uri-variable name="zipCode" expression="payload.getZip()"/>
</int-http:outbound-gateway>
```

`Uri-variable`子元素定义了两个属性：`name`和`expression`。`name`属性标识 URI 变量的名称，而`expression`属性用于设置实际值。使用`expression`属性，您可以利用**Spring Expression Language**（**SpEL**）的全部功能，这使您可以完全动态地访问消息负载和消息标头。例如，在上面的配置中，将在消息的负载对象上调用`getZip()`方法，并且该方法的结果将用作名为`zipCode`的 URI 变量的值。

自 Spring Integration 3.0 以来，HTTP 出站端点支持`Uri-variables-expression`属性，用于指定应该评估的`Expression`，从而为 URL 模板中的所有 URI 变量占位符生成一个映射。它提供了一种机制，可以根据出站消息使用不同的变量表达式。此属性与`<Uri-variable/>`子元素互斥：

```java
<int-http:outbound-gateway
  url="http://foo.host/{foo}/bars/{bar}"
  request-channel="trafficChannel"
  http-method="GET"
  Uri-variables-expression="@uriVariablesBean.populate(payload)"
  expected-response-type="java.lang.String"/>
```

## 使用 HTTP 出站网关和 HTTP 入站网关处理超时

以下表格显示了处理 HTTP 出站和 HTTP 入站网关的差异：

| **HTTP 出站网关中的超时** | **HTTP 入站网关中的超时** |
| --- | --- |
| `ReplyTimeOut`映射到`HttpRequestExecutingMessageHandler`的`sendTimeOut`属性。 | 在这里，我们使用`RequestTimeOut`属性，它映射到`HttpRequestHandlingMessagingGateway`类的`requestTimeProperty`。 |
| `sendTimeOut`的默认值为`1`，发送到`MessageChannel`。 | 默认超时属性为 1,000 毫秒。超时属性将用于设置`MessagingTemplate`实例中使用的`sendTimeOut`参数。 |

# Spring 对标头自定义的支持

如果我们需要对标头进行进一步的自定义，则 Spring Integration 包为我们提供了完整的支持。如果在配置中明确指定标头名称，并使用逗号分隔的值，将覆盖默认行为。

以下是进一步标头自定义的配置：

```java
<int-http:outbound-gateway id="httpGateway"
    url="http://localhost/app2"
    mapped-request-headers="boo, bar"
    mapped-response-headers="X-*, HTTP_RESPONSE_HEADERS"
    channel="someChannel"/>

<int-http:outbound-channel-adapter id="httpAdapter"
    url="http://localhost/app2"
    mapped-request-headers="boo, bar, HTTP_REQUEST_HEADERS"
    channel="someChannel"/>
```

另一个选项是使用 header-mapper 属性，该属性采用 DefaultHttpHeaderMapper 类的配置。

该类配备了用于入站和出站适配器的静态工厂方法。

以下是`header-mapper`属性的配置：

```java
<bean id="headerMapper" class="o.s.i.http.support.DefaultHttpHeaderMapper">
  <property name="inboundHeaderNames" value="foo*, *bar, baz"/>
  <property name="outboundHeaderNames" value="a*b, d"/>
</bean>
```

# 使用 Spring 的 RestTemplate 发送多部分 HTTP 请求

大多数情况下，我们在应用程序中实现了文件上传功能。文件作为多部分请求通过 HTTP 发送。

在本节中，让我们看看如何使用`RestTemplate`配置入站通道适配器以通过 HTTP 请求发送文件。

让我们使用入站通道适配器配置服务器，然后为其编写客户端：

```java
<int-http:inbound-channel-adapter id="httpInboundAdapter"
  channel="receiveChannel"
  name="/inboundAdapter.htm"
  supported-methods="GET, POST"/>
<int:channel id="receiveChannel"/>
<int:service-activator input-channel="receiveChannel">
  <bean class="org.springframework.integration.samples.multipart.MultipartReceiver"/>
</int:service-activator>
<bean id="multipartResolver" class="org.springframework.web.multipart.commons.CommonsMultipartResolver"/>
```

`httpInboundAdapter`将接收请求并将其转换为带有`LinkedMultiValueMap`负载的消息。然后，我们将在`multipartReceiver`服务激活器中解析它。

```java
public void receive(LinkedMultiValueMap<String, Object> multipartRequest){
  System.out.println("### Successfully received multipart request ###");
  for (String elementName : multipartRequest.keySet()) {
    if (elementName.equals("company")){
      System.out.println("\t" + elementName + " - " +((String[]) multipartRequest.getFirst("company"))[0]);
    }
    else if (elementName.equals("company-logo")){
      System.out.println("\t" + elementName + " - as UploadedMultipartFile: " + ((UploadedMultipartFile) multipartRequest.getFirst("company-logo")).getOriginalFilename());
    }
  }
}
```

现在，让我们编写一个客户端。通过客户端，我们指的是创建一个地图并向其中添加文件。

1.  现在，我们将创建一个`MultiValueMap`：

```java
MultiValueMap map = new LinkedMultiValueMap();
```

1.  地图可以填充值，例如个人的详细信息：

```java
Resource anjanapic = new ClassPathResource("org/abc/samples/multipart/anjana.png");
map.add("username","anjana");
map.add("lastname","mankale");
map.add("city","bangalore");
map.add("country","India");
map.add("photo",anjana.png);
```

1.  此步骤是创建标头并设置内容类型：

```java
HttpHeaders headers = new HttpHeaders();
headers.setContentType(new MediaType("multipart", "form-data"));
```

1.  我们需要将`header`和`map`作为请求传递给`HttpEntity`：

```java
HttpEntity request = new HttpEntity(map, headers);
```

1.  让我们使用`RestTemplate`传递请求：

```java
RestTemplate template = new RestTemplate();
String Uri = "http://localhost:8080/multipart-http/inboundAdapter.htm";
ResponseEntity<?> httpResponse = template.exchange(Uri, HttpMethod.POST, request, null
```

现在，我们应该得到一个输出，其中照片已上传到服务器。

# 总结

在本章中，我们已经了解了 HTTP 和 Spring Integration 对访问 HTTP 方法和请求的支持。我们还演示了多部分请求和响应，并展示了如何配置入站和出站 HTTP 网关和适配器。

我们已经学习了通过配置 Spring 的入站和出站网关来发送多部分 HTTP 请求。我们还演示了如何使用多值映射来填充请求并将映射放入 HTTP 头部。最后，我们看到了可用的有效负载表达式列表。

在下一章中，让我们来看看 Spring 对 Hadoop 的支持。


# 第七章：与 Hadoop 一起使用 Spring

在构建现代 Web 应用程序的架构中，处理大量数据一直是一个主要挑战。 Hadoop 是 Apache 的开源框架，提供了处理和存储大量数据的库。它提供了一种可扩展、成本效益和容错的解决方案，用于存储和处理大量数据。在本章中，让我们演示 Spring 框架如何支持 Hadoop。 Map 和 Reduce、Hive 和 HDFS 是与基于云的技术一起使用的一些 Hadoop 关键术语。除了 Apache Hadoop 之外，Google 还推出了自己的 Map 和 Reduce 以及分布式文件系统框架。

# Apache Hadoop 模块

Apache Hadoop 由以下模块组成：

+   **Hadoop Common**：这是 Hadoop 的其他模块使用的通用模块。它类似于一个实用程序包。

+   **Hadoop 分布式文件系统**：当我们需要在各种机器或机器集群上存储大量数据时，可以考虑使用 Hadoop 分布式文件系统。

+   **Hadoop Yarn**：想象一种情景，我们在云上有许多需要在特定时间通过发送电子邮件通知租户重新启动或重启的服务器。 Hadoop Yarn 可用于在计算机或集群之间调度资源。

+   **Hadoop Map 和 Reduce**：如果我们需要处理大量数据集，可以将其分解为小集群并将它们作为单元进行处理，然后稍后合并它们。这可以通过 Apache map 和 reduce 提供的库来实现。

## Hadoop 的 Spring 命名空间

以下是需要用来将 Hadoop 框架与 Spring 集成的命名空间。[`www.springframework.org/schema/hadoop/spring-hadoop.xsd`](http://www.springframework.org/schema/hadoop/spring-hadoop.xsd)定义了 Spring-Hadoop 的 XSD，通常在`application-context.xml`文件中使用。 XSD 详细说明了如何使用 Spring 框架配置 Hadoop 作业。

```java
<?xml version="1.0" encoding="UTF-8"?>
<beans 

   xsi:schemaLocation="
    http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd
    http://www.springframework.org/schema/hadoop http://www.springframework.org/schema/hadoop/spring-hadoop.xsd">

   <bean id ... >

   4<hdp:configuration ...>
</beans>
```

## Hadoop 分布式文件系统

**Hadoop 分布式文件系统**（**HDFS**）用于在分布式文件系统上存储大量数据。 HDFS 将元数据和应用程序数据分别存储在不同的服务器上。用于存储元数据的服务器称为`NameNode`服务器。用于存储应用程序数据的服务器称为`DataNode`服务器。`NameNode`和`DataNodes`以主从架构运行。通常，一个`NameNode`会有许多`DataNodes`。`NameNodes`存储文件的命名空间，并将文件分割成许多小块存储在`DataNodes`上。`DataNodes`通常根据`NameNode`的指令执行功能，如块创建、复制和删除。因此，与 Hadoop 的主要任务将涉及与文件系统的交互。这可能包括创建文件、解析文件进行处理或删除文件。

可以通过多种方式访问 Hadoop 文件系统。我们在这里列出了一些：

+   `hdfs`：它使用 RPC 进行通信，使用的协议是`hdfs://`。客户端、服务器和集群需要具有相同的版本，否则将发生序列化错误。

+   `hftp`和`hsftp`：这些是基于 HTTP 的、与版本无关的协议，前缀为`hftp://`。

+   `webhdfs`：这是基于 REST API 的 HTTP，并且也是版本无关的。

抽象类`org.apache.hadoop.fs.FileSystem`的行为类似于 Hadoop 文件系统实现的入口点。Spring 框架通过子类`SimplerFileSystem`扩展了这个类。这个子类包含了所有的文件操作方法，比如从一个位置复制到另一个位置。

Spring 框架提供了一个处理 Hadoop 分布式文件系统的包。包`org.springframework.data.hadoop.fs`中有处理文件资源的类。

`HdfsResourceLoader`是 Spring 的 Hadoop 文件系统包中的一个类，用于加载 Hadoop 文件系统中的资源。它有以配置对象作为输入的构造函数。`HdfsResourceLoader`的构造函数如下所示。它还有从指定路径获取资源和在使用后关闭文件流的方法。

```java
HdfsResourceLoader(Configuration config)
HdfsResourceLoader(Configuration config) 
HdfsResourceLoader(Configuration config, URI uri) 
HdfsResourceLoader(Configuration config, URI uri, String user) HdfsResourceLoader(FileSystem fs)
```

使用以下命令配置 Spring 使用`webhdfs`：

```java
<hdp:configuration>
  fs.default.name=webhdfs://localhost
  ...
</hdp:configuration>
```

要手动配置 URI 和文件系统 ID，可以给出以下配置：

```java
<!-- manually creates the default SHDP file-system named 'hadoopFs' -->
<hdp:file-system uri="webhdfs://localhost"/>

<!-- creates a different FileSystem instance --> 
<hdp:file-system id="old-cluster" uri="hftp://old-cluster/"/>
```

诸如**Rhino**和**Groovy**之类的语言提供了 Java 脚本或使用 Python 来进行 HDFS 配置。以下是一个示例。可以配置脚本在启动时或有条件的启动时运行。可以用于此配置的两个脚本变量是`run-at-start-up`和`evaluate`。脚本也可以配置为作为任务启动（这意味着作为批处理作业启动）。

```java
<beans  ...> 
<hdp:configuration .../>

<hdp:script id="inlined-js" language="javascript" run-at-startup="true">
  importPackage(java.util);
  name = UUID.randomUUID().toString()
  scriptName = "src/test/resources/test.properties"
  // fs - FileSystem instance based on 'hadoopConfiguration' bean
  // call FileSystem#copyFromLocal(Path, Path)  
  fs.copyFromLocalFile(scriptName, name)
  // return the file length 
  fs.getLength(name)
</hdp:script>

</beans>
```

这里显示了一些与隐式变量和与隐式变量相关的类：

+   `hdfsRL-org.springframework.data.hadoop.io.HdfsResourceLoader`：一个 HDFS 资源加载器（依赖于`hadoop-resource-loader`或单例类型匹配，根据'`cfg`'自动创建）。

+   `distcp-org.springframework.data.hadoop.fs.DistributedCopyUtil`：对`DistCp`进行编程访问。

+   `fs-org.apache.hadoop.fs.FileSystem`：一个 Hadoop 文件系统（依赖于'`hadoop-fs`' bean 或单例类型匹配，根据'cfg'创建）。

+   `fsh-org.springframework.data.hadoop.fs.FsShell`：一个文件系统 shell，将 hadoop `fs`命令作为 API 暴露出来。

## HBase

Apache HBase 主要是 Hadoop 的键值存储。它实际上是一个易于扩展的数据库，可以容纳数百万行和列。它可以跨硬件进行扩展，类似于 NoSQL 数据库。它与 Map 和 Reduce 集成，并且最适合使用 RESTFUL API。HBase 源自 Google 的 bigdata。它已经被 Netflix、Yahoo 和 Facebook 使用。它也是内存密集型的，因为它旨在处理大量数据并且必须针对硬件进行扩展。

让我们使用 Eclipse 和 Hadoop HBase 创建一个简单的员工表。在 Eclipse 中，只需添加以下 JAR 文件，或者如果您使用 Maven，请确保在 Maven 的`pom.xml`文件中更新以下 JAR 文件：

+   `hbase-0.94.8.jar`

+   `commons-logging-1.1.1.jar`

+   `log4j-1.2.16.jar`

+   `zookeeper-3.4.5.jar`

+   `hadoop-core-1.1.2.jar`

+   `commons-configuration-1.6.jar`

+   `common-lang-2.5.jar`

+   `protobuf-java-2.4.0a.jar`

+   `slf4j-api-1.4.3.jar`

+   `slf4j-log4j12-1.4.3.jar`

创建一个`Main`类，并使用以下代码。这个类将使用`HbaseAdmin`类创建一个包含 ID 和 Name 两列的员工表。这个类有用于在 Hadoop 中创建、修改和删除表的方法。

```java
import org.apache.hadoop.conf.Configuration;

import org.apache.hadoop.hbase.HBaseConfiguration;

import org.apache.hadoop.hbase.HColumnDescriptor;

import org.apache.hadoop.hbase.HTableDescriptor;

import org.apache.hadoop.hbase.client.HBaseAdmin;

public class HbaseTableCreation
{
  public static void main(String[] args) throws IOException {
    HBaseConfiguration hc = new HBaseConfiguration(new Configuration());

    HTableDescriptor ht = new HTableDescriptor("EmployeeTable"); 

    ht.addFamily( new HColumnDescriptor("Id"));

    ht.addFamily( new HColumnDescriptor("Name"));

    System.out.println( "connecting" );

    HBaseAdmin hba = new HBaseAdmin( hc );

    System.out.println( "Creating Table EmployeeTable" );

    hba.createTable( ht );

    System.out.println("Done....EmployeeTable..");
  }
}
```

HBase 得到了 Spring Framework 的支持，并且 Spring Hadoop 包中还创建了一个`factoryBean`来支持它。`HbaseConfigurationFactoryBean` bean 位于`org.springframework.data.hadoop.hbase`包中。`HBaseAccessor`类是一个抽象类，并且已经被两个子类`HbaseTemplate`和`HbaseInterceptors`扩展。

![HBase](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr-app-dev/img/B02116_07_01.jpg)

Spring 提供了一个名为`HBaseTemplate`的核心类。当 HBase 被实现时，这个类是应用程序的第一个接触点。这个类有访问表的所有方法，比如`execute`、`find`、`find all`等等。

这个类有以下构造函数：

```java
HbaseTemplate() 
HbaseTemplate(Configuration configuration)
```

这是可以在应用程序的`context.xml`或`Hbasecontext.xml`文件中使用的 HBase 模板配置：

```java
// default HBase configuration
<hdp:hbase-configuration/>

// wire hbase configuration (using default name 'hbaseConfiguration') into the template 
<bean id="htemplate" class="org.springframework.data.hadoop.hbase.HbaseTemplate" p:configuration-ref="hbaseConfiguration"/>
```

让我们也看看如何使用`HBaseTemplate`来检索表信息，以下是一个示例代码片段：

```java
// writing to 'EmployeeTable'
template.execute("EmployeeTable", new TableCallback<Object>() {
  @Override
  public Object doInTable(HTable table) throws Throwable {
    Put p = new Put(Bytes.toBytes("Name"));
    p.add(Bytes.toBytes("Name"), Bytes.toBytes("SomeQualifier"), Bytes.toBytes("Anjana"));
    table.put(p);
    return null;
  }
});

// read each row from 'EmployeeTable'
List<String> rows = template.find("EmployeeTable", "Name", new RowMapper<String>() {
  @Override
  public String mapRow(Result result, int rowNum) throws Exception {
    return result.toString();
  }
}));
```

Spring 还支持 AOP 与 Hadoop HBase 的集成，并有一个包来处理所有 AOP 事件，使用`HBaseInterceptors`。这个类实现了以下接口：

+   `org.aopalliance.aop.Advice`

+   `org.aopalliance.intercept.Interceptor`

+   `org.aopalliance.intercept.MethodInterceptor`

+   `InitializingBean`

`HBaseInterceptors`与`HBaseSynchronizationManager`可用于在方法调用之前将 HBase 表绑定到线程，或在方法调用之后将其分离。

+   这是 Spring 的 Hadoop HBase 配置，用于创建一个 HBase 配置对象来管理 HBase 配置连接：

```java
<!-- default bean id is 'hbaseConfiguration' that uses the existing 'hadoopCconfiguration' object ->
<hdp:hbase-configuration configuration-ref="hadoopCconfiguration" />
```

+   这是 Spring 的 Hadoop HBase 配置，用于在应用程序上下文为空或由于某种原因不可用时管理代理和连接：

```java
<!-- delete associated connections but do not stop the proxies -->
<hdp:hbase-configuration stop-proxy="false" delete-connection="true">
  toooo=baaaa
  property=value
</hdp:hbase-configuration>
```

+   这是一个名为`ZooKeeper`的高性能协调服务器的配置，它用于 Hadoop 分布式系统：

```java
<!-- specify ZooKeeper host/port -->
<hdp:hbase-configuration zk-quorum="${hbase.host}" zk-port="${hbase.port}">
```

我们还可以从文件中加载属性，如下所示：

```java
<hdp:hbase-configuration properties-ref="some-props-bean" properties-location="classpath:/conf/testing/hbase.properties"/>
```

## Map 和 Reduce

**Map 和 Reduce**是一种允许大规模扩展的编程方法。术语“Map 和 Reduce”意味着我们将使用映射来处理数据。我们可以看到这里有两个步骤。第一个是创建映射（创建具有键值对的映射），第二个是减少，它读取第一步创建的映射，并将其分解成许多较小的映射。

让我们想象一个与 Map 和 Reduce 相关的场景——假设我们需要获取印度老虎的数量，并做一些工作来改善它们的生存条件，以免它们灭绝。我们可能有老虎数量的平均数字。假设我们派遣人员到不同的邦，他们收集到的信息如下：卡纳塔克邦（100），泰米尔纳德邦（150），等等。然后我们将这些数字合并成一个数字，以得到老虎的总数量。人口的映射可以被看作是一个并行过程（映射作业），而合并结果可以被看作是一个减少作业。

## 为 Map 和 Reduce 在 Spring 中创建一个配置对象

配置对象保存有关 Map 和 Reduce 作业的信息。配置对象本身是一个映射到类`ConfigurationFactoryBean`的 bean 定义，具有默认名称`hadoopConfiguration`。

配置对象可以简单地配置如下：

```java
<hdp:configuration />
```

这是配置对象的另一种变化：

```java
<hdp:configuration resources="classpath:/custom-site.xml, classpath:/hq-site.xml">
```

另一种变化是直接在`configuration`标记中使用`java.properties`直接配置 Hadoop 资源，如下所示：

```java
<hdp:configuration>
        fs.default.name=hdfs://localhost:9000
        hadoop.tmp.dir=/tmp/hadoop
        electric=sea
     </hdp:configuration>
```

您还可以使用 Spring 的属性占位符来外部化属性，如下所示：

```java
<hdp:configuration>
        fs.default.name=${hd.fs}
        hadoop.tmp.dir=file://${java.io.tmpdir}
        hangar=${number:18}
     </hdp:configuration>
          <context:property-placeholder location="classpath:hadoop.properties" />
```

### 使用 Spring 创建 Map 和 Reduce 作业

可以使用 Spring Framework 将 Map 和 Reduce 安排为作业。Spring Framework 带有`spring-data-hadoop`包，支持 Map 和 Reduce。为此，我们需要确保我们有 Apache Hadoop 核心包。

让我们实现一个简单的场景，统计输入文件中每个单词的出现次数。创建一个简单的 Maven Java 项目，具有以下所述的依赖关系。

#### Maven 项目的依赖关系

我们需要在`pom.xml`文件中添加这些依赖项：

```java
< !-- Spring Data Apache Hadoop -- >
< dependency >
    < groupId > org.springframework.data </ groupId >
    < artifactId  > spring-data-hadoop </ artifactId >
    < version > 1.0.0.RELEASE </ version >
< /dependency >
< !-- Apache Hadoop Core –- >
< dependency >
    < groupId > org.apache.hadoop </ groupId >
    < artifactId > hadoop-core </ artifactId >
    < version > 1.0.3 </version >
</dependency>
```

Apache Hadoop Map 和 Reduce 带有一个映射器类，可用于创建映射，以解决读取内容并存储单词出现次数的问题，使用键值对。文件中的每一行将被分解为要存储在映射中的单词。

我们可以通过扩展`ApacheMapper`类并覆盖 map 方法来创建自定义映射器，如下所示：

```java
public class CustomWordMapper extends Mapper<LongWritable, Text, Text, IntWritable> {
  private Text myword = new Text();

  @Override
  protected void map(LongWritable key, Text value, Context context) throws IOException, InterruptedException {
    String line = value.toString();
    StringTokenizer lineTokenz = new StringTokenizer(line);
    while (lineTokenz.hasMoreTokens()) {
      String cleaned_data = removeNonLettersNonNumbers(lineTokenz.nextToken());
        myword.set(cleaned_data);
        context.write(myword, new IntWritable(1));
    }
  }

  /**
  * Replace all Unicode characters that are neither numbers nor letters with an empty string.
  * @param original, It is the original string
  * @return a string object that contains only letters and numbers
  */
  private String removeNonLettersNonNumbers (String original) {
    return original.replaceAll("[^\\p{L}\\p{N}]", "");
  }
}
```

`CustomWordMapper`类执行以下操作：

1.  创建`Text()`类的`myword`实例。

1.  覆盖超类`Mapper`的`map`方法，并实现以下步骤：

1.  文本对象转换为字符串，并赋值给字符串`line`。

1.  Line 是一个传递给字符串标记器的字符串对象。

1.  使用`while`循环遍历字符串标记器，并调用`removeNonLettersNonNumbers`方法。返回的字符串赋值给`myword`文本实例。

1.  调用`context.write(myword,newIntwritable(1))`方法。

1.  有一个方法可以删除非字母和非数字，使用`string.replaceAll()`方法。最后返回一个只包含数字和字母的字符串对象。

接下来我们将创建一个 reducer 组件。reducer 组件将执行以下任务：

1.  扩展`reducer`类。

1.  为 reducer 类创建一个字符串属性，该属性接受需要搜索的字符串及其需要找到的出现次数。

1.  覆盖`reduce`方法。

1.  删除不需要的键值对。

1.  保留所需的键值对。

1.  检查输入键是否已经存在。如果存在，它将获取出现次数，并将最新值存储。

```java
import org.apache.hadoop.io.IntWritable;
import org.apache.hadoop.io.Text;
import org.apache.hadoop.mapreduce.Reducer;

public class CustomWordReducer extends Reducer<Text, IntWritable, Text, IntWritable> {
    protected static final String MY_TARGET_TEXT = "SPRING";

@Override
 protected void reduce(Text keyTxt, Iterable<IntWritable> values, Context context) throws IOException, InterruptedException {
        if (containsTargetWord(keyTxt)) {
            int wCount = 0;
            for (IntWritable value: values) {
               wCount += value.get();
            }
            context.write(key, new IntWritable(wCount));
        }
    }
    private boolean containsTargetWord(Text keyTxt) {
        return keyTxt.toString().equals(MY_TARGET_TEXT);
    }
}
```

1.  使用 HDFS 端口和输入输出文件路径配置`application.properties`文件。

1.  这是示例`application.properties`文件：

```java
fs.default.name=hdfs://localhost:9000
mapred.job.tracker=localhost:9001
input.path=/path/to/input/file/
output.path=/path/to/output/file

```

一旦属性被配置，它应该在 Spring 上下文中可用。因此，在 Spring 的`application-context.xml`文件中使用`property-placeholder`配置属性文件。这是需要在`application-conext.xml`文件中添加的配置片段。

```java
<context:property-placeholder location="classpath:application.properties" />
```

您可以直接在`application-context.xml`文件中配置 Apache Hadoop，也可以使用属性文件并从属性文件中读取键值对。由于我们使用了属性文件，我们将从属性文件中读取值。以下代码片段显示`${mapred.job.tracker}`是属性文件中的一个键。您可以看到默认名称也是使用键`${fs.default.name}`从属性文件中配置的。在`application-context.xml`文件中配置 Apache Hadoop 如下：

```java
<hdp:configuration>
  fs.default.name=${fs.default.name}
  mapred.job.tracker=${mapred.job.tracker}
</hdp:configuration>
```

1.  接下来，我们需要在 Spring 中配置 Hadoop 作业：

1.  提供作业 ID。

1.  指定输入路径；它将从属性文件中读取。

1.  指定输出路径；它将从属性文件中读取。

1.  按类进行 Jar。

1.  Mapper 类引用自定义 mapper 类。

1.  Reducer 类引用自定义 reducer 类。

1.  这是需要在`application-xccontext.xml`文件中可用的配置片段。在`application-context.xml`文件中配置 Hadoop 作业如下：

```java
<hdp:job id="wordCountJobId"
input-path="${input.path}"
output-path="${output.path}"
jar-by-class="net.qs.spring.data.apachehadoop.Main"
mapper="com.packt.spring.data.apachehadoop.CustomWordMapper"
reducer="com.packt.spring.data.apachehadoop.CustomWordReducer"/>
```

1.  最后，我们需要在`application-context.xml`文件中配置作业运行器。作业运行器配置告诉 Spring 框架何时启动作业。在这里，我们已经配置了作业运行器在启动时启动`wordcountjob`。

1.  这是作业运行器的配置片段。配置`application-context.xml`文件以运行 Hadoop 作业。

```java
<hdp:job-runner id="wordCountJobRunner" job-ref="wordCountJobId" run-at-startup="true"/>
```

由于这是一个独立的 Spring 应用程序，我们没有一个将调用应用程序上下文的 web 模块。上下文需要在一个类文件中加载。因此，让我们创建一个带有`static`方法的`Main`类来加载`application-context.xml`文件。

我们可以创建一个在启动时加载`application-context.xml`文件的类，如下所示：

```java
import org.springframework.context.ApplicationContext;
importorg.springframework.context.support.ClassPathXmlApplicationContext;

public class Main {
  public static void main(String[] arguments) {
    ApplicationContext ctx = new ClassPathXmlApplicationContext("application-context.xml");
  }
}
```

让我们创建一个名为`myinput.txt`的文件，内容如下：

```java
SPRING IS A SEASON. SPRING IS A FRAMEWORK IN JAVA. ITS SPRING IN INDIA. SPRING IS GREEEN. SPRING SPRING EVERY WHERE
```

接下来，我们需要通过执行此命令向 HDFS 提供输入文件：

```java
hadoop dfs -put myinput.txt /input/myinput.txt
hadoop dfs -ls /input

```

运行`Main`类以查看输出。

## 使用 Hadoop 流和 Spring DataApache Hadoop 进行 Map 和 Reduce 作业

在本节中，我们将演示使用 Unix shell 命令进行 Map 和 Reduce 数据流。由于这与 Hadoop 流相关，我们将在 Unix 系统上设置一个 Hadoop 实例。Hadoop 实例始终在 Unix 机器上以生产模式运行，而在开发中，将使用 Windows Hadoop 实例。

1.  这些是设置要求的要求：

+   JAVA 1.7.x

+   必须安装 SSH

1.  下载最新的 Apache Hadoop 分发二进制包。

1.  解压并将包提取到一个文件夹中。

1.  设置以下环境变量：

+   `JAVA_HOME`

+   `HADOOP_HOME`

+   `HADOOP_LOG_DIR`

+   `PATH`

我们还需要配置 Hadoop 安装目录的`conf`文件夹中存在的文件：

+   `Core-site.xml`

+   `Hdfs-site.xml`

+   `Mapred-site.xml`

我们需要设置一个默认的 Hadoop 文件系统。

1.  要配置默认的 Hadoop 文件系统，请在`core-site.xml`文件中提供设置信息。

```java
<configuration>
  <property>
  <name>fs.default.name</name>
  <value>hdfs://localhost:9000</value>
  </property>
</configuration>
```

1.  还要配置复制因子。复制因子配置确保文件的副本存储在 Hadoop 文件系统中。在`hdfs-site.xml`文件中设置属性`dfs.replication`及其值。

```java
<configuration>
  <property>
    <name>dfs.replication</name>
    <value>1</value>
  </property>
</configuration>
```

1.  最后，配置作业跟踪器；此配置在`mapred-site.xml`文件中完成。

```java
<configuration>
  <property>
    <name>mapred.job.tracker</name>
    <value>localhost:9001</value>
  </property>
</configuration>
```

1.  要在伪分布式模式下运行 Hadoop，我们只需要格式；在`bin`文件夹中，有`start`和`stop` Hadoop 实例命令。

接下来，我们将演示如何将 Python 与 Apache Hadoop 数据集成。

我们将使用 Maven 创建一个简单的项目。这些是依赖关系：

```java
<!-- Spring Data Apache Hadoop -->
<dependency>
  <groupId>org.springframework.data</groupId>
  <artifactId>spring-data-hadoop</artifactId>
  <version>1.0.0.RC2</version>
</dependency>
<!-- Apache Hadoop Core -->
<dependency>
  <groupId>org.apache.hadoop</groupId>
  <artifactId>hadoop-core</artifactId>
  <version>1.0.3</version>
</dependency>
<!-- Apache Hadoop Streaming -->
<dependency>
  <groupId>org.apache.hadoop</groupId>
  <artifactId>hadoop-streaming</artifactId>
  <version>1.0.3</version>
</dependency>
```

我们需要一个 mapper 和 reducer Python 脚本。Python 中的 mapper 脚本应该实现以下功能：

+   脚本应该从标准输入流中读取，一次读取一行输入，并将其转换为 UTF-8

+   行中的单词必须分割成单词

+   行中的特殊字符需要替换为空字符，然后得到一个键值对作为制表符；它们被限定到标准输出

这是 Python 中的 mapper 脚本：

```java
#!/usr/bin/python
# -*- coding: utf-8 -*-
import sys
import unicodedata

# Removes punctuation characters from the string
def strip_punctuation(word):
 return ''.join(x for x in word if unicodedata.category(x) != 'Po')

#Process input one line at the time
for line in sys.stdin:
 #Converts the line to Unicode
 line = unicode(line, "utf-8")
 #Splits the line to individual words
 words = line.split()
 #Processes each word one by one
 for word in words:
 #Removes punctuation characters
 word = strip_punctuation(word)
 #Prints the output
 print ("%s\t%s" % (word, 1)).encode("utf-8")

```

Python 中的 Reducer 脚本应该实现以下功能：

1.  脚本应该读取从`mapper`类生成的键值对输出。然后，计算关键字的出现次数。

```java
#!/usr/bin/python
# -*- coding: utf-8 -*-s
import sys
wordCount = 0
#Process input one line at the time
for line in sys.stdin:
 #Converts the line to Unicode
 line = unicode(line, "utf-8")
 #Gets key and value from the current line
 (key, value) = line.split("\t")
 if key == "Amily":
 #Increase word count by one
 wordCount = int(wordCount + 1);
#Prints the output
print ("Watson\t%s" % wordCount).encode("utf-8")

```

1.  一旦 Python 脚本准备就绪，我们需要在属性文件中提供 mapper 和 reducer 类名和配置。这是`.properties`文件：

```java
#Configures the default file system of Apache Hadoop
fs.default.name=hdfs://localhost:9000

#The path to the directory that contains our input files
input.path=/input/

#The path to the directory in which the output is written
output.path=/output/

#Configure the path of the mapper script
mapper.script.path=pythonmapper.py

#Configure the path of the reducer script
reducer.script.path=pythonreducer.py

```

1.  我们还需要在`context.xml`文件中配置`property-placeholder`和 Apache Hadoop。这是配置：

```java
<context:property-placeholder location="classpath:application.properties" />
<hdp:configuration>
  fs.default.name=${fs.default.name}
</hdp:configuration>
```

1.  最后，我们需要配置 Hadoop 作业并将作业分配给作业运行器，该运行器将初始化作业。

```java
<hdp:configuration>
  fs.default.name=${fs.default.name}
</hdp:configuration>
<hdp:streaming id="streamingJob"
  input-path="${input.path}"
  output-path="${output.path}"
  mapper="${mapper.script.path}"
  reducer="${reducer.script.path}"/>
<hdp:job-runner id="streamingJobRunner" job-ref="streamingJob" run-at-startup="true"/>
```

1.  现在，我们需要使用应用程序上下文来调用配置，以便应用程序上下文加载 Spring 框架中的所有配置。

```java
import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;

public class Main {
  public static void main(String[] arguments) {
    ApplicationContext ctx = new ClassPathXmlApplicationContext("applicationContext.xml");
  }
}
```

1.  在命令提示符中运行以下命令以提供输入文件。让文件放在名为`input`的文件夹中：

```java
hadoop dfs -put MILLSANDBOON.txt /input/ MILLSANDBOON.txt

```

1.  输出可以在输出目录中使用以下命令读取。

```java
hadoop dfs -rmr /output
hadoop dfs -cat /output/part-00000

```

您应该看到一个输出，显示提供的文本中单词“Amily”的出现次数。

# 摘要

到目前为止，我们已经看到了 Spring 如何与 Apache Hadoop 集成，并提供了搜索和计数数据的 Map 和 Reduce 过程。我们还讨论了 Python 与 Apache Hadoop 的集成。我们已经演示了如何在 Spring 框架中配置 Hadoop 作业，并且还看到了 HDFS 配置。

Hadoop 是一个庞大的概念。有关更多信息，请参阅[`docs.spring.io/spring-hadoop/docs/current/reference/html/`](http://docs.spring.io/spring-hadoop/docs/current/reference/html/)和[`github.com/spring-projects/spring-hadoop-samples`](https://github.com/spring-projects/spring-hadoop-samples)。

我们已经演示了如何在 Unix 机器上安装 Hadoop 实例。在下一章中，我们将看到如何在 OSGI 中使用 Spring 动态模块。


# 第八章：Spring 与 OSGI

**OSGI**是**Open Service Gateway Intiative**的缩写。这是一个规范，包括用于动态部署模块的模块化系统和服务平台。根据规范，应用程序可以分解为模块并独立部署。当我们考虑开发 OSGI 应用程序时，这意味着我们需要使用可用的 OSGI API 来开发应用程序。第二步是将其部署到 OSGI 容器中。因此，在 OSGI 中开发应用程序时，我们可以将应用程序分解为模块并独立部署它们，然后卸载；我们还可以并行运行应用程序的各个版本。在本章中，我们将看到 Spring 如何支持 OSGI 捆绑开发及其应用程序的部署。我们将首先从 OSGI 开始，然后逐渐转向 Spring 的支持。

# OSGI 容器

OSGI 容器必须实现一组服务，并且 OSGI 容器与应用程序之间建立了一项合同。以下提到的所有 OSGI 容器都是开源的：

+   **KnoplerFish**：Knopler 框架可以很容易地安装，并且更容易地将模块捆绑和部署到容器中。捆绑应用程序需要一个`.manifest`文件和构建`.xml`文件。必须拥有该框架。 JAR 文件应该在 Java 构建路径中可用。需要在 KnoplerFish 容器中部署的捆绑包将具有一个实现`BundleActivator`接口的类。该接口带有需要实现的`start()`和`stop()`方法。通常还会创建一个线程类，并且在`BundleActivator`接口实现类的 start 方法中启动该线程，并在 stop 方法中停止。您还可以通过创建一个接口和实现类来创建一个 OSGI 服务。该服务可以在`BundleActivator`类的`start()`方法中注册。这是实现`BundleActivator`接口的类。有`ServiceListeners`和`ServiceTrackers`来监视容器中的 OSGI 服务。

+   **Equinox**：这是核心 OSGI 框架的实现。它提供各种可选的 OSGI 服务。Eclipse 提供了一个 OSGI 插件来开发 OSGI 捆绑应用程序。Eclipse 提供了一个 JAR 文件，可以使用 Eclipse 的安装启动、停止命令轻松安装。

+   **Apache Felix**：Apache Felix 是 Apache 项目的另一个 OSGI 容器。Felix 有各种子项目可以插入。它还支持与 Knoplerfish 下的应用程序开发类似的方式。它还有一个 Maven 捆绑插件。

## OSGI 使用

让我们列出 OSGI 框架的关键用途：

+   该框架提供了应用程序的模块化

+   该框架实现了基于捆绑包的架构

+   可以并行运行同一项目的多个版本

+   我们还可以将 OSGI 应用程序和 OSGI 捆绑包集成到 Web 容器中

+   使其与 Web 应用程序的前端配合工作也存在一些挑战

+   有很多框架，至少有四个框架，可用于在 OSGI 规范之上开发 POJO 应用程序

+   OSGI 捆绑包的大小相对较小

# Spring 与 OSGI 的集成

Spring 为 OSGI 开发提供了完整的支持。OSGI 模块支持被称为 Spring OSGI，目前已更新为一组新的库和版本，称为 Spring Dynamic Modules。Spring 动态模块允许您在 OSGI 框架之上编写 Spring 应用程序。其挑战之一是使简单的 POJO 能够与 OSGI 框架无缝配合，并将 Spring Beans 集成为 OSGI 服务。Spring Beans 可以导出为 OSGI 服务

```java
<bean name="authorService" 
 class="com.packt.osgi.authorservice.impl.AuthorServiceImpl"/> 
<osgi:service id="auhtorServiceOsgi" 
 ref="authorService" 
 interface="com.packt.osgi.authorservice.AuthorService"/>
```

Spring 动态编程模型提供了 API 编程，Spring Beans 在捆绑中可见。Spring 动态模型为我们提供了跨捆绑的依赖注入，并且通过 Spring 动态服务提供了对 OSGI 的所有支持，处理变得更加容易。

每个捆绑理想上都应该有一个单独的应用上下文。应用上下文随着捆绑的启动和停止而创建和销毁。这些上下文文件位于 META-INF 下。

典型的捆绑结构如下图所示：

![Spring integration with OSGI](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr-app-dev/img/7320OS_08_01.jpg)

下图展示了 OSGI 模块如何成为 Web 应用程序的一部分，以及每个捆绑如何与 OSGI 框架交互。您还可以看到 Web 容器上有许多 Web 应用程序，它们使用 OSGI 框架作为服务访问应用程序捆绑。

![Spring integration with OSGI](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr-app-dev/img/7320OS_08_02.jpg)

# Spring 动态模块和 OSGI

让我们看看 Spring 动态模块是如何工作的。Spring 带有其 OSGI 集成框架，其中有一个名为`extender`的类。这个类检查所有现有的捆绑，并标记由 Spring 提供支持的捆绑。只有具有 Spring 上下文清单标头或`META-INF`/`spring`文件夹中的 XML 文件的捆绑才会被标记为 Spring 兼容。所有前面的步骤都是在启动时触发的，`extender`包在`org.springframeork.osgi.bundle.extender`中可用。现在，我们必须知道为什么 Spring 动态模块会标记 Spring 支持的捆绑。具有 Spring 配置文件的捆绑会进一步转换为应用上下文对象。`extender`不仅标记 Spring 支持的捆绑以创建应用上下文对象，还会检查捆绑是否导入任何 OSGI 服务。如果发现任何导出外部服务的捆绑，则这些 bean 将移动到 OSGI 共享服务注册表中。`extender`使用监听器和事件注册导出 OSGI 服务的捆绑。OSGI 还与 Equinox、Felix 和 KnoplerFish 进行了测试。

在 Eclipse IDE 中设置 Spring DM 时，需要遵循以下步骤：

1.  下载 Spring DM；寻找最新的 Spring OSGI DM。

1.  将 ZIP 文件提取到本地目录中；将其命名为`c:\OSGI-SPRING`。

1.  在启动 Eclipse 时创建一个新的工作空间。

1.  通过选择**插件开发**选项或 Java 中的**安装插件**选项导入所有必要的 JAR 文件和所有 Spring DM JAR 文件。确保在 Eclipse 环境中拥有以下提到的所有插件。

+   `org.springframeork.osgi.bundle.core`

+   `org.springframeork.osgi.bundle.extender`

+   `org.springframeork.osgi.bundle.io`

+   `org.springframeork.bundle.spring.aop`

+   `org.springframeork.bundle.spring.beans`

+   `org.springframeork.bundle.spring.context`

+   `org.springframeork.bundle.spring.core`

+   `org.springframeork.bundle.spring.jdbc`

+   `org.springframeork.bundle.spring.tx`

+   `org.springframeork.osgi.aopalliance.osgi`

## 简单的 OSGI 应用程序

在本节中，让我们首先开发一个简单的 OSGI 应用程序。我们将创建两个捆绑——一个提供打印字符串的服务，另一个捆绑会以相等的时间间隔消费该服务。

1.  以下是第一个捆绑：

```java
package com.packt.osgi.provider.able;

public interface MySimpleOSGIService {
  void mysimplemethod();
}
package com.packt.osgi.provider.impl;

import com.bw.osgi.provider.able.MySimpleOSGIService;

public class MySimpleOSGIServiceImpl implements MySimpleOSGIService {
  @Override
  void mysimplemethod(){
    System.out.println("this my simple method which is the implementation class");
  }
}
```

1.  使用激活器导出服务：

```java
package com.packt.osgi.provider;
import org.osgi.framework.BundleActivator;
import org.osgi.framework.BundleContext;
import org.osgi.framework.ServiceRegistration;
import com.bw.osgi.provider.able.MySimpleOSGIService;
import com.bw.osgi.provider.impl.MySimpleOSGIServiceImpl;

public class MyProviderActivator implements BundleActivator {
  private ServiceRegistration registration;

  @Override
  public void start(BundleContext bundleContext) throws Exception {
    registration = bundleContext.registerService(
      MySimpleOSGIService.class.getName(),
      new MySimpleOSGIServiceImpl(),
      null);
  }

  @Override
  public void stop(BundleContext bundleContext) throws Exception {
    registration.unregister();
  }
}
```

1.  现在，我们已经准备好第一个捆绑，我们将使用 Maven 来构建它。我们还需要 Maven 捆绑插件来构建 XML 文件。

```java
?xml version="1.0" encoding="UTF-8"?>

<project   xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
  <modelVersion>4.0.0</modelVersion>

  <groupId>OSGiDmMySimpleProvider</groupId>
  <artifactId>OSGiDmMySimpleProvider</artifactId>
  <version>1.0</version>

  <dependencies>
    <dependency>
    <groupId>org.apache.felix</groupId>
    <artifactId>org.osgi.core</artifactId>
    <version>1.4.0</version>
    </dependency>
  </dependencies>

  <build>
    <plugins>
      <plugin>
      <groupId>org.apache.maven.plugins</groupId>
      <artifactId>maven-compiler-plugin</artifactId>
      <version>2.0.2</version>
      <configuration>
        <source>1.6</source>
        <target>1.6</target>
      </configuration>
      </plugin>

      <plugin>
        <groupId>org.apache.felix</groupId>
        <artifactId>maven-bundle-plugin</artifactId>
        <extensions>true</extensions>
        <configuration>
          <instructions>
          <Bundle-SymbolicName>OSGiDmMySimpleProvider</Bundle-SymbolicName>
          <Export-Package>com.packt.osgi.provider.able</Export-Package>
          <Bundle-Activator>com.packt.osgi.provider.MyProviderActivator</Bundle-Activator>
          <Bundle-Vendor>PACKT</Bundle-Vendor>
          </instructions>
          </configuration>
        </plugin>
      </plugins>
  </build> 
</project>
```

1.  要构建它，只需简单的`mvn install`命令即可。

1.  接下来，让我们尝试消费服务：

```java
package com.packt.osgi.consumer;
import javax.swing.Timer;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import com.packt.osgi.provider.able.MySimpleOSGIService;
public class MySimpleOSGIConsumer implements ActionListener {
  private final MySimpleOSGIService service;
  private final Timer timer;
  public MySimpleOSGIConsumer(MySimpleOSGIService service) {
    super();
    this.service = service;
    timer = new Timer(1000, this);
  }

  public void startTimer(){
    timer.start();
  }

  public void stopTimer() {
    timer.stop();
  }

  @Override
  public void actionPerformed(ActionEvent e) {
    service.mysimplemethod();
  }
}
```

1.  现在，我们必须再次为消费者创建一个激活器：

```java
package com.packt.osgi.consumer;

import org.osgi.framework.BundleActivator;
import org.osgi.framework.BundleContext;
import org.osgi.framework.ServiceReference;
import com.packt.osgi.provider.able.MySimpleOSGIService;

public class MySimpleOSGIActivator implements BundleActivator {
  private MySimpleOSGIConsumer consumer;

  @Override
  public void start(BundleContext bundleContext) throws Exception {
    ServiceReference reference = bundleContext.getServiceReference(MySimpleOSGIService.class.getName());

    consumer = new MySimpleOSGIConsumer((MySimpleOSGIService) bundleContext.getService(reference));
    consumer.startTimer();
  }

  @Override
  public void stop(BundleContext bundleContext) throws Exception {
    consumer.stopTimer();
  }
}
```

# 将 Spring 动态模块与 OSGI 集成

在本节中，让我们演示如何将 Spring 动态模块集成到 OSGI 应用程序中。Spring 动态模块（Spring DM）使得基于 OSGI 的应用程序的开发变得更加容易。我们可以像任何其他 Spring bean 一样轻松地注入服务。

我们将看一下集成 Spring 动态模块所需的以下依赖项：

+   OSGI 服务

+   `BundleActivator`类

+   `Context.xml`文件配置以注入服务

以下是需要在应用程序类路径中提供的依赖项列表：

+   `com.springsource.net.sf.cglib-2.1.3.jar`

+   `com.springsource.org.aopalliance-1.0.0.jar`

+   `log4j.osgi-1.2.15-SNAPSHOT.jar`

+   `com.springsource.slf4j.api-1.5.0.jar`

+   `com.springsource.slf4j.log4j-1.5.0.jar`

+   `com.springsource.slf4j.org.apache.commons.logging-1.5.0.jar`

+   `org.springframework.aop-3.x.jar`

+   `org.springframework.beans-3.x.jar`

+   `org.springframework.context-3.x.jar`

+   `org.springframework.core-3.x.jar`

+   `spring-osgi-core-1.2.1.jar`

+   `spring-osgi-extender-1.2.1.jar`

+   `spring-osgi-io-1.2.1.jar`

所以，让我们创建一个简单的`HelloWorldService`接口类：

```java
package com.packt.osgi.provider.able;
public interface HelloWorldService {
  void hello();
}
```

接下来，我们将实现`service`类。这是一个简单的类

```java
package com.packt.osgi.provider.impl;
import com.packt.osgi.provider.able.HelloWorldService;
public class HelloWorldServiceImpl implements HelloWorldService {
  @Override
  public void hello(){
    System.out.println("Hello World !");
  }
}
```

我们将编写一个激活器类，需要激活服务`BundleActivator`。我们需要调用的`ProviderActivator`类是`HelloWorldService`。实际上，我们正在注册服务。但是，使用 Spring DM 集成使我们的配置变得简单。我们不需要这个集成类。

```java
package com.packt.osgi.provider;
import org.osgi.framework.BundleActivator;
import org.osgi.framework.BundleContext;
import org.osgi.framework.ServiceRegistration;
import com. packt.osgi.provider.able.HelloWorldService;
import com. packt.osgi.provider.impl.HelloWorldServiceImpl;

public class ProviderActivator implements BundleActivator {
  private ServiceRegistration registration;

  @Override
  public void start(BundleContext bundleContext) throws Exception {
    registration = bundleContext.registerService(
                   HelloWorldService.class.getName(),
                   new HelloWorldServiceImpl(),null);
  }

  @Override
  public void stop(BundleContext bundleContext) throws Exception {
    registration.unregister();
  }
}
```

我们只需要在`META-INF`/`spring`文件夹中创建一个`provider-context.xml`文件。这是一个简单的 XML 文件上下文，但我们使用一个新的命名空间来注册服务 - [`www.springframework.org/schema/osgi`](http://www.springframework.org/schema/osgi)。所以，让我们开始：

```java
<?xml version="1.0" encoding="UTF-8"?>
<beans 

  xsi:schemaLocation="http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans-3.0.xsd http://www.springframework.org/schema/osgi http://www.springframework.org/schema/osgi/spring-osgi.xsd">
  <bean id="helloWorldService" class="com.packt.osgi.provider.impl.HelloWorldServiceImpl"/>
  <osgi:service ref="helloWorldService" interface="com.packt.osgi.provider.able.HelloWorldService"/>
</beans>
```

唯一与 OSGI 相关的是`osgi:service`声明。这一行表示我们需要将`HelloWorldService`注册为 OSGI 服务，使用`HelloWorldService`接口作为服务的名称。

如果您将上下文文件放在`META-INF`/`spring`文件夹中，它将被 Spring Extender 自动检测，并创建一个应用程序上下文。

1.  现在我们可以转到消费者 bundle。在第一阶段，我们创建了那个消费者：

```java
package com.packt.osgi.consumer;
import javax.swing.Timer;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import com.bw.osgi.provider.able.HelloWorldService;
public class HelloWorldConsumer implements ActionListener {
  private final HelloWorldService service;
  private final Timer timer;
  public HelloWorldConsumer(HelloWorldService service) {
    super();
    this.service = service;
    timer = new Timer(1000, this);
  }
  public void startTimer(){
    timer.start();
  }
  public void stopTimer() {
    timer.stop();
  }
  @Override
  public void actionPerformed(ActionEvent e) {
    service.hello();
  }
}
```

1.  接下来，让我们编写`BundleActivator`类：

```java
package com.packt.osgi.consumer;
import org.osgi.framework.BundleActivator;
import org.osgi.framework.BundleContext;
import org.osgi.framework.ServiceReference;
import com. packt.osgi.provider.able.HelloWorldService;
public class HelloWorldActivator implements BundleActivator {
  private HelloWorldConsumer consumer;
  @Override
  public void start(BundleContext bundleContext) throws Exception {
    ServiceReference reference = bundleContext.getServiceReference(HelloWorldService.class.getName());
    consumer = new HelloWorldConsumer((HelloWorldService) bundleContext.getService(reference));
    consumer.startTimer();
  }
  @Override
  public void stop(BundleContext bundleContext) throws Exception {
    consumer.stopTimer();
  }
}
```

注入不再是必要的。我们可以在这里保留计时器的启动，但是，再次，我们可以使用框架的功能来启动和停止计时器。

1.  所以，让我们删除激活器并创建一个应用程序上下文来创建消费者并自动启动它，并将其放在`META-INF`/`spring`文件夹中：

```java
<?xml version="1.0" encoding="UTF-8"?>
<beans 

  xsi:schemaLocation="http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans-3.0.xsd http://www.springframework.org/schema/osgi 
  http://www.springframework.org/schema/osgi/spring-osgi.xsd">

  <bean id="consumer" class="com.packt.osgi.consumer.HelloWorldConsumer" init-method="startTimer" destroy-method="stopTimer" lazy-init="false" >
    <constructor-arg ref="eventService"/>
  </bean>

  <osgi:reference id="eventService" interface="com.packt.osgi.provider.able.HelloWorldService"/>
</beans>
```

我们使用`init`方法和`destroy`方法属性来启动和停止与框架的时间，并使用`constructor-arg`来将引用注入到服务中。使用`osgi:reference`字段和使用接口作为服务的键来获取对服务的引用。

这就是我们需要做的所有事情。比第一个版本简单多了，不是吗？除了简化之外，您还可以看到源代码既不依赖于 OSGI 也不依赖于 Spring Framework；这就是纯 Java，这是一个很大的优势。

Maven POM 文件与第一阶段相同，只是我们可以削减对 OSGI 的依赖。

提供者：

```java
<?xml version="1.0" encoding="UTF-8"?>

<project 

  xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
  <modelVersion>4.0.0</modelVersion>
  <groupId>OSGiDmHelloWorldProvider</groupId>
  <artifactId>OSGiDmHelloWorldProvider</artifactId>
  <version>1.0</version>
  <packaging>bundle</packaging>

  <build>
    <plugins>
      <plugin>
        <groupId>org.apache.maven.plugins</groupId>
        <artifactId>maven-compiler-plugin</artifactId>
        <version>2.0.2</version>
        <configuration>
          <source>1.6</source>
          <target>1.6</target>
         </configuration>
      </plugin>

      <plugin>
        <groupId>org.apache.felix</groupId>
        <artifactId>maven-bundle-plugin</artifactId>
        <extensions>true</extensions>
        <configuration>
          <instructions>
            <Bundle-SymbolicName>OSGiDmHelloWorldProvider</Bundle-SymbolicName>
            <Export-Package>com.bw.osgi.provider.able</Export-Package>
            <Bundle-Vendor>Baptiste Wicht</Bundle-Vendor>
          </instructions>
        </configuration>
      </plugin>
    </plugins>
  </build> 
</project>
```

消费者：

```java
<?xml version="1.0" encoding="UTF-8"?>

<project 

  xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
  <modelVersion>4.0.0</modelVersion>
  <groupId>OSGiDmHelloWorldConsumer</groupId>
  <artifactId>OSGiDmHelloWorldConsumer</artifactId>
  <version>1.0</version>
  <packaging>bundle</packaging>

  <dependencies>
    <dependency>
      <groupId>OSGiDmHelloWorldProvider</groupId>
      <artifactId>OSGiDmHelloWorldProvider</artifactId>
      <version>1.0</version>
    </dependency>
  </dependencies>

  <build>
    <plugins>
      <plugin>
        <groupId>org.apache.maven.plugins</groupId>
        <artifactId>maven-compiler-plugin</artifactId>
        <version>2.0.2</version>
        <configuration>
          <source>1.6</source>
          <target>1.6</target>
        </configuration>
      </plugin>

      <plugin>
        <groupId>org.apache.felix</groupId>
        <artifactId>maven-bundle-plugin</artifactId>
        <extensions>true</extensions>
        <configuration>
          <instructions>
            <Bundle-SymbolicName>OSGiDmHelloWorldConsumer</Bundle-SymbolicName>
            <Bundle-Vendor>Baptiste Wicht</Bundle-Vendor>
          </instructions>
        </configuration>
      </plugin>
    </plugins>
  </build>
</project>
```

我们可以使用 Maven install 构建这两个 bundle。所以，让我们在 Felix 中测试一下我们的东西：

```java
Welcome to Apache Felix Gogo
g! install file:../com.springsource.slf4j.org.apache.commons.logging-1.5.0.jar
Bundle ID: 5
g! install file:../com.springsource.slf4j.log4j-1.5.0.jar
Bundle ID: 6
g! install file:../com.springsource.slf4j.api-1.5.0.jar
Bundle ID: 7
g! install file:../log4j.osgi-1.2.15-SNAPSHOT.jar
Bundle ID: 8
g! install file:../com.springsource.net.sf.cglib-2.1.3.jar
Bundle ID: 9
g! install file:../com.springsource.org.aopalliance-1.0.0.jar
Bundle ID: 10
g! install file:../org.springframework.core-2.5.6.SEC01.jar
Bundle ID: 11
g! install file:../org.springframework.context-2.5.6.SEC01.jar
Bundle ID: 12
g! install file:../org.springframework.beans-2.5.6.SEC01.jar
Bundle ID: 13
g! install file:../org.springframework.aop-2.5.6.SEC01.jar
Bundle ID: 14
g! install file:../spring-osgi-extender-1.2.1.jar
Bundle ID: 15
g! install file:../spring-osgi-core-1.2.1.jar
Bundle ID: 16
g! install file:../spring-osgi-io-1.2.1.jar
Bundle ID: 17
g! start 5 7 8 9 10 11 12 13 14 15 16 17
log4j:WARN No appenders could be found for logger (org.springframework.osgi.extender.internal.activator.ContextLoaderListener).
log4j:WARN Please initialize the log4j system properly.
g! install file:../OSGiDmHelloWorldProvider-1.0.jar
Bundle ID: 18
g! install file:../OSGiDmHelloWorldConsumer-1.0.jar
Bundle ID: 19
g! start 18
g! start 19
g! Hello World !
Hello World !
Hello World !
Hello World !
Hello World !
Hello World !
Hello World !
Hello World !
stop 19
g!
```

总之，Spring DM 确实使与 OSGI 的开发变得更加容易。使用 Spring DM，您还可以启动 bundle。它还允许您创建 Web bundle 并轻松使用 OSGI compendium 的服务。

# 摘要

在本章中，我们开发了一个简单的 OSGI 应用程序。我们还演示了 Spring DM 如何支持 OSGI 开发，减少文件的创建，并通过配置使事情变得更容易。


# 第九章：使用 Spring Boot 引导应用程序

在本章中，我们将看到另一个 Spring 包——Spring Boot，它允许用户快速开始使用 Spring 框架。使用**Spring Boot 抽象层**的应用程序称为**Spring Boot 应用程序**。Spring 推出了一个 Spring 初始化器 Web 应用程序，其中有一个 Web 界面，我们可以在其中选择需要启动的应用程序类型。

如果您曾经在不同的应用服务器上运行过，新开发人员通常必须配置许多设置才能启动和运行。Spring Boot 方法允许开发人员立即启动和运行，而无需配置应用服务器，从而可以专注于开发代码。

Spring 还推出了一个命令行界面，帮助我们快速开始 Spring 开发。在本章中，让我们深入了解 Spring Boot 并看看它提供了什么。

# 设置 Spring Boot

Spring Boot 应用程序可以通过以下方式设置：

+   使用[`start.spring.io/`](http://start.spring.io/)

+   使用 Maven 从存储库下载依赖项

+   使用 Gradle

+   从 Spring 指南存储库下载源代码

+   下载 Spring STS 并使用启动器项目

# Spring Gradle MVC 应用程序

**Gradle**类似于 Maven；它有助于构建应用程序。我们需要在`build.gradle`文件中提供所有依赖信息。Spring Boot 还有一个 Gradle 插件。Gradle 插件有助于将所有依赖的 JAR 文件放置在类路径上，并最终构建成一个可运行的单个 JAR 文件。可运行的 JAR 文件将具有一个`application.java`文件；这个类将有一个`public static void main()`方法。这个类将被标记为可运行的类。

这里显示了一个示例 Gradle 文件：

```java
buildscript {
  repositories {
    maven { url "http://repo.spring.io/libs-milestone" }
    mavenLocal()
  }
  dependencies {
    classpath("org.springframework.boot:spring-boot-gradle-plugin:1.1.3.RELEASE")
  }
}

  apply plugin: 'java'
  apply plugin: 'war'
  apply plugin: 'spring-boot'
  jar {
    baseName = PacktSpringBootMVCDemo '
    version =  '1.0'
  }
  repositories {
    mavenCentral()
    maven { url "http://repo.spring.io/libs-milestone" }
  }

  configurations {
    providedRuntime
  }
  dependencies {
    compile ("org.springframework.boot:spring-boot-starter-web")
    providedRuntime("org.apache.tomcat.embed:tomcat-embed-jasper")

  }
  task wrapper(type: Wrapper) {
    gradleVersion = '2.0'
  }
```

如果您正在使用 Eclipse 作为 IDE，STS 已经推出了适用于 Eclipse 的 Gradle 插件（[`gradle.org/docs/current/userguide/eclipse_plugin.html`](http://gradle.org/docs/current/userguide/eclipse_plugin.html)），可以从[`www.gradle.org/tooling`](https://www.gradle.org/tooling)下载并安装。Gradle 也提供了类似的设置来清理和构建应用程序。

下一步是在属性文件中定义应用程序上下文根。Gradle 项目结构类似于 Maven 项目结构。将`application.properties`文件放在`resources`文件夹中。我们需要提供服务器上下文路径和服务器上下文端口。以下是示例属性文件：

```java
server.contextPath=/PacktSpringBootMVCDemo
server.port=8080
```

1.  让我们创建一个简单的包：`com.packt.controller`

1.  在包中创建一个简单的 Spring 控制器类，并使用@ Controller 注解。

1.  让我们创建一个带有`@Request`映射注解的方法。`@RequestMapping`注解将请求映射到 JSP 页面。在这个方法中，我们将请求映射到方法。这些方法返回一个字符串变量或模型视图对象。

```java
package com.packt.controller;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.servlet.ModelAndView;
@Controller
public class PacktController{
  @RequestMapping(value = "/saygoodmorning  method = RequestMethod.GET)
  public ModelAndView getGoodmorning() {
    return new ModelAndView("greet").addObject("greet", "goodmorning");
  }
  @RequestMapping(value = "/saygoodafternoon  method = RequestMethod.GET)
  public ModelAndView getGoodmorning() {
    return new ModelAndView("greet").addObject("greet ", "goodafternoon");
  }
  @RequestMapping(value = "/saygoodnight  method = RequestMethod.GET)
  public ModelAndView getGoodmorning() {
    return new ModelAndView("greet").addObject("greet ", "goodnight");
  }
}
```

1.  创建一个 Spring MVC 配置文件，使用`@Configuration`和`@WebMVC` `annotation`如下。我们还为应用程序文件配置了内部视图解析器。

```java
package com.packt.config;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.DefaultServletHandlerConfigurer;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;
import org.springframework.web.servlet.view.InternalResourceViewResolver;

@Configuration
@EnableWebMvc
public class ApplicationConfigurerAdapter extends WebMvcConfigurerAdapter{
  @Override
  public void configureDefaultServletHandling(DefaultServletHandlerConfigurer configurer) {
    configurer.enable();
  }

  @Bean
  public InternalResourceViewResolver viewResolver() {
    InternalResourceViewResolver resolver = new InternalResourceViewResolver();
    resolver.setPrefix("WEB-INF/jsp/");
    resolver.setSuffix(".jsp");
    return resolver;
  }

}
```

让我们创建一个名为`greet.jsp`的简单 JSP 页面：

```java
<html>
  <head><title>Hello world Example</title></head>
  <body>
    <h1>Hello ${name}, How are you?</h1>
  </body>
</html>
```

接下来创建一个简单的应用程序类，使用`@EnableAutoConfiguration`和`@ComponentScan`注解。`@ComponenetScan`注解表示 Spring 框架核心应搜索包下的所有类。`@EnableAutoConfiguration`注解用于代替在`web.xml`文件中配置 dispatcher servlet。

以下是示例文件：

```java
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableAutoConfiguration
@ComponentScan
public class Application {
  public static void main(String[] args) {
    SpringApplication.run(Application.class, args);
  }

}
```

访问以下 URL：

+   `http://localhost:8080/PacktSpringBootMVCDemo/saygoodmorning`

+   `http://localhost:8080/PacktSpringBootMVCDemo/saygoodafternoon`

+   `http://localhost:8080/PacktSpringBootMVCDemo/saygoodnight`

## 使用 Spring Boot 进行热交换

热交换或热部署意味着您可以对类文件或应用程序中的任何文件进行更改，并立即在运行中的应用程序中看到更改。我们可能需要重新加载 Web 浏览器上的应用程序，或者只需刷新页面。Spring Loaded 是一个支持热部署的依赖 JAR 文件。让我们看看 Spring Boot 应用程序中的热交换。

让我们使用 Thymeleaf 模板引擎创建一个简单的 Spring MVC 应用程序：

1.  首先，我们需要从 GitHub 存储库下载 Spring Loaded JAR。检查以下 URL 以获取最新版本：

[`github.com/spring-projects/spring-loaded`](https://github.com/spring-projects/spring-loaded)。

1.  确保您在`pom.xml`文件中具有所有提到的依赖项，或者将它们明确添加到您的项目中：

```java
<dependency>
    <groupId>org.apache.tomcat.embed</groupId>
    <artifactId>tomcat-embed-jasper</artifactId>
    <scope>provided</scope>
</dependency>
<dependency>
    <groupId>javax.servlet</groupId>
    <artifactId>jstl</artifactId>
</dependency>
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-actuator</artifactId>
</dependency>
```

1.  下一步是将下载的 Spring loaded JAR 添加到 Eclipse 或 Eclipse STS 环境中。按照给定的步骤将 Spring loaded JAR 添加为运行时配置：

1.  在 Eclipse 中创建一个`PacktSpringBootThymeLeafExample`项目。

1.  右键单击您的项目。

1.  搜索**Run As**。

1.  点击**Run Configuration**。

1.  点击 Java 应用程序。

1.  点击项目名称。

1.  在**VM Argument**部分中选择**Arguments**；添加以下命令：

```java
- javaagent:/<provide the path to the jar>/springloaded-1.2.0.RELEASE.jar -noverify
```

1.  点击**Apply**和**Run**。

我们还需要配置`application.properties`文件，以便对**Thymeleaf**页面进行任何修改时不需要重新启动服务器：

```java
spring.thymeleaf.cache: false.
```

我们可以使用 Spring STS starter 项目并创建一个 Spring Boot 类。Spring Eclipse STS 将为我们提供以下两个类：

+   `Application.java`

+   `ApplicationTest.java`

`Application.java`是 Spring Boot 的主类，因为它在其中有 public static void main 方法。在这个方法中，使用`SpringApplication`类对`ApplicationContext`进行初始化。`SpringApplication`类具有以下一些注解：

+   `@ConditionalOnClass`

+   `@ConditionalOnMissingBean`

这些用于检查类路径上可用的 bean 列表。如果您想要查看框架放置在类路径下的 bean，可以对生成的`Application.java`文件进行轻微修改，如下所示：

```java
@ComponentScan
@EnableAutoConfiguration
public class Application {
  public static void main(String[] args) {
    ApplicationContext ctx = SpringApplication.run(Application.class, args);
    System.out.println("---------------------------LIST BEANS PROVIDED BY SPRING BOOT_---------------------");
    String[] beanNames = ctx.getBeanDefinitionNames();
    Arrays.sort(beanNames);
    for (String beanName : beanNames) {
      System.out.println(beanName);
    }

  }
}
```

输出：

```java
---------------------------LIST BEANS PROVIDED BY SPRING BOOT_---------------------
JSPController
application
applicationContextIdFilter
auditEventRepository
auditListener
autoConfigurationAuditEndpoint
basicErrorController
beanNameHandlerMapping
beanNameViewResolver
....
mappingJackson2HttpMessageConverter
messageConverters
messageSource
tomcatEmbeddedServletContainerFactory
traceEndpoint
traceRepository
viewControllerHandlerMapping
viewResolver
webRequestLoggingFilter
```

`SpringApplication`类位于`org.springframework.boot.SpringApplication`包中。

这里显示了`SpringApplication`类的一个简单示例，其中显示了`SpringApplication`类的静态运行方法：

```java
@Configuration
@EnableAutoConfiguration
public class MyPacktApplication {

  // ... Bean definitions

  public static void main(String[] args) throws Exception {
    SpringApplication.run(MyPacktApplication.class, args);
  }
```

在这里看另一个例子，首先初始化一个`SpringApplication`类，然后调用`.run`方法：

```java
@Configuration
@EnableAutoConfiguration
public class MyPacktApplication {
  // ... Bean definitions
  public static void main(String[] args) throws Exception {
    SpringApplication app = new SpringApplication(MyPacktApplication.class);
    // ... customize app settings here
    app.run(args)
  }
}
```

以下是`SpringApplication`类可用的构造函数：

+   `SpringApplication(Object... sources)`

+   `SpringApplication(ResourceLoader resourceLoader, Object... sources)`

1.  让我们创建一个带有 Spring 最新版本 4.x 中可用的`@RestController`注解的简单 Controller 类。

```java
@RestController
public class MyPacktController {

  @RequestMapping("/")
  public String index() {
    return "Greetings ";
  }

  @RequestMapping("/greetjsontest") 
  public @ResponseBody Map<String, String> callSomething () {

    Map<String, String> map = new HashMap<String, String>();
    map.put("afternoon", " Good afternoon");
    map.put("morning", " Good Morning");
    map.put("night", " Good Night");
    return map;
  }
}
```

1.  接下来，我们将配置 Spring Boot 来处理 JSP 页面；默认情况下，Spring Boot 不配置 JSP，因此我们将创建一个 JSP 控制器，如下面的代码片段所示：

```java
@Controller
public class SpringBootJSPController {
  @RequestMapping("/calljsp")
  public String test(ModelAndView modelAndView) {

    return "myjsp";
  }
}
```

1.  按照以下方式配置属性文件：

```java
spring.view.prefix: /WEB-INF/jsp/
spring.view.suffix: .jsp
```

1.  让我们创建一个 JSP 文件`myjsp:`

```java
<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
  <head>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
    <title>Insert title here</title>
  </head>
  <body>
    <h1>Hello world</h1>
  </body>
</html>
```

以下是`EmbededServletContainerCustomizer`的实现类，它实际上将 Web 服务器容器嵌入应用程序中。它调用服务器并将应用程序部署到其中。

```java
@ComponentScan
@EnableAutoConfiguration

public class Application implements EmbeddedServletContainerCustomizer {
  @Value("${someproperty:webapp/whereever }")
  private String documentRoot;
  @Override
  public void customize(ConfigurableEmbeddedServletContainerFactory factory) {
    factory.setDocumentRoot(new File(documentRoot));
  }
}
```

## 将 Spring Boot 与 Spring 安全集成

在本节中，我们将看到如何使用注解将 Spring Boot 与 Spring 安全集成。我们可以很容易地将 Spring 安全与 Spring Boot 集成。

1.  让我们首先在 Spring boot 中嵌入一个 tomcat 服务器来接受请求；以下是我们需要创建一个密钥库文件使其更安全的代码：

```java
@Bean
EmbeddedServletContainerCustomizer containerCustomizer (
  @Value("${https.port}") final int port, 
  @Value("${keystore.file}") Resource keystoreFile,
  @Value("${keystore.alias}") final String alias, 
  @Value("${keystore.password}") final String keystorePass,
  @Value("${keystore.type}") final String keystoreType) throws Exception {
    final String absoluteKeystoreFile = keystoreFile.getFile().getAbsolutePath();
    return new EmbeddedServletContainerCustomizer() {
      public void customize(ConfigurableEmbeddedServletContainer container) {
        TomcatEmbeddedServletContainerFactory tomcat = (TomcatEmbeddedServletContainerFactory) container;
        tomcat.addConnectorCustomizers(new TomcatConnectorCustomizer() {
          public void customize(Connector connector) {
            connector.setPort(port);
            connector.setSecure(true);
            connector.setScheme("https");
            Http11NioProtocol proto = (Http11NioProtocol) connector.getProtocolHandler();
            proto.setSSLEnabled(true);
            proto.setKeystoreFile(absoluteKeystoreFile);
            proto.setKeyAlias(alias);
            proto.setKeystorePass(keystorePass);
            proto.setKeystoreType(keystoreType);
          }
        });
      }
    };
  }
```

1.  让我们还使用`@Configuration`和`@EnableWebMVCSecurity`注解在 java 中创建一个简单的安全配置文件。安全配置文件扩展了`WebSecurityConfigurerAdapter`。

```java
@Configuration
@EnableWebMvcSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

  @Value("${ldap.domain}")
  private String DOMAIN;

  @Value("${ldap.url}")
  private String URL;

  @Value("${http.port}")
  private int httpPort;

  @Value("${https.port}")
  private int httpsPort;

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    /*
    * Set up your spring security config here. For example...
    */
    http.authorizeRequests().anyRequest().authenticated().and().formLogin().loginUrl("/login").permitAll();
      /*
      * Use HTTPs for ALL requests
      */
      http.requiresChannel().anyRequest().requiresSecure();
      http.portMapper().http(httpPort).mapsTo(httpsPort);
    }

    @Override
    protected void configure(AuthenticationManagerBuilder authManagerBuilder) throws Exception {
    authManagerBuilder.authenticationProvider(activeDirectoryLdapAuthenticationProvider()).userDetailsService(userDetailsService());
    }

    @Bean
    public AuthenticationManager authenticationManager() {
      return new ProviderManager(Arrays.asList(activeDirectoryLdapAuthenticationProvider()));
    }
    @Bean
    public AuthenticationProvider activeDirectoryLdapAuthenticationProvider() {
      ActiveDirectoryLdapAuthenticationProvider provider = new ActiveDirectoryLdapAuthenticationProvider(DOMAIN, URL);
        provider.setConvertSubErrorCodesToExceptions(true);
        provider.setUseAuthenticationRequestCredentials(true);
        return provider;
    }
  }
```

# Eclipse Spring Boot 的 Cloud Foundry 支持

在本节中，让我们看看如何使用 Spring boot 在 Cloud Foundry 上开发应用程序。**Cloud Foundry**是一个用作服务云应用程序的平台。它是一个开放的 PaaS。PaaS 使得在云上运行、部署和运行应用程序成为可能。

参考以下链接，其中提供了有关作为服务可用的 Spring 平台的完整信息以及如何配置 Spring 以与 Cloud Foundry 一起工作。您将看到它提供了从 MongoDB 到 RabbitMQ 消息服务器的平台作为服务。

[`docs.cloudfoundry.org/buildpacks/java/spring-service-bindings.html`](http://docs.cloudfoundry.org/buildpacks/java/spring-service-bindings.html)

Eclipse 还推出了一个针对云平台的插件，可以从以下给定位置下载和安装。该插件支持 Spring boot 和 grails 应用程序。您还可以创建一个服务器实例到使用自签名证书的私有云。

[`github.com/cloudfoundry/eclipse-integration-cloudfoundry`](https://github.com/cloudfoundry/eclipse-integration-cloudfoundry)

我们所需要做的就是开发一个简单的启动应用程序，并将其拖放到 Cloud Foundry 服务器中，然后重新启动服务器。

# 使用 Spring Boot 开发 RestfulWebService

在本节中，让我们开发一个简单的 restful 服务，并使用`SpringBoot`引导应用程序。我们还将创建一个简单的 restful 服务，将产品信息存储到数据库中。

产品创建场景应满足以下提到的用例：

+   假设不存在具有相同`Product_id`的产品，它应该将新产品存储在数据库中并立即返回存储的对象。

+   假设存在一个具有相同`Product_id`的产品，它不应该存储，而是返回一个带有相关消息的错误状态。

+   假设以前存储的产品，它应该能够检索它们的列表。

以下是`pom.xml`文件，用于应用程序中使用的依赖项引用。您可以看到我们在这里使用了父 Spring boot 引用，以便我们可以解析所有依赖项引用。我们还在`pom.xml`文件中设置了 Java 版本为 1.7。

```java
<project  
  xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/maven-v4_0_0.xsd">
  <modelVersion>4.0.0</modelVersion>

  <groupId>com.packt.restfulApp</groupId>
  <artifactId>restfulSpringBootApp</artifactId>
  <version>1.0-SNAPSHOT</version>
  <packaging>jar</packaging>

  <parent>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-parent</artifactId>
    <version>1.0.1.RELEASE</version>
  </parent>

  <name>Example Spring Boot REST Service</name>

  <properties>
    <java.version>1.7</java.version>
    <guava.version>16.0.1</guava.version>
    <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
    <project.reporting.outputEncoding>UTF-8</project.reporting.outputEncoding>
  </properties>

</project>
```

让我们看看`pom.xml`文件中使用的依赖项。以下是使用的 Spring boot 依赖项。还要注意，版本信息没有指定，因为它由前面提到的`spring-boot-starter-parent`管理。

```java
<dependencies>
  <!-- Spring Boot -->
  <dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter</artifactId>
  </dependency>

  <dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-test</artifactId>
    <scope>test</scope>
  </dependency>

  <dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-web</artifactId>
  </dependency>

  <dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-data-jpa</artifactId>
  </dependency>

  <!-- Hibernate validator -->

  <dependency>
    <groupId>org.hibernate</groupId>
    <artifactId>hibernate-validator</artifactId>
  </dependency>

  <!-- HSQLDB -->

  <dependency>
    <groupId>org.hsqldb</groupId>
    <artifactId>hsqldb</artifactId>
    <scope>runtime</scope>
  </dependency>

  <!-- Guava -->

  <dependency>
    <groupId>com.google.guava</groupId>
    <artifactId>guava</artifactId>
    <version>${guava.version}</version>
  </dependency>

  <!-- Java EE -->

  <dependency>
    <groupId>javax.inject</groupId>
    <artifactId>javax.inject</artifactId>
    <version>1</version>
  </dependency>
</dependencies>
```

我们还将看到为什么这些依赖项被用于 Spring boot。当涉及到 Spring boot 时，它的功能分布在 starter 模块之间：

+   `spring-boot-starter`：这是 Spring boot 的主要核心模块

+   `spring-boot-starter-test`：这里有一些用于单元测试的工具，包括 JUnit4 和 Mockito

+   `spring-boot-starter-web`：这会拉取 Spring MVC 依赖项，还有将用于 JSON 的 Jackson，最重要的是 Tomcat，它充当嵌入式 Servlet 容器

+   `spring-boot-starter-data-jpa`：用于设置 Spring Data JPA，并与 Hibernate 捆绑在一起

+   `Guava`：它使用`@Inject`注释而不是`@Autowired`

最后，添加一个 Spring boot Maven 插件如下。`spring-boot-maven`插件的功能如下：

+   它为 Maven 提供了一个`spring-boot:run`目标，因此应用程序可以在不打包的情况下轻松运行。

+   它钩入一个打包目标，以生成一个包含所有依赖项的可执行 JAR 文件，类似于`maven-shade`插件，但方式不那么混乱。

```java
<build>
  <plugins>

  <!-- Spring Boot Maven -->

    <plugin>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-maven-plugin</artifactId>
    </plugin>

  </plugins>
</build>
```

到目前为止，我们已经看了依赖项及其功能，现在让我们开始构建应用程序。

**Bean 类或实体类**：

1.  让我们创建一个简单的`Product.java`文件如下：

```java
@Entity
public class Product {
  @Id
  @Column(name = "id", nullable = false, updatable = false)
  @NotNull 
  private Long product_id;
  @Column(name = "password", nullable = false)
  @NotNull
  @Size(max = 64)
  private String product_name;

  public Action(Long product_id, String product_name) {

    this. produc_id = product_id;
    this. produc_name = produc_name;
  }
```

1.  接下来创建一个`Jparepository`子接口；我们不需要为此提供任何实现，因为它由 Spring JPA 数据处理：

```java
public interface ProductRepository extends JpaRepository<Product, String>{

}
```

**服务类**：

1.  让我们创建一个处理保存的服务接口。

```java
public interface ProductService {

  Product save(Product product);

}
```

1.  我们还应该为服务接口创建一个实现类：

```java
@Service
public class ProductServiceImpl implements ProductService {

  private final ProductRepository repository;

  @Inject
  public ProductServiceImpl(final ProductRepository repository) {
    this.repository = repository;
  }

  @Override
  @Transactional
  public Product save(final Product product) {
    Product existing = repository.findOne(Product.getId());
    if (existing != null) {
      throw new ProductAlreadyExistsException(
        String.format("There already exists a Product with id=%s", product.getId()));
    }
    return repository.save(product);
  }
```

1.  在下一步中，我们还将创建一个用于服务`Impl`的测试类，如下所示：

```java
@RunWith(MockitoJUnitRunner.class)
public class ProductControllerTest {

  @Mock
  private ProductService ProductService;

  private ProductController ProductController;

  @Before
  public void setUp() {
    ProductController = new ProductController(ProductService);
  }

  @Test
  public void shouldCreateProduct() throws Exception {
    final Product savedProduct = stubServiceToReturnStoredProduct();
    final Product Product = new Product();
    Product returnedProduct = ProductController.createProduct(Product);
    // verify Product was passed to ProductService
    verify(ProductService, times(1)).save(Product);
    assertEquals("Returned Product should come from the service", savedProduct, returnedProduct);
  }

  private Product stubServiceToReturnStoredProduct() {
    final Product Product = new Product();
    when(ProductService.save(any(Product.class))).thenReturn(Product);
    return Product;
  }
```

1.  让我们使用`@RestController`注解创建一个控制器；还要注意我们使用了`@Inject`注解。

+   `@RestController`：这与`@Controller`注解的区别在于前者在每个方法上也意味着`@ResponseBody`，这意味着写的内容更少，因为从 restful web 服务中我们无论如何都会返回 JSON 对象。

+   `@RequestMapping`：这将`createProduct()`映射到`/Product` URL 上的`POST`请求。该方法将产品对象作为参数。它是从请求的主体中创建的，这要归功于`@RequestBody`注解。然后进行验证，这是由`@Valid`强制执行的。

+   `@Inject`：`ProductService`将被注入到构造函数中，并且产品对象将被传递给其`save()`方法进行存储。存储后，存储的产品对象将被自动转换回 JSON，即使没有`@ResponseBody`注解，这是`@RestController`的默认值。

```java
@RestsController
public class ProductController {
  private final ProductService ProductService;
  @Inject
  public ProductController(final ProductService ProductService) {
    this.ProductService = ProductService;
  }
  @RequestMapping(value = "/Product", method = RequestMethod.POST)
  public Product createProduct(@RequestBody @Valid final Product Product) {
    return ProductService.save(Product);
  }
}
```

1.  让我们创建一个带有`public static void main()`的`Main`类。我们还可以使用这些注解：

+   `@Configuration` - 这告诉 Spring 框架这是一个配置类

+   `@ComponentScan` - 这使得可以扫描包和子包以寻找 Spring 组件

+   `@EnableAutoConfiguration`

该类进一步扩展了`SpringBootServletInitializer`，它将为我们配置调度程序 servlet 并覆盖`configure`方法。

以下是`Main`类：

```java
@Configuration
@EnableAutoConfiguration
@ComponentScan
public class Application extends SpringBootServletInitializer {

  public static void main(final String[] args) {
    SpringApplication.run(Application.class, args);
  }

  @Override
  protected final SpringApplicationBuilder configure(final SpringApplicationBuilder application) {
    return application.sources(Application.class);
  }
}
```

1.  现在，让我们使用 Maven 和 Bootstrap 运行应用程序：

```java
mvn package
java -jar target/restfulSpringBootApp.jar
```

现在，您可以做到这一点：

```java
curl -X POST -d '{ "id": "45", "password": "samsung" }' http://localhost:8080/Product
```

并查看 http://localhost:8080/的响应是否如下：

```java
{ "id": "45", "password": "samsung" }
```

# 总结

在本章中，我们演示了使用 Spring Boot 启动应用程序的过程。我们从设置一个简单的 Spring Boot 项目开始。我们还创建了一个带有 Gradle 支持的简单 MVC 应用程序。接下来，我们讨论了使用 Spring Boot 进行热交换 Java 文件的方法。

我们还提供了关于 Spring Boot 如何支持云平台服务器并帮助在云上部署应用程序的信息。最后，我们演示了一个使用 Spring Boot 的 restful 应用程序。

在下一章中，我们将讨论 Spring 缓存。
