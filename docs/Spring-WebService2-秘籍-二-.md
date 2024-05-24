# Spring WebService2 秘籍（二）

> 原文：[`zh.annas-archive.org/md5/1F0369E05A9E0B8B44E275BC989E8AD8`](https://zh.annas-archive.org/md5/1F0369E05A9E0B8B44E275BC989E8AD8)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第二章：为 SOAP Web 服务构建客户端

在本章中，我们将涵盖：

+   在 Eclipse 中设置 Web 服务客户端开发环境

+   使用 Maven 设置 Web 服务客户端开发环境

+   在 HTTP 传输上创建 Web 服务客户端

+   在 JMS 传输上创建 Web 服务客户端

+   在 E-mail 传输上创建 Web 服务客户端

+   在 XMPP 传输上创建 Web 服务客户端

+   使用 XPath 表达式创建 Web 服务客户端

+   为 WS-Addressing 端点创建 Web 服务客户端

+   使用 XSLT 转换 Web 服务消息

# 介绍

使用 Java API，如`SAAJ`，可以生成客户端 SOAP 消息，并将其传输到/从 Web 服务。但是，这需要额外的编码和关于 SOAP 消息的知识。

`org.springframework.ws.client.core`包含了客户端 API 的核心功能，可以简化调用服务器端 Web 服务。

这个包中的 API 提供了像`WebServiceTemplate`这样的模板类，简化了 Web 服务的使用。使用这些模板，您将能够在各种传输协议（HTTP、JMS、电子邮件、XMPP 等）上创建 Web 服务客户端，并发送/接收 XML 消息，以及在发送之前将对象编组为 XML。Spring 还提供了一些类，如`StringSource`和`Result`，简化了在使用`WebServiceTemplate`时传递和检索 XML 消息。

在本章中，前两个教程解释了如何在 Eclipse 和 Maven 中设置调用 Web 服务客户端的环境。

然后我们将讨论如何使用`WebServiceTemplate`在各种传输协议（HTTP、JMS、电子邮件、XMPP 等）上创建 Web 服务客户端。除此之外，*使用 XPath 表达式设置 Web 服务客户端*这个教程解释了如何从 XML 消息中检索数据。最后，在最后一个教程*使用 XSLT 转换 Web 服务消息*中，介绍了如何在客户端和服务器之间将 XML 消息转换为不同格式。为了设置 Web 服务服务器，使用了第一章中的一些教程，*构建 SOAP Web 服务*，并创建了一个单独的客户端项目，调用服务器端的 Web 服务。

# 在 Eclipse 中设置 Web 服务客户端开发环境

最简单的 Web 服务客户端是调用服务器端 Web 服务的 Java 类。在这个教程中，介绍了设置调用服务器端 Web 服务的环境。在这里，客户端的 Java 类以两种形式调用服务器端的 Web 服务。第一种是在类的主方法中调用 Web 服务的 Java 类。第二种是使用 JUnit 测试类调用服务器端的 Web 服务。

## 准备工作

这个教程类似于第一章中讨论的*使用 Maven 构建和运行 Spring-WS*这个教程，*构建 SOAP Web 服务*。

1.  下载并安装 Java EE 开发人员 Helios 的 Eclipse IDE。

1.  在这个教程中，项目的名称是`LiveRestaurant_R-2.1`（服务器端 Web 服务），具有以下 Maven 依赖项：

+   `spring-ws-core-2.0.1.RELEASE.jar`

+   `jdom-1.0.jar`

+   `log4j-1.2.9.jar`

+   `jaxen-1.1.jarb`

+   `xalan-2.7.0.jar`

1.  `LiveRestaurant_R-2.1-Client`（客户端）具有以下 Maven 依赖项：

+   `spring-ws-core-2.0.1.RELEASE.jar`

+   `jdom-1.0.jar`

+   `log4j-1.2.9.jar`

+   `jaxen-1.1.jar`

+   `xalan-2.7.0.jar`

+   `junit-4.7.jar`

1.  运行以下 Maven 命令，以便将客户端项目导入 Eclipse（客户端）：

```java
mvn eclipse:eclipse -Declipse.projectNameTemplate="LiveRestaurant_R-2.1-Client" 

```

## 如何做...

这个教程使用了第一章中讨论的*使用 JDOM 处理传入的 XML 消息*这个教程，*构建 SOAP Web 服务*作为服务器端项目。

1.  在主方法中运行调用 Web 服务的 Java 类。

1.  通过转到**File** | **Import** | **General** | **Existing projects into workspace** | **LiveRestaurant_R-2..1-Client**，将`LiveRestaurant_R-2.1-Client`导入 Eclipse 工作区。

1.  转到命令提示符中的`LiveRestaurant_R-2.1`文件夹，并使用以下命令运行服务器：

```java
mvn clean package tomcat:run 

```

1.  在`com.packtpub.liverestaurant.client`包的`src/main/java`文件夹中选择`OrderServiceClient`类，然后选择**Run As** | **Java Application**。

在客户端上运行 Java 类时的控制台输出如下：

```java
Received response ....
<tns:placeOrderResponse > <tns:refNumber>order-John_Smith_9999</tns:refNumber>
</tns:placeOrderResponse>
for request...
<tns:placeOrderRequest >
<tns:order>
<tns:refNumber>9999</tns:refNumber>
<tns:customer>
.......
</tns:customer>
<tns:dateSubmitted>2008-09-29T05:49:45</tns:dateSubmitted>
<tns:orderDate>2014-09-19T03:18:33</tns:orderDate>
<tns:items>
<tns:type>Snacks</tns:type>
<tns:name>Pitza</tns:name>
<tns:quantity>2</tns:quantity>
</tns:items>
</tns:order>
</tns:placeOrderRequest>.... 

```

1.  在 Eclipse 中运行一个 JUnit 测试用例。

1.  在`com.packtpub.liverestaurant.client`包的`src/test/java`文件夹中选择`OrderServiceClientTest`类，然后选择**Run As** | **Junit Test**。

运行 JUnit 测试用例时的控制台输出如下（您可以单击**Console**标签旁边的**JUnit**标签，查看测试用例是否成功）：

```java
Received response ..
<tns:placeOrderResponse >
<tns:refNumber>order-John_Smith_9999</tns:refNumber>
</tns:placeOrderResponse>..
......
<tns:placeOrderRequest >
<tns:order>
<tns:refNumber>9999</tns:refNumber>
<tns:customer>
......
</tns:customer>
<tns:dateSubmitted>2008-09-29T05:49:45</tns:dateSubmitted>
<tns:orderDate>2014-09-19T03:18:33</tns:orderDate>
<tns:items>
<tns:type>Snacks</tns:type>
<tns:name>Pitza</tns:name>
<tns:quantity>2</tns:quantity>
</tns:items>
</tns:order>
</tns:placeOrderRequest> 

```

### 注意

要传递参数或自定义测试的设置，请选择测试单元类，**Run As** | **Run Configuration** |，然后在左窗格上双击**JUnit**。

然后，您将能够自定义传递的参数或设置并运行客户端。

## 工作原理...

当运行调用 Web 服务的 Java 类的主方法时，Eclipse 通过以下 Java 类路径内部运行以下命令：

```java
java -classpath com.packtpub.liverestaurant.client.OrderServiceClient 

```

当运行 JUnit 测试用例时，Eclipse 通过内部调用以下命令来运行 JUnit 框架的测试用例：

```java
java -classpath com.packtpub.liverestaurant.client.OrderServiceClientTest 

```

## 另请参阅

在第一章中讨论的*使用 Maven 构建和运行 Spring-WS 项目*和*使用 JDOM 处理传入的 XML 消息*配方，

本章讨论的*使用 HTTP 传输创建 Web 服务客户端*配方。

# 使用 Maven 设置 Web 服务客户端开发环境

Maven 支持使用命令提示符运行类的主方法以及 JUnit 测试用例。

在这个配方中，解释了设置 Maven 环境以调用客户端 Web 服务。在这里，客户端 Java 代码以两种形式调用服务器上的 Web 服务。第一种是在类的主方法中调用 Web 服务的 Java 类。第二种使用 JUnit 调用服务器端 Web 服务。

## 准备工作

在这个配方中，项目的名称是`LiveRestaurant_R-2.2`（用于服务器端 Web 服务），具有以下 Maven 依赖项：

+   `spring-ws-core-2.0.1.RELEASE.jar`

+   `log4j-1.2.9.jar`

以下是`LiveRestaurant_R-2.2-Client`（客户端 Web 服务）的 Maven 依赖项：

+   `spring-ws-core-2.0.1.RELEASE.jar`

+   `junit-4.7.jar`

## 如何做...

这个配方使用了第一章中讨论的*使用 DOM 处理传入的 XML 消息*配方，*构建 SOAP Web 服务*作为服务器端项目。

1.  在主方法中运行调用 Web 服务的 Java 类。

1.  转到命令提示符中的`LiveRestaurant_R-2.2`文件夹，并使用以下命令运行服务器：

```java
mvn clean package tomcat:run 

```

1.  转到文件夹`LiveRestaurant_R-2.2-Client`并运行以下命令：

```java
mvn clean package exec:java 

```

+   在客户端上运行 Maven 命令时，以下是输出：

```java
Received response ....
<placeOrderResponse >
<refNumber>order-John_Smith_9999</refNumber>
</placeOrderResponse>....
<tns:placeOrderRequest >
<tns:order>
<tns:refNumber>9999</tns:refNumber>
<tns:customer>
.....
</tns:customer>
<tns:dateSubmitted>2008-09-29T05:49:45</tns:dateSubmitted>
<tns:orderDate>2014-09-19T03:18:33</tns:orderDate>
<tns:items>
<tns:type>Snacks</tns:type>
<tns:name>Pitza</tns:name>
<tns:quantity>2</tns:quantity>
</tns:items>
</tns:order>
</tns:placeOrderRequest> 

```

1.  使用 Maven 运行 JUnit 测试用例。

1.  转到命令提示符中的`LiveRestaurant_R-2.2`文件夹，并使用以下命令运行服务器：

```java
mvn clean package tomcat:run 

```

1.  转到文件夹`LiveRestaurant_R-2.2-Client`并运行以下命令：

```java
mvn clean package 

```

+   在客户端上使用 Maven 运行 JUnit 测试用例后，以下是输出：

```java
Received response ...
<placeOrderResponse >
<refNumber>order-John_Smith_9999</refNumber>
</placeOrderResponse>...
for request ...
<tns:placeOrderRequest >
<tns:order>
<tns:refNumber>9999</tns:refNumber>
<tns:customer>
.....
</tns:customer>
<tns:dateSubmitted>2008-09-29T05:49:45</tns:dateSubmitted>
<tns:orderDate>2014-09-19T03:18:33</tns:orderDate>
<tns:items>
<tns:type>Snacks</tns:type>
<tns:name>Pitza</tns:name>
<tns:quantity>2</tns:quantity>
</tns:items>
</tns:order>
</tns:placeOrderRequest></SOAP-ENV:Body></SOAP-ENV:Envelope>]
Tests run: 1, Failures: 0, Errors: 0, Skipped: 0, Time elapsed: 0.702 sec
Results :
Tests run: 1, Failures: 0, Errors: 0, Skipped: 0 

```

## 工作原理...

在`pom.xml`文件中设置`exec-maven-plugin`，告诉 Maven 运行`OrderServiceClient`的`mainClass`的 Java 类。该 Java 类告诉 Maven 运行`OrderServiceClient`的`mainClass`：

```java
<build>
<finalName>LiveRestaurant_Client</finalName>
<plugins>
.......
</plugin>
<plugin>
<groupId>org.codehaus.mojo</groupId>
<artifactId>exec-maven-plugin</artifactId>
<version>1.2.1</version>
<executions>
<execution>
<goals>
<goal>java</goal>
</goals>
</execution>
</executions>
<configuration>
<mainClass>com.packtpub.liverestaurant.client.OrderServiceClient</mainClass>
</configuration>
</plugin>
</plugins>
</build>

```

Maven 通过项目类路径内部运行以下命令：

```java
java -classpath com.packtpub.liverestaurant.client.OrderServiceClient

```

要在 Maven 中设置和运行 JUnit 测试用例，测试类 `OrderServiceClientTest` 应该包含在文件夹 `src/test/java` 中，并且测试类名称应该以 `Test` 结尾（`OrderServiceClientTest`）。命令 `mvn clean package` 运行 `src/test/java` 文件夹中的所有测试用例（内部 Maven 调用）：

```java
java -classpath ...;junit.jar.. junit.textui.TestRunner com.packtpub.liverestaurant.client.OrderServiceClientTest ) . 

```

## 另请参阅

在第一章中讨论的*使用 Maven 构建和运行 Spring-WS 项目*和*使用 JDOM 处理传入的 XML 消息*的配方，*构建 SOAP Web 服务*。

在本章中讨论的*在 HTTP 传输上创建 Web 服务客户端*的配方。

# 在 HTTP 传输上创建 Web 服务客户端

在这个配方中，`WebServiceTemplate` 用于通过 HTTP 传输从客户端发送/接收简单的 XML 消息。

## 准备工作

在这个配方中，项目的名称是 `LiveRestaurant_R-2.3`（用于服务器端 Web 服务），具有以下 Maven 依赖项：

+   `spring-ws-core-2.0.1.RELEASE.jar`

+   `log4j-1.2.9.jar`

以下是 `LiveRestaurant_R-2.3-Client`（客户端 Web 服务）的 Maven 依赖项：

+   `spring-ws-core-2.0.1.RELEASE.jar`

+   `junit-4.7.jar`

## 如何做到...

这个配方使用了在第一章中讨论的*通过注释负载根来设置端点*的配方，*构建 SOAP Web 服务*，作为服务器端项目。以下是如何设置客户端：

1.  创建一个调用 `WebServiceTemplate` 中的 Web 服务服务器的类在 `src/test` 中。

1.  在 `applicationContext.xml` 文件中配置 `WebServiceTemplate`。

1.  从文件夹 `Liverestaurant_R-2.3` 运行以下命令：

```java
mvn clean package tomcat:run 

```

1.  打开一个新的命令窗口到 `Liverestaurant_R-2.3-Client` 并运行以下命令：

```java
mvn clean package 

```

+   以下是客户端输出：

```java
Received response ....
<tns:placeOrderResponse >
<tns:refNumber>order-John_Smith_1234</tns:refNumber>
</tns:placeOrderResponse>...
<tns:placeOrderRequest >
<tns:order>
<tns:refNumber>9999</tns:refNumber>
<tns:customer>
......
</tns:customer>
<tns:dateSubmitted>2008-09-29T05:49:45</tns:dateSubmitted>
<tns:orderDate>2014-09-19T03:18:33</tns:orderDate>
<tns:items>
<tns:type>Snacks</tns:type>
<tns:name>Pitza</tns:name>
<tns:quantity>2</tns:quantity>
</tns:items>
</tns:order>
</tns:placeOrderRequest>
.....
Tests run: 2, Failures: 0, Errors: 0, Skipped: 0, Time elapsed: 0.749 sec
Results :
Tests run: 2, Failures: 0, Errors: 0, Skipped: 0 

```

## 它是如何工作的...

`Liverestaurant_R-2.3` 是一个服务器端项目，它重复使用了在第一章中讨论的*通过注释负载根来设置端点*的配方。*构建 SOAP Web 服务*。

已配置的客户端 `WebServiceTemplate` 的 `applicationContext.xml` 文件（`id="webServiceTemplate"`）用于发送和接收 XML 消息。可以从客户端程序中获取此 bean 的实例以发送和接收 XML 消息。

`messageFactory` 是 `SaajSoapMessageFactory` 的一个实例，它被引用在 `WebServiceTemplate` 内。`messageFactory` 用于从 XML 消息创建 SOAP 数据包。默认的服务 URI 是 `WebServiceTemplate` 默认使用的 URI，用于发送/接收所有请求/响应：

```java
<bean id="messageFactory" class="org.springframework.ws.soap.saaj.SaajSoapMessageFactory" />
<bean id="webServiceTemplate" class="org.springframework.ws.client.core.WebServiceTemplate">
<constructor-arg ref="messageFactory" />
<property name="defaultUri" value="http://localhost:8080/LiveRestaurant/spring-ws/OrderService" />
</bean>

```

`OrderServiceClientTest.java` 是一个简单的 JUnit 测试用例，用于在 `setUpBeforeClass()` 方法中从 `applicationContext.xml` 中获取和初始化 `WebServiceTemplate`（由 `@BeforeClass` 标记）。在 `testCancelOrderRequest` 和 `testPlaceOrderRequest` 方法中（由 `@Test` 标记），`WebServiceTemplate` 发送一个简单的 XML 消息（由现有输入 XML 文件的 `StringSource` 对象创建），并接收包装在 `Result` 对象中的来自服务器的响应：

```java
private static WebServiceTemplate wsTemplate = null;
private static InputStream isPlace;
private static InputStream isCancel;
@BeforeClass
public static void setUpBeforeClass() throws Exception {
ClassPathXmlApplicationContext appContext = new ClassPathXmlApplicationContext("/applicationContext.xml");
wsTemplate = (WebServiceTemplate) appContext.getBean("webServiceTemplate");
isPlace = new OrderServiceClientTest().getClass().getResourceAsStream("placeOrderRequest.xml");
isCancel = new OrderServiceClientTest().getClass().getResourceAsStream("cancelOrderRequest.xml");
}
@Test
public final void testPlaceOrderRequest() throws Exception {
Result result = invokeWS(isPlace);
Assert.assertTrue(result.toString().indexOf("placeOrderResponse")>0);
}
@Test
public final void testCancelOrderRequest() throws Exception {
Result result = invokeWS(isCancel);
Assert.assertTrue(result.toString().indexOf("cancelOrderResponse")>0);
}
private static Result invokeWS(InputStream is) {
StreamSource source = new StreamSource(is);
StringResult result = new StringResult();
wsTemplate.sendSourceAndReceiveToResult(source, result);
return result;
}

```

## 另请参阅

在第一章中讨论的*通过注释负载根来设置端点*的配方，*构建 SOAP Web 服务*和在本章中讨论的*使用 Maven 设置 Web 服务客户端开发环境*的配方。

# 在 JMS 传输上创建 Web 服务客户端

JMS（Java 消息服务）于 1999 年由 Sun Microsystems 作为 Java 2、J2EE 的一部分引入。使用 JMS 的系统可以同步或异步通信，并基于点对点和发布-订阅模型。Spring Web 服务提供了在 Spring 框架中基于 JMS 功能构建 JMS 协议的 Web 服务的功能。Spring Web 服务在 JMS 协议上提供以下通信功能：

+   客户端和服务器可以断开连接，只有在发送/接收消息时才能连接

+   客户端不需要等待服务器回复（例如，如果服务器需要很长时间来处理，例如进行复杂的数学计算）

+   JMS 提供了确保客户端和服务器之间消息传递的功能

在这个配方中，`WebServiceTemplate`用于在客户端上通过 JMS 传输发送/接收简单的 XML 消息。使用一个 JUnit 测试用例类在服务器端设置并使用`WebServiceTemplate`发送和接收消息。

## 准备工作

在这个配方中，项目的名称是`LiveRestaurant_R-2.4`，具有以下 Maven 依赖项：

+   `spring-ws-core-2.0.1.RELEASE.jar`

+   `spring-ws-support-2.0.1.RELEASE.jar`

+   `spring-test-3.0.5.RELEASE.jar`

+   `spring-jms-3.0.5.RELEASE.jar`

+   `junit-4.7.jar`

+   `xmlunit-1.1.jar`

+   `log4j-1.2.9.jar`

+   `jms-1.1.jar`

+   `activemq-core-4.1.1.jar`

## 如何做...

本配方使用在第一章中讨论的配方*在 JMS 传输上设置 Web 服务*，*构建 SOAP Web 服务*作为服务器端项目。

1.  创建一个调用`WebServiceTemplate`的 Web 服务服务器的 JUnit 测试类。

1.  在`applicationContext`中配置`WebServiceTemplate`以通过 JMS 协议发送消息。

1.  运行命令`mvn clean package`。您将看到以下输出：

```java
Received response ..
<tns:placeOrderResponse >
<tns:refNumber>order-John_Smith_1234</tns:refNumber>
</tns:placeOrderResponse>....
<tns:placeOrderRequest >
<tns:order>
<tns:refNumber>9999</tns:refNumber>
<tns:customer>
.....
</tns:customer>
<tns:dateSubmitted>2008-09-29T05:49:45</tns:dateSubmitted>
<tns:orderDate>2014-09-19T03:18:33</tns:orderDate>
<tns:items>
<tns:type>Snacks</tns:type>
<tns:name>Pitza</tns:name>
<tns:quantity>2</tns:quantity>
</tns:items>
</tns:order>
</tns:placeOrderRequest> 

```

## 它是如何工作的...

在这个项目中，我们使用一个 JUnit 类在 JMS 传输上设置 Web 服务服务器。服务器使用`PayloadEndpoint`接收 XML 请求消息，并返回一个简单的 XML 消息作为响应（服务器已经在第一章中讨论的配方*在 JMS 传输上设置 Web 服务*，*构建 SOAP Web 服务*中描述）。

已配置客户端`WebServiceTemplate`的`applicationContext.xml`文件（`id="webServiceTemplate"`）用于发送和接收 XML 消息。可以从客户端程序中获取此 bean 的实例以发送和接收 XML 消息。`messageFactory`是`SaajSoapMessageFactory`的一个实例，被引用在`WebServiceTemplate`内。`messageFactory`用于从 XML 消息创建 SOAP 数据包。默认服务 URI 是`WebServiceTemplate`默认使用的 JMS URI，用于发送/接收所有请求/响应。配置在`WebServiceTemplate`内的`JmsMessageSender`用于发送 JMS 消息。要使用`JmsMessageSender`，`defaultUri`或`JMS URI`应包含`jms:`前缀和目的地名称。一些`JMS URI`的例子是`jms:SomeQueue, jms:SomeTopic?priority=3&deliveryMode=NON_PERSISTENT, jms:RequestQueue?replyToName=ResponseName`等。默认情况下，`JmsMessageSender`发送 JMS`BytesMessage`，但可以通过在 JMS URI 上使用`messageType`参数来覆盖使用`TextMessages`。例如，`jms:Queue?messageType=TEXT_MESSAGE`。

```java
<bean id="webServiceTemplate" class="org.springframework.ws.client.core.WebServiceTemplate">
<constructor-arg ref="messageFactory"/>
<property name="messageSender">
<bean class="org.springframework.ws.transport.jms.JmsMessageSender">
<property name="connectionFactory" ref="connectionFactory"/>
</bean>
</property>
<property name="defaultUri" value="jms:RequestQueue?deliveryMode=NON_PERSISTENT"/>
</bean>

```

`JmsTransportWebServiceIntegrationTest.java`是一个 JUnit 测试用例，从`applicationContext.xml`文件中获取并注入`WebServiceTemplate`（由`@ContextConfiguration("applicationContext.xml")`标记）。在`testSendReceive()`方法（由`@Test`标记），`WebServiceTemplate`发送一个简单的 XML 消息（由简单输入字符串的`StringSource`对象创建），并接收包装在`Result`对象中的服务器响应。在`testSendReceive()`方法（由`@Test`标记）中，发送和接收消息类似于 HTTP 客户端，并使用`WebServiceTemplate.sendSourceAndReceiveToResult`发送/接收消息：

```java
@Test
public void testSendReceive() throws Exception {
InputStream is = new JmsTransportWebServiceIntegrationTest().getClass().getResourceAsStream("placeOrderRequest.xml");
StreamSource source = new StreamSource(is);
StringResult result = new StringResult();
webServiceTemplate.sendSourceAndReceiveToResult(source, result);
XMLAssert.assertXMLEqual("Invalid content received", expectedResponseContent, result.toString());
}

```

## 另请参阅

在第一章中讨论的配方*在 JMS 传输上设置 Web 服务*，*构建 SOAP Web 服务*。

*使用 Spring Junit 对 Web 服务进行单元测试*

# 在 E-mail 传输上创建 Web 服务客户端

在这个示例中，`WebServiceTemplate` 用于在客户端上通过电子邮件传输发送/接收简单的 XML 消息。使用第一章中讨论的 *在电子邮件传输上设置 Web 服务* 这个示例，*构建 SOAP Web 服务* 来设置 Web 服务。使用 JUnit 测试用例类来在服务器端设置 Web 服务，并使用 `WebServiceTemplate` 发送/接收消息。

## 准备工作

在这个示例中，项目的名称是 `LiveRestaurant_R-2.5`，具有以下 Maven 依赖项：

+   `spring-ws-core-2.0.1.RELEASE.jar`

+   `spring-ws-support-2.0.1.RELEASE.jar`

+   `spring-test-3.0.5.RELEASE.jar`

+   `mail-1.4.1.jar`

+   `mock-javamail-1.6.jar`

+   `junit-4.7.jar`

+   `xmlunit-1.1.jar`

## 如何做...

这个示例使用第一章中讨论的 *在电子邮件传输上设置 Web 服务* 这个示例，*构建 SOAP Web 服务* 作为服务器端项目。

1.  创建一个测试类，使用 `WebServiceTemplate` 调用 Web 服务服务器。

1.  在 `applicationContext` 中配置 `WebServiceTemplate` 以通过电子邮件协议发送消息。

1.  运行命令 `mvn clean package`。以下是此命令的输出：

```java
Received response
<tns:placeOrderResponse >
<tns:refNumber>order-John_Smith_1234</tns:refNumber>
</tns:placeOrderResponse>....
<tns:placeOrderRequest >
<tns:order>
<tns:refNumber>9999</tns:refNumber>
<tns:customer>
.....
</tns:customer>
<tns:dateSubmitted>2008-09-29T05:49:45</tns:dateSubmitted>
<tns:orderDate>2014-09-19T03:18:33</tns:orderDate>
<tns:items>
<tns:type>Snacks</tns:type>
<tns:name>Pitza</tns:name>
<tns:quantity>2</tns:quantity>
</tns:items>
</tns:order>
</tns:placeOrderRequest> 

```

## 它是如何工作的...

该项目通过 JUnit 类在电子邮件传输上设置 Web 服务服务器。这个类使用 Spring JUnit 来加载应用程序上下文，首先设置服务器，然后运行客户端单元测试以验证其是否按预期运行。服务器已在第一章中讨论的 *在电子邮件传输上设置 Web 服务* 这个示例中解释过。

配置的客户端 `WebServiceTemplate (id="webServiceTemplate")` 的 `applicationContext.xml` 文件用于发送和接收 XML 消息。可以从客户端程序中获取此 bean 的实例以发送和接收 XML 消息。`messageFactory` 是 `SaajSoapMessageFactory` 的一个实例，被引用在 `WebServiceTemplate` 内。`messageFactory` 用于从 XML 消息创建 SOAP 数据包。`transportURI` 是一个由 `WebServiceTemplate` 使用的 URI，指示用于发送请求的服务器。`storeURI` 是一个 URI，配置在 `WebServiceTemplate` 内，指示用于轮询响应的服务器（通常是 POP3 或 IMAP 服务器）。默认 URI 是 `WebServiceTemplate` 默认使用的电子邮件地址 URI，用于发送/接收所有请求/响应：

```java
<bean id="webServiceTemplate" class="org.springframework.ws.client.core.WebServiceTemplate">
<constructor-arg ref="messageFactory"/>
<property name="messageSender">
<bean class="org.springframework.ws.transport.mail.MailMessageSender">
<property name="from" value="client@packtpubtest.com"/>
<property name="transportUri" value="smtp://smtp.packtpubtest.com"/>
<property name="storeUri" value="imap://client@packtpubtest.com/INBOX"/>
<property name="receiveSleepTime" value="1500"/>
<property name="session" ref="session"/>
</bean>
</property>
<property name="defaultUri" value="mailto:server@packtpubtest.com"/>
</bean>
<bean id="session" class="javax.mail.Session" factory-method="getInstance">
<constructor-arg>
<props/>
</constructor-arg>
</bean>

```

`MailTransportWebServiceIntegrationTest.java` 是一个 JUnit 测试用例，从 `applicationContext.xml` 中获取并注入 `WebServiceTemplate`（由 `@ContextConfiguration("applicationContext.xml")` 标记）。在 `testWebServiceOnMailTransport()` 方法中（由 `@Test` 标记），`WebServiceTemplate` 发送一个简单的 XML 消息（由输入 XML 文件的 `StringSource` 对象创建），并接收包装在 `Result` 对象中的来自服务器的响应。

```java
@Test
public void testWebServiceOnMailTransport() throws Exception {
InputStream is = new MailTransportWebServiceIntegrationTest().getClass().getResourceAsStream("placeOrderRequest.xml");
StreamSource source = new StreamSource(is);
StringResult result = new StringResult();
webServiceTemplate.sendSourceAndReceiveToResult(source, result);
applicationContext.close();
XMLAssert.assertXMLEqual("Invalid content received", expectedResponseContent, result.toString());
}

```

## 另请参阅..

在第一章中讨论的 *在电子邮件传输上设置 Web 服务* 这个示例，*构建 SOAP Web 服务*。

使用 Spring Junit 对 Web 服务进行单元测试

# 在 XMPP 传输上设置 Web 服务

**XMPP**（可扩展消息和出席协议）是一种开放和分散的 XML 路由技术，系统可以使用它向彼此发送 XMPP 消息。XMPP 网络由 XMPP 服务器、客户端和服务组成。使用 XMPP 的每个系统都由唯一的 ID（称为**Jabber ID (JID)**）识别。XMPP 服务器发布 XMPP 服务，以提供对客户端的远程服务连接。

在这个配方中，`WebServiceTemplate`用于通过 XMPP 传输在客户端发送/接收简单的 XML 消息。使用了第一章中的*在 XMPP 传输上设置 Web 服务*配方，*构建 SOAP Web 服务*，来设置一个 Web 服务。使用了一个 JUnit 测试用例类来在服务器端设置 Web 服务，并使用`WebServiceTemplate`发送和接收消息。

## 准备工作

在这个配方中，项目的名称是`LiveRestaurant_R-2.6`，具有以下 Maven 依赖项：

+   `spring-ws-core-2.0.1.RELEASE.jar`

+   `spring-ws-support-2.0.1.RELEASE.jar`

+   `spring-test-3.0.5.RELEASE.jar`

+   `junit-4.7.jar`

+   `xmlunit-1.1.jar`

+   `smack-3.1.0.jar`

## 如何做...

1.  这个配方使用了在第一章中讨论的*在 XMPP 传输上设置 Web 服务*配方，*构建 SOAP Web 服务*，作为服务器端项目。

1.  创建一个测试类，调用`WebServiceTemplate`调用 Web 服务服务器。

1.  在`applicationContext`中配置`WebServiceTemplate`以通过 XMPP 协议发送消息。

1.  运行命令`mvn clean package`。您将看到以下输出：

```java
Received response ..
<tns:placeOrderResponse >
<tns:refNumber>order-John_Smith_1234</tns:refNumber>
</tns:placeOrderResponse>....
<tns:placeOrderRequest >
<tns:order>
<tns:refNumber>9999</tns:refNumber>
<tns:customer>
.....
</tns:customer>
<tns:dateSubmitted>2008-09-29T05:49:45</tns:dateSubmitted>
<tns:orderDate>2014-09-19T03:18:33</tns:orderDate>
<tns:items>
<tns:type>Snacks</tns:type>
<tns:name>Pitza</tns:name>
<tns:quantity>2</tns:quantity>
</tns:items>
</tns:order>
</tns:placeOrderRequest> 

```

## 工作原理...

该项目使用 JUnit 类在 XMPP 传输上设置了一个 Web 服务服务器。该服务器已经在配方*在电子邮件传输上设置 Web 服务*中解释过，在第一章中讨论了*构建 SOAP Web 服务*。

已配置客户端`WebServiceTemplate`的`applicationContext.xml`文件（`id="webServiceTemplate"`）用于发送和接收 XML 消息。可以从客户端程序中获取此 bean 的实例，以发送和接收 XML 消息。`messageFactory`是`SaajSoapMessageFactory`的一个实例，被引用在`WebServiceTemplate`内。`messageFactory`用于从 XML 消息创建 SOAP 数据包。`WebServiceTemplate`使用`XmppMessageSender`发送消息到服务器。默认 URI 是`WebServiceTemplate`默认使用的 XMPP 地址 URI，用于发送/接收所有请求/响应：

```java
<bean id="webServiceTemplate" class="org.springframework.ws.client.core.WebServiceTemplate">
<constructor-arg ref="messageFactory"/>
<property name="messageSender">
<bean class="org.springframework.ws.transport.xmpp.XmppMessageSender">
<property name="connection" ref="connection"/>
</bean>
</property>
<property name="defaultUri" value="xmpp:yourUserName@gmail.com"/>
</bean>

```

`XMPPTransportWebServiceIntegrationTest.java`是一个 JUnit 测试用例，从`applicationContext.xml`中获取并注入`WebServiceTemplate`（由`@ContextConfiguration("applicationContext.xml")`标记）。在`testWebServiceOnXMPPTransport()`方法中（由`@Test`标记），`WebServiceTemplate`发送一个 XML 消息（由简单的输入 XML 文件的`StringSource`对象创建），并接收服务器包装在`Result`对象中的响应。

```java
@Autowired
private GenericApplicationContext applicationContext;
@Test
public void testWebServiceOnXMPPTransport() throws Exception {
StringResult result = new StringResult();
StringSource sc=new StringSource(requestContent);
webServiceTemplate.sendSourceAndReceiveToResult(sc, result);
XMLAssert.assertXMLEqual("Invalid content received", requestContent, result.toString());
applicationContext.close();
}

```

## 另请参阅

在第一章中讨论的*在 XMPP 传输上设置 Web 服务*配方，*构建 SOAP Web 服务*。

使用 Spring JUnit 对 Web 服务进行单元测试

# 使用 XPath 表达式创建 Web 服务客户端

在 Java 编程中使用 XPath 是从 XML 消息中提取数据的标准方法之一。但是，它将 XML 节点/属性的 XPath 地址（最终可能非常长）与 Java 代码混合在一起。

Spring 提供了一个功能，可以从 Java 中提取这些地址，并将它们转移到 Spring 配置文件中。在这个配方中，使用了第一章中的*通过注释有效负载根设置端点*配方，*构建 SOAP Web 服务*，来设置一个 Web 服务服务器。

## 准备工作

在这个配方中，项目的名称是`LiveRestaurant_R-2.7`（用于服务器端 Web 服务），具有以下 Maven 依赖项：

+   `spring-ws-core-2.0.1.RELEASE.jar`

+   `log4j-1.2.9.jar`

以下是`LiveRestaurant_R-2.7-Client`（用于客户端 Web 服务）的 Maven 依赖项：

+   `spring-ws-core-2.0.1.RELEASE.jar`

+   `junit-4.7.jar`

+   `log4j-1.2.9.jar`

## 如何做...

此食谱使用了在服务器端项目中讨论的*通过注释负载根设置端点*食谱。

1.  在`applicationContext.xml`中配置 XPath 表达式。

1.  在`applicationContext`中配置`WebServiceTemplate`以通过 HTTP 协议发送消息，如食谱*在 HTTP 传输上创建 Web 服务客户端*中所述。

1.  创建一个测试类，使用`WebServiceTemplate`调用 Web 服务服务器，并在 Java 代码中使用 XPath 表达式提取所需的值。

1.  从文件夹`Liverestaurant_R-2.7`中运行命令`mvn clean package tomcat:run`。

1.  打开一个新的命令窗口到`Liverestaurant_R-2.7-Client`并运行以下命令：

```java
mvn clean package. 

```

+   以下是客户端代码的输出：

```java
--Request
<tns:placeOrderRequest >
<tns:order>
<tns:refNumber>9999</tns:refNumber>
<tns:customer>
<tns:addressPrimary>
<tns:doorNo>808</tns:doorNo>
<tns:building>W8</tns:building>
<tns:street>St two</tns:street>
<tns:city>NY</tns:city>
<tns:country>US</tns:country>
<tns:phoneMobile>0018884488</tns:phoneMobile>
<tns:phoneLandLine>0017773366</tns:phoneLandLine>
<tns:email>d@b.c</tns:email>
</tns:addressPrimary>
<tns:addressSecondary>
<tns:doorNo>409</tns:doorNo>
<tns:building>W2</tns:building>
<tns:street>St one</tns:street>
<tns:city>NY</tns:city>
<tns:country>US</tns:country>
<tns:phoneMobile>0018882244</tns:phoneMobile>
<tns:phoneLandLine>0019991122</tns:phoneLandLine>
<tns:email>a@b.c</tns:email>
</tns:addressSecondary>
<tns:name>
<tns:fName>John</tns:fName>
<tns:mName>Paul</tns:mName>
<tns:lName>Smith</tns:lName>
</tns:name>
</tns:customer>
<tns:dateSubmitted>2008-09-29T05:49:45</tns:dateSubmitted>
<tns:orderDate>2014-09-19T03:18:33</tns:orderDate>
<tns:items>
<tns:type>Snacks</tns:type>
<tns:name>Pitza</tns:name>
<tns:quantity>2</tns:quantity>
</tns:items>
</tns:order>
</tns:placeOrderRequest>
<!--Received response-->
<tns:placeOrderResponse >
<tns:refNumber>order-John_Smith_1234</tns:refNumber></tns:placeOrderResponse>
...Request
<tns:cancelOrderRequest >
<tns:refNumber>9999</tns:refNumber>
</tns:cancelOrderRequest></SOAP-ENV:Body></SOAP-ENV:Envelope>]
...Received response..
<tns:cancelOrderResponse >
<tns:cancelled>true</tns:cancelled></tns:cancelOrderResponse> 

```

## 工作原理...

设置客户端和服务器端，并使用`WebserviceTemplate`的方式与我们在食谱*在 HTTP 传输上创建 Web 服务客户端*中所做的一样。在客户端`applicationContext.xml`中配置了`xpathExpPlace`和`xpathExpCancel`，并创建了`XPathExpressionFactoryBean`的实例，该实例获取所需数据的 XPath 属性和 XML 消息的命名空间：

```java
<bean id="xpathExpCancel"
class="org.springframework.xml.xpath.XPathExpressionFactoryBean">
<property name="expression" value="/tns:cancelOrderResponse/tns:cancelled" />
<property name="namespaces">
<props>
<prop key="tns">http://www.packtpub.com/liverestaurant/OrderService/schema</prop>
</props>
</property>
</bean>
<bean id="xpathExpPlace"
class="org.springframework.xml.xpath.XPathExpressionFactoryBean">
<property name="expression" value="/tns:placeOrderResponse/tns:refNumber" />
<property name="namespaces">
<props>
<prop key="tns">http://www.packtpub.com/liverestaurant/OrderService/schema</prop>
</props>
</property>
</bean>

```

在`OrderServiceClientTest`类中，可以从`applicationContext`中提取`XPathExpressionFactoryBean`的实例。`String message = xpathExp.evaluateAsString(result.getNode())`使用 XPath 表达式返回所需的数据：

```java
@Test
public final void testPlaceOrderRequest() {
DOMResult result=invokeWS(isPlace);
String message = xpathExpPlace.evaluateAsString(result.getNode());
Assert.assertTrue(message.contains("Smith"));
}
@Test
public final void testCancelOrderRequest() {
DOMResult result= invokeWS(isCancel);
Boolean cancelled = xpathExpCancel.evaluateAsBoolean(result.getNode());
Assert.assertTrue(cancelled);
}

```

## 另请参阅

食谱*使用 XPath 表达式设置端点*在第一章 *构建 SOAP Web 服务*中讨论。

在本章中讨论的食谱*在 HTTP 传输上创建 Web 服务客户端*。

使用 Spring JUnit 对 Web 服务进行单元测试。

# 为 WS-Addressing 端点创建 Web 服务客户端

如食谱*设置一个传输中立的 WS-Addressing 端点*中所述，讨论在第一章 *构建 SOAP Web 服务*，WS-Addressing 是一种替代的路由方式。WS-Addressing 将路由数据与消息分开，并将其包含在 SOAP 头中，而不是在 SOAP 消息的主体中。以下是从客户端发送的 WS-Addressing 样式的 SOAP 消息示例：

```java
<SOAP-ENV:Header >
<wsa:To>server_uri</wsa:To>
<wsa:Action>action_uri</wsa:Action>
<wsa:From>client_address </wsa:From>
<wsa:ReplyTo>client_address</wsa:ReplyTo>
<wsa:FaultTo>admen_uri </wsa:FaultTo>
<wsa:MessageID>..</wsa:MessageID>
</SOAP-ENV:Header>
<SOAP-ENV:Body>
<tns:placeOrderRequest>....</tns:placeOrderReques>
</SOAP-ENV:Body></SOAP-ENV:Envelope>] 

```

在使用 WS-Addressing 时，与其他方法（包括在消息中包含路由数据）相比，客户端或服务器可以访问更多功能。例如，客户端可以将`ReplyTo`设置为自己，将`FaultTo`设置为管理员端点地址。然后服务器将成功消息发送到客户端，将故障消息发送到管理员地址。

Spring-WS 支持客户端和服务器端的 WS-Addressing。要为客户端创建 WS-Addressing 头，可以使用`org.springframework.ws.soap.addressing.client.ActionCallback`。此回调将`Action`头保留为参数。它还使用 WS-Addressing 版本和`To`头。

在此食谱中，使用了在第一章 *构建 SOAP Web 服务*中讨论的*设置一个传输中立的 WS-Addressing 端点*食谱来设置 WS-Addressing Web 服务。在这里使用客户端应用程序来调用服务器并返回响应对象。

## 准备工作

在此食谱中，项目名称为`LiveRestaurant_R-2.8`（用于服务器端 Web 服务），具有以下 Maven 依赖项：

+   `spring-ws-core-2.0.1.RELEASE.jar`

+   `log4j-1.2.9.jar`

以下是`LiveRestaurant_R-2.8-Client`（用于客户端 Web 服务）的 Maven 依赖项：

+   `spring-ws-core-2.0.1.RELEASE.jar`

+   `junit-4.7.jar`

+   `log4j-1.2.9.jar`

## 如何做...

这个配方使用了第一章中讨论的*为 Web 服务设置与传输无关的 WS-Addressing 端点*配方，*构建 SOAP Web 服务*，作为服务器端项目。创建 WS-Addressing 的客户端与*在 HTTP 传输上创建 Web 服务客户端*配方中描述的方式相同，不使用 WebServiceTemplate。为了在客户端上添加 WS-Addressing 头，`WebServiceTemplate`的`sendSourceAndReceiveToResult`方法获得一个`ActionCallBack`实例。

1.  从文件夹`LiveRestaurant_R-2.8`中运行以下命令：

```java
mvn clean package tomcat:run 

```

1.  打开一个新的命令窗口到`LiveRestaurant_R-2.8-Client`，并运行以下命令：

```java
mvn clean package 

```

+   以下是客户端输出：

```java
Received response [<SOAP-ENV:Envelope xmlns:SOAP-ENV="..../">
<SOAP-ENV:Header >
<wsa:To SOAP-ENV:mustUnderstand="1">....</wsa:To><wsa:Action>http://www.packtpub.com/OrderService/CanOrdReqResponse</wsa:Action>
<wsa:MessageID>....</wsa:MessageID>
<wsa:RelatesTo>...</wsa:RelatesTo>
</SOAP-ENV:Header>
<SOAP-ENV:Body>
<tns:cancelOrderResponse >
<tns:cancelled>true</tns:cancelled></tns:cancelOrderResponse>
</SOAP-ENV:Body></SOAP-ENV:Envelope>]
for request ...
<SOAP-ENV:Envelope xmlns:SOAP
-ENV=".."><SOAP-ENV:Header >
<wsa:To SOAP-ENV:mustUnderstand="1">http://www.packtpub.com/liverestaurant/OrderService/schema</wsa:To>
<wsa:To SOAP-ENV:mustUnderstand="1">http://www.packtpub.com/liverestaurant/OrderService/schema</wsa:To>
<wsa:Action>http://www.packtpub.com/OrderService/CanOrdReq</wsa:Action>
<wsa:MessageID>..</wsa:MessageID>
</SOAP-ENV:Header><SOAP-ENV:Body/>
</SOAP-ENV:Envelope>]
<?xml version="1.0" encoding="UTF-8"?>
<tns:cancelOrderResponse >
<tns:cancelled>true</tns:cancelled></tns:cancelOrderResponse> 

```

## 工作原理...

`Liverestaurant_R-2.8`项目是一个支持 WS-Addressing 端点的服务器端 Web 服务。

已配置的客户端`WebServiceTemplate`的`applicationContext.xml`文件（`id="webServiceTemplate"）用于发送和接收 XML 消息，如*在 HTTP 传输上创建 Web 服务客户端*配方中描述的，除了使用`WebServiceTemplate`的 Java 类的实现。

WS-Addressing 客户端将`ActionCallBack`的实例传递给`WebServiceTemplate`的`sendSourceAndReceiveToResult`方法。使用`ActionCallBack`，客户端添加一个包含`Action` URI 的自定义头，例如，[`www.packtpub.com/OrderService/OrdReq`](http://www.packtpub.com/OrderService/OrdReq)和`To` URI，例如，[`www.packtpub.com/liverestaurant/OrderService/schema`](http://www.packtpub.com/liverestaurant/OrderService/schema)。

```java
@Test
public final void testPlaceOrderRequest() throws URISyntaxException {
invokeWS(isPlace,"http://www.packtpub.com/OrderService/OrdReq");
}
@Test
public final void testCancelOrderRequest() throws URISyntaxException {
invokeWS(isCancel,"http://www.packtpub.com/OrderService/CanOrdReq");
}
private static Result invokeWS(InputStream is,String action) throws URISyntaxException {
StreamSource source = new StreamSource(is);
StringResult result = new StringResult();
wsTemplate.sendSourceAndReceiveToResult(source, new ActionCallback(new URI(action),new Addressing10(),new URI("http://www.packtpub.com/liverestaurant/OrderService/schema")),
result);
return result;
}

```

使用这个头，服务器端将能够在端点中找到方法（使用`@Action`注释）。

## 参见

在第一章中讨论的*为 Web 服务设置与传输无关的 WS-Addressing 端点*配方，*构建 SOAP Web 服务*。

在本章中讨论的*在 HTTP 传输上创建 Web 服务客户端*配方。

使用 Spring JUnit 对 Web 服务进行单元测试

# 使用 XSLT 转换 Web 服务消息

最终，Web 服务的客户端可能使用不同版本的 XML 消息，要求在服务器端使用相同的 Web 服务。

Spring Web 服务提供`PayloadTransformingInterceptor`。这个端点拦截器使用 XSLT 样式表，在需要多个版本的 Web 服务时非常有用。使用这个拦截器，您可以将消息的旧格式转换为新格式。

在这个配方中，使用第一章中的*为 Web 服务设置简单的端点映射*配方，*构建 SOAP Web 服务*，来设置一个 Web 服务，这里的客户端应用程序调用服务器并返回响应消息。

## 准备工作

在这个配方中，项目的名称是`LiveRestaurant_R-2.9`（用于服务器端 Web 服务），具有以下 Maven 依赖项：

+   `spring-ws-core-2.0.1.RELEASE.jar`

+   `log4j-1.2.9.jar`

以下是`LiveRestaurant_R-2.9-Client`（客户端 Web 服务）的 Maven 依赖项：

+   `spring-ws-core-2.0.1.RELEASE.jar`

+   `junit-4.7.jar`

+   `log4j-1.2.9.jar`

## 如何做...

这个配方使用了第一章中讨论的*为 Web 服务设置简单的端点映射*配方，*构建 SOAP Web 服务*，作为服务器端项目。客户端与*在 HTTP 传输上创建 Web 服务客户端*配方中讨论的相同，除了 XSLT 文件及其在服务器端应用程序上下文文件中的配置：

1.  创建 XSLT 文件（oldResponse.xslt，oldRequest.xslt）。

1.  修改`LiveRestaurant_R-2.9`中的`spring-ws-servlet.xml`文件以包含 XSLT 文件

1.  从文件夹`Liverestaurant_R-2.9`中运行以下命令：

```java
mvn clean package tomcat:run 

```

1.  打开一个新的命令窗口到`Liverestaurant_R-2.9-Client`，并运行以下命令：

```java
mvn clean package 

```

+   以下是客户端输出：

```java
Received response...
<ns:OrderResponse  message="Order Accepted!"/>...
for request ....
<OrderRequest  message="This is a sample Order Message"/> 

```

+   以下是服务器端输出：

```java
actual request ..
<ns:OrderRequest >
<ns:message>This is a sample Order Message</ns:message></ns:OrderRequest>
actual response = <ns:OrderResponse >
<ns:message>Order Accepted!</ns:message></ns:OrderResponse> 

```

## 它是如何工作的...

服务器端与第一章中描述的*设置简单的端点映射用于 Web 服务*的配方相同，*构建 SOAP Web 服务*。在客户端，`WebServiceTemplate`和`OrderServiceClientTest.java`与*在 HTTP 传输上创建 Web 服务客户端*的配方中描述的相同。

唯一的区别是服务器应用程序上下文文件。`spring-servlet.xml`中的`transformingInterceptor` bean 使用`oldRequests.xslt`和`oldResponse.xslt`分别将旧的请求 XML 消息转换为服务器的更新版本，反之亦然：

```java
. <bean class="org.springframework.ws.server.endpoint.mapping.SimpleMethodEndpointMapping">
<property name="endpoints">
<ref bean="OrderServiceEndpoint" />
</property>
<property name="methodPrefix" value="handle"></property>
<property name="interceptors">
<list>
<bean
class="org.springframework.ws.server.endpoint.interceptor.PayloadLoggingInterceptor">
<property name="logRequest" value="true" />
<property name="logResponse" value="true" />
</bean>
<bean id="transformingInterceptor"
class="org.springframework.ws.server.endpoint.interceptor.PayloadTransformingInterceptor">
<property name="requestXslt" value="/WEB-INF/oldRequests.xslt" />
<property name="responseXslt" value="/WEB-INF/oldResponse.xslt" />
</bean>
</list>
</property>
</bean>

```

## 另请参阅

在第一章中讨论的*设置简单的端点映射用于 Web 服务*的配方，*构建 SOAP Web 服务*。

使用 Spring JUnit 对 Web 服务进行单元测试。


# 第三章：测试和监视 Web 服务

在本章中，我们将涵盖：

+   使用 Spring-JUnit 支持进行集成测试

+   使用`MockWebServiceClient`进行服务器端集成测试

+   使用`MockWebServiceServer`进行客户端集成测试

+   使用 TCPMon 监视 Web 服务的 TCP 消息

+   使用 soapUI 监视和负载/功能测试 Web 服务

# 介绍

新的软件开发策略需要全面的测试，以实现软件开发过程中的质量。测试驱动设计（TDD）是开发过程的一种演进方法，它结合了测试优先的开发过程和重构。在测试优先的开发过程中，您在编写完整的生产代码之前编写测试以简化测试。这种测试包括单元测试和集成测试。

Spring 提供了使用 spring-test 包的集成测试功能支持。这些功能包括依赖注入和在测试环境中加载应用程序上下文。

编写一个使用模拟框架（如 EasyMock 和 JMock）测试 Web 服务的单元测试非常容易。但是，它不测试 XML 消息的内容，因此不模拟测试的真实生产环境。

Spring Web-Services 2.0 提供了创建服务器端集成测试以及客户端集成测试的功能。使用这些集成测试功能，可以在不部署在服务器上时测试 SOAP 服务，当测试服务器端时，而在测试客户端时无需设置服务器。

在第一个配方中，我们将讨论如何使用 Spring 框架进行集成测试。在接下来的两个配方中，详细介绍了 Spring-WS 2.0 的集成测试的新功能。在最后两个配方中，介绍了使用 soapUI 和 TCPMon 等工具监视和测试 Web 服务。

# 使用 Spring-JUnit 支持进行集成测试

Spring 支持使用`org.springframework.test`包中的类进行集成测试。这些功能使用生产应用程序上下文或任何用于测试目的的自定义应用程序上下文在测试用例中提供依赖注入。本教程介绍了如何使用具有功能的 JUnit 测试用例，`spring-test.jar`，JUnit 4.7 和 XMLUnit 1.1。

### 注意

请注意，要运行集成测试，我们需要启动服务器。但是，在接下来的两个配方中，我们将使用 Spring-WS 2.0 的集成测试的新功能，无需启动服务器。

## 准备工作

在本配方中，项目名称为`LiveRestaurant_R-3.1`（服务器端 Web 服务），具有以下 Maven 依赖项：

+   `spring-ws-core-2.0.1.RELEASE.jar`

+   `log4j-1.2.9.jar`

以下是`LiveRestaurant_R-3.1-Client`（客户端 Web 服务）的 Maven 依赖项：

+   `spring-ws-core-2.0.1.RELEASE.jar`

+   `spring-test-3.0.5.RELEASE.jar`

+   `log4j-1.2.9.jar`

+   `junit-4.7.jar`

+   `xmlunit-1.1.jar`

## 如何做...

本教程使用了在第一章中讨论的*通过注释有效负载根设置端点*配方中使用的项目，*构建 SOAP Web 服务*，作为服务器端项目。以下是客户端设置：

1.  创建一个调用`src/test`中的`WebServiceTemplate`的 Web 服务服务器的测试类。

1.  在`applicationContext.xml`中配置`WebServiceTemplate`。

1.  从文件夹`Liverestaurant_R-3.1`运行以下命令：

```java
mvn clean package tomcat:run 

```

1.  打开一个新的命令窗口到`Liverestaurant_R-3.1-Client`并运行以下命令：

```java
mvn clean package. 

```

+   以下是客户端输出：

```java
.................
-------------------------------------------------------
T E S T S
-------------------------------------------------------
Running com.packtpub.liverestaurant.client.OrderServiceClientTest
............................
Tests run: 2, Failures: 0, Errors: 0, Skipped: 0, Time elapsed: 1.633 sec
Results :
Tests run: 2, Failures: 0, Errors: 0, Skipped: 0 

```

## 它是如何工作的...

服务器端项目设置了一个 Web 服务服务器，客户端项目运行集成测试，并向服务器发送预定义的请求消息，并从服务器获取响应消息。然后将服务器响应与预期响应进行比较。Web 服务的设置和 Web 服务的客户端已在前两章中详细介绍。这里只详细介绍测试框架。

在`OrderServiceClientTest.java`中，方法`setUpBefore()`将首先被调用以初始化数据（因为它被`@before`注释），然后将调用由`@Test`注释的测试方法（`testCancelOrderRequest`或`testPalceOrderRequest`），最后，方法`setUpAfter()`将被调用以释放资源（因为它被`@after`注释）。

当您运行`mvn clean package`时，Maven 会构建并运行`src/test/java`文件夹中的任何测试类。因此，在`OrderServiceClientTest.java`中，首先将加载测试应用程序上下文。在应用程序上下文中，只需要`WebServiceTemplate`的配置：

```java
<bean id="messageFactory" class="org.springframework.ws.soap.saaj.SaajSoapMessageFactory" />
<bean id="webServiceTemplate" class="org.springframework.ws.client.core.WebServiceTemplate">
<constructor-arg ref="messageFactory" />
<property name="defaultUri" value="http://localhost:8080/LiveRestaurant/spring-ws/OrderService" />
</bean>

```

在`OrderServiceClientTest.java`中，为了包含 Spring 依赖注入，并设置和运行测试，代码用一些信息进行了注释。JUnit `@RunWith`注解告诉 JUnit 使用 Spring `TestRunner`。Spring 的`@ContextConfiguration`注解告诉加载哪个应用程序上下文，并使用此上下文注入`applicationContext`和`webServiceTemplate`，这些都用`@Autowired`进行了注解：

```java
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration("/applicationContext.xml")
public class OrderServiceClientTest {
@Autowired
private WebServiceTemplate webServiceTemplate;
........

```

JUnit 中的`@Before`告诉在运行测试用例之前运行标记的方法(`setUpBefore`)。JUnit `@After`导致在执行测试用例后调用标记的方法。JUnit 中的`@Test`将标记的方法(`testCancelOrderRequest`和`testPlaceOrderRequest`)转换为 JUnit 测试方法：

```java
@After
public void setUpAfter() {
applicationContext.close();
}
@Test
public final void testPlaceOrderRequest() throws Exception {
Result result = invokeWS(placeOrderRequest);
XMLAssert.assertXMLEqual("Invalid content received", getStringFromInputStream(placeOrderResponse), result.toString());
}
@Test
public final void testCancelOrderRequest() throws Exception {
Result result = invokeWS(cancelOrderRequest);
XMLAssert.assertXMLEqual("Invalid content received", getStringFromInputStream(cancelOrderResponse), result.toString());
}
private Result invokeWS(InputStream is) {
StreamSource source = new StreamSource(is);
StringResult result = new StringResult();
webServiceTemplate.sendSourceAndReceiveToResult(source, result);
return result;
}
public String getStringFromInputStream (InputStream is)
throws IOException {
BufferedInputStream bis = new BufferedInputStream(is);
ByteArrayOutputStream buf = new ByteArrayOutputStream();
int result = bis.read();
while(result != -1) {
byte b = (byte)result;
buf.write(b);
result = bis.read();
}
return buf.toString();
}

```

请注意，对于每个测试方法，`@After`和`@Before`方法将被执行一次。`XMLAssert.assertXMLEqual`比较实际结果和预期的 XML 消息。

### 提示

在实际情况下，数据将每天动态变化。我们应该能够根据日期和数据库动态构建数据。这有助于持续集成和一段时间内的冒烟测试。

## 另请参阅

在第一章中讨论的*通过注释 payload-root 设置端点*配方，*构建 SOAP Web 服务*。

在第二章中讨论的*在 HTTP 传输上创建 Web 服务客户端*配方，*构建 SOAP Web 服务的客户端*。

# 使用 MockWebServiceClient 进行服务器端集成测试

编写使用 EasyMock 和 JMock 等模拟框架测试 Web 服务的单元测试非常容易。但是，它不测试 XML 消息的内容，因此它不模拟测试的真实生产环境（因为这些模拟对象模拟软件的一部分，而这部分软件没有运行，这既不是单元测试也不是集成测试）。

Spring Web-Services 2.0 提供了创建服务器端集成测试的功能。使用这个功能，可以非常简单地测试 SOAP 服务，而无需在服务器上部署，也无需在 Spring 配置文件中配置测试客户端。

服务器端集成测试的主要类是`org.springframework.ws.test.server`包中的`MockWebServiceClient`。这个类创建一个请求消息，将请求发送到服务，并获取响应消息。客户端将响应与预期消息进行比较。

## 准备工作

在这个配方中，项目的名称是`LiveRestaurant_R-3.2`（作为包含使用`MockWebServiceClient`的测试用例的服务器端 Web 服务），并具有以下 Maven 依赖项：

+   `spring-ws-core-2.0.1.RELEASE.jar`

+   `spring-ws-test-2.0.1.RELEASE.jar`

+   `spring-test-3.0.5.RELEASE.jar`

+   `log4j-1.2.9.jar`

+   `junit-4.7.jar`

## 如何做...

这个配方使用了来自*通过注释 payload-root 设置端点*的项目，该项目在第一章中讨论，*构建 SOAP Web 服务*，作为服务器端项目。以下是测试用例的设置：

1.  在`pom.xml`中包含以下数据：

```java
<testResources>
<testResource>
<directory>src/main/webapp</directory>
</testResource>
</testResources>
</build>

```

1.  在`src/test/java`文件夹中添加测试用例类。

1.  对`Liverestaurant_R-3.2`运行以下命令：

```java
mvn clean package 

```

+   以下是服务器端的输出：

```java
..................
-------------------------------------------------------
T E S T S
-------------------------------------------------------
Running com.packtpub.liverestaurant.service.test.OrderServiceServerSideIntegrationTest
l.........
Tests run: 2, Failures: 0, Errors: 0, Skipped: 0, Time elapsed: 1.047 sec
Results :
Tests run: 2, Failures: 0, Errors: 0, Skipped: 0 

```

## 它是如何工作的...

在类`OrderServiceServerSideIntegrationTest.java`中，注释和单元测试材料与配方*使用 Spring-JUnit 支持进行集成测试*中使用的相同。唯一的区别是我们不在这里设置服务器。相反，我们在测试用例类中加载服务器应用上下文：

```java
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration("/WEB-INF/spring-ws-servlet.xml")
public class OrderServiceServerSideIntegrationTest {
.......................

```

在`@Before`方法中，测试用例类初始化了客户端模拟对象和 XML 消息：

```java
@Before
public void createClient() {
wsMockClient = MockWebServiceClient.createClient(applicationContext);
placeOrderRequest = new OrderServiceServerSideIntegrationTest().getClass().getResourceAsStream("placeOrderRequest.xml");
cancelOrderRequest = new OrderServiceServerSideIntegrationTest().getClass().getResourceAsStream("cancelOrderRequest.xml");
placeOrderResponse = new OrderServiceServerSideIntegrationTest().getClass().getResourceAsStream("placeOrderResponse.xml");
cancelOrderRsponse = new OrderServiceServerSideIntegrationTest().getClass().getResourceAsStream("cancelOrderResponse.xml");
}

```

然后，它发送一条消息并接收响应。然后比较预期的响应和实际的响应：

```java
@After
public void setUpAfterClass() {
applicationContext.close();
}
@Test
public final void testPlaceOrderRequest() throws Exception {
Source requestPayload = new StreamSource(placeOrderRequest);
Source responsePayload = new StreamSource(placeOrderResponse);
wsMockClient.sendRequest(withPayload(requestPayload)).
andExpect(payload(responsePayload));
}
@Test
public final void testCancelOrderRequest() throws Exception {
Source requestPayload = new StreamSource(cancelOrderRequest);
Source responsePayload = new StreamSource(cancelOrderRsponse);
wsMockClient.sendRequest(withPayload(requestPayload)).
andExpect(payload(responsePayload));
}

```

在方法`createClient()中，MockWebServiceClient.createClient(applicationContext)`创建了客户端模拟对象（`wsMockClient`）的实例。在测试用例方法`(testCancelOrderRequest, testPlaceOrderRequest)`中，使用代码`wsMockClient.sendRequest(withPayload(requestPayload)).andExpect(payload(responsePayload))`，模拟客户端发送 XML 消息并将响应（来自服务器端点）与预期响应进行比较（客户端模拟知道来自应用上下文文件的服务器端点，当它向服务器发送请求时，调用端点方法并获取响应）。

## 另请参阅

在本章中讨论的配方*使用 Spring-JUnit 支持进行集成测试*和*使用 MockWebServiceServer 进行客户端集成测试*。

在第一章中讨论的配方*通过注释 payload-root 设置端点*，*构建 SOAP Web 服务*。

# 使用 MockWebServiceServer 进行客户端集成测试

编写一个使用模拟框架测试 Web 服务客户端的客户端单元测试非常容易。但是，它不会测试通过线路发送的 XML 消息的内容，特别是当模拟整个客户端类时。

Spring Web 服务 2.0 提供了创建客户端集成测试的功能。使用这个功能，很容易测试 SOAP 服务的客户端而不需要设置服务器。

客户端集成测试的主要类是`org.springframework.ws.test.server`包中的`MockWebServiceServer`。这个类接受来自客户端的请求消息，对其进行验证，然后将响应消息返回给客户端。

由于这个项目是使用`MockWebServiceServer`进行客户端测试集成，它不需要任何外部服务器端 Web 服务。

## 准备就绪

在这个配方中，项目的名称是`LiveRestaurant_R-3.3-Client`（作为客户端项目，包括使用`MockServiceServer`作为服务器的测试用例），并且具有以下 Maven 依赖项：

+   `spring-ws-core-2.0.1.RELEASE.jar`

+   `spring-ws-test-2.0.1.RELEASE.jar`

+   `spring-test-3.0.5.RELEASE.jar`

+   `log4j-1.2.9.jar`

+   `junit-4.7.jar`

## 如何做...

这个配方使用了来自*在 HTTP 传输上创建 Web 服务客户端*的客户端项目，该项目在第二章中讨论，*构建 SOAP Web 服务的客户端*。以下是测试用例的设置：

1.  在`src/test`下创建一个测试用例类。

1.  创建一个扩展`WebServiceGatewaySupport`的类来发送/接收消息。

1.  对`Liverestaurant_R-3.3-Client`运行以下命令：

```java
mvn clean package 

```

+   以下是客户端输出：

```java
**************************
-------------------------------------------------------
T E S T S
-------------------------------------------------------
Running com.packtpub.liverestaurant.client.test.ClientSideIntegrationTest
........
Tests run: 3, Failures: 0, Errors: 0, Skipped: 0, Time elapsed: 0.945 sec
Results :
Tests run: 3, Failures: 0, Errors: 0, Skipped: 0 

```

## 它是如何工作的...

测试用例类`ClientSideIntegrationTest.java`中的流程如下：

1.  使用`WebServiceGatewaySupport`（扩展`WebServiceGatewaySupport`的`OrderServiceClient`）创建`MockWebServiceServer`。您还可以使用`WebServiceTemplate`或使用`ApplicationContext`创建`MockWebServiceServer`。

1.  使用`RequestMatcher`设置请求期望，并使用`ResponseCreator`返回响应。

1.  通过使用`WebServiceTemplate`进行客户端调用。

1.  调用`verify`方法以确保满足所有期望。应用程序上下文文件只是`WebServiceTemplate`和`OrderServiceClient`的配置：

```java
<bean id="client" class=" com.packtpub.liverestaurant.client.test.OrderServiceClient">
<property name="webServiceTemplate" ref="webServiceTemplate"/>
</bean>
<bean id="webServiceTemplate" class="org.springframework.ws.client.core.WebServiceTemplate">
<property name="defaultUri" value="http://www.packtpub.com/liverestaurant/OrderService/schema"/>
</bean>
</beans>

```

在`ClientSideIntegrationTest.java`中，注释和单元测试材料与*使用 Spring-JUnit 支持进行集成测试*配方中使用的相同。方法`createServer()`使用`WebServiceGatewaySupport`（`OrderServiceClient`扩展`WebServiceGatewaySupport`）创建`MockWebServiceServer`：

```java
public class OrderServiceClient extends WebServiceGatewaySupport {
public Result getStringResult(Source source) {
StringResult result = new StringResult();
getWebServiceTemplate().sendSourceAndReceiveToResult(source, result);
return result;
}
}

```

在测试中，方法`testExpectedRequestResponse, mockServer.expect`设置了预期的请求和响应（`webServiceTemplate`在`client-integration-test.xml`中以“测试模式”配置。当调用`sendSourceAndReceiveToResult`方法时，模板会在没有任何真正的 HTTP 连接的情况下虚拟调用服务器）。然后`client.getStringResult`调用`webserviceTemplate`来调用服务器（`MockWebServiceServer`）。然后，`mockServer.verify`检查返回的响应是否与预期的响应匹配：

```java
@Test
public void testExpectedRequestResponse() throws Exception {
Source requestPayload = new StringSource(getStringFromInputStream(placeOrderRequest));
Source responsePayload = new StringSource(getStringFromInputStream(placeOrderResponse));
mockServer.expect(payload(requestPayload)).andRespond(withPayload(responsePayload));
Result result = client.getStringResult(requestPayload);
XMLAssert.assertXMLEqual("Invalid content received", xmlToString(responsePayload), result.toString());
mockServer.verify();
}

```

在测试方法`testSchema`中，使用了预期请求和响应的模式，而不是使用硬编码的请求/响应。此测试可以测试请求/响应的格式是否符合预期。如下所示：

```java
. @Test
public void testSchema() throws Exception {
Resource schema=new FileSystemResource("orderService.xsd");
mockServer.expect(validPayload(schema));
client.getStringResult(new StreamSource(placeOrderRequest));
mockServer.verify();
}

```

在测试方法`testSchemaWithWrongRequest`中，使用了预期请求和响应的模式。然而，客户端试图发送无效请求，这将导致失败：

```java
@Test(expected = AssertionError.class)
public void testSchemaWithWrongRequest() throws Exception {
Resource schema=new FileSystemResource("orderService.xsd");
mockServer.expect(validPayload(schema));
client.getStringResult(new StringSource(getStringFromInputStream(cancelOrderRequestWrong)));
mockServer.verify();
}

```

## 另请参阅

本章讨论了*使用 Spring-JUnit 支持进行集成测试*的配方。

# 使用 TCPMon 监视 Web 服务的 TCP 消息

**TCPMon**是一个带有 Swing UI 的 Apache 项目，它提供了监视客户端和服务器之间传输的基于 TCP 的消息的功能。还可以使用 TCPMon 向服务器发送 SOAP 消息。

本配方介绍了如何监视 Web 服务客户端和服务器之间传递的消息。此外，它还展示了如何使用 TCPMon 发送 SOAP 消息。该配方*使用 Spring-JUnit 支持进行集成测试*用于服务器端和客户端项目。

## 准备工作

从网站[`ws.apache.org/commons/tcpmon/download.cgi`](http://ws.apache.org/commons/tcpmon/download.cgi)下载并安装 TCPMon 1.0。

## 如何操作...

监视客户端和服务器之间的消息如下：

1.  在 Windows 上使用`tcpmon.bat（Linux 上的 tcpmon.sh）`运行它。

1.  在**Listen port #**和**Target port #**字段中输入值**8081**和**8080**，然后单击**Add**选项。![如何操作...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-websvc2-cb/img/5825_03_01.jpg)

1.  更改`LiveRestaurant_R-3.1-Client`中的`applicationContext.xml`以使用**8081**端口进行`webserviceTemplate`：

```java
<bean id="messageFactory" class="org.springframework.ws.soap.saaj.SaajSoapMessageFactory" />
<bean id="webServiceTemplate" class="org.springframework.ws.client.core.WebServiceTemplate">
<constructor-arg ref="messageFactory" />
<property name="defaultUri" value="http://localhost:8081/LiveRestaurant/spring-ws/OrderService" />
</bean>

```

1.  使用以下命令从项目`LiveRestaurant_R-3.1`运行服务器：

```java
mvn clean package tomcat:run 

```

1.  从项目`LiveRestaurant_R-3.1-Client`中使用以下命令运行客户端：

```java
mvn clean package 

```

1.  转到**Port 8081**选项卡，查看请求和响应消息，如下截图所示：

![如何操作...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-websvc2-cb/img/5825_03_02.jpg)

按以下方式向服务器发送 SOAP 请求：

转到**Sender**选项卡。输入 SOAP 服务地址和 SOAP 请求消息，然后单击**Send**按钮查看响应：

![如何操作...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-websvc2-cb/img/5825_03_03.jpg)

## 工作原理...

监视客户端和 Web 服务服务器之间传输的消息是 TCPMon 的最重要用途。此外，TCPMon 还可以用作客户端向 Web 服务服务器发送消息。这是一个中间角色，显示了客户端和服务器之间传输的消息。客户端必须指向中间件而不是服务器服务。

![工作原理...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-websvc2-cb/img/5825_03_04.jpg)

第二个活动（向服务器发送 SOAP 请求）显示使用 TCPMon 向服务器发送消息，接收响应，并在 TCPMon 上显示所有这些。

## 另请参阅

本章讨论了*使用 Spring-JUnit 支持进行集成测试*的方法。

# 使用 soapUI 监控和负载/功能测试 Web 服务

soapUI 是用于测试 Web 服务的开源测试解决方案。使用用户友好的 GUI，该工具提供了创建和执行自动功能和负载测试以及监控 SOAP 消息的功能。

本方法介绍了如何使用 soapUI 监控 Web 服务的 SOAP 消息以及功能和负载测试。为了设置 Web 服务，使用了`Recipe 3.1`，*使用 Spring-JUnit 支持进行集成测试*。

## 准备工作

通过执行以下步骤开始：

1.  安装并运行 soapUI 4.0 ([`www.soapui.org/`](http://www.soapui.org/))。

1.  从文件夹`LiveRestaurant_R-3.1`运行以下命令：

```java
mvn clean package tomcat:run 

```

## 如何操作...

要运行功能测试并监控 SOAP 消息，请执行以下步骤：

1.  右键单击**Projects**节点。选择**New soapUI Project**并输入 WSDL URL 和**Project Name**。![操作步骤...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-websvc2-cb/img/5825_03_05.jpg)

1.  在导航窗格中右键单击项目名称**OrderService**。选择**Launch HTTP Monitor**并启用**Set as Global Proxy**选项。单击**OK**按钮：![操作步骤...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-websvc2-cb/img/5825_03_06.jpg)

1.  展开**OrderService**方法**(cancelOrder**和**placeOrder)**。双击**cancelOrder**。单击**Submit Request to Specific Endpoint URL**（**Request1**屏幕左上角的绿色图标）。这是此操作的输出：![操作步骤...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-websvc2-cb/img/5825_03_07.jpg)

1.  右键单击**OrderServiceSoap11** | **Generate Test Suite** | **OK**。输入**OrderServiceSoap11 TestSuite**。![操作步骤...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-websvc2-cb/img/5825_03_08.jpg)

1.  在导航窗格中双击**OrderServiceSoap11 TestSuite**。单击运行所选的**TestCases**。![操作步骤...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-websvc2-cb/img/5825_03_09.jpg)

1.  当运行测试套件时，以下是输出：

![操作步骤...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-websvc2-cb/img/5825_03_10.jpg)

进行负载测试如下：

1.  右键单击**cancelOrder**测试用例。选择**New Local Test**并输入**Load Test Name**。![操作步骤...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-websvc2-cb/img/5825_03_11.jpg)

1.  双击**Load test name**。输入**Parameter**并单击**Run Load Test**。![操作步骤...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-websvc2-cb/img/5825_03_12.jpg)

1.  以下是测试的输出：

![操作步骤...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-websvc2-cb/img/5825_03_13.jpg)

## 工作原理...

功能测试和监控 SOAP 消息：soapUI 提供三个级别的功能测试：测试套件、测试用例和测试步骤。

测试用例是从 WSDL 文件生成的单元测试，测试套件是这些单元测试的集合。测试步骤控制执行流程并验证要测试的服务的功能。例如，前面提到的**cancelOrder**测试套件中的一个测试用例可能首先测试数据库。如果有这样的订单可用，它会取消订单。

负载测试：soapUI 提供了在测试用例上运行多个线程（取决于您的计算机硬件限制）的功能。运行负载测试时，底层测试用例将在每个线程内部克隆。延迟设置让每个线程在开始之前等待，并让 Web 服务为每个线程休息。

## 另请参阅

本章讨论了*使用 Spring-JUnit 支持进行集成测试*的方法。


# 第四章：异常/SOAP 故障处理

在本章中，我们将涵盖：

+   通过将异常的消息作为 SOAP 故障字符串返回来处理服务器端异常

+   将异常类名称映射到 SOAP 故障

+   使用`@SOAPFault`对异常类进行注释

+   在 Spring-WS 中编写自己的异常解析器

# 介绍

在处理 Web 服务时生成的服务器端异常被传输为 SOAP 故障。`SOAP <Fault>`元素用于在 SOAP 消息中携带错误和状态信息。

以下代码表示 SOAP 消息中 SOAP 故障元素的一般结构：

```java
<SOAP-ENV:Fault>
<faultcode xsi:type="xsd:string">SOAFP-ENV:Client</faultcode>
<faultstring xsi:type="xsd:string">
A human readable summary of the fault
</faultstring>
<detail xsi:type="xsd:string">
Application specific error information related to the Body element
</detail>
</SOAP-ENV:Fault>

```

如果存在`Fault`元素，则必须作为`Body`元素的子元素出现。SOAP 消息中只能出现一次`Fault`元素。

Spring Web 服务提供了智能机制来处理 SOAP 故障，其易于使用的 API。在处理请求时抛出的异常由`MessageDispatcher`捕捉，并委托给应用程序上下文（XML 或注释中声明的）中声明的任何端点异常解析器。这种异常解析器基于处理机制允许开发人员在抛出特定异常时定义自定义行为（例如返回自定义的 SOAP 故障）。

本章从易于处理异常的机制开始，然后转向稍微复杂的情景。

`org.springframework.ws.server.EndpointExceptionResolver`是 Spring-WS 中服务器端异常处理的主要规范/合同。`org.springframework.ws.soap.server.endpoint.SimpleSoapExceptionResolver`是`EndpointExceptionResolver`的默认实现，可在 Spring-WS 框架中使用。如果开发人员没有明确处理，`MessageDispatcher`将使用`SimpleSoapExceptionResolver`处理服务器端异常。

本章中的示例演示了`org.springframework.ws.server.EndpointExceptionResolver`及其实现的不同用法，包括`SimpleSoapExceptionResolver`。

为了演示目的，构建 Spring-WS 的最简单的方法是使用`MessageDispatcherServlet`简化 WebService 的创建。

# 通过将异常的消息作为 SOAP 故障字符串返回来处理服务器端异常

Spring-WS 框架会自动将服务器端抛出的应用程序级别异常的描述转换为 SOAP 故障消息，并将其包含在响应消息中发送回客户端。本示例演示了捕获异常并设置有意义的消息以作为响应中的 SOAP 故障字符串发送。

## 准备就绪

在此示例中，项目的名称是`LiveRestaurant_R-4.1`（用于服务器端 Web 服务），并具有以下 Maven 依赖项：

+   `spring-ws-core-2.0.1.RELEASE.jar`

+   `log4j-1.2.9.jar`

以下是`LiveRestaurant_R-4.1-Client`（客户端 Web 服务）的 Maven 依赖项：

+   `spring-ws-core-2.0.1.RELEASE.jar`

+   `spring-test-3.0.5.RELEASE.jar`

+   `log4j-1.2.9.jar`

## 如何做...

本示例使用了*通过注释负载根设置端点*中讨论的项目，该项目在第一章中讨论了*构建 SOAP Web 服务*。以下步骤描述了如何修改端点：

1.  修改端点以在应用程序/系统错误发生时抛出异常。

1.  在 Maven 嵌入的 Tomcat 服务器中构建和部署项目。

1.  从项目的根目录在命令行窗口中运行以下命令：

```java
mvn clean package tomcat:run. 

```

1.  要测试，打开一个新的命令窗口，转到文件夹`LiveRestaurant_R-4.1-Client`，并运行以下命令：

```java
mvn clean package exec:java 

```

+   以下是服务器端控制台的输出（请注意消息中生成的`SOAP-Env:Fault`元素）：

```java
DEBUG [http-8080-1] (MessageDispatcher.java:167) - Received request.....
<SOAP-ENV:Fault><faultcode>SOAP-ENV:Server</faultcode>
<faultstring xml:lang="en">Reference number is not provided!</faultstring>
</SOAP-ENV:Fault>
For request
...
<tns:placeOrderRequest >
......
</tns:placeOrderRequest> 

```

+   以下是客户端控制台的输出：

```java
Received response ....
<SOAP-ENV:Fault>
<faultcode>SOAP-ENV:Server</faultcode>
<faultstring xml:lang="en">Reference number is not provided!</faultstring>
</SOAP-ENV:Fault>
... for request....
<tns:placeOrderRequest >
.........
</tns:placeOrderRequest>
....
[WARNING]
java.lang.reflect.InvocationTargetException
at sun.reflect.NativeMethodAccessorImpl.invoke0(Native Method)
.........
at org.codehaus.mojo.exec.ExecJavaMojo$1.run(ExecJavaMojo.java:297)
at java.lang.Thread.run(Thread.java:619)
Caused by: org.springframework.ws.soap.client.SoapFaultClientException: Reference number is not provided!
........... 

```

## 它是如何工作的...

在端点（`OrderServiceEndpoint`）的处理程序方法（`handlePlaceOrderRequest`）中，由于传入消息不包含参考编号，因此会抛出一个简单的`RuntimeException`。这象征着任何意外的运行时异常。为了澄清，一个有意义的错误描述**（未提供参考编号！）**被传递给异常：

```java
@PayloadRoot(localPart = "placeOrderRequest", namespace = SERVICE_NS)
public @ResponsePayload
Source handlePlaceOrderRequest(@RequestPayload Source source) throws Exception {
//extract data from input parameter
String fName="John";
String lName="Smith";
String refNumber="";
if(refNumber.length()>0)
return new StringSource(
"<tns:placeOrderResponse xmlns:tns=\"http://www.packtpub.com/liverestaurant/OrderService/schema\"><tns:refNumber>"+orderService.placeOrder(fName, lName, refNumber)+"</tns:refNumber></tns:placeOrderResponse>");
else
throw new RuntimeException("Reference number is not provided!");
}

```

您可以看到，对于这个项目没有配置显式的异常解析器。当没有配置异常解析器时，Spring-WS 框架的智能`MessageDispatcher`会分配一个默认的异常解析器来处理任何异常。它使用`SimpleSoapExceptionResolver`来处理这种情况。

`SimpleSoapExceptionResolver`通过执行以下操作解决异常：

+   将异常记录到日志记录器（控制台，日志文件）

+   生成带有异常消息作为故障字符串的 SOAP 故障消息，并作为响应消息的一部分返回

当我们在客户端检查响应消息时，可以看到在方法`OrderServiceEndpoint.handlePlaceOrderRequest`中设置的确切异常消息（未提供参考**编号！**）作为响应消息中的 SOAP 故障字符串返回。

有趣的是，开发人员不需要做任何处理或发送 SOAP 故障消息，除了抛出一个带有有意义的消息的异常。

## 另请参阅

在第一章中讨论的配方*通过注释有效负载根设置端点*，*构建 SOAP Web 服务*。

在第二章中讨论的配方*在 HTTP 传输上创建 Web 服务客户端*，*构建 SOAP Web 服务的客户端*。

# 将异常类名称映射到 SOAP 故障

Spring-WS 框架允许在 bean 配置文件`spring-ws-servlet.xml`中轻松定制 SOAP 故障消息。它使用一个特殊的异常解析器`SoapFaultMappingExceptionResolver`来完成这项工作。我们可以将异常类映射到相应的 SOAP 故障，以便生成并返回给客户端。

## 准备工作

在这个配方中，项目的名称是`LiveRestaurant_R-4.2`（用于服务器端 Web 服务），具有以下 Maven 依赖项：

+   `spring-ws-core-2.0.1.RELEASE.jar`

+   `log4j-1.2.9.jar`

以下是`LiveRestaurant_R-4.2-Client`（客户端 Web 服务）的 Maven 依赖项：

+   `spring-ws-core-2.0.1.RELEASE.jar`

+   `spring-test-3.0.5.RELEASE.jar`

+   `log4j-1.2.9.jar`

## 如何做...

这个配方使用了*通过注释有效负载根设置端点*中的项目，在第一章中讨论，*构建 SOAP Web 服务*。

1.  创建一个自定义异常类`DataOutOfRangeException.java`。

1.  修改`OrderServiceEndpoint`以抛出`DataOutOfRangeException`。

1.  在`spring-ws-servlet.xml`中注册`SoapFaultMappingExceptionResolver`。

1.  在 Maven 嵌入的 Tomcat 服务器中构建和部署项目。

1.  从项目的根目录，在命令行窗口中运行以下命令：

```java
mvn clean package tomcat:run 

```

1.  要测试，打开一个新的命令窗口，转到文件夹`LiveRestaurant_R-4.2-Client`，并运行以下命令：

```java
mvn clean package exec:java 

```

+   以下是服务器端控制台的输出（请注意，消息中生成了`SOAP-Env:Fault`元素）：

```java
DEBUG [http-8080-1] (MessageDispatcher.java:177) -
Sent response
...
<SOAP-ENV:Fault>
<faultcode>SOAP-ENV:Server</faultcode>
<faultstring xml:lang="en">such a data is out of range!</faultstring>
</SOAP-ENV:Fault>
</SOAP-ENV:Body>
... for request
<tns:placeOrderRequest >
.......
</tns:placeOrderRequest> 

```

+   以下是客户端控制台的输出：

```java
Received response...
<SOAP-ENV:Fault>
<faultcode>SOAP-ENV:Server</faultcode>
<faultstring xml:lang="en">such a data is out of range!</faultstring>
</SOAP-ENV:Fault>
......
for request....
<tns:placeOrderRequest >
.......
</tns:placeOrderRequest>
.....
[WARNING]
java.lang.reflect.InvocationTargetException
.........
Caused by: org.springframework.ws.soap.client.SoapFaultClientException: such a data is out of range!
....... 

```

## 工作原理...

在前面的代码中，`OrderServiceEndpoint.placeOrderRequest`方法抛出一个自定义异常`DataOutOfRangeException`，它象征着典型的服务器端异常：

```java
@PayloadRoot(localPart = "placeOrderRequest", namespace = SERVICE_NS)
public @ResponsePayload
Source handlePlaceOrderRequest(@RequestPayload Source source) throws Exception {
//extract data from input parameter
String fName="John";
String lName="Smith";
String refNumber="123456789";
if(refNumber.length()<7)
return new StringSource(
"<tns:placeOrderResponse xmlns:tns=\"http://www.packtpub.com/liverestaurant/OrderService/schema\"><tns:refNumber>"+orderService.placeOrder(fName, lName, refNumber)+"</tns:refNumber></tns:placeOrderResponse>");
else
throw new DataOutOfRangeException("RefNumber is out of range");
}

```

`MessageDispatcher`捕获了这个异常，并将其委托给配置的异常解析器。在这个项目中，使用了`SoapFaultMappingExceptionResolver`，这是一种特殊的解析器，允许在配置文件中将异常类与自定义消息进行映射。在这个例子中，使用了不同的消息来映射`DataOutOfRangeException`。它充当拦截器，将 SOAP 故障消息转换为以下映射中给定的内容：

```java
<bean id="exceptionResolver"
class="org.springframework.ws.soap.server.endpoint.SoapFaultMappingExceptionResolver">
<property name="defaultFault" value="SERVER" />
<property name="exceptionMappings">
<value>
com.packtpub.liverestaurant.service.exception.DataOutOfRangeException=SERVER,
such a data is out of range!
</value>
</property>
</bean>

```

生成的 SOAP 故障消息在服务器端和客户端控制台屏幕上都有记录。它显示了映射的 SOAP 故障消息，而不是`DataOutOfRangeException`类最初抛出的内容。

## 还有更多...

这个强大的功能可以将异常与 SOAP 故障字符串进行映射，非常有用，可以将 SOAP 故障管理外部化，不需要修改代码并重新构建。此外，如果设计得当，`spring-ws.xml`文件中的配置（SOAP 故障映射）可以作为所有可能的 SOAP 故障消息的单一参考点，可以轻松维护。

### 提示

这是 B2B 应用的一个很好的解决方案。不适用于 B2C，因为需要支持多种语言。一般来说，最好的方法是通过在数据库中配置消息。这样，我们可以在运行时更改和修复它们。在 XML 中配置的缺点是需要重新启动。在实时情况下，一个应用在 30 台服务器上运行。部署和重新启动是痛苦的过程。

## 另请参阅

在第一章中讨论的*通过注释有效负载根设置端点*的配方，*构建 SOAP Web 服务*。

在第二章中讨论的*在 HTTP 传输上创建 Web 服务客户端*配方，*构建 SOAP Web 服务的客户端*

在本章中讨论的*通过将异常消息作为 SOAP 故障字符串返回来处理服务器端异常*的配方。

# 使用@SOAPFault 对异常类进行注释

Spring-WS 框架允许将应用程序异常注释为 SOAP 故障消息，并在异常类本身中进行轻松定制。它使用一个特殊的异常解析器`SoapFaultAnnotationExceptionResolver`来完成这项工作。可以通过在类中进行注释来定制 SOAP 故障字符串和故障代码。

## 准备工作

在这个配方中，项目的名称是`LiveRestaurant_R-4.3`（服务器端 Web 服务），并且具有以下 Maven 依赖项：

+   `spring-ws-core-2.0.1.RELEASE.jar`

+   `log4j-1.2.9.jar`

以下是`LiveRestaurant_R-4.3-Client`（客户端 Web 服务）的 Maven 依赖项：

+   `spring-ws-core-2.0.1.RELEASE.jar`

+   `spring-test-3.0.5.RELEASE.jar`

+   `log4j-1.2.9.jar`

+   `junit-4.7.jar`

+   `xmlunit-1.1.jar`

## 如何做...

这个配方使用了第一章中讨论的*通过注释有效负载根设置端点*的项目作为服务器端，以及第三章中讨论的*如何使用 Spring-Junit 支持集成测试*的配方作为客户端。

1.  创建一个自定义异常类（`InvalidOrdeRequestException.java`），并用`@SoapFault`进行注释。

1.  创建一个自定义异常类（`OrderProcessingFailedException.java`），并用`@SoapFault`进行注释。

1.  修改`Endpoint（OrderServiceEndpoint）`以抛出`InvalidOrderRequestException`和`OrderProcessingFailedException`。

1.  在服务器应用程序上下文文件（`spring-ws-servlet.xml`）中注册`SoapFaultAnnotationExceptionResolver`。

1.  在 Maven 嵌入的 Tomcat 服务器中构建和部署项目。

1.  从项目的根目录，在命令行窗口中运行以下命令：

```java
mvn clean package tomcat:run. 

```

1.  为了测试，打开一个新的命令窗口，进入文件夹`LiveRestaurant_R-4.3-Client`，并运行以下命令：

```java
mvn clean package 

```

+   以下是客户端控制台的输出（请注意消息中生成的 SOAP-Env:Fault 元素）：

```java
DEBUG [main] (WebServiceTemplate.java:632) -
Received response
.....
<SOAP-ENV:Fault><faultcode>SOAP-ENV:Client</faultcode>
<faultstring xml:lang="en">Invalid Order Request: Request message incomplete</faultstring>
</SOAP-ENV>
for request....
<tns:placeOrderRequest ....>
....
</tns:placeOrderRequest>
....................
Received response ...
<SOAP-ENV:Fault><faultcode>SOAP-ENV:Server</faultcode>
<faultstring xml:lang="en">Database server under maintenance, please try after some time.</faultstring>
</SOAP-ENV:Fault>...
for request ...
<tns:cancelOrderRequest ..>
<tns:refNumber>9999</tns:refNumber>
</tns:cancelOrderRequest>
...
Tests run: 2, Failures: 0, Errors: 2, Skipped: 0, Time elapsed: 0.874 sec <<< FAILURE! 

```

## 它是如何工作的...

在端点的方法中，`OrderServiceMethodEndoint.processOrder`（`placeOrderRequest`和`cancelOrderRequest`），抛出自定义异常（`ProcessingFailedException`和`InvalidOrderRequestException`），代表典型的服务器端/客户端异常：

```java
@PayloadRoot(localPart = "placeOrderRequest", namespace = SERVICE_NS)
public @ResponsePayload
Source handlePlaceOrderRequest(@RequestPayload Source source) throws Exception {
//extract data from input parameter
String fName="John";
String lName="Smith";
String refNumber="";
if(refNumber.length()>0)
return new StringSource(
"<tns:placeOrderResponse xmlns:tns=\"http://www.packtpub.com/liverestaurant/OrderService/schema\"><tns:refNumber>"+orderService.placeOrder(fName, lName, refNumber)+"</tns:refNumber></tns:placeOrderResponse>");
else
throw new InvalidOrderRequestException("Reference number is not provided!");
}
@PayloadRoot(localPart = "cancelOrderRequest", namespace = SERVICE_NS)
public @ResponsePayload
Source handleCancelOrderRequest(@RequestPayload Source source) throws Exception {
//extract data from input parameter
boolean cancelled =true ;
if( isDataBaseServerRunning())
return new StringSource(
"<tns:cancelOrderResponse xmlns:tns=\"http://www.packtpub.com/liverestaurant/OrderService/schema\"><cancelled>"+(cancelled?"true":"false")+"</cancelled></tns:cancelOrderResponse>");
else
throw new ProcessingFailedException("Database server is down!");
}
private boolean isDataBaseServerRunning(){
return false;
}

```

这个异常被`MessageDispatcher`捕获并委托给配置的异常解析器。在这个项目中，使用了`SoapFaultAnnotationExceptionResolver`，这是一种特殊的解析器，允许异常类在类中用自定义的故障代码和故障字符串进行注释。`SoapFaultAnnotationExceptionResolver`被配置为在`spring-ws-servlet.xml`中使用，因此任何异常处理都会在运行时由`MessageDispatcherServlet`委托给它：

```java
<bean id="exceptionResolver"
class="org.springframework.ws.soap.server.endpoint.SoapFaultAnnotationExceptionResolver">
<property name="defaultFault" value="SERVER" />
</bean>

```

`ProcessingFailedException`代表服务器端系统异常（faultCode = FaultCode.SERVER）：

```java
@SoapFault(faultCode = FaultCode.SERVER,
faultStringOrReason = "Database server under maintenance, please try after some time.")
public class ProcessingFailedException extends Exception {
public ProcessingFailedException(String message) {
super(message);
}
}

```

`InvalidOrderRequestException`代表客户端业务逻辑异常（faultCode `= FaultCode.CLIENT）：`

```java
@SoapFault(faultCode = FaultCode.CLIENT,
faultStringOrReason = "Invalid Order Request: Request message incomplete")
public class InvalidOrderRequestException extends Exception {
public InvalidOrderRequestException(String message) {
super(message);
}
}

```

您可以看到，带注释的`faultStringOrReason`被生成为 SOAP 故障，并传输回客户端。生成的 SOAP 故障消息在服务器端和客户端控制台屏幕上都被记录，显示了带注释的 SOAP 故障消息，而不是在`Endpoint`类中最初抛出的内容。

## 还有更多...

`@SoapFault`注释的`faultCode`属性具有以下可能的枚举值：

+   `CLIENT`

+   `CUSTOM`

+   `RECEIVER`

+   `SENDER`

从枚举列表中选择一个指示调度程序应生成哪种 SOAP 故障以及其具体内容。根据前面的选择，依赖属性变得强制性。

例如，如果为`faultCode`选择了`FaultCode.CUSTOM`，则必须使用`customFaultCode`字符串属性，而不是`faultStringOrReason`，如本配方的代码片段中所示。用于`customFaultCode`的格式是`QName.toString()`的格式，即`"{" + Namespace URI + "}" + local part`，其中命名空间是可选的。请注意，自定义故障代码仅在 SOAP 1.1 上受支持。

`@SoaPFault`注释还有一个属性，即 locale，它决定了 SOAP 故障消息的语言。默认语言环境是英语。

### 注意

在一般实践中，我们使用错误代码而不是错误消息。在客户端使用映射信息进行映射。这样可以避免对网络的任何负载，并且不会出现多语言支持的问题。

## 另请参阅

在第一章中讨论的*通过注释有效负载根设置端点*的配方，*构建 SOAP Web 服务。*

在第三章中讨论的*如何使用 Spring-JUnit 支持集成测试*的配方，*测试和监控 Web 服务。*

在本章中讨论的*将异常类名映射到 SOAP 故障*的配方。

# 在 Spring-WS 中编写自己的异常解析器

Spring-WS 框架提供了默认机制来处理异常，使用标准异常解析器，它允许开发人员通过构建自己的异常解析器来以自己的方式处理异常。SOAP 故障可以定制以在其自己的格式中添加自定义细节，并传输回客户端。

本示例说明了一个自定义异常解析器，它将异常堆栈跟踪添加到 SOAP 响应的 SOAP 故障详细元素中，以便客户端获取服务器端异常的完整堆栈跟踪，对于某些情况非常有用。这个自定义异常解析器已经具有注释的功能，就像前面的示例一样。

## 准备就绪

在本配方中，项目的名称是`LiveRestaurant_R-4.4`（用于服务器端 Web 服务），具有以下 Maven 依赖项：

+   `spring-ws-core-2.0.1.RELEASE.jar`

+   `log4j-1.2.9.jar`

`LiveRestaurant_R-4.4-Client`（用于客户端）具有以下 Maven 依赖项：

+   `spring-ws-core-2.0.1.RELEASE.jar`

+   `spring-test-3.0.5.RELEASE.jar`

+   `log4j-1.2.9.jar`

+   `junit-4.7.jar`

+   `xmlunit-1.1.jar`

## 如何做...

本配方使用了*通过注释 payload-root 设置端点*中讨论的项目，第一章，*构建 SOAP Web 服务*。

1.  创建一个自定义异常解析器`DetailedSoapFaultExceptionResolver`，扩展`SoapFaultAnnotationExceptionResolver`。

1.  在`spring-ws-servlet.xml`中注册`DetailedSoapFaultExceptionResolver`。

1.  在 Maven 嵌入的 Tomcat 服务器中构建和部署项目。

1.  从项目的根目录，在命令行窗口中运行以下命令：

```java
mvn clean package tomcat:run. 

```

1.  要进行测试，请打开一个新的命令窗口，转到文件夹`LiveRestaurant_R-4.4-Client`，并运行以下命令：

```java
mvn clean package exec:java 

```

+   以下是服务器端控制台的输出（请注意在消息中生成的`SOAP-Env:Fault`元素）：

```java
DEBUG [http-8080-1] (MessageDispatcher.java:167) - Received request.....
<tns:placeOrderRequest >
......
</tns:placeOrderRequest></SOAP-ENV:Body>...
DEBUG [http-8080-1] (MessageDispatcher.java:177) - Sent response
...
<SOAP-ENV:Fault><faultcode>SOAP-ENV:Client</faultcode>
<faultstring xml:lang="en">Invalid Order Request: Request message incomplete</faultstring
><detail>
<stack-trace >
at com.packtpub.liverestaurant.service.endpoint.OrderSeviceEndpoint.handlePlaceOrderRequest(OrderSeviceEndpoint.java:43)
at sun.reflect.NativeMethodAccessorImpl.invoke0(Native Method)
at sun.reflect.NativeMethodAccessorImpl.invoke(NativeMethodAccessorImpl.java:39)
at sun.reflect.DelegatingMethodAccessorImpl.invoke(DelegatingMethodAccessorImpl.java:25)
at java.lang.reflect.Method.invoke(Method.java:597)
at org.springframework.ws.server.endpoint.MethodEndpoint.invoke(MethodEndpoint.java:132)
at org.springframework.ws.server.endpoint.adapter.DefaultMethodEndpointAdapter.invokeInternal(DefaultMethodEndpointAdapter.java:229)
at org.springframework.ws.server.endpoint.adapter.AbstractMethodEndpointAdapter.invoke(AbstractMethodEndpointAdapter.java:53)
at org.springframework.ws.server.MessageDispatcher.dispatch(MessageDispatcher.java:230)
....... 
</stack-trace></detail></SOAP-ENV:Fault>

```

## 工作原理...

在上述代码中，我们的自定义异常解析器`DetailedSoapFaultExceptionResolver`是`SoapFaultAnnotationExceptionResolver`的子类，覆盖了方法`custmizeFault()`，将异常堆栈跟踪添加到 SOAP 故障详细元素中。方法`stackTraceToString()`从给定的异常返回异常堆栈跟踪，并用于将堆栈跟踪设置为响应消息的 SOAP 故障的详细元素。

## 还有更多...

有许多不同的创建自定义异常解析器的方法。不仅可以继承`SoapFaultAnnotationExceptionResolver`来实现这一目的。任何`org.springframework.ws.server.EndpointExceptionResolver`的实现都可以适当配置为用作异常解析器。开发人员可以从 Spring-WS API 中提供的一组非常方便的`EndpointExceptionResolver`实现中进行选择，利用这些实现的功能。

自定义这些类的位置是方法`customizeFault`。可以通过覆盖方法`customizeFault`来自定义 SOAP 故障。查看包`org.springframework.ws.soap.server.endpoint`，以获取适合您要求的现成异常解析器。

如果需要开发一个与当前可用实现不符的专门自定义异常解析器，则`AbstractSoapFaultDefinitionExceptionResolver`将是一个理想的起点，因为它已经实现了一些任何异常解析器都需要的非常常见和基本功能。开发人员只需实现抽象方法`resolveExceptionInternal()`，以满足特定需求。

需要注意的是，应该指示`MessageDispatcherServlet`考虑使用的解析器，可以通过在`spring-ws-servlet.xml`中注册或在异常类中进行注释（除了在`spring-ws-servlet.xml`中注册）。

## 另请参阅

本配方*通过注释 payload-root 设置端点*中讨论的项目，第一章，*构建 SOAP Web 服务*。

本章讨论的配方*使用@SOAP fault 注释异常类*。
