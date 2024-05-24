# Java 12 编程学习手册（七）

> 原文：[Learn Java 12 Programming ](https://libgen.rs/book/index.php?md5=2D05FE7A99FD37AE2178F1DD99C27887)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 十六、微服务

在本章中，您将了解什么是微服务，它们与其他架构样式的区别，以及现有的微服务框架如何支持消息驱动架构。我们还将帮助您决定微服务的大小，并讨论服务大小是否对将其标识为微服务起到任何作用。在本章结束时，您将了解如何构建微服务，并将它们用作创建反应式系统的基础组件。我们将通过使用 Vert.x 工具箱构建的小型反应式系统的详细代码演示来支持讨论。

本章将讨论以下主题：

*   什么是微服务？
*   微服务的大小
*   微服务之间的通信方式
*   微服务反应式系统的一个例子

# 什么是微服务？

随着处理负载的不断增加，解决这个问题的传统方法是添加更多具有相同部署的`.ear`或`.war`文件的服务器，然后将它们连接到一个集群中。这样，故障服务器可以自动替换为另一个服务器，系统性能不会下降。支持所有集群服务器的数据库通常也是集群的

然而，增加集群服务器的数量对于可伸缩性来说是一个过于粗粒度的解决方案，特别是当处理瓶颈仅局限于应用中运行的许多过程中的一个时。想象一下，一个特定的 CPU 或 I/O 密集型进程会降低整个应用的速度；添加另一个服务器只是为了缓解应用的一个部分的问题，可能会带来太多的开销

减少开销的一种方法是将应用分为三层：前端（或 Web 层）、中间层（或应用层）和后端（或后端层）。每一层都可以使用自己的服务器集群独立部署，这样每一层都可以水平增长并保持独立于其他层。这样的解决方案使得可伸缩性更加灵活；然而，与此同时，这使得部署过程复杂化，因为需要处理更多的可部署单元。

另一种保证每一层顺利部署的方法是一次在一台服务器上部署新代码，特别是在设计和实现新代码时考虑到了向后兼容性。这种方法对于前端和中间层都很好，但是对于后端可能没有那么顺利。此外，部署过程中的意外中断是由人为错误、代码缺陷、纯事故或所有这些因素的组合造成的，因此，很容易理解为什么很少有人期待在生产过程中部署一个主要版本。

然而，将应用划分为多个层可能仍然过于粗糙。在这种情况下，应用的一些关键部分，特别是那些需要比其他部分更大扩展性的部分，可以部署在它们自己的服务器集群中，并且只需向系统的其他部分提供*服务*。

事实上，**面向服务架构**（**SOA**）就是这样诞生的。当独立部署的服务不仅通过它们对可伸缩性的需求，而且通过它们中的代码更改的频率来确定时，增加可部署单元的数量所引起的复杂性被部分抵消。在设计过程中尽早识别这一点可以简化部署，因为与系统的其他部分相比，只有少数部分需要更频繁地更改和重新部署。不幸的是，预测未来的系统将如何演变并不容易。这就是为什么一个独立的部署单元通常被认为是一种预防措施，因为在设计阶段这样做比以后更容易。这反过来又导致可部署部队的规模不断缩小

不幸的是，维护和协调一个松散的服务系统是要付出代价的。每个参与者都必须负责维护其 API，不仅在形式上（比如名称和类型），而且在精神上：相同服务的新版本产生的结果在规模上必须相同。在类型上保持相同的值，然后在规模上使其变大或变小，这对于服务的客户来说可能是不可接受的。因此，尽管声明了独立性，但服务作者必须更清楚他们的客户是谁，他们的需求是什么

幸运的是，将应用拆分为可独立部署的单元带来了一些意想不到的好处，这些好处增加了将系统拆分为更小服务的动机。物理隔离允许在选择编程语言和实现平台时具有更大的灵活性。它还可以帮助您选择最适合该工作的技术，并聘请能够实现该技术的专家。这样，您就不必受为系统其他部分所做的技术选择的约束。这也有助于招聘人员在寻找必要人才时更加灵活，这是一个很大的优势，因为对工作的需求继续超过流入就业市场的专家。

每一个独立的部分（服务）都能够以自己的速度发展，并且变得更加复杂，只要与系统其他部分的契约没有改变或者以一种协调良好的方式引入。微服务就是这样产生的，后来被 Netflix、Google、Twitter、eBay、Amazon 和 Uber 等数据处理巨头投入使用。现在让我们谈谈这项努力的结果和经验教训。

# 微服务的大小

*微服务必须有多小？* 对于这个问题没有一个普遍的答案，一般共识与微服务的以下特征一致（没有特定顺序）：

*   源代码的大小应该小于 SOA 架构中服务的大小。
*   一个开发团队应该能够支持多个微服务，团队的规模应该是两个比萨饼足够为整个团队提供午餐。
*   它必须是可部署的，并且独立于其他微服务，假设契约（即 API）没有变化。
*   每个微服务都必须有自己的数据库（或模式，或至少是一组表）–尽管这是一个有争议的话题，特别是在多个微服务能够修改同一个数据集的情况下；如果同一个团队维护所有这些数据集，那么在同时修改同一数据时更容易避免冲突。
*   它必须是无状态且幂等的；如果微服务的一个实例失败了，那么另一个实例应该能够完成失败的微服务所期望的。
*   它应该提供一种检查其*健康状况*的方法，证明服务已启动并正在运行，拥有所有必要的资源，并且准备好执行该工作

在设计过程、开发和部署后需要考虑资源共享，并在从不同过程访问同一资源时对干扰程度（例如阻塞）假设的验证进行监控。在修改同一持久性数据的过程中也需要特别小心，无论是在数据库、模式之间共享，还是在同一模式中的表之间共享。如果*最终的一致性*是可接受的（这通常是用于统计目的的较大数据集的情况），则需要采取特殊措施。但是，对事务完整性的需求常常带来一个难题。

支持跨多个微服务的事务的一种方法是创建一个充当**分布式事务管理器**（**DTM**）角色的服务。通过这种方式，其他服务可以将数据修改请求传递给它。DTM 服务可以将并发修改的数据保存在自己的数据库表中，只有在数据变得一致后，才能在一个事务中将结果移动到目标表中。例如，只有当相应的金额被另一个微服务添加到分类账时，一个微服务才能将钱添加到一个账户。

如果访问数据所花费的时间是一个问题，或者如果您需要保护数据库不受过多并发连接的影响，那么将数据库专用于微服务可能是一个解决方案。或者，内存缓存可能是一种方法。添加一个提供对缓存的访问的服务会增加服务的隔离，但是需要在管理同一缓存的对等方之间进行同步（这有时很困难）。

在回顾了所有列出的要点和可能的解决方案之后，每个微服务的大小应该取决于这些考虑的结果，而不是作为强加给所有服务的大小的空白声明。这有助于避免毫无成效的讨论，并产生一个适合于解决特定项目及其需求的结果

# 微服务之间的通信方式

目前有十多种框架用于构建微服务。最流行的两种是 [SpringBoot](https://spring.io/projects/spring-boot)和 [MicroFile](https://microprofile.io)，其目标是优化基于微服务架构的企业 Java。轻量级开源微服务框架，[KumuluzEE](https://ee.kumuluz.com) 符合 MicroFile。

以下是其他框架的列表（按字母顺序排列）：

*   **Akka**：这是一个为 Java 和 Scala 构建高度并发、分布式和弹性的消息驱动应用的工具箱（`akka.io`。
*   **Bootique**：这是一个针对可运行 Java 应用的最低限度的固执己见的框架（`bootique.io`。
*   **Dropwizard**：这是一个 Java 框架，用于开发操作友好、高性能和 RESTful Web 服务（[www.dropwizard.io](https://www.dropwizard.io/1.3.9/docs/)）。
*   **Jodd**：这是一套 1.7MB 以下的 Java 微框架、工具和工具（[jodd.org 网站](https://jodd.org/)）。
*   **Lightbend Lagom**：这是一个基于 Akka 和 Play（[的固执己见的微服务框架 www.lightbend.com](https://www.lightbend.com/)）。
*   **Ninja**：这是一个 [Java 的全栈框架](https://www.ninjaframework.org/)。
*   **Spotify-Apollo**：这是 Spotify 用来编写微服务的一组 Java 库（Spotify/Apollo）。
*   **Vert.x**：这是一个在 JVM（`vertx.io`上构建反应式应用的工具箱。

所有这些框架都支持微服务之间基于 REST 的通信；其中一些还具有发送消息的附加方式

为了演示与传统通信方法相比的替代方法，我们将使用 Vert.x，它是一个事件驱动的非阻塞轻量级多语言工具包。它允许您用 Java、JavaScript、Groovy、Ruby、Scala、Kotlin 和 Ceylon 编写组件。它支持一个异步编程模型和一个分布式事件总线，可以访问浏览器内的 JavaScript，从而允许创建实时 Web 应用。但是，由于本书的重点，我们将只使用 Java。

Vert.xAPI 有两个源代码树：第一个源代码树以`io.vertx.core`开头，第二个源代码树以`io.vertx.rxjava.core`开头。第二个源树是`io.vertx.core`类的反应版本。事实上，无功源树是基于非无功源的，所以这两个源树并不是不兼容的。相反，除了非反应式实现还提供了反应式版本。因为我们的讨论集中在反应式编程上，所以我们将主要使用`io.vertx.rxjava`源代码树的类和接口，也称为 **RX 化的 Vert.x API**。

首先，我们将向`pom.xml`文件添加以下依赖项，如下所示：

```java
<dependency>
   <groupId>io.vertx</groupId>
    <artifactId>vertx-web</artifactId>
    <version>3.6.3</version>
</dependency>
<dependency>
    <groupId>io.vertx</groupId>
    <artifactId>vertx-rx-java</artifactId>
    <version>3.6.3</version>
</dependency>
```

实现`io.vertx.core.Verticle`接口的类作为基于 Vert.x 的应用的构建块。`io.vertx.core.Verticle`接口有四个抽象方法：

```java
Vertx getVertx();
void init(Vertx var1, Context var2);
void start(Future<Void> var1) throws Exception;
void stop(Future<Void> var1) throws Exception;

```

为了使编码在实践中更容易，有一个抽象的`io.vertx.rxjava.core.AbstractVerticle`类实现了所有的方法，但是它们是空的，不做任何事情。它允许通过扩展`AbstractVerticle`类并只实现应用所需的`Verticle`接口的那些方法来创建垂直体。在大多数情况下，仅仅实现`start()`方法就足够了。

Vert.x 有自己的系统，通过事件总线交换消息（或事件）。通过使用`io.vertx.rxjava.core.eventBus.EventBus`类的`rxSend(String address, Object msg)`方法，任何垂直体都可以向任何地址发送消息（只是一个字符串）：

```java
Single<Message<String>> reply = vertx.eventBus().rxSend(address, msg);

```

`vertx`对象（它是`AbstractVerticle`的受保护属性，可用于每个垂直方向）允许访问事件总线和`rxSend()`调用方法。`Single<Message<String>>`返回值表示响应消息可以返回的回复；您可以订阅它，或者以任何其他方式处理它。

Verticle 还可以注册为特定地址的消息接收器（使用者）：

```java
vertx.eventBus().consumer(address);
```

如果多个 Verticle 注册为同一地址的消费者，那么`rxSend()`方法使用循环算法只将消息传递给这些消费者中的一个。

或者，`publish()`方法可用于向使用相同地址注册的所有消费者传递消息：

```java
EventBus eb = vertx.eventBus().publish(address, msg);
```

返回的对象是`EventBus`对象，它允许您在必要时添加其他`EventBus`方法调用。

如您所记得的，消息驱动异步处理是由微服务组成的反应式系统的弹性、响应性和弹性的基础。因此，在下一节中，我们将演示如何构建一个既使用基于 REST 的通信又使用基于 Vert.x`EventBus`的消息的反应式系统。

# 微服务的反应式系统

为了演示如果使用 Vert.x 实现，微服务的反应式系统会是什么样子，我们将创建一个 HTTP 服务器，它可以接受系统中基于 REST 的请求，向另一个 Verticle 发送基于`EventBus`的消息，接收回复，并将响应发送回原始请求。

为了演示这一切是如何工作的，我们还将编写一个程序，向系统生成 HTTP 请求，并允许您从外部测试系统。

# HTTP 服务器

让我们假设进入反应式系统演示的入口点是一个 HTTP 调用。这意味着我们需要创建一个充当 HTTP 服务器的 Verticle。Vert.x 使这变得非常简单；下面垂直线中的三行就可以做到这一点：

```java
HttpServer server = vertx.createHttpServer();
server.requestStream().toObservable()
      .subscribe(request -> request.response()
                .setStatusCode(200)
                .end("Hello from " + name + "!\n")
      );
server.rxListen(port).subscribe();
```

如您所见，创建的服务器监听指定的端口，并用 Hello…响应每个传入的请求。默认情况下，主机名为`localhost`。如有必要，可以使用相同方法的重载版本为主机指定另一个地址：

```java
server.rxListen(port, hostname).subscribe();
```

下面是我们创建的垂直体的完整代码：

```java
package com.packt.learnjava.ch16_microservices;
import io.vertx.core.Future;
import io.vertx.rxjava.core.AbstractVerticle;
import io.vertx.rxjava.core.http.HttpServer;
public class HttpServerVert extends AbstractVerticle {
    private int port;
    public HttpServerVert(int port) { this.port = port; }
    public void start(Future<Void> startFuture) {
        String name = this.getClass().getSimpleName() + 
                       "(" + Thread.currentThread().getName() + 
                                            ", localhost:" + port + ")";
        HttpServer server = vertx.createHttpServer();
        server.requestStream().toObservable()
              .subscribe(request -> request.response()
                        .setStatusCode(200)
                        .end("Hello from " + name + "!\n")
              );
        server.rxListen(port).subscribe();
        System.out.println(name + " is waiting...");
    }
}
```

我们可以使用以下代码部署此服务器：

```java
Vertx vertx = Vertx.vertx();
RxHelper.deployVerticle(vertx, new HttpServerVert(8082));
```

结果如下：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/b813c685-d758-4581-8a07-3c12d8f2f054.png)

请注意，…is waiting…消息会立即出现，甚至在任何请求传入之前也会出现–这是此服务器的异步特性。`name`前缀被构造成包含类名、线程名、主机名和端口。注意，线程名称告诉我们服务器监听事件循环线程`0`。

现在我们可以使用`curl`命令向部署的服务器发出请求，响应如下：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/b6e4ed70-a4b5-4ba4-979d-0fd81e245186.png)

如您所见，我们已经发出了 HTTP`GET`（默认）请求，并用预期的名称返回了预期的 Hello…消息

以下代码是`start()`方法的更现实版本：

```java
Router router = Router.router(vertx);
router.get("/some/path/:name/:address/:anotherParam")
      .handler(this::processGetSomePath);
router.post("/some/path/send")
      .handler(this::processPostSomePathSend);
router.post("/some/path/publish")
      .handler(this::processPostSomePathPublish);
vertx.createHttpServer()
     .requestHandler(router::handle)
     .rxListen(port)
     .subscribe();
System.out.println(name + " is waiting..."); 
```

现在我们使用`Router`类，根据 HTTP 方法（`GET`或`POST`和路径向不同的处理器发送请求。它要求您向`pom.xml`文件添加以下依赖项：

```java
<dependency>
    <groupId>io.vertx</groupId>
    <artifactId>vertx-web</artifactId>
    <version>3.6.3</version>
</dependency>

```

第一条路由为`/some/path/:name/:address/:anotherParam`路径，包含三个参数（`name`、`address`、`anotherParam`）。HTTP 请求在`RoutingContext`对象内传递给以下处理器：

```java
private void processGetSomePath(RoutingContext ctx){
    ctx.response()
       .setStatusCode(200)
       .end("Got into processGetSomePath using " + 
                                        ctx.normalisedPath() + "\n");
}
```

处理器只返回一个 HTTP 代码`200`和一个硬编码消息，该消息设置在 HTTP 响应对象上，并由`response()`方法返回。在幕后，HTTP 响应对象来自 HTTP 请求。为了清晰起见，我们已经使处理器的第一个实现变得简单。稍后，我们将以更现实的方式重新实现它们。

第二条路径为`/some/path/send`路径，处理器如下：

```java
private void processPostSomePathSend(RoutingContext ctx){
    ctx.response()
       .setStatusCode(200)
       .end("Got into processPostSomePathSend using " + 
                                        ctx.normalisedPath() + "\n");

```

第三条路径为`/some/path/publish`路径，处理器如下：

```java
private void processPostSomePathPublish(RoutingContext ctx){
    ctx.response()
       .setStatusCode(200)
       .end("Got into processPostSomePathPublish using " + 
                                        ctx.normalisedPath() + "\n");
}
```

如果我们再次部署服务器并发出 HTTP 请求以命中每个路由，我们将看到以下屏幕截图：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/777454cb-2ac0-4b48-80ca-6ed76e42a3a2.png)

前面的屏幕截图说明了我们向第一个 HTTP`GET`请求发送了预期的消息，但在响应第二个 HTTP`GET`请求时未找到接收到的资源。这是因为我们的服务器中没有 HTTP`GET`请求的`/some/path/send`路由。然后，我们切换到 HTTP`POST`请求，并接收两个`POST`请求的预期消息。

从路径名可以猜到我们将使用`/some/path/send`路由发送`EventBus`消息，使用`/some/path/publish`路由发布`EventBus`消息，但是在实现相应的路由处理器之前，我们先创建一个接收`EventBus`消息的垂直体。

# `EventBus`消息接收器

消息接收器的实现非常简单：

```java
vertx.eventBus()
     .consumer(address)
     .toObservable()
     .subscribe(msgObj -> {
            String body = msgObj.body().toString();
            String msg = name + " got message '" + body + "'.";
            System.out.println(msg);
            String reply = msg + " Thank you.";
            msgObj.reply(reply);
     }, Throwable::printStackTrace );

```

可以通过`vertx`对象访问`EventBus`对象。`EventBus`类的`consumer(address)`方法允许您设置与此消息接收器关联的地址并返回`MessageConsumer<Object>`。然后我们将这个对象转换成`Observable`并订阅它，等待异步接收消息。`subscribe()`方法有几个重载版本。我们选择了一个接受两个函数的函数：第一个函数为每个发出的值（在我们的例子中，为每个接收到的消息）调用；第二个函数在管道中的任何地方抛出异常时调用（即，它的行为类似于包罗万象的`try...catch`块）。`MessageConsumer<Object>`类表示，原则上消息可以由任何类的对象表示。如您所见，我们决定发送一个字符串，所以我们将消息体转换为`String`。`MessageConsumer<Object>`类还有一个`reply(Object)`方法，允许您将消息发送回发送者。

消息接收垂直的完整实现如下：

```java
package com.packt.learnjava.ch16_microservices;
import io.vertx.core.Future;
import io.vertx.rxjava.core.AbstractVerticle;
public class MessageRcvVert extends AbstractVerticle {
    private String id, address;
    public MessageRcvVert(String id, String address) {
        this.id = id;
        this.address = address;
    }
    public void start(Future<Void> startFuture) {
        String name = this.getClass().getSimpleName() + 
                    "(" + Thread.currentThread().getName() + 
                                   ", " + id + ", " + address + ")";
        vertx.eventBus()
             .consumer(address)
             .toObservable()
             .subscribe(msgObj -> {
                    String body = msgObj.body().toString();
                    String msg = name + " got message '" + body + "'.";
                    System.out.println(msg);
                    String reply = msg + " Thank you.";
                    msgObj.reply(reply);
             }, Throwable::printStackTrace );
        System.out.println(name + " is waiting...");
    }
}
```

我们可以用部署`HttpServerVert`垂直的方式部署此眩晕：

```java
String address = "One";
Vertx vertx = Vertx.vertx();
RxHelper.deployVerticle(vertx, new MessageRcvVert("1", address));

```

如果运行此代码，将显示以下消息：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/d8620c51-9fdf-4121-ad41-c35c69e905a6.png)

如您所见，到达并执行了`MessageRcvVert`的最后一行，而创建的管道和我们传递给它的操作符的函数正在等待消息的发送。所以，我们现在就开始吧。

# `EventBus`消息发送器

正如我们所承诺的，我们现在将以更现实的方式重新实现`HttpServerVert`垂直面的处理器。`GET`方法处理器现在看起来像以下代码块：

```java
private void processGetSomePath(RoutingContext ctx){
    String caller = ctx.pathParam("name");
    String address = ctx.pathParam("address");
    String value = ctx.pathParam("anotherParam");
    System.out.println("\n" + name + ": " + caller + " called.");
    vertx.eventBus()
         .rxSend(address, caller + " called with value " + value)
         .toObservable()
         .subscribe(reply -> {
            System.out.println(name + 
                           ": got message\n    " + reply.body());
            ctx.response()
               .setStatusCode(200)
               .end(reply.body().toString() + "\n");
        }, Throwable::printStackTrace);
}
```

如您所见，`RoutingContext`类提供了`pathParam``()`方法，该方法从路径中提取参数（如果它们被标记为`:`，如我们的示例所示）。然后，我们再次使用`EventBus`对象向作为参数提供的地址异步发送消息。`subscribe()`方法使用提供的函数来处理来自消息接收器的应答，并将应答发送回原始请求到 HTTP 服务器。

现在让我们部署两个垂直点，`HttpServerVert`和`MessageRcvVert`垂直点：

```java
String address = "One";
Vertx vertx = Vertx.vertx();
RxHelper.deployVerticle(vertx, new MessageRcvVert("1", address));
RxHelper.deployVerticle(vertx, new HttpServerVert(8082));

```

运行上述代码时，屏幕显示以下消息：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/9e30c01f-6771-437d-8b70-5918d2e79525.png)

请注意，每个 Verticle 都在自己的线程上运行。现在我们可以使用`curl`命令提交 HTTP`GET`请求，结果如下：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/bdaa1e47-f359-4eeb-85d6-de95fd9c9961.png)

这就是如何从我们的演示系统之外看待交互。在内部，我们还可以看到以下消息，这些消息允许我们跟踪我们的眩晕是如何相互作用和发送消息的：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/af5c5810-8924-4265-8108-2de9f9d69bae.png)

结果与预期完全一致。

现在，`/some/path/send`路径的处理器如下：

```java
private void processPostSomePathSend(RoutingContext ctx){
   ctx.request().bodyHandler(buffer -> {
       System.out.println("\n" + name + ": got payload\n    " + buffer);
       JsonObject payload = new JsonObject(buffer.toString());
       String caller = payload.getString("name");
       String address = payload.getString("address");
       String value = payload.getString("anotherParam");
       vertx.eventBus()
            .rxSend(address, caller + " called with value " + value)
            .toObservable()
            .subscribe(reply -> {
                System.out.println(name + 
                                  ": got message\n    " + reply.body());
                ctx.response()
                   .setStatusCode(200)
                   .end(reply.body().toString() + "\n");
            }, Throwable::printStackTrace);
   });
}
```

对于 HTTP`POST`请求，我们希望发送 JSON 格式的有效负载，其值与我们作为 HTTP`GET`请求的参数发送的值相同。该方法的其余部分与`processGetSomePath()`实现非常相似。让我们再次部署`HttpServerVert`和`MessageRcvVert` Verticles，然后用有效负载发出 HTTP`POST`请求，结果如下：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/aade93a7-98e3-44a8-981a-564a72fbe360.png)

这看起来与设计的 HTTP`GET`请求的结果一模一样。在后端，将显示以下消息：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/1240de08-bb90-4abb-99c0-4b29b618ea69.png)

这些消息中也没有什么新内容，只是显示了 JSON 格式。

最后，我们来看一下`/some/path/publish`路径的 HTTP`POST`请求的处理器：

```java
private void processPostSomePathPublish(RoutingContext ctx){
   ctx.request().bodyHandler(buffer -> {
       System.out.println("\n" + name + ": got payload\n    " + buffer);
       JsonObject payload = new JsonObject(buffer.toString());
       String caller = payload.getString("name");
       String address = payload.getString("address");
       String value = payload.getString("anotherParam");
       vertx.eventBus()
            .publish(address, caller + " called with value " + value);
       ctx.response()
          .setStatusCode(202)
          .end("The message was published to address " + 
                                                     address + ".\n");
    });
}
```

这一次，我们使用了`publish()`方法来发送消息。请注意，此方法无法接收答复。这是因为，正如我们已经提到的，`publish()`方法将消息发送给所有注册到此地址的接收器。如果我们使用`/some/path/publish`路径发出一个 HTTP`POST`请求，结果看起来略有不同：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/a0ec2f38-d071-49ee-b220-bcddae299614.png)

此外，后端上的消息看起来也不同：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/8cd1ecef-2f5e-40ff-a16d-33f7b4700849.png)

所有这些差异都与服务器无法获得回复这一事实有关，即使接收方发送回复的方式与响应由`rxSend()`方法发送的消息的方式完全相同。

在下一节中，我们将部署几个发送者和接收器的实例，并通过`rxSend()`和`publish()`方法检查消息分布之间的差异。

# 反应式系统演示

现在，让我们使用上一节中创建的 Verticles 来组装和部署一个小型反应式系统：

```java
package com.packt.learnjava.ch16_microservices;
import io.vertx.rxjava.core.RxHelper;
import io.vertx.rxjava.core.Vertx;
public class ReactiveSystemDemo {
   public static void main(String... args) {
      String address = "One";
      Vertx vertx = Vertx.vertx();
      RxHelper.deployVerticle(vertx, new MessageRcvVert("1", address));
      RxHelper.deployVerticle(vertx, new MessageRcvVert("2", address));
      RxHelper.deployVerticle(vertx, new MessageRcvVert("3", "Two"));
      RxHelper.deployVerticle(vertx, new HttpServerVert(8082));
   }
}
```

如您所见，我们将部署两个使用相同的`One`地址接收消息的 Verticle 和一个使用`Two`地址的 Verticle。如果我们运行上述程序，屏幕将显示以下消息：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/2f67915c-1df0-4f5a-be9f-12842ec550d6.png)

现在开始向系统发送 HTTP 请求。首先，我们发送三次相同的 HTTP`GET`请求：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/62b4e189-4ff8-47ef-9b4e-a5b5aeac0c55.png)

如前所述，如果有多个注册在同一地址的垂直站点，`rxSend()`方法使用循环算法来选择应该接收下一条消息的垂直站点。第一个请求通过`ID="1"`发送给接收器，第二个请求通过`ID="2"`发送给接收器，第三个请求再次通过`ID="1"`发送给接收器。

我们使用对`/some/path/send`路径的 HTTP`POST`请求得到相同的结果：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/b0422829-73ed-4c05-b4bf-521e04c6934c.png)

同样，使用循环算法旋转消息的接收器。

现在，让我们向系统发布两次消息：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/14cd5171-831e-4830-b7c8-47fc8c520225.png)

由于接收方的回复无法传播回系统用户，因此我们需要查看登录到后端的消息：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/1ad7b15a-8f79-4890-b116-5108d2aaef11.png)

如您所见，`publish()`方法将消息发送到注册到指定地址的所有 Verticle。注意，带有`ID="3"`（注册为`Two`地址）的 Verticle 从未收到消息。

在我们结束这个被动系统演示之前，值得一提的是，Vert.x 允许您轻松地对 Verticle 进行集群。您可以在 [Vert.x 文档](https://vertx.io/docs/vertx-core/java)中阅读此功能。

# 总结

本章向读者介绍了微服务的概念，以及如何使用微服务创建反应式系统。我们讨论了应用大小的重要性，以及它如何影响您将其转换为微服务的决策。您还了解了现有的微服务框架如何支持消息驱动架构，并有机会在实践中使用其中的一个工具 Vert.x 工具包。

在下一章中，我们将探讨 **Java 微基准线束**（**JMH**）项目，它允许您测量代码性能和其他参数。我们将定义什么是 JMH，如何创建和运行基准，基准参数是什么，以及支持的 IDE 插件。

# 测验

1.  选择所有正确的语句：

2.  微服务能比一些单一应用更大吗？ 
3.  微服务如何相互通信？
4.  列举两个为支持微服务而创建的框架。
5.  Vert.x 中微服务的主要构建块是什么？
6.  Vert.x 中的`send`和`publish`事件总线消息有什么区别？
7.  事件总线的`send`方法如何决定在 Vert.x 中发送消息的接收器？
8.  Vert.x verticles 可以集群吗？
9.  在哪里可以找到有关 Vert.x 的更多信息？

# 十七、Java 微基准线束

在本章中，读者将介绍一个允许测量各种代码性能特征的 **Java 微基准线束**（**JMH**）项目。如果性能是应用的一个重要问题，那么这个工具可以帮助您识别瓶颈，精确到方法级别。使用它，读者不仅能够测量代码的平均执行时间和其他性能值（例如吞吐量），而且能够以一种受控的方式进行测量，不管是否有 JVM 优化、预热运行等等。

除了理论知识，读者还将有机会使用实际的演示示例和建议来运行 JMH。

本章将讨论以下主题：

*   什么是 JMH？
*   创建 JMH 基准
*   运行基准测试
*   使用 IDE 插件
*   JMH 基准参数
*   JMH 使用示例

# 什么是 JMH？

根据字典，**基准**是*一个标准或参照点，可以对事物进行比较或评估*。在编程中，它是比较应用性能的一种方法，或者只是比较方法。**微基准**关注的是后者较小的代码片段，而不是整个应用。JMH 是衡量单个方法性能的框架。

这似乎非常有用。我们能不能不只是在一个循环中运行一个方法一千次或十万次，测量它所用的时间，然后计算方法性能的平均值？我们可以。问题是 JVM 是一个比代码执行机器复杂得多的程序。它的优化算法专注于使应用代码尽可能快地运行。

例如，让我们看看下面的类：

```java
class SomeClass {
    public int someMethod(int m, int s) {
        int res = 0;
        for(int i = 0; i < m; i++){
            int n = i * i;
            if (n != 0 && n % s == 0) {
                res =+ n;
            }
        }
        return res;
    }
}
```

我们用代码填充了`someMethod()`方法，这些代码没有多大意义，但使方法保持忙碌。要测试此方法的性能，很有可能将代码复制到某个测试方法中并在循环中运行：

```java
public void testCode() {
   StopWatch stopWatch = new StopWatch();
   stopWatch.start();
   int xN = 100_000;
   int m = 1000;
   for(int x = 0; i < xN; x++) {
        int res = 0;
        for(int i = 0; i < m; i++){
            int n = i * i;
            if (n != 0 && n % 250_000 == 0) {
                res += n;
            }
        }
    }
    System.out.println("Average time = " + 
                             (stopWatch.getTime() / xN /m) + "ms");
}
```

但是，JVM 将看到从未使用过`res`结果，并将计算限定为**死代码**（从未执行的代码部分）。那么，为什么还要执行这些代码呢？

您可能会惊讶地发现，算法的显著复杂性或简化并不影响性能。这是因为，在每种情况下，代码都不是实际执行的

您可以更改测试方法，并通过返回它来假装使用了结果：

```java
public int testCode() {
   StopWatch stopWatch = new StopWatch();
   stopWatch.start();
   int xN = 100_000;
   int m = 1000;
   int res = 0;
   for(int x = 0; i < xN; x++) {
        for(int i = 0; i < m; i++){
            int n = i * i;
            if (n != 0 && n % 250_000 == 0) {
                res += n;
            }
        }
    }
    System.out.println("Average time = " + 
                             (stopWatch.getTime() / xN / m) + "ms");
 return res;
}
```

这可能会说服 JVM 每次都执行代码，但不能保证。JVM 可能会注意到，输入到计算中的数据并没有改变，这个算法每次运行都会产生相同的结果。因为代码是基于常量输入的，所以这种优化称为**常量折叠**。此优化的结果是，此代码可能只执行一次，并且每次运行都假定相同的结果，而不实际执行代码。

但实际上，基准测试通常是围绕一个方法而不是一块代码构建的。例如，测试代码可能如下所示：

```java
public void testCode() {
   StopWatch stopWatch = new StopWatch();
   stopWatch.start();
   int xN = 100_000;
   int m = 1000;
   SomeClass someClass = new SomeClass();
   for(int x = 0; i < xN; x++) {
        someClass.someMethod(m, 250_000);
    }
    System.out.println("Average time = " + 
                             (stopWatch.getTime() / xN / m) + "ms");
}
```

但即使是这段代码也容易受到我们刚才描述的 JVM 优化的影响。

JMH 的创建是为了帮助避免这种情况和类似的陷阱。在“JMH 用法示例”部分，我们将向您展示如何使用 JMH 来解决死代码和常量折叠优化问题，使用`@State`注解和`Blackhole`对象。

此外，JMH 不仅可以测量平均执行时间，还可以测量吞吐量和其他性能特性。

# 创建 JMH 基准

要开始使用 JMH，必须将以下依赖项添加到`pom.xml`文件中：

```java
<dependency>
    <groupId>org.openjdk.jmh</groupId>
    <artifactId>jmh-core</artifactId>
    <version>1.21</version>
</dependency>
<dependency>
    <groupId>org.openjdk.jmh</groupId>
    <artifactId>jmh-generator-annprocess</artifactId>
    <version>1.21</version>
</dependency>

```

第二个`.jar`文件`annprocess`的名称提示 JMH 使用注解。如果你这么猜的话，你是对的。以下是为测试算法性能而创建的基准的示例：

```java
public class BenchmarkDemo {
    public static void main(String... args) throws Exception{
        org.openjdk.jmh.Main.main(args);
    }
    @Benchmark
    public void testTheMethod() {
        int res = 0;
        for(int i = 0; i < 1000; i++){
            int n = i * i;
            if (n != 0 && n % 250_000 == 0) {
                res += n;
            }
        }
    }
}
```

请注意`@Benchmark`注解。它告诉框架必须测量此方法的性能。如果您运行前面的`main()`方法，您将看到类似于以下内容的输出：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/3316accf-de05-4c3a-a117-a67dd492be62.png)

这只是包含不同条件下的多次迭代的广泛输出的一部分，目的是避免或抵消 JVM 优化。它还考虑了一次运行代码和多次运行代码之间的差异。在后一种情况下，JVM 开始使用即时编译器，它将经常使用的字节码编译成本地二进制代码，甚至不读取字节码。预热周期就是为了达到这个目的而执行的，代码在没有测量其性能的情况下就被作为一个空运行来执行，这个空运行会使 JVM 升温。

还有一些方法可以告诉 JVM 编译哪个方法并直接作为二进制文件使用，每次编译哪个方法，以及提供类似的指令来禁用某些优化。我们将很快讨论这个问题。

现在让我们看看如何运行基准测试。

# 运行基准测试

正如您可能已经猜测的，运行基准的一种方法就是执行`main()`方法。可以直接使用`java`命令或使用 IDE 完成。我们在第 1 章、“从 Java12 开始”中讨论了它。然而，有一种更简单、更方便的方法来运行基准：使用 IDE 插件。

# 使用 IDE 插件

所有主要的支持 Java 的 IDE 都有这样一个插件。我们将演示如何使用安装在 MacOS 计算机上的 IntelliJ 插件，但它同样适用于 Windows 系统。

以下是要遵循的步骤：

1.  要开始安装插件，请同时按`Cmd`键和逗号（`,`），或者只需单击顶部水平菜单中的扳手符号（带有悬停文本首选项）：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/e45bf358-db14-4110-a024-d2b603ce61e0.png)

2.  它将在左窗格中打开一个包含以下菜单的窗口：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/e5fc8950-6ce9-4842-9fa8-8b1705da19ff.png)

3.  选择“插件”，如前面的屏幕截图所示，并观察具有以下顶部水平菜单的窗口：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/c997082a-cb91-4937-9daf-e17839eb00be.png)

4.  选择“市场”，在“市场”输入框的“搜索插件”中输入`JMH`，然后按`Enter`。如果您有互联网连接，它将显示一个 JMH 插件符号，类似于此屏幕截图中显示的符号：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/1efbcb07-de86-4b92-9d4e-0830a9429f71.png)

5.  单击“安装”按钮，然后在它变为“重新启动 IDE”后，再次单击它：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/3c6e563e-17e8-4735-9296-d2ccd8873449.png)

6.  IDE 重新启动后，插件就可以使用了。现在，您不仅可以运行`main()`方法，而且如果您有几个带有`@Benchmark`注解的方法，还可以选择要执行的基准测试方法。要执行此操作，请从“运行”下拉菜单中选择“运行…”：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/c77f55c5-2ee7-48fa-942d-c826cf22c1b6.png)

7.  它将弹出一个窗口，其中包含可运行的方法选择：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/1e239cb3-3672-4607-8df2-95533b4a775f.png)

8.  选择一个你想运行的，它将被执行。至少运行一次方法后，只需右键单击它并从弹出菜单中执行它：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/b8c7c313-2eab-4338-bc59-0d7b535b5455.png)

9.  也可以使用每个菜单项右侧显示的快捷方式。

现在让我们回顾一下可以传递给基准的参数。

# JMH 基准参数

有许多基准参数允许为手头任务的特定需要微调度量。我们只介绍主要的。

# 模式

第一组参数定义了特定基准必须测量的性能方面（模式）：

*   `Mode.AverageTime`：测量平均执行时间
*   `Mode.Throughput`：通过在迭代中调用基准方法来测量吞吐量
*   `Mode.SampleTime`：采样执行时间，而不是平均执行时间；允许我们推断分布、百分位数等
*   `Mode.SingleShotTime`：测量单个方法调用时间；允许在不连续调用基准方法的情况下测试冷启动

这些参数可以在注解`@BenchmarkMode`中指定。例如：

```java
@BenchmarkMode(Mode.AverageTime)
```

可以组合多种模式：

```java
@BenchmarkMode({Mode.Throughput, Mode.AverageTime, Mode.SampleTime, Mode.SingleShotTime}
```

也可以要求所有人：

```java
@BenchmarkMode(Mode.All)
```

所描述的参数以及我们将在本章后面讨论的所有参数都可以在方法和/或类级别进行设置。方法级别集值覆盖类级别值。

# 输出时间单位

用于呈现结果的时间单位可以使用`@OutputTimeUnit`注解指定：

```java
@OutputTimeUnit(TimeUnit.NANOSECONDS)
```

可能的时间单位来自`java.util.concurrent.TimeUnit`枚举。

# 迭代

另一组参数定义了用于预热和测量的迭代。例如：

```java
@Warmup(iterations = 5, time = 100, timeUnit = TimeUnit.MILLISECONDS)
@Measurement(iterations = 5, time = 100, timeUnit = TimeUnit.MILLISECONDS)
```

# 分叉

在运行多个测试时，`@Fork`注解允许您将每个测试设置为在单独的进程中运行。例如：

```java
@Fork(10)
```

传入的参数值指示 JVM 可以分叉到独立进程的次数。默认值为`-1`，如果在测试中使用多个实现同一接口的类，并且这些类相互影响，那么如果没有它，测试的性能可能是混合的。

`warmups`参数是另一个参数，可以设置为指示基准必须执行多少次而不收集测量值：

```java
@Fork(value = 10, warmups = 5)
```

它还允许您向`java`命令行添加 Java 选项。例如：

```java
@Fork(value = 10, jvmArgs = {"-Xms2G", "-Xmx2G"})
```

JMH 参数的完整列表以及如何使用它们的示例可以在[`openjdk`项目](http://hg.openjdk.java.net/code-tools/jmh/file/tip/jmh-samples/src/main/java/org/openjdk/jmh/samples)中找到。例如，我们没有提到`@Group`、`@GroupThreads`、`@Measurement`、`@Setup`、`@Threads`、`@Timeout`、`@TearDown`或`@Warmup`。

# JMH 使用示例

现在让我们运行一些测试并比较它们。首先，我们运行以下测试方法：

```java
@Benchmark
@BenchmarkMode(Mode.All)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
public void testTheMethod0() {
    int res = 0;
    for(int i = 0; i < 1000; i++){
        int n = i * i;
        if (n != 0 && n % 250_000 == 0) {
            res += n;
        }
    }
}
```

如您所见，我们要求度量所有性能特征，并在呈现结果时使用纳秒。在我们的系统上，测试执行大约需要 20 分钟，最终结果摘要如下所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/20bb9f9c-f0cf-4894-b194-cb204bebfc22.png)

现在我们将测试更改为：

```java
@Benchmark
@BenchmarkMode(Mode.All)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
public void testTheMethod1() {
    SomeClass someClass = new SomeClass();
    int i = 1000;
    int s = 250_000;
    someClass.someMethod(i, s);
}
```

如果我们现在运行`testTheMethod1()`，结果会略有不同：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/b4aa63c1-3b29-4d93-9ff5-2a869a53eb9b.png)

在采样和单次运行方面，结果相差较大。你可以玩这些方法，并改变分叉和数量的热身

# 使用`@State`注解

这个 JMH 特性允许您对 JVM 隐藏数据源，从而防止死代码优化。您可以添加一个类作为输入数据的源，如下所示：

```java
@State(Scope.Thread)
public static class TestState {
    public int m = 1000;
    public int s = 250_000;
}

@Benchmark
@BenchmarkMode(Mode.All)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
public int testTheMethod3(TestState state) {
    SomeClass someClass = new SomeClass();
    return someClass.someMethod(state.m, state.s);
}
```

`Scope`值用于在测试之间共享数据。在我们的例子中，只有一个测试使用了`TestCase`类对象，我们不需要共享。否则，该值可以设置为`Scope.Group`或`Scope.Benchmark`，这意味着我们可以在`TestState`类中添加设置器，并在其他测试中读取/修改它。

当我们运行此版本的测试时，得到以下结果：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/65fe7297-cb01-4963-9752-643ab32aa66a.png)

数据又变了。注意，平均执行时间增加了三倍，这表明没有应用更多的 JVM 优化。

# 使用黑洞对象

这个 JMH 特性允许模拟结果使用情况，从而防止 JVM 进行优化：

```java
@Benchmark
@BenchmarkMode(Mode.All)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
public void testTheMethod4(TestState state, Blackhole blackhole) {
    SomeClass someClass = new SomeClass();
    blackhole.consume(someClass.someMethod(state.m, state.s));
}
```

如您所见，我们刚刚添加了一个参数`Blackhole`对象，并在其上调用了`consume()`方法，从而假装使用了测试方法的结果。

当我们运行此版本的测试时，得到以下结果：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/c655a032-9ced-4a09-bce1-a2c5fcc28a5d.png)

这一次，结果看起来没什么不同。显然，即使在添加`Blackhole`用法之前，恒定折叠优化也被中和了

# 使用`@CompilerControl`注解

调整基准测试的另一种方法是告诉编译器编译、内联（或不内联）和从代码中排除（或不排除）特定方法。例如，考虑以下类：

```java
class SomeClass{
     public int oneMethod(int m, int s) {
        int res = 0;
        for(int i = 0; i < m; i++){
            int n = i * i;
            if (n != 0 && n % s == 0) {
                res = anotherMethod(res, n);
            }
        }
        return res;
    }

    @CompilerControl(CompilerControl.Mode.EXCLUDE)
    private int anotherMethod(int res, int n){
        return res +=n;
    }

}
```

假设我们对方法`anotherMethod()`编译/内联如何影响性能感兴趣，我们可以将其`CompilerControl`模式设置为：

*   `Mode.INLINE`：强制此方法内联
*   `Mode.DONT_INLINE`：为了避免这种方法内联
*   `Mode.EXCLUDE`：为了避免这种方法编译

# 使用`@Param`注解

有时，有必要对不同的输入数据集运行相同的基准测试。在这种情况下，`@Param`注解非常有用。

`@Param` is a standard Java annotation used by various frameworks, for example, JUnit. It identifies an array of parameter values. The test with the `@Param` annotation will be run as many times as there are values in the array. Each test execution picks up a different value from the array.

举个例子：

```java
@State(Scope.Benchmark)
public static class TestState1 {
    @Param({"100", "1000", "10000"})
    public int m;
    public int s = 250_000;
}

@Benchmark
@BenchmarkMode(Mode.All)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
public void testTheMethod6(TestState1 state, Blackhole blackhole) {
    SomeClass someClass = new SomeClass();
    blackhole.consume(someClass.someMethod(state.m, state.s));
}
```

`testTheMethod6()`基准将与参数`m`的每个列出的值一起使用。

# 一句警告

所描述的工具消除了程序员度量性能的大部分顾虑。然而，几乎不可能涵盖 JVM 优化、概要文件共享和 JVM 实现的类似方面的所有情况，特别是如果我们考虑到 JVM 代码在不同的实现之间不断发展和不同的话。JMH 的作者通过打印以下警告以及测试结果来确认这一事实：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/141191b6-156c-414a-a3f8-a1450455bb14.png)

剖面仪的说明及其用法见[`openjdk`项目](http://hg.openjdk.java.net/code-tools/jmh/file/tip/jmh-samples/src/main/java/org/openjdk/jmh/samples)。在相同的示例中，您将看到 JMH 基于注解生成的代码的描述。

如果您想深入了解代码执行和测试的细节，没有比研究生成的代码更好的方法了。它描述了 JMH 为运行所请求的基准测试所做的所有步骤和决策。您可以在`target/generated-sources/annotations`中找到生成的代码。

这本书的范围不允许进入如何阅读它的太多细节，但它不是很难，特别是如果你从一个简单的案例开始只测试一个方法。我们祝你在这一努力中一切顺利。

# 总结

在本章中，读者了解了 JMH 工具，并能够将其用于特定的实际案例，类似于他们在编程应用时遇到的那些案例。读者已经学习了如何创建和运行基准，如何设置基准参数，以及如何在需要时安装 IDE 插件。我们也提供了实用的建议和参考资料供进一步阅读。

在下一章中，读者将介绍设计和编写应用代码的有用实践。我们将讨论 Java 习惯用法、它们的实现和用法，并提供实现`equals()`、`hashCode()`、`compareTo()`和`clone()`方法的建议。我们还将讨论`StringBuffer`和`StringBuilder`类的用法之间的区别、如何捕获异常、最佳设计实践以及其他经验证的编程实践。

# 测验

1.  选择所有正确的语句：

2.  列出开始使用 JMH 所需的两个步骤。
3.  说出运行 JMH 的四种方法。
4.  列出两种可以与 JMH 一起使用（测量）的模式（性能特征）。
5.  列出两个可用于显示 JMH 测试结果的时间单位。
6.  如何在 JMH 基准之间共享数据（结果、状态）？
7.  如何告诉 JMH 使用枚举的值列表为参数运行基准测试？

8.  如何强制或关闭方法的编译？
9.  如何关闭 JVM 的常量折叠优化？
10.  如何以编程方式为运行特定基准测试提供 Java 命令选项？

# 十八、编写高质量代码的最佳实践

当程序员相互交谈时，他们经常使用非程序员无法理解的术语，或者不同编程语言的程序员模糊理解的术语。但是那些使用相同编程语言的人彼此理解得很好。有时也可能取决于程序员的知识水平。一个新手可能不明白一个有经验的程序员在说什么，而一个有经验的同事则点头以示回应

在本章中，读者将了解一些 Java 编程术语，即描述某些特性、功能、设计解决方案等的 Java 习惯用法。读者还将学习设计和编写应用代码的最流行和最有用的实践。在本章结束时，读者将对其他 Java 程序员在讨论他们的设计决策和使用的功能时所谈论的内容有一个坚实的理解。

本章将讨论以下主题：

*   Java 习惯用法及其实现和用法
*   `equals()`、`hashCode()`、`compareTo()`和`clone()`方法
*   `StringBuffer`和`StringBuilder`类
*   `try`、`catch`、`finally`条款
*   最佳设计实践
*   代码是为人编写的
*   测试：通往高质量代码的最短路径

# Java 习惯用法及其实现和用法

除了服务于专业人员之间的交流方式之外，编程习惯用法也是经过验证的编程解决方案和常用实践，它们不是直接从语言规范中派生出来的，而是从编程经验中产生的，我们将讨论最常用的习惯用法，您可以在 [Java 官方文档](https://docs.oracle.com/javase/tutorial)中找到并研究完整的习惯用法列表。

# `equals()`和`hashCode()`方法

`java.lang.Object`类中`equals()`和`hashCode()`方法的默认实现如下：

```java
public boolean equals(Object obj) {
    return (this == obj);
}
/**
* Whenever it is invoked on the same object more than once during
* an execution of a Java application, the hashCode method
* must consistently return the same integer...
* As far as is reasonably practical, the hashCode method defined
* by class Object returns distinct integers for distinct objects.
*/
@HotSpotIntrinsicCandidate
public native int hashCode();

```

如您所见，`equals()`方法的默认实现只比较指向存储对象的地址的内存引用。类似地，您可以从注释（引用自源代码）中看到，`hashCode()`方法为同一个对象返回相同的整数，为不同的对象返回不同的整数。让我们用`Person`类来演示它：

```java
public class Person {
    private int age;
    private String firstName, lastName;
    public Person(int age, String firstName, String lastName) {
        this.age = age;
        this.lastName = lastName;
        this.firstName = firstName;
    }
    public int getAge() { return age; }
    public String getFirstName() { return firstName; }
    public String getLastName() { return lastName; }
}
```

下面是默认的`equals()`和`hashCode()`方法的行为示例：

```java
Person person1 = new Person(42, "Nick", "Samoylov");
Person person2 = person1;
Person person3 = new Person(42, "Nick", "Samoylov");
System.out.println(person1.equals(person2)); //prints: true
System.out.println(person1.equals(person3)); //prints: false
System.out.println(person1.hashCode());      //prints: 777874839
System.out.println(person2.hashCode());      //prints: 777874839
System.out.println(person3.hashCode());      //prints: 596512129

```

`person1`和`person2`引用及其哈希码是相等的，因为它们指向相同的对象（内存的相同区域和相同的地址），而`person3`引用指向另一个对象。

但实际上，正如我们在第 6 章、“数据结构、泛型和流行工具”中所描述的，我们希望对象的相等性基于所有或部分对象属性的值，因此这里是`equals()`和`hashCode()`方法的典型实现：

```java
@Override
public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null) return false;
    if(!(o instanceof Person)) return false;
    Person person = (Person)o;
    return getAge() == person.getAge() &&
            Objects.equals(getFirstName(), person.getFirstName()) &&
            Objects.equals(getLastName(), person.getLastName());
}
@Override
public int hashCode() {
    return Objects.hash(getAge(), getFirstName(), getLastName());
}
```

它以前更复杂，但是使用`java.util.Objects`工具会更容易，特别是当您注意到`Objects.equals()`方法也处理`null`时。

我们已经将所描述的`equals()`和`hashCode()`方法的实现添加到`Person1`类中，并执行了相同的比较：

```java
Person1 person1 = new Person1(42, "Nick", "Samoylov");
Person1 person2 = person1;
Person1 person3 = new Person1(42, "Nick", "Samoylov");
System.out.println(person1.equals(person2)); //prints: true
System.out.println(person1.equals(person3)); //prints: true
System.out.println(person1.hashCode());      //prints: 2115012528
System.out.println(person2.hashCode());      //prints: 2115012528
System.out.println(person3.hashCode());      //prints: 2115012528

```

如您所见，我们所做的更改不仅使相同的对象相等，而且使具有相同属性值的两个不同对象相等。此外，哈希码值现在也基于相同属性的值。

在第 6 章、“数据结构、泛型和流行工具”中，我们解释了在实现`equals()`方法的同时实现`hasCode()`方法的重要性。

在`equals()`方法中建立等式和在`hashCode()`方法中进行散列计算时，使用完全相同的属性集是非常重要的。

将`@Override`注解放在这些方法前面可以确保它们确实覆盖`Object`类中的默认实现。否则，方法名中的输入错误可能会造成一种假象，即新的实现被使用了，而实际上它并没有被使用。事实证明，调试这种情况比仅仅添加`@Override`注解要困难和昂贵得多，如果该方法不覆盖任何内容，就会产生错误。

# `compareTo()`方法

在第 6 章、“数据结构、泛型和流行工具”中，我们广泛使用了`compareTo()`方法（`Comparable`接口的唯一方法），并指出基于该方法建立的顺序（通过集合元素实现）称为**自然顺序**。

为了证明这一点，我们创建了`Person2`类：

```java
public class Person2 implements Comparable<Person2> {
    private int age;
    private String firstName, lastName;
    public Person2(int age, String firstName, String lastName) {
        this.age = age;
        this.lastName = lastName;
        this.firstName = firstName;
    }
    public int getAge() { return age; }
    public String getFirstName() { return firstName; }
    public String getLastName() { return lastName; }
    @Override
    public int compareTo(Person2 p) {
        int result = Objects.compare(getFirstName(), 
                     p.getFirstName(), Comparator.naturalOrder());
        if (result != 0) {
            return result;
        }
        result = Objects.compare(getLastName(), 
                      p.getLastName(), Comparator.naturalOrder());
        if (result != 0) {
            return result;
        }
        return Objects.compare(age, p.getAge(), 
                                      Comparator.naturalOrder());
    }
    @Override
    public String toString() {
        return firstName + " " + lastName + ", " + age;
    }
}
```

然后我们组成一个`Person2`对象列表并对其进行排序：

```java
Person2 p1 = new Person2(15, "Zoe", "Adams");
Person2 p2 = new Person2(25, "Nick", "Brook");
Person2 p3 = new Person2(42, "Nick", "Samoylov");
Person2 p4 = new Person2(50, "Ada", "Valentino");
Person2 p6 = new Person2(50, "Bob", "Avalon");
Person2 p5 = new Person2(10, "Zoe", "Adams");
List<Person2> list = new ArrayList<>(List.of(p5, p2, p6, p1, p4, p3));
Collections.sort(list);
list.stream().forEach(System.out::println); 
```

结果如下：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/52c7cab4-96da-436c-a93a-2628ad9b13c1.png)

有三件事值得注意：

*   根据`Comparable`接口，`compareTo()`方法必须返回负整数、零或正整数，因为对象小于、等于或大于另一个对象。在我们的实现中，如果两个对象的相同属性的值不同，我们会立即返回结果。我们已经知道这个对象是*大*或*小*，不管其他属性是什么。但是比较两个对象的属性的顺序对最终结果有影响。它定义属性值影响顺序的优先级。
*   我们已将`List.of()`的结果放入`new ArrayList()`对象中。我们这样做是因为，正如我们在第 6 章、“数据结构、泛型和流行工具”中已经提到的，工厂方法`of()`创建的集合是不可修改的。不能在其中添加或删除任何元素，也不能更改元素的顺序，同时需要对创建的集合进行排序。我们使用了`of()`方法，只是因为它更方便并且提供了更短的表示法
*   最后，使用`java.util.Objects`进行属性比较，使得实现比定制编码更简单、更可靠。

在实现`compareTo()`方法时，重要的是确保不违反以下规则：

*   只有当返回值为`0`时，`obj1.compareTo(obj2)`才返回与`obj2.compareTo(obj1)`相同的值。
*   如果返回值不是`0`，则`obj1.compareTo(obj2)`与`obj2.compareTo(obj1)`符号相反。
*   如果`obj1.compareTo(obj2) > 0`和`obj2.compareTo(obj3) > 0`，那么`obj1.compareTo(obj3) > 0`。
*   如果`obj1.compareTo(obj2) < 0`和`obj2.compareTo(obj3) < 0`，那么`obj1.compareTo(obj3) < 0`。
*   若`obj1.compareTo(obj2) == 0`，则`obj2.compareTo(obj3)`与`obj1.compareTo(obj3) > 0`符号相同。
*   `obj1.compareTo(obj2)`和`obj2.compareTo(obj1)`抛出相同的异常（如果有的话）。

也建议，但并非总是要求，如果`obj1.equals(obj2)`那么`obj1.compareTo(obj2) == 0`，同时，如果`obj1.compareTo(obj2) == 0`那么`obj1.equals(obj2)`。

# `clone()`方法

`java.lang.Object`类中的`clone()`方法实现如下：

```java
@HotSpotIntrinsicCandidate
protected native Object clone() throws CloneNotSupportedException;

```

注释指出：

```java
/**
 * Creates and returns a copy of this object.  The precise meaning
 * of "copy" may depend on the class of the object.
 ***
```

此方法的默认结果按原样返回对象字段的副本，如果值是原始类型，则可以这样做。但是，如果对象属性包含对另一个对象的引用，则只复制引用本身，而不复制引用的对象本身。这就是为什么这种拷贝被称为**浅拷贝**。要获得一个**深度副本**，必须覆盖`clone()`方法并克隆引用对象的每个对象属性

在任何情况下，为了能够克隆一个对象，它必须实现`Cloneable`接口，并确保继承树上的所有对象（以及作为对象的属性）也实现`Cloneable`接口（除了`java.lang.Object`类）。`Cloneable`接口只是一个标记接口，它告诉编译器程序员有意识地决定允许克隆这个对象（无论是因为浅拷贝足够好还是因为`clone()`方法被覆盖）。试图对未实现`Cloneable`接口的对象调用`clone()`将导致`CloneNotSupportedException`。

这看起来已经很复杂了，但实际上，还有更多的陷阱。例如，假设`Person`类具有`Address`类类型的`address`属性。`Person`对象`p1`的浅拷贝`p2`将引用`Address`的同一对象，因此`p1.address == p2.address`。下面是一个例子。`Address`类如下：

```java
class Address {
    private String street, city;
    public Address(String street, String city) {
        this.street = street;
        this.city = city;
    }
    public void setStreet(String street) { this.street = street; }
    public String getStreet() { return street; }
    public String getCity() { return city; }
}
```

`Person3`类这样使用它：

```java
class Person3 implements Cloneable{
    private int age;
    private Address address;
    private String firstName, lastName;

    public Person3(int age, String firstName, 
                             String lastName, Address address) {
        this.age = age;
        this.address = address;
        this.lastName = lastName;
        this.firstName = firstName;
    }
    public int getAge() { return age; }
    public Address getAddress() { return address; }
    public String getLastName() { return lastName; }
    public String getFirstName() { return firstName; }
    @Override
    public Person3 clone() throws CloneNotSupportedException{
        return (Person3) super.clone();
    }
}
```

请注意，方法`clone`执行浅层复制，因为它不克隆`address`属性。下面是使用这种方法实现的结果：

```java
Person3 p1 = new Person3(42, "Nick", "Samoylov",
                             new Address("25 Main Street", "Denver"));
Person3 p2 = p1.clone();
System.out.println(p1.getAge() == p2.getAge());                // true
System.out.println(p1.getLastName() == p2.getLastName());      // true
System.out.println(p1.getLastName().equals(p2.getLastName())); // true
System.out.println(p1.getAddress() == p2.getAddress());        // true
System.out.println(p2.getAddress().getStreet());  //prints: 25 Main Street
p1.getAddress().setStreet("42 Dead End");
System.out.println(p2.getAddress().getStreet());  //prints: 42 Dead End

```

如您所见，克隆完成后，对源对象的`address`属性所做的更改将反映在克隆的相同属性中。这不是很直观，是吗？克隆的时候我们希望有独立的拷贝，不是吗？ 

为了避免共享`Address`对象，还需要显式地克隆它。为了做到这一点，必须使`Address`对象可克隆，如下所示：

```java
public class Address implements Cloneable{
    private String street, city;
    public Address(String street, String city) {
        this.street = street;
        this.city = city;
    }
    public void setStreet(String street) { this.street = street; }
    public String getStreet() { return street; }
    public String getCity() { return city; }
    @Override
    public Address clone() throws CloneNotSupportedException {
        return (Address)super.clone();
    }
}
```

有了这个实现，我们现在可以添加`address`属性克隆：

```java
class Person4 implements Cloneable{
    private int age;
    private Address address;
    private String firstName, lastName;
    public Person4(int age, String firstName, 
                             String lastName, Address address) {
        this.age = age;
        this.address = address;
        this.lastName = lastName;
        this.firstName = firstName;
    }
    public int getAge() { return age; }
    public Address getAddress() { return address; }
    public String getLastName() { return lastName; }
    public String getFirstName() { return firstName; }
    @Override
    public Person4 clone() throws CloneNotSupportedException{
        Person4 cl = (Person4) super.clone();
 cl.address = this.address.clone();
        return cl;
    }
}
```

现在，如果我们运行相同的测试，结果将与我们最初预期的一样：

```java
Person4 p1 = new Person4(42, "Nick", "Samoylov",
        new Address("25 Main Street", "Denver"));
Person4 p2 = p1.clone();
System.out.println(p1.getAge() == p2.getAge());                // true
System.out.println(p1.getLastName() == p2.getLastName());      // true
System.out.println(p1.getLastName().equals(p2.getLastName())); // true
System.out.println(p1.getAddress() == p2.getAddress());        // false
System.out.println(p2.getAddress().getStreet()); //prints: 25 Main Street
p1.getAddress().setStreet("42 Dead End");
System.out.println(p2.getAddress().getStreet()); //prints: 25 Main Street

```

因此，如果应用希望深度复制所有属性，那么所有涉及的对象都必须是可克隆的。只要没有相关的对象，无论是当前对象中的属性还是父类中的属性（以及它们的属性和父对象），在不使它们可克隆的情况下不获取新的对象属性，并且在容器对象的`clone()`方法中显式克隆，这是可以的。最后一句话很复杂。其复杂性的原因是克隆过程的潜在复杂性。这就是为什么程序员经常远离使对象可克隆的原因。

相反，如果需要，他们更喜欢手动克隆对象。例如：

```java
Person4 p1 = new Person4(42, "Nick", "Samoylov",
                              new Address("25 Main Street", "Denver"));
Address address = new Address(p1.getAddress().getStreet(), 
                                            p1.getAddress().getCity());
Person4 p2 = new Person4(p1.getAge(), p1.getFirstName(), 
                                            p1.getLastName(), address);
System.out.println(p1.getAge() == p2.getAge());                // true
System.out.println(p1.getLastName() == p2.getLastName());      // true
System.out.println(p1.getLastName().equals(p2.getLastName())); // true
System.out.println(p1.getAddress() == p2.getAddress());        // false
System.out.println(p2.getAddress().getStreet()); //prints: 25 Main Street
p1.getAddress().setStreet("42 Dead End");
System.out.println(p2.getAddress().getStreet()); //prints: 25 Main Street

```

如果向任何相关对象添加了另一个属性，这种方法仍然需要更改代码。但是，它提供了对结果的更多控制，并且发生意外后果的可能性更小。

幸运的是，`clone()`方法并不经常使用。事实上，你可能永远不会遇到使用它的需要。

# `StringBuffer`和`StringBuilder`类

我们在第 6 章、“数据结构、泛型和流行工具”中讨论了`StringBuffer`和`StringBuilder`类之间的区别。我们这里不重复了。相反，我们只会提到，在单线程进程（这是绝大多数情况下）中，`StringBuilder`类是首选，因为它更快。

# `try-catch-finally`

本书包含第 4 章、“处理”，专门介绍`try`、`catch`、`finally`子句的用法，这里不再赘述。我们只想再次重申，使用资源尝试语句是释放资源的首选方法（传统上是在`finally`块中完成的）。遵从库使代码更简单、更可靠。

# 最佳设计实践

术语*最佳*通常是主观的和上下文相关的。这就是为什么我们要披露以下建议是基于主流节目中的绝大多数案例。但是，不应盲目和无条件地遵循这些原则，因为在某些情况下，有些做法是无用的，甚至是错误的。在跟随他们之前，试着理解他们背后的动机，并将其作为你的决策指南。例如，大小很重要。如果应用不会超过几千行代码，那么一个简单的带有洗衣单样式代码的整体就足够了。但是，如果有复杂的代码包和几个人在处理它，如果一个特定的代码区域需要比其他区域更多的资源，那么将代码分解成专门的片段将有利于代码理解、维护甚至扩展。

我们将从没有特定顺序的更高层次的设计决策开始。

# 确定松散耦合的功能区域

这些设计决策可以很早就做出，仅仅是基于对未来系统的主要部分、它们的功能以及它们产生和交换的数据的一般理解。这样做有几个好处：

*   对未来系统结构的识别，对进一步的设计步骤和实现有影响
*   部件的专业化和深入分析
*   部件并行开发
*   更好地理解数据流

# 将功能区划分为传统层

在每个功能区就绪后，可以根据所使用的技术方面和技术进行特化。技术专业化的传统分离是：

*   前端（用户图形或 Web 界面）
*   具有广泛业务逻辑的中间层
*   后端（数据存储或数据源）

这样做的好处包括：

*   按层部署和扩展
*   基于专业知识的程序员专业化
*   部件并行开发

# 面向接口编程

基于前两小节中描述的决策的专用部分必须在隐藏实现细节的接口中描述。这种设计的好处在于面向对象编程的基础，在第 2 章、“Java 面向对象编程（OOP）”中有详细的描述，所以这里不再重复。

# 使用工厂

我们在[第二章](02.html)“Java 面向对象编程（OOP）”中也谈到了这一点。根据定义，接口不描述也不能描述实现接口的类的构造器。使用工厂可以缩小这个差距，只向客户端公开一个接口

# 优先组合而不是继承

最初，面向对象编程的重点是继承，作为在对象之间共享公共功能的方式。继承甚至是我们在第 2 章、“Java 面向对象编程（OOP）”中所描述的四个面向对象编程原则之一。然而，实际上，这种功能共享方法在同一继承行中包含的类之间创建了太多的依赖关系。应用功能的演化通常是不可预测的，继承链中的一些类开始获取与类链的原始目的无关的功能。我们可以说，有一些设计解决方案允许我们不这样做，并保持原始类完好无损。但是，在实践中，这样的事情总是发生，子类可能会突然改变行为，仅仅因为它们通过继承获得了新的功能。我们不能选择我们的父项，对吗？此外，封装方式是封装的另一个基础原则。

另一方面，组合允许我们选择和控制类的哪些功能可以使用，哪些可以忽略。它还允许对象保持轻，而不受继承的负担。这样的设计更灵活、更可扩展、更可预测。

# 使用库

在整本书中，我们多次提到使用 **Java 类库**（**JCL**）、**Java 开发工具包**（**JDK**）和外部 Java 库可以使编程变得更简单，并生成更高质量的代码。甚至还有一个专门的章节，第 7 章、“Java 标准和外部库”，其中概述了最流行的 Java 库。创建库的人会投入大量的时间和精力，所以你应该随时利用他们。

在第 13 章、“函数式编程”中，我们描述了驻留在 JCL 的`java.util.function`包中的标准函数式接口。这是另一种利用库的方法，使用一组众所周知的共享接口，而不是定义自己的接口。

这最后一句话是本章下一个主题的一个很好的过渡，这个主题是关于编写其他人容易理解的代码。

# 代码是为人编写的

最初几十年的编程需要编写机器命令，以便电子设备能够执行这些命令。这不仅是一项繁琐且容易出错的工作，而且还要求您以产生最佳性能的方式编写指令，因为计算机速度很慢，而且根本没有进行太多代码优化。

从那时起，我们在硬件和编程方面都取得了很大的进步。现代编译器在使提交的代码尽可能快地工作方面走了很长的路，即使程序员没有考虑它。我们在上一章第 1 章第 7 章“Java 微基准线束”中用具体的例子进行了讨论

它允许程序员编写更多的代码行，而不用考虑太多优化问题。但是传统和许多关于编程的书籍仍然需要它，一些程序员仍然担心他们的代码性能，而不是它产生的结果。遵循传统比脱离传统容易。这就是为什么程序员往往更关注他们编写代码的方式，而不是他们自动化的业务，尽管实现错误业务逻辑的好代码是无用的。

不过，回到话题上来。在现代 JVM 中，程序员对代码优化的需求不像以前那么迫切了。如今，程序员必须主要关注全局，以避免导致代码性能差和代码被多次使用的结构性错误。当 JVM 变得更复杂时，后者就变得不那么紧迫了，实时地观察代码，当用相同的输入多次调用相同的代码块时，只返回结果（不执行）。

这给我们留下了唯一可能的结论：在编写代码时，我们必须确保它对人类来说是容易阅读和理解的，而不是对计算机来说。那些在这个行业工作了一段时间的人对几年前自己编写的代码感到困惑。一种是通过清晰和透明的意图来改进代码编写风格。

我们可以讨论注释的必要性，直到奶牛回到谷仓。我们绝对不需要注释来直接响应代码的功能。例如：

```java
//Initialize variable
int i = 0;
```

解释意图的注释更有价值：

```java
// In case of x > 0, we are looking for a matching group 
// because we would like to reuse the data from the account.
// If we find the matching group, we either cancel it and clone,
// or add the x value to the group, or bail out.
// If we do not find the matching group,
// we create a new group using data of the matched group.
```

注释代码可能非常复杂。好的注释解释了意图并提供了帮助我们理解代码的指导。然而，程序员通常不会费心去写注释。反对写注释的论据通常包括两种：

*   注释必须与代码一起维护和发展，否则，它们可能会产生误导，但是没有工具可以提示程序员在更改代码的同时调整注释。因此，注释是危险的。
*   代码本身的编写（包括变量和方法的名称选择）不需要额外的解释。

这两种说法都是正确的，但注释也确实非常有用，尤其是那些抓住意图的注释。此外，这样的注释往往需要较少的调整，因为代码意图不会经常更改（如果有的话）。

# 测试是获得高质量代码的最短路径

我们将讨论的最后一个最佳实践是这样的陈述：*测试不是一项开销或一项负担；它是程序员成功的指南*。唯一的问题是什么时候写测试

有一个令人信服的论点，要求在编写任何一行代码之前编写一个测试。如果你能做到，那就太好了。我们不会劝你放弃的。但是，如果您不这样做，请尝试在编写完一行或所有被指定编写的代码之后开始编写测试。

实际上，许多经验丰富的程序员发现在实现了一些新功能之后开始编写测试代码是很有帮助的，因为这是程序员更好地理解新代码如何适合现有上下文的时候。他们甚至可能尝试对一些值进行编码，以查看新代码与调用新方法的代码集成的程度。在确保新代码集成良好之后，程序员可以继续实现和调优新的代码，并根据调用代码上下文中的需求测试新实现。

必须添加一个重要的限定条件：在编写测试时，最好不是由您来设置输入数据和测试标准，而是由分配给您任务的人或测试人员来设置。根据代码生成的结果设置测试是众所周知的程序员陷阱。客观的自我评估并不容易，如果可能的话

# 总结

在本章中，我们讨论了主流程序员每天遇到的 Java 习惯用法。我们还讨论了最佳设计实践和相关建议，包括代码编写风格和测试。

在本章中，读者了解了与某些特性、功能和设计解决方案相关的最流行的 Java 习惯用法。这些习语通过实际例子进行了演示，读者已经学会了如何将它们融入到自己的代码中，以及如何使用专业语言与其他程序员进行交流

在下一章中，我们将向读者介绍为 Java 添加新特性的四个项目：Panama、Valhalla、Amber 和 Loom。我们希望它能帮助读者了解 Java 开发，并设想未来版本的路线图。

# 测验

1.  选择所有正确的语句：
    1.  习语可以用来传达代码意图。
    2.  习语可以用来解释代码的作用。
    3.  习语可能被误用，使谈话的主题模糊不清。
    4.  为了表达清楚，应该避免使用习语。

2.  是否每次执行`equals()`时都需要执行`hasCode()`？
3.  如果`obj1.compareTo(obj2)`返回负值，这是什么意思？
4.  深度复制概念是否适用于克隆期间的原始类型值？
5.  哪个更快，`StringBuffer`还是`StringBuilder`？
6.  面向接口编程有什么好处？
7.  使用组合和继承有什么好处？
8.  与编写自己的代码相比，使用库的优势是什么？
9.  你的代码的目标受众是谁？
10.  是否需要测试？

# 十九、Java 新特性

在本章中，读者将了解当前最重要的项目，这些项目将为 Java 添加新特性并在其他方面增强它。阅读本章之后，读者将了解如何遵循 Java 开发，并将设想未来 Java 发行版的路线图。如果需要，读者也可以成为 JDK 源代码贡献者。

本章将讨论以下主题：

*   Java 的继续发展
*   Panama 项目
*   Valhalla 项目
*   Amber 项目
*   Loom 项目
*   Skara 项目

# Java 继续发展

这对任何 Java 开发人员来说都是最好的消息：Java 得到了积极的支持，并不断得到增强，以跟上行业的最新需求。这意味着，无论你听到什么关于其他语言和最新技术的消息，你都会很快得到添加到 Java 中的最佳特性和功能。每半年发布一次新的时间表，你可以放心，新增加的内容一旦证明是有用和实用的，就会发布

在考虑设计一个新的应用或新的功能以添加到现有的应用时，了解 Java 在不久的将来如何增强是很重要的。这些知识可以帮助您设计新代码，使之更容易适应新的 Java 函数，并使您的应用更简单、更强大。对于一个主流程序员来说，遵循所有的 **JDK 增强建议**（**JEP**）可能是不切实际的，因为必须遵循太多不同的讨论和开发线程。相比之下，掌握您感兴趣的领域中的一个 Java 增强项目要容易得多。你甚至可以尝试作为某一领域的专家或只是作为感兴趣的一方为这样的项目做出贡献。

在本章中，我们将回顾我们认为最重要的五个 Java 增强项目：

*   **Panama 项目**：关注与非 Java 库的互操作性
*   **Valhalla 项目**：围绕引入新的值类型和相关的泛型增强而构思
*   **Amber 项目**：包括 Java 语言扩展的各种工作，包括数据类、模式匹配、原始字符串文本、简明方法体和 Lambda 增强，这些都是最重要的子项目
*   **Loom 项目**：解决了名为**纤程**的轻量级线程的创建问题，并简化了异步编码

# Panama 项目

在整本书中，我们建议使用各种 Java 库—标准的 **Java 类库**（**JCL**）和外部 Java 库，这些库有助于提高代码质量并缩短开发时间。但是应用也可能需要非 Java 外部库。近年来，随着人们对使用机器学习算法进行数据处理的需求不断增长，这种需求也随之增加。例如，将这些算法移植到 Java 并不总是能跟上人脸识别、视频中人类行为分类和跟踪摄像机运动等领域的最新成果。

现有的利用不同语言编写的库的机制是 **Java 本机接口**（**JNI**）、**Java 本机访问**（**JNA**）和 **Java 本机运行时**（**JNR**）。尽管有这些功能，访问本机代码（为特定平台编译的其他语言的代码）并不像使用 Java 库那么容易。此外，它限制了 **Java 虚拟机**（**JVM**）的代码优化，经常需要用 C 语言编写代码

[**Panama** 项目](https://openjdk.java.net/projects/panama)为了解决这些问题，包括 C++ 功能的支持。作者使用的术语是**外部库**。这个术语包括所有其他语言的库。新方法背后的思想是使用一个名为 **jextract** 的工具将本机头翻译成相应的 Java 接口。生成的接口允许直接访问本机方法和数据结构，而无需编写 C 代码。

毫不奇怪，支持类计划存储在`java.foreign`包中。

在撰写本文时（2019 年 3 月），Panama 早期的 access 构建基于不完整的 Java13 版本，面向专家用户。预计它可以将为本机库创建 Java 绑定的工作量减少 90%，生成的代码的执行速度至少是 JNI 的四到五倍。

# Valhalla 项目

[**Valhalla 项目**](https://openjdk.java.net/projects/valhalla)源于这样一个事实，即自从 Java 在大约 25 年前首次引入以来，硬件已经发生了变化，当时做出的决定在今天会有不同的结果。例如，从内存获取值的操作和算术操作在性能时间方面产生的成本大致相同。如今，情况发生了变化。内存访问比算术运算长 200 到 1000 倍。这意味着涉及原始类型的操作要比基于它们的包装类型的操作便宜得多。

当我们使用两个基本类型做一些事情时，我们获取值并在操作中使用它们。当我们对包装器类型执行相同的操作时，我们首先使用引用来访问对象（相对于 20 年前的操作本身，对象现在要长得多），只有这样我们才能获取值。这就是为什么 Valhalla 项目试图为引用类型引入一个新的**值**类型，它提供了对值的访问，而无需使用引用，就像原始类型通过值可用一样。

它还将节省内存消耗和包装数组的效率。现在，每个元素将由一个值表示，而不是由引用表示。

这样的解决方案从逻辑上引出了泛型问题。今天，泛型只能用于包装类型。我们可以写`List<Integer>`，但不能写`List<int>`。这也是 Valhalla 项目准备解决的问题。它将扩展泛型类型，以支持泛型类和接口在原始类型上的特化。扩展也允许在泛型中使用原始类型。

# Amber 项目

[**Amber 项目**](https://openjdk.java.net/projects/amber)专注于小型 Java 语法增强，使其更具表现力、简洁性和简单性。这些改进将提高 Java 程序员的工作效率，并使他们的代码编写更加愉快

Amber 项目创建的两个 Java 特性已经交付，我们讨论了它们：

*   类型保持架`var`（参见第 1 章、“Java12 入门”）从 Java10 开始使用。
*   Java11 中增加了 Lambda 参数的局部变量语法（参见第 13 章、“函数式编程”。
*   不太详细的`switch`语句（参见第 1 章、“Java12 入门”）是作为 Java12 的预览特性引入的。

未来的 Java 版本还将发布其他新特性。在下面的小节中，我们将只仔细研究其中的五个：

*   数据类
*   模式匹配
*   原始字符串
*   简明方法体
*   Lambda 表达式

# 数据类

有些类只携带数据。它们的目的是将几个值放在一起，而不是其他值。例如：

```java
public class Person {
    public int age;
    public String firstName, lastName;

    public Person(int age, String firstName, String lastName) {
        this.age = age;
        this.lastName = lastName;
        this.firstName = firstName;
    }
}
```

它们还可能包括`equals()`、`hashCode()`和`toString()`方法的标准集，如果是这样的话，为什么还要为这些方法编写实现呢？它们可以自动生成—就像您的 IDE 现在可以这样做一样。这就是名为**数据类**的新实体背后的思想，可以简单地定义如下：

```java
record Person(int age, String firstName, String lastName) {}
```

默认情况下，其余的将假定为存在

但是，[正如 Brian Goetz 所写](https://cr.openjdk.java.net/~briangoetz/amber/datum.html)，问题来了：

“它们是可扩展的吗？字段是可变的吗？我可以控制生成的方法的行为或字段的可访问性吗？我可以添加其他字段和构造器吗？”

——布莱恩·戈茨

正是在这种情况下，这一思想的当前状态正处于试图限制范围，并仍然为语言提供价值的中间阶段。

敬请关注

# 模式匹配

几乎每个程序员都会时不时地遇到需要根据值的类型切换到不同的值处理的情况。例如：

```java
SomeClass someObj = new SomeClass();
Object value = someOtherObject.getValue("someKey");
if (value instanceof BigDecimal) {
    BigDecimal v = (BigDecimal) value;
    BigDecimal vAbs = v.abs();
    ...
} else if (value instanceof Boolean) {
    Boolean v = (Boolean)value;
    boolean v1 = v.booleanValue();
    ...
} else if (value instanceof String) {
    String v = (String) value;
    String s = v.substring(3);
    ...
}
...
```

在编写这样的代码时，您很快就会感到厌烦。这就是模式匹配要解决的问题。实现该功能后，可以将前面的代码示例更改为如下所示：

```java
SomeClass someObj = new SomeClass();
Object value = someOtherObject.getValue("someKey");
if (value instanceof BigDecimal v) {
    BigDecimal vAbs = v.abs();
    ...
} else if (value instanceof Boolean v) {
    boolean v1 = v.booleanValue();
    ...
} else if (value instanceof String v) {
    String s = v.substring(3);
    ...
}
...
```

很好，不是吗？它还将支持内联版本，如以下版本：

```java
if (value instanceof String v && v.length() > 4) {
    String s = v.substring(3);
    ...
}
```

这个新的语法将首先在一个`if`语句中被允许，然后再添加到一个`switch`语句中。

# 原始字符串

偶尔，您可能希望缩进一个输出，因此它看起来像这样，例如：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/ec003b46-eb9b-4375-b3eb-90f69817ed18.png)

要实现这一点，代码如下所示：

```java
String s = "The result:\n" +
           "   - the symbol A was not found;\n" +
           "   - the type of the object was not Integer either.";
System.out.println(s); 
```

添加新的*原始字符串字面值*后，相同的代码可以更改为如下所示：

```java
String s = `The result:
               - the symbol A was not found;
               - the type of the object was not Integer either.
           `;
System.out.println(s); 
```

这样，代码看起来就不那么杂乱，更容易编写。也可以使用`align()`方法将原始字符串文本与左边距对齐，使用`indent(int n)`方法设置缩进值，并使用`align(int indent)`方法设置对齐后的缩进值。

类似地，将字符串放在符号（`` ` ``）内将允许我们避免使用转义指示符反斜杠（`\`）。例如，在执行命令时，当前代码可能包含以下行：

```java
Runtime.getRuntime().exec("\"C:\\Program Files\\foo\" bar");

```

使用原始字符串字面值，可以将同一行更改为以下内容：

```java
Runtime.getRuntime().exec(`"C:\Program Files\foo" bar`);

```

同样，它更容易写和读。

# 简明方法体

Lambda 表达式语法终止了这个特性的概念，它可以非常紧凑。例如：

```java
Function<String, Integer> f = s -> s.length();
```

或者，使用方法引用，可以表示得更短：

```java
Function<String, Integer> f = String::length;
```

这种方法的逻辑扩展是：为什么不对标准获取器应用相同的速记风格呢？看看这个方法：

```java
String getFirstName() { return firstName; }
```

可以简单地缩短为以下形式：

```java
String getFirstName() -> firstName;
```

或者，考虑该方法使用其他方法时的情况：

```java
int getNameLength(String name) { return name.length(); }
```

也可以通过方法引用来缩短，如下所示：

```java
int getNameLength(String name) = String::length;
```

但是，在撰写本文（2019 年 3 月）时，该提案仍处于早期阶段，在最终版本中，许多内容可以更改。

# Lambda 改进

Amber 项目计划向 Lambda 表达式语法添加三个内容：

*   隐藏局部变量
*   函数表达式的更好消歧
*   使用下划线表示未使用的参数

# 使用下划线而不是参数名

在许多其他编程语言中，Lambda 表达式中的下划线（`_`表示未命名的参数。在 Java9 将下划线用作标识符定为非法之后，Amber 项目计划在当前实现实际上不需要该参数的情况下将其用作 Lambda 参数。例如，看看这个函数：

```java
BiFunction<Integer, String, String> f = (i, s) -> s.substring(3);
```

参数（`i`在函数体中没有使用，但是我们仍然提供标识符作为占位符

使用新的添加项，可以将其替换为下划线，从而避免使用标识符并指示从未使用参数：

```java
BiFunction<Integer, String, String> f = (_, s) -> s.substring(3);
```

这样，就很难忽略一个输入值没有被使用的事实。

# 隐藏局部变量

目前，不可能为 Lambda 表达式的参数指定与在本地上下文中用作标识符的名称相同的名称。例如：

```java
int i = 42;
//some other code
BiFunction<Integer, String, String> f = (i, s) -> s.substring(3); //error

```

在将来的版本中，这样的名称重用是可能的。

# 更好地消除函数表达式的歧义

在撰写本文时，可以按如下方式重载方法：

```java
void method(Function<String, String> fss){
    //do something
}
void method(Predicate<String> predicate){
    //do something
}
```

但是，只能通过显式定义传入函数的类型来使用它：

```java
Predicate<String> pred = s -> s.contains("a");
method(pred);

```

尝试将其与内联 Lambda 表达式一起使用将失败：

```java
method(s -> s.contains("a"));   // compilation error
```

编译器抱怨，因为它无法解决一个歧义，因为两个函数都有一个相同类型的输入参数，并且只有在涉及到`return`类型时才不同。

Amber 项目可能会解决这个问题，但是最终的决定还没有做出，因为这取决于这个建议对编译器实现的影响

# Loom 项目

[**Loom**](https://openjdk.java.net/projects/loom) 可能是本章中列出的能够提升 Java 能力的最重要的项目。从大约 25 年前的早期开始，Java 就提供了一个相对简单的多线程模型和一个定义良好的同步机制。我们在第 8 章、“多线程和并发处理”中进行了描述。这种简单性，以及 Java 的整体简单性和安全性，是 Java 成功的主要因素之一。Java Servlet 允许处理许多并发请求，并且是基于 Java 的 HTTP 服务器的基础。

Java 中的线程是基于 OS 内核线程的，这是一个通用线程。但是内核操作系统线程也被设计用来执行许多不同的系统任务。它使得这样的线程对于特定应用的业务需求来说过于繁重（需要太多的资源）。满足应用接收的请求所需的实际业务操作通常不需要所有线程功能。这意味着当前的线程模型限制了应用的能力。为了估计这个限制有多强，我们可以观察到，现在的 HTTP 服务器可以处理超过一百万个并发打开的套接字，而 JVM 不能处理超过几千个。

这就是引入异步处理的动机，尽量少地使用线程，而引入轻量级处理工作者。我们在第 15 章、“反应式编程”和第 16 章、“微服务”中讨论过。异步处理模型工作得很好，但是它的编程并不像其他 Java 编程那样简单。它还需要大量的工作来与基于线程的遗留代码集成，甚至需要更多的工作来迁移遗留代码以采用新模型

添加这样的复杂性使得 Java 不像以前那么容易学习，而 Loom 项目将通过使 Java 更加轻量级来重新使用 Java 并发处理的简单性。

该项目计划向 Java 添加一个新类`Fiber`，以支持由 JVM 管理的轻量级线程构造。纤程占用的资源要少得多。它们也几乎没有或几乎没有上下文切换的开销，当一个线程挂起时，另一个线程必须启动或继续它自己的由于 CPU 时间共享或类似原因而挂起的作业。当前线程的上下文切换是性能受限的主要原因之一。

为了让您了解与线相比，纤程有多轻，织机开发商罗恩·普雷斯勒（Ron Pressler）和艾伦·贝特曼（Alan Bateman）[提供了以下数字](http://cr.openjdk.java.net/~rpressler/loom/JVMLS2018.pdf)：

*   **线程**：
    *   通常为栈保留 1 MB+16 KB 的内核数据结构
    *   每个启动线程约 2300 字节，包括**虚拟机**（**VM**）元数据
*   **纤程**：
    *   延续栈：数百字节到 KBs
    *   当前原型中每个纤程 200-240 字节

如您所见，我们希望并行处理的性能会有显著的改进。

术语**延续**并不新鲜。在*纤程*之前使用。它表示*一个顺序执行的指令序列，可以挂起自身*。并发处理器的另一部分是**调度器**，它将延续分配给 CPU 核心，将暂停的一个替换为准备运行的另一个，并确保准备恢复的延续最终将分配给 CPU 核心。当前的线程模型也有一个延续和一个调度器，即使它们并不总是作为 API 公开。Loom 项目打算将延续和调度器分开，并在它们之上实现 Java 纤程。现有的`ForkJoinPool`可能会用作纤程

[您可以在项目提案](https://cr.openjdk.java.net/~rpressler/loom/Loom-Proposal.html)中阅读更多关于 Loom 项目动机和目标的信息，这对于任何 Java 开发人员来说都是一本相对简单且非常有启发性的读物。

# Skara 项目

[**Skara**](http://openjdk.java.net/projects/skara) 没有向 Java 添加新特性。它的重点是改进对 JDK 的 Java 源代码的访问

现在要访问源代码，需要从 Mercurial 存储库下载并手动编译。Skara 项目的目标是将源代码迁移到 Git，因为 Git 现在是最流行的源代码存储库，而且许多程序员已经在使用它了。如您所知，本书中示例的源代码也存储在 GitHub 上

[你可以在 GitHub 中看到 Skara 项目的当前结果](https://github.com/Project-Skara/jdk)。它仍然使用 JDK Mercurial 存储库的镜像。但是，在未来，它将变得更加独立。

# 总结

在本章中，读者了解了增强 JDK 的当前最重要的项目。我们希望您能够理解如何遵循 Java 开发，并且已经设想了未来 Java 发行版的路线图 https://openjdk.java.net/projects）你也可以看看。我们还希望您对成为一名高效的 JDK 源代码贡献者和活跃的社区成员的前景感到足够的兴奋。欢迎光临！

# 二十、答案

# 第 1 章：Java12 入门 

1.  c） Java 开发工具包
2.  b） Java 类库
3.  d） Java 标准版
4.  b） 集成开发环境
5.  a） 项目建设，b）项目配置，c）项目文件
6.  a） 布尔值，b）数字
7.  a） `long`，c）`short`，d）`byte`
8.  d） 值表示
9.  a） `\\`，b）`2_0`，c）`2__0f`，d）`\f`
10.  a） `%`、c）`&`、d）`->`
11.  a） 0
12.  b） 否，否
13.  d） 4
14.  c） 编译错误
15.  b） 2
16.  a、c、d
17.  d） `20 -1`
18.  c） `x`值在 11 范围内
19.  c） 结果为 32
20.  a） 可以声明变量，b）可以指定变量
21.  b） 选择语句，d）增量语句

# 第 2 章：Java 面向对象编程（OOP）

1.  a、d 
2.  b、c、d
3.  a、b、c 
4.  a、c、d
5.  d
6.  c、d 
7.  a、b 
8.  b、d 
9.  d
10.  b
11.  a、c 
12.  b、c、d
13.  a、b 
14.  b、c 
15.  b、c、d
16.  b、c 
17.  c
18.  a、b、c 
19.  b、c、d
20.  a、c 
21.  a、c、d

# 第 3 章：Java 基础

1.  a、d 
2.  c、d 
3.  a、b、d
4.  a、c、d
5.  a、c 
6.  a、b、d
7.  a、b、c、d
8.  c、d 
9.  d
10.  c
11.  b
12.  c

# 第 4 章：异常处理

1.  a、b、c 
2.  b
3.  c
4.  a、b、c、d
5.  1
6.  a、c 
7.  d

# 第 5 章：字符串、输入/输出和文件

1.  b
2.  c
3.  b
4.  1
5.  d
6.  a、c、d
7.  c
8.  d
9.  a、b、c 
10.  c、d（注意使用`mkdir()`方法代替`mkdirs()`）

# 第 6 章：数据结构、泛型和流行工具

1.  d
2.  b、d 
3.  a、b、c、d
4.  a、b、c、d
5.  a、b、d
6.  a、b、c 
7.  c
8.  a、b、c、d
9.  b、d 
10.  b
11.  b、c 
12.  1
13.  c
14.  d
15.  b
16.  c
17.  1
18.  b
19.  c

# 第 7 章：Java 标准和外部库

1.  a、b、c 
2.  a、b、d
3.  b、c 
4.  b、d 
5.  a、c 
6.  a、b、c、d
7.  b、c、d
8.  b、c 
9.  b
10.  c、d 
11.  a、c 
12.  b、d 
13.  a、d 
14.  b、c、d
15.  a、b、d
16.  b、d 

# 第 8 章：多线程和并发处理

1.  a、c、d
2.  b、c、d
3.  1
4.  a、c、d
5.  b、c、d
6.  a、b、c、d
7.  c、d 
8.  a、b、c 
9.  b、c 
10.  b、c、d
11.  a、b、c 
12.  b、c 
13.  b、c 

# 第 9 章：JVM 结构和垃圾收集

1.  b、d 
2.  c
3.  d
4.  b、c 
5.  a、d 
6.  c
7.  a、b、c、d
8.  a、c、d
9.  b、d 
10.  a、b、c、d
11.  1
12.  a、b、c 
13.  a、c 
14.  a、c、d
15.  b、d 

# 第 10 章：管理数据库中的数据

1.  c
2.  a、d 
3.  b、c、d
4.  a、b、c、d
5.  a、b、c 
6.  a、d 
7.  a、b、c 
8.  a、c 
9.  a、c、d
10.  a、b 
11.  a、d 
12.  a、b、d
13.  a、b、c 

# 第 11 章：网络编程

1.  正确答案可能包括 FTP、SMTP、HTTP、HTTPS、WebSocket、SSH、Telnet、LDAP、DNS 或其他一些协议
2.  正确的答案可能包括 UDP、TCP、SCTP、DCCP 或其他协议
3.  `java.net.http`
4.  UDP 协议
5.  是的
6.  `java.net`
7.  传输控制协议
8.  它们是同义词
9.  按源的 IP 地址和端口以及目标的 IP 地址和端口
10.  `ServerSocket`无需客户端运行即可使用。它只是在指定的端口上“监听”
11.  UDP 协议
12.  传输控制协议
13.  正确答案可能包括 HTTP、HTTPS、Telnet、FTP 或 SMTP
14.  a、c、d
15.  它们是同义词
16.  它们是同义词
17.  `/something/something?par=42`
18.  正确答案可能包括二进制格式、标头压缩、多路复用或推送功能
19.  `java.net.http.HttpClient`
20.  `java.net.http.WebSocket`
21.  不是区别
22.  `java.util.concurrent.CompletableFuture`

# 第 12 章：Java GUI 编程

1.  舞台
2.  节点
3.  应用
4.  `void start(Stage pm)`
5.  `static void launch(String... args)`
6.  `--module-path`和`--add-modules`
7.  `void stop()`
8.  `WebView`
9.  `Media MediaPlayer MediaView`
10.  `--add-exports`
11.  以下列表中的任意五个：`Blend`、`Bloom`、`BoxBlur`、`ColorAdjust`、`DisplacementMap`、`DropShadow`、`Glow`、`InnerShadow`、`Lighting`、`MotionBlur`、`PerspectiveTransform`、`Reflection`、`ShadowTone`、`SepiaTone`

# 第 13 章：函数式编程

1.  c
2.  a、d
3.  1
4.  `void`
5.  1
6.  `boolean`
7.  不是
8.  `T`
9.  1
10.  `R`
11.  闭包上下文
12.  `Location::methodName`

# 第 14 章：Java 标准流

1.  a、b
2.  `of()`无参数产生空流
3.  `java.util.Set`
4.  135
5.  42
6.  2121
7.  不是，但是它扩展了函数式接口`Consumer`，可以这样传递
8.  不是
9.  3
10.  1.5
11.  `"42, X, a"`
12.  编译错误，因为`peek()`不能返回任何内容
13.  2
14.  另一个目标
15.  `"a"`
16.  1
17.  `filter()`、`map()`和`flatMap()`中的任何一个
18.  `distinct()`、`limit()`、`sorted()`、`reduce()`和`collect()`中的任何一个

# 第 15 章：反应式编程

1.  a、b、c 
2.  是的
3.  无阻塞输入/输出
4.  不
5.  反应式扩展
6.  `java.util.concurrent`
7.  a、d
8.  阻塞运算符名称以“阻塞”开头
9.  一个热的可观测物体以它自己的速度发射值。一个冷的可观察对象在上一个值到达终端操作符之后发出下一个值
10.  可观察对象停止发射值，管道停止运行
11.  a、c、d
12.  例如，以下任意两个：`buffer()`、`flatMap()`、`groupBy()`、`map()`、`scan()`、`window()`

13.  例如，以下任意两个：`debounce()`、`distinct()`、`elementAt(long n)`、`filter()`、`firstElement()`、`ignoreElements()`、`lastElement()`、`sample()`、`skip()`、`take()`
14.  删除过多的值，获取最新值，使用缓冲区
15.  `subscribeOn()``observeOn()``fromFuture()`

# 第 16 章：微服务

1.  a、c
2.  是的
3.  与传统应用的方式相同，而且它们通常有自己的通信方式（例如，使用事件总线）
4.  列表中的任意两个：Akka，Dropwizard，Jodd，Lightbend Lagom，Ninja，Spotify Apollo，Vert.x。
5.  实现接口`io.vertx.core.Verticle`的类
6.  `Send`只向一个注册地址的接收器发送消息；`publish`向所有注册地址相同的接收器发送消息
7.  它使用循环算法
8.  是的
9.  <https://vertx.io/>

# 第 17 章：Java 微基准线束

1.  b、c、d
2.  将对 JMH 的依赖添加到项目中（如果手动运行，则添加类路径），并将注解`@Benchmark`添加到要测试性能的方法中
3.  作为`main`方法使用带有显式命名的主类的 Java 命令，作为`main`方法使用带有可执行的`.jar`文件的 Java 命令，并且使用 IDE 运行作为`main`方法或者使用插件并运行单个方法
4.  以下任意两项：`Mode.AverageTime`、`Mode.Throughput`、`Mode.SampleTime`、`Mode.SingleShotTime`

5.  以下任意两项：`TimeUnit.NANOSECONDS`、`TimeUnit.MICROSECONDS`、`TimeUnit.MILLISECONDS`、`TimeUnit.SECONDS`、`TimeUnit.MINUTES`、`TimeUnit.HOURS`、`TimeUnit.DAYS`
6.  使用带有注解`@State`的类的对象
7.  使用`state`属性前面的注解`@Param`
8.  使用注解`@CompilerConrol`
9.  使用消耗生成结果的类型为`Blackhole`的参数
10.  使用注解`@Fork`

# 第 18 章：编写高质量代码的最佳实践

1.  a、b、c
2.  一般来说，这是推荐的，但不是必需的。但在某些情况下，例如，将要在基于哈希的数据结构中放置和搜索类的对象时，它是必需的
3.  `obj1`小于`obj2`
4.  不
5.  `StringBuilder`
6.  允许在不更改客户端代码的情况下更改实现
7.  对代码演化的更多控制和适应变化的代码灵活性
8.  更可靠的代码，更快的编写，更少的测试，更容易让其他人理解
9.  其他将要维护您的代码的程序员，以及稍后的您
10.  不，但对你很有帮助