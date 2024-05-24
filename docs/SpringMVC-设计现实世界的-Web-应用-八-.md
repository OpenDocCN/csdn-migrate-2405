# SpringMVC：设计现实世界的 Web 应用（八）

> 原文：[`zh.annas-archive.org/md5/AB3510E97B9E20602840C849773D49C6`](https://zh.annas-archive.org/md5/AB3510E97B9E20602840C849773D49C6)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十五章：通过 WebSockets 和 STOMP 进行通信

本章涵盖了四个配方。它们都充分拥抱了我们的 CloudStreet Market 应用程序。通过改进，使其更具反应性，更具互动性。

这些配方有以下标题：

+   使用 STOMP 通过 SockJS 流式传输社交事件

+   使用 RabbitMQ 作为多协议消息代理

+   在 RabbitMQ 中堆叠和消费任务与 AMQP

+   使用 Spring Session 和 Redis 保护消息

# 介绍

让我们快速回顾一下在前几章中希望你已经学到的内容。逐章，你必须已经发现：

+   如何启动一个项目，以及如何依赖标准来保持代码库的可扩展性和适应性。这些标准来自于一系列工具的选择，例如 Maven 或 Java Persistence API。所呈现的标准还伴随着一系列常见实践，例如在客户端，使用 AngularJS MVC 模式或 Bootstrap Framework UI。

+   如何在面对现代挑战时充分利用 Spring MVC。Spring MVC 已被证明是一个 Web MVC 框架（具有其请求流程、内容协商、视图解析、模型绑定、异常处理等），但也作为 Spring 环境中集成的 Spring 组件进行了演示。它是一个集成框架，能够传递 Spring Security 身份验证或 Spring Social 抽象。它还能够提供 Spring Data 分页工具以及对 HTTP 规范的竞争性实现。

+   如何设计一个实现高级无状态和超媒体 API 的微服务架构，促进职责的分离。前端和后端之间的职责分离，以及组件的功能可分割性（水平可伸缩性）在独立的 Web 存档（`.war`）中的职责分离。

本章重点介绍新兴的 WebSocket 技术以及为我们的应用程序构建**面向消息的中间件**（**MOM**）。这是一个罕见的展示，它在 Spring 中实现了如此多关于 WebSocket 的内容。从使用默认的嵌入式 WebSocket 消息代理到完整功能的 RabbitMQ 代理（使用 STOMP 和 AMQP 协议）。我们将看到如何向多个客户端广播消息并推迟执行耗时任务，提供显著的可伸缩性优势。

通过一个专门用于需要访问常见数据库服务器的 WebSockets 的新 Java 项目，并且在类似生产环境的角度上，我们将用 MySQL 服务器替换 HSQLDB。

我们将看到如何动态创建私有队列以及如何让经过身份验证的客户端从这些私有队列中发布和接收消息。我们将做所有这些，以在我们的应用程序中实现真正的应用程序功能。

为了实现 WebSocket 身份验证和消息认证，我们将使 API 有状态。有状态意味着 API 将使用 HTTP 会话在用户请求之间保持用户经过身份验证。借助 Spring Session 的支持和高度可集群化的 Redis 服务器的使用，会话将在多个 Web 应用程序之间共享。

# 使用 STOMP 通过 SockJS 流式传输社交事件

在这个示例中，我们使用 STOMP 通过 SockJS 广播用户活动（事件）。SockJS 提供了 WebSocket 的自定义实现。

## 准备工作

有一些配置工作需要事先完成，特别是在 Apache HTTP 代理上。之后，我们将看到如何在客户端使用 SockJS 和 AngularJS 初始化 WebSocket。

我们的 WebSocket 将订阅通过 Spring 从`cloudstreetmarket-api`模块发布的主题（用于广播）。

## 如何做…

1.  在 Eclipse 的**Git Perspective**中，检出`v8.1.x`分支的最新版本。

1.  在`zipcloud-parent`项目上运行`Maven clean`和`Maven install`命令（右键单击项目，选择**Run as…** | **Maven Clean**，然后选择**Run as…** | **Maven Install)**。之后，进行**Maven | Update** **Project**以使 Eclipse 与 Maven 配置同步（右键单击项目，然后单击**Maven** | **Update Project…**）。

1.  类似地，在`cloudstreetmarket-parent`上运行**Maven clean**和**Maven install**命令，然后运行**Maven** | **Update Project…**（以更新所有`cloudstreetmarket-parent`模块）。

### Apache HTTP 代理配置

1.  在 Apache `httpd.conf`文件中，更改`VirtualHost`定义为：

```java
<VirtualHost cloudstreetmarket.com:80>
  ProxyPass        /portal http://localhost:8080/portal
  ProxyPassReverse /portal http://localhost:8080/portal
  ProxyPass        /api  	http://localhost:8080/api
  ProxyPassReverse /api  	http://localhost:8080/api
  RewriteEngine on
  RewriteCond %{HTTP:UPGRADE} ^WebSocket$ [NC]
  RewriteCond %{HTTP:CONNECTION} ^Upgrade$ [NC]
  RewriteRule .* ws://localhost:8080%{REQUEST_URI} [P]
  RedirectMatch ^/$ /portal/index
</VirtualHost>
```

1.  在`httpd.conf`中，取消注释以下行：

```java
LoadModule proxy_wstunnel_module modules/mod_proxy_wstunnel.so
```

### 前端

1.  在`cloudstreetmarket-webapp`模块的`index.jsp`文件中，导入了两个额外的 JavaScript 文件：

```java
<script src="img/sockjs-1.0.2.min.js"></script>
<script src="img/stomp-2.3.3.js"></script> 
```

### 注意

这两个文件已经被本地复制，但最初，两者都是在线找到的：

[`cdnjs.cloudflare.com/ajax/libs/sockjs-client/1.0.2/sockjs.min.js`](https://cdnjs.cloudflare.com/ajax/libs/sockjs-client/1.0.2/sockjs.min.js)

[`cdnjs.cloudflare.com/ajax/libs/stomp.js/2.3.3/stomp.js`](https://cdnjs.cloudflare.com/ajax/libs/stomp.js/2.3.3/stomp.js)

1.  对于这个示例，客户端方面的所有更改都与文件`src/main/webapp/js/home/home_community_activity.js`有关（它驱动着登陆页面上**用户活动**的反馈）。这个文件与模板`/src/main/webapp/html/home.html`相关联。

1.  在`homeCommunityActivityController`的`init()`函数中，添加了以下部分：

```java
cloudStreetMarketApp.controller('homeCommunityActivityController', function ($scope, $rootScope, httpAuth, modalService, communityFactory, genericAPIFactory, $filter){
  var $this = this,
  socket = new SockJS('/api/users/feed/add'),
  stompClient = Stomp.over(socket);
  pageNumber = 0;
  $scope.communityActivities = {};
  $scope.pageSize=10;
  $scope.init = function () {
    $scope.loadMore();
    socket.onclose = function() {
      stompClient.disconnect();
    };
    stompClient.connect({}, function(frame) {
    stompClient.subscribe('/topic/actions', 	function(message){
     var newActivity = $this.prepareActivity( JSON.parse(message.body)
       );
        $this.addAsyncActivityToFeed(newActivity);
        $scope.$apply();
    });
    });
  ...
  }
...
```

1.  `loadMore()`函数仍然被调用以在滚动到底部时拉取新的活动。但是现在，因为新的活动可以异步插入，`communityActivities`变量不再是数组，而是一个用作映射的对象，其中活动 ID 作为键。这样做可以让我们将同步结果与异步结果合并：

```java
  $scope.loadMore = function () {
    communityFactory.getUsersActivity(pageNumber, $scope.pageSize).then(function(response) {
      var usersData = response.data,
      status = response.status,
      headers  = response.headers,
      config = response.config;
      $this.handleHeaders(headers);
      if(usersData.content){
        if(usersData.content.length > 0){
          pageNumber++;
        }
        $this.addActivitiesToFeed(usersData.content);
      }
    });
  };
```

1.  与以前一样（自第四章，“为无状态架构构建 REST API”），我们循环遍历社区活动以构建活动源。现在，每个活动都带有一定数量的**喜欢**和**评论**。目前，如果用户已经通过身份验证，他就有能力看到**喜欢**的数量：![前端](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00897.jpeg)

1.  与点赞图像绑定的 Angular 化 HTML 如下：

```java
    <span ng-if="userAuthenticated() && value.amountOfLikes == 0">
    <img ng-src="img/{{image}}" class="like-img" 
      ng-init="image='img/icon-finder/1441189591_1_like.png'"
      ng-mouseover="image='img/icon-finder/1441188631_4_like.png'"
      ng-mouseleave="image='img/icon-finder/1441189591_1_like.png'"
      ng-click="like(value.id)"/>
  </span>
```

1.  在控制器中，`like()`作用域函数支持此 DOM 元素来创建一个新的`like`活动，该活动针对原始活动：

```java
  $scope.like = function (targetActionId){
    var likeAction = {
      id: null,
      type: 'LIKE',
      date: null,
      targetActionId: targetActionId,
      userId: httpAuth.getLoggedInUser()
    };
    genericAPIFactory.post("/api/actions/likes", likeAction);
  }
```

1.  相反的逻辑也可以找到**不喜欢**一个活动。

### 后端

1.  已添加以下 Maven 依赖项到`cloudstreetmarket-api`：

```java
    <dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-websocket</artifactId>
      <version>${spring.version}</version>
   </dependency>
   <dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-messaging</artifactId>
      <version>${spring.version}</version>
   </dependency>
```

1.  在`web.xml`文件（来自`cloudstreetmarket-api`），必须将以下属性添加到我们的 servlet 及其每个过滤器中：

```java
<async-supported>true</async-supported>
```

1.  已创建以下专用配置 bean：

```java
@Configuration
@ComponentScan("edu.zipcloud.cloudstreetmarket.api")
@EnableWebSocketMessageBroker
public class WebSocketConfig extends AbstractWebSocketMessageBrokerConfigurer {

   @Override
   public void registerStompEndpoints(final StompEndpointRegistry registry) {
         registry.addEndpoint("/users/feed/add")
            .withSockJS();
    }
   @Override
   public void configureMessageBroker(final MessageBrokerRegistry registry) {
      registry.setApplicationDestinationPrefixes("/app");
       registry.enableSimpleBroker("/topic");
    }
}
```

已添加新的控制器`ActivityFeedWSController`如下：

```java
@RestController
public class ActivityFeedWSController extends CloudstreetApiWCI{
    @MessageMapping("/users/feed/add")
    @SendTo("/topic/actions")
    public UserActivityDTO handle(UserActivityDTO message) throws Exception{
        return message;
    }
    @RequestMapping(value="/users/feed/info", method=GET)
    public String infoWS(){
        return "v0";
    }
}
```

1.  作为 Spring 配置，我们已将以下 bean 添加到`dispatcher-servlet.xml`中：

```java
<bean
  class="org.sfw.web.socket.server.support.OriginHandshakeInterceptor">
    <property name="allowedOrigins">
      <list>
      <value>http://cloudstreetmarket.com</value>
      </list>
    property>
</bean>
```

在`security-config.xml`中，已将以下配置添加到 http Spring Security 命名空间：

```java
    <security:http create-session="stateless" 
        entry-point-ref="authenticationEntryPoint" authentication-manager-ref="authenticationManager">
    ...
    <security:headers>
      <security:frame-options policy="SAMEORIGIN"/>
    </security:headers>
    ...
    </security:http>
```

现在让我们看看事件是如何生成的。

1.  创建新的财务交易时，会向主题`/topic/actions`发送消息。这是在`TransactionController`中完成的：

```java
@RestController
@ExposesResourceFor(Transaction.class)
@RequestMapping(value=ACTIONS_PATH + TRANSACTIONS_PATH, produces={"application/xml", "application/json"})
public class TransactionController extends CloudstreetApiWCI<Transaction> {
  @Autowired
  private SimpMessagingTemplate messagingTemplate;
  @RequestMapping(method=POST)
  @ResponseStatus(HttpStatus.CREATED)
  public TransactionResource post(@Valid @RequestBody Transaction transaction, HttpServletResponse response, BindingResult result) {
    ...
   messagingTemplate.convertAndSend("/topic/actions", new UserActivityDTO(transaction));
    ...
  }
}
```

同样，当创建一个`like`活动时，也会向`/topic/actions`主题发送消息，这是在`LikeActionController`中完成的：

```java
 @RequestMapping(method=POST)
@ResponseStatus(HttpStatus.CREATED)
public LikeActionResource post(@RequestBody LikeAction likeAction, HttpServletResponse response) {
   ...
    likeAction = likeActionService.create(likeAction);
   messagingTemplate.convertAndSend("/topic/actions", new UserActivityDTO(likeAction));
   ...
}
```

1.  现在启动 Tomcat 服务器。使用 Yahoo! Oauth2 和您的个人 Yahoo!帐户登录应用程序（如果您还没有，请创建一个）。为`Cloudstreet Market`应用程序注册一个新用户。

1.  在您的网络浏览器中，使用已登录的用户在应用程序中打开两个不同的选项卡。将其中一个选项卡保留在登陆页面上。

1.  使用另一个选项卡，导航到**价格和市场** | **所有价格搜索**菜单。搜索一个股票代码，比如 Facebook，并购买三股。

1.  等待接收信息消息：![后端](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00898.jpeg)

然后检查浏览器的第一个选项卡（您没有使用的选项卡）。

![后端](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00899.jpeg)

您会注意到活动源在顶部收到了一个新元素！

1.  此外，在控制台中，您应该有以下日志跟踪：![后端](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00900.jpeg)

1.  同样，**like**事件会实时刷新：![后端](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00901.jpeg)

## 它是如何工作的...

在这里，我们将在介绍 Spring-WebSocket 支持工具之前，看一下关于 WebSocket、STOMP 和 SockJS 的一些一般概念。

### WebSocket 简介

WebSocket 是基于 TCP 的全双工通信协议。全双工通信系统允许两方通过双向通道同时*发言*和*被听到*。电话对话可能是全双工系统的最佳例子。

这项技术特别适用于需要利用新 HTTP 连接引起的开销的应用程序。自 2011 年以来，WebSocket 协议一直是互联网标准（[`tools.ietf.org/html/rfc6455`](https://tools.ietf.org/html/rfc6455)）。

#### WebSocket 生命周期

在建立 WebSocket 连接之前，客户端发起握手 HTTP 请求，服务器做出响应。握手请求还代表了一个协议升级请求（从 HTTP 到 WebSocket），用`Upgrade`头正式化。服务器通过响应中相同的`Upgrade`头（和值）确认了这个协议升级。除了`Upgrade`头之外，为了防范缓存代理攻击，客户端还发送了一个 base-64 编码的随机密钥。对此，服务器在`Sec-WebSocket-Accept`头中发送了这个密钥的哈希。

以下是我们应用程序中发生的握手的示例：

![WebSocket 生命周期](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00902.jpeg)

该协议生命周期可以通过以下序列图进行总结：

![WebSocket 生命周期](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00903.jpeg)

#### 两个专用的 URI 方案

该协议为`WebSockets ws://`和`wss://`定义了两个 URI 方案（`wss`允许加密连接）。

### STOMP 协议

**STOMP**代表**简单文本定向消息协议**。该协议提供了一种基于帧的可互操作格式，允许 STOMP 客户端与 STOMP 消息代理通信。

这是一个需要并信任现有的双向流式网络协议的消息协议。WebSocket 提供基于帧的数据传输，WebSocket 帧确实可以是 STOMP 格式的帧。

以下是一个 STOMP 帧的示例：

```java
CONNECTED
session:session-4F_y4UhJTEjabe0LfFH2kg
heart-beat:10000,10000
server:RabbitMQ/3.2.4
version:1.1
user-name:marcus
```

帧具有以下结构：

![STOMP 协议](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00904.jpeg)

STOMP 协议规范定义了一组客户端命令（`SEND`，`SUBSCRIBE`，`UNSUBSCRIBE`，`BEGIN`，`COMMIT`，`ABORT`，`ACK`，`NACK`，`DISCONNECT`，`CONNECT`和`STOMP`）和服务器命令（`CONNECTED`，`MESSAGE`，`RECEIPT`和`ERROR`）。

只有`SEND`，`MESSAGE`和`ERROR`帧可以有主体。协议规范可以在网上找到：[`stomp.github.io/stomp-specification-1.2.html`](http://stomp.github.io/stomp-specification-1.2.html)。

在客户端，我们使用了 JavaScript 库**STOMP Over WebSocket**，文件名为`stomp.js`。该库将 STOMP 格式的帧映射到 WebSocket 帧。默认情况下，它查找 web 浏览器的`WebSocket`类，以使 STOMP 客户端创建 WebSocket。

该库还可以从自定义的`WebSocket`实现中创建 STOMP 客户端。从 SockJS WebSockets，我们可以这样创建 STOMP 客户端：

```java
    var socket = new SockJS('/app/users/feed/add');
    var stompClient = Stomp.over(socket);
        stompClient.connect({}, function(frame) {
  ...
    });
    socket.onclose = function() {
    stompClient.disconnect();
  };
```

### SockJS

WebSockets 现在几乎被所有浏览器支持。但是，我们无法控制客户使用的版本。在许多情况下，对 7%到 15%的受众隐藏这样的技术根本不是一个选择。

在客户端，SockJS 提供了一个自定义实现，可以看作是浏览器原生`WebSocket`实现的装饰器。通过一个简单而方便的库，SockJS 确保了跨浏览器的兼容性。通过一系列回退传输选项（`xhr-streaming`，`xdr-streaming`，`iframe-eventsource`，`iframe-htmlfile`，`xhr-polling`等），它尽可能地模拟了 WebSockets。

对于服务器实现，为了匹配客户端的回退行为，SockJS 还定义了自己的协议：

[`sockjs.github.io/sockjs-protocol/sockjs-protocol-0.3.3.html`](http://sockjs.github.io/sockjs-protocol/sockjs-protocol-0.3.3.html)

### Spring WebSocket 支持

根据 Java WebSocket API 规范（JSR-356），Spring 4+提供了一个解决方案，该解决方案打包在模块`spring-websocket`和`spring-messaging`中。但是 Spring 提供的不仅仅是 JSR-356 的实现。例如，基于以下事实：

+   没有使用消息协议的 WebSocket 太低级，无法直接在应用程序中使用，需要自定义处理框架：Spring 团队选择提供和支持消息协议实现（STOMP）。

+   WebSockets 目前并不受所有浏览器支持：Spring 还通过其实现的 SockJS 协议提供了 WebSocket 回退支持。

#### 一体化配置

我们已经启用了 WebSocket 引擎，并为 SockJS 和 STOMP 配置了一个配置 bean——`WebSocketConfig`：

```java
@Configuration
@ComponentScan("edu.zipcloud.cloudstreetmarket.api")
@EnableWebSocketMessageBroker
public class WebSocketConfig extends   AbstractWebSocketMessageBrokerConfigurer {

  @Override
  public void registerStompEndpoints(final StompEndpointRegistry registry) {
        registry.addEndpoint("/users/feed/add")
        .withSockJS();
  }

  @Override
  public void configureMessageBroker(final MessageBrokerRegistry registry) {
        registry.setApplicationDestinationPrefixes("/app");
        registry.enableSimpleBroker("/topic");
  }
}
```

WebSocket 端点定义为上下文路径`/users/feed/add`。它在客户端端匹配了定义的 SockJS 客户端构造函数参数：

```java
var socket = new SockJS('/api/users/feed/add');
```

从端点（`clientInboundChannel`）到消息处理程序的路由，WebSocket 引擎需要选择将消息路由到何处，我们在这里有两个选项。根据情况和我们想要实现的目标，我们可以将消息定位到应用内消费者（消息处理程序）或直接将消息路由到消息代理，以便将消息分发给订阅的客户端。

这个分割是通过定义两个不同的目的地前缀来配置的。在我们的情况下，我们决定使用`/app`前缀将消息路由到相应的消息处理程序，使用`/topic`前缀来识别准备分发给客户端的消息。

现在让我们看看如何定义消息处理程序以及如何使用它们。

#### 通过@MessageMapping 定义消息处理程序

`@MessageMapping`注解用于 Spring MVC 控制器方法，标记它们可用作消息处理程序方法。

从`clientInboundChannel`中的消息到路由到消息处理程序，WebSocket 引擎根据它们配置的值缩小到正确的`@MessageMapping`方法。

与 Spring MVC 一样，这个值可以用 Ant 样式（例如`/targets/**`）来定义。然而，与`@RequestParam`和`@PathVariable`注解一样，模板变量也可以通过在方法参数上使用`@DestinationVariable`注解来传递（目标模板定义如下：`/targets/{target}`）。

### 发送消息以进行分发

必须配置消息代理。在这个示例中，我们使用了一个`simple`消息代理（`simpMessageBroker`），我们已经从`MessageBrokerRegistry`中启用了它。这种内存中的代理适用于在没有外部代理（RabbitMQ、ActiveMQ 等）的情况下堆叠 STOMP 消息。当有可用性将消息分发给 WebSocket 客户端时，这些消息被发送到`clientOutboundChannel`。

我们已经看到，当消息目的地以`/topic`为前缀时（就像我们的情况一样），消息会直接发送到消息代理。但是当我们在消息处理程序方法或后端代码的其他地方发送调度消息时怎么办？我们可以使用下一节中描述的`SimpMessagingTemplate`来实现这一点。

#### SimpMessagingTemplate

我们在 CSMReceiver 类中自动装配了一个`SimpMessagingTemplate`，稍后我们将使用它将 AMQP 消息的有效载荷转发给 WebSocket 客户端。

`SimpMessagingTemplate`与 Spring 的`JmsTemplate`具有相同的目的（如果您熟悉它），但它适用于简单的消息协议（如 STOMP）。

一个方便且继承自著名的方法是`convertAndSend`方法，它尝试识别并使用`MessageConverter`来序列化一个对象，并将其放入一个新消息中，然后将此消息发送到指定的目的地：

```java
simpMessagingTemplate.convertAndSend(String destination, Object message);
```

这个想法是为消息代理目标（在我们的情况下是带有`/topic`前缀）定位。

#### @SendTo 注解

这个注解使我们不必显式使用`SimpMessagingTemplate`。目的地被指定为注解值。这个方法还将处理从有效载荷到消息的转换：

```java
@RestController
public class ActivityFeedWSController extends CloudstreetApiWCI{

  @MessageMapping("/users/feed/add")
  @SendTo("/topic/actions")
  public UserActivityDTO handle(UserActivityDTO payload) throws Exception{
        return payload;
 }
}
```

## 还有更多...

在本节中，我们提供了与 SockJS 回退选项相关的额外信息来源。

正如之前介绍的，Spring 提供了 SockJS 协议实现。在 Spring 中使用`withSockJS()`功能方法配置 SockJS 很容易，在`StompEndPoint`注册期间。这个小小的配置片段告诉 Spring 在我们的端点上激活 SockJS 回退选项。

SockJS 客户端对服务器的第一个调用是一个 HTTP 请求，到端点路径连接`/info`以评估服务器配置。如果此 HTTP 请求不成功，则不会尝试任何其他传输（甚至不会尝试 WebSocket）。

如果您想了解 SockJS 客户端如何查询服务器以获取合适的回退选项，可以在 Spring 参考指南中阅读更多内容：

[`docs.spring.io/spring/docs/current/spring-framework-reference/html/websocket.html#websocket-server-handshake`](http://docs.spring.io/spring/docs/current/spring-framework-reference/html/websocket.html#websocket-server-handshake)

## 另请参阅

+   **JSR-356**：您可以在线找到规范文档，了解有关 Java WebSocket 规范的更多信息，spring-websocket 正在遵循该规范：[`jcp.org/en/jsr/detail?id=356`](https://jcp.org/en/jsr/detail?id=356)

# 使用 RabbitMQ 作为多协议消息代理

安装和使用外部 RabbitMQ 作为功能齐全的消息代理可以开启新的技术机会，并设计类似生产环境的基础设施。

## 准备工作

在本教程中，我们将安装 RabbitMQ 作为独立服务器，并配置它以支持 STOMP 消息。

我们还将更新我们的 WebSocket Spring 配置，以依赖于这个功能齐全的消息代理，而不是内部简单的消息代理。

## 如何做…

1.  在 Eclipse 的**Git Perspective**中，这次检出`v8.2.x`分支。

1.  已添加了两个新的 Java 项目，必须导入。从 Eclipse 中，选择**File** | **Import…**菜单。

1.  **导入**向导打开，以便您可以在层次结构中选择项目类型。打开**Maven**类别，选择**Existing Maven Projects**选项，然后单击**Next**。

1.  **导入 Maven 项目**向导打开。选择（或输入）工作区位置（应为`<home-directory>/workspace`）作为根目录。

1.  如下截图所示，选择以下两个**pom.xml**文件：**cloudstreetmarket-shared/pom.xml**和**cloudstreetmarket-websocket/pom.xml**。![如何做…](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00905.jpeg)

1.  两个项目`cloudstreetmarket-shared`和`cloudstreetmarket-websocket`必须显示在项目层次结构中。

1.  在 Web 模块上定位运行时环境，按照以下说明操作：在 Eclipse 中，右键单击**cloudmarket-websocket**项目，选择**Properties**菜单，在导航面板中选择**Targeted Runtimes**。在中央窗口中，勾选服务器**Apache Tomcat v8.0**的复选框。

1.  在`/app`目录中，`cloudstreetmarket.properties`文件已更新。反映在位于`<home-directory>/app/cloudstreetmarket.properties`的文件中的更改。

1.  在`zipcloud-parent`上运行`Maven clean`和`Maven install`命令，然后在`cloudstreetmarket-parent`上运行，然后在所有模块上运行**Maven** | **Update Project**。

1.  以我们想要的方式运行 RabbitMQ，需要我们下载并安装该产品作为独立产品。

1.  根据本地机器的配置，不同的操作方式适用。您将在 RabbitMQ 网站上找到适当的链接和安装指南：[`www.rabbitmq.com/download.html`](https://www.rabbitmq.com/download.html)

### 提示

如果您使用 Windows 操作系统，请注意，下载和安装 Erlang（[`www.erlang.org/download.html`](http://www.erlang.org/download.html)）是先决条件。

1.  一旦安装了 RabbitMQ 并且其服务正在运行，打开您喜欢的 Web 浏览器，以检查 RabbitMQ 是否作为 Web 控制台运行在 URL：`http://localhost:15672`（就像下面的截图中一样）。![如何做…](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00906.jpeg)

### 注意

我们将在稍后回来设置 RabbitMQ 配置。现在，只需记住这个控制台可以用于监视消息和管理连接、队列、主题和交换。

1.  需要激活 RabbitMQ STOMP 插件。这是从`rabbitmq_server-x.x.x\sbin`目录中执行以下命令行完成的：

```java
rabbitmq-plugins enable rabbitmq_stomp
```

1.  已添加以下 Maven 依赖项：

```java
<dependency>
  <groupId>org.springframework.amqp</groupId>
  <artifactId>spring-rabbit</artifactId>
  <version>1.4.0.RELEASE</version>
</dependency>
<dependency>
  <groupId>io.projectreactor</groupId>
  <artifactId>reactor-core</artifactId>
  <version>2.0.5.RELEASE</version>
</dependency>
<dependency>
  <groupId>io.projectreactor</groupId>
  <artifactId>reactor-net</artifactId>
  <version>2.0.5.RELEASE</version>
</dependency>
<dependency>
  <groupId>io.projectreactor.spring</groupId>
  <artifactId>reactor-spring-context</artifactId>
  <version>2.0.5.RELEASE</version>
</dependency>
<dependency>
  <groupId>io.netty</groupId>
  <artifactId>netty-all</artifactId>
  <version>4.0.31.Final</version>
</dependency>
```

1.  在`cloudstreetmarket-api`模块的`dispatcher-servlet.xml`中，已添加以下 bean，使用`rabbit`命名空间：

```java
<beans 

   ...

   xsi:schemaLocation="http://www.sfw.org/schema/beans
   ...
   http://www.sfw.org/schema/rabbit
  http://www.sfw.org/schema/rabbit/spring-rabbit-1.5.xsd">
    ...
  <rabbit:connection-factory id="connectionFactory" host="localhost" username="guest" password="guest" />
  <rabbit:admin connection-factory="connectionFactory" />
  <rabbit:template id="messagingTemplate" connection-factory="connectionFactory"/>
</beans>
```

1.  在`csmcore-config.xml`文件（在`cloudstreetmarket-core`中），以下 bean 已添加了`task`命名空间：

```java
<beans 

    ...
    xmlns:task=http://www.sfw.org/schema/task
    http://www.sfw.org/schema/task/spring-task-4.0.xsd">
    ...
    <task:annotation-driven scheduler="wsScheduler"/>
    <task:scheduler id="wsScheduler" pool-size="1000"/>
    <task:executor id="taskExecutor"/>
</beans>
```

1.  在 Spring 配置方面，我们的`AnnotationConfig` bean（`cloudstreetmarket-api`的主配置 bean）已添加了两个注释：

```java
@EnableRabbit
@EnableAsync
public class AnnotationConfig {
	...
}
```

1.  最后，`WebSocketConfig` bean 也已更新；特别是经纪人注册。我们现在使用的是`StompBrokerRelay`而不是简单的经纪人：

```java
@Configuration
@ComponentScan("edu.zipcloud.cloudstreetmarket.api")
@EnableWebSocketMessageBroker
@EnableScheduling
@EnableAsync
public class WebSocketConfig extends AbstractWebSocketMessageBrokerConfigurer {
...
    @Override
    public void configureMessageBroker(final MessageBrokerRegistry registry) {
     registry.setApplicationDestinationPrefixes( WEBAPP_PREFIX_PATH);
     registry.enableStompBrokerRelay(TOPIC_ROOT_PATH);
    }
}
```

### 提示

就是这样！一切都准备好使用 RabbitMQ 作为我们系统的外部代理。但是，请注意，如果您现在尝试启动服务器，代码将期望 MySQL 已安装以及 Redis 服务器。这两个第三方系统将在接下来的两个配方中详细介绍。

## 它是如何工作的…

### 使用全功能消息代理

与简单消息代理相比，使用 RabbitMQ 等全功能消息代理提供了有趣的好处，我们现在将讨论这些好处。

#### 集群性-RabbitMQ

RabbitMQ 代理由一个或多个 Erlang 节点组成。这些节点分别代表 RabbitMQ 的一个实例，并可以独立启动。节点可以使用命令行工具`rabbitmqctl`相互链接。例如，`rabbitmqctl join_cluster rabbit@rabbit.cloudstreetmarket.com`实际上会将一个节点连接到现有的集群网络。RabbitMQ 节点使用 cookie 相互通信。为了连接到同一个集群，两个节点必须具有相同的 cookie。

#### 更多的 STOMP 消息类型

与简单消息代理相比，使用全功能消息代理（而不是简单消息代理）支持额外的 STOMP 帧命令。例如，简单消息代理不支持`ACK`和`RECEIPT`。

### StompMessageBrokerRelay

在上一个配方中，我们讨论了消息在 Spring WebSocket 引擎中经过的流程。如下图所示，当切换到外部消息代理中继时，这个流程不受影响。

![StompMessageBrokerRelay](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00907.jpeg)

只有 RabbitMQ 外部消息代理显示为额外的部分。`BrokerMessageHandler`（`StompBrokerRelayMessageHandler`）只充当一个代理，将目标定位到幕后的 RabbitMQ 节点。`StompBrokerRelay`和其消息代理之间只维护一个 TCP 连接。`StompBrokerRelay`通过发送心跳消息来维护连接。

## 另请参阅

+   **RabbitMQ 指南和文档**：这个配方只是一个概述，但 RabbitMQ 文档做得很好，非常完整。这是一个很好的信息来源，你可以在这里找到：

[`www.rabbitmq.com/documentation.html`](http://www.rabbitmq.com/documentation.html)

[`www.rabbitmq.com/stomp.html`](http://www.rabbitmq.com/stomp.html)

# 使用 RabbitMQ 和 AMQP 堆叠和消费任务

这个配方将演示如何实现**面向消息的中间件**（**MoM**）。这是一种基于组件之间异步通信的可伸缩性技术。

## 准备工作

我们已经介绍了新的`cloudstreetmarket-shared`和`cloudstreetmarket-websocket` Java 项目。现在，WebSockets 已从`cloudstreetmarket-api`中分离出来，但`cloudstreetmarket-websocket`和`cloudstreetmarket-api`仍将使用消息进行通信。

为了将次要任务（如事件生成）与请求线程解耦，您需要学习如何使用 RabbitMQ 配置和使用 AMQP 消息模板和监听器。

## 如何做…

1.  访问 RabbitMQ Web 控制台`http://localhost:15672`。

### 注意

如果由于某种原因无法访问网络控制台，请返回到先前的教程，在那里可以找到下载和安装指南。

1.  在网络控制台的**队列**选项卡中，创建一个名为`AMQP_USER_ACTIVITY`的新队列。使用**持久**和**自动删除: "否"**参数创建它：![如何做…](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00908.jpeg)

### 发送方

当 API 被请求执行操作，如**创建交易**或**创建喜欢活动**时，我们会产生事件。

### 提示

通过非常少的调整，我们现在使用`RabbitTemplate`而不是以前的`SimpMessagingTemplate`，并且将目标定位到一个中间的 AMQP 队列，而不是最终的 STOMP 客户端。

在`TransactionController`中，POST 处理程序已更新如下：

```java
import org.springframework.amqp.rabbit.core.RabbitTemplate;
@RestController
public class TransactionController extends CloudstreetApiWCI<Transaction> {
  @Autowired
  private RabbitTemplate messagingTemplate;

  @RequestMapping(method=POST)
  @ResponseStatus(HttpStatus.CREATED)
  public TransactionResource post(@Valid @RequestBody Transaction transaction, HttpServletResponse response, BindingResult result) {
   ...
   messagingTemplate.convertAndSend("AMQP_USER_ACTIVITY", new UserActivityDTO(transaction));
   ...
   return resource;
  }
}
```

在`LikeActionController`中，POST 处理程序已更新如下：

```java
import org.springframework.amqp.rabbit.core.RabbitTemplate;

@RestController
public class LikeActionController extends CloudstreetApiWCI<LikeAction> {
  @Autowired
  private RabbitTemplate messagingTemplate;
  @RequestMapping(method=POST)
  @ResponseStatus(HttpStatus.CREATED)
  public LikeActionResource post(@RequestBody LikeAction likeAction, HttpServletResponse response) {
  ...
   messagingTemplate.convertAndSend("AMQP_USER_ACTIVITY", new UserActivityDTO(likeAction));
   ...
   return resource;
  }
}
```

### 消费方

如前所述，`cloudstreetmarket-websocket`模块现在监听`AMQP_USER_ACTIVITY`队列。

1.  必要的配置设置在`displatcher-servlet.xml`（`cloudstreetmarket-websocket`）中。在那里，我们创建了一个`rabbitConnectionFactory`和一个`rabbitListenerContainerFactory` bean：

```java
<rabbit:connection-factory id="rabbitConnectionFactory" username="guest" host="localhost" password="guest"/>
<bean id="rabbitListenerContainerFactory" class="org.sfw.amqp.rabbit.config.SimpleRabbitListenerContainerFactory">
    <property name="connectionFactory" ref="rabbitConnectionFactory"/>
    <property name="concurrentConsumers" value="3"/>
    <property name="maxConcurrentConsumers" value="10"/>
    <property name="prefetchCount" value="12"/>
</bean>
```

1.  最后，监听器 bean 的创建如下，使用`CSMReceiver`类：

```java
@Component
public class CSMReceiver {
  @Autowired
  private SimpMessagingTemplate simpMessagingTemplate;

  @RabbitListener(queues = "AMQP_USER_ACTIVITY_QUEUE")
  public void handleMessage(UserActivityDTO payload) {
  simpMessagingTemplate.convertAndSend("/topic/actions", payload);
  }
} 
```

### 提示

您可以在这里识别使用的`SimpMessagingTemplate`，将传入的消息负载转发给最终的 STOMP 客户端。

1.  在`cloudstreetmarket-websocket`中创建了一个新的`WebSocketConfig` bean。这个 bean 与我们在`cloudstreetmarket-api`中的 bean 非常相似。

### 客户端

我们在客户端（`cloudstreetmarket-webapp`）上没有改变太多东西，因为我们目前仍专注于着陆页（`home_community_activity.js`）。

主要区别在于 STOMP 端点现在将目标定位到`/ws`上下文路径。WebSockets 在 5 秒延迟后从`init()`函数中启动。此外，`SockJS`套接字和 STOMP 客户端现在集中在全局变量（使用`Window`对象）中，以简化用户导航期间的 WebSockets 生命周期：

```java
var timer = $timeout( function(){ 
  window.socket = new SockJS('/ws/channels/users/broadcast');
  window.stompClient = Stomp.over(window.socket);
    window.socket.onclose = function() {
        window.stompClient.disconnect();
      };
  window.stompClient.connect({}, function(frame) {
    window.stompClient.subscribe('/topic/actions', function(message){
        var newActivity = $this.prepareActivity(JSON.parse(message.body));
        $this.addAsyncActivityToFeed(newActivity);
        $scope.$apply();
      });
    });
     $scope.$on(
      "$destroy",
        function( event ) {
          $timeout.cancel( timer );
          window.stompClient.disconnect();
          }
      );
                }, 5000);
```

## 它是如何工作的...

这种类型的基础设施以一种松散但可靠的方式将应用程序组件耦合在一起。

### 消息架构概述

在这个教程中，我们给我们的应用程序添加了一个 MoM。主要想法是尽可能地将进程与客户端请求生命周期解耦。

为了使我们的 REST API 专注于资源处理，一些业务逻辑显然是次要的，比如：

+   通知社区有新用户注册了一个帐户

+   通知社区用户执行了特定交易

+   通知社区用户已喜欢另一个用户的动作

我们决定创建一个专门处理 WebSockets 的新 webapp。我们的 API 现在通过向`ws` web app 发送消息与之通信。

消息负载是社区`Action`对象（来自`Action.java`超类）。从`cloudstreetmarket-api` web app 到`cloudstreetmarket-websocket` webapp，这些动作对象被序列化并包装在 AMQP 消息中。一旦发送，它们被堆叠在一个单一的 RabbitMQ 队列（`AMQP_USER_ACTIVITY`）中。

发送方和接收方部分都是 AMQP 实现（`RabbitTemplate`和`RabbitListener`）。这种逻辑现在将以`websocket` web app 可以承受的速度进行处理，而不会对用户体验产生影响。当在`cloudstreetmarket-websocket`端接收到时，消息负载将作为 STOMP 消息即时发送到 WebSocket 客户端。

在这里直接性能的好处是值得商榷的（在这个例子中）。毕竟，我们大部分时间都是通过额外的消息传递层推迟了次要事件的发布。然而，在设计清晰度和业务组件分离方面的好处是无价的。

#### 可扩展的模型

我们已经谈论了保持 web 应用程序无状态的好处。这是我们迄今为止尝试做的事情，我们为此感到自豪！

没有 HTTP 会话，我们很容易就能对`api`网络应用程序或`portal`网络应用程序的流量激增做出反应。在 Apache HTTP 代理上，我们可以很容易地使用`mod_proxy_balancer`设置负载均衡器来处理 HTTP 连接。

您可以在 Apache HTTP 文档中了解更多信息：[`httpd.apache.org/docs/2.2/mod/mod_proxy_balancer.html`](http://httpd.apache.org/docs/2.2/mod/mod_proxy_balancer.html)

![可扩展模型](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00909.jpeg)

对于 WebSocket 网络应用程序，它在无状态时基本上是一样的。在 Apache HTTP 配置中，配置的`mod_proxy_wstunnel`应该处理 WebSocket 的负载平衡，并提供应用程序故障转移。

### AMQP 还是 JMS？

**高级消息队列协议**（AMQP）定义了一种**线级**协议，并保证了发送方和消费方之间的互操作性。符合该协议的任何一方都可以创建和解释消息，因此可以与任何其他符合该协议的组件进行互操作，而不受底层技术的影响。

相比之下，JMS 是 Java 平台**企业版（EE）**的一部分。随着 JSR-914 的到来，JMS 是一个定义 API 应该如何创建、发送、接收和读取消息的标准。JMS 不提供线级指导，也不保证各方之间的互操作性。

AMQP 控制消息的格式和这些消息经过的流程，而 JMS 控制边界（操作员）的技术实现。当我们在一个潜在复杂的环境中寻求通信一致性时，AMQP 似乎是 MoM 协议的一个不错的选择。

## 还有更多...

本节提供了扩展您对 AMQP 和事件发布方法的知识的外部资源。

### Pivotal 公司对 AMQP 的很好介绍

如果您想更好地了解 AMQP 及其与 JMS 的区别，请查看[spring.io](http://spring.io)网站上的以下文章：

[`spring.io/understanding/AMQP`](https://spring.io/understanding/AMQP)

### 发布应用程序事件的更好方法

现在，我们还没有实现一个适当的模式来发布事件。下面链接的文章来自[spring.io](http://spring.io)博客。它介绍了在 Spring 4.2+中发布事件的最佳实践：

[`spring.io/blog/2015/02/11/better-application-events-in-spring-framework-4-2`](https://spring.io/blog/2015/02/11/better-application-events-in-spring-framework-4-2)

## 另请参阅

+   **负载均衡 WebSockets**：在以下文章中了解更多关于这个主题的内容，作者是 Arun Gupta（当时在红帽公司）：

[`blog.arungupta.me/load-balance-websockets-apache-httpd-techtip48`](http://blog.arungupta.me/load-balance-websockets-apache-httpd-techtip48)

# 使用 Spring Session 和 Redis 保护消息

总之，到目前为止，我们已经看到了如何向 StockJS 客户端广播 STOMP 消息，如何在外部多协议代理中堆叠消息，以及如何与这个代理（RabbitMQ）在 Spring 生态系统中进行交互。

## 准备工作

这个示例是关于实现专用队列，而不再是主题（广播），以便用户可以接收与他们正在查看的特定内容相关的实时更新。这也演示了 SockJS 客户端如何将数据发送到他们的私有队列。

对于私有队列，我们必须保护消息和队列访问。我们已经打破了我们对 API 的无状态原则，以利用 Spring Session。这扩展了`cloudstreetmarket-api`执行的身份验证，并在`cloudstreetmarket-websocket`中重用了 Spring Security 上下文。

## 如何做到这一点...

### Apache HTTP 代理配置

因为`v8.2.x`分支引入了新的`cloudstreetmarket-websocket`网络应用程序，Apache HTTP 代理配置需要更新以完全支持我们的 WebSocket 实现。我们的`VirtualHost`定义现在是：

```java
<VirtualHost cloudstreetmarket.com:80>
  ProxyPass        /portal http://localhost:8080/portal
  ProxyPassReverse /portal http://localhost:8080/portal
  ProxyPass        /api  	http://localhost:8080/api
  ProxyPassReverse /api  	http://localhost:8080/api
  ProxyPass        /ws  	http://localhost:8080/ws
  ProxyPassReverse /ws  	http://localhost:8080/ws
  RewriteEngine on
  RewriteCond %{HTTP:UPGRADE} ^WebSocket$ [NC]
  RewriteCond %{HTTP:CONNECTION} ^Upgrade$ [NC]
  RewriteRule .* ws://localhost:8080%{REQUEST_URI} [P]
  RedirectMatch ^/$ /portal/index
</VirtualHost>
```

### Redis 服务器安装

1.  如果您使用的是基于 Linux 的机器，请在[`redis.io/download`](http://redis.io/download)下载最新稳定版本（3+）。要下载的存档格式是`tar.gz`。按照页面上的说明进行安装（解包，解压缩，并使用 make 命令构建）。

安装完成后，要快速启动 Redis，请运行：

```java
$ src/redis-server
```

1.  如果您使用的是基于 Windows 的机器，我们建议使用此存储库：[`github.com/ServiceStack/redis-windows`](https://github.com/ServiceStack/redis-windows)。请按照`README.md`页面上的说明进行操作。运行 Microsoft 的 Redis 本机端口允许您在没有任何其他第三方安装的情况下运行 Redis。

要快速启动 Redis 服务器，运行以下命令：

```java
$ redis-server.exe redis.windows.conf
```

1.  当 Redis 运行时，您应该能够看到以下欢迎屏幕：![Redis 服务器安装](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00910.jpeg)

1.  在 Eclipse 中更新 Tomcat 配置以使用本地 Tomcat 安装。要这样做，请双击当前服务器（**服务器**选项卡）：![Redis 服务器安装](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00911.jpeg)

1.  这将打开以下配置面板：![Redis 服务器安装](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00912.jpeg)

确保**使用 Tomcat 安装**单选按钮已被选中。

### 提示

如果面板变灰，右键单击当前服务器，然后单击**添加**，**删除**...从服务器中删除三个部署的 web 应用程序，然后再次右键单击服务器，然后单击**发布**。

1.  现在，下载以下 jar 包：

+   **jedis-2.5.2.jar**：一个小型的 Redis Java 客户端库

+   **commons-pool2-2.2.jar**：Apache 通用对象池库

您可以分别从[`central.maven.org/maven2/redis/clients/jedis/2.5.2/jedis-2.5.2.jar`](http://%20http://central.maven.org/maven2/redis/clients/jedis/2.5.2/jedis-2.5.2.jar)和[`central.maven.org/maven2/org/apache/commons/commons-pool2/2.2/commons-pool2-2.2.jar`](http://central.maven.org/maven2/org/apache/commons/commons-pool2/2.2/commons-pool2-2.2.jar)下载它们。

你也可以在`chapter_8/libs`目录中找到这些 jar 包。

1.  在`chapter_8/libs`目录中，您还将找到**tomcat-redis-session-manager-2.0-tomcat-8.jar**存档。将三个 jar 包`tomcat-redis-session-manager-2.0-tomcat-8.jar`，`commons-pool2-2.2.jar`和`jedis-2.5.2.jar`复制到 Eclipse 引用的本地 Tomcat 安装的`lib`目录中。如果我们在第一章中的说明已经被遵循，那么这应该是`C:\tomcat8\lib`或`/home/usr/{system.username}/tomcat8/lib`。

1.  现在在你的工作空间中，打开**Server**项目的**context.xml**文件。![Redis 服务器安装](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00913.jpeg)

1.  添加以下`Valve`配置：

```java
<Valve asyncSupported="true" className="edu.zipcloud.catalina.session.RedisSessionHandlerValve"/>
<Manager className="edu.zipcloud.catalina.session.RedisSessionManager"
      host="localhost" 
      port="6379" 
      database="0" 
      maxInactiveInterval="60"/>
```

### MySQL 服务器安装

在创建新的`cloudstreetmarket-websocket`web 应用程序时，我们还将数据库引擎从 HSQLDB 更改为了 MySQL。这样做使我们能够在`api`和`websocket`模块之间共享数据库。

1.  本节的第一步是从[`dev.mysql.com/downloads/mysql`](http://dev.mysql.com/downloads/mysql)下载并安装 MySQL 社区服务器。下载适合您系统的通用版本。如果您使用的是 MS Windows，我们建议安装安装程序。

1.  您可以按照 MySQL 团队在[`dev.mysql.com/doc/refman/5.7/en/installing.html`](http://dev.mysql.com/doc/refman/5.7/en/installing.html)提供的安装说明进行操作。

我们现在要为模式用户和数据库名称定义一个通用配置。

1.  创建一个以您选择的密码为密码的根用户。

1.  创建一个技术用户（具有管理员角色），应用程序将使用该用户。此用户需要被称为`csm_tech`，并且需要有密码`csmDB1$55`：![MySQL 服务器安装](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00914.jpeg)

1.  启动 MySQL 客户端（命令行工具），如下所示：

+   在 MS Windows 上，启动 MySQL 服务器安装目录中的`mysql.exe`程序：`\MySQL Server 5.6\bin\mysql.exe`

+   在 Linux 或 Mac OS 上，从终端调用`mysql`命令

在两个平台上，第一步是提供之前选择的 root 密码。

1.  使用 MySQL Workbench 或 MySQL 客户端创建`csm`数据库：

```java

mysql> CREATE DATABASE csm; 

```

1.  选择`csm`数据库作为当前数据库：

```java

mysql> USE csm;

```

1.  从 Eclipse 启动本地 Tomcat 服务器。一旦它启动，您可以再次关闭它；这一步只是为了让 Hibernate 生成模式。

1.  然后我们需要手动插入数据。为此，依次执行以下导入命令：

```java

mysql> csm < <home-directory>\cloudstreetmarket-parent\cloudstreetmarket-core\src\main\resources\META-INF\db\currency_exchange.sql;
mysql> csm < <home-directory>\cloudstreetmarket-parent\cloudstreetmarket-core\src\main\resources\META-INF\db\init.sql;
mysql> csm < <home-directory>\cloudstreetmarket-parent\cloudstreetmarket-core\src\main\resources\META-INF\db\stocks.sql;
mysql> csm < <home-directory>\cloudstreetmarket-parent\cloudstreetmarket-core\src\main\resources\META-INF\db\indices.sql;

```

### 应用级别的更改

1.  在`cloudstreetmarket-api`和`cloudstreetmarket-websocket`中，已向`web.xml`文件添加了以下过滤器。此过滤器必须在 Spring Security 链定义之前放置：

```java
<filter>
  <filter-name>springSessionRepositoryFilter</filter-name>
  <filter-class>
  org.springframework.web.filter.DelegatingFilterProxy
  </filter-class>
  <async-supported>true</async-supported>
</filter>
<filter-mapping>
  <filter-name>springSessionRepositoryFilter</filter-name>
  <url-pattern>/*</url-pattern>
</filter-mapping>
```

1.  还添加了一些 Maven 依赖项到`cloudstreetmarket-api`：

```java
<!-- Spring Session -->
<dependency>
  <groupId>org.springframework.session</groupId>
  <artifactId>spring-session</artifactId>
  <version>1.0.2.RELEASE</version>
</dependency>
<dependency>
  <groupId>org.apache.commons</groupId>
  <artifactId>commons-pool2</artifactId>
  <version>2.2</version>
</dependency>
<dependency>
  <groupId>org.springframework.session</groupId>
  <artifactId>spring-session-data-redis</artifactId>
  <version>1.0.2.RELEASE</version>
</dependency>
<!-- Spring Security -->
<dependency>
  <groupId>org.springframework.security</groupId>
  <artifactId>spring-security-messaging</artifactId>
  <version>4.0.2.RELEASE</version>
</dependency>
  <dependency>
    <groupId>commons-io</groupId>
    <artifactId>commons-io</artifactId>
    <version>2.4</version>
  </dependency>
```

1.  再次在`cloudstreetmarket-api`中，`security-config.xml`已更新以反映 Spring Security 过滤器链中的以下更改：

```java
<security:http create-session="ifRequired" 
  authentication-manager-ref="authenticationManager" entry-point-ref="authenticationEntryPoint">
 <security:custom-filter ref="basicAuthenticationFilter" after="BASIC_AUTH_FILTER" />
   <security:csrf disabled="true"/>
 <security:intercept-url pattern="/oauth2/**" access="permitAll"/>
 <security:intercept-url pattern="/basic.html" access="hasRole('ROLE_BASIC')"/>
   <security:intercept-url pattern="/**" access="permitAll"/>
 <security:session-management session-authentication-strategy-ref="sas"/>
</security:http>
<bean id="sas" class="org.springframework.security.web.authentication.session.SessionFixationProtectionStrategy" />
```

1.  同时，`security-config.xml`文件和`cloudstreetmarket-websocket`中的`security-config.xml`文件现在定义了三个额外的 bean：

```java
<bean class="org.springframework.data.redis.connection.jedis.JedisConnectionFactory" p:port="6379"/>
<bean class="org.springframework.session.data.redis.config.annotation.web.http.RedisHttpSessionConfiguration"/>
<bean class="edu.zipcloud.cloudstreetmarket.core.util.RootPath CookieHttpSessionStrategy"/>
```

1.  在`cloudstreetmarket-webapp`中小心翼翼地不要创建会话。我们希望会话只在`cloudstreetmarket-api`中创建。我们通过向`cloudstreetmarket-webapp`中的`web.xml`文件添加以下配置来实现这一点：

```java
<session-config>
    <session-timeout>1</session-timeout>
    <cookie-config>
        <max-age>0</max-age>
    </cookie-config>
</session-config>
```

1.  关于 Spring Security，`cloudstreetmarket-websocket`具有以下配置：

```java
<bean id="securityContextPersistenceFilter" class="org.springframework.security.web.context.SecurityContextPersistenceFilter"/>
<security:http create-session="never" 
authentication-manager-ref="authenticationManager" entry-point-ref="authenticationEntryPoint">
  <security:custom-filter ref="securityContextPersistenceFilter" before="FORM_LOGIN_FILTER" />
  <security:csrf disabled="true"/>
  <security:intercept-url pattern="/channels/private/**" access="hasRole('OAUTH2')"/>
  <security:headers>
      <security:frame-options policy="SAMEORIGIN" />
  </security:headers>
</security:http>
<security:global-method-security secured-annotations="enabled" pre-post-annotations="enabled" authentication-manager-ref="authenticationManager"/>
```

1.  `cloudstreetmarket-websocket`中的两个配置 bean 完成了 XML 配置：

在`edu.zipcloud.cloudstreetmarket.ws.config`中定义的`WebSocketConfig` bean 如下：

```java
@EnableScheduling
@EnableAsync
@EnableRabbit
@Configuration
@EnableWebSocketMessageBroker
public class WebSocketConfig extends   AbstractSessionWebSocketMessageBrokerConfigurer<Expiring Session> {
  @Override
  protected void configureStompEndpoints(StompEndpointRegistry registry) {
          registry.addEndpoint("/channels/users/broadcast")
          .setAllowedOrigins(protocol.concat(realmName))
          .withSockJS()
          .setClientLibraryUrl( Constants.SOCKJS_CLIENT_LIB);

        registry.addEndpoint("/channels/private")
          .setAllowedOrigins(protocol.concat(realmName))
          .withSockJS()
          .setClientLibraryUrl( Constants.SOCKJS_CLIENT_LIB);
  }

  @Override
  public void configureMessageBroker(final MessageBrokerRegistry registry) {
        registry.enableStompBrokerRelay("/topic", "/queue");
        registry.setApplicationDestinationPrefixes("/app");
  }

  @Override
  public void configureClientInboundChannel(ChannelRegistration registration) {
        registration.taskExecutor() corePoolSize(Runtime.getRuntime().availableProcessors() *4);
  }

  @Override
  //Increase number of threads for slow clients
  public void configureClientOutboundChannel( 
     ChannelRegistration registration) {
        registration.taskExecutor().corePoolSize( Runtime.getRuntime().availableProcessors() *4);
  }
  @Override
  public void configureWebSocketTransport(  
    WebSocketTransportRegistration registration) {
        registration.setSendTimeLimit(15*1000) 
          .setSendBufferSizeLimit(512*1024); 
  }
}
```

在`edu.zipcloud.cloudstreetmarket.ws.config`中定义的`WebSocketSecurityConfig` bean 如下：

```java
@Configuration
public class WebSocketSecurityConfig extends AbstractSecurityWebSocketMessageBrokerConfigurer {
    @Override
    protected void configureInbound( MessageSecurityMetadataSourceRegistry messages) {
    messages.simpMessageDestMatchers("/topic/actions", "/queue/*", "/app/queue/*").permitAll();
    }
    @Override
    protected boolean sameOriginDisabled() {
    return true;
    }
}
```

1.  `ActivityFeedWSController`类已复制到`cloudstreetmarket-websocket`以广播用户活动。它仍然不需要任何特定的角色或身份验证：

```java
@RestController
public class ActivityFeedWSController extends CloudstreetWebSocketWCI{

    @MessageMapping("/channels/users/broadcast")
    @SendTo("/topic/actions")
    public UserActivityDTO handle(UserActivityDTO message) throws Exception {
        return message;
    }

    @RequestMapping(value="/channels/users/broadcast/info", produces={"application/json"})
    @ResponseBody
    public String info(HttpServletRequest request) {
      return "v0";
    }
}
```

1.  一个额外的控制器将消息（即最新的股票价值）发送到私有队列：

```java
@RestController
public class StockProductWSController extends CloudstreetWebSocketWCI<StockProduct>{

  @Autowired
  private StockProductServiceOffline stockProductService;

  @MessageMapping("/queue/CSM_QUEUE_{queueId}")
  @SendTo("/queue/CSM_QUEUE_{queueId}")
  @PreAuthorize("hasRole('OAUTH2')")
  public List<StockProduct> sendContent(@Payload List<String> tickers, @DestinationVariable("queueId") String queueId) throws Exception {
      String username = extractUserFromQueueId(queueId);
      if(!getPrincipal().getUsername().equals(username)){
        throw new IllegalAccessError("/queue/CSM_QUEUE_"+queueId);
      }
      return stockProductService.gather(username,      tickers.toArray(new String[tickers.size()]));
  }

  @RequestMapping(value=PRIVATE_STOCKS_ENDPOINT+"/info", produces={"application/xml", "application/json"})
  @ResponseBody
  @PreAuthorize("hasRole('OAUTH2')")
  public String info(HttpServletRequest request) {
      return "v0";
  }

  private static String extractUserFromQueueId(String token){
        Pattern p = Pattern.compile("_[0-9]+$");
        Matcher m = p.matcher(token);
        String sessionNumber = m.find() ? m.group() : "";
        return token.replaceAll(sessionNumber, "");
	}
}
```

1.  在客户端上，新的 WebSockets 是从股票搜索屏幕（股票结果列表）发起的。特别是在`stock_search.js`和`stock_search_by_market.js`中，已添加以下块，以便定期请求对已显示给经过身份验证的用户的结果集的数据更新：

```java
if(httpAuth.isUserAuthenticated()){
  window.socket = new SockJS('/ws/channels/private');
  window.stompClient = Stomp.over($scope.socket);
  var queueId = httpAuth.generatedQueueId();

  window.socket.onclose = function() {
    window.stompClient.disconnect();
  };
  window.stompClient.connect({}, function(frame) {
    var intervalPromise = $interval(function() {
      window.stompClient.send( '/app/queue/CSM_QUEUE_'+queueId, {}, JSON.stringify($scope.tickers)); 
    }, 5000);

    $scope.$on(
        "$destroy",
        function( event ) {
          $interval.cancel(intervalPromise);
          window.stompClient.disconnect();
        }
    );

  window.stompClient.subscribe('/queue/CSM_QUEUE_'+queueId, function(message){
    var freshStocks = JSON.parse(message.body);
    $scope.stocks.forEach(function(existingStock) {
      //Here we update the currently displayed stocks
    });

    $scope.$apply();
    dynStockSearchService.fadeOutAnim(); //CSS animation   
      //(green/red backgrounds…)
     });
    });
};
```

`httpAuth.generatedQueueId()`函数基于经过身份验证的用户名生成一个随机队列名称（有关详细信息，请参见`http_authorized.js`）。

### RabbitMQ 配置

1.  打开 RabbitMQ WebConsole，选择**Admin**选项卡，然后选择**Policy**菜单（也可以从`http://localhost:15672/#/policies` URL 访问）。

1.  添加以下策略：![RabbitMQ 配置](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00915.jpeg)

此策略（命名为`PRIVATE`）适用于所有与模式`CSM_QUEUE_*`匹配的自动生成的队列，自动过期时间为 24 小时。

### 结果

1.  让我们来看看...在启动 Tomcat 服务器之前，请确保：

+   MySQL 正在加载数据运行

+   Redis 服务器正在运行

+   RabbitMQ 正在运行

+   Apache HTTP 已重新启动/重新加载

1.  当所有这些信号都是绿色时，启动 Tomcat 服务器。

1.  使用 Yahoo!帐户登录应用程序，注册新用户，并导航到屏幕：**价格和市场** | **按市场搜索**。如果您选择的市场可能在您的时间开放，您应该能够注意到结果列表上的实时更新：![结果](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00916.jpeg)

## 它是如何工作的...

### Redis 服务器

Redis 是一个开源的内存数据结构存储。日复一日，它越来越受欢迎，作为 NoSQL 数据库和键值存储。

它能够存储具有可选过期时间和非常高的可用性（在其显著的集群中）的键，使其成为会话管理器实现的非常可靠的底层技术。这正是我们通过 Spring Session 所做的使用。

### Spring 会话

Spring Session 是一个相对较新的 Spring 项目，但它旨在成长并在 Spring 生态系统中占据重要位置，特别是最近的微服务和物联网趋势。该项目由 Pivotal inc 的 Rob Winch 管理。正如之前介绍的，Spring Session 提供了一个 API 来管理不同 Spring 组件的用户会话。

Spring Session 最有趣和显著的特性是其能够与容器（Apache Tomcat）集成，以提供`HttpSession`的自定义实现。

#### SessionRepositoryFilter

为了使用自定义的`HttpSession`实现，Spring Session 完全替换了`HttpServletRequest`，使用自定义包装器（`SessionRepositoryRequestWrapper`）。这个操作是在`SessionRepositoryFilter`内执行的，它是需要在`web.xml`中配置的 servlet 过滤器，以拦截请求流（在 Spring MVC 之前）。

为了完成其工作，`SessionRepositoryFilter`必须有一个`HttpSession`实现。在某个时候，我们注册了`RedisHttpSessionConfiguration` bean。这个 bean 定义了其他几个 bean，其中包括一个`sessionRepository`，它是一个`RedisOperationsSessionRepository`。

看到`SessionRepositoryFilter`如何对跨应用程序的所有执行的会话操作进行桥接，以实际执行这些操作的引擎实现。

##### RedisConnectionFactory

为了生成适合连接到 Redis 的连接，需要一个`RedisConnectionFactory`实现。在选择`RedisConnectionFactory`实现时，我们一直遵循 Spring 团队的选择，这似乎是`JedisConnectionFactory`。这个`RedisConnectionFactory`依赖于 Jedis（一个轻量级的 Redis Java 客户端）。[`github.com/xetorthio/jedis`](https://github.com/xetorthio/jedis)。

#### CookieHttpSessionStrategy

我们已经注册了一个`HttpSessionStrategy`实现：`RootPathCookieHttpSessionStrategy`。这个类是我们代码库中 Spring `CookieHttpSessionStrategy`的定制版本。

因为我们想要将 cookie 从`cloudstreetmarket-api`传递到`cloudstreetmarket-websocket`，所以 cookie 路径（cookie 的属性）需要设置为根路径（而不是 servlet 上下文路径）。Spring Session 1.1+应该提供可配置的路径功能。

[`github.com/spring-projects/spring-session/issues/155`](https://github.com/spring-projects/spring-session/issues/155)

目前，我们的`RootPathCookieHttpSessionStrategy`（基本上是`CookieHttpSessionStrategy`）生成并期望带有**SESSION**名称的 cookie：

![CookieHttpSessionStrategy](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00917.jpeg)

目前，只有`cloudstreetmarket-api`生成这样的 cookie（其他两个 web 应用程序在生成 cookie 时受到限制，以免干扰我们的会话）。

#### Spring Data Redis 和 Spring Session Data Redis

你还记得我们的好朋友 Spring Data JPA 吗？现在，Spring Data Redis 遵循类似的目的，但用于 Redis NoSQL 键值存储：

|   | *"Spring Data Redis（框架通过消除与 Spring 的出色基础设施支持交互所需的冗余任务和样板代码，使编写使用 Redis 键值存储的 Spring 应用程序变得容易。"* |   |
| --- | --- | --- |
|   | --*Spring Data Redis 参考* |

Spring Session Data Redis 是专门为 Spring Session 管理目的实现 Spring Data Redis 的 Spring 模块。

### Tomcat 的 Redis 会话管理器

Apache Tomcat 本身提供了集群和会话复制功能。然而，这些功能依赖于负载均衡器的粘性会话。粘性会话在可伸缩性方面有利有弊。作为缺点，我们可以记住当服务器宕机时会话可能丢失。此外，会话的粘性可能会在我们实际需要应对交通激增时导致加载时间缓慢。

我们还使用了 James Coleman 的一个开源项目，允许 Tomcat 服务器在会话创建时立即将非粘性会话存储在 Redis 中，以供其他 Tomcat 实例使用。这个开源项目可以在以下地址找到：

[`github.com/jcoleman/tomcat-redis-session-manager`](https://github.com/jcoleman/tomcat-redis-session-manager)

然而，这个项目并不正式支持 Tomcat 8。因此，另一个分支在 Tomcat 发布过程中更进一步，并且更接近 Tomcat 8 的要求：

[`github.com/rmohr/tomcat-redis-session-manager`](https://github.com/rmohr/tomcat-redis-session-manager)

我们分叉了这个存储库，并为 Tomcat 8 提供了一个适配器，网址是 https://github.com/alex-bretet/tomcat-redis-session-manager。

`tomcat-redis-session-manager-2.0-tomcat-8.jar`复制到`tomcat/lib`来自这个存储库。

### 注意

Tomcat 8 仍然很新，外围工具需要时间来跟进发布。我们不提供`tomcat-redis-session-manager-2.0-tomcat-8.jar`供生产使用。

### 在 Redis 中查看/清除会话

在 Redis 的主安装目录中，可以找到一个命令行工具（`Cli`）的可执行文件。可以从命令行启动这个可执行文件：

```java

$ src/redis-cli

```

或者：

```java

$ redis-cli.exe

```

这个可执行文件可以访问 Redis 控制台。例如，`KEY *`命令列出所有活动会话：

```java
127.0.0.1:6379> keys *
1) "spring:session:sessions:4fc39ce3-63b3-4e17-b1c4-5e1ed96fb021"
2) "spring:session:expirations:1418772300000"
```

`FLUSHALL`命令清除所有活动会话：

```java
redis 127.0.0.1:6379> FLUSHALL
OK
```

### 提示

通过在线教程了解 Redis 客户端语言，网址是[`try.redis.io`](http://try.redis.io)。

### securityContextPersistenceFilter

我们在`cloudstreetmarket-websocket` Spring Security 过滤器链中使用这个过滤器。它的作用是从配置的`SecurityContextRepository`中将外部 Spring Security 上下文注入到`SecurityContextHolder`中：

```java
<bean id="securityContextPersistenceFilter" class="org.sfw.security.web.context.SecurityContextPersistence Filter">
    <constructor-arg name="repo" ref="httpSessionSecurityContextRepo" />
</bean>

<bean id="httpSessionSecurityContextRepo" class='org.sfw.security.web.context.HttpSessionSecurityContext Repository'>operty name='allowSessionCreation' value='false' />
</bean> 
```

这个过滤器与`SecurityContextRepository`交互，以便在过滤器链完成后持久化上下文。结合 Spring Session，当您需要重用在另一个组件（在我们的情况下是另一个 Web 应用程序）中执行的身份验证时，这个过滤器非常有用。

在这一点上，我们还能够声明一个`global-method-security`元素（Spring Security 命名空间的一部分），允许我们在`@MessageMapping`注释的方法（我们的消息处理方法）中使用`@PreAuthorize`注释：

```java
<global-method-security secured-annotations="enabled" pre-post-annotations="enabled" />
```

### AbstractSessionWebSocketMessageBrokerConfigurer

这是一个很长的标题。我们使用这个抽象类为我们的`WebSocketConfig`提供以下功能：

+   确保会话在传入的 WebSocket 消息上保持活动状态

+   确保 WebSocket 会话在会话终止时被销毁

### AbstractSecurityWebSocketMessageBrokerConfigurer

以类似的方式，这个抽象类为我们的`WebSocketSecurityConfig` bean 提供了授权功能。有了它，`WebSocketSecurityConfig` bean 现在控制着允许传入消息的目的地。

## 还有更多...

### Spring Session

再次推荐 Spring Session 的 Spring 参考文档，非常好。请查看：

[`docs.spring.io/spring-session/docs/current/reference/html5`](http://docs.spring.io/spring-session/docs/current/reference/html5)

### Apache HTTP 代理额外配置

在`httpd.conf`中添加的几行用于在 WebSocket 握手期间将 WebSocket 方案重写为`ws`。不这样做会导致 SockJS 退回到其**XHR**选项（WebSocket 模拟）。

### Spring Data Redis

此外，我们建议您阅读有关 Spring Data Redis 项目的更多信息（在其参考文档中）：

[`docs.spring.io/spring-data/data-redis/docs/current/reference/html`](http://docs.spring.io/spring-data/data-redis/docs/current/reference/html)

## 另请参阅

+   **深入了解 Spring WebSockets** by Sergi Almar: 这是在 SpringOne2GX 2014 上进行的演示：

[`www.slideshare.net/sergialmar/websockets-with-spring-4`](http://www.slideshare.net/sergialmar/websockets-with-spring-4)

+   **Spring-websocket-portfolio，展示应用程序**：我们还必须强调 Rossen Stoyanchev 的 Spring WebSocket 展示应用程序：

[`github.com/rstoyanchev/spring-websocket-portfolio`](https://github.com/rstoyanchev/spring-websocket-portfolio)



# 第十六章：测试和故障排除

通过列出的以下配方，本章介绍了一套用于维护、调试和改进应用程序状态的常见实践：

+   使用 Flyway 自动化数据库迁移

+   使用 Mockito 和 Maven Surefire 进行单元测试

+   使用 Cargo、Rest-assured 和 Maven Failsafe 进行集成测试

+   在集成测试中注入 Spring Bean

+   使用 Log4j2 进行现代应用程序日志记录

# 介绍

随着我们现在接近这段旅程的结束，我们必须看到如何巩固工作。在现实世界中，测试必须在开发功能之前编写（或至少同时进行）。在软件开发中编写自动化测试传达了对应用程序状态的巨大信心。这是确保没有遗漏的最佳方式。拥有一个能够通过现代持续集成工具自行测试的系统，确保功能不会在任何时候受到损害。

通过 UI 进行手动测试不能被信任来覆盖开发人员必须考虑的每一个边缘情况。开发人员有责任确保所有漏洞并覆盖所有可能的路径，这是一个很大的责任。

我们的开发人员工作是一项了不起的工作。永恒的技术提升为我们每个人设定了无与伦比的步伐-保持竞争，应对市场，有时引领市场。

我们的工作是长时间的高度专注、搜索信息、设计、重新设计等。编写测试为周期带来了健康的稳定性。它使我们能够在开发的功能上完成一天，甚至在几周和几个月后也是如此。

# 使用 FlyWay 自动化数据库迁移

在交付生命周期中，跨版本和多个环境维护数据库可能会成为一个真正的头疼事。Flyway 是对模式更改可能引起的熵的肯定保护。管理和自动化迁移，Flyway 是软件制造商的一项非常有价值的资产。

## 准备就绪

在这个配方中，我们审查了 Flyway 配置。我们特别审查了它与 Maven 的集成。这将使每个构建都升级（如果有必要）相应的数据库，以使其达到期望水平。

## 如何做…

1.  在 Eclipse 的**Git Perspective**中，检出分支`v9.x.x`的最新版本。

1.  在您的工作区的`/app`目录中，`cloudstreetmarket.properties`文件已更新。此外，还出现了一个额外的`db/migration`目录，其中包含一个`Migration-1_0__init.sql`文件，以及一个新的`/logs`目录。

1.  请确保将所有这些更改反映到位于您的操作系统用户`home` `directory`中的 app 目录中：`<home-directory>/app`。

1.  还要确保您的**MySQL 服务器**正在运行。

1.  在`zipcloud-parent`项目上运行**Maven clean**和**Maven install**命令（右键单击项目**Run as…** | **Maven Clean**，然后**Run as…** | **Maven Install**）。

1.  现在，在`cloudstreetmarket-parent`项目上运行**Maven clean**和**Maven install**命令。

1.  在堆栈跟踪的顶部（在 Maven 阶段的包），您应该看到以下日志：![如何做…](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00918.jpeg)

1.  在这个阶段，数据库应该已经被重置，以匹配结构和数据的标准状态。

1.  如果您重新运行构建，现在应该看到以下日志：![如何做…](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00919.jpeg)

1.  在父`pom.xml`（在`cloudstreetmarket-parent`中），您可以注意到一个新的插件定义：

```java
<plugin>
  <groupId>com.googlecode.flyway</groupId>
  <artifactId>flyway-maven-plugin</artifactId>
  <version>2.3.1</version>
  <inherited>false</inherited>
  <executions>
      <execution>
      <id>package</id>
      <goals>
      <goal>migrate</goal>
      </goals>
      </execution>
  </executions>
  <configuration>
    <driver>${database.driver}</driver>
    <url>${database.url}</url>
    <serverId>${database.serverId}</serverId>
    <schemas>
      <schema>${database.name}</schema>
      </schemas>
    <locations>
      <location>
        filesystem:${user.home}/app/db/migration
        </location>
      </locations>
      <initOnMigrate>true</initOnMigrate>
        <sqlMigrationPrefix>Migration-</sqlMigrationPrefix>
        <placeholderPrefix>#[</placeholderPrefix>
        <placeholderSuffix>]</placeholderSuffix>
        placeholderReplacement>true</placeholderReplacement>
        <placeholders>
        <db.name>${database.name}</db.name>
        </placeholders>
  </configuration>
  <dependencies>
        <dependency>
        <groupId>mysql</groupId>
        <artifactId>mysql-connector-java</artifactId>
        <version>5.1.6</version>
        </dependency>
  </dependencies>
  </plugin>
```

1.  一些变量（例如`${database.driver}`）在此定义中使用的默认属性对应于`pom.xml`的顶层设置：

```java
  <database.name>csm</database.name>
  <database.driver>com.mysql.jdbc.Driver</database.driver>
  <database.url>jdbc:mysql://localhost</database.url>
  <database.serverId>csm_db</database.serverId>
```

1.  `database.serverId`必须与 Maven `settings.xml`文件中的新`Server`条目匹配（在下一点中描述）。

1.  编辑 Maven `settings.xml`文件（您必须在第一章中创建的*企业 Spring 应用程序的设置例程*中找到位于`<home-directory>/.m2/settings.xml`）。在根节点的某个位置添加以下块：

```java
  <servers>
      <server>  
      <id>csm_db</id>
      <username>csm_tech</username>
      <password>csmDB1$55</password>
      </server>
  </servers>
```

1.  在父`pom.xml`（在`cloudstreetmarket-parent`中），已添加了一个新的`Profile`，用于可选地覆盖此`pom.xml`的默认属性：

```java
<profiles>
  <profile>
  <id>flyway-integration</id>
  <properties>
  <database.name>csm_integration</database.name>
  <database.driver>com.mysql.jdbc.Driver</database.driver>
  <database.url>jdbc:mysql://localhost</database.url>
  <database.serverId>csm_db</database.serverId>
  </properties>
  </profile>
</profiles>
```

### 提示

使用`csm_integration`配置文件运行`Maven Clean Install`（`mvn clean install –Pcsm_integration`）在这种情况下会升级`csm_integration`数据库（如果有必要）。

## 它是如何工作的…

Flyway 是一个数据库版本控制和迁移工具，采用 Apache v2 许可证（免费软件）。它是 Boxfuse GmbH 公司的注册商标。

Flyway 不是这个类别中唯一的产品，但在行业中以其简单性和易配置性而广泛存在。迁移脚本可以用普通的 SQL 编写，并支持许多提供程序。从传统的 RDBMS（Oracle、MySQL、SQL Server 等）到内存数据库（HSQLDB、solidDB 等），甚至云解决方案（AWS Redshift、SQL Azure 等）都得到支持。

### 有限数量的命令

Flyway 提供了以下六个命令，用于报告和操作目的。

#### 迁移

`Migrate`命令是我们集成到 Maven 打包阶段的目标。它查找类路径或文件系统以执行潜在的迁移。可以配置多个`locations`（脚本存储库）。在 Flyway Maven 插件中，这些`locations`在根`configuration`节点中定义。设置模式以保留特定的文件名。

#### 清理

`Clean`命令还原了数据库模式的原始状态。使用此命令删除所有对象（表、视图、函数等）。

#### 信息

`Info`命令提供有关给定模式的当前状态和迁移历史的反馈。如果您查看本地 MySQL 服务器，在`csm`模式中，您会注意到已创建一个名为`schema_version`的元数据表。Flyway 使用以下表来比较脚本存储库状态与数据库状态，并填补差距。

| 版本 | 描述 | 脚本 | 安装于 | 成功 |
| --- | --- | --- | --- | --- |
| `0` | `<< Flyway 模式创建 >>` | `'csm'` | `2015 年 11 月 12 日 18:11` | `1` |
| `1` | `删除并创建` | `/Migration-1_0__drop_and_create.sql` | `2015 年 11 月 12 日 18:11` | `1` |

`Info`命令基本上将此表打印为报告。

#### 验证

`Validate`命令可用于确保在数据库上执行的迁移实际上与当前存储库中的脚本相对应。

#### Baseline

当我们有一个尚未由 Flyway 管理的现有数据库时，可以使用`Baseline`命令。创建一个 Baseline 版本来标记数据库的状态，并使其准备好与即将到来的版本一起使用。在此 Baseline 之前的版本将被简单地忽略。

#### 修复

`Repair`命令可以清理元数据表的损坏状态。为此，Flyway 删除了失败的迁移条目，并重置了存储的校验和以匹配脚本的校验和。

### 关于 Flyway Maven 插件

Flyway Maven 插件提供了 Maven 控制 Flyway 程序的接口。我们对插件的配置如下：

```java
<plugin>
    <groupId>com.googlecode.flyway</groupId>
    <artifactId>flyway-maven-plugin</artifactId>
    <version>2.3.1</version>
    <inherited>false</inherited>
    <executions>
      <execution>
        <id>package</id>
        <goals>
          <goal>migrate</goal>
        </goals>
      </execution>
    </executions>
    <configuration>
      <driver>${database.driver}</driver>
    <url>${database.url}</url>
    <serverId>${database.serverId}</serverId>
    <schemas>
       <schema>${database.name}</schema>
    </schemas>
    <locations>
      <location>
          filesystem:${user.home}/app/db/migration
        </location>
        </locations>
    <initOnMigrate>true</initOnMigrate>
      <sqlMigrationPrefix>Migration-</sqlMigrationPrefix>
      <placeholderPrefix>#[</placeholderPrefix>
      <placeholderSuffix>]</placeholderSuffix>
      <placeholderReplacement>true</placeholderReplacement>
      <placeholders>
      <db.name>${database.name}</db.name>
     </placeholders>
  </configuration>
</plugin>
```

与 Maven 插件一样，执行部分允许将 Maven 阶段绑定到插件的一个或多个目标。对于 Flyway Maven 插件，目标是先前介绍的 Flyway 命令。我们告诉 Maven 何时考虑插件以及在该插件中调用什么。

我们的`configuration`部分介绍了在迁移期间检查的一些参数。例如，`locations`指定要递归扫描的迁移存储库（它们可以以`classpath`:或`filesystem:`开头）。`schemas`定义了 Flyway 管理的整套迁移的模式列表。第一个模式将成为迁移中的默认模式。

一个有趣的功能是能够在迁移脚本中使用变量，以便这些脚本可以用作多个环境的模板。变量名称使用`placeholders`定义，并且脚本中标识变量的方式可以通过`placeholderPrefix`和`placeholderSuffix`进行配置。

整个配置参数列表可以在以下位置找到：

[`flywaydb.org/documentation/maven/migrate.html`](http://flywaydb.org/documentation/maven/migrate.html)。

## 还有更多…

### 官方文档

Flyway 有很好的文档，并得到其社区的积极支持。在[`flywaydb.org`](http://flywaydb.org)上在线阅读有关该产品的更多信息。

您还可以通过 GitHub 存储库[`github.com/flyway/flyway`](https://github.com/flyway/flyway)来关注或贡献该项目。

## 另请参阅

+   **Liquibase**：Flyway 的主要竞争对手可能是 Liquibase。Liquibase 不使用纯 SQL 来编写脚本；它有自己的多重表示 DSL。有关更多信息，请访问：

[`www.liquibase.org`](http://www.liquibase.org)。

# 使用 Mockito 和 Maven Surefire 进行单元测试

单元测试对于监视组件的实现非常有用。Spring 的传统理念促进了应用程序范围内可重用的组件。这些组件的核心实现可能会改变状态（瞬时对象的状态）或触发与其他组件的交互。

单元测试中使用模拟特别评估了组件方法的行为，以及与其他组件的关系。当开发人员习惯于使用模拟时，令人惊讶的是设计在多大程度上受到了不同层和逻辑外部化的影响。同样，对象名称和方法名称变得更加重要。因为它们总结了在其他地方发生的事情，模拟节省了下一个开发人员在代码区域操作时的精力。

开发单元测试在本质上是企业政策。由于测试覆盖的代码百分比可以很容易地反映产品的成熟度，这种代码覆盖率也正在成为评估公司及其产品的标准参考。还必须指出，作为开发流程进行代码审查的公司从拉取请求中获得了有价值的见解。当拉取请求通过测试突出显示行为变化时，潜在变化的影响变得更加清晰。

## 如何做…

1.  在`cloudstreetmarket-parent`项目上重新运行`Maven Install`，就像在上一个示例中一样。当构建过程开始构建核心模块时，您应该看到以下日志，表明在**test**阶段（在**compile**和**package**之间）执行了单元测试：![如何做…](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00920.jpeg)

1.  这些测试可以在`cloudstreetmarket-core`模块中找到，特别是在`src/test/java`源文件夹中：![如何做…](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00921.jpeg)

单元测试和集成测试都使用 JUnit：

```java
    <dependency>
         <groupId>junit</groupId>
         <artifactId>junit</artifactId>
         <version>4.9</version>
    </dependency>
```

1.  JUnit 在 Eclipse IDE 中得到了原生支持，该 IDE 提供了从类或方法外部运行和调试测试的处理程序：![如何做…](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00922.jpeg)

1.  一个非常简单的 JUnit 测试类是`IdentifiableToIdConverterTest`（见下面的代码）。该类断言所有注册的实体都可以通过`IdentifiableToIdConverter`进行转换，以成为`Identifiable`实现（记住 HATEOAS）：

```java
import static org.junit.Assert.*;
import org.junit.Test;
import edu.zipcloud.cloudstreetmarket.core.entities.*;

public class IdentifiableToIdConverterTest {

  private IdentifiableToIdConverter converter;

  @Test
  public void canConvertChartStock(){
    converter = new IdentifiableToIdConverter(ChartStock.class);
    assertTrue(converter.canConvert(ChartStock.class));
    }

  @Test
  public void canConvertAction(){
    converter = new IdentifiableToIdConverter(Action.class);
    assertTrue(converter.canConvert(Action.class));
  }
}
```

1.  更高级的单元测试使用 Mockito 库。例如，在以下`YahooQuoteToCurrencyExchangeConverterTest`中：

```java
@RunWith(MockitoJUnitRunner.class)
public class YahooQuoteToCurrencyExchangeConverterTest {
  @InjectMocks
  private YahooQuoteToCurrencyExchangeConverter converter;
  @Mock
  private CurrencyExchangeRepository currencyExchangeRepository;
  @Test
  public void transferCriticalData(){
      when(currencyExchangeRepository.findOne(
      any(String.class))
      )
      .thenReturn(new CurrencyExchange("WHATEVER_ID""));
    CurrencyExchange currencyExchange = converter.convert(buildYahooQuoteInstance());
    assertEquals("WHATEVER_ID"",currencyExchange.getId());
    assertEquals("USDGBP=X"", currencyExchange.getName());
    assertEquals(BigDecimal.valueOf(10), 
      currencyExchange.getBid());
    ...
    assertEquals(BigDecimal.valueOf(17), 
    currencyExchange.getOpen());	
    verify(currencyExchangeRepository, times(1))
      .findOne(any(String.class));
  }
  ...
}
```

在这里，突出显示的`transferCriticalData()`测试获取了一个未使用真实的`@Autowired CurrencyExchangeRepository`而是使用**Mock**的`YahooQuoteToCurrencyExchangeConverter`实例。转换器使用`convert()`方法调用`YahooQuote`实例。

### 注意

Mock 被告知在其`convert()`方法内调用其`findOne`(`String s`)方法时返回特定的`CurrencyExchange`实例。然后，返回的`currencyExchange`对象逐个字段进行评估，以确保它们与各自的期望匹配。

1.  已在不同的模块中添加了对 Mockito 的 Maven 依赖项：

```java
    <dependency>
      <groupId>org.mockito</groupId>
      <artifactId>mockito-all</artifactId>
      <version>1.9.5<version>
    </dependency>
```

1.  在`CommunityServiceImplTest`中可以找到对 Mockito 的更广泛使用。例如，在以下示例中，`registerUser_generatePasswordAndEncodeIt`测试使用了`ArgumentCaptor`：

```java
@Test
public void registerUser_generatesPasswordAndEncodesIt() {
  when(communityServiceHelper.generatePassword())
    .thenReturn("newPassword");
  when(passwordEncoder.encode("newPassword"))
    .thenReturn("newPasswordEncoded");
  ArgumentCaptor<User>userArgumentCaptor = 
    ArgumentCaptor.forClass(User.class);
  userA.setPassword(null);
  communityServiceImpl.registerUser(userA);
  verify(userRepository, times(1))
    .save(userArgumentCaptor.capture());
  verify(passwordEncoder, times(1))
    .encode("newPassword");
  String capturedGeneratedPassword = 
    userArgumentCaptor.getValue().getPassword();
  assertEquals("newPasswordEncoded", capturedGeneratedPassword);
}
```

## 它是如何工作的...

### @Test 注释

`@Test`注释必须放置在 public void 方法上，以便 JUnit 将其视为测试用例。在这些方法中引发的异常将被视为测试失败。因此，没有引发任何异常的执行代表成功。

`@Test`注释可以通过传递以下两个可选参数进行自定义。

#### 预期和超时参数

`@Test`注释上的**expected**参数指定测试预期引发特定类型的异常才能成功。当引发不同类型的异常或根本没有引发异常时，JUnit 必须将执行视为失败。当测试用例在其`@Test`注释中提供了**timeout**参数时，当执行时间超过指定时间时，此测试将失败。

### @RunWith 注释

如配方中介绍的，`@RunWith`注释允许使用外部测试运行器（而不是默认的`BlockJUnit4ClassRunner`）。顺便说一句，指定默认 JUnit 运行器的声明性技术可能是将`@RunWith`定位到`JUnit4.class`，如下所示：`@RunWith(JUnit4.class)`。

| | *运行器运行测试并在执行过程中通知`RunNotifier`发生重要事件* | |
| --- | --- | --- |
| | --*JUnit.org Javadoc* |

自定义的`Runner`必须实现`org.junit.runner.Runner`中的抽象方法，例如`run(RunNotifier notifier)`和`getDescription()`。它还必须跟进核心 JUnit 函数，例如驱动测试执行流程。JUnit 具有一组注释，例如`@BeforeClass`，`@Before`，`@After`和`@AfterClass`，这些注释由`org.junit.runner.ParentRunner`本地处理。我们将在下面讨论这些注释。

### @Before 和@After 注释

在包含多个测试用例的测试类中，尝试使测试逻辑尽可能清晰是一个很好的做法。从这个角度来看，变量初始化和上下文重新初始化是人们经常尝试外部化以实现可重用性的操作。`@Before`注释可以定义在`public void`方法上，以便 Runner 在**每个单独的测试**之前执行它们。同样，`@After`注释标记了`public void`方法，以便在**每个测试**之后执行（通常用于清理资源或销毁上下文）。

关于继承，父类的`@Before`方法将在当前类的`@Before`方法之前运行。同样，超类中声明的`@After`方法将在当前类的`@After`方法之后运行。

Javadoc 中的另一个有趣的点指定了**所有**`@After`方法都保证会运行，**即使**`@Before`或`@Test`注释的方法引发异常。

### @BeforeClass 和 @AfterClass 注解

`@BeforeClass` 和 `@AfterClass` 注解可以应用于**public static void** 方法。`@BeforeClass` 使方法在测试生命周期中运行**一次**。该方法将在任何其他 `@Test` 或 `@Before` 标注的方法之前运行。

一个被标注为 `@AfterClass` 的方法保证在所有测试之后运行**一次**，并且在所有 `@BeforeClass`，`@Before` 或 `@After` 标注的方法之后运行，即使其中一个抛出异常。

`@BeforeClass` 和 `@AfterClass` 对于处理与测试上下文准备相关的消耗性能的操作（数据库连接管理和前/后业务处理）是有价值的工具。

关于继承，超类中标注为 `@BeforeClass` 的方法将在当前类的方法**之前**执行，而超类中标注为 `@AfterClass` 的方法将在当前类的方法**之后**执行。

### 使用 Mockito

Mockito 是一个支持测试驱动开发和行为驱动开发的开源测试框架。它允许创建双对象（模拟对象）并有助于隔离被测试系统。

#### MockitoJUnitRunner

我们一直在谈论自定义运行器。`MockitoJUnitRunner` 在实现上实际上是在默认的 `JUnitRunner` 周围实现了一个装饰模式。

这种设计使得使用这个运行器是可选的（所有提供的服务也可以用 Mockito 声明式地实现）。

`MockitoJUnitRunner` 自动初始化 `@Mock` 注解的依赖项（这样我们就不需要在 `@Before` 标注的方法中调用 `MockitoAnnotations.initMocks(this)`）。

`initMocks(java.lang.Object testClass)`

|   | *为给定的 testClass 初始化使用 Mockito 注解标注的对象：`@Mock`* |   |
| --- | --- | --- |
|   | --*Javadoc* |

`MockitoJUnitRunner` 也通过在每个测试方法之后调用 `Mockito.validateMockitoUsage()` 来验证我们实现框架的方式。这种验证通过明确的错误输出使我们更有效地使用库。

#### transferCriticalData 示例

被测试系统是 `YahooQuoteToCurrencyExchangeConverter`。`@InjectMocks` 注解告诉 Mockito 在每个测试之前使用初始化的 Mock 对象对目标转换器执行依赖注入（构造函数注入、属性设置器或字段注入）。

`Mockito.when(T methodCall)` 方法，结合 `thenReturn(T value)`，允许在 `converter.convert(...)` 测试方法内部实际调用 `currencyExchangeRepository.findOne` 时定义一个假的 `CurrencyExchange` 返回对象。

`Mockito verify` 方法与 `verify(currencyExchangeRepository, times(1)).findOne(any(String.class))` 告诉 Mockito 验证被测试的 `convert` 方法如何与 Mock(s) 交互。在下面的例子中，我们希望 `convert` 方法只调用了存储库一次。

#### registerUser 示例

更具体地，在 `registerUser_generatesPasswordAndEncodesIt` 测试中，我们使用 `MockitoArgumentCaptor` 手动对被调用的模拟方法的对象进行更深入的分析。

当我们没有中间层并且结果被重用来调用其他方法时，`MockitoArgumentCaptor` 是很有用的。

比表面的（但仍然非常有用的）类型检查更多的内省工具可能是必需的（例如，`any(String.class)`）。解决方案是在测试方法中使用 `ArgumentCaptor` 与额外的局部变量。

### 提示

记住，实现方法中的局部变量和瞬态状态总是增加相关测试的复杂性。更短、明确和内聚的方法总是更好的选择。

## 还有更多…

### 关于 Mockito

我们建议查看 Mockito 的 Javadoc，它非常完善并且包含了很多实用的例子。

[`docs.mockito.googlecode.com/hg/org/mockito/Mockito.html`](http://docs.mockito.googlecode.com/hg/org/mockito/Mockito.html)

### JUnit 规则

到目前为止，我们还没有涵盖 JUnit 规则。JUnit 提供了`@Rule`注解，可以应用于测试类字段，以抽象出重复的业务特定准备工作。通常用于准备测试上下文对象（固定装置）。

[`www.codeaffine.com/2012/09/24/junit-rules`](http://www.codeaffine.com/2012/09/24/junit-rules)

[`junit.org/javadoc/latest/org/junit/Rule.html`](http://junit.org/javadoc/latest/org/junit/Rule.html)

## 另请参阅

+   **代码覆盖率，JaCoCo**：JaCoCo 是一个库，用于帮助维护和增加应用程序中测试覆盖的代码百分比；它位于：[`eclemma.org/jacoco`](http://eclemma.org/jacoco)。

+   在以下位置阅读有关 JaCoCo Maven 插件的更多信息：

[`eclemma.org/jacoco/trunk/doc/maven.html`](http://eclemma.org/jacoco/trunk/doc/maven.html)

# 使用 Cargo、Rest-assured 和 Maven failsafe 进行集成测试

集成测试与单元测试一样重要。它们从更高的层面验证功能，并同时涉及更多的组件或层。当环境需要快速演变时，集成测试（IT 测试）变得更加重要。设计过程通常需要迭代，而单元测试有时会严重影响我们重构的能力，而高级别测试相对来说受到的影响较小。

## 准备就绪

本文介绍了如何开发重点放在 Spring MVC Web 服务上的自动化 IT 测试。这些 IT 测试不是行为测试，因为它们根本不评估用户界面。要测试行为，需要更高的测试级别，模拟用户通过应用程序界面的旅程。

我们将配置 Cargo Maven 插件，作为 pre-integration-test Maven 阶段的一部分来建立一个测试环境。在 integration-test 阶段，我们将让 Maven failsafe 插件执行我们的 IT 测试。这些 IT 测试将使用 Rest-assured 库对测试环境运行 HTTP 请求并断言 HTTP 响应。

## 如何做…

1.  我们已经在`cloudstreetmarket-api`模块中设计了集成测试。这些测试旨在测试 API 控制器方法。![如何做…](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00923.jpeg)

1.  伟大的 Rest-assured 库附带以下 Maven 依赖项：

```java
  <dependency>
    <groupId>com.jayway.restassured</groupId>
    <artifactId>rest-assured</artifactId>
    <version>2.7.0</version>
  </dependency>
```

1.  使用 REST-assured 进行 IT 测试的典型示例是`UserControllerIT.createUserBasicAuth()`：

```java
public class UserControllerIT extends AbstractCommonTestUser{
  private static User userA;
  @Before
  public void before(){
    userA = new User.Builder()
      .withId(generateUserName())
      .withEmail(generateEmail())
      .withCurrency(SupportedCurrency.USD)
      .withPassword(generatePassword())
      .withLanguage(SupportedLanguage.EN)
      .withProfileImg(DEFAULT_IMG_PATH)
      .build();
  }
  @Test
  public void createUserBasicAuth(){
    Response responseCreateUser = given()
      .contentType("application/json;charset=UTF-8")
      .accept("application/json"")
      .body(userA)
      .expect
      .when()
      .post(getHost() + CONTEXT_PATH + "/users");
  String location = 
      responseCreateUser.getHeader("Location");
  assertNotNull(location);
  Response responseGetUser = given()
      .expect().log().ifError()
      .statusCode(HttpStatus.SC_OK)
      .when()
      .get(getHost() + CONTEXT_PATH + location + 
      		JSON_SUFFIX);
    UserDTO userADTO = 
      deserialize(responseGetUser.getBody().asString());
    assertEquals(userA.getId(), userADTO.getId());
    assertEquals(userA.getLanguage().name(), 
    userADTO.getLanguage());
    assertEquals(HIDDEN_FIELD, userADTO.getEmail());
    assertEquals(HIDDEN_FIELD, userADTO.getPassword());
    assertNull(userA.getBalance());
  }
}
```

1.  因为它们需要更长的时间来执行，我们希望将 IT 测试的执行与主 Maven 生命周期解耦。我们已将这些 IT 测试关联到名为`integration`的 Maven 配置文件。

### 注意

Maven 配置文件提供了使用额外生命周期绑定来丰富 Maven 构建的可能性。例如，我们的集成配置文件是通过在通常的命令中传递此配置文件 ID 作为`Profile`参数来激活的：

`$ mvn clean install -P integration`

1.  对于我们的 API IT 测试，我们已将特定于配置文件的配置放在了`cloudstreetmarket-api pom.xml`文件中：

```java
<profiles>
  <profile>
  <id>integration</id>
  <build>
  <plugins>
    <plugin>
      <groupId>org.apache.maven.plugins</groupId>
      <artifactId>maven-failsafe-plugin</artifactId>
      <version>2.12.4</version>
      <configuration>
      <includes>
        <include>**/*IT.java</include>
      </includes>
      <excludes>
        <exclude>**/*Test.java</exclude>
      </excludes>
   </configuration>
   <executions>
      <execution>
        <id>integration-test</id>
        <goals>
          <goal>integration-test</goal>
        </goals>
      </execution>
      <execution>
        <id>verify</id>
        <goals><goal>verify</goal></goals>
      </execution>
   </executions>
 </plugin>
 <plugin>
  <groupId>org.codehaus.cargo</groupId>
  <artifactId>cargo-maven2-plugin</artifactId>
  <version>1.4.16</version>
      <configuration>
      <wait>false</wait>
      <container>
      <containerId>tomcat8x</containerId>
            <home>${CATALINA_HOME}</home>
      <logLevel>warn</logLevel>
      </container>
      <deployer/>
      <type>existing</type>
      <deployables>
      <deployable>
      <groupId>edu.zc.csm</groupId>
      <artifactId>cloudstreetmarket-api</artifactId>
      <type>war</type>
        <properties>
          <context>api</context>
        </properties>
      </deployable>
      </deployables>
    </configuration>
    <executions>
      <execution>
        <id>start-container</id>
        <phase>pre-integration-test</phase>
        <goals>
         <goal>start</goal>
         <goal>deploy</goal>
      </goals>
    </execution>
    <execution>
      <id>stop-container</id>
      <phase>post-integration-test</phase>
      <goals>
         <goal>undeploy</goal>
         <goal>stop</goal>
      </goals>
         </execution>
      </executions>
    </plugin>
  </plugins>
  </build>
  </profile>
</profiles>
```

1.  在尝试在您的计算机上运行它们之前，请检查您的**CATALINA_HOME**环境变量是否指向 Tomcat 目录。如果没有，您必须创建它。要设置的变量应该是以下内容（如果您已经按照第一章进行了设置，则应该是）：

+   `C:\tomcat8`：在 MS Windows 上

+   `/home/usr/{system.username}/tomcat8`：在 Linux 上

+   `/Users/{system.username}/tomcat8`：在 Mac OS X 上

1.  此外，请确保 Apache HTTP、Redis 和 MySQL 在您的本地计算机上运行正常（如果您跳过了上一章，请参阅上一章）。 

1.  准备就绪后：

+   在终端中执行以下 Maven 命令（如果 Maven 目录在您的路径中）：

```java

 mvn clean verify -P integration

```

+   或者在 Eclipse IDE 中从**Run** | **Run Configurations…**菜单中创建此自定义构建的快捷方式。要创建的构建配置如下：

![如何做…](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00924.jpeg)

1.  运行此命令（或快捷方式）应该：

1.  将**api.war**部署到本地 Tomcat 服务器

1.  启动本地 Tomcat

1.  执行与**/*IT.java 模式匹配的测试类

如果所有测试都通过，您应该看到`[INFO] BUILD SUCCESS`消息。

1.  在构建到 API 时，您应该看到以下一小段堆栈跟踪，表明我们的 IT 测试成功执行：![如何做…](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00925.jpeg)

## 它是如何工作的…

我们将在本节中解释为什么我们引入了 Maven failsafe 插件，Cargo 插件配置如何满足我们的需求，我们如何使用 REST-assured，以及这个 REST-assured 库有多有用。

### Maven Failsafe 与 Maven Surefire

我们使用 Maven failsafe 来运行集成测试，使用 Maven Surefire 来运行单元测试。这是使用这些插件的标准方式。以下表反映了这一点，插件的默认命名模式用于测试类：

|   | Maven Surefire | Maven Failsafe |
| --- | --- | --- |
| **默认测试包含模式** |

```java

**/Test*.java
**/*Test.java
**/*TestCase.java

```

|

```java

**/IT*.java
**/*IT.java
**/*ITCase.java

```

|

| **默认输出目录** |
| --- |

```java

${basedir}/target/surefire-reports

```

|

```java

${basedir}/target/failsafe-reports

```

|

| **绑定到构建阶段** |
| --- |

```java

test

```

|

```java

pre-integration-test
integration-test
post-integration-test
verify

```

|

对于 Maven Failsafe，您可以看到我们覆盖的模式包含/排除是可选的。关于绑定到 Maven 构建阶段，我们选择在`integration-test`和`verify`阶段触发我们的集成测试的执行。

### Code Cargo

Cargo 是一个轻量级库，为操作多个支持的容器（Servlet 和 JEE 容器）提供标准 API。覆盖的 API 操作示例包括部署构件、远程部署和容器启动/停止。当通过 Maven、Ant 或 Gradle 使用时，它主要用于提供对集成测试的支持，但也可以用于其他范围。

#### Cargo Maven 插件

我们通过其 Maven 插件`org.codehaus.cargo:cargo-maven2-plugin`使用 Cargo 自动准备一个集成环境，我们可以对其运行集成测试。在集成测试之后，我们期望此环境关闭。

##### 绑定到 Maven 阶段

以下执行已声明为`cargo-maven2-plugin`配置的一部分：

```java
<executions>
  <execution>
    <id>start-container</id>
    <phase>pre-integration-test</phase>
    <goals>
      <goal>start</goal>
    <goal>deploy</goal>
      </goals>
  </execution>
  <execution>
        <id>stop-container</id>
    <phase>post-integration-test</phase>
      <goals>
      <goal>undeploy</goal>
      <goal>stop</goal>
        </goals>
  </execution>
</executions>
```

让我们看看执行`mvn install`命令时会发生什么。

`install`是默认 Maven 生命周期的一个阶段。如第一章中所解释的*企业 Spring 应用程序的设置例程*，默认生命周期有 23 个构建阶段，从`validate`到`deploy`。`install`阶段是第 22 个阶段，因此会检查 22 个阶段，看是否有插件目标可以附加到它们上面。

在这里，`pre-integration-test`阶段（出现在默认生命周期的`validate`和`install`之间）将触发位于我们的 maven Cargo 插件的`start`和`deploy`目标下的进程。与此相同的逻辑是`post-integration-test`触发`undeploy`和`stop`目标。

在执行 IT 测试之前，我们启动和部署 Tomcat 服务器。这些 IT 测试在`integration-test`阶段使用 Maven failsafe 进行处理。最后，Tomcat 服务器被取消部署并停止。

IT 测试也可以在`verify`阶段执行（如果服务器在默认 Maven 生命周期之外启动）。

##### 使用现有的 Tomcat 实例

在 Cargo Maven 插件配置中，我们针对现有的 Tomcat 实例。我们的应用当前依赖于 MySQL、Redis、Apache HTTP 和自定义会话管理。我们决定 IT 测试执行将需要在适当的集成环境中运行。

如果没有这些依赖关系，我们将让 Cargo 下载 Tomcat 8 实例。

### Rest assured

REST-assured 是一个由 Jayway 公司支持的 Apache v2 许可的开源库。它是用 Groovy 编写的，允许通过其独特的功能 DSL 进行 HTTP 请求和验证 JSON 或 XML 响应，从而大大简化了 REST 服务的测试。

#### 静态导入

为了有效地使用 REST-assured，文档建议添加以下包的静态导入：

+   `com.jayway.restassured.RestAssured.*`

+   `com.jayway.restassured.matcher.RestAssuredMatchers.*`

+   `org.hamcrest.Matchers.*`

#### 一种给定、当、然后的方法

要了解 REST-assured DSL 的基础知识，让我们考虑我们的一个测试（在`UserControllerIT`中），它提供了 REST-assured 使用的简要概述：

```java
  @Test
  public void createUserBasicAuthAjax(){
    Response response = given()
    .header("X-Requested-With", "XMLHttpRequest")
    .contentType("application/json;charset=UTF-8")
    .accept("application/json\")
    .body(userA)
    .when()
    .post(getHost() + CONTEXT_PATH + "/users");
    assertNotNull(response.getHeader("Location"));
  }
```

语句的`given`部分是 HTTP 请求规范。使用 REST-assured，一些请求头，如`Content-Type`或`Accept`，可以以直观的方式使用`contentType(…)`和`accept(…)`来定义。其他**头部**可以通过通用的`.header(…)`来访问。请求参数和身份验证也可以以相同的方式定义。

对于`POST`和`PUT`请求，有必要向请求传递一个 body。这个`body`可以是普通的 JSON 或 XML，也可以直接是 Java 对象（就像我们在这里做的那样）。这个`body`作为 Java 对象，将根据规范中定义的`content-type`（JSON 或 XML）由库进行转换。

在 HTTP 请求规范之后，`when()`语句提供了有关实际 HTTP 方法和目的地的信息。

在这个阶段，返回的对象允许我们从`then()`块中定义期望，或者像我们在这里做的那样，从中检索`Response`对象，从中可以单独定义约束。在我们的测试用例中，预期`Response`的`Location`头部应该被填充。

## 还有更多…

更多信息可以在以下 Cargo 和 REST-assured 各自的文档中找到：

### 关于 Cargo

有关产品及其与第三方系统集成的更多信息，请参阅[`codehaus-cargo.github.io/cargo/Home.html`](https://codehaus-cargo.github.io/cargo/Home.html)。

### 更多 REST-assured 示例

有关更多示例，REST-assured 在线 Wiki 提供了大量信息：

[`github.com/jayway/rest-assured/wiki/Usage`](https://github.com/jayway/rest-assured/wiki/Usage)

# 将 Spring Bean 注入集成测试

这个示例是如何将 Spring 管理的 bean 注入到集成测试类中的一个示例。即使对于其首要目标是将后端作为黑匣子进行评估的 IT 测试，有时也需要从中间层访问技术对象。

## 准备工作

我们将看到如何重用 Spring 管理的`datasource`实例，将其注入到我们的测试类中。这个`datasource`将帮助我们构建一个`jdbcTemplate`的实例。从这个`jdbcTemplate`，我们将查询数据库并模拟/验证否则无法测试的过程。

## 如何做…

1.  我们在我们的`UserControllerIT`测试中`@Autowired`了一个`dataSource` SpringBean。这个 bean 在测试特定的 Spring 配置文件（`spring-context-api-test.xml`）`resources`目录（`cloudstreetmarket-api`）中定义：![如何做…](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00926.jpeg)

```java
<context:property-placeholderlocation="
  file:${user.home}/app/cloudstreetmarket.properties""/>
<bean id="dataSource" 		
  class="org.apache.commons.dbcp2.BasicDataSource" 	
  destroy-method="close"">
  <property name="driverClassName"">
     <value>com.mysql.jdbc.Driver</value>
  </property>
  <property name="url"">
    <value>${db.connection.url}</value>
  </property>
<property name="username"">
  <value>${db.user.name}</value>
</property>
<property name="password"">
  <value>${db.user.passsword}</value>
</property>
<property name="defaultReadOnly">
  <value>false</value>
</property>
</bean>
```

在`UserControllerIT`类中，从`@Autowired dataSource` bean 创建了一个`jdbcTemplate`实例：

```java
    @Autowired
    private JdbcTemplate jdbcTemplate;
    @Autowired
    public void setDataSource(DataSource dataSource) {
    	this.jdbcTemplate = new JdbcTemplate(dataSource);
    }
```

1.  我们使用`jdbcTemplate`直接在数据库中插入和删除`Social Connections`（参见第五章，“使用 Spring MVC 进行身份验证”）。这使我们能够绕过并模拟成功的用户 OAuth2 身份验证流程（通常通过 Web 浏览器进行）。

对于删除社交连接，我们创建了以下私有方法，根据需要由测试调用：

```java
    private void deleteConnection(String spi, String id) {
    	this.jdbcTemplate.update("delete from userconnection where providerUserId = ? and userId = "?", new Object[] {spi, id});
   }
```

1.  在`UserControllerIT`类的顶部，可以注意到以下两个注解：

+   `@RunWith(SpringJUnit4ClassRunner.class)`告诉 JUnit 使用 JUnit 的自定义扩展（`SpringJUnit4ClassRunner`）来运行，支持 Spring`TestContext`框架。

+   `@ContextConfiguration("classpath:spring-context-api-test.xml")`指定了加载和配置 Spring 应用程序上下文的位置和方式：

```java
    @RunWith(SpringJUnit4ClassRunner.class)
    @ContextConfiguration("classpath:spring-context-api-test.xml"")
    public class UserControllerIT extends AbstractCommonTestUser{
    private static User userA;
    private static User userB;
    ...
    }
```

## 它是如何工作的...

### SpringJUnit4ClassRunner

在设计上，`SpringJUnit4ClassRunner`是 JUnit 的`BlockJUnit4ClassRunner`的直接子类。`SpringJUnit4ClassRunner`在加载`TestContextManager`时初始化。`TestContextManager`管理`TestContext`的生命周期，并且还可以将测试事件反映给注册的`TestExecutionListeners`（来自`@BeforeClass`、`@AfterClass`、`@Before`和`@After`注解）。

通过加载 Spring 上下文，`SpringJUnit4ClassRunner` Spring 上下文，`SpringJUnit4ClassRunner`使得在测试类中可以使用 Spring 管理的 bean。`SpringJUnit4ClassRunner`还支持一组注解（来自 JUnit 或 Spring 测试），可以在测试类中使用。可以信任这些注解的使用，以便随后为上下文定义的对象提供适当的生命周期管理。

这些注解是`@Test`（带有其`expected`和`timeout`注解参数）、`@Timed`、`@Repeat`、`@Ignore`、`@ProfileValueSourceConfiguration`和`@IfProfileValue`。

### @ContextConfiguration 注解

这个类级别的注解是特定于 Spring 测试的。它定义了如何以及从哪里加载 Spring 上下文用于测试类。

我们在配方中的定义针对特定的 Spring XML 配置文件`@ContextConfiguration("classpath:spring-context-api-test.xml")`。

然而，自 Spring 3.1 以来，上下文可以以编程方式定义，`@ContextConfiguration`也可以以以下方式针对配置类：

`@ContextConfiguration(classes={AnnotationConfig.class,` `WebSocketConfig.class})`

如下面的片段所示，两种声明类型可以组合在同一个注解中：

`@ContextConfiguration(classes={AnnotationConfig.class,` `WebSocketConfig.class}, locations={`"`classpath:spring-context-api-test.xml`"`})`

## 还有更多...

我们将在本节中更多地了解为测试目的而使用的 Spring JdbcTemplate。

### JdbcTemplate

在*第一章，企业 Spring 应用程序的设置例程*中，我们介绍了使 Spring 框架成为今天的样子的不同模块。其中一组模块是**数据访问和集成**。这个组包含了 JDBC、ORM、OXM、JMS 和事务模块。

`JdbcTemplate`是 Spring JDBC 核心包的关键部分。它可靠地允许使用简单的实用方法执行数据库操作，并为大量的模板代码提供了抽象。再次，这个工具节省了我们的时间，并提供了设计高质量产品的模式。

### 模板逻辑的抽象

让我们以我们的测试类中删除连接的方法为例：

```java
jdbcTemplate.update("delete from userconnection where 
  providerUserId = ? and userId = "?", new Object[] {spi, id});
```

使用`jdbcTemplate`，删除数据库元素是一条指令。它在内部创建一个`PreparedStatement`，根据我们实际传递的值选择正确的类型，并为我们管理数据库连接，确保无论发生什么都关闭这个连接。

`jdbcTemplate.update`方法被设计用于发出单个 SQL 更新操作。它可以用于插入、更新，也可以删除。

就像在 Spring 中经常发生的那样，`jdbcTemplate`也会将产生的已检查异常（如果有的话）转换为未检查异常。在这里，潜在的`SQLExceptions`将被包装在`RuntimeException`中。

#### 自动生成 ID 的提取

`jdbcTemplate.update`方法还提供其他参数类型：

```java
jdbcTemplate.update(final PreparedStatementCreator psc, final
  KeyHolder generatedKeyHolder);
```

在插入的情况下，可以在需要时调用此方法来读取并可能重用生成的 ID（在查询执行之前是未知的）。

在我们的示例中，如果我们想要在插入新连接时重用生成的连接 ID，我们将这样做：

```java
KeyHolder keyHolder = new GeneratedKeyHolder();
jdbcTemplate.update(
  new PreparedStatementCreator() {
    public PreparedStatement createPreparedStatement(Connection 
    connection) throws SQLException {
    PreparedStatement ps = connection.prepareStatement("insert into userconnection (accessToken, ... , secret, userId ) values (?, ?, ... , ?, ?)", new String[] {"id""});
    ps.setString(1, generateGuid());
    ps.setDate(2, new Date(System.currentTimeMillis()));
    ...
    return ps;
    }
  }, keyHolder);
  Long Id = keyHolder.getKey().longValue();
```

但我们并没有明确要求这样的用例。

# 使用 Log4j2 的现代应用程序日志记录

在 Java 生态系统的 20 年演变之后，日志记录的方式已经看到了不同的策略、趋势和架构。如今，可以在使用的第三方依赖项中找到几种日志框架。我们必须支持它们所有来调试应用程序或跟踪运行时事件。

## 准备就绪

这个配方为`CloudStreet Market`应用程序提供了一个未来的`Log4j2`实现。它需要将几个 Maven 依赖项添加到我们的模块中。作为解决方案，它可能看起来相当复杂，但实际上需要支持的日志框架数量有限，`Log4j2`迁移背后的逻辑相当简单。

## 如何做...

1.  已将以下 Maven 依赖项添加到父模块（`cloudstreetmarket-parent`）的依赖项管理部分：

```java
    <!-- Logging dependencies -->
    <dependency>
      <groupId>org.apache.logging.log4j</groupId>
      <artifactId>log4j-api</artifactId>
      <version>2.4.1</version>
    </dependency>
    <dependency>
      <groupId>org.apache.logging.log4j</groupId>
      <artifactId>log4j-core</artifactId>
      <version>2.4.1</version>
    </dependency>
    <dependency>
      <groupId>org.apache.logging.log4j</groupId>
      <artifactId>log4j-slf4j-impl</artifactId>
      <version>2.4.1</version>
    </dependency>
    <dependency>
      <groupId>org.apache.logging.log4j</groupId>
      <artifactId>log4j-1.2-api</artifactId>
      <version>2.4.1</version>
    </dependency>
    <dependency>
      <groupId>org.apache.logging.log4j</groupId>
      <artifactId>log4j-jcl</artifactId>
      <version>2.4.1</version>
      </dependency>
    <dependency>
      <groupId>org.apache.logging.log4j</groupId>
      <artifactId>log4j-web</artifactId>
        <scope>runtime</scope>
      <version>2.4.1</version>
    </dependency>
    <dependency>
      <groupId>org.slf4j</groupId>
      artifactId>slf4j-api</artifactId>
      <version>${slf4j.version}</version>
    </dependency>
```

### 提示

最后一个依赖项管理，`org.slf4j`，允许我们确保`slf4j`的一个版本将在所有地方使用。

1.  然后在`api`，`ws`和`core`模块中添加了以下依赖项：`log4j-api`，`log4j-core`，`log4j-slf4j-impl`，`log4j-1.2-api`和`log4j-jcl`。

1.  在 web 模块（`api`，`ws`和`webapp`）中，已添加了`log4j-web`。

1.  请注意，`slf4j-api`仅用于依赖项管理。

1.  使用**额外的 JVM 参数**启动 Tomcat 服务器：

```java
-Dlog4j.configurationFile=<home-directory>\app\log4j2.xml.
```

### 提示

将`<home-directory>`替换为您在计算机上实际使用的路径。

1.  用户主目录中的应用程序目录现在包含`log4j2`配置文件：

```java
<?xml version="1.0" encoding="UTF-8"?>
<Configuration status="OFF" monitorInterval="30">
<Appenders
  <Console name="Console" target="SYSTEM_OUT">
    <PatternLayout pattern"="%d{HH:mm:ss.SSS} %-5level %logger{36} - %msg%n""/>
  </Console>
  <RollingFile name="FileAppender" fileName="${sys:user.home}/app/logs/cloudstreetmarket.log"
        filePattern="${sys:user.home}/app/logs/${date:yyyy-MM}/cloudstreetmarket-%d{MM-dd-yyyy}-%i.log.gz">
      <PatternLayout>
        <Pattern>%d %p %C{1} %m%n</Pattern>
      </PatternLayout>
      <Policies>
        <TimeBasedTriggeringPolicy />
        <SizeBasedTriggeringPolicy size="250 MB"/>
      </Policies>
  </RollingFile>
</Appenders>
<Loggers>
  <Logger name="edu.zipcloud" level="INFO"/>
  <Logger name="org.apache.catalina" level="ERROR"/>
  <Logger name="org.springframework.amqp" level="ERROR"/>
  <Logger name="org.springframework.security" level="ERROR"/>

  <Root level="WARN">
    <AppenderRef ref="Console"/>
  <AppenderRef ref="FileAppender"/>
  </Root>
</Loggers>
</Configuration>
```

1.  作为备选方案，每个单个模块的类路径（`src/main/resources`）中也存在一个`log4j2.xml`文件。

1.  已在不同的类中放置了一些日志说明，以跟踪用户的旅程。

在`SignInAdapterImpl`中记录说明：

```java
    import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@Transactional
public class SignInAdapterImpl implements SignInAdapter{
  private static final Logger logger = 
    LogManager.getLogger(SignInAdapterImpl.class);
  ...
  public String signIn(String userId, Connection<?>connection, NativeWebRequest request) {
  ...
  communityService.signInUser(user);
  logger.info("User {} logs-in with OAUth2 account", user.getId());
  return view;
  }
}
```

在`UsersController`中记录说明：

```java
@RestController
@RequestMapping(value=USERS_PATH, produces={"application/xml", "application/json"})
public class UsersController extends CloudstreetApiWCI{
  private static final Logger logger = LogManager.getLogger(UsersController.class);
  ...
  @RequestMapping(method=POST)
  @ResponseStatus(HttpStatus.CREATED)
  public void create(@Valid @RequestBody User user, 
    @RequestHeader(value="Spi", required=false) String guid, 
  @RequestHeader(value="OAuthProvider", required=false) String provider, HttpServletResponse response) throws IllegalAccessException{
      if(isNotBlank(guid)){
      ...
      communityService.save(user);
      logger.info("User {} registers an OAuth2 account: "{}", user.getId(), guid);
      }
      else{
    user = communityService.createUser(user, ROLE_BASIC);
    ...
    logger.info("User registers a BASIC account"", user.getId());
      }
    ...
  }
  ...
}
```

1.  启动本地 Tomcat 服务器，并简要浏览应用程序。与以下示例一样，您应该能够在聚合文件`<home-directory>/apps/logs/cloudstreetmarket.log`中观察到客户活动的跟踪：![如何做...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00927.jpeg)

### 提示

通过我们制作的`log4j2.xml`配置，`cloudstreetmarket.log`文件将在达到 250MB 时自动被压缩并分类到目录中。

## 工作原理...

我们主要将在本节中审查 Log4j2 如何设置与其他日志框架一起工作。配置的其他部分（此处未涵盖）被认为更直观。

### Apache Log4j2 和其他日志框架

Log4j1+作为一个项目正在消亡，因为它不再与 Java 5+兼容。

Log4j 2 是作为 log4j 代码库的一个分支构建的。从这个角度来看，它与 Logback 项目竞争。Logback 最初是 Log4j 的合法继续。

Log4j 2 实际上实现了 Logback 的许多改进，但也修复了 Logback 架构固有的问题。

Logback 提供了很好的性能改进，特别是在多线程方面。相比之下，Log4j 2 提供了类似的性能。

#### SLF4j 的情况

SLF4j 本身不是一个日志框架；它是一个抽象层，允许用户在部署时插入任何日志系统。

SLF4j 在类路径中需要一个 SLF4j 绑定。绑定的示例如下：

+   `slf4j-log4j12-xxx.jar`：（log4j 版本 1.2），

+   `slf4j-jdk14-xxx.jar`：（来自 jdk 1.4 的`java.util.logging`），

+   `slf4j-jcl-xxx.jar`：（Jakarta Commons Logging）

+   `logback-classic-xxx.jar`。

它通常还需要目标日志框架的核心库。

### 迁移到 log4j 2

Log4j2 不提供对 Log4j1+的向后兼容性。 这可能听起来像一个问题，因为应用程序（如`CloudStreetMarket`）经常使用嵌入其自己的日志框架的第三方库。 例如，Spring 核心具有对 Jakarta Commons Logging 的传递依赖。

为了解决这种情况，Log4j 2 提供了适配器，确保内部日志不会丢失，并将桥接到加入 log4j 2 日志流的日志。 几乎所有可能产生日志的系统都有适配器。

#### Log4j 2 API 和核心

Log4j 2 带有 API 和实现。 两者都是必需的，并且具有以下依赖项：

```java
<dependency>
  <groupId>org.apache.logging.log4j</groupId>
  <artifactId>log4j-api</artifactId>
  <version>2.4.1</version>
</dependency>
<dependency>
  <groupId>org.apache.logging.log4j</groupId>
  <artifactId>log4j-core</artifactId>
  <version>2.4.1</version>
</dependency>
```

#### Log4j 2 适配器

如前所介绍，一组**适配器**和**桥接**可用于为我们的应用程序提供向后兼容性。

##### Log4j 1.x API 桥接

当在特定模块中注意到对 Log4j 1+的传递依赖时，应添加以下桥接：

```java
<dependency>
  <groupId>org.apache.logging.log4j</groupId>
  <artifactId>log4j-1.2-api</artifactId>
  <version>2.4.1</version>
</dependency>
```

##### Apache Commons Logging 桥接

当在特定模块中注意到对 Apache（Jakarta）Commons Logging 的传递依赖时，应添加以下桥接：

```java
<dependency>
  <groupId>org.apache.logging.log4j</groupId>
  <artifactId>log4j-jcl</artifactId>
  <version>2.4.1</version>
</dependency>
```

##### SLF4J 桥接

相同的逻辑适用于覆盖 slf4j 的使用；应添加以下桥接：

```java
<dependency>
  <groupId>org.apache.logging.log4j</groupId>
  <artifactId>log4j-slf4j-impl</artifactId>
  <version>2.4.1</version>
</dependency>
```

##### Java Util Logging 适配器

我们的应用程序中没有注意到对`java.util.logging`的传递依赖，但如果有的话，我们将使用以下桥接：

```java
<dependency>
  <groupId>org.apache.logging.log4j</groupId>
  <artifactId>log4j-jul</artifactId>
  <version>2.4.1</version>
</dependency>
```

##### Web Servlet 支持

Apache Tomcat 容器有自己的一组库，也会产生日志。 在 Web 模块上添加以下依赖项是确保容器日志路由到主 Log4j2 管道的一种方法。

```java
<dependency>
  <groupId>org.apache.logging.log4j</groupId>
  <artifactId>log4j-web</artifactId>
  <version>2.4.1</version>
  <scope>runtime</scope>
</dependency>
```

### 配置文件

此食谱的第六步详细介绍了我们的 log4j2 配置。 它由不同的可配置的`Appenders`（基本上是输出通道）组成。 我们正在使用控制台和基于文件的`Appender`，但是 Log4j 2 具有关于`Appenders`的基于插件的架构，如果需要，可以使用外部输出通道（SMTP，打印机，数据库等）。

## 还有更多...

作为外部信息源，我们指出了有趣的 Log4j2 自动配置，该配置由级联查找配置文件、官方文档和用于直接记录到 Redis 的`Appender`组成。

### 自动配置

Log4j2 实现级联查找以定位 log4j2 配置文件。 从查找提供的`log4j.configurationFile`系统属性开始，到类路径中的`log4j2-test.xml`和`log4j2.xml`文件，官方文档详细介绍了所有遵循的级联步骤。 此文档可在以下地址找到：

[`logging.apache.org/log4j/2.x/manual/configuration.html`](https://logging.apache.org/log4j/2.x/manual/configuration.html)

### 官方文档

官方文档非常完善，可在以下地址找到：

[`logging.apache.org/log4j/2.x.`](https://logging.apache.org/log4j/2.x.)

### 有趣的 Redis Appender 实现

以下地址介绍了一个 Apache 许可的项目，该项目提供了一个 Log4j2 **Appender**，可以直接记录到 Redis 中：

[`github.com/pavlobaron/log4j2redis`](https://github.com/pavlobaron/log4j2redis)


