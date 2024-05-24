# RESTful Java 模式和最佳实践（二）

> 原文：[`zh.annas-archive.org/md5/829D0A6DE6895E44AC3D7583B5540457`](https://zh.annas-archive.org/md5/829D0A6DE6895E44AC3D7583B5540457)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：高级设计原则

本章涵盖了每个开发人员在设计 RESTful 服务时必须了解的高级设计原则。它还提供了务实的见解，为开发人员提供足够的信息来构建具有 REST API 的复杂应用程序。

本章将涵盖以下主题：

+   速率限制模式

+   响应分页

+   国际化和本地化

+   REST 的可插拔性和可扩展性

+   REST API 开发人员的其他主题

本章包含了不同的代码片段，但展示这些片段的完整示例作为书籍源代码下载包的一部分包含在内。

与之前的章节一样，我们将尝试覆盖读者所需的最低限度的细节，以便为其提供对本质上复杂的主题的扎实的一般理解，同时还提供足够的技术细节，以便读者能够轻松地立即开始工作。

# 速率限制模式

速率限制涉及限制客户端可以发出的请求数量。客户端可以根据其用于请求的访问令牌进行识别，如第三章中所述，*安全性和可追溯性*。另一种客户端可以被识别的方式是客户端的 IP 地址。

为了防止滥用服务器，API 必须实施节流或速率限制技术。基于客户端，速率限制应用程序可以决定是否允许请求通过。

服务器可以决定每个客户端的自然速率限制应该是多少，例如，每小时 500 个请求。客户端通过 API 调用向服务器发出请求。服务器检查请求计数是否在限制范围内。如果请求计数在限制范围内，则请求通过并且计数增加给客户端。如果客户端请求计数超过限制，服务器可以抛出 429 错误。

服务器可以选择包含一个`Retry-After`头部，指示客户端在可以发送下一个请求之前应等待多长时间。

应用程序的每个请求可以受到两种不同的节流的影响：具有访问令牌和没有访问令牌的请求。具有访问令牌的应用程序的请求配额可以与没有访问令牌的应用程序的请求配额不同。

以下是`HTTP 429 Too Many Requests`错误代码的详细信息。

### 注意

**429 Too Many Requests (RFC 6585)**

用户在一定时间内发送了太多请求。这是为了与速率限制方案一起使用。

`429 Too Many Requests`错误的响应可能包括一个`Retry-After`头部，指示客户端需要等待多长时间才能发出新的请求。以下是一个示例代码片段：

```java
HTTP/1.1 429 Too Many Requests
Content-Type: text/html
Retry-After: 3600
 <html>
       <head>
   <title>Too Many Requests</title>
   </head>
 <body>
 <h1>Too many Requests</h1>
       <p>100 requests per hour to this Web site per logged in use allowed.</p>
   </body>
   </html>
```

前面的 HTTP 响应示例设置了`Retry-After`头部为 3600 秒，以指示客户端可以稍后重试。此外，服务器可以发送一个`X-RateLimit-Remaining`头部，指示此客户端还有多少待处理的请求。

现在我们对速率限制有了一些想法，以及速率限制错误和`Retry-After`和`X-RateLimit-Remaining`头部的工作原理，让我们通过 JAX-RS 编写代码。

*项目的布局*部分中的以下代码显示了如何在 JAX-RS 中实现一个简单的速率限制过滤器。

## 项目的布局

项目的目录布局遵循标准的 Maven 结构，简要解释如下表。此示例生成一个 WAR 文件，可以部署在任何符合 Java EE 7 标准的应用服务器上，如 GlassFish 4.0。

此示例演示了一个简单的咖啡店服务，客户可以查询他们下的特定订单。

| 源代码 | 描述 |
| --- | --- |
| `src/main/java` | 此目录包含咖啡店应用程序所需的所有源代码 |

`CoffeeResource`类是一个简单的 JAX-RS 资源，如下所示：

```java
@Path("v1/coffees")
public class CoffeesResource {
    @GET
    @Path("{order}")
    @Produces(MediaType.APPLICATION_XML)
    @NotNull(message="Coffee does not exist for the order id requested")
    public Coffee getCoffee(@PathParam("order") int order) {
        return CoffeeService.getCoffee(order);
    }
}
```

项目中有一个`CoffeeResource`类，用于获取有关咖啡订单的详细信息。`getCoffee`方法返回一个包含订单详细信息的`Coffee`对象。

为了强制执行速率限制，我们将添加一个`RateLimiter`类，它是一个简单的 servlet 过滤器，如下图所示。

`RateLimiter`类将检查客户端的 IP 地址，并检查客户端发出的请求是否超过限制。以下图表详细描述了示例中涵盖的速率限制功能：

![项目布局](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/rst-java-ptn-best-prac/img/7963OS_05_01.jpg)

前面的图表显示了客户端向[`api.com/foo`](http://api.com/foo)发出`GET`请求。**速率限制过滤器**根据 IP 地址检查客户端的访问计数。由于客户端未超过速率限制，请求被转发到服务器。服务器可以返回 JSON、XML 或文本响应。

以下图表显示客户端向[`api.com/foo`](http://api.com/foo)发出`GET`请求。**速率限制过滤器**根据 IP 地址检查客户端的访问计数。由于客户端超过了速率限制，请求未转发到服务器，并且速率限制器在 HTTP 响应中返回`429 Too Many Requests`错误代码。

![项目布局](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/rst-java-ptn-best-prac/img/7963OS_05_02.jpg)

## 对速率限制示例的详细查看

要使用 JAX-RS 实现速率限制器，我们需要实现一个`Filter`类。如下代码片段所示：

```java
@WebFilter(filterName = "RateLimiter",
        urlPatterns = {"/*"}
        )
public class RateLimiter implements Filter {
    private static final int REQ_LIMIT = 3;
    private static final int TIME_LIMIT = 600000;
    private static AccessCounter accessCounter = AccessCounter.getInstance();
}
```

前面的代码片段显示了`javax.servlet.annotation`包的`WebFilter`接口的实现。`@WebFilter`注解表示这个类是应用程序的过滤器。

`@WebFilter`注解必须在注解中具有至少一个`urlPatterns`或`value`属性。

`REQ_LIMIT`常量代表在一段时间内可以发出的请求数量。`TIME_LIMIT`常量代表速率限制的时间持续时间，之后客户端可以接受新请求。

为简单起见，示例中的限制值较小。在实际场景中，限制可以是，例如，每分钟 60 个请求或每天 1,000 个请求。如果请求计数达到限制，`Retry-After`头将指示客户端在服务器处理下一个请求之前必须等待的时间。

为了跟踪与客户端关联的请求计数，我们创建了一个名为`AccessCounter`的类。以下是`AccessCounter`类的代码。`AccessCounter`类是一个带有`@Singleton`注解的`Singleton`类。它存储了一个包含 IP 地址作为键和与客户端相关的数据（称为`AccessData`）作为值的`ConcurrentHashMap`类。

```java
@Singleton
public class AccessCounter {

    private static AccessCounter accessCounter;

    private static ConcurrentHashMap<String,AccessData> accessDetails = new ConcurrentHashMap<String, AccessData>();
}
```

`AccessData`类负责存储客户端的详细信息，例如请求的数量以及上次请求是何时。它是一个简单的**普通旧 Java 对象**（**POJO**），如下代码片段所示：

```java
public class AccessData {
    private long lastUpdated;
    private AtomicInteger count;

    public long getLastUpdated() {
        return lastUpdated;
    }

    public void setLastUpdated(long lastUpdated) {
        this.lastUpdated = lastUpdated;
    }

    public AtomicInteger getCount() {
        return count;
    }

    public void setCount(AtomicInteger count) {
        this.count = count;
    }

 …
```

如前面的代码片段所示，`AccessData`类有一个名为`count`的字段和一个名为`lastUpdated`的字段。每当新请求到达时，计数会递增，并且`lastUpdated`字段设置为当前时间。

`RateLimiter`类的`doFilter()`方法在以下代码片段中使用：

```java
@Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse,
                         FilterChain filterChain) throws IOException, ServletException {

        HttpServletRequest httpServletRequest = (HttpServletRequest) servletRequest;
        HttpServletResponse httpServletResponse = (HttpServletResponse) servletResponse;

        String ipAddress = getIpAddress(httpServletRequest);
        if (accessCounter.contains(ipAddress)) {
            if (!requestLimitExceeded(ipAddress)) {
                accessCounter.increment(ipAddress);
                accessCounter.getAccessDetails(ipAddress).setLastUpdated(System.currentTimeMillis());

            } else {

                httpServletResponse.addIntHeader("Retry-After",TIME_LIMIT);
                httpServletResponse.sendError(429);

            }
        } else {
            accessCounter.add(ipAddress);

        }
        filterChain.doFilter(servletRequest, servletResponse)

    }
```

前面的代码显示了`javax.servlet.Filter`类的`doFilter()`方法，在`RateLimiter`实现中被重写。在这个方法中，首先确定客户端的 IP 地址。

如果`accessCounter`类包含 IP 地址，则在`requestLimitExceeded()`方法中将检查请求限制是否已超过。

如果速率限制已超过，则`Retry-After`标头将与`429 Too Many Requests`错误一起发送到`httpServletResponse`。如果同一客户端发出了新请求，并且大于`TIME_LIMIT`值，则计数器将重置为 0，并且可以再次处理来自客户端的请求。

以下是可以在响应中发送回客户端的速率限制标头：

+   `X-RateLimit-Limit`：客户端在特定时间段内可以发出的最大请求数

+   `X-RateLimit-Remaining`：当前速率限制窗口中剩余的请求数

本书附带了一个详细的示例。在将示例部署到应用程序服务器后，客户端可以进行多个请求以获取咖啡订单的详细信息。

为了简单起见，我们已经将速率限制设置为 3，时间限制设置为 10 分钟。以下是一个示例`curl`请求：

```java
curl -i http://localhost:8080/ratelimiting/v1/coffees/1
HTTP/1.1 200 OK
X-Powered-By: Servlet/3.1 JSP/2.3 (GlassFish Server Open Source Edition  4.0  Java/Oracle Corporation/1.7)
Server: GlassFish Server Open Source Edition  4.0 
Content-Type: application/json
Date: Mon, 23 Jun 2014 23:27:34 GMT
Content-Length: 57

{
 "name":"Mocha",
 "order":1,
 "size":"Small",
 "type":"Brewed"
}

```

一旦超过速率限制，您将看到`429`错误：

```java
curl -i http://localhost:8080/ratelimiting/v1/coffees/1
HTTP/1.1 429 CUSTOM
X-Powered-By: Servlet/3.1 JSP/2.3 (GlassFish Server Open Source Edition  4.0  Java/Oracle Corporation/1.7)
Server: GlassFish Server Open Source Edition  4.0 
Retry-After: 600000
Content-Language: 
Content-Type: text/html
Date: Mon, 23 Jun 2014 23:29:04 GMT
Content-Length: 1098

```

### 提示

此示例显示了如何构建自定义过滤器以实现速率限制。另一个选择是使用名为**Repose**的开源项目，它是一个可扩展且广泛的速率限制实现。 Repose 是一个开源的 HTTP 代理服务，提供速率限制、客户端认证、版本控制等功能。有关更多详细信息，请查看[`openrepose.org/`](http://openrepose.org/)。

在下一节中，我们将讨论在使用 REST API 时必须遵循的最佳实践。

## 避免达到速率限制的最佳实践

以下是在使用 REST API 时避免达到速率限制的最佳实践。

### 缓存

在服务器端缓存 API 响应可以帮助避免达到速率限制。设置合理的到期时间间隔可确保数据库不会因查询而受到影响，并且如果资源未更改，则可以从缓存发送响应。例如，从 Twitter 获取的推文的应用程序可以缓存来自 Twitter API 的响应或使用 Twitter 流 API（在下一节中介绍）。理想情况下，API 消费者不应该每分钟进行相同的请求。这通常是一种带宽浪费，因为在大多数情况下将返回完全相同的结果。

### 不要在循环中发出调用

不在循环中发出调用是一个好习惯。服务器 API 应设计得尽可能详细，并通过在响应中发送尽可能多的细节来帮助客户端。这确保了消费者可以在一个 API 操作中获取一组对象，而不是在循环中获取单个对象。

### 记录请求

在客户端使用日志记录以查看客户端发出了多少请求是一个好习惯。观察日志将帮助客户端分析哪些是不冗余的查询，这些查询会增加速率限制并且可以被消除。

### 避免轮询

此外，消费者不应该轮询更改。客户端可以使用 WebHooks（[`en.wikipedia.org/wiki/Webhook`](http://en.wikipedia.org/wiki/Webhook)）或推送通知（[`en.wikipedia.org/wiki/Push_technology`](http://en.wikipedia.org/wiki/Push_technology)）来接收通知，而不是轮询以查看内容是否已更改。有关 WebHooks 的更多详细信息将在第六章中给出，*新兴标准和 REST 的未来*。

### 支持流式 API

API 开发人员可以支持流式 API。这可以帮助客户端避免达到速率限制。Twitter 提供的一组流式 API 为开发人员提供了低延迟访问 Twitter 全球推文数据流的机会。流式客户端不需要承担与轮询 REST 端点相关的开销，并且将收到指示已发生推文和其他事件的消息。

一旦应用程序建立到流式端点的连接，它们将收到推文的订阅，而不必担心轮询或 REST API 速率限制。

### 注意

**Twitter REST API 速率限制案例研究**

Twitter 每小时对未经身份验证的客户端的请求限制为 150 次。

基于 OAuth 的调用允许每小时基于请求中的访问令牌进行 350 次请求。

超出搜索 API 的速率限制的应用程序将收到 HTTP 420 响应代码。最佳做法是注意此错误条件，并遵守返回的 Retry-After 头。Retry-After 头的值是客户端应该在再次请求数据之前等待的秒数。如果客户端发送的请求超过每小时允许的数量，客户端将收到 420 Enhance Your Calm 错误。

### 提示

**420 Enhance Your Calm (Twitter)**

这不是 HTTP 标准的一部分，但在 Twitter 搜索和趋势 API 被限制时返回。应用程序最好实现`429 Too Many Requests`响应代码。

# 响应分页

REST API 被从 Web 到移动客户端的其他系统使用，因此，返回多个项目的响应应该分页，每页包含一定数量的项目。这就是所谓的响应分页。除了响应之外，最好还添加一些关于对象总数、页面总数和指向下一组结果的链接的附加元数据。消费者可以指定页面索引来查询结果以及每页的结果数。

在客户端未指定每页结果数的情况下，实施和记录每页结果数的默认设置是一种推荐做法。例如，GitHub 的 REST API 将默认页面大小设置为 30 条记录，最多为 100 条，并对客户端查询 API 的次数设置了速率限制。如果 API 有默认页面大小，那么查询字符串可以只指定页面索引。

以下部分涵盖了可以使用的不同类型的分页技术。API 开发人员可以根据其用例选择实现一个或多个这些技术。

## 分页类型

以下是可以使用的不同分页技术：

+   基于偏移量的分页

+   基于时间的分页

+   基于游标的分页

### 基于偏移量的分页

基于偏移量的分页是客户端希望按页码和每页结果数指定结果的情况。例如，如果客户端想要查询所有已借阅的书籍的详细信息，或者已订购的咖啡，他们可以发送以下查询请求：

```java
GET v1/coffees/orders?page=1&limit=50
```

以下表格详细说明了基于偏移量的分页将包括哪些查询参数：

| 查询参数 | 描述 |
| --- | --- |
| `page` | 这指定要返回的页面 |
| `limit` | 这指定了响应中可以包含的每页最大结果数 |

### 基于时间的分页

当客户端想要查询特定时间范围内的一组结果时，将使用基于时间的分页技术。

例如，要获取在特定时间范围内订购的咖啡列表，客户端可以发送以下查询：

```java
GET v1/coffees/orders?since=140358321&until=143087472
```

以下表格详细说明了基于时间的分页将包括哪些查询参数：

| 查询参数 | 描述 |
| --- | --- |
| `until:` | 这是指向时间范围结束的 Unix 时间戳 |
| `since` | 这是指向时间范围开始的 Unix 时间戳 |
| `limit` | 这指定了响应中可以包含的每页最大结果数 |

### 基于游标的分页

基于游标的分页是一种技术，其中结果通过游标分隔成页面，并且可以使用响应中提供的下一个和上一个游标向前和向后导航结果。

基于游标的分页 API 避免在分页请求之间添加额外资源的情况下返回重复记录。这是因为游标参数是一个指针，指示从哪里恢复结果，用于后续调用。

#### Twitter 和基于游标的分页

以下是 Twitter 如何使用基于游标的分页的示例。获取拥有大量关注者的用户的 ID 的查询可以进行分页，并以以下格式返回：

```java
{
    "ids": [
        385752029, 
        602890434, 
        ...
        333181469, 
        333165023
    ],
    "next_cursor": 1374004777531007833, 
    "next_cursor_str": "1374004777531007833", 
    "previous_cursor": 0, 
    "previous_cursor_str": "0"
}
```

`next_cursor` 值可以传递给下一个查询，以获取下一组结果：

```java
GET https://api.twitter.com/1.1/followers/ids.json?screen_name=someone &cursor=1374004777531007833
```

使用 `next_cursor` 和 `previous_cursor` 值，可以轻松在结果集之间导航。

现在我们已经介绍了不同的分页技术，让我们详细介绍一个示例。以下示例显示了如何使用 JAX-RS 实现简单的基于偏移量的分页技术。

## 项目的布局

项目的目录布局遵循标准的 Maven 结构，以下表格简要解释了这一点。

所使用的示例是咖啡店服务的示例，可以查询到目前为止所有下的订单。

| 源代码 | 描述 |
| --- | --- |
| `src/main/java` | 此目录包含咖啡店应用程序所需的所有源代码 |

这是 `CoffeeResource` 类：

```java
@Path("v1/coffees")
public class CoffeesResource {
    @GET
    @Path("orders")
    @Produces(MediaType.APPLICATION_JSON)
    public List<Coffee> getCoffeeList( 
@QueryParam("page")  @DefaultValue("1") int page,
                                       @QueryParam("limit") @DefaultValue("10") int limit ) {
        return CoffeeService.getCoffeeList( page, limit);

    }
}
```

`getCoffeeList()` 方法接受两个 `QueryParam` 值：`page` 和 `limit`。`page QueryParam` 值对应于页面索引，`limit` 对应于每页的结果数。`@DefaultValue` 注释指定了如果查询参数不存在可以使用的默认值。

以下是运行示例时的输出。`metadata` 元素包含 `totalCount` 值的详细信息，即记录的总数。此外，还有 `JSONArray` 的 `links` 属性，其中包含诸如 `self`（当前页面）和 `next`（获取更多结果的下一个链接）等详细信息。

```java
{
    "metadata": {
        "resultsPerPage": 10,
        "totalCount": 100,
        "links": [
            {
                "self": "/orders?page=1&limit=10"
            },
            {
                "next": "/orders?page=2&limit=10"
            }
        ]
    },
    "coffees": [
        {
            "Id": 10,
            "Name": "Expresso",
            "Price": 2.77,
            "Type": "Hot",
            "Size": "Large"
        },
        {
            "Id": 11,
            "Name": "Cappuchino",
            "Price": 0.14,
            "Type": "Brewed",
            "Size": "Large"
        },
…..
       ……
    ]
}
```

示例与本书可下载的源代码包捆绑在一起。

### 提示

在 REST API 中，为分页包含每页结果数的默认值始终是一个好习惯。此外，建议 API 开发人员在响应中添加元数据，以便 API 的消费者可以轻松获取附加信息，以获取下一组结果。

# 国际化和本地化

通常，服务需要在全球环境中运行，并且响应需要根据国家和语言环境进行定制。本地化参数可以在以下字段之一中指定：

+   HTTP 头

+   查询参数

+   REST 响应的内容

语言协商类似于内容协商；HTTP 头 `Accept-Language` 可以根据 ISO-3166 国家代码的任何两字母首字母取不同的语言代码（[`www.iso.org/iso/country_codes.htm)`](http://www.iso.org/iso/country_codes.htm)）。`Content-Language` 头类似于 `Content-Type` 头，可以指定响应的语言。

例如，以下是在客户端发送的请求的响应中发送的 `Content-Language` 头：

```java
HTTP/1.1 200 OK
X-Powered-By: Servlet/3.1 JSP/2.3 (GlassFish Server Open Source Edition  4.0  Java/Oracle Corporation/1.7)
Server: GlassFish Server Open Source Edition  4.0 
Content-Language: en
Content-Type: text/html
Date: Mon, 23 Jun 2014 23:29:04 GMT
Content-Length: 1098
```

前面的响应将 `Content-Language` 设置为 `en` 作为响应的一部分。

JAX-RS 支持使用 `javax.ws.rs.core.Variant` 类和 `Request` 对象进行运行时内容协商。`Variant` 类可以包含媒体类型、语言和编码。`Variant.VariantListBuilder` 类用于构建表示变体的列表。

以下代码片段显示了如何创建资源表示变体的列表：

```java
List<Variant> variantList = 
    Variant.
      .languages("en", "fr").build();
```

前面的代码片段调用了 `VariantListBuilder` 类的 `build` 方法，语言为 `"en"` 和 `"fr"`。

查询参数可以包括特定于语言环境的信息，以便服务器可以以该语言返回信息。

以下是一个示例：

```java
GET v1/books?locale=fr
```

此查询显示了一个示例，其中将在查询参数中包含区域设置以获取图书的详细信息。此外，REST 响应的内容可以包含特定于国家/地区的细节，如货币代码，以及基于请求中发送的 HTTP 标头或查询参数的其他细节。

# 其他主题

以下部分涵盖了一些杂项主题的细节，如 HATEOAS 和 REST 中的可扩展性。

## HATEOAS

**超媒体作为应用状态的引擎**（**HATEOAS**）是 REST 应用程序架构的一个约束。

超媒体驱动的 API 通过在服务器发送的响应中提供超媒体链接，提供有关可用 API 和消费者可以采取的相应操作的详细信息。

例如，包含名称和 ISBN 等数据的 REST 资源的图书表示如下所示：

```java
{ 
   "Name":" Developing RESTful Services with JAX-RS 2.0,
            WebSockets, and JSON",
   "ISBN": "1782178120"
}
```

HATEOAS 实现将返回以下内容：

```java
{
    "Name":" Developing RESTful Services with JAX-RS 2.0, 
             WebSockets, and JSON",
    "ISBN": "1782178120"
    "links": [
       {
        "rel": "self",
        "href": "http://packt.com/books/123456789"
       }
    ]
}
```

在前面的示例中，`links`元素具有`rel`和`href` JSON 对象。

在这个例子中，`rel`属性是一个自引用的超链接。更复杂的系统可能包括其他关系。例如，图书订单可能具有`"rel":"customer"`关系，将图书订单链接到其客户。`href`是一个完整的 URL，唯一定义资源。

HATEOAS 的优势在于它帮助客户端开发人员探索协议。链接为客户端开发人员提供了关于可能的下一步操作的提示。虽然没有超媒体控件的标准，但建议遵循 ATOM RFC（4287）。

### 注意

根据 Richardson 成熟度模型，HATEOAS 被认为是 REST 的最终级别。这意味着每个链接都被假定实现标准的 REST 动词`GET`、`POST`、`PUT`和`DELETE`。使用`links`元素添加详细信息，如前面代码片段所示，可以为客户端提供导航服务和采取下一步操作所需的信息。

## PayPal REST API 和 HATEOAS

PayPal REST API 提供 HATEOAS 支持，因此每个响应都包含一组链接，可以帮助消费者决定下一步要采取的操作。

例如，PayPal REST API 的示例响应包括以下代码中显示的 JSON 对象：

```java
{
    "href": "https://www.sandbox.paypal.com/webscr?cmd=_express-checkout&token=EC-60U79048BN7719609",
    "rel": "approval_url",
    "method": "REDIRECT"
  },
  {
    "href": "https://api.sandbox.paypal.com/v1/payments/payment/PAY-6RV70583SB702805EKEYSZ6Y/execute",
    "rel": "execute",
    "method": "POST"
  }
```

属性的简要描述如下。

+   `href`：这包含可用于未来 REST API 调用的 URL 的信息

+   `rel`：此链接显示它与先前的 REST API 调用相关

+   `method`：显示用于 REST API 调用的方法

### 注意

有关更多详细信息，请查看[`developer.paypal.com/docs/integration/direct/paypal-rest-payment-hateoas-links/`](https://developer.paypal.com/docs/integration/direct/paypal-rest-payment-hateoas-links/)。

## REST 和可扩展性

基于设计风格的约束的 RESTful 应用程序在时间上更具可扩展性和可维护性。基于设计风格的 RESTful 应用程序更易于理解和使用，主要是因为它们的简单性。它们也更可预测，因为一切都是关于资源。此外，与需要解析复杂 WSDL 文档才能开始理解发生了什么的 XML-RPC 应用程序相比，RESTful 应用程序更易于使用。

## REST API 的其他主题

以下部分列出了对 REST 开发人员可能有用的其他主题。我们已经在早期章节中涵盖了从设计 RESTful 服务、错误处理、验证、身份验证和缓存到速率限制的主题。本节重点介绍了其他实用工具，以赋予 REST API 开发人员更好的测试和文档编制能力。

## 测试 RESTful 服务

拥有一组自动化测试总是有效的，可以验证服务器发送的响应。用于构建 RESTful 服务的自动化测试的一个框架是 REST Assured。

REST Assured 是用于轻松测试 RESTful 服务的 Java DSL。它支持`GET`、`PUT`、`POST`、`HEAD`、`OPTIONS`和`PATCH`，可以用于验证服务器发送的响应。

以下是一个获取咖啡订单并验证响应中返回的 ID 的示例：

```java
    get("order").
    then().assertThat().
    body("coffee.id",equalTo(5));
```

在上面的片段中，我们调用获取咖啡订单并验证`coffee.id`值为 5。

REST Assured 支持轻松指定和验证参数、标头、Cookie 和主体，也支持将 Java 对象与 JSON 和 XML 相互映射。有关更多详细信息，您可以查看[`code.google.com/p/rest-assured/`](https://code.google.com/p/rest-assured/)。

### 记录 RESTful 服务

为消费者构建 RESTful 服务时，无论他们来自同一企业还是来自外部应用程序或移动客户端，提供文档都是一个良好的实践。以下部分涵盖了一些为 RESTful 服务提供良好文档的框架。

Swagger 是一个用于描述、生成、消费和可视化 RESTful web 服务的框架实现。方法、参数和模型的文档紧密集成到服务器代码中。Swagger 是与语言无关的，Scala、Java 和 HTML5 的实现都可用。

有关如何将 Swagger 添加到 REST API 的教程可在以下网址找到：

[`github.com/wordnik/swagger-core/wiki/Adding-Swagger-to-your-API`](https://github.com/wordnik/swagger-core/wiki/Adding-Swagger-to-your-API)

# 推荐阅读

以下链接涉及本章涵盖的一些主题，对于审查和获取详细信息将会很有用：

+   [`dev.twitter.com/docs`](https://dev.twitter.com/docs): Twitter API 文档

+   [`dev.twitter.com/console`](https://dev.twitter.com/console): Twitter 开发者控制台

+   [`dev.twitter.com/docs/rate-limiting/1.1`](https://dev.twitter.com/docs/rate-limiting/1.1): Twitter API 在 v1.1 中的速率限制

+   [`dev.twitter.com/docs/misc/cursoring`](https://dev.twitter.com/docs/misc/cursoring): Twitter API 和游标

+   [`dev.twitter.com/docs/api/streaming`](https://dev.twitter.com/docs/api/streaming): Twitter 流 API

+   [`developers.facebook.com/docs/reference/ads-api/api-rate-limiting/`](https://developers.facebook.com/docs/reference/ads-api/api-rate-limiting/): Facebook API 速率限制

+   [`developer.github.com/v3/rate_limit/`](https://developer.github.com/v3/rate_limit/): GitHub API 速率限制

+   [`developers.facebook.com/docs/opengraph/guides/internationalization/`](https://developers.facebook.com/docs/opengraph/guides/internationalization/): Facebook 本地化

# 摘要

本章涵盖了每个 RESTful API 开发人员都应该了解的高级主题。一开始，我们看到了速率限制示例，演示了如何强制执行节流，以便服务器不会被 API 调用淹没。我们还看到了 Twitter、GitHub 和 Facebook API 如何执行速率限制。我们涵盖了不同的分页技术和基本分页示例以及最佳实践。然后，我们转向国际化和其他杂项主题。最后，我们涵盖了 HATEOAS 以及它如何成为 REST API、REST 和可扩展性主题的下一个级别。

下一章将涵盖其他新兴标准，如 WebSockets、WebHooks 以及 REST 在不断发展的 Web 标准中的作用。


# 第六章：新兴标准和 REST 的未来

本章涵盖了新兴和发展中的技术，将增强 RESTful 服务的功能，并提供对 REST 的未来以及其他实时 API 支持者的一些看法。我们将涵盖一些实时 API，并看看它们如何帮助解决轮询等旧方式的问题。鉴于 Twitter、Facebook 和 Stripe 等平台的普遍流行，它们采用了一种范式转变，因此提供了实时 API，以在事件发生时向客户端提供信息，这并不奇怪。

本章将涵盖以下主题：

+   实时 API

+   轮询

+   WebHooks

+   WebSockets

+   额外的实时 API 支持者，包括以下内容：

+   PubSubHubbub

+   服务器发送事件

+   XMPP

+   XMPP 上的 BOSH

+   使用 WebHooks 和 WebSockets 的公司案例

+   WebHooks 和 WebSockets 的比较

+   REST 和微服务

我们将从定义实时 API 的含义开始，然后讨论轮询及其缺点。接下来，我们将详细介绍广泛用于异步实时通信的不同模型。最后，我们将详细阐述 WebHooks 和 WebSockets 的务实方法。

# 实时 API

在我们的情境中，实时 API 帮助 API 消费者在事件发生时接收他们感兴趣的事件。实时更新的一个例子是当有人在 Facebook 上发布链接，或者你在 Twitter 上关注的人发表关于某个话题的推文。另一个实时 API 的例子是在股价变化发生时接收股价变化的信息。

# 轮询

轮询是从产生事件和更新流的数据源获取数据的最传统方式。客户端定期发出请求，如果有响应，服务器就会发送数据。如果服务器没有要发送的数据，就会返回空响应。以下图表显示了连续轮询的工作原理：

![轮询](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/rst-java-ptn-best-prac/img/7963OS_06_01.jpg)

轮询带来了诸多缺点，比如在服务器没有更新时对请求返回空响应，这导致了带宽和处理时间的浪费。低频率的轮询会导致客户端错过接近更新发生时间的更新，而过于频繁的轮询也会导致资源浪费，同时还会面临服务器施加的速率限制。

为了消除轮询的这些缺点，我们将涵盖以下主题：

+   PuSH 模型-PubSubHubbub

+   流模型

## PuSH 模型-PubSubHubbub

PuSH 是基于发布/订阅协议的简单主题，基于 ATOM/RSS。它的目标是将原子源转换为实时数据，并消除影响源的消费者的轮询。订阅者在主题上注册他们的兴趣，原始发布者告诉感兴趣的订阅者有新的内容。

为了分发发布和内容分发的任务，有一个**Hub**的概念，可以委托发送内容给订阅者。以下图表描述了 PubSubHubbub 模型：

![PuSH 模型-PubSubHubbub](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/rst-java-ptn-best-prac/img/7963OS_06_02.jpg)

让我们看看这个模型是如何工作的：

1.  **Subscriber**通过从**Publisher**获取 feed 来发现**Hub**。

1.  一旦**Hub**被发现，**Subscriber**就会订阅**Hub**感兴趣的 feed URI。

1.  现在，当**Publisher**有更新要发送时，它会让**Hub**获取更新。

1.  **Hub**然后将更新发送给所有发布者。

这种模型的优势在于，发布者不必担心向所有订阅者发送更新。另一方面，订阅者有一个优势，即他们可以在事件发生时从 hub 获取更新，而无需不断地轮询发布者。

在接下来的章节中讨论的**WebHooks**范例使用了这个协议。

## 流模型

异步通信的流模型涉及保持通道打开并在数据发生时发送数据。在这种情况下，需要保持套接字连接打开。

### 服务器发送事件

**服务器发送事件**（**SSE**）是基于流模型的技术，其中浏览器通过 HTTP 连接自动从服务器获取更新。W3C 已将服务器发送事件 EventSource API 作为 HTML5 的一部分进行了标准化。

使用 SSE，客户端使用`"text/eventstream"` MimeType 向服务器发起请求。一旦进行了初始握手，服务器可以在事件发生时不断向客户端发送事件。这些事件是从服务器发送到客户端的纯文本消息。它们可以是客户端侧的事件监听器可以消耗的数据，事件监听器可以解释并对接收到的事件做出反应。

SSE 定义了从服务器发送到客户端的事件的消息格式。消息格式由一系列以换行符分隔的纯文本行组成。携带消息主体或数据的行以`data:`开头，以`\n\n`结尾，如下面的代码片段所示：

```java
data: My message \n\n
```

携带一些**服务质量**（**QoS**）指令的行（例如`retry`和`id`）以 QoS 属性名称开头，后跟`:`，然后是 QoS 属性的值。标准格式使得可以开发围绕 SSE 的通用库，以使软件开发更加容易。

以下图表显示了 SSE 的工作原理：

![服务器发送事件](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/rst-java-ptn-best-prac/img/7963OS_06_03.jpg)

如图所示，客户端订阅了一个事件源。服务器会在事件发生时不断发送更新。

此外，服务器可以将 ID 与整个消息关联并发送，如下面的代码片段所示：

```java
id: 12345\n
data: Message1\n
data: Message 2\n\n
```

前面的代码片段显示了如何发送带有事件 ID 和数据的多行消息，最后一行以两个`\n\n`字符结尾。

设置一个 ID 让客户端能够跟踪最后触发的事件，这样如果与服务器的连接断开，客户端发送的新请求中会设置一个特殊的 HTTP 头(`Last-Event-ID`)。

接下来的部分将介绍如何将 ID 与 SSE 关联，SSE 在连接丢失和重试时的工作原理，以及如何将事件名称与 SSE 关联。

#### 将 ID 与事件关联

每个 SSE 消息都可以有一个消息标识符，可以用于各种目的，例如跟踪客户端接收到的消息，并为其保留一个检查点。当消息 ID 在 SSE 中使用时，客户端可以将最后的消息 ID 作为连接参数之一提供，以指示服务器从特定消息开始恢复。当然，服务器端代码应该实现一个适当的过程，以从客户端请求的消息 ID 恢复通信。

以下代码片段显示了带有 ID 的 SSE 消息的示例：

```java
id: 123 \n
data: This is a single line event \n\n
```

#### 在连接失败的情况下重试

Firefox、Chrome、Opera 和 Safari 支持服务器发送事件。如果浏览器和服务器之间出现连接丢失，浏览器可以尝试重新连接到服务器。服务器可以配置一个重试指令，以允许客户端进行重试。重试间隔的默认值为 3 秒。服务器可以发送一个重试事件来增加重试间隔到 5 秒，如下所示：

```java
retry: 5000\n
data: This is a single line data\n\n
```

#### 将事件名称与事件关联

另一个 SSE 指令是事件名称。每个事件源可以生成多种类型的事件，客户端可以根据订阅的事件类型决定如何消费每种事件类型。以下代码片段显示了`name`事件指令如何融入消息中：

```java
event: bookavailable\n
data: {"name" : "Game of Thrones"}\n\n
event: newbookadded\n
data: {"name" :"Storm of Swords"}\n\n
```

### 服务器发送事件和 JavaScript

被认为是 JavaScript 开发人员在客户端中 SSE 的基础 API 是`EventSource`接口。`EventSource`接口包含相当多的函数和属性，但最重要的函数列在下表中：

| 函数名 | 描述 |
| --- | --- |
| `addEventListener` | 此函数添加事件监听器，以处理基于事件类型的传入事件。 |
| `removeEventListener` | 此函数移除已注册的监听器。 |
| `onmessage` | 当消息到达时调用此函数。使用`onmessage`方法时，没有自定义事件处理可用。监听器管理自定义事件处理。 |
| `onerror` | 当连接出现问题时调用此函数。 |
| `onopen` | 当连接打开时调用此函数。 |
| `onclose` | 当连接关闭时调用此函数。 |

以下代码片段显示了如何订阅一个来源省略的不同事件类型。代码片段假定传入的消息是 JSON 格式的消息。例如，有一个应用程序可以在某个存储中有新书可用时向用户流式传输更新。`'bookavailable'`监听器使用简单的 JSON 解析器来解析传入的 JSON。

然后，它将用此来更新 GUI，而`'newbookadded'`监听器使用恢复函数来过滤并选择性处理 JSON 对。

```java
var source = new EventSource('books');
source.addEventListener('bookavailable', function(e) {
  var data = JSON.parse(e.data);
  // use data to update some GUI element...
}, false);

source.addEventListener('newbookadded', function(e) {
  var data = JSON.parse(e.data, function (key, value) {
    var type;
    if (value && typeof value === 'string') {
return "String value is: "+value;
    }
    return value;
```

### 服务器发送事件和 Jersey

SSE 不是标准 JAX-RS 规范的一部分。然而，在 JAX-RS 的 Jersey 实现中支持它们。更多细节请查看[`jersey.java.net/documentation/latest/sse.html`](https://jersey.java.net/documentation/latest/sse.html)。

# WebHooks

**WebHooks**是一种用户定义的自定义 HTTP 回调形式。在 WebHook 模型中，客户端提供事件生成器的端点，事件生成器可以向其*发布*事件。当事件发布到端点时，对此类事件感兴趣的客户端应用程序可以采取适当的操作。WebHooks 的一个例子是使用 GIT post-receive hook 触发 Hudson 作业等事件。

为了确认订阅者正常接收到 WebHook，订阅者的端点应返回`200 OK HTTP`状态码。事件生成器将忽略请求正文和除状态外的任何其他请求标头。任何 200 范围之外的响应代码，包括 3xx 代码，都将表示他们未收到 WebHook，并且 API 可能会重试发送 HTTP `POST`请求。

GitHub 生成的 WebHooks 事件传递了有关存储库中活动的信息负载。WebHooks 可以触发多种不同的操作。例如，消费者可能在进行提交时、复制存储库时或创建问题时请求信息负载。

以下图表描述了 WebHooks 如何与 GitHub 或 GitLab 一起工作：

![WebHooks](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/rst-java-ptn-best-prac/img/7963OS_06_04.jpg)

让我们看看 WebHooks 是如何工作的：

1.  用户进行**Git**推送。

1.  消费者与 GitHub 注册的事件对象有一个自定义的 WebHook URL。例如，当发生事件时，比如进行提交时，GitHub 服务将使用**POST**消息将有关提交的信息负载发送到消费者提供的端点。

1.  然后，消费应用程序可以将数据存储在**dB**中，或者执行其他操作，比如触发持续集成构建。

### 注意

一些流行的 WebHooks 案例研究

Twilio 使用 WebHooks 发送短信。GitHub 使用 WebHooks 发送存储库更改通知，以及可选的一些负载。

PayPal 使用**即时付款通知**（**IPN**），这是一种自动通知商家与 PayPal 交易相关事件的消息服务，它基于 WebHooks。

Facebook 的实时 API 使用 WebHooks，并基于**PubSubHubbub**（**PuSH**）。

如前所述，如果一个 API 没有提供 WebHooks 形式的通知，其消费者将不得不不断轮询数据，这不仅效率低下，而且不是实时的。

## WebSockets

WebSocket 协议是一种在单个 TCP 连接上提供全双工通信通道的协议。

WebSocket 协议是一种独立的基于 TCP 的协议，它与 HTTP 的唯一关系是，切换到 WebSockets 的握手被 HTTP 服务器解释为`Upgrade`请求。

它提供了在客户端（例如 Web 浏览器）和端点之间进行全双工、实时通信的选项，而无需不断建立连接或密集轮询资源。WebSockets 广泛用于社交动态、多人游戏、协作编辑等领域。

以下行显示了 WebSocket 协议握手的示例，从`Upgrade`请求开始：

```java
GET /text HTTP/1.1\r\n Upgrade: WebSocket\r\n Connection: Upgrade\r\n Host: www.websocket.org\r\n …\r\n 
HTTP/1.1 101 WebSocket Protocol Handshake\r\n 
Upgrade: WebSocket\r\n 
Connection: Upgrade\r\n 
…\r\n
```

下图显示了一个握手的示例，使用了`HTTP/1.1 Upgrade`请求和`HTTP/1.1 Switching Protocols`响应：

![WebSockets](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/rst-java-ptn-best-prac/img/7963OS_06_05.jpg)

一旦客户端和服务器之间建立了连接，使用`Upgrade`请求和`HTTP/1.1`响应，WebSocket 数据帧（二进制或文本）可以在客户端和服务器之间双向发送。

WebSockets 数据最小帧为 2 字节；与 HTTP 头部传输相比，这大大减少了开销。

下面是使用 JavaScript WebSockets API 的一个非常基本的示例：

```java
//Constructionof the WebSocket object
var websocket = new WebSocket("coffee"); 
//Setting the message event Function
websocket.onmessage = function(evt) { 
onMessageFunc(evt)
};
//onMessageFunc which when a message arrives is invoked.
function onMessageFunc (evt) { 
//Perform some GUI update depending the message content
}
//Sending a message to the server
websocket.send("coffee.selected.id=1020"); 
//Setting an event listener for the event type "open".
addEventListener('open', function(e){
        onOpenFunc(evt)});

//Close the connection.
websocket.close();
```

以下表格将详细描述 WebSockets 功能和各种函数：

| 函数名 | 描述 |
| --- | --- |
| `send` | 这个函数可以用来向服务器指定的 URL 发送消息。 |
| `onopen` | 当连接创建时，将调用此函数。`onopen`函数处理`open`事件类型。 |
| `onmessage` | 当新消息到达时，将调用`onmessage`函数来处理`message`事件。 |
| `onclose` | 当连接被关闭时，将调用此函数。`onclose`方法处理`close`事件类型。 |
| `onerror` | 当通信通道发生错误时，将调用此函数来处理`error`事件。 |
| `close` | 这个函数用于关闭通信套接字并结束客户端和服务器之间的交互。 |

### 注意

**流行的 WebSockets 案例研究**

德州扑克是最早大规模利用 WebSockets 连接的游戏之一。在德州扑克 HTML5 中使用 WebSockets 可以提供流畅、高速的游戏体验，允许在移动网络上实现同步体验。根据连接的不同，游戏加载和刷新几乎立即完成。

# 额外的实时 API 支持者

还有一些常用的实时或几乎实时通信协议和 API，它们大多数在浏览器之外使用。其中一些协议和 API 将在接下来的部分中描述。

## XMPP

XMPP 协议是为满足文本消息和互联网聊天导向解决方案的要求而开发的。XMPP 的基本通信模型是客户端到服务器、服务器到服务器、服务器到客户端。为了支持这一点，它定义了基于 XML 消息的客户端到服务器协议和服务器到服务器协议，直接通过 TCP 编码和传输。

XMPP 是一种成熟的协议，在不同语言和平台上有许多实现。与 XMPP 相关的主要缺点是长轮询和开放套接字来处理入站和出站通信。

## XMPP 上的 BOSH

**同步 HTTP 上的双向流**（**BOSH**）在 XEP-0124 中规定了在 HTTP 上进行 XMPP 的标准方式。对于客户端发起的协议，客户端简单地在 HTTP 上发送 XMPP 数据包，对于服务器发起的协议，服务器使用长轮询，连接在预定的时间内保持打开状态。

BOSH 的主要优势在于它提供了使用 Web 浏览器作为 XMPP 客户端的可能性，利用了 BOSH 的任何 JavaScript 实现。Emite、JSJaC 和 xmpp4js 是一些支持 BOSH 的库。

# WebHooks、WebSockets 和服务器发送事件之间的比较

与 WebSockets 不同，SSE 是通过 HTTP 发送的。SSE 仅提供了从服务器到客户端的事件单向通信，并不像 WebSockets 那样支持全双工通信。SSE 具有自动重试连接的能力；它们还具有可以与消息关联的事件 ID，以提供**服务质量**（**QoS**）功能。WebSockets 规范不支持这些功能。

另一方面，WebSockets 支持全双工通信，减少了延迟并有助于提高吞吐量，因为它们在 HTTP 上进行了初始握手，然后消息在端点之间通过 TCP 传输。

与前面提到的两种协议相比，WebHooks 的准入门槛较低，并为应用程序和服务提供了一种简单的集成方式。这使得能够通过 HTTP 请求使一组松散耦合的云服务相互连接和交换。

下表比较和对比了 WebHooks、WebSockets 和 SSE 在不同领域的情况：

| 标准 | WebHooks | WebSockets | 服务器发送事件 |
| --- | --- | --- | --- |
| 异步实时通信支持 | 是 | 是 | 是 |
| 回调 URL 注册 | 是 | 否 | 否 |
| 长期开放连接 | 否 | 是 | 是 |
| 双向 | 否 | 是 | 否 |
| 错误处理 | 否 | 是 | 是 |
| 易于支持和实现 | 是 | 需要浏览器和代理服务器支持 | 是 |
| 需要回退到轮询 | 否 | 是 | 否 |

接下来的部分将介绍高可用云应用程序如何向基于微服务的架构迈进。

# REST 和微服务

随着微服务架构的出现，SOA 的梦想已经成为现实，微服务架构将单片应用程序分解为一组细粒度服务。我们现在将看一下微服务相对于单片服务的不同优势。

## 简单性

许多开发人员发现，与使用更复杂的传统企业相比，使用轻量级 API 服务构建相同的应用程序更具弹性、可扩展性和可维护性。这种风格就是基于微服务的架构。这与诸如 CORBA 和 RMI 的传统 RPC 方法或 SOAP 等庞大的 Web 服务协议的方法形成对比。

## 问题的隔离

在单片应用程序中，服务的所有组件都加载在单个应用程序构件（WAR、EAR 或 JAR 文件）中，该构件部署在单个 JVM 上。这意味着如果应用程序或应用程序服务器崩溃，将导致所有服务的失败。

然而，使用微服务架构，服务可以是独立的 WAR/EAR 文件。服务可以通过 REST 和 JSON 或 XML 相互通信。在微服务架构中，另一种服务之间通信的方式是使用 AMQP/Rabbit MQ 等消息协议。

## 扩展和缩减

对于单片服务，部署的应用程序文件中并非所有服务都需要进行扩展，但它们都被迫遵循在部署级别制定的相同扩展和缩减规则。

使用微服务架构，可以通过较小的服务构建应用程序，这些服务可以独立部署和扩展。这导致了一种对故障具有弹性、可扩展和灵活的架构，可以从特性定义阶段快速开发、构建和部署服务，直到生产阶段。

## 能力的清晰分离

在微服务架构中，这些服务可以根据业务能力进行组织。例如，库存服务可以与计费服务分开，而计费服务可以与运输服务分开。如果其中一个服务失败，其他服务仍然可以继续提供请求，正如*问题隔离*部分所述。

## 语言独立性

微服务架构的另一个优势是，这些服务是使用简单易用的 REST/JSON API 构建的，可以轻松被其他语言或框架（如 PHP、Ruby-On-Rails、Python 和 node.js）消费。

亚马逊和 Netflix 是微服务架构的先驱之一。eBay 开源了 Turmeric，这是一个全面的、基于策略驱动的 SOA 平台，可用于开发、部署、保护、运行和监控 SOA 服务和消费者。

# 推荐阅读

以下是一些额外资源的链接，感兴趣的读者可以查看，以更全面地了解本章提到的用例：

+   [`stripe.com/docs/webhooks`](https://stripe.com/docs/webhooks)：WebHooks 支持

+   [`github.com/sockjs`](https://github.com/sockjs)：GitHub SockJs

+   [`developer.github.com/webhooks/testing/`](https://developer.github.com/webhooks/testing/)：GitHub WebHooks

+   [`www.twilio.com/platform/webhooks`](http://www.twilio.com/platform/webhooks)：Twilio WebHooks

+   [`xmpp4js.sourceforge.net/`](http://xmpp4js.sourceforge.net/)：XMPP4JS BOSH 库

+   [`code.google.com/p/emite/`](https://code.google.com/p/emite/)：Emite BOSH 库

# 总结

在本章中，我们涵盖了 WebHooks、SSEs、WebSockets 等高级主题，以及它们在本章中的使用场景和方式。本章的主要收获之一是要理解提供实时 API 的重要性，以避免与重复轮询相关的低效。我们看到了一些公司在其解决方案中同时使用 WebHooks 和 WebSockets 的案例研究。我们在整本书的各个章节中看到了不同的最佳实践和设计原则；作为总结，本章对 REST 和异步通信的未来提供了实质性的介绍。社交数据的大量增加有可能成为发展语义网络的重要推动力，这将使代理能够代表我们执行非平凡的操作，并使用我们讨论过的各种模式进行实时更新。

此外，我们看到高可用云应用程序往往会转向网络化组件模型，应用程序会被分解为可以使用微服务架构独立部署和扩展的*微*服务。要了解更多关于构建 RESTful 服务的详细信息，请查看书籍*Developing RESTful Services with JAX-RS2.0, WebSockets, and JSON*，作者 Bhakti Mehta 和 Masoud Kalali，出版社 Packt Publishing。


# 附录 A. 附录

在这个社交网络、云计算和移动应用的时代，人们希望与他人保持联系，发表意见，协作构建应用程序，分享输入并提出问题。从[`www.statisticbrain.com/twitter-statistics/`](http://www.statisticbrain.com/twitter-statistics/)中提到的数据可以看出，Twitter 拥有大约 650 万用户，每天有 5800 万条推文。同样，Facebook 的统计数据也令人震惊：13 亿用户使其成为社交网络平台的核心。多年来，GitHub 已经发展成为默认的社交编码平台。因此，Twitter、Facebook 和 GitHub 是最广泛使用的构建应用程序、挖掘数据以及构建与分析相关信息的平台之一。

前几章涵盖了构建 RESTful 服务、添加性能、缓存、安全性以及 RESTful 服务的扩展等主题，本章将重点介绍一些流行的 REST 平台以及它们如何与之前章节中涵盖的不同模式相结合，作为它们的 API 基础设施的一部分。

本章将涵盖以下主题：

+   GitHub REST API 概述

+   Facebook Open Graph API 概述

+   Twitter REST API 概述

# GitHub REST API 概述

GitHub 已经成为极其流行的社交协作编码平台，用于构建代码以及为其他存储库做出贡献。开发人员使用它来创建、构建和部署软件，使用范围从个人项目到各种企业使用它作为其流程的一部分。GitHub 在其服务的 API 文档中有详尽的文档，网址为[`developer.github.com/v3/`](https://developer.github.com/v3/)。

以下部分详细介绍了 GitHub 如何处理我们在之前章节中涵盖的所有不同模式。

## 从 GitHub 获取详细信息

以下命令显示了如何使用未经身份验证的 cURL 命令来获取用户的数据，获取存储库的详细信息等。

以下命令获取`javaee-samples`用户的详细信息：

```java
curl https://api.github.com/users/javaee-samples
{
 "login": "javaee-samples",
 "id": 6052086,
 "avatar_url": "https://avatars.githubusercontent.com/u/6052086?",
 "gravatar_id": null,
 "url": "https://api.github.com/users/javaee-samples",
 "html_url": "https://github.com/javaee-samples",
 "followers_url": "https://api.github.com/users/javaee-samples/followers",
 "following_url": "https://api.github.com/users/javaee-samples/following{/other_user}",
 "gists_url": "https://api.github.com/users/javaee-samples/gists{/gist_id}",
 "starred_url": "https://api.github.com/users/javaee-samples/starred{/owner}{/repo}",
 "subscriptions_url": "https://api.github.com/users/javaee-samples/subscriptions",
 "organizations_url": "https://api.github.com/users/javaee-samples/orgs",
 "repos_url": "https://api.github.com/users/javaee-samples/repos",
 "events_url": "https://api.github.com/users/javaee-samples/events{/privacy}",
 "received_events_url": "https://api.github.com/users/javaee-samples/received_events",
 "type": "Organization",
 "site_admin": false,
 "name": "JavaEE Samples",
 "company": null,
 "blog": "https://arungupta.ci.cloudbees.com/",
 "location": null,
 "email": null,
 "hireable": false,
 "bio": null,
 "public_repos": 11,
 "public_gists": 0,
 "followers": 0,
 "following": 0,
 "created_at": "2013-11-27T17:17:00Z",
 "updated_at": "2014-07-03T16:17:51Z"

```

### 注意

如前述命令所示，前述响应中有不同的 URL，可用于获取关注者、提交等详细信息。这种呈现 URL 的方式与我们在本书早期使用`links`、`href`、`rel`等方式介绍的 HATEOAS 示例不同。这显示了不同平台选择不同方式提供连接服务的方式，这是不言自明的。

要获取用户的存储库并进行分页，可以使用如下查询：

```java
curl https://api.github.com/users/javaee-samples/repos?page=1&per_page=10
…..

```

GitHub API 使用 OAuth2 来对用户进行身份验证。所有使用 GitHub API 的开发人员都需要注册他们的应用程序。注册的应用程序会被分配一个唯一的客户端 ID 和客户端密钥。

有关为用户获取经过身份验证的请求的更多详细信息，请查看[`developer.github.com/v3/oauth/`](https://developer.github.com/v3/oauth/)。

## 动词和资源操作

以下表格涵盖了 GitHub API 如何使用动词来执行特定资源的操作：

| 动词 | 描述 |
| --- | --- |
| `HEAD` | 用于获取 HTTP 头信息 |
| `GET` | 用于检索资源，比如用户详细信息 |
| `POST` | 用于创建资源，比如合并拉取请求 |
| `PATCH` | 用于对资源进行部分更新 |
| `PUT` | 用于替换资源，比如更新用户 |
| `DELETE` | 用于删除资源，比如将用户移除为协作者 |

## 版本控制

GitHub API 在其 URI 中使用版本 v3。API 的默认版本可能会在将来更改。如果客户端依赖于特定版本，他们建议明确发送一个`Accept`头，如下所示：

```java
Accept: application/vnd.github.v3+json
```

## 错误处理

如第二章中所述，*资源设计*，客户端错误由`400 错误`代码表示。GitHub 使用类似的约定来表示错误。

如果使用 API 的客户端发送无效的 JSON，则会返回`400 Bad Request`响应给客户端。如果使用 API 的客户端在请求体中漏掉了字段，则会返回`422 Unprocessable Entity`响应给客户端。

## 速率限制

GitHub API 还支持速率限制，以防止服务器因某些恶意客户端的过多请求而导致失败。对于使用**基本身份验证**或**OAuth**的请求，客户端每小时最多可以发出 5,000 个请求。对于未经身份验证的请求，客户端每小时的速率限制为 60 个请求。GitHub 使用**X-RateLimit-Limit**、**X-RateLimit-Remaining**和**X-RateLimit-Reset**头来告知速率限制的状态。

因此，我们已经介绍了 GitHub API 的细节，介绍了他们选择如何实现本书中迄今为止介绍的一些 REST 原则。下一节将介绍 Facebook Open Graph REST API，涵盖版本控制、错误处理、速率限制等主题。

# Facebook Graph API 概述

Facebook Graph API 是从 Facebook 数据中获取信息的一种方式。使用 HTTP REST API，客户端可以执行各种任务，如查询数据、发布更新和图片、获取相册和创建相册、获取节点的点赞数、获取评论等。下一节将介绍如何访问 Facebook Graph API。

### 注意

在 Web 上，Facebook 使用 OAuth 2.0 协议的变体进行身份验证和授权。原生的 Facebook 应用程序用于 iOS 和 Android。

要使用 Facebook API，客户端需要获取一个访问令牌来使用 OAuth 2.0。以下步骤显示了如何创建应用程序 ID 和密钥，然后获取访问令牌来执行对 Facebook 数据的查询：

1.  前往[developers.facebook.com/apps](http://developers.facebook.com/apps)。您可以创建一个新的应用程序。创建应用程序后，您将被分配应用程序 ID 和密钥，如下面的屏幕截图所示：![Facebook Graph API 概述](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/rst-java-ptn-best-prac/img/7963OS_07_01.jpg)

1.  一旦您获得了应用程序 ID 和密钥，就可以获取访问令牌并执行对 Facebook 数据的查询。

### 注意

Facebook 有一个特殊的`/me`端点，对应于正在使用访问令牌的用户。要获取用户的照片，请求可以如下所示：

`GET /graph.facebook.com/me/photos`

1.  要发布消息，用户可以调用如下简单的 API：

```java
      POST /graph.facebook.com/me/feed?message="foo"
       &access_token="…."
```

1.  要使用 Graph Explorer 获取您的 ID、名称和照片的详细信息，查询如下：

```java
https://developers.facebook.com/tools/explorer?method=GET&path=me%3Ffields=id,name
```

1.  下面的屏幕截图显示了一个 Graph API Explorer 查询，节点为`dalailama`。点击 ID 可以查看节点的更多详细信息。![Facebook Graph API 概述](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/rst-java-ptn-best-prac/img/7963OS_07_02.jpg)

因此，我们看到如何使用 Graph API Explorer 应用程序来构建社交图中节点的查询。我们可以通过各种字段（如 ID 和名称）进行查询，并尝试使用`GET`、`POST`或`DELETE`等方法。

## 动词和资源操作

下表总结了 Facebook Graph API 中常用的动词：

| 动词 | 描述 |
| --- | --- |
| `GET` | 用于检索资源，如动态、相册、帖子等 |
| `POST` | 用于创建资源，如动态、帖子、相册等 |
| `PUT` | 用于替换资源 |
| `DELETE` | 用于删除资源 |

### 提示

一个重要的观察是，Facebook Graph API 使用`POST`而不是`PUT`来更新资源。

## 版本控制

Graph API 目前使用的是 2014 年 8 月 7 日发布的 2.1 版本。客户端可以在请求 URL 中指定版本。如果客户端没有指定版本，Facebook Open Graph API 将默认使用最新可用的版本。每个版本保证在 2 年内可用，之后如果客户端使用旧版本进行任何调用，它们将被重定向到 API 的最新版本。

## 错误处理

以下片段显示了失败的 API 请求的错误响应：

```java
    {
       "error": {
         "message": "Message describing the error",
         "type": "OAuthException",
         "code": 190 ,
        "error_subcode": 460
       }
     }
```

如前面的代码所示，错误消息中有称为`code`和`error_subcode`的 JSON 对象，可用于找出问题所在以及恢复操作。在这种情况下，`code`的值是`190`，这是一个`OAuthException`值，而`error_subcode`值为`460`，表示密码可能已更改，因此`access_token`无效。

## 速率限制

Facebook Graph API 根据使用 API 的实体是用户、应用程序还是广告，具有不同的速率限制政策。当用户的调用超过限制时，用户将被阻止 30 分钟。有关更多详细信息，请查看[`developers.facebook.com/docs/reference/ads-api/api-rate-limiting/`](https://developers.facebook.com/docs/reference/ads-api/api-rate-limiting/)。下一节将介绍 Twitter REST API 的详细信息。

# Twitter API 概述

Twitter API 具有 REST API 和 Streaming API，允许开发人员访问核心数据，如时间线、状态数据、用户信息等。

Twitter 使用三步 OAuth 进行请求。

### 注意

**Twitter API 中 OAuth 的重要方面**

客户端应用程序不需要存储登录 ID 和密码。应用程序发送代表用户的访问令牌，而不是使用用户凭据的每个请求。

为了成功完成请求，`POST`变量、查询参数和请求的 URL 始终保持不变。

用户决定哪些应用程序可以代表他，并随时可以取消授权。

每个请求的唯一标识符（`oauth_nonce`标识符）防止重放相同的请求，以防它被窥探。

对于向 Twitter 发送请求，大多数开发人员可能会发现初始设置有点令人困惑。[`blog.twitter.com/2011/improved-oauth-10a-experience`](https://blog.twitter.com/2011/improved-oauth-10a-experience)的文章显示了如何创建应用程序、生成密钥以及使用 OAuth 工具生成请求。

以下是 Twitter 中 OAuth 工具生成的请求示例，显示了获取`twitterapi`句柄状态的查询：

### 注意

Twitter API 不支持未经身份验证的请求，并且具有非常严格的速率限制政策。

```java
curl --get 'https://api.twitter.com/1.1/statuses/user_timeline.json' --data 'screen_name=twitterapi' --header 'Authorization: OAuth oauth_consumer_key="w2444553d23cWKnuxrlvnsjWWQ", oauth_nonce="dhg2222324b268a887cdd900009ge4a7346", oauth_signature="Dqwe2jru1NWgdFIKm9cOvQhghmdP4c%3D", oauth_signature_method="HMAC-SHA1", oauth_timestamp="1404519549", oauth_token="456356j901-A880LMupyw4iCnVAm24t33HmnuGOCuNzABhg5QJ3SN8Y", oauth_version="1.0"'—verbose.

```

这会产生如下输出：

```java
GET /1.1/statuses/user_timeline.json?screen_name=twitterapi HTTP/1.1
Host: api.twitter.com
Accept: */*
 HTTP/1.1 200 OK
…
"url":"http:\/\/t.co\/78pYTvWfJd","entities":{"url":{"urls":[{"url":"http:\/\/t.co\/78pYTvWfJd","expanded_url":"http:\/\/dev.twitter.com","display_url":"dev.twitter.com","indices":[0,22]}]},"description":{"urls":[]}},"protected":false,"followers_count":2224114,"friends_count":48,"listed_count":12772,"created_at":"Wed May 23 06:01:13 +0000 2007","favourites_count":26,"utc_offset":-25200,"time_zone":"Pacific Time (US & Canada)","geo_enabled":true,"verified":true,"statuses_count":3511,"lang":"en","contributors_enabled":false,"is_translator":false,"is_translation_enabled":false,"profile_background_color":"C0DEED","profile_background_image_url":"http:\/\/pbs.twimg.com\/profile_background_images\/656927849\/miyt9dpjz77sc0w3d4vj….

```

## 动词和资源操作

以下表格总结了 Twitter REST API 中常用的动词：

| 动词 | 描述 |
| --- | --- |
| `GET` | 用于检索资源，如用户、关注者、收藏夹、订阅者等。 |
| `POST` | 用于创建资源，如用户、关注者、收藏夹、订阅者等。 |
| `POST`与动词`update` | 用于替换资源。例如，要更新友谊关系，URL 将是`POST friendships/update`。 |
| `POST`与动词`destroy` | 用于删除资源，如删除直接消息、取消关注某人等。例如，URL 将是`POST direct_messages/destroy`。 |

## 版本控制

Twitter API 的当前版本是 1.1。它仅支持 JSON，不再支持 XML、RSS 或 Atom。使用 Twitter API 版本 1.1，所有客户端都需要使用 OAuth 进行身份验证以进行查询。Twitter API 版本 1.0 已被弃用，有 6 个月的时间窗口来迁移到新版本。

## 错误处理

Twitter API 在对 REST API 的响应中返回标准的 HTTP 错误代码。成功时返回`200 OK`。当没有数据返回时返回`304 Not Modified`，当认证凭据丢失或不正确时返回`401 Not Authorized`，当出现故障并需要发布到论坛时返回`500 Internal Server Error`等等。除了详细的错误消息，Twitter API 还生成可机器读取的错误代码。例如，响应中的错误代码`32`意味着服务器无法对用户进行身份验证。更多详情，请查看[`dev.twitter.com/docs/error-codes-responses`](https://dev.twitter.com/docs/error-codes-responses)。

# 推荐阅读

以下部分提供了一些链接，可能对您有所帮助：

+   Facebook 工具：[`developers.facebook.com/tools/`](https://developers.facebook.com/tools/)

+   Twurl（为 Twitter 启用 OAuth 的 cURL）：[`github.com/twitter/twurl`](https://github.com/twitter/twurl)

+   GitHub API 文档：[`developer.github.com/v3/`](https://developer.github.com/v3/)

+   Twitter API 文档：[`dev.twitter.com/docs/api/1.1`](https://dev.twitter.com/docs/api/1.1)

+   Stripe API 文档：[`stripe.com/docs/api`](https://stripe.com/docs/api)

# 摘要

本附录是一份由流行平台（如 GitHub、Facebook 和 Twitter）实施的 API 的简要集合，以及它们处理各种 REST 模式的方法。尽管用户可以通过 REST API 的数据做出多种可能性，但这些框架之间的共同点是使用 REST 和 JSON。这些平台的 REST API 由 Web 和移动客户端使用。本附录涵盖了这些平台如何处理版本控制、动词、错误处理，以及基于 OAuth 2.0 对请求进行认证和授权。

本书从 REST 的基础知识和如何构建自己的 RESTful 服务开始。从那时起，我们涵盖了各种主题以及构建可扩展和高性能的 REST 服务的技巧和最佳实践。我们还参考了各种库和工具，以改进 REST 服务的测试和文档，以及实时 API 的新兴标准。我们还涵盖了使用 WebSockets、WebHooks 以及 REST 的未来的案例研究。

我们希望我们的这一努力能帮助您更好地理解、学习、设计和开发未来的 REST API。
