# SpringMVC：设计现实世界的 Web 应用（十）

> 原文：[`zh.annas-archive.org/md5/AB3510E97B9E20602840C849773D49C6`](https://zh.annas-archive.org/md5/AB3510E97B9E20602840C849773D49C6)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第二十章：打造 RESTful 应用程序

在本章中，我们将介绍 RESTful 架构的主要原则。然后，借助非常方便的工具，我们将设计一个友好的 API，利用 Jackson 的能力将我们的模型序列化为 JSON。

我们将使用适当的错误代码和 HTTP 动词记录我们的应用程序，并使用 Swagger UI 自动生成我们应用程序的整洁前端。

最后，我们将研究其他形式的序列化，并了解更多关于 Spring MVC 的内容协商机制。

# 什么是 REST？

**REST**（表述状态转移）是一种定义创建可扩展 Web 服务的最佳实践的架构风格，利用了 HTTP 协议的能力。

一个 RESTful 的 Web 服务应该自然地表现出以下特性：

+   **客户端-服务器**: UI 与数据存储分离

+   **无状态**: 每个请求都包含足够的信息，以便服务器在不维护任何状态的情况下运行

+   **可缓存**: 服务器的响应包含足够的信息，允许客户端对数据存储做出明智的决定

+   **统一接口**: URI 唯一标识资源，超链接允许发现 API

+   **分层**: API 的每个资源提供了合理的细节水平

这种架构的优势在于它易于维护和发现。它还具有良好的可扩展性，因为无需在服务器和客户端之间维护持久连接，这消除了负载平衡或粘性会话的需要。最后，服务更有效，因为信息布局整齐，易于缓存。

让我们看看如何通过使用 Richardson 的成熟度模型逐步设计更好的 API。

# Richardson 的成熟度模型

Leonard Richardson 因定义了从 0 到 3 的四个级别而闻名，描述了 Web API 的“RESTfulness”级别。每个级别都需要额外的工作和投资在 API 中，但也提供了额外的好处。

## 级别 0 – HTTP

级别 0 真的很容易达到；你只需要通过 HTTP 协议在网络上提供你的资源。你可以使用你认为最适合你的用例的任何数据表示（XML、JSON 等）。

## 级别 1 – 资源

大多数人在听到 REST 这个词时会想到资源。资源是我们模型中元素的唯一标识符，例如用户或推文。使用 HTTP，资源显然与统一资源标识符 URI 相关联，如下例所示：

+   `/users` 包含我们所有用户的列表

+   `/user/42` 包含特定用户

+   `/user/42/tweets` 包含与特定用户关联的所有推文的列表

也许你的 API 可以允许访问与用户相关的特定推文，使用`/user/42/tweet/3`，或者每条推文都有唯一标识，这种情况下你可能更喜欢`/tweet/3`。

这个级别的目标是通过公开多个专门的资源来处理应用程序的复杂性。

关于服务器可以返回的响应类型没有规则。当你列出所有资源时，你可能只想包含稀缺信息，并在请求特定资源时提供更多细节。一些 API 甚至允许你在提供给你之前列出你感兴趣的字段。

真的取决于你来定义 API 的形式，记住一个简单的规则：最少惊讶原则。给你的用户他们期望的东西，你的 API 就已经很好了。

## 级别 2 – HTTP 动词

这个级别是关于使用 HTTP 动词来识别资源上可能的操作。这是描述 API 可以做什么的一个非常好的方式，因为 HTTP 动词是开发人员之间的一个众所周知的标准。

主要动词列在这里：

+   `GET`: 这读取特定 URI 上的数据。

+   `HEAD`：这与`GET`相同，但没有响应主体。这对于获取资源的元数据（缓存信息等）很有用。

+   `DELETE`：这会删除一个资源。

+   `PUT`：这会更新或创建一个资源。

+   `POST`：这会更新或创建一个资源。

+   `PATCH`：这会部分更新一个资源。

+   `OPTIONS`：这会返回服务器在特定资源上支持的方法列表。

大多数允许**创建读取更新删除**（**CRUD**）操作的应用只需要三个动词：`GET`、`DELETE`和`POST`。你实现的动词越多，你的 API 就会变得越丰富和更有语义。它帮助第三方通过允许他们输入一些命令并查看发生了什么来与你的服务交互。

`OPTIONS`和`HEAD`动词很少见，因为它们在元数据级别上工作，通常对任何应用程序都不是至关重要的。

乍一看，`PUT`和`POST`动词似乎做着相同的事情。主要区别在于`PUT`动词被认为是幂等的，这意味着多次发送相同的请求应该导致相同的服务器状态。这条规则的含义基本上是，`PUT`动词应该在给定的 URI 上操作，并包含足够的信息使请求成功。

例如，客户端可以在`/user/42`上使用`PUT`数据，结果将是更新或创建，取决于请求之前实体是否存在。

另一方面，当你不确定应该写入什么 URI 时，应该使用`POST`。你可以发送`POST`到`/users`而不在请求中指定 ID，并期望用户被创建。你也可以发送`POST`到相同的`/users`资源，这次在请求实体中指定一个用户 ID，并期望服务器更新相应的用户。

正如你所看到的，这两个选项都有效。一个常见的用例是使用`POST`进行创建（因为大多数情况下，服务器应该负责 ID），并使用`PUT`来更新已知 ID 的资源。

服务器也可能允许部分修改资源（而不需要客户端发送完整的资源内容）。在这种情况下，它应该响应`PATCH`方法。

在这个级别上，我也鼓励你在提供响应时使用有意义的 HTTP 代码。我们马上会看到最常见的代码。

## Level 3 - 超媒体控制

超媒体控制也被称为**超文本作为应用状态的引擎**（**HATEOAS**）。在这个生僻的首字母缩略词背后，隐藏着 RESTful 服务最重要的特性：通过超文本链接使其可发现。这本质上是服务器告诉客户端它的选项是什么，使用响应头或响应实体。

例如，在使用`PUT`创建资源后，服务器应该返回一个带有`201 CREATED`代码的响应，并发送一个包含创建的资源 URI 的`Location`头。

没有一个标准定义了 API 其他部分的链接应该是什么样子。Spring Data REST，一个允许你使用最少的配置创建 RESTful 后端的 Spring 项目，通常会输出这样：

```java

{
 "_links" : {
 "people" : {
 "href" : "http://localhost:8080/users{?page,size,sort}",
 "templated" : true
 }
 }
}

```

然后，去`/users`：

```java

{
 "_links" : {
 "self" : {
 "href" : "http://localhost:8080/users{?page,size,sort}",
 "templated" : true
 },
 "search" : {
 "href" : "http://localhost:8080/users/search"
 }
 },
 "page" : {
 "size" : 20,
 "totalElements" : 0,
 "totalPages" : 0,
 "number" : 0
 }
}

```

这给了你一个关于你可以用 API 做什么的好主意，不是吗？

# API 版本控制

如果第三方客户端使用你的 API，你可以考虑对 API 进行版本控制，以避免在更新应用程序时出现破坏性变化。

对 API 进行版本控制通常是提供一组稳定资源在子域下可用的问题。例如，GitLab 维护其 API 的三个版本。它们可以在`https://example/api/v3`下访问，等等。像软件中的许多架构决策一样，版本控制是一种权衡。

设计这样的 API 并识别 API 中的破坏性变化将需要更多的工作。通常情况下，添加新字段不会像移除或转换 API 实体结果或请求那样成为问题。

大多数情况下，您将负责 API 和客户端，因此不需要这样的复杂性。

### 注意

有关 API 版本控制的更深入讨论，请参阅此博客文章：

[`www.troyhunt.com/2014/02/your-api-versioning-is-wrong-which-is.html`](http://www.troyhunt.com/2014/02/your-api-versioning-is-wrong-which-is.html)

# 有用的 HTTP 代码

良好的 RESTful API 的另一个重要方面是以明智的方式使用 HTTP 代码。HTTP 规范定义了许多标准代码。它们应该涵盖良好 API 需要向其用户传达的 99%内容。以下列表包含最重要的代码，每个 API 都应该使用并且每个开发人员都应该知道：

| 代码 | 意义 | 用法 |
| --- | --- | --- |
| **2xx - 成功** | **当一切顺利时使用这些代码。** |   |
| `200` | 一切正常。 | 请求成功。 |
| `201` | 已创建资源 | 资源已成功创建。响应应包括与创建相关联的位置列表。 |
| `204` | 没有内容可返回。 | 服务器已成功处理请求，但没有内容可返回。 |
| **3xx - 重定向** | **当客户端需要进一步操作以满足请求时使用这些代码**。 |   |
| `301` | 永久移动 | 资源的 URI 已更改，并且其新位置在`Location`标头中指示。 |
| `304` | 资源未被修改。 | 资源自上次以来未发生更改。此响应必须包括日期、ETag 和缓存信息。 |
| **4xx - 客户端错误** | **由于客户端的错误而导致请求未成功执行**。 |   |
| `400` | 错误的请求 | 服务器无法理解客户端发送的数据。 |
| `403` | 禁止 | 请求已理解但不允许。这可以丰富错误描述信息。 |
| `404` | 未找到 | 没有与此 URI 匹配的内容。这可以用来替代 403，如果不应该透露有关安全性的信息。 |
| `409` | 冲突 | 请求与另一个修改冲突。响应应包括有关如何解决冲突的信息。 |
| **5xx - 服务器错误** | **服务器端发生错误**。 |   |
| `500` | 内部服务器错误 | 服务器意外地未能处理请求。 |

### 注意

有关更详细的列表，请参阅[`www.restapitutorial.com/httpstatuscodes.html`](http://www.restapitutorial.com/httpstatuscodes.html)。

# 客户是王者

我们将允许第三方客户端通过 REST API 检索搜索结果。这些结果将以 JSON 或 XML 的形式提供。

我们希望处理`/api/search/mixed;keywords=springFramework`形式的请求。这与我们已经创建的搜索表单非常相似，只是请求路径以`api`开头。在此命名空间中找到的每个 URI 都应返回二进制结果。

让我们在`search.api`包中创建一个新的`SearchApiController`类：

```java
package masterSpringMvc.search.api;

import masterSpringMvc.search.SearchService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.social.twitter.api.Tweet;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/search")
public class SearchApiController {
    private SearchService searchService;

    @Autowired
    public SearchApiController(SearchService searchService) {
        this.searchService = searchService;
    }

    @RequestMapping(value = "/{searchType}", method = RequestMethod.GET)
    public List<Tweet> search(@PathVariable String searchType, @MatrixVariable List<String> keywords) {
        return searchService.search(searchType, keywords);
    }
}
```

这与我们以前的控制器非常相似，有三个细微的差异：

+   控制器类使用`@RequestMapping`注解。这将是我们的基本地址，并将前缀在此控制器中声明的每个其他映射。

+   我们不再重定向到视图，而是在搜索方法中返回一个普通对象。

+   控制器使用`@RestController`而不是`@Controller`进行注释。

`RestController`是一种快捷方式，用于声明将每个响应返回为如果使用`@ResponseBody`注解进行注释的控制器。它告诉 Spring 将返回类型序列化为适当的格式，默认为 JSON。

在使用 REST API 时，一个良好的实践是始终指定您将响应的方法。对于`GET`或`POST`方法，请求能够以相同的方式处理的可能性非常小。

如果您访问`http://localhost:8080/api/search/mixed;keywords=springFramework`，您应该会得到一个非常大的结果，如下所示：

![客户端是王者](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00963.jpeg)

确实，Spring 自动处理了整个`Tweet`类的属性的序列化，使用了 Jackson。

# 调试 RESTful API

使用浏览器，您只能对特定 API 执行`GET`请求。好的工具将使您的开发变得更简单。有很多工具可以测试 RESTful API。我只会列出我使用和喜爱的工具。

## JSON 格式化扩展

通常，您只会测试`GET`方法，您的第一反应将是将地址复制到浏览器中检查结果。在这种情况下，您有可能获得更多的内容，而不仅仅是纯文本，例如 Chrome 的 JSON Formatter 或 Firefox 的 JSONView 等扩展。

## 浏览器中的 RESTful 客户端

浏览器是处理 HTTP 请求的自然工具。然而，使用地址栏很少能够详细测试您的 API。

Postman 是 Chrome 的一个扩展，RESTClient 是其 Firefox 的对应物。它们都具有类似的功能，例如创建和共享查询集合、修改标头以及处理身份验证（基本、摘要和 OAuth）。在撰写本文时，只有 RESTClient 处理 OAuth2。

## httpie

**httpie**是一个类似 curl 但面向 REST 查询的命令行实用程序。它允许您输入诸如此类的命令：

```java

http PUT httpbin.org/put hello=world

```

这比这个丑陋的版本要友好得多：

```java

curl -i -X PUT httpbin.org/put -H Content-Type:application/json -d '{"hello": "world"}'

```

# 自定义 JSON 输出

使用我们的工具，我们能够轻松地查看服务器生成的请求。它很大。默认情况下，Spring Boot 使用的 JSON 序列化库 Jackson 将序列化所有可以通过 getter 方法访问的内容。

我们希望有一些更轻量级的东西，比如这样：

```java
{
 "text": "original text",
 "user": "some_dude",
 "profileImageUrl": "url",
 "lang": "en",
 "date": 2015-04-15T20:18:55,
 "retweetCount": 42
}

```

自定义将被序列化的字段的最简单方法是向我们的 bean 添加注释。您可以在类级别使用`@JsonIgnoreProperties`注释来忽略一组属性，或者在希望忽略的属性的 getter 上添加`@JsonIgnore`。

在我们的情况下，`Tweet`类不是我们自己的类。它是 Spring Social Twitter 的一部分，我们无法对其进行注释。

直接使用模型类进行序列化很少是一个好选择。这将使您的模型与您的序列化库绑定在一起，而这应该保持为一个实现细节。

在处理不可修改的代码时，Jackson 提供了两个选项：

+   创建一个专门用于序列化的新类。

+   使用 mixins，这些是简单的类，将与您的模型关联起来。这些将在您的代码中声明，并且可以用任何 Jackson 注释进行注释。

由于我们只需要对模型的字段进行一些简单的转换（大量隐藏和少量重命名），我们可以选择使用 mixins。

这是一种良好的、非侵入式的方式，可以通过一个简单的类或接口在运行时重命名和排除字段。

另一种指定应用程序不同部分中使用的字段子集的选项是使用`@JsonView`注解对其进行注释。这不会在本章中涵盖，但我鼓励您查看这篇优秀的博客文章[`spring.io/blog/2014/12/02/latest-jackson-integration-improvements-in-spring`](https://spring.io/blog/2014/12/02/latest-jackson-integration-improvements-in-spring)。

我们希望能够控制我们 API 的输出，所以让我们创建一个名为`LightTweet`的新类，可以从一条推文中构建出来：

```java
package masterSpringMvc.search;

import org.springframework.social.twitter.api.Tweet;
import org.springframework.social.twitter.api.TwitterProfile;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;

public class LightTweet {
    private String profileImageUrl;
    private String user;
    private String text;
    private LocalDateTime date;
    private String lang;
    private Integer retweetCount;

    public LightTweet(String text) {
        this.text = text;
    }

    public static LightTweet ofTweet(Tweet tweet) {
        LightTweet lightTweet = new LightTweet(tweet.getText());
        Date createdAt = tweet.getCreatedAt();
        if (createdAt != null) {
            lightTweet.date = LocalDateTime.ofInstant(createdAt.toInstant(), ZoneId.systemDefault());
        }
        TwitterProfile tweetUser = tweet.getUser();
        if (tweetUser != null) {
            lightTweet.user = tweetUser.getName();
            lightTweet.profileImageUrl = tweetUser.getProfileImageUrl();
        }
        lightTweet.lang = tweet.getLanguageCode();
        lightTweet.retweetCount = tweet.getRetweetCount();
        return lightTweet;
    }

  // don't forget to generate getters
  // They are used by Jackson to serialize objects
}
```

现在我们需要让我们的`SearchService`类返回`LightTweets`类而不是 tweets：

```java
    public List<LightTweet> search(String searchType, List<String> keywords) {
        List<SearchParameters> searches = keywords.stream()
                .map(taste -> createSearchParam(searchType, taste))
                .collect(Collectors.toList());

        List<LightTweet> results = searches.stream()
                .map(params -> twitter.searchOperations().search(params))
                .flatMap(searchResults -> searchResults.getTweets().stream())
                .map(LightTweet::ofTweet)
                .collect(Collectors.toList());

        return results;
    }
```

这将影响`SearchApiController`类的返回类型，以及`SearchController`类中的 tweets 模型属性。在这两个类中进行必要的修改。

我们还需要更改`resultPage.html`文件的代码，因为一些属性已更改（我们不再有嵌套的`user`属性）：

```java
<ul class="collection">
    <li class="collection-item avatar" th:each="tweet : ${tweets}">
        <img th:src="img/strong>}" alt="" class="circle"/>
        <span class="title" th:text="${tweet.user}">Username</span>

        <p th:text="${tweet.text}">Tweet message</p>
    </li>
</ul>
```

我们快要完成了。如果重新启动应用程序并转到`http://localhost:8080/api/search/mixed;keywords=springFramework`，您会发现日期格式不是我们期望的那个：

![自定义 JSON 输出](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00964.jpeg)

这是因为 Jackson 没有内置对 JSR-310 日期的支持。幸运的是，这很容易解决。只需将以下库添加到 build.gradle 文件中的依赖项中：

```java
compile 'com.fasterxml.jackson.datatype:jackson-datatype-jsr310'
```

这确实改变了日期格式，但现在它输出的是一个数组而不是格式化的日期。

要更改这一点，我们需要了解库做了什么。它包括一个名为 JSR-310 Module 的新 Jackson 模块。Jackson 模块是一个扩展点，用于自定义序列化和反序列化。这个模块将由 Spring Boot 在启动时自动注册到 JacksonAutoConfiguration 类中，该类将创建一个默认的 Jackson ObjectMapper 方法，并支持众所周知的模块。

我们可以看到前一个模块为 JSR-310 中定义的所有新类添加了一堆序列化器和反序列化器。这将尝试将每个日期转换为 ISO 格式，如果可能的话。请参阅[`github.com/FasterXML/jackson-datatype-jsr310`](https://github.com/FasterXML/jackson-datatype-jsr310)。

例如，如果我们仔细看 LocalDateTimeSerializer，我们会发现它实际上有两种模式，并且可以使用称为 WRITE_DATES_AS_TIMESTAMPS 的序列化特性在两种模式之间切换。

要定义此属性，我们需要自定义 Spring 的默认对象映射器。从自动配置中可以看出，Spring MVC 提供了一个实用类来创建我们可以使用的 ObjectMapper 方法。将以下 bean 添加到您的 WebConfiguration 类中：

```java
@Bean
@Primary
public ObjectMapper objectMapper(Jackson2ObjectMapperBuilder builder) {
   ObjectMapper objectMapper = builder.createXmlMapper(false).build();
   objectMapper.configure(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false);
   return objectMapper;
}
```

这次，我们完成了，日期已经格式化正确，如您在这里所见：

![自定义 JSON 输出](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00965.jpeg)

# 用户管理 API

我们的搜索 API 非常好，但让我们做一些更有趣的事情。像许多 Web 应用程序一样，我们将需要一个用户管理模块来识别我们的用户。为此，我们将创建一个新的 user 包。在此包中，我们将添加一个模型类，如下所示：

```java
package masterSpringMvc.user;

import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;

public class User {
    private String twitterHandle;
    private String email;
    private LocalDate birthDate;
    private List<String> tastes = new ArrayList<>();

    // Getters and setters for all fields
}
```

由于我们暂时不想使用数据库，我们将在同一个包中创建一个 UserRepository 类，由一个简单的 Map 支持：

```java
package masterSpringMvc.user;

import org.springframework.stereotype.Repository;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Repository
public class UserRepository {
    private final Map<String, User> userMap = new ConcurrentHashMap<>();

    public User save(String email, User user) {
        user.setEmail(email);
        return userMap.put(email, user);
    }

    public User save(User user) {
        return save(user.getEmail(), user);
    }

    public User findOne(String email) {
        return userMap.get(email);
    }

    public List<User> findAll() {
        return new ArrayList<>(userMap.values());
    }

    public void delete(String email) {
        userMap.remove(email);
    }

    public boolean exists(String email) {
        return userMap.containsKey(email);
    }
}
```

最后，在 user.api 包中，我们将创建一个非常天真的控制器实现：

```java
package masterSpringMvc.user.api;

import masterSpringMvc.user.User;
import masterSpringMvc.user.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api")
public class UserApiController {

    private UserRepository userRepository;

    @Autowired
    public UserApiController(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @RequestMapping(value = "/users", method = RequestMethod.GET)
    public List<User> findAll() {
        return userRepository.findAll();
    }

    @RequestMapping(value = "/users", method = RequestMethod.POST)
    public User createUser(@RequestBody User user) {
        return userRepository.save(user);
    }

    @RequestMapping(value = "/user/{email}", method = RequestMethod.PUT)
    public User updateUser(@PathVariable String email, @RequestBody User user) {
        return userRepository.save(email, user);
    }

    @RequestMapping(value = "/user/{email}", method = RequestMethod.DELETE)
    public void deleteUser(@PathVariable String email) {
        userRepository.delete(email);
    }
}
```

我们使用 RESTful 存储库实现了所有经典的 CRUD 操作，使用用户的电子邮件地址作为唯一标识符。

在这种情况下，您将很快面临问题，因为 Spring 会删除点后面找到的内容。解决方案与我们在 URL 映射中使用的支持 URL 中的分号的解决方案非常相似，该解决方案在第三章中有所介绍，*文件上传和错误处理*。

在我们已经在 WebConfiguration 类中定义的 configurePathMatch（）方法中添加 useRegisteredSuffixPatternMatch 属性，该属性设置为 false：

```java
@Override
public void configurePathMatch(PathMatchConfigurer configurer) {
    UrlPathHelper urlPathHelper = new UrlPathHelper();
    urlPathHelper.setRemoveSemicolonContent(false);
    configurer.setUrlPathHelper(urlPathHelper);
    configurer.setUseRegisteredSuffixPatternMatch(true);
}
```

现在我们已经有了 API，可以开始与之交互了。

以下是一些使用 httpie 的示例命令：

```java

~ $ http get http://localhost:8080/api/users
HTTP/1.1 200 OK
Content-Type: application/json;charset=UTF-8
Date: Mon, 20 Apr 2015 00:01:08 GMT
Server: Apache-Coyote/1.1
Transfer-Encoding: chunked

[]

~ $ http post http://localhost:8080/api/users email=geo@springmvc.com birthDate=2011-12-12 tastes:='["spring"]'
HTTP/1.1 200 OK
Content-Length: 0
Date: Mon, 20 Apr 2015 00:02:07 GMT
Server: Apache-Coyote/1.1

~ $ http get http://localhost:8080/api/users
HTTP/1.1 200 OK
Content-Type: application/json;charset=UTF-8
Date: Mon, 20 Apr 2015 00:02:13 GMT
Server: Apache-Coyote/1.1
Transfer-Encoding: chunked

[
 {
 "birthDate": "2011-12-12",
 "email": "geo@springmvc.com",
 "tastes": [
 "spring"
 ],
 "twitterHandle": null
 }
]

~ $ http delete http://localhost:8080/api/user/geo@springmvc.com
HTTP/1.1 200 OK
Content-Length: 0
Date: Mon, 20 Apr 2015 00:02:42 GMT
Server: Apache-Coyote/1.1

~ $ http get http://localhost:8080/api/users
HTTP/1.1 200 OK
Content-Type: application/json;charset=UTF-8
Date: Mon, 20 Apr 2015 00:02:46 GMT
Server: Apache-Coyote/1.1
Transfer-Encoding: chunked

[]

```

这很好，但不够好。状态码还没有处理。我们需要更多的 RESTfulness 来爬上 Richardson 阶梯。

# 状态码和异常处理

我们要做的第一件事是正确处理响应状态。默认情况下，Spring 会自动处理一些状态：

+   `500 Server Error`：表示处理请求时发生异常。

+   `405 Method not Supported`：当在现有处理程序上使用不正确的方法时出现。

+   `404 Not Found`：当处理程序不存在时出现。

+   `400 Bad Request`：表示请求体或参数与服务器的期望不匹配。

+   `200 OK`：对于任何没有错误处理的请求抛出。

使用 Spring MVC，有两种返回状态码的方式：

+   从 REST 控制器返回 ResponseEntity 类

+   抛出一个异常，将在专用处理程序中捕获

## 使用 ResponseEntity 的状态码

HTTP 协议规定我们在创建新用户时应返回`201 Created`状态。在我们的 API 中，可以使用`POST`方法实现这一点。在处理不存在的实体时，我们还需要抛出一些 404 错误。

Spring MVC 有一个将 HTTP 状态与响应实体关联起来的类，称为`ResponseEntity`。让我们更新我们的`UserApiController`类来处理错误代码：

```java
package masterSpringMvc.user.api;

import masterSpringMvc.user.User;
import masterSpringMvc.user.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api")
public class UserApiController {

    private UserRepository userRepository;

    @Autowired
    public UserApiController(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @RequestMapping(value = "/users", method = RequestMethod.GET)
    public List<User> findAll() {
        return userRepository.findAll();
    }

    @RequestMapping(value = "/users", method = RequestMethod.POST)
    public ResponseEntity<User> createUser(@RequestBody User user) {
        HttpStatus status = HttpStatus.OK;
        if (!userRepository.exists(user.getEmail())) {
            status = HttpStatus.CREATED;
        }
        User saved = userRepository.save(user);
        return new ResponseEntity<>(saved, status);
    }

    @RequestMapping(value = "/user/{email}", method = RequestMethod.PUT)
    public ResponseEntity<User> updateUser(@PathVariable String email, @RequestBody User user) {
        if (!userRepository.exists(user.getEmail())) {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
        User saved = userRepository.save(email, user);
        return new ResponseEntity<>(saved, HttpStatus.CREATED);
    }

    @RequestMapping(value = "/user/{email}", method = RequestMethod.DELETE)
    public ResponseEntity<User> deleteUser(@PathVariable String email) {
        if (!userRepository.exists(email)) {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
        userRepository.delete(email);
        return new ResponseEntity<>(HttpStatus.OK);
    }
}
```

您可以看到我们朝着第一级 RESTful 发展，但涉及了大量样板代码。

## 异常状态代码

在我们的 API 中处理错误的另一种方法是抛出异常。有两种方法可以将异常映射到 Spring MVC 中：

+   在类级别使用`@ExceptionHandler`，就像我们在第三章中的上传控制器中对`IOException`所做的那样，*文件上传和错误处理*

+   使用`@ControllerAdvice`来捕获所有控制器抛出的全局异常或一部分控制器抛出的异常

这两个选项可以帮助您做出一些面向业务的决策，并在应用程序中定义一套实践。

要将这些处理程序与 HTTP 状态代码关联起来，我们可以在注释方法中注入响应，并使用`HttpServletResponse.sendError()`方法，或者只需在方法上注释`@ResponseStatus`注解。

我们将定义自己的异常，`EntityNotFoundException`。当用户正在处理的实体找不到时，我们的业务存储库将抛出此异常。这将有助于简化 API 代码。

这是异常的代码。我们可以将其放在一个名为`error`的新包中：

```java
package masterSpringMvc.error;

public class EntityNotFoundException extends Exception {
    public EntityNotFoundException(String message) {
        super(message);
    }

    public EntityNotFoundException(String message, Throwable cause) {
        super(message, cause);
    }
}
```

我们的存储库现在将在各个位置抛出异常。我们还将区分保存和更新用户：

```java
package masterSpringMvc.user;

import masterSpringMvc.error.EntityNotFoundException;
import org.springframework.stereotype.Repository;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Repository
public class UserRepository {
    private final Map<String, User> userMap = new ConcurrentHashMap<>();

    public User update(String email, User user) throws EntityNotFoundException {
        if (!exists(email)) {
            throw new EntityNotFoundException("User " + email + " cannot be found");
        }
        user.setEmail(email);
        return userMap.put(email, user);
    }

    public User save(User user) {
        return userMap.put(user.getEmail(), user);
    }

    public User findOne(String email) throws EntityNotFoundException {
        if (!exists(email)) {
            throw new EntityNotFoundException("User " + email + " cannot be found");
        }
        return userMap.get(email);
    }

    public List<User> findAll() {
        return new ArrayList<>(userMap.values());
    }

    public void delete(String email) throws EntityNotFoundException {
        if (!exists(email)) {
            throw new EntityNotFoundException("User " + email + " cannot be found");
        }
        userMap.remove(email);
    }

    public boolean exists(String email) {
        return userMap.containsKey(email);
    }
}
```

我们的控制器变得更简单，因为它不必处理 404 状态。我们现在从我们的控制器方法中抛出`EntityNotFound`异常：

```java
package masterSpringMvc.user.api;

import masterSpringMvc.error.EntityNotFoundException;
import masterSpringMvc.user.User;
import masterSpringMvc.user.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api")
public class UserApiController {

    private UserRepository userRepository;

    @Autowired
    public UserApiController(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @RequestMapping(value = "/users", method = RequestMethod.GET)
    public List<User> findAll() {
        return userRepository.findAll();
    }

    @RequestMapping(value = "/users", method = RequestMethod.POST)
    public ResponseEntity<User> createUser(@RequestBody User user) {
        HttpStatus status = HttpStatus.OK;
        if (!userRepository.exists(user.getEmail())) {
            status = HttpStatus.CREATED;
        }
        User saved = userRepository.save(user);
        return new ResponseEntity<>(saved, status);
    }

    @RequestMapping(value = "/user/{email}", method = RequestMethod.PUT)
    public ResponseEntity<User> updateUser(@PathVariable String email, @RequestBody User user) throws EntityNotFoundException {
        User saved = userRepository.update(email, user);
        return new ResponseEntity<>(saved, HttpStatus.CREATED);
    }

    @RequestMapping(value = "/user/{email}", method = RequestMethod.DELETE)
    public ResponseEntity<User> deleteUser(@PathVariable String email) throws EntityNotFoundException {
        userRepository.delete(email);
        return new ResponseEntity<>(HttpStatus.OK);
    }
}
```

如果我们不处理此异常，Spring 将默认抛出 500 错误。为了处理它，我们将在错误包中创建一个小类，就在我们的`EntityNotFoundException`类旁边。它将被称为`EntityNotFoundMapper`类，并负责处理异常：

```java
package masterSpringMvc.error;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;

@ControllerAdvice
public class EntityNotFoundMapper {

    @ExceptionHandler(EntityNotFoundException.class)
    @ResponseStatus(value = HttpStatus.NOT_FOUND, reason = "Entity could not be found")
    public void handleNotFound() {
    }
}
```

@ControllerAdvice`注解允许我们通过对 bean 进行注解来为一组控制器添加一些行为。这些控制器建议可以处理异常，还可以使用`@ModelAttribute`声明模型属性或使用`@InitBinder`声明验证器策略。

通过我们刚刚编写的代码，我们可以在一个地方处理我们的控制器抛出的所有`EntityNotFoundException`类，并将其与 404 状态关联起来。这样，我们可以抽象这个概念，并确保我们的应用程序在所有控制器中一致地处理它。

我们不打算在我们的 API 中处理超链接。相反，我鼓励您查看 Spring HATEOAS 和 Spring Data REST，它们提供了非常优雅的解决方案，使您的资源更易发现。

# Swagger 文档

Swagger 是一个非常棒的项目，它可以让您在 HTML5 网页中记录和与 API 进行交互。以下截图展示了 API 文档：

![Swagger 文档](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00966.jpeg)

Swagger 以前很庞大（用 Scala 编写）并且在 Spring 设置中有些复杂。自 2.0 版本以来，该库已经被重写，一个名为`spring-fox`的非常整洁的项目将允许轻松集成。

### 注意

`spring-fox`，以前称为`swagger-springmvc`，已经存在三年多了，仍然是一个非常活跃的项目。

将以下依赖项添加到构建文件中：

```java
compile 'io.springfox:springfox-swagger2:2.1.2'
compile 'io.springfox:springfox-swagger-ui:2.1.2'
```

第一个将提供一个注解，以在您的应用程序中启用 Swagger，并使用注解描述您的资源。Swagger 然后将生成您的 API 的 JSON 表示。

第二个是一个 WebJar，其中包含通过 Web 客户端使用生成的 JSON 的静态资源。

现在您唯一需要做的就是将`@EnableSwagger2`注解添加到您的`WebConfiguration`类中：

```java
@Configuration
@EnableSwagger2
public class WebConfiguration extends WebMvcConfigurerAdapter {
 }
```

我们刚刚添加的`swagger-ui.jar`文件中包含了`META-INF/resources`中的 HTML 文件。

当您访问`http://localhost:8080/swagger-ui.html`时，Spring Boot 会自动提供它。

默认情况下，Springfox 将扫描整个类路径，并显示应用程序中声明的所有请求映射。

在我们的情况下，我们只想公开 API：

```java
@Bean
public Docket userApi() {
    return new Docket(DocumentationType.SWAGGER_2)
        .select()
        .paths(path -> path.startsWith("/api/"))
        .build();
}
```

Springfox 与`Docket`组合一起工作，您必须在配置类中定义它们作为 bean。它们是 RESTful 资源的逻辑分组。一个应用程序可以有很多。

查看文档（[`springfox.github.io/springfox`](http://springfox.github.io/springfox)）以查看所有可用的不同设置。

# 生成 XML

RESTful API 有时会以不同的媒体类型（JSON、XML 等）返回响应。负责选择正确媒体类型的机制在 Spring 中称为内容协商。

在 Spring MVC 中，默认情况下，`ContentNegotiatingViewResolver` bean 将负责根据应用程序中定义的内容协商策略来解析正确的内容。

您可以查看`ContentNegotiationManagerFactoryBean`，了解这些策略在 Spring MVC 中是如何应用的。

内容类型可以通过以下策略解析：

+   根据客户端发送的`Accept`头部

+   使用参数，如`?format=json`

+   使用路径扩展，如`/myResource.json`或`/myResource.xml`

您可以通过覆盖`WebMvcConfigurerAdapter`类的`configureContentNegotiation()`方法来自定义这些策略在 Spring 配置中的使用。

默认情况下，Spring 将使用`Accept`头部和路径扩展。

要在 Spring Boot 中启用 XML 序列化，您可以将以下依赖项添加到类路径中：

```java
compile 'com.fasterxml.jackson.dataformat:jackson-dataformat-xml'
```

如果您使用浏览器浏览您的 API 并转到`http://localhost:8080/api/users`，您将看到以下结果为 XML：

![生成 XML](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00967.jpeg)

这是因为您的浏览器通常不会请求 JSON，但 XML 在 HTML 之后。如下截图所示：

![生成 XML](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00968.jpeg)

要获取 JSON，您可以转到`http://localhost:8080/api/users.json`，或者使用 Postman 或 httpie 发送适当的`Accept`头部。

# 检查点

在本章中，我们添加了一个搜索`ApiController`类。因为 Twitter API 返回的推文不适合我们的使用，我们引入了一个`LightTweet`类来将它们转换为更友好的格式。

我们还开发了一个用户 API。`User`类是模型。用户通过`UserRepository`类存储和检索，`UserApiController`类公开 HTTP 端点以执行用户的 CRUD 操作。我们还添加了一个通用异常和一个将异常与 HTTP 状态关联的映射器。

在配置中，我们添加了一个文档化我们的 API 的 bean，感谢 Swagger，并且我们自定义了 JSR-310 日期的序列化。我们的代码库应该如下所示：

![检查点](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00969.jpeg)

# 总结

在本章中，我们已经看到如何使用 Spring MVC 创建 RESTful API。这种后端在性能和维护方面都有很大的好处，当与 JavaScript MVC 框架（如 Backbone、Angular JS 或 React.js）配合使用时，效果更佳。

我们看到了如何正确处理错误和异常，并学会了如何利用 HTTP 状态来创建更好的 API。

最后，我们使用 Swagger 添加了自动文档，并增加了生成 XML 和 JSON 的能力。

在下一章中，我们将学习如何保护我们的应用程序，并使用 Twitter API 注册我们的用户。



# 第二十一章：保护您的应用程序

在本章中，我们将学习如何保护我们的 Web 应用程序，以及如何应对现代分布式 Web 应用程序的安全挑战。

本章将分为五个部分：

+   首先，我们将在几分钟内设置基本的 HTTP 认证

+   然后，我们将为网页设计基于表单的认证，保留 RESTful API 的基本认证

+   我们将允许用户通过 Twitter OAuth API 进行注册

+   然后，我们将利用 Spring Session 来确保我们的应用程序可以使用分布式会话机制进行扩展

+   最后，我们将配置 Tomcat 使用 SSL 进行安全连接

# 基本认证

最简单的身份验证机制是基本认证（[`en.wikipedia.org/wiki/Basic_access_authentication`](http://en.wikipedia.org/wiki/Basic_access_authentication)）。简而言之，如果没有用户名和密码，我们的页面将无法访问。

我们的服务器将通过发送“401 未经授权”的 HTTP 状态码并生成`WWW-Authenticate`头来指示我们的资源受到保护。

为了成功通过安全检查，客户端必须发送一个包含`Basic`值后面跟着`user:password`字符串的 base 64 编码的`Authorization`头。浏览器窗口将提示用户输入用户名和密码，如果认证成功，用户将获得对受保护页面的访问权限。

让我们将 Spring Security 添加到我们的依赖项中：

```java
compile 'org.springframework.boot:spring-boot-starter-security'
```

重新启动应用程序并导航到应用程序中的任何 URL。系统将提示您输入用户名和密码：

![基本认证](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00970.jpeg)

如果您未能进行身份验证，您将看到抛出`401`错误。默认用户名是`user`。身份验证的正确密码将在每次应用程序启动时随机生成，并显示在服务器日志中：

```java

Using default security password: 13212bb6-8583-4080-b790-103408c93115

```

默认情况下，Spring Security 保护除`/css/`、`/js/`、`/images/`和`**/favicon.ico`等少数经典路由之外的所有资源。

如果您希望配置默认凭据，可以将以下属性添加到`application.properties`文件中：

```java
security.user.name=admin
security.user.password=secret
```

## 授权用户

在我们的应用程序中只有一个用户不允许进行细粒度的安全控制。如果我们想要更多地控制用户凭据，我们可以在`config`包中添加以下`SecurityConfiguration`类：

```java
package masterSpringMvc.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
@EnableGlobalMethodSecurity(securedEnabled = true)
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Autowired
    public void configureAuth(AuthenticationManagerBuilder auth)
            throws Exception {
        auth.inMemoryAuthentication()
                .withUser("user").password("user").roles("USER").and()
                .withUser("admin").password("admin").roles("USER", "ADMIN");
    }
}
```

这段代码将设置一个包含我们应用程序用户及其角色的内存系统。它将覆盖先前在应用程序属性中定义的安全名称和密码。

`@EnableGlobalMethodSecurity`注释将允许我们对应用程序的方法和类进行注释，以定义它们的安全级别。

例如，假设我们的应用程序只有管理员才能访问用户 API。在这种情况下，我们只需在资源中添加`@Secured`注释，以允许仅对 ADMIN 角色进行访问：

```java
@RestController
@RequestMapping("/api")
@Secured("ROLE_ADMIN")
public class UserApiController {
  // ... code omitted
}
```

我们可以使用 httpie 轻松测试，通过使用`-a`开关使用基本认证和`-p=h`开关，只显示响应头。

让我们尝试一下没有管理员配置文件的用户：

```java

> http GET 'http://localhost:8080/api/users' -a user:user -p=h
HTTP/1.1 403 Forbidden
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
Content-Type: application/json;charset=UTF-8
Date: Sat, 23 May 2015 17:40:09 GMT
Expires: 0
Pragma: no-cache
Server: Apache-Coyote/1.1
Set-Cookie: JSESSIONID=2D4761C092EDE9A4DB91FA1CAA16C59B; Path=/; HttpOnly
Transfer-Encoding: chunked
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block

```

现在，使用管理员：

```java

> http GET 'http://localhost:8080/api/users' -a admin:admin -p=h
HTTP/1.1 200 OK
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
Content-Type: application/json;charset=UTF-8
Date: Sat, 23 May 2015 17:42:58 GMT
Expires: 0
Pragma: no-cache
Server: Apache-Coyote/1.1
Set-Cookie: JSESSIONID=CE7A9BF903A25A7A8BAD7D4C30E59360; Path=/; HttpOnly
Transfer-Encoding: chunked
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block

```

您还会注意到 Spring Security 自动添加了一些常见的安全头：

+   `Cache Control`：这可以防止用户缓存受保护的资源

+   `X-XSS-Protection`：这告诉浏览器阻止看起来像 CSS 的东西

+   `X-Frame-Options`：这将禁止我们的网站嵌入到 IFrame 中

+   `X-Content-Type-Options`：这可以防止浏览器猜测用于伪造 XSS 攻击的恶意资源的 MIME 类型

### 注意

这些头的全面列表可在[`docs.spring.io/spring-security/site/docs/current/reference/htmlsingle/#headers`](http://docs.spring.io/spring-security/site/docs/current/reference/htmlsingle/#headers)上找到。

## 授权的 URL

注释我们的控制器非常容易，但并不总是最可行的选择。有时，我们只想完全控制我们的授权。

删除`@Secured`注释；我们将想出更好的办法。

让我们看看通过修改`SecurityConfiguration`类，Spring Security 允许我们做什么：

```java
@Configuration
@EnableGlobalMethodSecurity(securedEnabled = true)
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Autowired
    public void configureAuth(AuthenticationManagerBuilder auth)
        throws Exception {
        auth.inMemoryAuthentication()
            .withUser("user").password("user").roles("USER").and()
            .withUser("admin").password("admin").roles("USER", "ADMIN");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .httpBasic()
            .and()
            .csrf().disable()
            .authorizeRequests()
            .antMatchers("/login", "/logout").permitAll()
            .antMatchers(HttpMethod.GET, "/api/**").hasRole("USER")
            .antMatchers(HttpMethod.POST, "/api/**").hasRole("ADMIN")
            .antMatchers(HttpMethod.PUT, "/api/**").hasRole("ADMIN")
            .antMatchers(HttpMethod.DELETE, "/api/**").hasRole("ADMIN")
            .anyRequest().authenticated();
    }
}
```

在前面的代码示例中，我们使用 Spring Security 的流畅 API 配置了应用程序的安全策略。

通过调用与不同安全问题相关的方法并与`and()`方法链接，此 API 允许我们全局配置 Spring Security。

我们刚刚定义的是基本身份验证，没有 CSRF 保护。所有用户将允许在`/login`和`/logout`上的请求。对 API 的`GET`请求只允许具有`USER`角色的用户，而对 API 的`POST`、`PUT`和`DELETE`请求只对具有 ADMIN 角色的用户可访问。最后，每个其他请求将需要任何角色的身份验证。

CSRF 代表**跨站点请求伪造**，指的是一种攻击，恶意网站会在其网站上显示一个表单，并在您的网站上发布表单数据。如果您网站的用户没有注销，`POST`请求将保留用户的 cookie，因此将被授权。

CSRF 保护将生成短暂的令牌，这些令牌将与表单数据一起发布。我们将在下一节中看到如何正确启用它；现在，让我们先禁用它。有关更多详细信息，请参见[`docs.spring.io/spring-security/site/docs/current/reference/htmlsingle/#csrf`](http://docs.spring.io/spring-security/site/docs/current/reference/htmlsingle/#csrf)。

### 注意

要了解有关授权请求 API 的更多信息，请查看[`docs.spring.io/spring-security/site/docs/current/reference/htmlsingle/#authorize-requests`](http://docs.spring.io/spring-security/site/docs/current/reference/htmlsingle/#authorize-requests)。

## Thymeleaf 安全标签

有时，您需要显示来自身份验证层的数据，例如用户的名称和角色，或根据用户的权限隐藏和显示网页的一部分。`thymeleaf-extras-springsecurity`模块将允许我们这样做。

将以下依赖项添加到您的`build.gradle`文件中：

```java
compile 'org.thymeleaf.extras:thymeleaf-extras-springsecurity3'
```

使用此库，我们可以在`layout/default.html`的导航栏下添加一个小块，以显示已登录的用户：

```java
<!DOCTYPE html>
<html 

      >
<head>
  <!-- content trimmed -->
</head>
<body>

<!-- content trimmed -->
<nav>
    <div class="nav-wrapper indigo">
        <ul class="right">
        <!-- content trimmed -->
        </ul>
    </div>
</nav>
<div>
 You are logged as <b sec:authentication="name" /> with roles <span sec:authentication="authorities" />
 -
 <form th:action="@{/logout}" method="post" style="display: inline-block">
 <input type="submit" value="Sign Out" />
 </form>
 <hr/>
</div>

<section layout:fragment="content">
    <p>Page content goes here</p>
</section>

<!-- content trimmed -->
</body>
</html>
```

请注意 HTML 声明中的新命名空间和`sec:authentication`属性。它允许访问`org.springframework.security.core.Authentication`对象的属性，该对象表示当前登录的用户，如下截图所示：

![Thymeleaf 安全标签](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00971.jpeg)

暂时不要点击注销链接，因为它与基本身份验证不兼容。我们将在下一部分使其工作。

`lib`标签还有一些其他标签，例如用于检查用户授权的标签：

```java
<div sec:authorize="hasRole('ROLE_ADMIN')">
    You are an administrator
</div>
```

### 注意

请参阅[`github.com/thymeleaf/thymeleaf-extras-springsecurity`](https://github.com/thymeleaf/thymeleaf-extras-springsecurity)上可用的文档，以了解有关该库的更多信息。

# 登录表单

基本身份验证对于我们的 RESTful API 很好，但我们更希望有一个由我们团队精心设计的登录页面，以改善网页体验。

Spring Security 允许我们定义尽可能多的`WebSecurityConfigurerAdapter`类。我们将把我们的`SecurityConfiguration`类分成两部分：

+   `ApiSecurityConfiguration`：这将首先进行配置。这将使用基本身份验证保护 RESTful 端点。

+   `WebSecurityConfiguration`：然后将为我们应用程序的其余部分配置登录表单。

您可以删除或重命名`SecurityConfiguration`，并创建`ApiSecurityConfiguration`代替：

```java
@Configuration
@Order(1)
public class ApiSecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Autowired
    public void configureAuth(AuthenticationManagerBuilder auth)
        throws Exception {
        auth.inMemoryAuthentication()
            .withUser("user").password("user").roles("USER").and()
            .withUser("admin").password("admin").roles("USER", "ADMIN");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .antMatcher("/api/**")
            .httpBasic().and()
            .csrf().disable()
            .authorizeRequests()
            .antMatchers(HttpMethod.GET).hasRole("USER")
            .antMatchers(HttpMethod.POST).hasRole("ADMIN")
            .antMatchers(HttpMethod.PUT).hasRole("ADMIN")
            .antMatchers(HttpMethod.DELETE).hasRole("ADMIN")
            .anyRequest().authenticated();
    }
}
```

请注意`@Order(1)`注解，这将确保在执行其他配置之前执行此配置。然后，创建第二个用于 Web 的配置，称为`WebSecurityConfiguration`：

```java
package masterSpringMvc.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
public class WebSecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .formLogin()
                .defaultSuccessUrl("/profile")
                .and()
                .logout().logoutSuccessUrl("/login")
                .and()
                .authorizeRequests()
                .antMatchers("/webjars/**", "/login").permitAll()
                .anyRequest().authenticated();
    }
}
```

此代码的结果是，与`/api/**`匹配的任何内容都将受到基本身份验证的保护，而不受 CSRF 保护。然后，将加载第二个配置。它将保护其他所有内容。应用程序的这一部分中的所有内容都需要客户端进行身份验证，除了 WebJars 上的请求和登录页面上的请求（这将避免重定向循环）。

如果未经身份验证的用户尝试访问受保护的资源，他们将自动重定向到登录页面。

默认情况下，登录 URL 是`GET /login`。默认登录将通过`POST /login`请求发布，其中将包含三个值：用户名（`username`）、密码（`password`）和 CSRF 令牌（`_csrf`）。如果登录不成功，用户将被重定向到`/login?error`。默认注销页面是一个带有 CSRF 令牌的`POST /logout`请求。

现在，如果您尝试在应用程序上导航，此表单将自动生成！

如果您已经从以前的尝试中登录，请关闭浏览器；这将清除会话。

![登录表单](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00972.jpeg)

我们现在可以登录和退出应用程序了！

这很可爱，但我们可以用很少的努力做得更好。首先，我们将在`WebSecurityConfiguration`类中定义一个`/login`登录页面：

```java
@Override
protected void configure(HttpSecurity http) throws Exception {
    http
        .formLogin()
        .loginPage("/login") // <= custom login page
        .defaultSuccessUrl("/profile")
        // the rest of the configuration stays the same
}
```

这将让我们创建自己的登录页面。为此，我们需要一个非常简单的控制器来处理`GET login`请求。您可以在`authentication`包中创建一个：

```java
package masterSpringMvc.authentication;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class LoginController {

    @RequestMapping("/login")
    public String authenticate() {
        return "login";
    }
}
```

这将触发位于模板目录中的`login.html`页面的显示。让我们创建它：

```java
<!DOCTYPE HTML>
<html 

      layout:decorator="layout/default">
<head>
    <title>Login</title>
</head>
<body>
<div class="section no-pad-bot" layout:fragment="content">
    <div class="container">

        <h2 class="header center orange-text">Login</h2>

        <div class="row">
            <div id="errorMessage" class="card-panel red lighten-2" th:if="${param.error}">
                <span class="card-title">Invalid user name or password</span>
            </div>

            <form class="col s12" action="/login" method="post">
                <div class="row">
                    <div class="input-field col s12">
                        <input id="username" name="username" type="text" class="validate"/>
                        <label for="username">Username</label>
                    </div>
                </div>
                <div class="row">
                    <div class="input-field col s12">
                        <input id="password" name="password" type="password" class="validate"/>
                        <label for="password">Password</label>
                    </div>
                </div>
                <div class="row center">
                    <button class="btn waves-effect waves-light" type="submit" name="action">Submit
                        <i class="mdi-content-send right"></i>
                    </button>
                </div>
                <input type="hidden" th:name="${_csrf.parameterName}" th:value="${_csrf.token}"/>
            </form>
        </div>
    </div>
</div>
</body>
</html>
```

请注意，我们处理错误消息，并发布 CSRF 令牌。我们还使用默认的用户名和密码输入名称，但如果需要，这些是可配置的。结果看起来已经好多了！

![登录表单](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00973.jpeg)

您可以立即看到，Spring Security 默认为所有非经过身份验证的用户分配匿名凭据。

我们不应该向匿名用户显示登出按钮，因此我们可以将相应的 HTML 部分包装在`sec:authorize="isAuthenticated()"`中，只显示给经过身份验证的用户，如下所示：

```java
<div sec:authorize="isAuthenticated()">
    You are logged as <b sec:authentication="name"/> with roles <span sec:authentication="authorities"/>
    -
    <form th:action="@{/logout}" method="post" style="display: inline-block">
        <input type="submit" value="Sign Out"/>
    </form>
    <hr/>
</div>
```

# Twitter 身份验证

我们的应用程序与 Twitter 强烈集成，因此允许我们通过 Twitter 进行身份验证似乎是合乎逻辑的。

在继续之前，请确保您已在 Twitter 应用程序上启用了 Twitter 登录（[`apps.twitter.com`](https://apps.twitter.com)）：

![Twitter 身份验证](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00974.jpeg)

## 设置社交身份验证

Spring social 通过 OAuth 提供程序（如 Twitter）实现身份验证，通过登录/注册场景。它将拦截`/signin/twitter`上的`POST`请求。如果用户未知于`UsersConnectionRepository`接口，则将调用`signup`端点。这将允许我们采取必要措施在我们的系统上注册用户，也许要求他们提供额外的细节。

让我们开始工作。我们需要做的第一件事是将`signin/**`和`/signup` URL 添加为公开可用的资源。让我们修改我们的`WebSecurityConfiguration`类，更改`permitAll`行：

```java
.antMatchers("/webjars/**", "/login", "/signin/**", "/signup").permitAll()
```

为了启用登录/注册场景，我们还需要一个`SignInAdapter`接口，一个简单的监听器，当已知用户再次登录时将被调用。

我们可以在我们的`LoginController`旁边创建一个`AuthenticatingSignInAdapter`类。

```java
package masterSpringMvc.authentication;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.social.connect.Connection;
import org.springframework.social.connect.UserProfile;
import org.springframework.social.connect.web.SignInAdapter;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.NativeWebRequest;

@Component
public class AuthenticatingSignInAdapter implements SignInAdapter {

    public static void authenticate(Connection<?> connection) {
        UserProfile userProfile = connection.fetchUserProfile();
        String username = userProfile.getUsername();
        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(username, null, null);
        SecurityContextHolder.getContext().setAuthentication(authentication);
        System.out.println(String.format("User %s %s connected.", userProfile.getFirstName(), userProfile.getLastName()));
    }

    @Override
    public String signIn(String userId, Connection<?> connection, NativeWebRequest request) {
        authenticate(connection);
        return null;
    }
}
```

正如您所看到的，此处理程序在完美的时间调用，允许用户使用 Spring Security 进行身份验证。我们马上就会回到这一点。现在，我们需要在同一个包中定义我们的`SignupController`类，负责首次访问用户：

```java
package masterSpringMvc.authentication;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.social.connect.Connection;
import org.springframework.social.connect.ConnectionFactoryLocator;
import org.springframework.social.connect.UsersConnectionRepository;
import org.springframework.social.connect.web.ProviderSignInUtils;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.context.request.WebRequest;

@Controller
public class SignupController {
    private final ProviderSignInUtils signInUtils;

    @Autowired
    public SignupController(ConnectionFactoryLocator connectionFactoryLocator, UsersConnectionRepository connectionRepository) {
        signInUtils = new ProviderSignInUtils(connectionFactoryLocator, connectionRepository);
    }

    @RequestMapping(value = "/signup")
    public String signup(WebRequest request) {
        Connection<?> connection = signInUtils.getConnectionFromSession(request);
        if (connection != null) {
            AuthenticatingSignInAdapter.authenticate(connection);
            signInUtils.doPostSignUp(connection.getDisplayName(), request);
        }
        return "redirect:/profile";
    }
}
```

首先，此控制器从会话中检索当前连接。然后，它通过与之前相同的方法对用户进行身份验证。最后，它将触发`doPostSignUp`事件，这将允许 Spring Social 在我们之前提到的`UsersConnectionRepository`接口中存储与我们的用户相关的信息。

我们需要做的最后一件事是在我们的登录页面下方的前一个表单下面添加一个成功的“使用 Twitter 登录”按钮：

```java
<form th:action="@{/signin/twitter}" method="POST" class="center">
    <div class="row">
        <button class="btn indigo" name="twitterSignin" type="submit">Connect with Twitter
            <i class="mdi-social-group-add left"></i>
        </button>
    </div>
</form>
```

![设置社交身份验证](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00975.jpeg)

当用户点击**使用 Twitter 连接**按钮时，他们将被重定向到 Twitter 登录页面：

![设置社交身份验证](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00976.jpeg)

## 解释

代码不多，但要理解所有部分有点棘手。理解正在发生的事情的第一步是查看 Spring Boot 的`SocialWebAutoConfiguration`类。

在这个类中声明的`SocialAutoConfigurationAdapter`类包含以下 bean：

```java
@Bean
@ConditionalOnBean(SignInAdapter.class)
@ConditionalOnMissingBean(ProviderSignInController.class)
public ProviderSignInController signInController(
        ConnectionFactoryLocator factoryLocator,
        UsersConnectionRepository usersRepository, SignInAdapter signInAdapter) {
    ProviderSignInController controller = new ProviderSignInController(
            factoryLocator, usersRepository, signInAdapter);
    if (!CollectionUtils.isEmpty(this.signInInterceptors)) {
 controller.setSignInInterceptors(this.signInInterceptors);
    }
    return controller;
}
```

如果在我们的配置中检测到一个`ProviderSignInController`类，那么`ProviderSignInController`类将自动设置。这个控制器是登录过程的基石。看一下它的功能（我只会总结重要的部分）：

+   它将处理我们的连接按钮的`POST /signin/{providerId}`

+   它将重定向用户到我们身份提供者的适当登录 URL

+   它将通过`GET /signin/{providerId}`从身份提供者接收到 OAuth 令牌

+   然后它将处理登录

+   如果在`UsersConnectionRepository`接口中找不到用户，它将使用`SessionStrategy`接口来存储待处理的登录请求，然后重定向到`signupUrl`页面

+   如果找到用户，则会调用`SignInAdapter`接口，并将用户重定向到`postSignupUrl`页面。

这个身份验证的两个重要组件是`UsersConnectionRepository`接口，负责从某种存储中存储和检索用户，以及`SessionStrategy`接口，它将临时存储用户连接，以便可以从`SignupController`类中检索到。

默认情况下，Spring Boot 为每个身份验证提供程序创建一个`InMemoryUsersConnectionRepository`接口，这意味着我们的用户连接数据将存储在内存中。如果重新启动服务器，用户将变为未知用户，并且将再次通过注册流程。

`ProviderSignInController`类默认使用`HttpSessionSessionStrategy`，它会将连接存储在 HTTP 会话中。我们在`SignupController`类中使用的`ProviderSignInUtils`类也默认使用这个策略。如果我们在多个服务器上分发我们的应用程序，这可能会有问题，因为会话可能不会在每台服务器上都可用。

通过为`ProviderSignInController`和`ProviderSignInUtils`类提供自定义的`SessionStrategy`接口，可以轻松地覆盖这些默认设置，以将数据存储在 HTTP 会话之外的其他位置。

同样，我们可以通过提供`UsersConnectionRepository`接口的另一个实现来为我们的用户连接数据使用另一种存储方式。

Spring Social 提供了一个`JdbcUsersConnectionRepository`接口，它会自动将经过身份验证的用户保存在数据库中的`UserConnection`表中。这本书不会对此进行详细介绍，但您应该可以通过将以下 bean 添加到配置中来轻松配置它：

```java
@Bean
@Primary
public UsersConnectionRepository getUsersConnectionRepository(
  DataSource dataSource, ConnectionFactoryLocator connectionFactoryLocator) {
    return new JdbcUsersConnectionRepository(
      dataSource, connectionFactoryLocator, Encryptors.noOpText());
}
```

### 注意

查看我的博客上的这篇文章[`geowarin.github.io/spring/2015/08/02/social-login-with-spring.html`](http://geowarin.github.io/spring/2015/08/02/social-login-with-spring.html)以获取更多详细信息。

# 分布式会话

正如我们在前面的部分中看到的，Spring Social 在几个时刻将东西存储在 HTTP 会话中。我们的用户配置文件也存储在会话中。这是一个经典的方法，可以在用户浏览网站时将东西保存在内存中。

然而，如果我们想要扩展我们的应用程序并将负载分布到多个后端服务器，这可能会带来麻烦。我们现在已经进入了云时代，第七章，“优化您的请求”将讨论将我们的应用程序部署到云端。

为了使我们的会话在分布式环境中工作，我们有几种选择：

+   我们可以使用粘性会话。这将确保特定用户始终被重定向到同一台服务器并保持其会话。这需要额外的部署配置，并不是特别优雅的方法。

+   重构我们的代码，将数据放入数据库而不是会话中。然后，如果我们将其与客户端发送的每个请求一起使用的 cookie 或令牌相关联，我们可以从数据库中加载用户的数据。

+   使用 Spring Session 项目透明地使用分布式数据库，如 Redis 作为底层会话提供程序。

在本章中，我们将看到如何设置第三种方法。设置起来非常容易，并且提供了惊人的好处，即可以在不影响应用程序功能的情况下关闭它。

我们需要做的第一件事是安装 Redis。在 Mac 上安装它，使用`brew`命令：

```java

brew install redis

```

对于其他平台，请按照[`redis.io/download`](http://redis.io/download)上的说明进行操作。

然后，您可以使用以下命令启动服务器：

```java

redis-server

```

将以下依赖项添加到您的`build.gradle`文件中：

```java
compile 'org.springframework.boot:spring-boot-starter-redis'
compile 'org.springframework.session:spring-session:1.0.1.RELEASE'
```

在`application.properties`旁边创建一个名为`application-redis.properties`的新配置文件：

```java
spring.redis.host=localhost
spring.redis.port=6379
```

Spring Boot 提供了一种方便的方式来将配置文件与配置文件关联。在这种情况下，只有在 Redis 配置文件处于活动状态时，才会加载`application-redis.properties`文件。

然后，在`config`包中创建一个`RedisConfig`类：

```java
package masterSpringMvc.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.session.data.redis.config.annotation.web.http.EnableRedisHttpSession;

@Configuration
@Profile("redis")
@EnableRedisHttpSession
public class RedisConfig {
}
```

正如您所看到的，此配置仅在`redis`配置文件处于活动状态时才会生效。

我们完成了！现在我们可以使用以下标志启动我们的应用程序：

```java

-Dspring.profiles.active=redis

```

您还可以使用`gradlew build`生成 JAR 文件，并使用以下命令启动它：

```java

java -Dserver.port=$PORT -Dspring.profiles.active=redis -jar app.jar

```

或者，您可以在 Bash 中使用 Gradle 启动它，如下所示：

```java

SPRING_PROFILES_ACTIVE=redis ./gradlew bootRun

```

您还可以简单地将其设置为 IDE 运行配置中的 JVM 选项。

就是这样！现在您有一个服务器存储着您已登录用户的详细信息。这意味着我们可以扩展并为我们的 Web 资源拥有多个服务器，而我们的用户不会注意到。而且我们不必在我们这边编写任何代码。

这也意味着即使重新启动服务器，您也将保留会话。

为了验证它是否有效，请使用`redis-cli`命令连接到 Redis。一开始，它将不包含任何键：

```java

> redis-cli
127.0.0.1:6379> KEYS *
(empty list or set)

```

转到您的应用程序并开始将内容放入会话中：

```java

127.0.0.1:6379> KEYS *
1) "spring:session:expirations:1432487760000"
2) "spring:session:sessions:1768a55b-081a-4673-8535-7449e5729af5"
127.0.0.1:6379> HKEYS spring:session:sessions:1768a55b-081a-4673-8535-7449e5729af5
1) "sessionAttr:SPRING_SECURITY_CONTEXT"
2) "sessionAttr:org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository.CSRF_TOKEN"
3) "lastAccessedTime"
4) "maxInactiveInterval"
5) "creationTime"

```

### 注意

您可以在[`redis.io/commands`](http://redis.io/commands)上查看可用命令的列表。

# SSL

**安全套接字层**（**SSL**）是一种安全协议，其中数据经过加密并通过证书发送给受信任的一方。在本部分中，我将向您展示使用 Spring Boot 创建安全连接的不同方法。完成这些步骤对于开始下一章并不是强制性的。它们包含在内是为了完整起见，因此如果您急于将应用程序部署到云端，可以随意跳过它们。

在第八章，“将您的 Web 应用程序部署到云端”中，我们将看到大多数云平台已经处理 SSL，因此我们不必在我们这边进行配置。

## 生成自签名证书

通常，X.509 证书由证书颁发机构提供。他们通常会向您收费，因此，为了测试目的，我们可以创建自己的自签名密钥库文件。

JDK 自带一个名为 keytool 的二进制文件，用于管理证书。使用它，您可以创建一个密钥库并将证书导入现有的密钥库中。您可以在项目根目录内发出以下命令来创建一个：

```java

$ keytool -genkey -alias masterspringmvc -keyalg RSA -keystore src/main/resources/tomcat.keystore
Enter keystore password: password
Re-enter new password: password
What is your first and last name?
 [Unknown]:  Master Spring MVC
What is the name of your organizational unit?
 [Unknown]:  Packt
What is the name of your organization?
 [Unknown]:  Packt
What is the name of your City or Locality?
 [Unknown]:  Paris
What is the name of your State or Province?
 [Unknown]:  France
What is the two-letter country code for this unit?
 [Unknown]:  FR
Is CN=Master Spring MVC, OU=Packt, O=Packt, L=Paris, ST=France, C=FR correct?
 [no]:  yes

Enter key password for <masterspringmvc>
 (RETURN if same as keystore password): password2
Re-enter new password: password2

```

这将生成一个名为`masterspringmvc`的密钥库，使用 RSA 算法，并将其存储在`src/main/resources`中的密钥库中。

### 提示

不要将密钥库推送到您的存储库中。它可能会被暴力破解，这将使您的网站的安全性失效。您还应该使用强大的、随机生成的密码生成密钥库。

## 简单的方法

如果你只关心有一个安全的 https 通道而没有 http 通道，那就很容易了：

```java

server.port = 8443
server.ssl.key-store = classpath:tomcat.keystore
 server.ssl.key-store-password = password
server.ssl.key-password = password2

```

### 提示

不要将密码推送到您的存储库中。使用`${}`符号导入环境变量。

## 双重方式

如果您希望在应用程序中同时使用 http 和 https 通道，您应该向应用程序添加这种配置：

```java
@Configuration
public class SslConfig {

    @Bean
    public EmbeddedServletContainerFactory servletContainer() throws IOException {
        TomcatEmbeddedServletContainerFactory tomcat = new TomcatEmbeddedServletContainerFactory();
        tomcat.addAdditionalTomcatConnectors(createSslConnector());
        return tomcat;
    }

    private Connector createSslConnector() throws IOException {
        Connector connector = new Connector(Http11NioProtocol.class.getName());
        Http11NioProtocol protocol =
                (Http11NioProtocol) connector.getProtocolHandler();
        connector.setPort(8443);
        connector.setSecure(true);
        connector.setScheme("https");
        protocol.setSSLEnabled(true);
        protocol.setKeyAlias("masterspringmvc");
        protocol.setKeystorePass("password");
        protocol.setKeyPass("password2");
        protocol.setKeystoreFile(new ClassPathResource("tomcat.keystore").getFile().getAbsolutePath());
        protocol.setSslProtocol("TLS");
        return connector;
    }
}
```

这将加载先前生成的密钥库，以在 8080 端口之外创建一个额外的 8443 端口的通道。

您可以使用 Spring Security 自动将连接从`http`重定向到`https`，配置如下：

```java
@Configuration
public class WebSecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .requiresChannel().anyRequest().requiresSecure()
            .and()
            /* rest of the configuration */;
    }
}
```

## 在一个安全的服务器后面

通常，使用 SSL 保护应用程序的最便捷方式是将其放在一个启用了 SSL 的 Web 服务器后面，如 Apache 或 CloudFlare。这些通常会使用事实上的标头来指示连接先前是使用 SSL 发起的。

如果您告诉 Spring Boot 您的`application.properties`文件中正确的标头是什么，它就可以理解这个协议：

```java

server.tomcat.remote_ip_header=x-forwarded-for
server.tomcat.protocol_header=x-forwarded-proto

```

### 注意

有关更多详细信息，请参阅此处的文档[`docs.spring.io/spring-boot/docs/current/reference/html/howto-embedded-servlet-containers.html#howto-use-tomcat-behind-a-proxy-server`](http://docs.spring.io/spring-boot/docs/current/reference/html/howto-embedded-servlet-containers.html#howto-use-tomcat-behind-a-proxy-server)。

# 检查点

在本章中，我们添加了三个配置项：`ApiSecurityConfiguration`，用于配置我们的 REST API 使用基本的 HTTP 身份验证；`WebSecurityConfiguration`，为我们的 Web 用户设置一个登录表单，以便使用帐户或 Twitter 登录；以及`RedisConfig`，允许我们的会话存储和从 Redis 服务器检索。

在认证包中，我们添加了一个`LoginController`类，用于重定向到我们的登录页面，一个`SignupController`类，第一次用户使用 Twitter 注册时将调用它，以及一个`AuthenticatingSignInAdapater`类，每次使用 Twitter 登录时都会调用它：

![检查点](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00977.jpeg)

# 总结

使用 Spring 来保护我们的 Web 应用程序非常简单。可能性是无限的，高级配置如社交登录也近在咫尺。分发会话和扩展也只需要几分钟。

在下一章中，我们将看到如何测试我们的应用程序，并确保它永远不会退化。



# 第二十二章：不留任何机会——单元测试和验收测试

在本章中，我们将看到为什么以及如何测试我们的应用程序。我们将看到单元测试和验收测试之间的区别，并学习如何进行两者。

本章分为两部分。在第一部分中，我们将使用 Java 编写测试，同时学习不同的测试方法。在第二部分中，我们将使用 Groovy 编写完全相同的测试，并看看如何使用这种令人敬畏的语言来提高我们的代码可读性。

如果您在本章中做了所有的事情，您将有双重测试，所以请随意保留对您最易读的测试。

# 为什么我要测试我的代码？

在 Java 世界工作使许多开发人员意识到测试的重要性。一系列良好的测试可以及早发现回归，并在我们发布产品时让我们更有信心。

现在很多人都熟悉持续集成的概念（[`www.thoughtworks.com/continuous-integration`](http://www.thoughtworks.com/continuous-integration)）。这是一种实践，其中服务器负责在源代码控制系统上进行更改时构建应用程序。

构建应该尽可能快，并且能够自我测试。这种实践的主要思想是获得快速的反馈循环；一旦系统中的某些东西出现问题，你应该尽快了解出了什么问题。

你为什么要在意？毕竟，测试你的应用程序是额外的成本；花在设计和维护测试上的时间必然会占用一些开发时间。

实际上，bug 被发现得越晚，成本就越高。如果你仔细想想，甚至由你的 QA 团队发现的 bug 的成本也比你自己发现的 bug 更高。它迫使你回到编写代码时的上下文：我为什么写这一行？那个函数的基础业务规则是什么？

如果你早早地编写测试，并且能够在几秒钟内启动它们，那么在你的代码中解决潜在 bug 肯定会花费更少的时间。

测试的另一个好处是它们作为代码的活文档。写大量的文档，甚至是代码注释，可能会变得无效，因为它们很容易过时，养成为极限情况或意外行为编写良好测试的习惯将成为未来的安全网。

这行代码是干什么用的？你有没有发现自己问过这种问题？如果你有一套良好的单元测试，你可以删除它并查看结果！测试给了我们对代码和重构能力前所未有的信心。软件非常脆弱。如果你不在乎它，它会慢慢腐烂和死亡。

要负责任——不要让你的代码死掉！

# 我应该如何测试我的代码？

我们可以对软件进行不同类型的测试，比如安全测试、性能测试等。作为开发人员，我们将专注于我们可以自动化的测试，并且将有助于改进我们的代码。

测试分为两类：单元测试和验收测试。测试金字塔（[`martinfowler.com/bliki/TestPyramid.html`](http://martinfowler.com/bliki/TestPyramid.html)）显示了这些测试应该以什么比例编写：

![我应该如何测试我的代码？](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00978.jpeg)

在金字塔的底部，你有单元测试（启动快，相对容易维护），在顶部是 UI 测试（成本更高，执行速度更慢）。集成测试位于中间：它们可以被视为具有单元之间复杂交互的大型单元测试。

金字塔的理念是提醒你把焦点放在你影响最大并且获得最佳反馈循环的地方。

# 测试驱动开发

许多开发人员养成了良好的测试驱动开发（TTD）的习惯。这种实践是从极限编程（XP）继承而来的，它将每个开发阶段分成小步骤，然后为每个步骤编写一个失败的测试。你进行必要的修改，使测试再次通过（测试变绿）。然后你可以重构你的代码，只要测试仍然是绿色的。以下图示了 TDD 的循环：

![测试驱动开发](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00979.jpeg)

你可以通过非常短的反馈循环迭代，直到功能完成，保证没有回归，并且保证你从一开始就测试了所有的代码。

TDD 受到了批评。最有趣的批评是这些：

+   编写测试比实际实现需要更多的时间

+   它可能导致设计不良的应用程序

事实上，成为一个优秀的 TDD 实践者需要时间。一旦你知道应该测试什么，并且足够了解你的工具，你将不会浪费太多时间。

使用 TDD（或任何其他方法）来设计一个具有良好设计的应用程序也需要有经验的开发人员。如果你陷入了 baby steps 的咒语并忘记了看大局，那么糟糕的设计可能是 TDD 的副作用。TDD 不会奇迹般地导致出色的应用程序设计，所以要小心，并记得在完成每个功能后退一步。

从书的开头，我们的代码中只有一个自动生成的单元测试。这很糟糕！我们没有遵循良好的实践。这一章是为了解决这个问题而存在的。

# 单元测试

我们可以编写的较低级别的测试称为单元测试。它们应该测试代码的一小部分，因此称为单元。如何定义一个单元取决于你；它可以是一个类或一组密切相关的类。定义这个概念将决定什么将被模拟（用虚拟对象替换）。你要用轻量级替代品替换数据库吗？你要替换与外部服务的交互吗？你要模拟行为与被测试的上下文无关的密切相关的对象吗？

我的建议是保持平衡的态度。保持你的测试干净和快速，其他一切都会随之而来。

我很少完全模拟数据层。我倾向于在测试中使用嵌入式数据库。它们提供了一种在测试时加载数据的简单方法。

作为一个规则，我总是模拟与外部服务的协作，原因有两个，如下：

+   测试的速度和在不连接到网络的情况下运行测试的可能性

+   为了能够在与这些服务通信时测试错误情况

此外，模拟和存根之间存在微妙的区别。我们将尝试使用这两种方法来看它们之间的关系。

## 适合工作的正确工具

测试新手的第一个障碍是缺乏编写相关和可维护测试的好工具和库的知识。

我将在这里列出一些。这个列表绝不是详尽无遗的，但它包含了我们将要使用的工具，并且与 Spring 轻松兼容：

| JUnit | 最广泛采用的 Java 测试运行器。默认由所有构建工具启动。 |
| --- | --- |
| AssertJ | 一种流畅的断言库。比 Hamcrest 更容易使用。 |
| Mockito | 一个简单的模拟框架。 |
| DbUnit | 用于使用 XML 数据集模拟和断言数据库内容。 |
| Spock | 一种优雅的 Groovy DSL，用于以行为驱动开发（BDD）风格（Given/When/Then）编写测试。 |

Groovy 在我的测试工具集中占据了重要位置。即使你还没有准备好将一些 Groovy 代码投入生产，你仍然可以在测试中轻松使用这种语言的便利性。使用 Gradle 非常容易实现，但我们将在几分钟内看到。

# 验收测试

在 Web 应用程序的背景下，“验收测试”通常指的是在浏览器中的端到端测试。在 Java 世界中，Selenium 显然是最可靠和成熟的库之一。

在 JavaScript 世界中，我们可以找到其他替代方案，如 PhantomJS 或 Protractor。PhantomJS 在我们的案例中非常相关，因为这里有一个 Web 驱动程序可用于在这个无头浏览器中运行 Selenium 测试，这将提高启动时间，而且不需要模拟 X 服务器或启动单独的 Selenium 服务器：

| Selenium 2 | 提供 Web 驱动程序以操纵浏览器进行自动化测试。 |
| --- | --- |
| PhantomJS | 一个无头浏览器（没有 GUI）。可能是最快的浏览器。 |
| FluentLenium | 用于操纵 Selenium 测试的流畅库。 |
| Geb | 用于操纵 Selenium 测试的 Groovy 库。 |

# 我们的第一个单元测试

现在是时候编写我们的第一个单元测试了。

我们将专注于在控制器级别编写测试，因为我们几乎没有业务代码或服务。编写 Spring MVC 测试的关键是我们类路径中的`org.springframework.boot:spring-boot-starter-test`依赖项。它将添加一些非常有用的库，比如这些：

+   `hamcrest`：这是 JUnit 的断言库

+   `mockito`：这是一个模拟库

+   `spring-test`：这是 Spring 测试库

我们将测试当用户尚未创建其个人资料时，重定向到个人资料页面的情况。

我们已经有一个名为`MasterSpringMvc4ApplicationTests`的自动生成测试。这是使用 Spring 测试框架编写的最基本的测试：如果上下文无法加载，它将什么也不做，只会失败。

```java
@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = MasterSpringMvc4Application.class)
@WebAppConfiguration
public class MasterSpringMvc4ApplicationTests {

    @Test
    public void contextLoads() {
    }
}
```

我们可以删除这个测试，并创建一个新的测试，确保没有个人资料的用户将默认重定向到个人资料页面。它实际上测试了`HomeController`类的代码，所以让我们称之为`HomeControllerTest`类，并将其放在与`HomeController`相同的包中，即`src/test/java`。所有的 IDE 都有从类创建 JUnit 测试用例的快捷方式。现在找出如何使用您的 IDE 来完成这个操作！

这是测试：

```java
package masterSpringMvc.controller;

import masterSpringMvc.MasterSpringMvcApplication;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = MasterSpringMvcApplication.class)
@WebAppConfiguration
public class HomeControllerTest {
    @Autowired
    private WebApplicationContext wac;

    private MockMvc mockMvc;

    @Before
    public void setup() {
        this.mockMvc = MockMvcBuilders.webAppContextSetup(this.wac).build();
    }

    @Test
    public void should_redirect_to_profile() throws Exception {
        this.mockMvc.perform(get("/"))
                .andDo(print())
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/profile"));
    }
}
```

我们使用`MockMvc`来模拟与 Spring 控制器的交互，而不会产生 Servlet 容器的实际开销。

我们还使用了 Spring 提供的一些匹配器来断言我们的结果。它们实际上实现了 Hamcrest 匹配器。

`.andDo(print())`语句将为测试场景的请求和响应生成整洁的调试输出。如果您觉得太啰嗦，可以将其注释掉。

就是这样！语法在开始时有点棘手，但一个具有良好代码补全功能的 IDE 将能够帮助您。

现在我们想测试的是，如果用户填写了其个人资料的测试部分，我们是否可以将其重定向到正确的搜索。为此，我们需要使用`MockHttpSession`类对会话进行存根。

```java
import org.springframework.mock.web.MockHttpSession;
import masterSpringMvc.profile.UserProfileSession;

// put this test below the other one
@Test
public void should_redirect_to_tastes() throws Exception {
    MockHttpSession session = new MockHttpSession();
    UserProfileSession sessionBean = new UserProfileSession();
    sessionBean.setTastes(Arrays.asList("spring", "groovy"));
    session.setAttribute("scopedTarget.userProfileSession", sessionBean);

    this.mockMvc.perform(get("/").session(session))
        .andExpect(status().isFound())
        .andExpect(redirectedUrl("/search/mixed;keywords=spring,groovy"));
}
```

您将不得不为测试添加`setTastes()` setter 到`UserProfileSession` bean 中。

在`org.springframework.mock.web`包中有很多用于 Servlet 环境的模拟工具。

请注意，表示我们会话中的 bean 的属性以`scopedTarget`为前缀。这是因为 Spring 会对会话 bean 进行代理。因此，在 Spring 上下文中实际上有两个对象，我们定义的实际 bean 和最终会出现在会话中的代理。

模拟会话是一个很好的类，但我们可以使用一个构建器来重构测试，该构建器将隐藏实现细节，并且以后可以重复使用：

```java
@Test
public void should_redirect_to_tastes() throws Exception {

    MockHttpSession session = new SessionBuilder().userTastes("spring", "groovy").build();
    this.mockMvc.perform(get("/")
        .session(session))
        .andExpect(status().isFound())
        .andExpect(redirectedUrl("/search/mixed;keywords=spring,groovy"));
}
```

构建器的代码如下：

```java
public class SessionBuilder {
    private final MockHttpSession session;
    UserProfileSession sessionBean;

    public SessionBuilder() {
        session = new MockHttpSession();
        sessionBean = new UserProfileSession();
        session.setAttribute("scopedTarget.userProfileSession", sessionBean);
    }

    public SessionBuilder userTastes(String... tastes) {
        sessionBean.setTastes(Arrays.asList(tastes));
        return this;
    }

    public MockHttpSession build() {
        return session;
    }
}
```

在这次重构之后，您的测试应该始终通过，当然。

# 模拟和存根

如果我们想测试`SearchController`类处理的搜索请求，我们肯定会想要模拟`SearchService`。

有两种方法可以做到这一点：使用模拟对象或存根。

## 使用 Mockito 进行模拟

首先，我们可以使用 Mockito 创建一个模拟对象：

```java
package masterSpringMvc.search;

import masterSpringMvc.MasterSpringMvcApplication;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.util.Arrays;

import static org.hamcrest.Matchers.*;
import static org.mockito.Matchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = MasterSpringMvcApplication.class)
@WebAppConfiguration
public class SearchControllerMockTest {
    @Mock
    private SearchService searchService;

    @InjectMocks
    private SearchController searchController;

    private MockMvc mockMvc;

    @Before
    public void setup() {
        MockitoAnnotations.initMocks(this);
        this.mockMvc = MockMvcBuilders
                .standaloneSetup(searchController)
                .setRemoveSemicolonContent(false)
                .build();
    }

    @Test
    public void should_search() throws Exception {

        when(searchService.search(anyString(), anyListOf(String.class)))
                .thenReturn(Arrays.asList(
                        new LightTweet("tweetText")
                ));

        this.mockMvc.perform(get("/search/mixed;keywords=spring"))
                .andExpect(status().isOk())
                .andExpect(view().name("resultPage"))
                .andExpect(model().attribute("tweets", everyItem(
                        hasProperty("text", is("tweetText"))
                )));

        verify(searchService, times(1)).search(anyString(), anyListOf(String.class));
    }
}
```

您可以看到，我们创建了一个独立的上下文，而不是使用 web 应用程序上下文来设置`MockMvc`。这个上下文只包含我们的控制器。这意味着我们可以完全控制控制器及其依赖项的实例化和初始化。这将使我们能够轻松地在我们的控制器中注入一个模拟对象。

缺点是我们必须重新声明我们的配置的一部分，比如说我们不想在分号后删除 URL 字符的配置。

我们使用了一些 Hamcrest 匹配器来断言最终会出现在视图模型中的属性。

模拟的方法有其好处，比如能够验证与模拟对象的交互并在运行时创建期望。

这也会使您的测试与对象的实际实现耦合。例如，如果您更改了控制器中获取推文的方式，您很可能会破坏与该控制器相关的测试，因为它们仍然尝试模拟我们不再依赖的服务。

## 在测试时存根我们的 bean

另一种方法是在我们的测试中用另一个实现类替换`SearchService`类的实现。

我们早些时候有点懒，没有为`SearchService`定义一个接口。*始终根据接口而不是实现进行编程*。在这句谚语背后的智慧中，隐藏着*四人帮*最重要的教训。

控制反转的好处之一是允许在测试或实际系统中轻松替换我们的实现。为了使其工作，我们将不得不修改所有使用`SearchService`的地方，使用新的接口。有了一个好的 IDE，有一个叫做`提取接口`的重构，它会做到这一点。这应该创建一个包含我们的`SearchService`类的`search()`公共方法的接口：

```java
public interface TwitterSearch {
    List<LightTweet> search(String searchType, List<String> keywords);
}
```

当然，我们的两个控制器，`SearchController`和`SearchApiController`，现在必须使用接口而不是实现。

现在我们有能力为`TwitterSearch`类创建一个测试替身，专门用于我们的测试用例。为了使其工作，我们将需要声明一个名为`StubTwitterSearchConfig`的新 Spring 配置，其中将包含`TwitterSearch`的另一个实现。我将其放在 search 包中，紧邻`SearchControllerMockTest`：

```java
package masterSpringMvc.search;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;

import java.util.Arrays;

@Configuration
public class StubTwitterSearchConfig {
    @Primary @Bean
    public TwitterSearch twitterSearch() {
        return (searchType, keywords) -> Arrays.asList(
                new LightTweet("tweetText"),
                new LightTweet("secondTweet")
        );
    }
}
```

在这个配置类中，我们使用`@Primary`注解重新声明了`TwitterSearch` bean，这将告诉 Spring 优先使用这个实现，如果在类路径中找到其他实现。

由于`TwitterSearch`接口只包含一个方法，我们可以使用 lambda 表达式来实现它。

这是使用我们的`StubConfiguration`类以及带有`SpringApplicationConfiguration`注解的主配置的完整测试：

```java
package masterSpringMvc.search;

import masterSpringMvc.MasterSpringMvcApplication;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import static org.hamcrest.Matchers.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = {
        MasterSpringMvcApplication.class,
        StubTwitterSearchConfig.class
})
@WebAppConfiguration
public class SearchControllerTest {
    @Autowired
    private WebApplicationContext wac;

    private MockMvc mockMvc;

    @Before
    public void setup() {
        this.mockMvc = MockMvcBuilders.webAppContextSetup(this.wac).build();
    }

    @Test
    public void should_search() throws Exception {

        this.mockMvc.perform(get("/search/mixed;keywords=spring"))
                .andExpect(status().isOk())
                .andExpect(view().name("resultPage"))
                .andExpect(model().attribute("tweets", hasSize(2)))
                .andExpect(model().attribute("tweets",
                                hasItems(
                                        hasProperty("text", is("tweetText")),
                                        hasProperty("text", is("secondTweet"))
                                ))
                );
    }
}
```

## 我应该使用模拟对象还是存根对象？

这两种方法都有各自的优点。有关详细解释，请查看 Martin Fowler 的这篇伟大的文章：[`martinfowler.com/articles/mocksArentStubs.html`](http://martinfowler.com/articles/mocksArentStubs.html)。

我的测试例程更多地是关于编写存根，因为我喜欢测试对象的输出而不是它们的内部工作原理。但这取决于你。Spring 作为一个依赖注入框架，意味着你可以轻松选择你喜欢的方法。

# 单元测试 REST 控制器

我们刚刚测试了一个传统的控制器重定向到视图。原则上，测试 REST 控制器非常类似，但有一些微妙之处。

由于我们将测试控制器的 JSON 输出，我们需要一个 JSON 断言库。将以下依赖项添加到您的`build.gradle`文件中：

```java
testCompile 'com.jayway.jsonpath:json-path'
```

让我们为`SearchApiController`类编写一个测试，该控制器允许搜索推文并以 JSON 或 XML 格式返回结果：

```java
package masterSpringMvc.search.api;

import masterSpringMvc.MasterSpringMvcApplication;
import masterSpringMvc.search.StubTwitterSearchConfig;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.http.MediaType;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import static org.hamcrest.Matchers.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = {
        MasterSpringMvcApplication.class,
        StubTwitterSearchConfig.class
})
@WebAppConfiguration
public class SearchApiControllerTest {
    @Autowired
    private WebApplicationContext wac;

    private MockMvc mockMvc;

    @Before
    public void setup() {
        this.mockMvc = MockMvcBuilders.webAppContextSetup(this.wac).build();
    }

    @Test
    public void should_search() throws Exception {

        this.mockMvc.perform(
                get("/api/search/mixed;keywords=spring")
                        .accept(MediaType.APPLICATION_JSON))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$", hasSize(2)))
                .andExpect(jsonPath("$[0].text", is("tweetText")))
                .andExpect(jsonPath("$[1].text", is("secondTweet")));
    }
}
```

注意 JSON 输出上的简单而优雅的断言。测试我们的用户控制器将需要更多的工作。

首先，让我们将`assertj`添加到类路径中；它将帮助我们编写更清晰的测试：

```java
testCompile 'org.assertj:assertj-core:3.0.0'
```

然后，为了简化测试，在我们的`UserRepository`类中添加一个`reset()`方法，这将帮助我们进行测试：

```java
void reset(User... users) {
        userMap.clear();
        for (User user : users) {
                save(user);
        }
}
```

在现实生活中，我们可能应该提取一个接口并创建一个存根进行测试。我会把这留给你作为练习。

这是第一个获取用户列表的测试：

```java
package masterSpringMvc.user.api;

import masterSpringMvc.MasterSpringMvcApplication;
import masterSpringMvc.user.User;
import masterSpringMvc.user.UserRepository;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.http.MediaType;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import static org.hamcrest.Matchers.*;
   import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = MasterSpringMvcApplication.class)
@WebAppConfiguration
public class UserApiControllerTest {

    @Autowired
    private WebApplicationContext wac;

    @Autowired
    private UserRepository userRepository;

    private MockMvc mockMvc;

    @Before
    public void setup() {
        this.mockMvc = MockMvcBuilders.webAppContextSetup(this.wac).build();
        userRepository.reset(new User("bob@spring.io"));
    }

    @Test
    public void should_list_users() throws Exception {
        this.mockMvc.perform(
                get("/api/users")
                        .accept(MediaType.APPLICATION_JSON)
        )
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$", hasSize(1)))
                .andExpect(jsonPath("$[0].email", is("bob@spring.io")));
    }
}
```

为了使其工作，为`User`类添加一个构造函数，以电子邮件属性作为参数。注意：您还需要为 Jackson 添加一个默认构造函数。

该测试与之前的测试非常相似，另外设置了`UserRepository`。

现在让我们测试创建用户的`POST`方法：

```java
import static org.assertj.core.api.Assertions.assertThat;

// Insert this test below the previous one
@Test
public void should_create_new_user() throws Exception {
        User user = new User("john@spring.io");
        this.mockMvc.perform(
                post("/api/users")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(JsonUtil.toJson(user))
        )
                .andExpect(status().isCreated());

        assertThat(userRepository.findAll())
                .extracting(User::getEmail)
                .containsOnly("bob@spring.io", "john@spring.io");
}
```

有两件事需要注意。第一件事是使用 AssertJ 来断言测试后存储库的内容。您需要以下静态导入才能使其工作：

```java
import static org.assertj.core.api.Assertions.assertThat;
```

第二个是我们使用一个实用方法，在将对象发送到控制器之前将其转换为 JSON。为此，我在`utils`包中创建了一个简单的实用程序类，如下所示：

```java
package masterSpringMvc.utils;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;

public class JsonUtil {
    public static byte[] toJson(Object object) throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        mapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);
        return mapper.writeValueAsBytes(object);
    }
}
```

`DELETE`方法的测试如下：

```java
@Test
public void should_delete_user() throws Exception {
        this.mockMvc.perform(
                delete("/api/user/bob@spring.io")
                        .accept(MediaType.APPLICATION_JSON)
        )
                .andExpect(status().isOk());

        assertThat(userRepository.findAll()).hasSize(0);
}

@Test
public void should_return_not_found_when_deleting_unknown_user() throws Exception {
        this.mockMvc.perform(
                delete("/api/user/non-existing@mail.com")
                        .accept(MediaType.APPLICATION_JSON)
        )
                .andExpect(status().isNotFound());
}
```

最后，这是用于更新用户的`PUT`方法的测试：

```java
@Test
public void put_should_update_existing_user() throws Exception {
        User user = new User("ignored@spring.io");
        this.mockMvc.perform(
                put("/api/user/bob@spring.io")
                        .content(JsonUtil.toJson(user))
                        .contentType(MediaType.APPLICATION_JSON)
        )
                .andExpect(status().isOk());

        assertThat(userRepository.findAll())
                .extracting(User::getEmail)
                .containsOnly("bob@spring.io");
}
```

糟糕！最后一个测试没有通过！通过检查`UserApiController`的实现，我们很容易看出原因：

```java
   @RequestMapping(value = "/user/{email}", method = RequestMethod.PUT)
    public ResponseEntity<User> updateUser(@PathVariable String email, @RequestBody User user) throws EntityNotFoundException {
        User saved = userRepository.update(email, user);
        return new ResponseEntity<>(saved, HttpStatus.CREATED);
    }
```

我们在控制器中返回了错误的状态！将其更改为`HttpStatus.OK`，测试应该再次变为绿色。

使用 Spring，可以轻松地使用应用程序的相同配置编写控制器测试，但我们也可以有效地覆盖或更改测试设置中的一些元素。

在运行所有测试时，您将注意到的另一件有趣的事情是应用程序上下文只加载一次，这意味着开销实际上非常小。

我们的应用程序也很小，因此我们没有努力将配置拆分为可重用的部分。不在每个测试中加载完整的应用程序上下文可能是一个非常好的做法。您实际上可以使用`@ComponentScan`注释将组件扫描拆分为不同的单元。

此注释有几个属性，允许您使用`includeFilter`和`excludeFilter`定义过滤器（例如仅加载控制器）并使用`basePackageClasses`和`basePackages`注释扫描特定包。

您还可以将配置拆分为多个`@Configuration`类。一个很好的例子是将我们应用程序的用户和推文部分的代码拆分为两个独立的部分。

现在我们将看一下验收测试，这是一种非常不同的测试。

# 测试身份验证

如果您希望在 MockMvc 测试中设置 Spring Security，可以在我们之前的测试旁边编写此测试：

```java
package masterSpringMvc.user.api;

import masterSpringMvc.MasterSpringMvcApplication;
import masterSpringMvc.user.User;
import masterSpringMvc.user.UserRepository;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.http.MediaType;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.util.Base64;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = MasterSpringMvcApplication.class)
@WebAppConfiguration
public class UserApiControllerAuthTest {

    @Autowired
    private FilterChainProxy springSecurityFilter;

    @Autowired
    private WebApplicationContext wac;

    @Autowired
    private UserRepository userRepository;

    private MockMvc mockMvc;

    @Before
    public void setup() {
        this.mockMvc = MockMvcBuilders.webAppContextSetup(this.wac).addFilter(springSecurityFilter).build();
        userRepository.reset(new User("bob@spring.io"));
    }

    @Test
    public void unauthenticated_cannot_list_users() throws Exception {
        this.mockMvc.perform(
                get("/api/users")
                        .accept(MediaType.APPLICATION_JSON)
        )
                .andExpect(status().isUnauthorized());
    }

    @Test
    public void admin_can_list_users() throws Exception {
        this.mockMvc.perform(
                get("/api/users")
                        .accept(MediaType.APPLICATION_JSON)
                        .header("Authorization", basicAuth("admin", "admin"))
        )
                .andExpect(status().isOk());
    }

    private String basicAuth(String login, String password) {
        byte[] auth = (login + ":" + password).getBytes();
        return "Basic " + Base64.getEncoder().encodeToString(auth);
    }
}
```

在前面的示例中，我们将`SpringSecurityFilter`添加到了我们的配置中。这将激活 Spring 安全检查。要测试身份验证是否有效，我们只需在请求中发送正确的标头。

基本身份验证的优势在于它非常容易模拟。对于更复杂的设置，您将不得不在身份验证端点上执行模拟请求。

在撰写本文时，Spring Boot 的版本为 1.2.3，并依赖于 Spring Security 3。

几周后，Spring Boot 1.3.0 将可用，它将更新 Spring Security 并使用版本 4。

这是一个好消息，因为 Spring Security 4 包括使用简单注释轻松设置经过身份验证的用户。有关更多详细信息，请参见[`docs.spring.io/spring-security/site/docs/4.0.x/reference/htmlsingle/#test`](http://docs.spring.io/spring-security/site/docs/4.0.x/reference/htmlsingle/#test)。

# 编写验收测试

单元测试只能覆盖应用程序组件之间的不同交互的子集。为了再进一步，我们需要设置验收测试，这些测试将实际启动完整的应用程序，并允许我们与其界面进行交互。

## Gradle 配置

在将集成测试添加到项目中时，我们想要做的第一件事是将它们放在与单元测试不同的位置。

其原因实质上是，验收测试比单元测试慢。它们可以成为不同集成作业的一部分，例如每晚构建，我们希望开发人员能够轻松地从他们的 IDE 启动不同类型的测试。要使用 Gradle 实现这一点，我们将不得不添加一个名为`integrationTest`的新配置。对于 Gradle 来说，配置是一组工件及其依赖项。我们的项目中已经有几个配置：`compile`，`testCompile`等。

您可以通过在项目的根目录键入`./gradlew properties`来查看项目的配置等更多信息。

在`build.gradle`文件的末尾添加新的配置：

```java
configurations {
    integrationTestCompile.extendsFrom testCompile
    integrationTestRuntime.extendsFrom testRuntime
}
```

这将允许您为`integrationTestCompile`和`integrationTestRuntime`声明依赖项。更重要的是，通过继承测试配置，我们可以访问它们的依赖项。

### 提示

我不建议将集成测试依赖项声明为`integrationTestCompile`。就 Gradle 而言，这样做是可以的，但 IDE 内的支持是不存在的。我通常会将我的集成测试依赖项声明为`testCompile`依赖项。这只是一个小不便。

现在我们有了新的配置，我们必须创建一个与它们关联的`sourceSet`类。`sourceSet`类表示 Java 源代码和资源的逻辑组。当然，它们也必须继承自测试和主类；请参阅以下代码：

```java
sourceSets {
    integrationTest {
        compileClasspath += main.output + test.output
        runtimeClasspath += main.output + test.output
    }
}
```

最后，我们需要添加一个任务来从我们的构建中运行它们，如下所示：

```java
task integrationTest(type: Test) {
    testClassesDir = sourceSets.integrationTest.output.classesDir
    classpath = sourceSets.integrationTest.runtimeClasspath
    reports.html.destination = file("${reporting.baseDir}/integrationTests")
}
```

要运行我们的测试，我们可以输入`./gradlew integrationTest`。除了配置我们的类路径和查找测试类的位置之外，我们还定义了一个目录，用于生成测试报告。

这个配置允许我们在`src/integrationTest/java`或`src/integrationTest/groovy`中编写我们的测试，这将使我们更容易识别它们并单独运行它们，而不是与我们的单元测试一起运行。

默认情况下，它们将生成在`build/reports/tests`中。如果我们不覆盖它们，如果我们使用`gradle clean test integrationTest`同时运行测试和集成测试，它们将互相覆盖。

值得一提的是，Gradle 生态系统中的一个新插件旨在简化声明新的测试配置，详细信息请访问[`plugins.gradle.org/plugin/org.unbroken-dome.test-sets`](https://plugins.gradle.org/plugin/org.unbroken-dome.test-sets)。

## 我们的第一个 FluentLenium 测试

FluentLenium 是一个用于操纵 Selenium 测试的惊人库。让我们向我们的构建脚本添加一些依赖项：

```java
testCompile 'org.fluentlenium:fluentlenium-assertj:0.10.3'
testCompile 'com.codeborne:phantomjsdriver:1.2.1'
testCompile 'org.seleniumhq.selenium:selenium-java:2.45.0'
```

默认情况下，`fluentlenium`带有`selenium-java`。我们重新声明它，只是为了明确要求使用最新版本。我们还添加了对`PhantomJS`驱动程序的依赖，这不是 Selenium 官方支持的。`selenium-java`库的问题在于它捆绑了所有支持的 web 驱动程序。

您可以通过输入`gradle dependencies`来查看我们项目的依赖树。在底部，您将看到类似于以下内容：

```java
+--- org.fluentlenium:fluentlenium-assertj:0.10.3
|    +--- org.fluentlenium:fluentlenium-core:0.10.3
|    |    \--- org.seleniumhq.selenium:selenium-java:2.44.0 -> 2.45.0
|    |         +--- org.seleniumhq.selenium:selenium-chrome-driver:2.45.0

|    |         +--- org.seleniumhq.selenium:selenium-htmlunit-driver:2.45.0

|    |         +--- org.seleniumhq.selenium:selenium-firefox-driver:2.45.0

|    |         +--- org.seleniumhq.selenium:selenium-ie-driver:2.45.0

|    |         +--- org.seleniumhq.selenium:selenium-safari-driver:2.45.0

|    |         +--- org.webbitserver:webbit:0.4.14 (*)
|    |         \--- org.seleniumhq.selenium:selenium-leg-rc:2.45.0
|    |              \--- org.seleniumhq.selenium:selenium-remote-driver:2.45.0 (*)
|    \--- org.assertj:assertj-core:1.6.1 -> 3.0.0
```

由于我们只会使用`PhantomJS`驱动程序，将所有这些依赖项放在类路径中是非常不必要的。为了排除我们不需要的依赖项，我们可以在依赖项声明之前的构建脚本中添加以下部分：

```java
configurations {
    testCompile {
        exclude module: 'selenium-safari-driver'
        exclude module: 'selenium-ie-driver'
        //exclude module: 'selenium-firefox-driver'
        exclude module: 'selenium-htmlunit-driver'
        exclude module: 'selenium-chrome-driver'
    }
}
```

我们只需将`firefox`驱动程序准备好。`PhantomJS`驱动程序是一个无头浏览器，因此理解没有 GUI 发生的事情可能会很棘手。切换到 Firefox 来调试复杂的测试可能会很好。

有了正确配置的类路径，我们现在可以编写我们的第一个集成测试。Spring Boot 有一个非常方便的注解来支持这个测试：

```java
import masterSpringMvc.MasterSpringMvcApplication;
import masterSpringMvc.search.StubTwitterSearchConfig;
import org.fluentlenium.adapter.FluentTest;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.phantomjs.PhantomJSDriver;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.boot.test.WebIntegrationTest;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import static org.assertj.core.api.Assertions.assertThat;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = {
        MasterSpringMvcApplication.class,
        StubTwitterSearchConfig.class
})
@WebIntegrationTest(randomPort = true)
public class FluentIntegrationTest extends FluentTest {

    @Value("${local.server.port}")
    private int serverPort;

    @Override
    public WebDriver getDefaultDriver() {
        return new PhantomJSDriver();
    }

    public String getDefaultBaseUrl() {
        return "http://localhost:" + serverPort;
    }

    @Test
    public void hasPageTitle() {
        goTo("/");
        assertThat(findFirst("h2").getText()).isEqualTo("Login");
    }
}
```

请注意，FluentLenium 具有一个用于请求 DOM 元素的简洁 API。使用 AssertJ，我们可以在页面内容上编写易于阅读的断言。

### 注意

请查看[`github.com/FluentLenium/FluentLenium`](https://github.com/FluentLenium/FluentLenium)上的文档以获取更多信息。

使用`@WebIntegrationTest`注解，Spring 实际上会创建嵌入式 Servlet 容器（Tomcat）并在随机端口上启动我们的 Web 应用程序！我们需要在运行时检索此端口号。这将允许我们为我们的测试提供一个基本 URL，这个 URL 将成为我们在测试中进行的所有导航的前缀。

如果您尝试在这个阶段运行测试，您将看到以下错误消息：

```java

java.lang.IllegalStateException: The path to the driver executable must be set by the phantomjs.binary.path capability/system property/PATH variable; for more information, see https://github.com/ariya/phantomjs/wiki. The latest version can be downloaded from http://phantomjs.org/download.html

```

实际上，PhantomJS 需要安装在您的机器上才能正常工作。在 Mac 上，只需使用`brew install phantomjs`。对于其他平台，请参阅[`phantomjs.org/download.html`](http://phantomjs.org/download.html)上的文档。

如果您不想在您的机器上安装新的二进制文件，请用`new FirefoxDriver()`替换`new PhantomJSDriver()`。您的测试会慢一点，但您会有一个 GUI。

我们的第一个测试是着陆在个人资料页面，对吧？现在我们需要找到一种登录的方法。

使用存根进行伪登录怎么样？

将这个类放在测试源代码中（`src/test/java`）：

```java
package masterSpringMvc.auth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.social.connect.ConnectionFactoryLocator;
import org.springframework.social.connect.UsersConnectionRepository;
import org.springframework.social.connect.web.ProviderSignInController;
import org.springframework.social.connect.web.SignInAdapter;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.servlet.view.RedirectView;

@Configuration
public class StubSocialSigninConfig {

    @Bean
    @Primary
    @Autowired
    public ProviderSignInController signInController(ConnectionFactoryLocator factoryLocator,
                                                     UsersConnectionRepository usersRepository,
                                                     SignInAdapter signInAdapter) {
        return new FakeSigninController(factoryLocator, usersRepository, signInAdapter);
    }

    public class FakeSigninController extends ProviderSignInController {
        public FakeSigninController(ConnectionFactoryLocator connectionFactoryLocator,
                                    UsersConnectionRepository usersConnectionRepository,
                                    SignInAdapter signInAdapter) {
            super(connectionFactoryLocator, usersConnectionRepository, signInAdapter);
        }

        @Override
        public RedirectView signIn(String providerId, NativeWebRequest request) {
            UsernamePasswordAuthenticationToken authentication =
                    new UsernamePasswordAuthenticationToken("geowarin", null, null);
            SecurityContextHolder.getContext().setAuthentication(authentication);
            return new RedirectView("/");
        }
    }
}
```

这将认证任何点击 Twitter 登录按钮的用户为 geowarin。

我们将编写第二个测试，填写个人资料表单并断言搜索结果是否显示：

```java
import masterSpringMvc.MasterSpringMvcApplication;
import masterSpringMvc.auth.StubSocialSigninConfig;
import masterSpringMvc.search.StubTwitterSearchConfig;
import org.fluentlenium.adapter.FluentTest;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.phantomjs.PhantomJSDriver;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.boot.test.WebIntegrationTest;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import static org.assertj.core.api.Assertions.assertThat;
import static org.fluentlenium.core.filter.FilterConstructor.withName;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = {
        MasterSpringMvcApplication.class,
        StubTwitterSearchConfig.class,
        StubSocialSigninConfig.class
})
@WebIntegrationTest(randomPort = true)
public class FluentIntegrationTest extends FluentTest {

    @Value("${local.server.port}")
    private int serverPort;

    @Override
    public WebDriver getDefaultDriver() {
        return new PhantomJSDriver();
    }

    public String getDefaultBaseUrl() {
        return "http://localhost:" + serverPort;
    }

    @Test
    public void hasPageTitle() {
        goTo("/");
        assertThat(findFirst("h2").getText()).isEqualTo("Login");
    }

    @Test
    public void should_be_redirected_after_filling_form() {
        goTo("/");
        assertThat(findFirst("h2").getText()).isEqualTo("Login");

        find("button", withName("twitterSignin")).click();
 assertThat(findFirst("h2").getText()).isEqualTo("Your profile");

        fill("#twitterHandle").with("geowarin");
        fill("#email").with("geowarin@mymail.com");
        fill("#birthDate").with("03/19/1987");

        find("button", withName("addTaste")).click();
        fill("#tastes0").with("spring");

        find("button", withName("save")).click();

        takeScreenShot();
        assertThat(findFirst("h2").getText()).isEqualTo("Tweet results for spring");
        assertThat(findFirst("ul.collection").find("li")).hasSize(2);
    }
}
```

请注意，我们可以轻松地要求我们的网络驱动程序对当前用于测试的浏览器进行截图。这将产生以下输出：

![我们的第一个 FluentLenium 测试](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00980.jpeg)

## 使用 FluentLenium 的页面对象

以前的测试有点混乱。我们在测试中硬编码了所有选择器。当我们使用相同的元素编写大量测试时，这可能变得非常危险，因为每当我们更改页面布局时，所有测试都会失败。此外，测试有点难以阅读。

为了解决这个问题，一个常见的做法是使用一个页面对象来表示我们应用程序中的特定网页。使用 FluentLenium，页面对象必须继承`FluentPage`类。

我们将创建三个页面，分别对应我们 GUI 的每个元素。第一个将是具有单击`twitterSignin`按钮选项的登录页面，第二个将是具有填写个人资料表单的便利方法的个人资料页面，最后一个将是我们可以断言显示结果的结果页面。

让我们立即创建登录页面。我把所有三个页面都放在了`pages`包中：

```java
package pages;

import org.fluentlenium.core.FluentPage;
import org.fluentlenium.core.domain.FluentWebElement;
import org.openqa.selenium.support.FindBy;

import static org.assertj.core.api.Assertions.assertThat;

public class LoginPage extends FluentPage {
    @FindBy(name = "twitterSignin")
    FluentWebElement signinButton;

    public String getUrl() {
        return "/login";
    }

    public void isAt() {
        assertThat(findFirst("h2").getText()).isEqualTo("Login");
    }

    public void login() {
        signinButton.click();
    }
}
```

让我们为我们的个人资料页面创建一个页面：

```java
package pages;

import org.fluentlenium.core.FluentPage;
import org.fluentlenium.core.domain.FluentWebElement;
import org.openqa.selenium.support.FindBy;

import static org.assertj.core.api.Assertions.assertThat;

public class ProfilePage extends FluentPage {
    @FindBy(name = "addTaste")
    FluentWebElement addTasteButton;
    @FindBy(name = "save")
    FluentWebElement saveButton;

    public String getUrl() {
        return "/profile";
    }

    public void isAt() {
        assertThat(findFirst("h2").getText()).isEqualTo("Your profile");
    }

    public void fillInfos(String twitterHandle, String email, String birthDate) {
        fill("#twitterHandle").with(twitterHandle);
        fill("#email").with(email);
        fill("#birthDate").with(birthDate);
    }

    public void addTaste(String taste) {
        addTasteButton.click();
        fill("#tastes0").with(taste);
    }

    public void saveProfile() {
        saveButton.click();
    }
}
```

让我们也为搜索结果页面创建另一个：

```java
package pages;

import com.google.common.base.Joiner;
import org.fluentlenium.core.FluentPage;
import org.fluentlenium.core.domain.FluentWebElement;
import org.openqa.selenium.support.FindBy;

import static org.assertj.core.api.Assertions.assertThat;

public class SearchResultPage extends FluentPage {
    @FindBy(css = "ul.collection")
    FluentWebElement resultList;

    public void isAt(String... keywords) {
        assertThat(findFirst("h2").getText())
                .isEqualTo("Tweet results for " + Joiner.on(",").join(keywords));
    }

    public int getNumberOfResults() {
        return resultList.find("li").size();
    }
}
```

现在我们可以使用这些页面对象重构测试：

```java
@Page
private LoginPage loginPage;
@Page
private ProfilePage profilePage;
@Page
private SearchResultPage searchResultPage;

@Test
public void should_be_redirected_after_filling_form() {
    goTo("/");
    loginPage.isAt();

    loginPage.login();
    profilePage.isAt();

    profilePage.fillInfos("geowarin", "geowarin@mymail.com", "03/19/1987");
    profilePage.addTaste("spring");

    profilePage.saveProfile();

    takeScreenShot();
    searchResultPage.isAt();
    assertThat(searchResultPage.getNumberOfResults()).isEqualTo(2);
}
```

更易读了，不是吗？

## 使我们的测试更加 Groovy

如果你不了解 Groovy，可以将其视为 Java 的近亲，但没有冗长。Groovy 是一种具有可选类型的动态语言。这意味着当需要时，您可以获得类型系统的保证，并且在知道自己在做什么时，可以使用鸭子类型的多功能性。

使用这种语言，您可以编写没有 getter、setter、`equals`和`hashcode`方法的 POJOs。一切都为您处理。

写`==`实际上会调用`equals`方法。操作符可以被重载，这允许使用小箭头（例如`<<`）向文件中写入文本。这也意味着您可以将整数添加到`BigIntegers`并获得正确的结果。

**Groovy 开发工具包**（**GDK**）还为经典的 Java 对象添加了几种非常有趣的方法。它还将正则表达式和闭包视为一等公民。

### 注意

如果您想对 Groovy 有一个扎实的介绍，请查看[`www.groovy-lang.org/style-guide.html`](http://www.groovy-lang.org/style-guide.html)上的 Groovy 风格指南。

您还可以观看 Peter Ledbrook 在[`www.infoq.com/presentations/groovy-for-java`](http://www.infoq.com/presentations/groovy-for-java)上的精彩演示。

就我个人而言，我总是试图在我工作的应用程序的测试方面推动 Groovy。这确实提高了代码的可读性和开发人员的生产力。

## 使用 Spock 进行单元测试

为了能够在我们的项目中编写 Groovy 测试，我们需要使用 Groovy 插件而不是 Java 插件。

以下是您构建脚本中的内容：

```java
apply plugin: 'java'
```

将其更改为以下内容：

```java
apply plugin: 'groovy'
```

这种修改是完全无害的。Groovy 插件扩展了 Java 插件，因此它唯一的区别是它可以在`src/main/groovy`、`src/test/groovy`和`src/integrationTest/groovy`中添加 Groovy 源。

显然，我们还需要将 Groovy 添加到类路径中。我们还将通过`spock-spring`依赖项添加 Spock，这将使其与 Spring 兼容，这是最受欢迎的 Groovy 测试库：

```java
testCompile 'org.codehaus.groovy:groovy-all:2.4.4:indy'
testCompile 'org.spockframework:spock-spring'
```

现在我们可以用不同的方法重写`HomeControllerTest`。让我们在`src/test/groovy`中创建一个`HomeControllerSpec`类。我将其添加到`masterSpringMvc.controller`包中，就像我们的第一个`HomeControllerTest`实例一样：

```java
package masterSpringMvc.controller

import masterSpringMvc.MasterSpringMvcApplication
import masterSpringMvc.search.StubTwitterSearchConfig
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.SpringApplicationContextLoader
import org.springframework.test.context.ContextConfiguration
import org.springframework.test.context.web.WebAppConfiguration
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.setup.MockMvcBuilders
import org.springframework.web.context.WebApplicationContext
import spock.lang.Specification

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@ContextConfiguration(loader = SpringApplicationContextLoader,
        classes = [MasterSpringMvcApplication, StubTwitterSearchConfig])
@WebAppConfiguration
class HomeControllerSpec extends Specification {
    @Autowired
    WebApplicationContext wac;

    MockMvc mockMvc;

    def setup() {
        mockMvc = MockMvcBuilders.webAppContextSetup(this.wac).build();
    }

    def "User is redirected to its profile on his first visit"() {
        when: "I navigate to the home page"
        def response = this.mockMvc.perform(get("/"))

        then: "I am redirected to the profile page"
        response
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/profile"))
    }
}
```

我们的测试立即变得更易读，因为我们可以使用字符串作为方法名，并且 Spock 提供了小的 BDD DSL（领域特定语言）。这在这里并不直接可见，但`then`块内的每个语句都将隐式地成为一个断言。

在撰写本文时，由于 Spock 不读取元注解，因此无法使用`@SpringApplicationConfiguration`注解，因此我们只是用`@ContextConfiguration(loader = SpringApplicationContextLoader)`替换了它，这本质上是一样的。

现在我们有了相同测试的两个版本，一个是 Java，另一个是 Groovy。由您来选择最适合您编码风格的版本，并删除另一个版本。如果您决定坚持使用 Groovy，您将不得不用 Groovy 重写`should_redirect_to_tastes()`测试。这应该很容易。

Spock 还对模拟有强大的支持。我们可以稍微不同地重写之前的`SearchControllerMockTest`类：

```java
package masterSpringMvc.search

import masterSpringMvc.MasterSpringMvcApplication
import org.springframework.boot.test.SpringApplicationContextLoader
import org.springframework.test.context.ContextConfiguration
import org.springframework.test.context.web.WebAppConfiguration
import org.springframework.test.web.servlet.setup.MockMvcBuilders
import spock.lang.Specification

import static org.hamcrest.Matchers.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@ContextConfiguration(loader = SpringApplicationContextLoader,
        classes = [MasterSpringMvcApplication])
@WebAppConfiguration
class SearchControllerMockSpec extends Specification {
    def twitterSearch = Mock(TwitterSearch)
    def searchController = new SearchController(twitterSearch)

    def mockMvc = MockMvcBuilders.standaloneSetup(searchController)
            .setRemoveSemicolonContent(false)
            .build()

    def "searching for the spring keyword should display the search page"() {
        when: "I search for spring"
        def response = mockMvc.perform(get("/search/mixed;keywords=spring"))

        then: "The search service is called once"
        1 * twitterSearch.search(_, _) >> [new LightTweet('tweetText')]

        and: "The result page is shown"
        response
                .andExpect(status().isOk())
                .andExpect(view().name("resultPage"))

        and: "The model contains the result tweets"
        response
                .andExpect(model().attribute("tweets", everyItem(
                hasProperty("text", is("tweetText"))
        )))
    }
}
```

Mockito 的所有冗长都已经消失。`then`块实际上断言了`twitterSearch`方法被调用一次(`1 *`)，并且带有任何参数(`_, _`)。与 mockito 一样，我们也可以期望特定的参数。

双箭头`>>`语法用于从模拟方法返回对象。在我们的情况下，它是包含一个元素的列表。

只需在我们的类路径中添加少量依赖，我们就已经编写了更易读的测试，但我们还没有完成。我们还将重构我们的验收测试以使用 Geb，这是一个可以驱动 Selenium 测试的 Groovy 库。

## 使用 Geb 进行集成测试

Geb 是在 Grails 框架中编写测试的事实上的库。尽管它的版本是 0.12.0，但它非常稳定，非常舒适。

它提供了类似 jQuery 的选择器 API，使得即使对于前端开发人员来说，编写测试也变得很容易。Groovy 也是一种具有一些 JavaScript 影响的语言，这也会吸引他们。

让我们在类路径中添加支持 Spock 规范的 Geb：

```java
testCompile 'org.gebish:geb-spock:0.12.0'
```

可以通过在`src/integrationTest/groovy`的根目录下找到的 Groovy 脚本`GebConfig.groovy`来配置 Geb：

```java
import org.openqa.selenium.Dimension
import org.openqa.selenium.firefox.FirefoxDriver
import org.openqa.selenium.phantomjs.PhantomJSDriver

reportsDir = new File('./build/geb-reports')
driver = {
        def driver = new FirefoxDriver()
    // def driver = new PhantomJSDriver()
    driver.manage().window().setSize(new Dimension(1024, 768))
    return driver
}
```

在这个配置中，我们指示 Geb 将生成其报告的位置以及要使用的驱动程序。Geb 中的报告是增强版的屏幕截图，还包含当前页面的 HTML。可以通过在 Geb 测试中调用`report`函数来随时触发它们的生成。

让我们用 Geb 重写我们的第一个集成测试：

```java
import geb.Configuration
import geb.spock.GebSpec
import masterSpringMvc.MasterSpringMvcApplication
import masterSpringMvc.search.StubTwitterSearchConfig
import org.springframework.beans.factory.annotation.Value
import org.springframework.boot.test.SpringApplicationContextLoader
import org.springframework.boot.test.WebIntegrationTest
import org.springframework.test.context.ContextConfiguration

@ContextConfiguration(loader = SpringApplicationContextLoader,
        classes = [MasterSpringMvcApplication, StubTwitterSearchConfig])
@WebIntegrationTest(randomPort = true)
class IntegrationSpec extends GebSpec {

    @Value('${local.server.port}')
    int port

    Configuration createConf() {
        def configuration = super.createConf()
        configuration.baseUrl = "http://localhost:$port"
        configuration
    }

    def "User is redirected to the login page when not logged"() {
        when: "I navigate to the home page"
        go '/'
//        report 'navigation-redirection'

        then: "I am redirected to the profile page"
        $('h2', 0).text() == 'Login'
    }
}
```

目前，它与 FluentLenium 非常相似。我们已经可以看到`$`函数，它将允许我们通过其选择器抓取 DOM 元素。在这里，我们还声明了我们要通过给定的`0`索引在页面中找到第一个`h2`。

## 使用 Geb 的页面对象

使用 Geb 的页面对象真是一种真正的乐趣。我们将创建与之前相同的页面对象，以便您可以欣赏到其中的区别。

使用 Geb，页面对象必须继承自`geb.Page`类。首先，让我们创建`LoginPage`。我建议避免将其放在与之前相同的包中。我创建了一个名为`geb.pages`的包：

```java
package geb.pages

import geb.Page

class LoginPage extends Page {

    static url = '/login'
    static at = { $('h2', 0).text() == 'Login' }
    static content = {
        twitterSignin { $('button', name: 'twitterSignin') }
    }

    void loginWithTwitter() {
        twitterSignin.click()
    }
}
```

然后我们可以创建`ProfilePage`：

```java
package geb.pages

import geb.Page

class ProfilePage extends Page {

    static url = '/profile'
    static at = { $('h2', 0).text() == 'Your profile' }
    static content = {
        addTasteButton { $('button', name: 'addTaste') }
        saveButton { $('button', name: 'save') }
    }

    void fillInfos(String twitterHandle, String email, String birthDate) {
        $("#twitterHandle") << twitterHandle
        $("#email") << email
        $("#birthDate") << birthDate
    }

    void addTaste(String taste) {
        addTasteButton.click()
        $("#tastes0") << taste
    }

    void saveProfile() {
        saveButton.click();
    }
}
```

这基本上与以前的页面相同。请注意小的`<<`用于为输入元素分配值。您也可以在它们上调用`setText`。

`at`方法完全属于框架的一部分，当您导航到相应的页面时，Geb 将自动断言这些方法。

让我们创建`SearchResultPage`：

```java
package geb.pages

import geb.Page

class SearchResultPage extends Page {
    static url = '/search'
    static at = { $('h2', 0).text().startsWith('Tweet results for') }
    static content = {
        resultList { $('ul.collection') }
        results { resultList.find('li') }
    }
}
```

由于能够重用先前定义的内容，它会变得更短。

在没有设置页面对象的情况下，我们可以编写以下测试：

```java
import geb.Configuration
import geb.pages.LoginPage
import geb.pages.ProfilePage
import geb.pages.SearchResultPage
import geb.spock.GebSpec
import masterSpringMvc.MasterSpringMvcApplication
import masterSpringMvc.auth.StubSocialSigninConfig
import masterSpringMvc.search.StubTwitterSearchConfig
import org.springframework.beans.factory.annotation.Value
import org.springframework.boot.test.SpringApplicationContextLoader
import org.springframework.boot.test.WebIntegrationTest
import org.springframework.test.context.ContextConfiguration

@ContextConfiguration(loader = SpringApplicationContextLoader,
        classes = [MasterSpringMvcApplication, StubTwitterSearchConfig, StubSocialSigninConfig])
@WebIntegrationTest(randomPort = true)
class IntegrationSpec extends GebSpec {

    @Value('${local.server.port}')
    int port

    Configuration createConf() {
        def configuration = super.createConf()
        configuration.baseUrl = "http://localhost:$port"
        configuration
    }

    def "User is redirected to the login page when not logged"() {
        when: "I navigate to the home page"
        go '/'

        then: "I am redirected to the login page"
        $('h2').text() == 'Login'
    }

    def "User is redirected to its profile on his first visit"() {
        when: 'I am connected'
        to LoginPage
        loginWithTwitter()

        and: "I navigate to the home page"
        go '/'

        then: "I am redirected to the profile page"
        $('h2').text() == 'Your profile'
    }

    def "After filling his profile, the user is taken to result matching his tastes"() {
        given: 'I am connected'
        to LoginPage
        loginWithTwitter()

        and: 'I am on my profile'
        to ProfilePage

        when: 'I fill my profile'
        fillInfos("geowarin", "geowarin@mymail.com", "03/19/1987");
        addTaste("spring")

        and: 'I save it'
        saveProfile()

        then: 'I am taken to the search result page'
        at SearchResultPage
        page.results.size() == 2
    }
}
```

哇，多么美丽！您肯定可以直接使用 Geb 编写用户故事！

通过我们简单的测试，我们只是触及了 Geb 的表面。还有更多功能可用，我鼓励您阅读*Geb 之书*，这是一份非常好的文档，可在[`www.gebish.org/manual/current/`](http://www.gebish.org/manual/current/)上找到。

# 检查点

在本章中，我们在 `src/test/java` 中添加了一堆测试。我选择使用 Groovy，所以我删除了重复的测试：

![检查点](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00981.jpeg)

在 `src/test/groovy` 目录中，我已经重构了两个测试如下：

![检查点](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00982.jpeg)

在 `src/integrationTest/groovy` 中，我们有一个使用 Geb 编写的集成测试：

![检查点](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00983.jpeg)

最后，我们在 Gradle 构建中添加了一个 `integrationTest` 任务。运行 `gradle clean test` 和 `gradle clean integrationTest` 来确保所有测试都通过。

如果构建成功，我们准备进入下一章。

# 总结

在本章中，我们研究了单元测试和集成测试之间的区别。

我们看到测试是一个健康的习惯，将使我们对我们构建和发布的内容充满信心。这将在长远来看为我们节省金钱并减少一些头痛。

Spring 与经典的使用 Java 编写的 JUnit 测试很好配合，并且对集成测试有一流的支持。但我们也可以轻松地使用其他语言，比如 Groovy，使测试更易读和更易写。

测试无疑是 Spring 框架的最大优势之一，也是首次使用依赖注入的主要原因之一。

敬请关注下一章，我们将优化我们的应用程序，使其准备好在云中部署！

