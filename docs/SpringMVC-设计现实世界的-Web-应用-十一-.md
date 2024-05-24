# SpringMVC：设计现实世界的 Web 应用（十一）

> 原文：[`zh.annas-archive.org/md5/AB3510E97B9E20602840C849773D49C6`](https://zh.annas-archive.org/md5/AB3510E97B9E20602840C849773D49C6)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第二十三章：优化您的请求

在本章中，我们将研究不同的技术来提高我们应用程序的性能。

我们将实现优化 Web 应用程序的经典方法：缓存控制头、Gzipping、应用程序缓存和 ETags，以及更具反应性的内容，如异步方法调用和 WebSockets。

# 生产配置文件

在上一章中，我们看到了如何定义一个应用程序属性文件，该文件只在使用特定配置文件启动应用程序时才会被读取。我们将使用相同的方法，在 `src/main/resources` 目录中创建一个 `application-prod.properties` 文件，就在现有的 `application.properties` 文件旁边。这样，我们将能够使用优化设置配置生产环境。

我们将在这个文件中放入一些属性以开始。在第二章中，*处理表单和复杂的 URL 映射*，我们停用了 Thymeleaf 缓存，并强制翻译捆绑包在每次访问时重新加载。

这对开发很有用，但在生产中是无用且耗时的。所以让我们来解决这个问题：

```java
spring.thymeleaf.cache=true
spring.messages.cache-seconds=-1
```

缓存期限为 `-1` 表示永久缓存捆绑包。

现在，如果我们使用 "prod" 配置文件启动应用程序，模板和捆绑包应该永久缓存。

来自 "prod" 配置文件的属性确实会覆盖我们 `application.properties` 文件中声明的属性。

# Gzipping

**Gzipping** 是一种被浏览器广泛理解的压缩算法。您的服务器将提供压缩响应，这将消耗更多的 CPU 周期，但将节省带宽。

然后客户端浏览器将为解压资源和向用户显示资源而付费。

要利用 Tomcat 的 Gzipping 能力，只需将以下行添加到 `application-prod.properties` 文件中：

```java
server.tomcat.compression=on
server.tomcat.compressableMimeTypes=text/html,text/xml,text/css,text/plain,\
  application/json,application/xml,application/javascript
```

这将在提供与列表中指定的 MIME 类型匹配且长度大于 2048 字节的任何文件时启用 Tomcat 的 Gzipping 压缩。您可以将 `server.tomcat.compression` 设置为 `force` 以强制压缩，或者将其设置为数字值，如果您想更改 Gzipped 资产的最小长度值。

如果您想更多地控制压缩，比如压缩级别，或者想排除用户代理不进行压缩，您可以通过将 `org.eclipse.jetty:jetty-servlets` 依赖项添加到您的项目中，使用 Jetty 中的 `GzipFilter` 类。

这将自动触发`GzipFilterAutoConfiguration`类，可以通过以`spring.http.gzip`为前缀的一些属性进行配置。查看`GzipFilterProperties`以了解其自定义级别。

### 注意

有关更多信息，请参阅[`docs.spring.io/spring-boot/docs/current/reference/html/howto-embedded-servlet-containers.html#how-to-enable-http-response-compression`](http://docs.spring.io/spring-boot/docs/current/reference/html/howto-embedded-servlet-containers.html#how-to-enable-http-response-compression)上的文档。

# 缓存控制

缓存控制是由服务器发送的一组 HTTP 头，用于控制用户的浏览器允许缓存资源的方式。

在上一章中，我们已经看到 Spring Security 自动禁用了受保护资源的缓存。

如果我们想要从缓存控制中受益，我们必须首先禁用该功能：

```java
security.headers.cache=false

# Cache resources for 3 days
spring.resources.cache-period=259200
```

现在，启动应用程序，转到主页，并检查 Chrome 开发者控制台。您会看到我们的 JavaScript 文件已经被 Gzip 压缩和缓存，如下截图所示：

![缓存控制](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00984.jpeg)

如果您想对缓存有更多控制，可以在配置中为自己的资源添加处理程序：

```java
@Override
public void addResourceHandlers(ResourceHandlerRegistry registry) {
    // This is just an example
    registry.addResourceHandler("/img/**")
            .addResourceLocations("classpath:/static/images/")
            .setCachePeriod(12);
}
```

我们还可以覆盖 Spring Security 的默认设置。如果我们想要为我们的 API 停用“无缓存控制”策略，我们可以像这样更改`ApiSecurityConfiguration`类：

```java
@Override
protected void configure(HttpSecurity http) throws Exception {
    http
        .antMatcher("/api/**")
// This is just an example – not required in our case
        .headers().cacheControl().disable()
        .httpBasic().and()
        .csrf().disable()
        .authorizeRequests()
        .antMatchers(HttpMethod.GET).hasRole("USER")
        .antMatchers(HttpMethod.POST).hasRole("ADMIN")
        .antMatchers(HttpMethod.PUT).hasRole("ADMIN")
        .antMatchers(HttpMethod.DELETE).hasRole("ADMIN")
        .anyRequest().authenticated();
}
```

# 应用程序缓存

现在我们的网络请求已经被压缩和缓存，我们可以采取的下一步措施是将昂贵操作的结果放入缓存以减少服务器负载。Twitter 搜索需要一些时间，并且会消耗我们在 Twitter API 上的应用程序请求比例。使用 Spring，我们可以轻松地缓存搜索并在每次使用相同参数调用搜索时返回相同的结果。

我们需要做的第一件事是使用`@EnableCache`注解激活 Spring 缓存。我们还需要创建一个`CacheManager`来解析我们的缓存。让我们在`config`包中创建一个`CacheConfiguration`类：

```java
package masterSpringMvc.config;

import org.springframework.cache.CacheManager;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.cache.concurrent.ConcurrentMapCache;
import org.springframework.cache.support.SimpleCacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.Arrays;

@Configuration
@EnableCaching
public class CacheConfiguration {

    @Bean
    public CacheManager cacheManager() {
        SimpleCacheManager simpleCacheManager = new SimpleCacheManager();
        simpleCacheManager.setCaches(Arrays.asList(
                new ConcurrentMapCache("searches")
        ));
        return simpleCacheManager;
    }
}
```

在上一个例子中，我们使用了最简单的缓存抽象。还有其他可用的实现，比如`EhCacheCacheManager`或`GuavaCacheManager`，我们一会儿会用到。

现在我们已经配置了缓存，我们可以在我们的方法上使用`@Cacheable`注解。这样做时，Spring 将自动缓存方法的结果，并将其与当前参数关联以进行检索。

Spring 需要在缓存方法的 bean 周围创建代理。这通常意味着在同一个 bean 内调用缓存方法不会失败地使用 Spring 的缓存。

在我们的情况下，在`SearchService`类中，我们调用搜索操作的部分将受益于缓存。

作为预备步骤，最好将负责创建`SearchParameters`类的代码放在一个名为`SearchParamsBuilder`的专用对象中：

```java
package masterSpringMvc.search;

import org.springframework.social.twitter.api.SearchParameters;

import java.util.List;
import java.util.stream.Collectors;

public class SearchParamsBuilder {

    public static SearchParameters createSearchParam(String searchType, String taste) {
        SearchParameters.ResultType resultType = getResultType(searchType);
        SearchParameters searchParameters = new SearchParameters(taste);
        searchParameters.resultType(resultType);
        searchParameters.count(3);
        return searchParameters;
    }

    private static SearchParameters.ResultType getResultType(String searchType) {
        for (SearchParameters.ResultType knownType : SearchParameters.ResultType.values()) {
            if (knownType.name().equalsIgnoreCase(searchType)) {
                return knownType;
            }
        }
        return SearchParameters.ResultType.RECENT;
    }
}
```

这将帮助我们在我们的服务中创建搜索参数。

现在我们想为我们的搜索结果创建一个缓存。我们希望每次调用 Twitter API 时都会缓存。Spring 缓存注解依赖于代理来对`@Cacheable`方法进行检测。因此，我们需要一个新的类，其中的方法带有`@Cacheable`注解。

当您使用 Spring 抽象 API 时，您不知道缓存的底层实现。许多都要求缓存方法的返回类型和参数类型都是可序列化的。

`SearchParameters`不是可序列化的，这就是为什么我们将搜索类型和关键字（都是字符串）传递给缓存方法的原因。

由于我们想要将`LightTweets`对象放入缓存，我们希望使它们可序列化；这将确保它们始终可以从任何缓存抽象中写入和读取：

```java
public class LightTweet implements Serializable {
    // the rest of the code remains unchanged
}
```

让我们创建一个`SearchCache`类，并将其放在`search.cache`包中：

```java
package masterSpringMvc.search.cache;

import masterSpringMvc.search.LightTweet;
import masterSpringMvc.search.SearchParamsBuilder;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.social.TwitterProperties;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.social.twitter.api.SearchParameters;
import org.springframework.social.twitter.api.Twitter;
import org.springframework.social.twitter.api.impl.TwitterTemplate;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
public class SearchCache {
    protected final Log logger = LogFactory.getLog(getClass());
    private Twitter twitter;

    @Autowired
    public SearchCache(TwitterProperties twitterProperties) {
        this.twitter = new TwitterTemplate(twitterProperties.getAppId(), twitterProperties.getAppSecret());
    }

    @Cacheable("searches")
    public List<LightTweet> fetch(String searchType, String keyword) {
        logger.info("Cache miss for " + keyword);
        SearchParameters searchParam = SearchParamsBuilder.createSearchParam(searchType, keyword);
        return twitter.searchOperations()
                .search(searchParam)
                .getTweets().stream()
                .map(LightTweet::ofTweet)
                .collect(Collectors.toList());
    }
}
```

它真的不能再简单了。我们使用`@Cacheable`注释来指定将使用的缓存的名称。不同的缓存可能有不同的策略。

请注意，我们手动创建了一个新的`TwitterTemplate`方法，而不是像以前那样注入它。这是因为稍后我们将不得不从其他线程访问缓存。在 Spring Boot 的`TwitterAutoConfiguration`类中，`Twitter` bean 绑定到请求范围，因此在 Servlet 线程之外不可用。

有了这两个新对象，我们的`SearchService`类的代码就变成了这样：

```java
package masterSpringMvc.search;

import masterSpringMvc.search.cache.SearchCache;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
@Profile("!async")
public class SearchService implements TwitterSearch {
    private SearchCache searchCache;

    @Autowired
    public SearchService(SearchCache searchCache) {
        this.searchCache = searchCache;
    }

    @Override
    public List<LightTweet> search(String searchType, List<String> keywords) {
        return keywords.stream()
                .flatMap(keyword -> searchCache.fetch(searchType, keyword).stream())
                .collect(Collectors.toList());
    }
}
```

请注意，我们使用`@Profile("!async")`对服务进行了注释。这意味着只有在未激活`async`配置文件时，我们才会创建这个 bean。

稍后，我们将创建`TwitterSearch`类的另一个实现，以便能够在两者之间切换。

不错！假设我们重新启动应用程序并尝试一个大请求，比如以下内容：

`http://localhost:8080/search/mixed;keywords=docker,spring,spring%20boot,spring%20mvc,groovy,grails`

一开始可能需要一点时间，但然后我们的控制台将显示以下日志：

```java
2015-08-03 16:04:01.958  INFO 38259 --- [nio-8080-exec-8] m.search.cache.SearchCache               : Cache miss for docker
2015-08-03 16:04:02.437  INFO 38259 --- [nio-8080-exec-8] m.search.cache.SearchCache               : Cache miss for spring
2015-08-03 16:04:02.728  INFO 38259 --- [nio-8080-exec-8] m.search.cache.SearchCache               : Cache miss for spring boot
2015-08-03 16:04:03.098  INFO 38259 --- [nio-8080-exec-8] m.search.cache.SearchCache               : Cache miss for spring mvc
2015-08-03 16:04:03.383  INFO 38259 --- [nio-8080-exec-8] m.search.cache.SearchCache               : Cache miss for groovy
2015-08-03 16:04:03.967  INFO 38259 --- [nio-8080-exec-8] m.search.cache.SearchCache               : Cache miss for grails

```

之后，如果我们点击刷新，结果将立即显示，并且控制台中不会出现缓存未命中。

就我们的缓存而言，就缓存 API 而言还有很多内容。您可以使用以下方法对方法进行注释：

+   `@CachEvict`：这将从缓存中删除条目

+   `@CachePut`：这将把方法的结果放入缓存，而不会干扰方法本身

+   `@Caching`：这将重新组合缓存注释

+   `@CacheConfig`：这指向不同的缓存配置

`@Cacheable`注释也可以配置为根据某些条件缓存结果。

### 注意

有关 Spring 缓存的更多信息，请参阅以下文档：

[`docs.spring.io/spring/docs/current/spring-framework-reference/html/cache.html`](http://docs.spring.io/spring/docs/current/spring-framework-reference/html/cache.html)

## 缓存失效

目前，搜索结果将被永久缓存。使用默认的简单缓存管理器并不能给我们很多选项。我们可以做的另一件事是改进我们的应用程序缓存。由于我们的类路径中有 Guava，我们可以用以下代码替换缓存配置中的现有缓存管理器：

```java
package masterSpringMvc.config;

import com.google.common.cache.CacheBuilder;
import org.springframework.cache.CacheManager;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.cache.guava.GuavaCacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.concurrent.TimeUnit;

@Configuration
@EnableCaching
public class CacheConfiguration {

    @Bean
    public CacheManager cacheManager() {
        GuavaCacheManager cacheManager = new GuavaCacheManager("searches");
        cacheManager
                .setCacheBuilder(
                        CacheBuilder.newBuilder()
                                .softValues()
                                .expireAfterWrite(10, TimeUnit.MINUTES)
                );
        return cacheManager;
    }
}
```

这将构建一个在 10 分钟后过期并使用软值的缓存，这意味着如果 JVM 内存不足，条目将被清理。

尝试玩弄 Guava 的缓存构建器。您可以为测试指定更小的时间单位，甚至指定不同的缓存策略。

### 注意

请参阅[`code.google.com/p/guava-libraries/wiki/CachesExplained`](https://code.google.com/p/guava-libraries/wiki/CachesExplained)上的文档。

## 分布式缓存

我们已经有了一个 Redis 配置文件。如果 Redis 可用，我们还可以将其用作缓存提供程序。这将允许我们在多个服务器上分发缓存。让我们更改`RedisConfig`类：

```java
package masterSpringMvc.config;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.cache.CacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.context.annotation.Profile;
import org.springframework.data.redis.cache.RedisCacheManager;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.session.data.redis.config.annotation.web.http.EnableRedisHttpSession;

import java.util.Arrays;

@Configuration
@Profile("redis")
@EnableRedisHttpSession
public class RedisConfig {

    @Bean(name = "objectRedisTemplate")
    public RedisTemplate objectRedisTemplate(RedisConnectionFactory redisConnectionFactory) {
        RedisTemplate<Object, Object> template = new RedisTemplate<>();
        template.setConnectionFactory(redisConnectionFactory);
        return template;
    }

    @Primary @Bean
    public CacheManager cacheManager(@Qualifier("objectRedisTemplate") RedisTemplate template) {
        RedisCacheManager cacheManager = new RedisCacheManager(template);
        cacheManager.setCacheNames(Arrays.asList("searches"));
        cacheManager.setDefaultExpiration(36_000);
        return cacheManager;
    }
}
```

有了这个配置，如果我们使用"Redis"配置文件运行我们的应用程序，那么 Redis 缓存管理器将被用来代替`CacheConfig`类中定义的缓存管理器，因为它被`@Primary`注释。

这将允许缓存在需要在多个服务器上进行扩展时进行分布。Redis 模板用于序列化缓存返回值和参数，并且需要对象是`Serializable`。

# 异步方法

我们的应用程序仍然存在瓶颈；当用户搜索十个关键字时，每次搜索都会按顺序执行。我们可以通过使用不同的线程并同时启动所有搜索来轻松提高应用程序的速度。

要启用 Spring 的异步功能，必须使用`@EnableAsync`注释。这将透明地执行任何使用`@Async`注释的方法，使用`java.util.concurrent.Executor`。

可以通过实现`AsyncConfigurer`接口来自定义默认的执行程序。让我们在`config`包中创建一个名为`AsyncConfig`的新配置类：

```java
package masterSpringMvc.config;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.aop.interceptor.AsyncUncaughtExceptionHandler;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.AsyncConfigurer;
import org.springframework.scheduling.annotation.EnableAsync;

import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

@Configuration
@EnableAsync
public class AsyncConfiguration implements AsyncConfigurer {

    protected final Log logger = LogFactory.getLog(getClass());

    @Override
    public Executor getAsyncExecutor() {
        return Executors.newFixedThreadPool(10);
    }

    @Override
    public AsyncUncaughtExceptionHandler getAsyncUncaughtExceptionHandler() {
        return (ex, method, params) -> logger.error("Uncaught async error", ex);
    }
}
```

通过这种配置，我们确保在整个应用程序中不会分配超过 10 个线程来处理我们的异步任务。这在 Web 应用程序中非常重要，因为每个客户端都有一个专用的线程。您使用的线程越多，它们阻塞的时间越长，您可以处理的客户端请求就越少。

让我们注释我们的搜索方法并使其异步化。我们需要使其返回`Future`的子类型，这是一个表示异步结果的 Java 并发类。

我们将创建`TwitterSearch`类的新实现，该实现将在不同的线程中查询搜索 API。该实现有点棘手，所以我会将其分解成小部分。

首先，我们需要使用`@Async`注解对将查询 API 的方法进行注释，以告诉 Spring 使用我们的执行程序安排任务。同样，Spring 将使用代理来完成其工作，因此这个方法必须在调用它的服务的不同类中。如果这个组件也能使用我们的缓存，那就太好了。这将导致我们创建这个组件：

```java
@Component
private static class AsyncSearch {
    protected final Log logger = LogFactory.getLog(getClass());
    private SearchCache searchCache;

    @Autowired
    public AsyncSearch(SearchCache searchCache) {
        this.searchCache = searchCache;
    }

    @Async
    public ListenableFuture<List<LightTweet>> asyncFetch(String searchType, String keyword) {
        logger.info(Thread.currentThread().getName() + " - Searching for " + keyword);
        return new AsyncResult<>(searchCache.fetch(searchType, keyword));
    }
}
```

现在不要创建这个类。让我们先看看我们的服务需要什么。

`ListenableFuture`抽象允许我们在未来完成后添加回调，无论是在正确结果的情况下还是在发生异常时。

等待一堆异步任务的算法看起来像这样：

```java
@Override
public List<LightTweet> search(String searchType, List<String> keywords) {
    CountDownLatch latch = new CountDownLatch(keywords.size());
    List<LightTweet> allTweets = Collections.synchronizedList(new ArrayList<>());
    keywords
            .stream()
            .forEach(keyword -> asyncFetch(latch, allTweets, searchType, keyword));

    await(latch);
    return allTweets;
}
```

如果您不了解`CountDownLatch`方法，它只是一个简单的阻塞计数器。

`await()`方法将等待，直到锁存器达到 0 才解锁线程。

在前面的代码中显示的`asyncFetch`方法将为我们的`asynFetch`方法附加一个回调。回调将结果添加到`allTweets`列表中，并递减锁存器。一旦每个回调都被调用，该方法将返回所有推文。

明白了吗？这是最终代码：

```java
package masterSpringMvc.search;

import masterSpringMvc.search.cache.SearchCache;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Profile;
import org.springframework.scheduling.annotation.Async;
import org.springframework.scheduling.annotation.AsyncResult;
import org.springframework.social.twitter.api.SearchParameters;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;
import org.springframework.util.concurrent.ListenableFuture;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CountDownLatch;

@Service
@Profile("async")
public class ParallelSearchService implements TwitterSearch {
    private final AsyncSearch asyncSearch;

    @Autowired
    public ParallelSearchService(AsyncSearch asyncSearch) {
        this.asyncSearch = asyncSearch;
    }

    @Override
    public List<LightTweet> search(String searchType, List<String> keywords) {
        CountDownLatch latch = new CountDownLatch(keywords.size());
        List<LightTweet> allTweets = Collections.synchronizedList(new ArrayList<>());

        keywords
                .stream()
                .forEach(keyword -> asyncFetch(latch, allTweets, searchType, keyword));

        await(latch);
        return allTweets;
    }

    private void asyncFetch(CountDownLatch latch, List<LightTweet> allTweets, String searchType, String keyword) {
        asyncSearch.asyncFetch(searchType, keyword)
                .addCallback(
                        tweets -> onSuccess(allTweets, latch, tweets),
                        ex -> onError(latch, ex));
    }

    private void await(CountDownLatch latch) {
        try {
            latch.await();
        } catch (InterruptedException e) {
            throw new IllegalStateException(e);
        }
    }

    private static void onSuccess(List<LightTweet> results, CountDownLatch latch, List<LightTweet> tweets) {
        results.addAll(tweets);
        latch.countDown();
    }

    private static void onError(CountDownLatch latch, Throwable ex) {
        ex.printStackTrace();
        latch.countDown();
    }

    @Component
    private static class AsyncSearch {
        protected final Log logger = LogFactory.getLog(getClass());
        private SearchCache searchCache;

        @Autowired
        public AsyncSearch(SearchCache searchCache) {
            this.searchCache = searchCache;
        }

        @Async
        public ListenableFuture<List<LightTweet>> asyncFetch(String searchType, String keyword) {
            logger.info(Thread.currentThread().getName() + " - Searching for " + keyword);
            return new AsyncResult<>(searchCache.fetch(searchType, keyword));
        }
    }
}
```

现在，要使用这个实现，我们需要使用`async`配置文件运行应用程序。

我们可以通过用逗号分隔它们来同时运行多个活动配置文件，如下所示：

`--spring.profiles.active=redis,async`

如果我们对多个术语进行搜索，我们可以看到类似这样的东西：

```java
pool-1-thread-3 - Searching groovy
pool-1-thread-1 - Searching spring
pool-1-thread-2 - Searching java
```

这表明不同的搜索是并行进行的。

Java 8 实际上引入了一种称为`CompletableFuture`的新类型，这是一个更好的 API 来操作 futures。可完成的未来的主要问题是没有执行程序可以在没有一点代码的情况下与它们一起工作。这超出了本文的范围，但您可以查看我的博客了解有关该主题的文章：[`geowarin.github.io/spring/2015/06/12/completable-futures-with-spring-async.html`](http://geowarin.github.io/spring/2015/06/12/completable-futures-with-spring-async.html)。

### 注意

**免责声明**

以下部分包含大量的 JavaScript。显然，我认为你应该看一下代码，特别是如果 JavaScript 不是你最喜欢的语言的话。现在是学习它的时候了。话虽如此，即使 WebSocket 非常酷，也不是必需的。您可以放心地跳到最后一章并立即部署您的应用程序。

# ETags

我们的 Twitter 结果被整洁地缓存，因此刷新结果页面的用户不会触发对 Twitter API 的额外搜索。但是，即使结果没有改变，响应也会多次发送给这个用户，这将浪费带宽。

ETag 是 Web 响应数据的哈希值，并作为标头发送。客户端可以记住资源的 ETag，并使用`If-None-Match`标头将最后已知版本发送到服务器。这使得服务器可以在请求在此期间不发生变化时回答`304 Not Modified`。

Spring 有一个特殊的 Servlet 过滤器，称为`ShallowEtagHeaderFilter`，用于处理 ETags。只需将其添加为`MasterSpringMvc4Application`配置类中的一个 bean：

```java
@Bean
public Filter etagFilter() {
    return new ShallowEtagHeaderFilter();
}
```

只要响应没有缓存控制标头，这将自动生成响应的 ETags。

现在，如果我们查询我们的 RESTful API，我们可以看到 ETag 随服务器响应一起发送：

```java
> http GET 'http://localhost:8080/api/search/mixed;keywords=spring' -a admin:admin
HTTP/1.1 200 OK
Content-Length: 1276
Content-Type: application/json;charset=UTF-8
Date: Mon, 01 Jun 2015 11:29:51 GMT
ETag: "00a66d6dd835b6c7c60638eab976c4dd7"
Server: Apache-Coyote/1.1
Set-Cookie: JSESSIONID=662848E4F927EE9A1BA2006686ECFE4C; Path=/; HttpOnly

```

现在，如果我们再次请求相同的资源，在`If-None-Match`标头中指定我们知道的最后一个 ETag，服务器将自动以`304 Not Modified`状态响应：

```java
> http GET 'http://localhost:8080/api/search/mixed;keywords=spring' If-None-Match:'"00a66d6dd835b6c7c60638eab976c4dd7"' -a admin:admin
HTTP/1.1 304 Not Modified
Date: Mon, 01 Jun 2015 11:34:21 GMT
ETag: "00a66d6dd835b6c7c60638eab976c4dd7"
Server: Apache-Coyote/1.1
Set-Cookie: JSESSIONID=CA956010CF268056C241B0674C6C5AB2; Path=/; HttpOnly

```

### 提示

由于我们搜索的并行性质，不同关键字获取的推文可能以不同的顺序到达，这将导致 ETag 发生变化。如果您希望这种技术适用于多个搜索，请在将搜索结果发送到客户端之前考虑对搜索结果进行排序。

如果我们想利用它，显然需要重写我们的客户端代码来处理它们。我们将看到一个简单的解决方案，使用 jQuery 来做到这一点，使用浏览器的本地存储来保存用户的最新查询。

首先，从我们的模型中删除`tweets`变量；我们将不再从服务器进行搜索。您将需要修改一个或两个测试以反映这一变化。

在继续之前，让我们将 lodash 添加到我们的 JavaScript 库中。如果您不了解 lodash，可以将其添加到项目依赖项中，如下所示：

```java
compile 'org.webjars.bower:lodash:3.9.3'
```

将其添加到`default.html`布局中，就在 materialize 的 JavaScript 下面：

```java
<script src="img/lodash.js"></script>
```

我们将修改`resultPage.html`文件，并将推文应该出现的部分留空：

```java
<!DOCTYPE html>
<html 

      layout:decorator="layout/default">
<head lang="en">
    <title>Hello twitter</title>
</head>
<body>
<div class="row" layout:fragment="content">

    <h2 class="indigo-text center" th:text="|Tweet results for ${search}|">Tweets</h2>

    <ul id="tweets" class="collection">
 </ul>
</div>
</body>
</html>
```

然后，我们将在页面底部添加一个脚本元素，就在关闭 body 之前：

```java
<script layout:fragment="script" th:inline="javascript">
    /*<![CDATA[*/
    var baseUrl = /*[[@{/api/search}]]*/ "/";
    var currentLocation = window.location.href;
    var search = currentLocation.substr(currentLocation.lastIndexOf('/'));
    var url = baseUrl + search;
    /*]]>*/
</script>
```

上述脚本将负责构建我们请求的 URL。我们将通过发出简单的 jQuery AJAX 调用来使用它：

```java
$.ajax({
    url: url,
    type: "GET",
    beforeSend: setEtag,
    success: onResponse
});
```

我们将使用`beforeSend`回调在发出调用之前有机会修改请求标头：

```java
function getLastQuery() {
    return JSON.parse(localStorage.getItem('lastQuery')) || {};
}

function storeQuery(query) {
    localStorage.setItem('lastQuery', JSON.stringify(query));
}

function setEtag(xhr) {
    xhr.setRequestHeader('If-None-Match', getLastQuery().etag)
}
```

如您所见，我们可以轻松地从本地存储中读取和写入。这里的问题是本地存储只能处理字符串，因此我们必须将查询对象解析和序列化为 JSON。

如果 HTTP 状态是`304 Not Modified`，我们可以通过从本地存储中检索内容来处理响应：

```java
function onResponse(tweets, status, xhr) {
  if (xhr.status == 304) {
      console.log('Response has not changed');
      tweets = getLastQuery().tweets
  }

  var etag = xhr.getResponseHeader('Etag');
  storeQuery({tweets: tweets, etag: etag});

  displayTweets(tweets);
}

function displayTweets(tweets) {
  $('#tweets').empty();
  $.each(tweets, function (index, tweet) {
      addTweet(tweet);
  })
}
```

对于接下来将看到的`addTweet`函数，我使用了 lodash，这是一个非常有用的 JavaScript 实用程序库，用于生成模板。将推文添加到页面的函数可以编写如下：

```java
function addTweet(tweet) {
    var template = _.template('<li class="collection-item avatar">' +
        '<img class="circle" src="img/${tweet.profileImageUrl}" />' +
        '<span class="title">${tweet.user}</span>' +
        '<p>${tweet.text}</p>' +
        '</li>');

    $('#tweets').append(template({tweet: tweet}));
}
```

这是很多 JavaScript！使用 Backbone.js 等库将这种模式概括为单页面应用程序可能更有意义。尽管如此，这将作为一个简单的示例，展示如何在应用程序中实现 ETags。

如果您尝试多次刷新搜索页面，您会发现内容不会改变，并且会立即显示：

![ETags](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00985.jpeg)

ETags 还有其他用途，例如用于事务的乐观锁定（它让您知道客户端应该在任何时间上使用对象的哪个版本）。在服务器端在发送数据之前对数据进行哈希处理也是额外的工作，但它将节省带宽。

# WebSockets

我们可以考虑的另一种优化是在数据可用时将数据发送到客户端。由于我们在多个线程中获取搜索结果，数据将以多个块的形式到达。我们可以逐步发送它们，而不是等待所有结果。

Spring 对 WebSockets 有很好的支持，这是一种允许客户端与服务器保持长时间连接的协议。数据可以在连接的两端推送到 WebSockets，消费者将实时获取数据。

我们将使用一个名为 SockJS 的 JavaScript 库，以确保与所有浏览器兼容。如果我们的用户使用过时的浏览器，Sockjs 将自动切换到另一种策略。

我们还将使用 StompJS 连接到我们的消息代理。

将以下库添加到您的构建中：

```java
compile 'org.springframework.boot:spring-boot-starter-websocket'
compile 'org.springframework:spring-messaging'

compile 'org.webjars:sockjs-client:1.0.0'
compile 'org.webjars:stomp-websocket:2.3.3'
```

将 WebJars 添加到我们的默认 Thymeleaf 模板中：

```java
<script src="img/sockjs.js"></script>
<script src="img/stomp.js"></script>
```

要在我们的应用程序中配置 WebSockets，我们还需要添加一些配置：

```java
@Configuration
@EnableWebSocketMessageBroker
public class WebSocketConfiguration extends AbstractWebSocketMessageBrokerConfigurer {

    @Override
    public void configureMessageBroker(MessageBrokerRegistry config) {
        config.enableSimpleBroker("/topic");
        config.setApplicationDestinationPrefixes("/ws");
    }

    @Override
    public void registerStompEndpoints(StompEndpointRegistry registry) {
        registry.addEndpoint("/twitterSearch").withSockJS();
    }

}
```

这将配置我们应用程序中可用的不同频道。SockJS 客户端将连接到`twitterSearch`端点，并将数据推送到服务器上的`/ws/ channel`，并能够监听`/topic/`以进行更改。

这将允许我们在新的控制器中注入`SimpMessagingTemplate`，以便通过`/topic/searchResult`频道向客户端推送数据，如下所示：

```java
@Controller
public class SearchSocketController {
    private CachedSearchService searchService;
    private SimpMessagingTemplate webSocket;

    @Autowired
    public SearchSocketController(CachedSearchService searchService, SimpMessagingTemplate webSocket) {
        this.searchService = searchService;
        this.webSocket = webSocket;
    }

    @MessageMapping("/search")
    public void search(@RequestParam List<String> keywords) throws Exception {
        Consumer<List<LightTweet>> callback = tweet -> webSocket.convertAndSend("/topic/searchResults", tweet);
        twitterSearch(SearchParameters.ResultType.POPULAR, keywords, callback);
    }

    public void twitterSearch(SearchParameters.ResultType resultType, List<String> keywords, Consumer<List<LightTweet>> callback) {
        keywords.stream()
            .forEach(keyword -> {
                searchService.search(resultType, keyword)
                    .addCallback(callback::accept, Throwable::printStackTrace);
            });
    }
}
```

在我们的`resultPage`中，JavaScript 代码非常简单：

```java
var currentLocation = window.location.href;
var search = currentLocation.substr(currentLocation.lastIndexOf('=') + 1);

function connect() {
  var socket = new SockJS('/hello');
  stompClient = Stomp.over(socket);
  // stompClient.debug = null;
  stompClient.connect({}, function (frame) {
      console.log('Connected: ' + frame);

      stompClient.subscribe('/topic/searchResults', function (result) {
          displayTweets(JSON.parse(result.body));
      });

      stompClient.send("/app/search", {}, JSON.stringify(search.split(',')));
  });
}
```

`displayTweets`函数基本上与以前相同：

```java
function displayTweets(tweets) {
    $.each(tweets, function (index, tweet) {
        addTweet(tweet);
    })
}

function addTweet(tweet) {
    var template = _.template('<li class="collection-item avatar">' +
        '<img class="circle" src="img/${tweet.profileImageUrl}" />' +
        '<span class="title">${tweet.userName}</span>' +
        '<p>${tweet.text}</p>' +
        '</li>');

    $('#tweets').append(template({tweet: tweet}));
}
```

就是这样！客户端现在将实时接收应用程序中所有搜索的结果！

在将其推向生产之前，这将需要更多的工作。以下是一些想法：

+   为客户端创建子频道，以便私下监听更改

+   当客户端使用完毕时关闭频道

+   为新推文添加 CSS 过渡，以便用户感觉到它是实时的

+   使用真正的代理，如 RabbitMQ，允许后端与连接一起扩展

WebSocket 还有比这个简单示例更多的内容。不要忘记查看[`docs.spring.io/spring/docs/current/spring-framework-reference/html/websocket.html`](http://docs.spring.io/spring/docs/current/spring-framework-reference/html/websocket.html)上的文档以获取更多信息。

# 检查点

在本章中，我们创建了两个新的配置：`AsyncConfiguration`，它将允许我们使用`@Async`注解将任务提交给执行器，并且`CacheConfiguration`，它将创建一个`CacheManager`接口，并允许我们使用`@Cacheable`注解。由于我们可以使用 Redis 作为缓存管理器，我们还修改了`RedisConfig`类。

我们创建了一个`SearchCache`类，其中包含了推文的缓存，现在我们有两个`TwitterSearch`实现可供选择：老旧的`SearchService`，它将同步获取每个结果，以及`ParallelSearchService`，它将在不同的线程中发出每个查询：

![检查点](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00986.jpeg)

# 总结

在本章中，我们看到了与性能改进相关的两种不同哲学。一开始，我们试图通过缓存数据并尽可能少地使用与服务器的连接来减少客户端使用的带宽。

然而，在第二部分，我们开始做一些更高级的事情，允许搜索并行运行，并且每个客户端通过 Web 套接字与服务器保持同步的持久连接。这将允许客户端实时接收更新，我们的应用程序将感觉更具反应性，但会消耗更多的线程。

我强烈建议您在我们进入下一章并永久部署我们的应用程序之前，对结果进行完善！



# 第二十四章：将您的 Web 应用部署到云端

在本章中，我们将参观不同的云提供商，了解分布式架构的挑战和好处，并了解如何将您的 Web 应用程序部署到 Pivotal Web Services 和 Heroku。

# 选择您的主机

云托管有许多形式。对于开发人员来说，选择主要将在平台即服务（PaaS）和基础设施即服务（IaaS）之间进行。

使用最新的技术，您通常会有一台裸机，您可以管理并在其中安装应用程序所需的所有服务。

如果我们不考虑 Docker 等技术（这绝对是令人惊叹的，您绝对应该尝试一下），这与传统托管非常相似，其中您的运营团队将不得不设置和维护应用程序可以运行的环境。

另一方面，PaaS 使得在开发应用程序时轻松部署应用程序，只需简单的推送即可部署工作流程。

最知名的提供商有：

+   由 Pivotal 支持的 Cloud Foundry

+   由红帽提供的 OpenShift

+   Heroku 于 2010 年被 Salesforce 收购

这三个提供商各有优缺点。我将尝试为您概述这些。

## Cloud Foundry

由 Pivotal 支持，Pivotal Web 服务是由 Spring 背后的公司 Pivotal 维护的开源 PaaS Cloud Foundry 运行，并提供有趣的套餐。

他们提供 60 天的免费试用，其定价是您为实例分配的内存和您拥有的实例数量的函数。

他们的价格范围从每月 2.70 美元的最小（128 Mb）实例到每月 43.20 美元的 2 GB 实例。

如果您想尝试一下，免费试用不需要信用卡。他们有一个市场，可以轻松安装服务，如 Redis 或 Postgre SQL，但免费选项相对有限。他们有一个很好的命令行实用程序，可以从控制台管理您的应用程序。您可以使用构建包，也可以直接推送 JAR 文件进行部署。

### 提示

构建包将尝试猜测您正在使用的堆栈，并以最标准的方式构建您的应用程序（Maven 的`mvn package`，Gradle 的`./gradlew stage`等）。

### 注意

请参考以下网址提供的教程，将您的应用程序部署到 Cloud Foundry：

[`docs.cloudfoundry.org/buildpacks/java/gsg-spring.html`](http://docs.cloudfoundry.org/buildpacks/java/gsg-spring.html)

## OpenShift

**OpenShift**由 Red Hat 维护，并由 OpenShift Origin 提供支持，这是一个在 Google 的 Kubernetes 之上运行 Docker 容器的开源设施。

它的定价合理，并提供了很多自由度，因为它既是 PaaS 又是 IaaS。其定价是基于齿轮、运行应用程序的容器或服务（如 Jenkins 或数据库）。

OpenShift 有一个免费计划，提供三个小齿轮。您的应用程序每月必须闲置 24 小时，除非您输入您的计费信息。

额外或更大的齿轮按月收费，最小的约为 15 美元，最大的为 72 美元。

要在 OpenShift 上部署 Spring Boot 应用程序，您将需要使用自定义的 Do It Yourself cartridge。这比其他基于构建包的 PaaS 需要更多的工作，但也更容易配置。

查看博客文章，了解有关在 OpenShift 上使用 Spring Boot 的教程，网址为[`blog.codeleak.pl/2015/02/openshift-diy-build-spring-boot.html`](http://blog.codeleak.pl/2015/02/openshift-diy-build-spring-boot.html)。

## Heroku

Heroku 是一个知名的 PaaS，拥有广泛的文档和基于构建包的代码中心方法。它可以连接到许多称为附加组件的服务，但使用它们需要您的计费信息。

对于一个免费项目来说真的很有趣，而且很快就可以开始。不足之处是，如果您想扩展规模，它的直接成本将超过每月 25 美元。免费实例在 30 分钟的不活动后将进入睡眠模式，这意味着免费的 Heroku 应用程序加载时间总是需要 30 秒。

Heroku 拥有出色的管理仪表板和命令行工具。在本章中，我选择了 Heroku，因为它非常直接。您在这里掌握的概念适用于大多数 PaaS。

只要您不使用 Redis 附加组件，您可以遵循本章的大部分内容并部署您的应用程序，而无需提供信用卡信息。如果选择免费计划，您将不会被收费。

# 将您的 Web 应用程序部署到 Pivotal Web 服务

如果您想将您的应用程序部署到 Pivotal Web 服务（PWS），请参考本节。

## 安装 Cloud Foundry CLI 工具

创建 Cloud Foundry 应用程序的第一步是在 PWS 上设置一个帐户。这在[`docs.run.pivotal.io/starting/`](http://docs.run.pivotal.io/starting/)中有记录。

您将被要求创建一个组织，每个新组织都将在组织内创建一个默认空间（开发）。如下图所示：

![安装 Cloud Foundry CLI 工具](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00987.jpeg)

在左侧导航栏中，您将看到一个指向**工具**的链接，您可以从中下载 CLI。它也可以从开发者控制台中获得。选择适合您操作系统的适当软件包：

![安装 Cloud Foundry CLI 工具](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00988.jpeg)

## 组装应用程序

我们的应用程序只需要组装以进行部署。

PWS 的好处是您无需推送源代码即可部署。您可以生成 JAR，推送它，一切都将被自动检测。

我们可以使用以下命令将其打包以进行部署：

```java
./gradlew assemble

```

这将在`build/libs`目录中创建一个 jar 文件。此时，您可以执行以下命令。以下命令将将您的部署目标定位到 PWS（`run.pivotal.io`）中的空间：

```java
$ cf login -a api.run.pivotal.io -u <account email> -p <password> -o <organization> -s development

API endpoint: api.run.pivotal.io
Authenticating...
OK

Targeted org <account org>

Targeted space development

API endpoint:   https://api.run.pivotal.io (API version: 2.33.0) 
User:           <account email> 
Org:            <account organization> 
Space:          <account space>

```

成功登录后，您可以使用以下命令推送您的 jar 文件。您需要想出一个可用的名称：

```java
$ cf push your-app-name -p build/libs/masterSpringMvc-0.0.1-SNAPSHOT.jar

Creating app msmvc4 in org Northwest / space development as wlund@pivotal.io...
OK
Creating route msmvc4.cfapps.io...
OK
Binding msmvc4.cfapps.io to msmvc4...
OK
Uploading msmvc4...
Uploading app files from: build/libs/masterSpringMvc-0.0.1-SNAPSHOT.jar
Uploading 690.8K, 108 files
Done uploading 
OK
Starting app msmvc4 in org <Organization> / space development as <account email>
-----> Downloaded app package (15M)
-----> Java Buildpack Version: v3.1 | https://github.com/cloudfoundry/java-buildpack.git#7a538fb
-----> Downloading Open Jdk JRE 1.8.0_51 from https://download.run.pivotal.io/openjdk/trusty/x86_64/openjdk-1.8.0_51.tar.gz (1.5s)
 Expanding Open Jdk JRE to .java-buildpack/open_jdk_jre (1.4s)
-----> Downloading Open JDK Like Memory Calculator 1.1.1_RELEASE from https://download.run.pivotal.io/memory-calculator/trusty/x86_64/memory-calculator-1.1.1_RELEASE (0.1s)
 Memory Settings: -Xmx768M -Xms768M -XX:MaxMetaspaceSize=104857K -XX:MetaspaceSize=104857K -Xss1M
-----> Downloading Spring Auto Reconfiguration 1.7.0_RELEASE from https://download.run.pivotal.io/auto-reconfiguration/auto-reconfiguration-1.7.0_RELEASE.jar (0.0s)
-----> Uploading droplet (59M)
0 of 1 instances running, 1 starting
1 of 1 instances running

App started
OK
App msmvc4 was started using this command `CALCULATED_MEMORY=$($PWD/.java-buildpack/open_jdk_jre/bin/java-buildpack-memory-calculator-1.1.1_RELEASE -memorySizes=metaspace:64m.. -memoryWeights=heap:75,metaspace:10,stack:5,native:10 -totMemory=$MEMORY_LIMIT) && SERVER_PORT=$PORT $PWD/.java-buildpack/open_jdk_jre/bin/java -cp $PWD/.:$PWD/.java-buildpack/spring_auto_reconfiguration/spring_auto_reconfiguration-1.7.0_RELEASE.jar -Djava.io.tmpdir=$TMPDIR -XX:OnOutOfMemoryError=$PWD/.java-buildpack/open_jdk_jre/bin/killjava.sh $CALCULATED_MEMORY org.springframework.boot.loader.JarLauncher`

Showing health and status for app msmvc4 in org <Organization> / space development as <Account Email>
OK

requested state: started
instances: 1/1
usage: 1G x 1 instances
urls: msmvc4.cfapps.io
last uploaded: Tue Jul 28 22:04:08 UTC 2015
stack: cflinuxfs2
buildpack: java-buildpack=v3.1-https://github.com/cloudfoundry/java-buildpack.git#7a538fb java-main open-jdk-like-jre=1.8.0_51 open-jdk-like-memory-calculator=1.1.1_RELEASE spring-auto-reconfiguration=1.7.0_RELEASE

 state     since                    cpu    memory         disk         details 
#0   running   2015-07-28 03:05:04 PM   0.0%   450.9M of 1G   137M of 1G

```

平台正在为您执行很多工作。它提供了一个容器，并检测所需的构建包，本例中为 Java。

然后安装所需的 JDK 并上传我们指向的应用程序。它创建了一个应用程序的路由，并向我们报告，然后为我们启动了应用程序。

现在您可以在开发者控制台上查看应用程序：

![组装应用程序](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00989.jpeg)

选择突出显示的路由后，应用程序将可供使用。访问[`msmvc4.cfapps.io`](http://msmvc4.cfapps.io)，然后您将看到以下截图：

![组装应用程序](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00990.jpeg)

太棒了！

唯一还不能工作的是文件上传。但是，我们将在一分钟内解决这个问题。

## 激活 Redis

在您的应用程序服务中，您可以在许多服务之间进行选择。其中之一是 Redis Cloud，它具有 30MB 免费存储空间的免费计划。继续选择此计划。

在表格中，选择你喜欢的任何名称，并将服务绑定到你的应用程序。默认情况下，Cloud Foundry 将在你的环境中注入与服务相关的一些属性：

+   `cloud.services.redis.connection.host`

+   `cloud.services.redis.connection.port`

+   `cloud.services.redis.connection.password`

+   `cloud.services.redis.connection.uri`

这些属性将始终遵循相同的约定，因此在添加更多服务时很容易跟踪您的服务。

默认情况下，Cloud Foundry 启动 Spring 应用程序并激活 Cloud 配置文件。

我们可以利用这一点，在`src/main/resources`中创建一个`application-cloud.properties`文件，当我们的应用程序在 PWS 上运行时将使用该文件：

```java
spring.profiles.active=prod,redis

spring.redis.host=${cloud.services.redis.connection.host}
spring.redis.port=${cloud.services.redis.connection.port}
spring.redis.password=${cloud.services.redis.connection.password}

upload.pictures.uploadPath=file:/tmp
```

这将绑定我们的 Redis 实例到我们的应用程序，并激活两个额外的配置文件：`prod`和`redis`。

我们还更改了上传图片的路径。请注意，在云上使用文件系统遵守不同的规则。请参考以下链接获取更多详细信息：

[`docs.run.pivotal.io/devguide/deploy-apps/prepare-to-deploy.html#filesystem`](http://docs.run.pivotal.io/devguide/deploy-apps/prepare-to-deploy.html#filesystem)

我们需要做的最后一件事是停用一个 Spring Session 功能，在我们托管的实例上将不可用：

```java
@Bean
@Profile({"cloud", "heroku"})
public static ConfigureRedisAction configureRedisAction() {
    return ConfigureRedisAction.NO_OP;
}
```

### 注意

有关更多信息，请访问[`docs.spring.io/spring-session/docs/current/reference/html5/#api-redisoperationssessionrepository-sessiondestroyedevent`](http://docs.spring.io/spring-session/docs/current/reference/html5/#api-redisoperationssessionrepository-sessiondestroyedevent)。

您将看到此配置也将应用于 Heroku。

就是这样。您可以重新组装您的 Web 应用程序并再次推送它。现在，您的会话和应用程序缓存将存储在 Redis 中！

您可能希望探索市场，寻找其他可用功能，例如绑定到数据或消息服务，扩展应用程序以及管理超出本介绍范围的应用程序的健康状况。

玩得开心，享受平台提供的生产力！

# 在 Heroku 上部署您的 Web 应用程序

在本节中，我们将免费在 Heroku 上部署您的应用程序。我们甚至将使用免费的 Redis 实例来存储我们的会话和缓存。

## 安装工具

创建 Heroku 应用程序的第一件事是下载[`toolbelt.heroku.com`](https://toolbelt.heroku.com)上可用的命令行工具。

在 Mac 上，您还可以使用`brew`命令进行安装：

```java
> brew install heroku-toolbelt

```

在 Heroku 上创建一个帐户，并使用`heroku login`将工具包链接到您的帐户：

```java
> heroku login
Enter your Heroku credentials.
Email: geowarin@mail.com
Password (typing will be hidden):
Authentication successful.

```

然后，转到您的应用程序根目录，输入`heroku create appName --region eu`。将`appName`替换为您选择的名称。如果您不提供名称，它将自动生成：

```java
> heroku create appname --region eu
Creating appname... done, region is eu
https://appname.herokuapp.com/ | https://git.heroku.com/appname.git
Git remote heroku added

```

如果您已经使用 UI 创建了一个应用程序，那么转到您的应用程序根目录，然后简单地添加远程`heroku git:remote -a yourapp`。

这些命令的作用是向我们的 Git 存储库添加一个名为`heroku`的 Git 远程。在 Heroku 上部署的过程只是将您的分支之一推送到 Heroku。远程安装的 Git 挂钩将负责其余的工作。

如果您输入`git remote -v`命令，您应该会看到`heroku`版本：

```java
> git remote -v
heroku    https://git.heroku.com/appname.git (fetch)
heroku    https://git.heroku.com/appname.git (push)
origin    https://github.com/Mastering-Spring-MVC-4/mastering-spring-mvc4-code.git (fetch)
origin    https://github.com/Mastering-Spring-MVC-4/mastering-spring-mvc4-code.git (push)

```

## 设置应用程序

我们需要两个要素来在 Heroku 上运行 Gradle 应用程序：构建文件中的一个名为`stage`的任务，以及一个包含用于运行我们的应用程序的命令的小文件，名为`ProcFile`。

### Gradle

Gradle 构建包将自动尝试在您的应用程序根目录上运行`./gradlew stage`命令。

### 注意

您可以在[`github.com/heroku/heroku-buildpack-gradle`](https://github.com/heroku/heroku-buildpack-gradle)上获取有关 Gradle 构建包的更多信息。

我们还没有"stage"任务。将以下代码添加到您的`build.gradle`文件中：

```java
task stage(type: Copy, dependsOn: [clean, build]) {
    from jar.archivePath
    into project.rootDir
    rename {
        'app.jar'
    }
}
stage.mustRunAfter(clean)

clean << {
    project.file('app.jar').delete()
}
```

这将定义一个名为`stage`的任务，它将复制 Spring Boot 在应用程序根目录生成的 jar 文件，并将其命名为`app.jar`。

这样查找 jar 文件会容易得多。`stage`任务依赖于`clean`任务和`build`任务，这意味着在开始`stage`任务之前，两者都将被执行。

默认情况下，Gradle 将尝试优化任务依赖图。因此，我们必须提供一个提示，并强制运行`stage`之前运行`clean`任务。

最后，我们向已经存在的`clean`任务添加了一个新的指令，即删除生成的`app.jar`文件。

现在，如果您运行`./gradlew stage`，它应该运行测试并将打包的应用程序放在项目的根目录。

### Procfile

当 Heroku 检测到一个 Gradle 应用程序时，它将自动运行一个安装了 Java 8 的容器。因此，我们需要非常少的配置。

我们需要一个包含用于运行我们的应用程序的 shell 命令的文件。在您的应用程序根目录创建一个名为`Procfile`的文件：

```java
web: java -Dserver.port=$PORT -Dspring.profiles.active=heroku,prod -jar app.jar
```

这里有几件事情需要注意。首先，我们将我们的应用程序声明为 Web 应用程序。我们还重新定义了应用程序将在其上运行的端口，使用环境变量。这非常重要，因为您的应用程序将与许多其他应用程序共存，每个应用程序只分配一个端口。

最后，您可以看到我们的应用程序将使用两个配置文件运行。第一个是我们在上一章中创建的`prod`配置文件，用于优化性能，还有一个新的`heroku`配置文件，我们将在稍后创建。

## 一个 Heroku 配置文件

我们不希望将诸如我们的 Twitter 应用程序密钥之类的敏感信息放入源代码控制中。因此，我们必须创建一些属性，以从应用程序环境中读取这些属性：

```java
spring.social.twitter.appId=${twitterAppId}
spring.social.twitter.appSecret=${twitterAppSecret}
```

为了使这个工作，您必须在 Heroku 上配置我们之前讨论过的两个环境变量。您可以使用工具包来完成这个任务：

```java
> heroku config:set twitterAppId=appId
```

或者，您可以转到您的仪表板，并在设置选项卡中配置环境：

![一个 Heroku 配置文件](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00991.jpeg)

### 注意

访问[`devcenter.heroku.com/articles/config-vars`](https://devcenter.heroku.com/articles/config-vars)获取更多信息。

## 运行您的应用程序

现在是时候在 Heroku 上运行我们的应用程序了！

如果您还没有这样做，请将所有更改提交到主分支。现在，只需将主分支推送到`heroku`远程，使用`git push heroku master`。这将下载所有依赖项并从头构建您的应用程序，因此可能需要一些时间：

```java
> git push heroku master
Counting objects: 1176, done.
Delta compression using up to 8 threads.
Compressing objects: 100% (513/513), done.
Writing objects: 100% (1176/1176), 645.63 KiB | 0 bytes/s, done.
Total 1176 (delta 485), reused 1176 (delta 485)
remote: Compressing source files... done.
remote: Building source:
remote:
remote: -----> Gradle app detected
remote: -----> Installing OpenJDK 1.8... done
remote: -----> Building Gradle app...
remote:        WARNING: The Gradle buildpack is currently in Beta.
remote: -----> executing ./gradlew stage
remote:        Downloading https://services.gradle.org/distributions/gradle-2.3-all.zip

...

remote:        :check
remote:        :build
remote:        :stage
remote:
remote:        BUILD SUCCESSFUL
remote:
remote:        Total time: 2 mins 36.215 secs
remote: -----> Discovering process types
remote:        Procfile declares types -> web
remote:
remote: -----> Compressing... done, 130.1MB
remote: -----> Launching... done, v4
remote:        https://appname.herokuapp.com/ deployed to Heroku
remote:
remote: Verifying deploy.... done.
To https://git.heroku.com/appname.git
* [new branch]      master -> master

```

应用程序构建完成后，它将自动运行。输入`heroku logs`以查看最新日志，或者输入`heroku logs -t`以跟踪它们。

您可以在控制台上看到您的应用程序正在运行，如果一切按计划进行，您将能够连接到[`yourapp.herokuapp.com`](http://yourapp.herokuapp.com)。如下面的截图所示：

![运行您的应用程序](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00992.jpeg)

我们在线了！是时候告诉您的朋友了！

## 激活 Redis

要在我们的应用程序中激活 Redis，我们可以在几种选择之间进行选择。Heroku Redis 附加组件是测试版。它完全免费，带有 20MB 的存储空间，分析和日志记录。

### 注意

访问[`elements.heroku.com/addons/heroku-redis`](https://elements.heroku.com/addons/heroku-redis)以获取更多详细信息。

在这个阶段，您将需要提供您的信用卡详细信息以继续。

要为您的应用程序安装 Redis 附加组件，请输入以下内容：

```java
heroku addons:create heroku-redis:test

```

现在，我们已经激活了附加组件，当我们的应用程序在 Heroku 上运行时，将会有一个名为`REDIS_URL`的环境变量可用。

您可以使用`heroku config`命令检查该变量是否已定义：

```java
> heroku config
=== masterspringmvc Config Vars
JAVA_OPTS:        -Xmx384m -Xss512k -XX:+UseCompressedOops
REDIS_URL:        redis://x:xxx@ec2-xxx-xx-xxx-xxx.eu-west-1.compute.amazonaws.com:6439

```

由于`RedisConnectionFactory`类不理解 URI，我们需要稍微调整一下：

```java
@Configuration
@Profile("redis")
@EnableRedisHttpSession
public class RedisConfig {

    @Bean
    @Profile("heroku")
    public RedisConnectionFactory redisConnectionFactory() throws URISyntaxException {
        JedisConnectionFactory redis = new JedisConnectionFactory();

        String redisUrl = System.getenv("REDIS_URL");
        URI redisUri = new URI(redisUrl);
        redis.setHostName(redisUri.getHost());
        redis.setPort(redisUri.getPort());
        redis.setPassword(redisUri.getUserInfo().split(":", 2)[1]);

        return redis;
    }

    @Bean
         @Profile({"cloud", "heroku"})
    public static ConfigureRedisAction configureRedisAction() {
        return ConfigureRedisAction.NO_OP;
    }
}
```

我们现在在`RedisConfig`类中有两个 Heroku 特定的 bean。这些 bean 只有在`redis`和`heroku`配置文件都激活时才会生效。

请注意，我们还停用了一些 Spring Session 配置。

Spring Session 通常会通过 Redis Pub/Sub 接口监听与销毁会话密钥相关的事件。

它将自动尝试配置 Redis 环境以在启动时激活监听器。在我们这样的安全环境中，除非您拥有管理员访问权限，否则不允许添加监听器。

在我们的情况下，这些 redis 监听器并不是非常重要，所以我们可以安全地禁用这种行为。欲了解更多信息，请访问[`docs.spring.io/spring-session/docs/current/reference/html5/#api-redisoperationssessionrepository-sessiondestroyedevent`](http://docs.spring.io/spring-session/docs/current/reference/html5/#api-redisoperationssessionrepository-sessiondestroyedevent)。

我们需要修改我们的`Procfile`文件，以便 Heroku 使用`redis`配置运行我们的应用程序：

```java
web: java -Dserver.port=$PORT -Dspring.profiles.active=heroku,redis,prod -jar app.jar
```

提交您的更改并将代码推送到 Heroku。

# 改进您的应用程序

我们已经在线部署了一个相当不错的应用程序，但在您进行改进之前，它既不是非常有用，也不是非常原创。

尝试使其更好，更个性化。一旦您为自己的成就感到自豪，请在 Twitter 上使用`#masterspringmvc`标签推文您的应用程序 URL。

尝试推出尽可能最好的应用程序。我们还有很多事情没有做。以下是一些想法：

+   删除用户的旧图片以避免保留未使用的图片

+   使用 Twitter 身份验证信息填充用户配置文件

+   与用户帐户进行交互

+   使用 Web 套接字频道查看应用程序上正在进行的实时搜索

让您的想象力飞翔！

我的版本的应用程序部署在[`masterspringmvc.herokuapp.com`](http://masterspringmvc.herokuapp.com)。我将改进一些细节，使应用程序更具反应性。试着找出不同之处！

# 摘要

在云提供商上部署我们的应用程序非常简单，因为它是一个可运行的 jar 包，这要归功于 Spring Boot。云部署现在非常实惠，部署 Java 应用程序几乎变得太容易了。

通过 Redis 支持的会话，我们奠定了可扩展应用程序的基础。事实上，我们可以轻松地在负载均衡器后面添加多个服务器，并根据需求吸收高流量。

唯一不可扩展的是我们的 WebSocket，它需要额外的工作才能在消息代理（如 Rabbit MQ）之上运行。

我肯定还记得以前很难找到运行 Tomcat 的主机，并且价格昂贵。那些日子已经一去不复返，未来属于 Web 开发人员，所以让它发生吧！

在下一章中，我们将看看如何使我们的应用程序变得更好，讨论我们尚未涵盖的技术，谈论 Spring 生态系统的一般情况以及现代 Web 应用程序的挑战。



# 第二十五章：超越 Spring Web

在本章中，我们将看到我们已经走了多远，我们解决了哪些问题，还有哪些问题有待解决。

我们将讨论 Spring 生态系统的一般情况，以及持久性、部署和单页应用程序。

# Spring 生态系统

从 Web 到数据，Spring 是一个全面的生态系统，旨在以模块化的方式解决各种问题：

![Spring 生态系统](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00993.jpeg)

请查看 Spring IO 平台[`spring.io/platform`](https://spring.io/platform)。

## 核心

在 Spring 框架的核心，显然有一个依赖注入机制。

我们只是浅尝了安全功能和框架与 Groovy 的出色集成。

## 执行

我们详细了解了 Spring Boot 的内容——将简单性和内聚性带入庞大的子项目网络。

它使您能够专注于真正重要的事情，即您的业务代码。

Spring XD 项目也非常有趣。其目标是提供处理、分析、转换或导出数据的工具，并且明确关注大数据。有关更多信息，请访问[`projects.spring.io/spring-xd`](http://projects.spring.io/spring-xd)。

## 数据

在开发我们的应用程序时，我们还没有考虑如何在数据库中存储数据。在 Pivotal 的参考架构中，有一个专门用于关系数据和非关系（NoSQL）数据的层。

Spring 生态系统在`spring-data`标签下提供了许多有趣的解决方案，可以在[`projects.spring.io/spring-data/`](http://projects.spring.io/spring-data/)找到。

在构建缓存时，我们瞥见了 Spring Data Redis，但 Spring Data 还有更多内容。

所有 Spring Data 项目都共享基本概念，例如模板 API，这是一个从持久性系统中检索和存储对象的抽象。

Spring Data JPA（[`projects.spring.io/spring-data-jpa/`](http://projects.spring.io/spring-data-jpa/)）和 Spring Data Mongo（[`projects.spring.io/spring-data-mongodb/`](http://projects.spring.io/spring-data-mongodb/)）是一些最著名的 Spring Data 项目。它们让您通过存储库操作实体，这些存储库是提供创建查询、持久化对象等功能的简单接口。

Petri Kainulainen（[`www.petrikainulainen.net/spring-data-jpa-tutorial/`](http://www.petrikainulainen.net/spring-data-jpa-tutorial/)）在 Spring Data 上有很多深入的例子。它没有使用 Spring Boot 提供的设施，但您应该能够很容易地开始使用指南，例如[`spring.io/guides/gs/accessing-data-jpa/`](https://spring.io/guides/gs/accessing-data-jpa/)。

Spring Data REST 也是一个神奇的项目，它将通过 RESTful API 半自动地公开您的实体。请访问[`spring.io/guides/gs/accessing-data-rest/`](https://spring.io/guides/gs/accessing-data-rest/)获取详细教程。

## 其他值得注意的项目

Spring Integration（[`projects.spring.io/spring-integration`](http://projects.spring.io/spring-integration)）和 Spring Reactor（[`projectreactor.io`](http://projectreactor.io)）也是我最喜欢的 Spring 项目之一。

Spring Reactor 是 Pivotal 实现的反应流。其想法是在服务器端提供完全非阻塞的 IO。

另一方面，Spring Integration 专注于企业集成模式，并允许你设计通道来加载和转换来自异构系统的数据。

关于你可以通过通道实现的一个很好而简单的例子可以在这里看到：[`ilopmar.github.io/contest/#_spring_boot_application`](http://ilopmar.github.io/contest/#_spring_boot_application)。

如果你的应用需要与异构和/或复杂的子系统进行通信，那么一定值得一看。

在 Spring 生态系统中，我们还没有提到的最后一个项目是 Spring Batch，它是一个非常有用的抽象，用于处理企业系统的日常运营中的大量数据。

# 部署

Spring Boot 提供了将你的 Spring 应用程序作为简单的 JAR 运行和分发的能力，在这方面取得了很大的成功。

这无疑是朝着正确方向迈出的一步，但有时你不只是想部署你的 Web 应用。

当处理具有多个服务器和数据源的复杂系统时，运维团队的工作可能会变得非常头疼。

## Docker

谁没有听说过 Docker 呢？它是容器世界中的新宠儿，并且由于其充满活力的社区而取得了相当大的成功。

Docker 的理念并不新颖，它利用了 Linux 容器（LXC）和 cgroups 来为应用程序提供完全隔离的环境。

你可以在 Spring 网站上找到一个关于 Docker 的教程，它会指导你进行第一步：[`spring.io/guides/gs/spring-boot-docker`](https://spring.io/guides/gs/spring-boot-docker)。

Pivotal Cloud Foundry 多年来一直在使用容器技术，他们的容器管理器叫做 Warden。他们最近转向了 Garden，这是一个支持不仅仅是 Linux 容器，还有 Windows 容器的抽象。

Garden 是 Cloud Foundry 的最新版本（称为 Diego）的一部分，它还允许 Docker 镜像作为部署单元。

Cloud Foundry 的开发人员版本也以 Lattice 的名字发布了，可以在[`spring.io/blog/2015/04/06/lattice-and-spring-cloud-resilient-sub-structure-for-your-cloud-native-spring-applications`](https://spring.io/blog/2015/04/06/lattice-and-spring-cloud-resilient-sub-structure-for-your-cloud-native-spring-applications)找到。

如果你想在不使用命令行的情况下测试容器，我建议你看看 Kitematic。通过这个工具，你可以在不在系统上安装二进制文件的情况下运行 Jenkins 容器或 MongoDB。访问[`kitematic.com/`](https://kitematic.com/)了解更多关于 Kitematic 的信息。

Docker 生态系统中另一个值得一提的工具是 Docker Compose。它允许你通过一个配置文件运行和链接多个容器。

请参考[`java.dzone.com/articles/spring-session-demonstration`](http://java.dzone.com/articles/spring-session-demonstration)，这是一个由两个 Web 服务器、一个用于存储用户会话的 Redis 和一个用于负载均衡的 Nginx 实例组成的 Spring Boot 应用的很好的例子。当然，关于 Docker Swarm 还有很多值得学习的地方，它可以让你通过简单的命令来扩展你的应用，还有 Docker Machine，它可以在任何机器上为你创建 Docker 主机，包括云提供商。

Google 的 Kubernetes 和 Apache Mesos 也是 Docker 容器大大受益的分布式系统的很好的例子。

# 单页应用

今天大多数的 Web 应用都是用 JavaScript 编写的。Java 被放在后端，并且在处理数据和业务规则方面起着重要作用。然而，现在很多 GUI 的工作都是在客户端进行的。

这在响应性和用户体验方面有很好的原因，但这些应用增加了额外的复杂性。

开发人员现在必须精通 Java 和 JavaScript，而且一开始可能会对各种框架感到有些不知所措。

## 参与者

如果你想深入了解 JavaScript，我强烈推荐 Dave Syer 的 Spring 和 AngularJS 教程，可在[`spring.io/guides/tutorials/spring-security-and-angular-js`](https://spring.io/guides/tutorials/spring-security-and-angular-js)上找到。

选择 JavaScript MVC 框架也可能有些困难。多年来，AngularJS 一直受到 Java 社区的青睐，但人们似乎正在远离它。欲了解更多信息，请访问[`gist.github.com/tdd/5ba48ba5a2a179f2d0fa`](https://gist.github.com/tdd/5ba48ba5a2a179f2d0fa)。

其他选择包括以下内容：

+   **BackboneJS**：这是一个非常简单的 MVC 框架，建立在 Underscore 和 jQuery 之上。

+   **Ember**：这是一个全面的系统，提供了更多与数据交互的便利设施。

+   **React**：这是 Facebook 的最新项目。它有一种处理视图的新而非常有趣的哲学。它的学习曲线相当陡峭，但在设计 GUI 框架方面，它是一个非常有趣的系统。

React 是我目前最喜欢的项目。它让你专注于视图，其单向数据流使得应用程序的状态易于理解。然而，它仍处于 0.13 版本。这使得它非常有趣，因为充满活力的社区总是提出新的解决方案和想法，但也有些令人不安，因为即使经过两年多的开源开发，前方的道路似乎仍然很长。请访问[`facebook.github.io/react/blog/2014/03/28/the-road-to-1.0.html`](https://facebook.github.io/react/blog/2014/03/28/the-road-to-1.0.html)了解有关“通往 1.0 版本的道路”的信息。

## 未来

我看到很多 Java 开发人员抱怨 JavaScript 的宽松性，并且很难处理它不是一种强类型语言的事实。

还有其他选择，比如**Typescript**（[`www.typescriptlang.org/`](http://www.typescriptlang.org/)），非常有趣并提供了我们 Java 开发人员一直用来简化生活的东西：接口、类、IDE 中的有用支持和自动完成。

很多人押注下一个版本（2.0）的 Angular 将会彻底改变一切。我认为这是最好的。他们与微软的 Typescript 团队的合作真的很独特。

大多数 JEE 开发人员听到 ECMAScript 的一个重大新功能是装饰器时会微笑，这允许开发这个新框架的装饰器是一种注解机制：

### 注意

要了解注解和装饰器之间的区别，请访问[`blog.thoughtram.io/angular/2015/05/03/the-difference-between-annotations-and-decorators.html`](http://blog.thoughtram.io/angular/2015/05/03/the-difference-between-annotations-and-decorators.html)。

JavaScript 正在迅速发展，ECMAScript 6 具有许多有趣的功能，使其成为一种非常先进和复杂的语言。不要错过机会，在为时已晚之前查看[`github.com/lukehoban/es6features`](https://github.com/lukehoban/es6features)！

Web 组件规范也是一个改变游戏规则的因素。其目标是提供可重用的 UI 组件，React 团队和 Angular 2 团队都计划与其进行接口交互。谷歌已经在 Web 组件之上开发了一个名为 Polymer 的有趣项目，现在已经是 1.0 版本。

### 注意

请参阅[`ng-learn.org/2014/12/Polymer/`](http://ng-learn.org/2014/12/Polymer/)的文章，以了解更多关于这些项目的情况。

## 无状态

在处理 JavaScript 客户端时，依赖会话 cookie 并不是最佳选择。大多数应用程序选择完全无状态，并使用令牌识别客户端。

如果您想坚持使用 Spring Session，请查看`HeaderHttpSessionStrategy`类。它具有通过 HTTP 标头发送和检索会话的实现。可以在[`drissamri.be/blog/2015/05/21/spr`](https://drissamri.be/blog/2015/05/21/spr)找到示例。

# 总结

Spring 生态系统广泛，为现代 Web 应用程序开发人员提供了很多选择。

很难找到一个 Spring 项目没有解决的问题。

是时候说再见了！我希望您喜欢我们与 Spring MVC 的小旅程，并且它将帮助您愉快地开发并创建令人惊叹的项目，无论是在工作中还是在业余时间。

# 附录 A. 参考文献

这个学习路径已经为您准备好，使用 Spring MVC 框架创建企业级应用程序。它包括以下 Packt 产品：

+   *Spring Essentials, Shameer Kunjumohamed and Hamidreza Sattari*

+   *Spring MVC Cookbook, Alex Bretet*

+   *Mastering Spring MVC 4, Geoffroy Warins*

# 索引

## A

+   @After 注释 / @Before 和@After 注释

+   @AfterClass 注释 / @BeforeClass 和@AfterClass 注释

+   @AspectJ 注释

+   声明 / 声明@Aspect 注释

+   切入点 / 切入点

+   建议 / 建议

+   基于@AspectJ 注释的 AOP

+   关于 / 基于@AspectJ 注释的 AOP

+   验收测试

+   关于 / 我应该如何测试我的代码？, 验收测试, 编写验收测试

+   Gradle，配置 / Gradle 配置

+   使用 FluentLenium / 我们的第一个 FluentLenium 测试

+   使用 Groovy / 使我们的测试更加 Groovy

+   ACID（原子性，一致性，隔离性，持久性）

+   关于 / Spring 事务支持

+   ACID 属性

+   关于 / ACID 属性

+   参考链接 / ACID 属性

+   高级消息队列协议（AMQP）

+   任务，与之堆叠 / 准备就绪

+   任务，与之消耗 / 准备就绪

+   关于 / AMQP 还是 JMS？

+   由 pivotal 提供的 URL / pivotal 提供的 AMQP 简介

+   应用程序事件，发布 / 发布应用程序事件的更好方法

+   建议，@AspectJ 注释

+   关于 / 建议

+   注释 / 建议

+   @Around 建议 / @Around 建议

+   访问建议参数 / 访问建议参数

+   贫血领域模型

+   URL / 贫血领域模型

+   关于 / 贫血领域模型

+   angular-translate.js

+   用于客户端翻译 / 使用 angular-translate.js 进行客户端翻译

+   URL / 使用 angular-translate.js 进行客户端翻译

+   AngularJS

+   关于 / SPA 框架

+   用于设计客户端 MVC 模式 / Designing a client-side MVC pattern with AngularJS

+   URL / There's more...

+   URL，用于表单文档 / See also

+   AngularJS Controllers

+   关于 / AngularJS Controllers

+   双向 DOM-scope 绑定 / Bidirectional DOM-scope binding

+   AngularJS Directives

+   关于 / AngularJS directives

+   ng-repeat / ng-repeat

+   ng-if / ng-if

+   AngularJS factories

+   关于 / AngularJS factories

+   依赖注入 / Dependency injection

+   AngularJS JavaScript library

+   URL / Setting up the DOM and creating modules

+   angular 路由

+   关于 / Angular routes

+   Angular UI

+   使用 Bootstrap 分页 / Bootstrap pagination with the Angular UI

+   注解定义的控制器

+   @Controller annotation / @Controller

+   @RequestMapping annotation / @RequestMapping

+   注解

+   定义 / Auditing with Spring Data

+   @CreatedBy / Auditing with Spring Data

+   @CreatedDate / Auditing with Spring Data

+   @LastModifiedBy / Auditing with Spring Data

+   @LastModifiedDate / Auditing with Spring Data

+   AssertFalse / On-field constraint annotations

+   AssertFalse.List / On-field constraint annotations

+   AssertTrue / On-field constraint annotations

+   AssertTrue.List / On-field constraint annotations

+   DecimalMax / On-field constraint annotations

+   DecimalMax.List / On-field constraint annotations

+   DecimalMin / On-field constraint annotations

+   DecimalMin.List / On-field constraint annotations

+   Digits / On-field constraint annotations

+   Digits.List / On-field constraint annotations

+   Future / On-field constraint annotations

+   Future.List / On-field constraint annotations

+   Max / On-field constraint annotations

+   Max.List / On-field constraint annotations

+   Min / On-field constraint annotations

+   Min.List / On-field constraint annotations

+   NotNull / On-field constraint annotations

+   NotNull.列表/ 现场约束注释

+   过去/ 现场约束注释

+   过去.列表/ 现场约束注释

+   模式/ 现场约束注释

+   模式.列表/ 现场约束注释

+   大小/ 现场约束注释

+   大小.列表/ 现场约束注释

+   Apache Commons 日志桥接/ Apache Commons 日志桥接

+   Apache HTTP

+   URL/ 还有更多...

+   替代方案/ 替代方案 Apache HTTP

+   Apache HTTP 配置

+   代理 Tomcat/ 配置 Apache HTTP 代理您的 Tomcat, 如何做..., 它是如何工作的...

+   关于/ Apache HTTP 配置

+   虚拟主机/ 虚拟主机

+   mod_proxy 模块/ mod_proxy 模块

+   ProxyPassReverse/ ProxyPassReverse

+   mod_alias 模块/ mod_alias 模块

+   Tomcat 连接器/ Tomcat 连接器

+   Apache HTTP 文档

+   URL/ 可扩展模型

+   Apache HTTP 服务器

+   在 MS Windows 上安装，URL/ 如何做...

+   在 Linux/Mac OS 上安装，URL/ 如何做...

+   Apache JServ 协议（AJP）连接器/ AJP 连接器

+   API

+   使用 Swagger 记录/ 使用 Swagger 记录和公开 API, 如何做...

+   使用 Swagger 公开/ 使用 Swagger 记录和公开 API, 如何做...

+   公开的元数据/ 公开的元数据

+   API 端点

+   为 Taskify 应用程序构建/ 为 Taskify 应用程序构建 API 端点

+   UserController.java/ UserController.java

+   TaskController.java/ TaskController.java

+   API 服务器应用

+   构建/ 构建 API 服务器应用

+   项目，设置/ 设置和配置项目

+   定义用户和任务/ 定义模型定义-用户和任务

+   API 版本控制

+   关于/ API 版本控制

+   参考链接/ API 版本控制

+   应用程序

+   日志记录，使用 Log4j2/ 使用 Log4j2 进行现代应用程序日志记录, 如何做...

+   应用程序缓存

+   创建/ 应用程序缓存

+   参考链接/ 应用程序缓存

+   失效/ 缓存失效

+   分布式缓存/ 分布式缓存

+   参数解析器

+   JPA2 标准 API / JPA2 标准 API 和 Spring Data JPA 规范

+   Spring Data JPA 规范 / JPA2 标准 API 和 Spring Data JPA 规范

+   SpecificationArgumentResolver/ SpecificationArgumentResolver

+   面向方面的编程（AOP）

+   关于/ 面向方面的编程

+   静态 AOP/ 静态和动态 AOP

+   动态 AOP / 静态和动态 AOP

+   概念/ AOP 概念和术语

+   术语/ AOP 概念和术语

+   Spring AOP / Spring AOP-定义和配置样式

+   基于 XML 模式的 AOP/ 基于 XML 模式的 AOP

+   @AspectJ 基于注释的 AOP/ @AspectJ 基于注释的 AOP

+   异步请求处理

+   在 Spring MVC 中/ Spring MVC 中的异步请求处理

+   异步方法

+   使用/ 异步方法

+   参考链接/ 异步方法

+   Atomikos

+   URL/ 全局与本地事务

+   认证

+   关于/ 认证

+   测试/ 测试认证

+   AuthenticationManager 接口/ AuthenticationManager 接口

+   授权

+   关于/ 授权

+   授权的 URL

+   认证/ 授权的 URL

+   授权用户

+   认证/ 授权用户

## B

+   @Before 注释 / @Before 和@After 注释

+   @BeforeClass 注释 / @BeforeClass 和@AfterClass 注释

+   BackboneJS

+   关于/ 玩家

+   基本身份验证

+   URL/ 基本身份验证

+   关于/ 基本身份验证

+   配置/ 基本身份验证

+   用于授权用户/ 授权用户

+   用于授权的 URL/ 授权的 URL

+   使用 thymeleaf 安全标签/ Thymeleaf 安全标签

+   BasicAuthenticationFilter

+   关于/ BasicAuthenticationFilter

+   使用 authenticationEntryPoint/ 使用 authenticationEntryPoint

+   基本方案

+   认证/ 通过基本方案进行认证, 如何做...

+   Spring 安全命名空间/ Spring 安全命名空间

+   AuthenticationManager 接口/ AuthenticationManager 接口

+   Spring 安全参考/ 在 Spring 安全参考中

+   记住我 cookie/功能/ 记住我 cookie/功能

+   bean 定义配置文件

+   使用/ 使用 bean 定义配置文件

+   bean 依赖项

+   注入/ 注入 bean 依赖项

+   基于构造函数的依赖注入/ 基于构造函数的依赖注入

+   基于 setter 的依赖注入/ 基于 setter 的依赖注入

+   BeanFactory 接口

+   关于/ Spring IoC 容器

+   bean 生命周期

+   连接/ 连接到 bean 生命周期

+   InitializingBean，实现/ 实现 InitializingBean 和 DisposableBean

+   DisposableBean，实现/ 实现 InitializingBean 和 DisposableBean

+   @PostConstruct，对@Components 进行注释/ 在@Components 上注释@PostConstruct 和@PreDestroy

+   @PreDestroy，对@Components 进行注释/ 在@Components 上注释@PostConstruct 和@PreDestroy

+   init-method 和 destroy-method 属性/ <bean/>的 init-method 和 destroy-method 属性

+   beans

+   关于/ Spring IoC 容器, 详细介绍 Beans

+   定义/ Bean 定义

+   实例化/ 实例化 beans

+   实例化，使用构造函数/ 使用构造函数

+   实例化，使用静态工厂方法/ 使用静态工厂方法

+   实例化，使用实例工厂方法/ 使用实例工厂方法

+   使用命名空间快捷方式进行更清晰的 bean 定义/ 使用命名空间快捷方式进行更清晰的 bean 定义

+   列表，作为依赖项进行连线/ 将列表作为依赖项进行连线

+   映射，作为依赖项进行连线/ 将映射作为依赖项进行连线

+   依赖项，自动装配/ 自动装配依赖项

+   作用域/ Bean 作用域

+   bean 验证

+   用于验证资源/ 准备工作, 如何做…

+   使用 Spring 验证器/ 使用 Spring 验证器

+   JSR-303/JSR-349 bean 验证 / 使用 JSR-303/JSR-349 Bean 验证

+   ValidationUnits 实用程序/ ValidationUtils

+   创建自定义验证器 / 创建自定义验证器

+   参考链接 / Spring 关于验证的参考

+   绑定请求

+   关于 / 绑定请求和编组响应, 准备就绪, 如何做..., 它是如何工作的...

+   Bitronix

+   URL / 全局与本地事务

+   样板逻辑

+   抽象 / 样板逻辑的抽象

+   自动生成的 ID，提取 / 提取自动生成的 ID

+   bookapp-rest 应用程序

+   URL / 我们的 MessageSource bean 定义

+   Bootstrap

+   响应式单页 Web 设计，设置 / 使用 Bootstrap 设置和自定义响应式单页 Web 设计, 如何做..., 安装 Bootstrap 主题

+   亮点 / Bootstrap 亮点

+   URL / 还有更多...

+   Bootstrap 组件

+   导航栏 / 导航栏

+   英雄单元 / 英雄单元

+   警报 / 警报

+   徽章和标签 / 徽章和标签

+   Bootstrap CSS 实用程序

+   统一按钮 / 统一按钮

+   图标 / 图标

+   表格 / 表格

+   Bootstrap 分页

+   使用 Angular UI / 使用 Angular UI 的 Bootstrap 分页

+   URL / 使用 Angular UI 的 Bootstrap 分页

+   Bootstrap 脚手架

+   关于 / Bootstrap 脚手架

+   网格系统和响应式设计 / 网格系统和响应式设计

+   定义列 / 定义列

+   列，偏移 / 偏移和嵌套

+   嵌套 / 偏移和嵌套

+   流体网格 / 流体网格

+   Bootstrap 主题

+   自定义 / 自定义 Bootstrap 主题

+   安装 / 主题安装

+   经纪人通道 / Spring 4 中 STOMP over WebSocket 和回退选项

+   BSON（二进制 JSON）格式

+   关于 / Spring Data MongoDB

+   Maven 构建生命周期

+   关于 / Maven 的构建生命周期

+   清洁生命周期 / 清洁生命周期

+   默认生命周期 / 默认生命周期

+   插件 / 插件目标

+   内置生命周期 / 内置生命周期绑定

+   Maven 命令 / 关于 Maven 命令

## C

+   @ComponentScan 注释 / 创建一个简单的 WebSocket 应用程序

+   @Configuration 注释 / 创建一个简单的 WebSocket 应用程序

+   @ContextConfiguration 注释 / @ContextConfiguration 注释, 还有更多…

+   @ControllerAdvice

+   使用@ControllerAdvice 进行全局异常处理 / 使用@ControllerAdvice 进行全局异常处理

+   支持 ResponseEntityExceptionHandler 类 / 支持 ResponseEntityExceptionHandler 类

+   统一的错误响应对象 / 统一的错误响应对象

+   @Controller 注释 / @Controller

+   缓存控制

+   关于 / 另请参阅

+   缓存控制

+   关于 / 缓存控制

+   配置 / 缓存控制

+   货物

+   与集成测试 / 使用 Cargo，Rest-assured 和 Maven failsafe 进行集成测试, 如何做…, 它是如何工作的…

+   Codehaus Cargo / Code Cargo

+   Maven 插件 / Cargo Maven 插件

+   关于 / 关于 Cargo

+   URL / 关于 Cargo

+   Cargo Maven 插件

+   关于 / Cargo Maven 插件

+   Maven 阶段，绑定到 / 绑定到 Maven 阶段

+   现有的 Tomcat 实例，使用 / 使用现有的 Tomcat 实例

+   级联属性

+   关于 / 级联属性

+   证书签名请求（CSR）

+   URL / 关于 SSL 和 TLS

+   检查点

+   关于 / 检查点

+   清理命令 / 清理

+   清理生命周期

+   预清理阶段 / 清理生命周期

+   清理阶段 / 清理生命周期

+   后清理阶段 / 清理生命周期

+   客户端表单

+   使用 HTML5/AngularJS 进行验证 / 使用 HTML5 AngularJS 验证客户端表单, 如何做…, 它是如何工作的…

+   控制变量 / 表单中的控制变量

+   状态转换 / 表单状态转换和样式

+   样式 / 表单状态转换和样式

+   客户端表单，验证约束

+   必需的 / 必需的

+   最小/最大长度 / 最小/最大长度

+   正则表达式模式 / 正则表达式模式

+   客户端 MVC 模式

+   设计，使用 AngularJS / 使用 AngularJS 设计客户端 MVC 模式

+   客户端验证，配置文件页面

+   启用 / 客户端验证

+   参考链接 / 客户端验证

+   Cloud Foundry

+   关于 / Cloud Foundry

+   URL / Cloud Foundry

+   Cloud Foundry CLI 工具

+   安装 / 安装 Cloud Foundry CLI 工具

+   URL / 安装 Cloud Foundry CLI 工具

+   cloudstreetmarket-parent

+   关于 / 准备就绪

+   代码测试

+   好处 / 为什么我应该测试我的代码？

+   单元测试 / 我应该如何测试我的代码？

+   验收测试 / 我应该如何测试我的代码？

+   组件类型注释

+   @Component / 组件类型注释

+   @Service / 组件类型注释

+   @Repository / 组件类型注释

+   @Controller / 组件类型注释

+   @RestController / 组件类型注释

+   配置元数据，依赖注入

+   关于 / 配置元数据

+   基于 XML 的配置元数据 / 基于 XML 的配置元数据

+   基于注释的配置元数据 / 基于注释的配置元数据

+   基于 XML 的与基于注释的配置 / 基于 XML 与基于注释的配置

+   组件类型注释 / 组件类型注释

+   基于 Java 的配置元数据 / 基于 Java 的配置元数据

+   JSR 330 标准注释 / JSR 330 标准注释

+   基于构造函数的依赖注入

+   关于 / 基于构造函数还是基于 setter 的依赖注入 - 哪个更好？

+   构造函数注入

+   关于 / 将配置文件放入会话中

+   URL / 将配置文件放入会话中

+   容器级默认初始化和销毁方法

+   关于 / 容器级默认初始化方法和默认销毁方法

+   容器管理的事务（CMT）

+   关于 / Spring 事务的相关性

+   内容协商

+   配置 / 如何做..., 它是如何工作的...

+   XML 编组，支持 / 支持 XML 编组

+   ContentNegotiationManager

+   与 ContentNegotiationManager 的协商策略

+   接受头 / 接受头

+   URL 路径中的文件扩展名后缀 / URL 路径中的文件扩展名后缀

+   请求参数 / 请求参数

+   Java 激活框架 / Java 激活框架

+   ContentNegotiationManagerFactoryBean JavaDoc

+   关于 / ContentNegotiationManagerFactoryBean JavaDoc

+   内容

+   为 REST 国际化 / 为 REST 国际化消息和内容

+   动态翻译，后端实现 / 后端

+   动态翻译，前端实现 / 前端, 它是如何工作的...

+   持续集成

+   参考链接 / 为什么我应该测试我的代码？

+   控制器

+   使用简单 URL 映射进行配置 / 使用简单 URL 映射配置控制器, 如何做...

+   控制器方法处理程序签名

+   关于 / 控制器方法处理程序签名

+   支持的方法参数类型 / 支持的方法参数类型

+   方法参数的支持注解 / 方法参数的支持注解

+   支持的返回类型 / 支持的返回类型

+   控制器

+   关于 / 详细的控制器

+   使用@RequestMapping 映射请求 URL / 使用@RequestMapping 映射请求 URL

+   使用@PathVariable 注解的 URI 模板模式 / 使用@PathVariable 注解的 URI 模板模式

+   使用@RequestParam 注解绑定参数 / 使用@RequestParam 注解绑定参数

+   请求处理程序方法参数 / 请求处理程序方法参数

+   请求处理程序方法返回类型 / 请求处理程序方法返回类型

+   模型属性，设置 / 设置模型属性

+   为 JSON 和 XML 媒体构建 RESTful 服务 / 为 JSON 和 XML 媒体构建 RESTful 服务

+   使用 RestController 构建 RESTful 服务 / 使用 RestController 构建 RESTful 服务

+   授权 / 在服务和控制器上进行授权, 如何做...

+   控制变量，客户端表单

+   修改/未修改状态 / 修改/未修改状态

+   $error 属性 / 错误

+   ConversionService API / ConversionService API

+   CookieHttpSessionStrategy / CookieHttpSessionStrategy

+   核心模块

+   创建/ 为什么我们创建核心模块？

+   创建读取更新删除（CRUD）

+   关于/ Level 2-HTTP 动词

+   跨站点请求伪造（csrf）/ 我们的<http>配置

+   跨站点请求伪造（CSRF）攻击

+   关于/ 认证

+   跨站点请求伪造（CSRF）

+   关于/ 授权的 URL

+   URL/ 授权的 URL

+   自定义约束

+   参考链接/ 特定实现约束

+   自定义错误页面

+   创建/ 自定义错误页面

+   自定义范围

+   创建/ 创建自定义范围

+   自定义验证器

+   URL/ 创建自定义验证器

## D

+   DAO 支持

+   关于/ DAO 支持和@Repository 注释

+   数据

+   使用 OAuth 从第三方 API 检索/ 使用 OAuth 从第三方 API 检索数据, 如何做..., 它是如何工作的...

+   Yahoo!，财务数据/ Yahoo!财务数据介绍

+   图形，生成/显示/ 图形生成/显示

+   财务数据，拉取/ 财务数据是如何拉取/刷新的？

+   财务数据，刷新/ 财务数据是如何拉取/刷新的？

+   调用第三方服务/ 调用第三方服务

+   现有的 API 提供商/ Spring Social-现有的 API 提供商

+   数据供应实现

+   通过接口注入服务/ 通过接口注入服务

+   虚拟实现，选择/ Spring 如何选择虚拟实现？

+   在视图层中使用的 DTO/ 在视图层中使用的 DTO

+   虚拟服务实现/ 虚拟服务实现

+   数据访问对象（DAO）/ 基于 XML 的配置元数据

+   数据库迁移

+   自动化，使用 FlyWay/ 使用 FlyWay 自动化数据库迁移, 如何做...

+   数据源

+   配置/ 配置数据源

+   参考/ 配置数据源

+   数据源

+   关于/ Spring 管理的数据源 bean

+   数据传输对象（DTO）

+   关于/ 个人资料页面-表单

+   声明式事务管理

+   关于/ 声明式事务管理

+   代理模式/ 事务模式-代理和 AspectJ

+   AspectJ 模式 / 事务模式-代理和 AspectJ

+   定义事务行为 / 定义事务行为

+   回滚规则，设置 / 设置回滚规则

+   默认生命周期

+   验证 / 默认生命周期

+   初始化 / 默认生命周期

+   generate-sources / 默认生命周期

+   process-sources / 默认生命周期

+   generate-resources / 默认生命周期

+   process-resources / 默认生命周期

+   编译 / 默认生命周期

+   process-classes / 默认生命周期

+   generate-test-sources / 默认生命周期

+   process-test-sources / 默认生命周期

+   generate-test-resources / 默认生命周期

+   process-test-resources / 默认生命周期

+   test-compile / 默认生命周期

+   process-test-classes / 默认生命周期

+   测试 / 默认生命周期

+   准备包 / 默认生命周期

+   打包 / 默认生命周期

+   pre-integration-test / 默认生命周期

+   integration-test / 默认生命周期

+   post-integration-test / 默认生命周期

+   验证 / 默认生命周期

+   install / 默认生命周期

+   部署 / 默认生命周期

+   依赖注入 / 依赖注入

+   依赖注入（DI） / Spring 框架模块

+   关于 / 依赖注入, Spring 框架带来了什么？

+   Spring IoC 容器 / Spring IoC 容器

+   配置元数据 / 配置元数据

+   依赖注入，带有作用域的 bean

+   关于 / 带有作用域的 bean 的依赖注入

+   可部署模块

+   名称，选择 / 我们如何选择可部署模块的名称？

+   部署

+   关于 / 部署

+   Docker / Docker

+   开发环境

+   设置 / 设置开发环境

+   Dispatcher Servlet

+   架构 / DispatcherServlet

+   DispatcherServlet

+   关于 / DispatcherServlet 解释

+   使用 WebApplicationContext/ WebApplicationContext-Web 的 ApplicationContext

+   支持豆/ 支持 DispatcherServlet 的豆和它们的角色

+   支持的豆/ 支持 DispatcherServlet 的豆和它们的角色/ DispatcherServlet-Spring MVC 入口点

+   分布式缓存

+   配置/ 分布式缓存

+   分布式会话

+   关于/ 分布式会话

+   设置/ 分布式会话

+   DNS

+   URL/ 还有更多...

+   DNS 配置/ DNS 配置或主机别名

+   DNS 记录

+   版本/ 在生产中-编辑 DNS 记录

+   Docker

+   关于/ Docker

+   URL/ Docker

+   参考链接/ Docker

+   文档

+   使用 Swagger/ 使用 Swagger 进行文档编制

+   文档对象模型（DOM）/ 每个 HTML 文档一个应用程序

+   DOM

+   设置/ 设置 DOM 和创建模块

+   DOM 范围绑定

+   双向/ 双向 DOM 范围绑定

+   领域驱动设计（DDD）

+   关于/ 贫血领域模型

+   领域对象和实体

+   关于/ 领域对象和实体

+   查询解析方法/ 查询解析方法

+   @Query 注释，使用/ 使用@Query 注释

+   Spring Data web 支持扩展/ Spring Data web 支持扩展

+   审计，使用 Spring Data/ 使用 Spring Data 进行审计

+   领域对象安全（ACLs）

+   URL/ 领域对象安全（ACLs）

+   DTO

+   转换为 Spring HATEOAS 资源/ 将 DTO 转换为 Spring HATEOAS 资源, 如何做..., 它是如何工作的...

## E

+   @EnableAutoConfiguration 注释/ 创建一个简单的 WebSocket 应用程序

+   Eclipse

+   为 Java 8 配置/ 为 Java 8，Maven 3 和 Tomcat 8 配置 Eclipse, 如何做...

+   为 Maven 3 配置/ 为 Java 8，Maven 3 和 Tomcat 8 配置 Eclipse, 如何做...

+   为 Tomcat 8 配置/ 为 Java 8，Maven 3 和 Tomcat 8 配置 Eclipse, 如何做...

+   eclipse.ini 文件/ eclipse.ini 文件

+   -vm 选项，设置/ 设置-vm 选项

+   JVM 参数，自定义/ 自定义 JVM 参数

+   JDK 兼容级别，修改/ 更改 JDK 兼容级别

+   Maven，配置/ 配置 Maven

+   存储库管理器/ 存储库管理器

+   Tomcat 8，集成/ Eclipse 中的 Tomcat 8

+   URL/ 还有更多...

+   GIT，配置/ 在 Eclipse 中配置 GIT, 它是如何工作的...

+   Eclipse.ini 文件

+   URL/ 还有更多...

+   eclipse.ini 文件

+   关于/ eclipse.ini 文件

+   URL/ eclipse.ini 文件

+   Eclipse IDE

+   需要/ 为什么要使用 Eclipse IDE？

+   下载，适用于 Java EE 开发人员/ 如何做...

+   安装，适用于 Java EE 开发人员/ 如何做..., Eclipse for Java EE developers

+   URL/ 如何做...

+   JVM，选择/ 选择 JVM

+   Java SE 8/ Java SE 8

+   EJB3 实体

+   定义/ 准备就绪, 如何做..., 它是如何工作的...

+   要求/ 实体要求

+   模式，映射/ 映射模式

+   继承，定义/ 定义继承

+   关系，定义/ 定义关系

+   嵌入式数据库

+   使用/ 使用嵌入式数据库

+   EmbeddedServletContainerCustomizer 接口

+   关于/ 处理文件上传错误

+   URL/ 处理文件上传错误

+   Ember

+   关于/ 玩家

+   Ember.js

+   关于/ SPA 框架, 介绍 Ember.js

+   Ember 应用程序

+   解剖学/ Ember 应用程序的解剖学

+   路由器/ 路由器

+   路由或路由处理程序/ 路由或路由处理程序

+   模板/ 模板

+   组件/ 组件

+   模型/ 模型

+   控制器/ 控制器

+   输入助手/ 输入助手

+   自定义助手/ 自定义助手

+   初始化程序/ 初始化程序

+   服务/ 服务

+   Ember CLI

+   关于/ 介绍 Ember.js, 使用 Ember CLI

+   使用/ 使用 Ember CLI

+   features / 使用 Ember CLI

+   setting up / 设置 Ember CLI

+   commands / 使用 Ember CLI 命令入门

+   project structure / Ember 项目结构

+   POD structure / 使用 POD 结构

+   Ember CLI 命令

+   about / 使用 Ember CLI 命令入门

+   ember / 使用 Ember CLI 命令入门

+   ember new <appname> / 使用 Ember CLI 命令入门

+   ember init / 使用 Ember CLI 命令入门

+   ember build / 使用 Ember CLI 命令入门

+   ember server (or serve) / 使用 Ember CLI 命令入门

+   ember generate <generatortype> <name> <options> / 使用 Ember CLI 命令入门

+   ember destroy <generatortype> <name> <options> / 使用 Ember CLI 命令入门

+   ember test / 使用 Ember CLI 命令入门

+   ember install <addon-name> / 使用 Ember CLI 命令入门

+   Ember Data

+   about / 介绍 Ember.js

+   data, persisting with / 使用 Ember Data 持久化数据

+   DS.Model / 使用 Ember Data 持久化数据

+   DS.Store / 使用 Ember Data 持久化数据

+   DS.Adapter / 使用 Ember Data 持久化数据

+   DS.Serializer / 使用 Ember Data 持久化数据

+   architecture / Ember Data 架构

+   models, building / 定义模型

+   model relationships, defining / 定义模型关系

+   Ember 开发堆栈

+   about / 介绍 Ember.js

+   Ember Inspector

+   about / 介绍 Ember.js

+   Ember object model

+   about / 理解 Ember 对象模型

+   types (classes), declaring / 声明类型（类）和实例

+   instances, declaring / 声明类型（类）和实例

+   properties, accessing / 访问和修改属性

+   properties, mutating / 访问和修改属性

+   computed properties / 计算属性

+   property observers / 属性观察者

+   collections, working with / 处理集合

+   Ember.Array / 使用集合

+   Ember.ArrayProxy / 使用集合

+   Ember.MutableArray / 使用集合

+   Ember.Enumerable / 使用集合

+   Ember.NativeArray / 使用集合

+   企业版（EE）/ AMQP 还是 JMS？

+   企业集成（EAI）

+   关于 / Spring 子项目

+   企业 JavaBean（EJB）

+   关于 / 介绍

+   企业 JavaBean（EJB）

+   关于 / Spring 事务的相关性

+   实体

+   关于 / 实体的好处

+   好处 / 实体的好处

+   实体，OAuth2

+   资源所有者 / OAuth2 授权框架

+   客户端或第三方应用程序 / OAuth2 授权框架

+   授权服务器 / OAuth2 授权框架

+   资源服务器 / OAuth2 授权框架

+   实体管理器

+   关于 / 实体管理器及其持久性上下文

+   持久性上下文 / 实体管理器及其持久性上下文

+   EntityManagerFactory bean

+   关于 / EntityManagerFactory bean 及其持久性单元

+   厄尔朗

+   URL / 如何做...

+   错误消息

+   翻译 / 翻译错误消息

+   ETag

+   关于 / 另请参阅

+   ETags

+   关于 / ETags

+   生成 / ETags

+   使用 / ETags

+   异常处理

+   关于 / 状态码和异常处理

+   异常

+   在 Spring 数据层处理 / 在 Spring 数据层处理异常

+   全局处理 / 准备工作, 如何做..., 工作原理...

## F

+   备用控制器

+   配置，使用 ViewResolver / 使用 ViewResolver 配置备用控制器, 如何做...

+   URI 模板模式 / URI 模板模式

+   ViewResolvers / ViewResolvers

+   备用选项

+   使用 / Spring 4 中 STOMP over WebSocket 和备用选项

+   Fastboot

+   关于 / 介绍 Ember.js

+   feedEk jQuery 插件

+   URL / 创建响应式内容

+   FetchType 属性

+   关于 / FetchType 属性

+   文件上传

+   关于 / 上传文件

+   个人资料图片，上传/ 上传文件

+   上传的图片，在网页上显示/ 将图像写入响应

+   上传属性，管理/ 管理上传属性

+   上传的图片，显示/ 显示上传的图片

+   错误，处理/ 处理文件上传错误

+   实现/ 将其放在一起

+   检查点/ 检查点

+   文件上传

+   处理/ 处理文件上传

+   过滤

+   关于/ 如何做..., 它是如何工作的...

+   FluentLenium

+   用于验收测试/ 我们的第一个 FluentLenium 测试

+   关于/ 我们的第一个 FluentLenium 测试

+   URL/ 我们的第一个 FluentLenium 测试

+   页面对象/ 使用 FluentLenium 的页面对象

+   FlyWay

+   用于自动化数据库迁移/ 使用 FlyWay 自动化数据库迁移, 如何做...

+   命令/ 有限的命令数量

+   maven 插件/ 关于 Flyway Maven 插件

+   配置参数，URL/ 关于 Flyway Maven 插件

+   官方文档/ 官方文档

+   GitHub 仓库，URL/ 官方文档

+   FlyWay，命令

+   关于/ 有限的命令数量

+   迁移/ 迁移

+   清洁/ 清洁

+   信息/ 信息

+   验证/ 验证

+   基线/ 基线

## G

+   垃圾收集

+   参考链接/ 还有更多...

+   GDAXI 指数代码

+   URL/ 如何做...

+   Geb

+   用于集成测试/ 使用 Geb 进行集成测试

+   关于/ 使用 Geb 进行集成测试

+   页面对象/ 使用 Geb 的页面对象

+   参考链接/ 使用 Geb 的页面对象

+   Git

+   关于/ 上传文件

+   空目录/ 上传文件

+   GIT

+   安装/ 下载和安装 GIT

+   下载/ 下载和安装 GIT

+   URL/ 下载和安装 GIT

+   在 Eclipse 中配置/ 在 Eclipse 中配置 GIT

+   全局事务

+   全局与本地事务/ 全局与本地事务

+   参考链接/ 全局与本地事务

+   Google 协议缓冲区

+   URL / 提供的 HttpMessageConverters

+   Gradle

+   配置 / Gradle 配置

+   运行 / Gradle

+   URL / Gradle

+   GrantedAuthority 接口

+   关于 / GrantedAuthority 接口

+   Groovy

+   接受测试/ 使我们的测试更加灵活

+   关于 / 使我们的测试更加灵活

+   URL / 使我们的测试更加灵活

+   Groovy 开发工具包（GDK）

+   关于 / 使我们的测试更加灵活

+   Gzipping

+   关于 / Gzipping

+   参考链接 / Gzipping

## H

+   HandlerMapping

+   关于 / DispatcherServlet

+   HAProxy

+   URL / 替代 Apache HTTP 的选择

+   标题

+   参考链接 / 另请参阅

+   堆内存

+   年轻一代 / 自定义 JVM 参数

+   旧一代 / 自定义 JVM 参数

+   Heroku

+   关于 / Heroku

+   Web 应用程序，部署 / 在 Heroku 上部署您的 Web 应用程序

+   命令行工具，安装 / 安装工具

+   URL / 安装工具

+   Web 应用程序，设置 / 设置应用程序

+   运行 Gradle / Gradle

+   运行 Procfile / Procfile

+   配置文件，创建 / 一个 Heroku 配置文件

+   Web 应用程序，执行 / 运行您的应用程序

+   激活 Redis / 激活 Redis

+   Heroku Redis 附加组件

+   URL / 激活 Redis

+   Hibernate 查询语言（HQL）

+   关于 / 使用 JPQL

+   HikariCP 数据源

+   关于 / 另请参阅

+   URL / 另请参阅

+   主机

+   别名 / 主机的别名

+   选择 / 选择您的主机

+   Cloud Foundry / Cloud Foundry

+   OpenShift / OpenShift

+   Heroku / Heroku

+   主机别名 / DNS 配置或主机别名

+   HTML5/AngularJS

+   客户端表单，验证 / 使用 HTML5 AngularJS 验证客户端表单, 如何做..., 它是如何工作的...

+   HTML 文档

+   模块自动引导 / 模块自动引导

+   模块自动引导，手动 / 手动模块引导

+   HTTP/1.1 规范

+   参考链接 / HTTP/1.1 规范-RFC 7231 语义和内容

+   必要条件/【基本要求】

+   安全方法/【安全和幂等方法】

+   幂等方法/【安全和幂等方法】

+   特定于方法的约束/【其他特定于方法的约束】

+   HTTP 代码

+   关于/【有用的 HTTP 代码】

+   URL/【有用的 HTTP 代码】

+   HTTP 连接器/【HTTP 连接器】

+   URL/【另请参阅】

+   httpie

+   关于/【httpie】

+   HttpMessageConverters

+   使用/【HttpMessageConverters】

+   本机 HttpMessageConverters/【提供的 HttpMessageConverters】

+   MappingJackson2HttpMessageConverter，使用/【使用 MappingJackson2HttpMessageConverter】

+   HTTP 方法

+   REST 处理程序，扩展到/【将 REST 处理程序扩展到所有 HTTP 方法】，【如何做…】，【它是如何工作的…】

+   HTTP 会话

+   配置文件，存储/【将配置文件放入会话中】

+   关于/【将配置文件放入会话中】

+   HTTP 状态码/【HTTP 状态码】

+   HTTP 动词

+   获取/【级别 2 - HTTP 动词】

+   头/【级别 2 - HTTP 动词】

+   删除/【级别 2 - HTTP 动词】

+   放置/【级别 2 - HTTP 动词】

+   发布/【级别 2 - HTTP 动词】

+   PATCH/【级别 2 - HTTP 动词】

+   选项/【级别 2 - HTTP 动词】

+   超媒体驱动的 API

+   链接，构建/【为超媒体驱动的 API 构建链接】，【如何做…】，【它是如何工作的…】，【构建链接】

+   资源装配器/【资源装配器】

+   PagedResourcesAssembler/【PagedResourcesAssembler】

+   EntityLinks/【EntityLinks】

+   ControllerLinkBuilder/【ControllerLinkBuilder】

+   @RequestMapping 中的正则表达式/【在@RequestMapping 中使用正则表达式】

+   超媒体作为应用程序状态的引擎（HATEOAS）

+   关于/【介绍】

+   超文本应用语言（HAL）

+   URL/【另请参阅】

+   应用程序状态的超文本作为引擎（HATEOAS）

+   关于/【级别 3 - 超媒体控件】

## 我

+   iconmonstr

+   URL/【将图像写入响应】

+   IDE（集成开发环境）

+   关于/【Spring 工具套件（STS）】

+   标识符

+   关于/【实体要求】

+   ID 暴露

+   URL/【另请参阅】

+   信息命令/ 信息

+   继承，EJB3 实体

+   定义/ 定义继承

+   单表策略/ 单表策略

+   按类策略/ 按类策略

+   继承，Maven 依赖

+   关于/ Maven 依赖的继承

+   基本继承/ 基本继承

+   管理继承/ 管理继承

+   集成测试

+   Spring Beans，注入/ 将 Spring Beans 注入集成测试, 如何做...

+   使用 Geb/ 使用 Geb 进行集成测试

+   拦截器

+   关于/ 更改区域设置

+   国际化（i18n）

+   关于/ 国际化

+   区域设置，修改/ 更改区域设置

+   应用文本，翻译/ 翻译应用文本

+   数据列表，在表单中处理/ 表单中的列表

+   物联网（IoT）/ 微服务架构

+   互联网服务提供商（ISP）/ DNS 配置或主机别名

+   控制反转（IOC）

+   关于/ Spring 框架带来了什么？

+   控制反转（IoC）容器/ Spring 框架模块

## J

+   Jackson 2.x 扩展组件

+   URL/ 提供的 HttpMessageConverters

+   JaCoCo

+   URL/ 另请参阅

+   jar

+   关于/ 准备就绪

+   jar 依赖

+   关于/ 准备就绪

+   jar 模块

+   选择名称/ 我们如何选择 jar 模块的名称？

+   Java 8

+   Eclipse，配置/ 准备就绪, 如何做...

+   流/ Java 8 流和 lambda 表达式

+   lambda 表达式/ Java 8 流和 lambda 表达式

+   Java 8 日期时间 API

+   参考链接/ 个人资料页面-表单

+   Java 激活框架（JAF）

+   关于/ 提供的 HttpMessageConverters

+   JavaBeans 组件/ 使用 JSP EL 呈现变量

+   JavaBeans 标准

+   URL/ 关于 JavaBeans 标准的更多信息

+   JavaDoc

+   URL/ WebContentGenerator 提供的更多功能, 使用 JAXB2 实现作为 XML 解析器

+   Java EE 教程

+   URL/ 使用 JSTL 呈现变量

+   Java 持久化 API（JPA）

+   关于/ 介绍

+   在 Spring 中配置 / 在 Spring 中配置 Java 持久化 API, 如何做..., 它是如何工作的...

+   Spring 管理的 DataSource bean / Spring 管理的 DataSource bean

+   EntityManagerFactory bean，配置 / EntityManagerFactory bean 及其持久化单元

+   持久化单元，配置 / EntityManagerFactory bean 及其持久化单元

+   Spring Data JPA，配置 / Spring Data JPA 配置

+   使用 / 利用 JPA 和 Spring Data JPA, 如何做..., 它是如何工作的...

+   Java 持久化查询语言（JPQL）

+   使用 / 使用 JPQL

+   参考链接 / 使用 JPQL

+   Java SE 8

+   使用 / Java SE 8

+   Java 服务器页面（JSP）

+   关于 / 解析 JSP 视图

+   Java 服务器页面标签库（JSTL）

+   关于 / 解析 JSP 视图

+   Java 服务器标签库（JSTL）

+   用于在视图中显示模型 / 在视图中显示模型，使用 JSTL, 如何做..., 它是如何工作的...

+   URL / 更多关于 JSTL

+   Java Util 日志适配器 / Java Util 日志适配器

+   JAXB2 实现

+   作为 XML 解析器使用 / 将 JAXB2 实现作为 XML 解析器使用

+   JDBC 操作

+   使用 Sql*类 / 使用 Sql*类进行 JDBC 操作

+   组件 / 使用 Sql*类进行 JDBC 操作

+   JdbcTemplate

+   方法 / JdbcTemplate

+   回调接口 / JdbcTemplate

+   NamedParameterJdbcTemplate / NamedParameterJdbcTemplate/ JdbcTemplate

+   JDK 8

+   安装 / 如何做...

+   JDK 兼容级别

+   修改 / 更改 JDK 兼容级别

+   JMS

+   关于 / AMQP 还是 JMS？

+   联接表继承策略

+   关于 / 另请参阅

+   JOTM

+   URL / 全局与本地事务

+   JPA（Java 持久化架构）

+   关于 / Spring Data JPA

+   JPA 实体

+   选择公开的策略 / 选择公开 JPA 实体的策略, 如何做..., 它是如何工作的...

+   REST CRUD 原则 / REST CRUD 原则

+   最小信息，暴露/ 暴露最小信息, 如果实体拥有关系

+   资源分离/ 资源分离

+   JSON 输出

+   自定义/ 自定义 JSON 输出

+   JSP EL

+   URL / 更多关于 JSP EL

+   JSP 表达式语言（JSP EL）/ 准备就绪

+   关于/ 准备就绪

+   JSP

+   Taglib 指令/ JSP 中的 Taglib 指令

+   JSP 标准标签库（JSTL）

+   关于/ 使用 JSTL 呈现变量

+   JSR-250

+   关于/ JSR-250 和遗留方法安全

+   JSR-303/JSR-349 bean 验证

+   使用/ 使用 JSR-303/JSR-349 Bean 验证

+   字段约束注释/ 字段约束注释

+   特定于实现的约束/ 特定于实现的约束

+   LocalValidator（可重用）/ LocalValidator（可重用）

+   JSR-310

+   URL / 自定义 JSON 输出

+   JSR-356

+   URL / 另请参阅

+   JTA（Java 事务 API）

+   关于/ Spring 事务的相关性

+   JUnit 规则

+   URL / JUnit 规则

+   JVM

+   选择/ 选择 JVM

+   JVM 参数

+   自定义/ 自定义 JVM 参数

## L

+   lambda，Java 8

+   关于/ Java 8 流和 lambda

+   布局

+   使用/ 使用布局

+   链接

+   为超媒体驱动的 API 构建/ 为超媒体驱动的 API 构建链接, 如何做…

+   链接！/ ResourceSupport 类

+   Liquibase

+   URL / 另请参阅

+   液体火

+   关于/ 介绍 Ember.js

+   负载均衡 WebSockets

+   URL / 另请参阅

+   LocaleResolver

+   用于国际化消息/ 使用 LocaleResolver

+   AcceptHeaderLocaleResolver / AcceptHeaderLocaleResolver

+   FixedLocaleResolver / FixedLocaleResolver

+   SessionLocaleResolver / SessionLocaleResolver

+   CookieLocaleResolver / CookieLocaleResolver

+   本地存储

+   URL / localStorage 的浏览器支持

+   Log4j 1.x API 桥接/ Log4j 1.x API 桥接

+   Log4j2

+   用于应用程序日志记录/ Log4j2 的现代应用程序日志记录, 如何做…

+   和其他日志框架/ Apache Log4j2 等其他日志框架

+   SLF4j, 案例 / SLF4j 的案例

+   迁移到 / 迁移到 log4j 2

+   API 和核心 / Log4j 2 API 和核心

+   适配器 / Log4j 2 适配器

+   配置文件 / 配置文件

+   自动配置 / 自动配置

+   自动配置, URL / 自动配置

+   官方文档 / 官方文档

+   官方文档, URL / 官方文档

+   Redis Appender, 实现 / 有趣的 Redis Appender 实现

+   Redis, URL / 有趣的 Redis Appender 实现

+   Log4j2, 适配器

+   关于 / Log4j 2 适配器

+   Log4j 1.x API 桥接器 / Log4j 1.x API 桥接器

+   Apache Commons Logging 桥接器 / Apache Commons Logging 桥接器

+   SLF4J 桥接器 / SLF4J 桥接器

+   Java Util Logging 适配器 / Java Util Logging 适配器

+   Web Servlet 支持 / Web Servlet 支持

+   登录表单

+   设计 / 登录表单

+   Luna 分发

+   URL / 如何做...

## M

+   @MessageMapping

+   用于定义消息处理程序 / 通过@MessageMapping 定义消息处理程序

+   m2eclipse 插件

+   URL / 更多信息...

+   编组响应

+   关于 / 绑定请求和编组响应, 如何做..., 它是如何工作的...

+   Material Design

+   使用 WebJars / 使用 WebJars 进行 Material Design

+   Materialize

+   URL / 使用 WebJars 进行 Material Design

+   矩阵变量

+   URL 映射 / 使用矩阵变量进行 URL 映射

+   Maven

+   需要 / 为什么要使用 Maven?

+   配置 / 配置 Maven

+   项目结构, 定义 / 使用 Maven 定义项目结构, 准备工作, 如何做...

+   构建生命周期 / Maven 的构建生命周期

+   参考资料 / 更多信息...

+   Maven 3

+   Eclipse, 配置 / 准备工作, 如何做...

+   Maven checkstyle 插件

+   关于 / Maven 的 checkstyle 插件

+   URL / Maven 的 checkstyle 插件

+   Maven Failsafe

+   与 Maven Surefire 相比 / Maven Failsafe 与 Maven Surefire

+   Maven 模型

+   参考链接 / 使用 Maven 属性

+   Maven 插件

+   URL / 还有更多...

+   Maven Surefire

+   关于 / 使用 Mockito 和 Maven Surefire 进行单元测试, 如何做…

+   内存优化

+   参考链接 / 还有更多...

+   面向消息的中间件（MoM） / 使用 RabbitMQ 和 AMQP 堆叠和消费任务

+   消息代理

+   使用全功能消息代理 / 使用全功能消息代理

+   集群能力 / 集群能力 - RabbitMQ

+   STOMP 消息类型 / 更多 STOMP 消息类型

+   StompMessageBrokerRelay / StompMessageBrokerRelay

+   消息驱动的 Bean（MDB）

+   关于 / Spring 事务的相关性

+   消息

+   用于 REST 的国际化 / 为 REST 国际化消息和内容

+   使用 MessageSource beans 进行国际化 / MessageSource beans

+   使用 LocaleResolver / 使用 LocaleResolver

+   发送，分发 / 发送消息以分发

+   SimpMessagingTemplate / SimpMessagingTemplate

+   @SendTo 注释 / The @SendTo 注释

+   使用 Spring Session 进行安全保护 / 使用 Spring Session 和 Redis 保护消息

+   使用 Redis 进行安全保护 / 使用 Spring Session 和 Redis 保护消息

+   Apache HTTP 代理配置 / Apache HTTP 代理配置

+   Redis 服务器安装 / Redis 服务器安装

+   MySQL 服务器安装 / MySQL 服务器安装

+   应用级别的更改 / 应用级别的更改

+   RabbitMQ 配置 / RabbitMQ 配置

+   结果 / 结果

+   Redis 服务器 / Redis 服务器

+   Spring 会话 / Spring 会话

+   SessionRepositoryFilter / SessionRepositoryFilter

+   RedisConnectionFactory / RedisConnectionFactory

+   CookieHttpSessionStrategy / CookieHttpSessionStrategy

+   Tomcat 的 Redis 会话管理器 / Tomcat 的 Redis 会话管理器

+   在 Redis 中查看会话 / 查看/刷新 Redis 中的会话

+   在 Redis 中查看/刷新会话 / 查看/刷新 Redis 中的会话

+   securityContextPersistenceFilter / securityContextPersistenceFilter

+   AbstractSessionWebSocketMessageBrokerConfigurer / AbstractSessionWebSocketMessageBrokerConfigurer

+   AbstractSecurityWebSocketMessageBrokerConfigurer / AbstractSecurityWebSocketMessageBrokerConfigurer

+   Spring 会话，URL / Spring 会话

+   Apache HTTP 代理，额外配置 / Apache HTTP 代理额外配置

+   Spring Data Redis / Spring Data Redis

+   MessageSource beans

+   用于国际化消息 / MessageSource beans

+   ResourceBundleMessageSource / ResourceBundleMessageSource

+   ReloadableResourceBundleMessageSource / ReloadableResourceBundleMessageSource

+   StaticMessageSource / StaticMessageSource

+   定义 / 我们的 MessageSource bean 定义

+   面向消息的中间件（MOM）

+   关于 / 介绍

+   迁移命令 / 迁移

+   Mockito

+   单元测试 / 使用 Mockito 和 Maven Surefire 进行单元测试, 如何做...

+   @Test 注释 / @Test 注释

+   使用 / 使用 Mockito

+   JUnitRunner / MockitoJUnitRunner

+   transferCriticalData 示例 / transferCriticalData 示例

+   registerUser 示例 / registerUser 示例

+   URL / 关于 Mockito

+   JUnit 规则 / JUnit 规则

+   用于创建模拟 / 使用 Mockito 进行模拟

+   MockitoJUnitRunner / MockitoJUnitRunner

+   模拟

+   关于 / Mocks 和 stubs

+   和存根，选择 / 我应该使用模拟还是存根？

+   参考链接 / 我应该使用模拟还是存根？

+   模型

+   在视图中显示，使用 JSTL / 在视图中显示模型，使用 JSTL, 如何做..., 它是如何工作的...

+   在控制器中填充 / 在控制器中填充模型

+   使用 JSP EL 渲染变量 / 使用 JSP EL 渲染变量

+   隐式对象 / 隐式对象

+   模型-视图-控制器（MVC）架构模式

+   关于 / 介绍 Ember.js

+   模型-视图-控制器模式

+   关于 / 模型-视图-控制器模式

+   模型 / 模型-视图-控制器模式

+   视图 / 模型-视图-控制器模式

+   控制器 / 模型-视图-控制器模式

+   模块

+   创建/ 设置 DOM 和创建模块

+   组件，定义/ 定义模块的组件, 工作原理…

+   URL/ 还有更多…

+   mod_alias 模块/ mod_alias 模块

+   mod_proxy 模块/ mod_proxy 模块

+   morris.js 库

+   URL/ 创建响应式内容

+   多用途互联网邮件扩展（MIME）

+   关于/ 上传文件

+   MVC 架构

+   关于/ MVC 架构

+   模型/ MVC 架构

+   视图/ MVC 架构

+   控制器/ MVC 架构

+   最佳实践/ MVC 评论家和最佳实践

+   评论家/ MVC 评论家和最佳实践

+   贫血领域模型/ 贫血领域模型

+   sagan 项目/ 从源代码中学习

+   sagan 项目，URL/ 从源代码中学习

+   MVC 设计模式/ MVC 设计模式

+   MVC 异常

+   URL/ 另请参阅

## N

+   本机 SQL 查询

+   使用/ 使用本机 SQL 查询

+   URL/ 使用本机 SQL 查询

+   导航

+   使用/ 导航

+   重定向选项/ 导航

+   前向选项/ 导航

+   无级联操作

+   关于/ 级联属性

+   Node.js

+   URL/ 设置 Ember CLI

## O

+   OAuth

+   数据，从第三方 API 检索/ 使用 OAuth 从第三方 API 检索数据, 操作方法…

+   OAuth2 认证服务器（AS）

+   关于/ 准备工作

+   OAuth2 授权框架

+   关于/ OAuth2 授权框架

+   实体/ OAuth2 授权框架

+   OAuth 开发

+   别名定义 / OAuth 开发的别名定义

+   面向对象编程（OOP）

+   关于/ 面向方面的编程

+   每个 HTTP 连接策略一个线程 / Spring MVC 中的异步请求处理

+   OpenShift

+   关于/ OpenShift

+   URL/ OpenShift

+   Oracle Hotspot JDK

+   URL/ 操作方法…

## P

+   页面对象

+   使用 FluentLenium/ 使用 FluentLenium 的页面对象

+   使用 Geb/ 使用 Geb 的页面对象

+   分页

+   添加/ 添加分页、过滤和排序功能, 如何做..., 它是如何工作的...

+   Spring 数据分页支持/ Spring 数据分页支持（您会喜欢它！）

+   和存储库中的排序/ 存储库中的分页和排序

+   PagingAndSortingRepository<T,ID>/ PagingAndSortingRepository<T,ID>

+   PageableHandlerMethodArgumentResolver/ web 部分-PageableHandlerMethodArgumentResolver

+   负载映射

+   使用@RequestBody 请求/ 使用@RequestBody 映射请求负载

+   永久代（PermGen）

+   关于/ 自定义 JVM 参数

+   持久化单元

+   关于/ EntityManagerFactory bean 及其持久化单元

+   PhantomJS

+   URL/ 我们的第一个 FluentLenium 测试

+   Pivotal Web Services（PWS）

+   Web 应用程序，部署/ 将您的 Web 应用程序部署到 Pivotal Web Services

+   普通的 Java 对象（POJOs）

+   关于/ 介绍

+   普通的旧 Java 对象（POJO）

+   关于/ 个人资料页面-表单

+   普通的旧 Java 对象（POJOs）

+   关于/ 贫血领域模型

+   普通的旧 Java 对象（POJOs）

+   关于/ 领域对象和实体

+   插件

+   关于/ 插件

+   Maven 编译器插件/ Maven 编译器插件

+   Maven surefire 插件/ Maven surefire 插件

+   Maven enforcer 插件/ Maven enforcer 插件

+   Maven war 插件/ Maven war 插件

+   Maven checkstyle 插件/ Maven checkstyle 插件

+   POD 结构

+   与之一起工作/ 与 POD 结构一起工作

+   切入点设计者（PCDs）

+   关于/ 切入点设计者

+   切入点，@AspectJ 注解

+   关于/ 切入点

+   设计者/ 切入点设计者

+   示例/ 切入点示例

+   POJO（普通的旧 Java 对象）/ Spring 框架背后的设计概念

+   Procfile

+   运行/ Procfile

+   生产配置文件

+   配置/ 生产配置文件

+   个人资料

+   存储，在会话中/ 将个人资料放入会话中

+   个人资料页面

+   关于/ 个人资料页面-表单

+   创建/ 个人资料页面-表单

+   添加验证/ 验证

+   启用客户端验证/ 客户端验证

+   检查点/ 检查点

+   项目对象模型（POM）

+   关于/ 为什么要使用 Maven？

+   项目结构

+   使用 Maven 定义/ 使用 Maven 定义项目结构, 准备就绪, 如何做...

+   创建 Maven 项目/ 新的 Maven 项目，新的 Maven 模块

+   创建 Maven 模块/ 新的 Maven 项目，新的 Maven 模块

+   标准项目层次结构/ 标准项目层次结构

+   在 IDE 中/ IDE 中的项目结构

+   属性

+   注入到 Spring 环境中/ 将属性注入到 Spring 环境中

+   PropertyEditor/ConversionService/ 在 PropertyEditors 或转换器之间进行选择

+   PropertyEditor 实现

+   关于/ 内置的 PropertyEditor 实现

+   PropertyPlaceholderConfigurer

+   关于/ 使用 PropertyPlaceholderConfigurer 外部化属性

+   属性，外部化/ 使用 PropertyPlaceholderConfigurer 外部化属性

+   特定于提供程序的配置，第三方 OAuth2 方案

+   关于/ 特定于提供程序的配置

+   connectionFactoryLocator bean/ 一个入口点-connectionFactoryLocator

+   特定于提供程序的 ConnectionFactories/ 特定于提供程序的 ConnectionFactories

+   使用提供程序帐户登录/ 使用提供程序帐户登录

+   验证的 API 调用，执行/ 执行验证的 API 调用

+   Spring social ConnectController/ Spring social ConnectController

+   SocialAuthenticationFilter/ SocialAuthenticationFilter

+   Spring 社交连接器列表/ Spring 社交连接器列表

+   实现 OAuth2 认证服务器/ 实现 OAuth2 认证服务器

+   和谐发展博客/ 和谐发展博客

+   代理模式

+   URL/ 还有更多...

+   ProxyPassReverse

+   关于/ ProxyPassReverse

+   工作者/ 工作者

## Q

+   查询查找策略

+   定义/ 查询解析方法

+   查询参数

+   关于/ 使用请求参数获取数据

## R

+   @Repository 注释

+   关于/ DAO 支持和@Repository 注释

+   @RequestBody

+   请求负载映射/ 使用@RequestBody 映射请求负载

+   @RequestMapping

+   新的支持类/ 自 Spring MVC 3.1 以来@RequestMapping 的新支持类

+   @RequestMapping 注释/ @RequestMapping

+   @RequestMapping 注释

+   支持/ 广泛支持@RequestMapping 注释

+   setMessageConverters/ setMessageConverters

+   setCustomArgumentResolvers/ setCustomArgumentResolvers

+   setWebBindingInitializer / setWebBindingInitializer

+   作为终极过滤器使用/ @RequestMapping 注释作为终极过滤器

+   @RequestPart

+   用于上传图像/ 使用@RequestPart 上传图像

+   @RunWith 注释

+   关于/ @RunWith 注释

+   RabbitMQ

+   作为多协议消息代理使用/ 将 RabbitMQ 用作多协议消息代理, 如何做...

+   URL / 如何做...

+   指南和文档，URL/ 另请参阅

+   任务，使用 Spring Session 和 Redis 进行保护/ 准备工作

+   任务，使用 Spring Session 和 Redis 进行保护/ 准备工作

+   raphael.js 库

+   URL / 创建响应式内容

+   React

+   关于/ 玩家

+   ReactJS

+   关于/ SPA 框架

+   Redis

+   消息，使用 Spring Session 和 Redis 进行保护/ 使用 Spring Session 和 Redis 保护消息

+   URL / Redis 服务器安装, 分布式会话

+   激活/ 激活 Redis, 激活 Redis

+   关系，EJB3 实体

+   定义/ 定义关系

+   选择/ 实体之间的关系是如何选择的

+   远程

+   URL / setMessageConverters

+   修复命令/ 修复, 关于 Flyway Maven 插件

+   存储库管理器

+   关于/ 存储库管理器

+   URL / 还有更多...

+   REpresentational State Transfer (REST)

+   关于/ REST 的定义

+   Restful CloudStreetMarket/ RESTful CloudStreetMarket

+   REpresentational State Transfer (REST)

+   关于/ 为 JSON 和 XML 媒体构建 RESTful 服务

+   请求通道/ Spring 4 中 STOMP over WebSocket 和回退选项

+   RequestMappingHandlerAdapter

+   URL / 自 Spring MVC 3.1 以来@RequestMapping 的新支持类

+   RequestMappingHandlerAdapter bean

+   关于 / 一个超级 RequestMappingHandlerAdapter bean

+   资源

+   处理 / 处理资源

+   ResourceSupport 类 / ResourceSupport 类

+   响应通道 / Spring 4 中 STOMP over WebSocket 和回退选项

+   ResponseEntityExceptionHandler

+   URL / JavaDocs

+   响应式内容

+   创建 / 创建响应式内容

+   响应式单页 Web 设计

+   使用 Bootstrap 设置 / 使用 Bootstrap 设置和自定义响应式单页 Web 设计, 如何做...

+   自定义 Bootstrap 主题 / 自定义 Bootstrap 主题

+   响应式单页 Web 设计

+   安装 Bootstrap 主题 / 安装 Bootstrap 主题

+   自定义 Bootstrap 主题 / 自定义 Bootstrap 主题

+   REST

+   关于 / 什么是 REST？

+   Rest-assured

+   与之集成测试 / 使用 Cargo，Rest-assured 和 Maven failsafe 进行集成测试, 如何做..., 它是如何工作的...

+   关于 / Rest assured

+   静态导入 / 静态导入

+   用法 / 一种给定，当，然后的方法

+   REST-assured

+   示例 / 更多 REST-assured 示例

+   示例，URL / 更多 REST-assured 示例

+   REST 控制器

+   单元测试 / 单元测试 REST 控制器

+   REST 环境

+   凭据，存储 / 在 REST 环境中存储凭据

+   客户端（AngularJS） / 客户端（AngularJS）

+   服务器端 / 服务器端

+   微服务，用于身份验证 / 用于微服务的身份验证

+   使用 BASIC 身份验证 / 使用 BASIC 身份验证

+   使用 OAuth 进行登录 / 使用 OAuth2

+   HTML5 SessionStorage / HTML5 SessionStorage

+   BCryptPasswordEncoder / BCryptPasswordEncoder

+   HTTP 头，使用 AngularJS 设置 / 使用 AngularJS 设置 HTTP 头

+   浏览器支持，用于 localStorage / 用于 localStorage 的浏览器支持

+   SSL 和 TLS / 关于 SSL 和 TLS

+   RESTful API，调试

+   关于 / 调试 RESTful API

+   JSON 格式化扩展 / JSON 格式化扩展

+   浏览器中的 RESTful 客户端 / 浏览器中的 RESTful 客户端

+   httpie / httpie

+   RESTful web 服务，属性

+   客户端-服务器 / 什么是 REST？

+   无状态的 / 什么是 REST？

+   可缓存的 / 什么是 REST？

+   统一接口 / 什么是 REST？

+   分层的 / 什么是 REST？

+   REST 处理程序

+   扩展，到 HTTP 方法 / 将 REST 处理程序扩展到所有 HTTP 方法, 如何做…, 它是如何工作的...

+   HTTP/1.1 规范 / HTTP/1.1 规范 - RFC 7231 语义和内容

+   负载映射，使用@RequestBody 请求 / 使用@RequestBody 映射请求负载

+   HttpMessageConverters / HttpMessageConverters

+   @RequestPart，用于上传图像 / 使用@RequestPart 上传图像

+   事务管理 / 事务管理

+   Richardson 的成熟模型

+   关于 / Richardson 的成熟模型

+   级别 0 - HTTP / 级别 0 - HTTP

+   级别 1 - 资源 / 级别 1 - 资源

+   级别 2 - HTTP 动词 / 级别 2 - HTTP 动词

+   级别 3 - 超媒体控制 / 级别 3 - 超媒体控制

+   Richardson 成熟模型

+   关于 / Richardson 成熟模型

+   URL / Richardson 成熟模型

+   ROME 项目

+   URL / 提供的 HttpMessageConverters

+   根名称服务器 / DNS 配置或主机别名

+   路由

+   处理 / 处理路由

+   例行

+   需要 / 为什么需要这样的例行？

## S

+   @SendTo 注释 /  @SendTo 注释

+   Saas 提供商

+   URL / Spring 社交连接器列表

+   模式，EJB3 实体

+   映射 / 映射模式

+   表，映射 / 映射表

+   列，映射 / 映射列

+   字段，注释 / 注释字段或 getter

+   getter，注释 / 注释字段或 getter

+   主键，映射 / 映射主键

+   标识符生成 / 标识符生成

+   SearchApiController 类

+   在 search.api 包中创建 / 客户是王

+   securityContextPersistenceFilter / securityContextPersistenceFilter

+   安全头

+   关于 / 授权用户

+   URL / 授权用户

+   自签名证书

+   生成 / 生成自签名证书

+   序列化器

+   URL / Jackson 自定义序列化器

+   服务类 / 基于 XML 的配置元数据

+   服务提供商（SP）

+   关于 / 准备就绪

+   服务

+   授权 / 在服务和控制器上进行授权, 如何做...

+   SessionRepositoryFilter

+   关于 / SessionRepositoryFilter

+   RedisConnectionFactory / RedisConnectionFactory

+   基于 setter 的 DI

+   关于 / 基于构造函数还是基于 setter 的 DI - 哪个更好？

+   SimpleJdbc 类 / SimpleJdbc 类

+   简单文本导向消息协议（STOMP）

+   关于 / STOMP 协议

+   URL / STOMP 协议

+   简单 URL 映射

+   用于配置控制器 / 使用简单 URL 映射配置控制器, 如何做...

+   简单 WebSocket 应用程序

+   创建 / 创建一个简单的 WebSocket 应用程序

+   单页应用程序（SPA）

+   动机 / SPA 背后的动机

+   关于 / 解释 SPA

+   架构优势 / SPA 的架构优势

+   单页应用

+   关于 / 单页应用程序

+   建议 / 参与者

+   未来的增强 / 未来

+   无状态选项 / 无状态化

+   参考链接 / 无状态化

+   SLF4j

+   案例 / SLF4j 的案例

+   SLF4J 桥接器 / SLF4J 桥接器

+   社交事件

+   使用 STOMP 通过 SockJS 进行流式传输 / 使用 STOMP 通过 SockJS 进行流式传输社交事件 , 如何做...

+   Apache HTTP 代理配置 / Apache HTTP 代理配置

+   前端 / 前端

+   前端，URL / 前端

+   后端 / 后端, 它是如何工作的...

+   SockJS

+   关于 / SockJS

+   URL / SockJS

+   回退，选项 / 还有更多...

+   客户端查询，URL / 还有更多...

+   Sockjs

+   关于 / WebSockets

+   SPA 框架

+   关于 / SPA 框架

+   AngularJS / SPA 框架

+   ReactJS / SPA 框架

+   Ember.js / SPA 框架

+   SpEL（Spring 表达式语言）

+   关于 / 查询解析方法

+   SpEL API

+   关于 / SpEL API

+   接口和类 / SpEL API

+   Spock

+   用于单元测试 / 使用 Spock 进行单元测试

+   Spring

+   使用 / 使用 Spring 进行测试

+   安装 / 安装 Spring，Spring MVC 和 Web 结构, 如何做..., 它是如何工作的...

+   Maven 依赖项的继承 / Maven 依赖项的继承

+   包括第三方依赖项 / 包括第三方依赖项

+   Web 资源 / Web 资源

+   Java 持久性 API（JPA），配置 / 在 Spring 中配置 Java 持久性 API, 如何做..., 它是如何工作的...

+   生态系统 / Spring 生态系统

+   URL / Spring 生态系统

+   核心 / 核心

+   执行 / 执行

+   XD 项目，URL / 执行

+   数据 / 数据

+   值得注意的项目 / 其他值得注意的项目

+   Spring 的 JSF 集成

+   关于 / Spring 的 JSF 集成

+   Spring 的 Struts 集成

+   关于 / Spring 的 Struts 集成

+   Spring 管理的 DataSource bean

+   关于 / Spring 管理的 DataSource bean

+   spring-messaging 模块

+   关于 / Spring 4 中的 STOMP over WebSocket 和回退选项

+   spring-security-crypto

+   URL / 社交连接持久性

+   Spring-websocket-portfolio

+   URL / 另请参阅

+   Spring 4.2+

+   URL / 发布应用程序事件的更好方法

+   Spring AOP

+   定义 / Spring AOP - 定义和配置样式

+   配置样式 / Spring AOP - 定义和配置样式

+   Spring 应用程序

+   关于 / 你的第一个 Spring 应用程序

+   控制反转（IoC）/ 控制反转解释

+   Spring Beans

+   在集成测试中注入 / 将 Spring Beans 注入集成测试, 如何做...

+   SpringJUnit4ClassRunner / SpringJUnit4ClassRunner

+   @ContextConfiguration 注释 /  @ContextConfiguration 注释, 还有更多...

+   JdbcTemplate / JdbcTemplate

+   样板逻辑，抽象 / 抽象样板逻辑

+   自动生成的 ID，提取 / 提取自动生成的 ID

+   Spring Boot

+   登录 / 个人资料页面-表单

+   URL / 个人资料页面-表单

+   Spring Data

+   关于 / Spring Data, Spring Data

+   子项目，定义 / Spring Data

+   Commons / Spring Data Commons

+   存储库规范 / Spring Data 存储库规范

+   MongoDB / Spring Data MongoDB

+   领域对象和实体 / 领域对象和实体

+   Spring 事务支持 / Spring 事务支持

+   Spring Data Commons

+   定义 / Spring Data Commons

+   Spring Data JPA

+   配置 / Spring Data JPA 配置

+   使用 / 利用 JPA 和 Spring Data JPA, 如何做..., 它是如何工作的...

+   注入 EntityManager 实例 / 注入 EntityManager 实例

+   Java 持久性查询语言（JPQL），使用 / 使用 JPQL

+   代码，减少 / 使用 Spring Data JPA 减少样板代码

+   查询，创建 / 创建查询

+   实体，持久化 / 持久化实体

+   本地 SQL 查询，使用 / 使用本地 SQL 查询

+   配置事务 / 事务

+   URL / 数据

+   Spring Data 层

+   异常处理 / 在 Spring Data 层处理异常

+   Spring Data Mongo

+   URL / 数据

+   Spring Data MongoDB

+   关于 / Spring Data MongoDB

+   启用 / 启用 Spring Data MongoDB

+   MongoRepository / MongoRepository

+   Spring Data Redis（SDR）框架 / Spring Data Redis 和 Spring Session Data Redis

+   Spring Data 存储库

+   自定义实现 / 另请参阅

+   参考链接 / 另请参阅

+   Spring Data 存储库规范

+   关于 / Spring Data 存储库规范

+   Spring Data JPA / Spring Data JPA

+   Spring Data JPA，启用 / 启用 Spring Data JPA

+   JpaRepository / JpaRepository

+   Spring Data REST

+   URL / 另请参阅, 数据

+   Spring EL

+   URL / Spring EL

+   Spring 表达式语言

+   关于 / Spring 表达式语言

+   特性 / SpEL 特性

+   注解支持 / SpEL 注解支持

+   Spring 表达式语言（SpEL）

+   关于 / Spring 表达式语言

+   URL / Spring 表达式语言

+   使用请求参数获取数据 / 使用请求参数获取数据

+   Spring 表单

+   在 JSP 中组合 / 在 JSP 中组合表单

+   验证 / 验证表单

+   Spring 表单标签库

+   关于 / Spring 和 Spring 表单标签库

+   Springfox

+   URL / Swagger 文档

+   Spring 框架

+   URL / 内置的 PropertyEditor 实现

+   Spring 框架

+   设计概念 / Spring 框架背后的设计概念

+   关于 / Spring 框架带来了什么？

+   Spring 框架模块

+   关于 / Spring 框架模块

+   Spring HATEOAS 资源

+   DTO，转换成 / 将 DTO 转换为 Spring HATEOAS 资源, 如何做…

+   关于 / Spring HATEOAS 资源

+   ResourceSupport 类 / ResourceSupport 类

+   资源类 / 资源类

+   可识别的接口 / 可识别的接口

+   实体的@Id，抽象化 / 抽象化实体的@Id, 还有更多…

+   URL / 另请参阅, 另请参阅

+   Spring 集成

+   URL / 其他值得注意的项目

+   Spring IoC 容器

+   关于 / Spring IoC 容器

+   Spring IO 参考文档

+   URL / Spring IO 参考文档

+   Spring JDBC

+   方法 / Spring JDBC 抽象

+   Spring JDBC 抽象

+   关于 / Spring JDBC 抽象

+   JdbcTemplate / JdbcTemplate

+   SimpleJdbc 类 / SimpleJdbc 类

+   SpringJUnit4ClassRunner / SpringJUnit4ClassRunner

+   Spring 景观

+   关于 / Spring 景观

+   Spring 框架模块 / Spring 框架模块

+   Spring 工具套件（STS） / Spring 工具套件（STS）

+   Spring 子项目 / Spring 子项目

+   Spring MVC

+   Web 应用程序 / Spring MVC 架构

+   Spring MVC

+   特性 / Spring MVC 的特性

+   architecture / Spring MVC 的架构和组件, Spring MVC 架构

+   components / Spring MVC 的架构和组件

+   asynchronous request processing / Spring MVC 中的异步请求处理

+   installing / 安装 Spring，Spring MVC 和 web 结构, 如何做..., 它是如何工作的...

+   about / Spring MVC 概述

+   front controller / 前端控制器

+   MVC 设计模式 / MVC 设计模式

+   flow / Spring MVC 流程

+   DispatcherServlet / DispatcherServlet-Spring MVC 入口点

+   annotation-defined controllers / 注解定义的控制器

+   Spring MVC 1-0-1

+   about / Spring MVC 1-0-1

+   reference link / Spring MVC 1-0-1

+   Spring MVC 3.1 / 自 Spring MVC 3.1 以来的@RequestMapping 新支持类

+   Spring MVC 应用程序

+   creating / 你的第一个 Spring MVC 应用程序

+   setting up / 设置 Spring MVC 应用程序

+   project structure / Spring MVC 应用程序的项目结构

+   web.xml 文件 / 将 web.xml 文件 spring 化的 web 应用程序

+   web app, springifying / 将 web.xml 文件 spring 化的 web 应用程序

+   ApplicationContext 文件 / Spring MVC 应用程序中的 ApplicationContext 文件

+   HomeController / HomeController-主屏幕的@Controller

+   home.jsp 文件 / home.jsp 文件-登陆界面

+   incoming requests, handling / 处理传入请求

+   Spring Reactor

+   URL / 其他值得注意的项目

+   about / 其他值得注意的项目

+   Spring 安全

+   users, adapting / 将用户和角色适应 Spring 安全, 如何做..., 它是如何工作的...

+   roles, adapting / 将用户和角色适应 Spring 安全, 如何做..., 它是如何工作的...

+   about / Spring 安全简介

+   ThreadLocal context holders / ThreadLocal 上下文持有者

+   interfaces / Noticeable Spring Security interfaces

+   Authentication interface / The Authentication interface

+   UserDetails interface / The UserDetails interface

+   UserDetailsManager interface / The UserDetailsManager interface

+   GrantedAuthority interface / The GrantedAuthority interface

+   Spring security, reference

+   about / Spring Security reference

+   technical overview / Technical overview

+   URL / Technical overview, Sample applications

+   sample applications / Sample applications

+   core services / Core services

+   Spring Security 4

+   reference link / Testing the authentication

+   Spring security authorities

+   about / Spring Security authorities

+   configuration attributes / Configuration attributes

+   Security Interceptor protecting secure objects / Configuration attributes

+   Spring security filter-chain

+   URL / SocialAuthenticationFilter

+   Spring security namespace

+   <http> component / The <http> component

+   Spring security filter-chain / The Spring Security filter-chain

+   <http> configuration / Our <http> configuration

+   BasicAuthenticationFilter / BasicAuthenticationFilter

+   with authenticationEntryPoint / With an authenticationEntryPoint

+   URL / In the Spring Security reference

+   Spring security OAuth project

+   URL / Implementing an OAuth2 authentication server

+   Spring security reference

+   URL / In the Spring Security reference, The Spring Security reference

+   Spring session

+   messages, securing with / Securing messages with Spring Session and Redis

+   Spring Social

+   about / Setting up Spring Social Twitter

+   URL / Setting up Spring Social Twitter

+   Spring social reference

+   URL / The Spring social ConnectController

+   Spring Social Twitter project

+   creating / Enough Hello Worlds, let's fetch tweets!

+   application, registering / Registering your application

+   setting up / Setting up Spring Social Twitter

+   Twitter, accessing / Accessing Twitter

+   Spring subprojects

+   about / Spring subprojects

+   URL / Spring subprojects

+   Spring Tool Suite (STS)

+   关于

+   URL

+   Spring 事务

+   定义

+   声明式事务管理

+   使用@Transactional 注解

+   程序化事务管理

+   Spring 验证器

+   使用 Spring 验证器

+   ValodationUtils 实用程序

+   国际化验证错误

+   Spring WebSockets

+   URL，参见

+   Spring WebSocket 支持

+   关于 Spring WebSocket 支持

+   一体化配置

+   消息处理程序，通过@MessageMapping 定义

+   Sql*类

+   使用 Sql*类定义 JDBC 操作

+   SSL

+   参考链接

+   关于 SSL

+   生成自签名证书

+   创建

+   为 http 和 https 通道创建

+   在受保护的服务器后面创建

+   权威性（SOA）

+   状态码

+   500 服务器错误，状态码和异常处理

+   405 方法不受支持，状态码和异常处理

+   404 未找到，状态码和异常处理

+   400 错误请求

+   200 OK，状态码和异常处理

+   使用 ResponseEntity

+   带异常的状态码

+   状态码

+   关于状态码和异常处理

+   StompMessageBrokerRelay

+   STOMP over SockJS

+   社交事件，使用 STOMP 通过 SockJS 进行流式传输

+   STOMP over WebSocket

+   关于/ Spring 4 中的 STOMP over WebSocket 和回退选项

+   流，Java 8

+   关于/ Java 8 流和 lambda

+   存根

+   关于/ 模拟和存根

+   创建，用于测试 bean/ 在测试时存根化我们的 bean

+   和模拟，选择/ 我应该使用模拟还是存根？

+   支持的 bean，DispatcherServlet

+   HandlerMapping/ 支持 DispatcherServlet 的 Bean 及其角色

+   HandlerAdapter/ 支持 DispatcherServlet 的 Bean 及其角色

+   HandlerExceptionResolver/ 支持 DispatcherServlet 的 Bean 及其角色

+   ViewResolver/ 支持 DispatcherServlet 的 Bean 及其角色

+   LocaleResolver/ 支持 DispatcherServlet 的 Bean 及其角色

+   LocaleContextResolver/ 支持 DispatcherServlet 的 Bean 及其角色

+   ThemeResolver/ 支持 DispatcherServlet 的 Bean 及其角色

+   MultipartResolver/ 支持 DispatcherServlet 的 Bean 及其角色

+   FlashMapManager/ 支持 DispatcherServlet 的 Bean 及其角色

+   Swagger

+   API，文档/ 准备就绪, 如何做..., 它是如何工作的...

+   API，暴露/ 如何做..., 它是如何工作的...

+   不同的工具/ 不同的工具，不同的标准

+   关于/ Swagger 文档

+   Swagger.io

+   URL/ Swagger.io

+   Swagger UI

+   关于/ Swagger UI

## T

+   @Test 注释

+   关于/ @Test 注释

+   预期和超时参数/ 预期和超时参数

+   @Transactional 注释

+   使用/ 使用@Transactional 注释

+   事务管理，启用/ 启用@Transactional 的事务管理

+   Taskify 应用程序

+   构建/ 构建 Taskify 应用程序

+   Taskify Ember 应用

+   构建/ 构建 Taskify Ember 应用

+   Taskify，设置为 Ember CLI 项目/ 将 Taskify 设置为 Ember CLI 项目

+   Ember Data，设置/ 设置 Ember Data

+   应用程序路由，配置/ 配置应用程序路由

+   主屏幕，构建/ 构建主屏幕

+   构建用户屏幕 / 构建用户屏幕

+   自定义助手，构建 / 构建自定义助手

+   操作处理程序，添加 / 添加操作处理程序

+   自定义组件，构建 / 构建自定义组件-模态窗口

+   使用{{modal-window}}构建 userEditModal / 使用{{modal-window}}构建 userEditModal

+   构建任务屏幕 / 构建任务屏幕

+   任务

+   使用 RabbitMQ 堆叠 / 使用 RabbitMQ 和 AMQP 堆叠和消费任务, 如何做…

+   使用 RabbitMQ 消费 / 使用 RabbitMQ 和 AMQP 堆叠和消费任务, 如何做…

+   发送方 / 发送方

+   消费者端 / 消费者端

+   客户端 / 客户端

+   消息架构概述 / 消息架构概述

+   可扩展模型 / 可扩展模型

+   模板方法

+   关于 / JdbcTemplate

+   术语，面向方面的编程（AOP）

+   方面 / AOP 概念和术语

+   连接点 / AOP 概念和术语

+   建议 / AOP 概念和术语

+   切入点 / AOP 概念和术语

+   目标对象 / AOP 概念和术语

+   编织 / AOP 概念和术语

+   介绍 / AOP 概念和术语

+   测试驱动开发（TDD） / 使用 Spring 进行测试

+   测试驱动开发（TTD）

+   关于 / 测试驱动开发

+   测试框架

+   关于 / 介绍 Ember.js

+   测试支持，Spring

+   模拟对象 / 模拟对象

+   单元和集成测试工具 / 单元和集成测试工具

+   th*each 标签

+   关于 / 访问 Twitter

+   Spring 第三方依赖

+   Spring 框架依赖模型 / Spring 框架依赖模型

+   Spring MVC 依赖 / Spring MVC 依赖

+   使用 Maven 属性 / 使用 Maven 属性

+   第三方 OAuth2 方案

+   使用第三方 OAuth2 方案进行身份验证 / 使用第三方 OAuth2 方案进行身份验证, 如何做…, 它是如何工作的…

+   应用程序角度 / 从应用程序角度

+   Yahoo!观点 / 从 Yahoo!的观点

+   OAuth2 显式授权流程 / OAuth2 显式授权流程

+   刷新令牌和访问令牌 / 刷新令牌和访问令牌

+   Spring 社交 / Spring 社交-角色和关键功能

+   社交连接持久性 / 社交连接持久性

+   特定于提供程序的配置 / 特定于提供程序的配置

+   Thymeleaf

+   关于 / 解析 Thymeleaf 视图, 使用 Thymeleaf

+   视图，解析 / 解析 Thymeleaf 视图

+   使用 / 使用 Thymeleaf

+   参考链接 / 使用 Thymeleaf, Thymeleaf 安全标签

+   页面，添加 / 我们的第一个页面

+   thymeleaf 安全标签

+   使用 / Thymeleaf 安全标签

+   Tomcat（7+）

+   参考链接 / 全局与本地事务

+   Tomcat 8

+   Eclipse，配置 / 准备就绪, 如何做...

+   URL / 如何做...

+   Eclipse，集成 / Eclipse 中的 Tomcat 8

+   Tomcat 连接器

+   关于 / Tomcat 连接器

+   HTTP 连接器 / HTTP 连接器

+   AJP 连接器 / AJP 连接器

+   URL / 还有更多...

+   工具

+   关于 / 合适的工具

+   JUnit / 合适的工具

+   AssertJ / 合适的工具

+   Mockito / 合适的工具

+   DbUnit / 合适的工具

+   Spock / 合适的工具

+   交易

+   关于 / Spring 事务支持

+   事务属性

+   定义 / Spring 事务基础

+   事务管理

+   关于 / 事务管理

+   构建 / 简化的方法

+   ACID 属性 / ACID 属性

+   全局事务，本地事务 / 全局与本地事务

+   推特

+   URL / 注册您的应用程序, Twitter 身份验证

+   Twitter 身份验证

+   设置 / Twitter 身份验证

+   社交身份验证，设置 / 设置社交身份验证

+   编码 / 解释

+   Typescript

+   关于 / 未来

+   URL / 未来

## U

+   UI 行为

+   处理，使用的组件 / 使用组件处理 UI 行为

+   ToggleButton 组件，逐步构建 / 逐步构建 ToggleButton 组件

+   使用 Handlebars 构建 UI 模板

+   关于 / 使用 Handlebars 构建 UI 模板

+   Handlebars 助手 / Handlebars 助手

+   数据绑定，带输入助手 / 带输入助手的数据绑定

+   控制流助手，在 Handlebars 中使用 / 在 Handlebars 中使用控制流助手

+   事件助手，使用 / 使用事件助手

+   统一表达式语言（UEL） / Spring 表达式语言

+   单元测试

+   关于 / 我应该如何测试我的代码？, 单元测试

+   工具 / 工作的正确工具

+   编写 / 我们的第一个单元测试

+   REST 控制器 / 对 REST 控制器进行单元测试

+   使用 Spock / 使用 Spock 进行单元测试

+   URI 模板模式

+   关于 / URI 模板模式

+   Ant 样式路径模式 / Ant 样式路径模式

+   路径模式比较 / 路径模式比较

+   ViewResolvers / ViewResolvers

+   URL 映射

+   带矩阵变量 / 带矩阵变量的 URL 映射

+   UserDetails 接口

+   关于 / UserDetails 接口

+   认证提供者 / 认证提供者

+   UserDetailsManager 接口

+   关于 / UserDetailsManager 接口

+   用户体验范式

+   关于 / 用户体验范式

+   用户管理 API

+   关于 / 用户管理 API

+   用户

+   预调用处理 / 预调用处理

+   AccessDecisionManager 接口 / AccessDecisionManager

+   调用处理 / 调用处理后

+   基于表达式的访问控制 / 基于表达式的访问控制

+   Web 安全表达式 / Web 安全表达式

+   方法安全表达式 / 方法安全表达式

+   @PreAuthorize，用于访问控制 / 使用@PreAuthorize 和@PostAuthorize 进行访问控制

+   @PostAuthorize，用于访问控制 / 使用@PreAuthorize 和@PostAuthorize 进行访问控制

+   集合过滤，使用@PreFilter / 使用@PreFilter 和@PostFilter 过滤集合

+   使用@PostFilter 进行集合过滤 / 使用@PreFilter 和@PostFilter 进行集合过滤

+   JSR-250 / JSR-250 和传统方法安全

## V

+   验证命令 / 验证

+   验证，个人资料页面

+   添加 / 验证

+   参考链接 / 验证

+   自定义验证消息 / 自定义验证消息

+   定义自定义注释 / 自定义验证的自定义注释

+   ValidationUnits 实用程序

+   URL / ValidationUtils

+   验证器

+   参考链接 / 客户端验证

+   ViewResolver

+   用于配置回退控制器 / 使用 ViewResolver 配置回退控制器, 如何做..., 它是如何工作的...

+   视图解析器

+   AbstractCachingViewResolver / 解析视图

+   XmlViewResolver / 解析视图

+   ResourceBundleViewResolver / 解析视图

+   基于 URL 的视图解析器/ 解析视图

+   InternalResourceViewResolver / 解析视图

+   VelocityViewResolver / 解析视图

+   FreeMarkerViewResolver / 解析视图

+   JasperReportsViewResolver / 解析视图

+   TilesViewResolver / 解析视图

+   视图

+   使用 / 使用视图

+   解析 / 解析视图

+   JSP 视图，解析 / 解析 JSP 视图

+   在 JSP 页面中绑定模型属性 / 使用 JSTL 在 JSP 页面中绑定模型属性

+   视图技术，Spring MVC / 更多视图技术

## W

+   web.xml 文件

+   参考链接 / 还有更多...

+   Web 应用程序

+   Dispatcher Servlet / DispatcherServlet

+   显示数据 / 将数据传递给视图

+   部署到 Pivotal Web Services（PWS） / 将您的 Web 应用程序部署到 Pivotal Web Services

+   安装 Cloud Foundry CLI 工具 / 安装 Cloud Foundry CLI 工具

+   组装 / 组装应用程序

+   激活 Redis / 激活 Redis

+   在 Heroku 上部署 / 将您的 Web 应用程序部署到 Heroku

+   在 Heroku 上设置 / 设置应用程序

+   在 Heroku 上执行 / 运行您的应用程序

+   改进 / 改进您的应用程序

+   WebApplicationObjectSupport

+   URL/ WebContentGenerator 提供的更多功能

+   Web 存档（war）

+   关于/ 准备就绪

+   Web 缓存

+   URL/ Web 缓存

+   WebContentGenerator

+   关于/ WebContentGenerator 提供的更多功能

+   WebContentInterceptor

+   定义/ 定义通用的 WebContentInterceptor, 如何做..., 它是如何工作的...

+   控制器/ 控制器的常见行为

+   会话，需要/ 需要会话

+   会话，同步/ 同步会话

+   缓存头管理/ 缓存头管理

+   HTTP 方法支持/ HTTP 方法支持

+   高级拦截器/ 高级拦截器

+   请求生命周期/ 请求生命周期

+   WebJars

+   用于材料设计/ 使用 WebJars 进行材料设计

+   布局，使用/ 使用布局

+   使用导航/ 导航

+   TweetController，使用/ 检查点

+   Web 资源

+   关于/ Web 资源

+   目标运行环境/ 目标运行环境

+   Spring Web 应用程序上下文/ Spring Web 应用程序上下文

+   插件/ 插件

+   Web 服务

+   URL/ setMessageConverters

+   Web Servlet 支持/ Web Servlet 支持

+   WebSocket

+   关于/ WebSockets

+   使用/ WebSockets

+   参考链接/ WebSockets

+   WebSocket 应用程序

+   消息，广播给单个用户/ 在 WebSocket 应用程序中向单个用户广播消息

+   WebSockets

+   关于/ WebSockets 简介

+   URL/ WebSockets 简介

+   生命周期/ WebSocket 生命周期

+   URI 方案/ 两个专用 URI 方案

+   Web 结构

+   关于/ 安装 Spring，Spring MVC 和 Web 结构

+   创建/ 准备就绪, 如何做..., 它是如何工作的...

+   Web 工具平台（WTP）插件

+   关于/ Eclipse 中的 Tomcat 8

+   工作者/ 工作者

## X

+   XML

+   生成/ 生成 XML

+   XML 编组，支持

+   关于/ 支持 XML 编组

+   XStream 编组器/ XStream 编组器

+   XML 解析器

+   JAXB2 实现，使用为 / 使用 JAXB2 实现作为 XML 解析器

+   基于 XML 模式的 AOP

+   关于 / 基于 XML 模式的 AOP

+   XStream

+   URL / XStream 编组器

+   X Stream 转换器

+   URL / XStream 转换器

## Y

+   Yahoo! API

+   URL / 另请参阅

+   Yahoo!财务股票代码 / 另请参阅

## Z

+   zipcloud-core

+   关于 / 准备工作

+   zipcloud-parent

+   关于 / 准备工作
