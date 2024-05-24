# 精通 Spring 应用开发（四）

> 原文：[`zh.annas-archive.org/md5/A95A09924E8304BAE696F70C7C92A54C`](https://zh.annas-archive.org/md5/A95A09924E8304BAE696F70C7C92A54C)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十章：Spring 缓存

自 Spring 3.1 版本以来，Spring 缓存已经开始起作用。Spring 还添加了注释来支持缓存机制。缓存抽象层提供了很多支持来使用不同的缓存解决方案。在本章中，我们将探讨 Spring 缓存。我们将看到如何设置 Spring 缓存。您可以理想地将您的缓存代码与业务逻辑绑定在一起。

缓存避免重新计算。理想情况下，您不必再次重复相同的过程来获取相同的值。缓存将值存储在内存中。您可以随时选择您想要缓存和不想要缓存的内容。这是架构设计的一部分。一旦数据被缓存，它将从缓存的内存中检索，从而节省计算时间。

# 用于缓存的 Spring 注释

Spring 提出了两个主要的用于缓存的注释；我们将在整个章节中使用这些。以下是这两个注释：

+   `@Cacheable`：这可以用于标记将存储在缓存中的方法和返回值。这可以应用于方法或类型级别。

+   当应用于方法级别时，被注释方法的返回值将被缓存

+   当应用于类型级别时，每个方法的返回值都被缓存

+   `@CacheEvict`：用于释放缓存内存中的对象。

## @Cacheable 用法

让我们看一下在类型级别应用`@Cacheable`注解的小实现。我们考虑一个简单的 DAO 类，有两个不同名称的方法。我们使用了`@Cacheable`注解，它接受三个参数：

+   值

+   键

+   条件

现在我们可以实现它：

```java
@Cacheable(value = "product")
public class ProductDAO {

  public Product findProduct(String Name, int price) {

    return new Product(Name,price);
  }
  public Product findAnotherProduct(String Name, int price) {

     return new Product(Name,price);
  }
}
```

在上述代码中，Spring 缓存默认会分配一个缓存键，带有注释的签名。

我们还可以提供自定义键。使用 SpEL 表达式，以下是提供自定义缓存键的演示：

```java
public class ProductDAO {

  public Product findProduct(String productName, int price) {

    return new Product(productName,price);
  }

@Cacheable(value = "product" ,key="#productName")
  public Product findAnotherProduct(String productName, int price) {

     return new Product(productName,price);
  }
}
```

我们也可以执行条件缓存。让我们对价格大于 1000 的产品进行条件缓存：

```java
@Cacheable(value = "product", condition = "#price>1000")
  public Product findProductByPrice(String productName, int price) {

    return new Product(String productName, int price);
  }
```

## @CacheEvict 用法

让我们看一下如何使用`@CacheEvict`来刷新缓存中的单个对象和多个对象。每次用户添加评分时，`productId`都将有新的缓存值。以前的评分将被清除：

```java
@Transactional
@CacheEvict(value="products", key="#rating.producttId")
public ItemRatingResponse addRatingForproduct(Rating rating, Integer currentNumberOfRatings, Float currentRating) {
  return addRatingForItem(rating, currentNumberOfRatings, currentRating);
}
```

以下是用于刷新所有缓存对象的`@CacheEvict`用法。您可以看到一次刷新多个对象。

```java
@Caching(evict = {
    @CacheEvict(value="referenceData", allEntries=true),
    @CacheEvict(value="product", allEntries=true),
    @CacheEvict(value="searchResults", allEntries=true),
    @CacheEvict(value="newestAndRecommendedproducts", allEntries=true),
    @CacheEvict(value="randomAndTopRatedproducts", allEntries=true)	    
  })
public void flushAllCaches() {
  LOG.warn("All caches have been completely flushed");
}
```

# Spring 缓存存储库

缓存存储库是实际对象保存的地方。Spring 支持两种类型的存储库：

使用`ConcurrentMap`也是在应用程序中实现缓存的选项。存储库对代码几乎没有（如果有的话）影响，并且在不同存储库之间切换应该非常容易。我们的对象将被缓存在 ConcurrentMap 中。

我们可以根据以下代码配置 ConcurrentMap：

```java
  <bean id="cacheManager" class="org.springframework.cache.support.SimpleCacheManager">
    <property name="caches">
     <set>
       <bean class="org.springframework.cache.concurrent.ConcurrentMapCacheFactoryBean" p:name="task" />
     </set>
    </property>
       </bean>
```

## Ehcache 流行的库

这个缓存被许多流行的框架用来处理应用程序中的缓存。ehcache 被 hibernate 框架用来处理应用程序的 DAO（数据访问）层中的缓存。

我们可以有多个存储库。请注意，此存储库的名称必须与注释中使用的名称相同。

# Spring CacheManager

让我们看一下在 Spring 缓存框架中用于配置缓存的核心接口和实现类。Spring CacheManager 实际上是 Spring 缓存框架中的一个接口。以下是实现 CacheManager 接口的类的列表：

+   `AbstractCacheManager`：这个抽象类实现了`CacheManager`接口。它对于静态环境很有用，其中后备缓存不会改变。

+   `CompositeCacheManager`：这是复合`CacheManager`实现，它遍历给定的`CacheManager`实例集合。它允许自动将`NoOpCacheManager`添加到列表中，以处理没有后备存储的缓存声明。

+   `ConcurrentMapCacheManager`：这是`CacheManager`的实现，它会为每个`getCache(java.lang.String)`请求懒惰地构建`ConcurrentMapCache`实例。它还支持一个静态模式，其中缓存名称集合是通过`setCacheNames(java.util.Collection)`预定义的，不会在运行时动态创建更多的缓存区域。

+   `ehCacheCacheManager`：由 EhCache `CacheManager`支持的`CacheManager`。

+   `NoOpCacheManager`：适用于禁用缓存的基本的无操作 CacheManager 实现，通常用于支持缓存声明而没有实际的后备存储。它将简单地接受任何项目到缓存中，而不实际存储它们。

+   `SimpleCacheManager`：Simple CacheManager 针对给定的缓存集合工作。这对于测试或简单的缓存声明很有用。

# Spring 的 Maven 依赖与缓存

如果您正在使用 Maven 作为构建工具，请确保在`pom.xml`文件中添加 ehcache 依赖项。以下是在 Spring 的缓存框架中使用缓存的 Maven 依赖项：

```java
  <groupId>net.sf.ehcache</groupId>
  <artifactId>ehcache</artifactId>
  <version>2.7.4</version>
</dependency>
```

## ehcache 的声明式配置

在下一节中，我们可以看到如何以声明方式配置缓存存储。`ecache.xml`文件如下：

```java
<ehcache 
  xsi:noNamespaceSchemaLocation="ehcache.xsd" 
  updateCheck="true" 
  monitoring="autodetect" 
  dynamicConfig="true"
  maxBytesLocalHeap="150M"
  >
  <diskStore path="java.io.tmpdir"/>

  <cache name="searchResults"
        maxBytesLocalHeap="100M"
        eternal="false"
        timeToIdleSeconds="300"
        overflowToDisk="true"
        maxElementsOnDisk="1000"      
        memoryStoreEvictionPolicy="LRU"/>      

  <cache name="Products"
        maxBytesLocalHeap="40M"
        eternal="false"
        timeToIdleSeconds="300"
        overflowToDisk="true"
        maxEntriesLocalDisk="1000"
        diskPersistent="false"
        diskExpiryThreadIntervalSeconds="120"
        memoryStoreEvictionPolicy="LRU"/>       

  <cache name="referenceData"
        maxBytesLocalHeap="5M"
        eternal="true"
        memoryStoreEvictionPolicy="LRU">
        <pinning store="localMemory"/>
  </cache>

  <cache name="newestAndRecommendedProducts"
              maxBytesLocalHeap="3M"
        eternal="true"
        memoryStoreEvictionPolicy="LRU">
        <pinning store="localMemory"/>
  </cache>

  <cache name="randomAndTopRatedProducts"
              maxBytesLocalHeap="1M"
        timeToLiveSeconds="300"
        memoryStoreEvictionPolicy="LRU">      
   </cache> 

</ehcache>
```

让我们也看看`echace.xml`中使用的以下属性的含义，以便在正确使用它们时有所帮助：

+   `maxBytesLocalHeap`：这定义了缓存可以从 VM 堆中使用多少字节。如果已定义了 CacheManager `maxBytesLocalHeap`，则此缓存的指定数量将从 CacheManager 中减去。其他缓存将共享余额。此属性的值以`<number>k|K|m|M|g|G`表示，用于千字节（k|K）、兆字节（m|M）和千兆字节（g|G）。例如，`maxBytesLocalHeap="2g"`分配了 2 千兆字节的堆内存。如果指定了`maxBytesLocalHeap`，则不能使用`maxEntriesLocalHeap`属性。如果设置了 CacheManager `maxBytesLocalHeap`，则不能使用`maxEntriesLocalHeap`。

### 注意

在最高级别设置，此属性定义了为所有定义的缓存分配的内存。之后您必须将其与各个缓存分开。

+   `eternal`：这设置了元素是否是永恒的。如果是永恒的，超时将被忽略，元素永远不会过期。

+   `timeToIdleSeconds`：这设置了元素在过期之前的空闲时间。也就是说，元素在过期之前的访问之间的最长时间。只有在元素不是永久的情况下才会使用。可选属性。值为`0`表示元素可以无限期地空闲。默认值为`0`。

+   `timeToLiveSeconds`：这设置了元素在过期之前的生存时间，即创建时间和元素过期时间之间的最长时间。只有在元素不是永久的情况下才会使用。可选属性。值为`0`表示元素可以永久存活。默认值为 0。

+   `memoryStoreEvictionPolicy`：在达到`maxEntriesLocalHeap`限制时将执行该策略。默认策略为**最近最少使用**（**LRU**）。

### 注意

如果您想从数据库中卸载一些负载，还可以使用`localTempSwap`持久性策略，在这种情况下，您可以在缓存或 CacheManager 级别使用`maxEntriesLocalDisk`或`maxBytesLocalDisk`来控制磁盘层的大小。

已配置的两个缓存，参考数据和`newestAndRecommendedPodcasts`都固定在本地内存中（`<pinning store="localMemory"/>`），这意味着数据将始终保留在缓存中。要从缓存中取消固定数据，您必须清除缓存。

# 带缓存的 Spring MVC

在本节中，让我们开发一个简单的 MVC 应用程序来演示简单的 Spring 缓存。让我们从配置开始。

要启用缓存，我们需要将以下配置添加到应用程序`context.xml`文件中：

```java
<beans  

xsi:schemaLocation="http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd
http://www.springframework.org/schema/cache http://www.springframework.org/schema/cache/spring-cache.xsd">
<cache:annotation-driven />
//your beans
</beans>
```

`<cache:annotation-driven />`将识别 spring 缓存注释`@Cacheable`和`@CacheEvict`。

让我们演示一个带有简单缓存配置的应用程序`context.xml`文件：

```java
<?xml version="1.0" encoding="UTF-8"?>
<beans 

xsi:schemaLocation="
 http://www.springframework.org/schema/beans
 http://www.springframework.org/schema/beans/spring-beans.xsd
http://www.springframework.org/schema/cache
http://www.springframework.org/schema/cache/spring-cache.xsd
http://www.springframework.org/schema/context
http://www.springframework.org/schema/context/spring-context.xsd">
<!-- Scans within the base package of the application for @Components to configure as beans -->
<context:component-scan base-package="com" />
<!-- Process cache annotations -->
<cache:annotation-driven />

<!-- Configuration for using Ehcache as the cache manager-->
<bean id="cacheManager" p:cache-manager-ref="ehcache"/>
<bean id="ehcache" p:config-location="classpath:ehcache.xml"/>
<bean id="author" class="com.packt.model.Author"/>
</beans>
```

接下来让我们演示`ehchace.xml`文件：

```java
<ehcache>
<diskStore path="java.io.tmpdir"/>
<cache name="authorCache"
maxElementsInMemory="10000"
eternal="false"
timeToIdleSeconds="120"
timeToLiveSeconds="120"
overflowToDisk="true"
maxElementsOnDisk="10000000"
diskPersistent="false"
diskExpiryThreadIntervalSeconds="120"
memoryStoreEvictionPolicy="LRU"/>
</ehcache>
```

接下来，我们将看到一个简单的 POJO 类`Author.java`：

```java
package com.packt.model;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cache.annotation.Cacheable;

public class Author {
 Logger logger = LoggerFactory.getLogger(getClass());
 @Cacheable(value="authorCache", key = "#id")
public String getAuthor(Integer id){
logger.info("get author called");
return "author"+id;
}
}
```

接下来，我们将编写一个带有注入的 Author pojo 的简单控制器：

```java
package com.packt.web;
import java.util.HashMap;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import com.packt.model.Author;
@Controller
public class WebController {

@Autowired
Author author;
@RequestMapping("/index.htm")
public String authorPage(@RequestParam(required= false) Integer id, HashMap<String, String> map){
map.put("message", author.getAuthor(id));
return "index";
}
}
```

最后，我们将编写一个`.jsp`文件：

```java
<%@ page language="java" contentType="text/html; charset=ISO-8859-1"
pageEncoding="ISO-8859-1"%>

<%@taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=ISO-8859-1">
<title>Cache Example</title>
</head>
<body>
<h1>This is ${message }</h1>
</body>
</html>
```

当我们使用`http://localhost:8080/springcachedemo/index.htm?id=1`运行应用程序时，数据被缓存，第二次访问 URL 时，您将能够观察到该值是从缓存中检索出来的。

现在在 URL 中更新 ID `id=2.访问 http://localhost:8080/springcachedemo/index.htm?id=2`，数据不是从缓存中检索出来的，但它被缓存了。

# 实现自己的缓存算法

在这一部分，让我们首先实现一个简单的缓存算法，看看它的缺点，然后展示 spring 缓存如何解决这些问题。

让我们绘制一个简单的流程图来看看缓存场景：

![实现自己的缓存算法](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr-app-dev/img/7320OS_10_01.jpg)

让我们看看如何以简单的方式实现缓存。想象一下生成一个斐波那契数。斐波那契数是通过将其前两个斐波那契数相加而生成的。因此，我们可以在 java 中计算一个简单的类，并看看我们如何在这里使用缓存。

让我们创建一个用于缓存对象的映射：

```java
import java.util.HashMap;
import java.util.Map;
public class FibonacciCache {
  private Map<Long, Long> cachemap = new HashMap<>();
  public FibonacciCache() {
    // The base case for the Fibonacci Sequence
    cachemap.put(0L, 1L);
    cachemap.put(1L, 1L);
  }
  public Long getNumber(long index) {
    // Check if value is in cache
    if (cachemap.containsKey(index)) {
     return cachemap.get(index);
    }

    // Compute value and save it in cache
    long value = getNumber(index - 1) + getNumber(index - 2);
    cachemap.put(index, value);
    return value;
  }
}
```

这种方法不是线程安全的，同样的值会被计算多次。当两个线程运行在这个类上时，它们最终会缓存相同的值。

我们可以通过实现并发哈希映射来克服这一问题。上述代码可以重写如下：

```java
import java.util.HashMap;
import java.util.Map;

public class FibonacciConncurentCache {
  private Map<Long, Long> concurrent_cachemap = new ConcurrentHashMap<>();
  public FibonacciCache() {
    // The base case for the Fibonacci Sequence
   concurrent_cachemap.put(0L, 1L);
    concurrent_cachemap.put(1L, 1L);
  }
  public Long getNumber(long index) {
    // Check if value is in cache
    if (concurrent_cachemap.containsKey(index)) {
      return concurrent_cachemap.get(index);
    }
    // Compute value and save it in concurrent_cachemap
    long value = getNumber(index - 1) + getNumber(index - 2);
    concurrent_cachemap.put(index, value);
    return value; }}
```

上述代码将使算法线程安全，防止相同值的重新计算。但这种设计不能用于其他算法。如果我们要找出下一个斐波那契数是奇数还是质数，这是不支持的。

让我们使用 Future、Callable ExecutorService 和 Concurrent HashMap 来解决这个问题。我们还将看到 Future callable 和 executor Service 的含义。

**ExecutorService**提供了创建线程池的选项。ExecutorService 是并发包中的一个接口。`ThreadPoolExecutor`和`ScheduledThreadPoolExecutor`是实现`ExecutorService`的两个类。

有几种不同的方法可以将任务委托给`ExecutorService`进行执行：

+   execute (Runnable)

+   submit (Runnable)

+   submit (Callable)

+   invokeAny (...)

+   invokeAll (...)

**Callable**是类似于 Runnable 的接口。它是一个返回结果并可能抛出异常的任务。实现者定义了一个没有参数的方法叫做`call`。

Callable 接口类似于 Runnable，两者都设计用于其实例可能由另一个线程执行的类。然而，Runnable 不返回结果，也不能抛出已检查的异常。

Executors 类包含了将其他常见形式转换为 Callable 类的实用方法。

让我们创建一个通用类；`MyCache`，这个类实例接受键和值对。它使用并发`HashMap`。

1.  让我们在条件上调用`getter`和`setter`方法；如果值已经在缓存中，那么只需获取该值，并且只有在不存在时才设置它。

```java
import java.util.concurrent.Callable;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.FutureTask;

public class MyCache<K, V> {

  private final ConcurrentMap<K, Future<V>> cache = new ConcurrentHashMap<>();

  private Future<V> createFutureIfAbsent(final K key, final Callable<V> callable) {
    Future<V> future = cache.get(key);
    if (future == null) {
      final FutureTask<V> futureTask = new FutureTask<V>(callable);
      future = cache.putIfAbsent(key, futureTask);
      if (future == null) {
        future = futureTask;
        futureTask.run();
      }
    }
    return future;
  }

  public V getValue(final K key, final Callable<V> callable) throws InterruptedException, ExecutionException {
    try {
      final Future<V> future = createFutureIfAbsent(key, callable);
      return future.get();
    } catch (final InterruptedException e) {
      cache.remove(key);
      throw e;
    } catch (final ExecutionException e) {
      cache.remove(key);
      throw e;
    } catch (final RuntimeException e) {
      cache.remove(key);
      throw e;
    }
  }
  public void setValueIfAbsent(final K key, final V value) {
    createFutureIfAbsent(key, new Callable<V>() {
      @Override
      public V call() throws Exception {
        return value;
      } }); 
}}
```

1.  接下来的步骤是在我们的斐波那契数列代码中使用缓存算法：

```java
import java.util.concurrent.Callable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class MyFibonacci {

  private static final Logger LOGGER = LoggerFactory.getLogger(MyFibonacci.class);

  public static void main(final String[] args) throws Exception {
    final long index = 12;
    final MyFibonacci myfibi = new MyFibonacci();
    final long fn = myfibi.getNumber(index);
    MyFibonacci.LOGGER.debug("The {}th Fibonacci number is: {}", index, fn);
  }

  private final MyCache<Long, Long> cache = new MyCache<>();

  public MyFibonacci() {
    cache.setValueIfAbsent(0L, 1L);
    cache.setValueIfAbsent(1L, 1L);
  }

  public long getNumber(final long index) throws Exception {
    return cache.getValue(index, new Callable<Long>() {
      @Override
      public Long call() throws Exception {
        MyFibonacci.LOGGER.debug("Computing the {} MyFibonacci number", index);
        return getNumber(index - 1) + getNumber(index - 2);
      }
    });
  }
}
```

正如您在前面的示例中所看到的，所需的修改非常少。所有缓存代码都封装在缓存算法中，我们的代码只是与之交互。缓存算法是线程安全的，由于所有状态都由缓存算法保存，我们的类本质上是线程安全的。使用这种新方法，我们可以让这个类（`MyFibonacci`）专注于其业务逻辑，即计算斐波那契数列。每个斐波那契数只计算一次。所有其他时间，这些都是从缓存中检索的。在下面的示例中，我们将看到如何在另一个上下文中使用相同的缓存算法。想象一个需要使用缓存的长时间学习任务。我们将使用`org.spring.framework.util.StopWatch`包中的 Spring Stop Watch 类。该类有两个构造函数：

+   `StopWatch()`: 这构造一个新的秒表

+   `StopWatch(String id)`: 这构造一个带有给定 ID 的新秒表

简单的秒表允许计时多个任务，公开总运行时间，并为每个命名任务提供运行时间。它隐藏了`System.currentTimeMillis()`的使用，提高了应用程序代码的可读性，并减少了计算错误的可能性。

### 注意

请注意，这个对象不是设计为线程安全的，并且不使用同步或线程。因此，可以从 EJB 中调用它是安全的。

这个类通常用于验证概念证明和开发中的性能，而不是作为生产应用程序的一部分。

让我们看看代码：

```java
import java.util.concurrent.Callable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.StopWatch;

public class LongRunningTaskExample {

  private static final Logger LOGGER = 
  public static void main(final String[] args) throws Exception {
    final LongRunningTaskExample task = new LongRunningTaskExample();

    final StopWatch stopWatch = new StopWatch(" Long Running Task");
    stopWatch.start("First Run");
    task.computeLongTask("a");
    stopWatch.stop();

    stopWatch.start("Other Runs");
    for (int i = 0; i < 100; i++) {
      task.computeLongTask("a");
    }
    stopWatch.stop();

    LongRunningTaskExample.LOGGER.debug("{}", stopWatch);
  }

  private final MyCache<String, Long> cache = new MyCache<>();

  public long computeLongTask(final String key) throws Exception {
    return cache.getValue(key, new Callable<Long>() {
      @Override
      public Long call() throws Exception {
        FictitiousLongRunningTask.LOGGER.debug("Computing  Long Running Task: {}", key);
        Thread.sleep(10000); // 10 seconds
        return System.currentTimeMillis();
      }
    });
  }
}
```

前面代码的输出：

```java
[main] DEBUG LongRunningTask.java:36 - Computing  Long Running Task: a
[main] DEBUG LongRunningTask.java:27 - StopWatch ' Long Running Task': running time (millis) = 10006; [First Run] took 10005 = 100%; [Other Runs] took 1 = 0%

```

对缓存算法没有进行任何更改，并且实现起来非常容易。前面的代码将产生类似于以下代码的结果。如前面的输出所示，一旦第一个值被计算并保存在缓存中，所有其他检索都会立即发生，而不会引入任何明显的延迟。

让我们进一步实现前面的长时间运行任务，并使用 spring 缓存缓存计算值。

我们将创建两个简单的类：`Worker`和`Main`。`Worker`类有两个方法，这些方法从`main`类中调用：

```java
Import org.springframework.context.support.ClassPathXmlApplicationContext;
public class Main {
  public static void main(final String[] args) {
    final String xmlFile = "META-INF/spring/app-context.xml";
    try (ClassPathXmlApplicationContext context = new ClassPathXmlApplicationContext(xmlFile)) {
      final Worker worker = context.getBean(Worker.class);
      worker.longTask(1);
      worker.longTask(1);
      worker.longTask(1);
      worker.longTask(2);
      worker.longTask(2);
    }
  }

import org.springframework.stereotype.Component;
@Component
public class Worker {
  public String longTask(final long id) {
    System.out.printf("Running long task for id: %d...%n", id);
    return "Long task for id " + id + " is done";
  }
  public String shortTask(final long id) {
    System.out.printf("Running short task for id: %d...%n", id);
    return "Short task for id " + id + " is done";
  }
}
```

您可以观察到 Longtask 已经传递了相同的值进行重新计算。我们可以使用`@Cacheable`注解来解决这个问题。前面的代码可以重写如下。这将防止对相同值的 Longtask 进行重新编译。

```java
import org.springframework.stereotype.Component;
@Component
public class Worker {
@Cacheable("task")
  public String longTask(final long id) {
    System.out.printf("Running long task for id: %d...%n", id);
    return "Long task for id " + id + " is done";
  }
  public String shortTask(final long id) {
    System.out.printf("Running short task for id: %d...%n", id);
    return "Short task for id " + id + " is done";
  }
}
```

# 总结

在本章中，我们看到了如何实现自己的缓存算法以及如何制作一个通用算法。我们研究了 Spring 对缓存的支持，以及 Spring 缓存框架中不同类型的缓存存储库。我们演示了如何在 Spring MVC 应用程序中使用注解来使用缓存。我们还讨论了移除缓存的场景以及何时最适合选择缓存。最后，我们还讨论了在 Spring 框架中支持缓存机制的类和接口。

在接下来的章节中，我们将研究 Spring 与 thymeleaf 框架集成和 Spring Webservices。


# 第十一章：Spring 与 Thymeleaf 集成

Thymeleaf 是一个完全用 Java 编写的模板引擎。它支持 XML/XHTML/HTML5，这意味着我们可以使用 Thymeleaf 模板引擎库使用 XML 或 XHTML 或 HTML5 开发模板。它提供了一个可选的模块，用于 Spring MVC 和 Spring Web Flow 集成。模板引擎帮助我们在 UI 中创建可重用的组件。模板通常按照约定包括标题、菜单、消息、正文、内容和页脚组件。内容部分动态加载消息。我们可以使用模板创建不同的布局。

Thymeleaf 可以用来代替 JSP。到目前为止，我们已经使用了 JSP 和自定义标签制作模板。Thymeleaf 模板是 XHTML、XML、HTML5 模板引擎。甚至网页设计师也可以很容易地与之交互。所使用的表达语言与 JSP 表达语言相比非常先进。

在本章中，我们将演示如何将 Spring MVC 与 Thymeleaf 模板集成。我们将看到如何使用可用的依赖项开始使用 Spring Thymeleaf。

# Thymeleaf 属性

让我们看一些 Thymeleaf 提供的用于设计页面的基本属性。我们还将看一下它如何与 Java 对象和循环交互。Thymeleaf 使用了许多属性。

+   显示消息：

```java
<p th:text="#{msg.greet}">Helloo Good Morning!</p>
```

+   要显示循环，我们有`th:each`：

```java
<li th:each="product : ${products}" th:text="${product.title}">XYZLLDD</li>
```

+   现在，让我们看一个表单提交操作：

```java
<form th:action="@{/buyBook}">
```

+   如果我们必须提交按钮，那么添加：

```java
<input type="button" th:value="#{form.submit}" />
```

# Spring Thymeleaf 依赖

要开始使用 Thymeleaf 模板引擎，我们需要在`pom.xml`文件中添加以下依赖项：

+   Thyemleaf 库：

+   `groupId`: `org.thymeleaf`

+   `artifactId`: `thymeleaf`

+   `version`: 2.1.4 Release

+   Spring-Thymeleaf 插件库：

+   `groupId`: `org.thymeleaf`

+   `artifactId`: `thymeleaf-spring4`

+   `version`: 2.1.4\. Release

为了测试框架（注意版本不一定与核心版本匹配），Thymeleaf 需要 Java SE 5.0 或更新版本。此外，它依赖于以下库：

+   unbescape 1.1.0 或更高版本

+   ONGL 3.0.8 或更高版本

+   Javassist 3.16.1-GA 或更高版本

+   slf4j 1.6.6 或更高版本

+   此外，如果您使用 LEGACYHTML5 模板模式，则需要 NekoHTML 1.9.21 或更高版本

## Spring MVC 和 Thymeleaf

在本节中，让我们看一下如何在 Spring MVC 框架中配置 Thymeleaf。我们也可以使用`SpringContext.xml`文件进行 Thymeleaf 配置，但由于我们已经看到了许多这样的例子，其中我们在 XML 文件中执行了配置，我们将看一下如何在 Java 文件中使用 Spring 注解添加配置。让我们创建一个简单的类`CustomPacktConfiguration`，并为该类使用`@Configuration`注解，告诉框架这个类有配置。

在配置类中，将模板模式设置为应用程序中使用的格式，即 XHTML 或 XML 模板。然后我们需要将模板配置设置为`thymeleafviewResolver`对象，还需要实际传递`templateResolver`类。

```java
@Configuration
@ComponentScan(basePackageClasses = PacktController.class)
public class CutomPacktConfiguration {
  @Bean public ViewResolver viewResolver() {
    ClassLoaderTemplateResolver templateResolver = new ClassLoaderTemplateResolver();
    templateResolver.setTemplateMode("XHTML");
    templateResolver.setPrefix("views/");
    templateResolver.setSuffix(".html");
    SpringTemplateEngine engine = new SpringTemplateEngine();
    engine.setTemplateResolver(templateResolver);
    ThymeleafViewResolver thymeleafviewResolver = new ThymeleafViewResolver();
    thymeleafviewResolver.setTemplateEngine(engine);
    return thymeleafviewResolver;
    }
  }

@Controller
public class MyPacktControllerController {
  @Autowired private PacktService packtService;
  @RequestMapping("/authors")
  public String authors(Model model) {
    model.addAttribute("authors",packtService.getAuthors));
    return "authors";
  }

}
```

## 使用 Spring Thymeleaf 的 MVC

在本节中，我们将深入探讨 Thymeleaf 在 Spring 应用程序中的集成，并开发一个简单的 MVC 应用程序，列出作者并允许用户添加、编辑和删除作者。在 Java 文件中进行配置而不是在 XML 文件中进行配置的优势是代码安全性。您的 XML 可以很容易被更改，但在 Java 文件中进行配置的情况下，我们可能需要将类文件部署到服务器上以查看更改。在本例中，让我们使用`JavaConfig`方法来配置 bean。我们可以省略 XML 配置文件。

1.  让我们首先从控制器开始，它有方法来插入和列出数据库中可用的作者。

```java
package demo.packt.thymeleaf.controller;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.servlet.ModelAndView;
import demo.packt.thymeleaf.exception.AuthorFoundException;
import demo.packt.thymeleaf.model.Author;
import demo.packt.thymeleaf.model.AuthorData;
import demo.packt.thymeleaf.service.AuthorService;

@Controller
public class AuthorController {
  private static final String HOME_VIEW = "home";
  private static final String RESULTS_FRAGMENT = "results :: resultsList";

  @Autowired
  private AuthorService authorService;

  @ModelAttribute("author")
  public Author prepareAuthorModel() {
    return new Author();
  }

  @ModelAttribute("authorData")
  public AuthorData prepareAuthorDataModel() {
    return authorService.getAuthorData();
  }

  @RequestMapping(value = "/home", method = RequestMethod.GET)
  public String showHome(Model model) {
    prepareAuthorDataModel();
    prepareAuthorModel();
    return HOME_VIEW;
  }

  @RequestMapping(value = "/authors/{surname}", method = RequestMethod.GET)
  public String showAuthorListwithSurname(Model model, @PathVariable("surname") String surname) {
    model.addAttribute("authors", authorService.getAuthorsList(surname));
    return RESULTS_FRAGMENT;
  }

  @RequestMapping(value = "/authors", method = RequestMethod.GET)
  public String showAuthorList(Model model) {
    model.addAttribute("authors", authorService.getAuthorsList());
    return RESULTS_FRAGMENT;
  }

  @RequestMapping(value = "/authors/insert", method = RequestMethod.POST)
  public String insertAuthor(Author newAuthor, Model model) {
    authorService.insertNewAuthor(newAuthor);
    return showHome(model);
  }

  @ExceptionHandler({AuthorFoundException.class})
  public ModelAndView handleDatabaseError(AuthorFoundException e) {
    ModelAndView modelAndView = new ModelAndView();
    modelAndView.setViewName("home");
    modelAndView.addObject("errorMessage", "error.user.exist");
    modelAndView.addObject("Author", prepareAuthorModel());
    modelAndView.addObject("authorData", prepareAuthorDataModel());

    return modelAndView;
  }
}
```

1.  接下来通过扩展`RuntimeException`类定义自定义`RuntimeException`：

```java
package demo.packt.thymeleaf.exception;
public class AuthorFoundException extends RuntimeException {
  private static final long serialVersionUID = -3845574518872003019L;
  public AuthorFoundException() {
    super();
  }
  public AuthorFoundException(String message) {
    super(message);
  }
}
```

1.  在这一步中，我们将从 Thymeleaf 服务开始，编写一个接口和实现类。

+   接口描述了接口中使用的方法：

```java
package demo.packt.thymeleaf.service;
import java.util.List;
import demo.packt.thymeleaf.model.Author;
import demo.packt.thymeleaf.model.AuthorData;
public interface AuthorService {
  HotelData getAuthorData();
  List<Author> getAuthorsList();
  List<Author> getAuthorList(String surname);
  void insertNewAuthor(Author newAuthor);
}
```

+   接下来我们将实现接口：

```java
package demo.packt.thymeleaf.service;
import java.util.List;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import demo.packt.thymeleaf.exception.AuthorFoundException;
import demo.packt.thymeleaf.model.Author;
import demo.packt.thymeleaf.model.AuthorData;
import demo.packt.thymeleaf.repository.AuthorRepository;

@Service("authorServiceImpl")
public class AuthorServiceImpl implements AuthorService {
  @Autowired
  AuthorRepository authorRepository;
  @Override
  public AuthorData getAuthorData() {
    AuthorData data = new AuthorData();
    data.setAddress("RRNAGAR, 225");
    data.setName("NANDA");
    return data;
  }
  @Override
  public List<Author> getAuthorsList() {
    return authorRepository.findAll();
  }
  @Override
  public List<Author> getAuthorsList(String surname) {
    return authorRepository.findAuthorsBySurname(surname);
  }

  @Override
  public void insertNewGuest(Author newAuthor) {
    if (authorRepository.exists(newAuthor.getId())) {
      throw new AuthorFoundException();
    }
    authorRepository.save(newAuthor);
  }
}
```

1.  让我们实现应用程序服务实现类中使用的存储库类：

```java
package demo.packt.thymeleaf.repository;
import java.util.List;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.mongodb.repository.Query;
import demo.packt.thymeleaf.model.Guest;
public interface AuthorRepository extends MongoRepository<Author, Long> {
  @Query("{ 'surname' : ?0 }")
  List<Author> findAuthorsBySurname(String surname);
}
```

1.  接下来在应用程序中实现 Model 类（`Author`和`AuthorData`）。

+   首先让我们实现`Author`类：

```java
package demo.packt.thymeleaf.model;
import java.io.Serializable;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;
@Document(collection = "authors")
public class Author implements Serializable {
  private static final long serialVersionUID = 1L;
  @Id
  private Long id;
  private String name;
  private String surname;
  private String country;

  /**
   * @return the name
   */
  public String getName() {
    return name;
  }
  /**
   * @param name the name to set
   */
  public void setName(String name) {
    this.name = name;
  }
  /**
   * @return the surname
   */
  public String getSurname() {
    return surname;
  }
  /**
   * @param surname the surname to set
   */
  public void setSurname(String surname) {
    this.surname = surname;
  }
  /**
   * @return the id
   */
  public Long getId() {
    return id;
  }
  /**
   * @param id the id to set
   */
  public void setId(Long id) {
    this.id = id;
  }
  /**
   * @return the country
   */
  public String getCountry() {
    return country;
  }
  /**
   * @param country the country to set
   */
  public void setCountry(String country) {
    this.country = country;
  }
}
```

+   接下来，让我们实现`AuthorData`类：

```java
package demo.packt.thymeleaf.model;
import java.io.Serializable;
public class AuthorData implements Serializable {
  private static final long serialVersionUID = 1L;
  private String name;
  private String address;
  public String getName() {
    return name;
  }
  public void setName(String name) {
    this.name = name;
  }
  public String getAddress() {
    return address;
  }
  public void setAddress(String address) {
    this.address = address;
  }
}
```

1.  在这一步中，我们将创建配置类；如前所述，我们不使用 XML 进行配置。我们有两个配置文件——一个用于数据库配置的 MongoDB，另一个是组件扫描配置文件：

```java
import org.springframework.context.annotation.Configuration;
import org.springframework.data.mongodb.config.AbstractMongoConfiguration;
import org.springframework.data.mongodb.repository.config.EnableMongoRepositories;
import com.mongodb.Mongo;
@Configuration
@EnableMongoRepositories(«demo.packt.thymeleaf.repository»)
public class MongoDBConfiguration extends AbstractMongoConfiguration {
  @Override
  protected String getDatabaseName() {
    return "author-db";
  }
  @Override
  public Mongo mongo() throws Exception {
    return new Mongo();
  }
}
```

这个类是一个重要的类，标志着应用程序实例化的开始。在这里，我们还配置了 Thymeleaf 模板视图解析器并提供了组件扫描信息。模板和视图解析器也在这个类中进行了配置：

```java
package demo.packt.thymeleaf.configuration;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Description;
import org.springframework.context.annotation.Import;
import org.springframework.context.support.ResourceBundleMessageSource;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;
import org.thymeleaf.spring3.SpringTemplateEngine;
import org.thymeleaf.spring3.view.ThymeleafViewResolver;
import org.thymeleaf.templateresolver.ServletContextTemplateResolver;

@EnableWebMvc
@Configuration
@ComponentScan("demo.packt.thymeleaf")
@Import(MongoDBConfiguration.class)
public class WebAppConfiguration extends WebMvcConfigurerAdapter {

  @Bean
  @Description("Thymeleaf template resolver serving HTML 5")
  public ServletContextTemplateResolver templateResolver() {
    ServletContextTemplateResolver templateResolver = new ServletContextTemplateResolver();
    templateResolver.setPrefix("/WEB-INF/html/");
    templateResolver.setSuffix(".html");
    templateResolver.setTemplateMode("HTML5");

    return templateResolver;
  }

  @Bean
  @Description("Thymeleaf template engine with Spring integration")
  public SpringTemplateEngine templateEngine() {
    SpringTemplateEngine templateEngine = new SpringTemplateEngine();
    templateEngine.setTemplateResolver(templateResolver());

    return templateEngine;
  }

  @Bean
  @Description("Thymeleaf view resolver")
  public ThymeleafViewResolver viewResolver() {
    ThymeleafViewResolver viewResolver = new ThymeleafViewResolver();
    viewResolver.setTemplateEngine(templateEngine());

    return viewResolver;
  }

  @Bean
  @Description("Spring message resolver")
  public ResourceBundleMessageSource messageSource() {
    ResourceBundleMessageSource messageSource = new ResourceBundleMessageSource();  
    messageSource.setBasename("i18n/messages");

    return messageSource;  
  }

  @Override
  public void addResourceHandlers(ResourceHandlerRegistry registry) {
    registry.addResourceHandler("/resources/**").addResourceLocations("/WEB-INF/resources/");
  }
}
```

1.  下一步是在`WEB-INF`文件夹下创建 HTML 文件，创建一个`home.html`文件如下：

```java
<!DOCTYPE html>
<html 
       lang="en">

<head>
<meta charset="UTF-8"/>
<title>Thymeleaf example</title>
<link rel="stylesheet" th:href="@{/spring/resources/css/styles.css}" type="text/css" media="screen"/>
<script th:src="img/functions.js}" type="text/javascript"></script>
<script th:src="img/jquery-min-1.9.1.js}" type="text/javascript"></script>
</head>

<body>
<div style="width:800px; margin:0 auto;">

<h1 th:text="#{home.title}">Thymeleaf example</h1>

<div class="generic-info">
  <h3 th:text="#{author.information}">Author Information</h3>

  <span th:text="${authorData.name}">Author name</span><br />
  <span th:text="${authorData.address}">Author address</span><br />
</div>

<div class="main-block">
  <!-- Insert new Author -->
  <span class="subtitle">Add Author form</span>
  <form id="guestForm" th:action="@{/spring/authors/insert}" th:object="${Author}" method="post">
    <div class="insertBlock">
    <span class="formSpan">
    <input id="authorId" type="text" th:field="*{id}" required="required"/>
    <br />
    <label for="authorId" th:text="#{insert.id}">id:</label>
    </span>
    <span class="formSpan" style="margin-bottom:20px">
    <input id="authorName" type="text" th:field="*{name}" required="required"/>
      <br />
      <label for="authorName" th:text="#{insert.name}">name:</label>
    </span>

    <span class="formSpan">
    <input id="authorSurname" type="text" th:field="*{surname}" required="required"/>
    <br />
    <label for="authorSurname" th:text="#{insert.surname}">surname:</label>
    </span>
    <span class="formSpan" style="margin-bottom:20px">
    <input id="authorCountry" type="text" th:field="*{country}" required="required"/>
    <br />
    <label for="authorCountry" th:text="#{insert.country}">country:</label>
    </span>

    <input type="submit" value="add" th:value="#{insert.submit}"/>
    <span class="messageContainer" th:unless="${#strings.isEmpty(errorMessage)}" th:text="#{${errorMessage}}"></span>
    </div>
  </form>
  <!-- Guests list -->
  <form>
    <span class="subtitle">Author list form</span>
    <div class="listBlock">
    <div class="search-block">
    <input type="text" id="searchSurname" name="searchSurname"/>
    <br />
    <label for="searchSurname" th:text="#{search.label}">Search label:</label>

    <button id="searchButton" name="searchButton" onclick="retrieveAuthors()" type="button" th:text="#{search.button}">Search button</button>
    </div>

    <!-- Results block -->
    <div id="resultsBlock">

    </div>
    </div>

  </form>
</div>

</div>
</body>
</html>
```

1.  最后，创建一个简单的`results.html`文件：

```java
<!DOCTYPE html>
<html 
   lang="en">
<head>
</head>
<body>
  <div th:fragment="resultsList" th:unless="${#lists.isEmpty(authors)}" class="results-block">
  <table>
  <thead>
  <tr>
  <th th:text="#{results.author.id}">Id</th>
  <th th:text="#{results.author.surname}">Surname</th>
  <th th:text="#{results.author.name}">Name</th>
  <th th:text="#{results.author.country}">Country</th>
  </tr>
  </thead>
  <tbody>
  <tr th:each="author : ${authors}">
  <td th:text="${author.id}">id</td>
  <td th:text="${author.surname}">surname</td>
  <td th:text="${author.name}">name</td>
  <td th:text="${author.country}">country</td>
  </tr>
  </tbody>
  </table>
  </div>
</body>
</html>
```

这将为用户提供一个作者列表和一个用于将作者信息插入 MongoDB 数据库的表单，使用 Thymeleaf 模板。

# Spring Boot 与 Thymeleaf 和 Maven

在本节中，我们将看到如何使用 Spring boot 创建一个带有 Thymeleaf 应用程序的 Spring。

这个操作的前提是 Maven 必须安装。要检查 Maven 是否已安装，请在命令提示符中键入以下命令：

```java
mvn –version

```

1.  使用原型来生成一个带有`thymeleaf`项目的 Spring boot：

```java
mvn archetype:generate -DarchetypeArtifactId=maven-archetype-quickstart -DgroupId=com.packt.demo -DartifactId=spring-boot-thymeleaf -interactiveMode=false

```

上述命令将创建一个`spring-boot-thymeleaf`目录。这可以导入到 Eclipse IDE 中。

1.  您将打开`pom.xml`文件并添加一个`parent`项目：

```java
<parent>
  <groupId>org.springframework.boot</groupId>
  <artifactId>spring-boot-starter-parent</artifactId>
  <version>1.1.8.RELEASE</version>
</parent>
```

1.  开始向`pom.xml`文件添加一个依赖项：

```java
<dependencies>
  <dependency>
  <groupId>org.springframework.boot</groupId>
  <artifactId>spring-boot-starter-web</artifactId>
  </dependency>
  <dependency>
  <groupId>org.springframework.boot</groupId>
  <artifactId>spring-boot-starter-thymeleaf</artifactId>
  </dependency>
</dependencies>
```

1.  最后添加 Spring boot 插件：

```java
<build>
  <plugins>
  <plugin>
  <groupId>org.springframework.boot</groupId>
  <artifactId>spring-boot-maven-plugin</artifactId>
  </plugin>
  </plugins>
</build>
```

让我们开始修改 web。但等一下，这不是 web 应用程序！

1.  因此，让我们修改`App`类，使其成为 Spring Boot 应用程序的入口点：

```java
package com.packt.demo
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

@EnableAutoConfiguration
@Configuration
@ComponentScan
public class App {
  public static void main(String[] args) {
    SpringApplication.run(App.class);
  }
}
```

1.  接下来，让我们配置 Thymeleaf 模板。为了配置它，我们需要在`src/main/resources/templates`目录下添加模板：

```java
<!DOCTYPE html>
<html>
<head>
  <title>Hello Spring Boot!</title>
  <meta http-equiv="Content-Type" content="text/html; charset=UTF-8"/>
</head>
<body>
<p>Hello Spring Boot!</p>
</body>
<html>
```

1.  您可以通过添加 CSS 和 JavaScript 引用来升级 Thymeleaf 模板，如下所示：

```java
<!DOCTYPE html>
<html>
<head>
  <title>Hello Spring Boot!</title>
  <meta http-equiv="Content-Type" content="text/html; charset=UTF-8"/>
  <link href="../static/css/core.css"
    th:href="@{/css/core.css}"
    rel="stylesheet" media="screen" />
</head>
<body>
<p>Hello Spring Boot!</p>
</body>
</html>
```

1.  Spring boot 支持开箱即用的 WebJars。将以下依赖项添加到`pom.xml`文件中。

```java
<dependency>
  <groupId>org.webjars</groupId>
  <artifactId>bootstrap</artifactId>
  <version>3.2.0</version>
</dependency>
<dependency>
  <groupId>org.webjars</groupId>
  <artifactId>jquery</artifactId>
  <version>2.1.1</version>
</dependency>
```

并在模板中引用库，如下所示：

```java
<link href="http://cdn.jsdelivr.net/webjars/bootstrap/3.2.0/css/bootstrap.min.css"
  th:href="@{/webjars/bootstrap/3.2.0/css/bootstrap.min.css}"
  rel="stylesheet" media="screen" />

<script src="img/jquery.min.js"
  th:src="img/jquery.min.js}"></script>
```

如您所见，对于静态原型设计，库是从 CDN 下载的，将打包从 JAR 转换为 WAR

使用 Spring boot 作为普通 web 应用程序运行这个项目非常容易。首先，我们需要将`pom.xml`中的打包类型从 JAR 改为 WAR（打包元素）。其次，确保 Tomcat 是一个提供的依赖项：

```java
<packaging>war</packaging>
```

我们还需要创建一个控制器来处理应用程序请求：

```java
package com.packt.demo;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
class HomeController {

  @RequestMapping("/")
  String index() {
    return "index";
  }
}
```

最后一步是引导一个 servlet 配置。创建一个`Init`类并继承自`SpringBootServletInitializer`：

```java
package packt.demo;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.context.web.SpringBootServletInitializer;

public class ServletInitializer extends SpringBootServletInitializer {
    @Override
    protected SpringApplicationBuilder configure(SpringApplicationBuilder application) {
    return application.sources(App.class);
  }
}
```

我们可以使用`mvn clean package`命令检查配置是否与 Maven 一起工作。WAR 文件将被创建：

```java
Building war: C:\Projects\demos\spring-boot-thymeleaf\target\spring-boot-thymeleaf-1.0-SNAPSHOT.war

```

使用 Maven 直接从 WAR 文件启动应用程序，使用以下命令：

```java
java-jar target\spring-boot-thymeleaf-1.0-SNAPSHOT.war

```

创建 WAR 项目后，我们将在 Eclipse 中运行应用程序。在我们改变了打包方式后，Eclipse 将检测项目中的更改并向其添加 web facet。下一步是配置 Tomcat 服务器并运行它。导航到**Edit Configurations**，并添加带有解压的 WAR 构件的 Tomcat 服务器。现在你可以像运行其他 web 应用程序一样运行应用程序。

## 重新加载 Thymeleaf 模板

由于应用程序在 Eclipse 中运行在本地 Tomcat 服务器上，我们将重新加载静态资源（例如 CSS 文件）而无需重新启动服务器。但是，默认情况下，Thymeleaf 会缓存模板，因此为了更新 Thymeleaf 模板，我们需要改变这种行为。

+   将`application.properties`添加到`src/main/resources`目录中，其中包含`spring.thymeleaf.cache=false`属性

+   重新启动服务器，从现在开始您可以重新加载 Thymeleaf 模板而无需重新启动服务器

+   更改其他配置默认值

缓存配置并不是我们可以调整的唯一可用配置。请查看`ThymeleafAutoConfiguration`类，了解您可以更改的其他内容。举几个例子：`spring.thymeleaf.mode`，`spring.thymeleaf.encoding`。

## 使用 Thymeleaf 的 Spring 安全

由于我们使用了 Spring 安全，我们将在我们的 Spring 应用程序中使用 JSP 中的自定义登录表单。在本节中，让我们看看如何引入 Thymeleaf 模板来保护基于 Spring 的应用程序。

您可以像这样使用 Spring 安全方言来显示已登录用户的信息。属性`sec:authorize`在属性表达式评估为`True`时呈现其内容。您可以在成功认证后显示的基本文件中使用此代码：

```java
?
<div sec:authorize="hasRole('ROLE_ADMIN')">
  This content is only shown to administrators.
</div>
<div sec:authorize="hasRole('ROLE_USER')">
  This content is only shown to users.
</div>
  The attribute sec:authentication is used to print logged user name and roles:
?
  Logged user: <span sec:authentication="name">Bob</span>
  Roles: <span sec:authentication="principal.authorities">[ROLE_USER, ROLE_ADMIN]</span>
```

正如我们所知，以下是我们在 Spring 应用程序中添加 Spring 安全所执行的一些必要步骤。但是，您会注意到我们已经配置了一个 Thymeleaf 文件的 HTML 文件。

1.  配置 Spring 安全过滤器。

1.  将`applicationContext-springsecurity.xml`文件配置为上下文参数。

1.  在`applicationContext-springsecurity.xml`中配置需要保护的 URL。

1.  示例配置如下：

```java
<?
<http auto-config="true">
  <form-login login-page="/login.html" authentication-failure-url="/login-error.html" />
  <logout />
  ...
</http>
```

1.  配置 Spring 控制器：

```java
@Controller
public class MySpringController {

  ...

  // Login form
  @RequestMapping("/login.html")
  public String login() {
    return "login.html";
  }

  // Login form with error
  @RequestMapping("/login-error.html")
  public String loginError(Model model) {
    model.addAttribute("loginError", true);
    return "login.html";
  }
}
```

1.  让我们看一下`Login.html`文件，这是 Thymeleaf 文件。这可以通过文件开头给出的 XMLNS 来识别。还要注意，我们正在处理 JSP 文件中的错误；当登录失败时，它会显示错误消息。我们还将创建一个`error.html`文件来处理错误：

```java
<!DOCTYPE html>
<html  >
  <head>
  <title>Login page</title>
  </head>
  <body>
  <h1>Login page</h1>
  <p th:if="${loginError}">Wrong user or password</p>
  <form th:action="@{/j_spring_security_check}" method="post">
  <label for="j_username">Username</label>:
  <input type="text" id="j_username" name="j_username" /> <br />
  <label for="j_password">Password</label>:
  <input type="password" id="j_password" name="j_password" /> <br />
  <input type="submit" value="Log in" />
  </form>
  </body>
</html>

/*Error.html file*/
?
<!DOCTYPE html>
<html  >
  <head>
  <title>Error page</title>
  </head>
  <body>
  <h1 th:text="${errorCode}">500</h1>
  <p th:text="${errorMessage}">java.lang.NullPointerException</p>
  </body>
</html>
```

这一步是关于配置错误页面。错误页面可以在`web.xml`文件中配置。首先，我们需要向`web.xml`文件添加`<error-page>`标签。一旦配置了错误页面，我们需要通知控制器类有关错误页面的信息：

```java
<error-page>
  <exception-type>java.lang.Throwable</exception-type>
  <location>/error.html</location>
</error-page>
<error-page>
  <error-code>500</error-code>
  <location>/error.html</location>
</error-page>
```

1.  在控制器中为`error`页面添加请求映射：

```java
@RequestMapping("/error.html")
public String error(HttpServletRequest request, Model model) {
  model.addAttribute("errorCode", request.getAttribute("javax.servlet.error.status_code"));
  Throwable throwable = (Throwable) request.getAttribute("javax.servlet.error.exception");
  String errorMessage = null;
  if (throwable != null) {
    errorMessage = throwable.getMessage();
  }
  model.addAttribute("errorMessage", errorMessage);
  return "error.html";
  }
}
```

访问[`www.thymeleaf.org/doc/tutorials/2.1/usingthymeleaf.html`](http://www.thymeleaf.org/doc/tutorials/2.1/usingthymeleaf.html)了解更多详情。

# 摘要

在本章中，我们已经看到了如何将 Thymeleaf 模板引擎集成到 Spring MVC 应用程序中，以及如何使用 Spring boot 启动 Spring 与 Thymeleaf 应用程序。我们还演示了如何使用 Spring Thymeleaf 模板为 Spring 安全创建自定义表单。

在下一章中，我们将看到 Spring 与 Web 服务集成，并了解它为开发 SOAP 和 REST Web 服务提供了什么。


# 第十二章：Spring 与 Web 服务集成

在本章中，我们将看到 Spring 如何支持`JAX_WS`网络服务，以及如何在**Spring Web Service** (**Spring-WS**)框架中创建网络服务。我们还将看到 Spring Web Service 如何被消费，演示一个客户端应用程序，以及 Spring 支持的 Web 服务的注解。

# Spring 与 JAX-WS

在本节中，让我们创建一个简单的 JAX-WS 网络服务。我们还将看到如何将 JAX-WS 网络服务与 Spring 集成。JAX-WS 是 JAX-RPC 的最新版本，它使用远程方法调用协议来访问 Web 服务。

我们在这里需要做的就是将 Spring 的服务层公开为`JAX_WS`服务提供程序层。这可以使用`@webservice`注解来完成，只需要几个步骤。让我们记下其中涉及的步骤。

1.  在 Eclipse 中创建一个`PACKTJAXWS-Spring`简单的 Maven web 项目或动态 web 项目。

1.  现在，我们需要在`web.xml`文件中配置 JAX-WS servlet：

```java
<?xml version="1.0" encoding="UTF-8"?>
<web-app   xsi:schemaLocation="http://java.sun.com/xml/ns/javaee http://java.sun.com/xml/ns/javaee/web-app_3_0.xsd" id="WebApp_ID" version="3.0">
<display-name>JAXWS-Spring</display-name>
<servlet>
  <servlet-name>jaxws-servlet</servlet-name>
  <servlet-class>
    com.sun.xml.ws.transport.http.servlet.WSSpringServlet
  </servlet-class>
</servlet>
<servlet-mapping>
  <servlet-name>jaxws-servlet</servlet-name>
  <url-pattern>/jaxws-spring</url-pattern>
</servlet-mapping>

<!-- Register Spring Listener -->
<listener>
  <listener-class>org.springframework.web.context.ContextLoaderListener</listener-class> 
</listener> 
</web-app>
```

1.  创建一个`Context.xml`应用文件，并在其中添加网络服务信息。我们将在这里提供网络服务名称和服务提供者类信息。

```java
<?xml version="1.0" encoding="UTF-8"?>
<beans  

       xsi:schemaLocation="http://www.springframework.org/schema/beans
       http://www.springframework.org/schema/beans/spring-beans-3.0.xsd
       http://jax-ws.dev.java.net/spring/core
       http://jax-ws.java.net/spring/core.xsd
       http://jax-ws.dev.java.net/spring/servlet
       http://jax-ws.java.net/spring/servlet.xsd">
  <wss:binding url="/jaxws-spring">
  <wss:service>
  <ws:service bean="#packWs"/>
  </wss:service>
  </wss:binding>
  <!-- Web service bean -->
  <bean id="packtWs" class="com.packt.webservicedemo.ws.PacktWebService">
  <property name="myPACKTBObject" ref="MyPACKTBObject" />
  </bean>
  <bean id="MyPACKTBObject" class="com.packt.webservicedemo.bo.impl.MyPACKTBObjectImpl" />
</beans>
```

1.  接下来，我们需要使所有的 jar 文件在类路径中可用。由于这是一个 Maven 项目，我们只需要更新`pom.xml`文件。

```java
<project   xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.javacodegeeks.enterprise.ws</groupId>
  <artifactId>PACKTJAXWS-Spring</artifactId>
  <version>0.0.1-SNAPSHOT</version>
  <dependencies>
    <dependency>
      <groupId>org.springframework</groupId>
        <artifactId>spring-core</artifactId>
        <version>${spring.version}</version>
    </dependency>
    <dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-context</artifactId>
      <version>${spring.version}</version>
    </dependency>
    <dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-web</artifactId>
      <version>${spring.version}</version>
    </dependency>

    <dependency>
      <groupId>org.jvnet.jax-ws-commons.spring</groupId>
      <artifactId>jaxws-spring</artifactId>
      <version>1.9</version>
    </dependency>
  </dependencies>
  <properties>
    <spring.version>3.2.3.RELEASE</spring.version>
  </properties>
</project>
```

1.  我们现在将创建一个带有`@WebService`注解的网络服务类。我们还定义了可能需要的绑定类型，比如`SOAPBinding`和`Style`。`@Webmethod`注解指定了提供服务的方法。

```java
package com.packt.webservicedemo.ws;
import javax.jws.WebMethod;
import javax.jws.WebService;
import javax.jws.soap.SOAPBinding;
import javax.jws.soap.SOAPBinding.Style;
import javax.jws.soap.SOAPBinding.Use;
import com.packt.webservicedemo.bo.*;

@WebService(serviceName="PacktWebService")
@SOAPBinding(style = Style.RPC, use = Use.LITERAL)
public class PacktWebService{
  //Dependency Injection (DI) via Spring
  MyPACKTBObject myPACKTBObject;
  @WebMethod(exclude=true)
  public void setMyPACKTBObject(MyPACKTBObject myPACKTBObject) {
    this.myPACKTBObject = myPACKTBObject;
  }
  @WebMethod(operationName="printMessage")
  public String printMessage() {
    return myPACKTBObject.printMessage();

  }
}
package com.packt.webservicedemo.bo;
public interface MyPACKTBObject {
  String printMessage();
}
public class MyPACKTBObjectImpl implements MyPACKTBObject {
  @Override
  public String printMessage() {
    return "PACKT SPRING WEBSERVICE JAX_WS";
  }
}
```

1.  我们应该将 Maven JAR 文件添加到 Eclipse 项目的构建路径中。

1.  运行应用程序：`http://localhost:8080/PACKTJAXWS-Spring/jaxws-spring`。

您应该能够看到 WSDL URL，并在单击链接时，WSDL 文件应该打开。

# 使用 JAXB 编组的 Spring Web 服务请求

在本节中，让我们看看如何使用 Spring Web Service 框架开发一个简单的网络服务。我们需要 JAXB 来对 XML 请求进行编组和解组。Spring Web Service 支持契约优先的网络服务。我们需要首先设计 XSD/WSDL，然后启动网络服务。

我们正在创建一个作者网络服务，它将给我们提供作者列表。

1.  **配置 web.xml 文件**：让我们首先在`web.xml`文件中进行网络服务配置。我们需要配置 Spring Web Service servlet。需要定义消息分发 servlet 和它将处理的 URL 模式。指定`contextConfigLocation`而不是允许默认值(`/WEB-INF/spring-ws-servlet.xml`)，因为这个位置使得配置更容易与单元测试共享。

```java
<?xml version="1.0" encoding="UTF-8"?>
<web-app  

  xsi:schemaLocation="http://java.sun.com/xml/ns/javaee 
  http://java.sun.com/xml/ns/javaee/web-app_2_5.xsd" 
  id="WebApp_ID" version="2.5">

  <servlet>
    <servlet-name>spring-ws</servlet-name>
    <servlet-class>org.springframework.ws.transport.http.MessageDispatcherServlet</servlet-class>
    <init-param>
      <param-name>contextConfigLocation</param-name>
      <param-value>classpath:/spring-ws-context.xml</param-value>
    </init-param>
  </servlet>

  <servlet-mapping>
    <servlet-name>spring-ws</servlet-name>
    <url-pattern>/*</url-pattern>
  </servlet-mapping>

</web-app>
```

1.  **配置 Spring 上下文文件**(`/src/main/resources/spring-ws-context.xml`)：`EndPoint`类需要在`spring-ws-context.xml`中进行配置。该类带有`@EndPointAnnotation`注解。`AuthorEndpoint`被定义为一个 bean，并且将自动注册到 Spring Web Services 中，因为该类被`@Endpoint`注解标识为端点。此配置使用了`author.xsd`，这是一个用于生成 JAXB bean 以生成 WSDL 的 xml 模式描述符文件。位置 URI 与`web.xml`中指定的 URL 模式匹配。

使用 Spring OXM 配置 JAXB 编组器/解组器，并设置在`MarshallingMethodEndpointAdapter` bean 上。

```java
<?xml version="1.0" encoding="UTF-8"?>
<beans 

       xsi:schemaLocation="http://www.springframework.org/schema/beans 
       http://www.springframework.org/schema/beans/spring-beans.xsd
       http://www.springframework.org/schema/context
       http://www.springframework.org/schema/context/spring-context.xsd">

  <context:component-scan base-package="org. packtws.ws.service" />

  <bean id="person" class="org.springframework.ws.wsdl.wsdl11.DefaultWsdl11Definition"
    p:portTypeName="Author"
    p:locationUri="/authorService/"
    p:requestSuffix="-request"
    p:responseSuffix="-response">
    <property name="schema">
      <bean class="org.springframework.xml.xsd.SimpleXsdSchema"
        p:xsd="classpath:/author.xsd" />
      </bean>
    </property>
  </bean>

  <bean class="org.springframework.ws.server.endpoint.mapping.PayloadRootAnnotationMethodEndpointMapping">
    <description>An endpoint mapping strategy that looks for @Endpoint and @PayloadRoot annotations.</description>
  </bean>

  <bean class="org.springframework.ws.server.endpoint.adapter.MarshallingMethodEndpointAdapter">
    <description>Enables the MessageDispatchServlet to invoke methods requiring OXM marshalling.</description>
    <constructor-arg ref="marshaller"/>
  </bean>

  <bean id="marshaller" class="org.springframework.oxm.jaxb.Jaxb2Marshaller"
    p:contextPath="org.packtws.author.schema.beans" />

</beans>
```

1.  **定义 XSD Author.xsd**：一个非常简单的 XSD 定义了一个元素，用于指示获取所有作者的传入请求（name 元素未使用），以及包含作者元素列表的作者响应元素。

**author.xsd**

```java
<xsd:schema 
  targetNamespace=" http://www.packtws.org/author/schema/beans "
  >

  <xsd:element name="get-authors-request">
  <xsd:complexType>
    <xsd:sequence>
      <xsd:element name="name" type="xsd:string" />
    </xsd:sequence>
  </xsd:complexType>
  </xsd:element>

  <xsd:element name="author-response">
    <xsd:complexType>
      <xsd:sequence>
        <xsd:element name="author" type="author"
          minOccurs="0" maxOccurs="unbounded"/>
      </xsd:sequence>
    </xsd:complexType>
  </xsd:element>

  <xsd:complexType name="author">
  <xsd:sequence>
    <xsd:element name="id" type="xsd:int" />
    <xsd:element name="first-name" type="xsd:string" />
    <xsd:element name="last-name" type="xsd:string" />
  </xsd:sequence>
  </xsd:complexType>

</xsd:schema>
```

1.  **编组 AuthorService**：让我们创建一个接口`MarshallingAuthorService`，用于使用以下 JAXB 生成的 bean 获取作者：

+   对于`get-authors-request`元素：`GetAuthorsRequst`

+   对于`author-response`元素：`AuthorResponse`

它还具有与命名空间（与 XSD 匹配）和请求常量相匹配的常量：

```java
public interface MarshallingAuthorService {
  public final static String NAMESPACE = " http://www.packtws.org/author/schema/beans ";
  public final static String GET_Authors_REQUEST = "get-authors-request";
  public AuthorResponse getAuthors(GetAuthorsRequest request);
}
```

1.  **创建端点类**：让我们创建一个标有`@Endpoint`注解的端点类。这个类将实现`MarshallingAuthorService`的方法。`getAuthors`方法被指示处理特定的命名空间和传入的请求元素。端点只是准备一个静态响应，但这很容易可以注入一个 DAO，并从数据库中检索信息，然后映射到 JAXB beans 中。AuthorResponse 是使用 JAXB Fluent API 创建的，比标准的 JAXB API 更简洁。

```java
@Endpoint
public class AuthorEndpoint implements MarshallingAuthorService {
  /**
  * Gets Author list.
  */
  @PayloadRoot(localPart=GET_AuthorS_REQUEST, namespace=NAMESPACE)
  public AuthorResponse getAuthors(GetPersonsRequest request) {
    return new AuthorResponse().withAuthor(
    new Author().withId(1).withFirstName("Anjana").withLastName("Raghavendra"),
    new Author().withId(2).withFirstName("Amrutha").withLastName("Prasad"));
  }

}
```

1.  **添加依赖信息**：还要确保在 maven 的`pom.xml`文件中添加以下依赖项：

```java
<dependency>
  <groupId>org.springframework.ws</groupId>
  <artifactId>org.springframework.ws</artifactId> 
  <version>${spring.ws.version}</version>
</dependency>
<dependency>
  <groupId>org.springframework.ws</groupId>
  <artifactId>org.springframework.ws.java5</artifactId> 
  <version>${spring.ws.version}</version>
</dependency>

<dependency>
  <groupId>javax.xml.bind</groupId>
  <artifactId>com.springsource.javax.xml.bind</artifactId>
  <version>2.1.7</version>
</dependency>
<dependency>
  <groupId>com.sun.xml</groupId>
  <artifactId>com.springsource.com.sun.xml.bind.jaxb1</artifactId>
  <version>2.1.7</version>
</dependency>
<dependency>
  <groupId>javax.wsdl</groupId>
  <artifactId>com.springsource.javax.wsdl</artifactId>
  <version>1.6.1</version>
</dependency>
<dependency>
  <groupId>javax.xml.soap</groupId>
  <artifactId>com.springsource.javax.xml.soap</artifactId>
  <version>1.3.0</version>
</dependency>
<dependency>
  <groupId>com.sun.xml</groupId>
  <artifactId>com.springsource.com.sun.xml.messaging.saaj</artifactId>
  <version>1.3.0</version>
</dependency>
<dependency>
  <groupId>javax.activation</groupId>
  <artifactId>com.springsource.javax.activation</artifactId>
  <version>1.1.1</version>
</dependency>
<dependency>
  <groupId>javax.xml.stream</groupId>
  <artifactId>com.springsource.javax.xml.stream</artifactId>
  <version>1.0.1</version>
</dependency>
```

1.  **构建和部署应用程序**：我们需要在 tomcat 上进行这个操作以查看 WSDL URL。因此，我们已经完成了提供 web 服务的所有步骤。

# 使用 JAXB unmarshalling 为 Spring Web Services 编写客户端应用程序

让我们为作者服务编写一个简单的客户端应用程序。`org.springbyexample.ws.service`包被扫描以查找`AuthorServiceClient`，并将 web 服务模板注入其中。JAXB marshaller/umarshaller 被定义并设置在这个模板上。

`jetty-context.xml`的导入对于创建客户端并不重要，但它创建了一个嵌入式的 Jetty 实例，加载了`spring-ws-context.xml`和它的服务。单元测试中的客户端能够独立运行。

**AuthorServiceClientTest.xml**：

```java
<?xml version="1.0" encoding="UTF-8"?>
<beans 

  xsi:schemaLocation="http://www.springframework.org/schema/beans 
  http://www.springframework.org/schema/beans/spring-beans.xsd
  http://www.springframework.org/schema/context 
  http://www.springframework.org/schema/context/spring-context.xsd">

  <import resource="jetty-context.xml"/>

  <context:component-scan base-package="org.springbyexample.ws.client" />

  <context:property-placeholder location="org/springbyexample/ws/client/ws.properties"/>

  <bean id="authorWsTemplate" class="org.springframework.ws.client.core.WebServiceTemplate"
  p:defaultUri="http://${ws.host}:${ws.port}/${ws.context.path}/authorService/"
  p:marshaller-ref="marshaller"
  p:unmarshaller-ref="marshaller" />

  <bean id="marshaller" class="org.springframework.oxm.jaxb.Jaxb2Marshaller"
  p:contextPath="org.springbyexample.author.schema.beans" />

</beans>
```

**AuthorServiceClient**：

在这一点上，Spring Web Services 几乎可以处理所有事情。只需要调用模板，它将从服务端点返回`AuthorResponse`。客户端可以像这样使用：`AuthorResponse response = client.getAuthors(new GetAuthorsRequest());`

```java
public class AuthorServiceClient implements MarshallingAuthorService {

  @Autowired
  private WebServiceTemplate wsTemplate;

  /**
    * Gets author list.
  */
  public AuthorResponse getAuthors(GetAuthorsRequest request) {
    PersonResponse response = (PersonResponse) wsTemplate.marshalSendAndReceive(request);

    return response;

  }
}
```

# 总结

在本章中，我们看到了如何将`JAX_WS`与 Spring Web Service 集成。我们还演示了如何创建 Spring Web Services 和端点类，以及如何通过访问 WSDL URL 来访问 web 服务。
