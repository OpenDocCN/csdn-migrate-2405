# 精通 Java 11（四）

> 原文：[Mastering Java 11](https://libgen.rs/book/index.php?md5=550A7DE63D6FA28E9423A226A5BBE759)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 十二、并发性增强

在上一章中，我们讨论了现代 Java 平台的几个增强。这些增强代表了一系列工具和 API 的更新，以使使用 Java 开发更容易，并为我们的 Java 应用提供了更大的优化可能性。我们研究了新的 HTTP 客户端、对 Javadoc 和 Doclet API 的更改、新的 JavaScript 解析器、JAR 和 JRE 更改、新的 Java 级 JVM 编译器接口、对 TIFF 图像的新支持、平台日志记录、XML 目录支持、集合以及新的特定于平台的桌面功能。我们还研究了对方法处理和弃用注解的增强。

在本章中，我们将介绍 Java 平台的并发增强。我们主要关注的是对反应式编程的支持，这是一种由`Flow `类 API 提供的并发增强。反应式编程最初是在 Java9 中发布的，它仍然是 Java10 和 Java11 的一个重要特性。我们还将探讨额外的并发增强。

更具体地说，我们将讨论以下主题：

*   反应式程序设计
*   `Flow`API
*   其他并发更新
*   旋转等待提示

# 技术要求

本章以及随后的几章介绍 Java11。Java 平台的 SE 可从 [Oracle 官方网站](http://www.oracle.com/technetwork/java/javase/downloads/index.html)下载。

集成开发环境（IDE）包就足够了。来自 JetBrains 的 IntelliJ IDEA 用于与本章和后续章节相关的所有编码。IntelliJ IDEA 的社区版可从[网站](https://www.jetbrains.com/idea/features/)下载。

# 反应式程序设计

反应式编程是指应用在异步数据流发生时对其作出反应。下图说明了此流程：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/6f04c52b-a794-4b01-82cb-0fa083ac1b49.png)

反应式编程流程

反应式编程并不是一个仅由学术界使用的奇特的软件工程术语。事实上，它是一种编程模型，可以提高效率，而不是让应用在内存中的数据上迭代的更常见方法。

有更多的反应式编程。首先，让我们考虑一下数据流是由发布者以异步方式提供给订阅服务器的。

数据流是字符串和原始数据类型的二进制输入/输出，`DataInput`接口用于输入流，`DataOutput `接口用于输出流。

处理器或处理器链可用于转换数据流，而无需发布者或订阅者参与。在下面的例子中，**处理器**在没有**发布者**或**订户**参与，甚至没有意识到的情况下处理数据流：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/ddece52b-6927-498a-9017-31a81864923d.png)

处理器-订户关系

除了更高的效率之外，反应式编程还带来了一些额外的好处，这些好处强调如下：

*   代码库可以不那么冗长，因此：
*   更容易编码
*   易于维护
*   更容易阅读

*   流处理可提高内存效率
*   这是一个针对各种编程应用的解决方案
*   需要编写的样板代码更少，因此开发时间可以集中在编程核心功能上
*   以下类型的编程需要较少的时间和代码：
*   并发
*   低级线程
*   同步

# 反应式程序设计标准化

软件开发的许多方面都有标准，而反应式编程也没有逃脱这一点。有一个**反应流**计划来标准化异步流处理。在 Java 上下文中，具体的焦点是 JVM 和 JavaScript。

Reactive 流计划旨在解决控制线程之间如何交换数据流的问题。正如您在上一节中所记得的，处理器的概念是基于对发布者或接收器没有影响。本无影响授权书规定，不需要以下内容：

*   数据缓冲
*   数据平移
*   转换

该标准的基本语义定义了数据流元素传输的规则。这个标准是专门为 Java9 平台而建立的。Reactive 流包含一个库，可以帮助开发人员在`org.reactivestreams`和`java.util.concurrent.Flow`名称空间之间进行转换。

成功使用反应式编程和反应式流标准化的关键是理解相关术语：

| **术语** | **说明** |
| --- | --- |
| 需求 | 需求是指订阅者对更多元素的请求，以及发布者尚未满足的元素请求总数。 |
| 需求 | 需求还指发布者尚未满足的请求元素总数。 |
| 外部同步 | 线程安全的外部访问协调。 |
| 无阻碍 | 如果方法在不需要大量计算的情况下快速执行，则称其为无障碍方法。非阻塞方法不会延迟订阅服务器的线程执行。 |
| 没有 | NOP 执行是可以重复调用而不影响调用线程的执行。 |
| 响应度 | 这个术语是指组件的响应能力。 |
| 正常返回 | 正常返回是指当没有错误时的正常状态。`onError`方法是标准允许的唯一通知用户故障的方法。 |
| 信号 | 以下方法之一： |
| | `cancel()` |
| | `onComplete()` |
| | `onError()` |
| | `onSubscribe()` |
| | `request()` |

在下一节中，我们将研究 Java 平台中的`Flow` API，因为它们对应于反应流规范。

# `Flow` API

`Flow`类是`java.util.concurrent`包的一部分。它帮助开发人员将反应式编程融入到他们的应用中。这个类有一个方法`defaultBufferSize()`和四个接口。

`defaultBufferSize()`方法是一个静态方法，返回发布和订阅缓冲区的默认缓冲区大小。默认为`256`，返回为`int`。

让我们看看这四个接口。

# `Flow.Publisher`接口

`Flow.Publisher`接口是一个函数式接口。`Publisher`是发送给用户的数据的生产者：

```java
@FunctionalInterface
public static interface Flow.Publisher<T>
```

此函数式接口可以用作 Lambda 表达式赋值目标。它只接受一个参数，所订阅项目的类型`<T>`。它有一种方法，即`void subscribe(Flow.Subscriber subscriber)`。

# `Flow.Subscriber`接口

`Flow.Subscriber`接口用于接收消息，其实现如下：

```java
public static interface Flow.Subscriber<T>
```

此接口设置为接收消息。它只接受一个参数，所订阅项目的类型，`<T>`。它有以下方法：

*   `void onComplete()`
*   `void onError(Throwable throwable)`
*   `void onNext(T item)`
*   `void onSubscribe(Flow.Subscription subscription)`

# `Flow.Subscription`接口

`Flow.Subscription`接口确保只有订户接收请求。此外，您将在此处看到，订阅可以随时取消：

```java
public static interface Flow.Subscription
```

此接口不接受任何参数，是控制`Flow.Publisher`和`Flow.Subscriber`实例之间消息的链接。它有以下方法：

*   `void cancel()`
*   `void request(long n)`

# `Flow.Processor`接口

`Flow.Processor`接口可以同时作为`Subscriber`和`Publisher`。此处提供了实现：

```java
static interface Flow.Processor<T,R> extends Flow.Subscriber<T>, Flow.Publisher<R>
```

此接口接受两个参数：订阅项类型`<T>`和发布项类型`<R>`。它没有自己的方法，但从`java.util.concurrent.Flow.Publisher`继承了以下方法：

```java
void subscribe(Flow.Subscriber<? super T> subscriber)
```

`Flow.Processor`还继承了`java.util.concurrent.Flow.Subscriber`接口的以下方法：

*   `void onComplete()`
*   `void onError(Throwable throwable)`
*   `void onNext(T item)`
*   `void onSubscribe(Flow.Subscription subscription)`

# 示例实现

在任何给定的反应式编程实现中，我们将有请求数据的`Subscriber`和提供数据的`Publisher`。首先，让我们看一个示例`Subscriber`实现：

```java
import java.util.concurrent.Flow.*;

public class packtSubscriber<T> implements Subscriber<T> {

  private Subscription theSubscription;

  // We will override the four Subscriber interface methods
  @Override
  public void onComplete() {
    System.out.println("Data stream ended");
  }

  @Override
  public void onError(Throwable theError) {
    theError.printStackTrace();
  }

  @Override
  public void onNext(T theItem) {
    System.out.println("Next item received: " + theItem);
    theSubscription.request(19); // arbitrary number 
  }

  @Override
  public void onSubscribe(Subscription theSubscription) {
    this.theSubscription = theSubscription;
    theSubscription.request(19);
  }
}
```

如您所见，实现`Subscriber`并不困难。繁重的工作由位于`Subscriber`和`Publisher`之间的处理器完成。让我们看一个示例实现，`Publisher`向订阅者发布数据流：

```java
import java.util.concurrent.SubsmissionPublisher;
. . .
// First, let's create a Publisher instance
SubmissionPublisher<String> packtPublisher = 
  newSubmissionPublisher<>();

// Next, we will register a Subscriber
PacktSubscriber<String> currentSubscriber = 
  new PacktSubscriber<>();
packtPublisher.subscribe(currentSubscriber);

// Finally, we will publish data to the Subscriber 
// and close the publishing effort
System.out.println("||---- Publishing Data Stream ----||");
. . .
packtPublisher.close();
System.out.println("||---- End of Data Stream Reached ----||");
```

# 额外的并发更新

Java 平台最近得到了增强，以改进并发性的使用。在本节中，我们将简要探讨 Java 并发的概念，并查看 Java 平台的相关增强功能，包括：

*   Java 并发
*   反应流的支持
*   `CompletableFuture`API 增强

# Java 并发

在本节中，我们将从并发的简要说明开始，然后看系统配置，介绍 Java 线程，最后看并发的改进。

# 并发性解释

并行处理从 20 世纪 60 年代就开始了，在那些形成的年代，我们已经有了允许多个进程共享一个处理器的系统。这些系统被更清楚地定义为伪并行系统，因为它看起来只是多个进程同时被执行。时至今日，我们的计算机仍以这种方式运行。20 世纪 60 年代和现在的区别在于，我们的计算机可以有多个 CPU，每个 CPU 都有多个内核，这更好地支持并发。

并发性和并行性经常被用作可互换的术语。并发是指当多个进程重叠时，尽管开始和停止时间可能不同。并行性发生在任务同时启动、运行和停止时。

# 系统配置

需要考虑几种不同的处理器配置。本节提供两种常见配置。第一种配置是共享内存的配置，如下所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/01cf4b94-05d3-4d73-b2a5-4ef580744c50.png)

共享内存配置

如您所见，共享内存系统配置有多个处理器，它们共享一个公共系统内存。第二个特色系统配置是分布式内存系统：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/70b93dee-6c51-4bbc-8854-b0ed34ae9bbd.png)

分布式存储系统

在分布式存储系统中，每个处理器都有自己的内存，每个单独的处理器都与其他处理器完全链接，形成了一个完全链接的分布式系统。

# Java 线程

Java 中的线程是一个程序执行，内置在 JVM 中。`Thread`类是`java.lang`包（`java.lang.Thread`的一部分。线程具有控制 JVM 执行它们的顺序的优先级。虽然概念很简单，但实现却不简单。让我们先来仔细看看`Thread`类。

`Thread`类有一个嵌套类：

*   `public static enum Thread.State`

与`Thread`类相关的还有以下接口：

*   `public static interface Thread.UncaughtExceptionHandler`

有三个类变量用于管理线程优先级：

*   `public static final int MAX_PRIORITY`
*   `public static final int MIN_PRIORITY`
*   `public static final int NORM_PRIORITY`

`Thread`类有八个构造器，它们都分配一个新的`Thread`对象。以下是构造器签名：

*   `public Thread()`
*   `public Thread(Runnable target)`
*   `public Thread(Runnable target, String name)`
*   `public Thread(String name)`
*   `public Thread(ThreadGroup group, Runnable target)`
*   `public Thread(ThreadGroup group, Runnable target, String name)`
*   `public Thread(ThreadGroup group, Runnable target, String name, long stackSize)`
*   `public Thread(ThreadGroup group, String name)`

`Thread`类还有 43 个方法，其中 6 个已经被弃用。剩下的方法在这里列出，除了分别列出的访问器和变异器。有关每种方法的详细信息，请参阅文档：

*   `public static int activeCount()`
*   `public final void checkAccess()`
*   `protected Object clone() throws CloneNotSupportedException`
*   `public static Thread currentThread()`
*   `public static void dumpStack()`
*   `public static int enumerate(Thread[] array)`
*   `public static boolean holdsLock(Object obj)`
*   `public void interrupt()`
*   `public static boolean interrupted()`
*   `public final boolean isAlive()`
*   `public final boolean isDaemon()`
*   `public boolean isInterrupted()`
*   连接方法：
*   `public final void join() throws InterruptedException`
*   `public final void join(long millis) throws InterruptedException`
*   `public final void join(long millis, int nano) throws InterruptedException`

*   `public void run()`
*   睡眠方法：
*   `public static void sleep(long mills) throws InterruptedException`
*   `public static void sleep(long mills, int nano) throws InterruptedException`

*   `public void start()`
*   `public String toString()`
*   `public static void yield()`

以下是`Thread`类的访问器/获取器和变异器/设置器列表：

*   访问器/获取器：
*   `public static Map<Thread, StackTraceElement[]> getAllStacktraces()`
*   `public ClassLoader getContextClassLoader()`
*   `public static Thread.UncaughtExceptionHandler getDefaultUncaughtExceptionHandler()`
*   `public long getId()`
*   `public final String getName()`
*   `public final int getPriority()`
*   `public StackTraceElement[] getStackTrace()`
*   `public Thread.State getState()`
*   `public final ThreadGroup getThreadGroup()`
*   `public Thread.UncaughtExceptionHandler getUncaughtExceptionHandler()`

*   更改器/设置器：
*   `public void setContextClassLoader(ClassLoader cl)`
*   `public final void setDaemon(boolean on)`
*   `public static void setDefaultUncaughtExceptionHandler(Thread.UncaughtExceptionHandler eh)`
*   `public final void setName(String name)`
*   `public final void setPriority(int newPriority)`
*   `public void setUncaughtExceptionHandler(Thread.UncaughtException Handler eh)`

在 Java 中，并发通常被称为多线程。如前所述，管理线程，尤其是多线程，需要非常逼真的控制。Java 提供了一些技术，包括锁的使用。可以锁定代码段，以确保在任何给定时间只有一个线程可以执行该代码。我们可以使用`synchronized`关键字锁定类和方法。下面是如何锁定整个方法的示例：

```java
public synchronized void protectedMethod() {
  . . .
}
```

下面的代码片段演示了如何使用`synchronized`关键字锁定方法中的代码块：

```java
. . .
public class unprotectedMethod() {
  . . .
  public int doSomething(int tValue) {
    synchronized (this) {
      if (tValue != 0) {
        // do something to change tValue
        return tValue;
      }
    }
  }
}
```

# 并发性改进

在我们的 Java 应用中使用多线程的能力将极大地提高效率，并利用现代计算机日益增长的处理能力。Java 中线程的使用为我们的并发控制提供了很大的粒度。

线程是 Java 并发功能的核心。我们可以通过定义一个`run`方法并实例化一个`Thread`对象，在 Java 中创建一个线程。完成这组任务有两种方法。我们的第一个选择是扩展`Thread`类并覆盖`Thread.run()`方法。下面是这种方法的一个例子：

```java
. . .
class PacktThread extends Thread {
  . . .
  public void run() {
    . . .
  }
}
. . .
Thread varT = new PacktThread();
. . .
// This next line is start the Thread by 
// executing the run() method.
varT.start();
. . .
```

第二种方法是创建一个实现`Runnable`接口的类，并将该类的实例传递给`Thread`的构造器。举个例子：

```java
. . .
class PacktRunner implements Runnable {
  . . .
  public void run() {
    . . .
  }
}
. . .
PacktRunner varR = new PacktRunner();
Thread varT = new Thread(varR);
. . .
// This next line is start the Thread by 
// executing the run() method.
varT.start();
. . .
```

这两种方法都同样有效，您使用哪种方法被认为是开发人员的选择。当然，如果您希望获得更多的灵活性，那么第二种方法可能是更好的方法。你可以尝试这两种方法来帮助你做出决定。

# `CompletableFuture` API 增强

`CompletableFuture<T>`类是`java.util.concurrent`包的一部分。该类扩展了`Object`类，实现了`Future<T>`和`CompletionStage<T>`接口。此类用于标注可以完成的线程。我们可以使用`CompletableFuture`类来表示未来的结果。当使用`complete`方法时，可以完成将来的结果。

重要的是要认识到，如果多个线程试图同时完成（完成或取消），除一个线程外，其他所有线程都将失败。让我们看看这个类，然后看看增强功能。

# 类详情

`CompletableFuture<T>`类有一个嵌套类，用于标记异步任务：

```java
public static interface CompletableFuture.AsynchronousCompletionTask
```

`CompletableFuture<T>`类的构造器必须与提供的构造器签名同步。它也不能接受任何论据。该类具有以下方法，这些方法按返回的内容组织：

返回`CompletionStage`：

*   `public CompletableFuture<Void> acceptEither(CompletionStage<? extends T> other, Consumer<? super T> action)`
*   `public CompletableFuture<Void> acceptEitherAsync(CompletionStage<? extends T> other, Consumer<? super T> action)`
*   `public CompletableFuture<Void> acceptEitherAsync(CompletionStage<? extends T> other, Consumer<? super T> action, Executor executor)`
*   `public <U> CompletableFuture<U> applyToEither(CompletionStage<? extends T> other, Function<? super T, U> fn)`
*   `public <U> CompletableFuture<U> applyToEitherAsync(CompletionStage<? extends T> other, Function<? super T, U> fn)`
*   `public <U> CompletableFuture<U> applyToEitherAsync(CompletionStage<? extends T> other, Function<? super T, U> fn, Executor executor)`
*   `public static <U> CompletedStage<U> completedStage(U value)`
*   `public static <U> CompletionStage<U> failedStage(Throwable ex)`
*   ``public <U> CompletableFuture<U> handle(BiFunction<? super T, Throwable, ? extends U> fn)``
*   `public <U> CompletableFuture<U> handleAsync(BiFunction<? super T, Throwable, ? extends U> fn)`
*   `public <U> CompletableFuture<U> handleAsync(BiFunction<? super T, Throwable, ? extends U> fn, Executor executor)`
*   `public CompletionStage<T> minimalCompletionStage()`
*   `public CompletableFuture<Void> runAfterBoth(CompletionStage<?> other, Runnable action)`
*   `public CompletableFuture<Void> runAfterBothAsync(CompletionStage<?> other, Runnable action)`
*   `public CompletableFuture<Void> runAfterBothAsync(CompletionStage<?> other, Runnable action, Executor executor)`
*   `public CompletableFuture<Void> runAfterEither(CompletionStage<?> other, Runnable action)`
*   `public CompletableFuture<Void> runAfterEitherAsync(CompletionStage<?> other, Runnable action)`
*   `public CompletableFuture<Void> runAfterEitherAsync(CompletionStage<?> other, Runnable action, Executor executor)`
*   `public CompletableFuture<T> whenComplete(BiConsumer<? super T, ? super Throwable> action)`
*   `public CompletableFuture<T> whenCompleteAsync(BiConsumer<? super T, ? super Throwable> action)`
*   `public CompletableFuture<T> whenCompleteAsync(BiConsumer<? super T, ? super Throwable> action, Executor executor)`

这些方法返回`CompletionStage`：

*   `public CompletableFuture<Void> thenAccept(Consumer<? super T> action)`
*   `public CompletableFuture<Void> thenAcceptAsync(Consumer<? super T> action)`
*   ``public CompletableFuture<Void> thenAcceptAsync(Consumer<? super T> action, Executor executor)``
*   `public <U> CompletableFuture<Void> thenAcceptBoth(CompletionStage<? extends U> other, BiConsumer<? super T, ? super U> action)`
*   `public <U> CompletableFuture<Void> thenAcceptBothAsync(CompletionStage<? extends U> other, BiConsumer<? super T, ? super U> action)`
*   `public <U> CompletableFuture<Void> thenAcceptBothAsync(CompletionStage<? extends U> other, BiConsumer<? super T, ? super U> action, Executor executor)`
*   `public <U> CompletableFuture<U> thenApply(Function<? super T, ? extends U> fn)`
*   `public <U> CompletableFuture<U> thenApplyAsync(Function<? super T, ? extends U> fn)`
*   `public <U> CompletableFuture<U> thenApplyAsync(Function<? super T, ? extends U> fn, Executor executor)`
*   `public <U, V> CompletableFuture<V> thenCombine(CompletionStage<? extends U> other, BiFunction<? super T, ? super U, ? extends V> fn)`
*   `public <U, V> CompletableFuture<V> thenCombineAsync(CompletionStage<? extends U> other, BiFunction<? super T, ? super U, ? extends V> fn)`
*   `public <U, V> CompletableFuture<V> thenCombineAsync(CompletionStage<? extends U> other, BiFunction<? super T, ? super U, ? extends V> fn, Executor executor)`
*   `public <U> CompletableFuture<U> thenCompose(Function<? super T, ? extends CompletionStage<U>> fn)`
*   `public <U> CompletableFuture<U> thenComposeAsync(Function<? super T, ? extends CompletionStage<U>> fn)`
*   `public <U> CompletableFuture<U> thenComposeAsync(Function<? super T, ? extends CompletionStage<U>> fn, Executor executor)`
*   `public CompletableFuture<Void> thenRun(Runnable action)`
*   `public CompletableFuture<Void>thenRunAsync(Runnable action)`
*   `public CompletableFuture<Void>thenRunAsync(Runnable action, Executor executor)`

这些方法返回`CompletableFuture`：

*   `public static CompletableFuture<Void> allOf(CompletableFuture<?>...cfs)`
*   `public static CompletableFuture<Object> anyOf(CompletableFuture<?>... cfs)`
*   `public CompletableFuture<T> completeAsync(Supplier<? extends T> supplier, Executor executor)`
*   `public CompletableFuture<T> completeAsync(Supplier<? extends T> supplier)`
*   `public static <U> CompletableFuture<U> completedFuture(U value)`
*   `public CompletableFuture<T> completeOnTimeout(T value, long timeout, TimeUnit unit)`
*   `public CompletableFuture<T> copy()`
*   `public CompletableFuture<T> exceptionally(Function<Throwable, ? extends T> fn)`
*   `public static <U> CompletableFuture<U> failedFuture(Throwable ex)`
*   `public <U> CompletableFuture<U> newIncompeteFuture()`
*   `public CompletableFuture<T> orTimeout(long timeout, TimeUnit unit)`
*   `public static ComletableFuture<Void> runAsync(Runnable runnable)`
*   `public static CompletableFuture<Void> runAsync(Runnable runnable, Executor executor)`
*   `public static <U> CompletableFuture<U> supplyAsync(Supplier<U> supplier)`
*   `public static <U> CompletableFuture<U> supplyAsync(Supplier<U. supplier, Executor executor)`
*   `public CompletableFuture<T> toCompletableFuture()`

这些方法返回`Executor`：

*   `public Executor defaultExecutor()`
*   `public static Executor delayedExecutor(long delay, Timeunit unit, Executor executor)`
*   `public static Executor delayedExecutor(long delay, Timeunit unit)`

这些方法返回`boolean`：

*   `public boolean cancel(boolean mayInterruptIfRunning)`
*   `public boolean complete(T value)`
*   `public boolean completeExceptionally(Throwable ex)`
*   `public boolean isCancelled()`
*   `public boolean isCompletedExceptionally()`
*   `public boolean isDone()`

无返回类型：

*   `public void obtrudeException(Throwable ex)`
*   `public void obtrudeValue(T value)`

其他方法：

*   `public T get(long timeout, TimeUnit unit) throws InterruptedException, ExecutionException, TimeoutException`
*   `public T get() throws InterruptedException, ExecutionException`
*   `public T getNow(T valueIfAbsent)`
*   `public int getNumberOfDependents()`
*   `public T join()`
*   `public String toString()`

# 增强

作为当前 Java 平台的一部分，`CompletableFuture<T>`类收到了以下增强：

*   添加的基于时间的增强功能：
*   这样可以根据经过的时间来完成
*   现在也支持延迟执行

*   子类显著增强：
    *   扩展`CompletableFuture`更容易
    *   子类支持可选的默认执行器

具体来说，Java9 中添加了以下方法：

*   `newIncompleteFuture()`
*   `defaultExecutor()`
*   `copy()`
*   `minimalCompletionStage()`
*   `completeAsync()`
*   `orTimeout()`
*   `completeOnTimeout()`
*   `delayedExecutor()`
*   `completedStage()`
*   `failedFuture()`
*   `failedStage()`

# 旋转等待提示

对于并发，我们需要确保等待执行的线程实际得到执行。自旋等待的概念是一个不断检查真实情况的过程。Java 平台有一个 API，允许 Java 代码发出当前正在执行自旋循环的提示。

虽然这并不是每个 Java 开发人员都会使用的特性，但它对于低级编程是有用的。提示系统只是发出提示指示，不执行其他操作。添加这些提示的理由包括以下假设：

*   当使用自旋提示时，自旋循环的动作时间可以提高
*   使用自旋提示将减少线程到线程的延迟
*   CPU 功耗将降低
*   硬件线程将执行得更快

这个提示功能将包含在一个新的`onSpinWait()`方法中，作为`java.lang.Thread`类的一部分。下面是实现`onSpinWait()`方法的示例：

```java
. . .
volatile boolean notInReceiptOfEventNotification
. . .
while ( notInReceiptOfEventNotification ); {
  java.lang.Thread.onSpinWait();
}
// Add functionality here to read and process the event
. . .
```

# 总结

在本章中，我们讨论了 Java 平台的并发增强。我们将并发作为一个核心 Java 概念进行了深入的研究，并着眼于 Java 提供了什么。我们还研究了支持反应式编程的`Flow`类 API。此外，我们还探讨了并发增强和新的旋转等待提示。

在下一章中，我们将重点介绍 Java 平台的安全增强功能，以及实际示例。

# 问题

1.  什么是反应式编程？
2.  什么是数据流？
3.  使用反应式编程的主要好处是什么？
4.  反应式编程的无影响授权有哪些规定？
5.  `Flow`类是什么包？
6.  列出`Flow`类的四个接口。
7.  什么是并发性？
8.  并发和并行的区别是什么？
9.  解释共享内存系统配置。
10.  解释分布式内存系统配置。

# 进一步阅读

以下是您可以参考的信息列表：

*   《Java9 反应式编程》在[这个页面](https://www.packtpub.com/application-development/reactive-programming-java-9)提供。
*   《Java9 并发高级元素》【视频】在[这个页面](https://www.packtpub.com/application-development/java-9-concurrency-advanced-elements-video)提供。

# 十三、安全增强功能

在最后一章中，我们讨论了现代 Java 平台的并发增强。我们深入研究了并发性，它既是一个核心概念，也是 Java 的一系列增强。我们还研究了支持反应式编程的`Flow`类 API。此外，我们还探讨了 Java 的并发增强和旋转等待提示。

在本章中，我们将介绍最近对 JDK 所做的几个涉及安全性的更改。这些变化的大小并不反映其重要性。现代 Java 平台的安全增强为开发人员提供了编写和维护比以前更安全的应用的能力。

更具体地说，我们将在本章中回顾以下主题：

*   数据报传输层安全
*   创建 PKCS12 密钥库
*   提高安全应用性能
*   TLS 应用层协议协商扩展
*   利用 GHASH 和 RSA 的 CPU 指令
*   用于 TLS 的 OCSP 装订
*   基于 DRBG 的`SecureRandom`实现

# 技术要求

本章和随后的几章主要介绍 Java11。Java 平台的**标准版**（**SE**）可从 [Oracle 官网](http://www.oracle.com/technetwork/java/javase/downloads/index.html)下载。

IDE 包就足够了。来自 JetBrains 的 IntelliJ IDEA 用于与本章和后续章节相关的所有编码。IntelliJ IDEA 的社区版可从[网站](https://www.jetbrains.com/idea/features/)下载。

# 数据报传输层安全

**数据报传输层安全**（**DTLS**）是一种通信协议。该协议为基于数据报的应用提供了一个安全层。DTLS 允许安全通信，基于**传输层安全**（**TLS**）协议。嵌入式安全性有助于确保消息不被伪造、篡改或窃听。

让我们回顾一下相关术语：

*   **通信协议**：一组控制信息传输方式的规则。
*   **数据报**：结构化传输单元。
*   **窃听**：监听在途数据包时未被发现。
*   **伪造**：用伪造的发送者传送数据包。
*   **网络包**：一种格式化的数据传输单元。
*   **篡改**：在发送方发送数据包之后，在预定接收方接收数据包之前，对数据包的篡改。
*   **TLS 协议**：最常用的网络安全协议。例如，它使用 IMPA 和 POP 发送电子邮件。

最近的 DTLS Java 增强旨在为 DTLS 的 1.0 和 1.2 版本创建 API。

在接下来的部分中，我们将查看每个 DTLS 版本 1.0 和 1.2，然后回顾对 Java 平台所做的更改。

# DTLS 协议版本 1.0

DTLS 协议 1.0 版于 2006 年建立，为数据报协议提供通信安全。其基本特征如下：

*   允许客户端/服务器应用通信，而不允许：
*   窃听
*   篡改
*   信息伪造

*   基于 TLS 协议
*   提供安全保障
*   保留了 DLS 协议的数据报语义

下图说明了**传输层**在 **SSL/TLS** 协议层的总体架构中的位置以及每层的协议：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/b8bdfd37-c99d-4798-b658-a7f8093e5d10.png)

SSL/TLS 协议层

DTLS 协议版本 1.0 提供了主要覆盖区域的详细规范，如下所示：

*   密码：
*   防重放分组密码
*   新密码套件
*   标准（或空）流密码

*   拒绝服务对策
*   握手：
*   消息格式
*   协议
*   可靠性

*   信息：
*   分裂与重组
*   对丢失不敏感的消息
*   大小
*   超时和重传
*   数据包丢失

*   **路径最大转换单元**（PMTU）发现
*   记录层
*   记录有效负载保护
*   重新排序
*   重放检测
*   传输层映射

# DTLS 协议版本 1.2

DTLS 协议 1.2 版于 2012 年 1 月发布，版权归**互联网工程任务组**（**IETF**）所有。本节共享说明在版本 1.2 中所做更改的代码示例。

下面的代码演示了 TLS1.2 握手消息头。此格式支持：

*   消息碎片
*   消息丢失
*   重新排序：

```java
// Copyright (c) 2012 IETF Trust and the persons identified 
// as authors of the code. All rights reserved.

struct 
{
  HandshakeType msg_type;
  uint24 length;
  uint16 message_seq; // New field
  uint24 fragment_offset; // New field
  uint24 fragment_length; // New field
  select (HandshakeType)
  {
    case hello_request: HelloRequest;
    case client_hello: ClientHello;
    case hello_verify_request: HelloVerifyRequest; // New type
    case server_hello: ServerHello;
    case certificate:Certificate;
    case server_key_exchange: ServerKeyExchange;
    case certificate_request: CertificateRequest;
    case server_hello_done:ServerHelloDone;
    case certificate_verify: CertificateVerify;
    case client_key_exchange: ClientKeyExchange;
    case finished: Finished;
  } body;
} Handshake;
```

本节中的代码来自 DTLS 协议文件，并根据 IETF *有关文件*的法律规定重新发布。

记录层包含我们打算发送到记录中的信息。信息开始于`DTLSPlaintext`结构中，然后在握手发生之后，记录被加密，并且可以通过通信流发送。记录层格式遵循 1.2 版中的新字段，并在代码注释中用`// New field`注解，如下所示：

```java
// Copyright (c) 2012 IETF Trust and the persons identified
// as authors of the code. All rights reserved.

struct
{
  ContentType type;
  ProtocolVersion version;
  uint16 epoch; // New field
  uint48 sequence_number; // New field
  uint16 length;
  opaque fragment[DTLSPlaintext.length];
} DTLSPlaintext;

struct
{
  ContentType type;
  ProtocolVersion version;
  uint16 epoch; // New field
  uint48 sequence_number; // New field
  uint16 length;
  opaque fragment[DTLSCompressed.length];
} DTLSCompressed;

struct
{
  ContentType type;
  ProtocolVersion version;
  uint16 epoch; // New field
  uint48 sequence_number; // New field
  uint16 length;
  select (CipherSpec.cipher_type)
  {
    case block: GenericBlockCipher;
    case aead: GenericAEADCipher; // New field
  } fragment;
} DTLSCiphertext;
```

最后，这里是更新的握手协议：

```java
// Copyright (c) 2012 IETF Trust and the persons identified
// as authors of the code. All rights reserved.

enum {
  hello_request(0), client_hello(1),
  server_hello(2),
  hello_verify_request(3), // New field
  certificate(11), server_key_exchange (12),
  certificate_request(13), server_hello_done(14),
  certificate_verify(15), client_key_exchange(16),
  finished(20), (255) } HandshakeType;

  struct {
    HandshakeType msg_type;
    uint24 length;
    uint16 message_seq; // New field
    uint24 fragment_offset; // New field
    uint24 fragment_length; // New field
    select (HandshakeType) {
      case hello_request: HelloRequest;
      case client_hello: ClientHello;
      case server_hello: ServerHello;
      case hello_verify_request: HelloVerifyRequest; // New field
      case certificate:Certificate;
      case server_key_exchange: ServerKeyExchange;
      case certificate_request: CertificateRequest;
      case server_hello_done:ServerHelloDone;
      case certificate_verify: CertificateVerify;
      case client_key_exchange: ClientKeyExchange;
      case finished: Finished;
    } body; } Handshake;

  struct {
    ProtocolVersion client_version;
    Random random;
    SessionID session_id;
    opaque cookie<0..2^8-1>; // New field
    CipherSuite cipher_suites<2..2^16-1>;
    CompressionMethod compression_methods<1..2^8-1>; } ClientHello;

 struct {
    ProtocolVersion server_version;
    opaque cookie<0..2^8-1>; } HelloVerifyRequest;
```

# Java 中的 DTLS 支持

DTLS API 的 Java 实现是独立于传输的，而且是轻量级的。API 的设计考虑如下：

*   将不管理读取超时
*   实现将为每个包装/展开操作使用一个 TLS 记录
*   应用（而不是 API）需要：
*   确定超时值
*   组装无序的应用数据

DTLS 是一种协议，用于在将数据传递到传输层协议之前保护来自应用层的数据。DTLS 是加密和传输实时数据的一个很好的解决方案。应谨慎行事，以免在应用实现中引入漏洞。以下是在 Java 应用中实现 DTL 的一些安全注意事项：

*   实现 DTLS 1.2，因为它是 Java 支持的最新版本。
*   避免 **Rivest Shamir Adleman**（**RSA**）加密。如果必须使用 RSA，请为私钥添加额外的安全性，因为这是 RSA 的一个弱点。
*   当使用**椭圆曲线 Diffie-Hellman**（**ECDH**）匿名密钥协商协议时，使用 192 位或更多。192 位的值基于**美国国家标准与技术研究所**（**NIST**）的建议。
*   强烈建议使用**带有相关数据的认证加密**（**AEAD**），这是一种加密形式。AEAD 为加密和解密的数据提供真实性、机密性和完整性保证。
*   在实现握手重新协商时，始终实现`renegotiation_info`扩展。
*   在使用通信协议的所有 Java 应用中建立**前向保密**（**FS**）功能。实现 FS 可以确保过去的会话加密密钥不会在长期加密密钥受损时受损。理想情况下，**完美前向保密**（**PFS**），其中每个密钥仅对单个会话有效，将用于要求传输数据最大安全性的 Java 应用中。

# 创建 PKCS12 密钥库

Java 平台为密钥库提供了更高的安全性。在默认情况下创建 PKCS12 密钥库之前，我们将首先回顾密钥库的概念，查看`KeyStore`类，然后查看 Java 平台的最新更新。

# 密钥库入门

`KeyStore`的概念相对简单。它本质上是一个存储公钥证书和私钥的数据库文件或数据存储库文件。`KeyStore`将存储在`/jre/lib/security/cacerts`文件夹中。正如您将在下一节中看到的，这个数据库是由 Java 的`java.security.KeyStore`类方法管理的。

`KeyStore`的特点包括：

*   包含以下条目类型之一：
*   私钥
*   公钥证书

*   每个条目的唯一别名字符串名称
*   每个密钥的密码保护

# Java 密钥库（JKS）

`java.security.KeyStore`类是加密密钥和证书的存储设施。这个类扩展了`java.lang.Object`，如下所示：

```java
public class KeyStore extends Object
```

由`KeyStore`管理的条目有三种类型，每种类型都实现`KeyStore.Entry`接口，`KeyStore`类提供的三个接口之一。下表定义了条目实现：

| **实现** | **说明** |
| --- | --- |
| `KeyStore.PrivateKeyEntry` | 包含`PrivateKey`，它可以以受保护的格式存储。包含公钥的证书链。 |
| `KeyStore.SecretKeyEntry` | 包含`SecretKey`，它可以以受保护的格式存储。 |
| `KeyStore.TrustedCertifcateEntry` | 包含来自外部源的单个公钥`Certificate`。 |

这个类从 1.2 版开始就是 Java 平台的一部分。它有一个构造器、三个接口、六个子类和几个方法。构造器定义如下：

```java
protected KeyStore(KeyStoreSpi keyStoresSpi, Provider provider, String type)
```

`KeyStore`类包含以下接口：

*   `public static interface KeyStore.Entry`：此接口作为`KeyStore`条目类型的标记，不包含方法。
*   `public static interface KeyStore.LoadStoreParameter`：此接口作为加载和存储参数的标记，有如下返回`null`的方法，或用于保护`KeyStore`数据的参数：
    *   `getProtectionParameter()`
*   `public static interface KeyStore.ProtectionParameter`：此接口作为`KeyStore`保护参数的标记，不含方法。

`java.security.KeyStore`类还包含六个嵌套类，每个嵌套类都将在后面的部分中进行研究。

`KeyStoreSpi`类定义密钥存储的**服务提供者接口**（**SPI**）。

# 了解密钥库生成器

`KeyStore.Builder`类用于延迟`KeyStore`的实例化：

```java
public abstract static class KeyStore.Builder extends Object
```

这个类为实例化一个`KeyStore`对象提供了必要的信息。该类具有以下方法：

*   `public abstract KeyStore getKeyStore() throws KeyStoreException`。
*   `public abstractKeyStore.ProtectionParameter getProjectionParameter(String alias) throws KeyStoreException`。
*   `newInstance`有三个选项：
*   `public static KeyStore.Builder newInstance(KeyStore keyStore, KeyStore.ProtectionParameter protectionParameter)`
*   `public static KeyStore.Builder newInstance(String type, Provider provider, File file, KeyStore.ProtectionParameter protection)`
*   `public static KeyStore.Builder newInstance(String type, Provider provider, KeyStore.ProtectionParameter protection)`

# `CallbackHandlerProtection`类

`KeyStore.CallbackHandlerProtection`类定义如下：

```java
public static class KeyStore.CallbackHandlerProtection extends Object implements KeyStore.ProtectionParameter
```

此类提供`ProtectionParameter`来封装`CallbackHandler`，方法如下：

```java
public CallbackHandler getCallbackHandler()
```

# `PasswordProtection`类

`KeyStore.PasswordProtection`类定义如下：

```java
public static class KeyStore.PasswordProtection extends Object implements KeyStore.ProtectionParameter, Destroyable
```

这个调用提供了一个基于密码的`ProtectionParameter`实现。此类具有以下方法：

*   `public void destroy() throws DestroyFailedException`：此方法清除密码
*   `public char[] getPassword()`：返回对密码的引用
*   `public boolean isDestroyed()`：清除密码返回`true`

# `PrivateKeyEntry`类

`KeyStore.PrivateKeyEntry`类定义如下：

```java
public static final class KeyStore.PrivateKeyEntry extends Object implements KeyStore.Entry
```

这将创建一个条目来保存`PrivateKey`和相应的`Certificate`链。此类具有以下方法：

*   `public Certificate getCertificate()`：从`Certificate`链返回结束实体`Certificate`
*   `public Certificate[] getCertificateChain()`：返回`Certificate`链作为`Certificates`的数组
*   `public PrivateKey getPrivateKey()`：返回当前分录的`PrivateKey`
*   `public String toString()`：返回`PrivateKeyEntry`为`String`

# `SecretKeyEntry`类

`KeyStore.SecretKeyEntry`类定义如下：

```java
public static final class KeyStore.SecretKeyEntry extends Object implements KeyStore.Entry
```

这个类持有`SecretKey`，有以下方法：

*   `public SecretKey getSecretKey()`：返回分录的`SecretKey`
*   `public String toString()`：返回`SecretKeyEntry`为`String`

# `TrustedCertificateEntry`类

`KeyStore.TrustedCertificateEntry`类定义如下：

```java
public static final class KeyStore.TrustedCertificateEntry extends Object implements KeyStore.Entry
```

此类持有一个可信的`Certificate`，并具有以下方法：

*   `public Certificate getTrustedCertificate()`：返回条目的可信`Certificate`
*   `public String toString()`：返回条目的可信`Certificate`为`String`

使用这个类的关键是理解它的流。首先，我们必须使用`getInstance`方法加载`KeyStore`。接下来，我们必须请求访问`KeyStore`实例。然后，我们必须获得访问权限，以便能够读写到`Object`：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/08d813bf-e1a6-4d78-b846-b13fee96e0d3.png)

密钥库加载请求访问模式

以下代码段显示了加载请求访问实现：

```java
. . .
try {
  // KeyStore implementation will be returned for the default type
  KeyStore myKS = KeyStore.getInstance(KeyStore.getDefaultType());

  // Load
  myKS.load(null, null);

  // Instantiate a KeyStore that holds a trusted certificate
  TrustedCertificateEntry myCertEntry =
    new TrustedCertificateEntry(generateCertificate());

  // Assigns the trusted certificate to the "packt.pub" alias
  myKS.setCertificateEntry("packt.pub", 
    myCertEntry.getTrustedCertificate());

  return myKS;
  }
  catch (Exception e) {
    throw new AssertionError(e);
  }
}
. . .
```

# Java9、10 和 11 中的 PKCS12 默认值

在 Java9 之前，默认的`KeyStore`类型是 **Java 密钥库**（**JKS**）。当前的 Java 平台使用 PKCS 作为默认的`KeyStore`类型，更确切地说，PKCS12。

**PKCS** 是**公钥密码标准**的首字母缩写。

与 JKS 相比，PKCS 的这种变化提供了更强的加密算法。正如您所料，JDK9、10 和 11 仍然与 JKS 兼容，以支持以前开发的系统。

# 提高安全应用性能

当运行安装了安全管理器的应用时，现代 Java 平台包括性能改进。安全管理器可能导致处理开销和不理想的应用性能。

这是一项令人印象深刻的任务，因为当前运行安全管理器时的 CPU 开销估计会导致 10-15% 的性能下降。完全消除 CPU 开销是不可行的，因为运行安全管理器需要一些 CPU 处理。也就是说，目标是尽可能降低间接费用的百分比。

这项工作导致了以下优化，每个优化将在后面的部分中详细介绍：

*   安全策略实现
*   权限评估
*   哈希码
*   包检查算法

# 安全策略实现

JDK 使用`ConcurrentHashMap`将`ProtectionDomain`映射到`PermissionCollection`。`ConcurrentHashMap`通常用于应用中的高并发性。它具有以下特点：

*   线程安全
*   进入映射不需要同步
*   快速读取
*   使用锁的写入
*   无对象级锁定
*   非常精细的级别上的锁定

`ConcurrentHashMap`类定义如下：

```java
public class ConcurrentHashMap<K, V> extends AbstractMap<K, V> implements ConcurrentMap<K, V>, Serializable
```

在前面的类定义中，`K`表示哈希映射维护的键的类型，`V`表示映射值的类型。有一个`KeySetView`子类和几个方法。

与强制执行安全策略相关的附加类有三个-`ProtectionDomain`、`PermissionCollection`和`SecureClassLoader`：

*   `ProtectionDomain`类用于封装一组类，以便向域授予权限。
*   `PermissionCollection`类表示权限对象的集合。
*   `SecureClassLoader`类扩展了`ClassLoader`类，它提供了额外的功能，用于定义具有系统策略检索权限的类。在 Java 中，这个类使用`ConcurrentHashMap`来提高安全性。

# 权限评估

在权限评估类别下，进行了三项优化：

*   `identifyPolicyEntries`列表以前有用于同步的策略供应器代码。此代码已被删除，在 Java9、10 或 11 中不可用。
*   `PermissionCollection`条目现在存储在`ConcurrentHashMap`中。它们以前被存储为`Permission`类中的`HashMap`。
*   权限现在存储在`PermissionCollection`的子类中的并发集合中。

# `java.security.CodeSource`包

哈希码是一个对象生成的数字，存储在哈希表中，用于快速存储和检索。Java 中的每个对象都有一个哈希码。以下是哈希码的一些特征和规则：

*   哈希码对于正在运行的进程中的相等对象是相同的
*   哈希码可以在执行周期之间更改
*   哈希码不应用作密钥

Java 平台包括一个改进的`hashCode`方法`java.security.CodeSource`来优化 DNS 查找。这些可能是处理器密集型的，因此使用代码源 URL 的字符串版本来计算哈希码。

`CodeSource`类定义如下：

```java
public class CodeSource extends Object implements Serializable
```

此类具有以下方法：

*   `public boolean equals(Object obj)`：如果对象相等，则返回`true`。这将覆盖`Object`类中的`equals`方法。
*   `public final Certificate[] getCertificates()`：返回证书数组。
*   `public final CodeSigner[] getCodeSigners()`：返回与`CodeSource`关联的代码签名者数组。
*   `public final URL getLocation()`：返回 URL。
*   `public int hashCode()`：返回当前对象的哈希码值。
*   `public boolean implies(CodeSource codesource)`：如果给定的代码源满足以下条件，则返回`true`：
    *   不为空
    *   对象的证书不为空
    *   对象的位置不为空
*   `public String toString()`：返回一个字符串，其中包含关于`CodeSource`的信息，包括位置和证书。

# 包检查算法

当运行安装了安全管理器的应用时，Java 最近的性能改进是以`java.lang.SecurityManager`包增强的形式出现的。更具体地说，`checkPackageAccess`方法的包检查算法被修改。

`java.lang.SecurityManager`类允许应用在特定操作上实现安全策略。此类的`public void checkPackageAccess(String pkg)`方法从`getProperty()`方法接收逗号分隔的受限包列表。如这里所示，根据评估，`checkPackageAccess`方法可以抛出两个异常中的一个：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/64debc0e-e1c0-4ce6-bf99-a8960cfad77a.png)

`checkPackageAccess`方法的异常

# TLS 应用层协议协商扩展

`javax.net.ssl`包最近进行了增强，支持**传输层安全扩展**（**TLS ALPN**）（简称**应用层协议协商**）。此扩展允许 TLS 连接的应用协议协商。

# TLS ALPN 扩展

ALPN 是 TLS 扩展，可用于协商在使用安全连接时要实现的协议。ALPN 是协商协议的有效手段。如下图所示，TLS 握手有五个基本步骤：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/364a8bb5-a723-4e9e-98f3-536d1047297c.png)

TLS 握手的五个步骤

# `java.net.ssl`包

`java.net.ssl`包包含与安全套接字包相关的类。这允许我们以 SSL 为例，可靠地检测引入网络字节流的错误。它还提供了加密数据以及提供客户端和服务器认证的能力。

此包包括以下接口：

*   `public interface HandshakeCompletedListener extends EventListener`
*   `public interface HostnameVerifier`
*   `public interface KeyManager`
*   `public interface ManagerFactoryParameters`
*   `public interface SSLSession`
*   `public interface SSLSessionBindingListener extends EventListener`
*   `public interface SSLSessionContext`
*   `public interace TrustManager`
*   `public interface X509KeyManager extends KeyManager`
*   `public interface X509TrustManager extends TrustManager`

`java.net.ssl`包还有以下子类：

*   `public class CertPathTrustManagerParameters extends Object implements ManagerFactoryParameters`
*   `public abstract class ExtendedSSLSession extends Object implements SSLSession`
*   `public class HandshakeCompleteEvent extends EventObject`
*   `public abstract class HttpsURLConnection extends HttpURLConnection`
*   `public class KeyManagerFactory extends Object`
*   `public abstract class KeyManagerFactorySpi`
*   `public class KeyStoreBuilderParameters extends Object implements ManagerFactoryParameters`
*   ``public class SSLContext extends Object``
*   `public abstract class SSLContextSpi extends Object`
*   `public abstract class SSLEngine extends Object`
*   `public class SSLEngineResult extends Object`
*   `public class SSLParameters extends Object`
*   `public final class SSLPermission extends BasicPermission`
*   `public abstract class SSLServerSocket extends ServerSocket`
*   `public abstract class SSLServerSocketFactory extends ServerSocketFactory`
*   `public class SSLSessionBindingEvent extends EventObject`
*   `public abstract class SSLSocket extends Socket`
*   `public abstract class SSLSocketFactory extends SocketFactory`
*   `public class TrustManagerFactory extends Object`
*   `public abstract class TrustManagerFactorySpi extends Object`
*   `public abstract class X509ExtendedKeyManager extends Object implements X509KeyManager`
*   `public abstract class X509ExtendedTrustManager extends Object implements x509TrustManager`

# `java.net.ssl`包扩展

Java 平台中对`java.net.ssl`包的这个更改使得它现在支持 TLS-ALPN 扩展。这一变化的主要好处如下：

*   TLS 客户端和服务器现在可以使用多个应用层协议，这些协议可以使用也可以不使用同一传输层端口
*   ALPN 扩展允许客户端对其支持的应用层协议进行优先级排序
*   服务器可以为 TLS 连接选择客户端协议
*   支持 HTTP/2

下面的说明是 TLS 握手的五个基本步骤。针对 Java9 进行了更新并在此处显示，下图显示了在客户端和服务器之间共享协议名称的位置：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/87ae496e-9220-4439-9c50-7c3d55027d91.png)

TLS 握手：共享协议名称

一旦接收到客户端的应用层协议列表，服务器就可以选择服务器的首选交集值，并从外部扫描初始明文`ClientHellos`，选择一个 ALPN 协议。应用服务器将执行以下操作之一：

*   选择任何受支持的协议
*   确定 ALPN 值（远程提供和本地支持）是互斥的
*   忽略 ALPN 扩展名

与 ALPN 扩展相关的其他关键行为如下：

*   服务器可以更改连接参数
*   SSL/TLS 握手开始后，应用可以查询 ALPN 值是否已被选中
*   SSL/TLS 握手结束后，应用可以查看使用了哪种协议

`ClientHello`是 TLS 握手中的第一条消息。其结构如下：

```java
struct {
  ProtocolVersion client_version;
  Random random;
  SessionID session_id;
  CipherSuite cipher_suites<2..2^16-1>;
  CompressionMethod compression_methods<1..2^8-1>;
  Extension extensions<0..2^16-1>;
} ClientHello;
```

# 利用 GHASH 和 RSA 的 CPU 指令

现代 Java 平台包括一个改进的加密操作性能，特别是 GHASH 和 RSA。通过利用最新的 SPARC 和 IntelX64CPU 指令，Java 实现了这种性能改进。

此增强不需要新的或修改的 API 作为 Java 平台的一部分。

# 散列

**Galois HASH**（**GHASH**）和 **RSA** 是密码系统哈希算法。哈希是由文本字符串生成的固定长度的字符串或数字。算法，更具体地说是散列算法，被设计成这样的结果散列不能被反向工程。我们使用散列存储用盐生成的密码。

在密码学中，盐是一种随机数据，用作哈希函数生成密码的输入。盐有助于防止彩虹表攻击和字典攻击。

下图说明了哈希的基本工作原理：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/8962c8f0-78f6-4151-9dca-7db4f235bf51.png)

哈希概述

如您所见，**散列算法**被输入明文和**盐**，从而产生一个新的散列密码并存储**盐**。以下是带有示例输入/输出的相同图形，以演示功能：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/ce245ee5-0a14-442b-9903-34da1912a923.png)

哈希和盐功能

如下图所示，验证过程从用户输入纯文本密码开始。散列算法接受纯文本并用存储的盐重新散列它。然后，将得到的哈希密码与存储的密码进行比较：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/7a039fd2-0c1b-40d6-9b16-bf68c1aa3dbf.png)

哈希匹配验证

# 用于 TLS 的 OCSP 装订

**在线证书状态协议**（**OCSP**）装订是检查数字证书撤销状态的方法。确定 SSL 证书有效性的 OCSP 装订方法被评估为既安全又快速。通过允许 Web 服务器提供其组织证书的有效性信息，而不是从证书的颁发供应商处请求验证信息的较长过程，可以实现确定速度。

OCSP 装订以前被称为 TLS 证书状态请求扩展。

# OCSP 装订入门

OCSP 装订过程涉及多个组件和有效性检查。下图说明了 OCSP 装订过程：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/38752ba7-69c8-4782-9194-aa1ecf20673b.png)

哈希匹配验证

如您所见，当用户试图通过浏览器打开 SSL 加密的网站时，该过程就开始了。浏览器查询 Web 服务器以确保 SSL 加密的网站具有有效的证书。Web 服务器查询证书的供应商，并提供证书状态和数字签名的时间戳。Web 服务器获取这两个组件，将它们装订在一起，并将装订好的集合返回到请求的浏览器。然后，浏览器可以检查时间戳的有效性，并决定是显示 SSL 加密的网站还是显示错误。

# Java 平台的最新变化

**TLS 的 OCSP 装订**通过 TLS 证书状态请求扩展实现 OCSP 装订。OSCP 装订检查 X.509 证书的有效性。

X.509 证书是使用 X509 **公钥基础设施**（**PKI**）的数字证书。

在 Java9 之前，可以在客户端启用证书有效性检查（实际上，检查证书是否已被吊销），但效率低下：

*   OCSP 响应程序的性能瓶颈
*   基于多通道的性能下降
*   如果在客户端执行 OCSP 检查，则性能会进一步降低
*   **在浏览器未连接到 OCSP 响应程序时**失败
*   OCSP 响应程序易受拒绝服务攻击

用于 TLS 的新 OCSP 装订包括 Java9、10 和 11 的以下系统属性更改：

*   `jdk.tls.client.enableStatusRequestExtension`：
    *   默认设置：`true`
    *   启用`status_request`扩展
    *   启用`status_request_v2`扩展
    *   允许处理来自服务器的`CertificateStatus`消息
*   `jdk.tls.server.enableStatusRequestExtension`：
    *   默认设置：`false`
    *   在服务器端启用 OCSP 装订支持
*   `jdk.tls.stapling.responseTimeout`：
    *   默认设置：5000 毫秒
    *   控制服务器分配的获取 OCSP 响应的最长时间
*   `jdk.tls.stapling.cacheSize`：
    *   默认设置：256
    *   控制缓存项的最大数目
    *   可将最大值设置为零
*   `jdk.tls.stapling.cacheLifetime`：
    *   默认设置：3600 秒（1 小时）
    *   控制缓存响应的最大生存期
    *   可以将该值设置为零以禁用缓存的生存期
*   `jdk.tls.stapling.responderURI`：
    *   默认设置：无
    *   可以为没有**权限信息访问**（**AIA**）扩展的证书设置默认 URI
    *   除非设置了`jdk.tls.stapling.Override`属性，否则不覆盖 AIA 扩展
*   `jdk.tls.stapling.respoderOverride`：
    *   默认设置：`false`
    *   允许`jdk.tls.stapling.responderURI`提供的属性覆盖 AIA 扩展值
*   `jdk.tls.stapling.ignoreExtensions`：
    *   默认设置：`false`
    *   禁用 OCSP 扩展转发，如`status_request`或`status_request_v2`TLS 扩展中所述

`status_request`和`status_request_v2`TLS Hello 扩展现在都受客户端和服务器端 Java 实现的支持。

# 基于 DRBG 的`SecureRandom`实现

在 Java 的早期版本中，即版本 8 和更早版本中，JDK 有两种生成安全随机数的方法。有一种方法是用 Java 编写的，使用基于 SHA1 的随机数生成，而且不是很强。另一种方法依赖于平台，使用预配置的库。

**确定性随机位生成器**（**DRBG**）是一种产生随机数的方法。它已经被美国商务部的分支机构 NIST 批准。DRBG 方法包括生成安全随机数的现代和更强的算法。

最近，实现了三种特定的 DRBG 机制。这些机制如下：

*   `Hash_DRBG`
*   `HMAC_DRBG`
*   `CTR_DRBG`

您可以在[这个页面](http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-90Ar1.pdf)了解每个 DRBG 机制的细节。

以下是三个新的 API：

*   `SecureRandom`：新方法，允许配置具有以下可配置属性的`SecureRandom`对象：
    *   播种
    *   重新播种
    *   随机位生成
*   `SecureRandomSpi`：实现`SecureRandom`方法的新方法。
*   `SecureRandomParameter`：新的接口，以便输入可以传递给新的`SecureRandom`方法。

# 总结

在本章中，我们研究了 JDK 中涉及安全性的几个小而重要的更改。特色的安全增强功能为开发人员提供了编写和维护实现安全性的应用的独特能力。更具体地说，我们讨论了 DTL、密钥库、提高安全应用性能、TLS ALPN、利用 GHASH 和 RSA 的 CPU 指令、TLS 的 OCSP 装订以及基于 DRBG 的`SecureRandom`实现。

在下一章中，我们将探讨 Java 中使用的新命令行标志以及对各种命令行工具的更改。我们的内容将包括使用新的命令行选项和标志管理 Java 的 JVM 运行时和编译器。

# 问题

1.  什么是 DTLS？
2.  什么是 TLS？
3.  握手重新协商的安全考虑是什么？
4.  为什么要在 Java 应用中建立 FS 功能？
5.  什么是`KeyStore`？
6.  `KeyStore`存放在哪里？
7.  `Builder`类的目的是什么？
8.  `ConcurrentHashMap`有什么特点？
9.  什么是哈希码？
10.  什么是 GHASH？

# 进一步阅读

以下是您可以参考的信息列表：

*   《即时 Java 密码和认证安全》，在[这个页面](https://www.packtpub.com/application-development/instant-java-password-and-authentication-security-instant)提供。

# 十四、命令行标志

在上一章中，我们研究了 JDK 的几个安全性更改。Java 的安全增强为开发人员提供了编写和维护实现安全性的应用的能力。更具体地说，我们讨论了数据报传输层安全性、密钥库、提高安全应用性能、TLS ALPN、利用 GHASH 和 RSA 的 CPU 指令、TLS 的 OCSP 装订以及基于 DRBG 的`SecureRandom`实现。

在本章中，我们将探讨现代 Java 平台的几个变化，这些变化的共同主题是命令行标志。更具体地说，我们将介绍以下概念：

*   统一 JVM 日志记录
*   编译器控件
*   诊断命令
*   堆分析代理
*   移除 JHAT
*   命令行标志参数验证
*   为旧平台版本编译
*   基于 Java 的 JIT 编译器实验

# 技术要求

本章及后续章节主要介绍 Java11，Java 平台的**标准版**（**SE**）可从 [Oracle 官方网站](http://www.oracle.com/technetwork/java/javase/downloads/index.html)下载。

IDE 包就足够了。来自 JetBrains 的 IntelliJ IDEA 用于与本章和后续章节相关的所有编码。IntelliJ IDEA 的社区版可从[网站](https://www.jetbrains.com/idea/features/)下载。

# 统一 JVM 日志记录

Java9 中引入了为 JVM 创建统一的日志模式。以下是这项工作的目标的综合清单：

*   为所有日志操作创建一组 JVM 范围的命令行选项
*   使用分类标签进行日志记录
*   允许消息具有多个标签，也称为标签集
*   要提供六个级别的日志记录：
*   错误
*   警告
*   信息
*   调试
*   跟踪
*   开发

*   根据级别选择要记录的消息
*   要选择性地将日志记录定向到控制台或文件，请执行以下操作：
*   一次打印一行，不支持在同一行内交错
*   允许输出多行日志（非交错）
*   设置所有日志消息的格式，使其易于人阅读
*   添加装饰，如正常运行时间、级别和标记
*   与级别类似，用于选择基于装饰记录哪些消息
*   将 Java9 之前的`tty>print`日志转换为使用统一日志作为输出
*   允许使用`jcmd`和`MBeans`进行动态消息配置
*   允许启用和禁用单个日志消息
*   添加确定装饰打印的顺序的功能

对 JVM 的统一日志记录更改可以分为以下五类：

*   命令行选项
*   装饰
*   水平
*   输出
*   标签

让我们简单地看一下这些类别中的每一个。

# 命令行选项

新的命令行选项`-Xlog`是 Java 日志框架的关键组件。这个命令行选项有大量的参数和可能性。基本语法是`-Xlog`，后跟一个选项。

以下是正式的基本语法：

```java
-Xlog[:option]
```

下面是一个带有`all`选项的基本示例：

```java
-Xlog:all
```

以下是用于配置新的统一日志记录的广泛命令行语法：

```java
-Xlog[:option]
option := [<what>][:[<output>][:[<decorators>][:<outputoptions>]]]
'help'
'disable' 
what := <selector>[,...]
selector := <tag-set>[*][=<level>]
tag-set := <tag>[+..]
'all'
tag := name of tag
level := trace
debug
info
warning
error 
output := 'stderr'
'stdout'
[file=]<filename>
decorators := <decorator>[,...]
'none' 
decorator := time
uptime
timemillis
uptimemillis
timenanos
uptimenanos
pid
tid
level
tags
output-options := <output_option>[,...]
output-option := filecount=<file count>
filesize=<file size in kb>
parameter=value
```

以下`-Xlog`示例后面是说明：

```java
-Xlog:all
```

在前面的示例中，我们告诉 JVM 执行以下操作：

*   记录所有消息
*   使用`info`水平
*   向`stdout`提供输出

在本例中，所有的`warning`消息仍将输出到`stderr`。

以下示例在`debug`级别记录消息：

```java
-Xlog:gc+rt*=debug
```

在前面的示例中，我们告诉 JVM 执行以下操作：

*   记录至少带有`gc`和`rt`标记的所有消息
*   使用`debug`水平
*   向`stdout`提供输出

以下示例将输出推送到外部文件：

```java
-Xlog:disable - Xlog:rt=debug:rtdebug.txt
```

在前面的示例中，我们告诉 JVM 执行以下操作：

*   禁用除标记有`rt`标记的消息以外的所有消息
*   使用`debug`水平
*   向名为`rtdebug.txt`的文件提供输出

# 装饰

在 Java 日志框架的上下文中，装饰是关于日志消息的元数据。以下是按字母顺序排列的可用装饰品列表：

*   `level`：与记录的消息相关联的级别
*   `pid`：进程标识符
*   `tags`：与记录的消息相关联的标签集
*   `tid`：线程标识符
*   `time`：指当前日期和时间，采用 ISO-8601 格式
*   `timemillis`：当前时间（毫秒）
*   `timenanos`：当前时间（纳秒）
*   `uptime`：JVM 启动后的时间，以秒和毫秒为单位
*   `uptimemillis`：JVM 启动后的时间，以毫秒为单位
*   `uptimenanos`：JVM 启动后的时间，以纳秒为单位

装饰可以超越或包含在统一的日志输出中。无论使用哪种装饰，它们都将按以下顺序出现在输出中：

1.  `time`
2.  `uptime`
3.  `timemillis`
4.  `uptimemillis`
5.  `timenanos`
6.  `uptimenanos`
7.  `pid`
8.  `tid`
9.  `level`
10.  `tags`

# 级别

记录的消息单独与详细级别相关联。如前所述，级别为**错误**、**警告**、**信息**、**调试**、**跟踪**、**开发**。下表显示了这些级别相对于记录的信息量的详细程度是如何增加的。“开发级别”仅用于开发目的，在产品应用内部版本中不可用：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/bb99d707-4f7f-4c17-b548-d045c48c9e16.png)

日志消息的详细级别

# 使用 Xlog 输出

Java 日志框架支持三种类型的输出，包括直接使用`-Xlog`命令行语法的示例：

在下面的示例中，我们向`stderr`提供输出：

```java
-Xlog:all=warning:stderr:none
```

下面的示例向`stdout`提供输出：

```java
-Xlog:all=warning:stdout:none
```

以下示例将输出写入文本文件：

```java
-Xlog:all=warning:file=logmessages.txt:none
```

# 标签

新的日志框架由一组在 JVM 中标识的标记组成。如果需要，可以在源代码中更改这些标记。标签应该是自识别的，例如用于垃圾收集的`gc`。

当多个标记组合在一起时，它们形成一个标记集。当我们通过源代码添加自己的标记时，每个标记都应该与一个标记集相关联。这将有助于确保标签保持有序，并且易于人类阅读。

# 编译器控制

控制 **Java 虚拟机**（**JVM**）编译器似乎是一项不必要的任务，但对于许多开发人员来说，这是测试的一个重要方面。这是通过依赖于方法的编译器标志实现的。

在本节中，我们将从 JVM 编译模式开始，然后看看可以使用 Java 平台控制的编译器。

# 编译模式

现代 Java 平台的变化包括对 JVM 编译器的细粒度控制。如下图所示，Java HotSpot JVM 有两种 JIT 编译模式 **C1** 和 **C2**：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/99ad8a9a-c4a9-4cdb-8e8f-9f33a0a5c847.png)

Java HotSpot JVM 编译模式

**C1** 和 **C2** 编译模式使用不同的编译技术，如果在同一个代码基上使用，可以产生不同的机器代码集。

# C1 编译模式

Java HotSpot VM 中的 C1 编译模式通常用于具有以下特征的应用：

*   快速启动
*   增强优化
*   客户端

# C2 编译模式

第二种编译模式 C2 由具有下列特征的应用使用：

*   长运行时间
*   服务器端

# 分层编译

分层编译允许我们同时使用 **C1** 和 **C2** 编译模式。从 Java8 开始，分层编译是默认的过程。如图所示，启动时使用 **C1** 模式有助于提供更大的优化。然后，一旦 App 充分预热，则采用 **C2** 模式：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/b754514c-8f92-4362-a596-a2aae85512c2.png)

分层编译

# Java11 中的编译器控制

Java 承诺能够有限地控制 JVM 编译器并在运行时进行更改。这些额外的能力不会降低性能。这使得测试和测试优化更加逼真，因为我们可以运行小型编译器测试，而不必重新启动整个 JVM。

为了控制编译器操作，我们需要创建一个指令文件。这些文件包含由一组带有值的选项组成的编译器指令。指令文件基本上使用 JSON 的一个子集：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/c2346c5a-ead3-40d6-9132-354fe22d5c2c.png)

编译器指令结构

**JavaScript 对象表示法**（**JSON**）格式用于数据交换。指令文件与 JSON 有以下格式差异：

*   `int`和`doubles`是唯一支持的数字格式
*   双正斜杠（`//`）可用于注释行
*   尾随逗号（`,`）可用于数组和对象中
*   不支持转义字符
*   选项名的格式为字符串，不必加引号

您可以在[这个页面](http://www.json.org)了解更多关于 JSON 的信息。

我们可以在命令行中使用以下语法添加指令文件：

```java
-XX:CompilerDirectivesFile=<file>
```

以下是指令文件的 Shell 示例：

```java
[ // Open square bracket marks the start of the directives file

{ // Open curly brace marks the start of a directive block
  // A directives block that applies specifically to the C1 mode
  c1: {
        // directives go here
      },

  // A directives block that applies specifically to the C2 mode
  c2: {
        // directives go here
      },

  // Here we can put a directives that do not apply to
  // a specific compiler mode
},

{ // can have multiple directive blocks

  c1: {
        // directives go here
      }

  c2: {
        // directives go here
      }
}
] // Close square bracket marks the start of the directives file
```

# 诊断命令

在现代 Java 平台中添加了七个新的诊断命令，以增强诊断 JDK 和 JVM 的能力。

`print_codegenlist`命令打印当前排队等待编译的方法。由于 C1 和 C2 编译模式位于不同的队列上，因此需要向特定队列发出此命令。

`dump_codelist`诊断命令将打印编译方法的下列信息：

*   完整签名
*   地址范围
*   状态：
*   活着
*   非参与
*   僵尸

此外，`dump_codelist`诊断命令允许将输出定向到`stdout`或指定的文件。输出可以是 XML 格式或标准文本。

`print_codeblocks`命令允许我们打印以下内容：

*   代码缓存大小
*   代码缓存列表
*   代码缓存中的块列表
*   代码块地址

`datadump_request`诊断命令向 **Java 虚拟机工具接口**（**JVMTI**）发送转储请求。它取代了 **Java 虚拟机调试接口**（**JVMDI**）和 **Java 虚拟机评测接口**（**JVMPI**）。

使用`set_vmflag`命令，我们可以在 JVM 或库中设置命令行标志或选项。

`print_class_summary`诊断命令打印所有加载类的列表及其继承结构。

`print_utf8pool`命令打印所有 UTF-8 字符串常量。

# 堆性能分析代理

JVMTI `hprof`代理最近从 Java 平台上删除了。以下是与此更改相关的关键术语：

*   **工具接口**（**TI**）：这是一个本机编程接口，允许工具控制正在 Java 虚拟机内运行的应用的执行。该接口还允许状态查询。这个工具的完整术语是 Java 虚拟机工具接口，或 JVMTI。
*   **堆性能测试**（**HPROF**）：这是一个内部 JDK 工具，用于分析 JVM 对 cpu 和堆的使用。开发人员最常见的暴露是崩溃后生成的文件。生成的文件包含堆转储。

Java11JDK 不包含`hprof`代理。它被删除主要是因为有更好的替代品可用。以下是它们的相关功能表：

| **HPROF 功能** | **备选方案** |
| --- | --- |
| 分配探查器（堆=站点） | Java 可视化 |
| CPU 档案器（CPU=样本） | Java VisualVM |
| （CPU=次数） | Java 飞行记录器 |
| 堆转储（Heap=dump） | 内部 JVM 功能： |
| | `GC.heap_dump(icmd <pid> GC.heap_dump)` |
| | `jmap -dump` |

有趣的是，最初创建 HPROF 时，并不打算在生产中使用它。实际上，它只是为了测试 JVM 工具接口的代码。因此，随着现代 Java 平台的出现，HPROF 库（`libhprof.so`将不再是 JDK 的一部分。

# 移除 JHAT

**Java 堆分析工具**（**JHAT**）用于解析 Java 堆转储文件。此堆转储文件解析工具的语法如下：

```java
jhat
    [-stack <bool>]
    [-refs <bool>]
    [-port <port>]
    [-baseline <file>]
    [-debug <int>]
    [-version]
    [-h|-help]
   <file>
```

下面简要介绍与 JHAT 命令相关的选项：

| **选项** | **说明** | **默认值** |
| --- | --- | --- |
| `-J<flag>` | 这会将`<flag>`传递给运行时系统 | 不适用 |
| `-stack<bool>` | 这将切换对象分配调用栈的跟踪 | `true` |
| `-refs<bool>` | 这将切换对对象引用的跟踪 | `true` |
| `-port<port>` | 这表示 JHAT HTTP 服务器的端口 | `7000` |
| `-exclude<exclude-filename>` | 这将从可访问对象中排除指定的文件 | 不适用 |
| `-baseline<filename>` | 这将指定用于比较的基准堆转储 | 不适用 |
| `-debug<int>` | 这将设置输出的详细程度 | 不适用 |
| `-version ` | 这只是输出 JHAT 版本号 | 不适用 |
| `-h` `-help` | 这将提供帮助文本 | 不适用 |

JHAT 从 JDK-6 开始就以实验的形式成为 Java 平台的一部分。它不受支持，被认为是过时的。从 Java9 开始，这个工具不再是 JDK 的一部分。

# 命令行标志参数验证

在本章中，您已经了解了 Java 平台中命令行标志的许多用法。一致努力确保所有带参数的 JVM 命令行标志都得到验证。这项工作的主要目标是：

*   避免 JVM 崩溃
*   提供错误消息来告诉你无效的标志参数

从下图中可以看到，没有尝试自动更正标志参数错误；相反，只是为了识别错误并防止 JVM 崩溃：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/128fb567-a118-407d-a9f1-51813cee37f3.png)

标志参数错误

这里提供了一个示例错误消息，指出标志参数超出范围。此错误将在 JVM 初始化期间执行的标志参数范围检查期间显示：

```java
exampleFlag UnguardOnExecutionViolation = 4 is outside the allowed range [0 . . . 3]
```

以下是一些有关 Java 平台更改的细节：

*   展开当前的`globals.hpp`源文件，以确保完整的标志默认值和允许的范围被记录
*   定义一个框架以支持将来添加新的 JVM 命令行标志：
*   这将包括值范围和值集
*   这将确保有效性检查将应用于所有新添加的命令行标志

*   修改宏表：
*   为可选范围添加最小值/最大值
*   为以下项添加约束项：
    *   确保每次标记更改时都执行约束检查
    *   当 JVM 运行时，将继续检查所有可管理的标志

# 为旧平台版本编译

Java 编译器`javac`在 Java9 中进行了更新，以确保它可以用来编译 Java 程序，以便在用户选择的旧版本 Java 平台上运行。在下面的截图中可以看到，`javac`有几个选项，包括`-source`和`-target`。以下截图中显示的`javac`来自 Java8：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/f4dc0735-e351-4d4d-aa78-0197bb1de867.png)

Java8 中的 Javac 选项

`-source`选项用于指定编译器接受的 Java 版本。`-target`选项通知您将生成哪个版本的类文件`javac`。默认情况下，`javac`生成最新 Java 版本和平台 API 版本的类文件。当编译的应用使用仅在最新平台版本中可用的 API 时，这可能会导致问题。这将导致应用无法在较旧的平台版本上运行，尽管使用了`-source`和`-target`选项。

为了解决上述问题，Java 中提供了一个新的命令行选项，这个选项是`--release`选项，当使用这个选项时，会自动配置`javac`来生成与特定平台版本相链接的类文件。下面的屏幕截图显示了当前 Java 平台的`javac`选项。如您所见，新的`--release`选项包括：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/69faeaf0-a366-4c5f-809d-1ae6a3b244fe.png)

Java18.9 中的 Javac 选项

以下是新选项的语法：

```java
javac --release <release> <source files>
```

# 基于 Java 的实验性 JIT 编译器

在 Java10 中启用了基于 Java 的即时（**JIT**）编译器，可以作为 Linux/x64 平台的实验性 JIT 编译器。基于 Java 的 JIT 编译器被称为 Graal

做出这一更改的目的是希望通过实验可以证明将 JIT 编译器添加到 JDK 中的概念

# 总结

在本章中，我们探讨了现代 Java 平台的一些变化，这些变化的共同主题是命令行标志。具体来说，我们讨论了统一 JVM 日志记录、编译器控制、新的诊断命令、HPROF 堆分析代理的删除、JHAT 的删除、命令行标志参数验证，以及针对旧平台版本进行编译的能力。

在下一章中，我们将重点介绍 Java 中提供的附加工具的最佳实践。其中包括 UTF-8、Unicode 7.0、Linux 等等。

# 问题

1.  Java9 中引入的 JVM 日志记录模式是什么？
2.  日志记录的五个类别是什么？
3.  什么是装饰？
4.  日志中的详细程度是多少？
5.  哪一个详细级别是最高的？
6.  哪种详细程度最低？
7.  如何更改日志标记？

8.  什么用于控制 JVM？
9.  Java HotSpot JVM 的 JIT 编译模式是什么？
10.  哪种编译模式具有快速启动功能？

# 进一步阅读

以下是您可以参考的信息列表：

*   《Java SE 9 整洁代码入门》【视频】在[这个页面](https://www.packtpub.com/application-development/getting-started-clean-code-java-se-9-video)提供。

# 十五、Java 平台的其他增强功能

在最后一章中，我们探讨了 Java 中命令行标志的一些变化，具体包括统一 JVM 日志记录、编译器控制、新的诊断命令、删除 HPROF 堆分析代理、删除 **Java 堆分析工具**（**JHAT**），命令行标志参数验证，以及为旧平台版本编译的能力。

在本章中，我们将重点介绍 Java 平台提供的附加工具的最佳实践。具体来说，我们将讨论以下主题：

*   支持 UTF-8
*   Unicode 支持
*   Linux/AArch64 端口
*   多分辨率图像
*   **公共场所数据库**（**CDLR**）

# 技术要求

本章及后续章节主要介绍 Java11，Java 平台的**标准版**（**SE**）可从 [Oracle 官方下载网站](http://www.oracle.com/technetwork/java/javase/downloads/index.html)下载。

IDE 包就足够了。来自 JetBrains 的 IntelliJ IDEA 用于与本章和后续章节相关的所有编码。IntelliJ IDEA 的社区版可从[网站](https://www.jetbrains.com/idea/features/)下载。

# UTF-8 支持 

**Unicode 转换格式 8**（**UTF-8**）是一个字符集，它封装了所有 Unicode 字符，使用一到四个 8 位字节。UTF-8 是面向字节的 Unicode 编码格式，自 2009 年以来一直是网页编码的主要字符集。

以下是 UTF-8 的一些特点：

*   它可以对所有 1112064 个 Unicode 代码点进行编码
*   它使用 1 到 4 个 8 位字节
*   它几乎占所有网页的 90%
*   它与 ASCII 向后兼容
*   它是可逆的

UTF-8 的广泛使用强调了确保 Java 平台完全支持 UTF-8 的重要性。对于 Java 应用，我们能够指定具有 UTF-8 编码的属性文件。Java 平台包括对`ResourceBundle`API 的更改，以支持 UTF-8。

让我们看一看前现代 Java（Java8 和更早版本）`ResourceBundle`类，然后看看在现代 Java 平台上对这个类做了哪些更改。

# `ResourceBundle`类

下面的类为开发人员提供了从资源包中隔离特定于语言环境的资源的能力。这个类大大简化了本地化和翻译：

```java
public abstract class ResourceBundle extends Object
```

创建资源包需要有目的的方法。例如，假设我们正在创建一个资源包，它将为业务应用支持多种语言。我们的按钮标签，除其他外，将显示不同的根据当前地区。因此，在我们的示例中，我们可以为按钮创建一个资源包，我们可以称之为`buttonResources`。然后，对于每个区域设置，我们可以创建`buttonResource_<identifier>`。以下是一些示例：

*   `buttonResource_ja:`日语
*   `buttonResource_uk:`英国英语
*   `buttonResource_it:`意大利语
*   `buttonResource_lh:`立陶宛语

我们可以使用与缺省包的基名称相同的资源包，因此，`buttonResource`将包含缺省包。

为了获得特定于语言环境的对象，我们调用了`getBundle`方法。例如：

```java
. . .
ResourceBundle = buttonResource = 
  ResourceBundle.getBundle("buttonResource", currentLocale);
. . .
```

在下一节中，我们将通过查看其嵌套类、字段和构造器以及包含的方法来检查`ResourceBundle`类。

# 嵌套类

有一个嵌套类与`ResourceBundle`类相关联，即`ResourceBundle.Control`类。提供使用`ResourceBundle.getBundle`方法时使用的回调方法，如下图：

```java
public static class ResourceBundle.Control extends Object
```

`ResourceBundle.Control`类有以下字段：

*   `public static final List<String> FORMAT_CLASS`
*   `public static final List<String> FORMAT_DEFAULT`
*   `public static final List<String> FORMAT_PROPERTIES`
*   `public static final long TTL_DONT_CACHE`
*   `public static final long TTL_NO_EXPIRATION_CONTROL`

该类有一个空构造器和以下方法：

*   `getCandidateLocales()`：

```java
public List<Locale> getCandidateLocales(String baseName, Locale locale)
```

我们来看看`getCandidateLocales()`方法的细节：

| **组件** | **明细** |
| --- | --- |
| **抛出** | `NullPointerException`（如果`baseName`或`locale`为空） |
| **参数** | `baseName`：完全限定类名 | 
| | `locale`：期望的`locale` |
| **返回** | 候选区域设置列表 |

*   `getControl()`：

```java
public static final ResourceBundle.Control getControl(List<String> formats)
```

我们来看看`getControl()`方法的细节：

| **组件** | **明细** |
| --- | --- |
| **抛出** | `IllegalArgumentException`（如果`formats`未知） |
| | `NullPointerException`（如果`formats`为空）  |
| **参数** | `formats`：这些是`ResourceBundle.Control.getFormats`方法返回的格式 |
| **返回** | 支持指定格式的`ResourceBundle.Control` |

*   `getFallbackLocale()`：

```java
public Locale getFallbackLocale(String baseName, Locale locale)
```

我们来看看`getFallbackLocale()`方法的细节：

| **组件** | **明细** |
| --- | --- |
| **抛出** | `NullPointerException`（如果`baseName`或`locale`为空） |
| **参数** | `baseName`：完全限定类名 |
| | `locale`：`ResourceBundle.getBundle`方法找不到的期望的`locale` |
| **返回** | 后备`locale` |

*   `getFormats()`：

```java
public List<String> getFormats(String baseName)
```

我们来看看`getFormats()`方法的细节：

| **组件** | **明细** |
| --- | --- |
| **抛出** | `NullPointerException`（如果`baseName`为空） |
| **参数** | `baseName`：完全限定类名 |
| **返回** | 字符串列表及其格式，以便可以加载资源包 |

*   `getNoFallbackControl()`：

```java
public static final ResourceBundle.Control getNoFallbackControl(List<String> formats)
```

我们来看看`getNoFallbackControl()`方法的细节：

| **组件** | **明细** |
| --- | --- |
| **抛出** |  `IllegalArgumentException`（如果`formats`未知） |
| | `NullPointerException`（如果`formats`为空） |
| **参数** | `formats`：这些是`ResourceBundle.Control.getFormats`方法返回的格式 |
| **返回** | 支持指定的格式的`ResourceBundle.Control`，没有后备`locale`。 |

*   `getTimeToLive()`：

```java
public long getTimeToLive(String baseName, Locale locale)
```

我们来看看`getTimeToLive()`方法的细节：

| **组件** | **明细** |
| --- | --- |
| **抛出** | `NullPointerException`（如果`baseName`为空） |
| **参数** | `baseName`：完全限定的类名 |
| | `locale`：时间`locale` |
| **返回** | 距离缓存时间的偏移，零或正毫秒 |

*   `needsReload()`：

```java
public boolean needsReload(String baseName, Locale locale, String format, ClassLoader loader, ResourceBundle bundle, long loadTime)
```

我们来看看`needsReload()`方法的细节：

| **组件** | **明细** |
| --- | --- |
| **抛出** | `NullPointerException`（如果下列任何参数为空）： |
| | `baseName` |
| | `locale` |
| | `format` |
| | `loader` |
| | `bundle` |
| **参数** | `baseName`：完全限定类名 |
| | `locale`：期望的`locale` |
| | `format`：资源包格式 |
| | `loader`：用于加载包的`ClassLoader` |
| | `bundle`：过期包 |
| | `ClassLoader loadTime`：包被添加到缓存中的时间 |
| **返回** | `true`/`false`表示到期包是否需要重新加载 |

*   `newBundle()`：

```java
public ResourceBundle newBundle(String baseName, Locale locale, String format, ClassLoader loader, boolean reload)
```

我们来看看`newBundle()`方法的细节：

| **组件** | **明细** |
| --- | --- |
| **抛出** | `ClassCastException`（如果被加载类不能转换为`ResourceBundle`） |
| | `ExceptionInInitializerError`（如果初始化失败） |
| | `IllegalAccessException`（如果构造器不可访问） |
| | `IllegalArgumentException`（如果格式未知） |
| | `InstantiationException`（如果类实例化失败） |
| | `IOException`（资源读取错误） |
| | `NullPointerException`（如下列参数空）： |
| | `baseName`、`locale`、`format` |
| | `SecurityException`（如拒绝访问实例） |
| **参数** | 
| | `baseName`：完全限定类名 |
| | `locale`：所需的语言环境 |
| | `format`：资源包格式 |
| | `loader`：用于加载包的`ClassLoader` |
| | `reload`：`true`/`false`标志、指示资源包是否已过期 |
| **返回** | 资源包的实例 |

*   `toBundleName()`：

```java
public String toBundleName(String baseName, Locale locale)
```

我们来看看`toBundleName()`方法的细节：

| **组件** | **明细** |
| --- | --- |
| **抛出** | `NullPointerException`（如果`baseName`或`locale`为空） |
| **参数** | `baseName`：完全限定类名 |
| | `locale`：期望的`locale` |
| **返回** | 资源包名称 |

*   `toResourceName()`：

```java
public final String toResourceName(String bundleName, String suffix)
```

我们来看看`toResourceName()`方法的细节：

| **组件** | **明细** |
| --- | --- |
| **抛出** | `NullPointerException`（如果`bundleName`或`suffix`为空） |
| **参数** | `bundleName`：包名称 |
| | `suffix`：文件名后缀 |
| **返回** | 转换后的资源名称 |

# 字段和构造器

`ResourceBundle`类有一个字段，如下所述：

```java
protected Resourcebundle parent
```

当找不到指定的资源时，通过`getObject`方法搜索父包。

`ResourceBundle`类的构造器如下：

```java
public ResourceBundle() {
}
```

# 方法

`ResourceBundle`类有 18 个方法，这里分别描述：

*   `clearCache()`：

```java
public static final void clearCache()
```

从下表可以看出，`clearCache()`方法不抛出任何异常，不接受任何参数，也没有返回值：

| **组件** | **明细** |
| --- | --- |
| **抛出** | 没有 |
| **参数** | 没有 |
| **返回** | 没有 |

以下是以`ClassLoader`为参数的`clearCache()`方法的一个版本：

```java
public static final void clearCache(ClassLoader loader)
```

以下是以`ClassLoader`为参数的`clearCache()`方法版本的详细信息：

| **组件** | **明细** |
| --- | --- |
| **抛出** | `NullPointerException`（如果`loader`为空） |
| **参数** | `loader`：类的`loader` |
| **返回** | 没有 |

*   `containsKey()`：

```java
public boolean containsKey(String key)
```

我们来看看`containsKey()`方法的细节：

| **组件** | **明细** |
| --- | --- |
| **抛出** | `NullPointerException`（如果`key`为空） |
| **参数** | `key`：资源`key` |
| **返回** | `true`/`false`取决于`key`是在`ResourceBundle`还是在父束中 |

*   `getBundle()`：

```java
public static final ResourceBundle getBundle(String baseName)
```

我们来看看第一版`getBundle()`方法的细节：

| **组件** | **明细** |
| --- | --- |
| **抛出** | `MissingResourceException` |
| | `NullPointerException`（如果`baseName`为空）
| **参数** | `baseName`：完全限定类名 |
| **返回** | 基于给定`baseName`和默认`locale`的资源包 |

以下是第二版`getBundle()`方法的语法：

```java
public static final ResourceBundle getBundle(String baseName, Resourcebundle.Control control)
```

我们来看看第二版`getBundle()`方法的细节：

| **组件** | **明细** |
| --- | --- |
| **抛出** | `IllegalArgumentException`（如果传递的`control`执行不当） |
| | `MissingResourceException`（如果所提供的`baseName`的资源包找不到） |
| | `NullPointerException`（如果`baseName`为空） |
| **参数** | `baseName`：完全限定类名 |
| | `control`：提供信息、以便加载`resource`包 |
| **返回** | 基于给定`baseName`和默认`locale`的资源包 |

以下是第三版`getBundle()`方法的语法：

```java
public static final ResourceBundle getBundle(String baseName, Locale locale)
```

我们来看看第三版`getBundle()`方法的细节：

| **组件** | **明细** |
| --- | --- |
| **抛出** | `MissingResourceException` |
| | `NullPointerException`（如或`baseName`或`locale`为空） |
| **参数** | `baseName`：完全限定类名 |
| | `locale`：期望的`locale` |
| **返回** | 基于给定的`baseName`和`locale`的资源包 |

以下是第四版`getBundle()`方法的语法：

```java
public static final ResourceBundle getBundle(String baseName, Locale targetLocale, Resourcebundle.Control control)
```

我们来看看第四版`getBundle()`方法的细节：

| **组件** | **明细** |
| --- | --- |
| **抛出** | `IllegalArgumentException`（如果传递的`control`执行不当） |
| | `MissingResourceException`（如果所提供的`baseName`的资源包找不到） |
| | `NullPointerException`（如果`baseName`、`control`或`locale`为空） |
| **参数** | `baseName`：完全限定类名 |
| | `control`：提供信息、以便加载`resource`包 |
| | `targetLocale`：期望的`locale` |
| **返回** | 基于给定的`baseName`和`locale`的资源包 | |

以下是第五版`getBundle()`方法的语法：

```java
public static final ResourceBundle getBundle(String baseName, Locale locale, ClassLoader loader)
```

我们来看看第五版`getBundle()`方法的细节：

| **组件** | **明细** |
| --- | --- |
| **抛出** | `MissingResourceException`（如果所提供的`baseName`的资源包找不到） |
| | `NullPointerException`（如果`baseName`、`control`或`locale`为空） |
| **参数** | `baseName`：完全限定类名 |
| | `locale`：期望的`locale` |
| | `loader`：类的`loader` |
| **返回** | 基于给定的`baseName`和`locale`的资源包 |

以下是第六版`getBundle()`方法的语法：

```java
public static final ResourceBundle getBundle(String baseName, Locale targetLocale, ClassLoader loader, ResourceBundle.Control control)
```

我们来看看第六版`getBundle()`方法的细节：

| **组件** | **明细** |
| --- | --- |
| **抛出** | `IllegalArgumentException`（如果传递的`control`执行不当） |
| | `MissingResourceException`（如果所提供的`baseName`的资源包找不到） |
| | `NullPointerException`（如果`baseName`、`control`或`locale`为空） |
| **参数** | `baseName`：完全限定类名 |
| | `control`：提供信息、以便加载`resource`包 |
| | `locale`：期望的`locale` |
| | `loader`：类的`loader` |
| **返回** | 基于给定的`baseName`和`locale`的资源包 |

*   `getKeys()`：

```java
public abstract Enumeration<String> getKeys()
```

我们来看看`Enumeration()`方法的细节：

| **组件** | **明细** |
| --- | --- |
| **抛出** | 没有 |
| **参数** | 没有 |
| **返回** | `ResourceBundle`和父包中的键的枚举 |

*   `getLocale()`：

```java
public Locale getLocale()
```

我们来看看`getLocale()`方法的细节：

| **组件** | **明细** |
| --- | --- |
| **抛出** | 没有 |
| **参数** | 没有 |
| **返回** | 当前资源包的`locale` |

*   `getObject()`：

```java
public final Object getObject(String key)
```

我们来看看`getObject()`方法的细节：

| **组件** | **明细** |
| --- | --- |
| **抛出** | `MissingResourceException`（如果所提供的`baseName`的资源包找不到） |
| | `NullPointerException`（如果`baseName`、`control`或`locale`为空） |
| **参数** | `key`：这是所需对象的`key` |
| **返回** | 提供`key`的对象 |

*   `getString()`：

```java
public final String getString(String key)
```

我们来看看`getString()`方法的细节：

| **组件** | **明细** |
| --- | --- |
| **抛出** | `ClassCastException`（如果被加载类不能转换为`ResourceBundle`） |
| | `MissingResourceException`（如果所提供的`baseName`的资源包找不到） |
| | `NullPointerException`（如果`baseName`、`control`或`locale`为空） |
| **参数** | `key`：这是所需`String`的关键 |
| **返回** | `String`提供的键 |

*   `getStringArray()`：

```java
public final String[] getStringArray(String key)
```

我们来看看`getStringArray()`方法的细节：

| **组件** | **明细** |
| --- | --- |
| **抛出** | `IllegalArgumentException`（如果传递的`control`执行不当） |
| | `MissingResourceException`（如果所提供的`baseName`的资源包找不到） |
| | `NullPointerException`（如果`baseName`、`control`或`locale`为空） |
| **参数** | `key`：这是所需`String`数组的`key` |
| **返回** | 为`key`提供`String`数组 |

*   `handleGetObject()`：

```java
protected abstract Object handleGetObject(String key)
```

我们来看看`handleGetObject()`方法的细节：

| **组件** | **明细** |
| --- | --- |
| **抛出** | `NullPointerException`（如果`key`为空） |
| **参数** | `key`：`key`表示所需的`Object` |
| **返回** | 给定`key`的对象 |

*   `handleKeySet()`：

```java
protected Set<String> handleKeySet()
```

我们来看看`handleKeySet()`方法的细节：

| **组件** | **明细** |
| --- | --- |
| **抛出** | 没有 |
| **参数** | 没有 |
| **返回** | `ResourceBundle`中的一组键 |

*   `keySet()`：

```java
public Set<String> keySet()
```

我们来看看`keySet()`方法的细节：

| **组件** | **明细** |
| --- | --- |
| **抛出** | 没有 |
| **参数** | 没有 |
| **返回** | `ResourceBundle`及其`parent`包中的一组键 |

*   `setParent()`：

```java
protected void setParent(ResourceBundle parent)
```

我们来看看`setParent()`方法的细节：

| **组件** | **明细** |
| --- | --- |
| **抛出** | 没有 |
| **参数** | `parent`：当前捆绑的`parent`捆绑 |
| **返回** | 没有 |

# 现代 Java 平台的变化

Java 平台以前支持基于 ISO-8859-1 的属性文件格式。这种格式不容易支持转义字符，尽管它提供了适当的转义机制。使用 ISO-8859-1 需要在文本字符与其转义形式之间进行转换。

当前的 Java 平台包括一个修改过的`ResourceBundle`类，其默认文件编码设置为 UTF-8，而不是 ISO-8859-1。这节省了应用进行上述转义机制转换所需的时间。

# Unicode 支持

随着 Unicode 规范的更新，Java 平台也随之更新。Java8 支持 Unicode 6.2，Java9 支持 Unicode 7.0，Java11 支持 Unicode 10.0.0，于 2017 年 6 月 20 日发布。

有关 Unicode 版本 10.0.0 的更多信息，[请访问官方规范页面](http://unicode.org/versions/Unicode10.0.0/)。

Java 平台尚未实现以下 Unicode 标准：

*   **Unicode 技术标准 #10**（**UTS#10**）：**Unicode 排序算法详细说明了如何比较 Unicode 字符串**
*   **Unicode 技术标准 #39**（**UTS#39**）：Unicode 安全机制   
*   **Unicode 技术标准 #46**（**UTS#46**）：Unicode 应用中的国际化域名（**IDNA**）——允许应用使用 ASCII 字符串标签来表示非 ASCII 标签
*   **Unicode 技术标准 #51**（**UTS#51**）：Unicode 表情符号

特定于 Unicode 支持的核心 Java 平台更改包括以下 Java 类：

*   `java.lang`包包括以下内容：
    *   `Character`
    *   `String`

*   `java.text`包包括以下内容：
    *   `Bidi`
    *   `BreakIterator`
    *   `Normalizer`

让我们快速看一下这些类中的每一个，以帮助巩固我们对 Unicode 10.0.0 在 Java 平台上的广泛影响的理解。

# `java.lang`包

`java.lang`包提供了几乎所有 Java 应用中使用的基本类。在本节中，我们将介绍`Character`和`String`类。

这是`Character`类：

```java
public final class Character extends Object implements 
  Serializable, Comparable<Character>
```

这是自 Java 第一个版本以来出现的众多核心类之一。`Character`类的对象由一个类型为`char`的字段组成。

这是`String`类：

```java
public final class String extends Object implements 
  Serializable, Comparable<String>, CharSequence
```

字符串（字符串是另一个核心原始类）是不可变的字符串。

修改`Character`和`String`类以支持更新的 Unicode 版本，即用于 Java9 和更高版本的版本 7.0，这是帮助保持 Java 作为首要编程语言的相关性的一个重要步骤。

# `java.text`包

`Bidi`、`BreakIterator`和`Normalizer`类的应用不如`Character`和`String`类广泛。以下是这些类的简要概述：

这是`Bidi`类：

```java
public final class Bidi extends Object
```

此类用于实现 Unicode 的双向算法。用于支持阿拉伯语或希伯来语。

有关 *UNICODE 双向算法*的具体信息，请访问[这个页面](http://unicode.org/reports/tr9/)。

`BreakIterator`类用于查找文本边界：

```java
public abstract class BreakIterator extends Object implements Cloneable
```

这是`Normalizer`类：

```java
public final class Normalizer extends Object
```

此类包含两个方法：

*   `isNormalized`：用于确定给定序列的`char`值是否归一化
*   `normalize`：规范化`char`值的序列

# 额外重要事项

如前所述，JDK8 支持 Unicode 6.2。6.3 版于 2013 年 9 月 30 日发布，主要内容如下：

*   双向行为改进
*   改进的 Unihan 数据
*   更好地支持希伯来语

2014 年 6 月 16 日发布的 7.0.0 版引入了以下更改：

*   添加了 2834 个字符
    *   增加对阿塞拜疆语、俄语和高级德语方言的支持
    *   象形符号
    *   多个国家和地区的历史脚本
*   Unicode 双向算法的更新。
*   新增粤语发音词条近 3000 条。
*   Indic 脚本属性的主要增强。

Unicode 在 6.3 和 7.0.0 版本中的巨大变化强调了当前支持 7.0.0 的 Java 平台的重要性，而不是像 Java8 那样支持 6.3。

# Linux/AArch64 端口

从 JDK9 开始，JDK 已经被移植到 Linux/AArch64。为了理解这对我们 Java 开发人员意味着什么，让我们来讨论一下硬件。

ARM 是一家英国公司，30 多年来一直在开发计算核心和架构。他们的原名是 Acorn RISC Machine，**RISC** 代表**精简指令集计算机**。在此过程中，公司更名为**高级 RISC 机器**（**ARM**），最后更名为 **ARM Holdings**，或者干脆更名为 **ARM**。它将其架构授权给其他公司。ARM 报告说，已经制造了超过 1000 亿个 ARM 处理器。

2011 年末，ARM 推出了一个新的 ARM 架构，名为 **ARMv8**。这个架构包括一个名为 **AArch64** 的 64 位可选架构，正如您所料，它附带了一个新的指令集。以下是 AArch64 功能的简要列表：

*   A64 指令集：
    *   31 个通用 64 位寄存器
    *   专用零或栈指针寄存器
    *   接受 32 位或 64 位参数的能力
*   高级 SIMD（NEON）-增强：
    *   32 x 128 位寄存器
    *   支持双精度浮点
    *   AES 加密/解密和 SHA-1/SHA-2 哈希
*   新的异常系统

Oracle 在确定这种架构是现代 Java 平台需要支持的方面做了大量的工作。据说新的 AArch64 架构本质上是一种全新的设计。JDK9、10 和 11 已通过以下实现成功移植到 Linux/AArch64：

*   模板解释器
*   C1 JIT 编译器
*   C2 JIT 编译器

有关 C1 和 C2 JIT 编译器的信息，请参阅第 14 章“命令行标志”。

# 多分辨率图像

Java11 包含一个支持多分辨率图像的 API。具体来说，它允许多分辨率图像封装同一图像的多个分辨率变体。此 API 位于`java.awt.image`包中。下图显示了多分辨率如何将一组具有不同分辨率的图像封装到单个图像中：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/95510b0a-ae51-4b9a-95e4-ef3ab542753a.png)

多图像分辨率封装

这个新的 API 将使开发人员能够检索所有图像变体或检索特定分辨率的图像。这是一套强大的功能。`java.awt.Graphics`类用于从多分辨率图像中检索所需的变量

下面简要介绍一下 API：

```java
package java.awt.image;

public interface MultiResolutionImage {
  Image getResolutionVariant(float destinationImageWidth, 
    float destinationImageHeight);

  public List <Image> getResolutionVariants();
}
```

从前面的代码示例中可以看到，API 包含分别返回图像和图像列表的`getResolutionVariant`和`getResolutionVariants`。因为`MultiResolutionImage`是一个接口，所以我们需要一个抽象类来实现它。

# 通用区域数据仓库

默认情况下，Java11 实现了使用 Unicode 公共语言环境数据存储库中的语言环境数据的决策。CLDR 是许多支持多种语言的软件应用的关键组件，它被吹捧为最大的语言环境数据存储库，被众多大型软件供应商使用，包括苹果、谷歌、IBM 和微软。CLDR 的广泛使用使其成为非官方的行业标准语言环境数据存储库。使其成为当前 Java 平台中的默认存储库进一步巩固了其作为软件行业标准的地位。

有趣的是，CLDR 已经是 JDK8 的一部分，但不是默认库。在 Java8 中，我们必须通过设置系统属性来启用 CLDR，如下所示：

```java
java.locale.providers=JRE,CLDR
```

现在，在 Java 中，我们不再需要启用 CLDR，因为它将是默认的存储库

在当前的 Java 平台中还有其他语言环境数据存储库。它们按默认的查找顺序列在此处：

*   CLDR
*   COMPAT（以前叫 JRE）
*   **服务提供商接口**（**SPI**）

要更改查找顺序，我们可以更改`java.locale.providers`设置，如图所示：

```java
java.locale.providers=SPI,COMPAT,CLDR
```

在上例中，`SPI`将首先，然后是`COMPAT`，然后是`CLDR`。

# 总结

在本章中，我们将重点介绍当前 Java 平台提供的附加工具的最佳实践。具体来说，我们介绍了 UTF-8 属性文件、Unicode 7.0.0、Linux/AArch64 端口、多分辨率图像和公共语言环境数据存储库。

在下一章中，我们将通过展望 Java19.3（Java12）和 Java19.9（Java13）中的内容来展望 Java 平台的未来方向。

# 问题

1.  什么是 UTF-8？
2.  列出 UTF-8 的五个特性。
3.  哪个类为开发人员提供了从资源包中隔离特定于语言环境的资源的能力？
4.  `clearCache()`方法返回什么？
5.  `getBundle()`方法返回什么？
6.  Java11 支持什么版本的 Unicode？
7.  JDK9、10 和 11 已经成功移植到 Linux/AArch64。列出三种实现。
8.  什么是多分辨率图像？
9.  哪个类用于从多分辨率图像中检索所需的变体？
10.  什么是 CLDR？