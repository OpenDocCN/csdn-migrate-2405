# Java 代码面试完全指南（七）

> 原文：[`zh.annas-archive.org/md5/2AD78A4D85DC7F13AC021B920EE60C36`](https://zh.annas-archive.org/md5/2AD78A4D85DC7F13AC021B920EE60C36)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四部分：奖励 - 并发和函数式编程

公司非常关注并发和函数式编程等主题。本章涵盖了围绕这两个主题的最流行的问题。这四章是奖励章节；其方法与迄今为止阅读的章节不同。由于这些主题的性质，我们将简要涉及它们，并详细阐述在相应主题的面试中提出的问题。您可以在本章的技术要求部分找到在 GitHub 存储库中使用的代码链接。

本节包括以下章节：

+   第十六章，并发

+   第十七章，函数式编程风格

+   第十八章，单元测试

+   第十九章，系统可扩展性


# 第十六章：并发

开发单线程的 Java 应用程序很少可行。因此，大多数项目将是多线程的（即它们将在多线程环境中运行）。这意味着，迟早，您将不得不解决某些多线程问题。换句话说，您将不得不动手编写直接或通过专用 API 操纵 Java 线程的代码。

本章涵盖了关于 Java 并发（多线程）的最常见问题，这些问题在关于 Java 语言的一般面试中经常出现。和往常一样，我们将从简要介绍开始，介绍 Java 并发的主要方面。因此，我们的议程很简单，涵盖以下主题：

+   Java 并发（多线程）简介

+   问题和编码挑战

让我们从我们的主题 Java 并发的基本知识开始。使用以下简介部分提取一些关于并发的基本问题的答案，比如*什么是并发？*，*什么是 Java 线程？*，*什么是多线程？*等。

# 技术要求

本章中使用的代码可以在 GitHub 上找到：[`github.com/PacktPublishing/The-Complete-Coding-Interview-Guide-in-Java/tree/master/Chapter16`](https://github.com/PacktPublishing/The-Complete-Coding-Interview-Guide-in-Java/tree/master/Chapter16)

# Java 并发（多线程）简介

我们的计算机可以同时运行多个*程序*或*应用程序*（例如，我们可以同时在媒体播放器上听音乐并浏览互联网）。*进程*是程序或应用程序的执行实例（例如，通过在计算机上双击 NetBeans 图标，您启动将运行 NetBeans 程序的进程）。此外，*线程*是*轻量级子进程*，表示进程的最小可执行工作单元。Java 线程的开销相对较低，并且它与其他线程共享公共内存空间。一个进程可以有多个线程，其中一个是*主线程*。

重要说明

进程和线程之间的主要区别在于线程共享公共内存空间，而进程不共享。通过共享内存，线程减少了大量开销。

*并发*是应用程序处理其工作的多个任务的能力。程序或应用程序可以一次处理一个任务（*顺序处理*）或同时处理多个任务（*并发处理*）。

不要将并发与*并行*混淆。*并行*是应用程序处理每个单独任务的能力。应用程序可以串行处理每个任务，也可以将任务分割成可以并行处理的子任务。

重要说明

并发是关于**处理**（而不是执行）多个事情，而并行是关于**执行**多个事情。

通过*多线程*实现并发。*多线程*是一种技术，使程序或应用程序能够同时处理多个任务，并同步这些任务。这意味着多线程允许通过在同一时间执行两个或更多任务来最大程度地利用 CPU。我们在这里说*在同一时间*是因为这些任务看起来像是同时运行；然而，实质上，它们不能这样做。它们利用操作系统的 CPU *上下文切换*或*时间片*功能。换句话说，CPU 时间被所有运行的任务共享，并且每个任务被安排在一定时间内运行。因此，多线程是*多任务处理*的关键。

重要说明

在单核 CPU 上，我们可以实现并发但*不是*并行。

总之，线程可以产生多任务的错觉；然而，在任何给定的时间点，CPU 只执行一个线程。CPU 在线程之间快速切换控制，从而产生任务并行执行（或推进）的错觉。实际上，它们是并发执行的。然而，随着硬件技术的进步，现在普遍拥有多核机器和计算机。这意味着应用程序可以利用这些架构，并且每个线程都有一个专用的 CPU 在运行。

以下图表通过四个线程（**T1**、**T2**、**T3**和**T4**）澄清了并发和并行之间的混淆：

16.1-并发与并行

](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_16.1_B15403.jpg)

16.1-并发与并行

因此，一个应用程序可以是以下之一：

+   并发但不是并行：它同时执行多个任务，但没有两个任务同时执行。

+   并行但不是并发：它在多核 CPU 中同时执行一个任务的多个子任务。

+   既不是并行也不是并发：它一次执行所有任务（顺序执行）。

+   并行和并发：它在多核 CPU 中同时并发执行多个任务。

被分配执行任务的一组同质工作线程称为*线程池*。完成任务的工作线程将返回到池中。通常，线程池绑定到任务队列，并且可以调整到它们持有的线程的大小。通常情况下，为了获得最佳性能，线程池的大小应等于 CPU 核心的数量。

在多线程环境中*同步*是通过*锁定*实现的。锁定用于在多线程环境中协调和限制对资源的访问。

如果多个线程可以访问相同的资源而不会导致错误或不可预测的行为/结果，那么我们处于*线程安全的上下文*。可以通过各种同步技术（例如 Java `synchronized`关键字）实现*线程安全*。

接下来，让我们解决一些关于 Java 并发的问题和编码挑战。

# 问题和编码挑战

在本节中，我们将涵盖 20 个关于并发的问题和编码挑战，这在面试中非常流行。

您应该知道，Java 并发是一个广泛而复杂的主题，任何 Java 开发人员都需要详细了解。对 Java 并发的基本见解应该足以通过一般的 Java 语言面试，但对于特定的面试来说还不够（例如，如果您申请一个将涉及开发并发 API 的工作，那么您必须深入研究这个主题并学习高级概念-很可能，面试将以并发为中心）。

## 编码挑战 1-线程生命周期状态

`线程`。

`Thread.State`枚举。Java 线程的可能状态可以在以下图表中看到：

![16.2-Java 线程状态](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_16.2_B15403.jpg)

16.2-Java 线程状态

Java `Thread`的不同生命周期状态如下：

+   `NEW` `Thread#start()`方法被调用）。

+   `RUNNABLE` `Thread#start()`方法，线程从`NEW`到`RUNNABLE`。在`RUNNABLE`状态下，线程可以运行或准备运行。等待**JVM**（Java 虚拟机）线程调度程序分配必要的资源和时间来运行的线程是准备运行的，但尚未运行。一旦 CPU 可用，线程调度程序将运行线程。

+   `BLOCKED` `BLOCKED`状态。例如，如果一个线程*t1*试图进入另一个线程*t2*已经访问的同步代码块（例如，标记为`synchronized`的代码块），那么*t1*将被保持在`BLOCKED`状态，直到它可以获取所需的锁。

+   `WAITING` `WAITING`状态。

+   `TIMED WAITING` `TIMED_WAITING`状态。

+   `TERMINATED` `TERMINATE`状态。

除了描述 Java 线程的可能状态之外，面试官可能会要求您为每个状态编写一个示例。这就是为什么我强烈建议您花时间分析名为*ThreadLifecycleState*的应用程序（为简洁起见，书中未列出代码）。该应用程序的结构非常直观，主要注释解释了每种情景/状态。

## 编码挑战 2 - 死锁

**问题**：向我们解释一下死锁，我们会雇佣你！

**解决方案**：雇佣我，我会向您解释。

在这里，我们刚刚描述了一个死锁。

死锁可以这样解释：线程*T1*持有锁*P*，并尝试获取锁*Q*。与此同时，有一个线程*T2*持有锁*Q*，并尝试获取锁*P*。这种死锁被称为*循环等待*或*致命拥抱*。

Java 不提供死锁检测和/或解决机制（例如数据库有）。这意味着死锁对应用程序来说可能非常尴尬。死锁可能部分或完全阻塞应用程序。这导致显著的性能惩罚，意外的行为/结果等。通常，死锁很难找到和调试，并且会迫使您重新启动应用程序。

避免竞争死锁的最佳方法是避免使用嵌套锁或不必要的锁。嵌套锁很容易导致死锁。

模拟死锁的常见问题是**哲学家就餐**问题。您可以在*Java 编码问题*书中找到对这个问题的详细解释和实现（[`www.packtpub.com/programming/java-coding-problems`](https://www.packtpub.com/programming/java-coding-problems)）。*Java 编码问题*包含两章专门讨论 Java 并发，并旨在使用特定问题深入探讨这个主题。

在本书的代码包中，您可以找到一个名为*Deadlock*的死锁示例。

## 编码挑战 3 - 竞争条件

**问题**：解释一下*竞争条件*是什么。

**解决方案**：首先，我们必须提到可以由多个线程执行（即并发执行）并公开共享资源（例如共享数据）的代码片段/块被称为*关键部分*。

*竞争条件*发生在线程在没有线程同步的情况下通过这样的关键部分。线程在关键部分中*竞争*尝试读取/写入共享资源。根据线程完成这场竞赛的顺序，应用程序的输出会发生变化（应用程序的两次运行可能会产生不同的输出）。这导致应用程序的行为不一致。

避免竞争条件的最佳方法是通过使用锁、同步块、原子/易失性变量、同步器和/或消息传递来正确同步关键部分。

编码挑战 4 - 可重入锁

**问题**：解释什么是*可重入锁*概念。

**解决方案**：一般来说，*可重入锁*指的是一个进程可以多次获取锁而不会使自身陷入死锁的过程。如果锁不是可重入的，那么进程仍然可以获取它。但是，当进程尝试再次获取锁时，它将被阻塞（死锁）。可重入锁可以被另一个线程获取，或者被同一个线程递归地获取。

可重入锁可以用于不包含可能破坏它的更新的代码片段。如果代码包含可以更新的共享状态，那么再次获取锁将会破坏共享状态，因为在执行代码时调用了该代码。

在 Java 中，可重入锁是通过`ReentrantLock`类实现的。可重入锁的工作方式是：当线程第一次进入锁时，保持计数设置为 1。在解锁之前，线程可以重新进入锁，导致每次进入时保持计数增加一。每个解锁请求将保持计数减少一，当保持计数为零时，锁定的资源被打开。

## 编码挑战 5 - Executor 和 ExecutorService

`Executor`和`ExecutorService`？

在`java.util.concurrent`包中，有许多专用于执行任务的接口。最简单的一个被命名为`Executor`。这个接口公开了一个名为`execute (Runnable command)`的方法。

一个更复杂和全面的接口，提供了许多额外的方法，是`ExecutorService`。这是`Executor`的增强版本。Java 带有一个完整的`ExecutorService`实现，名为`ThreadPoolExecutor`。

在本书的代码包中，您可以找到在名为*ExecutorAndExecutorService*的应用程序中使用`Executor`和`ThreadPoolExecutor`的简单示例。

编码挑战 6 - Runnable 与 Callable 的比较

`Callable`接口和`Runnable`接口？

`Runnable`接口是一个包含一个名为`run()`的方法的函数接口。`run()`方法不接受任何参数，返回`void`。此外，它不能抛出已检查的异常（只能抛出`RuntimeException`）。这些陈述使`Runnable`适用于我们不寻找线程执行结果的情况。`run()`签名如下：

```java
void run()
```

另一方面，`Callable`接口是一个包含一个名为`call()`的方法的函数接口。`call()`方法返回一个通用值，并且可以抛出已检查的异常。通常，`Callable`用于`ExecutorService`实例。它用于启动异步任务，然后调用返回的`Future`实例来获取其值。`Future`接口定义了用于获取`Callable`对象生成的结果和管理其状态的方法。`call()`签名如下：

```java
V call() throws Exception
```

请注意，这两个接口都代表一个任务，该任务旨在由单独的线程并发执行。

在本书的代码包中，您可以找到在名为*RunnableAndCallable*的应用程序中使用`Runnable`和`Callable`的简单示例。

## 编码挑战 7 - 饥饿

**问题**：解释什么是线程*饥饿*。

**解决方案**：一个永远（或很少）得不到 CPU 时间或访问共享资源的线程是经历*饥饿*的线程。由于它无法定期访问共享资源，这个线程无法推进其工作。这是因为其他线程（所谓的*贪婪*线程）在这个线程之前获得访问，并使资源长时间不可用。

避免线程饥饿的最佳方法是使用*公平*锁，比如 Java 的`ReentrantLock`。*公平*锁授予等待时间最长的线程访问权限。通过 Java 的`Semaphore`可以实现多个线程同时运行而避免饥饿。*公平*`Semaphore`使用 FIFO 来保证在争用情况下授予许可。

编码挑战 8 - 活锁

**问题**：解释什么是线程*活锁*。

**解决方案**：当两个线程不断采取行动以响应另一个线程时，就会发生活锁。这些线程不会在自己的工作中取得任何进展。请注意，这些线程没有被阻塞；它们都忙于相互响应而无法恢复工作。

这是一个活锁的例子：想象两个人试图在走廊上互相让对方通过。马克向右移动让奥利弗通过，奥利弗向左移动让马克通过。现在他们互相阻塞。马克看到自己挡住了奥利弗，向左移动，奥利弗看到自己挡住了马克，向右移动。他们永远无法互相通过并一直阻塞对方。

我们可以通过 `ReentrantLock` 避免活锁。这样，我们可以确定哪个线程等待的时间最长，并为其分配一个锁。如果一个线程无法获取锁，它应该释放先前获取的锁，然后稍后再试。

编码挑战 9 – Start() 与 run()

Java `Thread` 中的 `start()` 方法和 `run()` 方法。

`start()` 和 `run()` 的区别在于 `start()` 方法创建一个新的线程，而 `run()` 方法不会。`start()` 方法创建一个新的线程，并调用在这个新线程中写的 `run()` 方法内的代码块。`run()` 方法在同一个线程上执行该代码（即调用线程），而不创建新线程。

另一个区别是在线程对象上两次调用 `start()` 将抛出 `IllegalStateException`。另一方面，两次调用 `run()` 方法不会导致异常。

通常，新手会忽略这些区别，并且，由于 `start()` 方法最终调用 `run()` 方法，他们认为没有理由调用 `start()` 方法。因此，他们直接调用 `run()` 方法。

## 编码挑战 10 – 线程与可运行

`Thread` 或实现 `Runnable`？

通过 `java.lang.Thread` 或实现 `java.lang.Runnable`。首选的方法是实现 `Runnable`。

大多数情况下，我们实现一个线程只是为了让它运行一些东西，而不是覆盖 `Thread` 的行为。只要我们想要给一个线程运行一些东西，我们肯定应该坚持实现 `Runnable`。事实上，使用 `Callable` 或 `FutureTask` 更好。

此外，通过实现 `Runnable`，你仍然可以扩展另一个类。通过扩展 `Thread`，你不能扩展另一个类，因为 Java 不支持多重继承。

最后，通过实现 `Runnable`，我们将任务定义与任务执行分离。

编码挑战 11 – CountDownLatch 与 CyclicBarrier

`CountDownLatch` 和 `CyclicBarrier`。

`CountDownLatch` 和 `CyclicBarrier` 是 Java *同步器* 中的五个之一，另外还有 `Exchanger`、`Semaphore` 和 `Phaser`。

`CountDownLatch` 和 `CyclicBarrier` 之间的主要区别在于 `CountDownLatch` 实例在倒计时达到零后无法重用。另一方面，`CyclicBarrier` 实例是可重用的。`CyclicBarrier` 实例是循环的，因为它可以被重置和重用。要做到这一点，在所有等待在屏障处的线程被释放后调用 `reset()` 方法；否则，将抛出 `BrokenBarrierException`。

## 编码挑战 12 – wait() 与 sleep()

`wait()` 方法和 `sleep()` 方法。

`wait()` 方法和 `sleep()` 方法的区别在于 `wait()` 必须从同步上下文（例如，从 `synchronized` 方法）中调用，而 `sleep()` 方法不需要同步上下文。从非同步上下文调用 `wait()` 将抛出 `IllegalMonitorStateException`。

此外，重要的是要提到 `wait()` 在 `Object` 上工作，而 `sleep()` 在当前线程上工作。实质上，`wait()` 是在 `java.lang.Object` 中定义的非`static`方法，而 `sleep()` 是在 `java.lang.Thread` 中定义的`static`方法。

此外，`wait()` 方法释放锁，而 `sleep()` 方法不释放锁。`sleep()` 方法只是暂停当前线程一段时间。它们都会抛出 `IntrupptedException` 并且可以被中断。

最后，应该在决定何时释放锁的循环中调用`wait()`方法。另一方面，不建议在循环中调用`sleep()`方法。

编码挑战 13 - ConcurrentHashMap 与 Hashtable

`ConcurrentHashMap`比`Hashtable`快吗？

`ConcurrentHashMap`比`Hashtable`更快，因为它具有特殊的内部设计。`ConcurrentHashMap`在内部将映射分成段（或桶），并且在更新操作期间仅锁定特定段。另一方面，`Hashtable`在更新操作期间锁定整个映射。因此，`Hashtable`对整个数据使用单个锁，而`ConcurrentHashMap`对不同段（桶）使用多个锁。

此外，使用`get()`从`ConcurrentHashMap`中读取是无锁的（无锁），而所有`Hashtable`操作都是简单的`synchronized`。

## 编码挑战 14 - ThreadLocal

`ThreadLocal`？

`ThreadLocal`用作分别存储和检索每个线程的值的手段。单个`ThreadLocal`实例可以存储和检索多个线程的值。如果线程*A*存储*x*值，线程*B*在同一个`ThreadLocal`实例中存储*y*值，那么后来线程*A*检索*x*值，线程*B*检索*y*值。Java `ThreadLocal`通常用于以下两种情况：

1.  为每个线程提供实例（线程安全和内存效率）

1.  为每个线程提供上下文

## 编码挑战 15 - submit()与 execute()

`ExecutorService#submit()`和`Executor#execute()`方法。

用于执行的`Runnable`任务，它们并不相同。主要区别可以通过简单检查它们的签名来观察。注意，`submit()`返回一个结果（即代表任务的`Future`对象），而`execute()`返回`void`。返回的`Future`对象可以用于在以后（过早地）以编程方式取消运行的线程。此外，通过使用`Future#get()`方法，我们可以等待任务完成。如果我们提交一个`Callable`，那么`Future#get()`方法将返回调用`Callable#call()`方法的结果。

## 编码挑战 16 - interrupted()和 isInterrupted()

`interrupted()`和`isInterrupted()`方法。

`Thread.interrupt()`方法中断当前线程并将此标志设置为`true`。

`interrupted()`和`isInterrupted()`方法之间的主要区别在于`interrupted()`方法会清除中断状态，而`isInterrupted()`不会。

如果线程被中断，则`Thread.interrupted()`将返回`true`。但是，除了测试当前线程是否被中断外，`Thread.interrupted()`还会清除线程的中断状态（即将其设置为`false`）。

非`static isInterrupted()`方法不会更改中断状态标志。

作为一个经验法则，在捕获`InterruptedException`后，不要忘记通过调用`Thread.currentThread().interrupt()`来恢复中断。这样，我们的代码的调用者将意识到中断。

编码挑战 17 - 取消线程

**问题**：如何停止或取消线程？

`volatile`（也称为轻量级同步机制）。作为`volatile`标志，它不会被线程缓存，并且对它的操作不会在内存中重新排序；因此，线程无法看到旧值。读取`volatile`字段的任何线程都将看到最近写入的值。这正是我们需要的，以便将取消操作通知给所有对此操作感兴趣的运行中的线程。以下图表说明了这一点：

![16.3 - Volatile 标志读/写](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_16.3_B15403.jpg)

16.3 - Volatile 标志读/写

请注意，`volatile`变量不适合读-修改-写场景。对于这种场景，我们将依赖原子变量（例如`AtomicBoolean`、`AtomicInteger`和`AtomicReference`）。

在本书的代码包中，您可以找到一个取消线程的示例。该应用程序名为*CancelThread*。

## 编码挑战 18 - 在线程之间共享数据

问题：如何在两个线程之间共享数据？

`BlockingQueue`，`LinkedBlockingQueue`和`ConcurrentLinkedDeque`。依赖于这些数据结构在线程之间共享数据非常方便，因为您不必担心线程安全和线程间通信。

编码挑战 19 - ReadWriteLock

`ReadWriteLock`是在 Java 中的。

`ReadWriteLock`用于在并发环境中维护读写操作的效率和线程安全性。它通过*锁分段*的概念实现这一目标。换句话说，`ReadWriteLock`为读和写使用单独的锁。更确切地说，`ReadWriteLock`保持一对锁：一个用于只读操作，一个用于写操作。只要没有写线程，多个读线程可以同时持有读锁（共享悲观锁）。一个写线程可以一次写入（独占/悲观锁）。因此，`ReadWriteLock`可以显著提高应用程序的性能。

除了`ReadWriteLock`，Java 还提供了`ReentrantReadWriteLock`和`StampedLock`。`ReentrantReadWriteLock`类将*可重入锁*概念（参见*编码挑战 4*）添加到`ReadWriteLock`中。另一方面，`StampedLock`比`ReentrantReadWriteLock`表现更好，并支持乐观读取。但它不是*可重入*的；因此，它容易发生死锁。

## 编码挑战 20 - 生产者-消费者

**问题**：为著名的生产者-消费者问题提供一个实现。

注意

这是任何 Java 多线程面试中的一个常见问题！

**解决方案**：生产者-消费者问题是一个可以表示为以下形式的设计模式：

![16.4 - 生产者-消费者设计模式](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_16.4_B15403.jpg)

16.4 - 生产者-消费者设计模式

在这种模式中，生产者线程和消费者线程通常通过一个队列进行通信（生产者将数据入队，消费者将数据出队），并遵循特定于建模业务的一组规则。这个队列被称为*数据缓冲区*。当然，根据流程设计，其他数据结构也可以扮演数据缓冲区的角色。

现在，让我们假设以下情景（一组规则）：

+   如果数据缓冲区为空，那么生产者会生产一个产品（将其添加到数据缓冲区）。

+   如果数据缓冲区不为空，那么消费者会消费一个产品（从数据缓冲区中移除它）。

+   只要数据缓冲区不为空，生产者就会等待。

+   只要数据缓冲区为空，消费者就会等待。

接下来，让我们通过两种常见的方法解决这种情况。我们将从基于`wait()`和`notify()`方法的解决方案开始。

## 通过`wait()`和`notify()`实现生产者-消费者

一些面试官可能会要求您实现`wait()`和`notify()`方法。换句话说，他们不允许您使用内置的线程安全队列，如`BlockingQueue`。

例如，让我们考虑数据缓冲区（`queue`）由`LinkedList`表示，即非线程安全的数据结构。为了确保生产者和消费者以线程安全的方式访问这个共享的`LinkedList`，我们依赖于`Synchronized`关键字。

### 生产者

如果队列不为空，那么生产者会等待，直到消费者完成。为此，生产者依赖于`wait()`方法，如下所示：

```java
synchronized (queue) {     
  while (!queue.isEmpty()) {
    logger.info("Queue is not empty ...");
    queue.wait();
  }
}
```

另一方面，如果队列为空，那么生产者会将一个产品入队，并通过`notify()`通知消费者线程，如下所示：

```java
synchronized (queue) {
  String product = "product-" + rnd.nextInt(1000);
  // simulate the production time
  Thread.sleep(rnd.nextInt(MAX_PROD_TIME_MS)); 
  queue.add(product);
  logger.info(() -> "Produced: " + product);
  queue.notify();
}
```

在将产品添加到队列后，消费者应该准备好消费它。

### 消费者

如果队列为空，那么消费者会等待，直到生产者完成。为此，生产者依赖于`wait()`方法，如下所示：

```java
synchronized (queue) {
  while (queue.isEmpty()) {
    logger.info("Queue is empty ...");
    queue.wait();
  }
}
```

另一方面，如果队列不为空，则消费者将出列一个产品并通过`notify()`通知生产者线程，如下所示：

```java
synchronized (queue) {
  String product = queue.remove(0);
  if (product != null) {
    // simulate consuming time
    Thread.sleep(rnd.nextInt(MAX_CONS_TIME_MS));                                
    logger.info(() -> "Consumed: " + product);
    queue.notify();
  }
}
```

完整的代码在捆绑代码*ProducerConsumerWaitNotify*中可用。

通过内置的阻塞队列进行生产者-消费者

如果您可以使用内置的阻塞队列，那么您可以选择`BlockingQueue`甚至`TransferQueue`。它们两者都是线程安全的。在下面的代码中，我们使用了`TransferQueue`，更确切地说是`LinkedTransferQueue`。

### 生产者

生产者等待消费者通过`hasWaitingConsumer()`可用：

```java
while (queue.hasWaitingConsumer()) {
  String product = "product-" + rnd.nextInt(1000);
  // simulate the production time
  Thread.sleep(rnd.nextInt(MAX_PROD_TIME_MS)); 
  queue.add(product);
  logger.info(() -> "Produced: " + product);
}
```

在将产品添加到队列后，消费者应准备好消费它。

### 消费者

消费者使用`poll()`方法并设置超时来提取产品：

```java
// MAX_PROD_TIME_MS * 2, just give enough time to the producer
String product = queue.poll(
  MAX_PROD_TIME_MS * 2, TimeUnit.MILLISECONDS);
if (product != null) {
  // simulate consuming time
  Thread.sleep(rnd.nextInt(MAX_CONS_TIME_MS));                         
  logger.info(() -> "Consumed: " + product);
}
```

完整的代码在捆绑代码*ProducerConsumerQueue*中可用

总结

在本章中，我们涵盖了在 Java 多线程面试中经常出现的最受欢迎的问题。然而，Java 并发是一个广泛的主题，深入研究它非常重要。我强烈建议您阅读 Brian Goetz 的*Java 并发实践*。这对于任何 Java 开发人员来说都是必读之书。

在下一章中，我们将涵盖一个热门话题：Java 函数式编程。


# 第十七章：函数式编程

你可能知道，Java 不像 Haskell 那样是一种纯函数式编程语言，但从版本 8 开始，Java 添加了一些函数式支持。添加这种支持的努力取得了成功，并且函数式代码被开发人员和公司广泛采用。函数式编程支持更易理解、易维护和易测试的代码。然而，以函数式风格编写 Java 代码需要严肃的了解 lambda、流 API、`Optional`、函数接口等知识。所有这些函数式编程主题也可以是面试的主题，在本章中，我们将涵盖一些必须了解的热门问题，以通过常规的 Java 面试。我们的议程包括以下主题：

+   Java 函数式编程概述

+   问题和编码挑战

让我们开始吧！

# Java 函数式编程概述

像往常一样，本节旨在突出和复习我们主题的主要概念，并为回答技术面试中可能出现的基本问题提供全面的资源。

## 函数式编程的关键概念

因此，函数式编程的关键概念包括以下内容：

+   函数作为一等对象

+   纯函数

+   高阶函数

让我们简要地介绍一下这些概念。

### 函数作为一等对象

说函数是一等对象意味着我们可以创建一个函数的*实例*，并将变量引用该函数实例。这就像引用`String`、`List`或任何其他对象。此外，函数可以作为参数传递给其他函数。然而，Java 方法不是一等对象。我们能做的最好的事情就是依赖于 Java lambda 表达式。

### 纯函数

*纯*函数是一个执行没有*副作用*的函数，返回值仅取决于其输入参数。以下 Java 方法是一个纯函数：

```java
public class Calculator {
  public int sum(int x, int y) {
    return x + y;
  }
}
```

如果一个方法使用成员变量或改变成员变量的状态，那么它就不是一个*纯*函数。

### 高阶函数

高阶函数将一个或多个函数作为参数和/或返回另一个函数作为结果。Java 通过 lambda 表达式模拟高阶函数。换句话说，在 Java 中，高阶函数是一个以一个（或多个）lambda 表达式作为参数和/或返回另一个 lambda 表达式的方法。

例如，`Collections.sort()`方法接受一个`Comparator`作为参数，这是一个高阶函数：

```java
Collections.sort(list, (String x, String y) -> {
  return x.compareTo(y);
});
```

`Collections.sort()`的第一个参数是一个`List`，第二个参数是一个 lambda 表达式。这个 lambda 表达式参数是使`Collections.sort()`成为一个高阶函数的原因。

### 纯函数式编程规则

现在，让我们简要讨论纯函数式编程规则。纯函数式编程也有一套规则要遵循。这些规则如下：

+   没有状态

+   没有副作用

+   不可变变量

+   偏爱递归而不是循环

让我们简要地介绍一下这些规则。

### 没有状态

通过*无状态*，我们并不是指函数式编程消除了状态。通常，无状态意味着函数没有外部状态。换句话说，函数可能使用包含临时状态的局部变量，但不能引用其所属类/对象的任何成员变量。

### 无副作用

通过“无副作用”，我们应该理解一个函数不能改变（突变）函数之外的任何状态（在其功能范围之外）。函数之外的状态包括以下内容：

+   包含该函数的类/对象中的成员变量

+   作为参数传递给函数的成员变量

+   或外部系统中的状态（例如数据库或文件）。

### 不可变变量

函数式编程鼓励并支持不可变变量的使用。依赖不可变变量有助于我们更轻松、更直观地避免*副作用*。

### 更喜欢递归而不是循环

由于递归依赖于重复的函数调用来模拟循环，代码变得更加函数式。这意味着不鼓励使用以下迭代方法来计算阶乘：

```java
static long factorial(long n) {
  long result = 1;
  for (; n > 0; n--) {
    result *= n;
  }
  return result;
}
```

函数式编程鼓励以下递归方法：

```java
static long factorial(long n) {
  return n == 1 ? 1 : n * factorial(n - 1);
}
```

我们使用*尾递归*来改善性能损耗，因为在前面的例子中，每个函数调用都保存为递归堆栈中的一个帧。当存在许多递归调用时，尾递归是首选。在尾递归中，函数执行递归调用作为最后要做的事情，因此编译器不需要将函数调用保存为递归堆栈中的帧。大多数编译器将优化尾递归，从而避免性能损耗：

```java
static long factorialTail(long n) {
  return factorial(1, n);
}
static long factorial(long acc, long v) {
  return v == 1 ? acc : factorial(acc * v, v - 1);
}
```

另外，循环可以通过受 Java Stream API 的启发来实现：

```java
static long factorial(long n) {
  return LongStream.rangeClosed(1, n)
     .reduce(1, (n1, n2) -> n1 * n2);
}
```

现在，是时候练习一些问题和编码挑战了。

# 问题和编码挑战

在本节中，我们将涵盖 21 个在面试中非常流行的问题和编码挑战。让我们开始吧！

## 编码挑战 1- Lambda 部分

**问题**：描述 Java 中 lambda 表达式的部分。此外，什么是 lambda 表达式的特征？

**解决方案**：如下图所示，lambda 有三个主要部分：

![图 17.1- Lambda 部分](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_17.1_B15403.jpg)

图 17.1- Lambda 部分

lambda 表达式的部分如下：

+   在箭头的左侧，是 lambda 的参数，这些参数在 lambda 主体中被使用。在这个例子中，这些是`FilenameFilter.accept(File folder, String fileName)`方法的参数。

+   在箭头的右侧，是 lambda 的主体。在这个例子中，lambda 的主体检查文件（`fileName`）所在的文件夹（`folder`）是否可读，并且这个文件的名称是否以*.pdf*字符串结尾。

+   箭头位于参数列表和 lambda 主体之间，起到分隔作用。

接下来，让我们谈谈 lambda 表达式的特征。因此，如果我们写出前面图表中 lambda 的匿名类版本，那么它将如下所示：

```java
FilenameFilter filter = new FilenameFilter() {
  @Override
  public boolean accept(File folder, String fileName) {
    return folder.canRead() && fileName.endsWith(".pdf");
  }
};
```

现在，如果我们比较匿名版本和 lambda 表达式，我们会注意到 lambda 表达式是一个简洁的匿名函数，可以作为参数传递给方法或保存在变量中。

下图中显示的四个词表征了 lambda 表达式：

![图 17.2- Lambda 特征](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_17.2_B15403.jpg)

图 17.2- Lambda 特征

作为一个经验法则，请记住，lambda 支持行为参数化设计模式（行为作为函数的参数传递），并且只能在功能接口的上下文中使用。

## 编码挑战 2-功能接口

**问题**：什么是功能接口？

**解决方案**：在 Java 中，功能接口是一个只包含一个抽象方法的接口。换句话说，功能接口只包含一个未实现的方法。因此，功能接口将函数作为接口进行封装，并且该函数由接口上的单个抽象方法表示。

除了这个抽象方法之外，功能接口还可以有默认和/或静态方法。通常，功能接口会用`@FunctionalInterface`进行注解。这只是一个信息性的注解类型，用于标记功能接口。

这是一个功能接口的例子：

```java
@FunctionalInterface
public interface Callable<V> {
  V call() throws Exception;
}
```

根据经验法则，如果一个接口有更多没有实现的方法（即抽象方法），那么它就不再是一个函数式接口。这意味着这样的接口不能被 Java lambda 表达式实现。

## 编码挑战 3 - 集合与流

**问题**：集合和流之间的主要区别是什么？

**解决方案**：集合和流是非常不同的。一些不同之处如下：

+   `List`、`Set`和`Map`），流旨在对该数据应用操作（例如*过滤*、*映射*和*匹配*）。换句话说，流对存储在集合上的数据表示的视图/源应用复杂的操作。此外，对流进行的任何修改/更改都不会反映在原始集合中。

+   **数据修改**：虽然我们可以向集合中添加/删除元素，但我们不能向流中添加/删除元素。实际上，流消耗视图/源，对其执行操作，并在不修改视图/源的情况下返回结果。

+   **迭代**：流消耗视图/源时，它会自动在内部执行该视图/源的迭代。迭代取决于选择应用于视图/源的操作。另一方面，集合必须在外部进行迭代。

+   **遍历**：集合可以被多次遍历，而流只能被遍历一次。因此，默认情况下，Java 流不能被重用。尝试两次遍历流将导致错误读取*Stream has already been operated on or closed*。

+   **构造**：集合是急切构造的（所有元素从一开始就存在）。另一方面，流是懒惰构造的（所谓的*中间*操作直到调用*终端*操作才被评估）。

## 编码挑战 4 - map()函数

`map()`函数是做什么的，为什么要使用它？

`map()`函数是一个名为*映射*的中间操作，通过`Stream` API 可用。它用于通过简单应用给定函数将一种类型的对象转换为另一种类型。因此，`map()`遍历给定流，并通过应用给定函数将每个元素转换为它的新版本，并在新的`Stream`中累积结果。给定的`Stream`不会被修改。例如，通过`Stream#map()`将`List<String>`转换为`List<Integer>`可以如下进行：

```java
List<String> strList = Arrays.asList("1", "2", "3");
List<Integer> intList = strList.stream()
  .map(Integer::parseInt)
  .collect(Collectors.toList());
```

挑战自己多练习一些例子。尝试应用`map()`将一个数组转换为另一个数组。

## 编码挑战 5 - flatMap()函数

`flatMap()`函数是做什么的，为什么要使用它？

`flatMap()`函数是一个名为*展平*的中间操作，通过`Stream` API 可用。这个函数是`map()`的扩展，意味着除了将给定对象转换为另一种类型的对象之外，它还可以展平它。例如，有一个`List<List<Object>>`，我们可以通过`Stream#flatMap()`将其转换为`List<Object>`，如下所示：

```java
List<List<Object>> list = ...
List<Object> flatList = list.stream()
  .flatMap(List::stream)
  .collect(Collectors.toList());
```

下一个编码挑战与此相关，所以也要考虑这一点。

## 编码挑战 6 - map()与 flatMap()

`map()`和`flatMap()`函数？

`flatMap()`函数还能够将给定对象展平。换句话说，`flatMap()`也可以展平一个`Stream`对象。

为什么这很重要？嗯，`map()`知道如何将一系列元素包装在`Stream`中，对吧？这意味着`map()`可以生成诸如`Stream<String[]>`、`Stream<List<String>>`、`Stream<Set<String>>`甚至`Stream<Stream<R>>`等流。但问题是，这些类型的流不能被流操作成功地操作（即，如我们所期望的那样）`sum()`、`distinct()`和`filter()`。

例如，让我们考虑以下`List`：

```java
List<List<String>> melonLists = Arrays.asList(
  Arrays.asList("Gac", "Cantaloupe"),
  Arrays.asList("Hemi", "Gac", "Apollo"),
  Arrays.asList("Gac", "Hemi", "Cantaloupe"));
```

我们试图从这个列表中获取甜瓜的不同名称。如果将数组包装成流可以通过`Arrays.stream()`来完成，对于集合，我们有`Collection.stream()`。因此，第一次尝试可能如下所示：

```java
melonLists.stream()
  .map(Collection::stream) // Stream<Stream<String>>
  .distinct();
```

但这不起作用，因为`map()`将返回`Stream<Stream<String>>`。解决方案由`flatMap()`提供，如下所示：

```java
List<String> distinctNames = melonLists.stream()
  .flatMap(Collection::stream) // Stream<String>
  .distinct()
  .collect(Collectors.toList());
```

输出如下：`Gac`，`Cantaloupe`，`Hemi`，`Apollo`。

此外，如果您在理解这些函数式编程方法时遇到困难，我强烈建议您阅读我的另一本书，*Java 编码问题*，可从 Packt 获得（[`www.packtpub.com/programming/java-coding-problems`](https://www.packtpub.com/programming/java-coding-problems)）。该书包含两个关于 Java 函数式编程的全面章节，提供了详细的解释、图表和应用，对于深入研究这个主题非常有用。

## 编码挑战 7-过滤器（）函数

`filter()`函数是做什么的，为什么要使用它？

`filter()`函数是通过`Stream` API 提供的一种名为*filtering*的中间操作。它用于过滤满足某种条件的`Stream`元素。条件是通过`java.util.function.Predicate`函数指定的。这个谓词函数只是一个以`Object`作为参数并返回`boolean`的函数。

假设我们有以下整数`List`：

```java
List<Integer> ints
  = Arrays.asList(1, 2, -4, 0, 2, 0, -1, 14, 0, -1);
```

可以通过以下方式对此列表进行流处理并提取非零元素：

```java
List<Integer> result = ints.stream()
  .filter(i -> i != 0)
  .collect(Collectors.toList());
```

结果列表将包含以下元素：`1`，`2`，`-4`，`2`，`-1`，`14`，`-1`。

请注意，对于几个常见操作，Java `Stream` API 已经提供了即用即得的中间操作。例如，无需使用`filter()`和为以下操作定义`Predicate`：

+   `distinct()`: 从流中删除重复项

+   `skip(n)`: 跳过前`n`个元素

+   `limit(s)`: 将流截断为不超过`s`长度

+   `sorted()`: 根据自然顺序对流进行排序

+   `sorted(Comparator<? super T> comparator)`: 根据给定的`Comparator`对流进行排序

所有这些函数都内置在`Stream` API 中。

## 编码挑战 8-中间操作与终端操作

**问题**：中间操作和终端操作之间的主要区别是什么？

`Stream`，而终端操作产生除`Stream`之外的结果（例如，集合或标量值）。换句话说，中间操作允许我们在名为*管道*的查询类型中链接/调用多个操作。

中间操作直到调用终端操作才会执行。这意味着中间操作是懒惰的。主要是在实际需要某个给定处理的结果时执行它们。终端操作触发`Stream`的遍历并执行管道。

在中间操作中，我们有`map()`，`flatMap()`，`filter()`，`limit()`和`skip()`。在终端操作中，我们有`sum()`，`min()`，`max()`，`count()`和`collect()`。

## 编码挑战 9-peek()函数

`peek()`函数是做什么的，为什么要使用它？

`peek()`函数是通过`Stream` API 提供的一种名为*peeking*的中间操作。它允许我们查看`Stream`管道。主要是，`peek()`应该对当前元素执行某个*非干扰*的操作，并将元素转发到管道中的下一个操作。通常，这个操作包括在控制台上打印有意义的消息。换句话说，`peek()`是调试与流和 lambda 表达式处理相关问题的一个很好的选择。例如，想象一下，我们有以下地址列表：

```java
addresses.stream()
  .peek(p -> System.out.println("\tstream(): " + p))
  .filter(s -> s.startsWith("c"))
  .sorted()
  .peek(p -> System.out.println("\tsorted(): " + p))
  .collect(Collectors.toList());
```

重要的是要提到，即使`peek()`可以用于改变状态（修改流的数据源），它代表*看，但不要触摸*。通过`peek()`改变状态可能在并行流管道中成为真正的问题，因为修改操作可能在上游操作提供的任何时间和任何线程中被调用。因此，如果操作修改了共享状态，它负责提供所需的同步。

作为一个经验法则，在使用`peek()`来改变状态之前要三思。此外，要注意这种做法在开发人员中是有争议的，并且可以被归类为不良做法甚至反模式的范畴。

## 编码挑战 10 - 懒惰流

**问题**：说一个流是懒惰的是什么意思？

**解决方案**：说一个流是懒惰的意思是，流定义了一系列中间操作的管道，只有当管道遇到终端操作时才会执行。这个问题与本章的*编码挑战 8*有关。

## 编码挑战 11 - 函数式接口与常规接口

**问题**：函数式接口和常规接口之间的主要区别是什么？

**解决方案**：函数式接口和常规接口之间的主要区别在于，常规接口可以包含任意数量的抽象方法，而函数式接口只能有一个抽象方法。

您可以查阅本书的*编码挑战 2*以深入了解。

## 编码挑战 12 - 供应商与消费者

`Supplier`和`Consumer`？

`Supplier`和`Consumer`是两个内置的函数式接口。`Supplier`充当工厂方法或`new`关键字。换句话说，`Supplier`定义了一个名为`get()`的方法，不带参数并返回类型为`T`的对象。因此，`Supplier`对于*提供*某个值很有用。

另一方面，`Consumer`定义了一个名为`void accept(T t)`的方法。这个方法接受一个参数并返回`void`。`Consumer`接口*消耗*给定的值并对其应用一些操作。与其他函数式接口不同，`Consumer`可能会引起*副作用*。例如，`Consumer`可以用作设置方法。

## 编码挑战 13 - 谓词

`Predicate`？

`Predicate`是一个内置的函数式接口，它包含一个抽象方法，其签名为`boolean test(T object)`：

```java
@FunctionalInterface
public interface Predicate<T> {
  boolean test(T t);
  // default and static methods omitted for brevity
}
```

`test()`方法测试条件，如果满足条件则返回`true`，否则返回`false`。`Predicate`的常见用法是与`Stream<T> filter(Predicate<? super T> predicate)`方法一起过滤流中不需要的元素。

## 编码挑战 14 - findFirst()与 findAny()

`findFirst()`和`findAny()`？

`findFirst()`方法从流中返回第一个元素，特别适用于获取序列中的第一个元素。只要流有定义的顺序，它就会返回流中的第一个元素。如果没有遇到顺序，那么`findFirst()`会返回流中的任何元素。

另一方面，`findAny()`方法从流中返回任何元素。换句话说，它从流中返回一个任意（非确定性）的元素。`findAny()`方法忽略了遇到的顺序，在非并行操作中，它很可能返回第一个元素，但不能保证这一点。为了最大化性能，在并行操作中无法可靠地确定结果。

请注意，根据流的来源和中间操作，流可能有或可能没有定义的遇到顺序。

## 编码挑战 15 - 将数组转换为流

**问题**：如何将数组转换为流？

**解决方案**：将对象数组转换为流可以通过至少三种方式来完成，如下所示：

1.  第一种是通过`Arrays#stream()`：

```java
public static <T> Stream<T> toStream(T[] arr) {
  return Arrays.stream(arr);
}
```

1.  其次，我们可以使用`Stream#of()`：

```java
public static <T> Stream<T> toStream(T[] arr) {        
  return Stream.of(arr);
}
```

1.  最后一种技术是通过`List#stream()`：

```java
public static <T> Stream<T> toStream(T[] arr) {        
  return Arrays.asList(arr).stream();
}
```

将原始数组（例如整数）转换为流可以通过至少两种方式完成，如下：

1.  首先，通过`Arrays#stream()`：

```java
public static IntStream toStream(int[] arr) {       
  return Arrays.stream(arr);
}
```

1.  其次，通过使用`IntStream#of()`：

```java
public static IntStream toStream(int[] arr) {
  return IntStream.of(arr);
}
```

当然，对于长整型，您可以使用`LongStream`，对于双精度浮点数，您可以使用`DoubleStream`。

## 编码挑战 16-并行流

**问题**：什么是并行流？

**解决方案**：并行流是一种可以使用多个线程并行执行的流。例如，您可能需要过滤包含 1000 万个整数的流，以找到小于某个值的整数。您可以使用并行流来代替使用单个线程顺序遍历流。这意味着多个线程将同时在流的不同部分搜索这些整数，然后将结果合并。

## 编码挑战 17-方法引用

**问题**：什么是方法引用？

`::`，然后在其后提供方法的名称。我们有以下引用：

+   对静态方法的方法引用：*Class*::*staticMethod*（例如，`Math::max`等同于`Math.max(`*x*`,` *y*`)`）

+   对构造函数的方法引用：*Class*::*new*（例如，`AtomicInteger::new`等同于`new AtomicInteger(`*x*`)`）

+   对实例方法的方法引用：*object*::*instanceMethod*（`System.out::println`等同于`System.out.println(`*foo*`)`）

+   对类类型的实例方法的方法引用：*Class*::*instanceMethod*（`String::length`等同于`str.length()`）

## 编码挑战 18-默认方法

**问题**：什么是默认方法？

**解决方案**：默认方法主要是在 Java 8 中添加的，以提供对接口的支持，使其可以超越抽象合同（即仅包含抽象方法）。这个功能对于编写库并希望以兼容的方式发展 API 的人非常有用。通过默认方法，接口可以在不破坏现有实现的情况下进行丰富。

默认方法直接在接口中实现，并且通过`default`关键字识别。例如，以下接口定义了一个名为`area()`的抽象方法和一个名为`perimeter()`的默认方法：

```java
public interface Polygon {
  public double area();
  default double perimeter(double... segments) {
    return Arrays.stream(segments)
      .sum();
  }
}
```

由于`Polygon`有一个抽象方法，它也是一个函数接口。因此，它可以用`@FunctionalInterface`注解。

## 编码挑战 19-迭代器与 Spliterator

`Iterator`和`Spliterator`？

`Iterator`是为`Collection`API 创建的，而`Spliterator`是为`Stream`API 创建的。

通过分析它们的名称，我们注意到*Spliterator* = *Splittable Iterator*。因此，`Spliterator`可以分割给定的源并且也可以迭代它。分割是用于并行处理的。换句话说，`Iterator`可以顺序迭代`Collection`中的元素，而`Spliterator`可以并行或顺序地迭代流的元素。

`Iterator`只能通过`hasNext()`/`next()`遍历集合的元素，因为它没有大小。另一方面，`Spliterator`可以通过`estimateSize()`近似地提供集合的大小，也可以通过`getExactSizeIfKnown()`准确地提供集合的大小。

`Spliterator`可以使用多个标志来内部禁用不必要的操作（例如，`CONCURRENT`，`DISTINCT`和`IMMUTABLE`）。`Iterator`没有这样的标志。

最后，您可以按以下方式围绕`Iterator`创建一个`Spliterator`：

```java
Spliterators.spliteratorUnknownSize(
  your_Iterator, your_Properties);
```

在书籍*Java 编码问题*（[`www.amazon.com/gp/product/B07Y9BPV4W/`](https://www.amazon.com/gp/product/B07Y9BPV4W/)）中，您可以找到有关此主题的更多详细信息，包括编写自定义`Spliterator`的完整指南。

## 编码挑战 20-Optional

`Optional`类？

`Optional`类是在 Java 8 中引入的，主要目的是减轻/避免`NullPointerException`。Java 语言架构师 Brian Goetz 的定义如下：

Optional 旨在为库方法的返回类型提供有限的机制，在需要清晰表示没有结果的情况下，使用 null 很可能会导致错误。

简而言之，您可以将`Optional`视为一个单值容器，它可以包含一个值或者为空。例如，一个空的`Optional`看起来像这样：

```java
Optional<User> userOptional = Optional.empty();
```

一个非空的`Optional`看起来像这样：

```java
User user = new User();
Optional<User> userOptional = Optional.of(user);
```

在《Java 编程问题》（[`www.amazon.com/gp/product/B07Y9BPV4W/`](https://www.amazon.com/gp/product/B07Y9BPV4W/)）中，您可以找到一个完整的章节专门讨论了使用`Optional`的最佳实践。这是任何 Java 开发人员必读的章节。

## 编码挑战 21 - String::valueOf

`String::valueOf`的意思是什么？

`String::valueOf`是对`String`类的`valueOf`静态方法的方法引用。考虑阅读《编码挑战 17》以获取更多关于这个的信息。

# 总结

在本章中，我们涵盖了关于 Java 中函数式编程的几个热门话题。虽然这个主题非常广泛，有很多专门的书籍，但在这里涵盖的问题应该足以通过涵盖 Java 8 语言主要特性的常规 Java 面试。

在下一章中，我们将讨论与扩展相关的问题。


# 第十八章：单元测试

作为开发人员（或软件工程师），您必须在测试领域也具备技能。例如，开发人员负责编写其代码的单元测试（例如，使用 JUnit 或 TestNG）。很可能，不包含单元测试的拉取请求也不会被接受。

在本章中，我们将涵盖单元测试面试问题，如果您申请开发人员或软件工程师等职位，可能会遇到这些问题。当然，如果您正在寻找测试人员（手动/自动化）职位，那么本章可能只代表测试的另一个视角，因此不要期望在这里看到特定于手动/自动化测试人员职位的问题。在本章中，我们将涵盖以下主题：

+   单元测试简介

+   问题和编码问题

让我们开始吧！

# 技术要求

本章中使用的代码可以在 GitHub 上找到：[`github.com/PacktPublishing/The-Complete-Coding-Interview-Guide-in-Java/tree/master/Chapter18`](https://github.com/PacktPublishing/The-Complete-Coding-Interview-Guide-in-Java/tree/master/Chapter18)

# 单元测试简介

测试应用程序的过程包含几个测试层。其中之一是*单元测试*层。

主要的，一个应用程序是由称为单元的小功能部分构建的（例如，一个常规的 Java 方法可以被认为是一个单元）。测试这些单元在特定输入/条件/约束下的功能和正确性称为单元测试。

这些单元测试是由开发人员使用源代码和测试计划编写的。理想情况下，每个开发人员都应该能够编写测试/验证其代码的单元测试。单元测试应该是有意义的，并提供被接受的代码覆盖率。

如果单元测试失败，那么开发人员负责修复问题并再次执行单元测试。以下图表描述了这一陈述：

![图 18.1 – 单元测试流程](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_18.1_B15403.jpg)

图 18.1 – 单元测试流程

单元测试使用**单元测试用例**。*单元测试用例*是一对输入数据和预期输出，用于塑造对某个功能的测试。

如果您参加的面试要求了解单元测试，如果被问及功能测试和/或集成测试的问题，不要感到惊讶。因此，最好准备好这些问题的答案。

功能测试是基于给定的输入和产生的输出（行为）来测试功能要求，需要将其与预期输出（行为）进行比较。每个功能测试都使用功能规范来验证表示该功能要求实现的组件（或一组组件）的正确性。这在下图中有解释：

![图 18.2 – 功能测试](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_18.2_B15403.jpg)

图 18.2 – 功能测试

**集成测试**的目标是在软件组件被迭代增量地集成时发现缺陷。换句话说，已经进行单元测试的模块被集成（分组或聚合）并按照集成计划进行测试。这在下图中有所描述：

![图 18.3 – 集成测试](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_18.3_B15403.jpg)

图 18.3 – 集成测试

关于单元测试和集成测试的问题经常被问及面试候选人，问题是突出这两者之间的主要区别。以下表格将帮助您准备回答这个问题：

![图 18.4 – 单元测试和集成测试的比较](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_18.4_B15403.jpg)

图 18.4 – 单元测试和集成测试的比较

一个好的测试人员能够在不做任何关于输入的假设或约束的情况下对测试对象进行压力测试和滥用。这也适用于单元测试。现在我们已经涉及了单元测试，让我们来看看一些关于单元测试的编码挑战和问题。

# 问题和编码挑战

在这一部分，我们将涵盖与单元测试相关的 15 个问题和编码挑战，这在面试中非常受欢迎。让我们开始吧！

## 编码挑战 1 - AAA

**问题**：单元测试中的 AAA 是什么？

**解决方案**：AAA 首字母缩写代表[**A**]rrange，[**A**]ct，[**A**]ssert，它代表一种构造测试的方法，以维持清晰的代码和可读性。今天，AAA 是一种几乎成为行业标准的测试模式。以下代码片段说明了这一点：

```java
@Test
public void givenStreamWhenSumThenEquals6() {
  // Arrange
  Stream<Integer> theStream = Stream.of(1, 2, 3);
  // Act
  int sum = theStream.mapToInt(i -> i).sum();
  // Assert
  assertEquals(6, sum);
}
```

**安排**部分：在这一部分，我们准备或设置测试。例如，在前面的代码中，我们准备了一个整数流，其中的元素是 1、2 和 3。

**行动**部分：在这一部分，我们执行必要的操作以获得测试的结果。例如，在前面的代码中，我们对流的元素求和，并将结果存储在一个整数变量中。

**断言**部分：在这一部分，我们检查单元测试的结果是否与预期结果相匹配。这是通过断言来完成的。例如，在前面的代码中，我们检查元素的总和是否等于 6。

你可以在名为*junit5/ArrangeActAssert*的应用程序中找到这段代码。

## 编码挑战 2 - FIRST

**问题**：单元测试中的**FIRST**是什么？

**解决方案**：好的测试人员使用 FIRST 来避免在单元测试中遇到的许多问题。FIRST 首字母缩写代表[**F**]ast，[**I**]solated，[**R**]epeatable，[**S**]elf-validating，[**T**]imely。让我们看看它们各自的含义：

**快速**：建议编写运行快速的单元测试。快速是一个依赖于你有多少单元测试、你多频繁运行它们以及你愿意等待它们运行多长时间的任意概念。例如，如果每个单元测试的平均完成时间为 200 毫秒，你运行 5000 个单元测试，那么你将等待约 17 分钟。通常，单元测试很慢，因为它们访问外部资源（例如数据库和文件）。

**隔离**：理想情况下，你应该能够随时以任何顺序运行任何测试。如果你的单元测试是隔离的，并且专注于小代码片段，这是可能的。良好的单元测试不依赖于其他单元测试，但这并不总是可实现的。尽量避免依赖链，因为当出现问题时它们是有害的，你将不得不进行调试。

**可重复**：单元测试应该是可重复的。这意味着单元测试的断言每次运行时都应该产生相同的结果。换句话说，单元测试不应该依赖于可能给断言引入可变结果的任何东西。

**自我验证**：单元测试应该是自我验证的。这意味着你不应该手动验证测试的结果。这是耗时的，并且会显示断言没有完成它们的工作。努力编写断言，使它们按预期工作。

及时：重要的是不要推迟编写单元测试。你推迟得越久，面对的缺陷就会越多。你会发现自己找不到时间回来编写单元测试。想想如果我们不断推迟倒垃圾会发生什么。我们推迟得越久，拿出来就会越困难，我们的健康也会受到风险。我有没有提到气味？所以，及时地编写单元测试。这是一个好习惯！

## 编码挑战 3 - 测试夹具

**问题**：什么是测试夹具？

**解决方案**：通过测试夹具，我们指的是任何存在于测试之外并用于设置应用程序的测试数据，以便它处于固定状态。应用程序的固定状态允许对其进行测试，并且处于一个恒定和已知的环境中。

## 编码挑战 4-异常测试

**问题**：在 JUnit 中测试异常的常见方法有哪些？

`try`/`catch`习语，`@Test`的`expected`元素，以及通过`ExpectedException`规则。

`try`/`catch`习语在 JUnit 3.x 中盛行，并且可以如下使用：

```java
@Test
public void givenStreamWhenGetThenException() {
  Stream<Integer> theStream = Stream.of();
  try {
    theStream.findAny().get();
    fail("Expected a NoSuchElementException to be thrown");
  } catch (NoSuchElementException ex) {
    assertThat(ex.getMessage(), is("No value present"));
  }
}
```

由于`fail()`抛出`AssertionError`，它不能用来测试这种错误类型。

从 JUnit 4 开始，我们可以使用`@Test`注解的`expected`元素。该元素的值是预期异常的类型（`Throwable`的子类）。查看以下示例，该示例使用了`expected`：

```java
@Test(expected = NoSuchElementException.class)
public void givenStreamWhenGetThenException() {
  Stream<Integer> theStream = Stream.of();
  theStream.findAny().get();
}
```

只要您不想测试异常消息的值，这种方法就可以。此外，请注意，如果任何代码行抛出`NoSuchElementException`，则测试将通过。您可能期望此异常是由特定代码行引起的，而实际上可能是由其他代码引起的。

另一种方法依赖于`ExpectedException`规则。从 JUnit 4.13 开始，此方法已被弃用。让我们看看代码：

```java
@Rule
public ExpectedException thrown = ExpectedException.none();
@Test
public void givenStreamWhenGetThenException() 
    throws NoSuchElementException {
  Stream<Integer> theStream = Stream.of();
  thrown.expect(NoSuchElementException.class);
  thrown.expectMessage("No value present");
  theStream.findAny().get();
}
```

通过这种方法，您可以测试异常消息的值。这些示例已被分组到一个名为*junit4/TestingExceptions*的应用程序中。

从 JUnit5 开始，我们可以使用两种方法来测试异常。它们都依赖于`assertThrows()`方法。此方法允许我们断言给定的函数调用（作为 lambda 表达式甚至作为方法引用传递）导致抛出预期类型的异常。以下示例不言自明：

```java
@Test
public void givenStreamWhenGetThenException() {
  assertThrows(NoSuchElementException.class, () -> {
    Stream<Integer> theStream = Stream.of();
    theStream.findAny().get();
  });
}
```

这个例子只验证了异常的类型。但是，由于异常已被抛出，我们可以断言抛出异常的更多细节。例如，我们可以断言异常消息的值如下：

```java
@Test
public void givenStreamWhenGetThenException() {
  Throwable ex = assertThrows(
    NoSuchElementException.class, () -> {
      Stream<Integer> theStream = Stream.of();
      theStream.findAny().get();
    });
  assertEquals(ex.getMessage(), "No value present");
}
```

只需使用`ex`对象来断言您认为从`Throwable`中有用的任何内容。每当您不需要断言有关异常的详细信息时，请依靠`assertThrows()`，而不捕获返回。这两个示例已被分组到一个名为*junit5/TestingExceptions*的应用程序中。

## 编码挑战 5-开发人员还是测试人员

**问题**：谁应该使用 JUnit-开发人员还是测试人员？

**解决方案**：通常，JUnit 由开发人员用于编写 Java 中的单元测试。编写单元测试是测试应用程序代码的编码过程。JUnit 不是一个测试过程。但是，许多测试人员愿意学习并使用 JUnit 进行单元测试。

## 编码挑战 6-JUnit 扩展

**问题**：您知道/使用哪些有用的 JUnit 扩展？

**解决方案**：最常用的 JUnit 扩展是 JWebUnit（用于 Web 应用程序的基于 Java 的测试框架）、XMLUnit（用于测试 XML 的单个 JUnit 扩展类）、Cactus（用于测试服务器端 Java 代码的简单测试框架）和 MockObject（模拟框架）。您需要对这些扩展中的每一个都说几句话。

## 编码挑战 7-@Before*和@After*注释

您知道/使用哪些`@Before*`/`@After*`注释？

`@Before`，`@BeforeClass`，`@After`和`@AfterClass`。

在每个测试之前执行方法时，我们使用`@Before`注解对其进行注释。这对于在运行测试之前执行常见的代码片段非常有用（例如，我们可能需要在每个测试之前执行一些重新初始化）。在每个测试之后清理舞台时，我们使用`@After`注解对方法进行注释。

当仅在所有测试之前执行一次方法时，我们使用`@BeforeClass`注解对其进行注释。该方法必须是`static`的。这对于全局和昂贵的设置非常有用，例如打开到数据库的连接。在所有测试完成后清理舞台时，我们使用`@AfterClass`注解对一个`static`方法进行注释；例如，关闭数据库连接。

您可以在名为*junit4/BeforeAfterAnnotations*的简单示例中找到一个简单的示例。

从 JUnit5 开始，我们有`@BeforeEach`作为`@Before`的等效项，`@BeforeAll`作为`@BeforeClass`的等效项。实际上，`@Before`和`@BeforeClass`被重命名为更具指示性的名称，以避免混淆。

您可以在名称为*junit5/BeforeAfterAnnotations*的简单示例中找到这个。

## 编码挑战 8 - 模拟和存根

**问题**：模拟和存根是什么？

**解决方案**：模拟是一种用于创建模拟真实对象的对象的技术。这些对象可以预先编程（或预设或预配置）期望，并且我们可以检查它们是否已被调用。在最广泛使用的模拟框架中，我们有 Mockito 和 EasyMock。

存根类似于模拟，只是我们无法检查它们是否已被调用。存根预先配置为使用特定输入产生特定输出。

## 编码挑战 9 - 测试套件

**问题**：什么是测试套件？

**解决方案**：测试套件是将多个测试聚合在多个测试类和包中，以便它们一起运行的概念。

在 JUnit4 中，我们可以通过`org.junit.runners.Suite`运行器和`@SuiteClasses(...)`注解来定义测试套件。例如，以下代码片段是一个聚合了三个测试（`TestConnect.class`，`TestHeartbeat.class`和`TestDisconnect.class`）的测试套件：

```java
@RunWith(Suite.class)
@Suite.SuiteClasses({
  TestConnect.class,
  TestHeartbeat.class,
  TestDisconnect.class
})
public class TestSuite {
    // this class was intentionally left empty
}
```

完整的代码称为*junit4/TestSuite*。

在 JUnit5 中，我们可以通过`@SelectPackages`和`@SelectClasses`注解来定义测试套件。

`@SelectPackages`注解对于从不同包中聚合测试非常有用。我们只需要指定包的名称，如下例所示：

```java
@RunWith(JUnitPlatform.class)
@SuiteDisplayName("TEST LOGIN AND CONNECTION")
@SelectPackages({
  "coding.challenge.connection.test",
  "coding.challenge.login.test"
})
public class TestLoginSuite {
  // this class was intentionally left empty
}
```

`@SelectClasses`注解对于通过类名聚合测试非常有用：

```java
@RunWith(JUnitPlatform.class)
@SuiteDisplayName("TEST CONNECTION")
@SelectClasses({
  TestConnect.class, 
  TestHeartbeat.class, 
  TestDisconnect.class
})
public class TestConnectionSuite {
  // this class was intentionally left empty
}
```

完整的代码称为*junit5/TestSuite*。

此外，可以通过以下注解来过滤测试包、测试类和测试方法：

+   过滤包：`@IncludePackages`和`@ExcludePackages`

+   过滤测试类：`@IncludeClassNamePatterns`和`@ExcludeClassNamePatterns`

+   过滤测试方法：`@IncludeTags`和`@ExcludeTags`

## 编码挑战 10 - 忽略测试方法

**问题**：如何忽略测试？

`@Ignore`注解。在 JUnit5 中，我们可以通过`@Disable`注解做同样的事情。

忽略测试方法在我们预先编写了一些测试并且希望在运行当前测试时不运行这些特定测试时是有用的。

## 编码挑战 11 - 假设

**问题**：什么是假设？

**解决方案**：假设用于执行测试，如果满足指定条件，则使用假设。它们通常用于处理测试执行所需的外部条件，但这些条件不在我们的控制范围之内，或者与被测试的内容不直接相关。

在 JUnit4 中，假设是可以在`org.junit.Assume`包中找到的`static`方法。在这些假设中，我们有`assumeThat()`，`assumeTrue()`和`assumeFalse()`。以下代码片段举例说明了`assumeThat()`的用法：

```java
@Test
public void givenFolderWhenGetAbsolutePathThenSuccess() {
  assumeThat(File.separatorChar, is('/'));
  assertThat(new File(".").getAbsolutePath(),
    is("C:/SBPBP/GitHub/Chapter18/junit4"));
}
```

如果`assumeThat()`不满足给定条件，则测试将被跳过。完整的应用程序称为*junit4/Assumptions*。

在 JUnit5 中，假设是可以在`org.junit.jupiter.api.Assumptions`包中找到的`static`方法。在这些假设中，我们有`assumeThat()`，`assumeTrue()`和`assumeFalse()`。所有三种都有不同的用法。以下代码片段举例说明了`assumeThat()`的用法：

```java
@Test
public void givenFolderWhenGetAbsolutePathThenSuccess() {
  assumingThat(File.separatorChar == '/',
   () -> {
     assertThat(new File(".").getAbsolutePath(), 
       is("C:/SBPBP/GitHub/Chapter18/junit5"));
   });
   // run these assertions always, just like normal test
   assertTrue(true);
}
```

请注意，测试方法（`assertThat()`）只有在满足假设时才会执行。lambda 之后的所有内容都将被执行，而不管假设的有效性如何。完整的应用程序称为*junit5/Assumptions*。

## 编码挑战 12 - @Rule

`@Rule`？

**解决方案**：JUnit 通过所谓的*规则*提供了高度的灵活性。规则允许我们创建和隔离对象（代码），并在多个测试类中重用这些代码。主要是通过可重用的规则增强测试。JUnit 提供了内置规则和可以用来编写自定义规则的 API。

## 编码挑战 13 - 方法测试返回类型

在 JUnit 测试方法中使用`void`？

将`void`转换为其他内容，但 JUnit 不会将其识别为测试方法，因此在测试执行期间将被忽略。

## 编码挑战 14 - 动态测试

**问题**：我们能在 JUnit 中编写动态测试（在运行时生成的测试）吗？

`@Test`是在编译时完全定义的静态测试。JUnit5 引入了动态测试 - 动态测试是在运行时生成的。

动态测试是通过一个工厂方法生成的，这个方法使用`@TestFactory`注解进行注释。这样的方法可以返回`DynamicTest`实例的`Iterator`、`Iterable`、`Collection`或`Stream`。工厂方法没有被`@Test`注解，并且不是`private`或`static`。此外，动态测试不能利用生命周期回调（例如，`@BeforeEach`和`@AfterEach`会被忽略）。

让我们看一个简单的例子：

```java
1: @TestFactory
2: Stream<DynamicTest> dynamicTestsExample() {
3:
4:   List<Integer> items = Arrays.asList(1, 2, 3, 4, 5);
5:
6:   List<DynamicTest> dynamicTests = new ArrayList<>();
7:
8:   for (int item : items) {
9:     DynamicTest dynamicTest = dynamicTest(
10:        "pow(" + item + ", 2):", () -> {
11:        assertEquals(item * item, Math.pow(item, 2));
12:    });
13:    dynamicTests.add(dynamicTest);
14:  }
15:
16:  return dynamicTests.stream();
17: }
```

现在，让我们指出主要的代码行：

`@TestFactory`注解来指示 JUnit5 这是一个动态测试的工厂方法。

`Stream<DynamicTest>`。

**4**：我们测试的输入是一个整数列表。对于每个整数，我们生成一个动态测试。

`List<DynamicTest>`。在这个列表中，我们添加每个生成的测试。

**8-12**：我们为每个整数生成一个测试。每个测试都有一个名称和包含必要断言的 lambda 表达式。

**13**：我们将生成的测试存储在适当的列表中。

测试的`Stream`。

运行这个测试工厂将产生五个测试。完整的例子被称为*junit5/TestFactory*。

## 编码挑战 15 - 嵌套测试

**问题**：我们能在 JUnit5 中编写嵌套测试吗？

`@Nested`注解。实际上，我们创建了一个嵌套测试类层次结构。这个层次结构可能包含设置、拆卸和测试方法。然而，我们必须遵守一些规则，如下：

+   嵌套测试类使用`@Nested`注解进行注释。

+   嵌套测试类是非`static`的内部类。

+   嵌套测试类可以包含一个`@BeforeEach`方法，一个`@AfterEach`方法和测试方法。

+   内部类中不允许使用`static`成员，这意味着嵌套测试中不能使用`@BeforeAll`和`@AfterAll`方法。

+   类层次结构的深度是无限的。

嵌套测试的一些示例代码可以在这里看到：

```java
@RunWith(JUnitPlatform.class)
public class NestedTest {
  private static final Logger log 
    = Logger.getLogger(NestedTest.class.getName());
  @DisplayName("Test 1 - not nested")
  @Test
  void test1() {
    log.info("Execute test1() ...");
  }
  @Nested
  @DisplayName("Running tests nested in class A")
  class A {
    @BeforeEach
    void beforeEach() {
      System.out.println("Before each test 
        method of the A class");
    }
    @AfterEach
    void afterEach() {
      System.out.println("After each test 
        method of the A class");
    }
    @Test
    @DisplayName("Test2 - nested in class A")
    void test2() {
      log.info("Execute test2() ...");
    }
  }
}
```

完整的例子被称为*junit5/NestedTests*。

# 总结

在本章中，我们涵盖了关于通过 JUnit4 和 JUnit5 进行单元测试的几个热门问题和编码挑战。不要忽视这个话题是很重要的。很可能，在 Java 开发人员或软件工程师职位的面试的最后部分，你会得到一些与测试相关的问题。此外，这些问题将与单元测试和 JUnit 相关。

在下一章中，我们将讨论与扩展和扩展相关的面试问题。


# 第十九章：系统可伸缩性

可伸缩性无疑是 Web 应用程序成功的最关键需求之一。应用程序的可伸缩能力取决于整个系统架构，而在构建项目时考虑可伸缩性是最佳选择。当业务的成功可能需要应用程序因大量流量而需要高度可伸缩时，您以后会非常感激。

因此，随着网络的发展，设计和构建可伸缩的应用程序也变得更加重要。在本章中，我们将涵盖您在初级/中级面试中可能会被问到的所有可伸缩性问题，比如 Web 应用程序软件架构师、Java 架构师或软件工程师等职位。如果您正在寻找的职位不涉及与软件架构和设计相关的任务，那么可伸缩性很可能不会成为面试话题。

本章的议程包括以下内容：

+   简而言之，可伸缩性

+   问题和编码挑战

让我们开始吧！

# 简而言之，可伸缩性

面试官最可预测但也最重要的问题是：什么是可伸缩性？可伸缩性是指一个过程（系统、网络、应用程序）应对工作负载增加的能力和能力（通过工作负载，我们理解任何推动系统极限的东西，如流量、存储容量、最大交易数量等），当添加资源（通常是硬件）时。可伸缩性可以表示系统性能提升与资源使用增加之间的比率。此外，可伸缩性还意味着能够在不影响/修改主节点结构的情况下添加额外的资源。

如果增加更多资源导致性能略微提高，甚至更糟的是，增加资源对性能没有影响，那么您面临所谓的*可伸缩性差*。

您如何实现可伸缩性？在涉及可伸缩性问题的面试中，您很可能也会被问到这个问题。给出一个一般、全面且不会花费太多时间的答案是最佳选择。应该触及的主要点包括以下内容：

+   **利用 12 要素**（https://12factor.net/）：这种方法与编程语言无关，对于交付灵活和可伸缩的应用程序非常有帮助。

+   **明智地实现持久性**：从为应用程序选择合适的数据库和开发最优化的模式，到掌握扩展持久层的技术（例如，集群、副本、分片等），这是值得您全部关注的关键方面之一。

+   **不要低估查询**：数据库查询是获取短事务的关键因素。调整连接池和查询以实现可伸缩性。例如，注意跨节点连接，这可能会迅速降低性能。

+   **选择托管和工具**：扩展不仅仅是代码！基础设施也非常重要。今天，许多云服务提供商（例如亚马逊）提供自动扩展和专用工具（Docker、Kubernetes 等）。

+   **考虑负载均衡和反向代理**：有一天，您必须从单服务器切换到多服务器架构。在云基础设施下运行（例如亚马逊），只需进行几项配置即可轻松提供这些设施（对于大多数云服务提供商，负载均衡和反向代理是*即插即用*的一部分）。否则，您必须为这一重大变化做好准备。

+   **缓存**：在扩展应用程序时，考虑新的缓存策略、拓扑和工具。

+   **减轻后端负担**：尽可能将尽可能多的计算从后端移到前端。这样，您可以减轻后端的工作负担。

+   **测试和监控**：测试和监控代码将帮助您尽快发现问题。

还有许多其他方面需要讨论，但在这一点上，面试官应该准备将面试推进到下一步。

# 问题和编码挑战

在本节中，我们涵盖了 13 个问题和编码挑战，这些问题和挑战在初中级可扩展性面试中是必须了解的。让我们开始吧！

## 编码挑战 1 - 扩展类型

**问题**：扩展和扩展意味着什么？

**解决方案**：扩展（或纵向扩展）是通过向现有系统添加更多资源来实现更好的性能并成功应对更大的工作负载。通过资源，我们可以理解更多的存储、更多的内存、更多的网络、更多的线程、更多的连接、更强大的主机、更多的缓存等。添加新资源后，应用程序应能够遵守服务级别协议。今天，在云中扩展是非常高效和快速的。像 AWS、Azure、Oracle、Heroku、Google Cloud 等云可以根据阈值计划自动分配更多的资源，仅需几分钟。当流量减少时，AWS 可以禁用这些额外的资源。这样，您只需支付您使用的部分。

扩展（或横向扩展）通常与分布式架构相关。有两种基本形式的扩展：

+   在预打包的基础设施/节点块中增加更多的基础设施容量（例如，超融合）。

+   使用独立的分布式服务来收集有关客户的信息。

通常，扩展是通过添加更多与当前使用的相同类型或任何兼容类型的服务器或 CPU 来完成的。扩展使服务提供商能够为客户提供“按需增长”的基础设施和服务。扩展速度相当快，因为不需要导入或重建任何东西。然而，扩展速度受服务器通信速度的限制。

像 AWS 这样的云可以根据阈值计划自动分配更多的基础设施，仅需几分钟。当流量较低时，AWS 可以禁用这些额外的基础设施。这样，您只需支付您使用的部分。

通常，扩展提供比扩展更好的性能。

## 编码挑战 2 - 高可用性

**问题**：什么是高可用性？

**解决方案**：高可用性和低延迟对于许多企业来说至关重要。

通常以一年中的正常运行时间的百分比来表示，当应用程序在没有中断的情况下对用户可用时，就实现了高可用性（在一年内 99.9%的时间内）。

通过集群实现高可用性是常见的。

## 编码挑战 3 - 低延迟

**问题**：什么是低延迟？

**解决方案**：低延迟是与计算机网络相关的术语，它被优化为以最小的延迟或延迟处理极高数量的数据。这样的网络被设计和构建用于处理试图实现几乎实时数据处理能力的操作。

## 编码挑战 4 - 集群

**问题**：什么是集群，为什么我们需要集群？

**解决方案**：集群是一组可以单独运行应用程序的机器。我们可以有应用程序服务器集群、数据库服务器集群等。

拥有集群显著降低了我们的服务在集群中的一台机器失败时变得不可用的机会。换句话说，集群的主要目的是实现 100%的可用性或服务的零停机时间（高可用性 - 见*编码挑战 2*）。当然，所有集群机器同时失败的可能性仍然很小，但通常通过将机器放置在不同的位置或由它们自己的资源支持来减轻这种可能性。

## 编码挑战 5 - 延迟、带宽和吞吐量

**问题**：什么是延迟、带宽和吞吐量？

**解决方案**：在面试中解释这些概念的最佳方法是使用下图中的管道进行简单类比：

![图 19.1 – 延迟与带宽与吞吐量](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_19.1_B15403.jpg)

图 19.1 – 延迟与带宽与吞吐量

**延迟**是通过管道传输所需的时间，而不是管道长度。但是，它作为管道长度的函数来衡量。

**带宽**是管道有多宽。

**吞吐量**是通过管道流动的水量。

## 编码挑战 6 – 负载均衡

**问题**：什么是负载均衡？

**解决方案**：负载均衡是一种用于在多台机器或集群之间分配工作负载的技术。在负载均衡使用的算法中，有循环轮询、粘性会话（或会话亲和性）和 IP 地址亲和性。常见且简单的算法是循环轮询，它按循环顺序分配工作负载，确保所有可用的机器获得相等数量的请求，没有一台机器过载或负载不足。

例如，下图标记了典型主从架构中负载均衡器的位置：

![图 19.2 – 主从架构中的负载均衡器](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_19.2_B15403.jpg)

图 19.2 – 主从架构中的负载均衡器

通过在机器之间分配工作，负载均衡力求实现最大吞吐量和响应时间。

## 编码挑战 7 – 粘性会话

**问题**：什么是粘性会话（或会话亲和性）？

**解决方案**：粘性会话（或会话亲和性）是负载均衡器中遇到的一个概念。通常，用户信息存储在会话中，并且会话在集群中的所有机器上都有副本。但是会话复制（参见*编码挑战 11*）可以通过从同一台机器为特定用户会话请求提供服务来避免。

因此，会话与机器关联。这发生在会话创建时。对于此会话的所有传入请求始终重定向到关联的机器。用户数据仅在该机器上。

在 Java 中，粘性会话通常通过`jsessionid` cookie 来实现。在第一次请求时，cookie 被发送到客户端。对于每个后续请求，客户端请求也包含 cookie。这样，cookie 标识了会话。

粘性会话方法的主要缺点在于，如果机器失败，则用户信息丢失，该会话无法恢复。如果客户端浏览器不支持 cookie 或禁用 cookie，则无法通过 cookie 实现粘性会话。

## 编码挑战 8 – 分片

**问题**：什么是分片？

**解决方案**：分片是一种将单个逻辑数据库系统分布在一组机器上的架构技术。下图描述了这种说法：

![图 19.3 – 分片](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_19.3_B15403.jpg)

图 19.3 – 分片

如前面的图所示，分片是关于数据库方案的水平分区。主要是将数据库表（例如`teams`）的行分别存储（例如，西数据中心保存奇数行，而东数据中心保存偶数行），而不是将表分割为列（将表分割为列称为规范化和垂直分区）。

每个分区称为*分片*。从前面的图中可以看出，每个分片可以独立地位于物理位置或单独的数据库服务器上。

分片的目标是使数据库系统具有高度可伸缩性。每个分片中的行数较少，减少了索引大小，并提高了读取/搜索操作的性能。

分片的缺点如下：

+   应用程序必须知道数据的位置。

+   向系统添加/删除节点需要重新平衡系统。

+   跨节点连接查询会带来性能惩罚。

## 编码挑战 9 – 无共享架构

**问题**：什么是无共享架构？

**解决方案**：无共享架构（标记为**SN**）是一种分布式计算技术，它认为每个节点都是独立的，并包含其需要具有自治权的一切。此外，系统中不需要任何单一的争用点。SN 架构的主要方面包括以下内容：

+   节点独立工作。

+   节点之间没有共享资源（内存、文件等）。

+   如果一个节点失败，那么它只影响其用户（其他节点继续工作）。

具有线性和理论上无限的可扩展性，SN 架构非常受欢迎。谷歌是依赖 SN 的主要参与者之一。

## 编码挑战 10 - 故障转移

**问题**：什么是故障转移？

**解决方案**：故障转移是一种通过在集群中的另一台机器上切换来实现高可用性的技术。通常，故障转移是通过负载均衡器自动应用的，通过心跳检查机制。主要是通过负载均衡器检查机器的可用性，确保它们响应。如果某台机器的心跳失败（机器没有响应），那么负载均衡器就不会向其发送任何请求，并将请求重定向到集群中的另一台机器。

## 编码挑战 11 - 会话复制

**问题**：什么是会话复制？

**解决方案**：会话复制通常出现在应用服务器集群中，其主要目标是实现会话故障转移。

会话复制是每次用户更改其当前会话时应用的。主要是，用户会话会自动复制到集群中的其他机器。这样，如果一台机器失败，负载均衡器会将传入的请求发送到集群中的另一台机器。由于集群中的每台机器都有用户会话的副本，负载均衡器可以选择其中任何一台机器。

虽然会话复制可以维持会话故障转移，但在内存和网络带宽方面可能会有额外的成本。

## 编码挑战 12 - CAP 定理

**问题**：CAP 定理是什么？

**解决方案**：CAP 定理由 Eric Brewer 发布，专门针对分布式计算。根据这个定理，分布式计算系统只能同时提供以下三个中的两个：

+   **一致性**：并发更新对所有节点都是可用的。

+   **可用性**：每个请求都会收到成功或失败的响应。

+   **分区容忍性**：系统在部分故障的情况下仍然可以运行。

以下图描述了 CAP 定理：

![图 19.4 - CAP 定理](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_19.4_B15403.jpg)

图 19.4 - CAP 定理

谷歌、Facebook 和亚马逊等公司使用 CAP 定理来决定其应用架构。

## 编码挑战 13 - 社交网络

**问题**：您将如何为像 Facebook 这样的社交网络设计数据结构？描述一种算法来显示两个人之间的最短路径（例如，Tom → Alice → Mary → Kely）。

**解决方案**：通常，社交网络是使用图来设计的。结果是一个庞大的图，如下图所示（此图是通过 Google 图像通过*社交网络图*关键字收集的）：

![图 19.5 - 社交网络图](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_19.5_B15403.jpg)

图 19.5 - 社交网络图

因此，找到两个人之间的路径意味着在这样的图中找到一条路径。在这种情况下，问题就变成了如何在这样一个庞大的图中高效地找到两个节点之间的路径。

我们可以从一个人开始，遍历图来找到另一个人。遍历图可以使用**BFS**（**广度优先搜索**）或**DFS**（**深度优先搜索**）来完成。有关这些算法的更多细节，请查看*第十三章*，*树和图*。

DFS 将非常低效！两个人可能只相隔一度，但 DFS 可能在找到这种相对即时的连接之前遍历数百万个节点（人）。

因此，胜利者是 BFS。更确切地说，我们可以采用双向 BFS。就像两列火车从相反的方向开来，在某个时刻相交一样，我们使用一个从人*A*（源）开始的 BFS，和一个从人*B*（目的地）开始的 BFS。当搜索相撞时，我们找到了*A*和*B*之间的路径。

为什么不使用单向 BFS？因为从*A*到*B*会遍历*p+p*p*人。主要是，单向 BFS 将遍历*A*的*p*个朋友，然后是每个朋友的*p*个朋友。这意味着对于长度为*q*的路径，单向 BFS 将在 O(pq)的运行时间内执行。另一方面，双向 BFS 遍历 2*p*个节点：每个*A*的*p*个朋友和每个*B*的*p*个朋友。这意味着对于长度为*q*的路径，双向 BFS 执行 O(pq/2+ pq/2) = O(pq/2)。显然，O(pq/2)比 O(pq)更好。

让我们考虑一个路径，比如 Ana -> Bob -> Carla -> Dan -> Elvira，每个人都有 100 个朋友。单向 BFS 将遍历 1 亿（1004）个节点。双向 BFS 只会遍历 2 万个节点（2 x 1002）。

找到连接*A*和*B*的有效方法只是其中一个问题。另一个问题是由于人数众多，当数据量如此之大以至于无法存储在一台机器上时。这意味着我们的图将使用多台机器（例如，一个集群）。如果我们将用户列表表示为 ID 列表，那么我们可以使用分片并在每台机器上存储 ID 范围。这样，我们通过首先进入包含该人 ID 的机器来沿着路径前进到下一个人。

为了减少在机器之间的大量随机跳跃，这将降低性能，我们可以通过考虑国家、城市、州等来分布用户到机器上。同一个国家的用户更有可能成为朋友。

需要回答的更多问题包括缓存使用、何时停止没有结果的搜索、如果机器出现故障该怎么办等等。

很明显，解决前述问题等问题并不是一件容易的事。这需要解决很多问题和问题，因此阅读和尽可能多地实践是必须的。

# 实践是成功的关键

这个简短章节的主题值得一本整书。但是，挑战自己解决以下前 10 个问题将增强您对可扩展性的见解，并增加成为软件工程师的机会。

## 设计 bitly、TinyURL 和 goo.gl（用于缩短 URL 的服务）

需要解决的问题：

+   如何为每个给定的 URL 分配一个唯一的标识符（ID）？

+   每秒有数千个 URL，如何在规模上生成唯一的标识符（ID）？

+   如何处理重定向？

+   如何处理自定义短 URL？

+   如何处理过期的 URL（删除它们）？

+   如何跟踪统计数据（例如，点击统计）？

## 设计 Netflix、Twitch 和 YouTube（全球视频流服务）

需要解决的问题：

+   如何存储和分发数据以适应大量同时用户（用户可以观看和分享数据）？

+   如何跟踪统计数据（例如，总浏览次数、投票等）？

+   如何允许用户在视频上添加评论（最好是实时的）？

## 设计 WhatsApp 和 Facebook Messenger（全球聊天服务）

需要解决的问题：

+   如何设计用户之间的一对一对话/会议？

+   如何设计群聊/会议？

+   如何处理离线用户（未连接到互联网）？

+   何时发送推送通知？

+   如何支持端到端加密？

## 设计 Reddit、HackerNews、Quora 和 Voat（留言板服务和社交网络）

需要解决的问题：

+   如何跟踪每个答案的统计数据（总浏览次数、投票等）？

+   如何允许用户关注其他用户或主题？

+   如何设计包含用户热门问题的时间线（类似于新闻源生成）？

## 设计谷歌云盘、谷歌相册和 Dropbox（全球文件存储和共享服务）

需要解决的问题：

+   如何设计用户功能，如上传、搜索、查看和共享文件/照片？

+   如何跟踪文件共享的权限？

+   如何允许一组用户编辑同一文档？

## 设计 Twitter、Facebook 和 Instagram（一个非常大的社交媒体服务）

需要解决的问题：

+   如何高效存储和搜索帖子/推文？

+   如何实现新闻源生成？

+   如何解决社交图（参见*编码挑战 13*）？

## 设计 Lyft、Uber 和 RideAustin（共乘服务）

需要解决的问题：

+   如何将乘车请求与附近的司机匹配？

+   如何为不断移动的乘客和司机存储数百万个位置（地理坐标）？

+   如何更新驾驶员/乘客位置（每秒更新一次）？

## 设计类型提前和网络爬虫（与搜索引擎相关的服务）

需要解决的问题：

+   如何刷新数据？

+   如何存储先前的搜索查询？

+   如何检测已输入字符串的最佳匹配？

+   当用户输入速度过快时，如何解决？

+   如何找到新页面（网页）？

+   如何为动态变化的网页分配优先级？

+   如何确保爬虫不会永远卡在同一个域上？

## 设计 API 速率限制器（例如 GitHub 或 Firebase）

需要解决的问题：

+   如何限制在时间窗口内的请求数量（例如，每秒 30 个请求）？

+   如何实现在服务器集群中工作的速率限制？

+   如何解决限流（软限流和硬限流）？

## 设计附近的地方/朋友和 Yelp（一个临近服务器）

需要解决的问题：

+   如何搜索附近的朋友或地点？

+   如何对地点进行排名？

+   如何根据人口密度存储位置数据？

回答这些挑战并不是一件容易的事，需要丰富的经验。然而，如果你是一名初级/中级程序员，并且已经阅读了关于可扩展性的介绍性章节，那么你应该能够决定你的职业道路是否应该朝这个方向发展。然而，请记住，设计大规模分布式系统是软件工程面试中一个非常苛刻的领域。

# 总结

这是本书的最后一章。我们刚刚涵盖了一系列与可扩展性主题相关的问题。

恭喜你走到了这一步！现在，在本书的最后，记得尽可能多地练习，对自己的判断有信心，永不放弃！我真诚地希望你的下一个 Java 职位能给你带来梦想的工作，而这本书能为你的成功做出贡献。
