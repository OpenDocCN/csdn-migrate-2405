# 精通 Java8 并发编程（二）

> 原文：[`zh.annas-archive.org/md5/BFECC9856BE4118734A8147A2EEBA11A`](https://zh.annas-archive.org/md5/BFECC9856BE4118734A8147A2EEBA11A)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第三章：从执行者中获得最大效益

在第二章中，*管理大量线程-执行者*，我们介绍了执行者的基本特性，作为改进执行大量并发任务的并发应用程序性能的一种方式。在本章中，我们将进一步解释执行者的高级特性，使它们成为您并发应用程序的强大工具。在本章中，我们将涵盖以下内容：

+   执行者的高级特性

+   第一个例子-高级服务器应用程序

+   第二个例子-执行周期性任务

+   有关执行者的其他信息

# 执行者的高级特性

执行者是一个允许程序员执行并发任务而不必担心线程的创建和管理的类。程序员创建`Runnable`对象并将它们发送到执行者，执行者创建和管理必要的线程来执行这些任务。在第二章中，*管理大量线程-执行者*，我们介绍了执行者框架的基本特性：

+   如何创建执行者以及我们创建执行者时的不同选项

+   如何将并发任务发送到执行者

+   如何控制执行者使用的资源

+   执行者在内部如何使用线程池来优化应用程序的性能

但是，执行者可以为您提供更多选项，使其成为并发应用程序中的强大机制。

## 取消任务

您可以在将任务发送到执行者后取消任务的执行。使用`submit()`方法将`Runnable`对象发送到执行者时，它返回`Future`接口的实现。这个类允许您控制任务的执行。它具有`cancel()`方法，尝试取消任务的执行。它接收一个布尔值作为参数。如果它采用`true`值并且执行者正在执行此任务，则将中断执行任务的线程。

以下是您希望取消的任务无法取消的情况：

+   任务已经被取消

+   任务已经完成执行

+   任务正在运行，并且您向`cancel()`方法提供了`false`作为参数

+   API 文档中未指定的其他原因

`cancel()`方法返回一个布尔值，指示任务是否已取消。

## 安排任务的执行

`ThreadPoolExecutor`类是`Executor`和`ExecutorService`接口的基本实现。但是，Java 并发 API 提供了这个类的扩展，以允许执行计划任务。这是`ScheduledThreadPoolExeuctor`类，您可以：

+   在延迟后执行任务

+   定期执行任务；这包括以固定速率或固定延迟执行任务

## 重写执行者方法

执行者框架是一个非常灵活的机制。您可以实现自己的执行者，扩展现有类（`ThreadPoolExecutor`或`ScheduledThreadPoolExecutor`）以获得所需的行为。这些类包括使更改执行者工作方式变得容易的方法。如果您重写`ThreadPoolExecutor`，可以重写以下方法：

+   `beforeExecute()`：此方法在执行者中的并发任务执行之前调用。它接收将要执行的`Runnable`对象和将执行它们的`Thread`对象。此方法接收的`Runnable`对象是`FutureTask`类的实例，而不是使用`submit()`方法将`Runnable`对象发送到执行者的`Runnable`对象。

+   `afterExecute()`: 这个方法在执行器中的并发任务执行后被调用。它接收到已执行的`Runnable`对象和一个存储可能在任务内部抛出的异常的`Throwable`对象。与`beforeExecute()`方法一样，`Runnable`对象是`FutureTask`类的一个实例。

+   `newTaskFor()`: 这个方法创建将要执行`submit()`方法发送的`Runnable`对象的任务。它必须返回`RunnableFuture`接口的一个实现。默认情况下，Open JDK 8 和 Oracle JDK 8 返回`FutureTask`类的一个实例，但这种情况在将来的实现中可能会改变。

如果您扩展了`ScheduledThreadPoolExecutor`类，可以重写`decorateTask()`方法。这个方法类似于用于计划任务的`newTaskFor()`方法。它允许您重写执行器执行的任务。

## 更改一些初始化参数

您还可以通过更改创建时的一些参数来更改执行器的行为。最有用的是：

+   `BlockingQueue<Runnable>`: 每个执行器都使用内部的`BlockingQueue`来存储等待执行的任务。您可以将此接口的任何实现作为参数传递。例如，您可以更改执行任务的默认顺序。

+   `ThreadFactory`: 您可以指定`ThreadFactory`接口的一个实现，执行器将使用该工厂来创建执行任务的线程。例如，您可以使用`ThreadFactory`接口来创建`Thread`类的扩展，该扩展保存有关任务执行时间的日志信息。

+   `RejectedExecutionHandler`: 在调用`shutdown()`或`shutdownNow()`方法之后，发送到执行器的所有任务都将被拒绝。您可以指定`RejectedExecutionHandler`接口的一个实现来管理这种情况。

# 第一个示例 - 高级服务器应用程序

在第二章中，*管理大量线程 - 执行器*，我们介绍了一个客户端/服务器应用程序的示例。我们实现了一个服务器来搜索世界银行的世界发展指标数据，并且一个客户端对该服务器进行多次调用以测试执行器的性能。

在本节中，我们将扩展该示例以添加以下特性：

+   您可以使用新的取消查询取消服务器上的查询执行。

+   您可以使用优先级参数控制查询的执行顺序。具有更高优先级的任务将首先执行。

+   服务器将计算使用服务器的不同用户使用的任务数量和总执行时间。

为了实现这些新特性，我们对服务器进行了以下更改：

+   我们为每个查询添加了两个参数。第一个是发送查询的用户的名称，另一个是查询的优先级。查询的新格式如下：

+   **查询**: `q;username;priority;codCountry;codIndicator;year`，其中`username`是用户的名称，`priority`是查询的优先级，`codCountry`是国家代码，`codIndicator`是指标代码，`year`是一个可选参数，用于查询的年份。

+   **报告**: `r;username;priority;codIndicator`，其中`username`是用户的名称，`priority`是查询的优先级，`codIndicator`是您要报告的指标代码。

+   **状态**: `s;username;priority`，其中`username`是用户的名称，`priority`是查询的优先级。

+   **停止**: `z;username;priority`，其中`username`是用户的名称，`priority`是查询的优先级。

+   我们已经实现了一个新的查询：

+   **取消**：`c;username;priority`，其中`username`是用户的名称，`priority`是查询的优先级。

+   我们实现了自己的执行器来：

+   计算每个用户的服务器使用情况

+   按优先级执行任务

+   控制任务的拒绝

+   我们已经调整了`ConcurrentServer`和`RequestTask`以考虑服务器的新元素

服务器的其余元素（缓存系统、日志系统和`DAO`类）都是相同的，因此不会再次描述。

## ServerExecutor 类

正如我们之前提到的，我们实现了自己的执行器来执行服务器的任务。我们还实现了一些额外但必要的类来提供所有功能。让我们描述这些类。

### 统计对象

我们的服务器将计算每个用户在其上执行的任务数量以及这些任务的总执行时间。为了存储这些数据，我们实现了`ExecutorStatistics`类。它有两个属性来存储信息：

```java
public class ExecutorStatistics {
    private AtomicLong executionTime = new AtomicLong(0L);
    private AtomicInteger numTasks = new AtomicInteger(0);
```

这些属性是`AtomicVariables`，支持对单个变量的原子操作。这允许您在不使用任何同步机制的情况下在不同的线程中使用这些变量。然后，它有两种方法来增加任务数量和执行时间：

```java
    public void addExecutionTime(long time) {
        executionTime.addAndGet(time);
    }
    public void addTask() {
        numTasks.incrementAndGet();
    }
```

最后，我们添加了获取这两个属性值的方法，并重写了`toString()`方法以便以可读的方式获取信息：

```java
    @Override
    public String toString() {
        return "Executed Tasks: "+getNumTasks()+". Execution Time: "+getExecutionTime();
    }
```

### 被拒绝的任务控制器

当您创建一个执行器时，可以指定一个类来管理其被拒绝的任务。当您在执行器中调用`shutdown()`或`shutdownNow()`方法后提交任务时，执行器会拒绝该任务。

为了控制这种情况，我们实现了`RejectedTaskController`类。这个类实现了`RejectedExecutionHandler`接口，并实现了`rejectedExecution()`方法：

```java
public class RejectedTaskController implements RejectedExecutionHandler {

    @Override
    public void rejectedExecution(Runnable task, ThreadPoolExecutor executor) {
        ConcurrentCommand command=(ConcurrentCommand)task;
        Socket clientSocket=command.getSocket();
        try {
            PrintWriter out = new PrintWriter(clientSocket.getOutputStream(),true);

            String message="The server is shutting down."
                +" Your request can not be served."
                +" Shutting Down: "
                +String.valueOf(executor.isShutdown())
                +". Terminated: "
                +String.valueOf(executor.isTerminated())
                +". Terminating: "
                +String.valueOf(executor.isTerminating());
            out.println(message);
            out.close();
            clientSocket.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
```

`rejectedExecution()`方法每拒绝一个任务调用一次，并接收被拒绝的任务和拒绝任务的执行器作为参数。

### 执行器任务

当您向执行器提交一个`Runnable`对象时，它不会直接执行该`Runnable`对象。它会创建一个新对象，即`FutureTask`类的实例，正是这个任务由执行器的工作线程执行。

在我们的情况下，为了测量任务的执行时间，我们在`ServerTask`类中实现了我们自己的`FutureTask`实现。它扩展了`FutureTask`类，并实现了`Comparable`接口，如下所示：

```java
public class ServerTask<V> extends FutureTask<V> implements Comparable<ServerTask<V>>{
```

在内部，它将要执行的查询存储为`ConcurrentCommand`对象：

```java
    private ConcurrentCommand command;
```

在构造函数中，它使用`FutureTask`类的构造函数并存储`ConcurrentCommand`对象：

```java
    public ServerTask(ConcurrentCommand command) {
        super(command, null);
        this.command=command;
    }

    public ConcurrentCommand getCommand() {
        return command;
    }

    public void setCommand(ConcurrentCommand command) {
        this.command = command;
    }
```

最后，它实现了`compareTo()`操作，比较两个`ServerTask`实例存储的命令。这可以在以下代码中看到：

```java
    @Override
    public int compareTo(ServerTask<V> other) {
        return command.compareTo(other.getCommand());
    }
```

### 执行器

现在我们有了执行器的辅助类，我们必须实现执行器本身。我们实现了`ServerExecutor`类来实现这个目的。它扩展了`ThreadPoolExecutor`类，并具有一些内部属性，如下所示：

+   `startTimes`：这是一个`ConcurrentHashMap`，用于存储每个任务的开始日期。类的键将是`ServerTask`对象（一个`Runnable`对象），值将是一个`Date`对象。

+   `executionStatistics`：这是一个`ConcurrentHashMap`，用于存储每个用户的使用统计。键将是用户名，值将是一个`ExecutorStatistics`对象。

+   `CORE_POOL_SIZE`，`MAXIMUM_POOL_SIZE`和`KEEP_ALIVE_TIME`：这些是用于定义执行器特性的常量。

+   `REJECTED_TASK_CONTROLLER`: 这是一个`RejectedTaskController`类的属性，用于控制执行器拒绝的任务。

这可以通过以下代码来解释：

```java
public class ServerExecutor extends ThreadPoolExecutor {
    private ConcurrentHashMap<Runnable, Date> startTimes;
    private ConcurrentHashMap<String, ExecutorStatistics> executionStatistics;
    private static int CORE_POOL_SIZE = Runtime.getRuntime().availableProcessors();
    private static int MAXIMUM_POOL_SIZE = Runtime.getRuntime().availableProcessors();
    private static long KEEP_ALIVE_TIME = 10;

    private static RejectedTaskController REJECTED_TASK_CONTROLLER = new RejectedTaskController();

    public ServerExecutor() {
        super(CORE_POOL_SIZE, MAXIMUM_POOL_SIZE, KEEP_ALIVE_TIME, TimeUnit.SECONDS, new PriorityBlockingQueue<>(), REJECTED_TASK_CONTROLLER);

        startTimes = new ConcurrentHashMap<>();
        executionStatistics = new ConcurrentHashMap<>();
    }
```

该类的构造函数调用父类构造函数，创建一个`PriorityBlockingQueue`类来存储将在执行器中执行的任务。该类根据`compareTo()`方法的执行结果对元素进行排序（因此存储在其中的元素必须实现`Comparable`接口）。使用此类将允许我们按优先级执行任务。

然后，我们重写了`ThreadPoolExecutor`类的一些方法。首先是`beforeExecute()`方法。该方法在每个任务执行之前执行。它接收`ServerTask`对象作为参数，以及将要执行任务的线程。在我们的情况下，我们使用`ConcurrentHashMap`存储每个任务的开始日期：

```java
    protected void beforeExecute(Thread t, Runnable r) {
        super.beforeExecute(t, r);
        startTimes.put(r, new Date());
    }
```

下一个方法是`afterExecute()`方法。该方法在执行器中每个任务执行后执行，并接收已执行的`ServerTask`对象作为参数和一个`Throwable`对象。只有在任务执行过程中抛出异常时，最后一个参数才会有值。在我们的情况下，我们将使用此方法来：

+   计算任务的执行时间。

+   以以下方式更新用户的统计信息：

```java
    @Override
    protected void afterExecute(Runnable r, Throwable t) {
        super.afterExecute(r, t);
        ServerTask<?> task=(ServerTask<?>)r;
        ConcurrentCommand command=task.getCommand();

        if (t==null) {
            if (!task.isCancelled()) {
                Date startDate = startTimes.remove(r);
                Date endDate=new Date();
                long executionTime= endDate.getTime() - startDate.getTime();
                            ;
                ExecutorStatistics statistics = executionStatistics.computeIfAbsent (command.getUsername(), n -> new ExecutorStatistics());
                statistics.addExecutionTime(executionTime);
                statistics.addTask();
                ConcurrentServer.finishTask (command.getUsername(), command);
            }
            else {

                String message="The task" + command.hashCode() + "of user" + command.getUsername() + "has been cancelled.";
                Logger.sendMessage(message);
            }

        } else {

            String message="The exception "
                    +t.getMessage()
                    +" has been thrown.";
            Logger.sendMessage(message);
        }
    }
```

最后，我们重写了`newTaskFor()`方法。该方法将被执行，将我们通过`submit()`方法发送到执行器的`Runnable`对象转换为由执行器执行的`FutureTask`实例。在我们的情况下，我们将默认的`FutureTask`类替换为我们的`ServerTask`对象：

```java
    @Override
    protected <T> RunnableFuture<T> newTaskFor(Runnable runnable, T value) {
        return new ServerTask<T>(runnable);
    }
```

我们在执行器中包含了一个额外的方法，用于将执行器中存储的所有统计信息写入日志系统。此方法将在服务器执行结束时调用，稍后您将看到。我们有以下代码：

```java
    public void writeStatistics() {

        for(Entry<String, ExecutorStatistics> entry: executionStatistics.entrySet()) {
             String user = entry.getKey();
             ExecutorStatistics stats = entry.getValue(); Logger.sendMessage(user+":"+stats);
        }
    }
```

## 命令类

命令类执行您可以发送到服务器的不同查询。您可以向我们的服务器发送五种不同的查询：

+   **查询**：这是用于获取有关国家、指标和可选年份的信息的命令。由`ConcurrentQueryCommand`类实现。

+   **报告**：这是用于获取有关指标的信息的命令。由`ConcurrentReportCommand`类实现。

+   **状态**：这是用于获取服务器状态信息的命令。由`ConcurrentStatusCommand`类实现。

+   **取消**：这是用于取消用户任务执行的命令。由`ConcurrentCancelCommand`类实现。

+   **停止**：这是用于停止服务器执行的命令。由`ConcurrentStopCommand`类实现。

我们还有`ConcurrentErrorCommand`类，用于处理服务器接收到未知命令的情况，以及`ConcurrentCommand`类，它是所有命令的基类。

### ConcurrentCommand 类

这是每个命令的基类。它包括所有命令共有的行为，包括以下内容：

+   调用实现每个命令特定逻辑的方法

+   将结果写入客户端

+   关闭通信中使用的所有资源

该类扩展了`Command`类，并实现了`Comparable`和`Runnable`接口。在第二章的示例中，命令是简单的类，但在这个示例中，并发命令是将发送到执行器的`Runnable`对象：

```java
public abstract class ConcurrentCommand extends Command implements Comparable<ConcurrentCommand>, Runnable{
```

它有三个属性：

+   `username`：这是用于存储发送查询的用户的名称。

+   `priority`：这是用于存储查询的优先级。它将确定查询的执行顺序。

+   `socket`：这是与客户端通信中使用的套接字。

该类的构造函数初始化了这些属性：

```java
    private String username;
    private byte priority;
    private Socket socket;

    public ConcurrentCommand(Socket socket, String[] command) {
        super(command);
        username=command[1];
        priority=Byte.parseByte(command[2]);
        this.socket=socket;

    }
```

这个类的主要功能在抽象的`execute()`方法中，每个具体命令都将通过该方法来计算和返回查询的结果，并且在`run()`方法中。`run()`方法调用`execute()`方法，将结果存储在缓存中，将结果写入套接字，并关闭通信中使用的所有资源。我们有以下内容：

```java
    @Override
    public abstract String execute();

    @Override
    public void run() {

        String message="Running a Task: Username: "
                +username
                +"; Priority: "
                +priority;
        Logger.sendMessage(message);

        String ret=execute();

        ParallelCache cache = ConcurrentServer.getCache();

        if (isCacheable()) {
            cache.put(String.join(";",command), ret);
        }

        try {
            PrintWriter out = new PrintWriter(socket.getOutputStream(),true);
            out.println(ret);
            socket.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
        System.out.println(ret);
    }
```

最后，`compareTo()`方法使用优先级属性来确定任务的顺序。这将被`PriorityBlockingQueue`类用来对任务进行排序，因此具有更高优先级的任务将首先执行。请注意，当`getPriority()`方法返回较低的值时，任务的优先级更高。如果任务的`getPriority()`返回`1`，那么该任务的优先级将高于`getPriority()`方法返回`2`的任务：

```java
    @Override
    public int compareTo(ConcurrentCommand o) {
        return Byte.compare(o.getPriority(), this.getPriority());
    }
```

### 具体命令

我们对实现不同命令的类进行了微小的更改，并添加了一个由`ConcurrentCancelCommand`类实现的新命令。这些类的主要逻辑包含在`execute()`方法中，该方法计算查询的响应并将其作为字符串返回。

新的`ConcurrentCancelCommand`的`execute()`方法调用`ConcurrentServer`类的`cancelTasks()`方法。此方法将停止与作为参数传递的用户相关的所有待处理任务的执行：

```java
    @Override
    public String execute() {
        ConcurrentServer.cancelTasks(getUsername());

        String message = "Tasks of user "
                +getUsername()
                +" has been cancelled.";
        Logger.sendMessage(message);
        return message;
    }
```

`ConcurrentReportCommand`的`execute()`方法使用`WDIDAO`类的`query()`方法来获取用户请求的数据。在第二章中，*管理大量线程-执行者*，您可以找到此方法的实现。实现几乎相同。唯一的区别是命令数组索引如下：

```java
    @Override
    public String execute() {

        WDIDAO dao=WDIDAO.getDAO();

        if (command.length==5) {
            return dao.query(command[3], command[4]);
        } else if (command.length==6) {
            try {
                return dao.query(command[3], command[4], Short.parseShort(command[5]));
            } catch (NumberFormatException e) {
                return "ERROR;Bad Command";
            }
        } else {
            return "ERROR;Bad Command";
        }
    }
```

`ConcurrentQueryCommand`的`execute()`方法使用`WDIDAO`类的`report()`方法来获取数据。在第二章中，*管理大量线程-执行者*，您还可以找到此方法的实现。这里的实现几乎相同。唯一的区别是命令数组索引：

```java
    @Override
    public String execute() {

        WDIDAO dao=WDIDAO.getDAO();
        return dao.report(command[3]);
    }
```

`ConcurrentStatusCommand`在其构造函数中有一个额外的参数：`Executor`对象，它将执行命令。此命令使用此对象来获取有关执行程序的信息，并将其作为响应发送给用户。实现几乎与第二章中的相同。我们使用相同的方法来获取`Executor`对象的状态。

`ConcurrentStopCommand`和`ConcurrentErrorCommand`与第二章中的相同，因此我们没有包含它们的源代码。

## 服务器部分

服务器部分接收来自服务器客户端的查询，并创建执行查询的命令类，并将其发送到执行程序。由两个类实现：

+   `ConcurrentServer`类：它包括服务器的`main()`方法和取消任务以及完成系统执行的其他方法。

+   `RequestTask`类：此类创建命令并将其发送到执行程序

与第二章的示例*管理大量线程-执行器*的主要区别是`RequestTask`类的作用。在`SimpleServer`示例中，`ConcurrentServer`类为每个查询创建一个`RequestTask`对象并将其发送到执行器。在这个例子中，我们只会有一个`RequestTask`的实例，它将作为一个线程执行。当`ConcurrentServer`接收到一个连接时，它将把用于与客户端通信的套接字存储在一个并发的待处理连接列表中。`RequestTask`线程读取该套接字，处理客户端发送的数据，创建相应的命令，并将命令发送到执行器。

这种改变的主要原因是只在执行器中留下查询的代码，并将预处理的代码留在执行器之外。

### ConcurrentServer 类

`ConcurrentServer`类需要一些内部属性才能正常工作：

+   一个`ParallelCache`实例用于使用缓存系统。

+   一个`ServerSocket`实例用于接收来自客户端的连接。

+   一个`boolean`值用于知道何时停止执行。

+   一个`LinkedBlockingQueue`用于存储发送消息给服务器的客户端的套接字。这些套接字将由`RequestTask`类处理。

+   一个`ConcurrentHashMap`用于存储与执行器中的每个任务相关的`Future`对象。键将是发送查询的用户的用户名，值将是另一个`Map`，其键将是`ConcurrenCommand`对象，值将是与该任务相关联的`Future`实例。我们使用这些`Future`实例来取消任务的执行。

+   一个`RequestTask`实例用于创建命令并将其发送到执行器。

+   一个`Thread`对象来执行`RequestTask`对象。

这段代码如下：

```java
public class ConcurrentServer {
    private static ParallelCache cache;
    private static volatile boolean stopped=false;
    private static LinkedBlockingQueue<Socket> pendingConnections;
    private static ConcurrentMap<String, ConcurrentMap<ConcurrentCommand, ServerTask<?>>> taskController;
    private static Thread requestThread;
    private static RequestTask task;
```

这个类的`main()`方法初始化这些对象，并打开`ServerSocket`实例以监听来自客户端的连接。此外，它创建`RequestTask`对象并将其作为线程执行。它将循环执行，直到`shutdown()`方法改变了 stopped 属性的值。之后，它等待`Executor`对象的完成，使用`RequestTask`对象的`endTermination()`方法，并使用`finishServer()`方法关闭`Logger`系统和`RequestTask`对象：

```java
    public static void main(String[] args) {

        WDIDAO dao=WDIDAO.getDAO();
        cache=new ParallelCache();
        Logger.initializeLog();
        pendingConnections = new LinkedBlockingQueue<Socket>();
        taskController = new ConcurrentHashMap<String, ConcurrentHashMap<Integer, Future<?>>>();
        task=new RequestTask(pendingConnections, taskController);
        requestThread=new Thread(task);
        requestThread.start();

        System.out.println("Initialization completed.");

        serverSocket= new ServerSocket(Constants.CONCURRENT_PORT);
        do {
            try {
                Socket clientSocket = serverSocket.accept();
                pendingConnections.put(clientSocket);
            } catch (Exception e) {
                e.printStackTrace();
            }
        } while (!stopped);
        finishServer();
        System.out.println("Shutting down cache");
        cache.shutdown();
        System.out.println("Cache ok" + new Date());

    }
```

它包括两种方法来关闭服务器的执行器。`shutdown()`方法改变`stopped`变量的值，并关闭`serverSocket`实例。`finishServer()`方法停止执行器，中断执行`RequestTask`对象的线程，并关闭`Logger`系统。我们将这个过程分成两部分，以便在服务器的最后一条指令之前使用`Logger`系统：

```java
    public static void shutdown() {
        stopped=true;
        try {
            serverSocket.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void finishServer() {
        System.out.println("Shutting down the server...");
        task.shutdown();
        System.out.println("Shutting down Request task");
        requestThread.interrupt();
        System.out.println("Request task ok");
        System.out.println("Closing socket");
        System.out.println("Shutting down logger");
        Logger.sendMessage("Shutting down the logger");
        Logger.shutdown();
        System.out.println("Logger ok");
        System.out.println("Main server thread ended");
    }
```

服务器包括取消与用户关联的任务的方法。正如我们之前提到的，`Server`类使用嵌套的`ConcurrentHashMap`来存储与用户关联的所有任务。首先，我们获取一个用户的所有任务的`Map`，然后我们处理这些任务的所有`Future`对象，调用`Future`对象的`cancel()`方法。我们将值`true`作为参数传递，因此如果执行器正在运行该用户的任务，它将被中断。我们已经包括了必要的代码来避免`ConcurrentCancelCommand`的取消：

```java
    public static void cancelTasks(String username) {

        ConcurrentMap<ConcurrentCommand, ServerTask<?>> userTasks = taskController.get(username);
        if (userTasks == null) {
            return;
        }
        int taskNumber = 0;

        Iterator<ServerTask<?>> it = userTasks.values().iterator();
        while(it.hasNext()) {
            ServerTask<?> task = it.next();
             ConcurrentCommand command = task.getCommand();
              if(!(command instanceof ConcurrentCancelCommand) && task.cancel(true)) {
                    taskNumber++;
                    Logger.sendMessage("Task with code "+command.hashCode()+"cancelled: "+command.getClass().getSimpleName());
                    it.remove();
              }
        }
        String message=taskNumber+" tasks has been cancelled.";
        Logger.sendMessage(message);
    }
```

最后，我们已经包括了一个方法，当任务正常执行完毕时，从我们的`ServerTask`对象的嵌套映射中消除与任务相关的`Future`对象。这就是`finishTask()`方法：

```java
    public static void finishTask(String username, ConcurrentCommand command) {

        ConcurrentMap<ConcurrentCommand, ServerTask<?>> userTasks = taskController.get(username);
        userTasks.remove(command);
        String message = "Task with code "+command.hashCode()+" has finished";
        Logger.sendMessage(message);

    }
```

### RequestTask 类

`RequestTask`类是`ConcurrentServer`类与客户端连接和`Executor`类执行并发任务之间的中介。它与客户端打开套接字，读取查询数据，创建适当的命令，并将其发送到执行器。

它使用一些内部属性：

+   `LinkedBlockingQueue`，`ConcurrentServer`类在其中存储客户端套接字

+   `ServerExecutor`用于执行命令作为并发任务。

+   使用`ConcurrentHashMap`存储与任务相关的`Future`对象

该类的构造函数初始化了所有这些对象：

```java
public class RequestTask implements Runnable {
    private LinkedBlockingQueue<Socket> pendingConnections;
    private ServerExecutor executor = new ServerExecutor();
    private ConcurrentMap<String, ConcurrentMap<ConcurrentCommand, ServerTask<?>>> taskController;
    public RequestTask(LinkedBlockingQueue<Socket> pendingConnections, ConcurrentHashMap<String, ConcurrentHashMap<Integer, Future<?>>> taskController) {
        this.pendingConnections = pendingConnections;
        this.taskController = taskController;
    }
```

该类的主要方法是`run()`方法。它执行一个循环，直到线程被中断，处理存储在`pendingConnections`对象中的套接字。在该对象中，`ConcurrentServer`类存储了与发送查询到服务器的不同客户端通信的套接字。它打开套接字，读取数据，并创建相应的命令。它还将命令发送到执行器，并将`Future`对象存储在与任务的`hashCode`和发送查询的用户相关联的双重`ConcurrentHashMap`中：

```java
    public void run() {
        try {
            while (!Thread.currentThread().interrupted()) {
                try {
                    Socket clientSocket = pendingConnections.take();
                    BufferedReader in = new BufferedReader(new InputStreamReader (clientSocket.getInputStream()));
                    String line = in.readLine();

                    Logger.sendMessage(line);

                    ConcurrentCommand command;

                    ParallelCache cache = ConcurrentServer.getCache();
                    String ret = cache.get(line);
                    if (ret == null) {
                        String[] commandData = line.split(";");
                        System.out.println("Command: " + commandData[0]);
                        switch (commandData[0]) {
                        case "q":
                            System.out.println("Query");
                            command = new ConcurrentQueryCommand(clientSocket, commandData);
                            break;
                        case "r":
                            System.out.println("Report");
                            command = new ConcurrentReportCommand (clientSocket, commandData);
                            break;
                        case "s":
                            System.out.println("Status");
                            command = new ConcurrentStatusCommand(executor, clientSocket, commandData);
                            break;
                        case "z":
                            System.out.println("Stop");
                            command = new ConcurrentStopCommand(clientSocket, commandData);
                            break;
                        case "c":
                            System.out.println("Cancel");
                            command = new ConcurrentCancelCommand (clientSocket, commandData);
                            break;
                        default:
                            System.out.println("Error");
                            command = new ConcurrentErrorCommand(clientSocket, commandData);
                            break;
                        }

                        ServerTask<?> controller = (ServerTask<?>)executor.submit(command);
                        storeContoller(command.getUsername(), controller, command);
                    } else {
                        PrintWriter out = new PrintWriter (clientSocket.getOutputStream(),true);
                        out.println(ret);
                        clientSocket.close();
                    }

                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        } catch (InterruptedException e) {
            // No Action Required
        }
    }
```

`storeController()`方法是将`Future`对象存储在双重`ConcurrentHashMap`中的方法：

```java
    private void storeContoller(String userName, ServerTask<?> controller, ConcurrentCommand command) {
        taskController.computeIfAbsent(userName, k -> new ConcurrentHashMap<>()).put(command, controller);
    }
```

最后，我们包含了两个方法来管理`Executor`类的执行，一个是调用`shutdown()`方法来关闭执行器，另一个是等待其完成。请记住，您必须显式调用`shutdown()`或`shutdownNow()`方法来结束执行器的执行。否则，程序将无法终止。请看下面的代码：

```java
    public void shutdown() {

        String message="Request Task: "
                +pendingConnections.size()
                +" pending connections.";
        Logger.sendMessage(message);
        executor.shutdown();
    }

    public void terminate() {
        try {
            executor.awaitTermination(1,TimeUnit.DAYS);
            executor.writeStatistics();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

    }
```

## 客户端部分

现在是测试服务器的时候了。在这种情况下，我们不会太担心执行时间。我们测试的主要目标是检查新功能是否正常工作。

我们将客户端部分分为以下两个类：

+   **ConcurrentClient 类**：这实现了服务器的单个客户端。该类的每个实例都有不同的用户名。它进行了 100 次查询，其中 90 次是查询类型，10 次是报告类型。查询查询的优先级为 5，报告查询的优先级较低（10）。

+   **MultipleConcurrentClient 类**：这测试了多个并发客户端的行为。我们已经测试了具有一到五个并发客户端的服务器。该类还测试了取消和停止命令。

我们已经包含了一个执行器来执行对服务器的并发请求，以增加客户端的并发级别。

在下图中，您可以看到任务取消的结果：

![客户端部分](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-cncr-prog-java8/img/00008.jpeg)

在这种情况下，**USER_2**用户的四个任务已被取消。

以下图片显示了关于每个用户的任务数量和执行时间的最终统计数据：

![客户端部分](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-cncr-prog-java8/img/00009.jpeg)

# 第二个示例 - 执行周期性任务

在之前的执行器示例中，任务只执行一次，并且尽快执行。执行器框架包括其他执行器实现，使我们对任务的执行时间更加灵活。`ScheduledThreadPoolExecutor`类允许我们*周期性*执行任务，并在*延迟*后执行任务。

在本节中，您将学习如何执行周期性任务，实现**RSS 订阅**阅读器。这是一个简单的情况，您需要定期执行相同的任务（阅读 RSS 订阅的新闻）。我们的示例将具有以下特点：

+   将 RSS 源存储在文件中。我们选择了一些重要报纸的世界新闻，如纽约时报、每日新闻或卫报。

+   我们为每个 RSS 源向执行器发送一个`Runnable`对象。每次执行器运行该对象时，它会解析 RSS 源并将其转换为包含 RSS 内容的`CommonInformationItem`对象列表。

+   我们使用**生产者/消费者设计模式**将 RSS 新闻写入磁盘。生产者将是执行器的任务，它们将每个`CommonInformationItem`写入缓冲区。只有新项目将存储在缓冲区中。消费者将是一个独立的线程，它从缓冲区中读取新闻并将其写入磁盘。

+   任务执行结束和下一次执行之间的时间将是一分钟。

我们还实现了示例的高级版本，其中任务执行之间的时间可以变化。

## 共同部分

正如我们之前提到的，我们读取一个 RSS 源并将其转换为对象列表。为了解析 RSS 文件，我们将其视为 XML 文件，并在`RSSDataCapturer`类中实现了一个**SAX**（简单 XML API）解析器。它解析文件并创建一个`CommonInformationItem`列表。这个类为每个 RSS 项存储以下信息：

+   **标题**：RSS 项的标题。

+   **日期**：RSS 项的日期。

+   **链接**：RSS 项的链接。

+   **描述**：RSS 项的文本。

+   **ID**：RSS 项的 ID。如果该项不包含 ID，我们将计算它。

+   **来源**：RSS 来源的名称。

我们使用生产者/消费者设计模式将新闻存储到磁盘中，因此我们需要一个缓冲区来存储新闻和一个`Consumer`类，该类从缓冲区中读取新闻并将其存储到磁盘中。

我们在`NewsBuffer`类中实现了缓冲区。它有两个内部属性：

+   **LinkedBlockingQueue**：这是一个带有阻塞操作的并发数据结构。如果我们想从列表中获取一个项目，而它是空的，调用方法的线程将被阻塞，直到列表中有元素为止。我们将使用这个结构来存储`CommonInformationItems`。

+   **ConcurrentHashMap**：这是`HashMap`的并发实现。我们将使用它来在缓冲区中存储之前存储的新闻项的 ID。

我们只会将以前未插入的新闻插入到缓冲区中：

```java
public class NewsBuffer {
    private LinkedBlockingQueue<CommonInformationItem> buffer;
    private ConcurrentHashMap<String, String> storedItems;

    public NewsBuffer() {
        buffer=new LinkedBlockingQueue<>();
        storedItems=new ConcurrentHashMap<String, String>();
    }
```

在`NewsBuffer`类中有两个方法：一个用于将项目存储在缓冲区中，并检查该项目是否已经插入，另一个用于从缓冲区中获取下一个项目。我们使用`compute()`方法将元素插入`ConcurrentHashMap`中。这个方法接收一个 lambda 表达式作为参数，其中包含与该键关联的实际值（如果键没有关联的值，则为 null）。在我们的情况下，如果该项以前没有被处理过，我们将把该项添加到缓冲区中。我们使用`add()`和`take()`方法来向队列中插入、获取和删除元素：

```java
    public void add (CommonInformationItem item) {
        storedItems.compute(item.getId(), (id, oldSource) -> {
              if(oldSource == null) {
                buffer.add(item);
                return item.getSource();
              } else {
                System.out.println("Item "+item.getId()+" has been processed before");
                return oldSource;
              }
            });
    }

    public CommonInformationItem get() throws InterruptedException {
        return buffer.take();
    }
```

缓冲区的项目将由`NewsWriter`类写入磁盘，该类将作为一个独立的线程执行。它只有一个内部属性，指向应用程序中使用的`NewsBuffer`类：

```java
public class NewsWriter implements Runnable {
    private NewsBuffer buffer;
    public NewsWriter(NewsBuffer buffer) {
        this.buffer=buffer;
    }
```

这个`Runnable`对象的`run()`方法从缓冲区中获取`CommonInformationItem`实例并将它们保存到磁盘中。由于我们使用了阻塞方法`take`，如果缓冲区为空，这个线程将被阻塞，直到缓冲区中有元素为止。

```java
    public void run() {
        try {
            while (!Thread.currentThread().interrupted()) {
                CommonInformationItem item=buffer.get();

                Path path=Paths.get ("output\\"+item.getFileName());

                try (BufferedWriter fileWriter = Files.newBufferedWriter(path, StandardOpenOption.CREATE)) {
                    fileWriter.write(item.toString());
                } catch (IOException e) {
                    e.printStackTrace();
                }

            }
        } catch (InterruptedException e) {
            //Normal execution
        }
    }
```

## 基本读取器

基本读取器将使用标准的`ScheduledThreadPoolExecutor`类来定期执行任务。我们将为每个 RSS 源执行一个任务，并且在一个任务执行的终止和下一个任务执行的开始之间将有一分钟的时间。这些并发任务在`NewsTask`类中实现。它有三个内部属性来存储 RSS 源的名称、其 URL 和存储新闻的`NewsBuffer`类：

```java
public class NewsTask implements Runnable {
    private String name;
    private String url;
    private NewsBuffer buffer;

    public NewsTask (String name, String url, NewsBuffer buffer) {
        this.name=name;
        this.url=url;
        this.buffer=buffer;
    }
```

这个`Runnable`对象的`run()`方法简单地解析 RSS 源，获取`CommonItemInterface`实例的列表，并将它们存储在缓冲区中。这个方法将定期执行。在每次执行中，`run()`方法将从头到尾执行：

```java
    @Override
    public void run() {
        System.out.println(name+": Running. " + new Date());
        RSSDataCapturer capturer=new RSSDataCapturer(name);
        List<CommonInformationItem> items=capturer.load(url);

        for (CommonInformationItem item: items) {
            buffer.add(item);
        }
    }
```

在这个例子中，我们还实现了另一个线程来实现执行器和任务的初始化以及等待执行的结束。我们将这个类命名为`NewsSystem`。它有三个内部属性，用于存储带有 RSS 源的文件路径，用于存储新闻的缓冲区，以及用于控制其执行结束的`CountDownLatch`对象。`CountDownLatch`类是一种同步机制，允许您使一个线程等待一个事件。我们将在第九章中详细介绍这个类的使用，*深入并发数据结构和同步工具*。我们有以下代码：

```java
public class NewsSystem implements Runnable {
    private String route;
    private ScheduledThreadPoolExecutor executor;
    private NewsBuffer buffer;
    private CountDownLatch latch=new CountDownLatch(1);

    public NewsSystem(String route) {
        this.route = route;
        executor = new ScheduledThreadPoolExecutor (Runtime.getRuntime().availableProcessors());
        buffer=new NewsBuffer();
    }
```

在`run()`方法中，我们读取所有的 RSS 源，为每一个创建一个`NewsTask`类，并将它们发送到我们的`ScheduledThreadPool`执行器。我们使用`Executors`类的`newScheduledThreadPool()`方法创建了执行器，并使用`scheduleAtFixedDelay()`方法将任务发送到执行器。我们还启动了`NewsWriter`实例作为一个线程。`run()`方法等待有人告诉它结束执行，使用`CountDownLatch`类的`await()`方法，并结束`NewsWriter`任务和`ScheduledExecutor`的执行。

```java
    @Override
    public void run() {
        Path file = Paths.get(route);
        NewsWriter newsWriter=new NewsWriter(buffer);
        Thread t=new Thread(newsWriter);
        t.start();

        try (InputStream in = Files.newInputStream(file);
                BufferedReader reader = new BufferedReader(
                        new InputStreamReader(in))) {
            String line = null;
            while ((line = reader.readLine()) != null) {
                String data[] = line.split(";");

                NewsTask task = new NewsTask(data[0], data[1], buffer);
                System.out.println("Task "+task.getName());
                executor.scheduleWithFixedDelay(task,0, 1, TimeUnit.MINUTES);
            }
        }  catch (Exception e) {
            e.printStackTrace();
        }

        synchronized (this) {
            try {
                latch.await();
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }

        System.out.println("Shutting down the executor.");
        executor.shutdown();
        t.interrupt();
        System.out.println("The system has finished.");

    }
```

我们还实现了`shutdown()`方法。这个方法将使用`CountDownLatch`类的`countDown()`方法通知`NewsSystem`类结束执行。这个方法将唤醒`run()`方法，因此它将关闭运行`NewsTask`对象的执行器：

```java
    public void shutdown() {
        latch.countDown();
    }
```

这个例子的最后一个类是实现了例子的`main()`方法的`Main`类。它启动了一个`NewsSystem`实例作为一个线程，等待 10 分钟，然后通知线程完成，从而结束整个系统的执行，如下所示：

```java
public class Main {

    public static void main(String[] args) {

        // Creates the System an execute it as a Thread
        NewsSystem system=new NewsSystem("data\\sources.txt");

        Thread t=new Thread(system);

        t.start();

        // Waits 10 minutes
        try {
            TimeUnit.MINUTES.sleep(10);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        // Notifies the finalization of the System
         (
        system.shutdown();
    }
```

当您执行这个例子时，您会看到不同的任务是如何周期性地执行的，以及新闻项目是如何写入磁盘的，如下面的截图所示：

![基本阅读器](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-cncr-prog-java8/img/00010.jpeg)

## 高级读者

基本新闻阅读器是`ScheduledThreadPoolExecutor`类的一个使用示例，但我们可以更进一步。与`ThreadPoolExecutor`一样，我们可以实现自己的`ScheduledThreadPoolExecutor`以获得特定的行为。在我们的例子中，我们希望周期性任务的延迟时间根据一天中的时间而变化。在这一部分，您将学习如何实现这种行为。

第一步是实现一个告诉我们周期性任务两次执行之间延迟的类。我们将这个类命名为`Timer`类。它只有一个名为`getPeriod()`的静态方法，它返回一个执行结束和下一个开始之间的毫秒数。这是我们的实现，但您也可以自己制作：

```java
public class Timer {
    public static long getPeriod() {
        Calendar calendar = Calendar.getInstance();
        int hour = calendar.get(Calendar.HOUR_OF_DAY);

        if ((hour >= 6) && (hour <= 8)) {
            return TimeUnit.MILLISECONDS.convert(1, TimeUnit.MINUTES);
        }

        if ((hour >= 13) && (hour <= 14)) {
            return TimeUnit.MILLISECONDS.convert(1, TimeUnit.MINUTES);
        }

        if ((hour >= 20) && (hour <= 22)) {
            return TimeUnit.MILLISECONDS.convert(1, TimeUnit.MINUTES);
        }
        return TimeUnit.MILLISECONDS.convert(2, TimeUnit.MINUTES);
    }
}
```

接下来，我们必须实现执行器的内部任务。当您将一个`Runnable`对象发送到执行器时，从外部来看，您会将这个对象视为并发任务，但执行器会将这个对象转换为另一个任务，即`FutureTask`类的一个实例，其中包括`run()`方法来执行任务以及`Future`接口的方法来管理任务的执行。为了实现这个例子，我们必须实现一个扩展`FutureTask`类的类，并且，由于我们将在**计划执行器**中执行这些任务，它必须实现`RunnableScheduledFuture`接口。这个接口提供了`getDelay()`方法，返回到下一个任务执行的剩余时间。我们在`ExecutorTask`类中实现了这些内部任务。它有四个内部属性：

+   `ScheduledThreadPoolExecutor`类创建的原始`RunnableScheduledFuture`内部任务

+   将执行任务的计划执行器

+   任务的下一次执行的开始日期

+   RSS 订阅的名称

代码如下：

```java
public class ExecutorTask<V> extends FutureTask<V> implements RunnableScheduledFuture<V> {
    private RunnableScheduledFuture<V> task;

    private NewsExecutor executor;

    private long startDate;

    private String name;

    public ExecutorTask(Runnable runnable, V result, RunnableScheduledFuture<V> task, NewsExecutor executor) {
        super(runnable, result);
        this.task = task;
        this.executor = executor;
        this.name=((NewsTask)runnable).getName();
        this.startDate=new Date().getTime();
    }
```

在这个类中，我们重写或实现了不同的方法。首先是`getDelay()`方法，正如我们之前告诉过你的，它返回给定单位时间内任务下一次执行的剩余时间：

```java
    @Override
    public long getDelay(TimeUnit unit) {
        long delay;
        if (!isPeriodic()) {
            delay = task.getDelay(unit);
        } else {
            if (startDate == 0) {
                delay = task.getDelay(unit);
            } else {
                Date now = new Date();
                delay = startDate - now.getTime();
                delay = unit.convert(delay, TimeUnit.MILLISECONDS);
            }

        }

        return delay;
    }
```

接下来的是`compareTo()`方法，它比较两个任务，考虑到任务的下一次执行的开始日期：

```java
    @Override
    public int compareTo(Delayed object) {
        return Long.compare(this.getStartDate(), ((ExecutorTask<V>)object).getStartDate());
    }
```

然后，`isPeriodic()`方法返回`true`如果任务是周期性的，如果不是则返回`false`：

```java
    @Override
    public boolean isPeriodic() {
        return task.isPeriodic();
    }
```

最后，我们有`run()`方法，它实现了这个示例的最重要部分。首先，我们调用`FutureTask`类的`runAndReset()`方法。这个方法执行任务并重置它的状态，这样它就可以再次执行。然后，我们使用`Timer`类计算下一次执行的开始日期，最后，我们必须再次将任务插入`ScheduledThreadPoolExecutor`类的队列中。如果不执行这最后一步，任务将不会再次执行，如下所示：

```java
    @Override
    public void run() {
        if (isPeriodic() && (!executor.isShutdown())) {
            super.runAndReset();
            Date now=new Date();
            startDate=now.getTime()+Timer.getPeriod();
            executor.getQueue().add(this);
            System.out.println("Start Date: "+new Date(startDate));
        }
    }
```

一旦我们有了执行器的任务，我们就必须实现执行器。我们实现了`NewsExecutor`类，它扩展了`ScheduledThreadPoolExecutor`类。我们重写了`decorateTask()`方法。通过这个方法，你可以替换调度执行器使用的内部任务。默认情况下，它返回`RunnableScheduledFuture`接口的默认实现，但在我们的情况下，它将返回`ExecutorClass`实例的一个实例：

```java
public class NewsExecutor extends ScheduledThreadPoolExecutor { 
    public NewsExecutor(int corePoolSize) {
        super(corePoolSize);
    }

    @Override
    protected <V> RunnableScheduledFuture<V> decorateTask(Runnable runnable,
            RunnableScheduledFuture<V> task) {
        ExecutorTask<V> myTask = new ExecutorTask<>(runnable, null, task, this);
        return myTask;
    }
}
```

我们必须实现`NewsSystem`和`Main`类的其他版本来使用`NewsExecutor`。我们为此目的实现了`NewsAdvancedSystem`和`AdvancedMain`。

现在你可以运行高级新闻系统，看看执行之间的延迟时间如何改变。

# 有关执行器的附加信息

在本章中，我们扩展了`ThreadPoolExecutor`和`ScheduledThreadPoolExecutor`类，并重写了它们的一些方法。但是，如果需要更特定的行为，你可以重写更多的方法。以下是一些你可以重写的方法：

+   `shutdown()`: 你必须显式调用这个方法来结束执行器的执行。你可以重写它来添加一些代码，以释放你自己的执行器使用的额外资源。

+   `shutdownNow()`: `shutdown()`方法和`shutdownNow()`方法的区别在于，`shutdown()`方法等待所有等待在执行器中的任务的最终处理。

+   `submit()`, `invokeall()`, 或 `invokeany()`: 你可以调用这些方法将并发任务发送到执行器中。如果需要在任务插入执行器的任务队列之前或之后执行一些操作，可以重写它们。请注意，在任务入队之前或之后添加自定义操作与在任务执行之前或之后添加自定义操作是不同的，我们在重写`beforeExecute()`和`afterExecute()`方法时已经做过。

在新闻阅读器示例中，我们使用`scheduleWithFixedDelay()`方法将任务发送到执行器。但是`ScheduledThreadPoolExecutor`类还有其他方法来执行周期性任务或延迟任务：

+   `schedule()`: 这个方法在给定的延迟之后执行一次任务。

+   `scheduleAtFixedRate()`: 这个方法以给定的周期执行周期性任务。与`scheduleWithFixedDelay()`方法的区别在于，在后者中，两次执行之间的延迟从第一次执行结束到第二次执行开始，而在前者中，两次执行之间的延迟在两次执行的开始之间。

# 总结

在本章中，我们介绍了两个示例，探讨了执行器的高级特性。在第一个示例中，我们延续了第二章中的客户端/服务器示例，*管理大量线程 - 执行器*。我们实现了自己的执行器，扩展了`ThreadPoolExecutor`类，以按优先级执行任务，并测量每个用户任务的执行时间。我们还包括了一个新的命令，允许取消任务。

在第二个示例中，我们解释了如何使用`ScheduledThreadPoolExecutor`类来执行周期性任务。我们实现了两个版本的新闻阅读器。第一个版本展示了如何使用`ScheduledExecutorService`的基本功能，第二个版本展示了如何覆盖`ScheduledExecutorService`类的行为，例如，更改任务两次执行之间的延迟时间。

在下一章中，您将学习如何执行返回结果的`Executor`任务。如果您扩展`Thread`类或实现`Runnable`接口，`run()`方法不会返回任何结果，但执行器框架包括`Callable`接口，允许您实现返回结果的任务。


# 第四章：从任务中获取数据 - Callable 和 Future 接口

在第二章，*管理大量线程 - 执行程序*，和第三章，*从执行程序中获得最大效益*，我们介绍了执行程序框架，以提高并发应用程序的性能，并向您展示了如何实现高级特性以使该框架适应您的需求。在这些章节中，执行程序执行的所有任务都基于`Runnable`接口及其不返回值的`run()`方法。然而，执行程序框架允许我们执行基于`Callable`和`Future`接口的返回结果的其他类型的任务。在本章中，我们将涵盖以下主题：

+   Callable 和 Future 接口介绍

+   第一个例子 - 用于单词的最佳匹配算法

+   第二个例子 - 构建文档集合的倒排索引

# 介绍 Callable 和 Future 接口

执行程序框架允许程序员在不创建和管理线程的情况下执行并发任务。您创建任务并将它们发送到执行程序。它会创建和管理必要的线程。

在执行程序中，您可以执行两种类型的任务：

+   **基于 Runnable 接口的任务**：这些任务实现了不返回任何结果的`run()`方法。

+   **基于 Callable 接口的任务**：这些任务实现了`call()`接口，返回一个对象作为结果。`call()`方法返回的具体类型由`Callable`接口的泛型类型参数指定。为了获取任务返回的结果，执行程序将为每个任务返回一个`Future`接口的实现。

在之前的章节中，您学习了如何创建执行程序，将基于`Runnable`接口的任务发送到其中，并个性化执行程序以适应您的需求。在本章中，您将学习如何处理基于`Callable`和`Future`接口的任务。

## Callable 接口

`Callable`接口与`Runnable`接口非常相似。该接口的主要特点是：

+   它是一个泛型接口。它有一个单一类型参数，对应于`call()`方法的返回类型。

+   它声明了`call()`方法。当执行程序运行任务时，该方法将被执行。它必须返回声明中指定类型的对象。

+   `call()`方法可以抛出任何已检查异常。您可以通过实现自己的执行程序并覆盖`afterExecute()`方法来处理异常。

## Future 接口

当您将一个`Callable`任务发送到执行程序时，它将返回一个`Future`接口的实现，允许您控制任务的执行和状态，并获取结果。该接口的主要特点是：

+   您可以使用`cancel()`方法取消任务的执行。该方法有一个`boolean`参数，用于指定是否要在任务运行时中断任务。

+   您可以通过`isCancelled()`方法检查任务是否已被取消，或者通过`isDone()`方法检查任务是否已完成。

+   您可以使用`get()`方法获取任务返回的值。此方法有两个变体。第一个没有参数，并返回任务执行完成后的返回值。如果任务尚未执行完成，它会挂起执行线程，直到任务完成。第二个变体接受两个参数：一段时间和该时间段的`TimeUnit`。与第一个的主要区别在于线程等待作为参数传递的时间段。如果时间段结束，任务尚未执行完成，该方法会抛出`TimeoutException`异常。

# 第一个示例-用于单词的最佳匹配算法

单词的**最佳匹配算法**的主要目标是找到与作为参数传递的字符串最相似的单词。要实现这些算法之一，您需要以下内容：

+   **单词列表**：在我们的案例中，我们使用了为填字游戏社区编制的**英国高级谜语词典**（**UKACD**）。它有 250,353 个单词和习语。可以从[`www.crosswordman.com/wordlist.html`](http://www.crosswordman.com/wordlist.html)免费下载。

+   **衡量两个单词相似性的度量标准**：我们使用了 Levenshtein 距离，用于衡量两个**字符**序列之间的差异。**Levenshtein 距离**是将第一个字符串转换为第二个字符串所需的最小插入、删除或替换次数。您可以在[`en.wikipedia.org/wiki/Levenshtein_distance`](https://en.wikipedia.org/wiki/Levenshtein_distance)中找到对此度量标准的简要描述。

在我们的示例中，您将实现两个操作：

+   第一个操作使用 Levenshtein 距离返回与**字符序列**最相似的单词列表。

+   第二个操作使用 Levenshtein 距离确定字符序列是否存在于我们的字典中。如果使用`equals()`方法会更快，但我们的版本对于本书的目标来说是一个更有趣的选择。

您将实现这些操作的串行和并发版本，以验证并发在这种情况下是否有帮助。

## 常见类

在此示例中实现的所有任务中，您将使用以下三个基本类：

+   `WordsLoader`类将单词列表加载到`String`对象列表中。

+   `LevenshteinDistance`类计算两个字符串之间的 Levenshtein 距离。

+   `BestMatchingData`类存储最佳匹配算法的结果。它存储单词列表以及这些单词与输入字符串的距离。

UKACD 在一个文件中，每行一个单词，因此`WordsLoader`类实现了`load()`静态方法，该方法接收包含单词列表的文件的路径，并返回一个包含 250,353 个单词的字符串对象列表。

`LevenshteinDistance`类实现了`calculate()`方法，该方法接收两个字符串对象作为参数，并返回这两个单词之间的距离的`int`值。这是这个分类的代码：

```java
public class LevenshteinDistance {

    public static int calculate (String string1, String string2) {
        int[][] distances=new int[string1.length()+1][string2.length()+1];

        for (int i=1; i<=string1.length();i++) {
            distances[i][0]=i;
        }

        for (int j=1; j<=string2.length(); j++) {
            distances[0][j]=j;
        }

        for(int i=1; i<=string1.length(); i++) {
            for (int j=1; j<=string2.length(); j++) {
                if (string1.charAt(i-1)==string2.charAt(j-1)) {
                    distances[i][j]=distances[i-1][j-1];
                } else {
                    distances[i][j]=minimum(distances[i-1][j], distances[i][j-1],distances[i-1][j-1])+1;
                }
            }
        }

        return distances[string1.length()][string2.length()];
    }

    private static int minimum(int i, int j, int k) {
        return Math.min(i,Math.min(j, k));
    }
}
```

`BestMatchingData`类只有两个属性：一个字符串对象列表，用于存储单词列表，以及一个名为距离的整数属性，用于存储这些单词与输入字符串的距离。

## 最佳匹配算法-串行版本

首先，我们将实现最佳匹配算法的串行版本。我们将使用此版本作为并发版本的起点，然后我们将比较两个版本的执行时间，以验证并发是否有助于提高性能。

我们已经在以下两个类中实现了最佳匹配算法的串行版本：

+   `BestMatchingSerialCalculation`类计算与输入字符串最相似的单词列表

+   `BestMatchingSerialMain`包括`main()`方法，执行算法，测量执行时间，并在控制台中显示结果

让我们分析一下这两个类的源代码。

### `BestMatchingSerialCalculation`类

这个类只有一个名为`getBestMatchingWords`()的方法，它接收两个参数：一个带有我们作为参考的序列的字符串，以及包含字典中所有单词的字符串对象列表。它返回一个`BestMatchingData`对象，其中包含算法的结果：

```java
public class BestMatchingSerialCalculation {

    public static BestMatchingData getBestMatchingWords(String word, List<String> dictionary) {
        List<String> results=new ArrayList<String>();
        int minDistance=Integer.MAX_VALUE;
        int distance;
```

在内部变量初始化之后，算法处理字典中的所有单词，计算这些单词与参考字符串之间的 Levenshtein 距离。如果一个单词的计算距离小于实际最小距离，我们清除结果列表并将实际单词存储到列表中。如果一个单词的计算距离等于实际最小距离，我们将该单词添加到结果列表中：

```java
        for (String str: dictionary) {
            distance=LevenshteinDistance.calculate(word,str);
            if (distance<minDistance) {
                results.clear();
                minDistance=distance;
                results.add(str);
            } else if (distance==minDistance) {
                results.add(str);
            }
        }
```

最后，我们创建了`BestMatchingData`对象来返回算法的结果：

```java
        BestMatchingData result=new BestMatchingData();
        result.setWords(results);
        result.setDistance(minDistance);
        return result;
    }

}
```

### `BestMachingSerialMain`类

这是示例的主要类。它加载 UKACD 文件，使用作为参数接收的字符串调用`getBestMatchingWords()`，并在控制台中显示结果，包括算法的执行时间。

```java
public class BestMatchingSerialMain {

    public static void main(String[] args) {

        Date startTime, endTime;
        List<String> dictionary=WordsLoader.load("data/UK Advanced Cryptics Dictionary.txt");

        System.out.println("Dictionary Size: "+dictionary.size());

        startTime=new Date();
        BestMatchingData result= BestMatchingSerialCalculation.getBestMatchingWords (args[0], dictionary);
        List<String> results=result.getWords();
        endTime=new Date();
        System.out.println("Word: "+args[0]);
        System.out.println("Minimum distance: " +result.getDistance());
        System.out.println("List of best matching words: " +results.size());
        results.forEach(System.out::println);
        System.out.println("Execution Time: "+(endTime.getTime()- startTime.getTime()));
    }

}
```

在这里，我们使用了一个名为**方法引用**的新的 Java 8 语言构造和一个新的`List.forEach()`方法来输出结果。

## 最佳匹配算法 - 第一个并发版本

我们实现了两个不同的并发版本的最佳匹配算法。第一个是基于`Callable`接口和`AbstractExecutorService`接口中定义的`submit()`方法。

我们使用了以下三个类来实现算法的这个版本：

+   `BestMatchingBasicTask`类实现了实现`Callable`接口的任务，并将在执行器中执行

+   `BestMatchingBasicConcurrentCalculation`类创建执行器和必要的任务，并将它们发送到执行器

+   `BestMatchingConcurrentMain`类实现了`main()`方法，用于执行算法并在控制台中显示结果

让我们来看看这些类的源代码。

### `BestMatchingBasicTask`类

如前所述，这个类将实现将获得最佳匹配单词列表的任务。这个任务将实现参数化为`BestMatchingData`类的`Callable`接口。这意味着这个类将实现`call()`方法，而这个方法将返回一个`BestMatchingData`对象。

每个任务将处理字典的一部分，并返回该部分获得的结果。我们使用了四个内部属性，如下所示：

+   字典的第一个位置（包括）

+   它将分析的字典的最后位置（不包括）

+   作为字符串对象列表的字典

+   参考输入字符串

这段代码如下：

```java
public class BestMatchingBasicTask implements Callable <BestMatchingData > {

    private int startIndex;

    private int endIndex;

    private List < String > dictionary;

    private String word;

    public BestMatchingBasicTask(int startIndex, int endIndex, List < String > dictionary, String word) {
        this.startIndex = startIndex;
        this.endIndex = endIndex;
        this.dictionary = dictionary;
        this.word = word;
    }
```

`call()`方法处理`startIndex`和`endIndex`属性之间的所有单词，并计算这些单词与输入字符串之间的 Levenshtein 距离。它只会返回距离输入字符串最近的单词。如果在过程中找到比之前更接近的单词，它会清除结果列表并将新单词添加到该列表中。如果找到一个与目前找到的结果距离相同的单词，它会将该单词添加到结果列表中，如下所示：

```java
    @Override
    public BestMatchingData call() throws Exception {
        List<String> results=new ArrayList<String>();
        int minDistance=Integer.MAX_VALUE;
        int distance;
        for (int i=startIndex; i<endIndex; i++) {
            distance = LevenshteinDistance.calculate (word,dictionary.get(i));
            if (distance<minDistance) {
                results.clear();
                minDistance=distance;
                results.add(dictionary.get(i));
            } else if (distance==minDistance) {
                results.add(dictionary.get(i));
            }
        }
```

最后，我们创建了一个`BestMatchingData`对象，其中包含我们找到的单词列表及其与输入字符串的距离，并返回该对象。

```java
        BestMatchingData result=new BestMatchingData();
        result.setWords(results);
        result.setDistance(minDistance);
        return result;
    }
}
```

基于`Runnable`接口的任务与`run()`方法中包含的返回语句的主要区别。`run()`方法不返回值，因此这些任务无法返回结果。另一方面，`call()`方法返回一个对象（该对象的类在实现语句中定义），因此这种类型的任务可以返回结果。

### BestMatchingBasicConcurrentCalculation 类

这个类负责创建处理完整字典所需的任务，执行器来执行这些任务，并控制执行器中任务的执行。

它只有一个方法`getBestMatchingWords()`，接收两个输入参数：完整单词列表的字典和参考字符串。它返回一个包含算法结果的`BestMatchingData`对象。首先，我们创建并初始化了执行器。我们使用机器的核心数作为我们想要在其上使用的最大线程数。

```java
public class BestMatchingBasicConcurrentCalculation {

    public static BestMatchingData getBestMatchingWords(String word, List<String> dictionary) throws InterruptedException, ExecutionException {

        int numCores = Runtime.getRuntime().availableProcessors();
        ThreadPoolExecutor executor = (ThreadPoolExecutor) Executors.newFixedThreadPool(numCores);
```

然后，我们计算每个任务将处理的字典部分的大小，并创建一个`Future`对象的列表来存储任务的结果。当您将基于`Callable`接口的任务发送到执行器时，您将获得`Future`接口的实现。您可以使用该对象来：

+   知道任务是否已执行

+   获取任务执行的结果（`call()`方法返回的对象）

+   取消任务的执行

代码如下：

```java
        int size = dictionary.size();
        int step = size / numCores;
        int startIndex, endIndex;
        List<Future<BestMatchingData>> results = new ArrayList<>();
```

然后，我们创建任务，使用`submit()`方法将它们发送到执行器，并将该方法返回的`Future`对象添加到`Future`对象的列表中。`submit()`方法立即返回。它不会等待任务执行。我们有以下代码：

```java
        for (int i = 0; i < numCores; i++) {
            startIndex = i * step;
            if (i == numCores - 1) {
                endIndex = dictionary.size();
            } else {
                endIndex = (i + 1) * step;
            }
            BestMatchingBasicTask task = new BestMatchingBasicTask(startIndex, endIndex, dictionary, word);
            Future<BestMatchingData> future = executor.submit(task);
            results.add(future);
        }
```

一旦我们将任务发送到执行器，我们调用执行器的`shutdown()`方法来结束其执行，并迭代`Future`对象的列表以获取每个任务的结果。我们使用不带任何参数的`get()`方法。如果任务已经完成执行，该方法将返回`call()`方法返回的对象。如果任务尚未完成，该方法将使当前线程休眠，直到任务完成并且结果可用。

我们用任务的结果组成一个结果列表，因此我们将只返回与参考字符串最接近的单词列表如下：

```java
        executor.shutdown();
        List<String> words=new ArrayList<String>();
        int minDistance=Integer.MAX_VALUE;
        for (Future<BestMatchingData> future: results) {
            BestMatchingData data=future.get();
            if (data.getDistance()<minDistance) {
                words.clear();
                minDistance=data.getDistance();
                words.addAll(data.getWords());
            } else if (data.getDistance()==minDistance) {
                words.addAll(data.getWords());
            }

        }
```

最后，我们创建并返回一个`BestMatchingData`对象，其中包含算法的结果：

```java
        BestMatchingData result=new BestMatchingData();
        result.setDistance(minDistance);
        result.setWords(words);
        return result;
    }
}
```

### 注意

`BestMatchingConcurrentMain`类与之前介绍的`BestMatchingSerialMain`非常相似。唯一的区别是使用的类（`BestMatchingBasicConcurrentCalculation`而不是`BestMatchingSerialCalculation`），因此我们不在这里包含源代码。请注意，我们既没有使用线程安全的数据结构，也没有同步，因为我们的并发任务在独立的数据片段上工作，并且在并发任务终止后，最终结果是以顺序方式合并的。

## 最佳匹配算法 - 第二个并发版本

我们使用`AbstractExecutorService`的`invokeAll()`方法（在`ThreadPoolExecutorClass`中实现）实现了最佳匹配算法的第二个版本。在之前的版本中，我们使用了接收`Callable`对象并返回`Future`对象的`submit()`方法。`invokeAll()`方法接收`Callable`对象的`List`作为参数，并返回`Future`对象的`List`。第一个`Future`与第一个`Callable`相关联，依此类推。这两种方法之间还有另一个重要的区别。虽然`submit()`方法立即返回，但`invokeAll()`方法在所有`Callable`任务结束执行时返回。这意味着所有返回的`Future`对象在调用它们的`isDone()`方法时都将返回`true`。

为了实现这个版本，我们使用了前面示例中实现的`BestMatchingBasicTask`类，并实现了`BestMatchingAdvancedConcurrentCalculation`类。与`BestMatchingBasicConcurrentCalculation`类的区别在于任务的创建和结果的处理。在任务的创建中，现在我们创建一个列表并将其存储在我们要执行的任务上：

```java
        for (int i = 0; i < numCores; i++) {
            startIndex = i * step;
            if (i == numCores - 1) {
                endIndex = dictionary.size();
            } else {
                endIndex = (i + 1) * step;
            }
            BestMatchingBasicTask task = new BestMatchingBasicTask(startIndex, endIndex, dictionary, word);
            tasks.add(task);
        }
```

为了处理结果，我们调用`invokeAll()`方法，然后遍历返回的`Future`对象列表：

```java
        results = executor.invokeAll(tasks);
        executor.shutdown();
        List<String> words = new ArrayList<String>();
        int minDistance = Integer.MAX_VALUE;
        for (Future<BestMatchingData> future : results) {
            BestMatchingData data = future.get();
            if (data.getDistance() < minDistance) {
                words.clear();
                minDistance = data.getDistance();
                words.addAll(data.getWords());
            } else if (data.getDistance()== minDistance) {
                words.addAll(data.getWords());
            }
        }
        BestMatchingData result = new BestMatchingData();
        result.setDistance(minDistance);
        result.setWords(words);
        return result;
    }
```

为了执行这个版本，我们实现了`BestMatchingConcurrentAdvancedMain`。它的源代码与之前的类非常相似，因此不包括在内。

## 单词存在算法-串行版本

作为这个示例的一部分，我们实现了另一个操作，用于检查一个字符串是否存在于我们的单词列表中。为了检查单词是否存在，我们再次使用 Levenshtein 距离。如果一个单词与列表中的一个单词的距离为`0`，我们认为这个单词存在。如果我们使用`equals()`或`equalsIgnoreCase()`方法进行比较，或者将输入单词读入`HashSet`并使用`contains()`方法进行比较（比我们的版本更有效），会更快，但我们认为我们的版本对于本书的目的更有用。

与之前的示例一样，首先我们实现了操作的串行版本，以便将其作为实现并发版本的基础，并比较两个版本的执行时间。

为了实现串行版本，我们使用了两个类：

+   `ExistSerialCalculation`类实现了`existWord()`方法，将输入字符串与字典中的所有单词进行比较，直到找到它

+   `ExistSerialMain`类，启动示例并测量执行时间

让我们分析这两个类的源代码。

### `ExistSerialCalculation`类

这个类只有一个方法，即`existWord()`方法。它接收两个参数：我们要查找的单词和完整的单词列表。它遍历整个列表，计算输入单词与列表中的单词之间的 Levenshtein 距离，直到找到单词（距离为`0`）为止，此时返回`true`值，或者在没有找到单词的情况下完成单词列表，此时返回`false`值。

```java
public class ExistSerialCalculation {

    public static boolean existWord(String word, List<String> dictionary) {
        for (String str: dictionary) {
            if (LevenshteinDistance.calculate(word, str) == 0) {
                return true;
            }
        }
        return false;
    }
}
```

### `ExistSerialMain`类

这个类实现了`main()`方法来调用`exist()`方法。它将主方法的第一个参数作为我们要查找的单词，并调用该方法。它测量其执行时间并在控制台中显示结果。我们有以下代码：

```java
public class ExistSerialMain {

    public static void main(String[] args) {

        Date startTime, endTime;
        List<String> dictionary=WordsLoader.load("data/UK Advanced Cryptics Dictionary.txt");

        System.out.println("Dictionary Size: "+dictionary.size());

        startTime=new Date();
        boolean result=ExistSerialCalculation.existWord(args[0], dictionary);
        endTime=new Date(); 
        System.out.println("Word: "+args[0]);
        System.out.println("Exists: "+result);
        System.out.println("Execution Time: "+(endTime.getTime()- startTime.getTime()));
    }
}
```

## 单词存在算法-并发版本

要实现这个操作的并发版本，我们必须考虑它最重要的特点。我们不需要处理整个单词列表。当我们找到单词时，我们可以结束列表的处理并返回结果。这种不处理整个输入数据并在满足某些条件时停止的操作称为**短路操作**。

`AbstractExecutorService`接口定义了一个操作（在`ThreadPoolExecutor`类中实现），与这个想法完美契合。它是`invokeAny()`方法。这个方法将`Callable`任务列表发送到执行器，并返回第一个完成执行而不抛出异常的任务的结果。如果所有任务都抛出异常，这个方法会抛出`ExecutionException`异常。

与之前的示例一样，我们实现了不同的类来实现这个算法的版本：

+   `ExistBasicTask`类实现了我们将在执行器中执行的任务

+   `ExistBasicConcurrentCalculation`类创建执行器和任务，并将任务发送到执行器。

+   `ExistBasicConcurrentMain`类执行示例并测量其运行时间

### ExistBasicTasks 类

这个类实现了将要搜索这个单词的任务。它实现了参数化为`Boolean`类的`Callable`接口。如果任务找到单词，`call()`方法将返回`true`值。它使用四个内部属性：

+   完整的单词列表

+   列表中任务将处理的第一个单词（包括）

+   任务将处理的列表中的最后一个单词（不包括）

+   任务将要查找的单词

我们有以下代码：

```java
public class ExistBasicTask implements Callable<Boolean> {

    private int startIndex;

    private int endIndex;

    private List<String> dictionary;

    private String word;

    public ExistBasicTask(int startIndex, int endIndex, List<String> dictionary, String word) {
        this.startIndex=startIndex;
        this.endIndex=endIndex;
        this.dictionary=dictionary;
        this.word=word;
    }
```

`call`方法将遍历分配给该任务的列表部分。它计算输入单词与列表中单词之间的 Levenshtein 距离。如果找到单词，它将返回`true`值。

如果任务处理了所有的单词但没有找到这个单词，它将抛出一个异常以适应`invokeAny()`方法的行为。如果任务在这种情况下返回`false`值，`invokeAny()`方法将立即返回`false`值，而不会等待其他任务。也许另一个任务会找到这个单词。

我们有以下代码：

```java
    @Override
    public Boolean call() throws Exception {
        for (int i=startIndex; i<endIndex; i++) {
            if (LevenshteinDistance.calculate(word, dictionary.get(i))==0) {
                return true;
            }
        }
            if (Thread.interrupted()) {
                return false;
            }
        throw new NoSuchElementException("The word "+word+" doesn't exists.");
    }
```

### ExistBasicConcurrentCalculation 类

这个类将在完整的单词列表中执行输入单词的搜索，创建并执行必要的任务。它只实现了一个名为`existWord()`的方法。它接收两个参数，输入字符串和完整的单词列表，并返回一个布尔值，指示单词是否存在。

首先，我们创建执行任务的执行器。我们使用`Executor`类，并创建一个`ThreadPoolExecutor`类，最大线程数由机器的可用硬件线程数确定，如下所示：

```java
public class ExistBasicConcurrentCalculation {

    public static boolean existWord(String word, List<String> dictionary) throws InterruptedException, ExecutionException{
        int numCores = Runtime.getRuntime().availableProcessors();
        ThreadPoolExecutor executor = (ThreadPoolExecutor) Executors.newFixedThreadPool(numCores);
```

然后，我们创建与执行器中运行的线程数相同数量的任务。每个任务将处理单词列表的一个相等部分。我们创建任务并将它们存储在一个列表中：

```java
        int size = dictionary.size();
        int step = size / numCores;
        int startIndex, endIndex;
        List<ExistBasicTask> tasks = new ArrayList<>();

        for (int i = 0; i < numCores; i++) {
            startIndex = i * step;
            if (i == numCores - 1) {
                endIndex = dictionary.size();
            } else {
                endIndex = (i + 1) * step;
            }
            ExistBasicTask task = new ExistBasicTask(startIndex, endIndex, dictionary,
                    word);
            tasks.add(task);
        }
```

然后，我们使用`invokeAny()`方法在执行器中执行任务。如果方法返回布尔值，则单词存在。我们返回该值。如果方法抛出异常，则单词不存在。我们在控制台打印异常并返回`false`值。在这两种情况下，我们调用执行器的`shutdown()`方法来终止其执行，如下所示：

```java
        try {
            Boolean result=executor.invokeAny(tasks);
            return result;
        } catch (ExecutionException e) {
            if (e.getCause() instanceof NoSuchElementException)
                return false;
            throw e;
        } finally {
            executor.shutdown();
        }
    }
}
```

### ExistBasicConcurrentMain 类

这个类实现了这个示例的`main()`方法。它与`ExistSerialMain`类相同，唯一的区别是它使用`ExistBasicConcurrentCalculation`类而不是`ExistSerialCalculation`，因此它的源代码没有包含。

## 比较解决方案

让我们比较我们在本节中实现的两个操作的不同解决方案（串行和并发）。为了测试算法，我们使用了 JMH 框架（[`openjdk.java.net/projects/code-tools/jmh/`](http://openjdk.java.net/projects/code-tools/jmh/)），它允许您在 Java 中实现微基准测试。使用基准测试框架比简单地使用`currentTimeMillis()`或`nanoTime()`方法来测量时间更好。我们在一个四核处理器的计算机上执行了 10 次，并计算了这 10 次的中等执行时间。让我们分析执行结果。

### 最佳匹配算法

在这种情况下，我们实现了算法的三个版本：

+   串行版本

+   并发版本，一次发送一个任务

+   并发版本，使用`invokeAll()`方法

为了测试算法，我们使用了三个不在单词列表中的不同字符串：

+   `Stitter`

+   `Abicus`

+   `Lonx`

这些是最佳匹配算法对每个单词返回的单词：

+   `Stitter`：`sitter`、`skitter`、`slitter`、`spitter`、`stilter`、`stinter`、`stotter`、`stutter`和`titter`

+   `Abicus`：`abacus`和`amicus`

+   `Lonx`：`lanx`、`lone`、`long`、`lox`和`lynx`

下表讨论了中等执行时间及其毫秒标准偏差：

| 算法 | Stitter | Abicus | lonx |
| --- | --- | --- | --- |
| 串行 | 467.01 ± 23.40 | 408.03 ± 14.66 | 317.60 ± 28.78 |
| 并发：`submit()`方法 | 209.72 ± 74.79 | 184.10 ± 90.47 | 155.61 ± 65.43 |
| 并发：`invokeAll()`方法 | 217.66 ± 65.46 | 188.28 ± 81.28 | 160.43 ± 65.14 |

我们可以得出以下结论：

+   算法的并发版本比串行版本获得更好的性能。

+   算法的并发版本之间获得了类似的结果。所有并发版本的标准偏差值都非常高。我们可以使用单词`lonx`的加速度比来比较并发版本方法和串行版本，以了解并发如何提高算法的性能：![最佳匹配算法](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-cncr-prog-java8/img/00011.jpeg)

### 存在的算法

在这种情况下，我们实现了两个版本的算法：

+   串行版本

+   使用`invokeAny()`方法的并发版本

为了测试算法，我们使用了一些字符串：

+   在单词列表中不存在的单词`xyzt`

+   在单词列表的末尾附近存在的单词`stutter`

+   在单词列表的开始附近存在的单词`abacus`

+   在单词列表的后半部分之后存在的单词`lynx`

毫秒中的中等执行时间和它们的标准偏差显示在下表中：

| 算法 | 单词 | 执行时间（毫秒） |
| --- | --- | --- |
| 串行 | `abacus` | 50.70 ± 13.95 |
|   | `lynx` | 194.41 ± 26.02 |
| `stutter` | 398.11 ± 23.4 |
| `xyzt` | 315.62 ± 28.7 |
| 并发 | `abacus` | 50.72 ± 7.17 |
|   | `lynx` | 69.15 ± 62.5 |
| `stutter` | 126.74 ± 104.52 |
| `xyzt` | 203.37 ± 76.67 |

我们可以得出以下结论：

+   一般来说，并发版本的算法比串行版本提供更好的性能。

+   单词在列表中的位置是一个关键因素。对于单词`abacus`，它出现在列表的开头，两种算法给出了类似的执行时间，但对于单词`stutter`，差异非常大。

+   并发情况下的标准偏差非常大。

如果我们使用加速度比较并发版本和串行版本的单词`lynx`，结果是：

![存在的算法](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-cncr-prog-java8/img/00012.jpeg)

# 第二个例子 - 为文档集合创建倒排索引

在**信息检索**领域，**倒排索引**是一种常用的数据结构，用于加速对文档集合中文本的搜索。它存储文档集合的所有单词以及包含该单词的文档列表。

要构建索引，我们必须解析集合中的所有文档，并以增量方式构建索引。对于每个文档，我们提取该文档的重要单词（删除最常见的单词，也称为停用词，可能应用词干算法），然后将这些单词添加到索引中。如果单词存在于索引中，我们将文档添加到与该单词关联的文档列表中。如果单词不存在，则将单词添加到索引的单词列表中，并将文档与该单词关联。您可以添加参数到关联中，如单词在文档中的**词频**，这将为您提供更多信息。

当您在文档集合中搜索一个单词或一组单词时，您使用倒排索引来获取与每个单词关联的文档列表，并创建一个包含搜索结果的唯一列表。

在本节中，您将学习如何使用 Java 并发工具来为文档集合构建倒排索引文件。作为文档集合，我们已经获取了包含有关电影信息的维基百科页面，以构建一组 100,673 个文档。我们已经将每个维基百科页面转换为文本文件。您可以下载包含有关该书的所有信息的文档集合。

为了构建倒排索引，我们不删除任何单词，也不使用任何词干算法。我们希望尽可能简单地保持算法，以便将注意力集中在并发工具上。

这里解释的相同原则可以用于获取关于文档集合的其他信息，例如，每个文档的向量表示，可以作为**聚类算法**的输入，正如您将在第六章中学到的，*优化分治解决方案 - 分叉/加入框架*。

与其他示例一样，您将实现这些操作的串行和并发版本，以验证并发在这种情况下是否有帮助。

## 通用类

串行和并发版本都共同使用类将文档集合加载到 Java 对象中。我们使用了以下两个类：

+   存储在文档中的单词列表的`Document`类

+   `DocumentParse`类将存储在文件中的文档转换为文档对象

让我们分析这两个类的源代码。

### Document 类

`Document`类非常简单。它只有两个属性和用于获取和设置这些属性值的方法。这些属性是：

+   文件名，作为字符串。

+   词汇表（即文档中使用的单词列表）作为`HashMap`。**键**是**单词**，值是单词在文档中出现的次数。

### DocumentParser 类

正如我们之前提到的，这个类将存储在文件中的文档转换为`Document`对象。它将这个单词分成三个方法。第一个是`parse()`方法，它接收文件路径作为参数，并返回该文档的词汇`HashMap`。这个方法逐行读取文件，并使用`parseLine()`方法将每一行转换为一个单词列表，并将它们添加到词汇中，如下所示：

```java
public class DocumentParser {

    public Map<String, Integer>  parse(String route) {
        Map<String, Integer> ret=new HashMap<String,Integer>();
        Path file=Paths.get(route);
        try ( BufferedReader reader = Files.newBufferedReader(file)) {
                String line = null;
                while ((line = reader.readLine()) != null) {
                    parseLine(line,ret);
                }
            } catch (IOException x) {
              x.printStackTrace();
            } catch (Exception e) {
              e.printStackTrace();
            }
        return ret;

    }
```

`parseLine()`方法处理提取其单词的行。我们认为一个单词是一个字母序列，以便继续这个例子的简单性。我们已经使用了`Pattern`类来提取单词，使用`Normalizer`类将单词转换为小写并删除元音的重音，如下所示：

```java
private static final Pattern PATTERN = Pattern.compile("\\P{IsAlphabetic}+");

private void parseLine(String line, Map<String, Integer> ret) {
  for(String word: PATTERN.split(line)) {
    if(!word.isEmpty())
      ret.merge(Normalizer.normalize(word, Normalizer.Form.NFKD).toLowerCase(), 1, (a, b) -> a+b);
  }
}
```

## 串行版本

这个示例的串行版本是在`SerialIndexing`类中实现的。这个类有一个`main()`方法，它读取所有文档，获取其词汇，并以增量方式构建倒排索引。

首先，我们初始化必要的变量。文档集合存储在数据目录中，因此我们将所有文档存储在`File`对象的数组中。我们还初始化了`invertedIndex`对象。我们使用`HashMap`，其中键是单词，值是包含该单词的文件名的字符串对象列表，如下所示：

```java
public class SerialIndexing {

    public static void main(String[] args) {

        Date start, end;

        File source = new File("data");
        File[] files = source.listFiles();
        Map<String, List<String>> invertedIndex=new HashMap<String,List<String>> ();
```

然后，我们使用`DocumentParse`类解析所有文档，并使用`updateInvertedIndex()`方法将从每个文档获得的词汇添加到倒排索引中。我们测量整个过程的执行时间。我们有以下代码：

```java
        start=new Date();
        for (File file : files) {

            DocumentParser parser = new DocumentParser();

            if (file.getName().endsWith(".txt")) {
                Map<String, Integer> voc = parser.parse (file.getAbsolutePath());
                updateInvertedIndex(voc,invertedIndex, file.getName());
            }
        }
        end=new Date();
```

最后，我们在控制台上显示执行结果：

```java
        System.out.println("Execution Time: "+(end.getTime()- start.getTime()));
        System.out.println("invertedIndex: "+invertedIndex.size());
    }
```

`updateInvertedIndex()`方法将文档的词汇添加到倒排索引结构中。它处理构成词汇的所有单词。如果单词存在于倒排索引中，我们将文档的名称添加到与该单词关联的文档列表中。如果单词不存在，我们将单词添加并将文档与该单词关联，如下所示：

```java
private static void updateInvertedIndex(Map<String, Integer> voc, Map<String, List<String>> invertedIndex, String fileName) {
  for (String word : voc.keySet()) {
    if (word.length() >= 3) {
      invertedIndex.computeIfAbsent(word, k -> new ArrayList<>()).add(fileName);
    }
  }
}
```

## 第一个并发版本 - 每个文档一个任务

现在是时候实现文本索引算法的并发版本了。显然，我们可以并行处理每个文档的过程。这包括从文件中读取文档并处理每一行以获取文档的词汇表。任务可以将该词汇表作为它们的结果返回，因此我们可以基于`Callable`接口实现任务。

在前面的例子中，我们使用了三种方法将`Callable`任务发送到执行程序：

+   提交()

+   调用所有()

+   调用任意()

我们必须处理所有文档，因此我们必须放弃`invokeAny()`方法。另外两种方法都不方便。如果我们使用`submit()`方法，我们必须决定何时处理任务的结果。如果我们为每个文档发送一个任务，我们可以处理结果：

+   在发送每个任务之后，这是不可行的

+   在所有任务完成后，我们必须存储大量的`Future`对象

+   在发送一组任务后，我们必须包含代码来同步这两个操作。

所有这些方法都有一个问题：我们以顺序方式处理任务的结果。如果我们使用`invokeAll()`方法，我们就处于类似于第 2 点的情况。我们必须等待所有任务完成。

一个可能的选择是创建其他任务来处理与每个任务相关的`Future`对象，而 Java 并发 API 为我们提供了一种优雅的解决方案，即使用`CompletionService`接口及其实现，即`ExecutorCompletionService`类。

`CompletionService`对象是一个具有执行程序的机制，它允许您解耦任务的生产和对这些任务结果的消费。您可以使用`submit()`方法将任务发送到执行程序，并在任务完成时使用`poll()`或`take()`方法获取任务的结果。因此，对于我们的解决方案，我们将实现以下元素：

+   一个`CompletionService`对象来执行任务。

+   每个文档一个任务，解析文档并生成其词汇表。这个任务将由`CompletionService`对象执行。这些任务在`IndexingTask`类中实现。

+   两个线程来处理任务的结果并构建倒排索引。这些线程在`InvertedIndexTask`类中实现。

+   一个`main()`方法来创建和执行所有元素。这个`main()`方法是在`ConcurrentIndexingMain`类中实现的。

让我们分析这些类的源代码。

### IndexingTask 类

这个类实现了解析文档以获取其词汇表的任务。它实现了参数化为`Document`类的`Callable`接口。它有一个内部属性来存储代表它必须解析的文档的`File`对象。看一下下面的代码：

```java
public class IndexingTask implements Callable<Document> {
    private File file;
    public IndexingTask(File file) {
        this.file=file;
    }
```

在`call()`方法中，它简单地使用`DocumentParser`类的`parse()`方法来解析文档并获取词汇表，并创建并返回包含获取的数据的`Document`对象：

```java
    @Override
    public Document call() throws Exception {
        DocumentParser parser = new DocumentParser();

        Map<String, Integer> voc = parser.parse(file.getAbsolutePath());

        Document document=new Document();
        document.setFileName(file.getName());
        document.setVoc(voc);
        return document;
    }
}
```

### InvertedIndexTask 类

这个类实现了获取`IndexingTask`对象生成的`Document`对象并构建倒排索引的任务。这些任务将作为`Thread`对象执行（在这种情况下我们不使用执行程序），因此它们基于`Runnable`接口。

`InvertedIndexTask`类使用三个内部属性：

+   一个参数化为`Document`类的`CompletionService`对象，以访问`IndexingTask`对象返回的对象。

+   一个`ConcurrentHashMap`来存储倒排索引。键是单词，值是`ConcurrentLinkedDeque`，其中包含文件的名称。在这种情况下，我们必须使用并发数据结构，而串行版本中使用的数据结构没有同步。

+   一个布尔值来指示任务可以完成其工作。

其代码如下：

```java
public class InvertedIndexTask implements Runnable {

    private CompletionService<Document> completionService;
    private ConcurrentHashMap<String, ConcurrentLinkedDeque<String>> invertedIndex;

    public InvertedIndexTask(CompletionService<Document> completionService,
            ConcurrentHashMap<String, ConcurrentLinkedDeque<String>> invertedIndex) {
        this.completionService = completionService;
        this.invertedIndex = invertedIndex;

    }
```

`run()`方法使用`CompletionService`的`take()`方法获取与任务关联的`Future`对象。我们实现一个循环，直到线程被中断为止。一旦线程被中断，它将使用`take()`方法再次处理所有未决的`Future`对象。我们使用`take()`方法返回的对象更新倒排索引，使用`updateInvertedIndex()`方法。我们有以下方法：

```java
public void run() {
        try {
            while (!Thread.interrupted()) {
                try {
                    Document document = completionService.take().get();
                    updateInvertedIndex(document.getVoc(), invertedIndex, document.getFileName());
                } catch (InterruptedException e) {
                    break;
                }
            }
            while (true) {
                Future<Document> future = completionService.poll();
                if (future == null)
                    break;
                Document document = future.get();
                updateInvertedIndex(document.getVoc(), invertedIndex, document.getFileName());
            }
        } catch (InterruptedException | ExecutionException e) {
            e.printStackTrace();
        }
    }
```

最后，`updateInvertedIndex`方法接收从文档中获取的词汇表、倒排索引和已处理文件的名称作为参数。它处理词汇表中的所有单词。如果单词不存在，我们使用`computeIfAbsent()`方法将单词添加到`invertedIndex`中：

```java
     private void updateInvertedIndex(Map<String, Integer> voc, ConcurrentHashMap<String, ConcurrentLinkedDeque<String>> invertedIndex, String fileName) {
        for (String word : voc.keySet()) {
            if (word.length() >= 3) {
                invertedIndex.computeIfAbsent(word, k -> new ConcurrentLinkedDeque<>()).add(fileName);
            }
        }
    }
```

### 并发索引类

这是示例中的主要类。它创建和启动所有组件，等待其完成，并在控制台中打印最终执行时间。

首先，它创建并初始化了所有需要执行的变量：

+   一个执行器来运行`InvertedTask`任务。与之前的示例一样，我们使用机器的核心数作为执行器中工作线程的最大数量，但在这种情况下，我们留出一个核心来执行独立线程。

+   一个`CompletionService`对象来运行任务。我们使用之前创建的执行程序来初始化这个对象。

+   一个`ConcurrentHashMap`来存储倒排索引。

+   一个`File`对象数组，其中包含我们需要处理的所有文档。

我们有以下方法：

```java
public class ConcurrentIndexing {

    public static void main(String[] args) {

        int numCores=Runtime.getRuntime().availableProcessors();
        ThreadPoolExecutor executor=(ThreadPoolExecutor) Executors.newFixedThreadPool(Math.max(numCores-1, 1));
        ExecutorCompletionService<Document> completionService=new ExecutorCompletionService<>(executor);
        ConcurrentHashMap<String, ConcurrentLinkedDeque<String>> invertedIndex=new ConcurrentHashMap <String,ConcurrentLinkedDeque<String>> ();

        Date start, end;

        File source = new File("data");
        File[] files = source.listFiles();
```

然后，我们处理数组中的所有文件。对于每个文件，我们创建一个`InvertedTask`对象，并使用`submit()`方法将其发送到`CompletionService`类：

```java
        start=new Date();
        for (File file : files) {
            IndexingTask task=new IndexingTask(file);
            completionService.submit(task);
        }
```

然后，我们创建两个`InvertedIndexTask`对象来处理`InvertedTask`任务返回的结果，并将它们作为普通的`Thread`对象执行：

```java
        InvertedIndexTask invertedIndexTask=new InvertedIndexTask(completionService,invertedIndex);
        Thread thread1=new Thread(invertedIndexTask);
        thread1.start();
        InvertedIndexTask invertedIndexTask2=new InvertedIndexTask(completionService,invertedIndex);
        Thread thread2=new Thread(invertedIndexTask2);
        thread2.start();
```

一旦我们启动了所有元素，我们等待执行器的完成，使用`shutdown()`和`awaitTermination()`方法。`awaitTermination()`方法将在所有`InvertedTask`任务完成执行时返回，因此我们可以完成执行`InvertedIndexTask`任务的线程。为此，我们中断这些线程（参见我关于`InvertedIndexTask`的评论）。

```java
        executor.shutdown();
        try {
            executor.awaitTermination(1, TimeUnit.DAYS);
            thread1.interrupt();
            thread2.interrupt();
            thread1.join();
            thread2.join();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
```

最后，我们在控制台中写入倒排索引的大小和整个过程的执行时间：

```java
        end=new Date();
        System.out.println("Execution Time: "+(end.getTime()- start.getTime()));
        System.out.println("invertedIndex: "+invertedIndex.size());
    }

}
```

## 第二个并发版本 - 每个任务处理多个文档

我们实现了这个示例的第二个并发版本。基本原则与第一个版本相同，但在这种情况下，每个任务将处理多个文档而不是只有一个。每个任务处理的文档数量将是主方法的输入参数。我们已经测试了每个任务处理 100、1,000 和 5,000 个文档的结果。

为了实现这种新方法，我们将实现三个新类：

+   `MultipleIndexingTask`类，相当于`IndexingTask`类，但它将处理一个文档列表，而不是只有一个

+   `MultipleInvertedIndexTask`类，相当于`InvertedIndexTask`类，但现在任务将检索一个`Document`对象的列表，而不是只有一个

+   `MultipleConcurrentIndexing`类，相当于`ConcurrentIndexing`类，但使用新的类

由于大部分源代码与之前的版本相似，我们只展示不同之处。

### 多重索引任务类

正如我们之前提到的，这个类与之前介绍的`IndexingTask`类相似。主要区别在于它使用一个`File`对象的列表，而不是只有一个文件：

```java
public class MultipleIndexingTask implements Callable<List<Document>> {

    private List<File> files;

    public MultipleIndexingTask(List<File> files) {
        this.files = files;
    }
```

`call()`方法返回一个`Document`对象的列表，而不是只有一个：

```java
    @Override
    public List<Document> call() throws Exception {
        List<Document> documents = new ArrayList<Document>();
        for (File file : files) {
            DocumentParser parser = new DocumentParser();

            Hashtable<String, Integer> voc = parser.parse (file.getAbsolutePath());

            Document document = new Document();
            document.setFileName(file.getName());
            document.setVoc(voc);

            documents.add(document);
        }

        return documents;
    }
}
```

### 多重倒排索引任务类

正如我们之前提到的，这个类与之前介绍的`InvertedIndexClass`类相似。主要区别在于`run（）`方法。`poll（）`方法返回的`Future`对象返回一个`Document`对象列表，因此我们必须处理整个列表。

```java
    @Override
    public void run() {
        try {
            while (!Thread.interrupted()) {
                try {
                    List<Document> documents = completionService.take().get();
                    for (Document document : documents) {
                        updateInvertedIndex(document.getVoc(), invertedIndex, document.getFileName());
                    }
                } catch (InterruptedException e) {
                    break;
                }
            }
            while (true) {
                Future<List<Document>> future = completionService.poll();
                if (future == null)
                    break;
                List<Document> documents = future.get();
                for (Document document : documents) {
                    updateInvertedIndex(document.getVoc(), invertedIndex, document.getFileName());
                }
            }
        } catch (InterruptedException | ExecutionException e) {
            e.printStackTrace();
        }
    }
```

### MultipleConcurrentIndexing 类

正如我们之前提到的，这个类与`ConcurrentIndexing`类相似。唯一的区别在于利用新类和使用第一个参数来确定每个任务处理的文档数量。我们有以下方法：

```java
        start=new Date();
        List<File> taskFiles=new ArrayList<>();
        for (File file : files) {
            taskFiles.add(file);
            if (taskFiles.size()==NUMBER_OF_TASKS) {
                MultipleIndexingTask task=new MultipleIndexingTask(taskFiles);
                completionService.submit(task);
                taskFiles=new ArrayList<>();
            }
        }
        if (taskFiles.size()>0) {
            MultipleIndexingTask task=new MultipleIndexingTask(taskFiles);
            completionService.submit(task);
        }

        MultipleInvertedIndexTask invertedIndexTask=new MultipleInvertedIndexTask (completionService,invertedIndex);
        Thread thread1=new Thread(invertedIndexTask);
        thread1.start();
        MultipleInvertedIndexTask invertedIndexTask2=new MultipleInvertedIndexTask (completionService,invertedIndex);
        Thread thread2=new Thread(invertedIndexTask2);
        thread2.start();
```

## 比较解决方案

让我们比较一下我们实现的三个版本的解决方案。正如我们之前提到的，就像文档集合一样，我们已经获取了包含有关电影信息的维基百科页面，构建了一组 100,673 个文档。我们已经将每个维基百科页面转换成了一个文本文件。您可以下载包含有关该书的所有信息的文档集合。

我们执行了五个不同版本的解决方案：

+   串行版本

+   每个文档一个任务的并发版本

+   具有多个任务的并发版本，每个文档 100、1,000 和 5,000 个文档

以下表格显示了五个版本的执行时间：

| 算法 | 执行时间（毫秒） |
| --- | --- |
| 串行 | 69,480.50 |
| 并发：每个任务一个文档 | 49,655.49 |
| 并发：每个任务 100 个文档 | 48,438.14 |
| 并发：每个任务 1,000 个文档 | 49,362.37 |
| 并发：每个任务 5,000 个文档 | 58,362.22 |

我们可以得出以下结论：

+   并发版本总是比串行版本获得更好的性能

+   对于并发版本，如果我们增加每个任务的文档数量，结果会变得更糟。

如果我们使用加速比将并发版本与串行版本进行比较，结果如下：

![比较解决方案](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-cncr-prog-java8/img/00013.jpeg)

## 其他感兴趣的方法

在本章中，我们使用了`AbstractExecutorService`接口（在`ThreadPoolExecutor`类中实现）和`CompletionService`接口（在`ExecutorCompletionService`中实现）的一些方法来管理`Callable`任务的结果。但是，我们还有其他版本的方法和其他要在这里提到的方法。

关于`AbstractExecutorService`接口，让我们讨论以下方法：

+   `invokeAll（Collection<? extends Callable<T>> tasks, long timeout, TimeUnit unit）`：此方法在所有任务完成其执行或第二个和第三个参数指定的超时到期时，返回与作为参数传递的`Callable`任务列表相关联的`Future`对象列表。

+   `invokeAny（Collection<? Extends Callable<T>> tasks, long timeout, TimeUnit unit）`：此方法返回作为参数传递的`Callable`任务列表中第一个任务的结果，如果它在第二个和第三个参数指定的超时之前完成执行而不抛出异常，则超时后抛出`TimeoutException`异常。

关于`CompletionService`接口，让我们讨论以下方法：

+   `poll（）`方法：我们使用了带有两个参数的此方法的版本，但也有一个不带参数的版本。从内部数据结构来看，此版本检索并删除自上次调用`poll（）`或`take（）`方法以来已完成的下一个任务的`Future`对象。如果没有任务完成，其执行返回`null`值。

+   “take（）”方法：此方法类似于上一个方法，但如果没有任务完成，它会使线程休眠，直到一个任务完成其执行。

# 总结

在本章中，您学习了可以用来处理返回结果的任务的不同机制。这些任务基于`Callable`接口，该接口声明了`call（）`方法。这是一个由`call`方法返回的类的参数化接口。

当您在执行器中执行`Callable`任务时，您将始终获得`Future`接口的实现。您可以使用此对象来取消任务的执行，了解任务是否已完成其执行或获取“call（）”方法返回的结果。

您可以使用三种不同的方法将`Callable`任务发送到执行器。使用“submit（）”方法，您发送一个任务，并且将立即获得与此任务关联的`Future`对象。使用“invokeAll（）”方法，您发送一个任务列表，并在所有任务完成执行时获得`Future`对象列表。使用“invokeAny（）”方法，您发送一个任务列表，并且将接收第一个完成而不抛出异常的任务的结果（不是`Future`对象）。其余任务将被取消。

Java 并发 API 提供了另一种机制来处理这些类型的任务。这种机制在`CompletionService`接口中定义，并在`ExecutorCompletionService`类中实现。该机制允许您解耦任务的执行和其结果的处理。`CompletionService`接口在内部使用执行器，并提供“submit（）”方法将任务发送到`CompletionService`接口，并提供“poll（）”和“take（）”方法来获取任务的结果。这些结果以任务完成执行的顺序提供。

您还学会了如何在两个真实世界的例子中实现这些概念：

+   使用 UKACD 数据集的最佳匹配算法

+   使用从维基百科提取的有关电影的信息的数据集的倒排索引构造器

在下一章中，您将学习如何以并发方式执行可以分为阶段的算法，例如关键词提取算法。您可以按照以下三个步骤实现该算法：

1.  第一步 - 解析所有文档并提取所有单词。

1.  第二步 - 计算每个文档中每个单词的重要性。

1.  第三步 - 获取最佳关键词。

这些步骤的主要特点是，您必须在开始下一个步骤之前完全完成一个步骤。Java 并发 API 提供了`Phaser`类来促进这些算法的并发实现。它允许您在阶段结束时同步涉及其中的所有任务，因此在所有任务完成当前任务之前，没有一个任务会开始下一个任务。
