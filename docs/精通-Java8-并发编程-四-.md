# 精通 Java8 并发编程（四）

> 原文：[`zh.annas-archive.org/md5/BFECC9856BE4118734A8147A2EEBA11A`](https://zh.annas-archive.org/md5/BFECC9856BE4118734A8147A2EEBA11A)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：使用并行流处理大型数据集-映射和减少模型

毫无疑问，Java 8 引入的最重要的创新是 lambda 表达式和 stream API。流是可以按顺序或并行方式处理的元素序列。我们可以应用中间操作来转换流，然后执行最终计算以获得所需的结果（列表、数组、数字等）。在本章中，我们将涵盖以下主题：

+   流的介绍

+   第一个例子-数字摘要应用程序

+   第二个例子-信息检索搜索工具

# 流的介绍

流是一系列数据（不是数据结构），允许您以顺序或并行方式应用一系列操作来过滤、转换、排序、减少或组织这些元素以获得最终对象。例如，如果您有一个包含员工数据的流，您可以使用流来：

+   计算员工的总数

+   计算居住在特定地方的所有员工的平均工资

+   获取未达到目标的员工列表

+   任何涉及所有或部分员工的操作

流受到函数式编程的极大影响（Scala 编程语言提供了一个非常类似的机制），并且它们被设计用于使用 lambda 表达式。流 API 类似于 C#语言中可用的 LINQ（Language-Integrated Query）查询，在某种程度上可以与 SQL 查询进行比较。

在接下来的章节中，我们将解释流的基本特性以及您将在流中找到的部分。

## 流的基本特性

流的主要特点是：

+   流不存储它的元素。流从其源获取元素，并将它们发送到形成管道的所有操作中。

+   您可以在并行中使用流而无需额外工作。创建流时，您可以使用`stream()`方法创建顺序流，或使用`parallelStream()`创建并发流。`BaseStream`接口定义了`sequential()`方法以获取流的顺序版本，以及`parallel()`以获取流的并发版本。您可以将顺序流转换为并行流，将并行流转换为顺序流，反复多次。请注意，当执行终端流操作时，所有流操作将根据最后的设置进行处理。您不能指示流按顺序执行某些操作，同时按并发方式执行其他操作。在 Oracle JDK 8 和 Open JDK 8 中，内部使用 Fork/Join 框架的实现来执行并发操作。

+   流受到函数式编程和 Scala 编程语言的极大影响。您可以使用新的 lambda 表达式来定义在流操作中执行的算法。

+   流不能重复使用。例如，当您从值列表中获取流时，您只能使用该流一次。如果您想对相同的数据执行另一个操作，您必须创建一个新的流。

+   流对数据进行延迟处理。直到必要时才获取数据。正如您将在后面学到的，流有一个起源、一些中间操作和一个终端操作。直到终端操作需要它，数据才会被处理，因此流处理直到执行终端操作才开始。

+   您无法以不同的方式访问流的元素。当您有一个数据结构时，您可以访问其中存储的一个确定的元素，例如指定其位置或其键。流操作通常统一处理元素，因此您唯一拥有的就是元素本身。您不知道元素在流中的位置和相邻元素。在并行流的情况下，元素可以以任何顺序进行处理。

+   流操作不允许您修改流源。例如，如果您将列表用作流源，可以将处理结果存储到新列表中，但不能添加，删除或替换原始列表的元素。尽管听起来很受限制，但这是一个非常有用的功能，因为您可以返回从内部集合创建的流，而不必担心列表将被调用者修改。

## 流的部分

流有三个不同的部分：

+   一个**源**，生成流所消耗的数据。

+   零个或多个**中间操作**，生成另一个流作为输出。

+   一个**终端操作**，生成一个对象，可以是一个简单对象或一个集合，如数组，列表或哈希表。还可以有不产生任何显式结果的终端操作。

### 流的源

流的源生成将由`Stream`对象处理的数据。您可以从不同的源创建流。例如，`Collection`接口在 Java 8 中包含了`stream()`方法来生成顺序流，`parallelStream()`来生成并行流。这使您可以生成一个流来处理几乎所有 Java 中实现的数据结构的数据，如列表（`ArrayList`，`LinkedList`等），集合（`HashSet`，`EnumSet`）或并发数据结构（`LinkedBlockingDeque`，`PriorityBlockingQueue`等）。另一个可以生成流的数据结构是数组。`Array`类包括`stream()`方法的四个版本，用于从数组生成流。如果您将`int`数组传递给该方法，它将生成`IntStream`。这是一种专门用于处理整数的流（您仍然可以使用`Stream<Integer>`而不是`IntStream`，但性能可能会显着下降）。类似地，您可以从`long[]`或`double[]`数组创建`LongStream`或`DoubleStream`。

当然，如果您将对象数组传递给`stream()`方法，您将获得相同类型的通用流。在这种情况下，没有`parallelStream()`方法，但是一旦您获得了流，您可以调用`BaseStream`接口中定义的`parallel()`方法，将顺序流转换为并发流。

`Stream` API 提供的另一个有趣的功能是，您可以生成并流来处理目录或文件的内容。`Files`类提供了使用流处理文件的不同方法。例如，`find()`方法返回一个流，其中包含满足某些条件的文件树中的`Path`对象。`list()`方法返回一个包含目录内容的`Path`对象的流。`walk()`方法返回一个使用深度优先算法处理目录树中所有对象的`Path`对象流。但最有趣的方法是`lines()`方法，它创建一个包含文件行的`String`对象流，因此您可以使用流来处理其内容。不幸的是，除非您有成千上万的元素（文件或行），这里提到的所有方法都无法很好地并行化。

此外，您可以使用`Stream`接口提供的两种方法来创建流：`generate()`和`iterate()`方法。`generate()`方法接收一个参数化为对象类型的`Supplier`作为参数，并生成该类型的对象的无限顺序流。`Supplier`接口具有`get()`方法。每当流需要一个新对象时，它将调用此方法来获取流的下一个值。正如我们之前提到的，流以一种懒惰的方式处理数据，因此流的无限性质并不成问题。您将使用其他方法将该流转换为有限方式。`iterate()`方法类似，但在这种情况下，该方法接收一个种子和一个`UnaryOperator`。第一个值是将`UnaryOperator`应用于种子的结果；第二个值是将`UnaryOperator`应用于第一个结果的结果，依此类推。在并发应用程序中应尽量避免使用此方法，因为它们的性能问题。

还有更多的流来源如下：

+   `String.chars()`: 返回一个`IntStream`，其中包含`String`的`char`值。

+   `Random.ints()`、`Random.doubles()`或`Random.longs()`: 分别返回`IntStream`、`DoubleStream`和`LongStream`，具有伪随机值。您可以指定随机数之间的范围，或者您想要获取的随机值的数量。例如，您可以使用`new Random.ints(10,20)`生成 10 到 20 之间的伪随机数。

+   `SplittableRandom`类：这个类提供了与`Random`类相同的方法，用于生成伪随机的`int`、`double`和`long`值，但更适合并行处理。您可以查看 Java API 文档以获取该类的详细信息。

+   `Stream.concat()`方法：这个方法接收两个流作为参数，并创建一个新的流，其中包含第一个流的元素，后跟第二个流的元素。

您可以从其他来源生成流，但我们认为它们不重要。

### 中间操作

中间操作的最重要特征是它们将另一个流作为它们的结果返回。输入流和输出流的对象可以是不同类型的，但中间操作总是会生成一个新的流。在流中可以有零个或多个中间操作。`Stream`接口提供的最重要的中间操作是：

+   `distinct()`: 这个方法返回一个具有唯一值的流。所有重复的元素将被消除

+   `filter()`: 这个方法返回一个满足特定条件的元素的流

+   `flatMap()`: 这个方法用于将流的流（例如，列表流，集合流等）转换为单个流

+   `limit()`: 这个方法返回一个包含最多指定数量的原始元素的流，按照首个元素的顺序开始

+   `map()`: 这个方法用于将流的元素从一种类型转换为另一种类型

+   `peek()`: 这个方法返回相同的流，但它执行一些代码；通常用于编写日志消息

+   `skip()`: 这个方法忽略流的前几个元素（具体数字作为参数传递）

+   `sorted()`: 这个方法对流的元素进行排序

### 终端操作

终端操作返回一个对象作为结果。它永远不会返回一个流。一般来说，所有流都将以一个终端操作结束，该操作返回所有操作序列的最终结果。最重要的终端操作是：

+   `collect()`: 这个方法提供了一种方法来减少源流的元素数量，将流的元素组织成数据结构。例如，您想按任何标准对流的元素进行分组。

+   `count()`: 返回流的元素数量。

+   `max()`: 返回流的最大元素。

+   `min()`: 这返回流的最小元素。

+   `reduce()`: 这种方法将流的元素转换为表示流的唯一对象。

+   `forEach()`/`forEachOrdered()`: 这些方法对流中的每个元素应用操作。如果流有定义的顺序，第二种方法使用流的元素顺序。

+   `findFirst()`/`findAny()`: 如果存在，分别返回`1`或流的第一个元素。

+   `anyMatch()`/`allMatch()`/`noneMatch()`: 它们接收一个谓词作为参数，并返回一个布尔值，指示流的任何、所有或没有元素是否与谓词匹配。

+   `toArray()`: 这种方法返回流的元素数组。

## MapReduce 与 MapCollect

MapReduce 是一种编程模型，用于在具有大量机器的集群中处理非常大的数据集。通常由两种方法实现两个步骤：

+   **Map**: 这过滤和转换数据。

+   **Reduce**: 这对数据应用汇总操作

要在分布式环境中执行此操作，我们必须拆分数据，然后分发到集群的机器上。这种编程模型在函数式编程世界中已经使用了很长时间。谷歌最近基于这一原则开发了一个框架，在**Apache 基金会**中，**Hadoop**项目作为这一模型的开源实现非常受欢迎。

Java 8 与流允许程序员实现与此非常相似的东西。`Stream`接口定义了中间操作(`map()`, `filter()`, `sorted()`, `skip()`等)，可以被视为映射函数，并且它提供了`reduce()`方法作为终端操作，其主要目的是对流的元素进行减少，就像 MapReduce 模型的减少一样。

`reduce`操作的主要思想是基于先前的中间结果和流元素创建新的中间结果。另一种减少的方式(也称为可变减少)是将新的结果项合并到可变容器中(例如，将其添加到`ArrayList`中)。这种减少是通过`collect()`操作执行的，我们将其称为**MapCollect**模型。

本章我们将看到如何使用 MapReduce 模型，以及如何在第八章中使用 MapCollect 模型。*使用并行流处理大规模数据集-Map 和 Collect 模型*。

# 第一个示例-数值汇总应用程序

当您拥有大量数据集时，最常见的需求之一是处理其元素以测量某些特征。例如，如果您有一个商店中购买的产品集合，您可以计算您销售的产品数量，每种产品的销售单位数，或者每位客户在其上花费的平均金额。我们称这个过程为**数值汇总**。

在本章中，我们将使用流来获取**UCI 机器学习库**的**银行营销**数据集的一些度量，您可以从[`archive.ics.uci.edu/ml/datasets/Bank+Marketing`](http://archive.ics.uci.edu/ml/datasets/Bank+Marketing)下载。具体来说，我们使用了`bank-additional-full.csv`文件。该数据集存储了葡萄牙银行机构营销活动的信息。

与其他章节不同的是，在这种情况下，我们首先解释使用流的并发版本，然后说明如何实现串行等效版本，以验证并发对流的性能也有所改进。请注意，并发对程序员来说是透明的，正如我们在本章的介绍中提到的那样。

## 并发版本

我们的数值汇总应用程序非常简单。它具有以下组件：

+   `Record`：这个类定义了文件中每条记录的内部结构。它定义了每条记录的 21 个属性和相应的`get()`和`set()`方法来建立它们的值。它的代码非常简单，所以不会包含在书中。

+   `ConcurrentDataLoader`：这个类将加载`bank-additional-full.csv`文件中的数据，并将其转换为`Record`对象的列表。我们将使用流来加载数据并进行转换。

+   `ConcurrentStatistics`：这个类实现了我们将用来对数据进行计算的操作。

+   `ConcurrentMain`：这个类实现了`main()`方法，调用`ConcurrentStatistics`类的操作并测量其执行时间。

让我们详细描述最后三个类。

### `ConcurrentDataLoader`类

`ConcurrentDataLoader`类实现了`load()`方法，加载银行营销数据集的文件并将其转换为`Record`对象的列表。首先，我们使用`Files`方法的`readAllLines()`方法加载文件并将其内容转换为`String`对象的列表。文件的每一行将被转换为列表的一个元素：

```java
public class ConcurrentDataLoader {

    public static List<Record> load(Path path) throws IOException {
        System.out.println("Loading data");

        List<String> lines = Files.readAllLines(path);
```

然后，我们对流应用必要的操作来获取`Record`对象的列表：

```java
        List<Record> records = lines
                .parallelStream()
                .skip(1)
                .map(l -> l.split(";"))
                .map(t -> new Record(t))
                .collect(Collectors.toList());
```

我们使用的操作有：

+   `parallelStream()`：我们创建一个并行流来处理文件的所有行。

+   `skip(1)`：我们忽略流的第一个项目；在这种情况下，文件的第一行，其中包含文件的标题。

+   `map (l → l.split(";"))`：我们将每个字符串转换为`String[]`数组，通过`；`字符分割行。我们使用 lambda 表达式，其中`l`表示输入参数，`l.split()`将生成字符串数组。我们在字符串流中调用此方法，它将生成`String[]`流。

+   `map(t → new Record(t))`：我们使用`Record`类的构造函数将每个字符串数组转换为`Record`对象。我们使用 lambda 表达式，其中`t`表示字符串数组。我们在`String[]`流中调用此方法，并生成`Record`对象流。

+   `collect(Collectors.toList())`：这个方法将流转换为列表。我们将在第八章中更详细地讨论`collect`方法，*使用并行流处理大型数据集-映射和收集模型*。

正如你所看到的，我们以一种紧凑、优雅和并发的方式进行了转换，而没有使用任何线程、任务或框架。最后，我们返回`Record`对象的列表，如下所示：

```java
        return records;
    }
}
```

### `ConcurrentStatistics`类

`ConcurrentStatistics`类实现了对数据进行计算的方法。我们有七种不同的操作来获取关于数据集的信息。让我们描述每一个。

#### 订阅者的工作信息

这个方法的主要目标是获取订阅了银行存款（字段 subscribe 等于`yes`）的人员职业类型（字段 job）的人数。

这是这个方法的源代码：

```java
public class ConcurrentStatistics {

    public static void jobDataFromSubscribers(List<Record> records) {
        System.out.println ("****************************************");
        System.out.println("Job info for Deposit subscribers");

        ConcurrentMap<String, List<Record>> map = records.parallelStream()
                .filter(r -> r.getSubscribe().equals("yes"))
                .collect(Collectors.groupingByConcurrent (Record::getJob));

        map.forEach((k, l) -> System.out.println(k + ": " + l.size()));

        System.out.println ("****************************************");
    }
```

该方法接收`Record`对象的列表作为输入参数。首先，我们使用流来获取一个`ConcurrentMap<String, List<Record>>`对象，其中包含不同的工作类型和每种工作类型的记录列表。该流以`parallelStream()`方法开始，创建一个并行流。然后，我们使用`filter()`方法选择那些`subscribe`属性为`yes`的`Record`对象。最后，我们使用`collect()`方法传递`Collectors.groupingByConcurrent()`方法，将流的实际元素按照工作属性的值进行分组。请注意，`groupingByConcurrent()`方法是一个无序收集器。收集到列表中的记录可能是任意顺序的，而不是原始顺序（不像简单的`groupingBy()`收集器）。

一旦我们有了`ConcurrentMap`对象，我们使用`forEach()`方法将信息写入屏幕。

#### 订阅者的年龄数据

该方法的主要目标是从银行存款的订阅者的年龄（字段 subscribe 等于`yes`）中获取统计信息（最大值、最小值和平均值）。

这是该方法的源代码：

```java
    public static void ageDataFromSubscribers(List<Record> records) {

        System.out.println ("****************************************");
        System.out.println("Age info for Deposit subscribers");

        DoubleSummaryStatistics statistics = records.parallelStream()
                .filter(r -> r.getSubscribe().equals("yes"))
                .collect(Collectors.summarizingDouble (Record::getAge));

        System.out.println("Min: " + statistics.getMin());
        System.out.println("Max: " + statistics.getMax());
        System.out.println("Average: " + statistics.getAverage());
        System.out.println ("****************************************");
    }
```

该方法接收`Record`对象的列表作为输入参数，并使用流来获取带有统计信息的`DoubleSummaryStatistics`对象。首先，我们使用`parallelStream()`方法获取并行流。然后，我们使用`filter()`方法获取银行存款的订阅者。最后，我们使用带有`Collectors.summarizingDouble()`参数的`collect()`方法来获取`DoubleSummaryStatistics`对象。该类实现了`DoubleConsumer`接口，并在`accept()`方法中收集接收到的值的统计数据。`accept()`方法由流的`collect()`方法在内部调用。Java 还提供了`IntSummaryStatistics`和`LongSummaryStatistics`类，用于从`int`和`long`值获取统计数据。在这种情况下，我们使用`max()`、`min()`和`average()`方法分别获取最大值、最小值和平均值。

#### 订阅者的婚姻数据

该方法的主要目标是获取银行存款订阅者的不同婚姻状况（字段婚姻）。

这是该方法的源代码：

```java
    public static void maritalDataFromSubscribers(List<Record> records) {

        System.out.println ("****************************************");
        System.out.println("Marital info for Deposit subscribers");

        records.parallelStream()
                .filter(r -> r.getSubscribe().equals("yes"))
                .map(r -> r.getMarital())
                .distinct()
                .sorted()
                .forEachOrdered(System.out::println);
        System.out.println ("****************************************");
    }
```

该方法接收`Record`对象的列表作为输入参数，并使用`parallelStream()`方法获取并行流。然后，我们使用`filter()`方法仅获取银行存款的订阅者。接下来，我们使用`map()`方法获取所有订阅者的婚姻状况的`String`对象流。使用`distinct()`方法，我们只取唯一的值，并使用`sorted()`方法按字母顺序排序这些值。最后，我们使用`forEachOrdered()`打印结果。请注意，不要在这里使用`forEach()`，因为它会以无特定顺序打印结果，这将使`sorted()`步骤变得无用。当元素顺序不重要且可能比`forEachOrdered()`更快时，`forEach()`操作对于并行流非常有用。

#### 非订阅者的联系人数据

当我们使用流时，最常见的错误之一是尝试重用流。我们将通过这个方法展示这个错误的后果，该方法的主要目标是获取最大联系人数（属性 campaign）。

该方法的第一个版本是尝试重用流。以下是其源代码：

```java
    public static void campaignDataFromNonSubscribersBad (List<Record> records) {

        System.out.println ("****************************************");
        System.out.println("Number of contacts for Non Subscriber");

        IntStream stream = records.parallelStream()
                .filter(Record::isNotSubscriber)
                .mapToInt(r -> r.getCampaign());

        System.out
                .println("Max number of contacts: " + stream.max().getAsInt());
        System.out
                .println("Min number of contacts: " + stream.min().getAsInt());
        System.out.println ("****************************************");
    }
```

该方法接收`Record`对象的列表作为输入参数。首先，我们使用该列表创建一个`IntStream`对象。使用`parallelStream()`方法创建并行流。然后，我们使用`filter()`方法获取非订阅者，并使用`mapToInt()`方法将`Record`对象流转换为`IntStream`对象，将每个对象替换为`getCampaign()`方法的值。

我们尝试使用该流获取最大值（使用`max()`方法）和最小值（使用`min()`方法）。如果执行此方法，我们将在第二次调用中获得`IllegalStateException`，并显示消息**流已经被操作或关闭**。

我们可以通过创建两个不同的流来解决这个问题，一个用于获取最大值，另一个用于获取最小值。这是此选项的源代码：

```java
    public static void campaignDataFromNonSubscribersOk (List<Record> records) {

        System.out.println ("****************************************");
        System.out.println("Number of contacts for Non Subscriber");
        int value = records.parallelStream()
                .filter(Record::isNotSubscriber)
                .map(r -> r.getCampaign())
                .mapToInt(Integer::intValue)
                .max()
                .getAsInt();

        System.out.println("Max number of contacts: " + value);

        value = records.parallelStream()
                .filter(Record::isNotSubscriber)
                .map(r -> r.getCampaign())
                .mapToInt(Integer::intValue)
                .min()
                .getAsInt();

        System.out.println("Min number of contacts: " + value);
        System.out.println ("****************************************");
    }
```

另一个选项是使用`summaryStatistics()`方法获取一个`IntSummaryStatistics`对象，就像我们在之前的方法中展示的那样。

#### 多数据过滤

该方法的主要目标是获取满足以下条件之一的记录数量：

+   `defaultCredit`属性取值为`true`

+   `housing`属性取值为`false`

+   `loan`属性取值为`false`

实现此方法的一种解决方案是实现一个过滤器，检查元素是否满足这些条件之一。您还可以使用`Stream`接口提供的`concat()`方法实现其他解决方案。这是源代码：

```java
    public static void multipleFilterData(List<Record> records) {

        System.out.println ("****************************************");
        System.out.println("Multiple filter");

        Stream<Record> stream1 = records.parallelStream()
                .filter(Record::isDefaultCredit);
        Stream<Record> stream2 = records.parallelStream()
                .filter(r -> !(r.isHousing()));
        Stream<Record> stream3 = records.parallelStream()
                .filter(r -> !(r.isLoan()));

        Stream<Record> complete = Stream.concat(stream1, stream2);
        complete = Stream.concat(complete, stream3);

        long value = complete.parallel().unordered().distinct().count();

        System.out.println("Number of people: " + value);
        System.out.println ("****************************************");
    }
```

该方法接收`Record`对象列表作为输入参数。首先，我们创建三个满足每个条件的元素流，然后使用`concat()`方法生成单个流。`concat()`方法只创建一个流，其中包含第一个流的元素，然后是第二个流的元素。因此，对于最终流，我们使用`parallel()`方法将最终流转换为并行流，`unordered()`方法获取无序流，这将在使用并行流的`distinct()`方法中提供更好的性能，`distinct()`方法获取唯一值，以及`count()`方法获取流中的元素数量。

这不是最优的解决方案。我们使用它来向您展示`concat()`和`distinct()`方法的工作原理。您可以使用以下代码以更优化的方式实现相同的功能

```java
    public static void multipleFilterDataPredicate (List<Record> records) {

        System.out.println ("****************************************");
        System.out.println("Multiple filter with Predicate");

        Predicate<Record> p1 = r -> r.isDefaultCredit();
        Predicate<Record> p2 = r -> !r.isHousing();
        Predicate<Record> p3 = r -> !r.isLoan();

        Predicate<Record> pred = Stream.of(p1, p2, p3)
                    .reduce(Predicate::or).get();

        long value = records.parallelStream().filter(pred).count();

        System.out.println("Number of people: " + value);
        System.out.println ("****************************************");
    }
```

我们创建了三个谓词的流，并通过`Predicate::or`操作将它们减少为一个复合谓词，当输入谓词之一为`true`时，该复合谓词为`true`。您还可以使用`Predicate::and`减少操作来创建一个谓词，当所有输入谓词都为`true`时，该谓词为`true`。

#### 非订阅者的持续时间数据

该方法的主要目标是获取最长的 10 次电话通话（持续时间属性），这些通话最终没有订阅银行存款（字段 subscribe 等于`no`）。

这是此方法的源代码：

```java
    public static void durationDataForNonSubscribers(List<Record> records) {

        System.out.println ("****************************************");
        System.out.println("Duration data for non subscribers");
        records.parallelStream().filter(r -> r.isNotSubscriber()) .sorted(Comparator.comparingInt (Record::getDuration) .reversed()).limit(10) .forEachOrdered(
            r -> System.out.println("Education: " + r.getEducation() + "; Duration: " + r.getDuration()));
        System.out.println ("****************************************");
    }
```

该方法接收`Record`对象列表作为输入参数，并使用`parallelStream()`方法获取并行流。我们使用`filter()`方法获取非订阅者。然后，我们使用`sorted()`方法并传递一个比较器。比较器是使用`Comparator.comparingInt()`静态方法创建的。由于我们需要按照相反的顺序排序（最长持续时间优先），我们只需将`reversed()`方法添加到创建的比较器中。`sorted()`方法使用该比较器来比较和排序流的元素，因此我们可以按照我们想要的方式获取排序后的元素。

元素排序后，我们使用`limit()`方法获取前 10 个结果，并使用`forEachOrdered()`方法打印结果。

#### 年龄在 25 到 50 岁之间的人

该方法的主要目标是获取文件中年龄在 25 到 50 岁之间的人数。

这是此方法的源代码：

```java
    public static void peopleBetween25and50(List<Record> records) {

        System.out.println ("****************************************");
        System.out.println("People between 25 and 50");
        int count=records.parallelStream() .map(r -> r.getAge()) .filter(a -> (a >=25 ) && (a <=50)) .mapToInt(a -> 1) .reduce(0, Integer::sum);
        System.out.println("People between 25 and 50: "+count);
        System.out.println ("****************************************");
    }
```

该方法接收`Record`对象的列表作为输入参数，并使用`parallelStream()`方法获取并行流。然后，我们使用`map()`方法将`Record`对象流转换为`int`值流，将每个对象替换为其年龄属性的值。然后，我们使用`filter()`方法仅选择年龄在 25 到 50 岁之间的人，并再次使用`map()`方法将每个值转换为`1`。最后，我们使用`reduce()`方法对所有这些`1`进行求和，得到 25 到 50 岁之间的人的总数。`reduce()`方法的第一个参数是身份值，第二个参数是用于从流的所有元素中获得单个值的操作。在这种情况下，我们使用`Integer::sum`操作。第一次求和是在流的初始值和第一个值之间进行的，第二次求和是在第一次求和的结果和流的第二个值之间进行的，依此类推。

### `ConcurrentMain`类

`ConcurrentMain`类实现了`main()`方法来测试`ConcurrentStatistic`类。首先，我们实现了`measure()`方法，用于测量任务的执行时间：

```java
public class ConcurrentMain {
    static Map<String, List<Double>> totalTimes = new LinkedHashMap<>();
    static List<Record> records;

    private static void measure(String name, Runnable r) {
        long start = System.nanoTime();
        r.run();
        long end = System.nanoTime();
        totalTimes.computeIfAbsent(name, k -> new ArrayList<>()).add((end - start) / 1_000_000.0);
    }
```

我们使用一个映射来存储每个方法的所有执行时间。我们将执行每个方法 10 次，以查看第一次执行后执行时间的减少。然后，我们包括`main()`方法的代码。它使用`measure()`方法来测量每个方法的执行时间，并重复这个过程 10 次：

```java
    public static void main(String[] args) throws IOException {
        Path path = Paths.get("data\\bank-additional-full.csv");

        for (int i = 0; i < 10; i++) {
            records = ConcurrentDataLoader.load(path);
            measure("Job Info", () -> ConcurrentStatistics.jobDataFromSubscribers (records));
            measure("Age Info", () -> ConcurrentStatistics.ageDataFromSubscribers (records));
            measure("Marital Info", () -> ConcurrentStatistics.maritalDataFromSubscribers (records));
            measure("Multiple Filter", () -> ConcurrentStatistics.multipleFilterData(records));
            measure("Multiple Filter Predicate", () -> ConcurrentStatistics.multipleFilterDataPredicate (records));
            measure("Duration Data", () -> ConcurrentStatistics.durationDataForNonSubscribers (records));
            measure("Number of Contacts Bad: ", () -> ConcurrentStatistics .campaignDataFromNonSubscribersBad(records));
            measure("Number of Contacts", () -> ConcurrentStatistics .campaignDataFromNonSubscribersOk(records));
            measure("People Between 25 and 50", () -> ConcurrentStatistics.peopleBetween25and50(records));
        }
```

最后，我们在控制台中写入所有执行时间和平均执行时间，如下所示：

```java
                times.stream().map(t -> String.format("%6.2f", t)).collect(Collectors.joining(" ")), times .stream().mapToDouble (Double::doubleValue).average().getAsDouble()));
    }
}
```

## 串行版本

在这种情况下，串行版本几乎等于并行版本。我们只需将所有对`parallelStream()`方法的调用替换为对`stream()`方法的调用，以获得顺序流而不是并行流。我们还必须删除我们在其中一个示例中使用的`parallel()`方法的调用，并将对`groupingByConcurrent()`方法的调用更改为`groupingBy()`。

## 比较两个版本

我们已经执行了操作的两个版本，以测试并行流的使用是否提供更好的性能。我们使用了 JMH 框架（[`openjdk.java.net/projects/code-tools/jmh/`](http://openjdk.java.net/projects/code-tools/jmh/)）来执行它们，该框架允许您在 Java 中实现微基准测试。使用基准测试框架比简单地使用`currentTimeMillis()`或`nanoTime()`等方法来测量时间更好。我们在一个四核处理器的计算机上执行了它们 10 次，并计算了这 10 次的平均执行时间。请注意，我们已经实现了一个特殊的类来执行 JMH 测试。您可以在源代码的`com.javferna.packtpub.mastering.numericalSummarization.benchmark`包中找到这些类。以下是以毫秒为单位的结果：

| 操作 | 顺序流 | 并行流 |
| --- | --- | --- |
| 作业信息 | 13.704 | 9.550 |
| 年龄信息 | 7.218 | 5.512 |
| 婚姻信息 | 8.551 | 6.783 |
| 多重过滤 | 27.002 | 23.668 |
| 具有谓词的多重过滤 | 9.413 | 6.963 |
| 数据持续时间 | 41.762 | 23.641 |
| 联系人数 | 22.148 | 13.059 |
| 年龄在 25 到 50 岁之间的人 | 9.102 | 6.014 |

我们可以看到，并行流始终比串行流获得更好的性能。这是所有示例的加速比：

| 操作 | 加速比 |
| --- | --- |
| 作业信息 | 1.30 |
| 年龄信息 | 1.25 |
| 婚姻信息 | 1.16 |
| 多重过滤 | 1.08 |
| 数据持续时间 | 1.51 |
| 联系人数 | 1.64 |
| 年龄在 25 到 50 岁之间的人 | 1.37 |

# 第二个示例 - 信息检索搜索工具

根据维基百科（[`en.wikipedia.org/wiki/Information_retrieval`](https://en.wikipedia.org/wiki/Information_retrieval)），**信息检索**是：

> “从信息资源集合中获取与信息需求相关的信息资源。”

通常，信息资源是一组文档，信息需求是一组单词，这总结了我们的需求。为了在文档集合上进行快速搜索，我们使用了一种名为**倒排索引**的数据结构。它存储了文档集合中的所有单词，对于每个单词，都有一个包含该单词的文档列表。在第四章中，*从任务中获取数据 - Callable 和 Future 接口*，您构建了一个由维基百科页面构成的文档集合的倒排索引，其中包含有关电影的信息，构成了一组 100,673 个文档。我们已经将每个维基百科页面转换为一个文本文件。这个倒排索引存储在一个文本文件中，每一行包含单词、它的文档频率，以及单词在文档中出现的所有文档，以及单词在文档中的`tfxidf`属性的值。文档按照`tfxidf`属性的值进行排序。例如，文件的一行看起来像这样：

```java
velankanni:4,18005302.txt:10.13,20681361.txt:10.13,45672176.txt:10 .13,6592085.txt:10.13
```

这一行包含了`velankanni`一词，DF 为`4`。它出现在`18005302.txt`文档中，`tfxidf`值为`10.13`，在`20681361.txt`文档中，`tfxidf`值为`10.13`，在`45672176.txt`文档中，`tfxidf`值为`10.13`，在`6592085.txt`文档中，`tfxidf`值为`10.13`。

在本章中，我们将使用流 API 来实现我们的搜索工具的不同版本，并获取有关倒排索引的信息。

## 减少操作的介绍

正如我们在本章前面提到的，`reduce`操作将一个摘要操作应用于流的元素，生成一个单一的摘要结果。这个单一的结果可以与流的元素相同类型，也可以是其他类型。`reduce`操作的一个简单例子是计算一系列数字的总和。

流 API 提供了`reduce()`方法来实现减少操作。这个方法有以下三个不同的版本：

+   `reduce(accumulator)`: 此版本将`accumulator`函数应用于流的所有元素。在这种情况下没有初始值。它返回一个`Optional`对象，其中包含`accumulator`函数的最终结果，如果流为空，则返回一个空的`Optional`对象。这个`accumulator`函数必须是一个`associative`函数，它实现了`BinaryOperator`接口。两个参数可以是流元素，也可以是之前累加器调用返回的部分结果。

+   `reduce(identity, accumulator)`: 当最终结果和流的元素具有相同类型时，必须使用此版本。身份值必须是`accumulator`函数的身份值。也就是说，如果你将`accumulator`函数应用于身份值和任何值`V`，它必须返回相同的值`V: accumulator(identity,V)=V`。该身份值用作累加器函数的第一个结果，并且如果流没有元素，则作为返回值。与另一个版本一样，累加器必须是一个实现`BinaryOperator`接口的`associative`函数。

+   `reduce(identity, accumulator, combiner)`: 当最终结果的类型与流的元素不同时，必须使用此版本。identity 值必须是`combiner`函数的标识，也就是说，`combiner(identity,v)=v`。`combiner`函数必须与`accumulator`函数兼容，也就是说，`combiner(u,accumulator(identity,v))=accumulator(u,v)`。`accumulator`函数接受部分结果和流的下一个元素以生成部分结果，combiner 接受两个部分结果以生成另一个部分结果。这两个函数必须是可结合的，但在这种情况下，`accumulator`函数是`BiFunction`接口的实现，`combiner`函数是`BinaryOperator`接口的实现。

`reduce()`方法有一个限制。正如我们之前提到的，它必须返回一个单一的值。你不应该使用`reduce()`方法来生成一个集合或复杂对象。第一个问题是性能。正如流 API 的文档所指定的，`accumulator`函数在处理一个元素时每次都会返回一个新值。如果你的`accumulator`函数处理集合，每次处理一个元素时都会创建一个新的集合，这是非常低效的。另一个问题是，如果你使用并行流，所有线程将共享 identity 值。如果这个值是一个可变对象，例如一个集合，所有线程将在同一个集合上工作。这与`reduce()`操作的理念不符。此外，`combiner()`方法将始终接收两个相同的集合（所有线程都在同一个集合上工作），这也不符合`reduce()`操作的理念。

如果你想进行生成集合或复杂对象的减少，你有以下两个选项：

+   使用`collect()`方法进行可变减少。第八章，“使用并行流处理大型数据集 - 映射和收集模型”详细解释了如何在不同情况下使用这种方法。

+   创建集合并使用`forEach()`方法填充集合所需的值。

在这个例子中，我们将使用`reduce()`方法获取倒排索引的信息，并使用`forEach()`方法将索引减少到查询的相关文档列表。

## 第一种方法 - 完整文档查询

在我们的第一种方法中，我们将使用与一个单词相关联的所有文档。我们搜索过程的实现步骤如下：

1.  我们在倒排索引中选择与查询词对应的行。

1.  我们将所有文档列表分组成一个单一列表。如果一个文档与两个或更多不同的单词相关联，我们将这些单词在文档中的`tfxidf`值相加，以获得文档的最终`tfxidf`值。如果一个文档只与一个单词相关联，那么该单词的`tfxidf`值将成为该文档的最终`tfxidf`值。

1.  我们按照`tfxidf`值对文档进行排序，从高到低。

1.  我们向用户展示具有更高`tfxidf`值的 100 个文档。

我们在`ConcurrentSearch`类的`basicSearch()`方法中实现了这个版本。这是该方法的源代码：

```java
        public static void basicSearch(String query[]) throws IOException {

        Path path = Paths.get("index", "invertedIndex.txt");
        HashSet<String> set = new HashSet<>(Arrays.asList(query));
        QueryResult results = new QueryResult(new ConcurrentHashMap<>());

        try (Stream<String> invertedIndex = Files.lines(path)) {

            invertedIndex.parallel() .filter(line -> set.contains(Utils.getWord(line))) .flatMap(ConcurrentSearch::basicMapper) .forEach(results::append);

            results .getAsList() .stream() .sorted() .limit(100) .forEach(System.out::println);

            System.out.println("Basic Search Ok");
        }

    }
```

我们接收一个包含查询词的字符串对象数组。首先，我们将该数组转换为一个集合。然后，我们使用`invertedIndex.txt`文件的行进行*try-with-resources*流处理，该文件包含倒排索引。我们使用*try-with-resources*，这样我们就不必担心打开或关闭文件。流的聚合操作将生成一个具有相关文档的`QueryResult`对象。我们使用以下方法来获取该列表：

+   `parallel()`: 首先，我们获取并行流以提高搜索过程的性能。

+   `filter()`: 我们选择将单词与查询中的单词相关联的行。`Utils.getWord()`方法获取行的单词。

+   `flatMap()`: 我们将包含倒排索引每一行的字符串流转换为`Token`对象流。每个标记包含文件中单词的`tfxidf`值。对于每一行，我们将生成与包含该单词的文件数量相同的标记。

+   `forEach()`: 我们使用该类的`add()`方法生成`QueryResult`对象。

一旦我们创建了`QueryResult`对象，我们使用以下方法创建其他流来获取最终结果列表：

+   `getAsList()`: `QueryResult`对象返回一个包含相关文档的列表

+   `stream()`: 创建一个流来处理列表

+   `sorted()`: 按其`tfxidf`值对文档列表进行排序

+   `limit()`: 获取前 100 个结果

+   `forEach()`: 处理 100 个结果并将信息写入屏幕

让我们描述一下示例中使用的辅助类和方法。

### basicMapper()方法

该方法将字符串流转换为`Token`对象流。正如我们将在后面详细描述的那样，标记存储文档中单词的`tfxidf`值。该方法接收一个包含倒排索引行的字符串。它将行拆分为标记，并生成包含包含该单词的文档数量的`Token`对象。该方法在`ConcurrentSearch`类中实现。以下是源代码：

```java
    public static Stream<Token> basicMapper(String input) {
        ConcurrentLinkedDeque<Token> list = new ConcurrentLinkedDeque();
        String word = Utils.getWord(input);
        Arrays .stream(input.split(","))
          .skip(1) .parallel() .forEach(token -> list.add(new Token(word, token)));

        return list.stream();
    }
```

首先，我们创建一个`ConcurrentLinkedDeque`对象来存储`Token`对象。然后，我们使用`split()`方法拆分字符串，并使用`Arrays`类的`stream()`方法生成一个流。跳过第一个元素（包含单词的信息），并并行处理其余的标记。对于每个元素，我们创建一个新的`Token`对象（将单词和具有`file:tfxidf`格式的标记传递给构造函数），并将其添加到流中。最后，我们使用`ConcurrenLinkedDeque`对象的`stream()`方法返回一个流。

### Token 类

正如我们之前提到的，这个类存储文档中单词的`tfxidf`值。因此，它有三个属性来存储这些信息，如下所示：

```java
public class Token {

    private final String word;
    private final double tfxidf;
    private final String file;
```

构造函数接收两个字符串。第一个包含单词，第二个包含文件和`file:tfxidf`格式中的`tfxidf`属性，因此我们必须按以下方式处理它：

```java
    public Token(String word, String token) {
        this.word=word;
        String[] parts=token.split(":");
        this.file=parts[0];
        this.tfxidf=Double.parseDouble(parts[1]);
    }
```

最后，我们添加了一些方法来获取（而不是设置）三个属性的值，并将对象转换为字符串，如下所示：

```java
    @Override
    public String toString() {
        return word+":"+file+":"+tfxidf;
    }
```

### QueryResult 类

这个类存储与查询相关的文档列表。在内部，它使用一个映射来存储相关文档的信息。键是存储文档的文件的名称，值是一个`Document`对象，它还包含文件的名称和该文档对查询的总`tfxidf`值，如下所示：

```java
public class QueryResult {

    private Map<String, Document> results;
```

我们使用类的构造函数来指示我们将使用的`Map`接口的具体实现。我们在并发版本中使用`ConcurrentHashMap`，在串行版本中使用`HashMap`：

```java
    public QueryResult(Map<String, Document> results) {
        this.results=results;
    }
```

该类包括`append`方法，用于将标记插入映射，如下所示：

```java
    public void append(Token token) {
        results.computeIfAbsent(token.getFile(), s -> new Document(s)).addTfxidf(token.getTfxidf());
    }
```

我们使用`computeIfAbsent()`方法来创建一个新的`Document`对象，如果没有与文件关联的`Document`对象，或者如果已经存在，则获取相应的对象，并使用`addTfxidf()`方法将标记的`tfxidf`值添加到文档的总`tfxidf`值中。

最后，我们包含了一个将映射作为列表获取的方法，如下所示：

```java
    public List<Document> getAsList() {
        return new ArrayList<>(results.values());
    }
```

`Document`类将文件名存储为字符串，并将总`tfxidf`值存储为`DoubleAdder`。这个类是 Java 8 的一个新特性，允许我们在不担心同步的情况下从不同的线程对变量进行求和。它实现了`Comparable`接口，以按其`tfxidf`值对文档进行排序，因此具有最大`tfxidf`值的文档将排在前面。它的源代码非常简单，所以没有包含在内。

## 第二种方法 - 减少文档查询

第一种方法为每个单词和文件创建一个新的`Token`对象。我们注意到常见单词，例如`the`，有很多相关联的文档，而且很多文档的`tfxidf`值很低。我们已经改变了我们的映射方法，只考虑每个单词的前 100 个文件，因此生成的`Token`对象数量将更少。

我们在`ConcurrentSearch`类的`reducedSearch()`方法中实现了这个版本。这个方法与`basicSearch()`方法非常相似。它只改变了生成`QueryResult`对象的流操作，如下所示：

```java
        invertedIndex.parallel() .filter(line -> set.contains(Utils.getWord(line))) .flatMap(ConcurrentSearch::limitedMapper) .forEach(results::append);
```

现在，我们将`limitedMapper()`方法作为`flatMap()`方法中的函数使用。

### `limitedMapper()`方法

这个方法类似于`basicMapper()`方法，但是，正如我们之前提到的，我们只考虑与每个单词相关联的前 100 个文档。由于文档按其`tfxidf`值排序，我们使用了单词更重要的 100 个文档，如下所示：

```java
    public static Stream<Token> limitedMapper(String input) {
        ConcurrentLinkedDeque<Token> list = new ConcurrentLinkedDeque();
        String word = Utils.getWord(input);

        Arrays.stream(input.split(",")) .skip(1) .limit(100) .parallel() .forEach(token -> {
            list.add(new Token(word, token));
          });

        return list.stream();
    }
```

与`basicMapper()`方法的唯一区别是`limit(100)`调用，它获取流的前 100 个元素。

## 第三种方法 - 生成包含结果的 HTML 文件

在使用网络搜索引擎（例如 Google）的搜索工具时，当您进行搜索时，它会返回您的搜索结果（最重要的 10 个），并且对于每个结果，它会显示文档的标题和包含您搜索的单词的片段。

我们对搜索工具的第三种方法是基于第二种方法，但是通过添加第三个流来生成包含搜索结果的 HTML 文件。对于每个结果，我们将显示文档的标题和其中出现查询词的三行。为了实现这一点，您需要访问倒排索引中出现的文件。我们已经将它们存储在一个名为`docs`的文件夹中。

这第三种方法是在`ConcurrentSearch`类的`htmlSearch()`方法中实现的。构造`QueryResult`对象的方法的第一部分与`reducedSearch()`方法相同，如下所示：

```java
    public static void htmlSearch(String query[], String fileName) throws IOException {
        Path path = Paths.get("index", "invertedIndex.txt");
        HashSet<String> set = new HashSet<>(Arrays.asList(query));
        QueryResult results = new QueryResult(new ConcurrentHashMap<>());

        try (Stream<String> invertedIndex = Files.lines(path)) {

            invertedIndex.parallel() .filter(line -> set.contains(Utils.getWord(line))) .flatMap(ConcurrentSearch::limitedMapper) .forEach(results::append);
```

然后，我们创建文件以写入输出和其中的 HTML 标头：

```java
                         path = Paths.get("output", fileName + "_results.html");
            try (BufferedWriter fileWriter = Files.newBufferedWriter(path, StandardOpenOption.CREATE)) {

                fileWriter.write("<HTML>");
                fileWriter.write("<HEAD>");
                fileWriter.write("<TITLE>");
                fileWriter.write("Search Results with Streams");
                fileWriter.write("</TITLE>");
                fileWriter.write("</HEAD>");
                fileWriter.write("<BODY>");
                fileWriter.newLine();
```

然后，我们包括生成 HTML 文件中结果的流：

```java
                            results.getAsList()
                    .stream()
                    .sorted()
                    .limit(100)
                    .map(new ContentMapper(query)).forEach(l -> {
                        try {
                            fileWriter.write(l);
                            fileWriter.newLine();
                        } catch (IOException e) {
                            e.printStackTrace();
                        }
                });

                fileWriter.write("</BODY>");
                fileWriter.write("</HTML>");

            }
```

我们使用了以下方法：

+   `getAsList()`获取与查询相关的文档列表。

+   `stream()`生成一个顺序流。我们不能并行化这个流。如果我们尝试这样做，最终文件中的结果将不会按文档的`tfxidf`值排序。

+   `sorted()`按其`tfxidf`属性对结果进行排序。

+   `map()`使用`ContentMapper`类将`Result`对象转换为每个结果的 HTML 代码字符串。我们稍后会解释这个类的细节。

+   `forEach()`将`map()`方法返回的`String`对象写入文件。`Stream`对象的方法不能抛出已检查的异常，所以我们必须包含将抛出异常的 try-catch 块。

让我们看看`ContentMapper`类的细节。

### `ContentMapper`类

`ContentMapper`类是`Function`接口的实现，它将`Result`对象转换为包含文档标题和三行文本的 HTML 块，其中包括一个或多个查询词。

该类使用内部属性存储查询，并实现构造函数来初始化该属性，如下所示：

```java
public class ContentMapper implements Function<Document, String> {
    private String query[];

    public ContentMapper(String query[]) {
        this.query = query;
    }
```

文档的标题存储在文件的第一行。我们使用 try-with-resources 指令和 Files 类的 lines()方法来创建和流式传输文件行的 String 对象，并使用 findFirst()获取第一行作为字符串：

```java
    public String apply(Document d) {
        String result = "";

        try (Stream<String> content = Files.lines(Paths.get("docs",d.getDocumentName()))) {
            result = "<h2>" + d.getDocumentName() + ": "
                    + content.findFirst().get()
                    + ": " + d.getTfxidf() + "</h2>";
        } catch (IOException e) {
            e.printStackTrace();
            throw new UncheckedIOException(e);
        }
```

然后，我们使用类似的结构，但在这种情况下，我们使用 filter()方法仅获取包含一个或多个查询单词的行，使用 limit()方法获取其中三行。然后，我们使用 map()方法为段落添加 HTML 标签（<p>），并使用 reduce()方法完成所选行的 HTML 代码：

```java
                try (Stream<String> content = Files.lines(Paths.get ("docs",d.getDocumentName()))) {
            result += content
                    .filter(l -> Arrays.stream(query).anyMatch (l.toLowerCase()::contains))
                    .limit(3)
                    .map(l -> "<p>"+l+"</p>")
                    .reduce("",String::concat);
            return result;
        } catch (IOException e) {
            e.printStackTrace();
            throw new UncheckedIOException(e);
        }
    }
```

## 第四种方法-预加载倒排索引

前三种解决方案在并行执行时存在问题。正如我们之前提到的，使用常见的 Java 并发 API 提供的 Fork/Join 池执行并行流。在第六章中，*优化分治解决方案-分支/加入框架*，您学到了不应在任务内部使用 I/O 操作，如从文件中读取或写入数据。这是因为当线程阻塞读取或写入文件中的数据时，框架不使用工作窃取算法。由于我们使用文件作为流的源，因此我们正在惩罚我们的并发解决方案。

解决这个问题的一个方法是将数据读取到数据结构中，然后从该数据结构创建流。显然，与其他方法相比，这种方法的执行时间会更短，但我们希望比较串行和并行版本，以查看（正如我们所期望的那样）并行版本是否比串行版本具有更好的性能。这种方法的不好之处在于你需要将数据结构保存在内存中，因此你需要大量的内存。

这第四种方法是在 ConcurrentSearch 类的 preloadSearch()方法中实现的。该方法接收查询作为 String 的 Array 和 ConcurrentInvertedIndex 类的对象（稍后我们将看到该类的详细信息）作为参数。这是此版本的源代码：

```java
        public static void preloadSearch(String[] query, ConcurrentInvertedIndex invertedIndex) {

        HashSet<String> set = new HashSet<>(Arrays.asList(query));
        QueryResult results = new QueryResult(new ConcurrentHashMap<>());

        invertedIndex.getIndex()
            .parallelStream()
            .filter(token -> set.contains(token.getWord()))
            .forEach(results::append);

        results
            .getAsList()
            .stream()
            .sorted()
            .limit(100)
            .forEach(document -> System.out.println(document));

        System.out.println("Preload Search Ok.");
    }
```

ConcurrentInvertedIndex 类具有 List<Token>来存储从文件中读取的所有 Token 对象。它有两个方法，get()和 set()用于这个元素列表。

与其他方法一样，我们使用两个流：第一个流获取 Result 对象的 ConcurrentLinkedDeque，其中包含整个结果列表，第二个流将结果写入控制台。第二个流与其他版本相同，但第一个流不同。我们在这个流中使用以下方法：

+   `getIndex()`: 首先，我们获取 Token 对象的列表

+   `parallelStream()`: 然后，我们创建一个并行流来处理列表的所有元素

+   `filter()`: 我们选择与查询中的单词相关联的标记

+   `forEach()`: 我们处理标记列表，使用 append()方法将它们添加到 QueryResult 对象中

### ConcurrentFileLoader 类

ConcurrentFileLoader 类将 invertedIndex.txt 文件的内容加载到内存中，其中包含倒排索引的信息。它提供了一个名为 load()的静态方法，该方法接收存储倒排索引的文件路径，并返回一个 ConcurrentInvertedIndex 对象。我们有以下代码：

```java
public class ConcurrentFileLoader {

    public ConcurrentInvertedIndex load(Path path) throws IOException {
        ConcurrentInvertedIndex invertedIndex = new ConcurrentInvertedIndex();
        ConcurrentLinkedDeque<Token> results=new ConcurrentLinkedDeque<>();
```

我们使用 try-with-resources 结构打开文件并创建一个流来处理所有行：

```java
        try (Stream<String> fileStream = Files.lines(path)) {
            fileStream
            .parallel()
            .flatMap(ConcurrentSearch::limitedMapper)
            .forEach(results::add);
        }

        invertedIndex.setIndex(new ArrayList<>(results));
        return invertedIndex;
    }
}
```

我们在流中使用以下方法：

+   `parallel()`: 我们将流转换为并行流

+   `flatMap()`: 我们使用 ConcurrentSearch 类的 limitedMapper()方法将行转换为 Token 对象的流

+   `forEach()`: 我们处理 Token 对象的列表，使用 add()方法将它们添加到 ConcurrentLinkedDeque 对象中

最后，我们将`ConcurrentLinkedDeque`对象转换为`ArrayList`，并使用`setIndex()`方法将其设置在`InvertedIndex`对象中。

## 第五种方法-使用我们自己的执行器

为了进一步说明这个例子，我们将测试另一个并发版本。正如我们在本章的介绍中提到的，并行流使用了 Java 8 中引入的常见 Fork/Join 池。然而，我们可以使用一个技巧来使用我们自己的池。如果我们将我们的方法作为 Fork/Join 池的任务执行，流的所有操作将在同一个 Fork/Join 池中执行。为了测试这个功能，我们已经在`ConcurrentSearch`类中添加了`executorSearch()`方法。该方法接收查询作为`String`对象数组的参数，`InvertedIndex`对象和`ForkJoinPool`对象。这是该方法的源代码：

```java
    public static void executorSearch(String[] query, ConcurrentInvertedIndex invertedIndex, ForkJoinPool pool) {
        HashSet<String> set = new HashSet<>(Arrays.asList(query));
        QueryResult results = new QueryResult(new ConcurrentHashMap<>());

        pool.submit(() -> {
            invertedIndex.getIndex()
                .parallelStream()
                .filter(token -> set.contains(token.getWord()))
                .forEach(results::append);

            results
                .getAsList()
                .stream()
                .sorted()
                .limit(100)
                .forEach(document -> System.out.println(document));
        }).join();

        System.out.println("Executor Search Ok.");

    }
```

我们使用`submit()`方法将该方法的内容及其两个流作为 Fork/Join 池中的任务执行，并使用`join()`方法等待其完成。

## 从倒排索引获取数据-`ConcurrentData`类

我们已经实现了一些方法，使用`ConcurrentData`类中的`reduce()`方法获取有关倒排索引的信息。

## 获取文件中的单词数

第一个方法计算文件中的单词数。正如我们在本章前面提到的，倒排索引存储了单词出现的文件。如果我们想知道出现在文件中的单词，我们必须处理整个倒排索引。我们已经实现了这个方法的两个版本。第一个版本实现在`getWordsInFile1()`中。它接收文件的名称和`InvertedIndex`对象作为参数，如下所示：

```java
    public static void getWordsInFile1(String fileName, ConcurrentInvertedIndex index) {
        long value = index
                .getIndex()
                .parallelStream()
                .filter(token -> fileName.equals(token.getFile()))
                .count();
        System.out.println("Words in File "+fileName+": "+value);
    }
```

在这种情况下，我们使用`getIndex()`方法获取`Token`对象的列表，并使用`parallelStream()`方法创建并行流。然后，我们使用`filter()`方法过滤与文件相关的令牌，最后，我们使用`count()`方法计算与该文件相关的单词数。

我们已经实现了该方法的另一个版本，使用`reduce()`方法而不是`count()`方法。这是`getWordsInFile2()`方法：

```java
    public static void getWordsInFile2(String fileName, ConcurrentInvertedIndex index) {

        long value = index
                .getIndex()
                .parallelStream()
                .filter(token -> fileName.equals(token.getFile()))
                .mapToLong(token -> 1)
                .reduce(0, Long::sum);
        System.out.println("Words in File "+fileName+": "+value);
    }
```

操作序列的开始与前一个相同。当我们获得了文件中单词的`Token`对象流时，我们使用`mapToInt()`方法将该流转换为`1`的流，然后使用`reduce()`方法来求和所有`1`的数字。

## 获取文件中的平均 tfxidf 值

我们已经实现了`getAverageTfxidf()`方法，它计算集合中文件的单词的平均`tfxidf`值。我们在这里使用了`reduce()`方法来展示它的工作原理。您可以在这里使用其他方法来获得更好的性能：

```java
    public static void getAverageTfxidf(String fileName, ConcurrentInvertedIndex index) {

        long wordCounter = index
                .getIndex()
                .parallelStream()
                .filter(token -> fileName.equals(token.getFile()))
                .mapToLong(token -> 1)
                .reduce(0, Long::sum);

        double tfxidf = index
                .getIndex()
                .parallelStream()
                .filter(token -> fileName.equals(token.getFile()))
                .reduce(0d, (n,t) -> n+t.getTfxidf(), (n1,n2) -> n1+n2);

        System.out.println("Words in File "+fileName+": "+(tfxidf/wordCounter));
    }
```

我们使用了两个流。第一个计算文件中的单词数，其源代码与`getWordsInFile2()`方法相同。第二个计算文件中所有单词的总`tfxidf`值。我们使用相同的方法来获取文件中单词的`Token`对象流，然后我们使用`reduce`方法来计算所有单词的`tfxidf`值的总和。我们将以下三个参数传递给`reduce()`方法：

+   `O`: 这作为标识值传递。

+   `(n,t) -> n+t.getTfxidf()`: 这作为`accumulator`函数传递。它接收一个`double`数字和一个`Token`对象，并计算数字和令牌的`tfxidf`属性的总和。

+   `(n1,n2) -> n1+n2`: 这作为`combiner`函数传递。它接收两个数字并计算它们的总和。

## 获取索引中的最大和最小 tfxidf 值

我们还使用`reduce()`方法在`maxTfxidf()`和`minTfxidf()`方法中计算倒排索引的最大和最小`tfxidf`值：

```java
    public static void maxTfxidf(ConcurrentInvertedIndex index) {
        Token token = index
                .getIndex()
                .parallelStream()
                .reduce(new Token("", "xxx:0"), (t1, t2) -> {
                    if (t1.getTfxidf()>t2.getTfxidf()) {
                        return t1;
                    } else {
                        return t2;
                    }
                });
        System.out.println(token.toString());
    }
```

该方法接收`ConcurrentInvertedIndex`作为参数。我们使用`getIndex()`来获取`Token`对象的列表。然后，我们使用`parallelStream()`方法在列表上创建并行流，使用`reduce()`方法来获取具有最大`tfxidf`的`Token`。在这种情况下，我们使用两个参数的`reduce()`方法：一个身份值和一个`accumulator`函数。身份值是一个`Token`对象。我们不关心单词和文件名，但是我们将其`tfxidf`属性初始化为值`0`。然后，`accumulator`函数接收两个`Token`对象作为参数。我们比较两个对象的`tfxidf`属性，并返回具有更大值的对象。

`minTfxidf()`方法非常相似，如下所示：

```java
    public static void minTfxidf(ConcurrentInvertedIndex index) {
        Token token = index
                .getIndex()
                .parallelStream()
                .reduce(new Token("", "xxx:1000000"), (t1, t2) -> {
                    if (t1.getTfxidf()<t2.getTfxidf()) {
                        return t1;
                    } else {
                        return t2;
                    }
                });
        System.out.println(token.toString());
    }
```

主要区别在于，在这种情况下，身份值用非常高的值初始化了`tfxidf`属性。

## ConcurrentMain 类

为了测试前面部分中解释的所有方法，我们实现了`ConcurrentMain`类，该类实现了`main()`方法来启动我们的测试。在这些测试中，我们使用了以下三个查询：

+   `query1`，使用单词`james`和`bond`

+   `query2`，使用单词`gone`，`with`，`the`和`wind`

+   `query3`，使用单词`rocky`

我们已经使用三个版本的搜索过程测试了三个查询，测量了每个测试的执行时间。所有测试都类似于这样的代码：

```java
public class ConcurrentMain {

    public static void main(String[] args) {

        String query1[]={"james","bond"};
        String query2[]={"gone","with","the","wind"};
        String query3[]={"rocky"};

            Date start, end;

        bufferResults.append("Version 1, query 1, concurrent\n");
        start = new Date();
        ConcurrentSearch.basicSearch(query1);
        end = new Date();
        bufferResults.append("Execution Time: "
                + (end.getTime() - start.getTime()) + "\n");
```

要将倒排索引从文件加载到`InvertedIndex`对象中，您可以使用以下代码：

```java
        ConcurrentInvertedIndex invertedIndex = new ConcurrentInvertedIndex();
        ConcurrentFileLoader loader = new ConcurrentFileLoader();
        invertedIndex = loader.load(Paths.get("index","invertedIndex.txt"));
```

要创建用于`executorSearch()`方法的`Executor`，您可以使用以下代码：

```java
        ForkJoinPool pool = new ForkJoinPool();
```

## 串行版本

我们已经实现了这个示例的串行版本，使用了`SerialSearch`，`SerialData`，`SerialInvertendIndex`，`SerialFileLoader`和`SerialMain`类。为了实现该版本，我们进行了以下更改：

+   使用顺序流而不是并行流。您必须删除使用`parallel()`方法将流转换为并行流的用法，或者将`parallelStream()`方法替换为`stream()`方法以创建顺序流。

+   在`SerialFileLoader`类中，使用`ArrayList`而不是`ConcurrentLinkedDeque`。

## 比较解决方案

让我们比较我们实现的所有方法的串行和并行版本的解决方案。我们使用 JMH 框架（[`openjdk.java.net/projects/code-tools/jmh/`](http://openjdk.java.net/projects/code-tools/jmh/)）执行它们，该框架允许您在 Java 中实现微基准测试。使用基准测试框架比仅使用`currentTimeMillis()`或`nanoTime()`等方法测量时间更好。我们在具有四核处理器的计算机上执行了 10 次，因此并行算法在理论上可以比串行算法快四倍。请注意，我们已经实现了一个特殊的类来执行 JMH 测试。您可以在源代码的`com.javferna.packtpub.mastering.irsystem.benchmark`包中找到这些类。

对于第一个查询，使用单词`james`和`bond`，这些是以毫秒为单位获得的执行时间：

|   | **串行** | **并行** |
| --- | --- | --- |
| 基本搜索 | 3516.674 | 3301.334 |
| 减少搜索 | 3458.351 | 3230.017 |
| HTML 搜索 | 3298.996 | 3298.632 |
| 预加载搜索 | 153.414 | 105.195 |
| 执行器搜索 | 154.679 | 102.135 |

对于第二个查询，使用单词`gone`，`with`，`the`和`wind`，这些是以毫秒为单位获得的执行时间：

|   | **串行** | **并行** |
| --- | --- | --- |
| 基本搜索 | 3446.022 | 3441.002 |
| 减少搜索 | 3249.930 | 3260.026 |
| HTML 搜索 | 3299.625 | 3379.277 |
| 预加载搜索 | 154.631 | 113.757 |
| 执行器搜索 | 156.091 | 106.418 |

对于第三个查询，使用单词`rocky`，这些是以毫秒为单位获得的执行时间：

|   | 串行 | 并行 |
| --- | --- | --- |
| 基本搜索 | 3271.308 | 3219.990 |
| 减少搜索 | 3318.343 | 3279.247 |
| HTML 搜索 | 3323.345 | 3333.624 |
| 预加载搜索 | 151.416 | 97.092 |
| 执行器搜索 | 155.033 | 103.907 |

最后，这是返回有关倒排索引信息的方法的平均执行时间（毫秒）：

|   | 串行 | 并发 |
| --- | --- | --- |
| `getWordsInFile1` | 131.066 | 81.357 |
| `getWordsInFile2` | 132.737 | 84.112 |
| `getAverageTfxidf` | 253.067 | 166.009 |
| `maxTfxidf` | 90.714 | 66.976 |
| `minTfxidf` | 84.652 | 68.158 |

我们可以得出以下结论：

+   当我们读取倒排索引以获取相关文档列表时，执行时间变得更糟。在这种情况下，并发和串行版本之间的执行时间非常相似。

+   当我们使用倒排索引的预加载版本时，算法的并发版本在所有情况下都给我们更好的性能。

+   对于给我们提供倒排索引信息的方法，并发版本的算法总是给我们更好的性能。

我们可以通过速度提升来比较并行和顺序流在这个结束的三个查询中的表现：

![比较解决方案](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-cncr-prog-java8/img/00019.jpeg)

最后，在我们的第三种方法中，我们生成了一个包含查询结果的 HTML 网页。这是查询`james bond`的第一个结果：

![比较解决方案](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-cncr-prog-java8/img/00020.jpeg)

对于查询`gone with the wind`，这是第一个结果：

![比较解决方案](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-cncr-prog-java8/img/00021.jpeg)

最后，这是查询`rocky`的第一个结果：

![比较解决方案](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-cncr-prog-java8/img/00022.jpeg)

# 摘要

在本章中，我们介绍了流，这是 Java 8 中引入的一个受函数式编程启发的新功能，并准备好使用新的 lambda 表达式。流是一系列数据（不是数据结构），允许您以顺序或并发的方式应用一系列操作来过滤、转换、排序、减少或组织这些元素以获得最终对象。

您还学习了流的主要特征，当我们在顺序或并发应用程序中使用流时，我们必须考虑这些特征。

最后，我们在两个示例中使用了流。在第一个示例中，我们使用了`Stream`接口提供的几乎所有方法来计算大型数据集的统计数据。我们使用了 UCI 机器学习库的银行营销数据集，其中包含 45211 条记录。在第二个示例中，我们实现了不同的方法来搜索倒排索引中与查询相关的最相关文档。这是信息检索领域中最常见的任务之一。为此，我们使用`reduce()`方法作为流的终端操作。

在下一章中，我们将继续使用流，但更专注于`collect()`终端操作。


# 第八章：使用并行流处理大型数据集-映射和收集模型

在第七章中，*使用并行流处理大型数据集-映射和减少模型*，我们介绍了流的概念，这是 Java 8 的新功能。流是可以以并行或顺序方式处理的元素序列。在本章中，您将学习如何处理流，内容包括以下主题：

+   collect()方法

+   第一个例子-没有索引的搜索数据

+   第二个例子-推荐系统

+   第三个例子-社交网络中的常见联系人

# 使用流来收集数据

在第七章中，*使用并行流处理大型数据集-映射和减少模型*，我们对流进行了介绍。让我们记住它们最重要的特点：

+   流的元素不存储在内存中

+   流不能重复使用

+   流对数据进行延迟处理

+   流操作不能修改流源

+   流允许您链接操作，因此一个操作的输出是下一个操作的输入

流由以下三个主要元素组成：

+   生成流元素的源

+   零个或多个生成另一个流作为输出的中间操作

+   生成结果的一个终端操作，可以是简单对象、数组、集合、映射或其他任何东西

Stream API 提供了不同的终端操作，但有两个更重要的操作，因为它们具有灵活性和强大性。在第七章中，*使用并行流处理大型数据集-映射和减少模型*，您学习了如何使用 reduce()方法，在本章中，您将学习如何使用 collect()方法。让我们介绍一下这个方法。

## collect()方法

collect()方法允许您转换和分组流的元素，生成一个新的数据结构，其中包含流的最终结果。您可以使用最多三种不同的数据类型：输入数据类型，来自流的输入元素的数据类型，用于在 collect()方法运行时存储元素的中间数据类型，以及 collect()方法返回的输出数据类型。

collect()方法有两个不同的版本。第一个版本接受以下三个函数参数：

+   供应商：这是一个创建中间数据类型对象的函数。如果您使用顺序流，此方法将被调用一次。如果您使用并行流，此方法可能会被多次调用，并且必须每次产生一个新的对象。

+   **累加器**：此函数用于处理输入元素并将其存储在中间数据结构中。

+   **组合器**：此函数用于将两个中间数据结构合并为一个。此函数仅在并行流中调用。

这个版本的 collect()方法使用两种不同的数据类型：来自流的元素的输入数据类型和将用于存储中间元素并返回最终结果的中间数据类型。

collect()方法的第二个版本接受实现 Collector 接口的对象。您可以自己实现这个接口，但使用 Collector.of()静态方法会更容易。此方法的参数如下：

+   **供应商**：此函数创建中间数据类型的对象，并且它的工作方式如前所述

+   **累加器**：调用此函数来处理输入元素，必要时对其进行转换，并将其存储在中间数据结构中

+   **组合器**：调用此函数将两个中间数据结构合并为一个，它的工作方式如前所述

+   **完成器**：如果需要进行最终转换或计算，则调用此函数将中间数据结构转换为最终数据结构

+   **特征**：您可以使用这个最终变量参数来指示您正在创建的收集器的一些特征

实际上，这两个版本之间有轻微的区别。三参数 collect 接受一个组合器，即`BiConsumer`，它必须将第二个中间结果合并到第一个中间结果中。与此不同的是，这个组合器是`BinaryOperator`，应该返回组合器。因此，它有自由地将第二个合并到第一个中间结果中，或者将第一个合并到第二个中间结果中，或者创建一个新的中间结果。`of()`方法还有另一个版本，它接受相同的参数，除了完成器；在这种情况下，不执行完成转换。

Java 为您提供了`Collectors`工厂类中的一些预定义收集器。您可以使用其中的一个静态方法获取这些收集器。其中一些方法是：

+   `averagingDouble()`，`averagingInt()`和`averagingLong()`：这将返回一个收集器，允许您计算`double`，`int`或`long`函数的算术平均值。

+   `groupingBy()`: 这将返回一个收集器，允许您根据对象的属性对流的元素进行分组，生成一个映射，其中键是所选属性的值，值是具有确定值的对象的列表。

+   `groupingByConcurrent()`: 这与前一个方法类似，除了两个重要的区别。第一个区别是它在并行模式下可能比`groupingBy()`方法更快，但在顺序模式下可能更慢。第二个最重要的区别是`groupingByConcurrent()`函数是一个无序的收集器。列表中的项目不能保证与流中的顺序相同。另一方面，`groupingBy()`收集器保证了顺序。

+   `joining()`: 这将返回一个`Collector`工厂类，将输入元素连接成一个字符串。

+   `partitioningBy()`: 这将返回一个`Collector`工厂类，根据谓词的结果对输入元素进行分区。

+   `summarizingDouble()`，`summarizingInt()`和`summarizingLong()`：这些返回一个`Collector`工厂类，用于计算输入元素的摘要统计信息。

+   `toMap()`: 这将返回一个`Collector`工厂类，允许您根据两个映射函数将输入元素转换为一个映射。

+   `toConcurrentMap()`: 这与前一个方法类似，但是以并发方式进行。没有自定义合并器，`toConcurrentMap()`对于并行流只是更快。与`groupingByConcurrent()`一样，这也是一个无序的收集器，而`toMap()`使用遇到的顺序进行转换。

+   `toList()`: 这将返回一个`Collector`工厂类，将输入元素存储到一个列表中。

+   `toCollection()`: 这个方法允许你将输入元素累积到一个新的`Collection`工厂类（`TreeSet`，`LinkedHashSet`等）中，按照遇到的顺序。该方法接收一个`Supplier`接口的实现作为参数，用于创建集合。

+   `maxBy()`和`minBy()`：这将返回一个`Collector`工厂类，根据传递的比较器产生最大和最小的元素。

+   `toSet()`: 这将返回一个`Collector`，将输入元素存储到一个集合中。

# 第一个例子 - 在没有索引的情况下搜索数据

在第七章中，*使用并行流处理大规模数据集 - 映射和归约模型*，您学习了如何实现搜索工具，以查找与输入查询类似的文档，使用倒排索引。这种数据结构使搜索操作更容易和更快，但会有情况，您将不得不对大量数据进行搜索操作，并且没有倒排索引来帮助您。在这些情况下，您必须处理数据集的所有元素才能获得正确的结果。在本例中，您将看到其中一种情况以及`Stream` API 的`reduce()`方法如何帮助您。

为了实现这个例子，您将使用**亚马逊产品共购买网络元数据**的子集，其中包括亚马逊销售的 548,552 个产品的信息，包括标题、销售排名以及相似产品、分类和评论列表。您可以从[`snap.stanford.edu/data/amazon-meta.html`](https://snap.stanford.edu/data/amazon-meta.html)下载这个数据集。我们已经取出了前 20,000 个产品，并将每个产品记录存储在单独的文件中。我们已更改了一些字段的格式，以便简化数据处理。所有字段都具有`property:value`格式。

## 基本类

我们有一些在并发和串行版本之间共享的类。让我们看看每个类的细节。

### Product 类

`Product`类存储有关产品的信息。以下是`Product`类：

+   `id`：这是产品的唯一标识符。

+   `asin`：这是亚马逊的标准识别号。

+   `title`：这是产品的标题。

+   `group`：这是产品的组。该属性可以取值`Baby Product`、`Book`、`CD`、`DVD`、`Music`、`Software`、`Sports`、`Toy`、`Video`或`Video Games`。

+   `salesrank`：这表示亚马逊的销售排名。

+   `similar`：这是文件中包含的相似商品的数量。

+   `categories`：这是一个包含产品分类的`String`对象列表。

+   `reviews`：这是一个包含产品评论（用户和值）的`Review`对象列表。

该类仅包括属性的定义和相应的`getXXX()`和`setXXX()`方法，因此其源代码未包含在内。

### 评论类

正如我们之前提到的，`Product`类包括一个`Review`对象列表，其中包含用户对产品的评论信息。该类将每个评论的信息存储在以下两个属性中：

+   `user`：进行评论的用户的内部代码

+   `value`：用户对产品给出的评分

该类仅包括属性的定义和相应的`getXXX()`和`setXXX()`方法，因此其源代码未包含在内。

### ProductLoader 类

`ProductLoader`类允许您从文件加载产品的信息到`Product`对象中。它实现了`load()`方法，该方法接收一个包含产品信息文件路径的`Path`对象，并返回一个`Product`对象。以下是其源代码：

```java
public class ProductLoader {
    public static Product load(Path path) {
        try (BufferedReader reader = Files.newBufferedReader(path)) {
            Product product=new Product();
            String line=reader.readLine();
            product.setId(line.split(":")[1]);
            line=reader.readLine();
            product.setAsin(line.split(":")[1]);
            line=reader.readLine();
            product.setTitle(line.substring (line.indexOf(':')+1));
            line=reader.readLine();
            product.setGroup(line.split(":")[1]);
            line=reader.readLine();
            product.setSalesrank(Long.parseLong (line.split(":")[1]));
            line=reader.readLine();
            product.setSimilar(line.split(":")[1]);
            line=reader.readLine();

            int numItems=Integer.parseInt(line.split(":")[1]);

            for (int i=0; i<numItems; i++) {
                line=reader.readLine();
                product.addCategory(line.split(":")[1]);
            }

            line=reader.readLine();
            numItems=Integer.parseInt(line.split(":")[1]);
            for (int i=0; i<numItems; i++) {
                line=reader.readLine();
                String tokens[]=line.split(":");
                Review review=new Review();
                review.setUser(tokens[1]);
                review.setValue(Short.parseShort(tokens[2]));
                product.addReview(review);
            }
            return product;
        } catch (IOException x) {
            throw newe UncheckedIOException(x);
        } 

    }
}
```

## 第一种方法 - 基本搜索

第一种方法接收一个单词作为输入查询，并搜索存储产品信息的所有文件，无论该单词是否包含在定义产品的字段中的一个中。它只会显示包含该单词的文件的名称。

为了实现这种基本方法，我们实现了`ConcurrentMainBasicSearch`类，该类实现了`main()`方法。首先，我们初始化查询和存储所有文件的基本路径：

```java
public class ConcurrentMainBasicSearch {

    public static void main(String args[]) {
        String query = args[0];
        Path file = Paths.get("data");
```

我们只需要一个流来生成以下结果的字符串列表：

```java
        try {
            Date start, end;
            start = new Date();
            ConcurrentLinkedDeque<String> results = Files
                    .walk(file, FileVisitOption.FOLLOW_LINKS)
                    .parallel()
                    .filter(f -> f.toString().endsWith(".txt"))
                    .collect(ArrayList<String>::new,
                            new ConcurrentStringAccumulator (query),
                            List::addAll);
            end = new Date();
```

我们的流包含以下元素：

+   我们使用`Files`类的`walk()`方法启动流，将我们文件集合的基本`Path`对象作为参数传递。该方法将返回所有文件和存储在该路径下的目录作为流。

+   然后，我们使用`parallel()`方法将流转换为并发流。

+   我们只对以`.txt`扩展名结尾的文件感兴趣，因此我们使用`filter()`方法对它们进行过滤。

+   最后，我们使用`collect()`方法将`Path`对象的流转换为`ConcurrentLinkedDeque`对象，其中包含文件名的`String`对象。

我们使用`collect()`方法的三个参数版本，使用以下功能参数：

+   **供应商**：我们使用`ArrayList`类的`new`方法引用来为每个线程创建一个新的数据结构，以存储相应的结果。

+   **累加器**：我们在`ConcurrentStringAccumulator`类中实现了自己的累加器。稍后我们将描述这个类的细节。

+   **组合器**：我们使用`ConcurrentLinkedDeque`类的`addAll()`方法来连接两个数据结构。在这种情况下，第二个集合中的所有元素将被添加到第一个集合中。第一个集合将用于进一步组合或作为最终结果。

最后，我们在控制台中写入流获得的结果：

```java
            System.out.println("Results for Query: "+query);
            System.out.println("*************");
            results.forEach(System.out::println);
            System.out.println("Execution Time: "+(end.getTime()- start.getTime()));
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
```

每当我们要处理流的路径以评估是否将其名称包含在结果列表中时，累加器功能参数将被执行。为了实现这个功能，我们实现了`ConcurrentStringAccumulator`类。让我们看看这个类的细节。

### ConcurrentStringAccumulator 类

`ConcurrentStringAccumulator`类加载包含产品信息的文件，以确定是否包含查询的术语。它实现了`BiConsumer`接口，因为我们希望将其用作`collect()`方法的参数。我们已经使用`List<String>`和`Path`类对该接口进行了参数化：

```java
public class ConcurrentStringAccumulator implements BiConsumer<List<String>, Path> {
```

它将查询定义为内部属性，在构造函数中初始化如下：

```java
    private String word;

    public ConcurrentStringAccumulator (String word) {
        this.word=word.toLowerCase();
    }
```

然后，我们实现了`BiConsumer`接口中定义的`accept()`方法。该方法接收两个参数：`ConcurrentLinkedDeque<String>`类和`Path`类中的一个。

为了加载文件并确定它是否包含查询，我们使用以下流：

```java
    @Override
    public void accept(List<String> list, Path path) {
        boolean result;

try (Stream<String> lines = Files.lines(path)) {
            result = lines
                    .parallel()
                    .map(l -> l.split(":")[1].toLowerCase())
                    .anyMatch(l -> l.contains(word))
```

我们的流包含以下元素：

+   我们使用`Files`类的`lines()`方法创建`String`对象的流，在 try-with-resources 语句中。该方法接收一个指向文件的`Path`对象作为参数，并返回文件的所有行的流。

+   然后，我们使用`parallel()`方法将流转换为并发流。

+   然后，我们使用`map()`方法获取每个属性的值。正如我们在本节的介绍中提到的，每行都具有`property:value`格式。

+   最后，我们使用`anyMatch()`方法来知道是否有任何属性的值包含查询词。

如果计数变量的值大于`0`，则文件包含查询词，我们将文件名包含在结果的`ConcurrentLinkedDeque`类中：

```java
            if (counter>0) {
                list.add(path.toString());
            }
        } catch (Exception e) {
            System.out.println(path);
            e.printStackTrace();
        }
    }

}
```

## 第二种方法-高级搜索

我们的基本搜索有一些缺点：

+   我们在所有属性中寻找查询词，但也许我们只想在其中一些属性中寻找，例如标题

+   我们只显示文件的名称，但如果我们显示额外信息，如产品的标题，将更具信息性

为了解决这些问题，我们将实现实现`main()`方法的`ConcurrentMainSearch`类。首先，我们初始化查询和存储所有文件的基本`Path`对象：

```java
public class ConcurrentMainSearch {
    public static void main(String args[]) {
        String query = args[0];
        Path file = Paths.get("data");
```

然后，我们使用以下流生成`Product`对象的`ConcurrentLinkedDeque`类：

```java
        try {
            Date start, end;
            start=new Date();
            ConcurrentLinkedDeque<Product> results = Files
                    .walk(file, FileVisitOption.FOLLOW_LINKS)
                    .parallel()
                    .filter(f -> f.toString().endsWith(".txt"))
                    .collect(ArrayList<Product>::new,
                            new ConcurrentObjectAccumulator (query),
                            List::addAll);
            end=new Date();
```

这个流与我们在基本方法中实现的流具有相同的元素，有以下两个变化：

+   在`collect()`方法中，我们在累加器参数中使用`ConcurrentObjectAccumulator`类

+   我们使用`Product`类参数化`ConcurrentLinkedDeque`类

最后，我们将结果写入控制台，但在这种情况下，我们写入每个产品的标题：

```java
            System.out.println("Results");
            System.out.println("*************");
            results.forEach(p -> System.out.println(p.getTitle()));
            System.out.println("Execution Time: "+(end.getTime()- start.getTime()));

        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
```

您可以更改此代码以写入有关产品的任何信息，如销售排名或类别。

这个实现与之前的实现之间最重要的变化是`ConcurrentObjectAccumulator`类。让我们看看这个类的细节。

### ConcurrentObjectAccumulator 类

`ConcurrentObjectAccumulator`类实现了参数化为`ConcurrentLinkedDeque<Product>`和`Path`类的`BiConsumer`接口，因为我们希望在`collect()`方法中使用它。它定义了一个名为`word`的内部属性来存储查询词。这个属性在类的构造函数中初始化：

```java
public class ConcurrentObjectAccumulator implements
        BiConsumer<List<Product>, Path> {

    private String word;

    public ConcurrentObjectAccumulator(String word) {
        this.word = word;
    }
```

`accept()`方法的实现（在`BiConsumer`接口中定义）非常简单：

```java
    @Override
    public void accept(List<Product> list, Path path) {

        Product product=ProductLoader.load(path);

        if (product.getTitle().toLowerCase().contains (word.toLowerCase())) {
            list.add(product);
        }

    }

}
```

该方法接收指向我们要处理的文件的`Path`对象作为参数，并使用`ConcurrentLinkedDeque`类来存储结果。我们使用`ProductLoader`类将文件加载到`Product`对象中，然后检查产品的标题是否包含查询词。如果包含查询词，我们将`Product`对象添加到`ConcurrentLinkedDeque`类中。

## 示例的串行实现

与本书中的其他示例一样，我们已经实现了搜索操作的两个版本的串行版本，以验证并行流是否能够提高性能。

您可以通过删除`Stream`对象中的`parallel()`调用来实现前面描述的四个类的串行等效版本，以使流并行化。

我们已经包含了书籍的源代码，其中包括`SerialMainBasicSearch`、`SerialMainSearch`、`SerialStringAccumulator`和`SerialObjectAccumulator`类，它们是串行版本的等效类，其中包括前面注释的更改。

## 比较实现

我们已经测试了我们的实现（两种方法：串行和并行版本）以比较它们的执行时间。为了测试它们，我们使用了三个不同的查询：

+   模式

+   Java

+   树

对于每个查询，我们已经执行了串行和并行流的两个搜索操作（基本和对象）。我们使用了 JMH 框架（[`openjdk.java.net/projects/code-tools/jmh/`](http://openjdk.java.net/projects/code-tools/jmh/)）来执行它们，该框架允许您在 Java 中实现微基准测试。使用基准测试框架比简单地使用`currentTimeMillis()`或`nanoTime()`等方法来测量时间更好。我们在一个四核处理器的计算机上执行了 10 次，并计算了这 10 次的平均执行时间。以下是以毫秒为单位的结果：

|   | 字符串搜索 | 对象搜索 |
| --- | --- | --- |
|   | **Java** | **模式** | **树** | **Java** | **模式** | **树** |
| **串行** | 4318.551 | 4372.565 | 4364.674 | 4573.985 | 4588.957 | 4591.100 |
| **并行** | 32402.969 | 2428.729 | 2412.747 | 2190.053 | 2173.511 | 2173.936 |

我们可以得出以下结论：

+   不同查询的结果非常相似

+   使用串行流，字符串搜索的执行时间比对象搜索的执行时间更好

+   使用并行流，对象搜索的执行时间比字符串搜索的执行时间更好

+   并行流在所有情况下都比串行流获得更好的性能

例如，如果我们比较并行和串行版本，对于使用速度提升的查询模式进行对象搜索，我们会得到以下结果：

![比较实现](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-cncr-prog-java8/img/00023.jpeg)

# 第二个示例 - 推荐系统

**推荐系统**根据客户购买/使用的产品/服务以及购买/使用与他相同服务的用户购买/使用的产品/服务向客户推荐产品或服务。

我们已经使用了前一节中解释的示例来实现推荐系统。每个产品的描述都包括一些客户对产品的评论。这个评论包括客户对产品的评分。

在这个例子中，您将使用这些评论来获取对客户可能感兴趣的产品的列表。我们将获取客户购买的产品列表。为了获取该列表，我们对购买这些产品的用户列表以及这些用户购买的产品列表进行排序，使用评论中给出的平均分数。这将是用户的建议产品。

## 通用类

我们已经添加了两个新的类到前一节中使用的类中。这些类是：

+   `ProductReview`：这个类通过添加两个新属性扩展了产品类

+   `ProductRecommendation`：这个类存储了对产品的推荐的信息

让我们看看这两个类的细节。

### ProductReview 类

`ProductReview`类通过添加两个新属性扩展了`Product`类：

+   `buyer`：这个属性存储产品的客户的姓名

+   `value`：这个属性存储客户在评论中给产品的评分

该类包括属性的定义：相应的`getXXX()`和`setXXX()`方法，一个从`Product`对象创建`ProductReview`对象的构造函数，以及新属性的值。它非常简单，所以它的源代码没有包含在内。

### ProductRecommendation 类

`ProductRecommendation`类存储了产品推荐所需的信息，包括以下内容：

+   `title`：我们正在推荐的产品的标题

+   `value`：该推荐的分数，计算为该产品所有评论的平均分数

这个类包括属性的定义，相应的`getXXX()`和`setXXX()`方法，以及`compareTo()`方法的实现（该类实现了`Comparable`接口），这将允许我们按照其值的降序对推荐进行排序。它非常简单，所以它的源代码没有包含在内。

## 推荐系统 - 主类

我们已经在`ConcurrentMainRecommendation`类中实现了我们的算法，以获取推荐给客户的产品列表。这个类实现了`main()`方法，该方法接收客户的 ID 作为参数，我们想要获取推荐的产品。我们有以下代码：

```java
    public static void main(String[] args) {
        String user = args[0];
        Path file = Paths.get("data");
        try {
            Date start, end;
            start=new Date();
```

我们已经使用不同的流来转换最终解决方案中的数据。第一个加载整个`Product`对象列表的流来自其文件：

```java
            List<Product> productList = Files
                .walk(file, FileVisitOption.FOLLOW_LINKS)
                .parallel()
                .filter(f -> f.toString().endsWith(".txt"))
                .collect(ConcurrentLinkedDeque<Product>::new
                 ,new ConcurrentLoaderAccumulator(), ConcurrentLinkedDeque::addAll);
```

这个流有以下元素：

+   我们使用`Files`类的`walk()`方法开始流。这个方法将创建一个流来处理数据目录下的所有文件和目录。

+   然后，我们使用`parallel()`方法将流转换为并发流。

+   然后，我们只获取扩展名为`.txt`的文件。

+   最后，我们使用`collect()`方法来获取`ConcurrentLinkedDeque`类的`Product`对象。它与前一节中使用的方法非常相似，不同之处在于我们使用了另一个累加器对象。在这种情况下，我们使用`ConcurrentLoaderAccumulator`类，稍后我们将对其进行描述。

一旦我们有了产品列表，我们将使用客户的标识符作为地图的键来组织这些产品。我们使用`ProductReview`类来存储产品的客户信息。我们将创建与`Product`有关的评论数量相同的`ProductReview`对象。我们使用以下流进行转换：

```java
        Map<String, List<ProductReview>> productsByBuyer=productList
                .parallelStream()
                .<ProductReview>flatMap(p -> p.getReviews().stream().map(r -> new ProductReview(p, r.getUser(), r.getValue())))
                .collect(Collectors.groupingByConcurrent( p -> p.getBuyer()));
```

这个流有以下元素：

+   我们使用`productList`对象的`parallelStream()`方法开始流，因此我们创建了一个并发流。

+   然后，我们使用`flatMap()`方法将我们拥有的`Product`对象流转换为唯一的`ProductReview`对象流。

+   最后，我们使用`collect()`方法生成最终的映射。在这种情况下，我们使用`Collectors`类的`groupingByConcurrent()`方法生成的预定义收集器。返回的收集器将生成一个映射，其中键将是买家属性的不同值，值将是购买该用户的产品信息的`ProductReview`对象列表。如方法名称所示，此转换将以并发方式完成。

下一个流是此示例中最重要的流。我们获取客户购买的产品，并为该客户生成推荐。这是一个由一个流完成的两阶段过程。在第一阶段，我们获取购买原始客户购买的产品的用户。在第二阶段，我们生成一个包含这些客户购买的产品以及这些客户所做的所有产品评论的映射。以下是该流的代码：

```java
            Map<String,List<ProductReview>> recommendedProducts=productsByBuyer.get(user)
                    .parallelStream()
                    .map(p -> p.getReviews())
                    .flatMap(Collection::stream)
                    .map(r -> r.getUser())
                    .distinct()
                    .map(productsByBuyer::get)
                    .flatMap(Collection::stream)
                    .collect(Collectors.groupingByConcurrent(p -> p.getTitle()));
```

在该流中，我们有以下元素：

+   首先，我们获取用户购买的产品列表，并使用`parallelStream()`方法生成并发流。

+   然后，我们使用`map()`方法获取该产品的所有评论。

+   此时，我们有一个`List<Review>`流。我们将该流转换为`Review`对象的流。现在我们有了一个包含用户购买产品的所有评论的流。

+   然后，我们将该流转换为包含进行评论的用户名称的`String`对象流。

+   然后，我们使用`distinct()`方法获取用户的唯一名称。现在我们有一个包含购买与原始用户相同产品的用户名称的`String`对象流。

+   然后，我们使用`map()`方法将每个客户转换为其购买产品的列表。

+   此时，我们有一个`List<ProductReview>`对象的流。我们使用`flatMap()`方法将该流转换为`ProductReview`对象的流。

+   最后，我们使用`collect()`方法和`groupingByConcurrent()`收集器生成产品的映射。映射的键将是产品的标题，值将是先前获得的客户所做的评论的`ProductReview`对象列表。

要完成我们的推荐算法，我们需要最后一步。对于每个产品，我们想计算其评论的平均分，并按降序对列表进行排序，以便将评分最高的产品显示在第一位。为了进行该转换，我们使用了额外的流：

```java
        List<ProductRecommendation> recommendations = recommendedProducts
                    .entrySet()
                    .parallelStream()
                    .map(entry -> new
                     ProductRecommendation(
                         entry.getKey(),
                         entry.getValue().stream().mapToInt(p -> p.getValue()).average().getAsDouble()))
                    .sorted()
                    .collect(Collectors.toList());
            end=new Date();
         recommendations. forEach(pr -> System.out.println (pr.getTitle()+": "+pr.getValue()));

            System.out.println("Execution Time: "+(end.getTime()- start.getTime()));

        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
```

我们处理前一步得到的映射。对于每个产品，我们处理其评论列表，生成一个`ProductRecommendation`对象。该对象的值是使用`mapToInt()`方法将`ProductReview`对象的流转换为整数流，并使用`average()`方法获取字符串中所有数字的平均值来计算每个评论的平均值。

最后，在推荐`ConcurrentLinkedDeque`类中，我们有一个`ProductRecommendation`对象列表。我们使用另一个带有`sorted()`方法的流对该列表进行排序。我们使用该流将最终列表写入控制台。

## ConcurrentLoaderAccumulator 类

为了实现此示例，我们使用了`ConcurrentLoaderAccumulator`类作为`collect()`方法中的累加器函数，将包含所有要处理文件路径的`Path`对象流转换为`Product`对象的`ConcurrentLinkedDeque`类。以下是该类的源代码：

```java
public class ConcurrentLoaderAccumulator implements
        BiConsumer<ConcurrentLinkedDeque<Product>, Path> {

    @Override
    public void accept(ConcurrentLinkedDeque<Product> list, Path path) {

        Product product=ProductLoader.load(path);
        list.add(product);

    }
}
```

它实现了`BiConsumer`接口。`accept()`方法使用`ProducLoader`类（在本章前面已经解释过）从文件中加载产品信息，并将生成的`Product`对象添加到作为参数接收的`ConcurrentLinkedDeque`类中。

## 串行版本

与本书中的其他示例一样，我们实现了此示例的串行版本，以检查并行流是否提高了应用程序的性能。要实现此串行版本，我们必须按照以下步骤进行：

+   将`ConcurrentLinkedDeque`数据结构替换为`List`或`ArrayList`数据结构

+   将`parallelStrem()`方法替换为`stream()`方法

+   将`gropingByConcurrent()`方法替换为`groupingBy()`方法

您可以在本书的源代码中看到此示例的串行版本。

## 比较两个版本

为了比较我们的推荐系统的串行和并行版本，我们已经为三个用户获取了推荐的产品：

+   `A2JOYUS36FLG4Z`

+   `A2JW67OY8U6HHK`

+   `A2VE83MZF98ITY`

对于这三个用户，我们使用 JMH 框架（[`openjdk.java.net/projects/code-tools/jmh/`](http://openjdk.java.net/projects/code-tools/jmh/)）执行了两个版本，该框架允许您在 Java 中实现微基准测试。使用基准测试框架比简单地使用`currentTimeMillis()`或`nanoTime()`等方法来测量时间更好。我们在一个四核处理器的计算机上执行了 10 次，并计算了这 10 次的中位执行时间。以下是以毫秒为单位的结果：

|   | A2JOYUS36FLG4Z | A2JW67OY8U6HHK | A2VE83MZF98ITY |
| --- | --- | --- | --- |
| **串行** | 4848.672 | 4830.051 | 4817.216 |
| **并行** | 2454.003 | 2458.003 | 2527.194 |

我们可以得出以下结论：

+   所得结果对于这三个用户来说非常相似

+   并行流的执行时间始终优于顺序流的执行时间

如果我们比较并行和串行版本，例如使用加速比的第二个用户，我们得到以下结果：

![比较两个版本](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-cncr-prog-java8/img/00024.jpeg)

# 第三个例子 - 社交网络中的共同联系人

社交网络正在改变我们的社会以及人们之间的关系方式。Facebook、Linkedin、Twitter 或 Instagram 拥有数百万用户，他们使用这些网络与朋友分享生活时刻，建立新的职业联系，推广自己的专业品牌，结识新朋友，或者了解世界上的最新趋势。

我们可以将社交网络视为一个图，其中用户是图的节点，用户之间的关系是图的弧。与图一样，有些社交网络（如 Facebook）中用户之间的关系是无向的或双向的。如果用户*A*与用户*B*连接，用户*B*也与*A*连接。相反，有些社交网络（如 Twitter）中用户之间的关系是有向的。在这种情况下，我们说用户*A*关注用户*B*，但反之则不一定成立。

在这一部分，我们将实现一个算法来计算社交网络中每对用户的共同联系人，这些用户之间存在双向关系。我们将实现[`stevekrenzel.com/finding-friends-with-mapreduce`](http://stevekrenzel.com/finding-friends-with-mapreduce)中描述的算法。该算法的主要步骤如下。

我们的数据源将是一个文件，其中我们存储了每个用户及其联系人：

```java
A-B,C,D,
B-A,C,D,E,
C-A,B,D,E,
D-A,B,C,E,
E-B,C,D,
```

这意味着用户*A*的联系人是*B*、*C*和*D*。请注意，关系是双向的，因此如果*A*是*B*的联系人，*A*也将是*B*的联系人，并且这两种关系都必须在文件中表示。因此，我们有以下两个部分的元素：

+   用户标识符

+   该用户的联系人列表

接下来，我们为每个元素生成一个由三部分组成的元素集。这三部分是：

+   用户标识符

+   朋友的用户标识符

+   该用户的联系人列表

因此，对于用户*A*，我们将生成以下元素：

```java
A-B-B,C,D
A-C-B,C,D
A-D-B,C,D
```

我们对所有元素采取相同的处理过程。我们将按字母顺序存储两个用户标识符。因此，对于用户*B*，我们生成以下元素：

```java
A-B-A,C,D,E
B-C-A,C,D,E
B-D-A,C,D,E
B-E-A,C,D,E
```

一旦我们生成了所有新元素，我们就将它们分组为两个用户标识符。例如，对于元组*A*-*B*，我们将生成以下组：

```java
A-B-(B,C,D),(A,C,D,E)
```

最后，我们计算两个列表之间的交集。结果列表是两个用户之间的共同联系人。例如，用户*A*和*B*共同拥有联系人*C*和*D*。

为了测试我们的算法，我们使用了两个数据集：

+   之前呈现的测试样本。

+   社交圈：您可以从[`snap.stanford.edu/data/egonets-Facebook.html`](https://snap.stanford.edu/data/egonets-Facebook.html)下载的 Facebook 数据集包含来自 Facebook 的 4,039 个用户的联系信息。我们已将原始数据转换为我们示例使用的数据格式。

## 基类

与书中其他示例一样，我们实现了此示例的串行和并发版本，以验证并行流改进了我们应用程序的性能。两个版本共享一些类。

### 人员类

`Person`类存储了社交网络中每个人的信息，包括以下内容：

+   用户 ID，存储在 ID 属性中

+   该用户的联系人列表，存储为`String`对象列表，存储在 contacts 属性中

该类声明了属性和相应的`getXXX()`和`setXXX()`方法。我们还需要一个构造函数来创建列表，以及一个名为`addContact()`的方法，用于将单个联系人添加到联系人列表中。该类的源代码非常简单，因此不会在此处包含。

### PersonPair 类

`PersonPair`类扩展了`Person`类，添加了存储第二个用户标识符的属性。我们将此属性称为`otherId`。该类声明了属性并实现了相应的`getXXX()`和`setXXX()`方法。我们需要一个额外的方法，名为`getFullId()`，它返回一个由逗号分隔的两个用户标识符的字符串。该类的源代码非常简单，因此不会在此处包含。

### 数据加载器类

`DataLoader`类加载包含用户及其联系人信息的文件，并将其转换为`Person`对象列表。它只实现了一个名为`load()`的静态方法，该方法接收文件路径作为`String`对象参数，并返回`Person`对象列表。

如前所述，文件的格式如下：

```java
User-C1,C2,C3...CN
```

在这里，`User`是用户的标识符，`C1、C2、C3….CN`是该用户的联系人的标识符。

该类的源代码非常简单，因此不会在此处包含。

## 并发版本

首先，让我们分析此算法的并发版本。

### 通用人员映射器类

`CommonPersonMapper`类是一个辅助类，稍后将使用它。它将从`Person`对象生成所有可能的`PersonPair`对象。该类实现了使用`Person`和`List<PersonPair>`类参数化的`Function`接口。

它实现了`Function`接口中定义的`apply()`方法。首先，我们初始化要返回的`List<PersonPair>`对象，并获取并对该人的联系人列表进行排序：

```java
public class CommonPersonMapper implements Function<Person, List<PersonPair>> {

    @Override
    public List<PersonPair> apply(Person person) {

        List<PersonPair> ret=new ArrayList<>();

        List<String> contacts=person.getContacts();
        Collections.sort(contacts);
```

然后，我们处理整个联系人列表，为每个联系人创建一个`PersonPair`对象。如前所述，我们将两个联系人按字母顺序排序。较小的联系人存储在 ID 字段中，另一个存储在`otherId`字段中：

```java
        for (String contact : contacts) {
            PersonPair personExt=new PersonPair();
            if (person.getId().compareTo(contact) < 0) {
                personExt.setId(person.getId());
                personExt.setOtherId(contact);
            } else {
                personExt.setId(contact);
                personExt.setOtherId(person.getId());
            }
```

最后，我们将联系人列表添加到新对象中，然后将对象添加到结果列表中。处理完所有联系人后，我们返回结果列表：

```java
            personExt.setContacts(contacts);
            ret.add(personExt);
        }
        return ret;
    }
}
```

### ConcurrentSocialNetwork 类

`ConcurrentSocialNetwork`是这个示例的主要类。它只实现了一个名为`bidirectionalCommonContacts()`的静态方法。该方法接收社交网络中的人员列表及其联系人，并返回一个`PersonPair`对象列表，其中包含每对联系人之间的共同联系人。

在内部，我们使用两个不同的流来实现我们的算法。我们使用第一个流将`Person`对象的输入列表转换为映射。该映射的键将是每对用户的两个标识符，值将是包含两个用户联系人的`PersonPair`对象列表。因此，这些列表始终有两个元素。我们有以下代码：

```java
public class ConcurrentSocialNetwork {

    public static List<PersonPair> bidirectionalCommonContacts(
            List<Person> people) {

        Map<String, List<PersonPair>> group = people.parallelStream()
                .map(new CommonPersonMapper())
                .flatMap(Collection::stream)
                .collect(Collectors.groupingByConcurrent (PersonPair::getFullId));
```

该流具有以下组件：

+   我们使用输入列表的`parallelStream()`方法创建流。

+   然后，我们使用`map()`方法和前面解释的`CommonPersonMapper`类来将每个`Person`对象转换为包含该对象所有可能性的`PersonPair`对象列表。

+   此时，我们有一个`List<PersonPair>`对象的流。我们使用`flatMap()`方法将该流转换为`PersonPair`对象的流。

+   最后，我们使用`collect()`方法使用`groupingByConcurrent()`方法返回的收集器生成映射，使用`getFullId()`方法返回的值作为映射的键。

然后，我们使用`Collectors`类的`of()`方法创建一个新的收集器。该收集器将接收一个字符串集合作为输入，使用`AtomicReference<Collection<String>>`作为中间数据结构，并返回一个字符串集合作为返回类型。

```java
        Collector<Collection<String>, AtomicReference<Collection<String>>, Collection<String>> intersecting = Collector.of(
                () -> new AtomicReference<>(null), (acc, list) -> {
                  acc.updateAndGet(set -> set == null ? new ConcurrentLinkedQueue<>(list) : set).retainAll(list);
                }, (acc1, acc2) -> {
                  if (acc1.get() == null)
                    return acc2;
                  if (acc2.get() == null)
                    return acc1;
                  acc1.get().retainAll(acc2.get());
                  return acc1;
                }, (acc) -> acc.get() == null ? Collections.emptySet() : acc.get(), Collector.Characteristics.CONCURRENT, Collector.Characteristics.UNORDERED);
```

`of()`方法的第一个参数是 supplier 函数。当我们需要创建数据的中间结构时，总是调用此 supplier。在串行流中，此方法只调用一次，但在并发流中，此方法将根据线程数调用一次。

```java
() -> new AtomicReference<>(null),
```

在我们的例子中，我们只需创建一个新的`AtomicReference`来存储`Collection<String>`对象。

`of()`方法的第二个参数是累加器函数。此函数接收中间数据结构和输入值作为参数：

```java
(acc, list) -> {
      acc.updateAndGet(set -> set == null ? new ConcurrentLinkedQueue<>(list) : set).retainAll(list);
                },
```

在我们的例子中，`acc`参数是`AtomicReference`，`list`参数是`ConcurrentLinkedDeque`。我们使用`AtomicReference`的`updateAndGet()`方法。此方法更新当前值并返回新值。如果`AtomicReference`为 null，则使用列表的元素创建一个新的`ConcurrentLinkedDeque`。如果`AtomicReference`不为 null，则它将存储一个`ConcurrentLinkedDeque`。我们使用`retainAll()`方法添加列表的所有元素。

`of()`方法的第三个参数是 combiner 函数。此函数仅在并行流中调用，并接收两个中间数据结构作为参数，以生成一个中间数据结构。

```java
   (acc1, acc2) -> {
      if (acc1.get() == null)
        return acc2;
       if (acc2.get() == null)
        return acc1;
      acc1.get().retainAll(acc2.get());
      return acc1;
    },
```

在我们的例子中，如果其中一个参数为 null，则返回另一个。否则，我们使用`acc1`参数中的`retainAll()`方法并返回结果。

`of()`方法的第四个参数是 finisher 函数。该函数将最终的中间数据结构转换为我们想要返回的数据结构。在我们的例子中，中间和最终的数据结构是相同的，因此不需要转换。

```java
(acc) -> acc.get() == null ? Collections.emptySet() : acc.get(),
```

最后，我们使用最后一个参数来指示收集器是并发的，也就是说，累加器函数可以从多个线程同时调用相同的结果容器，并且是无序的，也就是说，此操作不会保留元素的原始顺序。

现在我们已经定义了收集器，我们必须将第一个流生成的映射转换为具有每对用户的共同联系人的`PersonPair`对象列表。我们使用以下代码：

```java
        List<PersonPair> peopleCommonContacts = group.entrySet()
                  .parallelStream()
                  .map((entry) -> {
                    Collection<String> commonContacts =  
                      entry.getValue()
                        .parallelStream()
                        .map(p -> p.getContacts())
                        .collect(intersecting);
                    PersonPair person = new PersonPair();
                    person.setId(entry.getKey().split(",")[0]);
                    person.setOtherId(entry.getKey().split (",")[1]);
                    person.setContacts(new ArrayList<String> (commonContacts));
                    return person;
                  }).collect(Collectors.toList());

        return peopleCommonContacts;
    }
}
```

我们使用`entySet()`方法处理映射的所有元素。我们创建一个`parallelStream()`方法来处理所有`Entry`对象，然后使用`map()`方法将每个`PersonPair`对象列表转换为具有共同联系人的唯一`PersonPair`对象。

对于每个条目，键是由用户对的标识符连接而成的，作为分隔符，值是两个`PersonPair`对象的列表。第一个包含一个用户的联系人，另一个包含另一个用户的联系人。

我们为该列表创建一个流，以生成具有以下元素的两个用户的共同联系人：

+   我们使用列表的`parallelStream()`方法创建流

+   我们使用`map()`方法来替换其中存储的联系人列表的每个`PersonPair()`对象

+   最后，我们使用我们的收集器生成带有共同联系人的`ConcurrentLinkedDeque`

最后，我们创建一个新的`PersonPair`对象，其中包含两个用户的标识符和共同联系人列表。我们将该对象添加到结果列表中。当映射的所有元素都被处理时，我们可以返回结果列表。

### ConcurrentMain 类

`ConcurrentMain`类实现了`main()`方法来测试我们的算法。正如我们之前提到的，我们已经使用以下两个数据集进行了测试：

+   一个非常简单的数据集，用于测试算法的正确性

+   基于 Facebook 真实数据的数据集

这是这个类的源代码：

```java
public class ConcurrentMain {

    public static void main(String[] args) {

        Date start, end;
        System.out.println("Concurrent Main Bidirectional - Test");
        List<Person> people=DataLoader.load("data","test.txt");
        start=new Date();
        List<PersonPair> peopleCommonContacts= ConcurrentSocialNetwork.bidirectionalCommonContacts (people);
        end=new Date();
        peopleCommonContacts.forEach(p -> System.out.println (p.getFullId()+": "+getContacts(p.getContacts())));
        System.out.println("Execution Time: "+(end.getTime()- start.getTime()));

        System.out.println("Concurrent Main Bidirectional - Facebook");
        people=DataLoader.load("data","facebook_contacts.txt");
        start=new Date();
        peopleCommonContacts= ConcurrentSocialNetwork.bidirectionalCommonContacts (people);
        end=new Date();
        peopleCommonContacts.forEach(p -> System.out.println (p.getFullId()+": "+getContacts(p.getContacts())));
        System.out.println("Execution Time: "+(end.getTime()- start.getTime()));

    }

    private static String formatContacts(List<String> contacts) {
        StringBuffer buffer=new StringBuffer();
        for (String contact: contacts) {
            buffer.append(contact+",");
        }
        return buffer.toString();
    }
}
```

## 串行版本

与本书中的其他示例一样，我们实现了这个示例的串行版本。这个版本与并发版本相同，做出以下更改：

+   用`stream()`方法替换`parallelStream()`方法

+   用`ArrayList`数据结构替换`ConcurrentLinkedDeque`数据结构

+   用`groupingBy()`方法替换`groupingByConcurrent()`方法

+   不要在`of()`方法中使用最终参数

### 比较两个版本

我们使用 JMH 框架（[`openjdk.java.net/projects/code-tools/jmh/`](http://openjdk.java.net/projects/code-tools/jmh/)）执行了两个版本和两个数据集。该框架允许您在 Java 中实现微基准测试。使用基准测试框架比简单使用`currentTimeMillis()`或`nanoTime()`等方法测量时间更好。我们在具有四核处理器的计算机上执行了 10 次，并计算了这 10 次的中等执行时间。以下是以毫秒为单位的结果：

|   | **示例** | **Facebook** |
| --- | --- | --- |
| **串行** | 0.861 | 7002.485 |
| **并发** | 1.352 | 5303.990 |

我们可以得出以下结论：

+   对于示例数据集，串行版本获得了更好的执行时间。这个结果的原因是示例数据集的元素很少。

+   对于 Facebook 数据集，并发版本获得了更好的执行时间。

如果我们比较 Facebook 数据集的并发和串行版本，我们会得到以下结果：

![比较两个版本](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-cncr-prog-java8/img/00025.jpeg)

# 摘要

在本章中，我们使用`Stream`框架提供的不同版本的`collect()`方法来转换和分组`Stream`的元素。这和第七章，“使用并行流处理大型数据集 - 映射和归约模型”，教你如何使用整个流 API。

基本上，`collect()` 方法需要一个收集器来处理流的数据，并生成由流形成的一组聚合操作返回的数据结构。收集器与三种不同的数据结构一起工作——输入元素的类，用于处理输入元素的中间数据结构，以及返回的最终数据结构。

我们使用了不同版本的`collect()`方法来实现一个搜索工具，该工具必须在没有倒排索引的文件集中查找查询，一个推荐系统，以及一个工具来计算社交网络中两个用户之间的共同联系人。

在下一章中，我们将深入研究 Java 并发 API 提供的并发数据结构和同步机制。
