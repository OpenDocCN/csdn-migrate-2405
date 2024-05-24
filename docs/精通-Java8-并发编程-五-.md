# 精通 Java8 并发编程（五）

> 原文：[`zh.annas-archive.org/md5/BFECC9856BE4118734A8147A2EEBA11A`](https://zh.annas-archive.org/md5/BFECC9856BE4118734A8147A2EEBA11A)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第九章：深入研究并发数据结构和同步实用程序

在每个计算机程序中最重要的元素之一是**数据结构**。数据结构允许我们根据需要以不同的方式存储我们的应用程序读取、转换和写入的数据。选择适当的数据结构是获得良好性能的关键点。糟糕的选择可能会显着降低算法的性能。Java 并发 API 包括一些设计用于在并发应用程序中使用的数据结构，而不会引起数据不一致或信息丢失。

并发应用程序中另一个关键点是**同步机制**。您可以使用它们通过创建临界区来实现互斥，也就是说，只能由一个线程执行的代码段。但您还可以使用同步机制来实现线程之间的依赖关系，例如，并发任务必须等待另一个任务的完成。Java 并发 API 包括基本的同步机制，如`synchronized`关键字和非常高级的实用程序，例如`CyclicBarrier`类或您在第五章中使用的`Phaser`类，*分阶段运行任务 - Phaser 类*。

在本章中，我们将涵盖以下主题：

+   并发数据结构

+   同步机制

# 并发数据结构

每个计算机程序都使用数据。它们从数据库、文件或其他来源获取数据，转换数据，然后将转换后的数据写入数据库、文件或其他目的地。程序使用存储在内存中的数据，并使用数据结构将数据存储在内存中。

当您实现并发应用程序时，您必须非常小心地使用数据结构。如果不同的线程可以修改唯一数据结构中存储的数据，您必须使用同步机制来保护该数据结构上的修改。如果不这样做，可能会出现数据竞争条件。您的应用程序有时可能会正常工作，但下一次可能会因为随机异常而崩溃，在无限循环中卡住，或者悄悄地产生不正确的结果。结果将取决于执行的顺序。

为了避免数据竞争条件，您可以：

+   使用非同步数据结构，并自行添加同步机制

+   使用 Java 并发 API 提供的数据结构，它在内部实现了同步机制，并经过优化，可用于并发应用程序

第二个选项是最推荐的。在本节的页面中，您将回顾最重要的并发数据结构，特别关注 Java 8 的新功能。

## 阻塞和非阻塞数据结构

Java 并发 API 提供了两种类型的并发数据结构：

+   **阻塞数据结构**：这种数据结构提供了在其中插入和删除数据的方法，当操作无法立即完成时（例如，如果您想取出一个元素而数据结构为空），发出调用的线程将被阻塞，直到操作可以完成

+   **非阻塞数据结构**：这种数据结构提供了在其中插入和删除数据的方法，当操作无法立即完成时，返回一个特殊值或抛出异常

有时，我们对阻塞数据结构有非阻塞等价物。例如，`ConcurrentLinkedDeque`类是一个非阻塞数据结构，而`LinkedBlockingDeque`是阻塞等价物。阻塞数据结构具有类似非阻塞数据结构的方法。例如，`Deque`接口定义了`pollFirst()`方法，如果双端队列为空，则不会阻塞并返回`null`。每个阻塞队列实现也实现了这个方法。

**Java 集合框架**（**JCF**）提供了一组可以在顺序编程中使用的不同数据结构。Java 并发 API 扩展了这些结构，提供了可以在并发应用程序中使用的其他结构。这包括：

+   **接口**：这扩展了 JCF 提供的接口，添加了一些可以在并发应用程序中使用的方法

+   **类**：这些类实现了前面的接口，提供了可以在应用程序中使用的实现

在以下部分，我们介绍了并发应用程序中可以使用的接口和类。

### 接口

首先，让我们描述并发数据结构实现的最重要的接口。

#### BlockingQueue

**队列**是一种线性数据结构，允许您在队列末尾插入元素并从开头获取元素。它是一种**先进先出**（**FIFO**）的数据结构，队列中引入的第一个元素是被处理的第一个元素。

JCF 定义了`Queue`接口，该接口定义了队列中要实现的基本操作。该接口提供了以下方法：

+   在队列末尾插入元素

+   从队列头部检索并删除元素

+   从队列头部检索但不删除元素

该接口定义了这些方法的两个版本，当方法可以完成时具有不同的行为（例如，如果要从空队列中检索元素）：

+   抛出异常的方法

+   返回特殊值的方法，例如`false`或`null`

下表包括了每个操作的方法名称：

| 操作 | 异常 | 特殊值 |
| --- | --- | --- |
| 插入 | `add()` | `offer()` |
| 检索和删除 | `remove()` | `poll()` |
| 检索但不删除 | `element()` | `peek()` |

`BlockingDeque`接口扩展了`Queue`接口，添加了在操作可以完成时阻塞调用线程的方法。这些方法包括：

| 操作 | 阻塞 |
| --- | --- |
| 插入 | `put()` |
| 检索和删除 | `take()` |
| 检索但不删除 | N/A |

#### BlockingDeque

**双端队列**是一种线性数据结构，类似于队列，但允许您从数据结构的两侧插入和删除元素。JCF 定义了扩展`Queue`接口的`Deque`接口。除了`Queue`接口提供的方法之外，它还提供了在两端插入、检索和删除以及在两端检索但不删除的方法：

| 操作 | 异常 | 特殊值 |
| --- | --- | --- |
| 插入 | `addFirst()`，`addLast()` | `offerFirst()`，`offerLast()` |
| 检索和删除 | `removeFirst()`，`removeLast()` | `pollFirst()`，`pollLast()` |
| 检索但不删除 | `getFirst()`，`getLast()` | `peekFirst()`，`peekLast()` |

`BlockingDeque`接口扩展了`Deque`接口，添加了在操作无法完成时阻塞调用线程的方法：

| 操作 | 阻塞 |
| --- | --- |
| 插入 | `putFirst()`，`putLast()` |
| 检索和删除 | `takeFirst()`，`takeLast()` |
| 检索但不删除 | N/A |

#### ConcurrentMap

**映射**（有时也称为**关联数组**）是一种数据结构，允许您存储（键，值）对。JCF 提供了`Map`接口，该接口定义了与映射一起使用的基本操作。这包括插入、检索和删除以及检索但不删除的方法：

+   `put()`: 将（键，值）对插入到映射中

+   `get()`: 返回与键关联的值

+   `remove()`: 移除与指定键关联的（键，值）对

+   `containsKey()`和`containsValue()`: 如果映射包含指定的键或值，则返回 true

这个接口在 Java 8 中已经修改，包括以下新方法。您将在本章后面学习如何使用这些方法：

+   `forEach()`: 这个方法对映射的所有元素执行给定的函数。

+   `compute()`, `computeIfAbsent()`和`computeIfPresent()`: 这些方法允许您指定计算与键关联的新值的函数。

+   `merge()`: 这个方法允许你指定将（键，值）对合并到现有的映射中。如果键不在映射中，它会直接插入。如果不是，执行指定的函数。

`ConcurrentMap`扩展了`Map`接口，为并发应用程序提供相同的方法。请注意，在 Java 8 中（不像 Java 7），`ConcurrentMap`接口没有向`Map`接口添加新方法。

#### TransferQueue

这个接口扩展了`BlockingQueue`接口，并添加了从生产者传输元素到消费者的方法，其中生产者可以等待直到消费者取走它的元素。这个接口添加的新方法是：

+   `transfer()`: 将一个元素传输给消费者，并等待（阻塞调用线程），直到元素被消费。

+   `tryTransfer()`: 如果有消费者在等待，就传输一个元素。如果没有，这个方法返回`false`值，并且不会将元素插入队列。

### Classes

Java 并发 API 提供了之前描述的接口的不同实现。其中一些不添加任何新特性，但其他一些添加了新的有趣功能。

#### LinkedBlockingQueue

这个类实现了`BlockingQueue`接口，提供了一个具有阻塞方法的队列，可以选择具有有限数量的元素。它还实现了`Queue`、`Collection`和`Iterable`接口。

#### ConcurrentLinkedQueue

这个类实现了`Queue`接口，提供了一个线程安全的无限队列。在内部，它使用非阻塞算法来保证在您的应用程序中不会出现数据竞争。

#### LinkedBlockingDeque

这个类实现了`BlockingDeque`接口，提供了一个具有阻塞方法的双端队列，可以选择具有有限数量的元素。它比`LinkedBlockingQueue`具有更多的功能，但可能有更多的开销，因此当不需要双端队列功能时应该使用`LinkedBlockingQueue`。

#### ConcurrentLinkedDeque

这个类实现了`Deque`接口，提供了一个线程安全的无限双端队列，允许您在队列的两端添加和删除元素。它比`ConcurrentLinkedQueue`具有更多的功能，但可能有更多的开销，就像`LinkedBlockingDeque`一样。

#### ArrayBlockingQueue

这个类实现了`BlockingQueue`接口，提供了一个基于数组的有限元素数量的阻塞队列实现。它还实现了`Queue`、`Collection`和`Iterable`接口。与非并发的基于数组的数据结构（`ArrayList`和`ArrayDeque`）不同，`ArrayBlockingQueue`在构造函数中分配一个固定大小的数组，并且不会调整大小。

#### DelayQueue

这个类实现了`BlockingDeque`接口，提供了一个具有阻塞方法和无限元素数量的队列实现。这个队列的元素必须实现`Delayed`接口，因此它们必须实现`getDelay()`方法。如果该方法返回负值或零值，延迟已经过期，元素可以从队列中取出。队列的头部是延迟值最负的元素。

#### LinkedTransferQueue

这个类提供了`TransferQueue`接口的实现。它提供了一个具有无限元素数量的阻塞队列，并且可以将它们用作生产者和消费者之间的通信通道，其中生产者可以等待消费者处理他们的元素。

#### PriorityBlockingQueue

这个类提供了`BlockingQueue`接口的实现，其中元素可以根据它们的自然顺序或在类的构造函数中指定的比较器进行轮询。这个队列的头部由元素的排序顺序确定。

#### ConcurrentHashMap

这个类提供了`ConcurrentMap`接口的实现。它提供了一个线程安全的哈希表。除了 Java 8 版本中添加到`Map`接口的方法之外，这个类还添加了其他方法：

+   `search()`, `searchEntries()`, `searchKeys()`, and `searchValues()`: 这些方法允许您在（键，值）对、键或值上应用搜索函数。搜索函数可以是 lambda 表达式，当搜索函数返回非空值时，方法结束。这就是方法执行的结果。

+   `reduce()`, `reduceEntries()`, `reduceKeys()`, 和 `reduceValues()`: 这些方法允许您应用`reduce()`操作来转换（键，值）对、键或条目，就像流中发生的那样（参见第八章，“使用并行流处理大型数据集 - Map 和 Collect 模型”了解有关`reduce()`方法的更多细节）。

已添加更多方法（`forEachValue`，`forEachKey`等），但这里不涉及它们。

## 使用新特性

在本节中，您将学习如何使用 Java 8 中引入的并发数据结构的新特性。

### ConcurrentHashMap 的第一个示例

在第八章中，您实现了一个应用程序，从 20,000 个亚马逊产品的数据集中进行搜索。我们从亚马逊产品共购买网络元数据中获取了这些信息，其中包括 548,552 个产品的标题、销售排名和类似产品的信息。您可以从[`snap.stanford.edu/data/amazon-meta.html`](https://snap.stanford.edu/data/amazon-meta.html)下载这个数据集。在那个示例中，您使用了一个名为`productsByBuyer`的`ConcurrentHashMap<String, List<ExtendedProduct>>`来存储用户购买的产品的信息。这个映射的键是用户的标识符，值是用户购买的产品的列表。您将使用该映射来学习如何使用`ConcurrentHashMap`类的新方法。

#### forEach()方法

这个方法允许您指定一个函数，该函数将在每个`ConcurrentHashMap`的（键，值）对上执行。这个方法有很多版本，但最基本的版本只有一个`BiConsumer`函数，可以表示为 lambda 表达式。例如，您可以使用这个方法来打印每个用户购买了多少产品的代码：

```java
    productsByBuyer.forEach( (id, list) -> System.out.println(id+": "+list.size()));
```

这个基本版本是通常的`Map`接口的一部分，并且总是按顺序执行。在这段代码中，我们使用了 lambda 表达式，其中`id`是元素的键，`list`是元素的值。

在另一个示例中，我们使用了`forEach()`方法来计算每个用户给出的平均评分。

```java
    productsByBuyer.forEach( (id, list) -> {
        double average=list.stream().mapToDouble(item -> item.getValue()).average().getAsDouble();
        System.out.println(id+": "+average);
    });
```

在这段代码中，我们还使用了 lambda 表达式，其中`id`是元素的键，`list`是其值。我们使用了应用于产品列表的流来计算平均评分。

此方法的其他版本如下：

+   `forEach(parallelismThreshold, action)`: 这是您在并发应用程序中必须使用的方法的版本。如果地图的元素多于第一个参数中指定的数量，则此方法将并行执行。

+   `forEachEntry(parallelismThreshold, action)`: 与之前相同，但在这种情况下，操作是`Consumer`接口的实现，它接收一个带有元素的键和值的`Map.Entry`对象。在这种情况下，您也可以使用 lambda 表达式。

+   `forEachKey(parallelismThreshold, action)`: 与之前相同，但在这种情况下，操作仅应用于`ConcurrentHashMap`的键。

+   `forEachValue(parallelismThreshold, action)`: 与之前相同，但在这种情况下，操作仅应用于`ConcurrentHashMap`的值。

当前实现使用通用的`ForkJoinPool`实例来执行并行任务。

#### search()方法

此方法将搜索函数应用于`ConcurrentHashMap`的所有元素。此搜索函数可以返回空值或非空值。`search()`方法将返回搜索函数返回的第一个非空值。此方法接收两个参数：

+   `parallelismThreshold`: 如果地图的元素多于此参数指定的数量，则此方法将并行执行。

+   `searchFunction`: 这是`BiFunction`接口的实现，可以表示为 lambda 表达式。此函数接收每个元素的键和值作为参数，并且如前所述，如果找到您要搜索的内容，则必须返回非空值，如果找不到，则必须返回空值。

例如，您可以使用此函数找到包含某个单词的第一本书：

```java
    ExtendedProduct firstProduct=productsByBuyer.search(100,
        (id, products) -> {
            for (ExtendedProduct product: products) {
                if (product.getTitle() .toLowerCase().contains("java")) {
                    return product;
                }
            }
        return null;
    });
    if (firstProduct!=null) {
        System.out.println(firstProduct.getBuyer()+":"+ firstProduct.getTitle());
    }
```

在这种情况下，我们使用 100 作为`parallelismThreshold`，并使用 lambda 表达式来实现搜索函数。在此函数中，对于每个元素，我们处理列表的所有产品。如果我们找到包含单词`java`的产品，我们返回该产品。这是`search()`方法返回的值。最后，我们在控制台中写入产品的买家和标题。

此方法还有其他版本：

+   `searchEntries(parallelismThreshold, searchFunction)`: 在这种情况下，搜索函数是`Function`接口的实现，它接收一个`Map.Entry`对象作为参数

+   `searchKeys(parallelismThreshold, searchFunction)`: 在这种情况下，搜索函数仅应用于`ConcurrentHashMap`的键

+   `searchValues(parallelismThreshold, searchFunction)`: 在这种情况下，搜索函数仅应用于`ConcurrentHashMap`的值

#### reduce()方法

此方法类似于`Stream`框架提供的`reduce()`方法，但在这种情况下，您直接使用`ConcurrentHashMap`的元素。此方法接收三个参数：

+   `parallelismThreshold`: 如果`ConcurrentHashMap`的元素多于此参数中指定的数量，则此方法将并行执行。

+   `transformer`: 此参数是`BiFunction`接口的实现，可以表示为 lambda 函数。它接收一个键和一个值作为参数，并返回这些元素的转换。

+   `reducer`: 此参数是`BiFunction`接口的实现，也可以表示为 lambda 函数。它接收 transformer 函数返回的两个对象作为参数。此函数的目标是将这两个对象分组为一个对象。

作为这种方法的一个例子，我们将获得一个产品列表，其中包含值为`1`的评论（最差的值）。我们使用了两个辅助变量。第一个是`transformer`。它是一个`BiFunction`接口，我们将用作`reduce()`方法的`transformer`元素：

```java
BiFunction<String, List<ExtendedProduct>, List<ExtendedProduct>> transformer = (key, value) -> value.stream().filter(product -> product.getValue() == 1).collect(Collectors.toList());
```

此函数将接收键，即用户的`id`，以及用户购买的产品的`ExtendedProduct`对象列表。我们处理列表中的所有产品，并返回评分为一的产品。

第二个变量是 reducer `BinaryOperator`。我们将其用作`reduce()`方法的 reducer 函数：

```java
BinaryOperator<List<ExtendedProduct>> reducer = (list1, list2) ->{
        list1.addAll(list2);
        return list1;
};
```

reduce 接收两个`ExtendedProduct`列表，并使用`addAll()`方法将它们连接成一个单一的列表。

现在，我们只需实现对`reduce()`方法的调用：

```java
    List<ExtendedProduct> badReviews=productsByBuyer.reduce(10, transformer, reducer);
    badReviews.forEach(product -> {
        System.out.println(product.getTitle()+":"+ product.getBuyer()+":"+product.getValue());
    });
```

`reduce()`方法还有其他版本：

+   `reduceEntries()`，`reduceEntriesToDouble()`，`reduceEntriesToInt()`和`reduceEntriesToLong()`：在这种情况下，转换器和 reducer 函数作用于`Map.Entry`对象。最后三个版本分别返回`double`，`int`和`long`值。

+   `reduceKeys()`，`reduceKeysToDouble()`和`reduceKeysToInt()`，`reduceKeysToLong()`：在这种情况下，转换器和 reducer 函数作用于映射的键。最后三个版本分别返回`double`，`int`和`long`值。

+   `reduceToInt()`，`reduceToDouble()`和`reduceToLong()`：在这种情况下，转换器函数作用于键和值，reducer 方法分别作用于`int`，`double`或`long`数。这些方法返回`int`，`double`和`long`值。

+   `reduceValues()`，`reduceValuesToDouble()`，`reduceValuesToInt()`和`reduceValuesToLong()`：在这种情况下，转换器和 reducer 函数作用于映射的值。最后三个版本分别返回`double`，`int`和`long`值。

#### compute()方法

此方法（在`Map`接口中定义）接收元素的键和可以表示为 lambda 表达式的`BiFunction`接口的实现作为参数。如果键存在于`ConcurrentHashMap`中，则此函数将接收元素的键和值，否则为`null`。该方法将用函数返回的值替换与键关联的值，如果不存在，则将它们插入`ConcurrentHashMap`，或者如果对于先前存在的项目返回`null`，则删除该项目。请注意，在`BiFunction`执行期间，一个或多个映射条目可能会被锁定。因此，您的`BiFunction`不应该工作太长时间，也不应该尝试更新同一映射中的任何其他条目。否则可能会发生死锁。

例如，我们可以使用此方法与 Java 8 中引入的新原子变量`LongAdder`一起计算与每个产品关联的不良评论数量。我们创建一个名为 counter 的新`ConcurrentHashMap`。键将是产品的标题，值将是`LongAdder`类的对象，用于计算每个产品有多少不良评论。

```java
    ConcurrentHashMap<String, LongAdder> counter=new ConcurrentHashMap<>();
```

我们处理在上一节中计算的`badReviews` `ConcurrentLinkedDeque`的所有元素，并使用`compute()`方法创建和更新与每个产品关联的`LongAdder`。

```java
    badReviews.forEach(product -> {
        counter.computeIfAbsent(product.getTitle(), title -> new LongAdder()).increment();
    });
    counter.forEach((title, count) -> {
        System.out.println(title+":"+count);
    });
```

最后，我们将结果写入控制台。

### 另一个使用 ConcurrentHashMap 的例子

`ConcurrentHashMap`类中添加的另一种方法并在 Map 接口中定义。这是`merge()`方法，允许您将（键，值）对合并到映射中。如果键不存在于`ConcurrentHashMap`中，则直接插入。如果键存在，则必须定义从旧值和新值中关联的键的新值。此方法接收三个参数：

+   我们要合并的键。

+   我们要合并的值。

+   可以表示为 lambda 表达式的`BiFunction`的实现。此函数接收旧值和与键关联的新值作为参数。该方法将用此函数返回的值与键关联。`BiFunction`在映射的部分锁定下执行，因此可以保证它不会同时为相同的键并发执行。

例如，我们已经将上一节中使用的亚马逊的 20,000 个产品按评论年份分成文件。对于每一年，我们加载`ConcurrentHashMap`，其中产品是键，评论列表是值。因此，我们可以使用以下代码加载 1995 年和 1996 年的评论：

```java
        Path path=Paths.get("data\\amazon\\1995.txt");
        ConcurrentHashMap<BasicProduct, ConcurrentLinkedDeque<BasicReview>> products1995=BasicProductLoader.load(path);
        showData(products1995);

        path=Paths.get("data\\amazon\\1996.txt");
        ConcurrentHashMap<BasicProduct, ConcurrentLinkedDeque<BasicReview>> products1996=BasicProductLoader.load(path);
        System.out.println(products1996.size());
        showData(products1996);
```

如果我们想将`ConcurrentHashMap`的两个版本合并成一个，可以使用以下代码：

```java
        products1996.forEach(10,(product, reviews) -> {
            products1995.merge(product, reviews, (reviews1, reviews2) -> {
                System.out.println("Merge for: "+product.getAsin());
                reviews1.addAll(reviews2);
                return reviews1;
            });
        });
```

我们处理了 1996 年的`ConcurrentHashMap`的所有元素，并且对于每个（键，值）对，我们在 1995 年的`ConcurrentHashMap`上调用`merge()`方法。`merge`函数将接收两个评论列表，因此我们只需将它们连接成一个。

### 使用 ConcurrentLinkedDeque 类的示例

`Collection`接口在 Java 8 中还包括了新的方法。大多数并发数据结构都实现了这个接口，因此我们可以在它们中使用这些新特性。其中两个是第七章和第八章中使用的`stream()`和`parallelStream()`方法。让我们看看如何使用`ConcurrentLinkedDeque`和我们在前面章节中使用的 20,000 个产品。

#### removeIf() 方法

此方法在`Collection`接口中有一个默认实现，不是并发的，并且没有被`ConcurrentLinkedDeque`类覆盖。此方法接收`Predicate`接口的实现作为参数，该接口将接收`Collection`的元素作为参数，并应返回`true`或`false`值。该方法将处理`Collection`的所有元素，并将删除那些使用谓词获得`true`值的元素。

例如，如果您想删除所有销售排名高于 1,000 的产品，可以使用以下代码：

```java
    System.out.println("Products: "+productList.size());
    productList.removeIf(product -> product.getSalesrank() > 1000);
    System.out.println("Products; "+productList.size());
    productList.forEach(product -> {
        System.out.println(product.getTitle()+": "+product.getSalesrank());
    });
```

#### spliterator() 方法

此方法返回`Spliterator`接口的实现。**spliterator**定义了`Stream` API 可以使用的数据源。您很少需要直接使用 spliterator，但有时您可能希望创建自己的 spliterator 来为流生成自定义源（例如，如果您实现自己的数据结构）。如果您有自己的 spliterator 实现，可以使用`StreamSupport.stream(mySpliterator, isParallel)`在其上创建流。这里，`isParallel`是一个布尔值，确定创建的流是否是并行的。分割器类似于迭代器，您可以使用它来遍历集合中的所有元素，但可以将它们分割以以并发方式进行遍历。

分割器有八种不同的特征来定义其行为：

+   `CONCURRENT`: 分割器源可以安全并发修改

+   `DISTINCT`: 分割器返回的所有元素都是不同的

+   `IMMUTABLE`: 分割器源不可修改

+   `NONNULL`: 分割器永远不会返回`null`值

+   `ORDERED`: 分割器返回的元素是有序的（这意味着它们的顺序很重要）

+   `SIZED`: 分割器能够使用`estimateSize()`方法返回确切数量的元素

+   `SORTED`: 分割器源已排序

+   `SUBSIZED`: 如果使用`trySplit()`方法来分割这个分割器，生成的分割器将是`SIZED`和`SUBSIZED`

此接口最有用的方法是：

+   `estimatedSize()`: 此方法将为您提供分割器中元素数量的估计。

+   `forEachRemaining()`: 这个方法允许您对尚未被处理的 spliterator 的元素应用`Consumer`接口的实现，可以用 lambda 函数表示。

+   `tryAdvance()`: 这个方法允许您对 spliterator 要处理的下一个元素应用`Consumer`接口的实现，可以用 lambda 函数表示，如果有的话。

+   `trySplit()`: 这个方法尝试将 spliterator 分成两部分。调用者 spliterator 将处理一些元素，返回的 spliterator 将处理其他元素。如果 spliterator 是`ORDERED`，返回的 spliterator 必须处理元素的严格前缀，调用必须处理严格后缀。

+   `hasCharacteristics()`: 这个方法允许您检查 spliterator 的属性。

让我们看一个使用`ArrayList`数据结构的例子，有 20,000 个产品。

首先，我们需要一个辅助任务，它将处理一组产品，将它们的标题转换为小写。这个任务将有一个`Spliterator`作为属性：

```java
public class SpliteratorTask implements Runnable {

    private Spliterator<Product> spliterator;

    public SpliteratorTask (Spliterator<Product> spliterator) {
        this.spliterator=spliterator;
    }

    @Override
    public void run() {
        int counter=0;
        while (spliterator.tryAdvance(product -> {
            product.setTitle(product.getTitle().toLowerCase());
        })) {
            counter++;
        };
        System.out.println(Thread.currentThread().getName() +":"+counter);
    }

}
```

正如您所看到的，这个任务在执行完毕时会写入处理的产品数量。

在主方法中，一旦我们用 20,000 个产品加载了`ConcurrentLinkedQueue`，我们就可以获得 spliterator，检查它的一些属性，并查看它的估计大小。

```java
    Spliterator<Product> split1=productList.spliterator();
    System.out.println(split1.hasCharacteristics (Spliterator.CONCURRENT));
    System.out.println(split1.hasCharacteristics (Spliterator.SUBSIZED));
    System.out.println(split1.estimateSize());
```

然后，我们可以使用`trySplit()`方法分割 spliterator，并查看两个 spliterator 的大小：

```java
    Spliterator<Product> split2=split1.trySplit();
    System.out.println(split1.estimateSize());
    System.out.println(split2.estimateSize());
```

最后，我们可以在执行器中执行两个任务，一个用于 spliterator，以查看每个 spliterator 是否真的处理了预期数量的元素。

```java
    ThreadPoolExecutor executor=(ThreadPoolExecutor) Executors.newCachedThreadPool();
    executor.execute(new SpliteratorTask(split1));
    executor.execute(new SpliteratorTask(split2));
```

在下面的截图中，您可以看到这个例子的执行结果：

![spliterator()方法](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-cncr-prog-java8/img/00026.jpeg)

您可以看到，在分割 spliterator 之前，`estimatedSize()`方法返回 20,000 个元素。在`trySplit()`方法执行后，两个 spliterator 都有 10,000 个元素。这些是每个任务处理的元素。

## 原子变量

Java 1.5 引入了原子变量，以提供对`integer`、`long`、`boolean`、`reference`和`Array`对象的原子操作。它们提供了一些方法来增加、减少、建立值、返回值，或者在当前值等于预定义值时建立值。

在 Java 8 中，新增了四个新类。它们是`DoubleAccumulator`、`DoubleAdder`、`LongAccumulator`和`LongAdder`。在前面的部分，我们使用了`LongAdder`类来计算产品的差评数量。这个类提供了类似于`AtomicLong`的功能，但是当您频繁地从不同线程更新累积和并且只在操作结束时请求结果时，它的性能更好。`DoubleAdder`函数与之相等，但是使用双精度值。这两个类的主要目标是拥有一个可以由不同线程一致更新的计数器。这些类的最重要的方法是：

+   `add()`: 用指定的值增加计数器的值

+   `increment()`: 等同于`add(1)`

+   `decrement()`: 等同于`add(-1)`

+   `sum()`: 这个方法返回计数器的当前值

请注意，`DoubleAdder`类没有`increment()`和`decrement()`方法。

`LongAccumulator`和`DoubleAccumulator`类是类似的，但它们有一个非常重要的区别。它们有一个构造函数，您可以在其中指定两个参数：

+   内部计数器的身份值

+   一个将新值累积到累加器中的函数

请注意，函数不应依赖于累积的顺序。在这种情况下，最重要的方法是：

+   `accumulate()`: 这个方法接收一个`long`值作为参数。它将函数应用于当前值和参数来增加或减少计数器的值。

+   `get()`: 返回计数器的当前值。

例如，以下代码将在所有执行中在控制台中写入 362,880：

```java
            LongAccumulator accumulator=new LongAccumulator((x,y) -> x*y, 1);

        IntStream.range(1, 10).parallel().forEach(x -> accumulator.accumulate(x));

        System.out.println(accumulator.get());
```

我们在累加器内部使用可交换操作，因此无论输入顺序如何，结果都是相同的。

# 同步机制

任务的同步是协调这些任务以获得期望的结果。在并发应用程序中，我们可以有两种同步方式：

+   **进程同步**：当我们想要控制任务的执行顺序时，我们使用这种同步。例如，一个任务必须在开始执行之前等待其他任务的完成。

+   **数据同步**：当两个或多个任务访问相同的内存对象时，我们使用这种同步。在这种情况下，您必须保护对该对象的写操作的访问。如果不这样做，您可能会遇到数据竞争条件，程序的最终结果会因每次执行而异。

Java 并发 API 提供了允许您实现这两种类型同步的机制。Java 语言提供的最基本的同步机制是`synchronized`关键字。这个关键字可以应用于一个方法或一段代码。在第一种情况下，只有一个线程可以同时执行该方法。在第二种情况下，您必须指定一个对象的引用。在这种情况下，只有一个由对象保护的代码块可以同时执行。

Java 还提供其他同步机制：

+   `Lock` 接口及其实现类：这种机制允许您实现一个临界区，以确保只有一个线程将执行该代码块。

+   `Semaphore` 类实现了由*Edsger Dijkstra*引入的著名的**信号量**同步机制。

+   `CountDownLatch` 允许您实现一个情况，其中一个或多个线程等待其他线程的完成。

+   `CyclicBarrier` 允许您在一个公共点同步不同的任务。

+   `Phaser` 允许您实现分阶段的并发任务。我们在第五章中对这种机制进行了详细描述，*分阶段运行任务 - Phaser 类*。

+   `Exchanger` 允许您在两个任务之间实现数据交换点。

+   `CompletableFuture`，Java 8 的一个新特性，扩展了执行器任务的`Future`机制，以异步方式生成任务的结果。您可以指定在生成结果后要执行的任务，因此可以控制任务的执行顺序。

在接下来的部分中，我们将向您展示如何使用这些机制，特别关注 Java 8 版本中引入的`CompletableFuture`机制。

## CommonTask 类

我们实现了一个名为`CommonTask`类的类。这个类将使调用线程在`0`和`10`秒之间的随机时间内休眠。这是它的源代码：

```java
public class CommonTask {

    public static void doTask() {
        long duration = ThreadLocalRandom.current().nextLong(10);
        System.out.printf("%s-%s: Working %d seconds\n",new Date(),Thread.currentThread().getName(),duration);
        try {
            TimeUnit.SECONDS.sleep(duration);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }

}
```

在接下来的部分中，我们将使用这个类来模拟其执行时间。

## Lock 接口

最基本的同步机制之一是`Lock`接口及其实现类。基本实现类是`ReentrantLock`类。您可以使用这个类来轻松实现临界区。例如，以下任务在其代码的第一行使用`lock()`方法获取锁，并在最后一行使用`unlock()`方法释放锁。在同一时间只有一个任务可以执行这两个语句之间的代码。

```java
public class LockTask implements Runnable {

    private static ReentrantLock lock = new ReentrantLock();
    private String name;

    public LockTask(String name) {
        this.name=name;
    }

    @Override
    public void run() {
        try {
            lock.lock();
            System.out.println("Task: " + name + "; Date: " + new Date() + ": Running the task");
            CommonTask.doTask();
            System.out.println("Task: " + name + "; Date: " + new Date() + ": The execution has finished");
        } finally {
            lock.unlock();
        }

    }
}
```

例如，您可以通过以下代码在执行器中执行十个任务来检查这一点：

```java
public class LockMain {

    public static void main(String[] args) {
        ThreadPoolExecutor executor=(ThreadPoolExecutor) Executors.newCachedThreadPool();
        for (int i=0; i<10; i++) {
            executor.execute(new LockTask("Task "+i));
        }
        executor.shutdown();
        try {
            executor.awaitTermination(1, TimeUnit.DAYS);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }
}
```

在下面的图片中，您可以看到这个示例的执行结果。您可以看到每次只有一个任务被执行。

![Lock 接口](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-cncr-prog-java8/img/00027.jpeg)

## Semaphore 类

信号量机制是由 Edsger Dijkstra 于 1962 年引入的，用于控制对一个或多个共享资源的访问。这个机制基于一个内部计数器和两个名为`wait()`和`signal()`的方法。当一个线程调用`wait()`方法时，如果内部计数器的值大于 0，那么信号量会减少内部计数器，并且线程获得对共享资源的访问。如果内部计数器的值为 0，线程将被阻塞，直到某个线程调用`signal()`方法。当一个线程调用`signal()`方法时，信号量会查看是否有一些线程处于`waiting`状态（它们已经调用了`wait()`方法）。如果没有线程在等待，它会增加内部计数器。如果有线程在等待信号量，它会选择其中一个线程，该线程将返回到`wait()`方法并访问共享资源。其他等待的线程将继续等待它们的轮到。

在 Java 中，信号量是在`Semaphore`类中实现的。`wait()`方法被称为`acquire()`，`signal()`方法被称为`release()`。例如，在这个例子中，我们使用了一个`Semaphore`类来保护它的代码：

```java
public class SemaphoreTask implements Runnable{
    private Semaphore semaphore;
    public SemaphoreTask(Semaphore semaphore) {
        this.semaphore=semaphore;
    }
    @Override
    public void run() {
        try {
            semaphore.acquire();
            CommonTask.doTask();
        } catch (InterruptedException e) {
            e.printStackTrace();
        } finally {
            semaphore.release();
        }
    }
}
```

在主程序中，我们执行了共享一个`Semaphore`类的十个任务，该类初始化了两个共享资源，因此我们将同时运行两个任务。

```java
    public static void main(String[] args) {

        Semaphore semaphore=new Semaphore(2);
        ThreadPoolExecutor executor=(ThreadPoolExecutor) Executors.newCachedThreadPool();

        for (int i=0; i<10; i++) {
            executor.execute(new SemaphoreTask(semaphore));
        }

        executor.shutdown();
        try {
            executor.awaitTermination(1, TimeUnit.DAYS);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }
```

以下截图显示了这个例子执行的结果。你可以看到两个任务同时在运行：

![信号量类](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-cncr-prog-java8/img/00028.jpeg)

## CountDownLatch 类

这个类提供了一种等待一个或多个并发任务完成的机制。它有一个内部计数器，必须初始化为我们要等待的任务数量。然后，`await()`方法使调用线程休眠，直到内部计数器到达零，`countDown()`方法减少内部计数器。

例如，在这个任务中，我们使用`countDown()`方法来减少`CountDownLatch`对象的内部计数器，它在构造函数中接收一个参数。

```java
public class CountDownTask implements Runnable {

    private CountDownLatch countDownLatch;

    public CountDownTask(CountDownLatch countDownLatch) {
        this.countDownLatch=countDownLatch;
    }

    @Override
    public void run() {
        CommonTask.doTask();
        countDownLatch.countDown();

    }
}
```

然后，在`main()`方法中，我们在执行器中执行任务，并使用`CountDownLatch`的`await()`方法等待它们的完成。该对象被初始化为我们要等待的任务数量。

```java
    public static void main(String[] args) {

        CountDownLatch countDownLatch=new CountDownLatch(10);

        ThreadPoolExecutor executor=(ThreadPoolExecutor) Executors.newCachedThreadPool();

        System.out.println("Main: Launching tasks");
        for (int i=0; i<10; i++) {
            executor.execute(new CountDownTask(countDownLatch));
        }

        try {
            countDownLatch.await();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        System.out.

        executor.shutdown();
    }
```

以下截图显示了这个例子执行的结果：

![CountDownLatch 类](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-cncr-prog-java8/img/00029.jpeg)

## CyclicBarrier 类

这个类允许你在一个共同点同步一些任务。所有任务都将在那个点等待，直到所有任务都到达。在内部，它还管理一个内部计数器，记录还没有到达那个点的任务。当一个任务到达确定的点时，它必须执行`await()`方法等待其余的任务。当所有任务都到达时，`CyclicBarrier`对象唤醒它们，使它们继续执行。

这个类允许你在所有参与方到达时执行另一个任务。要配置这个，你必须在对象的构造函数中指定一个可运行的对象。

例如，我们实现了以下的 Runnable，它使用了一个`CyclicBarrier`对象来等待其他任务：

```java
public class BarrierTask implements Runnable {

    private CyclicBarrier barrier;

    public BarrierTask(CyclicBarrier barrier) {
        this.barrier=barrier;
    }

    @Override
    public void run() {
        System.out.println(Thread.currentThread().getName()+": Phase 1");
        CommonTask.doTask();
        try {
            barrier.await();
        } catch (InterruptedException e) {
            e.printStackTrace();
        } catch (BrokenBarrierException e) {
            e.printStackTrace();
        }
        System.out.println(Thread.currentThread().getName()+": Phase 2");

    }
}
```

我们还实现了另一个`Runnable`对象，当所有任务都执行了`await()`方法时，它将被`CyclicBarrier`执行。

```java
public class FinishBarrierTask implements Runnable {

    @Override
    public void run() {
        System.out.println("FinishBarrierTask: All the tasks have finished");
    }
}
```

最后，在`main()`方法中，我们在执行器中执行了十个任务。你可以看到`CyclicBarrier`是如何初始化的，它与我们想要同步的任务数量以及`FinishBarrierTask`对象一起：

```java
    public static void main(String[] args) {
        CyclicBarrier barrier=new CyclicBarrier(10,new FinishBarrierTask());

        ThreadPoolExecutor executor=(ThreadPoolExecutor) Executors.newCachedThreadPool();

        for (int i=0; i<10; i++) {
            executor.execute(new BarrierTask(barrier));
        }

        executor.shutdown();

        try {
            executor.awaitTermination(1, TimeUnit.DAYS);
        } catch (InterruptedException e) {
             e.printStackTrace();
        }
    }
```

以下截图显示了这个例子执行的结果：

![CyclicBarrier 类](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-cncr-prog-java8/img/00030.jpeg)

你可以看到当所有任务都到达调用`await()`方法的点时，`FinishBarrierTask`被执行，然后所有任务继续执行。

## CompletableFuture 类

这是 Java 8 并发 API 中引入的一种新的同步机制。它扩展了`Future`机制，赋予它更多的功能和灵活性。它允许您实现一个事件驱动模型，链接任务，只有在其他任务完成时才会执行。与`Future`接口一样，`CompletableFuture`必须使用操作返回的结果类型进行参数化。与`Future`对象一样，`CompletableFuture`类表示异步计算的结果，但`CompletableFuture`的结果可以由任何线程建立。它具有`complete()`方法，在计算正常结束时建立结果，以及`completeExceptionally()`方法，在计算异常结束时建立结果。如果两个或更多线程在同一个`CompletableFuture`上调用`complete()`或`completeExceptionally()`方法，只有第一次调用会生效。

首先，您可以使用其构造函数创建`CompletableFuture`。在这种情况下，您必须使用`complete()`方法来建立任务的结果，就像我们之前解释的那样。但您也可以使用`runAsync()`或`supplyAsync()`方法来创建一个。`runAsync()`方法执行一个`Runnable`对象并返回`CompletableFuture<Void>`，因此计算不会返回任何结果。`supplyAsync()`方法执行一个`Supplier`接口的实现，该接口参数化了此计算将返回的类型。`Supplier`接口提供`get()`方法。在该方法中，我们必须包含任务的代码并返回其生成的结果。在这种情况下，`CompletableFuture`的结果将是`Supplier`接口的结果。

这个类提供了许多方法，允许您组织任务的执行顺序，实现一个事件驱动模型，其中一个任务直到前一个任务完成后才开始执行。以下是其中一些方法：

+   `thenApplyAsync()`: 这个方法接收`Function`接口的实现作为参数，可以表示为 lambda 表达式。当调用的`CompletableFuture`完成时，将执行此函数。此方法将返回`CompletableFuture`以获取`Function`的结果。

+   `thenComposeAsync()`: 这个方法类似于`thenApplyAsync`，但在提供的函数也返回`CompletableFuture`时很有用。

+   `thenAcceptAsync()`: 这个方法类似于前一个方法，但参数是`Consumer`接口的实现，也可以指定为 lambda 表达式；在这种情况下，计算不会返回结果。

+   `thenRunAsync()`: 这个方法与前一个方法相同，但在这种情况下，它接收一个`Runnable`对象作为参数。

+   `thenCombineAsync()`: 这个方法接收两个参数。第一个是另一个`CompletableFuture`实例。另一个是`BiFunction`接口的实现，可以指定为 lambda 函数。当两个`CompletableFuture`（调用方和参数）都完成时，将执行此`BiFunction`。此方法将返回`CompletableFuture`以获取`BiFunction`的结果。

+   `runAfterBothAsync()`: 这个方法接收两个参数。第一个是另一个`CompletableFuture`。另一个是`Runnable`接口的实现，当两个`CompletableFuture`（调用方和参数）都完成时将执行。

+   `runAfterEitherAsync()`: 这个方法等同于前一个方法，但当`CompletableFuture`对象之一完成时，将执行`Runnable`任务。

+   `allOf()`: 这个方法接收一个`CompletableFuture`对象的可变列表作为参数。它将返回一个`CompletableFuture<Void>`对象，当所有`CompletableFuture`对象都完成时，它将返回其结果。

+   `anyOf()`: 这个方法等同于前一个方法，但是返回的`CompletableFuture`在其中一个`CompletableFuture`完成时返回其结果。

最后，如果你想要获取`CompletableFuture`返回的结果，你可以使用`get()`或`join()`方法。这两种方法都会阻塞调用线程，直到`CompletableFuture`完成并返回其结果。这两种方法之间的主要区别在于，`get()`会抛出`ExecutionException`，这是一个受检异常，而`join()`会抛出`RuntimeException`（这是一个未检查的异常）。因此，在不抛出异常的 lambda 表达式（如`Supplier`、`Consumer`或`Runnable`）中使用`join()`更容易。

前面解释的大部分方法都有`Async`后缀。这意味着这些方法将使用`ForkJoinPool.commonPool`实例以并发方式执行。那些没有`Async`后缀版本的方法将以串行方式执行（也就是说，在执行`CompletableFuture`的同一个线程中），而带有`Async`后缀和一个执行器实例作为额外参数。在这种情况下，`CompletableFuture`将在传递的执行器中异步执行。

### 使用 CompletableFuture 类

在这个例子中，您将学习如何使用`CompletableFuture`类以并发方式实现一些异步任务的执行。我们将使用亚马逊的 2 万个产品集合来实现以下任务树：

![使用 CompletableFuture 类](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-cncr-prog-java8/img/00031.jpeg)

首先，我们将使用这些例子。然后，我们将执行四个并发任务。第一个任务将搜索产品。当搜索完成时，我们将把结果写入文件。第二个任务将获取评分最高的产品。第三个任务将获取销量最高的产品。当这两个任务都完成时，我们将使用另一个任务来连接它们的信息。最后，第四个任务将获取购买了产品的用户列表。`main()`程序将等待所有任务的完成，然后写入结果。

让我们看看实现的细节。

#### 辅助任务

在这个例子中，我们将使用一些辅助任务。第一个是`LoadTask`，它将从磁盘加载产品信息，并返回一个`Product`对象的列表。

```java
public class LoadTask implements Supplier<List<Product>> {

    private Path path;

    public LoadTask (Path path) {
        this.path=path;
    }
    @Override
    public List<Product> get() {
        List<Product> productList=null;
        try {
            productList = Files.walk(path, FileVisitOption.FOLLOW_LINKS).parallel()
                    .filter(f -> f.toString().endsWith(".txt")) .map(ProductLoader::load).collect (Collectors.toList());
        } catch (IOException e) {
            e.printStackTrace();
        }

        return productList;
    }
}
```

它实现了`Supplier`接口以作为`CompletableFuture`执行。在内部，它使用流来处理和解析所有文件，获取产品列表。

第二个任务是`SearchTask`，它将在`Product`对象列表中实现搜索，查找标题中包含某个词的产品。这个任务是`Function`接口的实现。

```java
public class SearchTask implements Function<List<Product>, List<Product>> {

    private String query;

    public SearchTask(String query) {
        this.query=query;
    }

    @Override
    public List<Product> apply(List<Product> products) {
        System.out.println(new Date()+": CompletableTask: start");
        List<Product> ret = products.stream()
                .filter(product -> product.getTitle() .toLowerCase().contains(query))
                .collect(Collectors.toList());
        System.out.println(new Date()+": CompletableTask: end: "+ret.size());
        return ret;
    }

}
```

它接收包含所有产品信息的`List<Product>`，并返回符合条件的产品的`List<Product>`。在内部，它在输入列表上创建流，对其进行过滤，并将结果收集到另一个列表中。

最后，`WriteTask`将把搜索任务中获取的产品写入一个`File`。在我们的例子中，我们生成了一个 HTML 文件，但是可以随意选择其他格式来写入这些信息。这个任务实现了`Consumer`接口，所以它的代码应该类似于下面这样：

```java
public class WriteTask implements Consumer<List<Product>> {

    @Override
    public void accept(List<Product> products) {
        // implementation is omitted
    }
}
```

#### main()方法

我们在`main()`方法中组织了任务的执行。首先，我们使用`CompletableFuture`类的`supplyAsync()`方法执行`LoadTask`。

```java
public class CompletableMain {

    public static void main(String[] args) {
        Path file = Paths.get("data","category");

        System.out.println(new Date() + ": Main: Loading products");
        LoadTask loadTask = new LoadTask(file);
        CompletableFuture<List<Product>> loadFuture = CompletableFuture
                .supplyAsync(loadTask);
```

然后，使用结果的`CompletableFuture`，我们使用`thenApplyAsync()`在加载任务完成后执行搜索任务。

```java
        System.out.println(new Date() + ": Main: Then apply for search");

        CompletableFuture<List<Product>> completableSearch = loadFuture
                .thenApplyAsync(new SearchTask("love"));
```

一旦搜索任务完成，我们希望将执行结果写入文件。由于这个任务不会返回结果，我们使用了`thenAcceptAsync()`方法：

```java
        CompletableFuture<Void> completableWrite = completableSearch
                .thenAcceptAsync(new WriteTask());

        completableWrite.exceptionally(ex -> {
            System.out.println(new Date() + ": Main: Exception "
                    + ex.getMessage());
            return null;
        });
```

我们使用了 exceptionally()方法来指定当写入任务抛出异常时我们想要做什么。

然后，我们在`completableFuture`对象上使用`thenApplyAsync()`方法执行任务，以获取购买产品的用户列表。我们将此任务指定为 lambda 表达式。请注意，此任务将与搜索任务并行执行。

```java
        System.out.println(new Date() + ": Main: Then apply for users");

        CompletableFuture<List<String>> completableUsers = loadFuture
                .thenApplyAsync(resultList -> {

                    System.out.println(new Date()
                            + ": Main: Completable users: start");
                                        List<String> users = resultList.stream()
                .flatMap(p -> p.getReviews().stream())
                .map(review -> review.getUser())
                .distinct()
                .collect(Collectors.toList());
                    System.out.println(new Date()
                            + ": Main: Completable users: end");

                    return users;
                });
```

与这些任务并行进行的是，我们还使用`thenApplyAsync()`方法执行任务，以找到最受欢迎的产品和最畅销的产品。我们也使用 lambda 表达式定义了这些任务。

```java
        System.out.println(new Date()
                + ": Main: Then apply for best rated product....");

        CompletableFuture<Product> completableProduct = loadFuture
                .thenApplyAsync(resultList -> {
                    Product maxProduct = null;
                    double maxScore = 0.0;

                    System.out.println(new Date()
                            + ": Main: Completable product: start");
                    for (Product product : resultList) {
                        if (!product.getReviews().isEmpty()) {
                            double score = product.getReviews().stream()
                                    .mapToDouble(review -> review.getValue())
                                    .average().getAsDouble();
                            if (score > maxScore) {
                                maxProduct = product;
                                maxScore = score;
                            }
                        }
                    }
                    System.out.println(new Date()
                            + ": Main: Completable product: end");
                    return maxProduct;
                });

        System.out.println(new Date()
                + ": Main: Then apply for best selling product....");
        CompletableFuture<Product> completableBestSellingProduct = loadFuture
                .thenApplyAsync(resultList -> {
                    System.out.println(new Date() + ": Main: Completable best selling: start");
                  Product bestProduct = resultList
                .stream()
                .min(Comparator.comparingLong (Product::getSalesrank))
                .orElse(null);
                    System.out.println(new Date()
                            + ": Main: Completable best selling: end");
                    return bestProduct;

                });
```

正如我们之前提到的，我们希望连接最后两个任务的结果。我们可以使用`thenCombineAsync()`方法来指定一个任务，在两个任务都完成后执行。

```java
        CompletableFuture<String> completableProductResult = completableBestSellingProduct
        .thenCombineAsync(
             completableProduct, (bestSellingProduct, bestRatedProduct) -> {
        System.out.println(new Date() + ": Main: Completable product result: start");
        String ret = "The best selling product is " + bestSellingProduct.getTitle() + "\n";
        ret += "The best rated product is "
            + bestRatedProduct.getTitle();
        System.out.println(new Date() + ": Main: Completable product result: end");
        return ret;
    });
```

最后，我们使用`allOf()`和`join()`方法等待最终任务的结束，并使用`get()`方法编写结果以获取它们。

```java
        System.out.println(new Date() + ": Main: Waiting for results");
        CompletableFuture<Void> finalCompletableFuture = CompletableFuture
                .allOf(completableProductResult, completableUsers,
                        completableWrite);
        finalCompletableFuture.join();

        try {
            System.out.println("Number of loaded products: "
                    + loadFuture.get().size());
            System.out.println("Number of found products: "
                    + completableSearch.get().size());
            System.out.println("Number of users: "
                    + completableUsers.get().size());
            System.out.println("Best rated product: "
                    + completableProduct.get().getTitle());
            System.out.println("Best selling product: "
                    + completableBestSellingProduct.get() .getTitle());
            System.out.println("Product result: "+completableProductResult.get());
        } catch (InterruptedException | ExecutionException e) {
            e.printStackTrace();
        }
```

在下面的截图中，您可以看到此示例的执行结果：

![main()方法](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-cncr-prog-java8/img/00032.jpeg)

首先，`main()`方法执行所有配置并等待任务的完成。任务的执行遵循我们配置的顺序。

# 总结

在本章中，我们回顾了并发应用程序的两个组件。第一个是数据结构。每个程序都使用它们来存储需要处理的信息。我们已经快速介绍了并发数据结构，以便详细描述 Java 8 并发 API 中引入的新功能，这些功能影响了`ConcurrentHashMap`类和实现`Collection`接口的类。

第二个是同步机制，允许您在多个并发任务想要修改数据时保护数据，并在必要时控制任务的执行顺序。在这种情况下，我们也快速介绍了同步机制，并详细描述了`CompletableFuture`，这是 Java 8 并发 API 的一个新功能。

在下一章中，我们将向您展示如何实现完整的并发系统，集成也可以是并发的不同部分，并使用不同的类来实现其并发性。


# 第十章：片段集成和替代方案的实现

从第二章到第八章，您使用了 Java 并发 API 的最重要部分来实现不同的示例。通常，这些示例是真实的，但大多数情况下，这些示例可以是更大系统的一部分。例如，在第四章中，*从任务中获取数据 - Callable 和 Future 接口*，您实现了一个应用程序来构建一个倒排索引，用于信息检索系统。在第六章中，*优化分治解决方案 - Fork/Join 框架*，您实现了 k 均值聚类算法来对一组文档进行聚类。然而，您可以实现一个完整的信息检索应用程序，该应用程序读取一组文档，使用向量空间模型表示它们，并使用 K-NN 算法对它们进行聚类。在这些情况下，您可能会使用不同的并发技术（执行器、流等）来实现不同的部分，但它们必须在它们之间同步和通信以获得所需的结果。

此外，本书中提出的所有示例都可以使用 Java 并发 API 的其他组件来实现。我们也将讨论其中一些替代方案。

在这一章中，我们将涵盖以下主题：

+   大块同步机制

+   文档聚类应用示例

+   实现替代方案

# 大块同步机制

大型计算机应用程序由不同的组件组成，这些组件共同工作以获得所需的功能。这些组件必须在它们之间进行同步和通信。在第九章中，*深入并发数据结构和同步实用程序*，您学到了可以使用不同的 Java 类来同步任务并在它们之间进行通信。但是当您要同步的组件也是可以使用不同机制来实现并发的并发系统时，这个任务组织就更加复杂了。例如，您的应用程序中有一个组件使用 Fork/Join 框架生成其结果，这些结果被使用`Phaser`类同步的其他任务使用。

在这些情况下，您可以使用以下两种机制来同步和通信这些组件：

+   **共享内存**：系统共享数据结构以在它们之间传递信息。

+   **消息传递**：系统之一向一个或多个系统发送消息。有不同的实现方式。在诸如 Java 之类的面向对象编程语言中，最基本的消息传递机制是一个对象调用另一个对象的方法。您还可以使用**Java 消息服务**（**JMS**）、缓冲区或其他数据结构。您可以有以下两种消息传递技术：

+   **同步**：在这种情况下，发送消息的类会等待接收者处理其消息

+   **异步**：在这种情况下，发送消息的类不等待处理其消息的接收者。

在这一部分，您将实现一个应用程序，用于对由四个子系统组成的文档进行聚类，这些子系统之间进行通信和同步以对文档进行聚类。

# 一个文档聚类应用的示例

该应用程序将读取一组文档，并使用 k-means 聚类算法对其进行组织。为了实现这一点，我们将使用四个组件：

+   **Reader 系统**：该系统将读取所有文档，并将每个文档转换为`String`对象列表。

+   **Indexer 系统**：该系统将处理文档并将其转换为单词列表。同时，它将生成包含所有出现在文档中的单词的全局词汇表。

+   **Mapper 系统**：该系统将把每个单词列表转换为数学表示，使用向量空间模型。每个项目的值将是**Tf-Idf**（术语频率-逆文档频率）度量。

+   **聚类系统**：该系统将使用 k-means 聚类算法对文档进行聚类。

所有这些系统都是并发的，并使用自己的任务来实现它们的功能。让我们看看如何实现这个例子。

## k-means 聚类的四个系统

让我们看看如何实现 Reader、Indexer、Mapper 和 Clustering 系统。

### Reader 系统

我们已经在`DocumentReader`类中实现了这个系统。这个类实现了`Runnable`接口，并且内部使用了三个属性：

+   一个`ConcurrentLinkedDeque`类的`String`对象，其中包含您需要处理的文件的所有名称

+   一个`ConcurrentLinkedQueue`类的`TextFile`对象，用于存储文档

+   一个`CountDownLatch`对象，用于控制任务执行的结束

类的构造函数初始化这些属性（三个属性由构造函数作为参数接收），这里给出的`run()`方法实现了所有功能：

```java
        String route;
        System.out.println(Thread.currentThread().getName()+": Reader start");

        while ((route = files.pollFirst()) != null) {
            Path file = Paths.get(route);

            TextFile textFile;
            try {
                textFile = new TextFile(file);
                buffer.offer(textFile);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        System.out.println(Thread.currentThread().getName()+": Reader end: "+buffer.size());
        readersCounter.countDown();
    }
}
```

首先，我们读取所有文件的内容。对于每个文件，我们创建一个`TextFile`类的对象。这个类包含文本文件的名称和内容。它有一个构造函数，接收一个包含文件路径的`Path`对象。最后，我们在控制台中写入一条消息，并使用`CountDownLatch`对象的`countDown()`方法来指示该任务的完成。

这是`TextFile`类的代码。在内部，它有两个属性来存储文件名和其内容。它使用`Files`类的`readAllLines()`方法将文件内容转换为`List<String>`数据结构：

```java
public class TextFile {

    private String fileName;
    private List<String> content;

    public TextFile(String fileName, List<String> content) {
        this.fileName = fileName;
        this.content = content;
    }

    public TextFile(Path path) throws IOException {
        this(path.getFileName().toString(), Files.readAllLines(path));
    }

    public String getFileName() {
        return fileName;
    }

    public List<String> getContent() {
        return content;
    }
}
```

### Indexer 系统

这个系统是在`Indexer`类中实现的，该类还实现了`Runnable`接口。在这种情况下，我们使用五个内部属性，如下所示：

+   一个`ConcurrentLinkedQueue`，其中包含所有文档内容的`TextFile`

+   一个`ConcurrentLinkedDeque`，其中包含形成每个文档的单词列表的`Document`对象

+   一个`CountDownLatch`对象，用于控制`Reader`系统的完成

+   一个`CountDownLatch`对象，用于指示该系统任务的完成

+   一个`Vocabulary`对象，用于存储构成文档集合的所有单词

类的构造函数初始化了这些属性（接收所有这些属性作为参数）：

```java
public class Indexer implements Runnable {

    private ConcurrentLinkedQueue<TextFile> buffer;
    private ConcurrentLinkedDeque<Document> documents;
    private CountDownLatch readersCounter;
    private CountDownLatch indexersCounter;
    private Vocabulary voc;
```

`run()`方法实现了所有功能，如下所示：

```java
    @Override
    public void run() {
        System.out.println(Thread.currentThread().getName()+": Indexer start");
        do {
            TextFile textFile= buffer.poll();
            if (textFile!=null) {
                Document document= parseDoc(textFile);
```

首先，它从队列中获取`TextFile`，如果不是`null`，则使用`parseDoc()`方法将其转换为`Document`对象。然后，它处理文档的所有单词，将它们存储在全局词汇表对象中，并将文档存储在文档列表中，如下面的代码所示：

```java
                document.getVoc().values()
                    .forEach(voc::addWord);
                documents.offer(document);
            }
        } while ((readersCounter.getCount()>0) || (!buffer.isEmpty()));
```

```java
countDown() method of the CountDownLatch object to indicate that this task has finished its execution:
```

```java
        indexersCounter.countDown();
        System.out.println(Thread.currentThread().getName()+": Indexer end");
    }
```

`parseDoc()`方法接收包含文档内容的`List<String>`，并返回一个`Document`对象。它创建一个`Document`对象，使用`forEach()`方法处理所有行，如下所示：

```java
    private Document parseDoc(TextFile textFile) {
        Document doc=new Document();

        doc.setName(textFile.getFileName());
        textFile.getContent().forEach(line -> parseLine(line,doc));

        return doc;
    }
```

`parseLine()`方法将行分割成单词，并将它们存储在`doc`对象中，如下所示：

```java
    private static void parseLine(String inputLine, Document doc) {

        // Clean string
        String line=new String(inputLine);
        line = Normalizer.normalize(line, Normalizer.Form.NFKD);
        line = line.replaceAll("[^\\p{ASCII}]", "");
        line = line.toLowerCase();

        // Tokenizer
        StringTokenizer tokenizer = new StringTokenizer(line,
                " ,.;:-{}[]¿?¡!|\\=*+/()\"@\t~#<>", false);
        while (tokenizer.hasMoreTokens()) {
            doc.addWord(tokenizer.nextToken());
        }
    }
```

您可以在之前呈现的代码中包含一个优化，即预编译`replaceAll()`方法中使用的正则表达式：

```java
static final Pattern NON_ASCII = Pattern.compile("[^\\p{ASCII}]");
    line = NON_ASCII.matcher(line).replaceAll("");
    }
```

### 映射器系统

该系统是在`Mapper`类中实现的，该类还实现了`Runnable`接口。在内部，它使用以下两个属性：

+   一个包含所有文档信息的`ConcurrentLinkedDeque`对象

+   包含整个集合中所有单词的`Vocabulary`对象

其代码如下：

```java
public class Mapper implements Runnable {

    private ConcurrentLinkedDeque<Document> documents;
    private Vocabulary voc;
```

类的构造函数初始化了这些属性，`run()`方法实现了该系统的功能：

```java
    public void run() {
        Document doc;
        int counter=0;
        System.out.println(Thread.currentThread().getName()+": Mapper start");
        while ((doc=documents.pollFirst())!=null) {
            counter++;
```

首先，它从`Deque`对象中使用`pollFirst()`方法获取一个文档。然后，它处理文档中的所有单词，计算`tfxidf`度量，并创建一个新的`Attribute`对象来存储这些值。这些属性被存储在一个列表中。

```java
            List<Attribute> attributes=new ArrayList<>();
            doc.getVoc().forEach((key, item)-> {
                Word word=voc.getWord(key);
                item.setTfxidf(item.getTfxidf()/word.getDf());
                Attribute attribute=new Attribute();
                attribute.setIndex(word.getIndex());
                attribute.setValue(item.getTfxidf());
                attributes.add(attribute);
            });
```

最后，我们将列表转换为一个`Attribute`对象数组，并将该数组存储在`Document`对象中：

```java
            Collections.sort(attributes);
            doc.setExample(attributes);
        }
        System.out.println(Thread.currentThread().getName()+": Mapper end: "+counter);

    }
```

### 聚类系统

该系统实现了 k 均值聚类算法。您可以使用第五章中介绍的元素，*将任务分为阶段运行-Phaser 类*，来实现该系统。该实现具有以下元素：

+   **DistanceMeasurer 类**：这个类计算包含文档信息的`Attribute`对象数组与簇的质心之间的欧氏距离

+   **DocumentCluster 类**：这个类存储了关于一个簇的信息：质心和该簇的文档

+   **AssigmentTask 类**：这个类扩展了 Fork/Join 框架的`RecursiveAction`类，并执行算法的分配任务，其中我们计算每个文档与所有簇之间的距离，以决定每个文档的簇

+   **UpdateTask 类**：这个类扩展了 Fork/Join 框架的`RecursiveAction`类，并执行算法的更新任务，重新计算每个簇的质心，作为存储在其中的文档的平均值

+   **ConcurrentKMeans 类**：这个类有一个静态方法`calculate()`，执行聚类算法并返回一个包含所有生成的簇的`DocumentCluster`对象数组

我们只添加了一个新类，`ClusterTask`类，它实现了`Runnable`接口，并将调用`ConcurrentKMeans`类的`calculate()`方法。在内部，它使用两个属性如下：

+   一个包含所有文档信息的`Document`对象数组

+   包含集合中所有单词的`Vocabulary`对象

构造函数初始化了这些属性，`run()`方法实现了任务的逻辑。我们调用`ConcurrentKMeans`类的`calculate()`方法，传递五个参数如下：

+   包含所有文档信息的`Document`对象数组。

+   包含集合中所有单词的`Vocabulary`对象。

+   我们想要生成的簇的数量。在这种情况下，我们使用`10`作为簇的数量。

+   用于初始化簇质心的种子。在这种情况下，我们使用`991`作为种子。

+   在 Fork/Join 框架中用于将任务分割成子任务的参考大小。在这种情况下，我们使用`10`作为最小大小。

这是该类的代码：

```java
    @Override
    public void run() {
        System.out.println("Documents to cluster: "+documents.length);
        ConcurrentKMeans.calculate(documents, 10, voc.getVocabulary().size(), 991, 10);
    }
```

## 文档聚类应用程序的主类

一旦我们实现了应用程序中使用的所有元素，我们必须实现系统的`main()`方法。在这种情况下，这个方法非常关键，因为它负责启动系统并创建需要同步它们的元素。`Reader`和`Indexer`系统将同时执行。它们将使用一个缓冲区来共享信息。当读取器读取一个文档时，它将在缓冲区中写入`String`对象的列表，然后继续处理下一个文档。它不会等待处理该`List`的任务。这是**异步消息传递**的一个例子。`Indexer`系统将从缓冲区中取出文档，处理它们，并生成包含文档所有单词的`Vocabulary`对象。`Indexer`系统执行的所有任务共享`Vocabulary`类的同一个实例。这是**共享内存**的一个例子。

主类将使用`CountDownLatch`对象的`await()`方法以同步的方式等待`Reader`和`Indexer`系统的完成。该方法会阻塞调用线程的执行，直到其内部计数器达到 0。

一旦两个系统都完成了它们的执行，`Mapper`系统将使用`Vocabulary`对象和`Document`信息来获取每个文档的向量空间模型表示。当`Mapper`完成执行后，`Clustering`系统将对所有文档进行聚类。我们使用`CompletableFuture`类来同步`Mapper`系统的结束和`Clustering`系统的开始。这是两个系统之间异步通信的另一个例子。

我们已经在`ClusteringDocs`类中实现了主类。

首先，我们创建一个`ThreadPoolExecutor`对象，并使用`readFileNames()`方法获取包含文档的文件的`ConcurrentLinkedDeque`：

```java
public class ClusteringDocs {

    private static int NUM_READERS = 2;
    private static int NUM_WRITERS = 4;

    public static void main(String[] args) throws InterruptedException {

        ThreadPoolExecutor executor=(ThreadPoolExecutor) Executors.newCachedThreadPool();
        ConcurrentLinkedDeque<String> files=readFiles("data");
        System.out.println(new Date()+":"+files.size()+" files read.");
```

然后，我们创建文档的缓冲区`ConcurrentLinkedDeque`，用于存储`Document`对象、`Vocabulary`对象和两个`CountDownLatch`对象——一个用于控制`Reader`系统任务的结束，另一个用于控制`Indexer`系统任务的结束。我们有以下代码：

```java
        ConcurrentLinkedQueue<List<String>> buffer=new ConcurrentLinkedQueue<>();
        CountDownLatch readersCounter=new CountDownLatch(2);
        ConcurrentLinkedDeque<Document> documents=new ConcurrentLinkedDeque<>();
        CountDownLatch indexersCounter=new CountDownLatch(4);
        Vocabulary voc=new Vocabulary();
```

然后，我们启动两个任务来执行`DocumentReader`类的`Reader`系统，另外四个任务来执行`Indexer`类的`Indexer`系统。所有这些任务都在我们之前创建的`Executor`对象中执行：

```java
        System.out.println(new Date()+":"+"Launching the tasks");
        for (int i=0; i<NUM_READERS; i++) {
            DocumentReader reader=new DocumentReader(files,buffer,readersCounter);
            executor.execute(reader);

        }

        for (int i=0; i<NUM_WRITERS; i++) {
            Indexer indexer=new Indexer(documents, buffer, readersCounter, indexersCounter, voc);
            executor.execute(indexer);
        }
```

然后，`main()`方法等待这些任务的完成；首先是`DocumentReader`任务，然后是`Indexer`任务，如下所示：

```java
        System.out.println(new Date()+":"+"Waiting for the readers");
        readersCounter.await();

        System.out.println(new Date()+":"+"Waiting for the indexers");
        indexersCounter.await();
```

然后，我们将`ConcurrentLinkedDeque`类的`Document`对象转换为数组：

```java
        Document[] documentsArray=new Document[documents.size()];
        documentsArray=documents.toArray(documentsArray);
```

我们启动`Indexer`系统，使用`CompletableFuture`类的`runAsync()`方法执行`Mapper`类的四个任务，如下所示：

```java
        System.out.println(new Date()+":"+"Launching the mappers");
        CompletableFuture<Void>[] completables = Stream.generate(() -> new Mapper(documents, voc))
                .limit(4)
                .map(CompletableFuture::runAsync)
                .toArray(CompletableFuture[]::new);
```

然后，我们启动`Clustering`系统，启动`ClusterTask`类的一个任务（请记住，这些任务将启动其他任务来执行算法）。`main()`方法使用`CompletableFuture`类的`allOf()`方法等待`Mapper`任务的完成，然后使用`thenRunAsync()`方法在`Mapper`系统完成后启动聚类算法：

```java
        System.out.println(new Date()+":"+"Launching the cluster calculation");

        CompletableFuture<Void> completableMappers= CompletableFuture.allOf(completables);
        ClusterTask clusterTask=new ClusterTask(documentsArray, voc);
        CompletableFuture<Void> completableClustering= completableMappers.thenRunAsync(clusterTask);
```

最后，我们使用`get()`方法等待`Clustering`系统的完成，并按以下方式结束程序的执行：

```java
        System.out.println(new Date()+":"+"Wating for the cluster calculation");
        try {
            completableClustering.get();
        } catch (InterruptedException | ExecutionException e) {
            e.printStackTrace();
        }

        System.out.println(new Date()+":"+"Execution finished");
        executor.shutdown();
    }
```

`readFileNames()`方法接收一个字符串作为参数，该字符串必须是存储文档集合的目录的路径，并生成一个包含该目录中文件名称的`ConcurrentLinkedDeque`类的`String`对象。

## 测试我们的文档聚类应用程序

为了测试这个应用程序，我们使用了来自维基百科的有关电影的 100,673 个文档中的 10,052 个文档的子集作为文档集。在下图中，您可以看到执行的第一部分的结果-从执行开始到索引器执行结束为止：

![测试我们的文档聚类应用程序](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-cncr-prog-java8/img/00033.jpeg)

以下图片显示了示例执行的其余部分：

![测试我们的文档聚类应用程序](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-cncr-prog-java8/img/00034.jpeg)

您可以看到任务如何在本章前面同步。首先，`Reader`和`Indexer`任务以并发方式执行。当它们完成时，映射器对数据进行转换，最后，聚类算法组织示例。

# 使用并发编程实现替代方案

本书中大多数示例都可以使用 Java 并发 API 的其他组件来实现。在本节中，我们将描述如何实现其中一些替代方案。

## k 最近邻算法

您已经在第二章中使用执行器实现了 k 最近邻算法，*管理大量线程-执行器*，这是一种用于监督分类的简单机器学习算法。您有一组先前分类的示例的训练集。要获得新示例的类别，您需要计算此示例与示例的训练集之间的距离。最近示例中的大多数类别是为示例选择的类别。您还可以使用并发 API 的以下组件之一实现此算法：

+   **线程**：您可以使用`Thread`对象实现此示例。您必须使用普通线程执行执行器中执行的任务。每个线程将计算示例与训练集子集之间的距离，并将该距离保存在所有线程之间共享的数据结构中。当所有线程都完成时，您可以使用距离对数据结构进行排序并计算示例的类别。

+   **Fork/Join 框架**：与先前的解决方案一样，每个任务将计算示例与训练集子集之间的距离。在这种情况下，您定义了这些子集中示例的最大数量。如果一个任务需要处理更多的示例，您将该任务分成两个子任务。在加入了两个任务之后，您必须生成一个包含两个子任务结果的唯一数据结构。最后，您将获得一个包含所有距离的数据结构，可以对其进行排序以获得示例的类别。

+   **流**：您可以从训练数据创建一个流，并将每个训练示例映射到一个包含要分类的示例与该示例之间距离的结构中。然后，您对该结构进行排序，使用`limit()`获取最接近的示例，并计算最终的结果类别。

## 构建文档集的倒排索引

我们已经在第四章中使用执行器实现了此示例，*从任务中获取数据-Callable 和 Future 接口*。倒排索引是信息检索领域中用于加速信息搜索的数据结构。它存储了文档集中出现的单词，对于每个单词，存储了它们出现的文档。当您搜索信息时，您无需处理文档。您查看倒排索引以提取包含您插入的单词的文档，并构建结果列表。您还可以使用并发 API 的以下组件之一实现此算法：

+   **线程**：每个线程将处理一部分文档。这个过程包括获取文档的词汇并更新一个共同的数据结构与全局索引。当所有线程都完成执行后，可以按顺序创建文件。

+   **Fork/Join 框架**：您定义任务可以处理的文档的最大数量。如果一个任务必须处理更多的文档，您将该任务分成两个子任务。每个任务的结果将是一个包含由这些任务或其子任务处理的文档的倒排索引的数据结构。在合并两个子任务后，您将从其子任务的倒排索引构造一个唯一的倒排索引。

+   **流**：您创建一个流来处理所有文件。您将每个文件映射到其词汇对象，然后将减少该词汇流以获得倒排索引。

## 单词的最佳匹配算法

您已经在第四章中实现了这个例子，*从任务中获取数据 - Callable 和 Future 接口*。这个算法的主要目标是找到与作为参数传递的字符串最相似的单词。您还可以使用并发 API 的以下组件之一来实现此算法：

+   **线程**：每个线程将计算搜索词与整个词列表的子列表之间的距离。每个线程将生成一个部分结果，这些结果将合并到所有线程之间共享的最终结果中。

+   **Fork/Join 框架**：每个任务将计算搜索词与整个词列表的子列表之间的距离。如果列表太大，必须将任务分成两个子任务。每个任务将返回部分结果。在合并两个子任务后，任务将把两个子列表整合成一个。原始任务将返回最终结果。

+   **流**：您为整个单词列表创建一个流，将每个单词与包括搜索词与该单词之间距离的数据结构进行映射，对该列表进行排序，并获得结果。

## 遗传算法

您已经在第五章中实现了这个例子，*分阶段运行任务 - Phaser 类*。**遗传算法**是一种基于自然选择原则的自适应启发式搜索算法，用于生成**优化**和**搜索问题**的良好解决方案。有不同的方法可以使用多个线程来进行遗传算法。最经典的方法是创建*岛屿*。每个线程代表一个岛屿，其中一部分种群会进化。有时，岛屿之间会发生迁移，将一些个体从一个岛屿转移到另一个岛屿。算法完成后，选择跨所有岛屿的最佳物种。这种方法大大减少了争用，因为线程很少彼此交流。

还有其他方法在许多出版物和网站上有很好的描述。例如，这份讲义集在[`cw.fel.cvut.cz/wiki/_media/courses/a0m33eoa/prednasky/08pgas-handouts.pdf`](https://cw.fel.cvut.cz/wiki/_media/courses/a0m33eoa/prednasky/08pgas-handouts.pdf)上很好地总结了这些方法。

您还可以使用并发 API 的以下组件之一来实现此算法：

+   **线程**：所有个体的种群必须是一个共享的数据结构。您可以按以下方式实现三个阶段：选择阶段以顺序方式进行；交叉阶段使用线程，其中每个线程将生成预定义数量的个体；评估阶段也使用线程。每个线程将评估预定义数量的个体。

+   执行者：您可以实现类似于之前的内容，将任务在执行者中执行，而不是独立的线程。

+   **Fork/Join 框架**：主要思想是相同的，但在这种情况下，您的任务将被分割，直到它们处理了预定义数量的个体。在这种情况下，加入部分不起作用，因为任务的结果将存储在共同的数据结构中。

## 关键词提取算法

您已经在第五章中实现了这个例子，*分阶段运行任务-Phaser 类*。我们使用这种算法来提取描述文档的一小组词语。我们尝试使用 Tf-Idf 等度量标准找到最具信息量的词语。您还可以使用并发 API 的以下组件来实现此示例：

+   **线程**：您需要两种类型的线程。第一组线程将处理文档集以获得每个词的文档频率。您需要一个共享的数据结构来存储集合的词汇表。第二组线程将再次处理文档，以获得每个文档的关键词，并更新一个维护整个关键词列表的结构。

+   **Fork/Join 框架**：主要思想与以前的版本类似。您需要两种类型的任务。第一个任务是获得文档集的全局词汇表。每个任务将计算子集文档的词汇表。如果子集太大，任务将执行两个子任务。在加入子任务后，它将将获得的两个词汇表合并为一个。第二组任务将计算关键词列表。每个任务将计算子集文档的关键词列表。如果子集太大，它将执行两个子任务。当这些任务完成时，父任务将使用子任务返回的列表生成关键词列表。

+   **流**：您创建一个流来处理所有文档。您将每个文档与包含文档词汇表的对象进行映射，并将其减少以获得全局词汇表。您生成另一个流来再次处理所有文档，将每个文档与包含其关键词的对象进行映射，并将其减少以生成最终的关键词列表。

## 一个 k 均值聚类算法

您已经在第六章中实现了这个算法，*优化分治解决方案-Fork/Join 框架*。这个算法将一组元素分类到先前定义的一定数量的集群中。您对元素的类别没有任何信息，因此这是一种无监督学习算法，它试图找到相似的项目。您还可以使用并发 API 的以下组件来实现此示例：

+   **线程**：您将有两种类型的线程。第一种将为示例分配一个集群。每个线程将处理示例集的子集。第二种线程将更新集群的质心。集群和示例必须是所有线程共享的数据结构。

+   **执行者**：您可以实现之前提出的想法，但是在执行任务时使用执行者，而不是使用独立的线程。

## 一个过滤数据算法

您已经在第六章中实现了这个算法，*优化分治解决方案-Fork/Join 框架*。这个算法的主要目标是从一个非常大的对象集中选择满足某些条件的对象。您还可以使用并发 API 的以下组件来实现此示例：

+   **线程**：每个线程将处理对象的一个子集。如果您正在寻找一个结果，当找到一个线程时，它必须暂停其余的执行。如果您正在寻找一个元素列表，那个列表必须是一个共享的数据结构。

+   **执行器**：与之前相同，但在执行器中执行任务，而不是使用独立线程。

+   **流**：您可以使用`Stream`类的`filter()`方法来对对象进行搜索。然后，您可以将这些结果减少到您需要的格式。

## 搜索倒排索引

您已经在第七章中实现了这个算法，*使用并行流处理大型数据集-映射和减少模型*。在之前的例子中，我们讨论了如何实现创建倒排索引以加速信息搜索的算法。这是执行信息搜索的算法。您还可以使用并发 API 的以下组件来实现此示例：

+   **线程**：这是一个共同数据结构中的结果列表。每个线程处理倒排索引的一部分。每个结果都按顺序插入以生成一个排序的数据结构。如果您获得了足够好的结果列表，您可以返回该列表并取消任务的执行。

+   **执行器**：这与前一个类似，但在执行器中执行并发任务。

+   **Fork/Join framework**：这与前一个类似，但每个任务将倒排索引的部分划分为更小的块，直到它们足够小。

## 数字摘要算法

您已经在第七章中实现了这个例子，*使用并行流处理大型数据集-映射和减少模型*。这种类型的算法希望获得关于非常大的数据集的统计信息。您还可以使用并发 API 的以下组件来实现此示例：

+   **线程**：我们将有一个对象来存储线程生成的数据。每个线程将处理数据的一个子集，并将该数据的结果存储在共同的对象中。也许，我们将不得不对该对象进行后处理，以生成最终结果。

+   **执行器**：这与前一个类似，但在执行器中执行并发任务。

+   **Fork/Join framework**：这与前一个类似，但每个任务将倒排索引的部分划分为更小的块，直到它们足够小。

## 没有索引的搜索算法

您已经在第八章中实现了这个例子，*使用并行流处理大型数据集-映射和收集模型*。当您没有倒排索引来加速搜索时，该算法会获取满足某些条件的对象。在这些情况下，您必须在进行搜索时处理所有元素。您还可以使用并发 API 的以下组件来实现此示例：

+   **线程**：每个线程将处理一个对象（在我们的案例中是文件）的子集，以获得结果列表。结果列表将是一个共享的数据结构。

+   **执行器**：这与前一个类似，但并发任务将在执行器中执行。

+   **Fork/Join framework**：这与前一个类似，但任务将倒排索引的部分划分为更小的块，直到它们足够小。

## 使用映射和收集模型的推荐系统

您已经在第八章中实现了这个例子，*使用并行流处理大型数据集 - 映射和收集模型*。**推荐系统**根据客户购买/使用的产品/服务以及购买/使用与他购买/使用相同服务的用户购买/使用的产品/服务向客户推荐产品或服务。您还可以使用并发 API 的 Phaser 组件来实现这个例子。该算法有三个阶段：

+   **第一阶段**：我们需要将带有评论的产品列表转换为购买者与他们购买的产品的列表。每个任务将处理产品的一个子集，并且购买者列表将是一个共享的数据结构。

+   **第二阶段**：我们需要获得购买了与参考用户相同产品的用户列表。每个任务将处理用户购买的产品项目，并将购买了该产品的用户添加到一个共同的用户集合中。

+   **第三阶段**：我们获得了推荐的产品。每个任务将处理前一个列表中的用户，并将他购买的产品添加到一个共同的数据结构中，这将生成最终的推荐产品列表。

# 总结

在本书中，您实现了许多真实世界的例子。其中一些例子可以作为更大系统的一部分。这些更大的系统通常有不同的并发部分，它们必须共享信息并在它们之间进行同步。为了进行同步，我们可以使用三种机制：共享内存，当两个或更多任务共享一个对象或数据结构时；异步消息传递，当一个任务向另一个任务发送消息并且不等待其处理时；以及同步消息传递，当一个任务向另一个任务发送消息并等待其处理时。

在本章中，我们实现了一个用于聚类文档的应用程序，由四个子系统组成。我们使用了早期介绍的机制来在这四个子系统之间同步和共享信息。

我们还修改了书中提出的一些例子，讨论了它们的其他实现方法。

在下一章中，您将学习如何获取并发 API 组件的调试信息，以及如何监视和测试并发应用程序。


# 第十一章：测试和监控并发应用程序

**软件测试**是每个开发过程的关键任务。每个应用程序都必须满足最终用户的要求，测试阶段是证明这一点的地方。它必须在可接受的时间内以指定的格式生成有效的结果。测试阶段的主要目标是尽可能多地检测软件中的错误，以便纠正错误并提高产品的整体质量。

传统上，在瀑布模型中，测试阶段在开发阶段非常先进时开始，但如今越来越多的开发团队正在使用敏捷方法，其中测试阶段集成到开发阶段中。主要目标是尽快测试软件，以便在流程早期检测错误。

在 Java 中，有许多工具，如**JUnit**或**TestNG**，可以自动执行测试。其他工具，如**JMeter**，允许您测试有多少用户可以同时执行您的应用程序，还有其他工具，如**Selenium**，您可以用来在 Web 应用程序中进行集成测试。

测试阶段在并发应用程序中更为关键和更为困难。您可以同时运行两个或更多个线程，但无法控制它们的执行顺序。您可以对应用程序进行大量测试，但无法保证不存在执行不同线程的顺序引发竞争条件或死锁的情况。这种情况也导致了错误的再现困难。您可能会发现只在特定情况下发生的错误，因此很难找到其真正的原因。在本章中，我们将涵盖以下主题，以帮助您测试并发应用程序：

+   监控并发对象

+   监控并发应用程序

+   测试并发应用程序

# 监控并发对象

Java 并发 API 提供的大多数并发对象都包括了用于了解它们状态的方法。此状态可以包括正在执行的线程数、正在等待条件的线程数、已执行的任务数等。在本节中，您将学习可以使用的最重要的方法以及您可以从中获取的信息。这些信息对于检测错误的原因非常有用，特别是如果错误只在非常罕见的情况下发生。

## 监控线程

线程是 Java 并发 API 中最基本的元素。它允许您实现原始任务。您可以决定要执行的代码（扩展`Thread`类或实现`Runnable`接口）、何时开始执行以及如何与应用程序的其他任务同步。`Thread`类提供了一些方法来获取有关线程的信息。以下是最有用的方法：

+   `getId()`: 此方法返回线程的标识符。它是一个`long`正数，且是唯一的。

+   `getName()`: 此方法返回线程的名称。默认情况下，它的格式为`Thread-xxx`，但可以在构造函数中或使用`setName()`方法进行修改。

+   `getPriority()`: 此方法返回线程的优先级。默认情况下，所有线程的优先级都为五，但您可以使用`setPriority()`方法进行更改。具有较高优先级的线程可能优先于具有较低优先级的线程。

+   `getState()`: 此方法返回线程的状态。它返回一个`Enum` `Thread.State`的值，可以取值：`NEW`、`RUNNABLE`、`BLOCKED`、`WAITING`、`TIMED_WAITING`和`TERMINATED`。您可以查看 API 文档以了解每个状态的真正含义。

+   `getStackTrace()`: 此方法以`StackTraceElement`对象的数组形式返回此线程的调用堆栈。您可以打印此数组以了解线程所做的调用。

例如，您可以使用类似以下的代码片段来获取线程的所有相关信息：

```java
    System.out.println("**********************");
    System.out.println("Id: " + thread.getId());
    System.out.println("Name: " + thread.getName());
    System.out.println("Priority: " + thread.getPriority());
    System.out.println("Status: " + thread.getState());
    System.out.println("Stack Trace");
    for(StackTraceElement ste : thread.getStackTrace()) {
      System.out.println(ste);
    }

    System.out.println("**********************\n");
```

使用此代码块，您将获得以下输出：

![监视线程](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-cncr-prog-java8/img/00035.jpeg)

## 监视锁

**锁**是 Java 并发 API 提供的基本同步元素之一。它在`Lock`接口和`ReentrantLock`类中定义。基本上，锁允许您在代码中定义临界区，但`Lock`机制比其他机制更灵活，如同步关键字（例如，您可以有不同的锁来进行读写操作或具有非线性的临界区）。`ReentrantLock`类具有一些方法，允许您了解`Lock`对象的状态：

+   `getOwner()`: 此方法返回一个`Thread`对象，其中包含当前拥有锁的线程，也就是执行临界区的线程。

+   `hasQueuedThreads()`: 此方法返回一个`boolean`值，指示是否有线程在等待获取此锁。

+   `getQueueLength()`: 此方法返回一个`int`值，其中包含等待获取此锁的线程数。

+   `getQueuedThreads()`: 此方法返回一个`Collection<Thread>`对象，其中包含等待获取此锁的`Thread`对象。

+   `isFair()`: 此方法返回一个`boolean`值，指示公平属性的状态。此属性的值用于确定下一个获取锁的线程。您可以查看 Java API 信息，以获取有关此功能的详细描述。

+   `isLocked()`: 此方法返回一个`boolean`值，指示此锁是否被线程拥有。

+   `getHoldCount()`: 此方法返回一个`int`值，其中包含此线程获取锁的次数。如果此线程未持有锁，则返回值为零。否则，它将返回当前线程中调用`lock()`方法的次数，而未调用匹配的`unlock()`方法。

`getOwner()`和`getQueuedThreads()`方法受到保护，因此您无法直接访问它们。为解决此问题，您可以实现自己的`Lock`类，并实现提供该信息的方法。

例如，您可以实现一个名为`MyLock`的类，如下所示：

```java
public class MyLock extends ReentrantLock {

    private static final long serialVersionUID = 8025713657321635686L;

    public String getOwnerName() {
        if (this.getOwner() == null) {
            return "None";
        }
        return this.getOwner().getName();
    }

    public Collection<Thread> getThreads() {
        return this.getQueuedThreads();
    }
}
```

因此，您可以使用类似以下的代码片段来获取有关锁的所有相关信息：

```java
    System.out.println("************************\n");
    System.out.println("Owner : " + lock.getOwnerName());
    System.out.println("Queued Threads: " + lock.hasQueuedThreads());
    if (lock.hasQueuedThreads()) {
        System.out.println("Queue Length: " + lock.getQueueLength());
        System.out.println("Queued Threads: ");
        Collection<Thread> lockedThreads = lock.getThreads();
        for (Thread lockedThread : lockedThreads) {
            System.out.println(lockedThread.getName());
        }
    }
    System.out.println("Fairness: " + lock.isFair());
    System.out.println("Locked: " + lock.isLocked());
    System.out.println("Holds: "+lock.getHoldCount());
    System.out.println("************************\n");
```

使用此代码块，您将获得类似以下的输出：

![监视锁](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-cncr-prog-java8/img/00036.jpeg)

## 监视执行器

**执行器框架**是一种机制，允许您执行并发任务，而无需担心线程的创建和管理。您可以将任务发送到执行器。它具有一个内部线程池，用于执行任务。执行器还提供了一种机制来控制任务消耗的资源，以便您不会过载系统。执行器框架提供了`Executor`和`ExecutorService`接口以及一些实现这些接口的类。实现它们的最基本的类是`ThreadPoolExecutor`类。它提供了一些方法，允许您了解执行器的状态：

+   `getActiveCount()`: 此方法返回正在执行任务的执行器线程数。

+   `getCompletedTaskCount()`: 此方法返回已由执行器执行并已完成执行的任务数。

+   `getCorePoolSize()`: 此方法返回核心线程数。此数字确定池中的最小线程数。即使执行器中没有运行任务，池中的线程数也不会少于此方法返回的数字。

+   `getLargestPoolSize()`: 此方法返回执行器池中同时存在的最大线程数。

+   `getMaximumPoolSize()`: 此方法返回池中可以同时存在的最大线程数。

+   `getPoolSize()`: 此方法返回池中当前线程的数量。

+   `getTaskCount()`: 此方法返回已发送到执行程序的任务数量，包括等待、运行和已完成的任务。

+   `isTerminated()`: 如果已调用`shutdown()`或`shutdownNow()`方法并且`Executor`已完成所有待处理任务的执行，则此方法返回`true`。否则返回`false`。

+   `isTerminating()`: 如果已调用`shutdown()`或`shutdownNow()`方法但执行程序仍在执行任务，则此方法返回`true`。

您可以使用类似以下代码片段来获取`ThreadPoolExecutor`的相关信息：

```java
    System.out.println ("*******************************************");
    System.out.println("Active Count: "+executor.getActiveCount());
    System.out.println("Completed Task Count: "+executor.getCompletedTaskCount());
    System.out.println("Core Pool Size: "+executor.getCorePoolSize());
    System.out.println("Largest Pool Size: "+executor.getLargestPoolSize());
    System.out.println("Maximum Pool Size: "+executor.getMaximumPoolSize());
    System.out.println("Pool Size: "+executor.getPoolSize());
    System.out.println("Task Count: "+executor.getTaskCount());
    System.out.println("Terminated: "+executor.isTerminated());
    System.out.println("Is Terminating: "+executor.isTerminating());
    System.out.println ("*******************************************");
```

使用此代码块，您将获得类似于以下内容的输出：

![监控执行程序](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-cncr-prog-java8/img/00037.jpeg)

## 监控 Fork/Join 框架

**Fork/Join 框架**提供了一种特殊的执行程序，用于可以使用分而治之技术实现的算法。它基于工作窃取算法。您创建一个必须处理整个问题的初始任务。此任务创建其他处理问题较小部分的子任务，并等待其完成。每个任务将要处理的子问题的大小与预定义大小进行比较。如果大小小于预定义大小，则直接解决问题。否则，将问题分割为其他子任务，并等待它们返回的结果。工作窃取算法利用正在执行等待其子任务结果的线程来执行其他任务。`ForkJoinPool`类提供了允许您获取其状态的方法：

+   `getParallelism()`: 此方法返回为池设定的期望并行级别。

+   `getPoolSize()`: 此方法返回池中线程的数量。

+   `getActiveThreadCount()`: 此方法返回当前正在执行任务的池中线程数量。

+   `getRunningThreadCount()`: 此方法返回不在等待其子任务完成的线程数量。

+   `getQueuedSubmissionCount()`: 此方法返回已提交到池中但尚未开始执行的任务数量。

+   `getQueuedTaskCount()`: 此方法返回此池的工作窃取队列中的任务数量。

+   `hasQueuedSubmissions()`: 如果已提交到池中但尚未开始执行的任务，则此方法返回`true`。否则返回`false`。

+   `getStealCount()`: 此方法返回 Fork/Join 池执行工作窃取算法的次数。

+   `isTerminated()`: 如果 Fork/Join 池已完成执行，则此方法返回`true`。否则返回`false`。

您可以使用类似以下代码片段来获取`ForkJoinPool`类的相关信息：

```java
    System.out.println("**********************");
    System.out.println("Parallelism: "+pool.getParallelism());
    System.out.println("Pool Size: "+pool.getPoolSize());
    System.out.println("Active Thread Count: "+pool.getActiveThreadCount());
    System.out.println("Running Thread Count: "+pool.getRunningThreadCount());
    System.out.println("Queued Submission: "+pool.getQueuedSubmissionCount());
    System.out.println("Queued Tasks: "+pool.getQueuedTaskCount());
    System.out.println("Queued Submissions: "+pool.hasQueuedSubmissions());
    System.out.println("Steal Count: "+pool.getStealCount());
    System.out.println("Terminated : "+pool.isTerminated());
    System.out.println("**********************");
```

其中`pool`是一个`ForkJoinPool`对象（例如`ForkJoinPool.commonPool()`）。使用此代码块，您将获得类似于以下内容的输出：

![监控 Fork/Join 框架](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-cncr-prog-java8/img/00038.jpeg)

## 监控 Phaser

**Phaser**是一种同步机制，允许您执行可以分为阶段的任务。此类还包括一些方法来获取 Phaser 的状态：

+   `getArrivedParties()`: 此方法返回已完成当前阶段的注册方数量。

+   `getUnarrivedParties()`: 此方法返回尚未完成当前阶段的注册方数量。

+   `getPhase()`: 此方法返回当前阶段的编号。第一个阶段的编号为`0`。

+   `getRegisteredParties()`: 此方法返回 Phaser 中注册方的数量。

+   `isTerminated()`: 此方法返回一个`boolean`值，指示 Phaser 是否已完成执行。

您可以使用类似以下代码片段来获取 Phaser 的相关信息：

```java
    System.out.println ("*******************************************");
    System.out.println("Arrived Parties: "+phaser.getArrivedParties());
    System.out.println("Unarrived Parties: "+phaser.getUnarrivedParties());
    System.out.println("Phase: "+phaser.getPhase());
    System.out.println("Registered Parties: "+phaser.getRegisteredParties());
    System.out.println("Terminated: "+phaser.isTerminated());
    System.out.println ("*******************************************");
```

使用此代码块，您将获得类似于此的输出：

![监视 Phaser](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-cncr-prog-java8/img/00039.jpeg)

## 监视流

流机制是 Java 8 引入的最重要的新功能之一。它允许您以并发方式处理大量数据集，以简单的方式转换数据并实现映射和减少编程模型。这个类没有提供任何方法（除了返回流是否并行的`isParallel()`方法）来了解流的状态，但包括一个名为`peek()`的方法，您可以将其包含在方法管道中，以记录有关在流中执行的操作或转换的日志信息。

例如，此代码计算前 999 个数字的平方的平均值：

```java
double result=IntStream.range(0,1000)
    .parallel()
    .peek(n -> System.out.println (Thread.currentThread().getName()+": Number "+n))
    .map(n -> n*n)
    .peek(n -> System.out.println (Thread.currentThread().getName()+": Transformer "+n))
    .average()
    .getAsDouble();
```

第一个`peek()`方法写入流正在处理的数字，第二个写入这些数字的平方。如果您执行此代码，由于以并发方式执行流，您将获得类似于此的输出：

![监视流](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-cncr-prog-java8/img/00040.jpeg)

# 监视并发应用程序

当您实现 Java 应用程序时，通常会使用诸如 Eclipse 或 NetBeans 之类的 IDE 来创建项目并编写源代码。但是**JDK**（**Java 开发工具包**的缩写）包括可以用于编译、执行或生成 Javadoc 文档的工具。其中之一是**Java VisualVM**，这是一个图形工具，可以显示有关在 JVM 中执行的应用程序的信息。您可以在 JDK 安装的 bin 目录中找到它（`jvisualvm.exe`）。您还可以安装 Eclipse 的插件（Eclipse VisualVM 启动器）以集成其功能。

如果您执行它，您将看到一个类似于这样的窗口：

![监视并发应用程序](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-cncr-prog-java8/img/00041.jpeg)

在屏幕的左侧，您可以看到**应用程序**选项卡，其中将显示当前用户在系统中正在运行的所有 Java 应用程序。如果您在其中一个应用程序上双击，您将看到五个选项卡：

+   **概述**：此选项卡显示有关应用程序的一般信息。

+   **监视器**：此选项卡显示有关应用程序使用的 CPU、内存、类和线程的图形信息。

+   **线程**：此选项卡显示应用程序线程随时间的演变。

+   **采样器**：此选项卡显示有关应用程序内存和 CPU 利用率的信息。它类似于**分析器**选项卡，但以不同的方式获取数据。

+   **分析器**：此选项卡显示有关应用程序内存和 CPU 利用率的信息。它类似于**采样器**选项卡，但以不同的方式获取数据。

在接下来的部分，您将了解每个选项卡中可以获得的信息。您可以在[`visualvm.java.net/docindex.html`](https://visualvm.java.net/docindex.html)上查阅有关此工具的完整文档。

## 概述选项卡

如前所述，此选项卡显示有关应用程序的一般信息。此信息包括：

+   **PID**：应用程序的进程 ID。

+   **主机**：执行应用程序的计算机名称。

+   **主类**：实现`main()`方法的类的完整名称。

+   **参数**：您传递给应用程序的参数列表。

+   **JVM**：执行应用程序的 JVM 版本。

+   **Java**：您正在运行的 Java 版本。

+   **Java 主目录**：系统中 JDK 的位置。

+   **JVM 标志**：与 JVM 一起使用的标志。

+   **JVM 参数**：此选项卡显示我们（或 IDE）传递给 JVM 以执行应用程序的参数。

+   **系统属性**：此选项卡显示系统属性和属性值。您可以使用`System.getProperties()`方法获取此信息。

这是访问应用程序数据时的默认选项卡，并且外观类似于以下截图：

![概述选项卡](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-cncr-prog-java8/img/00042.jpeg)

## 监视器选项卡

正如我们之前提到的，此选项卡向您显示了有关应用程序使用的 CPU、内存、类和线程的图形信息。您可以看到这些指标随时间的演变。此选项卡的外观类似于这样：

![监视器选项卡](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-cncr-prog-java8/img/00043.jpeg)

在右上角，您有一些复选框可以选择要查看的信息。**CPU**图表显示了应用程序使用的 CPU 的百分比。**堆**图表显示了堆的总大小以及应用程序使用的堆的大小。在这部分，您可以看到有关**元空间**（JVM 用于存储类的内存区域）的相同信息。**类**图表显示了应用程序使用的类的数量，**线程**图表显示了应用程序内运行的线程数量。您还可以在此选项卡中使用两个按钮：

+   **执行 GC**：立即在应用程序中执行垃圾回收

+   **堆转储**：它允许您保存应用程序的当前状态以供以后检查

当您创建堆转储时，将会有一个新的选项卡显示其信息。它的外观类似于这样：

![监视器选项卡](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-cncr-prog-java8/img/00044.jpeg)

您有不同的子选项卡来查询您进行堆转储时应用程序的状态。

## 线程选项卡

正如我们之前提到的，在**线程**选项卡中，您可以看到应用程序线程随时间的演变。它向您展示了以下信息：

+   **活动线程**：应用程序中的线程数量。

+   **守护线程**：应用程序中标记为守护线程的线程数量。

+   **时间线**：线程随时间的演变，包括线程的状态（使用颜色代码），线程运行的时间以及线程存在的时间。在`总计`列的右侧，您可以看到一个箭头。如果单击它，您可以选择在此选项卡中看到的列。

其外观类似于这样：

![线程选项卡](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-cncr-prog-java8/img/00045.jpeg)

此选项卡还有**线程转储**按钮。如果单击此按钮，您将看到一个新的选项卡，其中包含应用程序中每个正在运行的线程的堆栈跟踪。其外观类似于这样：

![线程选项卡](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-cncr-prog-java8/img/00046.jpeg)

## 采样器选项卡

**采样器**选项卡向您展示了应用程序使用的 CPU 和内存的利用信息。为了获取这些信息，它获取了应用程序的所有线程的转储，并处理了该转储。该选项卡类似于**分析器**选项卡，但正如您将在下一节中看到的，它们之间的区别在于它们用于获取信息的方式。

此选项卡的外观类似于这样：

![采样器选项卡](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-cncr-prog-java8/img/00047.jpeg)

您有两个按钮：

+   **CPU**：此按钮用于获取有关 CPU 使用情况的信息。如果单击此按钮，您将看到两个子选项卡：

+   **CPU 样本**：在此选项卡中，您将看到应用程序类的 CPU 利用率

+   **线程 CPU 时间**：在此选项卡中，您将看到每个线程的 CPU 利用率

+   **内存**：此按钮用于获取有关内存使用情况的信息。如果单击此按钮，您将看到另外两个子选项卡：

+   **堆直方图**：在此选项卡中，您将看到按数据类型分配的字节数

+   **每个线程分配**：在此选项卡中，您可以看到每个线程使用的内存量

## 分析器选项卡

**分析器**选项卡向您展示了使用仪器 API 的应用程序的 CPU 和内存利用信息。基本上，当 JVM 加载方法时，此 API 会向方法添加一些字节码以获取这些信息。此信息会随时间更新。

此选项卡的外观类似于这样：

![分析器选项卡](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-cncr-prog-java8/img/00048.jpeg)

默认情况下，此选项卡不会获取任何信息。您必须启动分析会话。为此，您可以使用**CPU**按钮来获取有关 CPU 利用率的信息。这包括每个方法的执行时间和对这些方法的调用次数。您还可以使用**内存**按钮。在这种情况下，您可以看到每种数据类型的内存量和对象数量。

当您不需要获取更多信息时，可以使用**停止**按钮停止分析会话。

# 测试并发应用程序

测试并发应用程序是一项艰巨的任务。您的应用程序的线程在计算机上运行，没有任何保证它们的执行顺序（除了您包含的同步机制），因此很难（大多数情况下是不可能的）测试所有可能发生的情况。您可能会遇到无法重现的错误，因为它只在罕见或独特的情况下发生，或者因为 CPU 内核数量的不同而在一台机器上发生而在其他机器上不会发生。为了检测和重现这种情况，您可以使用不同的工具：

+   **调试**：您可以使用调试器来调试应用程序。如果应用程序中只有几个线程，您必须逐步进行每个线程的调试，这个过程将非常繁琐。您可以配置 Eclipse 或 NetBeans 来测试并发应用程序。

+   **MultithreadedTC**：这是一个**Google Code**的存档项目，可以用来强制并发应用程序的执行顺序。

+   **Java PathFinder**：这是 NASA 用于验证 Java 程序的执行环境。它包括验证并发应用程序的支持。

+   **单元测试**：您可以创建一堆单元测试（使用 JUnit 或 TestNG），并启动每个测试，例如，1,000 次。如果每个测试都成功，那么即使您的应用程序存在竞争，它们的机会也不是很高，可能对生产是可以接受的。您可以在代码中包含断言来验证它是否存在竞争条件。

在接下来的部分中，您将看到使用 MultithreadedTC 和 Java PathFinder 工具测试并发应用程序的基本示例。

## 使用 MultithreadedTC 测试并发应用程序

MultithreadedTC 是一个存档项目，您可以从[`code.google.com/p/multithreadedtc/`](http://code.google.com/p/multithreadedtc/)下载。它的最新版本是 2007 年的，但您仍然可以使用它来测试小型并发应用程序或大型应用程序的部分。您不能用它来测试真实的任务或线程，但您可以用它来测试不同的执行顺序，以检查它们是否引起竞争条件或死锁。

它基于一个内部时钟，使用允许您控制不同线程的执行顺序的滴答声。以测试该执行顺序是否会引起任何并发问题。

首先，您需要将两个库与您的项目关联起来：

+   **MultithreadedTC 库**：最新版本是 1.01 版本

+   **JUnit 库**：我们已经测试了这个例子，使用的是 4.12 版本

要使用 MultithreadedTC 库实现测试，您必须扩展`MultithreadedTestCase`类，该类扩展了 JUnit 库的`Assert`类。您可以实现以下方法：

+   `initialize()`: 这个方法将在测试执行开始时执行。如果需要执行初始化代码来创建数据对象、数据库连接等，您可以重写它。

+   `finish()`: 这个方法将在测试执行结束时执行。您可以重写它来实现测试的验证。

+   `threadXXX()`: 您必须为测试中的每个线程实现一个以`thread`关键字开头的方法。例如，如果您想要进行一个包含三个线程的测试，您的类将有三个方法。

`MultithreadedTestCase`提供了`waitForTick()`方法。此方法接收等待的时钟周期数作为参数。此方法使调用线程休眠，直到内部时钟到达该时钟周期。

第一个时钟周期是时钟周期编号`0`。MultithreadedTC 框架每隔一段时间检查测试线程的状态。如果所有运行的线程都在`waitForTick()`方法中等待，它会增加时钟周期编号并唤醒所有等待该时钟周期的线程。

让我们看一个使用它的例子。假设您想要测试具有内部`int`属性的`Data`对象。您希望一个线程增加值，另一个线程减少值。您可以创建一个名为`TestClassOk`的类，该类扩展了`MultithreadedTestCase`类。我们使用数据对象的三个属性：我们将用于增加和减少数据的数量以及数据的初始值：

```java
public class TestClassOk extends MultithreadedTestCase {

    private Data data;
    private int amount;
    private int initialData;

    public TestClassOk (Data data, int amount) {
        this.amount=amount;
        this.data=data;
        this.initialData=data.getData();
    }
```

我们实现了两种方法来模拟两个线程的执行。第一个线程在`threadAdd()`方法中实现：

```java
    public void threadAdd() {
        System.out.println("Add: Getting the data");
        int value=data.getData();
        System.out.println("Add: Increment the data");
        value+=amount;
        System.out.println("Add: Set the data");
        data.setData(value);
    }
```

它读取数据的值，增加其值，并再次写入数据的值。第二个线程在`threadSub()`方法中实现：

```java
    public void threadSub() {
        waitForTick(1);
        System.out.println("Sub: Getting the data");
        int value=data.getData();
        System.out.println("Sub: Decrement the data");
        value-=amount;
        System.out.println("Sub: Set the data");
        data.setData(value);
    }
}
```

首先，我们等待`1`时钟周期。然后，我们获取数据的值，减少其值，并重新写入数据的值。

要执行测试，我们可以使用`TestFramework`类的`runOnce()`方法：

```java
public class MainOk {

    public static void main(String[] args) {

        Data data=new Data();
        data.setData(10);
        TestClassOk ok=new TestClassOk(data,10);

        try {
            TestFramework.runOnce(ok);
        } catch (Throwable e) {
            e.printStackTrace();
        }

    }
}
```

当测试开始执行时，两个线程（`threadAdd()`和`threadSub()`）以并发方式启动。`threadAdd()`开始执行其代码，`threadSub()`在`waitForTick()`方法中等待。当`threadAdd()`完成其执行时，MultithreadedTC 的内部时钟检测到唯一运行的线程正在等待`waitForTick()`方法，因此它将时钟值增加到`1`并唤醒执行其代码的线程。

在下面的屏幕截图中，您可以看到此示例的执行输出。在这种情况下，一切都很顺利。

![使用 MultithreadedTC 测试并发应用程序](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-cncr-prog-java8/img/00049.jpeg)

但是，您可以更改线程的执行顺序以引发错误。例如，您可以实现以下顺序，这将引发竞争条件：

```java
    public void threadAdd() {
        System.out.println("Add: Getting the data");
        int value=data.getData();
        waitForTick(2);
        System.out.println("Add: Increment the data");
        value+=amount;
        System.out.println("Add: Set the data");
        data.setData(value);
    }

    public void threadSub() {
        waitForTick(1);
        System.out.println("Sub: Getting the data");
        int value=data.getData();
        waitForTick(3);
        System.out.println("Sub: Decrement the data");
        value-=amount;
        System.out.println("Sub: Set the data");
        data.setData(value);
    }
```

在这种情况下，执行顺序确保两个线程首先读取数据的值，然后执行其操作，因此最终结果将不正确。

在下面的屏幕截图中，您可以看到此示例的执行结果：

![使用 MultithreadedTC 测试并发应用程序](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-cncr-prog-java8/img/00050.jpeg)

在这种情况下，`assertEquals()`方法会抛出异常，因为期望值和实际值不相等。

该库的主要限制是，它仅适用于测试基本的并发代码，并且在实现测试时无法用于测试真正的`Thread`代码。

## 使用 Java Pathfinder 测试并发应用程序

**Java Pathfinder**或 JPF 是来自 NASA 的开源执行环境，可用于验证 Java 应用程序。它包括自己的虚拟机来执行 Java 字节码。在内部，它检测代码中可能存在多个执行路径的点，并执行所有可能性。在并发应用程序中，这意味着它将执行应用程序中运行的线程之间的所有可能的执行顺序。它还包括允许您检测竞争条件和死锁的工具。

该工具的主要优势是，它允许您完全测试并发应用程序，以确保它不会出现竞争条件和死锁。该工具的不便之处包括：

+   您必须从源代码安装它

+   如果您的应用程序很复杂，您将有成千上万种可能的执行路径，测试将非常漫长（如果应用程序很复杂，可能需要很多小时）

在接下来的几节中，我们将向您展示如何使用 Java Pathfinder 测试并发应用程序。

### 安装 Java Pathfinder

正如我们之前提到的，您必须从源代码安装 JPF。该代码位于 Mercurial 存储库中，因此第一步是安装 Mercurial，并且由于我们将使用 Eclipse IDE，因此还需要安装 Eclipse 的 Mercurial 插件。

您可以从[`www.mercurial-scm.org/wiki/Download`](https://www.mercurial-scm.org/wiki/Download)下载 Mercurial。您可以下载提供安装助手的安装程序，在计算机上安装 Mercurial 后可能需要重新启动系统。

您可以从 Eclipse 菜单中使用`Help > Install new software`下载 Eclipse 的 Mercurial 插件，并使用 URL [`mercurialeclipse.eclipselabs.org.codespot.com/hg.wiki/update_site/stable`](http://mercurialeclipse.eclipselabs.org.codespot.com/hg.wiki/update_site/stable) 作为查找软件的 URL。按照其他插件的步骤进行操作。

您还可以在 Eclipse 中安装 JPF 插件。您可以从[`babelfish.arc.nasa.gov/trac/jpf/wiki/install/eclipse-plugin`](http://babelfish.arc.nasa.gov/trac/jpf/wiki/install/eclipse-plugin)下载。

现在您可以访问 Mercurial 存储库资源管理器透视图，并添加 Java Pathfinder 的存储库。我们将仅使用存储在[`babelfish.arc.nasa.gov/hg/jpf/jpf-core`](http://babelfish.arc.nasa.gov/hg/jpf/jpf-core)中的核心模块。您无需用户名或密码即可访问存储库。创建存储库后，您可以右键单击存储库并选择**Clone repository**选项，以在计算机上下载源代码。该选项将打开一个窗口以选择一些选项，但您可以保留默认值并单击**Next**按钮。然后，您必须选择要加载的版本。保留默认值并单击**Next**按钮。最后，单击**Finish**按钮完成下载过程。Eclipse 将自动运行`ant`来编译项目。如果有任何编译问题，您必须解决它们并重新运行`ant`。

如果一切顺利，您的工作区将有一个名为`jpf-core`的项目，如下面的截图所示：

![安装 Java Pathfinder](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-cncr-prog-java8/img/00051.jpeg)

最后的配置步骤是创建一个名为`site.properties`的文件，其中包含 JPF 的配置。如果您访问**Window** | **Preferences**中的配置窗口，并选择**JPF Preferences**选项，您将看到 JPF 插件正在查找该文件的路径。如果需要，您可以更改该路径。

![安装 Java Pathfinder](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-cncr-prog-java8/img/00052.jpeg)

由于我们只使用核心模块，因此文件将只包含到`jpf-core`项目的路径：

```java
jpf-core = D:/dev/book/projectos/jpf-core
```

### 运行 Java Pathfinder

安装了 JPF 后，让我们看看如何使用它来测试并发应用程序。首先，我们必须实现一个并发应用程序。在我们的情况下，我们将使用一个带有内部`int`值的`Data`类。它将初始化为`0`，并且将具有一个`increment()`方法来增加该值。

然后，我们将有一个名为`NumberTask`的任务，它实现了`Runnable`接口，将增加一个`Data`对象的值 10 次。

```java
public class NumberTask implements Runnable {

    private Data data;

    public NumberTask (Data data) {
        this.data=data;
    }

    @Override
    public void run() {

        for (int i=0; i<10; i++) {
            data.increment(10);
        }
    }

}
```

最后，我们有一个实现了`main()`方法的`MainNumber`类。我们将启动两个将修改同一个`Data`对象的`NumberTasks`对象。最后，我们将获得`Data`对象的最终值。

```java
public class MainNumber {

    public static void main(String[] args) {
        int numTasks=2;
        Data data=new Data();

        Thread threads[]=new Thread[numTasks];
        for (int i=0; i<numTasks; i++) {
            threads[i]=new Thread(new NumberTask(data));
            threads[i].start();
        }

        for (int i=0; i<numTasks; i++) {
            try {
                threads[i].join();
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }

        System.out.println(data.getValue());
    }

}
```

如果一切顺利，没有发生竞争条件，最终结果将是 200，但我们的代码没有使用任何同步机制，所以可能会发生这种情况。

如果我们想要使用 JPF 执行此应用程序，我们需要在项目内创建一个具有`.jpf`扩展名的配置文件。例如，我们已经创建了`NumberJPF.jpf`文件，其中包含我们可以使用的最基本的配置文件：

```java
+classpath=${config_path}/bin
target=com.javferna.packtpub.mastering.testing.main.MainNumber
```

我们修改了 JPF 的类路径，添加了我们项目的`bin`目录，并指定了我们应用程序的主类。现在，我们准备通过 JPF 执行应用程序。为此，我们右键单击`.jpf`文件，然后选择**验证**选项。我们将看到在控制台中可以看到大量输出消息。每个输出消息都来自应用程序的不同执行路径。

![运行 Java Pathfinder](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-cncr-prog-java8/img/00053.jpeg)

当 JPF 结束所有可能的执行路径的执行时，它会显示有关执行的统计信息：

![运行 Java Pathfinder](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-cncr-prog-java8/img/00054.jpeg)

JPF 执行显示未检测到错误，但我们可以看到大多数结果与 200 不同，因此我们的应用程序存在竞争条件，正如我们所预期的那样。

在本节的介绍中，我们说 JPF 提供了检测竞争条件和死锁的工具。JPF 将此实现为实现`Observer`模式以响应代码执行中发生的某些事件的`Listener`机制。例如，我们可以使用以下监听器：

+   精确竞争检测器：使用此监听器来检测竞争条件

+   死锁分析器：使用此监听器来检测死锁情况

+   覆盖分析器：使用此监听器在 JPF 执行结束时编写覆盖信息

您可以在`.jpf`文件中配置要在执行中使用的监听器。例如，我们通过添加`PreciseRaceDetector`和`CoverageAnalyzer`监听器扩展了先前的测试在`NumberListenerJPF.jpf`文件中：

```java
+classpath=${config_path}/bin
target=com.javferna.packtpub.mastering.testing.main.MainNumber
listener=gov.nasa.jpf.listener.PreciseRaceDetector,gov.nasa.jpf.li stener.CoverageAnalyzer
```

如果我们通过 JPF 使用**验证**选项执行此配置文件，您将看到应用程序在检测到第一个竞争条件时结束，并在控制台中显示有关此情况的信息：

![运行 Java Pathfinder](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-cncr-prog-java8/img/00055.jpeg)

您还将看到`CoverageAnalyzer`监听器也会写入信息：

![运行 Java Pathfinder](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-cncr-prog-java8/img/00056.jpeg)

JPF 是一个非常强大的应用程序，包括更多的监听器和更多的扩展机制。您可以在[`babelfish.arc.nasa.gov/trac/jpf/wiki`](http://babelfish.arc.nasa.gov/trac/jpf/wiki)找到其完整文档。

# 总结

测试并发应用程序是一项非常艰巨的任务。线程的执行顺序没有保证（除非在应用程序中引入了同步机制），因此您应该测试比串行应用程序更多的不同情况。有时，您的应用程序会出现错误，您可以重现这些错误，因为它们只会在非常罕见的情况下发生，有时，您的应用程序会出现错误，只会在特定的机器上发生，因为其硬件或软件配置。

在本章中，您已经学会了一些可以帮助您更轻松测试并发应用程序的机制。首先，您已经学会了如何获取有关 Java 并发 API 的最重要组件（如`Thread`、`Lock`、`Executor`或`Stream`）状态的信息。如果需要检测错误的原因，这些信息可能非常有用。然后，您学会了如何使用 Java VisualVM 来监视一般的 Java 应用程序和特定的并发应用程序。最后，您学会了使用两种不同的工具来测试并发应用程序。

通过本书的章节，您已经学会了如何使用 Java 并发 API 的最重要组件，如执行器框架、`Phaser`类、Fork/Join 框架以及 Java 8 中包含的新流 API，以支持对实现机器学习、数据挖掘或自然语言处理的元素流进行函数式操作的真实应用程序。您还学会了如何使用并发数据结构和同步机制，以及如何同步大型应用程序中的不同并发块。最后，您学会了并发应用程序的设计原则以及如何测试它们，这是确保成功使用这些应用程序的两个关键因素。

实现并发应用程序是一项艰巨的任务，但也是一项激动人心的挑战。我希望本书对您成功应对这一挑战有所帮助。
