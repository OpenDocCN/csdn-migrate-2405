# Java 12 编程学习手册（六）

> 原文：[Learn Java 12 Programming ](https://libgen.rs/book/index.php?md5=2D05FE7A99FD37AE2178F1DD99C27887)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 十四、Java 标准流

在本章中，我们将讨论数据流的处理，它不同于我们在第 5 章、“字符串、输入/输出和文件”中回顾的 I/O 流。我们将定义数据流是什么，如何使用`java.util.stream.Stream`对象的方法（操作）处理它们的元素，以及如何在管道中链接（连接）流操作。我们还将讨论流的初始化以及如何并行处理流。

本章将讨论以下主题：

*   作为数据和操作源的流
*   流初始化
*   操作（方法）
*   数字流接口
*   并行流

# 作为数据和操作源的流

上一章中描述和演示的 Lambda 表达式以及函数式接口为 Java 添加了强大的函数编程功能。它们允许将行为（函数）作为参数传递给为数据处理性能而优化的库。通过这种方式，程序员可以专注于所开发系统的业务方面，而将性能方面留给专家——库的作者。这样一个库的一个例子是包`java.util.stream`，这将是本章的重点。

在第 5 章“字符串、输入/输出和文件”中，我们谈到了 I/O 流作为数据源，但除此之外，它们对数据的进一步处理没有太大帮助。它们是基于字节或字符的，而不是基于对象的。只有先以编程方式创建并序列化对象之后，才能创建对象流。I/O 流只是到外部资源的连接，大部分是文件，其他的不多。然而，有时可以从 I/O 流转换到`java.util.stream.Stream`。例如，`BufferedReader`类的`lines()`方法将底层基于字符的流转换为`Stream<String>`对象。

另一方面，`java.util.stream`包的流面向对象集合的处理。在第 6 章“数据结构、泛型和流行工具”中，我们描述了`Collection`接口的两种方法，允许将集合元素作为流的元素读取：`default Stream<E> stream()`和`default Stream<E> parallelStream()`。我们还提到了`java.util.Arrays`的`stream()`方法。它有以下八个重载版本，用于将数组或数组的一部分转换为相应数据类型的流：

*   `static DoubleStream stream(double[] array)`
*   `static DoubleStream stream(double[] array, int startInclusive, int endExclusive)`
*   `static IntStream stream(int[] array)`
*   `static IntStream stream(int[] array, int startInclusive, int endExclusive)`
*   `static LongStream stream(long[] array)`
*   `static LongStream stream(long[] array, int startInclusive, int endExclusive)`
*   `static <T> Stream<T> stream(T[] array)`
*   `static <T> Stream<T> stream(T[] array, int startInclusive, int endExclusive)`

现在让我们更仔细地看一下包`java.util.stream`的流。理解流的最好方法是将它与集合进行比较。后者是存储在内存中的数据结构。在将每个集合元素添加到集合之前，都会对其进行计算。相比之下，流发出的元素存在于源中的其他地方，并且是按需计算的。因此，集合可以是流的源。

一个`Stream`对象是一个接口`Stream`、`IntStream`、`LongStream`或`DoubleStream`的实现；最后三个被称为**数字流**。接口`Stream`的方法也可以在数字流中使用。一些数值流有一些特定于数值的额外方法，例如`average()`和`sum()`。在本章中，我们将主要讨论`Stream`接口及其方法，但是我们将要讨论的所有内容也同样适用于数字流。

流一旦处理了先前发射的元素，就*产生*（或*发射*）流元素。它允许对方法（操作）进行声明性表示，这些方法（操作）也可以并行地应用于发出的元素。今天，当大型数据集处理的机器学习需求变得无处不在时，这个特性加强了 Java 在为数不多的现代编程语言中的地位。

# 流初始化

创建和初始化流的方法有很多种，`Stream`类型的对象或任何数字接口。我们将它们按类和接口进行分组，这些类和接口具有`Stream`创建方法。我们这样做是为了方便读者，所以读者更容易记住和找到他们，如果需要的话。

# 流接口

这组`Stream`工厂由属于`Stream`接口的静态方法组成。

# `empty()`

`Stream<T> empty()`方法创建一个不发射任何元素的空流：

```java
Stream.empty().forEach(System.out::println);   //prints nothing
```

`Stream`方法`forEach()`的作用类似于`Collection`方法`forEach()`，并将传入的函数应用于每个流元素：

```java
new ArrayList().forEach(System.out::println);  //prints nothing
```

结果与从空集合创建流相同：

```java
new ArrayList().stream().forEach(System.out::println);  //prints nothing
```

如果没有任何元素发射，什么都不会发生。我们将在“终端操作”部分讨论`Stream`方法`forEach()`。

# `of(T... values)`

`of(T... values)`方法接受可变参数，也可以创建空流：

```java
Stream.of().forEach(System.out::print);       //prints nothing
```

但它通常用于初始化非空流：

```java
Stream.of(1).forEach(System.out::print);           //prints: 1
Stream.of(1,2).forEach(System.out::print);         //prints: 12
Stream.of("1 ","2").forEach(System.out::print);    //prints: 1 2
```

注意用于调用`println()`和`print()`方法的方法引用。

使用`of(T... values)`方法的另一种方法如下：

```java
String[] strings = {"1 ", "2"};
Stream.of(strings).forEach(System.out::print);      //prints: 1 2
```

如果没有为`Stream`对象指定类型，则编译器不会抱怨数组是否包含混合类型：

```java
Stream.of("1 ", 2).forEach(System.out::print);      //prints: 1 2
```

添加声明预期元素类型的泛型会在至少一个列出的元素具有不同类型时导致异常：

```java
//Stream<String> stringStream = Stream.of("1 ", 2);   //compile error
```

泛型可以帮助程序员避免许多错误，因此应该尽可能地添加泛型。

`of(T... values)`方法也可用于多个流的连接。例如，假设我们有以下四个流，我们希望将它们连接成一个流：

```java
Stream<Integer> stream1 = Stream.of(1, 2);
Stream<Integer> stream2 = Stream.of(2, 3);
Stream<Integer> stream3 = Stream.of(3, 4);
Stream<Integer> stream4 = Stream.of(4, 5);

```

我们希望将它们连接到一个新的流中，该流将发出值`1,2,2,3,3,4,4,5`。首先，我们尝试以下代码：

```java
Stream.of(stream1, stream2, stream3, stream4)
      .forEach(System.out::print);
              //prints: java.util.stream.ReferencePipeline$Head@58ceff1j

```

它没有达到我们所希望的。它将每个流视为`Stream`接口实现中使用的内部类`java.util.stream.ReferencePipeline`的对象。因此，我们需要添加`flatMap()`操作来将每个流元素转换为一个流（我们在“中间操作”部分中描述）：

```java
Stream.of(stream1, stream2, stream3, stream4)
      .flatMap(e -> e).forEach(System.out::print);   //prints: 12233445

```

我们作为参数（`e -> e`传入`flatMap()`的函数看起来好像什么都没做，但这是因为流的每个元素已经是一个流了，所以不需要对它进行转换。通过返回一个元素作为`flatMap()`操作的结果，我们告诉管道将返回值视为`Stream`对象。

# `ofNullable(T)`

如果传入的参数`t`不是`null`，则`ofNullable(T t)`方法返回一个发出单个元素的`Stream<T>`，否则返回一个空的`Stream`。为了演示`ofNullable(T t)`方法的用法，我们创建了以下方法：

```java
void printList1(List<String> list){
    list.stream().forEach(System.out::print);
}
```

我们已经执行了两次这个方法——参数列表等于`null`和`List`对象。结果如下：

```java
//printList1(null);                          //NullPointerException
List<String> list = List.of("1 ", "2");
printList1(list);                            //prints: 1 2

```

注意第一次调用`printList1()`方法是如何生成`NullPointerException`的。为了避免异常，我们可以实现如下方法：

```java
void printList1(List<String> list){ 
     (list == null ? Stream.empty() : list.stream()) 
                           .forEach(System.out::print);
} 
```

用`ofNullable(T t)`方法也可以得到同样的结果：

```java
void printList2(List<String> list){
    Stream.ofNullable(list).flatMap(l -> l.stream())
                           .forEach(System.out::print);
}
```

注意我们如何添加了`flatMap()`，否则，流入`forEach()`的`Stream`元素将是`List`对象。我们将在“中间操作”一节中详细介绍`flatMap()`方法。前面代码中传递给`flatMap()`操作的函数也可以表示为方法引用：

```java
void printList4(List<String> list){
    Stream.ofNullable(list).flatMap(Collection::stream)
                           .forEach(System.out::print);
}
```

# `iterate(T, UnaryOperator<T>)`

`Stream`接口的两种静态方法允许使用类似于传统`for`循环的迭代过程生成值流：

*   `Stream<T> iterate(T seed, UnaryOperator<T> func)`：基于第二参数、函数`func`对第一参数`seed`的迭代应用，创建无限序列流，产生值流`seed`、`f(seed)`、`f(f(seed))`等
*   `Stream<T> iterate(T seed, Predicate<T> hasNext, UnaryOperator<T> next)`：基于第三个参数函数`next`对第一个参数`seed`的迭代应用，创建一个有限的序列流，只要第三个参数函数`hasNext`返回`true`，就会产生一个值流`seed`、`f(seed)`、`f(f(seed))`等等

以下代码演示了这些方法的用法：

```java
Stream.iterate(1, i -> ++i).limit(9)
      .forEach(System.out::print); //prints: 123456789

Stream.iterate(1, i -> i < 10, i -> ++i)
      .forEach(System.out::print);        //prints: 123456789

```

请注意，我们被迫在第一个管道中添加一个中间运算符`limit(int n)`，以避免生成无穷多的生成值。我们将在“中间操作”一节中详细讨论此方法

# `concat(Stream<> a, Stream<T> b)`

`Stream`接口的`Stream<T> concat(Stream<> a, Stream<T> b)`静态方法基于作为参数传入的两个流`a`和`b`创建一个值流。新创建的流包括第一个参数`a`的所有元素，然后是第二个参数`b`的所有元素。以下代码演示了此方法：

```java
Stream<Integer> stream1 = List.of(1, 2).stream();
Stream<Integer> stream2 = List.of(2, 3).stream();
Stream.concat(stream1, stream2)
 .forEach(System.out::print); //prints: 1223

```

注意，元素`2`在两个原始流中都存在，因此由结果流发射两次。

# `generate(Supplier<T> )`

接口`Stream`的静态方法`Stream<T> generate(Supplier<T> supplier)`创建一个无限流，其中每个元素由提供的函数`Supplier<T>`生成。以下是两个示例：

```java
Stream.generate(() -> 1).limit(5)
 .forEach(System.out::print);        //prints: 11111

Stream.generate(() -> new Random().nextDouble()).limit(5)
      .forEach(System.out::println);      //prints: 0.38575117472619247
                                          //        0.5055765386778835
                                          //        0.6528038976983277
                                          //        0.4422354489467244
                                          //        0.06770955839148762

```

如果运行此代码，可能会得到不同的结果，因为生成的值具有随机（伪随机）性质。

由于创建的流是无限的，所以我们添加了一个只允许指定数量的流元素通过的`limit(int n)`操作，我们将在“中间操作”部分详细介绍这个方法

# 流生成器接口

`Stream.Builder<T> builder()`静态方法返回可用于构造`Stream`对象的内部（位于接口`Stream`内部）接口`Builder`。接口`Builder`扩展了`Consumer`接口，有如下方法：

*   `default Stream.Builder<T> add(T t)`：调用`accept(T)`方法并返回（`Builder`对象），从而允许以流畅的点连接样式链接`add(T t)`方法
*   `void accept(T t)`：在流中添加一个元素（这个方法来自`Consumer`接口）
*   `Stream<T> build()`：将此生成器从构造状态转换为`built`状态；调用此方法后，不能向该流添加新元素

`add(T t)`方法的用法很简单：

```java
Stream.<String>builder().add("cat").add(" dog").add(" bear")
      .build().forEach(System.out::print);       //prints: cat dog bear

```

请注意我们是如何将泛型`<String>`添加到`builder()`方法前面的。这样，我们告诉构建器我们正在创建的流将具有`String`类型的元素。否则，它会将元素添加为`Object`类型，并且不会确保添加的元素是`String`类型。

`accept(T t)`方法在生成器作为`Consumer<T>`类型的参数传递时使用，或者不需要链接添加元素的方法时使用。例如，下面是一个代码示例：

```java
Stream.Builder<String> builder = Stream.builder();
List.of("1", "2", "3").stream().forEach(builder);   
builder.build().forEach(System.out::print);        //prints: 123

```

`forEach(Consumer<T> consumer)`方法接受具有`accept(T t)`方法的`Consumer`函数。每次流发出一个元素时，`forEach()`方法接收它并将它传递给`Builder`对象的`accept(T t)`方法。然后，当在下一行中调用`build()`方法时，将创建`Stream`对象，并开始发射前面由`accept(T t)`方法添加的元素。发出的元素被传递到`forEach()`方法，然后由该方法逐个打印它们。

下面是一个明确使用`accept(T t)`方法的例子：

```java
List<String> values = List.of("cat", " dog", " bear");
Stream.Builder<String> builder = Stream.builder();
for(String s: values){
    if(s.contains("a")){
        builder.accept(s);
    }
}
builder.build().forEach(System.out::print);        //prints: cat bear

```

这一次，我们决定不向流中添加所有的列表元素，而只添加那些包含字符`a`的元素，正如所料，创建的流只包含`cat`和`bear`元素。另外，请注意我们如何使用`<String>`泛型来确保所有流元素都是`String`类型。

# 其他类和接口

在 Java8 中，`java.util.Collection`接口增加了两个默认方法：

*   `Stream<E> stream()`：返回此集合的元素流
*   `Stream<E> parallelStream()`：返回（可能）此集合元素的并行流；*可能*，因为 JVM 试图将流拆分为几个块并并行（如果有多个 CPU）或实际上并行（使用 CPU 的分时）处理；但这并不总是可能的，并且部分取决于请求处理的性质

这意味着所有扩展这个接口的集合接口，包括`Set`和`List`，都有这些方法。例如：

```java
List.of("1", "2", "3").stream().forEach(builder);
List.of("1", "2", "3").parallelStream().forEach(builder);
```

我们将在“并行处理”部分讨论并行流。

我们已经在“作为数据和操作源的流”部分的开头描述了`java.util.Arrays`类的八个静态重载方法`stream()`。下面是使用数组的子集创建流的另一种方法的示例：

```java
int[] arr = {1, 2, 3, 4, 5}; 
Arrays.stream(arr, 2, 4).forEach(System.out::print); //prints: 34 
```

`java.util.Random`类允许创建伪随机值的数字流：

*   `DoubleStream doubles()`：在`0`（包含）和`1`（排除）之间创建一个不受限制的`double`值流
*   `IntStream ints()`和`LongStream longs()`：创建对应类型值的无限流
*   `DoubleStream doubles(long streamSize)`：在`0`（含）和`1`（不含）之间创建`double`值的流（指定大小）
*   `IntStream ints(long streamSize)`和`LongStream longs(long streamSize)`：创建相应类型值的指定大小的流
*   `IntStream ints(int randomNumberOrigin, int randomNumberBound)`：在`randomNumberOrigin`（包含）和`randomNumberBound`（排除）之间创建一个不受限制的`int`值流
*   `LongStream longs(long randomNumberOrigin, long randomNumberBound)`：在`randomNumberOrigin`（包含）和`randomNumberBound`（排除）之间创建一个不受限制的`long`值流
*   `DoubleStream doubles(long streamSize, double randomNumberOrigin, double randomNumberBound)`：创建一个在`randomNumberOrigin`（包括）和`randomNumberBound`（不包括）之间具有指定大小的`double`值的流

以下是上述方法之一的示例：

```java
new Random().ints(5, 8).limit(5) 
            .forEach(System.out::print);    //prints: 56757 
```

`java.nio.file.Files`类有六个静态方法创建线和路径流：

*   `Stream<String> lines(Path path)`：从提供的路径指定的文件创建行流
*   `Stream<String> lines(Path path, Charset cs)`：从提供的路径指定的文件创建行流；使用提供的字符集将文件中的字节解码为字符
*   `Stream<Path> list(Path dir)`：在指定目录中创建文件和目录流
*   `Stream<Path> walk(Path start, FileVisitOption... options)`：创建以`Path start`开头的文件树的文件和目录流
*   `Stream<Path> walk(Path start, int maxDepth, FileVisitOption... options)`：创建文件树的文件和目录流，从`Path start`开始，一直到指定的深度`maxDepth`
*   `Stream<Path> find(Path start, int maxDepth, BiPredicate<Path, BasicFileAttributes> matcher, FileVisitOption... options)`：创建文件树的文件和目录流（与提供的谓词匹配），从`Path start`开始，向下到`maxDepth`值指定的深度

创建流的其他类和方法包括：

*   `java.util.BitSet`类有`IntStream stream()`方法，该方法创建一个索引流，这个`BitSet`包含一个处于设置状态的位。
*   `java.io.BufferedReader`类有`Stream<String> lines()`方法，它从这个`BufferedReader`对象（通常是从一个文件）创建一个行流。
*   `java.util.jar.JarFile`类具有创建 ZIP 文件条目流的`Stream<JarEntry> stream()`方法。
*   `java.util.regex.Pattern`类具有`Stream<String> splitAsStream(CharSequence input)`方法，该方法根据提供的序列围绕此模式的匹配创建流。
*   `java.lang.CharSequence`接口有两种方式：
    *   `default IntStream chars()`：创建一个扩展`char`值的`int`零流
    *   `default IntStream codePoints()`：根据该序列创建代码点值流

还有一个`java.util.stream.StreamSupport`类，它包含库开发人员使用的静态低级工具方法。但我们不会再讨论它，因为这超出了本书的范围。

# 操作（方法）

`Stream`接口的许多方法，那些以函数式接口类型作为参数的方法，被称为**操作**，因为它们不是作为传统方法实现的。它们的功能作为函数传递到方法中。这些操作只是调用函数式接口的方法的 Shell，该函数式接口被指定为参数方法的类型。

例如，让我们看一下`Stream<T> filter (Predicate<T> predicate)`方法。它的实现是基于对`Predicate<T>`函数的方法`boolean test(T t)`的调用。因此，与其说*使用`Stream`对象的`filter()`方法来选择一些流元素并跳过其他流元素*，程序员更喜欢说，*应用一个操作过滤器，允许一些流元素通过并跳过其他流元素*。它描述动作（操作）的性质，而不是特定的算法，在方法接收到特定函数之前，算法是未知的。`Stream`接口有两组操作：

*   **中间操作**：返回`Stream`对象的实例方法
*   **终端操作**：返回`Stream`以外类型的实例方法

流处理通常被组织为使用 Fluent（点连接）样式的管道。一个`Stream`创建方法或另一个流源启动这样一个管道。终端操作产生最终结果或副作用，并结束管道，因此命名为。中间操作可以放在起始`Stream`对象和终端操作之间。

中间操作处理流元素（或不处理，在某些情况下）并返回修改（或不修改）`Stream`对象，因此可以应用下一个中间或终端操作。中间操作示例如下：

*   `Stream<T> filter(Predicate<T> predicate)`：仅选择与标准匹配的元素
*   `Stream<R> map(Function<T,R> mapper)`：根据传入的函数转换元素；请注意返回的`Stream`对象的类型可能与输入类型有很大的不同
*   `Stream<T> distinct()`：删除重复项
*   `Stream<T> limit(long maxSize)`：将流限制为指定的元素数
*   `Stream<T> sorted()`：按一定顺序排列流元素
*   我们将在“中间操作”部分讨论其他一些中间操作。

流元素的处理实际上只有在终端操作开始执行时才开始。然后所有中间操作（如果存在）按顺序开始处理。一旦终端操作完成执行，流就会关闭并且无法重新打开。

终端操作的例子有`forEach()`、`findFirst()`、`reduce()`、`collect()`、`sum()`、`max()`以及`Stream`接口的其他不返回`Stream`对象的方法。我们将在“终端操作”部分讨论。

所有的`Stream`操作都支持并行处理，这在多核计算机上处理大量数据的情况下尤其有用。我们将在“并行流”部分讨论。

# 中间操作

正如我们已经提到的，中间操作返回一个`Stream`对象，该对象发出相同或修改的值，甚至可能与流源的类型不同。

中间操作可以按其功能分为四类操作，分别执行**过滤**、**映射**、**排序**或**窥视**。

# 过滤

此组包括删除重复项、跳过某些元素、限制已处理元素的数量以及仅选择通过某些条件的元素进行进一步处理的操作：

*   `Stream<T> distinct()`：使用`method Object.equals(Object)`比较流元素并跳过重复项
*   `Stream<T> skip(long n)`：忽略首先发出的流元素的提供数量
*   `Stream<T> limit(long maxSize)`：只允许处理提供数量的流元素
*   `Stream<T> filter(Predicate<T> predicate)`：只允许被提供的`Predicate`函数处理时产生`true`的元素被处理
*   `default Stream<T> dropWhile(Predicate<T> predicate)`：在所提供的`Predicate`函数处理时，跳过流中导致`true`的第一个元素
*   `default Stream<T> takeWhile(Predicate<T> predicate)`：只允许流的第一个元素在被提供的`Predicate`函数处理时产生`true`

下面的代码演示了刚才描述的操作是如何工作的：

```java
Stream.of("3", "2", "3", "4", "2").distinct()
                         .forEach(System.out::print);     //prints: 324

List<String> list = List.of("1", "2", "3", "4", "5");
list.stream().skip(3).forEach(System.out::print);         //prints: 45

list.stream().limit(3).forEach(System.out::print);        //prints: 123

list.stream().filter(s -> Objects.equals(s, "2"))
             .forEach(System.out::print);                 //prints: 2

list.stream().dropWhile(s -> Integer.valueOf(s) < 3)
             .forEach(System.out::print);                 //prints: 345

list.stream().takeWhile(s -> Integer.valueOf(s) < 3)
             .forEach(System.out::print);                 //prints: 12

```

注意，我们可以重用源`List<String>`对象，但不能重用`Stream`对象。一旦`Stream`对象被关闭，它就不能被重新打开。

# 映射

这一组可以说包括最重要的中间操作。它们是修改流元素的唯一中间操作。它们**将**（转换）原始流元素值映射到新的流元素值：

*   `Stream<R> map(Function<T, R> mapper)`：将提供的函数应用于流的`T`类型的每个元素，并生成`R`类型的新元素值
*   `IntStream mapToInt(ToIntFunction<T> mapper)`：将提供的函数应用于流的`T`类型的每个元素，并生成`int`类型的新元素值
*   `LongStream mapToLong(ToLongFunction<T> mapper)`：将提供的函数应用于流的`T`类型的每个元素，并生成`long`类型的新元素值
*   `DoubleStream mapToDouble(ToDoubleFunction<T> mapper)`：将提供的函数应用于流的`T`类型的每个元素，并生成`double`类型的新元素值
*   `Stream<R> flatMap(Function<T, Stream<R>> mapper)`：将提供的函数应用于流的`T`类型的每个元素，并生成一个`Stream<R>`对象，该对象发出`R`类型的元素
*   `IntStream flatMapToInt(Function<T, IntStream> mapper)`：将提供的函数应用于流的`T`类型的每个元素，并生成一个`IntStream`对象，该对象发出`int`类型的元素
*   `LongStream flatMapToLong(Function<T, LongStream> mapper)`：将提供的函数应用于流的`T`类型的每个元素，并生成一个`LongStream`对象，该对象发出`long`类型的元素
*   `DoubleStream flatMapToDouble(Function<T, DoubleStream> mapper)`：将提供的函数应用于流的`T`类型的每个元素，并生成一个`DoubleStream`对象，该对象发出`double`类型的元素

以下是使用这些操作的示例：

```java
List<String> list = List.of("1", "2", "3", "4", "5");
list.stream().map(s -> s + s)
             .forEach(System.out::print);    //prints: 1122334455

list.stream().mapToInt(Integer::valueOf)
             .forEach(System.out::print);    //prints: 12345

list.stream().mapToLong(Long::valueOf)
             .forEach(System.out::print);    //prints: 12345

list.stream().mapToDouble(Double::valueOf)
             .mapToObj(Double::toString)
             .map(s -> s + " ")
             .forEach(System.out::print);  //prints: 1.0 2.0 3.0 4.0 5.0

list.stream().mapToInt(Integer::valueOf)
             .flatMap(n -> IntStream.iterate(1, i -> i < n, i -> ++i))
             .forEach(System.out::print);        //prints: 1121231234

list.stream().map(Integer::valueOf)
             .flatMapToInt(n ->
                  IntStream.iterate(1, i -> i < n, i -> ++i))
             .forEach(System.out::print);        //prints: 1121231234

list.stream().map(Integer::valueOf)
             .flatMapToLong(n ->
                  LongStream.iterate(1, i -> i < n, i -> ++i))
             .forEach(System.out::print);        //prints: 1121231234

list.stream().map(Integer::valueOf)
             .flatMapToDouble(n ->
                  DoubleStream.iterate(1, i -> i < n, i -> ++i))
             .mapToObj(Double::toString)
             .map(s -> s + " ")
             .forEach(System.out::print);
                       //prints: 1.0 1.0 2.0 1.0 2.0 3.0 1.0 2.0 3.0 4.0
```

在上一个示例中，将流转换为`DoubleStream`，我们将每个数值转换为一个`String`对象，并添加空格，这样就可以用数字之间的空格打印结果。这些示例非常简单：只需进行最小处理即可进行转换。但在现实生活中，每个`map()`或`flatMap()`操作通常都接受一个更复杂的函数，该函数做一些更有用的事情。

# 排序

以下两个中间操作对流元素进行排序：

*   `Stream<T> sorted()`：按自然顺序排序流元素（根据它们的`Comparable`接口实现）
*   `Stream<T> sorted(Comparator<T> comparator)`：根据提供的`Comparator<T>`对象对流元素进行排序

当然，在所有元素发出之前，这些操作无法完成，因此这种处理会产生大量开销，降低性能，并且必须用于小规模流

下面是演示代码：

```java
List<String> list = List.of("2", "1", "5", "4", "3");
list.stream().sorted().forEach(System.out::print);  //prints: 12345
list.stream().sorted(Comparator.reverseOrder())
             .forEach(System.out::print);           //prints: 54321

```

# 窥探

中间的`Stream<T> peek(Consumer<T> action)`操作将提供的`Consumer<T>`函数应用于每个流元素，但不改变流值（函数`Consumer<T>`返回`void`。此操作用于调试。下面的代码显示了它的工作原理：

```java
List<String> list = List.of("1", "2", "3", "4", "5");
list.stream()
 .peek(s -> System.out.print("3".equals(s) ? 3 : 0))
 .forEach(System.out::print); //prints: 0102330405
```

# 终端操作

**终端操作**是流的最重要的操作。不使用任何其他操作就可以完成其中的所有操作。

我们已经使用了`forEach(Consumer<T>)`终端操作来打印每个元素。它不返回一个值，因此用于它的副作用。但是`Stream`接口有许多更强大的终端操作，它们返回值。

其中最主要的是`collect()`操作，它有`R collect(Collector<T, A, R> collector)`和`R collect(Supplier<R> supplier, BiConsumer<R, T> accumulator, BiConsumer<R, R> combiner)`两种形式。它允许组合几乎任何可以应用于流的进程。经典的例子如下：

```java
List<String> list = Stream.of("1", "2", "3", "4", "5")
                          .collect(ArrayList::new,
                                   ArrayList::add,
                                   ArrayList::addAll);
System.out.println(list);  //prints: [1, 2, 3, 4, 5]

```

在这个例子中，它的使用方式适合于并行处理。`collect()`操作的第一个参数是基于流元素生成值的函数。第二个参数是累积结果的函数。第三个参数是组合处理流的所有线程的累积结果的函数。

但是只有一个这样的通用终端操作会迫使程序员重复编写相同的函数。这就是 API 作者添加类`Collectors`的原因，该类生成许多专门的`Collector`对象，而无需为每个`collect()`操作创建三个函数。

除此之外，API 作者还在接口`Stream`中添加了各种更专门的终端操作，这些操作更简单、更易于使用。在本节中，我们将回顾`Stream`接口的所有终端操作，并在`Collect`小节中查看`Collectors`类生成的大量`Collector`对象。我们从最简单的终端操作开始，它允许一次处理这个流的每个元素。

在我们的示例中，我们将使用以下类：`Person`：

```java
public class Person {
    private int age;
    private String name;
    public Person(int age, String name) {
        this.age = age;
        this.name = name;
    }
    public int getAge() {return this.age; }
    public String getName() { return this.name; }
    @Override
    public String toString() {
        return "Person{" + "name='" + this.name + "'" +
                                       ", age=" + age + "}";
    }
}
```

# 处理每个元素

此组中有两个终端操作：

*   `void forEach(Consumer<T> action)`：为该流的每个元素应用提供的操作
*   `void forEachOrdered(Consumer<T> action)`：按照源定义的顺序为该流的每个元素应用提供的操作，而不管该流是连续的还是并行的

如果需要处理元素的顺序很重要，并且必须是顺序值在源代码处排列，请使用第二种方法，特别是如果您可以预见您的代码可能会在具有多个 CPU 的计算机上执行。否则，请使用第一个，就像我们在所有示例中所做的那样。

让我们看一个使用`forEach()`操作从文件中读取逗号分隔的值（年龄和名称）并创建`Person`对象的示例。我们已将以下文件`persons.csv`（`csv`代表*逗号分隔值*）放在`resources`文件夹中：

```java
23 , Ji m
    2 5 , Bob
  15 , Jill
17 , Bi ll
```

我们在值的内部和外部添加了空格，以便借此机会向您展示一些处理实际数据的简单但非常有用的技巧。

首先，我们将读取文件并逐行显示其内容，但只显示包含字母`J`的行：

```java
Path path = Paths.get("src/main/resources/persons.csv");
try (Stream<String> lines = Files.newBufferedReader(path).lines()) {
    lines.filter(s -> s.contains("J"))
         .forEach(System.out::println);  //prints: 23 , Ji m
                                         //          15 , Jill
} catch (IOException ex) {
    ex.printStackTrace();
}
```

这是使用`forEach()`操作的一种典型方式：独立地处理每个元素。此代码还提供了一个资源尝试构造的示例，该构造自动关闭`BufferedReader`对象

下面是一个没有经验的程序员如何编写代码，从`Stream<String> lines`对象读取流元素，并创建`Person`对象列表：

```java
List<Person> persons = new ArrayList<>();
lines.filter(s -> s.contains("J")).forEach(s -> {
    String[] arr = s.split(",");
    int age = Integer.valueOf(StringUtils.remove(arr[0], ' '));
    persons.add(new Person(age, StringUtils.remove(arr[1], ' ')));
});

```

您可以看到`split()`方法是如何使用逗号分隔各行的，以及`org.apache.commons.lang3.StringUtils.remove()`方法是如何从每个值中删除空格的。尽管此代码在单核计算机上的小示例中运行良好，但它可能会在长流和并行处理中产生意外的结果。

这就是 Lambda 表达式要求所有变量都是`final`或有效`final`的原因，因为同一个函数可以在不同的上下文中执行。

以下是上述代码的正确实现：

```java
List<Person> persons = lines.filter(s -> s.contains("J"))
        .map(s -> s.split(","))
        .map(arr -> {
            int age = Integer.valueOf(StringUtils.remove(arr[0], ' '));
            return new Person(age, StringUtils.remove(arr[1], ' '));
        }).collect(Collectors.toList());
```

为了提高可读性，我们可以创建一个方法来进行映射：

```java
private Person createPerson(String[] arr){
    int age = Integer.valueOf(StringUtils.remove(arr[0], ' '));
    return new Person(age, StringUtils.remove(arr[1], ' '));
}
```

现在我们可以使用它如下：

```java
List<Person> persons = lines.filter(s -> s.contains("J"))
                            .map(s -> s.split(","))
                            .map(this::createPerson)
                            .collect(Collectors.toList());

```

如您所见，我们使用了`collect()`操作符和`Collectors.toList()`方法创建的`Collector`函数。我们将在“收集”小节中看到更多由类`Collectors`创建的函数。

# 计算所有元素

`Stream`接口的`long count()`终端操作看起来简单而良性。它返回此流中的元素数。那些习惯于使用集合和数组的人可以不用三思而后行地使用`count()`操作。以下代码段演示了一个警告：

```java
long count = Stream.of("1", "2", "3", "4", "5")
                   .peek(System.out::print)
                   .count();
System.out.print(count);          //prints: 5               

```

如果我们运行前面的代码，结果如下所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/46166046-1838-459b-baf4-4e203ac031e5.png)

如您所见，实现`count()`方法的代码能够在不执行所有管道的情况下确定流大小。`peek()`操作没有打印任何内容，这证明元素没有被发射。因此，如果您希望看到打印的流的值，您可能会感到困惑，并希望代码有某种缺陷

另一个警告是，并不总是能够在源位置确定流的大小。此外，这条河可能是无限的。所以，你必须小心使用`count()`。

确定流大小的另一种可能方法是使用`collect()`操作：

```java
long count = Stream.of("1", "2", "3", "4", "5")
                   .peek(System.out::print)         //prints: 12345
                   .collect(Collectors.counting());
System.out.println(count);                          //prints: 5 
```

下面的屏幕截图显示了在运行前面的代码示例后发生的情况：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/1f00826d-c8dc-454a-a446-f44452b5fb26.png)

如您所见，`collect()`操作不计算源处的流大小。这是因为`collect()`操作没有`count()`操作专业化。它只是将传入的收集器应用于流。收集器只计算由`collect()`操作提供给它的元素。

# 全部匹配，任何匹配，无匹配

有三个看起来非常相似的终端操作，允许我们评估所有、任何或没有一个流元素具有特定的值：

*   `boolean allMatch(Predicate<T> predicate)`：当每个流元素在用作所提供的`Predicate<T>`函数的参数时返回`true`时，返回`true`
*   `boolean anyMatch(Predicate<T> predicate)`：当其中一个流元素作为所提供的`Predicate<T>`函数的参数返回`true`时，返回`true`
*   `boolean noneMatch(Predicate<T> predicate)`：当作为提供的`Predicate<T>`函数的参数使用时，当没有一个流元素返回`true`时，返回`true`

以下是它们的用法示例：

```java
List<String> list = List.of("1", "2", "3", "4", "5");
boolean found = list.stream()
                    .peek(System.out::print)             //prints: 123
                    .anyMatch(e -> "3".equals(e));
System.out.println(found);                               //prints: true

boolean noneMatches = list.stream()
                          .peek(System.out::print)       //prints: 123
                          .noneMatch(e -> "3".equals(e));
System.out.println(noneMatches);                         //prints: false

boolean allMatch = list.stream()
                       .peek(System.out::print)          //prints: 1
                       .allMatch(e -> "3".equals(e));
System.out.println(allMatch);                            //prints: false
```

请注意，所有这些操作都进行了优化，以便在可以提前确定结果的情况下不会处理所有流元素。

# 找到任何一个或第一个

以下终端操作允许相应地查找流的任何或第一个元素：

*   `Optional<T> findAny()`：返回一个包含流的任何元素的值的`Optional`，如果流为空，则返回一个空的`Optional`
*   `Optional<T> findFirst()`：返回一个包含流的第一个元素的值的`Optional`，如果流是空的，则返回一个空的`Optional`

以下示例说明了这些操作：

```java
List<String> list = List.of("1", "2", "3", "4", "5");
Optional<String> result = list.stream().findAny();
System.out.println(result.isPresent());    //prints: true
System.out.println(result.get());          //prints: 1

result = list.stream()
             .filter(e -> "42".equals(e))
             .findAny();
System.out.println(result.isPresent());    //prints: false
//System.out.println(result.get());        //NoSuchElementException

result = list.stream().findFirst();
System.out.println(result.isPresent());    //prints: true
System.out.println(result.get());          //prints: 1

```

在前面的第一个和第三个示例中，`findAny()`和`findFirst()`操作产生相同的结果：它们都找到流的第一个元素。但在并行处理中，结果可能不同。

当流被分成若干部分进行并行处理时，`findFirst()`操作总是返回流的第一个元素，`findAny()`操作只返回其中一个处理线程中的第一个元素。

现在让我们更详细地谈谈`class java.util.Optional`。

# `Optional`类

`java.util.Optional`的宾语用于避免返回`null`（因为它可能导致`NullPointerException`）。相反，`Optional`对象提供的方法允许检查值的存在，如果返回值是`null`，则用预定义的值替换它。例如：

```java
List<String> list = List.of("1", "2", "3", "4", "5");
String result = list.stream()
                    .filter(e -> "42".equals(e))
                    .findAny()
                    .or(() -> Optional.of("Not found"))
                    .get();
System.out.println(result);                       //prints: Not found

result = list.stream()
             .filter(e -> "42".equals(e))
             .findAny()
             .orElse("Not found");
System.out.println(result);                      //prints: Not found

Supplier<String> trySomethingElse = () -> {
    //Code that tries something else
    return "43";
};
result = list.stream()
             .filter(e -> "42".equals(e))
             .findAny()
             .orElseGet(trySomethingElse);
System.out.println(result);                      //prints: 43

list.stream()
    .filter(e -> "42".equals(e))
    .findAny()
    .ifPresentOrElse(System.out::println,
        () -> System.out.println("Not found")); //prints: Not found

```

如您所见，如果`Optional`对象是空的，那么以下情况适用：

*   `Optional`类的`or()`方法允许返回另一个`Optional`对象。
*   `orElse()`方法允许返回替代值。
*   `orElseGet()`方法允许提供`Supplier`函数，该函数返回一个可选值。
*   `ifPresentOrElse()`方法允许提供两个函数：一个消耗`Optional`对象的值，另一个在`Optional`对象为空的情况下执行其他操作。

# 最小值和最大值

以下终端操作返回流元素的最小值或最大值（如果存在）：

*   `Optional<T> min(Comparator<T> comparator)`：使用提供的`Comparator`对象返回该流的最小元素
*   `Optional<T> max(Comparator<T> comparator)`：使用提供的`Comparator`对象返回该流的最大元素

下面的代码演示了这一点：

```java
List<String> list = List.of("a", "b", "c", "c", "a");
String min = list.stream()
                 .min(Comparator.naturalOrder())
                 .orElse("0");
System.out.println(min);     //prints: a

String max = list.stream()
 .max(Comparator.naturalOrder())
                 .orElse("0");
System.out.println(max);     //prints: c

```

如您所见，在非数值的情况下，最小元素是根据提供的比较器从左到右排序时的第一个元素。因此，最大值是最后一个元素。对于数值，最小值和最大值只是：流元素中的最小值和最大值：

```java
int mn = Stream.of(42, 77, 33)
               .min(Comparator.naturalOrder())
               .orElse(0);
System.out.println(mn);    //prints: 33

int mx = Stream.of(42, 77, 33)
               .max(Comparator.naturalOrder())
               .orElse(0);
System.out.println(mx);    //prints: 77

```

让我们看另一个例子，使用`Person`类。任务是在以下列表中找到最年长的人：

```java
List<Person> persons = List.of(new Person(23, "Bob"),
 new Person(33, "Jim"),
 new Person(28, "Jill"),
 new Person(27, "Bill"));

```

为了做到这一点，我们可以创建下面的`Compartor<Person>`，只按年龄比较`Person`对象：

```java
Comparator<Person> perComp = (p1, p2) -> p1.getAge() - p2.getAge();
```

然后，使用这个比较器，我们可以找到最年长的人：

```java
Person theOldest = persons.stream()
                          .max(perComp)
                          .orElse(null);
System.out.println(theOldest);    //prints: Person{name='Jim', age=33}
```

# 到数组

以下两个终端操作生成包含流元素的数组：

*   `Object[] toArray()`：创建一个对象数组；每个对象都是流的一个元素
*   `A[] toArray(IntFunction<A[]> generator)`：使用提供的函数创建流元素数组

让我们看一些例子：

```java
List<String> list = List.of("a", "b", "c");
Object[] obj = list.stream().toArray();
Arrays.stream(obj).forEach(System.out::print);    //prints: abc

String[] str = list.stream().toArray(String[]::new);
Arrays.stream(str).forEach(System.out::print);    //prints: abc

```

第一个例子很简单。它将元素转换为相同类型的数组。至于第二个例子，`IntFunction`作为`String[]::new`的表示可能并不明显，所以让我们来看看它。`String[]::new`是表示 Lambda 表达式`i -> new String[i]`的方法引用，因为`toArray()`操作从流接收的不是元素，而是它们的计数：

```java
String[] str = list.stream().toArray(i -> new String[i]);
```

我们可以通过添加`i`值的打印来证明：

```java
String[] str = list.stream()
                   .toArray(i -> {
                          System.out.println(i);    //prints: 3
                          return  new String[i];
                   });

```

`i -> new String[i]`表达式是一个`IntFunction<String[]>`，根据它的文档，它接受一个`int`参数并返回指定类型的结果。可以使用匿名类定义它，如下所示：

```java
IntFunction<String[]> intFunction = new IntFunction<String[]>() { 
         @Override 
         public String[] apply(int i) { 
              return new String[i]; 
         } 
}; 
```

`java.util.Collection`接口有一个非常类似的方法，可以将集合转换为数组：

```java
List<String> list = List.of("a", "b", "c");
String[] str = list.toArray(new String[lits.size()]);
Arrays.stream(str).forEach(System.out::print);    //prints: abc

```

唯一的区别是`Stream`接口的`toArray()`接受一个函数，而`Collection`接口的`toArray()`接受一个数组。

# 归约

这种终端操作被称为`reduce`，因为它处理所有流元素并产生一个值，从而将所有流元素减少为一个值。但这并不是唯一的行动。`collect`操作将流元素的所有值也减少为一个结果。而且，在某种程度上，所有的终端操作都是还原的。它们在处理许多元素后产生一个值。

因此，您可以将`reduce`和`collect`视为同义词，它们有助于为`Stream`接口中的许多可用操作添加结构和分类。此外，`reduce`组中的操作可以被视为`collect`操作的专用版本，因为`collect()`可以定制为提供与`reduce()`操作相同的功能。

也就是说，让我们看一组`reduce`操作：

*   `Optional<T> reduce(BinaryOperator<T> accumulator)`：使用提供的聚合元素的关联函数来减少流中的元素；返回一个包含减少值（如果可用）的`Optional`
*   `T reduce(T identity, BinaryOperator<T> accumulator)`：提供与先前`reduce()`版本相同的功能，但使用`identity`参数作为累加器的初始值，或者在流为空时使用默认值
*   `U reduce(U identity, BiFunction<U,T,U> accumulator, BinaryOperator<U> combiner)`：提供与先前`reduce()`版本相同的功能，但是，当此操作应用于并行流时，使用`combiner`函数来聚合结果；如果流不是并行的，则不使用`combiner`函数

为了演示`reduce()`操作，我们将使用之前使用的`Person`类和`Person`对象的相同列表作为流示例的源：

```java
List<Person> persons = List.of(new Person(23, "Bob"),
                               new Person(33, "Jim"),
                               new Person(28, "Jill"),
                               new Person(27, "Bill"));
```

让我们使用`reduce()`操作来查找列表中最年长的人：

```java
Person theOldest = list.stream()
              .reduce((p1, p2) -> p1.getAge() > p2.getAge() ? p1 : p2)
              .orElse(null);
System.out.println(theOldest);    //prints: Person{name='Jim', age=33}

```

它的实现有点令人惊讶，不是吗？`reduce()`操作需要一个累加器，但它似乎没有积累任何东西。相反，它比较所有流元素。累加器保存比较的结果，并将其作为下一个比较（与下一个元素）的第一个参数。在本例中，可以说累加器累加了前面所有比较的结果

现在让我们明确地积累一些东西。让我们把所有人的名字集中在一个逗号分隔的列表中：

```java
String allNames = list.stream()
                      .map(p -> p.getName())
                      .reduce((n1, n2) -> n1 + ", " + n2)
                      .orElse(null);
System.out.println(allNames);            //prints: Bob, Jim, Jill, Bill

```

在这种情况下，积累的概念更有意义，不是吗？

现在让我们使用`identity`值来提供一些初始值：

```java
String all = list.stream()
                 .map(p -> p.getName())
                 .reduce("All names: ", (n1, n2) -> n1 + ", " + n2);
System.out.println(all);   //prints: All names: , Bob, Jim, Jill, Bill

```

注意，`reduce()`操作的这个版本返回`value`，而不是`Optional`对象。这是因为，通过提供初始值，我们可以保证，如果流结果为空，结果中至少会出现这个值。但最终的字符串看起来并不像我们希望的那么漂亮。显然，所提供的初始值被视为任何其他流元素，并且我们创建的累加器会在它后面添加一个逗号。为了使结果看起来更漂亮，我们可以再次使用第一个版本的`reduce()`操作，并通过以下方式添加初始值：

```java
String all = "All names: " + list.stream()
                                 .map(p -> p.getName())
                                 .reduce((n1, n2) -> n1 + ", " + n2)
                                 .orElse(null);
System.out.println(all);     //prints: All names: Bob, Jim, Jill, Bill
```

或者我们可以用空格代替逗号作为分隔符：

```java
String all = list.stream()
                 .map(p -> p.getName())
                 .reduce("All names:", (n1, n2) -> n1 + " " + n2);
System.out.println(all);     //prints: All names: Bob Jim Jill Bill
```

现在结果看起来更好了。在下一小节中演示`collect()`操作的同时，我们将展示一种更好的方法来创建以逗号分隔的带有前缀的值列表。

同时，让我们继续回顾一下`reduce()`操作，看看它的第三种形式：有三个参数的形式：`identity`、`accumulator`和`combiner`。将组合器添加到`reduce()`操作不会改变结果：

```java
String all = list.stream()
                 .map(p -> p.getName())
                 .reduce("All names:", (n1, n2) -> n1 + " " + n2,
                                       (n1, n2) -> n1 + " " + n2 );
System.out.println(all);      //prints: All names: Bob Jim Jill Bill

```

这是因为流不是并行的，并且组合器仅与并行流一起使用。如果我们使流平行，结果会改变：

```java
String all = list.parallelStream()
                 .map(p -> p.getName())
                 .reduce("All names:", (n1, n2) -> n1 + " " + n2,
                                       (n1, n2) -> n1 + " " + n2 );
System.out.println(all); 
  //prints: All names: Bob All names: Jim All names: Jill All names: Bill
```

显然，对于并行流，元素序列被分解成子序列，每个子序列独立地处理，其结果由组合器聚合。在执行此操作时，组合器将初始值（标识）添加到每个结果中。即使我们移除合并器，并行流处理的结果仍然是相同的，因为提供了默认的合并器行为：

```java
String all = list.parallelStream()
                 .map(p -> p.getName())
                 .reduce("All names:", (n1, n2) -> n1 + " " + n2);
System.out.println(all); 
  //prints: All names: Bob All names: Jim All names: Jill All names: Bill
```

在前两种形式的`reduce()`操作中，累加器使用同一值。在第三种形式中，标识值由组合器使用（注意，`U`类型是组合器类型）。为了消除结果中的重复标识值，我们决定从组合器中的第二个参数中删除它（以及尾随空格）：

```java
String all = list.parallelStream().map(p->p.getName())
                 .reduce("All names:", (n1, n2) -> n1 + " " + n2,
       (n1, n2) -> n1 + " " + StringUtils.remove(n2, "All names: "));
System.out.println(all);      //prints: All names: Bob Jim Jill Bill 
```

结果如预期。

到目前为止，在我们基于字符串的示例中，标识不仅仅是一个初始值。它还充当结果字符串中的标识符（标签）。但是当流的元素是数字时，标识看起来更像是一个初始值。让我们看看下面的例子：

```java
List<Integer> ints = List.of(1, 2, 3);
int sum = ints.stream()
              .reduce((i1, i2) -> i1 + i2)
              .orElse(0);
System.out.println(sum);                          //prints: 6
sum = ints.stream()
          .reduce(Integer::sum)
          .orElse(0);
System.out.println(sum);                          //prints: 6
sum = ints.stream()
          .reduce(10, Integer::sum);
System.out.println(sum);                         //prints: 16
sum = ints.stream()
          .reduce(10, Integer::sum, Integer::sum);
System.out.println(sum);                         //prints: 16

```

前两个管道完全相同，只是第二个管道使用方法引用。第三和第四条管道也具有相同的功能。它们都使用初始值`10`。现在第一个参数作为初始值比恒等式更有意义，不是吗？在第四个管道中，我们添加了一个组合器，但由于流不是平行的，所以没有使用它。让我们把它平行，看看会发生什么：

```java
List<Integer> ints = List.of(1, 2, 3);
int sum = ints.parallelStream()
              .reduce(10, Integer::sum, Integer::sum);
System.out.println(sum);                        //prints: 36
```

结果是`36`，因为`10`的初始值加了三次，每次都是部分结果。很明显，这条河被分成了三个子序列。但情况并非总是如此，因为子序列的数量随着流的增长而变化，计算机上的 CPU 数量也随之增加。这就是为什么不能依赖于固定数量的子序列，最好不要对并行流使用非零初始值：

```java
List<Integer> ints = List.of(1, 2, 3);
int sum = ints.parallelStream()
              .reduce(0, Integer::sum, Integer::sum);
System.out.println(sum);                             //prints: 6
sum = 10 + ints.parallelStream()
               .reduce(0, Integer::sum, Integer::sum);
System.out.println(sum);                             //prints: 16

```

如您所见，我们已经将`identity`设置为`0`，所以每个子序列都会得到它，但是当组合器组装所有处理线程的结果时，总数不受影响。

# 收集

`collect()`操作的一些用法非常简单，任何初学者都很容易掌握，而其他情况可能很复杂，即使对于一个经验丰富的程序员来说也不容易理解。加上已经讨论过的操作，我们在这一节中介绍的最流行的`collect()`用法足以满足初学者的所有需求，并将涵盖更有经验的专业人士的大多数需求。与数字流的操作（见下一节“数字流接口”）一起，它们涵盖了主流程序员的所有需求。

正如我们已经提到的，`collect()`操作非常灵活，允许我们定制流处理。它有两种形式：

*   `R collect(Collector<T, A, R> collector)`：使用提供的`Collector`处理`T`类型的流元素，通过`A`类型的中间累加产生`R`类型的结果
*   `R collect(Supplier<R> supplier, BiConsumer<R, T> accumulator, BiConsumer<R, R> combiner)`：使用提供的函数处理`T`类型的流元素：
    *   `Supplier<R> supplier`：新建结果容器
    *   `BiConsumer<R, T> accumulator`：向结果容器添加元素的无状态函数
    *   `BiConsumer<R, R> combiner`：合并两个部分结果容器的无状态函数：将第二个结果容器中的元素添加到第一个结果容器中

让我们先来看第二种形式的`collect()`操作。它非常类似于我们刚才演示的三个参数的`reduce()`操作：`supplier`、`accumulator`和`combiner`。最大的区别在于，`collect()`操作中的第一个参数不是一个标识或初始值，而是一个容器，一个对象，它将在函数之间传递并保持处理的状态。

让我们通过从`Person`对象列表中选择最年长的人来演示它是如何工作的。对于下面的示例，我们将使用熟悉的`Person`类作为容器，但向其中添加一个没有参数的构造器和两个设置器：

```java
public Person(){}
public void setAge(int age) { this.age = age;}
public void setName(String name) { this.name = name; }
```

添加一个没有参数和设置器的构造器是必要的，因为作为容器的`Person`对象应该可以在任何时候创建，而不需要任何参数，并且应该能够接收和保留部分结果：迄今为止年龄最大的人的姓名和年龄。`collect()`操作将在处理每个元素时使用此容器，并且在处理最后一个元素后，将包含最年长者的姓名和年龄。

我们将再次使用相同的人员名单：

```java
List<Person> list = List.of(new Person(23, "Bob"),
                            new Person(33, "Jim"),
                            new Person(28, "Jill"),
                            new Person(27, "Bill"));

```

下面是一个`collect()`操作，用于查找列表中最年长的人：

```java
BiConsumer<Person, Person> accumulator = (p1, p2) -> {
    if(p1.getAge() < p2.getAge()){
        p1.setAge(p2.getAge());
        p1.setName(p2.getName());
    }
};
BiConsumer<Person, Person> combiner = (p1, p2) -> {
    System.out.println("Combiner is called!");
    if(p1.getAge() < p2.getAge()){
        p1.setAge(p2.getAge());
        p1.setName(p2.getName());
    }
};
Person theOldest = list.stream()
                       .collect(Person::new, accumulator, combiner);
System.out.println(theOldest);     //prints: Person{name='Jim', age=33}

```

我们尝试在操作调用中内联函数，但是看起来有点难读，所以我们决定先创建函数，然后在`collect()`操作中使用它们。容器，一个`Person`对象，在处理第一个元素之前只创建一次。在这个意义上，它类似于`reduce()`操作的初始值。然后将其传递给累加器，累加器将其与第一个元素进行比较。容器中的`age`字段被初始化为默认值 0，因此，第一个元素的`age`和`name`在容器中被设置为迄今为止最老的人的参数。当第二个流元素（`Person`对象）被发射时，它的`age`值与当前存储在容器中的`age`值进行比较，依此类推，直到流的所有元素都被处理。结果显示在前面的注释中。

当流是连续的时，从不调用组合器。但是当我们使它并行（`list.parallelStream()`）时，消息合并器被调用！打印了三次。好吧，在`reduce()`操作的情况下，部分结果的数量可能会有所不同，这取决于 CPU 的数量和`collect()`操作实现的内部逻辑。因此，消息组合器被称为！可打印任意次数

现在让我们看一下`collect()`操作的第一种形式。它需要实现`java.util.stream.Collector<T,A,R>`接口的类的对象，其中`T`是流类型，`A`是容器类型，`R`是结果类型。您可以使用以下方法之一`of()`（来自`Collector`接口）来创建必要的`Collector`对象：

```java
static Collector<T,R,R> of(Supplier<R> supplier, 
                           BiConsumer<R,T> accumulator, 
                           BinaryOperator<R> combiner, 
                           Collector.Characteristics... characteristics)
```

或者

```java
static Collector<T,A,R> of(Supplier<A> supplier, 
                           BiConsumer<A,T> accumulator, 
                           BinaryOperator<A> combiner, 
                           Function<A,R> finisher, 
                           Collector.Characteristics... characteristics).
```

必须传递给前面方法的函数与我们已经演示过的函数类似。但我们不打算这么做，有两个原因。首先，它涉及的内容更多，将我们推到了本书的范围之外；其次，在此之前，您必须查看`java.util.stream.Collectors`类，它提供了许多现成的收集器。

正如我们已经提到的，连同到目前为止讨论的操作和我们将在下一节中介绍的数字流操作，即用收集器涵盖了主流编程中的绝大多数处理需求，并且很有可能您永远不需要创建自定义收集器

# 收集器

`java.util.stream.Collectors`类提供了 40 多个创建`Collector`对象的方法。我们将只演示最简单和最流行的：

*   `Collector<T,?,List<T>> toList()`：创建一个收集器，从流元素生成一个`List`对象
*   `Collector<T,?,Set<T>> toSet()`：创建一个收集器，从流元素生成一个`Set`对象
*   `Collector<T,?,Map<K,U>> toMap (Function<T,K> keyMapper, Function<T,U> valueMapper)`：创建一个收集器，从流元素生成一个`Map`对象
*   `Collector<T,?,C> toCollection (Supplier<C> collectionFactory)`：创建一个收集器，该收集器生成`Supplier<C> collectionFactory`所提供类型的`Collection`对象
*   `Collector<CharSequence,?,String> joining()`：创建一个收集器，通过连接流元素生成一个`String`对象
*   `Collector<CharSequence,?,String> joining (CharSequence delimiter)`：创建一个收集器，该收集器生成一个分隔符，将`String`对象与流元素分开
*   `Collector<CharSequence,?,String> joining (CharSequence delimiter, CharSequence prefix, CharSequence suffix)`：创建一个收集器，该收集器生成一个分隔符，将`String`对象与流元素分开，并添加指定的`prefix`和`suffix`
*   `Collector<T,?,Integer> summingInt(ToIntFunction<T>)`：创建一个收集器，计算应用于每个元素的所提供函数生成的结果之和；对于`long`和`double`类型，存在相同的方法
*   `Collector<T,?,IntSummaryStatistics> summarizingInt(ToIntFunction<T>)`：创建一个收集器，用于计算应用于每个元素的所提供函数生成的结果的总和、最小值、最大值、计数和平均值；对于`long`和`double`类型，存在相同的方法
*   `Collector<T,?,Map<Boolean,List<T>>> partitioningBy (Predicate<? super T> predicate)`：创建一个收集器，使用提供的`Predicate`函数分离元素
*   `Collector<T,?,Map<K,List<T>>> groupingBy(Function<T,U>)`：创建一个收集器，将元素分组到一个`Map`，其中包含所提供函数生成的键

下面的演示代码演示如何使用由所列方法创建的收集器。首先，我们演示`toList()`、`toSet()`、`toMap()`和`toCollection()`方法的用法：

```java
List<String> ls = Stream.of("a", "b", "c")
                        .collect(Collectors.toList());
System.out.println(ls);                //prints: [a, b, c]

Set<String> set = Stream.of("a", "a", "c")
                        .collect(Collectors.toSet());
System.out.println(set);                //prints: [a, c]

List<Person> list = List.of(new Person(23, "Bob"),
                            new Person(33, "Jim"),
                            new Person(28, "Jill"),
                            new Person(27, "Bill"));
Map<String, Person> map = list.stream()
                              .collect(Collectors
                              .toMap(p -> p.getName() + "-" + 
                                          p.getAge(), p -> p));
System.out.println(map); //prints: {Bob-23=Person{name='Bob', age:23},
                         //         Bill-27=Person{name='Bill', age:27},
                         //         Jill-28=Person{name='Jill', age:28},
                         //         Jim-33=Person{name='Jim', age:33}}

Set<Person> personSet = list.stream()
                            .collect(Collectors
                            .toCollection(HashSet::new));
System.out.println(personSet);  //prints: [Person{name='Bill', age=27},
                                //         Person{name='Jim', age=33},
                                //         Person{name='Bob', age=23},
                                //         Person{name='Jill', age=28}]
```

`joining()`方法允许将分隔列表中的`Character`和`String`值与`prefix`和`suffix`连接起来：

```java
List<String> list1 = List.of("a", "b", "c", "d");
String result = list1.stream()
                     .collect(Collectors.joining());
System.out.println(result);                    //prints: abcd

result = list1.stream()
              .collect(Collectors.joining(", "));
System.out.println(result);                 //prints: a, b, c, d

result = list1.stream()
              .collect(Collectors.joining(", ", "The result: ", ""));
System.out.println(result);           //prints: The result: a, b, c, d

result = list1.stream()
        .collect(Collectors.joining(", ", "The result: ", ". The End."));
System.out.println(result);    //prints: The result: a, b, c, d. The End.
```

现在让我们转到`summingInt()`和`summarizingInt()`方法。它们创建收集器，计算应用于每个元素的所提供函数产生的`int`值的总和和其他统计信息：

```java
List<Person> list2 = List.of(new Person(23, "Bob"),
                             new Person(33, "Jim"),
                             new Person(28, "Jill"),
                             new Person(27, "Bill"));
int sum = list2.stream()
               .collect(Collectors.summingInt(Person::getAge));
System.out.println(sum);                 //prints: 111

IntSummaryStatistics stats = list2.stream()
           .collect(Collectors.summarizingInt(Person::getAge));
System.out.println(stats); //prints: IntSummaryStatistics{count=4,
                           //sum=111, min=23, average=27.750000, max=33}
System.out.println(stats.getCount());    //prints: 4
System.out.println(stats.getSum());      //prints: 111
System.out.println(stats.getMin());      //prints: 23
System.out.println(stats.getAverage());  //prints: 27.750000
System.out.println(stats.getMax());      //prints: 33
```

还有`summingLong()`、`summarizingLong()`、`summingDouble()`和`summarizingDouble()`方法。

`partitioningBy()`方法创建一个收集器，该收集器根据提供的条件对元素进行分组，并将这些组（列表）放在一个`Map`对象中，`boolean`值作为键：

```java
Map<Boolean, List<Person>> map2 = list2.stream()
       .collect(Collectors.partitioningBy(p -> p.getAge() > 27));
System.out.println(map2);
     //{false=[Person{name='Bob', age=23}, Person{name='Bill', age=27},
     //  true=[Person{name='Jim', age=33}, Person{name='Jill', age=28}]}

```

如您所见，使用`p.getAge() > 27`标准，我们可以将所有人分为两组：一组低于或等于`age`的`27`年（键为`false`），另一组高于`27`（键为`true`）。

最后，`groupingBy()`方法允许按一个值对元素进行分组，并将这些组（列表）放入一个`Map`对象中，该值作为键：

```java
List<Person> list3 = List.of(new Person(23, "Bob"),
                             new Person(33, "Jim"),
                             new Person(23, "Jill"),
                             new Person(33, "Bill"));
Map<Integer, List<Person>> map3 = list3.stream()
                       .collect(Collectors.groupingBy(Person::getAge));
System.out.println(map3);  
      // {33=[Person{name='Jim', age=33}, Person{name='Bill', age=33}], 
      //  23=[Person{name='Bob', age=23}, Person{name='Jill', age=23}]} 
```

为了能够演示这个方法，我们更改了`Person`对象的列表，将每个对象上的`age`设置为`23`或`33`。结果是两组按`age`排序。

还有重载的`toMap()`、`groupingBy()`和`partitioningBy()`方法，以及以下创建相应`Collector`对象的方法（通常也是重载的）：

*   `counting()`
*   `reducing()`
*   `filtering()`
*   `toConcurrentMap()`
*   `collectingAndThen()`
*   `maxBy()``minBy()`
*   `mapping()``flatMapping()`
*   `averagingInt()``averagingLong()``averagingDouble()`
*   `toUnmodifiableList()``toUnmodifiableMap()``toUnmodifiableSet()`

如果在本书中讨论的操作中找不到所需的操作，请先搜索`Collectors`API，然后再构建自己的`Collector`对象。

# 数字流接口

如前所述，三个数字接口`IntStream`、`LongStream`和`DoubleStream`的方法都与接口`Stream`中的方法相似，包括接口`Stream.Builder`中的方法。这意味着我们在本章中讨论的所有内容都同样适用于任何数字流接口。这就是为什么在本节中我们只讨论那些在`Stream`接口中不存在的方法：

*   接口`IntStream`和`LongStream`中的`range(lower,upper)`和`rangeClosed(lower,upper)`方法允许从指定范围内的值创建流
*   中间操作`boxed()`和`mapToObj()`将数字流转换为`Stream`
*   中间操作`mapToInt()`、`mapToLong()`和`mapToDouble()`将一种类型的数字流转换为另一种类型的数字流
*   中间操作`flatMapToInt()`、`flatMapToLong()`和`flatMapToDouble()`将流转换为数字流
*   终端操作`sum()`和`average()`计算数字流元素的总和和平均值

# 创建流

除了创建流的`Stream`接口的方法之外，接口`IntStream`和`LongStream`还允许从指定范围内的值创建流。

# `range()`，`rangeClosed()`

`range(lower, upper)`方法依次生成所有值，从`lower`值开始，以`upper`前的值结束：

```java
IntStream.range(1, 3).forEach(System.out::print);   //prints: 12
LongStream.range(1, 3).forEach(System.out::print);  //prints: 12

```

`rangeClosed(lower, upper)`方法依次生成所有值，从`lower`值开始，到`upper`值结束：

```java
IntStream.rangeClosed(1, 3).forEach(System.out::print); //prints: 123
LongStream.rangeClosed(1, 3).forEach(System.out::print);  //prints: 123

```

# 中间操作

除了`Stream`接口的中间操作外，接口`IntStream`、`LongStream`、`DoubleStream`还具有若干特定的中间操作：`boxed()`、`mapToObj()`、`mapToInt()`、`mapToLong()`、`mapToDouble()`、`flatMapToInt()`、`flatMapToLong()`、`flatMapToDouble()`。

# `boxed()`，`mapToObj()`

中间操作`boxed()`将原始类型数字类型的元素转换为相应的包装类型：

```java
    //IntStream.range(1, 3).map(Integer::shortValue) //compile error
    //                  .forEach(System.out::print);

    IntStream.range(1, 3)
             .boxed()
             .map(Integer::shortValue)
             .forEach(System.out::print);            //prints: 12

    //LongStream.range(1, 3).map(Long::shortValue)   //compile error
    //                .forEach(System.out::print);

    LongStream.range(1, 3)
              .boxed()
              .map(Long::shortValue)
              .forEach(System.out::print);           //prints: 12

    //DoubleStream.of(1).map(Double::shortValue)     //compile error
    //              .forEach(System.out::print);

    DoubleStream.of(1)
                .boxed()
                .map(Double::shortValue)
                .forEach(System.out::print);         //prints: 1
```

在前面的代码中，我们已经注释掉了生成编译错误的行，因为`range()`方法生成的元素是原始类型。`boxed()`操作将原始类型值转换为相应的包装类型，因此可以将其作为引用类型进行处理。中间操作`mapToObj()`做了类似的转换，但它不像`boxed()`操作那样专业化，允许使用原始类型的元素来生成任何类型的对象：

```java
IntStream.range(1, 3)
         .mapToObj(Integer::valueOf)
         .map(Integer::shortValue)
         .forEach(System.out::print);           //prints: 12

IntStream.range(42, 43)
      .mapToObj(i -> new Person(i, "John"))
      .forEach(System.out::print); //prints: Person{name='John', age=42}

LongStream.range(1, 3)
          .mapToObj(Long::valueOf)
          .map(Long::shortValue)
          .forEach(System.out::print);          //prints: 12

DoubleStream.of(1)
            .mapToObj(Double::valueOf)
            .map(Double::shortValue)
            .forEach(System.out::print);        //prints: 1

```

在前面的代码中，我们添加了`map()`操作，只是为了证明`mapToObj()`操作完成了任务，并按照预期创建了一个包装类型的对象。另外，通过添加产生`Person`对象的管道，我们已经演示了如何使用`mapToObj()`操作来创建任何类型的对象

# `mapToInt()`，`mapToLong()`，`mapToDouble()`

中间操作`mapToInt()`、`mapToLong()`、`mapToDouble()`允许将一种类型的数字流转换为另一种类型的数字流。出于演示目的，我们通过将每个`String`值映射到其长度，将`String`值列表转换为不同类型的数字流：

```java
List<String> list = List.of("one", "two", "three");
list.stream()
    .mapToInt(String::length)
    .forEach(System.out::print);               //prints: 335

list.stream()
    .mapToLong(String::length)
    .forEach(System.out::print);               //prints: 335

list.stream()
    .mapToDouble(String::length)
    .forEach(d -> System.out.print(d + " "));  //prints: 3.0 3.0 5.0

list.stream()
    .map(String::length)
    .map(Integer::shortValue)
    .forEach(System.out::print);               //prints: 335

```

创建的数字流的元素属于原始类型：

```java
//list.stream().mapToInt(String::length)
//             .map(Integer::shortValue) //compile error
//             .forEach(System.out::print);
```

而且，正如我们在本主题中所讨论的，如果您想将元素转换为数字包装类型，中间的`map()`操作是实现这一点的方法（而不是`mapToInt()`）：

```java
list.stream().map(String::length)
        .map(Integer::shortValue)
        .forEach(System.out::print);      //prints: 335

```

# `flatMapToInt()`，`flatMapToLong()`，`flatMapToDouble()`

中间操作`flatMapToInt()`、`flatMapToLong()`、`flatMapToDouble()`产生相应类型的数字流：

```java
List<Integer> list = List.of(1, 2, 3);
list.stream()
    .flatMapToInt(i -> IntStream.rangeClosed(1, i))
    .forEach(System.out::print);               //prints: 112123

list.stream()
    .flatMapToLong(i -> LongStream.rangeClosed(1, i))
    .forEach(System.out::print);               //prints: 112123

list.stream()
    .flatMapToDouble(DoubleStream::of)
    .forEach(d -> System.out.print(d + " "));  //prints: 1.0 2.0 3.0

```

正如您在前面的代码中看到的，我们在原始流中使用了`int`值。但它可以是任何类型的流：

```java
List.of("one", "two", "three")
    .stream()
    .flatMapToInt(s -> IntStream.rangeClosed(1, s.length()))
    .forEach(System.out::print);             //prints: 12312312345

```

# 终端操作

特定于数字的终端操作非常简单。其中有两个：

*   `sum()`：计算数字流元素的和
*   `average()`：计算数值流元素的平均值

# 求和，平均

如果需要计算数值流元素值的总和或平均值，则流的唯一要求是它不应是无限的。否则，计算永远不会结束。以下是这些操作用法的示例：

```java
int sum = IntStream.empty()
                   .sum();
System.out.println(sum);            //prints: 0

sum = IntStream.range(1, 3)
               .sum();
System.out.println(sum);            //prints: 3

double av = IntStream.empty()
                     .average()
                     .orElse(0);
System.out.println(av);             //prints: 0.0

av = IntStream.range(1, 3)
              .average()
              .orElse(0);
System.out.println(av);             //prints: 1.5

long suml = LongStream.range(1, 3)
                      .sum();
System.out.println(suml);           //prints: 3

double avl = LongStream.range(1, 3)
                       .average()
                       .orElse(0);
System.out.println(avl);            //prints: 1.5

double sumd = DoubleStream.of(1, 2)
                          .sum();
System.out.println(sumd);           //prints: 3.0

double avd = DoubleStream.of(1, 2)
                         .average()
                         .orElse(0);
System.out.println(avd);            //prints: 1.5

```

如您所见，在空流上使用这些操作不是问题。

# 并行流

我们已经看到，如果没有为处理并行流而编写和测试代码，那么从顺序流更改为并行流可能会导致不正确的结果。以下是与并行流相关的更多考虑事项。

# 无状态和有状态操作

有**无状态操作**，例如`filter()`、`map()`和`flatMap()`，它们在从一个流元素到下一个流元素的处理过程中不保留数据（不维护状态）。并且有状态操作，例如`distinct()`、`limit()`、`sorted()`、`reduce()`和`collect()`，可以将状态从先前处理的元素传递到下一个元素的处理。

在从顺序流切换到并行流时，无状态操作通常不会造成问题。每个元素都是独立处理的，流可以被分解成任意数量的子流进行独立处理。对于有状态操作，情况就不同了。首先，将它们用于无限流可能永远无法完成处理。此外，在讨论有状态操作`reduce()`和`collect()`时，我们已经演示了如果在没有考虑并行处理的情况下设置初始值（或标识），那么切换到并行流如何产生不同的结果。

还有性能方面的考虑。有状态操作通常需要使用缓冲在多个过程中处理所有流元素。对于大型流，它可能会占用 JVM 资源，并且会减慢（如果不是完全关闭）应用的速度。

这就是为什么程序员不应该轻率地从顺序流切换到并行流的原因。如果涉及到有状态操作，则必须对代码进行设计和测试，以便能够在没有负面影响的情况下执行并行流处理。

# 顺序处理还是并行处理？

正如我们在上一节中所指出的，并行处理可能会也可能不会产生更好的性能。在决定使用并行流之前，您必须测试每个用例。并行性可以产生更好的性能，但代码必须经过设计和可能的优化才能做到这一点。每个假设都必须在尽可能接近生产的环境中进行测试。

但是，在决定顺序处理和并行处理时，您可以考虑以下几点：

*   小数据流通常按顺序处理得更快（那么，对于您的环境来说，什么是*小*应该通过测试和测量性能来确定）
*   如果有状态的操作不能被无状态的操作所替代，那么请仔细设计并行处理的代码，或者干脆避免它
*   对于需要大量计算的过程，请考虑并行处理，但要考虑将部分结果合并到一起以获得最终结果

# 总结

在本章中，我们讨论了数据流处理，它不同于我们在第 5 章、“字符串、输入/输出和文件”中回顾的处理 I/O 流。我们定义了数据流是什么，如何使用流操作处理它们的元素，以及如何在管道中链接（连接）流操作。我们还讨论了流初始化以及如何并行处理流

在下一章中，读者将介绍**反应式宣言**，它的主旨，以及它的实现示例。我们将讨论无功和响应系统的区别，以及什么是**异步**和**非阻塞**处理。我们还将讨论**反应流**和 **RxJava**。

# 测验

1.  I/O 流和`java.util.stream.Stream`有什么区别？选择所有适用的选项：
    1.  I/O 流面向数据传送，`Stream`面向数据处理
    2.  一些 I/O 流可以转换成`Stream`
    3.  I/O 流可以从文件中读取，而`Stream`不能
    4.  I/O 流可以写入文件，`Stream`不能

2.  `Stream`方法`empty()`和`of(T... values)`有什么共同点？
3.  由`Stream.ofNullable(Set.of(1,2,3 )`流发射的元素是什么类型的？
4.  下面的代码打印什么？

```java
Stream.iterate(1, i -> i + 2)
      .limit(3)
      .forEach(System.out::print);
```

5.  下面的代码打印什么？

```java
Stream.concat(Set.of(42).stream(), 
             List.of(42).stream()).limit(1)
                                  .forEach(System.out::print);
```

6.  下面的代码打印什么？

```java
Stream.generate(() -> 42 / 2)
      .limit(2)
      .forEach(System.out::print);
```

7.  `Stream.Builder`是函数式接口吗？
8.  下面的流发出多少元素？

```java
new Random().doubles(42).filter(d -> d >= 1)
```

9.  下面的代码打印什么？ 

```java
Stream.of(1,2,3,4)
        .skip(2)
        .takeWhile(i -> i < 4)
        .forEach(System.out::print);
```

10.  以下代码中的`d`值是多少？ 

```java
double d = Stream.of(1, 2)
                 .mapToDouble(Double::valueOf)
                 .map(e -> e / 2)
                 .sum();
```

11.  在下面的代码中，`s`字符串的值是多少？

```java
String s = Stream.of("a","X","42").sorted()
 .collect(Collectors.joining(","));
```

12.  以下代码的结果是什么？

```java
List.of(1,2,3).stream()
              .peek(i -> i > 2 )
              .forEach(System.out::print);
```

13.  `peek()`操作在下面的代码中打印多少个流元素？

```java
List.of(1,2,3).stream()
              .peek(System.out::println)
              .noneMatch(e -> e == 2);

```

14.  当`Optional`对象为空时，`or()`方法返回什么？
15.  在下面的代码中，`s`字符串的值是多少？

```java
String s = Stream.of("a","X","42")
 .max(Comparator.naturalOrder())
 .orElse("12");
```

16.  `IntStream.rangeClosed(42, 42)`流发出多少元素？
17.  说出两个无状态操作。
18.  说出两个有状态操作。

# 十五、反应式程序设计

在本章中，读者将被介绍到**反应式宣言**和反应式编程的世界。我们从定义和讨论主要的相关概念开始—异步、非阻塞和响应。利用它们，我们定义并讨论了反应式编程，主要的反应式框架，并对 **RxJava** 进行了详细的讨论。

本章将讨论以下主题：

*   异步处理
*   非阻塞 API
*   反应式–响应迅速、弹性十足、富有弹性、信息驱动
*   反应流
*   RxJava

# 异步处理

**异步**是指请求者立即得到响应，但结果不存在。相反，请求者等待结果发送给他们，或者保存在数据库中，或者，例如，作为允许检查结果是否准备好的对象呈现。如果是后者，请求者会周期性地调用这个对象的某个方法，当结果就绪时，使用同一对象上的另一个方法检索它。异步处理的优点是请求者可以在等待时做其他事情。

在第 8 章“多线程和并发处理”中，我们演示了如何创建子线程。这样的子线程然后发送一个非异步（阻塞）请求，并等待其返回而不做任何操作。同时，主线程继续执行并定期调用子线程对象，以查看结果是否就绪。这是最基本的异步处理实现。事实上，当我们使用并行流时，我们已经使用了它。

在幕后创建子线程的并行流操作将流分解为多个段，并将每个段分配给一个专用线程进行处理，然后将所有段的部分结果聚合为最终结果。在上一章中，我们甚至编写了执行聚合任务的函数。提醒一下，这个函数被称为一个**组合器**。

让我们用一个例子来比较顺序流和并行流的性能。

# 顺序流和并行流

为了演示顺序处理和并行处理之间的区别，让我们设想一个从 10 个物理设备（传感器）收集数据并计算平均值的系统。以下是从由 ID 标识的传感器收集测量值的`get()`方法：

```java
double get(String id){
    try{
        TimeUnit.MILLISECONDS.sleep(100);
    } catch(InterruptedException ex){
        ex.printStackTrace();
    }
    return id * Math.random();
}
```

我们设置了 100 毫秒的延迟来模拟从传感器收集测量值所需的时间。至于得到的测量值，我们使用`Math.random()`方法。我们将使用方法所属的`MeasuringSystem`类的对象来调用这个`get()`方法

然后我们要计算一个平均值，以抵消单个设备的误差和其他特性：

```java
void getAverage(Stream<Integer> ids) {
    LocalTime start = LocalTime.now();
    double a = ids.mapToDouble(id -> new MeasuringSystem().get(id))
                  .average()
                  .orElse(0);
    System.out.println((Math.round(a * 100.) / 100.) + " in " +
          Duration.between(start, LocalTime.now()).toMillis() + " ms");
}
```

注意我们如何使用`mapToDouble()`操作将 IDs 流转换为`DoubleStream`，以便应用`average()`操作。`average()`操作返回一个`Optional<Double>`对象，我们调用它的`orElse(0)`方法，该方法返回计算值或零（例如，如果测量系统无法连接到它的任何传感器并返回一个空流）

`getAverage()`方法的最后一行打印结果以及计算结果所用的时间。在实际代码中，我们将返回结果并将其用于其他计算。但是，为了演示，我们只是打印出来。

现在我们可以比较顺序流处理和并行处理的性能：

```java
List<Integer> ids = IntStream.range(1, 11)
                             .mapToObj(i -> i)
                             .collect(Collectors.toList());
getAverage(ids.stream());          //prints: 2.99 in 1030 ms
getAverage(ids.parallelStream());  //prints: 2.34 in  214 ms

```

如果运行此示例，结果可能会有所不同，因为您可能还记得，我们将收集的测量值模拟为随机值。

如您所见，并行流的处理速度是顺序流的处理速度的五倍。结果是不同的，因为每次测量产生的结果都略有不同

虽然在幕后，并行流使用异步处理，但这并不是程序员在谈论请求的异步处理时所考虑的。从应用的角度来看，它只是并行（也称为并发）处理。它比顺序处理要快，但是主线程必须等到所有的调用都被发出并且数据被检索出来。如果每个调用至少需要 100 毫秒（在我们的例子中是这样），那么所有调用的处理就不能在更短的时间内完成。

当然，我们可以创建一个子线程，让它进行所有调用，并等待调用完成，而主线程则执行其他操作。我们甚至可以创建一个这样做的服务，所以应用只需告诉这样的服务必须做什么，然后继续做其他事情。稍后，主线程可以再次调用服务并获得结果或在某个商定的位置获取结果。

这将是程序员们谈论的真正的异步处理。但是，在编写这样的代码之前，让我们先看看位于`java.util.concurrent`包中的`CompletableFuture`类。它完成了所描述的一切，甚至更多。

# 使用`CompletableFuture`对象

使用`CompletableFuture`对象，我们可以通过从`CompletableFuture`对象得到结果，将请求单独发送到测量系统。这正是我们在解释什么是异步处理时描述的场景。让我们在代码中演示一下：

```java
List<CompletableFuture<Double>> list = 
     ids.stream()
        .map(id -> CompletableFuture.supplyAsync(() -> 
                                       new MeasuringSystem().get(id)))
        .collect(Collectors.toList());
```

`supplyAsync()`方法不会等待对测量系统的调用返回。相反，它会立即创建一个`CompletableFuture`对象并返回它，以便客户可以在以后的任何时候使用该对象来检索测量系统返回的值：

```java
LocalTime start = LocalTime.now();
double a = list.stream()
               .mapToDouble(cf -> cf.join().doubleValue())
               .average()
               .orElse(0);
System.out.println((Math.round(a * 100.) / 100.) + " in " +
     Duration.between(start, LocalTime.now()).toMillis() + " ms"); 
                                               //prints: 2.92 in 6 ms
```

也有一些方法允许检查是否返回了值，但这并不是本演示的重点，演示如何使用`CompletableFuture`类来组织异步处理。

创建的`CompletableFuture`对象列表可以存储在任何地方，并且处理速度非常快（在本例中为 6 毫秒），前提是已经收到测量结果。在创建`CompletableFuture`对象列表和处理它们之间，系统没有阻塞，可以做其他事情。

`CompletableFuture`类有许多方法，并支持其他几个类和接口。例如，可以添加固定大小的线程池以限制线程数：

```java
ExecutorService pool = Executors.newFixedThreadPool(3);
List<CompletableFuture<Double>> list = ids.stream()
        .map(id -> CompletableFuture.supplyAsync(() -> 
                         new MeasuringSystem().get(id), pool))
        .collect(Collectors.toList());

```

有许多这样的池用于不同的目的和不同的性能。但这一切并没有改变整个系统的设计，所以我们省略了这些细节。

如您所见，异步处理的功能非常强大。异步 API 还有一个变体，称为**非阻塞 API**，我们将在下一节中讨论。

# 非阻塞 API

非阻塞 API 的客户端希望能够快速返回结果，也就是说，不会被阻塞很长时间。因此，非阻塞 API 的概念意味着一个高度响应的应用。它可以同步或异步地处理请求—这对客户端并不重要。但实际上，这通常意味着应用使用异步处理，这有助于提高吞吐量和性能。

术语**非阻塞**与`java.nio`包一起使用。**非阻塞输入/输出**（**NIO**）支持密集的输入/输出操作。它描述了应用的实现方式：它不为每个请求指定一个执行线程，而是提供多个轻量级工作线程，这些线程以异步和异步方式进行处理同时

# `java.io`包与`java.nio`包

向外部存储器（例如硬盘驱动器）写入数据和从外部存储器（例如硬盘驱动器）读取数据的操作要比仅在存储器中进行的操作慢得多。`java.io`包中已经存在的类和接口工作得很好，但偶尔会成为性能瓶颈。创建新的`java.nio`包是为了提供更有效的 I/O 支持。

`java.io`的实现是基于 I/O 流处理的，如前所述，即使后台发生某种并发，基本上也是一个阻塞操作。为了提高速度，引入了基于对内存中的缓冲区进行读写的`java.nio`实现。这样的设计使得它能够将填充/清空缓冲区的缓慢过程与快速读取/写入缓冲区的过程分离开来。

在某种程度上，它类似于我们在`CompletableFuture`用法示例中所做的。在缓冲区中有数据的另一个优点是，可以检查数据，沿着缓冲区往返，这在从流中顺序读取时是不可能的。它在数据处理过程中提供了更大的灵活性。此外，`java.nio`实现引入了另一个中间过程，称为**通道**，用于与缓冲区之间的批量数据传输。

读取线程从一个通道获取数据，只接收当前可用的数据，或者什么都不接收（如果通道中没有数据）。如果数据不可用，线程可以执行其他操作，而不是保持阻塞状态，例如，读取/写入其他通道，就像我们的`CompletableFuture`示例中的主线程可以自由执行测量系统从传感器读取数据时必须执行的操作一样。

这样，几个工作线程就可以服务于多个 I/O 进程，而不是将一个线程专用于一个 I/O 进程。这种解决方案被称为**非阻塞 I/O**，后来被应用到其他进程中，最突出的是事件循环中的*事件处理*，也称为**运行循环**。

# 事件/运行循环

许多非阻塞系统基于**事件**（或**运行**）循环—一个持续执行的线程。它接收事件（请求、消息），然后将它们分派给相应的事件处理器（工作器）。事件处理器没有什么特别之处。它们只是程序员专用于处理特定事件类型的方法（函数）。

这种设计被称为**反应器设计模式**。围绕处理并发事件和服务请求而构建，并命名为**反应式编程**和**反应式系统**，即对事件做出反应并对其进行并发处理。

基于事件循环的设计广泛应用于操作系统和图形用户界面中。它在 Spring5 的 SpringWebFlux 中可用，并用 JavaScript 及其流行的执行环境实现节点.JS. 最后一个使用事件循环作为其处理主干。工具箱 Vert.x 也是围绕事件循环构建的。

在采用事件循环之前，为每个传入请求分配一个专用线程，这与我们演示的流处理非常相似。每个线程都需要分配一定数量的非请求特定的资源，因此一些资源（主要是内存分配）被浪费了。然后，随着请求数量的增长，CPU 需要更频繁地将上下文从一个线程切换到另一个线程，以允许或多或少地并发处理所有请求。在负载下，切换上下文的开销足以影响应用的性能。

实现事件循环解决了这两个问题。它避免了为每个请求创建一个专用线程，并在处理请求之前一直保留该线程，从而消除了资源浪费。有了事件循环，每个请求只需分配更小的内存就可以捕获其细节，这使得在内存中保留更多的请求成为可能，以便它们可以并发处理。由于上下文大小的减小，CPU 上下文切换的开销也变得更小了。

非阻塞 API 是实现请求处理的方式。它使系统能够处理更大的负载，同时保持高度的响应性和弹性。

# 反应式

术语**反应式**通常用于反应式编程和反应式系统的上下文中。反应式编程（也称为 Rx 编程）基于异步数据流（也称为**反应式流**）。介绍为 Java 的**反应式扩展**（**RX**），又称 [**RxJava**](http://reactivex.io)。后来，RX 支持被添加到了 Java9 的`java.util.concurrent`包中。它允许`Publisher`生成一个数据流，而`Subscriber`可以异步订阅该数据流。

反应流和标准流（也称为位于`java.util.stream`包中的 **Java8 流**）之间的一个主要区别是，反应流的源（发布者）以自己的速率将元素推送到订户，而在标准流中，新元素仅在前一个元素被推送之后才被推送和发射已处理

如您所见，即使没有这个新的 API，我们也可以通过使用`CompletableFuture`异步处理数据。但是在编写了几次这样的代码之后，您注意到大多数代码只是管道，所以您会觉得必须有一个更简单、更方便的解决方案。这就是[反应流倡议](https://www.reactive-streams.org/)的方式，工作范围定义如下：

“反应流的范围是找到最小的接口，方法和协议集，以描述实现目标所需的必要操作和实体–具有无阻塞背压的异步数据流。”

术语**无阻塞背压**是指异步处理的问题之一：在不需要停止（阻塞）数据输入的情况下，协调传入数据的速率与系统处理它们的能力。解决办法是通知消息来源，消费者很难跟上输入。此外，处理应该以比仅仅阻塞流更灵活的方式对传入数据的速率的变化作出反应，因此名称为*反应式*。

已经有几个库实现了 ReactiveStreamsAPI：[RxJava](http://reactivex.io)、[Reactor](https://projectreactor.io)、[Akka](https://akka.io/docs) 和 [Vertx](https://vertx.io/) 是最有名的。使用 RxJava 或另一个异步流库构成了“反应式编程”。它实现了[反应宣言](https://www.reactivemanifesto.org)中宣布的目标：构建*响应*、*弹性*、*弹性*、*消息驱动*的反应式系统。

# 响应式

这个词似乎是不言自明的。及时作出反应的能力是任何系统的基本素质之一。有很多方法可以实现。即使是由足够多的服务器和其他基础设施支持的传统阻塞 API，也可以在不断增长的负载下实现良好的响应。

反应式编程有助于减少硬件的使用。它是有代价的，因为被动代码需要改变我们对控制流的思考方式。但过了一段时间，这种新的思维方式就和其他熟悉的技能一样自然了。

我们将在下面几节中看到许多反应式编程的例子。

# 可恢复的

失败是不可避免的。硬件崩溃、软件有缺陷、接收到意外数据或采用了未经测试的执行路径—这些事件中的任何一个或它们的组合都可能随时发生。*弹性*是系统在意外情况下继续交付预期结果的能力。

例如，可以使用可部署组件和硬件的冗余、系统各部分的隔离以降低多米诺效应的可能性、设计具有自动可更换部件的系统、发出警报以便合格人员能够进行干预。我们还讨论了分布式系统作为设计弹性系统的一个很好的例子。

分布式架构消除了单点故障。此外，将系统分解为许多专门的组件，这些组件使用消息相互通信，可以更好地调整最关键部分的重复，并为它们的隔离和潜在故障的遏制创造更多的机会。

# 弹性的

承受最大可能负载的能力通常与**可伸缩性**有关。但是，在变化的载荷下，而不仅仅是在增长的载荷下，保持相同性能特征的能力被称为**弹性**。

弹性系统的客户不应注意到空闲周期和峰值负载周期之间的任何差异。非阻塞的反应式实现风格促进了这种质量。此外，将程序分解为更小的部分，并将它们转换为可以独立部署和管理的服务，这样就可以对资源分配进行微调。

这种小型服务被称为微服务，它们中的许多一起可以组成一个既可伸缩又有弹性的反应式系统。我们将在下面的部分和下一章更详细地讨论这种架构。

# 消息驱动

我们已经确定组件隔离和系统分布是帮助保持系统响应性、弹性和弹性的两个方面。松散和灵活的连接也是支持这些品质的重要条件。反应式系统的异步特性并没有给设计者留下其他选择，而是在消息上构建组件之间的通信。

它在每个部件周围创造了一个喘息的空间，如果没有这个空间，系统将是一个紧密耦合的整体，容易出现各种问题，更不用说维护的噩梦了。

在下一章中，我们将研究可用于将应用构建为使用消息进行通信的松散耦合微服务集合的架构样式。

# 反应流

Java9 中引入的反应流 API 由以下四个接口组成：

```java
@FunctionalInterface
public static interface Flow.Publisher<T> {
    public void subscribe(Flow.Subscriber<T> subscriber);
}
public static interface Flow.Subscriber<T> {
    public void onSubscribe(Flow.Subscription subscription);
    public void onNext(T item);
    public void onError(Throwable throwable);
    public void onComplete();
}
public static interface Flow.Subscription {
    public void request(long numberOfItems);
    public void cancel();
}
public static interface Flow.Processor<T,R>
              extends Flow.Subscriber<T>, Flow.Publisher<R> {
}
```

一个`Flow.Subscriber`对象可以作为参数传递到`Flow.Publisher<T>`的`subscribe()`方法中。然后发布者调用订阅者的`onSubscribe()`方法，并将`Flow.Subsctiption`对象作为参数传递给它。现在订阅者可以调用订阅对象上的`request(long numberOfItems)`向发布者请求数据。这就是**拉取模式**的实现方式，它让订户决定何时请求另一个项目进行处理。订阅者可以通过调用订阅时的`cancel()`方法取消对发布者服务的订阅。

作为回报，发布者可以通过调用订阅者的`onNext()`方法将新项目传递给订阅者。当不再有数据到来时（源中的所有数据都已发出），发布者调用订阅者的`onComplete()`方法。另外，通过调用订阅者的`onError()`方法，发布者可以告诉订阅者它遇到了问题

`Flow.Processor`接口描述了一个既可以充当订阅者又可以充当发布者的实体。它允许创建此类处理器的链（管道），以便订阅者可以从发布者接收项目，对其进行转换，然后将结果传递给下一个订阅者或处理器。

在推送模式中，发布者可以在没有来自订户的任何请求的情况下调用`onNext()`。如果处理速度低于项目发布速度，订阅者可以使用各种策略来缓解压力。例如，它可以跳过项目或为临时存储创建一个缓冲区，希望项目生产速度会减慢，订户能够赶上

这是 ReactiveStreams 计划为支持具有非阻塞背压的异步数据流而定义的最小接口集。如您所见，它允许订阅者和发布者相互交谈并协调传入数据的速率，从而为我们在“反应式”部分讨论的背压问题提供了多种解决方案。

有许多方法可以实现这些接口。目前，在 JDK9 中，只有一个接口的实现：`SubmissionPublisher`类实现了`Flow.Publisher`。原因是这些接口不应该由应用开发人员使用。它是一个**服务提供者接口**（**SPI**），由反应流库的开发人员使用。如果需要的话，可以使用已经实现了我们已经提到的 ReactiveStreamsAPI 的现有工具箱之一：RxJava、Reactor、Akka Streams、Vert.x 或任何其他您喜欢的库。

# RxJava 

我们将使用 [**RxJava2.2.7**](http://reactivex.io) 在我们的例子中。可以通过以下依赖项将其添加到项目中：

```java
<dependency>
    <groupId>io.reactivex.rxjava2</groupId>
    <artifactId>rxjava</artifactId>
    <version>2.2.7</version>
</dependency>
```

我们首先比较一下使用`java.util.stream`包和`io.reactivex`包实现相同功能的两个实现。示例程序将非常简单：

*   创建整数流`1`、`2`、`3`、`4`、`5`。
*   只过滤偶数（`2`和`4`）。
*   计算每个过滤后数字的平方根。
*   计算所有平方根的和。

下面是如何使用`java.util.stream`包实现的：

```java
double a = IntStream.rangeClosed(1, 5)
                    .filter(i -> i % 2 == 0)
                    .mapToDouble(Double::valueOf)
                    .map(Math::sqrt)
                    .sum();
System.out.println(a);          //prints: 3.414213562373095

```

使用 RxJava 实现的相同功能如下所示：

```java
Observable.range(1, 5)
          .filter(i -> i % 2 == 0)
          .map(Math::sqrt)
          .reduce((r, d) -> r + d)
          .subscribe(System.out::println);   //prints: 3.414213562373095

```

RxJava 基于`Observable`对象（扮演`Publisher`角色）和`Observer`，订阅`Observable`并等待数据发出。

相比之下，对于`Stream`功能，`Observable`具有显著不同的功能。例如，流一旦关闭，就不能重新打开，`Observable`对象可以再次使用。举个例子：

```java
Observable<Double> observable = Observable.range(1, 5)
        .filter(i -> i % 2 == 0)
        .doOnNext(System.out::println)    //prints 2 and 4 twice
        .map(Math::sqrt);
observable
        .reduce((r, d) -> r + d)
        .subscribe(System.out::println);  //prints: 3.414213562373095
observable
        .reduce((r, d) -> r + d)
        .map(r -> r / 2)
        .subscribe(System.out::println);  //prints: 1.7071067811865475

```

在前面的示例中，您可以从注释中看到，`doOnNext()`操作被调用了两次，这意味着可观察对象发出了两次值，每个处理管道一次：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/2b3e4ceb-c446-4905-b64c-9a2002794eaf.png)

如果我们不想让`Observable`运行两次，我们可以通过添加`cache()`操作来缓存它的数据：

```java
Observable<Double> observable = Observable.range(1,5)
        .filter(i -> i % 2 == 0)
        .doOnNext(System.out::println)  //prints 2 and 4 only once
        .map(Math::sqrt)
        .cache();
observable
        .reduce((r, d) -> r + d)
        .subscribe(System.out::println); //prints: 3.414213562373095
observable
        .reduce((r, d) -> r + d)
        .map(r -> r / 2)
        .subscribe(System.out::println);  //prints: 1.7071067811865475

```

如您所见，相同的`Observable`的第二次使用利用了缓存的数据，因此允许更好的性能：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/42bd8994-6da4-4a6a-b67d-cc7283c7abdb.png)

RxJava 提供了如此丰富的功能，我们无法在本书中详细地回顾它。相反，我们将尝试介绍最流行的 API。API 描述了可使用`Observable`对象调用的方法。此类方法通常也称为**操作**（与标准 Java8 流的情况一样）或**操作符**（主要用于反应流）。我们将使用这三个术语、方法、操作和运算符作为同义词

# 可观察对象的类型

谈到 RxJava2API（请注意，它与 RxJava1 有很大的不同），我们将使用可以在[这个页面](http://reactivex.io/RxJava/2.x/javadoc/index.html)中找到的在线文档。

观察者订阅接收来自可观察对象的值，该对象可以表现为以下类型之一：

*   **阻塞**：等待结果返回
*   **非阻塞**：异步处理所发射的元素
*   **冷**：根据观察者的要求发射一个元素
*   **热**：无论观察者是否订阅，发射元素

可观察对象可以是`io.reactivex `包的以下类别之一的对象：

*   `Observable<T>`：可以不发射、一个或多个元素；不支持背压。
*   `Flowable<T>`：可以不发射、一个或多个元素；支持背压。
*   `Single<T>`：可以发出一个元素或错误；背压的概念不适用。
*   `Maybe<T>`：表示延迟计算；可以不发出值、一个值或错误；背压的概念不适用。
*   `Completable`：表示没有任何值的延迟计算；表示任务完成或错误；背压的概念不适用。

这些类中的每一个的对象都可以表现为阻塞、非阻塞、冷或热可观察。它们的不同之处在于可以发出的值的数量、延迟返回结果的能力或仅返回任务完成标志的能力，以及它们处理背压的能力。

# 阻塞与非阻塞

为了演示这种行为，我们创建了一个可观察的对象，它发出五个连续整数，从`1`开始：

```java
Observable<Integer> obs = Observable.range(1,5);
```

`Observable`的所有阻塞方法（操作符）都以“阻塞”开头，所以`blockingLast()`是阻塞操作符之一，阻塞管道直到最后一个元素被释放：

```java
Double d2 = obs.filter(i -> i % 2 == 0)
               .doOnNext(System.out::println)  //prints 2 and 4
               .map(Math::sqrt)
               .delay(100, TimeUnit.MILLISECONDS)
               .blockingLast();
System.out.println(d2);                        //prints: 2.0
```

在本例中，我们只选择偶数，打印所选元素，然后计算平方根并等待 100 毫秒（模拟长时间运行的计算）。此示例的结果如下所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/ac98bac3-67c0-4610-927e-192d877e2d95.png)

相同功能的非阻塞版本如下所示：

```java
List<Double> list = new ArrayList<>();
obs.filter(i -> i % 2 == 0)
   .doOnNext(System.out::println)  //prints 2 and 4
   .map(Math::sqrt)
   .delay(100, TimeUnit.MILLISECONDS)
   .subscribe(d -> {
        if(list.size() == 1){
            list.remove(0);
        }
        list.add(d);
   });
System.out.println(list);          //prints: []

```

我们使用`List`对象来捕获结果，因为您可能还记得，Lambda 表达式不允许使用非`final`变量。

如您所见，结果列表为空。这是因为执行管道计算时没有阻塞（异步）。因此，由于 100 毫秒的延迟，控件同时转到打印列表内容的最后一行，该行仍然是空的。我们可以在最后一行前面设置延迟：

```java
try {
    TimeUnit.MILLISECONDS.sleep(200);
} catch (InterruptedException e) {
    e.printStackTrace();
}
System.out.println(list);   //prints: [2.0]
```

延迟必须至少为 200ms，因为管道处理两个元素，每个元素的延迟为 100ms。现在，如您所见，该列表包含一个期望值`2.0`

这基本上就是阻塞运算符和非阻塞运算符之间的区别。其他表示可观察对象的类也有类似的阻塞运算符。下面是阻塞`Flowable`、`Single`和`Maybe`的示例：

```java
Flowable<Integer> obs = Flowable.range(1,5);
Double d2 = obs.filter(i -> i % 2 == 0)
        .doOnNext(System.out::println)  //prints 2 and 4
        .map(Math::sqrt)
        .delay(100, TimeUnit.MILLISECONDS)
        .blockingLast();
System.out.println(d2);                 //prints: 2.0

Single<Integer> obs2 = Single.just(42);
int i2 = obs2.delay(100, TimeUnit.MILLISECONDS).blockingGet();
System.out.println(i2);                 //prints: 42

Maybe<Integer> obs3 = Maybe.just(42); 
int i3 = obs3.delay(100, TimeUnit.MILLISECONDS).blockingGet(); 
System.out.println(i3);                 //prints: 42 

```

`Completable`类具有允许设置超时的阻塞运算符：

```java
(1) Completable obs = Completable.fromRunnable(() -> {
            System.out.println("Running...");       //prints: Running...
            try {
                TimeUnit.MILLISECONDS.sleep(200);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
    });                                           
(2) Throwable ex = obs.blockingGet();
(3) System.out.println(ex);                               //prints: null

//(4) ex = obs.blockingGet(15, TimeUnit.MILLISECONDS);
//                                java.util.concurrent.TimeoutException: 
//               The source did not signal an event for 15 milliseconds.

(5) ex = obs.blockingGet(150, TimeUnit.MILLISECONDS);
(6) System.out.println(ex);                               //prints: null

(7) obs.blockingAwait();
(8) obs.blockingAwait(15, TimeUnit.MILLISECONDS);
```

上述代码的结果显示在以下屏幕截图中：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/e4317b1f-255b-43df-8fd5-c4cdf0986b28.png)

第一条运行消息来自第 2 行，响应阻塞`blockingGet()`方法的调用。第一条空消息来自第 3 行。第 4 行抛出异常，因为超时设置为 15 毫秒，而实际处理设置为 100 毫秒延迟。第二条运行消息来自第 5 行，响应于`blockingGet()`方法调用。这一次，超时被设置为 150 毫秒，也就是超过 100 毫秒，并且该方法能够在超时结束之前返回。

最后两行（7 和 8）演示了有无超时的`blockingAwait()`方法的用法。此方法不返回值，但允许可观察管道运行其过程。有趣的是，即使将超时设置为小于管道完成所需时间的值，它也不会因异常而中断。显然，它是在管道处理完成之后开始等待的，除非它是一个稍后将被修复的缺陷（文档对此并不清楚）。

尽管存在阻塞操作（我们将在下面的章节中讨论每种可观察的类型时对这些操作进行更多的回顾），但是它们仅在不可能仅使用非阻塞操作实现所需功能的情况下使用。反应式编程的主要目的是努力以非阻塞方式异步处理所有请求

# 冷还是热

到目前为止，我们看到的所有示例都只演示了一个可观察的*冷*，即那些仅在处理前一个值已经被处理之后，才应处理管道的请求提供下一个值的示例。下面是另一个例子：

```java
Observable<Long> cold = Observable.interval(10, TimeUnit.MILLISECONDS);
cold.subscribe(i -> System.out.println("First: " + i));
pauseMs(25);
cold.subscribe(i -> System.out.println("Second: " + i));
pauseMs(55);

```

我们已经使用方法`interval()`创建了一个`Observable`对象，该对象表示每个指定间隔（在我们的例子中，每 10ms）发出的序列号流。然后我们订阅创建的对象，等待 25ms，再次订阅，再等待 55ms，`pauseMs()`方法如下：

```java
void pauseMs(long ms){
    try {
        TimeUnit.MILLISECONDS.sleep(ms);
    } catch (InterruptedException e) {
        e.printStackTrace();
    }
}
```

如果我们运行前面的示例，输出将如下所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/421f6075-29e9-431d-a237-b23f737c0c48.png)

正如您所看到的，每个管道都处理了冷可观察到的辐射的每个值。

为了将*冷*可观察物转换成*热*可观察物，我们使用`publish()`方法将可观察物转换成扩展`Observable`的`ConnectableObservable`对象：

```java
ConnectableObservable<Long> hot = 
         Observable.interval(10, TimeUnit.MILLISECONDS).publish();
hot.connect();
hot.subscribe(i -> System.out.println("First: " + i));
pauseMs(25);
hot.subscribe(i -> System.out.println("Second: " + i));
pauseMs(55);

```

如您所见，我们必须调用`connect()`方法，以便`ConnectableObservable`对象开始发出值。输出如下所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/181c6ce4-39f7-4f26-a8af-5239bd2a8872.png)

输出显示第二个管道没有收到前三个值，因为它订阅了后面的可观察对象。因此，可观察物发出的值与观察者处理它们的能力无关。如果处理落后，并且新的值不断出现，而之前的值还没有完全处理完，`Observable`类将它们放入缓冲区。如果这个缓冲区足够大，JVM 可能会耗尽内存，因为正如我们已经提到的，`Observable`类没有背压管理的能力。

在这种情况下，`Flowable`类是可观察的更好的候选对象，因为它确实具有处理背压的能力。举个例子：

```java
PublishProcessor<Integer> hot = PublishProcessor.create();
hot.observeOn(Schedulers.io(), true)
   .subscribe(System.out::println, Throwable::printStackTrace);
for (int i = 0; i < 1_000_000; i++) {
    hot.onNext(i);
}
```

`PublishProcessor`类扩展了`Flowable`，并有`onNext(Object o)`方法强制它发出传入的对象。在调用它之前，我们已经使用`Schedulers.io()`线程订阅了`observate`。我们将在“多线程（调度器）”部分讨论调度器。

`subscribe()`方法有几个重载版本。我们决定使用一个接受两个`Consumer`函数的函数：第一个处理传入的值，第二个处理由任何管道操作引发的异常（类似于`Catch`块）。

如果我们运行前面的示例，它将成功打印前 127 个值，然后抛出`MissingBackpressureException`，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/075795f4-e2cd-4e7d-aef1-ddf815a51a4d.png)

异常中的消息提供了一个线索：`Could not emit value due to lack of requests`。显然，这些值的发射率高于消耗率，内部缓冲区只能保存 128 个元素。如果我们增加延迟（模拟更长的处理时间），结果会更糟：

```java
PublishProcessor<Integer> hot = PublishProcessor.create();
hot.observeOn(Schedulers.io(), true)
   .delay(10, TimeUnit.MILLISECONDS)
   .subscribe(System.out::println, Throwable::printStackTrace);
for (int i = 0; i < 1_000_000; i++) {
    hot.onNext(i);
}
```

即使是前 128 个元素也无法通过，输出只有`MissingBackpressureException`

为了解决这个问题，必须制定背压策略。例如，让我们删除管道无法处理的每个值：

```java
PublishProcessor<Integer> hot = PublishProcessor.create();
hot.onBackpressureDrop(v -> System.out.println("Dropped: "+ v))
   .observeOn(Schedulers.io(), true)
   .subscribe(System.out::println, Throwable::printStackTrace);
for (int i = 0; i < 1_000_000; i++) {
    hot.onNext(i);
}
```

注意，策略必须在`observeOn()`操作之前设置，因此它将被创建的`Schedulers.io()`线程拾取。

输出显示许多发出的值被丢弃。下面是一个输出片段：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/197a7e6c-92a4-4e63-ad5b-add6ec985939.png)

我们将在“操作符”一节中相应操作符的概述中讨论其他背压策略。

# 可处理对象

请注意，`subscribe()`方法实际上返回一个`Disposable`对象，可以查询该对象来检查管道处理是否已完成（并已处理）：

```java
Observable<Integer> obs = Observable.range(1,5);
List<Double> list = new ArrayList<>();
Disposable disposable =
     obs.filter(i -> i % 2 == 0)
        .doOnNext(System.out::println)     //prints 2 and 4
        .map(Math::sqrt)
        .delay(100, TimeUnit.MILLISECONDS)
        .subscribe(d -> {
            if(list.size() == 1){
                list.remove(0);
            }
            list.add(d);
        });
System.out.println(list);                    //prints: []
System.out.println(disposable.isDisposed()); //prints: false
try {
    TimeUnit.MILLISECONDS.sleep(200);
} catch (InterruptedException e) {
    e.printStackTrace();
}
System.out.println(disposable.isDisposed());  //prints: true
System.out.println(list);                     //prints: [2.0]
```

还可以强制处理管道，从而有效地取消处理：

```java
Observable<Integer> obs = Observable.range(1,5);
List<Double> list = new ArrayList<>();
Disposable disposable =
     obs.filter(i -> i % 2 == 0)
        .doOnNext(System.out::println)       //prints 2 and 4
        .map(Math::sqrt)
        .delay(100, TimeUnit.MILLISECONDS)
        .subscribe(d -> {
            if(list.size() == 1){
                list.remove(0);
            }
            list.add(d);
        });
System.out.println(list);                    //prints: []
System.out.println(disposable.isDisposed()); //prints: false
disposable.dispose();
try {
    TimeUnit.MILLISECONDS.sleep(200);
} catch (InterruptedException e) {
    e.printStackTrace();
}
System.out.println(disposable.isDisposed()); //prints: true
System.out.println(list);                    //prints: []
```

如您所见，通过添加对`disposable.dispose()`的调用，我们已经停止了处理：列表内容，即使经过 200 毫秒的延迟，仍然是空的（前面示例的最后一行）。

这种强制处理方法可以用来确保没有失控的线程。每个创建的`Disposable`对象都可以按照`finally`块中释放资源的相同方式进行处理。`CompositeDisposable`类帮助以协调的方式处理多个`Disposable`对象。

当`onComplete`或`onError`事件发生时，管道自动处理。

例如，您可以使用`add()`方法，将新创建的`Disposable`对象添加到`CompositeDisposable`对象中。然后，必要时，可以对`CompositeDisposable`对象调用`clear()`方法。它将删除收集的`Disposable`对象，并对每个对象调用`dispose()`方法。

# 创建可观察对象

在我们的示例中，您已经看到了一些创建可观察对象的方法。在`Observable`、`Flowable`、`Single`、`Maybe`和`Completable`中还有许多其他工厂方法。但并不是所有下列方法都可以在这些接口中使用（参见注释；*所有*表示所有列出的接口都有它）：

*   `create()`：通过提供完整实现（所有）创建一个`Observable`对象
*   `defer()`：每次订阅一个新的`Observer`时创建一个新的`Observable`对象（所有）
*   `empty()`：创建一个空的`Observable`对象，该对象在订阅后立即完成（除`Single`外的所有对象）
*   `never()`：创建一个`Observable`对象，它不发射任何东西，也不做任何事情；甚至不完成（所有）
*   `error()`：创建一个`Observable`对象，该对象在订阅时立即发出异常（所有）
*   `fromXXX()`：创建一个`Observable`对象，其中`XXX`可以为`Callable`、`Future`（所有）、`Iterable`、`Array`、`Publisher`（`Observable`和`Flowable`、`Action`、`Runnable`（`Maybe`和`Completable`）；这意味着它基于提供的函数或对象创建一个`Observable`对象
*   `generate()`：创建一个冷`Observable`对象，该对象基于提供的函数或对象生成值（仅限`Observable`和`Flowable`）
*   `range(), rangeLong(), interval(), intervalRange()`：创建一个`Observable`对象，该对象发出连续的`int`或`long`值，这些值受指定范围的限制或不受指定时间间隔的限制（仅限`Observable`和`Flowable`）
*   `just()`：根据提供的对象或一组对象（除`Completable`外的所有对象）创建一个`Observable`对象
*   `timer()`：创建一个`Observable`对象，该对象在指定的时间之后发出`0L`信号（所有），然后完成`Observable`和`Flowable`的操作

还有许多其他有用的方法，如`repeat()`、`startWith()`等。我们只是没有足够的空间来列出它们。[参考在线文档](http://reactivex.io/RxJava/2.x/javadoc/index.html)。

让我们看一个`create()`方法用法的例子。`Observable`的`create()`方法如下：

```java
public static Observable<T> create(ObservableOnSubscribe<T> source)
```

传入的对象必须是函数式接口`ObservableOnSubscribe<T>`的实现，它只有一个抽象方法`subscribe()`：

```java
void subscribe(ObservableEmitter<T> emitter)
```

`ObservableEmitter<T>`接口包含以下方法：

*   `boolean isDisposed()`：如果处理管道被处理或发射器被终止，则返回`true`
*   `ObservableEmitter<T> serialize()`：提供基类`Emitter`中`onNext()`、`onError()`、`onComplete()`调用使用的序列化算法
*   `void setCancellable(Cancellable c)`：在这个发射器上设置`Cancellable`实现（只有一个方法`cancel()`的函数式接口）
*   `void setDisposable(Disposable d)`：在这个发射器上设置`Disposable`实现（有`isDispose()`和`dispose()`两种方法的接口）
*   `boolean tryOnError(Throwable t)`：处理错误条件，尝试发出提供的异常，如果不允许发出则返回`false`

为了创建一个可观察的接口，所有前面的接口可以实现如下：

```java
ObservableOnSubscribe<String> source = emitter -> {
    emitter.onNext("One");
    emitter.onNext("Two");
    emitter.onComplete();
};
Observable.create(source)
          .filter(s -> s.contains("w"))
          .subscribe(v -> System.out.println(v),
                     e -> e.printStackTrace(),
                     () -> System.out.println("Completed"));
pauseMs(100); 
```

让我们更仔细地看一下前面的例子。我们创建了一个`ObservableOnSubscribe`函数`source`并实现了发射器：我们让发射器在第一次调用`onNext()`时发出一个，在第二次调用`onNext()`时发出两个，然后再调用`onComplete()`。我们将`source`函数传递到`create()`方法中，并构建管道来处理所有发出的值。

为了让它更有趣，我们添加了`filter()`操作符，它只允许进一步传播具有`w`字符的值。我们还选择了具有三个参数的`subscribe()`方法版本：函数`Consumer onNext`、`Consumer onError`和`Action onComplete`。第一个在每次到达方法的下一个值时调用，第二个在发出异常时调用，第三个在源发出`onComplete()`信号时调用。在创建管道之后，我们暂停了 100 毫秒，以便让异步进程有机会完成。结果如下：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/ad0c62da-98d3-409b-8430-1d78e719a219.png)

如果我们从发射器实现中删除行`emitter.onComplete()`，则只会显示消息 2。

这些是如何使用`create()`方法的基础。如您所见，它允许完全定制。在实践中，它很少被使用，因为有许多更简单的方法来创建一个可观察的。我们将在以下几节中对它们进行回顾。

您将在本章其他部分的示例中看到其他工厂方法的示例。

# 运算符

在每一个可观察的接口中，`Observable`、`Flowable`、`Single`、`Maybe`或`Completable`都有成百上千（如果我们计算所有重载版本）的操作符可用

在`Observable`和`Flowable`中，方法的数量超过 500 个。这就是为什么在本节中，我们将提供一个概述和几个例子，帮助读者浏览可能的选项迷宫。

为了帮助了解全局，我们将所有操作符分为十类：转换、过滤、组合、从 XXX 转换、异常处理、生命周期事件处理、工具、条件和布尔、背压和可连接。

请注意，这些不是所有可用的运算符。您可以在[在线文档](http://reactivex.io/RxJava/2.x/javadoc/index.html)中看到更多信息。

# 转化

这些运算符转换可观察对象发出的值：

*   `buffer()`：根据提供的参数或使用提供的函数将发出的值收集到包裹中，并定期一次发出一个包裹
*   `flatMap()`：基于当前可观察对象生成可观察对象，并将其插入到当前流中，这是最流行的操作符之一
*   `groupBy()`：将当前`Observable`分为若干组可观察对象（`GroupedObservables`个对象）
*   `map()`：使用提供的函数转换发出的值
*   `scan()`：将所提供的函数应用于每个值，并结合先前将相同函数应用于先前值所产生的值
*   `window()`：发出一组类似于`buffer()`但作为可观察对象的值，每个值都发出原始可观察对象的一个子集，然后以`onCompleted()`结束

下面的代码演示了`map()`、`flatMap()`和`groupBy()`的用法：

```java
Observable<String> obs = Observable.fromArray("one", "two");

obs.map(s -> s.contains("w") ? 1 : 0)
   .forEach(System.out::print);              //prints: 01

List<String> os = new ArrayList<>();
List<String> noto = new ArrayList<>();
obs.flatMap(s -> Observable.fromArray(s.split("")))
        .groupBy(s -> "o".equals(s) ? "o" : "noto")
        .subscribe(g -> g.subscribe(s -> {
            if (g.getKey().equals("o")) {
                os.add(s);
            } else {
                noto.add(s);
            }
        }));
System.out.println(os);                  //prints: [o, o]
System.out.println(noto);                //prints: [n, e, t, w]
```

# 过滤

以下运算符（及其多个重载版本）选择哪些值将继续流经管道：

*   `debounce()`：仅当指定的时间跨度已过而可观察到的对象未发出另一个值时才发出一个值
*   `distinct()`：仅选择唯一值
*   `elementAt(long n)`：只在流中指定的`n`位置发出一个值
*   `filter()`：仅发出符合指定条件的值
*   `firstElement()`：仅发射第一个值
*   `ignoreElements()`：不发数值，只有`onComplete()`信号通过
*   `lastElement()`：仅发出最后一个值
*   `sample()`：发出指定时间间隔内发出的最新值
*   `skip(long n)`：跳过第一个`n`值
*   `take(long n)`：只发出第一个`n`值

以下是刚刚列出的一些运算符的用法示例：

```java
Observable<String> obs = Observable.just("onetwo")
        .flatMap(s -> Observable.fromArray(s.split("")));
// obs emits "onetwo" as characters           
obs.map(s -> {
            if("t".equals(s)){
               NonBlockingOperators.pauseMs(15);
            }
            return s;
        })
        .debounce(10, TimeUnit.MILLISECONDS)
        .forEach(System.out::print);               //prints: eo
obs.distinct().forEach(System.out::print);         //prints: onetw
obs.elementAt(3).subscribe(System.out::println);   //prints: t
obs.filter(s -> s.equals("o"))
   .forEach(System.out::print);                    //prints: oo
obs.firstElement().subscribe(System.out::println); //prints: o
obs.ignoreElements().subscribe(() -> 
       System.out.println("Completed!"));          //prints: Completed!
Observable.interval(5, TimeUnit.MILLISECONDS)
   .sample(10, TimeUnit.MILLISECONDS)
   .subscribe(v -> System.out.print(v + " "));     //prints: 1 3 4 6 8 
pauseMs(50);

```

# 连接

以下运算符（及其多个重载版本）使用多个源可观察对象创建新的可观察对象：

*   `concat(src1, src2)`：创建一个`Observable`发出`src1`的所有值，然后将`src2`的所有值全部释放出来
*   `combineLatest(src1, src2, combiner)`：创建一个`Observable`，该值由两个源中的任何一个发出，并使用提供的函数组合器将每个源发出的最新值组合起来
*   `join(src2, leftWin, rightWin, combiner)`：根据`combiner`函数，将`leftWin`和`rightWin`时间窗内两个可见光发射的值合并
*   `merge()`：将多个可观察对象合并为一个可观察对象，与`concat()`不同的是，它可以对多个可观察对象进行合并，而`concat()`从不对不同可观察对象的发射值进行合并
*   `startWith(T item)`：在从可观察源发出值之前，添加指定值
*   `startWith(Observable<T> other)`：在从源可观察对象发出值之前，将指定可观察对象的值相加
*   `switchOnNext(Observable<Observable> observables)`：创建一个新的`Observable`，该新的`Observable`发出指定可观察对象的最近发出的值
*   `zip()`：使用提供的函数组合指定的可观察对象

以下代码演示了其中一些运算符的使用：

```java
Observable<String> obs1 = Observable.just("one")
                      .flatMap(s -> Observable.fromArray(s.split("")));
Observable<String> obs2 = Observable.just("two")
                      .flatMap(s -> Observable.fromArray(s.split("")));
Observable.concat(obs2, obs1, obs2)
          .subscribe(System.out::print);             //prints: twoonetwo
Observable.combineLatest(obs2, obs1, (x,y) -> "("+x+y+")")
          .subscribe(System.out::print);          //prints: (oo)(on)(oe)
System.out.println();
obs1.join(obs2, i -> Observable.timer(5, TimeUnit.MILLISECONDS),
                i -> Observable.timer(5, TimeUnit.MILLISECONDS),
              (x,y) -> "("+x+y+")").subscribe(System.out::print); 
                          //prints: (ot)(nt)(et)(ow)(nw)(ew)(oo)(no)(eo)
Observable.merge(obs2, obs1, obs2)
          .subscribe(System.out::print);             //prints: twoonetwo
obs1.startWith("42")
    .subscribe(System.out::print); //prints: 42one
Observable.zip(obs1, obs2, obs1,  (x,y,z) -> "("+x+y+z+")")
          .subscribe(System.out::print);       //prints: (oto)(nwn)(eoe) 
```

# 从`XXX`转换

这些运算符非常简单。以下是`Observable`类的从`XXX`转换操作符列表：

*   `fromArray(T... items)`：从可变参数创建`Observable`
*   `fromCallable(Callable<T> supplier)`：从`Callable`函数创建`Observable`
*   `fromFuture(Future<T> future)`：从`Future`对象创建`Observable`
*   `fromFuture(Future<T> future, long timeout, TimeUnit unit)`：从`Future`对象创建`Observable`，超时参数应用于`future`
*   `fromFuture(Future<T> future, long timeout, TimeUnit unit, Scheduler scheduler)`：从`Future`对象创建`Observable`，超时参数应用于`future`和调度器（建议使用`Schedulers.io()`，请参阅“多线程（调度器）”部分）
*   `fromFuture(Future<T> future, Scheduler scheduler)`：从指定调度器上的`Future`对象创建一个`Observable`（`Schedulers.io()`推荐，请参阅“多线程（调度器）”部分）
*   `fromIterable(Iterable<T> source)`：从可迭代对象创建`Observable`（例如`List`）
*   `fromPublisher(Publisher<T> publisher)`：从`Publisher`对象创建`Observable`

# 异常处理

`subscribe()`操作符有一个重载版本，它接受处理管道中任何地方引发的异常的`Consumer<Throwable>`函数。它的工作原理类似于包罗万象的`try-catch`块。如果您将这个函数传递给`subscribe()`操作符，您可以确定这是所有异常结束的唯一地方。

但是，如果您需要在管道中间处理异常，以便值流可以由引发异常的操作符之后的其他操作符恢复和处理，那么以下操作符（及其多个重载版本）可以帮助您：

*   `onErrorXXX()`：捕捉到异常时恢复提供的序列；`XXX`表示运算符的操作：`onErrorResumeNext()`、`onErrorReturn()`或`onErrorReturnItem()`
*   `retry()`：创建一个`Observable`，重复源发出的发射；如果调用`onError()`，则重新订阅源`Observable`

演示代码如下所示：

```java
Observable<String> obs = Observable.just("one")
                     .flatMap(s -> Observable.fromArray(s.split("")));
Observable.error(new RuntimeException("MyException"))
          .flatMap(x -> Observable.fromArray("two".split("")))
          .subscribe(System.out::print,
           e -> System.out.println(e.getMessage())//prints: MyException
          );
Observable.error(new RuntimeException("MyException"))
          .flatMap(y -> Observable.fromArray("two".split("")))
          .onErrorResumeNext(obs)
          .subscribe(System.out::print);          //prints: one
Observable.error(new RuntimeException("MyException"))
          .flatMap(z -> Observable.fromArray("two".split("")))
          .onErrorReturnItem("42")
          .subscribe(System.out::print);          //prints: 42

```

# 生命周期事件处理

这些操作符在管道中任何位置发生的特定事件上都被调用。它们的工作方式类似于“处理”部分中描述的操作符。

这些操作符的格式是`doXXX()`，其中`XXX`是事件的名称：`onComplete`、`onNext`、`onError`等。并不是所有的类都有，有些类在`Observable`、`Flowable`、`Single`、`Maybe`或`Completable`上略有不同。但是，我们没有空间列出所有这些类的所有变体，我们的概述将局限于`Observable`类的生命周期事件处理操作符的几个示例：

*   `doOnSubscribe(Consumer<Disposable> onSubscribe)`：当观察者订阅时执行
*   `doOnNext(Consumer<T> onNext)`：当源可观测调用`onNext`时，应用提供的`Consumer`功能
*   `doAfterNext(Consumer<T> onAfterNext)`：将提供的`Consumer`功能推送到下游后应用于当前值
*   `doOnEach(Consumer<Notification<T>> onNotification)`：对每个发出的值执行`Consumer`函数
*   `doOnEach(Observer<T> observer)`：为每个发出的值及其发出的终端事件通知一个`Observer`
*   `doOnComplete(Action onComplete)`：在源可观察对象生成`onComplete`事件后，执行提供的`Action`函数
*   `doOnDispose(Action onDispose)`：管道被下游处理后执行提供的`Action`功能
*   `doOnError(Consumer<Throwable> onError)`：发送`onError`事件时执行
*   `doOnLifecycle(Consumer<Disposable> onSubscribe, Action onDispose)`：对相应的事件调用相应的`onSubscribe`或`onDispose`函数
*   `doOnTerminate(Action onTerminate)`：当源可观测对象生成`onComplete`事件或引发异常（`onError`事件）时，执行提供的`Action`函数
*   `doAfterTerminate(Action onFinally)`：在源可观测对象生成`onComplete`事件或引发异常（`onError`事件）后，执行提供的`Action`函数
*   `doFinally(Action onFinally)`：在源可观测对象生成`onComplete`事件或引发异常（`onError`事件）或下游处理管道后，执行提供的`Action`函数

下面是演示代码：

```java
Observable<String> obs = Observable.just("one")
            .flatMap(s -> Observable.fromArray(s.split("")));

obs.doOnComplete(() -> System.out.println("Completed!")) 
        .subscribe(v -> {
            System.out.println("Subscribe onComplete: " + v);
        });        
pauseMs(25);
```

如果我们运行此代码，输出将如下所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/19b14d2a-6ff5-410c-9a67-515f8943a2e6.png)

您还将在“多线程（调度器）”部分中看到这些运算符用法的其他示例。

# 公共操作

可以使用各种有用的操作符（及其多个重载版本）来控制管道行为：

*   `delay()`：将发射延迟一段时间
*   `materialize()`：创建一个`Observable`，它表示发出的值和发送的通知
*   `dematerialize()`：反转`materialize()`运算符的结果
*   `observeOn()`：指定`Observer`应遵守`Observable`的`Scheduler`（螺纹）（见“多线程（调度器）”部分）
*   `serialize()`：强制序列化发出的值和通知
*   `subscribe()`：订阅一个可观测对象的发射和通知；各种重载版本接受用于各种事件的回调，包括`onComplete`、`onError`；只有在调用`subscribe()`之后，值才开始流经管道
*   `subscribeOn()`：使用指定的`Scheduler`异步订阅`Observer`到`Observable`（参见“多线程（调度器）”部分）
*   `timeInterval(), timestamp()`：将发出值的`Observable<T>`转换为`Observable<Timed<T>>`，然后相应地发出两次发射之间经过的时间量或时间戳
*   `timeout()`：重复源`Observable`的发射；如果在指定的时间段后没有发射，则生成错误
*   `using()`：创建一个与`Observable`一起自动处理的资源；工作方式类似于资源尝试构造

下面的代码包含一些在管道中使用的操作符的示例：

```java
Observable<String> obs = Observable.just("one")
                     .flatMap(s -> Observable.fromArray(s.split("")));
obs.delay(5, TimeUnit.MILLISECONDS)
   .subscribe(System.out::print);                          //prints: one
pauseMs(10);
System.out.println(); //used here just to break the line
Observable source = Observable.range(1,5);
Disposable disposable = source.subscribe();
Observable.using(
  () -> disposable,
  x -> source,
  y -> System.out.println("Disposed: " + y) //prints: Disposed: DISPOSED
)
.delay(10, TimeUnit.MILLISECONDS)
.subscribe(System.out::print);                          //prints: 12345
pauseMs(25);
```

如果我们运行所有这些示例，输出将如下所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/aa7ef37f-6ec1-44af-84c3-dffe282f2508.png)

如您所见，管道完成后，会将处理后的信号发送给`using`操作符（第三个参数），因此我们作为第三个参数传递的`Consumer`函数可以处理管道使用的资源

# 条件与布尔

以下运算符（及其多个重载版本）允许求值一个或多个可观察对象或发射值，并相应地更改处理逻辑：

*   `all(Predicate criteria)`：返回`Single<Boolean>`和`true`值，如果所有发出的值都符合提供的条件
*   `amb()`：接受两个或多个源可观察对象，并仅从第一个开始发射的源可观察对象发射值
*   `contains(Object value)`：如果被观察物发出所提供的值，则返回`Single<Boolean>`和`true`
*   `defaultIfEmpty(T value)`：如果源`Observable`没有发出任何东西，则发出提供的值
*   `sequenceEqual()`：如果提供的源发出相同的序列，则返回`Single<Boolean>`和`true`；重载版本允许提供用于比较的相等函数
*   `skipUntil(Observable other)`：丢弃发出的值，直到提供的`Observable other`发出值为止
*   `skipWhile(Predicate condition)`：只要所提供的条件保持`true`，则丢弃发射值
*   `takeUntil(Observable other)`：在提供的`Observable other`发出值之后丢弃发出的值
*   `takeWhile(Predicate condition)`：在提供的条件变成`false`后丢弃发射值

此代码包含几个演示示例：

```java
Observable<String> obs = Observable.just("one")
                  .flatMap(s -> Observable.fromArray(s.split("")));
Single<Boolean> cont = obs.contains("n");
System.out.println(cont.blockingGet());             //prints: true
obs.defaultIfEmpty("two")
   .subscribe(System.out::print);                   //prints: one
Observable.empty().defaultIfEmpty("two")
          .subscribe(System.out::print);            //prints: two

Single<Boolean> equal = Observable.sequenceEqual(obs, 
                                 Observable.just("one"));
System.out.println(equal.blockingGet());            //prints: false

equal = Observable.sequenceEqual(Observable.just("one"), 
                                 Observable.just("one"));
System.out.println(equal.blockingGet());           //prints: true

equal = Observable.sequenceEqual(Observable.just("one"), 
                                 Observable.just("two"));
System.out.println(equal.blockingGet());           //prints: false

```

# 背压

我们在“冷与热”一节讨论并论证了**背压**效应和可能的下降策略。另一种策略如下：

```java
Flowable<Double> obs = Flowable.fromArray(1.,2.,3.);
obs.onBackpressureBuffer().subscribe();
//or
obs.onBackpressureLatest().subscribe();
```

缓冲策略允许定义缓冲区大小，并提供在缓冲区溢出时可以执行的函数。最新的策略告诉值生产者暂停（当消费者不能及时处理发出的值时），并根据请求发出下一个值。

背压操作器仅在`Flowable`类中可用。

# 连接

此类运算符允许连接可观察对象，从而实现更精确控制的订阅动态：

*   `publish()`：将`Observable`对象转换为`ConnectableObservable`对象
*   `replay()`：返回一个`ConnectableObservable`对象，该对象在每次订阅新的`Observer`时重复所有发出的值和通知
*   `connect()`：指示`ConnectableObservable`开始向订户发送值
*   `refCount()`：将`ConnectableObservable`转换为`Observable`

我们已经演示了`ConnectableObservable`如何在“冷与热”部分工作。`ConnectiableObservable`和`Observable`之间的一个主要区别是`ConnectableObservable`在调用其`connect`操作符之前不会开始发出值。

# 多线程（调度器）

默认情况下，RxJava 是单线程的。这意味着源可观测对象及其所有操作符都会通知调用了`subscribe()`操作符的同一线程上的观察者。

这里有两个操作符，`observeOn()`和`subscribeOn()`，允许将单个操作的执行移动到不同的线程。这些方法以一个`Scheduler`对象作为参数，该对象调度要在不同线程上执行的各个操作。

`subscribeOn()`操作符声明哪个调度器应该发出这些值。
`observeOn()`操作符声明哪个调度器应该观察和处理值。

`Schedulers`类包含工厂方法，这些方法创建具有不同生命周期和性能配置的`Scheduler`对象：

*   `computation()`：基于有限的线程池创建一个调度器，其大小为可用处理器的数量；它应该用于 CPU 密集型计算；使用`Runtime.getRuntime().availableProcessors()`避免使用比可用处理器更多的此类调度器；否则，由于线程上下文切换的开销，性能可能会下降
*   `io()`：基于用于 I/O 相关工作的无边界线程池创建调度器，例如当与源的交互本质上是阻塞的时，通常使用文件和数据库；否则避免使用它，因为它可能会旋转太多线程，并对性能和内存使用产生负面影响
*   `newThread()`：每次创建一个新线程，不使用任何池；创建线程的成本很高，所以您应该知道使用它的原因
*   `single()`：创建一个基于单个线程的调度器，该线程按顺序执行所有任务；在执行顺序很重要时非常有用
*   `trampoline()`：创建以先进先出方式执行任务的调度器；用于执行递归算法
*   `from(Executor executor)`：根据提供的执行器（线程池）创建一个调度器，允许控制线程的最大数量及其生命周期。我们在第 8 章、“多线程和并发处理”中讨论了线程池。为了提醒您，以下是我们讨论过的池：

```java
          Executors.newCachedThreadPool();
          Executors.newSingleThreadExecutor();
          Executors.newFixedThreadPool(int nThreads);
          Executors.newScheduledThreadPool(int poolSize);
          Executors.newWorkStealingPool(int parallelism);

```

如您所见，`Schedulers`类的一些其他工厂方法由这些线程池中的一个提供支持，并充当线程池声明的一个更简单、更简短的表达式。为了使示例更简单和更具可比性，我们将只使用一个`computation()`调度器。让我们看看 RxJava 中并行/并发处理的基础知识。

以下代码是将 CPU 密集型计算委派给专用线程的示例：

```java
Observable.fromArray("one","two","three")
          .doAfterNext(s -> System.out.println("1: " + 
                 Thread.currentThread().getName() + " => " + s))
          .flatMap(w -> Observable.fromArray(w.split(""))
                           .observeOn(Schedulers.computation())
              //.flatMap(s -> {             
              //      CPU-intensive calculations go here
              // }  
                .doAfterNext(s -> System.out.println("2: " + 
                         Thread.currentThread().getName() + " => " + s))
          )
          .subscribe(s -> System.out.println("3: " + s));
pauseMs(100);

```

在本例中，我们决定从每个发出的单词创建一个子字符流，并让一个专用线程处理每个单词的字符。此示例的输出如下所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/91fc68b9-2936-479c-bba8-c5df3b812429.png)

如您所见，主线程用于发出单词，每个单词的字符由专用线程处理。请注意，尽管在本例中，`subscribe()`操作的结果顺序与单词和字符发出的顺序相对应，但在实际情况中，每个值的计算时间将不相同，因此不能保证结果将以相同的顺序出现。

如果需要，我们也可以把每个单词放在一个专用的非主线程上，这样主线程就可以自由地做其他可以做的事情。例如，

```java
Observable.fromArray("one","two","three")
        .observeOn(Schedulers.computation())
        .doAfterNext(s -> System.out.println("1: " + 
                         Thread.currentThread().getName() + " => " + s))
        .flatMap(w -> Observable.fromArray(w.split(""))
                .observeOn(Schedulers.computation())
                .doAfterNext(s -> System.out.println("2: " + 
                         Thread.currentThread().getName() + " => " + s))
        )
        .subscribe(s -> System.out.println("3: " + s));
pauseMs(100);
```

该示例的输出如下：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/ee29dc44-8876-479a-91fb-9aaa2baaca47.png)

如您所见，主线程不再发出单词。

在 RxJava2.0.5 中，引入了一种新的更简单的并行处理方法，类似于标准 Java8 流中的并行处理。使用`ParallelFlowable`可以实现如下相同的功能：

```java
ParallelFlowable src = 
                     Flowable.fromArray("one","two","three").parallel();
src.runOn(Schedulers.computation())
   .doAfterNext(s -> System.out.println("1: " + 
                        Thread.currentThread().getName() + " => " + s))
   .flatMap(w -> Flowable.fromArray(((String)w).split("")))
   .runOn(Schedulers.computation())
   .doAfterNext(s -> System.out.println("2: " + 
                        Thread.currentThread().getName() + " => " + s))
   .sequential()
   .subscribe(s -> System.out.println("3: " + s));
pauseMs(100);

```

如您所见，`ParallelFlowable`对象是通过将`parallel()`操作符应用于常规的`Flowable`而创建的。然后，`runOn()`操作符告诉创建的可观察对象使用`computation()`调度器来发送值。请注意，不再需要在`flatMap()`操作符中设置另一个调度器（用于处理字符）。它可以设置在它的外部-只是在主管道中，这使得代码更简单。结果如下：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/d522525e-60b8-4870-b9c1-49dc85665818.png)

至于`subscribeOn()`运算符，其在管道中的位置不起任何作用。不管它放在哪里，它仍然告诉可观察的调度器应该发出值。举个例子：

```java
Observable.just("a", "b", "c")
          .doAfterNext(s -> System.out.println("1: " + 
                         Thread.currentThread().getName() + " => " + s))
          .subscribeOn(Schedulers.computation())
          .subscribe(s -> System.out.println("2: " + 
                        Thread.currentThread().getName() + " => " + s));
pauseMs(100);
```

结果如下：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/751bff5d-4e41-4d3b-aff2-d172cd5cd438.png)

即使我们改变`subscribeOn()`操作符的位置，如下面的例子所示，结果也不会改变：

```java
Observable.just("a", "b", "c")
          .subscribeOn(Schedulers.computation())
          .doAfterNext(s -> System.out.println("1: " + 
                         Thread.currentThread().getName() + " => " + s))
          .subscribe(s -> System.out.println("2: " + 
                         Thread.currentThread().getName() + " => " + s));
pauseMs(100);
```

最后，这是两个运算符的示例：

```java
Observable.just("a", "b", "c")
          .subscribeOn(Schedulers.computation())
          .doAfterNext(s -> System.out.println("1: " + 
                       Thread.currentThread().getName() + " => " + s))
          .observeOn(Schedulers.computation())
          .subscribe(s -> System.out.println("2: " + 
                      Thread.currentThread().getName() + " => " + s));
pauseMs(100);

```

结果现在显示使用了两个线程：一个用于订阅，另一个用于观察：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/2e17e983-3447-4425-aa9e-96268cadad2c.png)

这就结束了我们对 RxJava 的简短概述，RxJava 是一个巨大的、仍在增长的库，有很多可能性，其中许多我们在本书中没有足够的篇幅来回顾。我们鼓励您尝试并学习它，因为反应式编程似乎是现代数据处理的发展方向。

# 总结

在本章中，读者了解了什么是反应式编程及其主要概念：异步、非阻塞、响应式等等。简单地介绍和解释了反应流，以及 RxJava 库，这是第一个支持反应编程原则的可靠实现。

在下一章中，我们将讨论微服务作为创建反应式系统的基础，并将回顾另一个成功支持反应式编程的库：我们将用它来演示如何构建各种微服务。

# 测验

1.  选择所有正确的语句：

2.  不使用线程池就可以使用`CompletableFuture`吗？
3.  `java.nio`中的`nio`代表什么？
4.  `event`循环是唯一支持非阻塞 API 的设计吗？
5.  RxJava 中的`Rx`代表什么？
6.  **Java 类库**（**JCL**）的哪个 Java 包支持反应流？
7.  从以下列表中选择可以表示反应流中可观察到的所有类：
    1.  `Flowable`
    2.  `Probably`
    3.  `CompletableFuture`
    4.  `Single`

8.  您如何知道`Observable`类的特定方法（运算符）是阻塞的？
9.  冷和热之间的区别是什么？
10.  `Observable`的`subscribe()`方法返回`Disposable`对象。当对这个对象调用`dispose()`方法时会发生什么？
11.  选择创建`Observable`对象的所有方法的名称：

12.  说出两个变换的`Observable`操作符。
13.  说出两个过滤`Observable`操作符。
14.  列举两种背压处理策略。
15.  指定两个允许向管道处理添加线程的`Observable`操作符。