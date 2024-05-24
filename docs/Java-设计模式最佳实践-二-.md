# Java 设计模式最佳实践（二）

> 原文：[Design Patterns and Best Practices in Java](https://libgen.rs/book/index.php?md5=096AE07A3FFC0E5B9926B8DE68424560)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 五、函数式模式

> 原文：[Design Patterns and Best Practices in Java](https://libgen.rs/book/index.php?md5=096AE07A3FFC0E5B9926B8DE68424560)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)
> 
> 贡献者：[飞龙](https://github.com/wizardforcel)
> 
> 本文来自[【ApacheCN Java 译文集】](https://github.com/apachecn/apachecn-java-zh)，采用[译后编辑（MTPE）](https://cn.bing.com/search?q=%E8%AF%91%E5%90%8E%E7%BC%96%E8%BE%91)流程来尽可能提升效率。

本章的目的是学习函数模式，以及通过引入函数式编程风格（现在在最重要的编程语言中是可能的）对传统模式所做的更改。Java8 引入了一些函数式特性，增加了一个新的抽象级别，影响了我们编写一些面向对象设计模式的方式，甚至使其中一些模式变得无关紧要。在本章中，我们将看到设计模式是如何被新的语言特性所改变，甚至取代的。在他的论文《动态语言中的设计模式》中，Peter Norvig 注意到 23 种设计模式中有 16 种更简单，或者被动态语言中现有的语言特征所取代，比如 Dylan。全文见[这个页面](http://norvig.com/design-patterns/)。在这一章中，我们将看到什么可以被取代，以及新出现的模式是怎样和怎样的。正如 peternorvig 在他的论文中所说的，*很久以前，子程序调用只是一种模式*，随着语言的发展，这些模式会发生变化或被替换。

为了运行本章中的代码，我们使用了 Java 中可用的 JShell REPL 工具，可以从 Windows 中的`$JAVA_HOME/bin/jshell on Linux or %JAVA_HOME%/bin/jshell.exe`访问该工具。

# 函数式编程简介

在 20 世纪 30 年代，数学家阿隆佐教会发展了 Lambda 微积分。这是函数式编程范式的起点，因为它提供了理论基础。下一步是 John McCarthy 于 1958 年设计的 **LISP**（简称**列表编程**）。LISP 是第一种函数式编程语言，它的一些风格，如 commonlisp，至今仍在使用。

在函数式编程（通常缩写为 FP）中，函数是一级公民；这意味着软件是通过将函数而不是对象组合为 OOP 来构建的。这是以声明的方式完成的，*告诉而不请求它*，通过组合函数，促进不变性，避免副作用和共享数据。这就产生了一个更简洁的代码，它对变化具有弹性、可预测性，并且更易于维护和业务人员阅读。

函数代码具有更高的信噪比；我们必须编写更少的代码才能实现与 OOP 相同的功能。通过避免副作用和数据突变，依靠数据转换，系统变得更简单，更易于调试和修复。另一个好处是可预测性。我们知道，对于同一个输入，同一个函数总是会给出相同的输出；因此，它也可以用于并行计算，在任何其他函数之前或之后调用（CPU/编译器不需要对调用顺序进行假设），其返回值一经计算就可以缓存，从而提高性能。

作为一种声明式编程类型，它更关注需要做什么，而命令式则侧重于应该如何做。样品流如下图所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/dsn-ptn-bst-prac-java/img/802a63ff-3eb0-4942-805e-4d0700b6c553.png)

函数式编程范式使用以下概念和原则：

*   Lambda 表达式
*   纯函数
*   参照透明度
*   一阶函数
*   高阶函数
*   函数组合
*   柯里化
*   闭包
*   不变性
*   函子
*   应用
*   单子

# Lambda 表达式

这个名字来自 Lambda 演算，希腊字母 Lambda（`λ`）用于将一个术语绑定到一个函数。Lambda 项可以是变量（`x`，例如，`λ.x.M`，其中`M`是函数或应用，其中两个项，`M`和`N`相互应用。通过构造（合成）术语，现在可以进行表达式缩减和/或转换。Lambda 表达式缩减可以通过使用解释器进行在线测试，[例如 Berkeley 的解释器](https://people.eecs.berkeley.edu/~gongliang13/lambda/)。

以下是用于在已知`x`、`y`坐标时计算圆半径平方的 Lambda 演算 Lambda 表达式的示例：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/dsn-ptn-bst-prac-java/img/32aaa83a-4d8b-4c11-b447-3e2c1c89604c.png)

它在数学上定义为一个 n 元函数：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/dsn-ptn-bst-prac-java/img/483911fb-d2f2-4532-af2b-0c12c15a9684.png)

申请如下：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/dsn-ptn-bst-prac-java/img/65470300-9036-4d64-bda5-9d4b474d9c9a.png)

这是柯里化版本（注意额外的减少步骤）：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/dsn-ptn-bst-prac-java/img/4bbd6be2-aeb6-49d0-9bac-ceddaba43ac0.png)

在语句上使用 Lambda 表达式的主要好处是 Lambda 表达式可以组合并简化为更简单的形式。

Java8 引入了 Lambda 表达式（以前通过使用匿名类提供），实现使用了 Java8 中引入的 invoke 动态，而不是匿名类，以提高性能（需要加载太多生成的类）和定制（将来的更改）的原因。

# 纯函数

纯函数是一个没有副作用的函数，它的输出对于相同的输入是相同的（可预测的和可缓存的）。副作用是修改函数外部上下文的操作。这方面的例子包括：

*   写入文件/控制台/网络/屏幕
*   修改外部变量/状态
*   调用非纯函数
*   启动进程

副作用有时是不可避免的，甚至是需要的——I/O 或低级操作就是带有副作用的代码的例子（冯·诺依曼机器因为副作用而工作）。根据经验，尝试将有副作用的函数与代码的其余部分隔离开来。Haskell 和其他函数式编程语言使用 monad 来完成任务。稍后我们将有一个关于单子的介绍部分。

由于纯函数的输出是可预测的，因此也可以用缓存的输出替换它；这就是为什么纯函数被称为提供引用透明性的原因。Robert Martin 在他的书《Clean Code》中写道，纯函数更容易阅读和理解：

“事实上，花在阅读和写作上的时间之比远远超过 10:1。作为编写新代码的一部分，我们不断地阅读旧代码。。。[因此，]使阅读更容易，使写作更容易。”

在代码中使用纯函数可以提高工作效率，并允许新手花更少的时间阅读新代码，花更多的时间使用和修复新代码。

# 引用透明性

引用透明性是一个函数的属性，它可以用输入的返回值替换。好处是巨大的，因为这有利于记忆（缓存返回值）和对特定函数调用的并行化。测试这样的函数也很容易。

# 一阶函数

第一类函数是可以像面向对象编程中创建、存储、用作参数和作为值返回的对象一样处理的函数。

# 高阶函数

高阶函数是可以将其他函数作为参数，创建并返回它们的函数。它们通过使用现有的和已经测试过的小函数来促进代码重用。例如，在下面的代码中，我们计算给定温度（华氏度）的平均值（摄氏度）：

```java
jshell> IntStream.of(70, 75, 80, 90).map(x -> (x - 32)*5/9).average();
$4 ==> OptionalDouble[25.5]
```

注意在高阶`map`函数中使用 Lambda 表达式。相同的 Lambda 表达式可以在多个地方用于转换温度。

```java
jshell> IntUnaryOperator convF2C = x -> (x-32)*5/9;
convF2C ==> $Lambda$27/1938056729@4bec1f0c
jshell> IntStream.of(70, 75, 80, 90).map(convF2C).average();
$6 ==> OptionalDouble[25.5]
jshell> convF2C.applyAsInt(80);
$7 ==> 26Function
```

# 组合

在数学中，函数是用一个函数的输出作为下一个函数的输入而组合起来的。同样的规则也适用于函数式编程，其中一阶函数由高阶函数使用。前面的代码已经包含了这样一个示例，请参见`map`函数中的`andThen`纯函数的用法。

为了使函数的组成更加直观，我们可以用`andThen`方法重写转换公式：

```java
jshell> IntUnaryOperator convF2C = ((IntUnaryOperator)(x -> x-32)).andThen(x -> x *5).andThen(x -> x / 9);
convF2C ==> java.util.function.IntUnaryOperator$$Lambda$29/1234776885@dc24521
jshell> convF2C.applyAsInt(80);
$23 ==> 26
```

# 柯里化

**柯里化**是将一个 n 元函数转化为一系列或一元函数的过程，它是以美国数学家 Haskell Curry 的名字命名的。形式`g:: x -> y -> z`是`f :: (x, y) -> z`的柯里化形式。对于前面给出的平方半径公式，`f(x,y) = x<sup class="calibre33">2</sup> + y<sup class="calibre33">2</sup>`，一个柯里化版本，不使用双函数，将使用`apply`多次。一个函数的单一应用只会用一个值替换参数，正如我们前面看到的。下面的代码展示了如何创建一个双参数函数，对于`n`个参数，`Function<X,Y>`类的`apply`函数将有 n 个调用：

```java
jshell> Function<Integer, Function<Integer, Integer>> square_radius = x -> y -> x*x + y*y;
square_radius ==> $Lambda$46/1050349584@6c3708b3
jshell> List<Integer> squares = Arrays.asList(new Tuple<Integer, Integer>(1, 5), new Tuple<Integer, Integer>(2, 3)).stream().
map(a -> square_radius.apply(a.y).apply(a.x)).
collect(Collectors.toList());
squares ==> [26, 13]
```

# 闭包

闭包是实现词汇作用域的一种技术。词法范围允许我们访问内部范围内的外部上下文变量。假设在前面的例子中，`y`变量已经被赋值。Lambda 表达式可以保持一元表达式，并且仍然使用`y`作为变量。这可能会导致一些很难找到的 bug，如在下面的代码中，我们希望函数的返回值保持不变。闭包捕获一个对象的当前值，正如我们在下面的代码中看到的，我们的期望是，`add100`函数总是将 100 添加到给定的输入中，但是它没有：

```java
jshell> Integer a = 100
a ==> 100
jshell> Function<Integer, Integer> add100 = b -> b + a;
add100 ==> $Lambda$49/553871028@eec5a4a
jshell> add100.apply(9);
$38 ==> 109
jshell> a = 101;
a ==> 101
jshell> add100.apply(9);
$40 ==> 110
```

在这里，我们期望得到 109，但是它用 110 回答，这是正确的（101 加 9 等于 110）；我们的`a`变量从 100 变为 101。闭包需要谨慎使用，而且，根据经验，使用`final`关键字来限制更改。闭包并不总是有害的；在我们想要共享当前状态的情况下（并且在需要的时候能够修改它），闭包非常方便。例如，我们将在需要提供数据库连接（抽象连接）的回调的 API 中使用闭包；我们将使用不同的闭包，每个闭包提供基于特定数据库供应商设置的连接，通常从外部上下文中已知的属性文件读取。它可以用函数的方式实现模板模式。

# 不变性

在《Effective Java》中，Joshua Bloch 提出了如下建议：*将对象视为不可变的*。在 OOP 世界中需要考虑这个建议的原因在于可变代码有许多可移动的部分；它太复杂，不容易理解和修复。促进不变性简化了代码，并允许开发人员专注于流，而不是关注一段代码可能产生的副作用。最糟糕的副作用是，一个地方的微小变化可能会在另一个地方产生灾难性的结果（蝴蝶效应）。可变代码有时很难并行化，并且常常使用不同的锁。

# 函子

函子允许我们对给定的容器应用函数。他们知道如何从包装对象中展开值，应用给定的函数，并返回另一个包含结果/转换包装对象的函子。它们很有用，因为它们抽象了多种习惯用法，如集合、`Future`（`Promise`）和`Optional`。下面的代码演示了 Java 中的`Optional`函子的用法，其中`Optional`可以是一个给定的值，这是将函数应用于现有的包装值（`5`的`Optional`的结果）：

```java
jshell> Optional<Integer> a = Optional.of(5);
a ==> Optional[5]
```

现在我们将函数应用于值为 5 的包装整数对象，得到一个新的可选保持值 4.5：

```java
jshell> Optional<Float> b = a.map(x -> x * 0.9f);
b ==> Optional[4.5]
jshell> b.get()
$7 ==> 4.5
```

`Optional`是一个函子，类似于 Haskell 的`Maybe`（只是`| Nothing`），它甚至有一个静态`Optional.empty()`方法，返回一个没有值（`Nothing`）的`Optional`。

# 应用

应用添加了一个新级别的包装，而不是将函数应用于包装对象，函数也被包装。在下面的代码中，函数被包装在一个可选的。为了证明应用的一个用法，我们还提供了一个标识（所有内容都保持不变）选项，以防所需的函数（在我们的例子中是`toUpperCase`）为空。因为没有语法糖来自动应用包装函数，所以我们需要手动执行，请参阅`get().apply()`代码。注意 Java9 added 方法`Optional.or()`的用法，如果我们的输入`Optional`为空，它将延迟返回另一个`Optional`：

```java
jshell> Optional<String> a = Optional.of("Hello Applicatives")
a ==> Optional[Hello Applicatives]
jshell> Optional<Function<String, String>> upper = Optional.of(String::toUpperCase)
upper ==> Optional[$Lambda$14/2009787198@1e88b3c]
jshell> a.map(x -> upper.get().apply(x))
$3 ==> Optional[HELLO APPLICATIVES]
```

这是我们的应用，它知道如何将给定的字符串大写。让我们看看代码：

```java
jshell> Optional<Function<String, String>> identity = Optional.of(Function.identity())
identity ==> Optional[java.util.function.Function$$Lambda$16/1580893732@5c3bd550]
jshell> Optional<Function<String, String>> upper = Optional.empty()
upper ==> Optional.empty
jshell> a.map(x -> upper.or(() -> identity).get().apply(x))
$6 ==> Optional[Hello Applicatives]
```

前面的代码是我们的应用，它将标识函数（输出与输入相同）应用于给定的字符串。

# 单子

**单子**应用一个函数，将一个包装值返回给一个包装值。Java 包含了`Stream`、`CompletableFuture`和已经出现的`Optional`等示例。`flatMap`函数通过将给定的函数应用于邮政编码映射中可能存在或不存在的邮政编码列表来实现这一点，如下代码所示：

```java
jshell> Map<Integer, String> codesMapping = Map.of(400500, "Cluj-Napoca", 75001, "Paris", 10115, "Berlin", 10000, "New York")
codesMapping ==> {400500=Cluj-Napoca, 10115=Berlin, 10000=New York, 75001=Paris}
jshell> List<Integer> codes = List.of(400501, 75001, 10115, 10000)
codes ==> [400501, 75001, 10115, 10000]
jshell> codes.stream().flatMap(x -> Stream.ofNullable(codesMapping.get(x)))
$3 ==> java.util.stream.ReferencePipeline$7@343f4d3d
jshell> codes.stream().flatMap(x -> Stream.ofNullable(codesMapping.get(x))).collect(Collectors.toList());
$4 ==> [Paris, Berlin, New York]
```

Haskell 使用以下单子（在其他函数式编程语言中导入）。它们对于 Java 世界也很重要，[因为它们具有强大的抽象概念](https://wiki.haskell.org/All_About_Monads)：

*   读取器单子允许共享和读取环境状态。它在软件的可变部分和不可变部分之间提供了边缘功能。
*   写入器单子用于将状态附加到多个写入器，非常类似于记录到多个写入器（控制台/文件/网络）的日志过程。
*   状态单子既是读取器又是写入器。

为了掌握函子、应用和单子的概念，我们建议您查阅[这个页面](http://adit.io/posts/2013-04-17-functors,_applicatives,_and_monads_in_pictures.html)和[这个页面](https://bartoszmilewski.com/2011/01/09/monads-for-the-curious-programmer-part-1/)。在[这个页面](https://github.com/aol/cyclops-react)的 Cyclops React 库里也有一些函数式的好东西。

# Java 函数式编程简介

函数式编程是基于流和 Lambda 表达式的，两者都是在 Java8 中引入的。像 RetroLambda 这样的库允许 Java8 代码在旧的 JVM 运行时运行，比如 Java5、6 或 7（通常用于 Android 开发）。

# Lambda 表达式

Lambda 表达式是用于`java.util.functions`包接口的语法。最重要的是：

*   `BiConsumer<T,U>`：一种使用两个输入参数而不返回结果的操作，通常用在`forEach`映射方法中。支持使用`andThen`方法链接`BiConsumers`。
*   `BiFunction<T,U,R>`：通过调用`apply`方法，接受两个参数并产生结果的函数。
*   `BinaryOperator<T>`：对同一类型的两个操作数进行的一种操作，产生与操作数类型相同的结果，通过调用其继承的`apply`方法来使用。它静态地提供了`minBy`和`maxBy`方法，返回两个元素中的较小值/较大值。
*   `BiPredicate<T,U>`：由两个参数（也称为谓词）组成的布尔返回函数，用于调用其`test`方法。
*   `Consumer<T>`：使用单个输入参数的操作。就像它的二进制对应项一样，它支持链接，并通过调用它的`apply`方法来应用，如下面的示例所示，其中使用者是`System.out.println`方法：

```java
jshell> Consumer<Integer> printToConsole = System.out::println;
print ==> $Lambda$24/117244645@5bcab519
jshell> printToConsole.accept(9)
9
```

*   `Function<T,R>`：接受一个参数并产生结果的函数。它转换输入，而不是变异。它可以通过调用其`apply`方法直接使用，使用`andThen`链接，使用`compose`方法组合，如下面的示例代码所示。这样，我们的代码就可以通过在现有函数的基础上构造新函数来保持 **DRY**（缩写为**不要重复**）：

```java
jshell> Function<Integer, Integer> square = x -> x*x;
square ==> $Lambda$14/1870647526@47c62251
jshell> Function<Integer, String> toString = x -> "Number : " + x.toString();
toString ==> $Lambda$15/1722023916@77caeb3e
jshell> toString.compose(square).apply(4);
$3 ==> "Number : 16"
jshell> square.andThen(toString).apply(4);
$4 ==> "Number : 16"
```

*   `Predicate<T>`：一个参数的布尔返回函数。在下面的代码中，我们将测试字符串是否完全小写：

```java
jshell> Predicate<String> isLower = x -> x.equals(x.toLowerCase())
isLower ==> $Lambda$25/507084503@490ab905
jshell> isLower.test("lower")
$8 ==> true
jshell> isLower.test("Lower")
$9 ==> false
```

*   `Supplier<T>`：这是一个值供应器：

```java
jshell> String lambda = "Hello Lambda"
lambda ==> "Hello Lambda"
jshell> Supplier<String> closure = () -> lambda
closure ==> $Lambda$27/13329486@13805618
jshell> closure.get()
$13 ==> "Hello Lambda"
```

*   `UnaryOperator<T>`：作用于单个操作数的一种特殊函数，其结果与其操作数的类型相同；可以用`Function<T, T>`代替。

# 流

流是一个函数管道，用于转换而不是变异数据。它们有创造者、中间者和终端操作。要从流中获取值，需要调用终端操作。流不是数据结构，不能重复使用，一旦被使用，如果第二次收集，它将保持关闭状态，`java.lang.IllegalStateException`异常：流已经被操作或关闭，将被抛出。

# 流创建操作

流可以是连续的，也可以是并行的。它们可以从`Collection`接口、JarFile、ZipFile 或位集创建，也可以从 Java9 开始从`Optional class stream()`方法创建。`Collection`类支持`parallelStream()`方法，该方法可以返回并行流或串行流。通过调用适当的`Arrays.stream(...)`，可以构造各种类型的流，例如装箱原始类型（`Integer`、`Long`、`Double`）或其他类。为原始类型调用它的结果是以下特定流：`IntStream`、`LongStream`或`DoubleStream`。这些专用流类可以使用它们的静态方法之一来构造流，例如`generate(...)`、`of(...)`、`empty()`、`iterate(...)`、`concat(...)`、`range(...)`、`rangeClosed(...)`或`builder()`。通过调用`lines(...)`方法可以很容易地从`BufferedReader`对象获取数据流，该方法也以静态形式存在于`Files`类中，用于从路径给定的文件获取所有行。`Files`类提供了其他流创建者方法，如`list(...)`、`walk(...)`、`find(...)`。

Java9 除了前面提到的`Optional`之外，还添加了更多返回流的类，比如`Matcher`类（`results(...)`方法）或`Scanner`类（`findAll(...)`和`tokens()`方法）。

# 流中间操作

中间流操作是延迟应用的；这意味着只有在终端操作被调用之后才进行实际调用。在下面的代码中，使用在网上使用[随机生成的名称](http://www.behindthename.com/random/?)，一旦找到第一个有效名称，搜索将停止（只返回一个`Stream<String>`对象）：

```java
jshell> Stream<String> stream = Arrays.stream(new String[] {"Benny Gandalf", "Aeliana Taina","Sukhbir Purnima"}).
...> map(x -> { System.out.println("Map " + x); return x; }).
...> filter(x -> x.contains("Aeliana"));
stream ==> java.util.stream.ReferencePipeline$2@6eebc39e
jshell> stream.findFirst();
Map Benny Gandalf
Map Aeliana Taina
$3 ==> Optional[Aeliana Taina]
```

流中间操作包含以下操作：

*   `sequential()`：将当前流设置为串行流。
*   `parallel()`：将当前流设置为可能的并行流。根据经验，对大型数据集使用并行流，并行化可以提高性能。在我们的代码中，并行操作会导致性能下降，因为并行化的成本大于收益，而且我们正在处理一些否则无法处理的条目：

```java
jshell> Stream<String> stream = Arrays.stream(new String[] {"Benny Gandalf", "Aeliana Taina","Sukhbir Purnima"}).
...> parallel().
...> map(x -> { System.out.println("Map " + x); return x; }).
...> filter(x -> x.contains("Aeliana"));
stream ==> java.util.stream.ReferencePipeline$2@60c6f5b
jshell> stream.findFirst();
Map Benny Gandalf
Map Aeliana Taina
Map Sukhbir Purnima
$14 ==> Optional[Aeliana Taina]
```

*   `unordered()`：无序处理输入。它使得序列流的输出顺序具有不确定性，并通过允许更有效地实现一些聚合函数（如去重复或`groupBy`），从而提高并行执行的性能。
*   `onClose(..)`：使用给定的输入处理器关闭流使用的资源。`Files.lines(...)`流利用它来关闭输入文件，比如在下面的代码中，它是自动关闭的，但是也可以通过调用`close()`方法手动关闭流：

```java
jshell> try (Stream<String> stream = Files.lines(Paths.get("d:/input.txt"))) {
...> stream.forEach(System.out::println);
...> }
Benny Gandalf
Aeliana Taina
Sukhbir Purnima
```

*   `filter(..)`：应用谓词过滤输入。
*   `map(..)`：通过应用函数来转换输入。
*   `flatMap(..)`：使用基于映射函数的流中的值替换输入。
*   `distinct()`：使用`Object.equals()`返回不同的值。
*   `sorted(..)`：根据自然/给定比较器对输入进行排序。
*   `peek(..)`：允许使用流所持有的值而不更改它们。
*   `limit(..)`：将流元素截断为给定的数目。
*   `skip(..)`：丢弃流中的前 n 个元素。

下面的代码显示了`peek`、`limit`和`skip`方法的用法。它计算出商务旅行折合成欧元的费用。第一笔和最后一笔费用与业务无关，因此需要过滤掉（也可以使用`filter()`方法）。`peek`方法是打印费用总额中使用的费用：

```java
jshell> Map<Currency, Double> exchangeToEur = Map.of(Currency.USD, 0.96, Currency.GBP, 1.56, Currency.EUR, 1.0);
exchangeToEur ==> {USD=0.96, GBP=1.56, EUR=1.0}
jshell> List<Expense> travelExpenses = List.of(new Expense(10, Currency.EUR, "Souvenir from Munchen"), new Expense(10.5, Currency.EUR, "Taxi to Munich airport"), new Expense(20, Currency.USD, "Taxi to San Francisco hotel"), new Expense(30, Currency.USD, "Meal"), new Expense(21.5, Currency.GBP, "Taxi to San Francisco airport"), new Expense(10, Currency.GBP, "Souvenir from London"));
travelExpenses ==> [Expense@1b26f7b2, Expense@491cc5c9, Expense@74ad ... 62d5aee, Expense@69b0fd6f]
jshell> travelExpenses.stream().skip(1).limit(4).
...> peek(x -> System.out.println(x.getDescription())).
...> mapToDouble(x -> x.getAmount() * exchangeToEur.get(x.getCurrency())).
...> sum();
Taxi to Munich airport
Taxi to San Francisco hotel
Meal
Taxi to San Francisco airport
$38 ==> 92.03999999999999
```

除了前面介绍的`Stream<T>.ofNullable`方法外，Java9 还引入了`dropWhile`和`takeWhile`。它们的目的是让开发人员更好地处理无限流。在下面的代码中，我们将使用它们将打印的数字限制在 5 到 10 之间。移除上限（由`takeWhile`设置）将导致无限大的递增数字打印（在某个点上，它们将溢出，但仍会继续增加–例如，在迭代方法中，使用`x -> x + 100`）：

```java
jshell> IntStream.iterate(1, x-> x + 1).
...> dropWhile(x -> x < 5).takeWhile(x -> x < 7).
...> forEach(System.out::println);
```

输出是 5 和 6，正如预期的那样，因为它们大于 5，小于 7。

# 流终端操作

终端操作是遍历中间操作管道并进行适当调用的值或副作用操作。它们可以处理返回的值（`forEach(...)`、`forEachOrdered(...)`），也可以返回以下任意值：

*   迭代器（例如`iterator()`和`spliterator()`方法）
*   集合（`toArray(...)`、`collect(...)`，使用集合`toList()`、`toSet()`、`toColletion()`、`groupingBy()`、`partitioningBy()`或`toMap()`）
*   特定元素（`findFirst()`、`findAny()`）
*   聚合（归约）可以是以下任何一种：
    *   **算法**：`min(...)`、`max(...)`、`count()`或`sum()`、`average()`、`summaryStatistics()`只针对`IntStream`、`LongStream`、`DoubleStream`。
    *   **布尔值**：`anyMatch(...)`、`allMatch(...)`和`noneMatch(...)`。
    *   **自定义**：使用`reduce(...)`或`collect(...)`方式。一些可用的收集器包括`maxBy()`、`minBy()`、`reducing()`、`joining()`和`counting()`。

# 面向对象设计模式的再实现

在本节中，我们将根据 Java8 和 Java9 中提供的新特性来回顾一些 GOF 模式。

# 单子

使用闭包和`Supplier<T>`可以重新实现单例模式。Java 混合代码可以利用`Supplier<T>`接口，比如在下面的代码中，单例是一个枚举（根据函数编程，singleton 类型是那些只有一个值的类型，就像枚举一样）。以下示例代码与第 2 章“创建模式”中的代码类似：

```java
jshell> enum Singleton{
...> INSTANCE;
...> public static Supplier<Singleton> getInstance()
...> {
...> return () -> Singleton.INSTANCE;
...> }
...>
...> public void doSomething(){
...> System.out.println("Something is Done.");
...> }
...> }
| created enum Singleton
jshell> Singleton.getInstance().get().doSomething();
Something is Done.
```

# 构建器

Lombock 库将生成器作为其功能的一部分引入。只要使用`@Builder`注解，任何类都可以自动获得对`builder`方法的访问权，如 Lombock 示例代码在[这个页面](https://projectlombok.org/features/Builder)中所示：

```java
Person.builder().name("Adam Savage").city("San Francisco").job("Mythbusters").job("Unchained Reaction").build();
```

其他 Java8 之前的实现使用反射来创建通用生成器。Java8+ 泛型构建器版本可以通过利用供应器和`BiConsumer`组合来实现，如下代码所示：

```java
jshell> class Person { private String name;
...> public void setName(String name) { this.name = name; }
...> public String getName() { return name; }}
| replaced class Person
| update replaced variable a, reset to null
jshell> Supplier<Person> getPerson = Person::new
getPerson ==> $Lambda$214/2095303566@78b66d36
jshell> Person a = getPerson.get()
a ==> Person@5223e5ee
jshell> a.getName();
$91 ==> null
jshell> BiConsumer<Person, String> changePersonName = (x, y) -> x.setName(y)
changePersonName ==> $Lambda$215/581318631@6fe7aac8
jshell> changePersonName.accept(a, "Gandalf")
jshell> a.getName();
$94 ==> "Gandalf"
```

# 适配器

最好的例子是使用`map`函数，它执行从旧接口到新接口的自适应。我们将重用第 4 章中的示例“结构模式”，稍加改动；映射模拟适配器代码：

```java
jshell> class PS2Device {};
| created class PS2Device
jshell> class USBDevice {};
| created class USBDevice
jshell> Optional.of(new PS2Device()).stream().map(x -> new USBDevice()).findFirst().get()
$39 ==> USBDevice@15bb6bea
```

# 装饰器

装饰器可以通过利用函数组合来实现。例如，如前所示，可以使用`stream.peek`方法将日志添加到现有函数调用，并从提供给`peek`的`Consumer<T>`将日志记录到控制台。

我们的第 4 章“结构模式”，装饰器示例可以用函数式重写；注意装饰器用于使用与初始装饰器消费者相同的输入：

```java
jshell> Consumer<String> toASCII = x -> System.out.println("Print ASCII: " + x);
toASCII ==> $Lambda$159/1690859824@400cff1a
jshell> Function<String, String> toHex = x -> x.chars().boxed().map(y -> "0x" + Integer.toHexString(y)).collect(Collectors.joining(" "));
toHex ==> $Lambda$158/1860250540@55040f2f
jshell> Consumer<String> decorateToHex = x -> System.out.println("Print HEX: " + toHex.apply(x))
decorateToHex ==> $Lambda$160/1381965390@75f9eccc
jshell> toASCII.andThen(decorateToHex).accept("text")
Print ASCII: text
Print HEX: 0x74 0x65 0x78 0x74
```

# 责任链

责任链可以实现为处理器（函数）的列表，每个处理器执行一个特定的操作。下面的示例代码使用闭包和一系列函数，这些函数一个接一个地应用于给定的文本：

```java
jshell> String text = "Text";
text ==> "Text"
jshell> Stream.<Function<String, String>>of(String::toLowerCase, x -> LocalDateTime.now().toString() + " " + x).map(f -> f.apply(text)).collect(Collectors.toList())
$55 ==> [text, 2017-08-10T08:41:28.243310800 Text]
```

# 命令

其目的是将一个方法转换成一个对象来存储它并在以后调用它，能够跟踪它的调用、记录和撤消。这是`Consumer<T>`类的基本用法。

在下面的代码中，我们将创建一个命令列表并逐个执行它们：

```java
jshell> List<Consumer<String>> tasks = List.of(System.out::println, x -> System.out.println(LocalDateTime.now().toString() + " " + x))
tasks ==> [$Lambda$192/728258269@6107227e, $Lambda$193/1572098393@7c417213]
jshell> tasks.forEach(x -> x.accept(text))
Text
2017-08-10T08:47:31.673812300 Text
```

# 解释器

解释器的语法可以存储为关键字映射，相应的操作存储为值。在[第二章](2.html)“创建模式”中，我们使用了一个数学表达式求值器，将结果累加成一个栈。这可以通过将表达式存储在映射中来实现，并使用`reduce`来累加结果：

```java
jshell> Map<String, IntBinaryOperator> operands = Map.of("+", (x, y) -> x + y, "-", (x, y) -> x - y)
operands ==> {-=$Lambda$208/1259652483@65466a6a, +=$Lambda$207/1552978964@4ddced80}
jshell> Arrays.asList("4 5 + 6 -".split(" ")).stream().reduce("0 ",(acc, x) -> {
...> if (operands.containsKey(x)) {
...> String[] split = acc.split(" ");
...> System.out.println(acc);
...> acc = split[0] + " " + operands.get(x).applyAsInt(Integer.valueOf(split[1]), Integer.valueOf(split[2])) + " ";
...> } else { acc = acc + x + " ";}
...> return acc; }).split(" ")[1]
0 4 5
0 9 6
$76 ==> "3"
```

# 迭代器

迭代器部分是通过使用流提供的序列来实现的。Java8 添加了`forEach`方法，该方法接收消费者作为参数，其行为与前面的循环实现类似，如下面的示例代码所示：

```java
jshell> List.of(1, 4).forEach(System.out::println)
jshell> for(Integer i: List.of(1, 4)) System.out.println(i);
```

如预期的那样，每个示例的输出是 1 和 4。

# 观察者

在 Java8 中，观察者模式被 Lambda 表达式取代。最明显的例子是`ActionListener`替换。使用匿名类监听器的旧代码被替换为一个简单的函数调用：

```java
JButton button = new Jbutton("Click Here");
button.addActionListener(new ActionListener() 
{ 
  public void actionPerformed(ActionEvent e) 
  {
    System.out.println("Handled by the old listener");
  }
});
```

新代码只有一行：

```java
button.addActionListener(e -> System.out.println("Handled by lambda"));
```

# 策略

这个策略可以被一个函数代替。在下面的代码示例中，我们对所有价格应用 10% 的折扣策略：

```java
jshell> Function<Double, Double> tenPercentDiscount = x -> x * 0.9;
tenPercentDiscount ==> $Lambda$217/1990160809@4c9f8c13
jshell> List.<Double>of(5.4, 6.27, 3.29).stream().map(tenPercentDiscount).collect(Collectors.toList())
$98 ==> [4.86, 5.643, 2.9610000000000003]
```

# 模板方法

当模板提供调用顺序时，可以实现模板方法以允许注入特定的方法调用。在下面的示例中，我们将添加特定的调用并从外部设置它们的内容。它们可能已经插入了特定的内容。通过使用接收所有可运行项的单个方法，可以简化代码：

```java
jshell> class TemplateMethod {
...> private Runnable call1 = () -> {};
...> private Runnable call2 = () -> System.out.println("Call2");
...> private Runnable call3 = () -> {};
...> public void setCall1(Runnable call1) { this.call1 = call1;}
...> public void setCall2(Runnable call2) { this.call2 = call2; }
...> public void setCall3(Runnable call3) { this.call3 = call3; }
...> public void run() {
...> call1.run();
...> call2.run();
...> call3.run();
...> }
...> }
| created class TemplateMethod
jshell> TemplateMethod t = new TemplateMethod();
t ==> TemplateMethod@70e8f8e
jshell> t.setCall1(() -> System.out.println("Call1"));
jshell> t.setCall3(() -> System.out.println("Call3"));
jshell> t.run();
Call1
Call2
Call3
```

# 函数式设计模式

在本节中，我们将学习以下函数式设计模式：

*   映射和归约
*   借贷模式
*   尾部调用优化
*   回忆录
*   环绕执行方法

# 映射和归约

MapReduce 是 Google 开发的一种用于大规模并行编程的技术，由于易于表达，它以函数设计模式出现。在函数式编程中，它是单子的一种形式。

# 意图

其目的是将现有任务分解为多个较小的任务，并行运行它们，并聚合结果（`reduce`）。它有望提高大数据的性能。

# 示例

我们将通过基于给定的 Sleuth 跨度解析和聚合来自多个 Web 服务的日志并计算每个命中端点的总持续时间来演示 MapReduce 模式的用法。日志取自[这个页面](https://cloud.spring.io/spring-cloud-sleuth/spring-cloud-sleuth.html)并拆分成相应的服务日志文件。下面的代码并行读取所有日志、映射、排序和过滤相关日志条目，收集并减少（聚合）结果。如果有结果，它将被打印到控制台。导入的日期/时间类用于排序比较。`flatMap`代码需要处理`Exception`，如下代码所示：

```java
jshell> import java.time.*
jshell> import java.time.format.*
jshell> DateTimeFormatter dtf = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS")
dtf ==> Value(YearOfEra,4,19,EXCEEDS_PAD)'-'Value(MonthOf ... Fraction(NanoOfSecond,3,3)
jshell> try (Stream<Path> files = Files.find(Paths.get("d:/"), 1, (path, attr) -> String.valueOf(path).endsWith(".log"))) {
...> files.parallel().
...> flatMap(x -> { try { return Files.lines(x); } catch (IOException e) {} return null;}).
...> filter(x -> x.contains("2485ec27856c56f4")).
...> map(x -> x.substring(0, 23) + " " + x.split(":")[3]).
...> sorted((x, y) -> LocalDateTime.parse(x.substring(0, 23), dtf).compareTo(LocalDateTime.parse(y.substring(0, 23), dtf))).
...> collect(Collectors.toList()).stream().sequential().
...> reduce((acc, x) -> {
...> if (acc.length() > 0) {
...> Long duration = Long.valueOf(Duration.between(LocalDateTime.parse(acc.substring(0, 23), dtf), LocalDateTime.parse(x.substring(0, 23), dtf)).t oMillis());
...> acc += "n After " + duration.toString() + "ms " + x.substring(24);
...> } else {
...> acc = x;
...> }
...> return acc;}).ifPresent(System.out::println);
...> }
2016-02-26 11:15:47.561 Hello from service1\. Calling service2
After 149ms Hello from service2\. Calling service3 and then service4
After 334ms Hello from service3
After 363ms Got response from service3 [Hello from service3]
After 573ms Hello from service4
After 595ms Got response from service4 [Hello from service4]
After 621ms Got response from service2 [Hello from service2, response from service3 [Hello from service3] and from service4 [Hello from service4]]
```

# 借贷模式

借贷模式确保资源一旦超出范围就被决定性地处置。资源可以是数据库连接、文件、套接字或任何处理本机资源的对象（内存、系统句柄、任何类型的连接）之一。这与 MSDN 上描述的 Dispose 模式的意图类似。

# 意图

这样做的目的是让用户在未使用的资源被使用后，从释放这些资源的负担中解脱出来。用户可能忘记调用资源的`release`方法，从而导致泄漏。

# 示例

在处理数据库事务时，最常用的模板之一是获取事务、进行适当的调用、确保在异常时提交或回滚并关闭事务。这可以实现为借贷模式，其中移动部分是事务中的调用。以下代码显示了如何实现这一点：

```java
jshell> class Connection {
...> public void commit() {};
public void rollback() {};
public void close() {};
public void setAutoCommit(boolean autoCommit) {};
...> public static void runWithinTransaction(Consumer<Connection> c) {
...> Connection t = null;
...> try { t = new Connection(); t.setAutoCommit(false);
...> c.accept(t);
...> t.commit();
...> } catch(Exception e) { t.rollback(); } finally { t.close(); } } }
| created class Connection
jshell> Connection.runWithinTransaction(x -> System.out.println("Execute statement..."));
Execute statement...
```

# 尾部调用优化

**尾部调用优化**（**TCO**）是一些编译器在不使用栈空间的情况下调用函数的技术。Scala 通过用`@tailrec`注解递归代码来利用它。这基本上告诉编译器使用一个特殊的循环，称为 trampoline，它反复运行函数。函数调用可以处于一种或多种要调用的状态。在完成时，它返回结果（头部），在更多的情况下，它返回当前循环而不返回头部（尾部）。这个模式已经被 cyclops-react 提供给我们了。

# 意图

其目的是在不破坏栈的情况下启用递归调用。它只用于大量的递归调用，对于少数调用，它可能会降低性能。

# 示例

cyclops-react 的维护者 John McClean 演示了 [TCO 在 Fibonacci 序列中计算数字的用法](https://gist.github.com/johnmcclean/fb1735b49e6206396bd5792ca11ba7b2)。代码简洁易懂，基本上是从初始状态 0 和 1 开始累加斐波那契数，`f(0) = 0`、`f(1) = 1`，应用`f(n) = f(n-1) + f(n-2)`函数：

```java
importstatic cyclops.control.Trampoline.done;
importstatic cyclops.control.Trampoline.more;
import cyclops.control.Trampoline;
publicclass Main 
{
  publicvoid fib() 
  {
    for(int i=0;i<100_000;i++)
    System.out.println(fibonacci(i, 0l, 1l).get());
  }
  public Trampoline<Long> fibonacci(Integer count, Long a, Long b) 
  {
    return count==0 ? done(a) : more(()->fibonacci (count - 1, 
    b, a + b));
  }
  publicstaticvoid main(String[] args) 
  {
    new Main().fib();
  }
}
```

# 回忆录

多次调用前面的 Fibonacci 实现将导致 CPU 周期的浪费，因为有些步骤是相同的，并且我们可以保证，对于相同的输入，我们总是得到相同的输出（纯函数）。为了加速调用，我们可以缓存输出，对于给定的输入，只返回缓存结果，而不是实际计算结果。

# 意图

其目的是缓存给定输入的函数结果，并使用它加速对给定相同输入的相同函数的进一步调用。它应该只用于纯函数，因为它们提供了引用透明性。

# 示例

在下面的示例中，我们将重用 Fibonacci 代码并添加 Guava 缓存。缓存将保存 Fibonacci 的返回值，而键是输入数字。缓存配置为在大小和时间上限制内存占用：

```java
importstatic cyclops.control.Trampoline.done;
importstatic cyclops.control.Trampoline.more;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeUnit;
import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import cyclops.async.LazyReact;
import cyclops.control.Trampoline;
publicclass Main 
{
  public BigInteger fib(BigInteger n) 
  {
    return fibonacci(n, BigInteger.ZERO, BigInteger.ONE).get(); 
  }
  public Trampoline<BigInteger> fibonacci(BigInteger count, 
  BigInteger a, BigInteger b) 
  {
    return count.equals(BigInteger.ZERO) ? done(a) : 
    more(()->fibonacci (count.subtract(BigInteger.ONE), b, 
    a.add(b)));
  }
  publicvoid memoization(List<Integer> array) 
  {
    Cache<BigInteger, BigInteger> cache = CacheBuilder.newBuilder()
    .maximumSize(1_000_000)
    .expireAfterWrite(10, TimeUnit.MINUTES)
    .build();
    LazyReact react = new LazyReact().autoMemoizeOn((key,fn)->    
    cache.get((BigInteger)key,()-> (BigInteger)fn.
    apply((BigInteger)key)));
    Listresult = react.from(array)
    .map(i->fibonacci(BigInteger.valueOf(i), BigInteger.ZERO,  
    BigInteger.ONE))
    .toList();
  }
  publicstaticvoid main(String[] args) 
  {
    Main main = new Main();
    List<Integer> array = Arrays.asList(500_000, 499_999);
    long start = System.currentTimeMillis();
    array.stream().map(BigInteger::valueOf).forEach(x -> main.fib(x));
    System.out.println("Regular version took " +     
    (System.currentTimeMillis() - start) + " ms");
    start = System.currentTimeMillis();
    main.memoization(array);
    System.out.println("Memoized version took " +   
    (System.currentTimeMillis() - start) + " ms");
  }
}
```

输出如下：

```java

Regular version took 19022 ms
Memoized version took 394 ms
```

# 环绕执行方法

在度量每个版本的代码的性能时，前面的代码似乎都在重复。这可以通过环绕执行方法模式解决，方法是将执行的业务代码包装到 Lambda 表达式中。这种模式的一个很好的例子是单元测试前后的设置/拆卸函数。这类似于前面描述的模板方法和借贷模式。

# 意图

其目的是让用户可以在特定业务方法之前和之后执行某些特定的操作。

# 示例

上一个示例中提到的代码包含重复的代码（代码气味）。我们将应用环绕执行模式来简化代码并使其更易于阅读。可能的重构可以使用 Lambda，如我们所见：

```java
publicstaticvoid measurePerformance(Runnable runnable) 
{
  long start = System.currentTimeMillis();
  runnable.run();
  System.out.println("It took " + (System.currentTimeMillis() - 
  start) + " ms");
}
publicstaticvoid main(String[] args) 
{
  Main main = new Main();
  List<Integer> array = Arrays.asList(500_000, 499_999);
  measurePerformance(() -> array.stream().map(BigInteger::valueOf)
  .forEach(x -> main.fib(x)));
  measurePerformance(() -> main.memoization(array));
}
```

# 总结

在本章中，我们了解了函数式编程的含义、最新 Java 版本提供的特性，以及它们是如何改变一些现有的 GOF 模式的。我们还使用了一些函数式编程设计模式。

在下一章中，我们将深入到反应式世界，学习如何使用 RxJava 创建响应式应用。


# 六、让我们开始反应式吧

> 原文：[Design Patterns and Best Practices in Java](https://libgen.rs/book/index.php?md5=096AE07A3FFC0E5B9926B8DE68424560)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)
> 
> 贡献者：[飞龙](https://github.com/wizardforcel)
> 
> 本文来自[【ApacheCN Java 译文集】](https://github.com/apachecn/apachecn-java-zh)，采用[译后编辑（MTPE）](https://cn.bing.com/search?q=%E8%AF%91%E5%90%8E%E7%BC%96%E8%BE%91)流程来尽可能提升效率。

这一章将描述反应式编程范式，以及为什么它能很好地适用于带有函数元素的语言。读者将熟悉反应式编程背后的概念。我们将介绍在创建反应式应用时从观察者模式和迭代器模式中使用的元素。这些示例将使用反应式框架和名为 **RxJava**（版本 2.0）的 Java 实现。

我们将讨论以下主题：

*   什么是反应式编程？
*   RxJava 简介
*   安装 RxJava
*   可观察对象、可流动对象、观察者和订阅
*   创建可观察对象
*   变换可观察对象
*   过滤可观察对象
*   组合可观察对象
*   错误处理
*   调度者
*   主题
*   示例项目

# 什么是反应式编程？

根据[《反应宣言》](http://www.reactivemanifesto.org/)，无功系统具有以下属性：

*   **响应**：系统以一致的、可预测的方式及时响应。
*   **恢复**：系统对故障有弹性，能快速恢复。
*   **弹性**：系统通过增加或减少分配的资源，在不同的工作负载下保持其响应能力。这是通过动态查找和修复瓶颈来实现的。这不能与可伸缩性混淆。弹性系统需要根据需要上下伸缩——见[这个页面](http://www.reactivemanifesto.org/glossary#Elasticity)。
*   **消息驱动**：依赖异步消息传递，确保松耦合、隔离、位置透明和容错。

需求是真实的。如今，无响应系统被认为是有缺陷的，用户将避免使用。根据[这个页面](https://developers.google.com/search/mobile-sites/mobile-seo/)的说法，一个没有回应的网站在搜索引擎中的排名很低：

“响应式设计是谷歌的推荐设计模式”

反应式系统是一种使用元素构成复杂系统的架构风格，有些元素是用反应式编程技术构建的。

反应式编程是一种依赖于异步数据流的范例。它是异步编程的事件驱动子集。相反，反应式系统是消息驱动的，这意味着接收器是预先知道的，而对于事件，接收器可以是任何观察者。

反应式编程不仅仅是基于事件的编程，因为它利用了数据流，它强调数据流而不是控制流。以前，诸如鼠标或键盘事件之类的事件，或者诸如服务器上的新套接字连接之类的后端事件，都是在线程事件循环（thread of execution）中处理的。现在一切都可以用来创建一个数据流；假设来自某个后端端点的 JSON REST 响应成为一个数据流，它可以被等待、过滤，或者与来自不同端点的其他响应合并。这种方法通过消除开发人员显式创建在多核和多 CPU 环境中处理异步调用的所有样板代码的需要，提供了很大的灵活性。

一个最好的也是最被过度使用的反应式编程示例是电子表格示例。定义流（flow）类似于声明 Excel 的 C1 单元格的值等于 B1 单元格和 A1 单元格的内容。每当 A1 或 B1 单元更新时，就会观察到变化并对其作出反应，其副作用是 C1 值得到更新。现在假设 C2 到 Cn 单元格等于 A2 到 An 加上 B2 到 Bn 的内容；同样的规则适用于所有单元格。

反应式编程使用以下一些编程抽象，有些抽象取自函数式编程世界：

*   **`Optional`/`Promise`**：这些提供了一种手段，可以对不久的将来某个地方将要提供的值采取行动。
*   **流**：它提供了数据管道，就像列车轨道一样，为列车运行提供了基础设施。
*   **数据流变量**：这些是应用于流函数的输入变量的函数的结果，就像电子表格单元格一样，通过对两个给定的输入参数应用加号数学函数来设置。
*   **节流**：该机制用于实时处理环境，包括**数字信号处理器**（**DSP**）等硬件，通过丢弃元件来调节输入处理的速度，以赶上输入速度；用作背压策略。
*   **推送机制**：这与好莱坞原理相似，因为它反转了调用方向。一旦数据可用，就调用流中的相关观察者来处理数据；相反，拉机制以同步方式获取信息。

有许多 Java 库和框架允许程序员编写反应式代码，如 Reactor、Ratpack、RxJava、Spring Framework 5 和 Vert.x。通过添加 JDK9 Flow API，开发人员可以使用反应式编程，而无需安装其他 API。

# RxJava 简介

RxJava 是从 Microsoft.NET 世界移植的反应式扩展（一个库，用于使用可观察序列编写异步和基于事件的程序）的实现。2012 年，Netflix 意识到他们需要一个范式的转变，因为他们的架构无法应对庞大的客户群，所以他们决定通过将无功扩展的力量引入 JVM 世界来实现无功扩展；RxJava 就是这样诞生的。除了 RxJava 之外，还有其他 JVM 实现，比如 RxAndroid、RxJavaFX、RxKotlin 和 RxScale。这种方法给了他们想要的动力，通过公开，它也为我们提供了使用它的机会。

RxJavaJar 是根据 Apache 软件许可证 2.0 版获得许可的，可以在中央 Maven 存储库中获得。

有几个外部库使用 RxJava：

*   `hystrix`：一个延迟和容错库，用于隔离远程系统的访问点
*   `rxjava-http-tail`：一个 HTTP 日志跟踪库，可用方式与`tail -f`相同
*   `rxjava-jdbc`：使用 RxJava 和到`ResultSets`流的 JDBC 连接

# 安装 RxJava 框架

在本节中，我们将介绍 Maven 的 RxJava 安装（Gradle、SBT、Ivy、Grape、Leiningen 或 Buildr 步骤类似）以及 Java9 的 replJShell 的用法。

# Maven 安装

安装 RxJava 框架很容易。JAR 文件和依赖的项目反应流在 Maven 下的[这个页面](http://central.maven.org/maven2/io/reactivex/rxjava2/rxjava/2.1.3/rxjava-2.1.3.jar)中可用。

为了使用它，在您的`pom.xml`文件中包括这个 Maven 依赖项：

```java
<project  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.packt.java9</groupId>
  <artifactId>chapter6_client</artifactId>
  <version>0.0.1-SNAPSHOT</version>
  <properties>
    <maven.compiler.source>1.8</maven.compiler.source>
    <maven.compiler.target>1.8</maven.compiler.target>
  </properties>
  <dependencies>
    <!-- https://mvnrepository.com/artifact/io.reactivex.
    rxjava2/rxjava -->
    <dependency>
      <groupId>io.reactivex.rxjava2</groupId>
      <artifactId>rxjava</artifactId>
      <version>2.1.3</version>
    </dependency>
    <!-- https://mvnrepository.com/artifact/org.
    reactivestreams/reactive-streams -->
    <dependency>
      <groupId>org.reactivestreams</groupId>
      <artifactId>reactive-streams</artifactId>
      <version>1.0.1</version>
    </dependency>
  </dependencies>
</project>
```

安装在 Gradle、SBT、Ivy、Grape、Leiningen 或 Buildr 中类似；查看[这个页面](https://mvnrepository.com/artifact/io.reactivex.rxjava2/rxjava/2.1.3)了解需要添加到`configuration`文件的更多信息。

# JShell 安装

我们将在第 9 章“Java 最佳实践”中详细讨论 JShell，现在让我们从 RxJava 的角度来看一下。在 JShell 中安装 RxJava 框架是通过将 classpath 设置为 RxJava 和 reactive streams JAR 文件来完成的。请注意，Linux 上使用冒号，Windows 上使用分号作为文件路径分隔符：

```java
"c:Program FilesJavajdk-9binjshell" --class-path D:Kitsrxjavarxjava-2.1.3.jar;D:Kitsrxjavareactive-streams-1.0.1.jar
```

屏幕上将显示以下错误：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/dsn-ptn-bst-prac-java/img/081f90ec-4fec-4cf3-bfe5-4793220a018d.png)

前面的错误是因为我们忘记导入相关的 Java 类。

以下代码处理此错误：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/dsn-ptn-bst-prac-java/img/fd64466a-2b93-43ce-9fe2-a4fc81f8dd59.png)

现在我们已经成功地创建了我们的第一个可观察对象。在下面的部分中，我们将学习它的功能以及如何使用它。

# 可观察对象、可流动对象、观察者和订阅者

在 ReactiveX 中，观察者订阅一个可观察的对象。当观察者发射数据时，观察者通过消耗或转换数据做出反应。这种模式便于并发操作，因为它不需要在等待可观察对象发出对象时阻塞。相反，它以观察者的形式创建了一个哨兵，随时准备在以观察者的形式出现新数据时做出适当的反应。这个模型被称为反应堆模式。下图取自[这个页面](http://reactivex.io/assets/operators/legend.png)，解释了可观测数据流：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/dsn-ptn-bst-prac-java/img/b33888d8-4408-4fd5-9215-3a609f5cea79.png)

反应式的可观察性与祈使式的可观察性相似。它解决了相同的问题，但策略不同。一旦可用，`Observable`通过异步推送更改来工作，而`Iterable`则以同步方式拉送更改机制。处理错误的方法也不同；一种使用错误回调，而另一种使用副作用，例如抛出异常。下表显示了差异：

| 事件 | 可迭代对象 | 可观察对象 |
| --- | --- |
| 获取数据 | `T next()` | `onNext(T)` |
| 错误 | `throw new Exception` | `onError(Exception)` |
| 完成 | `Return` | `onCompleted()` |

使用订阅（`onNextAction`、`onErrorAction`、`onCompletedAction`）方法将观察者连接到被观察者。观察者实现以下方法的一些子集（只有`onNext`是必需的）：

*   `onNext`：每当被观察对象发出一个项目时调用，方法以被观察对象发出的项目作为参数
*   `onError`：调用它是为了表示它没有生成预期的数据或遇到了其他错误，并将异常/错误作为它的参数
*   `onCompleted`：当没有更多的数据要发出时调用

从设计的角度来看，反应式可观测对象通过使用`onError`和`onCompleted`回调来增加在完成和错误时发出信号的能力，从而增强了四人帮的观察者模式。

有两种类型的反应式观察结果：

*   **热**：即使没有连接用户，也会尽快开始发送。
*   **冷**：在开始发送数据之前，等待至少一个订户连接，因此至少一个订户可以从一开始就看到序列。它们被称为“可连接的”可观察对象，RxJava 拥有能够创建此类可观察对象的操作符。

RxJava2.0 引入了一种新的可观察类型，称为`Flowable`。新的`io.reactivex.Flowable`是一个支持背压的基本反应类，而可观察的不再是。背压是一组策略，用于处理当可观察对象发出订户可以处理的更多数据时的情况。

RxJava `Observable`应用于小数据集（最长不超过 1000 个元素），以防止`OutOfMemoryError`或用于 GUI 事件，例如鼠标移动或小频率（1000 Hz 或以下）的触摸事件。

在处理超过 10000 个元素、从磁盘读取（解析）文件（这在背压下很好地工作）、通过 JDBC 从数据库读取数据或执行基于块和/或拉的数据读取时，将使用`Flowable`。

# 创建可观察对象

以下操作符用于从现有对象、其他数据结构的数组或序列或计时器中从头开始创建可观察对象。

# 创建操作符

可以通过调用以下`io.reactivex.Observable`方法之一（操作符）从头开始创建可观察对象：

*   创建
*   生成
*   不安全创建

下面的示例演示如何从头开始构造一个可观察的。调用`onNext()`直到观察者没有被释放，`onComplete()`和`onError()`以编程方式获得 1 到 4 的数字范围：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/dsn-ptn-bst-prac-java/img/5d7d884e-4933-47c8-822e-433252cffe4d.png)

正如我们在前面的屏幕截图中所看到的，输出与预期一样，范围从 1 到 4，序列在使用后会被处理掉。

# 延迟运算符

一旦观察者连接，可以通过调用`defer`方法为每个观察者创建一个新的观察者。以下代码显示了`defer`在我们提供号码时的用法：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/dsn-ptn-bst-prac-java/img/d13e22a4-5612-4842-8604-45131c8b57e5.png)

控制台`println`方法输出 123，这是可观察的整数。

# 空运算符

可以通过调用`empty()`或`never() io.reactivex.Observable`方法来创建从不发送的空项目。

# `from`运算符

通过调用以下方法之一，可以从数组、`Future`或其他对象和数据结构进行转换：

*   `fromArray`：将数组转换为可观察数组
*   `fromCallable`：将提供值的`Callable`转换为`Observable`
*   `fromFuture`：将`Future`提供的值转换为可观察的值
*   `fromIterable`：将`Iterable`转换为`Observable`
*   `fromPublisher`：将反应发布者流转换为可观察发布者流
*   `just`：将给定对象转换为可观察对象

下面的示例从字母列表（`abc`）中创建一个`Observable`：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/dsn-ptn-bst-prac-java/img/3827aba1-f52f-4a66-a1ed-1c62e1f65eda.png)

`a`、`b`和`c`的整个数组被消耗，并通过`System.out.println`方法打印到控制台。

# 区间运算符

通过使用`interval`方法，可以创建一个可观察的对象，该对象发出一个由特定时间间隔间隔隔开的整数序列。下面的示例从不停止；它每秒钟连续打印一次记号号：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/dsn-ptn-bst-prac-java/img/fb9d71db-f693-4721-be43-73004eac1fa4.png)

尝试停止计时器也无济于事（即使是`Ctrl + C`，只要关闭窗口），它会继续按指令每隔一秒向控制台打印递增的数字。

# 定时器运算符

通过使用计时器方法，可以在给定的延迟之后发出单个项目。

# 范围运算符

可以使用以下方法创建序列号范围：

*   `intervalRange`：发出一系列长值的信号，第一个在一些初始延迟之后，接下来是周期性的
*   `range`：发出指定范围内的整数序列

# 重复运算符

为了重复特定的项目或特定的顺序，请使用：

*   `repeat`：重复给定可观测源发射的项目序列多次或永远（取决于输入）
*   `repeatUntil`：重复可观测源发出的项目序列，直到提供的`stop`函数返回`true`
*   `repeatWhen`：除了`onComplete`之外，发出与初始可观察对象相同的值

以下代码重复给定的`a`值，直到满足条件：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/dsn-ptn-bst-prac-java/img/417d530b-771a-41b7-b2b6-b8fa3283219f.png)

它向控制台重复三次`a`，直到`x`的值 3 大于 2。作为练习，将`x++`替换为`++x`并检查控制台。

# 转换可观测对象

这些运算符转换由可观察对象发出的项。

# 订阅操作符

这些是订户用来消耗来自可观察对象的发射和通知的方法，例如`onNext`、`onError`和`onCompleted`。用于订阅的可观察方法有：

*   `blockingForEach`：消耗此可观察对象发出的每个项目，并阻塞直到可观察对象完成。
*   `blockingSubscribe`：订阅当前线程上的可观察事件并消耗事件。
*   `forEachWhile`：订阅`Observable`并接收每个元素的通知，直到`onNext`谓词返回`false`。
*   `forEach`：订阅可观察到的元素并接收每个元素的通知。
*   `subscribe`：将给定的观察者订阅到该可观察对象。观察器可以作为回调、观察器实现或抽象`io.reactivex.subscribers.DefaultSubscriber<T>`类的子类型提供。

# 缓冲区运算符

`buffer`方法用于创建给定大小的包，然后将它们打包为列表。下面的代码显示了如何在 10 个数字中创建两个`bundle`，一个有 6 个，另一个有其余 4 个：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/dsn-ptn-bst-prac-java/img/c4292f4c-a67d-44da-99b9-07359a89daa5.png)

# 展开映射操作符

通过使用以下操作符之一，可以通过到达顺序（`flatMap`）、保持最后发射的顺序（`switchMap`）或通过保持原始顺序（`concatMap`）将给定的可观察对象转换为单个可观察对象：`concatMap`、`concatMapDelayError`、`concatMapEager`、`concatMapEagerDelayError`、`concatMapIterable`、`flatMap`、`flatMapIterable`、`switchMap`，或`switchMapDelayError`。下面的示例演示了如何通过随机选择可观察对象的顺序来更改输出的内容。（`flatMap`、`concatMap`、`switchMap`：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/dsn-ptn-bst-prac-java/img/c3fdb310-ec85-4469-86b6-329586a071bd.png)

`concatMap`实现将`c`字符串附加到给定的`a`、`b`和`c`字符串中的每一个，因此，输出是`ac`、`bc`和`cc`。

`flatMap`实现将`f`字符串附加到给定的`a`、`b`和`c`字符串中的每一个，如下所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/dsn-ptn-bst-prac-java/img/96750fcd-8d66-48dc-b62d-dea37238d9bf.png)

由于随机延迟，顺序与预期的`af`、`bf`、`cf`不同，运行几次就会输出预期的顺序。

下面的代码段显示了不同的输出。

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/dsn-ptn-bst-prac-java/img/98226dc4-761c-43f3-a4cf-d70b57c77f86.png)

`switchMap`实现将`s`字符串附加到给定的`a`、`b`和`c`字符串列表中的最后一个元素。

注意`advanceTimeBy`的用法。没有这个电话，什么都不会打印，因为发射被推迟了。

# 分组运算符

`groupBy`用于将一个可观察对象划分为一组可观察对象，每个可观察对象发出一组不同的项目。下面的代码按起始字母对字符串进行分组，然后打印键和特定键的组数据。请注意，这些组是可观察的，可用于构造其他数据流。

以下输出按第一个字母显示组作为一个组，并显示组键（即第一个字母）：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/dsn-ptn-bst-prac-java/img/44c6e7ea-5442-4bf8-bea1-6c8f0e77e773.png)

# 映射运算符

为每个项目应用一个函数来转换可观察对象可以通过以下方法实现：

*   `cast`：将结果强制转换为给定类型
*   `map`：对每个发出的项目应用指定的函数

# 扫描运算符

利用积累的转换可以用`scan`方法来完成。以下代码通过发出元素的当前和来使用它：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/dsn-ptn-bst-prac-java/img/2430126e-d52b-4730-b9bb-a70032b24ff7.png)

# 窗口操作符

`window`方法用于周期性地将项目从一个可观察窗口细分为可观察窗口，并突发发射这些窗口。下面的代码显示，使用一个元素的窗口不起任何作用，同时使用三个元素输出它们的总和：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/dsn-ptn-bst-prac-java/img/4d1158a4-c0ab-495a-a14c-f298825df7e3.png)

# 过滤可观察对象

这些操作符根据给定的条件/约束从给定的可观察对象选择性地发射项。

# 去抖动算符

只能在经过特定时间跨度后发射，可以使用以下方法：

*   `debounce`：镜像最初的可观察项，除了它删除源发出的项，然后在一段时间内删除另一项
*   `throttleWithTimeout`：仅发射那些在指定时间窗口内没有后跟另一个发射项的项

在下面的示例中，我们将删除在 100 毫秒的去抖动时间跨度过去之前触发的项；在我们的示例中，它只是最后一个管理的值。同样，通过使用测试调度器，我们提前了时间：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/dsn-ptn-bst-prac-java/img/14796180-af89-486d-b2c6-af30de36f343.png)

# 去重运算符

这将使用以下方法删除可观察对象发出的不同项：

*   `distinct`：只发射不同的元素
*   `distinctUntilChanged`：仅发射与其直接前辈不同的元素

在下面的代码中，我们将看到如何使用`distinct`方法从给定序列中删除重复项：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/dsn-ptn-bst-prac-java/img/04062498-1881-48c2-a36b-cafb2aa80c50.png)

我们可以看到重复的`aaa`字符串已经从输出中删除。

# 获取元素运算符

为了通过索引获得元素，使用`elementAt`方法。以下代码打印列表中的第三个元素：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/dsn-ptn-bst-prac-java/img/0d1cf753-0142-4ac3-bdb3-f27485bfaebc.png)

# 过滤运算符

在以下方法上使用只允许从通过测试（谓词/类型测试）的可观察对象中发出那些项：

*   `filter`：只发出满足指定谓词的元素
*   `ofType`：只发出指定类型的元素

以下代码显示了`filter`方法的用法，用于过滤掉不以字母`a`开头的元素：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/dsn-ptn-bst-prac-java/img/b231376c-4dd4-4c41-a306-c5c36fdb8475.png)

# 第一个/最后一个运算符

这些方法用于根据给定条件返回项目的第一个和最后一个匹配项。也有阻塞版本可用。可用的`io.reactivex.Observable methods`是：

*   `blockingFirst`：返回可观察对象发出的第一项
*   `blockingSingle`：返回可观察对象发出的第一个`Single`项
*   `first`：返回可观察对象发出的第一项
*   `firstElement`：返回仅发射第一个项目的`Maybe`
*   `single`：返回仅发射第一个项目的`Single`
*   `singleElement`：返回一个只发出第一个单曲的`Maybe`
*   `blockingLast`：返回可观察对象发出的最后一项
*   `last`：返回可观察对象发出的最后一项
*   `lastElement`：返回只发出最后一个单曲的`Maybe`

# 示例运算符

使用此运算符可发射特定项目（由采样时间段或节气门持续时间指定）。`io.reactivex.Observable`提供以下方法：

*   `sample`：在给定的时间段内发出最近发出的项目（如果有）
*   `throttleFirst`：仅发射给定连续时间窗口内发射的第一个项目
*   `throttleLast`：仅发射给定连续时间窗口内发射的最后一项

# 跳过运算符

从可观察的输出中删除第`n`个倒数第`n`个元素。以下代码显示了如何跳过给定输入的前三个元素：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/dsn-ptn-bst-prac-java/img/97de704a-97d6-44a5-9d1d-d5c670cc354c.png)

调用`skipLast`方法将只输出 1 和 2。

# 选取运算符

它只从给定的可见光发送第`n`个倒数第`n`个元素。以下示例显示如何仅从可观察的数值范围中获取前三个元素：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/dsn-ptn-bst-prac-java/img/e8d8122d-3c2c-4d1e-bc61-ae5c9313715c.png)

使用具有相同参数的`takeLast`方法将输出 3、4 和 5。

# 组合可观察对象

这些运算符用于组合多个可观察对象。

# 联合运算符

通过调用以下方法之一，组合来自两个或多个可观测对象的最新发射值：

*   `combineLatest`：发出聚合每个源的最新值的项
*   `withLatestFrom`：将给定的可观察对象合并到当前实例中

下面的示例（永远运行）显示了组合两个具有不同时间跨度的间隔可观察对象的结果—第一个每 6 毫秒发射一次，另一个每 10 毫秒发射一次：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/dsn-ptn-bst-prac-java/img/5c5081da-a559-42b7-b9fe-33696c536ca3.png)

前面代码的执行需要通过按`Ctrl + C`停止，因为它创建了一个无限列表。输出与预期一样，它包含基于创建时间戳的两个序列的组合值。

# 连接运算符

通过调用以下方法之一，可以基于给定窗口组合两个可观察对象：

*   `join`：使用聚合函数，根据重叠的持续时间，将两个可观察对象发出的项目连接起来
*   `groupJoin`：使用聚合函数，根据重叠的持续时间，将两个可观察对象发出的项目加入到组中

下面的示例使用`join`组合两个可观察对象，一个每 100 毫秒触发一次，另一个每 160 毫秒触发一次，并每 55 毫秒从第一个值中获取一个值，每 85 毫秒从第二个值中获取一个值：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/dsn-ptn-bst-prac-java/img/55cdf0f8-ce56-4452-a25d-5b04eaf29dc7.png)

前面的代码永远执行，需要手动停止。

# 合并运算符

将多个可观察对象合并为一个可观察对象，所有给定的发射都可以通过调用：

*   `merge`：将多个输入源展开为一个可观察源，无需任何转换
*   `mergeArray`：将作为数组给出的多个输入源展开为一个可观察源，而不进行任何转换
*   `mergeArrayDelayError`：将作为数组给出的多个输入源展开为一个可观察源，没有任何转换，也没有被错误打断
*   `mergeDelayError`：将多个输入源展开为一个可观察源，没有任何转换，也没有被错误打断
*   `mergeWith`：将这个和给定的源展开为一个可观察的，没有任何转换

在下面的示例中，我们将合并原始 1 到 5 范围的部分，合并方式是它包含所有条目，但顺序不同：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/dsn-ptn-bst-prac-java/img/6e6af107-c6bc-4a15-be00-3023a00ad305.png)

# 压缩运算符

基于组合器函数将多个可观察项组合成单个可观察项可以通过调用：

*   `zip`：将指定的组合器函数的结果应用于给定可观测项所发射的多个项目的组合
*   `zipIterable`：发出一个指定的组合器函数的结果，该函数应用于给定的可观测项发出的多个项的组合
*   `zipWith`：发出一个指定的组合器函数的结果，该组合器函数应用于这个和给定的可观察对象的组合

下面的代码显示了如何基于字符串连接组合器将`zip`应用于从 1 到 5 到 10 到 16（更多元素）的范围发出的元素。请注意，由于没有要应用的对应项，因此不会应用额外的发射（编号 16）：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/dsn-ptn-bst-prac-java/img/eb0fc961-36a5-4e0b-a200-3ac7f2b45424.png)

# 错误处理

`Observable`包含几个操作符，这些操作符允许错误处理、吞咽异常、转换异常、调用`finally`块、重试失败的序列以及即使发生错误也可以处理资源。

# 捕获运算符

这些运算符可以通过继续执行以下顺序从错误中恢复：

*   `onErrorResumeNext`：指示一个可观察对象将控制权传递给供应器提供的另一个可观察对象，而不是在出现问题时调用`onError`
*   `onErrorReturn`：指示可观察对象发出函数提供的默认值，以防出现错误
*   `onErrorReturnItem`：指示可观察对象发出提供的缺省值，以防出现错误
*   `onExceptionResumeNext`：指示一个可观察对象将控制传递给另一个可观察对象，而不是在出现问题时调用`onError`

下面的示例演示如何使用`onErrorReturnItem`方法；不使用`flatMap`技巧调用它将停止流并在最后输出`Default`。通过延迟对异常抛出代码的调用并对其应用`onErrorReturnItem`，我们可以继续序列并使用提供的默认值：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/dsn-ptn-bst-prac-java/img/672adc55-ebf3-4bb3-89de-850771d01fd4.png)

# `do`运算符

这些用于注册对特定生命周期事件采取的操作。我们可以使用它们来模拟`final`语句行为，释放分配给上游的资源，进行性能度量，或者执行不依赖于当前调用成功与否的其他任务。RxJava `Observable`通过提供以下方法来实现这一点：

*   `doFinally`：注册当前可观察对象调用`onComplete`或`onError`或被释放时要调用的动作
*   `doAfterTerminate`：在当前可观察对象调用`onComplete`或`onError`之后注册要调用的动作
*   `doOnDispose`：注册一个动作，在处理序列时调用
*   `doOnLifecycle`：根据序列的生命周期事件（订阅、取消、请求），为相应的`onXXX`方法注册回调
*   `doOnTerminate`：注册当前可观察对象调用`onComplete`或`onError`时要调用的动作

以下代码段显示了前面提到的命令的用法：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/dsn-ptn-bst-prac-java/img/56ecf8ec-7db3-4947-85b0-5801ba97a7b5.png)

在前面的示例中，我们可以看到生命周期事件的顺序是：订阅、终止、完成或错误，最后通过在每个事件上注册控制台打印操作。

# `using`运算符

`using`操作符在 Java 中有一个对应的操作符，名为资源尝试。它基本上也是这样做的，即创建一个在给定时间（当可观察对象被释放时）被释放的可支配资源。RxJava2.0 方法`using`实现了这个行为。

# 重试运算符

这些是在发生可恢复的故障（例如服务暂时关闭）时要使用的操作符。他们通过重新订阅来工作，希望这次能顺利完成。可用的 RxJava 方法如下：

*   `retry`：错误时永远重放同一流程，直到成功
*   `retryUntil`：重试，直到给定的`stop`函数返回`true`
*   `retryWhen`：基于接收错误/异常的重试逻辑函数，在错误情况下永远重放相同的流，直到成功为止

在下面的示例中，我们使用只包含两个值的`zip`来创建重试逻辑，该逻辑在一个时间段后重试两次以运行失败的序列，或者用 500 乘以重试计数。当连接到无响应的 Web 服务时，尤其是从每次重试都会消耗设备电池的移动设备时，可以使用此方法：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/dsn-ptn-bst-prac-java/img/70d6545a-2809-4a40-8d32-b37e6e937ae9.png)

# 调度器

在线程调度方面，可观测是不可知的——在多线程环境中，这是调度器的工作。一些操作符提供了可以将调度器作为参数的变体。有一些特定的调用允许从下游（使用操作符的点，这是`observeOn`的情况）或不考虑调用位置（调用位置无关紧要，因为这是`subscribeOn`方法的情况）观察流。在下面的示例中，我们将从上游和下游打印当前线程。注意，在`subscribeOn`的情况下，线程总是相同的：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/dsn-ptn-bst-prac-java/img/4acf684b-55fd-4938-845d-b40f900a1022.png)

注意`map`方法中的线程主要用法：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/dsn-ptn-bst-prac-java/img/027fbe82-d16e-4588-99b5-8abae35211b6.png)

请注意，`map`方法不再使用线程`main`。

RxJava2.0 提供了更多来自`io.reactivex.schedulers.Schedulers`工厂的调度器，每个调度器都有特定的用途：

*   `computation()`：返回用于计算工作的`Scheduler`实例
*   `io()`：返回一个用于 I/O 工作的`Scheduler`实例
*   `single()`：对于需要在同一后台线程上强顺序执行的工作，返回`Scheduler`实例
*   `trampoline()`：返回一个`Scheduler`实例，该实例在一个参与线程上以 FIFO 方式执行给定的工作
*   `newThread()`：返回一个`Scheduler`实例，该实例为每个工作单元创建一个新线程
*   `from(Executor executor)`：将`Executor`转换成新的`Scheduler`实例，并将工作委托给它

有一个只用于特殊测试目的的`Scheduler`，称为`io.reactivex.schedulers.TestScheduler`。我们已经使用了它，因为它允许手动推进虚拟时间，因此非常适合于测试依赖于时间的流，而不必等待时间通过（例如，单元测试）。

# 主体

主体是可观察的和订户的混合体，因为它们都接收和发射事件。RxJava2.0 提供了五个主题：

*   `AsyncSubject`：仅发射源可观测到的最后一个值，后跟一个完成
*   `BehaviorSubject`：发射最近发射的值，然后是可观测源发射的任何值
*   `PublishSubject`：仅向订阅方发送订阅时间之后源发送的项目
*   `ReplaySubject`：向任何订户发送源发出的所有项目，即使没有订阅
*   `UnicastSubject`：只允许单个用户在其生存期内订阅

# 示例项目

在下面的示例中，我们将展示 RxJava 在实时处理从多个传感器接收到的温度中的用法。传感器数据由 Spring 引导服务器提供（随机生成）。服务器配置为接受传感器名称作为配置，以便我们可以为每个实例更改它。我们将启动五个实例，并在客户端显示警告，如果其中一个传感器输出超过 80 摄氏度。

使用以下命令可以从 bash 轻松启动多个传感器：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/dsn-ptn-bst-prac-java/img/2570a499-f35d-448f-92a0-e008531b9272.png)

服务器端代码很简单，我们只配置了一个 REST 控制器，将传感器数据输出为 JSON，如下代码所示：

```java
@RestController
publicclass SensorController 
{
  @Value("${sensor.name}")
  private String sensorName;
  @RequestMapping(value="/sensor", method=RequestMethod.GET,   
  produces=MediaType.APPLICATION_JSON_VALUE)
  public ResponseEntity<SensorData> sensor() throws Exception 
  {
    SensorData data = new SensorData(sensorName);
    HttpHeaders headers = new HttpHeaders();
    headers.set(HttpHeaders.CONTENT_LENGTH, String.valueOf(new     
    ObjectMapper().writeValueAsString(data).length()));
    returnnew ResponseEntity<SensorData>(data, headers,     
    HttpStatus.CREATED);
  }
}
```

传感器数据是在`SensorData`构造器中随机生成的（注意 Lombock 库的使用，以摆脱获取设置器代码）：

```java
@Data
publicclass SensorData 
{
  @JsonProperty
  Double humidity;
  @JsonProperty
  Double temperature;
  @JsonProperty
  String sensorName;
  public SensorData(String sensorName) 
  {
    this.sensorName = sensorName;
    humidity = Double.valueOf(20 + 80 * Math.random());
    temperature = Double.valueOf(80 + 20 * Math.random()); 
  }
}
```

现在我们已经启动了服务器，我们可以从支持 RxJava 的客户端连接到它。

客户端代码使用 rxapache http 库：

```java
publicclass Main 
{
  @JsonIgnoreProperties(ignoreUnknown = true)
  staticclass SensorTemperature 
  {
    Double temperature;
    String sensorName;
    public Double getTemperature() 
    {
      return temperature;
    }
    publicvoid setTemperature(Double temperature) 
    {
      this.temperature = temperature;
    }
    public String getSensorName() 
    {
      return sensorName;
    }
    publicvoid setSensorName(String sensorName) 
    {
      this.sensorName = sensorName;
    }
    @Override
    public String toString() 
    {
      return sensorName + " temperature=" + temperature;
    }
  }  
}
```

`SensorTemperature`是我们的客户资料。它是服务器可以提供的内容的快照。其余信息将被 Jackson 数据绑定器忽略：

```java
publicstaticvoid main(String[] args) throws Exception 
{
  final RequestConfig requestConfig = RequestConfig.custom()
  .setSocketTimeout(3000)
  .setConnectTimeout(500).build();
  final CloseableHttpAsyncClient httpClient = HttpAsyncClients.custom()
  .setDefaultRequestConfig(requestConfig)
  .setMaxConnPerRoute(20)
  .setMaxConnTotal(50)
  .build();
  httpClient.start();
```

在前面的代码中，我们通过设置 TCP/IP 超时和允许的连接数来设置并启动 HTTP 客户端：

```java
Observable.range(1, 5).map(x ->
Try.withCatch(() -> new URI("http", null, "127.0.0.1", 8080 + x, "/sensor", null, null), URISyntaxException.class).orElse(null))
.flatMap(address -> ObservableHttp.createRequest(HttpAsyncMethods.createGet(address), httpClient)
.toObservable())
.flatMap(response -> response.getContent().map(bytes -> new String(bytes)))
.onErrorReturn(error -> "{"temperature":0,"sensorName":""}")
.map(json ->
Try.withCatch(() -> new ObjectMapper().readValue(json, SensorTemperature.class), Exception.class)
.orElse(new SensorTemperature()))
.repeatWhen(observable -> observable.delay(500, TimeUnit.MILLISECONDS))
.subscribeOn(Schedulers.io())
.subscribe(x -> {
if (x.getTemperature() > 90) {
System.out.println("Temperature warning for " + x.getSensorName());
} else {
System.out.println(x.toString());
}
}, Throwable::printStackTrace);
}
}
```

前面的代码基于范围创建 URL 列表，将其转换为响应列表，将响应字节展开为字符串，将字符串转换为 JSON，并将结果打印到控制台。如果温度超过 90 度，它将打印一条警告信息。它通过在 I/O 调度器中运行来完成所有这些，每 500 毫秒重复一次，如果出现错误，它将返回默认值。请注意`Try`单子的用法，因为选中的异常是由 Lambda 代码引发的，因此需要通过转换为可由 RxJava 在`onError`中处理的未选中表达式或在 Lambda 块中本地处理来处理。

由于客户端永远旋转，部分输出如下：

```java
NuclearCell2 temperature=83.92902289170053
Temperature warning for NuclearCell1
Temperature warning for NuclearCell3
Temperature warning for NuclearCell4
NuclearCell5 temperature=84.23921169948811
Temperature warning for NuclearCell1
NuclearCell2 temperature=83.16267124851476
Temperature warning for NuclearCell3
NuclearCell4 temperature=81.34379085987851
Temperature warning for NuclearCell5
NuclearCell2 temperature=88.4133065761349
```

# 总结

在本章中，我们学习了反应式编程，然后重点介绍了可用的最常用的反应式库之一——RxJava。我们学习了反应式编程抽象及其在 RxJava 中的实现。我们通过了解可观察对象、调度器和订阅是如何工作的、最常用的方法以及它们是如何使用的，从而通过具体的示例迈出了进入 RxJava 世界的第一步。

在下一章中，我们将学习最常用的反应式编程模式，以及如何在代码中应用它们。


# 七、反应式设计模式

> 原文：[Design Patterns and Best Practices in Java](https://libgen.rs/book/index.php?md5=096AE07A3FFC0E5B9926B8DE68424560)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)
> 
> 贡献者：[飞龙](https://github.com/wizardforcel)
> 
> 本文来自[【ApacheCN Java 译文集】](https://github.com/apachecn/apachecn-java-zh)，采用[译后编辑（MTPE）](https://cn.bing.com/search?q=%E8%AF%91%E5%90%8E%E7%BC%96%E8%BE%91)流程来尽可能提升效率。

在最后一章中，我们讨论了反应式编程风格，并强调了进行反应式编程的重要性。在本章中，我们将逐一回顾反应式编程的四大支柱，即响应性、弹性、弹性和消息驱动，并了解实现这些支柱的各种模式。本章将介绍以下主题：

*   响应模式
*   恢复模式
*   弹性模式
*   消息驱动的通信模式

# 响应模式

响应性意味着应用的交互性。它是否及时与用户交互？点击一个按钮能做它应该做的吗？界面是否在需要更新时得到更新？其思想是应用不应该让用户不必要地等待，应该提供即时反馈。

让我们看看帮助我们在应用中实现响应性的一些核心模式。

# 请求-响应模式

我们将从最简单的设计模式开始，请求-响应模式，它解决了反应式编程的响应性支柱。这是我们在几乎所有应用中使用的核心模式之一。是我们的服务接收请求并返回响应。许多其他模式都直接或间接地依赖于此，因此值得花几分钟来理解此模式。

下图显示了一个简单的请求-响应通信：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/dsn-ptn-bst-prac-java/img/0919b0eb-e256-4666-a18f-da09af8fed7d.png)

请求-响应关系有两个参与方。一个实体发出请求，第二个实体完成请求。请求者可以是从服务器请求详细信息的浏览器，也可以是从其他服务请求数据的服务。双方需要就请求和响应格式达成一致。这些可以是 XML、HTML、字符串、JSON 等形式；只要两个实体都理解通信，就可以使用任何格式。

我们将从一个简单的基于 Servlet 的示例开始。您可能不会在实际项目中使用基于 Servlet 的实现，除非您使用的是遗留应用，但是了解基础知识非常重要，因为它们是我们使用的大多数现代框架的起点。

我们将在这里创建一个雇员服务，它将处理`GET`和`POST`请求：

```java
/** 
*  
* This class is responsible for handling Employee Entity 
  related requests. 
*  
*/ 
public class EmployeeWebService extends HttpServlet 
{ 
  public void init() throws ServletException 
  { 
    // Do required initialization 
  } 
  public void doGet(HttpServletRequest request, 
  HttpServletResponse response) throws ServletException, 
  IOException 
  { 
    // Set response content type 
    response.setContentType("application/json"); 
    PrintWriter out = response.getWriter(); 
    /*  
    * This is a dummy example where we are simply returning 
    static employee details. 
    * This is just to give an idea how simple request response
    works. In real world you might want to  
    * fetch the data from data base and return employee list 
    or an employee object based on employee id 
    * sent by request. Well in real world you migth not want 
    to use servlet at all.  
    */ 
    JSONObject jsonObject = new JSONObject(); 
    jsonObject.put("EmployeeName", "Dave"); 
    jsonObject.put("EmployeeId", "1234"); 
    out.print(jsonObject); 
    out.flush(); 
  } 
  public void doPost(HttpServletRequest request, 
  HttpServletResponse response) throws ServletException, 
  IOException 
  { 
    // Similar to doGet, you might want to implement do post. 
    where we will read Employee values and add to database. 
  } 
  public void destroy() 
  { 
    // Handle any object cleanup or connection closures here. 
  } 
} 
```

前面的代码应该让您了解一个简单的请求-响应模式是如何工作的。`GET`和`POST`是两种最重要的通信方式。顾名思义，`GET`用于从服务器获取任何数据、信息、工件，而`POST`则向服务器添加新数据。大约 10-12 年前，您也会看到 Servlet 中嵌入了 HTML。但是，最近，情况已经转向更好、更易于维护的设计。为了保持关注点的分离和松散耦合，我们尝试保持表示层或前端代码独立于服务器端代码。这使我们可以自由地创建**应用编程接口**（**API**），以满足各种各样的客户，无论是桌面应用、移动应用还是第三方服务调用应用。

让我们更进一步，讨论一下维护 API 的 RESTful 服务。**REST** 代表**表述性状态转移**。最常见的 REST 实现是通过 HTTP，通过实现`GET`、`POST`、`PUT`和`DELETE`来实现，即处理 CRUD 操作。

我们来看看这四个核心业务：

*   `GET`：作为列表或单个实体获取数据。假设我们有一个雇员实体：`<url>/employees/`将返回系统中所有雇员的列表。`<url>/employees/{id}/`将返回特定的员工记录。

*   `POST`：新增实体数据。`<url>/employees/`将向系统中添加新的员工记录。

*   `PUT`：更新实体的数据。`<url>/employees/{id}`将更新系统中现有的员工记录。

*   `DELETE`：删除已有的实体记录。`<url>/employees/{id}`将从系统中删除现有员工记录。

如前所述，您几乎不会编写直接处理请求和响应的显式代码。有许多框架，如 Struts、Spring 等，可以帮助我们避免编写所有样板代码，并将重点放在核心业务逻辑上。

下面是一个基于 Spring 的快速示例；正如您将看到的，我们可以避免很多样板代码：

```java
@RestController
@RequestMapping("/employees")
/**
* This class implements GET and POST methods for Employee Entity
*/
publicclass EmployeeWebService 
{
  EmployeeDAO empDAO = new EmployeeDAO();
  /**
  * This method returns List of all the employees in the system.
  *
  * @return Employee List
  * @throws ServletException
  * @throws IOException
  */
  @RequestMapping(method = RequestMethod.GET)
  public List<Employee> EmployeeListService() throws 
  ServletException, IOException 
  {
    // fetch employee list and return
    List<Employee> empList = empDAO.getEmployeeList();
    return empList;
  }
  /**
  * This method returns details of a specific Employee.
  *
  * @return Employee
  * @throws ServletException
  * @throws IOException
  */
  @RequestMapping(method = RequestMethod.GET, value = "/{id}")
  public Employee EmployeeDataService(@PathVariable("id") 
  String id) throws ServletException, IOException 
  {
    // fetch employee details and return
    Employee emp = empDAO.getEmployee(id);
    return emp;
  }
  /**
  * This method returns Adds an Employee to the system  
  * 
  * @return Employee List
  * @throws ServletException
  * @throws IOException
  */
  @RequestMapping(method = RequestMethod.POST)
  public String EmployeeAddService(@RequestBody Employee emp) throws   
  ServletException, IOException 
  {
    // add employee and return id
    String empId= empDAO.addEmployee(emp);
    return empId;
  }
}
```

如您所见，我们正在使用一个**普通的旧 Java 对象**（**POJO**）类，并让它处理我们所有的 REST 调用。不需要扩展`HttpServlet`或管理`init`或`destroy`方法。

如果您了解 springmvc，就可以进入下一个模式。对于那些不熟悉 Spring 框架的人来说，花几分钟时间来理解前一个示例背后的工作原理是值得的。

当您使用 Spring 框架时，您需要告诉它您的服务器。因此，在你的`web.xml`中，添加以下内容：

```java
<servlet> 
  <servlet-name>springapp</servlet-name> 
  <servlet-class>org.springframework.web.servlet.
  DispatcherServlet</servlet-class> 
  <init-param> 
    <param-name>contextClass</param-name> 
    <param-value>org.springframework.web.context.support.
    AnnotationConfigWebApplicationContext </param-value> 
  </init-param> 
  <init-param> 
    <param-name>contextConfigLocation</param-name> 
    <param-value>com.employee.config.EmployeeConfig</param-value> 
  </init-param> 
  <load-on-startup>1</load-on-startup> 
</servlet> 
<servlet-mapping> 
  <servlet-name>springapp</servlet-name> 
  <url-pattern>/service/*</url-pattern> 
 </servlet-mapping>
```

这里我们已经告诉`web.xml`我们正在使用 Spring 的`DispatcherServlet`，对模式/服务的任何请求都应该转发到 Spring 代码。除了前面的代码行之外，我们还需要为 spring 提供配置。这可以在基于 Java 类或基于 XML 的配置中完成。我们已经告诉`web.xml`在`com.employee.config.EmployeeConfig`中寻找配置。

下面是一个基于类的配置示例：

```java
package com.employee.config; 
import org.springframework.context.annotation.ComponentScan; 
import org.springframework.context.annotation.Configuration; 
import org.springframework.web.servlet.config.annotation.EnableWebMvc; 
@EnableWebMvc 
@Configuration 
@ComponentScan(basePackages = "com.employee.*") 
public class EmployeeConfig 
{
} 
```

如您所见，这是一个非常基本的配置文件。您还可以添加数据库配置、安全特性等。关于 springmvc 的任何进一步讨论都超出了本书的范围。

要运行前面的代码，我们需要为 spring 和其他依赖项包含某些 JAR 文件。可以用不同的方式管理这些依赖关系；例如，人们可能更喜欢将 Jar 添加到存储库，或者使用 Maven、Gradle 等等。同样，对这些工具的讨论超出了本书的范围。以下是可以添加到 Maven 中的依赖项：

```java
<dependencies>
  <dependency>
    <groupId>org.springframework</groupId>
    <artifactId>spring-webmvc</artifactId>
    <version>4.3.9.RELEASE</version>
  </dependency>
  <dependency>
    <groupId>javax.servlet</groupId>
    <artifactId>servlet-api</artifactId>
    <version>2.5</version>
    <scope>provided</scope>
  </dependency>
  <dependency>
    <groupId>com.fasterxml.jackson.core</groupId>
    <artifactId>jackson-databind</artifactId>
    <version>2.5.0</version>
  </dependency>
</dependencies>
```

# 异步通信模式

当我们讨论反应式编程的响应支柱时，需要考虑的另一个重要模式是异步通信模式。虽然请求-响应模式确保所有请求都获得成功响应，但它没有考虑到某些请求可能需要花费大量时间来响应这一事实。异步通信模式有助于我们的应用保持响应，即使我们正在执行批量任务。我们实现响应或快速响应的方法是使核心任务执行异步。可以将其视为您的代码请求服务执行特定任务，例如更新数据库中的数据；服务接收数据并立即响应它已接收到数据。请注意，对数据库的实际写入尚未完成，但会向调用方法返回一条成功消息。

一个更相关的例子是，当一个服务被要求执行一项复杂的任务时，比如通过计算每个雇员的纳税义务来生成一个 Excel 报表，这个纳税义务需要根据每个雇员提供的工资和税务详细信息进行动态计算。因此，当税务报告服务收到生成此类报告的请求时，它只会返回一个确认收到请求的响应，并且 UI 将显示一条消息，在几分钟后刷新页面以查看更新的报告链接。这样，我们就不会阻塞最终用户，他/她可以在后台生成报告的同时执行其他任务。

异步通信是在多个层次上处理的；例如，当浏览器调用服务器时，我们的 JavaScript 框架（如 ReactJS 或 AngularJS）会根据接收到的数据量智能地呈现屏幕，并异步等待挂起的数据。但是，在这里，我们将更多地关注 Java 诱导的异步通信。在 Java 中处理异步任务的最简单方法是通过线程。

举个例子。我们有一个场景，在这个场景中，我们希望在 UI 上显示一个员工列表，同时，编译一个包含一些复杂计算的报告并将其发送给管理员。

以下代码显示了使用同步类型的方法调用时代码的外观：

```java
/**
* This method generates Employee data report and emails it to admin. This also
* returns number of employees in the system currently.
*
* @return EmployeeCount
* @throws ServletException
* @throws IOException
*/
@RequestMapping(method = RequestMethod.GET, value = "/report")
public List<Employee> EmployeeReport() throws ServletException, IOException 
{
  // Lets say this method gets all EmployeeDetails First
  List<Employee> empList = new EmployeeService().getEmployees();
  // Say there is a ReportUtil which takes the list data, does 
  some calculations
  // and dumps the report at a specific location
  String reportPath = ReportUtil.generateReport();
  // Finally say we have an email service which picks the report
  and send to admin. 
  EmailUtil.sendReport(reportPath);
  // Finally return the employee's count
  return empList;
}
```

假设获取数据需要一秒钟，生成报告需要四秒钟，通过电子邮件发送报告需要两秒钟。我们正在让用户等待 7 秒钟以获取他/她的数据。我们可以使报告异步化，以加快通信速度：

```java
/**
* This method generates Employee data report and emails it to admin. This also
* returns number of employees in the system currently.
*
* @return EmployeeCount
* @throws ServletException
* @throws IOException
*/
@RequestMapping(method = RequestMethod.GET, value = "/report")
public List<Employee> EmployeeReport() throws ServletException, IOException 
{
  // Lets say this method gets all EmployeeDetails First
  List<Employee> empList = new EmployeeService().getEmployees();
  Runnable myrunLambda = ()->
  {
    // Say there is a ReportUtil which takes the list data, does 
    some calculations
    // and dumps the report at a specific location
    String reportPath = ReportUtil.generateReport();
    // Finally say we have an email service which picks the report 
    and send to admin.
    EmailUtil.sendReport(reportPath);
  };
  new Thread(myrunLambda).start();
  // Finally return the employee's count
  return null;
}
```

我们已经将报表生成和电子邮件发送部分移出了关键路径，现在主线程在获取记录后立即返回。报告功能是在一个单独的线程中实现的。除了线程之外，实现异步通信的另一个重要方法是使用消息队列和消息驱动 bean。

# 缓存模式

另一种可以用来确保应用响应的模式是实现缓存。缓存将确保通过缓存结果以更快的方式处理类似类型的请求。我们可以在不同的层次上实现缓存，比如控制器层、服务层、数据层等等。我们还可以在请求命中代码之前实现缓存；也就是说，在服务器或负载平衡器级别。

在本章中，让我们以一个非常简单的示例来了解缓存如何帮助我们提高性能。让我们看一个简单的 Web 服务，它为员工返回数据：

```java
/**
* This method fetches a particular employee data.
* @param id
* @return
* @throws ServletException
* @throws IOException
*/
@RequestMapping(method = RequestMethod.GET, value = "/{id}")
public Employee EmployeeDataService(@PathVariable("id") String id) throws ServletException, IOException 
{
  /*
  * Again, to keep it simple, returning a dummy record.
  */
  EmployeeService employeeService = new EmployeeService();
  Employee emp = employeeService.getEmployee(id);
  return emp;
}
```

此方法从数据库获取数据并将其返回给最终用户。

Java 中有许多缓存实现。在本例中，我们创建一个非常简单的缓存机制：

```java
/**
* A simple cache class holding data for Employees
*
*/
class EmployeeCache
{
  static Map<String,Employee> cache = new HashMap<String,Employee>();
  /**
  * get Employee from cache
  * @param id
  * @return Employee
  */
  public static Employee getData(String id) 
  {
    return cache.get(id);
  }
  /**
  * Set employee data to cache
  * @param id
  * @param employee
  */
  public static void putData(String id, Employee employee) 
  {
    cache.put(id, employee);
  }
}
```

现在让我们更新我们的方法以利用缓存：

```java
/**
* This method fetches a particular employee data.
* @param id
* @return
* @throws ServletException
* @throws IOException
*/
@RequestMapping(method = RequestMethod.GET, value = "/{id}")
public Employee EmployeeDataService(@PathVariable("id") String id) throws ServletException, IOException 
{
  /*
  * Lets check of the data is available in cache.
  * If not available, we will get the data from database and 
  add to cache for future usage.
  */
  Employee emp = EmployeeCache.getData(id);
  if(emp==null)
  {
    EmployeeService employeeService = new EmployeeService();
    emp = employeeService.getEmployee(id);
    EmployeeCache.putData(id, emp);
  }
  return emp;
}
```

我们可以看到，第一次查找员工的详细信息时，缓存中将找不到这些信息，并且将执行从数据库获取数据的正常流程。同时，这些数据被添加到缓存中。因此，为同一员工获取数据的任何后续请求都不需要访问数据库。

# 扇出和最快的回复模式

在某些应用中，速度非常重要，尤其是在处理实时数据的情况下，例如在投注网站上，根据现场事件计算赔率非常重要。在最后五分钟内的进球，对于一场平局的比赛来说，会极大地改变胜算，有利于一支球队，你希望在人们开始增加赌注之前，这一点能在几秒钟内反映在网站上。

在这种情况下，请求处理的速度很重要，我们希望服务的多个实例来处理请求。我们将接受最先响应的服务的响应，并放弃其他服务请求。正如您所看到的，这种方法确实保证了速度，但它是有代价的。

# 快速失效模式

快速失败模式指出，如果服务必须失败，它应该快速失败并尽快响应调用实体。想想这个场景：你点击了一个链接，它显示了一个加载器。它会让您等待三到四分钟，然后显示一条错误消息，服务不可用，请在 10 分钟后重试。好吧，服务不可用是一回事，但是为什么要让某人等着告诉他们服务现在不可用呢。简言之，如果一个服务不得不失败，它至少应该尽快做到这一点，以保持良好的用户体验。

快速失败实现的一个例子是，如果您的服务依赖于另一个服务，那么您应该有一个快速机制来检查第三方服务是否启动。这可以通过简单的 ping 服务来实现。因此，在发送实际请求并等待响应之前，我们会对服务进行健康检查。如果我们的服务依赖于多个服务，这一点更为重要。在我们开始实际处理之前，检查所有服务的运行状况是很好的。如果任何服务不可用，我们的服务将立即发送等待响应，而不是部分处理请求然后发送失败。

# 恢复模式

在考虑应用的弹性时，我们应该尝试回答以下问题：应用能否处理失败条件？如果应用的一个组件出现故障，是否会导致整个应用宕机？应用中是否存在单点故障？

让我们看看一些模式，它们将帮助我们使应用具有弹性。

# 断路器型式

这是在系统中实现弹性和响应性的重要模式。通常，当一个服务在系统中失败时，它也会影响其他服务。例如，服务 X 调用系统中的服务 Y 来获取或更新一些数据。如果服务 Y 由于某种原因没有响应，我们的服务 X 将调用服务 Y，等待它超时，然后自己失败。设想一个场景，其中服务 X 本身被另一个服务 P 调用，以此类推。我们看到的是一个级联故障，最终会导致整个系统崩溃。

受电路启发的断路器模式表明，我们应该将故障限制在单个服务级别，而不是让故障传播；也就是说，我们需要一种机制让服务 X 了解服务 Y 是不健康的，并处理这种情况。处理这种情况的一种方法是服务 X 调用服务 Y，如果它观察到服务 Y 在 N 次重试后没有响应，它会认为服务不正常并将其报告给监视系统。同时，它在一段固定的时间内停止对服务 Y 的调用（例如，我们设置了一个 10 分钟的阈值）。

服务 X 将根据服务 Y 执行的操作的重要性来优雅地处理此故障。例如，如果服务 Y 负责更新帐户详细信息，服务 X 将向调用服务报告故障，或者对于 Y 正在执行的记录事务详细信息的所有服务，服务 X 将添加日志详细信息到回退队列，当服务 Y 备份时，它可以被清除。

这里的重要因素是不要让一次服务故障导致整个系统瘫痪。调用服务应该找出哪些是不健康的服务，并管理备用方法。

# 故障处理模式

在系统中保持弹性的另一个重要方面是问这样一个问题：如果一个或多个组件或服务宕机，我的系统还能正常工作吗？例如，以一个电子商务网站为例。有许多服务和功能协同工作以保持网站正常运行，例如产品搜索、产品目录、推荐引擎、评论组件、购物车、支付网关等等。如果其中一项服务（如搜索组件）由于负载或硬件故障而宕机，是否会影响最终用户下订单的能力？理想情况下，这两个服务应该独立创建和维护。因此，如果搜索服务不可用，用户仍然可以在购物车中订购商品或直接从目录中选择商品并购买。

处理失败的第二个方面是优雅地处理对失败组件的任何请求。对于上一个示例，如果用户尝试使用搜索功能（例如，用户界面上的搜索框仍然可用），我们不应该向用户显示空白页或让他/她永远等待。我们可以向他/她显示缓存的结果，或者显示一条消息，说明服务将在接下来的几分钟内使用推荐的目录启动。

# 有界队列模式

这种模式有助于我们保持系统的弹性和响应能力。此模式表示我们应该控制服务可以处理的请求数。大多数现代服务器都提供了一个请求队列，可以将其配置为在请求被丢弃和服务器繁忙消息被发送回调用实体之前让它知道应该排队的请求数。我们正在将这种方法扩展到服务级别。每个服务都应该基于一个队列，该队列将容纳要服务的请求。

队列应该有一个固定的大小，即服务在特定时间（例如一分钟）内可以处理的量。例如，如果我们知道服务 X 可以在一分钟内处理 500 个请求，那么我们应该将队列大小设置为 500，并且任何其他请求都将被发送一条关于服务正忙的消息。基本上，我们不希望调用实体等待很长时间，从而影响整个系统的性能。

# 监测模式

为了保持系统的弹性，我们需要监控服务性能和可用性的方法。我们可以向应用和服务添加多种类型的监视；例如，对于响应性，我们可以向应用添加周期性 ping，并验证响应需要多长时间，或者我们可以检查系统的 CPU 和 RAM 使用情况。如果您使用的是第三方云，例如 **Amazon Web Services**（**AWS**），那么您就获得了对这种监视的内置支持；否则您可以编写简单的脚本来检查当前的健康状态。日志监视用于检查应用中是否抛出错误或异常，以及这些错误或异常的严重程度。

监控到位后，我们可以在系统中添加警报和自动错误处理。警报可能意味着根据问题的严重程度发送电子邮件或文本消息。还可以内置升级机制；例如，如果问题在 X 时间内没有得到解决，则会向下一级升级点发送一条消息。通过使用自动错误处理，我们可以在需要创建其他服务实例、需要重新启动服务等情况下进行调用。

# 舱壁模式

舱壁是从货船上借来的术语。在货船中，舱壁是建造在不同货物段之间的一堵墙，它确保一段中的火灾或洪水仅限于该段，而其他段不受影响。您肯定已经猜到了我们的意图：一个服务或一组服务中的故障不应该导致整个应用崩溃。

为了实现隔板模式，我们需要确保我们的所有服务彼此独立地工作，并且一个服务中的故障不会导致另一个服务中的故障。维护单一责任模式、异步通信模式或快速故障和故障处理模式等技术有助于我们实现阻止一个故障在整个应用中传播的目标。

# 弹性模式

应用必须对可变负载条件作出反应。如果负载增加或减少，应用不应受到影响，并且应该能够处理任何负载级别而不影响性能。弹性的一个未提及的方面是应用不应该使用不必要的资源。例如，如果您希望您的服务器每分钟处理 1000 个用户，那么您将不会设置一个基础结构来处理 10000 个用户，因为您将支付所需成本的 10 倍。同时，您需要确保如果负载增加，应用不会阻塞。

让我们来看看帮助我们保持系统弹性的一些重要模式。

# 单一责任模式

也被称为简单组件模式或微服务模式，单责任模式是 OOP 单责任原则的一种扩展。在本书的最初几章中，我们已经讨论了单一责任原则。在基本层次上，当应用于面向对象编程时，单一责任原则规定一个类应该只有一个改变的理由。将此定义进一步扩展到架构级别，我们将此原则的范围扩展到组件或服务。因此，现在我们将单一责任模式定义为一个组件或服务应该只负责一个任务。

需要将应用划分为更小的组件或服务，其中每个组件只负责一个任务。将服务划分为更小的服务将产生更易于维护、扩展和增强的微服务。

为了进一步说明这一点，假设我们有一个名为`updateEmployeeSalaryAndTax`的服务。此服务获取基本工资并使用它计算总工资，包括可变和固定部分，最后计算税金：

```java
public void updateEmployeeSalaryAndTax(String employeeId, float baseSalary) 
{
  /*
  * 1\. Fetches Employee Data
  * 2\. Fetches Employee Department Data
  * 3\. Fetches Employee Salary Data
  * 4\. Applies check like base salary cannot be less than existing
  * 5\. Calculates House Rent Allowance, Grade pay, Bonus component
  based on Employees  
  * position, department, year of experience etc.
  * 6\. Updates Final salary Data
  * 7\. Gets Tax slabs based on country
  * 8\. Get state specific tax
  * 9\. Get Employee Deductions
  * 10\. Update Employee Tax details
  */
}
```

虽然在工资更新时计算这个似乎是合乎逻辑的，但是如果我们只需要计算税呢？比如说，一个员工更新了节税细节，为什么我们需要再次计算所有的工资细节，而不仅仅是更新税务数据。复杂的服务不仅通过添加不必要的计算来增加执行时间，而且还阻碍了可伸缩性和可维护性。假设我们需要更新税务公式，我们最终也会更新包含薪资计算细节的代码。总体回归范围面积增大。此外，假设我们知道薪资更新并不常见，但每次节税细节更新都会更新税务计算，而且税务计算本质上很复杂。对我们来说，将`SalaryUpdateService`保存在容量较小的服务器上，将`TaxCalculationService`保存在单独的、更大的机器上，或者保存多个`TaxCalculationService`实例可能更容易。

检查您的服务是否只执行一项任务的经验法则是，尝试用简单的英语解释并查找单词`and`，例如，如果我们说此服务更新工资明细`and`计算税款，或者此服务修改数据格式`and`将其上传到存储。当我们在对服务的解释中看到`and`时，我们知道这可以进一步细分。

# 无状态服务模式

为了确保我们的服务是可伸缩的，我们需要确保以无状态的方式构建它们。所谓无状态，我们的意思是服务不保留以前调用的任何状态，并将每个请求视为新的请求。这种方法的优点是，我们可以轻松地创建同一服务的副本，并确保哪个服务实例处理请求并不重要。

例如，假设我们有 10 个`EmployeeDetails`服务实例，负责为我`<url>/employees/id`提供服务，并返回特定员工的数据。不管哪个实例为请求提供服务，用户最终都会得到相同的数据。这有助于我们保持系统的弹性，因为我们可以随时启动任意数量的实例，并根据服务在该时间点上的负载将它们关闭。

让我们看一个反例；假设我们正在尝试使用会话或 Cookie 来维护用户操作的状态。这里，在`EmployeeDetails`服务上执行操作：

状态 1：John 成功登录。

状态 2：John 要求提供戴夫的雇员详细资料。

状态 3：John 请求 Dave 的详细信息页面上的薪资详细信息，系统返回 Dave 的薪资。

在这种情况下，*状态 3*请求没有任何意义，除非我们有来自前一状态的信息。我们得到一个请求`<url>/salary-details`，然后我们查看会话以了解谁在请求细节以及请求是为谁提出的。嗯，维护状态不是个坏主意，但是它会阻碍可伸缩性。

假设我们看到`EmployeeDetail`服务的负载在增加，并计划向集群中添加第二台服务器。挑战在于，假设前两个请求进入方框 1，第三个请求进入方框 2。现在，方框 2 不知道是谁在询问工资细节，是为谁。有一些解决方案，如维护粘性会话或跨框复制会话，或将信息保存在公共数据库中。但是这些都需要额外的工作来完成，这就破坏了快速自动缩放的目的。

如果我们认为每个请求都是独立的，也就是说，在提供所请求的信息、由谁提供、用户的当前状态等方面是自给自足的，那么我们就不必再担心维护用户的状态了。

例如，从`/salary-details to /employees/{id}/salary-details`开始的请求调用中的一个简单更改现在提供了关于请求谁的详细信息的信息。关于谁在询问详细信息，即用户的认证，我们可以使用基于令牌的认证或通过请求发送用户令牌等技术。

让我们看看基于 JWT 的认证。**JWT** 代表 **JSON Web 令牌**。JWT 只不过是嵌入在令牌或字符串中的 JSON。

我们先来看看如何创建 JWT 令牌：

```java
/**
* This method takes a user object and returns a token.
* @param user
* @param secret
* @return
*/
public String createAccessJwtToken(User user, String secret) 
{
  Date date = new Date();
  Calendar c = Calendar.getInstance();
  c.setTime(date);
  c.add(Calendar.DATE, 1);
  // Setting expiration for 1 day
  Date expiration = c.getTime();
  Claims claims = Jwts.claims().setSubject(user.getName())
  .setId(user.getId())
  .setIssuedAt(date)
  .setExpiration(expiration);
  // Setting custom role field
  claims.put("ROLE",user.getRole());
  return Jwts.builder().setClaims(claims).signWith
  (SignatureAlgorithm.HS512, secret).compact();
}
```

类似地，我们将编写一个方法来获取令牌并从令牌中获取详细信息：

```java
/**
* This method takes a token and returns User Object.
* @param token
* @param secret
* @return
*/
public User parseJwtToken(String token, String secret) 
{
  Jws<Claims> jwsClaims ;
  jwsClaims = Jwts.parser()
  .setSigningKey(secret)
  .parseClaimsJws(token);
  String role = jwsClaims.getBody().get("ROLE", String.class);
  User user = new User();
  user.setId(jwsClaims.getBody().getId());
  user.setName(jwsClaims.getBody().getSubject());
  user.setRole(role);
  return user;
}
```

关于 JWT 的完整讨论超出了本书的范围，但是前面的代码应该可以帮助我们理解 JWT 的基本概念。其思想是在令牌中添加关于请求实体的任何关键信息，这样我们就不需要显式地维护状态。令牌可以作为参数或头部的一部分发送到请求中，服务实体将解析令牌以确定请求是否确实来自有效方。

# 自动缩放模式

这更像是一种部署模式而不是开发模式。但理解这一点很重要，因为它将影响我们的开发实践。自动缩放与应用的弹性特性直接相关。服务可以通过两种方式放大或缩小以处理更高或更低数量的请求：垂直缩放和水平缩放。垂直扩展通常是指为同一台机器添加更多的电源，而水平扩展是指添加更多可以负载共享的实例。由于垂直缩放通常是昂贵的和有限制的，当我们谈到自动缩放时，我们通常指的是水平缩放。

自动缩放是通过监视实例容量使用情况并在此基础上进行调用来实现的。例如，我们可以设置一个规则，当托管服务的实例集群的平均 CPU 使用率超过 75% 时，应该引导一个新实例以减少其他实例的负载。类似地，我们可以有一个规则，每当平均负载降低到 40% 以下时，就会杀死一个实例以节省成本。大多数云服务提供商（如 Amazon）都提供了对自动缩放的内置支持。

# 自包含模式

简单地说，自包含意味着应用或服务应该是自给自足的，或者能够作为独立实体工作，而不依赖于任何其他实体。假设我们有一个针对`EmployeeData`的服务，处理一般员工数据处理，还有一个针对`EmployeeSalary`的服务。假设我们负责维护到`EmployeeData`服务的数据库连接。因此，每当`EmployeeSalary`服务需要处理数据库时，它都会调用`EmplyeeData`服务的`getDatabaseHandle`方法。这增加了一个不需要的依赖项，这意味着除非`EmployeeData`服务正常运行，否则我们的`EmployeeSalary`服务将无法正常工作。因此，`EmployeeSalary`服务应该维护自己的数据库连接池，并以自主的方式运行，这是合乎逻辑的。

# 消息驱动实现的模式

如果我们依赖基于消息的通信，我们可以避免紧耦合，增强弹性，因为组件可以增长或收缩而不必担心其他组件，并处理故障情况，因为一个组件的问题不会传播到其他组件。

以下是使用反应式应用编程时需要注意的主要设计模式。

# 事件驱动的沟通模式

事件驱动通信是指两个或多个组件基于某个事件相互传递消息。事件可以是添加新数据、更新数据状态或删除数据。例如，在系统中添加新员工记录时，需要向经理发送电子邮件。因此，负责管理员工记录的服务或组件将在添加新记录时向负责电子邮件功能的组件发送消息。处理这种通信有多种方法，但最常用的方法是通过消息队列。事件触发组件向队列中添加一条消息，接收方读取该消息并执行其部分操作：在本例中，向管理器发送一封电子邮件。

事件驱动模式背后的思想是，这两个组件彼此独立，但同时可以相互通信并采取所需的操作。在前面的示例中，电子邮件组件独立于添加记录的组件。如果电子邮件组件无法立即处理请求，则不会影响记录的添加。电子邮件组件可能已加载或由于某种原因已关闭。当电子邮件组件准备好处理消息时，它将从队列中读取并执行它需要执行的操作。

# 发布-订阅服务器模式

通常称为发布-订阅模式，这可以看作是事件驱动通信的扩展。在事件驱动通信中，一个动作触发一个事件，另一个组件需要在此基础上执行一些动作。如果多个组件对监听消息感兴趣怎么办？如果同一个组件对监听多种类型的消息感兴趣呢？利用主题的概念来解决问题。更广泛地说，我们可以把一个事件看作一个话题。

让我们重温一个示例，在这个示例中，雇员记录添加事件需要触发一封给经理的电子邮件。假设还有其他组件，例如运输系统、薪资管理系统等，它们还需要根据添加新员工记录的事件执行一些操作。此外，假设 EmailingTheManager 组件还对更新员工记录和删除员工记录等事件感兴趣；在这些情况下，也应该触发发送给经理的电子邮件。

所以，我们有一个主题叫做 Employee Added，另一个主题叫做 Employee Updated，还有一个主题叫做 Employee Deleted。负责管理员工数据的组件将所有这些事件发布到队列，因此称为发布者。对其中一个或多个主题感兴趣的组件将订阅这些主题，并称为订阅者。订阅者将听取他们感兴趣的主题，并根据收到的消息采取行动。

Pub-Sub 模式帮助我们实现组件之间的松散耦合，因为订阅者不需要知道发布者是谁，反之亦然。

# 幂等模式

当我们瞄准消息驱动和异步通信时，它会带来一些挑战。例如，如果系统中添加了重复的消息，是否会破坏状态？假设我们有一个银行帐户更新服务，我们发送一条消息，向帐户中添加 1000 美元。如果我们有重复的消息怎么办？系统将如何确保它不会仅仅因为收到重复的消息就两次添加钱？此外，该系统将如何区分重复消息和新消息？

有各种技术可以用来处理这个问题。最常见的方法是为每条消息添加一个消息编号或 ID，这样系统就可以确保每个具有唯一 ID 的消息只处理一次。另一种方法是保持消息中的前一个状态和新状态，即旧余额为 X，新余额为 Y，系统负责应用验证，以确保消息中提到的状态（旧余额）与系统状态匹配。

底线是，无论何时构建系统，我们都需要确保我们的应用能够处理这样一种情况：重复发送的消息得到了优雅的处理，并且不会破坏系统的状态。

# 总结

在本章中，我们讨论了帮助我们保持应用的反应式的模式，或者换句话说，帮助我们实现反应式编程的四大支柱，即响应性、弹性、弹性和消息驱动的通信。

在下一章中，我们将继续我们的旅程，探索一个架构良好的应用的一些当代方面。
