# Java 编程问题（三）

> 原文：[Java Coding Problems](https://libgen.rs/book/index.php?md5=3280024C263466704C8F7525E5BB6AAE)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 四、类型推断

> 原文：[Java Coding Problems](https://libgen.rs/book/index.php?md5=3280024C263466704C8F7525E5BB6AAE)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)
> 
> 贡献者：[飞龙](https://github.com/wizardforcel)
> 
> 本文来自[【ApacheCN Java 译文集】](https://github.com/apachecn/apachecn-java-zh)，自豪地采用[谷歌翻译](https://translate.google.cn/)。

本章包括 21 个涉及 JEP286 或 Java **局部变量类型推断**（**LVTI**）的问题，也称为`var`类型。这些问题经过精心设计，以揭示最佳实践和使用`var`时所涉及的常见错误。到本章结束时，您将了解到将`var`推向生产所需的所有知识。

# 问题

使用以下问题来测试您的类型推断编程能力。我强烈建议您在使用解决方案和下载示例程序之前，先尝试一下每个问题：

78.  **简单`var`示例**：编写一个程序，举例说明类型推断（`var`）在代码可读性方面的正确用法。
79.  **将`var`与原始类型结合使用**：编写一个程序，举例说明将`var`与 Java 原始类型（`int`、`long`、`float`、`double`结合使用。
80.  **使用`var`和隐式类型转换来维持代码的可维护性**：编写一个程序，举例说明`var`和*隐式类型转换*如何维持代码的可维护性。
81.  **显式向下转换或更好地避免`var`**：编写一个程序，举例说明`var`和显式向下转换的组合，并解释为什么要避免`var`。
82.  **如果被调用的名称没有包含足够的人性化类型信息，请避免使用`var`**：请举例说明应避免使用`var`，因为它与被调用的*名称*的组合会导致人性化信息的丢失。
83.  **结合 LVTI 和面向接口编程技术**：编写一个程序，通过*面向接口编程*技术来举例说明`var`的用法。

84.  **结合 LVTI 和菱形运算符**：编写一个程序，举例说明`var`和*菱形运算符*的用法。
85.  **使用`var`分配数组**：编写一个将数组分配给`var`的程序。
86.  **在复合声明中使用 LVTI**：解释并举例说明 LVTI 在复合声明中的用法。
87.  **LVTI 和变量范围**：解释并举例说明为什么 LVTI 应该尽可能地缩小变量的范围。
88.  **LVTI 和三元运算符**：编写几个代码片段，举例说明 LVTI 和*三元运算符*组合的优点。
89.  **LVTI 和`for`循环**：写几个例子来举例说明 LVTI 在`for`循环中的用法。
90.  **LVTI 和流**：编写几个代码片段，举例说明 LVTI 和 Java 流的用法。
91.  **使用 LVTI 分解嵌套的/大的表达式链**：编写一个程序，举例说明如何使用 LVTI 分解嵌套的/大的表达式链。
92.  **LVTI 和方法返回和参数类型**：编写几个代码片段，举例说明 LVTI 和 Java 方法在返回和参数类型方面的用法。
93.  **LVTI 和匿名类**：编写几个代码片段，举例说明 LVTI 在匿名类中的用法。
94.  **LVTI 可以是`final`和有效的`final`**：写几个代码片段，举例说明 LVTI 如何用于`final`和有效的`final`变量。
95.  **LVTI 和 Lambda**：通过几个代码片段解释如何将 LVTI 与 Lambda 表达式结合使用。
96.  **LVTI 和`null`初始化器、实例变量和`catch`块变量**：举例说明如何将 LVTI 与`null`*初始化器*、实例变量和`catch`块结合使用。
97.  **LVTI 和泛型类型`T`**：编写几个代码片段，举例说明如何将 LVTI 与泛型类型结合使用。
98.  **LVTI、通配符、协变和逆变**：编写几个代码片段，举例说明如何将 LVTI 与通配符、协变和逆变结合使用。

# 解决方案

以下各节介绍上述问题的解决方案。记住，通常没有一个正确的方法来解决一个特定的问题。另外，请记住，这里显示的解释仅包括解决问题所需的最有趣和最重要的细节。您可以[下载示例解决方案以查看更多详细信息并尝试程序](https://github.com/PacktPublishing/Java-Coding-Problems)。

# 78 简单`var`示例

从版本 10 开始，Java 附带了 JEP286 或 JavaLVTI，也称为`var`类型。

`var`标识符不是 Java *关键字*，而是*保留类型名*。

这是一个 100% 编译特性，在字节码、运行时或性能方面没有任何副作用。简而言之，LVTI 应用于局部变量，其工作方式如下：编译器检查右侧并推断出实类型（如果右侧是一个*初始化器*，则使用该类型）。

此功能可确保编译时安全。这意味着我们不能编译一个试图实现错误赋值的应用。如果编译器已经推断出`var`的具体/实际类型，我们只能赋值该类型的值。

LVTI 有很多好处；例如，它减少了代码的冗长，减少了冗余和*样板*代码。此外，LVTI 可以减少编写代码所花的时间，特别是在涉及大量声明的情况下，如下所示：

```java
// without var
Map<Boolean, List<Integer>> evenAndOddMap...

// with var
var evenAndOddMap = ...
```

一个有争议的优点是代码可读性。一些声音支持使用`var`会降低代码可读性，而另一些声音则支持相反的观点。根据用例的不同，它可能需要在可读性上进行权衡，但事实是，通常情况下，我们非常关注字段（实例变量）的有意义的名称，而忽略了局部变量的名称。例如，让我们考虑以下方法：

```java
public Object fetchTransferableData(String data)
    throws UnsupportedFlavorException, IOException {

  StringSelection ss = new StringSelection(data);
  DataFlavor[] df = ss.getTransferDataFlavors();
  Object obj = ss.getTransferData(df[0]);

  return obj;
}
```

这是一个简短的方法；它有一个有意义的名称和一个干净的实现。但是检查局部变量的名称。它们的名称大大减少（它们只是快捷方式），但这不是问题，因为左侧提供了足够的信息，我们可以很容易地理解每个局部变量的类型。现在，让我们使用 LVTI 编写以下代码：

```java
public Object fetchTransferableData(String data)
    throws UnsupportedFlavorException, IOException {

  var ss = new StringSelection(data);
  var df = ss.getTransferDataFlavors();
  var obj = ss.getTransferData(df[0]);

  return obj;
}
```

显然，代码的可读性降低了，因为现在很难推断出局部变量的类型。如下面的屏幕截图所示，编译器在推断正确的类型方面没有问题，但是对于人类来说，这要困难得多：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-cd-prob/img/95cb6f1d-d16c-4a89-b68b-50281887697b.png)

这个问题的解决方案是在依赖 LVTI 时为局部变量提供一个有意义的名称。例如，如果提供了局部变量的名称，代码可以恢复可读性，如下所示：

```java
public Object fetchTransferableData(String data)
    throws UnsupportedFlavorException, IOException {

  var stringSelection = new StringSelection(data);
  var dataFlavorsArray = stringSelection.getTransferDataFlavors();
  var obj = stringSelection.getTransferData(dataFlavorsArray[0]);

  return obj;
}
```

然而，可读性问题也是由这样一个事实引起的：通常，我们倾向于将类型视为主要信息，将变量名视为次要信息，而这应该是相反的。

让我们再看两个例子来执行上述语句。使用集合（例如，`List`）的方法如下：

```java
// Avoid
public List<Player> fetchPlayersByTournament(String tournament) {

  var t = tournamentRepository.findByName(tournament);
  var p = t.getPlayers();

  return p;
}

// Prefer
public List<Player> fetchPlayersByTournament(String tournament) {

  var tournamentName = tournamentRepository.findByName(tournament);
  var playerList = tournamentName.getPlayers();

  return playerList;
}
```

为局部变量提供有意义的名称并不意味着陷入*过度命名*技术。

例如，通过简单地重复类型名来避免命名变量：

```java
// Avoid
var fileCacheImageOutputStream​ 
  = new FileCacheImageOutputStream​(..., ...);

// Prefer
var outputStream​ = new FileCacheImageOutputStream​(..., ...);

// Or
var outputStreamOfFoo​ = new FileCacheImageOutputStream​(..., ...);
```

# 79 对原始类型使用`var`

将 LVTI 与原始类型（`int`、`long`、`float`和`double`）一起使用的问题是，预期类型和推断类型可能不同。显然，这会导致代码中的混乱和意外行为。

这种情况下的犯罪方是`var`类型使用的*隐式类型转换*。

例如，让我们考虑以下两个依赖显式原始类型的声明：

```java
boolean valid = true; // this is of type boolean
char c = 'c';         // this is of type char
```

现在，让我们用 LVTI 替换显式原始类型：

```java
var valid = true; // inferred as boolean
var c = 'c';      // inferred as char
```

很好！到目前为止没有问题！现在，让我们看看另一组基于显式原始类型的声明：

```java
int intNumber = 10;       // this is of type int
long longNumber = 10;     // this is of type long
float floatNumber = 10;   // this is of type float, 10.0
double doubleNumber = 10; // this is of type double, 10.0
```

让我们按照第一个示例中的逻辑，用 LVTI 替换显式原始类型：

```java
// Avoid
var intNumber = 10;    // inferred as int
var longNumber = 10;   // inferred as int
var floatNumber = 10;  // inferred as int
var doubleNumber = 10; // inferred as int
```

根据以下屏幕截图，所有四个变量都被推断为整数：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-cd-prob/img/ec6aa8f3-a41c-4cc5-bff2-9d08083bcc91.png)

这个问题的解决方案包括使用显式 Java *字面值*：

```java
// Prefer
var intNumber = 10;     // inferred as int
var longNumber = 10L;   // inferred as long
var floatNumber = 10F;  // inferred as float, 10.0
var doubleNumber = 10D; // inferred as double, 10.0
```

最后，让我们考虑一个带小数的数字的情况，如下所示：

```java
var floatNumber = 10.5; // inferred as double
```

变量名表明`10.5`是`float`，但实际上是推断为`double`。因此，即使是带小数的数字（尤其是带小数的数字），也建议使用*字面值*：

```java
var floatNumber = 10.5F; // inferred as float
```

# 80 使用`var`和隐式类型转换来维持代码的可维护性

在上一节中，“将`var`与原始类型结合使用”，我们看到将`var`与*隐式类型转换*结合使用会产生实际问题。但在某些情况下，这种组合可能是有利的，并维持代码的可维护性。

让我们考虑以下场景，我们需要编写一个方法，该方法位于名为`ShoppingAddicted`的外部 API 的两个现有方法之间（通过推断，这些方法可以是两个 Web 服务、端点等）。有一种方法专门用于返回给定购物车的最佳价格。基本上，这种方法需要一堆产品，并查询不同的在线商店，以获取最佳价格。

结果价格返回为`int`。此方法的存根如下所示：

```java
public static int fetchBestPrice(String[] products) {

  float realprice = 399.99F; // code to query the prices in stores
  int price = (int) realprice;

  return price;
}
```

另一种方法将价格作为`int`接收并执行支付。如果支付成功，则返回`true`：

```java
public static boolean debitCard(int amount) {

  return true;
}
```

现在，通过对该代码进行编程，我们的方法将充当客户端，如下所示（客户可以决定购买哪些商品，我们的代码将为他们返回最佳价格并相应地借记卡）：

```java
// Avoid
public static boolean purchaseCart(long customerId) {

  int price = ShoppingAddicted.fetchBestPrice(new String[0]);
  boolean paid = ShoppingAddicted.debitCard(price);

  return paid;
}
```

但是过了一段时间，`ShoppingAddicted`API 的拥有者意识到他们通过将实际价格转换成`int`来赔钱（例如，实际价格是 399.99，但在`int`形式中，它是 399.0，这意味着损失 99 美分）。因此，他们决定放弃这种做法，将实际价格返回为`float`：

```java
public static float fetchBestPrice(String[] products) {

  float realprice = 399.99F; // code to query the prices in stores

  return realprice;
}
```

因为返回的价格是`float`，所以`debitCard()`也会更新：

```java
public static boolean debitCard(float amount) {

  return true;
}
```

但是，一旦我们升级到新版本的`ShoppingAddicted`API，代码将失败，并有可能从`float`到`int`异常的*有损转换*。这是正常的，因为我们的代码需要`int`。由于我们的代码不能很好地容忍这些修改，因此需要相应地修改代码。

然而，如果我们已经预见到这种情况，并且使用了`var`而不是`int`，那么由于*隐式类型转换*，代码将不会出现问题：

```java
// Prefer
public static boolean purchaseCart(long customerId) {

  var price = ShoppingAddicted.fetchBestPrice(new String[0]);
  var paid = ShoppingAddicted.debitCard(price);

  return paid;
}
```

# 81 显式向下转换或更好地避免`var`

在“将`var`与原始类型结合使用”一节中，我们讨论了将*字面值*与原始类型结合使用（`int`、`long`、`float`和`double`来避免*隐式类型转换*带来的问题。但并非所有 Java 原始类型都可以利用*字面值*。在这种情况下，最好的方法是避免使用`var`。但让我们看看为什么！

检查以下关于`byte`和`short`变量的声明：

```java
byte byteNumber = 25;     // this is of type byte
short shortNumber = 1463; // this is of type short
```

如果我们用`var`替换显式类型，那么推断的类型将是`int`：

```java
var byteNumber = 25;    // inferred as int
var shortNumber = 1463; // inferred as int
```

不幸的是，这两种基本类型没有可用的*字面值*。帮助编译器推断正确类型的唯一方法是依赖显式向下转换：

```java
var byteNumber = (byte) 25;     // inferred as byte
var shortNumber = (short) 1463; // inferred as short
```

虽然这段代码编译成功并按预期工作，但我们不能说使用`var`比使用显式类型带来了任何价值。因此，在这种情况下，最好避免`var`和显式的向下转型。

# 82 如果被调用的名称没有包含足够的类型信息，请避免使用`var`

好吧，`var`不是一颗银弹，这个问题将再次凸显这一点。以下代码片段可以使用显式类型或`var`编写，而不会丢失信息：

```java
// using explicit types
MemoryCacheImageInputStream is =
  new MemoryCacheImageInputStream(...);
JavaCompiler jc = ToolProvider.getSystemJavaCompiler();
StandardJavaFileManager fm = compiler.getStandardFileManager(...);
```

因此，将前面的代码片段迁移到`var`将产生以下代码（通过从右侧目视检查被调用的*名称*来选择变量名称）：

```java
// using var
var inputStream = new MemoryCacheImageInputStream(...);
var compiler = ToolProvider.getSystemJavaCompiler();
var fileManager = compiler.getStandardFileManager(...);
```

同样的情况也会发生在过度命名的边界上：

```java
// using var
var inputStreamOfCachedImages = new MemoryCacheImageInputStream(...);
var javaCompiler = ToolProvider.getSystemJavaCompiler();
var standardFileManager = compiler.getStandardFileManager(...);
```

因此，前面的代码在选择变量的名称和可读性时不会引起任何问题。所谓的*名称*包含了足够的信息，让人类对`var`感到舒服。

但让我们考虑以下代码片段：

```java
// Avoid
public File fetchBinContent() {
  return new File(...);
}

// called from another place
// notice the variable name, bin
var bin = fetchBinContent();
```

对于人类来说，如果不检查*名称*、`fetchBinContent()`的返回类型，就很难推断出*名称*返回的类型。根据经验，在这种情况下，解决方案应该避免`var`并依赖显式类型，因为右侧没有足够的信息让我们为变量选择合适的名称并获得可读性很高的代码：

```java
// called from another place
// now the left-hand side contains enough information
File bin = fetchBinContent();
```

因此，如果将`var`与被调用的*名称*组合使用导致清晰度损失，则最好避免使用`var`。忽略此语句可能会导致混淆，并会增加理解和/或扩展代码所需的时间。

考虑另一个基于`java.nio.channels.Selector`类的例子。此类公开了一个名为`open()`的`static`方法，该方法返回一个新打开的`Selector`。但是，如果我们在一个用`var`声明的变量中捕获这个返回值，我们很可能会认为这个方法可能返回一个`boolean`，表示打开当前选择器的成功。使用`var`而不考虑可能的清晰度损失会产生这些问题。像这样的一些问题和代码将成为一个真正的痛苦。

# 83 LVTI 与面向接口编程技术相结合

Java 最佳实践鼓励我们将代码绑定到抽象。换句话说，我们需要依赖于*面向接口编程*的技术。

这种技术非常适合于集合声明。例如，建议声明`ArrayList`如下：

```java
List<String> players = new ArrayList<>();
```

我们也应该避免这样的事情：

```java
ArrayList<String> players = new ArrayList<>();
```

通过遵循第一个示例，代码实例化了`ArrayList`类（或`HashSet`、`HashMap`等），但声明了一个`List`类型的变量（或`Set`、`Map`等）。由于`List`、`Set`、`Map`以及更多的都是接口（或契约），因此很容易用`List`（`Set`和`Map`的其他实现来替换实例化，而无需对代码进行后续修改。

不幸的是，LVTI 不能利用*面向接口编程*技术。换句话说，当我们使用`var`时，推断的类型是具体的实现，而不是合同。例如，将`List<String>`替换为`var`将导致推断类型`ArrayList<String>`：

```java
// inferred as ArrayList<String>
var playerList = new ArrayList<String>();
```

然而，有一些解释支持这种行为：

*   LVTI 在局部级别（局部变量）起作用，其中*面向接口编程*技术的的使用少于方法参数/返回类型或字段类型。
*   由于局部变量的作用域很小，因此切换到另一个实现所引起的修改也应该很小。切换实现对检测和修复代码的影响应该很小。
*   LVTI 将右侧的代码视为一个用于推断实际类型的*初始化器*。如果将来要修改这个*初始化器*，那么推断的类型可能不同，这将导致使用此变量的代码出现问题。

# 84 LVTI 和菱形运算符相结合

根据经验，如果右侧不存在推断预期类型所需的信息，则 LVTI 与*菱形*运算符结合可能会导致意外的推断类型。

在 JDK7 之前，即 Coin 项目，`List<String>`将声明如下：

```java
List<String> players = new ArrayList<String>();
```

基本上，前面的示例显式指定泛型类的实例化参数类型。从 JDK7 开始，Coin 项目引入了*菱形*操作符，可以推断泛型类实例化参数类型，如下所示：

```java
List<String> players = new ArrayList<>();
```

现在，如果我们从 LVTI 的角度来考虑这个例子，我们将得到以下结果：

```java
var playerList = new ArrayList<>();
```

但是现在推断出的类型是什么呢？好吧，我们有一个问题，因为推断的类型将是`ArrayList<Object>`，而不是`ArrayList<String>`。解释很明显：推断预期类型（`String`所需的信息不存在（注意，右侧没有提到`String`类型）。这指示 LVTI 推断出最广泛适用的类型，在本例中是`Object`。

但是如果`ArrayList<Object>`不是我们的意图，那么我们需要一个解决这个问题的方法。解决方案是提供推断预期类型所需的信息，如下所示：

```java
var playerList = new ArrayList<String>();
```

现在，推断的类型是`ArrayList<String>`。也可以间接推断类型。请参见以下示例：

```java
var playerStack = new ArrayDeque<String>();

// inferred as ArrayList<String>
var playerList = new ArrayList<>(playerStack);
```

也可以通过以下方式间接推断：

```java
Player p1 = new Player();
Player p2 = new Player();
var listOfPlayer = List.of(p1, p2); // inferred as List<Player>

// Don't do this!
var listOfPlayer = new ArrayList<>(); // inferred as ArrayList<Object>
listOfPlayer.add(p1);
listOfPlayer.add(p2);
```

# 85 将数组赋给`var`

根据经验，将数组分配给`var`不需要括号`[]`。通过相应的显式类型定义一个`int`数组可以如下所示：

```java
int[] numbers = new int[10];

// or, less preferred
int numbers[] = new int[10];
```

现在，尝试直觉地使用`var`代替`int`可能会导致以下尝试：

```java
var[] numberArray = new int[10];
var numberArray[] = new int[10];
```

不幸的是，这两种方法都无法编译。解决方案要求我们从左侧拆下支架：

```java
// Prefer
var numberArray = new int[10]; // inferred as array of int, int[]
numberArray[0] = 3;            // works
numberArray[0] = 3.2;          // doesn't work
numbers[0] = "3";              // doesn't work
```

通常的做法是在声明时初始化数组，如下所示：

```java
// explicit type work as expected
int[] numbers = {1, 2, 3};
```

但是，尝试使用`var`将不起作用（不会编译）：

```java
// Does not compile
var numberArray = {1, 2, 3};
var numberArray[] = {1, 2, 3};
var[] numberArray = {1, 2, 3};
```

此代码无法编译，因为右侧没有自己的类型。

# 86 在复合声明中使用 LVTI

复合声明允许我们声明一组相同类型的变量，而无需重复该类型。类型只指定一次，变量用逗号分隔：

```java
// using explicit type
String pending = "pending", processed = "processed", 
       deleted = "deleted";
```

将`String`替换为`var`将导致无法编译的代码：

```java
// Does not compile
var pending = "pending", processed = "processed", deleted = "deleted";
```

此问题的解决方案是将复合声明转换为每行一个声明：

```java
// using var, the inferred type is String
var pending = "pending";
var processed = "processed";
var deleted = "deleted";
```

因此，根据经验，LVTI 不能用在复合声明中。

# 87 LVTI 和变量范围

干净的代码最佳实践包括为所有局部变量保留一个小范围。这是在 LVTI 存在之前就遵循的干净代码黄金规则之一。

此规则支持可读性和调试阶段。它可以加快查找错误和编写修复程序的过程。请考虑以下打破此规则的示例：

```java
// Avoid
...
var stack = new Stack<String>();
stack.push("John");
stack.push("Martin");
stack.push("Anghel");
stack.push("Christian");

// 50 lines of code that doesn't use stack

// John, Martin, Anghel, Christian
stack.forEach(...);
```

因此，前面的代码声明了一个具有四个名称的栈，包含 50 行不使用此栈的代码，并通过`forEach()`方法完成此栈的循环。此方法继承自`java.util.Vector`，将栈作为任意向量（`John`、`Martin`、`Anghel`、`Christian`循环。这是我们想要的遍历顺序。

但后来，我们决定从栈切换到`ArrayDeque`（原因无关紧要）。这次，`forEach()`方法将是由`ArrayDeque`类提供的方法。此方法的行为不同于`Vector.forEach()`，即循环将遍历**后进先出**（**LIFO**）遍历（`Christian`、`Anghel`、`Martin`、`John`之后的条目：

```java
// Avoid
...
var stack = new ArrayDeque<String>();
stack.push("John");
stack.push("Martin");
stack.push("Anghel");
stack.push("Christian");

// 50 lines of code that doesn't use stack

// Christian, Anghel, Martin, John
stack.forEach(...);
```

这不是我们的本意！我们切换到`ArrayDeque`是为了其他目的，而不是为了影响循环顺序。但是很难看出代码中有 bug，因为包含`forEach()`部分的代码部分不在我们完成修改的代码附近（代码行下面 50 行）。我们有责任提出一个解决方案，最大限度地提高快速修复这个 bug 的机会，避免一堆上下滚动来了解正在发生的事情。解决方案包括遵循我们之前调用的干净代码规则，并使用小范围的`stack`变量编写此代码：

```java
// Prefer
...
var stack = new Stack<String>();
stack.push("John");
stack.push("Martin");
stack.push("Anghel");
stack.push("Christian");

// John, Martin, Anghel, Christian
stack.forEach(...);

// 50 lines of code that doesn't use stack
```

现在，当我们从`Stack`切换到`ArrayQueue`时，我们应该更快地注意到错误并能够修复它。

# 88 LVTI 与三元运算符

只要写入正确，*三元*运算符允许我们在右侧使用不同类型的操作数。例如，以下代码将不会编译：

```java
// Does not compile
List evensOrOdds = containsEven ?
  List.of(10, 2, 12) : Set.of(13, 1, 11);

// Does not compile
Set evensOrOdds = containsEven ?
  List.of(10, 2, 12) : Set.of(13, 1, 11);
```

但是，可以通过使用正确/支持的显式类型重写代码来修复此代码：

```java
Collection evensOrOdds = containsEven ?
  List.of(10, 2, 12) : Set.of(13, 1, 11);

Object evensOrOdds = containsEven ?
  List.of(10, 2, 12) : Set.of(13, 1, 11);
```

对于以下代码片段，类似的尝试将失败：

```java
// Does not compile
int numberOrText = intOrString ? 2234 : "2234";

// Does not compile
String numberOrText = intOrString ? 2234 : "2234";
```

但是，可以这样修复：

```java
Serializable numberOrText = intOrString ? 2234 : "2234";

Object numberOrText = intOrString ? 2234 : "2234";
```

因此，为了在右侧有一个具有不同类型操作数的三元运算符，开发人员必须匹配支持两个条件分支的正确类型。或者，开发人员可以依赖 LVTI，如下所示（当然，这也适用于相同类型的操作数）：

```java
// inferred type, Collection<Integer>
var evensOrOddsCollection = containsEven ?
  List.of(10, 2, 12) : Set.of(13, 1, 11);

// inferred type, Serializable
var numberOrText = intOrString ? 2234 : "2234";
```

不要从这些例子中得出结论，`var`类型是在运行时推断出来的！不是的！

# 89 LVTI 和`for`循环

使用显式类型声明简单的`for`循环是一项琐碎的任务，如下所示：

```java
// explicit type
for (int i = 0; i < 5; i++) {
  ...
}
```

或者，我们可以使用增强的`for`循环：

```java
List<Player> players = List.of(
  new Player(), new Player(), new Player());
for (Player player: players) {
  ...
}
```

从 JDK10 开始，我们可以将变量的显式类型`i`和`player`替换为`var`，如下所示：

```java
for (var i = 0; i < 5; i++) { // i is inferred of type int
  ...
}

for (var player: players) { // i is inferred of type Player
  ...
}
```

当循环数组、集合等的类型发生更改时，使用`var`可能会有所帮助。例如，通过使用`var`，可以在不指定显式类型的情况下循环以下`array`的两个版本：

```java
// a variable 'array' representing an int[]
int[] array = { 1, 2, 3 };

// or the same variable, 'array', but representing a String[]
String[] array = {
  "1", "2", "3"
};

// depending on how 'array' is defined 
// 'i' will be inferred as int or as String
for (var i: array) {
  System.out.println(i);
}
```

# 90 LVTI 和流

让我们考虑以下`Stream<Integer>`流：

```java
// explicit type
Stream<Integer> numbers = Stream.of(1, 2, 3, 4, 5);
numbers.filter(t -> t % 2 == 0).forEach(System.out::println);
```

使用 LVTI 代替`Stream<Integer>`非常简单。只需将`Stream<Integer>`替换为`var`，如下所示：

```java
// using var, inferred as Stream<Integer>
var numberStream = Stream.of(1, 2, 3, 4, 5);
numberStream.filter(t -> t % 2 == 0).forEach(System.out::println);
```

下面是另一个例子：

```java
// explicit types
Stream<String> paths = Files.lines(Path.of("..."));
List<File> files = paths.map(p -> new File(p)).collect(toList());

// using var
// inferred as Stream<String>
var pathStream = Files.lines(Path.of(""));

// inferred as List<File>
var fileList = pathStream.map(p -> new File(p)).collect(toList());
```

看起来 Java10、LVTI、Java8 和`Stream`API 是一个很好的团队。

# 91 使用 LVTI 分解嵌套/大型表达式链

大型/嵌套表达式通常是一些代码片段，它们看起来非常令人印象深刻，令人生畏。它们通常被视为*智能*或*智慧*代码的片段。关于这是好是坏是有争议的，但最有可能的是，这种平衡倾向于有利于那些声称应该避免这种代码的人。例如，检查以下表达式：

```java
List<Integer> ints = List.of(1, 1, 2, 3, 4, 4, 6, 2, 1, 5, 4, 5);

// Avoid
int result = ints.stream()
  .collect(Collectors.partitioningBy(i -> i % 2 == 0))
  .values()
  .stream()
  .max(Comparator.comparing(List::size))
  .orElse(Collections.emptyList())
  .stream()
  .mapToInt(Integer::intValue)
  .sum();
```

这样的表达式可以是有意编写的，也可以表示一个增量过程的最终结果，该过程在时间上丰富了一个最初很小的表达式。然而，当这些表达式开始成为可读性的空白时，它们必须通过局部变量被分解成碎片。但这并不有趣，可以被认为是我们想要避免的令人筋疲力尽的工作：

```java
List<Integer> ints = List.of(1, 1, 2, 3, 4, 4, 6, 2, 1, 5, 4, 5);

// Prefer
Collection<List<Integer>> evenAndOdd = ints.stream()
  .collect(Collectors.partitioningBy(i -> i % 2 == 0))
  .values();

List<Integer> evenOrOdd = evenAndOdd.stream()
  .max(Comparator.comparing(List::size))
  .orElse(Collections.emptyList());

int sumEvenOrOdd = evenOrOdd.stream()
  .mapToInt(Integer::intValue)
  .sum();
```

检查前面代码中局部变量的类型。我们有`Collection<List<Integer>>`、`List<Integer>`和`int`。很明显，这些显式类型需要一些时间来获取和写入。这可能是避免将此表达式拆分为碎片的一个很好的理由。然而，如果我们希望采用局部变量的样式，那么使用`var`类型而不是显式类型的琐碎性是很诱人的，因为它节省了通常用于获取显式类型的时间：

```java
var intList = List.of(1, 1, 2, 3, 4, 4, 6, 2, 1, 5, 4, 5);

// Prefer
var evenAndOdd = intList.stream()
  .collect(Collectors.partitioningBy(i -> i % 2 == 0))
  .values();

var evenOrOdd = evenAndOdd.stream()
  .max(Comparator.comparing(List::size))
  .orElse(Collections.emptyList());

var sumEvenOrOdd = evenOrOdd.stream()
  .mapToInt(Integer::intValue)
  .sum();
```

令人惊叹的！现在，编译器的任务是推断这些局部变量的类型。我们只选择打破表达的点，用`var`来划分。

# 92 LVTI 和方法返回值和参数类型

根据经验，LVTI 不能用作`return`方法类型或参数方法类型；相反，`var`类型的变量可以作为方法参数传递或存储`return`方法。让我们通过几个例子来迭代这些语句：

*   LVTI 不能用作以下代码不编译的方法返回类型：

```java
// Does not compile
public var fetchReport(Player player, Date timestamp) {

  return new Report();
}
```

*   LVTI 不能用作方法参数类型以下代码不编译：

```java
public Report fetchReport(var player, var timestamp) {

  return new Report();
}
```

*   `var`类型的变量可以作为方法参数传递，也可以存储一个返回方法。下面的代码编译成功并且可以工作：

```java
public Report checkPlayer() {

  var player = new Player();
  var timestamp = new Date();
  var report = fetchReport(player, timestamp);

  return report;
}

public Report fetchReport(Player player, Date timestamp) {

  return new Report();
}
```

# 93 LVTI 和匿名类

LVTI 可以用于匿名类。下面是一个匿名类的示例，该类对`weighter`变量使用显式类型：

```java
public interface Weighter {
  int getWeight(Player player);
}

Weighter weighter = new Weighter() {
  @Override
  public int getWeight(Player player) {
    return ...;
  }
};

Player player = ...;
int weight = weighter.getWeight(player);
```

现在，看看如果我们使用 LVTI 会发生什么：

```java
var weighter = new Weighter() {
  @Override
  public int getWeight(Player player) {
    return ...;
  }
};
```

# 94 LVTI 可以是最终的，也可以是有效最终的

作为一个快速提醒，*从 JavaSE8 开始，一个局部类可以访问封闭块的局部变量和参数，这些变量和参数是`final`或实际上是`final`。一个变量或参数，其值在初始化后从未改变，实际上是最终的*。

下面的代码片段表示一个*有效最终*变量（尝试重新分配`ratio`变量将导致错误，这意味着该变量是*有效最终*）和两个`final`变量（尝试重新分配`limit`和`bmi`变量将导致错误）的用例在一个错误中，这意味着这些变量是`final`：

```java
public interface Weighter {
  float getMarginOfError();
}

float ratio = fetchRatio(); // this is effectively final

var weighter = new Weighter() {
  @Override
  public float getMarginOfError() {
    return ratio * ...;
  }
};

ratio = fetchRatio(); // this reassignment will cause error

public float fetchRatio() {

  final float limit = new Random().nextFloat(); // this is final
  final float bmi = 0.00023f;                   // this is final

  limit = 0.002f; // this reassignment will cause error
  bmi = 0.25f;    // this reassignment will cause error

  return limit * bmi / 100.12f;
}
```

现在，让我们用`var`替换显式类型。编译器将推断出这些变量（`ratio`、`limit`和`bmi`的正确类型并保持它们的状态-`ratio`将是*有效最终*，而`limit`和`bmi`是`final`。尝试重新分配其中任何一个将导致特定错误：

```java
var ratio = fetchRatio(); // this is effectively final 
var weighter = new Weighter() {
  @Override
  public float getMarginOfError() {
    return ratio * ...;
  }
};

ratio = fetchRatio(); // this reassignment will cause error 
public float fetchRatio() {

  final var limit = new Random().nextFloat(); // this is final
 final var bmi = 0.00023f; // this is final
 limit = 0.002f; // this reassignment will cause error
 bmi = 0.25f; // this reassignment will cause error
  return limit * bmi / 100.12f;
}
```

# 95 LVTI 和 Lambda

使用 LVTI 和 Lambda 的问题是无法推断具体类型。不允许使用 Lambda 和方法引用*初始化器*。此语句是`var`限制的一部分；因此，Lambda 表达式和方法引用需要显式的目标类型。

例如，以下代码片段将不会编译：

```java
// Does not compile
// lambda expression needs an explicit target-type
var incrementX = x -> x + 1;

// method reference needs an explicit target-type
var exceptionIAE = IllegalArgumentException::new;
```

由于`var`不能使用，所以这两段代码需要编写如下：

```java
Function<Integer, Integer> incrementX = x -> x + 1;
Supplier<IllegalArgumentException> exceptionIAE 
  = IllegalArgumentException::new;
```

但是在 Lambda 的上下文中，Java11 允许我们在 Lambda 参数中使用`var`。例如，下面的代码在 Java11 中工作（更多详细信息可以在[《JEP323：Lambda 参数的局部变量语法》](https://openjdk.java.net/jeps/323)中找到：

```java
@FunctionalInterface
public interface Square {
  int calculate(int x);
}

Square square = (var x) -> x * x;
```

但是，请记住，以下操作不起作用：

```java
var square = (var x) -> x * x; // cannot infer
```

# 96 LVTI 和`null`初始化器、实例变量和`catch`块变量

LVTI 与`null`*初始化器*、实例变量和`catch`块变量有什么共同点？嗯，LVTI 不能和它们一起使用。以下尝试将失败：

*   LVTI 不能与`null`*初始化器*一起使用：

```java
// result in an error of type: variable initializer is 'null'
var message = null;

// result in: cannot use 'var' on variable without initializer
var message;
```

*   LVTI 不能与实例变量（字段）一起使用：

```java
public class Player {

  private var age; // error: 'var' is not allowed here
  private var name; // error: 'var' is not allowed here
  ...
}
```

*   LVTI 不能用于`catch`块变量：

```java
try {
  TimeUnit.NANOSECONDS.sleep(1000);
} catch (var ex) {  ... }
```

# 资源尝试使用

另一方面，`var`类型非常适合*资源尝试使用*，如下例所示：

```java
// explicit type
try (PrintWriter writer = new PrintWriter(new File("welcome.txt"))) {
  writer.println("Welcome message");
}
```

```java
// using var
try (var writer = new PrintWriter(new File("welcome.txt"))) {
  writer.println("Welcome message");
}
```

# 97 LVTI 和泛型类型，`T`

为了理解 LVTI 如何与泛型类型相结合，让我们从一个示例开始。以下方法是泛型类型`T`的经典用例：

```java
public static <T extends Number> T add(T t) {
  T temp = t;
  ...
  return temp;
}
```

在这种情况下，我们可以将`T`替换为`var`，代码将正常工作：

```java
public static <T extends Number> T add(T t) {
  var temp = t;
  ...
  return temp;
}
```

因此，具有泛型类型的局部变量可以利用 LVTI。让我们看看其他一些示例，首先使用泛型类型`T`：

```java
public <T extends Number> T add(T t) {

  List<T> numberList = new ArrayList<T>();
  numberList.add(t);
  numberList.add((T) Integer.valueOf(3));
  numberList.add((T) Double.valueOf(3.9));

  // error: incompatible types: String cannot be converted to T
  // numbers.add("5");

  return numberList.get(0);
}
```

现在，我们将`List<T>`替换为`var`：

```java
public <T extends Number> T add(T t) {

  var numberList = new ArrayList<T>();
  numberList.add(t);
  numberList.add((T) Integer.valueOf(3));
  numberList.add((T) Double.valueOf(3.9));

  // error: incompatible types: String cannot be converted to T
  // numbers.add("5");

  return numberList.get(0);
}
```

注意并仔细检查`ArrayList`实例化是否存在`T`。不要这样做（这将被推断为`ArrayList<Object>`，并将忽略泛型类型`T`后面的实际类型）：

```java
var numberList = new ArrayList<>();
```

# 98 LVTI、通配符、协变和逆变

用 LVTI 替换通配符、协变和逆变是一项微妙的工作，应该在充分意识到后果的情况下完成。

# LVTI 和通配符

首先，我们来讨论 LVTI 和通配符（`?`。通常的做法是将通配符与`Class`关联，并编写如下内容：

```java
// explicit type
Class<?> clazz = Long.class;
```

在这种情况下，使用`var`代替`Class<?>`没有问题。根据右边的类型，编译器将推断出正确的类型。在本例中，编译器将推断出`Class<Long>`。

但是请注意，用 LVTI 替换通配符应该小心，并且您应该意识到其后果（或副作用）。让我们看一个例子，用`var`替换通配符是一个错误的选择。考虑以下代码：

```java
Collection<?> stuff = new ArrayList<>();
stuff.add("hello"); // compile time error
stuff.add("world"); // compile time error
```

由于类型不兼容，此代码无法编译。一种非常糟糕的方法是用`var`替换通配符来修复此代码，如下所示：

```java
var stuff = new ArrayList<>();
strings.add("hello"); // no error
strings.add("world"); // no error
```

通过使用`var`，错误将消失，但这不是我们在编写前面的代码（存在类型不兼容错误的代码）时想到的。所以，根据经验，不要仅仅因为一些恼人的错误会神奇地消失，就用`var`代替`Foo<?>`！试着思考一下预期的任务是什么，并相应地采取行动。例如，可能在前面的代码片段中，我们试图定义`ArrayList<String>`，但由于错误，最终得到了`Collection<?>`。

# LVTI 和协变/逆变

用 LVTI 替换协变（`Foo<? extends T>`）或逆变（`Foo<? super T>`）是一种危险的方法，应该避免。

请查看以下代码片段：

```java
// explicit types
Class<? extends Number> intNumber = Integer.class;
Class<? super FilterReader> fileReader = Reader.class;
```

在协变中，我们有一个上界，由`Number`类表示，而在逆变中，我们有一个下界，由`FilterReader`类表示。有了这些边界（或约束），以下代码将触发特定的编译时错误：

```java
// Does not compile
// error: Class<Reader> cannot be converted 
//        to Class<? extends Number>
Class<? extends Number> intNumber = Reader.class;

// error: Class<Integer> cannot be converted 
//        to Class<? super FilterReader>
Class<? super FilterReader> fileReader = Integer.class;
```

现在，让我们用`var`代替前面的协变和逆变：

```java
// using var
var intNumber = Integer.class;
var fileReader = Reader.class;
```

此代码不会导致任何问题。现在，我们可以将任何类赋给这些变量，这样我们的边界/约束就消失了。这不是我们打算做的：

```java
// this will compile just fine
var intNumber = Reader.class;
var fileReader = Integer.class;
```

所以，用`var`代替协变和逆变是个错误的选择！

# 总结

这是本章的最后一个问题。请看[《JEP323：Lambda 参数的局部变量语法》](https://openjdk.java.net/jeps/323)、[《JEP301：增强枚举》](http://openjdk.java.net/jeps/301)了解更多信息。只要您熟悉本章介绍的问题，采用这些特性应该是相当顺利的。

从本章下载应用以查看结果和其他详细信息。


# 五、数组、集合和数据结构

> 原文：[Java Coding Problems](https://libgen.rs/book/index.php?md5=3280024C263466704C8F7525E5BB6AAE)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)
> 
> 贡献者：[飞龙](https://github.com/wizardforcel)
> 
> 本文来自[【ApacheCN Java 译文集】](https://github.com/apachecn/apachecn-java-zh)，自豪地采用[谷歌翻译](https://translate.google.cn/)。

本章包括 30 个问题，涉及数组、集合和几个数据结构。其目的是为在广泛的应用中遇到的一类问题提供解决方案，包括排序、查找、比较、排序、反转、填充、合并、复制和替换。提供的解决方案是用 Java8-12 实现的，它们也可以作为解决其他相关问题的基础。在本章的最后，您将掌握广泛的知识，这些知识对于解决涉及数组、集合和数据结构的各种问题非常有用。

# 问题

使用以下问题测试基于数组、集合和数据结构的编程能力。我强烈建议您在使用解决方案和下载示例程序之前，先尝试一下每个问题：

99.  **数组排序**：编写几个程序，举例说明数组的不同排序算法。另外，编写一个数组洗牌程序。
100.  **寻找数组中的元素**：编写几个程序，举例说明如何在给定的数组中找到给定的元素（原始类型和对象）。查找索引和/或简单地检查值是否在数组中。
101.  **检查两个数组是否相等或不匹配**：编写一个程序，检查给定的两个数组是否相等或不匹配。
102.  **按字典比较两个数组**：编写一个程序，按字典法比较给定的数组。

103.  **从数组创建流**：编写从给定数组创建流的程序。
104.  **数组的最小值、最大值和平均值**：编写一个程序，计算给定数组的最大值、最小值和平均值。
105.  **反转数组**：写一个程序反转给定的数组。
106.  **填充和设置数组**：写几个填充数组和基于生成函数设置所有元素的例子来计算每个元素。
107.  **下一个较大的元素**（**NGE**）：编写一个程序，返回数组中每个元素的 NGE。
108.  **改变数组大小**：编写一个程序，通过将数组的大小增加一个元素来增加数组的大小。另外，编写一个程序，用给定的长度增加数组的大小。
109.  **创建不可修改/不可变集合**：编写几个创建不可修改和不可变集合的示例。
110.  **映射的默认值**：编写一个程序，从`Map`获取一个值或一个默认值。
111.  **计算`Map`中的键是否缺失/存在**：编写一个程序，计算缺失键的值或当前键的新值。
112.  **从`Map`中删除条目**：编写一个程序，用给定的键从`Map`删除。
113.  **替换`Map`中的条目**：编写一个程序来替换`Map`中给定的条目。
114.  **比较两个映射**：编写一个比较两幅映射的程序。
115.  **合并两个映射**：编写一个程序，合并两个给定的映射。
116.  **复制`HashMap`**：编写一个程序，执行`HashMap`的浅复制和深复制。
117.  **排序`Map`**：编写一个程序对`Map`进行排序。
118.  **删除集合中与谓词匹配的所有元素**：编写一个程序，删除集合中与给定谓词匹配的所有元素。
119.  **将集合转换成数组**：编写一个程序，将集合转换成数组。
120.  **过滤`List`集合**：写几个`List`过滤集合的方案。揭示最好的方法。
121.  **替换`List`的元素**：编写一个程序，将`List`的每个元素替换为对其应用给定运算符的结果。
122.  **线程安全集合、栈和队列**：编写几个程序来举例说明 Java 线程安全集合的用法。
123.  **广度优先搜索**（**BFS**）：编写实现 BFS 算法的程序。
124.  **Trie**：编写一个实现 Trie 数据结构的程序。
125.  **元组**：编写实现元组数据结构的程序。
126.  **并查**：编写实现并查算法的程序。
127.  **Fenwick 树或二叉索引树**：编写一个实现 Fenwick 树算法的程序。
128.  **布隆过滤器**：编写实现布隆过滤器算法的程序。

 **# 解决方案

以下各节介绍上述问题的解决方案。记住，通常没有一个正确的方法来解决一个特定的问题。另外，请记住，这里显示的解释仅包括解决问题所需的最有趣和最重要的细节。下载示例解决方案以查看更多详细信息，并在[这个页面](https://github.com/PacktPublishing/Java-Coding-Problems)中试用程序。

# 99 排序数组

排序数组是许多域/应用中遇到的常见任务。Java 提供了一个内置的解决方案，使用比较器对原始类型和对象的数组进行排序，这一点非常常见。这种解决方案效果很好，在大多数情况下都是比较可取的方法。让我们在下一节中看看不同的解决方案。

# JDK 内置解决方案

内置的解决方案名为`sort()`，它在`java.util.Arrays`类中有许多不同的风格（15 种以上的风格）。

在`sort()`方法的背后，有一个性能良好的快速排序类型的排序算法，称为双轴快速排序。

假设我们需要按自然顺序对整数数组进行排序（原始类型`int`。为此，我们可以依赖于`Arrays.sort(int[] a)`，如下例所示：

```java
int[] integers = new int[]{...};
Arrays.sort(integers);
```

有时，我们需要对一个对象数组进行排序。假设我们有一个类`Melon`：

```java
public class Melon {

  private final String type;
  private final int weight;

  public Melon(String type, int weight) {
    this.type = type;
    this.weight = weight;
  }

  // getters omitted for brevity
}
```

`Melon`的数组可以通过适当的`Comparator`按升序权重排序：

```java
Melon[] melons = new Melon[] { ... };

Arrays.sort(melons, new Comparator<Melon>() {
  @Override
  public int compare(Melon melon1, Melon melon2) {
    return Integer.compare(melon1.getWeight(), melon2.getWeight());
  }
});
```

通过 Lambda 表达式重写前面的代码可以获得相同的结果：

```java
Arrays.sort(melons, (Melon melon1, Melon melon2) 
  -> Integer.compare(melon1.getWeight(), melon2.getWeight()));
```

此外，数组提供了一种并行排序元素的方法`parallelSort()`。幕后使用的排序算法是一种基于`ForkJoinPool`的并行排序合并，它将数组分解为子数组，子数组本身进行排序，然后进行合并。举个例子：

```java
Arrays.parallelSort(melons, new Comparator<Melon>() {
  @Override
  public int compare(Melon melon1, Melon melon2) {
    return Integer.compare(melon1.getWeight(), melon2.getWeight());
  }
});
```

或者，通过 Lambda 表达式，我们有以下示例：

```java
Arrays.parallelSort(melons, (Melon melon1, Melon melon2) 
  -> Integer.compare(melon1.getWeight(), melon2.getWeight()));
```

前面的示例按升序对数组排序，但有时需要按降序对其排序。当我们对一个`Object`数组进行排序并依赖于一个`Comparator`时，我们可以简单地将返回的结果乘以`Integer.compare()`再乘以 -1：

```java
Arrays.sort(melons, new Comparator<Melon>() {
  @Override
  public int compare(Melon melon1, Melon melon2) {
    return (-1) * Integer.compare(melon1.getWeight(), 
      melon2.getWeight());
  }
});
```

或者，我们可以简单地在`compare()`方法中切换参数。

对于装箱原始类型的数组，解决方案可以依赖于`Collections.reverse()`方法，如下例所示：

```java
Integer[] integers = new Integer[] {3, 1, 5};

// 1, 3, 5
Arrays.sort(integers);

// 5, 3, 1
Arrays.sort(integers, Collections.reverseOrder());
```

不幸的是，没有内置的解决方案来按降序排列原始类型数组。最常见的情况是，如果我们仍然要依赖于`Arrays.sort()`，那么这个问题的解决方案是在数组按升序排序后反转数组（`O(n)`）：

```java
// sort ascending
Arrays.sort(integers);

// reverse array to obtain it in descending order
for (int leftHead = 0, rightHead = integers.length - 1;
       leftHead < rightHead; leftHead++, rightHead--) {

  int elem = integers[leftHead];
  integers[leftHead] = integers[rightHead];
  integers[rightHead] = elem;
}
```

另一个解决方案可以依赖于 Java8 函数式风格和装箱（请注意装箱是一个非常耗时的操作）：

```java
int[] descIntegers = Arrays.stream(integers)
  .boxed() //or .mapToObj(i -> i)
  .sorted((i1, i2) -> Integer.compare(i2, i1))
  .mapToInt(Integer::intValue)
  .toArray();
```

# 其他排序算法

嗯，还有很多其他的排序算法。每种方法都有优缺点，最好的选择方法是对应用特定的情况进行基准测试。

让我们研究其中的一些，如下一节中强调的，从一个非常慢的算法开始。

# 冒泡排序

冒泡排序是一个简单的算法，基本上气泡数组的元素。这意味着它会多次遍历数组，并在相邻元素顺序错误时交换它们，如下图所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-cd-prob/img/55223d63-21de-4e89-a1df-06ad4e1c72fc.png)

时间复杂度情况如下：最佳情况`O(n)`、平均情况`O(n<sup>2</sup>)`、最坏情况`O(n<sup>2</sup>)`

空间复杂度情况如下：最坏情况`O(1)`

实现冒泡排序的实用方法如下：

```java
public static void bubbleSort(int[] arr) {

  int n = arr.length;

  for (int i = 0; i < n - 1; i++) {
    for (int j = 0; j < n - i - 1; j++) {

      if (arr[j] > arr[j + 1]) {
        int temp = arr[j];
        arr[j] = arr[j + 1];
        arr[j + 1] = temp;
      }
    }
  }
}
```

还有一个依赖于`while`循环的优化版本。你可以在捆绑到这本书的代码中找到它，名字是`bubbleSortOptimized()`。

作为时间执行的性能比较，对于 100000 个整数的随机数组，优化后的版本将快 2 秒左右。

前面的实现可以很好地对原始类型数组进行排序，但是，要对`Object`数组进行排序，我们需要在代码中引入`Comparator`，如下所示：

```java
public static <T> void bubbleSortWithComparator(
    T arr[], Comparator<? super T> c) {

  int n = arr.length;

  for (int i = 0; i < n - 1; i++) {
    for (int j = 0; j < n - i - 1; j++) {

      if (c.compare(arr[j], arr[j + 1]) > 0) {
        T temp = arr[j];
        arr[j] = arr[j + 1];
        arr[j + 1] = temp;
      }
    }
  }
}
```

还记得以前的类吗？好吧，我们可以通过实现`Comparator`接口为它写一个`Comparator`：

```java
public class MelonComparator implements Comparator<Melon> {

  @Override
  public int compare(Melon o1, Melon o2) {
    return o1.getType().compareTo(o2.getType());
  }
}
```

或者，在 Java8 函数式风格中，我们有以下内容：

```java
// Ascending
Comparator<Melon> byType = Comparator.comparing(Melon::getType);

// Descending
Comparator<Melon> byType 
  = Comparator.comparing(Melon::getType).reversed();
```

在一个名为`ArraySorts`的工具类中，有一个`Melon`数组、前面的`Comparator`数组和`bubbleSortWithComparator()`方法，我们可以按照下面的思路编写一些东西：

```java
Melon[] melons = {...};
ArraySorts.bubbleSortWithComparator(melons, byType);
```

为简洁起见，跳过了带有`Comparator`的冒泡排序优化版本，但它在绑定到本书的代码中可用。

当数组几乎已排序时，冒泡排序速度很快。此外，它还非常适合对*兔子*（接近数组开头的大元素）和*海龟*（接近数组结尾的小元素）进行排序。但总的来说，这是一个缓慢的算法。

# 插入排序

插入排序算法依赖于一个简单的流。它从第二个元素开始，并将其与前面的元素进行比较。如果前面的元素大于当前元素，则算法将交换这些元素。此过程将继续，直到前面的元素小于当前元素。

在这种情况下，算法将传递到数组中的下一个元素并重复该流，如下图所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-cd-prob/img/e0b8ebdf-04b3-43c1-9796-8197146c17ab.png)

时间复杂度情况如下：最佳情况`O(n)`、平均情况`O(n<sup>2</sup>)`、最坏情况`O(n<sup>2</sup>)`

空间复杂度情况如下：最坏情况`O(1)`

基于此流程，原始类型的实现如下所示：

```java
public static void insertionSort(int arr[]) {

  int n = arr.length;

  for (int i = 1; i < n; ++i) {

    int key = arr[i];
    int j = i - 1;

    while (j >= 0 && arr[j] > key) {
      arr[j + 1] = arr[j];
      j = j - 1;
    }

    arr[j + 1] = key;
  }
}
```

为了比较一个`Melon`数组，我们需要在实现中引入一个`Comparator`，如下所示：

```java
public static <T> void insertionSortWithComparator(
  T arr[], Comparator<? super T> c) {

  int n = arr.length;

  for (int i = 1; i < n; ++i) {

    T key = arr[i];
    int j = i - 1;

    while (j >= 0 && c.compare(arr[j], key) > 0) {
      arr[j + 1] = arr[j];
      j = j - 1;
    }

    arr[j + 1] = key;
  }
}
```

在这里，我们有一个`Comparator`，它使用`thenComparing()`方法，按照 Java8 函数式编写的类型和重量对西瓜进行排序：

```java
Comparator<Melon> byType = Comparator.comparing(Melon::getType)
  .thenComparing(Melon::getWeight);
```

在一个名为`ArraySorts`的实用类中，有一个`Melon`数组、前面的`Comparator`数组和`insertionSortWithComparator()`方法，我们可以编写如下内容：

```java
Melon[] melons = {...};
ArraySorts.insertionSortWithComparator(melons, byType);
```

对于较小且大部分排序的数组，这可能会很快。此外，在向数组中添加新元素时，它的性能也很好。它也是非常有效的内存，因为一个单一的元素是移动。

# 计数排序

计数排序流从计算数组中的最小和最大元素开始。该算法根据计算出的最小值和最大值定义一个新的数组，该数组将使用*元素*作为*索引*对未排序的元素进行计数。此外，以这样的方式修改这个新数组，使得每个*索引*处的每个*元素*存储先前计数的总和。最后，从这个新的数组中得到排序后的数组。

时间复杂度情况如下：最佳情况`O(n + k)`、平均情况`O(n + k)`、最坏情况`O(n + k)`

空间复杂度情况如下：最坏情况`O(k)`

`k` is the number of possible values in the range.
`n` is the number of elements to be sorted.

让我们考虑一个简单的例子。初始数组包含以下元素，`arr`：`4`、`2`、`6`、`2`、`6`、`8`、`5`：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-cd-prob/img/570e8015-a037-48d9-b4f9-459a694b73ee.png)

最小元件为`2`，最大元件为`8`。新数组`counts`的大小等于最大值减去最小值`+1=8-2+1=7`。

对每个元素进行计数将产生以下数组（`counts[arr[i] - min]++`）：

```java
counts[2] = 1 (4); counts[0] = 2 (2); counts[4] = 2 (6);
counts[6] = 1 (8); counts[3] = 1 (5);
```

现在，我们必须循环此数组，并使用它重建排序后的数组，如下所示：

```java
public static void countingSort(int[] arr) {

  int min = arr[0];
  int max = arr[0];

  for (int i = 1; i < arr.length; i++) {
    if (arr[i] < min) {
      min = arr[i];
    } else if (arr[i] > max) {
      max = arr[i];
    }
  }

  int[] counts = new int[max - min + 1];

  for (int i = 0; i < arr.length; i++) {
    counts[arr[i] - min]++;
  }

  int sortedIndex = 0;

  for (int i = 0; i < counts.length; i++) {
    while (counts[i] > 0) {
      arr[sortedIndex++] = i + min;
      counts[i]--;
    }
  }
}
```

这是一个非常快速的算法。

# 堆排序

堆排序是一种依赖于二进制堆（完全二叉树）的算法。

时间复杂度情况如下：最佳情况`O(n log n)`、平均情况`O(n log n)`、最坏情况`O(n log n)`

空间复杂度情况如下：最坏情况`O(1)`

可以通过*最大堆*（父节点总是大于或等于子节点）按升序排序元素，通过*最小堆*（父节点总是小于或等于子节点）按降序排序元素。

在第一步，该算法使用提供的数组来构建这个堆，并将其转换为一个*最大堆*（该堆由另一个数组表示）。因为这是一个*最大堆*，所以最大的元素是堆的根。在下一步中，根与堆中的最后一个元素交换，堆大小减少 1（从堆中删除最后一个节点）。堆顶部的元素按顺序排列。最后一步由*建堆*（以自顶向下的方式构建堆的递归过程）和堆的根（重构*最大堆*）组成。重复这三个步骤，直到堆大小大于 1：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-cd-prob/img/d3f60043-6301-496d-b298-97ace7eb01dc.png)

例如，假设上图中的数组-`4`、`5`、`2`、`7`、`1`：

1.  因此，在第一步，我们构建堆：`4`、`5`、`2`、`7`、`1`。
2.  我们构建了*最大堆*：`7`、`5`、`2`、`4`、`1`（我们将`5`与`4`、`4`与`7`、`5`与`7`进行了交换）。
3.  接下来，我们将根（`7`）与最后一个元素（`1`）交换并删除`7`。结果：`1`、`5`、`2`、`4`、`7`。
4.  进一步，我们再次构建*最大堆*：`5`、`4`、`2`、`1`（我们将`5`与`1`进行了交换，将`1`与`4`进行了交换）。
5.  我们将根（`5`）与最后一个元素（`1`）交换，并删除`5`。结果：`1`、`4`、`2`、`5`、`7`。
6.  接下来，我们再次构建*最大堆*：`4`、`1`、`2`（我们将`1`与`4`进行了交换）。
7.  我们将根（`4`）与最后一个元素（`2`）交换，并删除`4`。结果：`2`、`1`。
8.  这是一个*最大堆*，因此将根（`2`）与最后一个元素（`1`）交换并移除`2`：`1`、`2`、`4`、`5`、`7`。
9.  完成！堆中只剩下一个元素（`1`）。

在代码行中，前面的示例可以概括如下：

```java
public static void heapSort(int[] arr) {
  int n = arr.length;

  buildHeap(arr, n);

  while (n > 1) {
    swap(arr, 0, n - 1);
    n--;
    heapify(arr, n, 0);
  }
}

private static void buildHeap(int[] arr, int n) {
  for (int i = arr.length / 2; i >= 0; i--) {
    heapify(arr, n, i);
  }
}

private static void heapify(int[] arr, int n, int i) {
  int left = i * 2 + 1;
  int right = i * 2 + 2;
  int greater;

  if (left < n && arr[left] > arr[i]) {
    greater = left;
  } else {
    greater = i;
  }

  if (right < n && arr[right] > arr[greater]) {
    greater = right;
  }

  if (greater != i) {
    swap(arr, i, greater);
    heapify(arr, n, greater);
  }
}

private static void swap(int[] arr, int x, int y) {
  int temp = arr[x];
  arr[x] = arr[y];
  arr[y] = temp;
}
```

如果我们想要比较对象，那么我们必须在实现中引入一个`Comparator`。此解决方案在捆绑到本书的代码中以`heapSortWithComparator()`的名称提供。

这里是一个用 Java8 函数式编写的`Comparator`，它使用`thenComparing()`和`reversed()`方法按类型和重量降序排列瓜类：

```java
Comparator<Melon> byType = Comparator.comparing(Melon::getType)
  .thenComparing(Melon::getWeight).reversed();                                                                                                                                                                                                                                                                                                                        
```

在一个名为`ArraySorts`的实用类中，有一个`Melon`数组、前面的`Comparator`数组和`heapSortWithComparator()`方法，我们可以编写如下内容：

```java
Melon[] melons = {...};
ArraySorts.heapSortWithComparator(melons, byType);
```

堆排序相当快，但不稳定。例如，对已排序的数组进行排序可能会使其保持不同的顺序。

我们将在这里停止关于排序数组的论文，但是，在本书附带的代码中，还有一些排序算法可用：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-cd-prob/img/56dcf8c1-a04d-4541-aa1d-402d74d053a2.png)

还有许多其他算法专门用于排序数组。其中一些是建立在这里介绍的基础上的（例如，梳排序、鸡尾酒排序和奇偶排序是冒泡排序的风格，桶排序是通常依赖于插入排序的分布排序，基数排序（LSD）是类似于桶排序的稳定分布，Gnome 排序是插入排序的变体）。

其他则是不同的方法（例如，`Arrays.sort()`方法实现的快速排序，`Arrays.parallelSort()`方法实现的合并排序）。

作为对本节的奖励，让我们看看如何洗牌一个数组。实现这一点的有效方法依赖于 Fisher-Yates 洗牌（称为 Knuth 洗牌）。基本上，我们以相反的顺序循环数组，然后随机交换元素。对于原始类型（例如，`int`），实现如下：

```java
public static void shuffleInt(int[] arr) {

  int index;

  Random random = new Random();

  for (int i = arr.length - 1; i > 0; i--) {

    index = random.nextInt(i + 1);
    swap(arr, index, i);
  }
}
```

在绑定到本书的代码中，还有一个实现，用于对`Object`的数组进行洗牌。

通过`Collections.shuffle(List<?> list)`洗牌列表非常简单。

# 100 在数组中查找元素

当我们在数组中搜索一个元素时，我们可能感兴趣的是找出这个元素出现的索引，或者只找出它是否存在于数组中。本节介绍的解决方案具体化为以下屏幕截图中的方法：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-cd-prob/img/e232122f-eaab-4f40-8188-71fbe14419ac.png)

让我们在下一节中看看不同的解决方案。

# 只检查是否存在

假设以下整数数组：

```java
int[] numbers = {4, 5, 1, 3, 7, 4, 1};
```

由于这是一个原始类型数组，解决方案可以简单地循环数组并返回给定整数的第一个匹配项，如下所示：

```java
public static boolean containsElement(int[] arr, int toContain) {

  for (int elem: arr) {
    if (elem == toContain) {
      return true;
    }
  }

  return false;
}
```

这个问题的另一个解决方法可以依赖于`Arrays.binarySearch()`方法。这种方法有几种风格，但在这种情况下，我们需要这个：`int binarySearch​(int[] a, int key)`。该方法将搜索给定数组中的给定键，并返回相应的索引或负值。唯一的问题是，此方法仅适用于已排序的数组；因此，我们需要事先对数组排序：

```java
public static boolean containsElement(int[] arr, int toContain) {

  Arrays.sort(arr);
  int index = Arrays.binarySearch(arr, toContain);

  return (index >= 0);
}
```

如果数组已经排序，那么可以通过删除排序步骤来优化前面的方法。此外，如果数组被排序，前面的方法可以返回数组中元素出现的索引，而不是一个`boolean`。但是，如果数组没有排序，请记住返回的索引对应于排序的数组，而不是未排序的（初始）数组。如果不想对初始数组进行排序，则建议将数组的克隆传递给此方法。另一种方法是在这个辅助方法中克隆数组。

在 Java8 中，解决方案可以依赖于函数式方法。这里一个很好的候选者是`anyMatch()`方法。此方法返回流中是否有元素与提供的谓词匹配。因此，我们需要做的就是将数组转换为流，如下所示：

```java
public static boolean containsElement(int[] arr, int toContain) {

  return Arrays.stream(arr)
    .anyMatch(e -> e == toContain);
}
```

对于任何其他原始类型，改编或概括前面的示例都非常简单。

现在，让我们集中精力在数组中寻找`Object`。让我们考虑一下`Melon`类：

```java
public class Melon {

  private final String type;
  private final int weight;

  // constructor, getters, equals() and hashCode() skipped for brevity
}
```

接下来，让我们考虑一个`Melon`数组：

```java
Melon[] melons = new Melon[] {new Melon("Crenshaw", 2000),
  new Melon("Gac", 1200), new Melon("Bitter", 2200)
};
```

现在，假设我们要在这个数组中找到 1200 克的木瓜。一个解决方案可以依赖于`equals()`方法，该方法用于确定两个对象的相等性：

```java
public static <T> boolean 
    containsElementObject(T[] arr, T toContain) {

  for (T elem: arr) {
    if (elem.equals(toContain)) {
      return true;
    }
  }

  return false;
}
```

同样，我们可以依赖于`Arrays.asList(arr).contains(find)`。基本上，将数组转换为一个`List`并调用`contains()`方法。在幕后，这种方法使用的是`equals()`合同。

如果此方法存在于名为`ArraySearch`的工具类中，则以下调用将返回`true`：

```java
// true
boolean found = ArraySearch.containsElementObject(
  melons, new Melon("Gac", 1200));
```

只要我们想依赖`equals()`合同，这个解决方案就行。但是我们可以认为，如果甜瓜的名字出现（Gac），或者它的重量出现（1200），那么我们的甜瓜就存在于数组中。对于这种情况，更实际的做法是依赖于`Comparator`：

```java
public static <T> boolean containsElementObject(
    T[] arr, T toContain, Comparator<? super T> c) {

  for (T elem: arr) {
    if (c.compare(elem, toContain) == 0) {
      return true;
    }
  }

  return false;
}
```

现在，一个只考虑瓜的类型的`Comparator`可以写为：

```java
Comparator<Melon> byType = Comparator.comparing(Melon::getType);
```

由于`Comparator`忽略了瓜的重量（没有 1205 克的瓜），下面的调用将返回`true`：

```java
// true
boolean found = ArraySearch.containsElementObject(
  melons, new Melon("Gac", 1205), byType);
```

另一种方法依赖于`binarySearch()`的另一种风格。`Arrays`类提供了一个`binarySearch()`方法，该方法获取一个`Comparator`、`<T> int binarySearch(T[] a, T key, Comparator<? super T> c)`。这意味着我们可以如下使用它：

```java
public static <T> boolean containsElementObject(
    T[] arr, T toContain, Comparator<? super T> c) {

  Arrays.sort(arr, c);
  int index = Arrays.binarySearch(arr, toContain, c);

  return (index >= 0);
}
```

如果初始数组状态应保持不变，则建议将数组的克隆传递给此方法。另一种方法是在这个辅助方法中克隆数组。

现在，一个只考虑瓜重的`Comparator`可以写为：

```java
Comparator<Melon> byWeight = Comparator.comparing(Melon::getWeight);
```

由于`Comparator`忽略了甜瓜的类型（没有蜜瓜类型的甜瓜），下面的调用将返回`true`：

```java
// true
boolean found = ArraySearch.containsElementObject(
  melons, new Melon("Honeydew", 1200), byWeight);
```

# 只检查第一个索引

对于一组原始类型，最简单的实现就说明了这一点：

```java
public static int findIndexOfElement(int[] arr, int toFind) {

  for (int i = 0; i < arr.length; i++) {
    if (arr[i] == toFind) {
      return i;
    }
  }

  return -1;
}
```

依靠 Java8 函数风格，我们可以尝试循环数组并过滤与给定元素匹配的元素。最后，只需返回找到的第一个元素：

```java
public static int findIndexOfElement(int[] arr, int toFind) {

  return IntStream.range(0, arr.length)
    .filter(i -> toFind == arr[i])
    .findFirst()
    .orElse(-1);
}
```

对于`Object`数组，至少有三种方法。首先，我们可以依据`equals()`合同：

```java
public static <T> int findIndexOfElementObject(T[] arr, T toFind) {

  for (int i = 0; i < arr.length; i++) {
    if (arr[i].equals(toFind)) {
      return i;
    }
  }

  return -1;
}
```

同样，我们可以依赖于`Arrays.asList(arr).indexOf(find)`。基本上，将数组转换为一个`List`并调用`indexOf()`方法。在幕后，这种方法使用的是`equals()`合同。

其次，我们可以依赖于`Comparator`：

```java
public static <T> int findIndexOfElementObject(
    T[] arr, T toFind, Comparator<? super T> c) {

  for (int i = 0; i < arr.length; i++) {
    if (c.compare(arr[i], toFind) == 0) {
      return i;
    }
  }

  return -1;
}
```

第三，我们可以依赖 Java8 函数式风格和一个`Comparator`：

```java
public static <T> int findIndexOfElementObject(
    T[] arr, T toFind, Comparator<? super T> c) {

  return IntStream.range(0, arr.length)
    .filter(i -> c.compare(toFind, arr[i]) == 0)
    .findFirst()
    .orElse(-1);
}
```

# 101 检查两个数组是否相等或不匹配

如果两个原始数组包含相同数量的元素，则它们相等，并且两个数组中所有对应的元素对都相等

这两个问题的解决依赖于`Arrays`实用类。下面几节给出了解决这些问题的方法。

# 检查两个数组是否相等

通过`Arrays.equals()`方法可以很容易地检查两个数组是否相等。对于基本类型、`Object`和泛型，这个标志方法有很多种风格。它还支持比较器。

让我们考虑以下三个整数数组：

```java
int[] integers1 = {3, 4, 5, 6, 1, 5};
int[] integers2 = {3, 4, 5, 6, 1, 5};
int[] integers3 = {3, 4, 5, 6, 1, 3};
```

现在，让我们检查一下`integers1`是否等于`integers2`，以及`integers1`是否等于`integers3`。这很简单：

```java
boolean i12 = Arrays.equals(integers1, integers2); // true
boolean i13 = Arrays.equals(integers1, integers3); // false
```

前面的例子检查两个数组是否相等，但是我们也可以通过`boolean equals(int[] a, int aFromIndex, int aToIndex, int[] b, int bFromIndex, int bToIndex)`方法检查数组的两个段（或范围）是否相等。因此，我们通过范围`[aFromIndex, aToIndex)`来划分第一个数组的段，通过范围`[bFromIndex, bToIndex)`来划分第二个数组的段：

```java
// true
boolean is13 = Arrays.equals(integers1, 1, 4, integers3, 1, 4);
```

现在，让我们假设`Melon`的三个数组：

```java
public class Melon {

  private final String type;
  private final int weight;

  public Melon(String type, int weight) {
    this.type = type;
    this.weight = weight;
  }

  // getters, equals() and hashCode() omitted for brevity
}

Melon[] melons1 = {
  new Melon("Horned", 1500), new Melon("Gac", 1000)
};

Melon[] melons2 = {
  new Melon("Horned", 1500), new Melon("Gac", 1000)
};

Melon[] melons3 = {
  new Melon("Hami", 1500), new Melon("Gac", 1000)
};
```

基于`equals()`合同或基于指定的`Comparator`，两个`Object`数组被视为相等。我们可以很容易地检查`melons1`是否等于`melons2`，以及`melons1`是否等于`melons3`，如下所示：

```java
boolean m12 = Arrays.equals(melons1, melons2); // true
boolean m13 = Arrays.equals(melons1, melons3); // false
```

在明确的范围内，使用`boolean equals(Object[] a, int aFromIndex, int aToIndex, Object[] b, int bFromIndex, int bToIndex)`：

```java
boolean ms13 = Arrays.equals(melons1, 1, 2, melons3, 1, 2); // false
```

虽然这些示例依赖于`Melon.equals()`实现，但以下两个示例依赖于以下两个`Comparator`：

```java
Comparator<Melon> byType = Comparator.comparing(Melon::getType);
Comparator<Melon> byWeight = Comparator.comparing(Melon::getWeight);
```

使用布尔值`equals(T[] a, T[] a2, Comparator<? super T> cmp)`，我们得到以下结果：

```java
boolean mw13 = Arrays.equals(melons1, melons3, byWeight); // true
boolean mt13 = Arrays.equals(melons1, melons3, byType);   // false
```

并且，在显式范围内，使用`Comparator`、`<T> boolean equals(T[] a, int aFromIndex, int aToIndex, T[] b, int bFromIndex, int bToIndex, Comparator<? super T> cmp)`，我们得到：

```java
// true
boolean mrt13 = Arrays.equals(melons1, 1, 2, melons3, 1, 2, byType);
```

# 检查两个数组是否包含不匹配项

如果两个数组相等，则不匹配应返回 -1。但是如果两个数组不相等，那么不匹配应该返回两个给定数组之间第一个不匹配的索引。为了解决这个问题，我们可以依赖 JDK9`Arrays.mismatch()`方法。

例如，我们可以检查`integers1`和`integers2`之间的不匹配，如下所示：

```java
int mi12 = Arrays.mismatch(integers1, integers2); // -1
```

结果是 -1，因为`integers1`和`integers2`相等。但是如果我们检查`integers1`和`integers3`，我们会得到值 5，这是这两个值之间第一个不匹配的索引：

```java
int mi13 = Arrays.mismatch(integers1, integers3); // 5
```

如果给定的数组有不同的长度，而较小的数组是较大数组的前缀，那么返回的不匹配就是较小数组的长度。

对于`Object`的数组，也有专用的`mismatch()`方法。这些方法依赖于`equals()`合同或给定的`Comparator`。我们可以检查`melons1`和`melons2`之间是否存在不匹配，如下所示：

```java
int mm12 = Arrays.mismatch(melons1, melons2); // -1
```

如果第一个索引发生不匹配，则返回值为 0。这在`melons1`和`melons3`的情况下发生：

```java
int mm13 = Arrays.mismatch(melons1, melons3); // 0
```

在`Arrays.equals()`的情况下，我们可以使用`Comparator`检查显式范围内的不匹配：

```java
// range [1, 2), return -1
int mms13 = Arrays.mismatch(melons1, 1, 2, melons3, 1, 2);

// Comparator by melon's weights, return -1
int mmw13 = Arrays.mismatch(melons1, melons3, byWeight);

// Comparator by melon's types, return 0
int mmt13 = Arrays.mismatch(melons1, melons3, byType);

// range [1,2) and Comparator by melon's types, return -1
int mmrt13 = Arrays.mismatch(melons1, 1, 2, melons3, 1, 2, byType);
```

# 102 按字典顺序比较两个数组

从 JDK9 开始，我们可以通过`Arrays.compare()`方法按字典顺序比较两个数组。既然不需要重新发明轮子，那么就升级到 JDK9，让我们深入研究一下。

两个数组的词典比较可能返回以下结果：

*   0，如果给定数组相等并且包含相同顺序的相同元素
*   如果第一个数组按字典顺序小于第二个数组，则值小于 0
*   如果第一个数组按字典顺序大于第二个数组，则该值大于 0

如果第一个数组的长度小于第二个数组的长度，则第一个数组在词典上小于第二个数组。如果数组具有相同的长度，包含原始类型，并且共享一个共同的前缀，那么字典比较就是比较两个元素的结果，精确地说就是`Integer.compare(int, int)`、`Boolean.compare(boolean, boolean)`、`Byte.compare(byte, byte)`等等。如果数组包含`Object`，那么字典比较依赖于给定的`Comparator`或`Comparable`实现。

首先，让我们考虑以下原始类型数组：

```java
int[] integers1 = {3, 4, 5, 6, 1, 5};
int[] integers2 = {3, 4, 5, 6, 1, 5};
int[] integers3 = {3, 4, 5, 6, 1, 3};
```

现在，`integers1`在词典上等于`integers2`，因为它们相等并且包含相同顺序的相同元素，`int compare(int[] a, int[] b)`：

```java
int i12 = Arrays.compare(integers1, integers2); // 0
```

但是，`integers1`在字典上大于`integers3`，因为它们共享相同的前缀（3，4，5，6，1），但是对于最后一个元素，`Integer.compare(5,3)`返回一个大于 0 的值，因为 5 大于 3：

```java
int i13 = Arrays.compare(integers1, integers3); // 1
```

可以在不同的数组范围内进行词典比较。例如，下面的示例通过`int compare(int[] a, int aFromIndex, int aToIndex, int[] b, int bFromIndex, int bToIndex)`方法比较范围`[3, 6]`中的`integers1`和`integers3`：

```java
int is13 = Arrays.compare(integers1, 3, 6, integers3, 3, 6); // 1
```

对于`Object`的数组，`Arrays`类还提供了一组专用的`compare()`方法。还记得`Melon`类吗？好吧，为了比较两个没有显式`Comparator`的`Melon`数组，我们需要实现`Comparable`接口和`compareTo()`方法。假设我们依赖于瓜的重量，如下所示：

```java
public class Melon implements Comparable {

  private final String type;
  private final int weight;

  @Override
  public int compareTo(Object o) {
    Melon m = (Melon) o;

    return Integer.compare(this.getWeight(), m.getWeight());
  }

  // constructor, getters, equals() and hashCode() omitted for brevity
}
```

注意，`Object`数组的词典比较不依赖于`equals()`。它需要显式的`Comparator`或`Comparable`元素。

假设`Melon`的以下数组：

```java
Melon[] melons1 = {new Melon("Horned", 1500), new Melon("Gac", 1000)};
Melon[] melons2 = {new Melon("Horned", 1500), new Melon("Gac", 1000)};
Melon[] melons3 = {new Melon("Hami", 1600), new Melon("Gac", 800)};
```

让我们通过`<T extends Comparable<? super T>> int compare(T[] a, T[] b)`将`melons1`与`melons2`进行词汇对比：

```java
int m12 = Arrays.compare(melons1, melons2); // 0
```

因为`melons1`和`melons2`是相同的，所以结果是 0。

现在，让我们对`melons1`和`melons3`做同样的事情。这一次，结果将是否定的，这意味着在词典中，`melons1`小于`melons3`。这是真的，因为在指数 0 时，角瓜的重量是 1500 克，比哈密瓜的重量要轻，哈密瓜的重量是 1600 克：

```java
int m13 = Arrays.compare(melons1, melons3); // -1
```

我们可以通过`<T extends Comparable<? super T>> int compare(T[] a, int aFromIndex, int aToIndex, T[] b, int bFromIndex, int bToIndex)`方法在数组的不同范围内进行比较。例如，在公共范围`[1, 2]`中，`melons1`在字典上大于`melons2`，因为 Gac 的重量在`melons1`中为 1000g，在`melons3`中为 800g：

```java
int ms13 = Arrays.compare(melons1, 1, 2, melons3, 1, 2); // 1
```

如果我们不想依赖`Comparable`元素（实现`Comparable`，我们可以通过`<T> int compare(T[] a, T[] b, Comparator<? super T> cmp)`方法传入一个`Comparator`：

```java
Comparator<Melon> byType = Comparator.comparing(Melon::getType);
int mt13 = Arrays.compare(melons1, melons3, byType); // 14
```

也可以通过`<T> int compare(T[] a, int aFromIndex, int aToIndex, T[] b, int bFromIndex, int bToIndex, Comparator<? super T> cmp)`使用范围：

```java
int mrt13 = Arrays.compare(melons1, 1, 2, melons3, 1, 2, byType); // 0
```

如果数字数组应该被无符号处理，那么依赖于一堆`Arrays.compareUnsigned​()`方法，这些方法可用于`byte`、`short`、`int`和`long`。

根据`String.compareTo()`和`int compareTo(String anotherString)`按字典顺序比较两个字符串。

# 103 从数组创建流

一旦我们从一个数组中创建了一个`Stream`，我们就可以访问所有流 API。因此，这是一个方便的操作，这是很重要的，在我们的工具带。

让我们从字符串数组开始（也可以是其他对象）：

```java
String[] arr = {"One", "Two", "Three", "Four", "Five"};
```

从这个`String[]`数组创建`Stream`最简单的方法是依赖于从 JDK8 开始的`Arrays.stream()`方法：

```java
Stream<String> stream = Arrays.stream(arr);
```

或者，如果我们需要来自子数组的流，那么只需添加范围作为参数。例如，让我们从`(0, 2)`之间的元素创建一个`Stream`，即 1 到 2：

```java
Stream<String> stream = Arrays.stream(arr, 0, 2);
```

同样的情况，但通过一个`List`可以写为：

```java
Stream<String> stream = Arrays.asList(arr).stream();
Stream<String> stream = Arrays.asList(arr).subList(0, 2).stream();
```

另一种解决方案依赖于`Stream.of()`方法，如以下简单示例所示：

```java
Stream<String> stream = Stream.of(arr);
Stream<String> stream = Stream.of("One", "Two", "Three");
```

从`Stream`创建数组可以通过`Stream.toArray()`方法完成。例如，一个简单的方法如下所示：

```java
String[] array = stream.toArray(String[]::new);
```

另外，让我们考虑一个原始数组：

```java
int[] integers = {2, 3, 4, 1};
```

在这种情况下，`Arrays.stream()`方法可以再次提供帮助，唯一的区别是返回的结果是`IntStream`类型（这是`Stream`的`int`原始类型特化）：

```java
IntStream intStream = Arrays.stream(integers);
```

但是`IntStream`类还提供了一个`of()`方法，可以如下使用：

```java
IntStream intStream = IntStream.of(integers);
```

有时，我们需要定义一个增量步长为 1 的有序整数的`Stream`。此外，`Stream`的大小应该等于数组的大小。特别是对于这种情况，`IntStream`方法提供了两种方法`range(int inclusive, int exclusive)`和`rangeClosed(int startInclusive, int endInclusive)`：

```java
IntStream intStream = IntStream.range(0, integers.length);
IntStream intStream = IntStream.rangeClosed(0, integers.length);
```

从整数的`Stream`创建数组可以通过`Stream.toArray()`方法完成。例如，一个简单的方法如下所示：

```java
int[] intArray = intStream.toArray();

// for boxed integers
int[] intArray = intStream.mapToInt(i -> i).toArray();
```

除了流的`IntStream`特化之外，JDK8 还提供`long`（`LongStream`）和`double`（`DoubleStream`）的特化。

# 104 数组的最小值、最大值和平均值

计算数组的最小值、最大值和平均值是一项常见的任务。让我们看看在函数式和命令式编程中解决这个问题的几种方法。

# 计算最大值和最小值

计算数字数组的最大值可以通过循环数组并通过与数组的每个元素进行比较来跟踪最大值来实现。就代码行而言，可以编写如下：

```java
public static int max(int[] arr) {

  int max = arr[0];

  for (int elem: arr) {
    if (elem > max) {
      max = elem;
    }
  }

  return max;
}
```

在可读性方面，可能需要使用`Math.max()`方法而不是`if`语句：

```java
...
max = Math.max(max, elem);
...
```

假设我们有以下整数数组和一个名为`MathArrays`的工具类，其中包含前面的方法：

```java
int[] integers = {2, 3, 4, 1, -4, 6, 2};
```

该数组的最大值可以容易地获得如下：

```java
int maxInt = MathArrays.max(integers); // 6
```

在 Java8 函数式风格中，此问题的解决方案需要一行代码：

```java
int maxInt = Arrays.stream(integers).max().getAsInt();
```

在函数式方法中，`max()`方法返回一个`OptionalInt`。同样，我们有`OptionalLong`和`OptionalDouble`。

此外，我们假设一个对象数组，在本例中是一个`Melon`数组：

```java
Melon[] melons = {
  new Melon("Horned", 1500), new Melon("Gac", 2200),
  new Melon("Hami", 1600), new Melon("Gac", 2100)
};

public class Melon implements Comparable {

  private final String type;
  private final int weight;

  @Override
  public int compareTo(Object o) {
    Melon m = (Melon) o;

    return Integer.compare(this.getWeight(), m.getWeight());
  }

  // constructor, getters, equals() and hashCode() omitted for brevity
}
```

很明显，我们前面定义的`max()`方法不能用于这种情况，但逻辑原理保持不变。这一次，实现应该依赖于`Comparable`或`Comparator`。基于`Comparable`的实现可以如下：

```java
public static <T extends Comparable<T>> T max(T[] arr) {

  T max = arr[0];

  for (T elem : arr) {
    if (elem.compareTo(max) > 0) {
      max = elem;
   }
  }

  return max;
}
```

检查`Melon.compareTo()`方法，注意我们的实现将比较瓜的重量。因此，我们可以很容易地从我们的数组中找到最重的瓜，如下所示：

```java
Melon maxMelon = MathArrays.max(melons); // Gac(2200g)
```

依赖于`Comparator`的实现可以写为：

```java
public static <T> T max(T[] arr, Comparator<? super T> c) {

  T max = arr[0];

  for (T elem: arr) {
    if (c.compare(elem, max) > 0) {
      max = elem;
    }
  }

  return max;
}
```

并且，如果我们根据甜瓜的类型定义一个`Comparator`，我们有以下结果：

```java
Comparator<Melon> byType = Comparator.comparing(Melon::getType);
```

然后，我们得到与字符串的词典比较相一致的最大值：

```java
Melon maxMelon = MathArrays.max(melons, byType); // Horned(1500g)
```

在 Java8 函数式风格中，此问题的解决方案需要一行代码：

```java
Melon maxMelon = Arrays.stream(melons).max(byType).orElseThrow();
```

# 计算平均值

计算一组数字（在本例中为整数）的平均值可以通过两个简单的步骤实现：

1.  计算数组中元素的和。
2.  将此总和除以数组的长度。

在代码行中，我们有以下内容：

```java
public static double average(int[] arr) {

  return sum(arr) / arr.length;
}

public static double sum(int[] arr) {

  double sum = 0;

  for (int elem: arr) {
    sum += elem;
  }

  return sum;
}
```

整数数组的平均值为 2.0：

```java
double avg = MathArrays.average(integers);
```

在 Java8 函数式风格中，此问题的解决方案需要一行代码：

```java
double avg = Arrays.stream(integers).average().getAsDouble();
```

对于第三方库支持，请考虑 Apache Common Lang（`ArrayUtil`）和 Guava 的`Chars`、`Ints`、`Longs`以及其他类。

# 105 反转数组

这个问题有几种解决办法。它们中的一些改变了初始数组，而另一些只是返回一个新数组

假设以下整数数组：

```java
int[] integers = {-1, 2, 3, 1, 4, 5, 3, 2, 22};
```

让我们从一个简单的实现开始，它将数组的第一个元素与最后一个元素交换，第二个元素与倒数第二个元素交换，依此类推：

```java
public static void reverse(int[] arr) {

  for (int leftHead = 0, rightHead = arr.length - 1; 
      leftHead < rightHead; leftHead++, rightHead--) {

    int elem = arr[leftHead];
    arr[leftHead] = arr[rightHead];
    arr[rightHead] = elem;
  }
}
```

前面的解决方案改变了给定的数组，这并不总是期望的行为。当然，我们可以修改它以返回一个新的数组，也可以依赖 Java8 函数样式，如下所示：

```java
// 22, 2, 3, 5, 4, 1, 3, 2, -1
int[] reversed = IntStream.rangeClosed(1, integers.length)
  .map(i -> integers[integers.length - i]).toArray();
```

现在，让我们反转一个对象数组。为此，让我们考虑一下`Melon`类：

```java
public class Melon {

  private final String type;
  private final int weight;

  // constructor, getters, equals(), hashCode() omitted for brevity
}
```

另外，让我们考虑一个`Melon`数组：

```java
Melon[] melons = {
  new Melon("Crenshaw", 2000), 
  new Melon("Gac", 1200),
  new Melon("Bitter", 2200)
};
```

第一种解决方案需要使用泛型来塑造实现，该实现将数组的第一个元素与最后一个元素交换，将第二个元素与最后一个元素交换，依此类推：

```java
public static <T> void reverse(T[] arr) {

  for (int leftHead = 0, rightHead = arr.length - 1; 
      leftHead < rightHead; leftHead++, rightHead--) {

    T elem = arr[leftHead];
    arr[leftHead] = arr[rightHead];
    arr[rightHead] = elem;
  }
}
```

因为我们的数组包含对象，所以我们也可以依赖于`Collections.reverse()`。我们只需要通过`Arrays.asList()`方法将数组转换成`List`：

```java
// Bitter(2200g), Gac(1200g), Crenshaw(2000g)
Collections.reverse(Arrays.asList(melons));
```

前面的两个解决方案改变了数组的元素。Java8 函数式风格可以帮助我们避免这种变异：

```java
// Bitter(2200g), Gac(1200g), Crenshaw(2000g)
Melon[] reversed = IntStream.rangeClosed(1, melons.length)
  .mapToObj(i -> melons[melons.length - i])
  .toArray(Melon[]:new);
```

对于第三方库支持，请考虑 Apache Common Lang（`ArrayUtils.reverse()`和 Guava 的`Lists`类。

# 106 填充和设置数组

有时，我们需要用一个固定值填充数组。例如，我们可能希望用值`1`填充整数数组。实现这一点的最简单方法依赖于一个`for`语句，如下所示：

```java
int[] arr = new int[10];

// 1, 1, 1, 1, 1, 1, 1, 1, 1, 1
for (int i = 0; i < arr.length; i++) {
  arr[i] = 1;
}
```

但我们可以通过`Arrays.fill()`方法将此代码简化为一行代码。对于基本体和对象，此方法有不同的风格。前面的代码可以通过`Arrays.fill(int[] a, int val)`重写如下：

```java
// 1, 1, 1, 1, 1, 1, 1, 1, 1, 1
Arrays.fill(arr, 1);
```

`Arrays.fill()` also come with flavors for filling up just a segment/range of an array. For integers, this method is `fill​(int[] a, int fromIndexInclusive, int toIndexExclusive, int val)`.

现在，应用一个生成函数来计算数组的每个元素怎么样？例如，假设我们要将每个元素计算为前一个元素加 1。最简单的方法将再次依赖于`for`语句，如下所示：

```java
// 1, 2, 3, 4, 5, 6, 7, 8, 9, 10
for (int i = 1; i < arr.length; i++) {
  arr[i] = arr[i - 1] + 1;
}
```

根据需要应用于每个元素的计算，必须相应地修改前面的代码。

对于这样的任务，JDK8 附带了一系列的`Arrays.setAll()`和`Arrays.parallelSetAll()`方法。例如，前面的代码片段可以通过`setAll​(int[] array, IntUnaryOperator generator)`重写如下：

```java
// 1, 2, 3, 4, 5, 6, 7, 8, 9, 10
Arrays.setAll(arr, t -> {
  if (t == 0) {
    return arr[t];
  } else {
    return arr[t - 1] + 1;
  }
});
```

除此之外，我们还有`setAll​(double[] array, IntToDoubleFunction generator)`、`setAll​(long[] array, IntToLongFunction generator)`和`setAll​(T[] array, IntFunction<? extends T> generator)`。

根据生成器的功能，此任务可以并行完成，也可以不并行完成。例如，前面的生成器函数不能并行应用，因为每个元素都依赖于前面元素的值。尝试并行应用此生成器函数将导致不正确和不稳定的结果。

但是假设我们要取前面的数组（1，2，3，4，5，6，7，8，9，10），然后将每个偶数值乘以它本身，将每个奇数值减去 1。因为每个元素都可以单独计算，所以在这种情况下我们可以授权一个并行进程。这是`Arrays.parallelSetAll()`方法的完美工作。基本上，这些方法是用来并行化`Arrays.setAll()`方法的。

现在我们将`parallelSetAll​(int[] array, IntUnaryOperator generator)`应用于这个数组：

```java
// 0, 4, 2, 16, 4, 36, 6, 64, 8, 100
Arrays.parallelSetAll(arr, t -> {
  if (arr[t] % 2 == 0) {
    return arr[t] * arr[t];
  } else {
    return arr[t] - 1;
  }
});
```

对于每个`Arrays.setAll()`方法，都有一个`Arrays.parallelSetAll()`方法。

作为奖励，`Arrays`附带了一组名为`parallelPrefix()`的方法。这些方法对于将数学函数应用于数组的元素（累积和并发）非常有用。

例如，如果我们要将数组中的每个元素计算为前面元素的和，那么我们可以如下所示：

```java
// 0, 4, 6, 22, 26, 62, 68, 132, 140, 240
Arrays.parallelPrefix(arr, (t, q) -> t + q);
```

# 107 下一个更大的元素

NGE 是一个涉及数组的经典问题。

基本上，有一个数组和它的一个元素`e`，我们要获取下一个（右侧）大于`e`的元素。例如，假设以下数组：

```java
int[] integers = {1, 2, 3, 4, 12, 2, 1, 4};
```

获取每个元素的 NGE 将产生以下对（-1 被解释为右侧的元素不大于当前元素）：

```java
1 : 2   2 : 3   3 : 4   4 : 12   12 : -1   2 : 4   1 : 4   4 : -1
```

这个问题的一个简单解决方案是循环每个元素的数组，直到找到一个更大的元素或者没有更多的元素要检查。如果我们只想在屏幕上打印对，那么我们可以编写一个简单的代码，如下所示：

```java
public static void println(int[] arr) {

  int nge;
  int n = arr.length;

  for (int i = 0; i < n; i++) {
    nge = -1;
    for (int j = i + 1; j < n; j++) {
      if (arr[i] < arr[j]) {
        nge = arr[j];
        break;
      }
    }

    System.out.println(arr[i] + " : " + nge);
  }
}
```

另一个解决方案依赖于栈。主要是，我们在栈中推送元素，直到当前处理的元素大于栈中的顶部元素。当这种情况发生时，我们弹出那个元素。本书附带的代码中提供了解决方案。

# 108 更改数组大小

增加数组的大小并不简单。这是因为 Java 数组的大小是固定的，我们不能修改它们的大小。这个问题的解决方案需要创建一个具有所需大小的新数组，并将所有值从原始数组复制到这个数组中。这可以通过`Arrays.copyOf()`方法或`System.arraycopy()`（由`Arrays.copyOf()`内部使用）完成。

对于一个原始数组（例如，`int`），我们可以将数组的大小增加 1 后将值添加到数组中，如下所示：

```java
public static int[] add(int[] arr, int item) {

  int[] newArr = Arrays.copyOf(arr, arr.length + 1);
  newArr[newArr.length - 1] = item;

  return newArr;
}
```

或者，我们可以删除最后一个值，如下所示：

```java
public static int[] remove(int[] arr) {

  int[] newArr = Arrays.copyOf(arr, arr.length - 1);

  return newArr;
}
```

或者，我们可以按如下所示调整给定长度数组的大小：

```java
public static int[] resize(int[] arr, int length) {

  int[] newArr = Arrays.copyOf(arr, arr.length + length);

  return newArr;
}
```

捆绑到本书中的代码还包含了`System.arraycopy()`备选方案。此外，它还包含泛型数组的实现。签名如下：

```java
public static <T> T[] addObject(T[] arr, T item);
public static <T> T[] removeObject(T[] arr);
public static <T> T[] resize(T[] arr, int length);
```

在有利的背景下，让我们将一个相关的主题引入讨论：如何在 Java 中创建泛型数组。以下操作无效：

```java
T[] arr = new T[arr_size]; // causes generic array creation error
```

有几种方法，但 Java 在`copyOf(T[] original, int newLength)`中使用以下代码：

```java
// newType is original.getClass()
T[] copy = ((Object) newType == (Object) Object[].class) ?
  (T[]) new Object[newLength] :
  (T[]) Array.newInstance(newType.getComponentType(), newLength);
```

# 109 创建不可修改/不可变的集合

在 Java 中创建不可修改/不可变的集合可以很容易地通过`Collections.unmodifiableFoo()`方法（例如，`unmodifiableList()`）完成，并且从 JDK9 开始，通过来自`List`、`Set`、`Map`和其他接口的一组`of()`方法完成。

此外，我们将在一组示例中使用这些方法来获得不可修改/不可变的集合。主要目标是确定每个定义的集合是不可修改的还是不可变的。

在阅读本节之前，建议先阅读第 2 章、“对象、不变性和`switch`表达式”中有关不变性的问题。

好吧。对于原始类型来说，这非常简单。例如，我们可以创建一个不可变的整数`List`，如下所示：

```java
private static final List<Integer> LIST 
  = Collections.unmodifiableList(Arrays.asList(1, 2, 3, 4, 5));

private static final List<Integer> LIST = List.of(1, 2, 3, 4, 5);
```

对于下一个示例，让我们考虑以下可变类：

```java
public class MutableMelon {

  private String type;
  private int weight;

  // constructor omitted for brevity

  public void setType(String type) {
    this.type = type;
  }

  public void setWeight(int weight) {
    this.weight = weight;
  }

  // getters, equals() and hashCode() omitted for brevity
}
```

# 问题 1 (`Collections.unmodifiableList()`)

让我们通过`Collections.unmodifiableList()`方法创建`MutableMelon`列表：

```java
// Crenshaw(2000g), Gac(1200g)
private final MutableMelon melon1 
  = new MutableMelon("Crenshaw", 2000);
private final MutableMelon melon2 
  = new MutableMelon("Gac", 1200);

private final List<MutableMelon> list 
  = Collections.unmodifiableList(Arrays.asList(melon1, melon2));
```

那么，`list`是不可修改的还是不变的？答案是不可更改的。虽然增变器方法会抛出`UnsupportedOperationException`，但底层的`melon1`和`melon2`是可变的。例如，我们把西瓜的重量设为`0`：

```java
melon1.setWeight(0);
melon2.setWeight(0);
```

现在，列表将显示以下西瓜（因此列表发生了变异）：

```java
Crenshaw(0g), Gac(0g)
```

# 问题 2 (`Arrays.asList()`)

我们直接在`Arrays.asList()`中硬编码实例，创建`MutableMelon`列表：

```java
private final List<MutableMelon> list 
  = Collections.unmodifiableList(Arrays.asList(
    new MutableMelon("Crenshaw", 2000), 
    new MutableMelon("Gac", 1200)));
```

那么，这个列表是不可修改的还是不变的？答案是不可更改的。当增变器方法抛出`UnsupportedOperationException`时，硬编码实例可以通过`List.get()`方法访问。一旦可以访问它们，它们就可以变异：

```java
MutableMelon melon1 = list.get(0);
MutableMelon melon2 = list.get(1);

melon1.setWeight(0);
melon2.setWeight(0);
```

现在，列表将显示以下西瓜（因此列表发生了变异）：

```java
Crenshaw(0g), Gac(0g)
```

# 问题 3 (`Collections.unmodifiableList()`和静态块）

让我们通过`Collections.unmodifiableList()`方法和`static`块创建`MutableMelon`列表：

```java
private static final List<MutableMelon> list;
static {
  final MutableMelon melon1 = new MutableMelon("Crenshaw", 2000);
  final MutableMelon melon2 = new MutableMelon("Gac", 1200);

  list = Collections.unmodifiableList(Arrays.asList(melon1, melon2));
}
```

那么，这个列表是不可修改的还是不变的？答案是不可更改的。虽然增变器方法会抛出`UnsupportedOperationException`，但是硬编码的实例仍然可以通过`List.get()`方法访问。一旦可以访问它们，它们就可以变异：

```java
MutableMelon melon1l = list.get(0);
MutableMelon melon2l = list.get(1);

melon1l.setWeight(0);
melon2l.setWeight(0);
```

现在，列表将显示以下西瓜（因此列表发生了变异）：

```java
Crenshaw(0g), Gac(0g)
```

# 问题 4 (`List.of()`)

让我们通过`List.of()`创建`MutableMelon`的列表：

```java
private final MutableMelon melon1 
  = new MutableMelon("Crenshaw", 2000);
private final MutableMelon melon2 
  = new MutableMelon("Gac", 1200);

private final List<MutableMelon> list = List.of(melon1, melon2);
```

那么，这个列表是不可修改的还是不变的？答案是不可更改的。虽然增变器方法会抛出`UnsupportedOperationException`，但是硬编码的实例仍然可以通过`List.get()`方法访问。一旦可以访问它们，它们就可以变异：

```java
MutableMelon melon1l = list.get(0);
MutableMelon melon2l = list.get(1);

melon1l.setWeight(0);
melon2l.setWeight(0);
```

现在，列表将显示以下西瓜（因此列表发生了变异）：

```java
Crenshaw(0g), Gac(0g)
```

对于下一个示例，让我们考虑以下不可变类：

```java
public final class ImmutableMelon {

  private final String type;
  private final int weight;

  // constructor, getters, equals() and hashCode() omitted for brevity
}
```

# 问题 5（不可变）

现在我们通过`Collections.unmodifiableList()`和`List.of()`方法创建`ImmutableMelon`列表：

```java
private static final ImmutableMelon MELON_1 
  = new ImmutableMelon("Crenshaw", 2000);
private static final ImmutableMelon MELON_2 
  = new ImmutableMelon("Gac", 1200);

private static final List<ImmutableMelon> LIST 
  = Collections.unmodifiableList(Arrays.asList(MELON_1, MELON_2));
private static final List<ImmutableMelon> LIST 
  = List.of(MELON_1, MELON_2);
```

那么，这个列表是不可修改的还是不变的？答案是不变的。增变器方法会抛出`UnsupportedOperationException`，我们不能对`ImmutableMelon`的实例进行变异。

根据经验，如果集合是通过`unmodifiableFoo()`或`of()`方法定义的，并且包含可变数据，则集合是不可修改的；如果集合是不可修改的，并且包含可变数据（包括原始类型），则集合是不可修改的。

需要注意的是，不可穿透的不变性应该考虑 Java 反射 API 和类似的 API，它们在操作代码时具有辅助功能。

对于第三方库支持，请考虑 Apache Common Collection、`UnmodifiableList`（和同伴）和 Guava 的`ImmutableList`（和同伴）。

在`Map`的情况下，我们可以通过`unmodifiableMap()`或`Map.of()`方法创建一个不可修改/不可修改的`Map`。

但我们也可以通过`Collections.emptyMap()`创建一个不可变的空`Map`：

```java
Map<Integer, MutableMelon> emptyMap = Collections.emptyMap();
```

与`emptyMap()`类似，我们有`Collections.emptyList()`和`Collections.emptySet()`。在返回一个`Map`、`List`或`Set`的方法中，这些方法作为返回非常方便，我们希望避免返回`null`。

或者，我们可以通过`Collections.singletonMap(K key, V value)`用单个元素创建一个不可修改/不可变的`Map`：

```java
// unmodifiable
Map<Integer, MutableMelon> mapOfSingleMelon 
  = Collections.singletonMap(1, new MutableMelon("Gac", 1200));

// immutable
Map<Integer, ImmutableMelon> mapOfSingleMelon 
  = Collections.singletonMap(1, new ImmutableMelon("Gac", 1200));
```

类似于`singletonMap()`，我们有`singletonList()`和`singleton()`。后者用于`Set`。

此外，从 JDK9 开始，我们可以通过一个名为`ofEntries()`的方法创建一个不可修改的`Map`。此方法以`Map.Entry`为参数，如下例所示：

```java
// unmodifiable Map.Entry containing the given key and value
import static java.util.Map.entry;
...
Map<Integer, MutableMelon> mapOfMelon = Map.ofEntries(
  entry(1, new MutableMelon("Apollo", 3000)),
  entry(2, new MutableMelon("Jade Dew", 3500)),
  entry(3, new MutableMelon("Cantaloupe", 1500))
);
```

或者，不可变的`Map`是另一种选择：

```java
Map<Integer, ImmutableMelon> mapOfMelon = Map.ofEntries(
  entry(1, new ImmutableMelon("Apollo", 3000)),
  entry(2, new ImmutableMelon("Jade Dew", 3500)),
  entry(3, new ImmutableMelon("Cantaloupe", 1500))
);
```

另外，可以通过 JDK10 从可修改/可变的`Map`中获得不可修改/不可变的`Map`，`Map.copyOf​(Map<? extends K,​? extends V> map)`方法：

```java
Map<Integer, ImmutableMelon> mapOfMelon = new HashMap<>();
mapOfMelon.put(1, new ImmutableMelon("Apollo", 3000));
mapOfMelon.put(2, new ImmutableMelon("Jade Dew", 3500));
mapOfMelon.put(3, new ImmutableMelon("Cantaloupe", 1500));

Map<Integer, ImmutableMelon> immutableMapOfMelon 
  = Map.copyOf(mapOfMelon);
```

作为这一节的奖励，让我们来讨论一个不可变数组。

**问题**：我能用 Java 创建一个不可变数组吗？

**答案**：不可以。或者。。。有一种方法可以在 Java 中生成不可变数组：

```java
static final String[] immutable = new String[0];
```

因此，Java 中所有有用的数组都是可变的。但是我们可以在`Arrays.copyOf()`的基础上创建一个辅助类来创建不可变数组，它复制元素并创建一个新数组（在幕后，这个方法依赖于`System.arraycopy()`。

因此，我们的辅助类如下所示：

```java
import java.util.Arrays;

public final class ImmutableArray<T> {

  private final T[] array;

  private ImmutableArray(T[] a) {
    array = Arrays.copyOf(a, a.length);
  }

  public static <T> ImmutableArray<T> from(T[] a) {
    return new ImmutableArray<>(a);
  }

  public T get(int index) {
    return array[index];
  }

  // equals(), hashCode() and toString() omitted for brevity
}
```

用法示例如下：

```java
ImmutableArray<String> sample =
  ImmutableArray.from(new String[] {
    "a", "b", "c"
  });
```

# 110 映射的默认值

在 JDK8 之前，这个问题的解决方案依赖于辅助方法，它基本上检查`Map`中给定键的存在，并返回相应的值或默认值。这种方法可以在工具类中编写，也可以通过扩展`Map`接口来编写。通过返回默认值，我们可以避免在`Map`中找不到给定键时返回`null`。此外，这是依赖默认设置或配置的方便方法。

从 JDK8 开始，这个问题的解决方案包括简单地调用`Map.getOrDefault()`方法。此方法获取两个参数，分别表示要在`Map`方法中查找的键和默认值。当找不到给定的键时，默认值充当应该返回的备份值。

例如，假设下面的`Map`封装了多个数据库及其默认的`host:port`：

```java
Map<String, String> map = new HashMap<>();
map.put("postgresql", "127.0.0.1:5432");
map.put("mysql", "192.168.0.50:3306");
map.put("cassandra", "192.168.1.5:9042");
```

我们来看看这个`Map`是否也包含 Derby DB 的默认`host:port`：

```java
map.get("derby"); // null
```

由于映射中没有 Derby DB，因此结果将是`null`。这不是我们想要的。实际上，当搜索到的数据库不在映射上时，我们可以在`69:89.31.226:27017`上使用 MongoDB，它总是可用的。现在，我们可以很容易地将此行为塑造为：

```java
// 69:89.31.226:27017
String hp1 = map.getOrDefault("derby", "69:89.31.226:27017");

// 192.168.0.50:3306
String hp2 = map.getOrDefault("mysql", "69:89.31.226:27017");
```

这种方法可以方便地建立流利的表达式，避免中断代码进行`null`检查。请注意，返回默认值并不意味着该值将被添加到`Map`。`Map`保持不变。

# 111 计算映射中是否不存在/存在

有时，`Map`并不包含我们需要的准确的*开箱即用*条目。此外，当条目不存在时，返回默认条目也不是一个选项。基本上，有些情况下我们需要计算我们的入口。

对于这种情况，JDK8 提供了一系列方法：`compute()`、`computeIfAbsent()`、`computeIfPresent()`和`merge()`。在这些方法之间进行选择是一个非常了解每种方法的问题。

现在让我们通过示例来看看这些方法的实现。

# 示例 1（`computeIfPresent()`）

假设我们有以下`Map`：

```java
Map<String, String> map = new HashMap<>();
map.put("postgresql", "127.0.0.1");
map.put("mysql", "192.168.0.50");
```

我们使用这个映射为不同的数据库类型构建 JDBC URL。

假设我们要为 MySQL 构建 JDBC URL。如果映射中存在`mysql`键，则应根据相应的值`jdbc:mysql://192.168.0.50/customers_db`计算 JDBC URL。但是如果不存在`mysql`键，那么 JDBC URL 应该是`null`。除此之外，如果我们的计算结果是`null`（无法计算 JDBC URL），那么我们希望从映射中删除这个条目。

这是`V computeIfPresent​(K key, BiFunction<? super K,​? super V,​? extends V> remappingFunction)`的工作。

在我们的例子中，用于计算新值的`BiFunction`如下所示（`k`是映射中的键，`v`是与键关联的值）：

```java
BiFunction<String, String, String> jdbcUrl 
  = (k, v) -> "jdbc:" + k + "://" + v + "/customers_db";
```

一旦我们有了这个函数，我们就可以计算出`mysql`键的新值，如下所示：

```java
// jdbc:mysql://192.168.0.50/customers_db
String mySqlJdbcUrl = map.computeIfPresent("mysql", jdbcUrl);
```

由于映射中存在`mysql`键，结果将是`jdbc:mysql://192.168.0.50/customers_db`，新映射包含以下条目：

```java
postgresql=127.0.0.1, mysql=jdbc:mysql://192.168.0.50/customers_db
```

再次调用`computeIfPresent()`将重新计算值，这意味着它将导致类似`mysql= jdbc:mysql://jdbc:mysql://....`的结果。显然，这是不可以的，所以请注意这方面。

另一方面，如果我们对一个不存在的条目进行相同的计算（例如，`voltdb`），那么返回的值将是`null`，映射保持不变：

```java
// null
String voldDbJdbcUrl = map.computeIfPresent("voltdb", jdbcUrl);
```

# 示例 2（`computeIfAbsent()`）

假设我们有以下`Map`：

```java
Map<String, String> map = new HashMap<>();
map.put("postgresql", "jdbc:postgresql://127.0.0.1/customers_db");
map.put("mysql", "jdbc:mysql://192.168.0.50/customers_db");
```

我们使用这个映射为不同的数据库构建  JDBC URL。

假设我们要为 MongoDB 构建 JDBC URL。这一次，如果映射中存在`mongodb`键，则应返回相应的值，而无需进一步计算。但是如果这个键不存在（或者与一个`null`值相关联），那么它应该基于这个键和当前 IP 进行计算并添加到映射中。如果计算值为`null`，则返回结果为`null`，映射保持不变。

嗯，这是`V computeIfAbsent​(K key, Function<? super K,​? extends V> mappingFunction)`的工作。

在我们的例子中，用于计算值的`Function`将如下所示（第一个`String`是映射中的键（`k`），而第二个`String`是为该键计算的值）：

```java
String address = InetAddress.getLocalHost().getHostAddress();

Function<String, String> jdbcUrl 
  = k -> k + "://" + address + "/customers_db";
```

基于此函数，我们可以尝试通过`mongodb`键获取 MongoDB 的 JDBC URL，如下所示：

```java
// mongodb://192.168.100.10/customers_db
String mongodbJdbcUrl = map.computeIfAbsent("mongodb", jdbcUrl);
```

因为我们的映射不包含`mongodb`键，它将被计算并添加到映射中。

如果我们的`Function`被求值为`null`，那么映射保持不变，返回值为`null`。

再次调用`computeIfAbsent()`不会重新计算值。这次，由于`mongodb`在映射中（在上一次调用中添加），所以返回的值将是`mongodb://192.168.100.10/customers_db`。这与尝试获取`mysql`的 JDBC URL 是一样的，它将返回`jdbc:mysql://192.168.0.50/customers_db`，而无需进一步计算。

# 示例 3（`compute()`）

假设我们有以下`Map`：

```java
Map<String, String> map = new HashMap<>();
map.put("postgresql", "127.0.0.1");
map.put("mysql", "192.168.0.50");
```

我们使用这个映射为不同的数据库类型构建  JDBC URL。

假设我们要为 MySQL 和 Derby DB 构建 JDBC URL。在这种情况下，不管键（`mysql`还是`derby`存在于映射中，JDBC URL 都应该基于相应的键和值（可以是`null`）来计算。另外，如果键存在于映射中，并且我们的计算结果是`null`（无法计算 JDBC URL），那么我们希望从映射中删除这个条目。基本上，这是`computeIfPresent()`和`computeIfAbsent()`的组合。

这是`V compute​(K key, BiFunction<? super K,​? super V,​? extends V> remappingFunction)`的工作。

此时，应写入`BiFunction`以覆盖搜索键的值为`null`时的情况：

```java
String address = InetAddress.getLocalHost().getHostAddress();
BiFunction<String, String, String> jdbcUrl = (k, v) 
  -> "jdbc:" + k + "://" + ((v == null) ? address : v) 
    + "/customers_db";
```

现在，让我们计算 MySQL 的 JDBC URL。因为`mysql`键存在于映射中，所以计算将依赖于相应的值`192.168.0.50`。结果将更新映射中`mysql`键的值：

```java
// jdbc:mysql://192.168.0.50/customers_db
String mysqlJdbcUrl = map.compute("mysql", jdbcUrl);
```

另外，让我们计算 Derby DB 的 JDBC URL。由于映射中不存在`derby`键，因此计算将依赖于当前 IP。结果将被添加到映射的`derby`键下：

```java
// jdbc:derby://192.168.100.10/customers_db
String derbyJdbcUrl = map.compute("derby", jdbcUrl);
```

在这两次计算之后，映射将包含以下三个条目：

*   `postgresql=127.0.0.1`
*   `derby=jdbc:derby://192.168.100.10/customers_db`
*   `mysql=jdbc:mysql://192.168.0.50/customers_db`

请注意，再次调用`compute()`将重新计算值。这可能导致不需要的结果，如`jdbc:derby://jdbc:derby://...`。
如果计算的结果是`null`（例如 JDBC URL 无法计算），并且映射中存在键（例如`mysql`），那么这个条目将从映射中删除，返回的结果是`null`。

# 示例 4（`merge()`）

假设我们有以下`Map`：

```java
Map<String, String> map = new HashMap<>();
map.put("postgresql", "9.6.1 ");
map.put("mysql", "5.1 5.2 5.6 ");
```

我们使用这个映射来存储每个数据库类型的版本，这些版本之间用空格隔开。

现在，假设每次发布数据库类型的新版本时，我们都希望将其添加到对应键下的映射中。如果键（例如，`mysql`）存在于映射中，那么我们只需将新版本连接到当前值的末尾。如果键（例如，`derby`）不在映射中，那么我们现在只想添加它。

这是`V merge​(K key, V value, BiFunction<? super V,​? super V,​? extends V> remappingFunction)`的完美工作。

如果给定的键（`K`与某个值没有关联或与`null`关联，那么新的值将是`V`。如果给定键（`K`与非`null`值相关联，则基于给定的`BiFunction`计算新值。如果此`BiFunction`的结果是`null`，并且该键存在于映射中，则此条目将从映射中删除。

在我们的例子中，我们希望将当前值与新版本连接起来，因此我们的`BiFunction`可以写为：

```java
BiFunction<String, String, String> jdbcUrl = String::concat;
```

我们在以下方面也有类似的情况：

```java
BiFunction<String, String, String> jdbcUrl 
  = (vold, vnew) -> vold.concat(vnew);
```

例如，假设我们希望在 MySQL 的映射版本 8.0 中连接。这可以通过以下方式实现：

```java
// 5.1 5.2 5.6 8.0
String mySqlVersion = map.merge("mysql", "8.0 ", jdbcUrl);
```

稍后，我们还将连接 9.0 版：

```java
// 5.1 5.2 5.6 8.0 9.0
String mySqlVersion = map.merge("mysql", "9.0 ", jdbcUrl);
```

或者，我们添加 Derby DB 的版本`10.11.1.1`。这将导致映射中出现一个新条目，因为不存在`derby`键：

```java
// 10.11.1.1
String derbyVersion = map.merge("derby", "10.11.1.1 ", jdbcUrl);
```

在这三个操作结束时，映射条目如下所示：

```java
postgresql=9.6.1, derby=10.11.1.1, mysql=5.1 5.2 5.6 8.0 9.0
```

# 示例 5（`putIfAbsent()`）

假设我们有以下`Map`：

```java
Map<Integer, String> map = new HashMap<>();
map.put(1, "postgresql");
map.put(2, "mysql");
map.put(3, null);
```

我们使用这个映射来存储一些数据库类型的名称。

现在，假设我们希望基于以下约束在该映射中包含更多数据库类型：

*   如果给定的键存在于映射中，那么只需返回相应的值并保持映射不变。
*   如果给定的键不在映射中（或者与一个`null`值相关联），则将给定的值放入映射并返回`null`。

嗯，这是`putIfAbsent​(K key, V value)`的工作。

以下三种尝试不言自明：

```java
String v1 = map.putIfAbsent(1, "derby");     // postgresql
String v2 = map.putIfAbsent(3, "derby");     // null
String v3 = map.putIfAbsent(4, "cassandra"); // null
```

映射内容如下：

```java
1=postgresql, 2=mysql, 3=derby, 4=cassandra
```

# 112 从映射中删除

从`Map`中删除可以通过一个键或者一个键和值来完成。

例如，假设我们有以下`Map`：

```java
Map<Integer, String> map = new HashMap<>();
map.put(1, "postgresql");
map.put(2, "mysql");
map.put(3, "derby");
```

通过键删除就像调用`V Map.remove(Object key)`方法一样简单。如果给定键对应的条目删除成功，则返回关联值，否则返回`null`。

检查以下示例：

```java
String r1 = map.remove(1); // postgresql
String r2 = map.remove(4); // null
```

现在，映射包含以下条目（已删除键 1 中的条目）：

```java
2=mysql, 3=derby
```

从 JDK8 开始，`Map`接口被一个新的`remove()`标志方法所丰富，该方法具有以下签名：`boolean remove​(Object key, Object value)`。使用这种方法，只有在给定的键和值之间存在完美匹配时，才能从映射中删除条目。基本上，这种方法是以下复合条件的捷径：`map.containsKey(key) && Objects.equals(map.get(key), value)`。

让我们举两个简单的例子：

```java
// true
boolean r1 = map.remove(2, "mysql");

// false (the key is present, but the values don't match)
boolean r2 = map.remove(3, "mysql");
```

结果映射包含一个剩余条目`3=derby`。

迭代和从`Map`中移除至少可以通过两种方式来完成：第一，通过`Iterator`（捆绑代码中存在的解决方案），第二，从 JDK8 开始，我们可以通过`removeIf​(Predicate<? super E> filter)`来完成：

```java
map.entrySet().removeIf(e -> e.getValue().equals("mysql"));
```

有关从集合中删除的更多详细信息，请参见“删除集合中与谓词匹配的所有元素”。

# 113 替换映射中的条目

从`Map`替换条目是一个在很多情况下都会遇到的问题。要实现这一点并避免在辅助方法中编写一段*意大利面条*代码，方便的解决方案依赖于 JDK8`replace()`方法。

假设我们有下面的`Melon`类和`Melon`的映射：

```java
public class Melon {

  private final String type;
  private final int weight;

  // constructor, getters, equals(), hashCode(),
  // toString() omitted for brevity
}

Map<Integer, Melon> mapOfMelon = new HashMap<>();
mapOfMelon.put(1, new Melon("Apollo", 3000));
mapOfMelon.put(2, new Melon("Jade Dew", 3500));
mapOfMelon.put(3, new Melon("Cantaloupe", 1500));
```

通过`V replace​(K key, V value)`可以完成按键 2 对应的甜瓜的更换。如果替换成功，则此方法将返回初始的`Melon`：

```java
// Jade Dew(3500g) was replaced
Melon melon = mapOfMelon.replace(2, new Melon("Gac", 1000));
```

现在，映射包含以下条目：

```java
1=Apollo(3000g), 2=Gac(1000g), 3=Cantaloupe(1500g)
```

此外，假设我们想用键 1 和阿波罗甜瓜（3000g）替换条目。所以，甜瓜应该是同一个，才能获得成功的替代品。这可以通过布尔值`replace​(K key, V oldValue, V newValue)`实现。此方法依赖于`equals()`合同来比较给定的值，因此`Melon`需要执行`equals()`方法，否则结果不可预知：

```java
// true
boolean melon = mapOfMelon.replace(
  1, new Melon("Apollo", 3000), new Melon("Bitter", 4300));
```

现在，映射包含以下条目：

```java
1=Bitter(4300g), 2=Gac(1000g), 3=Cantaloupe(1500g)
```

最后，假设我们要根据给定的函数替换`Map`中的所有条目。这可以通过`void replaceAll​(BiFunction<? super K,​? super V,​? extends V> function)`完成。

例如，将所有重量超过 1000g 的瓜替换为重量等于 1000g 的瓜，下面的`BiFunction`形成了这个函数（`k`是键，`v`是`Map`中每个条目的值）：

```java
BiFunction<Integer, Melon, Melon> function = (k, v) 
  -> v.getWeight() > 1000 ? new Melon(v.getType(), 1000) : v;
```

接下来，`replaceAll()`出现在现场：

```java
mapOfMelon.replaceAll(function);
```

现在，映射包含以下条目：

```java
1=Bitter(1000g), 2=Gac(1000g), 3=Cantaloupe(1000g)
```

# 114 比较两个映射

只要我们依赖于`Map.equals()`方法，比较两个映射是很简单的。在比较两个映射时，该方法使用`Object.equals()`方法比较它们的键和值。

例如，让我们考虑两个具有相同条目的瓜映射（在`Melon`类中必须存在`equals()`和`hashCode()`：

```java
public class Melon {

  private final String type;
  private final int weight;

  // constructor, getters, equals(), hashCode(),
  // toString() omitted for brevity
}

Map<Integer, Melon> melons1Map = new HashMap<>();
Map<Integer, Melon> melons2Map = new HashMap<>();
melons1Map.put(1, new Melon("Apollo", 3000));
melons1Map.put(2, new Melon("Jade Dew", 3500));
melons1Map.put(3, new Melon("Cantaloupe", 1500));
melons2Map.put(1, new Melon("Apollo", 3000));
melons2Map.put(2, new Melon("Jade Dew", 3500));
melons2Map.put(3, new Melon("Cantaloupe", 1500));
```

现在，如果我们测试`melons1Map`和`melons2Map`是否相等，那么我们得到`true`：

```java
boolean equals12Map = melons1Map.equals(melons2Map); // true
```

但如果我们使用数组，这将不起作用。例如，考虑下面两个映射：

```java
Melon[] melons1Array = {
  new Melon("Apollo", 3000),
  new Melon("Jade Dew", 3500), new Melon("Cantaloupe", 1500)
};
Melon[] melons2Array = {
  new Melon("Apollo", 3000),
  new Melon("Jade Dew", 3500), new Melon("Cantaloupe", 1500)
};

Map<Integer, Melon[]> melons1ArrayMap = new HashMap<>();
melons1ArrayMap.put(1, melons1Array);
Map<Integer, Melon[]> melons2ArrayMap = new HashMap<>();
melons2ArrayMap.put(1, melons2Array);
```

即使`melons1ArrayMap`和`melons2ArrayMap`相等，`Map.equals()`也会返回`false`：

```java
boolean equals12ArrayMap = melons1ArrayMap.equals(melons2ArrayMap);
```

这个问题源于这样一个事实：数组的`equals()`方法比较的是标识，而不是数组的内容。为了解决这个问题，我们可以编写一个辅助方法如下（这次依赖于`Arrays.equals()`，它比较数组的内容）：

```java
public static <A, B> boolean equalsWithArrays(
    Map<A, B[]> first, Map<A, B[]> second) {

  if (first.size() != second.size()) {
    return false;
  }

  return first.entrySet().stream()
    .allMatch(e -> Arrays.equals(e.getValue(), 
      second.get(e.getKey())));
}
```

# 115 对映射排序

排序一个`Map`有几种解决方案。首先，假设`Melon`中的`Map`：

```java
public class Melon implements Comparable {

  private final String type;
  private final int weight;

  @Override
  public int compareTo(Object o) {
    return Integer.compare(this.getWeight(), ((Melon) o).getWeight());
  }

  // constructor, getters, equals(), hashCode(),
  // toString() omitted for brevity
}

Map<String, Melon> melons = new HashMap<>();
melons.put("delicious", new Melon("Apollo", 3000));
melons.put("refreshing", new Melon("Jade Dew", 3500));
melons.put("famous", new Melon("Cantaloupe", 1500));
```

现在，让我们来研究几种排序这个`Map`的解决方案。基本上，我们的目标是通过一个名为`Maps`的工具类公开以下屏幕截图中的方法：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-cd-prob/img/68fea7e5-dde3-48c3-af33-d0701244c43e.png)

让我们在下一节中看看不同的解决方案。

# 通过`TreeMap`和自然排序按键排序

对`Map`进行排序的快速解决方案依赖于`TreeMap`。根据定义，`TreeMap`中的键按其自然顺序排序。此外，`TreeMap`还有一个`TreeMap​(Map<? extends K,​? extends V> m)`类型的构造器：

```java
public static <K, V> TreeMap<K, V> sortByKeyTreeMap(Map<K, V> map) {

  return new TreeMap<>(map);
}
```

调用它将按键对映射进行排序：

```java
// {delicious=Apollo(3000g), 
// famous=Cantaloupe(1500g), refreshing=Jade Dew(3500g)}
TreeMap<String, Melon> sortedMap = Maps.sortByKeyTreeMap(melons);
```

# 通过流和比较器按键和值排序

一旦我们为映射创建了一个`Stream`，我们就可以很容易地用`Stream.sorted()`方法对它进行排序，不管有没有`Comparator`。这一次，让我们使用一个`Comparator`：

```java
public static <K, V> Map<K, V> sortByKeyStream(
    Map<K, V> map, Comparator<? super K> c) {

  return map.entrySet()
    .stream()
    .sorted(Map.Entry.comparingByKey(c))
    .collect(toMap(Map.Entry::getKey, Map.Entry::getValue,
      (v1, v2) -> v1, LinkedHashMap::new));
}

public static <K, V> Map<K, V> sortByValueStream(
    Map<K, V> map, Comparator<? super V> c) {

  return map.entrySet()
    .stream()
    .sorted(Map.Entry.comparingByValue(c))
    .collect(toMap(Map.Entry::getKey, Map.Entry::getValue,
      (v1, v2) -> v1, LinkedHashMap::new));
}
```

我们需要依赖`LinkedHashMap`而不是`HashMap`。否则，我们就不能保持迭代顺序。

让我们把映射分类如下：

```java
// {delicious=Apollo(3000g), 
//  famous=Cantaloupe(1500g), 
//  refreshing=Jade Dew(3500g)}
Comparator<String> byInt = Comparator.naturalOrder();
Map<String, Melon> sortedMap = Maps.sortByKeyStream(melons, byInt);

// {famous=Cantaloupe(1500g), 
//  delicious=Apollo(3000g), 
//  refreshing=Jade Dew(3500g)}
Comparator<Melon> byWeight = Comparator.comparing(Melon::getWeight);
Map<String, Melon> sortedMap 
  = Maps.sortByValueStream(melons, byWeight);
```

# 通过列表按键和值排序

前面的示例对给定的映射进行排序，结果也是一个映射。如果我们只需要排序的键（我们不关心值），反之亦然，那么我们可以依赖于通过`Map.keySet()`创建的`List`作为键，通过`Map.values()`创建的`List`作为值：

```java
public static <K extends Comparable, V> List<K>
    sortByKeyList(Map<K, V> map) {

  List<K> list = new ArrayList<>(map.keySet());
  Collections.sort(list);

  return list;
}

public static <K, V extends Comparable> List<V>
    sortByValueList(Map<K, V> map) {

  List<V> list = new ArrayList<>(map.values());
  Collections.sort(list);

  return list;
}
```

现在，让我们对映射进行排序：

```java
// [delicious, famous, refreshing]
List<String> sortedKeys = Maps.sortByKeyList(melons);

// [Cantaloupe(1500g), Apollo(3000g), Jade Dew(3500g)]
List<Melon> sortedValues = Maps.sortByValueList(melons);
```

如果不允许重复值，则必须依赖于使用`SortedSet`的实现：

```java
SortedSet<String> sortedKeys = new TreeSet<>(melons.keySet());
SortedSet<Melon> sortedValues = new TreeSet<>(melons.values());
```

# 116 复制哈希映射

执行`HashMap`的浅拷贝的简便解决方案依赖于`HashMap`构造器`HashMap​(Map<? extends K,​? extends V> m)`。以下代码是不言自明的：

```java
Map<K, V> mapToCopy = new HashMap<>();
Map<K, V> shallowCopy = new HashMap<>(mapToCopy);
```

另一种解决方案可能依赖于`putAll​(Map<? extends K,​? extends V> m)`方法。此方法将指定映射中的所有映射复制到此映射，如以下助手方法所示：

```java
@SuppressWarnings("unchecked")
public static <K, V> HashMap<K, V> shallowCopy(Map<K, V> map) {

  HashMap<K, V> copy = new HashMap<>();
  copy.putAll(map);

  return copy;
}
```

我们还可以用 Java8 函数式风格编写一个辅助方法，如下所示：

```java
@SuppressWarnings("unchecked")
public static <K, V> HashMap<K, V> shallowCopy(Map<K, V> map) {

  Set<Entry<K, V>> entries = map.entrySet();
  HashMap<K, V> copy = (HashMap<K, V>) entries.stream()
    .collect(Collectors.toMap(
       Map.Entry::getKey, Map.Entry::getValue));

  return copy;
}
```

然而，这三种解决方案只提供了映射的浅显副本。[获取深度拷贝的解决方案可以依赖于克隆库](https://github.com/kostaskougios/cloning)在第 2 章中介绍，“对象、不变性和`switch`表达式”。将使用克隆的助手方法可以编写如下：

```java
@SuppressWarnings("unchecked") 
public static <K, V> HashMap<K, V> deepCopy(Map<K, V> map) {
  Cloner cloner = new Cloner();
  HashMap<K, V> copy = (HashMap<K, V>) cloner.deepClone(map);

  return copy;
}
```

# 117 合并两个映射

合并两个映射是将两个映射合并为一个包含两个映射的元素的映射的过程。此外，对于键碰撞，我们将属于第二个映射的值合并到最终映射中。但这是一个设计决定。

让我们考虑以下两个映射（我们特意为键 3 添加了一个冲突）：

```java
public class Melon {

  private final String type;
  private final int weight;

  // constructor, getters, equals(), hashCode(),
  // toString() omitted for brevity
}

Map<Integer, Melon> melons1 = new HashMap<>();
Map<Integer, Melon> melons2 = new HashMap<>();
melons1.put(1, new Melon("Apollo", 3000));
melons1.put(2, new Melon("Jade Dew", 3500));
melons1.put(3, new Melon("Cantaloupe", 1500));
melons2.put(3, new Melon("Apollo", 3000));
melons2.put(4, new Melon("Jade Dew", 3500));
melons2.put(5, new Melon("Cantaloupe", 1500));
```

从 JDK8 开始，我们在`Map: V merge​(K key, V value, BiFunction<? super V,​? super V,​? extends V> remappingFunction)`中有以下方法。

如果给定的键（`K`与值没有关联，或者与`null`关联，那么新的值将是`V`。如果给定键（`K`与非`null`值相关联，则基于给定的`BiFunction`计算新值。如果此`BiFunction`的结果是`null`，并且该键存在于映射中，则此条目将从映射中删除。

基于这个定义，我们可以编写一个辅助方法来合并两个映射，如下所示：

```java
public static <K, V> Map<K, V> mergeMaps(
    Map<K, V> map1, Map<K, V> map2) {  

  Map<K, V> map = new HashMap<>(map1);

  map2.forEach(
    (key, value) -> map.merge(key, value, (v1, v2) -> v2));

  return map;
}
```

请注意，我们不会修改原始映射。我们更希望返回一个包含第一个映射的元素与第二个映射的元素合并的新映射。在键冲突的情况下，我们用第二个映射（`v2`中的值替换现有值。

基于`Stream.concat()`可以编写另一个解决方案。基本上，这种方法将两个流连接成一个`Stream`。为了从一个`Map`创建一个`Stream`，我们称之为`Map.entrySet().stream()`。在连接从给定映射创建的两个流之后，我们只需通过`toMap()`收集器收集结果：

```java
public static <K, V> Map<K, V> mergeMaps(
    Map<K, V> map1, Map<K, V> map2) {

  Stream<Map.Entry<K, V>> combined 
    = Stream.concat(map1.entrySet().stream(), 
      map2.entrySet().stream());

  Map<K, V> map = combined.collect(
    Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue,
      (v1, v2) -> v2));

  return map;
}
```

作为奖励，`Set`（例如，整数的`Set`可以按如下方式排序：

```java
List<Integer> sortedList = someSetOfIntegers.stream()
  .sorted().collect(Collectors.toList());
```

对于对象，依赖于`sorted(Comparator<? super T>`。

# 118 删除集合中与谓词匹配的所有元素

我们的集合将收集一堆`Melon`：

```java
public class Melon {

  private final String type;
  private final int weight;

  // constructor, getters, equals(), 
  // hashCode(), toString() omitted for brevity
}
```

让我们在整个示例中假设以下集合（`ArrayList`，以演示如何从集合中移除与给定谓词匹配的元素：

```java
List<Melon> melons = new ArrayList<>();
melons.add(new Melon("Apollo", 3000));
melons.add(new Melon("Jade Dew", 3500));
melons.add(new Melon("Cantaloupe", 1500));
melons.add(new Melon("Gac", 1600));
melons.add(new Melon("Hami", 1400));
```

让我们看看下面几节给出的不同解决方案。

# 通过迭代器删除

通过`Iterator`删除是 Java 中最古老的方法。主要地，`Iterator`允许我们迭代（或遍历）集合并删除某些元素。最古老的方法也有一些缺点。首先，根据集合类型的不同，如果多个线程修改集合，那么通过一个`Iterator`删除很容易发生`ConcurrentModificationException`。此外，移除并不是所有集合的行为都相同（例如，从`LinkedList`移除要比从`ArrayList`移除快，因为前者只是将指针移动到下一个元素，而后者则需要移动元素）。不过，解决方案在捆绑代码中是可用的。

如果您所需要的只是`Iterable`的大小，那么请考虑以下方法之一：

```java
// for any Iterable
StreamSupport.stream(iterable.spliterator(), false).count();

// for collections
((Collection<?>) iterable).size()
```

# 移除通孔集合.removeIf()

从 JDK8 开始，我们可以通过`Collection.removeIf()`方法将前面的代码缩减为一行代码。此方法依赖于`Predicate`，如下例所示：

```java
melons.removeIf(t -> t.getWeight() < 3000);
```

这一次，`ArrayList`迭代列表并标记为删除那些满足我们的`Predicate`的元素。此外，`ArrayList`再次迭代以移除标记的元素并移动剩余的元素。

使用这种方法，`LinkedList`和`ArrayList`以几乎相同的方式执行。

# 通过流删除

从 JDK8 开始，我们可以从集合（`Collection.stream()`中创建一个`Stream`，并通过`filter(Predicate p)`过滤它的元素。过滤器将只保留满足给定`Predicate`的元件。

最后，我们通过合适的收集器收集这些元素：

```java
List<Melon> filteredMelons = melons.stream()
  .filter(t -> t.getWeight() >= 3000)
  .collect(Collectors.toList());
```

与其他两个解决方案不同，这个解决方案不会改变原始集合，但它可能会更慢，占用更多内存。

# 通过`Collectors.partitioningBy()`

有时，我们不想删除与谓词不匹配的元素。我们实际上想要的是基于谓词来分离元素。好吧，这是可以通过`Collectors.partitioningBy(Predicate p)`实现的。

基本上，`Collectors.partitioningBy()`将把元素分成两个列表。这两个列表作为值添加到`Map`。此`Map`的两个键是`true`和`false`：

```java
Map<Boolean, List<Melon>> separatedMelons = melons.stream()
  .collect(Collectors.partitioningBy(
    (Melon t) -> t.getWeight() >= 3000));

List<Melon> weightLessThan3000 = separatedMelons.get(false);
List<Melon> weightGreaterThan3000 = separatedMelons.get(true);
```

因此，`true`键用于检索包含与谓词匹配的元素的`List`，而`false`键用于检索包含与谓词不匹配的元素的`List`。

作为奖励，如果我们想检查`List`的所有元素是否相同，那么我们可以依赖`Collections.frequency(Collection c, Object obj)`。此方法返回指定集合中等于指定对象的元素数：

```java
boolean allTheSame = Collections.frequency(
  melons, melons.get(0)) == melons.size());
```

如果`allTheSame`是`true`，那么所有元素都是相同的。注意，`List`中的对象的`equals()`和`hashCode()`必须相应地实现。

# 119 将集合转换为数组

为了将集合转换为数组，我们可以依赖于`Collection.toArray()`方法。如果没有参数，此方法会将给定集合转换为一个`Object[]`，如下例所示：

```java
List<String> names = Arrays.asList("ana", "mario", "vio");
Object[] namesArrayAsObjects = names.toArray();
```

显然，这并不完全有用，因为我们期望的是一个`String[]`而不是`Object[]`。这可以通过`Collection.toArray​(T[] a)`实现，如下所示：

```java
String[] namesArraysAsStrings = names.toArray(new String[names.size()]);
String[] namesArraysAsStrings = names.toArray(new String[0]);
```

从这两种解决方案中，第二种方案更可取，因为我们避免计算集合大小。

但从 JDK11 开始，还有一种方法专门用于此任务，`Collection.toArray​(IntFunction<T[]> generator)`。此方法返回一个包含此集合中所有元素的数组，使用提供的生成器函数分配返回的数组：

```java
String[] namesArraysAsStrings = names.toArray(String[]::new);
```

除了固定大小可修改的`Arrays.asList()`之外，我们可以通过`of()`方法从数组中构建一个不可修改的`List`/`Set`：

```java
String[] namesArray = {"ana", "mario", "vio"};

List<String> namesArrayAsList = List.of(namesArray);
Set<String> namesArrayAsSet = Set.of(namesArray);
```

# 120 按列表过滤集合

我们在应用中遇到的一个常见问题是用一个`List`来过滤一个`Collection`。主要是从一个巨大的`Collection`开始，我们想从中提取与`List`元素匹配的元素。

在下面的例子中，让我们考虑一下`Melon`类：

```java
public class Melon {

  private final String type;
  private final int weight;

  // constructor, getters, equals(), hashCode(),
  // toString() omitted for brevity
}
```

这里，我们有一个巨大的`Collection`（在本例中，是一个`ArrayList Melon`：

```java
List<Melon> melons = new ArrayList<>();
melons.add(new Melon("Apollo", 3000));
melons.add(new Melon("Jade Dew", 3500));
melons.add(new Melon("Cantaloupe", 1500));
melons.add(new Melon("Gac", 1600));
melons.add(new Melon("Hami", 1400));
...
```

我们还有一个`List`，包含我们想从前面`ArrayList`中提取的瓜的类型：

```java
List<String> melonsByType 
  = Arrays.asList("Apollo", "Gac", "Crenshaw", "Hami");
```

这个问题的一个解决方案可能涉及循环收集和比较瓜的类型，但是生成的代码会非常慢。这个问题的另一个解决方案可能涉及到`List.contains()`方法和 Lambda 表达式：

```java
List<Melon> results = melons.stream()
  .filter(t -> melonsByType.contains(t.getType()))
  .collect(Collectors.toList());
```

代码紧凑，速度快。在幕后，`List.contains()`依赖于以下检查：

```java
// size - the size of melonsByType
// o - the current element to search from melons
// elementData - melonsByType
for (int i = 0; i < size; i++)
  if (o.equals(elementData[i])) {
    return i;
  }
}
```

然而，我们可以通过依赖于`HashSet.contains()`而不是`List.contains()`的解决方案来提高性能。当`List.contains()`使用前面的`for`语句来匹配元素时，`HashSet.contains()`使用`Map.containsKey()`。`Set`主要是基于`Map`实现的，每个增加的元素映射为`element`－`PRESENT`类型的键值。所以，`element`是这个`Map`中的一个键，`PRESENT`只是一个伪值。

当我们调用`HashSet.contains(element)`时，实际上我们调用`Map.containsKey(element)`。该方法基于给定元素的`hashCode()`，将给定元素与映射中的适当键进行匹配，比`equals()`快得多。

一旦我们将初始的`ArrayList`转换成`HashSet`，我们就可以开始了：

```java
Set<String> melonsSetByType = melonsByType.stream()
  .collect(Collectors.toSet());

List<Melon> results = melons.stream()
  .filter(t -> melonsSetByType.contains(t.getType()))
  .collect(Collectors.toList());
```

嗯，这个解决方案比上一个快。它的运行时间应该是上一个解决方案所需时间的一半。

# 121 替换列表的元素

我们在应用中遇到的另一个常见问题是替换符合特定条件的`List`元素。

在下面的示例中，让我们考虑一下`Melon`类：

```java
public class Melon {

  private final String type;
  private final int weight;

  // constructor, getters, equals(), hashCode(),
  // toString() omitted for brevity
}
```

然后，让我们考虑一下`Melon`的`List`：

```java
List<Melon> melons = new ArrayList<>();

melons.add(new Melon("Apollo", 3000));
melons.add(new Melon("Jade Dew", 3500));
melons.add(new Melon("Cantaloupe", 1500));
melons.add(new Melon("Gac", 1600));
melons.add(new Melon("Hami", 1400));
```

让我们假设我们想把所有重量在 3000 克以下的西瓜换成其他同类型、重 3000 克的西瓜。

解决这个问题的方法是迭代`List`，然后使用`List.set(int index, E element)`相应地替换瓜。

下面是一段意大利面代码：

```java
for (int i = 0; i < melons.size(); i++) {

  if (melons.get(i).getWeight() < 3000) {

    melons.set(i, new Melon(melons.get(i).getType(), 3000));
  }
}
```

另一种解决方案依赖于 Java8 函数式风格，或者更准确地说，依赖于`UnaryOperator`函数式接口。

基于此函数式接口，我们可以编写以下运算符：

```java
UnaryOperator<Melon> operator = t 
  -> (t.getWeight() < 3000) ? new Melon(t.getType(), 3000) : t;
```

现在，我们可以使用 JDK8，`List.replaceAll(UnaryOperator<E> operator)`，如下所示：

```java
melons.replaceAll(operator);
```

两种方法的性能应该几乎相同。

# 122 线程安全的集合、栈和队列

每当集合/栈/队列容易被多个线程访问时，它也容易出现特定于并发的异常（例如，`java.util.ConcurrentModificationException`。现在，让我们简要地概述一下 Java 内置的并发集合，并对其进行介绍。

# 并行集合

幸运的是，Java 为非线程安全集合（包括栈和队列）提供了线程安全（并发）的替代方案，如下所示。

# 线程安全列表

`ArrayList`的线程安全版本是`CopyOnWriteArrayList`。下表列出了 Java 内置的单线程和多线程列表：

| **单线程** | **多线程** |
| --- | --- |
| `ArrayList LinkedList` | `CopyOnWriteArrayList`（经常读取，很少更新）`Vector` |

`CopyOnWriteArrayList`实现保存数组中的元素。每次我们调用一个改变列表的方法（例如，`add()`、`set()`和`remove()`，Java 都会对这个数组的一个副本进行操作。

此集合上的`Iterator`将对集合的不可变副本进行操作。因此，可以修改原始集合而不会出现问题。在`Iterator`中看不到原始集合的潜在修改：

```java
List<Integer> list = new CopyOnWriteArrayList<>();
```

当读取频繁而更改很少时，请使用此集合。

# 线程安全集合

`Set`的线程安全版本是`CopyOnWriteArraySet`。下表列举了 Java 内置的单线程和多线程集：

| **单线程** | **多线程** |
| --- | --- |
| `HashSet TreeSet`（排序集）`LinkedHashSet`（维护插入顺序）`BitSet EnumSet` | `ConcurrentSkipListSet`（排序集）`CopyOnWriteArraySet`（经常读取，很少更新） |

这是一个`Set`，它的所有操作都使用一个内部`CopyOnWriteArrayList`。创建这样一个`Set`可以如下所示：

```java
Set<Integer> set = new CopyOnWriteArraySet<>();
```

当读取频繁而更改很少时，请使用此集合。

`NavigableSet`的线程安全版本是`ConcurrentSkipListSet`（并发`SortedSet`实现，最基本的操作在`O(log n)`中）。

# 线程安全映射

`Map`的线程安全版本是`ConcurrentHashMap`。

下表列举了 Java 内置的单线程和多线程映射：

| **单线程** | **多线程** |
| --- | --- |
| `HashMap TreeMap`（排序键）`LinkedHashMap`（维护插入顺序）`IdentityHashMap`（通过==比较按键）`WeakHashMap EnumMap` | `ConcurrentHashMap ConcurrentSkipListMap`（排序图）`Hashtable` |

`ConcurrentHashMap`允许无阻塞的检索操作（例如，`get()`）。这意味着检索操作可能与更新操作重叠（包括`put()`和`remove()`。

创建`ConcurrentHashMap`的步骤如下：

```java
ConcurrentMap<Integer, Integer> map = new ConcurrentHashMap<>();
```

当需要线程安全和高性能时，您可以依赖线程安全版本的`Map`，即`ConcurrentHashMap`。

避免`Hashtable`和`Collections.synchronizedMap()`，因为它们的性能较差。

对于支持`NavigableMap`的`ConcurrentMap`，操作依赖`ConcurrentSkipListMap`：

```java
ConcurrentNavigableMap<Integer, Integer> map 
  = new ConcurrentSkipListMap<>();
```

# 由数组支持的线程安全队列

Java 提供了一个**先进先出**（**FIFO**）的线程安全队列，由一个数组通过`ArrayBlockingQueue`支持。下表列出了由数组支持的单线程和多线程 Java 内置队列：

| **单线程** | **多线程** |
| --- | --- |
| `ArrayDeque PriorityQueue`（排序检索） | `ArrayBlockingQueue`（有界）`ConcurrentLinkedQueue`（无界）`ConcurrentLinkedDeque`（无界）`LinkedBlockingQueue`（可选有界）`LinkedBlockingDeque`（可选有界）`LinkedTransferQueue PriorityBlockingQueue SynchronousQueue DelayQueue Stack` |

`ArrayBlockingQueue`的容量在创建后不能更改。尝试将一个元素放入一个完整的队列将导致操作阻塞；尝试从一个空队列中获取一个元素也将导致类似的阻塞。

创建`ArrayBlockingQueue`很容易，如下所示：

```java
BlockingQueue<Integer> queue = new ArrayBlockingQueue<>(QUEUE_MAX_SIZE);
```

Java 还提供了两个线程安全的、可选的有界阻塞队列，它们基于通过`LinkedBlockingQueue`和`LinkedBlockingDeque`链接的节点（双向队列是一个线性集合，支持在两端插入和删除元素）。

# 基于链接节点的线程安全队列

Java 通过`ConcurrentLinkedDeque`/`ConcurrentLinkedQueue`提供了一个由链接节点支持的无边界线程安全队列/队列。这里是`ConcurrentLinkedDeque`：

```java
Deque<Integer> queue = new ConcurrentLinkedDeque<>();
```

# 线程安全优先级队列

Java 通过`PriorityBlockingQueue`提供了一个基于优先级堆的无边界线程安全优先级阻塞队列。

创建`PriorityBlockingQueue`很容易，如下所示：

```java
BlockingQueue<Integer> queue = new PriorityBlockingQueue<>();
```

非线程安全版本名为`PriorityQueue`。

# 线程安全延迟队列

Java 提供了一个线程安全的无界阻塞队列，在该队列中，只有当元素的延迟通过`DelayQueue`过期时，才能获取该元素。创建一个`DelayQueue`如下所示：

```java
BlockingQueue<TrainDelay> queue = new DelayQueue<>();
```

# 线程安全传输队列

Java 通过`LinkedTransferQueue`提供了基于链接节点的线程安全的无界传输队列。

这是一个 FIFO 队列，*头*是某个生产者在队列中停留时间最长的元素。队列的*尾*是某个生产者在队列中停留时间最短的元素。

创建此类队列的一种方法如下：

```java
TransferQueue<String> queue = new LinkedTransferQueue<>();
```

# 线程安全同步队列

Java 提供了一个阻塞队列，其中每个插入操作必须等待另一个线程执行相应的移除操作，反之亦然，通过`SynchronousQueue`：

```java
BlockingQueue<String> queue = new SynchronousQueue<>();
```

# 线程安全栈

栈的线程安全实现是`Stack`和`ConcurrentLinkedDeque`。

`Stack`类表示对象的**后进先出**（**LIFO**）栈。它通过几个操作扩展了`Vector`类，这些操作允许将向量视为栈。`Stack`的每一种方法都是同步的。创建一个`Stack`如下所示：

```java
Stack<Integer> stack = new Stack<>();
```

`ConcurrentLinkedDeque`实现可以通过其`push()`和`pop()`方法用作`Stack`（后进先出）：

```java
Deque<Integer> stack = new ConcurrentLinkedDeque<>();
```

为了获得更好的性能，请选择`ConcurrentLinkedDeque`而不是`Stack`。

绑定到本书中的代码为前面的每个集合提供了一个应用，用于跨越多个线程，以显示它们的线程安全特性。

# 同步的集合

除了并行集合，我们还有`synchronized`集合。Java 提供了一套包装器，将集合公开为线程安全的集合。这些包装在`Collections`中提供。最常见的有：

*   `synchronizedCollection​(Collection<T> c)`：返回由指定集合支持的同步（线程安全）集合
*   `synchronizedList​(List<T> list)`：返回指定列表支持的同步（线程安全）列表：

```java
List<Integer> syncList 
  = Collections.synchronizedList(new ArrayList<>());
```

*   `synchronizedMap​(Map<K,​V> m)`：返回指定映射支持的同步（线程安全）映射：

```java
Map<Integer, Integer> syncMap 
  = Collections.synchronizedMap(new HashMap<>());
```

*   `synchronizedSet​(Set<T> s)`：返回指定集支持的同步（线程安全）集：

```java
Set<Integer> syncSet 
  = Collections.synchronizedSet(new HashSet<>());
```

# 并发集合与同步集合

显而易见的问题是“并发集合和同步集合的区别是什么？”好吧，主要区别在于它们实现线程安全的方式。并发集合通过将数据划分为段来实现线程安全。线程可以并发地访问这些段，并且只能在所使用的段上获得锁。另一方面，同步集合通过*内部锁定*锁定整个集合（调用同步方法的线程将自动获取该方法对象的内在锁，并在方法返回时释放它）。

迭代同步的集合需要手动同步，如下所示：

```java
List syncList = Collections.synchronizedList(new ArrayList());
...
synchronized(syncList) {
  Iterator i = syncList.iterator();
  while (i.hasNext()) {
    // do_something_with i.next();
  }
}
```

由于并发集合允许线程的并发访问，因此它们的性能比同步集合高得多。

# 123 广度优先搜索

BFS 是遍历（访问）图或树的所有节点的经典算法。

理解这个算法最简单的方法是通过伪代码和一个例子。BFS 的伪码如下：

1.  *创建队列`Q`*
2.  *将`v`标记为已访问，并将`v`放入`Q`*
3.  *当`Q`为非空*
4.  *取下`Q`的头部`h`*
5.  *标记`h`的所有（未访问的）邻居并入队*

假设下图中的图，**步骤 0**：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-cd-prob/img/da9ace7a-fd80-4dc8-905a-278b00375fa2.png)

在第一步（**步骤 1**），我们访问顶点`0`。我们把它放在`visited`列表中，它的所有相邻顶点放在`queue`（3，1）中。此外，在**步骤 2** 中，我们访问`queue`、`3`前面的元素。顶点`3`在**步骤 2** 中有一个未访问的相邻顶点，所以我们将其添加到`queue`的后面。接下来，在**步骤 3** 中，我们访问`queue 1`前面的元素。该顶点有一个相邻的顶点（`0`），但该顶点已被访问。最后，我们访问顶点`2`，最后一个来自`queue`。这个有一个已经访问过的相邻顶点（`3`）。

在代码行中，BFS 算法可以实现如下：

```java
public class Graph {

  private final int v;
  private final LinkedList<Integer>[] adjacents;

  public Graph(int v) {

    this.v = v;
    adjacents = new LinkedList[v];

    for (int i = 0; i < v; ++i) {
      adjacents[i] = new LinkedList();
    }
  }

  public void addEdge(int v, int e) {
    adjacents[v].add(e);
  }

  public void BFS(int start) {

    boolean visited[] = new boolean[v];
    LinkedList<Integer> queue = new LinkedList<>();
    visited[start] = true;

    queue.add(start);

    while (!queue.isEmpty()) {
      start = queue.poll();
      System.out.print(start + " ");

      Iterator<Integer> i = adjacents[start].listIterator();
      while (i.hasNext()) {
        int n = i.next();
        if (!visited[n]) {
          visited[n] = true;
          queue.add(n);
        }
      }
    }
  }
}
```

并且，如果我们引入以下图表（从前面的图表），我们有如下：

```java
Graph graph = new Graph(4);
graph.addEdge(0, 3);
graph.addEdge(0, 1);
graph.addEdge(1, 0);
graph.addEdge(2, 3);
graph.addEdge(3, 0);
graph.addEdge(3, 2);
graph.addEdge(3, 3);
```

输出将为`0 3 1 2`。

# 124 Trie

Trie（也称为数字树）是一种有序的树结构，通常用于存储字符串。它的名字来源于 Trie 是 `reTrieval`数据结构。它的性能优于二叉树。

除 Trie 的根外，Trie 的每个节点都包含一个字符（例如，单词`hey`将有三个节点）。Trie 的每个节点主要包含以下内容：

*   值（字符或数字）
*   指向子节点的指针
*   如果当前节点完成一个字，则为`true`的标志
*   用于分支节点的单个根

下图表示构建包含单词`cat`、`caret`和`bye`的 Trie 的步骤顺序：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-cd-prob/img/04ad9477-0450-4037-82eb-690f9696f63b.png)

因此，在代码行中，Trie 节点的形状可以如下所示：

```java
public class Node {

  private final Map<Character, Node> children = new HashMap<>();
  private boolean word;

  Map<Character, Node> getChildren() {
    return children;
  }

  public boolean isWord() {
    return word;
  }

  public void setWord(boolean word) {
    this.word = word;
  }
}
```

基于这个类，我们可以定义一个 Trie 基本结构如下：

```java
class Trie {

  private final Node root;

  public Trie() {
    root = new Node();
  }

  public void insert(String word) {
    ...
  }

  public boolean contains(String word) {
    ...
  }

  public boolean delete(String word) {
    ...
  }
}
```

# 插入 Trie

现在，让我们关注在 Trie 中插入单词的算法：

1.  将当前节点视为根节点。
2.  从第一个字符开始，逐字符循环给定的单词。
3.  如果当前节点（`Map<Character, Node>`）为当前字符映射一个值（`Node`），那么只需前进到该节点。否则，新建一个`Node`，将其字符设置为当前字符，并前进到此节点。
4.  重复步骤 2（传递到下一个字符），直到单词的结尾。
5.  将当前节点标记为完成单词的节点。

在代码行方面，我们有以下内容：

```java
public void insert(String word) {

  Node node = root;

  for (int i = 0; i < word.length(); i++) {
    char ch = word.charAt(i);
    Function function = k -> new Node();

    node = node.getChildren().computeIfAbsent(ch, function);
  }

  node.setWord(true);
}
```

插入的复杂度为`O(n)`，其中`n`表示字长。

# 搜索 Trie

现在，让我们在 Trie 中搜索一个单词：

1.  将当前节点视为根节点。
2.  逐字符循环给定的单词（从第一个字符开始）。
3.  对于每个字符，检查其在 Trie 中的存在性（在`Map<Character, Node>`中）。
4.  如果字符不存在，则返回`false`。
5.  从第 2 步开始重复，直到单词结束。
6.  如果是单词，则在单词末尾返回`true`，如果只是前缀，则返回`false`。

在代码行方面，我们有以下内容：

```java
public boolean contains(String word) {

  Node node = root;

  for (int i = 0; i < word.length(); i++) {
    char ch = word.charAt(i);
    node = node.getChildren().get(ch);

    if (node == null) {
      return false;
    }
  }

  return node.isWord();
}
```

查找的复杂度为`O(n)`，其中`n`表示字长。

# 从 Trie 中删除

最后，让我们尝试从 Trie 中删除：

1.  验证给定的单词是否是 Trie 的一部分。
2.  如果它是 Trie 的一部分，那么只需移除它。

使用递归并遵循以下规则，以自下而上的方式进行删除：

*   如果给定的单词不在 Trie 中，那么什么也不会发生（返回`false`）
*   如果给定的单词是唯一的（不是另一个单词的一部分），则删除所有相应的节点（返回`true`）
*   如果给定的单词是 Trie 中另一个长单词的前缀，则将叶节点标志设置为`false`（返回`false`）
*   如果给定的单词至少有另一个单词作为前缀，则从给定单词的末尾删除相应的节点，直到最长前缀单词的第一个叶节点（返回`false`）

在代码行方面，我们有以下内容：

```java
public boolean delete(String word) {
  return delete(root, word, 0);
}

private boolean delete(Node node, String word, int position) {

  if (word.length() == position) {
    if (!node.isWord()) {
      return false;
    }

    node.setWord(false);

    return node.getChildren().isEmpty();
  }

  char ch = word.charAt(position);
  Node children = node.getChildren().get(ch);

  if (children == null) {
    return false;
  }

  boolean deleteChildren = delete(children, word, position + 1);

  if (deleteChildren && !children.isWord()) {
    node.getChildren().remove(ch);

    return node.getChildren().isEmpty();
  }

  return false;
}
```

查找的复杂度为`O(n)`，其中`n`表示字长。

现在，我们可以构建一个 Trie，如下所示：

```java
Trie trie = new Trie();
trie.insert/contains/delete(...);
```

# 125 元组

基本上，元组是由多个部分组成的数据结构。通常，元组有两到三个部分。通常，当需要三个以上的部分时，一个专用类是更好的选择。

元组是不可变的，每当我们需要从一个方法返回多个结果时就使用元组。例如，假设有一个方法返回数组的最小值和最大值。通常，一个方法不能同时返回这两个值，使用元组是一个方便的解决方案。

不幸的是，Java 不提供内置元组支持。然而，Java 附带了`Map.Entry<K,​V>`，用于表示来自`Map`的条目。此外，从 JDK9 开始，`Map`接口被一个名为`entry(K k, V v)`的方法丰富，该方法返回一个包含给定键和值的不可修改的`Map.Entry<K, V>`。

对于一个由两部分组成的元组，我们可以编写如下方法：

```java
public static <T> Map.Entry<T, T> array(
    T[] arr, Comparator<? super T> c) {

  T min = arr[0];
  T max = arr[0];

  for (T elem: arr) {
    if (c.compare(min, elem) > 0) {
      min = elem;
    } else if (c.compare(max, elem)<0) {
      max = elem;
    }
  }

  return entry(min, max);
}
```

如果这个方法存在于一个名为`Bounds`的类中，那么我们可以如下调用它：

```java
public class Melon {

  private final String type;
  private final int weight;

  // constructor, getters, equals(), hashCode(),
  // toString() omitted for brevity
}

Melon[] melons = {
  new Melon("Crenshaw", 2000), new Melon("Gac", 1200),
  new Melon("Bitter", 2200), new Melon("Hami", 800)
};

Comparator<Melon> byWeight = Comparator.comparing(Melon::getWeight);
Map.Entry<Melon, Melon> minmax = Bounds.array(melons, byWeight);

System.out.println("Min: " + minmax1.getKey());   // Hami(800g)
System.out.println("Max: " + minmax1.getValue()); // Bitter(2200g)
```

但我们也可以编写一个实现。一个由两部分组成的元组通常被称为一个*对*；因此，一个直观的实现可以如下所示：

```java
public final class Pair<L, R> {

  final L left;
  final R right;

  public Pair(L left, R right) {
    this.left = left;
    this.right = right;
  }

  static <L, R> Pair<L, R> of (L left, R right) {

    return new Pair<>(left, right);
  }

  // equals() and hashCode() omitted for brevity
}
```

现在，我们可以重写计算最小值和最大值的方法，如下所示：

```java
public static <T> Pair<T, T> array(T[] arr, Comparator<? super T> c) {
  ...
  return Pair.of(min, max);
}
```

# 126 并查集

并查算法在*不相交集*数据结构上运行。

不相交的集合数据结构定义了在某些不相交的子集中分离的元素集合，这些子集是不重叠的。从图形上看，我们可以用三个子集表示不相交集，如下图所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-cd-prob/img/15039898-6c0a-4ebd-9eb9-c4daef5aecf0.png)

在代码中，不相交集表示为：

*   `n`是元素的总数（例如，在上图中，`n`是 11）。
*   `rank`是一个用 0 初始化的数组，用于决定如何合并两个具有多个元素的子集（具有较低`rank`的子集成为具有较高`rank`的子集的子子集）。
*   `parent`是允许我们构建基于数组的并查的数组（最初为`parent[0] = 0; parent[1] = 1; ... parent[10] = 10;`）：

```java
public DisjointSet(int n) {

  this.n = n;
  rank = new int[n];
  parent = new int[n];

  initializeDisjointSet();
}
```

并查算法主要应具备以下功能：

*   将两个子集合并为一个子集
*   返回给定元素的子集（这对于查找同一子集中的元素很有用）

为了在内存中存储不相交的集合数据结构，我们可以将它表示为一个数组。最初，在数组的每个索引处，我们存储该索引（`x[i] = i`。每个索引可以映射到一段对我们有意义的信息，但这不是强制性的。例如，这样一个数组的形状可以如下图所示（最初，我们有 11 个子集，每个元素都是它自己的父元素）：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-cd-prob/img/ba9b8954-73d6-4bd1-985d-c0440bd7f127.png)

或者，如果我们使用数字，我们可以用下图来表示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-cd-prob/img/e9d26d14-2c11-448e-941f-e158edd1947c.png)

在代码行方面，我们有以下内容：

```java
private void initializeDisjointSet() {

  for (int i = 0; i < n; i++) {
    parent[i] = i;
  }
}
```

此外，我们需要通过*并集*操作来定义我们的子集。我们可以通过（*父*、*子*对）序列来定义子集。例如，让我们定义以下三对-`union(0,1);`、`union(4, 9);`和`union(6, 5);`。每次一个元素（子集）成为另一个元素（子集）的子元素时，它都会修改其值以反映其父元素的值，如下图所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-cd-prob/img/342345bb-564b-4498-bcb6-e65203a4656c.png)

这个过程一直持续到我们定义了所有的子集。例如，我们可以添加更多的联合-`union(0, 7);`、`union(4, 3);`、`union(4, 2);`、`union(6, 10);`和`union(4, 5);`。这将产生以下图形表示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-cd-prob/img/d2d1886f-9742-4158-840f-501262d12031.png)

根据经验，建议将较小的子集合并为较大的子集，反之亦然。例如，检查包含`4`的子集与包含`5`的子集相统一的时刻。此时，`4`是子集的父项，它有三个子项（`2`、`3`、`9`），而`5`紧挨着`10`，`6`的两个子项。因此，包含`5`的子集有三个节点（`6`、`5`、`10`），而包含`4`的子集有四个节点（`4`、`2`、`3`、`9`）。因此，`4`成为`6`的父，并且隐含地成为`5`的父。

在代码行中，这是`rank[]`数组的工作：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-cd-prob/img/314916a2-237a-4366-a08f-3b9f73abdbb3.png)

现在让我们看看如何实现`find`和`union`操作

# 实现查找操作

查找给定元素的子集是一个递归过程，通过跟随父元素遍历子集，直到当前元素是其自身的父元素（根元素）：

```java
public int find(int x) {

  if (parent[x] == x) {
    return x;
  } else {
    return find(parent[x]);
  }
}
```

# 实现并集操作

*并集*操作首先获取给定子集的根元素。此外，如果这两个根是不同的，它们需要依赖于它们的秩来决定哪一个将成为另一个的父（较大的秩将成为父）。如果它们的等级相同，则选择其中一个并将其等级增加 1：

```java
public void union(int x, int y) {

  int xRoot = find(x);
  int yRoot = find(y);

  if (xRoot == yRoot) {
    return;
  }

  if (rank[xRoot] < rank[yRoot]) {
    parent[xRoot] = yRoot;
  } else if (rank[yRoot] < rank[xRoot]) {
    parent[yRoot] = xRoot;
  } else {
    parent[yRoot] = xRoot;
    rank[xRoot]++;
  }
}
```

好吧。现在让我们定义一个不相交集：

```java
DisjointSet set = new DisjointSet(11);
set.union(0, 1);
set.union(4, 9);
set.union(6, 5);
set.union(0, 7);
set.union(4, 3);
set.union(4, 2);
set.union(6, 10);
set.union(4, 5);
```

现在让我们来玩玩它：

```java
// is 4 and 0 friends => false
System.out.println("Is 4 and 0 friends: " 
  + (set.find(0) == set.find(4)));

// is 4 and 5 friends => true
System.out.println("Is 4 and 5 friends: " 
  + (set.find(4) == set.find(5)));
```

该算法可以通过压缩元素间的路径来优化。例如，检查下图：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-cd-prob/img/4cf68dd2-b2c2-40bf-baae-969b28f3f902.png)

在左侧，在寻找`5`的父代时，必须经过`6`直到`4`。同样，在寻找`10`的父代时，必须经过`6`，直到`4`为止。然而，在右侧，我们通过直接链接到`4`来压缩`5`和`10`的路径。这一次，我们不需要通过中间元素就可以找到`5`和`10`的父代。

路径压缩可以针对`find()`操作进行，如下所示：

```java
public int find(int x) {

  if (parent[x] != x) {
    return parent[x] = find(parent[x]);
  }

  return parent[x];
}
```

捆绑到本书中的代码包含两个应用，有路径压缩和没有路径压缩。

# 127 Fenwick 树或二叉索引树

**芬威克树**（**FT**）或**二叉索引树**（**BIT**）是为存储对应于另一给定数组的和而构建的数组。构建数组的大小与给定数组的大小相同，并且构建数组的每个位置（或节点）都存储给定数组中某些元素的总和。由于 BIT 存储给定数组的部分和，因此通过避免索引之间的循环和计算和，它是计算给定数组中两个给定索引（范围和/查询）之间的元素和的非常有效的解决方案。

位可以在线性时间或`O(n log n)`中构造。显然，我们更喜欢线性时间，所以让我们看看如何做到这一点。我们从给定的（原始）数组开始，该数组可以是（下标表示数组中的索引）：

```java
3(1), 1(2), 5(3), 8(4), 12(5), 9(6), 7(7), 13(8), 0(9), 3(10), 1(11), 4(12), 9(13), 0(14), 11(15), 5(16)
```

构建位的想法依赖于**最低有效位**（**LSB**)概念。更准确地说，假设我们正在处理索引中的元素，`a`。那么，紧靠我们上方的值必须位于索引`b`，其中`b = a + LSB(a)`。为了应用该算法，索引 0 的值必须是 0；因此，我们操作的数组如下：

```java
0(0), 3(1), 1(2), 5(3), 8(4), 12(5), 9(6), 7(7), 13(8), 0(9), 3(10), 1(11), 4(12), 9(13), 0(14), 11(15), 5(16)
```

现在，让我们应用算法的几个步骤，用和填充位。在位的索引 0 处，我们有 0。此外，我们使用`b = a + LSB(a)`公式计算剩余和，如下所示：

1.  `a=1`：如果`a=1=0b00001`，则`b=0b00001+0b00001=1+1=2=0b00010`。我们说 2 负责`a`（也就是 1）。因此，在位中，在索引 1 处，我们存储值 3，在索引 2 处，我们存储值的和，`3+1=4`。
2.  `a=2`：如果`a=2=0b00010`，则`b=0b00010+0b00010=2+2=4=0b00100`。我们说 4 负责`a`（即 2）。因此，在索引 4 处，我们以位的形式存储值的和，`8+4=12`。
3.  `a=3`：如果`a=3=0b00011`，则`b=0b00011+0b00001=3+1=4=0b00100`。我们说 4 负责`a`（也就是 3）。因此，在位中，在索引 4 处，我们存储值的和，`12+5=17`。
4.  `a=4`。如果`a=4=0b00100`，则`b=0b00100+0b00100=4+4=8=0b01000`。我们说 8 负责`a`（也就是 4）。因此，在位中，在索引 8 处，我们存储值的和，`13+17=30`。

算法将以相同的方式继续，直到位完成。在图形表示中，我们的案例可以如下所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-cd-prob/img/73588a84-ac0f-4c97-9916-e907a74b3f2d.png)

如果索引的计算点超出了界限，那么只需忽略它。

在代码行中，前面的流的形状可以如下所示（值是给定的数组）：

```java
public class FenwickTree {

  private final int n;
  private long[] tree;
  ...

  public FenwickTree(long[] values) {

    values[0] = 0 L;
    this.n = values.length;
    tree = values.clone();

    for (int i = 1; i < n; i++) {

      int parent = i + lsb(i);
      if (parent < n) {
        tree[parent] += tree[i];
      }
    }
  }

  private static int lsb(int i) {

      return i & -i;

      // or
      // return Integer.lowestOneBit(i);
    }

    ...
}
```

现在，位准备好了，我们可以执行更新和范围查询。

例如，为了执行范围求和，我们必须获取相应的范围并将它们相加。请考虑下图右侧的几个示例，以快速了解此过程：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-cd-prob/img/0fa4928e-5819-457a-85b5-7c438cc46019.png)

就代码行而言，这可以很容易地形成如下形状：

```java
public long sum(int left, int right) {

  return prefixSum(right) - prefixSum(left - 1);
}

private long prefixSum(int i) {

  long sum = 0L;

  while (i != 0) {
    sum += tree[i];
    i &= ~lsb(i); // or, i -= lsb(i);
  }

  return sum;
}
```

此外，我们还可以增加一个新的值：

```java
public void add(int i, long v) {

  while (i < n) {
    tree[i] += v;
    i += lsb(i);
  }
}
```

我们还可以为某个索引设置一个新值：

```java
public void set(int i, long v) {
  add(i, v - sum(i, i));
}
```

具备所有这些功能后，我们可以按如下方式为数组创建位：

```java
FenwickTree tree = new FenwickTree(new long[] {
  0, 3, 1, 5, 8, 12, 9, 7, 13, 0, 3, 1, 4, 9, 0, 11, 5
});
```

然后我们可以玩它：

```java
long sum29 = tree.sum(2, 9); // 55
tree.set(4, 3);
tree.add(4, 5);
```

# 128 布隆过滤器

布隆过滤器是一种快速高效的数据结构，能够提供问题的概率答案“值 X 在给定的集合中吗？”

通常情况下，当集合很大且大多数搜索算法都面临内存和速度问题时，此算法非常有用。

布隆过滤器的速度和内存效率来自这样一个事实，即该数据结构依赖于位数组（例如，`java.util.BitSet`）。最初，该数组的位被设置为`0`或`false`。

比特数组是布隆过滤器的第一个主要组成部分。第二个主要成分由一个或多个哈希函数组成。理想情况下，这些是*成对独立的*和*均匀分布的*散列函数。另外，非常重要的是要非常快。murrur、`fnv`系列和`HashMix`是一些散列函数，它们在布鲁姆过滤器可以接受的范围内遵守这些约束。

现在，当我们向布隆过滤器添加一个元素时，我们需要对这个元素进行散列（通过每个可用的散列函数传递它），并将这些散列的索引处的位数组中的位设置为`1`或`true`。

下面的代码片段应该可以阐明主要思想：

```java
private BitSet bitset; // the array of bits
private static final Charset CHARSET = StandardCharsets.UTF_8;
...
public void add(T element) {

  add(element.toString().getBytes(CHARSET));
}

public void add(byte[] bytes) {

  int[] hashes = hash(bytes, numberOfHashFunctions);

  for (int hash: hashes) {
    bitset.set(Math.abs(hash % bitSetSize), true);
  }

  numberOfAddedElements++;
}
```

现在，当我们搜索一个元素时，我们通过相同的散列函数传递这个元素。此外，我们检查结果值是否在位数组中标记为`1`或`true`。如果不是，那么元素肯定不在集合中。但如果它们是，那么我们就以一定的概率知道元素在集合中。这不是 100% 确定的，因为另一个元素或元素的组合可能已经翻转了这些位。错误答案称为*假正例*。

在代码行方面，我们有以下内容：

```java
private BitSet bitset; // the array of bits
private static final Charset CHARSET = StandardCharsets.UTF_8;
...

public boolean contains(T element) {

  return contains(element.toString().getBytes(CHARSET));
}

public boolean contains(byte[] bytes) {

  int[] hashes = hash(bytes, numberOfHashFunctions);

  for (int hash: hashes) {
    if (!bitset.get(Math.abs(hash % bitSetSize))) {

      return false;
    }
  }

  return true;
}
```

在图形表示中，我们可以用大小为 11 的位数组和三个哈希函数来表示布隆过滤器，如下所示（我们添加了两个元素）：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-cd-prob/img/98ef7cb6-4c89-4d32-a26f-564448fffb33.png)

显然，我们希望尽可能减少*假正例*的数量。虽然我们不能完全消除它们，但我们仍然可以通过调整位数组的大小、哈希函数的数量和集合中元素的数量来影响它们的速率。

以下数学公式可用于塑造最佳布隆过滤器：

*   过滤器中的项数（可根据`m`、`k`、`p`估计）：

`n = ceil(m / (-k / log(1 - exp(log(p) / k))));`

*   *假正例*的概率，介于 0 和 1 之间的分数，或表示`p`中的 1 的数量：

`p = pow(1 - exp(-k / (m / n)), k);`

*   过滤器中的位数（或按 KB、KiB、MB、MB、GiB 等表示的大小）：

`m = ceil((n * log(p)) / log(1 / pow(2, log(2))));`

*   散列函数个数（可根据`m`和`n`估计）：

`k = round((m / n) * log(2));`

根据经验，一个较大的过滤器比一个较小的过滤器具有更少的*假正例*。此外，通过增加散列函数的数量，我们可以获得较少的*假正例*，但我们会减慢过滤器的速度，并将其快速填充。布隆过滤器的性能为`O(h)`，其中`h`是散列函数的个数。

在本书附带的代码中，有一个布隆过滤器的实现，它使用基于 SHA-256 和 murrur 的散列函数。由于这段代码太大，无法在本书中列出，因此请考虑将`Main`类中的示例作为起点。

# 总结

本章涵盖了涉及数组、集合和几个数据结构的 30 个问题。虽然涉及数组和集合的问题是日常工作的一部分，但涉及数据结构的问题引入了一些不太知名（但功能强大）的数据结构，如并查集和 Trie。

从本章下载应用以查看结果并检查其他详细信息。**
