# Java 编程问题（二）

> 原文：[Java Coding Problems](https://libgen.rs/book/index.php?md5=3280024C263466704C8F7525E5BB6AAE)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 二、对象、不变性和`switch`表达式

> 原文：[Java Coding Problems](https://libgen.rs/book/index.php?md5=3280024C263466704C8F7525E5BB6AAE)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)
> 
> 贡献者：[飞龙](https://github.com/wizardforcel)
> 
> 本文来自[【ApacheCN Java 译文集】](https://github.com/apachecn/apachecn-java-zh)，自豪地采用[谷歌翻译](https://translate.google.cn/)。

本章包括 18 个涉及对象、不变性和`switch`表达式的问题。本章从处理`null`引用的几个问题入手。它继续处理有关检查索引、`equals()`和`hashCode()`以及不变性（例如，编写不可变类和从不可变类传递/返回可变对象）的问题。本章的最后一部分讨论了克隆对象和 JDK12`switch`表达式。本章结束时，您将掌握对象和不变性的基本知识。此外，你将知道如何处理新的`switch`表达式。在任何 Java 开发人员的武库中，这些都是有价值的、非可选的知识。

# 问题

使用以下问题来测试您的对象、不变性和`switch`表达式编程能力。我强烈建议您在转向解决方案和下载示例程序之前，尝试一下每个问题：

40.  使用**命令式**代码检查`null`函数式引用：编写程序，对给定的函数式引用和命令式代码进行`null`检查。
41.  检查`null`引用并抛出一个定制的`NullPointerException`错误：编写一个程序，对给定的引用执行`null`检查并抛出带有定制消息的`NullPointerException`。
42.  检查`null`引用并抛出指定的异常（例如，`IllegalArgumentException`：编写一个程序，对给定的引用执行`null`检查并抛出指定的异常。
43.  检查`null`引用并返回非`null`默认引用：编写程序，对给定引用执行`null`检查，如果是非`null`，则返回；否则返回非`null`默认引用。
44.  检查从 0 到长度范围内的索引：编写一个程序，检查给定索引是否在 0（含）到给定长度（不含）之间。如果给定索引超出 0 到给定长度的范围，则抛出`IndexOutOfBoundsException`。   
45.  检查从 0 到长度范围内的子范围：编写一个程序，检查给定的开始到给定的结束的给定的子范围，是否在 0 到给定的长度的范围内。如果给定的子范围不在范围内，则抛出`IndexOutOfBoundsException`。
46.  解释`equals()`和`hashCode()`并举例说明`equals()`和`hashCode()`方法在 Java 中是如何工作的。
46.  不可变对象概述：解释并举例说明什么是 Java 中的不可变对象。
47.  不可变字符串：解释`String`类不可变的原因。   
48.  编写不可变类：写一个表示不可变类的程序。
49.  向不可变类传递或从不可变类返回可变对象：编写一个程序，向不可变类传递或从不可变类返回可变对象。
50.  通过构建器模式编写一个不可变类：编写一个表示不可变类中构建器模式实现的程序。51.  避免不可变对象中的坏数据：编写防止不可变对象中的*坏数据*的程序。
52.  克隆对象：编写一个程序，演示浅层和深层克隆技术。
53.  覆盖`toString()`：解释并举例说明覆盖`toString()`的实践。
54.  `switch`表达式：简要概述 JDK12 中的`switch`表达式。
55.  多个`case`标签：写一段代码，用多个`case`标签举例说明 JDK12`switch`。
56.  语句块：编写一段代码，用于举例说明 JDK12 `switch`，其中的`case`标签指向花括号块。

以下各节介绍上述每个问题的解决方案。记住，通常没有一个正确的方法来解决一个特定的问题。另外，请记住，这里显示的解释仅包括解决问题所需的最有趣和最重要的细节。下载示例解决方案以查看更多详细信息，并[尝试程序](https://github.com/PacktPublishing/Java-Coding-Problems)。

# 40 在函数式和命令式代码中检查空引用

与函数样式或命令式代码无关，检查`null`引用是一种常用且推荐的技术，用于减少著名的`NullPointerException`异常的发生。这种检查被大量用于方法参数，以确保传递的引用不会导致`NullPointerException`或意外行为。

例如，将`List<Integer>`传递给方法可能需要至少两个`null`检查。首先，该方法应该确保列表引用本身不是`null`。其次，根据列表的使用方式，该方法应确保列表不包含`null`对象：

```java
List<Integer> numbers 
  = Arrays.asList(1, 2, null, 4, null, 16, 7, null);
```

此列表将传递给以下方法：

```java
public static List<Integer> evenIntegers(List<Integer> integers) {

  if (integers == null) {
    return Collections.EMPTY_LIST;
  }

  List<Integer> evens = new ArrayList<>();
  for (Integer nr: integers) {
    if (nr != null && nr % 2 == 0) {
      evens.add(nr);
    }
  }

  return evens;
}
```

注意，前面的代码使用依赖于`==`和`!=`运算符（`integers==null`、`nr !=null`的经典检查。从 JDK8 开始，`java.util.Objects`类包含两个方法，它们基于这两个操作符包装`null`检查：`object == null`包装在`Objects.isNull()`中，`object != null`包装在`Objects.nonNull()`中。

基于这些方法，前面的代码可以重写如下：

```java
public static List<Integer> evenIntegers(List<Integer> integers) {

  if (Objects.isNull(integers)) {
    return Collections.EMPTY_LIST;
  }

  List<Integer> evens = new ArrayList<>();

  for (Integer nr: integers) {
    if (Objects.nonNull(nr) && nr % 2 == 0) {
      evens.add(nr);
    }
  }

  return evens;
}
```

现在，代码在某种程度上更具表现力，但这并不是这两种方法的主要用法。实际上，这两个方法是为了另一个目的（符合 API 注解）而添加的——在 Java8 函数式代码中用作谓词。在函数式代码中，`null`检查可以如下例所示完成：

```java
public static int sumIntegers(List<Integer> integers) {

  if (integers == null) {
    throw new IllegalArgumentException("List cannot be null");
  }

  return integers.stream()
    .filter(i -> i != null)
    .mapToInt(Integer::intValue).sum();
}

public static boolean integersContainsNulls(List<Integer> integers) {

  if (integers == null) {
    return false;
  }

  return integers.stream()
    .anyMatch(i -> i == null);
}
```

很明显，`i -> i != null`和`i -> i == null`的表达方式与周围的代码不一样。让我们用`Objects.nonNull()`和`Objects.isNull()`替换这些代码片段：

```java
public static int sumIntegers(List<Integer> integers) {

  if (integers == null) {
    throw new IllegalArgumentException("List cannot be null");
  }

  return integers.stream()
    .filter(Objects::nonNull)
    .mapToInt(Integer::intValue).sum();
}

public static boolean integersContainsNulls(List<Integer> integers) {

  if (integers == null) {
    return false;
  }

  return integers.stream()
    .anyMatch(Objects::isNull);
}
```

或者，我们也可以使用`Objects.nonNull()`和`Objects.isNull()`方法作为参数：

```java
public static int sumIntegers(List<Integer> integers) {

  if (Objects.isNull(integers)) {
    throw new IllegalArgumentException("List cannot be null");
  }

  return integers.stream()
    .filter(Objects::nonNull)
    .mapToInt(Integer::intValue).sum();
}

public static boolean integersContainsNulls(List<Integer> integers) {

  if (Objects.isNull(integers)) {
    return false;
  }

  return integers.stream()
    .anyMatch(Objects::isNull);
}
```

令人惊叹的！因此，作为结论，无论何时需要进行`null`检查，函数式代码都应该依赖于这两种方法，而在命令式代码中，这是一种偏好。

# 41 检查空引用并引发自定义的`NullPointerException`

检查`null`引用并用定制消息抛出`NullPointerException`可以使用以下代码完成（此代码执行这四次，在构造器中执行两次，在`assignDriver()`方法中执行两次）：

```java
public class Car {

  private final String name;
  private final Color color;

  public Car(String name, Color color) {

    if (name == null) {
      throw new NullPointerException("Car name cannot be null");
    }

    if (color == null) {
      throw new NullPointerException("Car color cannot be null");
    }

    this.name = name;
    this.color = color;
  }

  public void assignDriver(String license, Point location) {

    if (license == null) {
      throw new NullPointerException("License cannot be null");
    }

    if (location == null) {
      throw new NullPointerException("Location cannot be null");
    }
  }
}
```

因此，这段代码通过结合`==`操作符和`NullPointerException`类的手动实例化来解决这个问题。从 JDK7 开始，这种代码组合隐藏在一个名为`Objects.requireNonNull()`的`static`方法中。通过这种方法，前面的代码可以用表达的方式重写：

```java
public class Car {

  private final String name;
  private final Color color;

  public Car(String name, Color color) {

    this.name = Objects.requireNonNull(name, "Car name cannot be 
      null");
    this.color = Objects.requireNonNull(color, "Car color cannot be 
      null");
  }

  public void assignDriver(String license, Point location) {

    Objects.requireNonNull(license, "License cannot be null");
    Objects.requireNonNull(location, "Location cannot be null");
  }
}
```

因此，如果指定的引用是`null`，那么`Objects.requireNonNull()`将抛出一个包含所提供消息的`NullPointerException`。否则，它将返回选中的引用。

在构造器中，当提供的引用是`null`时，有一种典型的抛出`NullPointerException`的方法。但在方法上（例如，`assignDriver()`），这是一个有争议的方法。一些开发人员更喜欢返回一个无害的结果或者抛出`IllegalArgumentException`。下一个问题，检查空引用并抛出指定的异常（例如，`IllegalArgumentException`），解决了`IllegalArgumentException`方法。

在 JDK7 中，有两个`Objects.requireNonNull()`方法，一个是以前使用的，另一个是抛出带有默认消息的`NullPointerException`，如下例所示：

```java
this.name = Objects.requireNonNull(name);
```

从 JDK8 开始，还有一个`Objects.requireNonNull()`。这个将`NullPointerException`的自定义消息封装在`Supplier`中。这意味着消息创建被推迟，直到给定的引用是`null`（这意味着使用`+`操作符连接消息的各个部分不再是一个问题）。

举个例子：

```java
this.name = Objects.requireNonNull(name, () 
  -> "Car name cannot be null ... Consider one from " + carsList);
```

如果此引用不是`null`，则不创建消息。

# 42 检查空引用并引发指定的异常

当然，一种解决方案需要直接依赖于`==`操作符，如下所示：

```java
if (name == null) {
  throw new IllegalArgumentException("Name cannot be null");
}
```

因为没有`requireNonNullElseThrow()`方法，所以这个问题不能用`java.util.Objects`的方法来解决。抛出`IllegalArgumentException`或其他指定的异常可能需要一组方法，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-cd-prob/img/fcd54997-7ebf-46d7-8eea-c80bb23be82a.png)

让我们关注一下`requireNonNullElseThrowIAE()`方法。这两个方法抛出`IllegalArgumentException`，其中一个自定义消息被指定为`String`或`Supplier`（在`null`被求值为`true`之前避免创建）：

```java
public static <T> T requireNonNullElseThrowIAE(
    T obj, String message) {

  if (obj == null) {
    throw new IllegalArgumentException(message);
  }

  return obj;
}

public static <T> T requireNonNullElseThrowIAE(T obj,
    Supplier<String> messageSupplier) {

  if (obj == null) {
    throw new IllegalArgumentException(messageSupplier == null 
      ? null : messageSupplier.get());
  }

  return obj;
}
```

所以，投掷`IllegalArgumentException`可以通过这两种方法来完成。但这还不够。例如，代码可能需要抛出`IllegalStateException`、`UnsupportedOperationException`等。对于这种情况，最好采用以下方法：

```java
public static <T, X extends Throwable> T requireNonNullElseThrow(
    T obj, X exception) throws X {

  if (obj == null) {
    throw exception;
  }

  return obj;
}

public static <T, X extends Throwable> T requireNotNullElseThrow(
    T obj, Supplier<<? extends X> exceptionSupplier) throws X {

  if (obj != null) {
    return obj;
  } else {
    throw exceptionSupplier.get();
  }
}
```

考虑将这些方法添加到名为`MyObjects`的助手类中。如以下示例所示调用这些方法：

```java
public Car(String name, Color color) {

  this.name = MyObjects.requireNonNullElseThrow(name,
    new UnsupportedOperationException("Name cannot be set as null"));
  this.color = MyObjects.requireNotNullElseThrow(color, () ->
    new UnsupportedOperationException("Color cannot be set as null"));
}
```

此外，我们也可以通过这些例子来丰富`MyObjects`中的其他异常。

# 43 检查空引用并返回非空默认引用

通过`if`-`else`（或三元运算符）可以很容易地提供该问题的解决方案，如以下示例所示（作为变体，`name`和`color`可以声明为非`final`，并在声明时用默认值初始化）：

```java
public class Car {

  private final String name;
  private final Color color;
  public Car(String name, Color color) {

    if (name == null) {
      this.name = "No name";
    } else {
      this.name = name;
    }

    if (color == null) {
      this.color = new Color(0, 0, 0);
    } else {
      this.color = color;
    }
  }
}
```

但是，从 JDK9 开始，前面的代码可以通过`Objects`类的两个方法简化。这些方法是`requireNonNullElse()`和`requireNonNullElseGet()`。它们都有两个参数，一个是检查空值的引用，另一个是在检查的引用为`null`时返回的非`null`默认引用：

```java
public class Car {

  private final String name;
  private final Color color;

  public Car(String name, Color color) {

    this.name = Objects.requireNonNullElse(name, "No name");
    this.color = Objects.requireNonNullElseGet(color,
      () -> new Color(0, 0, 0));
  }
}
```

在前面的示例中，这些方法在构造器中使用，但也可以在方法中使用。

# 44 检查从 0 到长度范围内的索引

首先，让我们用一个简单的场景来突出这个问题。此场景可能在以下简单类中实现：

```java
public class Function {

  private final int x;

  public Function(int x) {

    this.x = x;
  }

  public int xMinusY(int y) {

    return x - y;
  }

  public static int oneMinusY(int y) {

    return 1 - y;
  }
}
```

注意，前面的代码片段没有对`x`和`y`进行任何范围限制。现在，让我们施加以下范围（这在数学函数中非常常见）：

*   `x`必须介于 0（含）和 11（不含）之间，所以`x`属于`[0, 11)`。
*   在`xMinusY()`方法中，`y`必须在 0（含）`x`（不含）之间，所以`y`属于`[0, x)`。
*   在`oneMinusY()`方法中，`y`必须介于 0（包含）和 16（排除）之间，所以`y`属于`[0, 16)`。

这些范围可以通过`if`语句在代码中施加，如下所示：

```java
public class Function {

  private static final int X_UPPER_BOUND = 11;
  private static final int Y_UPPER_BOUND = 16;
  private final int x;

  public Function(int x) {

    if (x < 0 || x >= X_UPPER_BOUND) {
      throw new IndexOutOfBoundsException("..."); 
    }

    this.x = x;
  }

  public int xMinusY(int y) {

    if (y < 0 || y >= x) {
      throw new IndexOutOfBoundsException("...");
    }

    return x - y;
  }

  public static int oneMinusY(int y) {

    if (y < 0 || y >= Y_UPPER_BOUND) {
      throw new IndexOutOfBoundsException("...");
    }

    return 1 - y;
  }
}
```

考虑用更有意义的异常替换`IndexOutOfBoundsException`（例如，扩展`IndexOutOfBoundsException`并创建一个类型为`RangeOutOfBoundsException`的自定义异常）。

从 JDK9 开始，可以重写代码以使用`Objects.checkIndex()`方法。此方法验证给定索引是否在 0 到长度的范围内，并返回该范围内的给定索引或抛出`IndexOutOfBoundsException`：

```java
public class Function {

  private static final int X_UPPER_BOUND = 11;
  private static final int Y_UPPER_BOUND = 16;
  private final int x;

  public Function(int x) {

    this.x = Objects.checkIndex(x, X_UPPER_BOUND);
  }

  public int xMinusY(int y) {

    Objects.checkIndex(y, x);

    return x - y;
  }

  public static int oneMinusY(int y) {

    Objects.checkIndex(y, Y_UPPER_BOUND);

    return 1 - y;
  }
}
```

例如，调用`oneMinusY()`，如下一个代码片段所示，将导致`IndexOutOfBoundsException`，因为`y`可以取`[0, 16]`之间的值：

```java
int result = Function.oneMinusY(20);
```

现在，让我们进一步检查从 0 到给定长度的子范围。

# 45 检查从 0 到长度范围内的子范围

让我们遵循上一个问题的相同流程。所以，这一次，`Function`类将如下所示：

```java
public class Function {

  private final int n;

  public Function(int n) {

    this.n = n;
  }

  public int yMinusX(int x, int y) {

    return y - x;
  }
}
```

注意，前面的代码片段没有对`x`、`y`和`n`进行任何范围限制。现在，让我们施加以下范围：

*   `n`必须介于 0（含）和 101（不含）之间，所以`n`属于`[0, 101]`。
*   在`yMinusX()`方法中，由`x`和`y`、`x`、`y`限定的范围必须是`[0, n]`的子范围。

这些范围可以通过`if`语句在代码中施加，如下所示：

```java
public class Function {

  private static final int N_UPPER_BOUND = 101;
  private final int n;

  public Function(int n) {

    if (n < 0 || n >= N_UPPER_BOUND) {
      throw new IndexOutOfBoundsException("...");
    }

    this.n = n;
  }

  public int yMinusX(int x, int y) {

    if (x < 0 || x > y || y >= n) {
      throw new IndexOutOfBoundsException("...");
    }

    return y - x;
  }
}
```

基于前面的问题，`n`的条件可以替换为`Objects.checkIndex()`。此外，JDK9`Objects`类还提供了一个名为`checkFromToIndex(int start, int end, int length)`的方法，该方法检查给定的子范围*给定的开始*、*给定的结束*是否在 0 到给定的长度的范围内。因此，此方法可应用于`yMinusX()`方法，以检查`x`与`y`所限定的范围是否为 0 到`n`的子范围：

```java
public class Function {

  private static final int N_UPPER_BOUND = 101;
  private final int n;

  public Function(int n) {

    this.n = Objects.checkIndex(n, N_UPPER_BOUND);
  }

  public int yMinusX(int x, int y) {

    Objects.checkFromToIndex(x, y, n);
    return y - x;
  }
}
```

例如，由于`x`大于`y`，下面的测试将导致`IndexOutOfBoundsException`：

```java
Function f = new Function(50);
int r = f.yMinusX(30, 20);
```

除了这个方法之外，`Objects`还有另一个名为`checkFromIndexSize(int start, int size, int length)`的方法。该方法检查*给定开始时间*到*给定开始时间加给定大小*的子范围，是否在 0 到*给定长度*的范围内。

# 46 `equals()`和`hashCode()`

`equals()`和`hashCode()`方法在`java.lang.Object`中定义。因为`Object`是所有 Java 对象的超类，所以这两种方法对所有对象都可用。他们的主要目标是为比较对象提供一个简单、高效、健壮的解决方案，并确定它们是否相等。如果没有这些方法和它们的契约，解决方案依赖于庞大而繁琐的`if`语句来比较对象的每个字段。

当这些方法没有被覆盖时，Java 将使用它们的默认实现。不幸的是，默认实现并不能真正实现确定两个对象是否具有相同值的目标。默认情况下，`equals()`检查*相等性*。换言之，当且仅当两个对象由相同的内存地址（相同的对象引用）表示时，它认为这两个对象相等，而`hashCode()`返回对象内存地址的整数表示。这是一个本机函数，称为*标识**哈希码。*

例如，假设以下类：

```java
public class Player {

  private int id;
  private String name;

  public Player(int id, String name) {

    this.id = id;
    this.name = name;
  }
}
```

然后，让我们创建包含相同信息的此类的两个实例，并比较它们是否相等：

```java
Player p1 = new Player(1, "Rafael Nadal");
Player p2 = new Player(1, "Rafael Nadal");

System.out.println(p1.equals(p2)); // false
System.out.println("p1 hash code: " + p1.hashCode()); // 1809787067
System.out.println("p2 hash code: " + p2.hashCode()); // 157627094
```

不要使用`==`运算符来测试对象的相等性（避免使用`if(p1 == p2)`。`==`操作符比较两个对象的引用是否指向同一个对象，而`equals()`比较对象值（作为人类，这是我们关心的）。

根据经验，如果两个变量拥有相同的引用，则它们*相同*，但是如果它们引用相同的值，则它们*相等*。*相同值*的含义由`equals()`定义。

对我们来说，`p1`和`p2`是相等的，但是请注意`equals()`返回了`false`（`p1`和`p2`实例的字段值完全相同，但是它们存储在不同的内存地址）。这意味着依赖于`equals()`的默认实现是不可接受的。解决方法是覆盖此方法，为此，重要的是要了解`equals()`合同，该合同规定了以下声明：

*   **自反性**：对象等于自身，即`p1.equals(p1)`必须返回`true`。
*   **对称性**：`p1.equals(p2)`必须返回与`p2.equals(p1)`相同的结果（`true`/`false`）。
*   **传递性**：如果是`p1.equals(p2)`和`p2.equals(p3)`，那么也是`p1.equals(p3)`。
*   **一致性**：两个相等的物体必须一直保持相等，除非其中一个改变。
*   **`null`返回`false`**：所有对象必须不等于`null`。

因此，为了遵守此约定，`Player`类的`equals()`方法可以覆盖如下：

```java
@Override
public boolean equals(Object obj) {

  if (this == obj) {
    return true;
  }

  if (obj == null) {
    return false;
  }

  if (getClass() != obj.getClass()) {
    return false;
  }

  final Player other = (Player) obj;

  if (this.id != other.id) {
    return false;
  }

  if (!Objects.equals(this.name, other.name)) {
    return false;
  }

  return true;
}
```

现在，让我们再次执行相等性测试（这次，`p1`等于`p2`：

```java
System.out.println(p1.equals(p2)); // true
```

好的，到目前为止还不错！现在，让我们将这两个`Player`实例添加到集合中。例如，让我们将它们添加到一个`HashSet`（一个不允许重复的 Java 集合）：

```java
Set<Player> players = new HashSet<>();
players.add(p1);
players.add(p2);
```

让我们检查一下这个`HashSet`的大小以及它是否包含`p1`：

```java
System.out.println("p1 hash code: " + p1.hashCode()); // 1809787067
System.out.println("p2 hash code: " + p2.hashCode()); // 157627094
System.out.println("Set size: " + players.size());    // 2
System.out.println("Set contains Rafael Nadal: "
  + players.contains(new Player(1, "Rafael Nadal"))); // false
```

与前面实现的`equals()`一致，`p1`和`p2`是相等的，因此`HashSet`的大小应该是 1，而不是 2。此外，它应该包含纳达尔。那么，发生了什么？

一般的答案在于 Java 是如何创建的。凭直觉很容易看出，`equals()`不是一种快速的方法；因此，当需要大量的相等比较时，查找将面临性能损失。例如，在通过集合中的特定值（例如，`HashSet`、`HashMap`和`HashTable`进行查找的情况下，这增加了一个严重的缺点，因为它可能需要大量的相等比较。

基于这个语句，Java 试图通过添加*桶*来减少相等比较。桶是一个基于散列的容器，它将相等的对象分组。这意味着相等的对象应该返回相同的哈希码，而不相等的对象应该返回不同的哈希码（如果两个不相等的对象具有相同的哈希码，则这是一个*散列冲突*，并且对象将进入同一个桶）。因此，Java 会比较散列代码，只有当两个不同的对象引用的散列代码相同（而不是相同的对象引用）时，它才会进一步调用`equals()`。基本上，这会加速集合中的查找。

但我们的案子发生了什么？让我们一步一步来看看：

*   当创建`p1`时，Java 将根据`p1`内存地址为其分配一个哈希码。
*   当`p1`被添加到`Set`时，Java 会将一个新的桶链接到`p1`哈希码。
*   当创建`p2`时，Java 将根据`p2`内存地址为其分配一个哈希码。
*   当`p2`被添加到`Set`时，Java 会将一个新的桶链接到`p2`哈希码（当这种情况发生时，看起来`HashSet`没有按预期工作，它允许重复）。
*   当执行`players.contains(new Player(1, "Rafael Nadal"))`时，基于`p3`存储器地址用新的哈希码创建新的播放器`p3`。
*   因此，在`contains()`的框架中，分别测试`p1`和`p3 p2`和`p3`的相等性涉及检查它们的哈希码，由于`p1`哈希码不同于`p3`哈希码，而`p2`哈希码不同于`p3`哈希码，比较停止，没有求值`equals()`，这意味着`HashSet`不包含对象（`p3`）

为了回到正轨，代码也必须覆盖`hashCode()`方法。`hashCode()`合同规定如下：

*   符合`equals()`的两个相等对象必须返回相同的哈希码。
*   具有相同哈希码的两个对象不是强制相等的。
*   只要对象保持不变，`hashCode()`必须返回相同的值。

根据经验，为了尊重`equals()`和`hashCode()`合同，遵循两条黄金法则：

*   当`equals()`被覆盖时，`hashCode()`也必须被覆盖，反之亦然。
*   以相同的顺序对两个方法使用相同的标识属性。

对于`Player`类，`hashCode()`可以被覆盖如下：

```java
@Override
public int hashCode() {

  int hash = 7;
  hash = 79 * hash + this.id;
  hash = 79 * hash + Objects.hashCode(this.name);

  return hash;
}
```

现在，让我们执行另一个测试（这次，它按预期工作）：

```java
System.out.println("p1 hash code: " + p1.hashCode()); // -322171805
System.out.println("p2 hash code: " + p2.hashCode()); // -322171805
System.out.println("Set size: " + players.size());    // 1
System.out.println("Set contains Rafael Nadal: "
  + players.contains(new Player(1, "Rafael Nadal"))); // true
```

现在，让我们列举一下使用`equals()`和`hashCode()`时的一些常见错误：

*   您覆盖了`equals()`并忘记覆盖`hashCode()`，反之亦然（覆盖两者或无）。
*   您使用`==`运算符而不是`equals()`来比较对象值。
*   在`equals()`中，省略以下一项或多项：
    *   从添加*自检*（`if (this == obj)...`开始。
    *   因为没有实例应该等于`null`，所以继续添加*空校验*（`if(obj == null)...`）。
    *   确保实例是我们期望的（使用`getClass()`或`instanceof`。
    *   最后，在这些角落案例之后，添加字段比较。

*   你通过继承来破坏对称。假设一个类`A`和一个类`B`扩展了`A`并添加了一个新字段。`B`类覆盖从`A`继承的`equals()`实现，并将此实现添加到新字段中。依赖`instanceof`会发现`b.equals(a)`会返回`false`（如预期），而`a.equals(b)`会返回`true`（非预期），因此对称性被破坏。依赖*切片比较*是行不通的，因为这会破坏及物性和自反性。解决这个问题意味着依赖于`getClass()`而不是`instanceof`（通过`getClass()`，类型及其子类型的实例不能相等），或者更好地依赖于组合而不是继承，就像绑定到本书中的应用（`P46_ViolateEqualsViaSymmetry`一样）。
*   返回一个来自`hashCode()`的常量，而不是每个对象的唯一哈希码。

自 JDK7 以来，`Objects`类提供了几个帮助程序来处理对象相等和哈希码，如下所示：

*   `Objects.equals(Object a, Object b)`：测试`a`对象是否等于`b`对象。
*   `Objects.deepEquals(Object a, Object b)`：用于测试两个对象是否相等（如果是数组，则通过`Arrays.deepEquals()`进行测试）。
*   `Objects.hash(Object ... values)`：为输入值序列生成哈希码。

通过`EqualsVerifier`库（[确保`equals()`和`hashCode()`尊重 Java SE 合同](https://mvnrepository.com/artifact/nl.jqno.equalsverifier/equalsverifier)）。

依赖`Lombok`库从对象的字段生成`hashCode()`和[`equals()`](https://projectlombok.org/)。但请注意`Lombok`与 JPA 实体结合的特殊情况。

# 47 不可变对象简述

不可变对象是一个一旦创建就不能更改的对象（其状态是固定的）。

在 Java 中，以下内容适用：

*   原始类型是不可变的。
*   著名的 Java`String`类是不可变的（其他类也是不可变的，比如`Pattern`、`LocalDate`）
*   数组不是不变的。
*   集合可以是可变的、不可修改的或不可变的。

不可修改的集合不是自动不变的。它取决于集合中存储的对象。如果存储的对象是可变的，那么集合是可变的和不可修改的。但是如果存储的对象是不可变的，那么集合实际上是不可变的。

不可变对象在并发（多线程）应用和流中很有用。由于不可变对象不能更改，因此它们无法处理并发问题，并且不会有损坏或不一致的风险。

使用不可变对象的一个主要问题与创建新对象的代价有关，而不是管理可变对象的状态。但是请记住，不可变对象在垃圾收集期间利用了特殊处理。此外，它们不容易出现并发问题，并且消除了管理可变对象状态所需的代码。管理可变对象状态所需的代码往往比创建新对象慢。

通过研究以下问题，我们可以更深入地了解 Java 中的对象不变性。

# 48 不可变字符串

每种编程语言都有一种表示字符串的方法。作为基本类型，字符串是预定义类型的一部分，几乎所有类型的 Java 应用都使用它们。

在 Java 中，字符串不是由一个像`int`、`long`和`float`这样的原始类型来表示的。它们由名为`String`的引用类型表示。几乎所有 Java 应用都使用字符串，例如，Java 应用的`main()`方法获取一个`String`类型的数组作为参数。

`String`的臭名昭著及其广泛的应用意味着我们应该详细了解它。除了知道如何声明和操作字符串（例如，反转和大写）之外，开发人员还应该理解为什么这个类是以特殊或不同的方式设计的。更确切地说，`String`为什么是不可变的？或者这个问题有一个更好的共鸣，比如说，`String`不变的利弊是什么？

# 字符串不变性的优点

在下一节中，我们来看看字符串不变性的一些优点。

# 字符串常量池或缓存池

支持字符串不变性的原因之一是由**字符串常量池**（**SCP**）或缓存池表示的。为了理解这种说法，让我们深入了解一下`String`类是如何在内部工作的。

SCP 是内存中的一个特殊区域（不是普通的堆内存），用于存储字符串文本。假设以下三个`String`变量：

```java
String x = "book";
String y = "book";
String z = "book";
```

创建了多少个`String`对象？说三个很有诱惑力，但实际上 Java 只创建一个具有`"book"`值的`String`对象。其思想是，引号之间的所有内容都被视为一个字符串文本，Java 通过遵循这样的算法（该算法称为**字符串内化**）将字符串文本存储在称为 SCP 的特殊内存区域中：

*   当一个字符串文本被创建时（例如，`String x = "book"`），Java 检查 SCP 以查看这个字符串文本是否存在。
*   如果在 SCP 中找不到字符串字面值，则在 SCP 中为字符串字面值创建一个新的字符串对象，并且相应的变量`x`将指向它。
*   如果在 SCP 中找到字符串字面值（例如，`String y = "book"`、`String z = "book"`），那么新变量将指向`String`对象（基本上，所有具有相同值的变量都将指向相同的`String`对象）：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-cd-prob/img/fb650718-b302-4bd2-8298-1b1b7813b4d9.png)

但是`x`应该是`"cook"`而不是`"book"`，所以我们用`"c"`-`x = x.replace("b", "c");`来代替`"b"`。

而`x`应该是`"cook"`，`y`和`z`应该保持不变。这种行为是由不变性提供的。Java 将创建一个新对象，并对其执行如下更改：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-cd-prob/img/4c94c088-32d7-4df0-a37b-9ba4e589c142.png)

因此，字符串不变性允许缓存字符串文本，这允许应用使用大量字符串文本，对堆内存和垃圾收集器的影响最小。在可变上下文中，修改字符串字面值可能导致变量损坏。

不要创建一个字符串作为`String x = new String("book")`。这不是字符串文本；这是一个`String`实例（通过构造器构建），它将进入普通内存堆而不是 SCP。在普通堆内存中创建的字符串可以通过显式调用`String.intern()`方法作为`x.intern()`指向 SCP。

# 安全

字符串不变性的另一个好处是它的安全性。通常，许多敏感信息（用户名、密码、URL、端口、数据库、套接字连接、参数、属性等）都以字符串的形式表示和传递。通过使这些信息保持不变，代码对于各种安全威胁（例如，意外或故意修改引用）变得安全。

# 线程安全性

想象一个应用使用成千上万个可变的`String`对象并处理线程安全代码。幸运的是，在这种情况下，由于不变性，我们想象的场景不会变成现实。任何不可变对象本质上都是线程安全的。这意味着字符串可以由多个线程共享和操作，没有损坏和不一致的风险。

# 哈希码缓存

`equals()`和`hashCode()`部分讨论了`equals()`和`hashCode()`。每次对特定活动进行哈希运算（例如，搜索集合中的元素）时，都应该计算哈希码。因为`String`是不可变的，所以每个字符串都有一个不可变的哈希码，可以缓存和重用，因为它在创建字符串后不能更改。这意味着可以从缓存中使用字符串的哈希码，而不是每次使用时重新计算它们。例如，`HashMap`为不同的操作（例如，`put()`、`get()`）散列其键，如果这些键属于`String`类型，则哈希码将从缓存中重用，而不是重新计算它们。

# 类加载

在内存中加载类的典型方法依赖于调用`Class.forName(String className)`方法。注意表示类名的参数`String`。由于字符串不变性，在加载过程中不能更改类名。然而，如果`String`是可变的，那么想象加载`class A`（例如，`Class.forName("A")`），在加载过程中，它的名称将被更改为`BadA`。现在，`BadA`物体可以做坏事！

# 字符串不变性的缺点

在下一节中，我们来看看字符串不变性的一些缺点。

# 字符串不能扩展

应该声明一个不可变的类`final`，以避免扩展性。然而，开发人员需要扩展`String`类以添加更多的特性，这一限制可以被认为是不变性的一个缺点。

然而，开发人员可以编写工具类（例如，Apache Commons Lang、`StringUtils`、Spring 框架、`StringUtils`、Guava 和字符串）来提供额外的特性，并将字符串作为参数传递给这些类的方法。

# 敏感数据长时间存储在内存中

字符串中的敏感数据（例如密码）可能长时间驻留在内存（SCP）中。作为缓存，SCP 利用了来自垃圾收集器的特殊处理。更准确地说，垃圾收集器不会以与其他内存区域相同的频率（周期）访问 SCP。作为这种特殊处理的结果，敏感数据在 SCP 中保存了很长一段时间，并且很容易被不必要的使用。

为了避免这一潜在缺陷，建议将敏感数据（例如密码）存储在`char[]`而不是`String`中。

# `OutOfMemoryError`错误

SCP 是一个很小的内存区，可以很快被填满。在 SCP 中存储过多的字符串字面值将导致`OutOfMemoryError`。

# 字符串是完全不变的吗？

在幕后，`String`使用`private final char[]`来存储字符串的每个字符。通过使用 Java 反射 API，在 JDK8 中，以下代码将修改此`char[]`（JDK11 中的相同代码将抛出`java.lang.ClassCastException`）：

```java
String user = "guest";
System.out.println("User is of type: " + user);

Class<String> type = String.class;
Field field = type.getDeclaredField("value");
field.setAccessible(true);

char[] chars = (char[]) field.get(user);

chars[0] = 'a';
chars[1] = 'd';
chars[2] = 'm';
chars[3] = 'i';
chars[4] = 'n';

System.out.println("User is of type: " + user);
```

因此，在 JDK8 中，`String`是*有效*不可变的，但不是*完全*。

# 49 编写不可变类

一个不可变的类必须满足几个要求，例如：

*   该类应标记为`final`以抑制可扩展性（其他类不能扩展该类；因此，它们不能覆盖方法）
*   所有字段都应该声明为`private`和`final`（在其他类中不可见，在这个类的构造器中只初始化一次）
*   类应该包含一个参数化的`public`构造器（或者一个`private`构造器和用于创建实例的工厂方法），用于初始化字段
*   类应该为字段提供获取器
*   类不应公开设置器

例如，以下`Point`类是不可变的，因为它成功地通过了前面的检查表：

```java
public final class Point {

  private final double x;
  private final double y;

  public Point(double x, double y) {
    this.x = x;
    this.y = y;
  }

  public double getX() {
    return x;
  }

  public double getY() {
    return y;
  }
}
```

如果不可变类应该操作可变对象，请考虑以下问题。

# 50 向不可变类传递/从不可变类返回可变对象

将可变对象传递给不可变类可能会破坏不可变性。让我们考虑以下可变类：

```java
public class Radius {

  private int start;
  private int end;

  public int getStart() {
    return start;
  }

  public void setStart(int start) {
    this.start = start;
  }

  public int getEnd() {
    return end;
  }

  public void setEnd(int end) {
    this.end = end;
  }
}
```

然后，让我们将这个类的一个实例传递给一个名为`Point`的不可变类。乍一看，`Point`类可以写为：

```java
public final class Point {

  private final double x;
  private final double y;
  private final Radius radius;

  public Point(double x, double y, Radius radius) {
    this.x = x;
    this.y = y;
    this.radius = radius;
  }

  public double getX() {
    return x;
  }

  public double getY() {
    return y;
  }

  public Radius getRadius() {
    return radius;
  }
}
```

这个类仍然是不变的吗？答案是否定的，`Point`类不再是不变的，因为它的状态可以改变，如下例所示：

```java
Radius r = new Radius();
r.setStart(0);
r.setEnd(120);

Point p = new Point(1.23, 4.12, r);

System.out.println("Radius start: " + p.getRadius().getStart()); // 0
r.setStart(5);
System.out.println("Radius start: " + p.getRadius().getStart()); // 5
```

注意，调用`p.getRadius().getStart()`返回两个不同的结果；因此，`p`的状态已经改变，所以`Point`不再是不可变的。该问题的解决方案是克隆`Radius`对象并将克隆存储为`Point`的字段：

```java
public final class Point {

  private final double x;
  private final double y;
  private final Radius radius;

  public Point(double x, double y, Radius radius) {
    this.x = x;
    this.y = y;

    Radius clone = new Radius();
    clone.setStart(radius.getStart());
    clone.setEnd(radius.getEnd());

    this.radius = clone;
  }

  public double getX() {
    return x;
  }

  public double getY() {
    return y;
  }

  public Radius getRadius() {
    return radius;
  }
}
```

这一次，`Point`类的不变性级别增加了（调用`r.setStart(5)`不会影响`radius`字段，因为该字段是`r`的克隆）。但是`Point`类并不是完全不可变的，因为还有一个问题需要解决，从不可变类返回可变对象会破坏不可变性。检查下面的代码，它分解了`Point`的不变性：

```java
Radius r = new Radius();
r.setStart(0);
r.setEnd(120);

Point p = new Point(1.23, 4.12, r);

System.out.println("Radius start: " + p.getRadius().getStart()); // 0
p.getRadius().setStart(5);
System.out.println("Radius start: " + p.getRadius().getStart()); // 5
```

再次调用`p.getRadius().getStart()`返回两个不同的结果；因此，`p`的状态已经改变。解决方案包括修改`getRadius()`方法以返回`radius`字段的克隆，如下所示：

```java
...
public Radius getRadius() {
    Radius clone = new Radius();
    clone.setStart(this.radius.getStart());
    clone.setEnd(this.radius.getEnd());

    return clone;
  }
...
```

现在，`Point`类又是不可变的。问题解决了！

在选择克隆技术/工具之前，在某些情况下，建议您花点时间分析/学习 Java 和第三方库中可用的各种可能性（例如，检查本章中的”克隆对象“部分）。对于浅拷贝，前面的技术可能是正确的选择，但是对于深拷贝，代码可能需要依赖不同的方法，例如复制构造器、`Cloneable`接口或外部库（例如，Apache Commons Lang`ObjectUtils`、JSON 序列化与`Gson`或 Jackson，或任何其他方法）。

# 51 通过生成器模式编写不可变类

当一个类（不可变或可变）有太多字段时，它需要一个具有许多参数的构造器。当其中一些字段是必需的，而其他字段是可选的时，这个类将需要几个构造器来覆盖所有可能的组合。这对于开发人员和类的用户来说都是很麻烦的。这就是构建器模式的用武之地。

根据**四人帮**（**GoF**），*构建器模式将复杂对象的构造与其表示分离，以便相同的构造过程可以创建不同的表示*。

生成器模式可以作为一个单独的类或内部的`static`类来实现。让我们关注第二个案例。`User`类有三个必填字段（`nickname`、`password`、`created`）和三个可选字段（`email`、`firstname`、`lastname`）。

现在，依赖于构建器模式的不可变的`User`类将显示如下：

```java
public final class User {

  private final String nickname;
  private final String password;
  private final String firstname;
  private final String lastname;
  private final String email;
  private final Date created;

  private User(UserBuilder builder) {
    this.nickname = builder.nickname;
    this.password = builder.password;
    this.created = builder.created;
    this.firstname = builder.firstname;
    this.lastname = builder.lastname;
    this.email = builder.email;
  }

  public static UserBuilder getBuilder(
      String nickname, String password) {
    return new User.UserBuilder(nickname, password);
  }

  public static final class UserBuilder {

    private final String nickname;
    private final String password;
    private final Date created;
    private String email;
    private String firstname;
    private String lastname;

    public UserBuilder(String nickname, String password) {
      this.nickname = nickname;
      this.password = password;
      this.created = new Date();
    }

    public UserBuilder firstName(String firstname) {
      this.firstname = firstname;
      return this;
    }

    public UserBuilder lastName(String lastname) {
      this.lastname = lastname;
      return this;
    }

    public UserBuilder email(String email) {
      this.email = email;
      return this;
    }

    public User build() {
      return new User(this);
    }
  }

  public String getNickname() {
    return nickname;
  }

  public String getPassword() {
    return password;
  }

  public String getFirstname() {
    return firstname;
  }

  public String getLastname() {
    return lastname;
  }

  public String getEmail() {
    return email;
  }

  public Date getCreated() {
    return new Date(created.getTime());
  }
}
```

以下是一些用法示例：

```java
import static modern.challenge.User.getBuilder;
...
// user with nickname and password
User user1 = getBuilder("marin21", "hjju9887h").build();

// user with nickname, password and email
User user2 = getBuilder("ionk", "44fef22")
  .email("ion@gmail.com")
  .build();

// user with nickname, password, email, firstname and lastname
User user3 = getBuilder("monika", "klooi0988")
  .email("monika@gmail.com")
  .firstName("Monika")
  .lastName("Ghuenter")
  .build();
```

# 52 避免不可变对象中的坏数据

*坏数据*是任何对不可变对象有负面影响的数据（例如，损坏的数据）。最有可能的是，这些数据来自用户输入或不受我们直接控制的外部数据源。在这种情况下，坏数据可能会击中不可变的对象，最糟糕的是没有修复它的方法。不可变的对象在创建后不能更改；因此，只要对象存在，坏数据就会快乐地存在。

这个问题的解决方案是根据一组全面的约束来验证输入到不可变对象中的所有数据。

执行验证有不同的方法，从自定义验证到内置解决方案。验证可以在不可变对象类的外部或内部执行，具体取决于应用设计。例如，如果不可变对象是通过构建器模式构建的，那么可以在 Builder 类中执行验证。

JSR380 是用于 bean 验证的 Java API（JavaSE/EE）规范，可用于通过注解进行验证。Hibernate 验证器是验证 API 的参考实现，它可以很容易地作为 Maven 依赖项在`pom.xml`文件中提供（请查看本书附带的源代码）。

此外，我们依赖于专用注解来提供所需的约束（例如，`@NotNull`、`@Min`、`@Max`、`@Size`和`@Email`）。在以下示例中，将约束添加到生成器类中，如下所示：

```java
...
public static final class UserBuilder {

  @NotNull(message = "cannot be null")
  @Size(min = 3, max = 20, message = "must be between 3 and 20 
    characters")
  private final String nickname;

  @NotNull(message = "cannot be null")
  @Size(min = 6, max = 50, message = "must be between 6 and 50 
    characters")
  private final String password;

  @Size(min = 3, max = 20, message = "must be between 3 and 20 
    characters")
  private String firstname;

  @Size(min = 3, max = 20, message = "must be between 3 and 20 
    characters")
  private String lastname;

  @Email(message = "must be valid")
  private String email;

  private final Date created;

  public UserBuilder(String nickname, String password) {
    this.nickname = nickname;
    this.password = password;
    this.created = new Date();
  }
...
```

最后，验证过程通过`Validator`API 从代码中触发（这仅在 JavaSE 中需要）。如果进入生成器类的数据无效，则不创建不可变对象（不要调用`build()`方法）：

```java
User user;
Validator validator 
  = Validation.buildDefaultValidatorFactory().getValidator();

User.UserBuilder userBuilder 
  = new User.UserBuilder("monika", "klooi0988")
    .email("monika@gmail.com")
    .firstName("Monika").lastName("Gunther");

final Set<ConstraintViolation<User.UserBuilder>> violations 
  = validator.validate(userBuilder);
if (violations.isEmpty()) {
  user = userBuilder.build();
  System.out.println("User successfully created on: " 
    + user.getCreated());
} else {
  printConstraintViolations("UserBuilder Violations: ", violations);
}
```

这样，坏数据就不能触及不可变的对象。如果没有生成器类，则可以直接在不可变对象的字段级别添加约束。前面的解决方案只是在控制台上显示潜在的冲突，但是根据情况，该解决方案可能执行不同的操作（例如，抛出特定的异常）。

# 53 克隆对象

克隆对象不是一项日常任务，但正确地克隆对象很重要。克隆对象主要是指创建对象的副本。拷贝主要有两种类型：*浅*拷贝（尽可能少拷贝）和*深*拷贝（复制所有内容）。

假设下面的类：

```java
public class Point {

  private double x;
  private double y;

  public Point() {}
  public Point(double x, double y) {
    this.x = x;
    this.y = y;
  }

  // getters and setters
}
```

所以，我们在一个类中映射了一个类型点`(x, y)`。现在，让我们进行一些克隆。

# 手动克隆

快速方法包括添加一个手动将当前`Point`复制到新`Point`的方法（这是一个浅复制）：

```java
public Point clonePoint() {
  Point point = new Point();
  point.setX(this.x);
  point.setY(this.y);

  return point;
}
```

这里的代码非常简单。只需创建一个新的`Point`实例，并用当前`Point`的字段填充其字段。返回的`Point`是当前`Point`的浅拷贝（因为`Point`不依赖其他对象，所以深拷贝是完全相同的）：

```java
Point point = new Point(...);
Point clone = point.clonePoint();
```

# 通过`clone()`克隆

`Object`类包含一个名为`clone()`的方法。此方法对于创建浅拷贝非常有用（也可以用于深拷贝）。为了使用它，类应该遵循给定的步骤：

*   实现`Cloneable`接口（如果该接口没有实现，则抛出`CloneNotSupportedException`。
*   覆盖`clone()`方法（`Object.clone()`为`protected`）。
*   调用`super.clone()`。

`Cloneable`接口不包含任何方法。这只是 JVM 可以克隆这个对象的一个信号。一旦实现了这个接口，代码就需要覆盖`Object.clone()`方法。这是需要的，因为`Object.clone()`是`protected`，为了通过`super`调用它，代码需要覆盖这个方法。如果将`clone()`添加到子类中，这可能是一个严重的缺点，因为所有超类都应该定义一个`clone()`方法，以避免`super.clone()`链调用失败。

此外，`Object.clone()`不依赖构造器调用，因此开发人员无法控制对象构造：

```java
public class Point implements Cloneable {

  private double x;
  private double y;

  public Point() {}

  public Point(double x, double y) {
    this.x = x;
    this.y = y;
  }

  @Override
  public Point clone() throws CloneNotSupportedException {
    return (Point) super.clone();
  }

  // getters and setters
}
```

创建克隆的步骤如下：

```java
Point point = new Point(...);
Point clone = point.clone();
```

# 通过构造器克隆

此克隆技术要求您使用构造器来丰富类，该构造器接受表示将用于创建克隆的类实例的单个参数。

让我们看看代码：

```java
public class Point {

  private double x;
  private double y;

  public Point() {}

  public Point(double x, double y) {
    this.x = x;
    this.y = y;
  }

  public Point(Point another) {
    this.x = another.x;
    this.y = another.y;
  }

  // getters and setters
}
```

创建克隆的步骤如下：

```java
Point point = new Point(...);
Point clone = new Point(point);
```

# 通过克隆库进行克隆

当一个对象依赖于另一个对象时，需要一个深度副本。执行深度复制意味着复制对象，包括其依赖链。例如，假设`Point`有一个`Radius`类型的字段：

```java
public class Radius {

  private int start;
  private int end;

  // getters and setters
}

public class Point {

  private double x;
  private double y;
  private Radius radius;

  public Point(double x, double y, Radius radius) {
    this.x = x;
    this.y = y;
    this.radius = radius;
  }

  // getters and setters
}
```

执行`Point`的浅拷贝将创建`x`和`y`的拷贝，但不会创建`radius`对象的拷贝。这意味着影响`radius`对象的修改也将反映在克隆中。是时候进行深度复制了。

一个麻烦的解决方案将涉及到调整以前提出的浅拷贝技术以支持深拷贝。幸运的是，有一些现成的解决方案可以应用，[其中之一就是克隆库](https://github.com/kostaskougios/cloning)：

```java
import com.rits.cloning.Cloner;
...
Point point = new Point(...);
Cloner cloner = new Cloner();
Point clone = cloner.deepClone(point);
```

代码是不言自明的。请注意，克隆库还附带了其他一些好处，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-cd-prob/img/c75891ec-3902-49da-8290-62d5f7b09c70.png)

# 通过序列化克隆

这种技术需要可序列化的对象（实现`java.io.Serializable`。基本上，对象在新对象中被序列化（`writeObject()`）和反序列化（`readObject()`）。可以实现这一点的助手方法如下所示：

```java
private static <T> T cloneThroughSerialization(T t) {

  try {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    ObjectOutputStream oos = new ObjectOutputStream(baos);
    oos.writeObject(t);

    ByteArrayInputStream bais 
      = new ByteArrayInputStream(baos.toByteArray());
    ObjectInputStream ois = new ObjectInputStream(bais);

    return (T) ois.readObject();
  } catch (IOException | ClassNotFoundException ex) {
    // log exception
    return t;
  }
}
```

因此，对象在`ObjectOutputStream`中序列化，在`ObjectInputStream`中反序列化。通过此方法克隆对象的步骤如下：

```java
Point point = new Point(...);
Point clone = cloneThroughSerialization(point);
```

ApacheCommonsLang 通过`SerializationUtils`提供了一个基于序列化的内置解决方案。在它的方法中，这个类提供了一个名为`clone()`的方法，可以如下使用：

```java
Point point = new Point(...);
Point clone = SerializationUtils.clone(point);
```

# 通过 JSON 克隆

几乎所有 Java 中的 JSON 库都可以序列化任何**普通的旧 Java 对象**（**POJO**），而不需要任何额外的配置/映射。在项目中有一个 JSON 库（很多项目都有）可以避免我们添加额外的库来提供深度克隆。主要来说，该解决方案可以利用现有的 JSON 库来获得相同的效果。

以下是使用`Gson`库的示例：

```java
private static <T> T cloneThroughJson(T t) {

  Gson gson = new Gson();
  String json = gson.toJson(t);

  return (T) gson.fromJson(json, t.getClass());
}

Point point = new Point(...);
Point clone = cloneThroughJson(point);
```

除此之外，您还可以选择编写专用于克隆对象的库。

# 54 覆盖`toString()`

`toString()`方法在`java.lang.Object`中定义，JDK 附带了它的默认实现。此默认实现自动用于`print()`、`println()`、`printf()`、开发期间调试、日志记录、异常中的信息消息等的所有对象。

不幸的是，默认实现返回的对象的字符串表示形式信息量不大。例如，让我们考虑下面的`User`类：

```java
public class User {
  private final String nickname;
  private final String password;
  private final String firstname;
  private final String lastname;
  private final String email;
  private final Date created;

  // constructor and getters skipped for brevity
}
```

现在，让我们创建这个类的一个实例，并在控制台上打印它：

```java
User user = new User("sparg21", "kkd454ffc",
  "Leopold", "Mark", "markl@yahoo.com");

System.out.println(user);
```

这个`println()`方法的输出如下：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-cd-prob/img/d41b9942-344f-444f-b3a4-dbd2513c92cf.png)

在前面的屏幕截图中，避免输出的解决方案包括覆盖`toString()`方法。例如，让我们覆盖它以公开用户详细信息，如下所示：

```java
@Override
public String toString() {
  return "User{" + "nickname=" + nickname + ", password=" + password
    + ", firstname=" + firstname + ", lastname=" + lastname
    + ", email=" + email + ", created=" + created + '}';
}
```

这次，`println()`将显示以下输出：

```java
User {
  nickname = sparg21, password = kkd454ffc, 
  firstname = Leopold, lastname = Mark, 
  email = markl@yahoo.com, created = Fri Feb 22 10: 49: 32 EET 2019
}
```

这比以前的输出信息更丰富。

但是，请记住，`toString()`是为不同的目的自动调用的。例如，日志记录可以如下所示：

```java
logger.log(Level.INFO, "This user rocks: {0}", user);
```

在这里，用户密码将命中日志，这可能表示有问题。在应用中公开日志敏感数据（如密码、帐户和秘密 IP）绝对是一种不好的做法。

因此，请特别注意仔细选择进入`toString()`的信息，因为这些信息最终可能会被恶意利用。在我们的例子中，密码不应该是`toString()`的一部分：

```java
@Override
public String toString() {
  return "User{" + "nickname=" + nickname
    + ", firstname=" + firstname + ", lastname=" + lastname
    + ", email=" + email + ", created=" + created + '}';
}
```

通常，`toString()`是通过 IDE 生成的方法。因此，在 IDE 为您生成代码之前，请注意您选择了哪些字段。

# 55 `switch`表达式

在简要概述 JDK12 中引入的`switch`表达式之前，让我们先来看一个典型的老式方法示例：

```java
private static Player createPlayer(PlayerTypes playerType) {

  switch (playerType) {

    case TENNIS:
      return new TennisPlayer();
    case FOOTBALL:
      return new FootballPlayer();
    case SNOOKER:      
      return new SnookerPlayer();
    case UNKNOWN:
      throw new UnknownPlayerException("Player type is unknown");
    default:
      throw new IllegalArgumentException(
        "Invalid player type: " + playerType);

  }
}
```

如果我们忘记了`default`，那么代码将无法编译。

显然，前面的例子是可以接受的。在最坏的情况下，我们可以添加一个伪变量（例如，`player`），一些杂乱的`break`语句，如果`default`丢失，就不会收到投诉。所以，下面的代码是一个老派，非常难看的`switch`：

```java
private static Player createPlayerSwitch(PlayerTypes playerType) {

  Player player = null;

  switch (playerType) {
    case TENNIS:
      player = new TennisPlayer();
      break;
    case FOOTBALL:
      player = new FootballPlayer();
      break;
    case SNOOKER:
      player = new SnookerPlayer();
      break;
    case UNKNOWN:
      throw new UnknownPlayerException(
        "Player type is unknown");
    default:
      throw new IllegalArgumentException(
        "Invalid player type: " + playerType);
  }

  return player;
}
```

如果我们忘记了`default`，那么编译器方面就不会有任何抱怨了。在这种情况下，丢失的`default`案例可能导致`null`播放器。

然而，自从 JDK12 以来，我们已经能够依赖于`switch`表达式。在 JDK12 之前，`switch`是一个语句，一个用来控制流的构造（例如，`if`语句），而不表示结果。另一方面，表达式的求值结果。因此，`switch`表达可产生结果。

前面的`switch`表达式可以用 JDK12 的样式写成如下：

```java
private static Player createPlayer(PlayerTypes playerType) {

  return switch (playerType) {
    case TENNIS ->
      new TennisPlayer();
    case FOOTBALL ->
      new FootballPlayer();
    case SNOOKER ->
      new SnookerPlayer();
    case UNKNOWN ->
      throw new UnknownPlayerException(
        "Player type is unknown");
    // default is not mandatory
    default ->
      throw new IllegalArgumentException(
        "Invalid player type: " + playerType);
  };
}
```

这次，`default`不是强制性的。我们可以跳过它。

JDK12`switch`足够聪明，可以在`switch`没有覆盖所有可能的输入值时发出信号。这在 Java `enum`值的情况下非常有用。JDK12`switch`可以检测所有`enum`值是否都被覆盖，如果没有被覆盖，则不会强制一个无用的`default`。例如，如果我们删除`default`并向`PlayerTypes enum`添加一个新条目（例如`GOLF`），那么编译器将通过一条消息向它发送信号，如下面的屏幕截图（这是来自 NetBeans 的）：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-cd-prob/img/fd6ef71d-5ca7-4757-a37c-3e111bb83418.png)

注意，在标签和执行之间，我们将冒号替换为箭头（Lambda 样式的语法）。此箭头的主要作用是防止跳转，这意味着只执行其右侧的代码块。不需要使用`break`。

不要断定箭头将`switch`语句转换为`switch`表达式。`switch`表达可用于结肠和`break`，如下所示：

```java
private static Player createPlayer(PlayerTypes playerType) {

  return switch (playerType) {
    case TENNIS:
      break new TennisPlayer();
    case FOOTBALL:
      break new FootballPlayer();
    case SNOOKER:
      break new SnookerPlayer();
    case UNKNOWN:
      throw new UnknownPlayerException(
        "Player type is unknown");
    // default is not mandatory
    default:
      throw new IllegalArgumentException(
        "Invalid player type: " + playerType);
  };
}
```

我们的示例在`enum`上发布了`switch`，但是 JDK12`switch`也可以在`int`、`Integer`、`short`、`Short`、`byte`、`Byte`、`char`、`Character`和`String`上使用。

注意，JDK12 带来了`switch`表达式作为预览特性。这意味着它很容易在接下来的几个版本中发生更改，需要在编译和运行时通过`--enable-preview`命令行选项来解锁它。

# 56 多个`case`标签

在 JDK12 之前，`switch`语句允许每个`case`有一个标签。从`switch`表达式开始，`case`可以有多个用逗号分隔的标签。请看下面举例说明多个`case`标签的方法：

```java
private static SportType 
  fetchSportTypeByPlayerType(PlayerTypes playerType) {

  return switch (playerType) {
    case TENNIS, GOLF, SNOOKER ->
      new Individual();
    case FOOTBALL, VOLLEY ->  
      new Team();    
  };
}
```

因此，如果我们传递给这个方法`TENNIS`、`GOLF`或`SNOOKER`，它将返回一个`Individual`类的实例。如果我们通过了`FOOTBALL`或`VOLLEY`，它将返回一个`Team`类的实例。

# 57 `case`语句块

标签的箭头可以指向单个语句（如前两个问题中的示例）或大括号中的块。这与 Lambda 块非常相似。查看以下解决方案：

```java
private static Player createPlayer(PlayerTypes playerType) {
  return switch (playerType) {
    case TENNIS -> {
      System.out.println("Creating a TennisPlayer ...");
      break new TennisPlayer();
    }
    case FOOTBALL -> {
      System.out.println("Creating a FootballPlayer ...");
      break new FootballPlayer();
    }
    case SNOOKER -> {
      System.out.println("Creating a SnookerPlayer ...");
      break new SnookerPlayer();
    }
    default ->
      throw new IllegalArgumentException(
        "Invalid player type: " + playerType);
  };
}
```

注意，我们通过`break`而不是`return`从花括号块中退出。换句话说，虽然我们可以从一个`switch`语句中`return`，但我们不能从一个表达式中`return`。

# 总结

这就是所有的人！本章向您介绍了几个涉及对象、不变性和`switch`表达式的问题。虽然覆盖对象和不变性的问题代表了编程的基本概念，但覆盖`switch`表达式的问题致力于引入新的 JDK12 特性来解决这个问题。

从本章下载应用以查看结果和其他详细信息。****


# 三、使用日期和时间

> 原文：[Java Coding Problems](https://libgen.rs/book/index.php?md5=3280024C263466704C8F7525E5BB6AAE)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)
> 
> 贡献者：[飞龙](https://github.com/wizardforcel)
> 
> 本文来自[【ApacheCN Java 译文集】](https://github.com/apachecn/apachecn-java-zh)，自豪地采用[谷歌翻译](https://translate.google.cn/)。

本章包括 20 个涉及日期和时间的问题。这些问题通过`Date`、`Calendar`、`LocalDate`、`LocalTime`、`LocalDateTime`、`ZoneDateTime`、`OffsetDateTime`、`OffsetTime`、`Instant`等涵盖了广泛的主题（转换、格式化、加减、定义时段/持续时间、计算等）。到本章结束时，您将在确定日期和时间方面没有问题，同时符合您的应用的需要。本章介绍的基本问题将非常有助于了解日期-时间 API 的整体情况，并将像拼图中需要拼凑起来的部分一样解决涉及日期和时间的复杂挑战。

# 问题

使用以下问题来测试您的日期和时间编程能力。我强烈建议您在使用解决方案和下载示例程序之前，先尝试一下每个问题：

58.  **将字符串转换为日期和时间**：**编写一个程序，演示字符串和日期/时间之间的转换。**
59.  **格式化日期和时间**：**解释日期和时间的格式模式。
60.  获取当前日期/时间（不含日期/时间）：编写程序，提取当前日期（不含时间或日期）。
61.  从`LocalDate`和`LocalTime`到`LocalDateTime`：编写一个程序，从`LocalDate`对象和`LocalTime`构建一个`LocalDateTime`。它将日期和时间组合在一个`LocalDateTime`对象中。
62.  通过`Instant`类获取机器时间：解释并举例说明`Instant`API。
63.  定义使用基于日期的值的时间段（`Period`）和使用基于时间的值的时间段（`Duration`）：解释并举例说明`Period`和`Duration`API 的用法。

64.  **获取日期和时间单位**：编写一个程序，从表示日期时间的对象中提取日期和时间单位（例如，从日期中提取年、月、分钟等）。
65.  **对日期时间的加减**：编写一个程序，对日期时间对象加减一定的时间（如年、日、分等）（如对日期加 1 小时，对`LocalDateTime`减 2 天等）。
66.  **获取 UTC 和 GMT 的所有时区**：编写一个程序，显示 UTC 和 GMT 的所有可用时区。
67.  **获取所有可用时区的本地日期时间**：编写一个程序，显示所有可用时区的本地时间。68.  **显示航班日期时间信息**：编写程序，显示 15 小时 30 分钟的航班时刻信息。更确切地说，是从澳大利亚珀斯飞往欧洲布加勒斯特的航班。
69.  将 Unix 时间戳转换为日期时间：编写将 Unix 时间戳转换为`java.util.Date`和`java.time.LocalDateTime`的程序。
70.  查找月份的第一天/最后一天：编写一个程序，通过 JDK8，`TemporalAdjusters`查找月份的第一天/最后一天。
71.  **定义/提取区域偏移**：编写一个程序，展示定义和提取区域偏移的不同技术。
72.  `Date`与`Temporal`之间的转换：编写`Date`与`Instant`、`LocalDate`、`LocalDateTime`等之间的转换程序。
73.  **迭代一系列日期**：编写一个程序，逐日（以一天的步长）迭代一系列给定日期。
74.  **计算年龄**：编写一个计算一个人年龄的程序。
75.  **一天的开始和结束**：编写一个程序，返回一天的开始和结束时间。
76.  **两个日期之间的差异**：编写一个程序，计算两个日期之间的时间量（以天为单位）。
77.  **实现象棋时钟**：编写实现象棋时钟的程序。

以下各节介绍上述问题的解决方案。记住，通常没有一个正确的方法来解决一个特定的问题。另外，请记住，这里显示的解释仅包括解决问题所需的最有趣和最重要的细节。下载示例解决方案以查看更多详细信息，并在[这个页面](https://github.com/PacktPublishing/Java-Coding-Problems)中试用程序。

# 58 将字符串转换为日期和时间

将`String`转换或解析为日期和时间可以通过一组`parse()`方法来完成。从日期和时间到`String`的转换可以通过`toString()`或`format()`方法完成。

# JDK8 之前

在 JDK8 之前，这个问题的典型解决方案依赖于抽象的`DateFormat`类的主扩展，名为`SimpleDateFormat`（这不是线程安全类）。在本书附带的代码中，有几个示例说明了如何使用此类。

# 从 JDK8 开始

从 JDK8 开始，`SimpleDateFormat`可以替换为一个新类—`DateTimeFormatter`。这是一个不可变（因此是线程安全的）类，用于打印和解析日期时间对象。这个类支持从预定义的格式化程序（表示为常量，如 ISO 本地时间`2011-12-03`，是`ISO_LOCAL_DATE`）到用户定义的格式化程序（依赖于一组用于编写自定义格式模式的符号）。

此外，除了`Date`类之外，JDK8 还提供了几个新类，它们专门用于处理日期和时间。其中一些类显示在下面的列表中（这些类也被称为临时类，因为它们实现了`Temporal`接口）：

*   `LocalDate`（ISO-8601 日历系统中没有时区的日期）
*   `LocalTime`（ISO-8601 日历系统中无时区的时间）
*   `LocalDateTime`（ISO-8601 日历系统中无时区的日期时间）
*   `ZonedDateTime`（ISO-8601 日历系统中带时区的日期时间），依此类推
*   `OffsetDateTime`（在 ISO-8601 日历系统中，有 UTC/GMT 偏移的日期时间）
*   `OffsetTime`（在 ISO-8601 日历系统中与 UTC/GMT 有偏移的时间）

为了通过预定义的格式化程序将`String`转换为`LocalDate`，它应该遵循`DateTimeFormatter.ISO_LOCAL_DATE`模式，例如`2020-06-01`。`LocalDate`提供了一种`parse()`方法，可以如下使用：

```java
// 06 is the month, 01 is the day
LocalDate localDate = LocalDate.parse("2020-06-01");
```

类似地，在`LocalTime`的情况下，字符串应该遵循`DateTimeFormatter.ISO_LOCAL_TIME`模式；例如，`10:15:30`，如下面的代码片段所示：

```java
LocalTime localTime = LocalTime.parse("12:23:44");
```

在`LocalDateTime`的情况下，字符串应该遵循`DateTimeFormatter.ISO_LOCAL_DATE_TIME`模式，例如`2020-06-01T11:20:15`，如下代码片段所示：

```java
LocalDateTime localDateTime 
  = LocalDateTime.parse("2020-06-01T11:20:15");
```

在`ZonedDateTime`的情况下，字符串必须遵循`DateTimeFormatter.ISO_ZONED_DATE_TIME`模式，例如`2020-06-01T10:15:30+09:00[Asia/Tokyo]`，如下代码片段所示：

```java
ZonedDateTime zonedDateTime 
  = ZonedDateTime.parse("2020-06-01T10:15:30+09:00[Asia/Tokyo]");
```

在`OffsetDateTime`的情况下，字符串必须遵循`DateTimeFormatter.ISO_OFFSET_DATE_TIME`模式，例如`2007-12-03T10:15:30+01:00`，如下代码片段所示：

```java
OffsetDateTime offsetDateTime 
  = OffsetDateTime.parse("2007-12-03T10:15:30+01:00");
```

最后，在`OffsetTime`的情况下，字符串必须遵循`DateTimeFormatter.ISO_OFFSET_TIME`模式，例如`10:15:30+01:00`，如下代码片段所示：

```java
OffsetTime offsetTime = OffsetTime.parse("10:15:30+01:00");
```

如果字符串不符合任何预定义的格式化程序，则是时候通过自定义格式模式使用用户定义的格式化程序了；例如，字符串`01.06.2020`表示需要用户定义格式化程序的日期，如下所示：

```java
DateTimeFormatter dateFormatter 
  = DateTimeFormatter.ofPattern("dd.MM.yyyy");
LocalDate localDateFormatted 
  = LocalDate.parse("01.06.2020", dateFormatter);
```

但是，像`12|23|44`这样的字符串需要如下用户定义的格式化程序：

```java
DateTimeFormatter timeFormatter 
  = DateTimeFormatter.ofPattern("HH|mm|ss");
LocalTime localTimeFormatted 
  = LocalTime.parse("12|23|44", timeFormatter);
```

像`01.06.2020, 11:20:15`这样的字符串需要一个用户定义的格式化程序，如下所示：

```java
DateTimeFormatter dateTimeFormatter 
  = DateTimeFormatter.ofPattern("dd.MM.yyyy, HH:mm:ss");
LocalDateTime localDateTimeFormatted 
  = LocalDateTime.parse("01.06.2020, 11:20:15", dateTimeFormatter);
```

像`01.06.2020, 11:20:15+09:00 [Asia/Tokyo]`这样的字符串需要一个用户定义的格式化程序，如下所示：

```java
DateTimeFormatter zonedDateTimeFormatter 
  = DateTimeFormatter.ofPattern("dd.MM.yyyy, HH:mm:ssXXXXX '['VV']'");
ZonedDateTime zonedDateTimeFormatted 
  = ZonedDateTime.parse("01.06.2020, 11:20:15+09:00 [Asia/Tokyo]", 
    zonedDateTimeFormatter);
```

像`2007.12.03, 10:15:30, +01:00`这样的字符串需要一个用户定义的格式化程序，如下所示：

```java
DateTimeFormatter offsetDateTimeFormatter 
  = DateTimeFormatter.ofPattern("yyyy.MM.dd, HH:mm:ss, XXXXX");
OffsetDateTime offsetDateTimeFormatted 
  = OffsetDateTime.parse("2007.12.03, 10:15:30, +01:00", 
    offsetDateTimeFormatter);
```

最后，像`10 15 30 +01:00`这样的字符串需要一个用户定义的格式化程序，如下所示：

```java
DateTimeFormatter offsetTimeFormatter 
  = DateTimeFormatter.ofPattern("HH mm ss XXXXX");
OffsetTime offsetTimeFormatted 
  = OffsetTime.parse("10 15 30 +01:00", offsetTimeFormatter);
```

前面示例中的每个`ofPattern()`方法也支持`Locale`。

从`LocalDate`、`LocalDateTime`或`ZonedDateTime`到`String`的转换至少可以通过两种方式完成：

*   依赖于`LocalDate`、`LocalDateTime`或`ZonedDateTime.toString()`方法（自动或显式）。请注意，依赖于`toString()`将始终通过相应的预定义格式化程序打印日期：

```java
// 2020-06-01 results in ISO_LOCAL_DATE, 2020-06-01
String localDateAsString = localDate.toString();

// 01.06.2020 results in ISO_LOCAL_DATE, 2020-06-01
String localDateAsString = localDateFormatted.toString();

// 2020-06-01T11:20:15 results 
// in ISO_LOCAL_DATE_TIME, 2020-06-01T11:20:15
String localDateTimeAsString = localDateTime.toString();

// 01.06.2020, 11:20:15 results in 
// ISO_LOCAL_DATE_TIME, 2020-06-01T11:20:15
String localDateTimeAsString 
  = localDateTimeFormatted.toString();

// 2020-06-01T10:15:30+09:00[Asia/Tokyo] 
// results in ISO_ZONED_DATE_TIME,
// 2020-06-01T11:20:15+09:00[Asia/Tokyo]
String zonedDateTimeAsString = zonedDateTime.toString();

// 01.06.2020, 11:20:15+09:00 [Asia/Tokyo] 
// results in ISO_ZONED_DATE_TIME,
// 2020-06-01T11:20:15+09:00[Asia/Tokyo]
String zonedDateTimeAsString 
  = zonedDateTimeFormatted.toString();
```

*   依靠`DateTimeFormatter.format()`方法。请注意，依赖于`DateTimeFormatter.format()`将始终使用指定的格式化程序打印日期/时间（默认情况下，时区将为`null`），如下所示：

```java
// 01.06.2020
String localDateAsFormattedString 
  = dateFormatter.format(localDateFormatted);

// 01.06.2020, 11:20:15
String localDateTimeAsFormattedString 
  = dateTimeFormatter.format(localDateTimeFormatted);

// 01.06.2020, 11:20:15+09:00 [Asia/Tokyo]
String zonedDateTimeAsFormattedString 
  = zonedDateTimeFormatted.format(zonedDateTimeFormatter);
```

在讨论中添加一个明确的时区可以如下所示：

```java
DateTimeFormatter zonedDateTimeFormatter 
  = DateTimeFormatter.ofPattern("dd.MM.yyyy, HH:mm:ssXXXXX '['VV']'")
    .withZone(ZoneId.of("Europe/Paris"));
ZonedDateTime zonedDateTimeFormatted 
  = ZonedDateTime.parse("01.06.2020, 11:20:15+09:00 [Asia/Tokyo]", 
    zonedDateTimeFormatter);
```

这次，字符串表示欧洲/巴黎时区中的日期/时间：

```java
// 01.06.2020, 04:20:15+02:00 [Europe/Paris]
String zonedDateTimeAsFormattedString 
  = zonedDateTimeFormatted.format(zonedDateTimeFormatter);
```

# 59 格式化日期和时间

前面的问题包含一些通过`SimpleDateFormat.format()`和`DateTimeFormatter.format()`格式化日期和时间的风格。为了定义*格式模式*，开发人员必须了解格式模式语法。换句话说，开发人员必须知道 Java 日期时间 API 使用的一组符号，以便识别有效的格式模式。

大多数符号与`SimpleDateFormat`（JDK8 之前）和`DateTimeFormatter`（从 JDK8 开始）通用。下表列出了 JDK 文档中提供的最常见符号的完整列表：

| **字母** | **含义** | **演示** | **示例** |
| --- | --- | --- | --- |
| `y` | 年 | 年 | `1994; 94` |
| `M` | 月 | 数字/文本 | `7; 07; Jul; July; J` |
| `W` | 每月的一周 | 数字 | 4 |
| `E` | 星期几 | 文本 | `Tue; Tuesday; T` |
| `d` | 日期 | 数字 | 15 |
| `H` | 小时 | 数字 | 22 |
| `m` | 分钟 | 数字 | 34 |
| `s` | 秒 | 数字 | 55 |
| `S` | 秒的分数 | 数字 | 345 |
| `z` | 时区名称 | 时区名称 | `Pacific Standard Time; PST` |
| `Z` | 时区偏移 | 时区偏移 | `-0800` |
| `V` | 时区 ID（JDK8） | 时区 ID | `America/Los_Angeles; Z; -08:30` |

下表提供了一些格式模式示例：

| **模式** | **示例** |
| --- | --- |
| `yyyy-MM-dd` | `2019-02-24` |
| `MM-dd-yyyy` | `02-24-2019` |
| `MMM-dd-yyyy` | `Feb-24-2019` |
| `dd-MM-yy` | `24-02-19` |
| `dd.MM.yyyy` | `24.02.2019` |
| `yyyy-MM-dd HH:mm:ss` | `2019-02-24 11:26:26` |
| `yyyy-MM-dd HH:mm:ssSSS` | `2019-02-24 11:36:32743` |
| `yyyy-MM-dd HH:mm:ssZ` | `2019-02-24 11:40:35+0200` |
| `yyyy-MM-dd HH:mm:ss z` | `2019-02-24 11:45:03 EET` |
| `E MMM yyyy HH:mm:ss.SSSZ` | `Sun Feb 2019 11:46:32.393+0200` |
| `yyyy-MM-dd HH:MM:ss VV`（JDK8） | `2019-02-24 11:45:41 Europe/Athens` |

在 JDK8 之前，可以通过`SimpleDateFormat`应用格式模式：

```java
// yyyy-MM-dd
Date date = new Date();
SimpleDateFormat formatter = new SimpleDateFormat("yyyy-MM-dd");
String stringDate = formatter.format(date);
```

从 JDK8 开始，可以通过`DateTimeFormatter`应用格式模式：

*   对于`LocalDate`（ISO-8601 日历系统中没有时区的日期）：

```java
// yyyy-MM-dd
LocalDate localDate = LocalDate.now();
DateTimeFormatter formatterLocalDate 
  = DateTimeFormatter.ofPattern("yyyy-MM-dd");
String stringLD = formatterLocalDate.format(localDate);

// or shortly
String stringLD = LocalDate.now()
  .format(DateTimeFormatter.ofPattern("yyyy-MM-dd"));
```

*   对于`LocalTime`（ISO-8601 日历系统中没有时区的时间）：

```java
// HH:mm:ss
LocalTime localTime = LocalTime.now();
DateTimeFormatter formatterLocalTime 
  = DateTimeFormatter.ofPattern("HH:mm:ss");
String stringLT 
  = formatterLocalTime.format(localTime);

// or shortly
String stringLT = LocalTime.now()
  .format(DateTimeFormatter.ofPattern("HH:mm:ss"));
```

*   对于`LocalDateTime`（ISO-8601 日历系统中没有时区的日期时间）：

```java
// yyyy-MM-dd HH:mm:ss
LocalDateTime localDateTime = LocalDateTime.now();
DateTimeFormatter formatterLocalDateTime 
  = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
String stringLDT 
  = formatterLocalDateTime.format(localDateTime);

// or shortly
String stringLDT = LocalDateTime.now()
  .format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
```

*   对于`ZonedDateTime`（ISO-8601 日历系统中带时区的日期时间）：

```java
// E MMM yyyy HH:mm:ss.SSSZ
ZonedDateTime zonedDateTime = ZonedDateTime.now();
DateTimeFormatter formatterZonedDateTime 
  = DateTimeFormatter.ofPattern("E MMM yyyy HH:mm:ss.SSSZ");
String stringZDT 
  = formatterZonedDateTime.format(zonedDateTime);

// or shortly
String stringZDT = ZonedDateTime.now()
  .format(DateTimeFormatter
    .ofPattern("E MMM yyyy HH:mm:ss.SSSZ"));
```

*   对于`OffsetDateTime`（在 ISO-8601 日历系统中，与 UTC/GMT 有偏移的日期时间）：

```java
// E MMM yyyy HH:mm:ss.SSSZ
OffsetDateTime offsetDateTime = OffsetDateTime.now();
DateTimeFormatter formatterOffsetDateTime 
  = DateTimeFormatter.ofPattern("E MMM yyyy HH:mm:ss.SSSZ");
String odt1 = formatterOffsetDateTime.format(offsetDateTime);

// or shortly
String odt2 = OffsetDateTime.now()
  .format(DateTimeFormatter
    .ofPattern("E MMM yyyy HH:mm:ss.SSSZ"));
```

*   对于`OffsetTime`（在 ISO-8601 日历系统中与 UTC/GMT 有偏移的时间）：

```java
// HH:mm:ss,Z
OffsetTime offsetTime = OffsetTime.now();
DateTimeFormatter formatterOffsetTime 
  = DateTimeFormatter.ofPattern("HH:mm:ss,Z");
String ot1 = formatterOffsetTime.format(offsetTime);

// or shortly
String ot2 = OffsetTime.now()
  .format(DateTimeFormatter.ofPattern("HH:mm:ss,Z"));
```

# 60 获取没有时间/日期的当前日期/时间

在 JDK8 之前，解决方案必须集中在`java.util.Date`类上。绑定到本书的代码包含此解决方案。

从 JDK8 开始，日期和时间可以通过专用类`LocalDate`和`LocalTime`从`java.time`包中获得：

```java
// 2019-02-24
LocalDate onlyDate = LocalDate.now();

// 12:53:28.812637300
LocalTime onlyTime = LocalTime.now();
```

# 61 `LocalDate`和`LocalTime`中的`LocalDateTime`

`LocalDateTime`类公开了一系列`of()`方法，这些方法可用于获取`LocalDateTime`的不同类型的实例。例如，从年、月、日、时、分、秒或纳秒获得的`LocalDateTime`类如下所示：

```java
LocalDateTime ldt = LocalDateTime.of​(2020, 4, 1, 12, 33, 21, 675);
```

因此，前面的代码将日期和时间组合为`of()`方法的参数。为了将日期和时间组合为对象，解决方案可以利用以下`of()`方法：

```java
public static LocalDateTime of​(LocalDate date, LocalTime time)
```

这导致`LocalDate`和`LocalTime`，如下所示：

```java
LocalDate localDate = LocalDate.now(); // 2019-Feb-24
LocalTime localTime = LocalTime.now(); // 02:08:10 PM
```

它们可以组合在一个对象`LocalDateTime`中，如下所示：

```java
LocalDateTime localDateTime = LocalDateTime.of(localDate, localTime);
```

格式化`LocalDateTime`显示日期和时间如下：

```java
// 2019-Feb-24 02:08:10 PM
String localDateTimeAsString = localDateTime
  .format(DateTimeFormatter.ofPattern("yyyy-MMM-dd hh:mm:ss a"));
```

# 62 通过`Instant`类的机器时间

JDK8 附带了一个新类，名为`java.time.Instant`。主要地，`Instant`类表示时间线上的一个瞬时点，从 1970 年 1 月 1 日（纪元）的第一秒开始，在 UTC 时区，分辨率为纳秒。

Java8`Instant`类在概念上类似于`java.util.Date`。两者都代表 UTC 时间线上的一个时刻。当`Instant`的分辨率高达纳秒时，`java.util.Date`的分辨率为毫秒。

这个类对于生成机器时间的时间戳非常方便。为了获得这样的时间戳，只需调用如下的`now()`方法：

```java
// 2019-02-24T15:05:21.781049600Z
Instant timestamp = Instant.now();
```

使用以下代码段可以获得类似的输出：

```java
OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
```

或者，使用以下代码段：

```java
Clock clock = Clock.systemUTC();
```

调用`Instant.toString()`产生一个输出，该输出遵循 ISO-8601 标准来表示日期和时间。

# 将字符串转换为`Instant`

遵循 ISO-8601 标准表示日期和时间的字符串可以通过`Instant.parse()`方法轻松转换为`Instant`，如下例所示：

```java
// 2019-02-24T14:31:33.197021300Z
Instant timestampFromString =
  Instant.parse("2019-02-24T14:31:33.197021300Z");
```

# 向`Instant`添加/减去时间

对于添加时间，`Instant`有一套方法。例如，向当前时间戳添加 2 小时可以如下完成：

```java
Instant twoHourLater = Instant.now().plus(2, ChronoUnit.HOURS);
```

在减去时间方面，例如 10 分钟，请使用以下代码段：

```java
Instant tenMinutesEarlier = Instant.now()
  .minus(10, ChronoUnit.MINUTES);
```

除`plus()`方法外，`Instant`还包含`plusNanos()`、`plusMillis()`、`plusSeconds()`。此外，除了`minus()`方法外，`Instant`还包含`minusNanos()`、`minusMillis()`、`minusSeconds()`。

# 比较`Instant`对象

比较两个`Instant`对象可以通过`Instant.isAfter()`和`Instant.isBefore()`方法来完成。例如，让我们看看以下两个`Instant`对象：

```java
Instant timestamp1 = Instant.now();
Instant timestamp2 = timestamp1.plusSeconds(10);
```

检查`timestamp1`是否在`timestamp2`之后：

```java
boolean isAfter = timestamp1.isAfter(timestamp2); // false
```

检查`timestamp1`是否在`timestamp2`之前：

```java
boolean isBefore = timestamp1.isBefore(timestamp2); // true
```

两个`Instant`对象之间的时差可以通过`Instant.until()`方法计算：

```java
// 10 seconds
long difference = timestamp1.until(timestamp2, ChronoUnit.SECONDS);
```

# 在`Instant`和`LocalDateTime`、`ZonedDateTime`和`OffsetDateTime`之间转换

这些常见的转换可以在以下示例中完成：

*   在`Instant`和`LocalDateTime`之间转换-因为`LocalDateTime`不知道时区，所以使用零偏移 UTC+0：

```java
// 2019-02-24T15:27:13.990103700
LocalDateTime ldt = LocalDateTime.ofInstant(
  Instant.now(), ZoneOffset.UTC);

// 2019-02-24T17:27:14.013105Z
Instant instantLDT = LocalDateTime.now().toInstant(ZoneOffset.UTC);
```

*   在`Instant`和`ZonedDateTime`之间转换—将`Instant`UTC+0 转换为巴黎`ZonedDateTime`UTC+1：

```java
// 2019-02-24T16:34:36.138393100+01:00[Europe/Paris]
ZonedDateTime zdt = Instant.now().atZone(ZoneId.of("Europe/Paris"));

// 2019-02-24T16:34:36.150393800Z
Instant instantZDT = LocalDateTime.now()
  .atZone(ZoneId.of("Europe/Paris")).toInstant();
```

*   在`Instant`和`OffsetDateTime`之间转换-指定 2 小时的偏移量：

```java
// 2019-02-24T17:34:36.151393900+02:00
OffsetDateTime odt = Instant.now().atOffset(ZoneOffset.of("+02:00"));

// 2019-02-24T15:34:36.153394Z
Instant instantODT = LocalDateTime.now()
  .atOffset(ZoneOffset.of("+02:00")).toInstant();
```

# 63 使用基于日期的值定义时段，使用基于时间的值定义持续时间

JDK8 附带了两个新类，分别命名为`java.time.Period`和`java.time.Duration`。让我们在下一节中详细了解它们。

# 使用基于日期的值的时间段

`Period`类意味着使用基于日期的值（年、月、周和天）来表示时间量。这段时间可以用不同的方法获得。例如，120 天的周期可以如下获得：

```java
Period fromDays = Period.ofDays(120); // P120D
```

在`ofDays()`方法旁边，`Period`类还有`ofMonths()`、`ofWeeks()`和`ofYears()`。

或者，通过`of()`方法可以得到 2000 年 11 个月 24 天的期限，如下所示：

```java
Period periodFromUnits = Period.of(2000, 11, 24); // P2000Y11M24D
```

`Period`也可以从`LocalDate`中得到：

```java
LocalDate localDate = LocalDate.now();
Period periodFromLocalDate = Period.of(localDate.getYear(),
  localDate.getMonthValue(), localDate.getDayOfMonth());
```

最后，可以从遵循 ISO-8601 周期格式`PnYnMnD`和`PnW`的`String`对象获得`Period`。例如，`P2019Y2M25D`字符串表示 2019 年、2 个月和 25 天：

```java
Period periodFromString = Period.parse("P2019Y2M25D");
```

调用`Period.toString()`将返回时间段，同时也遵循 ISO-8601 时间段格式，`PnYnMnD`和`PnW`（例如`P120D`、`P2000Y11M24D`）。

但是，当`Period`被用来表示两个日期之间的一段时间（例如`LocalDate`时，`Period`的真实力量就显现出来了。2018 年 3 月 12 日至 2019 年 7 月 20 日期间可表示为：

```java
LocalDate startLocalDate = LocalDate.of(2018, 3, 12);
LocalDate endLocalDate = LocalDate.of(2019, 7, 20);
Period periodBetween = Period.between(startLocalDate, endLocalDate);
```

年、月、日的时间量可以通过`Period.getYears()`、`Period.getMonths()`、`Period.getDays()`获得。例如，以下辅助方法使用这些方法将时间量输出为字符串：

```java
public static String periodToYMD(Period period) {

  StringBuilder sb = new StringBuilder();

  sb.append(period.getYears())
   .append("y:")
   .append(period.getMonths())
   .append("m:")
   .append(period.getDays())
   .append("d");

 return sb.toString();
}
```

我们将此方法称为`periodBetween`（差值为 1 年 4 个月 8 天）：

```java
periodToYMD(periodBetween); // 1y:4m:8d
```

当确定某个日期是否早于另一个日期时，`Period`类也很有用。有一个标志方法，名为`isNegative()`。有一个`A`周期和一个`B`周期，如果`B`在`A`之前，应用`Period.between(A, B)`的结果可以是负的，如果`A`在`B`之前，应用`isNegative()`的结果可以是正的，如果`B`在`A`之前，`false`在`A`之前，则`isNegative()`返回`true B`，如我们的例子所示（基本上，如果年、月或日为负数，此方法返回`false`）：

```java
// returns false, since 12 March 2018 is earlier than 20 July 2019
periodBetween.isNegative();
```

最后，`Period`可以通过加上或减去一段时间来修改。方法有`plusYears()`、`plusMonths()`、`plusDays()`、`minusYears()`、`minusMonths()`、`minusDays()`等。例如，在`periodBetween`上加 1 年可以如下操作：

```java
Period periodBetweenPlus1Year = periodBetween.plusYears(1L);
```

添加两个`Period`类可以通过`Period.plus()`方法完成，如下所示：

```java
Period p1 = Period.ofDays(5);
Period p2 = Period.ofDays(20);
Period p1p2 = p1.plus(p2); // P25D
```

# 使用基于时间的值的持续时间

`Duration`类意味着使用基于时间的值（小时、分钟、秒或纳秒）来表示时间量。这种持续时间可以通过不同的方式获得。例如，可以如下获得 10 小时的持续时间：

```java
Duration fromHours = Duration.ofHours(10); // PT10H
```

在`ofHours()`方法旁边，`Duration`类还有`ofDays()`、`ofMillis()`、`ofMinutes()`、`ofSeconds()`和`ofNanos()`。

或者，可以通过`of()`方法获得 3 分钟的持续时间，如下所示：

```java
Duration fromMinutes = Duration.of(3, ChronoUnit.MINUTES); // PT3M
```

`Duration`也可以从`LocalDateTime`中得到：

```java
LocalDateTime localDateTime 
  = LocalDateTime.of(2018, 3, 12, 4, 14, 20, 670);

// PT14M
Duration fromLocalDateTime 
  = Duration.ofMinutes(localDateTime.getMinute());
```

也可从`LocalTime`中获得：

```java
LocalTime localTime = LocalTime.of(4, 14, 20, 670);

// PT0.00000067S
Duration fromLocalTime = Duration.ofNanos(localTime.getNano());
```

最后，可以从遵循 ISO-8601 持续时间格式`PnDTnHnMn.nS`的`String`对象获得`Duration`，其中天被认为正好是 24 小时。例如，`P2DT3H4M`字符串有 2 天 3 小时 4 分钟：

```java
Duration durationFromString = Duration.parse("P2DT3H4M");
```

调用`Duration.toString()`将返回符合 ISO-8601 持续时间格式的持续时间`PnDTnHnMn.nS`（例如，`PT10H`、`PT3M`或`PT51H4M`）。

但是，与`Period`的情况一样，当`Duration`用于表示两次之间的时间段（例如，`Instant`时，揭示了它的真实功率。从 2015 年 11 月 3 日 12:11:30 到 2016 年 12 月 6 日 15:17:10 之间的持续时间可以表示为两个`Instant`类之间的差异，如下所示：

```java
Instant startInstant = Instant.parse("2015-11-03T12:11:30.00Z");
Instant endInstant = Instant.parse("2016-12-06T15:17:10.00Z");

// PT10059H5M40S
Duration durationBetweenInstant 
  = Duration.between(startInstant, endInstant);
```

以秒为单位，可通过`Duration.getSeconds()`方法获得该差值：

```java
durationBetweenInstant.getSeconds(); // 36212740 seconds
```

或者，从 2018 年 3 月 12 日 04:14:20.000000670 到 2019 年 7 月 20 日 06:10:10.000000720 之间的持续时间可以表示为两个`LocalDateTime`对象之间的差异，如下所示：

```java
LocalDateTime startLocalDateTime 
  = LocalDateTime.of(2018, 3, 12, 4, 14, 20, 670);
LocalDateTime endLocalDateTime 
  = LocalDateTime.of(2019, 7, 20, 6, 10, 10, 720);
// PT11881H55M50.00000005S, or 42774950 seconds
Duration durationBetweenLDT 
  = Duration.between(startLocalDateTime, endLocalDateTime);
```

最后，04:14:20.000000670 和 06:10:10.000000720 之间的持续时间可以表示为两个`LocalTime`对象之间的差异，如下所示：

```java
LocalTime startLocalTime = LocalTime.of(4, 14, 20, 670);
LocalTime endLocalTime = LocalTime.of(6, 10, 10, 720);

// PT1H55M50.00000005S, or 6950 seconds
Duration durationBetweenLT 
  = Duration.between(startLocalTime, endLocalTime);
```

在前面的例子中，`Duration`通过`Duration.getSeconds()`方法以秒表示，这是`Duration`类中的秒数。然而，`Duration`类包含一组方法，这些方法专用于通过`toDays()`以天为单位、通过`toHours()`以小时为单位、通过`toMinutes()`以分钟为单位、通过`toMillis()`以毫秒为单位、通过`toNanos()`以纳秒为单位来表达`Duration`。

从一个时间单位转换到另一个时间单位可能会产生残余。例如，从秒转换为分钟可能导致秒的剩余（例如，65 秒是 1 分钟，5 秒是剩余）。残差可以通过以下一组方法获得：天残差通过`toDaysPart()`，小时残差通过`toHoursPart()`，分钟残差通过`toMinutesPart()`等等。

假设差异应该显示为天：小时：分：秒：纳秒（例如，`9d:2h:15m:20s:230n`）。将`toFoo()`和`toFooPart()`方法的力结合在一个辅助方法中将产生以下代码：

```java
public static String durationToDHMSN(Duration duration) {

  StringBuilder sb = new StringBuilder();
  sb.append(duration.toDays())
    .append("d:")
    .append(duration.toHoursPart())
    .append("h:")
    .append(duration.toMinutesPart())
    .append("m:")
    .append(duration.toSecondsPart())
    .append("s:")
    .append(duration.toNanosPart())
    .append("n");

  return sb.toString();
}
```

让我们调用这个方法`durationBetweenLDT`（差别是 495 天 1 小时 55 分 50 秒 50 纳秒）：

```java
// 495d:1h:55m:50s:50n
durationToDHMSN(durationBetweenLDT);
```

与`Period`类相同，`Duration`类有一个名为`isNegative()`的标志方法。当确定某个特定时间是否早于另一个时间时，此方法很有用。有持续时间`A`和持续时间`B`，如果`B`在`A`之前，应用`Duration.between(A, B)`的结果可以是负的，如果`A`在`B`之前，应用`Duration.between(A, B)`的结果可以是正的，进一步逻辑，`isNegative()`如果`B`在`A`之前，则返回`true`，如果`A`在`B`之前，则返回`false`，如以下情况：

```java
durationBetweenLT.isNegative(); // false
```

最后，`Duration`可以通过增加或减少持续时间来修改。有`plusDays()`、`plusHours()`、`plusMinutes()`、`plusMillis()`、`plusNanos()`、`minusDays()`、`minusHours()`、`minusMinutes()`、`minusMillis()`和`minusNanos()`等方法来执行此操作。例如，向`durationBetweenLT`添加 5 小时可以如下所示：

```java
Duration durationBetweenPlus5Hours = durationBetweenLT.plusHours(5);
```

添加两个`Duration`类可以通过`Duration.plus()`方法完成，如下所示：

```java
Duration d1 = Duration.ofMinutes(20);
Duration d2 = Duration.ofHours(2);

Duration d1d2 = d1.plus(d2);

System.out.println(d1 + "+" + d2 + "=" + d1d2); // PT2H20M
```

# 64 获取日期和时间单位

对于`Date`对象，解决方案可能依赖于`Calendar`实例。绑定到本书的代码包含此解决方案。

对于 JDK8 类，Java 提供了专用的`getFoo()`方法和`get​(TemporalField field)`方法。例如，假设下面的`LocalDateTime`对象：

```java
LocalDateTime ldt = LocalDateTime.now();
```

依靠`getFoo()`方法，我们得到如下代码：

```java
int year = ldt.getYear();
int month = ldt.getMonthValue();
int day = ldt.getDayOfMonth();
int hour = ldt.getHour();
int minute = ldt.getMinute();
int second = ldt.getSecond();
int nano = ldt.getNano();
```

或者，依赖于`get​(TemporalField field)`结果如下：

```java
int yearLDT = ldt.get(ChronoField.YEAR);
int monthLDT = ldt.get(ChronoField.MONTH_OF_YEAR);
int dayLDT = ldt.get(ChronoField.DAY_OF_MONTH);
int hourLDT = ldt.get(ChronoField.HOUR_OF_DAY);
int minuteLDT = ldt.get(ChronoField.MINUTE_OF_HOUR);
int secondLDT = ldt.get(ChronoField.SECOND_OF_MINUTE);
int nanoLDT = ldt.get(ChronoField.NANO_OF_SECOND);
```

请注意，月份是从 1 开始计算的，即 1 月。

例如，`2019-02-25T12:58:13.109389100`的`LocalDateTime`对象可以被切割成日期时间单位，结果如下：

```java
Year: 2019 Month: 2 Day: 25 Hour: 12 Minute: 58 Second: 13 Nano: 109389100
```

通过一点直觉和文档，很容易将此示例改编为`LocalDate`、`LocalTime`、`ZonedDateTime`和其他示例。

# 65 日期时间的加减

这个问题的解决方案依赖于专用于处理日期和时间的 Java API。让我们在下一节中看看它们。

# 使用`Date`

对于`Date`对象，解决方案可能依赖于`Calendar`实例。绑定到本书的代码包含此解决方案。

# 使用`LocalDateTime`

跳转到 JDK8，重点是`LocalDate`、`LocalTime`、`LocalDateTime`、`Instant`等等。新的 Java 日期时间 API 提供了专门用于加减时间量的方法。`LocalDate`、`LocalTime`、`LocalDateTime`、`ZonedDateTime`、`OffsetDateTime`、`Instant`、`Period`、`Duration`以及许多其他方法，如`plusFoo()`和`minusFoo()`，其中`Foo`可以用单位替换时间（例如，`plusYears()`、`plusMinutes()`、`minusHours()`、`minusSeconds()`等等）。

假设如下`LocalDateTime`：

```java
// 2019-02-25T14:55:06.651155500
LocalDateTime ldt = LocalDateTime.now();
```

加 10 分钟和调用`LocalDateTime.plusMinutes(long minutes)`一样简单，减 10 分钟和调用`LocalDateTime.minusMinutes(long minutes)`一样简单：

```java
LocalDateTime ldtAfterAddingMinutes = ldt.plusMinutes(10);
LocalDateTime ldtAfterSubtractingMinutes = ldt.minusMinutes(10);
```

输出将显示以下日期：

```java
After adding 10 minutes: 2019-02-25T15:05:06.651155500
After subtracting 10 minutes: 2019-02-25T14:45:06.651155500
```

除了每个时间单位专用的方法外，这些类还支持`plus/minus(TemporalAmount amountToAdd)`和`plus/minus(long amountToAdd, TemporalUnit unit)`。

现在，让我们关注`Instant`类。除了`plus/minusSeconds()`、`plus/minusMillis()`、`plus/minusNanos()`之外，`Instant`类还提供了`plus/minus(TemporalAmount amountToAdd)`方法。

为了举例说明这个方法，我们假设如下`Instant`：

```java
// 2019-02-25T12:55:06.654155700Z
Instant timestamp = Instant.now();
```

现在，让我们加减 5 个小时：

```java
Instant timestampAfterAddingHours 
  = timestamp.plus(5, ChronoUnit.HOURS);
Instant timestampAfterSubtractingHours 
  = timestamp.minus(5, ChronoUnit.HOURS);
```

输出将显示以下`Instant`：

```java
After adding 5 hours: 2019-02-25T17:55:06.654155700Z
After subtracting 5 hours: 2019-02-25T07:55:06.654155700Z
```

# 66 使用 UTC 和 GMT 获取所有时区

UTC 和 GMT 被认为是处理日期和时间的标准参考。今天，UTC 是首选的方法，但是 UTC 和 GMT 在大多数情况下应该返回相同的结果。

为了获得 UTC 和 GMT 的所有时区，解决方案应该关注 JDK8 前后的实现。所以，让我们从 JDK8 之前有用的解决方案开始。

# JDK8 之前

解决方案需要提取可用的时区 ID（非洲/巴马科、欧洲/贝尔格莱德等）。此外，每个时区 ID 都应该用来创建一个`TimeZone`对象。最后，解决方案需要提取特定于每个时区的偏移量，并考虑到夏令时。绑定到本书的代码包含此解决方案。

# 从 JDK8 开始

新的 Java 日期时间 API 为解决这个问题提供了新的工具。

在第一步，可用的时区 id 可以通过`ZoneId`类获得，如下所示：

```java
Set<String> zoneIds = ZoneId.getAvailableZoneIds();
```

在第二步，每个时区 ID 都应该用来创建一个`ZoneId`实例。这可以通过`ZoneId.of(String zoneId)`方法实现：

```java
ZoneId zoneid = ZoneId.of(current_zone_Id);
```

在第三步，每个`ZoneId`可用于获得特定于所识别区域的时间。这意味着需要一个“实验室老鼠”参考日期时间。此参考日期时间（无时区，`LocalDateTime.now()`）通过`LocalDateTime.atZone()`与给定时区（`ZoneId`）组合，以获得`ZoneDateTime`（可识别时区的日期时间）：

```java
LocalDateTime now = LocalDateTime.now();
ZonedDateTime zdt = now.atZone(ZoneId.of(zone_id_instance));
```

`atZone()`方法尽可能地匹配日期时间，同时考虑时区规则，例如夏令时。

在第四步，代码可以利用`ZonedDateTime`来提取 UTC 偏移量（例如，对于欧洲/布加勒斯特，UTC 偏移量为`+02:00`）：

```java
String utcOffset = zdt.getOffset().getId().replace("Z", "+00:00");
```

`getId()`方法返回规范化区域偏移 ID，`+00:00`偏移作为`Z`字符返回；因此代码需要快速将`Z`替换为`+00:00`，以便与其他偏移对齐，这些偏移遵循`+hh:mm`或`+hh:mm:ss`格式。

现在，让我们将这些步骤合并到一个辅助方法中：

```java
public static List<String> fetchTimeZones(OffsetType type) {

  List<String> timezones = new ArrayList<>();
  Set<String> zoneIds = ZoneId.getAvailableZoneIds();
  LocalDateTime now = LocalDateTime.now();

  zoneIds.forEach((zoneId) -> {
    timezones.add("(" + type + now.atZone(ZoneId.of(zoneId))
      .getOffset().getId().replace("Z", "+00:00") + ") " + zoneId);
  });

  return timezones;
}
```

假设此方法存在于`DateTimes`类中，则获得以下代码：

```java
List<String> timezones 
  = DateTimes.fetchTimeZones(DateTimes.OffsetType.GMT);
Collections.sort(timezones); // optional sort
timezones.forEach(System.out::println);
```

此外，还显示了一个输出快照，如下所示：

```java
(GMT+00:00) Africa/Abidjan
(GMT+00:00) Africa/Accra
(GMT+00:00) Africa/Bamako
...
(GMT+11:00) Australia/Tasmania
(GMT+11:00) Australia/Victoria
...
```

# 67 获取所有可用时区中的本地日期时间

可通过以下步骤获得此问题的解决方案：

1.  获取本地日期和时间。
2.  获取可用时区。
3.  在 JDK8 之前，使用`SimpleDateFormat`和`setTimeZone()`方法。
4.  从 JDK8 开始，使用`ZonedDateTime`。

# JDK8 之前

在 JDK8 之前，获取当前本地日期时间的快速解决方案是调用`Date`空构造器。此外，还可以使用`Date`在所有可用的时区中显示，这些时区可以通过`TimeZone`类获得。绑定到本书的代码包含此解决方案。

# 从 JDK8 开始

从 JDK8 开始，获取默认时区中当前本地日期时间的一个方便解决方案是调用`ZonedDateTime.now()`方法：

```java
ZonedDateTime zlt = ZonedDateTime.now();
```

所以，这是默认时区中的当前日期。此外，该日期应显示在通过`ZoneId`类获得的所有可用时区中：

```java
Set<String> zoneIds = ZoneId.getAvailableZoneIds();
```

最后，代码可以循环`zoneIds`，对于每个区域 ID，可以调用`ZonedDateTime.withZoneSameInstant(ZoneId zone)`方法。此方法返回具有不同时区的此日期时间的副本，并保留以下瞬间：

```java
public static List<String> localTimeToAllTimeZones() {

  List<String> result = new ArrayList<>();
  Set<String> zoneIds = ZoneId.getAvailableZoneIds();
  DateTimeFormatter formatter 
    = DateTimeFormatter.ofPattern("yyyy-MMM-dd'T'HH:mm:ss a Z");
  ZonedDateTime zlt = ZonedDateTime.now();

  zoneIds.forEach((zoneId) -> {
    result.add(zlt.format(formatter) + " in " + zoneId + " is "
      + zlt.withZoneSameInstant(ZoneId.of(zoneId))
        .format(formatter));
  });

  return result;
}
```

此方法的输出快照可以如下所示：

```java
2019-Feb-26T14:26:30 PM +0200 in Africa/Nairobi 
  is 2019-Feb-26T15:26:30 PM +0300
2019-Feb-26T14:26:30 PM +0200 in America/Marigot 
  is 2019-Feb-26T08:26:30 AM -0400
...
2019-Feb-26T14:26:30 PM +0200 in Pacific/Samoa 
  is 2019-Feb-26T01:26:30 AM -1100
```

# 68 显示航班的日期时间信息

本节提供的解决方案将显示有关从澳大利亚珀斯到欧洲布加勒斯特的 15 小时 30 分钟航班的以下信息：

*   UTC 出发和到达日期时间
*   离开珀斯的日期时间和到达布加勒斯特的日期时间
*   离开和到达布加勒斯特的日期时间

假设从珀斯出发的参考日期时间为 2019 年 2 月 26 日 16:00（或下午 4:00）：

```java
LocalDateTime ldt = LocalDateTime.of(
  2019, Month.FEBRUARY, 26, 16, 00);
```

首先，让我们将这个日期时间与澳大利亚/珀斯（+08:00）的时区结合起来。这将产生一个特定于澳大利亚/珀斯的`ZonedDateTime`对象（这是出发时珀斯的时钟日期和时间）：

```java
// 04:00 PM, Feb 26, 2019 +0800 Australia/Perth
ZonedDateTime auPerthDepart 
  = ldt.atZone(ZoneId.of("Australia/Perth"));
```

此外，让我们在`ZonedDateTime`中加上 15 小时 30 分钟。结果`ZonedDateTime`表示珀斯的日期时间（这是抵达布加勒斯特时珀斯的时钟日期和时间）：

```java
// 07:30 AM, Feb 27, 2019 +0800 Australia/Perth
ZonedDateTime auPerthArrive 
  = auPerthDepart.plusHours(15).plusMinutes(30);
```

现在，让我们计算一下布加勒斯特的日期时间和珀斯的出发日期时间。基本上，以下代码表示从布加勒斯特时区的珀斯时区出发的日期和时间：

```java
// 10:00 AM, Feb 26, 2019 +0200 Europe/Bucharest
ZonedDateTime euBucharestDepart 
  = auPerthDepart.withZoneSameInstant(ZoneId.of("Europe/Bucharest"));
```

最后，让我们计算一下到达布加勒斯特的日期和时间。以下代码表示布加勒斯特时区珀斯时区的到达日期时间：

```java
// 01:30 AM, Feb 27, 2019 +0200 Europe/Bucharest
ZonedDateTime euBucharestArrive 
  = auPerthArrive.withZoneSameInstant(ZoneId.of("Europe/Bucharest"));
```

如下图所示，从珀斯出发的 UTC 时间是上午 8:00，而到达布加勒斯特的 UTC 时间是晚上 11:30：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-cd-prob/img/09ecaf27-f809-42b1-8858-ecf44aa33d5f.png)

这些时间可以很容易地提取为`OffsetDateTime`，如下所示：

```java
// 08:00 AM, Feb 26, 2019
OffsetDateTime utcAtDepart = auPerthDepart.withZoneSameInstant(
  ZoneId.of("UTC")).toOffsetDateTime();

// 11:30 PM, Feb 26, 2019
OffsetDateTime utcAtArrive = auPerthArrive.withZoneSameInstant(
  ZoneId.of("UTC")).toOffsetDateTime();
```

# 69 将 Unix 时间戳转换为日期时间

对于这个解决方案，假设下面的 Unix 时间戳是 1573768800。此时间戳等效于以下内容：

*   `11/14/2019 @ 10:00pm (UTC)`
*   ISO-8601 中的`2019-11-14T22:00:00+00:00`
*   `Thu, 14 Nov 2019 22:00:00 +0000`，RFC 822、1036、1123、2822
*   `Thursday, 14-Nov-19 22:00:00 UTC`，RFC 2822
*   `2019-11-14T22:00:00+00:00`在 RFC 3339 中

为了将 Unix 时间戳转换为日期时间，必须知道 Unix 时间戳的分辨率以秒为单位，而`java.util.Date`需要毫秒。因此，从 Unix 时间戳获取`Date`对象的解决方案需要将 Unix 时间戳乘以 1000，从秒转换为毫秒，如下两个示例所示：

```java
long unixTimestamp = 1573768800;

// Fri Nov 15 00:00:00 EET 2019 - in the default time zone
Date date = new Date(unixTimestamp * 1000L);

// Fri Nov 15 00:00:00 EET 2019 - in the default time zone
Date date = new Date(TimeUnit.MILLISECONDS
  .convert(unixTimestamp, TimeUnit.SECONDS));
```

从 JDK8 开始，`Date`类使用`from(Instant instant)`方法。此外，`Instant`类附带了`ofEpochSecond(long epochSecond)`方法，该方法使用`1970-01-01T00:00:00Z`的纪元的给定秒数返回`Instant`的实例：

```java
// 2019-11-14T22:00:00Z in UTC
Instant instant = Instant.ofEpochSecond(unixTimestamp);

// Fri Nov 15 00:00:00 EET 2019 - in the default time zone
Date date = Date.from(instant);
```

上一示例中获得的瞬间可用于创建`LocalDateTime`或`ZonedDateTime`，如下所示：

```java
// 2019-11-15T06:00
LocalDateTime date = LocalDateTime
  .ofInstant(instant, ZoneId.of("Australia/Perth"));

// 2019-Nov-15 00:00:00 +0200 Europe/Bucharest
ZonedDateTime date = ZonedDateTime
  .ofInstant(instant, ZoneId.of("Europe/Bucharest"));
```

# 70 查找每月的第一天/最后一天

这个问题的正确解决将依赖于 JDK8、`Temporal`和`TemporalAdjuster`接口。

`Temporal`接口位于日期和时间的表示后面。换句话说，表示日期和/或时间的类实现了这个接口。例如，以下类只是实现此接口的几个类：

*   `LocalDate`（ISO-8601 日历系统中没有时区的日期）
*   `LocalTime`（ISO-8601 日历系统中无时区的时间）
*   `LocalDateTime`（ISO-8601 日历系统中无时区的日期时间）
*   `ZonedDateTime`（ISO-8601 日历系统中带时区的日期时间），依此类推
*   `OffsetDateTime`（在 ISO-8601 日历系统中，从 UTC/格林威治时间偏移的日期时间）
*   `HijrahDate`（希吉拉历法系统中的日期）

`TemporalAdjuster`类是一个函数式接口，它定义了可用于调整`Temporal`对象的策略。除了可以定义自定义策略外，`TemporalAdjuster`类还提供了几个预定义的策略，如下所示（文档包含了整个列表，非常令人印象深刻）：

*   `firstDayOfMonth()`（返回当月第一天）
*   `lastDayOfMonth()`（返回当月最后一天）
*   `firstDayOfNextMonth()`（次月 1 日返回）
*   `firstDayOfNextYear()`（次年第一天返回）

注意，前面列表中的前两个调整器正是这个问题所需要的。

考虑一个修正-`LocalDate`：

```java
LocalDate date = LocalDate.of(2019, Month.FEBRUARY, 27);
```

让我们看看二月的第一天/最后一天是什么时候：

```java
// 2019-02-01
LocalDate firstDayOfFeb 
  = date.with(TemporalAdjusters.firstDayOfMonth());

// 2019-02-28
LocalDate lastDayOfFeb 
  = date.with(TemporalAdjusters.lastDayOfMonth());
```

看起来依赖预定义的策略非常简单。但是，假设问题要求您查找 2019 年 2 月 27 日之后的 21 天，也就是 2019 年 3 月 20 日。对于这个问题，没有预定义的策略，因此需要自定义策略。此问题的解决方案可以依赖 Lambda 表达式，如以下辅助方法中所示：

```java
public static LocalDate getDayAfterDays(
    LocalDate startDate, int days) {

  Period period = Period.ofDays(days);
  TemporalAdjuster ta = p -> p.plus(period);
  LocalDate endDate = startDate.with(ta);

  return endDate;
}
```

如果此方法存在于名为`DateTimes`的类中，则以下调用将返回预期结果：

```java
// 2019-03-20
LocalDate datePlus21Days = DateTimes.getDayAfterDays(date, 21);
```

遵循相同的技术，但依赖于`static`工厂方法`ofDateAdjuster()`，下面的代码片段定义了一个静态调整器，返回下一个星期六的日期：

```java
static TemporalAdjuster NEXT_SATURDAY 
    = TemporalAdjusters.ofDateAdjuster(today -> {

  DayOfWeek dayOfWeek = today.getDayOfWeek();

  if (dayOfWeek == DayOfWeek.SATURDAY) {
    return today;
  }

  if (dayOfWeek == DayOfWeek.SUNDAY) {
    return today.plusDays(6);
  }

  return today.plusDays(6 - dayOfWeek.getValue());
});
```

我们将此方法称为 2019 年 2 月 27 日（下一个星期六是 2019 年 3 月 2 日）：

```java
// 2019-03-02
LocalDate nextSaturday = date.with(NEXT_SATURDAY);
```

最后，这个函数式接口定义了一个名为`adjustInto()`的`abstract`方法。在自定义实现中，可以通过向该方法传递一个`Temporal`对象来覆盖该方法，如下所示：

```java
public class NextSaturdayAdjuster implements TemporalAdjuster {

  @Override
  public Temporal adjustInto(Temporal temporal) {

    DayOfWeek dayOfWeek = DayOfWeek
      .of(temporal.get(ChronoField.DAY_OF_WEEK));

    if (dayOfWeek == DayOfWeek.SATURDAY) {
      return temporal;
    }

    if (dayOfWeek == DayOfWeek.SUNDAY) {
      return temporal.plus(6, ChronoUnit.DAYS);
    }

    return temporal.plus(6 - dayOfWeek.getValue(), ChronoUnit.DAYS);
  }
}
```

下面是用法示例：

```java
NextSaturdayAdjuster nsa = new NextSaturdayAdjuster();

// 2019-03-02
LocalDate nextSaturday = date.with(nsa);
```

# 71 定义/提取区域偏移

通过*区域偏移*，我们了解需要从 GMT/UTC 时间中添加/减去的时间量，以便获得全球特定区域（例如，澳大利亚珀斯）的日期时间。通常，区域偏移以固定的小时和分钟数打印：`+02:00`、`-08:30`、`+0400`、`UTC+01:00`，依此类推。

因此，简而言之，时区偏移量是指时区与 GMT/UTC 之间的时间差。

# JDK8 之前

在 JDK8 之前，可以通过`java.util.TimeZone`定义一个时区，有了这个时区，代码就可以通过`TimeZone.getRawOffset()`方法得到时区偏移量（*原始*部分来源于这个方法不考虑夏令时）。绑定到本书的代码包含此解决方案。

# 从 JDK8 开始

从 JDK8 开始，有两个类负责处理时区表示。首先是`java.time.ZoneId`，表示欧洲雅典等时区；其次是`java.time.ZoneOffset`（扩展`ZoneId`），表示指定时区的固定时间（偏移量），以 GMT/UTC 表示。

新的 Java 日期时间 API 默认处理夏令时；因此，使用夏令时的夏-冬周期区域将有两个`ZoneOffset`类。

UTC 区域偏移量可以很容易地获得，如下所示（这是`+00:00`，在 Java 中用`Z`字符表示）：

```java
// Z
ZoneOffset zoneOffsetUTC = ZoneOffset.UTC;
```

系统默认时区也可以通过`ZoneOffset`类获取：

```java
// Europe/Athens
ZoneId defaultZoneId = ZoneOffset.systemDefault();
```

为了使用夏令时进行分区偏移，代码需要将日期时间与其关联。例如，关联一个`LocalDateTime`类（也可以使用`Instant`），如下所示：

```java
// by default it deals with the Daylight Saving Times
LocalDateTime ldt = LocalDateTime.of(2019, 6, 15, 0, 0);
ZoneId zoneId = ZoneId.of("Europe/Bucharest");

// +03:00
ZoneOffset zoneOffset = zoneId.getRules().getOffset(ldt);
```

区域偏移量也可以从字符串中获得。例如，以下代码获得`+02:00`的分区偏移：

```java
ZoneOffset zoneOffsetFromString = ZoneOffset.of("+02:00");
```

这是一种非常方便的方法，可以将区域偏移快速添加到支持区域偏移的`Temporal`对象。例如，使用它将区域偏移添加到`OffsetTime`和`OffsetDateTime`（用于在数据库中存储日期或通过电线发送的方便方法）：

```java
OffsetTime offsetTime = OffsetTime.now(zoneOffsetFromString);
OffsetDateTime offsetDateTime 
  = OffsetDateTime.now(zoneOffsetFromString);
```

我们问题的另一个解决方法是依赖于从小时、分钟和秒来定义`ZoneOffset`。`ZoneOffset`的一个助手方法专门用于：

```java
// +08:30 (this was obtained from 8 hours and 30 minutes)
ZoneOffset zoneOffsetFromHoursMinutes 
  = ZoneOffset.ofHoursMinutes(8, 30);
```

在`ZoneOffset.ofHoursMinutes()`旁边有`ZoneOffset.ofHours()`、`ofHoursMinutesSeconds()`和`ofTotalSeconds()`。

最后，每个支持区域偏移的`Temporal`对象都提供了一个方便的`getOffset()`方法。例如，下面的代码从前面的`offsetDateTime`对象获取区域偏移：

```java
// +02:00
ZoneOffset zoneOffsetFromOdt = offsetDateTime.getOffset();
```

# 72 在日期和时间之间转换

这里给出的解决方案将涵盖以下`Temporal`类—`Instant`、`LocalDate`、`LocalDateTime`、`ZonedDateTime`、`OffsetDateTime`、`LocalTime`和`OffsetTime`。

# `Date`-`Instant`

为了从`Date`转换到`Instant`，可采用`Date.toInstant()`方法求解。可通过`Date.from(Instant instant)`方法实现反转：

*   `Date`到`Instant`可以这样完成：

```java
Date date = new Date();

// e.g., 2019-02-27T12:02:49.369Z, UTC
Instant instantFromDate = date.toInstant();
```

*   `Instant`到`Date`可以这样完成：

```java
Instant instant = Instant.now();

// Wed Feb 27 14:02:49 EET 2019, default system time zone
Date dateFromInstant = Date.from(instant);
```

请记住，`Date`不是时区感知的，但它显示在系统默认时区中（例如，通过`toString()`）。`Instant`是 UTC 时区。

让我们快速地将这些代码片段包装在两个工具方法中，它们在一个工具类`DateConverters`中定义：

```java
public static Instant dateToInstant(Date date) {

  return date.toInstant();
}

public static Date instantToDate(Instant instant) {

  return Date.from(instant);
}
```

此外，让我们使用以下屏幕截图中的方法来丰富此类：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-cd-prob/img/ae07c212-3c31-4d8f-91b1-b494d5b9d393.png)

屏幕截图中的常量`DEFAULT_TIME_ZONE`是系统默认时区：

```java
public static final ZoneId DEFAULT_TIME_ZONE = ZoneId.systemDefault();
```

# `Date`–`LocalDate`

`Date`对象可以通过`Instant`对象转换为`LocalDate`。一旦我们从给定的`Date`对象中获得`Instant`对象，解决方案就可以应用于它系统默认时区，并调用`toLocaleDate()`方法：

```java
// e.g., 2019-03-01
public static LocalDate dateToLocalDate(Date date) {

  return dateToInstant(date).atZone(DEFAULT_TIME_ZONE).toLocalDate();
}
```

从`LocalDate`到`Date`的转换应该考虑到`LocalDate`不包含`Date`这样的时间成分，所以解决方案必须提供一个时间成分作为一天的开始（关于这个问题的更多细节可以在“一天的开始和结束”问题中找到）：

```java
// e.g., Fri Mar 01 00:00:00 EET 2019
public static Date localDateToDate(LocalDate localDate) {

  return Date.from(localDate.atStartOfDay(
    DEFAULT_TIME_ZONE).toInstant());
}
```

# `Date`–`LocalDateTime`

从`Date`到`DateLocalTime`的转换与从`Date`到`LocalDate`的转换是一样的，只是溶液应该调用`toLocalDateTime()`方法如下：

```java
// e.g., 2019-03-01T07:25:25.624
public static LocalDateTime dateToLocalDateTime(Date date) {

  return dateToInstant(date).atZone(
    DEFAULT_TIME_ZONE).toLocalDateTime();
}
```

从`LocalDateTime`到`Date`的转换非常简单。只需应用系统默认时区并调用`toInstant()`：

```java
// e.g., Fri Mar 01 07:25:25 EET 2019
public static Date localDateTimeToDate(LocalDateTime localDateTime) {

  return Date.from(localDateTime.atZone(
    DEFAULT_TIME_ZONE).toInstant());
}
```

# `Date`–`ZonedDateTime`

`Date`到`ZonedDateTime`的转换可以通过从给定`Date`对象获取`Instant`对象和系统默认时区来完成：

```java
// e.g., 2019-03-01T07:25:25.624+02:00[Europe/Athens]
public static ZonedDateTime dateToZonedDateTime(Date date) {

  return dateToInstant(date).atZone(DEFAULT_TIME_ZONE);
}
```

将`ZonedDateTime`转换为`Date`就是将`ZonedDateTime`转换为`Instant`：

```java
// e.g., Fri Mar 01 07:25:25 EET 2019
public static Date zonedDateTimeToDate(ZonedDateTime zonedDateTime) {

  return Date.from(zonedDateTime.toInstant());
}
```

# `Date`–`OffsetDateTime`

从`Date`到`OffsetDateTime`的转换依赖于`toOffsetDateTime()`方法：

```java
// e.g., 2019-03-01T07:25:25.624+02:00
public static OffsetDateTime dateToOffsetDateTime(Date date) {

  return dateToInstant(date).atZone(
    DEFAULT_TIME_ZONE).toOffsetDateTime();
}
```

从`OffsetDateTime`到`Date`的转换方法需要两个步骤。首先将`OffsetDateTime`转换为`LocalDateTime`；其次将`LocalDateTime`转换为`Instant`，对应偏移量：

```java
// e.g., Fri Mar 01 07:55:49 EET 2019
public static Date offsetDateTimeToDate(
    OffsetDateTime offsetDateTime) {

  return Date.from(offsetDateTime.toLocalDateTime()
    .toInstant(ZoneOffset.of(offsetDateTime.getOffset().getId())));
}
```

# `Date`–`LocalTime`

将`Date`转换为`LocalTime`可以依赖`LocalTime.toInstant()`方法，如下所示：

```java
// e.g., 08:03:20.336
public static LocalTime dateToLocalTime(Date date) {

  return LocalTime.ofInstant(dateToInstant(date), DEFAULT_TIME_ZONE);
}
```

将`LocalTime`转换为`Date`应该考虑到`LocalTime`没有日期组件。这意味着解决方案应将日期设置为 1970 年 1 月 1 日，即纪元：

```java
// e.g., Thu Jan 01 08:03:20 EET 1970
public static Date localTimeToDate(LocalTime localTime) {

  return Date.from(localTime.atDate(LocalDate.EPOCH)
    .toInstant(DEFAULT_TIME_ZONE.getRules()
      .getOffset(Instant.now())));
}
```

# `Date`-`OffsetTime`

将`Date`转换为`OffsetTime`可以依赖`OffsetTime.toInstant()`方法，如下所示：

```java
// e.g., 08:03:20.336+02:00
public static OffsetTime dateToOffsetTime(Date date) {

  return OffsetTime.ofInstant(dateToInstant(date), DEFAULT_TIME_ZONE);
}
```

将`OffsetTime`转换为`Date`应该考虑到`OffsetTime`没有日期组件。这意味着解决方案应将日期设置为 1970 年 1 月 1 日，即纪元：

```java
// e.g., Thu Jan 01 08:03:20 EET 1970
public static Date offsetTimeToDate(OffsetTime offsetTime) {

  return Date.from(offsetTime.atDate(LocalDate.EPOCH).toInstant());
}
```

# 73 迭代一系列日期

假设范围是由开始日期 2019 年 2 月 1 日和结束日期 2019 年 2 月 21 日界定的。这个问题的解决方案应该循环【2019 年 2 月 1 日，2019 年 2 月 21 日】间隔一天，并在屏幕上打印每个日期。基本上要解决两个主要问题：

*   一旦开始日期和结束日期相等，就停止循环。
*   每天增加开始日期直到结束日期。

# JDK8 之前

在 JDK8 之前，解决方案可以依赖于`Calendar`工具类。绑定到本书的代码包含此解决方案。

# 从 JDK8 开始

首先，从 JDK8 开始，可以很容易地将日期定义为`LocalDate`，而不需要`Calendar`的帮助：

```java
LocalDate startLocalDate = LocalDate.of(2019, 2, 1);
LocalDate endLocalDate = LocalDate.of(2019, 2, 21);
```

一旦开始日期和结束日期相等，我们就通过`LocalDate.isBefore(ChronoLocalDate other)`方法停止循环。此标志方法检查此日期是否早于给定日期。

使用`LocalDate.plusDays(long daysToAdd)`方法逐日增加开始日期直到结束日期。在`for`循环中使用这两种方法会产生以下代码：

```java
for (LocalDate date = startLocalDate; 
       date.isBefore(endLocalDate); date = date.plusDays(1)) {

  // do something with this day
  System.out.println(date);
}
```

输出的快照应如下所示：

```java
2019-02-01
2019-02-02
2019-02-03
...
2019-02-20
```

# 从 JDK9 开始

JDK9 可以用一行代码解决这个问题。由于新的`LocalDate.datesUntil(LocalDate endExclusive)`方法，这是可能的。此方法返回`Stream<LocalDate>`，增量步长为一天：

```java
startLocalDate.datesUntil(endLocalDate).forEach(System.out::println);
```

如果增量步骤应以天、周、月或年表示，则依赖于`LocalDate.datesUntil(LocalDate endExclusive, Period step)`。例如，1 周的增量步骤可以指定如下：

```java
startLocalDate.datesUntil(endLocalDate, Period.ofWeeks(1)).forEach(System.out::println);
```

输出应为（第 1-8 周，第 8-15 周），如下所示：

```java
2019-02-01
2019-02-08
2019-02-15
```

# 74 计算年龄

可能最常用的两个日期之间的差异是关于计算一个人的年龄。通常，一个人的年龄以年表示，但有时应提供月，甚至天。

# JDK8 之前

在 JDK8 之前，试图提供一个好的解决方案可以依赖于`Calendar`和/或`SimpleDateFormat`。绑定到本书的代码包含这样一个解决方案。

# 从 JDK8 开始

更好的方法是升级到 JDK8，并依赖以下简单的代码片段：

```java
LocalDate startLocalDate = LocalDate.of(1977, 11, 2);
LocalDate endLocalDate = LocalDate.now();

long years = ChronoUnit.YEARS.between(startLocalDate, endLocalDate);
```

由于`Period`类的原因，将月和日添加到结果中也很容易实现：

```java
Period periodBetween = Period.between(startLocalDate, endLocalDate);
```

现在，可以通过`periodBetween.getYears()`、`periodBetween.getMonths()`、`periodBetween.getDays()`获得以年、月、日为单位的年龄。

例如，在当前日期 2019 年 2 月 28 日和 1977 年 11 月 2 日之间，我们有 41 年 3 个月 26 天。

# 75 一天的开始和结束

在 JDK8 中，可以通过几种方法来找到一天的开始/结束。

让我们考虑一下通过`LocalDate`表达的一天：

```java
LocalDate localDate = LocalDate.of(2019, 2, 28);
```

找到 2019 年 2 月 28 日一天的开始的解决方案依赖于一个名为`atStartOfDay()`的方法。此方法从该日期午夜 00:00 返回`LocalDateTime`：

```java
// 2019-02-28T00:00
LocalDateTime ldDayStart = localDate.atStartOfDay();
```

或者，该溶液可以使用`of(LocalDate date, LocalTime time)`方法。该方法将给定的日期和时间组合成`LocalDateTime`。因此，如果经过的时间是`LocalTime.MIN`（一天开始时的午夜时间），则结果如下：

```java
// 2019-02-28T00:00
LocalDateTime ldDayStart = LocalDateTime.of(localDate, LocalTime.MIN);
```

一个`LocalDate`物体的一天结束时间至少可以用两种方法得到。一种解决方案是依靠`LocalDate.atTime(LocalTime time)`。得到的`LocalDateTime`可以表示该日期与一天结束时的组合，如果解决方案作为参数传递，`LocalTime.MAX`（一天结束时午夜前的时间）：

```java
// 2019-02-28T23:59:59.999999999
LocalDateTime ldDayEnd = localDate.atTime(LocalTime.MAX);
```

或者，该解决方案可以通过`atDate(LocalDate date)`方法将`LocalTime.MAX`与给定日期结合：

```java
// 2019-02-28T23:59:59.999999999
LocalDateTime ldDayEnd = LocalTime.MAX.atDate(localDate);
```

由于`LocalDate`没有时区的概念，前面的例子容易出现由不同的角落情况引起的问题，例如夏令时。有些夏令时会在午夜（00:00 变为 01:00 AM）更改时间，这意味着一天的开始时间是 01:00:00，而不是 00:00:00。为了缓解这些问题，请考虑以下示例，这些示例将前面的示例扩展为使用夏令时感知的`ZonedDateTime`：

```java
// 2019-02-28T00:00+08:00[Australia/Perth]
ZonedDateTime ldDayStartZone 
  = localDate.atStartOfDay(ZoneId.of("Australia/Perth"));

// 2019-02-28T00:00+08:00[Australia/Perth]
ZonedDateTime ldDayStartZone = LocalDateTime
  .of(localDate, LocalTime.MIN).atZone(ZoneId.of("Australia/Perth"));

// 2019-02-28T23:59:59.999999999+08:00[Australia/Perth]
ZonedDateTime ldDayEndZone = localDate.atTime(LocalTime.MAX)
  .atZone(ZoneId.of("Australia/Perth"));

// 2019-02-28T23:59:59.999999999+08:00[Australia/Perth]
ZonedDateTime ldDayEndZone = LocalTime.MAX.atDate(localDate)
  .atZone(ZoneId.of("Australia/Perth"));
```

现在，我们来考虑一下-`LocalDateTime`，2019 年 2 月 28 日，18:00:00：

```java
LocalDateTime localDateTime = LocalDateTime.of(2019, 2, 28, 18, 0, 0);
```

显而易见的解决方案是从`LocalDateTime`中提取`LocalDate`，并应用前面的方法。另一个解决方案依赖于这样一个事实，`Temporal`接口的每个实现（包括`LocalDate`）都可以利用`with(TemporalField field, long newValue)`方法。主要是，`with()`方法返回这个日期的一个副本，其中指定的字段`ChronoField`设置为`newValue`。因此，如果解决方案将`ChronoField.NANO_OF_DAY`（一天的纳秒）设置为`LocalTime.MIN`，那么结果将是一天的开始。这里的技巧是通过`toNanoOfDay()`将`LocalTime.MIN`转换为纳秒，如下所示：

```java
// 2019-02-28T00:00
LocalDateTime ldtDayStart = localDateTime
  .with(ChronoField.NANO_OF_DAY, LocalTime.MIN.toNanoOfDay());
```

这相当于：

```java
LocalDateTime ldtDayStart 
   = localDateTime.with(ChronoField.HOUR_OF_DAY, 0);
```

一天的结束是非常相似的。只需通过`LocalTime.MAX`而不是`MIN`：

```java
// 2019-02-28T23:59:59.999999999
LocalDateTime ldtDayEnd = localDateTime
  .with(ChronoField.NANO_OF_DAY, LocalTime.MAX.toNanoOfDay());
```

这相当于：

```java
LocalDateTime ldtDayEnd = localDateTime.with(
  ChronoField.NANO_OF_DAY, 86399999999999L);
```

与`LocalDate`一样，`LocalDateTime`对象不知道时区。在这种情况下，`ZonedDateTime`可以帮助：

```java
// 2019-02-28T00:00+08:00[Australia/Perth]
ZonedDateTime ldtDayStartZone = localDateTime
  .with(ChronoField.NANO_OF_DAY, LocalTime.MIN.toNanoOfDay())
  .atZone(ZoneId.of("Australia/Perth"));

// 2019-02-28T23:59:59.999999999+08:00[Australia/Perth]
ZonedDateTime ldtDayEndZone = localDateTime
  .with(ChronoField.NANO_OF_DAY, LocalTime.MAX.toNanoOfDay())
  .atZone(ZoneId.of("Australia/Perth"));
```

作为奖励，让我们看看 UTC 一天的开始/结束。除了依赖于`with()`方法的解决方案外，另一个解决方案可以依赖于`toLocalDate()`，如下所示：

```java
// e.g., 2019-02-28T09:23:10.603572Z
ZonedDateTime zdt = ZonedDateTime.now(ZoneOffset.UTC);

// 2019-02-28T00:00Z
ZonedDateTime dayStartZdt 
  = zdt.toLocalDate().atStartOfDay(zdt.getZone());

// 2019-02-28T23:59:59.999999999Z
ZonedDateTime dayEndZdt = zdt.toLocalDate()
  .atTime(LocalTime.MAX).atZone(zdt.getZone());
```

由于`java.util.Date`和`Calendar`存在许多问题，因此建议避免尝试用它们实现此问题的解决方案。

# 76 两个日期之间的差异

计算两个日期之间的差值是一项非常常见的任务（例如，请参阅“计算年龄”部分）。让我们看看其他方法的集合，这些方法可以用来获得以毫秒、秒、小时等为单位的两个日期之间的差异。

# JDK8 之前

建议通过`java.util.Date`和`Calendar`类来表示日期时间信息。最容易计算的差异用毫秒表示。绑定到本书的代码包含这样一个解决方案。

# 从 JDK8 开始

从 JDK8 开始，建议通过`Temporal`（例如，`DateTime`、`DateLocalTime`、`ZonedDateTime`等）来表示日期时间信息。

假设两个`LocalDate`对象，2018 年 1 月 1 日和 2019 年 3 月 1 日：

```java
LocalDate ld1 = LocalDate.of(2018, 1, 1);
LocalDate ld2 = LocalDate.of(2019, 3, 1);
```

计算这两个`Temporal`对象之间差异的最简单方法是通过`ChronoUnit`类。除了表示一组标准的日期周期单位外，`ChronoUnit`还提供了几种简便的方法，包括`between(Temporal t1Inclusive, Temporal t2Exclusive)`。顾名思义，`between()`方法计算两个`Temporal`对象之间的时间量。让我们看看计算`ld1`和`ld2`之间的差值的工作原理，以天、月和年为单位：

```java
// 424
long betweenInDays = Math.abs(ChronoUnit.DAYS.between(ld1, ld2));

// 14
long betweenInMonths = Math.abs(ChronoUnit.MONTHS.between(ld1, ld2));

// 1
long betweenInYears = Math.abs(ChronoUnit.YEARS.between(ld1, ld2));
```

或者，每个`Temporal`公开一个名为`until()`的方法。实际上，`LocalDate`有两个，一个返回`Period`作为两个日期之间的差，另一个返回`long`作为指定时间单位中两个日期之间的差。使用返回`Period`的方法如下：

```java
Period period = ld1.until(ld2);

// Difference as Period: 1y2m0d
System.out.println("Difference as Period: " + period.getYears() + "y" 
  + period.getMonths() + "m" + period.getDays() + "d");
```

使用允许我们指定时间单位的方法如下：

```java
// 424
long untilInDays = Math.abs(ld1.until(ld2, ChronoUnit.DAYS));

// 14
long untilInMonths = Math.abs(ld1.until(ld2, ChronoUnit.MONTHS));

// 1
long untilInYears = Math.abs(ld1.until(ld2, ChronoUnit.YEARS));
```

`ChronoUnit.convert()`方法也适用于`LocalDateTime`的情况。让我们考虑以下两个`LocalDateTime`对象：2018 年 1 月 1 日 22:15:15 和 2019 年 3 月 1 日 23:15:15：

```java
LocalDateTime ldt1 = LocalDateTime.of(2018, 1, 1, 22, 15, 15);
LocalDateTime ldt2 = LocalDateTime.of(2018, 1, 1, 23, 15, 15);
```

现在，让我们看看`ldt1`和`ldt2`之间的区别，用分钟表示：

```java
// 60
long betweenInMinutesWithoutZone 
  = Math.abs(ChronoUnit.MINUTES.between(ldt1, ldt2));
```

并且，通过`LocalDateTime.until()`方法以小时表示的差异：

```java
// 1
long untilInMinutesWithoutZone 
  = Math.abs(ldt1.until(ldt2, ChronoUnit.HOURS));
```

但是，`ChronoUnit.between()`和`until()`有一个非常棒的地方，那就是它们与`ZonedDateTime`一起工作。例如，让我们考虑欧洲/布加勒斯特时区和澳大利亚/珀斯时区的`ldt1`，加上一小时：

```java
ZonedDateTime zdt1 = ldt1.atZone(ZoneId.of("Europe/Bucharest"));
ZonedDateTime zdt2 = zdt1.withZoneSameInstant(
  ZoneId.of("Australia/Perth")).plusHours(1);
```

现在，我们用`ChronoUnit.between()`来表示`zdt1`和`zdt2`之间的差分，用`ZonedDateTime.until()`来表示`zdt1`和`zdt2`之间的差分，用小时表示：

```java
// 60
long betweenInMinutesWithZone 
  = Math.abs(ChronoUnit.MINUTES.between(zdt1, zdt2));

// 1
long untilInHoursWithZone 
  = Math.abs(zdt1.until(zdt2, ChronoUnit.HOURS));
```

最后，让我们重复这个技巧，但是对于两个独立的`ZonedDateTime`对象：一个为`ldt1`获得，一个为`ldt2`获得：

```java
ZonedDateTime zdt1 = ldt1.atZone(ZoneId.of("Europe/Bucharest"));
ZonedDateTime zdt2 = ldt2.atZone(ZoneId.of("Australia/Perth"));

// 300
long betweenInMinutesWithZone 
  = Math.abs(ChronoUnit.MINUTES.between(zdt1, zdt2));

// 5
long untilInHoursWithZone 
  = Math.abs(zdt1.until(zdt2, ChronoUnit.HOURS));
```

# 77 实现象棋时钟

从 JDK8 开始，`java.time`包有一个名为`Clock`的抽象类。这个类的主要目的是允许我们在需要时插入不同的时钟（例如，出于测试目的）。默认情况下，Java 有四种实现：`SystemClock`、`OffsetClock`、`TickClock`和`FixedClock`。对于每个实现，`Clock`类中都有`static`方法。例如，下面的代码创建了`FixedClock`（一个总是返回相同`Instant`的时钟）：

```java
Clock fixedClock = Clock.fixed(Instant.now(), ZoneOffset.UTC);
```

还有一个`TickClock`，它返回给定时区整秒的当前`Instant`滴答声：

```java
Clock tickClock = Clock.tickSeconds(ZoneId.of("Europe/Bucharest"));
```

还有一种方法可以用来在整分钟内打勾`tickMinutes()`，还有一种通用方法`tick()`，它允许我们指定`Duration`。

`Clock`类也可以支持时区和偏移量，但是`Clock`类最重要的方法是`instant()`。此方法返回`Clock`的瞬间：

```java
// 2019-03-01T13:29:34Z
System.out.println(tickClock.instant());
```

还有一个`millis()`方法，它以毫秒为单位返回时钟的当前时刻。

假设我们要实现一个时钟，它充当象棋时钟：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-cd-prob/img/ad6496ac-4425-407c-9a5f-c922283d6bcb.png)

为了实现一个`Clock`类，需要遵循以下几个步骤：

1.  扩展`Clock`类。
2.  执行`Serializable`。
3.  至少覆盖从`Clock`继承的抽象方法。

`Clock`类的框架如下：

```java
public class ChessClock extends Clock implements Serializable {

  @Override
  public ZoneId getZone() {
    ...
  }

  @Override
  public Clock withZone(ZoneId zone) {
    ...
  }

  @Override
  public Instant instant() {
    ...
  }
}
```

我们的`ChessClock`将只与 UTC 一起工作；不支持其他时区。这意味着`getZone()`和`withZone()`方法可以实现如下（当然，将来可以修改）：

```java
@Override
public ZoneId getZone() {
  return ZoneOffset.UTC;
}

@Override
public Clock withZone(ZoneId zone) {
  throw new UnsupportedOperationException(
    "The ChessClock works only in UTC time zone");
}
```

我们实现的高潮是`instant()`方法。难度在于管理两个`Instant`，一个是左边的玩家（`instantLeft`），一个是右边的玩家（`instantRight`）。我们可以将`instant()`方法的每一次调用与当前玩家已经执行了一个移动的事实相关联，现在轮到另一个玩家了。所以，基本上，这个逻辑是说同一个玩家不能调用`instant()`两次。实现这个逻辑，`instant()`方法如下：

```java
public class ChessClock extends Clock implements Serializable {

  public enum Player {
    LEFT,
    RIGHT
  }

  private static final long serialVersionUID = 1L;

  private Instant instantStart;
  private Instant instantLeft;
  private Instant instantRight;
  private long timeLeft;
  private long timeRight;
  private Player player;

  public ChessClock(Player player) {
    this.player = player;
  }

  public Instant gameStart() {

    if (this.instantStart == null) {
      this.timeLeft = 0;
      this.timeRight = 0;
      this.instantStart = Instant.now();
      this.instantLeft = instantStart;
      this.instantRight = instantStart;
      return instantStart;
    }

    throw new IllegalStateException(
      "Game already started. Stop it and try again.");
  }

  public Instant gameEnd() {

    if (this.instantStart != null) {
      instantStart = null;
      return Instant.now();
    }

    throw new IllegalStateException("Game was not started.");
  }

  @Override
  public ZoneId getZone() {
    return ZoneOffset.UTC;
  }

  @Override
  public Clock withZone(ZoneId zone) {
    throw new UnsupportedOperationException(
      "The ChessClock works only in UTC time zone");
  }

  @Override
  public Instant instant() {

    if (this.instantStart != null) {
      if (player == Player.LEFT) {
        player = Player.RIGHT;

        long secondsLeft = Instant.now().getEpochSecond() 
          - instantRight.getEpochSecond();
        instantLeft = instantLeft.plusSeconds(
          secondsLeft - timeLeft);
        timeLeft = secondsLeft;

        return instantLeft;
      } else {
        player = Player.LEFT;

        long secondsRight = Instant.now().getEpochSecond() 
          - instantLeft.getEpochSecond();
        instantRight = instantRight.plusSeconds(
          secondsRight - timeRight);
        timeRight = secondsRight;

        return instantRight;
      }
    }

    throw new IllegalStateException("Game was not started.");
  }
}
```

因此，根据哪个玩家调用了`instant()`方法，代码计算出该玩家在执行移动之前思考所需的秒数。此外，代码会切换播放器，因此下一次调用`instant()`将处理另一个播放器。

让我们考虑一个从`2019-03-01T14:02:46.309459Z`开始的国际象棋游戏：

```java
ChessClock chessClock = new ChessClock(Player.LEFT);

// 2019-03-01T14:02:46.309459Z
Instant start = chessClock.gameStart();
```

此外，玩家执行以下一系列动作，直到右边的玩家赢得游戏：

```java
Left moved first after 2 seconds: 2019-03-01T14:02:48.309459Z
Right moved after 5 seconds: 2019-03-01T14:02:51.309459Z
Left moved after 6 seconds: 2019-03-01T14:02:54.309459Z
Right moved after 1 second: 2019-03-01T14:02:52.309459Z
Left moved after 2 second: 2019-03-01T14:02:56.309459Z
Right moved after 3 seconds: 2019-03-01T14:02:55.309459Z
Left moved after 10 seconds: 2019-03-01T14:03:06.309459Z
Right moved after 11 seconds and win: 2019-03-01T14:03:06.309459Z
```

看来时钟正确地记录了运动员的动作。

最后，比赛在 40 秒后结束：

```java
Game ended:2019-03-01T14:03:26.350749300Z
Instant end = chessClock.gameEnd();

Game duration: 40 seconds
// Duration.between(start, end).getSeconds();
```

# 总结

任务完成了！本章提供了使用日期和时间信息的全面概述。广泛的应用必须处理这类信息。因此，将这些问题的解决方案放在你的工具带下不是可选的。从`Date`、`Calendar`到`LocalDate`、`LocalTime`、`LocalDateTime`、`ZoneDateTime`、`OffsetDateTime`、`OffsetTime`、`Instant`——它们在涉及日期和时间的日常任务中都是非常重要和有用的。

从本章下载应用以查看结果和其他详细信息。******
