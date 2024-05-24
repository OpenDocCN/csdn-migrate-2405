# Java 测试驱动开发（三）

> 原文：[`zh.annas-archive.org/md5/ccd393a1b3d624be903cafab189c1930`](https://zh.annas-archive.org/md5/ccd393a1b3d624be903cafab189c1930)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：TDD 和函数式编程-完美匹配

“任何足够先进的技术都是不可区分的魔术。”

-阿瑟·C·克拉克

到目前为止，我们在本书中看到的所有代码示例都遂循了一种特定的编程范式：**面向对象编程**（**OOP**）。这种范式已经垄断了软件行业很长时间，大多数软件公司都采用了 OOP 作为标准的编程方式。

然而，OOP 成为最常用的范式并不意味着它是唯一存在的范式。事实上，还有其他值得一提的范式，但本章将只关注其中之一：函数式编程。此外，本书的语言是 Java，因此所有的代码片段和示例都将基于 Java 8 版本中包含的函数式 API。

本章涵盖的主题包括：

+   Optional 类

+   函数的再思考

+   流

+   将 TDD 应用于函数式编程

# 设置环境

为了以测试驱动的方式探索 Java 函数式编程的一些好处，我们将使用 JUnit 和 AssertJ 框架设置一个 Java 项目。后者包含了一些方便的`Optional`方法。

让我们开始一个新的 Gradle 项目。这就是`build.gradle`的样子：

```java
apply plugin: 'java'

sourceCompatibility = 1.8
targetCompatibility = 1.8

repositories {
  mavenCentral()
}

dependencies {
  testCompile group: 'junit', name: 'junit', version: '4.12'
  testCompile group: 'org.assertj', name: 'assertj-core', version: '3.9.0'
}
```

在接下来的章节中，我们将探索 Java 8 中包含的一些增强编程体验的实用程序和类。它们大多不仅适用于函数式编程，甚至可以在命令式编程中使用。

# Optional - 处理不确定性

自从创建以来，`null`已经被开发人员无数次在无数个程序中使用和滥用。`null`的常见情况之一是代表值的缺失。这一点一点也不方便；它既可以代表值的缺失，也可以代表代码片段的异常执行。

此外，为了访问可能为`null`的变量，并减少不希望的运行时异常，比如`NullPointerException`，开发人员倾向于用`if`语句包装变量，以便以安全模式访问这些变量。虽然这样做是有效的，但对空值的保护增加了一些与代码的功能或目标无关的样板代码：

```java
if (name != null) {
  // do something with name
}
```

前面的代码克服了`null`的创造者在 2009 年的一次会议上所发现的问题：

“我称它为我的十亿美元的错误。这是在 1965 年发明了空引用。那时，我正在设计第一个综合的面向对象语言（ALGOL W）的引用类型系统。我的目标是确保所有引用的使用都是绝对安全的，由编译器自动执行检查。但我无法抵制放入一个空引用的诱惑，因为它太容易实现了。这导致了无数的错误、漏洞和系统崩溃，这可能在过去四十年中造成了十亿美元的痛苦和损害。”

-托尼·霍尔

随着 Java 8 的发布，实用类`Optional`作为替代前面的代码块被包含了进来。除了其他好处，它还带来了编译检查和零样板代码。让我们通过一个简单的例子来看`Optional`的实际应用。

# Optional 的示例

作为`Optional`的演示，我们将创建一个内存中的学生存储库。这个存储库有一个按`name`查找学生的方法，为了方便起见，将被视为 ID。该方法返回的值是`Optional<Student>`；这意味着响应可能包含也可能不包含`Student`。这种模式基本上是`Optional`的常见情况之一。

此时，读者应该熟悉 TDD 过程。为了简洁起见，完整的红-绿-重构过程被省略了。测试将与实现一起按照方便的顺序呈现，这可能与 TDD 迭代的顺序不一致。

首先，我们需要一个`Student`类来表示我们系统中的学生。为了简单起见，我们的实现将非常基本，只有两个参数：学生的`name`和`age`：

```java
public class Student {
  public final String name;
  public final int age;

  public Student(String name, int age) {
    this.name = name;
    this.age = age;
  }
}
```

下一个测试类验证了两种情况：成功的查找和失败的查找。请注意，AssertJ 对`Optional`有一些有用且有意义的断言方法。这使得测试非常流畅和可读：

```java
public class StudentRepositoryTest {

  private List<Student> studentList = Arrays.asList(
    new Student("Jane", 23),
    new Student("John", 21),
    new Student("Tom", 25) 
  );

  private StudentRepository studentRepository = 
    new StudentRepository(studentList);

  @Test
  public void whenStudentIsNotFoundThenReturnEmpty() {
    assertThat(studentRepository.findByName("Samantha"))
      .isNotPresent();
  }

  @Test
  public void whenStudentIsFoundThenReturnStudent() {
    assertThat(studentRepository.findByName("John"))
      .isPresent();
  }
}
```

在某些情况下，仅验证具有该`name`的学生的存在是不够的，我们可以对返回的对象执行一些断言。在大多数情况下，这是正确的做法：

```java
@Test
public void whenStudentIsFoundThenReturnStudent() {
  assertThat(studentRepository.findByName("John"))
    .hasValueSatisfying(s -> {
      assertThat(s.name).isEqualTo("John");
      assertThat(s.age).isEqualTo(21);
    });
}
```

现在，是时候专注于`StudentRepository`类了，它只包含一个构造函数和执行学生查找的方法。如下所示，查找方法`findByName`返回一个包含`Student`的`Optional`。请注意，这是一个有效但不是功能性的实现，只是作为一个起点使用：

```java
public class StudentRepository {
  StudentRepository(Collection<Student> students) { }

  public Optional<Student> findByName(String name) {
    return Optional.empty();
  }
}
```

如果我们对前面的实现运行测试，我们会得到一个成功的测试，因为查找方法默认返回`Optional.empty()`。另一个测试会抛出一个错误，如下所示：

```java
java.lang.AssertionError: 
Expecting Optional to contain a value but was empty.
```

为了完整起见，这是一个可能的实现之一：

```java
public class StudentRepository {
  private final Set<Student> studentSet;

  StudentRepository(Collection<Student> students) {
    studentSet = new HashSet<>(students);
  }

  public Optional<Student> findByName(String name) {
    for (Student student : this.studentSet) {
      if (student.name.equals(name))
        return Optional.of(student);
    }
    return Optional.empty();
  }
}
```

在下一节中，我们将看到对*函数*的不同观点。在 Java 8 中，如果以特定方式使用函数，它们将增加一些额外的功能。我们将通过一些示例来探索其中的一些功能。

# 重新审视函数

与面向对象的程序不同，以函数式方式编写的程序不持有任何可变状态。相反，代码由接受参数并返回值的函数组成。因为没有涉及可以改变执行的内部状态或副作用，所有函数都是确定性的。这是一个非常好的特性，因为它意味着对于相同参数的同一函数的不同执行将产生相同的结果。

以下片段说明了一个不会改变任何内部状态的函数：

```java
public Integer add(Integer a, Integer b) {
  return a + b;
}
```

以下是使用 Java 的函数式 API 编写的相同函数：

```java
public final BinaryOperator<Integer> add =
  new BinaryOperator<Integer>() {

    @Override
    public Integer apply(Integer a, Integer b) {
      return a + b;
    }
  };
```

第一个例子对于任何 Java 开发人员来说应该是非常熟悉的；它遵循了以两个整数作为参数并返回它们的和的常见语法。然而，第二个例子与我们习惯的传统代码有些不同。在这个新版本中，函数是一个作为值的对象，并且可以分配给一个字段。在某些情况下，这是非常方便的，因为它仍然可以在某些情况下用作函数，在其他情况下也可以用作返回值，在函数中作为参数或在类中作为字段。

有人可能会认为第一个版本的函数更合适，因为它更短，不需要创建一个新对象。嗯，这是真的，但函数也可以是对象，增强了它们的一系列新功能。就代码冗长而言，可以通过使用 lambda 表达式将其大大减少到一行：

```java
public final BinaryOperator<Integer> addLambda = (a, b) -> a + b;
```

在下一节中，将介绍**逆波兰表示法**（**RPN**）的一个可能解决方案。我们将使用函数式编程的强大和表现力，特别是 lambda 表示法，在需要函数作为某些函数的参数时变得非常方便。使用 lambda 使我们的代码非常简洁和优雅，提高了可读性。

# Kata - 逆波兰表示法

RPN 是用于表示数学表达式的一种表示法。它在运算符和操作数的顺序上与传统和广泛使用的中缀表示法不同。

在中缀表示法中，运算符放置在操作数之间，而在 RPN 中，操作数首先放置，运算符位于末尾。

这是使用中缀表示法编写的表达式：

```java
3 + 4
```

使用 RPN 编写的相同表达式：

```java
3 4 +
```

# 要求

我们将忽略如何读取表达式，以便我们可以专注于解决问题。此外，我们将仅使用正整数来简化问题，尽管接受浮点数或双精度数也不应该很困难。为了解决这个 kata，我们只需要满足以下两个要求：

+   对于无效输入（不是 RPN），应抛出错误消息

+   它接收使用 RPN 编写的算术表达式并计算结果

以下代码片段是我们开始项目的一个小脚手架：

```java
public class ReversePolishNotation {
  int compute(String expression) {
    return 0;
  }
}

public class NotReversePolishNotationError extends RuntimeException {
  public NotReversePolishNotationError() {
    super("Not a Reverse Polish Notation");
  }
}
```

以前面的代码片段作为起点，我们将继续进行，将要求分解为更小的规范，可以逐个解决。

# 要求 - 处理无效输入

鉴于我们的实现基本上什么都没做，我们将只专注于一件事 - 读取单个操作数。如果输入是单个数字（没有运算符），那么它是有效的逆波兰表示法，并返回数字的值。除此以外的任何内容目前都被视为无效的 RPN。

这个要求被转化为这四个测试：

```java
public class ReversePolishNotationTest {
  private ReversePolishNotation reversePolishNotation =
    new ReversePolishNotation();

  @Test(expected = NotReversePolishNotationError.class)
  public void emptyInputThrowsError() {
    reversePolishNotation.compute("");
  }

  @Test(expected = NotReversePolishNotationError.class)
  public void notANumberThrowsError() {
    reversePolishNotation.compute("a");
  }

  @Test
  public void oneDigitReturnsNumber() {
    assertThat(reversePolishNotation.compute("7")).isEqualTo(7);
  }

  @Test
  public void moreThanOneDigitReturnsNumber() {
    assertThat(reversePolishNotation.compute("120")).isEqualTo(120);
  }
}
```

当提供无效输入时，我们现在要求我们的`compute`方法抛出`IllegalArgumentException`。在任何其他情况下，它将作为整数值返回数字。可以通过以下代码行实现：

```java
public class ReversePolishNotation {
  int compute(String expression) {
    try {
      return (Integer.parseInt(expression));
    } catch (NumberFormatException e) {
      throw new NotReversePolishNotationError();
    }
  }
}
```

这个要求已经实现。另一个要求更复杂一些，所以我们将其分为两个部分 - 单一操作，意味着只有一个操作，和复杂操作，涉及任何类型的多个操作。

# 要求 - 单一操作

因此，计划是支持加法、减法、乘法和除法操作。如在 kata 演示中所解释的，在 RPN 中，运算符位于表达式的末尾。

这意味着*a - b*表示为*a b -*，其他运算符也是如此：加法*+*，乘法*，和除法*/*。

让我们在测试中添加每个支持的操作中的一个：

```java
@Test
public void addOperationReturnsCorrectValue() {
  assertThat(reversePolishNotation.compute("1 2 +")).isEqualTo(3);
}

@Test
public void subtractOperationReturnsCorrectValue() {
  assertThat(reversePolishNotation.compute("2 1 -")).isEqualTo(1);
}

@Test
public void multiplyOperationReturnsCorrectValue() {
  assertThat(reversePolishNotation.compute("2 1 *")).isEqualTo(2);
}

@Test
public void divideOperationReturnsCorrectValue() {
  assertThat(reversePolishNotation.compute("2 2 /")).isEqualTo(1);
}
```

这还包括必要的更改，使它们成功通过。行为基本上是将运算符放在表达式之间，并在输入表达式时执行操作。如果`expression`中只有一个元素，则适用前面的规则：

```java
int compute(String expression) {
  String[] elems = expression.trim().split(" ");
  if (elems.length != 1 && elems.length != 3)
    throw new NotReversePolishNotationError();
  if (elems.length == 1) {
    return parseInt(elems[0]);
  } else {
    if ("+".equals(elems[2]))
      return parseInt(elems[0]) + parseInt(elems[1]);
    else if ("-".equals(elems[2]))
      return parseInt(elems[0]) - parseInt(elems[1]);
    else if ("*".equals(elems[2]))
      return parseInt(elems[0]) * parseInt(elems[1]);
    else if ("/".equals(elems[2]))
      return parseInt(elems[0]) / parseInt(elems[1]);
    else
      throw new NotReversePolishNotationError();
  }
}
```

`parseInt`是一个`private`方法，用于解析输入并返回整数值或抛出异常：

```java
private int parseInt(String number) {
  try {
    return Integer.parseInt(number);
  } catch (NumberFormatException e) {
    throw new NotReversePolishNotationError();
  }
}
```

下一个要求是魔术发生的地方。我们将支持`expression`中的多个操作。

# 要求 - 复杂操作

复杂的操作很难处理，因为混合操作使得非受过训练的人眼难以理解操作应该以何种顺序进行。此外，不同的评估顺序通常会导致不同的结果。为了解决这个问题，逆波兰表达式的计算由队列的实现支持。以下是我们下一个功能的一些测试：

```java
@Test
public void multipleAddOperationsReturnCorrectValue() {
  assertThat(reversePolishNotation.compute("1 2 5 + +"))
    .isEqualTo(8);
}

@Test
public void multipleDifferentOperationsReturnCorrectValue() {
  assertThat(reversePolishNotation.compute("5 12 + 3 -"))
    .isEqualTo(14);
}

@Test
public void aComplexTest() {
  assertThat(reversePolishNotation.compute("5 1 2 + 4 * + 3 -"))
    .isEqualTo(14);
}
```

计算应该按顺序将表达式中的数字或操作数堆叠在 Java 中的队列或堆栈中。如果在任何时候找到运算符，则堆栈将用应用该运算符于这些值的结果替换顶部的两个元素。为了更好地理解，逻辑将被分成不同的函数。

首先，我们将定义一个函数，该函数接受一个堆栈和一个操作，并将该函数应用于顶部的前两个项目。请注意，由于堆栈的实现，第一次检索第二个操作数：

```java
private static void applyOperation(
    Stack<Integer> stack,
    BinaryOperator<Integer> operation
) {
  int b = stack.pop(), a = stack.pop();
  stack.push(operation.apply(a, b));
}
```

下一步是创建程序必须处理的所有函数。对于每个运算符，都定义了一个函数作为对象。这有一些优势，比如更好的隔离测试。在这种情况下，单独测试函数可能没有意义，因为它们是微不足道的，但在一些其他场景中，单独测试这些函数的逻辑可能非常有用：

```java
static BinaryOperator<Integer> ADD = (a, b) -> a + b;
static BinaryOperator<Integer> SUBTRACT = (a, b) -> a - b;
static BinaryOperator<Integer> MULTIPLY = (a, b) -> a * b;
static BinaryOperator<Integer> DIVIDE = (a, b) -> a / b;
```

现在，将所有部分放在一起。根据我们找到的运算符，应用适当的操作：

```java
int compute(String expression) {
  Stack<Integer> stack = new Stack<>();
  for (String elem : expression.trim().split(" ")) {
    if ("+".equals(elem))
      applyOperation(stack, ADD);
    else if ("-".equals(elem))
      applyOperation(stack, SUBTRACT);
    else if ("*".equals(elem))
      applyOperation(stack, MULTIPLY);
    else if ("/".equals(elem))
      applyOperation(stack, DIVIDE);
    else {
      stack.push(parseInt(elem));
    }
  }
  if (stack.size() == 1) return stack.pop();
  else throw new NotReversePolishNotationError();
}
```

代码可读性很强，非常容易理解。此外，这种设计允许通过轻松添加对其他不同操作的支持来扩展功能。

对于读者来说，将模数（*％*）操作添加到提供的解决方案可能是一个很好的练习。

另一个很好的例子是 lambda 完全适合的 Streams API，因为大多数函数都有一个名副其实的名称，如`filter`、`map`或`reduce`等。让我们在下一节更深入地探讨这一点。

# 流

Java 8 中包含的顶级实用程序之一是 Streams。在本章中，我们将在小的代码片段中使用 lambda 与 Streams 结合，并创建一个测试来验证它们。

为了更好地理解 Streams 是什么，该做什么，以及不该做什么，强烈建议阅读 Oracle 的 Stream 页面。一个很好的起点是[`docs.oracle.com/javase/8/docs/api/java/util/stream/Stream.html`](https://docs.oracle.com/javase/8/docs/api/java/util/stream/Stream.html)。

长话短说，流提供了一堆设施来处理可以以并行或顺序顺序执行的长计算。并行编程超出了本书的范围，因此下一个示例将仅顺序执行。此外，为了保持本章简洁，我们将专注于：

+   `filter`

+   `映射`

+   `flatMap`

+   `reduce`

# 过滤

让我们从`filter`操作开始。Filters 是一个名副其实的函数；它根据值是否满足条件来过滤流中的元素，如下例所示：

```java
@Test
public void filterByNameReturnsCollectionFiltered() {
  List<String> names = Arrays.asList("Alex", "Paul", "Viktor",
         "Kobe", "Tom", "Andrea");
  List<String> filteredNames = Collections.emptyList();

  assertThat(filteredNames)
      .hasSize(2)
      .containsExactlyInAnyOrder("Alex", "Andrea");
}
```

计算`filteredNames`列表的一种可能性如下：

```java
List<String> filteredNames = names.stream()
      .filter(name -> name.startsWith("A"))
      .collect(Collectors.toList());
```

那个是最简单的。简而言之，`filter`过滤输入并返回一个值，而不是过滤掉所有的元素。使用 lambda 使得代码优雅且易于阅读。

# 映射

`map`函数将流中的所有元素转换为另一个。结果对象可以与输入共享类型，但也可以返回不同类型的对象：

```java
@Test
public void mapToUppercaseTransformsAllElementsToUppercase() {
  List<String> names = Arrays.asList("Alex", "Paul", "Viktor");
  List<String> namesUppercase = Collections.emptyList();

  assertThat(namesUppercase)
      .hasSize(3)
      .containsExactly("ALEX", "PAUL", "VIKTOR");
}
```

`namesUppercase`列表应按以下方式计算：

```java
List<String> namesUppercase = names.stream()
  .map(String::toUpperCase)
  .collect(Collectors.toList());
```

注意`toUpperCase`方法的调用。它属于 Java 类`String`，只能通过引用函数和函数所属的类在该场景中使用。在 Java 中，这称为**方法引用**。

# flatMap

`flatMap`函数与`map`函数非常相似，但当操作可能返回多个值并且我们想保持单个元素流时使用它。在`map`的情况下，将返回一个集合流。让我们看看`flatMap`的使用：

```java
@Test
public void gettingLettersUsedInNames() {
  List<String> names = Arrays.asList("Alex", "Paul", "Viktor");
  List<String> lettersUsed = Collections.emptyList();

  assertThat(lettersUsed)
    .hasSize(12)
    .containsExactly("a","l","e","x","p","u","v","i","k","t","o","r");
}
```

一个可能的解决方案可能是：

```java
List<String> lettersUsed = names.stream()
  .map(String::toLowerCase)
  .flatMap(name -> Stream.of(name.split("")))
  .distinct()
  .collect(Collectors.toList());
```

这次我们使用了`Stream.of()`，这是一个创建流的便捷方法。另一个非常好的特性是`distinct()`方法，它使用`equals()`方法比较它们并返回唯一元素的集合。

# 减少

在前面的例子中，函数返回作为输入传递的所有名称中使用的字母列表。但是，如果我们只对不同字母的数量感兴趣，有一种更简单的方法。`reduce`基本上将函数应用于所有元素并将它们组合成一个单一的结果。让我们看一个例子：

```java
@Test
public void countingLettersUsedInNames() {
  List<String> names = Arrays.asList("Alex", "Paul", "Viktor");
  long count = 0;

  assertThat(count).isEqualTo(12);
}
```

这个解决方案与我们用于上一个练习的解决方案非常相似：

```java
long count = names.stream()
  .map(String::toLowerCase)
  .flatMap(name -> Stream.of(name.split("")))
  .distinct()
  .mapToLong(l -> 1L)
  .reduce(0L, (v1, v2) -> v1 + v2);
```

尽管前面的代码片段解决了问题，但有一种更好的方法来做到这一点：

```java
long count = names.stream()
  .map(String::toLowerCase)
  .flatMap(name -> Stream.of(name.split("")))
  .distinct()
  .count();
```

`count()`函数是 Streams 包含的另一个内置工具。它是一个特殊的快捷方式，用于计算流中包含的元素数量的`reduction`函数。

# 总结

函数式编程是一个古老的概念，因为它更容易在尝试通过并行执行任务来提高性能时使用而变得流行。在本章中，一些来自函数式世界的概念以及 AssertJ 提供的一些测试工具被介绍了。

测试没有副作用的函数非常容易，因为测试范围被缩小了。不需要测试函数可能对不同对象造成的更改，唯一需要验证的是调用的结果。没有副作用意味着只要参数相同，函数的结果就是相同的。因此，执行可以重复多次，并且在每次执行时都会得到相同的结果。此外，测试更容易阅读和理解。

总之，如果您需要在项目中使用这种范式，Java 包含了一个很好的函数式编程 API。但是有一些语言，其中一些是纯函数式的，提供了更强大的功能，更好的语法和更少的样板代码。如果您的项目或方法可以是纯函数式的，您应该评估是否使用其中一种其他语言是合理的。

本章中介绍的所有示例都可以在[`bitbucket.org/alexgarcia/tdd-java-funcprog.git`](https://bitbucket.org/alexgarcia/tdd-java-funcprog.git)找到。

现在是时候看一看遗留代码以及如何对其进行调整，使其更符合 TDD 的要求。


# 第八章：BDD - 与整个团队合作

“我不是一个伟大的程序员；我只是一个有着伟大习惯的好程序员。”

- 肯特·贝克

到目前为止，我们所做的一切都与只能由开发人员应用的技术有关。客户、业务代表和其他无法阅读和理解代码的人并未参与其中。

TDD 可以做得比我们到目前为止所做的更多。我们可以定义需求，与客户讨论，并就应该开发什么达成一致。我们可以使用这些需求并使它们可执行，以便驱动和验证我们的开发。我们可以使用通用语言编写验收标准。所有这些，以及更多，都是通过一种称为**行为驱动开发**（**BDD**）的 TDD 风格实现的。

我们将使用 BDD 方法开发一个书店应用程序。我们将用英语定义验收标准，分别实现每个功能，通过运行 BDD 场景确认其是否正常工作，并在必要时重构代码以达到所需的质量水平。该过程仍然遵循 TDD 的红-绿-重构，这是 TDD 的本质。主要区别在于定义级别。直到此刻，我们大多在单元级别工作，这次我们将稍微提高一点，并通过功能和集成测试应用 TDD。

我们选择的框架将是 JBehave 和 Selenide。

本章将涵盖以下主题：

+   不同类型的规范

+   行为驱动开发（BDD）

+   书店 BDD 故事

+   JBehave

# 不同的规范

我们已经提到 TDD 的一个好处是可执行的文档，它始终保持最新状态。然而，通过单元测试获得的文档通常是不够的。在这样低级别的工作中，我们可以深入了解细节；然而，很容易忽略整体情况。例如，如果您要检查我们为井字游戏创建的规范，您可能很容易忽略应用程序的要点。您会了解每个单元的功能以及它如何与其他单元互操作，但很难理解其背后的想法。准确地说，您会了解单元*X*执行*Y*并与*Z*通信；然而，功能文档和其背后的想法最多也是很难找到。

开发也是如此。在我们开始以单元测试的形式工作之前，我们需要先了解整体情况。在本书中，我们提出了用于编写规范的需求，这些规范导致了它们的实施。这些要求后来被丢弃了；它们已经不见了。我们没有把它们放入存储库，也没有用它们来验证我们工作的结果。

# 文档

在我们合作的许多组织中，文档是出于错误的原因而创建的。管理层倾向于认为文档与项目成功有某种关联——没有大量（通常是短暂的）文档，项目就会失败。因此，我们被要求花费大量时间规划、回答问题，并填写通常并非旨在帮助项目而是提供一种一切都在控制之下的错觉的问卷调查。有时候，某人的存在往往是通过文档来证明的（我的工作成果就是这份文件）。它还作为一种保证，表明一切都按计划进行（有一张 Excel 表格表明我们按计划进行）。然而，创建文档最常见的原因远非如此，而是一个简单陈述某些文档需要被创建的流程。我们可能会质疑这些文档的价值，然而，由于流程是神圣的，它们必须被制作出来。

不仅可能出于错误原因创建文档并且价值不够，而且通常情况下，它可能也会造成很大的损害。如果我们创建了文档，那么我们自然会相信它。但是，如果文档不是最新的，会发生什么？需求在变化，错误正在修复，正在开发新功能，有些功能正在被移除。如果给予足够的时间，所有传统文档都会过时。随着我们对代码进行的每一次更改，更新文档的任务是如此庞大和复杂，以至于迟早我们必须面对静态文档不反映现实的事实。如果我们对不准确的东西产生信任，我们的开发就是基于错误的假设。

唯一准确的文档是我们的代码。代码是我们开发的东西，我们部署的东西，也是唯一真实代表我们应用程序的来源。然而，代码并非每个参与项目的人都能阅读。除了程序员，我们可能还与经理、测试人员、业务人员、最终用户等一起工作。

为了寻找更好的定义什么构成更好的文档的方法，让我们进一步探讨一下潜在的文档使用者是谁。为了简单起见，我们将它们分为程序员（能够阅读和理解代码的人）和非程序员（其他人）。

# 面向程序员的文档

开发人员使用代码，既然我们已经确定代码是最准确的文档，那就没有理由不利用它。如果您想了解某个方法的作用，请查看该方法的代码。对某个类的功能有疑问？看看那个类。难以理解某段代码？我们有问题！然而，问题不是文档丢失，而是代码本身写得不好。

查看代码以理解代码通常还不够。即使您可能理解代码的功能，该代码的目的可能并不那么明显。它首先是为什么编写的呢？

这就是规格的作用。我们不仅在持续验证代码时使用它们，而且它们还充当可执行文档。它们始终保持最新，因为如果它们不是，它们的执行将失败。同时，虽然代码本身应该以易于阅读和理解的方式编写，但规格提供了一种更容易和更快速地理解我们编写某些实现代码的原因、逻辑和动机的方式。

使用代码作为文档并不排除其他类型。相反，关键不是避免使用静态文档，而是避免重复。当代码提供必要的细节时，首先使用它。在大多数情况下，这使我们得到更高级别的文档，例如概述、系统的一般目的、使用的技术、环境设置、安装、构建和打包，以及其他类型的数据，往往更像指南和快速启动信息而不是详细信息。对于这些情况，markdown 格式的简单`README`（[`whatismarkdown.com/`](http://whatismarkdown.com/)）往往是最好的。

对于所有基于代码的文档，TDD 是最好的启用程序。到目前为止，我们只与单元（方法）一起工作。我们还没有看到如何在更高层次上应用 TDD，比如，例如，功能规格。然而，在我们到达那里之前，让我们谈谈团队中的其他角色。

# 非程序员的文档

传统的测试人员倾向于形成与开发人员完全分离的团体。这种分离导致了越来越多的测试人员不熟悉代码，并假设他们的工作是质量检查。他们是流程结束时的验证者，起到了一种边境警察的作用，决定什么可以部署，什么应该退回。另一方面，越来越多的组织将测试人员作为团队的一部分，负责确保质量得到建立。后一组要求测试人员精通代码。对于他们来说，使用代码作为文档是非常自然的。然而，我们应该怎么处理第一组？对于不理解代码的测试人员，我们应该怎么办？此外，不仅（一些）测试人员属于这一组。经理、最终用户、业务代表等也包括在内。世界上充满了无法阅读和理解代码的人。

我们应该寻找一种方法来保留可执行文档提供的优势，但以一种所有人都能理解的方式编写它。此外，在 TDD 的方式下，我们应该允许每个人从一开始就参与可执行文档的创建。我们应该允许他们定义我们将用来开发应用程序的需求，并同时验证开发结果。我们需要一些能够在更高层次上定义我们将要做什么的东西，因为低级已经通过单元测试覆盖了。总之，我们需要可以作为需求的文档，可以执行的文档，可以验证我们工作的文档，并且可以被所有人编写和理解的文档。

向 BDD 问好。

# 行为驱动开发

行为驱动开发（BDD）是一种旨在在整个项目过程中保持对利益相关者价值的关注的敏捷过程；它是 TDD 的一种形式。规范是提前定义的，实施是根据这些规范进行的，并定期运行以验证结果。除了这些相似之处，还有一些区别。与 TDD 不同，BDD 鼓励我们在开始实施（编码）之前编写多个规范（称为场景）。尽管没有具体的规则，但 BDD 倾向于更高级的功能需求。虽然它也可以在单元级别上使用，但真正的好处是在采用可以被所有人编写和理解的更高级别方法时获得的。受众是另一个不同之处——BDD 试图赋予每个人（编码人员、测试人员、经理、最终用户、业务代表等）权力。

虽然基于单元级别的 TDD 可以被描述为从内到外（我们从单元开始，逐渐构建功能），但 BDD 通常被理解为从外到内（我们从功能开始，逐渐向内部单元发展）。BDD 充当了**验收标准**，作为准备就绪的指标。它告诉我们什么时候完成并准备投入生产。

我们首先定义功能（或行为），通过使用 TDD 和单元测试来处理它们，一旦完成一个完整的行为，就用 BDD 进行验证。一个 BDD 场景可能需要数小时甚至数天才能完成。在此期间，我们可以使用 TDD 和单元测试。完成后，我们运行 BDD 场景进行最终验证。TDD 是为编码人员设计的，具有非常快的周期，而 BDD 是为所有人设计的，具有更慢的周转时间。对于每个 BDD 场景，我们有许多 TDD 单元测试。

此时，您可能已经对 BDD 真正是什么感到困惑，所以让我们回顾一下。我们将从其格式的解释开始。

# 叙述

BDD 故事由一个叙述和至少一个场景组成。叙述只是提供信息，其主要目的是提供足够的信息，可以作为所有参与者之间沟通的开始（测试人员，业务代表，开发人员，分析师等）。它是一个简短而简单的功能描述，从需要它的人的角度讲述。

叙述的目标是回答三个基本问题：

1.  为了：应该构建的功能的好处或价值是什么？

1.  **作为**：谁需要所请求的功能？

1.  我想要：应该开发什么功能或目标？

一旦我们回答了这些问题，我们就可以开始定义我们认为最佳解决方案的内容。这种思考过程会产生提供更低级别细节的场景。

到目前为止，我们一直在低级别使用单元测试作为驱动力。我们从编码人员的角度规定了应该从哪里构建。我们假设高级需求早已定义，并且我们的工作是针对其中之一进行代码编写。现在，让我们退后几步，从头开始。

让我们假设，比如说，作为一个客户或业务代表。有人想到了这个好主意，我们正在与团队讨论。简而言之，我们想要建立一个在线书店。这只是一个想法，我们甚至不确定它会如何发展，所以我们想要开发一个**最小可行产品**（**MVP**）。我们想要探索的角色之一是商店管理员。这个人应该能够添加新书籍，更新或删除现有的书籍。所有这些操作都应该是可行的，因为我们希望这个人能够以高效的方式管理我们的书店收藏。我们为这个角色想出的叙述如下：

```java
In order to manage the book store collection efficiently 
As a store administrator 
I want to be able to add, update, and remove books 
```

现在我们知道了好处是什么（管理书籍），谁需要它（`管理员`），最后应该开发的功能是什么（`插入`，`更新`和`删除`操作）。请记住，这不是对应该做什么的详细描述。叙述的目的是引发一场讨论，从而产生一个或多个场景。

与 TDD 单元测试不同，叙述，实际上整个 BDD 故事，可以由任何人撰写。它们不需要编码技能，也不必涉及太多细节。根据组织的不同，所有叙述可以由同一个人（业务代表，产品所有者，客户等）撰写，或者可能是整个团队的协作努力。

现在我们对叙述有了更清晰的想法，让我们来看看场景。

# 场景

叙述作为一种沟通促进者，场景是该沟通的结果。它们应该描述角色（在*叙述*部分中指定）与系统的交互。与由开发人员为开发人员编写的代码不同，BDD 场景应该用简单的语言和最少的技术细节来定义，以便项目中的所有参与者（开发人员，测试人员，设计师，经理，客户等）都能对将添加到系统中的行为（或功能）有共同的理解。

场景充当叙述的验收标准。一旦与叙述相关的所有场景都成功运行，工作就可以被认为完成了。每个场景非常类似于一个单元测试，主要区别在于范围（一个方法对整个功能）和实现所需的时间（几秒钟或几分钟对几个小时甚至几天）。与单元测试类似，场景推动开发；它们首先被定义。

每个场景由描述和一个或多个以“给定”、“当”或“那么”开头的步骤组成。描述简短且仅供参考。它帮助我们一目了然地理解场景的功能。另一方面，步骤是场景的前提条件、事件和预期结果的序列。它们帮助我们明确定义行为，并且很容易将它们转化为自动化测试。

在本章中，我们将更多地关注 BDD 的技术方面以及它们如何融入开发者的思维方式。要了解更广泛的 BDD 使用和更深入的讨论，请参考 Gojko Adzic 的书《实例说明：成功团队如何交付正确的软件》。

“给定”步骤定义了上下文或前提条件，需要满足这些条件才能成功执行场景的其余部分。回到书籍管理的叙述，一个这样的前提条件可能是：

```java
Given user is on the books screen 
```

这是一个非常简单但非常必要的前提条件。我们的网站可能有很多页面，我们需要确保用户在执行任何操作之前处于正确的屏幕上。

“当”步骤定义了一个动作或某种事件。在我们的叙述中，我们定义了“管理员”应该能够“添加”、“更新”和“删除”书籍。让我们看看与“删除”操作相关的动作应该是什么：

```java
When user selects a book 
When user clicks the deleteBook button 
```

在这个例子中，我们使用“当”步骤定义了多个操作。首先，我们应该选择一本书，然后我们应该点击`deleteBook`按钮。在这种情况下，我们使用了一个 ID（`deleteBook`）来定义应该点击的按钮，而不是文本（删除书籍）。在大多数情况下，ID 更可取，因为它们提供了多种好处。它们是唯一的（在给定屏幕上只能存在一个 ID），它们为开发人员提供清晰的指示（创建一个带有 ID`deleteBook`的元素），并且它们不受同一屏幕上其他更改的影响。元素的文本可以很容易地改变；如果发生这种情况，使用它的所有场景也会失败。在网站的情况下，一个替代方案可能是 XPath。但是，尽量避免这种情况。它往往会因 HTML 结构的最小更改而失败。

与单元测试类似，场景应该是可靠的，并且在功能尚未开发或出现真正问题时失败。否则，当它们产生错误的负面影响时，开始忽略规范是一种自然反应。

最后，我们应该始终以某种验证结束场景。我们应该指定已执行操作的期望结果。按照相同的场景，我们的“那么”步骤可能是以下内容：

```java
Then book is removed 
```

这个结果在提供足够的数据和不涉及设计细节之间取得了平衡。例如，我们可以提到数据库，甚至更具体地说是 MongoDB。然而，在许多情况下，从行为角度来看，这些信息并不重要。我们只需确认书籍已从目录中删除，无论它存储在哪里。

现在我们熟悉了 BDD 故事格式，让我们写书店 BDD 故事。

# 书店 BDD 故事

在开始之前，请克隆位于[`bitbucket.org/vfarcic/tdd-java-ch08-books-store`](https://bitbucket.org/vfarcic/tdd-java-ch07-books-store)的可用代码。这是一个我们将在本章中使用的空项目。与以前的章节一样，它包含了每个部分的分支，以防您错过了什么。

我们将编写一个 BDD 故事，它将以纯文本格式、用简单的英语编写，没有任何代码。这样，所有利益相关者都可以参与并独立参与，而不受其编码能力的限制。稍后，我们将看到如何自动化我们正在编写的故事。

让我们首先在`stories`目录中创建一个名为`administration.story`的新文件：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/test-dvn-java-dev/img/e029d960-8a3b-417d-a3e6-0d8ce2b31304.png)

我们已经有了之前写的叙述，所以我们将在此基础上进行构建：

```java
Narrative: 
In order to manage the book store collection efficiently 
As a store administrator 
I want to be able to add, update, and remove books 
```

我们将使用 JBehave 格式来编写故事。有关 JBehave 的更多详细信息即将推出。在此之前，请访问[`jbehave.org/`](http://jbehave.org/)获取更多信息。

叙述总是以`Narrative`行开始，然后是`In order to`、`As a`和`I want to`行。我们已经讨论过它们各自的含义。

现在我们知道了为什么、谁和什么的答案，是时候和团队的其他成员坐下来讨论可能的场景了。我们还没有谈论步骤（`Given`、`When`和`Then`），而只是潜在场景的概述或简短描述。列表可能如下：

```java
Scenario: Book details form should have all fields 
Scenario: User should be able to create a new book 
Scenario: User should be able to display book details 
Scenario: User should be able to update book details 
Scenario: User should be able to delete a book 
```

我们遵循 JBehave 语法，使用`Scenario`后跟一个简短的描述。在这个阶段没有必要详细讨论；这个阶段的目的是作为一个快速的头脑风暴会议。在这种情况下，我们想出了这五个场景。第一个应该定义我们将用来管理书籍的表单字段。其余的场景试图定义不同的管理任务。它们都没有什么真正创造性的。我们应该开发一个非常简单的应用的 MVP。如果证明成功，我们可以扩展并真正发挥我们的创造力。根据当前的目标，应用将是简单而直接的。

现在我们知道了我们的场景是什么，总体上，是时候适当地定义每一个了。让我们开始处理第一个：

```java
Scenario: Book details form should have all fields 

Given user is on the books screen 
Then field bookId exists 
Then field bookTitle exists 
Then field bookAuthor exists 
Then field bookDescription exists 
```

这个场景不包含任何动作；没有`When`步骤。它可以被视为一个健全性检查。它告诉开发人员书籍表单中应该有哪些字段。通过这些字段，我们可以决定使用什么数据模式。ID 足够描述性，我们知道每个字段是关于什么的（一个 ID 和三个文本字段）。请记住，这个场景（以及接下来的场景）都是纯文本，没有任何代码。主要优点是任何人都可以编写它们，我们会尽量保持这种方式。

让我们看看第二个场景应该是什么样子的：

```java
Scenario: User should be able to create a new book 

Given user is on the books screen 
When user clicks the button newBook 
When user sets values to the book form 
When user clicks the button saveBook 
Then book is stored 
```

这个场景比之前的一个好一点。有一个明确的前提条件（`user`应该在某个屏幕上）；有几个动作（点击`newBook`按钮，填写表单，点击`saveBook`按钮）；最后是结果的验证（书已存储）。

其余的场景如下（因为它们都以类似的方式工作，我们觉得没有必要单独解释每一个）：

```java
Scenario: User should be able to display book details 

Given user is on the books screen 
When user selects a book 
Then book form contains all data 

Scenario: User should be able to update book details 

Given user is on the books screen 
When user selects a book 
When user sets values to the book form 
Then book is stored 

Scenario: User should be able to delete a book 

Given user is on the books screen 
When user selects a book 
When user clicks the deleteBook button 
Then book is removed 
```

唯一值得注意的是，当合适时我们使用相同的步骤（例如，`When user selects a book`）。因为我们很快会尝试自动化所有这些场景，使用相同的步骤文本将节省我们一些时间，避免重复编写代码。在表达场景的最佳方式和自动化的便利性之间保持平衡是很重要的。我们可以修改现有场景中的一些内容，但在重构它们之前，让我们先介绍一下 JBehave。

源代码可以在`00-story`分支的`tdd-java-ch08-books-store` Git 存储库中找到，网址为[`bitbucket.org/vfarcic/tdd-java-ch08-books-store/branch/00-story`](https://bitbucket.org/vfarcic/tdd-java-ch07-books-store/branch/00-story)。

# JBehave

JBehave 运行 BDD 故事需要两个主要组件——运行器和步骤。运行器是一个类，它将解析故事，运行所有场景，并生成报告。步骤是与场景中编写的步骤匹配的代码方法。项目已经包含了所有 Gradle 依赖项，所以我们可以直接开始创建 JBehave 运行器。

# JBehave 运行器

JBehave 也不例外，每种类型的测试都需要一个运行器。在前几章中，我们使用了 JUnit 和 TestNG 运行器。虽然这两者都不需要任何特殊配置，但 JBehave 要求我们创建一个类，其中包含运行故事所需的所有配置。

以下是我们将在本章中使用的`Runner`代码：

```java
public class Runner extends JUnitStories { 

  @Override 
  public Configuration configuration() { 
    return new MostUsefulConfiguration() 
                  .useStoryReporterBuilder(getReporter()) 
                  .useStoryLoader(new LoadFromURL()); 
  } 

  @Override 
  protected List<String> storyPaths() { 
    String path = "stories/**/*.story"; 
    return new StoryFinder().findPaths(
                CodeLocations.codeLocationFromPath("").getFile(),
                Collections.singletonList(path), 
                new ArrayList<String>(),
                "file:"); 
  }

  @Override 
  public InjectableStepsFactory stepsFactory() {
    return new InstanceStepsFactory(configuration(), new Steps());
  } 

  private StoryReporterBuilder getReporter() { 
    return new StoryReporterBuilder() 
       .withPathResolver(new FilePrintStreamFactory.ResolveToSimpleName())
       .withDefaultFormats()
       .withFormats(Format.CONSOLE, Format.HTML);
  }
}
```

这是非常平淡无奇的代码，所以我们只会对一些重要的部分进行评论。重写的`storyPaths`方法将我们的故事文件位置设置为`stories/**/*.story`路径。这是标准的 Apache Ant ([`ant.apache.org/`](http://ant.apache.org/))语法，翻译成普通语言意味着`stories`目录或任何子目录（`**`）中以`.story`结尾的任何文件都将被包括在内。另一个重要的重写方法是`stepsFactory`，用于设置包含步骤定义的类（我们很快就会与它们一起工作）。在这种情况下，我们将其设置为一个名为`Steps`的单个类的实例（存储库已经包含了一个我们稍后会使用的空类）。

源代码可以在`01-runner`分支的` tdd-java-ch08-books-store` Git 存储库中找到，网址为[`bitbucket.org/vfarcic/tdd-java-ch08-books-store/branch/01-runner`](https://bitbucket.org/vfarcic/tdd-java-ch07-books-store/branch/01-runner)。

现在我们的运行器已经完成，是时候启动它并查看结果了。

# 待定步骤

我们可以使用以下 Gradle 命令运行我们的情景：

```java
$ gradle clean test
```

Gradle 只运行自上次执行以来发生变化的任务。由于我们的源代码不会总是改变（我们通常只修改文本格式的故事），因此需要在`test`之前运行`clean`任务以删除缓存。

JBehave 为我们创建了一个漂亮的报告，并将其放入`target/jbehave/view`目录。在您喜欢的浏览器中打开`reports.html`文件。

报告的初始页面显示了我们故事的列表（在我们的情况下，只有 Administration）和两个预定义的故事，称为 BeforeStories 和 AfterStories。它们的目的类似于`@BeforeClass`和`@AfterClass` JUnit 注解方法。它们在故事之前和之后运行，并且可以用于设置和拆除数据、服务器等。

这个初始报告页面显示我们有五种情景，它们都处于待定状态。这是 JBehave 告诉我们的方式，它们既不成功也不失败，而是我们使用的步骤背后缺少代码：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/test-dvn-java-dev/img/71212836-767b-49ff-babc-8b3caef3562f.png)

每行的最后一列包含一个链接，允许我们查看每个故事的详细信息：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/test-dvn-java-dev/img/64b19c4e-c087-4791-be7a-eb538eeeaeb0.png)

在我们的情况下，所有的步骤都标记为待定。JBehave 甚至提出了我们需要为每个待定步骤创建的方法的建议。

总结一下，在这一点上，我们编写了一个包含五个情景的故事。这些情景中的每一个都相当于一个规范，既应该被开发，也应该用来验证开发是否正确完成。这些情景中的每一个都由几个步骤组成，定义了前提条件（`Given`）、行动（`When`）和预期结果（`Then`）。

现在是时候编写我们步骤背后的代码了。然而，在我们开始编码之前，让我们先介绍一下 Selenium 和 Selenide。

# Selenium 和 Selenide

Selenium 是一组可以用来自动化浏览器的驱动程序。我们可以使用它们来操作浏览器和页面元素，例如点击按钮或链接，填写表单字段，打开特定的 URL 等等。几乎所有浏览器都有相应的驱动程序，包括 Android、Chrome、FireFox、Internet Explorer、Safari 等等。我们最喜欢的是 PhantomJS，它是一个无界面的浏览器，比传统浏览器运行速度更快，我们经常用它来快速获取关于 Web 应用程序准备就绪的反馈。如果它按预期工作，我们可以继续在所有不同的浏览器和版本中尝试它，以确保我们的应用程序能够支持。

有关 Selenium 的更多信息可以在[`www.seleniumhq.org/`](http://www.seleniumhq.org/)找到，支持的驱动程序列表在[`www.seleniumhq.org/projects/webdriver/`](http://www.seleniumhq.org/projects/webdriver/)。

虽然 Selenium 非常适合自动化浏览器，但它也有缺点，其中之一是它在非常低的级别上操作。例如，点击按钮很容易，可以用一行代码完成：

```java
selenium.click("myLink") 
```

如果 ID 为`myLink`的元素不存在，Selenium 将抛出异常，测试将失败。虽然我们希望当预期的元素不存在时测试失败，但在许多情况下并不那么简单。例如，我们的页面可能会在异步请求服务器得到响应后才动态加载该元素。因此，我们可能不仅希望点击该元素，还希望等待直到它可用，并且只有在超时时才失败。虽然这可以用 Selenium 完成，但是这很繁琐且容易出错。此外，为什么我们要做别人已经做过的工作呢？让我们来认识一下 Selenide。

Selenide（[`selenide.org/`](http://selenide.org/)）是对 Selenium `WebDrivers`的封装，具有更简洁的 API、对 Ajax 的支持、使用 JQuery 风格的选择器等等。我们将在所有的 Web 步骤中使用 Selenide，您很快就会更加熟悉它。

现在，让我们写一些代码。

# JBehave 步骤

在开始编写步骤之前，安装 PhantomJS 浏览器。您可以在[`phantomjs.org/download.html`](http://phantomjs.org/download.html)找到有关您操作系统的说明。

安装了 PhantomJS 后，现在是时候指定一些 Gradle 依赖了：

```java
dependencies { 
    testCompile 'junit:junit:4.+' 
    testCompile 'org.jbehave:jbehave-core:3.+' 
    testCompile 'com.codeborne:selenide:2.+' 
    testCompile 'com.codeborne:phantomjsdriver:1.+' 
} 
```

您已经熟悉了 JUnit 和之前设置的 JBehave Core。两个新的添加是 Selenide 和 PhantomJS。刷新 Gradle 依赖项，以便它们包含在您的 IDEA 项目中。

现在是时候将 PhantomJS `WebDriver`添加到我们的`Steps`类中了：

```java
public class Steps { 

  private WebDriver webDriver; 

  @BeforeStory 
  public void beforeStory() { 
    if (webDriver == null) { 
      webDriver = new PhantomJSDriver(); 
      webDriverRunner.setWebDriver(webDriver); 
      webDriver.manage().window().setSize(new Dimension(1024, 768));
    }
  }
} 
```

我们使用`@BeforeStory`注解来定义我们用来进行一些基本设置的方法。如果驱动程序尚未指定，我们将设置为`PhantomJSDriver`。由于这个应用程序在较小的设备（手机、平板等）上会有不同的外观，因此我们需要清楚地指定屏幕的尺寸。在这种情况下，我们将其设置为合理的桌面/笔记本显示器分辨率 1024 x 768。

设置完成后，让我们编写我们的第一个待定步骤。我们可以简单地复制并粘贴报告中 JBehave 为我们建议的第一个方法：

```java
@Given("user is on the books screen") 
public void givenUserIsOnTheBooksScreen() { 
// PENDING 
} 
```

想象一下，我们的应用程序将有一个链接，点击它将打开书的界面。

为了做到这一点，我们需要执行两个步骤：

1.  打开网站主页。

1.  点击菜单中的书籍链接。

我们将指定这个链接的 ID 为`books`。ID 非常重要，因为它们可以让我们轻松地在页面上定位一个元素。

我们之前描述的步骤可以翻译成以下代码：

```java
private String url = "http://localhost:9001"; 

@Given("user is on the books screen") 
public void givenUserIsOnTheBooksScreen() { 
  open(url); 
  $("#books").click(); 
} 
```

我们假设我们的应用程序将在`localhost`的`9001`端口上运行。因此，我们首先打开主页的 URL，然后点击 ID 为`books`的元素。Selenide/JQuery 指定 ID 的语法是`#`。

如果我们再次运行我们的运行器，我们会看到第一步失败了，其余的仍然处于“待定”状态。现在，我们处于红色状态的红-绿-重构周期中。

让我们继续完成第一个场景中使用的其余步骤。第二个可以是以下内容：

```java
@Then("field bookId exists") 
public void thenFieldBookIdExists() { 
  $("#books").shouldBe(visible); 
} 
```

第三个步骤几乎相同，所以我们可以重构前一个方法，并将元素 ID 转换为变量：

```java
@Then("field $elementId exists") 
public void thenFieldExists(String elementId) { 
  $("#" + elementId).shouldBe(visible); 
} 
```

通过这个改变，第一个场景中的所有步骤都完成了。如果我们再次运行我们的测试，结果如下：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/test-dvn-java-dev/img/fba0f8bb-160e-419e-bdcb-e7279cfa6e91.png)

第一步失败了，因为我们甚至还没有开始实现我们的书店应用程序。Selenide 有一个很好的功能，每次失败时都会创建浏览器的截图。我们可以在报告中看到路径。其余的步骤处于未执行状态，因为场景的执行在失败时停止了。

接下来要做的事取决于团队的结构。如果同一个人既负责功能测试又负责实现，他可以开始实现并编写足够的代码使该场景通过。在许多其他情况下，不同的人负责功能规格和实现代码。在这种情况下，一个人可以继续为其余场景编写缺失的步骤，而另一个人可以开始实现。由于所有场景已经以文本形式编写，编码人员已经知道应该做什么，两者可以并行工作。我们将选择前一种方式，并为其余待办步骤编写代码。

让我们来看看下一个场景：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/test-dvn-java-dev/img/7764ae22-8928-422f-bb9a-84509441b1a3.png)

我们已经完成了上一个场景中一半的步骤，所以只剩下两个待办事项。在我们点击`newBook`按钮之后，我们应该给表单设置一些值，点击`saveBook`按钮，并验证书籍是否被正确存储。我们可以通过检查它是否出现在可用书籍列表中来完成最后一部分。

缺失的步骤可以是以下内容：

```java
@When("user sets values to the book form")
public void whenUserSetsValuesToTheBookForm() {
  $("#bookId").setValue("123");
  $("#bookTitle").setValue("BDD Assistant");
  $("#bookAuthor").setValue("Viktor Farcic");
  $("#bookDescription")
     .setValue("Open source BDD stories editor and runner");
}

@Then("book is stored")
public void thenBookIsStored() {
  $("#book123").shouldBe(present);
}
```

第二步假设每本可用的书都将以`book[ID]`的格式有一个 ID。

让我们来看看下一个场景：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/test-dvn-java-dev/img/fe09e624-4f55-4b09-bb55-9610baf3e64b.png)

就像在上一个场景中一样，还有两个待开发的步骤。我们需要有一种方法来选择一本书，并验证表单中的数据是否正确填充：

```java
@When("user selects a book") 
public void whenUserSelectsABook() { 
  $("#book1").click(); 
} 

@Then("book form contains all data") 
public void thenBookFormContainsAllData() { 
  $("#bookId").shouldHave(value("1")); 
  $("#bookTitle").shouldHave(value("TDD for Java Developers"));
  $("#bookAuthor").shouldHave(value("Viktor Farcic")); 
  $("#bookDescription").shouldHave(value("Cool book!")); 
} 
```

这两种方法很有趣，因为它们不仅指定了预期的行为（当点击特定书籍链接时，显示带有其数据的表单），还期望某些数据可用于测试。当运行此场景时，ID 为`1`的书，标题为`TDD for Java Developers`，作者为`Viktor Farcic`，描述为`Cool book!`的书应该已经存在。我们可以选择将这些数据添加到数据库中，或者使用一个将提前定义的值提供给测试的模拟服务器。无论如何选择设置测试数据的方式，我们都可以完成这个场景并进入下一个场景：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/test-dvn-java-dev/img/44e20820-5033-42f1-9291-b2c7da917642.png)

待办步骤的实现可以是以下内容：

```java
@When("user sets new values to the book form")
public void whenUserSetsNewValuesToTheBookForm() {
  $("#bookTitle").setValue("TDD for Java Developers revised");
  $("#bookAuthor").setValue("Viktor Farcic and Alex Garcia");
  $("#bookDescription").setValue("Even better book!"); 
  $("#saveBook").click(); 
} 

@Then("book is updated") 
public void thenBookIsUpdated() { 
  $("#book1").shouldHave(text("TDD for Java Developers revised"));
  $("#book1").click();
  $("#bookTitle").shouldHave(value("TDD for Java Developers revised"));
  $("#bookAuthor").shouldHave(value("Viktor Farcic and Alex Garcia")); 
  $("#bookDescription").shouldHave(value("Even better book!")); 
} 
```

最后，只剩下一个场景：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/test-dvn-java-dev/img/6d88b83f-ea0e-48ba-a0b4-d63de3bb12d9.png)

我们可以通过验证它不在可用书籍列表中来验证书籍是否已被移除：

```java
@Then("book is removed") 
public void thenBookIsRemoved() { 
  $("#book1").shouldNotBe(visible); 
} 
```

我们已经完成了步骤代码。现在，开发应用程序的人不仅有需求，还有一种验证每个行为（场景）的方法。他可以逐个场景地通过红-绿-重构周期。

源代码可以在`tdd-java-ch08-books-store` Git 存储库的`02-steps`分支中找到：[`bitbucket.org/vfarcic/tdd-java-ch08-books-store/branch/02-steps`](https://bitbucket.org/vfarcic/tdd-java-ch07-books-store/branch/02-steps)。

# 最终验证

让我们想象一个不同的人在代码上工作，应该满足我们的场景设定的要求。这个人一次选择一个场景，开发代码，运行该场景，并确认他的实现是正确的。一旦所有场景的实现都完成了，就是运行整个故事并进行最终验证的时候了。

为此，应用程序已经打包为`Docker`文件，并且我们已经为执行应用程序准备了一个带有 Vagrant 的虚拟机。

查看分支[`bitbucket.org/vfarcic/tdd-java-ch08-books-store/branch/03-validation`](https://bitbucket.org/vfarcic/tdd-java-ch07-books-store/branch/03-validation)并运行 Vagrant：

```java
$ vagrant up

```

输出应该类似于以下内容：

```java
==> default: Importing base box 'ubuntu/trusty64'...
==> default: Matching MAC address for NAT networking...
==> default: Checking if box 'ubuntu/trusty64' is up to date...
...
==> default: Running provisioner: docker...
    default: Installing Docker (latest) onto machine...
    default: Configuring Docker to autostart containers...
==> default: Starting Docker containers...
==> default: -- Container: books-fe
```

一旦 Vagrant 完成，我们可以通过在我们选择的浏览器中打开`http://localhost:9001`来查看应用程序：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/test-dvn-java-dev/img/f012b0d2-fd07-4234-923f-06243a8e6122.png)

现在，让我们再次运行我们的场景：

```java
$ gradle clean test
```

这一次没有失败，所有场景都成功运行了：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/test-dvn-java-dev/img/cf336342-f442-4174-8bf8-ad5eb38eafdc.png)

一旦所有场景都通过，我们就满足了验收标准，应用程序就可以交付到生产环境中。

# 总结

BDD，本质上是 TDD 的一种变体。它遵循编写测试（场景）在实现代码之前的相同基本原则。它推动开发并帮助我们更好地理解应该做什么。

一个主要的区别是生命周期持续时间。虽然 TDD 是基于单元测试的，我们从红色到绿色的转变非常快（如果不是秒数，就是分钟），BDD 通常采用更高级别的方法，可能需要几个小时甚至几天，直到我们从红色到绿色状态。另一个重要的区别是受众。虽然基于单元测试的 TDD 是开发人员为开发人员完成的，但 BDD 意图通过其无处不在的语言让每个人都参与其中。

虽然整本书都可以写关于这个主题，我们的意图是给你足够的信息，以便你可以进一步调查 BDD。

现在是时候看一看遗留代码以及如何使其更适合 TDD 了。


# 第九章：重构遗留代码-使其年轻化

TDD 可能不会立即适应遗留代码。你可能需要稍微调整一下步骤才能使其工作。要明白，在这种情况下，你的 TDD 可能会发生变化，因为你不再执行你习惯的 TDD。本章将向你介绍遗留代码的世界，尽可能多地从 TDD 中获取。

我们将从头开始，处理目前正在生产中的遗留应用程序。我们将以微小的方式进行修改，而不引入缺陷或回归，甚至有时间提前吃午饭！

本章涵盖以下主题：

+   遗留代码

+   处理遗留代码

+   REST 通信

+   依赖注入

+   不同级别的测试：端到端、集成和单元

# 遗留代码

让我们从遗留代码的定义开始。虽然有许多作者对此有不同的定义，比如对应用程序或测试的不信任、不再受支持的代码等等。我们最喜欢迈克尔·菲瑟斯创造的定义：

"遗留代码是没有测试的代码。这个定义的原因是客观的：要么有测试，要么没有测试。"

- 迈克尔·菲瑟斯

我们如何检测遗留代码？尽管遗留代码通常等同于糟糕的代码，但迈克尔·菲瑟斯在他的书《与遗留代码有效地工作》中揭露了一些问题，由 Dorling Kindersley（印度）私人有限公司（1993 年）出版。

**代码异味**。

代码异味是指代码中的某些结构，表明违反了基本设计原则，并对设计质量产生了负面影响。

代码异味通常不是错误——它们在技术上不是不正确的，也不会阻止程序当前的运行。相反，它们表明设计上的弱点可能会减缓开发速度或增加将来出现错误或故障的风险。

来源：[`en.wikipedia.org/wiki/Code_smell`](http://en.wikipedia.org/wiki/Code_smell)。

遗留代码的常见问题之一是*我无法测试这段代码*。它正在访问外部资源，引入其他副作用，使用新的操作符等。一般来说，良好的设计易于测试。让我们看一些遗留代码。

# 遗留代码示例

软件概念通常通过代码最容易解释，这个也不例外。我们已经看到并使用了井字棋应用程序（参见第三章，*红-绿-重构-从失败到成功直至完美*）。以下代码执行位置验证：

```java
public class TicTacToe { 

  public void validatePosition(int x, int y) { 
    if (x < 1 || x > 3) { 
      throw new RuntimeException("X is outside board"); 
    } 
    if (y < 1 || y > 3) { 
      throw new RuntimeException("Y is outside board"); 
    } 
  } 
} 
```

与此代码对应的规范如下：

```java
public class TicTacToeSpec { 
  @Rule 
  public ExpectedException exception = 
      ExpectedException.none(); 

  private TicTacToe ticTacToe; 

  @Before 
  public final void before() { 
    ticTacToe = new TicTacToe(); 
  } 

  @Test 
  public void whenXOutsideBoardThenRuntimeException() { 
    exception.expect(RuntimeException.class); 
    ticTacToe.validatePosition(5, 2); 
  } 

  @Test 
  public void whenYOutsideBoardThenRuntimeException() { 
    exception.expect(RuntimeException.class); 
    ticTacToe.validatePosition(2, 5); 
  } 
} 
```

JaCoCo 报告表明一切都被覆盖了（除了最后一行，方法的结束括号）：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/test-dvn-java-dev/img/5ab5211c-027a-4b93-ad7c-e7b568e5a1c3.png)

由于我们相信我们有很好的覆盖率，我们可以进行自动和安全的重构（片段）：

```java
public class TicTacToe { 

  public void validatePosition(int x, int y) { 
    if (isOutsideTheBoard(x)) { 
      throw new RuntimeException("X is outside board"); 
    } 
    if (isOutsideTheBoard(y)) { 
      throw new RuntimeException("Y is outside board"); 
    } 
  } 

  private boolean isOutsideTheBoard(final int position) { 
    return position < 1 || position > 3; 
  } 
} 
```

这段代码应该准备好了，因为测试成功，并且测试覆盖率非常高。

也许你已经意识到了，但有一个问题。`RuntimeException`块中的消息没有经过正确检查；即使代码覆盖率显示它覆盖了该行中的所有分支。

覆盖率到底是什么？

覆盖率是一个用来描述程序源代码被特定测试套件测试的程度的度量。来源：[`en.wikipedia.org/wiki/Code_coverage`](http://en.wikipedia.org/wiki/Code_coverage)。

让我们想象一个覆盖了代码的一部分简单部分的单一端到端测试。这个测试将使你的覆盖率百分比很高，但安全性不高，因为还有许多其他部分没有被覆盖。

我们已经在我们的代码库中引入了遗留代码——异常消息。只要这不是预期行为，这可能没有什么问题——没有人应该依赖异常消息，不是程序员调试他们的程序，或者日志，甚至用户。那些没有被测试覆盖的程序部分很可能在不久的将来遭受回归。如果你接受风险，这可能没问题。也许异常类型和行号就足够了。

我们已经决定删除异常消息，因为它没有经过测试：

```java
public class TicTacToe { 

  public void validatePosition(int x, int y) { 
    if (isOutsideTheBoard(x)) { 
      throw new RuntimeException(""); 
    } 
    if (isOutsideTheBoard(y)) { 
      throw new RuntimeException(""); 
    } 
  } 

  private boolean isOutsideTheBoard(final int position) { 
    return position < 1 || position > 3; 
  } 
} 
```

# 识别遗留代码的其他方法

你可能熟悉以下一些常见的遗留应用程序的迹象：

+   在一个补丁的基础上，就像一个活着的弗兰肯斯坦应用程序

+   已知的错误

+   更改是昂贵的

+   脆弱

+   难以理解

+   旧的，过时的，静态的或者经常是不存在的文档

+   散弹手术

+   破窗效应

关于维护它的团队，这是它对团队成员产生的一些影响：

+   辞职：负责软件的人看到了面前的巨大任务

他们

+   没有人再关心：如果你的系统已经有了破窗，引入新的破窗就更容易。

由于遗留代码通常比其他类型的软件更难，你会希望你最好的人来处理它。然而，我们经常受到截止日期的催促，想要尽快编程所需的功能，并忽略解决方案的质量。

因此，为了避免以这种糟糕的方式浪费我们才华横溢的开发人员，我们期望非遗留应用程序能够实现完全相反的情况。它应该是：

+   易于更改

+   可概括，可配置和可扩展

+   易于部署

+   健壮

+   没有已知的缺陷或限制

+   易于教给他人/从他人学习

+   广泛的测试套件

+   自我验证

+   能够使用钥匙孔手术

由于我们已经概述了遗留和非遗留代码的一些属性，应该很容易用其他质量替换一些质量。对吧？停止散弹手术，使用钥匙孔手术，再加上一些细节，你就完成了。对吧？

这并不像听起来那么容易。幸运的是，有一些技巧和规则，当应用时，可以改进我们的代码，应用程序更接近非遗留代码。

# 缺乏依赖注入

这是遗留代码库中经常检测到的一种味道。由于没有必要单独测试类，协作者在需要时被实例化，将创建协作者和使用它们的责任放在同一个类中。

这里有一个例子，使用`new`操作符：

```java
public class BirthdayGreetingService { 

  private final MessageSender messageSender; 

  public BirthdayGreetingService() { 
    messageSender = new EmailMessageSender(); 
  } 

  public void greet(final Employee employee) { 
    messageSender.send(employee.getAddress(), 
     "Greetings on your birthday"); 
  } 
} 
```

在当前状态下，`BirthdayGreeting`服务不可单元测试。它在构造函数中硬编码了对`EmailMessageSender`的依赖。除了使用反射注入对象或在`new`操作符上替换对象之外，无法替换这种依赖。

修改代码库总是可能引起回归的源头，所以应该谨慎进行。重构需要测试，除非不可能。

遗留代码困境。

当我们改变代码时，应该有测试。要进行测试，我们经常必须改变代码。

# 遗留代码更改算法

当你必须在遗留代码库中进行更改时，这是一个你可以使用的算法：

+   识别更改点

+   找到测试点

+   打破依赖关系

+   编写测试

+   进行更改和重构

# 应用遗留代码更改算法

要应用这个算法，我们通常从一套测试开始，并在重构时始终保持绿色。这与 TDD 的正常周期不同，因为重构不应引入任何新功能（也就是说，不应编写任何新的规范）。

为了更好地解释这个算法，想象一下我们收到了以下更改请求：为了以更非正式的方式向我的员工致以问候，我想发送一条推文而不是一封电子邮件。

# 识别更改点

系统目前只能发送电子邮件，因此需要进行更改。在哪里？快速调查显示，发送祝福的策略是在`BirthdayGreetingService`类的构造函数中决定的，遵循策略模式（[`en.wikipedia.org/?title=Strategy_pattern`](https://en.wikipedia.org/?title=Strategy_pattern)）：

```java
public class BirthdayGreetingService { 

  public BirthdayGreetingService() { 
    messageSender = new EmailMessageSender(); 
  } 
  [...] 
} 
```

# 找到测试点

由于`BirthdayGreetingService`类没有注入的协作者可以用来给对象附加额外的责任，唯一的选择是离开这个服务类来进行测试。一个选择是将`EmailMessageSender`类更改为模拟或虚拟实现，但这会对该类的实现造成风险。

另一个选择是为这个功能创建一个端到端的测试：

```java
public class EndToEndTest { 

  @Test 
  public void email_an_employee() { 
    final StringBuilder systemOutput = 
       injectSystemOutput(); 
    final Employee john = new Employee( 
       new Email("john@example.com")); 

    new BirthdayGreetingService().greet(john); 

    assertThat(systemOutput.toString(),  
      equalTo("Sent email to " 
        + "'john@example.com' with " 
        + "the body 'Greetings on your " 
        + "birthday'\n")); 
  } 

  // This code has been used with permission from 
  //GMaur's LegacyUtils: 
  // https://github.com/GMaur/legacyutils 
  private StringBuilder injectSystemOutput() { 
    final StringBuilder stringBuilder = 
      new StringBuilder(); 
    final PrintStream outputPrintStream = 
      new PrintStream( 
        new OutputStream() { 
        @Override 
        public void write(final int b) 
          throws IOException { 
          stringBuilder.append((char) b); 
        } 
      }); 
    System.setOut(outputPrintStream); 
    return stringBuilder; 
  } 
} 
```

此代码已经获得了[`github.com/GMaur/legacyutils`](https://github.com/GMaur/legacyutils)的许可使用。这个库可以帮助你执行捕获系统输出（`System.out`）的技术。

文件的名称不以 Specification（或`Spec`）结尾，比如`TicTacToeSpec`，因为这不是一个规范。这是一个测试，以确保功能保持不变。文件被命名为`EndToEndTest`，因为我们试图尽可能多地覆盖功能。

# 打破依赖关系

在创建了一个保证预期行为不会改变的测试之后，我们将打破`BirthdayGreetingService`和`EmailMessageSender`之间的硬编码依赖。为此，我们将使用一种称为**提取**和**重写调用**的技术，这首先在 Michael Feathers 的书中解释过：

```java
public class BirthdayGreetingService { 

  public BirthdayGreetingService() { 
    messageSender = getMessageSender(); 
  } 

  private MessageSender getMessageSender() { 
    return new EmailMessageSender(); 
  } 

[...] 
```

再次执行测试，并验证我们之前创建的孤立测试仍然是绿色的。此外，我们需要将这个方法`protected`或更加开放以便进行重写：

```java
public class BirthdayGreetingService { 

  protected MessageSender getMessageSender() { 
    return new EmailMessageSender(); 
  } 

[...] 
```

现在该方法可以被重写，我们创建一个虚拟服务来替换原始服务的实例。在代码中引入虚拟是一种模式，它包括创建一个可以替换现有对象的对象，其特点是我们可以控制其行为。这样，我们可以注入一些定制的虚拟来实现我们的需求。更多信息请参阅[`xunitpatterns.com/`](http://xunitpatterns.com/)。

在这种特殊情况下，我们应该创建一个扩展原始服务的虚拟服务。下一步是重写复杂的方法，以便为测试目的绕过代码的无关部分：

```java
public class FakeBirthdayGreetingService 
 extends BirthdayGreetingService { 

  @Override 
  protected MessageSender getMessageSender() { 
    return new EmailMessageSender(); 
  } 
} 
```

现在我们可以使用虚拟，而不是`BirthdayGreetingService`类：

```java
public class EndToEndTest { 

  @Test 
  public void email_an_employee() { 
    final StringBuilder systemOutput = 
      injectSystemOutput(); 
    final Employee john = new Employee( 
       new Email("john@example.com")); 

    new FakeBirthdayGreetingService().greet(john); 

    assertThat(systemOutput.toString(), 
      equalTo("Sent email to " 
        + "'john@example.com' with " 
        + "the body 'Greetings on  
        + "your birthday'\n")); 
  } 
```

测试仍然是绿色的。

现在我们可以应用另一种打破依赖关系的技术，即参数化构造函数，Feathers 在[`archive.org/details/WorkingEffectivelyWithLegacyCode`](https://archive.org/details/WorkingEffectivelyWithLegacyCode)的论文中有解释。生产代码可能如下所示：

```java
public class BirthdayGreetingService { 

  public BirthdayGreetingService(final MessageSender 
     messageSender) { 
    this.messageSender = messageSender; 
  } 
  [...] 
} 
```

与此实现对应的测试代码可能如下：

```java
public class EndToEndTest { 

  @Test 
  public void email_an_employee() { 
    final StringBuilder systemOutput = 
      injectSystemOutput(); 
    final Employee john = new Employee( 
      new Email("john@example.com")); 

    new BirthdayGreetingService(new 
         EmailMessageSender()).greet(john); 

    assertThat(systemOutput.toString(),  
      equalTo("Sent email to " 
        + "'john@example.com' with " 
        + "the body 'Greetings on " 
        + "your birthday'\n")); 
  } 
  [...] 
```

我们还可以删除`FakeBirthday`，因为它已经不再使用。

# 编写测试

在保留旧的端到端测试的同时，创建一个交互来验证`BirthdayGreetingService`和`MessageSender`的集成：

```java
  @Test 
  public void the_service_should_ask_the_messageSender() { 
    final Email address = 
      new Email("john@example.com"); 
    final Employee john = new Employee(address); 
    final MessageSender messageSender = 
      mock(MessageSender.class); 

    new BirthdayGreetingService(messageSender) 
      .greet(john); 

    verify(messageSender).send(address, 
         "Greetings on your birthday"); 
  } 
```

在这一点上，可以编写一个新的`TweetMessageSender`，完成算法的最后一步。

# kata 练习

程序员唯一能够提高的方法是通过实践。创建不同类型的程序并使用不同的技术通常会为程序员提供对软件构建的新见解。基于这个想法，kata 是一种定义了一些要求或固定特性的练习，以实现一些目标。

程序员被要求实现一个可能的解决方案，然后与其他解决方案进行比较，试图找到最佳解决方案。这个练习的关键价值不在于获得最快的实现，而在于讨论在设计解决方案时所做的决定。在大多数情况下，kata 中创建的所有程序最终都会被丢弃。

本章的 kata 练习是关于一个传统系统。这是一个足够简单的程序，在本章中可以处理，但也足够复杂，会带来一些困难。

# 传统 kata

您已经被分配了一个任务，即接管一个已经在生产中的系统，一个用于图书馆的工作软件：Alexandria 项目。

该项目目前缺乏文档，旧的维护者也不再提供讨论。因此，如果您接受这个任务，这将完全是您的责任，因为没有其他人可以依靠。

# 描述

我们已经能够从原始项目编写时恢复这些规范片段：

+   Alexandria 软件应该能够存储图书并将它们借给用户，用户有权归还图书。用户还可以通过作者、书名、状态和 ID 查询系统中的图书。

+   没有时间限制归还图书。

+   图书也可以被审查，因为这对业务原因很重要。

+   软件不应接受新用户。

+   用户应该在任何时候被告知服务器的时间。

# 技术评论

Alexandria 是一个用 Java 编写的后端项目，它使用 REST API 向前端通信信息。为了这个 kata 练习的目的，持久性已经实现为一个内存对象，使用了在[`xunitpatterns.com/Fake%20Object.html`](http://xunitpatterns.com/Fake%20Object.html)中解释的假测试替身。

代码可以在[`bitbucket.org/vfarcic/tdd-java-alexandria`](https://bitbucket.org/vfarcic/tdd-java-alexandria/)找到。

# 添加新功能

在添加新功能之前，传统代码可能不会干扰程序员的生产力。代码库的状态比期望的要差，但生产系统可以正常工作，没有任何不便。

现在是问题开始出现的时候。**产品所有者**（**PO**）想要添加一个新功能。

例如，作为图书管理员，我想知道给定图书的所有历史，以便我可以衡量哪些图书比其他图书更受欢迎。

# 黑盒或尖刺测试

由于 Alexandria 项目的旧维护者不再提供问题，并且没有文档，黑盒测试变得更加困难。因此，我们决定通过调查更好地了解软件，然后进行一些会泄露系统内部知识的尖刺。

我们将稍后使用这些知识来实现新功能。

黑盒测试是一种软件测试方法，它检查应用程序的功能，而不查看其内部结构或工作原理。这种类型的测试可以应用于几乎每个软件测试的级别：单元、集成、系统和验收。它通常占据大部分，如果不是所有的高级别测试，但也可以主导单元测试。

来源：[`en.wikipedia.org/wiki/Black-box_testing`](http://en.wikipedia.org/wiki/Black-box_testing)。

# 初步调查

当我们知道所需的功能时，我们将开始查看 Alexandria 项目：

+   15 个文件

+   基于 Gradle（`build.gradle`）

+   0 个测试

首先，我们想确认这个项目从未经过测试，缺少测试文件夹也证实了这一点：

```java
    $ find src/test
    find: src/test: No such file or directory

```

这些是 Java 部分的文件夹内容：

```java
    $ cd src/main/java/com/packtpublishing/tddjava/ch09/alexandria/
    $ find .
    .
    ./Book.java
    ./Books.java
    ./BooksEndpoint.java
    ./BooksRepository.java
    ./CustomExceptionMapper.java
    ./MyApplication.java
    ./States.java
    ./User.java
    ./UserRepository.java
    ./Users.java

```

以下是剩下的内容：

```java
    $ cd src/main
    $ find resources webapp
    resources
    resources/applicationContext.xml
    webapp
    webapp/WEB-INF
    webapp/WEB-INF/web.xml

```

这似乎是一个 Web 项目（由`web.xml`文件指示），使用 Spring（由`applicationContext.xml`指示）。`build.gradle`中的依赖项显示如下（片段）：

```java
compile 'org.springframework:spring-web:4.1.4.RELEASE'
```

拥有 Spring 已经是一个好迹象，因为它可以帮助进行依赖注入，但快速查看显示上下文并没有真正被使用。也许这是过去使用过的东西？

在`web.xml`文件中，我们可以找到这个片段：

```java
<?xml version="1.0" encoding="UTF-8"?> 
<web-app version="3.0"  

         xsi:schemaLocation="http://java.sun.com/xml/ns/javaee 
          http://java.sun.com/xml/ns/javaee/web-app_3_0.xsd"> 

    <module-name>alexandria</module-name> 

    <context-param> 
        <param-name>contextConfigLocation</param-name> 
        <param-value>classpath:applicationContext.xml</param-value> 
    </context-param> 

    <servlet> 
        <servlet-name>SpringApplication</servlet-name> 
        <servlet-class>
 org.glassfish.jersey.servlet.ServletContainer</servlet-class> 
        <init-param> 
            <param-name>javax.ws.rs.Application</param-name> 
            <param-value>com.packtpublishing.tddjava.alexandria.MyApplication</param-value> 
        </init-param> 
        <load-on-startup>1</load-on-startup> 
    </servlet> 
```

在这个文件中，我们发现了以下内容：

+   `applicationContext.xml`中的上下文将被加载

+   有一个应用文件（`com.packtpublishing.tddjava.alexandria.MyApplication`）将在一个 servlet 内执行

`MyApplication`文件如下：

```java
public class MyApplication extends ResourceConfig { 

  public MyApplication() { 
    register(RequestContextFilter.class); 
    register(BooksEndpoint.class); 
    register(JacksonJaxbJsonProvider.class); 
    register(CustomExceptionMapper.class); 
  } 
} 
```

配置执行`BooksEndpoint`端点所需的必要类（片段）：

```java
@Path("books") 
@Component 
public class BooksEndpoint { 

  private BooksRepository books = new BooksRepository(); 

  private UserRepository users = new UserRepository(); 
books and users) are created inside the endpoint and not injected. This makes unit testing more difficult.
```

我们可以从写下将在重构过程中使用的元素开始；我们在`BooksEndpoint`中编写**依赖注入**的代码。

# 如何寻找重构的候选对象

有不同的编程范式（例如，函数式、命令式和面向对象）和风格（例如，紧凑、冗长、简约和过于聪明）。因此，不同的人对重构的候选对象也不同。

还有另一种方式，与主观相反，可以客观地寻找重构的候选对象。有许多论文调查了如何客观地寻找重构的候选对象。这只是一个介绍，读者可以自行了解更多有关这些技术的信息。

# 引入新功能

在更深入了解代码之后，似乎最重要的功能性更改是替换当前的“状态”（片段）：

```java
@XmlRootElement 
public class Book { 

  private final String title; 
  private final String author; 
  private int status; //<- this attribute 
  private int id; 
```

并用它们的集合替换（片段）：

```java
@XmlRootElement 
public class Book { 
  private int[] statuses; 
  // ... 
```

这可能看起来可以工作（例如，将所有对该字段的访问更改为数组），但这也引发了一个功能性需求。

Alexandria 软件应该能够存储图书并将它们借给有权归还的用户。用户还可以通过作者、书名、状态和 ID 查询系统中的图书。

PO 确认通过“状态”搜索图书现在已经更改，它还允许搜索任何先前的“状态”。

这个改变越来越大。每当我们觉得是时候移除这个传统代码时，我们就开始应用传统代码算法。

我们还发现了原始执念和特性嫉妒的迹象：将“状态”存储为整数（原始执念），然后对另一个对象的状态进行操作（特性嫉妒）。我们将把这加入以下待办事项清单：

+   `BooksEndpoint`中的依赖注入

+   将“状态”更改为“状态”

+   删除对“状态”的原始执念（可选）

# 应用传统代码算法

在这种情况下，整个中间端作为独立运行，使用内存持久性。如果持久性保存在数据库中，可以使用相同的算法，但我们需要一些额外的代码来在测试运行之间清理和填充数据库。

我们将使用 DbUnit。更多信息可以在[`dbunit.sourceforge.net/`](http://dbunit.sourceforge.net/)找到。

# 编写端到端测试用例

我们决定采取的第一步，以确保在重构过程中保持行为的一致性，是编写端到端测试。在包括前端的其他应用程序中，可以使用更高级的工具，如 Selenium/Selenide。

在我们的情况下，由于前端不需要重构，所以工具可以是更低级的。我们选择编写 HTTP 请求，以进行端到端测试。

这些请求应该是自动的和可测试的，并且应该遵循所有现有的自动测试或规范。当我们在编写这些测试时发现真实的应用行为时，我们决定在一个名为 Postman 的工具中编写一个试验。

产品网站在这里：[`www.getpostman.com/`](https://www.getpostman.com/)。这也可以使用一个名为 curl 的工具（[`curl.haxx.se/`](http://curl.haxx.se/)）。

curl 是什么？

curl 是一个命令行工具和库，用于使用 URL 语法传输数据，支持`[...] HTTP`、`HTTPS`、`HTTP POST`、`HTTP PUT`和`[...]`。

curl 用于什么？

curl 用于命令行或脚本中传输数据。

来源：[`curl.haxx.se/`](http://curl.haxx.se/)。

为此，我们决定使用以下命令在本地执行传统软件：

```java
./gradlew clean jettyRun
```

这将启动一个处理请求的本地 jetty 服务器。最大的好处是部署是自动完成的，不需要打包一切并手动部署到应用服务器（例如，JBoss AS，GlassFish，Geronimo 和 TomEE）。这可以大大加快进行更改并看到效果的过程，从而减少反馈时间。以后，我们将从 Java 代码中以编程方式启动服务器。

我们开始寻找功能。正如我们之前发现的那样，`BooksEndpoint`类包含了 webservice 端点的定义，这是一个开始寻找功能的好地方。它们列如下：

1.  添加一本新书

1.  列出所有的书

1.  按 ID、作者、标题和状态搜索书籍

1.  准备这本书出租

1.  租借这本书

1.  审查这本书

1.  取消审查这本书

我们手动启动服务器并开始编写请求：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/test-dvn-java-dev/img/d210ad49-9c7a-48e2-b98e-a6fb7c9f6819.png)

这些测试对于一个暂时的测试来说似乎足够好。我们意识到的一件事是，每个响应都包含一个时间戳，所以这使得我们的自动化更加困难：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/test-dvn-java-dev/img/a2cb8545-b5bd-4d7a-adb3-bcd27600297a.png)

为了使测试具有更多的价值，它们应该是自动化和详尽的。目前它们不是，所以我们认为它们是暂时的。它们将在将来自动化。

我们进行的每一个测试都没有自动化。在这种情况下，Postman 界面的测试比自动化测试更快。而且，这种体验更加符合实际生产的使用情况。测试客户端（幸运的是，在这种情况下）可能会对生产环境产生一些问题，因此不能返回可信的结果。

在这种特殊情况下，我们发现 Postman 测试是一个更好的投资，因为即使在编写完它们之后，我们也会将它们丢弃。它们对 API 和结果提供了非常快速的反馈。我们还使用这个工具来原型化 REST API，因为它的工具既有效又有用。

这里的一般想法是：根据你是否想要将这些测试保存到未来，使用一个工具或另一个工具。这也取决于你想要多频繁地执行它们，以及在哪个环境中执行。

在写下所有请求后，这些是我们在应用程序中发现的状态，由状态图表示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/test-dvn-java-dev/img/3ea6c926-39d3-41cc-b9e4-8b78c3c4263b.png)

这些测试准备好后，我们开始理解应用程序，现在是时候自动化测试了。毕竟，如果它们没有自动化，我们对重构就不够自信。

# 自动化测试用例

我们以编程方式启动服务器。为此，我们决定使用 Grizzly（[`javaee.github.io/grizzly/`](https://javaee.github.io/grizzly/)），它允许我们使用 Jersey 的`ResourceConfig`（FQCN：`org.glassfish.jersey.server.ResourceConfig`）的配置来启动服务器，如测试`BooksEndpointTest`（片段）中所示。

代码可以在[`bitbucket.org/vfarcic/tdd-java-alexandria`](https://bitbucket.org/vfarcic/tdd-java-alexandria)找到：

```java
public class BooksEndpointTest { 
    public static final URI FULL_PATH =  
      URI.create("http://localhost:8080/alexandria"); 
    private HttpServer server; 

    @Before 
    public void setUp() throws IOException { 
        ResourceConfig resourceConfig = 
          new MyApplication(); 
        server = GrizzlyHttpServerFactory 
          .createHttpServer(FULL_PATH, resourceConfig); 
        server.start(); 
    } 

    @After 
    public void tearDown(){ 
        server.shutdownNow(); 
    } 
```

这将在地址`http://localhost:8080/alexandria`上准备一个本地服务器。它只会在短时间内可用（测试运行时），所以，如果你需要手动访问服务器，每当你想要暂停执行时，插入一个调用以下方法：

```java
public void pauseTheServer() throws Exception { 
    System.in.read(); 
} 
```

当你想要停止服务器时，停止执行或在分配的控制台中按*Enter*。

现在我们可以以编程方式启动服务器，暂停它（使用前面的方法），并再次执行暂时测试。结果是一样的，所以重构是成功的。

我们向系统添加了第一个自动化测试。

代码可以在[`bitbucket.org/vfarcic/tdd-java-alexandria`](https://bitbucket.org/vfarcic/tdd-java-alexandria)找到：

```java
public class BooksEndpointTest { 

   public static final String AUTHOR_BOOK_1 = 
     "Viktor Farcic and Alex Garcia"; 
    public static final String TITLE_BOOK_1 = 
      "TDD in Java"; 
    private final Map<String, String> TDD_IN_JAVA; 

    public BooksEndpointTest() { 
      TDD_IN_JAVA = getBookProperties(TITLE_BOOK_1, 
        AUTHOR_BOOK_1); 
    } 

    private Map<String, String> getBookProperties 
      (String title, String author) { 
        Map<String, String> bookProperties = 
          new HashMap<>(); 
        bookProperties.put("title", title); 
        bookProperties.put("author", author); 
        return bookProperties; 
    } 

    @Test 
    public void add_one_book() throws IOException { 
        final Response books1 = addBook(TDD_IN_JAVA); 
        assertBooksSize(books1, is("1")); 
    } 

     private void assertBooksSize(Response response, 
        Matcher<String> matcher) { 
        response.then().body(matcher); 
    } 

    private Response addBook 
      (Map<String, ?> bookProperties) { 
        return RestAssured 
            .given().log().path() 
            .contentType(ContentType.URLENC) 
            .parameters(bookProperties) 
            .post("books"); 
    } 
```

为了测试目的，我们使用了一个名为`RestAssured`的库（[`github.com/rest-assured/rest-assured`](https://github.com/rest-assured/rest-assured)），它可以更轻松地测试 REST 和 JSON。

为了完成自动化测试套件，我们创建了这些测试：

+   `add_one_book()`

+   `add_a_second_book()`

+   `get_book_details_by_id()`

+   `get_several_books_in_a_row()`

+   `censor_a_book()`

+   `cannot_retrieve_a_censored_book()`

代码可以在[ https://bitbucket.org/vfarcic/tdd-java-alexandria/](https://bitbucket.org/vfarcic/tdd-java-alexandria/)找到。

现在我们有了一个确保没有引入回归的测试套件，我们来看一下以下的待办事项清单：

1.  书籍的`BooksEndpoint`中的依赖注入

1.  将`status`更改为`statuses`

1.  使用`status`（可选）去除原始偏执

我们将首先解决依赖注入。

# 注入`BookRepository`依赖项

`BookRepository`的依赖代码在`BooksEndpoint`中（片段）：

```java
@Path("books") 
@Component 
public class BooksEndpoint { 

    private BooksRepository books = 
      new BooksRepository(); 
[...] 
```

# 提取和重写调用

我们将应用已经介绍的重构技术提取和重写调用。为此，我们创建一个失败的规范，如下所示：

```java
@Test 
public void add_one_book() throws IOException { 
    addBook(TDD_IN_JAVA); 

    Book tddInJava = new Book(TITLE_BOOK_1, 
      AUTHOR_BOOK_1, 
       States.fromValue(1)); 

    verify(booksRepository).add(tddInJava); 
} 
```

为了通过这个红色的规范，也被称为失败的规范，我们首先将依赖项创建提取到`BookRepository`类的`protected`方法中：

```java
@Path("books") 
@Component 
public class BooksEndpoint { 

    private BooksRepository books = 
      getBooksRepository(); 

    [...] 

     protected BooksRepository 
       getBooksRepository() { 
        return new BooksRepository(); 
    } 

    [...] 
```

我们将`MyApplication`启动器复制到这里：

```java
public class TestApplication 
    extends ResourceConfig { 

    public TestApplication 
      (BooksEndpoint booksEndpoint) { 
        register(booksEndpoint); 
        register(RequestContextFilter.class); 
        register(JacksonJaxbJsonProvider.class); 
        register(CustomExceptionMapper.class); 
    } 

    public TestApplication() { 
        this(new BooksEndpoint( 
          new BooksRepository())); 
    } 
} 
```

这允许我们注入任何`BooksEndpoint`。在这种情况下，在测试`BooksEndpointInteractionTest`中，我们将使用模拟重写依赖项获取器。这样，我们可以检查是否进行了必要的调用（来自`BooksEndpointInteractionTest`的片段）：

```java
@Test 
public void add_one_book() throws IOException { 
    addBook(TDD_IN_JAVA); 
    verify(booksRepository) 
      .add(new Book(TITLE_BOOK_1, 
          AUTHOR_BOOK_1, 1)); 
} 
```

运行测试；一切正常。尽管规范是成功的，但我们为了测试目的引入了一段设计，并且生产代码没有执行这个新的启动器`TestApplication`，而是仍然执行旧的`MyApplication`。为了解决这个问题，我们必须将两个启动器统一为一个。这可以通过重构参数化构造函数来解决，这也在 Roy Osherove 的书《单元测试的艺术》中有解释（[`artofunittesting.com`](http://artofunittesting.com)）。

# 构造函数参数化

我们可以通过接受`BooksEndpoint`依赖项来统一启动器。如果我们不指定，它将使用`BooksRepository`的真实实例注册依赖项。否则，它将注册接收到的依赖项：

```java
public class MyApplication 
      extends ResourceConfig { 

    public MyApplication() { 
        this(new BooksEndpoint( 
          new BooksRepository())); 
    } 

    public MyApplication 
      (BooksEndpoint booksEndpoint) { 
        register(booksEndpoint); 
        register(RequestContextFilter.class); 
        register(JacksonJaxbJsonProvider.class); 
        register(CustomExceptionMapper.class); 
    } 
} 
```

在这种情况下，我们选择了**构造函数链接**来避免构造函数中的重复。

在进行了这次重构之后，`BooksEndpointInteractionTest`类如下

在最终状态中：

```java
public class BooksEndpointInteractionTest { 

    public static final URI FULL_PATH = URI. 
        create("http://localhost:8080/alexandria"); 
    private HttpServer server; 
    private BooksRepository booksRepository; 

    @Before 
    public void setUp() throws IOException { 
        booksRepository = mock(BooksRepository.class); 
        BooksEndpoint booksEndpoint = 
          new BooksEndpoint(booksRepository); 
        ResourceConfig resourceConfig = 
          new MyApplication(booksEndpoint); 
        server = GrizzlyHttpServerFactory 
           .createHttpServer(FULL_PATH, resourceConfig); 
        server.start(); 
    } 
```

第一个测试通过了，所以我们可以将依赖注入任务标记为完成。

已执行的任务：

+   书籍的`BooksEndpoint`中的依赖注入

待办事项清单：

+   将`status`更改为`statuses`

+   去除原始偏执`status`（可选）

# 添加一个新功能

一旦我们有了必要的测试环境，我们就可以添加新功能。

作为图书管理员，我想知道给定书籍的所有历史，以便我可以衡量哪些书籍比其他书籍更受欢迎。

我们将从一个红色的规范开始：

```java
public class BooksSpec { 

    @Test 
    public void should_search_for_any_past_state() { 
        Book book1 = new Book("title", "author", 
           States.AVAILABLE); 
        book1.censor(); 

        Books books = new Books(); 
        books.add(book1); 

        String available = 
          String.valueOf(States.AVAILABLE); 
        assertThat( 
          books.filterByState(available).isEmpty(), 
           is(false)); 
    } 
} 
```

运行所有测试并查看最后一个失败。

实现所有状态的搜索（片段）：

```java
public class Book { 

    private ArrayList<Integer> status; 

    public Book(String title, String author, int status) { 
        this.title = title; 
        this.author = author; 
        this.status = new ArrayList<>(); 
        this.status.add(status); 
    } 

    public int getStatus() { 
        return status.get(status.size()-1); 
    } 

     public void rent() { 
        status.add(States.RENTED); 
    } 
    [...] 

    public List<Integer> anyState() { 
        return status; 
    } 
    [...] 
```

在这个片段中，我们省略了不相关的部分——未修改的部分，或者更改了实现方式的更多修改方法，比如`rent`，它们以相同的方式改变了实现：

```java
public class Books { 
    public Books filterByState(String state) { 
        Integer expectedState = Integer.valueOf(state); 
        return new Books( 
            new ConcurrentLinkedQueue<>( 
                books.stream() 
                  .filter(x 
                 -> x.anyState() 
                  .contains(expectedState)) 
                  .collect(toList()))); 
    } 
    [...] 
```

外部方法，特别是转换为 JSON 的方法，都没有受到影响，因为`getStatus`方法仍然返回一个`int`值。

我们运行所有测试，一切正常。

已执行的任务：

+   书籍的`BooksEndpoint`中的依赖注入

+   将`status`更改为`statuses`

待办事项清单：

+   去除原始偏执`status`（可选）

# 将状态的原始偏执移除为 int

我们决定也解决待办事项清单中的可选项目。

待办事项清单：

+   书籍的`BooksEndpoint`中的依赖注入

+   将`status`更改为`statuses`

+   删除对`status`的原始执着（可选）

气味：原始执着涉及使用原始数据类型来表示领域思想。 例如，我们使用字符串表示消息，整数表示金额，或者使用结构/字典/哈希表示特定对象。

来源是[`c2.com/cgi/wiki?PrimitiveObsession`](http://c2.com/cgi/wiki?PrimitiveObsession)。

由于这是一项重构步骤（即，我们不会向系统引入任何新行为），因此我们不需要任何新的规范。 我们将继续努力，尽量保持绿色，或者尽可能少的时间离开。

我们已将`States`从具有常量的 Java 类转换为：

```java
public class States { 
    public static final int BOUGHT = 1; 
    public static final int RENTED = 2; 
    public static final int AVAILABLE = 3; 
    public static final int CENSORED = 4; 
} 
```

并将其转换为`enum`：

```java
enum States { 
    BOUGHT (1), 
    RENTED (2), 
    AVAILABLE (3), 
    CENSORED (4); 

    private final int value; 

    private States(int value) { 
        this.value = value; 
    } 

    public int getValue() { 
        return value; 
    } 

    public static States fromValue(int value) { 
        for (States states : values()) { 
            if(states.getValue() == value) { 
                return states; 
            } 
        } 
        throw new IllegalArgumentException( 
          "Value '" + value 
    + "' could not be found in States"); 
    } 
} 
```

调整测试如下：

```java
public class BooksEndpointInteractionTest { 
    @Test 
    public void add_one_book() throws IOException { 
        addBook(TDD_IN_JAVA); 
        verify(booksRepository).add( 
            new Book(TITLE_BOOK_1, AUTHOR_BOOK_1, 
              States.BOUGHT)); 
    } 
    [...] 
public class BooksTest { 

    @Test 
    public void should_search_for_any_past_state() { 
        Book book1 = new Book("title", "author", 
           States.AVAILABLE); 
        book1.censor(); 

        Books books = new Books(); 
        books.add(book1); 

        assertThat(books.filterByState( 
            String.valueOf( 
              States.AVAILABLE.getValue())) 
            .isEmpty(), is(false)); 
    } 
    [...] 
```

调整生产代码。 代码片段如下：

```java
@XmlRootElement 
public class Books { 
      public Books filterByState(String state) { 
        State expected = 
          States.fromValue(Integer.valueOf(state)); 
        return new Books( 
            new ConcurrentLinkedQueue<>( 
                books.stream() 
                  .filter(x -> x.anyState() 
                    .contains(expected)) 
                  .collect(toList()))); 
    } 
    [...] 
```

还有以下内容：

```java
@XmlRootElement 
public class Book { 

    private final String title; 
    private final String author; 
    @XmlTransient 
    private ArrayList<States> status; 
    private int id; 

    public Book 
      (String title, String author, States status) { 
        this.title = title; 
        this.author = author; 
        this.status = new ArrayList<>(); 
        this.status.add(status); 
    } 

    public States getStatus() { 
        return status.get(status.size() - 1); 
    } 

    @XmlElement(name = "status") 
    public int getStatusAsInteger(){ 
        return getStatus().getValue(); 
    } 

    public List<States> anyState() { 
        return status; 
    } 
    [...] 
```

在这种情况下，使用注释进行了序列化：

```java
@XmlElement(name = "status") 
```

将方法的结果转换为名为`status`的字段。

此外，现在将`status`字段标记为`ArrayList<States>`，并使用`@XmlTransient`标记，因此不会序列化为 JSON。

我们执行了所有测试，它们都是绿色的，因此我们现在可以划掉待办清单中的可选元素。

执行的任务：

+   对`BooksEndpoint`进行依赖注入

+   将`status`更改为`statuses`

+   删除对`status`的原始执着（可选）

# 总结

如您所知，继承传统代码库可能是一项艰巨的任务。

我们声明传统代码是没有测试的代码，因此处理传统代码的第一步是创建测试，以帮助您在过程中保持相同的功能。 不幸的是，创建测试并不总是像听起来那么容易。 许多时候，传统代码是紧密耦合的，并呈现出其他症状，表明过去设计不佳，或者至少对代码质量缺乏兴趣。 请不要担心：您可以逐步执行一些繁琐的任务，如[`martinfowler.com/bliki/ParallelChange.html`](http://martinfowler.com/bliki/ParallelChange.html)所示。 此外，众所周知，软件开发是一个学习过程。 工作代码是一个副作用。 因此，最重要的部分是更多地了解代码库，以便能够安全地修改它。 请访问[`www.slideshare.net/ziobrando/model-storming`](http://www.slideshare.net/ziobrando/model-storming)获取更多信息。

最后，我们鼓励您阅读迈克尔·菲瑟斯的书《与传统代码有效地工作》。 它有很多针对这种类型代码库的技术，因此对于理解整个过程非常有用。
