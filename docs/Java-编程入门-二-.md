# Java 编程入门（二）

> 原文：[`zh.annas-archive.org/md5/C2294D9F4E8891D4151421288379909B`](https://zh.annas-archive.org/md5/C2294D9F4E8891D4151421288379909B)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：Java 语言元素和类型

本章从定义语言元素-标识符、变量、文字、关键字、分隔符和注释开始系统地介绍 Java。它还描述了 Java 类型-原始类型和引用类型。特别关注`String`类、`enum`类型和数组。

在本章中，我们将涵盖以下主题：

+   什么是 Java 语言元素？

+   注释

+   标识符和变量

+   保留和受限关键字

+   分隔符

+   原始类型和文字

+   引用类型和字符串

+   数组

+   枚举类型

+   练习-变量声明和初始化

# 什么是 Java 语言元素？

与任何编程语言一样，Java 具有适用于语言元素的语法。这些元素是用于构成语言结构的构建块，允许程序员表达意图。元素本身具有不同的复杂性级别。较低级别（更简单）的元素使得构建更高级别（更复杂）的元素成为可能。有关 Java 语法和语言元素的更详细和系统的处理，请参阅 Java 规范（[`docs.oracle.com/javase/specs`](https://docs.oracle.com/javase/specs)）。

在本书中，我们从属于最低级别之一的输入元素开始。它们被称为**输入元素**，因为它们作为 Java 编译器的输入。

# 输入元素

根据 Java 规范，Java 输入元素可以是以下三种之一：

+   空白字符：可以是这些 ASCII 字符之一- SP（空格），HT（水平制表符）或 FF（换页符，也称为分页符）

+   注释：一个自由形式的文本，不会被编译器处理，而是原样转换为字节码，因此程序员在编写代码时使用注释来添加人类可读的解释。注释可以包括空格，但不会被识别为输入元素；它只会作为注释的一部分进行处理。我们将在*注释*部分描述注释的语法规则并展示一些示例。

+   令牌：可以是以下之一：

+   标识符：将在*标识符和变量*部分描述。

+   关键字：将在*保留和受限关键字*部分描述。

+   分隔符：将在*分隔符*部分描述。

+   文字：将在*原始类型和文字*部分描述。一些文字可以包括空格，但不会被识别为输入元素；空格只会作为文字的一部分进行处理。

+   运算符：将在第九章中描述，*运算符、表达式和语句**。*

输入元素用于构成更复杂的元素，包括类型。一些关键字用于表示类型，我们也将在本章中讨论它们。

# 类型

Java 是一种强类型语言，这意味着任何变量声明必须包括其类型。类型限制了变量可以保存的值以及如何传递这个值。

Java 中的所有类型分为两类：

+   原始类型：在*原始类型和文字*部分描述

+   引用类型：在*引用类型和字符串*部分描述

一些引用类型需要更多关注，要么是因为它们的复杂性，要么是因为其他细节，必须解释清楚以避免将来的混淆：

+   数组：在*数组*部分描述

+   字符串（大写的第一个字符表示它是一个类的名称）：在*引用类型和字符串*部分描述

+   枚举类型：在*枚举类型*部分描述

# 注释

Java 规范提供了关于注释的以下信息：

"有两种注释：

/*文本*/

传统注释：从 ASCII 字符/*到 ASCII 字符*/的所有文本都被忽略（与 C 和 C++一样）。

//文本

行尾注释：从 ASCII 字符//到行尾的所有文本都被忽略（就像 C++中一样）。

这是我们已经编写的`SimpleMath`类中注释的一个例子：

```java
public class SimpleMath {
  /*
    This method just multiplies any integer by 2
    and returns the result
  */
  public int multiplyByTwo(int i){        
    //Should we check if i is bigger than 1/2 of Integer.MAX_VALUE ?
    return i * 2; // The magic happens here
  }
}
```

注释不会以任何方式影响代码。它们只是程序员的注释。此外，不要将它们与 JavaDoc 或其他文档生成系统混淆。

# 标识符和变量

标识符和变量是 Java 中最常用的元素之一。它们密切相关，因为每个变量都有一个名称，而变量的名称是一个标识符。

# 标识符

标识符是 Java 标记列表中的第一个。它是一系列符号，每个符号可以是字母、美元符号`$`、下划线`_`或任何数字 0-9。限制如下：

+   标识符的第一个符号不能是数字

+   单个符号标识符不能是下划线`_`

+   标识符不能与关键字拼写相同（请参阅*保留和受限关键字*部分）

+   标识符不能是布尔文字`true`或`false`

+   标识符不能拼写为特殊类型`null`

如果违反上述任何限制，编译器将生成错误。

实际上，标识符使用的字母通常来自英文字母表-小写或大写。但也可以使用其他字母表。您可以在 Java 规范的第 3.8 节中找到可以包含在标识符中的字母的正式定义（[`docs.oracle.com/javase/specs`](https://docs.oracle.com/javase/specs)）。以下是该部分示例的列表：

+   `i3`

+   `αρετη`

+   `String`

+   `MAX_VALUE`

+   `isLetterOrDigit`

为了展示各种可能性，我们可以再添加两个合法标识符的示例：

+   `$`

+   `_1`

# 变量

变量是一个存储位置，正如 Java 规范在*变量*部分所述。它有一个名称（标识符）和一个分配的类型。变量指的是存储值的内存。

Java 规范规定了八种变量：

+   **类变量**：可以在不创建对象的情况下使用的静态类成员

+   **实例变量**：只能通过对象使用的非静态类成员

+   **数组成员**：数组元素（参见*数组*部分）

+   **方法参数**：传递给方法的参数

+   **构造函数参数**：创建对象时传递给构造函数的参数

+   **Lambda 参数**：传递给 lambda 表达式的参数。我们将在第十七章中讨论它，*Lambda 表达式和函数式编程*

+   **异常参数**：在捕获异常时创建，我们将在第十章中讨论它，*控制流语句*

+   **局部变量**：在方法内声明的变量

从实际角度看，所有八种变量可以总结如下：

+   类成员，静态或非静态

+   数组成员（也称为组件或元素）

+   方法、构造函数或 lambda 表达式的参数

+   catch 块的异常参数

+   常规的局部代码变量，最常见的一种

大多数情况下，当程序员谈论变量时，他们指的是最后一种。它可以是类成员、类实例、参数、异常对象或您正在编写的代码所需的任何其他值。

# 变量声明、定义和初始化

让我们先看一下例子。假设我们连续有这三行代码：

```java
int x;  //declartion of variable x
x = 1;  //initialization of variable x
x = 2;  //assignment of variable x 
```

从前面的例子中可以看出，变量初始化是将第一个（初始）值赋给变量。所有后续的赋值不能称为初始化。

本地变量在初始化之前不能使用：

```java
int x;
int result = x * 2;  //generates compilation error

```

前面代码的第二行将生成编译错误。如果一个变量是类的成员（静态或非静态）或数组的组件，并且没有显式初始化，它将被赋予一个默认值，该默认值取决于变量的类型（参见*Primitive types and literals*和*Reference types and String*部分）。

声明创建一个新变量。它包括变量类型和名称（标识符）。单词**declaration**是 Java 规范中使用的一个技术术语，第 6.1 节（[`docs.oracle.com/javase/specs`](https://docs.oracle.com/javase/specs)）。但是一些程序员在 Java 中使用单词 definition 作为 declaration 的同义词，因为在其他一些编程语言（例如 C 和 C++）中，单词 definition 用于 Java 中不存在的一种语句类型。因此，要注意这一点，并假设当你听到*definition*应用于 Java 时，它们指的是 declaration。

在编写 Java 代码时，大多数情况下，程序员将声明和初始化语句结合在一起。例如，可以声明并初始化一个`int`类型的变量来保存整数`1`，如下所示：

```java
int $ = 1;
int _1 = 1;
int i3 = 1;
int αρετη = 1;
int String = 1;
int MAX_VALUE = 1;
int isLetterOrDigit = 1;

```

相同的标识符可以用来声明和初始化一个`String`类型的变量来保存`abs`：

```java
String $ = "abc";
String _1 = "abc";
String i3 = "abc";
String αρετη = "abc";
String String = "abc";
String MAX_VALUE = "abc";
String isLetterOrDigit = "abc";
```

正如您可能已经注意到的，在前面的例子中，我们使用了*Identifier*部分示例中的标识符。

# final 变量（常量）

final 变量是一旦初始化就不能被赋予另一个值的变量。它由`final`关键字表示：

```java
void someMethod(){
  final int x = 1;
  x = 2; //generates compilation error
  //some other code
}
```

尽管如此，以下代码将正常工作：

```java
void someMethod(){
  final int x;
  //Any code that does not use variable x can be added here
  x = 2;
  //some other code 
}
```java

前面的代码不会生成编译错误，因为在声明语句中，本地变量不会自动初始化为默认值。只有在变量没有显式初始化时，类、实例变量或数组组件才会被初始化为默认值（参见*Primitive types and literals*和*Reference types and String*部分）。

当一个 final 变量引用一个对象时，它不能被赋值给另一个对象，但是随时可以改变被分配的对象的状态（参见*引用类型和 String*部分）。对于引用数组的变量也是一样，因为数组是一个对象（参见*数组*部分）。

由于 final 变量不能被更改，它是一个常量。如果它具有原始类型或`String`类型，则称为常量变量。但是 Java 程序员通常将术语常量应用于类级别的 final 静态变量，并将本地 final 变量称为 final 变量。按照惯例，类级别常量的标识符以大写字母写入。以下是一些示例：

```java
static final String FEBRUARY = "February";
static final int DAYS_IN_DECEMBER = 31;
```

这些常量看起来与以下常量非常相似：

```java
Month.FEBRUARY;
TimeUnit.DAYS;
DayOfWeek.FRIDAY;

```

但前面的常量是在一种特殊类型的类中定义的，称为`enum`，尽管在所有实际目的上，所有常量的行为都是相似的，因为它们不能被更改。只需检查常量的类型，就可以知道其类（类型）提供了什么方法。

# 保留和受限关键字

关键字是 Java 标记中列出的第二个，我们已经看到了几个 Java 关键字——`abstract`, `class`, `final`, `implements`, `int`, `interface`, `new`, `package`, `private`, `public`, `return`, `static`, 和 `void`。现在我们将列出所有保留关键字的完整列表。这些关键字不能用作标识符。

# 保留关键字

以下是 Java 9 的所有 49 个关键字的列表：

| abstract | class | final | implements | int |
| --- | --- | --- | --- | --- |
| interface | new | package | private | public |
| return | static | void | if | this |
| break | double | default | protected | throw |
| byte | else  | import | synchronized | throws |
| case | enum | instanceof | boolean | transient |
| catch | extends | switch | short | try |
| char | for | assert | do | finally |
| continue | float | long | strictfp | volatile |
| native | super | while | _ (下划线) |  |

这些关键字用于不同的 Java 元素和语句，不能用作标识符。`goto`，`const`和`_`（下划线）关键字尚未用作关键字，但它们可能在未来的 Java 版本中使用。目前，它们只是包含在保留关键字列表中，以防止它们用作标识符。但它们可以作为标识符的一部分，例如：

```java
int _ = 3; //Error, underscore is a reserved keyword
int __ = 3; //More than 1 underscore as an identifier is OK
int _1 = 3;
int y_ = 3;
int goto_x = 3;
int const1 = 3;
```

`true` 和 `false` 看起来像关键字，不能用作标识符，但实际上它们不是 Java 关键字。它们是布尔字面值（值）。我们将在*基本类型和字面值*部分定义字面值是什么。

还有另一个看起来像关键字的词，但实际上是一种特殊类型——`null`（参见*引用类型和字符串*部分）。它也不能用作标识符。

# 受限关键字

有十个词被称为受限关键字：`open`，`module`，`requires`，`transitive`，`exports`，`opens`，`to`，`uses`，`provides`和`with`。它们被称为受限，因为它们在模块声明的上下文中不能作为标识符，我们将不在本书中讨论。在所有其他地方，可以将它们用作标识符。以下是这种用法的一个例子：

```java
int to = 1;
int open = 1;
int uses = 1;
int with = 1;
int opens =1;
int module = 1;
int exports =1;
int provides = 1;
int requires = 1;
int transitive = 1;

```

然而，最好不要在任何地方将它们用作标识符。有很多其他方法来命名一个变量。

# 分隔符

分隔符是 Java 标记中列出的第三个。以下是它们的全部十二个，没有特定的顺序：

```java
;  { }  ( )  [ ]  ,  .  ...  ::  @
```

# 分号";"

到目前为止，您已经非常熟悉分隔符`;`（分号）的用法。它在 Java 中的唯一作用是终止语句：

```java
int i;  //declaration statement
i = 2;  //assignment statement
if(i == 3){    //flow control statement called if-statement
  //do something
}
for(int i = 0; i < 10; i++){  
  //do something with each value of i
}
```

# 大括号“{}”

你已经看到了类周围的大括号`{}`：

```java
class SomeClass {
  //class body with code
}
```

你也看到了方法体周围的大括号：

```java
void someMethod(int i){
  //...
  if(i == 2){
    //block of code
  } else {
    //another block of code
  }
  ...
}
```

大括号也用于表示控制流语句中的代码块（参见第十章，*控制流语句*）：

```java
void someMethod(int i){
  //...
  if(i == 2){
    //block of code
  } else {
    //another block of code
  }
  ...
}
```

它们用于初始化数组（请参阅*数组*部分）：

```java
int[] myArray = {2,3,5};

```

还有一些其他很少使用的构造，其中使用大括号。

# 括号“（）”

您还看到了使用分隔符`()`（括号）在方法定义和方法调用中保持方法参数列表：

```java
void someMethod(int i) {
  //...
  String s = anotherMethod();
  //...
}
```

它们还用于控制流语句（请参阅第十章，*控制流语句*）：

```java
if(i == 2){
  //...
}
```

在类型转换期间（请参阅*基本类型和文字*部分），它们放在类型周围：

```java
long v = 23;
int i = (int)v;
```

至于设置执行的优先级（请参阅第九章，*运算符，表达式和语句*），您应该从基本代数中熟悉它：

```java
x = (y + z) * (a + b).
```

# 括号“[]”

分隔符`[]`（方括号）用于数组声明（请参阅*数组*部分）：

```java
int[] a = new int[23];
```

# 逗号“，”

逗号`,`用于括号中列出方法参数的分隔：

```java
void someMethod(int i, String s, int j) {
  //...
  String s = anotherMethod(5, 6.1, "another param");
  //...
}
```

逗号也可以用于在声明语句中分隔相同类型的变量：

```java
int i, j = 2; k;
```

在上面的示例中，`i`，`j`和`k`三个变量都声明为`int`类型，但只有变量`j`初始化为`2`。

在循环语句中使用逗号具有与声明多个变量相同的目的（请参阅第十章，*控制流语句*）：

```java
for (int i = 0; i < 10; i++){
   //...
} 
```

# 句号“.”

分隔符`.`（句点）用于分隔包名称的各个部分，就像您在`com.packt.javapath`示例中看到的那样。

您还看到了如何使用句号来分隔对象引用和该对象的方法：

```java
int result = simpleMath.multiplyByTwo(i);
```

同样，如果`simpleMath`对象具有`a`的公共属性，则可以将其称为`simpleMath.a`。

# 省略号“...”

分隔符`...`（省略号）仅用于 varargs：

```java
int someMethod(int i, String s, int... k){
  //k is an array with elements k[0], k[1], ...
}
```

可以以以下任何一种方式调用前面的方法：

```java
someMethod(42, "abc");          //array k = null
someMethod(42, "abc", 42, 43);  //k[0] = 42, k[1] = 43
int[] k = new int[2];
k[0] = 42;
k[1] = 43;
someMethod(42, "abc", k);       //k[0] = 42, k[1] = 43
```

在第二章中，*Java 语言基础*，在讨论`main()`方法时，我们解释了 Java 中`varargs`（可变参数）的概念。

# 冒号"::"

分隔符`::`（冒号）用于 lambda 表达式中的方法引用（请参阅第十七章，*Lambda 表达式和函数式编程*）：

```java
List<String> list = List.of("1", "32", "765");
list.stream().mapToInt(Integer::valueOf).sum();

```

# @符号“@”

分隔符`@`（@符号）用于表示注释：

```java
@Override
int someMethod(String s){
  //...
}
```

在第四章中创建单元测试时，您已经看到了注释的几个示例，*您的第一个 Java 项目*。 Java 标准库中有几个预定义的注释（`@Deprecated`，`@Override`和`@FunctionalInterface`等）。 我们将在第十七章中使用其中一个（`@FunctionalInterface`），*Lambda 表达式和函数式编程*。

注释是元数据。它们描述类、字段和方法，但它们本身不会被执行。Java 编译器和 JVM 读取它们，并根据注释以某种方式处理所描述的类、字段或方法。例如，在第四章，*您的第一个 Java 项目*中，您看到我们如何使用`@Test`注释。在公共非静态方法前面添加它会告诉 JVM 它是一个必须运行的测试方法。因此，如果您执行此类，JVM 将仅运行此方法。

或者，如果您在方法前面使用`@Override`注释，编译器将检查此方法是否实际覆盖了父类中的方法。如果在任何类的父类中找不到非私有非静态类的匹配签名，则编译器将引发错误。

还可以创建新的自定义注释（JUnit 框架确实如此），但这个主题超出了本书的范围。

# 基本类型和文字

Java 只有两种变量类型：基本类型和引用类型。基本类型定义了变量可以保存的值的类型以及这个值可以有多大或多小。我们将在本节讨论基本类型。

引用类型允许我们只向变量分配一种值 - 对存储对象的内存区域的引用。我们将在下一节*引用类型和字符串*中讨论引用类型。

基本类型可以分为两组：布尔类型和数值类型。数值类型组可以进一步分为整数类型（`byte`、`short`、`int`、`long`和`char`）和浮点类型（float 和 double）。

每种基本类型都由相应的保留关键字定义，列在*保留和受限关键字*部分中。

# 布尔类型

布尔类型允许变量具有两个值之一：`true`或`false`。正如我们在*保留关键字*部分中提到的那样，这些值是布尔文字，这意味着它们是直接表示自己的值 - 而不是一个变量。我们将在*基本类型文字*部分更多地讨论文字。

这是一个`b`变量声明和初始化为值`true`的示例：

```java
boolean b = true;

```

这是另一个示例，使用表达式将`true`值分配给`b`布尔变量：

```java
 int x = 1, y = 1;
 boolean b = 2 == ( x + y );
```

在前面的示例中，在第一行中，声明了两个`int`基本类型的变量`x`和`y`，并分别赋值为`1`。在第二行，声明了一个布尔变量，并将其赋值为`2 == ( x + y )`表达式的结果。括号设置了执行的优先级，如下所示：

+   计算分配给`x`和`y`变量的值的总和

+   使用`==`布尔运算符将结果与`2`进行比较

我们将在第九章，*运算符、表达式和语句*中学习运算符和表达式。

布尔变量用于控制流语句，我们将在第十章，*控制流语句*中看到它们的许多用法。

# 整数类型

Java 整数类型的值占用不同数量的内存：

+   byte：8 位

+   char：16 位

+   short：16 位

+   int：32 位

+   long：64 位

除了`char`之外，所有这些都是有符号整数。符号值（负号`-`为`0`，正号`+`为`1`）占据值的二进制表示的第一位。这就是为什么有符号整数只能作为正数，只能容纳无符号整数值的一半。但它允许有符号整数容纳负数，而无符号整数则不能。例如，在`byte`类型（8 位）的情况下，如果它是无符号整数，它可以容纳的值的范围将从 0 到 255（包括 0 和 255），因为 8 的 2 次方是 256。但是，正如我们所说，`byte`类型是有符号整数，这意味着它可以容纳的值的范围是从-128 到 127（包括-128、127 和 0）。

在`char`类型的情况下，它可以包含从 0 到 65535 的值，因为它是一个无符号整数。这个整数（称为代码点）标识 Unicode 表中的一个记录（[`en.wikipedia.org/wiki/List_of_Unicode_characters`](https://en.wikipedia.org/wiki/List_of_Unicode_characters)）。每个 Unicode 表记录都有以下列：

+   **代码点：** 十进制值，Unicode 记录的数字表示

+   **Unicode 转义：** 带有`\u`前缀的四位数

+   **可打印符号：** Unicode 记录的图形表示（控制码不可用）

+   **描述：** 符号的可读描述

以下是 Unicode 表中的五个记录：

| **代码点** | **Unicode 转义** | **可打印符号** | **描述** |
| --- | --- | --- | --- |
| 8 | \u0008 |  | 退格 |
| 10 | \u000A |  | 换行 |
| 36 | \u0024 | `$` | 美元符号 |
| 51 | \u0033 | `3` | 数字三 |
| 97 | \u0061 | `a` | 拉丁小写字母 a |

前两个示例是代表不可打印的控制码的 Unicode 示例。控制码用于向设备（例如显示器或打印机）发送命令。Unicode 集中只有 66 个这样的代码。它们的代码点从 0 到 32 和从 127 到 159。其余的 65535 个 Unicode 记录都有一个可打印的符号，即记录所代表的字符。

`char`类型的有趣（并且经常令人困惑）之处在于 Unicode 转义和代码点可以互换使用，除非`char`类型的变量参与算术运算。在这种情况下，使用代码点的值。为了证明这一点，让我们看一下以下代码片段（在注释中，我们捕获了输出）：

```java
char a = '3';
System.out.println(a);         //  3
char b = '$';
System.out.println(b);         //  $
System.out.println(a + b);     //  87
System.out.println(a + 2);     //  53
a = 36;    
System.out.println(a);         //  $ 
```

如您所见，`char`类型的变量`a`和`b`代表`3`和`$`符号，并且只要它们不参与算术运算，就会显示为这些符号。否则，只使用代码点值。

从这五个 Unicode 记录中可以看出，`3`字符的代码点值为 51，而`$`字符的代码点值为 36。这就是为什么将`a`和`b`相加得到 87，将`2`加到`a`上得到 53 的原因。

在示例代码的最后一行中，我们将十进制值 36 分配给了`char`类型的变量`a`。这意味着我们已经指示 JVM 将代码点为 36 的字符`$`分配给变量`a`。

这就是为什么`char`类型包含在 Java 的整数类型组中的原因，因为它在算术运算中充当数字类型。

每种原始类型可以容纳的值的范围如下：

+   `byte`：从-128 到 127，包括

+   `short`：从-32,768 到 32,767，包括

+   `int`：从-2.147.483.648 到 2.147.483.647，包括

+   `long`：从-9,223,372,036,854,775,808 到 9,223,372,036,854,775,807，包括

+   `char`：从'\u0000'到'\uffff'，即从 0 到 65,535，包括

您可以随时使用每种原始类型的相应包装类访问每种类型的最大值和最小值（我们将在第九章中更详细地讨论包装类，*运算符，表达式和语句*）。以下是一种方法（在注释中，我们已经显示了输出）：

```java
byte b = Byte.MIN_VALUE;
System.out.println(b);     //  -127
b = Byte.MAX_VALUE;
System.out.println(b);     //   128

short s = Short.MIN_VALUE;
System.out.println(s);      // -32768 
s = Short.MAX_VALUE;
System.out.println(s);      //  32767

int i = Integer.MIN_VALUE;
System.out.println(i);      // -2147483648
i = Integer.MAX_VALUE;
System.out.println(i);      //  2147483647

long l = Long.MIN_VALUE;
System.out.println(l);      // -9223372036854775808
l = Long.MAX_VALUE;
System.out.println(l);      //  9223372036854775807 

char c = Character.MIN_VALUE;
System.out.println((int)c); // 0
c = Character.MAX_VALUE;
System.out.println((int)c); // 65535

```

您可能已经注意到了`(int)c`构造。它称为**转换**，类似于电影制作期间对演员进行特定角色的尝试。任何原始数值类型的值都可以转换为另一个原始数值类型的值，前提是它不大于目标类型的最大值。否则，在程序执行期间将生成错误（此类错误称为运行时错误）。我们将在第九章*运算符，表达式和语句*中更多地讨论原始数值类型之间的转换。

数值类型和`boolean`类型之间的转换是不可能的。如果您尝试执行此操作，将生成编译时错误。

# 浮点类型

在 Java 规范中，浮点类型（`float`和`double`）的定义如下：

"单精度 32 位和双精度 64 位格式 IEEE 754 值。"

这意味着`float`类型占用 32 位，`double`类型占用 64 位。它们表示带有点“。”后的分数部分的正数和负数值：`1.2`，`345.56`，`10.`，`-1.34`。默认情况下，在 Java 中，带有点的数值被假定为`double`类型。因此，以下赋值会导致编译错误：

```java
float r = 23.4;

```

为了避免错误，必须通过在值后附加`f`或`F`字符来指示该值必须被视为`float`类型，如下所示：

```java
float r = 23.4f;
or
float r = 23.4F;
```

这些值（`23.4f`和`23.4F`）本身称为文字。我们将在*原始类型文字*部分中更多地讨论它们。

最小值和最大值可以通过与整数相同的方式找到。只需运行以下代码片段（在注释中，我们捕获了我们在计算机上得到的输出）：

```java
System.out.println(Float.MIN_VALUE);  //1.4E-45
System.out.println(Float.MAX_VALUE);  //3.4028235E38
System.out.println(Double.MIN_VALUE); //4.9E-324 
System.out.println(Double.MAX_VALUE); //1.7976931348623157E308
```

负值的范围与正数的范围相同，只是在每个数字前面加上减号`-`。零可以是`0.0`或`-0.0`。

# 原始类型的默认值

声明变量后，在使用之前必须为其分配一个值。正如我们在*变量声明，定义和初始化*部分中提到的，必须显式初始化或分配值给局部变量。例如：

```java
int x;
int y = 0;
x = 1;
```

但是，如果变量被声明为类字段（静态），实例（非静态）属性或数组组件，并且未显式初始化，则会自动使用默认值进行初始化。值本身取决于变量的类型：

+   对于`byte`，`short`，`int`和`long`类型，默认值为零，`0`

+   对于`float`和`double`类型，默认值为正零，`0.0`

+   对于`char`类型，默认值是`\u0000`，点码为零

+   对于`boolean`类型，默认值是`false`

# 原始类型文字

文字是*输入类型*部分列出的 Java 标记中的第四个。它是一个值的表示。我们将在*引用类型和字符串*部分讨论引用类型的文字。现在我们只讨论原始类型的文字。

为了演示原始类型的文字，我们将在`com.packt.javapath.ch05demo`包中使用一个`LiteralsDemo`程序。您可以通过右键单击`com.packt.javapath.ch05demo`包，然后选择 New | Class，并输入`LiteralsDemo`类名来创建它，就像我们在第四章中描述的那样，*你的第一个 Java 项目*。

在原始类型中，`boolean`类型的文字是最简单的。它们只有两个：`true`和`false`。我们可以通过运行以下代码来演示：

```java
public class LiteralsDemo {
  public static void main(String[] args){
    System.out.println("boolean literal true: " + true);
    System.out.println("boolean literal false: " + false);
  }
}
```

结果将如下所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/27cb9a73-2087-462e-865c-b651793f84e2.png)

这些都是可能的布尔文字（值）。

现在，让我们转向更复杂的`char`类型文字的话题。它们可以是以下形式：

+   一个单个字符，用单引号括起来

+   一个转义序列，用单引号括起来

单引号，或者撇号，是一个具有 Unicode 转义`\u0027`（十进制代码点 39）的字符。当我们在*整数类型*部分演示`char`类型在算术运算中作为数值类型的行为时，我们已经看到了几个`char`类型文字的例子。

以下是`char`类型文字作为单个字符的其他示例：

```java
System.out.println("char literal 'a': " + 'a');
System.out.println("char literal '%': " + '%');
System.out.println("char literal '\u03a9': " + '\u03a9'); //Omega
System.out.println("char literal '™': " + '™'); //Trade mark sign
```

如果你运行上面的代码，输出将如下所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/58d9eba1-c21a-4754-84ef-2ee7419aee0e.png)

现在，让我们谈谈`char`类型文字的第二种类型 - 转义序列。它是一组类似于控制码的字符组合。实际上，一些转义序列包括控制码。以下是完整列表：

+   `\b`（退格 BS，Unicode 转义`\u0008`）

+   `\t`（水平制表符 HT，Unicode 转义`\u0009`）

+   `\n`（换行 LF，Unicode 转义`\u000a`）

+   `\f`（换页 FF，Unicode 转义`\u000c`）

+   `\r`（回车 CR，Unicode 转义`\u000d`）

+   `\ "`（双引号"，Unicode 转义`\u0022`）

+   `\``（单引号'，Unicode 转义`\u0027`）

+   `\\`（反斜杠\，Unicode 转义`\u005c`）

正如你所看到的，转义序列总是以反斜杠（`\`）开头。让我们演示一些转义序列的用法：

```java
System.out.println("The line breaks \nhere");
System.out.println("The tab is\there");
System.out.println("\"");
System.out.println('\'');
System.out.println('\\');
```

如果你运行上面的代码，输出将如下所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/a24ce129-5240-40d3-a07c-bbd43fad874b.png)

正如你所看到的，`\n`和`\t`转义序列只作为控制码。它们本身不可打印，但会影响文本的显示。其他转义序列允许在其他情况下无法打印的上下文中打印符号。连续三个双引号或单引号将被视为编译器错误，就像单个反斜杠字符在没有反斜杠的情况下使用时一样。

与`char`类型文字相比，浮点文字要简单得多。如前所述，默认情况下，`23.45`文字为`double`类型，如果要将其设置为`double`类型，则无需添加字母`d`或`D`。但是，如果您愿意更明确，可以这样做。另一方面，`float`类型文字需要在末尾添加字母`f`或`F`。让我们运行以下示例（请注意我们如何使用`\n`转义序列在输出之前添加换行符）：

```java
System.out.println("\nfloat literal 123.456f: " + 123.456f);
System.out.println("double literal 123.456d: " + 123.456d);

```

结果如下：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/f38e82d3-eb09-42d4-946d-6d2e8179e3e2.png)

浮点类型文字也可以使用`e`或`E`表示科学计数法（参见[`en.wikipedia.org/wiki/Scientific_notation`](https://en.wikipedia.org/wiki/Scientific_notation)）：

```java
System.out.println("\nfloat literal 1.234560e+02f: " + 1.234560e+02f);
System.out.println("double literal 1.234560e+02d: " + 1.234560e+02d);
```

前面代码的结果如下：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/9719f0ac-ec78-41a5-885b-bfcdcd35cb4b.png)

如您所见，无论以十进制格式还是科学格式呈现，值都保持不变。

`byte`，`short`，`int`和`long`整数类型的文字默认为`int`类型。以下赋值不会导致任何编译错误：

```java
byte b = 10;
short s = 10;
int i = 10;
long l = 10;

```

但以下每一行都会生成错误：

```java
byte b = 128;
short s = 32768;
int i = 2147483648;
long l = 2147483648;

```

这是因为`byte`类型可以容纳的最大值为 127，`short`类型可以容纳的最大值为 32,767，`int`类型可以容纳的最大值为 2,147,483,647。请注意，尽管`long`类型可以容纳的最大值为 9,223,372,036,854,775,807，但最后一个赋值仍然失败，因为 2,147,483,648 文字默认为`int`类型，但超过了最大的`int`类型值。要创建`long`类型的文字，必须在末尾添加字母`l`或`L`，因此以下赋值也可以正常工作：

```java
long l = 2147483648L;
```

使用大写`L`是一个好习惯，因为小写字母`l`很容易与数字`1`混淆。

前面的整数字面值示例是用十进制数系统表示的。但是，`byte`，`short`，`int`和`long`类型的文字也可以用二进制（基数 2，数字 0-1），八进制（基数 8，数字 0-7）和十六进制（基数 16，数字 0-9 和 a-f）数系统表示。以下是演示代码：

```java
System.out.println("\nPrint literal 12:");
System.out.println("- bin 0b1100: "+ 0b1100);
System.out.println("- oct    014: "+ 014);
System.out.println("- dec     12: "+ 12);
System.out.println("- hex    0xc: "+ 0xc);

```

如果运行上述代码，输出将是：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/239db86f-5ce2-4211-8ea6-3d63206ac0c1.png)

如您所见，二进制文字以`0b`（或`0B`）开头，后跟以二进制系统表示的值`12`：`1100`（=`2⁰*0 + 2¹*0 + 2²*1 + 2³ *1`）。八进制文字以`0`开头，后跟以八进制系统表示的值`12`：`14`（=`8⁰*4 + 8¹*1`）。十进制文字就是`12`。十六进制文字以`0x`（或`0X`）开头，后跟以十六进制系统表示的值 12——`c`（因为在十六进制系统中，符号`a`到`f`（或`A`到`F`）对应的是十进制值`10`到`15`）。

在文字前面加上减号（`-`）会使值变为负数，无论使用哪种数字系统。以下是演示代码：

```java
System.out.println("\nPrint literal -12:");
System.out.println("- bin 0b1100: "+ -0b1100);
System.out.println("- oct    014: "+ -014);
System.out.println("- dec     12: "+ -12);
System.out.println("- hex    0xc: "+ -0xc);

```

如果运行上述代码，输出将如下所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/5382f549-f0de-4017-a6f5-cabe01bd18d1.png)

另外，为了完成我们对原始类型文字的讨论，我们想提到原始类型文字中下划线（`_`）的可能用法。在长数字的情况下，将其分成组有助于快速估计其数量级。以下是一些示例：

```java
int speedOfLightMilesSec = 299_792_458; 
float meanRadiusOfEarthMiles = 3_958.8f;
long creditCardNumber = 1234_5678_9012_3456L;
```

让我们看看当我们运行以下代码时会发生什么：

```java
long anotherCreditCardNumber = 9876____5678_____9012____1234L;
System.out.println("\n" + anotherCreditCardNumber);

```

前面代码的输出如下：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/65d2e9fd-81b4-42f8-b3d6-6c0413218765.png)

正如您所看到的，如果在数字文字中的数字之间放置一个或多个下划线，这些下划线将被忽略。在任何其他位置放置下划线将导致编译错误。

# 引用类型和字符串

当对象分配给变量时，此变量保存对对象所在内存的引用。从实际的角度来看，这样的变量在代码中被处理，就好像它是所代表的对象一样。这样的变量的类型可以是类、接口、数组或特殊的`null`类型。如果分配了`null`，则对象的引用将丢失，变量不再代表任何对象。如果对象不再使用，JVM 将在称为**垃圾收集**的过程中从内存中删除它。我们将在第十一章中描述这个过程，*JVM 进程和垃圾收集*。

还有一种称为类型变量的引用类型，用于声明泛型类、接口、方法或构造函数的类型参数。它属于 Java 泛型编程的范畴，超出了本书的范围。

所有对象，包括数组，都继承自第二章中描述的`java.lang.Object`类的所有方法，*Java 语言基础*。

引用`java.lang.String`类（或只是`String`）的变量也是引用类型。但在某些方面，`String`对象的行为类似于原始类型，这有时可能会令人困惑。这就是为什么我们将在本章中专门介绍`String`类的原因。

此外，枚举类型（也是引用类型）需要特别注意，我们将在本节末尾的*枚举类型*子节中进行描述。

# 类类型

使用相应的类名声明类类型的变量：

```java
<Class name> variableName;
```

它可以通过将`null`或该类的对象（实例）进行赋值来进行初始化。如果该类有一个超类（也称为父类）从中继承（扩展），则可以使用超类的名称进行变量声明。这是由于 Java 多态性的存在，该多态性在第二章中有所描述，*Java 语言基础*。例如，如果`SomeClass`类扩展`SomeBaseClass`，则以下声明和初始化都是可能的：

```java
SomeBaseClass someBaseClass = new SomeBaseClass();
someBaseClass = new SomeClass();
```java

而且，由于每个类默认都扩展了`java.lang.Object`类，以下声明和初始化也是可能的：

```java
Object someBaseClass = new SomeBaseClass();
someBaseClass = new SomeClass();

```

我们将在第九章中更多地讨论将子类对象分配给基类引用的情况，*运算符、表达式和语句*。

# 接口类型

使用相应的接口名称声明接口类型的变量：

```java
<Interface name> variableName;
```java

它可以通过将`null`或实现接口的类的对象（实例）分配给它来进行初始化。这是一个例子：

```java
interface SomeInterface{
  void someMethod();
}
interface SomeOtherInterface{
  void someOtherMethod();
}
class SomeClass implements SomeInterface {
  void someMethod(){
    ...
  }
} 
class SomeOtherClass implements SomeOtherInterface{
  void someOtherMethod(){
    ...
  }
}
SomeInterface someInterface = new SomeClass();
someInterface = new SomeOtherClass(); //not possible, error
someInterface.someMethod();         //works just fine
someInterface.someOtherMethod();   //not possible, error
```

我们将在[第九章]（33ed1fb4-36e0-499b-8156-4d5e88a2c404.xhtml）中更多地讨论将子类型分配给基类型引用。

# 数组

在 Java 中，数组是引用类型，并且也扩展（继承自）`Object`类。数组包含与声明的数组类型相同的类型的组件，或者可以将值分配给数组类型的类型。组件的数量可以为零，在这种情况下，数组为空数组。

数组组件没有名称，并且由索引引用，该索引是正整数或零。说具有*n*长度的`n`个组件的数组。一旦创建数组对象，其长度就永远不会改变。

数组声明以类型名称和空括号`[]`开头：

```java
byte[] bs;
long[][] ls;
Object[][] os;
SomeClass[][][] scs; 
```

括号对的数量表示数组的维数（或嵌套深度）。

有两种创建和初始化数组的方法：

+   通过创建表达式，使用`new`关键字，类型名称和每个括号中每个维度的长度的括号;例如：

```java
        byte[] bs = new byte[100];
        long[][] ls = new long [2][3];
        Object[][] os = new Object[3][2];
        SomeClass[][][] scs = new SomeClass[3][2][1]; 
```

+   通过数组初始化程序，使用由大括号括起来的每个维度的逗号分隔值的列表，例如：

```java
        int[][] is = { { 1, 2, 3 }, { 10, 20 }, { 3, 4, 5, 6 } };
        float[][] fs = { { 1.1f, 2.2f, 3 }, { 10, 20.f, 30.f } };
        Object[] oss = { new Object(), new SomeClass(), null, "abc" };
        SomeInterface[] sis = { new SomeClass(), null, new SomeClass() };
```

从这些示例中可以看出，多维数组可以包含不同长度的数组（`int [] [] is`数组）。此外，只要值可以分配给数组类型的变量（`float [] [] fs`，`Object [] is`和`SomeInterface [] sis`数组），组件类型值可以与数组类型不同。

因为数组是对象，所以每次创建数组时都会初始化其组件。让我们考虑这个例子：

```java
int[][] is = new int[2][3];
System.out.println("\nis.length=" + is.length);
System.out.println("is[0].length=" + is[0].length);
System.out.println("is[0][0].length=" + is[0][0]);
System.out.println("is[0][1].length=" + is[0][1]);
System.out.println("is[0][2].length=" + is[0][2]);
System.out.println("is[1].length=" + is[0].length);
System.out.println("is[1][0].length=" + is[1][0]);
System.out.println("is[1][1].length=" + is[1][1]);
System.out.println("is[1][2].length=" + is[1][2]);

```

如果我们运行前面的代码片段，输出将如下所示：

！[]（img / a2463ad3-fe53-43ab-9e19-511714b556cf.png）

可以在不初始化某些维度的情况下创建多维数组：

```java
int[][] is = new int[2][];
System.out.println("\nis.length=" + is.length);
System.out.println("is[0]=" + is[0]);
System.out.println("is[1]=" + is[1]);

```

此代码运行的结果如下：

！[]（img / 9c7279b2-2fe4-48b6-aa7e-b42fae6c43e1.png）

缺少的维度可以稍后添加：

```java
int[][] is = new int[2][];
is[0] = new int[3];
is[1] = new int[3];

```

重要的是，必须在使用之前初始化维度。

# 引用类型的默认值

引用类型的默认值是`null`。这意味着如果引用类型是静态类成员或实例字段，并且没有显式分配初始值，它将自动初始化并分配`null`的值。请注意，在数组的情况下，这适用于数组本身和其引用类型组件。

# 引用类型字面量

`null`字面量表示没有对引用类型变量的任何赋值。让我们看下面的代码片段：

```java
SomeClass someClass = new SomeClass();
someClass.someMethod();
someClass = null;
someClass.someMethod(); // throws NullPointerException
```

第一条语句声明了`someClass`变量，并为其分配了`SomeClass`类对象的引用。然后使用其引用调用了该类的一个方法。接下来的一行将`null`字面量赋给`someClass`变量。它从变量中移除了引用值。因此，当在下一行中我们尝试再次调用相同的方法时，我们会得到`NullPointerException`，这只有在使用的引用被赋予`null`值时才会发生。

`String`类型也是一个引用类型。这意味着`String`变量的默认值是`null`。`String`类从`java.lang.Object`类继承了所有方法，就像其他引用类型一样。

但在某些方面，`String`类的对象的行为就像原始类型一样。我们将讨论一个这样的情况——当`String`对象用作方法参数时——在*将引用类型值作为方法参数传递*部分。我们现在将讨论`String`类像原始类型一样行为的其他情况。

`String`类型的另一个特性使它看起来像一个原始类型的是，它是唯一一个不仅仅只有`null`字面量的引用类型。`String`类型也可以有零个或多个字符的字面量，用双引号括起来——`""`，`"$"`，`"abc"`和`"12-34"`。`String`字面量的字符也可以包括转义序列。以下是一些例子：

```java
System.out.println("\nFirst line.\nSecond line.");
System.out.println("Tab space\tin the line");
System.out.println("It is called a \"String literal\".");
System.out.println("Latin Capital Letter Y with diaeresis: \u0178");

```

如果你执行上述代码片段，输出将如下所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/c4ff739c-3cd1-4b9a-8900-8273a4536a18.png)

但是，与`char`类型字面量相反，`String`字面量在算术运算中不像数字那样行为。`String`类型适用的唯一算术运算是加法，它的行为类似于连接：

```java
System.out.println("s1" + "s2");
String s1 = "s1";
System.out.println(s1 + "s2");
String s2 = "s1";
System.out.println(s1 + s2);

```

运行上述代码，你会看到以下内容：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/7d0600b2-bac7-4769-a95f-4e7596b5f802.png)

`String`的另一个特点是，`String`类型的对象是不可变的。

# 字符串的不可变性

不能改变分配给变量的`String`类型值而不改变引用。JVM 作者决定这样做有几个原因：

+   所有的`String`字面量都存储在同一个称为字符串池的共同内存区域中。在存储新的`String`字面量之前，JVM 会检查是否已经存储了这样的字面量。如果这样的对象已经存在，就不会创建新对象，而是返回对现有对象的引用作为对新对象的引用。以下代码演示了这种情况：

```java
        System.out.println("s1" == "s1");
        System.out.println("s1" == "s2");
        String s1 = "s1";
        System.out.println(s1 == "s1");
        System.out.println(s1 == "s2");
        String s2 = "s1";
        System.out.println(s1 == s2);

```

在上述代码中，我们使用了`==`关系运算符，它用于比较原始类型的值和引用类型的引用。如果我们运行这段代码，结果将如下所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/728b25a9-08ca-45aa-a329-f818a04f7801.png)

你可以看到，文字的各种比较（直接或通过变量）始终在两个文字拼写相同的情况下产生`true`，并且在拼写不同的情况下产生`false`。这样，长`String`文字不会被复制，内存使用更好。

为了避免不同方法同时修改相同文字的并发修改，每次我们尝试改变`String`文字时，都会创建一个带有更改的文字副本，而原始的`String`文字保持不变。以下是演示它的代码：

```java
        String s1 = "\nthe original string";
        String s2 = s1.concat(" has been changed"); 
        System.out.println(s2);
        System.out.println(s1);
```

`String`类的`concat()`方法将另一个`String`文字添加到`s1`的原始值，并将结果分配给`s1`变量。此代码的输出如下：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/9007f810-5f17-47ab-a3f9-2f3a8ae6112a.png)

正如你所看到的，分配给`s1`的原始文字没有改变。

+   这样设计的另一个原因是安全性-这是 JVM 作者所考虑的最高优先级目标之一。`String`文字广泛用作用户名和密码，用于访问应用程序、数据库和服务器。`String`值的不可变性使其不太容易受到未经授权的修改。

+   另一个原因是，有一些计算密集型的过程（例如`Object`父类中的`hashCode()`方法）在长`String`值的情况下可能会相当耗费资源。通过使`String`对象不可变，如果已经对具有相同拼写的值执行了这样的计算，就可以避免这样的计算。

这就是为什么所有修改`String`值的方法都返回`String`类型的原因，它是指向携带结果的新`String`对象的引用。前面代码中的`concat()`方法就是这种方法的典型例子。

在`String`对象不是从文字创建的情况下，情况变得有些复杂，而是使用`String`构造函数`new String("some literal")`。在这种情况下，`String`对象存储在存储所有类的所有对象的相同区域，并且每次使用`new`关键字时，都会分配另一块内存（具有另一个引用）。以下是演示它的代码：

```java
String s3 = new String("s");
String s4 = new String("s");
System.out.println(s3 == s4);

```

如果你运行它，输出将如下：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/7d538290-5e7b-49af-a1e5-48067df41fba.png)

正如你所看到的，尽管拼写相同，但对象具有不同的内存引用。为了避免混淆并仅通过拼写比较`String`对象，始终使用`String`类的`equals()`方法。以下是演示其用法的代码：

```java
System.out.println("s5".equals("s5"));  //true
System.out.println("s5".equals("s6"));  //false
String s5 = "s5";
System.out.println(s5.equals("s5"));   //true
System.out.println(s5.equals("s6"));   //false
String s6 = "s6";
System.out.println(s5.equals(s5));     //true
System.out.println(s5.equals(s6));     //false
String s7 = "s6";
System.out.println(s7.equals(s6));     //true
String s8 = new String("s6");
System.out.println(s8.equals(s7));     //true
String s9 = new String("s9");
System.out.println(s8.equals(s9));     //false

```

如果你运行它，结果将是：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/5dc62d29-e4c1-47de-99d1-6f0a32eedba6.png)

我们将结果添加为前面代码的注释，以方便您查看。正如你所看到的，`String`类的`equals()`方法仅基于值的拼写返回`true`或`false`，因此当拼写比较是你的目标时，始终使用它。

顺便说一句，你可能记得`equals()`方法是在`Object`类中定义的——`String`类的父类。`String`类有它自己的`equals()`方法，它覆盖了父类中具有相同签名的方法，就像我们在第二章中展示的那样，*Java 语言基础*。`String`类的`equals()`方法的源代码如下：

```java
public boolean equals(Object anObject) {
  if (this == anObject) {
    return true;
  }
  if (anObject instanceof String) {
    String aString = (String)anObject;
    if (coder() == aString.coder()) {
      return isLatin1() ? 
             StringLatin1.equals(value, aString.value)
            : StringUTF16.equals(value, aString.value);
    }
  }
  return false;
}
```

正如你所看到的，它首先比较引用，如果它们指向相同的对象，则返回`true`。但是，如果引用不同，它会比较值的拼写，这实际上发生在`StringLatin1`和`StringUTF16`类的`equals()`方法中。

我们希望你能明白`String`类的`equals()`方法通过首先执行引用比较来进行优化，只有在不成功时才比较值本身。这意味着在代码中不需要比较引用。相反，对于`String`类型的对象比较，总是只使用`equals()`方法。

有了这个，我们就进入了本章讨论的最后一个引用类型——`enum`类型。

# 枚举类型

在描述`enum`类型之前，让我们看一个使用案例作为拥有这种类型的动机。假设我们想创建一个描述`TheBlows`家庭的类：

```java
public class TheBlows {
  private String name, relation, hobby = "biking";
  private int age;
  public TheBlows(String name, String relation, int age) {
    this.name = name;
    this.relation = relation;
    this.age = age;
  }
  public String getName() { return name; } 
  public String getRelation() { return relation; }
  public int getAge() { return age; }
  public String getHobby() { return hobby; }
  public void setHobby(String hobby) { this.hobby = hobby; }
}
```

我们将默认爱好设置为`骑车`，并允许稍后更改，但其他属性必须在对象构造期间设置。这很好，除了我们不想在系统中有超过四个这个家庭的成员，因为我们非常了解`TheBlows`家庭的所有成员。

为了强加这些限制，我们决定提前创建`TheBlows`类的所有可能对象，并将构造函数设为私有：

```java
public class TheBlows {
  public static TheBlows BILL = new TheBlows("Bill", "father", 42);
  public static TheBlows BECKY = new TheBlows("BECKY", "mother", 37);
  public static TheBlows BEE = new TheBlows("Bee", "daughter", 5);
  public static TheBlows BOB = new TheBlows("Bob", "son", 3);
  private String name, relation, hobby = "biking";
  private int age;
  private TheBlows(String name, String relation, int age) {
    this.name = name;
    this.relation = relation;
    this.age = age;
  }
  public String getName() { return name; }
  public String getRelation() { return relation; }
  public int getAge() { return age; }
  public String getHobby() { return hobby; }
  public void setHobby(String hobby) { this.hobby = hobby; }
}
```

现在只有`TheBlows`类的四个实例存在，这个类的其他对象都不能被创建。让我们看看如果运行以下代码会发生什么：

```java
System.out.println(TheBlows.BILL.getName());
System.out.println(TheBlows.BILL.getHobby());
TheBlows.BILL.setHobby("fishing");
System.out.println(TheBlows.BILL.getHobby());

```

我们将得到以下输出：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/c1cc72d3-55bb-46b8-901b-e202ec027a79.png)

同样，我们可以创建`TheJohns`家庭，有三个家庭成员：

```java
public class TheJohns {
  public static TheJohns JOE = new TheJohns("Joe", "father", 42);
  public static TheJohns JOAN = new TheJohns("Joan", "mother", 37);
  public static TheJohns JILL = new TheJohns("Jill", "daughter", 5);
  private String name, relation, hobby = "joggling";
  private int age;
  private TheJohns(String name, String relation, int age) {
    this.name = name;
    this.relation = relation;
    this.age = age;
  }
  public String getName() { return name; }
  public String getRelation() { return relation; }
  public int getAge() { return age; }
  public String getHobby() { return hobby; }
  public void setHobby(String hobby) { this.hobby = hobby; }
}
```

While doing that, we noticed a lot of commonalities in these two classes and decided to create a `Family` base class:

```java
public class Family {
  private String name, relation, hobby;
  private int age;
  protected Family(String name, String relation, int age, String hobby) {
    this.name = name;
    this.relation = relation;
    this.age = age;
    this.hobby = hobby;
  }
  public String getName() { return name; }
  public String getRelation() { return relation; }
  public int getAge() { return age; }
  public String getHobby() { return hobby; }
  public void setHobby(String hobby) { this.hobby = hobby; }
}
```

Now the `TheBlows` and `TheJohns` classes can be substantially simplified after extending the `Family` class. Here's how the `TheBlows` class can now look:

```java
public class TheBlows extends Family {
  public static TheBlows BILL = new TheBlows("Bill", "father", 42);
  public static TheBlows BECKY = new TheBlows("Becky", "mother", 37);
  public static TheBlows BEE = new TheBlows("Bee", "daughter", 5);
  public static TheBlows BOB = new TheBlows("Bob", "son", 3);
  private TheBlows(String name, String relation, int age) {
    super(name, relation, age, "biking");
  }
}
```

And that is the idea behind the `enum` type—to allow the creating of classes with a fixed number of named instances.

The `enum` reference type class extends the `java.lang.Enum` class. It defines the set of constants, each of them an instance of the `enum` type it belongs to. The declaration of such a set starts with the `enum` keyword. Here is an example:

```java
enum Season { SPRING, SUMMER, AUTUMN, WINTER }
```

Each of the listed items—`SPRING`, `SUMMER`, `AUTUMN`, and `WINTER`—is an instance of `Season`. They are the only four instances of the `Season` class that can exist in an application. No other instance of the `Season` class can be created. And that is the reason for the creation of the `enum` type: it can be used for cases when the list of instances of a class has to be limited to the fixed set, such as the list of possible seasons.

The `enum` declaration can also be written in a camel-case style:

```java
enum Season { Spring, Summer, Autumn, Winter }
```

But the all-uppercase style is used more often because, as we mentioned earlier, the static final constant's identifiers in Java programming are written this way by convention, in order to distinguish them from the non-constant variable. And `enum` constants are static and final implicitly.

Let's review an example of the `Season` class usage. Here is a method that prints different messages, depending on the season:

```java
void enumDemo(Season season){
  if(season == Season.WINTER){
    System.out.println("Dress up warmer");
  } else {
    System.out.println("You can drees up lighter now");
  }
}
```

Let's see what happens if we run the following two lines:

```java
enumDemo(Season.WINTER);
enumDemo(Season.SUMMER);
```

The result will be as follows:

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/8f4d8e93-b7b4-44af-9713-a1a9f6cd14ca.png)

You probably have noticed that we used an `==` operator that compares references. That is because the `enum` instances (as all static variables) exist uniquely in memory. And the `equals()` method (implemented in the `java.lang.Enum` parent class) brings the same result. Let's run the following code:

```java
Season season = Season.WINTER;
System.out.println(Season.WINTER == season);
System.out.println(Season.WINTER.equals(season));

```

The result will be:

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/e650d658-2e63-40ec-8205-ff45287ac8aa.png)

这是因为`java.lang.Enum`类的`equals()`方法是这样实现的：

```java
public final boolean equals(Object other) {
  return this == other;
}
```

正如您所看到的，它确切地比较了两个对象引用-`this`（指代当前对象的保留关键字）和对另一个对象的引用。如果您想知道为什么参数具有`Object`类型，我们想提醒您，所有引用类型，包括`enum`和`String`，都扩展了`java.lang.Object`。它们是隐式的。

`java.lang.Enum`的其他有用方法如下：

+   `name()`: 返回`enum`常量的标识符，就像在声明时拼写的那样。

+   `ordinal()`: 返回与枚举常量在声明时的位置相对应的整数（列表中的第一个枚举常量的序数值为零）。

+   `valueOf()`: 根据其名称返回`enum`常量对象。

+   `toString()`: 默认情况下返回与`name()`方法相同的值，但可以被重写以返回任何其他`String`值。

+   `values()`: 在`java.lang.Enum`类的文档中找不到的静态方法。在 Java 规范的 8.9.3 节（[`docs.oracle.com/javase/specs`](https://docs.oracle.com/javase/specs)）中，它被描述为隐式声明的，而 Java 教程（[`docs.oracle.com/javase/tutorial/java/javaOO/enum.html`](https://docs.oracle.com/javase/tutorial/java/javaOO/enum.html)）则指出编译器*在创建枚举时会自动添加一些特殊方法*。

其中，一个静态的`values()`方法返回一个包含`enum`的所有值的数组，按照它们被声明的顺序。

让我们看一个它们用法的例子。这是我们将用于演示的`enum`类：

```java
enum Season {
  SPRING, SUMMER, AUTUMN, WINTER;
}
```

以下是使用它的代码：

```java
System.out.println(Season.SPRING.name());
System.out.println(Season.SUMMER.ordinal());
System.out.println(Enum.valueOf(Season.class, "AUTUMN"));
System.out.println(Season.WINTER.name());

```

前面片段的输出如下：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/739ed513-aced-4e9c-b307-407928949fd4.png)

第一行是`name()`方法的输出。第二行是`ordinal()`方法的返回值：`SUMMER`常量在列表中是第二个，因此其序数值为 1。第三行是应用于`valueOf()`方法返回的`AUTUMN`的`enum`常量的`toString()`方法的结果。最后一行是应用于`WINTER`常量的`toString()`方法的结果。

`equals()`，`name()`和`ordinal()`方法在`java.lang.Enum`中被声明为`final`，因此它们不能被重写，而是按原样使用。`valueOf()`方法是静态的，不与任何类实例关联，因此不能被重写。我们唯一可以重写的方法是`toString()`方法：

```java
enum Season {
  SPRING, SUMMER, AUTUMN, WINTER;
  public String toString() {
    return "The best season";
  }
}
```

如果我们再次运行前面的代码，结果如下：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/19202174-e824-45da-ab53-4ed72a4ae21b.png)

现在，您可以看到`toString()`方法对于每个常量返回相同的结果。必要时，`toString()`方法可以为每个常量重写。让我们看一下`Season`类的这个版本：

```java
enum Season2 {
  SPRING,
  SUMMER,
  AUTUMN,
  WINTER { public String toString() { return "Winter"; } };
  public String toString() {
    return "The best season";
  }
}
```

我们只为`WINTER`常量重写了`toString()`方法。如果我们再次运行相同的代码片段，结果将如下：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/dc5ddc24-87cd-450a-ab70-0505e97b4b21.png)

正如您所看到的，除了`WINTER`之外，所有常量都使用了旧版本的`toString()`。

还可以为`enum`常量添加任何属性（以及 getter 和 setter），并将每个常量与相应的值关联起来。这是一个例子：

```java
enum Season {
  SPRING("Spring", "warmer than winter", 60),
  SUMMER("Summer", "the hottest season", 100),
  AUTUMN("Autumn", "colder than summer", 70),
  WINTER("Winter", "the coldest season", 40);

  private String feel, toString;
  private int averageTemperature;
  Season(String toString, String feel, int t) {
    this.feel = feel;
    this.toString = toString;
    this.averageTemperature = t;
  }
  public String getFeel(){ return this.feel; }
  public int getAverageTemperature(){
    return this.averageTemperature;
  }
  public String toString() { return this.toString; }
}
```

在上面的示例中，我们在`Season`类中添加了三个属性：`feel`、`toString`和`averageTemperature`。我们还创建了一个构造函数（用于为对象状态分配初始值的特殊方法），该构造函数接受这三个属性并添加获取器和`toString()`返回值的方法。然后，在每个常量的括号中，我们设置了在创建此常量时要传递给构造函数的值。

这是我们将要使用的演示方法：

```java
void enumDemo(Season season){
  System.out.println(season + " is " + season.getFeel());
  System.out.println(season + " has average temperature around " 
                               + season.getAverageTemperature());
}
```

`enumDemo()`方法接受`enum Season`常量并构造并显示两个句子。让我们为每个季节运行上述代码，就像这样：

```java
enumDemo2(Season3.SPRING);
enumDemo2(Season3.SUMMER);
enumDemo2(Season3.AUTUMN);
enumDemo2(Season3.WINTER);

```

结果如下：

![图片](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/90d857fd-ef52-4317-97b9-d2435ab70fb9.png)

`enum`类是一种非常强大的工具，它允许我们简化代码，并使其在运行时更加受保护，因为所有可能的值都是可预测的，并且可以提前测试。例如，我们可以使用以下单元测试来测试`SPRING`常量的获取器：

```java
@DisplayName("Enum Season tests")
public class EnumSeasonTest {
  @Test
  @DisplayName("Test Spring getters")
  void multiplyByTwo(){
    assertEquals("Spring", Season.SPRING.toString());
    assertEquals("warmer than winter", Season.SPRING.getFeel());
    assertEquals(60, Season.SPRING.getAverageTemperature());
  }
}
```

当然，获取器的代码不会出现太多错误。但如果`enum`类有更复杂的方法，或者固定值列表来自于一些应用需求文档，这样的测试将确保我们已按照要求编写了代码。

在标准的 Java 库中，有几个`enum`类。以下是这些类中常量的几个例子，可以让你了解其中的内容：

```java
Month.FEBRUARY;
TimeUnit.DAYS;
TimeUnit.MINUTES;
DayOfWeek.FRIDAY;
Color.GREEN;
Color.green;

```

所以，在创建自己的`enum`之前，尝试检查并查看标准库是否已提供具有所需值的类。

# 将引用类型值作为方法参数传递

一种需要特别讨论的引用类型和原始类型之间的重要区别是它们的值在方法中的使用方式。让我们通过示例来看看区别。首先，我们创建`SomeClass`类：

```java
class SomeClass{
  private int count;
  public int getCount() {
    return count;
  }
  public void setCount(int count) {
      this.count = count;
    }
}
```

然后我们创建一个使用它的类：


```java
public class ReferenceTypeDemo {
  public static void main(String[] args) {
    float f = 1.0f;
    SomeClass someClass = new SomeClass();
    System.out.println("\nBefore demoMethod(): f = " + f + 
                             ", count = " + someClass.getCount());
    demoMethod(f, someClass);
    System.out.println("After demoMethod(): f = " + f 
                           + ", count = " + someClass.getCount());
  }
  private static void demoMethod(float f, SomeClass someClass){
    //... some code can be here
    f = 42.0f;
    someClass.setCount(42);
    someClass = new SomeClass();
    someClass.setCount(1001);
  }
}
```

首先让我们看看`demoMethod()`内部。我们为演示目的使其非常简单，但假设它做了更多的事情，然后为`f`变量（参数）分配一个新值，并在`SomeClass`类的对象上设置一个新的计数值。然后，此方法尝试用指向具有另一个计数值的新`SomeClass`对象的新值替换传入的引用。

在`main()`方法中，我们声明并初始化`f`和`someClass`变量，并打印它们，然后将它们作为参数传递给`demoMethod()`方法，并再次打印相同变量的值。让我们运行`main()`方法并查看结果，结果应该如下所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/3fe7f190-7bc0-4bc5-bf1b-90634245d199.png)

要理解区别，我们需要考虑这两个事实：

+   方法传递的值是通过副本传递的

+   引用类型的值是指向所指对象所在内存的引用

这就是为什么当传递原始值（或`String`，如我们已经解释的那样是不可变的）时，会创建实际值的副本，因此原始值不会受到影响。

同样，如果传入对象的引用被传入，那么方法中的代码只能访问其副本，因此无法更改原始引用。这就是为什么我们尝试更改原始引用值并使其引用另一个对象并没有成功的原因。

但是方法内部的代码可以访问原始对象并使用引用值的副本更改其计数值，因为该值仍指向原始对象所在的相同内存区域。这就是为什么方法内部的代码能够执行原始对象的任何方法，包括更改对象状态（实例字段的值）的方法。

当将对象状态更改为参数传递时，称为副作用，有时会在以下情况下使用：

+   方法必须返回多个值，但无法通过返回的结构来实现

+   程序员不够熟练

+   第三方库或框架利用副作用作为获取结果的主要机制

但是最佳实践和设计原则（在这种情况下是单一责任原则，我们将在第八章中讨论*面向对象设计（OOD）原则*）指导程序员尽量避免副作用，因为副作用经常导致代码不易阅读（对于人类来说）和难以识别和修复的微妙运行时效果。

必须区分副作用和称为委托模式的代码设计模式（[`en.wikipedia.org/wiki/Delegation_pattern`](https://en.wikipedia.org/wiki/Delegation_pattern)），当在传入的对象上调用的方法是无状态的。我们将在第八章中讨论设计模式，*面向对象设计（OOD）原则*。

类似地，当数组作为参数传入时，副作用是可能的。以下是演示它的代码：

```java
public class ReferenceTypeDemo {
  public static void main(String[] args) {
    int[] someArray = {1, 2, 3};
    System.out.println("\nBefore demoMethod(): someArray[0] = " 
                                               + someArray[0]);
    demoMethod(someArray);
    System.out.println("After demoMethod(): someArray[0] = " 
                                                + someArray[0]);
  }
  private static void demoMethod(int[] someArray){
    someArray[0] = 42;
    someArray = new int[3];
    someArray[0] = 43;
  }
}
```

前面代码的执行结果如下：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/4431c564-3f1d-4148-87b7-126c30401e9d.png)

您可以看到，尽管在方法内部，我们能够将新数组分配给传入的变量，但值`43`的分配仅影响新创建的数组，但对原始数组没有影响。然而，使用传入的引用值的副本更改数组组件是可能的，因为副本仍然指向相同的原始数组。

并且，为了结束关于引用类型作为方法参数和可能的副作用的讨论，我们想证明`String`类型参数-由于`String`值的不可变性-在作为参数传递时的行为类似于原始类型。这是演示代码：

```java
public class ReferenceTypeDemo {
  public static void main(String[] args) {
    String someString = "Some string";
    System.out.println("\nBefore demoMethod(): string = " 
                                              + someString);
    demoMethod(someString);
    System.out.println("After demoMethod(): string = " 
                                              + someString);
  }
  private static void demoMethod(String someString){
    someString = "Some other string";
  }
}
```

上述代码产生以下结果：

！[](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/c29f1c82-c6e0-4f44-8f20-d3e72a10bcdb.png)

方法内的代码无法更改原始参数值。这样做的原因不是-与原始类型的情况一样-在将其传递到方法之前复制了参数值。在这种情况下，副本仍指向相同的原始`String`对象。实际原因是更改`String`值不会更改该值，而是创建另一个具有更改结果的`String`对象。这就是我们在*String 类型和文字*部分中描述的`String`值不可变性机制。分配给传入的引用值的副本的新（更改的）`String`对象的引用，并且不会对仍然指向原始 String 对象的原始引用值产生影响。

有了这个，我们结束了关于 Java 引用类型和 String 的讨论。

# 练习-变量声明和初始化

以下哪些陈述是正确的：

1.  int x ='x';

1.  int x1 =“x”;

1.  char x2 =“x”;

1.  char x4 = 1;

1.  String x3 = 1;

1.  Month.MAY = 5;

1.  Month month = Month.APRIL;

# 答案

1, 4, 7

# 总结

本章为讨论更复杂的 Java 语言构造奠定了基础。 Java 元素的知识，例如标识符，变量，文字，关键字，分隔符，注释和类型-原始和引用-对于 Java 编程是必不可少的。如果不正确理解，您还有机会了解一些可能引起混淆的领域，例如 String 类型的不可变性和引用类型作为方法参数时可能的副作用。数组和`enum`类型也得到了详细解释，使读者能够使用这些强大的构造并提高其代码的质量。

在下一章中，读者将介绍 Java 编程的最常见术语和编码解决方案-**应用程序编程接口**（**API**），对象工厂，方法覆盖，隐藏和重载。然后，关于软件系统设计和聚合（vs 继承）的优势的讨论将使读者进入最佳设计实践的领域。 Java 数据结构的概述将结束本章，为读者提供实用的编程建议和推荐。


# 第六章：接口，类和对象构造

本章向读者解释了 Java 编程的最重要方面：应用程序编程接口（API），对象工厂，方法重写，隐藏和重载。接着是聚合（而不是继承）的设计优势的解释，开始讨论软件系统设计。本章最后概述了 Java 数据结构。

在本章中，我们将涵盖以下主题：

+   什么是 API？

+   接口和对象工厂作为 API

+   重写，隐藏和重载

+   `this`和`super`关键字

+   构造函数和构造函数重载

+   最终变量，最终方法和最终类

+   对象关联（聚合）

+   练习-将类实例化限制为单个共享实例

# API 是什么？

术语**应用程序编程接口**（API）是程序员用来实现所需功能的协议，程序和服务的规范。API 可以代表基于 Web 的系统，操作系统，数据库系统，计算机硬件或软件库。

除此之外，在日常生活中，术语 API 经常用于实现规范的系统。例如，您可能熟悉 Twitter APIs（[`developer.twitter.com/en/docs`](https://developer.twitter.com/en/docs)）或 Amazon APIs（[`developer.amazon.com/services-and-apis`](https://developer.amazon.com/services-and-apis)），或者您可能已经使用能够通过提供数据（测量结果）来响应请求的设备（传感器）。因此，当程序员说*我们可以使用 Amazon API*时，他们不仅指提供的程序描述，还指服务本身。

在 Java 中，我们还有一些关于*API 使用*的术语变体，我们希望在以下小节中进行识别和描述。

# Java API

Java API 包括两大类 API 和实现它们的库：

+   Java 核心包（[`www.oracle.com/technetwork/java/api-141528.html`](http://www.oracle.com/technetwork/java/api-141528.html)）随 Java 安装提供并包含在 JDK 中

+   其他可以单独下载的框架和库，例如 Apache Commons APIs（[`commons.apache.org`](https://commons.apache.org)），或者我们已经在 Maven 的`pom.xml`文件中包含为依赖项的三个库。其中绝大多数可以在 Maven 仓库（[`mvnrepository.com`](https://mvnrepository.com)）中找到，但也可以在其他地方找到各种新的和实验性的库和框架。

# 命令行 API

命令行 API 描述了命令格式及其可能的选项，可用于执行应用程序（工具）。我们在第一章中讨论使用`java`和`javac`工具（应用程序）时看到了这样的例子，*您的计算机上的 Java 虚拟机（JVM）*。我们甚至在第四章中构建了自己的应用程序，定义了其 API，并描述了其命令行 API，接受整数作为参数。

# 基于 HTTP 的 API

基于 Web 的应用程序通常使用各种协议（[`en.wikipedia.org/wiki/List_of_web_service_protocols`](https://en.wikipedia.org/wiki/List_of_web_service_protocols)）提供基于 HTTP 的 API，允许通过互联网访问应用程序功能。HTTP 代表超文本传输协议，是分布式信息系统的应用协议，是**万维网**（**WWW**）数据通信的基础。

最流行的两种 Web 服务协议是：

+   基于 XML 的**SOAP**（Simple Object Access Protocol）协议

+   基于 JSON 的 REST 或 RESTful（**REpresentational State Transfer**）风格的 HTTP 协议

两者都描述了如何访问功能（服务）并将其合并到应用程序中。我们在本书中不描述 Web 服务。

# 软件组件 API

软件组件可以是一个库，一个应用子系统，一个应用层，甚至是一个单独的类——可以通过调用其方法直接从 Java 代码中使用的东西。软件组件的 API 看起来像描述方法签名的接口，可以在实现接口的类的对象上调用这些方法。如果组件有公共静态方法（不需要对象，只能使用类调用），这些方法也必须包含在 API 描述中。但是，对于组件 API 的完整描述，正如我们在第二章中已经提到的那样，关于如何创建组件的对象的信息也应该是 API 描述的一部分。

在本书中，我们不会超越应用程序边界，并且只会在先前描述的软件组件 API 的意义上使用术语 API。而且，我们将按其名称称呼实现 API 的实体（API 描述的服务）：应用子系统，应用层，库，类，接口和方法。

这就是为什么我们开始了一个关于接口和对象工厂的 API 相关讨论，它们相互补充，并且与静态方法一起组成了软件组件 API 的完整描述。

# 接口和对象工厂作为 API

名词抽象意味着书籍、文章或正式演讲的内容摘要。形容词抽象意味着存在于思想中或作为一个想法，但没有具体的或实体的存在。动词抽象意味着从理论上或与其他事物分开考虑（某事）。

这就是为什么接口被称为抽象——因为它只捕捉方法签名，不描述如何实现结果。相同接口的各种实现——不同的类——可能行为完全不同，即使它们接收相同的参数并返回相同的结果。最后一句是一个有深意的陈述，因为我们还没有定义行为这个术语。现在让我们来做。

类或其对象的行为由其方法执行的操作和它们返回的结果定义。如果一个方法不返回任何东西（`void`），则称这样的方法仅用于其副作用。

这种观点意味着返回值的方法具有直接（而不是副作用）的效果。然而，它也可能具有副作用，例如向另一个应用程序发送消息，或者在数据库中存储数据。理想情况下，应该尝试在方法名称中捕捉副作用。如果这不容易，因为方法做了很多事情，这可能表明需要将这样的方法分解为几个更好聚焦的方法。

同一方法签名的两个实现可能具有不同的行为的说法只有在方法名称没有捕捉到所有副作用，或者实现的作者没有遵守方法名称的含义时才有意义。但即使不同实现的行为相同，代码本身、它使用的库以及其有效性可能是不同的。

为什么隐藏实现细节很重要，我们将在第八章中解释，*面向对象设计（OOD）原则*。现在，我们只是提到客户端与实现的隔离允许系统更灵活地采用相同实现的新版本或完全切换到另一个实现。

# 接口

我们在第二章中讨论了接口，现在我们只看一些例子。让我们创建一个新的包，`com.packt.javapath.ch06demo.api`。然后，我们可以右键单击`com.packt.javapath.ch06demo.api`，打开 New | Java Class，选择 Interface，输入`Calculator`，然后单击 OK 按钮。我们已经创建了一个接口，并且可以向其添加一个方法签名，`int multiplyByTwo(int i)`，结果如下：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/3bf0e6a7-cecc-4cfe-bc2b-3337a3a24d78.png)

这将是实现此接口的每个类的公共接口。在现实生活中，我们不会使用包名称`api`，而是使用`calculator`，因为它更具体和描述性。但是我们正在讨论术语“API”，这就是我们决定以这种方式命名包的原因。

让我们创建另一个包，`com.packt.javapath.ch06demo.api.impl`，其中将保存所有`Calculator`的实现和我们将添加到`com.packt.javapath.ch06demo.api`包中的其他接口。第一个实现是`CalulatorImpl`类。到目前为止，您应该已经知道如何在其中创建`com.packt.javapath.ch06demo.api.impl`包和`CalulatorImpl`类。结果应该如下所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/d6e713bb-a6b6-40d0-8fe0-7be774bf7f0d.png)

我们将实现放在了比`api`更深一级的包中，这表明这些细节不应该暴露给我们创建的 API 的用户。

此外，我们需要编写一个测试并使用它来确保我们的功能对用户来说是正确和方便的。同样，我们假设您现在知道如何做到这一点。结果应该如下所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/8199defb-2557-47f7-97e8-35febe1cb351.png)

然后，我们添加缺失的测试主体和注释，如下所示：

```java
@DisplayName("API Calculator tests")
public class CalculatorTest {
  @Test
  @DisplayName("Happy multiplyByTwo()")
  void multiplyByTwo(){
    CalculatorImpl calculator = new CalculatorImpl();
    int i = 2;
    int result = calculator.multiplyByTwo(i);
    assertEquals(4, result);
  }
}
```

这段代码不仅作为功能测试，还可以被视为 API 用户编写的客户端代码的示例。因此，测试帮助我们从客户端的角度看待我们的 API。通过观察这段代码，我们意识到我们无法完全隐藏实现细节。即使我们将创建对象的行更改为以下内容：

```java
Calculator calculator = new CalculatorImpl();

```

这意味着，如果我们更改`CalculatorImpl`构造函数的签名或切换到同一接口的另一个实现（称为`AnotherCalculatorImpl`），客户端代码也必须更改。为了避免这种情况，程序员使用称为对象工厂的类。

# Object factory

对象工厂的目的是隐藏对象创建的细节，以便客户端在实现更改时无需更改代码。让我们创建一个生产`Calculator`对象的工厂。我们将把它放在与`Calculator`接口的实现位于同一包`com.packt.javapath.ch06demo.api.impl`中：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/525f9e16-73db-40de-ae66-c526bd1ab207.png)

我们可以更改测试（客户端代码）以使用此工厂：

```java
@DisplayName("API Calculator tests")
public class CalculatorTest {
  @Test
  @DisplayName("Happy multiplyByTwo()")
  void multiplyByTwo(){
    Calculator calculator = CalculatorFactory.createInstance();
    int i = 2;
    int result = calculator.multiplyByTwo(i);
    assertEquals(4, result);
  }
}
```

通过这样做，我们已经实现了我们的目标：客户端代码不会对实现`Calculator`接口的类有任何概念。例如，我们可以更改工厂，以便它创建另一个类的对象：

```java
public static Calculator create(){
  return AnotherCalculatorImpl();
}
```

`AnotherCalculatorImpl`类可能如下所示：

```java
class AnotherCalculatorImpl  implements Calculator {
  public int multiplyByTwo(int i){
    System.out.println(AnotherCalculatorImpl.class.getName());
    return i + i;
  }
}
```

这个`multiplyByTwo()`方法是将两个值相加，而不是将输入参数乘以 2。

我们还可以使工厂读取配置文件，并根据配置文件的值实例化实现：

```java
public class CalculatorFactory {
  public static Calculator create(){
    String whichImpl = 
       Utils.getStringValueFromConfig("calculator.conf", "which.impl");
    if(whichImpl.equals("multiplies")){
      return new CalculatorImpl();
    } else if (whichImpl.equals("adds")){
      return new AnotherCalculatorImpl();
    } else {
      throw new RuntimeException("Houston, we have a problem. " +
        "Unknown key which.impl value " + whichImpl + " is in config.");
    } 
  }     
}
```

我们还没有讨论`if...else`结构或`RuntimeException`类（参见第十章，*控制流语句*）。我们很快会讨论`Utils.getStringValueFromConfig()`方法。但是，我们希望你理解这段代码的作用：

+   读取配置文件

+   根据`which.impl`键的值实例化类

+   如果没有与`which.impl`键的值对应的类，则通过抛出异常退出方法（因此通知客户端存在必须解决的问题）

这是配置文件`calculator.conf`可能的样子：

```java
{
  "which.impl": "multiplies"
}
```

这称为**JavaScript 对象表示**（**JSON**）格式，它基于由冒号（`:`）分隔的键值对。您可以在[`www.json.org/`](http://www.json.org/)上了解更多关于 JSON 的信息。

`calculator.conf`文件位于`resources`目录（`main`目录的子目录）中。默认情况下，Maven 将此目录的内容放在类路径上，因此应用程序可以找到它。

要告诉工厂使用另一个`Calculator`实现，我们只需要做以下事情：

+   更改文件`calculator.conf`中键`which.impl`的值

+   更改工厂的`create()`方法以根据这个新值实例化新的实现

重要的是要注意，当我们切换`Calculator`实现时，客户端代码（`CalculatorTest`类）不受影响。这是使用接口和对象工厂类隐藏实现细节对客户端代码的优势。

现在，让我们看看`Utils`类及其`getStringValueFromConfig()`方法的内部。

# 读取配置文件

通过查看`getStringValueFromConfig()`方法的真实实现，我们超前于你对 Java 和 Java 库的了解。因此，我们不希望你理解所有的细节，但我们希望这种暴露会让你了解事情是如何做的，我们的课程目标是什么。

# 使用 json-simple 库

`getStringValueFromConfig()`方法位于`Utils`类中，我们已经创建了这个类来从`.conf`文件中读取值。这个类有以下代码：

```java
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

public class Utils {
  private static JSONObject config = null;
  public static String getStringValueFromConfig(String configFileName, 
                                                            String key){
    if(config == null){
      ClassLoader classLoader = Utils.class.getClassLoader();
      File file =
           new File(classLoader.getResource(configFileName).getFile());
      try(FileReader fr = new FileReader(file)){
        JSONParser parser = new JSONParser();
        config = (JSONObject) parser.parse(fr);
      } catch (ParseException | IOException ex){
        ex.printStackTrace();
        return "Problem reading config file.";
      }
    }
    return config.get(key) == null ? "unknown" : (String)config.get(key);
  }
}
```

首先，请注意称为缓存的技术。我们首先检查`config`静态类字段的值。如果它不是`null`，我们就使用它。否则，我们使用相同的类加载器在类路径上找到`config`文件，该类加载器用于加载我们传递的已知类。我们解析配置文件，这意味着将其分解为键值对。结果是我们分配给`config`字段的`JSONObject`类的生成对象的引用（缓存它，以便下次可以使用）。

这是缓存技术，用于避免浪费时间和其他资源。这种解决方案的缺点是，对配置文件的任何更改都需要重新启动应用程序，以便重新读取文件。在我们的情况下，我们假设这是可以接受的。但在其他情况下，我们可以添加一个定时器，并在定义的时间段过后刷新缓存数据，或者做类似的事情。

为了读取配置文件，我们使用 Apache Commons 库中的`FileReader`类（[`commons.apache.org/proper/commons-io`](https://commons.apache.org/proper/commons-io)）。为了让 Maven 知道我们需要这个库，我们已经将以下依赖项添加到`pom.xml`文件中：

```java
<dependency>
  <groupId>commons-io</groupId>
  <artifactId>commons-io</artifactId>
  <version>2.5</version>
</dependency>

```

要处理 JSON 格式的数据，我们使用 JSON.simple 库（也是根据 Apache 许可发布的），并将以下依赖项添加到`pom.xml`中：

```java
<dependency>
  <groupId>com.googlecode.json-simple</groupId>
  <artifactId>json-simple</artifactId>
  <version>1.1</version>
</dependency>

```

`JSONObject`类以 JSON 格式存储键值对。如果传入的键在文件中不存在，`JSONObject`类的对象返回值为`null`。在这种情况下，我们的`getStringValueFromConfig()`方法返回一个`String`字面量 unknown。否则，它将返回值转换为`String`。我们可以这样做，因为我们知道该值可以赋给`String`类型的变量。

`<condition>? <option1> : <option2>`构造被称为三元运算符。当条件为真时，它返回`option1`，否则返回`option2`。我们将在第九章中更多地讨论它，*运算符、表达式和语句*。

# 使用 json-api 库

或者，我们可以使用另一个 JSON 处理 API 及其实现：

```java
<dependency>
  <groupId>javax.json</groupId>
  <artifactId>javax.json-api</artifactId>
  <version>1.1.2</version>
</dependency>
<dependency>
  <groupId>org.glassfish</groupId>
  <artifactId>javax.json</artifactId>
  <version>1.1.2</version>
</dependency>

```

然后`getStringValueFromConfig()`方法的代码看起来会有些不同：

```java
import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonReader;
public class Utils {
  private static JsonObject config = null;
  public static String getStringValueFromConfig(String FileName, 
                                                           String key){
    if(config == null){
      ClassLoader classLoader = Utils.class.getClassLoader();
      File file = new File(classLoader.getResource(fileName).getFile());
      try(FileInputStream fis = new FileInputStream(file)){
        JsonReader reader = Json.createReader(fis);
        config = reader.readObject();
      } catch (IOException ex){
        ex.printStackTrace();
        return "Problem reading config file.";
      }
    }
    return config.get(key) == null ? "unknown" : config.getString(key);
  }
}
```

这个第二个实现需要的代码稍微少一些，并且使用了更一致的驼峰命名风格（`JsonObject`与`JSONObject`）。但是，由于它们的性能并没有太大的不同，使用哪个库在很大程度上取决于个人偏好。

# 单元测试

让我们创建一个单元测试，证明该方法按预期工作。到目前为止，你应该能够在`test/java/com/packt/javapath/ch06demo`目录（或在 Windows 的`test\java\com\packt\javapath\ch06demo`目录）中创建一个`UtilsTest`类。测试应该如下所示:

```java
@DisplayName("Utils tests")
public class UtilsTest {
  @Test
  @DisplayName("Test reading value from config file by key")
  void getStringValueFromConfig(){
    //test body we will write here
  }
}
```

接下来，我们添加`test/resources/utilstest.conf`文件（对于 Windows 是`test\resources\utilstest.conf`）:

```java
{
  "unknown": "some value"
}
```

它将扮演`config`文件的角色。有了这个，测试代码看起来如下:

```java
@Test
@DisplayName("Test reading value from config file by key")
void getStringValueFromConfig(){
  String fileName = "utilstest.conf";
  String value = Utils.getStringValueFromConfig(fileName, "some value");
  assertEquals("some value", value);

  value = Utils.getStringValueFromConfig(fileName, "some value");
  assertEquals("unknown", value);
}
```

我们测试两种情况:

+   返回的值应该在第一种情况下等于`some value`

+   如果在配置文件中键不存在，则值应该返回为`unknown`

我们运行这个测试并观察成功。为了确保，我们还可以将`utilstest.conf`文件的设置更改为以下内容:

```java
{
  "unknown": "another value"
}
```

这应该导致测试在第一种情况下失败。

让我们重新审视一下 Calculator API。

# 计算器 API

根据前面的讨论，我们可以在`Calculator`接口中描述 Calculator API 如下:

```java
public interface Calculator {
  int multiplyByTwo(int i);
}
static Calculator createInstance(){
  return CalculatorFactory.create();
}
```

如果`Calculator`实现的构造函数需要参数，我们将把它们添加到接口的`create()`工厂方法和`createInstance()`静态方法中。

当`Calculator`接口只存在一个实现时，前面的 API 声明就足够了。但是当你给客户端提供两个或更多的实现选择时，就像我们之前描述的那样，API 还应该包括`calculator.conf`配置文件的描述。

`配置描述`将不得不列出`which.impl`键的所有可能值（在我们的例子中是`multiplies`和`adds`）。我们还需要解释实现之间的差异，以便使用我们的计算器的程序员能够做出知情的选择。

如果这听起来太多了，那么你可能需要退一步重新审视你的 API 设计，因为它可能没有很好地聚焦，试图涵盖太多东西。考虑将这样的 API 分解为几个更简单的 API。描述每个较小的 API 更容易编写和理解。

例如，这是如何在我们的情况下将配置描述添加到接口中的:

```java
public interface Calculator {
  int multiplyByTwo(int i);
  static Calculator createInstance(){
    return  CalculatorFactory.create();
  }
  String CONF_NAME = "calculator.conf";
  String CONF_WHICH_IMPL = "which.impl";
  enum WhichImpl{
    multiplies, //use multiplication operation
    adds        //use addition operation
  }
}
```

正如你所看到的，我们在常量中捕获了配置文件名，以及配置键名。我们还为键的所有可能值创建了一个`enum`。我们还添加了实现之间差异的解释作为注释。如果解释太长，注释可以提供对文档、网站名称或 URL 的引用，例如。

由于配置文件中存在两种实现和两种可能的值，我们需要运行我们的单元测试`CalculatorTest`两次——对于配置的每种可能的值——以确保两种实现都按预期工作。但我们不想改变交付软件组件本身的配置。

这是`test/resources`目录（对于 Windows 为`test\resources`）再次发挥作用的时候。让我们在其中创建一个`calculator.conf`文件，并将以下行添加到`CalculatorTest`测试中，这将打印出该文件中的当前设置：

```java
String whichImpl = 
   Utils.getStringValueFromConfig(Calculator.CONF_NAME, 
                                     Calculator.CONF_WHICH_IMPL);
System.out.println(Calculator.CONF_WHICH_IMPL + "=" + whichImpl);

```

`CalculatorTest`代码应如下所示：

```java
void multiplyByTwo() {
  WhichImpl whichImpl = 
      Utils.getWhichImplValueFromConfig(Calculator.CONF_NAME, 
                                        Calculator.CONF_WHICH_IMPL);
  System.out.println("\n" + Calculator.CONF_WHICH_IMPL + 
                                                   "=" + whichImpl);
  Calculator calculator = Calculator.createInstance();
  int i = 2;
  int result = calculator.multiplyByTwo(i);
  assertEquals(4, result);
}
```

我们还可以添加一行，打印出每个实现的类名：

```java
public class CalculatorImpl implements Calculator {
  public int multiplyByTwo(int i){
    System.out.println(CalculatorImpl.class.getClass().getName());
    return i * 2;
  }
}
public class AnotherCalculatorImpl implements Calculator {
  public int multiplyByTwo(int i){
    System.out.println(AnotherCalculatorImpl.class.getClass().getName());
    return i + i;
 }
}
```

如果我们将`test`目录中的`calculator.conf`文件中的`which.impl`值设置为`adds`，则会变成这样：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/a123ab51-0369-4fe3-ac54-a73a829b2d6a.png)

`CalculatorTest`测试的结果将是：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/4af08c61-2654-40bc-89c4-a10f08681e58.png)

输出告诉我们三件事：

+   `calculator.conf`中`which.impl`的值被设置为`adds`

+   使用了相应的`AnotherCalculatorImpl`实现

+   调用的实现按预期工作

类似地，我们可以针对`calculator.conf`文件设置为`multiplies`运行我们的单元测试。

结果看起来很好，但我们仍然可以改进代码，使其不那么容易出错，如果将来某人决定通过添加新的实现或类似的方式来增强功能。我们可以利用添加到`Calculator`接口的常量，并使`create()`工厂方法更不容易受人为错误影响：

```java
public static Calculator create(){
  String whichImpl = Utils.getStringValueFromConfig(Calculator.CONF_NAME, 
                                       Calculator.CONF_WHICH_IMPL);         
  if(whichImpl.equals(Calculator.WhichImpl.multiplies.name())){
    return new CalculatorImpl();
  } else if (whichImpl.equals(Calculator.WhichImpl.adds.name())){
    return new AnotherCalculatorImpl();
  } else {
    throw new RuntimeException("Houston, we have a problem. " +
                     "Unknown key " + Calculator.CONF_WHICH_IMPL +
                     " value " + whichImpl + " is in config.");
  }
}
```

为了确保测试完成了其工作，我们将测试目录中的`calculator.conf`文件中的值更改为`add`（而不是`adds`），然后再次运行测试。输出将如下所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/252fb2df-1745-4fa7-8b42-92fae0a4f19d.png)

如预期的那样，测试失败了。这使我们对代码的工作方式有了一定的信心，而不仅仅是显示成功。

然而，当代码被修改或扩展时，代码可以改进以变得更易读，更易测试，并且更不易受人为错误影响。利用`enum`功能的知识，我们可以编写一个方法，将`calculator.conf`文件中键`which.impl`的值转换为类`enum WhichImpl`的一个常量（实例）。为此，我们将此新方法添加到类`Utils`中：


```java
WhichImpl getWhichImplValueFromConfig(String configFileName, String key){
  String whichImpl = getStringValueFromConfig(configFileName, key);
  try{
    return Enum.valueOf(WhichImpl.class, whichImpl);
  } catch (IllegalArgumentException ex){
    throw new RuntimeException("Houston, we have a problem. " +
                     "Unknown key " + Calculator.CONF_WHICH_IMPL +
                     " value " + whichImpl + " is in config.");
  }
}
```

这段代码基于`getStringValueFromConfig()`方法的使用，我们已经测试过并知道它按预期工作。`try...catch`结构允许我们捕获和处理一些代码（在这种情况下是`Enum.valueOf()`方法）遇到无法解决的条件并抛出异常的情况（我们将在第十章中学到更多关于这个的知识，*控制流语句*）。人们必须阅读 Java API 文档，才能知道`Enum.valueOf()`方法可能会抛出异常。例如，这是关于`Enum.valueOf()`方法的文档中的一句引用：

"Throws: IllegalArgumentException - 如果指定的枚举类型没有具有指定名称的常量，或者指定的类对象不表示枚举类型"

阅读即将使用的任何第三方类的 API 文档是一个好主意。在我们的代码中，我们捕获它并以一致的方式用我们自己的措辞抛出一个新的异常。

正如你所期望的，我们还为`getWhichImplValueFromConfig()`方法编写了一个单元测试，并将其添加到`UtilsTest`中：

```java
@Test
@DisplayName("Test matching config value to enum WhichImpl")
void getWhichImpValueFromConfig(){
  String confifFileName = "utilstest.conf";
  for(int i = 1; i <= WhichImpl.values().length; i++){
    String key = String.valueOf(i);
    WhichImpl whichImpl = 
       Utils.getWhichImplValueFromConfig(confifFileName, key);
    System.out.println(key + "=" + whichImpl);
  }
  try {
    WhichImpl whichImpl = 
       Utils.getWhichImplValueFromConfig(confifFileName, "unknown");
    fail("Should not get here! whichImpl = " + whichImpl);
  } catch (RuntimeException ex){
    assertEquals("Houston, we have a problem. " +
                 "Unknown key which.impl value unknown is in config.", 
                 ex.getMessage());
  }
  try {
    WhichImpl whichImpl = 
       Utils.getWhichImplValueFromConfig(confifFileName, "some value");
    fail("Should not get here! whichImpl = " + whichImpl);
  } catch (RuntimeException ex){
    assertEquals("Houston, we have a problem. " +
                 "Unknown key which.impl value unknown is in config.", 
                 ex.getMessage());
  }
}
```

为了支持这个测试，我们还在`utilstest.conf`文件中添加了两个条目：

```java
{
  "1": "multiplies",
  "2": "adds",
  "unknown": "unknown"
}
```

这个测试涵盖了三种情况：

+   如果`enum WhichImpl`中的所有常量都存在于配置文件中，那么`getWhichImplValueFromConfig()`方法就可以正常工作——它会找到它们中的每一个，不会抛出异常

+   如果传递给`getWhichImplValueFromConfig()`方法的键不是来自`enum WhichImpl`，则该方法会抛出一个异常，其中包含消息`Houston, we have a problem. Unknown key which.impl value unknown is in config`

+   如果传递给`getWhichImplValueFromConfig()`方法的键在配置文件中不存在，则该方法会抛出一个异常，其中包含消息`Houston, we have a problem. Unknown key which.impl value unknown is in config`

当我们确信这个方法按预期工作时，我们可以重写`create()`工厂方法如下：

```java
public static Calculator create(){
  WhichImpl whichImpl = 
    Utils.getWhichImplValueFromConfig(Calculator.CONF_NAME, 
                                      Calculator.CONF_WHICH_IMPL);
  switch (whichImpl){
    case multiplies:
      return new CalculatorImpl();
    case adds:
      return new AnotherCalculatorImpl();
    default:
      throw new RuntimeException("Houston, we have another " + 
                "problem. We do not have implementation for the key " +
                Calculator.CONF_WHICH_IMPL + " value " + whichImpl);
  }
}
```

`switch()`结构非常简单：它将执行线程定向到与匹配相应值的 case 下的代码块（更多信息请参阅第十章，*控制流语句*）。

The benefit of creating and using the method `getWhichImplValueFromConfig()` is that the `create()` method became much cleaner and focused on one task only: creating the right object. We will talk about the *Single Responsibility Principle* in section *So many OOD principles and so little time* of Chapter 8, *Object-Oriented Design (OOD) Principles*.

We have captured the Calculator API in one place—the interface `Calculator` —and we have tested it and proved that it works as designed. But there is another possible API aspect—the last one—we have not covered, yet.

# Adding static methods to API

Each of the classes that implement the `Calculator` interface may have static methods in addition to the instance methods defined in the interface. If such static methods could be helpful to the API's users, we should be able to document them in the `Calculator` interface, too, and that is what we are going to do now.

Let's assume that each of the implementations of the `Calculator` interface has a static method, `addOneAndConvertToString()`:

```java
public class CalculatorImpl implements Calculator {
  public static String addOneAndConvertToString(double d){
    System.out.println(CalculatorImpl.class.getName());
    return Double.toString(d + 1);
  }
  //...
}
public class AnotherCalculatorImpl implements Calculator {
  public static String addOneAndConvertToString(double d){
    System.out.println(AnotherCalculatorImpl.class.getName());
    return String.format("%.2f", d + 1);
  }
  //...
}
```

Notice that the methods have the same signature but slightly different implementations. The method in `CalculatorImpl` returns the result as is, while the method in `AnotherCalculatorImpl` returns the formatted value with two decimal places (we will show the result shortly).

Usually, static methods are called via a dot-operator applied to a class:

```java
String s1 = CalculatorImpl.addOneAndConvertToString(42d);
String s2 = AnotherCalculatorImpl.addOneAndConvertToString(42d);
```

But, we would like to hide (encapsulate) from an API client the implementation details so that the client code continues to use only the interface `Calculator`. To accomplish that goal, we will use the class `CalculatorFactory` again and add to it the following method:

```java
public static String addOneAndConvertToString(double d){
  WhichImpl whichImpl = 
       Utils.getWhichImplValueFromConfig(Calculator.CONF_NAME, 
                                         Calculator.CONF_WHICH_IMPL);
  switch (whichImpl){
    case multiplies:
      return CalculatorImpl.addOneAndConvertToString(d);
    case adds:
      return AnotherCalculatorImpl.addOneAndConvertToString(d);
    default:
      throw new RuntimeException("Houston, we have another " +
                "problem. We do not have implementation for the key " +
                Calculator.CONF_WHICH_IMPL + " value " + whichImpl);
  }
}
```

As you may have noticed, it looks very similar to the factory method `create()`. We also used the same values of the `which.impl` property—`multiplies` and `adds`—as identification of the class. With that, we can add the following static method to the `Calculator` interface:

```java
static String addOneAndConvertToString(double d){
  return CalculatorFactory.addOneAndConvertToString(d);
}
```

As you can see, this way we were able to hide the names of the classes that implemented the interface `Calculator` and the static method `addOneAndConvertToString ()`, too.

To test this new addition, we have expanded code in `CalculatorTest` by adding these lines:

```java
double d = 2.12345678;
String mString = "3.12345678";
String aString = "3.12";
String s = Calculator.addOneAndConvertToString(d);
if(whichImpl.equals(Calculator.WhichImpl.multiplies)){
  assertEquals(mString, s);
} else {
  assertNotEquals(mString, s);
}
if(whichImpl.equals(Calculator.WhichImpl.adds)){
  assertEquals(aString, s);
} else {
  assertNotEquals(aString, s);
}
```

在测试中，我们期望`String`类型的一个值，在`WhichImpl.multiplies`的情况下是相同的值，而在`WhichImpl.adds`的情况下是不同格式的值（只有两位小数）。让我们在`calculator.conf`中使用以下设置运行`CalculatorTest`：

```java
{
  "which.impl": "adds"
}
```

结果是：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/d70771b8-dd6c-442b-a6cd-8ea6393c6e3d.png)

当我们将`calculator.conf`设置为值`multiplies`时，结果如下：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/bbaa099b-1060-4191-8a6e-87d12be01e1f.png)

有了这个，我们完成了对计算器 API 的讨论。

# API 已完成

我们的 API 的最终版本如下：

```java
public interface Calculator {
  int multiplyByTwo(int i);
  static Calculator createInstance(){
    return  CalculatorFactory.create();
  }
  static String addOneAndConvertToString(double d){
    return  CalculatorFactory.addOneAndConvertToString(d);
  }
  String CONF_NAME = "calculator.conf";  //file name
  String CONF_WHICH_IMPL = "which.impl"; //key in the .conf file
  enum WhichImpl{
    multiplies, //uses multiplication operation
                // and returns addOneAndConvertToString() 
                // result without formating
    adds    //uses addition operation 
            // and returns addOneAndConvertToString()
            // result with two decimals only
  }
}
```

这样，我们保持了单一的记录源——捕获所有 API 细节的接口。如果需要更多细节，注释可以引用一些外部 URL，其中包含描述每个`Calculator`实现的完整文档。并且，重复我们在本节开头已经说过的，方法名称应该描述方法产生的所有副作用。

实际上，程序员试图编写小巧、重点突出的方法，并在方法名称中捕获方法的所有内容，但他们很少在接口中添加更多的抽象签名。当他们谈论 API 时，他们通常只指的是抽象签名，这是 API 最重要的方面。但我们认为在一个地方记录所有其他 API 方面也是一个好主意。

# 重载、重写和隐藏

我们已经提到了方法重写，并在第二章中解释了它，*Java 语言基础*。方法重写是用子类（或实现接口的类中的默认方法）的方法替换父类中实现的方法，这些方法具有相同的签名（或在实现接口的类中，或在相应的子接口中）。方法重载是在同一个类或接口中创建几个具有相同名称和不同参数（因此，不同签名）的方法。在本节中，我们将更详细地讨论接口、类和类实例的重写和重载成员，并解释隐藏是什么。我们从一个接口开始。

# 接口方法重载

我们在第二章，*Java 语言基础*中已经说过，除了抽象方法，接口还可以有默认方法和静态成员——常量、方法和类。

如果接口中已经存在抽象、默认或静态方法`m()`，就不能添加另一个具有相同签名（方法名称和参数类型列表）的方法`m()`。因此，以下示例生成编译错误，因为每对方法具有相同的签名，而访问修饰符（`private`、`public`）、`static`或`default`关键字、返回值类型和实现不是签名的一部分：

```java
interface A {
  int m(String s);
  double m(String s);  
} 
interface B {
  int m(int s);
  static int m(int i) { return 42; }
}
interface C {
  int m(double i);
  private double m(double s) { return 42d; }
}
interface D {
  int m(String s);
  default int m(String s) { return 42; }
}
interface E {
  private int m(int s) { return 1; };
  default double m(int i) { return 42d; }
}
interface F {
  default int m(String s) { return 1; };
  static int m(String s) { return 42; }
}
interface G {
  private int m(double d) { return 1; };
  static int m(double s) { return 42; }
}
interface H {
  default int m(int i) { return 1; };
  default double m(int s) { return 42d; }
}

```

要创建不同的签名，要么更改方法名称，要么更改参数类型列表。具有相同方法名称和不同参数类型的两个或多个方法构成方法重载。以下是接口中合法的方法重载示例：

```java
interface A {
  int m(String s);
  int m(String s, double d);
  int m(double d, String s);
  String m(int i);
  private double m(double d) { return 42d; }
  private int m(int i, String s) { return 1; }
  default int m(String s, int i) { return 1; }
} 
interface B {
  static int m(String s, int i) { return 42; }
  static int m(String s) { return 42; }
}

```

重载也适用于继承的方法，这意味着以下非静态方法的重载与前面的示例没有区别：

```java
interface D {
  default int m(int i, String s) { return 1; }
  default int m(String s, int i) { return 1; }
}
interface C {
  default double m(double d) { return 42d; }
}
interface B extends C, D {
  int m(double d, String s);
  String m(int i);
}
interface A extends B {
  int m(String s);
  int m(String s, double d);
}

```

您可能已经注意到我们在上一个代码中将`private`方法更改为`default`。我们这样做是因为`private`访问修饰符会使方法对子接口不可访问，因此无法在子接口中重载。

至于静态方法，以下组合的静态和非静态方法虽然允许，但不构成重载：

```java
interface A {
  int m(String s);
  static int m(String s, double d) { return 1 }
} 
interface B {
  int m(String s, int i);
  static int m(String s) { return 42; }
}
interface D {
  default int m(String s, int s) { return 1; }
  static int m(String s, double s) { return 42; }
}
interface E {
  private int m() { return 1; }
  static int m(String s) { return 42; }
}
```

静态方法属于类（因此在应用程序中是唯一的），而非静态方法与实例相关（每个对象都会创建一个方法副本）。

出于同样的原因，不同接口的静态方法不会相互重载，即使这些接口存在父子关系：

```java
interface G {
  static int m(String s) { return 42; }
}

interface F extends G {
  static int m(String s, int i) { return 42; }
}

```

只有属于同一接口的静态方法才能相互重载，而非静态接口方法即使属于不同接口也可以重载，前提是它们具有父子关系。

# 接口方法重写

与重载相比，重写只发生在非静态方法，并且只有当它们具有完全相同的签名时才会发生。

另一个区别是，重写方法位于子接口中，而被重写的方法属于父接口。以下是方法重写的示例：

```java
interface D {
  default int m(String s) { // does not override anything
    return 1; 
  } 
}

interface C extends D {
  default int m(String d) { // overrides method of D
    return 42; 
  } 
}

```

直接实现接口`C`的类，如果没有实现方法`m()`，将从接口`C`获取该方法的实现，而不会从接口`D`获取该方法的实现。只有直接实现接口`D`的类，如果没有实现方法`m()`，将从接口`D`获取该方法的实现。

注意我们使用了直接这个词。通过说类`X`直接实现接口`C`，我们的意思是类`X`定义如下：`class X implements C`。如果接口`C`扩展 D，则类`X`也实现接口`D`，但不是直接实现。这是一个重要的区别，因为在这种情况下，接口`C`的方法可以覆盖具有相同签名的接口`D`的方法，从而使它们对类`X`不可访问。

在编写依赖于覆盖的代码时，一个好的做法是使用注解`@Override`来表达程序员的意图。然后，Java 编译器和使用它的 IDE 将检查覆盖是否发生，并在带有此注解的方法没有覆盖任何内容时生成错误。以下是一些例子：

```java
interface B {
  int m(String s);
}
interface A extends B {
  @Override             //no error 
  int m(String s);
}
interface D {
  default int m1(String s) { return 1; }
}
interface C extends D {
  @Override            //error
  default int m(String d) { return 42; }
}
```

错误将帮助您注意到父接口中的方法拼写不同（`m1()`与`m()`）。以下是另一个例子：

```java
interface D {
  static int m(String s) { return 1; }
}
interface C extends D {
  @Override                  //error
  default int m(String d) { return 42; }
}
```

这个例子会生成一个错误，因为实例方法不能覆盖静态方法，反之亦然。此外，静态方法不能覆盖父接口的静态方法，因为接口的每个静态方法都与接口本身相关联，而不是与类实例相关联：

```java
interface D {
  static int m(String s) { return 1; }
}
interface C extends D{
  @Override               //error
  static int m(String d) { return 42; }
}
```

但是子接口中的静态方法可以隐藏父接口中具有相同签名的静态方法。实际上，任何静态成员——字段、方法或类——都可以隐藏父接口的相应静态成员，无论是直接父接口还是间接父接口。我们将在下一节讨论隐藏。

# 接口静态成员隐藏

让我们看一下以下两个接口：

```java
interface B {
  String NAME = "B";
  static int m(String d) { return 1; }
  class Clazz{
    String m(){ return "B";}
  }
}

interface A extends B {
  String NAME = "A";
  static int m(String d) { return 42; }
  class Clazz{
    String m(){ return "A";}
  }
}
```

接口`B`是接口`A`的父接口（也称为超接口或基接口），接口的所有成员默认都是`public`。接口字段和类也默认都是`static`。因此，接口`A`和`B`的所有成员都是`public`和`static`。让我们运行以下代码：

```java
public static void main(String[] args) {
  System.out.println(B.NAME);
  System.out.println(B.m(""));
  System.out.println(new B.Clazz().m());
}
```

结果将如下所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/de04757c-fb2d-4658-a5be-bad01309bd8c.png)

正如您所看到的，效果看起来像是覆盖，但产生它的机制是隐藏。在类成员隐藏的情况下，差异更为显著，我们将在下一节讨论。

# 类成员隐藏

让我们看看这两个类：

```java
class ClassC {
  public static String field = "static field C";
  public static String m(String s){
    return "static method C";
  }
}

class ClassD extends ClassC {
  public static String field = "static field D";
  public static String m(String s){
    return "static method D";
  }
}
```

}

```java
System.out.println(ClassD.field);
System.out.println(ClassD.m(""));
System.out.println(new ClassD().field);
System.out.println(new ClassD().m(""));
ClassC object = new ClassD();
System.out.println(object.field);
System.out.println(object.m(""));
```java

System.out.println(ClassD.field);

System.out.println(ClassD.m(""));

System.out.println(new ClassD().field);

System.out.println(new ClassD().m(""));

ClassC 对象 = new ClassD();

System.out.println(object.field);

System.out.println(object.m(""));

```java
1 System.out.println(ClassD.field);       //static field D
2 System.out.println(ClassD.m(""));       //static method D
3 System.out.println(new ClassD().field); //static field D
4 System.out.println(new ClassD().m("")); //static method D
5 ClassC object = new ClassD();
6 System.out.println(object.field);       //static field C
7 System.out.println(object.m(""));       //static method C

```java

1 System.out.println(ClassD.field); //静态字段 D

2 System.out.println(ClassD.m("")); //静态方法 D

3 System.out.println(new ClassD().field); //静态字段 D

4 System.out.println(new ClassD().m("")); //静态方法 D

5 ClassC object = new ClassD();

6 System.out.println(object.field); //静态字段 C

7 System.out.println(object.m("")); //静态方法 C

```java
class ClassC {
  public static String field1 = "instance field C";
  public String m1(String s){
    return "instance method C";
  }
}
class ClassD extends ClassC {
  public String field1 = "instance field D";
  public String m1(String s){
    return "instance method D";
  }
}
```java

类 ClassC {

public static String field1 = "实例字段 C";

public String m1(String s){

返回"实例方法 C";

}

}

类 ClassD 扩展自 ClassC {

public String field1 = "实例字段 D";

public String m1(String s){

返回"实例方法 D";

}

}

```java
System.out.println(new ClassD().field1);
System.out.println(new ClassD().m1(""));
ClassC object1 = new ClassD();
System.out.println(object1.m1(""));
System.out.println(object1.field1);
System.out.println(((ClassD)object1).field1);

```java

System.out.println(new ClassD().field1);

System.out.println(new ClassD().m1(""));

ClassC object1 = new ClassD();

System.out.println(object1.m1(""));

System.out.println(object1.field1);

System.out.println(((ClassD)object1).field1);

```java
1 System.out.println(new ClassD().field1);     //instance field D
2 System.out.println(new ClassD().m1(""));     //instance method D
3 ClassC object1 = new ClassD();
4 System.out.println(object1.m1(""));          //instance method D
5 System.out.println(object1.field1);          //instance field C
6 System.out.println(((ClassD)object1).field1);//instance field D

```java

1 System.out.println(new ClassD().field1); //实例字段 D

2 System.out.println(new ClassD().m1("")); //实例方法 D

3 ClassC object1 = new ClassD();

4 System.out.println(object1.m1("")); //实例方法 D

5 System.out.println(object1.field1); //实例字段 C

6 System.out.println(((ClassD)object1).field1); //实例字段 D

```java
class ClassC {
  private String field1 = "instance field C";
  public String getField(){ return field1; }
  public void setField(String s){ field1 = s; }
  public String m1(String s){
    return "instance class C";
  }
}
class ClassD extends ClassC {
  private String field1 = "instance field D";
  public String getField(){ return field1; }
  public void setField(String s){ field1 = s; }
  public String m1(String s){
    return "instance class D";
  }
}
```java

类 ClassC {

私有字符串字段 1 = "实例字段 C";

public String getField(){ return field1; }

public void setField(String s){ field1 = s; }

public String m1(String s){

return "实例类 C";

}

}

class ClassD extends ClassC {

private String field1 = "实例字段 D";

public String getField(){ return field1; }

public void setField(String s){ field1 = s; }

public String m1(String s){

return "实例类 D";

}

}

```java
void m() {
  // some code
}
int m(String s){
  // some code
  return 1;
}
void m(int i){
  // some code
}
int m(String s, double d){
  // some code
  return 1;
}
int m(double d, String s){
  // some code
  return 1;
}
```java

void m() {

// 一些代码

}

int m(String s){

// 一些代码

return 1;

}

void m(int i){

// 一些代码

}

int m(String s, double d){

// 一些代码

return 1;

}

int m(double d, String s){

// 一些代码

return 1;

}

```java
public class SimpleMath {
    public int multiplyByTwo(int i){
       return i * 2;
    }
}
```java

public class SimpleMath {

public int multiplyByTwo(int i){

return i * 2;

}

}

```java
public class SimpleMath {
    public int multiplyByTwo(int i){
        return 2 * i;
    }
    public int multiplyByTwo(String s){
        int i = Integer.parseInt(s);
        return 2 * i;
    }
}
```java

public class SimpleMath {

public int multiplyByTwo(int i){

return 2 * i;

}

public int multiplyByTwo(String s){

int i = Integer.parseInt(s);

return 2 * i;

}

}

```java
public class SimpleMath {
    public int multiplyByTwo(int i){
       return 2 * i;
    }
    public int multiplyByTwo(String s){
       int i = Integer.parseInt(s);
       return multiplyByTwo(i);
    }
}
```java

public class SimpleMath {

public int multiplyByTwo(int i){

return 2 * i;

}

public int multiplyByTwo(String s){

int i = Integer.parseInt(s);

return multiplyByTwo(i);

}

}

```java
public class SimpleMath {
  private int i;
  private String s;
  public SimpleMath() {
  }
  public SimpleMath(int i) {
    this.i = i;
  }
  public SimpleMath(String s) {
    this.s = s;
  }
  // Other methods that use values of the fields i and s
  // go here
}
```java

public class SimpleMath {

private int i;

private String s;

public SimpleMath() {

}

public SimpleMath(int i) {

this.i = i;

}

public SimpleMath(String s) {

this.s = s;

}

// Other methods that use values of the fields i and s

// go here

}

```java
public SimpleMath(int i) {
  this.i = i;
}
```java

public SimpleMath(int i) {

this.i = i;

}

```java
public class Person {
  private String firstName;
  private String lastName;
  private LocalDate dob;
  public Person(String firstName, String lastName, LocalDate dob) {
    this.firstName = firstName;
    this.lastName = lastName;
    this.dob = dob;
  }
  public String getFirstName() { return firstName; }
  public String getLastName() { return lastName; }
  public LocalDate getDob() { return dob; }

  @Override
  public boolean equals(Object other){
    if (other == null) return false;
    if (this == other) return true;
    if (!(other instanceof Person)) return false;
    final Person that = (Person) other;
    return this.getFirstName().equals(that.getFirstName()) &&
           this.getLastName().equals(that.getLastName()) &&
           this.getDob().equals(that.getDob());
  }
}
```java

public class Person {

private String firstName;

private String lastName;

private LocalDate dob;

public Person(String firstName, String lastName, LocalDate dob) {

this.firstName = firstName;

this.lastName = lastName;

this.dob = dob;

}

public String getFirstName() { return firstName; }

public String getLastName() { return lastName; }

public LocalDate getDob() { return dob; }

@Override

public boolean equals(Object other){

if (other == null) return false;

if (this == other) return true;

if (!(other instanceof Person)) return false;

final Person that = (Person) other;

return this.getFirstName().equals(that.getFirstName()) &&

this.getLastName().equals(that.getLastName()) &&

this.getDob().equals(that.getDob());

}

}

```java
public class PersonTest {
  @Test
  void equals() {
    LocalDate dob = LocalDate.of(2001, 01, 20);
    LocalDate dob1 = LocalDate.of(2001, 01, 21);

    Person p = new Person("Joe", "Blow", dob);
    assertTrue(p.equals(p));
    assertTrue(p.equals(new Person("Joe", "Blow", dob)));

    assertFalse(p.equals(new Person("Joe1", "Blow", dob)));
    assertFalse(p.equals(new Person("Joe", "Blow1", dob)));
    assertFalse(p.equals(new Person("Joe", "Blow", dob1)));
    assertFalse(p.equals( new Person("Joe1", "Blow1", dob1)));
  }
}
```java

public class PersonTest {

@Test

void equals() {

LocalDate dob = LocalDate.of(2001, 01, 20);

LocalDate dob1 = LocalDate.of(2001, 01, 21);

Person p = new Person("Joe", "Blow", dob);

assertTrue(p.equals(p));

assertTrue(p.equals(new Person("Joe", "Blow", dob)));

assertFalse(p.equals(new Person("Joe1", "Blow", dob)));

assertFalse(p.equals(new Person("Joe", "Blow1", dob)));

assertFalse(p.equals(new Person("Joe", "Blow", dob1)));

assertFalse(p.equals( new Person("Joe1", "Blow1", dob1)));

}

}

```java
assertFalse(p.equals(null));
assertFalse(p.equals(new Person(null, "Blow", dob)));
assertFalse(p.equals(new Person("Joe", null, dob)));
assertFalse(p.equals(new Person(null, null, dob)));
assertFalse(p.equals(new Person(null, null, null)));

assertTrue(new Person(null, "Blow", dob)
   .equals(new Person(null, "Blow", dob)));
assertTrue(new Person("Joe", null, dob)
   .equals(new Person("Joe", null, dob)));
assertTrue(new Person("Joe", "Blow", null)
   .equals(new Person("Joe", "Blow", null)));
assertTrue(new Person(null, null, null)
   .equals(new Person(null, null, null)));

```java

assertFalse(p.equals(null));

assertFalse(p.equals(new Person(null, "Blow", dob)));

assertFalse(p.equals(new Person("Joe", null, dob)));

assertFalse(p.equals(new Person(null, null, dob)));

assertFalse(p.equals(new Person(null, null, null)));

assertTrue(new Person(null, "Blow", dob)

.equals(new Person(null, "Blow", dob)));

assertTrue(new Person("Joe", null, dob)

.equals(new Person("Joe", null, dob)));

assertTrue(new Person("Joe", "Blow", null)

.equals(new Person("Joe", "Blow", null)));

assertTrue(new Person(null, null, null)

.equals(new Person(null, null, null)));

```java
return this.getFirstName().equals(that.getFirstName()) &&
       this.getLastName().equals(that.getLastName()) &&
       this.getDob().equals(that.getDob());

```java

return this.getFirstName().equals(that.getFirstName()) &&

this.getLastName().equals(that.getLastName()) &&

this.getDob().equals(that.getDob());

```java
public Person(String firstName, String lastName, LocalDate dob) {
  this.firstName = firstName == null ? "" : firstName;
  this.lastName = lastName == null ? "" : lastName;
  this.dob = dob;
  if(dob == null){
    throw new RuntimeException("Date of birth is null");
  }
}
```java

public Person(String firstName, String lastName, LocalDate dob) {

this.firstName = firstName == null ? "" : firstName;

this.lastName = lastName == null ? "" : lastName;

this.dob = dob;

if(dob == null){

throw new RuntimeException("Date of birth is null");

}

}

```java
assertFalse(p.equals(null));
assertFalse(p.equals(new Person(null, "Blow", dob)));
assertFalse(p.equals(new Person("Joe", null, dob)));
assertFalse(p.equals(new Person(null, null, dob)));
try {
  new Person("Joe", "Blow", null);
} catch (RuntimeException ex){
  assertNotNull(ex.getMessage());
  //add the record ex.getMessage() to the log here
}

assertTrue(new Person(null, "Blow", dob)
   .equals(new Person(null, "Blow", dob)));
assertTrue(new Person("Joe", null, dob)
   .equals(new Person("Joe", null, dob)));
assertTrue(new Person(null, null, dob)
   .equals(new Person(null, null, dob)));
```java

assertFalse(p.equals(null));

assertFalse(p.equals(new Person(null, "Blow", dob)));

assertFalse(p.equals(new Person("Joe", null, dob)));

assertFalse(p.equals(new Person(null, null, dob)));

try {

new Person("Joe", "Blow", null);

} catch (RuntimeException ex){

assertNotNull(ex.getMessage());

//在这里将记录 ex.getMessage()添加到日志

}

assertTrue(new Person(null, "Blow", dob)

.equals(new Person(null, "Blow", dob)));

assertTrue(new Person("Joe", null, dob)

.equals(new Person("Joe", null, dob)));

assertTrue(new Person(null, null, dob)

.equals(new Person(null, null, dob)));

```java
public class Vehicle {
  private int weightPounds, horsePower;
  public Vehicle(int weightPounds, int horsePower) {
    this.weightPounds = weightPounds;
    this.horsePower = horsePower;
  }
  protected int getWeightPounds(){ return this.weightPounds; }
  protected double getSpeedMph(double timeSec, int weightPounds){
    double v = 
        2.0 * this.horsePower * 746 * timeSec * 32.174 / weightPounds;
    return Math.round(Math.sqrt(v) * 0.68);
  }
}
```java

public class Vehicle {

private int weightPounds, horsePower;

public Vehicle(int weightPounds, int horsePower) {

this.weightPounds = weightPounds;

this.horsePower = horsePower;

}

protected int getWeightPounds(){ return this.weightPounds; }

protected double getSpeedMph(double timeSec, int weightPounds){

double v =

2.0 * this.horsePower * 746 * timeSec * 32.174 / weightPounds;

返回 Math.round（Math.sqrt（v）* 0.68）;

}

}

```java
public class Truck extends Vehicle {
  private int payloadPounds;
  public Truck(int payloadPounds, int weightPounds, int horsePower) {
    super(weightPounds, horsePower);
    this.payloadPounds = payloadPounds;
  }
  public void setPayloadPounds(int payloadPounds) {
    this.payloadPounds = payloadPounds;
  }
  protected int getWeightPounds(){ 
    return this.payloadPounds + getWeightPounds(); 
  }
  public double getSpeedMph(double timeSec){
    return getSpeedMph(timeSec, getWeightPounds());
  }
}
```java

public class Truck extends Vehicle {

private int payloadPounds;

public Truck（int payloadPounds，int weightPounds，int horsePower）{

super（weightPounds，horsePower）;

this.payloadPounds = payloadPounds;

}

public void setPayloadPounds（int payloadPounds）{

this.payloadPounds = payloadPounds;

}

protected int getWeightPounds（）{

返回 this.payloadPounds + getWeightPounds（）;

}

public double getSpeedMph（double timeSec）{

返回以英里/小时为单位的速度（timeSec，getWeightPounds（））。

}

}

```java
public class Car extends Vehicle {
  private int passengersCount;
  public Car(int passengersCount, int weightPounds, int horsePower) {
    super(weightPounds , horsePower);
    this.passengersCount = passengersCount;
  }
  public void setPassengersCount(int passengersCount) {
    this.passengersCount = passengersCount;
  }

  protected int getWeightPounds(){ 
    return this.passengersCount * 200 + getWeightPounds(); }
  public double getSpeedMph(double timeSec){
    return getSpeedMph(timeSec, getWeightPounds());
  }
}
```java

public class Car extends Vehicle {

private int passengersCount;

public Car（int passengersCount，int weightPounds，int horsePower）{

super（weightPounds，horsePower）;

this.passengersCount = passengersCount;

}

public void setPassengersCount（int passengersCount）{

this.passengersCount = passengersCount;

}

protected int getWeightPounds（）{

返回 this.passengersCount * 200 + getWeightPounds（）;}

public double getSpeedMph（double timeSec）{

返回以英里/小时为单位的速度（timeSec，getWeightPounds（））;

}

}

```java
Truck truck = new Truck(500, 2000, 300);
System.out.println(truck.getSpeedMph(10));

```java

Truck truck = new Truck（500，2000，300）;

System.out.println（truck.getSpeedMph（10））;

```java
protected int getWeightPounds(){ 
  return this.payloadPounds + getWeightPounds(); 
}
```java

protected int getWeightPounds(){

return this.payloadPounds + getWeightPounds();

}

```java
protected int getWeightPounds(){ 
  return this.payloadPounds + super.getWeightPounds(); 
}
```java

protected int getWeightPounds(){

return this.payloadPounds + super.getWeightPounds();

}

```java
public double getSpeedMph(double timeSec){
  return getSpeedMph(timeSec, getWeightPounds());
}
```java

public double getSpeedMph(double timeSec){

return getSpeedMph(timeSec, getWeightPounds());

}

```java
public double getSpeedMph(double timeSec){
  return getSpeedMph(timeSec, this.getWeightPounds());
}
```java

public double getSpeedMph(double timeSec){

return getSpeedMph(timeSec, this.getWeightPounds());

}

```java
public ClassName(){
  super();
}
```java

public ClassName(){

super();

}

```java
public class Parent {
}
public class Child extends Parent{
}
```java

public class Parent {

}

public class Child extends Parent{

}

```java
new Child();
```java

new Child();

```java
public class Parent {
  public Parent(int i) {
  }
}
```java

public class Parent {

public Parent(int i) {

}

}

```java
public class Parent {
  public Parent() {
  }
  public Parent(int i) {
  }
}
```java

public class Parent {

public Parent() {

}

public Parent(int i) {

}

}

```java
public class Child extends Parent{
  public Child() {
    super(10);
  }
}
```java

public class Child extends Parent{

public Child() {

super(10);

}

}

```java
public class Child extends Parent{
  public Child(int i) {
    super(i);
  }
}
```java

子类继承父类

public Child(int i) {

super(i);

}

}

```java
public class GrandDad{
  private String name = "GrandDad";
  public GrandDad() {
    System.out.println(name);
  }
}
public class Parent extends GrandDad{
  private String name = "Parent";
  public Parent() {
    System.out.println(name);
  }
}
public class Child extends Parent{
  private String name = "Child";
  public Child() {
    System.out.println(name);
  }
}
```java

public class GrandDad{

private String name = "GrandDad";

public GrandDad() {

System.out.println(name);

}

}

public class Parent extends GrandDad{

private String name = "Parent";

public Parent() {

System.out.println(name);

}

}

public class Child extends Parent{

private String name = "Child";

public Child() {

System.out.println(name);

}

}

```java
GrandDad.class.getSimpleName(); //always returns "GrandDad"
```java

GrandDad.class.getSimpleName(); //总是返回"GrandDad"

```java
public class GrandDad{
  private static String NAME = GrandDad.class.getSimpleName();
  public GrandDad() {
    System.out.println(NAME);
  }
}
public class Parent extends GrandDad{
  private static String NAME = Parent.class.getSimpleName();
  public Parent() {
    System.out.println(NAME);
  }
}
public class Child extends Parent{
  private static String NAME = Child.class.getSimpleName();
  public Child() {
    System.out.println(NAME);
  }
}
```java

public class GrandDad{

private static String NAME = GrandDad.class.getSimpleName();

public GrandDad() {

System.out.println（NAME）;

}

}

public class Parent extends GrandDad{

私有静态字符串名称= Parent.class.getSimpleName（）;

public Parent（）{

System.out.println（NAME）;

}

}

public class Child extends Parent{

私有静态字符串名称= Child.class.getSimpleName（）;

public Child（）{

System.out.println（NAME）;

}

}

```java
public class GrandDad{
  private static String NAME = GrandDad.class.getSimpleName()
  public GrandDad() {
    System.out.println(NAME);
  }
  public GrandDad(String familyName) {
    System.out.println(familyName + ": " + NAME);
  }
}
public class Parent extends GrandDad{
  private static String NAME = Parent.class.getSimpleName()
  public Parent() {
    System.out.println(NAME);
  }
  public Parent(String familyName) {
    System.out.println(familyName + ": " + NAME);
  }
}
public class Child extends Parent{
  private static String NAME = Child.class.getSimpleName()
  public Child() {
    System.out.println(NAME);
  }
  public Child(String familyName) {
    System.out.println(familyName + ": " + NAME);
  }
}
```java

public class GrandDad{

私有静态字符串名称= GrandDad.class.getSimpleName（）

public GrandDad（）{

System.out.println（NAME）;

}

public GrandDad（String familyName）{

System.out.println（familyName +“：”+ NAME）;

}

}

public class Parent extends GrandDad{

私有静态字符串名称= Parent.class.getSimpleName（）

public Parent（）{

System.out.println（NAME）;

}

public Parent（String familyName）{

System.out.println（familyName +“：”+ NAME）;

}

}

public class Child extends Parent{

私有静态字符串名称= Child.class.getSimpleName（）

public Child（）{

System.out.println（NAME）;

}

public Child（String familyName）{

System.out.println（familyName +“：”+ NAME）;

}

}

```java
public GrandDad(String familyName) {
  System.out.println(familyName + ": " + NAME);
}
public Parent(String familyName) {
  super(familyName);
  System.out.println(familyName + ": " + NAME);
}
public Child(String familyName) {
  super(familyName);
  System.out.println(familyName + ": " + NAME);
}
```java

public GrandDad（String familyName）{

System.out.println（familyName +“：”+ NAME）;

}

public Parent（String familyName）{

super（familyName）;

System.out.println（familyName +“：”+ NAME）;

}

public Child（String familyName）{

super（familyName）;

System.out.println（familyName +“：”+ NAME）;

}

```java
public class Child extends Parent{
  private static String NAME = Child.class.getSimpleName()
  public Child() {
    this("The Defaults");
  }
  public Child(String familyName) {
    super(familyName);
    System.out.println(familyName + ": " + NAME);
  }
}
```java

public class Child extends Parent{

私有静态字符串名称= Child.class.getSimpleName（）

public Child（）{

this（“The Defaults”）;

}

public Child（String familyName）{

super（familyName）;

System.out.println（familyName +“：”+ NAME）;

}

}

```java
        class SomeClass{
          private String someValue = "Initial value";
          public void setSomeValue(String someValue) {
            this.someValue = someValue;
          }
          public String getSomeValue() {
            return someValue;
          }
        }
        public class FinalDemo {
          public static void main(String... args) {
            final SomeClass o = new SomeClass();
            System.out.println(o.getSomeValue());   //Initial value
            o.setSomeValue("Another value");
            System.out.println(o.getSomeValue());   //Another value
            o.setSomeValue("Yet another value");
            System.out.println(o.getSomeValue());   //Yet another value

            final String s1, s2;
            final int x, y;
            y = 2;
            int v = y + 2;
            x = v - 4;
            System.out.println("x = " + x);        //x = 0
            s1 = "1";
            s2 = s1 + " and 2";
            System.out.println(s2);                // 1 and 2 
            //o = new SomeClass();                 //error
            //s2 = "3";                            //error
            //x = 5;                               //error
            //y = 6;                               //error
          }
        }
```java

类 SomeClass {

私有字符串 someValue =“初始值”;

public void setSomeValue（String someValue）{

this.someValue = someValue;

}

public String getSomeValue（）{

返回 someValue;

}

}

公共类 FinalDemo {

public static void main（String ... args）{

最终 SomeClass o = new SomeClass（）;

System.out.println（o.getSomeValue（））; //初始值

o.setSomeValue（“另一个值”）;

System.out.println（o.getSomeValue（））; //另一个值

o.setSomeValue（“另一个值”）;

System.out.println（o.getSomeValue（））; //另一个值

最终字符串 s1，s2;

最终 int x，y;

y = 2;

int v = y + 2;

x = v-4;

System.out.println（“x =”+ x）; // x = 0

s1 =“1”;

s2 = s1 +“和 2”;

System.out.println（s2）; // 1 和 2

// o = new SomeClass（）; //错误

// s2 =“3”; //错误

// x = 5; //错误

// y = 6; //错误

}

}

```java
        public class FinalDemo {
          final SomeClass o = new SomeClass();
          final String s1 = "Initial value";
          final String s2;
          final String s3;
          final int i = 1;
          final int j;
          final int k;
          {
            j = 2;
            s2 = "new value";
          }
          public FinalDemo() {
            k = 3;
            s3 = "new value";
          }
          public void method(){
            //this.i = 4;         //error
            //this.j = 4;         //error
            //this.k = 4;         //error
            //this.s3 = "";       //error
            this.o.setSomeValue("New value");
          }
        }
```java

公共类 FinalDemo {

最终 SomeClass o = new SomeClass（）;

最终字符串 s1 =“初始值”;

最终 s2;

最终字符串 s3;

最终 int i = 1;

最终 int j; 

最终 k;

{

j = 2;

s2 =“新值”;

}

公共 FinalDemo（）{

k = 3;

s3 =“新值”;

}

public void method（）{

// this.i = 4; //错误

// this.j = 4; //错误

// this.k = 4; //错误

// this.s3 =“”; //错误

this.o.setSomeValue（“新值”）;

}

}

```java
        public class FinalDemo {
          final static SomeClass OBJ = new SomeClass();
          final static String S1 = "Initial value";
          final static String S2;
          final static int INT1 = 1;
          final static int INT2;
          static {
            INT2 = 2;
            S2 = "new value";
          }    
          void method2(){
            OBJ.setSomeValue("new value");
            //OBJ = new SomeClass();
            //S1 = "";
            //S2 = "";
            //INT1 = 0;
            //INT2 = 0;
          }
        }
```java

公共类 FinalDemo {

最终静态 SomeClass OBJ = new SomeClass（）;

最终静态字符串 S1 =“初始值”;

最终静态字符串 S2;

最终静态 int INT1 = 1;

最终静态 int INT2;

静态{

INT2 = 2;

S2 =“新值”;

}

void method2（）{

OBJ.setSomeValue（“新值”）;

// OBJ = new SomeClass（）;

// S1 =“”;

// S2 =“”;

// INT1 = 0;

// INT2 = 0;

}

}

```java
void someMethod(final int i, final String s, final SomeClass o){
    //... 
}
```java

void someMethod(final int i, final String s, final SomeClass o){

//...

}

```java
class FinalVariable{
    private int i;
    public FinalVariable() { this.i = 1; }
    public void setInt(int i){
        this.i = 100;
        i = i;
    }
    public int getInt(){
        return this.i;
    }
}
```java

class FinalVariable{

private int i;

public FinalVariable() { this.i = 1; }

public void setInt(int i){

this.i = 100;

i = i;

}

public int getInt(){

return this.i;

}

}

```java
FinalVariable finalVar = new FinalVariable();
System.out.println("Initial setting: finalVar.getInt()=" + 
                                                 finalVar.getInt());
finalVar.setInt(5);
System.out.println("After setting to 5: finalVar.getInt()=" + 
                                                 finalVar.getInt());
```java

FinalVariable finalVar = new FinalVariable();

System.out.println("初始设置：finalVar.getInt()=" +

finalVar.getInt());

finalVar.setInt(5);

System.out.println("设置为 5 后：finalVar.getInt()=" +

finalVar.getInt());

```java
public void setInt(final int i){
  this.i = 100;
  i = i;
}
```java

public void setInt(final int i){

this.i = 100;

i = i;

}

```java
public void setInt(final int i){
    this.i = 100;
    this.i = i;
}
```java

public void setInt(final int i){

this.i = 100;

this.i = i;

}

```java
public class SingletonClassExample {
  private static SingletonClassExample OBJECT = null;

  private SingletonClassExample(){}

  public final SingletonClassExample getInstance() {
    if(OBJECT == null){
      OBJECT = new SingletonClassExample();
    }
    return OBJECT;
  }

  //... other class functionality
}
```java

public class SingletonClassExample {

private static SingletonClassExample OBJECT = null;

private SingletonClassExample(){}

public final SingletonClassExample getInstance() {

if(OBJECT == null){

OBJECT = new SingletonClassExample();

}

return OBJECT;

}

//... 其他类功能

}

```

另一种解决方案可能是将类私有化到工厂类中，并将其存储在工厂字段中，类似于以前的代码。

但要注意，如果这样一个单一对象具有正在改变的状态，就必须确保可以同时修改状态并依赖于它，因为这个对象可能会被不同的方法同时使用。

# 总结

本章还对最常用的术语 API 进行了详细讨论，以及相关主题的对象工厂、重写、隐藏和重载。此外，还详细探讨了关键字`this`和`super`的使用，并在构造函数的解释过程中进行了演示。本章以关键字`final`及其在局部变量、字段、方法和类中的使用进行了概述。

在下一章中，我们将描述包和类成员的可访问性（也称为可见性），这将帮助我们扩展面向对象编程的一个关键概念，封装。这将为我们讨论面向对象设计原则奠定基础。
