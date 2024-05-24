# 面向初学者的 Java 编程（三）

> 原文：[`zh.annas-archive.org/md5/4A5A4EA9FEFE1871F4FCEB6D5DD89CD1`](https://zh.annas-archive.org/md5/4A5A4EA9FEFE1871F4FCEB6D5DD89CD1)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第八章：有用的 Java 类

一旦我们对 Java 的基础知识，包括 Java 语法和 Java 构建的基本面向对象概念，有了一定的信心，我们就可以看一下 Java 的 API 和类库，这些对我们来说是立即和轻松地可访问的，用于编写 Java 程序。我们要这样做是因为我们将使用这些类库来加快我们的编程速度，并利用那些编写了非常棒东西的程序员的工作。

此外，查看 Java 类库，或者任何编程语言的类库，也是了解编程语言设计用途以及该语言中最佳编码应该是什么样子的好方法。

因此，在本章中，我们将看一下`Calendar`类及其工作原理。我们将深入研究`String`类及其一些有趣的方法。接下来，我们将介绍如何检测异常，即程序中的异常情况，以及如何处理它们。我们将看一下`Object`类，它是 Java 中所有类的超类。最后，我们将简要介绍 Java 的原始类。

本章将涵盖以下主题：

+   Calendar 类

+   `String`类以及使用`String`对象和文字之间的区别

+   异常及如何处理它们

+   `Object`类

+   Java 的原始类

# Calendar 类

在本节中，我们将看一下 Java 的`Calendar`类。在编写 Java 代码时，我们通常使用`Calendar`类来指代特定的时间点。

`Calendar`类实际上是 Java API 的一个相对较新的添加。以前，我们使用一个叫做`Date`的类来执行类似的功能。如果你最终要处理旧的 Java 代码，或者编写涉及 SQL 或 MySQL 数据库的 Java 代码，你可能会偶尔使用 Java 的`Date`类。如果发生这种情况，不要惊慌；查阅 Java 文档，你会发现有一些非常棒的函数可以在`Calendar`和`Date`对象之间进行切换。

为了看到 Java 的`Calendar`类的强大之处，让我们跳入一个 Java 程序并实例化它。让我们创建一个新程序；首先，从`java.util`包中导入所有类，因为`Calendar`类就在那里。

接下来，我们声明一个新的`Calendar`对象；我将其称为`now`，因为我们的第一个目标是将这个`Calendar`对象的值设置为当前时刻。让我们将`now`的值设置为`Calendar`对象的默认值，并看看它给我们带来了什么。为了做到这一点，我想我们需要使用`new`关键字。虽然我们实际上还没有在文档中查找过，但这似乎是一个合理的起始或默认日期，用于`Calendar`实例。

最后，让我们设置我们的程序，以便打印出我们的`now`对象中包含的信息：

```java
package datesandtimes; 

import java.util.*; 

public class DatesAndTimes { 
    public static void main(String[] args) { 
        Calendar now = new Calendar(); 
        System.out.println(now); 
    } 

} 
```

也许令人惊讶的是，当我们尝试编译这个基本程序时，它实际上失败了：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/f158bddd-0d63-4a9d-a67e-61669fc54652.png)

我们的错误出现在`Calendar`上，我们已经实例化了`Calendar`类，根据控制台显示的错误。错误是`Calendar`是抽象的，不能被实例化。

如果你还记得，抽象类是那些纯粹设计为被子类化的类，我们永远不能单独声明抽象类的实例。那么如果我们永远不能实例化 Java 的`Calendar`类，那么它有什么好处呢？当然，这不是一个公平的问题，因为我们绝对可以创建`Calendar`对象；它们只是特定类型的`Calendar`对象。我们几乎总是会使用`GregorianCalendar`。

# Calendar 的子类

让我们退一步，假设也许是正确的，我们不知道`Calendar`有哪些选项可用。这是使用**IDE（集成开发环境）**，比如 NetBeans，真的很棒的时候之一。

通常，在这个时间点上，我们需要查看 Java 文档，以确定`Calendar`的子类有哪些可以实例化。但是因为我们的 IDE 知道我们已经导入的包的一些元数据，我们可以询问我们的 IDE 它认为可能是我们代码的一个可能解决方案。如果你在 NetBeans 中工作，你可以通过从工具|选项|代码完成中检查一些代码完成选项来经常获得这些类型的建议。

然而，为了防止代码完成一直弹出，我将在这个场合使用 NetBeans 的快捷方式。默认情况下，这个快捷键组合是*Ctrl* + space，这将在我们光标当前位置弹出一个代码完成弹出窗口，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/a53f7a67-2fd6-445d-888f-2b011fd7336c.png)

NetBeans 中的代码完成选项非常出色。NetBeans 给了我们三个可能的建议：抽象的`Calendar`类，`BuddhistCalendar`和`GregorianCalendar`。我们已经知道我们不想使用`Calendar`类，因为我们实际上不能实例化一个抽象类。`BuddhistCalendar`和`GregorianCalendar`看起来确实是`Calendar`的子类。

如果我们选择`GregorianCalendar`，我们会看到它是`Calendar`的一个子类。所以让我们试着创建一个全新的`GregorianCalendar`实例，使用默认的设置和值：

```java
package datesandtimes; 

import java.util.*; 

public class DatesAndTimes { 
    public static void main(String[] args) { 
        Calendar now = new GregorianCalendar(); 
        System.out.println(now); 
    } 

} 
```

如果我们运行这个 Java 程序，我们确实会得到一些输出：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/09bc6484-e8c0-49ca-9386-2560c3833071.png)

这个输出意味着两件事：

+   我们的语法是正确的，因为我们成功编译了

+   我们可以看到 Java 在一个全新的`Calendar`对象中放入了什么值

Java 的一个很棒的地方是它要求新对象实现`toString()`方法，这个方法被`println()`使用。这意味着大多数 Java 标准库对象在我们要求它们打印自己时，能够以某种人类可读的格式打印出来。

我们这里打印出的新的`Calendar`类并不容易阅读，但我们可以浏览一下，看到许多字段已经被赋值，我们还可以看到`Calendar`类实际上有哪些字段（比如`areFieldsSet`，`areAllFieldsSet`等）。

# 获取当前的日，月和年

让我们看看如何从`Calendar`类中获取一个信息。让我们看看它是否实际上被设置为今天的值。让我们将日，月和年分别打印在三行`println`上，以保持简单。要访问当前的日，月和年，我们需要从`now`的`Calendar`对象中获取这些字段。如果我们的`Calendar`对象表示特定的时间点，它应该有日，月和年的字段，对吧？如果我们打开自动完成选项，我们可以看到我们的`Calendar`对象公开给我们的所有字段和方法，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/c178d672-c27e-45e8-ae73-5e000845e338.png)

我们不会找到一个容易访问的日，月和年字段，这可能开始让我们对`Calendar`感到失望；然而，我们只是没有深入到足够的层次。

`Calendar`类公开了`get()`方法，允许我们获取描述特定`Calendar`实例或时间点的字段。这是一个以整数作为参数的函数。对于我们中的一些人来说，这一开始可能看起来有点混乱。为什么我们要提供一个整数给`get()`，告诉它我们正在寻找哪个`Calendar`字段？

这个整数实际上是一个枚举器，我们暂时将其视为`Calendar`类本身公开的静态字符串。如果我们在`get()`的参数中输入`Calendar`类名，就像我们想要获取一个静态成员变量，然后返回自动完成，我们会看到我们可以在这个实例中使用的选项列表，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/e9d6c526-d232-4e65-baad-fbb4557bf1f1.png)

其中一些选项并不太合理。我们必须记住，自动完成只是告诉我们`Calendar`公开的内容；它并不给我们解决方案，因为它不知道我们想要做什么。例如，我们不希望使用我们的`Calendar`实例`now`来获取其`May`的值；这没有任何意义。但是，我们可以使用我们的`Calendar`实例来获取当前月份（`MONTH`）。同样，我们真正想要的是当月的日期（`DAY_OF_MONTH`）和当前年份（`YEAR`）。让我们运行以下程序：

```java
package datesandtimes; 

import java.util.*; 

public class DatesAndTimes { 
    public static void main(String[] args) { 
        Calendar now = new GregorianCalendar(); 
        System.out.println(now.get(Calendar.MONTH)); 
        System.out.println(now.get(Calendar.DAY_OF_MONTH)); 
        System.out.println(now.get(Calendar.YEAR)); 
    } 

} 
```

如果我们运行上述程序，我们得到输出`9`，`12`，`2017`：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/951c8817-a2e8-4342-8922-8ff33f63cf5a.png)

我写这本书是在 2017 年 10 月 12 日，所以这实际上有点令人困惑，因为十月是一年中的第十个月。

幸运的是，对此有一个合理的解释。与一年中的日期和年份不同，它们可以存储为整数变量，大多数编程语言中的`Calendar`和类似`Calendar`的类的大多数实现（不仅仅是 Java）选择将月份存储为数组。这是因为除了数值之外，每个月还有一个相应的字符串：它的名称。

由于数组是从零开始的，如果你忘记了这一点，我们的月份看起来比它应该的要低一个月。我们的`println()`函数可能应该如下所示：

```java
System.out.println(now.get(Calendar.MONTH) + 1); 
```

我得到了以下输出。你得相信我；这是今天的日期：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/9e391090-bdab-4c54-b429-2ecf1ff3da33.png)

因此，`Calendar`有很多与之关联的方法。除了使用`get()`函数将`Calendar`设置为当前时间点并从中读取外，我们还可以使用`set()`函数将`Calendar`设置为时间点。我们可以使用`add()`函数添加或减去负值来指定时间点。我们可以使用`before()`和`after()`函数检查时间点是在其他时间点之前还是之后。

# 日历的工作原理

然而，如果像我一样，你想知道这个`Calendar`对象是如何运作的。它是将月份、日期和时间秒存储在单独的字段中，还是有一个包含所有这些信息的大数字？

如果我们花一些时间查看`Calendar`类实现中可用的方法，我们会发现这两个方法：`setTimeInMillis()`及其姐妹方法`getTimeInMillis()`如下截图所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/594e44de-9eec-4c93-b94f-063721fc8b8a.png)

这些方法被特别设置是一个很好的机会，让我们看看`Calendar`类的真正思维方式。

让我们通过调用`getTimeInMillis()`函数并打印其输出来开始我们的探索：

```java
System.out.println(now.getTimeInMillis()); 
```

我们得到了一个非常大的整数，这很可能是自某个特定时间以来的毫秒数：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/8af89898-4b62-4305-b86f-5f5ddce7edbf.png)

如果我们进行数学计算，我们会发现这个时间点实际上不是公元元年；相反，它的时间要比那更接近。`Calendar`类称这个时间点为**纪元**，这是我们开始计算的时间点，当我们在 Java 中存储时间时，我们计算了多少毫秒自纪元以来。

我们可以使用计算器通过一个相当费力的过程来准确计算这个时间点，或者我们可以在我们的本地 Java 环境中以更少的痛苦来做。让我们简单地将`now`的值更改为`0`时的时间点，最初设置为默认或当前时间点。我们将使用`setTimeInMillis()`并提供`0`作为参数：

```java
package datesandtimes; 

import java.util.*; 

public class DatesAndTimes { 
    public static void main(String[] args) { 
        Calendar now = new GregorianCalendar(); 

 now.setTimeInMillis(0); 

        System.out.println(now.getTimeInMillis()); 
        System.out.println(now.get(Calendar.MONTH) + 1); 
        System.out.println(now.get(Calendar.DAY_OF_MONTH)); 
        System.out.println(now.get(Calendar.YEAR)); 
    } 

} 
```

当我们再次运行程序时，我们得到相同的输出字段：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/6e43915a-b424-4e21-ac8f-4c085a6f509f.png)

我们输出的第一个数字是我们确认毫秒已设置为`0`。现在我们的`Calendar`时间是 1970 年 1 月 1 日。因此，一旦我们开始向我们的对象添加天数，我们将从 1970 年 1 月 2 日开始计算。这个时间点被 Java `Calendar`称为时代。

为什么这对我们来说是一个非常有趣的事情？这意味着我们可以将我们的`Calendar`类转换为这些毫秒值，然后将它们作为整数值相加、相减，我想还可以将它们作为整数值相乘和相除。这使我们能够在数学的本机格式上对它们进行各种操作。

最后，我想向您展示另一件事，因为这是一个语法上的细节，您可能不熟悉，也可能不会在第一时间认出。如果您回忆一下本节开头，我们说`Calendar`是一个抽象类；我们只能实例化特定类型的`Calendar`类。然而，通常情况下，我们不会指定我们要找的确切类型的日历；我们会要求`Calendar`类来决定这一点。

正如我们在枚举中看到的，除了具有对象级方法之外，`Calendar`类还提供了一些静态方法，我们可以通过引用`Calendar`类型名称来使用。其中一个方法是`Calendar.getInstance()`，它将为我们创建 Java 可以找到的最佳匹配`Calendar`类：

```java
Calendar now = Calendar.getInstance(); 
```

在这种情况下，将是我们已经创建的相同的`GregorianCalendar`类。

# 字符串功能

在 Java 中处理字符串可能会有点令人困惑，因为它们确实是一个特殊情况。字符串与之相关联的是字符串字面值的概念，即双引号之间的字符序列。我们可以将它直接放入我们的 Java 程序中，Java 会理解它，就像它理解整数或单个字符一样。

与整数、字符和浮点数不同，Java 没有与这个字符串字面值相关联的原始关键字。如果我们想要的话，我们可能会得到的最接近的是字符数组；然而，通常情况下，Java 喜欢我们将字符串字面值与`String`类相关联。要更好地理解`String`类，请查看以下程序：

```java
package strings; 

public class Strings { 

    public static void main(String[] args) { 
        String s1 = new String
         ("Strings are arrays of characters"); 
        String s2 = new String
         ("Strings are arrays of characters"); 

        System.out.println("string1: " + s1); 
        System.out.println("string2: " + s2); 
        System.out.println(s1 == s2); 

    } 
} 
```

Java 中的`String`类是特殊的。在某些方面，它就像任何其他类一样。它有方法，正如我们在代码行中看到的，我们定义了变量`s1`和`s2`，它有一个构造函数。但是，我们可以对`String`类使用通常仅保留给字面值和基本类型的运算符。例如，在前面的程序中，我们将`s1`添加到字符串字面值`string 1:`中以获得有意义的结果。在处理 Java 对象时，这通常不是一个选项。

# 字符串字面值与字符串对象

Java 决定将`String`类的对象作为字符串字面值或真正的对象可以互换使用，这真的很强大。它给了我们比我们原本拥有的更多操作文本的选项，但它也有一些权衡。在处理`String`对象时，非常重要的是我们理解我们是在处理它的字符串值还是对象本身。这是因为我们可能会得到截然不同的行为。我们看到的前面的程序旨在说明其中一个实例。

这是一个非常简单的程序。让我们逐步进行并尝试预测其输出。我们首先声明并实例化两个`String`对象：`s1`和`s2`。我们使用`String`构造函数（我们很快会谈到为什么这很重要），并简单地将相同的字符串字面值传递给这些新对象中的每一个。然后，我们要求我们的程序打印出这些值，以便我们可以进行视觉比较。但是，我们还要求我们的程序执行这个有趣的任务：使用双等号比较运算符` s1`和`s2`进行比较。在运行此程序之前，花一秒钟时间问自己，“你认为这个比较的结果会是什么？”。

当我运行这个程序时，我发现 Java 不相信`s1`和`s2`的比较结果是`true`。我得到的结果是`false`：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/11c57936-eaa1-47bd-975b-4fb5ae8f3d01.png)

根据我们当时对`s1`和`s2`的想法，输出要么是合理的，要么是令人困惑的。如果我们认为`s1`和`s2`是由比较运算符比较的字符串文字，那么我们会感到非常困惑。我们会想知道为什么我们没有得到`true`的结果，因为分配给`s1`和`s2`的字符串文字是相同的。

然而，如果我们把`s1`和`s2`看作它们实际上是的对象，`false`的结果就更有意义了，因为我们询问 Java 的是，“这两个对象是相同的吗？”显然不是，因为它们都是创建两个不同新对象的结果。

这就是为什么我们喜欢在 Java 中尽可能使用`equals()`方法。几乎每个对象都实现了`equals()`方法，而且应该为每个对象编写`equals()`方法，以便逻辑上比较这些对象的值。

如果我们使用`equals()`方法比较我们的字符串，我们也比较它们包含的字符串文字值：

```java
System.out.println(s1.equals(s2)); 
```

现在，如果我们执行我们的程序，我们得到的结果是`true`，而不是当我们试图看它们是否实际上是存储在内存的相同位置的相同对象时得到的`false`：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/786b8fe7-9ac7-4202-a59d-a06e6ce02ea9.png)

# 字符串函数

这个`String`实现给了我们什么能力？嗯，我们知道我们可以添加或连接字符串，因为我们可以将它们作为文字进行操作。除了文字操作，我们还可以利用`String`类本身提供的所有功能。我们可以查看 Java 文档，了解可用的功能，或者我们可以始终使用 NetBeans 的代码完成功能进行检查。我应该在这里指出，我们甚至可以在字符串文字上使用`String`类的功能，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/877c76fc-5a48-413e-8982-dab2908cd52e.png)

# replace()函数

你将在方法列表中看到的大多数方法都是相当不言自明的（`toLowerCase()`，`toUpperCase()`等）。但为了确保我们都明白，让我们使用其中一个。让我们使用`replace()`。`replace()`函数接受两个参数，这些参数可以是单个字符，也可以是字符串符合条件的字符序列。该方法简单地用第二个字符串或字符替换第一个字符串或字符的所有实例。让我们看下面的`replace()`示例：

```java
package strings; 

public class Strings { 

    public static void main(String[] args) { 
        String s1 = new String
        ("Strings are arrays of  characters"); 
        String s2 = new String
        ("Strings are arrays of characters"); 

        System.out.println
        ("string1: " + s1.replace("characters", "char")); 
        System.out.println("string2: " + s2); 
        System.out.println(s1.equals(s2)); 
    } 
} 
```

当我们运行我们的程序时，我们看到我们修改了它的输出：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/b644940e-7847-4b30-bb78-e2083f63036d.png)

大多数这些方法只是修改返回的值。我们可以看到我们的程序仍然发现在代码的最后一行`s1`等于`s2`，这表明我们对`replace()`方法的调用没有修改`s1`的值。`replace()`方法只是返回修改后的值供我们的`println()`函数使用。

# format()函数

也许，`String`类中最有趣的方法之一实际上是它的静态方法之一：`String.format()`。为了向您展示`String.format()`的强大功能，我想为我们的项目创建一个全新的功能类。因此，在屏幕左侧显示的文件系统中右键单击项目名称，在新建类中输入`CustomPrinter.java`：

```java
package strings; 

public class Strings { 

    public static void main(String[] args) { 
        CustomPrinter printer = new CustomPrinter("> > %s < <"); 

        String s1 = new String
        ("Strings are arrays of characters"); 
        String s2 = new String
        ("Strings are arrays of characters"); 

        printer.println
        ("string1: " + s1.replace("characters", "char")); 
        printer.println("string2: " + s2); 
    } 
} 
```

为了让你看到我们在设置`CustomPrinter`类时在做什么，让我们看一下我们将在`main()`方法中使用的预写代码。`CustomPrinter`类的想法是它将有一个以字符串作为输入的构造函数。这个输入字符串将格式化或包装我们使用`CustomPrinter`实例打印到控制台的任何字符串。我们将在`CustomPrinter`中实现`System.out.println()`，所以当我们想要利用它来格式化我们的文本时，我们可以直接调用`printer.println()`。

在 Java 中格式化字符串时，我们使用一些特殊的语法。在我们的格式字符串中，我们可以用百分号（就像我们在代码中使用的`%s`）来预先标识字符`f`或`d`或`s`。在`String.format()`函数方面，Java 将这些理解为我们的格式字符串中要插入其他信息的区域。

我们在代码中使用的格式字符串将用尖括号包装我们创建的任何字符串输出。这比简单地将字符串附加和前置更复杂，我们当然可以创建一个实现，允许我们向我们的格式化字符串添加多个部分。

接下来让我们编辑`CustomPrinter.java`文件。我们知道我们需要一个`CustomPrinter`构造函数，它接受一个格式字符串作为输入。然后，我们可能需要存储这个`format`字符串。所以让我们的构造函数接受提供的格式字符串，并将其存储以备后用在`formatString`变量中：

```java
package strings; 

public class CustomPrinter { 
    private String formatString; 

    public CustomPrinter(String format) 
    { 
        formatString = format; 
    } 
} 
```

我们还声明了一个`println()`函数，据推测它将是一个`void`函数；它只会利用`system.out.println()`将某些东西打印到屏幕上。那个*某些东西*会有点复杂。我们需要拿到我们给定的格式字符串，并用`println()`函数提供的输入替换`%s`。

我们使用了强大的`String.format()`静态函数，它接受两个参数：一个格式字符串和要格式化的数据。如果我们的格式字符串有多个要格式化的字符串，我们可以在`String.format()`中提供多个字段。这是一个可以接受任意数量输入的函数。但是，为了保持一切简单和顺利，我们只会假设我们的格式字符串只有一个输入实例。

一旦我们成功使用`String.format()`函数格式化了这个字符串，我们就会简单地将它打印到屏幕上，就像我们之前做的那样：

```java
package strings; 

public class CustomPrinter { 
    private String formatString; 

    public CustomPrinter(String format) 
    { 
        formatString = format; 
    } 

    public void println(String input) 
    { 
        String formatted = String.format(formatString, input); 
        System.out.println(formatted); 
    } 
} 
```

当我们运行这个程序（我们需要运行我们有`main()`方法的类），我们会看到我们所有的输出都被正确地包裹在尖括号中：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/824bfc07-9fa2-4ba3-b869-26bd7e5abf07.png)

当然，像这样扩展自定义打印机，以接受更多的各种输入，并且比我们创建的快速东西更加动态，是任何东西的基础，比如日志系统，或者终端系统，你将能够看到相同的信息片段包裹在消息周围。例如，我们可以使用这样的自定义打印机，在向用户发送任何消息后放置日期和时间。然而，细节需要被正确格式化，这样它们不仅仅是被添加在末尾，而是在它们之间有适当的间距等。

我希望你已经学到了一些关于字符串的知识。Java 处理它们的方式真的很强大，但和大多数强大的编程工具一样，你需要在基本水平上理解它们，才能确保它们不会回来咬你。

# 异常

有时，我们的代码可能会失败。这可能是我们犯了编程错误，也可能是最终用户以我们没有预料到的方式使用我们的系统。有时，甚至可能是硬件故障；很多错误实际上不能真正归因于任何一个单一的来源，但它们会发生。我们的程序处理错误情况的方式通常和它处理理想使用情况的方式一样重要，甚至更重要。

在这一部分，我们将看一下 Java 异常。使用 Java 异常，我们可以检测、捕获，并在某些情况下从我们的程序中发生的错误中恢复。当我们处理异常时，有一件非常重要的事情要记住。异常之所以被称为异常，是因为它们存在于处理特殊情况，即我们在最初编写代码时无法处理或无法预料到的情况。

异常修改了我们程序的控制流，但我们绝不应该将它们用于除了捕获和处理或传递异常之外的任何其他用途。如果我们试图使用它们来实现逻辑，我们将制作一个对我们来说很快就会变得非常令人困惑，并且对于任何其他试图理解它的程序员来说立即变得非常令人困惑的程序。

为了帮助我们探索 Java 异常，我已经为我们设置了一个基本程序来玩耍；这是一个可能失败的东西。它是一个永恒的循环，做了两件真正的事情。首先，它使用`Scanner`的`nextFloat()`函数从用户那里获取输入，然后将该输入打印回用户：

```java
package exceptions; 

import java.util.*; 

public class Exceptions { 
    public static void main(String[] args) { 
        Scanner reader = new Scanner(System.in); 

        while(true) { 
            System.out.print("Input a number: "); 
            float input = reader.nextFloat(); 
            System.out.println("You input the number: " + input); 
            System.out.println("\r\n"); 
        } 
    } 
} 
```

如果我们将浮点值准确地分配为该程序的输入，那么该程序理论上将永远运行，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/b1fb966b-d867-438c-8a1d-211c5d62e9ba.png)

然而，如果我们犯了一个错误，并给这个程序一个字符串作为输入，`nextFloat()`函数将不知道该怎么处理它，就会发生异常：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/c39c4dd4-5866-4c87-bc24-27f820fca166.png)

当这种情况发生时，我们在控制台中会看到红色的文本。这些红色文本实际上是发送到`System.err`流中的。

# 分析控制台异常消息

让我们浏览输出文本并理解它的含义。它有两个重要的部分。输出文本的第一部分，即没有缩进的部分，是这个异常的标识符。它让我们知道异常已经被抛出并且发生在哪里。然后它告诉我们发生了什么类型的异常。您会注意到这个异常在`java.util`路径中被发现（输出的这部分看起来非常类似于我们是否将某些东西导入到我们的代码中或直接将其路径到外部库）。这是因为这个异常实际上是一个 Java 对象，我们的输出文本让我们确切地知道它是什么类型的对象。

这个异常测试的第二部分（缩进的部分）是我们称之为堆栈跟踪。基本上它是我们的程序中 Java 跳过的部分。堆栈跟踪的最底部是异常最初抛出的位置；在这种情况下，它是`Scanner.java`，位于第`909`行。

那不是我们的代码；那是为`Scanner.java`编写的代码，可能是`nextFloat()`方法所在的地方或`nextFloat()`方法调用的代码。

堆栈跟踪是代码的层次，所以一旦发生`InputMismatchException`，Java 就开始跳过这些代码层次或括号区域，直到最终达到代码所在的顶层，这在我们的情况下是`Exceptions.java`。这是我们创建的文件，它在堆栈跟踪的顶部。我们的`Exception.java`代码文件的第 11 行是 Java 能够处理或抛出这个异常的最后位置。

一旦达到第 11 行并且异常仍在向上传播，就没有其他处理了，因为它已经达到了我们程序的顶部。因此，异常最终通过打印到我们的`System.err`流并且我们的程序以结果`1`终止，这是一个失败的情况。

这对于调试目的来说非常好；我们知道我们必须去哪里找出程序出了什么问题，即`Exceptions.java`的第 11 行。但是，如果我们正在创建一个我们希望出于某种合理目的发布的程序，我们通常不希望我们的程序在发生次要错误时崩溃，特别是像这样的输入错误，这是用户偶尔会犯的错误。因此，让我们探讨一下如何处理异常。

# 处理异常

当 Java 被告知抛出异常时，它会停止执行当前的代码块，并开始跳级，直到异常被处理。这就是我们从`Scanner.java`类的第 909 行深处跳转到`Exceptions.java`的第 11 行的方式，这是我们的代码中发生异常的地方。如果我们的代码被另一个代码块执行，因为我们没有处理这个异常，所以不会打印到`System.err`，我们只会将异常抛到另一个级别。因此，他们会在堆栈跟踪中看到`Exception.java`的第 11 行。

然而，有时不断抛出异常是没有意义的。有时，我们希望处理异常情况，因为我们知道该如何处理它，或者因为，就像我们现在处理的情况一样，有比提供堆栈跟踪和异常名称更好的方式来告知用户出了什么问题。

此外，如果我们在这里处理异常，那么我们没有理由不能像什么都没有发生一样恢复我们的`while`循环。这个`while`循环的一个失败案例并不一定是终止我们的程序的理由。如果我们要处理异常情况，我们将使用`try...catch`代码块。

# try 和 catch 块

在我们认为可能会抛出异常并且我们想处理异常的任何代码块中，我们将把该行代码包装在`try`块中。在大多数情况下，这不会影响代码的执行方式，除非在`try`块内发生异常。如果在`try`块内抛出异常，代码不会将异常传播到下一个级别，而是立即执行以下`catch`块中的代码。

请注意，`catch`块在执行之前需要更多的信息；它们需要知道它们要捕获的确切内容。我们可以通过简单地捕获`Exception`类的任何内容来捕获所有异常，但这可能不是一个公平的做法。关于异常处理有很多不同的思路，但一般来说，人们会同意你应该只捕获和处理你在某种程度上预期可能发生的异常。

在我们看到的例子中，我们知道如果我们通过用户输入提供无效信息，就会抛出`InputMismatchException`。因为当这种异常发生时，我们将打印一条消息，明确告诉用户`请输入一个浮点数。`，我们当然不希望捕获任何不是`InputMismatchException`的异常。因此，我们使用以下代码来捕获`InputMismatchException`：

```java
package exceptions; 

import java.util.*; 

public class Exceptions { 
    public static void main(String[] args) { 
        Scanner reader = new Scanner(System.in); 

        while(true) { 
            try{ 
              System.out.print("Input a number: "); 
              float input = reader.nextFloat(); 
              System.out.println("You input the number: " + input); 
              System.out.println("\r\n"); 

            } 
            catch(InputMismatchException e) 
            { 
                System.out.println
                ("Please enter a float number."); 
                System.out.println("\r\n"); 
            } 
        }  
    } 
} 
```

当我们运行这个程序时，首先我们必须快速测试它在一个良好的用例中是否正常工作，就像以前一样。然后，如果我们通过提供字符串输入导致`InputMismatchException`被抛出，我们应该看到我们的 catch 块执行，并且我们应该得到`请输入一个浮点数。`的响应：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/8c550cd6-7f09-4b4b-bf7b-fda46a559b08.png)

现在，正如你所看到的，我们确实得到了那个响应，但不幸的是，我们一遍又一遍地得到了那个响应。我们无意中引入了一个更糟糕的错误。现在，我们的程序不是抛出异常并崩溃，而是进入了一个无限循环。

这是为什么会发生这种情况：我们的`Scanner`对象`reader`是一个流读取器，这意味着它有一个输入缓冲区供它读取。在正常的使用情况下，当我们的无限`while`循环执行时，我们的用户将浮点数添加到该输入缓冲区。我们提取这些内容，打印它们，然后返回循环的开始并等待另一个。然而，当该缓冲区中发现一个字符串时，我们调用`nextFloat()`函数的代码行会抛出一个异常，这没问题，因为我们用 catch 块捕获了它。

我们的 catch 块打印出一行文本，告诉用户他/她提供了无效的输入，然后我们回到 while 循环的开头。但是，我们`reader`对象缓冲区中的坏字符串仍然存在，因此当我们捕获异常时，我们需要清除该流。

幸运的是，这是我们可以处理的事情。一旦我们捕获并处理了异常，我们需要清除流读取器，只需获取其下一行并不使用其信息。这将从读取器中刷新`Please enter a float number.`行：

```java
catch(InputMismatchException e) 
{ 
    System.out.println("Please enter a float number."); 
    System.out.println("\r\n"); 
} 
```

如果我们现在运行程序，我们会看到它处理并从失败的输入中恢复，我们给它一个字符串，这很酷：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/dc6c1a2a-4cf6-4427-b9eb-0731597e7a41.png)

让我们再讨论一些我们可以处理异常的事情。首先，在异常情况结束时清除我们的读取器是有很多意义的，但在任何尝试的情况结束时清除我们的读取器可能更有意义。毕竟，我们进入这个`while`循环的假设是读取器中没有新行。因此，为了实现这一点，我们有`finally`块。

# 最后的块

如果我们想要无论我们在`try`块中是否成功，都要执行一个案例，我们可以在`catch`块后面跟着`finally`块。`finally`块无论如何都会执行，无论是否捕获了异常。这是为了让您可以在系统中放置清理代码。清理代码的一个例子是清除我们的`reader`对象缓冲区，以便以后或其他程序员不会困惑。

异常不仅仅是一个简单的被抛出的对象；它们可能包含很多非常重要的信息。正如我们之前看到的，异常可能包含堆栈跟踪。让我们快速修改我们的程序，以便在它仍然提供用户友好的`Please enter a float number.`信息的同时，也打印出堆栈跟踪，以便程序员可以调试我们的程序。

通常，当我们编写用户将要使用的完成代码时，我们永远不希望出现他们能够看到像堆栈跟踪这样深的东西。对大多数计算机用户来说这很困惑，并且在某些情况下可能构成安全风险，但作为调试模式或开发人员的功能，这些详细的异常可能非常有用。

`Exception`类公开了一个名为`printStackTrace()`的方法，它需要一个流作为输入。到目前为止，我们一直在使用`System.out`作为所有输出，所以我们将为`printStackTrace()`方法提供`System.out`作为其流：

```java
catch(InputMismatchException e) 
{ 
    System.out.println("Please enter a float number."); 
    e.printStackTrace(System.out); 
    System.out.println("\r\n"); 
} 
```

现在，当我们运行程序并给出一个错误的字符串时，我们会得到我们最初友好的异常文本代码。但是，我们仍然有堆栈跟踪，因此我们可以准确地看到错误的来源：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/2d5302f8-3d50-45d1-b9af-75e200a5bb84.png)

正如我之前提到的，异常处理是现代软件开发中一个非常深入的主题，但在本节结束时，您应该对基础知识有所了解。当您在代码中遇到异常或者在编写自己的代码时感到需要异常处理时，您应该做好充分的准备。

# 对象类

在本节中，我们将学习关于 Java 如何选择实现面向对象编程的一些非常重要的内容。我们将探索`Object`类本身。为了开始，我写了一个非常基本的程序：

```java
package theobjectclass; 

public class TheObjectClass { 

    public static void main(String[] args) { 
        MyClass object1 = new MyClass("abcdefg"); 
        MyClass object2 = new MyClass("abcdefg"); 

        object1.MyMethod(); 
        object2.MyMethod(); 

        System.out.println("The objects are the same: " + 
        (object1 == object2)); 
        System.out.println("The objects are the same: " + 
        object1.equals(object2)); 
    } 

} 
```

该程序利用了一个名为`MyClass`的自定义类，并创建了这个类的两个实例：`object1`和`object2`。然后，我们在这些对象上调用了一个名为`MyMethod`的 void 方法，该方法简单地打印出我们给它们的值。然后，程序比较了这些对象。

我们首先使用比较运算符（`==`）进行比较，检查这两个对象是否实际上是同一个对象。我们知道这不会是真的，因为我们可以看到这些对象是完全独立实例化的。它们共享一个类，但它们是`MyClass`类的两个不同实例。然后，我们使用`equals()`方法比较这些对象，在本节中我们将经常讨论这个方法。

当我们运行这个程序时，我们看到当使用比较运算符进行比较时，对象被发现不相同，这是我们所期望的。但是，我们还看到当它们使用`equals()`方法进行比较时，尽管这两个对象是在相同的参数下创建的，并且从它们的创建到现在做了完全相同的事情，但这两个对象被发现不相等。以下是上述代码的输出：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/ccc58e6f-859d-494a-b94a-94f4cd1be784.png)

那么，当`equals()`方法发现对象不相等时，这意味着什么？我们应该问自己的第一个问题是，`equals()`方法来自哪里或者它是在哪里实现的？

如果我们按照`MyClass`类的定义，实际上找不到`equals()`方法，这是非常奇怪的，因为`MyClass`并没有声明从任何超类继承，但`equals()`直接在`MyClass`实例上调用。实际上，`MyClass`，就像所有的 Java 类一样，都继承自一个超类。在每个类继承树的顶部，都有`Object`类，即使它在我们的代码中没有明确声明。

如果我们前往 Java 文档（[docs.oracle.com/javase/7/docs/api/java/lang/Object.html](http://docs.oracle.com/javase/7/docs/api/java/lang/Object.html)）并查找`Object`类，我们会找到这样的定义：“`Object`类是类层次结构的根。每个类都有`Object`作为超类。所有对象，包括数组，都实现了这个类的方法。”然后，如果我们滚动页面，我们会得到一个简短但非常重要的方法列表：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/47b9097e-61a6-4de3-999d-9e2524a7dd8a.png)

因为所有的 Java 对象都继承自`Object`类，我们可以安全地假设我们正在处理的任何 Java 对象都实现了这里的每个方法。在这些方法中，就包括我们刚刚讨论并试图找出其来源的`equals()`方法。这让我们非常清楚，`MyClass`正在从它的`Object`超类中继承`equals()`方法。

在对象级别上，`equals()`方法的定义非常模糊。它说：“指示某个其他对象是否**等于**这个对象。”在某种程度上，这种模糊性让我们作为程序员来决定在逐个类的基础上真正意味着什么是相等的。

假设我们做出决定，合理的决定，即如果它们包含的值相同，那么`object1`和`object2`应该被确定为相等。如果我们做出这个决定，那么我们当前程序的实现就不太正确，因为它目前告诉我们`object1`和`object2`不相等。为了改变这一点，我们需要重写`MyClass`中的`equals()`方法。

# 重写 equals()方法

覆盖`Object`类方法并不比覆盖任何其他超类的方法更困难。我们只需声明一个相同的方法，当我们处理`MyClass`对象时，这个特定的方法将在适当的时候被使用。重要的是要注意，`equals()`方法不以`MyClass`对象作为输入；它以任何对象作为输入。因此，在我们继续比较这个对象的值与我们当前`MyClass`对象的值之前，我们需要保护自己，并确保作为输入的对象实际上是一个`MyClass`对象。

为了做到这一点，让我们检查一些坏的情况，我们希望我们的程序只需返回`false`，甚至不比较这些对象的内部值：

1.  如果我们得到的对象实际上没有被实例化，是一个指针，或者是一个空指针，我们只需返回`false`，因为我们实例化的`MyClass`对象与什么都不等价。

1.  更困难的问题是：我们得到的用于比较的对象是`MyClass`的一个实例吗？让我们检查相反的情况；让我们确认这个对象不是`MyClass`的一个实例。`instanceof`关键字让我们看到一个对象在其库存中有哪些类。如果我们的`instanceof`语句不评估为`true`，我们只需返回`false`，因为我们将比较一个`MyClass`对象和一个不是`MyClass`对象的对象。

一旦我们成功地通过了这些障碍，我们就可以安全地假设我们可以将给定的对象转换为`MyClass`对象。现在我们只需比较它们包含的值字段并返回适当的值。让我们将以下代码写入我们的`MyClass.java`文件，并返回到我们的`main()`方法来运行它：

```java
package theobjectclass; 

public class MyClass { 
    public String value; 
    public MyClass(String value) 
    { 
         this.value = value; 
         System.out.println
         ("A MyClass object was created with value:" + value); 
     } 
     public void MyMethod() 
     { 
        System.out.println
        ("MyMethod was called on a MyClass object with value: " + 
        value); 
      }  

      @Override 
      public boolean equals(Object obj) 
      { 
         if(obj == null) 
           return false; 

         if(!(obj instanceof MyClass)) 
         return false; 

         return value.equals(((MyClass)obj).value); 

       } 
} 
```

当我们运行这个程序时，我们会看到`object1`和`object2`被发现相互等价：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/8404f7a6-5e88-4f4b-aa20-e57d5c784790.png)

# 其他 Object 方法

`Object`类声明了许多方法。除了`equals()`之外，一些重要的方法是`hashCode()`和`toString()`。在本节中，我们不会实现`hashCode()`，因为它需要我们做比较复杂的数学运算，但我强烈建议你查看`hashCode()`的工作原理，方法是查看文档并探索它。

目前，让我们只知道一个对象的`hashCode()`方法应该返回一个描述该特定对象的整数值。在所有情况下，如果两个对象通过`equals()`方法被发现相等，它们的`hashCode()`函数也应该返回相同的整数值。如果两个对象不相等，就`equals()`方法而言，它们的`hashCode()`函数应该返回不同的值。

此时，我们应该熟悉`toString()`方法。这也是`Object`类中的一个方法，这意味着我们可以在任何单个对象上调用`toString()`方法。但是，在我们的自定义对象中，直到我们覆盖`toString()`，它可能不会返回有意义的、可读的信息。

当你学习 Java 时，我强烈建议你实现`equals()`和`toString()`，即使是在你学习时编写的小测试类上也是如此。这是一个很好的习惯，并且它让你以 Java 相同的方式思考面向对象编程。当我们创建最终的软件项目，其中有其他程序员可能会使用的公共类时，我们应该非常小心，确保所有我们的类以可理解的方式正确实现这些方法。这是因为 Java 程序员希望能够利用这些方法来操作和理解我们的类。

# 基本类

在本节中，我想快速看一下 Java 中可用的原始类。在 Java 中，我们经常说字符串很特殊，因为它们有一个由双引号标识的文字解释；然而，我们主要通过`String`类与它们交互，而不是通过我们实际上无法使用的`string`原始类型。

然而，在标准的 Java 原始类型中，我们通常通过其原始类型方法与其交互。对于每种原始类型，我们都有一个相应的原始类。这些是`Integer`、`Character`和`Float`类等。在大多数情况下，我们创建一个实例然后在该实例上调用方法的显式使用并不是很有用，除非我们重写它们以创建自己的类。让我们看一下以下程序：

```java
package the.primitiveclasses; 

public class ThePrimitiveClasses { 

    public static void main(String[] args) { 
        String s = "string"; 

        Character c = 'c'; 
    } 

} 
```

`Character`类的实例`c`给我们的方法主要是转换方法，如下面的屏幕截图所示，这些方法将自动发生，或者我们可以简单地进行转换： 

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/68d33633-94fb-4a1a-a536-5e5695e2bfcc.png)

请注意，`compareTo()`有时也很有用。如果给定的其他字符等于并且小于`0`或大于`0`，则返回整数值`0`，具体取决于两个字符在整数转换比例中相对于彼此的位置。

然而，通常我们可能会发现自己使用这些原始类的静态方法来操作或从原始类型的实例中获取信息。例如，如果我想知道我们的字符`C`是否是小写，我当然可以将它转换为整数值，查看 ASCII 表，然后看看该整数值是否落在小写字符的范围内。但是，这是一项繁重的工作：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/05e99a92-cd67-499e-bd6c-4af194773208.png)

`Character`原始类为我提供了一个静态函数`isLowercase()`，如前面的屏幕截图所示，它将告诉我一个字符是否是小写。让我们运行以下程序：

```java
package the.primitiveclasses; 

public class ThePrimitiveClasses { 

    public static void main(String[] args) { 
        String s = "string"; 

        Character c = 'c'; 
        System.out.println(Character.isLowerCase(c)); 
    } 

} 
```

以下是前面代码的输出：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/83f738f6-0dc7-4675-85cb-e0c051b8add4.png)

这确实是原始函数的要点。我们可以以相同的方式与其他文字类型及其原始类型进行交互：如果愿意，可以使用类与字符串交互。

当我们不需要原始类的功能时，应继续使用原始类型（例如，使用`char`而不是`Character`）。语法高亮功能的存在以及这些原始类型在各种语言中的统一外观使它们更加友好，便于程序员使用。

# 摘要

在本章中，我们看了 Java 的`Calendar`类来处理日期和时间。我们详细了解了`String`类。我们还了解了异常是什么，以及如何处理它们使我们的程序更加健壮。然后，我们走过了`Object`类及其一些方法。最后，我们看了 Java 的原始类。

在下一章中，我们将学习如何使用 Java 处理文件。


# 第九章：文件输入和输出

文件 I/O 功能是一个非常强大的工具，可以使现代编程中最困难和令人沮丧的任务之一，即在代码的逻辑上分离的实体之间传输信息，比原本更容易。话虽如此，在本章中，您将学习如何使用`FileWriter`和`BufferedWriter`和`FileReader`和`BufferedReader`类来编写和读取数据文件。我们还将看一下`close()`方法和`Scanner`类的用法。然后您将学习异常处理。最后，我们将看到 I/O 的另一个方面：`Serializable`类。

具体来说，我们将在本章中涵盖以下主题：

+   向文件写入数据

+   从文件读取数据

+   Serializable 类

# 向文件写入数据

这将是一个令人兴奋的章节。首先，我们将看看如何使用 Java 写入文件。为此，我们将声明一个数学序列，前 50 个数字将是数学序列的前两个数字的和。当我们运行以下程序时，我们将看到这 50 个数字打印到我们的`System.out`流中，并且我们将能够在控制台窗口中查看它们：

```java
package writingtofiles; 

public class WritingToFiles { 
    public static void main(String[] args) { 
        for(long number : FibonacciNumbers()) 
        { 
            System.out.println(number); 
        } 
    } 

    private static long[] FibonacciNumbers() 
    { 
        long[] fibNumbers = new long[50]; 
        fibNumbers[0] = 0; 
        fibNumbers[1] = 1; 
        for(int i = 2; i < 50; i++) 
        { 
            fibNumbers[i] = fibNumbers[i - 1] + fibNumbers[i - 2]; 
        } 
        return fibNumbers; 
    } 
} 
```

然而，当我们永久关闭控制台时，这些数字将丢失。为了帮助我们完成这项任务，我们将利用`java.io`库；在这里，`io`代表**输入和输出**：

```java
import java.io.*; 
```

我们将利用这个库中的一个类：`FileWriter`。

# FileWriter 类

`FileWriter`类及其用法可以解释如下：

1.  让我们声明一个新的`FileWriter`类，并且出于稍后会变得明显的原因，让我们明确地将这个`FileWriter`类设置为 null：

```java
        public class WritingToFiles { 
            public static void main(String[] args) { 
                FileWriter out = null; 
```

1.  一旦我们这样做，我们就可以继续实例化它。为了写入文件，我们需要知道两件重要的事情：

+   首先，当然，我们需要知道要写入文件的内容

+   其次，我们的`FileWriter`类需要知道它应该写入哪个文件

1.  当我们使用`FileWriter`类时，我们将它与特定文件关联起来，因此我们将文件名传递给它的构造函数，我们希望它写入该文件。我们的`FileWriter`类能够在没有文件的情况下创建文件，因此我们应该选择一个以`.txt`结尾的名称，这样我们的操作系统就会知道我们正在创建一个文本文件：

```java
        public class WritingToFiles { 
            public static void main(String[] args) { 
                FileWriter out = null; 
                    out = new FileWriter("out.txt"); 
```

尽管我们使用有效的参数调用了`FileWriter`构造函数，NetBeans 仍会告诉我们，我们在这段代码中会得到一个编译器错误。它会告诉我们有一个未报告的异常，即可能在此处抛出`IOException`错误。Java 中的许多异常都标记为已处理异常。这些是函数明确声明可能抛出的异常。`FileWriter`是一个明确声明可能抛出`IOException`错误的函数。因此，就 Java 而言，我们的代码不明确处理这种可能的异常是错误的。

1.  当然，为了处理这个问题，我们只需用`try...catch`块包装我们使用`FileWriter`类的代码部分，捕获`IOException`错误：

1.  如果我们捕获到`IOException`错误，现在可能是打印有用消息到**错误流**的好时机：

```java
        catch(IOException e) 
        { 
             System.err.println("File IO Failed."); 
        } 
```

然后，我们的程序将完成运行，并且将终止，因为它已经到达了`main`方法的末尾。有了这个异常捕获，`FileWriter`的实例化现在是有效和合法的，所以让我们把它用起来。

我们不再需要我们的程序将数字打印到控制台，所以让我们注释掉我们的`println`语句，如下面的代码块所示：

```java
        for(long number : FibonacciNumbers()) 
        { 
            // System.out.println(number); 
        } 
```

我们将用我们的`FileWriter`类做同样的逻辑处理：

```java
            try{ 
                out = new FileWriter("out.txt"); 
                for(long number : FibonacciNumbers()) 
                { 
                    // System.out.println(number); 
                } 
```

`FileWriter`类没有`println`语句，但它有`write`方法。每当我们的`foreach`循环执行时，我们希望使用`out.write(number);`语法将数字写入我们的文件。

1.  不幸的是，`write`方法不知道如何以“长数字”作为输入；它可以接受一个字符串，也可以接受一个整数。因此，让我们使用静态的`String`类方法`valueOf`来获取我们的“长数字”的值，以便将数字打印到我们的文件中：

```java
        for(long number : FibonacciNumbers()) 
        { 
            out.write(String.valueOf(number)); 
            // System.out.println(number); 
        } 
```

因此，我们现在应该拥有一个成功的程序的所有部分：

+   +   首先，我们声明并实例化了我们的`FileWriter`类，并给它一个文件名

+   然后，我们循环遍历我们的斐波那契数列，并告诉我们的`FileWriter`类将这些数字写入`out.txt`

然而，问题是`out.txt`在哪里？我们没有给`FileWriter`类一个完整的系统路径，只是一个文件名。我们知道`FileWriter`类有能力创建这个文件，如果它不存在，但在我们系统的目录中，`FileWriter`类会选择在哪里创建这个文件？

要回答这个问题，我们需要知道 NetBeans 将为我们编译的程序创建`.jar`文件的位置。为了找出这一点，我们可以打开控制台窗口并构建我们的程序。在这里，NetBeans 会告诉我们它正在创建所有文件的位置。例如，在我的情况下，有一个名为`WritingToFiles`的文件夹；如果我们导航到这个文件夹，我们会看到我们的项目文件。其中一个文件是`dist`，缩写为**可分发**，这就是我们的 JAR 文件将被编译到的地方：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/4b4712a9-692f-47dc-bac8-085a3768f239.png)

JAR 文件是我们能够获得的最接近原始 Java 代码的可执行文件。因为 Java 代码必须由 Java 虚拟机解释，我们实际上无法创建 Java 可执行文件；然而，在大多数安装了 Java 的操作系统中，我们可以通过双击运行 JAR 文件，就像运行可执行文件一样。我们还可以告诉 Java 虚拟机使用 Java 命令行`-jar`命令启动和运行 JAR 文件，后面跟着我们想要执行的文件的名称，当然：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/0df1bcb5-9a5d-4ff4-9675-e3e73121a04d.png)

当我们提交这个命令时，Java 虚拟机解释并执行了我们的`WritingToFiles.jar`程序。看起来好像成功了，因为在目录中创建了一个新文件，如前面的截图所示。这是工作目录，直到我们移动它，这就是执行 JAR 文件的命令将执行的地方。所以这就是我们的`FileWriter`类选择创建`out.txt`的地方。

# 使用 close()方法释放资源

不幸的是，当我们打开`out.txt`时，我们看不到任何内容。这让我们相信我们的文件写入可能没有成功。那么出了什么问题呢？嗯，使用`FileWriter`的一个重要部分我们没有考虑到。当我们创建我们的`FileWriter`时，它会打开一个文件，每当我们打开一个文件时，我们应该确保最终关闭它。从代码的角度来看，这是相当容易做到的；我们只需在我们的`FileWriter`上调用`close`方法：

```java
public class WritingToFiles { 
    public static void main(String[] args) { 
        FileWriter out = null; 
        try{ 
            out = new FileWriter("out.txt"); 
            for(long number : FibonacciNumbers()) 
            { 
                out.write(String.valueOf(number)); 
                // System.out.println(number); 
            } 

        } 
        catch(IOException e) 
        { 
            System.err.println("File IO Failed."); 
        } 

        finally{ 
            out.close(); 
        } 
    } 
```

有一个熟悉的错误消息出现，如下面的截图所示；`out.close`也可以报告一个`IOException`错误：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/9d911cd7-9921-4e02-87e7-44af424facee.png)

我们可以将`out.close`放在另一个`try...catch`块中，并处理这个`IOException`错误，但如果我们的文件无法关闭，那就意味着有非常严重的问题。在这种情况下，将这个异常传播到更健壮的代码而不是我们相当封闭的`WritingToFiles`程序可能更合适。如果我们不处理这个异常，这将是默认的行为，但我们确实需要让 Java 知道从我们当前的代码中向上传播这个异常是可能的。

当我们声明我们的`main`方法时，我们还可以让 Java 知道这个方法可能抛出哪些异常类型：

```java
public static void main(String[] args) throws IOException 
```

在这里，我们告诉 Java，在某些情况下，我们的`main`方法可能无法完美执行，而是会抛出`IOException`错误。现在，任何调用`WritingToFiles`的`main`方法的人都需要自己处理这个异常。如果我们构建了 Java 程序，然后再次执行它，我们会看到`out.txt`已经被正确打印出来。不幸的是，我们忘记在输出中加入新的行，所以数字之间没有可辨认的间距。当我们写入时，我们需要在每个数字后面添加`\r\n`。这是一个新的换行转义字符语法，几乎可以在每个操作系统和环境中看到：

```java
for(long number : FibonacciNumbers()) 
{ 
    out.write(String.valueOf(number) + "\r\n"); 
    // System.out.println(number); 
} 
```

再次构建、运行并查看`out.txt`，现在看起来非常有用：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/b2524382-1cf8-49fa-8b30-73d4e1caacba.png)

所以这是我们最初的目标：将这个斐波那契数列打印到一个文件中。在我们完成之前，还有一些事情要快速看一下。让我们看看如果我们再次运行程序会发生什么，然后看看我们的输出文本文件。文本文件看起来和之前一样，这可能是预期的，也可能不是。似乎`FileWriter`是否清除这个文件并写入全新的文本是一种抉择，或者它是否会在文件中现有文本后面放置追加的文本。默认情况下，我们的`FileWriter`会在写入新内容之前清除文件，但我们可以通过`FileWriter`构造函数中的参数来切换这种行为。比如，我们将其追加行为设置为`true`：

```java
try { 
    out = new FileWriter("out.txt", true); 
```

现在构建项目，运行它，并查看`out.txt`；我们会看到比以前多两倍的信息。我们的文本现在被追加到末尾。

# BufferedWriter 类

最后，在 Java 中有很多不同的写入器可供我们使用，`FileWriter`只是其中之一。我决定在这里向你展示它，因为它非常简单。它接受一些文本并将其打印到文件中。然而，很多时候，你会看到`FileWriter`被`BufferedWriter`类包裹。现在`BufferedWriter`类的声明将看起来像以下代码块中给出的声明，其中`BufferedWriter`被创建并给定`FileWriter`作为其输入。

`BufferedWriter`类非常酷，因为它会智能地接受你给它的所有命令，并尝试以最有效的方式将内容写入文件：

```java
package writingtofiles; 

import java.io.*; 

public class WritingToFiles { 
    public static void main(String[] args) throws IOException { 
        BufferedWriter out = null; 

        try { 
            out = new BufferedWriter(new FileWriter
             ("out.txt", true)); 

            for(long number : FibonacciNumbers()) 
            { 
                out.write(String.valueOf(number) + "\r\n"); 
                //System.out.println(number); 
            } 
        } 
        catch(IOException e) { 
            System.err.println("File IO Failed."); 
        } 
        finally{ 
            out.close(); 
        } 
    } 
```

我们刚刚编写的程序从我们的角度来看，做的事情与我们现有的程序一样。然而，在我们进行许多小写入的情况下，`BufferedWriter`可能会更快，因为在适当的情况下，它会智能地收集我们给它的写入命令，并以适当的块执行它们，以最大化效率：

```java
out = new BufferedWriter(new FileWriter("out.txt", true)); 
```

因此，很多时候你会看到 Java 代码看起来像前面的代码块，而不是单独使用`FileWriter`。

# 从文件中读取数据

作为程序员，我们经常需要从文件中读取输入。在本节中，我们将快速看一下如何从文件中获取文本输入。

我们已经告诉 Java，有时我们的`main`方法会简单地抛出`IOException`错误。以下代码块中的`FileWriter`和`FileReader`对象可能会因为多种原因创建多个`IOException`错误，例如，如果它们无法连接到它们应该连接的文件。

```java
package inputandoutput; 

import java.io.*; 

public class InputAndOutput { 
    public static void main(String[] args) throws IOException { 
        File outFile = new File("OutputFile.txt"); 
        File inFile = new File("InputFile.txt"); 

        FileWriter out = new FileWriter(outFile); 
        FileReader in = new FileReader(inFile); 

        //Code Here... 

        out.close(); 
        in.close(); 
    } 
} 
```

在为实际应用编写实际程序时，我们应该始终确保以合理的方式捕获和处理异常，如果真的有必要，就将它们向上抛出。但是我们现在要抛出所有的异常，因为我们这样做是为了学习，我们不想现在被包裹在`try...catch`块中的所有代码所拖累。

# FileReader 和 BufferedReader 类

在这里，您将通过我们已经有的代码（请参阅前面的代码）学习`FileReader`类。首先，按照以下步骤进行：

1.  我已经为我们声明了`FileWriter`和`FileReader`对象。`FileReader`是`FileWriter`的姊妹类。它能够，信不信由你，从文件中读取文本输入，并且它的构造方式非常相似。它在构造时期望被给予一个文件，以便在其生命周期内与之关联。

1.  与其简单地给`FileReader`和`FileWriter`路径，我选择创建`File`对象。Java 文件对象只是对现有文件的引用，我们告诉该文件在创建时将引用哪个文件，如下面的代码块所示：

```java
        package inputandoutput; 

        import java.io.*; 

        public class InputAndOutput { 
            public static void main(String[] args)
             throws IOException { 
                File outFile = new File("OutputFile.txt"); 
                File inFile = new File("InputFile.txt"); 

                FileWriter out = new FileWriter(outFile); 
                FileReader in = new FileReader(inFile); 

                //Code Here... 
                out.write(in.read()); 
                out.close(); 
                in.close(); 
            } 
        } 
```

在这个程序中，我们将使用包含一些信息的`InputFile.txt`。此外，我们将使用`OutputFile.txt`，目前里面没有信息。我们的目标是将`InputFile`中的信息移动到`OutputFile`中。`FileWriter`和`FileReader`都有一些在这里会有用的方法。

我们的`FileWriter`类有`write`方法，我们知道可以用它来将信息放入文件中。同样，`FileReader`有`read`方法，它将允许我们从文件中获取信息。如果我们简单地按顺序调用这些方法并运行我们的程序，我们会看到信息将从`InputFile`中取出并放入`OutputFile`中：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/bf4cf512-f991-429b-b835-a717aeea1821.png)

不幸的是，`OutputFile`中只出现了一个字符：`InputFile`文本的第一个字符。看起来我们的`FileReader`类的`read`方法只获取了最小可获取的文本信息。不过这对我们来说并不是问题，因为我们是程序员。

1.  我们可以简单地使用`in.read`方法循环遍历文件，以获取在`InputFile`文件中对我们可用的所有信息：

```java
        String input = ""; 
        String newInput; 
        out.write(in.read()); 
```

1.  然而，我们可以通过用`BufferedReader`类包装`FileReader`来使生活变得更加轻松。类似于我们用`BufferedWriter`包装`FileWriter`的方式，用`BufferedReader`包装`FileReader`将允许我们在任何给定时间收集不同长度的输入：

```java
        FileWriter out = new FileWriter(outFile); 
        BufferedReader in = new BufferedReader(new FileReader(inFile)); 
```

与包装我们的`FileWriter`类一样，包装我们的`FileReader`类几乎总是一个好主意。`BufferedReader`类还可以保护`FileReader`类，使其不受`FileReader`类一次性无法容纳的过大文件的影响。这种情况并不经常发生，但当发生时，可能会是一个相当令人困惑的错误。这是因为`BufferedReader`一次只查看文件的部分；它受到了那个实例的保护。

`BufferedReader`类还将让我们使用`nextLine`方法，这样我们就可以逐行从`InputFile`中收集信息，而不是逐个字符。不过，无论如何，我们的`while`循环看起来都会非常相似。这里唯一真正的挑战是我们需要知道何时停止在`InputFile`文件中寻找信息。为了弄清楚这一点，我们实际上会在`while`循环的条件部分放一些功能代码。

1.  我们将为这个`newInput`字符串变量分配一个值，这个值将是`in.readLine`。我们之所以要在`while`循环的条件部分进行这个赋值，是因为我们可以检查`newInput`字符串被分配了什么值。这是因为如果`newInput`字符串根本没有被分配任何值，那就意味着我们已经到达了文件的末尾：

```java
        while((newInput = in.readLine()) !=null) 
        { 

        } 
```

如果`newInput`有一个值，如果变量不是空的，那么我们会知道我们已经从文件中读取了合法的文本，实际上是一整行合法的文本，因为我们使用了`readLine`方法。

1.  在这种情况下，我们应该添加一行新的文本，即 `input += newInput;` 到我们的输入字符串。当我们执行完我们的 `while` 循环时，当 `newInput` 字符串被赋予值 `null`，因为读者没有其他内容可读时，我们应该打印出我们一直在构建的字符串：

```java
        while((newInput = in.readLine()) != null) 
        { 
            input += newInput; 
        } 
        out.write(input); 
```

1.  现在，因为我们的 `BufferedReader` 类的 `readLine` 方法专门读取文本行，它不会在这些行的末尾附加结束行字符，所以我们必须自己做：

```java
         while((newInput = in.readLine()) != null) 
        { 
             input += (newInput + "\r\n"); 
        } 
```

所以，我们已经执行了这个程序。让我们去我们的目录，看看复制到 `OutputFile` 的内容：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/5f074b43-77be-47bf-955d-653d75b19acf.png)

好了；`InputFile` 和 `OutputFile` 现在具有相同的内容。这就是 Java 中基本文件读取的全部内容。

还有一些其他需要注意的事情。就像我们可以用 `BufferedReader` 包装 `FileReader` 一样，如果我们导入 `java.util`，我们也可以用 `Scanner` 包装 `BufferedReader`：

```java
        Scanner in = new Scanner(new BufferedReader
        (new FileReader(inFile))); 
```

这将允许我们使用 `Scanner` 类的方法来获取我们正在读取的文本中与某些模式匹配的部分。还要注意的是，`FileReader` 类及其包装类只适用于从 Java 文件中读取文本。如果我们想要读取二进制信息，我们将使用不同的类；当您学习如何在 Java 中序列化对象时，您将看到更多相关内容。

# 可序列化类

通常，当我们处理实际代码之外的信息时，我们处理的是从文件中获取的或写入文件的人类可读的文本，或者来自输入或输出流的文本。然而，有时，人类可读的文本并不方便，我们希望使用更适合计算机的信息。通过一种称为**序列化**的过程，我们可以将一些 Java 对象转换为二进制流，然后可以在程序之间传输。这对我们来说不是一种友好的方法，我们将在本节中看到。对我们来说，序列化的对象看起来像是一团乱码，但另一个了解该对象类的 Java 程序可以从序列化的信息中重新创建对象。

然而，并非所有的 Java 对象都可以被序列化。为了使对象可序列化，它需要被标记为可以被序列化的对象，并且它只能包含那些本身可以被序列化的成员。对于一些对象来说，那些依赖外部引用或者那些只是没有所有成员都标记为可序列化的对象，序列化就不合适。参考以下代码块：

```java
package serialization; 

public class Car { 
    public String vin; 
    public String make; 
    public String model; 
    public String color; 
    public int year; 

    public Car(String vin, String make, String model, String 
     color, int year) 
    { 
        this.vin = vin; 
        this.make = make; 
        this.model = model; 
        this.color = color; 
        this.year = year; 
    } 

    @Override  
    public String toString() 
    { 
        return String.format
         ("%d %s %s %s, vin:%s", year, color, make, model, vin); 
    } 
} 
```

在给定程序中的类（在上面的代码块中）是序列化的一个主要候选对象。它的成员是一些字符串和整数，这些都是 Java 标记为可序列化的类。然而，为了将 `Car` 对象转换为二进制表示，我们需要让 Java 知道 `Car` 对象也是可序列化的。

我们可以通过以下步骤来实现这一点：

1.  我们将需要 `io` 库来实现这一点，然后我们将让 Java 知道我们的 `Car` 对象实现了 `Serializable`：

```java
        import java.io.*; 
        public class Car implements Serializable{ 
```

这告诉 Java，`Car` 对象的所有元素都可以转换为二进制表示。除非我们已经查看了对象并经过深思熟虑并确定这是一个安全的假设，否则我们不应该告诉 Java 对象实现了 `Serializable`。

所以，我们现在将 `Car` 标记为 `Serializable` 类，但这当然是本节的简单部分。我们的下一个目标是利用这个新功能来创建一个 `Car` 对象，将其序列化，打印到文件中，然后再读取它。

1.  为此，我们将创建两个新的 Java 类：一个用于序列化我们的对象并将其打印到文件中，另一个类用于反序列化我们的对象并从文件中读取它。

1.  在这两个类中，我们将创建 `main` 方法，以便我们可以将我们的类作为单独的 Java 程序运行。

# 序列化对象

让我们从`Serialize`类开始，如下所示：

1.  我们要做的第一件事是为我们序列化的对象。所以让我们继续实例化一个新的`Car`对象。`Car`类需要四个字符串和一个整数作为它的变量。它需要一个车辆识别号码、制造商、型号、颜色和年份。因此，我们将分别给它所有这些：

```java
        package serialization; 
        public class Serialize { 
            public static void main(String[] args) { 
                Car c =  new Car("FDAJFD54254", "Nisan", "Altima",
                "Green", 2000); 
```

一旦我们创建了我们的`Car`对象，现在是时候打开一个文件并将这个`Car`序列化输出。在 Java 中打开文件时，我们将使用一些不同的管理器，这取决于我们是否想要将格式化的文本输出写入这个文件，还是我们只打算写入原始二进制信息。

1.  序列化对象是二进制信息，所以我们将使用`FileOutputStream`来写入这些信息。`FileOutputStream`类是使用文件名创建的：

```java
        FileOutputStream outFile = new FileOutputStream("serialized.dat"); 
```

因为我们正在写入原始二进制信息，所以指定它为文本文件并不那么重要。我们可以指定它为我们想要的任何东西。无论如何，我们的操作系统都不会知道如何处理这个文件，如果它尝试打开它的话。

我们将想要将所有这些信息包围在一个`try...catch`块中，因为每当我们处理外部文件时，异常肯定会被抛出。如果我们捕获到异常，让我们只是简单地打印一个错误消息：

```java
            try{ 
                FileOutputStream outFile =  
                new FileOutputStream("serialized.dat"); 
            } 
            catch(IOException e) 
            { 
                 System.err.println("ERROR"); 
             } 
```

请注意，我们需要在这里添加很多输入；让我们只是导入整个`java.io`库，也就是说，让我们导入`java.io.*;`包。

现在我认为我们可以继续了。我们已经创建了我们的`FileOutputStream`类，这个流非常好。但是，我们可以用另一个更专门用于序列化 Java 对象的字符串来包装它。

1.  这是`ObjectOutputStream`类，我们可以通过简单地将它包装在现有的`FileOutputStream`对象周围来构造`ObjectOutputStream`对象。一旦我们创建了这个`ObjectOutputStream`对象并将文件与之关联，将我们的对象序列化并将其写入这个文件变得非常容易。我们只需要使用`writeObject`方法，并提供我们的`Car`类作为要写入的对象。

1.  一旦我们将这个对象写入文件，我们应该负责关闭我们的输出字符串：

```java
        try{ 
            FileOutputStream outFile = new
            FileOutputStream("serialized.dat"); 
            ObjectOutputStream out = new ObjectOutputStream(outFile); 
            out.writeObject(c); 
            out.close(); 
        } 
        catch(IOException e) 
        { 
             System.err.println("ERROR"); 
         } 
```

现在我认为我们可以运行我们接下来的程序了。让我们看看会发生什么：

```java
        package serialization; 

        import java.io.*; 

        public class Serialize { 
            public static void main(String argv[]) { 
                Car c = new Car("FDAJFD54254", "Nisan", "Altima",
                "Green", 2000); 

                try { 
                    FileOutputStream outFile = new
                    FileOutputStream("serialized.dat"); 
                    ObjectOutputStream out = new
                    ObjectOutputStream(outFile); 
                    out.writeObject(c); 
                    out.close(); 
                } 
                catch(IOException e) 
                { 
                    System.err.println("ERROR"); 
                } 
            }
        } 
```

在这个 Java 项目中，我们有多个`main`方法。因此，就 NetBeans 而言，当我们运行程序时，我们应该确保右键单击要输入的`main`方法的类，并专门运行该文件。当我们运行这个程序时，我们实际上并没有得到任何有意义的输出，因为我们没有要求任何输出，至少没有抛出错误。但是，当我们前往这个项目所在的目录时，我们会看到一个新文件：`serialize.dat`。如果我们用记事本编辑这个文件，它看起来相当荒谬：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/d8f4ce67-e72d-41fa-a47a-4844defd3871.png)

这肯定不是一种人类可读的格式，但有一些单词，或者单词的片段，我们是能够识别的。它看起来肯定是正确的对象被序列化了。

# 反序列化对象

让我们从我们的另一个类开始，也就是`DeSerialize`类，并尝试编写一个方法，从我们已经将其序列化信息写入的文件中提取`Car`对象。这样做的步骤如下：

1.  再一次，我们需要一个`Car`对象，但这一次，我们不打算用构造函数值来初始化它；相反，我们将把它的值设置为我们从文件中读取回来的对象。我们在反序列化器中要使用的语法将看起来非常类似于我们在`Serialize`类`main`方法中使用的语法。让我们只是复制`Serialize`类的代码，这样我们就可以在构建`DeSerialize`类的`main`方法时看到镜像相似之处。

在之前讨论的`Serialize`类中，我们在`Serialize`类的方法中犯了一个不负责任的错误。我们关闭了`ObjectOutputStream`，但没有关闭`FileOutputStream`。这并不是什么大问题，因为我们的程序立即打开了这些文件，执行了它的功能，并在终止 Java 时销毁了这些对象，文件知道没有其他东西指向它们。因此，我们的操作系统知道这些文件已关闭，现在可以自由地写入。但是，在一个持续很长时间甚至无限期的程序中，不关闭文件可能会产生一些非常奇怪的后果。

当我们像在这个程序中所做的那样嵌套`FileInput`或`Output`类时，通常会以我们访问它们的相反顺序关闭文件。在这个程序中，我们在调用`out.close`之前调用`outFile.close`是没有意义的，因为在这一瞬间，我们的`ObjectOutputStream`对象将引用一个它无法访问的文件，因为内部的`FileOutputStream`类已经关闭了。现在删除`Car c = new Car("FDAJFD54254", " Nisan", "Altima", "Green", 2000);`在当前的`DeSerialize.java`类中。

搞定了这些，我们已经复制了我们的代码，现在我们要对其进行一些修改。所以，我们现在不是将对象序列化到文件中，而是从文件中读取序列化的对象。

1.  因此，我们将使用它的姐妹类`FileInputStream`，而不是`FileOutputStream`：

```java
        FileInputStream outFile = new FileInputStream("serialized.dat"); 
```

1.  让我们再次导入`java.io`。我们希望引用与前面的代码中给出的相同的文件名；另外，让我们聪明地命名我们的变量。

1.  以类似的方式，我们将`FileInputStream`包装为`ObjectInputStream`，而不是`ObjectOutputStream`，它仍然引用相同的文件：

```java
        ObjectInputStream in = new ObjectInputStream(outFile); 
```

当然，这一次我们对将对象写入文件没有兴趣，这很好，因为我们的`InputStream`类没有权限或知识来写入这个文件；然而，它可以从文件中读取对象。

1.  `ReadObject`不需要任何参数；它只是简单地读取那个文件中的任何对象。当它读取到那个对象时，将其赋给我们的`Car`对象。当然，`ReadObject`只知道它将从文件中获取一个对象；它不知道那个对象的类型是什么。序列化的一个弱点是，我们确实被迫去相信并将这个对象转换为预期的类型：

```java
         c = (Car)in.readObject(); 
```

1.  一旦我们这样做了，就是时候以相反的顺序关闭我们的文件读取器了：

```java
        try { 
            FileInputStream inFile = new FileInputStream("serialized.dat"); 
            ObjectInputStream in = new ObjectInputStream(inFile); 
            c = (Car)in.readObject(); 
            in.close(); 
            inFile.close(); 
        } 
```

1.  现在有另一种被处理的异常类型，即`ClassNotFoundException`：![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/f1a66c24-7b73-458f-a70f-b7e7bfb59c3c.png)

如果我们的`readObject`方法失败，就会抛出这个异常。

所以，让我们捕获`ClassNotFoundException`，为了保持简单和流畅，我们将像处理之前的 I/O 异常一样，抛出或打印出错误消息：

```java
            catch(ClassNotFoundException e) 

            { 
                System.err.println("ERROR"); 
            } 
```

1.  现在我们需要一种方法来判断我们的程序是否工作。因此，在最后，让我们尝试使用自定义的`toString`函数打印出我们汽车的信息，也就是`System.out.println(c.toString());`语句。NetBeans 提示我们，变量`c`在这个时候可能尚未初始化，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/209ae27d-b146-44b4-99d6-623c1f270534.png)

有些编程语言会让我们犯这个错误，我们的`Car`对象可能尚未初始化，因为这个`try`块可能已经失败了。为了让 NetBeans 知道我们意识到了这种情况，或者说，让 Java 知道我们意识到了这种情况，我们应该初始化我们的`Car`对象。我们可以简单地将其初始化为值`null`：

```java
            public class DeSerialize { 
                public static void main(String[] args) { 
                    Car c = null; 

                    try { 
                        FileInputStream inFile = new
                        FileInputStream("serialized.dat"); 
                        ObjectInputStream in = new
                        ObjectInputStream(inFile); 
                        c = (Car)in.readObject(); 
                        in.close(); 
                        inFile.close(); 
                    } 
                    catch(IOException e) 
                    { 
                         System.err.println("ERROR"); 
                    } 
                    catch(ClassNotFoundException e) 

                    { 
                         System.err.println("ERROR"); 
                    } 
                    System.out.println(c.toString()); 
                } 

            } 
```

现在是我们真相的时刻。让我们执行主方法。当我们在控制台中运行我们的文件时，我们得到的输出是一个 PIN 码：`2000 Green Nisan Altima with vin: FDAJFD54254`。如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/ff4aebb5-e973-413e-98e8-99e163e4e226.png)

这是我们在`Serialize.java`类的`main`方法中声明并序列化到文件中的同一辆车。显然，我们取得了成功。对象的序列化是 Java 非常优雅和出色的功能之一。

# 总结

在本章中，我们经历了编写和读取数据文件的过程，我们看到了`FileWriter`和`FileReader`类的用法，以及如何使用`close()`方法释放资源。我们还学习了如何捕获异常并处理它。然后，您学习了如何使用`BufferedWriter`和`BufferedReader`类分别包装`FileWriter`和`FileReader`类。最后，我们看到了 I/O 的另一个方面：`Serializable`类。我们分析了序列化的含义以及在序列化和反序列化对象方面的用法。

在下一章中，您将学习基本的 GUI 开发。


# 第十章：基本 GUI 开发

有时，我们编写的程序完全关乎原始功能。然而，我们经常编写的程序通常由我们或其他用户使用，他们期望与我们互动的过程变得流畅。在本章中，我们将看到 NetBeans 中**图形用户界面**（**GUI**）的基本功能。真正了不起的软件程序的几个定义是它们的 GUI 和用户体验。您将学习如何使用`JFrame`类创建应用程序窗口，设置其大小，向其添加标签，并关闭整个应用程序。然后是 GUI 编辑器的主题，即调色板；在这里，我们将看到调色板的工作实例以及其中可用的组件。最后，您将学习如何通过添加按钮并向其添加功能来触发事件。

本章我们将涵盖以下主题：

+   Swing GUI

+   可视化 GUI 编辑工具 - 调色板

+   事件处理

# Swing GUI

NetBeans 是一个功能强大的程序，提供了许多功能，我们通过 NetBeans 提供的 GUI、菜单和按钮来访问这些功能。理论上，我们可以选择将 NetBeans 作为一个命令行程序来操作，但是为了像那样使用 NetBeans，我们将不得不记住或查找一个大型的特定命令库，以执行我们想要执行的每个操作。一个功能强大且写得很好的应用程序具有流畅的界面，将引导我们进入重要的功能，并使我们轻松访问它。JDK 包含一个 Java 扩展库，即`swing`库，它使我们能够非常容易地将我们自己的代码包装在像 NetBeans 这样的 GUI 中。

# JFrame 类

为了开始这个跟踪，我们将编写一个程序，将打开一个新的 GUI 窗口。步骤如下：

1.  在`swing` Java GUI 中心是`JFrame`类。在我们的情况下，这个类将是我们的操作系统处理的实际窗口对象，我们可以在屏幕上移动它。我们可以创建一个新的`JFrame`类，就像创建任何其他对象一样。我们甚至可以向这个`JFrame`类的创建传递一些参数。如果我们只给它一个字符串参数，我们将告诉`JFrame`类要将什么作为它的名称呈现出来：

```java
        package GUI; 
        import javax.swing.*; 

        public class GUI { 
            public static void main(String[] args) { 
                JFrame frame = new JFrame("Hello World GUI"); 
            } 

        } 
```

1.  一旦我们声明了`JFrame`类，它就会像任何其他对象一样存在于 Java 的内存中。除非我们明确告诉它，否则它不会呈现给用户。它只是一个对`setVisible`函数的函数调用，我们将为这个函数分配值`true`，非常简单对吧：

```java
        frame.setVisible(true); 
```

1.  在我们使 JFrame 窗口可见之前，我们还应该调用`pack`方法：

```java
        frame.pack(); 
```

当我们创建更复杂的框架时，它们可能包含大量信息，在 GUI 中，这些信息占据了可见空间。`pack`方法基本上预先构建了框架中对象之间的物理关系，并确保当它实际对用户可见时，框架不会表现出奇怪的行为。到目前为止，我们已经编写了一个非常简单的程序 - 只有三行代码，我们不需要考虑太多：

```java
        package gui; 
        import javax.swing.*; 

        public class GUI { 

            public static void main(String[] args) { 
               JFrame frame = new JFrame("Hello World GUI"); 
               frame.pack(); 
               frame.setVisible(true); 
            } 

        } 
```

当我们运行这个程序时，可能会看起来什么都没有发生，但实际上是有的。在屏幕的左上角，出现了一个新窗口。如果我们点击这个窗口的右侧，理论上我们可以拖动它或者调整窗口的大小：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/6e502859-8e4b-4bb0-b330-c85e7d2c2665.png)

这是一个完全成熟的窗口，我们的操作系统现在可以处理，允许我们移动; 它甚至支持动态调整大小。您会看到我们的标题也已附加到我们的窗口上。所以这非常基础。

# 设置窗口的大小

现在让我们看看我们的现有`JFrame`类还能做些什么。当我们的 JFrame 窗口出现时，它非常小而且很难看到。这样大小的程序窗口永远不会对任何人有用，所以让我们看看`frame`在设置窗口大小方面给我们的能力。通常，我们会使用`setPreferredSize`方法来为我们的`JFrame`类应用大小。还有一个`setSize`方法，但是这个方法并不总是给我们期望的结果。这是因为现在我们的`JFrame`类被设置为可调整大小，我们不应该明确地为它分配一个大小；相反，我们应该指示它在没有用户的其他输入的情况下，即调整 JFrame 窗口大小，窗口应该是某个大小。

我们可以使用`Dimension`类来存储、操作和创建大小信息。要构造一个新的维度，我们只需给它一个宽度和高度。所以让我们将`JFrame`类的首选大小，即在拉伸之前它想要的大小，设置为`400 x 400`：

```java
frame.setPreferredSize(new Dimension(400, 400)); 
```

`Dimension`类位于另一个库中，所以我们需要导入`java.awt.*;`包，然后我们应该能够构建和编译我们的项目，然后再次打开我们的新 GUI：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/c0714f29-7547-4158-ae40-3f7895cf4d19.png)

现在我们有一个不错的正方形 GUI 来开始；但是，因为里面没有任何内容，它仍然相当无用。

# 添加一个标签

现在让我们从编程角度快速看一下如何向我们的 GUI 添加元素。可能我们可以放在`JFrame`中的最简单的元素是`JLabel`。标签负责包含文本，实例化它们非常简单。我们只需告诉它们应该包含什么文本。当然，在更复杂的程序和 GUI 中，这个文本可能会变得动态并且可能会改变，但现在，让我们只是显示一些文本：

```java
JLabel label = new JLabel("Hi. I am a GUI."); 
```

仅仅声明我们有一个`JLabel`类是不够的。我们还没有以任何方式将这个标签对象与我们现有的窗口关联起来。我们的窗口，你可能可以通过它公开的大量方法和成员来看出来，有很多组件，我们需要知道我们需要将我们的新`JLabel`类放在这些组件中的哪一个：

```java
package gui; 
import javax.swing.*; 
import java.awt.*; 
public class GUI { 

    public static void main(String[] args) { 
        JFrame frame = new JFrame("Hello World GUI"); 
        frame.setPreferredSize(new Dimension(400, 400)); 
        JLabel label = new JLabel("Hi. I am a GUI."); 

        frame.pack(); 
        frame.setVisible(true); 
    } 

} 
```

在我们的`JFrame`类中的一个组件是`contentPane`；那是我们在窗口内可见的区域，通常程序的 GUI 中的东西都放在那里。这似乎是我们添加新组件的一个合理位置，在这种情况下是`label`。再一次，让我们构建我们的程序，关闭旧实例，然后运行新程序：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/9ceda3ee-3b74-470a-b2be-eddfffad4092.png)

现在我们的 GUI 中有文本了！我们成功地向我们的 JFrame 窗口的内容中添加了一个元素。

# 关闭我们的应用程序

有点烦人的是，我们的程序在关闭关联的 GUI 后仍在继续运行。这有点傻。当我在 NetBeans GUI 上按关闭按钮时，NetBeans 关闭自身，并在我的系统上停止运行作为一个进程。我们可以使用它的`setDefaultCloseOperation`方法指示我们的窗口终止关联的进程。这个方法的返回类型是`void`，并且以整数值作为参数。这个整数是一个枚举器，有很多选项可供我们选择。所有这些选项都是由`JFrame`类静态声明的，我们可能正在寻找的是`EXIT_ON_CLOSE`，当我们关闭窗口时，它将退出我们的应用程序。构建和运行程序，终止 GUI，我们的进程也随之结束，不再悄悄地在后台运行：

```java
frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE); 
```

这是我们对 Java 中 GUI 的基本介绍。创建 GUI 很复杂，但也很令人兴奋，因为它是视觉和即时的；而且它真的很强大。

如下面的代码块所示，我们的程序现在是功能性的，但如果我们要扩展它，我们可能最终会遇到一些非常奇怪和令人困惑的问题。我们现在所做的与创建新 GUI 时的推荐做法相悖。这些推荐做法是为了保护我们免受程序变得多线程时可能出现的一些非常低级的问题。

当我们说我们的程序是多线程的时，这是什么意思？嗯，当我们创建我们的 GUI，当我们使它出现时，我们的程序从执行单个任务，即简单地从头到尾执行`main`方法，变成执行多个任务。这是因为我们现在正在执行以下代码：

```java
package gui; 
import javax.swing.*; 
import java.awt.*; 
public class GUI { 

    public static void main(String[] args) { 
        JFrame frame = new JFrame("Hello World GUI"); 
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE); 
        frame.setPreferredSize(new Dimension(400, 400)); 
        JLabel label = new JLabel("Hi. I am a GUI."); 
        frame.getContentPane().add(label); 
        frame.pack(); 
        frame.setVisible(true); 
    } 

} 
```

然而，此外，该代码还管理了我们创建的新窗口以及该窗口执行的任何功能。为了保护自己免受多线程代码的复杂性，建议我们通过允许 Swing 实用程序异步地为我们构建此 GUI 来创建我们的新 Swing GUI。

为了实现这一点，我们实际上需要将我们写的所有代码从`main`方法中提取出来，放在一个地方，我们可以从`main`方法中引用它。这将是一个新的函数，如下面的代码行所示：

```java
private static void MakeGUI() 
```

我们可以把所有这些代码都粘贴回我们的新函数中：

```java
private static void MakeGUI() 
{ 
    JFrame frame = new JFrame("Hello World GUI"); 
    frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE); 
    frame.setPreferredSize(new Dimension(400, 400)); 
    JLabel label = new JLabel("Hi. I am a GUI."); 
    frame.getContentPane().add(label); 
    frame.pack(); 
    frame.setVisible(true); 
} 
```

# SwingUtilities 类

现在，让我们看看 Swing 建议我们如何使我们的 GUI 出现。正如我所说，`swing`包为我们提供了一些功能，可以为我们执行这么多的工作和思考。`SwingUtilities`类有一个静态的`invokeLater`方法，当没有其他线程真正需要被处理或者所有其他思考都做完一会儿时，它将创建我们的 GUI：

```java
SwingUtilities.invokeLater(null); 
```

这个`invokeLater`方法希望我们向它传递一个`Runnable`对象，所以我们将不得不为自己创建一个`Runnable`对象：

```java
Runnable GUITask = new Runnable() 
```

`Runnable`对象是可以转换为自己的线程的对象。它们有一个我们将要重写的方法，叫做`run`，`SwingUtilities.invokeLater`方法将在适当时调用`Runnable`的`run`方法。当这发生时，我们希望它只是调用我们的`MakeGUI`方法并开始执行我们刚刚测试过的代码，那个将创建 GUI 的代码。我们将添加`Override`注释以成为良好的 Java 程序员，并将我们的新`Runnable`对象传递给`SwingUtilities`的`invokeLater`方法：

```java
public static void main(String[] args) { 
    Runnable GUITask = new Runnable(){ 
        @Override 
        public void run(){ 
            MakeGUI(); 
        } 
    }; 
    SwingUtilities.invokeLater(GUITask); 
} 
```

运行上述程序，我们成功了！功能完全相同，我们所做的可能对于这么小的程序来说有点过度；然而，对于我们来说，看看我们在一个更大的软件项目中应该期望看到的东西是非常有益的，比如多线程可能会成为一个问题。我们走得有点快，所以让我们停下来再看一下这一部分：

```java
Runnable GUITask = new Runnable(){ 
    @Override 
    public void run(){ 
        MakeGUI(); 
    } 
}; 
```

在这段代码中，我们创建了一个匿名类。虽然看起来我们创建了一个新的`Runnable`对象，但实际上我们创建了`Runnable`对象的一个新子类，它有自己特殊的重写版本的`run`方法，并且我们把它放在了我们的代码中间。这是一种强大的方法，可以减少所需的代码量。当然，如果我们过度使用它，我们的代码很快就会变得非常复杂，对我们或其他程序员来说很难阅读和理解。

# 一个可视化 GUI 编辑器工具 - 调色板

Java 编程语言，GUI 扩展库如`Swing`，以及一个强大的开发环境 - 如 NetBeans - 可以是一个非常强大的组合。现在我们将看看如何使用 NetBeans 中的 GUI 编辑器来创建 GUI。

为了跟上，我强烈建议您在本节中使用 NetBeans IDE。

因此，让我们开始创建一个 Java 应用程序，就像我们通常做的那样，并给它一个名称，然后我们就可以开始了。我们将从简单地删除 NetBeans 提供的默认 Java 文件，而是要求 NetBeans 创建一个新文件。我们要求它为我们创建一个 JFrame 表单：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/7d295170-a12e-45ef-9cdf-9a4e8cde07a6.png)

我们将为这个 JFrame 表单命名，并将其保留在同一个包中。当 NetBeans 创建此文件时，即使它是一个`.java`文件，弹出的窗口对我们来说看起来会非常不同。事实上，我们的文件仍然只是 Java 代码。单击“源”选项卡，以查看代码，如下图所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/99501467-d025-4a83-b179-fc4612e6cf97.png)

# 调色板的工作原理

我们可以在“源代码”选项卡中看到组成我们文件的 Java 代码；如果我们展开它，这个文件中实际上有很多代码。这些代码都是由 NetBeans 的调色板 GUI 编辑器为我们生成的，如下图所示。我们对这个 Java 文件所做的更改将影响我们的“设计”文件，反之亦然。从这个“设计”文件中，我们可以访问拖放编辑器，并且还可以编辑单个元素的属性，而无需跳转到我们的 Java 代码，也就是“源”文件。最终，在我们创建的任何应用程序中，我们都将不得不进入我们的 Java 代码，以为我们放入编辑器的部分提供后端编程功能；现在，让我们快速看一下编辑器的工作原理。

我想为密码保护对话框设置框架。这不会太复杂，所以我们将使 JFrame 表单比现在小一点。然后，看一下可用的 Swing 控件；有很多。事实上，借助 NetBeans，我们还可以使用其他 GUI 扩展系统：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/873a5355-84b0-4a53-8575-362b7d63fafb.png)

以下是设置密码保护对话框框架的步骤：

1.  让我们只使用 Swing 控件，保持相当基本。标签是最基本的。我们的密码对话框需要一些文本：![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/a16451a4-5988-4b39-9d35-b2817feac122.png)

1.  现在，密码对话框还需要一些用户交互。我们不仅需要密码，还需要用户的用户名。要获取用户名，我们将不得不在 Swing 控件下选择几个选项：![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/55194655-5992-418a-8d1d-e6b6c975b19f.png)

文本区是一个好选择。它允许用户在框中输入文本，不像标签，只有开发人员可以编辑。用户可以点击框并在其中输入一些文本。不幸的是，这个框相当大，如果我们点击它并尝试使其变小，我们将得到滚动条，以允许用户在其大小周围移动。

当滚动条出现时，我们可以通过更改我们可以从编辑器访问的任意数量的属性来修改此框的默认大小。然而，一个更简单的解决方案是简单地使用文本字段，它没有我们的框的所有多行功能。此外，在文本字段旁边放置标签，您会注意到图形编辑器有助于对齐事物。如果我们正确地双击诸如标签之类的字段，我们可以在那里编辑它们的文本：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/c7f3d1c1-bc6b-468d-a71d-067bea20b62c.png)

现代 GUI 的一个很酷的功能是有一些非常专业化的控件。其中之一是密码字段。在许多方面，它将表现得就像我们的文本字段控件一样，只是它会用点来替换用户在其中输入的任何文本，以便正在旁边看的人无法学到他们的密码。如果您未能双击可编辑元素，它将带您返回到源代码。

我们将编辑两个组件 - 文本和密码字段 - 以便我们的用户可以在其中放置文本，以便它们最初不会显示为默认值。我们可以双击密码字段，或者只需编辑控件的属性：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/09bad6b6-2965-4cf9-815f-1b666cc7b99b.png)

在这里，我们的文本字段控件的文本值可以被修改为一开始什么都没有，我们的密码也可以做同样的事情。您会注意到我们的密码的文本值实际上有文本，但它只显示为一堆点。但是，程序员可以访问此值以验证用户的密码。在属性选项卡中还有很多其他选项：我们可以做诸如更改字体和前景和背景颜色，给它边框等等的事情。

当我们运行程序时，您将看到它实际上存在，并且用户可以将值放入这些字段中：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/5252847a-208d-427e-84be-3e1cd8f8de03.png)

当然，我们还没有编写任何后端代码来对它们进行有用的操作，但 GUI 本身已经可以运行。这里没有发生任何魔法。如果我们跳转到这段代码的源代码并转到其`main`方法，我们将看到实际创建和显示给用户的 GUI 的代码（请参见以下屏幕截图）：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/cfa02b3a-44c3-4a72-8105-967356878cba.png)

重要的是要意识到，当我们访问源代码中的元素时，所有这些方法论也可以通过原始 Java 提供给我们。这就是我在这一部分真正想向您展示的内容，只是原始的力量以及我们如何快速使用 NetBeans 图形编辑器为系统设置 GUI 窗口。

# 事件处理

在 Java 中工作的最好的事情之一是它的 GUI 扩展库有多么强大，以及我们可以多快地让一个程序运行起来，不仅具有功能代码，而且还有一个漂亮的专业外观的用户界面，可以帮助任何人与我们的程序交互。这就是我们现在要做的：将基本用户名和密码验证的设计界面与我们将要编写的一些后端代码连接起来，这些代码实际上将检查两个文本字段，看它们是否是我们正在寻找的。 

首先，我们有一个基本的 GUI，其中有一个文本字段，用户可以在其中放置用户名和密码，这些将显示为星号：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/646c18ba-71b4-4b60-8c02-efa1ba424d8f.png)

# 添加按钮

到目前为止，此 GUI 的源代码完全是自动生成的。我们还没有触及它；它只是反映了我们在这里做出的设计决策。在我们开始编写后端代码来验证用户名和密码之前，我们的用户需要一种方式告诉我们，他们已经输入了用户名和密码，并且希望对其进行验证。这似乎是一个适合全能按钮的工作。因此，让我们从 Swing Controls 菜单中向我们的 GUI 添加一个按钮。我们将在属性选项中将其文本更改为`提交`，用户需要单击此按钮以提交他们的信息。现在，当单击按钮时，我们希望它执行一些编程逻辑。我们要检查用户名和密码字段，因为我们只是在学习和简单易行的事情；我们将只检查它们是否与一些硬编码的文本匹配。

问题是我们如何从 GUI 到功能性的 Java 代码？一般来说，我们将通过**事件驱动**编程模式来实现这一点，用户与 GUI 的交互决定了执行哪些 Java 代码以及发生了什么后端逻辑。另一种思考方式是，我们可以设置我们的 Java 代码的片段或方法来监听特定的与 GUI 相关的事件，并在它们发生时执行。您会注意到我们的 GUI 组件或控件，比如我们的按钮，其属性下有一个名为事件的字段。这些都是与我们的控件相关的可能发生的事情。理论上，我们可以将这些事件中的每一个绑定到我们 Java 源代码中的一个方法，当特定事件发生时，无论是因为用户交互还是我们编写的其他代码，我们相关的 Java 方法都会被调用。

# 为我们的按钮添加功能

为了让用户点击我们的按钮字段并执行一些编码操作，我们将为我们的`actionPerformed`事件分配一个事件处理程序。如果我们点击这个字段，我们已经有一个选项。我们的 GUI 设计师建议我们添加一个处理程序，即`jButton1ActionPerformed`。这是一个糟糕的方法名称，它将在我们的代码中存在；`jBbutton1`相当不具描述性。然而，它被选择是因为它是在实际的 Java 代码中创建`jButton`时分配的变量名：

```java
// Variables declaration - do not modify 
private javax.swing.JButton jButton1; 
private javax.swing.JLabel jLabel1; 
private javax.swing.JLabel jLabel2; 
private javax.swing.JLabel jLabel3; 
private javax.swing.JPasswordField jPasswordField1; 
private javax.swing.JTextField jTextField1; 
// End of variables declaration 
```

如果我们在源代码中向下滚动，我们会看到实际的声明。我相信我们可以更改这些设置，但 NetBeans 会让我们知道我们可能不应该直接修改这个。这是因为设计师也将对其进行修改。所以我们只需将按钮的名称从不具描述性的`jButton1`更改为`SubmitButton`：

```java
// Variables declaration - do not modify 
private javax.swing.JButton SubmitButton; 
```

当我们进行这个更改时，我们会看到 NetBeans 会更新我们的源代码，有一个`SubmitButton`对象在那里跳来跳去。这是一个以大写字母开头的变量，所以我们将在事件部分进行一次更改，将其更改为`submitButton`。

现在 NetBeans 建议执行的操作是`submitButtonActionPerformed`。当我们转到源代码时，我们会看到一个事件已经被创建，并且链接到了一个巨大的生成代码块中的`jButton`，这是 NetBeans 为了模仿我们通过他们的工具创建的 GUI 而创建的。如果我们在源代码中搜索我们的`submitButtonActionPerformed`方法，我们实际上会看到它被添加到生成的代码中：

```java
public void actionPerformed(java.awt.event.ActionEvent evt) { 
    submitButtonActionPerformed(evt); 
} 
```

我们的`submitButtonActionPerformed`方法已被添加为`submitButton`中放置的`ActionListener`的最终调用：

```java
submitButton.addActionListener(new java.awt.event.ActionListener() { 
    public void actionPerformed(java.awt.event.ActionEvent evt) { 
        submitButtonActionPerformed(evt); 
    } 
}); 
```

`ActionListener`当然只有一个工作，那就是看我们的按钮是否被点击。如果被点击，它将调用我们的`submitButtonActionPerformed`方法。因此，在这个`submitButtonActionPerformed`方法中，我们可以放一些老式的功能性 Java 代码。为此，我们需要做两件事：

+   检查密码字段的值

+   检查用户名字段的值

只有`ActionEvent`（如前面的代码块中所示）被传递到我们的`submitButtonActionPerformed`方法中。虽然与这个事件相关联的有很多有趣和有用的方法，但是导致我们的方法被调用的动作的上下文，它不会给我们我们真正需要的东西。我们真正需要的是我们的密码字段和我们的文本字段，幸运的是它们是我们当前类的私有成员。验证我们文本字段的值的步骤如下：

1.  从用户名开始，也就是`jTextField1`：

```java
        private void submitButtonActionPerformed
        (java.awt.event.ActionEvent evt) { 
            jTextField1 
        } 
```

当我们有机会时，我们应该重命名它，但现在我们只能接受它，因为我们只有一个文本字段：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/72f5504b-bdad-42e3-a5ea-abd2e589fe14.png)

如果您记得，在属性选项卡下的编辑器中，这个文本字段有一个文本属性。我们去掉了这个文本，因为我们不希望我们的用户名文本字段以任何文本开头。我们希望它是空白的，这样用户就会知道他们必须在那里放入自己的信息。

1.  现在，如果这是设计师向我们公开的属性，那么对象本身应该有一个相关的属性，确实有，即`getText()`：

```java
        private void submitButtonActionPerformed
        (java.awt.event.ActionEvent evt) { 
            jTextField1.getText() 
        } 
```

1.  当我们调用`getText`时，当然，我们返回当前存储在文本字段中的文本，并且我们将我们的超级秘密用户名设置为非常“有创意”的单词`username`。

这是一个条件语句，我们将要做另一个条件语句。我们想要询问我们的程序文本字段和密码字段 - 在这种情况下将暴露一个类似的方法`getPassword` - 是否都等于硬编码的字符串。我们的秘密密码将是`java`。请注意，`getPassword`实际上返回一个字符数组，而不是一个字符串，所以为了保持简单，让我们将密码值分配给一个字符串，然后我们就可以将其用作字符串。在我们的条件语句前面加上`if`，在括号内，我们就可以开始了：

```java
            private void submitButtonActionPerformed
            (java.awt.event.ActionEvent evt) { 
                String password = new
                String(jPasswordField1.getPassword()); 
                if (jTextField1.getText().equals("username")
                && password.equals("java")) 
                { 

                } 
            } 
```

现在我们需要给我们的用户一些指示，无论他们是否成功提供了正确的用户名和密码。好的，如果用户成功输入了一个好的用户名和一个好的密码，我们该怎么办呢？嗯，我认为如果我们在这里显示一个弹出对话框会很酷。

1.  `JOptionPane`为我们提供了`showMessageDialog`方法，这是一种非常酷的方式，可以向用户传达非常重要和即时的信息。它会显示一个弹出框，非常轻量级且易于使用。您可能需要修复这个导入：

```java
        { 
            JOptionPane.showMessageDialog(rootPane, password); 
        } 
```

`MessageDialog`需要创建自己的唯一重量级信息是要附加到的 GUI 组件，作为其父级。我们可以通过`ActionEvent`获取`button evt`，但这并没有太多意义，因为对话框不仅仅与按钮绑定；它与这个 GUI 的整体相关，这是验证用户名和密码。因此，如果我们可以将消息对话框绑定到 JFrame 表单本身，GUI 的顶级元素，那将是很好的，实际上我们可以：

```java
            public class MyGUI extends javax.swing.JFrame { 

                /** 
                 * Creates new form MyGUI 
                */ 
                public MyGUI() { 
                    initComponents(); 
                } 
```

1.  如果我们向上滚动一点到我们的源代码部分，检查我们正在写代码的确切位置，我们会看到我们在一个名为`MyGUI`的类中，它扩展了`JFrame`类。整个类与我们正在使用的`JFrame`类相关联。因此，要将`JFrame`作为变量传递给我们的`showMessageDialog`方法，我们只需使用`this`关键字。现在只需输入一条消息，以便在验证密码和用户名时向用户显示：

```java
        private void submitButtonActionPerformed
        (java.awt.event.ActionEvent evt) { 
            String password = new String(jPasswordField1.getPassword()); 
            if (jTextField1.getText().equals("username") 
            && password.equals("java")) 
            { 
                 JOptionPane.showMessageDialog(this, "Login Good!"); 
            } 
        } 
```

让我们运行我们的程序，看看我们建立了什么。对话框出现了，这是我们之前见过的，也是我们期望的，然后执行以下步骤：

1\. 输入我们的有效用户名，即`username`。

2\. 输入我们的有效密码，即`java`。

3\. 然后，点击提交按钮。

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/9fec4b08-91f9-4b42-8b45-a5be7830e506.png)

我们得到一个对话框，看起来像下面的截图。我们可以自由地在我们的 JFrame 实例中移动这个框：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/25daa1f0-039a-4e94-9c79-6c17cd0d5def.png)

只是为了测试一下，让我们输入一些胡言乱语。无论我们点击多少次提交，我们都得不到任何东西。而且一个好的用户名和没有密码也得不到任何东西，非常酷！我们只是触及了 Java GUI 可能性的表面，当然，也是 Java 本身。

为我们的程序创建 Java GUI 是容易的，在许多情况下，也是无痛的。有时，GUI 强制我们实现事件处理模型，在某种程度上甚至可以使我们创建依赖用户交互的 Java 程序变得更容易。

另一个我无法再强调的重要事情是，尽管 GUI 设计师很棒，我们也可以通过简单地坐下来在源代码部分编写 Java 代码来创建完全相同的项目。

我并不是说我们不应该使用 GUI 设计师 - 尤其是因为有很多代码和很多由 GUI 设计师为我们生成的精心编写的代码，这可以节省我们大量的时间 - 但这里绝对没有任何魔法发生。这都是使用`Swing`扩展库的 Java 代码。

# 总结

在本章中，我们看到了 NetBeans 中 GUI 的基本功能。您学会了如何使用`JFrame`类创建应用程序窗口，设置其大小，向其添加标签，并关闭应用程序。然后，我们深入讨论了 GUI 编辑器，调色板的主题。我们看到了一个工作的调色板以及其中可用的组件。最后，您学会了如何通过添加按钮并为其添加功能来触发事件。

在下一章中，您将学习有关 XML 的知识。


# 第十一章：XML

假设我们想要存储具有对我们程序有意义的结构的信息。此外，我们希望这些信息在某种程度上是可读的，有时甚至是可编辑的。为了实现这一点，我们经常转向 XML。

Java 为我们提供了强大的工具，用于操作、读取和编写 XML 原始文本和文件。然而，与许多强大的工具一样，我们需要学习如何使用它们。在本章中，我们首先将看看如何使用 Java 将 XML 文件加载到 Java 对象中。接下来，我们将逐步介绍如何使用 Java 解析 XML 数据。最后，我们将看到用于编写和修改 XML 数据的 Java 代码。

在本章中，我们将涵盖以下主题：

+   用于读取 XML 数据的 Java 代码

+   解析 XML 数据

+   编写和修改 XML 数据

# 读取 XML 数据

在本节中，我们将完成一个非常简单的任务，以便开始学习 Java 如何与 XML 交互的道路。我们将使用代码文件中提供的`cars.xml`文件中的 XML 信息。这个文件应该存储在我们 Java 项目的当前目录中，所以当我们运行我们的 Java 程序时，它将能够访问`cars.xml`而不需要任何额外的路径。我们将编辑以下 Java 程序以加载`cars.xml`文件：

```java
package loadinganxmlfile; 

import java.io.*; 
import javax.xml.parsers.*; 
import javax.xml.transform.*; 
import javax.xml.transform.dom.*; 
import javax.xml.transform.stream.*; 
import org.w3c.dom.*; 
import org.xml.sax.*; 

public class LoadingAnXMLFile { 
    public static void main(String[] args) { 

        try { 
            //Write code that can throw errors here 
        } 
        catch (ParserConfigurationException pce) { 
            System.out.println(pce.getMessage()); 
        } 
        catch (SAXException se) { 
            System.out.println(se.getMessage()); 
        } 
        catch (IOException ioe) { 
            System.err.println(ioe.getMessage()); 
        } 
    } 

    private static void PrintXmlDocument(Document xml) 
    { 
        try{ 
            Transformer transformer = 
             TransformerFactory.newInstance().newTransformer(); 
            StreamResult result = new StreamResult
             (new StringWriter()); 
            DOMSource source = new DOMSource(xml); 
            transformer.transform(source, result); 
            System.out.println(result.getWriter().toString()); 
        } 
        catch(TransformerConfigurationException e) 
        { 
            System.err.println("XML Printing Failed"); 
        } 
        catch(TransformerException e) 
        { 
            System.err.println("XML Printing Failed"); 
        } 
    } 
} 
```

在我们开始之前，请注意这个程序需要大量的导入。我们导入的`transform`类对我们将要编写的任何内容都不是必需的；我已经编写了一个名为`PrintXmlDocument()`的函数，如果我们成功加载它，它将把我们的 XML 文档打印到控制台窗口。如果您在本节中跟着代码，我建议您首先从一开始导入这些`transform`类。然后，当您使用额外的功能时，继续使用 NetBeans 的“修复导入”功能，以确切地看到工具所使用的库来自哪里。

让我们开始吧。我们的最终目标是拥有一个`Document`类的对象，其中包含我们`cars.xml`文件中的信息。一旦我们有了这个`Document`对象，我们只需要调用`Document`实例上的`PrintXmlDocument()`函数，就可以在我们的控制台窗口中看到信息。

不幸的是，创建这个`Document`对象并不像说`Document dom = new Document();`那样简单。相反，我们需要以一种结构化和程序化的方式创建它，以正确地保留我们的 XML 文件的可解析性。为此，我们将使用另外两个类：`DocumentBuilder`和`DocumentBuilderFactory`类。

`DocumentBuilder`类，信不信由你，将负责实际为我们构建文档。`DocumentBuilder`类作为一个独立的实体存在，与`Document`对象分开，这样我们作为程序员可以在逻辑上分开我们可以对文档本身执行的方法和创建该文档所需的附加方法的范围。与`Document`类类似，我们不能只是实例化`DocumentBuilder`类。相反，有一个第三个类我们将利用来获取`DocumentBuilder`，即`DocumentBuilderFactory`类。我已经将创建`Document`对象所需的代码分为三部分：

1.  `DocumentBuilderFactory`类包含一个名为`newInstance()`的静态方法。让我们在`main()`方法的第一个`try`块中添加以下方法调用。这将为我们实例化`DocumentBuilderFactory`以便我们可以使用它：

```java
        DocumentBuilderFactory factory = 
        DocumentBuilderFactory.newInstance(); 
```

1.  一旦我们有了`DocumentBuilderFactory`，我们就可以为自己获取一个新的`DocumentBuilder`对象。为此，我们将调用工厂的`newDocumentBuilder()`方法。让我们把它添加到我们的 try 块中：

```java
        DocumentBuilder builder = factory.newDocumentBuilder(); 
```

1.  最后，我们需要指示`DocumentBuilder`构建一个`Document`对象，并且该对象应该反映我们的`cars.xml`文件的结构。我们将在我们的`try`块中简单地用一个值实例化我们的`Document`对象。我们将从`builder`的`parse()`方法中获取这个值。这个方法的一个参数是一个引用文件名的字符串。如果我们在我们的 Java 程序中有一个引用文件对象，我们也可以使用它：

```java
        Document dom = builder.parse("cars.xml"); 
```

现在我们的`main()`方法看起来如下：

```java
        public static void main(String[] args) { 
            DocumentBuilderFactory factory = 
            DocumentBuilderFactory.newInstance(); 
            try { 
                // Write code that can throw errors here... 
                DocumentBuilder builder = 
                factory.newDocumentBuilder(); 
                Document dom = builder.parse("cars.xml"); 

                PrintXmlDocument(dom); 
            } 
            catch (ParserConfigurationException pce) { 
                System.out.println(pce.getMessage()); 
            }  
            catch (SAXException se) { 
                System.out.println(se.getMessage()); 
            } 
            catch (IOException ioe) { 
                System.err.println(ioe.getMessage()); 
            } 
        } 
```

现在是时候检查我们的代码是否有效了。我们使用`DocumentBuilderFactory`类的静态方法获取了`DocumentBuilderFactory`对象，并创建了一个全新的实例。通过`DocumentBuilderFactory`，我们创建了一个新的`DocumentBuilder`对象，它将能够智能地解析我们的 XML 文件。在解析我们的 XML 文件时，`DocumentBuilder`对象了解其中包含的信息的性质，并能够将其存储在我们的 XML 文档或`Document`对象模型元素中。当我们运行这个程序时，我们会得到原始 XML 文档的文本视图作为输出：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/96ce926c-1c7d-4208-8372-e8f3e4917da1.png)

由于加载这样的 XML 文件有很多步骤，我想将其放在自己的部分中。这样，当我们作为程序员学习如何从 XML 中操作和读取有价值的信息时，我们不会被我们在这里看到的所有语法所困扰。

# 解析 XML 数据

`Document`类为我们提供了一种简单的方法来在对象中存储格式化的信息。在前面部分的程序中，我们从`cars.xml`文件中读取信息到我们的 Java `Document`对象中。`cars.xml`文件如下所示：

```java
<?xml version="1.0"?> 
<cars> 
    <owner name="Billy"> 
        <car vin="LJPCBLCX11000237"> 
            <make>Ford</make> 
            <model>Fusion</model> 
            <year>2014</year> 
            <color>Blue</color> 
        </car> 
        <car vin="LGHIALCX89880011"> 
            <make>Toyota</make> 
            <model>Tacoma</model> 
            <year>2013</year> 
            <color>Green</color> 
        </car> 
        <car vin="GJSIALSS22000567"> 
            <make>Dodge</make> 
            <model>Charger</model> 
            <year>2013</year> 
            <color>Red</color> 
        </car> 
    </owner> 
    <owner name="Jane"> 
        <car vin="LLOKAJSS55548563"> 
            <make>Nissan</make> 
            <model>Altima</model> 
            <year>2000</year> 
            <color>Green</color> 
        </car> 
        <car vin="OOKINAFS98111001"> 
            <make>Dodge</make> 
            <model>Challenger</model> 
            <year>2013</year> 
            <color>Red</color> 
        </car> 
    </owner> 
</cars> 
```

这个文件的根节点是`cars`节点，这个节点中包含两个`owner`节点，即 Billy 和 Jane，每个节点中都有一些`car`节点。这些`car`元素中存储的信息与我们之前的 Java 类中可以存储的信息相对应。

本节的目标是从`cars.xml`中获取特定所有者（在本例中是 Jane）的汽车信息，并将这些信息存储在我们自定义的`Car`类中，以便我们可以利用`Car`类的`toString()`重写以以良好格式的方式将 Jane 的所有汽车打印到我们的控制台上。

通过我们已经设置的代码，我们的`Document`对象`dom`以相同的格式反映了`cars.xml`中存储的信息，所以我们只需要弄清楚如何询问这个`Document`对象这个问题：Jane 拥有什么车？为了弄清楚如何编写代码，你需要了解一些关于 XML 术语的知识。在本节中，我们将处理术语“元素”和“节点”。

在 XML 中，**元素**是一个具有开始和结束标记的实体，它还包含其中的所有信息。当我们的`Document`对象返回信息时，通常会以节点的形式返回信息。**节点**是 XML 文档的构建块，我们几乎可以将它们视为继承关系，其中所有元素都是节点，但并非所有节点都是元素。节点可以比整个 XML 元素简单得多。

# 访问 Jane 的 XML 元素

本节将帮助我们访问关于 Jane 拥有的汽车的信息，使用以下代码。我已将要添加到我们的`main()`函数中的代码分为六部分：

1.  因此，在寻找 Jane 拥有的所有汽车的过程中，让我们看看我们的 XML 文档在一开始为我们提供了哪些功能。如果我们通过代码补全快速扫描我们的方法列表，我们可以从我们的`Document`实例中调用`dom`。我们将看到`getDocumentElement()`方法为我们返回一个元素：![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/3e2462a0-5917-4b88-93da-b4d3a49a4e49.png)

这可能是一个很好的开始方式。这个方法返回我们的 XML 中的顶层元素；在这种情况下，我们将得到`cars`元素，其中包含了我们需要的所有信息。它还包含一些我们不需要的信息，比如 Billy 的车，但在我们访问之后我们会解析出来。一旦我们导入了正确的库，我们就可以直接在我们的代码中引用 XML 元素的概念，使用`Element`类。我们可以创建一个新的`Element`对象，并将其值分配给我们的 XML 文档的根元素：

```java
        Element doc = dom.getDocumentElement(); 
```

当然，我们需要更深入。我们的 XML 文档`cars`的根级别对我们来说并不直接有用；我们需要其中包含的信息。我们只真正想要一个`owner`节点的信息（包含关于 Jane 的车的信息）。但由于 XML 解析的方式，我们可能最好先获取这两个所有者节点，然后找到我们真正感兴趣的那个。

为了获取这两个节点，我们可以在我们刚刚创建并存储在`doc`中的根 XML 元素上调用一个方法。XML 元素可以包含其中的其他元素；在这种情况下，我们的根元素包含了许多`owner`元素。`getElementsByTagName()`方法允许我们收集这些内部元素的数量。XML 元素的标签名就是你所期望的；它是我们给我们的 XML 的特定元素的名称。在这种情况下，如果我们要求在我们文档的根元素中包含的所有标签名为`owner`的元素，我们将进一步缩小我们正在处理的 XML 的数量，接近我们所需的小节。

`getElementsByTagName()`方法返回的不是单个元素。即使在最高级别的这一部分中也有两个不同的元素，即两个所有者：`Billy`和`Jane`。因此，`getElementsByTagLineName()`方法不返回单个元素；而是返回一个`NodeList`对象，它是 XML 节点的集合。

```java
        NodeList ownersList = doc.getElementsByTagName("owner"); 
```

现在我们根本不再处理我们的根节点；我们只有它的内容。是时候真正地缩小我们的搜索范围了。我们的`NodeList`对象包含多个所有者，但我们只想要一个所有者，如果与该所有者相关联的属性名称恰好是`Jane`。为了找到这个特定的元素（如果存在的话），我们只需循环遍历`NodeList`，检查它包含的每个元素的属性。请注意，`ownersList`不是传统数组。它是一个`NodeList`对象，是它自己的一种对象。因此，我们不能在其上使用正常的数组语法。幸运的是，它向我们提供了模仿正常数组语法的方法。例如，`getLength()`方法将告诉我们`ownersList`中有多少个对象：

```java
        for(int i = 0; i < ownersList.getLength(); i++) 
        { 
        } 
```

1.  同样，当我们尝试创建一个新的`Element`对象并将该值分配给当前循环遍历的`ownersList`部分时，我们将无法使用数组的正常语法。不过，`ownersList`再次为我们提供了一个执行相同操作的方法。`item()`方法提供或要求一个索引作为输入。

请注意，`ownersList`是`NodeList`，但是元素是节点，不是所有节点都是元素，因此我们需要在这里做出决定。我们可以检查此函数返回的对象的性质，并确保它们实际上是 XML 元素。但为了保持事情的进行，我们只是假设我们的 XML 格式正确，并且我们只是让 Java 知道`item()`方法返回的节点实际上是一个元素；也就是说，它有一个开始标签和一个结束标签，并且可以包含其他元素和节点：

```java
            Element owner = (Element)ownersList.item(i); 
```

一旦我们成功地从所有者列表中访问了一个元素，现在是时候检查并看看这是否是我们正在寻找的所有者；因此，我们将需要一个条件语句。XML 元素向我们公开了`getAttribute()`方法，我们感兴趣的属性是`name`属性。因此，这里的代码将询问当前的`owner`，“你的`name`属性的值是多少？”如果该值等于`Jane`，那么我们知道我们已经访问了正确的 XML 元素。

现在在简的 XML 元素中，我们只有一些`car`元素。所以，再次是时候创建`NodeList`并用这些`car`元素填充它。我们现在需要在我们当前的所有者简上调用`getElementByTagName()`方法。如果我们使用顶层文档来调用这个函数，我们将得到文档中的所有`car`元素，甚至是比利的：

```java
            if(owner.getAttribute("name").equals("Jane")) 
            { 
                NodeList carsList = 
                owner.getElementsByTagName("car"); 
```

1.  这个`main()`方法变得有点复杂；这是我愿意在一个方法中做到的极限。我们的代码已经深入了几个层次，我们写的代码并不简单。我认为是时候将下一部分解析成自己的方法了。让我们简单地声明我们将要有一个`PrintCars()`方法，这个函数将接受`car`元素的`NodeList`来打印汽车节点：

```java
        PrintCars(carsList); 
```

我们的`main`方法现在如下所示：

```java
        public static void main(String[] args) { 
            DocumentBuilderFactory factory = 
            DocumentBuilderFactory.newInstance(); 
            try { 
                DocumentBuilder docBuilder = 
                factory.newDocumentBuilder(); 
                Document dom = docBuilder.parse("cars.xml"); 

                // Now, print out all of Jane's cars 
                Element doc = dom.getDocumentElement(); 
                NodeList ownersList = 
                doc.getElementsByTagName("owner"); 

                for(int i = 0; i < ownersList.getLength(); i++) 
                { 
                    Element owner = (Element)ownersList.item(i); 
                    if(owner.getAttribute("name").equals("Jane")) 
                    { 
                        NodeList carsList = 
                        owner.getElementsByTagName("car"); 
                        PrintCars(carsList); 
                    } 
                } 
            } 
            catch (ParserConfigurationException pce) { 
                System.out.println(pce.getMessage()); 
            }  
            catch (SAXException se) { 
                System.out.println(se.getMessage()); 
            }  
            catch (IOException ioe) { 
                System.err.println(ioe.getMessage()); 
            } 
        } 
```

# 打印简的汽车详情

现在，离开我们的`main()`方法，我们将定义我们的新的`PrintCars()`方法。我已经将`PrintCars()`函数的定义分成了八个部分：

1.  因为我们在程序的入口类中，`PrintCars()`方法是由静态的`main()`方法调用的，它可能应该是一个`static`函数。它将只是打印到我们的控制台，所以`void`是一个合适的返回类型。我们已经知道它将接受汽车的`NodeList`作为输入：

```java
        public static void PrintCars(NodeList cars) 
        { 
        } 
```

1.  一旦我们进入了这个函数，我们知道我们可以使用`car` XML 元素的列表。但为了打印出每一个，我们需要循环遍历它们。我们已经在程序中循环遍历了 XML 的`NodeList`，所以我们将使用一些非常相似的语法。让我们看看这个新代码需要改变什么。好吧，我们不再循环遍历`ownersList`；我们有一个新的`NodeList`对象来循环遍历`cars`的`NodeList`：

```java
        for(int i = 0; i < cars.getLength(); i++) 
        { 
        } 
```

1.  我们知道汽车仍然是`Element`实例，所以我们的强制转换仍然是合适的，但我们可能想要将我们用于循环遍历每辆汽车的变量重命名为类似`carNode`的东西。每次我们循环遍历一辆车时，我们将创建一个新的`Car`对象，并将该车的 XML 中的信息存储在这个实际的 Java 对象中：

```java
        Element carNode = (Element)cars.item(i); 
```

1.  因此，除了访问`car` XML，让我们也声明一个`Car`对象，并将其实例化为一个新的`Car`对象：

```java
        Car carObj = new Car(); 
```

1.  现在我们将通过从`carNode`中读取它们来构建存储在`carObj`中的值。如果我们快速跳回 XML 文件并查看存储在`car`元素中的信息，我们将看到它存储了`make`，`model`，`year`和`color`作为 XML 节点。车辆识别号`vin`实际上是一个属性。让我们简要看一下我们的`Car.java`类：

```java
        package readingxml; 

        public class Car { 
            public String vin; 
            public String make; 
            public String model; 
            public int year; 
            public String color; 
            public Car() 
            { 

            } 
            @Override 
            public String toString() 
            { 
                return String.format("%d %s %s %s, vin:%s", year, 
                color, make, model, vin); 
            } 
        } 
```

让我们先从简单的部分开始；所以，`make`，`model`和`color`都是存储在`Car`类中的字符串，它们恰好都是`car`元素内的节点。

回到我们的`PrintCars()`函数，我们已经知道如何访问元素内的节点。我们只需要再次使用`carNode`和`getElementsByTagName()`函数。如果我们获取所有标签名为`color`的元素，我们应该会得到一个只包含一个元素的列表，这个元素就是我们感兴趣的，告诉我们汽车颜色的元素。不幸的是，我们在这里有一个列表，所以我们不能直接操作该元素，直到我们从列表中取出它。不过，我们知道如何做到这一点。如果我们确信我们的 XML 格式正确，我们知道我们将获得一个只包含一个项目的列表。因此，如果我们获取该列表的第 0 个索引处的项目，那将是我们要找的 XML 元素。

存储在这个 XML 元素中的颜色信息不是一个属性，而是内部文本。因此，我们将查看 XML 元素公开的方法，看看是否有一个合适的方法来获取内部文本。有一个`getTextContent()`函数，它将给我们所有的内部文本，这些文本实际上不是 XML 元素标签的一部分。在这种情况下，它将给我们我们汽车的颜色。

获取这些信息还不够；我们需要存储它。幸运的是，`carObj`的所有属性都是公共的，所以我们可以在创建`car`对象后自由地为它们赋值。如果这些是私有字段而没有 setter，我们可能需要在构造`carObj`之前进行这些信息，然后通过它们传递给它希望有的构造函数。

```java
        carObj.color = 
        carNode.getElementsByTagName("color").item(0).getTextContent(); 
```

我们将为`make`和`model`做几乎完全相同的事情。我们唯一需要改变的是我们在查找元素时提供的关键字。

```java
        carObj.make = 
        carNode.getElementsByTagName("make").item(0).getTextContent(); 
        carObj.model = 
        carNode.getElementsByTagName("model").item(0).getTextContent(); 
```

1.  现在，我们可以继续使用相同的一般策略来处理我们车辆的`year`，但是我们应该注意，就`carObj`而言，`year`是一个整数。就我们的 XML 元素而言，`year`，就像其他任何东西一样，是一个`TextContent`字符串。幸运的是，将一个`string`转换为一个`integer`，只要它格式良好，这是一个我们在这里将做出的假设，不是太困难。我们只需要使用`Integer`类并调用它的`parseInt()`方法。这将尽力将一个字符串值转换为一个整数。我们将把它赋给`carObj`的`year`字段。

```java
        carObj.year = 
        Integer.parseInt(carNode.getElementsByTagName
        ("year").item(0).getTextContent()); 
```

1.  这样我们就只剩下一个字段了。注意`carObj`有一个车辆识别号字段。这个字段实际上不是一个整数；车辆识别号可以包含字母，所以这个值被存储为一个字符串。我们获取它会有一点不同，因为它不是一个内部元素，而是`car`元素本身的一个属性。我们再次知道如何从`carNode`获取属性；我们只是要获取名称为`vin`的属性并将其赋给`carObj`。

```java
         carObj.vin = carNode.getAttribute("vin"); 
```

1.  完成所有这些后，我们的`carObj`对象应该在所有成员中具有合理的值。现在是时候使用`carObj`存在的原因了：重写`toString()`函数。对于我们循环遍历的每辆车，让我们调用`carObj`的`toString()`函数，并将结果打印到控制台上。

```java
        System.out.println(carObj.toString()); 
```

我们的`PrintCars()`函数现在将如下所示：

```java
public static void PrintCars(NodeList cars) 
{ 
    for(int i = 0; i < cars.getLength(); i++) 
    { 
        Element carNode = (Element)cars.item(i); 
        Car carObj = new Car(); 
        carObj.color = 
         carNode.getElementsByTagName
         ("color").item(0).getTextContent(); 
        carObj.make = 
         carNode.getElementsByTagName
         ("make").item(0).getTextContent(); 
        carObj.model = carNode.getElementsByTagName
         ("model").item(0).getTextContent(); 
        carObj.year = 
         Integer.parseInt(carNode.getElementsByTagName
         ("year").item(0).getTextContent()); 
        carObj.vin = carNode.getAttribute("vin"); 
        System.out.println(carObj.toString()); 
    } 
} 
```

我们应该可以编译我们的程序了。现在当我们运行它时，希望它会打印出简的所有汽车，利用`carObj`的重写`toString()`方法，来很好地格式化输出。当我们运行这个程序时，我们得到两辆汽车作为输出，如果我们去我们的 XML 并查看分配给简的汽车，我们会看到这些信息确实与存储在这些汽车中的信息相匹配。

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/4d51007d-148e-44a8-a834-c655dd9fa7aa.png)

XML 和 Java 的组合真的非常强大。XML 是人类可读的。我们可以理解它，甚至可以对其进行修改，但它也包含了非常有价值的结构化信息。这是编程语言（如 Java）也能理解的东西。我们在这里编写的程序虽然有其特点，并且需要一定的知识来编写，但比起从原始文本文件中编写类似程序，它要容易得多，程序员也更容易理解和维护。

# 编写 XML 数据

能够读取 XML 信息当然很好，但是为了使语言对我们真正有用，我们的 Java 程序可能也需要能够写出 XML 信息。以下程序是一个从同一 XML 文件中读取和写入的程序的基本模型：

```java
package writingxml; 

import java.io.*; 
import javax.xml.parsers.*; 
import javax.xml.transform.*; 
import javax.xml.transform.dom.*; 
import javax.xml.transform.stream.*; 
import org.w3c.dom.*; 
import org.xml.sax.*; 

public class WritingXML { 
    public static void main(String[] args) { 
        File xmlFile = new File("cars.xml"); 
        Document dom = LoadXMLDocument(xmlFile);       
        WriteXMLDocument(dom, xmlFile); 
    } 

    private static void WriteXMLDocument
     (Document doc, File destination) 
    { 
        try{ 
            // Write doc to destination file here... 
        } 
        catch(TransformerConfigurationException e) 
        { 
            System.err.println("XML writing failed."); 
        } 
        catch(TransformerException e) 
        { 
            System.err.println("XML writing failed."); 
        } 
    } 

    private static Document LoadXMLDocument(File source) 
    { 
        try { 
            DocumentBuilderFactory factory = 
             DocumentBuilderFactory.newInstance(); 
            DocumentBuilder builder = 
             factory.newDocumentBuilder(); 
            Document dom = builder.parse(source); 
        } 
        catch (ParserConfigurationException e) { 
             System.err.println("XML loading failed."); 
        } 
        catch (SAXException e) { 
             System.err.println("XML loading failed."); 
        } 
        catch (IOException e) { 
            System.err.println("XML loading failed."); 
        } 

        return dom; 
    } 
} 
```

它的`main()`方法非常简单。它接受一个文件，然后从该文件中读取 XML，将其存储在 XML 文档的树对象中。然后，该程序调用`WriteXMLDocument()`将 XML 写回同一文件。目前，用于读取 XML 的方法已经为我们实现（`LoadXMLDocument()`）；然而，用于写出 XML 的方法尚未完成。让我们看看我们需要为我们写入 XML 信息到文档发生什么。我已将`WriteXMLDocument()`函数的代码分为四个部分。

# 用于编写 XML 数据的 Java 代码

编写 XML 数据需要执行以下步骤：

1.  由于 XML 文档的存储方式，我们需要将其转换为不同的格式，然后才能真正将其以与原始 XML 相同的格式打印到文件中。为此，我们将使用一个名为`Transformer`的专用于 XML 的类。与处理文档模型中的许多类一样，最好使用工厂来创建`Transformer`实例。在这种情况下，工厂称为`TransformerFactory`，像许多工厂一样，它公开了`newInstance()`方法，允许我们在需要时创建一个。要获取我们的新`Transformer`对象，它将允许我们将我们的`Document`对象转换为可发送到文件的流的东西，我们只需调用`TransformerFactory`的`newTransformer()`方法：

```java
        TransformerFactory tf = TransformerFactory.newInstance(); 
        Transformer transformer = tf.newTransformer(); 
```

1.  现在，在`Transformer`可以将我们的 XML 文档转换为其他内容之前，它需要知道我们希望它将我们当前`Document`对象的信息转换为什么。这个类就是`StreamResult`类；它是存储在我们当前`Document`对象中的信息的目标。流是一个原始的二进制信息泵，可以发送到任意数量的目标。在这种情况下，我们的目标将是提供给`StreamResult`构造函数的目标文件：

```java
        StreamResult result = new StreamResult(destination); 
```

1.  我们的`Transformer`对象并不会自动链接到我们的 XML 文档，它希望我们以唯一的方式引用我们的 XML 文档：作为`DOMSource`对象。请注意，我们的`source`对象（接下来定义）正在与`result`对象配对。当我们向`Transformer`对象提供这两个对象时，它将知道如何将一个转换为另一个。现在，要创建我们的`DOMSource`对象，我们只需要传入我们的 XML 文档：

```java
        DOMSource source = new DOMSource(doc); 
```

1.  最后，当所有设置完成后，我们可以执行代码的功能部分。让我们获取我们的`Transformer`对象，并要求它将我们的源（即`DOMSource`对象）转换为一个流式结果，目标是我们的目标文件：

```java
         transformer.transform(source, result); 
```

以下是我们的`WriteXMLDocument()`函数：

```java
private static void WriteXMLDocument
(Document doc, File destination) 
{ 
    try{ 
        // Write doc to destination file here 
        TransformerFactory tf = 
         TransformerFactory.newInstance(); 
        Transformer transformer = tf.newTransformer(); 
        StreamResult result = new StreamResult(destination); 
        DOMSource source = new DOMSource(doc); 

        transformer.transform(source, result); 
    } 
    catch(TransformerConfigurationException e) 
    { 
        System.err.println("XML writing failed."); 
    } 
    catch(TransformerException e) 
    { 
        System.err.println("XML writing failed."); 
    } 
} 
```

当我们运行这个程序时，我们将在文件中得到一些 XML，但是当我说这是我们之前拥有的相同的 XML 时，你必须相信我，因为我们首先读取 XML，然后将其作为结果打印回去。

为了真正测试我们的程序是否工作，我们需要在 Java 代码中对我们的`Document`对象进行一些更改，然后看看我们是否可以将这些更改打印到这个文件中。让我们改变汽车所有者的名字。让我们将所有汽车的交易转移到一个名叫 Mike 的所有者名下。

# 修改 XML 数据

XML I/O 系统的强大之处在于在加载和写入 XML 文档之间，我们可以自由修改存储在内存中的`Document`对象`dom`。而且，我们在 Java 内存中对对象所做的更改将被写入我们的永久 XML 文件。所以让我们开始做一些更改：

1.  我们将使用`getElementsByTagName()`来获取我们的 XML 文档中的所有`owner`元素。这将返回一个`NodeList`对象，我们将称之为`owners`：

```java
        NodeList owners = dom.getElementsByTagName("owner"); 
```

1.  为了将所有这些所有者的名字转换为`Mike`，我们需要遍历这个列表。作为复习，我们可以通过调用`owners`的`getLength()`函数来获取列表中的项目数，也就是我们的`NodeList`对象。要访问我们当前正在迭代的项目，我们将使用`owners`的`item()`函数，并传入我们的迭代变量`i`来获取该索引处的项目。让我们将这个值存储在一个变量中，以便我们可以轻松使用它；再次，我们将假设我们的 XML 格式良好，并告诉 Java，事实上，我们正在处理一个完全成熟的 XML 元素。

接下来，XML 元素公开了许多允许我们修改它们的方法。其中一个元素是`setAttribute()`方法，这就是我们将要使用的方法。请注意，`setAttribute()`需要两个字符串作为输入。首先，它想知道我们想要修改哪个属性。我们将要修改`name`属性（这是我们这里唯一可用的属性），并且我们将把它的值赋给`Mike`：

```java
            for(int i = 0; i < owners.getLength(); i++) 
            { 
                Element owner = (Element)owners.item(i); 
                owner.setAttribute("name", "Mike"); 
            } 
```

现在我们的`main()`方法将如下所示：

```java
public static void main(String[] args) { 
    File xmlFile = new File("cars.xml"); 
    Document dom = LoadXMLDocument(xmlFile); 

    NodeList owners = dom.getElementsByTagName("owner"); 
    for(int i = 0; i < owners.getLength(); i++) 
    { 
        Element owner = (Element)owners.item(i); 
        owner.setAttribute("name", "Mike"); 
    } 
    WriteXMLDocument(dom, xmlFile); 
} 
```

当我们运行程序并检查我们的 XML 文件时，我们将看到`Mike`现在是所有这些汽车的所有者，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/fe46f87a-5603-44b1-89f4-7c2826e14c0a.png)

现在可能有意义将这两个 XML 元素合并，使`Mike`只是一个所有者，而不是分成两个。这有点超出了本节的范围，但这是一个有趣的问题，我鼓励你反思一下，也许现在就试一试。

# 总结

在本章中，我们看到了将 XML 文件读入`Document`对象的 Java 代码。我们还看到了如何使用 Java 解析 XML 数据。最后，我们看到了如何在 Java 中编写和修改 XML 数据。

恭喜！你现在是一个 Java 程序员。
