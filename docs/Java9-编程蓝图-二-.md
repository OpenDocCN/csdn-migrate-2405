# Java9 编程蓝图（二）

> 原文：[`zh.annas-archive.org/md5/EFCA429E6A8AD54477E9BBC3A0DA41BA`](https://zh.annas-archive.org/md5/EFCA429E6A8AD54477E9BBC3A0DA41BA)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：日期计算器

如果你在 Java 中有任何严肃的开发经验，你会知道一件事是真实的——处理日期是糟糕的。`java.util.Date`类及其相关类是在 1.0 版中发布的，`Calendar`及其相关类是在 1.1 版中发布的。甚至在早期，问题就已经显现出来。例如，`Date`的 Javadoc 上说——*不幸的是，这些函数的 API 不适合国际化*。因此，`Calendar`在 1.1 版中被引入。当然，多年来还有其他的增强，但考虑到 Java 对向后兼容性的严格遵守，语言架构师们能做的只有那么多。尽管他们可能想要修复这些 API，但他们的手是被捆绑的。

幸运的是，**Java 规范请求**（**JSR 310**）已经提交。由 Stephen Colebourne 领导，开始了一个努力创建一个新的 API，基于非常流行的开源库 Joda-Time。在本章中，我们将深入研究这个新的 API，然后构建一个简单的命令行实用程序来执行日期和时间计算，这将让我们有机会看到这个 API 的一些实际应用。

因此，本章将涵盖以下主题：

+   Java 8 日期/时间 API

+   重新审视命令行实用程序

+   文本解析

# 入门

就像第二章中的项目，*在 Java 中管理进程*，这个项目在概念上是相当简单的。最终目标是创建一个命令行实用程序来执行各种日期和时间计算。然而，在此过程中，如果实际的日期/时间工作能够被放入一个可重用的库中，那将是非常好的，所以我们将这样做。这给我们留下了两个项目，我们将像上次一样设置为多模块 Maven 项目。

父 POM 将看起来像这样：

```java
    <?xml version="1.0" encoding="UTF-8"?> 
    <project 

      xsi:schemaLocation="http://maven.apache.org/POM/4.0.0
      http://maven.apache.org/xsd/maven-4.0.0.xsd"> 
      <modelVersion>4.0.0</modelVersion> 

      <artifactId>datecalc-master</artifactId> 
      <version>1.0-SNAPSHOT</version> 
      <packaging>pom</packaging> 
      <modules> 
        <module>datecalc-lib</module> 
        <module>datecalc-cli</module> 
      </modules> 
    </project> 

```

如果你读过第二章，*在 Java 中管理进程*，或者之前有过多模块 Maven 构建的经验，这里没有什么新的。这只是为了完整性而包含在内。如果这对你来说是陌生的，请花点时间在继续之前回顾第二章的前几页。

# 构建库

由于我们希望能够在其他项目中重用这个工具，我们将首先构建一个公开其功能的库。我们需要的所有功能都内置在平台中，因此我们的 POM 文件非常简单：

```java
    <?xml version="1.0" encoding="UTF-8"?> 
    <project 

      xsi:schemaLocation="http://maven.apache.org/POM/4.0.0
      http://maven.apache.org/xsd/maven-4.0.0.xsd"> 
      <modelVersion>4.0.0</modelVersion> 
      <parent> 
        <groupId>com.steeplesoft</groupId> 
          <artifactId>datecalc-master</artifactId> 
          <version>1.0-SNAPSHOT</version> 
      </parent> 
      <artifactId>datecalc-lib</artifactId> 
      <packaging>jar</packaging> 
      <dependencies> 
        <dependency> 
          <groupId>org.testng</groupId> 
          <artifactId>testng</artifactId> 
          <version>6.9.9</version> 
          <scope>test</scope> 
        </dependency> 
      </dependencies> 
    </project> 

```

几乎没有外部依赖。唯一列出的依赖是测试库 TestNG。在上一章中我们没有谈论太多关于测试（请放心，项目中有测试）。在本章中，我们将介绍测试的主题并展示一些例子。

现在我们需要定义我们的模块。请记住，这些是 Java 9 项目，所以我们希望利用模块功能来帮助保护我们的内部类不被意外公开。我们的模块非常简单。我们需要给它一个名称，然后导出我们的公共 API 包，如下所示：

```java
    module datecalc.lib { 
      exports com.steeplesoft.datecalc; 
    } 

```

由于我们需要的一切都已经在 JDK 中，我们没有什么需要声明的，除了我们导出的内容。

有了我们的项目设置，让我们快速看一下功能需求。我们这个项目的目的是构建一个系统，允许用户提供一个表示日期或时间计算表达式的任意字符串，并得到一个响应。这个字符串可能看起来像`"today + 2 weeks"`，以找出从今天开始的 2 周后的日期，`"now + 3 hours 15 minutes"`，以找出 3 小时 15 分钟后的时间，或者`"2016/07/04 - 1776/07/04"`，以找出两个日期之间的年、月和天数。这些表达式的处理将一次处理一行，因此明确排除了传入多个表达式的文本文档并得到多个结果的能力。当然，任何消费应用程序或库都可以很容易地实现这一点。

现在，我们已经设置好了一个项目，并且准备好了，我们对其相当简单的功能需求有一个大致的草图。我们准备开始编码。在这之前，让我们快速浏览一下新的`java.time`包，以更好地了解我们将在这个项目中看到的内容，以及我们在这个简单项目中**不会**使用的一些功能。

# 及时的插曲

在 Java 8 之前，两个主要的日期相关类是`Date`和`Calendar`（当然还有`GregorianCalendar`）。新的`java.time`包提供了几个新类，如`Duration`、`Period`、`Clock`、`Instant`、`LocalDate`、`LocalTime`、`LocalDateTime`和`ZonedDateTime`。还有大量的支持类，但这些是主要的起点。让我们快速看一下每一个。

# 持续时间

`Duration`是一个**基于时间的时间单位**。虽然用这种方式来表达可能听起来有点奇怪，但选择这种措辞是为了区分它与基于日期的时间单位，我们将在下面看到。简单来说，它是时间的度量，比如**10 秒**、**1 小时**或**100 纳秒**。`Duration`以秒为单位，但有许多方法可以以其他度量单位表示持续时间，如下所示：

+   `getNano()`: 这是以纳秒为单位的`Duration`

+   `getSeconds()`: 这是以秒为单位的`Duration`

+   `get(TemporalUnit)`: 这是以指定的度量单位为单位的`Duration`

还有各种算术方法，如下所述：

+   `add`/`minus (int amount, TemporalUnit unit)`

+   `add`/`minus (Duration)`

+   `addDays`/`minusDays(long)`

+   `addHours`/`minusHours(long)`

+   `addMillis`/`minusMillis(long)`

+   `addMinutes`/`minusMinutes(long)`

+   `addNanos`/`minusNanos(long)`

+   `addSeconds`/`minusSeconds(long)`

+   `dividedBy`/`multipliedBy`

我们还有许多方便的工厂和提取方法，如下所示：

+   `ofDays(long)`/`toDays()`

+   `ofHours(long)`/`toHours()`

+   `ofMinutes(long)`/`toMinutes()`

+   `ofSeconds(long)`/`toSeconds()`

还提供了一个`parse()`方法。不幸的是，对于一些人来说，这个方法的输入可能不是你所期望的。因为我们通常处理的是以小时和分钟为单位的持续时间，你可能期望这个方法接受类似于"1:37"的输入，表示 1 小时 37 分钟。然而，这将导致系统抛出`DateTimeParseException`。这个方法期望接收的是一个 ISO-8601 格式的字符串，看起来像这样--`PnDTnHnMn.nS`。这很棒，不是吗？虽然一开始可能会有点困惑，但一旦你理解了它，就不会太糟糕：

+   第一个字符是可选的`+`（加号）或`-`（减号）符号。

+   下一个字符是`P`，可以是大写或小写。

+   接下来是至少四个部分中的一个，表示天（`D`）、小时（`H`）、分钟（`M`）和秒（`S`）。再次强调，大小写不重要。

+   它们必须按照这个顺序声明。

+   每个部分都有一个数字部分，包括一个可选的`+`或`-`符号，一个或多个 ASCII 数字，以及度量单位指示符。秒数可能是分数（表示为浮点数），可以使用句点或逗号。

+   字母`T`必须出现在小时、分钟或秒的第一个实例之前。

简单吧？对于非技术人员来说可能不太友好，但它支持以字符串编码持续时间，允许无歧义地解析，这是一个巨大的进步。

# 期间

`Period`是一个基于日期的时间单位。而`Duration`是关于时间（小时、分钟、秒等）的，`Period`是关于年、周、月等的。与`Duration`一样，它公开了几种算术方法来添加和减去，尽管这些方法处理的是年、月和日。它还提供了`plus(long amount, TemporalUnit unit)`（以及相应的`minus`）。

此外，就像`Duration`一样，`Period`有一个`parse()`方法，它也采用 ISO-8601 格式，看起来像这样--`PnYnMnD`和`PnW`。根据前面的讨论，结构可能是相当明显的：

+   字符串以一个可选的符号开头，后面跟着字母`P`。

+   在第一种形式之后，有三个部分，至少一个必须存在--年（`Y`）、月（`M`）和日（`D`）。

+   对于第二种形式，只有一个部分--周（`W`）。

+   每个部分的金额可以有正数或负数的符号。

+   `W`单位不能与其他单位组合在一起。在内部，金额乘以`7`并视为天数。

# 时钟

`Clock`是一个抽象类，它提供了使用时区的当前时刻（我们将在下面看到），日期和时间的访问。在 Java 8 之前，我们需要调用`System.currentTimeInMillis()`和`TimeZone.getDefault()`来计算这些值。`Clock`提供了一个很好的接口，可以从一个对象中获取这些值。

Javadoc 声明使用`Clock`纯粹是可选的。事实上，主要的日期/时间类有一个`now()`方法，它使用系统时钟来获取它们的值。然而，如果您需要提供一个替代实现（比如在测试中，您需要另一个时区的`LocalTime`），这个抽象类可以被扩展以提供所需的功能，然后可以传递给适当的`now()`方法。

# Instant

`Instant`是一个单一的、确切的时间点（或**在时间线上**，您会看到 Javadoc 说）。这个类提供了算术方法，就像`Period`和`Duration`一样。解析也是一个选项，字符串是一个 ISO-8601 的时间点格式，比如`1977-02-16T08:15:30Z`。

# LocalDate

`LocalDate`是一个没有时区的日期。虽然这个类的值是一个日期（年、月和日），但是还有其他值的访问器方法，如下所示：

+   `getDayOfWeek()`: 这返回日期表示的星期几的`DayOfWeek`枚举。

+   `getDayOfYear()`: 这返回日期表示的一年中的日子（1 到 365，或闰年的 366）。这是从指定年份的 1 月 1 日开始的基于 1 的计数器。

+   `getEra()`: 这返回给定日期的 ISO 纪元。

当然，本地日期可以从字符串中解析，但是，这一次，格式似乎更加合理--`yyyy-mm-dd`。如果您需要不同的格式，`parse()`方法已经被重写，允许您指定可以处理字符串格式的`DateTimeFormatter`。

# LocalTime

`LocalTime`是`LocalDate`的基于时间的等价物。它存储`HH:MM:SS`，但**不**存储时区。解析时间需要上面的格式，但是，就像`LocalDate`一样，允许您指定一个`DateTimeFormatter`来表示替代字符串。

# LocalDateTime

`LocalDateTime`基本上是最后两个类的组合。所有的算术、工厂和提取方法都按预期应用。解析文本也是两者的组合，只是`T`必须分隔字符串的日期和时间部分--`'2016-01-01T00:00:00'`。这个类**不**存储或表示时区。

# ZonedDateTime

如果您需要表示日期/时间**和**时区，那么`ZonedDateTime`就是您需要的类。正如您可能期望的那样，这个类的接口是`LocalDate`和`LocalTime`的组合，还增加了处理时区的额外方法。

正如在持续时间 API 的概述中所展示的（并且在其他类中也有所暗示，尽管没有那么清楚地显示），这个新 API 的一个强大之处是能够在数学上操作和处理各种日期和时间工件。正是这个功能，我们将在这个项目中花费大部分时间来探索这个新的库。

# 回到我们的代码

我们需要解决的过程的第一部分是将用户提供的字符串解析为我们可以在程序中使用的东西。如果您要搜索解析器生成器，您会发现有很多选择，Antlr 和 JavaCC 等工具通常排在前面。诱人的是转向其中一个工具，但我们这里的目的相当简单，语法并不复杂。我们的功能要求包括：

+   我们希望能够向日期或时间添加/减去时间

+   我们希望能够从另一个日期或时间中减去一个日期或时间，以获得两者之间的差异

+   我们希望能够将一个时区的时间转换为另一个时区

对于这样简单的东西，解析器太昂贵了，无论是在复杂性还是二进制大小方面。我们可以很容易地使用 JDK 内置的工具编写解析器，这就是我们将要做的。

在我们进入代码之前，我们的计划是这样的——我们将定义许多**令牌**来表示日期计算表达式的逻辑部分。使用正则表达式，我们将分解给定的字符串，返回这些令牌的列表，然后按**从左到右**的顺序处理以返回结果。

话虽如此，让我们列出我们需要的令牌类型。我们需要一个日期，一个时间，操作符，任何数字金额，度量单位和时区。显然，我们不需要每个表达式中的每一个，但这应该涵盖我们所有给定的用例。

让我们从我们的令牌的基类开始。在定义类型层次结构时，询问是否需要基类或接口总是一个好主意。使用接口可以使开发人员在需要扩展不同类时对类层次结构具有额外的灵活性。然而，基类允许我们以一定的类型层次结构提供默认行为。为了使我们的`Token`实现尽可能简单，我们希望尽可能多地将其放在基类中，因此我们将使用如下的基类：

```java
    public abstract class Token<T> {
      protected T value;
      public interface Info {
        String getRegex();
        Token getToken(String text);
      }
      public T getValue() {
        return value;
      }
    }

```

Java 8 确实引入了一种从接口提供默认行为的方法，即**默认方法**。默认方法是接口上提供具体实现的方法，这是与接口的重大变化。在这一变化之前，所有接口能做的就是定义方法签名并强制实现类定义方法体。这使我们能够向接口添加方法并提供默认实现，以便接口的现有实现无需更改。在我们的情况下，我们提供的行为是存储一个值（实例变量`value`）和它的访问器（`getValue()`），因此具有默认方法的接口不合适。

请注意，我们还定义了一个嵌套接口`Info`，我们将在解析器部分详细介绍。

有了我们定义的基类，我们现在可以创建我们需要的令牌，如下所示：

```java
    public class DateToken extends Token<LocalDate> { 
      private static final String TODAY = "today"; 
      public static String REGEX = 
        "\\d{4}[-/][01]\\d[-/][0123]\\d|today"; 

```

为了开始这个类，我们定义了两个常量。`TODAY`是一个特殊的字符串，我们将允许用户指定今天的日期。第二个是我们将用来识别日期字符串的正则表达式：

```java
    "\\d{4}[-/][01]\\d[-/][0123]\\d|today" 

```

众所周知，正则表达式很丑陋，就像这些东西一样，这个并不太复杂。我们匹配 4 位数字（`\\d{4}`），或者是-或/（`[-/]`），0 或 1 后面跟任意数字（`[01]\\d`），另一个-或/，然后是 0、1、2 或 3 后面跟任意数字。最后一部分`|today`告诉系统匹配前面的模式，**或**文本`today`。所有这些正则表达式能做的就是识别一个**看起来**像日期的字符串。在当前形式下，它实际上不能确保它是有效的。我们可能可以制作一个可以确保这一点的正则表达式，但是引入的复杂性是不值得的。不过，我们可以让 JDK 为我们验证字符串，这就是我们将在`of`方法中做的。

```java
    public static DateToken of(String text) { 
      try { 
        return TODAY.equals(text.toLowerCase()) ? 
          new DateToken(LocalDate.now()) : 
          new DateToken( 
            LocalDate.parse(text.replace("/", "-"))); 
      } catch (DateTimeParseException ex) { 
          throw new DateCalcException( 
            "Invalid date format: " + text); 
        } 
    } 

```

在这里，我们定义了一个静态方法来处理`DateToken`实例的创建。如果用户提供字符串`today`，我们提供值`LocalDate.now()`，这做了你认为它可能会做的事情。否则，我们将字符串传递给`LocalDate.parse()`，将任何斜杠更改为破折号，因为这是该方法所期望的。如果用户提供了无效的日期，但正则表达式仍然匹配了它，我们将在这里得到一个错误。由于我们内置了支持来验证字符串，我们可以满足于让系统为我们做繁重的工作。

其他标记看起来非常相似。与其展示每个类，其中大部分都会非常熟悉，我们将跳过大部分这些类，只看看正则表达式，因为有些非常复杂。看看以下代码：

```java
    public class IntegerToken extends Token<Integer> { 
      public static final String REGEX = "\\d+"; 

```

嗯，这个不算太糟糕，是吧？这里将匹配一个或多个数字：

```java
    public class OperatorToken extends Token<String> { 
      public static final String REGEX = "\\+|-|to"; 

```

另一个相对简单的，它将匹配+、-或`to`文本：

```java
    public class TimeToken extends Token<LocalTime> { 
      private static final String NOW = "now"; 
      public static final String REGEX = 
        "(?:[01]?\\d|2[0-3]):[0-5]\\d *(?:[AaPp][Mm])?|now"; 

```

正则表达式分解如下：

+   `(?:`：这是一个非捕获组。我们需要将一些规则组合在一起，但我们不希望它们在我们的 Java 代码中处理时显示为单独的组。

+   [01]?：这是 0 或 1。`?`表示这应该发生一次或根本不发生。

+   |2[0-3]：我们要么想匹配前半部分，**或**这一部分，它将是 2 后面跟着 0、1、2 或 3。

+   `)`: 这结束了非捕获组。这个组将允许我们匹配 12 或 24 小时制的时间。

+   `:`：这个位置需要一个冒号。它的存在是不可选的。

+   `[0-5]\\d`：接下来，模式必须匹配一个 0-5 后面跟着另一个数字。这是时间的分钟部分。

+   `' *'`: 很难看到，所以我添加了引号来帮助指示，但我们想匹配 0 个或更多个（由星号表示）空格。

+   `(?:`: 这是另一个非捕获组。

+   `[AaPp][Mm]`：这些是`A`或`P`字母（任何大小写）后面跟着一个`M`（也是任何大小写）。

+   ）：我们结束了非捕获组，但用`?`标记它，以指示它应该发生一次或根本不发生。这个组让我们捕获任何`AM`/`PM`指定。

+   |现在：与上面的 today 一样，我们允许用户指定此字符串以指示当前时间。

同样，这个模式可能匹配一个无效的时间字符串，但我们将让`LocalTime.parse()`在`TimeToken.of()`中为我们处理。

```java
    public static TimeToken of(final String text) { 
      String time = text.toLowerCase(); 
      if (NOW.equals(time)) { 
        return new TimeToken(LocalTime.now()); 
      } else { 
          try { 
            if (time.length() <5) { 
                time = "0" + time; 
            } 
            if (time.contains("am") || time.contains("pm")) { 
              final DateTimeFormatter formatter = 
                new DateTimeFormatterBuilder() 
                .parseCaseInsensitive() 
                .appendPattern("hh:mma") 
                .toFormatter(); 
                return new 
                TimeToken(LocalTime.parse( 
                  time.replaceAll(" ", ""), formatter)); 
            } else { 
                return new TimeToken(LocalTime.parse(time)); 
            } 
          } catch (DateTimeParseException ex) { 
              throw new DateCalcException( 
              "Invalid time format: " + text); 
            } 
        }
    } 

```

这比其他的要复杂一些，主要是因为`LocalTime.parse()`期望的默认格式是 ISO-8601 时间格式。通常，时间是以 12 小时制和上午/下午指定的。不幸的是，这不是 API 的工作方式，所以我们必须进行调整。

首先，如果需要，我们填充小时。其次，我们查看用户是否指定了`"am"`或`"pm"`。如果是这样，我们需要创建一个特殊的格式化程序，这是通过`DateTimeFormatterBuilder`完成的。我们首先告诉构建器构建一个不区分大小写的格式化程序。如果我们不这样做，"AM"将起作用，但"am"将不起作用。接下来，我们附加我们想要的模式，即小时、分钟和上午/下午，然后构建格式化程序。最后，我们可以解析我们的文本，方法是将字符串和格式化程序传递给`LocalTime.parse()`。如果一切顺利，我们将得到一个`LocalTime`实例。如果不行，我们将得到一个`Exception`实例，我们将处理它。请注意，我们在字符串上调用`replaceAll()`。我们这样做是为了去除时间和上午/下午之间的任何空格。否则，解析将失败。

最后，我们来到我们的`UnitOfMeasureToken`。这个标记并不一定复杂，但它肯定不简单。对于我们的度量单位，我们希望支持单词`year`、`month`、`day`、`week`、`hour`、`minute`和`second`，所有这些都可以是复数，大多数都可以缩写为它们的首字母。这使得正则表达式很有趣：

```java
    public class UnitOfMeasureToken extends Token<ChronoUnit> { 
      public static final String REGEX =
        "years|year|y|months|month|weeks|week|w|days|
         day|d|hours|hour|h|minutes|minute|m|seconds|second|s"; 
      private static final Map<String, ChronoUnit> VALID_UNITS = 
        new HashMap<>(); 

```

这并不是很复杂，而是很丑陋。我们有一个可能的字符串列表，由逻辑`OR`运算符竖线分隔。可能可以编写一个正则表达式来搜索每个单词，或者它的部分，但这样的表达式很可能很难编写正确，几乎肯定很难调试或更改。简单和清晰几乎总是比聪明和复杂更好。

这里还有一个需要讨论的最后一个元素：`VALID_UNITS`。在静态初始化程序中，我们构建了一个`Map`，以允许查找正确的`ChronoUnit`：

```java
    static { 
      VALID_UNITS.put("year", ChronoUnit.YEARS); 
      VALID_UNITS.put("years", ChronoUnit.YEARS); 
      VALID_UNITS.put("months", ChronoUnit.MONTHS); 
      VALID_UNITS.put("month", ChronoUnit.MONTHS); 

```

等等。

现在我们准备来看一下解析器，它如下所示：

```java
    public class DateCalcExpressionParser { 
      private final List<InfoWrapper> infos = new ArrayList<>(); 

      public DateCalcExpressionParser() { 
        addTokenInfo(new DateToken.Info()); 
        addTokenInfo(new TimeToken.Info()); 
        addTokenInfo(new IntegerToken.Info()); 
        addTokenInfo(new OperatorToken.Info()); 
        addTokenInfo(new UnitOfMeasureToken.Info()); 
      } 
      private void addTokenInfo(Token.Info info) { 
        infos.add(new InfoWrapper(info)); 
      } 

```

当我们构建我们的解析器时，我们在`List`中注册了每个`Token`类，但我们看到了两种新类型：`Token.Info`和`InfoWrapper`。`Token.Info`是嵌套在`Token`类中的一个接口：

```java
    public interface Info { 
      String getRegex(); 
      Token getToken(String text); 
    } 

```

我们添加了这个接口，以便以方便的方式获取`Token`类的正则表达式，以及`Token`，而不必求助于反射。例如，`DateToken.Info`看起来像这样：

```java
    public static class Info implements Token.Info { 
      @Override 
      public String getRegex() { 
        return REGEX; 
      } 

      @Override 
      public DateToken getToken(String text) { 
        return of(text); 
      } 
    } 

```

由于这是一个嵌套类，我们可以轻松访问包含类的成员，包括静态成员。

下一个新类型，`InfoWrapper`，看起来像这样：

```java
    private class InfoWrapper { 
      Token.Info info; 
      Pattern pattern; 

      InfoWrapper(Token.Info info) { 
        this.info = info; 
        pattern = Pattern.compile("^(" + info.getRegex() + ")"); 
      } 
    } 

```

这是一个简单的私有类，所以一些正常的封装规则可以被搁置（尽管，如果这个类曾经被公开，肯定需要清理一下）。不过，我们正在做的是存储令牌的正则表达式的编译版本。请注意，我们用一些额外的字符包装了正则表达式。第一个是插入符（`^`），表示匹配必须在文本的开头。我们还用括号包装了正则表达式。不过，这次这是一个捕获组。我们将在下面的解析方法中看到为什么要这样做：

```java
    public List<Token> parse(String text) { 
      final Queue<Token> tokens = new ArrayDeque<>(); 

      if (text != null) { 
        text = text.trim(); 
        if (!text.isEmpty()) { 
          boolean matchFound = false; 
          for (InfoWrapper iw : infos) { 
            final Matcher matcher = iw.pattern.matcher(text); 
            if (matcher.find()) { 
              matchFound = true; 
              String match = matcher.group().trim(); 
              tokens.add(iw.info.getToken(match)); 
              tokens.addAll( 
                parse(text.substring(match.length()))); 
                break; 
            } 
          } 
          if (!matchFound) { 
            throw new DateCalcException( 
              "Could not parse the expression: " + text); 
          } 
        } 
      } 

      return tokens; 
    } 

```

我们首先确保`text`不为空，然后`trim()`它，然后确保它不为空。完成了这些检查后，我们循环遍历信息包装器的`List`以找到匹配项。请记住，编译的模式是一个捕获组，查看文本的开头，所以我们循环遍历每个`Pattern`直到找到匹配项。如果我们找不到匹配项，我们会抛出一个`Exception`。

一旦我们找到匹配，我们从`Matcher`中提取匹配的文本，然后使用`Token.Info`调用`getToken()`来获取匹配`Pattern`的`Token`实例。我们将其存储在我们的列表中，然后递归调用`parse()`方法，传递文本的子字符串，从我们的匹配后开始。这将从原始文本中删除匹配的文本，然后重复这个过程，直到字符串为空。一旦递归结束并且事情解开，我们将返回一个代表用户提供的字符串的`Queue`。我们使用`Queue`而不是，比如，`List`，因为这样处理会更容易一些。现在我们有了一个解析器，但我们的工作只完成了一半。现在我们需要处理这些令牌。

在关注关注关注的精神下，我们将这些令牌的处理——实际表达式的计算——封装在一个单独的类`DateCalculator`中，该类使用我们的解析器。考虑以下代码：

```java
    public class DateCalculator { 
      public DateCalculatorResult calculate(String text) { 
        final DateCalcExpressionParser parser = 
          new DateCalcExpressionParser(); 
        final Queue<Token> tokens = parser.parse(text); 

        if (tokens.size() > 0) { 
          if (tokens.peek() instanceof DateToken) { 
            return handleDateExpression(tokens); 
          } else if (tokens.peek() instanceof TimeToken) { 
              return handleTimeExpression(tokens); 
            } 
        } 
        throw new DateCalcException("An invalid expression
          was given: " + text); 
    } 

```

每次调用`calculate()`时，我们都会创建解析器的新实例。另外，请注意，当我们查看代码的其余部分时，我们会传递`Queue`。虽然这确实使方法签名变得有点大，但它也使类线程安全，因为类本身没有保存状态。

在我们的`isEmpty()`检查之后，我们可以看到`Queue` API 的方便之处。通过调用`poll()`，我们可以得到集合中下一个元素的引用，但是——这很重要——**我们保留了集合中的元素**。这让我们可以查看它而不改变集合的状态。根据集合中第一个元素的类型，我们委托给适当的方法。

对于处理日期，表达式语法是`<date> <operator> <date | number unit_of_measure>`。因此，我们可以通过提取`DateToken`和`OperatorToken`来开始我们的处理，如下所示：

```java
    private DateCalculatorResult handleDateExpression( 
      final Queue<Token> tokens) { 
        DateToken startDateToken = (DateToken) tokens.poll(); 
        validateToken(tokens.peek(), OperatorToken.class); 
        OperatorToken operatorToken = (OperatorToken) tokens.poll(); 
        Token thirdToken = tokens.peek(); 

        if (thirdToken instanceof IntegerToken) { 
          return performDateMath(startDateToken, operatorToken,
            tokens); 
        } else if (thirdToken instanceof DateToken) { 
            return getDateDiff(startDateToken, tokens.poll()); 
          } else { 
              throw new DateCalcException("Invalid expression"); 
            } 
    } 

```

从`Queue`中检索元素，我们使用`poll()`方法，我们可以安全地将其转换为`DateToken`，因为我们在调用方法中检查了这一点。接下来，我们`peek()`下一个元素，并通过`validateToken()`方法验证元素不为空且为所需类型。如果令牌有效，我们可以安全地`poll()`和转换。接下来，我们`peek()`第三个令牌。根据其类型，我们委托给正确的方法来完成处理。如果我们发现意外的`Token`类型，我们抛出一个`Exception`。

在查看这些计算方法之前，让我们看一下`validateToken()`：

```java
    private void validateToken(final Token token,
      final Class<? extends Token> expected) { 
        if (token == null || ! 
          token.getClass().isAssignableFrom(expected)) { 
            throw new DateCalcException(String.format( 
              "Invalid format: Expected %s, found %s", 
               expected, token != null ? 
               token.getClass().getSimpleName() : "null")); 
        } 
    } 

```

这里没有太多令人兴奋的东西，但敏锐的读者可能会注意到我们正在返回我们令牌的类名，并且通过这样做，我们向最终用户泄露了一个未导出类的名称。这可能不是理想的，但我们将把修复这个问题留给读者作为一个练习。

执行日期数学的方法如下：

```java
    private DateCalculatorResult performDateMath( 
      final DateToken startDateToken, 
      final OperatorToken operatorToken, 
      final Queue<Token> tokens) { 
        LocalDate result = startDateToken.getValue(); 
        int negate = operatorToken.isAddition() ? 1 : -1; 

        while (!tokens.isEmpty()) { 
          validateToken(tokens.peek(), IntegerToken.class); 
          int amount = ((IntegerToken) tokens.poll()).getValue() *
            negate; 
          validateToken(tokens.peek(), UnitOfMeasureToken.class); 
          result = result.plus(amount, 
          ((UnitOfMeasureToken) tokens.poll()).getValue()); 
        } 

        return new DateCalculatorResult(result); 
    } 

```

由于我们已经有了我们的起始和操作符令牌，我们将它们传递进去，以及`Queue`，以便我们可以处理剩余的令牌。我们的第一步是确定操作符是加号还是减号，根据需要给`negate`分配正数`1`或负数`-1`。我们这样做是为了能够使用一个方法`LocalDate.plus()`。如果操作符是减号，我们添加一个负数，得到与减去原始数相同的结果。

最后，我们循环遍历剩余的令牌，在处理之前验证每一个。我们获取`IntegerToken`；获取其值；将其乘以我们的负数修饰符`negate`，然后使用`UnitOfMeasureToken`将该值添加到`LocalDate`中，以告诉我们正在添加的值的**类型**。

计算日期之间的差异非常简单，如下所示：

```java
    private DateCalculatorResult getDateDiff( 
      final DateToken startDateToken, final Token thirdToken) { 
        LocalDate one = startDateToken.getValue(); 
        LocalDate two = ((DateToken) thirdToken).getValue(); 
        return (one.isBefore(two)) ? new
          DateCalculatorResult(Period.between(one, two)) : new
            DateCalculatorResult(Period.between(two, one)); 
    } 

```

我们从两个`DateToken`变量中提取`LocalDate`，然后调用`Period.between()`，它返回一个指示两个日期之间经过的时间量的`Period`。我们确实检查了哪个日期先出现，以便向用户返回一个正的`Period`，作为一种便利，因为大多数人通常不会考虑负周期。

基于时间的方法基本相同。最大的区别是时间差异方法：

```java
    private DateCalculatorResult getTimeDiff( 
      final OperatorToken operatorToken, 
      final TimeToken startTimeToken, 
      final Token thirdToken) throws DateCalcException { 
        LocalTime startTime = startTimeToken.getValue(); 
        LocalTime endTime = ((TimeToken) thirdToken).getValue(); 
        return new DateCalculatorResult( 
          Duration.between(startTime, endTime).abs()); 
    } 

```

这里值得注意的区别是使用了`Duration.between()`。它看起来与`Period.between()`相同，但`Duration`类提供了一个`Period`没有的方法：`abs()`。这个方法让我们返回`Period`的绝对值，所以我们可以按任何顺序将我们的`LocalTime`变量传递给`between()`。

在我们离开之前的最后一点注意事项是--我们将结果封装在`DateCalculatorResult`实例中。由于各种操作返回几种不同的、不相关的类型，这使我们能够从我们的`calculate()`方法中返回一个单一类型。由调用代码来提取适当的值。我们将在下一节中查看我们的命令行界面。

# 关于测试的简短插曲

在我们继续之前，我们需要讨论一个我们尚未讨论过的话题，那就是测试。在这个行业工作了一段时间的人很可能听说过**测试驱动开发**（或简称**TDD**）这个术语。这是一种软件开发方法，认为应该首先编写一个测试，这个测试将失败（因为没有代码可以运行），然后编写使测试**通过**的代码，这是指 IDE 和其他工具中给出的绿色指示器，表示测试已经通过。这个过程根据需要重复多次来构建最终的系统，总是以小的增量进行更改，并始终从测试开始。关于这个主题已经有大量的书籍写成，这个主题既备受争议，又常常被严格细分。这种方法的确切实现方式，如果有的话，几乎总是有不同的版本。

显然，在我们的工作中，我们并没有严格遵循 TDD 原则，但这并不意味着我们没有进行测试。虽然 TDD 纯粹主义者可能会挑剔，但我的一般方法在测试方面可能会有些宽松，直到我的 API 开始变得稳定为止。这需要多长时间取决于我对正在使用的技术的熟悉程度。如果我对它们非常熟悉，我可能会草拟一个快速的接口，然后基于它构建一个测试，作为测试 API 本身的手段，然后对其进行迭代。对于新的库，我可能会编写一个非常广泛的测试，以帮助驱动对新库的调查，使用测试框架作为引导运行环境的手段，以便我可以进行实验。无论如何，在开发工作结束时，新系统应该经过**完全**测试（**完全**的确切定义是另一个备受争议的概念），这正是我在这里努力追求的。关于测试和测试驱动开发的全面论述超出了我们的范围。

在 Java 中进行测试时，你有很多选择。然而，最常见的两种是 TestNG 和 JUnit，其中 JUnit 可能是最受欢迎的。你应该选择哪一个？这取决于情况。如果你正在处理一个现有的代码库，你可能应该使用已经在使用的东西，除非你有充分的理由做出其他选择。例如，该库可能已经过时并且不再受支持，它可能明显不符合你的需求，或者你已经得到了明确的指令来更新/替换现有系统。如果这些条件中的任何一个，或者类似这些的其他条件是真实的，我们就回到了这个问题--*我应该选择哪一个？*同样，这取决于情况。JUnit 非常受欢迎和常见，因此在项目中使用它可能是有道理的，以降低进入项目的门槛。然而，一些人认为 TestNG 具有更好、更清晰的 API。例如，TestNG 不需要对某些测试设置方法使用静态方法。它还旨在不仅仅是一个单元测试框架，还提供了用于单元、功能、端到端和集成测试的工具。在这里，我们将使用 TestNG 进行测试。

要开始使用 TestNG，我们需要将其添加到我们的项目中。为此，我们将在 Maven POM 文件中添加一个测试依赖项，如下所示：

```java
    <properties>
      <testng.version>6.9.9</testng.version>
    </properties>
    <dependencies> 
      <dependency> 
        <groupId>org.testng</groupId>   
        <artifactId>testng</artifactId>   
        <version>${testng.version}</version>   
        <scope>test</scope> 
      </dependency>   
    </dependencies> 

```

编写测试非常简单。使用 TestNG Maven 插件的默认设置，类只需要在`src/test/java`中，并以`Test`字符串结尾。每个测试方法都需要用`@Test`进行注释。

库模块中有许多测试，所以让我们从一些非常基本的测试开始，这些测试测试了标记使用的正则表达式，以识别和提取表达式的相关部分。例如，考虑以下代码片段：

```java
    public class RegexTest { 
      @Test 
      public void dateTokenRegex() { 
        testPattern(DateToken.REGEX, "2016-01-01"); 
        testPattern(DateToken.REGEX, "today"); 
      } 
      private void testPattern(String pattern, String text) { 
        testPattern(pattern, text, false); 
      } 

      private void testPattern(String pattern, String text, 
        boolean exact) { 
          Pattern p = Pattern.compile("(" + pattern + ")"); 
          final Matcher matcher = p.matcher(text); 

          Assert.assertTrue(matcher.find()); 
          if (exact) { 
            Assert.assertEquals(matcher.group(), text); 
          } 
      } 

```

这是对`DateToken`正则表达式的一个非常基本的测试。测试委托给`testPattern()`方法，传递要测试的正则表达式和要测试的字符串。我们的功能通过以下步骤进行测试：

1.  编译`Pattern`。

1.  创建`Matcher`。

1.  调用`matcher.find()`方法。

有了这个，被测试系统的逻辑就得到了执行。剩下的就是验证它是否按预期工作。我们通过调用`Assert.assertTrue()`来做到这一点。我们断言`matcher.find()`返回`true`。如果正则表达式正确，我们应该得到一个`true`的响应。如果正则表达式不正确，我们将得到一个`false`的响应。在后一种情况下，`assertTrue()`将抛出一个`Exception`，测试将失败。

这个测试确实非常基础。它可能——应该——更加健壮。它应该测试更多种类的字符串。它应该包括一些已知的坏字符串，以确保我们在测试中没有得到错误的结果。可能还有许多其他的增强功能可以实现。然而，这里的重点是展示一个简单的测试，以演示如何设置基于 TestNG 的环境。在继续之前，让我们看几个更多的例子。

这是一个用于检查失败的测试（**负面测试**）：

```java
    @Test 
    public void invalidStringsShouldFail() { 
      try { 
        parser.parse("2016/12/25 this is nonsense"); 
        Assert.fail("A DateCalcException should have been
          thrown (Unable to identify token)"); 
      } catch (DateCalcException dce) { 
      } 
    } 

```

在这个测试中，我们期望调用`parse()`失败，并抛出一个`DateCalcException`。如果调用**没有**失败，我们会调用`Assert.fail()`，强制测试失败并提供消息。如果抛出了`Exception`，它会被悄悄地吞没，测试将成功结束。

吞没`Exception`是一种方法，但你也可以告诉 TestNG 期望抛出一个`Exception`，就像我们在这里通过`expectedExceptions`属性所做的那样：

```java
    @Test(expectedExceptions = {DateCalcException.class}) 
    public void shouldRejectBadTimes() { 
      parser.parse("22:89"); 
    } 

```

同样，我们将一个坏的字符串传递给解析器。然而，这一次，我们通过注解告诉 TestNG 期望抛出异常——`@Test(expectedExceptions = {DateCalcException.class})`。

关于测试一般和特别是 TestNG，还可以写更多。对这两个主题的全面讨论超出了我们的范围，但如果你对任何一个主题不熟悉，最好找到其中的一些优秀资源并进行深入学习。

现在，让我们把注意力转向命令行界面。

# 构建命令行界面

在上一章中，我们使用了 Tomitribe 的 Crest 库构建了一个命令行工具，并且效果非常好，所以我们将在构建这个命令行时再次使用这个库。

要在我们的项目中启用 Crest，我们必须做两件事。首先，我们必须按照以下方式配置我们的 POM 文件：

```java
    <dependency> 
      <groupId>org.tomitribe</groupId> 
      <artifactId>tomitribe-crest</artifactId> 
      <version>0.8</version> 
    </dependency> 

```

我们还必须按照以下方式更新`src/main/java/module-info.java`中的模块定义：

```java
    module datecalc.cli { 
      requires datecalc.lib; 
      requires tomitribe.crest; 
      requires tomitribe.crest.api; 

      exports com.steeplesoft.datecalc.cli; 
    } 

```

我们现在可以像这样定义我们的 CLI 类：

```java
    public class DateCalc { 
      @Command 
      public void dateCalc(String... args) { 
        final String expression = String.join(" ", args); 
        final DateCalculator dc = new DateCalculator(); 
        final DateCalculatorResult dcr = dc.calculate(expression); 

```

与上一章不同，这个命令行将非常简单，因为我们唯一需要的输入是要评估的表达式。通过前面的方法签名，我们告诉 Crest 将所有命令行参数作为`args`值传递，然后我们通过`String.join()`将它们重新连接成`expression`。接下来，我们创建我们的计算器并计算结果。

现在我们需要询问我们的`DateCalcResult`来确定表达式的性质。考虑以下代码片段作为示例：

```java
    String result = ""; 
    if (dcr.getDate().isPresent()) { 
      result = dcr.getDate().get().toString(); 
    } else if (dcr.getTime().isPresent()) { 
      result = dcr.getTime().get().toString(); 
    } else if (dcr.getDuration().isPresent()) { 
      result = processDuration(dcr.getDuration().get()); 
    } else if (dcr.getPeriod().isPresent()) { 
      result = processPeriod(dcr.getPeriod().get()); 
    } 
    System.out.println(String.format("'%s' equals '%s'", 
      expression, result)); 

```

`LocalDate`和`LocalTime`的响应非常直接——我们可以简单地调用它们的`toString()`方法，因为默认值对于我们的目的来说是完全可以接受的。`Duration`和`periods`则更加复杂。两者都提供了许多提取细节的方法。我们将把这些细节隐藏在单独的方法中：

```java
    private String processDuration(Duration d) { 
      long hours = d.toHoursPart(); 
      long minutes = d.toMinutesPart(); 
      long seconds = d.toSecondsPart(); 
      String result = ""; 

      if (hours > 0) { 
        result += hours + " hours, "; 
      } 
      result += minutes + " minutes, "; 
      if (seconds > 0) { 
        result += seconds + " seconds"; 
      } 

      return result; 
    } 

```

这个方法本身非常简单——我们从`Duration`中提取各个部分，然后根据部分是否返回值来构建字符串。

与日期相关的`processPeriod()`方法类似：

```java
    private String processPeriod(Period p) { 
      long years = p.getYears(); 
      long months = p.getMonths(); 
      long days = p.getDays(); 
      String result = ""; 

      if (years > 0) { 
        result += years + " years, "; 
      } 
      if (months > 0) { 
        result += months + " months, "; 
      } 
      if (days > 0) { 
        result += days + " days"; 
      } 
      return result; 
    } 

```

这些方法中的每一个都将结果作为字符串返回，然后我们将其写入标准输出。就是这样。这不是一个非常复杂的命令行实用程序，但这里的练习目的主要在于库中。

# 总结

我们的日期计算器现在已经完成。这个实用程序本身并不是太复杂，尽管它确实如预期般发挥作用，这必须成为尝试使用 Java 8 的日期/时间 API 的工具。除了新的日期/时间 API，我们还初步了解了正则表达式，这是一种非常强大和复杂的工具，用于解析字符串。我们还重新访问了上一章的命令行实用程序库，并在单元测试和测试驱动开发的领域涉足了一点。

在下一章中，我们将更加雄心勃勃地进入社交媒体的世界，构建一个应用程序，帮助我们将一些喜爱的服务聚合到一个单一的应用程序中。


# 第五章：Sunago - 社交媒体聚合器

对于我们的下一个项目，我们将尝试一些更有雄心的东西；我们将构建一个桌面应用程序，它可以从各种社交媒体网络中聚合数据，并以一种无缝的交互方式显示出来。我们还将尝试一些新的东西，并且给这个项目起一个名字，这个名字可能比迄今为止使用的干巴巴但准确的`描述转换名称`更有吸引力。那么，这个应用程序，我们将其称为 Sunago，这是（Koine）希腊语单词συνάγω的音标拼写，意思是**我聚集在一起**，**收集**，**组装**。

构建应用程序将涵盖几个不同的主题，有些熟悉，有些新的。该清单包括以下内容：

+   JavaFX

+   国际化和本地化

+   **服务提供商接口**（**SPI**）

+   REST API 消费

+   `ClassLoader`操作

+   Lambda 表达式，lambda 表达式，还有更多的 lambda 表达式

像往常一样，这些只是一些亮点，其中还有许多有趣的内容。

# 入门

与每个应用程序一样，在开始之前，我们需要考虑一下我们希望应用程序做什么。也就是说，什么是功能需求？在高层次上，描述告诉我们我们希望以广义的术语实现什么，但更具体地，我们希望用户能够做到以下几点：

+   连接到几个不同的社交媒体网络

+   逐个网络确定要检索的数据组（用户、列表等）

+   在一个整合显示中查看来自每个网络的项目列表

+   能够确定项目来自哪个网络

+   单击项目并在用户默认浏览器中加载它

除了应用程序应该做的事情清单之外，它不应该做的事情包括以下几点：

+   回复项目

+   评论项目

+   管理朋友/关注列表

这些功能将是应用程序的很好的补充，但除了之前详细介绍的基本应用程序之外，它们并没有提供太多有趣的架构内容，因此，为了保持简单并使事情顺利进行，我们将限制范围到给定的基本需求集。

那么应用程序从哪里开始呢？与之前的章节一样，我们将把这个应用程序做成一个桌面应用程序，所以让我们从那里开始，使用 JavaFX 应用程序。我在这里稍微透露一点底牌，以便以后更容易：这将是一个多模块项目，因此我们首先需要创建父项目。在 NetBeans 中，点击文件 | 新建项目...，并选择`Maven`类别，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-prog-bp/img/bf651e9f-2210-43e1-b027-b6ba1d98b8f7.png)

点击下一步按钮，并填写项目详细信息，如下所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-prog-bp/img/35d2db60-289b-4589-9598-3c7e81523bc8.png)

单击完成后，您将看到一个空项目。一旦我们向该项目添加模块，区分它们可能会变得困难，因此作为一种惯例，我会给每个模块一个独特的“命名空间”名称。也就是说，每个模块都有自己的名称，当然，我会在项目名称前加上前缀。例如，由于这是项目的基本 POM，我将其称为`Master`。为了反映这一点，我修改生成的 POM，使其看起来像这样：

```java
    <?xml version="1.0" encoding="UTF-8"?> 
    <project   

      xsi:schemaLocation="http://maven.apache.org/POM/4.0.0  
      http://maven.apache.org/xsd/maven-4.0.0.xsd"> 
      <modelVersion>4.0.0</modelVersion> 
      <groupId>com.steeplesoft.sunago</groupId> 
      <artifactId>master</artifactId> 
      <version>1.0-SNAPSHOT</version> 
      <name>Sunago - Master</name> 
      <packaging>pom</packaging> 
    </project> 

```

目前还没有太多内容。像这样的父 POM 给我们带来的好处是，如果我们愿意，我们可以用一个命令构建所有项目，并且我们可以将任何共享配置移动到这个共享的父 POM 中，以减少重复。不过，现在我们需要添加的是一个模块，NetBeans 可以帮助我们做到这一点，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-prog-bp/img/795d1477-a580-4f9f-9d51-aa8f7493db24.png)

单击创建新模块后，您将看到熟悉的新项目窗口，从中您将选择 Maven | JavaFX 应用程序，并单击下一步。在新的 Java 应用程序屏幕中，输入`app`作为项目名称，并单击完成（所有其他默认设置均可接受）。 

再次，我们希望给这个模块一个有意义的名称，所以让我们修改生成的`pom.xml`如下：

```java
    <?xml version="1.0" encoding="UTF-8"?> 
    <project   

      xsi:schemaLocation="http://maven.apache.org/POM/4.0.0  
      http://maven.apache.org/xsd/maven-4.0.0.xsd"> 
      <modelVersion>4.0.0</modelVersion> 
      <parent> 
        <groupId>com.steeplesoft.sunago</groupId> 
        <artifactId>master</artifactId> 
        <version>1.0-SNAPSHOT</version> 
      </parent> 
      <artifactId>sunago</artifactId> 
      <name>Sunago - App</name> 
      <packaging>jar</packaging> 
    </project> 

```

当 NetBeans 创建项目时，它会为我们生成几个构件--两个类`FXMLController`和`MainApp`，以及资源`fxml/Scene.xml`和`styles/Styles.css`。虽然这可能是显而易见的，但构件应该具有清晰传达其目的的名称，所以让我们将它们重命名。

类`FxmlContoller`应该重命名为`SunagoController`。也许最快最简单的方法是在项目视图中双击打开类，然后在源编辑器中点击类声明中的类名，并按下*Ctrl* + *R*。重命名类对话框应该会出现，您需要输入新名称，然后按*Enter*。这将为您重命名类和文件。现在重复这个过程，将`MainApp`重命名为`Sunago`。

我们还想将生成的 FXML 文件`Scene.xml`重命名为`sunago.fxml`。要做到这一点，在项目视图中右键单击文件，然后从上下文菜单中选择重命名...。在重命名对话框中输入新名称（不包括扩展名），然后按*Enter*。在这个过程中，让我们也将`Styles.css`重命名为`styles.css`，以保持一致。这只是一个小事，但代码的一致性可以帮助您和未来接手您代码的人产生信心。

不幸的是，重命名这些文件不会调整 Java 源文件中对它们的引用，因此我们需要编辑`Sunago.java`，将它们指向这些新名称，操作如下：

```java
    @Override
    public void start(Stage stage) throws Exception {
      Parent root = fxmlLoader.load(
        getClass().getResource("/fxml/sunago.fxml"));

        Scene scene = new Scene(root);
        scene.getStylesheets().add("/styles/styles.css");

        stage.setTitle("Sunago, your social media aggregator");
        stage.setScene(scene);
        stage.show();
    }

```

还要注意，我们将标题更改为更合适的内容。

# 设置用户界面。

如果我们愿意，现在可以运行我们的应用程序。这将非常无聊，但它可以运行。让我们试着修复无聊的部分。

默认创建的 FXML 只是一个带有两个子元素的 AnchorPane，一个按钮和一个标签。我们不需要这些，所以让我们摆脱它们。我们的主用户界面将非常简单--基本上只是一堆垂直的组件--所以我们可以使用 VBox 作为我们的根组件。也许，将根组件从那里的 AnchorPane 更改为 VBox 的最简单方法是使用 Scene Builder 将该组件包装在 VBox 中，然后删除 AnchorPane：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-prog-bp/img/34cca0dd-2582-4fa2-96ad-6d3089fdbaa2.png)

要做到这一点，通过双击文件在 Scene Builder 中打开 FXML 文件（假设您已经正确配置了 NetBeans，以便它知道在哪里找到 Scene Builder。如果没有，请参考第一章，*介绍*）。在 Scene Builder 中，在左侧手风琴的文档部分中右键单击 AnchorPane，选择 Wrap in，然后选择 VBox，如前面的屏幕截图所示。然后，Scene Builder 将修改 FXML 文件，使 AnchorPane 作为预期的 VBox 的子元素。完成后，您可以右键单击 AnchorPane，然后单击删除以删除它及其子元素。这样我们就得到了一个比开始时更无聊的空用户界面。现在我们可以通过添加一些控件来修复它--一个菜单栏和一个列表视图。我们可以通过单击手风琴中控件部分中的每个组件，并将它们拖动到 VBox 中来实现。如果您将组件放在 VBox 上，它们将被追加到其子元素列表中。确保 MenuBar 在 ListView 之前，否则您将得到一个非常奇怪的用户界面。

现在在返回代码之前，让我们稍微配置一下这些组件。从左侧的文档部分选择 VBox，然后需要在右侧手风琴中选择布局部分。对于最小宽度和最小高度，分别输入`640`和`480`。这将使窗口的默认大小更大和更用户友好。

对于 MenuBar，我们需要展开其在 Document 下的条目，然后展开其每个 Menu 子项，这样应该会显示每个 Menu 的一个 MenuItem。点击第一个 Menu，然后在右侧将`Text`设置为`_File`，并勾选 Mnemonic Parsing。这将允许用户按下*Alt* + *F*来激活（或显示）此菜单。接下来，点击其`MenuItem`子项，将`Text`设置为`_Exit`，并勾选 Mnemonic Parsing。（如果`Menu`、`MenuItem`、`Button`等的文本中有下划线，请确保勾选了 Mnemonic Parsing。出于简洁起见，我不会再明确标记这一点。）打开 Code 部分，将 On Action 值设置为`closeApplication`。

第二个`Menu`的 Text 值应设置为`_Edit`。它的`MenuItem`应标记为`_Settings`，并具有`showPreferences`的 On Action 值。最后，第三个`Menu`应标记为`_Help`，其`MenuItem`标记为`About`，具有`showAbout`的 On Action 值。

接下来，我们想要给`ListView`一个 ID，所以在左侧选择它，确保右侧展开了 Code 部分，然后输入`entriesListView`作为 fx:id。

我们需要做的最后一个编辑是设置控制器。我们在左侧的手风琴中进行，找到最底部的 Controller 部分。展开它，并确保 Controller 类的值与我们在 NetBeans 中刚刚创建的 Java 类和包匹配，然后保存文件。

# 设置控制器

回到 NetBeans，我们需要修复我们的控制器，以反映我们刚刚在 FXML 中所做的更改。在`SunagoController`中，我们需要添加`entriesListView`属性如下：

```java
    @FXML 
    private ListView<SocialMediaItem> entriesListView; 

```

注意，参数化类型是`SocialMediaItem`。这是我们马上要创建的自定义模型。在我们着手处理之前，我们需要完成将用户界面连接在一起。我们在 FXML 中定义了三个`onAction`处理程序。相应的代码如下：

```java
    @FXML 
    public void closeApplication(ActionEvent event) { 
      Platform.exit(); 
    } 

```

关闭应用程序就是简单地在`Platform`类上调用`exit`方法。显示“关于”框也相当简单，正如我们在`showAbout`方法中看到的：

```java
    @FXML 
    public void showAbout(ActionEvent event) { 
      Alert alert = new Alert(Alert.AlertType.INFORMATION); 
      alert.setTitle("About..."); 
      alert.setHeaderText("Sunago (συνάγω)"); 
      alert.setContentText("(c) Copyright 2016"); 
      alert.showAndWait(); 
    } 

```

使用内置的`Alert`类，我们构建一个实例，并设置适用于关于屏幕的值，然后通过`showAndWait()`模态显示它。

首选项窗口是一个更复杂的逻辑，所以我们将其封装在一个新的控制器类中，并调用其`showAndWait()`方法。

```java
    @FXML 
    public void showPreferences(ActionEvent event) { 
      PreferencesController.showAndWait(); 
    } 

```

# 编写模型类

在我们看这个之前，主控制器中还有一些项目需要处理。首先是之前提到的模型类`SocialMediaItem`。你可能可以想象到，从社交网络返回的数据结构可能非常复杂，而且多种多样。例如，推文的数据需求可能与 Instagram 帖子的数据需求大不相同。因此，我们希望能够将这些复杂性和差异隐藏在一个简单、可重用的接口后面。在现实世界中，这样一个简单的抽象并不总是可能的，但是在这里，我们有一个名为`SocialMediaItem`的接口，你可以在这段代码中看到：

```java
    public interface SocialMediaItem { 
      String getProvider(); 
      String getTitle(); 
      String getBody(); 
      String getUrl(); 
      String getImage(); 
      Date getTimestamp(); 
    } 

```

抽象的一个问题是，为了使它们可重用，偶尔需要以这样的方式构造它们，以便它们暴露可能不被每个实现使用的属性。尽管目前还不明显，但在这里肯定是这种情况。有些人认为这种情况是不可接受的，他们可能有一定道理，但这确实是一个权衡的问题。我们的选择包括略微臃肿的接口或一个复杂的系统，其中每个网络支持模块（我们很快就会介绍）都提供自己的渲染器，并且应用程序必须询问每个模块，寻找可以处理每个项目的渲染器，同时绘制`ListView`。当然还有其他选择，但至少有这两个选择，为了简单和性能的缘故，我们将选择第一种选择。然而，在设计自己的系统时面临类似情况时，您需要评估项目的各种要求，并做出适当的选择。对于我们这里的需求，简单的方法已经足够了。

无论如何，每个社交媒体网络模块都将实现该接口来包装其数据。这将为应用程序提供一个通用接口，而无需知道确切的来源。不过，现在我们需要告诉`ListView`如何绘制包含`SocialMediaItem`的单元格。我们可以在控制器的`initialize()`方法中使用以下代码来实现：

```java
    entriesListView.setCellFactory(listView ->  
      new SocialMediaItemViewCell()); 

```

显然，这是一个 lambda。对于好奇的人来说，前面方法的 lambda 之前的版本将如下所示：

```java
    entriesListView.setCellFactory( 
      new Callback<ListView<SocialMediaItem>,  
      ListCell<SocialMediaItem>>() {  
        @Override 
        public ListCell<SocialMediaItem> call( 
          ListView<SocialMediaItem> param) { 
            return new SocialMediaItemViewCell(); 
          } 
    }); 

```

# 完成控制器

在我们查看`SocialMediaItemViewCell`之前，还有两个控制器项目。第一个是保存`ListView`数据的列表。请记住，`ListView`是从`ObservableList`操作的。这使我们能够对列表中的数据进行更改，并自动反映在用户界面中。为了创建该列表，我们将在定义类属性时使用 JavaFX 辅助方法，如下所示：

```java
    private final ObservableList<SocialMediaItem> entriesList =  
      FXCollections.observableArrayList(); 

```

然后我们需要将该`List`连接到我们的`ListView`。回到`initialize()`，我们有以下内容：

```java
    entriesListView.setItems(entriesList); 

```

为了完成`SocialMediaItem`接口的呈现，让我们这样定义`SocialMediaItemViewCell`：

```java
    public class SocialMediaItemViewCell extends  
      ListCell<SocialMediaItem> { 
      @Override 
      public void updateItem(SocialMediaItem item, boolean empty) { 
        super.updateItem(item, empty); 
        if (item != null) { 
          setGraphic(buildItemCell(item)); 
          this.setOnMouseClicked(me -> SunagoUtil 
            .openUrlInDefaultApplication(item.getUrl())); 
        } else { 
            setGraphic(null); 
          } 
      } 

      private Node buildItemCell(SocialMediaItem item) { 
        HBox hbox = new HBox(); 
        InputStream resource = item.getClass() 
          .getResourceAsStream("icon.png"); 
        if (resource != null) { 
          ImageView sourceImage = new ImageView(); 
          sourceImage.setFitHeight(18); 
          sourceImage.setPreserveRatio(true); 
          sourceImage.setSmooth(true); 
          sourceImage.setCache(true); 
          sourceImage.setImage(new Image(resource)); 
          hbox.getChildren().add(sourceImage); 
        } 

        if (item.getImage() != null) { 
          HBox picture = new HBox(); 
          picture.setPadding(new Insets(0,10,0,0)); 
          ImageView imageView = new ImageView(item.getImage()); 
          imageView.setPreserveRatio(true); 
          imageView.setFitWidth(150); 
          picture.getChildren().add(imageView); 
          hbox.getChildren().add(picture); 
        } 

        Label label = new Label(item.getBody()); 
        label.setFont(Font.font(null, 20)); 
        label.setWrapText(true); 
        hbox.getChildren().add(label); 

        return hbox; 
      } 

    } 

```

这里发生了很多事情，但`updateItem()`是我们首要关注的地方。这是每次在屏幕上更新行时调用的方法。请注意，我们检查`item`是否为空。我们这样做是因为`ListView`不是为其`List`中的每个项目调用此方法，而是为`ListView`中可见的每一行调用，无论是否有数据。这意味着，如果`List`有五个项目，但`ListView`足够高以显示十行，此方法将被调用十次，最后五次调用将使用空的`item`进行。在这种情况下，我们调用`setGraphic(null)`来清除先前呈现的任何项目。

但是，如果`item`不为空，我们需要构建用于显示项目的`Node`，这是在`buildItemCell()`中完成的。对于每个项目，我们希望呈现三个项目--社交媒体网络图标（用户可以一眼看出项目来自哪里）、项目中嵌入的任何图像，以及最后，项目中的任何文本/标题。为了帮助安排，我们从`HBox`开始。

接下来，我们尝试查找网络的图标。如果我们有一份正式的合同书，我们将在其中包含语言，规定模块包含一个名为`icon.png`的文件，该文件与模块的`SocialMediaItem`实现在同一个包中。然后，使用实现的`ClassLoader`，我们尝试获取资源的`InputStream`。我们检查是否为空，只是为了确保实际找到了图像；如果是，我们创建一个`ImageView`，设置一些属性，然后将资源包装在`Image`中，将其交给`ImageView`，然后将`ImageView`添加到`HBox`中。

# 为项目添加图像

如果该项目有图片，我们会以与网络图标图片相同的方式处理它。不过，这一次，我们实际上是在将`ImageView`添加到外部`HBox`之前将其包装在另一个`HBox`中。我们这样做是为了能够在图像周围添加填充（通过`picture.setPadding(new Insets())`）以便在图像和网络图标之间留出一些空间。

最后，我们创建一个`Label`来容纳项目的正文。我们通过`label.setFont(Font.font(null, 20))`将文本的字体大小设置为`20`点，并将其添加到我们的`HBox`，然后将其返回给调用者`updateItem()`。

每当您有一个`ListView`时，您可能会想要一个像我们这里一样的自定义`ListCell`实现。在某些情况下，调用`List`内容的`toString()`可能是合适的，但并不总是如此，而且您肯定不能在没有自己实现`ListCell`的情况下拥有像我们这里一样复杂的`ListCell`结构。如果您计划进行大量的 JavaFX 开发，最好熟悉这种技术。

# 构建首选项用户界面

我们终于完成了主控制器，现在可以把注意力转向下一个重要部分，`PreferencesController`。我们的首选项对话框通常是一个模态对话框。它将提供一个带有一个用于常规设置的选项卡，然后是每个支持的社交网络的选项卡的选项卡界面。我们通过向项目添加新的 FXML 文件和控制器来开始这项工作，NetBeans 有一个很好的向导。右键单击所需的包，然后单击 New | Other。从类别列表中，选择`JavaFX`，然后从文件类型列表中选择`Empty FXML`，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-prog-bp/img/bc7b7536-4970-4c03-9740-36023c951ae8.png)

点击“下一步”后，您应该会看到 FXML 名称和位置步骤。这将允许我们指定新文件的名称和创建它的包，就像在这个屏幕截图中看到的那样：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-prog-bp/img/f80f3d0b-47e9-4791-9a1f-1d553fc6c25d.png)

点击“下一步”将带我们到控制器类步骤。在这里，我们可以创建一个新的控制器类，或将我们的文件附加到现有的控制器类。由于这是我们应用程序的一个新对话框/窗口，我们需要创建一个新的控制器，如下所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-prog-bp/img/5315164e-af28-4892-803d-c3a72a365bfd.png)

勾选“使用 Java 控制器”复选框，输入`PreferencesController`作为名称，并选择所需的包。我们可以点击“下一步”，这将带我们到层叠样式表步骤，但我们对于这个控制器不感兴趣，所以我们通过点击“完成”来结束向导，这将带我们到我们新创建的控制器类的源代码。

让我们从布局用户界面开始。双击新的`prefs.fxml`文件以在 Scene Builder 中打开它。与我们上一个 FXML 文件一样，默认的根元素是 AnchorPane。对于这个窗口，我们想要使用 BorderPane，所以我们使用了与上次替换 AnchorPane 相同的技术--右键单击组件，然后单击 Wrap in | BorderPane。AnchorPane 现在嵌套在 BorderPane 中，所以我们再次右键单击它，然后选择删除。

为了构建用户界面，我们现在从左侧的手风琴中拖动一个 TabPane 控件，并将其放在 BorderPane 的 CENTER 区域。这将在我们的用户界面中添加一个具有两个选项卡的 TabPane。我们现在只想要一个，所以删除第二个。我们想要给我们的选项卡一个有意义的标签。我们可以通过双击预览窗口中的选项卡（或在检查器的属性部分中选择 Text 属性）并输入`General`来实现。最后，展开检查器的代码部分，并输入`tabPane`作为 fx:id。

现在我们需要提供一种方式，让用户可以关闭窗口，并保存或放弃更改。我们通过将 ButtonBar 组件拖动到边界面的 BOTTOM 区域来实现这一点。这将添加一个带有一个按钮的 ButtonBar，但我们需要两个，所以我们将另一个按钮拖到 ButtonBar 上。这个控件的好处是它会为我们处理按钮的放置和填充，所以当我们放置新按钮时，它会自动添加到正确的位置。 （这种行为可以被覆盖，但它正是我们想要的，所以我们可以接受默认值。）

对于每个`Button`，我们需要设置三个属性--`text`，`fx:id`和`onAction`。第一个属性在 Inspector 的 Properties 部分中，最后两个在 Code 部分。第一个按钮的值分别是`Save`，`savePrefs`和`savePreferences`。对于第二个按钮，值分别是`Cancel`，`cancel`和`closeDialog`。在 Inspector 中选择`ButtonBar`的 Layout 部分，并将右填充设置为 10，以确保`Button`不会紧贴窗口边缘。

最后，我们将在这一点上添加我们唯一的偏好设置。我们希望允许用户指定从每个社交媒体网络中检索的最大项目数。我们这样做是为了那些应用程序长时间未被使用（或从未被使用）的情况。在这些情况下，我们不希望尝试下载成千上万条推文。为了支持这一点，我们添加两个控件，`Label`和`TextField`。

将 Label 控件的位置设置正确非常简单，因为它是第一个组件。Scene Builder 将提供红色指南线，以帮助您将组件放置在所需位置，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-prog-bp/img/0c1cdf3f-96b1-49b5-917d-9033d21b1b47.png)

确保`TextField`与标签对齐可能会更加棘手。默认情况下，当您将组件放置在 TabPane 上时，Scene Builder 会添加一个 AnchorPane 来容纳新组件。HBox 可能是一个更好的选择，但我们将继续使用 AnchorPane 来演示 Scene Builder 的这个特性。如果您将 TextField 拖放到 TabPane 并尝试定位它，您应该会看到更多的红线出现。定位正确后，您应该会看到一条红线穿过标签和`TextField`的中间，表示这两个组件在垂直方向上对齐。这正是我们想要的，所以确保`TextField`和标签之间有一小段空间，然后放置它。

我们需要给 Label 一些有意义的文本，所以在预览窗口中双击它，输入`要检索的项目数量`。我们还需要为`TextField`设置一个 ID，以便与之交互，所以点击组件，在 Inspector 中展开 Code 部分，将 fx:id 设置为`itemCount`。

我们的用户界面虽然基本，但在这里已经尽可能完整，所以保存文件，关闭 Scene Builder，并返回到 NetBeans。

# 保存用户偏好设置

为了让我们新定义的用户界面与我们的控制器连接，我们需要创建与设置了`fx:id`属性的控件相匹配的实例变量，因此，我们将这些添加到`PreferencesController`中，如下所示：

```java
    @FXML 
    protected Button savePrefs; 
    @FXML 
    protected Button cancel; 
    @FXML 
    protected TabPane tabPane; 

```

在`initialize()`方法中，我们需要添加对加载保存值的支持，因此我们需要稍微讨论一下偏好设置。

Java 作为通用语言，使得可以编写任何偏好存储策略。幸运的是，它还提供了一些不同的标准 API，允许您以更容易移植的方式进行操作，其中包括`Preferences`和`Properties`。

`java.util.Properties`类自 JDK 1.0 版本以来就存在，虽然它的基本、简约的 API 可能很明显，但它仍然是一个非常有用的抽象。在其核心，`Properties`是一个`Hashtable`的实现，它添加了从输入流和读取器加载数据以及将数据写入输出流和写入器的方法（除了一些其他相关的方法）。所有属性都被视为`String`值，具有`String`键。由于`Properties`是一个`Hashtable`，您仍然可以使用`put()`和`putAll()`来存储非字符串数据，但如果调用`store()`，这将导致`ClassCastException`，因此最好避免这样做。

`java.util.prefs.Preferences`类是在 Java 1.4 中添加的，它是一个更现代的 API。与属性不同，我们必须单独处理持久性，偏好设置为我们不透明地处理这一点--我们不需要担心它是如何或何时写入的。实际上，设置偏好设置的调用可能会立即返回，而实际的持久性可能需要相当长的时间。`Preferences` API 的契约保证了即使 JVM 关闭，偏好设置也会被持久化，假设这是一个正常的、有序的关闭（根据定义，如果 JVM 进程突然死机，几乎没有什么可以做的）。

此外，用户也不需要担心偏好设置是如何保存的。实际的后备存储是一个特定于实现的细节。它可以是一个平面文件，一个特定于操作系统的注册表，一个数据库或某种目录服务器。对于好奇的人，实际的实现是通过使用类名来选择的，如果指定了的话，在`java.util.prefs.PreferencesFactory`系统属性中。如果没有定义，系统将查找文件`META-INF/services/java.util.prefs.PreferencesFactory`（这是一种称为 SPI 的机制，我们稍后会深入研究），并使用那里定义的第一个类。最后，如果失败，将加载和使用底层平台的实现。

那么应该选择哪一个呢？两者都可以正常工作，但您必须决定是否要控制信息存储的位置（`Properties`）或实现的便利性（`Preferences`）。在一定程度上，可移植性也可能是一个问题。例如，如果您的 Java 代码在某种移动设备或嵌入式设备上运行，您可能没有权限写入文件系统，甚至可能根本没有文件系统。然而，为了展示这两种实现可能有多相似，我们将同时实现两者。

为了坦率一点，我希望尽可能多的代码可以在 Android 环境中重复使用。为了帮助实现这一点，我们将创建一个非常简单的接口，如下所示：

```java
    public interface SunagoPreferences { 
      String getPreference(String key); 
      String getPreference(String key, String defaultValue); 
      Integer getPreference(String key, Integer defaultValue); 
      void putPreference(String key, String value); 
      void putPreference(String key, Integer value); 
    } 

```

我们只处理字符串和整数，因为应用程序的需求非常基本。接口定义好了，我们如何获取对实现的引用呢？为此，我们将使用一种我们已经简要提到过的技术--服务提供者接口（SPI）。

# 使用服务提供者接口的插件和扩展

我们之前已经在查看`Preferences`类时提到过 SPI，以及如何选择和加载实现，但它到底是什么呢？服务提供者接口是一个相对通用的术语，用于指代第三方可以实现的接口（或者可以扩展的类，无论是否抽象），以提供额外的功能，替换现有组件等。

简而言之，目标系统的作者（例如，我们之前的例子中的 JDK 本身）定义并发布一个接口。理想情况下，该系统会提供一个默认实现，但并非所有情况都需要。任何感兴趣的第三方都可以实现这个接口，注册它，然后目标系统可以加载和使用它。这种方法的一个优点是，目标系统可以很容易地进行扩展，而不需要与第三方进行耦合。也就是说，虽然第三方通过接口了解目标系统，但目标系统对第三方一无所知。它只是根据自己定义的接口进行操作。

这些第三方插件是如何注册到目标系统的？第三方开发人员将在特定目录中使用特定文件创建一个文本文件。该文件的名称与正在实现的接口相同。例如，对于`Preferences`类的示例，将实现`java.util.prefs.PreferencesFactory`接口，因此该文件的名称将是该接口的名称，该文件将位于类路径根目录中的`META-INF/services`目录中。在基于 Maven 的项目中，该文件将在`src/main/resources/META-INF/services`中找到。该文件只包含实现接口的类的名称。也可以在服务文件中列出多个类，每个类占一行。但是，是否使用其中的每一个取决于消费系统。

那么对于我们来说，所有这些是什么样子的呢？正如前面所述，我们将有一个难得的机会展示我们的`Preferences`支持的多个实现。这两个类都足够小，我们可以展示`Properties`和`Preferences`的用法，并使用 SPI 来选择其中一个使用。

让我们从基于`Properties`的实现开始：

```java
    public class SunagoProperties implements SunagoPreferences { 
      private Properties props = new Properties(); 
      private final String FILE = System.getProperty("user.home")  
        + File.separator + ".sunago.properties"; 

      public SunagoProperties() { 
        try (InputStream input = new FileInputStream(FILE)) { 
          props.load(input); 
        } catch (IOException ex) { 
        } 
    } 

```

在上面的代码中，我们首先实现了我们的`SunagoPreferences`接口。然后我们创建了一个`Properties`类的实例，并且我们还为文件名和位置定义了一个常量，我们将其以一种与系统无关的方式放在用户的主目录中。

# 使用 try-with-resources 进行资源处理

构造函数显示了一个有趣的东西，我们还没有讨论过--try-with-resources。在 Java 8 之前，你可能会写出这样的代码：

```java
    public SunagoProperties(int a) { 
      InputStream input = null; 
      try { 
        input = new FileInputStream(FILE); 
        props.load(input); 
      } catch  (IOException ex) { 
        // do something 
      } finally { 
          if (input != null) { 
            try { 
                input.close(); 
            } catch (IOException ex1) { 
                Logger.getLogger(SunagoProperties.class.getName()) 
                  .log(Level.SEVERE, null, ex1); 
            } 
          } 
        } 
    } 

```

上面的代码在 try 块外声明了一个`InputStream`，然后在`try`块中对其进行了一些处理。在`finally`块中，我们尝试关闭`InputStream`，但首先必须检查它是否为 null。例如，如果文件不存在（因为这是该类创建的第一次），将抛出`Exception`，并且`input`将为 null。如果它不为 null，我们可以在其上调用`close()`，但这可能会引发`IOException`，因此我们还必须将其包装在`try/catch`块中。

Java 8 引入了 try-with-resources 结构，使得代码变得更加简洁。如果一个对象是`AutoCloseable`的实例，那么它可以在`try`声明中被定义，无论是否抛出`Exception`，当`try`块范围终止时，它都会被自动关闭。这使我们可以用更少的噪音将通常需要十四行代码来表达的功能表达为四行代码。

除了`AutoCloseable`之外，注意我们通过`Properties.load(InputStream)`将文件中的任何现有值加载到我们的`Properties`实例中。

接下来，我们看到的是非常简单的 getter 和 setter：

```java
    @Override 
    public String getPreference(String key) { 
      return props.getProperty(key); 
    } 

    @Override 
    public String getPreference(String key, String defaultValue) { 
      String value = props.getProperty(key); 
      return (value == null) ? defaultValue : value; 
    } 

    @Override 
    public Integer getPreference(String key, Integer defaultValue) { 
      String value = props.getProperty(key); 
      return (value == null) ? defaultValue :  
        Integer.parseInt(value); 
    } 

    @Override 
    public void putPreference(String key, String value) { 
      props.put(key, value); 
      store(); 
    } 

    @Override 
    public void putPreference(String key, Integer value) { 
      if (value != null) { 
        putPreference(key, value.toString()); 
      } 
    } 

```

最后一个方法是将我们的偏好设置重新写出的方法，如下所示：

```java
    private void store() { 
      try (OutputStream output = new FileOutputStream(FILE)) { 
        props.store(output, null); 
      } catch (IOException e) { } 
    } 

```

这个最后一个方法看起来很像我们的构造函数，但我们创建了一个`OutputStream`，并调用`Properties.store(OutputStream)`将我们的值写入文件。请注意，我们从每个 put 方法调用此方法，以尽可能确保用户偏好设置被忠实地保存到磁盘上。

基于偏好设置的实现会是什么样子？并没有太大的不同。

```java
    public class SunagoPreferencesImpl implements SunagoPreferences { 
      private final Preferences prefs = Preferences.userRoot() 
        .node(SunagoPreferencesImpl.class.getPackage() 
        .getName()); 
      @Override 
      public String getPreference(String key) { 
        return prefs.get(key, null); 
      } 
      @Override 
      public String getPreference(String key, String defaultValue) { 
        return prefs.get(key, defaultValue); 
      } 

      @Override 
      public Integer getPreference(String key,Integer defaultValue){ 
        return prefs.getInt(key, defaultValue); 
      } 
      @Override 
      public void putPreference(String key, String value) { 
        prefs.put(key, value); 
      } 
      @Override 
      public void putPreference(String key, Integer value) { 
        prefs.putInt(key, value); 
      } 
    } 

```

有两件事需要注意。首先，我们不需要处理持久性，因为`Preferences`已经为我们做了。其次，`Preferences`实例的实例化需要一些注意。显然，我认为，我们希望这些偏好设置是针对用户的，因此我们从`Preferences.userRoot()`开始获取根偏好设置节点。然后我们要求存储我们偏好设置的节点，我们选择将其命名为我们类的包的名称。

这样放置的东西在哪里？在 Linux 上，文件可能看起来像`~/.java/.userPrefs/_!':!bw"t!#4!cw"0!'`!~@"w!'w!~@"z!'8!~g"0!#4!ag!5!')!c!!u!(:!d@"u!'%!~w"v!#4!}@"w!(!=/prefs.xml`（是的，那是一个目录名）。在 Windows 上，这些偏好设置保存在 Windows 注册表中，键为`HKEY_CURRENT_USER\SOFTWARE\JavaSoft\Prefs\com.steeplesoft.sunago.app`。但是，除非您想直接与这些文件交互，否则它们的确切位置和格式仅仅是实现细节。不过，有时候了解这些是件好事。

我们有两种实现，那么我们如何选择使用哪一种？在文件（包括源根以便清晰）`src/main/resources/META-INF/service/com.steeplesoft.sunago.api.SunagoPreferences`中，我们可以放置以下两行之一：

```java
    com.steeplesoft.sunago.app.SunagoPreferencesImpl 
    com.steeplesoft.sunago.app.SunagoProperties 

```

你可以列出两者，但只会选择第一个，我们现在将看到。为了简化，我们已经将其封装在一个实用方法中，如下所示：

```java
    private static SunagoPreferences preferences; 
    public static synchronized 
          SunagoPreferences getSunagoPreferences() { 
        if (preferences == null) { 
          ServiceLoader<SunagoPreferences> spLoader =  
            ServiceLoader.load(SunagoPreferences.class); 
          Iterator<SunagoPreferences> iterator = 
            spLoader.iterator(); 
          preferences = iterator.hasNext() ? iterator.next() : null; 
        } 
        return preferences; 
    } 

```

在这里可能有点过度，我们通过将`SunagoPreferences`接口的实例声明为私有静态实现了单例，并通过一个同步方法使其可用，该方法检查`null`，并在需要时创建实例。

虽然这很有趣，但不要让它让你分心。我们使用`ServiceLoader.load()`方法向系统请求`SunagoPreferences`接口的任何实现。值得再次注意的是，为了明确起见，它不会捡起**任何**系统中的实现，而只会捡起我们之前描述的服务文件中列出的**那些**。使用`ServiceLoader<SunagoPreferences>`实例，我们获取一个迭代器，如果它有一个条目（`iterator.hasNext()`），我们返回该实例（`iterator.next()`）。如果没有，我们返回`null`。这里有一个`NullPointerException`的机会，因为我们返回`null`，但我们也提供了一个实现，所以我们避免了这种风险。然而，在您自己的代码中，您需要确保像我们在这里所做的那样有一个实现，或者确保消费代码是`null`-ready。

# 添加一个网络 - Twitter

到目前为止，我们有一个非常基本的应用程序，可以保存和加载其偏好设置，但让我们开始连接社交网络，这才是我们在这里的目的。我们希望开发一个框架，使得轻松添加对不同社交网络的支持成为可能。从技术上讲，正如我们很快会看到的那样，**网络**甚至不需要是社交的，因为唯一会暗示特定类型来源的是所涉及的类和接口的名称。然而，事实上，我们将专注于社交网络，并且我们将使用一些不同的社交网络来展示一些多样性。为此，我们将从 Twitter 开始，这是一个非常受欢迎的微博平台，以及 Instagram，这是一个越来越注重照片的网络，现在已经成为 Facebook 的一部分。

说到 Facebook，为什么我们不演示与该社交网络的集成？有两个原因--一，它与 Twitter 没有显著不同，因此没有太多新内容需要涵盖；二，更重要的是，Facebook 提供的权限几乎不可能以对我们感兴趣的方式集成。例如，读取用户的主页时间线（或墙）的权限仅授予针对那些 Facebook 当前不可用的平台的应用程序，而且根本不授予桌面应用程序，而这正是我们的目标。

如前所述，我们希望能够在不更改核心应用程序的情况下公开添加更多网络的方法，因此我们需要开发一个 API。我们将在这里介绍一个或多或少**完成**状态的 API（任何软件真的会完成吗？）。然而，虽然您将看到一个相当完整的 API，但需要注意一点——试图从头开始创建一个抽象的尝试很少有好的结果。最好是编写一个具体的实现来更好地理解所需的细节，然后提取一个抽象。您在这里看到的是这个过程的最终结果，因此这个过程不会在这里深入讨论。

# 注册为 Twitter 开发者

要创建一个与 Twitter 集成的应用程序，我们需要创建一个 Twitter 开发者帐户，然后创建一个 Twitter 应用程序。要创建帐户，我们需要访问[`dev.twitter.com`](https://dev.twitter.com/)，然后点击加入按钮。创建开发者帐户后，您可以点击我的应用链接转到[`apps.twitter.com`](https://apps.twitter.com/)。在这里，我们需要点击创建新应用程序按钮，这将为我们提供一个看起来有点像这样的表单：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-prog-bp/img/e752561f-28a8-4dcc-a226-30986a4e13a8.png)

虽然我们正在开发的应用程序被称为*Sunago*，但您将无法使用该名称，因为它已经被使用；您将需要创建一个自己独特的名称，假设您打算自己运行该应用程序。创建应用程序后，您将被带到新应用程序的应用程序管理页面。从这个页面，您可以管理应用程序的权限和密钥，如果需要，还可以删除应用程序。

在这个页面上需要注意的一件事是，我们很快就会需要的应用程序的 Consumer Key 和 Secret 的位置。这些是长的，包含字母和数字的字符串，您的应用程序将使用它们来验证 Twitter 的服务。代表用户与 Twitter 互动的最终目标需要一组不同的令牌，我们很快就会获取。您的 Consumer Key 和 Secret，尤其是 Consumer Secret，应该保密。如果这个组合被公开，其他用户就可以冒充您的应用程序，如果他们滥用服务，可能会给您带来严重的麻烦。因此，您不会在本书或源代码中看到我生成的密钥/秘钥组合，这就是为什么您需要生成自己的组合。

现在拥有了我们的 Consumer Key 和 Secret，我们需要决定如何与 Twitter 交流。Twitter 提供了一个公共的 REST API，在他们的网站上有文档。如果我们愿意，我们可以选择某种 HTTP 客户端，并开始调用。然而，出于简单和清晰的考虑，更不用说健壮性、容错性等等，我们可能更好地使用某种更高级的库。幸运的是，有这样一个库，Twitter4J，它将使我们的集成更简单、更清晰（对于好奇的人来说，Twitter4J 有 200 多个 Java 类。虽然我们不需要所有这些功能，但它应该让您了解编写 Twitter 的 REST 接口的合理封装所需的工作范围）。

如前所述，我们希望能够在不更改核心应用程序的情况下向 Sunago 添加网络，因此我们将在一个单独的 Maven 模块中编写我们的 Twitter 集成。这将需要将我们已经为 Sunago 编写的一些代码提取到另一个模块中。然后我们的 Twitter 模块和主应用程序模块将依赖于这个新模块。由于我们将有多个模块参与，我们将确保指出每个类属于哪个模块。完成后，我们的项目依赖图将如下所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-prog-bp/img/f6941c98-9f1e-449b-b2be-2dfad92ae836.png)

从技术上讲，我们之所以显示应用程序模块和 Instagram 和 Twitter 模块之间的依赖关系，是因为我们正在将它们作为同一项目的一部分构建。正如我们将看到的那样，第三方开发人员可以轻松地开发一个独立的模块，将其添加到应用程序的运行时类路径中，并在不涉及构建级别依赖的情况下看到应用程序的变化。不过，希望这个图表能帮助解释模块之间的关系。

# 将 Twitter 偏好添加到 Sunago

让我们从在偏好设置屏幕上添加 Twitter 开始。在我们进行任何集成之前，我们需要能够配置应用程序，或者更准确地说，Twitter 模块，以便它可以连接为特定用户。为了实现这一点，我们将向 API 模块添加一个新接口，如下所示：

```java
    public abstract class SocialMediaPreferencesController { 
      public abstract Tab getTab(); 
      public abstract void savePreferences(); 
    } 

```

这个接口将为 Sunago 提供两个钩子进入模块--一个是让模块有机会绘制自己的偏好用户界面，另一个是允许它保存这些偏好。然后我们可以在我们的模块中实现它。不过，在我们这样做之前，让我们看看应用程序将如何找到这些实现，以便它们可以被使用。为此，我们将再次转向 SPI。在 Sunago 的`PreferencesController`接口中，我们添加了这段代码：

```java
    private List<SocialMediaPreferencesController> smPrefs =  
      new ArrayList<>(); 
    @Override 
    public void initialize(URL url, ResourceBundle rb) { 
      itemCount.setText(SunagoUtil.getSunagoPreferences() 
       .getPreference(SunagoPrefsKeys.ITEM_COUNT.getKey(), "50")); 
      final ServiceLoader<SocialMediaPreferencesController>  
       smPrefsLoader = ServiceLoader.load( 
         SocialMediaPreferencesController.class); 
       smPrefsLoader.forEach(smp -> smPrefs.add(smp)); 
       smPrefs.forEach(smp -> tabPane.getTabs().add(smp.getTab())); 
    } 

```

我们有一个实例变量来保存我们找到的任何`SocialMediaPreferencesController`实例的列表。接下来，在`initialize()`中，我们调用现在熟悉的`ServiceLoader.load()`方法来查找任何实现，然后将其添加到我们之前创建的`List`中。一旦我们有了我们的控制器列表，我们就对每个控制器调用`getTab()`，将返回的`Tab`实例添加到`PreferencesController`接口的`tabPane`中。

加载部分澄清后，让我们现在来看一下 Twitter 偏好用户界面的实现。我们首先要实现控制器，以支持用户界面的这一部分，如下所示：

```java
    public class TwitterPreferencesController  
      extends SocialMediaPreferencesController { 
        private final TwitterClient twitter; 
        private Tab tab; 

        public TwitterPreferencesController() { 
          twitter = new TwitterClient(); 
        } 

        @Override 
        public Tab getTab() { 
          if (tab == null) { 
            tab = new Tab("Twitter"); 
            tab.setContent(getNode()); 
          } 

          return tab; 
    } 

```

我们将很快看一下`TwitterClient`，但首先，关于`getTab()`的一点说明。请注意，我们创建了`Tab`实例，我们需要返回它，但我们将其内容的创建委托给`getNode()`方法。`Tab.setContent()`允许我们完全替换选项卡的内容，这是我们接下来要使用的。`getNode()`方法看起来像这样：

```java
    private Node getNode() { 
      return twitter.isAuthenticated() ? buildConfigurationUI() : 
        buildConnectUI(); 
    } 

```

如果用户已经进行了身份验证，那么我们希望呈现一些配置选项。如果没有，那么我们需要提供一种连接到 Twitter 的方式。

```java
    private Node buildConnectUI() { 
      HBox box = new HBox(); 
      box.setPadding(new Insets(10)); 
      Button button = new Button(MessageBundle.getInstance() 
       .getString("connect")); 
      button.setOnAction(event -> connectToTwitter()); 

      box.getChildren().add(button); 

      return box; 
    } 

```

在这个简单的用户界面中，我们创建了一个`HBox`主要是为了添加一些填充。如果没有我们传递给`setPadding()`的`new Insets(10)`实例，我们的按钮将紧贴窗口的顶部和左边缘，这在视觉上是不吸引人的。接下来，我们创建了`Button`，并设置了`onAction`处理程序（暂时忽略构造函数参数）。

有趣的部分隐藏在`connectToTwitter`中，如下所示：

```java
    private void connectToTwitter() { 
      try { 
        RequestToken requestToken =  
          twitter.getOAuthRequestToken(); 
        LoginController.showAndWait( 
          requestToken.getAuthorizationURL(), 
           e -> ((String) e.executeScript( 
             "document.documentElement.outerHTML")) 
              .contains("You've granted access to"), 
               e -> { 
                 final String html =  
                   "<kbd aria-labelledby=\"code-desc\"><code>"; 
                    String body = (String) e.executeScript( 
                      "document.documentElement.outerHTML"); 
                    final int start = body.indexOf(html) +  
                     html.length(); 
                    String code = body.substring(start, start+7); 
                    saveTwitterAuthentication(requestToken, code); 
                    showConfigurationUI(); 
               }); 
      } catch (TwitterException ex) { 
        Logger.getLogger(getClass().getName()) 
          .log(Level.SEVERE, null, ex); 
      } 
    } 

```

# OAuth 和登录到 Twitter

我们将很快进入`LoginController`，但首先，让我们确保我们理解这里发生了什么。为了代表用户登录到 Twitter，我们需要生成一个 OAuth 请求令牌，从中获取授权 URL。这些细节被很好地隐藏在 Twitter4J API 的后面，但基本上，它是在应用程序管理页面上列出的 OAuth 授权 URL，带有作为查询字符串传递的请求令牌。正如我们将看到的那样，这个 URL 在`WebView`中打开，提示用户对 Twitter 进行身份验证，然后授权应用程序（或拒绝）：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-prog-bp/img/fc55781d-1f06-44c5-8e30-9a1fc0cce901.png)

如果用户成功进行了身份验证并授权了应用程序，`WebView`将被重定向到一个成功页面，显示一个我们需要捕获的数字代码，以完成收集所需的身份验证/授权凭据。成功页面可能如下所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-prog-bp/img/348599c5-134b-469d-87de-5f1b287bce0a.png)

对于不熟悉 OAuth 的人来说，这允许我们在现在和将来的任意时刻作为用户进行身份验证，而无需存储用户的实际密码。我们的应用程序与 Twitter 之间的这次握手的最终结果是一个令牌和令牌密钥，我们将传递给 Twitter 进行身份验证。只要这个令牌是有效的——用户可以随时通过 Twitter 的网络界面使其失效——我们就可以连接并作为该用户进行操作。如果密钥被泄露，用户可以撤销密钥，只影响预期的应用程序和任何试图使用被盗密钥的人。

`LoginController`是 API 模块的一部分，它为我们处理所有样板代码，如下所示：

```java
    public class LoginController implements Initializable { 
      @FXML 
      private WebView webView; 
      private Predicate<WebEngine> loginSuccessTest; 
      private Consumer<WebEngine> handler; 

      public static void showAndWait(String url,  
       Predicate<WebEngine> loginSuccessTest, 
       Consumer<WebEngine> handler) { 
         try { 
           fxmlLoader loader = new fxmlLoader(LoginController 
             .class.getResource("/fxml/login.fxml")); 

           Stage stage = new Stage(); 
           stage.setScene(new Scene(loader.load())); 
           LoginController controller =  
              loader.<LoginController>getController(); 
           controller.setUrl(url); 
           controller.setLoginSuccessTest(loginSuccessTest); 
           controller.setHandler(handler); 

           stage.setTitle("Login..."); 
           stage.initModality(Modality.APPLICATION_MODAL); 

           stage.showAndWait(); 
         } catch (IOException ex) { 
           throw new RuntimeException(ex); 
         } 
    } 

```

上述代码是一个基本的 FXML 支持的 JavaFX 控制器，但我们有一个静态的辅助方法来处理创建、配置和显示实例的细节。我们使用 FXML 加载场景，获取控制器（它是封闭类的实例），设置`loginSuccessTest`和`handler`属性，然后显示对话框。

`loginSuccessTest`和`handler`看起来奇怪吗？它们是 Java 8 功能接口`Predicate<T>`和`Consumer<T>`的实例。`Predicate`是一个功能接口，它接受一个类型，我们的情况下是`WebEngine`，并返回一个`boolean`。它旨在检查给定指定类型的变量的某个条件。在这种情况下，我们调用`WebEngine.executeScript().contains()`来提取文档的一部分，并查看它是否包含指示我们已被重定向到登录成功页面的某个文本片段。

`Consumer<T>`是一个功能接口（或者在我们的情况下，是一个 lambda），它接受指定类型的单个参数，并返回 void。我们的处理程序是一个`Consumer`，一旦我们的`Predicate`返回 true，就会被调用。Lambda 从 HTML 页面中提取代码，调用`saveTwitterAuthentication()`完成用户身份验证，然后调用`showConfigurationUI()`来更改用户界面，以便用户可以配置与 Twitter 相关的设置。

`saveTwitterAuthentication()`方法非常简单，如下所示：

```java
    private void saveTwitterAuthentication(RequestToken requestToken,
     String code) { 
       if (!code.isEmpty()) { 
         try { 
           AccessToken accessToken = twitter 
             .getAcccessToken(requestToken, code); 
           prefs.putPreference(TwitterPrefsKeys.TOKEN.getKey(),  
             accessToken.getToken()); 
           prefs.putPreference(TwitterPrefsKeys.TOKEN_SECRET.getKey(),  
             accessToken.getTokenSecret()); 
         } catch (TwitterException ex) { 
           Logger.getLogger(TwitterPreferencesController 
             .class.getName()).log(Level.SEVERE, null, ex); 
         } 
       } 
    } 

```

`twitter.getAccessToken()`方法接受我们的请求令牌和我们从网页中提取的代码，并向 Twitter REST 端点发送 HTTP `POST`，生成我们需要的令牌密钥。当该请求返回时，我们将令牌和令牌密钥存储到我们的`Preferences`存储中（再次，不知道在哪里和如何）。

`showConfigurationUI()`方法和相关方法也应该很熟悉。

```java
    private void showConfigurationUI() { 
      getTab().setContent(buildConfigurationUI()); 
    } 
    private Node buildConfigurationUI() { 
      VBox box = new VBox(); 
      box.setPadding(new Insets(10)); 

      CheckBox cb = new CheckBox(MessageBundle.getInstance() 
        .getString("homeTimelineCB")); 
      cb.selectedProperty().addListener( 
        (ObservableValue<? extends Boolean> ov,  
          Boolean oldVal, Boolean newVal) -> { 
            showHomeTimeline = newVal; 
          }); 

      Label label = new Label(MessageBundle.getInstance() 
        .getString("userListLabel") + ":"); 

      ListView<SelectableItem<UserList>> lv = new ListView<>(); 
      lv.setItems(itemList); 
      lv.setCellFactory(CheckBoxListCell.forListView( 
        item -> item.getSelected())); 
      VBox.setVgrow(lv, Priority.ALWAYS); 

      box.getChildren().addAll(cb, label, lv); 
      showTwitterListSelection(); 

      return box;
    } 

```

在上述方法中的一个新项目是我们添加到`CheckBox`的`selectedProperty`的监听器。每当选定的值发生变化时，我们的监听器被调用，它设置`showHomeTimeline`布尔值的值。

`ListView`也需要特别注意。注意参数化类型`SelectableItem<UserList>`。那是什么？那是我们创建的一个抽象类，用于包装`CheckBoxListCell`中使用的项目，你可以在对`setCellFactory()`的调用中看到。该类看起来像这样：

```java
    public abstract class SelectableItem<T> { 
      private final SimpleBooleanProperty selected =  
        new SimpleBooleanProperty(false); 
      private final T item; 
      public SelectableItem(T item) { 
        this.item = item; 
      } 
      public T getItem() { 
        return item; 
      } 
      public SimpleBooleanProperty getSelected() { 
        return selected; 
      } 
    } 

```

这个类位于 API 模块中，是一个简单的包装器，包装了一个任意类型，添加了一个`SimpleBooleanProperty`。我们看到当设置单元格工厂时如何操作这个属性——`lv.setCellFactory(CheckBoxListCell .forListView(item -> item.getSelected()))`。我们通过`getSelected()`方法公开`SimpleBooleanProperty`，`CheckBoxListCell`使用它来设置和读取每行的状态。

我们最后一个与用户界面相关的方法是这样的：

```java
    private void showTwitterListSelection() { 
      List<SelectableItem<UserList>> selectable =  
        twitter.getLists().stream() 
         .map(u -> new SelectableUserList(u)) 
         .collect(Collectors.toList()); 
      List<Long> selectedListIds = twitter.getSelectedLists(prefs); 
      selectable.forEach(s -> s.getSelected() 
        .set(selectedListIds.contains(s.getItem().getId()))); 
      itemList.clear(); 
      itemList.addAll(selectable); 
    } 

```

使用相同的`SelectableItem`类，我们从 Twitter 请求用户可能创建的所有列表，我们将其包装在`SelectableUserList`中，这是`SelectableItem`的子类，覆盖`toString()`方法以在`ListView`中提供用户友好的文本。我们从首选项加载任何选中的列表，设置它们各自的布尔值/复选框，并更新我们的`ObservableList`，从而更新用户界面。

我们需要实现的最后一个方法来满足`SocialMediaPreferencesController`合同是`savePreferences()`，如下所示：

```java
    public void savePreferences() { 
      prefs.putPreference(TwitterPrefsKeys.HOME_TIMELINE.getKey(),  
       Boolean.toString(showHomeTimeline)); 
      List<String> selectedLists = itemList.stream() 
       .filter(s -> s != null) 
       .filter(s -> s.getSelected().get()) 
       .map(s -> Long.toString(s.getItem().getId())) 
       .collect(Collectors.toList()); 
      prefs.putPreference(TwitterPrefsKeys.SELECTED_LISTS.getKey(),  
       String.join(",", selectedLists)); 
    } 

```

这主要是将用户的选项保存到偏好设置中，但是列表处理值得一提。我们可以使用流并应用一对`filter()`操作来剔除对我们没有兴趣的条目，然后将通过的每个`SelectableUserList`映射到`Long`（即列表的 ID），然后将它们收集到`List<String>`中。我们使用`String.join()`连接该`List`，并将其写入我们的偏好设置。

# 为 Twitter 添加一个模型

还有一些其他接口我们需要实现来完成我们的 Twitter 支持。第一个，也是更简单的一个是`SocialMediaItem`：

```java
    public interface SocialMediaItem { 
      String getProvider(); 
      String getTitle(); 
      String getBody(); 
      String getUrl(); 
      String getImage(); 
      Date getTimestamp(); 
    } 

```

这个前面的接口为我们提供了一个很好的抽象，可以在不太拖沓的情况下返回社交网络可能返回的各种类型的数据，而不会被大多数（或至少很多）网络不使用的字段所拖累。这个`Tweet`类的 Twitter 实现如下：

```java
    public class Tweet implements SocialMediaItem { 
      private final Status status; 
      private final String url; 
      private final String body; 

      public Tweet(Status status) { 
        this.status = status; 
        body = String.format("@%s: %s (%s)",  
          status.getUser().getScreenName(), 
          status.getText(), status.getCreatedAt().toString()); 
        url = String.format("https://twitter.com/%s/status/%d", 
          status.getUser().getScreenName(), status.getId()); 
    } 

```

我们使用 Twitter4J 类`Status`提取我们感兴趣的信息，并将其存储在实例变量中（它们的 getter 没有显示，因为它们只是简单的 getter）。对于`getImage()`方法，我们会合理努力从推文中提取任何图像，如下所示：

```java
    public String getImage() { 
      MediaEntity[] mediaEntities = status.getMediaEntities(); 
      if (mediaEntities.length > 0) { 
        return mediaEntities[0].getMediaURLHttps(); 
      } else { 
          Status retweetedStatus = status.getRetweetedStatus(); 
          if (retweetedStatus != null) { 
            if (retweetedStatus.getMediaEntities().length > 0) { 
              return retweetedStatus.getMediaEntities()[0] 
               .getMediaURLHttps(); 
            } 
          } 
        } 
      return null; 
    } 

```

# 实现 Twitter 客户端

第二个接口是`SocialMediaClient`。这个接口不仅作为 Sunago 可以用来与任意社交网络集成交互的抽象，还作为一个指南，向有兴趣的开发人员展示集成的最低要求。它看起来像这样：

```java
    public interface SocialMediaClient { 
      void authenticateUser(String token, String tokenSecret); 
      String getAuthorizationUrl(); 
      List<? Extends SocialMediaItem> getItems(); 
      boolean isAuthenticated(); 
    } 

```

对于 Twitter 支持，这个前面的接口由类`TwitterClient`实现。大部分类都很基本，所以我们不会在这里重复（如果您想了解详情，可以在源代码库中查看），但是一个实现细节可能值得花一些时间。那个方法是`processList()`，如下所示：

```java
    private List<Tweet> processList(long listId) { 
      List<Tweet> tweets = new ArrayList<>(); 

      try { 
        final AtomicLong sinceId = new AtomicLong( 
          getSinceId(listId)); 
        final Paging paging = new Paging(1,  
          prefs.getPreference(SunagoPrefsKeys. 
          ITEM_COUNT.getKey(), 50), sinceId.get()); 
        List<Status> statuses = (listId == HOMETIMELINE) ?  
          twitter.getHomeTimeline(paging) : 
           twitter.getUserListStatuses(listId, paging); 
        statuses.forEach(s -> { 
          if (s.getId() > sinceId.get()) { 
            sinceId.set(s.getId()); 
          } 
          tweets.add(new Tweet(s)); 
        }); 
        saveSinceId(listId, sinceId.get()); 
      } catch (TwitterException ex) { 
          Logger.getLogger(TwitterClient.class.getName()) 
           .log(Level.SEVERE, null, ex); 
        } 
        return tweets; 
    } 

```

在这个最后的方法中有几件事情。首先，我们想限制实际检索的推文数量。如果这是应用程序首次使用，或者长时间以来首次使用，可能会有大量的推文。检索所有这些推文在网络使用、内存和处理时间方面都会非常昂贵。我们使用 Twitter4J 的`Paging`对象来实现这个限制。

我们也不想检索我们已经拥有的推文，所以对于每个列表，我们保留一个`sinceId`，我们可以传递给 Twitter API。它将使用这个来查找 ID 大于`sinceId`的指定数量的推文。

将所有这些封装在`Paging`对象中，如果列表 ID 为`-1`（我们用来标识主页时间线的内部 ID），我们调用`twitter.getHomeTimeline()`，或者对于用户定义的列表，我们调用`twitter.getUserListStatus()`。对于每个返回的`Status`，我们更新`sinceId`（我们使用`AtomicLong`对其进行建模，因为在 lambda 内部使用的任何方法变量必须是 final 或有效 final），并将推文添加到我们的`List`中。在退出之前，我们将列表的`sinceId`存储在我们的内存存储中，然后返回 Twitter 列表的推文。

# 国际化和本地化的简要介绍

虽然有些基本，但我们与 Twitter 的集成现在已经完成，因为它满足了我们对网络的功能要求。然而，还有一段代码需要我们快速看一下。在之前的一些代码示例中，您可能已经注意到了类似这样的代码：`MessageBundle.getInstance().getString("homeTimelineCB")`。那是什么，它是做什么的？

`MessageBundle`类是 JDK 提供的国际化和本地化设施（也称为 i18n 和 l10n，其中数字代表从单词中删除的字母数量以缩写）的一个小包装器。该类的代码如下：

```java
    public class MessageBundle { 
      ResourceBundle messages =  
        ResourceBundle.getBundle("Messages", Locale.getDefault()); 

      private MessageBundle() { 
      } 

      public final String getString(String key) { 
        return messages.getString(key); 
      } 

      private static class LazyHolder { 
        private static final MessageBundle INSTANCE =  
          new MessageBundle(); 
      } 

      public static MessageBundle getInstance() { 
        return LazyHolder.INSTANCE; 
      } 
    } 

```

这里有两个主要的注意事项。我们将从`getInstance()`方法的类末尾开始。这是所谓的**按需初始化持有者**（**IODH**）模式的一个示例。在 JVM 中有一个`MessageBundle`类的单个静态实例。但是，直到调用`getInstance()`方法之前，它才会被初始化。这是通过利用 JVM 加载和初始化静态的方式实现的。一旦类以任何方式被引用，它就会被加载到`ClassLoader`中，此时类上的任何静态都将被初始化。私有静态类`LazyHolder`直到 JVM 确信需要访问它之前才会被初始化。一旦我们调用`getInstance()`，它引用`LazyHolder.INSTANCE`，类就被初始化并创建了单例实例。

应该注意的是，我们正在尝试实现的单例性质有办法绕过（例如，通过反射），但是我们在这里的用例并不需要担心这样的攻击。

实际功能是在类的第一行实现的，如下所示

```java
    ResourceBundle messages =  
      ResourceBundle.getBundle("Messages", Locale.getDefault()); 

```

`ResourceBundle`文件在 Javadoc 的话语中*包含特定于区域设置的对象*。通常，这意味着字符串，就像在我们的情况下一样。`getBundle()`方法将尝试查找并加载具有指定区域设置的给定名称的包。在我们的情况下，我们正在寻找一个名为`Messages`的包。从技术上讲，我们正在寻找一个具有共享基本名称`Messages`的包系列中的包。系统将使用指定的`Locale`来查找正确的文件。此解析将遵循`Locale`使用的相同查找逻辑，因此`getBundle()`方法将返回具有最具体匹配名称的包。

假设我们在我的计算机上运行此应用程序。我住在美国，因此我的系统默认区域设置是`en_US`。然后，根据`Locale`查找规则，`getBundle()`将尝试按照以下顺序定位文件：

1.  `Messages_en_US.properties`。

1.  `Messages_en.properties`。

1.  `Messages.properties`。

系统将从最具体的文件到最不具体的文件，直到找到所请求的键。如果在任何文件中找不到，将抛出`MissingResourceException`。每个文件都由键/值对组成。我们的`Messages.properties`文件如下所示：

```java
    homeTimelineCB=Include the home timeline 
    userListLabel=User lists to include 
    connect=Connect 
    twitter=Twitter 

```

它只是一个简单的键到本地化文本的映射。我们可以在`Messages_es.properties`中使用这一行：

```java
    userListLabel=Listas de usuarios para incluir 

```

如果这是文件中唯一的条目，那么文件中的一个标签将是西班牙语，其他所有内容都将是默认的`Message.properties`，在我们的情况下是英语。

# 制作我们的 JAR 文件变得臃肿

有了这个，我们的实现现在已经完成。但在可以按照我们的意图使用之前，我们需要进行构建更改。如果您回忆一下本章开头对需求的讨论，我们希望构建一个系统，可以轻松让第三方开发人员编写模块，以添加对任意社交网络的支持，而无需修改核心应用程序。为了提供这种功能，这些开发人员需要提供一个 JAR 文件，Sunago 用户可以将其放入文件夹中。启动应用程序后，新功能现在可用。

然后，我们需要打包所有所需的代码。目前，项目创建了一个单一的 JAR，其中只包含我们的类。不过，这还不够，因为我们依赖于 Twitter4J jar。其他模块可能有更多的依赖项。要求用户放入半打甚至更多的 jar 可能有点过分。幸运的是，Maven 有一个机制，可以让我们完全避免这个问题：shade 插件。

通过在我们的构建中配置这个插件，我们可以生成一个单一的 jar 文件，其中包含我们项目中声明的每个依赖项的类和资源。这通常被称为**fat jar**，具体如下：

```java
    <build> 
      <plugins> 
        <plugin> 
          <artifactId>maven-shade-plugin</artifactId> 
            <version>${plugin.shade}</version> 
              <executions> 
                <execution> 
                  <phase>package</phase> 
                    <goals> 
                      <goal>shade</goal> 
                    </goals> 
                  </execution> 
              </executions> 
        </plugin> 
      </plugins> 
    </build> 

```

这是一个官方的 Maven 插件，所以我们可以省略`groupId`，并且我们在 POM 的继承树上定义了一个名为`plugin.shade`的属性。当运行 package 阶段时，该插件的 shade 目标将执行并构建我们的 fat jar。

```java
$ ll target/*.jar
  total 348
  -rwx------+ 1 jason None  19803 Nov 20 19:22 original-twitter-1.0-
  SNAPSHOT.jar
  -rwx------+ 1 jason None 325249 Nov 20 19:22 twitter-1.0-
  SNAPSHOT.jar  

```

原始的 jar 文件，大小相当小，被重命名为`original-twitter-1.0-SNAPSHOT.jar`，而 fat jar 接收配置的最终名称。就是这个 fat jar 被安装在本地 maven 仓库中，或者部署到像 Artifactory 这样的构件管理器中。

不过有一个小 bug。我们的 twitter 模块依赖于 API 模块，以便它可以看到应用程序暴露的接口和类。目前，即使这些都包含在 fat jar 中，我们也不希望这样，因为在某些情况下，这可能会导致一些`ClassLoader`问题。为了防止这种情况，我们将该依赖标记为`provided`，如下所示：

```java
    <dependency> 
      <groupId>${project.groupId}</groupId> 
      <artifactId>api</artifactId> 
      <version>${project.version}</version> 
      <scope>provided</scope> 
    </dependency> 

```

如果我们现在执行`mvn clean install`，我们将得到一个只包含我们需要捆绑的类的漂亮的 fat jar，并且准备好进行分发。

为了尽可能简单，我们只需要在 Sunago 的应用模块中声明对这个 jar 的依赖，如下所示：

```java
    <dependencies> 
      <dependency> 
        <groupId>${project.groupId}</groupId> 
        <artifactId>api</artifactId> 
        <version>${project.version}</version> 
      </dependency> 
      <dependency> 
        <groupId>${project.groupId}</groupId> 
        <artifactId>twitter</artifactId> 
        <version>${project.version}</version> 
      </dependency> 
    </dependencies> 

```

如果我们现在运行 Sunago，我们将看到 Twitter 添加到我们的设置屏幕上，并且一旦连接和配置，我们将看到推文显示在主屏幕上。我们还会注意到主屏幕有点单调，更重要的是，没有提供任何刷新内容的方式，所以让我们来解决这个问题。

# 添加一个刷新按钮

在项目窗口中，找到`sunago.fxml`，右键单击它，然后选择`Edit`。我们将手动进行这个用户界面的更改，只是为了体验。向下滚动，直到找到关闭的`Menubar`标签(`</Menubar>`)。在那之后的一行，插入这些行：

```java
    <ToolBar > 
      <items> 
        <Button fx:id="refreshButton" /> 
        <Button fx:id="settingsButton" /> 
      </items> 
    </ToolBar> 

```

在`SunagoController`中，我们需要添加实例变量如下：

```java
    @FXML 
    private Button refreshButton; 
    @FXML 
    private Button settingsButton; 

```

然后，在`initialize()`中，我们需要像这样设置它们：

```java
    refreshButton.setGraphic(getButtonImage("/images/reload.png")); 
    refreshButton.setOnAction(ae -> loadItemsFromNetworks()); 
    refreshButton.setTooltip(new Tooltip("Refresh")); 

    settingsButton.setGraphic(getButtonImage("/images/settings.png")); 
    settingsButton.setOnAction(ae -> showPreferences(ae)); 
    settingsButton.setTooltip(new Tooltip("Settings")); 

```

请注意，我们做的不仅仅是设置一个动作处理程序。我们做的第一件事是调用`setGraphic()`。从我们讨论的 Twitter 首选项选项卡中记得，调用`setGraphic()`将用你指定的`Node`替换子节点。在这两种情况下，该`Node`是一个`ImageView`，来自`getButtonImage()`方法。

```java
    private ImageView getButtonImage(String path) { 
      ImageView imageView = new ImageView( 
        new Image(getClass().getResourceAsStream(path))); 
      imageView.setFitHeight(32); 
      imageView.setPreserveRatio(true); 
      return imageView; 
    } 

```

在设置动作处理程序之后，我们还设置了一个工具提示。当用户用鼠标悬停在按钮上时，这将为我们的图形按钮提供一个文本描述，如下图所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-prog-bp/img/dcf381cf-be06-40e4-bdc5-42afe47ba32e.png)

刷新按钮的动作处理程序值得一看，如下所示：

```java
    private void loadItemsFromNetworks() { 
      List<SocialMediaItem> items = new ArrayList<>(); 
      clientLoader.forEach(smc -> { 
        if (smc.isAuthenticated()) { 
            items.addAll(smc.getItems()); 
        } 
      }); 

      items.sort((o1, o2) ->  
        o2.getTimestamp().compareTo(o1.getTimestamp())); 
      entriesList.addAll(0, items); 
    } 

```

这是我们从`initialize()`中调用的相同方法。使用我们之前讨论过的服务提供者接口，我们遍历系统中可用的每个`SocialMediaClient`。如果客户端已对其网络进行了身份验证，我们调用`getItems()`方法，并将其返回的任何内容添加到本地变量`items`中。一旦我们查询了系统中配置的所有网络，我们就对列表进行排序。这将导致各种网络的条目交错在一起，因为它们按照时间戳按降序排列。然后，将排序后的列表添加到我们的`ObservableList`的头部，或者第零个元素，以使它们出现在用户界面的顶部。

# 添加另一个网络 - Instagram

为了演示我们定义的接口如何使添加新网络相对快速和容易，以及让我们看到另一种集成类型，让我们向 Sunago 添加一个网络--Instagram。尽管 Instagram 是 Facebook 旗下的，但在撰写本文时，其 API 比这家社交媒体巨头更为宽松，因此我们能够相对轻松地添加一个有趣的集成。

与 Twitter 一样，我们需要考虑如何处理与 Instragram API 的交互。就像 Twitter 一样，Instagram 提供了一个使用 OAuth 进行保护的公共 REST API。同样，手动实现一个客户端来消费这些 API 并不是一个吸引人的选择，因为需要付出大量的努力。除非有充分的理由编写自己的客户端库，否则我建议如果有可用的客户端包装器，应该优先使用。幸运的是，有--jInstagram。

# 注册为 Instagram 开发者

在开始编写我们的客户端之前，我们需要在服务中注册一个新的 Instagram 客户端。我们可以通过首先在[`www.instagram.com/developer`](https://www.instagram.com/developer)创建（如果需要）一个 Instagram 开发者帐户。一旦有了帐户，我们需要通过单击页面上的“注册您的应用程序”按钮或直接访问[`www.instagram.com/developer/clients/manage/`](https://www.instagram.com/developer/clients/manage/)来注册我们的应用程序。从这里，我们需要单击“注册新客户端”，将呈现此表单：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-prog-bp/img/c71218c7-fd93-42a3-a406-0fd6450b5365.png)

注册新客户端后，您可以单击生成的网页上的“管理”按钮，获取客户端 ID 和密钥。记住这些信息，因为您一会儿会用到它们。

接下来，我们将通过创建一个新模块来启动实际的客户端，就像我们为 Twitter 模块所做的那样。不过，这次我们将把它命名为`Sunago - Instagram`和`artifactIdinstagram`。我们还将添加 jInstagram 依赖，如下所示：

```java
    <artifactId>instagram</artifactId> 
    <name>Sunago - Instagram</name> 
    <packaging>jar</packaging> 
    <dependencies> 
      <dependency> 
        <groupId>${project.groupId}</groupId> 
        <artifactId>api</artifactId> 
        <version>${project.version}</version> 
        <scope>provided</scope> 
      </dependency> 
      <dependency> 
        <groupId>com.sachinhandiekar</groupId> 
        <artifactId>jInstagram</artifactId> 
        <version>1.1.8</version> 
      </dependency> 
    </dependencies> 

```

请注意，我们已经添加了 Sunago `api`依赖项，并将其范围设置为提供。我们还需要添加 Shade 插件配置，它看起来与 Twitter 模块中的配置相同，因此这里不再显示。

# 实现 Instagram 客户端

创建了新模块后，我们需要创建三个特定的项目来满足 Sunago API 模块提供的合同。我们需要`SocialMediaPreferencesController`、`SocialMediaClient`和`SocialMediaItem`。

我们的`SocialMediaPreferencesController`实例是`InstagramPreferencesController`。它具有与接口所需的相同的`getTab()`方法，如下所示：

```java
    public Tab getTab() { 
      if (tab == null) { 
        tab = new Tab(); 
        tab.setText("Instagram"); 
        tab.setContent(getNode()); 
      } 

      return tab; 
    } 

    private Node getNode() { 
      Node node = instagram.isAuthenticated() 
        ? buildConfigurationUI() : buildConnectUI(); 
      return node; 
    } 

```

为了节省时间和空间，对于本示例，我们将 Instagram 的实现留得比我们为 Twitter 创建的实现更基本，因此用户界面定义并不那么有趣。但是，认证处理很有趣，因为尽管它使用与 Twitter 相同的 OAuth 流程，但返回的数据更容易消化。连接按钮调用此方法：

```java
    private static final String CODE_QUERY_PARAM = "code="; 
    private void showConnectWindow() { 
      LoginController.showAndWait(instagram.getAuthorizationUrl(), 
        e -> e.getLocation().contains(CODE_QUERY_PARAM), 
        e -> { 
          saveInstagramToken(e.getLocation()); 
          showInstagramConfig(); 
        }); 
    } 

```

这使用了我们在 Twitter 中看到的`LoginController`，但是我们的`Predicate`和`Consumer`要简洁得多。用户被重定向到的页面在 URL 中有代码作为查询参数，因此无需解析 HTML。我们可以直接从 URL 中提取它如下：

```java
    private void saveInstagramToken(String location) { 
      int index = location.indexOf(CODE_QUERY_PARAM); 
      String code = location.substring(index +  
        CODE_QUERY_PARAM.length()); 
      Token accessToken = instagram. 
        verifyCodeAndGetAccessToken(code); 
      instagram.authenticateUser(accessToken.getToken(),  
        accessToken.getSecret()); 
    } 

```

一旦我们有了代码，我们就可以使用`instagram`对象上的 API 来获取访问令牌，然后我们使用它来验证用户。那么`instagram`对象是什么样子的呢？像`TwitterClient`一样，`InstagramClient`是一个包装 jInstagram API 的`SocialMediaClient`。

```java
    public final class InstagramClient implements
    SocialMediaClient { 

      private final InstagramService service; 
      private Instagram instagram; 

```

jInstagram API 有两个我们需要使用的对象。`InstagramService`封装了 OAuth 逻辑。我们使用构建器获取它的实例如下：

```java
    service = new InstagramAuthService() 
     .apiKey(apiKey) 
     .apiSecret(apiSecret) 
     .callback("http://blogs.steeplesoft.com") 
     .scope("basic public_content relationships follower_list") 
     .build(); 

```

如前所述，要在本地运行应用程序，您需要提供自己的 API 密钥和密钥对。我们对回调 URL 的唯一用途是为 Instagram 提供一个重定向我们客户端的地方。一旦它这样做，我们就从查询参数中提取代码，就像我们之前看到的那样。最后，我们必须提供一个权限列表，这就是 Instagram 称之为权限的东西。这个列表将允许我们获取经过身份验证的用户关注的帐户列表，我们将用它来获取图片：

```java
    @Override 
    public List<? extends SocialMediaItem> getItems() { 
      List<Photo> items = new ArrayList<>(); 
      try { 
        UserFeed follows = instagram.getUserFollowList("self"); 
        follows.getUserList().forEach(u ->  
          items.addAll(processMediaForUser(u))); 
      } catch (InstagramException ex) { 
        Logger.getLogger(InstagramClient.class.getName()) 
          .log(Level.SEVERE, null, ex); 
      } 

      return items; 
    } 

```

如果您阅读了 jInstagram 文档，您可能会想使用`instagram.getUserFeeds()`方法，如果您这样做，您会得到我得到的东西-一个`404`错误页面。Instagram 已经对其 API 进行了一些工作，而 jInstagram 尚未反映。因此，我们需要为此实现自己的包装器，jInstagram 使这变得相当简单。在这里，我们获取用户关注的人的列表。对于每个用户，我们调用`processMediaForUser()`来获取和存储任何待处理的图片。

```java
    private List<Photo> processMediaForUser(UserFeedData u) { 
      List<Photo> userMedia = new ArrayList<>(); 
      try { 
        final String id = u.getId(); 
        instagram.getRecentMediaFeed(id, 
          prefs.getPreference(SunagoPrefsKeys.ITEM_COUNT 
            .getKey(), 50), 
          getSinceForUser(id), null, null, null).getData() 
            .forEach(m -> userMedia.add(new Photo(m))); 
        if (!userMedia.isEmpty()) { 
          setSinceForUser(id, userMedia.get(0).getId()); 
        } 
      } catch (InstagramException ex) { 
        Logger.getLogger(InstagramClient.class.getName()) 
          .log(Level.SEVERE, null, ex); 
      } 
      return userMedia; 
    } 

```

使用与 Twitter 客户端相同的**since ID**和最大计数方法，我们请求用户的任何最新媒体。每个返回的项目都被（通过 lambda）包装成`Photo`实例，这是我们的 Instagram 的`SocialMediaItem`子类。一旦我们有了列表，如果它不为空，我们就获取第一个`Photo`，我们知道它是最老的，因为这是 Instagram API 返回数据的方式，然后我们获取 ID，将其存储为下次调用此方法时的 since ID。最后，我们返回`List`，以便将其添加到之前给出的主`Photo`列表中。

# 在 Sunago 中加载我们的插件

有了这个，我们的新集成就完成了。要看它的运行情况，我们将依赖项添加到 Sunago 的 POM 中如下：

```java
    <dependency> 
      <groupId>${project.groupId}</groupId> 
      <artifactId>instagram</artifactId> 
      <version>${project.version}</version> 
    </dependency> 

```

然后我们运行应用程序。

显然，为每个新集成添加一个依赖项并不是一个理想的解决方案，即使只是因为用户不会从 IDE 或 Maven 中运行应用程序。因此，我们需要一种方法让应用程序在用户的机器上在运行时找到任何模块（或插件，如果您更喜欢这个术语）。最简单的解决方案是通过像这样的 shell 脚本启动应用程序：

```java
    #!/bin/bash 
    JARS=sunago-1.0-SNAPSHOT.jar 
    SEP=: 
    for JAR in `ls ~/.sunago/*.jar` ; do 
      JARS="$JARS$SEP$JAR" 
    done 

    java -cp $JARS com.steeplesoft.sunago.app.Sunago 

```

上述 shell 脚本使用主 Sunago jar 和`~/.sunago`中找到的任何 JAR 来创建类路径，然后运行应用程序。这很简单有效，但需要每个操作系统版本。幸运的是，这只需要为 Mac 和 Linux 编写这个 shell 脚本，以及为 Windows 编写一个批处理文件。这并不难做或难以维护，但需要您能够访问这些操作系统来测试和验证您的脚本。

另一个选择是利用类加载器。尽管大声说出来可能很简单，但`ClassLoader`只是负责加载类（和其他资源）的对象。在任何给定的 JVM 中，都有几个类加载器以分层方式工作，从引导`ClassLoader`开始，然后是平台`ClassLoader`，最后是系统--或应用程序--`ClassLoader`。可能一个给定的应用程序或运行时环境，比如**Java 企业版**（**Java EE**）应用服务器，可能会将一个或多个`ClassLoader`实例添加为应用程序`ClassLoader`的子级。这些添加的`ClassLoader`实例可能是分层的，也可能是**同级**。无论哪种情况，它们几乎肯定是应用程序`ClassLoader`的子级。

对类加载器及其所涉及的所有内容的全面处理远远超出了本书的范围，但可以说，我们可以创建一个新的`ClassLoader`来允许应用程序在我们的**插件**jar 中找到类和资源。为此，我们需要向我们的应用程序类 Sunago 添加几种方法--确切地说是三种。我们将从构造函数开始：

```java
    public Sunago() throws Exception { 
      super(); 
      updateClassLoader(); 
    } 

```

通常（虽然并非总是如此），当 JavaFX 应用程序启动时，会运行`public static void main`方法，该方法调用`Application`类上的`launch()`静态方法，我们对其进行子类化。根据`javafx.application.Application`的 Javadoc，JavaFX 运行时在启动应用程序时执行以下步骤：

1.  构造指定的`Application`类的实例。

1.  调用`init()`方法。

1.  调用`start(javafx.stage.Stage)`方法。

1.  等待应用程序完成，当发生以下任何一种情况时：

1.  应用程序调用`Platform.exit()`。

1.  最后一个窗口已经关闭，平台上的`implicitExit`属性为 true。

1.  调用`stop()`方法。

我们希望在第 1 步，在我们的`Application`的构造函数中执行我们的`ClassLoader`工作，以确保后续的一切都有最新的`ClassLoader`。这项工作是我们需要添加的第二种方法，就是这个：

```java
    private void updateClassLoader() { 
      final File[] jars = getFiles(); 
      if (jars != null) { 
        URL[] urls = new URL[jars.length]; 
        int index = 0; 
        for (File jar : jars) { 
          try { 
            urls[index] = jar.toURI().toURL(); 
            index++; 
          } catch (MalformedURLException ex) { 
              Logger.getLogger(Sunago.class.getName()) 
               .log(Level.SEVERE, null, ex); 
            } 
        } 
        Thread.currentThread().setContextClassLoader( 
          URLClassLoader.newInstance(urls)); 
      } 
    } 

```

我们首先要获取一个 jar 文件列表（我们马上就会看到那段代码），然后，如果数组不为空，我们需要构建一个`URL`数组，所以我们遍历`File`数组，并调用`.toURI().toURL()`来实现。一旦我们有了`URL`数组，我们就创建一个新的`ClassLoader`（`URLClassLoader.newInstance(urls)`），然后通过`Thread.currentThread().setContextClassLoader()`为当前线程设置`ClassLoader`。

这是我们最后的额外方法`getFiles()`：

```java
    private File[] getFiles() { 
      String pluginDir = System.getProperty("user.home")  
       + "/.sunago"; 
      return new File(pluginDir).listFiles(file -> file.isFile() &&  
       file.getName().toLowerCase().endsWith(".jar")); 
    } 

```

这最后的方法只是简单地扫描`$HOME/.sunago`中的文件，寻找以`.jar`结尾的文件。返回零个或多个 jar 文件的列表供我们的调用代码包含在新的`ClassLoader`中，我们的工作就完成了。

所以你有两种动态将插件 jar 添加到运行时的方法。每种方法都有其优点和缺点。第一种需要多平台开发和维护，而第二种有点风险，因为类加载器可能会有些棘手。我已经在 Windows 和 Linux 以及 Java 8 和 9 上测试了第二种方法，没有发现错误。你使用哪种方法，当然取决于你独特的环境和要求，但至少你有两种选项可以开始评估。

# 总结

话虽如此，我们的应用程序已经完成。当然，几乎没有软件是真正完成的，Sunago 还有很多可以做的事情。Twitter 支持可以扩展到包括直接消息。Instagram 模块需要添加一些配置选项。虽然 Facebook API 公开的功能有限，但可以添加某种有意义的 Facebook 集成。Sunago 本身可以进行修改，比如添加对社交媒体内容的应用内查看支持（而不是切换到主机操作系统的默认浏览器）。还有一些可以解决的小的用户体验问题。列表可以继续下去。然而，我们所拥有的是一个相当复杂的网络应用程序，它展示了 Java 平台的许多功能和能力。我们构建了一个可扩展的、国际化的 JavaFX 应用程序，展示了服务提供者接口和`ClassLoader`魔术的使用，并提供了许多关于 lambda、流操作和函数接口的更多示例。

在下一章中，我们将在这里提出的想法基础上构建，并构建 Sunago 的 Android 移植版，这样我们就可以随时随地进行社交媒体聚合。
