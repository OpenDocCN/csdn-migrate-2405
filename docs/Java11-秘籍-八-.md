# Java11 秘籍（八）

> 原文：[`zh.annas-archive.org/md5/2bf50d1e2a61626a8f3de4e5aae60b76`](https://zh.annas-archive.org/md5/2bf50d1e2a61626a8f3de4e5aae60b76)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十二章：使用 JShell 的读取-评估-打印循环（REPL）

在本章中，我们将涵盖以下内容：

+   熟悉 REPL

+   导航 JShell 及其命令

+   评估代码片段

+   JShell 中的面向对象编程

+   保存和恢复 JShell 命令历史

+   使用 JShell Java API

# 介绍

**REPL**代表**读取-评估-打印循环**，正如其名称所示，它读取在命令行上输入的命令，评估它，打印评估结果，并在输入任何命令时继续此过程。

所有主要语言，如 Ruby、Scala、Python、JavaScript 和 Groovy，都有 REPL 工具。Java 一直缺少这个必不可少的 REPL。如果我们要尝试一些示例代码，比如使用`SimpleDateFormat`解析字符串，我们必须编写一个包含所有仪式的完整程序，包括创建一个类，添加一个主方法，然后是我们想要进行实验的单行代码。然后，我们必须编译和运行代码。这些仪式使得实验和学习语言的特性变得更加困难。

使用 REPL，您只需输入您感兴趣的代码行，并且您将立即得到有关表达式是否在语法上正确并且是否给出所需结果的反馈。REPL 是一个非常强大的工具，特别适合初次接触该语言的人。假设您想展示如何在 Java 中打印*Hello World*；为此，您必须开始编写类定义，然后是`public static void main(String [] args)`方法，最后您将解释或尝试解释许多概念，否则对于新手来说将很难理解。

无论如何，从 Java 9 开始，Java 开发人员现在可以停止抱怨缺少 REPL 工具。一个名为 JShell 的新的 REPL 被捆绑到了 JDK 安装中。因此，我们现在可以自豪地将*Hello World*作为我们的第一个*Hello World*代码。

在本章中，我们将探索 JShell 的特性，并编写代码，这些代码将真正使我们惊叹并欣赏 REPL 的力量。我们还将看到如何使用 JShell Java API 创建我们自己的 REPL。

# 熟悉 REPL

在这个配方中，我们将看一些基本操作，以帮助我们熟悉 JShell 工具。

# 准备工作

确保您安装了最新的 JDK 版本，其中包含 JShell。JShell 从 JDK 9 开始可用。

# 如何做...

1.  您应该将`%JAVA_HOME%/bin`（在 Windows 上）或`$JAVA_HOME/bin`（在 Linux 上）添加到您的`PATH`变量中。如果没有，请访问第一章中的*在 Windows 上安装 JDK 18.9 并设置 PATH 变量*和*在 Linux（Ubuntu，x64）上安装 JDK 18.9 并配置 PATH 变量*这两个配方。

1.  在命令行上，输入`jshell`并按*Enter*。

1.  您将看到一条消息，然后是一个`jshell>`提示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java11-cb/img/e2b2e440-013a-437a-b2fe-0667e558a108.png)

1.  斜杠(`/`)，后跟 JShell 支持的命令，可帮助您与 JShell 进行交互。就像我们尝试`/help intro`以获得以下内容：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java11-cb/img/5c77960d-77a3-4adc-b739-afbe540bc99c.png)

1.  让我们打印一个`Hello World`消息：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java11-cb/img/91029a86-a887-453e-b956-f2970368704a.png)

1.  让我们打印一个自定义的`Hello World`消息：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java11-cb/img/446baf78-c749-42d9-9e80-b174d6a0168f.png)

1.  您可以使用上下箭头键浏览执行的命令。

# 它是如何工作的...

在`jshell`提示符中输入的代码片段被包装在足够的代码中以执行它们。因此，变量、方法和类声明被包装在一个类中，表达式被包装在一个方法中，该方法又被包装在一个类中。其他东西，如导入和类定义，保持原样，因为它们是顶级实体，即在另一个类定义中包装一个类定义是不需要的，因为类定义是一个可以独立存在的顶级实体。同样，在 Java 中，导入语句可以单独出现，它们出现在类声明之外，因此不需要被包装在一个类中。

在接下来的示例中，我们将看到如何定义一个方法，导入其他包，并定义类。

在前面的示例中，我们看到了`$1 ==> "Hello World"`。如果我们有一些值没有与之关联的变量，`jshell`会给它一个变量名，如`$1`或`$2`。

# 导航 JShell 及其命令

为了利用工具，我们需要熟悉如何使用它，它提供的命令以及我们可以使用的各种快捷键，以提高生产力。在这个示例中，我们将看看我们可以通过 JShell 导航的不同方式，以及它提供的不同键盘快捷键，以便在使用它时提高生产力。

# 如何做...

1.  通过在命令行上键入`jshell`来生成`JShell`。您将收到一个欢迎消息，其中包含开始的说明。

1.  键入`/help intro`以获得关于 JShell 的简要介绍：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java11-cb/img/b70a0a34-b052-4ee7-913d-280051978691.png)

1.  键入`/help`以获取支持的命令列表：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java11-cb/img/eaef19b9-06dc-4b27-a94f-e613306bf0cc.png)

1.  要获取有关命令的更多信息，请键入`/help <command>`。例如，要获取有关`/edit`的信息，请键入`/help /edit`：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java11-cb/img/9b27e73d-2cc1-4d0d-b575-201dfd8ad866.png)

1.  JShell 中有自动补全支持。这使得 Java 开发人员感到宾至如归。您可以使用*Tab*键来调用自动补全：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java11-cb/img/be642668-7b04-4b58-89a2-2377e5816a36.png)

1.  您可以使用`/!`来执行先前执行的命令，使用`/line_number`在行号重新执行表达式。

1.  要通过命令行导航光标，使用*Ctrl* + *A*到达行的开头，使用*Ctrl* + *E*到达行的结尾。

# 评估代码片段

在这个示例中，我们将看到执行以下代码片段：

+   导入语句

+   类声明

+   接口声明

+   方法声明

+   字段声明

+   语句

# 如何做...

1.  打开命令行并启动 JShell。

1.  默认情况下，JShell 导入了一些库。我们可以通过发出`/imports`命令来检查：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java11-cb/img/53d40193-23d2-4d38-9add-d41744f823a0.png)

1.  通过发出`import java.text.SimpleDateFormat`命令来导入`java.text.SimpleDateForm`。这将导入`SimpleDateFormat`类。

1.  让我们声明一个`Employee`类。我们将每行发出一个语句，以便它是一个不完整的语句，并且我们将以与任何普通编辑器相同的方式进行。下面的插图将澄清这一点：

```java
        class Employee{
          private String empId;
          public String getEmpId() {
            return empId;
          }
          public void setEmpId ( String empId ) {
            this.empId = empId;
          }
        }

```

您将得到以下输出：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java11-cb/img/f1891d8e-b111-4e17-8bfe-6507c85e19c3.png)

1.  让我们声明一个`Employability`接口，它定义了一个名为`employable()`的方法，如下面的代码片段所示：

```java
        interface Employability { 
          public boolean employable();
        }
```

通过`jshell`创建的前面的接口如下截图所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java11-cb/img/c9c87021-e754-422a-ae41-94d6894e703c.png)

1.  让我们声明一个`newEmployee(String empId)`方法，它用给定的`empId`构造一个`Employee`对象：

```java
        public Employee newEmployee(String empId ) {
          Employee emp = new Employee();
          emp.setEmpId(empId);
          return emp;
        }
```

JShell 中定义的前面的方法如下所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java11-cb/img/9bd0dddc-3b37-433a-ad81-33da5acb6c52.png)

1.  我们将使用前一步中定义的方法来创建一个声明`Employee`变量的语句：

```java
        Employee e = newEmployee("1234");
e.get + Tab key generates autocompletion as supported by the IDEs:
```

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java11-cb/img/8b923e7a-b343-4711-8557-b54d6aab68fe.png)

# 还有更多...

我们可以调用一个未定义的方法。看一下下面的例子：

```java
public void newMethod(){
  System.out.println("New  Method");
  undefinedMethod();
}
```

下面的图片显示了`newMethod()`调用`undefinedMethod()`的定义：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java11-cb/img/5a00c521-41c3-4a74-9c11-8cd8eb7e0b36.png)

但是，在使用方法之前，不能调用该方法：

```java
public void undefinedMethod(){
  System.out.println("Now defined");
}
```

下面的图片显示了定义`undefinedMethod()`，然后可以成功调用`newMethod()`：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java11-cb/img/98ba3d0a-baba-47c9-aa22-c64fdbe1fde4.png)

只有在我们定义了`undefinedMethod()`之后才能调用`newMethod()`。

# JShell 中的面向对象编程

在这个示例中，我们将使用预定义的 Java 类定义文件并将它们导入到 JShell 中。然后，我们将在 JShell 中使用这些类。

# 如何做...

1.  我们将在这个示例中使用的类定义文件在本书的代码下载中的`Chapter12/4_oo_programming`中可用。

1.  有三个类定义文件：`Engine.java`，`Dimensions.java`和`Car.java`。

1.  导航到这三个类定义文件可用的目录。

1.  `/open`命令允许我们从文件中加载代码。

1.  加载`Engine`类定义并创建一个`Engine`对象：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java11-cb/img/7b878742-330f-4cb5-aef2-7b8394a76bb2.png)

1.  加载`Dimensions`类定义并创建一个`Dimensions`对象：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java11-cb/img/4998d93c-85f2-4174-abe9-fbf9719054a0.png)

1.  加载`Car`类定义并创建一个`Car`对象：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java11-cb/img/d0ee5237-e262-4cd5-82f3-fa32cba224f5.png)

# 保存和恢复 JShell 命令历史

我们将尝试在`jshell`中执行一些代码片段，作为向新手解释 Java 编程的手段。此外，记录执行的代码片段的形式对于正在学习语言的人将是有用的。

在这个示例中，我们将执行一些代码片段并将它们保存到一个文件中。然后我们将从保存的文件中加载代码片段。

# 如何做...

1.  让我们执行一系列的代码片段，如下所示：

```java
        "Hello World"
        String msg = "Hello, %s. Good Morning"
        System.out.println(String.format(msg, "Friend"))
        int someInt = 10
        boolean someBool = false
        if ( someBool ) {
          System.out.println("True block executed");
        }
        if ( someBool ) {
          System.out.println("True block executed");
        }else{
          System.out.println("False block executed");
        }
        for ( int i = 0; i < 10; i++ ){
          System.out.println("I is : " + i );
        }
```

您将得到以下输出：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java11-cb/img/3a9285e5-04ba-4e58-b76f-f9a75bf7c4a1.png)

1.  使用`/save history`命令将执行的代码片段保存到名为`history`的文件中。

1.  使用`dir`或`ls`退出 shell，并列出目录中的文件，具体取决于操作系统。列表中将会有一个`history`文件。

1.  打开`jshell`并使用`/list`检查执行的代码片段的历史记录。您会看到没有执行任何代码片段。

1.  使用`/open history`加载`history`文件，然后使用`/list`检查执行的代码片段的历史记录。您将看到所有先前执行的代码片段被执行并添加到历史记录中：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java11-cb/img/47ce2ead-0eb4-4a84-8a94-0b4c07917ad0.png)

# 使用 JShell Java API

JDK 11 提供了用于评估 Java 代码片段的工具（如`jshell`）的 Java API。这个 Java API 存在于`jdk.jshell`模块中（[`cr.openjdk.java.net/~rfield/arch/doc/jdk/jshell/package-summary.html`](http://cr.openjdk.java.net/~rfield/arch/doc/jdk/jshell/package-summary.html)）。因此，如果您想在应用程序中使用 API，您需要声明对`jdk.jshell`模块的依赖。

在这个示例中，我们将使用 JShell JDK API 来评估简单的代码片段，并且您还将看到不同的 API 来获取 JShell 的状态。这个想法不是重新创建 JShell，而是展示如何使用其 JDK API。

在这个示例中，我们将不使用 JShell；相反，我们将按照通常的方式使用`javac`进行编译，并使用`java`进行运行。

# 如何做...

1.  我们的模块将依赖于`jdk.jshell`模块。因此，模块定义将如下所示：

```java
        module jshell{
          requires jdk.jshell;
        }
```

1.  使用`jdk.jshell.JShell`类的`create()`方法或`jdk.jshell.JShell.Builder`中的构建器 API 创建一个实例：

```java
        JShell myShell = JShell.create();
```

1.  使用`java.util.Scanner`从`System.in`中读取代码片段：

```java
        try(Scanner reader = new Scanner(System.in)){
          while(true){
            String snippet = reader.nextLine();
            if ( "EXIT".equals(snippet)){
              break;
            }
          //TODO: Code here for evaluating the snippet using JShell API
          }
        }
```

1.  使用`jdk.jshell.JShell#eval(String snippet)`方法来评估输入。评估将导致`jdk.jshell.SnippetEvent`的列表，其中包含评估的状态和输出。上述代码片段中的`TODO`将被以下行替换：

```java
        List<SnippetEvent> events = myShell.eval(snippet);
        events.stream().forEach(se -> {
          System.out.print("Evaluation status: " + se.status());
          System.out.println(" Evaluation result: " + se.value());
        });
```

1.  当评估完成时，我们将使用`jdk.jshell.JShell.snippets()`方法打印处理的代码片段，该方法将返回已处理的`Snippet`的`Stream`。

```java
        System.out.println("Snippets processed: ");
        myShell.snippets().forEach(s -> {
          String msg = String.format("%s -> %s", s.kind(), s.source());
          System.out.println(msg);
        });
```

1.  类似地，我们可以打印活动方法和变量，如下所示：

```java
        System.out.println("Methods: ");
        myShell.methods().forEach(m -> 
          System.out.println(m.name() + " " + m.signature()));

        System.out.println("Variables: ");
        myShell.variables().forEach(v -> 
          System.out.println(v.typeName() + " " + v.name()));
```

1.  在应用程序退出之前，我们通过调用其`close()`方法关闭`JShell`实例：

```java
        myShell.close();
```

此示例的代码可以在`Chapter12/6_jshell_api`中找到。您可以使用同一目录中提供的`run.bat`或`run.sh`脚本来运行示例。示例执行和输出如下所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java11-cb/img/47744154-6e86-4218-b780-966a546e8b13.png)

# 工作原理...

```java
eval(String snippet) method. We can even drop the previously-evaluated snippet using the drop(Snippet snippet) method. Both these methods result in a change of the internal state maintained by jdk.jshell.JShell.
```

传递给`JShell`评估引擎的代码片段被分类如下：

+   **错误**：语法错误的输入

+   **表达式**：可能会产生一些输出的输入

+   **导入**：导入语句

+   **方法**：方法声明

+   **语句**：语句

+   类型声明：类型，即类/接口声明

+   **变量声明**：变量声明

所有这些类别都在`jdk.jshell.Snippet.Kind`枚举中捕获。

```java
jdk.jshell.Snippet class.
```


# 第十三章：使用新的日期和时间 API

在本章中，我们将介绍以下内容：

+   如何构建不依赖于时区的日期和时间实例

+   如何构建依赖于时区的时间实例

+   如何创建日期间的基于日期的周期

+   如何创建基于时间的时间实例之间的周期

+   如何表示纪元时间

+   如何操作日期和时间实例

+   如何比较日期和时间

+   如何处理不同的日历系统

+   如何使用`DateTimeFormatter`格式化日期

# 介绍

使用`java.util.Date`和`java.util.Calendar`对于 Java 开发人员来说是一种痛苦，直到 Stephen Colebourne ([`www.joda.org/`](http://www.joda.org/))引入了 Joda-Time ([`www.joda.org/joda-time/`](http://www.joda.org/joda-time/))，这是一个用于在 Java 中处理日期和时间的库。Joda-Time 相对于 JDK API 提供了以下优势：

+   更丰富的 API 用于获取日期组件，如月份的日、星期的日、月份和年份，以及时间组件，如小时、分钟和秒。

+   轻松操作和比较日期和时间。

+   可用的既不依赖于时区又依赖于时区的 API。大多数情况下，我们将使用不依赖于时区的 API，这样更容易使用 API。

+   令人惊叹的 API，可以计算日期和时间之间的持续时间。

+   日期格式化和持续时间计算默认遵循 ISO 标准。

+   支持多个日历，如公历、佛历和伊斯兰历。

Joda-Time 启发了 JSR-310 ([`jcp.org/en/jsr/detail?id=310`](https://jcp.org/en/jsr/detail?id=310))，将 API 移植到了`java.time`包下，并作为 Java 8 的一部分发布。由于新的日期/时间 API 基于 ISO 标准，因此可以轻松地在应用程序的不同层之间集成日期/时间库。例如，在 JavaScript 层，我们可以使用 moment.js ([`momentjs.com/docs/`](https://momentjs.com/docs/))处理日期和时间，并使用其默认格式化样式（符合 ISO 标准）将数据发送到服务器。在服务器层，我们可以使用新的日期/时间 API 根据需要获取日期和时间实例。因此，我们可以使用标准日期表示在客户端和服务器之间进行交互。

在本章中，我们将探讨利用新的日期/时间 API 的不同方法。

# 如何处理不依赖于时区的日期和时间实例

在 JSR-310 之前，要为任何时间点或日历中的任何一天创建日期和时间实例并不直观。唯一的方法是使用`java.util.Calendar`对象设置所需的日期和时间，然后调用`getTime()`方法获取`java.util.Date`的实例。这些日期和时间实例也包含时区信息，有时会导致应用程序中的错误。

在新的 API 中，获取日期和时间实例要简单得多，这些日期和时间实例不包含任何与时区相关的信息。在本示例中，我们将向您展示如何使用`java.time.LocalDate`表示仅日期的实例，使用`java.time.LocalTime`表示仅时间的实例，以及使用`java.time.LocalDateTime`表示日期/时间实例。这些日期和时间实例是不依赖于时区的，并表示机器的当前时区中的信息。

# 准备工作

您需要安装至少 JDK 8 才能使用这些更新的库，本章中的示例使用 Java 10 及更高版本支持的语法。如果您愿意，可以直接在 JShell 中运行这些代码片段。您可以访问第十二章，*使用 JShell 进行读取-求值-打印循环(REPL)*，了解更多关于 JShell 的信息。

# 如何做…

1.  使用`now()`方法可以获取包装在`java.time.LocalDate`中的当前日期，如下所示：

```java
var date = LocalDate.now();
```

1.  我们可以使用通用的`get(fieldName)`方法或特定的方法，如`getDayOfMonth()`、`getDayOfYear()`、`getDayOfWeek()`、`getMonth()`和`getYear()`来获取`java.time.LocalDate`实例的各个字段，如下所示：

```java
var dayOfWeek = date.getDayOfWeek();
var dayOfMonth = date.getDayOfMonth();
var month = date.getMonth();
var year = date.getYear();
```

1.  我们可以使用`of()`方法获取日历中任何日期的`java.time.LocalDate`实例，如下所示：

```java
var date1 = LocalDate.of(2018, 4, 12);
var date2 = LocalDate.of(2018, Month.APRIL, 12);
date2 = LocalDate.ofYearDay(2018, 102);
date2 = LocalDate.parse("2018-04-12");
```

1.  有`java.time.LocalTime`类，用于表示任何时间实例，而不考虑日期。可以使用以下方法获取当前时间：

```java
var time = LocalTime.now();
```

1.  `java.time.LocalTime`类还带有`of()`工厂方法，可用于创建表示任何时间的实例。类似地，有方法来获取时间的不同组件，如下所示：

```java
time = LocalTime.of(23, 11, 11, 11);
time = LocalTime.ofSecondOfDay(3600);

var hour = time.getHour();
var minutes = time.getMinute();
var seconds = time.get(ChronoField.SECOND_OF_MINUTE);
```

1.  `java.time.LocalDateTime`用于表示包含时间和日期的实体。它由`java.time.LocalDate`和`java.time.LocalTime`组成，分别表示日期和时间。可以使用`now()`和不同版本的`of()`工厂方法创建其实例，如下所示：

```java
var dateTime1 = LocalDateTime.of(2018, 04, 12, 13, 30, 22);
var dateTime2 = LocalDateTime.of(2018, Month.APRIL, 12, 13, 30, 22);
dateTime2 = LocalDateTime.of(date2, LocalTime.of(13, 30, 22));
```

# 它是如何工作的…

`java.time`包中的以下三个类代表默认时区（系统的时区）中的日期和时间值：

+   `java.time.LocalDate`: 只包含日期信息

+   `java.time.LocalTime`: 只包含时间信息

+   `java.time.LocalDateTime`: 包含日期和时间信息

每个类都由以下字段组成：

+   日期

+   月

+   年

+   小时

+   分钟

+   秒

+   毫秒

所有类都包含`now()`方法，返回当前的日期和时间值。提供了`of()`工厂方法来根据它们的字段（如日、月、年、小时和分钟）构建日期和时间实例。`java.time.LocalDateTime`由`java.time.LocalDate`和`java.time.LocalTime`组成，因此可以从`java.time.LocalDate`和`java.time.LocalTime`构建`java.time.LocalDateTime`。

从这个示例中学到的重要 API 如下：

+   `now()`: 这会给出当前日期和时间

+   `of()`: 这个工厂方法用于构造所需的日期、时间和日期/时间实例

# 还有更多…

在 Java 9 中，有一个新的 API，`datesUntil`，它接受结束日期并返回从当前对象的日期到结束日期（但不包括结束日期）的顺序日期流（换句话说，`java.time.LocalDate`）。使用此 API 将给定月份和年份的所有日期分组到它们各自的星期几，即星期一、星期二、星期三等。

让我们接受月份和年份，并将其分别存储在`month`和`year`变量中。范围的开始将是该月和年的第一天，如下所示：

```java
var startDate = LocalDate.of(year, month, 1);
```

范围的结束日期将是该月的天数，如下所示：

```java
var endDate = startDate.plusDays(startDate.lengthOfMonth());
```

我们正在使用`lengthOfMonth`方法获取该月的天数。然后我们使用`datesUntil`方法获取`java.time.LocalDate`的流，然后执行一些流操作：

+   按星期几对`java.time.LocalDate`实例进行分组。

+   将分组的实例收集到`java.util.ArrayList`中。但在此之前，我们正在应用转换将`java.time.LocalDate`实例转换为一个简单的月份，这给我们提供了一个表示月份的整数列表。

代码中的前两个操作如下所示：

```java
var dayBuckets = startDate.datesUntil(endDate).collect(

Collectors.groupingBy(date -> date.getDayOfWeek(), 
    Collectors.mapping(LocalDate::getDayOfMonth, 
        Collectors.toList())
));
```

此代码可以在下载的代码的`Chapter13/1_2_print_calendar`中找到。

# 如何构造依赖于时区的时间实例

在上一个示例中，*如何构造不依赖于时区的日期和时间实例*，我们构造了不包含任何时区信息的日期和时间对象。它们隐式地表示了系统时区中的值；这些类是`java.time.LocalDate`、`java.time.LocalTime`和`java.time.LocalDateTime`。

通常我们需要根据某个时区表示时间；在这种情况下，我们将使用`java.time.ZonedDateTime`，它包含了带有`java.time.LocalDateTime`的时区信息。时区信息是使用`java.time.ZoneId`或`java.time.ZoneOffset`实例嵌入的。还有两个类，`java.time.OffsetTime`和`java.time.OffsetDateTime`，它们也是`java.time.LocalTime`和`java.time.LocalDateTime`的特定于时区的变体。

在这个示例中，我们将展示如何使用`java.time.ZonedDateTime`、`java.time.ZoneId`、`java.time.ZoneOffset`、`java.time.OffsetTime`和`java.time.OffsetDateTime`。

# 准备工作

我们将使用 Java 10 的语法，使用`var`来声明局部变量和模块。除了 Java 10 及以上版本，没有其他先决条件。

# 操作步骤

1.  我们将使用`now()`工厂方法根据系统的时区获取当前的日期、时间和时区信息，如下所示：

```java
var dateTime = ZonedDateTime.now();
```

1.  我们将使用`java.time.ZoneId`根据任何给定的时区获取当前的日期和时间信息：

```java
var indianTz = ZoneId.of("Asia/Kolkata");
var istDateTime = ZonedDateTime.now(indianTz);
```

1.  `java.time.ZoneOffset`也可以用来提供日期和时间的时区信息，如下所示：

```java
var indianTzOffset = ZoneOffset.ofHoursMinutes(5, 30);
istDateTime = ZonedDateTime.now(indianTzOffset);
```

1.  我们将使用`of()`工厂方法构建`java.time.ZonedDateTime`的一个实例：

```java
ZonedDateTime dateTimeOf = ZonedDateTime.of(2018, 4, 22, 14, 30, 11, 33, indianTz);
```

1.  我们甚至可以从`java.time.ZonedDateTime`中提取`java.time.LocalDateTime`：

```java
var localDateTime = dateTimeOf.toLocalDateTime();
```

# 工作原理

首先，让我们看看如何捕获时区信息。它是根据**格林威治标准时间（GMT）**的小时和分钟数捕获的，也被称为协调世界时（UTC）。例如，印度标准时间（IST），也称为 Asia/Kolkata，比 GMT 提前 5 小时 30 分钟。

Java 提供了`java.time.ZoneId`和`java.time.ZoneOffset`来表示时区信息。`java.time.ZoneId`根据时区名称捕获时区信息，例如 Asia/Kolkata，US/Pacific 和 US/Mountain。大约有 599 个时区 ID。这是使用以下代码行计算的：

```java
jshell> ZoneId.getAvailableZoneIds().stream().count()
$16 ==> 599
```

我们将打印 10 个时区 ID：

```java
jshell> ZoneId.getAvailableZoneIds().stream().limit(10).forEach(System.out::println)
Asia/Aden
America/Cuiaba
Etc/GMT+9
Etc/GMT+8
Africa/Nairobi
America/Marigot
Asia/Aqtau
Pacific/Kwajalein
America/El_Salvador
Asia/Pontianak
```

时区名称，例如 Asia/Kolkata，Africa/Nairobi 和 America/Cuiaba，基于国际分配的数字管理局（IANA）发布的时区数据库。IANA 提供的时区区域名称是 Java 的默认值。

有时时区区域名称也表示为 GMT+02:30 或简单地+02:30，这表示当前时区与 GMT 时区的偏移（提前或落后）。

这个`java.time.ZoneId`捕获了`java.time.zone.ZoneRules`，其中包含了获取时区偏移转换和其他信息的规则，比如夏令时。让我们调查一下 US/Pacific 的时区规则：

```java
jshell> ZoneId.of("US/Pacific").getRules().getDaylightSavings(Instant.now())
$31 ==> PT1H

jshell> ZoneId.of("US/Pacific").getRules().getOffset(LocalDateTime.now())
$32 ==> -07:00

jshell> ZoneId.of("US/Pacific").getRules().getStandardOffset(Instant.now())
$33 ==> -08:00
```

`getDaylightSavings()`方法返回一个`java.time.Duration`对象，表示以小时、分钟和秒为单位的一些持续时间。默认的`toString()`实现返回使用 ISO 8601 基于秒的表示，其中 1 小时 20 分钟 20 秒的持续时间表示为`PT1H20M20S`。关于这一点将在本章的*如何在时间实例之间创建基于时间的期间*中进行更多介绍。

我们不会详细介绍它是如何计算的。对于那些想了解更多关于`java.time.zone.ZoneRules`和`java.time.ZoneId`的人，请访问[`docs.oracle.com/javase/10/docs/api/java/time/zone/ZoneRules.html`](https://docs.oracle.com/javase/10/docs/api/java/time/zone/ZoneRules.html)和[`docs.oracle.com/javase/10/docs/api/java/time/ZoneId.html`](https://docs.oracle.com/javase/10/docs/api/java/time/ZoneId.html)的文档。

`java.time.ZoneOffset`类以时区领先或落后 GMT 的小时和分钟数来捕获时区信息。让我们使用`of*()`工厂方法创建`java.time.ZoneOffset`类的一个实例：

```java
jshell> ZoneOffset.ofHoursMinutes(5,30)
$27 ==> +05:30
```

`java.time.ZoneOffset`类继承自`java.time.ZoneId`并添加了一些新方法。重要的是要记住根据应用程序中要使用的所需时区构造`java.time.ZoneOffset`和`java.time.ZoneId`的正确实例。

现在我们对时区表示有了了解，`java.time.ZonedDateTime`实际上就是`java.time.LocalDateTime`加上`java.time.ZoneId`或`java.time.ZoneOffset`。还有两个其他类，`java.time.OffsetTime`和`java.time.OffsetDateTime`，分别包装了`java.time.LocalTime`和`java.time.LocalDateTime`，以及`java.time.ZoneOffset`。

让我们看看一些构造`java.time.ZonedDateTime`实例的方法。

第一种方法是使用`now()`：

```java
Signatures:
ZonedDateTime ZonedDateTime.now()
ZonedDateTime ZonedDateTime.now(ZoneId zone)
ZonedDateTime ZonedDateTime.now(Clock clock)

jshell> ZonedDateTime.now()
jshell> ZonedDateTime.now(ZoneId.of("Asia/Kolkata"))
$36 ==> 2018-05-04T21:58:24.453113900+05:30[Asia/Kolkata]
jshell> ZonedDateTime.now(Clock.fixed(Instant.ofEpochSecond(1525452037), ZoneId.of("Asia/Kolkata")))
$54 ==> 2018-05-04T22:10:37+05:30[Asia/Kolkata]
```

`now()`的第一种用法使用系统时钟以及系统时区来打印当前日期和时间。`now()`的第二种用法使用系统时钟，但时区由`java.time.ZoneId`提供，这种情况下是 Asia/Kolkata。`now()`的第三种用法使用提供的固定时钟和`java.time.ZoneId`提供的时区。

使用`java.time.Clock`类及其静态方法`fixed()`创建固定时钟，该方法接受`java.time.Instant`和`java.time.ZoneId`的实例。`java.time.Instant`的实例是在纪元后的一些静态秒数后构建的。`java.time.Clock`用于表示新的日期/时间 API 可以用来确定当前时间的时钟。时钟可以是固定的，就像我们之前看到的那样，然后我们可以创建一个比 Asia/Kolkata 时区的当前系统时间提前一小时的时钟，如下所示：

```java
var hourAheadClock = Clock.offset(Clock.system(ZoneId.of("Asia/Kolkata")), Duration.ofHours(1));
```

我们可以使用这个新的时钟来构建`java.time.LocalDateTime`和`java.time.ZonedDateTime`的实例，如下所示：

```java
jshell> LocalDateTime.now(hourAheadClock)
$64 ==> 2018-05-04T23:29:58.759973700
jshell> ZonedDateTime.now(hourAheadClock)
$65 ==> 2018-05-04T23:30:11.421913800+05:30[Asia/Kolkata]
```

日期和时间值都基于相同的时区，即 Asia/Kolkata，但正如我们已经了解的那样，`java.time.LocalDateTime`没有任何时区信息，它基于系统的时区或在这种情况下提供的`java.time.Clock`的值。另一方面，`java.time.ZonedDateTime`包含并显示时区信息为[Asia/Kolkata]。

另一种创建`java.time.ZonedDateTime`实例的方法是使用其`of()`工厂方法：

```java
Signatures:
ZonedDateTime ZonedDateTime.of(LocalDate date, LocalTime time, ZoneId zone)
ZonedDateTime ZonedDateTime.of(LocalDateTime localDateTime, ZoneId zone)
ZonedDateTime ZonedDateTime.of(int year, int month, int dayOfMonth, int hour, int minute, int second, int nanoOfSecond, ZoneId zone)

jshell> ZonedDateTime.of(LocalDateTime.of(2018, 1, 1, 13, 44, 44), ZoneId.of("Asia/Kolkata"))
$70 ==> 2018-01-01T13:44:44+05:30[Asia/Kolkata]

jshell> ZonedDateTime.of(LocalDate.of(2018,1,1), LocalTime.of(13, 44, 44), ZoneId.of("Asia/Kolkata"))
$71 ==> 2018-01-01T13:44:44+05:30[Asia/Kolkata]

jshell> ZonedDateTime.of(LocalDate.of(2018,1,1), LocalTime.of(13, 44, 44), ZoneId.of("Asia/Kolkata"))
$72 ==> 2018-01-01T13:44:44+05:30[Asia/Kolkata]

jshell> ZonedDateTime.of(2018, 1, 1, 13, 44, 44, 0, ZoneId.of("Asia/Kolkata"))
$73 ==> 2018-01-01T13:44:44+05:30[Asia/Kolkata] 
```

# 还有更多...

我们提到了`java.time.OffsetTime`和`java.time.OffsetDateTime`类。两者都包含特定于时区的时间值。在我们结束这个教程之前，让我们玩一下这些类。

+   使用`of()`工厂方法：

```java
jshell> OffsetTime.of(LocalTime.of(14,12,34), ZoneOffset.ofHoursMinutes(5, 30))
$74 ==> 14:12:34+05:30

jshell> OffsetTime.of(14, 34, 12, 11, ZoneOffset.ofHoursMinutes(5, 30))
$75 ==> 14:34:12.000000011+05:30
```

+   使用`now()`工厂方法：

```java
Signatures:
OffsetTime OffsetTime.now()
OffsetTime OffsetTime.now(ZoneId zone)
OffsetTime OffsetTime.now(Clock clock)

jshell> OffsetTime.now()
$76 ==> 21:49:16.895192800+03:00

jshell> OffsetTime.now(ZoneId.of("Asia/Kolkata"))

jshell> OffsetTime.now(ZoneId.of("Asia/Kolkata"))
$77 ==> 00:21:04.685836900+05:30

jshell> OffsetTime.now(Clock.offset(Clock.systemUTC(), Duration.ofMinutes(330)))
$78 ==> 00:22:00.395463800Z
```

值得注意的是我们如何构建了一个`java.time.Clock`实例，它比 UTC 时钟提前了 330 分钟（5 小时 30 分钟）。另一个类`java.time.OffsetDateTime`与`java.time.OffsetTime`相同，只是它使用`java.time.LocalDateTime`。因此，您将向其工厂方法`of()`传递日期信息，即年、月和日，以及时间信息。

# 如何在日期实例之间创建基于日期的期间

在过去，我们曾试图测量两个日期实例之间的期间，但由于 Java 8 之前缺乏 API 以及缺乏捕获此信息的适当支持，我们采用了不同的方法。我们记得使用基于 SQL 的方法来处理这样的信息。但从 Java 8 开始，我们有了一个新的类`java.time.Period`，它可以用来捕获两个日期实例之间的期间，以年、月和日的数量来表示。

此外，该类支持解析基于 ISO 8601 标准的字符串来表示期间。该标准规定任何期间都可以用`PnYnMnD`的形式表示，其中**P**是表示期间的固定字符，**nY**表示年数，**nM**表示月数，**nD**表示天数。例如，2 年 4 个月 10 天的期间表示为`P2Y4M10D`。

# 准备工作

您至少需要 JDK8 来使用`java.time.Period`，需要 JDK 9 才能使用 JShell，并且至少需要 JDK 10 才能使用本示例中使用的示例。

# 如何做…

1.  让我们使用其`of()`工厂方法创建一个`java.time.Period`的实例，其签名为`Period.of(int years, int months, int days)`：

```java
jshell> Period.of(2,4,30)
$2 ==> P2Y4M30D
```

1.  还有特定变体的`of*()`方法，即`ofDays()`，`ofMonths()`和`ofYears()`，也可以使用：

```java
jshell> Period.ofDays(10)
$3 ==> P10D
jshell> Period.ofMonths(4)
$4 ==> P4M
jshell> Period.ofWeeks(3)
$5 ==> P21D
jshell> Period.ofYears(3)
$6 ==> P3Y
```

请注意，`ofWeeks()`方法是一个辅助方法，用于根据接受的周数构建`java.time.Period`。

1.  期间也可以使用期间字符串构造，该字符串通常采用`P<x>Y<y>M<z>D`的形式，其中`x`，`y`和`z`分别表示年、月和日的数量：

```java
jshell> Period.parse("P2Y4M23D").getDays()
$8 ==> 23
```

1.  我们还可以计算`java.time.ChronoLocalDate`的两个实例之间的期间（其实现之一是`java.time.LocalDate`）：

```java
jshell> Period.between(LocalDate.now(), LocalDate.of(2018, 8, 23))
$9 ==> P2M2D
jshell> Period.between(LocalDate.now(), LocalDate.of(2018, 2, 23))
$10 ==> P-3M-26D
```

这些是创建`java.time.Period`实例的最有用的方法。开始日期是包含的，结束日期是不包含的。

# 它是如何工作的…

我们利用`java.time.Period`中的工厂方法来创建其实例。`java.time.Period`有三个字段分别用于保存年、月和日的值，如下所示：

```java
/**
* The number of years.
*/
private final int years;
/**
* The number of months.
*/
private final int months;
/**
* The number of days.
*/
private final int days;
```

还有一组有趣的方法，即`withDays()`，`withMonths()`和`withYears()`。如果它正在尝试更新的字段具有相同的值，则这些方法返回相同的实例；否则，它返回一个具有更新值的新实例，如下所示：

```java
jshell> Period period1 = Period.ofWeeks(2)
period1 ==> P14D

jshell> Period period2 = period1.withDays(15)
period2 ==> P15D

jshell> period1 == period2
$19 ==> false

jshell> Period period3 = period1.withDays(14)
period3 ==> P14D

jshell> period1 == period3
$21 ==> true
```

# 还有更多…

我们甚至可以使用`java.time.ChronoLocalDate`中的`until()`方法计算两个日期实例之间的`java.time.Period`：

```java
jshell> LocalDate.now().until(LocalDate.of(2018, 2, 23))
$11 ==> P-3M-26D

jshell> LocalDate.now().until(LocalDate.of(2018, 8, 23))
$12 ==> P2M2D
```

给定`java.time.Period`的一个实例，我们可以使用它来操作给定的日期实例。有两种可能的方法：

+   使用期间对象的`addTo`或`subtractFrom`方法

+   使用日期对象的`plus`或`minus`方法

这两种方法都显示在以下代码片段中：

```java
jshell> Period period1 = Period.ofWeeks(2)
period1 ==> P14D

jshell> LocalDate date = LocalDate.now()
date ==> 2018-06-21

jshell> period1.addTo(date)
$24 ==> 2018-07-05

jshell> date.plus(period1)
$25 ==> 2018-07-05
```

同样，您可以尝试`subtractFrom`和`minus`方法。还有另一组用于操作`java.time.Period`实例的方法，即以下方法：

+   `minus`，`minusDays`，`minusMonths`和`minusYears`：从期间中减去给定的值。

+   `plus`，`plusDays`，`plusMonths`和`plusYears`：将给定的值添加到期间。

+   `negated`：返回每个值都取反的新期间。

+   `normalized`：通过规范化其更高阶字段（如月和日）返回一个新的期间。例如，15 个月被规范化为 1 年和 3 个月。

我们将展示这些方法的操作，首先是`minus`方法：

```java
jshell> period1.minus(Period.of(1,3,4))
$28 ==> P2Y12M25D

jshell> period1.minusDays(4)
$29 ==> P3Y15M25D

jshell> period1.minusMonths(3)
$30 ==> P3Y12M29D

jshell> period1.minusYears(1)
$31 ==> P2Y15M29D
```

然后，我们将看到`plus`方法：

```java
jshell> Period period1 = Period.of(3, 15, 29)
period1 ==> P3Y15M29D

jshell> period1.plus(Period.of(1, 3, 4))
$33 ==> P4Y18M33D

jshell> period1.plusDays(4)
$34 ==> P3Y15M33D

jshell> period1.plusMonths(3)
$35 ==> P3Y18M29D

jshell> period1.plusYears(1)
$36 ==> P4Y15M29D
```

最后，这里是`negated()`和`normalized()`方法：

```java
jshell> Period period1 = Period.of(3, 15, 29)
period1 ==> P3Y15M29D

jshell> period1.negated()
$38 ==> P-3Y-15M-29D

jshell> period1
period1 ==> P3Y15M29D

jshell> period1.normalized()
$40 ==> P4Y3M29D

jshell> period1
period1 ==> P3Y15M29D
```

请注意，在前面的两种情况下，它并没有改变现有的期间，而是返回一个新的实例。

# 如何创建基于时间的期间实例

在我们之前的示例中，我们创建了一个基于日期的期间，由`java.time.Period`表示。在这个示例中，我们将看看如何使用`java.time.Duration`类来以秒和纳秒的方式创建时间实例之间的时间差异。

我们将看看创建`java.time.Duration`实例的不同方法，操作持续时间实例，并以小时和分钟等不同单位获取持续时间。ISO 8601 标准指定了表示持续时间的可能模式之一为`PnYnMnDTnHnMnS`，其中以下内容适用：

+   `Y`，`M`和`D`代表日期组件字段，即年、月和日

+   `T`用于将日期与时间信息分隔开

+   `H`，`M`和`S`代表时间组件字段，即小时、分钟和秒

`java.time.Duration`的字符串表示实现基于 ISO 8601。在*它是如何工作*部分中有更多内容。

# 准备好了

您至少需要 JDK 8 才能使用`java.time.Duration`，并且需要 JDK 9 才能使用 JShell。

# 如何做...

1.  可以使用`of*()`工厂方法创建`java.time.Duration`实例。我们将展示如何使用其中的一些方法，如下所示：

```java
jshell> Duration.of(56, ChronoUnit.MINUTES)
$66 ==> PT56M
jshell> Duration.of(56, ChronoUnit.DAYS)
$67 ==> PT1344H
jshell> Duration.ofSeconds(87)
$68 ==> PT1M27S
jshell> Duration.ofHours(7)
$69 ==> PT7H
```

1.  它们也可以通过解析持续时间字符串来创建，如下所示：

```java
jshell> Duration.parse("P12D")
$70 ==> PT288H
jshell> Duration.parse("P12DT7H5M8.009S")
$71 ==> PT295H5M8.009S
jshell> Duration.parse("PT7H5M8.009S")
$72 ==> PT7H5M8.009S
```

1.  它们可以通过查找两个支持时间信息的`java.time.Temporal`实例之间的时间跨度来构建，这些实例支持时间信息（即`java.time.LocalDateTime`等的实例），如下所示：

```java
jshell> LocalDateTime time1 = LocalDateTime.now()
time1 ==> 2018-06-23T10:51:21.038073800
jshell> LocalDateTime time2 = LocalDateTime.of(2018, 6, 22, 11, 00)
time2 ==> 2018-06-22T11:00
jshell> Duration.between(time1, time2)
$77 ==> PT-23H-51M-21.0380738S
jshell> ZonedDateTime time1 = ZonedDateTime.now()
time1 ==> 2018-06-23T10:56:57.965606200+03:00[Asia/Riyadh]
jshell> ZonedDateTime time2 = ZonedDateTime.of(LocalDateTime.now(), ZoneOffset.ofHoursMinutes(5, 30))
time2 ==> 2018-06-23T10:56:59.878712600+05:30
jshell> Duration.between(time1, time2)
$82 ==> PT-2H-29M-58.0868936S
```

# 它是如何工作的...

`java.time.Duration`所需的数据存储在两个字段中，分别表示秒和纳秒。提供了一些便利方法，以分钟、小时和天为单位获取持续时间，即`toMinutes()`、`toHours()`和`toDays()`。

让我们讨论字符串表示实现。`java.time.Duration`支持解析 ISO 字符串表示，其中日期部分仅包含天组件，时间部分包含小时、分钟、秒和纳秒。例如，`P2DT3M`是可接受的，而解析`P3M2DT3M`将导致`java.time.format.DateTimeParseException`，因为字符串包含日期部分的月份组件。

`java.time.Duration`的`toString()`方法始终返回`PTxHyMz.nS`形式的字符串，其中`x`表示小时数，`y`表示分钟数，`z.n`表示秒数到纳秒精度。让我们看一些例子：

```java
jshell> Duration.parse("P2DT3M")
$2 ==> PT48H3M

jshell> Duration.parse("P3M2DT3M")
| Exception java.time.format.DateTimeParseException: Text cannot be parsed to a Duration
| at Duration.parse (Duration.java:417)
| at (#3:1)

jshell> Duration.ofHours(4)
$4 ==> PT4H

jshell> Duration.parse("PT3H4M5.6S")
$5 ==> PT3H4M5.6S

jshell> Duration d = Duration.parse("PT3H4M5.6S")
d ==> PT3H4M5.6S

jshell> d.toDays()
$7 ==> 0

jshell> d.toHours()
$9 ==> 3
```

# 还有更多...

让我们来看一下提供的操作方法，这些方法允许从特定的时间单位（如天、小时、分钟、秒或纳秒）中添加/减去一个值。每个方法都是不可变的，因此每次都会返回一个新实例，如下所示：

```java
jshell> Duration d = Duration.parse("PT1H5M4S")
d ==> PT1H5M4S

jshell> d.plusDays(3)
$14 ==> PT73H5M4S

jshell> d
d ==> PT1H5M4S

jshell> d.plusDays(3)
$16 ==> PT73H5M4S

jshell> d.plusHours(3)
$17 ==> PT4H5M4S

jshell> d.plusMillis(4)
$18 ==> PT1H5M4.004S

jshell> d.plusMinutes(40)
$19 ==> PT1H45M4S
```

类似地，您可以尝试`minus*()`方法，进行减法。然后有一些方法可以操作`java.time.LocalDateTime`、`java.time.ZonedDateTime`等的实例。这些方法将持续时间添加/减去日期/时间信息。让我们看一些例子：

```java
jshell> Duration d = Duration.parse("PT1H5M4S")
d ==> PT1H5M4S

jshell> d.addTo(LocalDateTime.now())
$21 ==> 2018-06-25T21:15:53.725373600

jshell> d.addTo(ZonedDateTime.now())
$22 ==> 2018-06-25T21:16:03.396595600+03:00[Asia/Riyadh]

jshell> d.addTo(LocalDate.now())
| Exception java.time.temporal.UnsupportedTemporalTypeException: Unsupported unit: Seconds
| at LocalDate.plus (LocalDate.java:1272)
| at LocalDate.plus (LocalDate.java:139)
| at Duration.addTo (Duration.java:1102)
| at (#23:1)
```

您可以观察到在前面的示例中，当我们尝试将持续时间添加到仅包含日期信息的实体时，我们得到了一个异常。

# 如何表示纪元时间

在本教程中，我们将学习如何使用`java.time.Instant`来表示一个时间点，并将该时间点转换为纪元秒/毫秒。Java 纪元用于指代时间瞬间 1970-01-01 00:00:00Z，`java.time.Instant`存储了从 Java 纪元开始的秒数。正值表示时间超过了纪元，负值表示时间落后于纪元。它使用 UTC 中的系统时钟来计算当前时间瞬间值。

# 准备工作

您需要安装支持新日期/时间 API 和 JShell 的 JDK，才能尝试提供的解决方案。

# 如何做...

1.  我们将创建一个`java.time.Instant`实例，并打印出纪元秒，这将给出 Java 纪元后的 UTC 时间：

```java
jshell> Instant.now()
$40 ==> 2018-07-06T07:56:40.651529300Z

jshell> Instant.now().getEpochSecond()
$41 ==> 1530863807
```

1.  我们还可以打印出纪元毫秒，这显示了纪元后的毫秒数。这比仅仅秒更精确：

```java
jshell> Instant.now().toEpochMilli()
$42 ==> 1530863845158
```

# 它是如何工作的...

`java.time.Instant`类将时间信息存储在其两个字段中：

+   秒，类型为`long`：这存储了从 1970-01-01T00:00:00Z 纪元开始的秒数。

+   纳秒，类型为`int`：这存储了纳秒数

当您调用`now()`方法时，`java.time.Instant`使用 UTC 中的系统时钟来表示该时间瞬间。然后我们可以使用`atZone()`或`atOffset()`将其转换为所需的时区，我们将在下一节中看到。

如果您只想表示 UTC 中的操作时间线，那么存储不同事件的时间戳将基于 UTC，并且您可以在需要时将其转换为所需的时区。

# 还有更多...

我们可以通过添加/减去纳秒、毫秒和秒来操纵`java.time.Instant`，如下所示：

```java
jshell> Instant.now().plusMillis(1000)
$43 ==> 2018-07-06T07:57:57.092259400Z

jshell> Instant.now().plusNanos(1991999)
$44 ==> 2018-07-06T07:58:06.097966099Z

jshell> Instant.now().plusSeconds(180)
$45 ==> 2018-07-06T08:01:15.824141500Z
```

同样，您可以尝试`minus*()`方法。我们还可以使用`java.time.Instant`方法获取依赖于时区的日期时间，如`atOffset()`和`atZone()`所示：

```java
jshell> Instant.now().atZone(ZoneId.of("Asia/Kolkata"))
$36 ==> 2018-07-06T13:15:13.820694500+05:30[Asia/Kolkata]

jshell> Instant.now().atOffset(ZoneOffset.ofHoursMinutes(2,30))
$37 ==> 2018-07-06T10:15:19.712039+02:30
```

# 如何操纵日期和时间实例

日期和时间类`java.time.LocalDate`、`java.time.LocalTime`、`java.time.LocalDateTime`和`java.time.ZonedDateTime`提供了从它们的组件中添加和减去值的方法，即天、小时、分钟、秒、周、月、年等。

在这个示例中，我们将看一些可以用来通过添加和减去不同的值来操纵日期和时间实例的方法。

# 准备就绪

您将需要安装支持新的日期/时间 API 和 JShell 控制台的 JDK。

# 如何做到这一点...

1.  让我们操纵`java.time.LocalDate`：

```java
jshell> LocalDate d = LocalDate.now()
d ==> 2018-07-27

jshell> d.plusDays(3)
$5 ==> 2018-07-30

jshell> d.minusYears(4)
$6 ==> 2014-07-27
```

1.  让我们操纵日期和时间实例，`java.time.LocalDateTime`：

```java
jshell> LocalDateTime dt = LocalDateTime.now()
dt ==> 2018-07-27T15:27:40.733389700

jshell> dt.plusMinutes(45)
$8 ==> 2018-07-27T16:12:40.733389700

jshell> dt.minusHours(4)
$9 ==> 2018-07-27T11:27:40.733389700
```

1.  让我们操纵依赖于时区的日期和时间，`java.time.ZonedDateTime`：

```java
jshell> ZonedDateTime zdt = ZonedDateTime.now()
zdt ==> 2018-07-27T15:28:28.309915200+03:00[Asia/Riyadh]

jshell> zdt.plusDays(4)
$11 ==> 2018-07-31T15:28:28.309915200+03:00[Asia/Riyadh]

jshell> zdt.minusHours(3)
$12 ==> 2018-07-27T12:28:28.309915200+03:00[Asia/Riyadh]
```

# 还有更多...

我们刚刚看了一些由`plus*()`和`minus*()`表示的添加和减去 API。还提供了不同的方法来操纵日期和时间的不同组件，如年、日、月、小时、分钟、秒和纳秒。您可以尝试这些 API 作为练习。

# 如何比较日期和时间

通常，我们希望将日期和时间实例与其他实例进行比较，以检查它们是在之前、之后还是与其他实例相同。为了实现这一点，JDK 在`java.time.LocalDate`、`java.time.LocalDateTime`和`java.time.ZonedDateTime`类中提供了`isBefore()`、`isAfter()`和`isEqual()`方法。在这个示例中，我们将看看如何使用这些方法来比较日期和时间实例。

# 准备就绪

您将需要安装具有新的日期/时间 API 并支持 JShell 的 JDK。

# 如何做到这一点...

1.  让我们尝试比较两个`java.time.LocalDate`实例：

```java
jshell> LocalDate d = LocalDate.now()
d ==> 2018-07-28

jshell> LocalDate d2 = LocalDate.of(2018, 7, 27)
d2 ==> 2018-07-27

jshell> d.isBefore(d2)
$4 ==> false

jshell> d.isAfter(d2)
$5 ==> true

jshell> LocalDate d3 = LocalDate.of(2018, 7, 28)
d3 ==> 2018-07-28

jshell> d.isEqual(d3)
$7 ==> true

jshell> d.isEqual(d2)
$8 ==> false
```

1.  我们还可以比较依赖于时区的日期和时间实例：

```java
jshell> ZonedDateTime zdt1 = ZonedDateTime.now();
zdt1 ==> 2018-07-28T14:49:34.778006400+03:00[Asia/Riyadh]

jshell> ZonedDateTime zdt2 = zdt1.plusHours(4)
zdt2 ==> 2018-07-28T18:49:34.778006400+03:00[Asia/Riyadh]

jshell> zdt1.isBefore(zdt2)
$11 ==> true

jshell> zdt1.isAfter(zdt2)
$12 ==> false
jshell> zdt1.isEqual(zdt2)
$13 ==> false
```

# 还有更多...

比较可以在`java.time.LocalTime`和`java.time.LocalDateTime`上进行。这留给读者去探索。

# 如何使用不同的日历系统

到目前为止，在我们的示例中，我们使用了 ISO 日历系统，这是世界上遵循的事实标准日历系统。世界上还有其他地区遵循的日历系统，如伊斯兰历、日本历和泰国历。JDK 也为这些日历系统提供了支持。

在这个示例中，我们将看看如何使用两个日历系统：日本和伊斯兰历。

# 准备就绪

您应该安装支持新的日期/时间 API 和 JShell 工具的 JDK。

# 如何做到这一点...

1.  让我们打印 JDK 支持的不同日历系统中的当前日期：

```java
jshell> Chronology.getAvailableChronologies().forEach(chrono -> 
System.out.println(chrono.dateNow()))
2018-07-30
Minguo ROC 107-07-30
Japanese Heisei 30-07-30
ThaiBuddhist BE 2561-07-30
Hijrah-umalqura AH 1439-11-17
```

1.  让我们玩弄一下用日本日历系统表示的日期：

```java
jshell> JapaneseDate jd = JapaneseDate.now()
jd ==> Japanese Heisei 30-07-30

jshell> jd.getChronology()
$7 ==> Japanese

jshell> jd.getEra()
$8 ==> Heisei

jshell> jd.lengthOfYear()
$9 ==> 365

jshell> jd.lengthOfMonth()
$10 ==> 31
```

1.  日本日历中支持的不同纪元可以使用`java.time.chrono.JapeneseEra`进行枚举：

```java
jshell> JapaneseEra.values()
$42 ==> JapaneseEra[5] { Meiji, Taisho, Showa, Heisei, NewEra }
```

1.  让我们在伊斯兰历中创建一个日期：

```java
jshell> HijrahDate hd = HijrahDate.of(1438, 12, 1)
hd ==> Hijrah-umalqura AH 1438-12-01
```

1.  我们甚至可以将 ISO 日期/时间转换为伊斯兰历的日期/时间，如下所示：

```java
jshell> HijrahChronology.INSTANCE.localDateTime(LocalDateTime.now())
$23 ==> Hijrah-umalqura AH 1439-11-17T19:56:52.056465900

jshell> HijrahChronology.INSTANCE.localDateTime(LocalDateTime.now()).toLocalDate()
$24 ==> Hijrah-umalqura AH 1439-11-17

jshell> HijrahChronology.INSTANCE.localDateTime(LocalDateTime.now()).toLocalTime()
$25 ==> 19:57:07.705740500
```

# 它是如何工作的...

日历系统由`java.time.chrono.Chronology`及其实现表示，其中一些是`java.time.chrono.IsoChronology`、`java.time.chrono.HijrahChronology`和`java.time.chrono.JapaneseChronology`。`java.time.chrono.IsoChronology`是世界上使用的基于 ISO 的事实标准日历系统。每个日历系统中的日期由`java.time.chrono.ChronoLocalDate`及其实现表示，其中一些是`java.time.chrono.HijrahDate`、`java.time.chrono.JapaneseDate`和著名的`java.time.LocalDate`。

要能够在 JShell 中使用这些 API，您需要导入相关的包，如下所示：

```java
jshell> import java.time.*

jshell> import java.time.chrono.*
```

这适用于所有使用 JShell 的示例。

我们可以直接使用`java.time.chrono.ChronoLocalDate`的实现，例如`java.time.chrono.JapaneseDate`，或者使用`java.time.chrono.Chronology`的实现来获取相关的日期表示，如下所示：

```java
jshell> JapaneseDate jd = JapaneseDate.of(JapaneseEra.SHOWA, 26, 12, 25)
jd ==> Japanese Showa 26-12-25

jshell> JapaneseDate jd = JapaneseDate.now()
jd ==> Japanese Heisei 30-07-30

jshell> JapaneseDate jd = JapaneseChronology.INSTANCE.dateNow()
jd ==> Japanese Heisei 30-07-30

jshell> JapaneseDate jd = JapaneseChronology.INSTANCE.date(LocalDateTime.now())
jd ==> Japanese Heisei 30-07-30

jshell> ThaiBuddhistChronology.INSTANCE.date(LocalDate.now())
$41 ==> ThaiBuddhist BE 2561-07-30
```

从前面的代码片段中，我们可以看到可以使用其日历系统的`date(TemporalAccessor temporal)`方法将 ISO 系统日期转换为所需日历系统中的日期。

# 还有更多…

您可以尝试使用 JDK 支持的其他日历系统，即泰国、佛教和民国（中国）日历系统。还值得探索如何通过编写`java.time.chrono.Chronology`、`java.time.chrono.ChronoLocalDate`和`java.time.chrono.Era`的实现来创建我们自定义的日历系统。

# 如何使用 DateTimeFormatter 格式化日期

在使用`java.util.Date`时，我们使用`java.text.SimpleDateFormat`将日期格式化为不同的文本表示形式，反之亦然。格式化日期意味着，以不同格式表示给定日期或时间对象，例如以下格式：

+   2018 年 6 月 23 日

+   2018 年 8 月 23 日

+   2018-08-23

+   2018 年 6 月 23 日上午 11:03:33

这些格式由格式字符串控制，例如以下格式：

+   `dd MMM yyyy`

+   `dd-MM-yyyy`

+   `yyyy-MM-DD`

+   `dd MMM yyyy hh:mm:ss`

在这个示例中，我们将使用`java.time.format.DateTimeFormatter`来格式化新日期和时间 API 中的日期和时间实例，并查看最常用的模式字母。

# 准备工作

您将需要一个具有新的日期/时间 API 和`jshell`工具的 JDK。

# 如何做…

1.  让我们使用内置格式来格式化日期和时间：

```java
jshell> LocalDate ld = LocalDate.now()
ld ==> 2018-08-01

jshell> ld.format(DateTimeFormatter.ISO_DATE)
$47 ==> "2018-08-01"

jshell> LocalDateTime.now().format(DateTimeFormatter.ISO_DATE_TIME)
$49 ==> "2018-08-01T17:24:49.1985601"
```

1.  让我们创建一个自定义的日期/时间格式：

```java
jshell> DateTimeFormatter dtf = DateTimeFormatter.ofPattern("dd MMM yyyy hh:mm:ss a")
dtf ==> Value(DayOfMonth,2)' 'Text(MonthOfYear,SHORT)' 'V ... 2)' 'Text(AmPmOfDay,SHORT)
```

1.  让我们使用自定义的`java.time.format.DateTimeFormatter`来格式化当前的日期/时间：

```java
jshell> LocalDateTime ldt = LocalDateTime.now()
ldt ==> 2018-08-01T17:36:22.442159

jshell> ldt.format(dtf)
$56 ==> "01 Aug 2018 05:36:22 PM"
```

# 它是如何工作的…

让我们了解最常用的格式字母：

| **符号** | **意义** | **示例** |
| --- | --- | --- |
| `d` | 一个月中的日期 | 1,2,3,5 |
| `M`, `MMM`, `MMMM` | 一年中的月份 | `M`: 1,2,3,`MMM`: 六月，七月，八月`MMMM`: 七月，八月 |
| `y`, `yy` | 年 | `y`, `yyyy`: 2017, 2018`yy`: 18, 19 |
| `h` | 一天中的小时（1-12） | 1, 2, 3 |
| `k` | 一天中的小时（0-23） | 0, 1, 2, 3 |
| `m` | 分钟 | 1, 2, 3 |
| `s` | 秒 | 1, 2, 3 |
| `a` | 一天中的上午/下午 | 上午，下午 |
| `VV` | 时区 ID | 亚洲/加尔各答 |
| `ZZ` | 时区名称 | IST, PST, AST |
| `O` | 时区偏移 | GMT+5:30, GMT+3 |

基于前面的格式字母，让我们格式化`java.time.ZonedDateTime`：

```java
jshell> DateTimeFormatter dtf = DateTimeFormatter.ofPattern("dd MMMM yy h:mm:ss a VV")
dtf ==> Value(DayOfMonth,2)' 'Text(MonthOfYear)' 'Reduced ... mPmOfDay,SHORT)' 'ZoneId()

jshell> ZonedDateTime.now().format(dtf)
$67 ==> "01 August 18 6:26:04 PM Asia/Kolkata"

jshell> DateTimeFormatter dtf = DateTimeFormatter.ofPattern("dd MMMM yy h:mm:ss a zz")
dtf ==> Value(DayOfMonth,2)' 'Text(MonthOfYear)' 'Reduced ... y,SHORT)' 'ZoneText(SHORT)

jshell> ZonedDateTime.now().format(dtf)
$69 ==> "01 August 18 6:26:13 PM IST"

jshell> DateTimeFormatter dtf = DateTimeFormatter.ofPattern("dd MMMM yy h:mm:ss a O")
dtf ==> Value(DayOfMonth,2)' 'Text(MonthOfYear)' 'Reduced ... )' 'LocalizedOffset(SHORT)

jshell> ZonedDateTime.now().format(dtf)
$72 ==> "01 August 18 6:26:27 PM GMT+5:30"
```

`java.time.format.DateTimeFormatter`附带了基于 ISO 标准的大量默认格式。当您处理日期操作而没有用户参与时，这些格式应该足够了，也就是说，当日期和时间在应用程序的不同层之间交换时。

但是，为了向最终用户呈现日期和时间信息，我们需要以可读的格式对其进行格式化，为此，我们需要一个自定义的`DateTimeFormatter`。如果您需要自定义的`java.time.format.DateTimeFormatter`，有两种创建方式：

+   使用模式，例如 dd MMMM yyyy 和`java.time.format.DateTimeFormatter`中的`ofPattern()`方法

+   使用`java.time.DateTimeFormatterBuilder`

**使用模式**：

我们创建一个`java.time.format.DateTimeFormatter`的实例，如下所示：

```java
jshell> DateTimeFormatter dtf = DateTimeFormatter.ofPattern("dd MMMM yy h:mm:ss a VV")
dtf ==> Value(DayOfMonth,2)' 'Text(MonthOfYear)' 'Reduced ... mPmOfDay,SHORT)' 'ZoneId()
```

然后我们将格式应用到日期和时间实例：

```java
jshell> ZonedDateTime.now().format(dtf)
$92 ==> "01 August 18 7:25:00 PM Asia/Kolkata"
```

模式方法也使用`DateTimeFormatterBuilder`，其中构建器解析给定的格式字符串以构建`DateTimeFormatter`对象。

**使用`java.time.format.DateTimeFormatterBuilder`：**

让我们使用`DateTimeFormatterBuilder`来构建`DateTimeFormatter`，如下所示：

```java
jshell> DateTimeFormatter dtf = new DateTimeFormatterBuilder().
 ...> appendValue(DAY_OF_MONTH, 2).
 ...> appendLiteral(" ").
 ...> appendText(MONTH_OF_YEAR).
 ...> appendLiteral(" ").
 ...> appendValue(YEAR, 4).
 ...> toFormatter()
dtf ==> Value(DayOfMonth,2)' 'Text(MonthOfYear)' 'Value(Year,4)

jshell> LocalDate.now().format(dtf) E$106 ==> "01 August 2018"
```

您可以观察到`DateTimeFormatter`对象由一组指令组成，用于表示日期和时间。这些指令以`Value()`、`Text()`和分隔符的形式呈现。


# 第十四章：测试

本章展示了如何测试你的应用程序——如何捕获和自动化测试用例，如何在将 API 与其他组件集成之前对 API 进行单元测试，以及如何集成所有单元。我们将向您介绍**行为驱动开发**（**BDD**）并展示它如何成为应用程序开发的起点。我们还将演示如何使用 JUnit 框架进行单元测试。有时，在单元测试期间，我们必须使用一些虚拟数据存根依赖项，这可以通过模拟依赖项来完成。我们将向您展示如何使用模拟库来做到这一点。我们还将向您展示如何编写固定装置来填充测试数据，然后如何通过集成不同的 API 并一起测试它们来测试应用程序的行为。我们将涵盖以下内容：

+   使用 Cucumber 进行行为测试

+   使用 JUnit 对 API 进行单元测试

+   单元测试通过模拟依赖关系

+   使用固定装置来填充测试数据

+   集成测试

# 介绍

经过良好测试的代码为开发人员提供了心灵上的安宁。如果你觉得为你正在开发的新方法编写测试太过繁琐，那么通常第一次就做不对。无论如何，你都必须测试你的方法，而在长远来看，设置或编写单元测试比构建和启动应用程序多次要少时间消耗——每次代码更改和每次逻辑通过都要这样做。

我们经常感到时间紧迫的原因之一是我们在估算时间时没有包括编写测试所需的时间。一个原因是我们有时会忘记这样做。另一个原因是我们不愿意给出更高的估计，因为我们不想被认为技能不够。不管原因是什么，这种情况经常发生。只有经过多年的经验，我们才学会在估算中包括测试，并赢得足够的尊重和影响力，能够公开断言正确的做事方式需要更多的时间，但从长远来看节省了更多的时间。此外，正确的做法会导致健壮的代码，减少了很多压力，这意味着整体生活质量更好。

早期测试的另一个优势是在主要代码完成之前发现代码的弱点，这时修复它很容易。如果需要，甚至可以重构代码以提高可测试性。

如果你还不相信，记下你阅读此文的日期，并每年回顾一次，直到这些建议对你来说变得显而易见。然后，请与他人分享你的经验。这就是人类取得进步的方式——通过将知识从一代传递到下一代。

从方法上讲，本章的内容也适用于其他语言和职业，但示例主要是为 Java 开发人员编写的。

# 使用 Cucumber 进行行为测试

以下是程序员经常提出的三个反复出现的抱怨：

+   缺乏需求

+   需求的模糊性

+   需求一直在变化

有很多建议和流程可以帮助缓解这些问题，但没有一个能够完全消除它们。在我们看来，最成功的是敏捷过程方法与 BDD 相结合，使用 Cucumber 或其他类似框架。短迭代允许快速调整和业务（客户）与程序员之间的协调，而 BDD 与 Cucumber 以 Gherkin 捕获需求，但没有维护大量文档的开销。

Gherkin 中编写的需求必须被分解成**特性**。每个特性存储在一个扩展名为`.feature`的文件中，包含一个或多个描述特性不同方面的**场景**。每个场景由描述用户操作或输入数据以及应用程序对其的响应的步骤组成。

程序员实现必要的应用程序功能，然后使用它来在一个或多个`.java`文件中实现场景。每个步骤都在一个方法中实现。

在实施后，这些场景将成为一套测试，可以是像单元测试一样细粒度，也可以是像集成测试一样高级，以及介于两者之间的任何形式。这完全取决于谁编写了场景以及应用程序代码的结构。如果场景的作者是业务人员，那么场景往往更高级。但是，如果应用程序的结构使得每个场景（可能有多个输入数据的排列组合）都被实现为一个方法，那么它就可以有效地作为一个单元测试。或者，如果一个场景涉及多个方法甚至子系统，它可以作为一个集成测试，而程序员可以用更细粒度（更像单元测试）的场景来补充它。之后，在代码交付后，所有场景都可以作为回归测试。

您所付出的代价是场景的开销、维护，但回报是捕获需求并确保应用程序确实符合要求的正式系统。话虽如此，需要说明的一点是：捕获 UI 层的场景通常更加棘手，因为 UI 往往更频繁地发生变化，特别是在应用程序开发的初期。然而，一旦 UI 稳定下来，对其的需求也可以使用 Selenium 或类似的框架在 Cucumber 场景中进行捕获。

# 如何做...

1.  安装 Cucumber。Cucumber 的安装只是将框架作为 Maven 依赖项添加到项目中。由于我们将添加多个 Cucumber JAR 文件，而且它们都必须是相同版本，因此在`pom.xml`中添加`cucumber.version`属性是有意义的。

```java
    <properties>
        <cucumber.version>3.0.2</cucumber.version>
    </properties>
```

现在我们可以在`pom.xml`中将 Cucumber 主 JAR 文件添加为依赖项：

```java
<dependency>
    <groupId>io.cucumber</groupId>
    <artifactId>cucumber-java</artifactId>
    <version>${cucumber.version}</version>
    <scope>test</scope>
</dependency>

```

或者，如果您更喜欢流畅的基于流的编码风格，您可以添加一个不同的 Cucumber 主 JAR 文件：

```java
<dependency>
    <groupId>io.cucumber</groupId>
    <artifactId>cucumber-java8</artifactId>
    <version>${cucumber.version}</version>
    <scope>test</scope>
</dependency>

```

如果您的项目尚未设置 JUnit 作为依赖项，您可以按照以下步骤添加它以及另一个`cucumber-junit` JAR 文件：

```java
<dependency>
    <groupId>junit</groupId>
    <artifactId>junit</artifactId>
    <version>4.12</version>
    <scope>test</scope>
</dependency>
<dependency>
    <groupId>io.cucumber</groupId>
    <artifactId>cucumber-junit</artifactId>
    <version>${cucumber.version}</version>
    <scope>test</scope>
</dependency> 
```

以上是必要的，如果您计划利用 JUnit 断言。请注意，目前为止，Cucumber 不支持 JUnit 5。

或者，您可以使用 TestNG（[`testng.org`](https://testng.org)）中的断言：

```java
<dependency>
    <groupId>org.testng</groupId>
    <artifactId>testng</artifactId>
    <version>6.14.2</version>
    <scope>test</scope>
</dependency>
<dependency>
    <groupId>io.cucumber</groupId>
    <artifactId>cucumber-testng</artifactId>
    <version>${cucumber.version}</version>
    <scope>test</scope>
</dependency>
```

如您所见，在这种情况下，您需要添加`cucumber-testng` JAR 文件，而不是`cucumber-junit` JAR 文件。TestNG 提供了丰富多样的断言方法，包括深度集合和其他对象比较。

1.  运行 Cucumber。`cucumber-junit` JAR 文件还提供了一个`@RunWith`注解，将一个类指定为测试运行器：

```java
package com.packt.cookbook.ch16_testing;

import cucumber.api.CucumberOptions;
import cucumber.api.junit.Cucumber;
import org.junit.runner.RunWith;

@RunWith(Cucumber.class)
public class RunScenariousTest {
}
```

执行前述类将执行与运行器所在的相同包中的所有场景。Cucumber 读取每个`.feature`文件及其中的场景。对于每个场景的每个步骤，它尝试在与运行器和`.feature`文件相同的包中找到其实现。它按照场景中列出的顺序执行每个已实现的步骤。

1.  创建一个`.feature`文件。正如我们已经提到的，一个`.feature`文件包含一个或多个场景。文件的名称对 Cucumber 没有任何意义。文件的内容以`Feature`关键字（后面跟着冒号`:`）开始。接下来的文本描述了功能，并且与文件名类似，对 Cucumber 没有任何意义。功能描述在`Scenario`关键字（后面跟着冒号`:`）开始新行时结束。这就是第一个场景描述开始的地方。以下是一个例子：

```java
Feature: Vehicle speed calculation
 The calculations should be made based on the assumption
 that a vehicle starts moving, and driving conditions are 
 always the same.

Scenario: Calculate speed
 This the happy path that demonstrates the main case
```

当以下关键字之一在新行上开始时，场景描述结束：`Given`、`When`、`Then`、`And`或`But`。每个这些关键字在新行开始时，都表示步骤定义的开始。对于 Cucumber 来说，这样的关键字除了表示步骤定义的开始外，没有其他意义。但对于人类来说，如果场景以`Given`关键字开始，即描述系统的初始状态的步骤，那么阅读起来更容易。可能会有几个其他步骤（前提条件）跟随；每个步骤都以新行和`And`或`But`关键字开头，例如如下所示：

```java
Given the vehicle has 246 hp engine and weighs 4000 pounds
```

之后，步骤组描述了动作或事件。为了人类可读性，该组通常以新行的`When`关键字开头。其他动作或事件随后，每个都以新行和`And`或`But`关键字开头。建议将该组中的步骤数量保持在最小限度，以便每个场景都能够集中精力，例如如下所示：

```java
When the application calculates its speed after 10.0 sec
```

场景中的最后一组步骤以新行中的`Then`关键字开始。它们描述了预期的结果。与前两组步骤一样，该组中的每个后续步骤都以新行和`And`或`But`关键字开头，例如如下所示：

```java
Then the result should be 117.0 mph
```

总结之前，该功能如下：

```java
Feature: Vehicle speed calculation
 The calculations should be made based on the assumption
 that a vehicle starts moving, and driving conditions are
 always the same.

Scenario: Calculate speed
 This the happy path that demonstrates the main case

 Given the vehicle has 246 hp engine and weighs 4000 pounds
 When the application calculates its speed after 10.0 sec
 Then the result should be 117.0 mph
```

我们将其放在以下文件夹中的`src/test/resources/com/packt/cookbook/Chapter14_testing`中的`CalculateSpeed.feature`文件中。

请注意，它必须位于`test/resources`文件夹中，并且其路径必须与`RunScenariosTest`测试运行器所属的包名称匹配。

测试运行器像执行任何 JUnit 测试一样，例如使用`mvn test`命令，或者只需在 JDE 中运行它。执行时，它会查找同一包中的所有`.feature`文件（Maven 将它们从`resources`文件夹复制到`target/classes`文件夹，因此将它们设置在类路径上）。然后按顺序读取每个场景的步骤，并尝试在同一包中找到每个步骤的实现。

正如我们已经提到的，文件的名称对于 Cucumber 来说没有任何意义。它首先寻找`.feature`扩展名，然后找到第一个步骤，并在同一目录中尝试找到一个类，该类中有一个与步骤相同的注释方法。

为了说明其含义，让我们通过执行测试运行器来运行创建的特性。结果将如下所示：

```java
cucumber.runtime.junit.UndefinedThrowable: 
The step "the vehicle has 246 hp engine and weighs 4000 pounds" 
                                                     is undefined
cucumber.runtime.junit.UndefinedThrowable: 
The step "the application calculates its speed after 10.0 sec" 
                                                     is undefined
cucumber.runtime.junit.UndefinedThrowable: 
The step "the result should be 117.0 mph" is undefined

Undefined scenarios:
com/packt/cookbook/ch16_testing/CalculateSpeed.feature:6 
                                                # Calculate speed
1 Scenarios (1 undefined)
3 Steps (3 undefined)
0m0.081s

You can implement missing steps with the snippets below:

@Given("the vehicle has {int} hp engine and weighs {int} pounds")
public void the_vehicle_has_hp_engine_and_weighs_pounds(Integer 
                                             int1, Integer int2) {
 // Write code here that turns the phrase above 
 // into concrete actions
 throw new PendingException();
}

@When("the application calculates its speed after {double} sec")
public void the_application_calculates_its_speed_after_sec(Double 
                                                         double1) {
 // Write code here that turns the phrase above 
 // into concrete actions
 throw new PendingException();
}

@Then("the result should be {double} mph")
public void the_result_should_be_mph(Double double1) {
 // Write code here that turns the phrase above 
 // into concrete actions
 throw new PendingException();
}
```

正如您所看到的，Cucumber 不仅告诉我们有多少个`undefined`特性和场景，它甚至提供了一种可能的实现方式。请注意，Cucumber 允许使用大括号中的类型传递参数。以下是内置类型：`int`、`float`、`word`、`string`、`biginteger`、`bigdecimal`、`byte`、`short`、`long`和`double`。`word`和`string`之间的区别在于后者允许空格。但 Cucumber 还允许我们定义自定义类型。

1.  编写并运行步骤定义。Cucumber 术语中的`undefined`可能会令人困惑，因为我们确实定义了特性和场景。我们只是没有实现它们。因此，Cucumber 消息中的`undefined`实际上意味着`未实现`。

要开始实现，我们首先在与测试运行器相同的目录中创建一个名为`CalculateSpeedSteps`的类。类名对于 Cucumber 来说没有意义，所以您可以根据自己的喜好命名它。然后，我们将之前建议的三种方法与注释一起复制并放入该类中：

```java
package com.packt.cookbook.ch16_testing;

import cucumber.api.PendingException;
import cucumber.api.java.en.Given;
import cucumber.api.java.en.Then;
import cucumber.api.java.en.When;

public class Calc {
  @Given("the vehicle has {int} hp engine and weighs {int} pounds")
  public void the_vehicle_has_hp_engine_and_weighs_pounds(Integer 
                                              int1, Integer int2) {
        // Write code here that turns the phrase above 
        // into concrete actions
        throw new PendingException();
  }

  @When("the application calculates its speed after {double} sec")
  public void the_application_calculates_its_speed_after_sec(Double 
                                                         double1) {
        // Write code here that turns the phrase above 
        // into concrete actions
        throw new PendingException();
  }

  @Then("the result should be {double} mph")
    public void the_result_should_be_mph(Double double1) {
        // Write code here that turns the phrase above 
        // into concrete actions
        throw new PendingException();
  }
}
```

如果我们再次执行测试运行器，输出将如下所示：

```java
cucumber.api.PendingException: TODO: implement me
 at com.packt.cookbook.ch16_testing.CalculateSpeedSteps.the_vehicle
      _has_hp_engine_and_weighs_pounds(CalculateSpeedSteps.java:13)
 at *.the vehicle has 246 hp engine and weighs 4000 pounds(com/packt/cookbook/ch16_testing/CalculateSpeed.feature:9)

Pending scenarios:
com/packt/cookbook/ch16_testing/CalculateSpeed.feature:6 
                                                 # Calculate speed
1 Scenarios (1 pending)
3 Steps (2 skipped, 1 pending)
0m0.055s

cucumber.api.PendingException: TODO: implement me
 at com.packt.cookbook.ch16_testing.CalculateSpeedSteps.the_vehicle       has_hp_engine_and_weighs_pounds(CalculateSpeedSteps.java:13)
 at *.the vehicle has 246 hp engine and weighs 4000 pounds(com/packt/cookbook/ch16_testing/CalculateSpeed.feature:9)
```

运行器在第一个`PendingException`处停止执行，因此其他两个步骤被跳过。如果系统地应用 BDD 方法论，那么特性将首先编写——在编写应用程序的任何代码之前。因此，每个特性都会产生前面的结果。

随着应用程序的开发，每个新功能都得到了实现，并且不再失败。

# 它是如何工作的...

在要求被表达为功能后，应用程序会逐个功能地实现。例如，我们可以从创建`Vehicle`类开始：

```java
class Vehicle {
    private int wp, hp;
    public Vehicle(int weightPounds, int hp){
        this.wp = weightPounds;
        this.hp = hp;
    }
    protected double getSpeedMpH(double timeSec){
        double v = 2.0 * this.hp * 746 ;
        v = v*timeSec * 32.174 / this.wp;
        return Math.round(Math.sqrt(v) * 0.68);
    }
}
```

然后，先前显示的第一个功能的步骤可以实现如下：

```java
package com.packt.cookbook.ch16_testing;

import cucumber.api.java.en.Given;
import cucumber.api.java.en.Then;
import cucumber.api.java.en.When;
import static org.junit.Assert.assertEquals;

public class CalculateSpeedSteps {
  private Vehicle vehicle;
  private double speed;

  @Given("the vehicle has {int} hp engine and weighs {int} pounds")
  public void the_vehicle_has_hp_engine_and_weighs_pounds(Integer 
                                                  wp, Integer hp) {
        vehicle = new Vehicle(wp, hp);
  }

  @When("the application calculates its speed after {double} sec")
  public void 
        the_application_calculates_its_speed_after_sec(Double t) {
        speed = vehicle.getSpeedMpH(t);
  }

  @Then("the result should be {double} mph")
  public void the_result_should_be_mph(Double speed) {
        assertEquals(speed, this.speed, 0.0001 * speed);
  }
}
```

如果我们再次在`com.packt.cookbook.ch16_testing`包中运行测试运行器，步骤将成功执行。

现在，如果需求发生变化，并且`.feature`文件相应地进行了修改，除非应用程序代码也进行了更改并符合要求，否则测试将失败。这就是 BDD 的力量。它使要求与代码保持同步。它还允许 Cucumber 测试作为回归测试。如果代码更改违反了要求，测试将失败。

# 使用 JUnit 对 API 进行单元测试

根据维基百科，GitHub 上托管的项目中超过 30%包括 JUnit，这是一组单元测试框架，统称为 xUnit，起源于 SUnit。它在编译时作为 JAR 链接，并且（自 JUnit 4 以来）驻留在`org.junit`包中。

在面向对象编程中，一个单元可以是整个类，也可以是一个单独的方法。在实践中，我们发现最有用的是作为一个单独方法的单元。它为本章的示例提供了基础。

# 准备工作

在撰写本文时，JUnit 的最新稳定版本是 4.12，可以通过将以下 Maven 依赖项添加到`pom.xml`项目级别来使用：

```java
<dependency>
  <groupId>junit</groupId>
  <artifactId>junit</artifactId>
  <version>4.12</version>
  <scope>test</scope>
</dependency>
```

之后，您可以编写您的第一个 JUnit 测试。假设您已经在`src/main/java/com/packt/cookbook.ch02_oop.a_classes`文件夹中创建了`Vehicle`类（这是我们在第二章中讨论的代码，*OOP - 类和接口的快速跟踪*）：

```java
package com.packt.cookbook.ch02_oop.a_classes;
public class Vehicle {
  private int weightPounds;
  private Engine engine;
  public Vehicle(int weightPounds, Engine engine) {
    this.weightPounds = weightPounds;
    if(engine == null){
      throw new RuntimeException("Engine value is not set.");
    }
    this.engine = engine;
  }
  protected double getSpeedMph(double timeSec){
    double v = 2.0*this.engine.getHorsePower()*746;
    v = v*timeSec*32.174/this.weightPounds;
    return Math.round(Math.sqrt(v)*0.68);
  }
}
```

现在，您可以创建`src/test/java/com/packt/cookbook.ch02_oop.a_classes`文件夹，并在其中创建一个名为`VehicleTest.java`的新文件，其中包含`VehicleTest`类：

```java
package com.packt.cookbook.ch02_oop.a_classes;
import org.junit.Test;
public class VehicleTest {
  @Test
  public void testGetSpeedMph(){
    System.out.println("Hello!" + " I am your first test method!");
  }
}
```

使用您喜欢的 IDE 运行它，或者只需使用`mvn test`命令。您将看到包括以下内容的输出：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java11-cb/img/3ae6e5f2-a622-4f77-b934-2867786402f4.png)

恭喜！您已经创建了您的第一个测试类。它还没有测试任何东西，但这是一个重要的设置——这是以正确的方式进行操作所必需的开销。在下一节中，我们将开始实际测试。

# 如何做...

让我们更仔细地看一下`Vehicle`类。测试 getter 的价值不大，但我们仍然可以这样做，确保传递给构造函数的值由相应的 getter 返回。构造函数中的异常也属于必须测试的功能，以及`getSpeedMph()`方法。还有一个`Engine`类的对象，它具有`getHorsePower()`方法。它能返回`null`吗？为了回答这个问题，让我们看一下`Engine`类：

```java
public class Engine {
  private int horsePower;
  public int getHorsePower() {
    return horsePower;
  }
  public void setHorsePower(int horsePower) {
    this.horsePower = horsePower;
  }
}
```

`getHorsePower()`方法不能返回`null`。如果没有通过`setHorsePower()`方法显式设置，`horsePower`字段将默认初始化为零。但是返回负值是一个明显的可能性，这反过来可能会导致`getSpeedMph()`方法的`Math.sqrt()`函数出现问题。我们应该确保马力值永远不会是负数吗？这取决于方法的使用限制程度以及输入数据的来源。

类`Vehicle`的`weightPounds`字段的值也适用类似的考虑。它可能会在`getSpeedMph()`方法中由于除以零而导致`ArithmeticException`而使应用程序停止。

然而，在实践中，发动机马力和车辆重量的值几乎不可能是负数或接近零，因此我们将假设这一点，并不会将这些检查添加到代码中。

这样的分析是每个开发人员的日常例行公事和背景思考，这是朝着正确方向迈出的第一步。第二步是在单元测试中捕获所有这些思考和疑虑，并验证假设。

让我们回到我们创建的测试类。你可能已经注意到，`@Test`注解使某个方法成为测试方法。这意味着每次你发出运行测试的命令时，它都会被你的 IDE 或 Maven 运行。方法可以以任何你喜欢的方式命名，但最佳实践建议指出你正在测试的方法（在这种情况下是`Vehicle`类）。因此，格式通常看起来像`test<methodname><scenario>`，其中`scenario`表示特定的测试用例：一个成功的路径，一个失败，或者你想测试的其他条件。在第一个示例中，虽然我们没有使用后缀，但为了保持代码简单，我们将展示稍后测试其他场景的方法示例。

在测试中，你可以调用正在测试的应用程序方法，提供数据，并断言结果。你可以创建自己的断言（比较实际结果和预期结果的方法），或者你可以使用 JUnit 提供的断言。要做到后者，只需添加静态导入：

```java
import static org.junit.Assert.assertEquals;
```

如果你使用现代 IDE，你可以输入`import static org.junit.Assert`，看看有多少不同的断言可用（或者去 JUnit 的 API 文档中查看）。有十几个或更多的重载方法可用：`assertArrayEquals()`，`assertEquals()`，`assertNotEquals()`，`assertNull()`，`assertNotNull()`，`assertSame()`，`assertNotSame()`，`assertFalse()`，`assertTrue()`，`assertThat()`和`fail()`。如果你花几分钟阅读这些方法的作用将会很有帮助。你也可以根据它们的名称猜测它们的目的。下面是`assertEquals()`方法的使用示例：

```java
import org.junit.Test;
import static org.junit.Assert.assertEquals;
public class VehicleTest {
  @Test
  public void testGetSpeedMph(){
    System.out.println("Hello!" + " I am your first test method!");
    assertEquals(4, "Hello".length());
  }
}
```

我们比较单词`Hello`的实际长度和预期长度`4`。我们知道正确的数字应该是`5`，但我们希望测试失败以演示失败的行为。如果你运行前面的测试，你会得到以下结果：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java11-cb/img/e1062cd4-ecc4-430c-ab74-b23fe96f171d.png)

正如你所看到的，最后一行告诉你出了什么问题：预期值是`4`，而实际值是`5`。假设你像这样交换参数的顺序：

```java
assertEquals("Assert Hello length:","Hello".length(), 4);
```

结果将如下所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java11-cb/img/264588c3-e7e2-41ef-a779-f2450921c91e.png)

现在最后一条消息是误导性的。

重要的是要记住，在每个断言方法中，预期值的参数位于（在断言的签名中）**实际值之前**。

写完测试后，你会做其他事情，几个月后，你可能会忘记每个断言实际评估了什么。但有一天测试可能会失败（因为应用程序代码已更改）。你会看到测试方法名称，预期值和实际值，但你必须深入代码以找出哪个断言失败（每个测试方法通常有几个断言）。你可能会被迫添加调试语句并多次运行测试以找出原因。

为了帮助你避免这种额外的挖掘，JUnit 的每个断言都允许你添加描述特定断言的消息。例如，运行测试的这个版本：

```java
public class VehicleTest {
  @Test
  public void testGetSpeedMph(){
    System.out.println("Hello!" + " I am your first test method!");
    assertEquals("Assert Hello length:", 4, "Hello".length());
  }
}
```

如果你这样做，结果会更容易阅读：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java11-cb/img/240214a0-c228-4e70-a98e-c153f7a27484.png)

为了完成这个演示，我们将预期值更改为`5`：

```java
assertEquals("Assert Hello length:", 5, "Hello".length());
```

现在测试结果显示没有失败：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java11-cb/img/88e0720a-1f8b-4fdd-a58a-754ace2cc9aa.png)

# 它是如何工作的...

具备了对 JUnit 框架使用的基本理解，我们现在可以为计算具有特定重量和特定马力发动机的车辆速度的主要情况编写一个真正的测试方法。我们首先使用速度计算的公式手动计算预期值。例如，如果车辆的发动机功率为 246 hp，重量为 4,000 磅，那么在 10 秒内，其速度可以达到 117 英里/小时。由于速度是`double`类型，我们将使用带有一些 delta 的断言。否则，由于`double`值在计算机中的表示方式，两个`double`值可能永远不会相等。这是`org.junit.Assert`类的断言方法：

```java
void assertEquals(String message, double expected, 
                       double actual, double delta)
```

`delta`值是允许的精度。`test`方法的最终实现将如下所示：

```java
@Test
public void testGetSpeedMph(){
  double timeSec = 10.0;
  int engineHorsePower = 246;
  int vehicleWeightPounds = 4000;

  Engine engine = new Engine();
  engine.setHorsePower(engineHorsePower);

  Vehicle vehicle = new Vehicle(vehicleWeightPounds, engine);
  double speed = vehicle.getSpeedMph(timeSec);
  assertEquals("Assert vehicle (" + engineHorsePower 
            + " hp, " + vehicleWeightPounds + " lb) speed in " 
            + timeSec + " sec: ", 117, speed, 0.001 * speed);
}
```

如您所见，我们已经决定值的千分之一是我们目的的足够精度。如果我们运行前面的测试，输出将如下所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java11-cb/img/c294b3f1-8103-4030-8038-af6f531c11b1.png)

为了确保测试有效，我们可以将预期值设置为 119 英里/小时（与实际值相差超过 1％）并再次运行测试。结果将如下所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java11-cb/img/f79b70e9-475a-488a-8edc-f53d54f8b2b9.png)

我们将预期值改回 117，并继续编写我们在分析代码时讨论的其他测试用例。

让我们确保在预期时抛出异常。为此，我们添加另一个导入：

```java
import static org.junit.Assert.fail;

```

然后，我们可以编写测试代码，测试当`Vehicle`类的构造函数中传递的值为 null 时的情况（因此应该抛出异常）：

```java
@Test
public void testGetSpeedMphException(){
  int vehicleWeightPounds = 4000;
  Engine engine = null;
  try {
    Vehicle vehicle = new Vehicle(vehicleWeightPounds, engine);
    fail("Exception was not thrown");
  } catch (RuntimeException ex) {}
}
```

这个测试成功运行，这意味着`Vehicle`构造函数抛出了异常，并且代码从未到达过这一行：

```java
    fail("Exception was not thrown");

```

为了确保测试正确工作，我们临时将非 null 值传递给`Vehicle`构造函数：

```java
Engine engine = new Engine();
```

然后，我们观察输出：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java11-cb/img/e2efee35-c323-40dd-8a33-0dfb9df40e43.png)

通过这种方式，我们可以确保我们的测试按预期工作。或者，我们可以创建另一个测试，当抛出异常时失败：

```java
@Test
public void testGetSpeedMphException(){
  int vehicleWeightPounds = 4000;
  Engine engine = new Engine();
  try {
    Vehicle vehicle = new Vehicle(vehicleWeightPounds, engine);
  } catch (RuntimeException ex) {
    fail("Exception was thrown");
  }
}
```

编写这样的测试的最佳方式是在编写应用程序代码的过程中，这样您可以随着代码的复杂性增长而测试代码。否则，特别是在更复杂的代码中，您可能在编写所有代码后有问题调试它。

还有一些其他注释和 JUnit 功能对您可能有帮助，因此请参考 JUnit 文档，以更深入地了解所有框架功能。

# 通过模拟依赖项进行单元测试

编写单元测试需要控制所有输入数据。如果一个方法从其他对象接收其输入，就需要限制测试的深度，以便每个层可以作为一个单元独立测试。这就是模拟较低级别的需求时出现的情况。

模拟不仅可以垂直进行，还可以在同一级别水平进行。如果一个方法很大且复杂，您可能需要考虑将其拆分为几个较小的方法，这样您可以在模拟其他方法的同时仅测试其中一个。这是单元测试代码与其开发一起的另一个优势；在开发的早期阶段更容易重新设计代码以获得更好的可测试性。

# 准备就绪

模拟其他方法和类很简单。编码到接口（如第二章中描述的*快速跟踪到 OOP-类和接口*）使得这变得更容易，尽管有一些模拟框架允许您模拟不实现任何接口的类（我们将在本食谱的下一部分看到此类框架使用的示例）。此外，使用对象和方法工厂可以帮助您创建特定于测试的工厂实现，以便它们可以生成具有返回预期硬编码值的方法的对象。

例如，在第四章*函数式编程*中，我们介绍了`FactoryTraffic`，它生产了一个或多个`TrafficUnit`对象。在真实系统中，这个工厂会从某个外部系统中获取数据。使用真实系统作为数据源可能会使代码设置变得复杂。正如你所看到的，为了解决这个问题，我们通过根据与真实系统相似的分布生成数据来模拟数据：汽车比卡车多一点，车辆的重量取决于汽车的类型，乘客数量和有效载荷的重量等。对于这样的模拟，重要的是值的范围（最小值和最大值）应该反映出来自真实系统的值，这样应用程序就可以在可能的真实数据的全部范围内进行测试。

模拟代码的重要约束是它不应该太复杂。否则，它的维护将需要额外的开销，这将要么降低团队的生产力，要么降低测试覆盖率。

# 如何做...

`FactoryTraffic`的模拟可能如下所示：

```java
public class FactoryTraffic {
  public static List<TrafficUnit> generateTraffic(int 
    trafficUnitsNumber, Month month, DayOfWeek dayOfWeek, 
    int hour, String country, String city, String trafficLight){
    List<TrafficUnit> tms = new ArrayList();
    for (int i = 0; i < trafficUnitsNumber; i++) {
      TrafficUnit trafficUnit = 
        FactoryTraffic.getOneUnit(month, dayOfWeek,  hour, country, 
                                  city, trafficLight);
        tms.add(trafficUnit);
    }
    return tms;
  }
}
```

它组装了一个`TrafficUnit`对象的集合。在真实系统中，这些对象可以从例如某个数据库查询结果的行创建。但在我们的情况下，我们只是硬编码了这些值：

```java
public static TrafficUnit getOneUnit(Month month, 
              DayOfWeek dayOfWeek, int hour, String country, 
              String city, String trafficLight) {
  double r0 = Math.random(); 
  VehicleType vehicleType = r0 < 0.4 ? VehicleType.CAR :
  (r0 > 0.6 ? VehicleType.TRUCK : VehicleType.CAB_CREW);
  double r1 = Math.random();
  double r2 = Math.random();
  double r3 = Math.random();
  return new TrafficModelImpl(vehicleType, gen(4,1),
             gen(3300,1000), gen(246,100), gen(4000,2000),
             (r1 > 0.5 ? RoadCondition.WET : RoadCondition.DRY),    
             (r2 > 0.5 ? TireCondition.WORN : TireCondition.NEW),
             r1 > 0.5 ? ( r3 > 0.5 ? 63 : 50 ) : 63 );
}
```

如你所见，我们使用随机数生成器来为每个参数选择一个范围内的值。这个范围与真实数据的范围一致。这段代码非常简单，不需要太多的维护，但它提供了与真实数据类似的数据流给应用程序。

你可以使用另一种技术。例如，让我们重新审视`VechicleTest`类。我们可以使用其中一个模拟框架来模拟而不是创建一个真实的`Engine`对象。在这种情况下，我们使用 Mockito。以下是它的 Maven 依赖项：

```java
<dependency>
  <groupId>org.mockito</groupId>
  <artifactId>mockito-core</artifactId>
  <version>2.7.13</version>
  <scope>test</scope>
</dependency>

```

测试方法现在看起来像这样（已更改的两行已突出显示）：

```java
@Test
public void testGetSpeedMph(){
  double timeSec = 10.0;
  int engineHorsePower = 246;
  int vehicleWeightPounds = 4000;

 Engine engine = Mockito.mock(Engine.class);
  Mockito.when(engine.getHorsePower()).thenReturn(engineHorsePower);

  Vehicle vehicle =  new Vehicle(vehicleWeightPounds, engine);
  double speed = vehicle.getSpeedMph(timeSec);
  assertEquals("Assert vehicle (" + engineHorsePower 
               + " hp, " + vehicleWeightPounds + " lb) speed in " 
               + timeSec + " sec: ", 117, speed, 0.001 * speed);
}
```

如你所见，我们指示`mock`对象在调用`getHorsePower()`方法时返回一个固定值。我们甚至可以为我们想要测试的方法创建一个模拟对象：

```java
Vehicle vehicleMock = Mockito.mock(Vehicle.class);
Mockito.when(vehicleMock.getSpeedMph(10)).thenReturn(30d);

double speed = vehicleMock.getSpeedMph(10);
System.out.println(speed);

```

因此，它总是返回相同的值：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java11-cb/img/8d517f9e-a80c-4179-abb1-a42149aed65b.png)

然而，这将违背测试的目的，因为我们想测试计算速度的代码，而不是模拟它。

对于测试流的管道方法，还可以使用另一种技术。假设我们需要测试`TrafficDensity1`类中的`trafficByLane()`方法（我们也将有`TrafficDensity2`和`TrafficDensity3`）：

```java
public class TrafficDensity1 {
  public Integer[] trafficByLane(Stream<TrafficUnit> stream, 
  int trafficUnitsNumber, double timeSec,
  SpeedModel speedModel, double[] speedLimitByLane) {

    int lanesCount = speedLimitByLane.length;

    Map<Integer, Integer> trafficByLane = stream
      .limit(trafficUnitsNumber)
      .map(TrafficUnitWrapper::new)
      .map(tuw -> tuw.setSpeedModel(speedModel))
      .map(tuw -> tuw.calcSpeed(timeSec))
      .map(speed ->  countByLane(lanesCount, speedLimitByLane, speed))
      .collect(Collectors.groupingBy(CountByLane::getLane, 
               Collectors.summingInt(CountByLane::getCount)));

    for(int i = 1; i <= lanesCount; i++){
      trafficByLane.putIfAbsent(i, 0);
    }
    return trafficByLane.values()
      .toArray(new Integer[lanesCount]);
  }

  private CountByLane countByLane(int lanesCount, 
                 double[] speedLimit, double speed) {
    for(int i = 1; i <= lanesCount; i++){
      if(speed <= speedLimit[i - 1]){
        return new CountByLane(1, i);
      }
    }
    return new CountByLane(1, lanesCount);
  }
}
```

它使用了两个支持类：

```java
private class CountByLane{
  int count, lane;
  private CountByLane(int count, int lane){
    this.count = count;
    this.lane = lane;
  }
  public int getLane() { return lane; }
  public int getCount() { return count; }
}
```

它还使用以下内容：

```java
private static class TrafficUnitWrapper {
  private Vehicle vehicle;
  private TrafficUnit trafficUnit;
  public TrafficUnitWrapper(TrafficUnit trafficUnit){
    this.vehicle = FactoryVehicle.build(trafficUnit);
    this.trafficUnit = trafficUnit;
  }
  public TrafficUnitWrapper setSpeedModel(SpeedModel speedModel) {
    this.vehicle.setSpeedModel(speedModel);
    return this;
  }
  public double calcSpeed(double timeSec) {
    double speed = this.vehicle.getSpeedMph(timeSec);
    return Math.round(speed * this.trafficUnit.getTraction());
  }
}
```

我们在第三章*模块化编程*中演示了这些支持类的使用，同时讨论了流。现在我们意识到测试这个类可能不容易。

因为`SpeedModel`对象是`trafficByLane()`方法的输入参数，我们可以单独测试它的`getSpeedMph()`方法：

```java
@Test
public void testSpeedModel(){
  double timeSec = 10.0;
  int engineHorsePower = 246;
  int vehicleWeightPounds = 4000;
  double speed = getSpeedModel().getSpeedMph(timeSec,
                 vehicleWeightPounds, engineHorsePower);
  assertEquals("Assert vehicle (" + engineHorsePower 
               + " hp, " + vehicleWeightPounds + " lb) speed in " 
               + timeSec + " sec: ", 117, speed, 0.001 * speed);
}

private SpeedModel getSpeedModel(){
  //FactorySpeedModel possibly
}
```

参考以下代码：

```java
public class FactorySpeedModel {
  public static SpeedModel generateSpeedModel(TrafficUnit trafficUnit){
    return new SpeedModelImpl(trafficUnit);
  }
  private static class SpeedModelImpl implements SpeedModel{
    private TrafficUnit trafficUnit;
    private SpeedModelImpl(TrafficUnit trafficUnit){
      this.trafficUnit = trafficUnit;
    }
    public double getSpeedMph(double timeSec, 
                              int weightPounds, int horsePower) {
      double traction = trafficUnit.getTraction();
      double v = 2.0 * horsePower * 746 
                 * timeSec * 32.174 / weightPounds;
      return Math.round(Math.sqrt(v) * 0.68 * traction);
    }
  }
```

如你所见，`FactorySpeedModel`的当前实现需要`TrafficUnit`对象以获取牵引值。为了解决这个问题，我们可以修改前面的代码并移除`SpeedModel`对`TrafficUnit`的依赖。我们可以通过将牵引应用到`calcSpeed()`方法来实现。`FactorySpeedModel`的新版本可以看起来像这样：

```java
public class FactorySpeedModel {
  public static SpeedModel generateSpeedModel(TrafficUnit 
                                                   trafficUnit) {
    return new SpeedModelImpl(trafficUnit);
  }
 public static SpeedModel getSpeedModel(){
 return SpeedModelImpl.getSpeedModel();
 }
  private static class SpeedModelImpl implements SpeedModel{
    private TrafficUnit trafficUnit;
    private SpeedModelImpl(TrafficUnit trafficUnit){
      this.trafficUnit = trafficUnit;
    }
    public double getSpeedMph(double timeSec, 
                     int weightPounds, int horsePower) {
      double speed = getSpeedModel()
             .getSpeedMph(timeSec, weightPounds, horsePower);
      return Math.round(speed *trafficUnit.getTraction());
    }
    public static SpeedModel getSpeedModel(){
      return  (t, wp, hp) -> {
        double weightPower = 2.0 * hp * 746 * 32.174 / wp;
        return Math.round(Math.sqrt(t * weightPower) * 0.68);
      };
    }
  }
}
```

现在可以实现测试方法如下：

```java
@Test
public void testSpeedModel(){
  double timeSec = 10.0;
  int engineHorsePower = 246;
  int vehicleWeightPounds = 4000;
  double speed = FactorySpeedModel.generateSpeedModel()
                 .getSpeedMph(timeSec, vehicleWeightPounds, 
                              engineHorsePower);
  assertEquals("Assert vehicle (" + engineHorsePower 
               + " hp, " + vehicleWeightPounds + " lb) speed in " 
               + timeSec + " sec: ", 117, speed, 0.001 * speed);
}
```

然而，`TrafficUnitWrapper`中的`calcSpeed()`方法仍未经过测试。我们可以将`trafficByLane()`方法作为一个整体进行测试：

```java
@Test
public void testTrafficByLane() {
  TrafficDensity1 trafficDensity = new TrafficDensity1();
  double timeSec = 10.0;
  int trafficUnitsNumber = 120;
  double[] speedLimitByLane = {30, 50, 65};
  Integer[] expectedCountByLane = {30, 30, 60};
  Integer[] trafficByLane = 
    trafficDensity.trafficByLane(getTrafficUnitStream2(
      trafficUnitsNumber), trafficUnitsNumber, timeSec, 
      FactorySpeedModel.getSpeedModel(),speedLimitByLane);
    assertArrayEquals("Assert count of " 
              + trafficUnitsNumber + " vehicles by " 
              + speedLimitByLane.length +" lanes with speed limit " 
              + Arrays.stream(speedLimitByLane)
                      .mapToObj(Double::toString)
                      .collect(Collectors.joining(", ")),
                      expectedCountByLane, trafficByLane);
}
```

但这将需要创建一个具有固定数据的`TrafficUnit`对象流：

```java
TrafficUnit getTrafficUnit(int engineHorsePower, 
                           int vehicleWeightPounds) {
  return new TrafficUnit() {
    @Override
    public Vehicle.VehicleType getVehicleType() {
      return Vehicle.VehicleType.TRUCK;
    }
    @Override
    public int getHorsePower() {return engineHorsePower;}
    @Override
    public int getWeightPounds() { return vehicleWeightPounds; }
    @Override
    public int getPayloadPounds() { return 0; }
    @Override
    public int getPassengersCount() { return 0; }
    @Override
    public double getSpeedLimitMph() { return 55; }
    @Override
    public double getTraction() { return 0.2; }
    @Override
    public SpeedModel.RoadCondition getRoadCondition(){return null;}
    @Override
    public SpeedModel.TireCondition getTireCondition(){return null;}
    @Override
    public int getTemperature() { return 0; }
  };
}
```

这样的解决方案不能为不同车辆类型和其他参数提供各种测试数据。我们需要重新审视`trafficByLane()`方法的设计。

# 它是如何工作的...

如果你仔细观察`trafficByLane()`方法，你会注意到问题是由于计算的位置——在私有类`TrafficUnitWrapper`内部。我们可以将其移出，并在`TrafficDensity`类中创建一个新的`calcSpeed()`方法：

```java
double calcSpeed(double timeSec) {
  double speed = this.vehicle.getSpeedMph(timeSec);
  return Math.round(speed * this.trafficUnit.getTraction());
}
```

然后，我们可以改变其签名，并将`Vehicle`对象和`traction`系数作为参数包括进去：

```java
double calcSpeed(Vehicle vehicle, double traction, double timeSec){
  double speed = vehicle.getSpeedMph(timeSec);
  return Math.round(speed * traction);
}
```

让我们还向`TrafficUnitWrapper`类添加两个方法（您马上就会看到我们为什么需要它们）：

```java
public Vehicle getVehicle() { return vehicle; }
public double getTraction() { return trafficUnit.getTraction(); }
```

前面的更改允许我们重写流管道如下（更改的行用粗体标出）：

```java
Map<Integer, Integer> trafficByLane = stream
  .limit(trafficUnitsNumber)
  .map(TrafficUnitWrapper::new)
  .map(tuw -> tuw.setSpeedModel(speedModel))
  .map(tuw -> calcSpeed(tuw.getVehicle(), tuw.getTraction(), timeSec))
  .map(speed -> countByLane(lanesCount, speedLimitByLane, speed))
      .collect(Collectors.groupingBy(CountByLane::getLane, 
            Collectors.summingInt(CountByLane::getCount)));

```

通过将`calcSpeed()`方法设置为 protected，并假设`Vehicle`类在其自己的测试类`VehicleTest`中进行了测试，我们现在可以编写`testCalcSpeed()`方法：

```java
@Test
public void testCalcSpeed(){
  double timeSec = 10.0;
  TrafficDensity2 trafficDensity = new TrafficDensity2();

  Vehicle vehicle = Mockito.mock(Vehicle.class);
  Mockito.when(vehicle.getSpeedMph(timeSec)).thenReturn(100d);
  double traction = 0.2;
  double speed = trafficDensity.calcSpeed(vehicle, traction, timeSec);
  assertEquals("Assert speed (traction=" + traction + ") in " 
               + timeSec + " sec: ",20,speed,0.001 *speed);
}
```

剩下的功能可以通过模拟`calcSpeed()`方法来测试：

```java
@Test
public void testCountByLane() {
  int[] count ={0};
  double[] speeds = 
                  {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
  TrafficDensity2 trafficDensity = new TrafficDensity2() {
    @Override
    protected double calcSpeed(Vehicle vehicle, 
                     double traction, double timeSec) {
      return speeds[count[0]++];
    }
  };
  double timeSec = 10.0;
  int trafficUnitsNumber = speeds.length;

  double[] speedLimitByLane = {4.5, 8.5, 12.5};
  Integer[] expectedCountByLane = {4, 4, 4};

  Integer[] trafficByLane = trafficDensity.trafficByLane( 
    getTrafficUnitStream(trafficUnitsNumber), 
    trafficUnitsNumber, timeSec, FactorySpeedModel.getSpeedModel(),
    speedLimitByLane );
  assertArrayEquals("Assert count of " + speeds.length 
          + " vehicles by " + speedLimitByLane.length 
          + " lanes with speed limit " 
          + Arrays.stream(speedLimitByLane)
             .mapToObj(Double::toString).collect(Collectors
             .joining(", ")), expectedCountByLane, trafficByLane);
}
```

# 还有更多...

这种经验使我们意识到，使用内部私有类可能会使功能在隔离中无法测试。让我们试着摆脱`private`类`CountByLane`。这将导致`TrafficDensity3`类的第三个版本（更改的代码已突出显示）：

```java
Integer[] trafficByLane(Stream<TrafficUnit> stream, 
int trafficUnitsNumber, double timeSec,
SpeedModel speedModel, double[] speedLimitByLane) {
  int lanesCount = speedLimitByLane.length;
  Map<Integer, Integer> trafficByLane = new HashMap<>();
  for(int i = 1; i <= lanesCount; i++){
    trafficByLane.put(i, 0);
  }
  stream.limit(trafficUnitsNumber)
    .map(TrafficUnitWrapper::new)
    .map(tuw -> tuw.setSpeedModel(speedModel))
    .map(tuw -> calcSpeed(tuw.getVehicle(), tuw.getTraction(), 
                                                         timeSec))
 .forEach(speed -> trafficByLane.computeIfPresent(
 calcLaneNumber(lanesCount, 
                         speedLimitByLane, speed), (k, v) -> ++v));    return trafficByLane.values().toArray(new Integer[lanesCount]);}
protected int calcLaneNumber(int lanesCount, 
  double[] speedLimitByLane, double speed) {
 for(int i = 1; i <= lanesCount; i++){
 if(speed <= speedLimitByLane[i - 1]){
 return i;
      }
 }
 return lanesCount;
}
```

这个改变允许我们在我们的测试中扩展这个类：

```java
class TrafficDensityTestCalcLaneNumber extends TrafficDensity3 {
  protected int calcLaneNumber(int lanesCount, 
    double[] speedLimitByLane, double speed){
    return super.calcLaneNumber(lanesCount, 
    speedLimitByLane, speed);
  }
}
```

它还允许我们单独更改`calcLaneNumber()`测试方法：

```java
@Test
public void testCalcLaneNumber() {
  double[] speeds = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
  double[] speedLimitByLane = {4.5, 8.5, 12.5};
  int[] expectedLaneNumber = {1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3};

  TrafficDensityTestCalcLaneNumber trafficDensity = 
               new TrafficDensityTestCalcLaneNumber();
  for(int i = 0; i < speeds.length; i++){
    int ln = trafficDensity.calcLaneNumber(
               speedLimitByLane.length, 
               speedLimitByLane, speeds[i]);
    assertEquals("Assert lane number of speed " 
                + speeds + " with speed limit " 
                + Arrays.stream(speedLimitByLane)
                        .mapToObj(Double::toString).collect(
                              Collectors.joining(", ")), 
                expectedLaneNumber[i], ln);
  }
}
```

# 使用 fixtures 来为测试填充数据

在更复杂的应用程序中（例如使用数据库），通常需要在每个测试之前设置数据，并在测试完成后清理数据。一些数据的部分需要在每个测试方法之前设置和/或在每个测试方法完成后清理。其他数据可能需要在测试类的任何测试方法运行之前设置，并/或在测试类的最后一个测试方法完成后清理。

# 如何做...

为了实现这一点，您在其前面添加了一个`@Before`注释，这表示这个方法必须在每个测试方法之前运行。相应的清理方法由`@After`注释标识。类级别的设置方法由`@BeforeClass`和`@AfterClass`注释标识，这意味着这些设置方法只会在测试类的任何测试方法执行之前执行一次（`@BeforeClass`），并在测试类的最后一个测试方法执行之后执行一次（`@AfterClass`）。这是一个快速演示：

```java
public class DatabaseRelatedTest {
  @BeforeClass
  public static void setupForTheClass(){
    System.out.println("setupForTheClass() is called");
  }
  @AfterClass
  public static void cleanUpAfterTheClass(){
    System.out.println("cleanAfterClass() is called");
  }
  @Before
  public void setupForEachMethod(){
    System.out.println("setupForEachMethod() is called");
  }
  @After
  public void cleanUpAfterEachMethod(){
    System.out.println("cleanAfterEachMethod() is called");
  }
  @Test
  public void testMethodOne(){      
    System.out.println("testMethodOne() is called"); 
  }
  @Test
  public void testMethodTwo(){ 
    System.out.println("testMethodTwo() is called"); 
  }
}
```

如果现在运行测试，你会得到以下结果：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java11-cb/img/5c124906-d843-4d1d-8a75-ba87f6e17401.png)

这种修复测试上下文的方法称为**fixtures**。请注意，它们必须是公共的，类级别的设置/清理 fixtures 必须是静态的。然而，即将推出的 JUnit 版本 5 计划取消这些限制。

# 它是如何工作的...

这种用法的典型例子是在第一个测试方法运行之前创建必要的表，并在测试类的最后一个方法完成后删除它们。设置/清理方法也可以用于创建/关闭数据库连接，除非您的代码在 try-with-resources 结构中执行（参见第十一章，*内存管理和调试*）。

这是 fixtures 的一个使用示例（参见第六章，*数据库编程*，了解更多关于*如何设置数据库运行*的内容）。假设我们需要测试`DbRelatedMethods`类：

```java
class DbRelatedMethods{
  public void updateAllTextRecordsTo(String text){
    executeUpdate("update text set text = ?", text);
  }
  private void executeUpdate(String sql, String text){
    try (Connection conn = getDbConnection();
      PreparedStatement st = conn.prepareStatement(sql)){
        st.setString(1, text);
        st.executeUpdate();
      } catch (Exception ex) {
        ex.printStackTrace();
      }
    }
    private Connection getDbConnection(){
       //...  code that creates DB connection 
    }
}
```

我们希望确保前一个方法`updateAllTextRecordsTo()`总是使用提供的值更新`text`表的所有记录。我们的第一个测试`updateAllTextRecordsTo1()`是更新一个现有记录：

```java
@Test
public void updateAllTextRecordsTo1(){
  System.out.println("updateAllTextRecordsTo1() is called");
  String testString = "Whatever";
  System.out.println("  Update all records to " + testString);
  dbRelatedMethods.updateAllTextRecordsTo(testString);
  int count = countRecordsWithText(testString);
  assertEquals("Assert number of records with " 
                                  + testString + ": ", 1, count);
  System.out.println("All records are updated to " + testString);
}
```

这意味着表必须存在于测试数据库中，并且其中应该有一条记录。

我们的第二个测试，`updateAllTextRecordsTo2()`，确保即使每条记录包含不同的值，也会更新两条记录：

```java
@Test
public void updateAllTextRecordsTo2(){
  System.out.println("updateAllTextRecordsTo2() is called");
  String testString = "Unexpected";
  System.out.println("Update all records to " + testString);
  dbRelatedMethods.updateAllTextRecordsTo(testString);
  executeUpdate("insert into text(id,text) values(2, ?)","Text 01");

  testString = "Whatever";
  System.out.println("Update all records to " + testString);
  dbRelatedMethods.updateAllTextRecordsTo(testString);
  int count = countRecordsWithText(testString);
  assertEquals("Assert number of records with " 
               + testString + ": ", 2, count);
  System.out.println("  " + count + " records are updated to " +
                                                        testString);
}
```

前面的两个测试都使用了相同的表，即`text`。因此，在每次测试后无需删除表。这就是为什么我们在类级别创建和删除它的原因：

```java
@BeforeClass
public static void setupForTheClass(){
  System.out.println("setupForTheClass() is called");
  execute("create table text (id integer not null, 
          text character varying not null)");
}
@AfterClass
public static void cleanUpAfterTheClass(){
  System.out.println("cleanAfterClass() is called");
  execute("drop table text");
}
```

这意味着我们只需要在每个测试之前填充表格，并在每个测试完成后清理它：

```java
@Before
public void setupForEachMethod(){
  System.out.println("setupForEachMethod() is called");
  executeUpdate("insert into text(id, text) values(1,?)", "Text 01");
}
@After
public void cleanUpAfterEachMethod(){
  System.out.println("cleanAfterEachMethod() is called");
  execute("delete from text");
}
```

此外，由于我们可以为所有测试使用相同的对象`dbRelatedMethods`，因此让我们也在类级别上创建它（作为测试类的属性），这样它只会被创建一次：

```java
private DbRelatedMethods dbRelatedMethods = new DbRelatedMethods();

```

如果我们现在运行`test`类的所有测试，输出将如下所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java11-cb/img/05dd11a5-0699-4dfe-98cd-0ed6cbeb4627.png)

打印的消息可以让您跟踪所有方法调用的顺序，并查看它们是否按预期执行。

# 集成测试

如果您已经阅读了所有章节并查看了代码示例，您可能已经注意到，到目前为止，我们已经讨论并构建了典型分布式应用程序所需的所有组件。现在是将所有组件放在一起并查看它们是否按预期协作的时候了。这个过程被称为**集成**。

在这个过程中，我们将仔细评估应用程序是否符合要求。在功能需求以可执行形式呈现的情况下（例如使用 Cucumber 框架），我们可以运行它们并检查是否所有检查都通过。许多软件公司遵循行为驱动开发流程，并在很早的时候进行测试，有时甚至在编写大量代码之前（当然，这样的测试会失败，但一旦实现了预期的功能就会成功）。正如前面提到的，早期测试对于编写专注、清晰和易于测试的代码非常有帮助。

然而，即使不严格遵循“先测试”流程，集成阶段自然也包括某种行为测试。在本章中，我们将看到几种可能的方法和与此相关的具体示例。

# 准备就绪

您可能已经注意到，在本书的过程中，我们构建了几个组成应用程序的类，用于分析和建模交通。为了方便起见，我们已经将它们全部包含在`com.packt.cookbook.ch16_testing`包中。

从前面的章节中，您已经熟悉了`api`文件夹中的五个接口——`Car`、`SpeedModel`、`TrafficUnit`、`Truck`和`Vehicle`。它们的实现被封装在同名文件夹中的类中：`FactorySpeedModel`、`FactoryTraffic`和`FactoryVehicle`。这些工厂为我们的演示应用程序的核心类`AverageSpeed`（第七章，*并发和多线程编程*）和`TrafficDensity`（基于第五章，*流和管道*，但在本章中创建和讨论）提供输入。它们产生了激发开发这个特定应用程序的值。

应用程序的主要功能很简单。对于每条车道的车道数和速度限制，`AverageSpeed`计算（估计）每条车道的实际速度（假设所有驾驶员都是理性的，根据他们的速度选择车道），而`TrafficDensity`计算了 10 秒后每条车道上的车辆数（假设所有车辆在交通灯后同时开始）。这些计算是基于在特定位置和时间收集的`numberOfTrafficUnits`辆车的数据。这并不意味着所有的 1,000 辆车都在同一时间比赛。这 1,000 个测量点是在 50 年内收集的，用于在指定的交叉口在指定的小时内行驶的大约 20 辆车（平均每三分钟一辆车）。

应用程序的整体基础设施由`process`文件夹中的类支持：`Dispatcher`、`Processor`和`Subscription`。我们讨论了它们的功能，并在第七章，*并发和多线程编程*中进行了演示。这些类允许分发处理。

`Dispatcher`类向池中的`Processors`群发请求进行处理，使用`Subscription`类。每个`Processor`类根据请求执行任务（使用`AverageSpeed`和`TrafficDensity`类），并将结果存储在数据库中（使用`utils`文件夹中的`DbUtil`类，基于第六章中讨论的功能，*数据库编程*）。

我们已经将大多数这些类作为单元进行了测试。现在我们将对它们进行集成，并测试整个应用程序的正确行为。

这些要求仅用于演示目的。演示的目标是展示一些有动机的东西（类似真实数据），同时又足够简单，不需要特殊的交通分析和建模知识即可理解。

# 如何做...

集成有几个级别。我们需要集成应用程序的类和子系统，还需要将我们的应用程序与外部系统集成（由第三方开发和维护的交通数据源）。

这是使用`Chapter14Testing`类中的`demo1_class_level_integration()`方法进行类级别集成的示例：

```java
String result = IntStream.rangeClosed(1, 
  speedLimitByLane.length).mapToDouble(i -> {
    AverageSpeed averageSpeed = 
      new AverageSpeed(trafficUnitsNumber, timeSec, 
                       dateLocation, speedLimitByLane, i,100);
    ForkJoinPool commonPool = ForkJoinPool.commonPool();
    return commonPool.invoke(averageSpeed);
}).mapToObj(Double::toString).collect(Collectors.joining(", "));
System.out.println("Average speed = " + result);

TrafficDensity trafficDensity = new TrafficDensity();
Integer[] trafficByLane = 
     trafficDensity.trafficByLane(trafficUnitsNumber,
                    timeSec, dateLocation, speedLimitByLane );
System.out.println("Traffic density = "+Arrays.stream(trafficByLane)
                                .map(Object::toString)
                                .collect(Collectors.joining(", ")));

```

在这个例子中，我们集成了两个主要类，即`AverageSpeed`和`TrafficDensity`，并使用它们的接口的工厂和实现。

结果如下：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java11-cb/img/30015170-2ee5-4be1-8ace-87c4e98f8982.png)

请注意，结果在每次运行时略有不同。这是因为`FactoryTraffic`生成的数据在每个请求之间都有所不同。但是，在这个阶段，我们只需要确保一切协同工作，并产生一些看起来更或多或少准确的结果。我们已经通过单元测试了代码，并且对每个单元是否按预期工作有一定的信心。在实际集成*测试*过程中，而不是在集成过程中，我们将回到结果的验证。

在类级别完成集成后，使用`Chapter14Testing`类中的`demo1_subsystem_level_integration()`方法查看子系统如何一起工作：

```java
DbUtil.createResultTable();
Dispatcher.dispatch(trafficUnitsNumber, timeSec, dateLocation, 
                    speedLimitByLane);
try { Thread.sleep(2000L); } 
catch (InterruptedException ex) {}
Arrays.stream(Process.values()).forEach(v -> {
  System.out.println("Result " + v.name() + ": " 
                     + DbUtil.selectResult(v.name()));
});

```

在这段代码中，我们使用`DBUtil`创建了一个必要的表，用于保存`Processor`生成和记录的输入数据和结果。`Dispatcher`类向`Processor`类的对象发送请求和输入数据，如下所示：

```java
void dispatch(int trafficUnitsNumber, double timeSec, 
         DateLocation dateLocation, double[] speedLimitByLane) {
  ExecutorService execService =  ForkJoinPool.commonPool();
  try (SubmissionPublisher<Integer> publisher = 
                              new SubmissionPublisher<>()){
    subscribe(publisher, execService,Process.AVERAGE_SPEED, 
              timeSec, dateLocation, speedLimitByLane);
   subscribe(publisher,execService,Process.TRAFFIC_DENSITY, 
             timeSec, dateLocation, speedLimitByLane);
    publisher.submit(trafficUnitsNumber);
  } finally {
    try {
      execService.shutdown();
      execService.awaitTermination(1, TimeUnit.SECONDS);
    } catch (Exception ex) {
      System.out.println(ex.getClass().getName());
    } finally {
      execService.shutdownNow();
    }
  }
}
```

`Subscription`类用于发送/接收消息（参考第七章，*并发和多线程编程*，了解此功能的描述）：

```java
void subscribe(SubmissionPublisher<Integer> publisher, 
              ExecutorService execService, Process process, 
              double timeSec, DateLocation dateLocation, 
              double[] speedLimitByLane) {
  Processor<Integer> subscriber =  new Processor<>(process, timeSec, 
                                 dateLocation, speedLimitByLane);
  Subscription subscription = 
                       new Subscription(subscriber, execService);
  subscriber.onSubscribe(subscription);
  publisher.subscribe(subscriber);
}
```

处理器正在执行它们的工作；我们只需要等待几秒钟（如果您使用的计算机需要更多时间来完成工作，可以调整此时间）然后我们就可以得到结果。我们使用`DBUtil`从数据库中读取结果：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java11-cb/img/e2e9ca71-45f0-42b1-955e-071d82ab264d.png)

`Process`枚举类的名称指向数据库中`result`表中的相应记录。同样，在这个阶段，我们主要是希望得到任何结果，而不是关注值的正确性。

在基于`FactoryTraffic`生成的数据的应用程序子系统之间成功集成后，我们可以尝试连接提供真实交通数据的外部系统。在`FactoryTraffic`中，我们现在将从生成`TrafficUnit`对象切换到从真实系统获取数据：

```java
public class FactoryTraffic {
  private static boolean switchToRealData = true;
  public static Stream<TrafficUnit> 
  getTrafficUnitStream(DateLocation dl, int trafficUnitsNumber){
    if(switchToRealData){
      return getRealData(dL,  trafficUnitsNumber);
    } else {
      return IntStream.range(0, trafficUnitsNumber)
      .mapToObj(i -> generateOneUnit());
    }
  }

  private static Stream<TrafficUnit> 
  getRealData(DateLocation dl, int trafficUnitsNumber) {
    //connect to the source of the real data 
    // and request the flow or collection of data
    return new ArrayList<TrafficUnit>().stream();
  }
}
```

该开关可以作为类中的`Boolean`属性实现（如前面的代码所示），也可以作为项目配置属性。我们不会详细介绍连接到特定真实交通数据源的细节，因为这与本书的目的无关。

在这个阶段，主要关注性能，并在外部真实数据源和我们的应用程序之间实现平稳的数据流。在确保一切正常并且具有令人满意的性能的情况下，我们可以转向集成*测试*，并断言实际结果。

# 它是如何工作的...

对于测试，我们需要设置预期值，然后与处理真实数据的应用程序产生的实际值进行比较。但是真实数据在每次运行时都会略有变化，试图预测结果值要么使测试变得脆弱，要么迫使引入巨大的误差范围，这可能会有效地破坏测试的目的。

我们甚至不能模拟生成的数据（就像我们在单元测试中所做的那样），因为我们处于集成阶段，必须使用真实数据。

有一个可能的解决方案是将传入的真实数据和我们应用程序生成的结果存储在数据库中。然后，领域专家可以浏览每条记录，并断言结果是否符合预期。

为了实现这一点，我们在`TrafficDensity`类中引入了一个`boolean`开关，这样它就记录了每个计算单元的输入：

```java
public class TrafficDensity {
 public static Connection conn;
 public static boolean recordData = false;
  //... 
  private double calcSpeed(TrafficUnitWrapper tuw, double timeSec){
    double speed = calcSpeed(tuw.getVehicle(),       
    tuw.getTrafficUnit().getTraction(), timeSec);
 if(recordData) {
 DbUtil.recordData(conn, tuw.getTrafficUnit(), speed);
 }
    return speed;
  }
  //...
} 
```

我们还引入了一个静态属性，以保持所有类实例之间相同的数据库连接。否则，连接池应该很大，因为正如你可能从第七章中所记得的那样，*并发和多线程编程*，执行任务的工作人员数量随着要执行的工作量的增加而增加。

如果你看看`DbUtils`，你会看到一个创建`data`表的新方法，该表设计用于保存来自`FactoryTraffic`的`TrafficUnits`，以及保存用于数据请求和计算的主要参数的`data_common`表：请求的交通单位数量，交通数据的日期和地理位置，以秒为单位的时间（速度计算的时间点），以及每条车道的速度限制（其大小定义了我们在建模交通时计划使用多少条车道）。这是我们配置来进行记录的代码：

```java
private static void demo3_prepare_for_integration_testing(){
  DbUtil.createResultTable();
  DbUtil.createDataTables();
  TrafficDensity.recordData = true;
  try(Connection conn = DbUtil.getDbConnection()){
    TrafficDensity.conn = conn;
    Dispatcher.dispatch(trafficUnitsNumber, timeSec, 
                        dateLocation, speedLimitByLane);
  } catch (SQLException ex){
    ex.printStackTrace();
  }
}
```

记录完成后，我们可以将数据交给领域专家，他可以断言应用程序行为的正确性。

验证的数据现在可以用于集成测试。我们可以在`FactoryTrafficUnit`中添加另一个开关，并强制它读取记录的数据，而不是不可预测的真实数据：

```java
public class FactoryTraffic {
  public static boolean readDataFromDb = false;
  private static boolean switchToRealData = false;
  public static Stream<TrafficUnit> 
     getTrafficUnitStream(DateLocation dl, int trafficUnitsNumber){
 if(readDataFromDb){
 if(!DbUtil.isEnoughData(trafficUnitsNumber)){
 System.out.println("Not enough data");
        return new ArrayList<TrafficUnit>().stream();
      }
 return readDataFromDb(trafficUnitsNumber);
    }
    //....
}
```

正如你可能已经注意到的，我们还添加了`isEnoughData()`方法，用于检查是否有足够的记录数据：

```java
public static boolean isEnoughData(int trafficUnitsNumber){
  try (Connection conn = getDbConnection();
  PreparedStatement st = 
      conn.prepareStatement("select count(*) from data")){
    ResultSet rs = st.executeQuery();
    if(rs.next()){
      int count = rs.getInt(1);
      return count >= trafficUnitsNumber;
    }
  } catch (Exception ex) {
    ex.printStackTrace();
  }
  return false;
}
```

这将有助于避免在测试更复杂的系统时不必要的调试问题所带来的挫败感。

现在，我们不仅控制输入值，还可以控制预期结果，这些结果可以用来断言应用程序的行为。这两者现在都包含在`TrafficUnit`对象中。为了能够做到这一点，我们利用了第二章中讨论的新的 Java 接口特性，即接口默认方法：

```java
public interface TrafficUnit {
  VehicleType getVehicleType();
  int getHorsePower();
  int getWeightPounds();
  int getPayloadPounds();
  int getPassengersCount();
  double getSpeedLimitMph();
  double getTraction();
  RoadCondition getRoadCondition();
  TireCondition getTireCondition();
  int getTemperature();
 default double getSpeed(){ return 0.0; }
}
```

因此，我们可以将结果附加到输入数据。请参阅以下方法：

```java
List<TrafficUnit> selectData(int trafficUnitsNumber){...}
```

我们可以将结果附加到`DbUtil`类和`TrafficUnitImpl`类中的`DbUtil`中：

```java
class TrafficUnitImpl implements TrafficUnit{
  private int horsePower, weightPounds, payloadPounds, 
              passengersCount, temperature;
  private Vehicle.VehicleType vehicleType;
  private double speedLimitMph, traction, speed;
  private RoadCondition roadCondition;
  private TireCondition tireCondition;
  ...
  public double getSpeed() { return speed; }
}
```

我们也可以将其附加到`DbUtil`类中。

前面的更改使我们能够编写集成测试。首先，我们将使用记录的数据测试速度模型：

```java
void demo1_test_speed_model_with_real_data(){
  double timeSec = DbUtil.getTimeSecFromDataCommon();
  FactoryTraffic.readDataFromDb = true;
  TrafficDensity trafficDensity = new TrafficDensity();
  FactoryTraffic.
           getTrafficUnitStream(dateLocation,1000).forEach(tu -> {
    Vehicle vehicle = FactoryVehicle.build(tu);
    vehicle.setSpeedModel(FactorySpeedModel.getSpeedModel());
    double speed = trafficDensity.calcSpeed(vehicle, 
                               tu.getTraction(), timeSec);
    assertEquals("Assert vehicle (" + tu.getHorsePower() 
                 + " hp, " + tu.getWeightPounds() + " lb) speed in " 
                 + timeSec + " sec: ", tu.getSpeed(), speed, 
                 speed * 0.001);
  });
}
```

可以使用类似的方法来测试`AverageSpeed`类的速度计算。

然后，我们可以为类级别编写一个集成测试。

```java
private static void demo2_class_level_integration_test() {
  FactoryTraffic.readDataFromDb = true;
  String result = IntStream.rangeClosed(1, 
              speedLimitByLane.length).mapToDouble(i -> {
    AverageSpeed averageSpeed = new AverageSpeed(trafficUnitsNumber, 
               timeSec, dateLocation, speedLimitByLane, i,100);
    ForkJoinPool commonPool = ForkJoinPool.commonPool();
    return commonPool.invoke(averageSpeed);
  }).mapToObj(Double::toString).collect(Collectors.joining(", "));
  String expectedResult = "7.0, 23.0, 41.0";
  String limits = Arrays.stream(speedLimitByLane)
                        .mapToObj(Double::toString)
                        .collect(Collectors.joining(", "));
  assertEquals("Assert average speeds by " 
                + speedLimitByLane.length 
                + " lanes with speed limit " 
                + limits, expectedResult, result);

```

类似的代码也可以用于对 TrafficDensity 类进行类级别的测试：

```java
TrafficDensity trafficDensity = new TrafficDensity();
String result = Arrays.stream(trafficDensity.
       trafficByLane(trafficUnitsNumber, timeSec, 
                     dateLocation, speedLimitByLane))
       .map(Object::toString)
       .collect(Collectors.joining(", "));
expectedResult = "354, 335, 311";
assertEquals("Assert vehicle count by " + speedLimitByLane.length + 
         " lanes with speed limit " + limits, expectedResult, result);
```

最后，我们也可以为子系统级别编写集成测试：

```java
void demo3_subsystem_level_integration_test() {
  FactoryTraffic.readDataFromDb = true;
  DbUtil.createResultTable();
  Dispatcher.dispatch(trafficUnitsNumber, 10, dateLocation, 
                      speedLimitByLane);
  try { Thread.sleep(3000l); } 
  catch (InterruptedException ex) {}
  String result = DbUtil.selectResult(Process.AVERAGE_SPEED.name());
  String expectedResult = "7.0, 23.0, 41.0";
  String limits = Arrays.stream(speedLimitByLane)
                        .mapToObj(Double::toString)
                        .collect(Collectors.joining(", "));
  assertEquals("Assert average speeds by " + speedLimitByLane.length 
        + " lanes with speed limit " + limits, expectedResult, result);
  result = DbUtil.selectResult(Process.TRAFFIC_DENSITY.name());
  expectedResult = "354, 335, 311";
  assertEquals("Assert vehicle count by " + speedLimitByLane.length 
        + " lanes with speed limit " + limits, expectedResult, result);
}
```

所有前面的测试现在都成功运行，并且随时可以用于应用程序的回归测试。

只有当后者具有测试模式时，我们才能创建应用程序与真实交通数据源之间的自动集成测试，从而可以以与使用记录数据相同的方式发送相同的数据流。

所有这些集成测试都是可能的，当处理数据的数量在统计上是显著的时候。这是因为我们无法完全控制工作人员的数量以及 JVM 如何决定分配负载。很可能，在特定情况下，本章中演示的代码可能无法正常工作。在这种情况下，尝试增加请求的流量单位数量。这将确保更多的空间用于负载分配逻辑。
