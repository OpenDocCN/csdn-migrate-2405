# Java7 新特性秘籍（一）

> 原文：[`zh.annas-archive.org/md5/5FB42CDAFBC18FB5D8DD681ECE2B0206`](https://zh.annas-archive.org/md5/5FB42CDAFBC18FB5D8DD681ECE2B0206)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

随着 Java 7 的发布，许多新功能已被添加，显著提高了开发人员创建和维护 Java 应用程序的能力。这些包括语言改进，如更好的异常处理技术，以及 Java 核心库的添加，如新的线程机制。

本书使用一系列配方涵盖了这些新功能。每个配方都涉及一个或多个新功能，并提供了使用这些功能的模板。这应该使读者更容易理解这些功能以及何时以及如何使用它们。提供了逐步说明，以指导读者完成配方，然后解释生成的代码。

本书以讨论新语言增强开始，然后是一系列章节，每个章节都涉及特定领域，如文件和目录管理。假定读者熟悉 Java 6 的功能。本书不需要按顺序阅读，这使读者可以选择感兴趣的章节和配方。但建议读者阅读第一章，因为后续配方中会使用那里的许多功能。如果在配方中使用了其他新的 Java 7 功能，则提供了相关配方的交叉引用。

# 本书涵盖的内容

第一章, *Java 语言改进:* 本章讨论了作为 Coin 项目的一部分引入的各种语言改进。这些功能包括简单的改进，如在文字中使用下划线和在 switch 语句中使用字符串。还有更重要的改进，如 try-with-resources 块和引入的菱形操作符。

第二章, *使用路径定位文件和目录:* 本章介绍了 Path 类。它在本章和其他章节中被使用，并且是 Java 7 中许多新的与文件相关的添加的基础。

第三章, *获取文件和目录信息:* 许多应用程序需要访问特定的文件和目录信息。本章介绍了如何访问文件信息，包括访问基本文件属性、Posix 属性和文件的访问控制列表等信息。

第四章, *管理文件和目录:* 本章涵盖了管理文件和目录的基本机制，包括创建和删除文件等操作。还讨论了临时文件的使用和符号链接的管理。

第五章, *管理文件系统:* 这里介绍了许多有趣的主题，如如何获取文件系统和文件存储信息、用于遍历文件结构的类、如何监视文件和目录事件以及如何使用 ZIP 文件系统。

第六章, *Java 7 中的流 IO:* 引入了 NIO2。详细介绍了执行异步 IO 的新技术，以及执行随机访问 IO 和使用安全目录流的新方法。

第七章, *图形用户界面改进:* Java 7 中增加了几项功能，以解决创建 GUI 界面的问题。现在可以创建不同形状的窗口和透明窗口。此外，还解释了许多增强功能，如使用 JLayer 装饰器，它改善了在窗口上叠加图形的能力。

第八章，*事件处理：* 在本章中，我们将研究处理各种应用程序事件的新方法。Java 7 现在支持额外的鼠标按钮和精确的鼠标滚轮。改进了控制窗口焦点的能力，并引入了辅助循环来模拟模态对话框的行为。

第九章，*数据库、安全和系统增强：* 说明了各种数据库改进，例如引入新的 RowSetFactory 类以及如何利用新的 SSL 支持。此外，还演示了其他系统改进，例如对 MXBeans 的额外支持。

第十章，*并发处理：* 添加了几个新类来支持线程的使用，包括支持 fork/join 范式、phaser 模型、改进的 dequeue 类和 transfer queue 类的类。解释了用于生成随机数的新 ThreadLocalRandom 类。

第十一章，*杂项：* 本章演示了许多其他 Java 7 改进，例如对周、年和货币的新支持。本章还包括了对处理空引用的改进支持。

# 您需要为这本书做什么

本书所需的软件包括 Java 开发工具包（JDK）1.7 或更高版本。任何支持 Java 7 的集成开发环境都可以用于创建和执行示例。本书中的示例是使用 NetBeans 7.0.1 开发的。

# 这本书适合谁

本书旨在让熟悉 Java 的人了解 Java 7 中的新功能。

# 约定

在本书中，您会发现一些文本样式，用于区分不同类型的信息。以下是一些这些样式的示例，以及它们的含义解释。

文本中的代码单词显示如下：“我们可以通过使用`include`指令包含其他上下文。”

代码块设置如下：

```java
private void gameEngine(List<Entity> entities)
{
final Phaser phaser = new Phaser(1);
for (final Entity entity : entities)
{
final String member = entity.toString();
System.out.println(member + " joined the game");
phaser.register();
new Thread()
{
@Override
public void run()
{
System.out.println(member +
" waiting for the remaining participants");
phaser.arriveAndAwaitAdvance(); // wait for remaining entities
System.out.println(member + " starting run");
entity.run();
}
}.start();
}
phaser.arriveAndDeregister(); //Deregister and continue
System.out.println("Phaser continuing");
}
```

当我们希望引起您对代码块的特定部分的注意时，相关的行或项目会以粗体显示：

```java
private void gameEngine(List<Entity> entities)
{
final Phaser phaser = new Phaser(1);
for (final Entity entity : entities)
{
final String member = entity.toString();
System.out.println(member + " joined the game");
phaser.register();
new Thread()
{
@Override
public void run()
{
System.out.println(member +
" waiting for the remaining participants");
phaser.arriveAndAwaitAdvance(); // wait for remaining entities
System.out.println(member + " starting run");
entity.run();
}
}.start();
}
phaser.arriveAndDeregister(); //Deregister and continue
System.out.println("Phaser continuing");
}

```

任何命令行输入或输出都是这样写的：

```java
Paths.get(new URI("file:///C:/home/docs/users.txt")), Charset.defaultCharset()))

```

新术语和重要单词以粗体显示。您在屏幕上看到的单词，例如菜单或对话框中的单词，会在文本中以这种方式出现：“单击**下一步**按钮将您移动到下一个屏幕”。

### 注意

警告或重要说明会以这样的方式出现在框中。

### 提示

提示和技巧看起来像这样。

# 读者反馈

我们始终欢迎读者的反馈。请告诉我们您对本书的看法——您喜欢或不喜欢的地方。读者的反馈对我们开发您真正受益的标题非常重要。

要向我们发送一般反馈，只需发送电子邮件至`<feedback@packtpub.com>`，并在消息主题中提及书名。

如果您在某个主题上有专业知识，并且有兴趣撰写或为一本书做出贡献，请参阅我们的作者指南[www.packtpub.com/authors](http://www.packtpub.com/authors)。

# 客户支持

现在您是 Packt 图书的自豪所有者，我们有一些事情可以帮助您充分利用您的购买。

# 下载示例代码

您可以从[`www.packtpub.com`](http://www.packtpub.com)的帐户中下载您购买的所有 Packt 图书的示例代码文件。如果您在其他地方购买了本书，您可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)并注册，以便直接通过电子邮件接收文件。

## 勘误

尽管我们已经尽最大努力确保内容的准确性，但错误是难免的。如果您在我们的书籍中发现错误，无论是文字还是代码方面的错误，我们将不胜感激地接受您的报告。通过这样做，您可以帮助其他读者避免挫折，并帮助我们改进本书的后续版本。如果您发现任何勘误，请访问[`www.packtpub.com/support`](http://www.packtpub.com/support)，选择您的书籍，点击**勘误提交表**链接，并输入您的勘误详情。一旦您的勘误经过验证，您的提交将被接受，并且勘误将被上传到我们的网站，或者添加到该书籍的勘误列表中的“勘误”部分。

## 盗版

互联网上的侵犯版权行为是各种媒体持续存在的问题。在 Packt，我们非常重视版权和许可的保护。如果您在互联网上发现我们作品的任何非法副本，请立即向我们提供位置地址或网站名称，以便我们采取补救措施。

请通过`<copyright@packtpub.com>`与我们联系，并提供涉嫌盗版材料的链接。

我们感谢您帮助保护我们的作者，以及我们为您提供有价值内容的能力。

## 问题

如果您在阅读本书的过程中遇到任何问题，请通过`<questions@packtpub.com>`与我们联系，我们将尽力解决。


# 第一章：Java 语言改进

在本章中，我们将涵盖以下内容：

+   在 switch 语句中使用字符串字面量

+   使用下划线改进代码可读性的字面量

+   使用 try-with-resources 块改进异常处理代码

+   创建可与 try-with-resources 技术一起使用的资源

+   捕获多个异常类型以改进类型检查

+   在 Java 7 中重新抛出异常

+   使用`diamond`操作符进行构造类型推断

+   使用@SafeVarargs 注解

# 介绍

**Java 7**于 2011 年 7 月发布，引入了许多新功能。在 Java SDK 文档中，您可能会看到它被称为**Java 1.7**。本章将重点介绍作为 Coin 项目的一部分分组的功能（[`openjdk.java.net/projects/coin/`](http://openjdk.java.net/projects/coin/)）。**Coin 项目**指的是 Java 7 中设计为尽可能删除多余文本以使程序更易读的小语言更改。语言的更改不涉及修改**Java 虚拟机**（**JVM**）。这些新功能包括：

+   在 switch 语句中使用字符串

+   添加二进制字面量和在数字字面量中插入下划线的能力

+   多重捕获块的使用

+   try-with-resources 块

+   使用`diamond`操作符改进类型推断

+   改进了具有可变数量参数的方法的使用

自 Java 问世以来，只能使用整数值来控制 switch 语句。现在可以使用字符串，并且可以提供一种更方便的技术来控制基于字符串的执行流程。*在 switch 语句中使用字符串字面量*配方说明了这一特性。

现在可以在字面量中使用下划线，如*使用下划线改进代码可读性的字面量*配方中所述。这些可以使程序更易读和易维护。此外，现在可以使用二进制字面量。例如，可以使用字面位模式，而不是使用十六进制字面量。

在 Java 7 中新增了改进的 try-catch 块机制。这包括从单个 catch 块中捕获多个异常的能力，以及如何抛出异常的改进。*捕获多个异常类型以改进类型检查*配方探讨了这些增强功能。

异常处理的另一个改进涉及自动关闭资源。在早期版本的 Java 中，当在 try 块中打开多个资源时，当发生异常时有效关闭资源可能会很困难。Java 7 提供了一种新技术，如*使用 try-with-resources 块改进异常处理代码*配方中所讨论的。

要利用这种技术，表示资源的类必须实现新的`java.lang.AutoCloseable`接口。该接口由一个名为`close`的方法组成，当实现时，应根据需要释放资源。许多核心 Java 类已经增强了这一点。配方：*创建可与 try-with-resources 技术一起使用的资源*说明了如何为非核心类执行此操作。

Java 7 提供了以灵活的方式重新抛出异常的能力。它提供了一种更精确的抛出异常的方式，并在 try/catch 块中处理它们的灵活性更大。*在 Java 7 中重新抛出异常*配方说明了这一能力。

在**Java 1.5**引入泛型时，编写代码来解决许多类似问题变得更容易。然而，有时它的使用可能变得有些冗长。引入了`diamond`操作符减轻了这一负担，并在*使用`diamond`操作符进行构造类型推断*配方中进行了说明。

当一个方法使用变量数量的泛型参数时，有时会生成无效的警告。`@SafeVarargs`注解已被引入以标记方法为安全。这个问题与堆污染有关，并在*使用@SafeVarargs 注解*中进行了讨论。

### 注意

在本章和其他章节中，大多数代码示例将被编写为从主方法中执行。虽然不需要特定的**集成开发环境**（**IDE**）来使用 Java 7 的新功能，但本书中的示例是使用**NetBeans 7.0.1**和**Windows 7**开发的，除非另有说明。至少需要**Java 开发工具包**（**JDK**）**1.7**或更高版本。

另外，请注意提供的代码示例不包括`import`语句。这里不显示这些内容是为了减少代码行数。大多数 IDE 都可以很容易地插入这些导入，但您需要小心使用正确的导入。

# 在`switch`语句中使用字符串文字

在 Java 7 中，使用字符串文字在`switch`语句中是新的。以前，`switch`语句中只有整数值是有效的参数。根据字符串值做出决定并使用`switch`语句执行此任务可以简化原本需要的一系列`if`语句。这可以导致更易读和更高效的代码。

## 准备工作

应用程序可能会基于字符串值进行选择。一旦识别出这种情况，执行以下操作：

1.  创建一个`String`变量，通过`switch`语句进行处理。

1.  创建`switch`块，使用字符串文字作为 case 子句。

1.  使用`String`变量来控制`switch`语句。

## 如何做...

这里演示的例子将使用`switch`语句来处理应用程序的命令行参数。创建一个新的控制台应用程序。在`main`方法中，我们将使用`args`参数来处理应用程序的命令行参数。许多应用程序允许使用命令行参数来自定义或以其他方式影响应用程序的操作。在这个例子中，我们的应用程序将支持详细模式、日志记录，并提供有关应用程序的有效命令行参数的帮助消息。

1.  在这个例子中，创建一个名为`StringSwitchExample`的类，该类具有三个实例变量，可以通过命令行参数设置，如下所示：

```java
public class StringSwitchExample {
private static boolean verbose = false;
private static boolean logging = false;
private static boolean displayHelp = false;
}

```

### 提示

**下载示例代码**

您可以从您在[`www.packtpub.com`](http://www.packtpub.com)的帐户中下载您购买的所有 Packt 图书的示例代码文件。如果您在其他地方购买了这本书，您可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)并注册，以便将文件直接发送到您的邮箱。

1.  接下来，添加以下`main`方法，它将根据提供的命令行参数设置这些变量：

```java
public static void main(String[] args) {
for (String argument : args) {
switch (argument) {
case "-verbose":
case "-v":
verbose = true;
switch statementsstring literals, usingbreak;
case "-log":
logging = true;
break;
case "-help":
displayHelp = true;
break;
default:
System.out.println("Illegal command line argument");
}
}
displayApplicationSettings();
}

```

1.  添加以下辅助方法来显示应用程序设置：

```java
private static void displayApplicationSettings() {
System.out.println("Application Settings");
System.out.println("Verbose: " + verbose);
System.out.println("Logging: " + logging);
System.out.println("Help: " + displayHelp);
}

```

1.  使用以下命令行执行应用程序：

```java
java StringSwitchExample -verbose -log

```

1.  如果您使用的是集成开发环境（IDE），通常有一种方法可以设置命令行参数。例如，在 NetBeans 中，右键单击**项目**窗口中的项目名称，然后选择**属性**菜单将打开**项目属性**对话框。在**运行**类别中，**参数**文本框允许您设置命令行参数，如下截图所示：![如何做...](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java7-new-feat-cb/img/5627_1_01.jpg)

1.  当应用程序被执行时，您的输出应该如下所示：

**应用程序设置**

**详细信息：true**

**日志记录：true**

**帮助：false**

## 工作原理...

应用程序设置变量都初始化为`false`。使用 for-each 循环遍历每个命令行参数。`switch`语句使用特定的命令行参数来打开应用程序设置。`switch`语句的行为类似于早期的 Java`switch`语句。

### 注意

有趣的是，Java 虚拟机（JVM）目前不直接支持使用字符串进行切换。Java 编译器负责将`switch`语句中的字符串转换为适当的字节码。

当`for`循环完成时，将调用`displayApplicationSettings`方法。这将显示当前的应用程序设置，反映了由命令行参数指定的配置。

然而，需要注意的是，虽然`String`变量可以传递给`switch`语句，但与`switch`语句中使用的其他数据类型一样，用于案例子句的字符串必须是字符串文字。在使用字符串文字时，适用于`switch`语句的一般规则。`switch`块中的每个语句必须具有有效的非空标签，不能有两个相同的标签，并且每个`switch`块只能关联一个默认标签。

## 还有更多...

在使用字符串时，您需要注意以下两个问题：

+   字符串的空值

+   字符串的情况

使用一个被赋予空值的字符串引用变量将导致`java.lang.NullPointerException`。有关如何处理`NullPointerException`的更多信息，请参阅第十一章中的*处理空引用*配方，*杂项*。当与`switch`语句一起使用时，这也是真实的。此外，在`switch`语句中，对案例表达式的评估是区分大小写的。在前面的例子中，如果命令行参数与案例表达式中显示的内容不同，那么该案例将被跳过。如果我们使用以下命令行，其中我们将单词 verbose 大写：

```java
java StringSwitchExample -Verbose -log

```

然后，冗长模式将不再使用，如下面的输出所示：

**应用程序设置**

**冗长：假**

**日志记录：真**

**帮助：假**

# 使用下划线来改善代码的可读性

在 Java 7 中，数字文字可以包含下划线字符(_)。这旨在通过将文字的数字分成显著的组，在几乎任意满足开发人员需求的地方，来提高代码的可读性。下划线可以应用于任何支持的基数（二进制、八进制、十六进制或十进制）的原始数据类型，以及整数和浮点文字。

## 准备就绪

第一步是识别开发人员以这种方式格式化文字将有益的实例。通常，您会希望识别更长的数字或在其外部形式中具有显著部分的数字，例如借记卡号。基本步骤包括：

1.  识别要与下划线一起使用的文字。

1.  在文字中适当的位置插入下划线，使文字更易读。

## 如何做...

此示例说明了使用下划线来澄清大多数借记卡号中存在的固有间隙，并演示了它们在浮点数中的使用。

1.  创建一个新的控制台应用程序，并添加以下`main`方法：

```java
public static void main(String[] args) {
long debitCard = 1234_5678_9876_5432L;
System.out.println("The card number is: " + debitCard);
System.out.print("The formatted card number is:");
printFormatted(debitCard);
float minAmount = 5_000F;
float currentAmount = 5_250F;
float withdrawalAmount = 500F;
if ((currentAmount - withdrawalAmount) < minAmount) {
System.out.println("Minimum amount limit exceeded " + minAmount);
}
}

```

1.  添加一个方法来正确格式化输出的信用卡号，如下所示：

```java
private static void printFormatted(long cardNumber) {
String formattedNumber = Long.toString(cardNumber);
for (int i = 0; i < formattedNumber.length(); i++) {
if (i % 4 == 0) {
System.out.print(" ");
}
System.out.print(formattedNumber.charAt(i));
}
System.out.println();
}

```

1.  执行应用程序。输出将如下所示：

**卡号是：1234567898765432**

**格式化后的卡号是：1234 5678 9876 5432**

**最低金额限额超过 5000.0**

请注意，在第一行输出中，显示的数字不包含下划线，但我们的第二行格式化为在下划线的位置使用空格。这是为了说明数字在内部的外观与需要为外部显示格式化的方式之间的差异。

## 它是如何工作的...

借记卡示例将数字分成四个部分，使其更易读。由于借记卡号的长度，需要一个`long`变量。

接下来，在银行账户中设置了最低限额。类型为`float`的变量`minAmount`被设置为 5,000.00，使用下划线表示逗号的位置。另外两个名为`currentAmount`和`withdrawalAmount`的`float`被声明并分别设置为 5,250.00 和 500.00。然后代码确定了是否可以从`currentAmount`中减去`withdrawalAmount`并仍然保持余额高于`minAmount`。如果不行，将显示相应的消息。

### 注意

在大多数涉及货币的应用中，`java.util.Currency`类将是更合适的选择。前面的例子只使用浮点文字来解释下划线的用法。

下划线的唯一目的是使代码对开发人员更易读。编译器在代码生成期间和任何后续变量操作期间都会忽略下划线。连续的下划线被视为一个，并且也被编译器忽略。如果变量的输出格式很重要，它将需要单独处理。

## 还有更多...

下划线不仅可以用于十进制文字。此外，下划线也可能被误用。在这里，我们将讨论以下内容：

+   简单的下划线使用错误

+   使用下划线与十六进制文字

+   使用下划线与二进制文字

### 简单的下划线使用错误

下划线通常可以随意放置在文字中，但有限制它们的使用。在数字的开头或结尾、在使用`float`或`double`时与小数点相邻、在 D、F 或 L 后缀之前，或者在需要一串数字的地方放置下划线都是无效的。

以下是无效下划线使用的例子：

```java
long productKey = _12345_67890_09876_54321L;
float pi = 3._14_15F;
long licenseNumber = 123_456_789_L;

```

这将生成语法错误，**错误：非法下划线**。

### 使用下划线与十六进制文字

下划线在处理用十六进制或二进制表示的二进制数据时特别有用。在下面的例子中，表示要发送到数据端口的命令的整数值被表示为十六进制和二进制文字：

```java
int commandInHex = 0xE_23D5_8C_7;
int commandInBinary = 0b1110_0010001111010101_10001100_0111;

```

这两个数字是相同的。它们只是用不同的进制表示。在这里，我们使用了 2 进制和 16 进制。在这个例子中，16 进制表示可能更易读。2 进制文字将在下一节中更深入地讨论。

下划线用于更清晰地识别命令的各个部分。假设命令的前四位表示运算符，接下来的 16 位是操作数。接下来的 8 位和 4 位可能表示命令的其他方面。

### 使用下划线与二进制文字

我们还可以在二进制文字中使用下划线。例如，为了初始化设备，我们可能需要向数据端口发送一个特定的 8 位序列。这个序列可以被组织成这样，前两位指定操作（读、写等），接下来的三位可以指定设备资源，最后三位可以表示操作数。我们可以使用带有下划线的二进制文字来编码这个序列，如下所示：

```java
byte initializationSequence = 0b10_110_010;

```

使用下划线清楚地标识了每个字段。虽然不必使用变量`initializationSequence`，但它允许我们在程序中的多个地方使用该序列。另一个例子定义了一个掩码，在这种情况下，第一个三位在**AND**操作中被消除，如下所示：

```java
result = inputValue & 0b000_11111;

```

在按位 AND 操作中，操作数的每一位都与对方进行 AND 运算。这些例子如下所示：

```java
byte initializationSequence = (byte) 0b01_110_010;
byte inputValue = (byte) 0b101_11011;
byte result = (byte) (inputValue & (byte) 0b000_11111);
System.out.println("initializationSequence: " +
Integer.toBinaryString(initializationSequence));
System.out.println("result: " + Integer.toBinaryString(result));

```

执行此序列时，我们得到以下输出：

**初始化序列：1110010**

**结果：11011**

需要使用字节转换运算符，因为二进制文字默认为`int`类型。另外，请注意`toBinaryString`方法不显示前导零。

# 使用 try-with-resources 块来改进异常处理代码

在 Java 7 之前，为了正确打开和关闭资源（如`java.io.InputStream`或`java.nio.Channel`），所需的代码非常冗长且容易出错。尝试与资源块已添加，以简化错误处理并使代码更简洁。使用 try-with-resources 语句会导致在 try 块退出时自动关闭所有资源。使用 try-with-resources 块声明的资源必须实现接口`java.lang.AutoCloseable`。

这种方法可以更好地避免嵌套和过多的 try-catch 块，确保准确的资源管理，文献中可能称之为**自动资源管理**（**ARM**）。

## 准备就绪

在处理需要打开和关闭的资源时，通过以下方式实现`try-with-resource`块：

1.  创建 try 块并声明要管理的资源。

1.  在 try 块内使用资源。

## 如何做...

1.  创建一个控制台应用程序，并向其添加以下`main`方法。在工作目录中创建一个名为`users.txt`的文本文件，并向文件中添加一系列名称。此示例打开该文件并创建一个备份，同时演示了使用`try-with-resources`技术，其中使用 try 块创建了一个`java.io.BufferedReader`和`java.io.BufferedWriter`对象：

```java
public static void main(String[] args) {
try (BufferedReader inputReader = Files.newBufferedReader(
Paths.get(new URI ("file:///C:/home/docs/users.txt")),
Charset.defaultCharset());
BufferedWriter outputWriter = Files.newBufferedWriter(
Paths.get(new URI("file:///C:/home/docs/users.bak")),
Charset.defaultCharset())) {
String inputLine;
while ((inputLine = inputReader.readLine()) != null) {
outputWriter.write(inputLine);
outputWriter.newLine();
}
System.out.println("Copy complete!");
}
catch (URISyntaxException | IOException ex) {
ex.printStackTrace();
}
}

```

1.  执行应用程序。输出应该如下：

**复制完成！**

## 工作原理...

要管理的资源在`try`关键字和 try 块的左花括号之间的一组括号内声明和初始化。在这种情况下，创建了两个资源。第一个是与`users.txt`文件关联的`BufferedReader`对象，第二个是与`users.bak`文件关联的`BufferedWriter`对象。使用`java.nio.file.Path`接口的新 IO 技术在第六章中进行了讨论，*Java 7 中的流 IO*。

然后逐行读取第一个文件，并将其写入第二个文件。当 try 块退出时，两个 IO 流会自动关闭。然后显示一条消息，显示复制操作已完成。

请注意在 catch 块中使用垂直线。这是 Java 7 中的新功能，允许我们在单个 catch 块中捕获多个异常。这个操作符的使用在*捕获多个异常类型以改进类型检查*中进行了讨论。

请记住，使用 try-with-resources 块声明的资源之间用分号分隔。否则将导致编译时错误。此外，无论 try 块是否正常完成，都将尝试关闭资源。如果资源无法关闭，通常会抛出异常。

无论资源是否关闭，catch 和 finally 块始终被执行。但是，异常仍然可以从这些块中抛出。这在*创建可与 try-with-resources 技术一起使用的资源*中有更详细的讨论。

## 还有更多...

为了完全理解`try-with-resources`技术，我们需要解决另外两个主题，如下所示：

+   理解抑制异常

+   使用`try-with-resources`技术时的结构问题

### 理解抑制异常

为了支持这种方法，`java.lang.Exception`类添加了一个新的构造函数以及两个方法：`addSuppressed`和`getSuppressed`。抑制的异常是那些没有明确报告的异常。在 try-with-resources try 块的情况下，可能会从 try 块本身抛出异常，或者在 try 块创建的资源关闭时抛出异常。当抛出多个异常时，可能会抑制异常。

在 try-with-resources 块的情况下，与关闭操作相关的任何异常在从块本身抛出异常时都会被抑制。这在*Creating a resource that can be used with the try-with-resources technique*中有所示。

可以使用`getSuppressed`方法检索抑制的异常。程序员创建的异常可以使用`addSuppressed`方法将异常标记为被抑制。

### 在使用 try-with-resources 技术时的结构问题

当使用单个资源时，可能不希望使用这种技术。我们将展示三种不同的代码序列实现来显示`users.txt`文件的内容。首先，如下所示的代码使用了 try-with-resources 块。但是，需要在此块之前加上一个 try 块来捕获`java.net.URISyntaxException:`

```java
Path path = null;
try {
path = Paths.get(new URI("file:///C:/home/docs/users.txt"));
}
catch (URISyntaxException e) {
System.out.println("Bad URI");
}
try (BufferedReader inputReader = Files.newBufferedReader(path, Charset.defaultCharset())) {
String inputLine;
while ((inputLine = inputReader.readLine()) != null) {
System.out.println(inputLine);
}
}
catch (IOException ex) {
ex.printStackTrace();
}

```

这个例子是基于需要捕获`URISyntaxException`。可以通过在`get`方法中创建`java.net.URI`对象来避免这种情况。然而，这会使代码更难阅读：

```java
try (BufferedReader inputReader = Files.newBufferedReader(
Paths.get(new URI("file:///C:/home/docs/users.txt")), Charset.defaultCharset())) {
String inputLine;
while ((inputLine = inputReader.readLine()) != null) {
System.out.println(inputLine);
}
}
catch (IOException | URISyntaxException ex) {
ex.printStackTrace();
}

```

注意使用多个 catch 块，如*Catching multiple exception types to improve type checking*中所讨论的。另一种方法是通过使用带有`String`参数的`get`方法来避免`URI`对象：

```java
try {
Path path = Paths.get("users.txt");
BufferedReader inputReader =
Files.newBufferedReader(path, Charset.defaultCharset());
String inputLine;
while ((inputLine = inputReader.readLine()) != null) {
System.out.println(inputLine);
}
}
catch (IOException ex) {
ex.printStackTrace();
}

```

使用的方法和代码结构会影响代码的可读性和可维护性。在代码序列中可能有可能消除`URI`对象或类似对象的使用，也可能不可行。然而，仔细考虑替代方法可以大大改善应用程序。

## 另请参阅

*Catching multiple exception types to improve type checking*和*Creating a resource that can be used with the try-with-resources technique*提供了 Java 7 中异常处理的更多覆盖范围。

# 创建一个可以与 try-with-resources 技术一起使用的资源

Java 库中有许多资源，可以作为`try-with-resource`技术的一部分使用。然而，有时您可能希望创建自己的资源，以便与这种技术一起使用。本示例演示了如何做到这一点。

## 准备工作

要创建一个可以与`try-with-resources`技术一起使用的资源：

1.  创建一个实现`java.lang.AutoCloseable`接口的类。

1.  重写`close`方法。

1.  实现特定于资源的方法。

任何使用 try-with-resources 块创建的对象都必须实现`AutoCloseable`接口。这个接口有一个方法，即`close`。

## 如何做...

在这里，我们将通过创建三个类来说明这种方法：

+   包含`main`方法的一个类

+   实现`AutoCloseable`接口的两个类

1.  创建两个名为`FirstAutoCloseableResource`和`SecondAutoCloseableResource`的类。在这些类中，实现`manipulateResource`和`close`方法，如下所示：

```java
public class FirstAutoCloseableResource implements AutoCloseable {
@Override
public void close() throws Exception {
// Close the resource as appropriate
System.out.println("FirstAutoCloseableResource close method executed");
throw new UnsupportedOperationException(
"A problem has occurred in FirstAutoCloseableResource");
}
public void manipulateResource() {
// Perform some resource specific operation
System.out.println("FirstAutoCloseableResource manipulateResource method executed");
try-with-resource blockresource, creating}
}
public class SecondAutoCloseableResource implements AutoCloseable {
@Override
public void close() throws Exception {
// Close the resource as appropriate
System.out.println("SecondAutoCloseableResource close method executed");
throw new UnsupportedOperationException(
"A problem has occurred in SecondAutoCloseableResource");
}
public void manipulateResource() {
// Perform some resource specific operation
System.out.println("SecondAutoCloseableResource manipulateResource method executed");
}
}

```

1.  接下来，将以下代码添加到`main`方法中。我们使用`try-with-resources`技术与两个资源，然后调用它们的`manipulateResource`方法：

```java
try (FirstAutoCloseableResource resource1 = new FirstAutoCloseableResource();
SecondAutoCloseableResource resource2 = new SecondAutoCloseableResource()) {
resource1.manipulateResource();
resource2.manipulateResource();
}
catch (Exception e) {
e.printStackTrace();
for(Throwable throwable : e.getSuppressed()) {
System.out.println(throwable);
}
}

```

1.  当代码执行时，`close`方法会抛出`UnsupportedOperationException`，如下所示：

**FirstAutoCloseableResource manipulateResource 方法执行**

**SecondAutoCloseableResource manipulateResource 方法执行**

**SecondAutoCloseableResource close 方法执行**

**FirstAutoCloseableResource close 方法执行**

**java.lang.UnsupportedOperationException: SecondAutoCloseableResource 中发生了问题**

**在 packt.SecondAutoCloseableResource.close(SecondAutoCloseableResource.java:9)**

**在 packt.TryWithResourcesExample.displayAutoCloseableExample(TryWithResourcesExample.java:30)**

**在 packt.TryWithResourcesExample.main(TryWithResourcesExample.java:22)**

**被抑制：java.lang.UnsupportedOperationException: 在 FirstAutoCloseableResource 中发生了问题**

**在 packt.FirstAutoCloseableResource.close(FirstAutoCloseableResource.java:9)**

**... 2 个更多**

**java.lang.UnsupportedOperationException: 在 FirstAutoCloseableResource 中发生了问题**

## 它是如何工作的...

在资源类中，创建了`manipulateResource`方法来执行一些特定于资源的操作。资源类被声明为 try 块的一部分，并调用了`manipulateResource`方法。这在输出的第一部分中有所说明。输出已经被突出显示以澄清这个过程。

当 try 块终止时，`close`方法被执行。它们的执行顺序与预期相反。这是应用程序堆栈工作原理的结果。

在 catch 块中，堆栈被转储。此外，我们使用`getSuppressed`方法返回并显示被抑制的方法。在 Java 7 中引入了对被抑制异常的支持。这些类型的异常在*使用 try-with-resource 块改进异常处理代码*配方中讨论，并在本配方后面讨论。

## 还有更多...

在`close`方法中，可能有以下三种操作之一：

+   如果没有要关闭的内容或资源将始终关闭

+   关闭资源并返回而不出错

+   尝试关闭资源，但在失败时抛出异常

前两个条件很容易处理。在最后一个条件中，有一些事情需要记住。

始终实现`close`方法并提供特定的异常。这将为用户提供有关潜在问题更有意义的反馈。此外，不要抛出`InterruptedException`。如果`InterruptedException`被抑制，可能会出现运行时问题。

`close`方法不需要是幂等的。**幂等**方法是指重复执行该方法不会引起问题。例如，两次从同一文件中读取数据不一定会引起问题。而将相同的数据两次写入文件可能会引起问题。`close`方法不必是幂等的，但建议应该是。

## 另请参阅

*使用 try-with-resources 块改进异常处理代码*配方涵盖了这种类型的 try 块的使用。

# 捕获多个异常类型以改进类型检查

在 try 块内，可能会生成和抛出多个异常。一系列对应的 catch 块用于捕获并处理这些异常。经常情况下，处理一个异常所需的操作对其他异常也是相同的。一个例子是当执行异常的日志记录时。

在 Java 7 中，现在可以在单个 catch 块中处理多个异常。这种能力可以减少代码的重复。在 Java 的早期版本中，通常会有诱惑去通过捕获更高级别的异常类并从该块中处理多个异常来解决这个问题。现在这种方法的需求较少。

## 准备工作

通过使用单个捕获块捕获多个异常来实现：

1.  添加一个捕获块

1.  在捕获块的括号内包括多个异常，用竖线分隔

## 如何做...

在这个例子中，我们希望通过记录异常来处理用户的无效输入。这是一个简单的方法，足以解释如何处理多个异常。

1.  创建一个包含两个类`MultipleExceptions`和`InvalidParameter`的应用程序。`InvalidParameter`类用于处理无效的用户输入，而`MultipleExceptions`类包含`main`方法和示例代码。

1.  创建`InvalidParameter`类如下：

```java
public class InvalidParameter extends java.lang.Exception {
public InvalidParameter() {
super("Invalid Parameter");
}
}

```

1.  接下来，创建`MultipleExceptions`类，并添加一个`java.util.logging.Logger`对象，如下所示：

```java
public class MultipleExceptions {
private static final Logger logger = Logger.getLogger("log.
txt");
public static void main(String[] args) {
System.out.print("Enter a number: ");
try {
Scanner scanner = new Scanner(System.in);
int number = scanner.nextInt();
if (number < 0) {
throw new InvalidParameter();
}
System.out.println("The number is: " + number);
}
catch (InputMismatchException | InvalidParameter e) {
logger.log(Level.INFO, "Invalid input, try again");
}
}

```

1.  使用各种输入执行程序。使用有效数字，比如 12，会产生以下输出：

输入一个数字：12

数字是：12

1.  使用无效输入，比如非数字值，比如 cat，或者负数，比如-5，会产生以下输出：

输入一个数字：cat

无效输入，请重试

2011 年 8 月 28 日下午 1:48:59 packt.MultipleExceptions main

信息：无效输入，请重试

输入一个数字：-5

无效输入，请重试

2011 年 8 月 28 日下午 1:49:20 packt.MultipleExceptions main

信息：无效输入，请重试

## 它是如何工作的...

记录器已创建，当发生异常时，记录器文件中会有一条记录。使用 NetBeans 创建的输出也会显示这些日志消息。

当抛出异常时，进入 catch 块。请注意，这里感兴趣的两个异常，`java.util.InputMismatchException`和`InvalidParameter`出现在同一个 catch 语句中，并用竖线分隔。还要注意，只有一个变量`e`用于表示异常。

当需要处理几个特定的异常并以相同的方式处理时，这种方法是有用的。当一个 catch 块处理多个异常时，catch 块参数是隐式 final 的。这意味着无法给参数赋新值。以下是非法的，使用它会导致语法错误：

```java
}
catch (InputMismatchException | InvalidParameter e) {
e = new Exception(); // multi-catch parameter e may not be assigned
logger.log(Level.INFO, "Invalid input, try again");
}

```

除了比使用多个 catch 块更可读和更简洁之外，生成的字节码也更小，不会产生重复的代码。 

## 还有更多...

一组异常的基类影响何时使用 catch 块捕获多个异常。此外，断言在创建健壮的应用程序时是有用的。这些问题如下所述：

+   使用一个共同的异常基类和`java.lang.ReflectiveOperationException`

+   在 Java 7 中使用`java.lang.AssertionError`类

### 使用一个共同的异常基类和 ReflectiveOperationException

当不同的异常需要以相同的方式处理时，在同一个 catch 块中捕获多个异常是有用的。但是，如果多个异常共享一个公共基础异常类，那么捕获基类异常可能更简单。这是许多`IOException`派生类的情况。

例如，`Files`类的`delete`方法可能会抛出以下四种不同的异常之一：

+   `java.nio.file.NoSuchFileException`

+   `java.nio.file.DirectoryNotEmptyException`

+   `java.io.IOException`

+   `java.lang.SecurityException`

其中，`NoSuchFileException`和`DirectoryNotEmptyException`最终都是从`IOException`派生出来的。因此，捕获`IOException`可能足够，就像下面的代码所示：

```java
public class ReflectiveOperationExceptionExample {
public static void main(String[] args) {
try {
Files.delete(Paths.get(new URI("file:///tmp.txt")));
}
catch (URISyntaxException ex) {
ex.printStackTrace();
}
catch (IOException ex) {
ex.printStackTrace();
}
}
}

```

在这个例子中，注意`URI`构造函数可能抛出`URISyntaxException`异常。在第四章的食谱*删除文件或目录*中，详细介绍了`delete`方法的使用。

在 Java 7 中，`ReflectiveOperationException`是`java.lang`包中新增的一个异常。它是以下异常的基类：

+   `ClassNotFoundException`

+   `IllegalAccessException`

+   `InstantiationException`

+   `InvocationTargetException`

+   `NoSuchFieldException`

+   `NoSuchMethodException`

这个异常类可以简化反射类型异常的处理。多异常捕获机制更适用于那些没有共同基类的异常集合。

### 注意

一般来说，最好捕获尽可能特定于问题的异常。例如，处理缺少文件时，最好捕获`NoSuchFileException`而不是更广泛的`Exception`，这提供了更多关于异常的细节。

### 在 Java 7 中使用 AssertionError 类

断言在构建更健壮的应用程序中很有用。关于这个主题的很好介绍可以在[`download.oracle.com/javase/1.4.2/docs/guide/lang/assert.html`](http://download.oracle.com/javase/1.4.2/docs/guide/lang/assert.html)找到。在 Java 7 中，添加了一个新的构造函数，允许将消息附加到用户生成的断言错误。此构造函数有两个参数。第一个是与`AssertionError`关联的消息，第二个是`Throwable`子句。

在此配方中早期开发的`MultipleExceptions`类中，我们测试了数字是否小于零，如果是，则抛出异常。在这里，我们将通过抛出`AssertionError`来说明使用`AssertionError`构造函数，如果数字大于 10。

将以下代码添加到`main`方法中，靠近原始数字的测试：

```java
if(number>10) {
throw new AssertionError("Number was too big",new Throwable("Throwable assertion message"));
}

```

再次执行程序并输入**12**。您的结果应该类似于以下内容：

**输入一个数字：12**

**线程"main"中的异常 java.lang.AssertionError：数字太大**

**在 packt.MultipleExceptions.main(MultipleExceptions.java:28)**

**Caused by: java.lang.Throwable: Throwable assertion message**

**... 1 more**

**Java 结果：1**

在 Java 7 之前，不可能将消息与用户生成的`AssertionError`关联起来。

## 另请参阅

`Files`类的使用详细介绍在第四章中，*管理文件和目录*。

# 在 Java 7 中重新抛出异常

当在 catch 块中捕获异常时，有时希望重新抛出异常。这允许当前方法和调用当前方法的方法处理异常。

然而，在 Java 7 之前，只能重新抛出基类异常。当需要重新抛出多个异常时，您被限制在方法声明中声明一个公共基类。现在，可以对可以为方法抛出的异常更加严格。

## 做好准备

为了在 Java 中重新抛出异常，必须首先捕获它们。在 catch 块内部，使用`throw`关键字和要抛出的异常。Java 7 中的新的重新抛出技术要求您：

+   在 catch 块中使用基类异常类

+   使用`throw`关键字从 catch 块抛出派生类异常

+   修改方法的签名以抛出派生异常

## 如何做...

1.  我们将修改在*Catching multiple exception types to improve type checking*配方中开发的`ReflectiveOperationExceptionExample`类。修改`main`方法，以在 try 块中调用`deleteFile`方法，如下面的代码所示：

```java
public class ReflectiveOperationExceptionExample {
public static void main(String[] args) {
try {
deleteFile(Paths.get(new URI("file:///tmp.txt")));
}
catch (URISyntaxException ex) {
ex.printStackTrace();
}
catch (IOException ex) {
ex.printStackTrace();
}
}

```

1.  添加`deleteFile`方法，如下所示：

```java
private static void deleteFile(Path path) throws NoSuchFileException, DirectoryNotEmptyException {
Java 7exceptions, rethrowingtry {
Files.delete(path);
}
catch (IOException ex) {
if(path.toFile().isDirectory()) {
throw new DirectoryNotEmptyException(null);
}
else {
throw new NoSuchFileException(null);
}
}
}
}

```

1.  使用不存在的文件执行应用程序。输出应该如下：

**java.nio.file.NoSuchFileException**

**在 packt.ReflectiveOperationExceptionExample.deleteFile(ReflectiveOperationExceptionExample.java:33)**

**在 packt.ReflectiveOperationExceptionExample.main(ReflectiveOperationExceptionExample.java:16)**

## 它是如何工作的...

`main`方法调用并处理了`deleteFile`调用生成的异常。该方法声明可以抛出`NoSuchFileException`和`DirectoryNotEmptyException`。请注意，基类`IOException`用于捕获异常。在 catch 块内部，使用`File`类的`isDirectory`方法进行测试，以确定异常的原因。确定异常的根本原因后，抛出适当的异常。`Files`类的使用详细介绍在第四章中，*管理文件和目录*。

通过明确指定方法可能抛出的异常，我们可以清楚地了解方法的调用者可以期望什么。 此外，它可以防止方法意外抛出其他`IOException`派生的异常。 此示例的缺点是，如果另一个异常，例如`FileSystemException`，是根本原因，那么我们将错过它。 它将在`deleteFile`方法中捕获，因为它是从`IOException`派生的。 但是，我们未能在方法中处理它或将其传递给调用方法。

## 另请参阅

前三个配方提供了 Java 7 中异常处理的其他覆盖范围。

# 在构造函数类型推断中使用钻石操作符

使用钻石操作符简化了创建对象时的泛型使用。 它避免了程序中的未经检查的警告，并通过不需要显式重复指定参数类型来减少泛型冗长。 相反，编译器推断类型。 动态类型语言一直这样做。 虽然 Java 是静态类型的，但是钻石操作符的使用允许比以前更多的推断。 编译后的代码没有区别。

编译器将推断构造函数的参数类型。 这是约定大于配置的一个例子（[`en.wikipedia.org/wiki/Convention_over_configuration`](http://en.wikipedia.org/wiki/Convention_over_configuration)）。 通过让编译器推断参数类型（约定），我们避免了对象的显式规范（配置）。 Java 还在许多领域使用注释来影响这种方法。 类型推断现在可用，而以前只能用于方法。

## 准备就绪

使用钻石操作符：

1.  创建对象的通用声明。

1.  使用钻石操作符`<>`来指定要使用的类型推断。

## 如何做...

1.  创建一个简单的 Java 应用程序，其中包含一个`main`方法。 将以下代码示例添加到`main`方法中，以查看它们的工作原理。 例如，要声明字符串的`java.util.List`，我们可以使用以下内容：

```java
List<String> list = new ArrayList<>();

```

1.  标识符`list`声明为字符串列表。 钻石操作符`<>`用于推断`List`类型为`String`。 对于此代码不会生成警告。

## 它是如何工作的...

当创建对象时没有指定数据类型时，称为原始类型。 例如，在实例化标识符`list`时，以下使用了原始类型：

```java
List<String> list = new ArrayList(); // Uses raw type

```

编译代码时，将生成以下警告：

**注意：packt\Bin.java 使用未经检查或不安全的操作**。

**注意：重新编译时使用-Xlint:unchecked 以获取详细信息**。

将生成未经检查的警告。 通常希望在应用程序中消除未经检查的警告。 使用**—Xlint:unchecked**时，我们会得到以下结果：

**packt\Bin.java:26: 警告：[unchecked]未经检查的转换**

**List<String> arrayList = new ArrayList()**;

**^**

**需要：List<String>**

**找到：ArrayList**

**1 个警告**

在 Java 7 之前，我们可以通过显式使用参数类型来解决此警告，如下所示：

```java
List<String> list = new ArrayList<String>();

```

使用 Java 7，钻石操作符使这更短，更简单。 此操作符在处理更复杂的数据类型时变得更加有用，例如，`List`的`Map`对象如下所示：

```java
List<Map<String, List<String>> stringList = new ArrayList<>();

```

## 还有更多...

还有几个类型推断的方面需要讨论：

+   在类型不明显时使用钻石操作符

+   抑制未经检查的警告

+   了解擦除

### 在类型不明显时使用钻石操作符

在 Java 7 及更高版本中支持类型推断，只有构造函数的参数类型是明显的情况下才支持。 例如，如果我们在不指定类型的情况下使用钻石操作符，如下所示，将会收到一系列警告：

```java
List arrayList = new ArrayList<>();
arrayList.add("First");
arrayList.add("Second");

```

使用**—Xlint:unchecked**编译程序，将得到以下警告：

**... packt\Bin.java:29: 警告：[unchecked]未经检查的调用 add(E)作为原始类型 ArrayList 的成员**

**arrayList.add("First")**;

“其中 E 是类型变量：”

E 扩展 Object 在 ArrayList 类中声明

“... \packt\Bin.java:30:警告：[unchecked]未经检查的调用 add(E)作为原始类型 ArrayList 的成员”

arrayList.add("Second");

“其中 E 是类型变量：”

E 扩展 Object 在 ArrayList 类中声明

2 个警告

如果指定数据类型，则这些警告将消失：

```java
List<String> arrayList = new ArrayList<>();

```

### 抑制未经检查的警告

虽然不一定是理想的，但可以使用`@SuppressWarnings`注解来抑制由于未使用菱形操作符而生成的未经检查的异常。以下是一个示例：

```java
@SuppressWarnings("unchecked")
List<String> arrayList = new ArrayList();

```

### 理解擦除

当使用泛型时会发生擦除。声明中使用的数据类型在运行时不可用。这是在 Java 1.5 引入泛型时做出的语言设计决定，以使代码向后兼容。

考虑以下三种方法。它们只在`arrayList`变量的声明中有所不同：

```java
private static void useRawType() {
List<String> arrayList = new ArrayList();
arrayList.add("First");
arrayList.add("Second");
System.out.println(arrayList.get(0));
}
private static void useExplicitType() {
List<String> arrayList = new ArrayList<String>();
arrayList.add("First");
arrayList.add("Second");
System.out.println(arrayList.get(0));
}
private static void useImplicitType() {
List<String> arrayList = new ArrayList<>();
arrayList.add("First");
arrayList.add("Second");
System.out.println(arrayList.get(0));
}

```

当这些方法被编译时，编译时可用的类型信息将丢失。如果我们检查这三种方法的编译后字节码，我们会发现它们之间没有区别。

使用以下命令将显示程序的字节码：

```java
javap -v -p packt/Bin

```

这三种方法生成的代码是相同的。useImplicitType 的代码如下所示。它与其他两种方法相同；

```java
private static void useImplicitType();
flags: ACC_PRIVATE, ACC_STATIC
Code:
stack=3, locals=1, args_size=0
0: new #5 // class java/util/ArrayList
3: dup
4: invokespecial #6 // Method java/util/ArrayList."<in
it>":()V
7: astore_0
8: aload_0
9: ldc #7 // String First
11: invokevirtual #8 // Method java/util/ArrayList.add:
(Ljava/lang/Object;)Z
14: pop
15: aload_0
16: ldc #9 // String Second
18: invokevirtual #8 // Method java/util/ArrayList.add:
(Ljava/lang/Object;)Z
21: pop
22: getstatic #10 // Field java/lang/System.out:Ljav
a/io/PrintStream;
25: aload_0
26: iconst_0
27: invokevirtual #11 // Method java/util/ArrayList.get:
(I)Ljava/lang/Object;
30: checkcast #12 // class java/lang/String
33: invokevirtual #13 // Method java/io/PrintStream.prin
tln:(Ljava/lang/String;)V
36: return

```

# 使用@SafeVarargs 注解

`@SafeVarargs`和`@SuppressWarnings`注解可用于处理通常是无害的各种警告。`@SuppressWarnings`注解，顾名思义，将抑制特定类型的警告。

`@SafeVarargs`注解是在 Java 7 中引入的，用于指定某些使用可变数量参数的方法和构造函数是安全的。方法可以传递可变数量的参数。这些参数可能是泛型。如果是，那么可能希望使用`@SafeVarargs`注解来抑制无害的警告。

## 准备就绪

`@SafeVarargs`注解用于构造函数和方法。要使用`@SafeVarargs`注解，需要按照以下步骤进行：

1.  创建使用可变数量的泛型参数的方法或构造函数。

1.  在方法声明之前添加`@SafeVarargs`注解。

在 Java 7 中，使用泛型可变参数方法或构造函数会生成强制性的编译器警告。使用`@SafeVarargs`注解可以抑制这些警告，当这些方法或构造函数被认为是无害的时候。

## 如何做…

1.  为了演示`@SafeVarargs`注解，创建一个名为`displayElements`的应用程序，该方法显示有关每个参数及其值的信息：

```java
package packt;
import java.util.ArrayList;
public class SafeVargExample {
public static void main(String[] args) {
}
@SafeVarargs
public static <T> void displayElements(T... array) {
for (T element : array) {
System.out.println(element.getClass().getName() + ": " + element);
}
}
}

```

该方法使用可变数量的泛型参数。Java 将可变数量的参数实现为对象数组，该数组仅包含可重用类型。可重用类型在“它是如何工作”的部分中讨论。

1.  在`main`方法中添加以下代码以测试该方法：

```java
ArrayList<Integer> a1 = new ArrayList<>();
a1.add(new Integer(1));
a1.add(2);
ArrayList<Float> a2 = new ArrayList<>();
a2.add(new Float(3.0));
a2.add(new Float(4.0));
displayElements(a1, a2, 12);

```

1.  执行应用程序。输出应如下所示：

java.util.ArrayList: [1, 2]

java.util.ArrayList: [3.0, 4.0]

java.lang.Integer: 12

1.  注意在声明`java.util.ArrayList`时使用了菱形操作符`<>`。这个操作符是 Java 7 中的新功能，在“使用菱形操作符进行构造函数类型推断”这个主题中进行了讨论。

## 它是如何工作的…

在 Java 中，使用`..`符号创建具有可变数量参数的方法或构造函数，就像在`displayElements`方法中使用的那样。在这种情况下，元素类型是泛型的。

基本问题是泛型和数组无法很好地配合。当泛型在 Java 语言中添加到 1.5 时，它们被实现为使它们与早期代码向后兼容。这意味着它们是使用擦除实现的。也就是说，编译时可用的任何类型信息在运行时被移除。这些数据被称为**不可实体化**。

数组是实体化的。有关数组元素类型的信息被保留并可以在运行时使用。请注意，不可能声明一个泛型数组。可以按以下方式创建一个简单的字符串数组：

```java
String arr[] = {"First", "Second"};

```

然而，我们不能创建一个泛型数组，比如下面的例子：

```java
List<String> list1 = new ArrayList<String>();
list1.add("a");
List<String> list2 = new ArrayList<String>();
list2.add("b");
List<String> arr[] = {list1, list2}

```

这段代码将生成以下错误消息：

**无法创建 List<String>的泛型数组**

使用可变数量的参数的方法被实现为对象数组。它只能处理可实体化的类型。当调用使用可变数量的参数的方法时，将创建一个数组来保存这些参数。

由于我们使用了具有可变数量的泛型参数的方法，可能会出现称为**堆污染**的运行时问题。当将参数化类型的变量分配给与其定义时使用的类型不同的类型时，将在运行时表现为未经检查的警告。在运行时，它将导致`java.lang.ClassCastException`。使用`@SafeVarargs`注解将一个方法指定为避免堆污染的方法。

使用可变数量的泛型参数的方法将导致编译时警告。然而，并非所有使用可变数量的泛型参数的方法都会导致运行时异常。`@SafeVarargs`用于标记安全方法为安全。如果可能发生运行时异常，则不应使用该注解。这在下一节中进一步探讨。

请注意，如果没有使用`@SafeVarargs`注解，将生成以下警告：

**警告：[unchecked]为类型 ArrayList<? extends INT#1>[]的可变参数创建了未经检查的泛型数组**

**警告：[unchecked]可能会导致参数化可变参数类型 T 的堆污染**

第一个警告适用于`displayElements`调用，第二个警告适用于实际方法。代码没有问题，因此可以完全接受这些警告的抑制。

我们可以使用`@SuppressWarnings("unchecked")`注解来抑制方法声明处的警告，但在使用时仍会生成警告。使用`@SafeVarargs`可以在两个地方抑制警告。

## 还有更多...

还有一个有趣的地方是：

+   在 Java 核心库中使用`@SafeVarargs`注解

+   堆污染的一个例子

### 在 Java 核心库中使用@SafeVarargs 注解

JDK 1.7 库已经包含了`@SafeVarargs`注解。其中包括以下内容：

+   `public static <T> List<T> java.util.Arrays.asList(T... a)`

+   `public static <T> boolean java.util.Collections.addAll(Collection<? super T> c, T... elements)`

+   `public static <E extends Enum<E>> java.util.EnumSet<E> EnumSet.of(E first, E... rest)`

+   `protected final void javax.swing.SwingWorker.publish(V... chunks)`

这些方法被标记为`@SafeVarargs`注解，表示它们不会导致堆污染。这些方法被认为是安全的。

### 堆污染的一个例子

一些方法不应标记为安全，如下面从`@SafeVarargs`注解的 javadoc 描述中的代码所示（[`download.oracle.com/javase/7/docs/api/index.html`](http://download.oracle.com/javase/7/docs/api/index.html) 在`java.lang.SafeVarargs`注解文档下）。

在您的代码中添加以下方法：

```java
@SafeVarargs // Not actually safe!
static void merge(List<String>... stringLists) {
Object[] array = stringLists;
List<Integer> tmpList = Arrays.asList(42);
array[0] = tmpList; // Semantically invalid, but compiles without warnings
String element = stringLists[0].get(0); // runtime ClassCastException
}

```

使用以下代码测试该方法：

```java
List<String> list1 = new ArrayList<>();
list1.add("One");
list1.add("Two");
list1.add("Three");
List<String> list2 = new ArrayList<>();
list2.add("Four");
list2.add("Five");
list2.add("Six");
merge(list1,list2);

```

执行程序。您应该会收到以下错误消息：

**异常线程"main"java.lang.ClassCastException:java.lang.Integer 无法转换为 java.lang.String**

一个字符串列表被传递给方法，并分配给标识符`stringList`。接下来，声明了一个对象数组，并将其分配给了由`stringList`引用的相同对象。在这一点上，`stringList`和`array`引用了同一个对象，即`java.util.List`的字符串。以下说明了此时内存的配置：

![堆污染的示例](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java7-new-feat-cb/img/5627_1_02.jpg)

通过以下分配：

```java
array[0] = tmpList

```

数组的第一个元素被重新分配给了`tmpList`。这个重新分配在下图中有所说明：

![堆污染的示例](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java7-new-feat-cb/img/5627_1_03.jpg)

在这一点上，我们已经有效地将一个`Integer`对象分配给了一个`String`引用变量。它已被分配给了`stringLists`和`array`引用的数组的第一个元素。虚线显示了旧的引用，它已被替换为该行。当在运行时尝试将这个`Integer`对象分配给`String`引用变量时，会发生`ClassCastException`。

这种方法会导致堆污染，不应该用`@SafeVarargs`进行注释，因为它不安全。允许将`tmpList`分配给数组的第一个元素，因为我们只是将一个`List<Integer>`对象分配给了一个`Object`引用变量。这是 Java 中合法的**向上转型**的一个例子。

## 另请参阅

前面的配方*使用菱形操作符进行构造类型推断解释了泛型使用的改进。


# 第二章：使用路径定位文件和目录

在本章中，我们将涵盖以下内容：

+   创建 Path 对象

+   java.io.File 和 java.nio.file.Files 之间的互操作性

+   将相对路径转换为绝对路径

+   通过规范化路径来消除冗余

+   使用路径解析合并路径

+   在两个位置之间创建路径

+   在不同路径类型之间转换

+   确定两个路径是否等价

+   管理符号链接

# 介绍

文件系统是计算机上组织数据的一种方式。通常，它由一个或多个顶级目录组成，每个目录包含一系列文件。顶级目录通常被称为根。此外，文件系统存储在介质上，称为文件存储。

Java 7 引入了许多新的类和接口，使得与文件系统的工作更加简单和高效。这些类在很大程度上取代了`java.io`包中的旧类。

在本章和后续章节中，我们将演示如何使用目录结构管理文件系统，如下图所示：

![Introduction](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java7-new-feat-cb/img/5627_2_01.jpg)

椭圆代表目录，而矩形代表文件。基于 Unix 的系统和 Windows 系统在对根节点的支持上有所不同。Unix 系统支持单个根节点，而 Windows 系统允许多个根节点。目录或文件的位置使用路径来描述。路径的元素、目录和文件之间用正斜杠或反斜杠分隔。在 Unix 中使用正斜杠，在 Windows 中使用反斜杠。

音乐文件来自[`freepd.com/70s%20Sci%20Fi/`](http://freepd.com/70s%20Sci%20Fi/)。`status.txt`用于保存简单的状态信息，而`users.txt`则用于保存用户列表。音乐目录中的`users.txt`文件是指向`docs`目录中实际文件的符号链接，如红线所示。这些文件将在本章的各个示例中使用。当然，您可以使用任何您希望的文件或文件结构。

符号链接在基于 Unix 的平台上更常见。要为音乐目录中的`users.txt`文件创建符号链接，请在命令控制台中使用以下命令：`mklink users.txt c:\home\docs\users.txt`。这需要管理员权限才能执行。

本章涉及由`java.nio.file.Path`类表示的路径的管理。`Path`对象被`java.nio`包中的类广泛使用，由以下几个部分组成：

+   作为路径基础的根目录，比如 C 盘

+   用于分隔路径中组成目录和文件的名称的分隔符

+   中间目录的名称

+   终端元素，可以是文件或目录

这些内容在*理解路径*一节中进行了讨论和说明。以下是处理文件和目录的类：

+   `java.nio.file.Paths`包含用于创建`Path`对象的静态方法

+   `java.nio.file.Path`接口包含许多用于处理路径的方法

+   `java.nio.file.FileSystems`是用于访问文件系统的主要类

+   `java.nio.file.FileSystem`表示文件系统，比如 UNIX 系统上的/或 Windows 平台上的 C 盘

+   `java.nio.file.FileStore`表示实际存储设备并提供设备特定信息

+   `java.nio.file.attribute.FileStoreAttributeView`提供对文件信息的访问

最后两个类在后续章节中会更深入地讨论。为了访问文件或目录，我们通常会使用`FileSystems`类的`getDefault`方法来检索 JVM 可访问的文件系统的引用。要访问特定驱动器，我们可以使用`getFileSystem`方法，传入表示感兴趣的驱动器或目录的**统一资源标识符**（**URI**）对象。

`FileSystems`类提供了创建或访问文件系统的技术。在本章中，我们对类如何支持创建`Path`对象感兴趣。一旦我们有了文件系统对象的引用，我们就可以使用几种方法之一获取`Path`对象：

+   `getPath：`这使用系统相关路径来获取`Path`对象。`Path`对象用于定位和访问文件。

+   `getPathMatcher：`这将创建一个`PathMatcher`。它执行文件的各种匹配类型操作，并在第五章的“获取文件系统信息”配方中进行了讨论。

+   `getRootDirectories：`用于获取根目录列表。这个方法在第五章的“获取文件系统信息”配方中进行了说明。

*理解路径*配方介绍了`Path`对象的创建和一般用法。这些知识在后续配方和其他章节中使用，因此请确保理解本配方中涵盖的基本过程。

您仍然可以使用较旧的`java.io`包元素。可以使用`File`类的`toPath`方法创建表示`java.io.File`对象的路径。这在*java.io.File 和 java.nio.file.Files 之间的互操作性*配方中进行了讨论，并且在维护较旧的代码时可能会有用。

路径可以是相对的，也可以是绝对的。这些类型的路径以及处理它们的技术在“使用相对和绝对路径”配方中进行了讨论。

路径可能包含冗余和多余的元素。去除这些元素称为**规范化**。通过“通过规范化路径来删除路径中的冗余”配方，我们可以检查简化这些类型路径的可用技术。

路径可以组合成一个新的复合路径。这称为解析路径，并在*使用路径解析合并路径*配方中进行了讨论。这种技术可以用于创建新的路径，其中路径的部分来自不同的来源。

当需要文件的引用时，该路径有时相对于当前位置或其他位置。*在两个位置之间创建路径*配方说明了创建这样一个路径的过程。这个过程称为**相对化**。

不仅有相对和绝对路径，还有其他表示路径的方式，例如使用`java.net.URI`对象。创建`Path`对象时，并不一定需要实际路径存在。例如，可以创建`Path`以创建新的文件系统元素。*在不同路径类型之间转换*配方介绍了用于在这些不同类型路径之间转换的方法。

路径是依赖于系统的。也就是说，UNIX 系统上的路径与 Windows 系统上找到的路径不同。比较在同一平台上找到的两个路径可能相同，也可能不同。这在*确定两个路径是否等效*配方中进行了研究。

# 创建 Path 对象

需要路径来标识目录或文件。本配方的重点是如何为典型的文件和目录操作获取`Path`对象。路径在本章和许多后续章节中用于大多数配方，这些配方涉及文件和目录。

有几种方法可以创建或返回`Path`对象。在这里，我们将研究用于创建`Path`对象的方法以及如何使用其方法来进一步了解 Java 中使用的路径概念。

## 准备工作

为了创建`Path`对象，我们需要使用以下方法之一：

+   `FileSystem`类的`getPath`方法

+   `Paths`类的`get`方法

我们将首先使用`getPath`方法。`get`方法在本配方的*更多*部分中进行了解释。

## 如何做...

1.  创建一个带有`main`方法的控制台应用程序。在`main`方法中，添加以下代码序列，为文件`status.txt`创建一个`Path`对象。我们将使用几种`Path`类的方法来检查创建的路径，如下所示：

```java
Path path = FileSystems.getDefault().getPath("/home/docs/status.txt");
System.out.println();
System.out.printf("toString: %s\n", path.toString());
System.out.printf("getFileName: %s\n", path.getFileName());
System.out.printf("getRoot: %s\n", path.getRoot());
System.out.printf("getNameCount: %d\n", path.getNameCount());
for(int index=0; index<path.getNameCount(); index++) {
System.out.printf("getName(%d): %s\n", index, path.getName(index));
}
System.out.printf("subpath(0,2): %s\n", path.subpath(0, 2));
System.out.printf("getParent: %s\n", path.getParent());
System.out.println(path.isAbsolute());
}

```

1.  注意在`path`字符串中使用正斜杠。这种方法在任何平台上都可以工作。但是，在 Windows 上，您还可以使用如下所示的反斜杠：

```java
Path path = FileSystems.getDefault().getPath("\\home\\docs\\status.txt");

```

1.  在 Windows 平台上，任何一种方法都可以工作，但使用正斜杠更具可移植性。

1.  执行程序。您的输出应该如下所示：

toString: \home\docs\status.txt

getFileName: status.txt

getRoot: \

getNameCount: 3

getName(0): home

getName(1): docs

getName(2): status.txt

subpath(0,2): home\docs

getParent: \home\docs

false

## 它是如何工作的...

使用调用链接创建了`Path`对象，从`FileSystems`类的`getDefault`方法开始。这返回一个表示 JVM 可用文件系统的`FileSystem`对象。`FileSystem`对象通常指的是当前用户的工作目录。接下来，使用表示感兴趣文件的字符串执行了`getPath`方法。

代码的其余部分使用了各种方法来显示有关路径的信息。正如本章介绍中所详细介绍的那样，我们可以使用`Path`类的方法来显示有关路径部分的信息。`toString`方法针对路径执行，以说明默认情况下会得到什么。

`getFileName`返回了`Path`对象的文件名，`getRoot`返回了根目录。`getNameCount`方法返回了中间目录的数量加上一个文件名。for 循环列出了路径的元素。在这种情况下，有两个目录和一个文件，总共三个。这三个元素组成了路径。

虽然使用简单的 for 循环来显示这些名称，但我们也可以使用`iterator`方法来列出这些名称，如下面的代码所示：

```java
Iterator iterator = path.iterator();
while(iterator.hasNext()) {
System.out.println(iterator.next());
}

```

`Path`对象可能包括其他路径。可以使用`subpath`方法检索子路径。该方法具有两个参数。第一个表示初始索引，第二个参数指定排他性的最后索引。在此示例中，第一个参数设置为 0，表示要检索根级目录。最后一个索引设置为 2，这意味着只列出了顶部两个目录。

在这种情况下，`getParent`方法也返回相同的路径。但是，请注意它以反斜杠开头。这表示从每个元素的顶级元素开始，但最后一个元素除外的路径。

## 还有更多...

有几个问题需要进一步考虑：

+   使用`Paths`类的`get`方法

+   父路径的含义

### 使用 Paths 类的 get 方法

`Paths`类的`get`方法也可以用于创建`Path`对象。此方法使用可变数量的`String`参数来构造路径。在以下代码序列中，创建了一个从当前文件系统的根目录开始的`path`：

```java
try {
path = Paths.get("/home", "docs", "users.txt");
System.out.printf("Absolute path: %s", path.toAbsolutePath());
}
catch (InvalidPathException ex) {
System.out.printf("Bad path: [%s] at position %s",
ex.getInput(), ex.getIndex());
}

```

使用`toAbsolutePath`方法的输出显示了构建的路径。注意“E”元素。代码在 Windows 系统上执行，当前驱动器为“E”驱动器。`toAbsolutePath`方法在“使用相对路径和绝对路径”配方中进行了讨论。

绝对路径: E:\home\docs\users.txt

如果我们在路径的`String`中不使用斜杠，那么路径是基于当前工作目录创建的。删除斜杠并执行程序。您的输出应该类似于以下内容，其中“currentDirectory”被执行代码时使用的内容替换：

绝对路径: currentDirectory\home\docs\users.txt

使用“resolve”方法是一种更灵活的方法，如“使用路径解析合并路径”配方中所讨论的。

将输入参数转换为路径是依赖于系统的。如果用于创建路径的字符对于文件系统无效，则会抛出`java.nio.file.InvalidPathException`。例如，在大多数文件系统中，空值是一个非法字符。为了说明这一点，将反斜杠 0 添加到`path`字符串中，如下所示：

```java
path = Paths.get("/home\0", "docs", "users.txt");

```

执行时，部分输出将如下所示：

**错误路径：[/home \docs\users.txt] 位置在第 5 位**

`InvalidPathException`类的`getInput`方法返回用于创建路径的连接字符串。`getIndex`方法返回有问题的字符的位置，在本例中是空字符。

### 父路径的含义

`getParent`方法返回父路径。但是，该方法不访问文件系统。这意味着对于给定的`Path`对象，可能有也可能没有父级。

考虑以下路径声明：

```java
path = Paths.get("users.txt");

```

这是在当前工作目录中找到的`users.txt`文件。`getNameCount`将返回 1，`getParent`方法将返回 null。实际上，文件存在于目录结构中，并且有一个根和一个父级。因此，该方法的结果在某些情境下可能无用。

使用此方法大致相当于使用`subpath`方法：

```java
path = path.subpath(0,path.getNameCount()-1));

```

## 另请参阅

`toRealPath`方法在*使用相对路径和绝对路径*和*通过规范化路径来消除冗余*中有讨论。

# java.io.File 和 java.nio.file.Files 之间的互操作性

在引入`java.nio`包之前，`java.io`包的类和接口是 Java 开发人员用于处理文件和目录的唯一可用选项。虽然较新的包已经补充了`java.io`包的大部分功能，但仍然可以使用旧类，特别是`java.io.File`类。本文介绍了如何实现这一点。

## 准备工作

要使用`File`类获取`Path`对象，需要按照以下步骤进行：

1.  创建一个表示感兴趣文件的`java.io.File`对象

1.  应用`toPath`方法以获得`Path`对象

## 如何做...

1.  创建一个控制台应用程序。添加以下主要方法，我们在其中创建一个`File`对象和一个表示相同文件的`Path`对象。接下来，我们比较这两个对象，以确定它们是否表示相同的文件：

```java
public static void main(String[] args) {
try {
Path path =
Paths.get(new URI("file:///C:/home/docs/users.txt"));
File file = new File("C:\\home\\docs\\users.txt");
Path toPath = file.toPath();
System.out.println(toPath.equals(path));
}
catch (URISyntaxException e) {
System.out.println("Bad URI");
}
}

```

1.  当执行应用程序时，输出将为 true。

## 工作原理...

创建了两个`Path`对象。第一个`Path`对象是使用`Paths`类的`get`方法声明的。它使用`java.net.URI`对象为`users.txt`文件创建了一个`Path`对象。第二个`Path`对象`toPath`是从`File`对象使用`toPath`方法创建的。使用`Path`的`equals`方法来证明这些路径是等价的。

### 提示

注意使用正斜杠和反斜杠表示文件的字符串。`URI`字符串使用正斜杠，这是与操作系统无关的。而反斜杠用于 Windows 路径。

## 另请参阅

*理解路径*中演示了创建`Path`对象。此外，*使用相对路径和绝对路径*中讨论了创建`URI`对象。

# 将相对路径转换为绝对路径

路径可以表示为绝对路径或相对路径。两者都很常见，在不同情况下都很有用。`Path`类和相关类支持创建绝对路径和相对路径。

相对路径用于指定文件或目录的位置与当前目录位置的关系。通常，使用一个点或两个点来表示当前目录或下一个更高级目录。但是，在创建相对路径时，不需要使用点。

绝对路径从根级别开始，列出每个目录，用正斜杠或反斜杠分隔，取决于操作系统，直到达到所需的目录或文件。

在本示例中，我们将确定当前系统使用的路径分隔符，并学习如何将相对路径转换为绝对路径。在处理文件名的用户输入时，这是有用的。与绝对和相对路径相关的是路径的 URI 表示。我们将学习如何使用`Path`类的`toUri`方法来返回给定路径的这种表示。

## 准备工作

在处理绝对和相对路径时，经常使用以下方法：

+   `getSeparator`方法确定文件分隔符

+   `subpath`方法获取路径的一个部分或所有部分/元素

+   `toAbsolutePath`方法获取相对路径的绝对路径

+   `toUri`方法获取路径的 URI 表示

## 如何做...

1.  我们将逐个解决前面的每个方法。首先，使用以下`main`方法创建一个控制台应用程序：

```java
public static void main(String[] args) {
String separator = FileSystems.getDefault().getSeparator();
System.out.println("The separator is " + separator);
try {
Path path = Paths.get(new URI("file:///C:/home/docs/users.txt"));
System.out.println("subpath: " + path.subpath(0, 3));
path = Paths.get("/home", "docs", "users.txt");
System.out.println("Absolute path: " + path.toAbsolutePath());
System.out.println("URI: " + path.toUri());
}
catch (URISyntaxException ex) {
System.out.println("Bad URI");
}
catch (InvalidPathException ex) {
System.out.println("Bad path: [" + ex.getInput() + "] at position " + ex.getIndex());
}
}

```

1.  执行程序。在 Windows 平台上，输出应如下所示：

**分隔符是\**

**子路径：home\docs\users.txt**

**绝对路径：E:\home\docs\users.txt**

**URI：file:///E:/home/docs/users.txt**

## 工作原理...

`getDefault`方法返回一个表示 JVM 当前可访问的文件系统的`FileSystem`对象。对此对象执行`getSeparator`方法，返回一个反斜杠字符，表示代码在 Windows 机器上执行。

为`users.txt`文件创建了一个`Path`对象，并对其执行了`subpath`方法。这个方法在*理解路径*中有更详细的讨论。`subpath`方法总是返回一个相对路径。

接下来，使用`get`方法创建了一个路径。由于第一个参数使用了正斜杠，路径从当前文件系统的根开始。在这个例子中，提供的路径是相对的。

路径的 URI 表示与绝对和相对路径相关。`Path`类的`toUri`方法返回给定路径的这种表示。`URI`对象用于表示互联网上的资源。在这种情况下，它返回了一个文件的 URI 方案形式的字符串。

绝对路径可以使用`Path`类的`toAbsolutePath`方法获得。绝对路径包含路径的根元素和所有中间元素。当用户被要求输入文件名时，这可能很有用。例如，如果用户被要求提供一个文件名来保存结果，文件名可以添加到表示工作目录的现有路径中。然后可以获取绝对路径并根据需要使用。

## 还有更多...

请记住，`toAbsolutePath`方法无论路径引用有效文件还是目录都可以工作。前面示例中使用的文件不需要存在。考虑使用如下代码中所示的虚假文件。假设文件`bogusfile.txt`不存在于指定目录中：

```java
Path path = Paths.get(new URI("file:///C:/home/docs/bogusfile.txt"));
System.out.println("File exists: " + Files.exists(path));
path = Paths.get("/home", "docs", "bogusfile.txt");
System.out.println("File exists: " + Files.exists(path));

```

程序执行时，输出如下：

**分隔符是\**

**文件存在：false**

**子路径：home\docs\bogusfile.txt**

**文件存在：false**

**绝对路径：E:\home\docs\bogusfile.txt**

**URI：file:///E:/home/docs/bogusfile.txt**

如果我们想知道这是否是一个真实的路径，我们可以使用`toRealPath`方法，如*通过规范化路径来删除路径中的冗余*中所讨论的那样。

## 另请参阅

可以使用`normalize`方法删除路径中的冗余，如*通过规范化路径来删除路径中的冗余*中所讨论的那样。

当符号链接用于文件时，路径可能不是文件的真实路径。`Path`类的`toRealPath`方法将返回文件的真实绝对路径。这在*通过规范化路径来消除冗余*示例中进行了演示。

# 通过规范化路径消除冗余

当在定义路径时使用“.”或“..”符号时，它们的使用可能会引入冗余。也就是说，所描述的路径可能通过删除或以其他方式更改路径来简化。本示例讨论了使用`normalize`方法来影响这种转换。通过简化路径，可以避免错误并提高应用程序的性能。`toRealPath`方法还执行规范化，并在本示例的*还有更多...*部分进行了解释。

## 准备就绪

消除路径中冗余的基本步骤包括以下内容：

+   识别可能包含冗余的路径

+   使用`normalize`方法消除冗余

## 如何做...

介绍中的目录结构在此处复制以方便起见：

![如何做...](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java7-new-feat-cb/img/5627_2_01.jpg)

首先考虑以下路径：

```java
/home/docs/../music/ Space Machine A.mp3
/home/./music/ Robot Brain A.mp3

```

这些包含冗余或多余的部分。在第一个示例中，路径从`home`开始，然后进入`docs`目录的一个目录级别。然后，`.`符号将路径返回到`home`目录。然后继续进入`music`目录并到`mp3`文件。`docs/.`元素是多余的。

在第二个示例中，路径从`home`开始，然后遇到一个句点。这代表当前目录，即`home`目录。接下来，路径进入`music`目录，然后遇到`mp3`文件。`/`是多余的，不需要。

1.  创建一个新的控制台应用程序，并添加以下`main`方法：

```java
public static void main(String[] args) {
Path path = Paths.get("/home/docs/../music/Space Machine A.mp3");
System.out.println("Absolute path: " + path.toAbsolutePath());
System.out.println("URI: " + path.toUri());
System.out.println("Normalized Path: " + path.normalize());
System.out.println("Normalized URI: " + path.normalize().toUri());
System.out.println();
path = Paths.get("/home/./music/ Robot Brain A.mp3");
System.out.println("Absolute path: " + path.toAbsolutePath());
System.out.println("URI: " + path.toUri());
System.out.println("Normalized Path: " + path.normalize());
System.out.println("Normalized URI: " + path.normalize().toUri());
}

```

1.  执行应用程序。您应该获得以下输出，尽管根目录可能会根据系统配置而有所不同：

**绝对路径：E:\home\docs\..\music\Space Machine A.mp3**

**URI：file:///E:/home/docs/../music/Space%20Machine%20A.mp3**

**规范化路径：\home\music\Space Machine A.mp3**

**规范化的 URI：file:///E:/home/music/Space%20Machine%20A.mp3**

**绝对路径：E:\home\.\music\ Robot Brain A.mp3**

URI：file:///E:/home/./music/%20Robot%20Brain%20A.mp3

**规范化路径：\home\music\ Robot Brain A.mp3**

**规范化的 URI：file:///E:/home/music/%20Robot%20Brain%20A.mp3**

## 它是如何工作的...

使用`Paths`类的`get`方法使用先前讨论过的冗余多余路径创建了两个路径。`get`方法后面的代码显示了绝对路径和 URI 等效项，以说明创建的实际路径。接下来，使用了`normalize`方法，然后与`toUri`方法链接，以进一步说明规范化过程。请注意，冗余和多余的路径元素已经消失。`toAbsolutePath`和`toUri`方法在*使用相对和绝对路径*示例中进行了讨论。

`normalize`方法不会检查文件或路径是否有效。该方法只是针对路径执行语法操作。如果符号链接是原始路径的一部分，则规范化路径可能不再有效。符号链接在*管理符号链接*示例中讨论。

## 还有更多...

`Path`类的`toRealPath`将返回表示文件实际路径的路径。它会检查路径是否有效，如果文件不存在，则会返回`java.nio.file.NoSuchFileException`。

修改先前的示例，使用`toRealPath`方法并显示不存在的文件，如下面的代码所示：

```java
try
Path path = Paths.get("/home/docs/../music/NonExistentFile.mp3");
System.out.println("Absolute path: " + path.toAbsolutePath());
System.out.println("Real path: " + path.toRealPath());
}
catch (IOException ex) {
System.out.println("The file does not exist!");
}

```

执行应用程序。结果应包含以下输出：

**绝对路径：\\Richard-pc\e\home\docs\..\music\NonExistentFile.mp3**

**文件不存在！**

`toRealPath`方法规范化路径。它还解析任何符号链接，尽管在此示例中没有符号链接。

## 另请参阅

`Path`对象的创建在*理解路径*配方中有所讨论。符号链接在*管理符号链接*配方中有所讨论。

# 使用路径解析来组合路径

`resolve`方法用于组合两个路径，其中一个包含根元素，另一个是部分路径。这在创建可能变化的路径时非常有用，例如在应用程序的安装中使用的路径。例如，可能有一个默认目录用于安装应用程序。但是，用户可能能够选择不同的目录或驱动器。使用`resolve`方法创建路径允许应用程序独立于实际安装目录进行配置。

## 准备工作

使用`resolve`方法涉及两个基本步骤：

+   创建一个使用根元素的`Path`对象

+   对此路径执行`resolve`方法，使用第二个部分路径

部分路径是指仅提供完整路径的一部分，并且不包含根元素。

## 如何做...

1.  创建一个新的应用程序。将以下`main`方法添加到其中：

```java
public static void main(String[] args) {
Path rootPath = Paths.get("/home/docs");
Path partialPath = Paths.get("users.txt");
Path resolvedPath = rootPath.resolve(partialPath);
System.out.println("rootPath: " + rootPath);
System.out.println("partialPath: " + partialPath);
System.out.println("resolvedPath: " + resolvedPath);
System.out.println("Resolved absolute path: " + resolvedPath.toAbsolutePath());
}

```

1.  执行代码。您应该得到以下输出：

**rootPath: \home\docs**

**partialPath: users.txt**

**resolvedPath: \home\docs\users.txt**

**解析的绝对路径：E:\home\docs\users.txt**

## 工作原理...

以下三条路径已创建：

+   `\home\docs：`这是根路径

+   `users.txt：`这是部分路径

+   `\home\docs\users.txt：`这是生成的解析路径

通过使用`partialPath`变量作为`resolve`方法的参数执行对`rootPath`变量的操作来创建解析路径。然后显示这些路径以及`resolvedPath`的绝对路径。绝对路径包括根目录，尽管这在您的系统上可能有所不同。

## 还有更多...

`resolve`方法是重载的，一个使用`String`参数，另一个使用`Path`参数。`resolve`方法也可能被误用。此外，还有一个`overloadedresolveSibling`方法，其工作方式类似于`resolve`方法，只是它会移除根路径的最后一个元素。这些问题在这里得到解决。

### 使用`String`参数与`resolve`方法

`resolve`方法是重载的，其中一个接受`String`参数。以下语句将实现与前面示例相同的结果：

```java
Path resolvedPath = rootPath.resolve("users.txt");

```

路径分隔符也可以使用如下：

```java
Path resolvedPath = rootPath.resolve("backup/users.txt");

```

使用这些语句与先前的代码会产生以下输出：

根路径：\home\docs

**partialPath: users.txt**

**resolvedPath: \home\docs\backup\users.txt**

**解析的绝对路径：E:\home\docs\backup\users.txt**

请注意，解析的路径不一定是有效路径，因为备份目录可能存在，也可能不存在。在*通过规范化路径来消除路径中的冗余*配方中，可以使用`toRealPath`方法来确定它是否有效。

### 错误使用`resolve`方法

`resolve`方法有三种用法，可能会导致意外行为：

+   根路径和部分路径的顺序不正确

+   使用部分路径两次

+   使用根路径两次

如果我们颠倒`resolve`方法的使用顺序，也就是将根路径应用于部分路径，那么只会返回根路径。下面的代码演示了这一点：

```java
Path resolvedPath = partialPath.resolve(rootPath);

```

当执行代码时，我们得到以下结果：

根路径：\home\docs

**partialPath: users.txt**

**resolvedPath: \home\docs**

**解析的绝对路径：E:\home\docs**

这里只返回根路径。部分路径不会附加到根路径上。如下面的代码所示，使用部分路径两次：

```java
Path resolvedPath = partialPath.resolve(partialPath);

```

将产生以下输出：

**rootPath: \home\docs**

**partialPath: users.txt**

**resolvedPath: users.txt\users.txt**

**解析的绝对路径：currentWorkingDIrectory\users.txt\users.txt**

请注意，解析的路径是不正确的，绝对路径使用了当前工作目录。如下所示，使用根路径两次：

```java
Path resolvedPath = rootPath.resolve(rootPath);

```

结果与以相反顺序使用路径时相同：

**rootPath: \home\docs**

**partialPath: users.txt**

**resolvedPath: \home\docs**

**解析的绝对路径：E:\home\docs**

每当绝对路径被用作`resolve`方法的参数时，该绝对路径将被返回。如果空路径被用作方法的参数，则根路径将被返回。

### 使用`resolveSibling`

`resolveSibling`方法是重载的，可以接受`String`或`Path`对象。使用`resolve`方法时，部分路径被附加到根路径的末尾。`resolveSibling`方法与`resolve`方法不同之处在于，在附加部分路径之前，根路径的最后一个元素被移除。考虑以下代码序列：

```java
Path rootPath = Paths.get("/home/music/");
resolvedPath = rootPath.resolve("tmp/Robot Brain A.mp3");
System.out.println("rootPath: " + rootPath);
System.out.println("resolvedPath: " + resolvedPath);
System.out.println();
resolvedPath = rootPath.resolveSibling("tmp/Robot Brain A.mp3");
System.out.println("rootPath: " + rootPath);
System.out.println("resolvedPath: " + resolvedPath);

```

当执行时，我们得到以下输出：

**rootPath: \home\music**

**resolvedPath: \home\music\tmp\Robot Brain A.mp3**

**rootPath: \home\music**

**resolvedPath: \home\tmp\Robot Brain A.mp3**

请注意，解析路径在存在`music`目录时与使用`resolveSibling`方法时不同。当使用`resolve`方法时，目录存在。当使用`resolveSibling`方法时，目录不存在。如果没有父路径，或者方法的参数是绝对路径，则返回传递给方法的参数。如果参数为空，则返回父目录。

## 另请参阅

`Path`对象的创建在*理解路径*配方中有所讨论。此外，`toRealPath`方法在*通过规范化路径来消除路径中的冗余*配方中有所解释。

# 在两个位置之间创建路径

相对化路径意味着基于另外两个路径创建一个路径，使得新路径表示从原始路径中的一个导航到另一个的方式。这种技术找到了从一个位置到另一个位置的相对路径。例如，第一个路径可以表示一个应用程序默认目录。第二个路径可以表示一个目标目录。从这些目录创建的相对路径可以促进对目标的操作。

## 准备工作

要使用`relativize`方法从一个路径到另一个路径创建新路径，我们需要执行以下操作：

1.  创建一个代表第一个路径的`Path`对象。

1.  创建一个代表第二个路径的`Path`对象。

1.  对第一个路径使用第二个路径作为参数应用`relativize`方法。

## 如何做...

1.  创建一个新的控制台应用程序，并使用以下`main`方法。该方法创建两个`Path`对象，并显示它们之间的相对路径如下：

```java
public static void main(String[] args) {
Path firstPath;
Path secondPath;
firstPath = Paths.get("music/Future Setting A.mp3");
secondPath = Paths.get("docs");
System.out.println("From firstPath to secondPath: " + firstPath.relativize(secondPath));
System.out.println("From secondPath to firstPath: " + secondPath.relativize(firstPath));
System.out.println();
firstPath = Paths.get("music/Future Setting A.mp3");
secondPath = Paths.get("music");
System.out.println("From firstPath to secondPath: " + firstPath.relativize(secondPath));
System.out.println("From secondPath to firstPath: " + secondPath.relativize(firstPath));
System.out.println();
firstPath = Paths.get("music/Future Setting A.mp3");
secondPath = Paths.get("docs/users.txt");
System.out.println("From firstPath to secondPath: " + firstPath.relativize(secondPath));
System.out.println("From secondPath to firstPath: " + secondPath.relativize(firstPath));
System.out.println();
}

```

1.  执行应用程序。您的结果应该类似于以下内容：

**从 firstPath 到 secondPath: ..\..\docs**

**从 secondPath 到 firstPath: ..\music\Future Setting A.mp3**

**从 firstPath 到 secondPath: ..**

**从 secondPath 到 firstPath: Future Setting A.mp3**

**从 firstPath 到 secondPath: ..\..\docs\users.txt**

**从 secondPath 到 firstPath: ..\..\music\Future Setting A.mp3**

## 工作原理...

在第一个例子中，从`Future Setting A.mp3`文件到`docs`目录创建了一个相对路径。假定`music`和`docs`目录是兄弟目录。`.`符号表示向上移动一个目录。本章的介绍说明了这个例子的假定目录结构。

第二个例子演示了从同一目录中创建路径。从`firstpath`到`secondPath`的路径实际上是一个潜在的错误。取决于如何使用它，我们可能会最终进入`music`目录上面的目录，因为返回的路径是`.`，表示向上移动一个目录级别。第三个例子与第一个例子类似，只是两个路径都包含文件名。

该方法创建的相对路径可能不是有效的路径。通过使用可能不存在的`tmp`目录来说明，如下所示：

```java
firstPath = Paths.get("music/Future Setting A.mp3");
secondPath = Paths.get("docs/tmp/users.txt");
System.out.println("From firstPath to secondPath: " + firstPath.relativize(secondPath));
System.out.println("From secondPath to firstPath: " + secondPath.relativize(firstPath));

```

输出应该如下所示：

**从 firstPath 到 secondPath: ..\..\docs\tmp\users.txt**

**从 secondPath 到 firstPath：..\..\..\music\Future Setting A.mp3**

## 还有更多...

还有三种情况需要考虑：

+   两条路径相等

+   一条路径包含根

+   两条路径都包含根

### 两条路径相等

当两条路径相等时，`relativize`方法将返回一个空路径，如下面的代码序列所示：

```java
firstPath = Paths.get("music/Future Setting A.mp3");
secondPath = Paths.get("music/Future Setting A.mp3");
System.out.println("From firstPath to secondPath: " + firstPath.relativize(secondPath));
System.out.println("From secondPath to firstPath: " + secondPath.relativize(firstPath));
System.out.println();

```

输出如下：

**从 firstPath 到 secondPath：**

**从 secondPath 到 firstPath：**

虽然这不一定是错误，但请注意它不返回一个经常用来表示当前目录的单个点。

### 一条路径包含根

如果两条路径中只有一条包含根元素，则可能无法构造相对路径。是否可能取决于系统。在下面的例子中，第一条路径包含根元素`c:`。

```java
firstPath = Paths.get("c:/music/Future Setting A.mp3");
secondPath = Paths.get("docs/users.txt");
System.out.println("From firstPath to secondPath: " + firstPath.relativize(secondPath));
System.out.println("From secondPath to firstPath: " + secondPath.relativize(firstPath));
System.out.println();

```

当在 Windows 7 上执行此代码序列时，我们得到以下输出：

**线程"main"中的异常"java.lang.IllegalArgumentException: 'other'是不同类型的路径**

**从 firstPath 到 secondPath：.**。

**从 secondPath 到 firstPath：Future Setting A.mp3**

**atsun.nio.fs.WindowsPath.relativize(WindowsPath.java:388)**

**atsun.nio.fs.WindowsPath.relativize(WindowsPath.java:44)**

**atpackt.RelativizePathExample.main(RelativizePathExample.java:25)**

**Java 结果：1**

注意输出中对**other**的引用。这指的是`relativize`方法的参数。

### 两条路径都包含根

`relativize`方法在两条路径都包含根元素时创建相对路径的能力也取决于系统。这种情况在下面的例子中有所说明：

```java
firstPath = Paths.get("c:/music/Future Setting A.mp3");
secondPath = Paths.get("c:/docs/users.txt");
System.out.println("From firstPath to secondPath: " + firstPath.relativize(secondPath));
System.out.println("From secondPath to firstPath: " + secondPath.relativize(firstPath));
System.out.println();

```

在 Windows 7 上执行时，我们得到以下输出：

**从 firstPath 到 secondPath：..\..\docs\users.txt**

**从 secondPath 到 firstPath：..\..\music\Future Setting A.mp3**

## 另请参阅

`Path`对象的创建在*理解路径*配方中讨论。符号链接的结果取决于系统，并在*管理符号链接*配方中进行了更深入的讨论。

# 在路径类型之间进行转换

`Path`接口表示文件系统中的路径。这个路径可能是有效的，也可能不是。有时我们可能想要使用路径的另一种表示。例如，可以使用文件的`URI`在大多数浏览器中加载文件。`toUri`方法提供了路径的这种表示。在这个示例中，我们还将看到如何获取`Path`对象的绝对路径和真实路径。

## 准备好了

有三种方法提供替代路径表示：

+   `toUri`方法返回`URI`表示

+   `toAbsolutePath`方法返回绝对路径

+   `toRealPath`方法返回真实路径

## 如何做...

1.  创建一个新的控制台应用程序。在`main`方法中，我们将使用之前的每种方法。将以下`main`方法添加到应用程序中：

```java
public static void main(String[] args) {
try {
Path path;
path = Paths.get("users.txt");
System.out.println("URI path: " + path.toUri());
System.out.println("Absolute path: " + path.toAbsolutePath());
System.out.println("Real path: " + path.toRealPath(LinkOption.NOFOLLOW_LINKS));
}
catch (IOException ex) {
Logger.getLogger(ConvertingPathsExample.class.getName()).log(Level.SEVERE, null, ex);
}
}

```

1.  如果尚未存在，请在应用程序的工作目录中添加一个`users.txt`文件。执行程序。您的输出应该类似于以下内容，除了此输出中的**..**应反映`users.txt`文件的位置：

**URI 路径：file:///.../ConvertingPathsExample/users.txt**

**绝对路径...\ConvertingPathsExample\users.txt**

**真实路径：...\ConvertingPathsExample\users.txt**

## 它是如何工作的...

一个`users.txt`文件被添加到 Java 应用程序的工作目录中。该文件应包含用户名列表。`get`方法返回表示此文件的`Path`对象。然后对该对象执行了三种方法。

`toUri`和`toAbsolutePath`方法按预期返回路径。返回的路径取决于应用程序的工作目录。`toRealPath`方法应该返回与`toAbsolutePath`方法相同的输出。这是预期的，因为`users.txt`文件不是作为符号链接创建的。如果这是一个符号链接，那么将显示代表文件实际路径的不同路径。

## 还有更多...

由于`Path`对象可能实际上并不代表文件，如果文件不存在，使用`toRealPath`方法可能会抛出`java.nio.file.NoSuchFileException`。使用一个无效的文件名，如下所示：

```java
path = Paths.get("invalidFileName.txt");

```

输出应该如下所示：

**URI 路径：file:///.../ConvertingPathsExample/invalidFileName.txt**

**绝对路径：...\ConvertingPathsExample\invalidFileName.txt**

**Sep 11, 2011 6:40:40 PM packt.ConvertingPathsExample main**

**严重：null**

**java.nio.file.NoSuchFileException: ...\ConvertingPathsExample\invalidFileName.txt**

请注意，`toUri`和`toAbsolutePath`方法无论指定的文件是否存在都可以工作。在我们想要使用这些方法的情况下，我们可以使用`Files`类的`exists`方法来测试文件是否存在。前面的代码序列已经修改为使用`exists`方法，如下所示：

```java
if(Files.exists(path)) {
System.out.println("Real path: " + path.toRealPath(LinkOption.NOFOLLOW_LINKS));
}
else {
System.out.println("The file does not exist");
}

```

`java.nio.fil.LinkOption`枚举是在 Java 7 中添加的。它用于指定是否应该跟随符号链接。

执行时，输出应如下所示：

**URI 路径：file:///.../ConvertingPathsExample/invalidFileName.txt**

**绝对路径：...\ConvertingPathsExample\invalidFileName.txt**

**文件不存在**

# 确定两个路径是否等效

有时可能需要比较路径。`Path`类允许您使用`equals`方法测试路径的相等性。您还可以使用`compareTo`方法使用`Comparable`接口的实现按字典顺序比较两个路径。最后，`isSameFile`方法可用于确定两个`Path`对象是否将定位到相同的文件。

## 准备工作

为了比较两个路径，您必须：

1.  创建一个代表第一个路径的`Path`对象。

1.  创建一个代表第二个路径的`Path`对象。

1.  根据需要对路径应用`equals, compareTo`或`isSameFile`方法。

## 如何做...

1.  创建一个新的控制台应用程序并添加一个`main`方法。声明三个`Path`对象变量，如`path1，path2`和`path3`。将前两个设置为相同的文件，第三个设置为不同的路径。所有三个文件必须存在。接下来调用三个比较方法：

```java
public class ComparingPathsExample {
public static void main(String[] args) {
Path path1 = null;
Path path2 = null;
Path path3 = null;
path1 = Paths.get("/home/docs/users.txt");
path2 = Paths.get("/home/docs/users.txt");
path3 = Paths.get("/home/music/Future Setting A.mp3");
testEquals(path1, path2);
testEquals(path1, path3);
testCompareTo(path1, path2);
testCompareTo(path1, path3);
testSameFile(path1, path2);
testSameFile(path1, path3);
}

```

1.  添加三个静态方法如下：

```java
private static void testEquals(Path path1, Path path2) {
if (path1.equals(path2)) {
System.out.printf("%s and %s are equal\n",
path1, path2);
}
else {
System.out.printf("%s and %s are NOT equal\n",
path1, path2);
}
}
private static void testCompareTo(Path path1, Path path2) {
if (path1.compareTo(path2) == 0) {
System.out.printf("%s and %s are identical\n",
path1, path2);
}
else {
System.out.printf("%s and %s are NOT identical\n",
path1, path2);
}
}
private static void testSameFile(Path path1, Path path2) {
try {
if (Files.isSameFile(path1, path2)) {
System.out.printf("%s and %s are the same file\n",
path1, path2);
}
else {
System.out.printf("%s and %s are NOT the same file\n",
path1, path2);
}
}
catch (IOException e) {
e.printStackTrace();
}
}

```

1.  执行应用程序。您的输出应该类似于以下内容：

**\home\docs\users.txt 和 \home\docs\users.txt 是相等的**

**\home\docs\users.txt 和 \home\music\Future Setting A.mp3 不相等**

\home\docs\users.txt 和 \home\docs\users.txt 是相同的

**\home\docs\users.txt 和 \home\music\Future Setting A.mp3 不相同**

**\home\docs\users.txt 和 \home\docs\users.txt 是相同的文件**

**\home\docs\users.txt 和 \home\music\Future Setting A.mp3 不是同一个文件**

## 它是如何工作的...

在`testEquals`方法中，我们确定了路径对象是否被视为相等。如果它们相等，`equals`方法将返回 true。但是，相等的定义是依赖于系统的。一些文件系统将使用大小写等因素来确定路径是否相等。

`testCompareTo`方法使用`compareTo`方法按字母顺序比较路径。如果路径相同，该方法返回零。如果路径小于参数，则该方法返回小于零的整数，如果路径按字典顺序跟随参数，则返回大于零的值。

`testSameFile`方法确定路径是否指向相同的文件。首先测试`Path`对象是否相同。如果是，则该方法将返回 true。如果`Path`对象不相等，则该方法确定路径是否指向相同的文件。如果`Path`对象是由不同的文件系统提供程序生成的，则该方法将返回 false。由于该方法可能引发`IOException`，因此使用了 try 块。

## 还有更多...

`equals`和`compareTo`方法将无法成功比较来自不同文件系统的路径。但是，只要文件位于同一文件系统上，所涉及的文件无需存在，文件系统也不会被访问。如果要测试的路径对象不相等，则`isSameFile`方法可能需要访问文件。在这种情况下，文件必须存在，否则该方法将返回 false。

## 另请参阅

`Files`类的`exists`和`notExists`方法可用于确定文件或目录是否存在。这在第三章的*获取文件和目录信息*中有所涵盖。

# 管理符号链接

符号链接用于创建对实际存在于不同目录中的文件的引用。在介绍中，详细列出了文件层次结构，其中`users.txt`文件在`docs`目录和`music`目录中分别列出。实际文件位于`docs`目录中。`music`目录中的`users.txt`文件是对真实文件的符号链接。对用户来说，它们看起来是不同的文件。实际上，它们是相同的。修改任一文件都会导致真实文件被更改。

从程序员的角度来看，我们经常想知道哪些文件是符号链接，哪些不是。在本教程中，我们将讨论 Java 7 中可用于处理符号链接的方法。重要的是要了解在与符号链接一起使用方法时方法的行为。

## 准备就绪

虽然几种方法可能根据`Path`对象是否表示符号链接而有所不同，但在本章中，只有`toRealPath，exists`和`notExists`方法接受可选的`LinkOption`枚举参数。此枚举只有一个元素：`NOFOLLOW_LINKS`。如果未使用该参数，则方法默认会跟随符号链接。

## 如何做...

1.  创建一个新的控制台应用程序。使用以下`main`方法，在其中创建代表真实和符号`users.txt`文件的几个`Path`对象。演示了本章中几个`Path-related`方法的行为。

```java
public static void main(String[] args) {
Path path1 = null;
Path path2 = null;
path1 = Paths.get("/home/docs/users.txt");
path2 = Paths.get("/home/music/users.txt");
System.out.println(Files.isSymbolicLink(path1));
System.out.println(Files.isSymbolicLink(path2));
try {
Path path = Paths.get("C:/home/./music/users.txt");
System.out.println("Normalized: " + path.normalize());
System.out.println("Absolute path: " + path.toAbsolutePath());
System.out.println("URI: " + path.toUri());
System.out.println("toRealPath (Do not follow links): " + path.toRealPath(LinkOption.NOFOLLOW_LINKS));
System.out.println("toRealPath: " + path.toRealPath());
Path firstPath = Paths.get("/home/music/users.txt");
Path secondPath = Paths.get("/docs/status.txt");
System.out.println("From firstPath to secondPath: " + firstPath.relativize(secondPath));
System.out.println("From secondPath to firstPath: " + secondPath.relativize(firstPath));
System.out.println("exists (Do not follow links): " + Files.exists(firstPath, LinkOption.NOFOLLOW_LINKS));
System.out.println("exists: " + Files.exists(firstPath));
System.out.println("notExists (Do not follow links): " + Files.notExists(firstPath, LinkOption.NOFOLLOW_LINKS));
System.out.println("notExists: " + Files.notExists(firstPath));
}
catch (IOException ex) {
Logger.getLogger(SymbolicLinkExample.class.getName()).log(Level.SEVERE, null, ex);
}
catch (InvalidPathException ex) {
System.out.println("Bad path: [" + ex.getInput() + "] at position " + ex.getIndex());
}
}

```

1.  这些方法的行为可能因基础操作系统而异。当代码在 Windows 平台上执行时，我们会得到以下输出：

**false**

**true**

**标准化：C：\ home \ music \ users.txt**

**绝对路径：C：\ home \。music \ users.txt**

**URI：file:///C:/home/./music/users.txt**

toRealPath（不要跟随链接）：C：\ home \ music \ users.txt

**toRealPath：C：\ home \ docs \ users.txt**

**从 firstPath 到 secondPath：..\..\..\docs\status.txt**

**从 secondPath 到 firstPath：..\..\home\music\users.txt**

**exists（不要跟随链接）：true**

**exists：true**

**notExists（不要跟随链接）：false**

**notExists：false**

## 它是如何工作的...

创建了`path1`和`path2`对象，分别引用了真实文件和符号链接。针对这些对象执行了`Files`类的`isSymbolicLink`方法，指示哪个路径引用了真实文件。

使用多余的点符号创建了`Path`对象。针对符号链接执行的`normalize`方法的结果返回了对符号链接的标准化路径。使用`toAbsolutePath`和`toUri`方法会返回对符号链接而不是真实文件的路径。

`toRealPath`方法具有可选的`LinkOption`参数。我们使用它来获取真实文件的路径。当您需要真实路径时，这个方法非常有用，通常其他方法执行符号链接时不会返回真实路径。

`firstPath`和`secondPath`对象被用来探索`relativize`方法如何与符号链接一起工作。在这些例子中，使用了符号链接。最后一组例子使用了`exists`和`notExists`方法。使用符号链接并不影响这些方法的结果。

## 另请参阅

符号文件的使用对其他文件系统方法的影响将在后续章节中讨论。
