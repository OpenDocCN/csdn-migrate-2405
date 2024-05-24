# Java 基础知识（一）

> 原文：[`zh.annas-archive.org/md5/F34A3E66484E0F50CC62C9133E213205`](https://zh.annas-archive.org/md5/F34A3E66484E0F50CC62C9133E213205)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

## 关于

本节简要介绍了作者、本书的覆盖范围、开始所需的技术技能，以及完成所有包含的活动和练习所需的硬件和软件要求。

## 关于本书

自 Java 诞生以来，它已经席卷了编程世界。其特性和功能为开发人员提供了编写强大的跨平台应用程序所需的工具。《Java 基础》向您介绍了这些工具和功能，使您能够创建 Java 程序。本书从语言的介绍、其哲学和演变开始，直到最新版本。您将了解`javac`/`java`工具的工作原理，以及 Java 包的方式，以及 Java 程序通常的组织方式。一旦您对此感到满意，您将被介绍到语言的高级概念，如控制流关键字。您将探索面向对象编程及其在 Java 中的作用。在结束课程中，您将掌握类、类型转换和接口，并了解数据结构、数组和字符串的用途；处理异常；以及创建泛型。

通过本书，您将学会如何编写程序、自动化任务，并阅读高级算法和数据结构书籍，或者探索更高级的 Java 书籍。

### 关于作者

**Gazihan Alankus**是伊兹密尔经济大学的助理教授，教授与移动应用程序、游戏和物联网相关的书籍。他在华盛顿大学圣路易斯分校获得博士学位，并在谷歌实习。2019 年，他成为了谷歌开发者专家，专注于 Dart 编程语言。他喜欢参与各种研究和开发项目。

**Rogério Theodoro de Brito**拥有巴西圣保罗大学的计算机科学学士学位和计算生物学硕士学位。在学术上，他是自由/开源软件（FOSS）的爱好者，并在巴西圣保罗的麦肯齐长老会大学教授计算机科学和 IT 的各种课程。他是 Packt 的*edX 电子学习课程营销*的技术审阅员。

在完成硕士学位后，他开始担任学术讲师的角色，并一直在使用许多语言，如 C、C++、Java、C、Perl 和 Python。

**Basheer Ahamed Fazal**在印度一家著名的基于软件即服务的产品公司担任技术架构师。他曾在科技组织如 Cognizant、Symantec、HID Global 和 Ooyala 工作。他通过解决围绕敏捷产品开发的复杂问题，包括微服务、亚马逊云服务、基于谷歌云的架构、应用安全和大数据和人工智能驱动的倡议，磨练了自己的编程和算法能力。

**Vinicius Isola**拥有圣保罗大学物理学学士学位。当 Macromedia Flash 占据互联网时，他开始学习如何编写 ActionScript 程序。在学习 Visual Basic 的 10 个月课程期间，他使用它来构建细胞自动机与遗传算法相结合的生命模拟，用于大学的科学启蒙计划。

如今，他在 Everbridge 担任全职软件工程师，并利用业余时间学习新的编程语言，如 Go，并构建工具来帮助开发人员实现强大的持续集成和持续部署的自动化流水线。

**Miles Obare**领导着位于内罗毕的体育博彩公司 Betika 的数据工程团队。他致力于构建实时、可扩展的后端系统。此前，他曾在一家金融科技初创公司担任数据工程师，其工作涉及开发和部署数据管道和机器学习模型到生产环境。他拥有电气和计算机工程学位，并经常撰写有关分布式系统的文章。

### 目标

+   创建和运行 Java 程序

+   在代码中使用数据类型、数据结构和控制流

+   创建对象时实施最佳实践

+   与构造函数和继承一起工作

+   了解高级数据结构以组织和存储数据

+   使用泛型进行更强的编译时类型检查

+   学习如何处理代码中的异常

### 受众

*Java 基础*是为熟悉一些编程语言并希望快速了解 Java 最重要原则的技术爱好者设计的。

### 方法

*Java 基础*采用实用的方法，以最短的时间为初学者提供最基本的数据分析工具。它包含多个使用真实商业场景的活动，供您练习并在高度相关的环境中应用您的新技能。

### 硬件要求

为了获得最佳的学生体验，我们建议以下硬件配置：

+   处理器：Intel Core i7 或同等级

+   内存：8GB RAM

+   存储空间：35GB 可用空间

### 软件要求

您还需要提前安装以下软件：

+   操作系统：Windows 7 或更高版本

+   Java 8 JDK

+   IntelliJ IDEA

### 安装和设置

IntelliJ IDEA 是一个集成开发环境，试图将您可能需要的所有开发工具集成到一个地方。

**安装 IntelliJ IDEA**

1.  要在您的计算机上安装 IntelliJ，请转到 https://www.jetbrains.com/idea/download/#section=windows 并下载适用于您操作系统的社区版。

1.  打开下载的文件。您将看到以下窗口。单击**下一步**：![图 0.1：IntelliJ IDEA 社区设置向导](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-fund/img/C09581_00_01.jpg)

######

图 0.1：IntelliJ IDEA 社区设置向导

1.  选择安装 IntelliJ 的目录，然后选择**下一步**：![图 0.2：选择安装位置的向导](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-fund/img/C09581_00_02.jpg)

###### 图 0.2：选择安装位置的向导

1.  选择首选安装选项，然后单击**下一步**：![图 0.3：选择安装选项的向导](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-fund/img/C09581_00_03.jpg)

###### 图 0.3：选择安装选项的向导

1.  选择开始菜单文件夹，然后单击**安装**：![图 0.4：选择开始菜单文件夹的向导](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-fund/img/C09581_00_04.jpg)

###### 图 0.4：选择开始菜单文件夹的向导

1.  下载完成后单击**完成**：

![图 0.5：完成安装的向导](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-fund/img/C09581_00_05.jpg)

###### 图 0.5：完成安装的向导

安装完 IntelliJ 后重新启动系统。

**安装 Java 8 JDK**

Java 开发工具包（JDK）是使用 Java 编程语言构建应用程序的开发环境：

1.  要安装 JDK，请转到 https://www.oracle.com/technetwork/java/javase/downloads/jdk8-downloads-2133151.html。

1.  转到**Java SE Development Kit 8u201**并选择**接受许可协议**选项。

1.  下载适用于您操作系统的 JDK。

1.  下载文件后运行安装程序一次。

### 约定

文本中的代码单词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 用户名显示如下："正确的指令应该是`System.out.println`。"

代码块设置如下：

```java
public class Test { //line 1
    public static void main(String[] args) { //line 2
        System.out.println("Test"); //line 3
    } //line 4
} //line 5
```

新术语和重要单词以粗体显示。例如，屏幕上看到的单词，例如菜单或对话框中的单词，会在文本中显示为这样："右键单击**src**文件夹，然后选择**新建** | **类**。"

### 安装代码包

从 GitHub 存储库下载该书的代码包，并将其复制到您安装了 IntelliJ 的文件夹中。

### 其他资源

该书的代码包也托管在 GitHub 上：https://github.com/TrainingByPackt/Java-Fundamentals。

我们还有其他代码包，来自我们丰富的图书和视频目录，可在 https://github.com/PacktPublishing/ 上找到。快去看看吧！


# 第一章：*第一章*

# 介绍 Java

## 学习目标

在本课结束时，你将能够：

+   描述 Java 生态系统的工作

+   编写简单的 Java 程序

+   从用户那里读取输入

+   利用 java.util 包中的类

## 介绍

在这第一课中，我们开始学习 Java。如果你是从其他编程语言的背景下来学习 Java，你可能知道 Java 是一种用于编程计算机的语言。但 Java 不仅仅是如此。它不仅仅是一种无处不在的非常流行和成功的语言，它还是一系列技术。除了语言之外，它还包括一个非常丰富的生态系统，并且有一个充满活力的社区，致力于使生态系统尽可能动态。

## Java 生态系统

Java 生态系统的三个最基本部分是**Java 虚拟机（JVM）**，**Java 运行时环境（JRE）**和**Java 开发工具包（JDK）**，它们是 Java 实现提供的*标准*部分。

![图 1.1：Java 生态系统的表示](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-fund/img/C09581_01_01.jpg)

###### 图 1.1：Java 生态系统的表示

每个 Java 程序都在**JVM**的控制下运行。每次运行 Java 程序时，都会创建一个 JVM 实例。它为正在运行的 Java 程序提供安全性和隔离。它防止代码运行与系统中的其他程序发生冲突。它的工作原理类似于一个非严格的沙箱，使其可以安全地提供资源，即使在敌对环境（如互联网）中，但允许与其运行的计算机进行互操作。简单来说，JVM 就像一个*计算机内的计算机*，专门用于运行 Java 程序。

#### 注意

服务器通常同时执行许多 JVM。

在 Java 技术的*标准*层次结构中是`java`命令）。它包括所有基本的 Java 类（运行时）以及与主机系统交互的库（如字体管理，与图形系统通信，播放声音的能力以及在浏览器中执行 Java 小程序的插件）和实用程序（如 Nashorn JavaScript 解释器和 keytool 加密操作工具）。如前所述，JRE 包括 JVM。

在 Java 技术的顶层是`javac`。JDK 还包括许多辅助工具，如 Java 反汇编器（`javap`），用于创建 Java 应用程序包的实用程序（`jar`），从源代码生成文档的系统（`javadoc`）等等。JDK 是 JRE 的超集，这意味着如果你有 JDK，那么你也有 JRE（和 JVM）。

但这三个部分并不是 Java 的全部。Java 的生态系统包括社区的大量参与，这是该平台受欢迎的原因之一。

#### 注意

对 GitHub 上顶级 Java 项目使用的最流行的 Java 库进行的研究（根据 2016 年和 2017 年的重复研究）显示，JUnit，Mockito，Google 的 Guava，日志库（log4j，sl4j）以及所有 Apache Commons（Commons IO，Commons Lang，Commons Math 等）都标志着它们的存在，还有连接到数据库的库，用于数据分析和机器学习的库，分布式计算等几乎你能想象到的任何其他用途。换句话说，几乎任何你想编写程序的用途都有现有的工具库来帮助你完成任务。

除了扩展 Java 标准发行版功能的众多库之外，还有大量工具可以自动化构建（例如 Apache Ant，Apache Maven 和 Gradle），自动化测试，分发和持续集成/交付程序（例如 Jenkins 和 Apache Continuum），以及更多其他工具。

## 我们的第一个 Java 应用程序

正如我们之前简要提到的，Java 中的程序是用源代码（即普通文本，人类可读文件）编写的，这些源代码由编译器（在 Java 的情况下是`javac`）处理，以生成包含 Java 字节码的类文件。包含 Java 字节码的类文件，然后被提供给一个名为 java 的程序，其中包含执行我们编写的程序的 Java 解释器/JVM：

![图 1.2：Java 编译过程](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-fund/img/C09581_01_02.jpg)

###### 图 1.2：Java 编译过程

### 简单 Java 程序的语法

像所有编程语言一样，Java 中的源代码必须遵循特定的语法。只有这样，程序才能编译并提供准确的结果。由于 Java 是一种面向对象的编程语言，Java 中的所有内容都包含在类中。一个简单的 Java 程序看起来类似于这样：

```java
public class Test { //line 1
    public static void main(String[] args) { //line 2
        System.out.println("Test"); //line 3
    } //line 4
} //line 5
```

每个 java 程序文件的名称应与包含`main()`的类的名称相同。这是 Java 程序的入口点。

因此，只有当这些指令存储在名为`Test.java`的文件中时，前面的程序才会编译并运行而不会出现任何错误。

Java 的另一个关键特性是它区分大小写。这意味着`System.out.Println`会抛出错误，因为它的大小写没有正确。正确的指令应该是`System.out.println`。

`main()`应该始终声明如示例所示。这是因为，如果`main()`不是一个`public`方法，编译器将无法访问它，java 程序将无法运行。`main()`是静态的原因是因为我们不使用任何对象来调用它，就像你对 Java 中的所有其他常规方法一样。

#### 注意

我们将在本书的后面讨论这些`public`和`static`关键字。

注释用于提供一些额外的信息。Java 编译器会忽略这些注释。

单行注释用`//`表示，多行注释用`/* */`表示。

### 练习 1：一个简单的 Hello World 程序

1.  右键单击`src`文件夹，选择**新建** | **类**。

1.  输入`HelloWorld`作为类名，然后点击**确定**。

1.  在类中输入以下代码：

```java
public class HelloWorld{    
public static void main(String[] args) {  // line 2
        System.out.println("Hello, world!");  // line 3
    }
}
```

1.  通过点击**运行** | **运行“Main”**来运行程序。

程序的输出应该如下所示：

```java
Hello World!
```

### 练习 2：执行简单数学运算的简单程序

1.  右键单击`src`文件夹，选择**新建** | **类**。

1.  输入`ArithmeticOperations`作为类名，然后点击**确定**。

1.  用以下代码替换此文件夹中的代码：

```java
public class ArithmeticOperations {
    public static void main(String[] args) {
            System.out.println(4 + 5);
            System.out.println(4 * 5);
            System.out.println(4 / 5);
            System.out.println(9 / 2);
    }
}
```

1.  运行主程序。

输出应该如下所示：

```java
9
20
0
4
```

在 Java 中，当您将一个整数（例如 4）除以另一个整数（例如 5）时，结果总是一个整数（除非您另有指示）。在前面的情况下，不要惊讶地看到 4/5 的结果是 0，因为这是 4 除以 5 的商（您可以使用%而不是除法线来获得除法的余数）。

要获得 0.8 的结果，您必须指示除法是浮点除法，而不是整数除法。您可以使用以下行来实现：

```java
System.out.println(4.0 / 5);
```

是的，这意味着，像大多数编程语言一样，Java 中有多种类型的数字。

### 练习 3：显示非 ASCII 字符

1.  右键单击`src`文件夹，选择**新建** | **类**。

1.  输入`ArithmeticOperations`作为类名，然后点击**确定**。

1.  用以下代码替换此文件夹中的代码：

```java
public class HelloNonASCIIWorld {
    public static void main(String[] args) {
            System.out.println("Non-ASCII characters: ☺");
            System.out.println("∀x ∈ ℝ: ⌈x⌉ = −⌊−x⌋");
            System.out.println("π ≅ " + 3.1415926535); // + is used to concatenate 
    }
}
```

1.  运行主程序。

程序的输出应该如下所示：

```java
Non-ASCII characters: ☺
∀x ∈ ℝ: ⌈x⌉ = −⌊−x⌋
π ≅ 3.1415926535
```

### 活动 1：打印简单算术运算的结果

要编写一个打印任意两个值的和和乘积的 java 程序，请执行以下步骤：

1.  创建一个新类。

1.  在`main()`中，打印一句描述您将执行的值的操作以及结果。

1.  运行主程序。您的输出应该类似于以下内容：

```java
The sum of 3 + 4 is 7
The product of 3 + 4 is 12
```

#### 注意

此活动的解决方案可以在 304 页找到。

### 从用户那里获取输入

我们之前学习过一个创建输出的程序。现在，我们要学习一个补充性的程序：一个从用户那里获取输入，以便程序可以根据用户给程序的内容来工作：

```java
import java.io.IOException; // line 1
public class ReadInput { // line 2
    public static void main(String[] args) throws IOException { // line 3
        System.out.println("Enter your first byte");
        int inByte = System.in.read(); // line 4
        System.out.println("The first byte that you typed: " + (char) inByte); // line 5
        System.out.printf("%s: %c.%n", "The first byte that you typed", inByte); // line 6
    } // line 7
} // line 8
```

现在，我们必须剖析我们的新程序的结构，即具有公共类`ReadInput`的程序。你可能注意到它有更多的行，而且显然更复杂，但不要担心：在合适的时候，每一个细节都会被揭示出来（以其全部、光辉的深度）。但是，现在，一个更简单的解释就足够了，因为我们不想失去对主要内容的关注，即从用户那里获取输入。

首先，在第 1 行，我们使用了`import`关键字，这是我们之前没有见过的。所有的 Java 代码都是以分层方式组织的，有许多包（我们稍后会更详细地讨论包，包括如何创建自己的包）。

这里，层次结构意味着“像树一样组织”，类似于家谱。在程序的第 1 行，`import`这个词简单地意味着我们将使用`java.io.Exception`包中组织的方法或类。

在第 2 行，我们像以前一样创建了一个名为`ReadInput`的新公共类，没有任何意外。正如预期的那样，这个程序的源代码必须在一个名为`ReadInput.java`的源文件中。

在第 3 行，我们开始定义我们的`main`方法，但是这次在括号后面加了几个词。新词是`throws IOException`。为什么需要这个呢？

简单的解释是：“否则，程序将无法编译。”更长的解释是：“因为当我们从用户那里读取输入时，可能会出现错误，Java 语言强制我们告诉编译器关于程序在执行过程中可能遇到的一些错误。”

另外，第 3 行是需要第 1 行的`import`的原因：`IOException`是一个特殊的类，位于`java.io.Exception`层次结构之下。

第 5 行是真正行动开始的地方：我们定义了一个名为`inByte`（缩写为“将要输入的字节”）的变量，它将包含`System.in.read`方法的结果。

`System.in.read`方法在执行时，将从标准输入（通常是键盘，正如我们已经讨论过的）中取出第一个字节（仅一个），并将其作为答案返回给执行它的人（在这种情况下，就是我们，在第 5 行）。我们将这个结果存储在`inByte`变量中，并继续执行程序。

在第 6 行，我们打印（到标准输出）一条消息，说明我们读取了什么字节，使用了调用`System.out.println`方法的标准方式。

注意，为了打印字节（而不是代表计算机字符的内部数字），我们必须使用以下形式的结构：

+   一个开括号

+   单词`char`

+   一个闭括号

我们在名为`inByte`的变量之前使用了这个。这个结构被称为类型转换，将在接下来的课程中更详细地解释。

在第 7 行，我们使用了另一种方式将相同的消息打印到标准输出。这是为了向你展示有多少任务可以以不止一种方式完成，以及“没有单一正确”的方式。在这里，我们使用了`System.out.println`函数。

其余的行只是关闭了`main`方法定义和`ReadInput`类的大括号。

`System.out.printf`的一些主要格式字符串列在下表中：

![表 1.1：格式字符串及其含义](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-fund/img/C09581_Table_01_01.jpg)

###### 表 1.1：格式字符串及其含义

还有许多其他格式化字符串和许多变量，你可以在 Oracle 的网站上找到完整的规范。

我们将看到一些其他常见（修改过的）格式化字符串，例如%.2f（指示函数打印小数点后恰好两位小数的浮点数，例如 2.57 或-123.45）和%03d（指示函数打印至少三位数的整数，可能左侧填充 0，例如 001 或 123 或 27204）。

### 练习 4：从用户那里读取值并执行操作

从用户那里读取两个数字并打印它们的乘积，执行以下步骤：

1.  右键单击`src`文件夹，然后选择**新建** | **类**。

1.  输入`ProductOfNos`作为类名，然后单击**确定**。

1.  导入`java.io.IOException`包：

```java
import java.io.IOException;
```

1.  在`main()`中输入以下代码以读取整数：

```java
public class ProductOfNos{
public static void main(String[] args){
System.out.println("Enter the first number");
int var1 = Integer.parseInt(System.console().readLine());
System.out.println("Enter the Second number");
int var2 = Integer.parseInt(System.console().readLine());
```

1.  输入以下代码以显示两个变量的乘积：

```java
System.out.printf("The product of the two numbers is %d", (var1 * var2));
}
}
```

1.  运行程序。您应该看到类似于以下内容的输出：

```java
Enter the first number
10
Enter the Second number
20
The product of the two numbers is 200
```

干得好，这是你的第一个 Java 程序。

## 包

包是 Java 中的命名空间，可用于在具有相同名称的多个类时避免名称冲突。

例如，我们可能有由 Sam 开发的名为`Student`的多个类，另一个类由 David 开发的同名类。如果我们需要在代码中使用它们，我们需要区分这两个类。我们使用包将这两个类放入两个不同的命名空间。

例如，我们可能有两个类在两个包中：

+   `sam.Student`

+   `david.Student`

这两个包在文件资源管理器中如下所示：

![图 1.3：文件资源管理器中 sam.Student 和 david.Student 包的屏幕截图](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-fund/img/C09581_01_03.jpg)

###### 图 1.3：文件资源管理器中 sam.Student 和 david.Student 包的屏幕截图

所有对 Java 语言基本的类都属于`java.lang`包。Java 中包含实用类的所有类，例如集合类、本地化类和时间实用程序类，都属于`java.util`包。

作为程序员，您可以创建和使用自己的包。

### 使用包时需要遵循的规则

在使用包时需要考虑一些规则：

+   包应该用小写字母编写

+   为了避免名称冲突，包名应该是公司的反向域。例如，如果公司域是`example.com`，那么包名应该是`com.example`。因此，如果我们在该包中有一个`Student`类，可以使用`com.example.Student`访问该类。

+   包名应该对应文件夹名。对于前面的例子，文件夹结构将如下所示：![图 1.4：文件资源管理器中的文件夹结构的屏幕截图](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-fund/img/C09581_01_04.jpg)

###### 图 1.4：文件资源管理器中的文件夹结构的屏幕截图

要在代码中使用包中的类，您需要在 Java 文件的顶部导入该类。例如，要使用 Student 类，您可以按如下方式导入它：

```java
import com.example.Student;
public class MyClass {
}
```

`Scanner`是`java.util`包中的一个有用的类。这是一种输入类型（例如 int 或字符串）的简单方法。正如我们在早期的练习中看到的，包使用`nextInt()`以以下语法输入整数：

```java
sc = new Scanner(System.in);
int x =  sc.nextIn()
```

### 活动 2：从用户那里读取值并使用 Scanner 类执行操作

从用户那里读取两个数字并打印它们的和，执行以下步骤：

1.  创建一个新类，并将`ReadScanner`作为类名输入

1.  导入`java.util.Scanner`包

1.  在`main()`中使用`System.out.print`要求用户输入两个变量`a`和`b`的数字。

1.  使用`System.out.println`输出两个数字的和。

1.  运行主程序。

输出应该类似于这样：

```java
Enter a number: 12
Enter 2nd number: 23
The sum is 35\.  
```

#### 注意

此活动的解决方案可在 304 页找到。

### 活动 3：计算金融工具的百分比增长或减少

用户期望看到股票和外汇等金融工具的日增长或减少百分比。我们将要求用户输入股票代码，第一天的股票价值，第二天相同股票的价值，计算百分比变化并以格式良好的方式打印出来。为了实现这一点，执行以下步骤：

1.  创建一个新类，并输入`StockChangeCalculator`作为类名

1.  导入`java.util.Scanner`包：

1.  在`main()`中使用`System.out.print`询问用户股票的`symbol`，然后是股票的`day1`和`day2`值。

1.  计算`percentChange`值。

1.  使用`System.out.println`输出符号和带有两位小数的百分比变化。

1.  运行主程序。

输出应类似于：

```java
Enter the stock symbol: AAPL
Enter AAPL's day 1 value: 100
Enter AAPL's day 2 value: 91.5
AAPL has changed -8.50% in one day.
```

#### 注意

此活动的解决方案可在 305 页找到。

## 摘要

本课程涵盖了 Java 的基础知识。我们看到了 Java 程序的一些基本特性，以及如何在控制台上显示或打印消息。我们还看到了如何使用输入控制台读取值。我们还研究了可以用来分组类的包，并看到了`java.util`包中`Scanner`的一个示例。

在下一课中，我们将更多地了解值是如何存储的，以及我们可以在 Java 程序中使用的不同值。


# 第二章：*第二章*

# 变量、数据类型和运算符

## 学习目标

通过本课程结束时，您将能够：

+   在 Java 中使用原始数据类型

+   在 Java 中使用引用类型

+   实现简单的算术运算

+   使用类型转换方法

+   输入和输出各种数据类型

## 介绍

在上一课中，我们介绍了 Java 生态系统以及开发 Java 程序所需的工具。在本课中，我们将通过查看语言中的基本概念，如变量、数据类型和操作，开始我们的 Java 语言之旅。

## 变量和数据类型

计算机编程中的一个基本概念是内存，用于在计算机中存储信息。计算机使用位作为可以存储的最小信息单元。一个位要么是 1，要么是 0。我们可以将 8 位分组，得到所谓的“字节”。因为位非常小，所以在编程时通常使用字节作为最小单位。当我们编写程序时，我们实际上是从某个内存位置获取一些位，对它们进行一些操作，然后将结果写回到内存位置。

我们需要一种方法来在计算机的内存中存储不同类型的数据，并告诉计算机在哪个内存位置存储了什么类型的数据。

数据类型是我们指定需要在给定内存位置存储的数据类型和大小的一种方式。数据类型的一个示例是整数、字符或字符串。广义上讲，Java 中可用的数据类型可以分为以下类型：

+   原始数据类型

+   参考数据类型

**原始类型**是基本类型，即它们不能被修改。它们是不可分割的，并且构成了形成复杂类型的基础。Java 中有八种原始数据类型，我们将在后续章节中深入讨论：

+   byte

+   short

+   int

+   long

+   char

+   float

+   double

+   boolean

**引用类型**是指引用存储在特定内存位置的数据的类型。它们本身不保存数据，而是保存数据的地址。对象，稍后将介绍，是引用类型的示例：

![图 2.1：引用类型的表示](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-fund/img/C09581_Figure_02_01.jpg)

###### 图 2.1：引用类型的表示

所有数据类型都具有以下共同属性：

+   它们与一个值相关联。

+   它们支持对它们所持有的值进行某些操作。

+   它们在内存中占据一定数量的位。

例如，整数可以具有值，如 100，支持加法和减法等操作，并且在计算机内存中使用 32 位表示。

### 变量

每当我们想要处理特定的数据类型时，我们必须创建该数据类型的变量。例如，要创建一个保存您年龄的整数，您可以使用以下行：

```java
int age;
```

在这里，我们说变量名为`age`，是一个整数。整数只能保存范围在-2,147,483,648 到 2,147,483,647 之间的值。尝试保存范围外的值将导致错误。然后，我们可以给`age`变量赋值，如下所示：

```java
age = 30;
```

`age`变量现在保存了值 30。单词`age`称为**标识符**，用于引用存储值 30 的内存位置。标识符是一个可读的单词，用于引用值的内存地址。

您可以使用自己选择的单词作为标识符来引用相同的内存地址。例如，我们可以将其写成如下形式：

```java
int myAge ;
myAge = 30;
```

以下是前面代码片段的图形表示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-fund/img/C09581_Figure_02_02.jpg)

###### 图 2.2：内存地址中年龄的表示

尽管我们可以使用任何单词作为标识符，但 Java 对构成有效标识符的规则有一些规定。以下是创建标识符名称时需要遵守的一些规则：

+   标识符应以字母、`_`或`$`开头。不能以数字开头。

+   标识符只能包含有效的 Unicode 字符和数字。

+   标识符之间不能有空格。

+   标识符可以是任意长度。

+   标识符不能是保留关键字。

+   标识符不能包含算术符号，如+或-。

+   标识符是区分大小写的，例如，age 和 Age 不是相同的标识符。

### 保留关键字

Java 还包含内置的保留字，不能用作标识符。这些单词在语言中有特殊的含义。

现在让我们讨论 Java 中的原始数据类型。正如我们之前所说，Java 有 8 种原始数据类型，我们将详细了解。

## 整数数据类型

整数类型是具有整数值的类型。这些是 int、long、short、byte 和 char。

### 整数数据类型

`int`数据类型用于表示整数。整数是-2,147,483,648 到 2,147,483,647 范围内的 32 位数字。整数的示例是 0、1、300、500、389 230、1,345,543、-500、-324,145 等。例如，要创建一个`int`变量来保存值 5，我们写如下：

```java
int num = 5;
```

`num`变量现在是一个值为 5 的`int`。我们还可以在一行中声明多个相同类型的变量：

```java
int num1, num2, num3, num4, num5;
```

在这里，我们创建了五个变量，全部为`int`类型，并初始化为零。我们还可以将所有变量初始化为特定值，如下所示：

```java
int num1 = 1, num2 = 2, num3 = 3, num4 = 4, num5 = 5;
```

除了以十进制格式表示整数外，我们还可以以八进制、十六进制和二进制格式表示整数：

+   要以十六进制格式表示，我们从 0x 或 0X 开始`int`，即零后面跟着 x 或 X。数字的长度必须至少为 2 位。十六进制数使用 16 个数字（0-9 和 A-F）。例如，要以十六进制表示 30，我们将使用以下代码：

```java
int hex_num = 0X1E;
```

打印出的数字将按预期输出 30。要在十六进制中保存值为 501 的整数，我们将写如下：

```java
int hex_num1 = 0x1F5;
```

+   要以八进制格式表示，我们从零开始`int`，并且必须至少有 2 位数字。八进制数有 8 位数字。例如，要以八进制表示 15，我们将执行以下操作：

```java
int oct_num = 017;
```

尝试打印前面的变量将输出 15。要表示 501 的八进制，我们将执行以下操作：

```java
int oct_num1 = 0765;
```

+   要以二进制格式表示，我们从 0b 或 0B 开始`int`，即零后面跟着 b 或 B。大小写不重要。例如，要在二进制中保存值 100，我们将执行以下操作：

```java
int bin_num = 0b1100100;
```

+   要在二进制中保存数字 999，我们将执行以下操作：

```java
int bin_num1 = 0B1111100111;
```

作为表示整数的前述四种格式的总结，所有以下变量都保存值为 117：

```java
int num = 117;
int hex_num = 0x75;
int oct_num = 0165;
int bin_num = 0b1110101;
```

### 长数据类型

`long`是`int`的 64 位等价。它们保存在-9,223,372,036,854,775,808 到 9,223,372,036,854,775,807 范围内的数字。长类型的数字称为长文字，并以 L 结尾。例如，要声明值为 200 的长，我们将执行以下操作：

```java
long long_num = 200L;
```

要声明值为 8 的`long`，我们将执行以下操作：

```java
long long_num = 8L;
```

由于整数是 32 位的，因此位于 long 范围内，我们可以将`int`转换为`long`。

## 类型转换

要将值为 23 的`int`转换为长文字，我们需要进行所谓的**类型转换**：

```java
int num_int = 23;
long num_long = (long)num_int;
```

在第二行，我们通过使用表示法`(long)num_int`将`int`类型的`num_int`转换为长文字。这被称为`强制转换`。强制转换是将一种数据类型转换为另一种数据类型的过程。虽然我们可以将 long 转换为`int`，但请记住，数字可能超出`int`范围，如果无法适应 int，一些数字将被截断。

与`int`一样，`long`也可以是八进制、十六进制和二进制的，如下所示：

```java
long num = 117L;
long hex_num = 0x75L;
long oct_num = 0165L;
long bin_num = 0b1110101L;
```

### 练习 5：类型转换

重要的是要将一种类型转换为另一种类型。在这个练习中，我们将把一个整数转换为浮点数：

1.  导入`Scanner`并创建一个公共类：

```java
import java.util.Scanner;

public class Main

{ 
    static Scanner sc = new Scanner(System.in);
    public static void main(String[] args) 
```

1.  输入一个整数作为输入：

```java
{ 
    System.out.println("Enter a Number: ");
    int num1 = sc.nextInt();
```

1.  打印出整数：

```java
System.out.println("Entered value is: " + num1);
```

1.  将整数转换为浮点数：

```java
float fl1 = num1;
```

1.  打印出浮点数：

```java
System.out.print("Entered value as a floating point variable is: " + fl1);

    } 

}
```

### 字节数据类型

`byte`是一个 8 位数字，可以容纳范围在-128 到 127 之间的值。`byte`是 Java 中最小的原始数据类型，可以用来保存二进制值。要给`byte`赋值，它必须在-128 到 127 的范围内，否则编译器会报错：

```java
byte num_byte = -32;
byte num_byte1 = 111;
```

你也可以将`int`转换为`byte`，就像我们对`long`所做的那样：

```java
int num_int = 23;
byte num_byte = (byte)num_int;
```

除了强制转换，我们还可以将`byte`赋给`int`：

```java
byte num_byte = -32;
int num_int = num_byte;
```

然而，我们不能直接将`int`赋给`byte`，必须进行强制转换。当你尝试运行以下代码时，会引发错误：

```java
int num_int = 23;
byte num_byte = num_int;
```

这是因为整数可以超出字节范围（-128 到 127），因此会丢失一些精度。Java 不允许你将超出范围的类型赋给较小范围的类型。你必须进行强制转换，这样溢出的位将被忽略。

### short 数据类型

`short`是一个 16 位的数据类型，可以容纳范围在-32,768 到 32,767 之间的数字。要给`short`变量赋值，确保它在指定的范围内，否则会抛出错误：

```java
short num = 13000;
short num_short = -18979;
```

你可以把`byte`赋给`short`，因为 byte 的所有值都在 short 的范围内。然而，反过来会报错，就像用`byte`和`int`解释的那样。要把`int`转换成`short`，你必须进行强制转换以避免编译错误。这也适用于将`long`转换为`short`：

```java
short num = 13000;
byte num_byte = 19;
num = num_byte; //OK
int num1 = 10;
short s = num1; //Error
long num_long = 200L;
s = (short)num_long; //OK
```

### 布尔数据类型

`boolean`是一个真或假的值：

```java
boolean finished = true;
boolean hungry = false;
```

#### 注意

一些语言，比如 C 和 C++，允许布尔值为 true 时取值为 1，false 时取值为 0。Java 不允许你将 1 或 0 赋给布尔值，这将引发编译时错误。

### char 数据类型

`char`数据类型用于保存单个字符。字符用单引号括起来。字符的例子有'a'、'b'、'z'和'5'。Char 类型是 16 位的，不能为负数。Char 类型本质上是从 0 到 65535 的整数，用来表示 Unicode 字符。声明 char 的示例如下：

```java
char a = 'a';
char b = 'b';
char c = 'c';
char five = '5';
```

请注意，字符要用单引号括起来，而不是双引号。用双引号括起来的`char`会变成`string`。`string`是一个或多个字符的集合。一个字符串的例子是"Hello World"：

```java
String hello = "Hello World";
```

用双引号括起来的`char`会引发错误，因为编译器将双引号解释为`string`，而不是 char：

```java
char hello = "Hello World"; //ERROR
```

同样，用单引号括起来的多个字符会引发编译错误，因为字符应该只有一个字符：

```java
String hello = 'Hello World'; //ERROR
```

除了用来保存单个字符，字符也可以用来保存转义字符。转义字符是具有特殊用途的特殊字符。它们由反斜杠后跟一个字符组成，并用单引号括起来。有 8 个预定义的转义字符，如下表所示，以及它们的用途：

![表 2.1：转义字符及其用法的表示](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-fund/img/C09581_Table_02_01.jpg)

###### 表 2.1：转义字符及其用法的表示

假设你写了下面这样一行：

```java
char nl = '\n';
```

`char`保存了一个换行符，如果你尝试将其打印到控制台，它会跳到下一行。

如果你打印`'\t'`，输出中会出现一个制表符。

```java
char tb = '\t';
```

一个'\\'会在输出中打印一个反斜杠。

你可以使用转义字符来根据你想要的输出格式化字符串。例如，让我们看看下面这行：

```java
String hello_world = "Hello \n World";
```

以下是输出：

```java
Hello 
 World
```

这是因为转义字符'`\n`'在`Hello`和`World`之间引入了一个新行。

此外，字符还可以使用 Unicode 转义字符'`\u`'来表示 Unicode。Unicode 是一种国际编码标准，其中一个字符被分配一个数值，可以在任何平台上使用。Unicode 旨在支持世界上所有可用的语言，这与 ASCII 相反。

### 浮点数据类型

浮点数据类型是具有小数部分的数字。例如 3.2、5.681 和 0.9734。Java 有两种数据类型来表示带有小数部分的类型：

+   `float`

+   `double`

浮点类型使用一种称为 IEEE 754 浮点标准的特殊标准表示。这个标准是由电气和电子工程师学会（IEEE）制定的，旨在使低级计算机中浮点类型的表示统一。请记住，浮点类型通常是近似值。当我们说 5.01 时，这个数字必须以二进制格式表示，表示通常是对实际数字的近似。在处理需要测量到微小数字级别的高性能程序时，了解浮点类型在硬件级别的表示方式以避免精度损失变得至关重要。

浮点类型有两种表示形式：十进制格式和科学计数法。

十进制格式是我们通常使用的正常格式，例如 5.4、0.0004 或 23,423.67。

科学计数法是使用字母 e 或 E 表示 10 的幂。例如，科学计数法中的 0.0004 是 4E-4 或 4e-4，类似于 4 x 10-4。科学计数法中的 23,423.67 将是 2.342367E4 或 2.342367e4，类似于 2.342367 x 104。

### 浮点数据类型

`float`用于保存 32 位小数，范围为 1.4 x 10 -45 到 3.4 x 10 38。也就是说，`float`可以保存的最小数字是 1.4 x 10 -45，最大数字是 3.4 x 10 38。浮点数后面跟着一个字母 f 或 F 表示它们是`float`类型。浮点数的示例如下：

```java
float a = 1.0f;
float b = 0.0002445f;
float c = 93647.6335567f;
```

浮点数也可以用科学计数法表示，如下所示：

```java
float a = 1E0f;
float b = 2.445E-4f;
float c = 9.36476335567E+4f;
```

Java 还有一个名为 Float 的类，可以封装浮点数并提供一些有用的功能。例如，要知道你的环境中可用的最大`float`数和最小`float`数，可以调用以下方法：

```java
float max = Float.MAX_VALUE;
float min = Float.MIN_VALUE;
```

当除以零时，Float 类还有值表示正无穷和负无穷：

```java
float max_inf = Float.POSITIVE_INFINITY;
float min_inf = Float.NEGATIVE_INFINITY;
```

浮点数支持两种零：-0.0f 和+0.0f。正如我们已经说过的，浮点类型在内存中表示为近似值，因此即使是零也不是绝对零。这就是为什么我们有两个零的原因。当一个数字被正零除时，我们得到`Float.POSITIVE_INFINITY`，当一个数字被负零除时，我们得到`Float.NEGATIVE_INFINITY`。

Float 类还有一个常量`NaN`，表示不是`float`类型的数字：

```java
float nan = Float.NaN;
```

与我们讨论过的整数类型一样，我们可以将`int`、`byte`、`short`、`long`和 char 赋值给 float，但不能反过来，除非我们进行转换。

#### 注意

将整数转换为浮点数，然后再转换回`int`，并不总是会得到原始数字。在进行`int`和`float`之间的转换时要小心。

### 双精度数据类型

`double`保存 64 位带小数部分的数字。也就是说，范围为 4.9 x 10e -324 到 1.7 x 10e 308。双精度用于保存比浮点数更大的数字。它们以 d 或 D 结尾表示。但是，在 Java 中，默认情况下，任何带小数部分的数字都是`double`，因此通常不需要在末尾添加 d 或 D。双精度的示例如下：

```java
double d1  = 4.452345;
double d2 = 3.142;
double d3 = 0.123456;
double d4 = 0.000999;
```

与浮点数一样，双精度也可以用科学计数法表示：

```java
double d1  = 4.452345E0;
double d2 = 3.142E0;
double d3 = 1.23456E-1;
double d4 = 9.99E-4;
```

你可能已经猜到了，Java 还提供了一个名为`Double`的类，其中包含一些有用的常量，如下所示：

```java
double max = Double.MAX_VALUE;
double min = Double.MIN_NORMAL;
double max_inf = Double.POSITIVE_INFINITY;
double min_inf = Double.NEGATIVE_INFINITY;
double nan = Double.NaN;
```

同样，我们可以将整数类型和`float`赋值给`double`，但不能反过来，除非我们进行转换。以下是一些允许和一些禁止的示例操作：

```java
int num = 100;
double d1 = num;
float f1 = 0.34f;
double d2 = f1;
double d3 = 'A'; //Assigns 65.0 to d3
int num  = 200;
double d3 = 3.142;
num = d3; //ERROR: We must cast
num = (int)d3; //OK
```

### 活动 4：输入学生信息并输出 ID

在任何开发环境中，存储和输出变量都是基础。在这个活动中，你将创建一个程序，要求学生输入他们的数据，然后输出一个简单的 ID 卡。该程序将使用整数和字符串以及`java.util`包中的 scanner 类。

以下活动使用字符串变量和整数变量输入关于学生的信息，然后打印出来。

1.  导入 scanner 包并创建一个新的类。

1.  导入学生的名字作为字符串。

1.  导入大学名称作为字符串。

1.  导入学生的年龄作为整数。

1.  使用`System.out.println`打印出学生的详细信息。

1.  运行程序后，输出应该类似于这样：

```java
Here is your ID 
*********************************
Name: John Winston
University: Liverpool University
Age: 19
*********************************
```

#### 注意

这个活动的解决方案可以在第 306 页找到。

### 活动 5：计算满箱水果的数量

约翰是一个桃子种植者。他从树上摘桃子，把它们放进水果箱里然后运输。如果一个水果箱装满了 20 个桃子，他就可以运输。如果他的桃子少于 20 个，他就必须摘更多的桃子，这样他就可以装满一个水果箱，然后运输。

我们想通过计算他能够运输的水果箱的数量以及留下的桃子的数量来帮助约翰，给出他能够摘的桃子的数量。为了实现这一点，执行以下步骤：

1.  创建一个新的类，并输入`PeachCalculator`作为类名

1.  导入`java.util.Scanner`包：

1.  在`main()`中使用`System.out.print`询问用户`numberOfPeaches`。

1.  计算`numberOfFullBoxes`和`numberOfPeachesLeft`的值。提示：使用整数除法。

1.  使用`System.out.println`输出这两个值。

1.  运行主程序。

输出应该类似于：

```java
Enter the number of peaches picked: 55
We have 2 full boxes and 15 peaches left.
```

#### 注意

这个活动的解决方案可以在第 307 页找到。

## 摘要

在这节课中，我们学习了在 Java 中使用基本数据类型和引用数据类型，以及对数据进行简单的算术运算。我们学会了如何将数据类型从一种类型转换为另一种类型。然后我们看到了如何使用浮点数据类型。

在下一节课中，我们将学习条件语句和循环结构。


# 第三章：*第三章*

# 控制流

## 学习目标

通过本课程结束时，你将能够：

+   使用 Java 中的`if`和`else`语句控制执行流程

+   使用 Java 中的 switch case 语句检查多个条件

+   利用 Java 中的循环结构编写简洁的代码来执行重复的操作

## 介绍

到目前为止，我们已经看过由 Java 编译器按顺序执行的一系列语句组成的程序。然而，在某些情况下，我们可能需要根据程序的当前状态执行操作。

考虑一下安装在 ATM 机中的软件的例子-它执行一系列操作，也就是说，当用户输入的 PIN 正确时，它允许交易发生。然而，当输入的 PIN 不正确时，软件执行另一组操作，也就是告知用户 PIN 不匹配，并要求用户重新输入 PIN。你会发现，几乎所有现实世界的程序中都存在依赖于值或阶段的这种逻辑结构。

也有时候，可能需要重复执行特定任务，也就是说，在特定时间段内，特定次数，或者直到满足条件为止。延续我们关于 ATM 机的例子，如果输入错误密码的次数超过三次，那么卡就会被锁定。

这些逻辑结构作为构建复杂 Java 程序的基本构件。本课程将深入探讨这些基本构件，可以分为以下两类：

+   条件语句

+   循环语句

## 条件语句

条件语句用于根据某些条件控制 Java 编译器的执行流程。这意味着我们根据某个值或程序的状态做出选择。Java 中可用的条件语句如下：

+   `if`语句

+   `if-else`语句

+   `else-if`语句

+   `switch`语句

### if 语句

if 语句测试一个条件，当条件为真时，执行 if 块中包含的代码。如果条件不为真，则跳过块中的代码，执行从块后的行继续执行。

`if`语句的语法如下：

```java
if (condition) {
//actions to be performed when the condition is true
}
```

考虑以下例子：

```java
int a = 9;
if (a < 10){
System.out.println("a is less than 10");
}
```

由于条件`a<10`为真，打印语句被执行。

我们也可以在`if`条件中检查多个值。考虑以下例子：

```java
if ((age > 50) && (age <= 70) && (age != 60)) {
System.out.println("age is above 50 but at most 70 excluding 60");
}
```

上述代码片段检查`age`的值是否超过 50，但最多为 70，不包括 60。

当`if`块中的语句只有一行时，我们不需要包括括号：

```java
if (color == 'Maroon' || color == 'Pink')
System.out.println("It is a shade of Red");
```

### else 语句

对于某些情况，如果`if`条件失败，我们需要执行不同的代码块。为此，我们可以使用`else`子句。这是可选的。

`if else`语句的语法如下：

```java
if (condition) {
//actions to be performed when the condition is true
}
else {
//actions to be performed when the condition is false
}
```

### 练习 6：实现简单的 if-else 语句

在这个练习中，我们将创建一个程序，根据空座位的数量来检查是否可以预订公交车票。完成以下步骤来实现：

1.  右键单击`src`文件夹，然后选择**新建** | **类**。

1.  输入`Booking`作为类名，然后点击**OK**。

1.  设置`main`方法：

```java
public class Booking{
public static void main(String[] args){
}
}
```

1.  初始化两个变量，一个用于空座位数量，另一个用于请求的票数：

```java
int seats = 3; // number of empty seats
int req_ticket = 4; // Request for tickets
```

1.  使用`if`条件检查所请求的票数是否小于或等于可用的空座位，并打印适当的消息：

```java
if( (req_ticket == seats) || (req_ticket < seats) ) {
     System.out.print("This booing can be accepted");
     }else
         System.out.print("This booking is rejected");
```

1.  运行程序。

你应该得到以下输出：

```java
This booking is rejected
```

### else-if 语句

当我们希望在评估`else`子句之前比较多个条件时，可以使用`else if`语句。

`else if`语句的语法如下：

```java
if (condition 1) {
//actions to be performed when condition 1 is true
}
else if (Condition 2) {
//actions to be performed when condition 2 is true
}
else if (Condition 3) {
//actions to be performed when condition 3 is true
}
…
…
else if (Condition n) {
//actions to be performed when condition n is true
}
else {
//actions to be performed when the condition is false
}
```

### 练习 7：实现 else-if 语句

我们正在构建一个电子商务应用程序，根据卖家和买家之间的距离计算交付费用。买家在我们的网站上购买物品并输入交付地址。根据距离，我们计算交付费用并显示给用户。在这个练习中，我们得到了以下表格，并需要编写一个程序来向用户输出交付费用：

![表 3.1：显示距离及其对应费用的表](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-fund/img/C09581_Table_03_01.jpg)

###### 表 3.1：显示距离及其对应费用的表

要做到这一点，请执行以下步骤：

1.  右键单击`src`文件夹，然后选择**新建** | **类**。

1.  输入`DeliveryFee`作为类名，然后单击**OK**。

1.  打开创建的类，然后创建主方法：

```java
public class DeliveryFee{
public static void main(String[] args){
}
}
```

1.  在`main`方法中，创建两个整数变量，一个称为`distance`，另一个称为`fee`。这两个变量将分别保存`distance`和交付费用。将`distance`初始化为 10，`fee`初始化为零：

```java
int distance = 10;
int fee = 0;
```

1.  创建一个`if`块来检查表中的第一个条件：

```java
if (distance > 0 && distance < 5){
   fee = 2;
}
```

这个`if`语句检查`distance`是否大于 0 但小于 5，并将交付`fee`设置为 2 美元。

1.  添加一个`else if`语句来检查表中的第二个条件，并将`fee`设置为 5 美元：

```java
else if (distance >= 5 && distance < 15){
   fee = 5;
}
```

1.  添加两个`else if`语句来检查表中的第三和第四个条件，如下面的代码所示：

```java
else if (distance >= 15 && distance < 25){
   fee = 10;
}else if (distance >= 25 && distance < 50){
   fee = 15;
}
```

1.  最后，添加一个`else`语句来匹配表中的最后一个条件，并设置适当的交付`fee`：

```java
else {
   fee = 20;
}
```

1.  打印出`fee`的值：

```java
System.out.println("Delivery Fee: " + fee);
```

1.  运行程序并观察输出：

```java
Delivery Fee: 5
```

### 嵌套的 if 语句

我们可以在其他`if`语句内部使用`if`语句。这种结构称为嵌套的`if`语句。我们首先评估外部条件，如果成功，然后评估第二个内部`if`语句，依此类推，直到所有`if`语句都完成：

```java
if (age > 20){

   if (height > 170){

       if (weight > 60){
           System.out.println("Welcome");
       }    
   }
}
```

我们可以嵌套任意多的语句，并且编译器将从顶部向下评估它们。

### switch case 语句

`switch case`语句是在相同的值进行相等比较时，执行多个`if` `else`语句的更简单更简洁的方法。以下是一个快速比较：

传统的`else if`语句如下所示：

```java
if(age == 10){
   discount = 300;
} else if (age == 20){
   discount = 200;
} else if (age == 30){
   discount = 100;
} else {
   discount = 50;
}
```

然而，使用`switch case`语句实现相同逻辑时，将如下所示：

```java
switch (age){
   case 10:
       discount = 300;
   case 20:
       discount = 200;
   case 30:
       discount = 100;
   default:
       discount = 50;
}
```

请注意，这段代码更易读。

要使用`switch`语句，首先需要使用关键字`switch`声明它，后跟括号中的条件。`case`语句用于检查这些条件。它们按顺序检查。

编译器将检查`age`的值与所有`case`进行匹配，如果找到匹配，那么将执行该`case`中的代码以及其后的所有`case`。例如，如果我们的`age`等于 10，将匹配第一个`case`，然后第二个`case`，第三个`case`和`default` `case`。如果所有其他情况都不匹配，则执行`default` `case`。例如，如果`age`不是 10、20 或 30，则折扣将设置为 50。它可以被解释为`if-else`语句中的`else`子句。`default` `case`是可选的，可以省略。

如果`age`等于 30，那么第三个`case`将被匹配并执行。由于`default` `case`是可选的，我们可以将其省略，执行将在第三个`case`之后结束。

大多数情况下，我们真正希望的是执行结束于匹配的`case`。我们希望如果匹配了第一个`case`，那么就执行该`case`中的代码，并忽略其余的情况。为了实现这一点，我们使用`break`语句告诉编译器继续在`switch`语句之外执行。以下是带有`break`语句的相同`switch case`：

```java
switch (age){
   case 10:
       discount = 300;
       break;
   case 20:
       discount = 200;
       break;
   case 30:
       discount = 100;
       break;
   default:
       discount = 50;
}
```

因为`default`是最后一个`case`，所以我们可以安全地忽略`break`语句，因为执行将在那里结束。

#### 注意：

在未来，另一个程序员添加额外的情况时，始终添加一个 break 语句是一个好的设计。

### 活动 6：使用条件控制执行流程

工厂每小时支付工人 10 美元。标准工作日是 8 小时，但工厂为额外的工作时间提供额外的补偿。它遵循的政策是计算工资如下：

+   如果一个人工作少于 8 小时-每小时* $10

+   如果一个人工作超过 8 小时但少于 12 小时-额外 20%的工资

+   超过 12 小时-额外的一天工资被记入

创建一个程序，根据工作小时数计算并显示工人赚取的工资。

为了满足这个要求，执行以下步骤：

1.  初始化两个变量和工作小时和工资的值。

1.  在`if`条件中，检查工人的工作小时是否低于所需小时。如果条件成立，则工资应为（工作小时* 10）。

1.  使用`else if`语句检查工作小时是否介于 8 小时和 12 小时之间。如果是这样，那么工资应该按照每小时 10 美元计算前 8 小时，剩下的小时应该按照每小时 12 美元计算。

1.  使用`else`块为默认的每天$160（额外的一天工资）。

1.  执行程序以观察输出。

#### 注意

此活动的解决方案可以在第 308 页找到。

### 活动 7：开发温度系统

在 Java 中编写一个程序，根据温度显示简单的消息。温度概括为以下三个部分：

+   高：在这种情况下，建议用户使用防晒霜

+   低：在这种情况下，建议用户穿外套

+   潮湿：在这种情况下，建议用户打开窗户

要做到这一点，执行以下步骤：

1.  声明两个字符串，`temp`和`weatherWarning`。

1.  用`High`、`Low`或`Humid`初始化`temp`。

1.  创建一个检查`temp`不同情况的 switch 语句。

1.  将变量`weatherWarning`初始化为每种温度情况的适当消息（`High`、`Low`、`Humid`）。

1.  在默认情况下，将`weatherWarning`初始化为“天气看起来不错。出去散步”。

1.  完成 switch 结构后，打印`weatherWarning`的值。

1.  运行程序以查看输出，应该类似于：

```java
Its cold outside, do not forget your coat.
```

#### 注意

此活动的解决方案可以在第 309 页找到。

## 循环结构

循环结构用于在满足条件的情况下多次执行特定操作。它们通常用于对列表项执行特定操作。例如，当我们想要找到从 1 到 100 所有数字的总和时。Java 支持以下循环结构：

+   `for`循环

+   `for each`循环

+   `while`循环

+   `do while`循环

### for 循环

`for`循环的语法如下：

```java
for( initialization ; condition ; expression) {
    //statements
}
```

初始化语句在`for`循环开始执行时执行。可以有多个表达式，用逗号分隔。所有表达式必须是相同类型的：

```java
for( int i  = 0, j = 0; i <= 9; i++)
```

`for`循环的条件部分必须评估为 true 或 false。如果没有表达式，则条件默认为 true。

在语句的每次迭代后执行表达式部分，只要条件为真。可以有多个用逗号分隔的表达式。

#### 注意

表达式必须是有效的 Java 表达式，即可以以分号终止的表达式。

以下是`for`循环的工作原理：

1.  首先，初始化被评估。

1.  然后，检查条件。如果条件为真，则执行`for`块中包含的语句。

1.  在执行语句后，执行表达式，然后再次检查条件。

1.  如果仍然不是 false，则再次执行语句，然后执行表达式，再次评估条件。

1.  这将重复，直到条件评估为 false。

1.  当条件求值为 false 时，`for`循环完成，循环后的代码部分被执行。

### 练习 8：实现一个简单的 for 循环

为了打印所有递增和递减的个位数，执行以下步骤：

1.  右键单击`src`文件夹，选择**新建** | **类**。

1.  输入`Looping`作为类名，然后点击**OK**。

1.  设置`main`方法：

```java
public class Looping
{
   public static void main(String[] args) {
   }
}
```

1.  实现一个`for`循环，初始化一个变量`i`为零，一个条件使得值保持在 10 以下，并且`i`应该在每次迭代中递增一个：

```java
System.out.println("Increasing order");
for( int i  = 0; i <= 9; i++)
System.out.println(i);
```

1.  实现另一个`for`循环，初始化一个变量`k`为 9，一个条件使得值保持在 0 以上，并且`k`应该在每次迭代中减少一个：

```java
System.out.println("Decreasing order");
for( int k  = 9; k >= 0; k--)
System.out.println(k);
```

输出：

```java
Increasing order 
0
1
2
3
4
5
6
7
8
9
Decreasing order
9
8
7
6
5
4
3
2
1
0
```

### 活动 8：实现 for 循环

约翰是一个桃农，他从树上摘桃子，把它们放进水果箱里然后运输。如果一个水果箱里装满了 20 个桃子，他就可以运输。如果他的桃子少于 20 个，他就必须摘更多的桃子，这样他就可以装满一个水果箱，然后运输。

我们想通过编写一个自动化软件来帮助约翰启动填充和运输箱子。我们从约翰那里得到桃子的数量，然后为每组 20 个桃子打印一条消息，并说明到目前为止已经运输了多少桃子。例如，对于第三个箱子，我们打印“到目前为止已经运输了 60 个桃子”。我们想用`for`循环来实现这一点。我们不需要担心剩下的桃子。为了实现这一点，执行以下步骤：

1.  创建一个新的类，输入`PeachBoxCounter`作为类名

1.  导入`java.util.Scanner`包：

1.  在`main()`中使用`System.out.print`询问用户`numberOfPeaches`。

1.  编写一个`for`循环，计算到目前为止运输的桃子数量。这从零开始，每次增加 20，直到剩下的桃子少于 20。

1.  在`for`循环中，打印到目前为止运输的桃子数量。

1.  运行主程序。

输出应该类似于：

```java
Enter the number of peaches picked: 42
shipped 0 peaches so far
shipped 20 peaches so far
shipped 40 peaches so far  
```

#### 注意

这个活动的解决方案可以在 310 页找到。

`for`循环的所有三个部分都是可选的。这意味着行`for( ; ;) `将提供任何错误。它只提供一个邀请循环。

这个`for`循环什么也不做，也不会终止。在`for`循环声明的变量在`for`循环的语句中是可用的。例如，在我们的第一个例子中，我们从语句部分打印了`i`的值，因为变量`i`是在`for`循环中声明的。然而，这个变量在`for`循环后不可用，并且可以自由声明。但是不能在`for`循环内再次声明：

```java
for (int i = 0; i <= 9; i++)
   int i  = 10;            //Error, i is already declared
```

`for`循环也可以有括号括住的语句，如果我们有多于一个语句。这就像我们之前讨论的`if-else`语句一样。如果只有一个语句，那么我们不需要括号。当语句多于一个时，它们需要被括在大括号内。在下面的例子中，我们打印出`i`和`j`的值：

```java
for (int i = 0, j = 0; i <= 9; i++, j++) {
   System.out.println(i);
   System.out.println(j);
}
```

#### 注意

表达式必须是有效的 Java 表达式，即可以用分号终止的表达式。

`break`语句可以用来中断`for`循环并跳出循环。它将执行超出`for`循环的范围。

例如，如果`i`等于 5，我们可能希望终止我们之前创建的`for`循环：

```java
for (int i = 0; i <= 9; i++){

   if (i == 5)
       break;
   System.out.println(i);
}
```

输出：

```java
0
1
2
3
4
```

前面的`for`循环从 0、1、2 和 3 迭代，终止于 4。这是因为在满足条件`i`即 5 之后，执行了`break`语句，这结束了`for`循环，循环后的语句不会被执行。执行继续在循环外部。

`continue`语句用于告诉循环跳过它后面的所有其他语句，并继续执行下一次迭代：

```java
for (int i = 0; i <= 9; i++){
   if (i == 5)
       continue;
   System.out.println(i);
}
```

输出：

```java
0
1
2
3
4
6
7
8
9
```

数字 5 没有被打印出来，因为一旦遇到`continue`语句，它后面的语句都会被忽略，并且开始下一次迭代。当处理多个项目时，`continue`语句可能会很有用，因为它可以跳过一些异常。

### 嵌套 for 循环

循环内的一组语句可以是另一个循环。这样的结构称为嵌套循环：

```java
public class Nested{
     public static void main(String []args){
        for(int i = 1; i <= 3; i++) {
   //Nested loop
   for(int j = 1; j <= 3; j++) {
       System.out.print(i + "" + j);
       System.out.print("\t");
   }
   System.out.println();
}
     }
}
```

输出：

```java
11    12    13
21    22    23
31    32    33
```

对于每个`i`的单个循环，我们循环`j`三次。您可以将这些`for`循环理解为如下：

重复`i`三次，对于每次重复，重复`j`三次。这样，我们总共有 9 次`j`的迭代。对于每次`j`的迭代，我们打印出`i`和`j`的值。

### 练习 9：实现嵌套 for 循环

我们在这个练习中的目标是打印一个有七行的星号金字塔，如下所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-fund/img/C09581_Figure_03_01.jpg)

###### 图 3.1：有七行的星号金字塔

为了实现这个目标，请执行以下步骤：

1.  右键单击`src`文件夹，然后选择**New** | **Class**。

1.  输入`NestedPattern`作为类名，然后点击**OK**。

1.  在主方法中，创建一个`for`循环，初始化变量`i`为 1，引入条件，使得`i`的值最多为 15，并将`i`的值增加 2：

```java
public class NestedPattern{ 
public static void main(String[] args) {
for (int i = 1; i <= 15; i += 2) {
}
}
}
}
```

1.  在这个循环内，创建另外两个`for`循环，一个用于打印空格，另一个用于打印*：

```java
for (int k = 0; k < (7 - i / 2); k++) {
   System.out.print(" ");
   }
for (int j = 1; j <= i; j++) {
   System.out.print("*");
   }
```

1.  在外部`for`循环中，添加以下代码以添加下一行：

```java
System.out.println();
```

运行程序。您将看到结果金字塔。

### for-each 循环

`for each`循环是 Java 5 中引入的`for`循环的高级版本。它们用于对数组或项目列表中的每个项目执行给定操作。

让我们来看看这个`for`循环：

```java
int[] arr = { 1, 2, 3, 4, 5 , 6, 7, 8, 9,10};
for (int i  = 0; i < 10; i++){
   System.out.println(arr[i]);
}
```

第一行声明了一个整数数组。数组是相同类型项目的集合。在这种情况下，变量 arr 持有 10 个整数的集合。然后我们使用`for`循环从`0`到`10`，打印出这个数组的元素。我们使用`i < 10`是因为最后一个项目在索引`9`处，而不是`10`。这是因为数组的元素从索引 0 开始。第一个元素在索引`0`处，第二个在索引`1`处，第三个在`2`处，依此类推。`arr[0]`将返回第一个元素，`arr[1]`第二个，`arr[2]`第三个，依此类推。

这个`for`循环可以用更短的`for each`循环来替代。`for each`循环的语法如下：

```java
for( type item : array_or_collection){
    //Code to executed for each item in the array or collection
}
```

对于我们之前的例子，`for each`循环将如下所示：

```java
for(int item : arr){
   System.out.println(item);
}
```

`int` `item`是我们当前所在数组中的元素。`for each`循环将遍历数组中的所有元素。在大括号内，我们打印出这个元素。请注意，我们不必像之前的`for`循环中那样使用`arr[i]`。这是因为`for each`循环会自动为我们提取值。此外，我们不必使用额外的`int` `i`来保持当前索引并检查我们是否在`10`以下`(i < 10)`，就像我们之前使用的`for`循环那样。`for each`循环更短，会自动为我们检查范围。

例如，我们可以使用`for each`循环来打印数组`arr`中所有元素的平方：

```java
for(int item : arr){
   int square = item * item;
   System.out.println(square);
}
```

输出：

```java
1
4
9
16
25
36
49
64
81
10
```

### while 和 do while 循环

有时，我们希望重复执行某些语句，也就是说，只要某个布尔条件为真。这种情况需要我们使用`while`循环或`do while`循环。`while`循环首先检查一个布尔语句，如果布尔为真，则执行一段代码块，否则跳过`while`块。`do while`循环首先在检查布尔条件之前执行一段代码块。当您希望代码至少执行一次时，请使用`do while`循环，当您希望在第一次执行之前首先检查布尔条件时，请使用`while`循环。以下是`while`和`do while`循环的格式：

`while`循环的语法：

```java
while(condition) {
//Do something
}
```

`do while`循环的语法：

```java
do {
//Do something
}
while(condition);
```

例如，要使用`while`循环打印从 0 到 10 的所有数字，我们将使用以下代码：

```java
public class Loops {
   public static void main(String[] args){
       int number = 0;
       while (number <= 10){
           System.out.println(number);
           number++;
       }
   }
}
```

输出：

```java
0
1
2
3
4
5
6
7
8
9
10
```

我们也可以使用`do while`循环编写上述代码：

```java
public class Loops {
   public static void main(String[] args){
       int number = 0;
       do {
           System.out.println(number);
           number++;
       }while (number <= 10);
   }
}
```

使用`do while`循环，条件最后被评估，所以我们确信语句至少会被执行一次。

### 练习 10：实现 while 循环

要使用`while`循环打印斐波那契数列的前 10 个数字，执行以下步骤：

1.  右键单击`src`文件夹，然后选择**新建** | **类**。

1.  输入`FibonacciSeries`作为类名，然后单击**确定**。

1.  声明`main`方法中所需的变量：

```java
public class FibonacciSeries {
    public static void main(String[] args) {
        int i = 1, x = 0, y = 1, sum=0;
    }
}
```

这里，`i`是计数器，`x`和`y`存储斐波那契数列的前两个数字，`sum`是一个用于计算变量`x`和`y`的和的变量。

1.  实现一个`while`循环，条件是计数器`i`不超过 10：

```java
while (i <= 10)
{
}
```

1.  在`while`循环内，实现打印`x`的值的逻辑，然后分配适当的值给`x`、`y`和`sum`，这样我们总是打印最后一个和倒数第二个数字的`sum`：

```java
System.out.print(x + " ");
sum = x + y;
x = y;
y = sum;
i++;
```

### 活动 9：实现 while 循环

记得 John，他是一个桃子种植者。他从树上摘桃子，把它们放进水果箱里然后运输。如果一个水果箱装满了 20 个桃子，他就可以运输一个水果箱。如果他的桃子少于 20 个，他就必须摘更多的桃子，这样他就可以装满一个装有 20 个桃子的水果箱并运输它。

我们想通过编写一个自动化软件来帮助 John 启动箱子的填充和运输。我们从 John 那里得到桃子的数量，并为每组 20 个桃子打印一条消息，说明我们已经运输了多少箱子，还剩下多少桃子，例如，“已运输 2 箱，剩余 54 个桃子”。我们想用`while`循环来实现这一点。只要我们有足够的桃子可以装满至少一个箱子，循环就会继续。与之前的`for`活动相反，我们还将跟踪剩余的桃子。为了实现这一点，执行以下步骤：

1.  创建一个新类，输入`PeachBoxCounter`作为类名

1.  导入`java.util.Scanner`包：

1.  在`main()`中使用`System.out.print`询问用户`numberOfPeaches`。

1.  创建一个`numberOfBoxesShipped`变量。

1.  编写一个 while 循环，只要我们至少有 20 个桃子就继续。

1.  在循环中，从`numberOfPeaches`中移除 20 个桃子，并将`numberOfBoxesShipped`增加 1。打印这些值。

1.  运行主程序。

输出应该类似于：

```java
Enter the number of peaches picked: 42
1 boxes shipped, 22 peaches remaining
2 boxes shipped, 2 peaches remaining
```

#### 注意

此活动的解决方案可在第 311 页找到。

### 活动 10：实现循环结构

我们的目标是创建一个订票系统，这样当用户提出票务请求时，票务会根据餐厅剩余座位的数量来批准。

要创建这样一个程序，执行以下步骤：

1.  导入从用户读取数据所需的包。

1.  声明变量以存储总座位数、剩余座位和请求的票数。

1.  在`while`循环内，实现`if else`循环，检查请求是否有效，这意味着请求的票数少于剩余座位数。

1.  如果前一步的逻辑为真，则打印一条消息表示票已处理，将剩余座位设置为适当的值，并要求下一组票。

1.  如果第 3 步的逻辑为假，则打印适当的消息并跳出循环。

#### 注意

此活动的解决方案可在第 312 页找到。

### 活动 11：嵌套循环连续桃子运输。

记得 John，他是一个桃子种植者。他从树上摘桃子，把它们放进水果箱里然后运输。如果一个水果箱装满了 20 个桃子，他就可以运输一个水果箱。如果他的桃子少于 20 个，他就必须摘更多的桃子，这样他就可以装满一个装有 20 个桃子的水果箱并运输它。

我们希望通过编写一个自动化软件来帮助约翰启动装箱和运输。在我们的自动化软件的这个新版本中，我们将允许约翰自行选择批量带来桃子，并将上一批剩下的桃子与新批次一起使用。

我们从约翰那里得到了桃子的进货数量，并将其加到当前的桃子数量中。然后，我们为每组 20 个桃子打印一条消息，说明我们已经运送了多少箱子，还剩下多少桃子，例如，“已运送 2 箱，剩余 54 个桃子”。我们希望用`while`循环来实现这一点。只要我们有足够多的桃子可以装至少一箱，循环就会继续。我们将有另一个`while`循环来获取下一批桃子，如果没有，则退出。为了实现这一点，执行以下步骤：

1.  创建一个新的类，并输入`PeachBoxCount`作为类名

1.  导入`java.util.Scanner`包：

1.  创建一个`numberOfBoxesShipped`变量和一个`numberOfPeaches`变量。

1.  在`main()`中，编写一个无限的`while`循环。

1.  使用`System.out.print`询问用户`incomingNumberOfPeaches`。如果这是零，则跳出这个无限循环。

1.  将进货的桃子加到现有的桃子中。

1.  编写一个`while`循环，只要我们至少有 20 个桃子就继续。

1.  在 for 循环中，从`numberOfPeaches`中减去 20 个桃子，并将`numberOfBoxesShipped`增加 1。打印这些值。

1.  运行主程序。

输出应类似于：

```java
Enter the number of peaches picked: 23
1 boxes shipped, 3 peaches remaining
Enter the number of peaches picked: 59
2 boxes shipped, 42 peaches remaining
3 boxes shipped, 22 peaches remaining
4 boxes shipped, 2 peaches remaining
Enter the number of peaches picked: 0
```

#### 注意

此活动的解决方案可在第 313 页找到。

## 总结

在本课程中，我们通过查看一些简单的例子，涵盖了 Java 和编程中一些基本和重要的概念。条件语句和循环语句通常是实现逻辑的基本要素。

在下一课中，我们将专注于另外一些基本概念，如函数、数组和字符串。这些概念将帮助我们编写简洁和可重用的代码。
