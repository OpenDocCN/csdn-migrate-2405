# Java9 和 JShell（一）

> 原文：[`zh.annas-archive.org/md5/E5B72AEC1D99D45B4B3574117C3D3F53`](https://zh.annas-archive.org/md5/E5B72AEC1D99D45B4B3574117C3D3F53)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

Java 绝对是本世纪最流行的编程语言之一。然而，每当我们需要快速探索新的算法或新的应用领域时，Java 并没有为我们提供一种简单的执行代码片段并打印结果的方式。由于这种限制，许多开发人员开始使用其他提供 REPL（读取-求值-打印-循环）实用程序的编程语言，如 Scala 和 Python。然而，许多时候，在探索阶段结束并且需求和算法清晰之后，需要回到 Java。

Java 9 引入了 JShell，一个新的实用程序，允许我们轻松运行 Java 9 代码片段并打印结果。这个实用程序是一个 REPL，使我们能够像开发者在 Scala 和 Python 中那样轻松地使用 Java。JShell 使学习 Java 9 及其最重要的特性变得更容易。

面向对象编程，也称为 OOP，是每个现代软件开发人员工作中必备的技能。这是非常有道理的，因为 OOP 允许您最大化代码重用并最小化维护成本。然而，学习面向对象编程是具有挑战性的，因为它包含太多抽象概念，需要现实生活的例子才能容易理解。此外，不遵循最佳实践的面向对象代码很容易变成维护的噩梦。

Java 是一种多范式编程语言，其中最重要的范式之一是面向对象编程。如果你想要使用 Java 9，你需要掌握 Java 中的面向对象编程。此外，由于 Java 9 还吸收了函数式编程语言中的一些优秀特性，因此了解如何将面向对象编程代码与函数式编程代码相结合是很方便的。

本书将使您能够使用 JShell 在 Java 9 中开发高质量可重用的面向对象代码。您将学习面向对象编程原则以及 Java 9 如何实现它们，结合现代函数式编程技术。您将学习如何从现实世界元素中捕捉对象并创建代表它们的面向对象代码。您将了解 Java 对面向对象代码的处理方式。您将最大化代码重用并减少维护成本。您的代码将易于理解，并且将与现实生活元素的表示一起工作。

此外，你将学习如何使用 Java 9 引入的新模块化功能组织代码，并准备创建复杂的应用程序。

# 本书内容包括

《第一章》*JShell – A Read-Evaluate-Print-Loop for Java 9*，开始我们的 Java 9 面向对象编程之旅。我们将学习如何启动并使用 Java 9 中引入的新实用程序：JShell，它将允许我们轻松运行 Java 9 代码片段并打印其结果。这个实用程序将使我们更容易学习面向对象编程。

《第二章》*Real-World Objects to UML Diagrams and Java 9 via JShell*，教我们如何从现实生活中识别对象。我们将了解使用对象编程更容易编写易于理解和重用的代码。我们将学习如何识别现实世界的元素，并将它们转化为 Java 支持的面向对象范式的不同组件。我们将开始使用 UML（统一建模语言）图表组织类。

第三章，“类和实例”，展示了类代表生成对象的蓝图或模板，这些对象也被称为实例。我们将设计一些代表现实对象蓝图的类。我们将学习对象的生命周期。我们将使用许多示例来理解初始化的工作原理。我们将声明我们的第一个类来生成对象的蓝图。我们将定制其初始化并在 JShell 中的实时示例中测试其个性化行为。我们将了解垃圾回收的工作原理。

第四章，“数据的封装”，教会你 Java 9 中类的不同成员以及它们如何反映在从类生成的实例的成员中。我们将使用实例字段、类字段、设置器、获取器、实例方法和类方法。我们将使用设置器和获取器生成计算属性。我们将利用访问修饰符隐藏数据。我们将使用静态字段创建所有类实例共享的值。

第五章，“可变和不可变类”，介绍了可变对象和不可变对象之间的区别。首先，我们将创建一个可变类，然后我们将构建这个类的不可变版本。我们将学习在编写并发代码时不可变对象的优势。

第六章，“继承、抽象、扩展和特化”，讨论了如何利用简单继承来专门化或扩展基类。我们将从上到下设计许多类，并使用链式构造函数。我们将使用 UML 图设计从另一个类继承的类。我们将在交互式 JShell 中编写类。我们将重写和重载方法。我们将运行代码以了解我们编写的所有东西是如何工作的。

第七章，“成员继承和多态”，教你如何控制子类是否可以覆盖成员。我们将利用最激动人心的面向对象特性之一：多态性。我们将利用 JShell 轻松理解类型转换。我们将声明执行与类实例操作的方法。

第八章，“接口的契约编程”，介绍了接口在 Java 9 中与类结合的工作原理。在 Java 9 中实现多重继承的唯一方法是通过接口的使用。我们将学习声明和组合多个蓝图以生成单个实例。我们将声明具有不同类型要求的接口。然后，我们将声明许多实现创建的接口的类。我们将结合接口和类以利用 Java 9 中的多重继承。我们将结合接口的继承和类的继承。

第九章，“接口的高级契约编程”，深入探讨了接口的契约编程。我们将使用接口作为参数的方法。我们将理解接口和类的向下转型，并将接口类型的实例视为不同的子类。JShell 将帮助我们轻松理解类型转换和向下转型的复杂性。我们将处理更复杂的场景，将类继承与接口继承相结合。

第十章，“泛型的代码重用最大化”，介绍了如何使用参数多态性。我们将学习如何通过编写能够处理不同类型对象的代码来最大化代码重用，即能够处理实现特定接口的类的实例或者其类层次结构包括特定超类的实例。我们将使用接口和泛型。我们将创建一个可以处理受限泛型类型的类。我们将利用泛型为多种类型创建一个泛型类。

第十一章，“高级泛型”，深入探讨了参数多态性。我们将声明一个可以使用两个受限泛型类型的类。我们将在 JShell 中使用具有两个泛型类型参数的泛型类。我们将利用 Java 9 中的泛型来泛化现有的类。

第十二章，“面向对象，函数式编程和 Lambda 表达式”，讨论了函数在 Java 9 中是一等公民。我们将在类中使用函数接口。我们将使用 Java 9 中包含的许多函数式编程特性，并将它们与我们在前几章中学到的关于面向对象编程的知识相结合。这样，我们将能够兼顾两者的优势。我们将分析许多算法的命令式和函数式编程方法之间的差异。我们将利用 lambda 表达式，并将 map 操作与 reduce 结合起来。

第十三章，“Java 9 中的模块化”，将所有面向对象的拼图拼在一起。我们将重构现有代码以利用面向对象编程。我们将理解 Java 9 中模块化源代码的用法。我们将使用模块创建一个新的 Java 9 解决方案，使用 Java 9 中的新模块化组织面向对象的代码，并学习许多调试面向对象代码的技巧。

# 你需要为这本书做什么

你需要一台双核 CPU 和至少 4GB RAM 的计算机，能够运行 JDK 9 Windows Vista SP2，Windows 7，Windows 8.x，Windows 10 或更高版本，或者 macOS 10.9 或更高版本，以及 JDK 9 支持的任何 Linux 发行版。任何能够运行 JDK 9 的 IoT 设备也将很有用。

# 这本书是为谁准备的

这本书可以被任何计算机科学专业的毕业生或刚开始从事软件工程师工作的人理解。基本上，对于像 Python、C++或者早期的 Java 版本这样的面向对象编程语言的理解就足够了。参与过完整的软件工程项目周期将是有帮助的。

# 约定

在这本书中，你会发现一些文本样式，用来区分不同类型的信息。以下是一些样式的例子，以及它们的含义。

文本中的代码单词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄显示如下：文本中的代码单词显示如下：“JShell 允许我们调用`System.out.printf`方法轻松格式化我们要打印的输出。”

代码块设置如下：

```java
double getGeneratedRectangleHeight() {
    final Rectangle rectangle = new Rectangle(37, 87);
    return rectangle.height; 
}
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目以粗体显示：

```java
double getGeneratedRectangleHeight() {
    final Rectangle rectangle = new Rectangle(37, 87);
    return rectangle.height; 
}
```

任何命令行输入或输出都以以下形式编写：

```java
javac -version

```

**新术语**和**重要单词**以粗体显示。例如，屏幕上看到的单词，菜单或对话框中的单词会以这样的形式出现在文本中：“单击**接受**，然后单击**退出**。”

### 注意

警告或重要说明会以这样的形式出现在框中。

### 提示

提示和技巧会以这样的形式出现。

# 读者反馈

我们始终欢迎读者的反馈。让我们知道您对本书的看法——您喜欢或不喜欢的地方。读者的反馈对我们开发您真正受益的标题非常重要。

要向我们发送一般反馈，只需发送电子邮件至`<feedback@packtpub.com>`，并在消息主题中提及书名。

如果您在某个专题上有专业知识，并且有兴趣撰写或为书籍做出贡献，请参阅我们的作者指南[www.packtpub.com/authors](http://www.packtpub.com/authors)。

# 客户支持

现在您是 Packt 书籍的自豪所有者，我们有一些事情可以帮助您充分利用您的购买。

## 下载示例代码

您可以从您在[`www.packtpub.com`](http://www.packtpub.com)的帐户中下载本书的示例代码文件。如果您在其他地方购买了这本书，您可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)并注册以直接将文件发送到您的电子邮件。

您可以按照以下步骤下载代码文件：

1.  使用您的电子邮件地址和密码登录或注册到我们的网站。

1.  将鼠标指针悬停在顶部的**支持**选项卡上。

1.  单击**代码下载和勘误**。

1.  在**搜索**框中输入书名。

1.  选择您要下载代码文件的书籍。

1.  从下拉菜单中选择您购买本书的地方。

1.  单击**代码下载**。

您还可以通过单击 Packt Publishing 网站上书籍页面上的**代码文件**按钮来下载代码文件。可以通过在**搜索**框中输入书名来访问该页面。请注意，您需要登录您的 Packt 帐户。

下载文件后，请确保使用最新版本的解压缩或提取文件夹：

+   WinRAR / 7-Zip for Windows

+   Zipeg / iZip / UnRarX for Mac

+   7-Zip / PeaZip for Linux

该书的代码包也托管在 GitHub 上[`github.com/PacktPublishing/Java-9-with-JShell`](https://github.com/PacktPublishing/Java-9-with-JShell)。我们还有其他代码包来自我们丰富的图书和视频目录，可在[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)上找到。去看看吧！

## 下载本书的彩色图片

我们还为您提供了一个 PDF 文件，其中包含本书中使用的屏幕截图/图表的彩色图片。彩色图片将帮助您更好地理解输出中的变化。您可以从[`www.packtpub.com/sites/default/files/downloads/Java9withJShell_ColorImages.pdf`](https://www.packtpub.com/sites/default/files/downloads/Java9withJShell_ColorImages.pdf)下载此文件。

## 勘误

尽管我们已经尽最大努力确保内容的准确性，但错误还是会发生。如果您在我们的书籍中发现错误——可能是文本或代码中的错误——我们将不胜感激，如果您能向我们报告。通过这样做，您可以帮助其他读者避免挫折，并帮助我们改进本书的后续版本。如果您发现任何勘误，请访问[`www.packtpub.com/submit-errata`](http://www.packtpub.com/submit-errata)，选择您的书籍，点击**勘误提交表**链接，并输入您的勘误详情。一旦您的勘误经过验证，您的提交将被接受，并且勘误将被上传到我们的网站或添加到该书籍的勘误列表中的**勘误**部分。

要查看先前提交的勘误表，请访问[`www.packtpub.com/books/content/support`](https://www.packtpub.com/books/content/support)，并在搜索框中输入书名。所需信息将显示在**勘误表**部分下。

## 盗版

互联网上盗版受版权保护的材料是一个持续存在的问题，涉及各种媒体。在 Packt，我们非常重视版权和许可的保护。如果您在互联网上发现我们作品的任何非法副本，请立即向我们提供位置地址或网站名称，以便我们采取补救措施。

请通过`<copyright@packtpub.com>`与我们联系，并附上涉嫌盗版材料的链接。

我们感谢您帮助保护我们的作者和我们为您提供有价值内容的能力。

## 问题

如果您对本书的任何方面有问题，可以通过`<questions@packtpub.com>`与我们联系，我们将尽力解决问题。


# 第一章：JShell-用于 Java 9 的读取-求值-打印-循环

在本章中，我们将开始使用 Java 9 进行面向对象编程的旅程。您将学习如何启动并使用 Java 9 中引入的新实用程序：JShell，它将使您能够轻松运行 Java 9 代码片段并打印其结果。我们将执行以下操作：

+   准备好使用 Java 9 进行**面向对象编程**的旅程

+   在 Windows，macOS 或 Linux 上安装所需的软件

+   了解使用**REPL**（**读取-求值-打印-循环**）实用程序的好处

+   检查默认导入并使用自动完成功能

+   在 JShell 中运行 Java 9 代码

+   评估表达式

+   使用变量，方法和源代码

+   在我们喜欢的外部代码编辑器中编辑源代码

+   加载源代码

# 准备好使用 Java 9 进行面向对象编程的旅程

在本书中，您将学习如何利用 Java 编程语言第 9 版中包含的所有面向对象的特性，即 Java 9。一些示例可能与以前的 Java 版本兼容，例如 Java 8，Java 7 和 Java 6，但是必须使用 Java 9 或更高版本，因为该版本不向后兼容。我们不会编写向后兼容以前的 Java 版本的代码，因为我们的主要目标是使用 Java 9 或更高版本，并使用其语法和所有新功能。

大多数情况下，我们不会使用任何**IDE**（**集成开发环境**），而是利用 JShell 和 JDK 中包含的许多其他实用程序。但是，您可以使用任何提供 Java 9 REPL 的 IDE 来使用所有示例。您将在接下来的章节中了解使用 REPL 的好处。在最后一章中，您将了解到使用 Java 9 引入的新模块化功能时，IDE 将给您带来的好处。

### 提示

无需具备 Java 编程语言的先前经验，即可使用本书中的示例并学习如何使用 Java 9 建模和创建面向对象的代码。如果您具有一些 C＃，C ++，Python，Swift，Objective-C，Ruby 或 JavaScript 的经验，您将能够轻松学习 Java 的语法并理解示例。许多现代编程语言都从 Java 中借鉴了功能，反之亦然。因此，对这些语言的任何了解都将非常有用。

在本章中，我们将在 Windows，macOS 或 Linux 上安装所需的软件。我们将了解使用 REPL，特别是 JShell，学习面向对象编程的好处。我们将学习如何在 JShell 中运行 Java 9 代码以及如何在 REPL 中加载源代码示例。最后，我们将学习如何在 Windows，macOS 和 Linux 上从命令行或终端运行 Java 代码。

# 在 Windows，macOS 或 Linux 上安装所需的软件

我们必须从[`jdk9.java.net/download/`](https://jdk9.java.net/download/)下载并安装适用于我们操作系统的最新版本的**JDK 9**（**Java 开发工具包 9**）。我们必须接受 Java 的许可协议才能下载软件。

与以前的版本一样，JDK 9 可用于许多不同的平台，包括但不限于以下平台：

+   Windows 32 位

+   Windows 64 位

+   macOS 64 位（以前称为 Mac OS X 或简称 OS X）

+   Linux 32 位

+   Linux 64 位

+   Linux on ARM 32 位

+   Linux on ARM 64 位

安装适用于我们操作系统的 JDK 9 的适当版本后，我们可以将 JDK 9 安装文件夹的`bin`子文件夹添加到`PATH`环境变量中。这样，我们就可以从我们所在的任何文件夹启动不同的实用程序。

### 提示

如果我们没有将 JDK 9 安装的文件夹的`bin`子文件夹添加到操作系统的`PATH`环境变量中，那么在执行命令时我们将始终需要使用`bin`子文件夹的完整路径。在启动不同的 Java 命令行实用程序的下一个说明中，我们将假设我们位于这个`bin`子文件夹中，或者`PATH`环境变量包含它。

一旦我们安装了 JDK 9，并将`bin`文件夹添加到`PATH`环境变量中，我们可以在 Windows 命令提示符或 macOS 或 Linux 终端中运行以下命令：

```java
javac -version

```

上一个命令将显示包含在 JDK 中的主要 Java 编译器的当前版本，该编译器将 Java 源代码编译为 Java 字节码。版本号应该以 9 开头，如下一个示例输出所示：

```java
javac 9-ea

```

如果上一个命令的结果显示的版本号不以 9 开头，我们必须检查安装是否成功。此外，我们必须确保`PATH`环境变量不包括 JDK 的旧版本路径，并且包括最近安装的 JDK 9 的`bin`文件夹。

现在，我们准备启动 JShell。在 Windows 命令提示符或 macOS 或 Linux 终端中运行以下命令：

```java
jshell

```

上一个命令将启动 JShell，显示包括正在使用的 JDK 版本的欢迎消息，并且提示符将更改为`jshell>`。每当我们看到这个提示时，这意味着我们仍然在 JShell 中。下面的屏幕截图显示了在 macOS 的终端窗口中运行的 JShell。

![在 Windows、macOS 或 Linux 上安装所需软件](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-jsh/img/00002.jpeg)

### 提示

如果我们想随时离开 JShell，我们只需要在 Mac 中按*Ctrl* + *D*。另一个选项是输入`/exit`并按*Enter*。

## 了解使用 REPL 的好处

Java 9 引入了一个名为 JShell 的交互式 REPL 命令行环境。这个工具允许我们执行 Java 代码片段并立即获得结果。我们可以轻松编写代码并查看其执行的结果，而无需创建解决方案或项目。我们不必等待项目完成构建过程来检查执行许多行代码的结果。JShell，像任何其他 REPL 一样，促进了探索性编程，也就是说，我们可以轻松地交互式地尝试和调试不同的算法和结构。

### 提示

如果您曾经使用过其他提供 REPL 或交互式 shell 的编程语言，比如 Python、Scala、Clojure、F#、Ruby、Smalltalk 和 Swift 等，您已经知道使用 REPL 的好处。

例如，假设我们必须与提供 Java 绑定的 IoT（物联网）库进行交互。我们必须编写 Java 代码来使用该库来控制无人机，也称为无人机（UAV）。无人机是一种与许多传感器和执行器进行交互的物联网设备，包括与发动机、螺旋桨和舵机连接的数字电子调速器。

我们希望能够编写几行代码来从传感器中检索数据并控制执行器。我们只需要确保事情按照文档中的说明进行。我们希望确保从高度计读取的数值在移动无人机时发生变化。JShell 为我们提供了一个适当的工具，在几秒钟内开始与库进行交互。我们只需要启动 JShell，加载库，并在 REPL 中开始编写 Java 9 代码。使用以前的 Java 版本，我们需要从头开始创建一个新项目，并在开始编写与库交互的第一行代码之前编写一些样板代码。JShell 允许我们更快地开始工作，并减少了创建整个框架以开始运行 Java 9 代码的需要。JShell 允许从 REPL 交互式探索 API（应用程序编程接口）。

我们可以在 JShell 中输入任何 Java 9 定义。例如，我们可以声明方法、类和变量。我们还可以输入 Java 表达式、语句或导入。一旦我们输入了声明方法的代码，我们就可以输入一个使用先前定义的方法的语句，并查看执行的结果。

JShell 允许我们从文件中加载源代码，因此，您将能够加载本书中包含的源代码示例并在 JShell 中评估它们。每当我们必须处理源代码时，您将知道可以从哪个文件夹和文件中加载它。此外，JShell 允许我们执行 JShell 命令。我们将在本章后面学习最有用的命令。

JShell 允许我们调用`System.out.printf`方法轻松格式化我们想要打印的输出。我们将在我们的示例代码中利用这个方法。

### 提示

JShell 禁用了一些在交互式 REPL 中没有用处的 Java 9 功能。每当我们在 JShell 中使用这些功能时，我们将明确指出 JShell 将禁用它们，并解释它们的影响。

在 JShell 中，语句末尾的分号(`;`)是可选的。但是，我们将始终在每个语句的末尾使用分号，因为我们不想忘记在编写项目和解决方案中的真实 Java 9 代码时必须使用分号。当我们输入要由 JShell 评估的表达式时，我们将省略语句末尾的分号。

例如，以下两行是等价的，它们都将在 JShell 中执行后打印`"Object-Oriented Programming rocks with Java 9!"`。第一行在语句末尾不包括分号(`;`)，第二行包括分号(`;`)。我们将始终使用分号(;)，如第二行中所示，以保持一致性。

```java
System.out.printf("Object-Oriented Programming rocks with Java 9!\n")
System.out.printf("Object-Oriented Programming rocks with Java 9!\n");
```

以下屏幕截图显示了在 Windows 10 上运行的 JShell 中执行这两行的结果：

![理解使用 REPL 的好处](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-jsh/img/00003.jpeg)

在一些示例中，我们将利用 JShell 为我们提供的网络访问功能。这个功能对于与 Web 服务交互非常有用。但是，您必须确保您的防火墙配置中没有阻止 JShell。

### 提示

不幸的是，在我写这本书的时候，JShell 没有包括语法高亮功能。但是，您将学习如何使用我们喜欢的编辑器来编写和编辑代码，然后在 JShell 中执行。

## 检查默认导入并使用自动完成功能

默认情况下，JShell 提供一组常见的导入，我们可以使用`import`语句从任何额外的包中导入必要的类型来运行我们的代码片段。我们可以在 JShell 中输入以下命令来列出所有导入：

```java
/imports

```

以下行显示了先前命令的结果：

```java
|    import java.io.*
|    import java.math.*
|    import java.net.*
|    import java.nio.file.*
|    import java.util.*
|    import java.util.concurrent.*
|    import java.util.function.*
|    import java.util.prefs.*
|    import java.util.regex.*
|    import java.util.stream.*

```

与我们在 JShell 之外编写 Java 代码时一样，我们不需要从`java.lang`包导入类型，因为它们默认被导入，并且在 JShell 中运行`/imports`命令时不会列出它们。因此，默认情况下，JShell 为我们提供了访问以下包中的所有类型：

+   `java.lang`

+   `java.io`

+   `java.math`

+   `java.net`

+   `java.nio.file`

+   `java.util`

+   `java.util.concurrent`

+   `java.util.function`

+   `java.util.prefs`

+   `java.util.regex`

+   `java.util.stream`

JShell 提供自动完成功能。我们只需要在需要自动完成功能的时候按下*Tab*键，就像在 Windows 命令提示符或 macOS 或 Linux 中的终端中工作时一样。

有时，以我们输入的前几个字符开头的选项太多。在这些情况下，JShell 会为我们提供一个包含所有可用选项的列表，以提供帮助。例如，我们可以输入`S`并按*Tab*键。JShell 将列出从先前列出的包中导入的以`S`开头的所有类型。以下屏幕截图显示了 JShell 中的结果：

![检查默认导入并使用自动补全功能](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-jsh/img/00004.jpeg)

我们想要输入`System`。考虑到前面的列表，我们只需输入`Sys`，以确保`System`是以`Sys`开头的唯一选项。基本上，我们在作弊，以便了解 JShell 中自动补全的工作原理。输入`Sys`并按下*Tab*键。JShell 将显示`System`。

现在，在 JShell 中输入一个点（`.`），然后输入一个`o`（你将得到`System.o`），然后按下*Tab*键。JShell 将显示`System.out`。

接下来，输入一个点（`.`）并按下*Tab*键。JShell 将显示在`System.out`中声明的所有公共方法。在列表之后，JShell 将再次包括`System.out.`，以便我们继续输入我们的代码。以下屏幕截图显示了 JShell 中的结果：

![检查默认导入并使用自动补全功能](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-jsh/img/00005.jpeg)

输入`printl`并按下*Tab*键。JShell 将自动补全为`System.out.println(`，即它将添加一个`n`和开括号（`(`）。这样，我们只需输入该方法的参数，因为只有一个以`printl`开头的方法。输入`"Auto-complete is helpful in JShell");`并按下*Enter*。下一行显示完整的语句：

```java
System.out.println("Auto-complete is helpful in JShell");
```

在运行上述行后，JShell 将显示 JShell 中的结果的屏幕截图：

![检查默认导入并使用自动补全功能](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-jsh/img/00006.jpeg)

# 在 JShell 中运行 Java 9 代码

```java
Ctrl + *D* to exit the current JShell session. Run the following command in the Windows Command Prompt or in a macOS or Linux Terminal to launch JShell with a verbose feedback:
```

```java
jshell -v

```

```java
calculateRectangleArea. The method receives a width and a height for a rectangle and returns the result of the multiplication of both values of type float:
```

```java
float calculateRectangleArea(float width, float height) {
    return width * height;
}
```

在输入上述代码后，JShell 将显示下一个消息，指示它已创建了一个名为`calculateRectangleArea`的方法，该方法有两个`float`类型的参数：

```java
|  created method calculateRectangleArea(float,float)

```

### 提示

请注意，JShell 写的所有消息都以管道符号（`|`）开头。

在 JShell 中输入以下命令，列出我们在当前会话中迄今为止键入和执行的当前活动代码片段：

```java
/list

```

```java
 result of the previous command. The code snippet that created the calculateRectangleArea method has been assigned 1 as the snippet id.
```

```java
 1 : float calculateRectangleArea(float width, float height) {
 return width * height;
 }

```

在 JShell 中输入以下代码，创建一个名为`width`的新的`float`变量，并将其初始化为`50`：

```java
float width = 50;
```

在输入上述行后，JShell 将显示下一个消息，指示它已创建了一个名为`width`的`float`类型的变量，并将值`50.0`赋给了这个变量：

```java
width ==> 50.0
|  created variable width : float

```

在 JShell 中输入以下代码，创建一个名为`height`的新的`float`变量，并将其初始化为`25`：

```java
float height = 25;
```

在输入上述行后，JShell 将显示下一个消息，指示它已创建了一个名为`height`的`float`类型的变量，并将值`25.0`赋给了这个变量：

```java
height ==> 25.0
|  created variable height : float

```

输入`float area = ca`并按下*Tab*键。JShell 将自动补全为`float area = calculateRectangleArea(`，即它将添加`lculateRectangleArea`和开括号（`(`）。这样，我们只需输入该方法的两个参数，因为只有一个以`ca`开头的方法。输入`width, height);`并按下*Enter*。下一行显示完整的语句：

```java
float area = calculateRectangleArea(width, height);
```

在输入上述行后，JShell 将显示下一个消息，指示它已创建了一个名为`area`的`float`类型的变量，并将调用`calculateRectangleArea`方法并将先前声明的`width`和`height`变量作为参数。该方法返回`1250.0`作为结果，并将其赋给`area`变量。

```java
area ==> 1250.0
|  created variable area : float

```

在 JShell 中输入以下命令，列出我们在当前会话中迄今为止键入和执行的当前活动代码片段：

```java
/list

```

```java
 with the snippet id, that is, a unique number that identifies each code snippet. JShell will display the following lines as a result of the previous command:
```

```java
 1 : float calculateRectangleArea(float width, float height) {
 return width * height;
 }
 2 : float width = 50;
 3 : float height = 25;
 4 : float area = calculateRectangleArea(width, height);

```

在 JShell 中输入以下代码，使用`System.out.printf`来显示`width`、`height`和`area`变量的值。我们在作为`System.out.printf`的第一个参数传递的字符串中的第一个`%.2f`使得字符串后面的下一个参数（`width`）以两位小数的浮点数形式显示。我们重复两次`%.2f`来以两位小数的浮点数形式显示`height`和`area`变量。

```java
System.out.printf("Width: %.2f, Height: %.2f, Area: %.2f\n", width, height, area);
```

在输入上述行后，JShell 将使用`System.out.printf`格式化输出，并打印下一个消息，后面跟着一个临时变量的名称：

```java
Width: 50.00, Height: 25.00, Area: 1250.00
$5 ==> java.io.PrintStream@68c4039c
|  created scratch variable $5 : PrintStream

```

## 评估表达式

JShell 允许我们评估任何有效的 Java 9 表达式，就像我们在使用 IDE 和典型的表达式评估对话框时所做的那样。在 JShell 中输入以下表达式：

```java
width * height;
```

在我们输入上一行后，JShell 将评估表达式，并将结果分配给一个以`$`开头并后跟一个数字的临时变量。JShell 显示临时变量名称`$6`，分配给该变量的值指示表达式评估结果的`1250.0`，以及临时变量的类型`float`。下面的行显示在我们输入上一个表达式后 JShell 中显示的消息：

```java
$6 ==> 1250.0
|  created scratch variable $6 : float

```

```java
$6 variable as a floating point number with two decimal places. Make sure you replace $6 with the scratch variable name that JShell generated.
```

```java
System.out.printf("The calculated area is %.2f", $6);
```

在我们输入上一行后，JShell 将使用`System.out.printf`格式化输出，并打印下一个消息：

```java
The calculated area is 1250.00

```

我们还可以在另一个表达式中使用先前创建的临时变量。在 JShell 中输入以下代码，将`10.5`（`float`）添加到`$6`变量的值中。确保用 JShell 生成的临时变量名称替换`$6`。

```java
$6 + 10.5f;
```

在我们输入上一行后，JShell 将评估表达式，并将结果分配给一个新的临时变量，其名称以`$`开头，后跟一个数字。JShell 显示临时变量名称`$8`，分配给该变量的值指示表达式评估结果的`1260.5`，以及临时变量的类型`float`。下面的行显示在我们输入上一个表达式后 JShell 中显示的消息：

```java
$8 ==> 1250.5
|  created scratch variable $8 : float

```

### 提示

与之前发生的情况一样，临时变量的名称可能不同。例如，可能是`$9`或`$10`，而不是`$8`。

# 使用变量、方法和源

到目前为止，我们已经创建了许多变量，而且在我们输入表达式并成功评估后，JShell 创建了一些临时变量。在 JShell 中输入以下命令，列出迄今为止在当前会话中创建的当前活动变量的类型、名称和值：

```java
/vars

```

以下行显示结果：

```java
|    float width = 50.0
|    float height = 25.0
|    float area = 1250.0
|    PrintStream $5 = java.io.PrintStream@68c4039c
|    float $6 = 1250.0
|    float $8 = 1260.5

```

在 JShell 中输入以下代码，将`80.25`（`float`）赋给先前创建的`width`变量：

```java
width = 80.25f;
```

在我们输入上一行后，JShell 将显示下一个消息，指示它已将`80.25`（`float`）分配给现有的`float`类型变量`width`：

```java
width ==> 80.25
|  assigned to width : float

```

在 JShell 中输入以下代码，将`40.5`（`float`）赋给先前创建的`height`变量：

```java
height = 40.5f;
```

在我们输入上一行后，JShell 将显示下一个消息，指示它已将`40.5`（`float`）分配给现有的`float`类型变量`height`：

```java
height ==> 40.5
|  assigned to height : float

```

再次在 JShell 中输入以下命令，列出当前活动变量的类型、名称和值：

```java
/vars

```

以下行显示了反映我们已经为`width`和`height`变量分配的新值的结果：

```java
|    float width = 80.25
|    float height = 40.5
|    float area = 1250.0
|    PrintStream $5 = java.io.PrintStream@68c4039c
|    float $6 = 1250.0
|    float $8 = 1260.5

```

在 JShell 中输入以下代码，创建一个名为`calculateRectanglePerimeter`的新方法。该方法接收一个矩形的`width`变量和一个`height`变量，并返回`float`类型的两个值之和乘以`2`的结果。

```java
float calculateRectanglePerimeter(float width, float height) {
    return 2 * (width + height);
}
```

在我们输入上一行后，JShell 将显示下一个消息，指示它已创建一个名为`calculateRectanglePerimeter`的方法，该方法有两个`float`类型的参数：

```java
|  created method calculateRectanglePerimeter(float,float)

```

在 JShell 中输入以下命令，列出迄今为止在当前会话中创建的当前活动方法的名称、参数类型和返回类型：

```java
/methods

```

以下行显示结果。

```java
|    calculateRectangleArea (float,float)float
|    calculateRectanglePerimeter (float,float)float

```

在 JShell 中输入以下代码，打印调用最近创建的`calculateRectanglePerimeter`的结果，其中`width`和`height`作为参数：

```java
calculateRectanglePerimeter(width, height);
```

在我们输入上一行后，JShell 将调用该方法，并将结果分配给一个以`$`开头并带有数字的临时变量。JShell 显示了临时变量名`$16`，分配给该变量的值表示方法返回的结果`241.5`，以及临时变量的类型`float`。下面的行显示了在我们输入调用方法的先前表达式后，JShell 中显示的消息：

```java
$16 ==> 241.5
|  created scratch variable $16 : float

```

现在，我们想对最近创建的`calculateRectanglePerimeter`方法进行更改。我们想添加一行来打印计算的周长。在 JShell 中输入以下命令，列出该方法的源代码：

```java
/list calculateRectanglePerimeter

```

以下行显示了结果：

```java
 15 : float calculateRectanglePerimeter(float width, float height) {
 return 2 * (width + height);
 }

```

在 JShell 中输入以下代码，用新代码覆盖名为`calculateRectanglePerimeter`的方法，该新代码打印接收到的宽度和高度值，然后使用与内置`printf`方法相同的方式工作的`System.out.printf`方法调用打印计算的周长。我们可以从先前列出的源代码中复制和粘贴这些部分。这里突出显示了更改：

```java
float calculateRectanglePerimeter(float width, float height) {
 float perimeter = 2 * (width + height);
 System.out.printf("Width: %.2f\n", width);
 System.out.printf("Height: %.2f\n", height);
 System.out.printf("Perimeter: %.2f\n", perimeter);
 return perimeter;
}
```

在我们输入上述行后，JShell 将显示下一个消息，指示它已修改并覆盖了名为`calculateRectanglePerimeter`的方法，该方法有两个`float`类型的参数：

```java
|  modified method calculateRectanglePerimeter(float,float)
|    update overwrote method calculateRectanglePerimeter(float,float)

```

在 JShell 中输入以下代码，以打印调用最近修改的`calculateRectanglePerimeter`方法并将`width`和`height`作为参数的结果：

```java
calculateRectanglePerimeter(width, height);
```

在我们输入上一行后，JShell 将调用该方法，并将结果分配给一个以`$`开头并带有数字的临时变量。前几行显示了由我们添加到方法中的三次调用`System.out.printf`生成的输出。最后，JShell 显示了临时变量名`$19`，分配给该变量的值表示方法返回的结果`241.5`，以及临时变量的类型`float`。

下面的行显示了在我们输入调用方法的先前表达式后，JShell 中显示的消息：

```java
Width: 80.25
Height: 40.50
Perimeter: 241.50
$19 ==> 241.5
|  created scratch variable $19 : float

```

# 在我们喜爱的外部代码编辑器中编辑源代码

我们创建了`calculateRectanglePerimeter`方法的新版本。现在，我们想对`calculateRectangleArea`方法进行类似的更改。但是，这一次，我们将利用编辑器来更轻松地对现有代码进行更改。

在 JShell 中输入以下命令，启动默认的 JShell 编辑面板编辑器，以编辑`calculateRectangleArea`方法的源代码：

```java
/edit calculateRectangleArea

```

JShell 将显示一个对话框，其中包含 JShell 编辑面板和`calculateRectangleArea`方法的源代码，如下面的屏幕截图所示：

![在我们喜爱的外部代码编辑器中编辑源代码](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-jsh/img/00007.jpeg)

JShell 编辑面板缺少我们从代码编辑器中喜欢的大多数功能，我们甚至不能认为它是一个体面的代码编辑器。事实上，它只允许我们轻松地编辑源代码，而无需从先前的列表中复制和粘贴。我们将在以后学习如何配置更好的编辑器。

在 JShell 编辑面板中输入以下代码，以用新代码覆盖名为`calculateRectangleArea`的方法，该新代码打印接收到的宽度和高度值，然后使用`Sytem.out.printf`方法调用打印计算的面积。这里突出显示了更改：

```java
float calculateRectangleArea(float width, float height) {
 float area = width * height;
 System.out.printf("Width: %.2f\n", width);
 System.out.printf("Height: %.2f\n", height);
 System.out.printf("Area: %.2f\n", area);
 return area;
}
```

点击**接受**，然后点击**退出**。JShell 将关闭 JShell 编辑面板，并显示下一个消息，指示它已修改并覆盖了名为`calculateRectangleArea`的方法，该方法有两个`float`类型的参数：

```java
|  modified method calculateRectangleArea(float,float)
|    update overwrote method calculateRectangleArea(float,float)

```

在 JShell 中输入以下代码，以打印调用最近修改的`calculateRectangleArea`方法并将`width`和`height`作为参数的结果：

```java
calculateRectangleArea(width, height);
```

输入上述行后，JShell 将调用该方法，并将结果赋给一个以`$`开头并带有数字的临时变量。前几行显示了通过对该方法添加的三次`System.out.printf`调用生成的输出。最后，JShell 显示了临时变量名`$24`，指示方法返回的结果的值`3250.125`，以及临时变量的类型`float`。接下来的几行显示了在输入调用方法的新版本的前一个表达式后，JShell 显示的消息：

```java
Width: 80.25
Height: 40.50
Area: 3250.13
$24 ==> 3250.125
|  created scratch variable $24 : float

```

好消息是，JShell 允许我们轻松配置任何外部编辑器来编辑代码片段。我们只需要获取要使用的编辑器的完整路径，并在 JShell 中运行一个命令来配置我们想要在使用`/edit`命令时启动的编辑器。

例如，在 Windows 中，流行的 Sublime Text 3 代码编辑器的默认安装路径是`C:\Program Files\Sublime Text 3\sublime_text.exe`。如果我们想要使用此编辑器在 JShell 中编辑代码片段，必须运行`/set editor`命令，后跟用双引号括起来的路径。我们必须确保在路径字符串中用双反斜杠（\\）替换反斜杠（\）。对于先前解释的路径，我们必须运行以下命令：

```java
/set editor "C:\\Program Files\\Sublimet Text 3\\sublime_text.exe"

```

输入上述命令后，JShell 将显示一条消息，指示编辑器已设置为指定路径：

```java
| Editor set to: C:\Program Files\Sublime Text 3\sublime_text.exe

```

更改编辑器后，我们可以在 JShell 中输入以下命令，以启动新编辑器对`calculateRectangleArea`方法的源代码进行更改：

```java
/edit calculateRectangleArea

```

JShell 将启动 Sublime Text 3 或我们可能指定的任何其他编辑器，并将加载一个临时文件，其中包含`calculateRectangleArea`方法的源代码，如下截图所示：

![在我们喜欢的外部代码编辑器中编辑源代码](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-jsh/img/00008.jpeg)

### 提示

如果我们保存更改，JShell 将自动覆盖该方法，就像我们使用默认编辑器 JShell Edit Pad 时所做的那样。进行必要的编辑后，我们必须关闭编辑器，以继续在 JShell 中运行 Java 代码或 JShell 命令。

在任何平台上，JShell 都会创建一个带有`.edit`扩展名的临时文件。因此，我们可以配置我们喜欢的编辑器，以便在打开带`.edit`扩展名的文件时使用 Java 语法高亮显示。

在 macOS 或 Linux 中，路径与 Windows 中的不同，因此必要的步骤也不同。例如，在 macOS 中，为了在默认路径中安装流行的 Sublime Text 3 代码编辑器时启动它，我们必须运行`/Applications/Sublime Text.app/Contents/SharedSupport/bin/subl`。

如果我们想要使用此编辑器在 JShell 中编辑代码片段，必须运行`/set editor`命令，后跟完整路径，路径需用双引号括起来。对于先前解释的路径，我们必须运行以下命令：

```java
/set editor "/Applications/Sublime Text.app/Contents/SharedSupport/bin/subl"

```

输入上述命令后，JShell 将显示一条消息，指示编辑器已设置为指定路径：

```java
|  Editor set to: /Applications/Sublime Text.app/Contents/SharedSupport/bin/subl

```

更改编辑器后，我们可以在 JShell 中输入以下命令，以启动新编辑器对`calculateRectangleArea`方法的源代码进行更改：

```java
/edit calculateRectangleArea

```

JShell 将在 macOS 上启动 Sublime Text 3 或我们可能指定的任何其他编辑器，并将加载一个临时文件，其中包含`calculateRectangleArea`方法的源代码，如下截图所示：

![在我们喜欢的外部代码编辑器中编辑源代码](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-jsh/img/00009.jpeg)

# 加载源代码

当然，我们不必为每个示例输入源代码。自动补全功能很有用，但我们将利用一个命令，允许我们在 JShell 中从文件加载源代码。

按下*Ctrl* + *D*退出当前的 JShell 会话。在 Windows 命令提示符中或 macOS 或 Linux 终端中运行以下命令，以启动具有详细反馈的 JShell：

```java
jshell -v

```

以下行显示了声明`calculateRectanglePerimeter`和`calculateRectangleArea`方法的最新版本的代码。然后，代码声明并初始化了两个`float`类型的变量：`width`和`height`。最后，最后两行调用了先前定义的方法，并将`width`和`height`作为它们的参数。示例的代码文件包含在`java_9_oop_chapter_01_01`文件夹中的`example01_01.java`文件中。

```java
float calculateRectanglePerimeter(float width, float height) {
    float perimeter = 2 * (width + height);
    System.out.printf("Width: %.2f\n", width);
    System.out.printf("Height: %.2f\n", height);
    System.out.printf("Perimeter: %.2f\n", perimeter);
    return perimeter;
}

float calculateRectangleArea(float width, float height) {
    float area = width * height;
    System.out.printf("Width: %.2f\n", width);
    System.out.printf("Height: %.2f\n", height);
    System.out.printf("Area: %.2f\n", area);
    return area;
}

float width = 120.25f;
float height = 35.50f;
calculateRectangleArea(width, height);
calculateRectanglePerimeter(width, height);
```

```java
If the root folder for the source code in Windows is C:\Users\Gaston\Java9, you can run the following command to load and execute the previously shown source code in JShell:
```

```java
/open C:\Users\Gaston\Java9\java_9_oop_chapter_01_01\example01_01.java

```

如果 macOS 或 Linux 中源代码的根文件夹是`~/Documents/Java9`，您可以运行以下命令在 JShell 中加载和执行先前显示的源代码：

```java
/open ~/Documents/Java9/java_9_oop_chapter_01_01/example01_01.java

```

在输入先前的命令后，根据我们的配置和操作系统，JShell 将加载和执行先前显示的源代码，并在运行加载的代码片段后显示生成的输出。以下行显示了输出：

```java
Width: 120.25
Height: 35.50
Area: 4268.88
Width: 120.25
Height: 35.50
Perimeter: 311.50

```

现在，在 JShell 中输入以下命令，以列出到目前为止在当前会话中执行的来自源文件的当前活动代码片段：

```java
/list

```

以下行显示了结果。请注意，JShell 使用不同的片段 ID 为不同的方法定义和表达式添加前缀，因为加载的源代码的行为方式与我们逐个输入片段一样：

```java
 1 : float calculateRectanglePerimeter(float width, float height) {
 float perimeter = 2 * (width + height);
 System.out.printf("Width: %.2f\n", width);
 System.out.printf("Height: %.2f\n", height);
 System.out.printf("Perimeter: %.2f\n", perimeter);
 return perimeter;
 }
 2 : float calculateRectangleArea(float width, float height) {
 float area = width * height;
 System.out.printf("Width: %.2f\n", width);
 System.out.printf("Height: %.2f\n", height);
 System.out.printf("Area: %.2f\n", area);
 return area;
 }
 3 : float width = 120.25f;
 4 : float height = 35.50f;

 5 : calculateRectangleArea(width, height);
 6 : calculateRectanglePerimeter(width, height);

```

### 提示

确保在找到书中的源代码时，使用先前解释的`/open`命令，后跟代码文件的路径和文件名，以便在 JShell 中加载和执行代码文件。这样，您就不必输入每个代码片段，而且可以检查在 JShell 中执行代码的结果。

# 测试你的知识

1.  JShell 是：

1.  Java 9 REPL。

1.  在以前的 JDK 版本中等同于`javac`。

1.  Java 9 字节码反编译器。

1.  REPL 的意思是：

1.  运行-扩展-处理-循环。

1.  读取-评估-处理-锁。

1.  读取-评估-打印-循环。

1.  以下哪个命令列出了当前 JShell 会话中创建的所有变量：

1.  `/variables`

1.  `/vars`

1.  `/list-all-variables`

1.  以下哪个命令列出了当前 JShell 会话中创建的所有方法：

1.  `/methods`

1.  `/meth`

1.  `/list-all-methods`

1.  以下哪个命令列出了当前 JShell 会话中迄今为止评估的源代码：

1.  `/source`

1.  `/list`

1.  `/list-source`

# 摘要

在本章中，我们开始了使用 Java 9 进行面向对象编程的旅程。我们学会了如何启动和使用 Java 9 中引入的新实用程序，该实用程序允许我们轻松运行 Java 9 代码片段并打印其结果：JShell。

我们学习了安装 JDK 9 所需的步骤，并了解了使用 REPL 的好处。我们学会了使用 JShell 来运行 Java 9 代码和评估表达式。我们还学会了许多有用的命令和功能。在接下来的章节中，当我们开始使用面向对象的代码时，我们将使用它们。

现在我们已经学会了如何使用 JShell，我们将学会如何识别现实世界的元素，并将它们转化为 Java 9 中支持的面向对象范式的不同组件，这是我们将在下一章中讨论的内容。


# 第二章：通过 JShell 识别 UML 图表和 Java 9 中的现实世界对象

在本章中，我们将学习如何从现实生活中的情况中识别对象。我们将了解，使用对象使得编写更易于理解和重用的代码变得更简单。我们将学习如何识别现实世界的元素，并将它们转化为 Java 9 中支持的面向对象范式的不同组件。我们将：

+   从应用程序需求中识别对象

+   从现实世界中捕捉对象

+   生成类以创建对象

+   识别变量和常量以创建字段

+   识别创建方法的动作

+   使用 UML 图表组织类

+   利用领域专家的反馈来改进我们的类

+   在 JShell 中使用 Java 对象

# 从应用程序需求中识别对象

每当你在现实世界中解决问题时，你都会使用元素并与它们互动。例如，当你口渴时，你拿起一个玻璃杯，倒满水、苏打水或你最喜欢的果汁，然后喝掉。同样，你可以轻松地从现实世界的场景中识别称为对象的元素，然后将它们转化为面向对象的代码。我们将开始学习面向对象编程的原则，以便在 Java 9 编程语言中开发任何类型的应用程序。

现在，我们将想象我们需要开发一个 RESTful Web 服务，这个服务将被移动应用程序和网络应用程序所使用。这些应用程序将具有不同的用户界面和多样化的用户体验。然而，我们不必担心这些差异，因为我们将专注于 Web 服务，也就是说，我们将成为后端开发人员。

艺术家使用不同的几何形状和有机形状的组合来创作艺术品。当然，创作艺术比这个简单的定义要复杂一些，但我们的目标是学习面向对象编程，而不是成为艺术专家。

几何形状由点和线组成，它们是精确的。以下是几何形状的例子：圆形、三角形、正方形、长方形。

有机形状是具有自然外观和弯曲外观的形状。这些形状通常是不规则的或不对称的。我们通常将来自自然界的事物，如动物和植物，与有机形状联系在一起。

当艺术家想要创造通常需要有机形状的事物的抽象解释时，他们使用几何形状。想象一下，Vanessa Pitstop 是一位画家和手工艺品制作人。几年前，她开始在 Instagram 和 YouTube 上上传关于她的艺术作品的视频，并在她的艺术生涯中取得了重要的里程碑：旧金山现代艺术博物馆准备举办她最重要艺术作品的展览。这一特别事件在社交网络网站上产生了巨大的影响，正如通常发生的那样，与这一重要的知名度提升相关的新软件开发任务也随之而来。

Pitstop 是一位非常受欢迎的 YouTuber，她的频道拥有超过四百万的粉丝。许多好莱坞女演员购买了她的艺术品，并在 Instagram 上上传了自拍照，背景是她的艺术作品。她的展览引起了对她作品的巨大额外兴趣，其中一位赞助商想要创建基于几何形状的移动应用程序和网络应用程序，并提供关于所有工具和丙烯颜料的细节，用户需要购买这些工具和颜料来制作艺术品。

Pitstop 草图基本形状，然后用丙烯颜料涂抹它们以构建几何图案。移动应用程序和 Web 应用程序将使用我们的 Web 服务来构建 Pitstop 的预定义图案，基于用户选择的画布大小和一些预定义的颜色方案。我们的 Web 服务将接收画布大小和颜色方案，以生成图案和材料清单。具体来说，Web 服务将提供用户必须购买的不同工具和丙烯颜料管、罐或瓶的清单，以绘制所绘制的图案。最后，用户将能够下订单请求所有或部分建议的材料。

以下图片显示了 Pitstop 的艺术作品的第一个例子，其中包含几何图案。让我们看一下图片，并提取组成图案的物体。

![从应用需求中识别对象](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-jsh/img/00010.jpeg)

以下对象组成了几何图案，具体来说，从上到下的以下 2D 形状：

+   12 个等边三角形

+   6 个正方形

+   6 个矩形

+   28 个圆

+   4 个椭圆

+   28 个圆

+   6 个矩形

+   6 个正方形

+   12 个等边三角形

相当简单地描述组成图案的 108 个物体或 2D 形状。我们能够识别所有这些物体，并指出每个物体的具体 2D 形状。如果我们测量每个三角形，我们会意识到它们是等边三角形。

以下图片显示了 Pitstop 的艺术作品的第二个例子，其中包含几何图案。让我们看一下图片，并提取组成图案的物体。

![从应用需求中识别对象](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-jsh/img/00011.jpeg)

以下对象组成了几何图案，具体来说，从上到下的以下 2D 形状：

+   12 个等边三角形

+   6 个正五边形

+   6 个矩形

+   24 个正六边形

+   4 个椭圆

+   24 个正六边形

+   6 个矩形

+   6 个正五边形

+   12 个等边三角形

这一次，我们可以描述组成图案的 100 个物体或 2D 形状。我们能够识别所有这些物体，并指出每个物体的具体 2D 形状。如果我们测量每个五边形和六边形，我们会意识到它们是正五边形和六边形。

以下图片显示了 Pitstop 的艺术作品的第三个例子，其中包含几何图案。在这种情况下，我们有大量的 2D 形状。让我们看一下图片，只提取图案中包含的不同 2D 形状。这一次，我们不会计算物体的数量。

![从应用需求中识别对象](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-jsh/img/00012.jpeg)

该图案包括以下 2D 形状：

+   等边三角形

+   正方形

+   正五边形

+   正六边形

+   正七边形

+   正八边形

+   正十边形

以下图片显示了 Pitstop 的艺术作品的第四个例子，其中包含几何图案。在这种情况下，我们也有大量的 2D 形状，其中一些与彼此相交。然而，如果我们留意，我们仍然能够识别不同的 2D 形状。让我们看一下图片，只提取图案中包含的不同 2D 形状。我们不会计算物体的数量。

![从应用需求中识别对象](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-jsh/img/00013.jpeg)

该图案包括以下 2D 形状：

+   正五边形

+   正十边形

+   圆形

+   等边三角形

+   正方形

+   正八边形

以下图片显示了 Pitstop 的艺术作品的第五个例子，其中包含几何图案。在这种情况下，我们将从左到右识别形状，因为图案有不同的方向。我们有许多形状相互交叉。让我们看一下图片，只提取图案中包含的不同 2D 形状。我们不会计算物体的数量。

![从应用需求中识别对象](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-jsh/img/00014.jpeg)

该图案包括以下 2D 形状：

+   圆形

+   正八边形

+   等边三角形

+   正方形

+   正八边形

# 捕捉现实世界的物体

我们可以轻松地从 Pitstop 的艺术品中识别出对象。我们了解到每个模式由许多二维几何形状组成，并且我们在分析的所有示例中识别出了她使用的不同形状。现在，让我们专注于 Web 服务的核心需求之一，即计算所需的丙烯酸漆量以制作艺术品。我们必须考虑每个模式中包含的每种二维形状的以下数据，以便计算所需的材料和生产每种形状所需的丙烯酸漆的数量：

+   线颜色

+   周长

+   填充颜色

+   面积

可以使用特定颜色来绘制每个形状的边界线，因此，我们必须计算周长，以便将其用作估算用户必须购买的丙烯酸漆的数量之一，以绘制每个二维形状的边界。然后，我们必须计算面积，以便将其用作估算用户必须购买的丙烯酸漆的数量之一，以填充每个二维形状的区域。

我们必须开始为我们的 Web 服务后端代码进行工作，该代码计算我们在迄今为止分析的所有示例艺术品中识别出的不同二维形状的面积和周长。我们得出结论，Web 服务必须支持以下九种形状的模式：

+   圆

+   椭圆

+   等边三角形

+   正方形

+   矩形

+   正五边形

+   正六边形

+   正八边形

+   正十边形

在进行一些关于二维几何的研究后，我们可以开始编写 Java 9 代码。具体来说，我们可能会编写九种方法来计算先前列举的二维形状的面积，另外九种方法来计算它们的周长。请注意，我们正在谈论将返回计算值的方法，也就是函数。我们停止了对对象的思考，因此，我们将在这条路上遇到一些问题，我们将用面向对象的方法来解决这些问题。

例如，如果我们开始考虑解决问题的方法，一个可能的解决方案是编写以下十八个函数来完成工作：

+   `calculateCircleArea`

+   `calculateEllipseArea`

+   `calculateEquilateralTriangleArea`

+   `calculateSquareArea`

+   `calculateRectangleArea`

+   `calculateRegularPentagonArea`

+   `calculateRegularHexagonArea`

+   `calculateRegularOctagonArea`

+   `calculateRegularDecagonArea`

+   `calculateCirclePerimeter`

+   `calculateEllipsePerimeter`

+   `calculateEquilateralTrianglePerimeter`

+   `calculateSquarePerimeter`

+   `calculateRectanglePerimeter`

+   `calculateRegularPentagonPerimeter`

+   `calculateRegularHexagonPerimeter`

+   `calculateRegularOctagonPerimeter`

+   `calculateRegularDecagonPerimeter`

先前列举的每种方法都必须接收每种形状的必要参数，并返回其计算出的面积或周长。这些函数没有副作用，也就是说，它们不会改变接收到的参数，并且只返回计算出的面积或周长的结果。

现在，让我们暂时忘记方法或函数。让我们回到我们被分配的 Web 服务需求中的真实世界对象。我们必须计算九个元素的面积和周长，这些元素是需求中代表真实物体的九个名词，具体来说是二维形状。我们已经建立了一个包含九个真实世界对象的列表。

在识别了现实生活中的对象并对其进行了一些思考之后，我们可以通过遵循面向对象的范例来开始设计我们的 Web 服务。我们可以创建代表列举的 2D 形状的状态和行为的软件对象，而不是创建一组执行所需任务的方法。这样，不同的对象模拟了现实世界的 2D 形状。我们可以使用这些对象来指定计算面积和周长所需的不同属性。然后，我们可以扩展这些对象以包括计算其他所需值所需的附加数据，例如绘制边界所需的丙烯酸漆的数量。

现在，让我们进入现实世界，思考之前列举的九种形状中的每一种。想象一下，我们必须在纸上绘制每种形状并计算它们的面积和周长。在我们绘制每种形状之后，我们将使用哪些值来计算它们的面积和周长？我们将使用哪些公式？

### 提示

我们在开始编码之前就开始了面向对象的设计，因此，我们将像不了解几何学的许多概念一样工作。例如，我们可以很容易地推广我们用来计算正多边形周长和面积的公式。然而，在大多数情况下，我们不会是该主题的专家，我们必须在可以用面向对象的方法概括行为之前获得一些应用领域的知识。因此，我们将深入研究这个主题，就好像我们对这个主题知之甚少。

下图显示了一个绘制的圆和我们将用来计算其周长和面积的公式。我们只需要半径值，通常标识为**r**。

![捕捉现实世界的对象](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-jsh/img/00015.jpeg)

下图显示了一个绘制的椭圆和我们将用来计算其周长和面积的公式。我们需要半长轴（通常标记为**a**）和半短轴（通常标记为**b**）的值。请注意，提供的周长公式提供了一个不太精确的近似值。我们将稍后更深入地研究这个特定问题。

![捕捉现实世界的对象](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-jsh/img/00016.jpeg)

下图显示了一个绘制的等边三角形和我们将用来计算其周长和面积的公式。这种三角形的三条边相等，三个内角相等于 60 度。我们只需要边长值，通常标识为**a**。

![捕捉现实世界的对象](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-jsh/img/00017.jpeg)

下图显示了一个绘制的正方形和我们将用来计算其周长和面积的公式。我们只需要边长值，通常标识为**a**。

![捕捉现实世界的对象](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-jsh/img/00018.jpeg)

下图显示了一个绘制的矩形和我们将用来计算其周长和面积的公式。我们需要宽度和高度值，通常标识为**w**和**h**。

![捕捉现实世界的对象](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-jsh/img/00019.jpeg)

下图显示了一个绘制的正五边形和我们将用来计算其周长和面积的公式。我们只需要边长值，通常标记为**a**。

![捕捉现实世界的对象](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-jsh/img/00020.jpeg)

下图显示了一个绘制的正六边形和我们将用来计算其周长和面积的公式。我们只需要边长值，通常标记为**a**。

![捕捉现实世下图显示了一个绘制的正八边形和我们将用来计算其周长和面积的公式。我们只需要边长值，通常标记为**a**。![捕捉现实世界的对象](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-jsh/img/00022.jpeg)

下图显示了一个绘制的正十边形和我们将用来计算其周长和面积的公式。我们只需要边长值，通常标记为**a**。

![捕捉现实世界的对象](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-jsh/img/00023.jpeg)

以下表格总结了计算每种形状的周长和面积所需的数据：

| 形状 | 所需数据 |
| --- | --- |
| 圆 | 半径 |
| 椭圆 | 半长轴和半短轴 |
| 等边三角形 | 边长 |
| 正方形 | 边长 |
| 矩形 | 宽度和高度 |
| 正五边形 | 边长 |
| 正六边形 | 边长 |
| 正八边形 | 边长 |
| 正十边形 | 边长 |

每个代表特定形状的对象都封装了我们确定的所需数据。例如，代表椭圆的对象将封装椭圆的半长轴和半短轴值，而代表矩形的对象将封装矩形的宽度和高度值。

### 注意

**数据封装**是面向对象编程的重要支柱之一。

# 生成类以创建对象

假设我们必须绘制和计算三个不同矩形的周长和面积。你最终会得到三个矩形，它们的宽度和高度值以及计算出的周长和面积。有一个蓝图来简化绘制每个具有不同宽度和高度值的矩形的过程将是很好的。

在面向对象编程中，**类**是创建对象的模板定义或蓝图。类是定义对象状态和行为的模型。声明了定义矩形状态和行为的类之后，我们可以使用它来生成代表每个真实世界矩形状态和行为的对象。

### 注意

对象也被称为实例。例如，我们可以说每个`矩形`对象是`Rectangle`类的一个实例。

下图显示了两个名为`rectangle1`和`rectangle2`的矩形实例。这些实例是根据它们指定的宽度和高度值绘制的。我们可以使用`Rectangle`类作为蓝图来生成这两个不同的`Rectangle`实例。请注意，`rectangle1`的宽度和高度值为`36`和`20`，`rectangle2`的宽度和高度值为`22`和`41`。每个实例的宽度和高度值都不同。理解类和通过其使用生成的对象或实例之间的区别非常重要。Java 9 支持的面向对象编程特性允许我们发现我们用来生成特定对象的蓝图。我们将在接下来的章节中使用这些特性。因此，我们可以确定每个对象是否是`Rectangle`类的实例。

![生成类以创建对象](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-jsh/img/00024.jpeg)

下图显示了两个名为`pentagon1`和`pentagon2`的正五边形实例。这些实例是根据它们指定的边长值绘制的。我们可以使用`RegularPentagon`类作为蓝图来生成这两个不同的`RegularPentagon`实例。请注意，`pentagon1`的边长值为`20`，`pentagon2`的边长值为`16`。每个实例的边长值都不同。

![生成类以创建对象](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-jsh/img/00025.jpeg)

下图显示了四个名为`ellipse1`、`ellipse2`、`ellipse3`和`ellipse4`的椭圆实例。这些实例是根据它们指定的半长轴和半短轴值绘制的。我们可以使用`Ellipse`类作为蓝图来生成这四个不同的`Ellipse`实例。请注意，每个椭圆都有其自己特定的半长轴和半短轴值。

![生成类以创建对象](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-jsh/img/00026.jpeg)

我们从 Web 服务需求中识别出了九个完全不同的真实世界对象，因此，我们可以生成以下九个类来创建必要的对象：

+   `圆`

+   `椭圆`

+   `等边三角形`

+   `正方形`

+   `矩形`

+   `正五边形`

+   `正六边形`

+   `正八边形`

+   `正十边形`

### 提示

请注意类名使用**Pascal case**。Pascal case 意味着组成名称的每个单词的第一个字母大写，而其他字母小写。这是 Java 中的编码约定。例如，我们使用`EquilateralTriangle`名称来命名将允许我们生成多个等边三角形的蓝图类。

# 识别变量和常量

我们知道每个形状所需的信息以实现我们的目标。现在，我们必须设计类，包括提供所需数据给每个实例的必要字段。我们必须确保每个类都有必要的字段，封装了对象执行基于我们应用领域的所有任务所需的所有数据。

让我们从`Circle`类开始。我们需要为该类的每个实例，也就是每个圆形对象，知道半径。因此，我们需要一个封装的变量，允许`Circle`类的每个实例指定半径的值。

### 注意

在 Java 9 中，用于封装每个类实例的数据的变量被称为**字段**。每个实例都有其自己独立的字段值。字段允许我们为类的实例定义特征。在其他支持面向对象原则的编程语言中，这些在类中定义的变量被称为**属性**。

`Circle`类定义了一个名为`radius`的浮点字段，其初始值对于该类的任何新实例都等于`0`。创建`Circle`类的实例后，可以更改`radius`属性的值。因此，我们创建后的圆形可以变得更小或更大。

### 提示

请注意字段名称使用**Camel case**。Camel case 意味着第一个字母小写，然后组成名称的每个单词的第一个字母大写，而其他字母小写。这是 Java 中的编码约定，适用于变量和字段。例如，我们使用`radius`名称来存储半径的字段值，而在其他需要这些数据的类中，我们将使用`lengthOfSide`来存储边长的属性值。

想象一下，我们创建了`Circle`类的两个实例。一个实例名为`circle1`，另一个实例名为`circle2`。实例名称允许我们访问每个对象的封装数据，因此，我们可以使用它们来更改暴露字段的值。

Java 9 使用点（`.`）来允许我们访问实例的属性。因此，`circle1.radius`提供了对名为`circle1`的`Circle`实例的半径的访问，`circle2.radius`对名为`circle2`的`Circle`实例也是如此。

### 提示

请注意，命名约定使我们能够区分实例名称（即变量）和类名称。每当我们看到大写字母或首字母大写时，这意味着我们正在谈论一个类，如`Circle`或`Rectangle`。

我们可以将`14`分配给`circle1.radius`，将`39`分配给`circle2.radius`。这样，每个`Circle`实例将对`radius`字段有不同的值。

现在，让我们转到`Rectangle`类。我们必须为该类定义两个浮点字段：`width`和`height`。它们的初始值也将为`0`。然后，我们可以创建四个`Rectangle`类的实例，分别命名为`rectangle1`，`rectangle2`，`rectangle3`和`rectangle4`。

我们可以将下表总结的值分配给`Rectangle`类的四个实例：

| 实例名称 | `width` | `height` |
| --- | --- | --- |
| `rectangle1` | `141` | `281` |
| `rectangle2` | `302` | `162` |
| `rectangle3` | `283` | `73` |
| `rectangle4` | `84` | `214` |

这样，`rectangle1.width` 将等于 `141`，而 `rectangle4.width` 将等于 `84`。`rectangle1` 实例表示宽度为 `141`，高度为 `281` 的矩形。

以下表格总结了我们需要用于 Web 服务后端代码的九个类中定义的浮点字段：

| 类名 | 字段列表 |
| --- | --- |
| `圆` | `半径` |
| `椭圆` | `半短轴` 和 `半长轴` |
| `等边三角形` | `边长` |
| `正方形` | `边长` |
| `矩形` | `宽度` 和 `高度` |
| `正五边形` | `边长` |
| `正六边形` | `边长` |
| `正八边形` | `边长` |
| `正十边形` | `边长` |

### 提示

这些字段是各自类的成员。然而，字段并不是类可以拥有的唯一成员。

请注意，这六个类中有六个具有相同字段：`边长`，具体来说，以下六个类：`等边三角形`，`正方形`，`正五边形`，`正六边形`，`正八边形`和`正十边形`。我们稍后将深入研究这六个类的共同之处，并利用面向对象的特性来重用代码并简化我们的 Web 服务维护。然而，我们刚刚开始我们的旅程，随着我们学习 Java 9 中包含的其他面向对象特性，我们将进行改进。实际上，让我们记住我们正在学习应用领域，并且我们还不是 2D 形状的专家。

下图显示了一个带有九个类及其字段的**UML**（**统一建模语言**）类图。这个图非常容易理解。类名出现在标识每个类的矩形的顶部。与类名相同形状下方的矩形显示了类暴露的所有字段名称，并以加号（**+**）作为前缀。这个前缀表示其后是 UML 中的属性名称和 Java 9 中的字段名称。请注意，下一个 UML 图并不代表我们类的最佳组织。这只是第一个草图。

![识别变量和常量](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-jsh/img/00027.jpeg)

# 识别创建方法的操作

到目前为止，我们设计了九个类，并确定了每个类所需的字段。现在，是时候添加与先前定义的字段一起工作的必要代码片段，以执行所有必要的任务，即计算周长和面积。我们必须确保每个类都有必要的封装函数，以处理对象中指定的属性值来执行所有任务。

让我们暂时忘记不同类之间的相似之处。我们将分别处理它们，就好像我们对几何公式没有必要的了解一样。我们将从`圆`类开始。我们需要一些代码片段，允许该类的每个实例使用`半径`属性的值来计算面积和周长。

### 提示

类中定义的用于封装类的每个实例行为的函数称为**方法**。每个实例都可以访问类暴露的方法集。方法中指定的代码可以使用类中指定的字段。当我们执行一个方法时，它将使用特定实例的字段。每当我们定义方法时，我们必须确保我们将它们定义在一个逻辑的地方，也就是所需数据所在的地方。

当一个方法不需要参数时，我们可以说它是一个**无参数**方法。在这种情况下，我们最初为类定义的所有方法都将是无参数方法，它们只是使用先前定义的字段的值，并使用先前在详细分析每个 2D 形状时显示的公式。因此，我们将能够在不带参数的情况下调用这些方法。我们将开始创建方法，但稍后我们将能够根据特定的 Java 9 功能探索其他选项。

`Circle`类定义了以下两个无参数方法。我们将在`Circle`类的定义中声明这两个方法的代码，以便它们可以访问`radius`属性的值，如下所示：

+   `calculateArea`：此方法返回一个浮点值，表示圆的计算面积。它返回 Pi（`π`）乘以`radius`字段值的平方（*π * radius*²或*π * (radius ^ 2)*）。

+   `calculatePerimeter`：此方法返回一个浮点值，表示圆的计算周长。它返回 Pi（`π`）乘以 2 倍的`radius`字段值（*π * 2 * radius*）。

### 提示

在 Java 9 中，`Math.PI`为我们提供了 Pi 的值。`Math.pow`方法允许我们计算第一个参数的值的幂。我们将在以后学习如何在 Java 9 中编写这些方法。

这些方法没有副作用，也就是说，它们不会对相关实例进行更改。这些方法只是返回计算的值，因此我们认为它们是非变异方法。它们的操作自然由`calculate`动词描述。

Java 9 使用点（`.`）允许我们执行实例的方法。假设我们有两个`Circle`类的实例：`circle1`，`radius`属性为`5`，`circle2`，`radius`属性为`10`。

如果我们调用`circle1.calculateArea()`，它将返回*π * 5*²的结果，约为`78.54`。如果我们调用`square2.calculateArea()`，它将返回*π * 10*²的结果，约为`314.16`。每个实例的`radius`属性值不同，因此执行`calculateArea`方法的结果也不同。

如果我们调用`circle1.calculatePerimeter()`，它将返回*π * 2 * 5*的结果，约为`31.41`。另一方面，如果我们调用`circle2.calculatePerimeter()`，它将返回*π *2 * 10*的结果，约为`62.83`。

现在，让我们转到`Rectangle`类。我们需要两个与`Circle`类指定的相同名称的方法：`calculateArea`和`calculatePerimeter`。此外，这些方法返回相同的类型，不需要参数，因此我们可以像在`Circle`类中一样将它们都声明为无参数方法。然而，这些方法必须以不同的方式计算结果；也就是说，它们必须使用矩形的适当公式，并考虑`width`和`height`字段的值。其他类也需要相同的两个方法。但是，它们每个都将使用相关形状的适当公式。

我们在`Ellipse`类生成的`calculatePerimeter`方法中遇到了特定的问题。对于椭圆来说，周长计算非常复杂，因此有许多提供近似值的公式。精确的公式需要无限系列的计算。我们将使用一个初始公式，它并不是非常精确，但我们以后会找到解决这个问题的方法，并改进结果。初始公式将允许我们返回一个浮点值，该值是椭圆周长的计算近似值。

以下图表显示了更新后的 UML 图表，其中包括九个类、它们的属性和方法。它显示了第二轮的结果：

![识别创建方法的操作](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-jsh/img/00028.jpeg)

# 使用 UML 图表组织类

到目前为止，我们的面向对象的解决方案包括九个类及其字段和方法。然而，如果我们再看看这九个类，我们会注意到它们都有相同的两个方法：`calculateArea`和`calculatePerimeter`。每个类中方法的代码是不同的，因为每个形状使用特殊的公式来计算面积或周长。然而，方法的声明、契约、接口或协议是相同的。这两个方法都有相同的名称，始终没有参数，并返回一个浮点值。因此，它们都返回相同的类型。

当我们谈论这九个类时，我们说我们在谈论九种不同的几何 2D 形状或简单的形状。因此，我们可以概括这九种形状的所需行为、协议或接口。这九种形状必须定义具有先前解释的声明的`calculateArea`和`calculatePerimeter`方法。我们可以创建一个接口来确保这九个类提供所需的行为。

接口是一个名为`Shape`的特殊类，它概括了我们应用程序中的几何 2D 形状的要求。在这种情况下，我们将使用一个特殊的类来工作，我们不会用它来创建实例，但将来我们会使用接口来实现相同的目标。`Shape`类声明了两个没有参数的方法，返回一个浮点值：`calculateArea`和`calculatePerimeter`。然后，我们将这九个类声明为`Shape`类的子类，它们将继承这些定义，并为这些方法的每一个提供特定的代码。

### 提示

`Shape`的子类（`Circle`、`Ellipse`、`EquilateralTriangle`、`Square`、`Rectangle`、`RegularPentagon`、`RegularHexagon`、`RegularOctagon`和`RegularDecagon`）实现这些方法，因为它们提供了代码，同时保持了`Shape`超类中指定的相同方法声明。**抽象**和**层次结构**是面向对象编程的两个主要支柱。我们只是在这个主题上迈出了第一步。

面向对象编程允许我们发现一个对象是否是特定超类的实例。当我们改变这九个类的组织结构，它们成为`Shape`的子类后，`Circle`、`Ellipse`、`EquilateralTriangle`、`Square`、`Rectangle`、`RegularPentagon`、`RegularHexagon`、`RegularOctagon`或`RegularDecagon`的任何实例也是`Shape`类的实例。

事实上，解释抽象并不难，因为当我们说它代表现实世界时，我们说的是面向对象模型的真相。

说一个正十边形是一个形状是有道理的，因此，`RegularDecagon`的一个实例也是`Shape`类的一个实例。`RegularDecagon`的一个实例既是`Shape`（`RegularDecagon`的超类）又是`RegularDecagon`（我们用来创建对象的类）。

下图显示了 UML 图的更新版本，包括超类或基类（`Shape`）、它的九个子类以及它们的属性和方法。请注意，图中使用一条线以箭头结束，将每个子类连接到其超类。您可以将以箭头结束的线读作：线开始的类*是*线结束的类的子类。例如，`Circle`是`Shape`的子类，`Rectangle`是`Shape`的子类。该图显示了第三轮的结果。

![使用 UML 图组织类](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-jsh/img/00029.jpeg)

### 注意

一个类可以是多个子类的超类。

# 使用领域专家的反馈

现在，是时候与我们的领域专家进行会议了，也就是那些对二维几何有着出色知识的人。我们可以使用 UML 图来解释解决方案的面向对象设计。在我们解释了用于抽象行为的不同类之后，领域专家向我们解释了许多形状都有共同之处，并且我们可以进一步概括行为。以下六种形状都是正多边形：

+   一个等边三角形（`EquilateralTriangle`类）有三条边

+   一个正方形（`Square`类）有四条边

+   一个正五边形（`RegularPentagon`类）有五条边

+   一个正六边形（`RegularHexagon`类）有六条边

+   一个正八边形（`RegularOctagon`类）有八条边

+   一个正十边形（`RegularDecagon`类）有十条边

正多边形是既等角又等边的多边形。组成正多边形的所有边都具有相同的长度，并围绕一个共同的中心放置。这样，任意两条边之间的所有角度都是相等的。

以下图片显示了六个正多边形和我们可以用来计算它们周长和面积的通用公式。计算面积的通用公式要求我们计算余切，该余切在公式中缩写为**cot**。

![使用领域专家的反馈](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-jsh/img/00030.jpeg)

### 提示

在 Java 9 中，`Math`类没有提供直接计算余切的方法。但是，它提供了计算正切的方法：`Math.tan`。`x`的余切等于`x`的正切的倒数：`1/ Math.tan(x)`。因此，我们可以用这个公式轻松计算余切。

由于这三种形状使用相同的公式，只是参数（**n**）的值不同，我们可以为这六个正多边形概括所需的接口。该接口是一个名为`RegularPolygon`的特殊类，它定义了一个新的`getSidesCount`方法，返回一个整数值作为边数。`RegularPolygon`类是先前定义的`Shape`类的子类。这是有道理的，因为正多边形确实是一种形状。代表正多边形的六个类成为`RegularPolygon`的子类。然而，`RegularPolygon`类中编写了`calculateArea`和`calculatePerimeter`方法，使用了通用公式。子类编写了`getSidesCount`方法以返回正确的值，如下所示：

+   `EquilateralTriangle`: 3

+   `Square`: 4

+   `RegularPentagon`: 5

+   `RegularHexagon`: 6

+   `RegularOctagon`: 8

+   `RegularDecagon`: 10

`RegularPolygon`类还定义了`lengthOfSide`属性，该属性先前在代表正多边形的三个类中定义。现在，这六个类成为`RegularPolygon`的子类，并继承了`lengthOfSide`属性。以下图显示了 UML 图的更新版本，其中包括新的`RegularPolygon`类和代表正多边形的六个类的更改。代表正多边形的六个类不声明`calculateArea`或`calculatePerimeter`方法，因为这些类从`RegularPolygon`超类继承了这些方法，并且不需要对应用通用公式的这些方法进行更改。

该图显示了第四轮的结果。

![使用领域专家的反馈](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-jsh/img/00031.jpeg)

当我们分析椭圆时，我们提到在计算其周长时存在问题。我们与我们的领域专家交谈，他为我们提供了有关该问题的详细信息。有许多公式可以提供该形状周长的近似值。添加使用其他公式计算周长的附加方法是有意义的。他建议我们使得可以使用以下公式计算周长：

+   *David W. Cantrell*提出的一个公式

+   由 *Srinivasa Aiyangar Ramanujan* 开发的公式的第二个版本

我们将为`Ellipse`类定义以下两个额外的无参数方法。新方法将返回一个浮点值，并解决椭圆形状的特定问题：

+   `calculatePerimeterWithRamanujanII`

+   `calculatePerimeterWithCantrell`

这样，`Ellipse`类将实现`Shape`超类中指定的方法，并添加两个特定方法，这些方法不包括在`Shape`的任何其他子类中。下图显示了更新后的 UML 图中`Ellipse`类的新方法。

该图显示了第五轮的结果：

![使用领域专家的反馈](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-jsh/img/00032.jpeg)

# 测试您的知识

1.  对象也被称为：

1.  子类。

1.  字段。

1.  实例。

1.  以下哪个类名遵循帕斯卡命名约定，并且是 Java 9 中类的适当名称：

1.  `regularDecagon`

1.  `RegularDecagon`

1.  `Regulardecagon`

1.  在类的方法中指定的代码：

1.  可以访问类中指定的字段。

1.  无法与类的其他成员交互。

1.  无法访问类中指定的字段。

1.  在一个类中定义的函数，用于封装类的每个实例的行为，被称为：

1.  子类。

1.  字段。

1.  方法。

1.  子类：

1.  仅从其超类继承方法。

1.  仅从其超类继承字段。

1.  继承其超类的所有成员。

1.  在 Java 9 中，用于封装类的每个实例的数据的变量被称为：

1.  字段。

1.  方法。

1.  子类。

1.  在 Java 9 中，用于封装类的每个实例的数据的变量被称为：

1.  字段。

1.  方法。

1.  子类。

1.  以下哪个字段名称遵循驼峰命名约定，并且是 Java 9 中字段的适当名称：

1.  `SemiMinorAxis`

1.  `semiMinorAxis`

1.  `semiminoraxis`

# 摘要

在本章中，您学会了如何识别现实世界的元素，并将它们转化为 Java 9 中支持的面向对象范式的不同组件：类、字段、方法和实例。您了解到类代表了生成对象的蓝图或模板，也被称为实例。

我们设计了一些具有字段和方法的类，这些类代表了现实生活中的蓝图，具体来说是 2D 形状。然后，我们通过利用抽象的力量和专门化不同的类来改进了初始设计。随着我们添加了超类和子类，我们生成了初始 UML 图的许多版本。我们了解了应用领域，并随着知识的增加和我们意识到能够概括行为，我们对原始设计进行了更改。

现在您已经学会了面向对象范式的一些基础知识，我们准备在 Java 9 中使用 JShell 创建类和实例，这是我们将在下一章讨论的内容。是时候开始面向对象编码了！


# 第三章：类和实例

在本章中，我们将开始使用 Java 9 中如何编写类和自定义实例初始化的示例。我们将了解类如何作为生成实例的蓝图工作，并深入了解垃圾回收机制。我们将：

+   在 Java 9 中理解类和实例

+   处理对象初始化及其自定义

+   了解对象的生命周期

+   介绍垃圾回收

+   声明类

+   自定义构造函数和初始化

+   了解垃圾回收的工作原理

+   创建类的实例并了解其范围

# 在 Java 9 中理解类和实例

在上一章中，我们学习了面向对象范式的一些基础知识，包括类和对象。我们开始为与 2D 形状相关的 Web 服务的后端工作。我们最终创建了一个具有许多类结构的 UML 图，包括它们的层次结构、字段和方法。现在是利用 JShell 开始编写基本类并在 JShell 中使用其实例的时候了。

在 Java 9 中，类始终是类型和蓝图。对象是类的工作实例，因此对象也被称为**实例**。

### 注意

类在 Java 9 中是一流公民，它们将是我们面向对象解决方案的主要构建块。

一个或多个变量可以持有对实例的引用。例如，考虑以下三个`Rectangle`类型的变量：

+   `矩形 1`

+   `矩形 2`

+   `矩形 10`

+   `矩形 20`

假设`rectangle1`变量持有对`Rectangle`类实例的引用，其`width`设置为`36`，`height`设置为`20`。`rectangle10`变量持有对`rectangle1`引用的相同实例。因此，我们有两个变量持有对相同的`Rectangle`对象的引用。

`rectangle2`变量持有对`Rectangle`类实例的引用，其`width`设置为`22`，`height`设置为`41`。`rectangle20`变量持有对`rectangle2`引用的相同实例。我们还有另外两个变量持有对相同的`Rectangle`对象的引用。

下图说明了许多`Rectangle`类型的变量持有对单个实例的引用的情况。变量名位于左侧，带有宽度和高度值的矩形代表`Rectangle`类的特定实例。

![在 Java 9 中理解类和实例](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-jsh/img/00033.jpeg)

在本章的后面，我们将在 JShell 中使用许多持有对单个实例的引用的变量。

# 处理对象初始化及其自定义

当您要求 Java 创建特定类的实例时，底层会发生一些事情。Java 创建指定类型的新实例，**JVM**（**Java 虚拟机**）分配必要的内存，然后执行构造函数中指定的代码。

当 Java 执行构造函数中的代码时，类已经存在一个活动实例。因此，构造函数中的代码可以访问类中定义的字段和方法。显然，我们必须小心构造函数中放置的代码，因为我们可能会在创建类的实例时产生巨大的延迟。

### 提示

构造函数非常有用，可以执行设置代码并正确初始化新实例。

让我们忘记我们之前为代表 2D 形状的类工作的层次结构。想象一下，我们必须将`Circle`类编码为一个独立的类，不继承自任何其他类。在我们调用`calculateArea`或`calculatePerimeter`方法之前，我们希望每个新的`Circle`实例的`半径`字段都有一个初始化为代表圆的适当值的值。我们不希望创建新的`Circle`实例而不指定`半径`字段的适当值。

### 提示

当我们想要在创建实例后立即为类的实例的字段定义值，并在访问引用创建的实例的变量之前使用构造函数时，构造函数非常有用。事实上，创建特定类的实例的唯一方法是使用我们提供的构造函数。

每当我们需要在创建实例时提供特定参数时，我们可以声明许多不同的构造函数，其中包含必要的参数，并使用它们来创建类的实例。构造函数允许我们确保没有办法创建特定的类，而不使用提供必要参数的构造函数。因此，如果提供的构造函数需要一个`半径`参数，那么我们将无法创建类的实例，而不指定`半径`参数的值。

想象一下，我们必须将`Rectangle`类编码为一个独立的类，不继承自任何其他类。在我们调用`calculateArea`或`calculatePerimeter`方法之前，我们希望每个新的`Rectangle`实例的`宽度`和`高度`字段都有一个初始化为代表每个矩形的适当值的值。我们不希望创建新的`Rectangle`实例而不指定`宽度`和`高度`字段的适当值。因此，我们将为这个类声明一个需要`宽度`和`高度`值的构造函数。

# 引入垃圾收集

在某个特定时间，您的应用程序将不再需要使用实例。例如，一旦您计算了圆的周长，并且已经在 Web 服务响应中返回了必要的数据，您就不再需要继续使用特定的`Circle`实例。一些编程语言要求您小心地保留活动实例，并且必须显式销毁它们并释放它们消耗的内存。

Java 提供了自动内存管理。JVM 运行时使用垃圾收集机制，自动释放不再被引用的实例使用的内存。垃圾收集过程非常复杂，有许多不同的算法及其优缺点，JVM 有特定的考虑因素，应该考虑避免不必要的巨大内存压力。然而，我们将专注于对象的生命周期。在 Java 9 中，当 JVM 运行时检测到您不再引用实例，或者最后一个保存对特定实例的引用的变量已经超出范围时，它会使实例准备好成为下一个垃圾收集周期的一部分。

例如，让我们考虑我们先前的例子，其中有四个变量保存对`Rectangle`类的两个实例的引用。考虑到`rectangle1`和`rectangle2`变量都超出了范围。被`rectangle1`引用的实例仍然被`rectangle10`引用，而被`rectangle2`引用的实例仍然被`rectangle20`引用。因此，由于仍在被引用，没有一个实例可以从内存中删除。下图说明了这种情况。超出范围的变量在右侧有一个 NO 标志。

![引入垃圾收集](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-jsh/img/00034.jpeg)

在`rectangle10`超出范围后，它引用的实例变得可处理，因此可以安全地添加到可以从内存中删除的对象列表中。以下图片说明了这种情况。准备从内存中删除的实例具有回收符号。

![引入垃圾收集](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-jsh/img/00035.jpeg)

在`rectangle20`超出范围后，它引用的实例变得可处理，因此可以安全地添加到可以从内存中删除的对象列表中。以下图片说明了这种情况。这两个实例都准备从内存中删除，它们都有一个回收符号。

![引入垃圾收集](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-jsh/img/00036.jpeg)

### 注意

JVM 会在后台自动运行垃圾收集过程，并自动回收那些准备进行垃圾收集且不再被引用的实例所消耗的内存。我们不知道垃圾收集过程何时会发生在特定实例上，也不应该干预这个过程。Java 9 中的垃圾收集算法已经得到改进。

想象一下，我们必须分发我们存放在盒子里的物品。在我们分发所有物品之后，我们必须将盒子扔进回收站。当我们还有一个或多个物品在盒子里时，我们不能将盒子扔进回收站。我们绝对不想丢失我们必须分发的物品，因为它们非常昂贵。

这个问题有一个非常简单的解决方案：我们只需要计算盒子中剩余物品的数量。当盒子中的物品数量达到零时，我们可以摆脱盒子，也就是说，我们可以将其扔进回收站。然后，垃圾收集过程将移除所有被扔进回收站的物品。

### 提示

幸运的是，我们不必担心将实例扔进回收站。Java 会自动为我们做这些。对我们来说完全透明。

一个或多个变量可以持有对类的单个实例的引用。因此，在 Java 可以将实例放入准备进行垃圾收集的列表之前，有必要考虑对实例的引用数量。当对特定实例的引用数量达到零时，可以安全地从内存中删除该实例并回收该实例消耗的内存，因为没有人再需要这个特定的实例。此时，实例已准备好被垃圾收集过程移除。

例如，我们可以创建一个类的实例并将其分配给一个变量。Java 将知道有一个引用指向这个实例。然后，我们可以将相同的实例分配给另一个变量。Java 将知道有两个引用指向这个单一实例。

在第一个变量超出范围后，仍然可以访问持有对实例的引用的第二个变量。Java 将知道仍然有另一个变量持有对这个实例的引用，因此该实例不会准备进行垃圾收集。此时，实例仍然必须可用，也就是说，我们需要它存活。

在第二个变量超出范围后，没有更多的变量持有对实例的引用。此时，Java 将标记该实例为准备进行垃圾收集，因为没有更多的变量持有对该实例的引用，可以安全地从内存中删除。

# 声明类

以下行声明了一个新的最小`Rectangle`类在 Java 中。示例的代码文件包含在`java_9_oop_chapter_03_01`文件夹中的`example03_01.java`文件中。

```java
class Rectangle {
}
```

`class`关键字，后面跟着类名（`Rectangle`），构成了类定义的头部。在这种情况下，我们没有为`Rectangle`类指定父类或超类。大括号（`{}`）对在类头部之后包围了类体。在接下来的章节中，我们将声明从另一个类继承的类，因此它们将有一个超类。在这种情况下，类体是空的。`Rectangle`类是我们可以在 Java 9 中声明的最简单的类。

### 注意

任何你创建的新类，如果没有指定超类，将会是`java.lang.Object`类的子类。因此，`Rectangle`类是`java.lang.Object`的子类。

以下行代表了创建`Rectangle`类的等效方式。然而，我们不需要指定类继承自`java.lang.Object`，因为这会增加不必要的样板代码。示例的代码文件包含在`java_9_oop_chapter_03_01`文件夹中的`example03_02.java`文件中。

```java
class Rectangle extends java.lang.Object {
}
```

# 自定义构造函数和初始化

我们希望用新矩形的宽度和高度值来初始化`Rectangle`类的实例。为了做到这一点，我们可以利用之前介绍的构造函数。构造函数是特殊的类方法，在我们创建给定类型的实例时会自动执行。在类内部的任何其他代码之前，Java 会运行构造函数内的代码。

我们可以定义一个构造函数，它接收宽度和高度值作为参数，并用它来初始化具有相同名称的字段。我们可以定义尽可能多的构造函数，因此我们可以提供许多不同的初始化类的方式。在这种情况下，我们只需要一个构造函数。

以下行创建了一个`Rectangle`类，并在类体内定义了一个构造函数。此时，我们并没有使用访问修饰符，因为我们希望保持类声明尽可能简单。我们稍后会使用它们。示例的代码文件包含在`java_9_oop_chapter_03_01`文件夹中的`example03_03.java`文件中。

```java
class Rectangle {
    double width;
    double height;

    Rectangle(double width, double height) {
        System.out.printf("Initializing a new Rectangle instance\n");
        System.out.printf("Width: %.2f, Height: %.2f\n", 
            width, height);
        this.width = width;
        this.height = height;
    }
}
```

构造函数是一个使用与类相同名称的类方法：`Rectangle`。在我们的示例`Rectangle`类中，构造函数接收`double`类型的两个参数：`width`和`height`。构造函数内的代码打印一条消息，指示代码正在初始化一个新的`Rectangle`实例，并打印`width`和`height`的值。这样，我们将了解构造函数内的代码何时被执行。因为构造函数有一个参数，它被称为**参数化构造函数**。

然后，以下行将作为参数接收的`width`双精度值分配给`width`双精度字段。我们使用`this.width`来访问实例的`width`字段，使用`width`来引用参数。`this`关键字提供了对已创建的实例的访问，我们希望初始化的对象，也就是正在构建的对象。我们使用`this.height`来访问实例的`height`字段，使用`height`来引用参数。

构造函数之前的两行声明了`width`和`height`双精度字段。这两个字段是成员变量，在构造函数执行完毕后我们可以无限制地访问它们。

以下行创建了`Rectangle`类的四个实例，分别命名为`rectangle1`、`rectangle2`、`rectangle3`和`rectangle4`。示例的代码文件包含在`java_9_oop_chapter_03_01`文件夹中的`example03_04.java`文件中。

```java
Rectangle rectangle1 = new Rectangle(31.0, 21.0);
Rectangle rectangle2 = new Rectangle(182.0, 32.0);
Rectangle rectangle3 = new Rectangle(203.0, 23.0);
Rectangle rectangle4 = new Rectangle(404.0, 14.0);
```

创建实例的每一行都指定了新变量（`Rectangle`）的类型，然后是将保存对新实例的引用的变量名（`rectangle1`、`rectangle2`、`rectangle3`或`rectangle4`）。然后，每一行都分配了使用`new`关键字后跟由逗号分隔并括在括号中的`width`和`height`参数的所需值的结果。

### 提示

在 Java 9 中，我们必须指定要保存对实例的引用的变量的类型。在这种情况下，我们使用`Rectangle`类型声明每个变量。如果您有其他编程语言的经验，这些语言提供了一个关键字来生成隐式类型的局部变量，比如 C#中的`var`关键字，您必须知道在 Java 9 中没有相应的关键字。

在我们输入了声明类和在 JShell 中创建了四个实例的所有行之后，我们将看到四条消息，这些消息说“正在初始化新的 Rectangle 实例”，然后是在构造函数调用中指定的宽度和高度值。以下截图显示了在 JShell 中执行代码的结果：

![自定义构造函数和初始化](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-jsh/img/00037.jpeg)

在执行了前面的行之后，我们可以检查我们创建的每个实例的`width`和`height`字段的值。以下行显示了 JShell 可以评估的表达式，以显示每个字段的值。示例的代码文件包含在`java_9_oop_chapter_03_01`文件夹中的`example03_05.java`文件中。

```java
rectangle1.width
rectangle1.height
rectangle2.width
rectangle2.height
rectangle3.width
rectangle3.height
rectangle4.width
rectangle4.height
```

以下截图显示了在 JShell 中评估先前表达式的结果。

![自定义构造函数和初始化](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-jsh/img/00038.jpeg)

在 JShell 中输入以下表达式。示例的代码文件包含在`java_9_oop_chapter_03_01`文件夹中的`example03_06.java`文件中。

```java
rectangle1 instanceof Rectangle
```

JShell 将显示`true`作为对先前表达式的评估结果，因为`rectangle1`是`Rectangle`类的一个实例。`instanceof`关键字允许我们测试对象是否为指定类型。使用此关键字，我们可以确定对象是否为`Rectangle`对象。

如前所述，`Rectangle`是`java.lang.Object`类的一个子类。JShell 已经从`java.lang`导入了所有类型，因此，我们可以将这个类简称为`Object`。在 JShell 中输入以下表达式。示例的代码文件包含在`java_9_oop_chapter_03_01`文件夹中的`example03_07.java`文件中。

```java
rectangle1 instanceof Object
```

JShell 将显示`true`作为对先前表达式的评估结果，因为`rectangle1`也是`java.lang.Object`类的一个实例。

在 JShell 中输入以下表达式。示例的代码文件包含在`java_9_oop_chapter_03_01`文件夹中的`example03_08.java`文件中。

```java
rectangle1.getClass().getName()
```

JShell 将显示`"Rectangle"`作为先前行的结果，因为`rectangle1`变量持有`Rectangle`类的一个实例。`getClass`方法允许我们检索对象的运行时类。该方法是从`java.lang.Object`类继承的。`getName`方法将运行时类型转换为字符串。

现在，我们将尝试创建一个`Rectangle`的实例，而不提供参数。以下行不会允许 Java 编译代码，并且将在 JShell 中显示构建错误，因为编译器找不到在`Rectangle`类中声明的无参数构造函数。对于这个类声明的唯一构造函数需要两个`double`参数，因此，Java 不允许创建未指定`width`和`height`值的`Rectangle`实例。示例的代码文件包含在`java_9_oop_chapter_03_01`文件夹中的`example03_09.java`文件中。

```java
Rectangle rectangleError = new Rectangle();
```

下一张截图显示了详细的错误消息：

![自定义构造函数和初始化](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-jsh/img/00039.jpeg)

# 了解垃圾回收的工作原理

```java
TipYou can follow best practices to release resources without having to add code to the `finalize` method. Remember that you don't know exactly when the `finalize` method is going to be executed. Even when the reference count reaches zero and all the variables that hold a reference have gone out of scope, the garbage collection algorithm implementation might keep the resources until the appropriate garbage collection destroys the instances. Thus, it is never a good idea to use the `finalize` method to release resources.
```

以下行显示了`Rectangle`类的新完整代码。新的行已经突出显示。示例的代码文件包含在`java_9_oop_chapter_03_01`文件夹中的`example03_10.java`文件中。

```java
class Rectangle {
    double width;
    double height;

    Rectangle(double width, double height) {
        System.out.printf("Initializing a new Rectangle instance\n");
        System.out.printf("Width: %.2f, Height: %.2f\n", 
            width, height);
        this.width = width;
        this.height = height;
    }

 // The following code doesn't represent a best practice
 // It is included just for educational purposes
 // and to make it easy to understand how the
 // garbage collection process works
 @Override
 protected void finalize() throws Throwable {
 try {
 System.out.printf("Finalizing Rectangle\n");
 System.out.printf("Width: %.2f, Height: %.2f\n", width, height);
 } catch(Throwable t){
 throw t;
 } finally{
 super.finalize();
 }
 }
}
```

新的行声明了一个`finalize`方法，覆盖了从`java.lang.Object`继承的方法，并打印一条消息，指示正在完成`Rectangle`实例，并显示实例的宽度和高度值。不要担心你尚不理解的代码片段，因为我们将在接下来的章节中学习它们。包含在类中的新代码的目标是让我们知道垃圾收集过程何时将对象从内存中删除。

### 提示

避免编写覆盖`finalize`方法的代码。Java 9 不鼓励使用`finalize`方法执行清理操作。

以下行创建了两个名为`rectangleToCollect1`和`rectangleToCollect2`的`Rectangle`类实例。然后，下一行将`null`分配给这两个变量，因此，两个对象的引用计数都达到了零，它们已准备好进行垃圾收集。这两个实例可以安全地从内存中删除，因为作用域中没有更多变量持有对它们的引用。示例的代码文件包含在`java_9_oop_chapter_03_01`文件夹中的`example03_11.java`文件中。

```java
Rectangle rectangleToCollect1 = new Rectangle(51, 121);
Rectangle rectangleToCollect2 = new Rectangle(72, 282);
rectangleToCollect1 = null;
rectangleToCollect2 = null;
```

以下截图显示了在 JShell 中执行上述行的结果：

![理解垃圾收集的工作原理](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-jsh/img/00040.jpeg)

两个矩形实例可以安全地从内存中删除，但我们没有看到消息表明对这些实例的`finalize`方法已被执行。请记住，我们不知道垃圾收集过程何时确定有必要回收这些实例使用的内存。

为了理解垃圾收集过程的工作原理，我们将强制进行垃圾收集。但是，非常重要的是要理解，在实际应用中我们不应该强制进行垃圾收集。我们必须让 JVM 在最合适的时机执行收集。

下一行显示了调用`System.gc`方法强制 JVM 执行垃圾收集的代码。示例的代码文件包含在`java_9_oop_chapter_03_01`文件夹中的`example03_12.java`文件中。

```java
System.gc();
```

以下截图显示了在 JShell 中执行上述行的结果。我们将看到表明两个实例的`finalize`方法已被调用的消息。

![理解垃圾收集的工作原理](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-jsh/img/00041.jpeg)

以下行创建了一个名为`rectangle5`的`Rectangle`类实例，然后将一个引用分配给`referenceToRectangle5`变量。这样，对象的引用计数增加到两个。下一行将`null`分配给`rectangle5`，使得对象的引用计数从两个减少到一个。`referenceToRectangle5`变量仍然持有对`Rectangle`实例的引用，因此，下一行强制进行垃圾收集不会将实例从内存中删除，我们也不会看到在`finalize`方法中代码执行的结果。仍然有一个在作用域中持有对实例的引用的变量。示例的代码文件包含在`java_9_oop_chapter_03_01`文件夹中的`example03_13.java`文件中。

```java
Rectangle rectangle5 = new Rectangle(50, 550);
Rectangle referenceToRectangle5 = rectangle5;
rectangle5 = null;
System.gc();
```

以下截图显示了在 JShell 中执行上述行的结果：

![理解垃圾收集的工作原理](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-jsh/img/00042.jpeg)

现在，我们将执行一行代码，将`null`分配给`referenceToRectangle5`，以使引用实例的引用计数达到零，并在下一行强制运行垃圾收集过程。示例的代码文件包含在`java_9_oop_chapter_03_01`文件夹中的`example03_14.java`文件中。

```java
referenceToRectangle5 = null;
System.gc();
```

以下截图显示了在 JShell 中执行前几行的结果。我们将看到指示实例的`finalize`方法已被调用的消息。

![了解垃圾回收的工作原理](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-jsh/img/00043.jpeg)

### 提示

非常重要的是，你不需要将引用赋值为`null`来强制 JVM 从对象中回收内存。在前面的例子中，我们想要了解垃圾回收的工作原理。Java 会在对象不再被引用时自动以透明的方式销毁对象。

# 创建类的实例并了解它们的作用域

我们将编写几行代码，在`getGeneratedRectangleHeight`方法的作用域内创建一个名为`rectangle`的`Rectangle`类的实例。方法内的代码使用创建的实例来访问并返回其`height`字段的值。在这种情况下，代码使用`final`关键字作为`Rectangle`类型的前缀来声明对`Rectangle`实例的**不可变引用**。

### 注意

不可变引用也被称为常量引用，因为我们不能用另一个`Rectangle`实例替换`rectangle`常量持有的引用。

在定义新方法后，我们将调用它并强制进行垃圾回收。示例的代码文件包含在`java_9_oop_chapter_03_01`文件夹中的`example03_15.java`文件中。

```java
double getGeneratedRectangleHeight() {
    final Rectangle rectangle = new Rectangle(37, 87);
    return rectangle.height; 
}

System.out.printf("Height: %.2f\n", getGeneratedRectangleHeight());
System.gc();
```

以下截图显示了在 JShell 中执行前几行的结果。我们将看到在调用`getGeneratedRectangleHeight`方法后，指示实例的`finalize`方法已被调用，并在下一次强制垃圾回收时的消息。当方法返回一个值时，矩形会超出作用域，因为它的引用计数从 1 下降到 0。

通过不可变变量引用的实例是安全的垃圾回收。因此，当我们强制进行垃圾回收时，我们会看到`finalize`方法显示的消息。

![创建类的实例并了解它们的作用域](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-jsh/img/00044.jpeg)

# 练习

现在你了解了对象的生命周期，是时候在 JShell 中花一些时间创建新的类和实例了。

## 练习 1

1.  创建一个新的`Student`类，其中包含一个需要两个`String`参数`firstName`和`lastName`的构造函数。使用这些参数来初始化与参数同名的字段。在创建类的实例时显示一个带有`firstName`和`lastName`值的消息。

1.  创建`Student`类的实例并将其分配给一个变量。检查在 JShell 中打印的消息。

1.  创建`Student`类的实例并将其分配给一个变量。检查在 JShell 中打印的消息。

## 练习 2

1.  创建一个接收两个`String`参数`firstName`和`lastName`的函数。使用接收到的参数来创建先前定义的`Student`类的实例。使用实例属性打印一个带有名字和姓氏的消息。稍后你可以创建一个方法并将其添加到`Student`类中来执行相同的任务。但是，我们将在接下来的章节中了解更多相关内容。

1.  使用必要的参数调用先前创建的函数。检查在 JShell 中打印的消息。

# 测试你的知识

1.  当 Java 执行构造函数中的代码时：

1.  我们无法访问类中定义的任何成员。

1.  该类已经存在一个活动实例。我们可以访问类中定义的方法，但无法访问其字段。

1.  该类已经存在一个活动实例，我们可以访问它的成员。

1.  构造函数非常有用：

1.  执行设置代码并正确初始化一个新实例。

1.  在实例被销毁之前执行清理代码。

1.  声明将对类的所有实例可访问的方法。

1.  Java 9 使用以下机制之一来自动释放不再被引用的实例使用的内存：

1.  实例映射减少。

1.  垃圾压缩。

1.  垃圾收集。

1.  Java 9 允许我们定义：

1.  一个主构造函数和两个可选的次要构造函数。

1.  许多具有不同参数的构造函数。

1.  每个类只有一个构造函数。

1.  我们创建的任何不指定超类的新类都将是一个子类：

1.  `java.lang.Base`

1.  `java.lang.Object`

1.  `java.object.BaseClass`

1.  以下哪行创建了`Rectangle`类的一个实例并将其引用分配给`rectangle`变量：

1.  `var rectangle = new Rectangle(50, 20);`

1.  `auto rectangle = new Rectangle(50, 20);`

1.  `Rectangle rectangle = new Rectangle(50, 20);`

1.  以下哪行访问了`rectangle`实例的`width`字段：

1.  `rectangle.field`

1.  `rectangle..field`

1.  `rectangle->field`

# 摘要

在本章中，您了解了对象的生命周期。您还了解了对象构造函数的工作原理。我们声明了我们的第一个简单类来生成对象的蓝图。我们了解了类型、变量、类、构造函数、实例和垃圾收集是如何在 JShell 中的实时示例中工作的。

现在您已经学会了开始创建类和实例，我们准备在 Java 9 中包含的数据封装功能中分享、保护、使用和隐藏数据，这是我们将在下一章讨论的内容。
