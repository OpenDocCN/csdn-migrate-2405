# Java 12 编程学习手册（一）

> 原文：[Learn Java 12 Programming ](https://libgen.rs/book/index.php?md5=2D05FE7A99FD37AE2178F1DD99C27887)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 零、前言

本书的目的是让读者对 Java 基础有一个坚实的理解，并引导他们完成一系列从基础到实际编程的实际步骤。讨论和示例旨在通过使用经验证的编程原理和实践来刺激读者专业直觉的增长。这本书从基础知识开始，把读者带到最新的编程技术，从专业的角度考虑。

读完这本书后，你将能够做到以下几点：

*   安装并配置 Java 开发环境
*   安装并配置您的**集成开发环境**（**IDE**）——本质上就是您的编辑器
*   编写、编译和执行 Java 程序和测试
*   了解并使用 Java 语言基础
*   理解并应用面向对象的设计原则
*   掌握最常用的 Java 构造
*   了解如何从 Java 应用访问和管理数据库中的数据
*   增强您对网络编程的理解
*   了解如何添加图形用户界面，以便更好地与应用交互
*   熟悉函数式编程
*   了解最先进的数据处理技术流，包括并行和反应流
*   学习并练习创建微服务和构建反应式系统
*   学习最佳设计和编程实践
*   展望 Java 的未来，学习如何成为它的一部分

# 这本书是给谁的

这本书是为那些想在现代 Java 编程专业中开始一个新的职业生涯的人，以及那些已经从事这项工作并且想更新他们对最新 Java 和相关技术和思想的知识的人准备的。

# 这本书的内容

第 1 章“Java12 入门”从基础开始，首先解释什么是“Java”并定义其主要术语，然后继续介绍如何安装编写和运行（执行）程序所需的工具。本章还描述了基本的 Java 语言构造，并用可以立即执行的示例来说明它们。

第 2 章“面向对象编程（OOP）”介绍了面向对象编程的概念及其在 Java 中的实现。每一个概念都用具体的代码示例来演示。详细讨论了类和接口的 Java 语言结构，以及重载、覆盖、隐藏和使用`final`关键字，最后一节介绍了多态的威力。

第 3 章“Java 基础”向读者展示了 Java 作为一种语言的更详细的观点。它从包中的代码组织开始，描述类（接口）及其方法和属性（字段）的可访问性级别。本文详细介绍了 Java 面向对象特性的主要类型引用类型，然后列出了保留关键字和限制关键字，并讨论了它们的用法。本章最后介绍了原始类型之间的转换方法，以及从原始类型到相应引用类型的转换方法。

第 4 章“处理”向读者介绍了与异常处理相关的 Java 构造的语法以及处理（处理）异常的最佳实践。本章以可用于在生产中调试应用代码的断言语句的相关主题结束。

第 5 章、“字符串、输入/输出和文件”，讨论字符串类方法，以及来自标准库和 ApacheCommons 项目的流行字符串工具。下面概述了 Java 输入/输出流和`java.io`包的相关类以及`org.apache.commons.io`包的一些类。文件管理类及其方法在专门的一节中进行了描述。

第 6 章、“数据结构、泛型和流行工具”介绍了 Java 集合框架及其三个主要接口`List`、`Set`和`Map`，包括泛型的讨论和演示。`equals()`和`hashCode()`方法也在 Java 集合的上下文中讨论。用于管理数组、对象和时间/日期值的工具类也有相应的专用部分。

第 7 章、“Java 标准和外部库”概述了 **Java 类库**（**JCL**）最流行的包的功能：`java.lang`、`java.util`、`java.time`、`java.io`和`java.nio`、`java.sql`和`javax.sql`、`java.net java.lang.math`、`java.math`、`java.awt`、`javax.swing`和`javafx`。最流行的外部库是以`org.junit`、`org.mockito`、`org.apache.log4j`、`org.slf4j`和`org.apache.commons`包为代表的。本章帮助读者避免在已经存在此类功能并且可以直接导入和删除的情况下编写自定义代码开箱即用。

第 8 章、“多线程和并发处理”介绍了通过使用并发处理数据的 worker（线程）来提高 Java 应用性能的方法。它解释了 Java 线程的概念并演示了它们的用法。文中还讨论了并行处理和并发处理的区别，以及如何避免由于并发修改共享资源而导致的不可预知的结果。

第 9 章、“JVM 结构和垃圾收集”为读者提供了 JVM 结构和行为的概述，这些比我们通常预期的要复杂。其中一个服务线程被称为*垃圾收集*，它执行的一项重要任务是从未使用的对象中释放内存。阅读本章后，读者将更好地了解什么是 Java 应用执行、JVM 中的 Java 进程、垃圾收集以及 JVM 的总体工作原理。

第 10 章“管理数据库中的数据”，说明并演示如何管理，即从 Java 应用插入、读取、更新和删除数据库中的数据。本文还简要介绍了 SQL 语言和基本的数据库操作：如何连接到数据库，如何创建数据库结构，如何使用 SQL 编写数据库表达式，以及如何执行它们。

第 11 章、“网络编程”，描述和讨论了最流行的网络协议**用户数据报协议**（**UDP**）、**传输控制协议**（**TCP**）、**超文本传输协议**（**HTTP**）和 WebSocket 及其对 JCL 的支持。它演示了如何使用这些协议，以及如何在 Java 代码中实现客户端服务器通信。所审查的 API 包括基于 URL 的通信和最新的 JavaHTTPClient API。

第 12 章“Java GUI 编程”，概述 Java GUI 技术，并演示如何使用 JavaFX 工具包创建 GUI 应用。JavaFX 的最新版本不仅提供了许多有用的特性，还允许保留和嵌入遗留的实现和样式。

第 13 章、“函数式编程”，解释了什么是函数式接口，概述了 JDK 附带的函数式接口，定义并演示了 Lambda 表达式以及如何与函数式接口一起使用，包括使用方法引用。

第 14 章、“Java 标准流”讲述了数据流的处理，不同于第 5 章、“字符串、输入/输出、文件”中回顾的 I/O 流。它定义了什么是数据流，如何使用`java.util.stream.Stream`对象的方法（操作）处理它们的元素，以及如何在管道中链接（连接）流操作。本文还讨论了流的初始化以及如何并行处理流。

第 15 章“反应式编程”，介绍了反应式宣言和反应式编程的世界。首先定义和讨论了主要的相关概念-“异步”、“非阻塞”、“响应”等。然后使用它们定义并讨论了反应式编程、主要的反应式框架，并更详细地讨论了 RxJava。

第 16 章“微服务”解释了如何构建微服务——创建反应式系统的基础组件。它讨论了什么是微服务，它们可以有多大或多小，以及现有的微服务框架如何支持消息驱动的架构。讨论通过使用 Vert.x 工具箱构建的小型反应式系统的详细代码演示进行了说明。

第 17 章“Java 微基准线束”，介绍了“Java 微基准线束”（**JMH**）项目，该项目允许我们测量各种代码性能特征。它定义了什么是 JMH，如何创建和运行基准，基准参数是什么，并概述了支持的 IDE 插件。本章最后给出了一些实际的演示示例和建议。

第 18 章“编写高质量代码的最佳实践”，介绍了 Java 习惯用法以及设计和编写应用代码的最流行和最有用的实践。

第 19 章“Java 新特性”，讲述当前最重要的项目，这些项目将为 Java 添加新特性并在其他方面增强 Java。在阅读了本章之后，读者将了解如何遵循 Java 开发，并能够预见未来 Java 发行版的路线图。如果需要，读者也可以成为 JDK 源代码贡献者。

# 充分利用这本书

系统地阅读各章，并在每章末尾回答测验问题。克隆或只是下载源代码存储库（请参阅以下部分），然后运行演示所讨论主题的所有代码示例。为了加快编程速度，没有什么比执行提供的示例、修改它们和尝试自己的想法更好的了。密码就是真理。

# 下载示例代码文件

您可以从您的帐户[下载本书的示例代码文件 www.packt.com](http://www.packt.com)。如果您在其他地方购买了本书，您可以访问[www.packt.com/support](http://www.packt.com/support)并注册，将文件直接通过电子邮件发送给您。

您可以通过以下步骤下载代码文件：

1.  在[登录或注册 www.packt.com](http://www.packt.com)
2.  选择“支持”选项卡
3.  点击代码下载和勘误表
4.  在搜索框中输入图书名称，然后按照屏幕上的说明进行操作

下载文件后，请确保使用最新版本的解压缩或解压缩文件夹：

*   用于 Windows 的 WinRAR/7-Zip
*   Mac 的 Zipeg/iZip/UnRarX
*   用于 Linux 的 7-Zip/PeaZip

这本书的代码包也托管[在 GitHub 上](https://github.com/PacktPublishing/Learn-Java-12-Programming)。如果代码有更新，它将在现有 GitHub 存储库中更新。

我们的丰富书籍和视频目录中还有其他代码包，可在[这个页面](https://github.com/PacktPublishing/)上找到。看看他们！

# 下载彩色图像

我们还提供了一个 PDF 文件，其中包含本书中使用的屏幕截图/图表的彩色图像。[您可以在这里下载](https://www.packtpub.com/sites/default/files/downloads/9781789957051_ColorImages.pdf)。

# 使用的约定

这本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码字、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄。下面是一个示例：“当在一个`try`块中抛出异常时，它将控制流重定向到第一个`catch`子句。”

代码块设置如下：

```java
void someMethod(String s){
    try {
        method(s);
    } catch (NullPointerException ex){
        //do something
    } catch (Exception ex){
        //do something else
    }
}
```

当我们希望提请您注意代码块的特定部分时，相关行或项以粗体显示：

```java
class TheParentClass {
    private int prop;
 public TheParentClass(int prop){
        this.prop = prop;
    }
    // methods follow
}
```

任何命令行输入或输出的编写方式如下：

```java
--module-path /path/JavaFX/lib \
 :-add-modules=javafx.controls,javafx.fxml
```

**粗体**：表示一个新术语、一个重要单词或屏幕上显示的单词。例如，菜单或对话框中的单词会像这样出现在文本中。下面是一个示例：“为项目 SDK（Java 版本 12，如果您已经安装了 JDK12）选择一个值，然后单击‘下一步’。”

警告或重要提示如下所示。

提示和窍门是这样出现的。

# 一、Java12 入门

本章介绍如何开始学习 Java12 和 Java。我们将从基础知识开始，首先解释什么是 Java 及其主要术语，然后介绍如何安装必要的工具来编写和运行（执行）程序。在这方面，Java12 与以前的 Java 版本没有太大区别，因此本章的内容也适用于旧版本。

我们将描述并演示构建和配置 Java 编程环境的所有必要步骤。这是最低限度，你必须在电脑上，以开始编程。我们还描述了基本的 Java 语言构造，并用可以立即执行的示例加以说明。

学习编程语言或任何语言的最好方法就是使用它，本章将指导读者如何使用 Java 实现这一点。本章涵盖的主题包括：

*   如何安装和运行 Java
*   如何安装并运行**集成开发环境**（**IDE**）
*   Java 原始类型和运算符
*   字符串类型和字面值
*   标识符和变量
*   Java 语句

# 如何安装和运行 Java

当有人说“Java”时，他们的意思可能完全不同：

*   **Java 程序设计语言**：一种高级程序设计语言，允许以人类可读的格式表达意图（程序），并将其翻译成计算机可执行的二进制代码
*   **Java 编译器**：一种程序，它能读取用 Java 编程语言编写的文本，并将其翻译成字节码，由 **Java 虚拟机**（**JVM**）解释成计算机可执行的二进制代码
*   **Java 虚拟机**（**JVM**）：一种程序，它读取已编译的 Java 程序，并将其解释为计算机可执行的二进制代码
*   **Java 开发工具包**（**JDK**）：程序（工具和工具）的集合，包括 Java 编译器、JVM 和支持库，允许编译和执行用 Java 语言编写的程序

下一节将引导读者完成 Java12 的 JDK 的安装以及基本的相关术语和命令

# 什么是 JDK？我们为什么需要它？

正如我们已经提到的，JDK 包括一个 Java 编译器和 JVM。编译器的任务是读取一个包含用 Java 编写的程序文本的`.java`文件（称为**源代码**），并将其转换（编译）为存储在`.class`文件中的字节码。然后 JVM 可以读取`.class`文件，将字节码解释为二进制代码，并将其发送到操作系统执行。编译器和 JVM 都必须从命令行显式调用

为了支持`.java`文件编译及其字节码的执行，JDK 安装还包括标准 Java 库 **Java 类库**（**JCL**）。如果程序使用第三方库，则在编译和执行过程中必须存在该程序。它必须从调用编译器的同一命令行中引用，然后在 JVM 执行字节码时引用。另一方面，JCL 不需要显式地引用。假设标准 Java 库位于 JDK 安装的默认位置，因此编译器和 JVM 知道在哪里找到它们

如果您不需要编译 Java 程序，只想运行已经编译的`.class`文件，可以下载安装 **Java 运行时环境**（**JRE**）。例如，它由 JDK 的一个子集组成，不包括编译器。

有时，JDK 被称为**软件开发工具包**（**SDK**），它是一组软件工具和支持库的总称，这些工具和库允许创建使用某种编程语言编写的源代码的可执行版本。因此，JDK 是一个用于 Java 的 SDK。这意味着可以将 JDK 称为 SDK。

您还可能听到与 JDK 相关的术语 **Java 平台**和 **Java 版本**。典型的平台是允许开发和执行软件程序的操作系统。由于 JDK 提供了自己的操作环境，因此也被称为平台。**版**是为特定目的组装的 Java 平台（JDK）的变体。有五个 Java 平台版本，如下所示：

*   **Java 平台标准版**（**Java SE**）：包括 JVM、JCL 等工具和工具。
*   **Java 平台企业版**（**Java EE**）：这包括 Java SE、服务器（为应用提供服务的计算机程序）、JCL 和其他库、代码示例、教程以及用于开发和部署大规模、多层和安全网络应用的其他文档。
*   **Java 平台微型版**（**Java ME**）：这是 Java SE 的一个子集，有一些专门的库，用于为手机、个人数字助理、电视机顶盒、打印机、传感器等嵌入式和移动设备开发和部署 Java 应用。JavaME 的一个变体（有自己的 JVM 实现）称为 **AndroidSDK**。它是由 Google 为 Android 编程开发的。
*   **Java Card**：它是 Java 版本中最小的一个，用于在小型嵌入式设备（如智能卡）上开发和部署 Java 应用。它有两个版本：**Java Card Classic Edition**，用于智能卡，基于 ISO7816 和 ISO14443 通信；以及 **Java Card Connected Edition**，支持 Web 应用模型和 TCP/IP 作为基本协议，运行在高端安全微控制器上。

所以，**安装 Java 就意味着安装 JDK**，这也意味着**在其中一个版本上安装 Java 平台**，在本书中，我们只讨论和使用 JavaSE。

# 安装 Java SE

所有最近发布的 JDK 都列在 Oracle 官方页面上：[www.oracle.com/technetwork/java/javase/overview/index.html](https://www.oracle.com/technetwork/java/javase/overview/index.html)（我们将其称为**安装主页**，以供进一步参考）。

以下是安装 Java SE 需要遵循的步骤：

1.  找到要查找的 JavaSE 版本的链接（本例中是 JavaSE12）并单击它。
2.  您将看到各种链接，其中之一是安装说明。或者，您可以通过单击下载选项卡访问此页面。
3.  单击标题为 OracleJDK 的下载链接。
4.  一个新的屏幕将提供一个单选按钮和指向各种 JDK 安装程序的链表，供您选择接受或拒绝许可协议。
5.  阅读许可协议并做出决定。如果您不接受它，就不能下载 JDK。如果您接受许可协议，您可以从可用列表中选择 JDK 安装程序。
6.  您需要选择适合您的操作系统的安装程序和您熟悉的格式（扩展名）。
7.  如果有疑问，请返回安装主页，选择下载选项卡，然后单击**安装说明**链接。
8.  按照与您的操作系统相对应的步骤进行操作。
9.  当您计算机上的`java -version`命令显示正确的 Java 版本时，JDK 安装成功，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/3a7e798e-2c94-4ef5-8ef2-695f2dd2df16.png)

# 命令、工具和工具

如果按照安装说明进行操作，您可能已经注意到目录下给出的链接（JDK 的已安装目录结构）。它将带您进入一个页面，该页面描述已安装的 JDK 在您的计算机上的位置以及 JDK 根目录的每个目录的内容。`bin`目录包含构成 Java 命令、工具和工具的所有可执行文件。如果目录`bin`没有自动添加到环境变量`PATH`，请考虑手动添加，这样您就可以从任何目录启动 Java 可执行文件。

在上一节中，我们已经演示了`Java`命令`java -version`。其他可用 Java 可执行文件（命令、工具、和工具）[可以在 JavaSE 文档中找到](https://www.oracle.com/technetwork/java/javase/documentation/index.html)。点击链接 Java 平台标准版技术文档站点，然后点击下一页的链接工具参考。您可以通过单击每个可执行工具的链接来了解其更多信息。

您还可以使用以下选项之一在计算机上运行列出的每个可执行文件：`-?`、`-h`、`--help`或`-help`。它将显示可执行文件及其所有选项的简要说明。

最重要的 Java 命令如下：

*   `javac`：根据`.java`文件中定义了多少 Java 类，读取`.java`文件，编译并创建一个或多个相应的`.class`文件。
*   `java`：执行`.class`文件。

这些命令使编程成为可能。每个 Java 程序员都必须很好地理解自己的结构和功能。但是，如果您对 Java 编程不熟悉，并且使用 IDE（请参阅“如何安装和运行 IDE”一节），则不需要立即掌握这些命令。一个好的 IDE 通过在每次更改时自动编译一个`.java`文件来隐藏它们。它还提供了一个图形元素，可以在每次单击它时运行程序。

另一个非常有用的 Java 工具是`jcmd`。它有助于与当前运行的任何 Java 进程（JVM）进行通信和诊断，并且有许多选项。但是在最简单的形式中，没有任何选项，它列出了当前运行的所有 Java 进程及其**进程 ID**（**PID**）。您可以使用它来查看是否已经运行了 Java 进程。如果有，那么可以使用提供的 PID 终止这样的进程。

# 如何安装和运行 IDE

曾经只是一个专门的编辑器，允许像 Word 编辑器检查英语句子的语法一样检查书面程序的语法，逐渐演变成一个**集成开发环境**（**IDE**）。它的主要功能在名称上。它集成了在一个**图形用户界面**（**GUI**）下编写、编译和执行程序所需的所有工具。利用 Java 编译器的强大功能，IDE 可以立即识别语法错误，然后通过提供上下文相关的帮助和建议来帮助提高代码质量

# 选择 IDE

Java 程序员可以使用几种 IDE，如 **NetBeans**、**Eclipse**、**IntelliJ IDEA**、**BlueJ**、**DrJava**、**JDeveloper**、**JCreator**、**jEdit**、**JSource**、**jCRASP** 和 **jEdit** 等等。最流行的是 NetBeans、Eclipse 和 IntelliJ IDEA。

NetBeans 开发始于 1996 年，是布拉格查尔斯大学的一个 JavaIDE 学生项目。1999 年，该项目和围绕该项目创建的公司被 Sun Microsystems 收购。在甲骨文收购 Sun Microsystems 之后，NetBeans 成为了开源软件，许多 Java 开发人员也为这个项目做出了贡献。它与 JDK8 捆绑在一起，成为 Java 开发的官方 IDE。2016 年，Oracle 将其捐赠给了 Apache 软件基金会。

有一个用于 Windows、Linux、Mac 和 Oracle Solaris 的 NetBeans IDE。它支持多种编程语言，并可以扩展插件。NetBeans 只与 JDK8 捆绑在一起，但是 netbeans8.2 也可以与 JDK9 一起工作，并使用 JDK9 引入的特性，例如 Jigsaw。在[上 netbeans.apache.org](https://netbeans.apache.org/)，您可以阅读更多关于 NetBeans IDE 的信息，并下载最新版本，截至本文撰写之时，该版本为 11.0。

Eclipse 是使用最广泛的 JavaIDE。向 IDE 添加新特性的插件列表在不断增长，因此无法列举 IDE 的所有功能。EclipseIDE 项目从 2001 年开始作为开源软件开发。一个非营利性的、成员支持的企业 Eclipse 基金会在 2004 创建，目的是提供基础设施（版本控制系统、代码审查系统、构建服务器、下载站点等等）和结构化的过程。基金会 30 多岁的员工中，没有一个人在从事 150 个 Eclipse 支持的项目。

EclipseIDE 插件的数量和种类之多对初学者来说是一个挑战，因为您必须找到解决相同或类似特性的不同实现的方法，这些实现有时可能是不兼容的，并且可能需要深入的调查以及对所有依赖项的清楚理解。尽管如此，eclipseIDE 还是非常流行，并且有可靠的社区支持。您可以阅读有关 eclipseIDE 的内容，并从[下载最新版本 www.eclipse.org/ide](http://www.eclipse.org/ide/)。

IntelliJ 有两个版本：付费版和免费社区版。付费版一直被评为最佳 Java IDE，但社区版也被列为三大主要 Java IDE 之一。开发该 IDE 的 JetBrains 软件公司在布拉格、圣彼得堡、莫斯科、慕尼黑、波士顿和新西伯利亚设有办事处。IDE 以其深刻的智能而闻名，即“在每一个上下文中都给出相关的建议：即时而巧妙的代码完成、动态的代码分析和可靠的重构工具”，[正如作者在其网站上描述产品时所说](https://www.jetbrains.com/idea/)。在“安装和配置 IntelliJ IDEA”部分，我们将引导您完成 IntelliJ IDEA 社区版的安装和配置。

# 安装和配置 IntelliJ IDEA

下载并安装 IntelliJ IDEA 需要遵循以下步骤：

1.  从[下载 IntelliJ 社区版安装程序 www.jetbrains.com/idea/download](http://www.jetbrains.com/idea/download)。
2.  启动安装程序并接受所有默认值。
3.  在安装选项屏幕上选择.java。我们假设您已经安装了 JDK，所以您不必检查下载和安装 JRE 选项。
4.  最后一个安装屏幕有一个复选框 Run IntelliJ IDEA，您可以选中它来自动启动 IDE。或者，您可以不选中该复选框，并在安装完成后手动启动 IDE。
5.  当 IDE 第一次启动时，它会询问您是否要导入 IntelliJ IDEA 设置。如果您以前没有使用过 IntelliJ IDEA 并且希望重用设置，请选中“不导入设置”复选框。
6.  下面的一两个屏幕询问您是否接受 JetBrains 隐私政策，以及您是否愿意支付许可证费用，还是愿意继续使用免费社区版或免费试用版（这取决于您获得的特定下载）。
7.  以您喜欢的方式回答问题，如果您接受隐私策略，CustomizeIntelliJ IDEA 屏幕将要求您选择一个主题，白色（IntelliJ）或黑色（Darcula）。

8.  如果提供了“全部跳过”和“设置默认值”以及“下一步：默认插件”按钮，请选择“下一步：默认插件”，因为它将为您提供预先配置 IDE 的选项。
9.  在任务屏幕上显示“调整”想法时，请为以下三个选项选择“自定义…”链接，每次一个：

10.  如果您决定更改设置值，您可以稍后通过从最顶部的菜单文件、Windows 上的设置或 Linux 和 MacOS 上的首选项进行选择。

# 创建项目

在开始编写程序之前，您需要创建一个项目。在 IntelliJ IDEA 中创建项目有几种方法，对于任何 IDE 都是一样的，如下所示：

1.  创建新项目：这将从头开始创建一个新项目。
2.  导入项目：这允许从文件系统读取现有的源代码。
3.  打开：这允许从文件系统读取现有项目。
4.  从版本控制签出：这允许从版本控制系统读取现有项目。

在本书中，我们将仅使用 IDE 提供的一系列引导步骤来引导您完成第一个选项。另外两个选项要简单得多，不需要额外的解释。一旦您学会了如何从头开始创建一个新项目，在 IDE 中创建项目的其他方法将非常简单。

首先单击“创建新项目”链接，然后按以下步骤继续操作：

1.  为项目 SDK 选择一个值（Java 版本 12，如果您已经安装了 JDK12），然后单击“下一步”。
2.  不要选中“创建项目模板”（如果选中，IDE 会生成一个固定程序`Hello world`和类似的程序，我们不需要），然后单击“下一步”。

3.  在“项目位置”字段中选择所需的项目位置（这是新代码将驻留的位置）。
4.  在“项目名称”字段中输入您喜欢的任何内容（例如，本书中代码的项目名为`learnjava`，然后单击`Finish`按钮。
5.  您将看到以下项目结构：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/5a917017-f5cc-4006-9be0-46dc22d088c0.png)

6.  右键单击项目名称（`learnjava`），从下拉菜单中选择添加框架支持。在以下弹出窗口中，选择 Maven：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/3fd339d0-ba03-45ff-a8e5-838af334c938.png)

7.  Maven 是一个项目配置工具。它的主要功能是管理项目依赖关系。我们稍后再谈。现在，我们将使用它的另一个职责，使用三个属性来定义和保持项目代码标识：

主要目标是使一个项目的身份在世界上所有项目中独一无二。为了避免`groupId`冲突，约定要求从相反的组织域名开始构建。例如，如果一个公司的域名是`company.com`，那么它的项目的组 ID 应该以`com.company`开头。这就是为什么在本书的代码中，我们使用了`groupId`值`com.packt.learnjava`。

我们开始吧。在弹出的“添加框架支持”窗口中，单击〖确定〗按钮，系统将弹出一个新生成的`pom.xml`文件，如下所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/c55fd0e3-2eae-44af-95b6-37c9d0abd187.png)

同时，在屏幕右下角会弹出另一个小窗口：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/98602cb5-1f08-4a80-871f-a3ea17e0e341.png)

单击“启用自动导入”链接。这将使编写代码更容易：您将开始使用的所有新类都将自动导入。我们将在适当的时候讨论类导入

现在让我们输入`groupId`、`artifactId`和`version`值：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/892763bf-8ab4-4f0d-ad8e-318d9580413d.png)

现在，如果有人想在他们的应用中使用您的项目代码，他们会通过显示的三个值引用它，Maven（如果他们使用它）会将它引入（当然，如果您将您的项目上传到公共共享的 Maven 存储库中）。在[这个页面](https://maven.apache.org/guides/)上阅读更多关于 Maven 的信息。

`groupId`值的另一个功能是定义保存项目代码的文件夹树的根目录。我们打开`src`文件夹，您将看到下面的目录结构：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/c34792dd-dadb-4f53-b009-d99575abd341.png)

`main`下的`java`文件夹保存应用代码，`test`下的`java`文件夹保存测试代码。

让我们使用以下步骤创建第一个程序：

1.  右键点击`java`，选择新建，点击打包：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/77aca3d0-651f-487b-95dd-96684a663d3a.png)

2.  在提供的新包窗口中，键入`com.packt.learnjava.ch01_start`如下：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/e52b0ead-1cbf-42a8-97f3-f0c708d01a62.png)

3.  单击 OK，您应该会在左侧面板中看到一组新文件夹，其中最后一个是`com.packt.learnjava.ch01_start`：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/25ce05c1-44cc-49a3-826c-6e03bdbaa1f0.png)

4.  右键单击它，选择“新建”，然后单击“Java 类”：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/203c5928-cdb9-4da9-9e9d-e6634455c875.png)

5.  在提供的输入窗口中，键入`PrimitiveTypes`：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/fc4c54ce-8d0d-4e28-8745-4f1b936ede26.png)

6.  单击 OK，您将看到在包`com.packt.learnjava.ch01_start`包中创建的第一个 Java 类`PrimitiveTypes`：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/0bc35e35-7f4e-4ea0-a19d-53efeb9e7cb6.png)

包反映了文件系统中 Java 类的位置。我们将在第二章“Java 面向对象编程”中讨论。现在，为了运行一个程序，我们创建了一个`main()`方法。如果存在，可以执行此方法并将其作为应用的入口点。它有一定的格式，如下所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/c15f913b-74ba-4d5c-8c92-eb826dc73230.png)

它必须具有以下属性：

*   `public`：可从包外自由进入
*   `static`：应该能够在不创建所属类的对象的情况下被调用

还应包括以下内容：

*   返回`void`（无）。
*   接受一个`String`数组作为输入，或者像我们所做的那样接受`varargs`。我们将在第二章“Java 面向对象编程（OOP）”中讨论`varargs`。现在，只需说`String[] args`和`String... args`定义了本质上相同的输入格式

我们在“执行来自于命令行的例子”部分中解释了如何使用命令行来运行主类。[您可以在 Oracle 官方文档中阅读更多关于 Java 命令行参数的信息](https://docs.oracle.com/javase/tutorial/essential/environment/cmdLineArgs.html)。也可以运行 IntelliJ IDEA 中的示例。

注意下面截图中左边的两个绿色三角形。点击其中任何一个，就可以执行`main()`方法。例如，让我们显示`Hello, world!`。

为此，请在`main()`方法内键入以下行：

```
System.out.println("Hello, world!");
```

然后，单击其中一个绿色三角形：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/e642b050-97bf-483c-8445-de3835101c05.png)

您应该在终端区域获得如下输出：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/c1e644e0-7c7b-4c6c-93ff-5902d44f4bcc.png)

从现在开始，每次讨论代码示例时，我们都将使用`main()`方法以相同的方式运行它们。在进行此操作时，我们将不捕获屏幕截图，而是将结果放在注释中，因为这样的样式更容易遵循。例如，以下代码显示了以前的代码演示在这种样式下的外观：

```
System.out.println("Hello, world!");     //prints: Hello, world!
```

可以在代码行右侧添加注释（任意文本），该行的右键以双斜杠`//`分隔。编译器不读取此文本，只保留它的原样。注释的存在不会影响性能，并用于向人类解释程序员的意图。

# 导入项目

在本节中，我们将演示使用本书的源代码将现有代码导入 IntelliJ IDEA 的过程。我们假设您已经在你的电脑上安装了 [Maven](https://maven.apache.org/install.html) 也安装了 [Git](https://gist.github.com/derhuerst/1b15ff4652a867391f03)，可以使用。我们还假设您已经安装了 JDK12，正如在 JavaSE 的“安装”一节中所描述的那样。

要使用本书的代码示例导入项目，请执行以下步骤：

1.  [转到源库](https://github.com/PacktPublishing/Learn-Java-12-Programming)，点击克隆或下载链接，如下图所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/bd39b427-2955-407c-8b53-c14fb575d0ce.png)

2.  单击克隆或下载链接，然后复制提供的 URL：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/04a08015-05c8-4fa1-ad1f-6777b9528a9d.png)

3.  在计算机上选择要放置源代码的目录，然后运行以下 Git 命令：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/d6448b6f-2cbd-486f-8b21-b5d29b99c3ca.png)

4.  新建`Learn-Java-12-Programming`文件夹，如下图所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/df18d3d4-58e1-4e0b-85d7-2529f0de4ede.png)

或者，您可以使用前面屏幕截图上显示的链接下载 ZIP 将源代码下载为一个`.zip`文件，而不是克隆。将下载的源代码解压到计算机上希望放置源代码的目录中，然后通过从名称中删除后缀`-master`来重命名新创建的文件夹，确保文件夹的名称为`Learn-Java-12-Programming`。

5.  新的`Learn-Java-12-Programming`文件夹包含 Maven 项目以及本书中的所有源代码。现在运行 IntelliJ IDEA 并单击最顶部菜单中的“文件”，然后单击“新建”和“从现有源项目…”：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/c48213f1-4050-4a09-a84d-06f27a07fed8.png)

6.  选择步骤 4 中创建的`Learn-Java-12-Programming`文件夹，点击打开按钮：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/65da3a80-efd5-4bf5-9ea5-b1d37bd75fdb.png)

7.  接受默认设置并单击以下每个屏幕上的“下一步”按钮，直到出现显示已安装 JDK 列表和“完成”按钮的屏幕：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/701d9b11-1d03-4cad-951a-6da3ca52f707.png)

8.  选择`12`并点击“完成”。您将看到项目导入到 IntelliJ IDEA 中：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/baa0cdcf-689e-443a-a89f-f4abe5520bc6.png)

9.  等待右下角出现以下小窗口：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/7532e15a-1f64-4f8d-8c6c-aa92818d5e5b.png)

您可能不想等待并继续执行步骤 12。当窗口稍后弹出时，只需执行步骤 10 和 11。如果错过此窗口，您可以随时单击事件日志链接，系统将向您显示相同的选项。

10.  单击它；然后单击“添加为 Maven”项目链接：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/40814047-9a46-473f-9594-41a3e83f2d94.png)

11.  每当出现以下窗口时，请单击启用自动导入：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/682b16df-7aea-4041-823a-ef33237340f4.png)

您可能不想等待并继续执行步骤 12。当窗口稍后弹出时，只需执行步骤 11。如果错过此窗口，您可以随时单击事件日志链接，系统将向您显示相同的选项。

12.  选择项目结构符号，它是以下屏幕截图右侧的第三个：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/1ca9fbce-afbb-49ff-a1e3-6d34d0ddbea2.png)

13.  如果列出了主模块和测试模块，请通过高亮显示它们并单击减号（`-`）来删除它们，如下屏幕所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/42f7963a-6c77-4eb9-b50f-97fdd20488c8.png)

14.  下面是模块的最终列表：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/acab69b0-a98a-4bb1-a5e3-cf5b66f2d0ef.png)

15.  单击右下角的“确定”返回项目。单击左窗格中的“Learn-Java-12-Programming”，继续在源代码树中向下，直到看到以下类列表：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/c0d0f564-8cf1-4325-94e4-ffcd5790e7b1.png)

16.  单击右窗格中的绿色箭头并执行所需的任何类。在“运行”窗口中可以看到的结果类似于以下内容：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/1c5ba52c-a17f-4541-bed6-148e9d5b7a32.png)

# 从命令行执行示例

要从命令行执行示例，请执行以下步骤：

1.  转到“导入项目”部分“步骤 4”中创建的`Learn-Java-12-Programming`文件夹`pom.xml`文件所在位置，运行`mvn clean package`命令：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/2a049007-e71b-42a2-92da-ce59cf1324de.png)

2.  选择要运行的示例。例如，假设要运行`ControlFlow.java`，请运行以下命令：

```
java -cp target/learnjava-1.0-SNAPSHOT.jar:target/libs/* \
com.packt.learnjava.ch01_start.ControlFlow
```

您将看到以下结果：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/74f3ccad-db4c-4703-9214-13b452befa37.png)

3.  如果要运行`ch05_stringsIoStreams`包中的示例文件，请使用不同的包和类名运行相同的命令：

```
java -cp target/learnjava-1.0-SNAPSHOT.jar:target/libs/* \
com.packt.learnjava.ch05_stringsIoStreams.Files
```

如果您的计算机有 Windows 系统，请使用以下命令作为一行：

```
java -cp target\learnjava-1.0-SNAPSHOT.jar;target\libs\* com.packt.learnjava.ch05_stringsIoStreams.Files
```

请注意，Windows 命令具有不同的斜杠和分号（`;`）作为类路径分隔符。

4.  结果如下：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/c589778c-12d6-4904-95f4-4912bd3921c7.png)

5.  这样，您就可以运行任何包含`main()`方法的类。将执行`main()`方法的内容。

# Java 原始类型和运算符

有了所有主要的编程工具，我们就可以开始把 Java 作为一种语言来讨论了。语言语法由 Java 语言规范定义，您可以在[这个页面](https://docs.oracle.com/javase/specs)上找到。每次你需要澄清的时候，请不要犹豫参考它。这并不像很多人想象的那么令人畏惧

Java 中的所有值都分为两类：`reference`类型和`primitive`类型。我们从基本类型和运算符开始，作为任何编程语言的自然入口点，在本章中，我们还将讨论一种称为`String`的引用类型（参见“字符串类型和字面值”部分）

所有的原始类型都可以分为两类：`boolean`类型和`numeric`类型。

# 布尔型

Java 中只有两个`boolean`类型值：`true`和`false`。这样的值只能分配给一个`boolean`类型的变量，例如：

```
boolean b = true;
```

`boolean`变量通常用于控制流语句中，我们将在“Java 语句”一节中讨论。下面是一个例子：

```
boolean b = x > 2;
if(b){ 
    //do something
}
```

在代码中，我们将`x > 2`表达式的求值结果赋给`b`变量。如果`x`的值大于`2`，则`b`变量得到赋值`true`。然后执行大括号内的代码`{}`。

# 数字类型

**Java 数字类型**形成两组：整数型（`byte`、`char`、`short`、`int`、`long`）和浮点型（`float`和`double`）。

# 整数类型

整数类型消耗的内存量如下：

*   `byte`：8 位
*   `char`：16 位
*   `short`：16 位
*   `int`：32 位
*   `long`：64 位

`char`类型是一个无符号整数，它可以保存 0 到 65535 之间的值（称为**码位**）。它表示一个 Unicode 字符，这意味着有 65536 个 Unicode 字符。以下是构成 Unicode 字符基本拉丁列表的三条记录：

| **码位** | **Unicode 转义** | **可打印符号** | **说明** |
| --- | --- | --- | --- |
| `33` | `\u0021` | `!` | 感叹号 |
| `50` | `\u0032` | `2` | 数字二 |
| `65` | `\u0041` | `A` | 拉丁文大写字母 A |

下面的代码演示了`char`类型的属性：

```
char x1 = '\u0032';
System.out.println(x1);  //prints: 2

char x2 = '2';
System.out.println(x2);  //prints: 2
x2 = 65;
System.out.println(x2);  //prints: A

char y1 = '\u0041';
System.out.println(y1);  //prints: A

char y2 = 'A';
System.out.println(y2);  //prints: A
y2 = 50;
System.out.println(y2);  //prints: 2

System.out.println(x1 + x2);  //prints: 115
System.out.println(x1 + y1);  //prints: 115

```

代码示例的最后两行解释了为什么将`char`类型视为整数类型，因为`char`值可以用于算术运算。在这种情况下，每个`char`值由其代码点表示。

其他整数类型的取值范围如下：

*   `byte`：从`-128`到`127`包括
*   `short`：从`-32,768`到`32,767`包括
*   `int`：从`-2.147.483.648`到`2.147.483.647`包括
*   `long`：从`-9,223,372,036,854,775,808`到`9,223,372,036,854,775,807`包括

始终可以从相应的 Java 常量中检索每个原始类型的最大值和最小值，如下所示：

```
System.out.println(Byte.MIN_VALUE);      //prints: -128
System.out.println(Byte.MAX_VALUE);      //prints:  127
System.out.println(Short.MIN_VALUE);     //prints: -32768
System.out.println(Short.MAX_VALUE);     //prints:  32767
System.out.println(Integer.MIN_VALUE);   //prints: -2147483648
System.out.println(Integer.MAX_VALUE);   //prints:  2147483647
System.out.println(Long.MIN_VALUE);      //prints: -9223372036854775808
System.out.println(Long.MAX_VALUE);      //prints:  9223372036854775807
System.out.println((int)Character.MIN_VALUE); //prints: 0
System.out.println((int)Character.MAX_VALUE); //prints: 65535

```

最后两行中的构造`(int)`是**转换操作符**用法的一个示例。它强制将值从一种类型转换为另一种类型，但这种转换并不总是保证成功。从我们的示例中可以看到，某些类型允许比其他类型更大的值。但是程序员可能知道某个变量的值永远不会超过目标类型的最大值，而转换操作符是程序员将自己的观点强加给编译器的方式。否则，如果没有转换运算符，编译器将引发错误，并且不允许赋值。但是，程序员可能会弄错，值可能会变大。在这种情况下，将在执行期间引发运行时错误。

但有些类型原则上不能转换为其他类型，或者至少不能转换为所有类型。例如，`boolean`类型值不能转换为整型值。

# 浮点类型

这组原始类型中有两种类型，`float`和`double`：

*   `float`：32 位
*   `doubele`：64 位

其正最大和最小可能值如下：

```
System.out.println(Float.MIN_VALUE);  //prints: 1.4E-45
System.out.println(Float.MAX_VALUE);  //prints: 3.4028235E38
System.out.println(Double.MIN_VALUE); //prints: 4.9E-324
System.out.println(Double.MAX_VALUE); //prints: 1.7976931348623157E308

```

最大和最小负值与刚才显示的值相同，只是前面有一个减号（`-`。因此，实际上，`Float.MIN_VALUE`和`Double.MIN_VALUE`不是最小值，而是对应类型的精度。对于每种浮点类型，零值可以是`0.0`或`-0.0`

浮点型的特点是有一个点（`.`），它将数字的整数部分和小数部分分开。默认情况下，在 Java 中，带点的数字被假定为`double`类型。例如，假设以下为双精度值：

```
42.3
```

这意味着以下赋值会导致编译错误：

```
float f = 42.3;
```

要表示您希望将其视为`float`类型，需要添加`f`或`F`。例如，以下分配不会导致错误：

```
float f = 42.3f;
float d = 42.3F;

double a = 42.3f;
double b = 42.3F;

float x = (float)42.3d;
float y = (float)42.3D;

```

正如您可能已经从示例中注意到的，`d`和`D`表示`double`类型。但我们能够将它们转换成`float`型，因为我们确信`42.3`完全在`float`型可能值的范围内。

# 基本类型的默认值

在某些情况下，即使程序员不想这样做，也必须给变量赋值。我们将在第 2 章、“Java 面向对象编程（OOP）”中讨论这种情况。在这种情况下，默认的原始类型值如下所示：

*   `byte`、`short`、`int`和`long`类型具有默认值`0`。
*   `char`类型的默认值为`\u0000`，代码点为`0`
*   `float`和`double`类型具有默认值`0.0`。
*   `boolean`类型有默认值`false`。

# 原始类型的字面值

值的表示称为**字面值**。`boolean`类型有两个文本：`true`和`false`。`byte`、`short`、`int`、`long`整数类型的字面值默认为`int`类型：

```
byte b = 42;
short s = 42;
int i = 42;
long l = 42;
```

另外，为了表示一个`long`类型的文本，您可以在后面加上字母`l`或`L`：

```
long l1 = 42l;
long l2 = 42L;
```

字母`l`很容易与数字 1 混淆，因此为此使用`L`（而不是`l`）是一种好的做法。

到目前为止，我们已经用十进制表示整数字面值。同时，`byte`、`short`、`int`和`long`类型的字面值也可以用二进制（以 2 为基数，数字 0-1）、八进制（以 8 为基数，数字 0-7）和十六进制（以 16 为基数，数字 0-9 和 a-f）数制表示。二进制字面值以`0b`（或`0B`开头，后跟二进制表示的值。例如，小数点`42`表示为`101010 = 2^0*0 + 2^1*1 + 2^2*0 + 2^3 *1  + 2^4 *0  + 2^5 *1`（我们从右边`0`开始）。八进制字面值以`0`开头，后跟八进制表示的值，因此`42`表示为`52 = 8^0*2+ 8^1*5`。十六进制字面值以`0x`（或`0X`开头），后跟以十六进制表示的值。因此，`42`被表示为`2a = 16^0*a + 16^1*2`，因为在十六进制系统中，`a`到`f`（或`A`到`F`）的符号映射到十进制值`10`到`15`。下面是演示代码：

```
int i = 42;
System.out.println(Integer.toString(i, 2));       // 101010
System.out.println(Integer.toBinaryString(i));    // 101010
System.out.println(0b101010);                     // 42

System.out.println(Integer.toString(i, 8));       // 52
System.out.println(Integer.toOctalString(i));     // 52
System.out.println(052);                          // 42

System.out.println(Integer.toString(i, 10));       // 42
System.out.println(Integer.toString(i));           // 42
System.out.println(42);                            // 42

System.out.println(Integer.toString(i, 16));       // 2a
System.out.println(Integer.toHexString(i));        // 2a
System.out.println(0x2a);                          // 42

```

如您所见，Java 提供了将十进制系统值转换为具有不同基的系统的方法。所有这些数值表达式都称为字面值。

数字字面值的一个特点是对人友好。如果数字较大，可以将其分成三个部分，用下划线（`_`符号）分隔。例如，请注意以下事项：

```
int i = 354_263_654;
System.out.println(i);  //prints: 354263654

float f = 54_436.98f;
System.out.println(f);  //prints: 54436.98

long l = 55_763_948L;
System.out.println(l);  //prints: 55763948

```

编译器忽略嵌入的下划线符号。

`char`型字面值分为两种：**单字符**或**转义序列**。在讨论数字类型时，我们看到了`char`型字面值的示例：

```
char x1 = '\u0032';
char x2 = '2';
char y1 = '\u0041';
char y2 = 'A';

```

如您所见，字符必须用单引号括起来

转义序列以反斜杠（`\`）开头，后跟字母或其他字符。以下是转义序列的完整列表：

*   `\b`：退格`BS`、Unicode 转义`\u0008`
*   `\t`：水平制表符`HT`、Unicode 转义符`\u0009`
*   `\n`：换行`LF`、Unicode 转义`\u000a`
*   `\f`：表单馈送`FF`、Unicode 转义`\u000c`
*   `\r`：回车`CR`，Unicode 转义`\u000d`
*   `\"`：双引号`"`，Unicode 转义`\u0022`
*   `\'`：单引号`'`，Unicode 转义`\u0027`
*   `\\`：反斜杠`\`、`Unicode escape \u005c`

在八个转义序列中，只有最后三个用符号表示。如果无法以其他方式显示此符号，则使用它们。例如，请注意以下事项：

```
System.out.println("\"");   //prints: "
System.out.println('\'');   //prints: '
System.out.println('\\');   //prints: \

```

其余部分更多地用作控制代码，用于指示输出设备执行某些操作：

```
System.out.println("The back\bspace");     //prints: The bacspace
System.out.println("The horizontal\ttab"); //prints: The horizontal   tab
System.out.println("The line\nfeed");      //prints: The line
                                           //        feed
System.out.println("The form\ffeed");      //prints: The form feed
System.out.println("The carriage\rreturn");//prints: return

```

如您所见，`\b`删除前一个符号，`\t`插入制表符空间，`\n`断开线开始新符号，`\f`迫使打印机弹出当前页，继续在另一页顶部打印，`/r`重新启动当前行。

# 新的紧凑数字格式

`java.text.NumberFormat`类以各种格式表示数字。它还允许根据所提供的格式（包括区域设置）调整格式。称为**压缩**或**短数字格式**。

它以特定于语言环境的可读形式表示一个数字。例如，请注意以下事项：

```
NumberFormat fmt = NumberFormat.getCompactNumberInstance(Locale.US, 
                                            NumberFormat.Style.SHORT);
System.out.println(fmt.format(42_000));          //prints: 42K
System.out.println(fmt.format(42_000_000));      //prints: 42M

NumberFormat fmtP = NumberFormat.getPercentInstance();
System.out.println(fmtP.format(0.42));          //prints: 42%

```

如您所见，要访问此功能，您必须获取`NumberFormat`类的特定实例，有时还需要基于区域设置和提供的样式。

# 运算符

Java 中有 44 个运算符，如下表所示：

| **运算符** | **说明** |
| --- | --- |
| `+``-``*``/``%` | 算术一元和二元运算符 |
| `++``--` | 递增和递减一元运算符 |
| `==``!=` | 相等运算符 |
| `<``>``<=``>=` | 关系运算符 |
| `!``&``&#124;` | 逻辑运算符 |
| `&&``&#124;&#124;``?:` | 条件运算符 |
| `=``+=``-=``*=``/=``%=` | 分配运算符 |
| `&=``&#124;=``^=``<<=``>>=``>>>=` | 赋值运算符 |
| `&``&#124;``~``^``<<``>>``>>>` | 位操作符 |
| `->``::` | 箭头和方法引用运算符 |
| `new` | 实例创建操作符 |
| `.` | 字段访问/方法调用运算符 |
| `instanceof` | 类型比较运算符 |
| （目标类型） | 铸造操作工 |

我们将不描述不常用的赋值运算符`&=`、`|=`、`^=`、`<<=`、`>>=`、`>>>=`和位运算符。您可以在 [Java 规范](https://docs.oracle.com/javase/specs)中了解它们。箭头`->`和方法引用`::`运算符将在第 14 章、“函数式编程”中描述。实例创建操作符`new`、字段访问/方法调用操作符`.`和类型比较操作符`instanceof`将在第 2 章、“Java 面向对象编程（OOP）”中讨论。至于`cast`运算符，我们已经在“整数类型”一节中描述过了。

# 算术一元（`+`和`-`）和二元运算符（`+`、`-`、`*`、`/`和`%`）

大多数算术运算符和正负号（**一元**运算符）我们都很熟悉。模运算符`%`将左操作数除以右操作数，并返回余数，如下所示：

```
int x = 5;
System.out.println(x % 2);   //prints: 1

```

另外值得一提的是，Java 中两个整数的除法会丢失小数部分，因为 Java 假定结果应该是整数 2，如下所示：

```
int x = 5;
System.out.println(x / 2);   //prints: 2
```

如果需要保留结果的小数部分，请将其中一个操作数转换为浮点类型。以下是实现这一目标的几种方法：

```
int x = 5;
System.out.println(x / 2.);           //prints: 2.5
System.out.println((1\. * x) / 2);     //prints: 2.5
System.out.println(((float)x) / 2);   //prints: 2.5
System.out.println(((double) x) / 2); //prints: 2.5
```

# 递增和递减一元运算符（`++`和`--`）

`++`运算符将整型的值增加`1`，而`--`运算符将整型的值减少`1`，如果放在变量前面（前缀），则在返回变量值之前将其值更改 1。但是当放在变量后面（后缀）时，它会在返回变量值后将其值更改为`1`。以下是几个例子：

```
int i = 2;
System.out.println(++i);   //prints: 3
System.out.println(i);     //prints: 3
System.out.println(--i);   //prints: 2
System.out.println(i);     //prints: 2
System.out.println(i++);   //prints: 2
System.out.println(i);     //prints: 3
System.out.println(i--);   //prints: 3
System.out.println(i);     //prints: 2

```

# 相等运算符（`==`和`!=`)

`==`运算符表示**等于**，而`!=`运算符表示**不等于**。它们用于比较同一类型的值，如果操作数的值相等，则返回`boolean`值`true`，否则返回`false`。例如，请注意以下事项：

```
int i1 = 1;
int i2 = 2;
System.out.println(i1 == i2);        //prints: false
System.out.println(i1 != i2);        //prints: true
System.out.println(i1 == (i2 - 1));  //prints: true
System.out.println(i1 != (i2 - 1));  //prints: false

```

但是，在比较浮点类型的值时，尤其是在比较计算结果时，要小心。在这种情况下，使用关系运算符（`<`、`>`、`<=`和`>=`）更可靠，因为例如，除法`1/3`会产生一个永无止境的小数部分`0.33333333...`，并最终取决于精度实现（这是一个复杂的主题，超出了本书的范围）。

# 关系运算符（`<`、`>`、`<=`和`>=`）

**关系运算符**比较值并返回一个`boolean`值。例如，观察以下情况：

```
int i1 = 1;
int i2 = 2;
System.out.println(i1 > i2);         //prints: false
System.out.println(i1 >= i2);        //prints: false
System.out.println(i1 >= (i2 - 1));  //prints: true
System.out.println(i1 < i2);         //prints: true
System.out.println(i1 <= i2);        //prints: true
System.out.println(i1 <= (i2 - 1));  //prints: true
float f = 1.2f;
System.out.println(i1 < f);          //prints: true
```

# 逻辑运算符（`!`，`&`和`|`）

逻辑运算符的定义如下：

*   如果操作数是`false`，则`!`二进制运算符返回`true`，否则返回`false`。
*   如果两个操作数都是`true`，`&`二进制运算符返回`true`。
*   如果至少有一个操作数是`true`，则`|`二进制运算符返回`true`。

举个例子：

```
boolean b = true;
System.out.println(!b);    //prints: false
System.out.println(!!b);   //prints: true
boolean c = true;
System.out.println(c & b); //prints: true
System.out.println(c | b); //prints: true
boolean d = false;
System.out.println(c & d); //prints: false
System.out.println(c | d); //prints: true
```

# 条件运算符（`&&`、`||`和`?:`)

`&&`和`||`运算符产生的结果与我们刚才演示的`&`和`|`逻辑运算符相同：

```
boolean b = true;
boolean c = true;
System.out.println(c && b); //prints: true
System.out.println(c || b); //prints: true
boolean d = false;
System.out.println(c && d); //prints: false
System.out.println(c || d); //prints: true

```

不同之处在于`&&`和`||`运算符并不总是求值第二个操作数，例如，在`&&`运算符的情况下，如果第一个操作数是`false`，则不求值第二个操作数，因为整个表达式的结果无论如何都是`false`。类似地，在`||`运算符的情况下，如果第一个操作数是`true`，则整个表达式将被清楚地求值为`true`，而不求值第二个操作数。我们可以用以下代码来演示：

```
int h = 1;
System.out.println(h > 3 & h++ < 3);  //prints: false
System.out.println(h);                //prints: 2
System.out.println(h > 3 && h++ < 3); //prints: false
System.out.println(h);                //prints: 2
```

`? :`运算符称为**三元运算符**。它计算一个条件（在符号`?`之前），如果结果是`true`，则将第一个表达式（在`?`和`:`符号之间）计算的值赋给变量；否则，将第二个表达式（在`:`符号之后）计算的值赋给变量：

```
int n = 1, m = 2;
float k = n > m ? (n * m + 3) : ((float)n / m); 
System.out.println(k);           //prints: 0.5
```

# 赋值运算符（`=`，`+=`，`-=`，`*=`，`/=`和`%=`）

`=`运算符只是将指定的值赋给一个变量：

```
x = 3;
```

其他赋值运算符在赋值前计算新值：

*   `x += 42`将表达式`x = x + 42`的结果赋给`x`。
*   `x -= 42`将表达式`x = x - 42`的结果赋给`x`。
*   `x *= 42`将表达式`x = x * 42`的结果赋给`x`。
*   `x /= 42`将表达式`x = x / 42`的结果赋给`x`。
*   `x %= 42`赋值表达式`x = x + x % 42`的剩余部分。

以下是这些运算符的工作方式：

```
float a = 1f;
a += 2;
System.out.println(a); //prints: 3.0
a -= 1;
System.out.println(a); //prints: 2.0
a *= 2;
System.out.println(a); //prints: 4.0
a /= 2;
System.out.println(a); //prints: 2.0
a %= 2;
System.out.println(a); //prints: 0.0
```

# 字符串类型和字面值

我们刚刚描述了 Java 语言的基本值类型。Java 中的所有其他值类型都属于一类**引用类型**。每个引用类型都是一个比值更复杂的构造。它由**类**来描述，该类用作创建**对象**的模板，该对象是包含在该类中定义的值和方法（处理代码）的存储区域。一个对象是由`new`操作符创建的。我们将在第 2 章"Java 面向对象编程"中更详细地讨论类和对象

在本章中，我们将讨论一种称为`String`的引用类型。它由`java.lang.String`类表示，正如您所看到的，它属于 JDK 最基本的包`java.lang`。我们之所以在早期引入`String`类，是因为它在某些方面的行为与原始类型非常相似，尽管它是一个引用类型。

之所以称为引用类型，是因为在代码中，我们不直接处理此类型的值。引用类型的值比原始类型的值更复杂。它称为对象，需要更复杂的内存分配，因此引用类型变量包含内存引用。它指向对象所在的内存区域，因此得名。

当引用类型变量作为参数传递到方法中时，需要特别注意引用类型的这种性质。我们将在第 3 章、“Java 基础”中详细讨论。现在，关于`String`，我们将看到`String`作为引用类型如何通过只存储一次每个`String`值来优化内存使用。

# 字符串常量

`String`类表示 Java 程序中的字符串。我们见过好几根这样的弦。例如，我们看到了`Hello, world!`。那是一个`String`字。

字面值的另一个例子是`null`。任何引用类都可以引用文本`null`。它表示不指向任何对象的引用值。在`String`类型的情况下，显示如下：

```
String s = null;
```

但是由双引号（`"abc"`、`"123"`、`"a42%$#"`括起来的字符组成的文本只能是`String`类型。在这方面，`String`类作为引用类型，与原始类型有一些共同点。所有的`String`字面值都存储在一个称为**字符串池**的专用内存段中，两个字面值的拼写相同，表示池中的相同值：

```
String s1 = "abc";
String s2 = "abc";
System.out.println(s1 == s2);    //prints: true
System.out.println("abc" == s1); //prints: true

```

JVM 作者选择了这样的实现来避免重复和提高内存使用率。前面的代码示例看起来很像带有原始类型的操作，不是吗？但是，当使用`new`操作符创建`String`对象时，新对象的内存分配在字符串池之外，因此两个`String`对象或任何其他对象的引用总是不同的：

```
String o1 = new String("abc");
String o2 = new String("abc");
System.out.println(o1 == o2);    //prints: false
System.out.println("abc" == o1); //prints: false

```

如有必要，可以使用`intern()`方法将用`new`运算符创建的字符串值移动到字符串池：

```
String o1 = new String("abc");
System.out.println("abc" == o1);          //prints: false
System.out.println("abc" == o1.intern()); //prints: true

```

在前面的代码中，`intern()`方法试图将新创建的`"abc"`值移动到字符串池中，但发现那里已经存在这样一个文本，因此它重用了字符串池中的文本。这就是上例中最后一行中的引用相等的原因。

好消息是，您可能不需要使用`new`操作符创建`String`对象，而且大多数 Java 程序员从不这样做。但是当`String`对象作为输入传递到您的代码中，并且您无法控制其来源时，仅通过引用进行比较可能会导致错误的结果（如果字符串具有相同的拼写，但是由`new operator`创建的）。这就是为什么，当需要通过拼写（和大小写）使两个字符串相等时，为了比较两个字面值或`String`对象，`equals()`方法是更好的选择：

```
String o1 = new String("abc");
String o2 = new String("abc");
System.out.println(o1.equals(o2));       //prints: true
System.out.println(o2.equals(o1));       //prints: true
System.out.println(o1.equals("abc"));    //prints: true
System.out.println("abc".equals(o1));    //prints: true
System.out.println("abc".equals("abc")); //prints: true
```

我们将很快讨论`equals()`和`String`类的其他方法。

使`String`文本和对象看起来像原始值的另一个特性是，可以使用算术运算符`+`添加它们：

```
String s1 = "abc";
String s2 = "abc";
String s = s1 + s2;
System.out.println(s);              //prints: abcabc
System.out.println(s1 + "abc");     //prints: abcabc
System.out.println("abc" + "abc");  //prints: abcabc

String o1 = new String("abc");
String o2 = new String("abc");
String o = o1 + o2;
System.out.println(o);              //prints: abcabc
System.out.println(o1 + "abc");     //prints: abcabc 
```

没有其他算术运算符可以应用于`String`文本或对象。

最后，Java12 引入了一个新的`String`文本，称为**原始字符串字面值**。它允许保留缩进和多行，而无需在引号中添加空格。例如，程序员将如何在 Java12 之前添加缩进并使用`\n`断行：

```
String html = "<html>\n" +
              "    <body>\n" +
              "             <p>Hello World.</p>\n" +
              "    </body>\n" +
              "</html>\n";
```

下面是 Java12 如何实现相同的结果：

```
String html = `<html>
                   <body>
                       <p>Hello World.</p>
                   </body>
               </html>
              `;
```

如您所见，原始字符串文本由一个或多个包含在反引号`` ` ``（`\u0060`）中的字符组成，也称为**反引号**或**重音符号**。

# 字符串不变性

由于所有的`String`文本都可以共享，JVM 作者确保，一旦存储，`String`变量就不能更改。它不仅有助于避免从代码的不同位置同时修改相同值的问题，而且还可以防止未经授权修改通常表示用户名或密码的`String`值。

下面的代码看起来像一个`String`值修改：

```
String str = "abc";
str = str + "def";
System.out.println(str);       //prints: abcdef
str = str + new String("123");
System.out.println(str);      //prints: abcdef123

```

但是，在幕后，原始的`"abc"`字面值仍然完好无损。相反，创建了一些新的文本：`"def"`、`"abcdef"`、`"123"`、`"abcdef123"`。为了证明这一点，我们执行了以下代码：

```
String str1 = "abc";
String r1 = str1;
str1 = str1 + "def";
String r2 = str1;
System.out.println(r1 == r2);      //prints: false
System.out.println(r1.equals(r2)); //prints: false

```

如您所见，`r1`和`r2`变量表示不同的记忆，它们所指的对象的拼写也不同。

我们将在第 5 章中进一步讨论字符串、“字符串、输入/输出和文件”。

# 标识符和变量

从我们的学校时代起，我们就有了一个直观的理解变量是什么。我们认为它是一个代表值的名称。我们用诸如`x`加仑水或`n`英里的距离等变量来解决问题，以及类似的问题。在 Java 中，变量的名称称为**标识符**，可以通过某些规则构造。使用标识符，可以声明（定义）变量并初始化变量。

# 标识符

[根据 Java 语言规范](https://docs.oracle.com/javase/specs)，标识符（变量名）可以是表示字母、数字 0-9、美元符号（`$`）或下划线（`_`的 Unicode 字符序列。

其他限制如下：

*   标识符的第一个符号不能是数字。
*   标识符的拼写不能与关键字相同（参见第 3 章“Java 基础”中的 Java 关键字）。
*   它不能拼写为`boolean`字面值`true`或`false`或字面值`null`。
*   而且，由于 Java9，标识符不能只是下划线（`_`。

以下是一些不寻常但合法的标识符示例：

```
$
_42
αρετη
String
```

# 变量声明（定义）和初始化

变量有名称（标识符）和类型。通常，它指的是存储值的存储器，但是可以不指任何内容（`null`）或者根本不指任何内容（那么它就不会被初始化）。它可以表示类属性、数组元素、方法参数和局部变量。最后一种是最常用的变量

在使用变量之前，必须声明并初始化它。在其他一些编程语言中，变量也可以被*定义*，因此 Java 程序员有时会使用*定义*这个词作为*声明*的同义词，这并不完全正确。

以下是术语回顾和示例：

```
int x;      //declartion of variable x
x = 1;      //initialization of variable x
x = 2;      //assignment of variable x
```

初始化和赋值看起来是一样的。区别在于它们的顺序：第一个赋值称为**初始化**。没有初始化，就不能使用变量。

声明和初始化可以组合在一个语句中。例如，请注意以下事项：

```
float $ = 42.42f;
String _42 = "abc";
int αρετη = 42;
double String = 42.;
```

# 类型推断变量

在 Java10 中，引入了一种类型保持器`var`。Java 语言规范对其定义如下：“`var`不是关键字，而是具有特殊含义的标识符，作为局部变量声明的类型。

在实际应用中，它可以让编译器计算出声明变量的类型，如下所示：

```
var x = 1;

```

在前面的示例中，编译器可以合理地假设`x`具有原始类型`int`。

你可以猜到，要做到这一点，光靠一个声明是不够的：

```
var x;    //compilation error
```

也就是说，在没有初始化的情况下，编译器无法在使用`var`时找出变量的类型。

# Java 语句

“Java 语句”是可以执行的最小构造。它描述一个动作，以分号（`;`结束。我们已经看到许多声明。例如，这里有三种说法：

```
float f = 23.42f;
String sf = String.valueOf(f);
System.out.println(sf);

```

第一行是声明语句和赋值语句的组合。第二行也是一个声明语句，它与赋值语句和方法调用语句相结合。第三行只是一个方法调用语句。

以下是 Java 语句类型列表：

*   只有一个符号`;`（分号）的空语句
*   一个类或接口声明语句（我们将在第 2 章、"Java 面向对象编程"中讨论）
*   局部变量声明语句：`int x;`
*   同步声明：这超出了本书的范围
*   表达式语句
*   控制流语句

表达式语句可以是以下语句之一：

*   方法调用语句：`someMethod();`
*   赋值声明：`n = 23.42f;`
*   对象创建语句：`new String("abc");`
*   一元递增或递减语句：`++x ;`或`--x;`或`x++;`或`x--;`

我们将在“表达式语句”部分中详细讨论表达式语句。

控制流语句可以是以下语句之一：

*   选择语句：`if-else`或`switch-case`
*   迭代语句：`for`或`while`或`do-while`
*   异常处理语句：`throw`或`try-catch`或`try-catch-finally`
*   分支语句：`break`或`continue`或`return`

我们将在“控制流语句”一节中详细讨论控制语句。

# 表达式语句

**表达式语句**由一个或多个表达式组成。表达式通常包含一个或多个运算符。可以对其求值，这意味着它可以生成以下类型之一的结果：

*   变量：例如`x = 1`。
*   值：例如`2*2`。

*   如果表达式是对返回`void`的方法的调用，则不返回任何东西。这种方法据说只产生副作用：例如`void someMethod()`

考虑以下表达式：

```
x = y++; 
```

前面的表达式将值赋给`x`变量，并且具有将`1`添加到`y`变量的值的副作用。

另一个例子是打印一行的方法：

```
System.out.println(x); 
```

`println()`方法不返回任何内容，并且具有打印某些内容的副作用。
根据其形式，表达式可以是以下表达式之一：

*   主要表达式：文本、新对象创建、字段或方法访问（调用）
*   一元运算符表达式：例如`x++`
*   二元运算符表达式：例如`x*y`
*   三元运算符表达式：例如`x > y ? true : false`
*   一个 Lambda 表达式：`x -> x + 1`（见第 14 章、“函数式编程”）

如果表达式由其他表达式组成，则括号通常用于清楚地标识每个表达式。这样，更容易理解和设置表达式的优先级。

# 控制流语句

当一个 Java 程序被执行时，它是一个语句一个语句地执行的。有些语句必须根据表达式求值的结果有条件地执行。这种语句被称为**控制流语句**，因为在计算机科学中，控制流（或控制流）是执行或求值单个语句的顺序。

控制流语句可以是以下语句之一：

*   选择语句：`if-else`或`switch-case`
*   迭代语句：`for`或`while`或`do-while`
*   异常处理语句：`throw`或`try-catch`或`try-catch-finally`
*   分支语句：`break`或`continue`或`return`

# 选择语句

选择语句基于表达式求值，有四种变体：

*   `if (expr) {do sth}`
*   `if (expr) {do sth} else {do sth else}`
*   `if (expr) {do sth} else if {do sth else} else {do sth else}`
*   `switch case`语句

以下是`if`语句的示例：

```
if(x > y){
    //do something
}

if(x > y){
    //do something
} else {
    //do something else
}

if(x > y){
    //do something
} else if (x == y){
    //do something else
} else {
    //do something different
}
```

`switch...case`语句是`if...else`语句的变体：

```
switch(x){
    case 5:               //means: if(x = 5)
        //do something 
        break;
    case 7:             
        //do something else
        break;
    case 12:
        //do something different
        break;
    default:             
        //do something completely different
        //if x is not 5, 7, or 12
}
```

如您所见，`switch...case`语句根据变量的值派生执行流。`break`语句允许退出`switch...case`语句。否则，将执行以下所有案件。

在 Java12 中，在预览模式中引入了一个新特性—一个不太详细的`switch...case`语句：

```
void switchDemo1(int x){
    switch (x) {
        case 1, 3 -> System.out.print("1 or 3");
        case 4    -> System.out.print("4");
        case 5, 6 -> System.out.print("5 or 6");
        default   -> System.out.print("Not 1,3,4,5,6");
    }
    System.out.println(": " + x);
}
```

如您所见，它使用箭头`->`，而不使用`break`语句。要利用此功能，您必须向`javac`和`java`命令添加一个`--enable-preview`选项。如果从 IDE 运行示例，则需要将此选项添加到配置中。在 IntelliJ IDEA 中，该选项应添加到两个配置屏幕：编译器和运行时：

1.  打开“首选项”屏幕并将其作为 LearnJava 模块的编译选项，如下屏幕所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/dbcc253d-62df-47cb-85a4-6a1f01b9a406.png)

2.  在最顶部的水平菜单上选择“运行”：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/70c46abf-21b6-448e-baa8-19003fbce52a.png)

3.  单击编辑配置。。。并将 VM 选项添加到将在运行时使用的 ControlFlow 应用：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/a1b5f8d7-f33a-4e63-8352-e3c39b83cdf8.png)

如前所述，我们已经添加了`--enable-preview`选项，并使用不同的参数执行了`switchDemo1()`方法：

```
switchDemo1(1);    //prints: 1 or 3: 1
switchDemo1(2);    //prints: Not 1,3,4,5,6: 2
switchDemo1(5);    //prints: 5 or 6: 5

```

你可以从注释中看到结果。

如果在每种情况下都要执行几行代码，您可以在代码块周围加上大括号`{}`，如下所示：

```
switch (x) {
    case 1, 3 -> { 
                    //do something
                 }
    case 4    -> {
                    //do something else 
                 }
    case 5, 6 -> System.out.println("5 or 6");
    default   -> System.out.println("Not 1,3,4,5,6");
}
```

java12`switch...case`语句甚至可以返回一个值。例如，这里的情况是，必须根据`switch...case`语句结果分配另一个变量：

```
void switchDemo2(int i){
    boolean b = switch(i) {
        case 0 -> false;
        case 1 -> true;
        default -> false;
    };
    System.out.println(b);
}
```

如果我们执行`switchDemo2()`方法，结果如下：

```
switchDemo2(0);    //prints: false
switchDemo2(1);    //prints: true
switchDemo2(2);    //prints: false

```

这看起来是一个很好的改进，如果这个特性被证明是有用的，它将作为一个永久的特性包含在未来的 Java 版本中。

# 迭代语句

**迭代语句**可以是以下三种形式之一：

*   `while`语句
*   `do..while`语句
*   `for`语句，也称为**循环语句**

`while`语句如下：

```
while (boolean expression){
      //do something
}
```

下面是一个具体的例子：

```
int n = 0;
while(n < 5){
 System.out.print(n + " "); //prints: 0 1 2 3 4 
 n++;
}
```

在一些例子中，我们使用了不给另一条线馈电的`print()`方法，而不是`println()`方法（在其输出端不添加换行控制）。`print()`方法在一行中显示输出。

`do...while`语句的形式非常相似：

```
do {
    //do something
} while (boolean expression)
```

它不同于`while`语句，总是在计算表达式之前至少执行一次语句块：

```
int n = 0;
do {
    System.out.print(n + " ");   //prints: 0 1 2 3 4
    n++;
} while(n < 5);

```

如您所见，当表达式在第一次迭代时为`true`时，它的行为方式相同。但如果表达式的计算结果为`false`，则结果不同：

```
int n = 6;
while(n < 5){
    System.out.print(n + " ");   //prints: 
    n++;
}

n = 6;
do {
    System.out.print(n + " ");   //prints: 6
    n++;
} while(n < 5);

```

`for`语句语法如下：

```

for(init statements; boolean expression; update statements) {
 //do what has to be done here
}
```

以下是`for`语句的工作原理：

*   `init`语句初始化一些变量。
*   使用当前变量值来计算`boolean expression`：如果是`true`，则执行语句块，否则退出`for`语句。
*   `update statements`更新变量，用这个新值重新计算`boolean expression`：如果为`true`，则执行语句块，否则退出`for`语句。
*   除非退出，否则重复最后一步。

如你所见，如果你不小心，你会进入一个无限循环：

```
for (int x = 0; x > -1; x++){
    System.out.print(x + " ");  //prints: 0 1 2 3 4 5 6 ...
}
```

因此，必须确保布尔表达式保证最终退出循环：

```
for (int x = 0; x < 3; x++){
    System.out.print(x + " ");  //prints: 0 1 2
}
```

以下示例演示了多个初始化和更新语句：

```
for (int x = 0, y = 0; x < 3 && y < 3; ++x, ++y){
    System.out.println(x + " " + y);
}
```

以下是前面`for`语句的变体，用于演示目的：

```
for (int x = getInitialValue(), i = x == -2 ? x + 2 : 0, j = 0;
 i < 3 || j < 3 ; ++i, j = i) {
 System.out.println(i + " " + j);
}
```

如果`getInitialValue()`方法像`int getInitialValue(){ return -2; }`一样实现，那么前面的两条`for`语句产生完全相同的结果。

要对值数组进行迭代，可以使用数组索引：

```
int[] arr = {24, 42, 0};
for (int i = 0; i < arr.length; i++){
    System.out.print(arr[i] + " ");  //prints: 24 42 0
}
```

或者，您可以使用更紧凑的形式的`for`语句来产生相同的结果，如下所示：

```
int[] arr = {24, 42, 0};
for (int a: arr){
    System.out.print(a + " ");  //prints: 24 42 0
}
```

最后一个表单对于如下所示的集合特别有用：

```
List<String> list = List.of("24", "42", "0");
for (String s: list){
    System.out.print(s + " ");  //prints: 24 42 0
}
```

我们将在第 6 章、“数据结构、泛型和流行工具”中讨论集合。

# 异常处理语句

在 Java 中，有称为**异常**的类，它们表示中断正常执行流的事件。它们的名字通常以`Exception`结尾：`NullPointerException`、`ClassCastException`、`ArrayIndexOutOfBoundsException`等等。

所有异常类都扩展了`java.lang.Exception`类，而`java.lang.Exception`类又扩展了`java.lang.Throwable`类（我们将在第 2 章“Java 面向对象编程（OOP）”中解释这意味着什么）。这就是为什么所有异常对象都有一个共同的行为。它们包含有关异常情况的原因及其起源位置（源代码行号）的信息。

每个异常对象可以由 JVM 自动生成（抛出），也可以由应用代码使用关键字`throw`自动生成（抛出）。如果一个代码块抛出异常，您可以使用一个`try-catch`或`try-catch-finally`构造来捕获抛出的异常对象，并将执行流重定向到另一个代码分支。如果周围的代码没有捕获异常对象，它将从应用传播到 JVM 并强制它退出（并中止应用执行）。因此，在所有可能引发异常的地方使用`try-catch`或`try-catch-finally`是一种很好的做法，您不希望应用中止执行。

以下是异常处理的典型示例：

```
try {
    //x = someMethodReturningValue();
    if(x > 10){
        throw new RuntimeException("The x value is out of range: " + x);
    }
    //normal processing flow of x here
} catch (RuntimeException ex) {
    //do what has to be done to address the problem
}
```

在前面的代码段中，`x > 10`的情况下不执行`normal processing flow`。相反，`do what has to be done`块将被执行。但是在`x <= 10`的情况下，`normal processing flow`块将运行，`do what has to be done`块将被忽略。

有时，不管是否抛出/捕获了异常，都必须执行代码块。不必在两个地方重复相同的代码块，您可以将其放入一个`finally`块中，如下所示：

```
try {
    //x = someMethodReturningValue();
    if(x > 10){
        throw new RuntimeException("The x value is out of range: " + x);
    }
    //normal processing flow of x here
} catch (RuntimeException ex) {
   System.out.println(ex.getMessage());   
                             //prints: The x value is out of range: ...
   //do what has to be done to address the problem
} finally {
   //the code placed here is always executed
}
```

我们将在第 4 章、“处理”中更详细地讨论异常处理。

# 分支语句

**分支语句**允许中断当前执行流，并从当前块后的第一行或控制流的某个（标记的）点继续执行。

分支语句可以是以下语句之一：

*   `break`
*   `continue`
*   `return`

我们已经看到了`break`在`switch-case`语句中的用法。下面是另一个例子：

```
String found = null;
List<String> list = List.of("24", "42", "31", "2", "1");
for (String s: list){
    System.out.print(s + " ");         //prints: 24 42 31
    if(s.contains("3")){
        found = s;
        break;
    }
}
System.out.println("Found " + found);  //prints: Found 31

```

如果我们需要找到包含`"3"`的第一个列表元素，我们可以在`condition s.contains("3")`被求值为`true`后立即停止执行。其余的列表元素将被忽略。

在更复杂的场景中，使用嵌套的`for`语句，可以设置一个标签（带有`:`列），指示必须退出哪个`for`语句：

```
String found = null;
List<List<String>> listOfLists = List.of(
        List.of("24", "16", "1", "2", "1"),
        List.of("43", "42", "31", "3", "3"),
        List.of("24", "22", "31", "2", "1")
);
exit: for(List<String> l: listOfLists){
    for (String s: l){
        System.out.print(s + " ");      //prints: 24 16 1 2 1 43
        if(s.contains("3")){
            found = s;
            break exit;
        }
    }
}
System.out.println("Found " + found);  //prints: Found 43

```

我们已经选择了标签名`exit`，但我们也可以称它为任何其他名称。

`continue`语句的工作原理类似，如下所示：

```

String found = null;
List<List<String>> listOfLists = List.of(
                List.of("24", "16", "1", "2", "1"),
                List.of("43", "42", "31", "3", "3"),
                List.of("24", "22", "31", "2", "1")
);
String checked = "";
cont: for(List<String> l: listOfLists){
        for (String s: l){
           System.out.print(s + " "); //prints: 24 16 1 2 1 43 24 22 31
           if(s.contains("3")){
               continue cont;
           }
           checked += s + " ";
        }
}
System.out.println("Found " + found);  //prints: Found 43
System.out.println("Checked " + checked);  
                                //prints: Checked 24 16 1 2 1 24 22
```

它与`break`不同，它告诉`for`语句中的哪一个继续，而不是仅仅退出。
`return`语句用于返回方法的结果：

```
String returnDemo(int i){
    if(i < 10){
        return "Not enough";
    } else if (i == 10){
        return "Exactly right";
    } else {
        return "More than enough";
    }
}
```

如您所见，一个方法中可以有几个`return`语句，每个语句在不同的情况下返回不同的值。如果方法不返回任何内容（`void`），则不需要`return`语句，尽管为了更好的可读性，经常使用`return`语句，如下所示：

```
void returnDemo(int i){
    if(i < 10){
        System.out.println("Not enough");
        return;
    } else if (i == 10){
        System.out.println("Exactly right");
        return;
    } else {
        System.out.println("More than enough");
        return;
    }
}
```

语句是 Java 编程的构造块。它们就像英语中的句子，是可以付诸行动的完整的意图表达。它们可以被编译和执行。编程就是用语句来表达行动计划。

至此，Java 基础知识的解释就结束了。

恭喜你度过难关！

# 总结

本章向您介绍了令人兴奋的 Java 编程世界。我们从解释主要术语开始，然后解释了如何安装必要的工具、JDK 和 IDE，以及如何配置和使用它们。

有了适当的开发环境，我们为读者提供了 Java 作为编程语言的基础知识。我们已经描述了 Java 基本类型，`String`类型及其文本。我们还定义了什么是标识符，什么是变量，最后描述了 Java 语句的主要类型。通过具体的代码示例说明了讨论的所有要点。

在下一章中，我们将讨论 Java 的面向对象方面。我们将介绍主要概念，解释什么是类，什么是接口，以及它们之间的关系。术语*重载*、*覆盖*、*隐藏*也将在代码示例中定义和演示，以及`final`关键字的用法。

# 测验

1.  JDK 代表什么？

2.  JCL 代表什么？

3.  JavaSE 代表什么？

4.  IDE 代表什么？

5.  Maven 的功能是什么？

6.  什么是 Java 原始类型？

7.  什么是 Java 原始类型？

8.  什么是*字面值*？

9.  以下哪项是字面值？

10.  以下哪些是 Java 操作符？

11.  下面的代码段打印什么？

```
int i = 0; System.out.println(i++);
```

12.  下面的代码段打印什么？

```
boolean b1 = true;
 boolean b2 = false;
 System.out.println((b1 & b2) + " " + (b1 && b2));
```

13.  下面的代码段打印什么？

```
int x = 10;
 x %= 6;
 System.out.println(x);
```

14.  以下代码段的结果是什么？

```
System.out.println("abc" - "bc");

```

15.  下面的代码段打印什么？

```
System.out.println("A".repeat(3).lastIndexOf("A"));
```

16.  正确的标识符是什么？

17.  下面的代码段打印什么？

```
for (int i=20, j=-1; i < 23 && j < 0; ++i, ++j){
         System.out.println(i + " " + j + " ");
 }
```

18.  下面的代码段打印什么？

```
int x = 10;
try {
    if(x++ > 10){
        throw new RuntimeException("The x value is out of range: " + x);
    }
    System.out.println("The x value is within the range: " + x);
} catch (RuntimeException ex) {
    System.out.println(ex.getMessage());
}
```

19.  下面的代码段打印什么？

```
int result = 0;
List<List<Integer>> source = List.of(
        List.of(1, 2, 3, 4, 6),
        List.of(22, 23, 24, 25),
        List.of(32, 33)
);
cont: for(List<Integer> l: source){
    for (int i: l){
        if(i > 7){
            result = i;
            continue cont;
        }
     }
}
System.out.println("result=" + result); 
```

20.  从以下选项中选择所有正确的语句：

21.  从以下选项中选择所有正确的 Java 语句类型：

# 二、Java 面向对象编程（OOP）

**面向对象编程**（**OOP**）是为了更好地控制共享数据的并发修改而产生的，这是前 OOP 编程的祸根。这个想法的核心不是允许直接访问数据，而是只允许通过专用的代码层访问数据。由于数据需要在这个过程中传递和修改，因此就产生了对象的概念。在最一般的意义上，*对象*是一组数据，它们也只能通过传递的一组方法来传递和访问。这些数据被称为组成了一个**对象状态**，而这些方法构成了**对象行为**。对象状态被隐藏（**封装**），不允许直接访问。

每个对象都是基于一个称为**类**的模板构建的，换句话说，一个类定义了一个对象类。每个对象都有一个特定的**接口**，这是其他对象与之交互方式的正式定义。最初，据说一个对象通过调用其方法向另一个对象发送消息。但这个术语并不适用，特别是在引入了实际的基于消息的协议和系统之后。

为了避免代码重复，引入了对象之间的父子关系：据说一个类可以从另一个类继承行为。在这种关系中，第一类称为**子类**或**派生类**，第二类称为**父类**或**基类**或**超类**。

在类和接口之间定义了另一种关系：据说一个类可以*实现*一个接口。由于接口描述了如何与对象交互，而不是对象如何响应交互，因此在实现同一接口时，不同对象的行为可能不同。

在 Java 中，一个类只能有一个直接父类，但可以实现许多接口。像它的祖先一样行为并依附于多个接口的能力被称为**多态**。

在本章中，我们将介绍这些面向对象的概念以及它们是如何在 Java 中实现的。讨论的主题包括：

*   面向对象的概念
*   类
*   接口
*   重载、覆盖和隐藏
*   最终变量、方法和类
*   多态的作用

# 面向对象的概念

正如我们在引言中所述，OOP 的主要概念如下：

*   **对象/类**：定义一个状态（数据）和行为（方法），并将它们结合在一起
*   **继承**：它将行为传播到通过父子关系连接的类链上
*   *“抽象/接口”*：描述如何访问对象数据和行为。它将对象的外观与其实现（行为）隔离（抽象）
*   **封装**：隐藏实现的状态和细节
*   **多态**：允许对象呈现实现接口的外观，并表现为任何祖先类

# 对象/类

原则上，您可以用最少的类和对象来创建一个非常强大的应用。在 Java8 和 JDK 中加入了函数式编程之后，实现这一点就变得更加容易了，它允许您将行为作为函数传递。但是传递数据（状态）仍然需要类/对象。这意味着 Java 作为 OOP 语言的地位保持不变。

类定义了保存对象状态的所有内部对象属性的类型。类还定义了由方法的代码表示的对象行为。类/对象可能没有状态或行为。Java 还提供了一个在不创建对象的情况下静态访问行为的方法。但是这些可能性仅仅是为了保持状态和行为一致而引入的对象/类概念的补充。

举例来说，为了说明这个概念，一个类`Vehicle`在原则上定义了车辆的特性和行为。让我们把模型简单化，假设一辆车只有两个特性：重量和一定功率的发动机。它也可以有一定的行为：它可以在一定的时间内达到一定的速度，这取决于它的两个属性的值。这种行为可以用一种方法来表示，该方法计算车辆在一定时间内可以达到的速度。`Vehicle`类的每个对象都有一个特定的状态（属性值），速度计算将在同一时间段内产生不同的速度

所有 Java 代码都包含在方法中。**方法**是一组具有（可选）输入参数和返回值（可选）的语句。此外，每种方法都有副作用：例如，它可以显示消息或将数据写入数据库。类/对象行为在方法中实现。

例如，按照我们的示例，速度计算可以驻留在`double calculateSpeed(float seconds)`方法中。您可以猜到，该方法的名称是`calculateSpeed`，它接受秒数（带有小数部分）作为参数，并将速度值返回为`double`。

# 继承

正如我们已经提到的，对象可以建立父子关系，并以这种方式共享属性和行为。例如，我们可以创建一个继承`Vehicle`类的属性（例如权重）和行为（速度计算）的`Car`类。此外，子类可以有自己的属性（例如，乘客数量）和特定于汽车的行为（例如，软减震）。但是，如果我们创建一个`Truck`类作为车辆的子类，它的额外卡车特定属性（例如有效载荷）和行为（硬减震）将不同。

据说，`Car`类或`Truck`类的每个对象都有一个`Vehicle`类的父对象。但是`Car`和`Truck`类的对象不共享特定的`Vehicle`对象（每次创建子对象时，首先创建一个新的父对象）。他们只分享父项的行为。这就是为什么所有子对象可以有相同的行为，但状态不同。这是实现代码可重用性的一种方法。当对象行为必须动态更改时，它可能不够灵活。在这种情况下，对象组合（从其他类带来行为）或函数式编程更合适（参见第 13 章、“函数式编程”）。

有可能使子项的行为与遗传行为不同。为了实现它，捕获行为的方法可以在`child`类中重新实现。据说子项可以*覆盖*遗传的行为，我们将很快解释如何做（见“重载、覆盖和隐藏”一节）。例如，如果`Car`类有自己的速度计算方法，则不继承父类`Vehicle`的相应方法，而是使用在子类中实现的新速度计算方法。

父类的属性也可以继承（但不能覆盖）。然而，类属性通常被声明为私有的；它们不能被继承这就是封装的要点。参见“访问修饰符”部分中对各种访问级别的描述`public`、`protected`和`private`。

如果父类从另一个类继承某些行为，那么子类也会获取（继承）该行为，当然，除非父类覆盖它。继承链的长度没有限制。

Java 中的父子关系用`extends`关键字表示：

```java
class A { }
class B extends A { }
class C extends B { }
class D extends C { }
```

在此代码中，`A`、`B`、`C`和`D`类具有以下关系：

*   类`D`继承自类`C`、`B`和`A`
*   类`C`继承自类`B`和`A`
*   类`B`继承自类`A`

类`A`的所有非私有方法都由类`B`、`C`和`D`继承（如果不覆盖）

# 抽象/接口

一个方法的名称及其参数类型的列表称为**方法签名**。它描述了如何访问一个对象（在我们的示例中是`Car`或`Truck`的）的行为。这样的描述与`return`类型一起被呈现为接口。它没有说明只计算方法名、参数类型、它们在参数列表中的位置以及结果类型的代码。所有的实现细节都隐藏（封装）在*实现*这个接口的类中。

正如我们已经提到的，一个类可以实现许多不同的接口。但是两个不同的类（及其对象）即使实现同一个接口，其行为也可能不同

与类类似，接口也可以使用`extends`关键字具有父子关系：

```java
interface A { }
interface B extends A {}
interface C extends B {}
interface D extends C {}
```

在本规范中，`A`、`B`、`C`、`D`的接口关系如下：

*   接口`D`继承自接口`C`、`B`和`A`
*   接口`C`继承自接口`B`和`A`
*   接口`B`继承自接口`A`

接口`A`的所有非私有方法都由接口`B`、`C`和`D`继承

抽象/接口还减少了代码不同部分之间的依赖性，从而提高了代码的可维护性。只要接口保持不变，每个类都可以更改，而无需与客户端协调。

# 封装

**封装**通常被定义为一种数据隐藏，或者将公开访问的方法和私有访问的数据捆绑在一起。从广义上讲，封装是对对象属性的受控访问

对象属性值的快照称为**对象状态**。对象状态是封装的数据。因此，封装解决了促使创建面向对象编程的主要问题：更好地管理对共享数据的并发访问。例如：

```java
class A {
  private String prop = "init value";
  public void setProp(String value){
     prop = value;
  }
  public String getProp(){
     return prop;
  }
}
```

如您所见，要读取或修改`prop`属性的值，我们不能直接访问它，因为访问修饰符`private`。相反，我们只能通过`setProp(String value)`和`getProp()`方法来实现。

# 多态

**多态**是一个对象作为不同类的对象或作为不同接口实现的能力。它的存在归功于前面提到的所有概念：继承、接口和封装。没有它们，多态就不可能

继承允许对象获取或覆盖其所有祖先的行为。接口对客户端代码隐藏实现它的类的名称。封装防止暴露对象状态

在下面的部分中，我们将演示所有这些概念的实际应用，并在“多态的实际应用”部分中查看多态的具体用法。

# 类

Java 程序是表示可执行操作的一系列语句，这些语句按方法组织，方法按类组织。一个或多个类存储在`.java`文件中，它们可以由 Java 编译器`javac`编译（从 Java 语言转换成字节码）并存储在`.class`文件中。每个`.class`文件只包含一个编译类，可以由 JVM 执行。

一个`java`命令启动 JVM 并告诉它哪个类是`main`类，这个类有一个名为`main()`的方法。`main`方法有一个特定的声明：它必须是`public static`，必须返回`void`，名称为`main`，并接受一个`String`类型数组的单个参数。

JVM 将主类加载到内存中，找到`main()`方法，开始一条语句一条语句地执行它。`java`命令还可以传递`main()`方法作为`String`值数组接收的参数（参数），如果 JVM 遇到需要执行另一个类的方法的语句，那么这个类（它的`.class`文件）也会加载到内存中，并执行相应的方法，Java 程序流是关于加载类和执行它们的方法的。

下面是主类的示例：

```java
public class MyApp {
  public static void main(String[] args){
     AnotherClass an = new AnotherClass();
     for(String s: args){
        an.display(s);
     }
   }
}
```

它表示一个非常简单的应用，它接收任意数量的参数并将它们逐个传递到`AnotherClass`类的`display()`方法中，当 JVM 启动时，它首先从`MyApp.class`文件加载`MyApp`类。然后它从`AnotherClass.class`文件加载`AnotherClass`类，使用`new`操作符创建该类的对象（我们稍后将讨论），并调用`display()`方法。

这里是`AnotherClass`类：

```java
public class AnotherClass {
   private int result;
   public void display(String s){
      System.out.println(s);
   }
   public int process(int i){
      result = i *2;
      return result;
   }
   public int getResult(){
      return result;
   }
} 
```

如您所见，`display()`方法用于它的副作用，只是它打印出传入的值，并且不返回任何内容（`void`。`AnotherClass`类还有两种方法：

*   `process()`方法将输入整数加倍，存储在其`result`属性中，并将值返回给调用者
*   `getResult()`方法允许以后随时从对象获取结果

在我们的演示应用中没有使用这两种方法。我们展示它们只是为了演示一个类可以有属性（在本例中为`result`）和许多其他方法。

`private`关键字使值只能从类内部、从其方法访问。关键字使属性或方法可由任何其他类访问。

# 方法

如前所述，Java 语句被组织为方法：

```java
<return type> <method name>(<list of parameter types>){
     <method body that is a sequence of statements>
}
```

我们已经看到了一些例子。一个方法有一个名称，一组输入参数或根本没有参数，`{}`括号内有一个主体，返回类型或`void`关键字表示该方法不返回任何值。

方法名和参数类型列表一起称为**方法签名**。输入参数的数量称为**参数量**。

如果两个方法在输入参数列表中具有相同的名称、相同的参数量和相同的类型序列，则它们具有相同的*签名*。

以下两种方法具有相同的签名：

```java
double doSomething(String s, int i){
    //some code goes here
}

double doSomething(String i, int s){
    //some code other code goes here
}
```

即使签名相同，方法中的代码也可能不同

以下两种方法具有不同的签名：

```java
double doSomething(String s, int i){
    //some code goes here
}

double doSomething(int s, String i){
    //some code other code goes here
}
```

只要改变参数序列，签名就不同了，即使方法名保持不变。

# 可变参数

有一种特殊类型的参数需要提及，因为它与所有其他类型的参数完全不同。它被声明为后跟三个点的类型。它被称为**可变参数**（**varargs**）。但是，首先，让我们简单地定义一下 Java 中的数组是什么。

**数组**是保存相同类型元素的数据结构。元素由数字索引引用。这就够了，现在。我们在第 6 章、“数据结构、泛型和流行工具”中更多地讨论数组

让我们从一个例子开始。让我们使用可变参数声明方法参数：

```java
String someMethod(String s, int i, double... arr){
 //statements that compose method body
}
```

当调用`someMethod`方法时，Java 编译器从左到右匹配参数。一旦到达最后一个可变参数，它将创建一个剩余参数的数组并将其传递给方法。下面是演示代码：

```java
public static void main(String... args){
    someMethod("str", 42, 10, 17.23, 4);

}

private static String someMethod(String s, int i, double... arr){
    System.out.println(arr[0] + ", " + arr[1] + ", " + arr[2]); 
                                             //prints: 10.0, 17.23, 4.0
    return s;
}
```

如您所见，可变参数的作用类似于指定类型的数组。它可以作为方法的最后一个或唯一参数列出。这就是为什么有时您可以看到前面示例中声明的`main`方法。

# 构造器

当创建一个对象时，JVM 使用一个**构造器**。构造器的目的是初始化对象状态，为所有声明的属性赋值。如果类中没有声明构造器，JVM 只会将缺省值赋给属性。我们已经讨论了原始类型的默认值：整数类型的默认值是`0`，浮点类型的默认值是`0.0`，布尔类型的默认值是`false`。对于其他 Java 引用类型（参见第 3 章、“Java 基础”），默认值为`null`，表示引用类型的属性没有赋值。

当一个类中没有声明构造器时，就说这个类有一个没有 JVM 提供的参数的默认构造器。

如果需要，可以显式声明任意数量的构造器，每个构造器使用不同的参数集来设置初始状态。举个例子：

```java
class SomeClass {
     private int prop1;
     private String prop2;
     public SomeClass(int prop1){
         this.prop1 = prop1;
     }
     public SomeClass(String prop2){
         this.prop2 = prop2;
     }
     public SomeClass(int prop1, String prop2){
         this.prop1 = prop1;
         this.prop2 = prop2;
     }   
     // methods follow 
}
```

如果属性不是由构造器设置的，则相应类型的默认值将自动分配给它。

当多个类沿同一连续线相关联时，首先创建父对象。如果父对象需要为其属性设置非默认初始值，则必须使用如下所示的`super`关键字将其构造器作为子构造器的第一行调用：

```java
class TheParentClass {
    private int prop;
    public TheParentClass(int prop){
        this.prop = prop;
    }
    // methods follow
}

class TheChildClass extends TheParentClass{
 private int x;
 private String prop;
 private String anotherProp = "abc";
 public TheChildClass(String prop){
 super(42);
 this.prop = prop;
 }
 public TheChildClass(int arg1, String arg2){
 super(arg1);
 this.prop = arg2;
 }
 // methods follow
}
```

在前面的代码示例中，我们向`TheChildClass`添加了两个构造器：一个总是将`42`传递给`TheParentClass`的构造器，另一个接受两个参数。请注意已声明但未显式初始化的`x`属性。当创建`TheChildClass`的对象时，它将被设置为值`0`，即`int`类型的默认值。另外，请注意显式初始化为`"abc"`值的`anotherProp`属性。否则，它将被初始化为值`null`，任何引用类型的默认值，包括`String`。

从逻辑上讲，有三种情况不需要类中构造器的显式定义：

*   当对象及其任何父对象都没有需要初始化的属性时
*   当每个属性与类型声明一起初始化时（例如，`int x = 42`）
*   当属性初始化的默认值足够好时

然而，即使满足了所有三个条件（在列表中提到），也有可能仍然实现了构造器。例如，您可能希望执行一些语句来初始化某个外部资源—对象一经创建就需要的文件或另一个数据库。

一旦添加了显式构造器，就不会提供默认构造器，并且以下代码将生成一个错误：

```java
class TheParentClass {
    private int prop;
    public TheParentClass(int prop){
        this.prop = prop;
    }
    // methods follow
}

class TheChildClass extends TheParentClass{
    private String prop;
    public TheChildClass(String prop){
        //super(42);       //No call to the parent's contuctor
        this.prop = prop;
    }
    // methods follow
}
```

为了避免这个错误，要么在`TheParentClass`中添加一个没有参数的构造器，要么调用父类的显式构造器作为子类构造器的第一条语句。以下代码不会生成错误：

```java
class TheParentClass {
    private int prop;
 public TheParentClass() {}
    public TheParentClass(int prop){
        this.prop = prop;
    }
    // methods follow
}

class TheChildClass extends TheParentClass{
    private String prop;
    public TheChildClass(String prop){
        this.prop = prop;
    }
    // methods follow
}
```

需要注意的一个重要方面是，构造器虽然看起来像方法，但不是方法，甚至不是类的成员。构造器没有返回类型，并且总是与类同名。它的唯一用途是在创建类的新实例时调用。

# `new`运算符

`new`操作符通过为新对象的属性分配内存并返回对该内存的引用来创建类的对象（也可以说它**实例化类**或**创建类**的实例）。此内存引用被分配给与用于创建对象或其父对象类型的类相同类型的变量：

```java
TheChildClass ref1 = new TheChildClass("something"); 
TheParentClass ref2 = new TheChildClass("something");
```

这是一个有趣的观察。在代码中，对象引用`ref1`和`ref2`都提供了对`TheChildClass`和`TheParentClass`方法的访问。例如，我们可以向这些类添加方法，如下所示：

```java
class TheParentClass {
    private int prop;
    public TheParentClass(int prop){
        this.prop = prop;
    }
    public void someParentMethod(){}
}

class TheChildClass extends TheParentClass{
    private String prop;
    public TheChildClass(int arg1, String arg2){
        super(arg1);
        this.prop = arg2;
    }
    public void someChildMethod(){}
}
```

然后我们可以使用以下任何引用调用它们：

```java
TheChildClass ref1 = new TheChildClass("something");
TheParentClass ref2 = new TheChildClass("something");
ref1.someChildMethod();
ref1.someParentMethod();
((TheChildClass) ref2).someChildMethod();
ref2.someParentMethod();

```

注意，要使用父级的类型引用访问子级的方法，我们必须将其强制转换为子级的类型。否则，编译器将生成一个错误。这是可能的，因为我们已经为父对象的类型引用指定了子对象的引用。这就是多态的力量。我们将在“多态的作用”一节中详细讨论。

当然，如果我们将父对象赋给父类型的变量，那么即使使用强制转换，也无法访问子对象的方法，如下例所示：

```java
TheParentClass ref2 = new TheParentClass(42);
((TheChildClass) ref2).someChildMethod();  //compiler's error
ref2.someParentMethod();
```

为新对象分配内存的区域称为**堆**。JVM 有一个名为**垃圾收集**的进程，它监视这个区域的使用情况，并在不再需要对象时释放内存以供使用。例如，查看以下方法：

```java
void someMethod(){
   SomeClass ref = new SomeClass();
   ref.someClassMethod();
   //other statements follow
}
```

一旦`someMethod()`方法的执行完成，`SomeClass`的对象就不再可访问。这就是垃圾收集器注意到的，并释放这个对象占用的内存，我们将在第 9 章、“JVM 结构和垃圾收集”中讨论垃圾收集过程。

# `java.lang.Object`对象

在 Java 中，默认情况下，所有类都是`Object`类的子类，即使您没有隐式地指定它。`Object`类在标准 JDK 库的`java.lang`包中声明。我们将在“包、导入和访问”部分定义什么是*包*，并在第 7 章、“Java 标准和外部库”中描述库。

让我们回顾一下在“继承”一节中提供的示例：

```java
class A { }
class B extends A {}
class C extends B {}
class D extends C {}
```

所有类`A`、`B`、`C`、`D`都是`Object`类的子类，每个类继承 10 个方法：

*   `public String toString()`
*   `public int hashCode()`
*   `public boolean equals (Object obj)`
*   `public Class getClass()`
*   `protected Object clone()`
*   `public void notify()`
*   `public void notifyAll()`
*   `public void wait()`
*   `public void wait(long timeout)`
*   `public void wait(long timeout, int nanos)`

前三个`toString()`、`hashCode()`和`equals()`是最常用的方法，并且经常被重新实现（覆盖）。`toString()`方法通常用于打印对象的状态。它在 JDK 中的默认实现如下所示：

```java
public String toString() {
   return getClass().getName()+"@"+Integer.toHexString(hashCode());
}
```

如果我们在`TheChildClass`类的对象上使用它，结果如下：

```java
TheChildClass ref1 = new TheChildClass("something");
System.out.println(ref1.toString());  
//prints: com.packt.learnjava.ch02_oop.Constructor$TheChildClass@72ea2f77
```

顺便说一句，在将对象传递给`System.out.println()`方法和类似的输出方法时，不需要显式调用`toString()`，因为它们无论如何都是在方法内部调用的，在我们的例子中`System.out.println(ref1)`会产生相同的结果。

所以，正如您所看到的，这样的输出对人不友好，所以覆盖`toString()`方法是个好主意，最简单的方法是使用 IDE。例如，在 IntelliJ IDEA 中，在`TheChildClass`代码中单击鼠标右键，如下图所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/5a69128d-ff43-4ff9-9bcf-4eea26602982.png)

选择并单击“生成”，然后选择并单击`toString()`，如下图所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/3a31d0a1-7e7a-429c-96ae-4c9d7223f034.png)

新的弹出窗口将允许您选择在`toString()`方法中包含哪些属性。仅选择`TheChildClass`的属性，如下所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/874ff9a2-d152-487a-99bc-b10fafe45200.png)

单击“确定”按钮后，将生成以下代码：

```java
@Override
public String toString() {
    return "TheChildClass{" +
            "prop='" + prop + '\'' +
            '}';
}
```

如果类中有更多属性并且您选择了它们，那么更多属性及其值将包含在方法输出中。如果我们现在打印对象，结果将是：

```java
TheChildClass ref1 = new TheChildClass("something");
System.out.println(ref1.toString());  
                          //prints: TheChildClass{prop='something'}
```

这就是为什么`toString()`方法经常被覆盖，甚至包括在 IDE 的服务中。

我们将在第 6 章、“数据结构、泛型和流行工具”中更详细地讨论`hashCode()`和`equals()`方法。

`getClass()`和`clone()`方法不常使用。`getClass()`方法返回`Class`类的一个对象，这个对象有许多提供各种系统信息的方法。最常用的方法是返回当前对象的类名的方法。`clone()`方法可以复制当前对象。只要当前对象的所有属性都是原始类型，它就可以正常工作。但是，如果存在引用类型属性，`clone()`方法必须重新实现，这样才能正确复制引用类型。否则，将只复制引用，而不复制对象本身。这种拷贝称为**浅拷贝**，在某些情况下可能已经足够好了。`protected`关键字表示只有该类的子类可以访问它（参见“包、导入和访问”部分）。

类`Object`中的最后五个方法用于线程之间的通信，而轻量级进程用于并发处理。它们通常不会重新实现。

# 实例和静态属性及方法

到目前为止，我们看到的大多数方法只能在类的对象（实例）上调用。这种方法称为**实例方法**。它们通常使用对象属性（对象状态）的值。否则，如果它们不使用对象状态，则可以使它们成为`static`并在不创建对象的情况下调用。这种方法的例子是`main()`方法，这里是另一个例子：

```java
class SomeClass{
    public static void someMethod(int i){
        //do something
    }
}
```

此方法可按如下方式调用：

```java
SomeClass.someMethod(42);

```

静态方法也可以在对象上调用，但这被认为是不好的做法，因为它对试图理解代码的人隐藏了方法的静态特性。此外，它还会引发编译器警告，根据编译器的实现，甚至可能生成编译器错误。

类似地，属性可以声明为静态的，因此无需创建对象即可访问。例如：

```java
class SomeClass{
    public static String SOME_PROPERTY = "abc";
}
```

也可以通过类直接访问此属性，如下所示：

```java
System.out.println(SomeClass.SOME_PROPERTY);  //prints: abc

```

拥有这样一个静态属性与状态封装的思想背道而驰，可能会导致并发数据修改的所有问题，因为它作为一个副本存在于 JVM 内存中，并且使用它的所有方法共享相同的值。这就是为什么静态属性通常用于两个目的：

*   存储一个常数—一个可以读取但不能修改的值（也称为**只读值**）
*   存储无状态对象，该对象的创建成本很高或保留只读值

常量的典型示例是资源的名称：

```java
class SomeClass{
    public static final String INPUT_FILE_NAME = "myFile.csv";
}
```

注意`static`属性前面的`final`关键字。它告诉编译器和 JVM 这个值一旦分配就不能改变。尝试这样做会产生错误。它有助于保护该值并清楚地表达将该值作为常量的意图。当人们试图理解代码的工作原理时，这些看似很小的细节使代码更容易理解。

也就是说，考虑使用接口来达到这样的目的。由于 Java1.8，接口中声明的所有字段都是隐式静态和`final`的，因此忘记将值声明为`final`的可能性较小。我们将很快讨论接口。

当一个对象被声明为静态`final`类属性时，并不意味着它的所有属性都自动成为`final`。它只保护属性不被分配同一类型的另一个对象，我们将在第 8 章、“多线程和并发处理”中讨论并发访问对象属性的复杂过程。然而，程序员通常使用静态`final`对象来存储只读的值，这些值只是按照在应用中使用的方式来存储的。典型的例子是应用配置信息。一旦从磁盘读取后创建，它就不会更改，即使可以更改。此外，数据的缓存是从外部资源获得的

同样，在将此类类属性用于此目的之前，请考虑使用一个接口，该接口提供更多支持只读功能的默认行为

与静态属性类似，可以在不创建类实例的情况下调用静态方法。例如，考虑以下类：

```java
class SomeClass{
    public static String someMethod() {
        return "abc";
    }
}
```

我们可以只使用类名来调用前面的方法：

```java
System.out.println(SomeClass.someMethod()); //prints: abc
```

# 接口

在“抽象/接口”部分中，我们一般地讨论了接口。在本节中，我们将描述一个表示它的 Java 语言构造

一个**接口**显示了一个对象的期望值。它隐藏了实现，并且只公开带有返回值的方法签名。例如，下面是一个接口，它声明了两个抽象方法：

```java
interface SomeInterface {
    void method1();
    String method2(int i);
}
```

下面是一个实现它的类：

```java
class SomeClass implements SomeInterface{
    public void method1(){
        //method body
    }
    public String method2(int i) {
        //method body
        return "abc";
    }
}
```

无法实例化接口。只有创建*实现*此接口的类的对象，才能创建接口类型的对象：

```java
SomeInterface si = new SomeClass(); 

```

如果没有实现接口的所有抽象方法，则必须将类声明为抽象的，并且不能实例化（参见“接口与抽象类”部分）

接口不描述如何创建类的对象。要发现这一点，必须查看该类并查看它有哪些构造器。接口也不描述静态类方法。因此，接口只是类实例（对象）的公共面。

在 Java8 中，接口不仅具有抽象方法（没有主体），而且具有真正实现的方法。根据 Java 语言规范，“接口的主体可以声明接口的成员，即字段、方法、类和接口。”如此宽泛的语句提出了一个问题：接口和类有什么区别？我们已经指出的一个主要区别是：不能实例化接口；只能实例化类。

另一个区别是在接口内部实现的非静态方法被声明为`default`或`private`。相反，`default`声明对于类方法不可用。

此外，接口中的字段是隐式公共的、静态的和最终的。相比之下，默认情况下，类属性和方法不是静态的或最终的。类本身、其字段、方法和构造器的隐式（默认）访问修饰符是包私有的，这意味着它只在自己的包中可见

# 默认方法

为了了解接口中默认方法的功能，让我们看一个接口和实现它的类的示例，如下所示：

```java
interface SomeInterface {
    void method1();
    String method2(int i);
 default int method3(){
 return 42;
    }
}

class SomeClass implements SomeInterface{
    public void method1(){
        //method body
    }
    public String method2(int i) {
        //method body
        return "abc";
    }
}
```

我们现在可以创建一个`SomeClass`类的对象并进行以下调用：

```java
SomeClass sc = new SomeClass();
sc.method1();
sc.method2(22);  //returns: "abc"
sc.method3();    //returns: 42

```

如您所见，`method3()`并没有在`SomeClass`类中实现，但是看起来好像该类已经实现了它。这是一种将新方法添加到现有类而不更改它的方法，方法是将默认方法添加到类实现的接口。

现在我们也将`method3()`实现添加到类中，如下所示：

```java
class SomeClass implements SomeInterface{
    public void method1(){
        //method body
    }
    public String method2(int i) {
        //method body
        return "abc";
    }
    public int method3(){
 return 15;
 }
}
```

现在忽略`method3()`的接口实现：

```java
SomeClass sc = new SomeClass();
sc.method1();
sc.method2(22);  //returns: "abc"
sc.method3();    //returns: 15
```

接口中默认方法的目的是为类（实现此接口的类）提供一个新方法，而不更改它们。但是一旦类实现了新方法，接口实现就会被忽略。

# 私有方法

如果接口中有多个默认方法，则可以创建只能由接口的默认方法访问的私有方法。它们可以用来包含公共功能，而不是在每个默认方法中重复：

```java
interface SomeInterface {
    void method1();
    String method2(int i);
    default int method3(){
        return getNumber();
    }
    default int method4(){
        return getNumber() + 22;
    }
    private int getNumber(){
        return 42;
    }
}
```

私有方法的这个概念与类中的私有方法没有什么不同（参见“包、导入和访问”部分）。无法从接口外部访问私有方法。

# 静态字段和方法

自 Java8 以来，接口中声明的所有字段都是隐式公共、静态和`final`常量。这就是为什么接口是常量的首选位置。你不需要在他们的声明中加上`public static final`。

至于静态方法，它们在接口中的作用方式与在类中的作用方式相同：

```java
interface SomeInterface{
   static String someMethod() {
      return "abc";
   }
}
```

注意，不需要将接口方法标记为`public`。默认情况下，所有非私有接口方法都是公共的。

我们可以只使用一个接口名来调用前面的方法：

```java
System.out.println(SomeInetrface.someMethod()); //prints: abc
```

# 接口与抽象类

我们已经提到类可以声明为`abstract`。它可能是我们不希望实例化的常规类，也可能是包含（或继承）抽象方法的类。在后一种情况下，我们必须将此类类声明为`abstract`，以避免编译错误。

在许多方面，抽象类与接口非常相似。它强制扩展它的每个子类实现抽象方法。否则，子级不能实例化，必须声明为抽象本身

但是，接口和抽象类之间的一些主要区别使它们在不同的情况下都很有用：

*   抽象类可以有构造器，而接口不能。
*   抽象类可以有状态，而接口不能。
*   抽象类的字段可以是`public`、`private`或`protected`、`static`或`final`或`final`，而在接口中，字段总是`public`、`static`、`final`。
*   抽象类中的方法可以是`public`、`private`或`protected`，接口方法只能是`public`或`private`。
*   如果要修改的类已经扩展了另一个类，则不能使用抽象类，但可以实现接口，因为一个类只能扩展另一个类，但可以实现多个接口

参见“多态实践”一节中的抽象用法示例。

# 重载、覆盖和隐藏

我们已经在*继承*和“抽象/接口”部分中提到了覆盖。它将父类中实现的非静态方法替换为子类中具有相同签名的方法。接口的默认方法也可以在扩展它的接口中覆盖。

隐藏类似于覆盖，但仅适用于静态方法和静态以及实例属性。

重载是在同一个类或接口中创建几个具有相同名称和不同参数（因此，不同的签名）的方法

在本节中，我们将讨论所有这些概念，并演示它们如何用于类和接口。

# 重载

不可能在同一接口中有两个方法，也不可能在一个类中有相同的签名。要有不同的签名，新方法必须有新名称或不同的参数类型列表（类型的顺序很重要）。有两个同名但参数类型列表不同的方法构成重载。下面是一些在接口中重载的合法方法的示例：

```java
interface A {
    int m(String s);
    int m(String s, double d);
    default int m(String s, int i) { return 1; }
    static int m(String s, int i, double d) { return 1; }
}
```

请注意，前面的两个方法没有相同的签名，包括`default`和`static`方法，否则将生成编译器的错误。指定为默认值或静态值都不会在重载中起任何作用。返回类型也不影响重载。我们到处使用`int`作为返回类型，只是为了让示例不那么混乱。

方法重载在类中的执行方式类似：

```java
    class C {
        int m(String s){ return 42; }
        int m(String s, double d){ return 42; }
        static int m(String s, double d, int i) { return 1; }
    }
```

在哪里声明具有相同名称的方法并不重要。下面的方法重载与前面的示例没有区别，如下所示：

```java
interface A {
    int m(String s);
    int m(String s, double d);
}
interface B extends A {
    default int m(String s, int i) { return 1; }
    static int m(String s, int i, double d) { return 1; }
}
class C {
     int m(String s){ return 42; }
}
class D extends C {
     int m(String s, double d){ return 42; }
     static int m(String s, double d, int i) { return 1; }
}
```

私有非静态方法只能由同一类的非静态方法重载。

当方法具有相同名称但参数类型列表不同，并且属于同一接口（或类）或不同接口（或类），其中一个接口是另一个接口的祖先时，就会发生重载。私有方法只能由同一类中的方法重载。

# 覆盖

与重载不同的是，重载发生在静态和非静态方法中，方法覆盖只发生在非静态方法中，并且只有当它们具有*完全相同的签名*和*属于不同的接口（或类）*，其中一个接口是另一个接口的祖先。

覆盖方法驻留在子接口（或类）中，而覆盖方法具有相同的签名，并且属于某个祖先接口（或类）。不能覆盖私有方法。

以下是在接口中覆盖方法的示例：

```java
interface A {
    default void method(){
        System.out.println("interface A");
    }
}
interface B extends A{
    @Override
    default void method(){
        System.out.println("interface B");
    }
}
class C implements B { }
```

如果我们使用`C`类实例调用`method()`，结果如下：

```java
C c = new C();
c.method();      //prints: interface B

```

请注意注解`@Override`的用法。它告诉编译器程序员认为带注解的方法覆盖了一个祖先接口的方法。通过这种方式，编译器可以确保覆盖确实发生，否则会生成错误。例如，程序员可能会将方法的名称拼错如下：

```java
interface B extends A{
    @Override
    default void metod(){
        System.out.println("interface B");
    }
}
```

如果发生这种情况，编译器会生成一个错误，因为没有方法`metod()`可以覆盖。如果没有注解`@Overrride`，这个错误可能会被程序员忽略，结果会截然不同：

```java
C c = new C();
c.method();      //prints: interface A
```

覆盖的规则同样适用于类实例方法。在下面的示例中，`C2`类覆盖了`C1`类的方法：

```java
class C1{
    public void method(){
        System.out.println("class C1");
    }
}
class C2 extends C1{
    @Override
    public void method(){
        System.out.println("class C2");
    }
}
```

结果如下：

```java
C2 c2 = new C2();
c2.method();      //prints: class C2

```

而且，在具有覆盖方法的类或接口和具有覆盖方法的类或接口之间有多少祖先并不重要：

```java
class C1{
    public void method(){
        System.out.println("class C1");
    }
}
class C3 extends C1{
    public void someOtherMethod(){
        System.out.println("class C3");
    }
}
class C2 extends C3{
    @Override
    public void method(){
        System.out.println("class C2");
    }
}
```

前面方法的覆盖结果仍然相同。

# 隐藏

**隐藏**被很多人认为是一个复杂的话题，但不应该是，我们会尽量让它看起来简单。

*隐藏*这个名字来源于类和接口的静态属性和方法的行为。每个静态属性或方法在 JVM 内存中作为单个副本存在，因为它们与接口或类关联，而不是与对象关联。接口或类作为单个副本存在。这就是为什么我们不能说子级的静态属性或方法覆盖父级的具有相同名称的静态属性或方法。当类或接口被加载时，所有静态属性和方法只被加载到内存中一次，并且保持在那里，而不是复制到任何地方。让我们看看这个例子。

让我们创建两个具有父子关系和具有相同名称的静态字段和方法的接口：

```java
interface A {
    String NAME = "interface A";
    static void method() {
        System.out.println("interface A");
    }
}
interface B extends A {
    String NAME = "interface B";
    static void method() {
        System.out.println("interface B");
    }
}
```

请注意接口字段标识符的大写字母。这就是通常用来表示常量的约定，不管它是在接口中还是在类中声明的。只是提醒您，Java 中的常量是一个变量，一旦初始化，就不能重新分配另一个值。接口字段默认为常量，因为接口中的任何字段都是*最终的*（请参阅“最终属性、方法和类”部分）。

如果从`B`接口打印`NAME`并执行其`method()`，则得到如下结果：

```java
System.out.println(B.NAME); //prints: interface B
B.method();                 //prints: interface B

```

它看起来很像覆盖，但实际上，它只是我们调用与这个特定接口相关联的特定属性或方法。

类似地，考虑以下类：

```java
public class C {
    public static String NAME = "class C";
    public static void method(){
        System.out.println("class C"); 
    }
    public String name1 = "class C";
}
public class D extends C {
    public static String NAME = "class D";
    public static void method(){
        System.out.println("class D"); 
    }
    public String name1 = "class D";
}
```

如果我们尝试使用类本身访问`D`类的静态成员，我们将得到我们所要求的：

```java
System.out.println(D.NAME);  //prints: class D
D.method();                  //prints: class D
```

只有在使用对象访问属性或静态方法时才会出现混淆：

```java
C obj = new D();

System.out.println(obj.NAME);       //prints: class C
System.out.println(((D) obj).NAME); //prints: class D

obj.method();                       //prints: class C
((D)obj).method();                  //prints: class D

System.out.println(obj.name1);       //prints: class C
System.out.println(((D) obj).name1); //prints: class D
```

`obj`变量引用了`D`类的对象，强制转换证明了这一点，如前面的示例所示。但是，即使我们使用对象，尝试访问静态属性或方法也会带来用作声明变量类型的类的成员。对于示例最后两行中的实例属性，Java 中的属性不符合多态行为，我们得到父`C`类的`name1`属性，而不是子`D`类的预期属性。

若要避免与类的静态成员混淆，请始终使用类而不是对象访问它们。若要避免与实例属性混淆，请始终将它们声明为私有并通过方法访问。

要演示最后一个技巧，请考虑以下类：

```java
class X {
    private String name = "class X";
    public String getName() {
        return name;
    }
    public void setName(String name) {
        this.name = name;
    }
}
class Y extends X {
    private String name = "class Y";
    public String getName() {
        return name;
    }
    public void setName(String name) {
        this.name = name;
    }
}
```

如果我们对实例属性执行与对类`C`和`D`相同的测试，结果将是：

```java
X x = new Y();
System.out.println(x.getName());      //prints: class Y
System.out.println(((Y)x).getName()); //prints: class Y

```

现在我们使用方法访问实例属性，这些方法是覆盖效果的主题，不再有意外的结果。

为了结束在 Java 中隐藏的讨论，我们想提到另一种类型的隐藏，即当局部变量隐藏具有相同名称的实例或静态属性时。下面是一个类：

```java
public class HidingProperty {
   private static String name1 = "static property";
   private String name2 = "instance property";

   public void method() {
      var name1 = "local variable";
      System.out.println(name1);     //prints: local variable

      var name2 = "local variable";  //prints: local variable
      System.out.println(name2);

      System.out.println(HidingProperty.name1); //prints: static property
      System.out.println(this.name2);         //prints: instance property
   }
}
```

如您所见，局部变量`name1`隐藏同名的静态属性，而局部变量`name2`隐藏实例属性。仍然可以使用类名访问静态属性（参见`HidingProperty.name1`。请注意，尽管声明为`private`，但可以从类内部访问它

实例属性总是可以通过使用`this`关键字来访问，该关键字表示**当前对象**。

# 最终变量、方法和类

在 Java 中，我们已经多次提到了与常量概念相关的一个`final`属性。但这只是使用`final`关键字的一种情况，它一般可以应用于任何变量。此外，类似的约束也可以应用于方法，甚至类，从而防止方法被覆盖和类被扩展。

# 最终变量

变量声明前面的`final`关键字使该变量在初始化后不可变。例如：

```java
final String s = "abc";

```

初始化甚至可以延迟：

```java
final String s;
s = "abc";

```

对于对象属性，此延迟只能持续到创建对象为止。这意味着可以在构造器中初始化属性。例如：

```java
private static class A {
    private final String s1 = "abc";
    private final String s2;
    private final String s3;   //error
    private final int x;       //error

    public A() {
        this.s1 = "xyz";      //error
        this.s2 = "xyz";     
    }
}
```

请注意，即使在对象构造期间，也不可能在声明期间和构造器中两次初始化属性。另外值得注意的是，`final`属性必须显式初始化。从前面的示例中可以看到，编译器不允许将`final`属性初始化为默认值。

也可以初始化初始化块中的`final`属性：

```java
class B {
    private final String s1 = "abc";
    private final String s2;
    {
        s1 = "xyz"; //error
        s2 = "abc";
    }
}
```

对于静态属性，无法在构造器中对其进行初始化，因此必须在其声明期间或在静态初始化块中对其进行初始化：

```java
class C {
    private final static String s1 = "abc";
    private final static String s2;
    static {
        s1 = "xyz"; //error
        s2 = "abc";
    }
}
```

在接口中，所有字段都是`final`，即使它们没有声明为`final`。由于接口中不允许使用构造器或初始化块，因此初始化接口字段的唯一方法是在声明期间。否则会导致编译错误：

```java
interface I {
    String s1;  //error
    String s2 = "abc";
}
```

# 最终方法

声明为`final`的方法不能在子类中覆盖，也不能在静态方法中隐藏。例如，`java.lang.Object`类是 Java 中所有类的祖先，它的一些方法声明为`final`：

```java
public final Class getClass()
public final void notify()
public final void notifyAll()
public final void wait() throws InterruptedException
public final void wait(long timeout) throws InterruptedException
public final void wait(long timeout, int nanos)
                                     throws InterruptedException
```

`final`类的所有私有方法和未继承方法实际上都是`final`的，因为您不能覆盖它们。

# 最终类

`final`类不能扩展。它不能有子项，这使得所有的方法都有效的`final`。此功能用于安全性，或者当程序员希望确保类功能不能由于某些其他设计考虑而被覆盖、重载或隐藏时。

# 多态的作用

多态是 OOP 最强大、最有用的特性。它使用了我们目前介绍的所有其他面向对象的概念和特性。这是掌握 Java 编程的最高概念点。之后，本书的其余部分将主要介绍 Java 语言语法和 JVM 功能

正如我们在“OOP 概念”一节中所述，**多态**是一个对象作为不同类的对象或作为不同接口的实现的能力。如果你在网上搜索“多态”这个词，你会发现它是“以几种不同形式出现的状态”。“变形”是“通过自然或超自然的方式，将一个事物或人的形式或性质改变为一种完全不同的形式或性质”。所以，**Java 多态**是一个对象在不同的条件下表现出完全不同的行为的能力，就像经历了一次蜕变。

我们将使用**对象工厂**——工厂的具体编程实现，这是一种返回不同原型或类的对象的方法（参见[《面向对象程序设计》](https://en.wikipedia.org/wiki/Factory_(object-oriented_programming))以实际动手的方式提出这个概念。*

# 对象工厂

对象工厂背后的思想是创建一个方法，在特定条件下返回特定类型的新对象。例如，查看`CalcUsingAlg1`和`CalcUsingAlg2`类：

```java
interface CalcSomething{ double calculate(); }
class CalcUsingAlg1 implements CalcSomething{
    public double calculate(){ return 42.1; }
}
class CalcUsingAlg2 implements CalcSomething{
    private int prop1;
    private double prop2;
    public CalcUsingAlg2(int prop1, double prop2) {
        this.prop1 = prop1;
        this.prop2 = prop2;
    }
    public double calculate(){ return prop1 * prop2; }
}
```

如您所见，它们都实现相同的接口`CalcSomething`，但使用不同的算法。现在，假设我们决定在属性文件中选择所使用的算法。然后我们可以创建以下对象工厂：

```java
class CalcFactory{
    public static CalcSomething getCalculator(){
        String alg = getAlgValueFromPropertyFile();
        switch(alg){
            case "1":
                return new CalcUsingAlg1();
            case "2":
                int p1 = getAlg2Prop1FromPropertyFile();
                double p2 = getAlg2Prop2FromPropertyFile();
                return new CalcUsingAlg2(p1, p2);
            default:
                System.out.println("Unknown value " + alg);
                return new CalcUsingAlg1();
        }
    }
}
```

工厂根据`getAlgValueFromPropertyFile()`方法返回的值选择要使用的算法，对于第二种算法，工厂还使用`getAlg2Prop1FromPropertyFile()`方法和`getAlg2Prop2FromPropertyFile()`方法获取算法的输入参数。但这种复杂性对客户来说是隐藏的：

```java
CalcSomething calc = CalcFactory.getCalculator();
double result = calc.calculate();

```

我们可以添加新的算法变体，改变源代码中的算法参数或算法选择的过程，但是客户端不需要改变代码。这就是多态的力量。

或者，我们可以使用继承来实现多态行为。考虑以下类别：

```java
class CalcSomething{
    public double calculate(){ return 42.1; }
}
class CalcUsingAlg2 extends CalcSomething{
    private int prop1;
    private double prop2;
    public CalcUsingAlg2(int prop1, double prop2) {
        this.prop1 = prop1;
        this.prop2 = prop2;
    }
    public double calculate(){ return prop1 * prop2; }
}
```

那么我们的工厂可能会如下所示：

```java
class CalcFactory{
    public static CalcSomething getCalculator(){
        String alg = getAlgValueFromPropertyFile();
        switch(alg){
            case "1":
                return new CalcSomething();
            case "2":
                int p1 = getAlg2Prop1FromPropertyFile();
                double p2 = getAlg2Prop2FromPropertyFile();
                return new CalcUsingAlg2(p1, p2);
            default:
                System.out.println("Unknown value " + alg);
                return new CalcSomething();
        }
    }
}
```

但客户端代码不变：

```java
CalcSomething calc = CalcFactory.getCalculator();
double result = calc.calculate();
```

如果有选择的话，有经验的程序员会使用一个公共接口来实现。它允许更灵活的设计，因为 Java 中的类可以实现多个接口，但可以扩展（继承）一个类。

# 实例运算符

不幸的是，生活并不总是那么简单，有时，程序员不得不处理一个由不相关的类（甚至来自不同的框架）组装而成的代码，在这种情况下，使用多态可能不是一个选择。尽管如此，您仍然可以隐藏算法选择的复杂性，甚至可以使用`instanceof`操作符模拟多态行为，当对象是某个类的实例时，该操作符返回`true`。

假设我们有两个不相关的类：

```java
class CalcUsingAlg1 {
    public double calculate(CalcInput1 input){
        return 42\. * input.getProp1();
    }
}

class CalcUsingAlg2{
    public double calculate(CalcInput2 input){
        return input.getProp2() * input.getProp1();
    }
}
```

每个类都需要一个特定类型的对象作为输入：

```java
class CalcInput1{
    private int prop1;
    public CalcInput1(int prop1) { this.prop1 = prop1; }
    public int getProp1() { return prop1; }
}

class CalcInput2{
    private int prop1;
    private double prop2;
    public CalcInput2(int prop1, double prop2) {
        this.prop1 = prop1;
        this.prop2 = prop2;
    }
    public int getProp1() { return prop1; }
    public double getProp2() { return prop2; }
}
```

假设我们实现的方法接收到这样一个对象：

```java
void calculate(Object input) {
    double result = Calculator.calculate(input);
    //other code follows
}
```

我们在这里仍然使用多态，因为我们将输入描述为`Object`类型，我们可以这样做，因为`Object`类是所有 Java 类的基类。

现在让我们看看`Calculator`类是如何实现的：

```java
class Calculator{
    public static double calculate(Object input){
        if(input instanceof CalcInput1){
            return new CalcUsingAlg1().calculate((CalcInput1)input);
        } else if (input instanceof CalcInput2){
            return new CalcUsingAlg2().calculate((CalcInput2)input);
        } else {
            throw new RuntimeException("Unknown input type " + 
                               input.getClass().getCanonicalName());
        }
    }
}
```

如您所见，它使用`instanceof`操作符来选择适当的算法。通过使用`Object`类作为输入类型，`Calculator`类也利用了多态，但它的大多数实现与之无关。然而，从外面看，它看起来是多态的，确实如此，但只是在一定程度上。

# 总结

本章向读者介绍了 OOP 的概念以及它们是如何在 Java 中实现的。它提供了每个概念的解释，并演示了如何在特定的代码示例中使用它。详细讨论了`class`和`interface`的 Java 语言结构。读者还了解了什么是重载、覆盖和隐藏，以及如何使用`final`关键字保护方法不被覆盖

从“多态的作用”部分，读者了解了多态强大的 Java 特性。本节将所有呈现的材料放在一起，并展示了多态如何保持在 OOP 的中心。

在下一章中，读者将熟悉 Java 语言语法，包括包、导入、访问修饰符、保留关键字和限制关键字，以及 Java 引用类型的一些方面。读者还将学习如何使用`this`和`super`关键字，原始类型的加宽和缩小转换是什么，装箱和拆箱，原始类型和引用类型的赋值，以及引用类型的`equals()`方法是如何工作的。

# 测验

1.  从以下列表中选择所有正确的 OOP 概念：

2.  从以下列表中选择所有正确的语句：

3.  从以下列表中选择所有正确的语句：

4.  从以下列表中选择所有正确的语句：

5.  从以下列表中选择所有正确的语句：

6.  从以下列表中选择所有正确的语句：

7.  从以下列表中选择所有正确的语句：

8.  从以下列表中选择所有正确的语句：

9.  从以下列表中选择所有正确的语句：

10.  从以下列表中选择所有正确的语句：

11.  从以下列表中选择所有正确的语句：

12.  从以下列表中选择所有正确的语句：

13.  从以下列表中选择所有正确的语句：

14.  从以下列表中选择所有正确的语句：

15.  从以下列表中选择所有正确的语句：

16.  从以下列表中选择所有正确的语句：

17.  从以下列表中选择所有正确的语句：

18.  从以下列表中选择所有正确的语句：

19.  从以下列表中选择所有正确的语句：

20.  从以下列表中选择所有正确的语句：

21.  从以下列表中选择所有正确的语句：