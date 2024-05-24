# Java 编程入门（一）

> 原文：[`zh.annas-archive.org/md5/C2294D9F4E8891D4151421288379909B`](https://zh.annas-archive.org/md5/C2294D9F4E8891D4151421288379909B)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

本书的目的是让读者对 Java 基础知识有扎实的理解，通过一系列从基础到实际编程的实践步骤来引导他们。讨论和示例旨在激发专业直觉，使用经过验证的编程原则和实践。

完成本书后，您将能够做到以下事情：

+   安装 Java 虚拟机并运行它

+   安装和配置集成开发环境（编辑器）

+   编写、编译和执行 Java 程序和测试

+   理解并使用 Java 语言基础知识

+   理解并应用面向对象设计原则

+   掌握最常用的 Java 构造

# 本书适合对象

目标受众是那些想要在现代 Java 编程中追求职业的人，以及想要刷新他们对最新 Java 版本知识的初学者和中级 Java 程序员。

# 本书涵盖内容

第一章，*计算机上的 Java 虚拟机（JVM）*，介绍了 Java 作为一种语言和工具。它描述了 Java 创建的动机、历史、版本、架构原则和组件。还概述了 Java 的营销定位和主要应用领域。然后，一系列实际步骤将引导您完成 Java 虚拟机在计算机上的安装和配置，以及其使用和主要命令。

第二章，*Java 语言基础*，介绍了 Java 作为面向对象编程（OOP）语言的基本概念。您将学习类、接口、对象及其关系，以及 OOP 的概念和特性。

第三章，*您的开发环境设置*，解释了开发环境是什么，并指导您进行配置和调整。它还概述了流行的编辑器和构建框架。逐步说明帮助读者创建自己的开发环境，并进行配置，包括设置类路径并在实践中使用它。

第四章，*你的第一个 Java 项目*，利用到目前为止学到的一切，引导读者编写程序和开发者测试并运行它们的过程。

第五章，*Java 语言元素和类型*，使读者熟悉 Java 语言元素：标识符、变量、文字、关键字、分隔符、注释等。它还描述了基本类型和引用类型。特别关注了 String 类、枚举类型和数组。

第六章，*接口、类和对象构造*，解释了 Java 编程的最重要方面——应用程序编程接口（API）、对象工厂、方法重写、隐藏和重载。还介绍了关键字 this 和 super 的用法。该章节以讨论最终类和方法结束。

第七章，*包和可访问性（可见性）*，介绍了包的概念，并教读者如何创建和使用它以提高代码清晰度。它还描述了类和类成员（方法和属性）的不同可访问性（可见性）级别。最后讨论了封装的关键面向对象设计概念。

第八章，*面向对象设计（OOD）原则*，提供了 Java 编程的更高层次视图。它讨论了良好设计的标准，并提供了经过验证的 OOD 原则指南。它还演示了说明所讨论原则的代码示例。

第九章，*运算符、表达式和语句*，帮助您深入了解 Java 编程的三个核心元素：运算符、表达式和语句。您将看到所有 Java 运算符的列表，了解最受欢迎的运算符的详细信息，并能够执行说明每个运算符的关键方面的具体示例。

第十章，*控制流语句*，描述了允许根据实现的算法逻辑构建程序流的 Java 语句，包括条件语句、迭代语句、分支语句和异常。

第十一章，*JVM 进程和垃圾回收*，让读者深入了解 JVM，看到它不仅仅是一个程序运行器。除了应用程序线程外，它还执行多个服务线程。其中一个服务线程执行一个重要任务，释放未使用对象的内存。

第十二章，*Java 标准和外部库*，概述了包含在 JDK 中的最受欢迎的库和外部库。简要示例演示了库的功能。该章还指导用户如何在互联网上找到库。

第十三章，*Java 集合*，向您介绍了 Java 集合，并提供了演示它们用法的代码示例。

第十四章，*管理集合和数组*，向您介绍了允许您创建、初始化和修改集合和数组的类。它们还允许创建不可修改和不可变的集合。其中一些类属于 Java 标准库，另一些属于流行的 Apache Commons 库。

第十五章，*管理对象、字符串、时间和随机数*，演示了 Java 标准库和 Apache Commons 中的类和实用程序，每个程序员都必须掌握，以成为有效的编码人员。

第十六章，*数据库编程*，解释了如何编写能够操作数据库中数据的 Java 代码——插入、读取、更新和删除。它还提供了 SQL 语言和基本数据库操作的简要介绍。

第十七章，*Lambda 表达式和函数式编程*，解释了函数式编程的概念。它概述了 JDK 提供的函数式接口，并解释了如何在 lambda 表达式中使用它们。

第十八章，*流和管道*，向读者介绍了数据流处理的强大概念。它解释了流是什么，如何使用 lambda 表达式处理它们，以及如何构建处理管道。它还展示了如何轻松地并行组织流处理。

第十九章，*响应式系统*，概述了您未来职业工作的前景。随着更多数据被处理和服务变得更加复杂，对更具适应性、高度可扩展和分布式流程的需求呈指数级增长，这正是我们将在本章中解决的问题——这样的软件系统在实践中是什么样子。

# 充分利用本书

读者不需要对 Java 编程有先验知识，尽管对编程的理解会帮助他们从本书中获得最多的知识。

# 下载示例代码文件

您可以从[www.packtpub.com](http://www.packtpub.com)的帐户中下载本书的示例代码文件。如果您在其他地方购买了本书，您可以访问[www.packtpub.com/support](http://www.packtpub.com/support)并注册，以便直接通过电子邮件接收文件。

您可以按照以下步骤下载代码文件：

1.  在[www.packtpub.com](http://www.packtpub.com/support)登录或注册。

1.  选择“支持”选项卡。

1.  Click on Code Downloads & Errata.

1.  在搜索框中输入书名，然后按照屏幕上的说明进行操作。

文件下载后，请确保使用以下最新版本解压或提取文件夹：

+   WinRAR/7-Zip for Windows

+   Zipeg/iZip/UnRarX for Mac

+   7-Zip/PeaZip for Linux

本书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/Introduction-to-Programming`](https://github.com/PacktPublishing/Introduction-to-Programming)。我们还有其他代码包，来自我们丰富的图书和视频目录，可在**[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)**上获得。请查看！

# 下载彩色图片

我们还提供了一个 PDF 文件，其中包含本书中使用的屏幕截图/图表的彩色图片。您可以在此处下载：[`www.packtpub.com/sites/default/files/downloads/IntroductiontoProgramming_ColorImages.pdf`](http://www.packtpub.com/sites/default/files/downloads/IntroductiontoProgramming_ColorImages.pdf)。

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码单词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄。例如："将下载的`WebStorm-10*.dmg`磁盘映像文件挂载为系统中的另一个磁盘"。

代码块设置如下：

```java
html, body, #map {
 height: 100%; 
 margin: 0;
 padding: 0
}
```

当我们希望引起您对代码块的特别关注时，相关行或项目将以粗体显示：

```java
[default]
exten => s,1,Dial(Zap/1|30)
exten => s,2,Voicemail(u100)
exten => s,102,Voicemail(b100)
exten => i,1,Voicemail(s0)
```

任何命令行输入或输出都将按照以下格式编写：

```java
$ mkdir css
$ cd css
```

**粗体**：表示新术语、重要单词或屏幕上看到的单词。例如，菜单或对话框中的单词会以这种方式出现在文本中。例如："从管理面板中选择系统信息"。

警告或重要提示会显示为这样。

提示和技巧会显示为这样。

# Get in touch

我们始终欢迎读者的反馈。

**一般反馈**：请通过电子邮件`feedback@packtpub.com`，并在主题中提及书名。如果您对本书的任何方面有疑问，请通过电子邮件`questions@packtpub.com`与我们联系。

**勘误**：尽管我们已经尽一切努力确保内容的准确性，但错误确实会发生。如果您在本书中发现错误，我们将不胜感激，如果您能向我们报告。请访问[www.packtpub.com/submit-errata](http://www.packtpub.com/submit-errata)，选择您的书，点击勘误提交表单链接，并输入详细信息。

**盗版**：如果您在互联网上发现我们作品的任何非法副本，我们将不胜感激，如果您能向我们提供位置地址或网站名称。请通过`copyright@packtpub.com`与我们联系，并提供材料链接。

**如果您有兴趣成为作者**：如果您对某个专题有专业知识，并且有兴趣撰写或为书籍做出贡献，请访问[authors.packtpub.com](http://authors.packtpub.com/)。

# 评论

请留下评论。阅读并使用本书后，为什么不在购买书籍的网站上留下评论呢？潜在的读者可以看到并使用您的客观意见来做出购买决策，我们在 Packt 可以了解您对我们产品的看法，我们的作者可以看到您对他们书籍的反馈。谢谢！

有关 Packt 的更多信息，请访问[packtpub.com](https://www.packtpub.com/)。


# 第一章：在您的计算机上安装 Java 虚拟机（JVM）

本书将指导您达到中级 Java 编程技能。编程不仅仅是了解语言语法。它还涉及编写、编译和执行程序或运行整个软件系统所需的工具和信息来源。这条路上的第一步是学习 Java 的重要组件，包括**Java 开发工具包**（**JDK**）和**Java 虚拟机**（**JVM**）。

本章将介绍 Java 作为一种语言和工具，并建立最重要的术语。它还将描述 Java 创建背后的动机，涵盖其历史、版本、版本和技术，并概述 Java 的营销位置和主要应用领域。然后，一系列实际步骤将引导读者完成在其计算机上安装和配置 Java，并介绍主要的 Java 命令。

在本章中，我们将涵盖以下主题：

+   什么是 Java？

+   Java 平台、版本、版本和技术

+   Java SE 开发工具包（JDK）的安装和配置

+   主要的 Java 命令

+   练习- JDK 工具和实用程序

# 什么是 Java？

由于本书是为初学者编写的，我们将假设你对 Java 几乎一无所知。但即使你知道一些，甚至很多，回顾基础知识也总是有帮助的，即使只是让你通过欣赏自己已经掌握了多少而感到自豪。因此，我们将从定义 Java、JVM、编译、字节码等术语开始。

# 基本术语

在谈论 Java 时，人们将 Java、JVM、JDK、SDK 和 Java 平台视为同义词。法律定义将 Java 视为*Sun 公司一套技术的商标*，但我们通常不会将 Java 视为商标。最常见的情况是，当有人说 Java 时，他们指的是一种由人类用来表达一系列指令（程序）的编程语言，这些指令可以由计算机执行（不是直接执行，而是在程序被编译/转换为计算机理解的代码之后）。人类可读的 Java 程序称为**源代码**，经过所有转换后的计算机可读程序称为**二进制代码**，因为它只使用 1 和 0 来表示。

您可以在[`docs.oracle.com/javase/specs/`](https://docs.oracle.com/javase/specs/)找到完整的**Java 语言规范**（描述）。它比人们预期的要容易得多，即使对于新手来说，它也可能会有所帮助，特别是如果将其用作参考文档。不要因为前几节的正式语言而感到泄气。尽量阅读你能理解的部分，并在理解 Java 的过程中回来，以及对更深入和更精确的定义的动力增加时再来阅读。

JVM 是一个程序，它将 Java`.class`文件的字节码翻译成二进制机器码，并将其发送到微处理器执行。

你有没有注意到有两个类似的术语，*bytecode*和*byte code*？在对话中，这两者的区别几乎是不可察觉的，所以人们可以互换使用它们。但是它们是有区别的。*Byte code*（或*Byte Code*，更准确地说）是一种可以由名为 JVM 的特殊程序执行的语言。相比之下，*bytecode*是由 Java 编译器（另一个程序）生成的指令的格式（每个指令占用一个字节，因此得名），该编译器读取人类可读的源代码并将其转换为 Byte Code。

Bytecode 是以 JVM 理解的格式表达的二进制代码。然后，JVM 读取（加载，使用名为**类加载器**的程序）字节码，将指令转换为二进制代码（JVM 正在运行的特定计算机微处理器理解的格式中的指令），并将结果传递给 CPU，即执行它的微处理器。

类是由 Java 编译器生成的文件（扩展名为.class），从具有相同名称和扩展名为.java 的源代码文件中生成。有十多种 JVM 实现，由不同公司创建，但我们将重点关注 Oracle JVM 的实现，称为 HotSpot。在第十一章，JVM 进程和垃圾收集中，我们将更仔细地查看 JVM 的功能、架构和进程。

在 Java 语言规范（https://docs.oracle.com/javase/specs）的同一页上，您可以找到 Java 虚拟机规范。我们建议您将其用作术语和理解 JVM 功能的参考来源。

JDK 是一组软件工具和支持库，允许创建和执行 Java 语言程序。

自 Java 9 以来，不再支持小程序（可以在浏览器中执行的组件），因此我们将不再详细讨论它们。应用程序是可以（编译后）在安装了 JVM 的计算机上执行的 Java 程序。因此，JDK 至少包括编译器、JVM 和 Java 类库（JCL）-一组可供应用程序调用的即用程序。但实际上，它还有许多其他工具和实用程序，可以帮助您编译、执行和监视 Java 应用程序。包含 JVM、JCL、类加载器和支持文件的 JDK 子集允许执行（运行）字节码。这样的组合称为 Java 运行时环境（JRE）。每个 Java 应用程序都在单独的 JVM 实例（副本）中执行，该实例具有自己分配的计算机内存，因此两个 Java 应用程序不能直接交流，而只能通过网络（Web 服务和类似手段）进行交流。

软件开发工具包（SDK）是一组软件工具和支持库，允许使用特定编程语言创建应用程序。Java 的 SDK 称为 JDK。

因此，当人们在提到 JDK 时使用 SDK 时，他们是正确的，但不够精确。

Java 平台由编译器、JVM、支持库和其他工具组成。

在前述定义中的支持库是 Java 标准库，也称为 JCL，并且对于执行字节码是必需的。如果程序需要一些其他库（不包括在 JCL 中），则它们必须在编译时添加（参见第三章，您的开发环境设置，描述了如何执行此操作），并包含在生成的字节码中。Java 平台可以是以下四种之一：Java 平台标准版（Java SE）、Java 平台企业版（Java EE）、Java 平台微型版（Java ME）或 Java Card。以前还有 JavaFX 平台，但自 Java 8 以来已合并到 Java SE 中。我们将在下一节讨论差异。

Open JDK 是 Java SE 的免费开源实现。

这些是最基本的术语。其他术语将根据需要在本书的相应上下文中介绍。

# 历史和流行度

Java 于 1995 年首次由 Sun Microsystems 发布。它源自 C 和 C++，但不允许用户在非常低的层次上操纵计算机内存，这是许多困难的根源，包括内存泄漏相关的问题，如果 C 和 C++程序员对此不太小心的话，他们会遇到。Java 因其简单性、可移植性、互操作性和安全性而脱颖而出，这使其成为最受欢迎的编程语言之一。据估计，截至 2017 年，全球有近 2000 万程序员（其中近 400 万在美国），其中大约一半使用 Java。有充分的理由相信，未来对软件开发人员的需求，包括 Java 开发人员，只会增长。因此，学习 Java 看起来是迈向稳定职业的一步。而学习 Java 实际上并不是非常困难。我们将向您展示如何做到这一点；只需继续阅读、思考，并在计算机上实践所有建议。

Java 被构想为一种允许用户*一次编写，到处运行*的工具-这是另一个解释和理解的术语。这意味着编译后的 Java 代码可以在支持 Java 的所有计算机上运行，而无需重新编译。正如您已经了解的那样，*支持 Java*意味着对于每个操作系统，都存在一个可以将字节码转换为二进制代码的解释器。这就是*到处运行*的实现方式：只要有 Java 解释器可用的地方。

在概念被证明受欢迎并且 Java 牢固地确立为其他面向对象语言中的主要参与者之一后，Sun Microsystems 将其大部分 JVM 作为自由和开源软件，并受 GNU**通用公共许可证**（**GPL**）管理。2007 年，Sun Microsystems 将其所有 JVM 的核心代码都以自由和开源的分发条款提供，除了一小部分 Sun 没有版权的代码。2010 年，甲骨文收购了 Sun Microsystems，并宣布自己是*Java 技术的管理者，致力于培育参与和透明度的社区*。

如今，Java 在许多领域中被广泛使用，最突出的是在 Android 编程和其他移动应用程序中，在各种嵌入式系统（各种芯片和专用计算机）、桌面**图形用户界面**（**GUI**）开发以及各种网络应用程序，包括网络应用程序和网络服务。Java 也广泛用于科学应用程序，包括快速扩展的机器学习和人工智能领域。

# 原则

根据*Java 编程语言的设计目标*（[`www.oracle.com/technetwork/java/intro-141325.html`](http://www.oracle.com/technetwork/java/intro-141325.html)），在创建 Java 语言时有五个主要目标。Java 语言必须是：

+   **面向对象和熟悉**：这意味着它必须看起来像 C++，但没有不必要的复杂性（我们将在第二章中讨论面向对象的术语，*Java 语言基础*）

+   **架构中立和可移植**：这意味着能够使用 JVM 作为将语言（源代码）与每个特定操作系统的知识（通常称为平台）隔离的环境

+   **高性能**：它应该与当时领先的编程语言一样工作

+   **解释性**：它可以在不链接的情况下移至执行阶段（从多个`.class`文件创建单个可执行文件），从而允许更快的编写-编译-执行循环（尽管现代 JVM 经过优化，以保持经常使用的`.class`文件的二进制版本，以避免重复解释）

+   **多线程**：它应该允许多个并发执行作业（线程），例如同时下载图像和处理其他用户命令和数据

+   动态：链接应该在执行期间发生

+   安全：它必须在运行时受到良好的保护，以防未经授权的修改

结果证明这些目标是明确定义的和富有成效的，因为 Java 成为了互联网时代的主要语言。

# Java 平台、版本、版本和技术

在日常讨论中，一些程序员会交替使用这些术语，但是 Java 平台、版本、版本和技术之间是有区别的。本节将重点解释这一点。

# 平台和版本

我们几乎每天都会听到“平台”这个术语。它的含义取决于上下文，但在最一般的意义上，它指的是一个允许某人做某事的设备或环境。它作为一个基础、一个环境、一个平台。在信息技术领域，平台提供了一个操作环境，软件程序可以在其中开发和执行。操作系统是平台的典型例子。Java 有自己的操作环境，正如我们在前面的部分中提到的，它有四个平台（和六个版本）：

+   Java 平台标准版（Java SE）：当人们说 Java 时，他们指的是这个版本。它包括 JVM、JCL 和其他工具和实用程序，允许在桌面和服务器上开发和部署 Java 应用程序。在本书中，我们将在这个版本的范围内进行讨论，并且只在本节中提到其他版本。

+   Java 平台企业版（Java EE）：由 Java SE、服务器（提供应用程序服务的计算机程序）、增强库、代码示例、教程和其他文档组成，用于开发和部署大规模、多层次和安全的网络应用程序。

+   Java 平台微型版（Java ME）：这是 Java SE 的一个小型（使用少量资源）子集，具有一些专门的类库，用于开发和部署嵌入式和移动设备的 Java 应用程序，比如手机、个人数字助理、电视机顶盒、打印机、传感器等。还有一个针对 Android 编程的 Java ME 变体（具有自己的 JVM 实现），由 Google 开发。它被称为 Android SDK。

+   Java Card：这是 Java 平台中最小的一个，用于开发和部署 Java 应用程序到小型嵌入式设备，比如智能卡。它有两个版本（引用自官方 Oracle 文档，网址为[`www.oracle.com/technetwork/java/embedded/javacard/documentation/javacard-faq-1970428.html#3`](http://www.oracle.com/technetwork/java/embedded/javacard/documentation/javacard-faq-1970428.html#3)）：

+   Java Card Classic Edition，它针对的是当今所有垂直市场上部署的智能卡，基于 ISO7816 和 ISO14443 通信。

+   Java Card Connected Edition，这是为了支持一个 Web 应用程序模型而开发的，其中 servlet 在卡上运行，TCP/IP 作为基本协议，并且在高端安全微控制器上运行，通常基于 32 位处理器，并支持像 USB 这样的高速通信接口。

# 版本

自 1996 年首次发布以来，Java 已经发展了九个主要版本：

+   JDK 1.0（1996 年 1 月 23 日）

+   JDK 1.1（1997 年 2 月 19 日）

+   J2SE 1.2（1998 年 12 月 8 日）

+   J2SE 1.3（2000 年 5 月 8 日）

+   J2SE 1.4（2002 年 2 月 6 日）

+   J2SE 5.0（2004 年 9 月 30 日）

+   Java SE 6（2006 年 12 月 11 日）

+   Java SE 7（2011 年 7 月 28 日）

+   Java SE 8（2014 年 3 月 18 日）

+   Java SE 9（2017 年 9 月 21 日）

+   Java SE 10（2018 年 3 月 20 日）

关于更改 Java 版本方案有几个建议。自 Java 10 以来，JDK 引入了新的基于时间的版本`$YEAR.$MONTH`。此外，计划每年 3 月和 9 月发布一个新的 Java 版本。因此，Java 11 将于 2018 年 9 月发布，JVM 版本为 18.9。我们将很快向您展示如何显示您正在使用的 JDK 版本。

# 技术

技术这个词被滥用了。程序员几乎用它来表示任何东西。如果您查看甲骨文的 Java 技术列表（[`www.oracle.com/java/technologies/index.html`](https://www.oracle.com/java/technologies/index.html)），您将找到以下列表：

+   **嵌入式**，包括以前列出的除了 Java EE 之外的所有 Java 平台，通常经过一些修改，通常具有更小的占用空间和其他优化

+   **Java SE**，包括 Java SE 和 Java SE Advanced，其中包括 Java SE 和一些用于企业级（不仅仅是开发计算机）安装的监控和管理工具

+   **Java EE**，如前所述

+   **云**，包括基于云的可靠、可扩展和弹性的服务

但在 Oracle 词汇表（[`www.oracle.com/technetwork/java/glossary-135216.html`](http://www.oracle.com/technetwork/java/glossary-135216.html)）中，以下技术被添加到列表中：

+   **JavaSpaces**：提供分布式持久性的技术

+   **Jini 技术**：一种**应用程序编程接口**（**API**），可以自动连接设备和服务

在其他地方，在 Oracle Java 10 文档的首页（[`docs.oracle.com/javase/10`](https://docs.oracle.com/javase/10)），客户端技术列如下：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/0f75d553-ab94-43fe-97be-59330e69902a.png)

与此同时，在 Oracle Java 教程（[`docs.oracle.com/javase/tutorial/getStarted/intro/cando.html`](https://docs.oracle.com/javase/tutorial/getStarted/intro/cando.html)）中，**Java Web Start**和**Java Plug-In**被提及为部署技术，<q>用于将您的应用程序部署到最终用户。</q>

然而，甲骨文提供的最大的 Java 技术列表在专门用于技术网络的页面上（[`www.oracle.com/technetwork/java/index.html`](http://www.oracle.com/technetwork/java/index.html)）。除了 Java SE、Java SE Advanced 和 Suite、Java 嵌入式、Java EE、Java FX 和 Java Card 之外，还列出了**Java TV**、**Java DB**和**开发工具**。如果您转到 Java SE 或 Java EE 页面，在“技术”选项卡下，您会发现超过两打的 API，以及各种软件组件也列为技术。因此，人们不应该感到惊讶在任何地方找到任何种类的 Java 技术列表。

似乎与 Java 有关的任何东西都至少被称为技术一次。为了避免进一步的混淆，从现在开始，在本书中，我们将尽量避免使用技术这个词。

# Java SE 开发工具包（JDK）安装和配置

从现在开始，每当我们谈论 Java 时，我们指的是 Java SE 10 版。我们将把它称为 Java 10，或 Java，或 JDK，除非另有说明。

# 从哪里开始

在您的计算机上进行任何 Java 开发之前，您需要安装和配置 JDK。为了做到这一点，搜索互联网以获取 JDK 下载，并选择任何以[`www.oracle.com/`](https://www.oracle.com/)开头的链接。截至目前，最好的链接应该是[`www.oracle.com/technetwork/java/javase/downloads/index.html`](http://www.oracle.com/technetwork/java/javase/downloads/index.html)。

如果您按照上述链接，您将看到这个部分：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/9b51d6bc-b626-4ca3-a965-d102a78ee09d.png)

让我们称这个页面为*Page1*，以供以后参考。现在，您可以点击 JDK 下的下载链接。其他两个下载链接提供了 JRE，正如您已经知道的，它只允许您运行已经编译的 Java 程序；我们需要编写一个程序，将其编译成字节码，然后运行它。

# 带有 Java 安装程序的页面

点击后，您将看到一个页面（*Page2*）有这个部分：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/b9d20525-9bb2-4d9a-a75d-dab18a26a376.png)

这些是不同**操作系统**（**OS**）的 Java 安装程序。您需要选择适合您操作系统的程序，并单击相应的链接（不要忘记使用单选按钮点击接受许可协议；如果有疑问，通过链接 Oracle Binary Code License Agreement for Java SE 阅读许可协议）。对于 Linux，有两个安装程序 - 一个是 Red Hat Package Manager 格式（`.rpm`），另一个只是一个存档（`.tar`）和压缩（`.gz`）版本。还要注意，在此列表中，只有 64 位操作系统的安装程序。截至目前，尚不清楚 32 位版本是否会被正式弃用，尽管它作为早期访问版本可用。

选择您需要的安装程序，并下载它。

# 如何安装

现在是安装 Java 的时候，基本上包括以下四个步骤：

1.  扩展安装程序

1.  创建目录

1.  将文件复制到这些目录中

1.  使 Java 可执行文件无需输入完整路径

要找到详细的安装说明，返回*Page1*并点击安装说明链接。找到适用于您操作系统的链接，并按照提供的步骤进行操作，但只选择与 JDK 相关的步骤。

最终，您将能够运行`java -version`命令，它将显示以下内容：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/0e2ef525-125a-441b-8eac-2eef6fc60824.png)

如您所见，它显示 Java 的版本为 10.0.1，JRE 和 JVM 的版本为 18.3（构建 10.0.1）。目前还不清楚未来的 Java、JRE 和 JVM 版本是否会遵循相同的格式。

无论如何，如果`java -version`命令显示您尝试安装的版本，这意味着您已经正确安装了 Java，现在可以享受与之一起工作。从现在开始，每当有新版本发布时，您都会收到升级提示，您只需点击提供的链接即可进行升级。或者，您可以转到安装程序页面（*Page2*），下载相应的安装程序，启动它，并重复您已经熟悉的过程。

实际上，程序员并不会每次都升级他们的 Java 安装。他们会保持开发版本与生产环境中的 Java 版本相同（以避免潜在的不兼容性）。如果他们想在升级生产环境之前尝试新版本，他们可能会在计算机上安装两个版本的 Java，并行使用。在第三章中，*您的开发环境设置*，您将学习如何做到这一点，以及如何在它们之间切换。

# 主要的 Java 命令

在前一节中，您看到了一个 Java 命令的示例，显示了 JVM 版本。顺便说一句，命令`java`启动了 JVM，并用于运行编译后的 Java 程序的字节码（我们将在第四章中详细演示如何做到这一点，*您的第一个 Java 项目*）。

# JVM 执行命令

现在，如果您只运行`java`，输出将显示帮助的简短版本。由于它相当长，我们将分几部分显示。这是第一部分：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/87e0ce48-eb94-46dc-8449-d9cb351d6ac3.png)

它显示了三种运行 JVM 的方式：

+   执行一个类，一个包含字节码的`.class`文件

+   要执行一个 jar 文件，一个带有扩展名`.jar`的文件，其中包含以 ZIP 格式的`.class`文件（甚至可能是整个应用程序），还包括一个特定于 Java 的清单文件

+   执行模块中的主类（一组`.class`文件和其他资源，比`.jar`文件更好地结构化），通常是应用程序或其一部分

如你所见，在上述每个命令中，都必须显式提供一个主类。它是必须首先执行的`.class`文件。它充当应用程序的主入口，并启动加载其他类（在需要时）以运行应用程序的链。这样的命令示例是：

```java
java MyGreatApplication
```

实际上，这意味着当前目录中有一个名为`MyGreatApplication.class`的文件，但我们不应指定文件扩展名。否则，JVM 将寻找文件`MyGreatApplication.class.class`，当然找不到，也无法运行任何内容。

在本书中，我们不会显式使用这些命令中的任何一个，并且将其留给编辑器在幕后运行，因为现代编辑器不仅帮助编写和修改源代码；它还可以编译和执行编写的代码。这就是为什么它不仅被称为编辑器，而是**集成开发环境**（**IDE**）。

尽管如此，我们将继续概述所有`java`命令选项，这样你就会知道在你的 IDE 背后发生了什么。要享受驾车乐趣，不需要了解引擎的内部工作细节，但了解其运作原理是有帮助的。此外，随着你的专业水平的提高和你所工作的应用程序的增长，你将需要调整 JVM 配置，因此这是第一次在幕后偷看。

以下是`java`命令输出的下一部分：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/b6f9936b-a8d5-4edc-8a84-7a918271ae38.png)

在前面的屏幕截图中，你可以看到两个已弃用的选项，后面是与类路径和模块路径相关的选项。最后两个选项非常重要。它们允许指定应用程序所在位置的类和应用程序使用的库的位置。后者可以是你编写的类或第三方库。

模块的概念超出了本书的范围，但模块路径的使用方式与类路径非常相似。类路径选项告诉 JVM 在哪里查找类，而模块路径告诉 JVM 模块的位置。可以在同一命令行中同时使用两者。

例如，假设你有一个名为`MyGreatApplication.class`的文件（其中包含你的程序的字节码`MyGreatApplication.java`），存储在`dir2`目录中，这是`dir1`目录的子目录，你的终端窗口当前显示的是`dir1`目录的内容：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/b9813eaf-2def-48f2-9e64-c8dbce1e73e1.png)

如你所见，还有另一个目录`dir3`，我们创建它来存储另一个文件`SomeOtherProgram.class`，这是你的应用程序使用的。我们还在`dir4`中放入了其他支持的`.class`文件库，这些文件被收集在`SomeLibrary.jar`中。然后运行你的应用程序的命令行如下：

```java
java -cp dir2:dir3:dir4/SomeLibrary.jar  MyGreatApplication //on Unix
java -cp dir2;dir3;dir4\SomeLibrary.jar  MyGreatApplication //on Windows
```

或者，我们可以将`SomeOtherProgram.class`和`MyGreatApplication.class`放入`some.jar`或`some.zip`文件，并将其放在`dir5`中。然后，命令将采用以下形式之一：

```java
java -cp dir4/SomeLibrary.jar:dir5/some.zip MyGreatApplication //Unix
java -cp dir4/SomeLibrary.jar:dir5/some.jar MyGreatApplication //Unix
java -cp dir4\SomeLibrary.jar;dir5\some.zip MyGreatApplication //Windows
java -cp dir4\SomeLibrary.jar;dir5\some.jar MyGreatApplication //Windows
```

我们可以使用`-cp`选项，也可以使用`-classpath`或`--class-path`选项。它们只是三种不同的约定，以便习惯于其中一种的人可以直观地编写命令行。这些风格中没有一个比其他更好或更差，尽管我们每个人都有偏好和意见。如果没有使用任何 classpath 选项，JVM 只会在当前目录中查找类。一些类（标准库）总是位于 Java 安装的某些目录中，因此无需使用 classpath 选项列出它们。我们将在第三章中更详细地讨论设置 classpath。

`java`命令输出的下一部分列出了一些选项，允许在实际执行应用程序之前验证一切是否设置正确：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/2d68305f-2660-4ee9-83a2-67aa2bd588e4.png)

由于模块超出了本书的范围，我们将跳过这些内容，继续输出的下一部分：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/dfd31045-7e5c-4c9e-b7f8-c960ae35dc06.png)

`-D` 选项允许设置一个可供应用程序访问的带有值的参数。它经常用于向应用程序传递一些值或标志，应用程序可以用来改变其行为。如果需要传递更多信息，那么就使用`.properties`文件（带有许多标志和各种值），而属性文件的位置则通过`-D`选项传递。完全取决于程序员，`.properties`文件或通过`-D`选项传递的值应该是什么。但是与应用程序配置相关的最佳实践也取决于您使用的特定框架或库。您将随着时间学会它们，这些实践超出了初学者程序员课程。

`-verbose` 选项提供了更多信息（比我们在这些截图中看到的）和一些特定的数据，取决于标志`class`、`module`、`gc`或`jni`，其中**gc**代表**垃圾收集器**，将在第十一章中讨论。对于其他标志，您可以阅读官方的 Oracle 文档，但很可能您不会很快使用它们。

`-version` 选项显示已安装的 Java 版本。这在第一天就非常有用，因为它允许随时检查当前使用的 Java 版本。在前面的部分中，我们演示了如何做到这一点，以及它产生的输出。当发布新版本的 Java 时，许多程序员会与他们当前使用的版本并行安装它，并在它们之间切换，无论是为了学习新功能还是为了开始为新版本编写代码，同时保留为旧版本编写的旧代码。您将学会如何在同一台计算机上安装两个版本的 Java，并在第三章中，*您的开发环境设置*中学会如何在它们之间切换。

我们将跳过与模块相关的选项。

在前面的截图中的其余选项与帮助相关。选项`-?`、`-h`、`-help`和`--help`显示了我们在这些截图中展示的内容，而选项`-X`和`--help-extra`提供了额外的信息。您可以自己尝试所有这些选项。

帮助输出的最后一部分如下：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/c0b12db1-c3f7-45da-9dea-6608a94380c2.png)

我们将不讨论这些选项。只需注意如何使用上一行中解释的长选项（带有两个连字符）。

# 编译命令

如前所述，用 Java 编写的程序称为源代码，并存储在`.java`文件中。编译命令`javac`读取它，并创建相应的带有 Java 字节码的`.class`文件。

让我们运行`javac`命令，而不指定`.java`文件。它将显示帮助信息。让我们分部分地进行审查：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/e6ec3374-6a59-4980-a82b-b21297711b17.png)

帮助告诉我们，这个命令的格式如下：

```java
javac <options> <source files>
```

要编译一些文件，可以在选项后的命令行中列出它们（如果文件不在当前目录中，必须使用绝对或相对路径前置文件名）。 列出的文件在 Oracle Solaris 中用冒号（`:`）分隔，在 Windows 中用分号（`;`）分隔，可以是目录、`.jar`文件或`.zip`文件。 还可以列出文件中的所有源文件，并使用`@filename`选项提供此文件名（请参阅前面的屏幕截图）。 但不要试图记住所有这些。 您很少（如果有的话）会显式运行`java`或`javac`命令。 您可能会使用一个 IDE 为您执行（请参阅第三章，*您的开发环境设置*）。 这也是我们将跳过前面屏幕截图中列出的大多数选项并仅提到其中两个选项的原因：`--class-path`（或`-classpath`或`-cp`），它指定当前编译代码所需的`.class`文件的位置，和`-d`，它指示创建`.class`文件的位置。

以下是`javac`帮助的下一部分：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/a1407f79-99c0-4b2a-b893-f77b46ebf783.png)

我们将在此提到前面屏幕截图中的唯一选项是`--help`（或`-help`），它提供了我们现在正在浏览的相同帮助消息。

最后，`javac`帮助的最后一部分如下：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/b406bf77-f4fa-46d0-9655-02f290994bc9.png)

我们已经描述了选项`--source-path`（或`-sourcepath`）。 选项`-verbose`要求编译器提供更详细的报告，说明它正在做什么，而选项`--version`（或`-version`）显示 JDK 版本：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/dab1a888-24c1-4bcb-b3a1-9b098ae8b5bf.png)

# 命令 jcmd 和其他命令

还有十几个其他的 Java 命令（工具和实用程序），您可能只有在专业编程几年后才会开始使用，如果有的话。 它们都在 Oracle Java 在线文档中有描述。 只需搜索 Java 实用程序和工具。

其中，我们只找到一个从 Java 编程的第一天起就非常有用的命令`jcmd`。 如果运行它，它会显示计算机上正在运行的所有 Java 进程（JVM 实例）。 在此示例中，您可以看到三个 Java 进程，进程 ID 分别为 3408、3458 和 3454：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/67653ba6-e839-41af-bf2c-d41b31ad5ebe.png)

进程 3408 运行 Maven 服务器（您的 IDE 通常会启动它）。 进程 3458 是我们运行`jcmd`。 进程 3454 是一个编辑器（IDE）IntelliJ IDEA，正在运行小型演示应用程序`com.packt.javapath.App`。

这样，您可以随时检查您的计算机上是否有一个失控的 Java 进程。 如果您想要停止它，可以使用任务管理器，或者需要 PID 的`kill`命令。

当您想要监视您的 Java 应用程序时，也需要了解 PID。 我们将在第十一章，*JVM 进程和垃圾收集*中讨论这一点。

通过这一点，我们完成了对 Java 命令的概述。 正如我们已经提到的，您的 IDE 将在幕后使用所有这些命令，因此您可能永远不会使用它们，除非您进行生产支持（这是在您开始学习 Java 几年后）。 但我们认为您需要了解它们，这样您就可以连接 Java 开发过程的各个方面。

# 练习 - JDK 工具和实用程序

在您的计算机上，找到 Java 安装目录，并列出所有命令（工具和实用程序） - 执行文件 - 存在那里。

如果您在其他可执行文件中看到`java`和`javac`，则您就在正确的位置。

# 答案

以下是安装在 Java 10.0.1 中的所有可执行文件的列表：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/39770b16-82b4-4a03-ba59-841621ebbb14.png)

找到这个目录的一种方法是查看环境变量`PATH`的值。例如，在 Mac 电脑上，Java 安装在目录`/Library/Java/JavaVirtualMachines/jdk-10.jdk/Contents/Home/bin`中。

描述 JVM 安装位置的 Oracle 文档可以在[`www.java.com/en/download/help/version_manual.xml`](https://www.java.com/en/download/help/version_manual.xml)找到。

# 总结

在本章中，您已经学习了最重要的与 Java 相关的术语——JVM、JDK、SDK、Java 平台等，涵盖了 Java 程序生命周期的主要阶段，从源代码到字节码再到执行。您还了解了 Java 的历史、创建背后的动机、版本和版本。提供的实际步骤和建议帮助您在计算机上安装 Java 并运行其主要命令`java`、`javac`和`jcmd`。有关更多详细信息，您被引用到官方的 Oracle 文档。找到并理解这些文档的能力是成为 Java 程序员成功的先决条件，因此我们建议您跟随所有提供的链接，并在互联网上进行一些相关搜索，以便您能够轻松找到良好的信息来源。

在下一章中，我们将深入探讨 Java 作为一种编程语言，并涵盖基础知识。这将成为接下来章节的基础（或者说是一个跳板）。如果您是 Java 的新手，我们建议您继续阅读而不要跳过，因为每一章都建立在前一章的知识基础上。即使您对 Java 有一些了解，重新复习基础知识也总是有帮助的。拉丁谚语说：“Repetitio est mater studiorum”（重复是学习之母）。


# 第二章：Java 语言基础

现在您对 Java 及其相关术语和工具有了一个大致的了解，我们将开始讨论 Java 作为一种编程语言。

本章将介绍 Java 作为**面向对象编程**（**OOP**）语言的基本概念。您将了解类、接口和对象及其关系。您还将学习 OOP 的概念和特性。

在本章中，我们将涵盖以下主题：

+   Java 编程的基本术语

+   类和对象（实例）

+   类（静态）和对象（实例）成员

+   接口、实现和继承

+   OOP 的概念和特性

+   练习-接口与抽象类

我们称它们为基础，因为它们是 Java 作为一种语言的基本原则，而在您可以开始专业编程之前还有更多要学习。对于那些第一次学习 Java 的人来说，学习 Java 的基础是一个陡峭的斜坡，但之后的道路会变得更容易。

# Java 编程的基本术语

Java 编程基础的概念有很多解释。一些教程假设基础对于任何面向对象的语言都是相同的。其他人讨论语法和基本语言元素和语法规则。还有一些人将基础简化为允许计算的值类型、运算符、语句和表达式。

我们对 Java 基础的看法包括了前面各种方法的一些元素。我们选择的唯一标准是实用性和逐渐增加的复杂性。我们将从本节的简单定义开始，然后在后续章节中深入探讨。

# 字节码

在最广泛的意义上，Java 程序（或任何计算机程序）意味着一系列顺序指令，告诉计算机该做什么。在计算机上执行之前，程序必须从人类可读的高级编程语言编译成机器可读的二进制代码。

在 Java 的情况下，人类可读的文本，称为源代码，存储在一个`.java`文件中，并可以通过 Java 编译器`javac`编译成字节码。Java 字节码是 JVM 的指令集。字节码存储在一个`.class`文件中，并可以由 JVM 或更具体地说是由 JVM 使用的**即时**（**JIT**）编译器解释和编译成二进制代码。然后由微处理器执行二进制代码。

字节码的一个重要特点是它可以从一台机器复制到另一台机器的 JVM 上执行。这就是 Java 可移植性的含义。

# 缺陷（bug）及其严重程度和优先级

*bug*这个词，意思是*小故障和困难*，早在 19 世纪就存在了。这个词的起源是未知的，但看起来好像动词*to bug*的意思是*打扰*，来自于一种讨厌的感觉，来自于一个嗡嗡作响并威胁要咬你或其他东西的昆虫-虫子。这个词在计算机第一次建造时就被用于编程缺陷。

缺陷的严重程度各不相同-它们对程序执行或结果的影响程度。一些缺陷是相当微不足道的，比如数据以人类可读的格式呈现。如果同样的数据必须由其他无法处理这种格式的系统消耗，那就另当别论了。那么这样的缺陷可能被归类为关键，因为它将不允许系统完成数据处理。

缺陷的严重程度取决于它对程序的影响，而不是修复它有多困难。

一些缺陷可能会导致程序在达到期望结果之前退出。例如，一个缺陷可能导致内存或其他资源的耗尽，并导致 JVM 关闭。

缺陷优先级，缺陷在待办事项列表中的高度，通常与严重性相对应。但是，由于客户的感知，一些低严重性的缺陷可能会被优先考虑。例如，网站上的语法错误，或者可能被视为冒犯的拼写错误。

缺陷的优先级通常对应于其严重性，但有时，优先级可能会根据客户的感知而提高。

# Java 程序依赖

我们还提到，程序可能需要使用已编译为字节码的其他程序和过程。为了让 JVM 找到它们，您必须在`java`命令中使用`-classpath`选项列出相应的`.class`文件。几个程序和过程组成了一个 Java 应用程序。

应用程序用于其任务的其他程序和过程称为应用程序依赖项。

请注意，JVM 在其他类代码请求之前不会读取`.class`文件。因此，如果在应用程序执行期间不发生需要它们的条件，那么类路径上列出的一些`.class`文件可能永远不会被使用。

# 语句

语句是一种语言构造，可以编译成一组指令给计算机。与日常生活中的 Java 语句最接近的类比是英语语句，这是一种表达完整思想的基本语言单位。Java 中的每个语句都必须以`;`（分号）结尾。

以下是一个声明语句的示例：

```java
int i;
```

前面的语句声明了一个`int`类型的变量`i`，代表*整数*（见第五章，*Java 语言元素和类型*）。

以下是一个表达式语句：

```java
 i + 2; 
```

前面的语句将 2 添加到现有变量`i`的值中。当声明时，`int`变量默认被赋值为 0，因此此表达式的结果为`2`，但未存储。这就是为什么它经常与声明和赋值语句结合使用的原因：

```java
int j = i + 2;
```

这告诉处理器创建一个`int`类型的变量`j`，并为其分配一个值，该值等于变量`i`当前分配的值加 2。在第九章，*运算符、表达式和语句*中，我们将更详细地讨论语句和表达式。

# 方法

Java 方法是一组语句，总是一起执行，目的是对某个输入产生某个结果。方法有一个名称，要么一组输入参数，要么根本没有参数，一个在`{}`括号内的主体，以及一个返回类型或`void`关键字，表示该消息不返回任何值。以下是一个方法的示例：

```java
int multiplyByTwo(int i){
  int j = i * 2;
  return j;
}
```

在前面的代码片段中，方法名为`multiplyByTwo`。它有一个`int`类型的输入参数。方法名和参数类型列表一起称为**方法签名**。输入参数的数量称为**arity**。如果两个方法具有相同的名称、相同的 arity 和相同的输入参数列表中类型的顺序，则它们具有相同的签名。

这是从 Java 规范第*8.4.2 节方法签名*中摘取的方法签名定义的另一种措辞。另一方面，在同一规范中，人们可能会遇到诸如：*具有相同名称和签名的多个方法*，*类*`Tuna`*中的方法*`getNumberOfScales`*具有名称、签名和返回类型*等短语。因此，要小心；即使是规范的作者有时也不将方法名包括在方法签名的概念中，如果其他程序员也这样做，不要感到困惑。

同一个前面的方法可以用许多风格重写，并且得到相同的结果：

```java
int multiplyByTwo(int i){ 
  return i * 2;
}
```

另一种风格如下：

```java
int multiplyByTwo(int i){ return i * 2; }
```

一些程序员更喜欢最紧凑的风格，以便能够在屏幕上看到尽可能多的代码。但这可能会降低另一个程序员理解代码的能力，这可能会导致编程缺陷。

另一个例子是一个没有输入参数的方法：

```java
int giveMeFour(){ return 4; }
```

这是相当无用的。实际上，没有参数的方法会从数据库中读取数据，例如，或者从其他来源读取数据。我们展示这个例子只是为了演示语法。

这是一个什么都不做的代码示例：

```java
void multiplyByTwo(){ }
```

前面的方法什么也不做，也不返回任何东西。语法要求使用关键字`void`来指示没有返回值。实际上，没有返回值的方法通常用于将数据记录到数据库，或者发送数据到打印机、电子邮件服务器、另一个应用程序（例如使用 Web 服务），等等。

为了完整起见，这是一个具有许多参数的方法的示例：

```java
String doSomething(int i, String s, double a){
  double result = Math.round(Math.sqrt(a)) * i;
  return s + Double.toString(result);
}
```

上述方法从第三个参数中提取平方根，将其乘以第一个参数，将结果转换为字符串，并将结果附加（连接）到第二个参数。将在第五章中介绍使用的`Math`类的类型和方法，*Java 语言元素和类型*。这些计算并没有太多意义，仅供说明目的。

# 类

Java 中的所有方法都声明在称为**类**的结构内。一个类有一个名称和一个用大括号`{}`括起来的主体，在其中声明方法：

```java
class MyClass {
  int multiplyByTwo(int i){ return i * 2; }
  int giveMeFour(){ return 4;} 
}
```

类也有字段，通常称为属性；我们将在下一节讨论它们。

# 主类和主方法

一个类作为 Java 应用程序的入口。在启动应用程序时，必须在`java`命令中指定它：

```java
java -cp <location of all .class files> MyGreatApplication
```

在上述命令中，`MyGreatApplication`是作为应用程序起点的类的名称。当 JVM 找到文件`MyGreatApplication.class`时，它会将其读入内存，并在其中查找名为`main()`的方法。这个方法有一个固定的签名：

```java
public static void main(String[] args) {
  // statements go here
}
```

让我们把前面的代码片段分成几部分：

+   `public`表示这个方法对任何外部程序都是可访问的（参见第七章，*包和可访问性（可见性）*）

+   `static`表示该方法在所有内存中只存在一个副本（参见下一节）

+   `void`表示它不返回任何东西

+   `main`是方法名

+   `String[] args`表示它接受一个 String 值的数组作为输入参数（参见第五章，*Java 语言元素和类型*）

+   `//`表示这是一个注释，JVM 会忽略它，这里只是为了人类（参见第五章，*Java 语言元素和类型*）

前面的`main()`方法什么也不做。如果运行，它将成功执行但不会产生结果。

您还可以看到输入参数写成如下形式：

```java
public static void main(String... args) {
  //body that does something
}
```

它看起来像是不同的签名，但实际上是相同的。自 JDK 5 以来，Java 允许将方法签名的*最后一个参数*声明为相同类型的变量可变性的一系列参数。这被称为**varargs**。在方法内部，可以将最后一个输入参数视为数组`String[]`，无论它是显式声明为数组还是作为可变参数。如果你一生中从未使用过 varargs，那么你会没问题。我们告诉你这些只是为了让你在阅读其他人的代码时避免混淆。

`main（）`方法的最后一个重要特性是其输入参数的来源。没有其他代码调用它。它是由 JVM 本身调用的。那么参数是从哪里来的呢？人们可能会猜想命令行是参数值的来源。在`java`命令中，到目前为止，我们假设没有参数传递给主类。但是如果主方法期望一些参数，我们可以构造命令行如下：

```java
java -cp <location of all .class files> MyGreatApplication 1 2
```

这意味着在`main（）`方法中，输入数组`args [0]`的第一个元素的值将是`1`，而输入数组`args [1]`的第二个元素的值将是`2`。是的，你注意到了，数组中元素的计数从`0`开始。我们将在第五章中进一步讨论这个问题，*Java 语言元素和类型*。无论是显式地使用数组`String[] args`描述`main（）`方法签名，还是使用可变参数`String... args`，结果都是一样的。

然后`main（）`方法中的代码调用同一 main`.class`文件中的方法或使用`-classpath`选项列出的其他`.class`文件中的方法。在接下来的部分中，我们将看到如何进行这样的调用。

# 类和对象（实例）

类用作创建对象的模板。创建对象时，类中声明的所有字段和方法都被复制到对象中。对象中字段值的组合称为**对象状态**。方法提供对象行为。对象也称为类的实例。

每个对象都是使用运算符`new`和看起来像一种特殊类型的方法的构造函数创建的。构造函数的主要职责是设置初始对象状态。

现在让我们更仔细地看一看 Java 类和对象。

# Java 类

Java 类存储在`.java`文件中。每个`.java`文件可以包含多个类。它们由 Java 编译器`javac`编译并存储在`.class`文件中。每个`.class`文件只包含一个已编译的类。

每个`.java`文件只包含一个`public`类。类名前的关键字`public`使其可以从其他文件中的类访问。文件名必须与公共类名匹配。文件还可以包含其他类，它们被编译成自己的`.class`文件，但只能被给出其名称的公共类访问`.java`文件。

这就是文件`MyClass.java`的内容可能看起来像的样子：

```java
public class MyClass {
  private int field1;
  private String field2;
  public String method1(int i){
    //statements, including return statement
  }
  private void method2(String s){
    //statements without return statement
  }
}
```

它有两个字段。关键字`private`使它们只能从类内部，从它的方法中访问。前面的类有两个方法 - 一个是公共的，一个是私有的。公共方法可以被任何其他类访问，而私有方法只能从同一类的其他方法中访问。

这个类似乎没有构造函数。那么，基于这个类的对象的状态将如何初始化？答案是，事实上，每个没有显式定义构造函数但获得一个默认构造函数的类。这里有两个显式添加的构造函数的例子，一个没有参数，另一个有参数：

```java
public class SomeClass {
  private int field1;
  public MyClass(){
    this.field1 = 42;
  }
  //... other content of the class - methods
  //    that define object behavior
}

public class MyClass {
  private int field1;
  private String field2;
  public MyClass(int val1, String val2){
    this.field1 = val1;
    this.field2 = val2;
  }
  //... methods here
}
```

在上面的代码片段中，关键字`this`表示当前对象。它的使用是可选的。我们可以写`field1 = val1;`并获得相同的结果。但是最好使用关键字`this`来避免混淆，特别是当（程序员经常这样做）参数的名称与字段的名称相同时，比如在下面的构造函数中：

```java
public MyClass(int field1, String field1){
  field1 = field1;
  field2 = field2;
}
```

添加关键字`this`使代码更友好。有时候，这是必要的。我们将在第六章中讨论这样的情况，*接口、类和对象构造*。

一个构造函数也可以调用这个类或任何其他可访问类的方法：

```java
public class MyClass {
  private int field1;
  private String field2;
  public MyClass(int val1, String val2){
    this.field1 = val1;
    this.field2 = val2;
    method1(33);
    method2(val2);
  }
  public String method1(int i){
    //statements, including return statement
  }
  private void method2(String s){
    //statements without return statement
  }
}
```

如果一个类没有显式定义构造函数，它会从默认的基类`java.lang.Object`中获得一个默认构造函数。我们将在即将到来的*继承*部分解释这意味着什么。

一个类可以有多个不同签名的构造函数，用于根据应用程序逻辑创建具有不同状态的对象。一旦在类中添加了带参数的显式构造函数，除非也显式添加默认构造函数，否则默认构造函数将不可访问。澄清一下，这个类只有一个默认构造函数：

```java
public class MyClass {
  private int field1;
  private String field2;
  //... other methods here
}
```

这个类也只有一个构造函数，但没有默认构造函数：

```java
public class MyClass {
  private int field1;
  private String field2;
  public MyClass(int val1, String val2){
    this.field1 = val1;
    this.field2 = val2;
  }
  //... other methods here
}
```

这个类有两个构造函数，一个有参数，一个没有参数：

```java
public class MyClass {
  private int field1;
  private String field2;
  public MyClass(){ }
  public MyClass(int val1, String val2){
    this.field1 = val1;
    this.field2 = val2;
  }
  //... other methods here
}
```

没有参数的前面构造函数什么也不做。它只是为了方便客户端代码创建这个类的对象，但不关心对象的特定初始状态。在这种情况下，JVM 创建默认的初始对象状态。我们将在第六章中解释默认状态，*接口、类和对象构造*。

同一个类的每个对象，由任何构造函数创建，都有相同的方法（相同的行为），即使它的状态（分配给字段的值）是不同的。

这些关于 Java 类的信息对于初学者来说已经足够了。尽管如此，我们还想描述一些其他类，这些类可以包含在同一个`.java`文件中，这样你就可以在其他人的代码中识别它们。这些其他类被称为**嵌套类**。它们只能从同一个文件中的类中访问。

我们之前描述的类-`.java`文件中唯一的一个公共类-也被称为顶级类。它可以包括一个称为内部类的嵌套类：

```java
public class MyClass { // top-level class
  class MyOtherClass { // inner class   
    //inner class content here
  }
}
```

顶级类还可以包括一个静态（关于静态成员的更多信息请参见下一节）嵌套类。`static`类不被称为内部类，只是一个嵌套类：

```java
public class MyClass { // top-level class
  static class MyYetAnotherClass { // nested class
    // nested class content here
  }
}
```

任何方法都可以包括一个只能在该方法内部访问的类。它被称为本地类：

```java
public class MyClass { // top-level class
  void someMethod() {
    class MyInaccessibleAnywhereElseClass { // local class
      // local class content here
    }
  }
}
```

本地类并不经常使用，但并不是因为它没有用。程序员只是不记得如何创建一个只在一个方法内部需要的类，而是创建一个外部或内部类。

最后但并非最不重要的一种可以包含在与公共类相同文件中的类是匿名类。它是一个没有名称的类，允许在原地创建一个对象，可以覆盖现有方法或实现一个接口。让我们假设我们有以下接口，`InterfaceA`，和类`MyClass`：

```java
public interface InterfaceA{
  void doSomething();
}
public class MyClass { 
  void someMethod1() {
    System.out.println("1\. Regular is called");
  }
  void someMethod2(InterfaceA interfaceA) {
    interfaceA.doSomething();
  }
}
```

我们可以执行以下代码：

```java
MyClass myClass = new MyClass();
myClass.someMethod1();
myClass = new MyClass() {     //Anonymous class extends class MyClass
  public void someMethod1(){              // and overrides someMethod1()
    System.out.println("2\. Anonymous is called");
  }
};
myClass.someMethod1();
myClass.someMethod2(new InterfaceA() { //Anonymous class implements
  public void doSomething(){     //  InterfaceA

    System.out.println("3\. Anonymous is called");
  }
});
```

结果将是：

```java
1\. Regular is called
2\. Anonymous is called
3\. Anonymous is called
```

我们不希望读者完全理解前面的代码。我们希望读者在阅读本书后能够做到这一点。

这是一个很长的部分，包含了很多信息。其中大部分只是供参考，所以如果你记不住所有内容，不要感到难过。在完成本书并获得一些 Java 编程的实际经验后，再回顾这一部分。

接下来还有几个介绍性部分。然后[第三章]（18c6e8b8-9d8a-4ece-9a3f-cd00474b713e.xhtml），*您的开发环境设置*，将引导您配置计算机上的开发工具，并且在[第四章]（64574f55-0e95-4eda-9ddb-b05da6c41747.xhtml），*您的第一个 Java 项目*，您将开始编写代码并执行它-每个软件开发人员都记得的时刻。

再走几步，你就可以称自己为 Java 程序员了。

# Java 对象（类实例）

人们经常阅读-甚至 Oracle 文档也不例外-对象被*用于模拟现实世界的对象*。这种观点起源于面向对象编程之前的时代。那时，程序有一个用于存储中间结果的公共或全局区域。如果不小心管理，不同的子例程和过程-那时称为方法-修改这些值，互相干扰，使得很难追踪缺陷。自然地，程序员们试图规范对数据的访问，并且使中间结果只能被某些方法访问。一组方法和只有它们可以访问的数据开始被称为对象。

这些构造也被视为现实世界对象的模型。我们周围的所有对象可能都有某种内在状态，但我们无法访问它，只知道对象的行为。也就是说，我们可以预测它们对这个或那个输入会有什么反应。在类（对象）中创建只能从同一类（对象）的方法中访问的私有字段似乎是隐藏对象状态的解决方案。因此，模拟现实世界对象的原始想法得以延续。

但是经过多年的面向对象编程，许多程序员意识到这样的观点可能会产生误导，并且在试图将其一贯应用于各种软件对象时实际上可能会产生相当大的危害。例如，一个对象可以携带用作算法参数的值，这与任何现实世界的对象无关，但与计算效率有关。或者，另一个例子，一个带回计算结果的对象。程序员通常称之为**数据传输对象**（**DTO**）。除非扩展现实世界对象的定义，否则它与现实世界对象无关，但那将是一个伸展。

软件对象只是计算机内存中的数据结构，实际值存储在其中。内存是一个现实世界的对象吗？物理内存单元是，但它们携带的信息并不代表这些单元。它代表软件对象的值和方法。关于对象的这些信息甚至不是存储在连续的内存区域中：对象状态存储在一个称为堆的区域中，而方法存储在方法区中，具体取决于 JVM 实现，可能或可能不是堆的一部分。

在我们的经验中，对象是计算过程的一个组成部分，通常不是在现实世界对象的模型上运行。对象用于传递值和方法，有时相关，有时不相关。方法和值的集合可能仅仅为了方便或其他考虑而被分组在一个类中。

公平地说，有时软件对象确实代表现实世界对象的模型。但关键是这并不总是如此。因此，除非真的是这样，让我们不将软件对象视为现实世界对象的模型。相反，让我们看看对象是如何创建和使用的，以及它们如何帮助我们构建有用的功能 - 应用程序。

正如我们在前一节中所描述的，对象是基于类创建的，使用关键字`new`和构造函数 - 要么是默认的，要么是显式声明的。例如，考虑以下类：

```java
public class MyClass {
  private int field1;
  private String field2;
  public MyClass(int val1, String val2){
    this.field1 = val1;
    this.field2 = val2;
  }

  public String method1(int i){
    //statements, including return statement
  }
  //... other methods are here
}
```

如果我们有这个类，我们可以在其他类的方法中写以下内容：

```java
public AnotherClass {
  ...
  public void someMethod(){
    MyClass myClass = new MyClass(3, "some string");
    String result = myClass.method1(2);
  }
  ...
}
```

在前面的代码中，语句`MyClass myClass = new MyClass(3, "some string");`创建了一个`MyClass`类的对象，使用了它的构造函数和关键字`new`，并将新创建的对象的引用分配给变量`myClass`。我们选择了一个对象引用的标识符，它与类名匹配，第一个字母小写。这只是一个约定，我们也可以选择另一个标识符（比如`boo`），结果是一样的。在第五章中，*Java 语言元素和类型*，我们会更详细地讨论标识符和变量。正如你在前面的例子中看到的，在下一行中，一旦创建了一个引用，我们就可以使用它来访问新创建对象的公共成员。

任何 Java 对象都只能通过使用关键字（运算符）`new`和构造函数来创建。这个过程也被称为**类实例化**。对对象的引用可以像任何其他值一样传递（作为变量、参数或返回值），每个有权访问引用的代码都可以使用它来访问对象的公共成员。我们将在下一节中解释什么是**公共成员**。

# 类（静态）和对象（实例）成员

我们已经提到了与对象相关的公共成员这个术语。在谈到`main()`方法时，我们还使用了关键字`static`。我们还声明了一个被声明为`static`的成员在 JVM 内存中只能有一个副本。现在，我们将定义所有这些，以及更多。

# 私有和公共

关键字`private`和`public`被称为**访问修饰符**。还有默认和`protected`访问修饰符，但我们将在第七章中讨论它们，*包和可访问性（可见性）*。它们被称为访问修饰符，因为它们调节类、方法和字段的可访问性（有时也被称为可见性），并且它们修改相应的类、方法或字段的声明。

一个类只有在它是嵌套类时才能是私有的。在前面的*Java 类*部分，我们没有为嵌套类使用显式访问修饰符（因此，我们使用了默认的），但如果我们希望只允许从顶级类和同级访问这些类，我们也可以将它们设为私有。

私有方法或私有字段只能从声明它的类（对象）中访问。

相比之下，公共类、方法或字段可以从任何其他类中访问。请注意，如果封闭类是私有的，那么方法或字段就不能是公共的。这是有道理的，不是吗？如果类本身在公共上是不可访问的，那么它的成员如何能是公共的呢？

# 静态成员

只有当类是嵌套类时，才能声明一个类为静态。类成员——方法和字段——也可以是静态的，只要类不是匿名的或本地的。任何代码都可以访问类的静态成员，而不需要创建类实例（对象）。在前面的章节中，我们在一个代码片段中使用了类`Math`，就是这样的一个例子。静态类成员在字段的情况下也被称为类变量，方法的情况下被称为类方法。请注意，这些名称包含`class`这个词作为形容词。这是因为静态成员与类相关联，而不是与类实例相关联。这意味着在 JVM 内存中只能存在一个静态成员的副本，尽管在任何时刻可以创建和驻留在那里的类的许多实例（对象）。

这里是另一个例子。假设我们有以下类：

```java
public class MyClass {
  private int field1;
  public static String field2;
  public MyClass(int val1, String val2){
    this.field1 = val1;
    this.field2 = val2;
  }

  public String method1(int i){
    //statements, including return statement
  }
  public static void method2(){
    //statements
  }
  //... other methods are here
}
```

从任何其他类的任何方法，可以通过以下方式访问前述`MyClass`类的公共静态成员：

```java
MyClass.field2 = "any string";
String s = MyClass.field2 + " and another string";
```

前述操作的结果将是将变量`s`的值分配为`any string and another string`。`String`类将在第五章中进一步讨论，*Java 语言元素和类型*。

同样，可以通过以下方式访问类`MyClass`的公共静态方法`method2()`：

```java
MyClass.method2();
```

类`MyClass`的其他方法仍然可以通过实例（对象）访问：

```java
MyClass mc = new MyClass(3, "any string");
String someResult = mc.method1(42);
```

显然，如果所有成员都是静态的，就没有必要创建`MyClass`类的对象。

然而，有时可以通过对象引用访问静态成员。以下代码可能有效 - 这取决于`javac`编译器的实现。如果有效，它将产生与前面代码相同的结果：

```java
MyClass mc = new MyClass(3, "any string");
mc.field2 = "Some other string";
mc.method2();
```

有些编译器会提供警告，比如*通过实例引用访问静态成员*，但它们仍然允许你这样做。其他编译器会产生错误*无法使静态引用非静态方法/字段*，并强制你纠正代码。Java 规范不规定这种情况。但是，通过对象引用访问静态类成员不是一个好的做法，因为它使得代码对于人类读者来说是模棱两可的。因此，即使你的编译器更宽容，最好还是避免这样做。

# 对象（实例）成员

非静态类成员在字段的情况下也称为实例变量，或者在方法的情况下称为实例方法。它只能通过对象的引用后跟一个点“。”来访问。我们已经看到了几个这样的例子。

按照长期以来的传统，对象的字段通常声明为私有的。如果必要，提供`set()`和/或`get()`方法来访问这些私有值。它们通常被称为 setter 和 getter，因为它们设置和获取私有字段的值。这是一个例子：

```java
public class MyClass {
  private int field1;
  private String field2;
  public void setField1(String val){
    this.field1 = val;
  }
  public String getField1(){
    return this.field1;
  }
  public void setField2(String val){
    this.field2 = val;
  }
  public String getField2(){
    return this.field2;
  }
  //... other methods are here
}
```

有时，有必要确保对象状态不能被改变。为了支持这种情况，程序员使用构造函数来设置状态并删除 setter：

```java
public class MyClass {
  private int field1;
  private String field2;
  public MyClass(int val1, String val2){
    this.field1 = val1;
    this.field2 = val2;
  }
  public String getField1(){
    return this.field1;
  }

  public String getField2(){
    return this.field2;
  }
  //... other non-setting methods are here
}
```

这样的对象称为不可变的。

# 方法重载

具有相同名称但不同签名的两个方法代表方法重载。这是一个例子：

```java
public class MyClass {
  public String method(int i){
    //statements
  }
  public int method(int i, String v){
    //statements
  }
}
```

以下是不允许的，会导致编译错误，因为返回值不是方法签名的一部分，如果它们具有相同的签名，则无法用于区分一个方法和另一个方法：

```java
public class MyClass {
  public String method(int i){
    //statements
  }
  public int method(int i){ //error
    //statements
  }
}
```

然而，这是允许的，因为这些方法具有不同的签名：

```java
public String method(String v, int i){
  //statements
}
public String method(int i, String v){
  //statements
}
```

# 接口、实现和继承

现在，我们要进入 Java 编程的最重要领域——接口、实现和继承这些广泛使用的 Java 编程术语。

# 接口

在日常生活中，“接口”这个词非常流行。它的含义与 Java 接口在编程中所扮演的角色非常接近。它定义了对象的公共界面。它描述了如何与对象进行交互以及可以期望它具有什么。它隐藏了内部类的工作原理，只公开了具有返回值和访问修饰符的方法签名。接口不能被实例化。接口类型的对象只能通过创建实现该接口的类的对象来创建（接口实现将在下一节中更详细地介绍）。

例如，看下面的类：

```java
public class MyClass {
  private int field1;
  private String field2;
  public MyClass(int val1, String val2){
    this.field1 = val1;
    this.field2 = val2;
  }
  public String method(int i){
    //statements
  }
  public int method(int i, String v){
    //statements
  }
}
```

它的接口如下：

```java
public interface MyClassInterface {
  String method(int i);
  int method(int i, String v);
}
```

因此，我们可以写`public class MyClass implements MyClassInterface {...}`。我们将在下一节中讨论它。

由于接口是*公共*的界面，默认情况下假定方法访问修饰符`public`，可以省略。

接口不描述如何创建类的对象。要发现这一点，必须查看类并查看它的构造函数的签名。还可以检查并查看是否存在可以在不创建对象的情况下访问的公共静态类成员。因此，接口只是类*实例*的公共界面。

让我们来看看接口的其余功能。根据 Java 规范，*接口的主体可以声明接口的成员，即字段、方法、类和接口。*如果您感到困惑，并问接口和类之间的区别是什么，您有一个合理的关注，我们现在将解决这个问题。

接口中的字段隐式地是公共的、静态的和最终的。修饰符`final`表示它们的值不能被改变。相比之下，在类中，类本身、它的字段、方法和构造函数的默认访问修饰符是包私有的，这意味着它只在自己的包内可见。包是相关类的命名组。您将在第七章中了解它们，*包和可访问性（可见性）*。

接口主体中的方法可以声明为默认、静态或私有。默认方法的目的将在下一节中解释。静态方法可以通过接口名称和点“`.`”从任何地方访问。私有方法只能被同一接口内的其他方法访问。相比之下，类中方法的默认访问修饰符是包私有的。

至于在接口内声明的类，它们隐式地是静态的。它们也是公共的，可以在没有接口实例的情况下访问，而创建接口实例是不可能的。我们不会再多谈论这样的类，因为它们用于超出本书范围的非常特殊的领域。

与类类似，接口允许在其内部声明内部接口。可以像任何静态成员一样从外部访问它，使用顶级接口和点“`.`”。我们想提醒您，接口默认是公共的，不能被实例化，因此默认是静态的。

与接口相关的最后一个非常重要的术语是抽象方法。接口中列出的没有实现的方法签名称为**抽象方法**，接口本身称为**抽象**，因为它抽象化、总结并移除了实现中的方法签名。抽象不能被实例化。例如，如果在任何类前面放置关键字`abstract`并尝试创建其对象，即使类中的所有方法都不是抽象的，编译器也会抛出错误。在这种情况下，类仅作为具有默认方法的接口。然而，在它们的使用上有显著的区别，您将在本章的接下来的*继承*部分中看到。

我们将在第六章*接口，类和对象构建*中更多地讨论接口，并在第七章*包和可访问性（可见性）*中涵盖它们的访问修饰符。

# 实现

一个接口可以被类实现，这意味着该类为接口中列出的每个抽象方法提供了一个具体的实现。这里是一个例子：

```java
interface Car {
  double getWeightInPounds();
  double getMaxSpeedInMilesPerHour();
}

public class CarImpl implements Car{
  public double getWeightInPounds(){
    return 2000d;
  }
  public double getMaxSpeedInMilesPerHour(){
    return 100d;
  }
}
```

我们将类命名为`CarImpl`，表示它是接口`Car`的实现。但是我们可以随意为其命名。

接口及其类实现也可以有其他方法，而不会引起编译错误。接口中额外方法的唯一要求是必须是默认方法并有具体实现。向类添加任何其他方法都不会干扰接口实现。例如：

```java
interface Car {
  double getWeightInPounds();
  double getMaxSpeedInMilesPerHour();
  default int getPassengersCount(){
    return 4;
  } 
}

public class CarImpl implements Car{
  private int doors;
  private double weight, speed;
  public CarImpl(double weight, double speed, int doors){
    this.weight = weight;
    this.speed = speed;
    this.dooes = doors;
  }
  public double getWeightInPounds(){
    return this.weight;
  }
  public double getMaxSpeedInMilesPerHour(){
    return this.speed;
  }
  public int getNumberOfDoors(){
    return this.doors;
  }
}
```

如果我们现在创建一个`CarImpl`类的实例，我们可以调用类中声明的所有方法：

```java
CarImpl car = new CarImpl(500d, 50d, 3); 
car.getWeightInPounds();         //Will return 500.0
car.getMaxSpeedInMilesPerHour(); //Will return 50.0
car.getNumberOfDoors();          //Will return 3

```

这并不令人惊讶。

但是，这里有一些你可能意想不到的：

```java
car.getPassengersCount();          //Will return 4
```

这意味着通过实现一个接口，类获得了接口默认方法。这就是默认方法的目的：为实现接口的所有类添加功能。如果没有默认方法，如果向旧接口添加一个抽象方法，所有当前的接口实现将触发编译错误。但是，如果添加一个带有`default`修饰符的新方法，现有的实现将继续像往常一样工作。

现在，另一个很好的技巧。如果一个类实现了与默认方法相同签名的方法，它将`覆盖`（一个技术术语）接口的行为。这里是一个例子：


```java
interface Car {
  double getWeightInPounds();
  double getMaxSpeedInMilesPerHour();
  default int getPassengersCount(){
    return 4;
  } 
}

public class CarImpl implements Car{
  private int doors;
  private double weight, speed;
  public CarImpl(double weight, double speed, int doors){
    this.weight = weight;
    this.speed = speed;
    this.dooes = doors;
  }
  public double getWeightInPounds(){
    return this.weight;
  }
  public double getMaxSpeedInMilesPerHour(){
    return this.speed;
  }
  public int getNumberOfDoors(){
    return this.doors;
  }
  public int getPassengersCount(){
    return 3;
  } 
}
```

如果我们使用本例中描述的接口和类，我们可以编写以下代码：

```java
CarImpl car = new CarImpl(500d, 50d, 3); 
car.getPassengersCount();        //Will return 3 now !!!!
```

如果接口的所有抽象方法都没有被实现，那么类必须声明为抽象类，并且不能被实例化。

接口的目的是代表它的实现-所有实现它的类的所有对象。例如，我们可以创建另一个实现`Car`接口的类：

```java
public class AnotherCarImpl implements Car{
  public double getWeightInPounds(){
    return 2d;
  }
  public double getMaxSpeedInMilesPerHour(){
    return 3d;
  }
  public int getNumberOfDoors(){
    return 4;
  }
  public int getPassengersCount(){
      return 5;

   } 
}
```

然后我们可以让`Car`接口代表它们中的每一个：

```java
Car car = new CarImpl(500d, 50d, 3); 
car.getWeightInPounds();          //Will return 500.0
car.getMaxSpeedInMilesPerHour();  //Will return 50.0
car.getNumberOfDoors();           //Will produce compiler error
car.getPassengersCount();         //Still returns 3 !!!!

car = new AnotherCarImpl();
car.getWeightInPounds();          //Will return 2.0
car.getMaxSpeedInMilesPerHour();  //Will return 3.0
car.getNumberOfDoors();           //Will produce compiler error
car.getPassengersCount();         //Will return 5 

```

从前面的代码片段中可以得出一些有趣的观察。首先，当变量`car`声明为接口类型时（而不是类类型，如前面的例子），不能调用接口中未声明的方法。

其次，`car.getPassengersCount()`方法第一次返回`3`。人们可能期望它返回`4`，因为`car`被声明为接口类型，人们可能期望默认方法起作用。但实际上，变量`car`指的是`CarImpl`类的对象，这就是为什么执行`car.getPassengersCount()`方法的是类的实现。

使用接口时，应该记住签名来自接口，但实现来自类，或者来自默认接口方法（如果类没有实现它）。这里还有默认方法的另一个特性。它们既可以作为可以实现的签名，也可以作为实现（如果类没有实现它）。

如果接口中有几个默认方法，可以创建私有方法，只能由接口的默认方法访问。它们可以用来包含公共功能，而不是在每个默认方法中重复。私有方法无法从接口外部访问。

有了这个，我们现在可以达到 Java 基础知识的高峰。在此之后，直到本书的结尾，我们只会添加一些细节并增强您的编程技能。这将是在高海拔高原上的一次漫步-您走得越久，就会感到越舒适。但是，要到达那个高度，我们需要爬上最后的上坡路；继承。

# 继承

一个类可以获取（继承）所有非私有非静态成员，因此当我们使用这个类的对象时，我们无法知道这些成员实际上位于哪里-在这个类中还是在继承它们的类中。为了表示继承，使用关键字`extends`。例如，考虑以下类：

```java
class A {
  private void m1(){...}
  public void m2(){...}
}

class B extends class A {
  public void m3(){...}
}

class C extends class B {
}
```

在这个例子中，类`B`和`C`的对象的行为就好像它们各自有方法`m2()`和`m3()`。唯一的限制是一个类只能扩展一个类。类`A`是类`B`和类`C`的基类。类`B`只是类`C`的基类。正如我们已经提到的，它们每个都有默认的基类`java.lang.Object`。类`B`和`C`是类`A`的子类。类`C`也是类`B`的子类。

相比之下，一个接口可以同时扩展许多其他接口。如果`AI`，`BI`，`CI`，`DI`，`EI`和`FI`是接口，那么允许以下操作：

```java
interface AI extends BI, CI, DI {
  //the interface body
}
interface DI extends EI, FI {
  //the interface body
}
```

在上述例子中，接口`AI`继承了接口`BI`，`CI`，`DI`，`EI`和`FI`的所有非私有非静态签名，以及任何其他是接口`BI`，`CI`，`DI`，`EI`和`FI`的基接口。

回到上一节的话题，*实现*，一个类可以实现多个接口：

```java
class A extends B implements AI, BI, CI, DI {
  //the class body
}
```

这意味着类`A`继承了类`B`的所有非私有非静态成员，并实现了接口`AI`，`BI`，`CI`和`DI`，以及它们的基接口。实现多个接口的能力来自于前面的例子，如果重写成这样，结果将完全相同：

```java
interface AI extends BI, CI, DI {
  //the interface body
}

class A extends B implements AI {
  //the class body
}
```

`扩展`接口（类）也称为超级接口（超类）或父接口（父类）。扩展接口（类）称为子接口（子类）或子接口（子类）。

让我们用例子来说明这一点。我们从接口继承开始：

```java
interface Vehicle {
  double getWeightInPounds();
}

interface Car extends Vehicle {
  int getPassengersCount();
}

public class CarImpl implements Car {
  public double getWeightInPounds(){
    return 2000d;
  }
  public int getPassengersCount(){
    return 4;
  }
}
```

在上述代码中，类`CarImpl`必须实现两个签名（列在接口`Vehicle`和接口`Car`中），因为从它的角度来看，它们都属于接口`Car`。否则，编译器会抱怨，或者类`CarImpl`必须声明为抽象的（不能被实例化）。

现在，让我们看另一个例子：

```java
interface Vehicle {
  double getWeightInPounds();
}

public class VehicleImpl implements Vehicle {
  public double getWeightInPounds(){
    return 2000d;
  }
}

interface Car extends Vehicle {
  int getPassengersCount();
}

public class CarImpl extends VehicleImpl implements Car {
  public int getPassengersCount(){
    return 4;
  }
}

```

在这个例子中，类`CarImpl`不需要实现`getWeightInPounds()`的抽象方法，因为它已经从基类`VehicleImpl`继承了实现。

所述类继承的一个后果通常对于初学者来说并不直观。为了证明这一点，让我们在类`CarImpl`中添加方法`getWeightInPounds()`：

```java
public class VehicleImpl {
  public double getWeightInPounds(){
    return 2000d;
  }
}

public class CarImpl extends VehicleImpl {
  public double getWeightInPounds(){
    return 3000d;
  }
  public int getPassengersCount(){
    return 4;
  }
}
```

在这个例子中，为了简单起见，我们不使用接口。因为类`CarImpl`是类`VehicleImpl`的子类，它可以作为类`VehicleImpl`的对象行为，这段代码将编译得很好：

```java
VehicleImpl vehicle = new CarImpl();
vehicle.getWeightInPounds();

```

问题是，你期望在前面片段的第二行中返回什么值？如果你猜测是 3,000，你是正确的。如果不是，不要感到尴尬。习惯需要时间。规则是，基类类型的引用可以引用其任何子类的对象。它被广泛用于覆盖基类行为。

峰会就在眼前。只剩下一步了，尽管它带来了一些你在读这本书之前可能没有预料到的东西，如果你对 Java 一无所知。

# java.lang.Object 类

所以，这里有一个惊喜。每个 Java 类，默认情况下（没有显式声明），都扩展了`Object`类。准确地说，它是`java.lang.Object`，但我们还没有介绍包，只会在第七章中讨论它们，*包和可访问性（可见性）*。

所有 Java 对象都继承了它的所有方法。共有十个：

+   `public boolean equals (Object obj)`

+   `public int hashCode()`

+   `public Class getClass()`

+   `public String toString()`

+   `protected Object clone()`

+   `public void wait()`

+   `public void wait(long timeout)`

+   `public void wait(long timeout, int nanos)`

+   `public void notify()`

+   `public void notifyAll()`

让我们简要地访问每个方法。

在我们这样做之前，我们想提一下，你可以在你的类中重写它们的默认行为，并以任何你需要的方式重新实现它们，程序员经常这样做。我们将在第六章中解释如何做到这一点，*接口、类和对象构造*。

# equals()方法

`java.lang.Object`类的`equals()`方法看起来是这样的：

```java
public boolean equals(Object obj) {
  //compares references of the current object
  //and the reference obj 
}
```

这是它的使用示例：

```java
Car car1 = new CarImpl();
Car car2 = car1;
Car car3 = new CarImpl();
car1.equals(car2);    //returns true
car1.equals(car3);    //returns false
```

从前面的例子中可以看出，默认方法`equals()`的实现只比较指向存储对象的地址的内存引用。这就是为什么引用`car1`和`car2`是相等的——因为它们指向同一个对象（内存的相同区域，相同的地址），而`car3`引用指向另一个对象。

`equals()`方法的典型重新实现使用对象的状态进行比较。我们将在第六章中解释如何做到这一点，*接口、类和对象构造*。

# `hashCode()`方法

`java.lang.Object`类的`hashCode()`方法看起来是这样的：

```java
public int hashCode(){
  //returns a hash code value for the object 
  //based on the integer representation of the memory address
}
```

Oracle 文档指出，如果两个方法根据`equals()`方法的默认行为是相同的，那么它们具有相同的`hashCode()`返回值。这很棒！但不幸的是，同一份文档指出，根据`equals()`方法，两个不同的对象可能具有相同的`hasCode()`返回值。这就是为什么程序员更喜欢重新实现`hashCode()`方法，并在重新实现`equals()`方法时使用它，而不是使用对象状态。尽管这种需要并不经常出现，我们不会详细介绍这种实现的细节。如果感兴趣，你可以在互联网上找到很好的文章。

# `getClass()`方法

`java.lang.Object`类的`getClass()`方法看起来是这样的：

```java
public Class getClass(){
  //returns object of class Class that has
  //many methods that provide useful information
}
```

从这个方法中最常用的信息是作为当前对象模板的类的名称。我们将在第六章中讨论为什么可能需要它，*接口、类和对象构造**.*可以通过这个方法返回的`Class`类的对象来访问类的名称。

# `toString()`方法

`java.lang.Object`类的`toString()`方法看起来像这样：

```java
public String toString(){
  //return string representation of the object
}
```

这个方法通常用于打印对象的内容。它的默认实现看起来像这样：

```java
public String toString() {
  return getClass().getName()+"@"+Integer.toHexString(hashCode());
}
```

正如你所看到的，它并不是非常具有信息性，所以程序员们会在他们的类中重新实现它。这是类`Object`中最常重新实现的方法。程序员们几乎为他们的每个类都这样做。我们将在第九章中更详细地解释`String`类及其方法，*运算符、表达式和语句*。

# `clone()`方法

`java.lang.Object`类的`clone()`方法看起来像这样：

```java
protected Object clone(){
  //creates copy of the object
}
```

这个方法的默认结果返回对象字段的副本，这是可以接受的，如果值不是对象引用。这样的值被称为**原始类型**，我们将在第五章中精确定义，*Java 语言元素和类型*。但是，如果对象字段持有对另一个对象的引用，那么只有引用本身会被复制，而不是引用的对象本身。这就是为什么这样的副本被称为浅层副本。要获得深层副本，必须重新实现`clone()`方法，并遵循可能相当广泛的对象树的所有引用。幸运的是，`clone()`方法并不经常使用。事实上，你可能永远不会遇到需要使用它的情况。

在阅读本文时，你可能会想知道，当对象被用作方法参数时会发生什么。它是使用`clone()`方法作为副本传递到方法中的吗？如果是，它是作为浅层副本还是深层副本传递的？答案是，都不是。只有对象的引用作为参数值传递进来，所以所有接收相同对象引用的方法都可以访问存储对象状态的内存区域。

这为意外数据修改和随后的数据损坏带来了潜在风险，将它们带入不一致的状态。这就是为什么，在传递对象时，程序员必须始终意识到他们正在访问可能在其他方法和类之间共享的值。我们将在第五章中更详细地讨论这一点，并在第十一章中扩展这一点，*JVM 进程和垃圾回收*，在讨论线程和并发处理时。

# The wait() and notify() methods

`wait()`和`notify()`方法及其重载版本用于线程之间的通信——轻量级的并发处理进程。程序员们不会重新实现这些方法。他们只是用它们来增加应用程序的吞吐量和性能。我们将在第十一章中更详细地讨论`wait()`和`notify()`方法，*JVM 进程和垃圾回收*。

现在，恭喜你。你已经踏上了 Java 基础复杂性的高峰，现在将继续水平前行，添加细节并练习所学知识。在阅读前两章的过程中，你已经在脑海中构建了 Java 知识的框架。如果有些东西不清楚或者忘记了，不要感到沮丧。继续阅读，你将有很多机会来刷新你的知识，扩展它，并保持更长时间。这将是一段有趣的旅程，最终会有一个不错的奖励。

# 面向对象编程概念

现在，我们可以谈论一些对你来说更有意义的概念，与在你学习主要术语并看到代码示例之前相比。这些概念包括：

+   对象/类：它将状态和行为保持在一起

+   封装：它隐藏了状态和实现的细节

+   继承：它将行为/签名传播到类/接口扩展链中

+   接口：它将签名与实现隔离开来

+   多态：这允许一个对象由多个实现的接口和任何基类表示，包括`java.lang.Object`。

到目前为止，你已经熟悉了上述所有内容，因此这将主要是一个总结，只添加一些细节。这就是我们学习的方式——观察特定事实，构建更大的图景，并随着新的观察不断改进这个图景。我们一直在做这件事，不是吗？

# 对象/类

一个 Java 程序和整个应用程序可以在不创建一个对象的情况下编写。只需在你创建的每个类的每个方法和每个字段前面使用`static`关键字，并从静态的`main()`方法中调用它们。你的编程能力将受到限制。你将无法创建一支可以并行工作的对象军队，他们可以在自己的数据副本上做类似的工作。但你的应用程序仍然可以工作。

此外，在 Java 8 中，添加了函数式编程特性，允许我们像传递对象一样传递函数。因此，你的无对象应用程序可能会非常强大。而且，一些没有对象创建能力的语言被使用得非常有效。然而，在面向对象的语言被证明有用并变得流行之后，第一个是 Smalltalk，一些传统的过程式语言，如 PHP、Perl、Visual Basic、COBOL 2002、Fortran 2003 和 Pascal 等，都添加了面向对象的能力。

正如我们刚才提到的，Java 还将其功能扩展到覆盖函数式编程，从而模糊了过程式、面向对象和函数式语言之间的界限。然而，类的存在和使用它们来创建对象的能力是编程语言必须支持的第一个概念，才能被归类为面向对象。

# 封装

封装——使数据和函数（方法）无法从外部访问或者有受控的访问——是创建面向对象语言的主要驱动因素之一。Smalltalk 是基于对象之间的消息传递的想法创建的，当一个对象调用另一个对象的方法时，这在 Smalltalk 和 Java 中都是这样做的。

封装允许调用对象的服务，而不知道这些服务是如何实现的。它减少了软件系统的复杂性，增加了可维护性。每个对象都可以独立地完成其工作，而无需与其客户端协调实现的更改，只要它不违反接口中捕获的合同。

我们将在第七章中进一步详细讨论封装，*包和可访问性（可见性）*。

# 继承

继承是另一个面向对象编程概念，受到每种面向对象语言的支持。通常被描述为能够重用代码的能力，这是一个真实但经常被误解的说法。一些程序员认为继承能够在应用程序之间实现代码的重用。根据我们的经验，应用程序之间的代码重用可以在没有继承的情况下实现，并且更多地依赖于应用程序之间的功能相似性，而不是特定的编程语言特性。这更多地与将通用代码提取到共享可重用库中的技能有关。

在 Java 或任何其他面向对象的语言中，继承允许在基类中实现的公共功能*在其子类中重用*。它可以用于通过将基类组装到一个共享的库中，实现模块化并提高代码的可重用性。但在实践中，这种方法很少被使用，因为每个应用程序通常具有特定的要求，一个共同的基类要么太简单而实际上无用，要么包含许多特定于每个应用程序的方法。此外，在第六章《接口、类和对象构造》中，我们将展示，使用聚合更容易实现可重用性，这是基于使用独立对象而不是继承。

与接口一起，继承使多态成为可能。

# 接口（抽象）

有时，接口的面向对象编程概念也被称为抽象，因为接口总结（抽象）了对象行为的公共描述，隐藏了其实现的细节。接口是封装和多态的一个组成部分，但足够重要，以至于被作为一个单独的概念来阐述。其重要性将在第八章《面向对象设计（OOD）原则》中变得特别明显，当我们讨论从项目想法和愿景到具体编程解决方案的过渡时。

接口和继承为多态提供了基础。

# 多态

从我们提供的代码示例中，您可能已经意识到，一个对象具有所有实现的接口中列出的方法和其基类的所有非私有非静态方法，包括`java.lang.Object`。就像一个拥有多重国籍的人一样，它可以被视为其基类或实现的接口的对象。这种语言能力被称为多态（来自*poly* - 许多和*morphos* - 形式）。

请注意，广义上讲，方法重载——当具有相同名称的方法根据其签名可以具有不同行为时——也表现出多态行为。

# 练习-接口与抽象类

接口和抽象类之间有什么区别？我们没有讨论过，所以您需要进行一些研究。

在 Java 8 中引入接口的默认方法后，差异显著缩小，在许多情况下可以忽略不计。

# 答案

抽象类可以有构造函数，而接口不能。

抽象类可以有状态，而接口不能。抽象类的字段可以是私有的和受保护的，而在接口中，字段是公共的、静态的和最终的。

抽象类可以具有任何访问修饰符的方法实现，而接口中实现的默认方法只能是 public。

如果您想要修改的类已经扩展到另一个类，您就不能使用抽象类，但是您可以实现一个接口，因为一个类只能扩展到另一个类，但可以实现多个接口。

# 总结

在本章中，您已经学习了 Java 和任何面向对象编程语言的基本概念。您现在了解了类和对象作为 Java 的基本构建模块，知道了静态和实例成员是什么，以及了解了接口、实现和继承。这是本初学者章节中最复杂和具有挑战性的练习，将读者带到了 Java 语言的核心，介绍了我们将在本书的其余部分中使用的语言框架。这个练习让读者接触到了关于接口和抽象类之间差异的讨论，这在 Java 8 发布后变得更加狭窄。

在下一章中，我们将转向编程的实际问题。读者将被引导完成在他们的计算机上安装必要工具和配置开发环境的具体步骤。之后，所有新的想法和软件解决方案将被演示，包括具体的代码示例。


# 第三章：你的开发环境设置

到目前为止，你可能已经对如何在计算机上编译和执行 Java 程序有了相当好的了解。现在，是时候学习如何编写程序了。在你能够做到这一点之前，这一章是最后一步。因为你需要先设置好你的开发环境，所以这一章将解释什么是开发环境，以及为什么你需要它。然后，它将引导你进行配置和调整，包括设置类路径。在此过程中，我们将提供流行编辑器的概述和 IntelliJ IDEA 的具体建议。

在这一章中，我们将涵盖以下主题：

+   什么是开发环境？

+   设置类路径

+   IDE 概述

+   如何安装和配置 IntelliJ IDEA

+   练习 - 安装 NetBeans

# 什么是开发环境？

开发环境是安装在你的计算机上的一组工具，它允许你编写 Java 程序（应用程序）和测试它们，与同事分享源代码，并对源代码进行编译和运行。我们将在本章讨论每个开发工具和开发过程的各个阶段。

# Java 编辑器是你的主要工具

一个支持 Java 的编辑器是开发环境的中心。原则上，你可以使用任何文本编辑器来编写程序并将其存储在`.java`文件中。不幸的是，普通文本编辑器不会警告你有关 Java 语言语法错误。这就是为什么支持 Java 的专门编辑器是编写 Java 程序的更好选择。

现代 Java 语言编辑器不仅仅是一个写作工具。它还具有与同一台计算机上安装的 JVM 集成的能力，并使用它来编译应用程序，执行它，等等。这就是为什么它不仅仅被称为编辑器，而是 IDE。它还可以与其他开发工具集成，因此你不需要退出 IDE 来将源代码存储在远程服务器上，例如源代码控制系统。

Java IDE 的另一个巨大优势是它可以提醒你有关语言的可能性，并帮助你找到实现所需功能的更好方法。

IDE 还支持代码重构。这个术语意味着改变代码以获得更好的可读性、可重用性或可维护性，而不影响其功能。例如，如果有一段代码在多个方法中使用，可以将其提取到一个单独的方法中，并在所有地方使用它，而不是复制代码。另一个例子是当类、方法或变量的名称更改为更具描述性的名称。使用普通编辑器需要你手动查找旧名称使用的所有地方。而 IDE 会为你完成这项工作。

IDE 的另一个有用功能是能够生成类的样板代码和标准方法，比如构造函数、getter、setter 或`toString()`方法。它通过让程序员专注于重要的事情来提高程序员的生产力。

因此，请确保你对所选择的 IDE 感到舒适。作为程序员，你将在大部分工作时间内与你的 IDE 编辑器一起工作。

# 源代码编译

一个集成开发环境（IDE）使用计算机上安装的`javac`编译器来查找所有 Java 语言的语法错误。早期发现这些错误比在应用程序已经在生产环境中运行后发现要容易得多。

并非所有编程语言都可以通过这种方式支持。Java 可以，因为 Java 是一种严格类型的语言，这意味着在使用变量之前需要为每个变量声明类型。在第二章中的示例中，您看到了`int`和`String`类型。之后，如果尝试对变量进行不允许的操作，或者尝试为其分配另一种类型，IDE 将警告您，您可以重新查看或坚持您编写代码的方式（当您知道自己在做什么时）。

尽管名称相似，JavaScript 与之相反，是一种动态类型的语言，允许在不定义其类型的情况下声明变量。这就是为什么 Java 新手可以从一开始就开发一个更复杂和完全功能的应用程序，而复杂的 JavaScript 代码即使对于经验丰富的程序员来说也仍然是一个挑战，并且仍然无法达到 Java 代码的复杂程度。

顺便说一下，尽管 Java 是在 C++之后引入的，但它之所以受欢迎，却是因为它对对象类型操作施加的限制。在 Java 中，与 C++相比，难以追踪的运行时错误的风险要小得多。运行时错误是那些不能仅根据语言语法在编译时由 IDE 找到的代码问题。

# 代码共享

IDE 集成了代码共享系统。在相同代码上的协作需要将代码放置在一个称为**源代码存储库**或版本控制存储库的共享位置，所有团队成员都可以访问。最著名的共享存储库之一是基于 Git 版本控制系统的基于 Web 的版本控制存储库 GitHub（[`github.com/`](https://github.com/)）。其他流行的源代码控制系统包括 CVS、ClearCase、Subversion 和 Mercurial 等。

关于这些系统的概述和指导超出了本书的范围。我们提到它们是因为它们是开发环境的重要组成部分。

# 代码和测试执行

使用 IDE，甚至可以执行应用程序或其测试。为了实现这一点，IDE 首先使用`javac`工具编译代码，然后使用 JVM（`java`工具）执行它。

IDE 还允许我们以调试模式运行应用程序，当执行可以在任何语句处暂停。这允许程序员检查变量的当前值，这通常是查找可怕的运行时错误的最有效方式。这些错误通常是由执行过程中分配给变量的意外中间值引起的。调试模式允许我们缓慢地沿着有问题的执行路径走，并查看导致问题的条件。

IDE 功能中最有帮助的一个方面是它能够维护类路径或管理依赖关系，我们将在下一节中讨论。

# 设置类路径

为了使`javac`编译代码并使`java`执行它，它们需要知道组成应用程序的文件的位置。在第二章中，*Java 语言基础*，在解释`javac`和`java`命令的格式时，我们描述了`-classpath`选项允许您列出应用程序使用的所有类和第三方库（或者说依赖的）的方式。现在，我们将讨论如何设置这个列表。

# 手动设置

有两种设置方式：

+   通过`-classpath`命令行选项

+   通过`CLASSPATH`环境变量

我们将首先描述如何使用`-classpath`选项。它在`javac`和`java`命令中具有相同的格式：

```java
-classpath dir1;dir2\*;dir3\alibrary.jar  (for Windows)

javac -classpath dir1:dir2/*:dir3/alibrary.jar   (for Lunix)
```

在前面的例子中，`dir1`、`dir2`和`dir3`是包含应用程序文件和应用程序依赖的第三方`.jar`文件的文件夹。每个文件夹也可以包括对目录的路径。路径可以是绝对路径，也可以是相对于运行此命令的当前位置的路径。

如果一个文件夹不包含`.jar`文件（例如只有`.class`文件），那么只需要列出文件夹名称即可。两个工具`javac`和`java`在搜索特定文件时都会查看文件夹内的内容。`dir1`文件夹提供了这样一个例子。

如果一个文件夹包含`.jar`文件（其中包含`.class`文件），则可以执行以下两种操作之一：

+   指定通配符`*`，以便在该文件夹中搜索所有`.jar`文件以查找所请求的`.class`文件（前面的`dir2`文件夹就是这样一个例子）

+   单独列出每个`.jar`文件（存储在`dir3`文件夹中的`alibrary.jar`文件就是一个例子）

`CLASSPATH`环境变量与`-classpath`命令选项具有相同的目的。作为`CLASSPATH`变量的值指定的文件位置列表的格式与前面描述的`-classpath`选项设置的列表相同。如果使用`CLASSPATH`，则可以在不使用`-classpath`选项的情况下运行`javac`和`java`命令。如果两者都使用，则`CLASSPATH`的值将被忽略。

要查看`CLASSPATH`变量的当前值，请打开命令提示符或终端，然后在 Windows OS 中键入`echo %CLASSPATH%`，在 Linux 中键入`echo $CLASSPATH`。很可能你什么都不会得到，这意味着`CLASSPATH`变量在您的计算机上没有使用。您可以使用`set`命令为其分配一个值。

可以使用`-classpath`选项包括`CLASSPATH`值：

```java
-classpath %CLASSPATH%;dir1;dir2\*;dir3\alibrary.jar (for Windows)

-classpath $CLASSPATH:dir1:dir2/*:dir3/alibrary.jar (for Lunix)
```

请注意，`javac`和`java`工具是 JDK 的一部分，因此它们知道在 JDK 中附带的 Java 标准库的位置，并且无需在类路径上指定标准库的`.jar`文件。

Oracle 提供了如何设置类路径的教程，网址为[`docs.oracle.com/javase/tutorial/essential/environment/paths.html`](https://docs.oracle.com/javase/tutorial/essential/environment/paths.html)。

# 在类路径上搜索

无论使用`-classpath`还是`CLASSPATH`，类路径值都表示`.class`和`.jar`文件的列表。`javac`和`java`工具总是从左到右搜索列表。如果同一个`.class`文件被列在多个位置（例如在多个文件夹或`.jar`文件中），那么只会找到它的第一个副本。如果类路径中包含同一库的多个版本，可能会导致问题。例如，如果在旧版本之后列出了库的新版本，则可能永远找不到库的新版本。

此外，库本身可能依赖于其他`.jar`文件及其特定版本。两个不同的库可能需要相同的`.jar`文件，但版本不同。

如您所见，当类路径上列出了许多文件时，它们的管理可能很快就会成为一项全职工作。好消息是，您可能不需要担心这个问题，因为 IDE 会为您设置类路径。

# IDE 会自动设置类路径

正如我们已经提到的，`javac`和`java`工具知道在 JDK 安装中附带的标准库的位置。如果您的代码使用其他库，您需要告诉 IDE 您需要哪些库，以便 IDE 可以找到它们并设置类路径。

为了实现这一点，IDE 使用了一个依赖管理工具。如今最流行的依赖管理工具是 Maven 和 Gradle。由于 Maven 的历史比 Gradle 长，所有主要的 IDE 都有这个工具，无论是内置的还是通过插件集成的。插件是可以添加到应用程序（在这种情况下是 IDE）中以扩展其功能的软件。

Maven 有一个广泛的在线存储库，存储了几乎所有现有的库和框架。要告诉具有内置 Maven 功能的 IDE 您的应用程序需要哪些第三方库，您必须在名为`pom.xml`的文件中标识它们。IDE 从`pom.xml`文件中读取您需要的内容，并从 Maven 存储库下载所需的库到您的计算机。然后，IDE 可以在执行`javac`或`java`命令时将它们列在类路径上。我们将向您展示如何在第四章中编写`pom.xml`内容，*您的第一个 Java 项目*。

现在是选择你的 IDE，安装它并配置它的时候了。在下一节中，我们将描述最流行的 IDE。

# 有许多 IDE

有许多可免费使用的 IDE：NetBeans、Eclipse、IntelliJ IDEA、BlueJ、DrJava、JDeveloper、JCreator、jEdit、JSource、jCRASP 和 jEdit 等。每个都有一些追随者，他们坚信自己的选择是最好的，所以我们不打算争论。毕竟这是一个偏好问题。我们将集中在三个最流行的 IDE 上 - NetBeans、Eclipse 和 IntelliJ IDEA。我们将使用 IntelliJ IDEA 免费的 Community Edition 进行演示。

我们建议在最终选择之前阅读有关这些和其他 IDE 的文档，甚至尝试它们。对于您的初步研究，您可以使用维基百科文章[`en.wikipedia.org/wiki/Comparison_of_integrated_development_environments#Java`](https://en.wikipedia.org/wiki/Comparison_of_integrated_development_environments#Java)，其中有一张表比较了许多现代 IDE。

# NetBeans

NetBeans 最初是在 1996 年作为布拉格查理大学的 Java IDE 学生项目创建的。1997 年，围绕该项目成立了一家公司，并生产了 NetBeans IDE 的商业版本。1999 年，它被 Sun Microsystems 收购。2010 年，在 Oracle 收购 Sun Microsystems 后，NetBeans 成为由 Oracle 生产的开源 Java 产品的一部分，并得到了大量开发人员的贡献。

NetBeans IDE 成为 Java 8 的官方 IDE，并可以与 JDK 8 一起下载在同一个捆绑包中；请参阅[`www.oracle.com/technetwork/java/javase/downloads/jdk-netbeans-jsp-142931.html`](http://www.oracle.com/technetwork/java/javase/downloads/jdk-netbeans-jsp-142931.html)。

2016 年，Oracle 决定将 NetBeans 项目捐赠给 Apache 软件基金会，并表示*通过即将发布的 Java 9 和 NetBeans 9 以及未来的成功，开放 NetBeans 治理模型，使 NetBeans 成员在项目的方向和未来成功中发挥更大的作用*。

NetBeans IDE 有 Windows、Linux、Mac 和 Oracle Solaris 版本。它可以编码、编译、分析、运行、测试、分析、调试和部署所有 Java 应用程序类型 - Java SE、JavaFX、Java ME、Web、EJB 和移动应用程序。除了 Java，它还支持多种编程语言，特别是 C/C++、XML、HTML5、PHP、Groovy、Javadoc、JavaScript 和 JSP。由于编辑器是可扩展的，可以插入对许多其他语言的支持。

它还包括基于 Ant 的项目系统、对 Maven 的支持、重构、版本控制（支持 CVS、Subversion、Git、Mercurial 和 ClearCase），并可用于处理云应用程序。

# Eclipse

Eclipse 是最广泛使用的 Java IDE。它有一个不断增长的广泛插件系统，因此不可能列出其所有功能。它的主要用途是开发 Java 应用程序，但插件也允许我们用 Ada、ABAP、C、C++、C#、COBOL、D、Fortran、Haskell、JavaScript、Julia、Lasso、Lua、NATURAL、Perl、PHP、Prolog、Python、R、Ruby、Rust、Scala、Clojure、Groovy、Scheme 和 Erlang 编写代码。开发环境包括 Eclipse **Java 开发工具**（**JDT**）用于 Java 和 Scala，Eclipse CDT 用于 C/C++，Eclipse PDT 用于 PHP 等。

*Eclipse*这个名字是在与微软 Visual Studio 的竞争中创造出来的，Eclipse 的目标是超越 Visual Studio。随后的版本以木星的卫星——卡利斯托、欧罗巴和迦尼米德的名字命名。之后，以发现这些卫星的伽利略的名字命名了一个版本。然后，使用了两个与太阳有关的名字——希腊神话中的太阳神赫利俄斯和彩虹的七种颜色之一——靛蓝。之后的版本，朱诺，有三重含义：罗马神话中的人物、一个小行星和前往木星的宇宙飞船。开普勒、月球和火星延续了天文主题，然后是来自化学元素名称的氖和氧。光子代表了对太阳主题名称的回归。

Eclipse 还可以编码、编译、分析、运行、测试、分析、调试和部署所有 Java 应用程序类型和所有主要平台。它还支持 Maven、重构、主要版本控制系统和云应用程序。

可用插件的种类繁多可能对新手构成挑战，甚至对更有经验的用户也是如此，原因有两个：

+   通常有多种方法可以向 IDE 添加相同的功能，通过组合不同作者的类似插件

+   一些插件是不兼容的，这可能会导致难以解决的问题，并迫使我们重新构建 IDE 安装，特别是在新版本发布时

# IntelliJ IDEA

IntelliJ IDEA 付费版本绝对是当今市场上最好的 Java IDE。但即使是免费的 Community Edition 在三大主要 IDE 中也占据着强势地位。在下面的维基百科文章中，您可以看到一个表格，它很好地总结了付费的 Ultimate 和免费的 Community Edition 之间的区别：[`en.wikipedia.org/wiki/IntelliJ_IDEA`](https://en.wikipedia.org/wiki/IntelliJ_IDEA)

它是由 JetBrains（以前被称为 IntelliJ）软件公司开发的，该公司在布拉格、圣彼得堡、莫斯科、慕尼黑、波士顿和新西伯利亚拥有约 700 名员工（截至 2017 年）。第一个版本于 2001 年 1 月发布，是最早具有集成高级代码导航和代码重构功能的 Java IDE 之一。从那时起，这个 IDE 以其对代码的深入洞察而闻名，正如作者在其网站上描述产品特性时所说的那样：[`www.jetbrains.com/idea/features`](https://www.jetbrains.com/idea/features)。

与前面描述的另外两个 IDE 一样，它可以编码、编译、分析、运行、测试、分析、调试和部署所有 Java 应用程序类型和所有主要平台。与前两个 IDE 一样，它还支持 Ant、Maven 和 Gradle，以及重构、主要版本控制系统和云应用程序。

在下一节中，我们将为您介绍 IntelliJ IDEA Community Edition 的安装和配置过程。

# 安装和配置 IntelliJ IDEA

以下步骤和截图将演示在 Windows 上安装 IntelliJ IDEA Community Edition，尽管对于 Linux 或 macOS，安装并没有太大的不同。

# 下载和安装

您可以从[`www.jetbrains.com/idea/download`](https://www.jetbrains.com/idea/download)下载 IntelliJ IDEA 社区版安装程序。下载安装程序后，通过双击它或右键单击并从菜单中选择“打开”选项来启动它。然后，通过单击“下一个>”按钮，接受所有默认设置，除非您需要执行其他操作。这是第一个屏幕：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/083f337d-e31d-4c5f-8ef3-3b47ed77ae82.png)

您可以使用“浏览...”按钮并选择“任何位置”作为目标文件夹，或者只需单击“下一个>”并在下一个屏幕上接受默认位置：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/73637610-0090-44dc-b563-5ac944c7bbf5.png)

在下一个屏幕上选中 64 位启动器（除非您的计算机仅支持 32 位）和`.java`：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/c37f9a10-2e34-462e-9eee-cfb193def702.png)

我们假设您已经安装了 JDK，因此在前一个屏幕上不需要检查“下载并安装 JRE”。如果您尚未安装 JDK，可以检查“下载并安装 JRE”，或者按照第一章中描述的步骤安装 JDK，*计算机上的 Java 虚拟机（JVM）*。

下一个屏幕允许您自定义启动菜单中的条目，或者您可以通过单击“安装”按钮接受默认选项：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/4e10a0e1-d7b3-4424-ab4a-1292c86330f2.png)

安装程序将花费一些时间来完成安装。下一个屏幕上的进度条将让您了解还有多少时间才能完成整个过程：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/3f37f576-ed3a-4f44-a4ea-b12ff990e562.png)

安装完成后，下一个>按钮变为可点击时，请使用它转到下一个屏幕。

在下一个屏幕上选中“运行 IntelliJ IDEA”框，并单击“完成”按钮：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/6200e762-07d4-4d8e-ba4a-ef78f523136e.png)

安装已完成，现在我们可以开始配置 IDE。

# 配置 IntelliJ IDEA

当 IntelliJ IDEA 第一次启动时，它会询问您是否有来自先前 IDE 版本的设置：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/bcb7a32a-81d8-4270-a2df-f313c8a2ca1a.png)

由于这是您第一次安装 IntelliJ IDEA，请单击“不导入设置”。

接下来的一个或两个屏幕也只会显示一次——在新安装的 IDE 首次启动时。它们将询问您是否接受 JetBrains 的隐私政策，以及您是否愿意支付许可证费用，还是希望继续使用免费的社区版或免费试用版（这取决于您获得的特定下载）。以您喜欢的方式回答问题，如果您接受隐私政策，下一个屏幕将要求您选择主题——白色（*IntelliJ*）或黑色（*Darcula*）。

我们选择了暗色主题，正如您将在我们的演示屏幕上看到的那样。但您可以选择任何您喜欢的，然后以后再更改：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/00e514db-230d-43fa-98e8-951346c40cec.png)

在上面的屏幕上，底部可以看到两个按钮：跳过剩余和设置默认和下一个：默认插件。如果您单击“跳过剩余并设置默认”，您将跳过现在配置一些设置的机会，但以后可以进行配置。对于此演示，我们将单击“下一个：默认插件”按钮，然后向您展示如何稍后重新访问设置。

这是默认设置选项的屏幕：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/8505312b-c990-423c-b0f9-1bd306a96acb.png)

您可以单击前面屏幕上的任何“自定义...”链接，查看可能的选项，然后返回。我们将仅使用其中的三个——构建工具、版本控制和测试工具。我们将首先通过单击“自定义...”来开始构建工具：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/eb0e3b40-3b53-45e3-b1ec-0aae96cc54fe.png)

我们将保留 Maven 选项的选择，但其他选项的存在不会有害，甚至可以帮助您以后探索相关功能。

点击保存更改并返回，然后点击版本控制符号下的自定义...链接：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/10e08611-46bc-44d6-8cb1-a998cc75a008.png)

我们稍后会谈一下源代码控制工具（或版本控制工具，它们也被称为），但是本书不涵盖这个主题的完整内容。在前面的屏幕上，您可以勾选您知道将要使用的版本控制系统的复选框。否则，请保持所有复选框都被勾选，这样一旦您打开从列出的工具之一检出的代码源树，版本控制系统就会自动集成。

点击保存更改并返回，然后点击测试工具符号下的自定义...链接：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/d7b8cedd-969c-49ca-b0b4-fea988a7f917.png)

在前面的屏幕上，我们将只保留 JUnit 复选框被选中，因为我们希望我们的演示配置清除不必要的干扰。但您可以保持所有复选框都被选中。拥有其他选项也没有坏处。此外，您可能决定在将来使用其他选项。

正如您所见，原则上，我们不需要更改任何默认设置。我们只是为了向您展示可用的功能。

点击保存更改并返回，然后点击“下一步：特色插件”按钮，然后点击“开始使用 IntelliJ IDEA”按钮。

如果您在安装时没有配置 IDE，或者做了一些不同的事情并希望更改配置，可以稍后进行更改。

我们将在安装后解释如何访问 IntelliJ IDEA 中的配置设置，并在第四章《您的第一个 Java 项目》中提供相应的屏幕截图。

# 练习 - 安装 NetBeans IDE

下载并安装 NetBeans IDE。

# 答案

截至撰写本文时，下载最新版本的 NetBeans 页面为[`netbeans.org/features/index.html`](https://netbeans.org/features/index.html)。

下载完成后，启动安装程序。您可能会收到一条消息，建议您在启动安装程序时使用`--javahome`选项。找到相应的安装说明，并执行。NetBeans 版本需要特定版本的 Java，不匹配可能会导致安装或运行问题。

如果安装程序启动而没有警告，您可以按照向导进行操作，直到屏幕显示安装成功完成并有“完成”按钮。点击“完成”按钮，然后运行 NetBeans。您现在可以开始使用 NetBeans IDE 编写 Java 代码。阅读完第四章《您的第一个 Java 项目》后，尝试在 NetBeans 中创建一个类似的项目，并看看与 IntelliJ IDEA 相比您是否喜欢它。

# 摘要

现在您知道开发环境是什么，以及您在计算机上需要哪些工具来开始编码。您已经学会了如何配置 IDE 以及它在幕后为您做了什么。您现在知道在选择 IDE 时要寻找什么。

在下一章中，您将开始使用它来编写和编译代码并进行测试。您将学习什么是 Java 项目，如何创建和配置一个项目，以及如何在不离开 IDE 的情况下执行代码和测试代码，这意味着您将成为一名 Java 程序员。


# 第四章：您的第一个 Java 项目

在前几章中，您学到了关于 Java 的许多东西，包括其基本方面和主要工具。现在，我们将应用所学知识来完成并迈出迈向真实程序的第一步——创建一个 Java 项目。我们将向您展示如何编写应用程序代码，如何测试它以及如何执行主代码及其测试。

在本章中，我们将涵盖以下主题：

+   什么是项目？

+   创建项目

+   编写和构建应用程序代码

+   执行和单元测试应用程序

+   练习：JUnit `@Before`和`@After`注解

# 什么是项目？

让我们从项目的定义和起源开始。

# 项目的定义和起源

根据牛津词典的英语，术语*项目*是*一个个人或协作的企业，经过精心计划以实现特定目标*。这个术语被 IDE 的设计者采用，意思是组成应用程序的文件集合。这就是为什么项目这个术语经常被用作应用程序的同义词。

# 与项目相关的术语

构成项目的文件存储在文件系统的目录中。最顶层的目录称为*项目根目录*，项目的其余目录形成其下的树。这就是为什么项目也可以被看作是包含应用程序和其测试的所有`.java`文件和其他文件的目录树。非 Java 文件通常称为`资源`，并存储在同名目录中。

程序员还使用*源代码树*、*源代码*或*源*这些术语作为项目的同义词。

当一个项目使用另一个项目的类时，它们被打包成一个`.jar`文件，通常构成一个*库*（一个或多个独立类的集合）或*框架*（一组旨在共同支持某些功能的类）。库和框架之间的区别不影响您的项目如何访问其类，因此从现在开始，我们将称项目使用的所有第三方`.jar`文件为库。在*Maven 项目配置*部分，我们将向您展示如何访问这些库，如果您的代码需要它们。

# 项目的生命周期

Java 项目的生命周期包括以下阶段（步骤、阶段）：

+   可行性：是否继续进行项目的决定

+   需求收集和高级设计

+   类级设计：*开发阶段的第一阶段*

+   项目创建

+   编写应用程序代码及其单元测试

+   项目构建：代码编译

+   将源代码存储在远程存储库中并与其他程序员共享

+   项目打包：将`.class`文件和所有支持的非 Java 文件收集到一个`.jar`文件中，通常称为*项目构件*或*构件*

+   项目安装：将构件保存在二进制存储库（也称为*构件库*）中，从中可以检索并与其他程序员共享。这个阶段是开发阶段的最后一个阶段

+   在测试环境中部署和执行项目；将构件放入一个可以在类似于生产环境的条件下执行和测试的环境中，*这是测试阶段*

+   项目在生产环境中部署和执行：*这是生产（也称为维护）阶段的第一阶段*

+   项目增强和维护：修复缺陷并向应用程序添加新功能

+   在不再需要项目后关闭项目

在本书中，我们只涵盖了四个项目阶段：

+   项目设计（参见第八章，*面向对象设计（OOD）原则*）

+   项目创建

+   编写应用程序代码及其单元测试

+   项目构建，使用`javac`工具进行代码编译

我们将向您展示如何使用 IntelliJ IDEA 社区版执行所有这些阶段，但其他 IDE 也有类似的操作。

为了构建项目，IDE 使用 Java 编译器（`javac`工具）和依赖管理工具。后者设置了`javac`和`java`命令中`-classpath`选项的值。最流行的三种依赖管理工具是 Maven、Gradle 和 Ant。IntelliJ IDEA 具有内置的 Maven 功能，不需要安装外部的依赖管理工具。

# 创建项目

有几种在 IntelliJ IDEA（或其他任何 IDE）中创建项目的方法：

+   使用项目向导（请参阅“使用项目向导创建项目”部分）

+   从文件系统中读取现有源代码

+   从源代码控制系统中读取现有源代码

在本书中，我们只会介绍第一种选项——使用项目向导。其他两个选项只需一步即可完成，无需太多解释。在学会如何手动创建项目之后，您将了解在从现有源代码自动创建项目时发生了什么。

# 使用项目向导创建项目

当您启动 IntelliJ IDEA 时，除了第一次，它会显示您已创建的项目列表。否则，您只会看到以下屏幕：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/d9c1ca00-c44a-4df6-a758-41466300cb6b.png)

导入项目、打开项目和从版本控制中检出这三个选项允许您处理现有项目。我们在本书中不会使用它们。

单击“创建新项目”链接，这将带您到项目创建向导的第一个屏幕。在左上角选择 Java，然后单击右上角的“新建”按钮，并选择计算机上安装的 JDK 的位置。之后，单击右下角的“确定”按钮。

在下一个窗口中，不要选择任何内容，只需单击“下一步”按钮：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/61ba60bf-f3e7-4947-b186-8ce954d1be64.png)

您在上面的屏幕截图中看不到“下一步”按钮，因为它在实际屏幕的底部，其余部分是空白空间，我们决定不在这里显示。

在下一个屏幕中，在上方的字段中输入项目名称（通常是您的应用程序名称），如下所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/1421815e-24de-4e39-8cec-9bba0f4fd9f9.png)

对于我们的演示代码，我们选择了项目（应用程序）名称为`javapath`，意思是 Java 编程的路径。单击上一个屏幕底部的“完成”按钮，您应该会看到类似于这样的内容：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/25b5df1f-4238-4be3-8534-e105e42805bc.png)

如果您在左窗格中看不到项目结构，请单击“查看”（在最顶部菜单中），然后选择“工具窗口”，然后选择“项目”，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/e275f861-da88-4088-a94a-f662403384f7.png)

现在您应该能够看到项目结构：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/5ee3b110-40db-43bf-9b63-d774581d76ff.png)

前面的项目包括：

+   `.idea`目录保存了项目的 IntelliJ IDEA 设置

+   `src`目录，包括子目录：

+   `main`，将在其`java`子目录（对于`.java`文件）和`resources`子目录（对于其他类型的文件）中保存应用程序文件，

+   `test`，将在其`java`（对于`.java`文件）和`resources`子目录（对于其他类型的文件）中保存应用程序的测试。

+   `javapath.iml`文件，这是另一个带有项目配置的 IntelliJ IDEA 文件

+   `External Libraries`目录，其中包含项目使用的所有库

在前面的截图中，你还可以看到`pom.xml`文件。这个文件用于描述代码所需的其他库。我们将在“Maven 项目配置”部分解释如何使用它。IDE 会自动生成它，因为在上一章中，在配置 IDE 时，我们指示了我们希望在 IDE 默认设置中与 Maven 集成。如果你还没有这样做，现在你可以右键单击项目名称（在我们的例子中是`JavaPath`），然后选择“添加框架支持”：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/fd6fe0b9-d54c-462c-b45c-d40a1e40db73.png)

然后，你将看到一个屏幕，你可以选择 Maven：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/4ab050c6-5a58-44be-8f58-756afa545957.png)

点击“确定”按钮，`pom.xml`文件将被创建。如果`pom.xml`文件没有 Maven 符号，应该按照前面的截图进行相同的步骤。添加 Maven 支持后的效果如下：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/9cf1a0bf-2b97-459f-9abe-2fb46d64cc2a.png)

触发`pom.xml`创建的另一种方法是响应右下角弹出的小窗口，其中包含各种建议，包括“添加为 Maven 项目”（这意味着代码依赖将由 Maven 管理）：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/ad8b0ad0-e94e-465c-b8d6-ed44567a3de9.png)

如果你错过了点击前面的链接，你仍然可以通过点击底部的链接来恢复建议：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/20cf88b3-d22d-42b9-bdf5-9096150d0c7c.png)

它将把建议带回到屏幕左下角：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/ddd94b75-8dde-4477-9f1f-d7d8b59d5888.png)

点击“添加为 Maven 项目”链接，`pom.xml`文件将被创建。

另一个有用的建议如下：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/cfc6d2f8-2f92-4f4c-8829-2911c6e9ca5a.png)

我们建议你点击“启用自动导入”链接。这将使 IDE 更好地支持你的项目，从而免除你手动执行某些操作。

如果以上方法都不适用于你，总是可以手动创建`pom.xml`文件。只需右键单击左窗格中的项目名称（`JavaPath`），选择“新建”，选择“文件”，然后输入文件名`pom.xml`，并点击“确定”按钮。

# Maven 项目配置

正如我们已经提到的，Maven 在编译和运行应用程序时帮助组成`javac`和`java`命令。它设置了`-classpath`选项的值。为了实现这一点，Maven 从`pom.xml`中读取项目所需的库列表。你有责任正确指定这些库。否则，Maven 将无法找到它们。

默认情况下，`pom.xml`文件位于项目根目录。这也是 IDE 运行`javac`命令并将`src/main/java`目录设置为类路径的目录，以便`javac`可以找到项目的源文件。它还将编译后的`.class`文件放在`target/classes`目录中，也放在根目录中，并在执行`java`命令时将此目录设置为类路径。

`pom.xml`的另一个功能是描述你的项目，以便它可以在你的计算机上唯一地被识别，甚至在互联网上的所有其他项目中也是如此。这就是我们现在要做的。让我们来看看`pom.xml`文件的内部：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/ede91dcf-6317-495e-a25a-978535dca95c.png)

你可以看到标识项目的三个 XML 标签：

+   `groupId`标识组织或开源社区内项目的组

+   `artifactId`标识组内的特定项目

+   `version`标识项目的版本

`groupId`标签中设置的值必须遵循包命名约定，所以现在，我们需要解释一下包是什么。包是 Java 应用程序的最大结构单元。每个包都将相关的 Java 类分组在一起。不同包中的两个不同类可以具有相同的名称。这就是为什么包也被称为命名空间。

包名必须是唯一的。它使我们能够正确地识别一个类，即使在类路径上列出了具有相同名称的其他包中存在一个类。包可以有几个子包。它们以类似于文件系统的目录结构的层次结构组织。包含所有其他包的包称为顶级包。它的名称被用作`pom.xml`文件的`groupId`标签值。

包命名约定要求顶级包名基于创建包的组织的互联网域名（倒序）。例如，如果域名是`oracle.com`，那么顶级包名必须是`com.oracle`，后面跟着（在一个点，`.`后）项目名称。或者，可以在倒置的域名和项目名称之间插入子域、部门名称或任何其他项目组。然后，其他子包跟随。

许多 JDK 标准库的包以`jdk`、`java`或`javax`开头，例如。但最佳实践是遵循 Java 规范第 6.1 节中定义的命名约定（[`docs.oracle.com/javase/specs`](https://docs.oracle.com/javase/specs)）。

选择一个独特的包名可能会有问题，当一个开源项目开始时，没有任何组织在脑海中。在这种情况下，程序员通常使用`org.github.<作者的名字>`或类似的东西。

在我们的项目中，我们有一个顶级的`com.packt.javapath`包。这样做有一点风险，因为另一个 Packt 的作者可能决定以相同的名称开始包。最好以`com.packt.nicksamoylov.javapath`开始我们的包。这样，作者的名字将解决可能的冲突，除非当然，另一个同名的作者开始为 Packt 写 Java 书。但是，我们决定冒险简洁。此外，我们认为我们在这本书中创建的代码不会被另一个项目使用。

因此，我们项目的`groupId`标签值将是`com.packt.javapath`。

`artifactId`标签值通常设置为项目名称。

`version`标签值包含项目版本。

`artifactId`和`version`用于在项目打包期间形成`.jar`文件名。例如，如果项目名称是`javapath`，版本是`1.0.0`，`.jar`文件名将是`javapath-1.0.0.jar`。

因此，我们的`pom.xml`现在看起来像这样：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/7101640e-2074-4130-82b3-97ef4adedbc0.png)

注意版本中的`-SNAPSHOT`后缀。它的用处只有当您要与其他程序员共享同一个项目时才会显现出来。但我们现在会解释它，这样您就能理解这个值的目的。当一个项目的构件（一个`.jar`文件）被创建时，它的名称将是`javapath-1.0-SNAPSHOT.jar`。文件名中的`-SNAPSHOT`表示它是一个正在进行的工作，代码正在从构建到构建中改变。这样，使用您的构件的其他 Maven 管理的项目将在`.jar`文件上的时间戳更改时每次下载它。

当代码稳定下来，更改变得罕见时，您可以将版本值设置为`1.0.0`，并且只有在代码更改并发布新项目版本时才更改它——例如`javapath-1.0.0.jar`、`javapath-1.0.1.jar`或`javapath-1.2.0.jar`。然后，使用`javapath`的其他项目不会自动下载新的文件版本。相反，另一个项目的程序员可以阅读每个新版本的发布说明，并决定是否使用它；新版本可能会引入不希望的更改，或者与他们的应用程序代码不兼容。如果他们决定需要一个新版本，他们会在项目的`pom.xml`文件中的`dependencies`标签中设置它，然后 Maven 会为他们下载它。

在我们的`pom.xml`文件中，还没有`dependencies`标签。但它可以放置在`<project>...</project>`标签的任何位置。让我们看一下`pom.xml`文件中依赖项的一些示例。我们现在可以将它们添加到项目中，因为无论如何我们以后都会使用它们：

```java
<dependencies>
  <dependency>
    <groupId>org.junit.jupiter</groupId>
    <artifactId>junit-jupiter-api</artifactId>
    <version>5.1.0-M1</version>
  </dependency>
  <dependency>
    <groupId>org.postgresql</groupId>
    <artifactId>postgresql</artifactId>
    <version>42.2.2</version>
  </dependency>
  <dependency>
    <groupId>org.apache.commons</groupId>
    <artifactId>commons-lang3</artifactId>
    <version>3.4</version>
  </dependency>
</dependencies>
```

第一个`org.junit.jupiter`依赖项是指`junit-jupiter-api-5.1.0-M1.jar`文件，其中包含编写测试所需的`.class`文件。我们将在下一节*编写应用程序代码和测试*中使用它。

第二个`org.postgresql`依赖项是指`postgresql-42.2.2.jar`文件，允许我们连接并使用 PostgreSQL 数据库。我们将在第十六章中使用此依赖项，*数据库编程*。

第三个依赖项是指`org.apache.commons`文件`commons-lang3-3.4.jar`，其中包含许多称为实用程序的小型、非常有用的方法，其中一些我们将大量使用，用于各种目的。

每个`.jar`文件都存储在互联网上的一个仓库中。默认情况下，Maven 将搜索其自己的中央仓库，位于[`repo1.maven.org/maven2`](http://repo1.maven.org/maven2)。您需要的绝大多数库都存储在那里。但在您需要指定其他仓库的罕见情况下，除了 Maven 中央仓库之外，您可以这样做：

```java
<repositories>
  <repository>
    <id>my-repo1</id>
    <name>your custom repo</name>
    <url>http://jarsm2.dyndns.dk</url>
  </repository>
  <repository>
    <id>my-repo2</id>
    <name>your custom repo</name>
    <url>http://jarsm2.dyndns.dk</url>
  </repository>
</repositories>
```

阅读 Maven 指南，了解有关 Maven 的更多详细信息[`maven.apache.org/guides`](http://maven.apache.org/guides)。

配置了`pom.xml`文件后，我们可以开始为我们的第一个应用程序编写代码。但在此之前，我们想提一下如何自定义 IntelliJ IDEA 的配置，以匹配您对 IDE 外观和其他功能的偏好。

# 随时更改 IDE 设置

您可以随时更改 IntelliJ IDEA 的设置和项目配置，以调整 IDE 的外观和行为，使其最适合您的风格。花点时间看看您可以在以下每个配置页面上设置什么。

要更改 IntelliJ IDEA 本身的配置：

+   在 Windows 上：点击顶部菜单上的文件，然后选择设置

+   在 Linux 和 macOS 上：点击顶部菜单上的 IntelliJ IDEA，然后选择首选项

您访问的配置屏幕将类似于以下内容：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/d957132c-f95f-4808-8c69-af37ff21b84c.png)

四处点击并查看您在这里可以做什么，以便了解 IDE 的可能性。

要更改特定于项目的设置，请单击文件，然后选择项目结构，并查看可用的设置和选项。请注意，可以通过右键单击项目名称（在左窗格中）然后选择打开模块设置来访问相同的屏幕。

在您建立了自己的风格并了解了自己的偏好之后，您可以将它们设置为 IDE 配置的默认设置，方法是通过文件|其他设置|默认设置。

默认项目结构也可以通过文件|其他设置|默认项目结构进行设置。这些默认设置将在每次创建新项目时自动应用。

有了这些，我们可以开始编写我们的应用程序代码了。

# 编写应用程序代码

这是程序员职业中最有趣的活动。这也是本书的目的——帮助你写出优秀的 Java 代码。

让我们从你的第一个应用程序的需求开始。它应该接受一个整数作为输入，将其乘以`2`，并以以下格式打印结果：`<输入数字> * 2 = <结果>`。

现在，让我们来设计一下。我们将创建`SimpleMath`类，其中包含`multiplyByTwo(int i)`方法，该方法将接受一个整数并返回结果。这个方法将被`MyApplication`类的`main()`方法调用。`main()`方法应该：

+   从用户那里接收一个输入数字

+   将输入值传递给`multiplyByTwo(int i)`方法

+   得到结果

+   以所需的格式在屏幕上打印出来

我们还将为`multiplyByTwo(int i)`方法创建测试，以确保我们编写的代码能够正确运行。

我们将首先创建包含我们的`.java`文件的目录。目录路径必须与每个类的包名匹配。我们已经讨论过包，并将顶级包名设置为`groupId`值。现在，我们将描述如何在`.java`文件中声明它。

# Java 包声明

包声明是任何 Java 类的第一行。它以`package`关键字开头，后面跟着包名。`javac`和`java`工具使用完全限定的类名在类路径上搜索类，这是一个在类名前附加包名的类名。例如，如果我们将`MyApplication`类放在`com.packt.javapath.ch04demo`包中，那么这个类的完全限定名将是`com.packt.javapath.ch04demo.MyApplication`。你可以猜到，`ch04demo`代表第四章的*演示代码*。这样，我们可以在不同的章节中使用相同的类名，它们不会冲突。这就是包名用于唯一标识类在类路径上的目的。

包的另一个功能是定义`.java`文件的位置，相对于`src\main\java`目录（适用于 Windows）或`src/main/java`目录（适用于 Linux）。包名必须与属于该包的文件的路径匹配：

```java
src\main\java\com\packt\javapath\ch04demo\MyApplication.java (for Windows)

src/main/java/com/packt/javapath/ch04demo/MyApplication.java (for Linux) 
```

包名与文件位置之间的任何不匹配都会触发编译错误。当使用 IDE 向包名右键单击后使用 IDE 向导创建新类时，IDE 会自动将正确的包声明添加为`.java`文件的第一行。但是，如果不使用 IDE 创建新的源文件，那么就需要自己负责匹配包名和`.java`文件的位置。

如果`.java`文件位于`src\main\java`目录（适用于 Windows）或`src/main/java`目录（适用于 Linux）中，则可以不声明包名。Java 规范将这样的包称为默认包。使用默认包只适用于小型或临时应用程序，因为随着类的数量增加，一百甚至一千个文件的平面列表将变得难以管理。此外，如果你编写的代码要被其他项目使用，那么这些其他项目将无法在没有包名的情况下引用你的类。在第七章《包和可访问性（可见性）》中，我们将更多地讨论这个问题。

在编译过程中，`.class`文件的目录树是由`javac`工具创建的，并且它反映了`.java`文件的目录结构。Maven 在项目根目录中创建了一个`target`目录，并在其中创建了一个`classes`子目录。然后，Maven 在`javac`命令中使用`-d`选项指定这个子目录作为生成文件的输出位置：

```java
//For Windows:
javac -classpath src\main\java -d target\classes 
 com.packt.javapath.ch04demo.MyApplication.java

//For Linux:
javac -classpath src/main/java -d target/classes 
 com.packt.javapath.ch04demo.MyApplication.java
```

在执行过程中，`.class`文件的位置设置在类路径上：

```java
//For Windows:
java -classpath target\classes com.packt.javapath.ch04demo.MyApplication

//For Linux:
java -classpath target/classes com.packt.javapath.ch04demo.MyApplication
```

有了包声明、其功能以及与目录结构的关系的知识，让我们创建我们的第一个包。

# 创建一个包

我们假设您已经按照“使用项目向导创建项目”的步骤创建了项目。如果您已经关闭了 IDE，请重新启动它，并通过在“最近项目”列表中选择`JavaPath`来打开创建的项目。

项目打开后，在左窗格中点击`src`文件夹，然后点击`main`文件夹。现在应该看到`java`文件夹：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/7f2a3362-e71f-4b18-b321-994848eff558.png)

右键单击`java`文件夹，选择“新建”菜单项，然后选择“包”菜单项：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/12d9f974-ec53-408e-a288-edc7b25dca93.png)

在弹出窗口中输入`com`：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/6bf9e2d4-2ca4-4d79-8073-f976cff359bb.png)

点击“确定”按钮。将创建`com`文件夹。

在左窗格中右键单击它，选择“新建”菜单项，然后选择“包”菜单项，在弹出窗口中输入`packt`：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/8bc316e8-3f10-4edf-9fff-2b5784b465cf.png)

重复这个过程，在`packt`文件夹下创建`javapath`文件夹，然后在`javapath`文件夹下创建`ch04demo`文件夹。在`com.packt.javapath.ch04demo`包就位后，我们可以创建它的成员——`MyApplication`类。

# 创建`MyApplication`类

要创建一个类，在左窗格中右键单击`com.packt.javapath.che04demo`包，选择“新建”菜单项，然后选择“Java 类”菜单项，在弹出窗口中输入`MyApplication`：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/12cce37d-6bdc-4d61-a9a2-3a990766a9a5.png)

点击“确定”按钮，类将被创建：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/c6371bf2-f8d5-44dc-a830-12f4c166a782.png)

右窗格中`MyApplication`类的名称变得模糊。这就是 IntelliJ IDEA 指示它尚未被使用的方式。

# 构建应用程序

在幕后，IDE 会在每次更改代码时编译您正在编写的代码。例如，尝试删除右窗格中类名称中的第一个字母`M`。IDE 会立即警告您有语法错误：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/df804b66-9c28-487f-84ec-a9d3ca2b67d1.png)

如果将鼠标移到前面截图中类声明的红色气泡或任何下划线类声明的红线上，您将看到“类'yApplication'是公共的，应该在名为'yApplication.java'的文件中声明”的消息。您可能还记得我们在第二章中谈到过这一点，*Java 语言基础知识*。

每个`.java`文件只包含一个`public`类。文件名必须与公共类名匹配。

因为 IDE 在每次更改后都会编译代码，所以在少量`.java`文件的情况下，显式构建项目是不必要的。但是当应用程序的大小增加时，您可能不会注意到出现问题。

这就是为什么请求 IDE 定期重新编译（或者换句话说，构建）应用程序的所有`.java`文件是一个好的做法，方法是点击顶部菜单中的“构建”，然后选择“重建项目”菜单项：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/a1f2f3c7-e8e0-463c-9ef4-366adf39fdc4.png)

您可能已经注意到其他相关的菜单项：Build Project 和 Build Module 'javapath'。模块是一种跨包捆绑类的方式。但是使用模块超出了本书的范围。Build Project 仅重新编译已更改的类以及使用更改的类的类。只有在构建时间显着时才有意义。另一方面，Rebuild Projects 重新编译所有`.java`文件，无论它们是否已更改，我们建议您始终使用它。这样，您可以确保每个类都已重新构建，并且没有遗漏依赖项。

单击 Rebuild Projects 后，您将在左窗格中看到一个新的`target`文件夹：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/eace96bb-ca9f-452d-b0fb-c24037973683.png)

这是 Maven（和 IntelliJ IDEA 使用的内置 Maven）存储`.class`文件的地方。您可能已经注意到`javac`工具为包名的每个部分创建一个文件夹。这样，编译类的树完全反映了源类的树。

现在，在继续编写代码之前，我们将执行一个技巧，使您的源树看起来更简单。

# 隐藏一些文件和目录

如果您不希望看到特定于 IDE 的文件（例如`.iml`文件）或临时文件和目录（例如`target`文件夹），可以配置 IntelliJ IDEA 不显示它们。只需单击 File | Settings（在 Windows 上）或 IntelliJ IDEA | Preferences（在 Linux 和 macOS 上），然后单击左列中的 Editor 菜单项，然后单击 File Types。生成的屏幕将具有以下部分：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/182f27f3-539a-4f24-b9aa-4fc65604cd81.png)

在屏幕底部，您可以看到忽略文件和文件夹标签以及带有文件名模式的输入字段。在列表的末尾添加以下内容：`*.iml;.idea;target;`。然后，单击 OK 按钮。现在，您的项目结构应该如下所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/f17e89e1-be92-4df8-972a-f1c5e0d93a20.png)

它仅显示应用程序源文件和第三方库（在外部库下）。

# 创建 SimpleMath 类

现在让我们创建另一个包`com.packt.javapath.math`，并在其中创建`SimpleMath`类。这样做的原因是，将来我们计划在此包中有几个类似的与数学相关的类，以及其他与数学无关的类。

在左窗格中，右键单击`com.packt.javapath.ch04demo`包，选择 New，然后单击 Package。在提供的输入字段中键入`math`，然后单击 OK 按钮。

右键单击`math`包名称，选择 New，然后单击 Java Class，在提供的输入字段中键入`SimpleMath`，然后单击 OK 按钮。

你应该创建一个新的`SimpleMath`类，看起来像这样：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/45202168-ee23-40e7-9910-2122a88846bd.png)

# 创建方法

首先，我们将以下方法添加到`SimpleMath`类中：

```java
public int multiplyByTwo(int i){
  return i * 2;
}
```

现在，我们可以将使用上述方法的代码添加到`MyApplication`类中：

```java
public static void main(String[] args) {
  int i = Integer.parseInt(args[0]);
  SimpleMath simpleMath = new SimpleMath();
  int result = simpleMath.multiplyByTwo(i);
  System.out.println(i + " * 2 = " + result);
}
```

上述代码非常简单。应用程序从`String[] args`输入数组的第一个元素接收一个整数作为输入参数。请注意，Java 数组中的第一个元素的索引是 0，而不是 1。参数作为字符串传递，并且必须通过使用标准 Java 库中`java.lang.Integer`类的`parseInt()`静态方法转换（解析）为`int`类型。我们将在第五章中讨论 Java 类型，*Java 语言元素和类型*。

然后，创建了一个`SimpleMath`类的对象，并调用了`multiplyByTwo()`方法。返回的结果存储在`int`类型的`result`变量中，然后使用标准 Java 库的`java.lang.System`类以所需的格式打印出来。这个类有一个`out`静态属性，它持有一个对`java.io.PrintStream`类对象的引用。而`PrintStream`类又有`println()`方法，它将结果打印到屏幕上。

# 执行和单元测试应用程序

有几种方法可以执行我们的新应用程序。在*构建应用程序*部分，我们看到所有编译后的类都存储在`target`文件夹中。这意味着我们可以使用`java`工具并列出带有`-classpath`选项的`target`文件夹来执行应用程序。

要做到这一点，打开命令提示符或终端窗口，然后转到我们新项目的根目录。如果不确定在哪里，可以查看 IntelliJ IDEA 窗口顶部显示的完整路径。一旦进入项目根目录（即存放`pom.xml`文件的文件夹），运行以下命令：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/dad25f60-410a-4c64-9847-d83b2932c7f5.png)

在上述截图中，可以看到`-classpath`选项（我们使用了缩写版本`-cp`）列出了所有编译后的类所在的目录。之后，我们输入了`com.packt.javapath.ch04demo.MyApplication`主类的名称，因为我们必须告诉`java`工具哪个类是应用程序的入口点，并包含`main()`方法。然后，我们输入`2`作为主类的输入参数。你可能还记得，`main()`方法期望它是一个整数。

当我们运行该命令时，结果以预期格式显示输出：`2 * 2 = 4`。

或者，我们可以将所有编译后的类收集到一个`myapp.jar`文件中，并使用类似的`java`命令在类路径上列出`myapp.jar`文件来运行：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/68445744-4225-4d7a-a13a-b29e1f44445e.png)

在上述截图中，可以看到我们首先进入了`target`文件夹及其`classes`子文件夹，然后使用`jar`命令将其内容（所有编译后的类）收集到`myapp.jar`文件中。然后，我们使用`java`命令并列出了`myapp.jar`文件和`-classpath`选项。由于`myapp.jar`文件在当前目录中，我们不包括任何目录路径。`java`命令的结果与之前相同：`2 * 2 = 4`。

另一种进入项目根目录的方法是直接从 IDE 打开终端窗口。在 IntelliJ IDEA 中，可以通过单击左下角的 Terminal 链接来实现：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/b634572c-f39d-48af-9664-10a12682bd46.png)

然后，我们可以在 IDE 内部的终端窗口中输入所有上述命令。

但是，有一种更简单的方法可以在项目开发阶段从 IDE 中执行应用程序，而不必输入所有上述命令，这是推荐的方法。这是你的 IDE，记住吗？我们将在下一节中演示如何做到这一点。

# 使用 IDE 执行应用程序

为了能够从 IDE 执行应用程序，首次需要进行一些配置。在 IntelliJ IDEA 中，如果单击最顶部的菜单项，点击 Run，然后选择 Edit Configurations...，将会看到以下屏幕：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/57ee7aff-829c-47f4-a2c3-b3c1153ff62d.png)

单击左上角的加号（+）符号，并在新窗口中输入值：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/4e6536d9-cea0-4cea-a7d5-c70c4db164f3.png)

在名称字段中输入`MyApplication`（或其他任何名称）。

在主类字段中输入`com.packt.javapath.ch02demo.MyApplication`。

在程序参数字段中输入`2`（或其他任何数字）。

在右上角的单一实例复选框中选中。这将确保您的应用程序始终只运行一个实例。

在填写了所有描述的值之后，单击右下角的 OK 按钮。

现在，如果您打开`MyApplication`类，您将看到两个绿色箭头 - 一个在类级别，另一个在`main()`方法中：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/44313d36-8ea3-40bf-bd74-ce920ac2a46d.png)

单击其中任何一个绿色箭头，您的应用程序将被执行。

结果将显示在 IntelliJ IDEA 左下角。将打开一个名为 Run 的窗口，并且您将看到应用程序执行的结果。如果您在程序参数字段中输入了`2`，则结果应该是相同的：`2 * 2 = 4`。

# 创建单元测试

现在，让我们为`SimpleMath`类的`multiplyByTwo()`方法编写一个测试，因为我们希望确保`multiplyByTwo()`方法按预期工作。只要项目存在，这样的测试就很有用，因为您可以在每次更改代码时运行它们，并验证现有功能没有意外更改。

方法是应用程序中最小的可测试部分。这就是为什么这样的测试被称为单元测试。为您创建的每个方法编写单元测试是一个好主意（例如，除了诸如 getter 和 setter 之类的微不足道的方法）。

我们将使用一个名为 JUnit 的流行测试框架。有几个版本。在撰写本文时，版本 5 是最新版本，但版本 3 和 4 仍在积极使用。我们将使用版本 5。它需要 Java 8 或更高版本，并且我们假设您的计算机上至少安装了 Java 9。

如我们已经提到的，在使用第三方库或框架时，您需要在`pom.xml`文件中将其指定为依赖项。一旦您这样做，Maven 工具（或 IDE 的内置 Maven 功能）将在 Maven 在线存储库中查找相应的`.jar`文件。它将下载该`.jar`文件到您计算机主目录中自动创建的`.m2`文件夹中的本地 Maven 存储库。之后，您的项目可以随时访问并使用它。

我们已经在*Maven 项目配置*部分的`pom.xml`中设置了对 JUnit 5 的依赖。但是，假设我们还没有这样做，以便向您展示程序员通常如何做。

首先，您需要进行一些研究并决定您需要哪个框架或库。例如，通过搜索互联网，您可能已经阅读了 JUnit 5 文档（[`junit.org/junit5`](http://junit.org/junit5)）并发现您需要在`junit-jupiter-api`上设置 Maven 依赖项。有了这个，您可以再次搜索互联网，这次搜索`maven dependency junit-jupiter-api`，或者只搜索`maven dependency junit 5`。您搜索结果中的第一个链接很可能会将您带到以下页面：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/25e23750-6422-4a3e-adfc-297ea4cd2aff.png)

选择您喜欢的任何版本（我们选择了最新版本 5.1.0-M1）并单击它。

将打开一个新页面，告诉您如何在`pom.xml`中设置依赖项：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/3c580196-a134-452e-a96d-b7e352f511d9.png)

或者，您可以转到 Maven 存储库网站（[`mvnrepository.com`](https://mvnrepository.com)）并在其搜索窗口中键入`junit-jupiter-api`。然后，单击提供的链接之一，您将看到相同的页面。

如果您在阅读第三章 *您的开发环境设置*时没有添加`junit-jupiter-api`依赖项，现在可以通过将提供的依赖项复制到`pom.xml`文件中的`<dependencies></dependencies>`标签内来添加它：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/1a19f2bc-aebf-42ee-aefd-43d8f4c3e9c7.png)

现在，您可以使用 JUnit 框架创建单元测试。

在 IntelliJ IDEA 中，`junit-jupiter-api-5.1.0-M1.jar`文件也列在左侧窗格的`External Libraries`文件夹中。如果您打开列表，您将看到还有两个其他库，这些库没有在`pom.xml`文件中指定：`junit-latform-commons-1.0.0-M1.jar`和`opentest4j-1.0.0.jar`。它们存在是因为`junit-jupiter-api-5.1.0-M1.jar`依赖于它们。这就是 Maven 的工作原理-它发现所有依赖项并下载所有必要的库。

现在，我们可以为`SimpleMath`类创建一个测试。我们将使用 IntelliJ IDEA 来完成。打开`SimpleMath`类，右键单击类名，然后选择 Go To，点击 Test：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/2432ae77-367c-4583-8688-33a3955ee126.png)

您将会看到一个小弹出窗口：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/a8498649-3985-495c-aee9-94585cd58e4d.png)

单击 Create New Test...，然后以下窗口将允许您配置测试：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/b349dccc-04c1-4b39-9c78-af90cfef7b8d.png)

在 IntelliJ IDEA 中有对 JUnit 5 的内置支持。在前面的屏幕中，选择 JUnit5 作为测试库，并选中`multiplyByTwo()`方法的复选框。然后，单击右下角的 OK 按钮。测试将被创建：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/1e3526b4-c252-4073-ad78-73a72c9c099c.png)

请注意，在左侧窗格的`test/java`文件夹下，创建了一个与`SimpleMath`类的包结构完全匹配的包结构。在右侧窗格中，您可以看到`SimpleMathTest`测试类，其中包含一个针对`multiplyByTwo()`方法的测试（目前为空）。测试方法可以有任何名称，但必须在其前面加上`@Test`，这被称为注解。它告诉测试框架这是其中一个测试。

让我们实现测试。例如，我们可以这样做：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/3640513c-02b3-481e-9869-09c7297fcbc5.png)

正如你所看到的，我们已经创建了`SimpleMath`类的对象，并调用了带有参数`2`的`multiplyByTwo()`方法。我们知道正确的结果应该是`4`，我们使用来自 JUnit 框架的`assertEquals()`方法来检查结果。我们还在类和测试方法中添加了`@DisplayName`注解。您很快就会看到这个注解的作用。

现在让我们修改`SimpleMath`类中的`mutliplyByTwo()`方法：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/a6427a90-f3ca-4f1e-abb6-e8ea76953674.png)

我们不仅仅是乘以`2`，我们还将`1`添加到结果中，所以我们的测试将失败。首先在错误的代码上运行测试是一个好习惯，这样我们可以确保我们的测试能够捕捉到这样的错误。

# 执行单元测试

现在，让我们回到`SimpleMathTest`类，并通过单击绿色箭头之一来运行它。类级别上的绿色箭头运行所有测试方法，而方法级别上的绿色箭头只运行该测试方法。因为我们目前只有一个测试方法，所以单击哪个箭头都无所谓。结果应该如下所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/168972fa-0fe1-42c0-9063-8a9127bbdef0.png)

这正是我们希望看到的：测试期望得到一个等于`4`的结果，但实际得到了`5`。这让我们对我们的测试是否正确工作有了一定的信心。

请注意，在左侧窗格中，我们可以看到来自`@DisplayName`注解的显示名称-这就是这些注解的目的。

还要单击右侧窗格中的每个蓝色链接，以查看它们的作用。第一个链接提供有关预期和实际结果的更详细信息。第二个链接将带您到测试的行，其中包含失败测试的断言，这样您就可以看到确切的上下文并纠正错误。

现在，您可以再次转到`SimpleMath`类，并删除我们添加的`1`。然后，单击左上角的绿色三角形（参见前面的屏幕截图）。这意味着*重新运行测试*。结果应该如下所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/8851a540-9056-4835-a8e3-45437fcb18d8.png)

顺便说一下，您可能已经注意到我们的屏幕截图和项目路径已经略有改变。这是因为我们现在是从在 macOS 上运行的 IntelliJ IDEA 中获取屏幕截图，所以我们可以覆盖 Windows 和 macOS。正如您所看到的，IntelliJ IDEA 屏幕在 Windows 和 macOS 系统上的外观基本相同。

# 多少单元测试足够？

这总是任何程序员在编写新方法或修改旧方法时都会考虑的问题-有多少单元测试足以确保应用程序得到彻底测试，以及应该是什么样的测试？通常，仅为应用程序的每个方法编写一个测试是不够的。通常需要测试许多功能方面。但是，每个测试方法应该只测试一个方面，这样更容易编写和理解。

例如，对于我们简单的`multiplyByTwo()`方法，我们可以添加另一个测试（我们将称之为`multiplyByTwoRandom()`），它会将随机整数作为输入传递给方法，并重复一百次。或者，我们可以考虑一些极端的数字，比如`0`和负数，并查看我们的方法如何处理它们（例如，我们可以称它们为`multiplyByZero()`和`multiplyByNegative()`）。另一个测试是使用一个非常大的数字-比 Java 允许的最大整数的一半还要大（我们将在第五章中讨论这样的限制，*Java 语言元素和类型*）。我们还可以考虑在`multiplyByTwo()`方法中添加对传入参数值的检查，并在传入参数大于最大整数的一半时抛出异常。我们将在第十章中讨论异常，*控制流语句*。

您可以看到最简单的方法的单元测试数量增长得多快。想象一下，对于一个比我们简单代码做得多得多的方法，可以编写多少单元测试。

我们也不希望写太多的单元测试，因为我们需要在项目的整个生命周期中维护所有这些代码。过去，不止一次，一个大项目因为编写了太多复杂的单元测试而变得维护成本过高，而这些测试几乎没有增加任何价值。这就是为什么通常在项目代码稳定并在生产中运行一段时间后，如果有理由认为它有太多的单元测试，团队会重新审视它们，并确保没有无用的测试、重复的测试或其他明显的问题。

编写良好的单元测试，可以快速工作并彻底测试代码，这是一种随着经验而来的技能。在本书中，我们将利用一切机会与您分享单元测试的最佳实践，以便在本书结束时，您将在这个非常重要的专业 Java 编程领域中有一些经验。

# 练习-JUnit @Before 和@After 注释

阅读 JUnit 用户指南（[`junit.org/junit5/docs/current/user-guide`](https://junit.org/junit5/docs/current/user-guide)）和类`SampleMathTest`两个新方法：

+   只有在任何测试方法运行之前执行一次的方法

+   只有在所有测试方法运行后执行一次的方法

我们没有讨论它，所以您需要进行一些研究。

# 答案

对于 JUnit 5，可以用于此目的的注释是`@BeforeAll`和`@AfterAll`。这是演示代码：

```java
public class DemoTest {
  @BeforeAll
  static void beforeAll(){
    System.out.println("beforeAll is executed");
  }
  @AfterAll
  static void afterAll(){
    System.out.println("afterAll is executed");
  }
  @Test
  void test1(){
    System.out.println("test1 is executed");
  }
  @Test
  void test2(){
    System.out.println("test2 is executed");
  }
}
```

如果您运行它，输出将是：

```java
beforeAll is executed
test1 is executed
test2 is executed
afterAll is executed 
```

# 总结

在本章中，您了解了 Java 项目以及如何设置和使用它们来编写应用程序代码和单元测试。您还学会了如何构建和执行应用程序代码和单元测试。基本上，这就是 Java 程序员大部分时间所做的事情。在本书的其余部分，您将更详细地了解 Java 语言、标准库以及第三方库和框架。

在下一章中，我们将深入探讨 Java 语言的元素和类型，包括`int`、`String`和`arrays`。您还将了解标识符是什么，以及如何将其用作变量的名称，以及有关 Java 保留关键字和注释的信息。
