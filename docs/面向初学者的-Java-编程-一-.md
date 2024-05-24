# 面向初学者的 Java 编程（一）

> 原文：[`zh.annas-archive.org/md5/4A5A4EA9FEFE1871F4FCEB6D5DD89CD1`](https://zh.annas-archive.org/md5/4A5A4EA9FEFE1871F4FCEB6D5DD89CD1)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

无论您是第一次接触高级面向对象编程语言，比如 Java，还是已经有一段时间的编程经验，只是想要将 Java 添加到您的技能范围，或者您从未接触过一行代码，本书都旨在满足您的需求。我们将快速前进，不会回避繁重的主题，但我们将从最基础的知识开始，边学习面向对象编程的概念。如果这本书能帮助您理解 Java 编程的重要性，以及如何在 NetBeans 中开始开发 Java 应用程序，我将认为它是成功的。如果 Java 成为您最喜爱的编程语言，我同样会感到高兴！

# 您需要为本书做些什么

对于本书，您需要**Java 开发工具包**（**JDK**）和 NetBeans

# 本书适合谁

本书适用于任何想要开始学习 Java 语言的人，无论您是学生、业余学习者，还是现有程序员想要增加新的语言技能。不需要 Java 或编程的任何先前经验。

# 约定

在本书中，您将找到一些区分不同信息类型的文本样式。以下是一些这些样式的示例及其含义的解释。

文本中的代码单词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 用户名显示如下："`Source Packages`文件夹是我们将编写代码的地方。"

代码块设置如下：

```java
public class HelloWorld {
    public static void main(String[] args) {
        System.out.println("Hello World!");
    }
}
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目以粗体显示：

```java
public class HelloWorld {
    public static void main(String[] args) {
        System.out.println("Hello World!");
    }
}
```

任何命令行输入或输出都以以下方式编写：

```java
java -jar WritingToFiles.jar
```

新术语和重要单词以粗体显示。您在屏幕上看到的单词，例如菜单或对话框中的单词，会以这种方式出现在文本中：“选择 Java SE 列下方的下载按钮。”

警告或重要提示将显示在这样的框中。

提示和技巧会以这种方式出现。

# 读者反馈

我们始终欢迎读者的反馈。请告诉我们您对本书的看法，您喜欢或不喜欢的地方。读者的反馈对我们开发您真正受益的书籍至关重要。

要向我们发送一般反馈，只需发送电子邮件至`feedback@packtpub.com`，并在主题中提及书名。

如果您在某个专题上有专业知识，并且有兴趣编写或为书籍做出贡献，请参阅我们的作者指南[www.packtpub.com/authors](http://www.packtpub.com/authors)。

# 客户支持

现在您是 Packt 书籍的自豪所有者，我们有一些事情可以帮助您充分利用您的购买。

# 下载示例代码

您可以从[`www.packtpub.com`](http://www.packtpub.com)的帐户中下载您购买的所有 Packt Publishing 书籍的示例代码文件。如果您在其他地方购买了本书，您可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)并注册，文件将直接通过电子邮件发送给您。您可以按照以下步骤下载代码文件：

1.  使用您的电子邮件地址和密码登录或注册到我们的网站。

1.  将鼠标指针悬停在顶部的“支持”选项卡上。

1.  单击“代码下载和勘误”。

1.  在搜索框中输入书名。

1.  选择您要下载代码文件的书籍。

1.  从下拉菜单中选择您购买本书的地方。

1.  单击“代码下载”。

文件下载完成后，请确保您使用最新版本的解压缩软件解压文件夹：

+   Windows 系统使用 WinRAR / 7-Zip

+   Mac 系统使用 Zipeg / iZip / UnRarX

+   Linux 系统使用 7-Zip / PeaZip

本书的代码包也托管在 GitHub 上，链接为[`github.com/PacktPublishing/Java-Programming-for-Beginners`](https://github.com/PacktPublishing/Java-Programming-for-Beginners)。我们还有其他丰富图书和视频代码包，可在[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)找到。快去看看吧！

# 下载本书的彩色图片

我们还为您提供了一个 PDF 文件，其中包含本书中使用的截图/图表的彩色图片。这些彩色图片将帮助您更好地理解输出的变化。您可以从[`www.packtpub.com/sites/default/files/downloads/JavaProgrammingforBeginners_ColorImages.pdf`](https://www.packtpub.com/sites/default/files/downloads/JavaProgrammingforBeginners_ColorImages.pdf)下载此文件。

# 勘误

尽管我们已经尽最大努力确保内容的准确性，但错误还是会发生。如果您在我们的书中发现错误——可能是文字或代码上的错误，我们将不胜感激，如果您能向我们报告。通过这样做，您可以帮助其他读者避免挫折，并帮助我们改进本书的后续版本。如果您发现任何勘误，请访问[`www.packtpub.com/submit-errata`](http://www.packtpub.com/submit-errata)报告，选择您的书，点击“勘误提交表”链接，并输入您的勘误详情。一旦您的勘误经过验证，您的提交将被接受，并且勘误将被上传到我们的网站或添加到该书标题的勘误部分的任何现有勘误列表中。

要查看先前提交的勘误，请访问[`www.packtpub.com/books/content/support`](https://www.packtpub.com/books/content/support)，并在搜索框中输入书名。所需信息将出现在“勘误”部分下。

# 盗版

互联网上的版权盗版是所有媒体的持续问题。在 Packt，我们非常重视版权和许可的保护。如果您在互联网上发现我们作品的任何非法副本，请立即向我们提供位置地址或网站名称，以便我们采取补救措施。

请通过`copyright@packtpub.com`与我们联系，并附上涉嫌盗版材料的链接。

感谢您帮助保护我们的作者，以及我们为您提供有价值内容的能力。

# 问题

如果您在阅读本书的过程中遇到任何问题，可以通过`questions@packtpub.com`与我们联系，我们将尽力解决。


# 第一章：开始使用 Java

无论这是你第一次涉足高级面向对象的编程语言，比如 Java，还是你已经编程了一段时间，只是想要把 Java 加入你的技能库，甚至你一生中从未接触过一行代码，这本书都是为你设计的。我们将快速前进，不会回避繁重的主题；然而，我们将从最基础的知识开始，随着学习面向对象编程的概念。

在本章中，我们将了解 Java 是什么，以及它的特性。然后，我们将按步骤设置开发环境，使我们能够编写和执行 Java 程序。一旦我们完成这一步，我们将编写我们的第一个 Java 程序并运行它。最后，我们将看看当我们遇到错误时该怎么办。

具体来说，我们将涵盖以下主题：

+   什么是 Java

+   Java 的特性和应用

+   安装 JDK

+   安装 NetBeans IDE

+   编写`HelloWorld.java`

+   NetBeans 的错误检测能力

# 什么是 Java？

Java 是由 Sun Microsystems 于 1995 年开发的，但它经受住了时间的考验，至今仍然非常相关和广泛使用。那么 Java 究竟是什么？Java 是一种高级的、通用的面向对象的编程语言。

# Java 的特性

以下是 Java 的主要特性：

+   **高级和通用**：Java 不是为了完成一个非常特定的任务而创建的，而是允许我们在一个开放的环境中编写计算机可读的指令。因为每台计算机系统都有自己专门的编程语言并不现实，甚至不可取，所以绝大多数代码都是用高级通用语言编写的，比如 Java。

+   **面向对象**：Java 也是我们所说的面向对象的语言。虽然我们在本书的后面才会深入讨论对象和类的具体内容，但现在知道对象允许我们在程序中定义模块化实体，使它们更易于阅读和更易于创建大规模的软件项目。对面向对象概念的牢固掌握对于任何现代软件开发人员来说绝对是必不可少的。

+   **平台无关**：最后，Java 的设计初衷是成为一种一次编写，随处运行的语言。这意味着如果你和我都有安装了 Java 的系统，即使我们的系统通常不相同--例如，我用的是 Windows 系统，你用的是 Mac--我在我的机器上运行的 Java 程序，我给你，也会在你的机器上基本上相同地运行，而无需重新编译。

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/4da86a3a-9c84-462b-9f69-54ba5f0be5d6.png)**编译**Java 等编程语言是将我们编写的人类可读代码转换为解释的机器友好代码的行为。不幸的是，这通常对人类来说并不友好。为了做到这一点，我们使用一个称为编译器的程序，它接收我们的代码作为文本，并将其转换为机器代码。

传统上，我们必须为每个要运行的系统重新编译程序，因为所有系统对其机器代码的理解都不同。Java 通过将所有 Java 程序编译为一种称为字节码的相同类型的解释代码来避免这个问题。

字节码中的编译 Java 程序可以在安装了 Java 的任何系统上运行。这是因为当我们在您的系统上安装 Java 时，我们还会安装一个特定于该系统的 Java 虚拟机。这台机器的责任是将字节码转换为最终发送到该系统处理器的指令。

通过使系统负责进行最终转换，Java 创造了一种一次编写，随处运行的语言，我可以把一个 Java 程序交给你，你可以在你的计算机上运行它，而且相当肯定它会以与我的计算机上相同的方式运行。这种强大的跨平台支持水平使得 Java 成为软件开发世界的主要工具之一。

# Java 应用程序

在当今的现代时代，Java 被用于开发桌面应用程序、Web 服务器和客户端 Web 应用程序。它是 Android 操作系统的本地语言，可以在 Android 手机和平板电脑上运行。

Java 已被用于编写视频游戏，有时甚至被移植到没有传统操作系统的较小设备上。它仍然是当今技术世界中的一个重要角色，我期待与您一起学习它。

# 设置您的开发环境

在本节中，我们将编写我们的第一个 Java 程序，但在我们开始编码之前，我们需要设置一个友好的 Java 开发环境。

# 安装 JDK

要开始这个过程，让我们下载一个**Java 开发工具包**（**JDK**）或 Java SDK。这个工具包包含允许我们用 Java 代码做很多不同事情的库和可执行文件。最重要的是，安装了我们的 SDK 后，我们将能够编译 Java 代码，然后运行已完成的 Java 程序。

您可能已经在您的计算机上安装了 Java；但是，除非您明确地这样做，您可能还没有安装 Java SDK。普通用户在其计算机上安装的 Java 版本称为**Java 运行环境**（**JRE**）。这允许执行 Java 程序，并且没有安装 JRE 的环境中无法运行 Java 程序。但是 JRE 不包含任何真正的开发工具，而这是我们需要的。好消息是 Java JRE 和 Java SDK 可以和谐共存。Java JRE 实际上只是 SDK 的一个子集，因此如果我们只安装了即将下载的 Java 开发工具包，我们就没问题了。

如果您以前已经下载了 Java 开发工具包，当您实际安装这个工具包时，Java 会让您知道它已经安装了，您可以跳过本节的这部分。对于其他人，请查看如何下载开发工具包：

1.  首先，通过浏览器导航到[www.oracle.com/technetwork/java/javase/downloads/index.html](http://www.oracle.com/technetwork/java/javase/downloads/index.html)。

1.  我们将使用由 Oracle 维护的 Java SE 或标准版开发工具包。要获取此工具包，只需转到“下载”选项卡，并选择我们想要 JDK：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/72641905-2850-4214-8f5c-c067985f5cad.jpg)

向下滚动，查看许可协议，接受许可协议，然后下载适合您操作系统的 SDK 版本。对我来说，这是`jdk-8u144-windows-x64.exe`，列在最后。

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/4b7ef3dc-c4d3-40e9-8d33-e9c2fe8f5f9f.jpg)

1.  一旦您的下载完成，安装它就像我们安装其他程序一样。在适当的时候选择默认选项，并确保记下我们将安装开发工具包的目录。

# 安装 NetBeans IDE

安装了我们的 Java 开发工具包，我们从技术上讲已经拥有了开始编写 Java 程序所需的所有工具。但是，我们必须通过命令行来编译它们，这在不同的操作系统上可能看起来有些不同。

为了保持一切简单，让我们通过在**集成开发环境**（**IDE**）中编写 Java 代码来开始学习 Java。这是一个独立的软件程序，可以帮助我们编写、编译和运行 Java 程序。我们将使用 NetBeans IDE，这很棒，因为它是免费的、开源的，并且在 Windows、Mac 和 Linux 环境中运行几乎相同。

要获取这个 IDE，前往[netbeans.org/downloads/](http://netbeans.org/downloads/)。

您将看到以下页面：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/1810e6d5-c115-480a-8191-325b52efb867.jpg)

因为我们已经下载了 Java 标准版开发工具包，所以这里我们要下载的是 NetBeans 的 Java SE 版本。选择“Java SE”列下面的下载按钮。NetBeans 应该会自动开始下载，但如果没有，点击以下图片中显示的链接：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/2d7ea03e-84fe-4f11-8b41-986c231e2cbd.jpg)

再次，我们将像安装任何其他程序一样安装 NetBeans，在适当的时候选择默认选项。很可能，NetBeans 会在我们的计算机上找到 Java 开发工具包。如果没有，它会提示我们安装 Java 开发工具包的目录。

# 编写我们的第一个 Java 程序

希望您已经安装了 NetBeans，并且没有遇到任何麻烦就启动了它。NetBeans 会管理我们程序的文件结构，但首先，我们需要告诉 NetBeans 我们准备开始一个新项目。

# 创建一个新项目

要创建一个新项目，点击“文件”，然后“新建项目”，选择 Java 应用程序：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/39f2a966-b160-4b48-9cd9-6d2d2672f297.jpg)

我们需要给我们的项目一个独特的名称；让我们称这个为`HelloWorld`。然后，我们可以选择一个放置文件的位置。因为这是我们的第一个 Java 程序，我们可能应该尽可能地从零开始。所以让我们取消选中“创建主类”选项，这样 NetBeans 会给我们一个几乎是空白的项目。然后，点击“完成”：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/9f5fb921-1f16-4012-8079-519cd2cdc128.jpg)

NetBeans 会为我们设置一个文件系统。我们可以像在标准文件系统资源管理器中一样浏览这个文件系统：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/f73dd9ca-ed52-47db-8947-e074a386c7b9.jpg)

`Source Packages`文件是我们将编写代码的地方。您会注意到在`Libraries`文件下，JDK 是链接的，允许我们访问其许多库资源：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/99635cb8-9ab8-4159-a9ec-52005733d693.jpg)

# 创建一个 Java 类

创建一个新项目后，我们应该看到我在下面的图片中看到的项目、文件和服务选项卡。让我们看看文件选项卡。虽然项目选项卡有点抽象，但文件选项卡显示了我们的`HelloWorld`项目所在的文件系统中实际包含的内容：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/68a454d5-2af1-4a14-a35b-6e267abb65d9.jpg)

最重要的是，这里的`src`文件没有任何文件。这是因为我们的项目没有与之关联的源代码，所以现在它不会做任何事情。为了解决这个问题，右键单击`src`，选择“新建”，然后选择“Java 类...”：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/67f5a9bf-42b3-4967-b24d-67c2bf2305cc.jpg)

我们将把我们的 Java 类命名为`HelloWorld`，就像项目的名称一样，因为这是我们的主类，程序应该从这里输入和开始。其他的东西现在都应该正常工作，所以点击“完成”，NetBeans 会为我们创建`HelloWorld.java`。一个`.java`文件本质上是一个文本文件，但它应该只包含 Java 代码和注释：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/3f9dbcfe-e415-461c-a52c-40f2a7b49f74.jpg)

# 编写代码

当我们告诉 NetBeans 创建`HelloWorld.java`文件时，它已经为我们添加了一些代码，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/ac8bbad7-0e17-4d8f-b7d2-83c63b7b8da6.jpg)

# Java 注释

您会注意到这个文档的一些内容是完全可读的；这些就是我们所谓的注释。在 Java 文件中出现在`/*`和`*/`符号之间的任何文本都将被编译器完全忽略。我们可以在这里写任何我们想要的东西，它不会影响我们的程序如何运行。现在，让我们删除这些注释，这样我们就可以纯粹地处理我们的 Java 代码。

# main()函数

Java 代码，就像英语一样，是从上到下，从左到右阅读的。即使我们的项目包含许多文件和许多类，我们仍然需要从特定点开始阅读和执行我们的代码。我们将这个文件和类命名为`HelloWorld`，与我们的项目同名，因为我们希望它是特殊的，并包含`public static void main(String[] args)`方法，我们的代码执行将从这里开始。这是一个很啰嗦的行话。现在，只需将其输入并知道这是我们的 Java 程序开始阅读和执行的地方。`main()`函数的代码用大括号括起来：

```java
public class HelloWorld {
  public static void main(String[] args) {
  }
}
```

在 IDE 中工作的一个很棒的地方是它会突出显示哪些括号相互对应。括号允许我们将代码放在其他代码区域中。例如，我们的`main()`方法包含在`HelloWorld`类中，我们即将编写和执行的 Java 代码将包含在我们的`main()`方法中。目前什么都没有的第 4 行是我们的程序将开始阅读和执行 Java 代码的地方。

# 打印字符串

我们的`HelloWorld`程序的目标相当温和。当它运行时，我们希望它将一些文本打印到屏幕底部的输出框中。

当我们下载了 Java SDK 时，我们获得了一个有用函数库，其中一个函数将做到这一点。这就是`println()`，或者打印行，函数。当我们的 Java 代码执行这个函数时，它会立即执行，因为它是我们`main()`方法入口点中的第一个函数，Java 代码将向我们的输出框打印一些文字。函数名后面跟着开括号和闭括号。在这些括号内，我们放置函数完成任务所需的信息。`println()`方法当然需要知道我们想要它打印什么。在 Java 中，一行文本由两个双引号括起来，我们称之为**字符串**。让我们让我们的程序打印`"Hello World!"`：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/589ef021-05ae-461e-b617-32e2b7195fd3.jpg)

# Java 语法

你可能已经注意到 NetBeans 一直在对我们大声呼喊。左边有一个灯泡和一个红点，文本下面有一些红色的抖动，很像在一些文本编辑器中出现拼写错误。这确实是我们所做的。我们犯了一个语法错误。我们的 Java 代码显然有问题，NetBeans 知道这一点。

这里有两个问题。首先是我们的代码没有以分号结束。Java 不能很好地读取空格和换行，所以我们需要在每行功能代码的末尾加上分号，原因与摩尔斯电码操作员在每行末尾发送消息“停止”是一样的。让我们在我们的`println()`语句的末尾添加一个分号：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/da46f0cd-a6e7-464f-9435-7e91e687b862.jpg)

NetBeans 变得更加满意了；抖动减少了，但如前面的截图所示，仍然有些问题。

问题在于编程语言中的函数，就像计算机上的文件一样，有一个存在的位置。NetBeans 不确定在哪里找到我们尝试使用的`println()`函数。所以我们只需要告诉 NetBeans 这个函数存在的位置。`println()`函数的完整路径始于`System`包，其中包括`out`类，该类定义了`println()`函数。我们在 Java 中写成`System.out.println("Hello World!");`，如下面的代码块所示。

让我们去掉我在第 5、6 和 7 行创建的额外空格，不是因为它们会影响我们程序的运行方式，而是因为这样看起来不够好看。现在我们已经写好了我们的`HelloWorld`程序：

```java
public class HelloWorld { 
    public static void main(String[] args) { 
        System.out.println("Hello World!"); 
    } 
} 
```

# 执行我们的程序

那我们该怎么办呢？正如我们所知，我们的计算机无法直接阅读这段 Java 代码。它必须将其转换为计算机可读的语言。因此，执行这段代码变成了一个两步过程：

1.  **编译我们的程序**：首先，我们要求 NetBeans 构建我们的项目。这意味着项目中的所有代码将被编译并转换为计算机可读的代码，基本上是一个计算机可读的项目！[](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/6929328e-d378-484b-9a23-cbdc8ac4acdd.jpg)

当我们按下“构建项目”按钮时，屏幕底部的输出框中会显示一大堆文本--希望是友好的“构建成功”消息，然后是构建项目所花费的时间：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/75e076ab-f22a-4773-b8bc-041ac99bb5d5.jpg)

1.  **运行我们的程序**：一旦我们构建了我们的项目，我们可以按下“运行项目”按钮来执行我们的代码和我们的`println`语句：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/f8283a03-07e0-458e-ae8a-bcd5237204a0.jpg)

然后 NetBeans 会给我们以下弹出框：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/1af1eb0b-246e-4bf6-8af2-ee056cea0708.jpg)

当我们在 IDE 之外执行程序时，我们通过启动其中一个可执行文件来执行它。因为我们现在处于集成开发环境中，NetBeans 想要确定我们希望将我们的哪个文件作为程序的入口点。我们只有一个选择，因为我们只写了一个 Java 类。所以让我们向 NetBeans 确认`HelloWorld`是我们的主类，因此`HelloWorld`程序中的`main()`函数将是我们开始执行 Java 程序的地方。然后，当我们点击“确定”时，输出框将告诉我们程序已经开始运行，然后我们的程序会像我们预期的那样在输出框中打印`"Hello World!"`：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/ca119785-2546-49c2-b977-285243c36e64.jpg)

就是这样！现在我们是 Java 程序员了。当然，还有很多要学习的。事实上，Java 中的`HelloWorld`可能是你写过的最简单的程序。Java 非常强大，事实上我们在写第一个程序时根本无法希望理解它的所有复杂性。真正的好消息是，从这一点开始，我们需要更少的信仰飞跃，我们可以开始逐步建立对 Java 的非常扎实的理解。

# 如何解释 NetBeans 检测到的错误？

随着我们编写越来越复杂的 Java 程序，我们不可避免地会犯一些错误。其中一些错误将是重大的逻辑错误或者是我们的误解，我们可能需要进一步教育自己才能解决。但是，特别是在开始编程时，我们会犯很多小错误，只要我们知道在哪里找，这些错误就非常容易修复。

幸运的是，Java 编译器设计成在遇到错误时向我们指出错误。为了看到这一点，让我们简单地使我们的`HelloWorld`程序不正确，方法是删除`println`语句末尾的分号：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/210c5d27-c106-4e69-8461-037b5c2e75bf.jpg)

现在 NetBeans 会在错误的行上显示红色波浪线，以让我们知道它相当确定有些地方出错了，但是我们仍然可以让编译器试一试。如果我们尝试构建这个项目，我们将不会得到通常的`编译成功`消息；相反，我们会得到一个错误消息：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/1e72afb6-0747-4961-98aa-e65fa60a5331.jpg)

这个错误是“需要';'”，这是一个非常方便和自解释的错误消息。同样重要的是这条消息后面的数字，是`4`。这让我们知道编译器在哪一行遇到了这个错误。在 NetBeans 中，如果我们点击错误消息，IDE 将会突出显示该行代码：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/5a8fc862-a551-4847-983a-90a65d88b83c.jpg)

如果我们加入分号，那么我们的程序将成功构建，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/89567df5-38cb-4314-8211-1e6a39f3f43d.jpg)

这就是全部内容。

当然，并非所有的错误消息都是那么自解释的。举例来说，让我们创建一个稍微复杂一点的错误。如果在这个程序中我们忘记插入一个括号会发生什么？这在下面的代码中有所说明：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/a3bd9e05-c334-4845-afa8-8438493525f9.jpg)

当我们按下构建项目时，我们得到了两个错误，尽管我们只犯了一个错误：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/c037519d-e9ed-40c4-a4a3-c3e6b4ba7974.jpg)

我们的第一个错误是`not a statement`，然后它告诉我们它不理解的那一行。如果我们仔细看一下第一个错误，我们可能会注意到我们缺少一对括号，所以我们将能够修复这个错误；但是，第二个错误呢？我们再次得到了`';' expected`，尽管在这种情况下我们确实有一个分号。

嗯，一旦程序中发生了一个错误，编译器理解代码行的能力就会很快破裂。当我们调试我们的代码时，一个基本的经验法则是只处理列表中的顶部错误；那是编译器在我们的代码中遇到的第一个错误。我们可能能够从下面更多的错误中获得一些有用的信息，但更多的情况是，它们只是由我们第一个语法错误生成的错误。这里没有什么太惊人的，但我想向你指出这一点，因为能够追踪编译器错误可以在我们学习编程时节省我们很多麻烦。

# 代码补全功能

在谈论 NetBeans 时，让我们快速了解另一个 IDE 功能。假设我想写一行新代码，我要使用`System`库中的某个东西：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/881707e3-08df-4582-92f4-1b115d9e3a36.jpg)

一旦我输入`System.`，NetBeans 就可以为我建议有效的响应。当然，其中只有一个是我要找的。NetBeans 编译器有很多这样的有用功能。如果你是那种认为代码补全很棒的人，可以继续使用这些工具。我们可以通过转到工具 | 选项 | 代码补全，并勾选我们想要的功能来实现这一点：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/036e89b8-1c27-42f2-bd51-35a92310b995.jpg)

如果你更希望 NetBeans 的行为更像文本编辑器，可以取消所有功能的勾选。

我们开始吧，在这一节中有很多清理工作，但希望会很快，也不会太痛苦。

# 总结

在本章中，您了解了 Java 是什么，以及它的特点。我们通过查看它在各个领域的应用来看到了 Java 的广泛应用。

我们走过了安装 Java 开发工具包的步骤。然后设置了一个名为**NetBeans**的开发环境，用于编写和执行 Java 程序。我们看到了如何使用 NetBeans 并在其中编写了我们的第一个 Java 程序。接下来，我们看到了如何使用 NetBeans 的错误检测功能来纠正错误。

在下一章中，我们将看一下各种 Java 数据类型以及如何使用变量。


# 第二章：理解有类型的变量

要创建甚至是简单的 Java 程序，我们需要一种存储和操作信息的方法。在这种情况下，我们的主要资源是变量，这就是我们将在本章中讨论的内容。我们将看看 Java 中的不同数据类型以及如何在程序中使用它们。我们还将看到`Math`类库及其一个函数。

具体来说，我们将讨论以下主题：

+   变量的介绍及其必要性

+   整数变量

+   浮点变量

+   `Math`类库及其`pow()`函数

+   字符变量

+   `String`类及其方法

# 整数变量

首先，让我们在 NetBeans 中创建一个新项目。我将把我的称为`Variables`，这次我们将允许 NetBeans 为我们创建主类，以便我们尽快开始编码。我们需要删除 NetBeans 在创建新项目时自动创建的所有注释，以便尽可能保持一切清晰可读，然后我们就可以开始了：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/f4dff2ef-aa16-4c77-a6a1-80fa47689ac8.jpg)

最初的计算机只不过是计算器，当然，Java 保留了这种功能。例如，Java 可以计算`1+1`，结果当然是`2`。然而，Java 相当复杂，设计用于执行许多不同的任务，因此我们需要为我们的命令提供上下文。在这里，我们告诉 Java 我们希望它打印`1+1`的结果：

```java
package variables; 

public class Variables { 

    public static void main(String[] args) { 
        System.out.println(1+1); 
    } 

} 
```

我们之前的程序将如预期般运行：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/ecbc403f-5889-4e61-945e-a3d184e24f97.jpg)

除了其他一些操作，Java 可以执行所有基本的算术运算。它可以进行加法、减法、乘法（我们使用`*`，而不是键盘上的`X`），以及除法。如果我们运行以下程序并输入`2`和`3`，我们将看到四个`println()`命令，所有这些命令都将给出正确的计算结果。当然，我们可以将这些数字更改为任何我们认为合适的数字组合：

```java
package variables; 

public class Variables { 

    public static void main(String[] args) { 
        System.out.println(2+3); 
        System.out.println(2-3); 
        System.out.println(2*3); 
        System.out.println(2/3); 
    } 
} 
```

以下是前面代码的输出：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/46d2e0fd-de73-44c8-811a-56e8cda1c167.jpg)

手动更改这些行有点麻烦，如果我们编写非常复杂的程序或接受用户输入的动态程序，这很快就变得不可行。

# 变量的解决方案

幸运的是，编程给了我们一种存储和检索数据的方法；这就是**变量**。要在 Java 中声明一个变量，我们首先必须指定我们将使用的变量类型。变量有许多不同的类型。在这种情况下，我们满足于使用整数，即没有指定小数位并且不是分数的数字。此外，在这种情况下，使用 Java 的原始类型是合适的。这些基本上是 Java 编程语言中信息的基本级别；我们在 Java 中使用的几乎所有其他东西都是由原始类型构建的。

要声明整数原始类型的变量，即整数，我们使用`int`关键字，全部小写。一旦我们这样做，我们需要给我们的变量一个名称。这是一个唯一的标识符，我们将用它来在将来访问这个信息。我们本地程序中的每个变量都应该有自己的名称。让我们称我们的第一个变量为`x`，我们的第二个变量为`y`：

```java
package variables; 

public class Variables { 

    public static void main(String[] args) { 
        int x; 
        int y; 

        System.out.println(2+3); 
        System.out.println(2-3); 
        System.out.println(2*3); 
        System.out.println(2/3); 
    } 
} 
```

我们刚刚编写了两行完全合法的 Java 代码。如果我们现在运行程序，我们将看到与之前相同的输出：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/8367c0c4-8769-4f2b-a658-833cce3172b2.jpg)

然而，在幕后，Java 也会为我们的`x`和`y`变量设置内存空间。这种分配不会影响我们的`println`命令，因为变量在其中还没有被引用。

所以让我们在变量中存储一些信息。我们可以在创建变量后通过变量的名称来引用变量。重要的是我们不要再次键入`int x`来引用我们的变量，因为这是 Java 创建一个全新变量`x`而不是访问现有变量`x`的命令：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/f8249e4c-22b4-4ca3-bc16-593d40173ca6.png)

一旦我们引用了变量，我们就可以使用等号更改其值。所以让我们将`x`设置为`4`，`y`设置为`3`。我们的`println`命令目前使用两个明确声明的整数：数字`2`和`3`。由于`x`和`y`也是整数，我们可以简单地用变量`x`和`y`替换现有的数字：

```java
package variables; 

public class Variables { 

    public static void main(String[] args) { 
        int x; 
        int y; 
        x = 4; 
        y = 3; 
        System.out.println(x+y); 
        System.out.println(x-y); 
        System.out.println(x*y); 
        System.out.println(x/y); 
    } 
} 
```

以下是前述代码的输出：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/e1c7a2a6-9b27-4ad8-b4ba-552e07ebe6b5.jpg)

当我们的 Java 代码涉及变量`x`和`y`时，它将查看它们当前具有的整数值。它会找到数字`4`和`3`。因此，如果我们运行程序，我们应该期望第一个`println`语句`x+y`计算为`4+3`，然后计算为`7`。这正是发生的事情。

所以这里有一些有趣的事情。我们程序的最后一行，其中我们将`x`除以`y`，并没有像我们在数学上期望的那样进行评估。在这行代码中，`x`的值为`4`，`y`的值为`3`，现在`4`除以`3`等于 1.3，但我们的程序只是输出`1`。那是因为 1.3 不是有效的整数值。整数只能是整数，永远不是分数或小数。因此，为了让我们使用整数，Java 会将具有小数部分的任何计算向下舍入到最接近的整数。如果我们想要在可能有分数结果的环境中工作，我们需要使用除整数以外的原始类型。

无论如何，现在我们已经设置了我们的`println`命令以接受整数变量输入而不是明确的数字，我们可以通过简单地更改这些整数变量的值来修改所有四行计算的行为。例如，如果我们希望我们的程序在输入值`-10`和`5`（整数可以是负数；它们只是不能有分数部分）上运行，我们只需要更改我们给变量`x`和`y`的值：

```java
package variables; 

public class Variables { 

    public static void main(String[] args) { 
        int x; 
        int y; 

        x = -10; 
        y = 5; 

        System.out.println(x+y); 
        System.out.println(x-y); 
        System.out.println(x*y); 
        System.out.println(x/y); 
    } 
} 
```

如果我们快速运行前述代码，我们将看到预期的结果：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/d32b5c65-880c-41a2-9863-aed25b3dce4c.jpg)

太棒了！您刚刚学会了在 Java 中使用整数和变量的基础知识。

# 整数变量的内存分配

让我们来看一个边缘情况，并了解一下 Java 的思维方式。您可能还记得我之前提到过，Java 在声明新变量时会设置内存。这是在高级编程语言（如 Java）中工作的巨大优势之一。Java 为我们抽象化或自动处理大部分内存管理。这通常使编写程序更简单，我们可以编写更短、更干净和更易读的代码。当然，重要的是我们要欣赏幕后发生的事情，以免遇到问题。

例如，每当 Java 为整数变量设置内存时，它也为所有整数变量设置相同数量的内存。这意味着 Java 可能在整数变量中存储的最大和最小值。最大整数值为`2147483647`，最小整数值为`2147483648`。

那么让我们做一个实验。如果我们尝试存储并打印一个比最大值大一的整数变量会发生什么？首先，让我们简化我们的程序。我们只是将一个比可能的值高一的值分配给变量`x`：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/504868da-232a-43e3-bd1e-81d726d29b6d.png)

当我们尝试这样做时，NetBeans 会对我们大喊大叫。它内置了一些逻辑，试图阻止我们犯下这个非常基本和常见的错误。如果我们尝试编译这个程序，我们也会得到一个错误。

然而，我们想要以科学的名义犯这个错误，所以我们要欺骗 NetBeans。我们将把变量`x`的值设置为最大可能的整数值，然后在我们的代码的下一行，我们将把`x`的值设置为比当前`x`高一的值，也就是`x=x+1`。实际上，我们可以使用一个巧妙的简写：`x=x+1`等同于`x++`。好的，当我们运行这个程序时，它将欺骗编译器和 NetBeans，并在运行时进行加法运算，我们尝试打印出一个整数值，这个值比 Java 可以存储在内存位置中的最大整数值多一：

```java
package variables; 

public class Variables { 

    public static void main(String[] args) { 
        int x; 

        x = 2147483647; 

        x++; 
        System.out.println(x); 

    } 
} 
```

当我们运行上述程序时，我们会得到以下负数：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/b95205e1-dc7d-4d43-b244-436bc92bc84c.jpg)

这个数字恰好是我们可以存储在整数中的最小数字。这在视觉上有一定的意义。我们已经走得如此之远，或者说向右，在我们的整数数线上，以至于我们到达了最左边或最负的点。当然，在数学上，这可能会变得相当混乱。

我们不太可能编写需要比这个值更高的整数的程序。然而，如果我们确实需要，我们当然需要意识到这个问题并规避它，使用一个可以处理更大值的变量类型。`long`变量类型就像整数一样，但我们需要为它分配更多的内存：

```java
package variables; 

public class Variables { 

    public static void main(String[] args) { 
        long x; 

        x = 2147483647; 

        x++; 
        System.out.println(x); 

    } 
} 
```

当我们运行上述程序时，我们将得到一个数学上准确的结果：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/e55622b8-4f38-451f-9dbb-4c729df8e319.jpg)

# 浮点变量

当我们只是简单地计数和操作整个对象时，整数是很棒的。然而，有时我们需要以更数学的方式处理数字，我们需要一个数据类型，可以让我们表达不完全是整数的想法。浮点数，或者浮点数，是 Java 的一个原始类型，允许我们表示有小数点和分数的数字。在本节中，我们将修改一些浮点和整数变量，以便看到它们的相似之处和不同之处。

让我们创建一个新的 Java 项目（你现在已经知道了）并将其命名为`FloatingPointNumbers`。让我们首先声明两个变量：一个整数（`iNumber`）和一个浮点数（`fNumber`）。正如我们所知，一旦声明了这些变量，我们就可以在我们的 Java 程序中修改和赋值给它们。这一次，让我向你展示，我们也可以在声明这些变量的同一行中修改和赋值给这些变量。所以当我声明了我的`iNumber`整数变量时，我可以立即给它赋值`5`：

```java
package floatingpointnumbers; 

public class FloatingPointNumbers { 

    public static void main(String[] args) { 
        int iNumber = 5; 
        float fNumber; 
    } 
} 
```

请注意，如果我们尝试用我们的浮点变量做类似的事情，NetBeans 会对我们大喊大叫，左侧会显示一个灯泡和红点：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/00c7ce26-7b13-43af-a214-06143904c0bb.png)

实际上，如果我们尝试编译我们的程序，我们会得到一个合法的编译器错误消息：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/d3765a7c-e60a-46f8-8d1d-9d7ad8e4bde1.jpg)

让我们分析一下为什么会发生这种情况。当我们在 Java 中使用一个显式数字，也就是说，打出数字而不是使用一个变量时，Java 仍然会给这个显式数字一个类型。因此，当我们打出一个没有小数位的数字时，这个数字被假定为整数类型。所以我们的赋值工作得很好。然而，带有小数位的数字被假定为这种类型，称为`double`；它是`float`数据类型的姐妹类型，但并不完全相同。我们稍后会讨论`double`。现在，我们需要告诉 Java 将`5.5`视为`float`类型的数字，而不是`double`。为此，我们只需要在数字后面加上`f`，如下所示：

```java
float fNumber = 5.5f; 
```

你会发现灯泡和红点已经消失了。为了确保我们的语法正确，让我们给我们的程序一些超级基本的功能。让我们使用`System.out.println()`按顺序打印我们的整数和浮点数变量：

```java
System.out.println(iNumber); 
System.out.println(fNumber); 
```

当我们构建这个程序时，我们的编译器错误消失了，当我们运行它时，我们看到了两个分配的值，一切都如预期那样。没有什么太激动人心的地方：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/c91aff6e-852d-4463-a59e-f5427c61a6d9.jpg)

# 整数和浮点数据类型之间的行为差异

现在，我们不再为变量分配显式值，而是进行一些基本的算术运算，以便我们可以看到在 Java 中修改整数和浮点数时的不同行为。在 Java 中，`float`和`int`都是原始类型，是编程语言的逻辑构建块。这意味着我们可以使用数学运算符进行比较和修改，例如除法。

我们知道，如果我们尝试将一个整数除以另一个整数，我们总是会得到一个整数作为结果，即使标准数学规则并不产生预期的结果。然而，如果我们将一个浮点数除以另一个浮点数，我们将得到一个更符合数学规则的结果：

```java
package floatingpointnumbers; 

public class FloatingPointNumbers { 

    public static void main(String[] args) { 
        int iNumber = 5/4; 
        float fNumber = 5.0f/4.0f; 
        System.out.println(iNumber); 
        System.out.println(fNumber); 
    } 
} 
```

以下是前面代码的输出：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/bb4b9190-5d11-4bbe-93c4-46769ff63be5.jpg)

有时，Java 会让我们做一些可能不是那么好的主意的事情。例如，Java 允许我们将浮点变量`fNumber`的值设置为一个整数除以另一个整数，而不是一个浮点数除以另一个浮点数：

```java
int iNumber = 5/4; 
float fNumber = 5/4; 
```

因为等号右侧的计算发生在我们的浮点变量`fNumber`的值改变之前，所以我们将在`5/4`的计算中看到相同的输出。这是因为 5 和 4 都是整数变量。因此，当我们运行程序时，即使`fNumber`仍然是一个浮点数（因为它带有小数点），它的值仍然设置为`5/4`的向下取整整数部分：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/04d86a0b-dda4-44a3-bc9f-a1be8869b39f.jpg)

解决这个问题非常简单；我们只需要将我们的整数值之一更改为浮点数，通过在其后添加`f`：

```java
int iNumber = 5/4; 
float fNumber = 5/4.0f; 
```

现在计算将知道如何进行小数点的除法：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/769f67af-a82c-4fb3-99f3-699d080c9821.jpg)

当我们停止使用显式声明的数字并开始使用变量时，正确地导航这一点变得更加棘手和重要。

现在让我们声明两个整数变量。我只是称它们为`iNumber1`和`iNumber2`。现在，我们不再试图将`fNumber`的值设置为一个显式声明的数字除以另一个数字，而是将其值设置为`iNumber1/iNumber2`，然后我们将打印出存储在`fNumber`中的结果：

```java
package floatingpointnumbers; 

public class FloatingPointNumbers { 

    public static void main(String[] args) { 
        int iNumber1 = 5; 
        int iNumber2 = 6; 
        float fNumber = iNumber1/iNumber2; 

        System.out.println(fNumber); 
    } 
} 
```

当我们运行这个程序时，因为我们再次将一个整数除以另一个整数，我们将看到向下取整的现象。存储在我们的浮点变量中的值是`0.0`，即`5/6`的向下取整结果：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/eb11f02b-69bc-4402-bf1d-2f8ea176e037.jpg)

如果我们正在处理显式声明的数字，我们可以通过将两个整数数字中的一个更改为浮点数来解决这个问题，只需在其后加上小数点和`f`。在这种情况下，使用`iNumber2f`不是一个选择，因为 Java 不再认为我们要求它将`iNumber2`视为浮点数，而是认为它正在寻找一个名为`iNumber2f`的变量，而这在这个上下文中显然不存在。

# 类型转换

我们也可以通过使用所谓的**转换**来实现类似的结果。这是一个命令，我们要求 Java 将一个类型的变量视为另一个类型。在这里，我们绕过了 Java 自然倾向于将`iNumber1`和`iNumber2`视为整数的倾向。我们介入并说：“你知道 Java，把这个数字当作浮点数处理”，当我们这样做时，我们承担了一些责任。Java 会尝试按照我们的要求做，但如果我们选择不当并尝试将一个对象转换为它不能转换的对象，我们的程序将崩溃。

幸运的是，我们在这里使用的是原始类型，原始类型知道如何像另一种类型一样行事。因此，我们可以通过将变量`iNumber1`转换为浮点数来实现类似的结果，方法是在其前面加上`(float)`：

```java
float fNumber = (float)iNumber1/iNumber2; 
```

现在，如果我们运行我们的程序，我们将看到预期的`5/6`结果：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/f023a0d3-25eb-4199-a362-c8054663de1d.jpg)

这是一个非常扎实的关于使用浮点数的介绍，我们几乎在任何时候都会使用它们来处理数学意义上的数字，而不是作为整数来计算整个对象。

# 双精度数据类型

让我们简要谈谈`double`数据类型。它是`float`的姐妹类型。它提供更高的分辨率：`double`数字可以有更多的小数位。但它们占用了更多的内存。在这个时候，使用 double 或 float 几乎总是一个风格或个人偏好的决定。除非你正在处理必须以最高内存效率运行的复杂软件，否则双精度占用的额外内存空间并不是非常重要的。

为了说明`double`的工作原理，让我们将`FloatingPointNumbers.java`程序中的两个整数更改为`double`数据类型。当我们只更改变量的名称时，程序的逻辑并没有改变。但是当我们将这些变量的声明从整数更改为双精度时，逻辑确实发生了变化。无论如何，当我们显式声明带有小数位的数字时，默认为`double`：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/99ffb0a4-0064-4de5-959f-eb48396bcbdf.png)

现在我们需要修复错误。错误是因为将`double`数据类型除以另一个`double`数据类型将返回一个`double`结果。我们可以通过两种方式解决这个问题：

1.  首先，我们可以将`dNumber1`和`dNumber2`转换为浮点数，然后再将它们相除：

```java
float fNumber = (float) dNumber1/ (float) dNumber2; 
```

1.  然而，将我们的两个双精度数字相除是一个完全合法的操作。那么为什么不允许这种自然发生，然后将结果的双精度转换为浮点数，从而保留更多的分辨率。就像在代数中一样，我们可以使用括号将我们希望在另一个块之前发生的程序的概念块分解：

```java
float fNumber = (float) (dNumber1/dNumber2); 
```

现在如果我们运行这个程序，我们会得到预期的结果：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/f0a31fb1-1568-43f3-85b4-0159b9c245b0.jpg)

# Math 类库

在任何软件开发项目中，我们将花费大量时间教导我们的程序解决它经常遇到的问题类型。作为程序员，我们也会一次又一次地遇到某些问题。有时，我们需要编写自己的解决方案，并希望将它们保存以备将来使用。然而，更多的时候，有人之前遇到过这些问题，如果他们已经公开提供了解决方案，我们的一个选择就是利用他们的解决方案来获益。

在这一部分，我们将使用与 JDK 捆绑在一起的`Math`类库来解决一些数学问题。要开始这一部分，创建一个全新的 NetBeans 项目（我将其命名为`TheMathLib`）并输入`main()`函数。我们将编写一个非常简单的程序。让我们声明一个浮点数变量并给它一个值（不要忘记在我们显式数字的末尾加上`f`字母，让 Java 知道我们声明了一个浮点数），然后使用`System.out.println()`将这个值打印到屏幕上：

```java
package themathlib; 

public class TheMathLib { 
    public static void main(String[] args) { 
        float number = 4.321f; 
        System.out.println(number); 
    } 
} 
```

好的，我们到这里： 

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/0e87c80c-cbba-4fba-9eb8-c78c235f9d2f.jpg)

现在，通过这个程序，我们希望能够轻松地将我们的浮点数提高到各种幂。所以，如果我们只想将这个数字平方，我想我们可以直接打印出`number*number`的值。如果我们想将其立方，我们可以打印出`number*number*number`。如果我们想将它提高到 6 次幂，我们可以将它乘以自身六次。当然，这很快就会变得难以控制，肯定有更好的方法。

让我们利用 Java 的`Math`类库来帮助我们将数字提升到不同的指数幂。现在，我刚告诉你我们正在寻找的功能存在于`Math`类库中。这是你应该期望从 Google 搜索中得到的正确方向，或者如果你是一名经验丰富的软件开发人员，你可以实现一个特定的 API。不幸的是，这对我们来说还不够信息来开始使用这个类库的功能。我们不知道它的工作细节，甚至不知道它为我们提供了什么功能。

要找出这个，我们需要查看它的文档。这是由 Oracle 管理的 Java 开发工具包中的库的文档网页：[docs.oracle.com/javase/7/docs/api/](http://docs.oracle.com/javase/7/docs/api/)。在页面上显示的库中，有`java.lang`。当我们选择它时，我们会在类摘要下找到我们一直在寻找的`Math`类。一旦我们导航到`Math`类库页面，我们会得到两件事。首先，我们得到一些关于库的人性化文本描述，它的历史，它的预期用途，非常元级别的东西。如果我们向下滚动，我们会看到库实现的功能和方法。这就是我们想要的细节：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/5af38ab7-0226-45ab-9385-b23abde20824.jpg)

# 使用 pow()函数

其中一个函数应该引起我们的注意，那就是`pow()`，或者幂函数。它返回第一个参数（`double a`）的值提高到第二个参数（`double b`）的幂。简而言之，它允许我们将数字提高到任意幂：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/f70ddefb-5585-416c-a21c-9f0fb95452eb.jpg)

让我们回到编码。好的，让我们在声明变量`number`之后使用`pow()`函数来修改它的值。我们要做的事情是`number = pow`之类的事情，但我们需要更多的信息：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/6def15f6-4682-4b40-9738-c78e12f8c2aa.png)

我们如何使用这个`pow()`函数？嗯，如果我们点击我们的文档，我们会看到当`pow()`函数被声明时，除了它的名称之外，还有在括号之间指定的两个参数。这些参数，`double a`和`double b`，是函数在操作之前请求的两个信息。 

为了使用这个函数，我们的工作是用实际变量或显式值替换请求的`double a`和`double b`，以便`pow()`函数可以发挥作用。我们的文档告诉我们，`double a`应该被替换为我们想要提高到`double b`次幂的变量或值。

所以让我们用我们想要提高到任意幂的变量`number`替换第一个类型参数。在这一点上，`number`是`float`而不是`double`，除非我们简单地将其更改为`double`，否则这将给我们带来一些麻烦。所以让我们这样做。对于第二个参数，我们没有一个预先创建的变量来替换`double b`，所以让我们使用一个显式值，比如`4.0`：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/811bebe1-6305-4142-9a72-d12617682d4f.png)

注意，当我调用`pow()`函数时，我去掉了`double`说明符。这个说明符只是为了让我们知道 Java 期望的类型。

理论上，`pow()`函数现在具有运行并将我们的数字变量的值提高到 4 次幂所需的所有信息。然而，NetBeans 仍然给我们显示红色警告标志。现在，这是因为 NetBeans，以及 Java 本身，不知道在哪里找到这个`pow`关键字。出于与我们需要指定完整路径到`System.out.println()`相同的原因，我们需要指定一个完整路径，以便 Java 可以找到`pow()`函数。这是我们在文档中找到`pow()`函数的路径。因此，让我们在我们的代码中指定`java.lang.Math.pow()`作为它的路径：

```java
package themathlib; 

public class TheMathLib { 
    public static void main(String[] args) { 
        double number = 4.321; 
        number = java.lang.Math.pow(number, 4.0); 
        System.out.println(number); 
    } 
} 
```

现在我们基本上可以开始了。让我们在`println`语句中使用一次`number`变量，然后我们应该能够运行我们的程序：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/6ff4def5-2691-46e7-8f33-0373021881f6.jpg)

如果我们想的话，我们可以将它插入我们的计算器，但我非常有信心，我们的程序已经输出了 4.321 的值提高到 4 次幂。

这很棒！我们刚刚使用外部代码不仅使我们的程序更容易编写，而且使它非常易读。它所需的代码行数比以前少得多。

# 导入类库

关于我们的程序，有一件事不太容易阅读，那就是到`pow()`和`println()`等函数的长路径。我们能不能缩短它们？当然可以。如果 Java 的制造商想要的话，他们可以让我们在所有情况下通过简单地输入`Math.pow()`来调用这个函数。不幸的是，这可能会产生一些意想不到的副作用。例如，如果有两个库链接到 Java，并且它们都声明了`Math.pow()`函数，Java 将不知道使用哪一个。因此，默认情况下，我们期望直接和明确地链接到库。

因此，如果我们想要只输入`Math.pow()`，我们可以将一个库导入到我们正在工作的本地空间中。我们只需要在我们的类和`main()`函数声明上面执行一个`import`命令。导入命令所需的输入只是我们希望 Java 在遇到一个关键字时查找的路径，比如`pow()`，它不立即识别。为了让我们在程序中使用更简单的语法`Math.pow()`，我们只需要输入`import java.lang.Math`：

```java
package themathlib; 

import java.lang.Math; 

public class TheMathLib { 
    public static void main(String[] args) { 
        double number = 4.321; 
        number = java.lang.Math.pow(number, 4.0); 
        System.out.println(number); 
    } 
} 
```

有一些特殊的导入语法。假设我们想要导入`java.lang`中的所有类库。为了做到这一点，我们可以用`.*`替换`.Math`，并将其变为`java.lang.*`，这意味着“导入`java.lang`包中的每个库”。我应该告诉你，在 NetBeans 中工作的人，这个导入是默认完成的。然而，在这种情况下，我们将明确地这样做，因为你可能在其他 Java 环境中工作时也需要这样做。

# 字符变量

操作数字的程序都很好，但通常我们也想要能够处理文本和单词。为了帮助我们做到这一点，Java 定义了字符或`char`，原始类型。字符是您可以在计算机上处理的最小文本实体。一开始我们可以把它们想象成单个字母。

让我们创建一个新项目；我们将其命名为`Characters.java`。我们将通过简单地定义一个单个字符来开始我们的程序。我们将其称为`character1`，并将其赋值为大写的`H`：

```java
package characters; 

public class Characters { 
    public static void main(String[] args) { 
        char character1 = 'H'; 
    } 
} 
```

就像在明确定义浮点数时我们必须使用一些额外的语法一样，当定义一个字符时，我们需要一些额外的语法。为了告诉 Java 我们在这里明确声明一个字符值，我们用两个单引号将我们想要分配给变量的字母括起来。单引号与双引号相反，让 Java 知道我们正在处理一个字符或一个单个字母，而不是尝试使用整个字符串。字符只能有单个实体值。如果我们尝试将`Hi`的值分配给`character1`，NetBeans 和 Java 都会告诉我们这不是一个有效的选项：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/c94edae3-6ae6-42bf-8c8f-648c655ca1ab.png)

现在，让我们继续编写一个有些复杂但对我们的示例目的非常有效的程序。让我们定义五个字符。我们将它们称为`character1`到`character5`。我们将它们中的每一个分配给单词"Hello"的五个字母中的一个，按顺序。当这些字符一起打印时，我们的输出将显示`Hello`。在我们程序的第二部分，让我们使用`System.out.print()`在屏幕上显示这些字母。`System.out.print()`代码的工作方式与`System.out.println()`完全相同，只是它不会在我们的行末添加回车。让我们将最后一个命令设置为`println`，这样我们的输出就与控制台中呈现的所有附加文本分开了：

```java
package characters; 

public class Characters { 

    public static void main(String[] args) { 
        char character1 = 'H'; 
        char character2 = 'e'; 
        char character3 = 'l'; 
        char character4 = 'l'; 
        char character5 = 'o'; 
        System.out.print(character1); 
        System.out.print(character2); 
        System.out.print(character3); 
        System.out.print(character4); 
        System.out.println(character5); 
    } 
} 
```

如果我们运行这个程序，它会向我们打招呼。它会说`Hello`，然后还会有一些额外的文本：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/b8050473-9463-4dd5-8718-97230d9a5c7c.jpg)

这很简单。

现在让我向您展示一些东西，这将让我们对计算机如何处理字符有一点了解。事实证明，我们不仅可以通过在两个单引号之间明确声明大写字母`H`来设置`character1`的值，还可以通过给它一个整数值来设置它的值。每个可能的字符值都有一个相应的数字，我们可以用它来代替。如果我们用值`72`替换`H`，我们仍然会打印出`Hello`。如果我们使用值`73`，比`72`大一的值，而不是大写字母`H`，我们现在会得到大写字母`I`，因为 I 是紧随 H 之后的字母。

我们必须确保不要在两个单引号之间放置`72`。最好的情况是 Java 会认识到`72`不是一个有效的字符，而更像是两个字符，那么我们的程序就不会编译。如果我们用单引号括起来的单个数字，我们的程序会编译得很好，但我们会得到完全意想不到的输出`7ello`。

那么我们如何找出字符的数值呢？嗯，有一个通用的查找表，**ASCII**表，它将字符映射到它们的数值：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/eb16142c-1f5e-44d0-8b7c-6fbb6a4444b1.png)

在本节中，我们一直在处理第 1 列（**Dec**）和第 5 列（**Chr**），它们分别是十进制数和它们映射到的字符。您会注意到，虽然许多这些字符是字母，但有些是键盘符号、数字和其他东西，比如制表符。就编程语言而言，换行、制表符和退格都是字符元素。

为了看到这个过程，让我们尝试用十进制值`9`替换程序中的一些字符，这应该对应一个制表符。如果我们用制表符替换单词中间的三个字母，作为输出，我们应该期望`H`，三个制表符和`o`：

```java
package characters; 

public class Characters { 

    public static void main(String[] args) { 
        char character1 = 'H'; 
        char character2 = 9; 
        char character3 = 9; 
        char character4 = 9; 
        char character5 = 'o'; 
        System.out.print(character1); 
        System.out.print(character2); 
        System.out.print(character3); 
        System.out.print(character4); 
        System.out.println(character5); 
    } 
```

以下是前述代码的输出：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/4f442e9c-7ff8-4d23-bc48-ad46675cc20a.jpg)

# 字符串

让我们谈谈 Java 中的字符串。首先，创建一个新的 NetBeans 项目，命名为`StringsInJava`，并输入`main()`函数。然后，声明两个变量：一个名为`c`的字符和一个名为`s`的`String`。很快，我们就清楚地看到`String`有点不同。您会注意到 NetBeans 没有选择用蓝色对我们的`String`关键字进行着色，就像我们声明原始类型的变量时那样：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/74e727d1-8ce8-4eb4-8572-e950945b1dc0.png)

这是因为`String`不像`char`那样是原始类型。`String`是我们所谓的类。类是面向对象编程的支柱。正如我们可以声明原始类型的变量一样，我们也可以声明类的变量，称为实例。在我们的程序中，变量`s`是`String`类的一个实例。与原始类型的变量不同，类的实例可以包含由它们是实例的类声明的自己的特殊方法和函数。在本节中，我们将使用一些特定于字符串的方法和函数来操作文本。

但首先，让我们看看`String`类有什么特别之处。我们知道，我们几乎可以将字符变量和字符文字互换使用，就像我们可以用任何其他原始类型一样。`String`类也可以与字符串文字互换使用，它类似于字符文字，但使用双引号并且可以包含许多或没有字符。大多数 Java 类不能与任何类型的文字互换，而我们通过`String`类来操作字符串文字的能力正是它如此宝贵的原因。

# 连接运算符

字符串还有一项功能，大多数 Java 类都做不到，那就是利用加号（`+`）运算符。如果我们声明三个字符串（比如`s1`，`s2`和`s3`），我们可以将第三个字符串的值设置为一个字符串加上另一个字符串。我们甚至可以将一个字符串文字添加到其中。然后，我们打印`s3`：

```java
package stringsinjava; 

public class StringsInJava { 

    public static void main(String[] args) { 
        char c = 'c'; 
        String s1 = "stringone"; 
        String s2 = "stringtwo"; 
        String s3 = s1+s2+"LIT"; 
        System.out.println(s3); 
    } 
} 
```

当我们运行这个程序时，我们将看到这三个字符串被添加在一起，就像我们所期望的那样：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/15aef721-7741-489e-8297-d4ba8efa14af.jpg)

# toUpperCase()函数

所以我向您承诺，字符串具有简单原始类型中看不到的功能。为了使用这个功能，让我们转到我们的 Java 文档中的`String`类，网址是[docs.oracle.com/javase/7/docs/api/](http://docs.oracle.com/javase/7/docs/api/)。在 Packages 下选择 java.lang，然后向下滚动并选择 ClassSummary 中的 String。与所有 Java 类的文档一样，String 文档包含 Method Summary，它将告诉我们关于现有`String`对象可以调用的所有函数。如果我们在 Method Summary 中向下滚动，我们将找到`toUpperCase()`函数，它将字符串中的所有字符转换为大写字母：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/d33d6172-8e2e-45de-9e66-5c6a64690309.jpg)

现在让我们使用这个函数。回到 NetBeans，我们现在需要确定在我们的程序中使用`toUpperCase()`函数的最佳位置：

```java
package stringsinjava; 
public class StringsInJava { 
    public static void main(String[] args) { 
        char c = 'c'; 
        String s1 = "stringone"; 
        String s2 = "stringtwo"; 
        String s3 = s1 + s2 + "LIT"; 
        System.out.println(s3); 
    } 
} 
```

我们知道我们需要在`StringsInJava.java`程序中确定`s3`的值之后，使用`toUpperCase()`函数。我们可以做以下两件事中的任何一件：

+   在确定`s3`的值之后，立即在下一行上使用该函数（只需键入`s3.toUpperCase();`）。

+   在我们打印出`s3`的值的那一行的一部分中调用该函数。我们可以简单地打印出`s3`的值，也可以打印出`s3.toUpperCase()`的值，如下面的代码块所示：

```java
package stringsinjava; 

public class StringsInJava { 

   public static void main(String[] args) { 
      char c = 'c'; 
      String s1 = "stringone"; 
      String s2 = "stringtwo"; 
      String s3 = s1+s2+"LIT"; 

      System.out.println(s3.toUpperCase()); 
   } 
} 
```

如果您还记得我们的文档，`toUpperCase()`函数不需要参数。它知道它是由`s3`调用的，这就是它所需要的所有知识，但我们仍然提供双空括号，以便 Java 知道我们实际上正在进行函数调用。如果我们现在运行这个程序，我们将得到预期的字符串大写版本：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/d52037bd-bb4a-4393-8ffa-a8468da9cf59.jpg)

但是，重要的是我们要理解这里发生了什么。`System.out.println(s3.toUpperCase());`代码行并不修改`s3`的值，然后打印出该值。相反，我们的`println`语句评估`s3.toUpperCase()`，然后打印出该函数返回的字符串。为了看到`s3`的实际值并没有被这个函数调用修改，我们可以再次打印`s3`的值：

```java
System.out.println(s3.toUpperCase()); 
System.out.println(s3); 
```

我们可以看到`s3`保留了它的小写组件：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/6903f535-8f3a-42ae-8705-bbffc3cbdd70.jpg)

如果我们想永久修改`s3`的值，我们可以在上一行这样做，并且我们可以将`s3`的值设置为函数的结果：

```java
package stringsinjava; 

public class StringsInJava { 
    public static void main(String[] args) { 
        char c = 'c'; 
        String s1 = "stringone"; 
        String s2 = "stringtwo"; 
        String s3 = s1 + s2 + "LIT"; 

        s3 = s3.toUpperCase(); 

        System.out.println(s3); 
        System.out.println(s3); 
    } 
} 
```

以下是前面代码的输出：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/6a4b2e41-154f-4468-b641-df6521c301b3.jpg)

# replace()函数

为了确认我们都在同一页面上，让我们再使用`String`类的一个方法。如果我们回到我们的文档并向上滚动，我们可以找到 String 的`replace()`方法：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/b878df4e-62f5-4c8c-ba1f-e6ba5f737f08.png)

与我们的`toUpperCase()`方法不同，它不带参数，`replace()`需要两个字符作为参数。该函数将返回一个新的字符串，其中我们作为参数给出的第一个字符（`oldChar`）的所有实例都被我们作为参数给出的第二个字符（`newChar`）替换。

让我们在`StringsInJava.java`的第一个`println()`行上使用这个函数。我们将输入`s3.replace()`并给我们的函数两个字符作为参数。让我们用字符`g`替换字符`o`：

```java
package stringsinjava; 

public class StringsInJava { 
    public static void main(String[] args) { 
       char c = 'c'; 
        String s1 = "stringone"; 
        String s2 = "stringtwo"; 
        String s3 = s1 + s2 + "LIT"; 

        s3 = s3.toUpperCase(); 

        System.out.println(s3.replace('g', 'o')); 
        System.out.println(s3); 
    } 
} 
```

当我们运行我们的程序时，当然什么也不会发生。这是因为当我们到达打印语句时，没有小写的`g`字符，也没有剩余的小写的`g`字符在`s3`中；只有大写的`G`字符。所以让我们尝试替换大写的`G`字符：

```java
System.out.println(s3.replace('G', 'o')); 
System.out.println(s3); 
```

现在，如果我们运行我们的程序，我们会看到替换发生在第一个`println`的实例上，而不是第二个实例上。这是因为我们实际上没有改变`s3`的值：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/11075cfd-2d3f-4276-8c4f-07faeff0d964.jpg)

太好了！现在你已经装备精良，只要你随时准备好 Java 文档，就可以调用各种`String`方法。

# 转义序列

如果你花了很多时间处理字符串，我预计你会遇到一个常见的问题。让我们快速看一下。我要在这里写一个全新的程序。我要声明一个字符串，然后让我们的程序将字符串打印到屏幕上。但我要给这个字符串赋值的值会有点棘手。我希望我们的程序打印出`The program says: "Hello World"`（我希望`Hello World`被双引号括起来）：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/28c20394-e017-4a4d-bdac-f5a589ccd91b.png)

这里的问题是，在字符串文字中放置双引号会让 Java 感到困惑，就像前面的屏幕截图所示的那样。当它阅读我们的程序时，它看到的第一个完整字符串是`"The program says:"`，这告诉 Java 我们已经结束了字符串。这当然不是我们想要的。

幸运的是，我们有一个系统可以告诉 Java，我们希望一个字符被视为字符文字，而不是它可能具有的特殊功能。为此，我们在字符前面放一个反斜杠。这被称为转义序列：

```java
String s= "The program says: \"Hello World\""; 
System.out.println(s); 
```

现在，当 Java 阅读这个字符串时，它将读取`The program says:`，然后看到反斜杠，并知道如何将我们的双引号视为双引号字符，而不是围绕字符串的双引号。当我们运行我们的程序时，我们将看不到反斜杠；它们本身是特殊字符：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/d7026d00-78d1-4124-9766-63ab2c3442b7.jpg)

如果我们确实想在字符串中看到反斜杠，我们需要在其前面加上一个反斜杠：

```java
String s= "The program says: \\ \"Hello World\""; 
System.out.println(s); 
```

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/b2312c48-76f0-4437-b73a-5315b4f764f2.jpg)

这就是字符串 101！

# 总结

在本章中，我们解释了变量是什么，以及它们对于创建更好的程序有多重要。我们详细介绍了 Java 的一些原始数据类型，即`int`、`long`、`float`、`char`和`double`。我们还看到了`String`类及其两种操作方法。

在下一章中，我们将看一下 Java 中的分支语句。


# 第三章：分支

每次运行时执行相同操作的程序都很好，但最有趣的计算机程序每次运行时都会做一些不同的事情，这可能是因为它们具有不同的输入，甚至是因为用户正在积极地与它们交互。有了这个，让我们通过理解条件语句来启动本章，然后我们将进一步探讨 Java 如何处理复杂的条件语句，修改程序的控制流，并研究循环功能。

具体来说，本章将涵盖以下主题：

+   理解`if`语句

+   复杂的条件语句

+   `switch`、`case`和`break`语句

+   `while`和`do...while`循环

+   `for`循环

# 理解 if 语句

今天，我们将探讨非常基本的`if`和`else`条件语句。要进一步理解这一点，请参考以下项目列表：

1.  让我们在 NetBeans 中创建一个新的 Java 项目。我将把我的项目命名为`ConditionalStatements`，并允许 NetBeans 为我创建`main`类；参考以下截图：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/fed44d7e-dcac-4bcd-af4b-85b68c4bf7ce.jpg)

为了保持清晰，我们可以摆脱所有的注释；现在我们可以开始了。为了让我们编写更有趣的程序，我们将快速学习如何在 Java 中进行一些基本的用户输入。在这个时候，你还没有足够的知识基础来完全理解我们即将要做的复杂性，但是你可能对正在发生的事情有基本的理解，并且将来肯定可以自己重复这个过程。

在这个**InputStream**/**Console**窗口中写入是一种简单的一次性过程，但是在 Java 中读取输入可能会更加复杂：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/7ee0bc80-e7a7-467d-be90-0f391752e393.jpg)

1.  用户输入被放入一个缓冲区，我们的程序在提示时访问它；因此，我们需要声明一个变量，允许我们在需要获取新用户输入时访问这个缓冲区。为此，我们将使用`Scanner`类。让我们称我们的新实例为`reader`。NetBeans 对我们大喊大叫，因为`Scanner`位于`java.util`包中，我们需要显式访问它。我们可以随时导入`java.util`包：

```java
package conditionalstatements; 

public class ConditionalStatements { 

    public static void main(String[] args) { 
        java.util.Scanner reader; 
    } 
} 
```

1.  这是你需要有点信心并超前一点，超出你现在真正准备完全理解的范围。我们需要为`reader`变量分配一个值，这个值是`Scanner`类型的，这样它就可以连接到 InputStream 窗口，用户将在其中输入。为此，我们将把它的值设置为一个全新的`Scanner()`对象的值，但是这个 Scanner 对象将使用一个类型参数，即`(System.in)`，这恰好是我们的用户将要使用的 InputStream 的链接：

```java
package conditionalstatements; 

import java.util.*; 

public class ConditionalStatements { 

    public static void main(String[] args) { 
        Scanner reader = new Scanner(System.in); 
    } 
} 
```

以下是前面代码的输出：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/e06f5667-f6bc-4689-a1ad-e0d229864520.jpg)

1.  就像我说的，这是一些重要的内容，你肯定不应该期望现在就完全理解它是如何工作的。现在，知道`reader`与我们的 InputStream 窗口连接，我们的`Scanner`对象具有`next()`函数，允许我们访问用户刚刚输入到流中的输入。就像大多数函数一样，这个函数只是返回这个输入，所以我们需要创建一个字符串来存储这个输入。

1.  完成这些后，我们可以使用`System.out.println()`函数将`input`值打印回控制台：

```java
package conditionalstatements; 

import java.util.*; 

public class ConditionalStatements { 

    public static void main(String[] args) { 
        Scanner reader = new Scanner(System.in); 
        String input = reader.next(); 
        System.out.println(input); 
    } 
} 
```

1.  当我们运行程序时，似乎没有任何事情发生，但实际上，我们的控制台在这里等待用户输入。现在，当我们在控制台中输入我们的输入并按下*Enter*键时，它将立即回显给我们：![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/2fa36d7d-6ad2-47af-a345-6939a71bfe6d.jpg)

1.  我们可以通过让程序提示用户输入而不是静静地等待来使其更加友好：

```java
public static void main(String[] args) { 
    Scanner reader = new Scanner(System.in); 
    System.out.println("Input now: "); 
    String input = reader.next(); 
    System.out.println(input); 
} 
```

# 条件语句

在本章的开头，我承诺过你会学习条件语句，我们现在就要做到这一点。但首先，让我们对我们程序的用户输入部分进行一个小修改。与其获取一个字符串，如果我们学习使用用户提供的整数值来工作，那将会更容易得多。因此，让我们将我们的`input`变量的值或类型更改为`int`数据类型；`reader.next()`函数返回一个字符串，但有一个类似的函数叫做`nextInt()`，它将返回一个整数：

```java
int input = reader.nextInt(); 
```

我们肯定不会在我们非常简单的程序中加入任何错误处理机制。

要知道，如果我们不小心向这个 Java 程序提供除整数以外的任何东西，程序将崩溃。

那么条件语句到底是什么？条件语句允许我们根据某些事情是真还是假，将我们的程序引导到不同的路径上，执行不同的代码行。在本章中，我们将使用条件语句根据用户给我们的输入值来打印不同的响应。具体来说，我们将告诉他们他们给我们的值是小于、大于还是等于数字 10。为了开始这个过程，让我们设置我们的输出情况。

如果我们的用户提供的输入大于 10，我们打印出`MORE`。如果用户提供的输入恰好小于 10，我们打印出`LESS`。当然，如果我们现在运行这个程序，它将简单地打印出`MORE`或`LESS`，两行都会打印。我们需要使用条件语句来确保这两行中只有一行在任何程序运行中执行，并且当然执行正确的行。您可能已经注意到，NetBeans 为我们创建的默认项目将我们的代码分成了用大括号括起来的段。

我们可以使用自己的括号进一步将我们的代码分成段。惯例规定，一旦我们创建了一组新的括号，一个新的代码段，我们需要在括号之间的所有内容之前添加一个制表符，以使我们的程序更易读。

# 使用 if 语句

一旦我们将我们的两个`system.out.println`语句分开，我们现在可以提供必须为真的情况，如果这些语句要运行的话。为此，我们用 Java 的`if`语句作为前缀，其中`if`是一个 Java 关键字，后面跟着两个括号，我们在括号之间放置要评估的语句。如果 Java 确定我们在括号之间写的语句为真，则以下括号中的代码将执行。如果 Java 确定该语句为假，则括号中的代码将被完全跳过。基本上，我们将给这个`if`语句两个输入。我们将给它变量`input`，如果你还记得，它包含我们从用户那里得到的整数值，我们将给它显式值`10`，这是我们要比较的值。Java 理解大于（`>`）和小于（`<`）比较运算符。因此，如果我们使这个`if`语句`if(input > 10)`，那么`System.out.println`命令（如下面的屏幕截图中所示）只有在用户提供大于 10 的值时才会运行：

```java
if(input > 10) 
        { 
            System.out.println("MORE!"); 
        } 
        { 
            System.out.println("LESS!"); 
        } 
```

现在，我们需要提供一个`if`语句，以确保我们的程序不会总是打印出`LESS`。

我们可以使用小于运算符，要求我们的程序在用户提供小于 10 的输入时打印出`LESS`。在几乎所有情况下，这都是很好的，但如果我们的用户提供的输入值是 10，我们的程序将什么也不打印。为了解决这个问题，我们可以使用小于或等于运算符来确保我们的程序始终对用户输入做出响应：

```java
package conditionalstatements; 

import java.util.*; 

public class ConditionalStatements { 

    public static void main(String[] args) { 
        Scanner reader = new Scanner(System.in); 
        System.out.println("Input now: "); 
        int input =  reader.nextInt(); 

        if(input > 10) 
        { 
            System.out.println("MORE!"); 
        } 
        if(input <= 10) 
        { 
            System.out.println("LESS"); 
        } 
    } 
} 
```

现在，让我们快速运行我们的程序，确保它能正常工作。

在 InputStream 窗口中有一个输入提示。让我们首先给它一个大于 10 的值，然后按*Enter*键。我们得到了`MORE`的响应，而不是`LESS`的响应；这是我们预期的结果：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/a1c5ebc2-852f-4f95-8a4f-b36932e7fcbc.jpg)

我们的程序不循环，所以我们需要再次运行它来测试`LESS`输出，这次让我们给它一个值`10`，这应该触发我们的小于或等于运算符。大功告成！

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/9d01689c-e4d7-48ee-bf12-29c9be84c256.jpg)

# 使用 else 语句

事实证明，有一种稍微更容易的方法来编写前面的程序。当我们编写一个条件语句或者说一对条件语句，其中我们总是要执行两个代码块中的一个时，现在可能是使用`else`关键字的好时机。`else`关键字必须跟在带括号的`if`块后面，然后跟着它自己的括号。`else`语句将在前一个`if`括号之间的代码未执行时评估为 true，并执行其括号之间的代码：

```java
import java.util.*; 

public class ConditionalStatements { 

    public static void main(String[] args) { 
        Scanner reader = new Scanner(System.in); 
        System.out.println("Input now: "); 
        int input =  reader.nextInt(); 

        if(input > 10) 
        { 
            System.out.println("MORE!"); 
        } 
       else 
        { 
            System.out.println("LESS"); 
        } 
    } 
} 
```

如果我们运行这个程序，我们将得到与之前相同的结果，只是少写了一点逻辑代码：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/19ce9e8f-2b8f-406a-b701-34809cabf6c7.jpg)

让我们以简要介绍我们的`if`语句中可以使用的其他运算符结束这个话题，然后我们将看看如果需要比较非原始类型的项目该怎么办。除了大于和小于运算符之外，我们还可以使用相等运算符（`==`），如果两侧的项目具有相同的值，则为 true。当使用相等运算符时，请确保不要意外使用赋值运算符（`=`）：

```java
if(input == 10) 
```

在某些情况下，您的程序不会编译，但在其他情况下，它将编译，并且您将得到非常奇怪的结果。如果您想使用相等运算符的相反操作，可以使用不等于（`!=`），如果两个项目的值不相同，则返回 true：

```java
if(input != 10) 
```

重要的是，当比较类的实例时，我们不应尝试使用这些相等运算符。我们只应在处理原始类型时使用它们。

为了证明这一点，让我们修改我们的程序，以便我们可以将`String`作为用户输入。我们将看看`String`是否等同于秘密密码代码：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/60cd30ee-5d55-4ffa-a99a-2b40396097bc.png)

如果是，它将打印出`YES`；如果不是，它将打印出`NO`。现在，NetBeans 给了我们一个警告（如前面的截图所示）；实际上，如果我们尝试使用一些不同的运算符来比较字符串，NetBeans 会让我们知道我们的程序可能甚至无法编译。这是因为 Java 不希望我们使用这些运算符来比较类的实例。相反，类应该公开允许我们逻辑比较它们的函数。几乎每个 Java 对象都有一些用于此目的的函数。其中最常见的之一是`equals()`函数，它接受相同类型的对象，并让我们知道它们是否等价。这个函数返回一个称为**布尔类型**的东西，它是自己的原始类型，可以具有 true 或 false 的值。我们的`if`语句知道如何评估这个布尔类型：

```java
import java.util.*; 

public class ConditionalStatements { 

    public static void main(String[] args) { 
        Scanner reader = new Scanner(System.in); 
        System.out.println("Input now: "); 
        String input =  reader.next(); 

        if(input.equals("password")) 
        { 
            System.out.println("YES"); 
        } 
        else 
        { 
            System.out.println("NO"); 
        } 
    } 
} 
```

让我们快速运行我们的程序，首先输入一个错误的字符串，然后输入`password`来看看我们的程序是否工作：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/e9cf84c3-0f85-40e3-8ba6-3b0c5fb8eaa0.jpg)

这就是`if-else`语句的基础。我现在鼓励你尝试一些我们看过的比较运算符，并尝试在彼此之间嵌套`if...else`语句。

最后一点，有时您可能会看到没有后续括号的`if`语句。这是有效的语法，基本上相当于将整个语句放在一行上。

# 复杂条件

首先，让我们编写一个非常简单的 Java 程序。我们将首先导入`java.util`，以便我们可以通过`Scanner`对象获得一些用户输入，并将这个`Scanner`对象与`System.in`输入字符串链接起来，这样我们就可以在控制台窗口中使用它。

完成这些后，我们需要从用户那里获取一些输入并存储它，因此让我们创建一个新的字符串并将其值分配给用户给我们的任何值。为了保持事情有趣，让我们给自己再增加两个 String 变量来使用。我们将它们称为`sOne`和`sTwo`；我们将第一个字符串变量的值分配为`abc`，第二个字符串变量的值分配为`z`：

```java
package complexconditionals; 

import java.util.*; 

public class ComplexConditionals { 
    public static void main(String[] args) { 
      Scanner reader = new Scanner (System.in); 
      String input = reader.next(); 
      String sOne = "abc"; 
      String sTwo = "z"; 
    } 
} 
```

因为这个话题是关于条件语句，我们可能需要其中之一，所以让我们创建一个`if...else`块。这是我们将评估我们条件语句的地方。我们将设置一些输出，这样我们就可以看到发生了什么。如果我们的条件语句评估为 true 并且我们进入块的以下部分，我们将简单地打印出`TRUE`：

```java
if() 
{ 
    System.out.println("TRUE");     
} 
else 
{ 

} 
```

如果条件语句评估为 false 并且我们跳过块的前一个`if`部分，而是进入`else`部分，我们将打印出`FALSE`：

```java
if() 
{ 
    System.out.println("TRUE");     
} 
else 
{ 
    System.out.println("FALSE"); 
} 
```

# 包含函数

现在可能是时候编写我们的条件语句了。让我向您介绍一个名为`contains`函数的新字符串函数：

```java
if(input.contains()) 
```

`contains`函数接受一个字符序列作为输入，其中包含一个字符串的资格。作为输出，它给我们一个布尔值，这意味着它将输出`TRUE`或`FALSE`。因此，我们的`if`语句应该理解这个函数的结果并评估为相同。为了测试我们的程序，让我们首先简单地通过以下过程。

我们将为我们的`contains`函数提供存储在`sOne`字符串中的值，即`abc`：

```java
package complexconditionals; 

import java.util.*; 

public class ComplexConditionals { 
    public static void main(String[] args) { 
      Scanner reader = new Scanner (System.in); 
      String input = reader.next(); 
      String sOne = "abc"; 
      String sTwo = "z"; 
      if(input.contains(sOne)) 
      { 
           System.out.println("TRUE");     
      } 
      else 
      { 
           System.out.println("FALSE"); 
      } 
    } 
} 
```

因此，如果我们运行我们的程序并为其提供`abcdefg`，其中包含`abc`字符串，我们将得到`TRUE`的结果。这是因为`input.contains`评估为 true，我们进入了我们的`if...else`块的`if`部分：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/886ca0f1-ddab-4e6d-be46-ecb2e2c31df5.jpg)

如果我们运行并提供一些不包含`abc`字符串的胡言乱语，我们可以进入块的`else`语句并返回`FALSE`：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/01e77543-5023-400f-9057-cf280175bef0.jpg)

没有太疯狂的地方。但是，假设我们想让我们的程序变得更加复杂。让我们在下一节中看看这个。

# 复杂的条件语句

如果我们想要检查并查看我们的输入字符串是否同时包含`sOne`和`sTwo`两个字符串呢？有几种方法可以做到这一点，我们将看看一些其他方法。但是，对于我们的目的来说，可能最简单的方法是在`if(input.contains(sOne))`行上使用**复杂**条件。Java 允许我们使用`&&`或`|`条件运算符一次评估多个 true 或 false 语句，或布尔对象。当与`&&`运算符比较的所有条件都评估为 true 时，`&&`运算符给我们一个 true 结果。当与`|`运算符比较的任何条件评估为 true 时，`|`运算符给我们一个 true 结果。在我们的情况下，我们想知道我们的输入字符串是否同时包含`sOne`和`sTwo`的内容，所以我们将使用`&&`运算符。这个运算符通过简单地在它的两侧提供两个条件语句来工作。因此，我们将在`sOne`和`sTwo`上运行我们的`input.contains`函数。如果`&&`运算符的两侧的这些函数都评估为 true，即(`if(input.contains(sOne) && input.contains(sTwo))`，我们的条件语句也将为 true：

```java
package complexconditionals; 

import java.util.*; 

public class ComplexConditionals { 
    public static void main(String[] args) { 
        Scanner reader = new Scanner (System.in); 
        String input = reader.next(); 
        String sOne = "abc"; 
        String sTwo = "z"; 
        if(input.contains(sOne)) 
        { 
            System.out.println("TRUE"); 
        } 
        else 
        { 
            System.out.println("FALSE"); 
        } 
    } 
} 
```

让我们运行我们的程序。`abcz`字符串在两种情况下都应该评估为 true，当我们按下*Enter*键时，我们看到实际情况确实如此：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/a7f9e3c4-ec4b-47c7-945a-83f2a8cbdeff.jpg)

如果我们只提供有效的字符串`z`，我们会得到一个 false 的结果，因为我们的`&&`运算符会评估为 false 和 true，这评估为 false。如果我们使用`|`运算符，这将是字符串：

```java
if(input.contains(sOne) || input.contains(sTwo)) 
```

以下是前面代码的输出：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/434b956d-d20a-4387-acbb-76dfbc0aa772.jpg)

这实际上会给我们一个真正的结果，因为现在我们只需要其中一个函数返回 true。布尔逻辑可能会变得非常疯狂。例如，我们可以将`&& false`语句放在我们的布尔条件的末尾，即`if(input.contains(sOne) || input.contains(sTwo) && false)`。在 Java 中，`true`和`false`代码术语是关键字；实际上，它们是显式值，就像数字或单个字符一样。`true`关键字评估为 true，`false`关键字评估为 false。

任何以`false`结尾的单个条件语句将始终作为整体评估为 false：

```java
if(input.contains(sOne) && false) 
```

有趣的是，如果我们返回到我们之前的原始语句，并运行以下程序，提供它最有效的可能输入，我们将得到真正的结果：

```java
package complexconditionals;
import java.util.*;
public class ComplexConditionals {
    public static void main(String[] args) {
        Scanner reader = new Scanner(System.in);
        String input = reader.next();
        String sOne = "abc";
        String sTwo = "z";
        if(input.contains(sOne) || input.contains(sTwo) && false)
        {
            System.out.println("TRUE");
        }
        else
        {
            System.out.println("FALSE");
        }
    }
}
```

以下是前面代码的输出：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/07c8a447-62db-4e98-b65e-34a9c778ef5d.png)

有趣的是，如果 Java 首先评估`if(input.contains(sOne) || input.contains(sTwo))`语句，然后是`&& false`语句，我们将得到一个 false 的结果；相反，Java 似乎选择首先评估`(input.contains(sTwo) && false)`语句，然后是`||`语句，即`(input.contains(sOne) ||)`。这可能会让事情变得非常混乱。

幸运的是，就像在代数中一样，我们可以要求 Java 按特定顺序执行操作。我们通过用括号括起我们的代码块来做到这一点。括号内的代码块将在 Java 离开括号以评估其他内容之前进行评估：

```java
if((input.contains(sOne) || input.contains(sTwo)) && false) 
```

因此，在我们用括号括起`||`语句之后，我们将计算`||`语句，然后以`false`结束该结果：

```java
package complexconditionals;
import java.util.*;
public class ComplexConditionals {
    public static void main(String[] args) {
        Scanner reader = new Scanner(System.in);
        String input = reader.next();
        String sOne = "abc";
        String sTwo = "z";
        if((input.contains(sOne) || input.contains(sTwo)) && false)
        {
            System.out.println("TRUE");
        }
        else
        {
            System.out.println("FALSE");
        }
    }
}
```

我们现在将看到我们前面的程序总是在这里评估为 false：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/e7c6a449-89cb-44ed-8d2e-a56f6144f07d.png)

复杂的条件可能会变得非常复杂。如果我们在代码中遇到这样的`if`语句，特别是如果这是我们没有编写的代码，可能需要花费很长时间才能弄清楚到底发生了什么。

# 布尔变量

为了帮助我们理解前面部分讨论的内容，我们有布尔变量：

```java
boolean bool = true; 
```

在上一行代码中，`boolean`是 Java 中的一个原始类型，`boolean`类型的变量只能有两个值之一：它可以是`true`或`false`。我们可以将我们的布尔变量的值设置为任何条件语句。因此，如果我们想要简化实际`if`语句中的代码外观，我们可以继续存储这些布尔值：

```java
boolean bool1 = input.contains(sOne); 
boolean bool2 = input.contains(sTwo);  
```

在实际评估`if`语句之前，我们需要这样做，使一切更加紧凑和可读：

```java
if((bool1 || bool2) && false) 
```

记住，游戏的名字是尽可能保持我们的代码简单和可读。一个非常长的条件语句可能写起来感觉很棒，但通常有更加优雅的解决方案。

这就是 Java 中复杂条件的实质。

# Switch，case 和 break

在本节中，我们将看一下`switch`语句，这是我们可以修改程序控制流的另一种方式。

首先，在 NetBeans 中创建一个新项目。至少在我的端上，我要摆脱所有这些注释。为了展示`switch`语句的强大，我们将首先编写一个仅使用`if`块的程序，然后将程序转换为使用`switch`语句的程序。以下是仅使用`if`块的程序的步骤：

1.  首先，让我们简单地声明一个变量`x`（`int x =1;`），这是我们的目标：如果`x`的值是`1`、`2`或`3`，我们想要分别打印出响应`RED`、`BLUE`或`GREEN`。如果`x`不是这些数字之一，我们将只打印出默认响应。

1.  使用`if`块做这件事情相当简单，尽管有点乏味：

```java
if(x == 1) 
{ 
System.out.println("RED") 
} 
```

然后，我们基本上只需复制并粘贴这段代码，并为蓝色和绿色情况进行修改：

```java
int x=1; 
if(x==1) 
{ 
    System.out.println("RED"); 
} 
if(x==2) 
{ 
    System.out.println("BLUE"); 
} 
if(x==3) 
{ 
    System.out.println("GREEN"); 
} 
```

1.  对于我们的默认情况，我们只想检查`x`不等于`1`，`x`不等于`2`，`x`不等于`3`：

```java
if((x != 1) && (x != 2) && (x != 3)) 
{ 
    System.out.println("NONE"); 
} 
```

让我们快速运行一下我们的程序：

```java
package switcher; 

public class Switcher { 
    public static void main(String[] args) { 
        int x=1; 

       if(x==1) 
       { 
           System.out.println("RED"); 
       } 
       if(x==2) 
       { 
           System.out.println("BLUE"); 
       } 
       if(x==3) 
       { 
           System.out.println("GREEN"); 
       } 
    } 
} 
```

以下是预期结果的屏幕截图：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/7e3988b1-d934-4ed0-967b-bce9492aaba4.jpg)

这是我们在编写更大程序的过程中可能会做的事情的简化版本。虽然我们以相当快的速度组织了这个程序，但很容易看出，如果我们要处理许多可能的`x`情况，这个问题将变得非常难以控制。而且，对于某人来阅读和弄清楚这里发生了什么，也是相当困难的。解决方案，你可能已经猜到了，是使用`switch`语句来控制程序的流程。

# 使用 switch、case 和 break 的程序

当我们想要根据一个变量的值执行不同的行或代码块时，`switch`语句非常有效。现在让我们使用`switch`语句来重写我们的一系列`if`块。语法在以下步骤中解释：

1.  我们首先声明我们将使用`switch`语句，`switch`是 Java 中的一个保留关键字。然后，我们提供我们希望`switch`语句作用的变量的名称，在这种情况下是`x`，因为我们将根据`x`的值执行不同的代码块：

```java
package switcher; 

public class Switcher { 
    public static void main(String[] args) { 
        int x=1; 

        switch(x) 
        { 

        } 
    } 
} 
```

然后，就像使用`if`或`else`语句一样，我们将使用两个括号创建一个新的代码段。

1.  现在，我们不再创建一系列难以控制的`if`块，而是使用`case`关键字在我们的`switch`语句中创建单独的代码块。在每个`case`关键字之后，我们给出一个规定的值，如果`x`的值与`case`关键字的值匹配，接下来的代码将执行。

因此，就像我们在做`if`块时一样，如果`x`的值是`1`，我们想要打印出`RED`。现在为每种可能的值编写单独的情况变得更加清晰和易于阅读。

1.  `switch`语句还有一个特殊情况，即`default`情况，我们几乎总是将其放在`switch`语句的末尾。

只有在其他情况都没有执行时，这种情况才会执行，这意味着我们不必为我们最后的`if`块编写复杂的布尔逻辑：

```java
package switcher; 

public class Switcher { 
    public static void main(String[] args) { 
        int x=7; 

        switch(x) 
        { 
            case 1: case 5: case 7: 
                System.out.println("RED"); 
            case 2: 
                System.out.println("BLUE"); 
            case 3: 
                System.out.println("GREEN"); 
            default: 
                System.out.println("NONE"); 
        } 
    }  
} 
```

如果我们运行前面的程序，实际上会看到每种可能的输出都会执行。这是因为我们忘记了做一件非常重要的事情：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/9e4403de-f278-4069-aa68-c503c2128703.jpg)

`switch`语句允许我们创建复杂的逻辑树，因为一旦一个`case`开始执行，它将继续执行，即使通过了队列中的下一个`case`。因为我们正在编写一个非常简单的程序，我们只希望执行一个`case`，所以我们需要在进入一个`case`并完成代码后明确结束执行。

1.  我们可以使用`break`关键字来做到这一点，它存在于一行代码中，并且简单地将我们从当前的`case`中跳出来：

```java
package switcher; 

public class Switcher { 
    public static void main(String[] args) { 
        int x=1; 

        switch(x) 
        { 
            case 1: 
                System.out.println("RED"); 
                break; 
            case 2: 
                System.out.println("BLUE"); 
                break; 
            case 3: 
                System.out.println("GREEN"); 
                break; 
            default: 
                System.out.println("NONE"); 
        } 
    } 
} 
```

现在，如果我们运行我们的程序，我们将看到预期的结果：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/6836df9b-f730-468b-a41d-38a45cb27b2f.jpg)

1.  除了从一个情况自由地转到另一个情况，我们还可以通过在一行中添加多个情况来增加我们的 switch 语句的复杂性和功能。因为情况自由地相互转到，做一些像`case 1: case 5: case;`这样的事情意味着如果我们提供这些数字之一：`1`，`5`或`7`，接下来的代码块将执行。所以这是`switch`语句的快速简单方法：

```java
package switcher; 

public class Switcher { 
    public static void main(String[] args) { 
        int x=7; 

        switch(x) 
        { 
            case 1: case 5: case 7: 
                System.out.println("RED"); 
                break; 
            case 2: 
                System.out.println("BLUE"); 
                break; 
            case 3: 
                System.out.println("GREEN"); 
                break; 
            default: 
                System.out.println("NONE"); 
        } 
    } 
} 
```

以下是前面代码的输出：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/b1feaa12-6894-4d4d-acff-58e1fc2bb4f2.jpg)

Switch 语句基本上是使用等号（`==`）运算符比较我们正在切换的变量或显式值和情况。如果元素不能使用等号运算符进行比较，switch 语句将无法正常工作。

从 Java SE v7 开始，您可以使用等号运算符比较字符串，因此可以在`switch`语句中使用它们。这并不总是这样，而且最好避免在`switch`语句中使用等号运算符与字符串。这是因为它破坏了您正在编写的代码的向后兼容性。

# While 和 do...while 循环

欢迎来到循环的入门课程。在本节结束时，我们将掌握 Java 的`while`和`do...while`循环。我对此感到非常兴奋，因为循环允许我们执行一块 Java 代码多次，正如我们所希望的那样。这是我们学习过程中非常酷的一步，因为能够连续多次执行小任务是使计算机在某些任务上比人类更优越的原因之一：

1.  开始这个话题，让我们创建一个新的 NetBeans 项目，输入`main`方法，然后简单地声明一个整数并给它一个值。我们可以选择任何正值。我们将要求我们的程序打印出短语`Hello World`的次数等于我们整数的值。

1.  为此，我们将使用`while`循环。`while`循环的语法看起来很像我们在写一个`if`语句。我们从保留的`while`关键字开始，然后跟着两个括号；在这些括号里，我们最终会放置一个条件语句。就像它是一个`if`语句一样，只有当我们的程序到达我们的`while`循环并且评估其条件语句为真时，接下来的代码块才会执行：

```java
package introtoloops; 

public class IntroToLoops { 
    public static void main(String[] args) { 
        int i=5; 

        while () 
        { 

        }  
    } 
} 
```

然而，将`while`循环与`if`语句分开的是，当到达`while`循环的代码块的末尾时，我们的程序基本上会跳回并再次执行这行代码，评估条件语句并且如果条件语句仍然为真，则重新进入`while`循环的代码块。

让我们从设置`while`循环的逻辑开始。我们希望循环执行的次数存储在整数 i 的值中，但我们需要一种方法将这个值传达给我们的循环。嗯，任何不会无限运行的循环都需要在循环内容中进行一些控制流的改变。在我们的情况下，让我们每次循环运行时改变程序的状态，通过减少 i 的值，这样当 i 达到 0 时，我们将循环运行了五次。

1.  如果是这种情况，这意味着我们只希望我们的循环在`i`的值大于`0`时执行。让我们暂停一下，快速看一下这行代码。这里`i = i -1`是一个完全有效的语句，但我们可以使用一个更快更容易阅读的快捷方式。我们可以使用`i--`来将整数变量的值减少一。一旦我们设置好这个，唯一剩下的事情就是将功能代码放在我们的循环内；那就是一个简单的`println`语句，说`Hello world`：

```java
package introtoloops; 

public class IntroToLoops { 
    public static void main(String[] args) { 
        int i=5; 

        while (i>0) 
        { 
            System.out.println("Hello world"); 
            i--; 
        }  
    } 
} 
```

1.  现在，让我们运行我们的程序，看看会发生什么：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/b53deb54-febf-49fd-b361-d2f8ac16958b.jpg)

好了，五个`Hello world`实例打印到我们的控制台窗口中，就像我们打算的那样。

# While 循环

通常，我们允许小程序，比如我们在这里编写的程序，在没有更多代码可执行时结束。但是，在使用循环时，我们可能会错误地创建一个无限的`while`循环并运行一个没有结束的程序：

```java
package introtoloops; 

public class IntroToLoops { 
    public static void main(String[] args) { 
        int i=5; 

        while (i>0) 
        { 
            System.out.println("Hello world"); 
        }  
    } 
} 
```

当这种情况发生时，我们需要手动关闭我们的程序。在 NetBeans 中，输出窗口的左侧有一个称为“停止”的方便小功能：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/c7d6f44b-a371-4bc4-becf-8a58f2ef672d.jpg)

如果我们通过命令提示符运行程序，“Ctrl”+“C”是取消执行程序的常用命令。现在我们已经掌握了基本的`while`循环语法，让我们尝试一些更复杂和更动态的东西：

1.  我心目中的程序将需要一些用户输入，因此让我们导入`java.util`并设置一个新的`Scanner`对象：

```java
public class IntroToLoops { 
    public static void main(String[] args) { 
        Scanner reader = new Scanner(System.in); 
```

1.  不过，我们不会立即收集用户输入，而是每次我们的`while`循环成功执行时收集新的用户输入：

```java
while(i > 0) { 
   reader.nextLine(); 
   System.out.println("Hello world"); 
} 
```

1.  每次我们收集这个输入，我们都需要一个地方来存储它，所以让我们创建一个新的字符串，其目的是存储新获取的输入的值：

```java
public class IntroToloops { 
    public static void main(String[] args) { 
        Scanner reader = new Scanner(System.in); 
        String input; 
        int i=5; 
        while(i>0) { 
            input= reader.nextLine(); 
            System.out.println("Hello world"); 
        } 
    }   
} 
```

这个`input`变量的值将在程序执行过程中多次更改，因为在每个`while`循环的开始，我们将为它分配一个新值。如果我们简单地执行这个程序，对我们用户来说将不会很有趣，因为当我们为它分配一个新值时，输入字符串的旧值将不断丢失。

1.  因此，让我们创建另一个字符串，其目的是存储我们从用户那里得到的所有连接值。然后，在我们的程序结束时，我们将打印出这个字符串的值，以便用户可以看到我们一直在存储他们的输入：

```java
public class IntroToloops { 
    public static void main(String[] args) { 
        Scanner reader = new Scanner(System.in); 
        String input; 
        String all = ""; 
        int i=5; 
        while(i>0) { 
            input = reader.nextLine(); 
        }   
        System.out.println(all); 
    }   
}
```

1.  在这里所示的行上将输入的值添加到所有字符串中：

```java
while(i>0) { 
   input = reader.nextLine(); 
   all = 
}
```

我们可以做一些事情。我们可以使用加法运算符很好地添加字符串。因此，`all = all + input`语句，其中`all`和`input`是字符串，加号是完全有效的。但是，当我们将某物添加到它自身并使用原始类型或可以像字符串一样起作用的类型时，我们还可以使用`+=`运算符，它执行相同的功能。此外，我们不能忘记重新实现整数值`i`的递减，以便我们的程序不会无限运行：

```java
package introtoloops; 
import java.util.*; 
public class IntroToLoops { 
    public static void main(String[] args) { 
        Scanner reader = new Scanner(System.in); 

        String input; 
        String all = ""; 
        int i=5; 

        while (i>0) { 
            input = reader.nextLine(); 
            all += input; 
            i--; 
        }  
        System.out.println(all); 
    } 
 }  
```

现在，如果我们运行这个程序并提供五个输入字符串，我们将得到如下屏幕截图所示的输出：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/7c471b2c-2671-4516-a0f3-1eac27ec5548.jpg)

我们将看到它们如预期般全部输出，这很酷，但我对这个程序有更大的计划。

实际上，如果我们只想编写我们在这里拥有的程序，稍后我们将学习的`for`循环可能完全合适。但是对于我们即将要做的事情，`while`和`do...while`循环是非常必要的。我想做的是在这个程序中摆脱我们的计数变量。相反，我们将允许用户告诉我们何时停止执行我们的程序。

当用户将输入的值设置为`STOP`字符串时，以所有大写字母，我们将退出执行我们的`while`循环并打印出他们迄今为止给我们的所有字符串。因此，我们只希望这个`while`循环在输入的值不是`STOP`值时运行。您会注意到，我们将得到一个预编译错误，如下屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/d2271039-64d5-4e5d-8032-3d104f32c4d8.png)

如果我们尝试运行程序，我们将会得到一个完整的编译器错误。这是因为我们的程序知道，当我们尝试执行这个条件语句的时候，输入的值还没有被设置。即使输入的不存在的值不等于`STOP`，这也是非常糟糕的形式。在这里的字符串情况下，它不是一个原始的值，我们的计算机在给它任何值之前是不可能访问它的任何方法的。

这里一个不太优雅的解决方案是给输入一个起始值，就像我们在`all`中所做的那样，但有一个更好的方法。一旦我们的循环执行了一次，我们知道输入将会有一个由用户给出的正确值，这个值可能是`STOP`，也可能不是。

# do...while 循环

如果我们不是在循环的开始检查条件，而是在循环的结束检查条件呢？这实际上是一个选项。`do...while`循环的操作方式与`while`循环相同，但第一次运行时，它们不会检查条件是否为真；它们只会运行并在最后检查它们的条件语句。我们需要在`do...while`循环的后面的条件语句的末尾加上一个分号。我提到这个是因为我总是忘记。现在，如果我们运行我们的程序，我们可以输入任意数量的字符串，然后输入`STOP`字符串，以查看到目前为止我们输入的所有内容并打印到屏幕上：

```java
public static void main(String[] args) { 
    Scanner reader = new Scanner(System.in); 

    String input; 
    String all = ""; 
    int i=5; 

    do 
    { 
        input = reader.nextLine(); 
        all += input; 
        i--; 
    } while(!input.equals("STOP")); 
    System.out.println(all); 
} 
```

以下是前面代码的输出：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/020caa84-f084-411a-b257-0a1e9854a695.jpg)

最后一点说明，几乎任何后面跟着自己代码块的东西，你会看到这样的语法，你会有一个关键字，可能是一个条件语句，然后是后面的括号；或者，你可能会看到括号从与关键字和条件语句相同的行开始。这两种方法都是完全有效的，事实上，括号从与关键字相同的行开始可能很快就变得更加普遍。

我鼓励你玩弄一下我们写的程序。尝试执行你认为会推动字符串所能容纳的信息量边界的循环，或者玩弄一下向屏幕呈现大量信息的循环。这是计算机做的事情，我们简单地无法用铅笔和纸做到，所以这很酷。

# for 循环

在这一部分，我们将快速看一下`for`循环。我们使用`for`循环以非常语义优雅的方式解决 Java 中的一个常见问题。当我们需要迭代一个变量来计算我们循环了多少次时，这些循环是合适的。

首先，我写了一个非常基本的程序，使用了一个`while`循环；它将值`1`到`100`打印到我们屏幕上的窗口。一旦你在脑海中理清了这个`while`循环是如何工作的，我们将使用`for`循环编写相同的循环，这样我们就可以看到在这种特定情况下`for`循环更加优雅。让我们注释掉我们的`while`循环，这样我们仍然可以在下面的截图中看到它，而不执行任何代码，并开始编写我们的`for`循环：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/d4996023-cabc-4c0c-8152-afe66ac3487a.jpg)

`for`循环的基本语法看起来非常类似于`while`循环。我们有保留关键字，在两个括号中我们将放一些循环需要的信息，以及我们将要循环的代码块。与`while`循环不同的是，`while`循环只在这些括号之间提供一个条件语句，而我们将为`for`循环提供大量信息。因为`for`循环设计用于处理特定情况，一旦我们提供了所有这些信息，它就会准确知道如何处理。这减轻了我们处理循环外的代码和在循环内手动递增或递减的需要。它使我们的代码的功能部分，即`println`语句，以及在更复杂的程序中可能在`for`循环内的更复杂的信息，更加独立。

我们典型的`for`循环需要三个输入。它们如下：

1.  首先，我们需要声明我们将要递增或递减以计算我们循环的次数的变量。在这种情况下，我们将使用一个整数`i`，并给它一个初始值`1`。我们在这个初始语句后面加上一个分号。这不是一个函数调用；这是`for`循环的特殊语法。

1.  特殊语法需要的第二个信息是我们需要评估每次重新开始循环时的条件语句。如果这个条件语句不成立，那么我们的`for`循环就结束了，我们继续在`for`循环块之后恢复我们的代码。在这种情况下，我们的条件语句将与`while`循环的条件语句相同。我们希望我们的`for`循环的最后一次迭代是当`i`等于`100`时，也就是当我们打印出`100`时。一旦`i`不再小于或等于 100，就是退出我们的`for`循环的时候了。

1.  就像我们特别给`for`循环的第一个信息使我们不必处理循环范围之外的变量一样，我们将给`for`循环的最后一个信息取代我们在循环范围内手动递增或递减计数器。这是特殊的修改代码，无论我们在这里为`for`循环提供什么，都将在每次循环结束时运行。在这种情况下，我们只想在每次循环结束时递增`i`的值。我想你会同意，这个程序比我们的`while`循环要干净得多：

```java
package forloops; 

public class Forloops { 
    public static void main(String[] args) { 
    /*  int i=1; 
        while(i <= 100) { 
            System.out.println(i); 
            i++; 
        }*/ 
        for(int i=1; i<=100; i++) 
        { 
            System.out.println(i); 
        } 
    } 
} 
```

现在，让我们检查一下它是否执行了相同的任务，即将值从`1`打印到`100`到我们的屏幕上，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/1cb8b21e-035c-4dfc-8e7b-4a57d4888cf2.jpg)

如果这个语句在我们的`for`循环的最开始执行，`0`就是正确的，但是这个语句在最后执行。

当我们在 Java 或任何编程语言中处理大数字和增量时，我们会遇到错误，就像我们刚刚遇到的那样，**一错再错**（**OBOE**）错误。OBOE 是那种即使有经验的程序员也会遇到的小逻辑错误，如果他们不注意或者只是看错了一瞬间。学会识别 OBOE 的症状，例如，输出的行数比预期的多一行，将使我们能够更有效地追踪并找到它们。

# 摘要

在本章中，我们基本上看到了如何使用条件`if...else`语句来运行复杂的条件，使用诸如`contains`、`complex`和`boolean`等函数。我们通过程序详细讨论了`switch`、`case`和`break`的复杂性；此外，我们深入探讨了如何使用`while`、`do...while`和`for`循环的循环功能。

在下一章中，我们将看一下所谓的**数据结构**。
