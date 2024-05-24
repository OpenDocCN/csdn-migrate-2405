# Java 自动化测试初学者实用指南（一）

> 原文：[`zh.annas-archive.org/md5/2fe4dbe3a91a5b3bffbf3ffa1b79bc31`](https://zh.annas-archive.org/md5/2fe4dbe3a91a5b3bffbf3ffa1b79bc31)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

Java 是程序员和开发人员最常用的软件语言之一。您是否来自非技术背景，想要掌握 Java 以满足自己的自动化需求？那么这本书适合您。

本书是一本指南，描述了有效处理与 Java 相关的自动化/项目的技术。您将学习如何在 Java 中处理字符串及其函数。随着学习的进行，您将掌握类，对象及其用法。本书将帮助您了解继承和异常的重要性，并提供实际示例。

通过本书的学习，您将获得全面的 Java 知识，这将帮助您通过任何工作面试。

# 本书适合对象

本书适用于希望进入软件质量保证领域并使用测试框架进行自动化测试的软件开发人员。本书假定您具有编写测试的 Java 编程经验。

# 充分利用本书

在阅读本书的过程中，任何关于 Java 的先前知识都会有所帮助。

# 下载示例代码文件

您可以从[www.packt.com](http://www.packt.com)的帐户中下载本书的示例代码文件。如果您在其他地方购买了本书，您可以访问[www.packt.com/support](http://www.packt.com/support)并注册，以便直接通过电子邮件接收文件。

您可以按照以下步骤下载代码文件：

1.  登录或注册[www.packt.com](http://www.packt.com)。

1.  选择“支持”选项卡。

1.  单击“代码下载和勘误”。

1.  在搜索框中输入书名，然后按照屏幕上的说明进行操作。

下载文件后，请确保使用最新版本的解压缩软件解压缩文件夹：

+   Windows 的 WinRAR/7-Zip

+   Mac 的 Zipeg/iZip/UnRarX

+   Linux 的 7-Zip/PeaZip

该书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/Hands-On-Automation-Testing-with-Java-for-Beginners`](https://github.com/PacktPublishing/Hands-On-Automation-Testing-with-Java-for-Beginners)。如果代码有更新，将在现有的 GitHub 存储库上进行更新。

我们还有来自我们丰富书籍和视频目录的其他代码包，可在**[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)**上找到。去看看吧！

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码词，数据库表名，文件夹名，文件名，文件扩展名，路径名，虚拟 URL，用户输入和 Twitter 句柄。 例如："要检查 Java 是否安装在我们的机器上，请导航到`C:\Program Files`。"

代码块设置如下：

```java
package coreJava;
public class finaldemo {
           public static void main(String[] args) {
               //TODO Auto-generated method stub
```

当我们希望引起您对代码块的特定部分的注意时，相关的行或项目会以粗体显示：

```java
protected void abc() {
    //TODO Auto-generated method stub
  System.out.println("Hello");
}
```

任何命令行输入或输出都以以下形式编写：

```java
$ import package.classname
```

**粗体**：表示新术语，重要单词或您在屏幕上看到的单词。例如，菜单或对话框中的单词会以这种方式出现在文本中。例如："不断点击“下一步”，以便在我们的机器上成功配置 Java。"

警告或重要说明会出现在这样的地方。

提示和技巧会以这种形式出现。

# 联系我们

我们始终欢迎读者的反馈。

**一般反馈**：如果您对本书的任何方面有疑问，请在邮件主题中提及书名，并发送电子邮件至`customercare@packtpub.com`。

**勘误**：尽管我们已经尽一切努力确保内容的准确性，但错误确实会发生。如果您在本书中发现错误，我们将不胜感激地向我们报告。请访问[www.packt.com/submit-errata](http://www.packt.com/submit-errata)，选择您的书，点击勘误提交表单链接，然后输入详细信息。

**盗版**：如果您在互联网上发现我们作品的任何形式的非法复制，请您提供给我们地址或网站名称，我们将不胜感激。请通过`copyright@packt.com`与我们联系，并附上材料链接。

**如果您有兴趣成为作者**：如果您在某个专题上有专业知识，并且有兴趣撰写或为一本书做出贡献，请访问[authors.packtpub.com](http://authors.packtpub.com/)。

# 评论

请留下评论。当您阅读并使用了这本书之后，为什么不在购买它的网站上留下评论呢？潜在的读者可以看到并使用您的客观意见来做出购买决定，我们在 Packt 可以了解您对我们产品的看法，我们的作者也可以看到您对他们书籍的反馈。谢谢！

有关 Packt 的更多信息，请访问[packt.com](http://www.packt.com/)。


# 第一章：Java 中的第一步编程

欢迎阅读《初学者 Java 自动化测试实战》。这是您在互联网上找到的唯一一本教授每个需要的主题，以成为强大的 Java 自动化测试人员的书籍。它包含简单的教学和简单的技术，以有效地处理与 Java 相关的自动化/项目。考虑到我们将详细解释每个核心 Java 主题，这将真正帮助我们开发和评估我们自己的 Java 自动化项目。

所有核心 Java 概念都将从零开始解释。我们不假设读者具有任何先决知识，因此我们认为所有读者都来自非编码背景，并且我们将教授每个读者，并在实时中使用的示例中支持他们。因此，我们不会仅限于理论。

在市场上查找课程时，你应该尝试学习一个新概念。你只会看到三行定义，然后是例子；就是这样。但在这里，我们将了解为什么、何时以及在何处我们在 Java 中使用**面向对象编程系统**（**OOPS**）概念。还将提供适当的编程示例，展示实时使用中的特定 OOPS 概念。这样，我们的书将通过实时项目进行驱动；这完全是关于实际学习。当我们开始使用 Java 集合时，这将发挥作用，比如核心 Java，这是我们书中的主要概念之一，因为你肯定需要从基础开始，并在工作场所开发自动化框架。此外，由于 Java 集合是核心部分之一，在整本书中，我们将非常注意为我们讨论的每个 Java 集合提供所有必要的实际场景。

我们将研究棘手的 Java 程序，查看输出、质数、斐波那契数列和金字塔。我们将按降序排列输出，查看数组矩阵，并打印最大列数。本书将为您提供详细的策略和技巧，这些将帮助您在处理这些程序时需要使用的逻辑。这将帮助您超越界限，获得编写困难 Java 程序所需的逻辑。

本书讨论的程序源自许多公司面试中常见的问题。您将获得有关这些问题的帮助，包括详细的解决方案和处理该逻辑的方法。因此，本书主要侧重于核心 Java。我们不涉及 Swing 和按钮，这在本书中超出了 Java 学习的范围。

在本书中，我们将学习核心 Java、集合和其他概念，如循环、类和数组。这些对于您开始和开发 Java 项目已经足够了。无论您被安排在哪个领域，从本书中获得的知识将帮助您立即开始测试自动化项目。

本章将涵盖以下概念：

+   Java 及其安装简介

+   使用 Java 编辑工具

+   在 Java 中编写您的第一个可执行程序

# Java 及其安装简介

当我们谈论 Java 时，首先想到的是它是平台无关的。这个特性使 Java 成为市场上炙手可热的编程工具。那么平台无关到底意味着什么呢？

我们编写的代码与环境无关；无论是 Windows、Unix、Linux 还是 Solaris。基本上，当我们编写一个 Java 程序时，Java 编译器将程序转换为字节码。当我们运行 Java 代码时，Java 编译器将整个编程代码转换为字节码。例如，我们正在使用 Windows 机器。当我们运行程序时，Java 编译器运行并为我们创建字节码，这个字节码可以在任何其他平台上执行，比如 Linux、macOS 和 Unix。这意味着我们在 Windows 上开发了一个字节码，而这个字节码可以在任何其他平台上运行。这就是我们所说的平台无关性。

这是 Java 编程中我们拥有的一个非常酷的功能。每当你让别人下载 Java 时，你会被问到的第一个问题是，是 JDK 还是 JRE？人们往往会在这两个术语之间感到困惑。在我们开始下载和配置 Java 之前，我们需要对此有清楚的认识。让我们来看看 JRE 和 JDK：

+   **JRE**代表**Java 运行环境**：它负责运行我们的 Java 程序。如果我们的目标只是运行一个普通的 Java 核心代码，那么 JRE 就足够了。

+   **JDK**代表**Java 开发工具包**：它用于调试我们的 Java 代码，或者如果我们想要 Java 文档或类似的东西。

JDK 包含 JRE、Java 文档和调试工具，以及其他很酷的东西。它是一个完整的 Java 工具包，我们将从中获得所有的组件。所以我们下载什么取决于我们，但我建议我们只下载 JDK 以确保安全。如果我们只是想练习和运行我们的程序，JRE 也足够了，但让我们坚持使用 JDK。

现在让我们回去从互联网上下载 Java 并尝试在我们的机器上配置它。要下载 Java，导航到以下页面：[`java.com/en/download/`](https://java.com/en/download/)。当你点击免费 Java 下载按钮时，如下面的截图所示，JRE 版本将被下载：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hsn-auto-test-java-bg/img/dfc3a806-e4d9-41c3-a4b0-93e5b80cb02f.png)

但我们打算在我们的程序中使用 JDK，所以导航到以下网站：[`www.oracle.com/technetwork/java/javase/downloads/index.html`](https://www.oracle.com/technetwork/java/javase/downloads/index.html)。在这里，有多个版本的 JDK。目前市场上最新的版本是 Java SE 10.0.2。点击下载，如下面的截图所示，以便所有组件都被下载并配置在我们的机器上：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hsn-auto-test-java-bg/img/8274c823-c93f-4b54-9241-6883351188d3.png)

配置需要一些时间，因为有相当多的步骤。不断点击下一步，以便 Java 能够成功配置在我们的机器上。要检查 Java 是否安装在我们的机器上，导航到`C:\Program Files`。如果我们在那里找到名为`Java`的文件夹，这意味着 Java 已经成功安装在我们的机器上。`Java`文件夹如下截图所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hsn-auto-test-java-bg/img/1f980050-78d0-4ffb-8832-6595311397bc.png)

这里需要记住的一个重要点是，如果我们是 64 位的，那么我们只会在`Program Files`中看到这个`Java`文件夹。如果我们的机器是 32 位的，那么我们需要回到`Program Files (x86)`去获取`Java`文件夹。

我们可以通过进入控制面板并点击系统来检查我们的系统类型。我正在使用的系统是 64 位的，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hsn-auto-test-java-bg/img/858828f6-6b25-4d5d-ad17-3ec43841d11d.png)

成功下载后，我们进入`Java`文件夹，观察到 JDK 和 JRE 都已经下载。我们进入 JDK 文件夹并复制整个文件路径。我们这样做是因为我们需要设置环境变量。设置环境变量意味着我们让系统知道 Java 文件夹的位置。

在我们的情况下，Java 文件夹位于 `C:/Program Files/Java/JDK`，但 Windows 不知道确切的位置。因此，为了让我们的系统知道这个位置，我们将把 JDK 主目录路径放在系统变量中。这将帮助我们的机器知道 Java 文件夹的位置，这样每当我们运行程序时，它将识别确切的 JDK 版本并运行我们的程序。要在系统环境变量中更新这个，我们复制整个 JDK 路径。转到控制面板，选择系统和安全，选择系统，然后点击高级系统设置。在高级系统设置中，选择环境变量。当我们点击环境变量时，会出现以下窗口：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hsn-auto-test-java-bg/img/f4d11791-9921-4256-b155-13af1ab89a80.png)

当我们在 Rahul 部分的用户变量中点击“新建”，我们将收到一个提示添加新的用户变量。我们将名称设置为 `JAVA_HOME`，将 JDK 路径粘贴到变量值文本框中，然后点击“确定”，如下屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hsn-auto-test-java-bg/img/fec48ef2-7351-4380-99a4-4f9553bd0f73.png)

这就是我们让系统知道`Java`文件夹的确切位置的方法。我们还需要更新另一个变量。为此，我们返回到 JDK 文件夹并进入`bin`文件夹。我们会看到多个`.exe`文件，如下屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hsn-auto-test-java-bg/img/e68a481a-76c8-4ab1-a7c8-d1699e36b519.png)

我们复制`bin`文件夹的位置路径，然后返回到我们的系统属性窗口。在系统变量中，我们会看到一个名为`Path`的变量。双击它将显示一个提示以编辑系统变量，如下屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hsn-auto-test-java-bg/img/90579f51-f2df-409a-97fe-549e89c09ff9.png)

在变量值中，我们到末尾，添加一个分号，并粘贴`bin`文件夹路径。这意味着我们将`Path`变量设置为`bin`文件夹。我们还创建一个名为`JAVA_HOME`的新变量，指向`Java`文件夹。在开始使用 Java 之前，我们需要设置这两个变量。一旦我们设置了这两个变量并点击“确定”，我们将成功设置环境变量。

如果我们想要交叉检查环境变量是否正确配置，我们使用命令提示符。在命令提示符中，我们输入 `java -version` 并按 *Enter*。如果我们得到如下屏幕截图所示的输出，这意味着 Java 已成功配置在我们的系统上：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hsn-auto-test-java-bg/img/d964dad8-c9d9-441b-81b3-78fdb3a09c83.png)

如果我们在添加变量之前运行命令，我们会发现 Java 无法识别。只有在设置系统环境变量之后，我们才能成功配置 Java。

前面的说明已经照顾到了从我们这边安装和配置系统。接下来，我们将尝试下载 Eclipse，这是一个 Java 编辑工具，我们可以在其中编写、运行和调试我们的代码。在下载 Eclipse 之前，我们必须确保 Java 在我们的机器上正确配置。如果安装或配置步骤中的任何一个没有正确完成，Eclipse 将无法正确安装。

# 使用 Java 编辑工具

在这里，我们将看一下我们将用来编写 Java 代码的编辑工具。市场上有许多工具可以作为新的 Java 编辑器，但我个人更喜欢使用 Eclipse。它带有许多内置功能和语法补充。随着我们的进展，我们将看到 Eclipse 的其他优势。有些优势无法在理论上讨论，所以一旦我们进展并开始实际编码，我们将了解它如何提示我们编写正确的语法。因此，在整本书的过程中，我们将在 Eclipse IDE 编辑器中编写所有的 Java 代码。

首先，我们下载 Eclipse IDE 编辑器并查看其提供的界面。以下链接将带我们到 Eclipse 的官方网站：[`www.eclipse.org/downloads/`](https://www.eclipse.org/downloads/)。该网站将看起来像以下屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hsn-auto-test-java-bg/img/6e7d05a0-5c60-4645-abd8-5650a5132707.png)

当我们点击下载 64 位按钮下面的下载包时，它会带我们到下面的页面：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hsn-auto-test-java-bg/img/93e61a00-a37e-4fd4-b666-9836716b7ab4.png)

我们将使用 Eclipse IDE for Java EE Developers。我们可以根据我们正在使用的系统选择 32 位或 64 位。我们已经知道如何检查我们的系统是 32 位还是 64 位，方法是访问控制面板并按照安装阶段给出的说明进行操作。

我们需要确保的一件重要的事情是，我们的 Java 版本与我们下载的 IDE 兼容。如果我们的系统是 32 位并且我们下载了 64 位的 Java，那么 Eclipse 将无法打开。因此，请确保我们的系统、Java 和 Eclipse 版本都在同一条线上。

文件将以 ZIP 文件形式下载，我们可以解压它。下面的屏幕截图显示了`eclipse`文件夹中将存在的文件夹：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hsn-auto-test-java-bg/img/42f48c59-4c10-4c05-8b74-678f8919c8c6.png)

如果我们双击`eclipse.exe`文件，Eclipse UI 将会打开。

如果我们想要编写我们的 Java 代码，我们需要创建一个 Java 项目。右键单击左侧的白色窗格窗口，然后点击新建|项目。这在下面的屏幕截图中显示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hsn-auto-test-java-bg/img/6b2f9f91-9e30-4bf8-b025-9a062ec08a2b.png)

我们会收到提示，告诉 Eclipse 我们正在进行什么样的项目，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hsn-auto-test-java-bg/img/0c733616-f358-4044-91c0-9a6a0c79ff3d.png)

正如我们所看到的，有许多不同的框架可用，比如 Java 项目、C/C++和 Android，但我们只对 Java 项目感兴趣，所以我们选择 Java 项目，然后点击下一步。我们将得到一个新的 Java 项目窗口，在这里我们将填写我们新项目的所有信息，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hsn-auto-test-java-bg/img/b882a9d4-72e6-4fcb-b2eb-987ac4fa0327.png)

我们为我们将要创建的 Java 项目选择一个项目名称。我们将命名我们的第一个项目为`coreJavaTraining`。点击下一步，然后完成。我们将收到一个提示，询问我们是否要打开关联的透视？选择否：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hsn-auto-test-java-bg/img/554a8c9d-9946-41db-ae31-a0d9d9f65ca3.png)

这将成功创建`coreJavaTraining`。在项目中，会自动创建一个源文件夹。这意味着我们需要在这个源文件夹中编写我们的类。什么是类？基本上，所有的 Java 代码都是写在一个类中的。当我们在记事本中写 Java 时，我们打开记事本，写入 Java 代码，并将特定的记事本文件保存为`.java`扩展名。但是在 Eclipse 中，所有这些工作都是由这个工具自己完成的。因此，我们只需要创建一个类，这将给我们一个合适的模板。我们右键单击源（`src`）文件，然后点击新建|类。我们将得到一个 Java 类提示，我们将在其中输入类名。我们将命名这个类为`Firstclass`，并确保我们选择了`public static void main (String[] args)`的复选框；我们将在后面讨论这个的重要性。最后，我们点击完成。这在下面的屏幕截图中显示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hsn-auto-test-java-bg/img/bcb92860-b758-4a6b-8a6b-ee6cd6b6619d.png)

我们可以看到内置的层次结构已经为我们创建好了，因为 Eclipse 创建了一个外部模板。我们可以在编辑器中看到一个类和`public static void main`已经存在。所有这些都是由 Eclipse 工具创建的。如果我们在记事本上正常写作而不使用任何工具，我们需要创建模板。但是在 Eclipse 中，我们只需要给出类名。我们将要输入的代码将被封装在类中；也就是说，在类的括号内。我们在创建文件时使用的任何名称都将成为类名。

所有代码的执行都将放在 `public static void main` 中，因为每当我们运行此文件时，Java 控制将直接转到此块。它不会触及任何在 `public static void main` 之外编写的代码。简而言之，我们在 `public static void main` 块之外编写代码，但最终我们需要在块内调用该代码。这是因为只有 `main` 块负责执行我们的 Java 代码。这就是为什么我们写 `public static void main`。随着我们在本书中的进一步学习，我们将了解 `public` 和 `void` 关键字，因为现在深入了解这些关键字还为时过早。我们可以在以下截图中看到模板：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hsn-auto-test-java-bg/img/3bd15290-1911-47a3-85b8-b329b8fb1658.png)

Eclipse 工具创建的类

# 在 Java 中编写您的第一个可执行程序

让我们从这一节开始进行基本编码。如果我们想要在输出中打印一些内容，Java 中有一个命令叫做 `System.out.println()`。这个命令将在控制台中打印输出。假设我们想要打印 `hello world`，当我们运行以下代码时，`hello world` 将在我们的输出控制台中打印出来：

```java
Firstclass.java
```

所以让我们运行代码。有两种方法来运行代码：

+   在项目资源管理器中右键单击文件名，点击“作为”并选择“Java 应用程序”。

+   或者，我们可以点击工具栏中给出的运行图标，然后在保存和启动窗口上点击 OK。图标看起来像这样：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hsn-auto-test-java-bg/img/8837d0df-f67f-4d4f-8e2c-33e7a974ab22.png)

这将运行我们的代码并打印输出。以下截图显示了我们编辑器中的 `hello world` 消息：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hsn-auto-test-java-bg/img/a6869a1c-2f13-4dbb-a8ac-b77ba30eddd4.png)

根据代码显示输出 `hello world`

简而言之，`System.out.println()` 用于在控制台中打印输出。我们将在几乎所有的实际示例中使用它来演示实际示例。如果我们从语句中删除 `ln`，它将不会在下一行打印输出。

让我们尝试打印一个语句，它将在同一行上显示两个打印命令的输出。在这里，我们在 `hello world` 语句之前添加了一个 `System.out.println("hi")` 语句。如果我们运行代码，输出将如下所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hsn-auto-test-java-bg/img/e9034e84-43a3-4a7a-93b4-422c57de9cad.png)

输出显示在两行上

观察一下 `hi` 是如何显示在一行上，然后 `hello world` 显示在下一行上的。在这里，`ln` 将输出显示在下一行。如果我们从这两个语句中删除 `ln` 并运行代码，消息将显示如下：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hsn-auto-test-java-bg/img/bd42539a-47bd-48ac-9970-12b9a284d555.png)

输出显示在同一行上

我们看到，`hihello world` 打印在同一行上。

如果我们编写代码，然后想部分检查输出，我们不需要删除代码行；我们只需要将其注释掉。我们可以通过在开头简单地放置双斜杠 (`//`) 来将其注释掉，这样 Java 将不会选择这行。这在以下截图中显示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hsn-auto-test-java-bg/img/258a0852-04bc-4505-a21d-4d6e35c487bd.png)

使用双斜杠进行注释

如果您删除斜杠并且语句只是一些随机单词，那么它将抛出错误。我们将看到一个下划线为红色的代码。这意味着在带有交叉标记的行上有一个错误。这在以下截图中显示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hsn-auto-test-java-bg/img/196ae870-4f8f-4f3f-a190-9845e9deb8c9.png)

错误在行号旁边标有一个交叉标记

再次添加反斜杠以注释掉错误。

请记住，这里我们只在 `main` 块中编写我们的实际代码。如果我们想要打印一个整数怎么办？

假设我们想要打印数字`4`。要打印它，我们首先需要将它存储在一个变量中，然后我们将打印这个变量。因此，当我们打印变量时，表示该变量的值将自动打印出来。对于这个例子，我们选择数字`4`，并将数字赋给一个名为`a`的变量。问题在于`a`不知道分配给它的数据类型是什么。因此，我们必须明确说明`a`是一个整数。如果我们不说明`a`是一个整数，它就会报错。

简而言之，我们首先创建一个名为`a`的变量，它只充当整数，然后将整数值`4`放入其中。下面的截图说明了我们所讨论的示例：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hsn-auto-test-java-bg/img/8bafaa90-b7b8-4472-aad2-25032cc69f34.png)

值 4 被赋给变量 a

因此，对于这种类型的代码，我们可以在外部输入，但如果要打印它，我们将不得不在主块中输入它。在这个例子中，我们想要打印`a`的值，所以我们添加了另一个`System.out.println(a)`语句。编辑器将为`print`语句中的变量`a`抛出一个错误。要知道错误是什么，我们将鼠标悬停在错误上，弹出窗口显示错误和可能的修复，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hsn-auto-test-java-bg/img/44424143-5c13-4032-9c0c-70ac34ee85fc.png)

当鼠标悬停在错误上时，会显示错误详细信息

在错误详细信息中将有一个点击选项。这将通过添加所需的内容自动解决错误。这是编辑器具有的一个令人惊讶的功能，随着我们进入更复杂的示例，它非常有帮助。

在我们的示例中，当我们点击错误详细信息弹出窗口中的`将'a'更改为'static'`时，`static`被添加到变量`a`中，我们能够运行代码。运行代码后，控制台将如下所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hsn-auto-test-java-bg/img/697afa9e-3e5a-440f-8fcc-01f96333b0d6.png)

根据代码显示变量 a 的值

我们将在后面的章节中详细了解`static`到底是什么

# 总结

在本章中，我们简要介绍了 Java。然后安装和配置了与 Java 一起工作所需的各种工具。接下来，我们看了一下我们将使用的编辑器来编写我们自己的 Java 代码。

最后，我们执行了我们的第一个示例，看到了编辑器的工作原理以及它如何处理错误。

在下一章中，我们将学习一些基本概念，如字符串、变量和方法，以及它们在代码中的不同之处。


# 第二章：理解 Java 中的类、对象及其用法

在上一章中，我们简要介绍了 Java 以及如何安装我们将在其中输入代码的编辑器。我们还在编辑器上编写并执行了我们的第一行代码。

在本章中，我们将更深入地了解一些基本概念，比如字符串和变量，以及它们之间的区别。我们还将看到方法是什么，以及它们如何与不同的代码一起使用。我们将讨论为什么对象在我们的代码中很重要，以及我们如何可以实现它们。

在本章中，我们将涵盖以下主题：

+   字符串和变量之间的区别

+   使用方法

+   在 Java 中类和对象的重要性

# 字符串和变量之间的区别

在第一章中，*Java 中的第一步编程*，我们打印了一个字符串和一个变量。如果我们仔细观察，当我们打印一个变量时，我们不使用双引号，但当我们打印一个字符串时，我们使用它们。这是因为值已经存在于变量中，因此我们不需要使用任何双引号。如果我们使用它们，Java 会将其视为字符串，并且输出将如下例中的字母`a`打印出来。如果我们运行这个并观察输出，将会打印出字母`a`，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hsn-auto-test-java-bg/img/95c911f9-6b23-4f44-a268-444f52f7de93.png)

输出显示代码中 a 的值

如果我们不使用双引号，Java 会检查是否有任何变量定义为这个字母。如果有，它会打印出该变量中的值。如果没有定义变量，则会出现错误。如果我们注释掉变量声明，我们会看到一个错误。将鼠标悬停在变量上，会得到一个提示，提示说创建一个本地变量'a'，或者我们可以通过添加双引号来使用它：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hsn-auto-test-java-bg/img/701160b8-1228-4ed6-a4ea-2c80aeadbda7.png)

快速修复下拉菜单，提供纠正代码错误的建议

简而言之，如果我们只是使用双引号，那么变量将被视为字符串，但如果我们不使用双引号，我们必须在某处声明变量。这就是打印字符串和打印变量之间的区别。

# 使用方法

基本上，方法是我们 Java 类中的代码块。让我们在这里写一个代码块作为示例，并观察打开和关闭的括号放在哪里。以下示例显示了一个完整的代码块：

```java
public void getData()
{
    static int a=4;
}
```

在这段代码中，我们将代码块命名为`getData()`，`void`是这个方法的返回类型。

如果我们期望从方法中返回一个数字，并且这个数字是一个整数，那么我们必须在`void`的位置写`integer`。对于字符串也是一样；如果我们计划从`getData()`方法中返回一个字符串，那么我们必须将其声明为`string`。如果我们不返回任何东西，也就是说，如果我们只是写了几行代码，那么我们将其保留为`void`。

看一下下面的截图：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hsn-auto-test-java-bg/img/f19e2e43-91e8-49bf-9df8-a86691130e56.png)

为 getData()指定返回类型为 void

在这里，我们没有返回任何东西，所以我们将其保留为`void`。

让我们在`System.out.println(" I am in method");`下面添加一行`return 2;`。在这里，我们返回的是一个整数。这就是为什么我们会在这里收到一个错误。如果我们将鼠标悬停在`return 2;`上显示的错误上，你会看到一个建议，将方法返回类型更改为'int'：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hsn-auto-test-java-bg/img/bbef302b-2ad0-4e6f-ac27-7403c44d3042.png)

快速修复下拉菜单，提供纠正代码错误的建议

点击建议后，我们的 IDE 会自动将返回类型修改为整数，错误就消失了。字符串数据类型也是一样的情况。

我们将在第十章中稍后讨论`public`访问修饰符，*final 关键字、包和修饰符的重要性*。有很多要讨论的，因为 Java 中有不同的访问修饰符，如`public`、`private`、`protected`和`default`。我们将通过适当的示例来看看每个访问修饰符，以便详细解释它们。现在，让我们将所有访问修饰符都视为`public`。

现在你一定想知道为什么 Java 中存在这些方法。它们有什么用途？

假设我们正在执行一个 10 行的代码块，例如，在页面上添加两个整数。现在每次我们到达需要我们添加两个整数的页面时，我们都必须再次编写这 10 行代码。也许复制 10 行代码对于一个实例来说并不重要，但是如果我们需要在整个项目中的 10 个实例中需要这个代码块呢？因此，10 页和 10 行代码使我们在一个 Java 程序中复制了 100 行代码。为了避免这种情况，我们将所有 10 行代码写入一个代码块中，并将该代码块命名为，例如`getData`或其他任何名称。此后，每当我们需要我们键入的 10 行代码时，我们只需调用`getData`方法。所有 10 行代码将进入该特定的代码块，并将被执行。在这种情况下，我们避免了 10 次编写代码；我们只在一个方法中编写一次，并在需要时调用该方法。

让我们通过一个例子来解释这一点：

```java
package coreJavaTraining;

public class Firstclass {

    public void getData()
    {
        System.out.println(" I am in method")
    }
    public static void main(String[] args) {
        System.out.println(a);
        System.out.println("hi");
        System.out.println("hello world");
    }
}
```

在上述类中，我们将考虑“我在方法中”作为我们之前谈到的 10 行代码。我们想要调用这个方法，但是`getData()`块在`main`块之外，这意味着代码无法执行。为了执行它，我们必须将其移动到`main`块内。在大多数情况下，人们只是将代码复制到`main`块内，然后收到错误，因为`main`块内不允许有方法。方法应该写在`main`块外，但在类内。如果我们在类外写点东西，那就没有意义，因为 Java 不会捕捉到它。但是如果我们在`main`块外写方法，我们如何将其放入`main`块内呢？为此，我们需要为包含我们的方法的类创建一个对象。在这里，我们的方法是在`Firstclass`类中定义的，因此我们为这个类创建一个对象，并且通过该对象我们可以访问类中存在的方法和变量。

在下一节中，我们将看到对象是什么，我们在哪里使用它们，以及如何使用对象来调用方法和变量。

# Java 中类和对象的重要性

对象是类的实例或引用。因此，我们可以通过它们的对象调用这个类中存在的方法和变量。我们不能直接调用方法和对象，只能使用它们的对象。因此，首先我们需要为类创建对象，然后我们可以在`main`类中调用方法。

让我们通过之前的例子来解释这一点：

```java
package coreJavaTraining;

public class Firstclass {

    public void getData()
    {
        System.out.println(" I am in method");
    }
    public static void main(String[] args) 
    {
        System.out.println("hi");
        System.out.println("hello world");
    }
}
```

由于`main`块已经在类中，为什么我们需要再次为这个类创建一个对象并调用它呢？

答案是`main`块不可能知道它外部的方法，除非我们创建一个对象来调用该方法。有一个例外，即`static`变量，表示该方法是静态的。因此，一般来说，只有通过对象才能访问其他方法。

# 在 Java 中创建对象

首先，我们需要在类中为对象分配一些内存。可以使用`new`运算符后跟类名来分配内存。然后我们为其定义一个对象名称。返回类型应始终是类名。这是为类创建内存分配的语法。因此，上述示例的内存分配代码将如下所示：

```java
Firstclass fn=new Firstclass();
```

在这里，我们说`fn`是`Firstclass`类的对象。现在我们已经创建了一个对象，让我们看看如何访问它。

# 在 Java 中访问对象

要访问类的方法，我们写入对象名称，然后`.`（点）。所有符合该类的方法都显示在下拉菜单中——这是 Eclipse 中的另一个很棒的功能。我们只需在下拉菜单中查找方法，而不是通过代码搜索它。

在示例中，我们使用了`getData()`方法。显示的其余方法都是内置的 Java 方法。观察方法的显示方式：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hsn-auto-test-java-bg/img/6a444ef7-aadf-4fc7-85cc-748bcd5af95a.png)

下拉菜单显示编辑器可用的所有类方法

单击`getData()`时，`getData()`块将被转移到调用对象的行，当我们运行程序时，代码将被执行，因为它是`main`块的一部分。访问代码最终将如下所示：

```java
fn.getData();
```

让我们看看这个例子的最终代码将是什么样子：

```java
package coreJavaTraining;

public class Firstclass {

    public void getData()
    {
        System.out.println(" I am in method")
    }
    public static void main(String[] args) 
    {
        Firstclass fn=new Firstclass();
        fn.getData();
        System.out.println("hi");
        System.out.println("hello world");
    }
}
```

因此，如果我们运行示例中给出的类，我们的结果将如下：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hsn-auto-test-java-bg/img/816f4740-d7ba-4ca8-a963-eede62592cc2.png)

输出显示我在方法中是代码

我们在输出中看到`我在方法`；这是因为控制从内存分配行开始，创建一个对象，并使用该对象调用该类的方法。控制返回到`getData()`块，并完成该块中存在的代码行；它执行打印语句，我们看到它被打印出来。这就是为什么对象在调用方法时是强大的。

相同的技术可以用于调用整数。假设我们在`a`类中声明一个变量并为其赋值。我们可以通过在`main`方法中添加以下行来打印变量值：

```java
System.out.println(fn.a);
```

这是在 Java 中使用类、对象和方法的一种方式；基本上我们是在封装。

# 在不同类中访问方法

假设我们遇到这样一种情况：我们正在使用一个类，但需要访问另一个类中的对象；这在 Java 中是可以做到的。让我们用一个例子来帮助解释这一点。我们使用两个类，`Firstclass()`（来自*在 Java 中访问对象*部分），然后我们创建一个新类，叫做`secondclass()`。创建新类时，编辑器会创建默认代码，我们可以在其中添加代码。我们添加一个随机方法，`public void setData()`，在其中我们打印`我在第二类方法`语句。

现在，我们希望`Firstclass()`类中有`setData()`方法。基本上我们想在`Firstclass()`中执行`setData()`方法。方法只能通过该类的对象来调用。为此，我们在调用另一个类中的方法的方法中创建一个对象。我们使用与前面示例中用于为对象分配内存的相似代码。以下代码添加到`Firstclass()`的`main`方法中：

```java
secondclass sn= new secondclass();
sn.setData();
```

在`main`类中输入代码时，当我们键入`sn.`来调用方法时，我们将再次获得 Java 中所有方法的选择。由于我们想调用`setData()`，我们从与我们共享的多个选项中选择它。通过为该类创建一个对象，这将成功地将`setData()`带入`Firstclass()`的`main`方法中。

如果我们运行代码，我们将得到以下输出：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hsn-auto-test-java-bg/img/5735c3cf-5d54-4ade-9e34-992f83229f8b.png)

输出显示我在代码中是第二类方法

# 摘要

我们首先讨论了字符串和变量之间的区别，以及它们在代码中的出现方式。然后我们看到了方法是什么，以及如何使用它们来编写我们的代码。之后，我们讨论了类和对象的重要性，以及它们如何用于调用执行类的方法。我们学会了如何为对象分配内存并在执行代码时调用该对象的方法。最后，我们学会了如何使用对象访问另一个类中存在的方法。

在下一章中，我们将更多地了解字符串，并查看`String`类。


# 第三章：在 Java 中处理字符串及其函数

在本章中，我们将讨论字符串并查看`String`类。我们还将学习如何定义字符串以及我们可以定义字符串的不同方式。然后我们将讨论`String`类中的不同方法。最后，我们将编写一些简单的代码来颠倒字符串的内容，并检查颠倒后的字符串是否是回文。

本章将涵盖以下主题：

+   介绍字符串

+   String 类及其方法

+   颠倒字符串的逻辑

# 介绍字符串

字符串是 Java 编程中最重要的概念之一。`String`是 Java 中的预定义类之一。因此，如果你想操作字符串，那么你可以简单地创建这个`String`类的对象，并使用该对象，你可以随心所欲地操作字符串。你可以根据`substring`的概念将字符串分成两部分。我们还可以连接两个字符串。所有这些都可以通过这个`String`类来实现。

让我们尝试自己操纵一个字符串。创建一个新的 Java 类，并将其命名为`stringclassdemo`。

几乎所有与 Java 相关的面试中最常见的问题之一是程序员如何定义字符串。答案是你可以使用以下两种方式之一：

+   通过定义`String`文字

+   通过创建一个`String`对象

现在让我们逐个查看每个方法，以了解定义字符串的不同方式。

# 定义字符串文字

定义`String`文字可以简单地完成，如下所示：

```java
        String a= "hello";
```

我们创建了一个字符串，即`hello`，并将其存储在名为`a`的变量中。这就是我们定义`String`的方式，与定义`String`文字相同。

假设你定义了另一个字符串，如下所示：

```java
        String a= "hello";
        String b= "hello";
```

不幸的是，即使`b`变量也有一个`hello`字符串，`a`变量也有相同的字符串定义。当 Java 程序编译时，它会创建一个名为`a`的`String`对象，并将`hello`赋给它。

现在，在为这个`hello`字符串创建对象之前，`b`变量首先检查`String`池中是否已经定义了任何`hello`字符串实例。如果已经定义，它将简单地将`a`引用到`b`对象，而不是单独创建一个对象。

# 创建一个 String 类的对象

我们创建了一个`String`类的对象，如下行代码所示：

```java
        String ab=new String();
```

现在，要创建一个`hello`字符串，你可以简单地将参数传递给`String`类，如下所示：

```java
        String ab=new String("hello");
```

`ab`对象现在可以对这个`hello`字符串执行所有的字符串操作。

让我们创建另一个字符串，名为`b`，也等于`hello`，如下所示：

```java
        String a=new String("hello");
        String b=new String("hello");
```

然而，在这里，已经使用`a`对象创建了一个`hello`字符串，当 Java 编译器来到`b`对象时，它仍然会创建一个重复的`hello`字符串并将其分配给`b`，因为在这里我们明确地强制它为这个类创建一个对象。尽管已经存在一个重复的对象，它仍然会为这个字符串创建一个对象；然而，在定义`String`文字时，如果对象已经存在于`String`池中，它将不会创建它，而是直接引用已创建的对象。

这就是使用`String`文字对象创建字符串和使用`String`类分别创建对象之间的基本区别。最终，两者都支持`String`方法，但在定义字符串时两种方法之间存在一些差异。

我们刚刚学到的这两种方法有什么区别？两个字符串都可以访问`hello`字符串，但你可以看到它们之间有一些区别。如果你以文字方式声明字符串，那么 Java 会将`hello`赋给`a`变量。这是创建字符串的一种更直接的方式，而不是使用对象创建方法。

在我们大部分常规的 Java 工作经验中，我们更喜欢使用`String`字面量。我们只是声明`a`等于`hello`，就这样。就像你定义整数一样。但是`String`是一个类，在后台，它为这个`hello`字符串创建了一个单独的对象，而整数只是一个引用数据类型，所以在后台不会发生任何事情。

让我们看看我们可以对我们创建的这个`hello`字符串应用什么样的操作。

# 字符串类及其方法

我们有一个`a`变量，这个变量也充当一个对象。当我们在编辑器中输入`a.`时，它会显示`String`类中存在的所有方法，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hsn-auto-test-java-bg/img/29781683-a824-484c-b21b-fa1150b48d12.png)

它将字符串中的第一个字符读为索引零，第二个字符读为索引一，依此类推。在编写程序时，如果你想要获取索引为二的字符，你可以简单地使用以下语句来获取：

```java
        Systme.out.println(a.charAt(2));
```

你可以在输出中打印它，这样你就会看到那个字符。你可能会想为什么我们需要从字符串中获取单个字符，但`charAt`方法经常被使用。在下一节中，我们将看一个可以完全反转字符串的程序。

目前，我们将只是概述这些方法。我们看到了如何获取字符串中特定索引位置的字符。现在让我们尝试反转这个过程。假设我们有一个字符，并且我们需要找到该字符在字符串中的索引值。我们可以使用`indexOf`方法来实现这一点，如下所示：

```java
        Systme.out.println(a.indexOf"e"));
```

运行这个程序。你会看到字符`l`在`2`，`H`在`0`，`e`在索引`1`，`l`在索引`2`。这就是你可以通过`String`方法提取字符和索引的方式。

但是如果我只想从第一个字符到第三个字符提取字符串呢？让我们看下面的例子：

```java
        String a= "javatraining";
        a.substring(3, 6);
```

我们输入`a.`，你会看到有一个`substring`。如果你想要提取从索引`3`开始到索引`6`结束的字符串，这意味着`j`将在`0`，`a`将在`1`，依此类推。它从`2`开始，然后移动到`3`，`4`，和`5`，然后它会打印出类似`vatra`的东西。

如果你想从整个字符串中提取`substring`，那么给出第一个字母的索引和最后一个字母的索引，这样我们的整个字符串将被打印在第一个和最后一个字母之间。请记住还有另一个`substring`方法，使用这个方法，如果你不传递最后一个索引，只传递第一个索引，那么它会从索引`5`打印到最后一个索引，如下所示：

```java
        a.substring(5);
```

让我们打印输出，看看`substring`是如何提取的。这个结果显示在下面的截图中：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hsn-auto-test-java-bg/img/8b700af8-859e-4349-b4e2-13b364f8e9ab.png)

这里，`e`的索引是`-1`，因为在这个字符串中没有叫做`e`的字母。每当没有找到时，它就会打印出`-1`。

这就是`substring`的总结。如果我想要将这个字符串与另一个名为`rahul teaches`的字符串`concat`起来，那么我会这样做：

```java
        String a= "javatraining";
        System.out.priontln(a.concat("rahul teaches"));
```

`a`变量中的`javatraining`字符串将与`rahul teaches`连接起来，并打印输出为`javatrainingrahul teaches`。我们还可以使用`a.length()`，它将给出从零开始的这个字符串的最大长度。还有一种叫做`trim`的类型。假设你的字符串中有一些空格，如下所示：

```java
        String a= " javatraining";
        System.out.println(a.trim());
```

这里，字符串的第一个字符是一个空格，然后是其余的字符。如果你想去掉那个空格，你可以简单地使用`a.trim`。当你打印输出时，这个空格就被移除了。

如果你想打印出所有的大写字母，我们可以使用`a.toUpperCase`。我们也可以使用`a.toLowerCase`来打印所有的小写字母。

还有一个有趣的方法要看一下，那就是`split`。基本上，我们可以根据我们的分隔符来分割整个字符串。为此，我们使用`a.split()`。在这种情况下，我们想要根据代码中的斜杠来分割它，如下所示：

```java
        String a= "java/training";
        System.out.println(a.split(/));
```

这意味着在`/`字符之前的整个字符串应该被分隔为一个字符串，剩下的部分应该被分隔为另一个字符串。这种方法不仅可以用来在斜杠处分割，还可以根据我们想要的任何内容进行分割，如下面的代码所示：

```java
        String a= "javatraining";
        System.out.println(a.split(t));
```

如果我们想要从`t`处分割我们的字符串，那么`java`将成为一个字符串，`raining`将成为另一个字符串。因为我们将有两个字符串，所以我们的输出将把这两个字符串存储在一个数组中，这个数组的返回类型当然是`String`，因为它是在一个`String`中写的，如下面的代码所示：

```java
        String arr[]=a.split("t");
        System.out.println(arr[0]);
        System.out.println(arr[1]);
```

如果你想打印字符串的第一部分，那么它将被存储在数组系统的`0`索引中，如果你想打印字符串的第二部分，那么它将被存储在数组的`1`索引中。

我们在这里要讨论的最后一个方法是`replace`方法，如下面的代码所示：

```java
        String a= "javatraining";
        System.out.println(a.replace("t", "s"));
```

在这里，我们想要用一个随机的`s`替换字符串中的`t`。为此，我们使用`a.replace("t", "s")`，就是这样。打印出来的结果中，字符串中所有的`t`都会被替换成`s`。

这就是`String`方法的全部内容。你仍然可以通过使用`a.`来玩弄它们，并逐步了解不同的方法，但这些是我们在 Java 编程中使用的核心方法。

让我们尝试解决一个基于本节学到的方法的例子。

# 反转字符串的逻辑

在本节中，让我们看看如何以相反的顺序打印字符串。这是雅虎面试中被问到的问题之一。让我们为我们的例子创建一个`reversedemo`类。

我们有一个名为`Rahul`的字符串，我们希望输出为`luhaR`。还有一个概念我们需要了解：回文。如果你输入一个字符串，比如`madam`，然后将字符串反转，输出结果仍然是`madam`。这种类型的字符串被称为**回文**。下面的代码展示了一个回文的例子：

```java
package demopack;

public class reversedemo {

    public static void main(String[] args) {

        String s = "madam";
        String t= "";
        for(int i=s.length()-1; i>=0; i--)
        {
            t= t+ s.charAt(i);
        }
        System.out.println(t);
    }
}    
```

我们将首先创建一个名为`s`的字符串，和一个空字符串，名为`t`。我们创建这个空字符串来在`for`循环之后连接每个元素，以便在控制台中以字符串的形式得到输出；否则，我们可能会得到以下的输出：

```java
m
a
d
a
m
```

使用连接逻辑，我们可以显示输出如下：

```java
madam
```

这是一个简单的逻辑，用于反转我们的字符串，并使用空字符串逻辑以字符串的形式显示它。我们使用了`charAt`方法并实现了我们的反转字符串。一旦我们有了我们的反转字符串，我们可以轻松地将它与原始字符串进行比较——在我们的例子中，这涉及将`t`字符串与`s`字符串进行比较，如果它们匹配，那么我们可以打印出给定的字符串是一个回文。

忘掉回文。这是字符串反转的概念。

# 总结

在本章中，我们介绍了字符串，这是 Java 中更重要的类之一。我们看了不同定义字符串的方法。然后我们看了`String`类下的不同方法。我们看了`String`类中一些常用的方法，在最后一部分，我们看了一个反转字符串的例子，以更好地理解`String`类。

在下一章中，我们将通过示例了解重要的循环和条件。


# 第四章：Java 程序的构建模块-循环和条件

循环和条件是 Java 程序的基本组成部分。本章将通过示例帮助我们理解重要的循环和条件。学习 Java 中的这些循环和条件将使编写代码变得更容易。

在本章中，我们将涵盖以下主题：

+   for 循环

+   if...else 条件

+   while 循环

+   嵌套循环

# for 循环

让我们看看`for`循环的工作原理。`for`循环是 Java 程序中最常用的循环之一，了解它的内部工作原理非常重要。因此，假设我们想使用`for`循环打印从 1 到 100 的数字。对于在`for`循环中执行 1 到 100 的数字的语法，并将其写入`for`循环，我们只需写：

```java
// 1 to 100

/*  for(initialization;condition;increment)
       {
       } */
    for (int i=0;i<100;i++)
    {
        system.out.println(i);
        }
}

```

由于我们想打印`0`、`1`、`2`、`3`，我们使用`i++`。这意味着对于每个循环，它只增加`1`。并且在循环时，每次它还会检查前面的条件是否满足。因此，如果`1`小于`100`，它会进入；如果`2`小于`100`，它会进入。直到满足此条件，它将继续循环。当`i`的值达到`100`时，`100`小于`100`，这是假的。此时，它终止循环并退出循环。我们将在这里使用一个基本示例：

```java
for (int i=0;i<5;i++)
    {
         system.out.println(i);
    }
```

在 IDE 中以调试模式运行测试用例，双击以下截图中显示的位置：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hsn-auto-test-java-bg/img/8aaee5c9-6a2c-43ac-aa74-c02f5b8cb927.png)

调试开始的行

当您看到蓝色图标时，点击像昆虫一样的符号以调试模式运行。它会要求您以调试模式启动。只需点击保存即可：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hsn-auto-test-java-bg/img/b08a7a2c-5824-45ab-b87f-1e0a39473d1b.png)

编辑器顶部的调试图标

您将在这里看到所有变量值。逐步进行，我们将进入循环，并执行程序的下一步：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hsn-auto-test-java-bg/img/efed05a3-dcc2-44de-8712-6fa2acd0e277.png)

调试时的变量值

最后，当它达到值`4`并再次增加`1`时，它是`5`。请注意，当值变为`5`时，它会退出循环而不会进入循环内部。因此，这意味着条件不再满足，循环将运行五次。输出如下截图所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hsn-auto-test-java-bg/img/0142eecc-269f-461a-9c7d-bfb6ce86e060.png)

根据代码的最终输出

所以，这就是`for`循环的工作原理。

现在，如果我们将条件设置为以下内容，即使第一次条件为假，也不会进入`for`循环内部：

```java
for (int i=5;i<3;i++)
```

在调试模式下运行前面的条件时，完整的循环被跳过，输出中什么也看不到。

让我们看另一个例子：

```java
for (int i=0;i<10;i+2 )
```

输出将是：

```java
0
2
4
6
8
```

这就是`for`循环的内部工作原理。

在下一节中，我们将学习`if...else`和`do...while`循环。

# 如果...else 条件

在学习`while`和`do...while`循环之前，我们将在本节讨论`if`条件。在 Java 程序中，当使用`if`条件语句时，仅当条件满足时才执行`if`块中的语句。否则，将运行`else`块中的语句。此执行仅发生一次。在`for`循环中，初始化一个变量，并且循环运行直到条件满足。

然而，在`if`情况下，它不会一直循环。只有在`if`条件满足时，它才会进入循环；否则，它将进入`else`块。因此，控制将执行此`else`块中的语句，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hsn-auto-test-java-bg/img/4c8a86a1-3c08-4821-861f-825c7fcc5da4.png)

根据代码的 if...else 条件输出

但所有这些只发生一次，不像`for`循环，条件满足直到返回并执行。

让我们看看以下示例：

```java
    if(5>2)
    {
        System.out.println("success");
    }
    else
    {
        System.out.println("fail");
    }
```

以下截图显示了这些错误：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hsn-auto-test-java-bg/img/fb0e677a-3ca2-4043-b08f-174fbb5b5db0.png)

快速修复下拉菜单，提供纠正代码错误的建议

第一个错误是删除包含条件，可以忽略。运行上述程序时，您将看到输出为“成功”，因为进入的条件`5`大于`2`是真的：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hsn-auto-test-java-bg/img/f7022ae4-60cb-484f-ba03-1aeef6950efe.png)

输出显示成功，根据代码

如果我们改变条件，使`5`小于`2`，使条件为假，它将跳到`else`块并执行`else`中的语句。

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hsn-auto-test-java-bg/img/ff440aae-1b9c-4108-a23e-5743b9c68173.png)

代码接收失败作为输出

这次输出应该是“失败”，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hsn-auto-test-java-bg/img/08efbbda-6a40-4a3c-94d0-21201524e20c.png)

输出显示成功，根据代码

这就是`if`条件的工作原理。

请注意，如果您的块中只有一行，则可以摆脱这些大括号，因为它最终会假定如果条件为真，则将执行下一行。这意味着如果您的块中只有一行，则可以摆脱大括号。但是，如果您想要有多于一个语句，如果您的条件为真，那么请确保您在大括号中编写以避免冲突。如果您不指定大括号，它仍将打印为“成功”，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hsn-auto-test-java-bg/img/2c1551ea-22ed-4bd1-bee1-09fa506a241d.png)

修改代码后，输出显示成功

在这里，`5`大于`2`。运行此代码时，程序将在没有大括号的情况下运行。

现在，添加一个附加语句，比如“第二步”，它会抛出一个错误，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hsn-auto-test-java-bg/img/5f56dfe4-3c35-4def-9ada-6f9c46bc7967.png)

错误在行号旁边标有一个交叉标记，显示语法错误

请注意前面屏幕截图中标记的标记的语法错误。要么您应该保留一个大括号，要么您应该避免这一步。为了摆脱这一点，我们将整个块都放在大括号中。这样，错误就消失了。

# 将 if...else 条件带入 for 循环

现在，让我们将`if...else`条件带入`for`循环。让我们将以下内容添加到我们的代码中：

```java
for (int i=0;i<10;i=i+2)
{
     if(i==8)
     system.out.println("print 8 is displayed");
     else 
        system.out.println("I did not find");
}
```

由于这里只有一个语句，我们不会将其写在大括号中。现在，让我们分析一下。值将从零开始进入`for`循环，直到该值小于`10`。

进入`for`循环后，它将检查第一个值`0`是否等于`8`。由于它不相等，它将显示“我没有找到”。现在，第二次，`2`将被加到`0`（根据我们设置的条件）。请注意，这个新值仍然不等于`8`；因此对于值`0`、`2`、`4`和`6`，输出将保持不变。接下来，当`8`进入`for`循环时，条件得到满足，并且“8 被显示”语句作为输出显示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hsn-auto-test-java-bg/img/8c71b43a-21c1-4dd2-a8a9-2f73d9d39404.png)

“8 被显示”和“我没有找到”显示为输出

现在，如果我们说`i=9`，它将永远不会被打印，因为我们设置的条件是`i+2`，这将是一个递增的偶数。这意味着条件不满足，并且在`if`条件之后的下一步不会被执行。因此，我们可以说，如果条件为真，那么它才会被执行；如果不是，那么`else`块中的条件或语句将被执行。当您运行此代码时，您总是会得到输出“我没有找到”。

但是，如果我们写以下语法，我们将得到输出“9 被显示”：

```java
for(int i=0;i<10;i=i+3)
```

这就是使用`for`循环的`if...else`条件的工作原理。在下一节中，我们将详细了解`for`循环。

# while 循环

在本节中，我们将详细学习`while`循环。首先，创建一个新类。现在让我们看看在编写代码时如何利用这个`while`循环。假设我们想要按顺序打印从 1 到 10 的数字。我们如何使用`while`循环打印这个？`while`循环的基本语法是：

```java
// While loop

while(boolean)
{

}
```

在这里，如果布尔表达式返回`true`，那么控制权才会进入这个循环，而如果表达式返回`false`，那么控制权就不会进入循环。这就是你对`while`循环的基本简单概念。现在假设我们想要输出从 1 到 10 的数字。为此，我们将编写以下代码：

```java
//While loop 

//1 to 10

int i=0;
while(i<10)
{
      System.out.println(i);
}
```

正如你所看到的，在前面的代码示例中，我们可以看到给定的条件是 true。所以，它进入循环并打印`i`的值。这个循环会一直执行，直到表达式评估为 false。根据我们的例子，条件将始终为 true；因此，它将进入无限循环并打印零。

这就是`while`循环的工作原理。除非在这个参数中条件变为 false，否则这个循环永远不会停止执行。现在，如果我们在打印变量之后递增会发生什么？让我们看看当我们这样做时会发生什么：

```java
//While loop 

//1 to 10

int i=0;
while(i<10)
{
      System.out.println(i);
      i++;
}
```

输出将如下截图所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hsn-auto-test-java-bg/img/a85aed48-a67a-4728-ac07-197732c9b00a.png)

根据代码的 while 条件输出

如果我们使用以下条件：

```java
while(i<=10)
```

新的输出将是：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hsn-auto-test-java-bg/img/e3cd184f-cdc3-4586-9c75-a5b9d32a5402.png)

修改代码后的 while 条件输出

同样，你可以反转条件，如下所示：

```java
//While loop 

//1 to 10

int i=10;
while(i>0)
{
      System.out.println(i);
      i++;//i=2
}
```

输出将会无限循环，因为数字会不断增加，因为`10`大于`0`。

如果我们使用递减条件，它将一直减少直到条件变为 false。之后，它将退出循环，如下面的代码示例所示：

```java
//While loop 

//1 to 10

int i=10;
while(i>0)
{
      System.out.println(i);
      i--;//i=2
}
```

前面的代码示例的输出将是：

```java
5
4
3
2
1
```

因此，这就是我们如何在 Java 程序中使用`while`循环语法。在下一节中，我们将看到如何使用`do...while`循环。

# `do...while`循环

`do...while`循环的语法是：

```java
do
{
}while();
```

让我们考虑以下例子，我们想要打印从 20 到 30 的数字：

```java
    int j=20;
do
{
    j++;
}while(j<30); // 1 loop of execution is guaranteed 
```

前面的代码将打印`20`、`21`、`22`直到`29`作为输出。因此，首先执行，然后再比较。

`while`和`do...while`循环之间的基本区别在于，`while`循环在评估布尔表达式之前不会执行，而`do...while`循环首先执行一次循环，然后评估是否继续执行更多循环。

让我们考虑以下例子，变量的值大于`30`：

```java
int j=20;
do
{
    j++;
}while(j>30); // 1 loop of execution is guaranteed 
```

在这里，输出将是`20`，之后的脚本将被终止，因为正如在本节前面提到的，在`do...while`循环中，执行一个循环是有保证的。如果你在`while`循环中运行相同的逻辑，即使是第一次，它也不会运行。 

因此，在下一节中，我们将尝试进行一个基于`for`循环、`while`循环、`do...while`循环和`if`条件的练习。这些程序将是理解循环的好的实践学习。

在下一节中，我们将学习嵌套循环的工作原理。

# 嵌套循环

这是最重要的概念之一。所有的编程逻辑都来自嵌套循环。如果你能掌握它背后的概念，那么你就能轻松地解决 Java 编程示例。所以，首先我会写一个语法：

```java
for(int i=1;i<=4;i++)  // this block will loop for 4 times
{
}
```

前面的语法意味着循环将运行四次。如果我们在前面的代码块中再写一个`for`循环会怎么样？在循环中实现循环的概念称为**嵌套循环**：

```java
     for(int i=1;i<=4;i++)  
     // (outer for loop) it will loop for 4 times
     {
         System.out.println("outer loop started");
         for(int j=1;j<=4;j++) //(inner for loop)
         {
             System.out.println("inner loop");
         }
         System.out.println("outer loop finished");
     }

```

因此，当我们完成前一个迭代时，一个循环系统就完成了。要完成一个外部循环，我们必须完成所有四个内部循环。这意味着我们必须运行这个内部循环 16 次（四次四次）才能完成这个外部循环四次。

输出如下截图所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hsn-auto-test-java-bg/img/ae3324e7-541a-43bf-8fc4-d712bd9f3431.png)

根据代码的嵌套循环的输出

在更进一步，`for`循环的概念将更频繁地被使用。为了理解`for`循环的概念，让我们尝试解决一些例子。

# 例子 1

编写以下输出的代码：

```java
1 2 3 4
5 6 7
8 9
10
```

正如我们在输出中观察到的，对于每一行，一个数字在递减。我们将在这里看一下外部循环和内部循环的概念。代码将如下：

```java
int k=1;
for(int i=0;i<4;i++)  
// (outer for loop) it will loop for 4 times
     {
         //System.out.println("outer loop started");
         for(int j=1;j<=4;j++) //(inner for loop)
         {
             System.out.print("k");
             System.out.print("\t");
         }
         System.out.println(" ");
    }
```

# 例子 2

编写以下输出的代码：

```java
1
2 3
4 5 6 
7 8 9 10
```

正如您所看到的，这个例子中使用的输出与第一个例子中的输出相反：

```java
int k=1;
for(int i=1;i<5;i++)  
// (outer for loop) it will loop for 4 times
     {
         //System.out.println("outer loop started");
         for(int j=1;j<=i;j++) //(inner for loop)
         {
             System.out.print("k");
             System.out.print("\t");
             k++;
         }
        System.out.println(" ");
     }
```

# 例子 3

以类似的方式，还有一个程序，称为排序数字

编写以下输出的代码：

```java
1
1 2 
1 2 3
1 2 3 4
```

上述输出的代码将是：

```java
    for(int i=1;i<5;i++)  
    // (outer for loop) it will loop for 4 times
         {
              for(int j=1;j<=i;j++) //(inner for loop)
              {
                  System.out.print("j");
                  System.out.print("\t");
              }
              System.out.println(" ");
         }
```

# 总结

通过使用简单的例子，我们学会了如何在 Java 中使用`if...else`条件。我们还看到了如何使用`for`循环和`while`循环来获得所需的输出。更进一步，我们学会了如何使用嵌套的`for`循环来以特定的模式获得输出。

在下一章中，我们将学习一些重要的概念，比如接口，它们的工作原理以及它们在 Java 中的用法。我们还将使用一个实际的例子来讨论继承。


# 第五章：关于接口和继承你需要知道的一切

在这一章中，我们将介绍一些重要的概念，比如接口、它们的工作原理以及它们在 Java 中的使用。我们将使用一个实际的例子来讨论继承。本章还将探讨函数重载和函数重写的概念以及它们之间的区别。

在本章中，我们将涵盖以下主题：

+   接口

+   继承介绍

+   函数重载

+   函数重写

# 接口

接口是 Java 面向对象编程中使用的核心概念之一，因此我们有必要熟悉接口及其用法。

接口和类很相似。接口和类之间唯一的区别是接口有方法但没有方法体。困惑了吗？在类中，我们通常定义一个方法，然后开始编写代码。例如，在一个类中，如果我们想要写任何代码，我们只需从`public void`开始声明类，并在该类中继续编写其余的代码，如下所示：

```java
public void getData()
{
}
```

在接口中，我们只能定义方法的签名；我们不能在方法内部编写任何代码。但是为什么？在接口中写方法签名有什么用？这个面向对象的概念在 Java 中有什么用？你可能会在心中有这些问题，所以让我们尝试用一个现实生活中的场景来理解接口的概念。

# 使用接口与交通灯系统

考虑到典型的交通灯系统，它在世界各地都被用来维护交通规则。每个国家都有自己的交通规则，比如在道路的左侧或右侧行驶。尽管交通规则因国家而异，但有一些规则是全球适用的，需要每个国家遵守。其中一个规则是使用交通灯来管理交通流量，红灯表示停车，黄灯表示准备发动引擎，绿灯表示行驶。假设这些全球规则是由一个中央交通管理机构实施的，我们想要实现，例如，澳大利亚的交通系统。这个系统将有自己的规则，但我们需要确保它遵循中央交通管理机构实施的全球规则。

通过这个例子，我们将尝试理解接口的概念。在这里，中央交通管理机构充当接口，澳大利亚交通规则充当实现接口的类；也就是说，澳大利亚交通系统必须遵循中央交通管理机构接口中提到的规则/方法。在任何接口中定义的方法只是签名，所以类将定义和实现接口中存在的方法。让我们在我们的 Java 代码中看看这个例子。

我们定义接口的方式与定义类的方式相同。在这个交通灯的例子中，让我们将类命名为`CentralTraffic`。我们现在有了一个准备好的接口，如下所示：

```java
package demopack;

public interface CentralTraffic {

    public void greenGo();
    public void redStop();
    public void FlashYellow();

}
```

我们可以看到语法中，我们使用了`interface`而不是`class`。我们使用与在类中定义方法相同的方法在接口中定义方法，但要记住，我们不能在接口中定义方法体，因为这是一个接口，这样做会报错。创建另一个类来实现这个接口，并将其命名为`AustralianTraffic`。一旦我们有了一个 Java 类，我们需要使用`implements`关键字将`CentralTraffic`接口实现到它上面，如下所示：

```java
public class AustralianTraffic implements CentralTraffic {
```

在使用上述句子后，我们的 IDE 会显示一个错误，当你将鼠标悬停在错误上时，会看到一些与错误相关的建议。一个建议是导入`CentralTraffic`，另一个是添加未实现的方法。点击这些建议来解决错误，你应该会得到以下代码：

```java
package coreJava;
import demopack.CentralTraffic;
public class AustralianTraffic implements CentralTraffic {

    public static void main(String[] args) {

    }
    @Override
    public void greenGo() {
        // TODO Auto-generated method stub
        System.out.println(" greengo implementation")
    }
    @Override
    public void redStop() {
        // TODO Auto-generated method stub
        System.out.println(" redstop implementation")
    }    
    @Override
    public void FlashingYellow() {
        // TODO Auto-generated method stub
        System.out.println(" flash yellow implementation")
    }

}
```

在`AustralianTraffic`类中可以看到`CentralTraffic`接口中定义的所有方法，我们也可以根据需要实现这些方法。现在，如果我们从 Java 类中删除`greenGo`方法，它将给我们一个错误。因为它是在接口中定义的方法，我们必须实现接口中定义的所有方法。

接口方法在`public static void main`之外定义，要执行这些方法，我们应该在`main`方法中为它们创建一个类对象，如下所示：

```java
        CentralTraffic a= new AustralianTraffic();
```

这行代码表示我们已经为`AustralianTraffic`类创建了一个对象，以实现`CentralTraffic`接口中存在的方法。主类应该如下所示：

```java
public class AustralianTraffic implements CentralTraffic {

    public static void main(String[] args) {
    CentralTraffic a= new AustralianTraffic();
    a.redStop();
    a.FlashYellow();
    a.greenGo();    
    }
```

现在，在实现接口的方法之后，我们可以在我们的 Java 类中定义我们自己的特定于国家的方法（规则），如下所示：

```java
public void walkonsymbol()
{
    System.out.println("walking");
} 
```

在我们的`main`方法中，如果我们尝试使用`a.`来调用我们的特定于国家的方法，就像我们在`main`类中为其他方法所做的那样，那么我们会发现我们无法这样做，因为`walkonsymbol`方法是特定于特定国家的（即`AustralianTraffic`类），并且它没有在`CentralTraffic`中实现。对于`walkonsymbol`方法，我们需要在`main`类中为`AustralianTraffic`类创建另一个对象，如下所示：

```java
        AustralianTraffic at=new AustralianTraffic();
        at.walkonsymbol();
```

与接口相关的另一条信息是，一个类可以实现多个接口。假设我们创建另一个接口，比如`ContinentalTraffic`，并定义与交通灯相关的另一条规则，比如火车符号表示火车正在通过。我们可以通过在`AustralianTraffic`类中添加逗号来实现这个接口，如下所示：

```java
public class AustralianTraffic implements CentralTraffic, ContinentalTraffic {
```

对于这个接口，我们需要遵循与`CentralTraffic`接口相同的步骤，比如将`ContinentalTraffic`导入`AustralianTraffic`，添加未实现的方法，在主类中创建一个特定于`ContinentalTraffic`的对象等。

现在你对接口和类之间的区别有了一个大致的了解。我们学会了如何定义接口，如何在另一个类中实现它们，以及如何使用对象调用它们。

# 继承

继承是 Java 中另一个重要的面向对象编程概念。让我们以车辆为例来理解继承的概念，就像我们在使用交通灯系统的例子中理解接口一样。车辆的基本属性是颜色、齿轮、镜子、刹车等。假设我们正在制造一辆具有某些属性的新车辆，比如具有更高 CC 的发动机，可能与旧车不同的设计。现在，要创建具有这些新特性的新车辆，我们仍然需要旧车辆的基本特性，比如默认情况下存在的镜子和刹车。

让我们以前面的例子为例，使用 Java 来反映这些关系，以便理解继承的概念。在我们的例子中，如果我们有一个车辆类，并将车辆的基本特征作为该类中存在的方法输入，那么当我们为新车辆创建一个类时，它可以继承为车辆创建的类的特征，我们不必编写这些特征的代码，因为它们通过继承对我们可用。

让我们开始编写代码。创建一个`parentClassdemo`类，这将是我们的父类。在这个类中，我们将定义我们的方法，如下：

```java
package coreJava;
public class parentClassdemo {

    String color = "red";

    public void Gear()
    {
        System.out.println("gear code is implemented");
    }
    public void Brakes()
    {
        System.out.println("brakes code is implemented");
    }
    public void audiosystem()
    {
        System.out.println("audiosystem code is implemented");
    }
}
```

现在我们将在子类中继承这些方法。在 Java 中创建一个`childClassDemo`。我们使用`extends`关键字继承父类，如下所示：

```java
package coreJava;
public class childClassDemo extends parentClassdemo {

    public void engine()
    {
        System.out.println("new engine");
    }
    public void color
    {
        System.out.println(color);
    }

    public static void main(String[] args) {
        childClassDemo cd=new childClassDemo();
        cd.color();
    }
```

在这里，我们使用`extends`关键字在`childClassDemo`类中继承了`parentClassdemo`类。在这个`childClassDemo`类中，我们定义了自己的`engine`方法，并使用了我们从`parentClassdemo`类继承的`color`方法。然后我们创建了一个`cd`对象，并用它来调用从继承类中的方法。

# 更多关于继承的内容

让我们讨论一些关于 Java 继承的臭名昭著的棘手问题和误解。

让我们开始讨论一些关于继承的更为著名的问题。看一下下面的代码块：

```java
class X
{
    //Class X members
}

class Y
{
    //Class Y members
}

class Z extends X, Y
{
    //Class Z members
}
X and Y class and some data fields or methods inside it. The Z class inherits the X and Y classes. Is this allowed? The answer is no. Java does not allows multiple inheritances, whereas it is allowed in C++. So here, we can conclude that the preceding code snippet is not right and will throw an error.
```

这也是继承和接口之间的一个区别，因为接口允许我们同时使用多个接口。

看一下下面的例子：

```java
class A
{
    int i = 10;
}

class B extends A
{
    int i = 20;
}

public class MainClass
{
    public static void main(String[] args)
    {
        A a = new B();
        System.out.println(a.i);
    }
}
```

在这里，我们有一个`A`类，它有一个`i`变量。还有一个`B`类，它扩展了`A`类，并且我们还有它的本地`i`变量设置为`20`。现在，在`MainClass`中，我们为`B`类创建一个对象。这一步实际上意味着什么？在这里，我们正在创建一个对象，并且说这个`B`类的对象应该引用`A`类的属性。虽然我们有权限通过这个`a`对象访问`B`类，但我们只能访问`A`类的属性或方法，因为`B`类在这里有权限访问`A`类，因为我们正在扩展它。

这里的问题是`a.i`会打印出`20`还是`10`？答案是，它会打印出`10`的变量值，因为`A a = new B();`明确告诉`a`它是`B`类的对象，但我们需要访问`A`类中的方法。如果我们想要输出`20`，我们将语法改为`B a = new B();`。

如果你参加 Java 测验或复杂的面试，你可能会遇到这样的问题。这些是你必须了解的关于继承的重要信息，你可以相应地进行计划。

# 函数重载

函数重载发生在一个类中有多个同名方法的情况下。如果我们在类中两次定义了`getData`方法，我们可以说`getData`函数被重载了，就像下面的代码所示：

```java
package coreJava;
//function overloading
public class childlevel extends childClassDemo {

    public void getData(int a)
    {

    }
    public void getData(String a)
    {

    }

    public static void main(String[] args) {
        childlevel cl=new childlevel();
        cl.getData(2);
        cl.getData("hello")
    }
}
```

在使用相同名称的函数的多个实例时，我们需要记住一些规则。第一条规则是函数重载的方法中的参数数量应该不同，第二条是参数数据类型应该不同。如果我们保留两个`getData`方法，都带有`int a`参数，它会抛出错误，所以我们需要为每个方法有不同数量的参数。现在，当你打印这些时，你会得到`2`和`hello`的输出。我们可以看到打印了两个不同的参数，但是使用了相同的方法名。让我们再添加一个带有两个参数的`getData`实例，如下所示：

```java
    public void getData(int a, int b)
    {

    }
```

现在我们有两个具有相同数据类型的`getData`实例，但参数数量不同。

你可能在现实世界中也会遇到函数重载，比如当你在电子商务网站中以分批方式被要求支付方式时。网站可能会使用不同的`getPayment`方法来确认支付——一个`getPayment`方法以借记卡作为参数，另一个`getPayment`方法以信用卡作为参数，另一个`getPayment`可能以礼品卡作为参数。因此，我们向同一个`getPayment`方法传递不同类型的参数。在这种情况下，我们坚持将`getPayment`作为方法名，并传递不同的参数，将函数重载的概念带入到这种特定的情景中。

# 函数覆盖

在这一部分，让我们讨论 Java 中另一个重要的特性——函数覆盖。让我们继续使用我们在学习继承时看到的相同例子。

在这个例子中，我们有一个名为`parentClassdemo`的父类和一个名为`childClassDemo`的子类，子类继承了父类，如下所示：

```java
package coreJava;
public class childClassDemo extends parentClassdemo {

    public void engine()
    {
        System.out.println("new engine");
    }

    public static void main(String[] args) {
        childClassDemo cd=new childClassDemo();
        cd.color();
    }
```

在这里，我们在子类中定义了`engine`方法，它打印一个新的引擎，还有另一个方法`color`，它在父类中定义，并且我们使用一个对象来调用它。如果我们打印这个，我们将得到`color`方法的输出，因为它在父类中定义。现在，我们在子类中创建一个新的方法，也将其命名为`color`，并定义如下：

```java
    public void color()
    {
        System.out.println("update color");
    }
```

我们有两个`color`方法的实例——一个在父类中定义，另一个在子类中定义。这就是函数重写概念发挥作用的地方。如果你运行子类，你将得到`update color`的输出。这是因为子类中定义的新`color`方法覆盖了父类中的`color`方法。

这总结了函数重写的整个概念，其中两个方法具有相同的名称、签名和参数。在函数重载中，我们有具有相同名称但不同参数的方法。这是函数重载和函数重写之间的一个主要区别。

# 总结

在本章中，我们介绍了一些重要的 Java 面向对象编程概念，如接口、继承、函数重载和函数重写。我们通过示例来看每个概念，这有助于我们更详细地理解这些概念。

在下一章中，我们将介绍 Java 代码中最重要的概念之一：数组。我们将看到不同类型的数组是如何样的，以及如何初始化和显示它们。


# 第六章：了解有关数组的一切

在本章中，我们将看一下 Java 代码中最重要的概念之一：数组。我们将看到不同的数组是如何样的，以及如何初始化和显示它们。我们还将看一些练习，以帮助我们更好地理解数组的工作原理。

我们将在本章中涵盖以下主题：

+   Java 程序中的数组及其用法

+   初始化数组和分配对象的方法

+   多维数组的逻辑编程

+   练习

# Java 程序中的数组及其用法

也许我们以前曾听说过数组这个术语，所以让我们看一下数组是什么，通过解释和一个例子。

数组是存储相同数据类型的多个值的容器。

在下面的例子中，我们将看到容器是什么，如何定义该容器，以及我们如何在其中存储值。

如果我们想要使用数组，我们可以使用以下代码为它们分配一些空间来声明它们：

```java
int a[] = new int[];
```

`new`关键字基本上为数组中的值分配内存。方括号表示我们正在将多个值添加到方括号中，`[]`表示数组的术语。要定义数组，我们必须为将要存储在其中的多个值创建空间。在这个例子中，我们计划存储在数组中的有五个整数值，这就是为什么我们指定了数组数据类型为整数，并且要添加的变量数量在方括号中给出：

```java
int a[] = new int[5];
```

正如我们在第三章中观察到的，*在 Java 中处理字符串及其函数*，如果值是字符串，我们将指定数组数据类型为`String`。

我们已经声明了一个数组并为值分配了内存，现在我们需要传递这些值。第一个值将被放在索引`0`中，第二个值将被放在索引`1`中，以此类推，对于所有五个值都是如此。索引命名从`0`索引开始，因此第一个值将被分配给`0`索引。这意味着我们实际上在数组中初始化了值。现在`a`数组包含了我们分配给它的所有值。对于我们的例子，我们为数组声明任意随机值。

现在让我们从数组中检索值。为此，我们在`main`类中声明数组的值后创建一个`for`循环，并在此之后留下一个打印语句：

```java
for(int i=0; i<a.length;i++);
{
    System.out.println(a[i]);
}
```

我们的起始点已经设置为索引`0`，限制已经设置为数组的长度。看一下`i<a.length`的代码，`length`是一个实际返回数组大小的方法。

在运行代码时，我们看到分配给数组的所有值都一个接一个地打印出来。在下一节中，我们将看到声明和初始化所有数组值的更简单的方法。

# 初始化数组和分配对象的方法

在上一节中，我们看到了如何声明数组；最简单的方法是以数组文字的形式。让我们用一个例子来解释这个。

我们通过在上一个例子中输入以下代码行来声明另一个数组：

```java
int b[] = {1,4,3,5,7,8};
```

在上一个例子中的声明和我们在这个例子中执行的声明之间有什么区别？

在上一个例子中，我们正在分配内存，然后赋值。在这个例子中，我们不是分配内存，而是直接将值传递给数组。在这里，内存是动态分配的，如果我们在数组声明中添加一个值，将自动分配内存并将值传递给它。在大多数情况下，编码人员使用这种方法来声明数组值，而不是声明分配然后赋值。

与上一个例子类似，第一个值分配给索引`0`。如果我们编写类似于上一个例子的打印语句并运行代码，我们将看到`b`数组的值被显示出来。

这就结束了单维数组；让我们谈谈多维数组。

# 多维数组

在*x*轴和*y*轴传递对象就是一个多维数组。其中*x*轴是行，*y*轴是矩阵中给定数组值的列。在这种情况下，multi 意味着我们从多个角度查看数组；这被称为**多维**数组。以下是我们创建的一个多维数组，用来解释这个概念：

```java
2  4  5
3  4  7
5  2  1
```

这是一个矩阵，它有三行三列。`2`在零行零列，旁边的`4`在零行第一列，其他值的迭代也是一样的。所以每个参数都有一个*x*轴和一个*y*轴。

让我们举个例子来解释这一点。我们将创建另一个类，命名为`Multidimensional.java`，并在其中声明一个多维数组`a`：

```java
int a[][] = new int[2][3];
```

第一个括号代表*x*轴或行，第二个代表*y*轴或列。因此，*x*轴有三个值，这意味着三行，*y*轴有三列。然后我们为我们创建的矩阵的每个元素分配值，以解释多维数组。以下代码显示了如何为矩阵分配值：

```java
a[0][0]=2;
a[0][1]=4;
a[0][2]=5;
a[1][0]=3;
a[1][1]=4;
a[1][2]=7;
```

这样我们将所有的值都输入到一个多维数组中。如果我们想要显示第二行第一列的值，我们写一个打印语句并给出我们想要显示的元素的位置。在这种情况下，我们想要显示第二行第一列，所以打印语句将写成：

```java
System.out.println(a[1][0]);
```

打印语句将显示`3`，这是该位置元素的值。在下一节中，我们将举一个例子来帮助解释如何在解决编码中使用所有这些概念。

我们如何打印在这个例子中声明的数组 a 的所有值？在之前的例子中，我们通过简单地创建一个`for`循环，将其迭代从`0`到数组的长度，并显示数组来打印数组。

如果我们想要以最简单的格式声明一个多维数组，就像在上一个例子中描述的数组`b`一样，我们可以按照以下方式写：

```java
int b[][]= {{2,4,5},{3,4,7},{5,2,1}};
```

数组将假定括号中的值在零索引中，第二个在第一个索引中，第三个在第二索引中。这是声明多维数组的最简单方式。

# 多维数组的逻辑编程

现在我们将看一下如何打印在上一节中使用的整个多维数组 a 的所有值。

如果我们分析数组的声明，我们会发现需要两个`for`循环来打印整个数组，一个用于行，一个用于列。

我们希望控制器扫描完整的第一行，然后是第二行，最后是第三行。因此，我们为行添加一个外部的`for`循环，并将长度限制设置为数组中的行数，在这种情况下是两行。行的外部`for`循环将如下所示：

```java
for(int i=0;i<2;i++)
```

这个`for`循环实际上会循环两次，因为我们为行设置了限制为`2`。第一个循环将扫描第一行，第二个循环将扫描第二行。现在对于每个循环，我们需要扫描该特定行中存在的三列。为此，我们添加一个内部的`for`循环，它将扫描每一列，并将限制设置为数组中的列数，对于这个例子来说是`3`。列的内部`for`循环将如下所示：

```java
for(int j=0;j<3;j++)
```

最后，为了打印数组，我们在内部的`for`循环中添加一个打印语句来显示所有的值。最终的代码将如下所示：

```java
for(int i=0;i<2;i++) //row
{
    for(int j=0;j<3;j++) //coloumn
    {
        System.out.println(a[i][j]);
    }
}
```

让我们试着理解我们在这里写的内容。控制将从外部的`for`循环开始；这个外部的`for`循环执行两次，因为它被设置为小于`2`。第一次进入外部的`for`循环后，它进入内部的`for`循环；这个循环执行三次，因为`j`被设置为小于`3`。

让我们调试一下，看一下代码中的一些步骤，以更好地理解这些循环。以下是在调试代码时将执行的步骤：

1.  控制器第一次执行外部循环，`i`的值已经初始化为`0`，这意味着*x*轴的值设置为`0`。控制器将查看第一行，因为`0`表示正在访问第一行。

1.  它移动到内部的`for`循环并执行它，`j`的初始值已经初始化为`0`；这意味着*y*轴的值被设置为`0`。控制器将查看第一行和第一列，因为它已经在第一行，由于外部循环。内部循环将控制器发送到第一列。

1.  `a`将取第一行和第一列的值，因为`i`和`j`的值被初始化为`0`，`a[0][0]`。因此，这次执行的输出将是第一行和第一列，在这个例子中是`2`。

1.  控制器再次移动到内部的`for`循环，因为循环的条件仍然满足，因为`j`被迭代为`1`，小于`3`；这意味着*y*轴的值被设置为`1`，它将访问第二列。控制器将查看第一行和第二列，因为它已经在第一行，由于外部循环和内部循环将控制器发送到第二列。

1.  `a`将取第一行和第二列的值，因为`i`和`j`的值设置为`0`和`1`，`a[0][1]`。因此，这次执行的输出将是第一行和第二列，在这个例子中是`4`。

1.  控制器再次移动到内部的`for`循环，因为循环的条件仍然满足，因为`j`被迭代为`2`，小于`3`。这意味着*y*轴的值被设置为`2`，它将访问第三列。控制器将查看第一行和第三列，因为它已经在第一行，由于外部循环和内部循环将控制器发送到第三列。

1.  `a`将取第一行和第三列的值，因为`i`和`j`的值设置为`0`和`2`，`a[0][2]`。因此，这次执行的输出将是第一行和第三列，在这个例子中是`5`。

1.  当控制器现在进入内部循环时，它将无法执行，因为`j`再次被迭代后的值将为`3`，这不小于我们为循环设置的限制。因此，控制器退出内部的`for`循环，回到外部循环，并将`i`的值迭代为`1`；这意味着*x*轴的值被设置为`1`。控制器将查看第二行，因为`1`表示正在访问第二行。

1.  步骤 2、3、4、5、6 和 7 再次重复，但这次*x*轴的值`i`被设置为`1`；这意味着将访问第二行。根据先前指定的步骤，显示第二行中的所有值，直到达到矩阵的第三列。

1.  控制器在访问第三列后退出内部循环，因为`j`将被迭代为`3`，小于我们为循环设置的限制。因此，控制器再次退出内部的`for`循环，并开始执行外部循环。

1.  在外部的`for`循环中，`i`的值将被迭代为`2`，并且循环不会被执行，因为它不小于`2`，这是我们为它设置的限制。

这就是使用两个`for`循环获取多维数组值的方式，其中外部循环处理行，内部循环处理列。

# 练习

让我们尝试一些练习，这些练习将帮助我们理解和处理数组。这些练习还将在面试时解释概念。

# 打印一个 3 x 3 矩阵中的最小数

让我们为这个练习创建另一个类，命名为`InterviewMinnumber`，并在主块中定义数组。定义代码将如下所示：

```java
int abc[][]={{2,4,5},{3,2,7},{1,2,9}};
```

这段代码声明了一个名为`abc`的 3x3 矩阵。现在我们需要遍历矩阵中的每个数字，并找到其中的最小数。为了遍历多维数组中的每个数字，我们需要使用我们在*多维数组上的逻辑编程*部分中使用的相同概念。

我们在这里使用两个`for`循环：一个外部的`for`循环用于遍历行，一个内部的`for`循环用于遍历列。两个`for`循环的代码将如下所示：

```java
for(int i=0;i<3;i++)
    {
    for(int j=0;j<3;j++)
    {
    }
}
```

为了找到最小数，我们声明一个变量`min`，并将`abc`数组的第一个值赋给它。我们假设`abc`矩阵中的第一个值是最小值。

我们在内部的`for`循环中添加一个`if`循环。在这个`if`循环中，无论我们写什么都将扫描我们声明的整个矩阵中的每个元素。在`if`循环中，我们添加一个条件，检查在那个实例从矩阵中取出的值是否小于`min`值。在`if`循环中，我们交换`min`和`abc`的值。最终的代码将如下所示：

```java
public class InterviewMinnumber 
{
    public static void main(String[] args) 
    {
        int abc[][]={{2,4,5},{3,2,10},{1,2,9}};
        int min=abc[0][0];
        for(int i=0;i<3;i++)
        {
            for(int j=0;j<3;j++)
            {
                if(abc[i][j]<min)
                {
                    min=abc[i][j];
                }
            }
        }
        System.out.println(min)
    }
}
```

让我们运行代码，看看它是如何找到矩阵中的最小数的。

当循环第一次执行时，矩阵中的第一个元素的值与`min`变量的值进行比较，但我们将`min`变量的值设置为第一个元素的值，即`2`。我们检查`if`循环中的条件，它比较矩阵中的元素的值和`min`的值。这里，`2`不小于`2`，所以它不进入循环，而是再次回到代码的开始。在循环的下一轮中，元素的值会改变，因为我们移动矩阵中的下一个元素。现在被比较的元素是`4`，我们再次检查`if`条件，它不会成立，因为`4`不小于`2`，而`2`是`min`的当前值。最后，当它到达第三行第一列的元素`1`时，`if`条件成立，控制器进入循环并将`1`赋给`min`的值。这将一直持续到数组矩阵中的最后一个元素，其中`abc`矩阵的每个值都与`min`变量的值进行比较。

如果我们调试代码并观察每一步，我们将更好地理解这段代码的逻辑和工作原理。

# 显示最小数所在列的最大数

在上一个例子中，我们观察了如何打印数组矩阵中的最小数。在这个例子中，我们将寻找矩阵中的最小数，然后在同一列中寻找最大数。这背后的逻辑是：我们首先找到最小数，记住它所属的行号，然后提取同一列中的最大数。

让我们使用在上一个例子中使用的相同矩阵。我们使用的矩阵的输出将是`4`。以下步骤将被实施来执行这个练习：

1.  找到我们声明的矩阵中的最小值

1.  识别最小数的列

1.  找到已识别列中的最大数

我们已经在上一个例子中执行了第 1 步，在那里我们找到了矩阵中的最小数，所以我们将使用相同的代码来进行这个例子，只是稍微改变一下变量：

```java
int abc[][]={{2, 4, 5}, {3, 0, 7}, {1, 2, 9}}
```

让我们继续进行第 2 步。如果我们观察代码，我们会发现`i`代表行号，`j`代表列号。所以`j`将取得最小数所在的列的值，我们将这个`j`的值赋给一个名为`mincolumn`的变量。所以我们在交换命令下编写代码，将`j`的值赋给`mincolumn`。代码将看起来像这样：

```java
mincoloumn=j;
```

所以当我们在矩阵中找到最小的数字时，我们将其赋值为`j`的值，即`mincloumn`的列号。在这种情况下，`mincolumn`的值将是`1`。这就完成了第 2 步。

在第 3 步中，我们从包含最小数字的列中寻找最大数字。我们在外部创建了一个`while`循环，该循环是我们用来查找矩阵中最小数字的外部`for`循环。我们将条件变量`k`初始化为`0`，并在每次满足`while`循环条件时迭代它。`while`循环的条件设置为`k`小于`3`；这是因为我们有三行要遍历以查找它们中的最大值。`while`循环的代码如下：

```java
while(k<3)
{
    k++;
}
```

我们声明一个名为`max`的变量，并给它一个初始值，即第`0`行和第`mincolumn`列。这样一来，变量`max`的初始值将是`4`，因为`4`是矩阵中包含最小数字的行中的第一个元素。声明代码如下：

```java
int max=abc[0][mincoloumn];
```

在`while`循环中，我们添加了一个`if`循环，并设置了一个条件，比较具有最小数字的列中的变量是否大于我们声明的变量`max`。如果条件满足，该数字的值将被赋给`max`变量，并且控制器在迭代`k`加`1`后从`if`循环中移出，并返回到`while`循环。迭代将使控制器转到下一行，因为`k`用于表示正在遍历以查找最大数字的行。

`if`循环的代码如下：

```java
if(abc[k][mincoloumn]>max)
{
    max=abc[k][mincoloumn];
}
```

因此，对于`k`的第一个值，即`0`，我们转到第一行和第二列，并将值赋给`max`；在这个例子中，值为`4`。在`if`条件中，我们将第一行第二列的值与`max`的值进行比较。在这个例子中，两个值是相同的，所以`if`循环不会被执行，我们迭代`k`并再次进入`while`循环。接下来，我们将第二行第二列的值与`max`的值进行比较；我们转到第二行，因为`k`的值被迭代了`1`，当前的`k`值是`1`。因此，在比较时，我们发现`o`小于`4`，其中`4`是`max`变量的值。条件再次不满足，`if`循环再次被跳过。这对于第三行也是一样的，`max`的最终值是`4`，这是该列中最大的数字。最后，我们留下一个打印语句来打印`max`的值。

# 使用/不使用临时变量交换变量

在这个练习中，我们将交换简单数组中元素的位置，并将它们按升序放置。

为了做到这一点，我们首先需要理解它的工作逻辑。让我们举个例子来解释一下。

我们初始化`a`数组并在其中声明值，如下面的代码所示：

```java
int a[]= {2,6,1,4,9};
```

我们可以使用冒泡排序机制来比较变量，并将它们按照我们想要的顺序放置。对于上面的例子，逻辑的工作方式如下；我们将`2`与`6`、`2`与`1`、`2`与`4`和`2`与`9`进行比较。在这次比较后，最小的数字是`1`，我们将其位置与第一个索引交换，即`2`。因此交换后，`1`将成为新的第一个索引。这意味着`1`是数组中给定值中最小的数字。现在我们移动到第二个索引，我们不会触及第一个索引，因为我们已经比较并声明`1`为固定的第一个索引，因为它是数组中最小的数字。现在我们取值`6`，它是第二个索引，并将其与数组中的其他值进行比较。首先我们比较`6`和`2`，由于`2`小于`6`，我们交换它们的位置，所以`2`是新的第一个索引，`6`是第二个索引。然后我们比较`2`和`3`；基本上我们是将第一个索引与数组中的所有其他值进行比较。然后我们将`2`与`3`、`2`与`4`和`2`与`9`进行比较；这里`2`是最小的数字。所以`2`成为数组中固定的第二个索引。现在我们还剩下四个需要排序的值。我们再次将`6`与其他值进行比较。`6`小于`3`，所以我们交换`6`和`3`的位置。这使得`3`成为数组中的第三个索引，我们将`3`与其他数字进行比较，`3`是其中最小的。所以`3`成为数组中固定的第三个索引。然后我们对最后三个值执行相同的操作，并得出最终的排列将是`1`、`2`、`3`、`4`、`6`、`9`。现在我们需要在 Java 程序中应用这个逻辑并打印它。

我们将为我们的逻辑决定一个算法，并根据算法逐步设计我们的代码。我们将编写一个外部的`for`循环，移动一个索引并与其余部分进行比较。

我们编写一个外部的`for`循环，并设置条件不要越过数组的长度；这里数组大小为`5`，所以条件设置为`i`小于`5`。如果`i`为`0`，变量值将与第一、第二、第三和第四个变量进行比较。如果`i`为`2`，变量将与第三和第四个变量进行比较。所以无论`i`索引是什么，它都应该开始比较`i`的值与其下一个索引的值。为此，我们将创建一个内部的`for`循环，并将`j`初始化为始终比`i`多一个数字，即`i`加`1`，因为我们将与下一个索引进行比较。所以，如果`i`等于`0`，`j`将为`1`。因此，零索引将从第一个索引开始比较。我们将比较直到数组的末尾，所以我们将内部的`for`循环的限制设置为`j`，因为它小于数组的长度，在这个例子中为`5`。

然后我们在内部的`for`循环中添加一个`if`循环。这个循环将在索引之间进行比较，并在满足条件时交换值。一旦第一轮比较完成，控制器退出内部的`for`循环，回到外部的`for`循环，这时进行比较后选择最小的数字，将其推到角落，并且索引移动到下一个值。

现在我们回到`if`循环内部，并编写代码在比较条件为真时交换值。为了交换变量的值，我们需要声明一个`temp`变量，并将`a[i]`的数字赋值给`temp`。我们添加以下代码成功交换变量：

```java
temp=a[i];
 a[i]=a[j];
 a[j]=temp;
```

最后，我们添加一个打印语句，显示经过比较和重新排列值后的最终数组。

最终输出将显示如下：

```java
1
2
4
6
9
```

# 总结

在本章中，我们涵盖了数组中的各种概念。我们看了不同类型的数组，以及它们如何被初始化和显示。然后我们进行了不同的练习，以了解我们如何在不同情况下使用数组。

在下一章中，我们将讨论为什么`Date`类和构造函数是 Java 的重要部分。


# 第七章：在 Java 11 中理解 Date 类和构造函数

`Date`类和构造函数是 Java 的重要部分。在本章中，我们将通过一些例子详细讨论这些内容。

在本章中，我们将涵盖：

+   日期类

+   日历类

+   构造函数

+   参数化构造函数

# 日期类

为了理解`Date`类的概念，我们将从创建我们的`dateDemo`类的源代码开始。假设我们想要打印当前日期或当前时间。我们该如何打印呢？

有时，我们被要求输入日期到当前日期字段中，我们需要从 Java 中获取它。在这种情况下，我们将使用`Date`类，它将给我们当前日期和当前时间，以及秒数。因此，关于日期、星期、月份、年份或小时的每个细节都可以通过 Java 类来读取。Java 开发了一个叫做`Date`的类，我们可以从中获取所有这些细节。以下截图显示了源代码：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hsn-auto-test-java-bg/img/2127fc87-0ea8-4136-89ad-c91a2b6ad5d1.png)

显示使用日期类的源代码

基本上，我们需要使用那个特定类中存在的方法。要使用该类中存在的方法，我们需要创建该特定类的对象。为此，让我们考虑以下代码语法：

```java
Date d= new Date();
```

这个`Date`类来自`util`包，`d`是`Date`类的对象，其中包含日期和时间。在前一章中，我们看到 Java 有一些包，比如`java.lang`包，其中包含了所有基本的 Java 东西，还有`java.util`，其中包含了集合框架和`Date`类。

前面的代码语法表明我们不知道`Date`类在哪里。为了使这个类在我们的 Java 文件中可用，我们需要导入`util` Java 包，因为这个`Date`类被打包到那个特定的包中。如果我们在前面的类中使用它来导入这个包，你就可以成功地使用那个日期。将鼠标移到这里，它会显示`import 'Date' (java.util)`，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hsn-auto-test-java-bg/img/6315b3ed-ec0c-4ee5-8394-852d79fbf046.png)

快速修复下拉菜单，提供纠正代码错误的建议

一旦你点击那个，你会看到：

```java
import java.util.Date
```

其中`util`是包，`Date`是一个类。

正如我们所见，`d`是包含日期和时间的对象，但我们如何打印它呢？因为它是一个对象格式，我们不能简单地使用以下内容：

```java
System.out.println(d)
```

要将其转换为可读文本，请参考以下截图：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hsn-auto-test-java-bg/img/abcf8219-d429-4217-9600-392a79c407a1.png)

将代码转换为可读文本格式

在这里，我们将`Date`转换为字符串，以便我们可以在输出中直观地看到它。在运行前面的代码时，如截图所示，它打印出以下内容：

```java
Fri Apr 15 17:37:27 EDT 2016
```

这就是我们如何从我们当前系统的 Java 日期中打印整个日期、时间和月份。前面输出的格式不是我们通常得到的，但它可能是特定的格式，比如：

```java
mm//dd//yyyy
```

如果我们想以前面的格式提取我们的日期，我们该如何做？

`d`对象给我们所有的细节。但我们如何将所有这些细节转换为前面的格式呢？为此，我们将使用以下内容：

```java
       Date d= new Date();

        SimpleDateFormat sdf=new SimpleDateFormat("M/d/yyyy");
        System.out.println(sdf.format(d));
        System.out.println(d.toString());
```

前面的代码语法的输出将是：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hsn-auto-test-java-bg/img/464c47f3-8bda-4d73-8a42-83e235e38004.png)

按照代码显示日期和时间的输出

请参考以下 URL 获取`SimpleDateFormat`格式代码：

+   [`www.tutorialspoint.com/java/java_date_time.htm`](http://www.tutorialspoint.com/java/java_date_time.htm)

现在，当改变对象和`SimpleDateFormat`代码时，我们看到以下内容：

```java
 Date d= new Date();

        SimpleDateFormat sdf=new SimpleDateFormat("M/d/yyyy");
        SimpleDateFormat sdf=new SimpleDateFormat("M/d/yyyy hh:mm:ss");
        System.out.println(sdf.format(d));
        System.out.println(sd.toString());
        System.out.println(d.toString());
```

输出将是：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hsn-auto-test-java-bg/img/eed47275-9213-438e-8db8-6ee259e99d2f.png)

以新格式显示日期和时间的输出

因此，我们实际上可以根据我们的需求格式化我们的日期，并将其传递到`SimpleDateFormat`方法中。我们可以将`d`对象带入并放入一个参数中，这样它将以特定的方式格式化。这就是使用 Java 检索日期的方法。

在下一节中，我们将看到如何使用`Calendar`类。

# 日历类

在前一节中，我们探讨了`Date`类，学习了`Date`方法以及如何使用简单的日期格式标准对它们进行操作。在本节中，我们将学习`Calendar`类，它类似于`Date`类，但具有一些额外的功能。让我们看看它们是什么，以及我们如何使用它们来提取我们的日期格式。

首先，我们将创建一个不同名称的类以避免冲突。要创建一个`Calendar`实例，请运行以下命令：

```java
Calendar cal=Calendar.getInstance();
Date d=new Date();
```

这些步骤与`Date`类的步骤相似。但是，`Calendar`对象具有一些`Date`不支持的独特功能。让我们来探索一下。

使用以下代码片段：

```java
        Calendar cal=Calendar.getInstance();
        SimpleDateFormat sd=new SimpleDateFormat("M/d/yyyy hh:mm:ss");
        System.out.println(sd.format(cal.getTime()));
```

前面代码的输出将是：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hsn-auto-test-java-bg/img/5f8f48c1-689c-4c56-b27a-debebf8a514f.png)

使用日历类显示日期和时间的输出

现在，假设我们想要打印月份和星期几。我们将在前面的代码片段中添加以下代码行：

```java
System.out.println(cal.get(Calendar.DAY_OF_MONTH));
System.out.println(cal.get(Calendar.DAY_OF_WEEK_IN_MONTH));
```

输出将如下所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hsn-auto-test-java-bg/img/e36a6cb9-d914-4aab-9863-b121a07af33a.png)

使用日历类显示日期、时间、月份的日期和星期几的输出

同样，我们可以从以下屏幕截图中看到有多个属性可供选择：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hsn-auto-test-java-bg/img/675cc76c-07cd-4a88-b00f-c26c75ed89e1.png)

下拉菜单显示日历类的多个属性

因此，在这里我们使用了`Calendar`实例来实际获取系统日期和时间，但在之前的类中我们使用了`Date`实例；这是唯一的区别。在这个`Calendar`实例中存在很多方法，你在`Date`类中找不到。

这就是根据我们的要求检索系统日期的方法。

# 构造函数

构造函数是 Java 编程语言中最重要的概念之一。因此，在看一个例子之前，让我们先了解一下构造函数是什么。

构造函数在创建对象时执行一块代码。这意味着，每当我们为类创建一个对象时，自动执行一块代码。换句话说，每当创建对象时，都会调用构造函数。

那么构造函数在哪里使用，我们如何定义它呢？应该编写一个构造函数，就像一个方法一样，但构造函数和方法之间的唯一区别是构造函数不会返回任何值，构造函数的名称应该始终是类名。

要为这个类创建一个构造函数，我们将编写以下代码语法：

```java
public class constructDemo()
{
//
}
```

从前面的代码语法可以看出，无论在这个构造函数中写了什么，只要创建对象并调用构造函数，这个块中的一组行就会被执行。这就是构造函数的主要目的：

```java
package coreJava;

public class constructDemo {
    public constructDemo()
    {
        System.out.println("I am in the constructor");
    }
    public-void getdata()
    {
        System.out.println("I am the method");
    }
    // will not return value
    //name of constructor should be the class name
    public static void main(String[] args)  {
        // TODO Auto-generated method stub
        constructDemo cd= new constructDemo(); 
```

每当执行前面的代码时，控制将自动检查是否有显式定义的构造函数。如果定义了，它将执行特定的块。在 Java 中，每当创建一个对象时，都会调用构造函数。

前面代码的输出将是：

```java
I am in the constructor
```

我们实际上并没有为每个类创建构造函数，但是现在我们特别引入了构造函数的概念，因为在之前，我们在定义构造函数时没有使用任何概念。现在，如果我们使用这个命令，程序仍然会运行，但这次它不会执行那个块。如果我们不定义任何构造函数，编译器将调用默认构造函数。我们可以称之为隐式构造函数。

我们在实时中大多依赖构造函数来初始化对象，或为我们的程序定义变量。构造函数和普通方法看起来很相似，因为它们在括号中定义了访问修饰符，但不接受任何返回类型，但在这种情况下它接受。因此，如果我们写：

```java
public constructDemo()
{
    System.out.println("I am in the constructor");
    System.out.println("I am in the constructor lecture 1");

}
```

前面代码的输出将是：

```java
I am in the constructor
I am in the constructor lecture 1
```

因此，通常人们使用上述代码块来在实时中定义变量或初始化属性，并继续使用构造函数。

在下一节中，我们将看一下 Java 中另一个构造函数。

# 参数化构造函数

我们在上一节学习的构造函数是默认构造函数，因为它不接受任何值。在具有相同语法的参数化构造函数中，我们实际上提供了一些参数，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hsn-auto-test-java-bg/img/c78cb8ee-e3e5-48fb-a444-d6050418e31a.png)

使用给定代码的参数化构造函数的输出

前一个构造函数和这个的唯一区别是这里我们传递了参数，在默认的情况下不传递任何参数。当我们运行我们的代码时，每当我们创建一个对象，如果我们不传递任何参数，编译器会自动选择默认构造函数，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hsn-auto-test-java-bg/img/29799d03-478d-4528-a35b-42f7eeac0ea7.png)

当传递默认参数时的输出

现在，让我们为同一个类创建另一个带参数的对象：

```java
constructDemo c=new constructDemo(4,5);
```

当我们按照上述语法定义参数时，编译器在执行运行时时检查是否有两个整数类型参数的构造函数。如果找到构造函数，它将执行以下代码语法：

```java
public constructDemo(int a, int b)
{
    System.out.println("I am in the parameterized constructor");
}
```

在未定义参数的情况下，编译器执行默认构造函数。上述代码的输出将是：

```java
 I am in the parameterized constructor
```

在运行时，创建对象时，我们必须给出参数，因此在执行过程中，它将与定义的构造函数进行比较。同样，我们可以为同一个类创建多个对象：

```java
constructDemo cd=new constructDemo();
constructDemo c=new constructDemo(4,5);
```

当两个构造函数一起运行时，输出将是：

```java
I am in the constructor
I am in the constructor lecture 1
I am in the parameterized constructor
```

现在，我们将创建另一个类似类型的构造函数，但这次只有一个参数：

```java
public constructDemo(String str)
{
    System.out.println(str);
}
public static void main(String[] args) 
{
    constructDemo cd=new constructDemo("hello");
}
```

输出将是：

```java
hello
```

因此，如果我们明确定义了某些内容，Java 编译器会优先选择显式构造函数，否则会打印隐式构造函数。这里需要注意的关键点是它不会返回任何值，并且构造函数必须仅用类名定义。

# 总结

在本章中，我们运行了一些代码示例，以了解`Date`类、`Calendar`类和构造函数的工作原理。

在本章中，我们将介绍三个关键字：`super`，`this`和讨论`finally`块。
