# Java9 编程蓝图（一）

> 原文：[`zh.annas-archive.org/md5/EFCA429E6A8AD54477E9BBC3A0DA41BA`](https://zh.annas-archive.org/md5/EFCA429E6A8AD54477E9BBC3A0DA41BA)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

世界已经等待 Java 9 很长时间了。更具体地说，我们一直在等待 Java 平台模块系统，而 Java 9 终于要推出了。如果一切顺利，我们最终将拥有真正的隔离，这可能会带来更小的 JDK 和更稳定的应用程序。当然，Java 9 提供的不仅仅是这些；在这个版本中有大量的重大变化，但这无疑是最令人兴奋的。话虽如此，这本书并不是一本关于模块系统的书。有很多优秀的资源可以让您深入了解 Java 平台模块系统及其许多影响。不过，这本书更多地是一个对 Java 9 的实际观察。与其讨论发布的细枝末节，尽管那样也很令人满意，但在接下来的几百页中，我们将看到最近 JDK 发布中的所有重大变化--特别是 Java 9--如何以实际的方式应用。

当我们完成时，您将拥有十个不同的项目，涵盖了许多问题领域，您可以从中获取可用的示例，以解决您自己独特的挑战。

# 本书内容

第一章，《介绍》，快速概述了 Java 9 的新功能，并介绍了 Java 7 和 8 的一些主要功能，为我们后面章节的使用做好铺垫。

第二章，《在 Java 中管理进程》，构建了一个简单的进程管理应用程序（类似于 Unix 的 top 命令），我们将探索 Java 9 中新的操作系统进程管理 API 的变化。

第三章，《重复文件查找器》，演示了在应用程序中使用新的文件 I/O API，包括命令行和 GUI，用于搜索和识别重复文件。大量使用了文件哈希、流和 JavaFX 等技术。

第四章，《日期计算器》，展示了一个库和命令行工具来执行日期计算。我们将大量使用 Java 8 的日期/时间 API。

第五章，《Sunago-社交媒体聚合器》，展示了如何与第三方系统集成以构建一个聚合器。我们将使用 REST API、JavaFX 和可插拔应用程序架构。

第六章，《Sunago-Android 移植》，让我们回到了第五章中的应用程序，《Sunago-社交媒体聚合器》。

第七章，《使用 MailFilter 管理电子邮件和垃圾邮件》，构建了一个邮件过滤应用程序，解释了各种电子邮件协议的工作原理，然后演示了如何使用标准的 Java 电子邮件 API--JavaMail 与电子邮件进行交互。

第八章，《使用 PhotoBeans 管理照片》，当我们使用 NetBeans Rich Client Platform 构建一个照片管理应用程序时，我们将走向完全不同的方向。

第九章，《使用 Monumentum 记笔记》，又开辟了一个新方向。在这一章中，我们构建了一个提供基于 Web 的记笔记的应用程序和微服务，类似于一些流行的商业产品。

第十章，《无服务器 Java》，将我们带入云端，我们将在 Java 中构建一个函数作为服务系统，用于发送基于电子邮件和短信的通知。

第十一章，《DeskDroid-用于 Android 手机的桌面客户端》，演示了一个与 Android 设备交互的桌面客户端的简单方法，我们将构建一个应用程序，从桌面查看并发送短信。

第十二章，*接下来是什么？*，讨论了 Java 的未来可能会带来什么，并且还涉及了 Java 在 JVM 上的两个最近的挑战者-Ceylon 和 Kotlin。

# 您需要为这本书做好准备

您需要 Java 开发工具包（JDK）9、NetBeans 8.2 或更新版本，以及 Maven 3.0 或更新版本。一些章节将需要额外的软件，包括 Gluon 的 Scene Builder 和 Android Studio。

# 这本书是为谁准备的

这本书适用于初学者到中级开发人员，他们有兴趣在实际示例中看到新的和多样化的 API 和编程技术。不需要深入了解 Java，但假定您对语言及其生态系统、构建工具等有基本了解。

# 约定

在本书中，您会发现一些区分不同信息种类的文本样式。以下是这些样式的一些示例及其含义的解释。

文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄显示如下：“Java 架构师引入了一个新文件，`module-info.java`，类似于现有的 `package-info.java` 文件，位于模块的根目录，例如在 `src/main/java/module-info.java`。”

代码块设置如下：

```java
    module com.steeplesoft.foo.intro {
      requires com.steeplesoft.bar;
      exports com.steeplesoft.foo.intro.model;
      exports com.steeplesoft.foo.intro.api;
    }

```

任何命令行输入或输出都以以下方式编写：

```java
$ mvn -Puber install

```

**新术语**和**重要单词**以粗体显示。例如，屏幕上看到的单词，例如菜单或对话框中的单词，会出现在文本中，如下所示：“在新项目窗口中，我们选择 Maven 然后 NetBeans 应用程序。”

警告或重要说明会出现在这样的地方。

提示和技巧会出现如下。

# 读者反馈

我们始终欢迎读者的反馈。让我们知道您对这本书的看法-您喜欢或不喜欢什么。读者的反馈对我们很重要，因为它有助于我们开发出您真正受益的标题。

要向我们发送一般反馈，只需发送电子邮件至 `feedback@packtpub.com`，并在主题中提及书名。

如果您在某个专题上有专长，并且有兴趣撰写或为一本书做出贡献，请参阅我们的作者指南[www.packtpub.com/authors](http://www.packtpub.com/authors)。

# 客户支持

既然您已经是 Packt 图书的自豪所有者，我们有一些东西可以帮助您充分利用您的购买。

# 下载示例代码

您可以从[`www.packtpub.com`](http://www.packtpub.com)的账户中下载本书的示例代码文件。如果您在其他地方购买了这本书，您可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)并注册，文件将直接发送到您的电子邮件。

您可以按照以下步骤下载代码文件：

1.  使用您的电子邮件地址和密码登录或注册我们的网站。

1.  将鼠标指针悬停在顶部的“支持”选项卡上。

1.  点击“代码下载和勘误”。

1.  在搜索框中输入书名。

1.  选择您要下载代码文件的书籍。

1.  从下拉菜单中选择您购买此书的地点。

1.  点击“代码下载”。

下载文件后，请确保使用以下最新版本的软件解压缩文件夹：

+   WinRAR / 7-Zip 适用于 Windows

+   Zipeg / iZip / UnRarX 适用于 Mac

+   7-Zip / PeaZip 适用于 Linux

该书的代码包也托管在 GitHub 上[`github.com/PacktPublishing/Java-9-Programming-Blueprints`](https://github.com/PacktPublishing/Java-9-Programming-Blueprints)。我们还有其他丰富的图书和视频代码包可供下载[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)。快去看看吧！

# 下载本书的彩色图片

我们还为您提供了一个 PDF 文件，其中包含本书中使用的屏幕截图/图表的彩色图像。彩色图像将帮助您更好地理解输出中的变化。您可以从[`www.packtpub.com/sites/default/files/downloads/Java9ProgrammingBlueprints_ColorImages`](https://www.packtpub.com/sites/default/files/downloads/Java9ProgrammingBlueprints_ColorImages)下载此文件。

# 勘误

尽管我们已经非常小心确保内容的准确性，但错误是难免的。如果您在我们的书中发现错误，也许是文本或代码中的错误，我们将不胜感激，如果您能向我们报告。通过这样做，您可以帮助其他读者避免挫折，并帮助我们改进本书的后续版本。如果您发现任何勘误，请访问[`www.packtpub.com/submit-errata`](http://www.packtpub.com/submit-errata)报告，选择您的书，点击勘误提交表链接，并输入您的勘误详情。一旦您的勘误经过验证，您的提交将被接受，并且勘误将被上传到我们的网站或添加到该标题的勘误部分下的任何现有勘误列表中。

查看先前提交的勘误表，请访问[`www.packtpub.com/books/content/support`](https://www.packtpub.com/books/content/support)并在搜索框中输入书名。所需信息将显示在勘误部分下方。

# 问题

盗版

请通过`copyright@packtpub.com`与我们联系，并附上涉嫌盗版材料的链接。

我们感谢您在保护我们的作者和我们为您提供有价值内容的能力方面的帮助。

# 在互联网上盗版受版权保护的材料是一个持续存在的问题，涉及所有媒体。在 Packt，我们非常重视版权和许可的保护。如果您在互联网上以任何形式发现我们作品的非法副本，请立即向我们提供位置地址或网站名称，以便我们采取补救措施。

如果您对本书的任何方面有问题，可以通过`questions@packtpub.com`与我们联系，我们将尽力解决问题。


# 第一章：介绍

在建造新建筑的过程中，一套蓝图帮助所有相关方进行沟通--建筑师、电工、木工、管道工等等。它详细说明了形状、大小和材料等细节。如果没有这些蓝图，每个分包商都将被迫猜测该做什么、在哪里做以及如何做。没有这些蓝图，现代建筑几乎是不可能的。

你手中的--或者你面前屏幕上的--是一套不同类型的蓝图。与其详细说明如何构建你特定的软件系统，因为每个项目和环境都有独特的约束和要求，这些蓝图提供了如何构建各种基于 Java 的系统的示例，提供了如何在**Java 开发工具包**（或**JDK**）中使用特定功能的示例，特别关注 Java 9 的新功能，然后你可以将其应用到你的具体问题上。

由于仅使用新的 Java 9 功能构建应用程序是不可能的，我们还将使用和突出显示 JDK 中许多最新功能。在我们深入讨论这意味着什么之前，让我们简要讨论一下最近几个主要 JDK 版本中的一些这些伟大的新功能。希望大多数 Java 公司已经在 Java 7 上，所以我们将专注于版本 8，当然还有版本 9。

在本章中，我们将涵盖以下主题：

+   Java 8 中的新功能

+   Java 9 中的新功能

+   项目

# Java 8 中的新功能

Java 8 于 2014 年 3 月 8 日发布，自 2004 年发布的 Java 5 以来，带来了可能是两个最重要的功能--lambda 和流。随着函数式编程在 JVM 世界中日益流行，尤其是在 Scala 等语言的帮助下，Java 的拥护者多年来一直在呼吁更多的函数式语言特性。最初计划在 Java 7 中发布，该功能在那个版本中被删除，最终在 Java 8 中稳定发布。

虽然可以希望每个人都熟悉 Java 的 lambda 支持，但经验表明，出于各种原因，许多公司都很慢地采用新的语言版本和特性，因此快速介绍可能会有所帮助。

# Lambda

lambda 这个术语源自 1936 年由阿隆佐·邱奇开发的λ演算，简单地指的是匿名函数。通常，函数（或者更正式的 Java 术语中的方法）是 Java 源代码中的一个静态命名的实体：

```java
    public int add(int x, int y) { 
      return x + y; 
    } 

```

这个简单的方法是一个名为`add`的方法，它接受两个`int`参数，并返回一个`int`参数。引入 lambda 后，现在可以这样写：

```java
    (int x, int y) → x + y 

```

或者，更简单地说：

```java
    (x, y) → x + y 

```

这种简化的语法表明我们有一个函数，它接受两个参数并返回它们的总和。根据这个 lambda 的使用位置，参数的类型可以被编译器推断出来，使得第二种更简洁的格式成为可能。最重要的是，注意这个方法不再有名称。除非它被分配给一个变量或作为参数传递（稍后会详细介绍），否则它不能被引用--或者在系统中使用。

当然，这个例子太简单了。更好的例子可能在许多 API 中，其中方法的参数是所谓的**单一抽象方法**（**SAM**）接口的实现，至少在 Java 8 之前，这是一个只有一个方法的接口。单一抽象方法的经典例子之一是`Runnable`。以下是使用 lambda 之前的`Runnable`用法的示例：

```java
    Runnable r = new Runnable() { 
      public void run() { 
        System.out.println("Do some work"); 
      } 
    }; 
    Thread t = new Thread(r); 
    t.start(); 

```

有了 Java 8 的 lambda，这段代码可以被大大简化为：

```java
    Thread t = new Thread(() ->
      System.out.println("Do some work")); 
    t.start(); 

```

`Runnable`方法的主体仍然相当琐碎，但在清晰度和简洁度方面的收益应该是相当明显的。

虽然 lambda 是匿名函数（即，它们没有名称），但是在 Java 中，就像许多其他语言一样，lambda 也可以被分配给变量并作为参数传递（实际上，如果没有这种能力，功能几乎没有价值）。重新访问前面代码中的`Runnable`方法，我们可以将声明和使用`Runnable`分开如下：

```java
    Runnable r = () { 
      // Acquire database connection 
      // Do something really expensive 
    }; 
    Thread t = new Thread(r); 
    t.start(); 

```

这比前面的例子更加冗长是有意的。`Runnable`方法的存根体意在模仿，以某种方式，一个真实的`Runnable`可能看起来的样子，以及为什么人们可能希望将新定义的`Runnable`方法分配给一个变量，尽管 lambda 提供了简洁性。这种新的 lambda 语法允许我们声明`Runnable`方法的主体，而不必担心方法名称、签名等。虽然任何像样的 IDE 都会帮助处理这种样板，但这种新语法给你和将来会维护你的代码的无数开发人员更少的噪音来调试代码。

任何 SAM 接口都可以被写成 lambda。你有一个比较器，你只需要使用一次吗？

```java
    List<Student> students = getStudents(); 
    students.sort((one, two) -> one.getGrade() - two.getGrade()); 

```

`ActionListener`怎么样？

```java
    saveButton.setOnAction((event) -> saveAndClose()); 

```

此外，你可以在 lambda 中使用自己的 SAM 接口，如下所示：

```java
    public <T> interface Validator<T> { 
      boolean isValid(T value); 
    } 
    cardProcessor.setValidator((card) 
    card.getNumber().startsWith("1234")); 

```

这种方法的优点之一是它不仅使消费代码更加简洁，而且还减少了创建一些具体 SAM 实例的努力水平。也就是说，开发人员不必再在匿名类和具体命名类之间做选择，可以在内联中声明它，干净而简洁。

除了 Java 开发人员多年来一直在使用的 SAM 之外，Java 8 还引入了许多功能接口，以帮助促进更多的函数式编程风格。Java 8 的 Javadoc 列出了 43 个不同的接口。其中，有一些基本的函数**形状**，你应该知道其中一些如下：

| `BiConsumer<T,U>` | 这代表了接受两个输入参数并且不返回结果的操作 |
| --- | --- |
| `BiFunction<T,U,R>` | 这代表了一个接受两个参数并产生结果的函数 |
| `BinaryOperator<T>` | 这代表了对两个相同类型的操作数进行操作，产生与操作数相同类型的结果 |
| `BiPredicate<T,U>` | 这代表了一个接受两个参数的谓词（布尔值函数） |
| `Consumer<T>` | 这代表了接受单个输入参数并且不返回结果的操作 |
| `Function<T,R>` | 这代表了一个接受一个参数并产生结果的函数 |
| `Predicate<T>` | 这代表了一个接受一个参数的谓词（布尔值函数） |
| `Supplier<T>` | 这代表了一个结果的供应者 |

这些接口有无数的用途，但也许展示其中一些最好的方法是把我们的注意力转向 Java 8 的下一个重大特性--Streams。

# 流

Java 8 的另一个重大增强，也许是 lambda 发挥最大作用的地方，是新的**Streams API**。如果你搜索 Java 流的定义，你会得到从有些循环的**数据元素流**到更技术性的**Java 流是单子**的答案，它们可能都是正确的。Streams API 允许 Java 开发人员通过一系列步骤与数据元素流进行交互。即使这样说也不够清晰，所以让我们通过查看一些示例代码来看看它的含义。

假设你有一个特定班级的成绩列表。你想知道班级中女生的平均成绩是多少。在 Java 8 之前，你可能会写出类似这样的代码：

```java
    double sum = 0.0; 
    int count = 0; 
    for (Map.Entry<Student, Integer> g : grades.entrySet()) { 
      if ("F".equals(g.getKey().getGender())) { 
        count++; 
        sum += g.getValue(); 
      } 
    } 
    double avg = sum / count; 

```

我们初始化两个变量，一个用于存储总和，一个用于计算命中次数。接下来，我们循环遍历成绩。如果学生的性别是女性，我们增加计数器并更新总和。当循环终止时，我们就有了计算平均值所需的信息。这样做是可以的，但有点冗长。新的 Streams API 可以帮助解决这个问题：

```java
    double avg = grades.entrySet().stream() 
     .filter(e -> "F".equals(e.getKey().getGender())) // 1 
     .mapToInt(e -> e.getValue()) // 2 
     .average() // 3 
     .getAsDouble(); //4 

```

这个新版本并没有显著变小，但代码的目的更加清晰。在之前的预流代码中，我们必须扮演计算机的角色，解析代码并揭示其预期目的。有了流，我们有了一个清晰的、声明性的方式来表达应用逻辑。对于映射中的每个条目，执行以下操作：

1.  过滤掉`gender`不是`F`的每个条目。

1.  将每个值映射为原始 int。

1.  计算平均成绩。

1.  以 double 形式返回值。

有了基于流和 lambda 的方法，我们不需要声明临时的中间变量（成绩计数和总数），也不需要担心计算明显简单的平均值。JDK 为我们完成了所有繁重的工作。

# 新的 java.time 包

虽然 lambda 和 streams 是非常重要的改变性更新，但是在 Java 8 中，我们得到了另一个期待已久的改变，至少在某些领域中同样令人兴奋：一个新的日期/时间 API。任何在 Java 中使用日期和时间的人都知道`java.util.Calendar`等的痛苦。显然，你可以完成工作，但并不总是美观的。许多开发人员发现 API 太痛苦了，所以他们将极其流行的 Joda Time 库集成到他们的项目中。Java 的架构师们同意了，并邀请了 Joda Time 的作者 Stephen Colebourne 来领导 JSR 310，这将 Joda Time 的一个版本（修复了各种设计缺陷）引入了平台。我们将在本书后面详细介绍如何在我们的日期/时间计算器中使用一些这些新的 API。

# 默认方法

在我们将注意力转向 Java 9 之前，让我们再看看另一个重要的语言特性：默认方法。自 Java 开始以来，接口被用来定义类的外观，暗示一种特定的行为，但无法实现该行为。在许多情况下，这使得多态性变得更简单，因为任意数量的类都可以实现给定的接口，并且消费代码将它们视为该接口，而不是它们实际上是什么具体类。

多年来，API 开发人员面临的问题之一是如何在不破坏现有代码的情况下发展 API 及其接口。例如，考虑 JavaServer Faces 1.1 规范中的`ActionSource`接口。当 JSF 1.2 专家组在制定规范的下一个修订版时，他们确定需要向接口添加一个新属性，这将导致两个新方法——getter 和 setter。他们不能简单地将方法添加到接口中，因为那样会破坏规范的每个实现，需要实现者更新他们的类。显然，这种破坏是不可接受的，因此 JSF 1.2 引入了`ActionSource2`，它扩展了`ActionSource`并添加了新方法。虽然许多人认为这种方法很丑陋，但 1.2 专家组有几种选择，而且都不是很好的选择。

然而，通过 Java 8，接口现在可以在接口定义上指定默认方法，如果扩展类没有提供方法实现，编译器将使用该默认方法。让我们以以下代码片段为例：

```java
    public interface Speaker { 
      void saySomething(String message); 
    } 
    public class SpeakerImpl implements Speaker { 
      public void saySomething(String message) { 
        System.out.println(message); 
      } 
    } 

```

我们开发了我们的 API 并向公众提供了它，它被证明非常受欢迎。随着时间的推移，我们发现了一个我们想要做出的改进：我们想要添加一些便利方法，比如`sayHello()`和`sayGoodbye()`，以节省我们的用户一些时间。然而，正如前面讨论的那样，如果我们只是将这些新方法添加到接口中，一旦他们更新到库的新版本，我们就会破坏我们用户的代码。默认方法允许我们扩展接口，并通过定义一个实现来避免破坏：

```java
    public interface Speaker { 
      void saySomething(String message); 
      default public void sayHello() { 
        System.out.println("Hello"); 
      } 
      default public void sayGoodbye() { 
        System.out.println("Good bye"); 
      } 
    } 

```

现在，当用户更新他们的库 JAR 时，他们立即获得这些新方法及其行为，而无需进行任何更改。当然，要使用这些方法，用户需要修改他们的代码，但他们不需要在想要使用之前这样做。

# Java 9 中的新功能

与 JDK 的任何新版本一样，这个版本也充满了许多很棒的新功能。当然，最吸引人的是基于您的需求而变化的，但我们将专注于一些最相关于我们将共同构建的项目的这些新功能。首先是最重要的，Java 模块系统。

# Java 平台模块系统/项目 Jigsaw

尽管 Java 8 是一个功能丰富的稳定版本，但许多人认为它有点令人失望。它缺乏备受期待的**Java 平台模块系统**（**JPMS**），也更为通俗，尽管不太准确地称为项目 Jigsaw。Java 平台模块系统最初计划在 2011 年的 Java 7 中发布，但由于一些悬而未决的技术问题，它被推迟到了 Java 8。Jigsaw 项目不仅旨在完成模块系统，还旨在将 JDK 本身模块化，这将有助于 Java SE 缩小到更小的设备，如手机和嵌入式系统。Jigsaw 原计划在 2014 年发布的 Java 8 中发布，但由于 Java 架构师认为他们仍需要更多时间来正确实现系统，因此又一次推迟了。不过，最终，Java 9 将终于交付这个长期承诺的项目。

话虽如此，它到底是什么？长期以来困扰 API 开发人员的一个问题，包括 JDK 架构师在内，就是无法隐藏公共 API 的实现细节。JDK 中一个很好的例子是开发人员不应直接使用的私有类`com.sun.*/sun.*`包和类。私有 API 广泛公开使用的一个完美例子是`sun.misc.Unsafe`类。除了在 Javadoc 中强烈警告不要使用这些内部类之外，几乎没有什么可以阻止它们的使用。直到现在。

有了 JPMS，开发人员将能够使实现类公开，以便它们可以在其项目内轻松使用，但不将它们暴露给模块外部，这意味着它们不会暴露给 API 或库的消费者。为此，Java 架构师引入了一个新文件`module-info.java`，类似于现有的`package-info.java`文件，位于模块的根目录，例如`src/main/java/module-info.java`。它被编译为`module-info.class`，并且可以通过反射和新的`java.lang.Module`类在运行时使用。

那么这个文件是做什么的，它是什么样子的？Java 开发人员可以使用这个文件来命名模块，列出其依赖关系，并向系统表达，无论是编译时还是运行时，哪些包被导出到世界上。例如，假设在我们之前的流示例中，我们有三个包：`model`，`api`和`impl`。我们想要公开模型和 API 类，但不公开任何实现类。我们的`module-info.java`文件可能看起来像这样：

```java
    module com.packt.j9blueprints.intro { 
      requires com.foo; 
      exports com.packt.j9blueprints.intro.model; 
      exports com.packt.j9blueprints.intro.api; 
    } 

```

这个定义暴露了我们想要导出的两个包，并声明了对`com.foo`模块的依赖。如果这个模块在编译时不可用，项目将无法构建，如果在运行时不可用，系统将抛出异常并退出。请注意，`requires`语句没有指定版本。这是有意的，因为决定不将版本选择问题作为模块系统的一部分来解决，而是留给更合适的系统，比如构建工具和容器。

当然，关于模块系统还可以说更多，但对其所有功能和限制的详尽讨论超出了本书的范围。我们将把我们的应用程序实现为模块，因此我们将在整本书中看到这个系统的使用——也许会更详细地解释一下。

想要更深入讨论 Java 平台模块系统的人可以搜索马克·莱恩霍尔德的文章《模块系统的现状》。

# 进程处理 API

在之前的 Java 版本中，与本地操作系统进程交互的开发人员必须使用一个相当有限的 API，一些操作需要使用本地代码。作为**Java Enhancement Proposal**（**JEP**）102 的一部分，Java 进程 API 被扩展了以下功能（引用自 JEP 文本）：

+   获取当前 Java 虚拟机的 pid（或等效值）以及使用现有 API 创建的进程的 pid。

+   枚举系统上的进程的能力。每个进程的信息可能包括其 pid、名称、状态，以及可能的资源使用情况。

+   处理进程树的能力；特别是一些销毁进程树的方法。

+   处理数百个子进程的能力，可能会将输出或错误流多路复用，以避免为每个子进程创建一个线程。

我们将在我们的第一个项目中探索这些 API 的变化，即进程查看器/管理器（详细信息请参见以下各节）。

# 并发变化

与 Java 7 中所做的一样，Java 架构师重新审视了并发库，做出了一些非常需要的改变，这一次是为了支持反应式流规范。这些变化包括一个新的类，`java.util.concurrent.Flow`，带有几个嵌套接口：`Flow.Processor`、`Flow.Publisher`、`Flow.Subscriber`和`Flow.Subscription`。

# REPL

一个似乎激动了很多人的变化并不是语言上的改变。它是增加了一个**REPL**（**读取-求值-打印-循环**），这是一个对语言外壳的花哨术语。事实上，这个新工具的命令是`jshell`。这个工具允许我们输入或粘贴 Java 代码并立即得到反馈。例如，如果我们想要尝试前一节讨论的 Streams API，我们可以这样做：

```java
$ jshell 
|  Welcome to JShell -- Version 9-ea 
|  For an introduction type: /help intro 

jshell> List<String> names = Arrays.asList(new String[]{"Tom", "Bill", "Xavier", "Sarah", "Adam"}); 
names ==> [Tom, Bill, Xavier, Sarah, Adam] 

jshell> names.stream().sorted().forEach(System.out::println); 
Adam 
Bill 
Sarah 
Tom 
Xavier 

```

这是一个非常受欢迎的补充，应该有助于 Java 开发人员快速原型和测试他们的想法。

# 项目

通过这个简短而高层次的概述，我们可以看到有哪些新功能可以使用，那么我们将要涵盖的这些蓝图是什么样的呢？我们将构建十个不同的应用程序，涉及各种复杂性和种类，并涵盖各种关注点。在每个项目中，我们将特别关注我们正在突出的新功能，但我们也会看到一些旧的、经过验证的语言特性和广泛使用的库，其中任何有趣或新颖的用法都会被标记出来。因此，这是我们的项目阵容。

# 进程查看器/管理器

当我们实现一个 Java 版本的古老的 Unix 工具——**top**时，我们将探索一些进程处理 API 的改进。结合这个 API 和 JavaFX，我们将构建一个图形工具，允许用户查看和管理系统上运行的进程。

这个项目将涵盖以下内容：

+   Java 9 进程 API 增强

+   JavaFX

# 重复文件查找器

随着系统的老化，文件系统中杂乱的机会，特别是重复的文件，似乎呈指数增长。利用一些新的文件 I/O 库，我们将构建一个工具，扫描一组用户指定的目录以识别重复项。我们将从工具箱中取出 JavaFX，添加一个图形用户界面，以提供更加用户友好的交互式处理重复项的方式。

这个项目将涵盖以下内容：

+   Java 文件 I/O

+   哈希库

+   JavaFX

# 日期计算器

随着 Java 8 的发布，Oracle 集成了一个基于 Joda Time 重新设计的新库到 JDK 中。这个新库被官方称为 JSR 310，它解决了 JDK 的一个长期的问题——官方的日期库不够充分且难以使用。在这个项目中，我们将构建一个简单的命令行日期计算器，它将接受一个日期，并且例如添加任意数量的时间。例如，考虑以下代码片段：

```java
$ datecalc "2016-07-04 + 2 weeks" 
2016-07-18 
$ datecalc "2016-07-04 + 35 days" 
2016-08-08 
$ datecalc "12:00CST to PST" 
10:00PST 

```

这个项目将涵盖以下内容：

+   Java 8 日期/时间 API

+   正则表达式

+   Java 命令行库

# 社交媒体聚合器

在许多社交媒体网络上拥有帐户的问题之一是难以跟踪每个帐户上发生的情况。拥有 Twitter、Facebook、Google+、Instagram 等帐户的活跃用户可能会花费大量时间从一个站点跳转到另一个站点，或者从一个应用程序跳转到另一个应用程序，阅读最新的更新。在本章中，我们将构建一个简单的聚合应用程序，从用户的每个社交媒体帐户中获取最新的更新，并在一个地方显示它们。功能将包括以下内容：

+   各种社交媒体网络的多个帐户：

+   Twitter

+   Pinterest

+   Instagram

+   只读的、丰富的社交媒体帖子列表

+   链接到适当的站点或应用程序，以便快速简便地进行后续跟进

+   桌面和移动版本

这个项目将涵盖以下内容：

+   REST/HTTP 客户端

+   JSON 处理

+   JavaFX 和 Android 开发

考虑到这一努力的规模和范围，我们将在两章中实际完成这个项目：第一章是 JavaFX，第二章是 Android。

# 电子邮件过滤

管理电子邮件可能会很棘手，特别是如果你有多个帐户。如果您从多个位置访问邮件（即从多个桌面或移动应用程序），管理您的电子邮件规则可能会更加棘手。如果您的邮件系统不支持存储在服务器上的规则，您将不得不决定在哪里放置规则，以便它们最常运行。通过这个项目，我们将开发一个应用程序，允许我们编写各种规则，然后通过可选的后台进程运行它们，以保持您的邮件始终得到适当的管理。

一个样本`rules`文件可能看起来像这样：

```java
    [ 
      { 
        "serverName": "mail.server.com", 
        "serverPort": "993", 
        "useSsl": true, 
        "userName": "me@example.com", 
        "password": "password", 
        "rules": [ 
           {"type": "move", 
               "sourceFolder": "Inbox", 
               "destFolder": "Folder1", 
               "matchingText": "someone@example.com"}, 
            {"type": "delete", 
               "sourceFolder": "Ads", 
               "olderThan": 180} 
         ] 
      } 
    ] 

```

这个项目将涵盖以下内容：

+   JavaMail

+   JavaFX

+   JSON 处理

+   操作系统集成

+   文件 I/O

# JavaFX 照片管理

Java 开发工具包有一个非常强大的图像处理 API。在 Java 9 中，这些 API 得到了改进，增强了对 TIFF 规范的支持。在本章中，我们将使用这个 API 创建一个图像/照片管理应用程序。我们将添加支持从用户指定的位置导入图像到配置的官方目录。我们还将重新访问重复文件查找器，并重用作为项目一部分开发的一些代码，以帮助我们识别重复的图像。

这个项目将涵盖以下内容：

+   新的`javax.imageio`包

+   JavaFX

+   NetBeans 丰富的客户端平台

+   Java 文件 I/O

# 客户端/服务器笔记应用程序

您是否曾经使用过基于云的笔记应用？您是否想知道制作自己的笔记应用需要什么？在本章中，我们将创建这样一个应用程序，包括完整的前端和后端。在服务器端，我们将把数据存储在备受欢迎的文档数据库 MongoDB 中，并通过 REST 接口公开应用程序的业务逻辑的适当部分。在客户端，我们将使用 JavaScript 开发一个非常基本的用户界面，让我们可以尝试并演示如何在我们的 Java 项目中使用 JavaScript。

该项目将涵盖以下内容：

+   文档数据库（MongoDB）

+   JAX-RS 和 RESTful 接口

+   JavaFX

+   JavaScript 和 Vue 2

# 无服务器 Java

无服务器，也被称为**函数即服务**（**FaaS**），是当今最热门的趋势之一。这是一种应用/部署模型，其中一个小函数部署到一个服务中，该服务几乎管理函数的每个方面——启动、关闭、内存等，使开发人员不必担心这些细节。在本章中，我们将编写一个简单的无服务器 Java 应用程序，以了解如何完成，以及如何在自己的应用程序中使用这种新技术。

该项目将涵盖以下内容：

+   创建 Amazon Web Services 账户

+   配置 AWS Lambda、简单通知服务、简单邮件服务和 DynamoDB

+   编写和部署 Java 函数

# Android 桌面同步客户端

通过这个项目，我们将稍微改变方向，专注于 Java 生态系统的另一个部分：Android。为了做到这一点，我们将专注于一个仍然困扰一些 Android 用户的问题——Android 设备与桌面（或笔记本电脑）系统的同步。虽然各种云服务提供商都在推动我们将更多内容存储在云端并将其流式传输到设备上，但一些人仍然更喜欢直接在设备上存储照片和音乐，原因各种各样，从云资源成本到不稳定的无线连接和隐私问题。

在本章中，我们将构建一个系统，允许用户在他们的设备和桌面或笔记本电脑之间同步音乐和照片。我们将构建一个 Android 应用程序，提供用户界面来配置和监视从移动设备端进行同步，以及在后台执行同步的 Android 服务（如果需要）。我们还将在桌面端构建相关组件——一个图形应用程序来配置和监视来自桌面端的同步过程，以及一个后台进程来处理来自桌面端的同步。

该项目将涵盖以下内容：

+   Android

+   用户界面

+   服务

+   JavaFX

+   REST

# 入门

我们已经快速浏览了一些我们将要使用的新语言特性。我们也简要概述了我们将要构建的项目。最后一个问题仍然存在：我们将使用什么工具来完成我们的工作？

当涉及到开发工具时，Java 生态系统拥有丰富的选择，因此我们有很多选择。我们面临的最基本的选择是构建工具。在这里，我们将使用 Maven。虽然有一个强大而有声望的社区支持 Gradle，但 Maven 似乎是目前最常见的构建工具，并且似乎得到了主要 IDE 的更健壮、更成熟和更本地的支持。如果您尚未安装 Maven，您可以访问[`maven.apache.org`](http://maven.apache.org/)并下载适合您操作系统的分发版，或者使用您的操作系统支持的任何软件包管理系统。

对于 IDE，所有的截图、指导等都将使用 NetBeans——来自 Oracle 的免费开源 IDE。当然，也有 IntelliJ IDEA 和 Eclipse 的支持者，它们都是不错的选择，但是 NetBeans 提供了一个完整而强大的开发工具，并且快速、稳定且免费。要下载 NetBeans，请访问[`netbeans.org`](http://netbeans.org/)并下载适合您操作系统的安装程序。由于我们使用 Maven，而 IDEA 和 Eclipse 都支持，您应该能够在您选择的 IDE 中打开这里提供的项目。但是，当 GUI 中显示步骤时，您需要根据您选择的 IDE 进行调整。

在撰写本文时，NetBeans 的最新版本是 8.2，使用它进行 Java 9 开发的最佳方法是在 Java 8 上运行 IDE，并将 Java 9 添加为 SDK。有一个可以在 Java 9 上运行的 NetBeans 开发版本，但是由于它是一个开发版本，有时可能不稳定。稳定的 NetBeans 9 应该会在 Java 9 本身发布时大致同时推出。与此同时，我们将继续使用 8.2：

1.  要添加 Java 9 支持，我们需要添加一个新的 Java 平台，我们将通过点击“工具”|“平台”来实现。

1.  这将打开 Java 平台管理器屏幕：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-prog-bp/img/9212fff4-28c7-4275-9304-ccf89a7720a5.png)

1.  点击屏幕左下角的“添加平台”。

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-prog-bp/img/12d5edc8-c463-425c-9728-8b0ec8225d09.png)

1.  我们想要添加一个 Java 标准版平台，所以我们将接受默认设置并点击“下一步”。

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-prog-bp/img/a4bb0f81-3af0-4268-babe-5772f0880e9c.png)

1.  在“添加 Java 平台”屏幕上，我们将导航到我们安装 Java 9 的位置，选择 JDK 目录，然后点击“下一步”。

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-prog-bp/img/0cf9f89c-a226-425c-835a-8b1c7d0b27ef.png)

1.  我们需要给新的 Java 平台命名（NetBeans 默认为一个非常合理的 JDK 9），所以我们将点击“完成”现在可以看到我们新添加的 Java 9 选项。

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-prog-bp/img/b1400a67-3da0-4cc6-84f0-820fe8cb437e.png)

设置了项目 SDK 后，我们准备好尝试一下这些新的 Java 9 功能，我们将从第二章“在 Java 中管理进程”开始进行。

如果您在 Java 9 上运行 NetBeans，这本书出版时应该是可能的，您将已经配置了 Java 9。但是，如果您需要特定版本，可以使用前面的步骤来配置 Java 8。

# 摘要

在本章中，我们快速浏览了 Java 8 中一些出色的新功能，包括 lambda、streams、新的日期/时间包和默认方法。从 Java 9 开始，我们快速浏览了 Java 平台模块系统和项目 Jigsaw、进程处理 API、新的并发更改以及新的 Java REPL。对于每个功能，我们都讨论了“是什么”和“为什么”，并查看了一些示例，了解了它们可能如何影响我们编写的系统。我们还看了一下本书中将要构建的项目类型和我们将要使用的工具。

在我们继续之前，我想重申一个早前的观点——每个软件项目都是不同的，因此不可能以一种简单的方式来编写这本书，让您可以简单地将大段代码复制粘贴到您的项目中。同样，每个开发人员编写代码的方式也不同；我构建代码的方式可能与您的大不相同。因此，在阅读本书时，重要的是不要被细节困扰。这里的目的不是向您展示使用这些 API 的唯一正确方式，而是给您一个示例，让您更好地了解它们可能如何使用。从每个示例中学习，根据自己的需要进行修改，然后构建出令人惊叹的东西。

说了这么多，现在让我们把注意力转向我们的第一个项目，进程管理器和新的进程处理 API。


# 第二章：在 Java 中管理进程

通过快速浏览 Java 9 的一些重大新功能以及之前几个版本的功能，让我们将注意力转向以实际方式应用其中一些新的 API。我们将从一个简单的进程管理器开始。

尽管通常最好让应用程序或实用程序在内部处理用户的所有问题，但偶尔您可能需要出于各种原因运行（或**外壳到**）外部程序。从 Java 的最早时期开始，JDK 就通过`Runtime`类提供了各种 API 来支持这一点。以下是最简单的示例：

```java
    Process p = Runtime.getRuntime().exec("/path/to/program"); 

```

一旦进程创建完成，您可以通过`Process`类跟踪其执行，该类具有诸如`getInputStream()`、`getOutputStream()`和`getErrorStream()`等方法。我们还可以通过`destroy()`和`waitFor()`对进程进行基本控制。Java 8 通过添加`destroyForcibly()`和`waitFor(long, TimeUnit)`推动了事情的发展。从 Java 9 开始，这些功能将得到扩展。引用**Java Enhancement Proposal**（**JEP**）中的内容，我们可以看到为此新功能的以下原因：

*许多企业应用程序和容器涉及多个 Java 虚拟机和进程，并且长期以来一直需要以下功能：*

+   *获取当前 Java 虚拟机的 pid（或等效值）以及使用现有 API 创建的进程的 pid 的能力。*

+   *枚举系统上的进程的能力。每个进程的信息可能包括其 pid、名称、状态，以及可能的资源使用情况。*

+   *处理进程树的能力，特别是一些销毁进程树的方法。*

+   *处理数百个子进程的能力，可能是复用输出或错误流以避免为每个子进程创建一个线程。*

在本章中，我们将构建一个简单的进程管理器应用程序，类似于 Windows 任务管理器或*nix 的 top。当然，在 Java 中没有必要编写进程管理器，但这将是我们探索这些新的进程处理 API 的绝佳途径。此外，我们还将花一些时间研究其他语言功能和 API，即 JavaFX 和`Optional`。

本章涵盖以下主题：

+   创建项目

+   引导应用程序

+   定义用户界面

+   初始化用户界面

+   添加菜单

+   更新进程列表

说了这么多，让我们开始吧。

# 创建项目

通常来说，如果可以在不需要特定 IDE 或其他专有工具的情况下重现构建，那将会更好。幸运的是，NetBeans 提供了创建基于 Maven 的 JavaFX 项目的能力。点击文件 | 新建项目，然后选择`Maven`，然后选择 JavaFX 应用程序：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-prog-bp/img/bd100520-c6c3-4175-aac0-ab8572069fd9.png)

接下来，执行以下步骤：

1.  点击下一步。

1.  将项目名称输入为`ProcessManager`。

1.  将 Group ID 输入为`com.steeplesoft`。

1.  将包输入为`com.steeplesoft.processmanager`。

1.  选择项目位置。

1.  点击完成。

请考虑以下屏幕截图作为示例：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-prog-bp/img/e0950b49-e0eb-46e5-a219-efa6d4dc8467.png)

创建新项目后，我们需要更新 Maven 的`pom`以使用 Java 9：

```java
    <build> 
      <plugins> 
        <plugin> 
          <groupId>org.apache.maven.plugins</groupId> 
          <artifactId>maven-compiler-plugin</artifactId> 
          <version>3.6.1</version> 
          <configuration> 
            <source>9</source> 
            <target>9</target> 
          </configuration> 
        </plugin> 
      </plugins> 
    </build> 

```

现在，NetBeans 和 Maven 都配置为使用 Java 9，我们准备开始编码。

# 引导应用程序

如介绍中所述，这将是一个基于 JavaFX 的应用程序，因此我们将从创建应用程序的框架开始。这是一个 Java 9 应用程序，我们打算利用 Java 模块系统。为此，我们需要创建模块定义文件`module-info.java`，该文件位于源代码树的根目录。作为基于 Maven 的项目，这将是`src/main/java`：

```java
    module procman.app { 
      requires javafx.controls; 
      requires javafx.fxml; 
    } 

```

这个小文件做了几件不同的事情。首先，它定义了一个新的`procman.app`模块。接下来，它告诉系统这个模块`requires`两个 JDK 模块：`javafx.controls`和`javafx.fxml`。如果我们没有指定这两个模块，那么我们的系统在编译时将无法通过，因为 JDK 不会将所需的类和包提供给我们的应用程序。这些模块是作为 Java 9 的标准 JDK 的一部分，所以这不应该是一个问题。然而，在未来的 Java 版本中可能会发生变化，这个模块声明将有助于通过强制主机 JVM 提供模块或无法启动来防止我们的应用程序运行时失败。还可以通过**J-Link**工具构建自定义的 Java 运行时，因此在 Java 9 下缺少这些模块仍然是可能的。有了我们的模块配置，让我们转向应用程序。

新兴的标准目录布局似乎是`src/main/java/*<module1>*`，`src/main/java/*<module2>*`等。在撰写本书时，虽然 Maven 可以被迫采用这样的布局，但插件本身虽然可以在 Java 9 下运行，但似乎不够了解模块，无法让我们以这种方式组织我们的代码。因此，出于简单起见，我们将一个 Maven 模块视为一个 Java 模块，并保持项目的标准源布局。

我们将创建的第一个类是`Application`的子类，NetBeans 为我们创建了`Main`类，我们将其重命名为`ProcessManager`：

```java
    public class ProcessManager extends Application { 
      @Override 
      public void start(Stage stage) throws Exception { 
        Parent root = FXMLLoader 
         .load(getClass().getResource("/fxml/procman.fxml")); 

        Scene scene = new Scene(root); 
        scene.getStylesheets().add("/styles/Styles.css"); 

        stage.setTitle("Process Manager"); 
        stage.setScene(scene); 
        stage.show(); 
      } 

      public static void main(String[] args) { 
        launch(args); 
      } 
    } 

```

我们的`ProcessManager`类扩展了 JavaFX 基类`Application`，它提供了各种功能来启动和停止应用程序。我们在`main()`方法中看到，我们只是委托给`Application.launch(String[])`，它为我们在启动新应用程序时做了大部分工作。

这个类的更有趣的部分是`start()`方法，这是 JavaFX 生命周期调用我们的应用程序的地方，让我们有机会构建用户界面，接下来我们将这样做。

# 定义用户界面

在构建 JavaFX 应用程序的用户界面时，可以通过两种方式之一完成：代码或标记。为了使我们的代码更小更可读，我们将使用 FXML 构建用户界面--这是专门为 JavaFX 创建的基于 XML 的语言，用于表达用户界面。这给我们提供了另一个二元选择--我们是手动编写 XML，还是使用图形工具？同样，选择是简单的--我们将使用一个名为**Scene Builder**的工具，这是一个最初由 Oracle 开发，现在由 Gluon 维护和支持的所见即所得的工具。然而，我们也将查看 XML 源码，以便了解正在做什么，所以如果你不喜欢使用 GUI 工具，你也不会被排除在外。

安装和使用 Scene Builder 就像你期望的那样非常简单。它可以从[`gluonhq.com/labs/scene-builder/`](http://gluonhq.com/labs/scene-builder/)下载。安装完成后，您需要告诉 NetBeans 在哪里找到它，这可以在设置窗口中完成，在 Java | JavaFX 下，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-prog-bp/img/73de633d-f536-4a29-80ea-a20329d5e939.png)

现在我们准备创建 FXML 文件。在项目视图中的`resources`目录下，创建一个名为`fxml`的新文件夹，在该文件夹中创建一个名为`procman.fxml`的文件，如下所示：

```java
    <BorderPane  

      fx:controller="com.steeplesoft.procman.Controller"> 
    </BorderPane> 

```

`BorderPane`是一个容器，定义了五个区域--`top`、`bottom`、`left`、`right`和`center`，让我们对控件在表单上的位置有了相当粗粒度的控制。通常，使用`BorderPane`，每个区域使用嵌套容器来提供通常必要的更细粒度的控制。对于我们的需求，这种控制水平将是完美的。

用户界面的主要关注点是进程列表，因此我们将从那些控件开始。从 Scene Builder 中，我们要点击左侧手风琴上的“控件”部分，然后向下滚动到`TableView`。单击此处并将其拖动到表单的`CENTER`区域，如 Scene Builder 中的此截图所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-prog-bp/img/85785dae-4740-4d97-9bbb-729be9e5b767.png)

生成的 FXML 应该看起来像这样：

```java
    <center> 
        <TableView fx:id="processList" 
               BorderPane.alignment="CENTER"> 
        </TableView> 
    </center> 

```

在其他区域没有组件的情况下，`TableView`将扩展以填充窗口的整个区域，这是我们目前想要的。

# 初始化用户界面

虽然 FXML 定义了用户界面的结构，但我们确实需要一些 Java 代码来初始化各种元素，响应操作等。这个类，称为控制器，只是一个扩展`javafx.fxml.Initializable`的类：

```java
    public class Controller implements Initializable { 
      @FXML 
      private TableView<ProcessHandle> processList; 
      @Override 
      public void initialize(URL url, ResourceBundle rb) { 
      } 
    } 

```

`initialize()`方法来自接口，并且在调用`FXMLLoader.load()`时由 JavaFX 运行时初始化控制器。请注意`@FXML`注解在实例变量`processList`上。当 JavaFX 初始化控制器时，在调用`initialize()`方法之前，系统会查找指定了`fx:id`属性的 FXML 元素，并将该引用分配给控制器中适当的实例变量。为了完成这种连接，我们必须对我们的 FXML 文件进行一些更改：

```java
    <TableView fx:id="processList" BorderPane.alignment="CENTER">
    ...

```

更改也可以在 Scene Builder 中进行，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-prog-bp/img/24f9d855-7146-4363-8c83-e8a011527891.png)

fx:id 属性的值必须与已用`@FXML`注释注释的实例变量的名称匹配。当调用`initialize`时，`processList`将具有对我们在 Java 代码中可以操作的`TableView`的有效引用。

fx:id 的值也可以通过 Scene Builder 进行设置。要设置该值，请在表单编辑器中单击控件，然后在右侧手风琴中展开代码部分。在 fx:id 字段中，键入所需变量名称的名称。

拼图的最后一部分是指定 FXML 文件的控制器。在 XML 源中，您可以通过用户界面的根元素上的`fx:controller`属性来设置这一点：

```java
    <BorderPane  xmlns="http://javafx.com/javafx/8.0.60"
      xmlns:fx="http://javafx.com/fxml/1" 
      fx:controller="com.steeplesoft.procman.Controller">

```

这也可以通过 Scene Builder 进行设置。在左侧手风琴上的文档部分，展开控制器部分，并在控制器类字段中输入所需的完全限定类名：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-prog-bp/img/f03c7d5b-2065-47b1-8f35-ff8471dde400.png)

有了这些部分，我们可以开始初始化`TableView`的工作，这让我们回到了我们的主要兴趣，即处理 API 的过程。我们的起点是`ProcessHandles.allProcesses()`。从 Javadoc 中，您可以了解到这个方法返回**当前进程可见的所有进程的快照**。从流中的每个`ProcessHandle`中，我们可以获取有关进程 ID、状态、子进程、父进程等的信息。每个`ProcessHandle`还有一个嵌套对象`Info`，其中包含有关进程的信息的快照。由于并非所有信息都可以在各种支持的平台上使用，并且受当前进程的权限限制，`Info`对象上的属性是`Optional<T>`实例，表示值可能设置或可能未设置。可能值得花点时间快速看一下`Optional<T>`是什么。

Javadoc 将`Optional<T>`描述为**可能包含非空值的容器对象**。受 Scala 和 Haskell 的启发，`Optional<T>`在 Java 8 中引入，允许 API 作者提供更安全的空值接口。在 Java 8 之前，`ProcessHandle.Info`上的方法可能定义如下：

```java
    public String command(); 

```

为了使用 API，开发人员可能会写出类似这样的代码：

```java
    String command = processHandle.info().command(); 
    if (command == null) { 
      command = "<unknown>"; 
    } 

```

如果开发人员未明确检查 null，几乎肯定会在某个时候发生`NullPointerException`。通过使用`Optional<T>`，API 作者向用户发出信号，表明返回值可能为 null，应该小心处理。然后，更新后的代码可能看起来像这样：

```java
    String command = processHandle.info().command() 
     .orElse("<unknown>"); 

```

现在，我们可以用一行简洁的代码来获取值，如果存在的话，或者获取默认值，如果不存在的话。正如我们将在后面看到的，`ProcessHandle.Info` API 广泛使用了这种构造方式。

作为开发人员，`Optional`还为我们提供了一些实例方法，可以帮助澄清处理 null 的代码：

+   `filter(Predicate<? super T> predicate)`: 使用这个方法，我们可以过滤`Optional`的内容。我们可以将`filter()`方法传递一个`Predicate`，而不是使用`if...else`块，并在内联进行测试。`Predicate`是一个接受输入并返回布尔值的`@FunctionalInterface`。例如，JavaFX 的`Dialog`的一些用法可能返回`Optional<ButtonType>`。如果我们只想在用户点击了特定按钮时执行某些操作，比如 OK，我们可以这样过滤`Optional`：

```java
        alert.showAndWait() 
         .filter(b -> b instanceof ButtonType.OK) 

```

+   `map(Function<? super T,? extends U> mapper)`: `map`函数允许我们将`Optional`的内容传递给一个函数，该函数将对其进行一些处理，并返回它。不过，函数的返回值将被包装在一个`Optional`中：

```java
        Optional<String> opts = Optional.of("hello"); 
        Optional<String> upper = opts.map(s ->  
         s.toUpperCase()); 
        Optional<Optional<String>> upper2 =  
         opts.map(s -> Optional.of(s.toUpperCase())); 

```

请注意，在`upper2`中`Optional`的双重包装。如果`Function`返回`Optional`，它将被包装在另一个`Optional`中，给我们带来这种不太理想的双重包装。幸运的是，我们有一个替代方案。

+   `flatMap(Function<? super T,Optional<U>> mapper)`: `flatMap`函数结合了两个函数式思想--映射和扁平化。如果`Function`的结果是一个`Optional`对象，而不是将值进行双重包装，它会被扁平化为一个单一的`Optional`对象。重新审视前面的例子，我们得到这样的结果：

```java
        Optional<String> upper3 = opts.flatMap(s ->      
         Optional.of(s.toUpperCase())); 

```

请注意，与`upper2`不同，`upper3`是一个单一的`Optional`：

+   `get()`: 如果存在值，则返回包装的值。如果没有值，则抛出`NoSuchElementException`错误。

+   `ifPresent(Consumer<? super T> action)`: 如果`Optional`对象包含一个值，则将其传递给`Consumer`。如果没有值存在，则什么也不会发生。

+   `ifPresentOrElse(Consumer<? super T> action, Runnable emptyAction)`: 像`ifPresent()`一样，如果有值存在，它会将值传递给`Consumer`。如果没有值存在，将执行`Runnable emptyAction`。

+   `isPresent()`: 如果`Optional`对象包含一个值，则简单地返回 true。

+   `or(Supplier<Optional<T>> supplier)`: 如果`Optional`对象有一个值，则描述该`Optional`。如果没有值存在，则返回`Supplier`生成的`Optional`对象。

+   `orElse(T other)`: 如果`Optional`对象包含一个值，则返回该值。如果没有值，则返回`other`。

+   `orElseGet(Supplier<? extends T> supplier)`: 这与前面提到的`orElse()`类似，但是如果没有值存在，则返回`Supplier`的结果。

+   `orElseThrow(Supplier<? extends X> exceptionSupplier)`: 如果存在值，则返回该值。如果没有值，则抛出`Supplier`提供的`Exception`。

`Optional`还有一些静态方法，可以方便地创建`Optional`实例，其中一些如下：

+   `empty()`: 这返回一个空的`Optional`对象。

+   `of(T value)`: 这返回一个描述非空值的`Optional`对象。如果该值为 null，则抛出`NullPointerException`。

+   `ofNullable(T value)`: 这返回一个描述该值的`Optional`对象。如果该值为 null，则返回一个空的`Optional`。

通过这个非常简短的介绍，我们可以看到`Optional<T>`的存在是如何影响我们的应用程序的。

然后，我们的第一步是获取要显示的进程列表。流 API 使这变得非常简单：

```java
    ProcessHandle.allProcesses() 
     .collect(Collectors.toList()); 

```

`allProcesses()`方法返回`Stream<ProcessHandle>`，这允许我们对问题应用新的流操作。在这种情况下，我们只想创建一个包含所有`ProcessHandle`实例的`List`，所以我们调用`collect()`，这是一个接受`Collector`的流操作。我们可以选择多种选项，但我们想要一个`List`，所以我们使用`Collectors.toList()`，它将收集流中的每个项目，并在流终止时最终返回一个`List`。注意，`List`的参数化类型将与`Stream`的参数化类型匹配，这种情况下是`ProcessHandle`。

这一行代码让我们得到了系统上每个进程的`List<ProcessHandle>`，当前进程可以看到，但这只让我们完成了一半。`TableView` API 不接受`List<T>`。它只支持`ObservableList<T>`，但这是什么？它的 Javadoc 非常简单地定义了它--*一个允许监听器在发生更改时跟踪更改的列表*。换句话说，当这个列表发生变化时，`TableView`会自动得到通知并重新绘制自己。一旦我们将`TableView`与这个列表关联起来，我们只需要担心数据，控件会处理其余的事情。创建`ObservableList`非常简单：

```java
    @FXML 
    private TableView<ProcessHandle> processView; 
    final private ObservableList<ProcessHandle> processList =  
      FXCollections.observableArrayList(); 
    // ... 
    processView.setItems(processList);      
    processList.setAll(ProcessHandle.allProcesses() 
     .collect(Collectors.toList())); 

```

在我们的情况下，`TableView`实例是由运行时注入的（这里包括是为了清晰起见），我们通过`FXCollections.observableArrayList()`创建`ObservableList`。在`initialize()`中，我们通过`setItems()`在`TableView`上设置`ObservableList`，然后通过`setAll()`填充`ObservableList`。有了这个，我们的`TableView`就有了渲染自己所需的所有数据。几乎。它有**数据**来渲染，但**如何**渲染呢？`ProcessHandle.Info`的每个字段放在哪里？为了回答这个问题，我们必须在表上定义列，并告诉每一列从哪里获取它的数据。

为了做到这一点，我们需要创建几个`TableColumn<S,T>`实例。`TableColumn`不仅负责显示其列标题（如果适用），还负责每个单元格的值。然而，你必须告诉它**如何**显示单元格。这是通过一个单元格值工厂来完成的。在 Java 7 下，该 API 会让我们得到这样的代码：

```java
    TableColumn<ProcessHandle, String> commandCol =  
     new TableColumn<>("Command"); 
    commandCol.setCellValueFactory(new  
      Callback<TableColumn.CellDataFeatures<ProcessHandle, String>,  
       ObservableValue<String>>() { 
         public ObservableValue<String> call( 
          TableColumn.CellDataFeatures<ProcessHandle,  
           String> p) { 
             return new SimpleObjectProperty(p.getValue()
              .info() 
              .command() 
              .map(Controller::afterLast) 
              .orElse("<unknown>")); 
           } 
       }
    ); 

```

我会提前说出来：这真的很丑。幸运的是，我们可以利用 lambda 和类型推断来让它更加愉快地阅读：

```java
    TableColumn<ProcessHandle, String> commandCol =  
     new TableColumn<>("Command"); 
    commandCol.setCellValueFactory(data ->  
     new SimpleObjectProperty(data.getValue().info().command() 
      .map(Controller::afterLast) 
      .orElse("<unknown>"))); 

```

这是六行代码取代了十四行。漂亮多了。现在，我们只需要再做五次，每次为一个列。尽管前面的代码可能已经改进了，但仍然有相当多的重复代码。同样，Java 8 的函数接口可以帮助我们进一步清理代码。对于每一列，我们想要指定标题、宽度以及从`ProcessHandle.Info`中提取什么。我们可以用这个方法来封装：

```java
    private <T> TableColumn<ProcessHandle, T>  
      createTableColumn(String header, int width,  
       Function<ProcessHandle, T> function) { 
         TableColumn<ProcessHandle, T> column = 
          new TableColumn<>(header); 

         column.setMinWidth(width); 
         column.setCellValueFactory(data ->  
          new SimpleObjectProperty<T>( 
           function.apply(data.getValue()))); 
           return column; 
    } 

```

`Function<T,R>`接口是`FunctionalInterface`，它表示一个接受一个类型`T`并返回另一个类型`R`的函数。在我们的情况下，我们正在定义这个方法，它以一个`String`、一个`int`和一个接受`ProcessHandle`并返回一个通用类型的函数作为参数。这可能很难想象，但有了这个方法的定义，我们可以用对这个方法的调用来替换前面的代码和类似的代码。同样的前面的代码现在可以被压缩为这样：

```java
    createTableColumn("Command", 250,  
      p -> p.info().command() 
      .map(Controller::afterLast) 
      .orElse("<unknown>")) 

```

现在我们只需要将这些列添加到控件中，可以用这个方法来实现：

```java
    processView.getColumns().setAll( 
      createTableColumn("Command", 250,  
      p -> p.info().command() 
       .map(Controller::afterLast) 
       .orElse("<unknown>")), 
      createTableColumn("PID", 75, p -> p.getPid()), 
      createTableColumn("Status", 150,  
       p -> p.isAlive() ? "Running" : "Not Running"), 
      createTableColumn("Owner", 150,  
       p -> p.info().user() 
        .map(Controller::afterLast) 
        .orElse("<unknown>")), 
      createTableColumn("Arguments", 75,  
       p -> p.info().arguments().stream() 
        .map(i -> i.toString()) 
        .collect(Collectors.joining(", ")))); 

```

请注意，我们在`ProcessHandle.Info`上使用的每种方法都返回了我们在前面的代码中看到的`Optional<T>`。由于它这样做，我们有一个非常好的和干净的 API 来获取我们想要的信息（或者一个合理的默认值），而不会在生产中出现`NullPointerException`的问题。

如果我们现在运行应用程序，应该会得到类似这样的东西：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-prog-bp/img/e8871d7e-c081-46c2-b354-06434888cb74.png)

到目前为止看起来不错，但还不够完善。我们希望能够启动新进程以及终止现有进程。这两者都需要菜单，所以我们接下来会添加这些。

# 添加菜单

JavaFX 中的菜单从一个名为`MenuBar`的组件开始。当然，我们希望这个菜单位于窗口的顶部，因此我们将该组件添加到`BorderPane`的`top`部分。如果您使用 Scene Builder，您的 FXML 文件中将会出现类似于以下内容：

```java
    <MenuBar BorderPane.alignment="CENTER"> 
      <menus> 
        <Menu mnemonicParsing="false" text="File"> 
          <items> 
            <MenuItem mnemonicParsing="false" text="Close" /> 
          </items> 
        </Menu> 
        <Menu mnemonicParsing="false" text="Edit"> 
          <items> 
            <MenuItem mnemonicParsing="false" text="Delete" /> 
          </items> 
        </Menu> 
        <Menu mnemonicParsing="false" text="Help"> 
          <items> 
            <MenuItem mnemonicParsing="false" text="About" /> 
          </items> 
        </Menu> 
      </menus> 
    </MenuBar> 

```

我们不需要编辑菜单，因此可以从 FXML 文件中删除该部分（或者通过右键单击 Scene Builder 中的第二个`Menu`条目，然后单击删除）。要创建我们想要的菜单项，我们将适当的`MenuItem`条目添加到`File`元素下的`item`元素中：

```java
    <Menu mnemonicParsing="true" text="_File"> 
      <items> 
        <MenuItem mnemonicParsing="true"  
          onAction="#runProcessHandler"  
          text="_New Process..." /> 
        <MenuItem mnemonicParsing="true"  
          onAction="#killProcessHandler"  
          text="_Kill Process..." /> 
        <MenuItem mnemonicParsing="true"  
          onAction="#closeApplication"  
          text="_Close" /> 
      </items> 
    </Menu> 

```

每个`MenuItem`条目都有三个属性定义：

+   `mnemonicParsing`：这指示 JavaFX 使用带有下划线前缀的任何字母作为键盘快捷键

+   `onAction`：这标识了在激活/单击`MenuItem`时将调用控制器上的方法

+   `text`：这定义了`MenuItem`的标签

最有趣的部分是`onAction`及其与控制器的关系。当然，JavaFX 已经知道这个表单由`com.steeplesoft.procman.Controller`支持，因此它将寻找具有以下签名的方法：

```java
    @FXML 
    public void methodName(ActionEvent event) 

```

`ActionEvent`是 JavaFX 在许多情况下使用的一个类。在我们的情况下，我们为每个菜单项专门有方法，因此事件本身并不是太有趣。让我们看看每个处理程序，从最简单的`closeApplication`开始：

```java
    @FXML 
    public void closeApplication(ActionEvent event) { 
      Platform.exit(); 
    } 

```

这里没有什么可看的；当单击菜单项时，我们通过调用`Platform.exit()`退出应用程序。

接下来，让我们看看如何终止一个进程：

```java
    @FXML 
    public void killProcessHandler(final ActionEvent event) { 
      new Alert(Alert.AlertType.CONFIRMATION,  
      "Are you sure you want to kill this process?",  
      ButtonType.YES, ButtonType.NO) 
       .showAndWait() 
       .filter(button -> button == ButtonType.YES) 
       .ifPresent(response -> { 
         ProcessHandle selectedItem =  
          processView.getSelectionModel() 
           .getSelectedItem(); 
         if (selectedItem != null) { 
           selectedItem.destroy(); 
           processListUpdater.updateList(); 
         } 
       }); 
    } 

```

我们这里有很多事情要做。我们首先要做的是创建一个`CONFIRMATION`类型的`Alert`对话框，询问用户确认请求。对话框有两个按钮：`YES`和`NO`。一旦对话框被创建，我们调用`showAndWait()`，它会显示对话框并等待用户的响应。它返回`Optional<ButtonType>`，其中包含用户点击的按钮的类型，可能是`ButtonType.YES`或`ButtonType.NO`，根据我们创建的`Alert`对话框的类型。有了`Optional`，我们可以应用`filter()`来找到我们感兴趣的按钮类型，即`ButtonType.YES`，其结果是另一个`Optional`。如果用户点击了 yes，`ifPresent()`将返回 true（感谢我们的过滤器），并且我们传递的 lambda 将被执行。非常好而简洁。

接下来感兴趣的是 lambda。一旦我们确定用户想要终止一个进程，我们需要确定**哪个**进程要终止。为此，我们通过`TableView.getSelectionModel().getSelectedItem()`询问`TableView`选择了哪一行。我们确实需要检查是否为 null（遗憾的是，这里没有`Optional`），以防用户实际上没有选择行。如果它不是 null，我们可以在`TableView`给我们的`ProcessHandle`上调用`destroy()`。然后我们调用`processListUpdater.updateList()`来刷新 UI。稍后我们会看看这个。

我们的最终操作处理程序必须运行以下命令：

```java
    @FXML 
    public void runProcessHandler(final ActionEvent event) { 
      final TextInputDialog inputDlg = new TextInputDialog(); 
      inputDlg.setTitle("Run command..."); 
      inputDlg.setContentText("Command Line:"); 
      inputDlg.setHeaderText(null); 
      inputDlg.showAndWait().ifPresent(c -> { 
        try { 
          new ProcessBuilder(c).start(); 
        } catch (IOException e) { 
            new Alert(Alert.AlertType.ERROR,  
              "There was an error running your command.") 
              .show(); 
          } 
      }); 
    } 

```

在许多方面，这与前面的`killProcessHandler()`方法类似——我们创建一个对话框，设置一些选项，调用`showAndWait()`，然后处理`Optional`。不幸的是，对话框不支持构建器模式，这意味着我们没有一个很好的流畅 API 来构建对话框，所以我们要分几个离散的步骤来做。处理`Optional`也类似。我们调用`ifPresent()`来查看对话框是否返回了命令行（也就是用户输入了一些文本**并**按下了 OK），并在存在的情况下将其传递给 lambda。

让我们快速看一下 lambda。这是多行 lambda 的另一个示例。到目前为止，我们看到的大多数 lambda 都是简单的一行函数，但请记住，lambda**可以**跨越多行。要支持这一点，需要做的就是像我们所做的那样将块包装在花括号中，然后一切照旧。对于这样的多行 lambda，必须小心，因为 lambda 给我们带来的可读性和简洁性的任何收益都可能很快被一个过大的 lambda 体所掩盖或抹去。在这些情况下，将代码提取到一个方法中并使用方法引用可能是明智的做法。最终，决定权在你手中，但请记住鲍勃·马丁叔叔的话--*清晰是王道*。

关于菜单的最后一项。为了更加实用，应用程序应该提供一个上下文菜单，允许用户右键单击一个进程并从那里结束它，而不是点击行，将鼠标移动到“文件”菜单等。添加上下文菜单是一个简单的操作。我们只需要修改我们在 FXML 中的`TableView`定义如下：

```java
    <TableView fx:id="processView" BorderPane.alignment="CENTER"> 
      <contextMenu> 
        <ContextMenu> 
          <items> 
            <MenuItem onAction="#killProcessHandler"  
               text="Kill Process..."/> 
          </items> 
        </ContextMenu> 
      </contextMenu> 
    </TableView> 

```

在这里，我们在`TableView`中添加了一个`contextMenu`子项。就像它的兄弟`MenuBar`一样，`contextMenu`有一个`items`子项，它又有 0 个或多个`MenuItem`子项。在这种情况下，`Kill Process...`的`MenuItem`看起来与`File`下的那个非常相似，唯一的区别是`mnemonicProcessing`信息。我们甚至重用了`ActionEvent`处理程序，因此没有额外的编码，无论您点击哪个菜单项，结束进程的行为始终相同。

# 更新进程列表

如果应用程序启动并显示了一个进程列表，但从未更新过该列表，那将毫无用处。我们需要的是定期更新列表的方法，为此，我们将使用一个`Thread`。

您可能知道，也可能不知道，`Thread`大致是在后台运行任务的一种方式（Javadoc 将其描述为程序中的*执行线程*）。系统可以是单线程或多线程的，这取决于系统的需求和运行时环境。多线程编程很难做到。幸运的是，我们这里的用例相当简单，但我们仍然必须小心，否则我们将看到一些非常意外的行为。

通常，在创建`Thread`时，您会得到的建议是实现一个`Runnable`接口，然后将其传递给线程的构造函数，这是非常好的建议，因为它使您的类层次结构更加灵活，因为您不会受到具体基类的约束（`Runnable`是一个`interface`）。然而，在我们的情况下，我们有一个相对简单的系统，从这种方法中获益不多，所以我们将直接扩展`Thread`并简化我们的代码，同时封装我们想要的行为。让我们来看看我们的新类：

```java
    private class ProcessListUpdater extends Thread { 
      private volatile boolean running = true; 

      public ProcessListRunnable() { 
        super(); 
        setDaemon(true); 
      } 

      public void shutdown() { 
        running = false; 
      } 

      @Override 
      public void run() { 
        while (running) { 
          updateList(); 
          try { 
            Thread.sleep(5000); 
          } catch (InterruptedException e) { 
              // Ignored 
            } 
        } 
      }  

      public synchronized void updateList() { 
        processList.setAll(ProcessHandle.allProcesses() 
          .collect(Collectors.toList())); 
        processView.sort(); 
      } 
    } 

```

我们有一个非常基本的类，我们给了它一个合理而有意义的名称，它扩展了`Thread`。在构造函数中，请注意我们调用了`setDaemon(true)`。这将允许我们的应用程序按预期退出，而不会阻塞，等待线程终止。我们还定义了一个`shutdown()`方法，我们将从我们的应用程序中使用它来停止线程。

`Thread`类确实有各种状态控制方法，如`stop()`、`suspend()`、`resume()`等，但这些方法都已被弃用，因为它们被认为是不安全的。搜索文章，为什么`Thread.stop`、`Thread.suspend`和`Thread.resume`被弃用？如果您想要更多细节；然而，现在建议的最佳做法是使用一个控制标志，就像我们用`running`做的那样，向`Thread`类发出信号，表明它需要清理并关闭。

最后，我们有我们的`Thread`类的核心，`run()`，它会无限循环（或直到`running`变为 false），在执行完工作后休眠五秒。实际工作是在`updateList()`中完成的，它构建了进程列表，更新了我们之前讨论过的`ObservableList`，然后指示`TableView`根据用户的排序选择重新排序自己，如果有的话。这是一个公共方法，允许我们在需要时调用它，就像我们在`killProcessHandler()`中所做的那样。这留下了以下的代码块来设置它：

```java
    @Override 
    public void initialize(URL url, ResourceBundle rb) { 
      processListUpdater = new ProcessListUpdater(); 
      processListUpdater.start(); 
      // ... 
    } 

```

以下代码将关闭它，我们已经在`closeHandler()`中看到了：

```java
    processListUpdater.shutdown(); 

```

敏锐的人会注意到`updateList()`上有`synchronized`关键字。这是为了防止由于从多个线程调用此方法而可能引起的任何竞争条件。想象一下，用户决定终止一个进程并在线程在恢复时点击确认对话框的确切时刻（这种情况比你想象的要常见）。我们可能会有两个线程同时调用`updateList()`，导致第一个线程在第二个线程调用`processList.setAll()`时刚好调用`processView.sort()`。当在另一个线程重建列表时调用`sort()`会发生什么？很难说，但可能是灾难性的，所以我们要禁止这种情况。`synchronized`关键字指示 JVM 一次只允许一个线程执行该方法，导致其他线程排队等待（请注意，它们的执行顺序是不确定的，所以你不能根据线程运行`synchronized`方法的顺序来做任何期望）。这避免了竞争条件的可能性，并确保我们的程序不会崩溃。

虽然在这里是合适的，但在使用`synchronized`方法时必须小心，因为获取和释放锁可能是昂贵的（尽管在现代 JVM 中要少得多），更重要的是，它强制线程在调用这个方法时按顺序运行，这可能会导致应用程序出现非常不希望的延迟，特别是在 GUI 应用程序中。在编写自己的多线程应用程序时要记住这一点。

# 摘要

有了这个，我们的应用程序就完成了。虽然不是一个非常复杂的应用程序，但它包括了一些有趣的技术，比如 JavaFX、Lambda、Streams、`ProcessHandle`以及相关的类和线程。

在下一章中，我们将构建一个简单的命令行实用程序来查找重复文件。通过这样做，我们将亲身体验新的文件 I/O API、Java 持久化 API（JPA）、文件哈希和一些更多的 JavaFX。


# 第三章：重复文件查找器

任何运行了一段时间的系统都会开始受到硬盘杂乱的影响。例如，大型音乐和照片收藏品尤其如此。除了最一丝不苟地复制和移动文件之外，我们最终会在这里复制一份，在那里复制一份。问题是，这些中哪些是重复的，哪些不是？在本章中，我们将构建一个文件遍历实用程序，它将扫描一组目录，寻找重复的文件。我们将能够指定是否应删除重复项，将其隔离，或者只是报告。

在本章中，我们将涵盖以下主题：

+   Java 平台模块系统

+   Java NIO（New I/O）文件 API

+   文件哈希

+   Java 持久性 API（JPA）

+   新的 Java 日期/时间 API

+   编写命令行实用程序

+   更多的 JavaFX

# 入门

这个应用程序在概念上相当简单，但比我们在上一章中看到的要复杂一些，因为我们将同时拥有命令行和图形界面。有经验的程序员很可能会立即意识到需要在这两个界面之间共享代码，因为“不要重复自己”是一个良好设计系统的许多标志之一。为了促进代码的共享，我们将引入第三个模块，提供一个可以被其他两个项目使用的库。我们将称这些模块为`lib`，`cli`和`gui`。设置项目的第一步是创建各种 Maven POM 文件来描述项目的结构。父 POM 将类似于这样：

```java
    <?xml version="1.0" encoding="UTF-8"?> 
    <project  

      xsi:schemaLocation="http://maven.apache.org/POM/4.0.0  
      http://maven.apache.org/xsd/maven-4.0.0.xsd"> 
      <modelVersion>4.0.0</modelVersion> 

     <groupId>com.steeplesoft.dupefind</groupId> 
     <artifactId>dupefind-master</artifactId> 
     <version>1.0-SNAPSHOT</version> 
     <packaging>pom</packaging> 

     <modules> 
       <module>lib</module> 
       <module>cli</module> 
       <module>gui</module> 
     </modules> 

     <name>Duplicate Finder - Master</name> 
    </project> 

```

这是一个相当典型的 POM 文件。我们将首先确定项目的父级，让我们继承一些设置、依赖关系等，避免在此项目中重复它们。接下来，我们将为项目定义 Maven 坐标。请注意，我们没有为这个项目定义版本，允许父版本级联下来。这将允许我们在一个地方根据需要增加版本，并隐式更新所有子项目。

对于那些以前没有见过多模块项目的人来说，这个 POM 的最后一个有趣的部分是“模块”部分。对于那些对此不熟悉的人来说，唯一需要注意的是，每个“模块”元素都指的是一个目录名称，它是当前目录的直接子目录，并且应该按照需要声明的顺序进行声明。在我们的情况下，CLI 和 GUI 都依赖于库，所以`lib`首先出现。接下来，我们需要为每个模块创建 POM 文件。这些都是典型的 jar 类型的 POM，所以这里不需要包含它们。每个模块中会有不同的依赖关系，但我们将根据需要进行覆盖。

# 构建库

这个项目的基础部分是库，CLI 和 GUI 都将使用它，所以从这里开始是有道理的。在设计库时——它的输入、输出和一般行为——了解我们希望这个系统做什么是有帮助的，所以让我们花点时间讨论功能需求。

如介绍中所述，我们希望能够在任意数量的目录中搜索重复文件。我们还希望能够将搜索和比较限制在特定文件中。如果我们没有指定要匹配的模式，那么我们希望检查每个文件。

最重要的部分是如何识别匹配项。当然，有许多方法可以做到这一点，但我们将使用的方法如下：

+   识别具有相同文件名的文件。想象一下那些情况，你可能已经将照片从相机下载到计算机进行安全保管，然后，后来，也许你忘记了已经下载了这些照片，所以你又将它们复制到其他地方。显然，你只想要一份拷贝，但是例如`IMG_9615.JPG`这个文件，在临时目录中和你的图片备份目录中是一样的吗？通过识别具有相同名称的文件，我们可以测试它们以确保。

+   识别具有相同大小的文件。这里匹配的可能性较小，但仍然存在机会。例如，一些照片管理软件在从设备导入图像时，如果发现具有相同名称的文件，将修改第二个文件的文件名并存储两个文件，而不是停止导入并要求立即用户干预。这可能导致大量文件，如`IMG_9615.JPG`和`IMG_9615-1.JPG`。这个检查将有助于识别这些情况。

+   对于上面的每个匹配，为了确定这些文件是否真的匹配，我们将基于文件内容生成一个哈希。如果多个文件生成相同的哈希，那么这些文件是相同的可能性极高。我们将标记这些文件为潜在的重复文件。

这是一个非常简单的算法，应该非常有效，但我们确实有一个问题，尽管这个问题可能并不立即显现。如果你有大量文件，特别是一个潜在重复文件较多的集合，处理所有这些文件可能是一个非常耗时的过程，我们希望尽量减轻这种情况，这就引出了一些非功能性要求：

+   程序应以并发方式处理文件，以尽量减少处理大文件集所需的时间

+   并发性应该受到限制，以免系统被处理请求所压倒

+   考虑到可能有大量数据，系统必须设计成避免使用所有可用的 RAM 并导致系统不稳定

有了这个相当简单的功能和非功能性要求清单，我们应该准备开始了。和上一个应用一样，让我们从定义我们的模块开始。在`src/main/java`中，我们将创建`module-info.java`：

```java
    module com.steeplesoft.dupefind.lib { 
      exports com.steeplesoft.dupefind.lib; 
    } 

```

最初，编译器和 IDE 会抱怨`com.steeplesoft.dupefind.lib`包不存在，并且不会编译项目。现在没关系，因为我们将立即创建该包。

在功能要求中使用**并发**这个词，很可能会立即让人想到线程。我们在第二章中介绍了线程的概念，所以如果你对它们不熟悉，请回顾一下上一章的内容。

我们在这个项目中使用的线程与上一个项目中的线程不同，因为我们有一些需要完成的工作，一旦完成，我们希望线程退出。我们还需要等待这些线程完成工作，以便我们可以分析它。在`java.util.concurrent`包中，JDK 提供了几种选项来实现这一点。

# 使用 Future 接口的并发 Java

其中一个更常见和受欢迎的 API 是`Future<V>`接口。`Future`是封装异步计算的一种方式。通常，`Future`实例是由`ExecutorService`返回的，我们稍后会讨论。一旦调用代码获得了对`Future`的引用，它就可以在`Future`在后台的另一个线程中运行时继续处理其他任务。当调用者准备好获取`Future`的结果时，它调用`Future.get()`。如果`Future`已经完成了它的工作，调用将立即返回结果。然而，如果`Future`仍在工作，对`get()`的调用将阻塞直到`Future`完成。

然而，对于我们的用途，`Future`并不是最合适的选择。在审查非功能性需求时，我们看到了避免通过明确列出的可用内存耗尽来使系统崩溃的愿望。正如我们将在后面看到的那样，这将通过将数据存储在轻量级的磁盘数据库中来实现，我们将通过存储检索到的文件信息而不是通过收集数据，然后在后处理方法中保存它来实现。鉴于此，我们的`Future`将不会返回任何东西。虽然有一种方法可以使其工作（将`Future`定义为`Future<?>`并返回`null`），但这并不是最自然的方法。

也许最合适的方法是`ExecutorService`，它是提供额外功能的`Executor`，例如创建`Future`（如前所述）和管理队列的终止。那么，`Executor`是什么？`Executor`是一个执行`Runnable`的机制，比简单调用`new Thread(runnable).start()`更健壮。接口本身非常基本，只包括`execute(Runnable)`方法，因此从 Javadoc 中无法立即看出其价值。然而，如果您查看`ExecutorService`，它是 JDK 提供的所有`Executor`实现的接口，以及各种`Executor`实现，它们的价值很容易变得更加明显。现在让我们快速调查一下。

查看`Executors`类，我们可以看到五种不同类型的`Executor`实现：缓存线程池、固定大小线程池、定时线程池、单线程执行器和工作窃取线程池。除了单线程`Executor`之外，每个都可以直接实例化（`ThreadPoolExecutor`、`ScheduledThreadPoolExecutor`和`ForkJoinPool`），但 JDK 的作者建议用户使用`Executors`类上的便利方法。也就是说，每个选项是什么，为什么选择其中之一？

+   `Executors.newCachedThreadPool()`: 这将返回一个提供缓存线程池的`Executor`。当任务到来时，`Executor`会尝试找到一个未使用的线程来执行任务。如果找不到，就会创建一个新的`Thread`并开始工作。任务完成后，`Thread`会返回到池中等待重用。大约 60 秒后，未使用的线程将被销毁并从池中移除，以防止资源被分配而永远不释放。但是，必须小心使用这个`Executor`，因为线程池是无限的，这意味着在大量使用时，系统可能会被活跃的线程压倒。

+   `Executors.newFixedThreadPool(int nThreads)`: 这个方法返回一个类似于前面提到的`Executor`，唯一的区别是线程池被限制为最多`nThreads`。

+   `Executors.newScheduledThreadPool(int corePoolSize)`: 这个`Executor`能够安排任务在可选的初始延迟后定期运行，基于延迟和`TimeUnit`值。例如，参见`schedule(Runnable command, long delay, TimeUnit unit)`方法。

+   `Executors.newSingleThreadExecutor()`: 这个方法将返回一个`Executor`，它将使用单个线程来执行提交给它的任务。任务保证按照它们被提交的顺序执行。

+   `Executors.newWorkStealingExecutor()`: 这个方法将返回一个所谓的**工作窃取**`Executor`，它是`ForkJoinPool`类型。提交给这个`Executor`的任务被编写成能够将工作分配给额外的工作线程，直到工作量低于用户定义的阈值。

考虑到我们的非功能性需求，固定大小的`ThreadPoolExecutor`似乎是最合适的。然而，我们需要支持的一个配置选项是强制为找到的每个文件生成哈希值。根据前面的算法，只有具有重复名称或大小的文件才会被哈希。然而，用户可能希望对他们的文件规范进行更彻底的分析，并希望强制对每个文件进行哈希。我们将使用工作窃取（或分叉/加入）池来实现这一点。

有了我们选择的线程方法，让我们来看看库的入口点，一个我们将称之为`FileFinder`的类。由于这是我们的入口点，它需要知道我们想要搜索的位置和我们想要搜索的内容。这将给我们实例变量`sourcePaths`和`patterns`：

```java
    private final Set<Path> sourcePaths = new HashSet<>(); 
    private final Set<String> patterns = new HashSet<>(); 

```

我们将变量声明为`private`，因为这是一个良好的面向对象的实践。我们还将它们声明为`final`，以帮助避免这些变量被分配新值而导致意外数据丢失的微妙错误。一般来说，我发现将变量默认标记为`final`是一个很好的实践，可以防止这种微妙的错误。在这样一个类的实例变量的情况下，只有在它被立即赋值，就像我们在这里做的那样，或者如果它在类的构造函数中被赋值，它才能被声明为`final`。

我们现在也想定义我们的`ExecutorService`：

```java
    private final ExecutorService es = 
      Executors.newFixedThreadPool(5); 

```

我们已经相当随意地选择将我们的线程池限制为五个线程，因为这似乎是在为繁重的请求提供足够数量的工作线程的同时，不分配大量可能在大多数情况下不会使用的线程之间取得一个公平的平衡。在我们的情况下，这可能是一个被夸大的小问题，但这绝对是需要牢记的事情。

接下来，我们需要提供一种方法来存储找到的任何重复项。考虑以下代码行作为示例：

```java
    private final Map<String, List<FileInfo>> duplicates =  
      new HashMap<>(); 

```

稍后我们会看到更多细节，但现在我们需要注意的是这是一个`Map`，其中包含由文件哈希键入的`List<FileInfo>`对象。

最后需要注意的变量是一些可能有点意外的东西——一个`EntityManagerFactory`。你可能会问自己，那是什么？`EntityManagerFactory`是一个与**Java 持久化 API**（**JPA**）定义的持久化单元进行交互的接口，它是 Java 企业版规范的一部分。幸运的是，规范是以这样一种方式编写的，以强制它在像我们这样的**标准版**（**SE**）上下文中可用。

那么，我们使用这样的 API 做什么呢？如果你回顾一下非功能性需求，我们已经指定了我们要确保查找重复文件不会耗尽系统上可用的内存。对于非常大的搜索，文件列表及其哈希值可能会增长到一个有问题的大小。再加上生成哈希值所需的内存，我们稍后会讨论，很可能会遇到内存不足的情况。因此，我们将使用 JPA 将我们的搜索信息保存在一个简单的轻量级数据库（SQLite）中，这将允许我们将数据保存到磁盘。它还将允许我们比重复地在内存结构上进行迭代更有效地查询和过滤结果。

在我们可以使用这些 API 之前，我们需要更新我们的模块描述符，让系统知道我们现在需要持久化模块。考虑以下代码片段作为示例：

```java
    module dupefind.lib { 
      exports com.steeplesoft.dupefind.lib; 
      requires java.logging; 
      requires javax.persistence; 
    } 

```

我们已经声明系统需要`javax.persistence`和`java.logging`，我们稍后会使用它们。正如我们在第二章中讨论的那样，*在 Java 中管理进程*，如果这些模块中的任何一个不存在，JVM 实例将无法启动。

模块定义中可能更重要的部分是`exports`子句。通过这一行（可以有 0 个或多个），我们告诉系统我们正在导出指定包中的所有类型。此行将允许我们的 CLI 模块（稍后我们将介绍）使用该模块中的类（以及接口、枚举等，如果我们要添加的话）。如果类型的包没有`export`，消费模块将无法看到该类型，稍后我们也将演示。

有了这个理解，让我们来看一下我们的构造函数：

```java
    public FileFinder() { 
      Map<String, String> props = new HashMap<>(); 
      props.put("javax.persistence.jdbc.url",  
       "jdbc:sqlite:" +  
       System.getProperty("user.home") +  
       File.separator +  
       ".dupfinder.db"); 
      factory = Persistence.createEntityManagerFactory 
       ("dupefinder", props); 
      purgeExistingFileInfo(); 
    } 

```

为了配置持久性单元，JPA 通常使用`persistence.xml`文件。但在我们的情况下，我们希望更多地控制数据库文件的存储位置。正如您在前面的代码中所看到的，我们正在使用`user.home`环境变量构建 JDBC URL。然后我们将其存储在`Map`中，使用 JPA 定义的键来指定 URL。然后将此`Map`传递给`createEntityManagerFactory`方法，该方法覆盖了`persistence.xml`中设置的任何内容。这允许我们将数据库放在适合用户操作系统的主目录中。

构造和配置好我们的类后，现在是时候看看我们将如何找到重复的文件了：

```java
    public void find() { 
      List<PathMatcher> matchers = patterns.stream() 
       .map(s -> !s.startsWith("**") ? "**/" + s : s) 
       .map(p -> FileSystems.getDefault() 
       .getPathMatcher("glob:" + p)) 
       .collect(Collectors.toList()); 

```

我们的第一步是根据用户指定的模式创建`PathMatcher`实例的列表。`PathMatcher`实例是一个功能接口，由试图匹配文件和路径的对象实现。我们的实例是从`FileSystems`类中检索的。

在请求`PathMatcher`时，我们必须指定 globbing 模式。正如在第一个调用`map()`中所看到的，我们必须对用户指定的内容进行调整。通常，模式掩码被简单地指定为`*.jpg`之类的东西。然而，这样的模式掩码不会按照用户的期望工作，因为它只会在当前目录中查找，而不会遍历任何子目录。为了做到这一点，模式必须以`**/`为前缀，我们在调用`map()`时这样做。有了我们调整后的模式，我们从系统的默认`FileSystem`中请求`PathMatcher`实例。请注意，我们将匹配模式指定为`"glob:" + p`，因为我们需要指示我们确实正在指定`glob`文件。

准备好我们的匹配器后，我们准备开始搜索。我们用这段代码来做到这一点：

```java
    sourcePaths.stream() 
     .map(p -> new FindFileTask(p)) 
     .forEach(fft -> es.execute(fft)); 

```

使用`Stream` API，我们将每个源路径映射到一个 lambda，该 lambda 创建`FindFileTask`的实例，为其提供它将搜索的源路径。然后，这些`FileFindTask`实例将通过`execute()`方法传递给我们的`ExecutorService`。

`FileFindTask`方法是该过程的工作马。它是一个`Runnable`，因为我们将把它提交给`ExecutorService`，但它也是一个`FileVisitor<Path>`，因为它将用于遍历文件树，我们将从`run()`方法中执行：

```java
    @Override 
    public void run() { 
      final EntityTransaction transaction = em.getTransaction(); 
      try { 
        transaction.begin(); 
        Files.walkFileTree(startDir, this); 
        transaction.commit(); 
      } catch (IOException ex) { 
        transaction.rollback(); 
      } 
    } 

```

由于我们将通过 JPA 向数据库插入数据，我们需要将事务作为第一步启动。由于这是一个应用程序管理的`EntityManager`，我们必须手动管理事务。我们在`try/catch`块外获取对`EntityTransaction`实例的引用，以简化引用。在`try`块内，我们启动事务，通过`Files.walkFileTree()`开始文件遍历，然后如果进程成功，提交事务。如果失败-如果抛出了`Exception`-我们回滚事务。

`FileVisitor` API 需要许多方法，其中大多数都不是太有趣，但出于清晰起见，我们将它们显示出来：

```java
    @Override 
    public FileVisitResult preVisitDirectory(final Path dir,  
    final BasicFileAttributes attrs) throws IOException { 
      return Files.isReadable(dir) ?  
       FileVisitResult.CONTINUE : FileVisitResult.SKIP_SUBTREE; 
    } 

```

在这里，我们告诉系统，如果目录是可读的，那么我们就继续遍历该目录。否则，我们跳过它：

```java
    @Override 
    public FileVisitResult visitFileFailed(final Path file,  
     final IOException exc) throws IOException { 
       return FileVisitResult.SKIP_SUBTREE; 
    } 

```

API 要求实现此方法，但我们对文件读取失败不太感兴趣，因此我们只是返回一个跳过的结果：

```java
    @Override 
    public FileVisitResult postVisitDirectory(final Path dir,  
     final IOException exc) throws IOException { 
       return FileVisitResult.CONTINUE; 
    } 

```

与前面的方法类似，这个方法是必需的，但我们对这个特定事件不感兴趣，所以我们通知系统继续：

```java
    @Override 
    public FileVisitResult visitFile(final Path file, final
     BasicFileAttributes attrs) throws IOException { 
       if (Files.isReadable(file) && isMatch(file)) { 
         addFile(file); 
       } 
       return FileVisitResult.CONTINUE; 
    } 

```

现在我们来到了一个我们感兴趣的方法。我们将检查文件是否可读，然后检查是否匹配。如果是，我们就添加文件。无论如何，我们都会继续遍历树。我们如何测试文件是否匹配？考虑以下代码片段作为示例：

```java
    private boolean isMatch(final Path file) { 
      return matchers.isEmpty() ? true :  
       matchers.stream().anyMatch((m) -> m.matches(file)); 
    } 

```

我们遍历我们之前传递给类的`PathMatcher`实例的列表。如果`List`为空，这意味着用户没有指定任何模式，方法的结果将始终为`true`。但是，如果`List`中有项目，我们就在`List`上使用`anyMatch()`方法，传递一个检查`Path`与`PathMatcher`实例匹配的 lambda。

添加文件非常简单：

```java
    private void addFile(Path file) throws IOException { 
      FileInfo info = new FileInfo(); 
      info.setFileName(file.getFileName().toString()); 
      info.setPath(file.toRealPath().toString()); 
      info.setSize(file.toFile().length()); 
      em.persist(info); 
    } 

```

我们创建一个`FileInfo`实例，设置属性，然后通过`em.persist()`将其持久化到数据库中。

定义并提交给`ExecutorService`的任务后，我们需要坐下来等待。我们通过以下两个方法调用来做到这一点：

```java
    es.shutdown(); 
    es.awaitTermination(Integer.MAX_VALUE, TimeUnit.SECONDS); 

```

第一步是要求`ExecutorService`关闭。`shutdown()`方法会立即返回，但它会指示`ExecutorService`拒绝任何新任务，并在空闲时关闭其线程。如果没有这一步，线程将会无限期地继续运行。接下来，我们将等待服务关闭。我们指定最大等待时间，以确保我们给予任务完成的时间。一旦这个方法返回，我们就准备好处理结果了，这是在接下来的`postProcessFiles()`方法中完成的：

```java
    private void postProcessFiles() { 
      EntityManager em = factory.createEntityManager(); 
      List<FileInfo> files = getDuplicates(em, "fileName"); 

```

# 使用 JPA 进行现代数据库访问

让我们在这里停顿一下。还记得我们对**Java Persistence API**（**JPA**）和数据库的讨论吗？这就是我们看到它的地方。通过 JPA，与数据库的交互是通过`EntityManager`接口完成的，我们从名为`EntityManagerFactory`的接口中检索到它。重要的是要注意，`EntityManager`实例不是线程安全的，因此它们不应该在线程之间共享。这就是为什么我们没有在构造函数中创建一个并传递它的原因。当然，这是一个局部变量，所以在这一点上我们不需要太担心，直到我们决定将它作为参数传递给另一个方法时。正如我们将在一会儿看到的，一切都发生在同一个线程中，所以在目前的代码中我们不必担心线程安全问题。

通过我们的`EntityManager`，我们调用`getDuplicates()`方法并传递管理器和字段名`fileName`。这就是那个方法的样子：

```java
    private List<FileInfo> getDuplicates(EntityManager em,  
     String fieldName) { 
       List<FileInfo> files = em.createQuery( 
         DUPLICATE_SQL.replace("%FIELD%", fieldName), 
          FileInfo.class).getResultList(); 
       return files; 
    } 

```

这是对 Java Persistence API 的相当简单的使用--我们正在创建一个查询，并告诉它我们想要，并获得一个`List`的`FileInfo`引用。`createQuery()`方法创建一个`TypedQuery`对象，我们将调用`getResultList()`来检索结果，这给我们`List<FileInfo>`。

在我们进一步进行之前，我们需要对 Java 持久化 API 进行简要介绍。JPA 是一种被称为**对象关系映射**（**ORM**）工具的东西。它提供了一种面向对象、类型安全和与数据库无关的方式来存储数据，通常是在关系数据库中。该规范/库允许应用程序作者使用具体的 Java 类来定义他们的数据模型，然后以很少考虑当前使用的数据库的具体机制来持久化和/或读取它们。（开发人员并没有完全屏蔽数据库问题——是否应该这样做还有争议——但这些问题被抽象到 JPA 接口的后面，大大减少了这些问题）。获取连接、创建 SQL、将其发送到服务器、处理结果等过程都由库处理，使得更多的精力集中在应用程序的业务上，而不是在底层实现上。它还允许在数据库之间具有很高的可移植性，因此应用程序（或库）可以很容易地在不同系统之间进行最小的更改（通常限于配置更改）。

JPA 的核心是`Entity`，即应用程序的业务对象（或领域模型，如果您愿意），它对应用程序的数据进行建模。这在 Java 代码中表示为**普通的 Java 对象**（**POJO**），并用各种注释进行标记。对所有这些注释（或整个 API）的完整讨论超出了本书的范围，但我们将使用足够多的注释来让您入门。

有了这个基本的解释，让我们来看看我们唯一的实体——`FileInfo`类：

```java
    @Entity 
    public class FileInfo implements Serializable { 
      @GeneratedValue 
      @Id 
      private int id; 
      private String fileName; 
      private String path; 
      private long size; 
      private String hash; 
    } 

```

这个类有五个属性。唯一需要特别关注的是`id`。这个属性保存每一行的主键值，因此我们用`@Id`对其进行注释。我们还用`@GeneratedValue`对这个字段进行注释，以指示我们有一个简单的主键，我们希望系统生成一个值。这个注释有两个属性：`strategy`和`generator`。策略的默认值是`GenerationType.AUTO`，我们在这里很高兴地接受。其他选项包括`IDENTITY`、`SEQUENCE`和`TABLE`。在更复杂的用法中，您可能希望显式地指定一个策略，这允许您对生成键的方式进行微调（例如，起始数字、分配大小、序列或表的名称等）。通过选择`AUTO`，我们告诉 JPA 选择适当的生成策略来适应我们的目标数据库。如果您指定的策略不是`AUTO`，您还需要使用`@SequenceGenerator`来为`SEQUENCE`指定细节，使用`@TableGenerator`来为`TABLE`指定细节。您还需要使用生成器属性将生成器的 ID 传递给`@GeneratedValue`注释。我们使用默认值，因此不需要为此属性指定值。

接下来的四个字段是我们确定需要捕获的数据。请注意，如果我们不需要指定这些字段与数据库列的映射的任何特殊内容，那么不需要注释。但是，如果我们想要更改默认值，我们可以应用`@Column`注释并设置适当的属性，可以是`columnDefinition`（用于帮助生成列的 DDL）、`insertable`、`length`、`name`、`nullable`、`precision`、`scale`、`table`、`unique`和`updatable`中的一个或多个。同样，我们对默认值感到满意。

JPA 还要求每个属性都有一个 getter 和一个 setter；规范似乎措辞奇怪，这导致了一些模棱两可，不确定是否这是一个硬性要求，不同的 JPA 实现处理方式也不同，但作为一种实践，提供两者肯定更安全。如果你需要一个只读属性，你可以尝试使用没有 setter 的方法，或者简单地使用一个空操作方法。我们没有在这里展示 getter 和 setter，因为它们没有什么有趣的地方。我们还省略了 IDE 生成的`equals()`和`hashCode()`方法。

为了帮助演示模块系统，我们将我们的实体放在`com.steeplesoft.dupefind.lib.model`子包中。我们会透露一点底牌，提前宣布这个类将被我们的 CLI 和 GUI 模块使用，所以我们需要更新我们的模块定义如下：

```java
    module dupefind.lib { 
      exports com.steeplesoft.dupefind.lib; 
      exports com.steeplesoft.dupefind.lib.model; 
      requires java.logging; 
      requires javax.persistence; 
    } 

```

这就是我们的实体，现在让我们把注意力转回到我们的应用逻辑上。`createQuery()`调用值得讨论一下。通常情况下，使用 JPA 时，查询是用所谓的**JPAQL**（**Java 持久化 API 查询语言**）编写的。它看起来很像 SQL，但更具面向对象的感觉。例如，如果我们想查询数据库中的每个`FileInfo`记录，我们可以使用以下查询：

```java
 SELECT f FROM FileInfo f 

```

我已经将关键字都大写了，变量名都小写了，实体名都是驼峰式写法。这主要是一种风格问题，但大多数标识符是不区分大小写的，JPA 确实要求实体名的大小写与它所代表的 Java 类的大小写匹配。你还必须为实体指定一个别名或标识变量，我们简单地称之为`f`。

要获取特定的`FileInfo`记录，可以指定一个`WHERE`子句，如下所示：

```java
 SELECT f from FileInfo f WHERE f.fileName = :name 

```

通过这个查询，我们可以像 SQL 一样过滤查询，并且，就像 SQL 一样，我们指定了一个位置参数。参数可以是一个名称，就像我们在这里做的一样，或者简单地是一个`?`。如果你使用一个名称，你可以使用该名称在查询中设置参数值。如果你使用问号，你必须使用其在查询中的索引设置参数。对于小型查询，这通常是可以的，但对于更大、更复杂的查询，我建议使用名称，这样你就不必管理索引值，因为这几乎肯定会在某个时候导致错误。设置参数可能看起来像这样：

```java
 Query query = em.createQuery( 
      "SELECT f from FileInfo f WHERE f.fileName = :name"); 
    query.setParameter("name", "test3.txt"); 
    query.getResultList().stream() //... 

```

说到这一点，让我们来看看我们的查询：

```java
 SELECT f  
    FROM FileInfo f,  
      (SELECT s.%FIELD%  
        FROM FileInfo s  
        GROUP BY s.%FIELD%  
        HAVING (COUNT(s.%FIELD%) > 1)) g 
    WHERE f.%FIELD% = g.%FIELD%  
    AND f.%FIELD% IS NOT NULL  
    ORDER BY f.fileName, f.path 

```

这个查询有一定的复杂性，让我们来分解一下看看发生了什么。首先，在我们的`SELECT`查询中，我们只会指定`f`，这是我们要查询的实体的标识变量。接下来，我们从一个常规表和一个临时表中进行选择，这由`FROM`子句中的子选择定义。为什么我们要这样做呢？我们需要识别所有具有重复值（`fileName`、`size`或`hash`）的行。为了做到这一点，我们使用了一个带有`COUNT`聚合函数的`HAVING`子句，`HAVING (COUNT(fieldName > 1))`，这实际上是说，给我所有这个字段出现超过一次的行。`HAVING`子句需要一个`GROUP BY`子句，一旦完成，所有具有重复值的行都会被聚合成一行。一旦我们有了那些行的列表，我们将把真实（或物理）表与这些结果连接起来，以过滤我们的物理表。最后，在`WHERE`子句中过滤掉空字段，然后按`fileName`和`path`排序，这样我们就不必在我们的 Java 代码中这样做了，这可能比在数据库中进行的效率要低--数据库是为这样的操作而设计的系统。

你还应该注意 SQL 中的`%FIELD%`属性。我们将为多个字段运行相同的查询，因此我们只编写了一次查询，并在文本中放置了一个我们将用所需字段替换的标记，这有点像*穷人的*模板。当然，有各种各样的方法可以做到这一点（你可能有更好的方法），但这种方法简单易用，所以在这种环境中是完全可以接受的。

我们还应该注意，一般来说，要么将 SQL 与值连接起来，要么像我们现在这样做字符串替换，都是一个非常糟糕的主意，但我们的情况有点不同。如果我们接受用户输入并以这种方式将其插入 SQL，那么我们肯定会成为 SQL 注入攻击的目标。然而，在我们这里的用法中，我们并没有从用户那里获取输入，所以这种方法应该是完全安全的。在数据库性能方面，这也不应该有任何不利影响。虽然我们将需要三个不同的硬解析（每个字段一个），但这与我们在源文件中硬编码查询没有什么不同。这些问题以及许多其他问题在编写查询时总是值得考虑的（这也是我说开发人员在很大程度上不用担心数据库问题的原因）。

所有这些都让我们完成了第一步，即识别所有具有相同名称的文件。现在我们需要识别具有相同大小的文件，可以使用以下代码来完成：

```java
    List<FileInfo> files = getDuplicates(em, "fileName"); 
    files.addAll(getDuplicates(em, "size")); 

```

在我们调用查找重复文件名的方法时，我们声明了一个局部变量`files`来存储这些结果。在查找具有重复大小的文件时，我们调用相同的`getDuplicates()`方法，但使用正确的字段名称，并通过`List.addAll()`方法简单地将其添加到`files`中。

我们现在已经有了所有可能的重复文件的完整列表，所以我们需要为每个文件生成哈希值，以查看它们是否真的是重复的。我们将使用以下循环来完成这个任务：

```java
    em.getTransaction().begin(); 
    files.forEach(f -> calculateHash(f)); 
    em.getTransaction().commit(); 

```

简而言之，我们开始一个事务（因为我们将向数据库插入数据），然后通过`List.forEach()`和一个调用`calculateHash(f)`的 lambda 循环遍历每个可能的重复文件，然后传递`FileInfo`实例。一旦循环终止，我们就提交事务以保存我们的更改。

`calculateHash()`方法是做什么的？让我们来看一下：

```java
    private void calculateHash(FileInfo file) { 
      try { 
        MessageDigest messageDigest =  
          MessageDigest.getInstance("SHA3-256"); 
        messageDigest.update(Files.readAllBytes( 
          Paths.get(file.getPath()))); 
        ByteArrayInputStream inputStream =  
          new ByteArrayInputStream(messageDigest.digest()); 
        String hash = IntStream.generate(inputStream::read) 
         .limit(inputStream.available()) 
         .mapToObj(i -> Integer.toHexString(i)) 
         .map(s -> ("00" + s).substring(s.length())) 
         .collect(Collectors.joining()); 
        file.setHash(hash); 
      } catch (NoSuchAlgorithmException | IOException ex) { 
        throw new RuntimeException(ex); 
      } 
    }  

```

这个简单的方法封装了读取文件内容和生成哈希所需的工作。它使用`SHA3-256`哈希请求`MessageDigest`的一个实例，这是 Java 9 支持的四种新哈希算法之一（另外三种是`SHA3-224`、`SHA3-384`和`SHA3-512`）。许多开发人员的第一个想法是使用 MD-5 或 SHA-1，但这些已不再被认为是可靠的。使用新的 SHA-3 应该保证我们避免任何错误的结果。

该方法的其余部分在其工作方式方面非常有趣。首先，它读取指定文件的所有字节，并将它们传递给`MessageDigest.update()`，这将更新`MessageDigest`对象的内部状态，以给我们想要的哈希值。接下来，我们创建一个包装`messageDigest.digest()`结果的`ByteArrayInputStream`。

有了我们的哈希值准备好了，我们将基于这些字节生成一个字符串。我们将通过使用`IntStream.generate()`方法生成一个流，使用我们刚刚创建的`InputStream`作为源。我们将限制流生成到`inputStream`中可用的字节。对于每个字节，我们将通过`Integer.toHexString()`将其转换为字符串；然后用零填充到两个空格，这样可以防止例如单个十六进制字符`E`和`F`被解释为`EF`；然后使用`Collections.joining()`将它们全部收集到一个字符串中。最后，我们将该字符串值更新到`FileInfo`对象中。

敏锐的人可能会注意到一些有趣的事情：我们调用`FileInfo.setHash()`来更改对象的值，但我们从未告诉系统要持久化这些更改。这是因为我们的`FileInfo`实例是一个受管理的实例，这意味着我们从 JPA 那里得到了它，JPA 在关注它，可以这么说。由于我们通过 JPA 检索了它，当我们对其状态进行任何更改时，JPA 知道需要持久化这些更改。当我们在调用方法中调用`em.getTransaction().commit()`时，JPA 会自动将这些更改保存到数据库中。

这种自动持久化有一个陷阱：如果您通过 JPA 检索对象，然后将其传递到某种序列化对象的障碍之后，例如通过远程 EJB 接口，那么 JPA 实体就被称为“分离”。要重新将其附加到持久性上下文中，您需要调用`entityManager.merge()`，之后这种行为将恢复。除非您有必要将持久性上下文的内存状态与底层数据库同步，否则无需调用`entityManager.flush()`。

一旦我们计算出潜在重复文件的哈希值（在这一点上，鉴于它们具有重复的 SHA-3 哈希值，它们几乎肯定是实际的重复文件），我们就可以准备收集并报告它们：

```java
    getDuplicates(em, "hash").forEach(f -> coalesceDuplicates(f)); 
    em.close(); 

```

我们调用相同的`getDuplicates()`方法来查找重复的哈希值，并将每个记录传递给`coalesceDuplicates()`方法，该方法将以适合向上报告到我们的 CLI 或 GUI 层的方式对其进行分组，或者，也许是向任何其他使用此功能的程序：

```java
    private void coalesceDuplicates(FileInfo f) { 
      String name = f.getFileName(); 
      List<FileInfo> dupes = duplicates.get(name); 
      if (dupes == null) { 
        dupes = new ArrayList<>(); 
        duplicates.put(name, dupes); 
      } 
      dupes.add(f); 
    } 

```

这个简单的方法遵循了一个可能非常熟悉的模式：

1.  从基于键的`Map`中获取`List`，文件名。

1.  如果地图不存在，则创建它并将其添加到地图中。

1.  将`FileInfo`对象添加到列表中。

这完成了重复文件检测。回到`find()`，我们将调用`factory.close()`来成为一个良好的 JPA 公民，然后返回到调用代码。有了这个，我们就可以构建我们的 CLI 了。

# 构建命令行界面

与我们的新库进行交互的主要方式将是我们现在要开发的命令行界面。不幸的是，Java SDK 没有内置的功能来帮助创建复杂的命令行实用程序。如果您已经使用 Java 一段时间，您可能已经看到以下方法签名：

```java
    public static void main(String[] args) 

```

显然，有一种机制来处理命令行参数。`public static void main`方法会传递表示用户在命令行上提供的参数的字符串数组，但这就是它的全部了。为了解析选项，开发人员需要迭代数组，分析每个条目。可能看起来像这样：

```java
    int i = 0; 
    while (i < args.length) { 
      if ("--source".equals(args[i])) { 
         System.out.println("--source = " + args[++i]); 
      } else if ("--target".equals(args[i])) { 
         System.out.println("--target = " + args[++i]); 
      } else if ("--force".equals(args[i])) { 
        System.out.println("--force set to true"); 
      } 
      i++; 
    } 

```

这是一个有效的解决方案，但非常天真和容易出错。它假设跟在`--source`和`--target`后面的是该参数的值。如果用户输入`--source --target /foo`，那么我们的处理器就会出错。显然，需要更好的解决方案。幸运的是，我们有选择。

如果您搜索 Java 命令行库，您会发现有大量的库（至少在最后一次统计时有 10 个）。我们在这里的空间（和时间）有限，所以显然无法讨论所有这些库，所以我将提到我熟悉的前三个：Apache Commons CLI，Airline 和 Crest。这些库中的每一个都与其竞争对手有一些相当重要的区别。

Commons CLI 采用更加程序化的方法；可用选项的列表、名称、描述、是否有参数等都是使用 Java 方法调用来定义的。创建了`Options`列表后，命令行参数就会被手动解析。前面的示例可以重写如下：

```java
    public static void main(String[] args) throws ParseException { 
      Options options = new Options(); 
      options.addOption("s", "source", true, "The source"); 
      options.addOption("t", "target", true, "The target"); 
      options.addOption("f", "force", false, "Force"); 
      CommandLineParser parser = new DefaultParser(); 
      CommandLine cmd = parser.parse(options, args); 
      if (cmd.hasOption("source")) { 
        System.out.println("--source = " +  
          cmd.getOptionValue("source")); 
      } 
      if (cmd.hasOption("target")) { 
        System.out.println("--target = " +  
          cmd.getOptionValue("target")); 
      } 
      if (cmd.hasOption("force")) { 
         System.out.println("--force set to true"); 
      } 
    } 

```

这当然更加详细，但我认为它也更加健壮。我们可以为选项指定长名称和短名称（`--source`与`-s`），我们可以给它一个描述，并且最重要的是，我们获得了内置验证，以确保选项具有其所需的值。尽管这是一个改进，但我从经验中学到，这里的程序化方法在实践中变得乏味。让我们看看我们的下一个候选者如何表现。

航空公司是一个命令行库，最初作为 GitHub 上 airlift 组织的一部分编写。在经过一段时间的停滞后，Rob Vesse 对其进行了分叉，并赋予了新的生命（http://rvesse.github.io/airline）。航空公司对命令行定义的方法更加基于类--要定义一个命令实用程序，您需要声明一个新类，并适当地使用一些注释进行标记。让我们使用航空公司来实现我们之前的简单命令行：

```java
    @Command(name = "copy", description = "Copy a file") 
    public class CopyCommand { 
      @Option(name = {"-s", "--source"}, description = "The source") 
      private String source; 
      @Option(name = {"-t", "--target"}, description = "The target") 
      private String target; 
      @Option(name = {"-f", "--force"}, description = "Force") 
      private boolean force = false; 
      public static void main(String[] args) { 
        SingleCommand<CopyCommand> parser =  
          SingleCommand.singleCommand(CopyCommand.class); 
        CopyCommand cmd = parser.parse(args); 
        cmd.run(); 
      } 

      private void run() { 
        System.out.println("--source = " + source); 
        System.out.println("--target = " + target); 
        if (force) { 
          System.out.println("--force set to true"); 
        } 
      } 
    } 

```

选项处理在代码大小方面不断增长，但我们对支持的选项以及它们各自的含义也越来越清晰。通过类声明上的`@Command`清晰地定义了我们的命令。可能的选项通过`@Option`--注释的实例变量来界定，而`run()`中的业务逻辑完全不包含命令行解析代码。在调用此方法时，所有数据都已被提取，我们准备好开始工作。这看起来非常不错，但让我们看看我们的最后一个竞争者有什么提供。

Crest 是 Tomitribe 的一个库，该公司是 TomEE 的背后公司，TomEE 是基于备受尊敬的 Tomcat Servlet 容器的“全 Apache Java EE Web Profile 认证堆栈”。Crest 对命令定义的方法是基于方法的，您需要为每个命令定义一个方法。它还使用注释，并且提供了开箱即用的 Bean 验证，以及可选的命令发现。重新实现我们的简单命令可能看起来像这样：

```java
    public class Commands { 
      @Command 
      public void copy(@Option("source") String source, 
        @Option("target") String target, 
        @Option("force") @Default("false") boolean force) { 
          System.out.println("--source = " + source); 
          System.out.println("--target = " + target); 
          if (force) { 
            System.out.println("--force set to true"); 
          } 
       } 
    } 

```

这似乎是两全其美的最佳选择：它既简洁又能保持命令的实际逻辑不受任何 CLI 解析的影响，除非您对方法上的注释感到困扰。尽管实际的逻辑实现代码不受这些影响。虽然航空公司和 Crest 都提供了对方没有的功能，但对我来说，Crest 更胜一筹，所以我们将使用它来实现我们的命令行界面。

有了选择的库，让我们看看我们的 CLI 可能是什么样子。最重要的是，我们需要能够指定要搜索的路径（或路径）。很可能，这些路径中的大多数文件将具有相同的扩展名，但这肯定不会总是这种情况，因此我们希望允许用户仅指定要匹配的文件模式（例如`.jpg`）。一些用户可能还对运行扫描需要多长时间感到好奇，因此让我们加入一个开关来打开该输出。最后，让我们添加一个开关，使该过程更加详细。

有了我们的功能要求，让我们开始编写我们的命令。Crest 在其命令声明中是基于方法的，但我们仍然需要一个类来放置我们的方法。如果这个 CLI 更复杂（或者，例如，如果您正在为应用服务器编写 CLI），您可以轻松地将几个 CLI 命令放在同一个类中，或者将类似的命令分组在几个不同的类中。您如何结构它们完全取决于您，因为 Crest 对您选择的任何方式都很满意。

我们将从以下方式声明我们的 CLI 界面开始：

```java
    public class DupeFinderCommands { 
      @Command 
      public void findDupes( 
        @Option("pattern") List<String> patterns, 
        @Option("path") List<String> paths, 
        @Option("verbose") @Default("false") boolean verbose, 
        @Option("show-timings")  
        @Default("false") boolean showTimings) { 

```

在我们讨论上述代码之前，我们需要声明我们的 Java 模块：

```java
    module dupefind.cli { 
      requires tomitribe.crest; 
      requires tomitribe.crest.api; 
    } 

```

我们定义了一个新模块，其名称与我们的库模块名称类似。我们还声明了我们需要两个 Crest 模块。

回到我们的源代码，我们有我们在功能需求中讨论过的四个参数。请注意，`patterns`和`paths`被定义为`List<String>`。当 Crest 解析命令行时，如果它找到其中一个的多个实例（例如，`--path=/path/one--path=/path/two`），它将收集所有这些值并将它们存储为`List`。另外，请注意，`verbose`和`showTimings`被定义为`boolean`，所以我们看到了 Crest 将代表我们执行的类型强制转换的一个很好的例子。我们还为这两个参数设置了默认值，所以当我们的方法执行时，我们肯定会得到明智、可预测的值。

该方法的业务逻辑非常简单。我们将处理 verbose 标志，打印所请求操作的摘要如下：

```java
    if (verbose) { 
      System.out.println("Scanning for duplicate files."); 
      System.out.println("Search paths:"); 
      paths.forEach(p -> System.out.println("\t" + p)); 
      System.out.println("Search patterns:"); 
      patterns.forEach(p -> System.out.println("\t" + p)); 
      System.out.println(); 
    } 

```

然后我们将执行实际工作。由于我们构建了库，所有重复搜索的逻辑都隐藏在我们的 API 后面：

```java
    final Instant startTime = Instant.now(); 
    FileFinder ff = new FileFinder(); 
    patterns.forEach(p -> ff.addPattern(p)); 
    paths.forEach(p -> ff.addPath(p)); 

    ff.find(); 

    System.out.println("The following duplicates have been found:"); 
    final AtomicInteger group = new AtomicInteger(1); 
    ff.getDuplicates().forEach((name, list) -> { 
      System.out.printf("Group #%d:%n", group.getAndIncrement()); 
      list.forEach(fileInfo -> System.out.println("\t"  
        + fileInfo.getPath())); 
    }); 
    final Instant endTime = Instant.now(); 

```

这段代码一开始不会编译，因为我们还没有告诉系统我们需要它。我们现在可以这样做：

```java
    module dupefind.cli { 
      requires dupefind.lib; 
      requires tomitribe.crest; 
      requires tomitribe.crest.api; 
    } 

```

我们现在可以导入`FileFinder`类。首先，为了证明模块实际上正在按预期工作，让我们尝试导入一个未被导出的东西：`FindFileTask`。让我们创建一个简单的类：

```java
    import com.steeplesoft.dupefind.lib.model.FileInfo; 
    import com.steeplesoft.dupefind.lib.util.FindFileTask; 
    public class VisibilityTest { 
      public static void main(String[] args) { 
        FileInfo fi; 
        FindFileTask fft; 
      } 
    } 

```

如果我们尝试编译这个，Maven/javac 会大声抱怨，错误消息如下：

```java
[ERROR] Failed to execute goal org.apache.maven.plugins:maven-compiler-plugin:3.6.1:compile (default-compile) on project cli: Compilation failure: Compilation failure:
[ERROR] /C:/Users/jason/src/steeplesoft/DupeFinder/cli/src/main/java/com/
steeplesoft/dupefind/cli/VisibilityTest.java:[9,54] 
com.steeplesoft.dupefind.lib.util.FindFileTask is not visible because 
package com.steeplesoft.dupefind.lib.util is not visible 
[ERROR] /C:/Users/jason/src/steeplesoft/DupeFinder/cli/src/main/java/com/
steeplesoft/dupefind/cli/VisibilityTest.java:[13,9] cannot find symbol 
[ERROR] symbol:   class FindFileTask 
[ERROR] location: class com.steeplesoft.dupefind.cli.VisibilityTest 

```

我们成功地隐藏了我们的实用程序类，同时暴露了我们的公共 API。这种做法可能需要一些时间才能变得普遍，但它应该能够在防止私有 API 结晶为伪公共方面发挥奇迹。

回到任务上，我们创建了`FileFinder`类的一个实例，使用`String.forEach`将我们的`paths`和`patterns`传递给查找器，然后通过调用`find()`开始工作。工作本身是多线程的，但我们暴露了一个同步 API，所以我们的调用会阻塞，直到工作完成。一旦返回，我们开始在屏幕上打印细节。由于`FindFiles.getDuplicates()`返回`Map<String, List<FileInfo>>`，我们在`Map`上调用`forEach()`来遍历每个键，然后在`List`上调用`forEach()`来打印有关每个文件的信息。我们还使用`AtomicInteger`作为索引，因为变量必须是 final 或有效 final，所以我们只使用了`AtomicInteger`的`final`实例。对于更有经验的开发人员来说，可能会想到`BigInteger`，但它是不可变的，所以在这里使用它是一个不好的选择。

运行命令的输出将类似于这样：

```java
The following duplicates have been found: 
Group #1: 
     C:\some\path\test\set1\file5.txt 
     C:\some\path\test\set2\file5.txt 
Group #2: 
     C:\some\path\test\set1\file11.txt 
     C:\some\path\test\set1\file11-1.txt 
     C:\some\path\test\set2\file11.txt 

```

接下来，我们处理`showTimings`。我在前面的代码中没有提到它，但现在我会提到，我们在处理之前和之后得到了一个`Instant`实例（来自 Java 8 的日期/时间库`java.time`）。只有当`showTimings`为 true 时，我们才会真正对它们做任何事情。处理它的代码看起来像这样：

```java
    if (showTimings) { 
      Duration duration = Duration.between(startTime, endTime); 
      long hours = duration.toHours(); 
      long minutes = duration.minusHours(hours).toMinutes(); 
      long seconds = duration.minusHours(hours) 
         .minusMinutes(minutes).toMillis() / 1000; 
      System.out.println(String.format( 
        "%nThe scan took %d hours, %d minutes, and %d seconds.%n",  
         hours, minutes, seconds)); 
    } 

```

有了我们的两个`Instant`，我们得到了一个`Duration`，然后开始计算小时、分钟和秒。希望这永远不会超过一个小时，但做好准备也无妨。这就是 CLI 的全部代码。Crest 为我们的命令行参数解析做了大部分工作，留下了一个简单而干净的逻辑实现。

我们还需要添加最后一件事，那就是 CLI 帮助。对于最终用户来说，能够找出如何使用我们的命令将非常有帮助。幸运的是，Crest 内置了支持来提供这些信息。要添加帮助信息，我们需要在与我们的命令类相同的包中创建一个名为`OptionDescriptions.properties`的文件（请记住，由于我们使用的是 Maven，这个文件应该在`src/main/resource`下），如下所示：

```java
 path = Adds a path to be searched. Can be specified multiple times. 
    pattern = Adds a pattern to match against the file names (e.g.,
    "*.png").
    Can be specified multiple times. 
    show-timings= Show how long the scan took 
    verbose = Show summary of duplicate scan configuration 

```

这样做将产生以下输出：

```java
 $ java -jar cli-1.0-SNAPSHOT.jar help findDupes 
    Usage: findDupes [options] 
    Options: 
      --path=<String[]>    Adds a path to be searched. Can be
                            specified multiple times. 
      --pattern=<String[]> Adds a pattern to match against
                            the file names
                           (e.g., "*.png"). Can be specified
                             multiple times. 
      --show-timings       Show how long the scan took 
      --verbose            Show summary of duplicate scan configuration 

```

您可以尽可能详细，而不会使您的源代码变得难以阅读。

有了这些，我们的 CLI 就功能齐全了。在继续之前，我们需要查看一下我们的 CLI 的一些构建问题，并看看 Crest 如何适应。显然，我们需要告诉 Maven 在哪里找到我们的 Crest 依赖项，如下面的代码片段所示：

```java
    <dependency> 
      <groupId>org.tomitribe</groupId> 
      <artifactId>tomitribe-crest</artifactId> 
      <version>${crest.version}</version> 
    </dependency> 

```

我们还需要告诉它在哪里找到我们的重复查找器库，如下所示：

```java
    <dependency> 
      <groupId>${project.groupId}</groupId> 
      <artifactId>lib</artifactId> 
      <version>${project.version}</version> 
    </dependency> 

```

注意`groupId`和`version`：由于我们的 CLI 和库模块是同一个父多模块构建的一部分，我们将`groupId`和`version`设置为父模块的`groupId`和`version`，允许我们从单个位置管理它，这样更改组或升级版本就简单得多。

POM 的`build`部分是更有趣的部分。首先，让我们从`maven-compiler-plugin`开始。虽然我们的目标是 Java 9，但`crest-maven-plugin`（我们稍后将看到）似乎目前不喜欢为 Java 9 生成的类，因此我们指示编译器插件发出 Java 1.8 字节码：

```java
    <plugin> 
      <groupId>org.apache.maven.plugins</groupId> 
      <artifactId>maven-compiler-plugin</artifactId> 
      <configuration> 
         <source>1.8</source> 
         <target>1.8</target> 
      </configuration> 
    </plugin> 

```

接下来，我们需要设置`crest-maven-plugin`。为了将我们的命令类暴露给 Crest，我们有两个选项：我们可以使用运行时扫描类，或者我们可以让 Crest 在构建时扫描命令。为了使此实用程序尽可能小，以及尽可能减少启动时间，我们将选择后一种方法，因此我们需要向构建中添加另一个插件，如下所示：

```java
    <plugin> 
      <groupId>org.tomitribe</groupId> 
      <artifactId>crest-maven-plugin</artifactId> 
      <version>${crest.version}</version> 
      <executions> 
         <execution> 
            <goals> 
              <goal>descriptor</goal> 
            </goals> 
         </execution> 
      </executions> 
    </plugin> 

```

当此插件运行时，它将生成一个名为`crest-commands.txt`的文件，Crest 将处理该文件以在启动时查找类。这里可能不会节省太多时间，但对于更大的项目来说，这绝对是需要牢记的事情。

最后，我们不希望用户每次都要担心设置类路径（或模块路径！），因此我们将引入 Maven Shade 插件，它将创建一个包含所有依赖项的单个大型 jar 文件：

```java
    <plugin> 
      <artifactId>maven-shade-plugin</artifactId> 
      <version>2.1</version> 
      <executions> 
         <execution> 
             <phase>package</phase> 
             <goals> 
                <goal>shade</goal> 
              </goals> 
              <configuration> 
                 <transformers> 
                   <transformer implementation= 
                     "org.apache.maven.plugins.shade.resource
                      .ManifestResourceTransformer"> 
                     <mainClass> 
                       org.tomitribe.crest.Main 
                     </mainClass> 
                   </transformer> 
                 </transformers> 
              </configuration> 
         </execution> 
      </executions> 
    </plugin> 

```

构建后，我们可以使用以下命令运行搜索：

```java
 java -jar target\cli-1.0-SNAPSHOT.jar findDupes \
      --path=../test/set1 --path=../test/set2 -pattern=*.txt 

```

显然，它仍然可以改进，所以我们希望在脚本包装器（shell、批处理等）中发布它，但 jar 的数量从 18 个左右减少到 1 个，这是一个很大的改进。

完成我们的 CLI 后，让我们制作一个简单的 GUI 来使用我们的库。

# 构建图形用户界面

对于我们的 GUI，我们希望暴露与命令行相同类型的功能，但显然，使用一个漂亮的图形界面。为此，我们将再次使用 JavaFX。我们将为用户提供一种选择对话框，用于选择要搜索的目录，并添加搜索模式的字段。一旦重复项被识别出来，我们将在列表中显示它们供用户查看。所有重复组将被列出，并且当点击时，该组中的文件将在另一个列表中显示。用户可以右键单击列表，选择查看文件或删除文件。完成后，应用程序将如下所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java9-prog-bp/img/b580b9aa-0fad-43ba-a9c4-0ec8cdaa3e90.png)

让我们从创建我们的项目开始。在 NetBeans 中，转到文件 | 新建项目，选择 Maven | JavaFX 应用程序。您可以随意命名，但我们使用了名称`Duplicate Finder - GUI`，`groupId`为`com.steeplesoft.dupefind`，`artifactId`为`gui`。

创建项目后，您应该有两个类，`Main`和`FXMLController`，以及`fxml/Scene.fxml`资源。这可能听起来有些重复，但在继续之前，我们需要按照以下方式设置我们的 Java 模块：

```java
    module dupefind.gui { 
      requires dupefind.lib; 
      requires java.logging; 
      requires javafx.controls; 
      requires javafx.fxml; 
      requires java.desktop; 
    } 

```

然后，为了创建我们看到的界面，我们将使用`BorderPane`，并将`MenuBar`添加到`top`部分，如下所示：

```java
    <top> 
      <MenuBar BorderPane.alignment="CENTER"> 
        <menus> 
          <Menu mnemonicParsing="false"  
            onAction="#closeApplication" text="File"> 
            <items> 
              <MenuItem mnemonicParsing="false" text="Close" /> 
            </items> 
          </Menu> 
          <Menu mnemonicParsing="false" text="Help"> 
            <items> 
              <MenuItem mnemonicParsing="false"  
                onAction="#showAbout" text="About" /> 
            </items> 
          </Menu> 
        </menus> 
      </MenuBar> 
    </top> 

```

当您使用 Scene Builder 添加`MenuBar`时，它会自动为您添加几个示例`Menu`条目。我们已经删除了不需要的条目，并将剩下的条目与控制器类中的 Java 方法绑定起来。具体来说，`Close`菜单将调用`closeApplication()`，`About`将调用`showAbout()`。这看起来就像之前在书中看到的菜单标记，所以没有太多可谈论的。

布局的其余部分稍微复杂一些。在`left`部分，我们有一些垂直堆叠的控件。JavaFX 有一个内置的容器，使这个操作变得很容易：`VBox`。我们将马上看到它的内容，但它的使用看起来像这样：

```java
    <VBox BorderPane.alignment="TOP_CENTER"> 
      <children> 
         <HBox... /> 
         <Separator ... /> 
         <Label .../> 
         <ListView ... /> 
         <HBox ... /> 
         <Label ... /> 
         <ListView... /> 
         <HBox ... /> 
      </children> 
      <padding> 
         <Insets bottom="10.0" left="10.0" right="10.0" 
           top="10.0" /> 
      </padding> 
    </VBox> 

```

这不是有效的 FXML，所以不要尝试复制粘贴。为了清晰起见，我省略了子元素的细节。正如您所看到的，`VBox`有许多子元素，每个子元素都将垂直堆叠，但正如我们从前面的屏幕截图中看到的那样，有一些我们希望水平排列。为了实现这一点，我们在需要的地方嵌套一个`HBox`实例。它的标记看起来就像`VBox`。

在这部分 FXML 中没有太多有趣的内容，但有一些需要注意的地方。我们希望用户界面的某些部分在窗口调整大小时收缩和增长，即`ListView`。默认情况下，每个组件的各种高度和宽度属性（最小、最大和首选）将使用计算出的大小，这意味着它们将尽可能大地渲染自己，而在大多数情况下，这是可以的。在我们的情况下，我们希望两个`ListView`实例尽可能多地增长在它们各自的容器内，这种情况下是我们之前讨论的`VBox`。为了实现这一点，我们需要修改我们的两个`ListView`实例，就像这样：

```java
    <ListView fx:id="searchPatternsListView" VBox.vgrow="ALWAYS" /> 
    ... 
    <ListView fx:id="sourceDirsListView" VBox.vgrow="ALWAYS" /> 

```

当两个`ListView`实例都设置为`ALWAYS`增长时，它们将争夺可用空间，并最终共享它。当然，可用空间取决于`VBox`实例的高度，以及容器中其他组件的计算高度。有了这个属性设置，我们可以增加或减小窗口的大小，观察两个`ListView`实例的增长和收缩，而其他一切保持不变。

对于用户界面的其余部分，我们将应用相同的策略来安排组件，但是这一次，我们将从一个`HBox`实例开始，并根据需要进行划分。我们有两个`ListView`实例，我们也希望用所有可用的空间来填充它们，所以我们以与前两个相同的方式标记它们。每个`ListView`实例还有一个`Label`，所以我们将每个`Label`/`ListView`对包装在一个`VBox`实例中，以获得垂直分布。在伪 FXML 中，这看起来像这样：

```java
    <HBox> 
      <children> 
         <Separator orientation="VERTICAL"/> 
         <VBox HBox.hgrow="ALWAYS"> 
           <children> 
             <VBox VBox.vgrow="ALWAYS"> 
                <children> 
                  <Label ... /> 
                  <ListView ... VBox.vgrow="ALWAYS" /> 
                </children> 
             </VBox> 
           </children> 
         </VBox> 
         <VBox HBox.hgrow="ALWAYS"> 
           <children> 
             <Label ... /> 
             <ListView ... VBox.vgrow="ALWAYS" /> 
           </children> 
         </VBox> 
      </children> 
    </HBox> 

```

在用户界面的这一部分中有一个值得注意的项目，那就是我们之前讨论过的上下文菜单。要向控件添加上下文，您需要在目标控件的 FXML 中嵌套一个`contextMenu`元素，就像这样：

```java
    <ListView fx:id="matchingFilesListView" VBox.vgrow="ALWAYS"> 
      <contextMenu> 
        <ContextMenu> 
          <items> 
            <MenuItem onAction="#openFiles" text="Open File(s)..." /> 
            <MenuItem onAction="#deleteSelectedFiles"  
              text="Delete File(s)..." /> 
           </items> 
         </ContextMenu> 
      </contextMenu> 
    </ListView> 

```

我们已经定义了一个包含两个`MenuItem`的内容菜单：`“打开文件…”`和`“删除文件…”`。我们还使用`onAction`属性指定了这两个`MenuItem`的操作。我们将在接下来看这些方法。

这标志着我们用户界面定义的结束，现在我们将注意力转向 Java 代码，我们将完成用户界面的准备工作，并实现我们应用程序的逻辑。

虽然我们没有展示实现这一点的 FXML，但我们的 FXML 文件与我们的控制器类`FXMLController`相关联。当然，这个类可以被任何名称调用，但我们选择使用 IDE 生成的名称。在一个更大的应用程序中，需要更多地关注这个类的命名。为了允许我们将用户界面组件注入到我们的代码中，我们需要在我们的类上声明实例变量，并用`@FXML`注解标记它们。一些示例包括以下内容：

```java
    @FXML 
    private ListView<String> dupeFileGroupListView; 
    @FXML 
    private ListView<FileInfo> matchingFilesListView; 
    @FXML 
    private Button addPattern; 
    @FXML 
    private Button removePattern; 

```

还有其他几个，但这应该足以演示这个概念。请注意，我们没有声明一个普通的`ListView`，而是将我们的实例参数化为`ListView<String>`和`ListView<FileInfo>`。我们知道这是我们放入控件的内容，因此在编译时指定类型参数可以让我们在编译时获得一定程度的类型安全性，但也可以避免在每次与它们交互时都必须转换内容。

接下来，我们需要设置将保存用户输入的搜索路径和模式的集合。我们将使用`ObservableList`实例。请记住，使用`ObservableList`实例时，容器可以在需要时自动重新呈现自身，当`Observable`实例被更新时：

```java
    final private ObservableList<String> paths =  
      FXCollections.observableArrayList(); 
    final private ObservableList<String> patterns =  
      FXCollections.observableArrayList(); 

```

在`initialize()`方法中，我们可以开始将事物联系在一起。考虑以下代码片段作为示例：

```java
    public void initialize(URL url, ResourceBundle rb) { 
      searchPatternsListView.setItems(patterns); 
      sourceDirsListView.setItems(paths); 

```

在这里，我们将我们的`ListView`实例与我们的`ObservableList`实例关联起来。现在，每当这些列表被更新时，用户界面将立即反映出变化。

接下来，我们需要配置重复文件组`ListView`。从我们的库返回的数据是一个由重复哈希键控的`List<FileInfo>`对象的`Map`。显然，我们不想向用户显示哈希列表，因此，就像 CLI 一样，我们希望用更友好的标签表示每个文件组。为此，我们需要创建一个`CellFactory`，它将创建一个负责呈现单元格的`ListCell`。我们将这样做：

```java
    dupeFileGroupListView.setCellFactory( 
      (ListView<String> p) -> new ListCell<String>() { 
        @Override 
        public void updateItem(String string, boolean empty) { 
          super.updateItem(string, empty); 
          final int index = p.getItems().indexOf(string); 
          if (index > -1) { 
            setText("Group #" + (index + 1)); 
          } else { 
            setText(null); 
          } 
       } 
    }); 

```

虽然 lambda 可能很棒，因为它们倾向于使代码更简洁，但它们也可能隐藏一些细节。在非 lambda 代码中，上面的 lambda 可能看起来像这样：

```java
    dupeFileGroupListView.setCellFactory(new  
      Callback<ListView<String>, ListCell<String>>() { 
        @Override 
        public ListCell<String> call(ListView<String> p) { 
          return new ListCell<String>() { 
            @Override 
            protected void updateItem(String t, boolean bln) { 
             super.updateItem(string, empty); 
              final int index = p.getItems().indexOf(string); 
              if (index > -1) { 
                setText("Group #" + (index + 1)); 
              } else { 
                setText(null); 
              } 
            } 
          }; 
        } 
    }); 

```

你肯定会得到更多的细节，但阅读起来也更困难。在这里包括两者的主要目的是：展示为什么 lambda 通常更好，并展示涉及的实际类型，这有助于 lambda 变得更有意义。有了对 lambda 的理解，我们接下来的方法是做什么？

首先，我们调用`super.updateItem()`，因为这只是一个良好的实践。接下来，我们找到正在呈现的字符串的索引。API 给了我们字符串（因为它是一个`ListView<String>`），所以我们在我们的`ObservableList<String>`中找到它的索引。如果找到了，我们将单元格的文本设置为`Group #`加上索引加一（因为 Java 中的索引通常是从零开始的）。如果找不到字符串（`ListView`正在呈现空单元格），我们将文本设置为 null，以确保该字段为空白。

接下来，我们需要在`matchingFilesListView`上执行类似的过程：

```java
    matchingFilesListView.getSelectionModel() 
      .setSelectionMode(SelectionMode.MULTIPLE); 
    matchingFilesListView.setCellFactory( 
      (ListView<FileInfo> p) -> new ListCell<FileInfo>() { 
        @Override 
        protected void updateItem(FileInfo fileInfo, boolean bln) { 
          super.updateItem(fileInfo, bln); 
          if (fileInfo != null) { 
             setText(fileInfo.getPath()); 
          } else { 
             setText(null); 
          } 
        } 
    }); 

```

这几乎是相同的，但有几个例外。首先，我们将`ListView`的选择模式设置为`MULTIPLE`。这将允许用户在感兴趣的项目上进行控制点击，或者在一系列行上进行 shift-click。接下来，我们以相同的方式设置`CellFactory`。请注意，由于`ListView`实例的参数化类型是`FileInfo`，因此`ListCell.updateItem()`方法签名中的类型是不同的。

我们还有最后一个用户界面设置步骤。如果您回顾一下屏幕截图，您会注意到“查找重复”按钮与`ListView`的宽度相同，而其他按钮的宽度仅足以呈现其内容。我们通过将`Button`元素的宽度绑定到其容器的宽度（即`HBox`实例）来实现这一点：

```java
    findFiles.prefWidthProperty().bind(findBox.widthProperty()); 

```

我们正在获取首选宽度属性，这是一个`DoubleProperty`，并将其绑定到`findBox`的宽度属性（也是一个`DoubleProperty`），这是控件的容器。`DoubleProperty`是一个`Observable`实例，就像`ObservableListView`一样，所以我们告诉`findFiles`控件观察其容器的宽度属性，并在其他属性更改时相应地设置自己的值。这样我们可以设置属性，然后忘记它。除非我们想要打破这两个属性之间的绑定，否则我们再也不必考虑它，当然也不需要手动观察一个属性来更新作者。框架会为我们做这些。

那么，这些按钮怎么样？我们如何让它们做一些事情？我们通过将`Button`元素的`onAction`属性设置为控制器中的一个方法来实现：`#someMethod`转换为`Controller.someMethod(ActionEvent event)`。我们至少有两种方法来处理这个问题：我们可以为每个按钮创建一个单独的处理程序方法，或者，就像我们在这里做的那样，我们可以创建一个方法，然后根据需要委托给另一个方法；两种方法都可以：

```java
    @FXML 
    private void handleButtonAction(ActionEvent event) { 
      if (event.getSource() instanceof Button) { 
        Button button = (Button) event.getSource(); 
        if (button.equals(addPattern)) { 
          addPattern(); 
        } else if (button.equals(removePattern)) { 
        // ... 

```

我们必须确保我们实际上获取了一个`Button`元素，然后将其转换并将其与被注入的实例进行比较。每个按钮的实际处理程序如下：

```java
    private void addPattern() { 
      TextInputDialog dialog = new TextInputDialog("*.*"); 
      dialog.setTitle("Add a pattern"); 
      dialog.setHeaderText(null); 
      dialog.setContentText("Enter the pattern you wish to add:"); 

      dialog.showAndWait() 
      .filter(n -> n != null && !n.trim().isEmpty()) 
      .ifPresent(name -> patterns.add(name)); 
    } 

```

要添加模式，我们创建一个带有适当文本的`TextInputDialog`实例，然后调用`showAndWait()`。JavaFX 8 中这种方法的美妙之处在于它返回`Optional<String>`。如果用户在对话框中输入文本，并且用户点击确定，`Optional`将包含内容。我们通过调用`ifPresent()`来识别，传递一个 lambda，将新模式添加到`ObservableList<String>`中，这将自动更新用户界面。如果用户没有点击确定，`Optional`将为空。如果用户没有输入任何文本（或输入了一堆空格），则调用`filter()`将阻止 lambda 运行。

删除项目类似，尽管我们需要隐藏一些细节在一个实用方法中，因为我们对功能有两个需求。我们确保已选择某些内容，然后显示确认对话框，如果用户点击确定，则从`ObservableList<String>`中删除模式：

```java
    private void removePattern() { 
      if (searchPatternsListView.getSelectionModel() 
      .getSelectedIndex() > -1) { 
        showConfirmationDialog( 
          "Are you sure you want to remove this pattern?", 
          (() -> patterns.remove(searchPatternsListView 
          .getSelectionModel().getSelectedItem()))); 
      } 
    } 

```

让我们来看看`showConfirmationDialog`方法：

```java
    protected void showConfirmationDialog(String message, 
     Runnable action) { 
      Alert alert = new Alert(Alert.AlertType.CONFIRMATION); 
      alert.setTitle("Confirmation"); 
      alert.setHeaderText(null); 
      alert.setContentText(message); 
      alert.showAndWait() 
      .filter(b -> b == ButtonType.OK) 
      .ifPresent(b -> action.run()); 
    } 

```

这与之前的对话框非常相似，应该是不言自明的。这里有趣的部分是使用 lambda 作为方法参数，这使得它成为一个高阶函数--意味着它接受一个函数作为参数，返回一个函数作为结果，或者两者都有。我们传递`Runnable`，因为我们想要一个不带参数并且不返回任何内容的 lambda，而`Runnable`是一个`FunctionalInterface`，符合这个描述。在显示对话框并获取用户的响应后，我们将仅过滤出按钮点击为`OK`的响应，并且如果存在，我们通过`action.run()`执行`Runnable`。我们必须指定`b -> action.run()`作为`ifPresent()`接受一个`Consumer<? super ButtonType>`，所以我们创建一个并忽略传入的值，从而使我们的调用代码免受该细节的影响。

添加路径需要一个`DirectoryChooser`实例：

```java
    private void addPath() { 
        DirectoryChooser dc = new DirectoryChooser(); 
        dc.setTitle("Add Search Path"); 
        dc.setInitialDirectory(new File(lastDir)); 
        File dir = dc.showDialog(null); 
        if (dir != null) { 
            try { 
                lastDir = dir.getParent(); 
                paths.add(dir.getCanonicalPath()); 
            } catch (IOException ex) { 
                Logger.getLogger(FXMLController.class.getName()).log(
                  Level.SEVERE, null, ex); 
            } 
        } 
    } 

```

创建`DirectoryChooser`实例时，我们将初始目录设置为上次使用的目录，以方便用户。当应用程序启动时，这默认为用户的主目录，但一旦成功选择了目录，我们将`lastDir`设置为添加的目录的父目录，允许用户从上次离开的地方开始，如果需要输入多个路径。`DirectoryChooser.showDialog()`返回一个文件，所以我们获取其规范路径并将其存储在路径中，这将再次自动更新我们的用户界面。

删除路径看起来与删除模式非常相似，如下面的代码片段所示：

```java
    private void removePath() { 
      showConfirmationDialog( 
        "Are you sure you want to remove this path?", 
        (() -> paths.remove(sourceDirsListView.getSelectionModel() 
        .getSelectedItem()))); 
    } 

```

同样的基本代码，只是不同的 lambda。lambda 不是很酷吗？

`findFiles()`按钮的处理程序有点不同，但看起来很像我们的 CLI 代码，如下所示：

```java
    private void findFiles() { 
       FileFinder ff = new FileFinder(); 
       patterns.forEach(p -> ff.addPattern(p)); 
       paths.forEach(p -> ff.addPath(p)); 

       ff.find(); 
       dupes = ff.getDuplicates(); 
       ObservableList<String> groups =  
         FXCollections.observableArrayList(dupes.keySet()); 

       dupeFileGroupListView.setItems(groups); 
    } 

```

我们创建了`FileFinder`实例，使用流和 lambda 设置路径和模式，然后开始搜索过程。当搜索完成时，我们通过`getDuplicates()`获取重复文件信息列表，然后使用映射的键创建一个新的`ObservableList<String>`实例，然后将其设置在`dupeFileGroupListView`上。

现在我们需要添加处理组列表上鼠标点击的逻辑，所以我们将在 FXML 文件中将`ListView`的`onMouseClicked`属性设置为`#dupeGroupClicked`，如下面的代码块所示：

```java
    @FXML 
    public void dupeGroupClicked(MouseEvent event) { 
      int index = dupeFileGroupListView.getSelectionModel() 
       .getSelectedIndex(); 
      if (index > -1) { 
        String hash = dupeFileGroupListView.getSelectionModel() 
        .getSelectedItem(); 
        matchingFilesListView.getItems().clear(); 
        matchingFilesListView.getItems().addAll(dupes.get(hash)); 
      } 
    } 

```

当单击控件时，我们获取索引并确保它是非负的，以确保用户实际上点击了某些内容。然后我们通过从`ListView`中获取所选项目来获取组的哈希值。请记住，虽然`ListView`可能显示类似于`Group #2`的内容，但该行的实际内容是哈希值。我们只是使用自定义的`CellFactory`来给它一个更漂亮的标签。有了哈希值，我们清除`matchingFilesListView`中的项目列表，然后获取控件的`ObservableList`并添加由哈希键控的`List`中的所有`FileInfo`对象。再次，由于`Observable`的强大功能，我们获得了自动用户界面更新。

我们还希望用户能够使用键盘浏览重复组列表以更新匹配文件列表。我们通过将`ListView`的`onKeyPressed`属性设置为指向这个相当简单的方法来实现：

```java
    @FXML 
    public void keyPressed(KeyEvent event) { 
      dupeGroupClicked(null); 
    } 

```

恰好我们对这两种方法中的实际“事件”并不是特别感兴趣（它们实际上从未被使用），所以我们可以天真地委托给之前讨论过的鼠标点击方法。

我们还需要实现两个较小的功能：查看匹配文件和删除匹配文件。

我们已经创建了上下文菜单和菜单条目，所以我们需要做的就是实现以下处理程序方法：

```java
    @FXML 
    public void openFiles(ActionEvent event) { 
      matchingFilesListView.getSelectionModel().getSelectedItems() 
      .forEach(f -> { 
        try { 
          Desktop.getDesktop().open(new File(f.getPath())); 
        } catch (IOException ex) { 
          // ... 
        } 
      }); 
    } 

```

匹配文件列表允许多个选择，所以我们需要从选择模型中获取`List<FileInfo>`，而不是我们已经看到的单个对象。然后我们调用`forEach()`来处理条目。我们希望在操作系统中使用用户配置的任何应用程序中打开文件。为此，我们使用了 Java 6 中引入的 AWT 类：`Desktop`。我们通过`getDesktop()`获取实例，然后调用`open()`，传递指向我们的`FileInfo`目标的`File`。

删除文件类似：

```java
    @FXML 
    public void deleteSelectedFiles(ActionEvent event) { 
      final ObservableList<FileInfo> selectedFiles =  
        matchingFilesListView.getSelectionModel() 
        .getSelectedItems(); 
      if (selectedFiles.size() > 0) { 
        showConfirmationDialog( 
          "Are you sure you want to delete the selected files", 
           () -> selectedFiles.forEach(f -> { 
            if (Desktop.getDesktop() 
            .moveToTrash(new File(f.getPath()))) {                         
              matchingFilesListView.getItems() 
              .remove(f); 
              dupes.get(dupeFileGroupListView 
               .getSelectionModel() 
               .getSelectedItem()).remove(f); 
            } 
        })); 
      } 
    } 

```

类似于打开文件，我们获取所有选定的文件。如果至少有一个文件，我们通过`showConfirmationDialog()`确认用户的意图，并传入一个处理删除的 lambda。我们使用`Desktop`类再次执行实际的文件删除，将文件移动到文件系统提供的垃圾桶中，以提供用户安全的删除选项。如果文件成功删除，我们从`ObservableList`中删除其条目，以及我们的缓存重复文件`Map`，这样如果用户再次点击此文件组，它就不会显示出来。

# 总结

至此，我们的应用程序就完成了。那么，我们覆盖了什么内容呢？从项目描述来看，这似乎是一个非常简单的应用程序，但当我们开始分解需求并深入实施时，我们最终涵盖了很多领域——这种情况并不罕见。我们构建了另一个多模块 Maven 项目。我们介绍了 Java 并发，包括基本的`Thread`管理和`ExecutorService`的使用，以及 Java 持久化 API，展示了基本的`@Entity`定义，`EntityManagerFactory/EntityManager`的使用和 JPAQL 查询的编写。我们讨论了使用`MessageDigest`类创建文件哈希，并演示了新的文件 I/O API，包括目录树遍历 API。我们还使用 JavaFX 构建了一个更复杂的用户界面，使用了嵌套容器，“链接”了`ListView`实例，并绑定了属性。

这对于一个“简单”的项目来说已经相当多了。我们的下一个项目也将相对简单，因为我们将构建一个命令行日期计算器，它将允许我们探索`java.time`包，并了解这个新的日期/时间 API 提供了一些什么。
