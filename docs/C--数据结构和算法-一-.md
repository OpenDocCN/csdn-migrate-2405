# C# 数据结构和算法（一）

> 原文：[`zh.annas-archive.org/md5/66e5287ccd1157bc24ed3bd6a5b7c4bf`](https://zh.annas-archive.org/md5/66e5287ccd1157bc24ed3bd6a5b7c4bf)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

作为开发人员，您肯定听说过各种数据结构和算法。然而，您是否曾深入思考过它们及其对应用程序性能的影响？如果没有，现在是时候深入研究这个话题了，而本书是一个很好的开始！

本书涵盖了许多数据结构，从简单的开始，即数组和它们的一些变体，作为随机访问数据结构的代表。然后，介绍了列表，以及它们的排序变体。本书还解释了基于栈和队列的有限访问数据结构，包括优先队列。在此之后，我们向您介绍了字典数据结构，它允许您将键映射到值并进行快速查找。字典的排序变体也得到支持。如果您想要从高性能的集合相关操作中受益，可以使用另一种数据结构，即哈希集合。树是最强大的构造之一，它存在几种变体，如二叉树、二叉搜索树，以及自平衡树和堆。我们分析的最后一个数据结构是图，它受到许多有趣的算法主题的支持，如图遍历、最小生成树、节点着色以及在图中找到最短路径。前方有很多内容等待着您！

您是否有兴趣了解选择合适的数据结构对应用程序性能的影响？您想知道如何通过选择正确的数据结构和相应的算法来提高解决方案的质量和性能吗？您对这些数据结构可以应用于现实场景感到好奇吗？如果对这些问题中的任何一个回答是肯定的，让我们开始阅读本书，了解在开发 C#应用程序时可以使用的各种数据结构和算法。

数组、列表、栈、队列、字典、哈希集合、树、堆和图，以及相应的算法——在接下来的页面中等待着您的是广泛的主题范围！让我们开始冒险，迈出掌握数据结构和算法的第一步，这将有望对您的项目和作为软件开发人员的职业产生积极影响！

# 本书适合的读者

本书旨在面向希望了解在各种应用程序中可以使用的 C#中的数据结构和算法的开发人员，包括 Web 和移动解决方案。这里介绍的主题适合具有不同经验水平的程序员，即使是初学者也会发现有趣的内容。然而，至少具有关于面向对象编程等 C#编程语言的基本知识将是一个额外的优势。

为了更容易理解内容，本书配有许多插图和示例。此外，附带项目的源代码附加在各章节中。因此，您可以轻松运行示例应用程序并进行调试，而无需自己编写代码。

值得一提的是，代码可以简化，并且可能与最佳实践有所不同。此外，示例可能具有显著有限甚至没有安全检查和功能。在使用本书中提供的内容发布应用程序之前，应对应用程序进行彻底测试，以确保它在各种情况下（如传递不正确的数据的情况）能够正确运行。

# 本书涵盖的内容

第一章，*入门*，解释了使用正确的数据结构和算法的非常重要的作用，以及它对开发解决方案的性能的影响。该章简要介绍了 C#编程语言和各种数据类型，包括值类型和引用类型。然后，它介绍了 IDE 的安装和配置过程，以及创建新项目，开发示例应用程序，以及使用断点和逐步技术进行调试的过程。

第二章，*数组和列表*，涵盖了使用两种随机访问数据结构存储数据的场景，即数组和列表。首先，解释了三种数组的变体，即单维、多维和交错。您还将了解四种排序算法，即选择、插入、冒泡排序和快速排序。该章还涉及了几种列表的变体，如简单、排序、双向链接和循环链接。

第三章，*栈和队列*，解释了如何使用两种有限访问数据结构的变体，即栈和队列，包括优先队列。该章展示了如何在栈上执行`push`和`pop`操作，并在队列的情况下描述了`enqueue`和`dequeue`操作。为了帮助您理解这些主题，还提供了一些示例，包括汉诺塔游戏和模拟具有多个顾问和呼叫者的呼叫中心的应用程序。

第四章，*字典和集合*，侧重于与字典和集合相关的数据结构，这使得将键映射到值，执行快速查找，并在集合上执行各种操作成为可能。该章介绍了哈希表的非泛型和泛型变体，排序字典，以及高性能的集合操作解决方案，以及“排序”集合的概念。

第五章，*树的变体*，描述了一些与树相关的主题。它介绍了基本树，以及在 C#中的实现，并展示了这一概念的示例。该章还向您介绍了二叉树、二叉搜索树和自平衡树，即 AVL 和红黑树。该章的其余部分致力于堆作为基于树的结构，即二叉、二项式和斐波那契堆。

第六章，*探索图形*，包含了大量关于图形的信息，从基本概念的解释开始，包括节点和几种边的变体。还涵盖了在 C#中实现图形。该章介绍了图形遍历的两种模式，即深度优先和广度优先搜索。然后，它介绍了使用 Kruskal 和 Prim 算法的最小生成树的主题，节点着色问题，以及使用 Dijkstra 算法在图中找到最短路径的解决方案。

第七章，*总结*，是对前几章所学知识的总结。它简要分类了数据结构，将它们分为线性和非线性两组。最后，该章讨论了各种数据结构的多样化应用。

# 为了充分利用本书

本书旨在面向具有不同经验的程序员。然而，初学者也会发现一些有趣的内容。然而，至少具有关于 C#的基本知识，比如面向对象编程，将是一个额外的优势。

# 下载示例代码文件

您可以从[www.packtpub.com](http://www.packtpub.com)的帐户中下载本书的示例代码文件。如果您在其他地方购买了本书，可以访问[www.packtpub.com/support](http://www.packtpub.com/support)并注册，以便直接通过电子邮件接收文件。

您可以按照以下步骤下载代码文件：

1.  登录或注册[www.packtpub.com](http://www.packtpub.com/support)。

1.  选择“支持”选项卡。

1.  单击“代码下载和勘误”。

1.  在搜索框中输入书名，然后按照屏幕上的说明操作。

下载文件后，请确保使用最新版本的解压缩或提取文件夹：

+   WinRAR/7-Zip 适用于 Windows

+   Zipeg/iZip/UnRarX 适用于 Mac

+   7-Zip/PeaZip 适用于 Linux

该书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/C-Sharp-Data-Structures-and-Algorithms`](https://github.com/PacktPublishing/C-Sharp-Data-Structures-and-Algorithms)。如果代码有更新，将在现有的 GitHub 存储库上进行更新。

我们还有其他代码包，来自我们丰富的图书和视频目录，可在[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)上获得。去看看吧！

# 下载彩色图像

我们还提供了一个 PDF 文件，其中包含本书中使用的屏幕截图/图表的彩色图像。您可以在这里下载：[`www.packtpub.com/sites/default/files/downloads/CSharpDataStructuresandAlgorithms_ColorImages.pdf`](https://www.packtpub.com/sites/default/files/downloads/CSharpDataStructuresandAlgorithms_ColorImages.pdf)。

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码字、文件夹名称、文件名、文件扩展名、路径名、虚拟 URL 和用户输入。例如："该类包含三个属性（即`Id`、`Name`和`Role`），以及两个构造函数。"

代码块设置如下：

```cs
int[,] numbers = new int[,] = 
{ 
    { 9, 5, -9 }, 
    { -11, 4, 0 }, 
    { 6, 115, 3 }, 
    { -12, -9, 71 }, 
    { 1, -6, -1 } 
};
```

任何命令行输入或输出都以以下方式编写：

```cs
 Enter the number: 10.5
    The average value: 10.5 (...)
    Enter the number: 1.5
    The average value: 4.875
```

**粗体**：表示新术语、重要单词或屏幕上看到的单词。例如，菜单或对话框中的单词会以这种方式出现在文本中。例如："当显示消息“安装成功！”时，请单击“启动”按钮启动 IDE。"

警告或重要说明会显示为这样。

技巧和窍门会显示为这样。


# 第一章：入门

开发应用程序肯定是一件令人兴奋的工作，但也具有挑战性，特别是如果您需要解决涉及高级数据结构和算法的复杂问题。在这种情况下，您经常需要关注性能，以确保解决方案在资源有限的设备上能够平稳运行。这样的任务可能非常困难，可能需要对编程语言、数据结构和算法有相当的了解。

您知道吗，即使将一个数据结构替换为另一个，也可能导致性能结果增加数百倍？听起来不可能吗？也许，但这是真的！举个例子，我想告诉您一个我参与的项目的简短故事。其目标是优化在图形图表上查找块之间连接的算法。这样的连接应该在图表中的任何块移动时自动重新计算、刷新和重绘。当然，连接不能穿过块，也不能重叠其他线，并且交叉点和方向变化的数量应该是有限的。根据图表的大小和复杂性，性能结果会有所不同。然而，在进行测试时，我们得到了同一个测试用例的结果范围从 1 毫秒到近 800 毫秒。最令人惊讶的可能是，这样巨大的改进主要是通过...改变了两组数据结构来实现的。

现在，您可能会问自己一个显而易见的问题：在特定情况下应该使用哪些数据结构，以及可以用哪些算法来解决一些常见问题？不幸的是，答案并不简单。然而，在本书中，您将找到许多关于数据结构和算法的信息，以 C#编程语言的背景呈现，包括许多示例、代码片段和详细解释。这样的内容可以帮助您回答前面提到的问题，同时开发下一个伟大的解决方案，这些解决方案可以被世界各地的许多人使用！您准备好开始您的数据结构和算法之旅了吗？如果是的，让我们开始吧！

在本章中，您将涵盖以下主题：

+   编程语言

+   数据类型

+   IDE 的安装和配置

+   创建项目

+   输入和输出

+   启动和调试

# 编程语言

作为开发人员，您肯定听说过许多编程语言，如 C#、Java、C++、C、PHP 或 Ruby。在所有这些语言中，您可以使用各种数据结构，以及实现算法，来解决基本和复杂的问题。然而，每种语言都有其自身的特点，这在实现数据结构和相应的算法时可能是可见的。正如前面提到的，本书将专注于 C#编程语言，这也是本节的主要内容。

C#语言，发音为“C Sharp”，是一种现代的、通用的、强类型的、面向对象的编程语言，可用于开发各种应用程序，如 Web、移动、桌面、分布式和嵌入式解决方案，甚至游戏。它与各种其他技术和平台合作，包括 ASP.NET MVC、Windows Store、Xamarin、Windows Forms、XAML 和 Unity。因此，当您学习 C#语言，以及在这种编程语言的背景下更多地了解数据结构和算法时，您可以利用这些技能来创建多种特定类型的软件。

当前版本的语言是 C# 7.1。值得一提的是它与语言的以下版本（例如 2.0、3.0 和 5.0）的有趣历史，在这些版本中，已添加了新功能以增加语言的可能性并简化开发人员的工作。当您查看特定版本的发布说明时，您将看到语言如何随着时间的推移而得到改进和扩展。

C#编程语言的语法类似于其他语言，比如 Java 或 C++。因此，如果您了解这些语言，您应该很容易理解用 C#编写的代码。例如，与之前提到的语言类似，代码由以分号（`;`）结尾的语句组成，花括号（`{`和`}`）用于分组语句，比如在`foreach`循环中。您还可以找到类似的代码结构，比如`if`语句，或`while`和`for`循环。

在 C#语言中开发各种应用程序也因为许多额外的出色功能而变得简化，比如**语言集成查询**（**LINQ**），它允许开发人员以一致的方式从各种集合中获取数据，比如 SQL 数据库或 XML 文档。还有一些缩短所需代码的方法，比如使用 lambda 表达式、表达式主体成员、getter 和 setter，或者字符串插值。值得一提的是自动垃圾回收，它简化了释放内存的任务。当然，上述解决方案只是在 C#开发中可用功能的非常有限的子集。在本书的后续部分中，您将看到一些其他功能，以及示例和详细描述。

# 数据类型

在 C#语言中开发应用程序时，您可以使用各种数据类型，它们分为两组，即**值类型**和**引用类型**。它们之间的区别非常简单——值类型的变量直接包含数据，而引用类型的变量只是存储对数据的引用，如下所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dsal/img/d38bd3e0-f4c1-4c4c-8b09-7125d7d0db69.png)

正如您所看到的，**值类型**直接将其实际**值**存储在**堆栈**内存中，而**引用类型**只在此处存储**引用**。实际值位于**堆**内存中。因此，也可能有两个或更多引用类型的变量引用完全相同的值。

当然，值类型和引用类型之间的区别在编程时非常重要，您应该知道哪些类型属于上述组。否则，您可能会在代码中犯错，这可能会很难找到。例如，您应该记住在更新引用类型的数据时要小心，因为更改也可能会反映在引用相同对象的其他变量中。此外，您在使用等号（`=`）运算符比较两个对象时也要小心，因为在比较两个引用类型的实例时，您可能会比较引用而不是数据本身。

C#语言还支持**指针类型**，可以声明为`type* identifier`或`void* identifier`。然而，这些类型超出了本书的范围。您可以在以下链接中了解更多信息：[`docs.microsoft.com/en-us/dotnet/csharp/programming-guide/unsafe-code-pointers/pointer-types`](https://docs.microsoft.com/en-us/dotnet/csharp/programming-guide/unsafe-code-pointers/pointer-types)。

# 值类型

为了让您更好地理解数据类型，让我们从对第一组（即**值类型**）的分析开始，它可以进一步分为**结构**和**枚举**。

更多信息请访问：[`docs.microsoft.com/en-us/dotnet/csharp/language-reference/keywords/value-types`](https://docs.microsoft.com/en-us/dotnet/csharp/language-reference/keywords/value-types)。

# 结构

在结构体中，您可以访问许多内置类型，这些类型可以作为关键字或来自`System`命名空间的类型使用。

其中之一是`Boolean`类型（`bool`关键字），它可以存储**逻辑值**，也就是两个值中的一个，即`true`或`false`。

至于存储**整数值**，您可以使用以下类型之一：`Byte`（`byte`关键字）、`SByte`（`sbyte`）、`Int16`（`short`）、`UInt16`（`ushort`）、`Int32`（`int`）、`UInt32`（`uint`）、`Int64`（`long`）和`UInt64`（`ulong`）。它们通过存储值的字节数和可用值的范围而有所不同。例如，`short`数据类型支持范围从-32,768 到 32,767 的值，而`uint`支持范围从 0 到 4,294,967,295 的值。整数类型中的另一种类型是`Char`（`char`），它表示单个 Unicode 字符，例如`'a'`或`'M'`。

在**浮点值**的情况下，您可以使用两种类型，即`Single`（`float`）和`Double`（`double`）。第一种使用 32 位，而第二种使用 64 位。因此，它们的精度有很大的不同。

此外，`Decimal`类型（`decimal`关键字）也是可用的。它使用 128 位，是货币计算的一个很好的选择。

C#编程语言中变量的一个示例声明如下：

```cs
int number; 
```

您可以使用等号（`=`）将值赋给变量，如下所示：

```cs
number = 500; 
```

当然，声明和赋值可以在同一行中执行：

```cs
int number = 500; 
```

如果您想声明和初始化一个**不可变值**，也就是一个**常量**，您可以使用`const`关键字，如下面的代码行所示：

```cs
const int DAYS_IN_WEEK = 7; 
```

有关内置数据类型的更多信息，以及完整的范围列表，请访问：[`msdn.microsoft.com/library/cs7y5x0x.aspx`](https://msdn.microsoft.com/library/cs7y5x0x.aspx)。

# 枚举

除了结构体，值类型还包括**枚举**。每个枚举都有一组命名的常量来指定可用的值集。例如，您可以创建可用语言或支持的货币的枚举。一个示例定义如下：

```cs
enum Language { PL, EN, DE }; 
```

然后，您可以将定义的枚举用作数据类型，如下所示：

```cs
Language language = Language.PL; 
switch (language) 
{ 
    case Language.PL: /* Polish version */ break; 
    case Language.DE: /* German version */ break; 
    default: /* English version */ break; 
} 
```

值得一提的是，枚举允许您用常量值替换一些*魔术字符串*（如`"PL"`或`"DE"`），这对代码质量有积极的影响。

您还可以从枚举的更高级特性中受益，例如更改基础类型或为特定常量指定值。您可以在此处找到更多信息：[`docs.microsoft.com/en-us/dotnet/csharp/language-reference/keywords/enum`](https://docs.microsoft.com/en-us/dotnet/csharp/language-reference/keywords/enum)。

# 引用类型

第二个主要类型组称为**引用类型**。作为一个快速提醒，引用类型的变量并不直接包含数据，因为它只是存储数据的引用。在这个组中，您可以找到三种内置类型，即`string`、`object`和`dynamic`。此外，您可以声明类、接口和委托。

有关引用类型的更多信息，请访问：[`docs.microsoft.com/en-us/dotnet/csharp/language-reference/keywords/reference-types`](https://docs.microsoft.com/en-us/dotnet/csharp/language-reference/keywords/reference-types)。

# 字符串

通常需要存储一些文本值。您可以使用`System`命名空间中的内置引用类型`String`来实现这一目标，也可以使用`string`关键字。`string`类型是 Unicode 字符的序列。它可以有零个字符、一个或多个字符，或者`string`变量可以设置为`null`。

您可以对`string`对象执行各种操作，例如连接或使用`[]`运算符访问特定字符，如下所示：

```cs
string firstName = "Marcin", lastName = "Jamro"; 
int year = 1988; 
string note = firstName + " " + lastName.ToUpper()  
   + " was born in " + year; 
string initials = firstName[0] + "." + lastName[0] + "."; 
```

一开始，声明了`firstName`变量，并将`"Marcin"`赋给它。同样，`"Jamro"`被设置为`lastName`变量的值。在第三行，您连接了五个字符串（使用`+`运算符），即`firstName`的当前值，空格，`lastName`的当前值转换为大写字符串（通过调用`ToUpper`方法），字符串`" was born in "`，以及`year`变量的当前值。在最后一行，使用`[]`运算符获取了`firstName`和`lastName`变量的第一个字符，并与两个点连接起来形成了缩写，即`M.J.`，这些缩写作为`initials`变量的值存储。

`Format`静态方法也可用于构造字符串，如下所示：

```cs
string note = string.Format("{0} {1} was born in {2}",  
   firstName, lastName.ToUpper(), year); 
```

在这个例子中，您指定了包含三个格式项的**复合格式字符串**，即`firstName`（由`{0}`表示），大写`lastName`（`{1}`），以及`year`（`{2}`）。要格式化的对象被指定为以下参数。

更多信息可在以下网址找到：[`docs.microsoft.com/en-us/dotnet/csharp/language-reference/keywords/string`](https://docs.microsoft.com/en-us/dotnet/csharp/language-reference/keywords/string)。

还值得一提的是**插值字符串**，它使用**插值表达式**来构造一个`string`。要使用这种方法创建一个`string`，需要在“”之前放置`$`字符，如下例所示：

```cs
string note = $"{firstName} {lastName.ToUpper()}  
   was born in {year}"; 
```

更多信息可在以下网址找到：[`docs.microsoft.com/en-us/dotnet/csharp/language-reference/keywords/interpolated-strings`](https://docs.microsoft.com/en-us/dotnet/csharp/language-reference/keywords/interpolated-strings)。

# 对象

`Object`类在`System`命名空间中声明，它在 C#语言中开发应用程序时扮演着非常重要的角色，因为它是所有类的基类。这意味着内置值类型和内置引用类型，以及用户定义的类型，都是从`Object`类派生出来的，也可以使用`object`别名来访问。

由于`object`类型是所有值类型的基本实体，这意味着可以将任何值类型的变量（例如`int`或`float`）转换为`object`类型，也可以将`object`类型的变量转换回特定的值类型。这些操作分别称为**装箱**（第一个）和**拆箱**（另一个）。它们如下所示：

```cs
int age = 28; 
object ageBoxing = age; 
int ageUnboxing = (int)ageBoxing; 
```

更多信息可在以下网址找到：[`docs.microsoft.com/en-us/dotnet/csharp/language-reference/keywords/object`](https://docs.microsoft.com/en-us/dotnet/csharp/language-reference/keywords/object)。

# 动态

除了已经描述的类型，还有`dynamic`类型可供开发人员使用。它允许在编译期间绕过类型检查，以便您可以在运行时执行它。这种机制在访问一些**应用程序编程接口**（**API**）时非常有用，但本书不会使用它。

更多信息可在以下网址找到：[`docs.microsoft.com/en-us/dotnet/csharp/language-reference/keywords/dynamic`](https://docs.microsoft.com/en-us/dotnet/csharp/language-reference/keywords/dynamic)。

# 类

如前所述，C#是一种面向对象的语言，支持声明类以及各种成员，包括构造函数、终结器、常量、字段、属性、索引器、事件、方法和运算符，以及委托。此外，类支持继承和实现接口。还有静态、抽象和虚拟成员可用。

以下是一个示例类：

```cs
public class Person 
{ 
    private string _location = string.Empty; 
    public string Name { get; set; } 
    public int Age { get; set; } 

    public Person() => Name = "---"; 

    public Person(string name, int age) 
    { 
        Name = name; 
        Age = age; 
    } 

    public void Relocate(string location) 
    { 
        if (!string.IsNullOrEmpty(location)) 
        { 
            _location = location; 
        } 
    } 

    public float GetDistance(string location) 
    { 
        return DistanceHelpers.GetDistance(_location, location); 
    } 
} 
```

`Person`类包含`_location`私有字段，默认值设置为空字符串（`string.Empty`），两个公共属性（`Name`和`Age`），一个默认构造函数，使用**表达式体定义**将`Name`属性的值设置为`---`，一个接受两个参数并设置属性值的额外构造函数，`Relocate`方法更新私有字段的值，以及`GetDistance`方法调用`DistanceHelpers`类的`GetDistance`静态方法，并返回两个城市之间的距离（以公里为单位）。

您可以使用`new`运算符创建类的实例。然后，您可以对创建的对象执行各种操作，比如调用方法，如下所示：

```cs
Person person = new Person("Mary", 20); 
person.Relocate("Rzeszow"); 
float distance = person.GetDistance("Warsaw");  
```

更多信息可在此处找到：[`docs.microsoft.com/en-us/dotnet/csharp/language-reference/keywords/class`](https://docs.microsoft.com/en-us/dotnet/csharp/language-reference/keywords/class)。

# 接口

在前面的部分中，提到了一个可以实现一个或多个**接口**的类。这意味着这样一个类必须实现所有在所有实现的接口中指定的方法、属性、事件和索引器。您可以使用`interface`关键字在 C#语言中轻松定义接口。

举个例子，让我们来看一下以下代码：

```cs
public interface IDevice 
{ 
    string Model { get; set; } 
    string Number { get; set; } 
    int Year { get; set; } 

    void Configure(DeviceConfiguration configuration); 
    bool Start(); 
    bool Stop(); 
} 
```

`IDevice`接口包含三个属性，分别表示设备型号（`Model`）、序列号（`Number`）和生产年份（`Year`）。此外，它还具有三个方法的签名，分别是`Configure`、`Start`和`Stop`。当一个类实现`IDevice`接口时，它应该包含上述属性和方法。

更多信息可在此处找到：[`docs.microsoft.com/en-us/dotnet/csharp/language-reference/keywords/interface`](https://docs.microsoft.com/en-us/dotnet/csharp/language-reference/keywords/interface)。

# 委托

`delegate`引用类型允许指定方法的必需签名。然后可以实例化委托，并像下面的代码中所示那样调用它。

```cs
delegate double Mean(double a, double b, double c); 

static double Harmonic(double a, double b, double c) 
{ 
    return 3 / ((1 / a) + (1 / b) + (1 / c)); 
} 

static void Main(string[] args) 
{ 
    Mean arithmetic = (a, b, c) => (a + b + c) / 3; 
    Mean geometric = delegate (double a, double b, double c) 
    { 
        return Math.Pow(a * b * c, 1 / 3.0); 
    }; 
    Mean harmonic = Harmonic; 
    double arithmeticResult = arithmetic.Invoke(5, 6.5, 7); 
    double geometricResult = geometric.Invoke(5, 6.5, 7); 
    double harmonicResult = harmonic.Invoke(5, 6.5, 7); 
} 
```

在示例中，`Mean`委托指定了用于计算三个浮点数的平均值的方法的必需签名。它使用 lambda 表达式（`arithmetic`）、匿名方法（`geometric`）和命名方法（`harmonic`）进行实例化。通过调用`Invoke`方法来调用每个委托。

更多信息可在此处找到：[`docs.microsoft.com/en-us/dotnet/csharp/language-reference/keywords/delegate`](https://docs.microsoft.com/en-us/dotnet/csharp/language-reference/keywords/delegate)。

# IDE 的安装和配置

在阅读本书时，您将看到许多示例，展示了数据结构和算法，以及详细的描述。代码的最重要部分将直接显示在书中。此外，完整的源代码也可以下载。当然，您可以只从书中阅读代码，但强烈建议您自己编写这样的代码，然后启动和调试程序，以了解各种数据结构和算法的运行方式。

如前所述，本书中展示的示例将使用 C#语言准备。为了保持简单，将创建基于控制台的应用程序，但这样的数据结构也可以用在其他类型的解决方案中。

示例项目将在**Microsoft Visual Studio 2017 Community**中创建。这个**集成开发环境**（**IDE**）是开发各种项目的综合解决方案。要下载、安装和配置它，您应该：

1.  打开网站[`www.visualstudio.com/downloads/`](https://www.visualstudio.com/downloads/)，并在 Visual Studio Community 2017 部分的 Visual Studio Downloads 标题下选择免费下载选项。安装程序的下载过程应该会自动开始。

1.  运行下载的文件并按照说明开始安装。当显示可能选项的屏幕时，选择.NET 桌面开发选项，如下面的屏幕截图所示。然后，点击安装。安装可能需要一些时间，但可以使用获取和应用进度条来观察其进展。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dsal/img/271ec5a2-9e1a-4567-9fb2-98ae4aa24a33.png)

1.  当显示安装成功！的消息时，点击启动按钮启动 IDE。您将被要求使用 Microsoft 帐户登录。然后，您应该在“以熟悉的环境开始”部分选择适当的开发设置（如 Visual C#）。此外，您应该从蓝色、蓝色（额外对比）、深色和浅色中选择颜色主题。最后，点击“启动 Visual Studio”按钮。

# 创建项目

在启动 IDE 后，让我们继续创建一个新项目。在阅读本书时，根据特定章节提供的信息，将执行这样的过程多次，以创建示例应用程序。

要创建一个新项目：

1.  在主菜单中点击“文件 | 新建 | 项目”。

1.  在新项目窗口的左侧选择已安装 | Visual C# | Windows 经典桌面，如下面的屏幕截图所示。然后，在中间点击 Console App (.NET Framework)。您还应该输入项目的名称（名称）和解决方案的名称（解决方案名称），并通过按浏览按钮选择文件的位置（位置）。最后，点击确定以自动创建项目并生成必要的文件：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dsal/img/f27929bd-547a-45de-b61d-81356765196b.png)

恭喜，您刚刚创建了第一个项目！但里面有什么呢？

让我们看看“解决方案资源管理器”窗口，它显示了项目的结构。值得一提的是，该项目包含在同名的解决方案中。当然，一个解决方案可以包含多个项目，这在开发更复杂的应用程序时是常见的情况。

如果找不到“解决方案资源管理器”窗口，可以通过从主菜单中选择“查看 | 解决方案资源管理器”选项来打开它。类似地，您可以打开其他窗口，如输出或类视图。如果在“查看”选项中找不到合适的窗口（例如 C#交互），让我们尝试在“查看 | 其他窗口”节点中找到它。

自动生成的项目（名为`GettingStarted`）具有以下结构：

+   “属性”节点包含一个文件（`AssemblyInfo.cs`），其中包含有关应用程序的程序集的一般信息，例如标题、版权和版本。使用属性进行配置，例如`AssemblyTitleAttribute`和`AssemblyVersionAttribute`。

+   “引用”元素显示了项目使用的其他程序集或项目。值得注意的是，您可以通过从“引用”元素的上下文菜单中选择“添加引用”选项来轻松添加引用。此外，您可以使用 NuGet 软件包管理器安装其他软件包，该软件包可以通过从“引用”上下文菜单中选择“管理 NuGet 软件包”来启动。

在自己编写复杂模块之前，先看看已经可用的包是个好主意，因为适当的包可能已经为开发人员提供。在这种情况下，您不仅可以缩短开发时间，还可以减少引入错误的机会。

+   `App.config`文件包含应用程序的基于**可扩展标记语言**（**XML**）的配置，包括.NET Framework 平台的最低支持版本号。

+   `Program.cs`文件包含 C#语言中主类的代码。您可以通过更改以下默认实现来调整应用程序的行为：

```cs
using System; 
using System.Collections.Generic; 
using System.Linq; 
using System.Text; 
using System.Threading.Tasks; 

namespace GettingStarted 
{ 
    class Program 
    { 
        static void Main(string[] args) 
        { 
        } 
    } 
} 
```

`Program.cs`文件的初始内容包含了`GettingStarted`命名空间中`Program`类的定义。该类包含了`Main`静态方法，当应用程序启动时会自动调用。还包括了五个`using`语句，分别是`System`、`System.Collections.Generic`、`System.Linq`、`System.Text`和`System.Threading.Tasks`。

在继续之前，让我们在文件资源管理器中查看项目的结构，而不是在“解决方案资源管理器”窗口中。这些结构是否完全相同？

您可以通过在“解决方案资源管理器”窗口中的项目节点的上下文菜单中选择“在文件资源管理器中打开文件夹”选项来打开项目所在的目录。

首先，您可以看到自动生成的`bin`和`obj`目录。两者都包含与 IDE 中设置的配置相关的`Debug`和`Release`目录。构建项目后，`bin`目录的子目录（即`Debug`或`Release`）包含`.exe`、`.exe.config`和`.pdb`文件，而`obj`目录中的子目录，例如，包含`.cache`和一些临时`.cs`文件。此外，没有`References`目录，但是有项目的基于 XML 的`.csproj`和`.csproj.user`文件。类似地，基于解决方案的`.sln`配置文件位于解决方案的目录中。

如果您正在使用**版本控制系统**，比如**SVN**或**Git**，您可以忽略`bin`和`obj`目录，以及`.csproj.user`文件。所有这些都可以自动生成。

如果您想学习如何编写一些示例代码，以及启动和调试程序，让我们继续到下一节。

# 输入和输出

书的后面部分中展示的许多示例将需要与用户进行交互，特别是通过读取输入数据和显示输出。您可以按照本节中的说明轻松地向应用程序添加这些功能。

# 从输入中读取

应用程序可以使用`System`命名空间中`Console`静态类的几种方法从**标准输入流**中读取数据，例如`ReadLine`和`ReadKey`。这两者都在本节的示例中展示了。

让我们来看看下面的代码行：

```cs
string fullName = Console.ReadLine(); 
```

在这里，您使用`ReadLine`方法。它会等待用户按下*Enter*键。然后，输入的文本将作为`fullName`字符串变量的值存储。

以类似的方式，您可以读取其他类型的数据，例如`int`，如下所示：

```cs
string numberString = Console.ReadLine(); 
int.TryParse(numberString, out int number); 
```

在这种情况下，调用了相同的`ReadLine`方法，并将输入的文本存储为`numberString`变量的值。然后，您只需要将其解析为`int`并将其存储为`int`变量的值。您可以如何做到这一点？解决方案非常简单——使用`Int32`结构的`TryParse`静态方法。值得一提的是，这样的方法返回一个布尔值，指示解析过程是否成功完成。因此，当提供的`string`表示不正确时，您可以执行一些额外的操作。

在下面的示例中，展示了关于`DateTime`结构和`TryParseExact`静态方法的类似情况：

```cs
string dateTimeString = Console.ReadLine(); 
if (!DateTime.TryParseExact( 
    dateTimeString, 
    "M/d/yyyy HH:mm", 
    new CultureInfo("en-US"), 
    DateTimeStyles.None, 
    out DateTime dateTime)) 
{ 
    dateTime = DateTime.Now; 
} 
```

这个示例比之前的更复杂，所以让我们详细解释一下。首先，日期和时间的字符串表示被存储为`dateTimeString`变量的值。然后，调用了`DateTime`结构的`TryParseExact`静态方法，传递了五个参数，即日期和时间的字符串表示（`dateTimeString`）、日期和时间的预期格式（`M/d/yyyy HH:mm`）、支持的文化（`en-US`）、附加样式（`None`），以及通过`out`参数修饰符传递的输出变量（`dateTime`）。

如果解析未成功完成，则将当前日期和时间（`DateTime.Now`）分配给`dateTime`变量。否则，`dateTime`变量包含与用户提供的`string`表示一致的`DateTime`实例。

在涉及`CultureInfo`类名称的代码部分中，您可能会看到以下错误：`CS0246 The type or namespace name 'CultureInfo' could not be found (are you missing a using directive or an assembly reference?)`。这意味着您在文件顶部没有合适的`using`语句。您可以通过单击显示在错误行左侧边缘的灯泡图标并选择`using System.Globalization;`选项来轻松添加一个。IDE 将自动添加缺少的`using`语句，错误将消失。

除了读取整行外，您还可以了解用户按下了哪个字符或功能键。为此，您可以使用`ReadKey`方法，如下面的代码部分所示：

```cs
ConsoleKeyInfo key = Console.ReadKey(); 
switch (key.Key) 
{ 
    case ConsoleKey.S: /* Pressed S */ break; 
    case ConsoleKey.F1: /* Pressed F1 */ break; 
    case ConsoleKey.Escape: /* Pressed Escape */ break; 
} 
```

调用`ReadKey`静态方法后，一旦用户按下任意键，按下的键的信息就会被存储为`ConsoleKeyInfo`实例（在当前示例中为`key`）。然后，您可以使用`Key`属性获取表示特定键的枚举值（`ConsoleKey`）。最后，使用`switch`语句根据按下的键执行操作。在所示的示例中，支持三个键，即*S*，*F1*和*Esc*。

# 写入输出

现在，您知道如何读取输入数据，但如何向用户提问或在屏幕上显示结果呢？答案以及示例在本节中展示。

与读取数据一样，与**标准输出流**相关的操作使用`System`命名空间中`Console`静态类的方法执行，即`Write`和`WriteLine`。让我们看看它们的运作方式！

要写一些文本，您只需调用`Write`方法，将文本作为参数传递。代码示例如下：

```cs
Console.Write("Enter a name: "); 
```

前一行导致显示以下输出：

```cs
    Enter a name: 
```

这里重要的是，所写的文本后面没有跟随换行符。如果要写一些文本并移到下一行，可以使用`WriteLine`方法，如下面的代码片段所示：

```cs
Console.WriteLine("Hello!"); 
```

执行此行代码后，将呈现以下输出：

```cs
    Hello!
```

当然，您还可以在更复杂的情况下使用`Write`和`WriteLine`方法。例如，您可以向`WriteLine`方法传递许多参数，即格式和附加参数，如下面代码的部分所示：

```cs
string name = "Marcin"; 
Console.WriteLine("Hello, {0}!", name); 
```

在这种情况下，该行将包含`Hello`，逗号，空格，`name`变量的值（即`Marcin`），以及感叹号。输出如下所示：

```cs
    Hello, Marcin!
```

下一个示例呈现了一个更复杂的场景，涉及在餐厅预订桌子的确认。输出应具有格式`Table [number] has been booked for [count] people on [date] at [time]`。您可以通过使用`WriteLine`方法来实现这个目标，如下所示：

```cs
string tableNumber = "A100"; 
int peopleCount = 4; 
DateTime reservationDateTime = new DateTime( 
    2017, 10, 28, 11, 0, 0); 
CultureInfo cultureInfo = new CultureInfo("en-US"); 
Console.WriteLine( 
    "Table {0} has been booked for {1} people on {2} at {3}", 
    tableNumber, 
    peopleCount, 
    reservationDateTime.ToString("M/d/yyyy", cultureInfo), 
    reservationDateTime.ToString("HH:mm", cultureInfo)); 
```

该示例以声明四个变量开始，即`tableNumber`（`A100`），`peopleCount`（`4`），`reservationDateTime`（2017 年 10 月 28 日上午 11:00），以及`cultureInfo`（`en-US`）。然后，调用`WriteLine`方法，传递五个参数，即格式字符串，后跟应显示在标有`{0}`，`{1}`，`{2}`和`{3}`的位置的参数。值得一提的是最后两行，其中基于`reservationDateTime`变量的当前值创建了表示日期（或时间）的字符串。

执行此代码后，将在输出中显示以下行：

```cs
    Table A100 has been booked for 4 people on 10/28/2017 at 11:00 
```

当然，在现实场景中，您将在同一代码中使用读取和写入相关的方法。例如，您可以要求用户提供一个值（使用`Write`方法），然后读取输入的文本（使用`ReadLine`方法）。

这个简单的例子，在本章的下一节中也很有用，如下所示。它允许用户输入与表格预订相关的数据，即桌号和人数，以及预订日期。当所有数据都输入后，将呈现确认。当然，用户将看到应提供的数据的信息：

```cs
using System; 
using System.Globalization; 

namespace GettingStarted 
{ 
    class Program 
    { 
        static void Main(string[] args) 
        { 
            CultureInfo cultureInfo = new CultureInfo("en-US"); 

            Console.Write("The table number: "); 
            string table = Console.ReadLine(); 

            Console.Write("The number of people: "); 
            string countString = Console.ReadLine(); 
            int.TryParse(countString, out int count); 

            Console.Write("The reservation date (MM/dd/yyyy): "); 
            string dateTimeString = Console.ReadLine(); 
            if (!DateTime.TryParseExact( 
                dateTimeString, 
                "M/d/yyyy HH:mm", 
                cultureInfo, 
                DateTimeStyles.None, 
                out DateTime dateTime)) 
            { 
                dateTime = DateTime.Now; 
            } 

            Console.WriteLine( 
                "Table {0} has been booked for {1} people on {2}  
                 at {3}", 
                table, 
                count, 
                dateTime.ToString("M/d/yyyy", cultureInfo), 
                dateTime.ToString("HH:mm", cultureInfo)); 
        } 
    } 
} 
```

前面的代码片段是基于先前显示和描述的代码部分。启动程序并输入必要的数据后，输出可能如下所示：

```cs
    The table number: A100
    The number of people: 4
    The reservation date (MM/dd/yyyy): 10/28/2017 11:00
    Table A100 has been booked for 4 people on 10/28/2017 at 11:00
    Press any key to continue . . . 
```

编写代码时，改进其质量是个好主意。与 IDE 相关的有趣可能性之一是删除未使用的`using`语句，以及对剩余语句进行排序。您可以通过在文本编辑器中选择“删除并排序使用”选项来轻松执行此操作。

# 启动和调试

不幸的是，编写的代码并不总是按预期工作。在这种情况下，最好开始**调试**，看看程序的运行方式，找到问题的源头并进行更正。这项任务对于复杂的算法特别有用，其中流程可能很复杂，因此仅通过阅读代码就很难分析。幸运的是，IDE 配备了各种调试功能，将在本节中介绍。

首先，让我们启动应用程序，看看它的运行情况！要这样做，您只需从下拉列表中选择适当的配置（在本例中为调试），然后单击主工具栏中带有绿色三角形和“开始”标题的按钮，或按下*F5*。要停止调试，您可以选择调试 | 停止调试，或按下*Shift* + *F5*。

您还可以在不调试的情况下运行应用程序。要这样做，请从主菜单中选择调试 | 启动无调试，或按下*Ctrl* + *F5*。

如前所述，有各种调试技术，但让我们从基于断点的调试开始，因为这是提供巨大机会的最常见方法之一。您可以在代码的任何行中放置**断点**。程序将在达到该行之前停止执行。然后，您可以查看特定变量的值，以检查应用程序是否按预期工作。

要添加断点，您可以单击左边的边距（在应放置断点的行旁边）或将光标放在应添加断点的行上，并按下*F9*键。在这两种情况下，将显示红色圆圈，并且给定行的代码将标有红色背景，如下截图中的第 17 行所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dsal/img/eb41bd4a-e0b2-4398-a76c-c5790e103123.png)

当执行程序时到达带有断点的行时，程序将停止，并且该行将标有黄色背景，边距图标也会更改，如截图中的第 15 行所示。现在，您可以通过简单地将光标移动到其名称上来检查变量的值。当前值将显示在工具提示中。

您还可以单击位于工具提示右侧的图钉图标，将其固定在编辑器中。然后，该值将在不必移动光标到变量名称上的情况下可见。一旦值发生变化，该值将自动刷新。结果如下截图所示。

IDE 可以根据当前执行的操作调整其外观和功能。例如，在调试时，您可以访问一些特殊的窗口，例如 Locals、Call Stack 和 Diagnostic Tools。第一个显示可用的本地变量及其类型和值。Call Stack 窗口显示有关以下调用方法的信息。最后一个（即 Diagnostic Tools）显示有关内存和 CPU 使用情况以及事件的信息。

此外，IDE 支持条件断点，仅当关联的布尔表达式计算为`true`时才停止程序的执行。您可以通过选择上下文菜单中的 Conditions 选项来为给定的断点添加条件，该菜单在右键单击左侧边栏中的断点图标后显示。然后，断点设置窗口将出现，在那里您应该勾选条件复选框并指定条件表达式，例如在以下屏幕截图中显示的表达式。在示例中，只有当`count`变量的值大于`5`时，即`count > 5`时，执行才会停止：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dsal/img/b2228230-44fd-477c-bebc-3be5145fc5fd.png)

当执行停止时，您可以使用逐步调试技术。要将程序的执行移动到下一行（而不是加入另一个断点），您可以单击主工具栏中的 Step Over 图标，或按*F10*。如果要进入在执行停止的行中调用的方法，只需单击 Step Into 按钮或按*F11*。当然，您也可以通过单击 Continue 按钮或按*F5*来转到下一个断点。

IDE 中的下一个有趣功能称为 Immediate Window。它允许开发人员在程序执行停止时使用变量的当前值执行各种表达式。您只需在 Immediate Window 中输入表达式，然后按*Enter*键。示例如下屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dsal/img/a8826820-8d88-47c8-95ab-b75584792e00.png)

在这里，通过执行`table.ToLower()`返回表号的小写版本。然后，计算并显示当前日期和`dateTime`变量之间的总分钟数。

# 摘要

这只是本书的第一章，但它包含了很多信息，在阅读剩下的章节时将会很有用。一开始，您看到使用适当的数据结构和算法并不是一件容易的事，但可能会对开发解决方案的性能产生重大影响。然后，简要介绍了 C#编程语言，重点介绍了各种数据类型，包括值类型和引用类型。还描述了类、接口和委托。

在本章的后续部分，介绍了 IDE 的安装和配置过程。然后，您学习了如何创建一个新项目，并详细描述了其结构。接下来，您看到了如何从标准输入流中读取数据，以及如何将数据写入标准输出流。读取和写入相关的操作也混合在一个示例中。

在本章结束时，您学会了如何运行示例程序，以及如何使用断点和逐步调试来找到问题的根源。此外，您还了解了 Immediate Window 功能的可能性。

介绍完毕后，您应该准备继续下一章，了解如何使用数组和列表，以及相关的算法。让我们开始吧！


# 第二章：数组和列表

作为开发人员，您肯定在应用程序中存储了各种集合，例如用户数据、书籍和日志。存储这些数据的一种自然方式是使用数组和列表。但是，您是否曾想过它们的变体？您是否听说过交错数组或循环链表？在本章中，您将看到这些数据结构的实际应用，以及示例和详细描述。这还不是全部，因为本章涉及许多关于数组和列表的主题，适合具有不同编程技能水平的开发人员。

在本章的开头，将介绍并将数组分为单维、多维和交错数组。您还将了解四种排序算法，即选择、插入、冒泡排序和快速排序。对于每一种算法，您将看到基于示例的说明、实现代码和逐步解释。

数组有很多可能性。然而，在使用 C#语言开发时可用的通用列表更加强大。在本章的剩余部分，您将看到如何使用几种列表的变体，例如简单、排序、双向和循环链表。对于每一个，都将展示一个示例的 C#代码，并附有详细描述。

本章将涵盖以下主题：

+   数组

+   排序算法

+   简单列表

+   排序列表

+   链表

+   循环链表

# 数组

让我们从数组数据结构开始。您可以使用它来存储许多相同类型的变量，例如`int`，`string`或用户定义的类。正如在介绍中提到的，在使用 C#语言开发应用程序时，您可以从以下图表中看到数组的几种变体。您不仅可以访问单维数组（表示为**a**），还可以访问多维（**b**）和交错（**c**）数组。所有这些的示例都在下图中显示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dsal/img/9fefe52c-959d-4887-aa69-dfc748aab7a9.png)

重要的是，数组中的元素数量在初始化后无法更改。因此，您将无法轻松地在数组末尾添加新项或在数组中的特定位置插入新项。如果需要这样的功能，可以使用本章中描述的其他数据结构，例如通用列表。

您可以在以下链接找到有关数组的更多信息：[`docs.microsoft.com/en-us/dotnet/csharp/programming-guide/arrays/`](https://docs.microsoft.com/en-us/dotnet/csharp/programming-guide/arrays/)。

通过这个简短的描述，您应该已经准备好了解更多关于数组的特定变体，并查看一些 C#代码。因此，让我们继续学习数组的最简单变体，即单维数组。

# 单维数组

单维数组存储相同类型的项目集合，可以通过索引访问。重要的是要记住，在 C#中，数组的索引是从零开始的。这意味着第一个元素的索引等于**0**，而最后一个元素的索引等于数组长度减一。

在前面的图表中显示了一个示例数组（在左侧，表示为**a**）。它包含五个元素，其值分别为**9**，**-11**，**6**，**-12**和**1**。第一个元素的索引等于**0**，而最后一个元素的索引等于**4**。

要使用单维数组，您需要声明和初始化它。声明非常简单，因为您只需要指定元素类型和名称，如下所示：

```cs
type[] name; 
```

以下行显示了具有整数值的数组的声明：

```cs
int[] numbers;  
```

现在您知道如何声明数组了，但初始化呢？要将数组元素初始化为默认值，可以使用`new`运算符，如下所示：

```cs
numbers = new int[5]; 
```

当然，您可以在同一行中组合声明和初始化，如下所示：

```cs
int[] numbers = new int[5]; 
```

不幸的是，所有元素目前都具有默认值，即整数值的情况下为零。因此，您需要设置特定元素的值。您可以使用`[]`运算符和元素的索引来做到这一点，就像下面的代码片段中所示的那样：

```cs
numbers[0] = 9; 
numbers[1] = -11; (...) 
numbers[4] = 1; 
```

此外，您可以使用以下一种变体将数组元素的声明和初始化组合为特定值：

```cs
int[] numbers = new int[] { 9, -11, 6, -12, 1 }; 
int[] numbers = { 9, -11, 6, -12, 1 };  
```

当您在数组中有正确的元素值时，可以使用`[]`运算符并指定索引来获取值，就像下面的代码行所示的那样：

```cs
int middle = numbers[2];
```

在这里，从名为`numbers`的数组中获取第三个元素（索引等于`2`）的值，并将其存储为`middle`变量的值。

有关单维数组的更多信息可在[`docs.microsoft.com/en-us/dotnet/csharp/programming-guide/arrays/single-dimensional-arrays`](https://docs.microsoft.com/en-us/dotnet/csharp/programming-guide/arrays/single-dimensional-arrays)找到。

# 示例-月份名称

总结一下您所学到的关于单维数组的信息，让我们看一个简单的例子，其中数组用于存储英文月份的名称。这些名称应该是自动获取的，而不是在代码中硬编码的。

实现如下所示：

```cs
string[] months = new string[12]; 

for (int month = 1; month <= 12; month++) 
{ 
    DateTime firstDay = new DateTime(DateTime.Now.Year, month, 1); 
    string name = firstDay.ToString("MMMM",  
        CultureInfo.CreateSpecificCulture("en")); 
    months[month - 1] = name; 
} 

foreach (string month in months) 
{ 
    Console.WriteLine($"-> {month}"); 
} 
```

首先，声明一个新的单维数组，并用默认值初始化。它包含`12`个元素，用于存储一年中的月份名称。然后，使用`for`循环来迭代所有月份的数字，即从`1`到`12`。对于每个月，创建表示特定月份第一天的`DateTime`实例。

通过在`DateTime`实例上调用`ToString`方法，传递日期的正确格式（`MMMM`），以及指定文化（例如`en`），来获取月份的名称。然后，使用`[]`运算符和元素的索引将名称存储在数组中。值得注意的是，索引等于当前`month`变量的值减一。这种减法是必要的，因为数组中的第一个元素的索引等于零，而不是一。

代码的下一个有趣部分是`foreach`循环，它遍历数组的所有元素。对于每个元素，在控制台中显示一行，即`->`后面的月份名称。结果如下：

```cs
    -> January
    -> February (...)
    -> November
    -> December
```

如前所述，单维数组并非唯一可用的变体。您将在下一节中了解更多关于多维数组的信息。

# 多维数组

C#语言中的数组不一定只有一维。也可以创建二维甚至三维数组。首先，让我们看一个关于声明和初始化具有`5`行和`2`列的二维数组的例子：

```cs
int[,] numbers = new int[5, 2]; 
```

如果您想创建一个三维数组，可以使用以下代码：

```cs
int[, ,] numbers = new int[5, 4, 3]; 
```

当然，您也可以将声明与初始化结合起来，就像下面的例子中所示的那样：

```cs
int[,] numbers = new int[,] = 
{ 
    { 9, 5, -9 }, 
    { -11, 4, 0 }, 
    { 6, 115, 3 }, 
    { -12, -9, 71 }, 
    { 1, -6, -1 } 
};
```

对于从多维数组中访问特定元素的方式需要一些解释。让我们看下面的例子：

```cs
int number = numbers[2][1]; 
numbers[1][0] = 11; 
```

在代码的第一行中，获取了第三行（索引等于`2`）和第二列（索引等于`1`）的值（即`115`），并将其设置为`number`变量的值。另一行将第二行和第一列中的`-11`替换为`11`。

有关多维数组的更多信息可在[`docs.microsoft.com/en-us/dotnet/csharp/programming-guide/arrays/multidimensional-arrays`](https://docs.microsoft.com/en-us/dotnet/csharp/programming-guide/arrays/multidimensional-arrays)找到。

# 示例-乘法表

第一个示例展示了对二维数组进行基本操作，目的是呈现一个乘法表。它写入了从`1`到`10`范围内所有整数值的乘法结果，如下所示：

```cs
       1   2   3   4   5   6   7   8   9  10
       2   4   6   8  10  12  14  16  18  20
       3   6   9  12  15  18  21  24  27  30
       4   8  12  16  20  24  28  32  36  40
       5  10  15  20  25  30  35  40  45  50
       6  12  18  24  30  36  42  48  54  60
       7  14  21  28  35  42  49  56  63  70
       8  16  24  32  40  48  56  64  72  80
       9  18  27  36  45  54  63  72  81  90
      10  20  30  40  50  60  70  80  90 100

```

让我们来看一下数组的声明和初始化方法：

```cs
int[,] results = new int[10, 10];
```

在这里，创建了一个有`10`行和`10`列的二维数组，并将其元素初始化为默认值，即零。

当数组准备好后，您应该用乘法的结果填充它。这样的任务可以使用两个`for`循环来执行：

```cs
for (int i = 0; i < results.GetLength(0); i++) 
{ 
    for (int j = 0; j < results.GetLength(1); j++) 
    { 
        results[i, j] = (i + 1) * (j + 1); 
    } 
} 
```

在前面的代码中，您可以找到在数组对象上调用的`GetLength`方法。该方法返回特定维度中的元素数量，即第一个（当参数为`0`时）和第二个（参数为`1`时）。在两种情况下，根据数组初始化时指定的值，都返回了`10`。

代码的另一个重要部分是设置二维数组中元素的值的方式。为此，您需要提供两个索引，例如`results[i, j]`。

最后，您只需要呈现结果。您可以使用两个`for`循环来做到这一点，就像填充数组一样。代码的这一部分如下所示：

```cs
for (int i = 0; i < results.GetLength(0); i++) 
{ 
    for (int j = 0; j < results.GetLength(1); j++) 
    { 
        Console.Write("{0,4}", results[i, j]); 
    } 
    Console.WriteLine(); 
} 
```

乘法结果在转换为`string`值后，长度不同，从一个字符（如`2*2`的结果`4`）到三个字符（`10*10`的`100`）。为了改善显示效果，需要始终在`4`个字符上写入每个结果。因此，如果整数值占用的空间较小，就应该添加前导空格。例如，结果 1 将显示为三个前导空格（`___1`，其中`_`是空格），而`100`只有一个（`_100`）。您可以通过在调用`Console`类的`Write`方法时使用适当的复合格式字符串（即`{0,4}`）来实现这个目标。

# 示例-游戏地图

另一个应用二维数组的例子是一个呈现游戏地图的程序。地图是一个有 11 行和 10 列的矩形。数组的每个元素指定了草地、沙地、水域或墙壁等类型的地形。地图上的每个位置都应该以特定的颜色显示（例如草地为绿色），并使用一个自定义字符来描述地形类型（例如水域为`≈`），如截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dsal/img/dd73ef8b-693e-4a5d-b14c-2af5879f2233.png)

首先，让我们声明枚举值`TerrainEnum`，其中包括四个常量，即`GRASS`、`SAND`、`WATER`和`WALL`，如下所示：

```cs
public enum TerrainEnum 
{ 
    GRASS, 
    SAND, 
    WATER, 
    WALL 
} 
```

为了提高整个项目的可读性，建议在一个单独的文件中声明`TerrainEnum`类型，命名为`TerrainEnum.cs`。这个规则也应该适用于所有用户定义的类型，包括类。

然后，您创建了两个扩展方法，可以根据地形类型（分别是`GetColor`和`GetChar`）获取特定的颜色和字符。这些扩展方法在`TerrainEnumExtensions`类中声明，如下所示：

```cs
public static class TerrainEnumExtensions 
{ 
    public static ConsoleColor GetColor(this TerrainEnum terrain) 
    { 
        switch (terrain) 
        { 
            case TerrainEnum.GRASS: return ConsoleColor.Green; 
            case TerrainEnum.SAND: return ConsoleColor.Yellow; 
            case TerrainEnum.WATER: return ConsoleColor.Blue; 
            default: return ConsoleColor.DarkGray; 
        } 
    } 

    public static char GetChar(this TerrainEnum terrain) 
    { 
        switch (terrain) 
        { 
            case TerrainEnum.GRASS: return '\u201c'; 
            case TerrainEnum.SAND: return '\u25cb'; 
            case TerrainEnum.WATER: return '\u2248'; 
            default: return '\u25cf'; 
        } 
    } 
} 
```

值得一提的是，`GetChar`方法根据`TerrainEnum`值返回适当的 Unicode 字符。例如，在`WATER`常量的情况下，返回了`'\u2248'`值，这是`≈`字符的表示。

您听说过**扩展方法**吗？如果没有，可以将其视为“添加”到特定现有类型（内置或用户定义）的方法，可以像定义实例方法一样调用它们。扩展方法的声明要求您在静态类中指定它作为带有第一个参数指示要“添加”此方法的类型的静态方法，并使用`this`关键字。您可以在[`docs.microsoft.com/en-us/dotnet/csharp/programming-guide/classes-and-structs/extension-methods`](https://docs.microsoft.com/en-us/dotnet/csharp/programming-guide/classes-and-structs/extension-methods)找到更多信息。

让我们来看看`Program`类中`Main`方法的主体。在这里，您配置地图，并在控制台中呈现它。代码如下：

```cs
TerrainEnum[,] map = 
{ 
    { TerrainEnum.SAND, TerrainEnum.SAND, TerrainEnum.SAND,  
      TerrainEnum.SAND, TerrainEnum.GRASS, TerrainEnum.GRASS,  
      TerrainEnum.GRASS, TerrainEnum.GRASS, TerrainEnum.GRASS,  
      TerrainEnum.GRASS }, (...) 
    { TerrainEnum.WATER, TerrainEnum.WATER, TerrainEnum.WATER,  
      TerrainEnum.WATER, TerrainEnum.WATER, TerrainEnum.WATER,  
      TerrainEnum.WATER, TerrainEnum.WALL, TerrainEnum.WATER,  
      TerrainEnum.WATER } 
}; 
Console.OutputEncoding = UTF8Encoding.UTF8; 
for (int row = 0; row < map.GetLength(0); row++) 
{ 
    for (int column = 0; column < map.GetLength(1); column++) 
    { 
        Console.ForegroundColor = map[row, column].GetColor(); 
        Console.Write(map[row, column].GetChar() + " "); 
    } 
    Console.WriteLine(); 
} 
Console.ForegroundColor = ConsoleColor.Gray; 
```

关于获取颜色和获取特定地图位置的字符的方式可能会有所帮助。这两个操作都是使用“添加”到`TerrainEnum`用户定义类型的扩展方法执行的。因此，您首先获取特定地图位置的`TerrainEnum`值（使用`[]`运算符和两个索引），然后调用适当的扩展方法，即`GetChar`或`GetColor`。要使用 Unicode 值，您不应忘记通过将`UTF8Encoding.UTF8`值设置为`OutputEncoding`属性来选择 UTF-8 编码。

到目前为止，您已经了解了单维和多维数组，但本书还有一个变体需要介绍。让我们继续阅读，以了解更多信息。

# 交错数组

本书中描述的数组的最后一种变体是交错数组，也称为**数组的数组**。听起来很复杂，但幸运的是，它非常简单。交错数组可以理解为单维数组，其中每个元素都是另一个数组。当然，这样的内部数组可以具有不同的长度，甚至可以未初始化。

如果您看一下以下图表，您将看到一个具有四个元素的交错数组的示例。第一个元素有一个具有三个元素（`9`，`5`，`-9`）的数组，第二个元素有一个具有五个元素（`0`，`-3`，`12`，`51`，`-3`）的数组，第三个未初始化（`NULL`），而最后一个是一个只有一个元素（`54`）的数组：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dsal/img/949bdc78-43f5-4477-8bb5-b25ab8b1d35c.png)

在继续示例之前，值得一提的是声明和初始化交错数组的方式，因为它与已经描述的数组有些不同。让我们看一下以下代码片段：

```cs
int[][] numbers = new int[4][]; 
numbers[0] = new int[] { 9, 5, -9 }; 
numbers[1] = new int[] { 0, -3, 12, 51, -3 }; 
numbers[3] = new int[] { 54 }; 
```

在第一行中，您可以看到具有四个元素的单维数组的声明。每个元素都是另一个整数值的单维数组。当执行第一行时，`numbers`数组将用默认值`NULL`初始化。因此，您需要手动初始化特定元素，如代码的下面三行所示。值得注意的是，第三个元素未初始化。

您还可以以不同的方式编写前面的代码，如下所示：

```cs
int[][] numbers = 
{ 
    new int[] { 9, 5, -9 }, 
    new int[] { 0, -3, 12, 51, -3 }, 
    NULL, 
    new int[] { 54 } 
}; 
```

对于访问交错数组中的特定元素的方法也需要一些说明。您可以按以下方式执行此操作：

```cs
int number = numbers[1][2]; 
number[1][3] = 50; 
```

代码的第一行将`number`变量的值设置为`12`，即数组中的第三个元素（索引等于`2`）的值，这是交错数组的第二个元素。另一行将数组中的第四个元素的值更改为`50`，这是交错数组的第二个元素，从`51`更改为`50`。

有关交错数组的更多信息，请访问[`docs.microsoft.com/en-us/dotnet/csharp/programming-guide/arrays/jagged-arrays`](https://docs.microsoft.com/en-us/dotnet/csharp/programming-guide/arrays/jagged-arrays)。

# 示例-年度交通计划

在引入了交错数组之后，让我们继续举个例子。您将看到如何开发一个程序，为整年的交通制定一个计划。对于每个月的每一天，应用程序会绘制出一种可用的交通工具。最后，程序会呈现生成的计划，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dsal/img/e50a99c3-cd6f-42d8-bd1b-2a0d736a2b2b.png)

首先，让我们声明一个枚举类型，其中包含代表可用交通类型的常量，即汽车、公共汽车、地铁、自行车或步行，如下所示：

```cs
public enum TransportEnum 
{ 
    CAR, 
    BUS, 
    SUBWAY, 
    BIKE, 
    WALK 
} 
```

接下来，创建两个扩展方法，它们返回控制台中给定交通工具的表示的字符和颜色。代码如下所示：

```cs
public static class TransportEnumExtensions 
{ 
    public static char GetChar(this TransportEnum transport) 
    { 
        switch (transport) 
        { 
            case TransportEnum.BIKE: return 'B'; 
            case TransportEnum.BUS: return 'U'; 
            case TransportEnum.CAR: return 'C'; 
            case TransportEnum.SUBWAY: return 'S'; 
            case TransportEnum.WALK: return 'W'; 
            default: throw new Exception("Unknown transport"); 
        } 
    }

    public static ConsoleColor GetColor( 
        this TransportEnum transport) 
    { 
        switch (transport) 
        { 
            case TransportEnum.BIKE: return ConsoleColor.Blue; 
            case TransportEnum.BUS: return ConsoleColor.DarkGreen; 
            case TransportEnum.CAR: return ConsoleColor.Red; 
            case TransportEnum.SUBWAY:  
                return ConsoleColor.DarkMagenta; 
            case TransportEnum.WALK:  
                return ConsoleColor.DarkYellow; 
            default: throw new Exception("Unknown transport"); 
        } 
    } 
} 
```

前面的代码不需要额外的解释，因为它与本章中已经呈现的代码非常相似。现在让我们继续到`Program`类的`Main`方法中的代码，它将分部分显示和描述。

在第一部分中，创建了一个交错数组，并用适当的值填充。假设交错数组有 12 个元素，代表当前年份的月份。每个元素都是一个具有`TransportEnum`值的单维数组。这样的内部数组的长度取决于给定月份的天数。例如，对于一月，它设置为 31 个元素，对于四月，它设置为 30 个元素。代码如下所示：

```cs
Random random = new Random(); 
int transportTypesCount =  
    Enum.GetNames(typeof(TransportEnum)).Length; 
TransportEnum[][] transport = new TransportEnum[12][]; 
for (int month = 1; month <= 12; month++) 
{ 
    int daysCount = DateTime.DaysInMonth( 
        DateTime.Now.Year, month); 
    transport[month - 1] = new TransportEnum[daysCount]; 
    for (int day = 1; day <= daysCount; day++) 
    { 
        int randomType = random.Next(transportTypesCount); 
        transport[month - 1][day - 1] = (TransportEnum)randomType; 
    } 
} 
```

让我们分析前面的代码。首先，创建了`Random`类的一个新实例。稍后将用于从可用的交通工具中选择合适的交通工具。接下来，获取了`TransportEnum`枚举类型中的常量数量，即可用交通类型的数量。然后，创建了交错数组，并使用`for`循环来遍历一年中的所有月份。在每次迭代中，使用`DateTime`的`DaysInMonth`静态方法获取天数，并使用零初始化一个数组（作为交错数组的一个元素）。在下一行代码中，您可以看到下一个`for`循环，它遍历月份的所有天。在此循环中，您会绘制一种交通类型，并将其设置为交错数组的一个元素的适当值。

代码的下一部分与在控制台中呈现计划的过程有关：

```cs
string[] monthNames = GetMonthNames(); 
int monthNamesPart = monthNames.Max(n => n.Length) + 2; 
for (int month = 1; month <= transport.Length; month++) 
{ 
    Console.Write( 
        $"{monthNames[month - 1]}:".PadRight(monthNamesPart)); 
    for (int day = 1; day <= transport[month - 1].Length; day++) 
    { 
        Console.ForegroundColor = ConsoleColor.White; 
        Console.BackgroundColor =  
            transport[month - 1][day - 1].GetColor(); 
        Console.Write(transport[month - 1][day - 1].GetChar()); 
        Console.BackgroundColor = ConsoleColor.Black; 
        Console.ForegroundColor = ConsoleColor.Gray; 
        Console.Write(" "); 
    } 
    Console.WriteLine(); 
} 
```

首先，使用`GetMonthNames`方法创建一个包含月份名称的单维数组，稍后将对其进行描述。然后，将`monthNamesPart`变量的值设置为存储月份名称的文本的最大必要长度。为此，使用 LINQ 表达式来从月份名称集合中找到文本的最大长度。获得的结果增加 2，以保留冒号和空格的位置。

C#语言的一个伟大特性是其使用 LINQ 的能力。这样的机制使得不仅可以从各种集合中获取数据，还可以以一致的方式从**结构化查询语言**（**SQL**）数据库和**可扩展标记语言**（**XML**）文档中获取数据。您可以在[`docs.microsoft.com/dotnet/csharp/linq/index`](https://docs.microsoft.com/dotnet/csharp/linq/index)上阅读更多内容。

然后，使用`for`循环来遍历交错数组的所有元素，即遍历所有月份。在每次迭代中，在控制台中呈现月份的名称。然后，使用下一个`for`循环来遍历交错数组当前元素的所有元素，即遍历月份的所有天。对于每个元素，设置适当的颜色（用于背景和前景），并呈现适当的字符。

最后，让我们来看一下`GetMonthNames`方法的实现：

```cs
private static string[] GetMonthNames() 
{ 
    string[] names = new string[12]; 
    for (int month = 1; month <= 12; month++) 
    { 
        DateTime firstDay = new DateTime( 
            DateTime.Now.Year, month, 1); 
        string name = firstDay.ToString("MMMM",  
            CultureInfo.CreateSpecificCulture("en")); 
        names[month - 1] = name; 
    } 
    return names; 
} 
```

这段代码不需要额外的解释，因为它是基于已经在单维数组示例中描述的代码。

# 排序算法

有许多算法对数组执行各种操作。然而，最常见的任务之一是对数组进行排序，以便将其元素按正确的顺序排列，无论是升序还是降序。排序算法的主题涉及许多方法，包括选择排序、插入排序、冒泡排序和快速排序，这些将在本章的这一部分中详细解释。

# 选择排序

让我们从**选择排序**开始，这是最简单的排序算法之一。该算法将数组分为已排序和未排序两部分。在接下来的迭代中，算法找到未排序部分中的最小元素，并将其与未排序部分中的第一个元素交换。听起来很简单，不是吗？

为了更好地理解算法，让我们看一下具有九个元素的数组的以下迭代（**-11**，**12**，**-42**，**0**，**1**，**90**，**68**，**6**，**-9**）的情况，如下图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dsal/img/81e1a940-e7ad-41b1-bb26-870264d29f34.png)

为了简化分析，使用粗体线来表示数组的已排序和未排序部分之间的边界。在开始（*步骤 1*）时，边界位于数组顶部，这意味着已排序部分为空。因此，算法找到未排序部分中的最小值（**-42**）并将其与该部分中的第一个元素（**-11**）交换。结果显示在*步骤 2*中，其中已排序部分包含一个元素（**-42**），而未排序部分包含八个元素。上述步骤重复执行几次，直到未排序部分只剩下一个元素。最终结果显示在*步骤 9*中。

现在你知道了选择排序算法的工作原理，但在前面的图表中显示的步骤左侧的 `i` 和 `m` 指示器扮演了什么角色？它们与该算法的实现中使用的变量有关。因此，现在是时候看看 C# 语言中的代码了。

算法实现为 `SelectionSort` 静态类，具有 `Sort` 通用静态方法，如下代码片段所示：

```cs
public static class SelectionSort 
{ 
    public static void Sort<T>(T[] array) where T : IComparable 
    { 
        for (int i = 0; i < array.Length - 1; i++) 
        { 
            int minIndex = i; 
            T minValue = array[i]; 
            for (int j = i + 1; j < array.Length; j++) 
            { 
                if (array[j].CompareTo(minValue) < 0) 
                { 
                    minIndex = j; 
                    minValue = array[j]; 
                } 
            } 
            Swap(array, i, minIndex); 
        } 
    } (...) 
} 
```

`Sort` 方法接受一个参数，即应该排序的数组（`array`）。在方法内部，使用 `for` 循环来迭代元素，直到未排序部分只剩下一个项目。因此，循环的迭代次数等于数组长度减一（`array.Length-1`）。在每次迭代中，另一个 `for` 循环用于找到未排序部分中的最小值（`minValue`，从 `i+1` 索引到数组末尾），并存储最小值的索引（`minIndex`，在前面的图表中称为 `m` 指示器）。然后，未排序部分中的最小元素（索引为 `minIndex`）与未排序部分中的第一个元素（索引为 `i`）进行交换，使用 `Swap` 辅助方法，其实现如下：

```cs
private static void Swap<T>(T[] array, int first, int second) 
{ 
    T temp = array[first]; 
    array[first] = array[second]; 
    array[second] = temp; 
} 
```

如果你想测试选择排序算法的实现，可以将以下代码放入 `Program` 类的 `Main` 方法中：

```cs
int[] integerValues = { -11, 12, -42, 0, 1, 90, 68, 6, -9 }; 
SelectionSort.Sort(integerValues); 
Console.WriteLine(string.Join(" | ", integerValues)); 
```

在前面的代码中，声明并初始化了一个新数组。然后调用 `Sort` 静态方法，传递数组作为参数。最后，通过连接数组元素（以 `|` 字符分隔）创建了一个 `string` 值，并在控制台中显示，如下所示：

```cs
    -42 | -11 | -9 | 0 | 1 | 6 | 12 | 68 | 90
```

通过使用通用方法，你可以轻松地使用创建的类来对各种数组进行排序，例如浮点数或字符串。示例代码如下：

```cs
string[] stringValues = { "Mary", "Marcin", "Ann", "James",  
    "George", "Nicole" }; 
SelectionSort.Sort(stringValues); 
Console.WriteLine(string.Join(" | ", stringValues)); 
```

因此，你将收到以下输出：

```cs
    Ann | George | James | Marcin | Mary | Nicole
```

在讨论各种算法时，最重要的话题之一是**计算复杂性**，特别是**时间复杂性**。它有一些变体，例如最坏或平均情况。复杂性可以解释为算法在输入大小（*n*）上需要执行的基本操作数量。时间复杂性可以使用**大 O 表示法**来指定，例如*O(n)*、*O(n²)*或*O(n log(n))*。但是，这是什么意思呢？*O(n)*表示操作数量与输入大小（*n*）呈线性增长。*O(n²)*变体称为**二次**，而*O(n log(n))*称为**线性对数**。还有其他变体，例如*O(1)*，它是**常数**。

在选择排序的情况下，最坏和平均时间复杂度都是*O(n²)*。为什么？让我们看一下代码来回答这个问题。有两个循环（一个在另一个内部），每个循环都遍历数组的许多元素。因此，复杂性被表示为*O(n²)*。

有关选择排序及其实现的更多信息可以在以下网址找到：

+   [`en.wikipedia.org/wiki/Selection_sort`](https://en.wikipedia.org/wiki/Selection_sort)

+   [`en.wikibooks.org/wiki/Algorithm_Implementation/Sorting/Selection_sort`](https://en.wikibooks.org/wiki/Algorithm_Implementation/Sorting/Selection_sort)

您刚刚了解了第一个排序算法！如果您对下一个排序方法感兴趣，请继续阅读下一节，介绍插入排序。

# 插入排序

**插入排序**是另一种算法，可以简单地对单维数组进行排序，如下图所示。与选择排序类似，数组被分为两部分，即排序和未排序。但是，一开始，第一个元素包括在排序部分中。在每次迭代中，算法从未排序部分中取出第一个元素，并将其放在排序部分的适当位置，以使排序部分保持正确的顺序。这样的操作重复，直到未排序部分为空。

让我们看一个使用插入排序对包含九个元素（**-11**、**12**、**-42**、**0**、**1**、**90**、**68**、**6**、**-9**）的数组进行排序的例子，如下图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dsal/img/0fa22285-42f2-4cdb-a20b-e5d9907d95e6.png)

一开始，排序部分中只有一个元素（**-11**）（*步骤 1*）。然后，在未排序部分中找到最小的元素（**-42**），并将其移动到排序部分的正确位置，即数组的开头，执行一系列交换操作（*步骤 2*和*3*）。因此，排序部分的长度增加到两个元素，即**-42**和**-11**。这样的操作重复，直到未排序部分为空（*步骤 22*）。

插入排序的实现代码非常简单：

```cs
public static class InsertionSort 
{ 
    public static void Sort<T>(T[] array) where T : IComparable 
    { 
        for (int i = 1; i < array.Length; i++) 
        { 
            int j = i; 
            while (j > 0 && array[j].CompareTo(array[j - 1]) < 0) 
            { 
                Swap(array, j, j - 1); 
                j--; 
            } 
        } 
    } (...) 
} 
```

与选择排序类似，实现是在一个新类中提供的，即`InsertionSort`。静态泛型`Sort`方法执行有关排序的操作，并将数组作为参数。在这个方法中，使用`for`循环来迭代未排序部分中的所有元素。因此，`i`变量的初始值设置为`1`，而不是`0`。在`for`循环的每次迭代中，执行`while`循环，将数组的未排序部分中的第一个元素（索引等于`i`变量的值）移动到排序部分的正确位置，使用与选择排序中所示的相同实现的`Swap`辅助方法。测试插入排序的方式也非常相似，但应该使用另一个类名，即`InsertionSort`而不是`SelectionSort`。

有关插入排序及其实现的更多信息可以在以下网址找到：

+   [`en.wikipedia.org/wiki/Insertion_sort`](https://en.wikipedia.org/wiki/Insertion_sort)

+   [`en.wikibooks.org/wiki/Algorithm_Implementation/Sorting/Insertion_sort`](https://en.wikibooks.org/wiki/Algorithm_Implementation/Sorting/Insertion_sort)

最后，值得一提的是插入排序的时间复杂度。与选择排序类似，最坏和平均时间复杂度均为*O(n²)*。如果你看一下代码，你还会看到两个循环（`for`和`while`）嵌套在一起，这取决于输入大小，可能会迭代多次。

# 冒泡排序

书中介绍的第三种排序算法是**冒泡排序**。它的操作方式非常简单，因为算法只是遍历数组并比较相邻元素。如果它们的位置不正确，就交换它们。听起来很简单，但这个算法并不是很高效，使用大型集合可能会导致性能问题。

为了更好地理解算法的工作原理，让我们看一下以下图表，展示了算法在对一个包含九个元素（**-11**，**12**，**-42**，**0**，**1**，**90**，**68**，**6**，**-9**）的单维数组进行排序时的操作：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dsal/img/2a67b8b0-b786-4aa5-8744-a1dd41b7bdf8.png)

正如你所看到的，在每一步中，算法比较数组中的两个相邻元素并在必要时交换它们。例如，在*步骤 1*中，比较了**-11**和**12**，但它们已经按正确顺序排列，因此不需要交换这些元素。在*步骤 2*中，比较了下一个相邻元素（即**12**和**-42**）。这次，这些元素没有按正确顺序排列，因此它们被交换了。上述操作被执行了多次。最后，数组将被排序，如*步骤 72*所示。

这个算法看起来很简单，但实现呢？它也是如此简单吗？幸运的是，是的！你只需要使用两个循环，比较相邻元素，并在必要时交换它们。就是这样！让我们看一下以下代码片段：

```cs
public static class BubbleSort 
{ 
    public static void Sort<T>(T[] array) where T : IComparable 
    { 
        for (int i = 0; i < array.Length; i++) 
        { 
            for (int j = 0; j < array.Length - 1; j++) 
            { 
                if (array[j].CompareTo(array[j + 1]) > 0) 
                { 
                    Swap(array, j, j + 1); 
                } 
            } 
        } 
    } (...) 
} 
```

`BubbleSort`类中声明的`Sort`静态泛型方法包含了冒泡排序算法的实现。如前所述，使用了两个`for`循环，以及一个比较和调用`Swap`方法（与先前描述的排序算法的情况相同）。此外，你可以使用类似的代码来测试实现，但不要忘记将类的名称替换为`BubbleSort`。

还可以通过在实现中引入简单的修改来使用冒泡排序算法的更优化版本。这是基于这样的假设：当在数组的一次迭代中未发现任何更改时，比较应该停止。修改后的代码如下：

```cs
public static T[] Sort<T>(T[] array) where T : IComparable 
{ 
    for (int i = 0; i < array.Length; i++) 
    { 
        bool isAnyChange = false; 
        for (int j = 0; j < array.Length - 1; j++) 
        { 
            if (array[j].CompareTo(array[j + 1]) > 0) 
            { 
                isAnyChange = true; 
                Swap(array, j, j + 1); 
            } 
        } 

        if (!isAnyChange) 
        { 
            break; 
        } 
    } 
    return array; 
} 
```

通过引入这样一个简单的修改，比较的次数可以显著减少。在前面的例子中，它从 72 步减少到 56 步。

有关冒泡排序及其实现的更多信息可以在以下网址找到：

+   [`en.wikipedia.org/wiki/Bubble_sort`](https://en.wikipedia.org/wiki/Bubble_sort)

+   [`en.wikibooks.org/wiki/Algorithm_Implementation/Sorting/Bubble_sort`](https://en.wikibooks.org/wiki/Algorithm_Implementation/Sorting/Bubble_sort)

在转向下一个排序算法之前，值得一提的是冒泡排序的时间复杂度。你可能已经猜到，最坏和平均情况都与选择和插入排序相同，即*O(n²)*。

# 快速排序

本书中描述的最后一个排序算法名为**快速排序**。它是一种流行的**分而治之算法**之一，将问题分解为一组较小的问题。此外，这种算法为开发人员提供了一种有效的排序方式。这是否意味着它的思想和实现非常复杂？幸运的是，不是！您将在本节中了解算法的工作原理，以及它的实现代码是什么样子的。让我们开始吧！

算法是如何工作的？首先，它选择某个值（例如来自数组的第一个或中间元素）作为**枢轴**。然后，它重新排列数组，使得小于或等于枢轴的值放在它之前（形成较低的子数组），而大于枢轴的值放在它之后（较高的子数组）。这个过程称为**分区**。本书中使用**霍尔分区方案**。接下来，算法递归地对上述每个子数组进行排序。当然，每个子数组进一步分成下一个两个子数组，依此类推。当子数组中有一个或零个元素时，递归调用停止，因为在这种情况下没有需要排序的内容。

前面的描述可能听起来有点复杂，所以让我们看一个例子：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dsal/img/16a55dc5-bea8-4a05-9b5a-93482f5e6c3b.png)

示例展示了快速排序算法如何对一个具有九个元素的一维数组（**-11**, **12**, **-42**, **0**, **1**, **90**, **68**, **6**, **-9**）进行排序。在这种情况下，假设枢轴被选择为当前正在排序的子数组的第一个元素的值。在*步骤 1*中，值**-11**被选择为枢轴。然后，需要重新排列数组。因此，**-11**与**-42**交换，**12**与**-11**交换，以确保只有小于或等于枢轴的值（**-42**, **-11**）在较低的子数组中，而大于枢轴的值（**12**, **0**, **1**, **90**, **68**, **6**, **-9**）放在较高的子数组中。然后，对上述两个子数组，即(**-42**, **11**)和(**12**, **0**, **1**, **90**, **68**, **6**, **-9**)递归调用算法，因此它们以与输入数组相同的方式进行分析。

例如，*步骤 5*显示值**12**被选择为枢轴。分区后，子数组分为两个其他子数组，即(**-9**, **0**, **1**, **6**, **12**)和(**68**, **90**)。对于这两个子数组，选择其他的枢轴元素，即**-9**和**68**。对数组的所有剩余部分执行这样的操作后，你将得到最终结果，如图中右侧所示(*步骤 15*)。

值得一提的是，在该算法的其他实现中，枢轴可以以不同的方式选择。例如，让我们看看在选择数组的中间元素的值时，以下步骤将如何改变：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dsal/img/34991257-e59f-4dbc-868d-2422d64a303b.png)

如果你理解算法的工作原理，让我们继续实现。这比之前展示的例子更复杂，它使用**递归**来调用子数组的排序方法。代码放在`QuickSort`类中：

```cs
public static class QuickSort 
{ 
    public static void Sort<T>(T[] array) where T : IComparable 
    { 
        Sort(array, 0, array.Length - 1); 
    } (...) 
} 
```

`QuickSort`类包含`Sort`方法的两个变体。第一个只接受一个参数，即应该排序的数组，并且在前面的代码片段中显示。它只调用`Sort`方法的另一个变体，这使得可以指定指示应该排序数组的哪一部分的下限和上限索引。`Sort`方法的另一个版本在这里显示：

```cs
private static T[] Sort<T>(T[] array, int lower, int upper)  
    where T : IComparable 
{ 
    if (lower < upper) 
    { 
        int p = Partition(array, lower, upper); 
        Sort(array, lower, p); 
        Sort(array, p + 1, upper); 
    } 
    return array; 
}
```

`Sort`方法通过比较`lower`和`upper`变量的值来检查数组（或子数组）是否至少有两个元素。在这种情况下，它调用`Partition`方法，该方法负责分区阶段，然后递归调用`Sort`方法以获得两个子数组，即较低（从`lower`到`p`的索引）和较高（从`p+1`到`upper`的索引）。

有关分区的代码显示在这里：

```cs
private static int Partition<T>(T[] array, int lower, int upper)  
    where T : IComparable 
{ 
    int i = lower; 
    int j = upper; 
    T pivot = array[lower]; 
    // or: T pivot = array[(lower + upper) / 2]; 
    do 
    { 
        while (array[i].CompareTo(pivot) < 0) { i++; } 
        while (array[j].CompareTo(pivot) > 0) { j--; } 
        if (i >= j) { break; } 
        Swap(array, i, j); 
    } 
    while (i <= j); 
    return j; 
} 
```

首先，选择枢轴值并将其存储为`pivot`变量的值。如前面的代码片段所示，可以以各种方式选择它，例如取第一个元素的值（如前面的代码片段所示），取中间元素的值（如前面的代码中的注释所示），甚至取随机值。然后，使用`do-while`循环根据 Hoare 分区方案重新排列数组，使用比较并交换元素。最后，返回`j`变量的当前值。

所呈现的实现是基于 Hoare 分区方案的，其伪代码和解释在[`en.wikipedia.org/wiki/Quicksort`](https://en.wikipedia.org/wiki/Quicksort)中呈现。有各种可能的实现快速排序的方式。您可以在[`en.wikibooks.org/wiki/Algorithm_Implementation/Sorting/Quicksort`](https://en.wikibooks.org/wiki/Algorithm_Implementation/Sorting/Quicksort)中找到更多信息。

时间复杂度呢？您认为它与选择、插入和冒泡排序相比有所不同吗？如果是这样，你是对的！它的平均时间复杂度为*O(n log(n))*，尽管最坏时间复杂度为*O(n²)*。

# 简单列表

数组真的是非常有用的数据结构，它们应用于许多算法中。然而，在某些情况下，由于其性质，它们的应用可能会变得复杂，这不允许增加或减少已创建数组的长度。如果您不知道要存储在集合中的元素的总数，该怎么办？您需要创建一个非常大的数组，然后只是不使用不必要的元素吗？这样的解决方案听起来不好，对吧？一个更好的方法是使用数据结构，如果有必要，可以动态增加集合的大小。

# 数组列表

满足此要求的第一个数据结构是**数组列表**，它由`System.Collections`命名空间中的`ArrayList`类表示。您可以使用此类存储大量数据，必要时可以轻松添加新元素。当然，您也可以删除它们，计算项目数，并找到存储在数组列表中的特定值的索引。

你怎么做到的？让我们看看以下代码：

```cs
ArrayList arrayList = new ArrayList(); 
arrayList.Add(5); 
arrayList.AddRange(new int[] { 6, -7, 8 }); 
arrayList.AddRange(new object[] { "Marcin", "Mary" }); 
arrayList.Insert(5, 7.8); 
```

在第一行中，创建了`ArrayList`类的一个新实例。然后，您可以使用`Add`，`AddRange`和`Insert`方法向数组列表添加新元素。第一个（即`Add`）允许您在列表末尾添加新项目。`AddRange`方法在数组列表末尾添加一系列元素，而`Insert`可以用于将元素放置在集合中的指定位置。当执行前面的代码时，数组列表将包含以下元素：`5`，`6`，`-7`，`8`，`"Marcin"`，`7.8`和`"Mary"`。正如您所看到的，数组列表中存储的所有项目都是`object`类型。因此，您可以同时在同一集合中放置各种类型的数据。

如果要指定列表中存储的每个元素的类型，可以使用泛型`List`类，该类在`ArrayList`之后描述。

值得一提的是，您可以使用索引轻松访问数组列表中的特定元素，如下面两行代码所示：

```cs
object first = arrayList[0]; 
int third  = (int)arrayList[2]; 
```

让我们看看第二行中的`int`转换。这种转换是必要的，因为数组列表存储`object`值。与数组的情况一样，在访问集合中的特定元素时使用基于零的索引。

当然，您可以使用`foreach`循环来遍历所有项目，如下所示：

```cs
foreach (object element in arrayList) 
{ 
    Console.WriteLine(element); 
} 
```

这还不是全部！`ArrayList`类有一组属性和方法，您可以在开发应用程序时使用这些属性和方法利用上述数据结构。首先，让我们看一下`Count`和`Capacity`属性：

```cs
int count = arrayList.Count; 
int capacity = arrayList.Capacity; 
```

第一个(`Count`)返回存储在数组列表中的元素数量，而另一个(`Capacity`)指示可以存储多少元素。如果在向数组列表添加新元素后检查`Capacity`属性的值，您将看到该值会自动增加以准备新项目的位置。这在下图中显示了`Count`（作为**A**）和`Capacity`（**B**）之间的差异：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dsal/img/a89f3497-53bd-4728-a403-765f66143602.png)

下一个常见且重要的任务是检查数组列表是否包含具有特定值的元素。您可以通过调用`Contains`方法来执行此操作，如下面的代码行所示：

```cs
bool containsMary = arrayList.Contains("Mary"); 
```

如果在数组列表中找到指定的值，则返回`true`值。否则，返回`false`。使用此方法，您可以检查元素是否存在于集合中。但是，如何找到此元素的索引？为此，您可以使用`IndexOf`或`LastIndexOf`方法，如下面的代码行所示：

```cs
int minusIndex = arrayList.IndexOf(-7); 
```

`IndexOf`方法返回数组列表中元素的第一次出现的索引，而`LastIndexOf`返回最后一次出现的索引。如果未找到值，则该方法返回`-1`。

除了向数组列表添加一些项目之外，您还可以轻松地删除添加的元素，如下面的代码所示：

```cs
arrayList.Remove(5); 
```

要从数组列表中删除项目，可以使用多种方法，即`Remove`，`RemoveAt`和`RemoveRange`。第一个(`Remove`)删除作为参数提供的值的第一次出现。`RemoveAt`方法删除具有与作为参数传递的值相等的索引的项目，而另一个(`RemoveRange`)使您可以从提供的索引开始删除指定数量的元素。而且，如果要删除所有元素，可以使用`Clear`方法。

在其他方法中，值得一提的是`Reverse`，它可以颠倒数组列表中元素的顺序，以及`ToArray`，它返回存储在`ArrayList`实例中的所有项目的数组。

有关`ArrayList`类的更多信息可在[`msdn.microsoft.com/library/system.collections.arraylist.aspx`](https://msdn.microsoft.com/library/system.collections.arraylist.aspx)找到。

# 通用列表

正如您所看到的，`ArrayList`类包含广泛的功能，但它有一个重大缺点——它不是强类型列表。如果要从强类型列表中受益，可以使用泛型`List`类，该类表示集合，其大小可以根据需要增加或减少。

泛型`List`类包含许多在存储数据时开发应用程序时非常有用的属性和方法。您将看到许多成员的名称与`ArrayList`类完全相同，例如`Count`和`Capacity`属性，以及`Add`，`AddRange`，`Clear`，`Contains`，`IndexOf`，`Insert`，`InsertRange`，`LastIndexOf`，`Remove`，`RemoveAt`，`RemoveRange`，`Reverse`和`ToArray`方法。您还可以使用索引和`[]`运算符从列表中获取特定元素。

除了已经描述的功能之外，您还可以使用`System.Linq`命名空间中的全面扩展方法集，例如查找最小值或最大值（`Min`或`Max`），计算平均值（`Average`），按升序或降序排序（`OrderBy`或`OrderByDescending`），以及检查列表中的所有元素是否满足条件（`All`）。当然，这些并不是在使用 C#语言中的通用列表创建应用程序时开发人员可用的唯一功能。

有关通用`List`类的更多信息，请访问[`msdn.microsoft.com/library/6sh2ey19.aspx`](https://msdn.microsoft.com/library/6sh2ey19.aspx)。

让我们来看两个示例，展示如何在实践中使用通用列表。

# 示例-平均值

第一个示例利用通用`List`类存储用户输入的浮点值（`double`类型）。输入数字后，将计算平均值并在控制台中呈现。当用户输入不正确的值时，程序停止操作。

`Program`类中`Main`方法中的代码如下：

```cs
List<double> numbers = new List<double>(); 
do 
{ 
    Console.Write("Enter the number: "); 
    string numberString = Console.ReadLine(); 
    if (!double.TryParse(numberString, NumberStyles.Float,  
        new NumberFormatInfo(), out double number)) 
    { 
        break; 
    } 

    numbers.Add(number); 
    Console.WriteLine($"The average value: {numbers.Average()}"); 
} 
while (true); 
```

首先创建`List`类的一个实例。然后，在无限循环（`do-while`）中，程序等待用户输入数字。如果正确，输入的值将被添加到列表中（通过调用`Add`方法），并计算列表元素的平均值（通过调用`Average`方法）并显示在控制台中。

因此，您可能会收到类似以下的输出：

```cs
    Enter the number: 10.5
    The average value: 10.5 (...)
    Enter the number: 1.5
    The average value: 4.875
```

在当前示例中，您已经看到了如何使用存储`double`值的列表。但是，它也可以存储用户定义类的实例吗？当然可以！您将在下一个示例中看到如何实现这一目标。

# 示例-人员列表

关于`List`类的第二个示例展示了如何使用这个数据结构来创建一个非常简单的人员数据库。为每个人存储姓名、国家和年龄。启动程序时，将一些人的数据添加到列表中。然后，使用 LINQ 表达式对数据进行排序，并在控制台中呈现。

让我们从`Person`类的声明开始，如下面的代码所示：

```cs
public class Person 
{ 
    public string Name { get; set; } 
    public int Age { get; set; } 
    public CountryEnum Country { get; set; } 
} 
```

该类包含三个公共属性，即`Name`、`Age`和`Country`。值得注意的是，`Country`属性是`CountryEnum`类型，它定义了三个常量，即`PL`（波兰）、`UK`（英国）和`DE`（德国），如下面的代码所示：

```cs
public enum CountryEnum 
{ 
    PL, 
    UK, 
    DE 
} 
```

代码的以下部分应该添加在`Program`类中`Main`方法中。它创建`List`类的一个新实例，并添加一些人的数据，这些人具有不同的姓名、国家和年龄，如下所示：

```cs
List<Person> people = new List<Person>(); 
people.Add(new Person() { Name = "Marcin",  
    Country = CountryEnum.PL, Age = 29 });
people.Add(new Person() { Name = "Sabine",
    Country = CountryEnum.DE, Age = 25 }); (...) 
people.Add(new Person() { Name = "Ann",  
    Country = CountryEnum.PL, Age = 31 }); 
```

在下一行中，使用 LINQ 表达式按人名升序对列表进行排序，并将结果转换为列表：

```cs
List<Person> results = people.OrderBy(p => p.Name).ToList();
```

然后，您可以使用`foreach`循环轻松遍历所有结果：

```cs
foreach (Person person in results) 
{ 
    Console.WriteLine($"{person.Name} ({person.Age} years)  
        from {person.Country}."); 
} 
```

运行程序后，呈现以下结果：

```cs
    Marcin (29 years) from PL. (...)
    Sabine (25 years) from DE.

```

就是这样！现在让我们再多谈一些 LINQ 表达式，它不仅可以用于对元素进行排序，还可以根据提供的条件执行筛选，并且更多。

例如，让我们来看一下使用**方法语法**的以下查询：

```cs
List<string> names = people.Where(p => p.Age <= 30) 
    .OrderBy(p => p.Name) 
    .Select(p => p.Name) 
    .ToList();
```

它选择所有年龄低于或等于`30`岁的人的姓名（`Select`子句）（`Where`子句），按姓名排序（`OrderBy`子句）。然后执行查询，并将结果作为列表返回。

可以使用**查询语法**完成相同的任务，如下例所示，结合调用`ToList`方法：

```cs
List<string> names = (from p in people 
                      where p.Age <= 30 
                      orderby p.Name 
                      select p.Name).ToList(); 
```

在本章的这一部分，您已经了解了如何使用`ArrayList`类和泛型`List`类来存储可以动态调整大小的集合中的数据。但这并不是本章中与列表相关主题的结束。您准备好了解另一个数据结构了吗？它可以保持元素的排序顺序。如果是这样，让我们继续到下一节，重点介绍排序列表。

# 排序列表

在本章中，您已经学会了如何使用数组和列表存储数据。但是，您知道您甚至可以使用一种确保元素排序的数据结构吗？如果不知道，让我们来了解一下`SortedList`泛型类（来自`System.Collections.Generic`命名空间），它是一个按键排序的**键值对**集合，无需自行排序。值得一提的是，所有键必须是唯一的，且不能等于`null`。

您可以使用`Add`方法轻松地向集合中添加元素，并使用`Remove`方法删除指定的项目。值得注意的是，除了其他方法之外，还有`ContainsKey`和`ContainsValue`用于检查集合是否包含具有给定键或值的项目，以及`IndexOfKey`和`IndexOfValue`用于返回集合中给定键或值的索引。由于排序列表存储键值对，因此您还可以访问`Keys`和`Values`属性。可以使用索引和`[]`运算符轻松获取特定的键和值。

有关`SortedList`泛型类的更多信息，请访问[`msdn.microsoft.com/library/ms132319.aspx`](https://msdn.microsoft.com/library/ms132319.aspx)。

在这个简短的介绍之后，让我们看一个示例，它将向您展示如何使用这种数据结构，并且还将指出与先前描述的`List`类相比的代码中的一些重要差异。

# 示例 - 通讯录

这个示例使用`SortedList`类创建了一个非常简单的按人名排序的通讯录。对于每个人，存储了以下数据：`Name`，`Age`和`Country`。`Person`类的声明如下所示：

```cs
public class Person 
{ 
    public string Name { get; set; } 
    public int Age { get; set; } 
    public CountryEnum Country { get; set; } 
}
```

`Country`属性的值可以设置为`CountryEnum`中的常量之一：

```cs
public enum CountryEnum 
{ 
    PL, 
    UK, 
    DE 
} 
```

代码中最有趣的部分放在`Program`类中的`Main`方法中。在这里，创建了`SortedList`泛型类的新实例，为键和值指定了类型，即`string`和`Person`，如下所示：

```cs
SortedList<string, Person> people =  
    new SortedList<string, Person>(); 
```

然后，您可以通过调用`Add`方法轻松地向排序列表中添加数据，传递两个参数，即键（即名称）和值（即`Person`类的实例），如下面的代码片段所示：

```cs
people.Add("Marcin", new Person() { Name = "Marcin",  
    Country = CountryEnum.PL, Age = 29 });
people.Add("Sabine", new Person() { Name = "Sabine", 
    Country = CountryEnum.DE, Age = 25 }); (...) 
people.Add("Ann", new Person() { Name = "Ann",  
    Country = CountryEnum.PL, Age = 31 }); 
```

当所有数据都存储在集合中时，您可以轻松地使用`foreach`循环迭代其元素（键值对）。值得一提的是，循环中使用的变量类型是`KeyValuePair<string, Person>`。因此，您需要使用`Key`和`Value`属性分别访问键和值，如下所示：

```cs
foreach (KeyValuePair<string, Person> person in people) 
{ 
    Console.WriteLine($"{person.Value.Name} ({person.Value.Age}  
        years) from {person.Value.Country}."); 
} 
```

程序启动后，您将在控制台中收到以下结果：

```cs
    Ann (31 years) from PL. (...)
    Marcin (29 years) from PL. (...)
    Sabine (25 years) from DE.
```

如您所见，集合会根据名称自动排序，这些名称被用作排序列表的键。但是，您需要记住键必须是唯一的，因此在这个示例中不能添加多个具有相同名称的人。

# 链表

在使用`List`泛型类时，您可以轻松地使用索引访问集合的特定元素。但是，当您获取单个元素时，如何移动到集合的下一个元素呢？这可能吗？为此，您可以考虑使用`IndexOf`方法来获取元素的索引。不幸的是，它返回给定值在集合中的第一次出现的索引，因此在这种情况下它不总是按预期工作。

如果有一种*指针*指向下一个元素将会很好，如下图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dsal/img/bbd7ff01-046f-41d1-99b1-1ae4c7116212.png)

通过这种方法，您可以轻松地使用`Next`属性从一个元素导航到下一个元素。这样的结构被称为**单向链表**。但是，通过添加`Previous`属性，可以进一步扩展它以允许向前和向后导航吗？当然可以！这样的数据结构被称为**双向链表**，并在下图中显示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dsal/img/b3e08b82-fb00-4983-b030-17f397830457.png)

正如您所看到的，双向链表包含`First`属性，指示列表中的第一个元素。每个项目都有两个属性，指向前一个和后一个元素（分别为`Previous`和`Next`）。如果没有前一个元素，则`Previous`属性等于`null`。同样，当没有下一个元素时，`Next`属性设置为`null`。此外，双向链表包含`Last`属性，指示最后一个元素。当列表中没有项目时，`First`和`Last`属性都设置为`null`。

但是，如果您想在基于 C#的应用程序中使用它，是否需要自己实现这样的数据结构？幸运的是，不需要，因为它作为`System.Collections.Generic`命名空间中的`LinkedList`泛型类可用。

在创建类的实例时，您需要指定类型参数，指示列表中单个元素的类型，例如`int`或`string`。但是，单个节点的类型不仅仅是`int`或`string`，因为在这种情况下，您将无法访问与双向链表相关的任何其他属性，例如`Previous`或`Next`。为了解决这个问题，每个节点都是`LinkedListNode`泛型类的实例，例如`LinkedListNode<int>`或`LinkedListNode<string>`。

对于向双向链表添加新节点的方法需要一些额外的解释。为此，您可以使用一组方法，即：

+   `AddFirst`：用于在列表的开头添加元素

+   `AddLast`：用于在列表的末尾添加元素

+   `AddBefore`：用于在列表中指定节点之前添加元素

+   `AddAfter`：用于在列表中指定节点之后添加元素

所有这些方法都返回`LinkedListNode`类的实例。此外，还有其他方法，例如`Contains`用于检查列表中是否存在指定的值，`Clear`用于从列表中删除所有元素，`Remove`用于从列表中删除节点。

有关`LinkedList`泛型类的更多信息，请访问[`msdn.microsoft.com/library/he2s3bh7.aspx`](https://msdn.microsoft.com/library/he2s3bh7.aspx)。

在这个简短的介绍之后，您应该准备好查看一个示例，展示如何在实践中应用双向链表，实现为`LinkedList`类。

# 示例 - 书籍阅读器

例如，您将准备一个简单的应用程序，允许用户通过更改页面来阅读书籍。按下*N*键后，应能够转到下一页（如果存在），按下*P*键后，应能够返回到上一页（如果存在）。当前页面的内容以及页码应该显示在控制台中，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dsal/img/6b53b23c-4fd4-4102-a08f-8ba0a5a9ff04.png)

让我们从`Page`类的声明开始，如下面的代码所示：

```cs
public class Page 
{ 
    public string Content { get; set; } 
} 
```

这个类表示一个单独的页面，包含`Content`属性。您应该在`Program`类的`Main`方法中创建`Page`类的几个实例，表示书的六页，如下面的代码片段所示：

```cs
Page pageFirst = new Page() { Content = "Nowadays (...)" }; 
Page pageSecond = new Page() { Content = "Application (...)" }; 
Page pageThird = new Page() { Content = "A lot of (...)" }; 
Page pageFourth = new Page() { Content = "Do you know (...)" }; 
Page pageFifth = new Page() { Content = "While (...)" }; 
Page pageSixth = new Page() { Content = "Could you (...)" }; 
```

创建实例后，让我们继续使用一些与添加相关的方法来构建链表，如下面的代码行所示：

```cs
LinkedList<Page> pages = new LinkedList<Page>(); 
pages.AddLast(pageSecond); 
LinkedListNode<Page> nodePageFourth = pages.AddLast(pageFourth); 
pages.AddLast(pageSixth); 
pages.AddFirst(pageFirst); 
pages.AddBefore(nodePageFourth, pageThird); 
pages.AddAfter(nodePageFourth, pageFifth); 
```

第一行创建了一个新列表。 然后执行以下操作：

+   将第二页的数据添加到列表的末尾（`[2]`）

+   在列表的末尾添加第四页的数据（`[2, 4]`）

+   在列表的末尾添加第六页的数据（`[2, 4, 6]`）

+   在列表的开头添加第一页的数据（`[1, 2, 4, 6]`）

+   在第四页的节点之前添加第三页的数据（`[1, 2, 3, 4, 6]`）

+   在第四页的节点后添加第五页的数据（`[1, 2, 3, 4, 5, 6]`）

代码的下一部分负责在控制台中呈现页面，以及在按下适当的键后在页面之间导航。 代码如下：

```cs
LinkedListNode<Page> current = pages.First; 
int number = 1; 
while (current != null) 
{ 
    Console.Clear(); 
    string numberString = $"- {number} -"; 
    int leadingSpaces = (90 - numberString.Length) / 2; 
    Console.WriteLine(numberString.PadLeft(leadingSpaces  
        + numberString.Length)); 
    Console.WriteLine(); 

    string content = current.Value.Content; 
    for (int i = 0; i < content.Length; i += 90) 
    { 
        string line = content.Substring(i); 
        line = line.Length > 90 ? line.Substring(0, 90) : line; 
        Console.WriteLine(line); 
    } 

    Console.WriteLine(); 
    Console.WriteLine($"Quote from "Windows Application  
        Development Cookbook" by Marcin  
        Jamro,{Environment.NewLine}published by Packt Publishing  
        in 2016."); 

    Console.WriteLine(); 
    Console.Write(current.Previous != null  
        ? "< PREVIOUS [P]" : GetSpaces(14)); 
    Console.Write(current.Next != null  
        ? "[N] NEXT >".PadLeft(76) : string.Empty); 
    Console.WriteLine(); 

    switch (Console.ReadKey(true).Key) 
    { 
        case ConsoleKey.N: 
            if (current.Next != null) 
            { 
                current = current.Next; 
                number++; 
            } 
            break; 
        case ConsoleKey.P: 
            if (current.Previous != null) 
            { 
                current = current.Previous; 
                number--; 
            } 
            break; 
        default: 
            return; 
    } 
} 
```

这部分代码可能需要一些解释。 在第一行，将`current`变量的值设置为链表中的第一个节点。 一般来说，`current`变量表示当前在控制台中呈现的页面。 然后，将页面编号的初始值设置为`1`（`number`变量）。 但是，代码中最有趣和复杂的部分在`while`循环中显示。

在循环中，清除控制台的当前内容，并正确格式化用于显示页面编号的字符串。 在其前后添加`-`字符。 此外，插入前导空格（使用`PadLeft`方法）以准备水平居中的字符串。

然后，将页面的内容分成不超过 90 个字符的行，并写入控制台。 为了分割字符串，使用了`Substring`方法和`Length`属性。 类似地，控制台中呈现了有关另一本书的引用的其他信息。 值得一提的是，`Environment.NewLine`属性会在字符串的指定位置插入换行符。 然后，如果上一页或下一页可用，则显示`PREVIOUS`和`NEXT`标题。

在代码的下一部分中，程序会等待用户按下任意键，然后不在控制台中呈现它（通过将`true`值作为参数传递）。 当用户按下*N*键时，使用`Next`属性将`current`变量设置为下一个节点。 当下一页不可用时，当然不应执行此操作。 类似地，处理*P*键，这会导致用户导航到上一页。 值得一提的是，页面的编号（`number`变量）会随着`current`变量的值的改变而修改。

最后，显示了辅助`GetSpaces`方法的代码：

```cs
private static string GetSpaces(int number) 
{ 
    string result = string.Empty; 
    for (int i = 0; i < number; i++) 
    { 
        result += " "; 
    } 
    return result; 
} 
```

这只是准备并返回具有指定空格数的`string`变量。

# 循环链表

在上一部分，您已经了解了双向链表。 正如您所看到的，这种数据结构的实现允许使用`Previous`和`Next`属性在节点之间导航。 但是，第一个节点的`Previous`属性设置为`null`，最后一个节点的`Next`属性也是如此。 您知道您可以轻松扩展此方法以创建**循环链表**吗？

这样的数据结构在下图中呈现：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dsal/img/7329d090-98aa-4bc7-a60e-442040f75443.png)

在第一个节点的`Previous`属性导航到最后一个节点，而最后一个节点的`Next`属性导航到第一个节点。 在某些特定情况下，这种数据结构可能会很有用，就像您在开发真实世界示例时所看到的那样。

值得一提的是，节点之间导航的方式不需要实现为属性。 它也可以用方法替换，正如您将在以下部分的示例中看到的。

# 实施

在对循环链表主题进行简短介绍之后，是时候看一下实现代码了。 让我们从以下代码片段开始：

```cs
public class CircularLinkedList<T> : LinkedList<T> 
{ 
    public new IEnumerator GetEnumerator() 
    { 
        return new CircularLinkedListEnumerator<T>(this); 
    } 
} 
```

循环链表的实现可以创建为一个扩展`LinkedList`的通用类，如前面的代码所示。值得一提的是`GetEnumerator`方法的实现，它使用`CircularLinkedListEnumerator`类。通过创建它，您将能够使用`foreach`循环无限迭代循环链表的所有元素。

`CircularLinkedListEnumerator`类的代码如下：

```cs
public class CircularLinkedListEnumerator<T> : IEnumerator<T> 
{ 
    private LinkedListNode<T> _current; 
    public T Current => _current.Value; 
    object IEnumerator.Current => Current; 

    public CircularLinkedListEnumerator(LinkedList<T> list) 
    { 
        _current = list.First; 
    } 

    public bool MoveNext() 
    { 
        if (_current == null) 
        { 
            return false; 
        } 

        _current = _current.Next ?? _current.List.First; 
        return true; 
    } 

    public void Reset() 
    { 
        _current = _current.List.First; 
    } 

    public void Dispose() { } 
} 
```

`CircularLinkedListEnumerator`类实现了`IEnumerator`接口。该类声明了表示列表迭代中当前节点（`_current`）的`private`字段。它还包含两个属性，即`Current`和`IEnumerator.Current`，这是`IEnumerator`接口所需的。构造函数只是根据作为参数传递的`LinkedList`类的实例设置了`_current`变量的值。

代码中最重要的部分之一是`MoveNext`方法。当`_current`变量设置为`null`时，即列表中没有项目时，它停止迭代。否则，它将当前元素更改为下一个元素，或者更改为列表中的第一个节点，如果下一个节点不可用。在`Reset`方法中，只需将`_current`字段的值设置为列表中的第一个节点。

最后，您需要创建两个扩展方法，使得在尝试从列表中的最后一个项目获取下一个元素时，可以导航到第一个元素，以及在尝试从列表中的第一个项目获取上一个元素时，可以导航到最后一个元素。为了简化实现，这些功能将作为`Next`和`Previous`方法而不是`Next`和`Previous`属性提供，如前面的图所示。代码如下所示：

```cs
public static class CircularLinkedListExtensions 
{ 
    public static LinkedListNode<T> Next<T>( 
        this LinkedListNode<T> node) 
    { 
        if (node != null && node.List != null) 
        { 
            return node.Next ?? node.List.First; 
        } 
        return null; 
    } 

    public static LinkedListNode<T> Previous<T>( 
        this LinkedListNode<T> node) 
    { 
        if (node != null && node.List != null) 
        { 
            return node.Previous ?? node.List.Last; 
        } 
        return null; 
    } 
} 
```

第一个扩展方法，即`Next`，检查节点是否存在以及列表是否可用。在这种情况下，它返回节点的`Next`属性的值（如果这个值不等于`null`），或者使用`First`属性返回列表中的第一个元素的引用。`Previous`方法以类似的方式操作。

到此为止！您刚刚完成了基于 C#的循环链表的实现，这可以在以后的各种应用中使用。但是如何呢？让我们看一下下面使用这种数据结构的示例。

# 示例 - 旋转轮子

这个示例模拟了一个游戏，用户以随机速度旋转轮子。轮子的旋转速度越来越慢，直到停止。然后用户可以再次旋转它，从上一次停止的位置开始，如下图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dsal/img/75f72d77-a896-4392-94ac-61d6771fef43.png)

让我们继续`Program`类中`Main`方法的代码的第一部分：

```cs
CircularLinkedList<string> categories =  
    new CircularLinkedList<string>(); 
categories.AddLast("Sport"); 
categories.AddLast("Culture"); 
categories.AddLast("History"); 
categories.AddLast("Geography"); 
categories.AddLast("People"); 
categories.AddLast("Technology"); 
categories.AddLast("Nature"); 
categories.AddLast("Science"); 
```

首先创建了`CircularLinkedList`类的新实例，它表示具有`string`元素的循环链表。然后添加了八个值，即`Sport`，`Culture`，`History`，`Geography`，`People`，`Technology`，`Nature`和`Science`。

代码的下一部分执行了最重要的操作：

```cs
Random random = new Random(); 
int totalTime = 0; 
int remainingTime = 0; 
foreach (string category in categories) 
{ 
    if (remainingTime <= 0) 
    { 
        Console.WriteLine("Press [Enter] to start  
            or any other to exit."); 
        switch (Console.ReadKey().Key) 
        { 
            case ConsoleKey.Enter: 
                totalTime = random.Next(1000, 5000); 
                remainingTime = totalTime; 
                break; 
            default: 
                return; 
        } 
    } 

    int categoryTime = (-450 * remainingTime) / (totalTime - 50)  
        + 500 + (22500 / (totalTime - 50)); 
    remainingTime -= categoryTime; 
    Thread.Sleep(categoryTime); 

    Console.ForegroundColor = remainingTime <= 0  
        ? ConsoleColor.Red : ConsoleColor.Gray; 
    Console.WriteLine(category); 
    Console.ForegroundColor = ConsoleColor.Gray; 
} 
```

首先声明了三个变量，即用于生成随机值的变量（`random`），旋转轮子的总时间（以毫秒为单位）（`totalTime`），以及旋转轮子的剩余时间（以毫秒为单位）（`remainingTime`）。

然后，使用`foreach`循环来迭代循环链表中的所有元素。如果在这样的循环中没有`break`或`return`指令，它将由于循环链表的特性而无限执行。如果到达最后一个项目，下一个迭代将自动获取列表中的第一个元素。

在循环中，检查剩余时间。如果剩余时间小于或等于零，即车轮已停止或尚未启动，将向用户显示消息，并等待*Enter*键被按下。在这种情况下，通过绘制旋转的总时间和设置剩余时间来配置新的旋转操作。当用户按下其他键时，程序将停止执行。

在下一步中，计算了循环的一次迭代时间。该公式使得在开始时可以提供较小的时间（车轮旋转更快），在结束时可以提供较大的时间（车轮旋转更慢）。然后，剩余时间减少，程序使用`Sleep`方法等待指定的毫秒数。

最后，如果显示了最终结果，则将前景色更改为红色，并在控制台中显示当前选择的旋转轮上的类别。

当您运行应用程序时，您可以得到以下结果：

```cs
    Press [Enter] to start or any other to exit.
    Culture
    History
    Geography (...)
    Culture
    History
    Press [Enter] to start or any other to exit.
    Geography (...)
    Nature
    Science (...)
    People
    Technology
    Press [Enter] to start or any other to exit.
```

您已经完成了使用循环链表的示例。这是本章中描述的数据结构之一。如果您想简要总结您所学到的信息，让我们继续对这个主题进行简要总结。

# 总结

数组和列表是开发各种应用程序时最常用的数据结构之一。然而，这个主题并不像看起来那么简单，因为即使数组也可以分为几个变体，即单维数组、多维数组和交错数组，也称为数组的数组。

在列表的情况下，差异更加明显，正如您在简单、通用、排序、单链、双链和循环链列表的情况下所看到的。幸运的是，数组列表、通用、排序和双链列表都有内置的实现。此外，您可以相当容易地扩展双链表以表现为循环链表。因此，您可以在不需要显著开发工作的情况下从适当的结构特性中受益。

可用的数据结构类型听起来可能相当复杂，但在本章中，您已经看到了特定数据结构的详细描述，以及基于 C#的示例的实现代码。它们应该为您简化事情，并可以作为您未来项目的基础。

您准备好学习其他数据结构了吗？如果是这样，让我们继续到下一章，了解关于栈和队列的内容！
