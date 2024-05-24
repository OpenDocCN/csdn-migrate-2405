# C# 面向对象编程实用指南（一）

> 原文：[`zh.annas-archive.org/md5/ADAC00B29224B3ED5BF1EE522FE998CB`](https://zh.annas-archive.org/md5/ADAC00B29224B3ED5BF1EE522FE998CB)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

面向对象编程（OOP）是围绕对象而不是动作组织的编程范式，围绕数据而不是逻辑。随着 C#的最新版本发布，有许多新的增强功能改进了 OOP。本书旨在以引人入胜和互动的方式教授 C#中的 OOP。阅读本书后，您将了解 OOP 的四大支柱，即封装、继承、抽象和多态，并能够利用 C# 8.0 的最新功能，如可空引用类型和异步流。然后，您将探索 OOP 中的各种设计模式、原则和最佳实践。

# 这本书适合谁

这本书适用于初学面向对象编程的人。它假设您已经具备基本的 C#技能。不需要对其他语言中的面向对象编程有任何了解。

# 本书涵盖的内容

第一章，《C#作为一种语言的概述》，涵盖了 C#编程语言的基本概述，以帮助初学者理解语言构造。本章还将解释.NET 作为一个框架存在的原因，以及如何在程序中利用.NET 框架。本章最后将介绍 Visual Studio 作为开发 C#项目的编辑器。

第二章，《你好，OOP-类和对象》，解释了面向对象编程的最基本概念。我们首先解释了什么是类，以及如何编写一个类。

第三章，《C#中的面向对象编程实现》，涵盖了使 C#成为面向对象编程语言的概念。本章涵盖了 C#语言的一些非常重要的主题，以及如何在实际编程中利用这些主题。

第四章，《对象协作》，涵盖了对象协作，它是什么，程序中的对象如何相互关联，以及对象之间存在多少种类型的关系。我们还将讨论依赖协作、关联和继承。

第五章，《异常处理》，涵盖了如何在执行代码时处理异常。我们将探讨不同类型的异常以及如何使用 try/catch 块消除代码中的问题。

第六章，《事件和委托》，涵盖了事件和委托。在本章中，我们将介绍事件是什么，委托是什么，事件如何与委托连接以及它们各自的用途。

第七章，《C#中的泛型》，介绍了一个非常有趣和重要的主题-泛型。我们将学习泛型是什么，以及它们为什么如此强大。

第八章，《建模和设计软件》，涵盖了软件设计中使用的不同统一建模语言（UML）图。我们将详细讨论最流行的图，包括类图、用例图和序列图。

第九章，《Visual Studio 和相关工具》，涵盖了 C#编程的最佳编辑器。Visual Studio 是一个非常丰富的集成开发环境。它具有一些令人惊叹的功能，可以使开发人员的工作效率非常高。在本章中，我们将介绍 Visual Studio 中可用的不同项目和窗口。

第十章，《通过示例探索 ADO.NET》，涵盖了 ADO.NET 类，以及通过实体框架的基本数据适配器、存储过程和对象关系模型的基础知识。我们还将讨论 ADO.NET 中的事务。

第十一章《C# 8 的新功能》涵盖了 C#语言的新功能，这个语言正在不断改进，C#语言工程师正在将额外的功能纳入语言中。2019 年，微软宣布将发布 C# 8.0，并概述将随该版本发布的新功能。本章将讨论 C# 8.0 中即将引入的新功能。我们将讨论可空引用类型、异步流、范围、接口成员的默认实现以及其他几个主题。

第十二章《理解设计模式和原则》包含有关设计原则和一些非常流行和重要的设计模式的信息。

第十三章《Git-版本控制系统》讨论了当今最流行的版本控制系统 Git。对于所有开发人员来说，学习 Git 是必不可少的。

第十四章《准备自己，面试和未来》包括一些最常见的面试问题和对这些问题的回答，以便您为下一次面试做好准备。这一章主要是为了让您对潜在的面试问题有一个概念。

# 充分利用本书

读者应该具有一些关于.NET Core 和.NET Standard 的先验知识，以及对 C#、Visual Studio 2017（作为 IDE）、版本控制、关系数据库和基本软件设计的基本知识。

# 下载示例代码文件

您可以从[www.packt.com](http://www.packt.com)的帐户下载本书的示例代码文件。如果您在其他地方购买了这本书，您可以访问[www.packt.com/support](http://www.packt.com/support)并注册，以便文件直接通过电子邮件发送给您。

您可以按照以下步骤下载代码文件：

1.  在[www.packt.com](http://www.packt.com)上登录或注册。

1.  选择“支持”选项卡。

1.  点击“代码下载和勘误”。

1.  在搜索框中输入书名，然后按照屏幕上的说明操作。

下载文件后，请确保使用最新版本的解压缩或提取文件夹：

+   WinRAR/7-Zip for Windows

+   Zipeg/iZip/UnRarX for Mac

+   7-Zip/PeaZip for Linux

本书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/Hands-On-Object-Oriented-Programming-with-CSharp`](https://github.com/PacktPublishing/Hands-On-Object-Oriented-Programming-with-CSharp)。如果代码有更新，将在现有的 GitHub 存储库上进行更新。

我们还有来自丰富书籍和视频目录的其他代码包，可在**[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)**上找到。去看看吧！

# 下载彩色图像

我们还提供了一份 PDF 文件，其中包含本书中使用的屏幕截图/图表的彩色图像。您可以在这里下载：[`www.packtpub.com/sites/default/files/downloads/9781788296229_ColorImages.pdf`](https://www.packtpub.com/sites/default/files/downloads/9781788296229_ColorImages.pdf)。

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄。这是一个例子：“`Tweet`和`Message`对象之间的关系”。

代码块设置如下：

```cs
class Customer
{
    public string firstName;
    public string lastName;
    public string phoneNumber;
    public string emailAddress;

    public string GetFullName()
    {
        return firstName + " " + lastName;
    }
}
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目将以粗体显示：

```cs
class class-name {
    // property 1
    // property 2
    // ...

    // method 1
    // method 2
    // ...
}
```

任何命令行输入或输出都以以下方式编写：

```cs
git config --global user.name = "john"
git config --global user.email = "john@example.com"
```

**粗体**：表示新术语、重要单词或屏幕上看到的单词。例如，菜单或对话框中的单词会以这种方式出现在文本中。这是一个例子：“转到工具|扩展和更新”。

警告或重要说明会以这种方式出现。

提示和技巧会以这种方式出现。


# 第一章：C#作为一种语言的概述

随着现代编程实践的引入，显然开发人员正在寻找更先进的构造，以帮助他们以最有效的方式交付最佳软件。建立在框架之上的语言旨在增强开发人员的能力，使他们能够快速构建具有较少复杂性的代码，以便代码可维护且可读。

市场上有许多高级面向对象的编程语言，但其中我认为最有前途的是 C#。C#语言在编程世界中并不新，已经存在了十多年，但随着语言本身的动态进展创造了许多新的构造，它已经超越了一些最广泛接受的语言竞争。C#是一种面向对象的、类型安全的、通用的语言，它是建立在由微软开发并由**欧洲计算机制造商协会**（**ECMA**）和**国际标准化组织**（**ISO**）批准的.NET 框架之上的。它是建立在公共语言基础设施上的，并且可以与基于相同架构构建的任何其他语言进行交互。受 C++的启发，该语言在不处理过多代码复杂性的情况下提供了最优质的应用程序。

在本章中，我们将涵盖以下主题：

+   C#的演变

+   C#的架构

+   C#语言的基础和语法

+   Visual Studio 作为编辑器

+   在 Visual Studio 中编写你的第一个程序

# C#的演变

C#是近年来最具活力的语言之一。这门语言是开源的，主要由一群软件工程师推动，他们最近提出了许多重大变化，以增强语言并提供处理现有语言复杂性的功能。为该语言提出的一些主要增强功能包括泛型、LINQ、动态和异步/等待模式：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/73797b91-d957-41f7-bd59-0b55cbde8a73.png)

在上图中，我们可以看到这门语言是如何从 C# 1.0 的托管代码开始演变的，到 C# 5.0 引入的异步编程构造，再到现代的 C# 8。在继续之前，让我们看一下 C#在不同演变阶段的一些亮点。

# 托管代码

托管代码这个词是在微软宣布.NET 框架之后出现的。在托管环境中运行的任何代码都由**公共语言运行时**（**CLR**）处理，它保持

# 泛型

泛型是在 C# 2.0 中引入的概念，允许模板类型定义和类型参数。泛型允许程序员定义具有开放类型参数的类型，这从根本上改变了程序员编写代码的方式。动态类型的泛型模板提高了可读性、可重用性和代码性能。

# LINQ

C#语言的第三个版本引入了**语言集成查询（LINQ）**，这是一种可以在对象结构上运行的新查询构造。LINQ 在编程世界中非常新颖，让我们一窥面向对象通用编程结构之上的函数式编程。LINQ 还引入了一堆新的接口，以`IQueryable`接口的形式，引入了许多可以使用 LINQ 与外部世界交互的库。Lambda 表达式和表达式树的引入提升了 LINQ 的性能。

# 动态

第四版还提供了一个全新的构造。它引入了动态语言结构。动态编程能力帮助开发人员将编程调用推迟到运行时。语言中引入了特定的语法糖，它在同一运行时编译动态代码。该版本还提出了许多增强其语言能力的新接口和类。

# 异步/等待

使用任何语言，线程或异步编程都是一种痛苦。在处理异步时，程序员必须面对许多复杂性，这些复杂性降低了代码的可读性和可维护性。有了 C#语言中的 async/await 功能，以异步方式编程就像同步编程一样简单。编程已经简化，所有复杂性都由编译器和框架在内部处理。

# 编译器作为服务

微软一直在研究如何向世界开放编译器源代码的某些部分。因此，作为程序员，您可以查询编译器的一些内部工作原理。C# 6.0 引入了许多库，使开发人员能够深入了解编译器、绑定器、程序的语法树等。尽管这些功能作为 Roslyn 项目开发了很长时间，但微软最终将其发布给外部世界。

# 异常过滤器

C# 6.0 装饰有许多较小的功能。其中一些功能为开发人员提供了实现简单代码的复杂逻辑的机会，而另一些则增强了语言的整体能力。异常过滤器是这个版本的新功能，它使程序能够过滤出特定的异常类型。异常过滤器作为 CLR 构造一直隐藏在语言中，但最终在 C# 6.0 中引入。

# C# 8 及更高版本

随着 C#成为市场上最具动态性的语言，它不断改进。通过新功能，如可空引用类型、异步流、范围和索引、接口成员等，以及最新版本的 C#带来的许多其他功能，它增强了基本功能，并帮助程序员利用这些新构造，从而使他们的生活更轻松。

请注意，在语言的演变过程中，.NET 框架也已开源。您可以在以下链接找到.NET 框架的源代码：[`referencesource.microsoft.com/`](https://referencesource.microsoft.com/)。

# .NET 架构

尽管它已有十年历史，但.NET 框架仍然构建良好，并确保将其分层、模块化和分级。每个层提供特定的功能给用户，有些是安全性方面的，有些是语言能力方面的。这些层为最终用户提供了一层抽象，并尽可能隐藏本机操作系统的大部分复杂性。.NET 框架被分成模块，每个模块都有自己独特的责任。较高层从较低层请求特定功能，因此它是分级的。

让我们来看一下.NET 架构的图表：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/015b47d1-2a67-40d8-8ef0-348aee4382c1.png)

上图描述了.NET 框架架构的布局。在最低级别上，它是与操作系统交互的操作系统，该操作系统中存在与操作系统中的内核 API 交互的操作系统。公共语言基础设施与 CLR 连接，提供监视每个代码执行和管理内存、处理异常以及确保应用程序行为符合预期的服务。基础设施的另一个重要目标是语言互操作性。公共语言运行时再次通过.NET 类库进行抽象。该层保存了语言构建的二进制文件，所有构建在库之上的编译器提供相同的编译代码，以便 CLR 可以理解代码并轻松相互交互。

在继续之前，让我们快速看一下构建在.NET 框架上的语言的一些关键方面。

# 公共语言运行时

CLR 提供了底层未管理基础设施与托管环境之间的接口。这以垃圾回收、安全性和互操作性的形式提供了托管环境的所有基本功能。CLR 由即时编译器组成，该编译器将使用特定编译器生成的程序集代码编译为本机调用。CLR 是.NET 架构中最重要的部分。

# 公共类型系统

由于语言和框架之间存在一层抽象，因此很明显，每种语言文字都映射到特定的 CLR 类型。例如，VB.NET 的整数与 C#的整数相同，因为它们都指向相同的类型 System.Int32。始终建议使用语言类型，因为编译器会处理类型的映射。CTS 系统构建为`System.Object`位于其顶点的类型层次结构。**公共类型系统**（**CTS**）分为两种类型，一种是值类型，它们是从`System.ValueTypes`派生的原始类型，而其他任何类型都是引用类型。值类型与引用类型的处理方式不同。这是因为在分配内存时，值类型在执行期间在线程堆栈上创建，而引用类型始终在堆上创建。

# .NET 框架类库

框架类库位于语言和 CLR 之间，因此框架中存在的任何类型都暴露给您编写的语言。.NET 框架由大量类和结构组成，提供无穷尽的功能，您作为程序员可以从中受益。类库以可以直接从程序代码中引用的二进制形式存储。

# 即时编译器

.NET 语言被编译两次。在第一种编译形式中，高级语言被转换为**Microsoft 中间语言**（**MSIL**），CLR 可以理解，而在程序执行时，MSIL 再次被编译。JIT 在程序运行时内部工作，并定期编译预计在执行期间需要的代码。

# C#语言的基本原理和语法

作为一种高级语言，C#装饰有许多更新和更新的语法，这有助于程序员高效地编写代码。正如我们之前提到的，语言支持的类型系统分为两种类型：

+   值类型

+   引用类型

值类型通常是存储在堆栈中的原始类型，用于本地执行，以便更快地分配和释放内存。值类型在代码开发过程中大多被使用，因此构成了整个代码的主要范围。

# 数据类型

C#的基本数据类型分为以下几类：

+   布尔类型：`bool`

+   字符类型：`char`

+   整数类型：`sbyte`、`byte`、`short`、`ushort`、`int`、`uint`、`long`和`ulong`

+   浮点类型：`float`和`double`

+   小数精度：`decimal`

+   字符串：`string`

+   对象类型：`object`

这些是原始数据类型。这些数据类型嵌入在 C#编程语言中。

# 可空类型

在 C#中，原始类型或值类型是不可空的。因此，开发人员总是需要将类型设置为可空，因为开发人员可能需要确定值是否是显式提供的。最新版本的.NET 提供了可空类型：

```cs
Nullable<int> a = null;
int? b = a; //same as above
```

在前面的示例中，两行都定义了可空变量，而第二行只是第一次声明的快捷方式。当值为 null 时，`HasValue`属性将返回`false`。这将确保您可以检测变量是否显式指定为值。

# 文字

文字也是任何程序的重要部分。C#语言为开发人员提供了不同种类的选项，允许程序员在代码中指定文字。让我们看看支持的不同类型的文字。

# 布尔

布尔文字以`true`或`false`的形式定义。除了`true`和`false`之外，布尔类型不能分配其他值：

```cs
bool result = true;
```

布尔类型的默认值是`false`。

# 整数

整数是一个可以有加号(+)或减号(-)作为前缀的数字，但这是可选的。如果没有给出符号，则被视为正数。您可以以 int、long 或十六进制形式定义数字文字：

```cs
int numberInDec = -16;
int numberInHex = -0x10;
long numberinLong = 200L;
```

您可以看到，第一个文字`-16`是指定为整数变量的文字，而相同的值是使用十六进制文字分配给整数的。长变量被分配了一个带有`L`后缀的值。

# 真实

实数是带有正负号的数字序列，如整数。这也使得可以指定分数值：

```cs
float realNumber = 12.5f;
realNumber = 1.25e+1f;
double realdNumber = 12.5;
```

正如您所看到的，最后一行中的文字`12.5`默认为`double`，因此需要分配给 double 变量，而前两行指定了浮点类型中的文字。您还可以指定`d`或`D`作为后缀来定义`double`，例如`f`或`F`用于`float`和`m`用于 decimal。

# 字符

字符文字需要保留在单引号内。文字的值可以如下：

+   一个字符，例如，`c`

+   字符代码，例如，`\u0063`

+   转义字符，例如，`\\`（反斜杠是一个转义字符）

# 字符串

字符串是一系列字符。在 C#中，字符串由双引号表示。在 C#中有不同的创建字符串的方式。让我们看看在 C#中创建字符串的不同方式：

```cs
string s = "hello world";
string s1 = "hello \n\r world"; //prints the string with escape sequence
string s2 = @"hello \n\r world"; //prints the string without escape sequence
string s3 = $"S1 : {s1}, S2: {s2}"; // Replaces the {s1} and {s2} with values
```

`@`字符可以放在字符串前面作为前缀，以便将字符串作为原样处理，而不必担心任何转义字符。它被称为原始字符串。`$`字符用作字符串插值的前缀。如果您的字符串文字以`$`符号开头，则如果它们放在`{ }`括号内，变量将自动替换为值。

# 编程语法-条件

条件是任何程序的最常见构建块之一。程序不能只有单个维度；比较、跳转和中断是 C#中最常见的练习形式。有三种类型的条件可用：

+   `if...else`

+   `switch-case`

+   `goto`（无条件 lumps）

# If-else 结构

最常用的条件语句是 if-else 结构。if-else 结构的基本组成部分包含一个`if`关键字，后面跟着一个布尔表达式和一组花括号来指定要执行的步骤。可选地，可能会有一个`else`关键字，后面跟着花括号，用于在`if`块为`false`时执行的代码：

```cs
int a = 5;
if (a == 5)
{
   // As a is 5, do something
}
else
{
  // As a is not 5, do something
}
```

if-else 结构也可以有一个 else-if 语句来指定多个执行条件。

# Switch-case 结构

另一方面，switch-case 几乎与`if`语句类似；在这个语句中，case 将确定执行步骤。在`switch`的情况下，这总是落在一组离散的值中，因此，这些值可以被设置：

```cs
int a = 5;
switch (a)
{
  case 4:
     // Do something; 
     break;
  case 5:
     // Do something;
     break;
 default:
     // Do something;
     break;
}
```

switch case 会自动选择正确的 case 语句，取决于值，并执行块内定义的步骤。case 需要以 break 语句结束。

# goto 语句

尽管它们不太受欢迎，也不建议使用，`goto`语句用于语言中的无条件跳转，并且被语言本身广泛使用。作为开发人员，你可以使用`goto`语句跳转到程序中的任何位置：

```cs
... code block
goto lbl1;
...
...
lbl1: expression body
```

`goto`语句直接跳转到指定的位置，没有任何条件或标准。

# 编程语法 - 循环

对于执行过程中的重复任务，循环发挥着至关重要的作用。循环允许程序员定义循环将在何时结束，或者循环应该执行到何时的条件，具体取决于循环的类型。有四种类型的循环：

+   当

+   do-while

+   对于

+   Foreach

# while 结构

在编程世界中，循环用于使一系列执行步骤重复，直到满足条件。`while`循环是 C#编程架构的基本组成部分之一，用于循环执行大括号中提到的循环体，直到`while`条件中提到的条件为`true`：

```cs
while (condition)
{
  loop body;
}
```

循环中提到的条件应该评估为`true`，以执行下一次迭代的循环。

# do-while 结构

`do...while`结构在执行一次步骤后检查条件。尽管`do...while`循环类似于`while`循环，但`do...while`循环和`while`循环之间唯一的区别是，`do...while`循环将至少执行一次循环体，即使条件为`false`：

```cs
do
{
  loop body;
}
while (condition);
```

# for 结构

语言中最流行的循环是`for`循环，它通过在块内部高效地维护循环的执行次数来处理复杂性：

```cs
for (initialization; condition; update)
{
  /* loop body */
}
```

`for`循环在条件中有几个部分。每个部分都用分号(`;`)分隔。第一部分定义了索引变量，在执行循环之前执行一次。第二部分是在每次`for`循环迭代时执行的条件。如果条件变为`false`，`for`循环将停止执行。第三部分也在每次执行循环体后执行，并且操作了在`for`循环初始化和条件中使用的变量。

# foreach 结构

`foreach`循环是语言中的新功能，用于迭代对象序列。尽管这在语言中纯粹是语法糖，但在处理集合时，`foreach`循环被广泛使用。`foreach`循环内部使用`IEnumerable<object>`接口，并且应该只用于实现了该接口的对象：

```cs
foreach (type variable in collection)
{
    //statements;
}
```

# 上下文 - break 和 continue 语句

如果你在使用循环，理解另外两个上下文关键字是非常重要的，它们使得与循环进行交互成为可能。

# Break

这允许开发人员在条件仍然有效的情况下中断循环并将上下文带出循环。编程上下文关键字`break`用作绕过正在执行的循环的循环。`break`语句在循环和 switch 语句中有效。

# Continue

这用于调用下一次迭代。上下文关键字允许开发人员继续到下一步，而不执行块中的任何其他代码。

现在，让我们看看如何在我们的程序中使用这两个上下文语句：

```cs
var x = 0;
while(x<=10)
{
   x++;
   if(x == 2)continue;
   Console.WriteLine(x);
   if(x == 5) break;
   Console.WriteLine("End of loop body");
}
Console.WriteLine($"End of loop, X : {x}");
```

前面的代码将跳过迭代值为`2`的循环体的执行，因为有`continue`语句。循环将一直执行直到`x`的值为`5`，因为有`break`语句。

# 在控制台应用程序中编写您的第一个 C#程序

现在您已经了解了 C#语言的基本知识和基础知识，文字，循环，条件等，我认为是时候看一个 C#代码示例了。所以，让我们通过编写一个简单的控制台应用程序，编译它，并使用 C#编译器运行它来开始本节。

打开您计算机上的任何记事本应用程序，并输入以下代码：

```cs
using System;

public  Program
{
      static void Main(string[] args)
      {
          int num, sum = 0, r;
          Console.WriteLine("Enter a Number : ");
          num = int.Parse(Console.ReadLine());
          while (num != 0)
          {
              r = num % 10;
              num = num / 10;
              sum = sum + r;
          }
          Console.WriteLine("Sum of Digits of the Number : " + sum);
          Console.ReadLine();
      }
}
```

上述代码是计算数字所有数字之和的经典示例。它使用`Console.ReadLine()`函数作为输入，解析并将其存储到变量`num`中，循环遍历直到数字为`0`，并取模`10`以获得除法的余数，然后将其相加以产生结果。

您可以看到代码块顶部有一个`using`语句，它确保可以调用`Console.ReadLine()`和`Console.WriteLine()`。`System`是代码中的一个命名空间，它使程序能够调用其中定义的类，而无需指定类的完整命名空间路径。

让我们将类保存为`program.cs`。现在，打开控制台并将其移动到您保存代码的位置。

要编译代码，我们可以使用以下命令：

```cs
csc Program.cs
```

编译将产生类似于这样的东西：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/2f54ec56-f834-44ce-85f9-aaeb2570861c.png)

编译将产生`program.exe`。如果您运行此程序，它将接受数字作为输入并产生结果：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/19038024-805d-4d63-bfab-9ebfef4760a2.png)

您可以看到代码正在控制台窗口中执行。

如果我们进一步分析代码的执行方式，我们可以看到.NET 框架提供了`csc`编译器，这是一个能够将我的 C#代码编译成托管可执行文件的可执行文件。编译器生成一个包含 MSIL 的可执行文件，然后在执行可执行文件时，.NET 框架调用一个可执行文件，并使用 JIT 进一步编译它，以便与输入/输出设备进行交互。

`csc`编译器提供了各种命令行钩子，可以进一步用于向程序添加**动态链接库**（**dll**）引用，将输出目标设置为 dll 等。您可以在以下链接找到完整的功能文档：[`docs.microsoft.com/en-us/dotnet/csharp/language-reference/compiler-options/listed-alphabetically`](https://docs.microsoft.com/en-us/dotnet/csharp/language-reference/compiler-options/listed-alphabetically)。

# Visual Studio 作为编辑器

微软创建了许多改进工具集，帮助创建，调试和运行程序。其中一个工具就是**Visual Studio**（**VS**）。微软 VS 是一个与微软语言一起工作的开发环境。这是开发人员可以依赖的工具，以便他们可以轻松地使用微软技术。VS 已经存在了相当长的时间，但新的 VS 已经完全重新设计，并作为 VS 2019 发布，以支持.NET 语言。

# Visual Studio 的演变

随着时间的推移，微软发布了更多优势和增强功能的新版本 VS。作为托管许多服务作为插件的插件主机，VS 已经发展出许多工具和扩展。它一直是每个开发人员活动的核心部分。VS 已被许多不属于开发人员社区的人使用，因为他们发现这个 IDE 对编辑和管理文档很有益。

# Visual Studio 的类型

微软推出了不同类型或版本的 VS。这些版本之间的区别在于功能和定价。其中一个版本是免费的，而其他版本需要购买。因此，了解哪个版本提供了哪些功能，哪个版本更适合哪种类型的工作，将使开发人员更容易选择合适的版本。

让我们来比较一下所有版本的 VS。

# Visual Studio Community

VS 社区版是免费版。这个版本没有一些其他版本中可用的高级功能，但这个社区版完全适用于构建小型/中型项目。这对于想要探索 C#编程语言的人特别有用，因为他们可以免费下载这个版本并开始构建应用程序。

# Visual Studio Professional

这个版本的 VS 是为您自己的开发而设计的，具有重要的调试工具和所有常用的开发人员工具。因此，您可以将 IDE 用作您的主要方向，然后可以继续！

# Visual Studio Enterprise

VS 企业版是为需要商业级 IDE 使用的企业而设计的。它支持用于测试、调试等的特殊工具。它还可以发现常见的编码错误，生成测试数据等等。

# Visual Studio Code

VS Code 是一个小型的开源工具，不是完整的 IDE，而是由微软开发的简单代码编辑器。这个编辑器非常轻量级且与平台无关。VS Code 没有大多数 VS IDE 具有的功能，但具有足够的功能来开发和调试应用程序。

对于本书，我们将在大多数情况下使用 VS 社区版，但您可以安装任何您希望的版本。您可以免费下载社区版，网址如下：[`www.visualstudio.com/downloads/`](https://www.visualstudio.com/downloads/)。

# Visual Studio IDE 简介

安装 VS 后，VS 安装程序将为您提供关于工作负载的几个选项，这意味着您将使用此 IDE 开发的应用程序类型。对于本书，我们只会创建 C#控制台应用程序，因此您可以选择该选项。现在，让我们开始 VS IDE。加载 IDE 后，它将显示一个带有多个选项的起始页面。选择创建新项目的选项。

# 新项目

选择新项目后，将出现新项目对话框。在此对话框中，将基于当前与 IDE 一起安装的软件包提供一些选项，如下图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/5e1316ae-e768-453e-b989-0eadeab4ed8d.png)

在上图中，左侧的分组是您可以选择的模板类型。在这里，我选择了 Windows 桌面，并从中间窗口中选择了控制台应用程序(.NET 框架)来创建我的应用程序。屏幕底部允许您命名项目并选择存储项目文件的位置。有两个复选框可用，其中一个说“选择时创建解决方案目录”（默认情况下，此复选框保持选中状态）。这将在所选路径下创建一个目录并将文件放入其中，否则它将在文件夹内部创建文件。

使用“搜索已安装的模板”在对话框的右上角按名称搜索任何模板，如果找不到您的模板。由于一台 PC 上可以存在多个框架，新项目对话框将允许您选择一个框架；在部署应用程序时需要使用它。默认情况下，它显示.NET 框架 4.6.1 作为项目的框架，但您可以通过从下拉菜单中选择一个来更改为任何框架。

最后，单击“确定”以使用默认文件创建项目：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/354b45b5-260c-4e91-ae13-360897be8c3c.png)

前面的屏幕截图显示了项目创建后基本 IDE 的外观。我们还可以看到 IDE 的每个部分。主要 IDE 由许多工具窗口组成。您可以在屏幕的各个部分看到一些工具窗口。任务列表窗口位于屏幕底部。主要 IDE 工作区位于中间，形成了 IDE 的工作区域。可以使用屏幕角落的缩放控件放大工作区。屏幕顶部的 IDE 搜索框可以帮助您更优雅、更轻松地找到 IDE 内部的选项。现在我们将整个 IDE 分成这些部分，并探索 IDE。

# 解决方案资源管理器

文件夹和文件在解决方案资源管理器中按层次结构显示。解决方案资源管理器是主窗口，列出了加载到 IDE 中的整个解决方案。这使您可以以树的形式轻松导航查看具有解决方案的项目和文件。解决方案资源管理器的外部节点本身就是一个解决方案，然后是项目，然后是文件和文件夹。解决方案资源管理器支持加载解决方案中的文件夹，并在第一级存储文档。设置为启动的项目以粗体标记。

解决方案资源管理器顶部有许多称为工具栏按钮的按钮。根据树中所选文件，工具栏按钮将启用或禁用。让我们逐个查看它们：

+   折叠所有按钮：此按钮允许您折叠当前选定节点下方的所有节点。在处理大型解决方案时，通常需要完全折叠部分树。您可以使用此功能而无需手动折叠每个节点。

+   属性：作为打开属性窗口的快捷方式，您可以选择此按钮以打开属性窗口并加载与当前选择节点相关联的元数据。

+   显示所有文件：解决方案通常映射到文件系统中目录的文件夹结构。解决方案中包含的文件仅显示在解决方案树上。显示所有文件允许您在查看目录中的所有文件和仅添加到解决方案中的文件之间切换。

+   刷新：刷新当前解决方案中文件的状态。刷新按钮还会检查文件系统中的每个文件，并根据需要显示其状态。

+   查看类图：类图是命名空间和类的逻辑树，而不是文件系统中的文件。选择此选项时，VS 会启动具有其属性、方法等所有详细信息的类图。类图对于单独查看所有类及其关联非常有用。

+   查看代码：当选择代码文件时，将出现查看代码按钮，它会加载与当前选择相关联的代码文件。例如，当选择 Windows 窗体时，它将显示其代码后端，代码需要在其中编写。

+   查看设计器：有时，根据树中所选的文件类型，会出现查看设计器按钮。此按钮会启动与当前选择的文件类型相关联的设计器。

+   添加新文件夹：如我已经提到的，解决方案也可以包含文件夹。您可以使用添加新文件夹按钮直接向解决方案中添加文件夹。

+   创建新解决方案：有时，在处理大型项目时，您可能需要创建整个解决方案的子集，并仅列出您当前正在处理的项目。此按钮将创建一个与原始解决方案同步的单独的解决方案资源管理器，但会显示解决方案树的特定部分。

在 VS 中的解决方案树也以文件系统中的组织方式加载项目的类结构。如果你看到一个折叠的文件夹，你可以展开它来看看里面有什么。如果你展开一个`.cs`文件，那么该类的所有成员都会被列出来。如果你只想看看类是如何组织的，你可以使用类视图窗口，但是通过使用解决方案资源管理器，你可以看到类，以及其自己层次结构内的其他元素。你可以通过选择视图|类视图或按*Ctrl + W 和 C*来打开类视图，这样你就可以只查看类的一部分和其成员：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/1b806af1-3d32-49bd-9325-46daf202e4f1.png)

在解决方案中有一些文件显示为空文件（在我们的情况下，像`bin`和`obj`这样的文件夹）。这意味着这些文件存在于文件系统中，但没有包含在解决方案文件中。

每个文件在解决方案中的树节点右侧都显示了额外的信息。这个按钮提供了与文件相关的额外信息。例如，如果你点击与`.cs`文件对应的按钮，它将打开一个带有`Contains`的菜单。这将在解决方案中为该特定文件获取关联的类视图。菜单可能会很长，取决于不能在通用工具栏按钮中显示的项目。当解决方案加载额外信息时，会有前进和后退按钮，可以用来在解决方案的视图之间导航。

# 主工作区域

主工作区域是你实际编写代码或对应用程序应用不同设置的地方。这个部分将打开你项目中的不同类型的文件。作为开发人员，你会在这个区域花费大部分时间编码。你可以在这个窗口中打开多个文件。不同的文件将显示在不同的标签中，你可以通过点击标签来在不同的标签之间切换。如果需要的话，你也可以固定标签。如果你认为需要这样，你可以让标签浮动，或者也可以使其全屏大小，这样你就可以专注于你正在工作的代码。

因此，当你在解决方案资源管理器中双击文件或从文件的上下文菜单中选择打开时，该文件将在主编辑区域的标签页中打开。这样，你可以在编辑器窗口中打开多个文件，并在需要时在不同的标签之间切换。每个标签标题都包含一些固定的项目集：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/6267cd7c-b4ce-4bc1-b4ee-244ed3935694.png)

在上面的截图中，你可以看到标签标题包含文件的名称（`Program.cs`），它显示`*`当项目需要保存时，并且有一个切换固定按钮（就像所有其他 IDE 工具窗口一样），它可以使标签固定在左侧，并且有一个关闭按钮。标题部分有时也会指示一些额外的状态，例如，当文件被锁定时，它会显示一个锁图标，当对象从元数据中加载时，它会在方括号中显示，就像上面的截图中一样。在这个部分，当我们不断打开文件时，它会形成一个标签页的堆栈，一直到最后。当整个区域被占满时，它最终会在工作区标题的右上角创建一个菜单，用来保存所有不能在屏幕上显示的文件列表。从这个菜单中，你可以选择需要打开的文件。*Ctrl + Tab*也可以用来在工作区中已加载的标签之间切换。

在选项卡标题下方和主工作区域之前有两个下拉菜单。一个加载了在 IDE 中打开的类，右边的一个加载了文件中创建的所有成员。这些下拉菜单有助于更轻松地在文件中导航，左边列出了当前文件中加载的所有类，而右边则列出了上下文中存在的所有成员。这两个下拉菜单足够智能，可以在编辑器中添加新代码时自动更新下拉值。

主工作区域由两个滚动条限定，用于处理文档的溢出。然而，在垂直滚动条之后，有一个特殊的按钮可以分割窗口，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/ef0a01a8-f0c9-4939-84ad-21aad17d40b8.png)

另一方面，水平滚动条上有另一个下拉菜单，显示编辑器的当前缩放百分比。VS 现在允许您将编辑器缩放到您喜欢的缩放级别。缩放功能的快捷键是*Ctrl* +滚动鼠标滚轮。

# 输出窗口

输出窗口通常位于 IDE 底部，并在编译、连接到各种服务、开始调试或需要 IDE 显示一些代码时打开。输出窗口用于显示日志和跟踪消息：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/e8288f79-7448-400a-97b0-939e02b33dd4.png)

输出窗口停靠在页面底部，列出各种类型的输出。从顶部的下拉菜单中，您可以选择要在输出窗口中看到的输出。您还可以选择清除日志，如果您只想显示更新的日志。

# 命令和即时窗口

命令窗口与 Windows 操作系统的命令提示符非常相似。您可以使用此工具执行命令。在 VS 命令行中，您可以在正在处理的项目上执行命令。命令非常方便，可以提高您的生产率，因为您不必四处拖动鼠标来执行某些操作。您可以运行命令轻松实现这一点。

要在 VS 中打开命令窗口，可以单击“查看”菜单，然后选择“窗口”。然后，选择“命令窗口”。或者，您可以使用键盘快捷键*Ctrl + Alt + A*来打开它。当您在命令窗口中时，您会看到每个输入前面都有一个`>`。这称为提示符。在提示符中，当您开始输入时，它将为您显示智能感知菜单。开始输入`Build.Compile`，项目将为您编译。您还可以使用`Debug.Start`来开始调试应用程序。您可以使用命令轻松调试应用程序。我将列出一些在使用命令窗口调试时经常使用的重要命令：

+   `?`: 告诉您变量的值（也可以使用`Debug.Print`执行相同操作）

+   `??`: 将变量发送到监视窗口

+   `locals`: 显示本地窗口

+   `autos`: 显示自动窗口

+   `GotoLn`: 将光标设置到特定行

+   `Bp`: 在当前行设置断点

与命令窗口类似，中间窗口允许您测试代码而无需运行它。中间窗口用于评估、执行语句，甚至打印变量值。要打开即时窗口，请转到“调试|窗口”并选择“即时”。

# IDE 中的搜索选项

在屏幕的右上角，您会找到一个新的搜索框。这称为 IDE 搜索框。VS IDE 非常庞大。其中有成千上万的选项可供配置。有时，很难找到您想要的特定选项。IDE 搜索功能可以帮助您更轻松地找到此选项：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/4f733c3a-cef0-46ce-a811-8f23b5a91f6a.png)

搜索选项将列出与 VS IDE 选项相关的所有条目，您可以轻松找到您要查找的任何功能。

# 在 Visual Studio 中编写您的第一个程序

VS 是开发人员在使用 C#语言时主要编码的 IDE。由于您已经对 VS 的工作原理有了基本的了解，让我们在 VS 中编写我们的第一个程序。让我们创建一个控制台应用程序，将解决方案命名为`MyFirstApp`，然后按下 OK。默认的解决方案模板将自动添加，其中包括一个带有`Main`程序的`Program.cs`，以及其他一些文件。

让我们构建一个生成 ATM 机的程序。菜单中有三个选项：

+   提款

+   存款

+   余额检查

提款将在余额（最初为$1,000）上执行，存款将向当前余额添加金额。现在，让我们看看程序的样子：

```cs
class Program
{
  static void Main(string[] args)
  {
      int balance, depositAmt, withdrawAmt;
      int choice = 0, pin = 0;
      Console.WriteLine("Enter your ledger balance");
      balance = int.Parse(Console.ReadLine());
      Console.WriteLine("Enter Your Pin Number ");
      pin = int.Parse(Console.ReadLine());

      if(pin != 1234)
      {
          Console.WriteLine("Invalid PIN");
          Console.ReadKey(false);
          return;
      }

      while (choice != 4)
      {
          Console.WriteLine("********Welcome to PACKT Payment Bank**************\n");
          Console.WriteLine("1\. Check Balance\n");
          Console.WriteLine("2\. Withdraw Cash\n");
          Console.WriteLine("3\. Deposit Cash\n");
          Console.WriteLine("4\. Quit\n");
          Console.WriteLine("*********************************************\n\n");
          Console.WriteLine("Enter your choice: ");
          choice = int.Parse(Console.ReadLine());

          switch (choice)
          {
              case 1:
                  Console.WriteLine("\n Your balance $ : {0} ", balance);
                  break;
              case 2:
                  Console.WriteLine("\n Enter the amount you want to withdraw : ");
                  withdrawAmt = int.Parse(Console.ReadLine());
                  if (withdrawAmt % 100 != 0)
                  {
                      Console.WriteLine("\n Denominations present are 100, 500 and 2000\. Your amount cannot be processed");
                  }
                  else if (withdrawAmt > balance)
                  {
                      Console.WriteLine("\n Sorry, insufficient balance.");
                  }
                  else
                  {
                      balance = balance - withdrawAmt;
                      Console.WriteLine("\n\n Your transaction is processed.");
                      Console.WriteLine("\n Current Balance is {0}", balance);
                  }
                  break;
              case 3:
                  Console.WriteLine("\n Enter amount you want to deposit");
                  depositAmt = int.Parse(Console.ReadLine());
                  balance = balance + depositAmt;
                  Console.WriteLine("Your ledger balance is {0}", balance);
                  break;
              case 4:
                  Console.WriteLine("\n Thank you for using the PACKT ATM.");
                  break;
          }
      }
      Console.ReadLine();
  }
}
```

现在，让我们说明一下程序。程序在打开 ATM 机之前会要求输入 PIN 码。PIN 码不会被检查，可以是任何数字。一旦程序启动，它会在控制台的前面创建一个菜单，其中包含所有所需的选项。

您可以看到整个代码都写在一个`while`循环中，因为它确保程序保持活动状态以进行多次执行。在执行期间，您可以选择任何可用的选项并执行与之相关的操作。

要执行程序，只需单击 IDE 工具栏上的运行按钮：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/0c757c06-5b31-4177-a91b-98fab60b2e87.png)

如果程序没有自动运行，您可以查看错误列表窗口以找出实际问题。如果代码中有错误，VS 将向您显示适当的错误消息，您可以双击它以导航到实际位置。

# 如何调试

如果您听说过 VS，您一定听说过 IDE 的调试功能。您可以按*F10*以调试模式启动程序。程序将以第一行的上下文启动调试模式。让我们执行几行。这将如下所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/37fb2d11-7ce8-4f7b-b8e2-f21c4a3c4b12.png)

代码编辑器工作区中突出显示的行表示当前执行已停止的行。该行还在代码编辑器的最左边标有箭头。您可以继续按*F10*或*F11*（步入）按钮来执行这些行。您必须检查本地窗口，以了解在执行期间本地变量的所有值。

# 通过代码调试

对于真正高级的用户，.NET 类库开放了一些有趣的调试器 API，您可以从源代码中调用调试器手动调试。

从程序的一开始，有一个`DEBUG`预处理变量，它确定项目是否是以调试模式构建的。

您可以按以下方式编写代码：

```cs
#IF DEBUG
/// The code runs only in debug mode
#ENDIF
```

预处理指令实际上是在编译时评估的。这意味着`IF DEBUG`内部的代码只会在以调试模式构建项目时编译到程序集中。

还有其他选项，如`Debug.Assert`、`Debug.Fail`和`Debug.Print`。所有这些选项只在调试模式下工作。在发布模式下，这些 API 将不会被编译。

如果有任何可用的进程，您还可以调用附加到进程的调试器，使用`Debugger.Break()`方法，在当前行中断调试器。您可以检查调试器。`IsAttached`用于查找调试器是否附加到当前进程。

当您开始调试代码时，VS 会启动实际的进程以及一个带有`.vshost`文件名的进程。VS 通过启用部分信任的调试和使用`.vshost`文件来提高*F5*体验，增强了调试体验。这些文件在后台工作，将实际进程与预定义的应用程序域附加以进行调试，以实现无缝的调试体验。

`.vshost`文件仅由 IDE 使用，不应该在实际项目中进行部署。

VS 需要终端服务来运行这些调试器，因为它即使在同一台机器上也会与进程通信。它通过使用终端服务来保持对进程的正常和远程调试的无缝体验。

# 总结

在本章中，我们介绍了 C#语言的基础知识，并介绍了 VS 编辑器。我们还尝试使用命令行和 VS 编写了我们的第一个程序。

在下一章中，我们将继续讨论面向对象的概念和技术，这将使我们能够编写更多的类。


# 第二章：面向对象编程 - 类和对象

**面向对象编程**（**OOP**）是特殊的。如果你在互联网上搜索关于 OOP 的书籍，你会发现数百本关于这个主题的书。但是这个主题永远不会变得陈旧，因为它是行业中最有效、最常用的编程方法。随着对软件开发人员的需求增加，对良好学习内容的需求也在增加。我们在这本书中的方法是以最简单的方式描述 OOP 的概念。理解 OOP 的基础对于想要使用 C#工作的开发人员来说是必须的，因为 C#是一种完全面向对象的语言。在本章中，我们将尝试理解 OOP 到底是什么，以及 OOP 的最基本概念，这些概念对我们开始编程之旅至关重要。在任何其他事情之前，让我们首先分析一下术语**面向对象编程**的含义。

第一个词是**对象**。根据词典的定义，对象是可以看到、感觉到或触摸到的东西；在现实世界中具有物理存在的东西。如果一个物品是虚拟的，这意味着它没有任何物理存在，不被视为对象。第二个词是**面向**，表示方向或目标。例如，当我们说我们面向建筑物时，我们的意思是我们正面朝它。第三个词是**编程**。我相信我不必解释什么是编程，但以防你完全不知道编程是什么并且正在阅读这本书来学习，让我简要解释一下编程是什么。编程只是给计算机指令。由于计算机不会说我们的语言，我们人类必须用计算机能理解的语言给它指令。我们人类称这些指令为**计算机程序**，因为我们正在引导或指导计算机做一件特定的事情。

现在我们知道了这三个关键词的定义，如果我们把所有这些词放在一起，我们就能理解短语“面向对象编程”的含义。OOP 意味着我们编写计算机程序时将对象置于思考的中心。OOP 既不是工具也不是编程语言，它只是一个概念。一些编程语言是设计遵循这个概念的。C#是最流行的面向对象语言之一。还有其他面向对象的语言，比如 Java、C++等等。

在 OOP 中，我们试图将软件组件看作小对象，并在它们之间建立关系来解决问题。你可能在编程世界中遇到过其他编程概念，比如过程式编程、函数式编程和其他类型的编程。有史以来最流行的计算机编程语言之一——C 编程语言是一种过程式编程语言。F#是函数式编程语言的一个例子。

在本章中，我们将涵盖 OOP 的以下主题：

+   OOP 中的类

+   类的一般形式

+   什么是对象？

+   类中的方法

+   OOP 的特点

# OOP 中的类

在 OOP 中，你从类中派生对象。在本节中，我们将更仔细地看看类到底是什么。

类是 OOP 中最重要的概念之一。你可以说它们是 OOP 的构建模块。类可以被描述为对象的蓝图。

类似于一个模板或蓝图，告诉我们这个类的实例将具有什么属性和行为。在大多数情况下，一个类本身实际上不能做任何事情——它只是用来创建对象的。让我们看一个例子来说明我所说的。假设我们有一个`Human`类。在这里，当我们说`Human`时，我们并不是指任何特定的人，而是指一般的人类。一个有两只手、两条腿和一个嘴巴的人，还可以走路、说话、吃饭和思考。这些属性及其行为适用于大多数人类。我知道这对于残疾人来说并非如此，但现在，我们将假设我们的一般人类是健全的，以保持我们的例子简单。因此，当我们在一个对象中看到上述属性和行为时，我们可以很容易地将该对象归类为人类对象或人。这种分类在面向对象编程中称为类。

让我们更仔细地看看`Human`类的属性和行为。人类可以列举数百种属性，但为了简单起见，我们可以说以下是人类的属性：

+   高度

+   体重

+   年龄

我们也可以对行为属性做同样的事情。一个人可以执行数百种特定的行为，但在这里我们只考虑以下行为：

+   走

+   谈

+   吃

# 类的一般形式

要在 C#中创建一个类，必须遵循特定的语法。其一般形式如下：

```cs
class class-name {
    // this is class body
}
```

`class`短语是 C#中的**保留关键字**，用于告诉编译器我们想要创建一个类。要创建一个类，需要在一个空格后放置`class`关键字，然后是类的名称。类的名称可以是以字符或下划线开头的任何内容。类名中也可以包括数字，但不能是类名的第一个字符。在选择的类名之后，必须放置一个开放的大括号，表示类体的开始。您可以在类中添加内容，例如属性和方法，然后用一个闭合的大括号结束类，如下所示：

```cs
class class-name {
 // property 1
 // property 2
 // ...

 // method 1
 // method 2
 // ...
}
```

还有其他关键字可以与类一起使用，以添加更多功能，例如访问修饰符、虚方法、部分方法等。不要担心这些关键字或它们的用途，因为我们将在本书的后面讨论这些内容。

# 编写一个简单的类

现在让我们创建我们的第一个类。假设我们正在为一家银行开发一些软件。我们的应用程序应该跟踪银行的客户及其银行账户，并对这些银行账户执行一些基本操作。由于我们将使用 C#设计我们的应用程序，因此我们必须以面向对象的方式思考我们的应用程序。我们将需要这个应用程序的一些对象，比如客户对象、银行账户对象和其他对象。因此，为了制作这些对象的蓝图，我们必须创建一个`Customer`类和一个`BankAccount`类，以及我们将需要的其他类。让我们首先使用以下代码创建`Customer`类：

```cs
class Customer
{
    public string firstName;
    public string lastName;
    public string phoneNumber;
    public string emailAddress;

    public string GetFullName()
    {
        return firstName + " " + lastName;
    }
}
```

我们从`class`关键字开始，然后是`Customer`类的名称。之后，我们在大括号`{}`内添加了类体。该类拥有的变量是`firstName`、`lastName`、`phoneNumber`和`emailAddress`。该类还有一个名为`GetFullName()`的方法，该方法使用`firstName`和`lastName`字段来准备全名并返回它。

现在让我们使用以下代码创建一个`BankAccount`类：

```cs
class BankAccount {
    public string bankAccountNumber;
    public string bankAccountOwnerName;
    public double amount;
    public datetime openningDate;

    public string Credit(){
        // Amount credited
    }

    public string Debit(){
        // Amount debited
    }
}
```

在这里，我们可以看到我们已经遵循了创建类的类似方法。我们使用了`class`关键字，然后是`BankAccount`类的名称。在名称之后，我们用一个开放的大括号开始了类体，并输入了字段，如`bankAccountNumber`、`bankAccountOwnerName`、`amount`和`openningDate`，然后是两个方法，`Credit`和`Debit`。通过放置一个闭合的大括号，我们结束了类体。

现在，不要担心诸如**public**之类的关键字；当我们讨论访问修饰符时，我们将在本书的后面学习这些关键字。

# 面向对象编程中的对象

我们现在知道了**类**是什么。现在让我们来看看面向对象编程中**对象**是指什么。

对象是类的一个实例。换句话说，对象是类的一个实现。例如，在我们的银行应用程序中，我们有一个`Customer`类，但这并不意味着我们实际上在我们的应用程序中有一个客户。要创建一个客户，我们必须创建`Customer`类的对象。假设我们有一个名为琼斯先生的客户。对于这个客户，我们必须创建`Customer`类的对象，其中人的名字是杰克琼斯。

由于琼斯先生是我们的客户，这意味着他也在我们的银行有一个账户。要为琼斯先生创建一个银行账户，我们必须创建一个`BankAccount`类的对象。

# 如何创建对象

在 C#中，要创建一个类的对象，您必须使用`new`关键字。让我们看一个对象的例子：

```cs
Customer customer1 = new Customer();
```

在这里，我们首先写了`Customer`，这是类的名称。这代表了对象的类型。之后，我们给出了对象的名称，在这种情况下是`customer1`。您可以给该对象任何名称。例如，如果客户是琼斯先生，我们可以将对象命名为`jackJones`。在对象名称之后，我们插入了一个等号（`=`），这意味着我们正在给`customer1`对象赋值。之后，我们输入了一个称为`new`的关键字，这是一个特殊的关键字，告诉编译器创建给定类的新对象。在这里，我们再次给出了`Customer`，并在其旁边加上了`()`。当我们放置`Customer()`时，我们实际上正在调用该类的构造函数。我们将在后续章节中讨论构造函数。

我们可以使用以下代码创建`jackJones`：

```cs
Customer jackJones = new Customer();
```

# C#中的变量

在前面的代码中，您可能已经注意到我们创建了一些变量。**变量**是一种变化的东西，这意味着它不是常数。在编程中，当我们创建一个变量时，计算机实际上会为其分配内存空间，以便可以将变量的值存储在那里。

让我们为我们在上一节中创建的对象的变量分配一些值。我们将首先处理`customer1`对象，如下所示的代码：

```cs
using System;

namespace Chapter2
{
    public class Code_2_2
    {
        static void Main(string[] args)
        {
            Customer customer1 = new Customer();
            customer1.firstName = "Molly";
            customer1.lastName = "Dolly";
            customer1.phoneNumber = "98745632";
            customer1.emailAddress = "mollydolly@email.com";

            Console.WriteLine("First name is " + customer1.firstName);
            Console.ReadKey();
        }
    }

    public class Customer
    {
        public string firstName;
        public string lastName;
        public string phoneNumber;
        public string emailAddress;

        public string GetFullName()
        {
            return firstName + " " + lastName;
        }
    }
}
```

在这里，我们正在给`customer1`对象赋值。该代码指示计算机在内存中创建一个空间并将值存储在其中。稍后，每当您访问变量时，计算机将转到内存位置并找出变量的值。现在，如果我们编写一个语句，将打印`firstName`变量的值以及其前面的附加字符串，它将如下所示：

```cs
Console.WriteLine("First name is " + customer1.firstName);
```

这段代码的输出将如下所示：

```cs
First name is Molly
```

# 类中的方法

让我们谈谈另一个重要的话题——方法。**方法**是在代码文件中编写的可以重复使用的代码片段。一个方法可以包含许多行代码，在调用时将被执行。让我们来看一下方法的一般形式：

```cs
access-modifier return-type method-name(parameter-list) {
    // method body
}
```

我们可以看到方法声明中的第一件事是`access-modifier`。这将设置方法的访问权限。然后，我们有方法的`return-type`，它将保存方法将返回的类型，例如`string`，`int`，`double`或其他类型。之后，我们有`method-name`，然后是括号`()`，表示这是一个方法。在括号中，我们有`parameter-list`。这可以是空的，也可以包含一个或多个参数。最后，我们有花括号`{}`，其中包含方法体。方法将执行的代码放在这里。

按照这种结构的任何代码将被 C#编译器视为方法。

# 创建一个方法

既然我们知道了方法是什么，让我们来看一个例子，如下所示的代码：

```cs
public string GetFullName(string firstName, string lastName){
    return firstName + lastName;
}
```

这段代码将创建一个名为`GetFullName`的方法。这个方法接受两个参数，`firstName`和`lastName`，放在括号里。我们还可以看到，我们必须指定这些参数的类型。在这个特定的例子中，这两个参数的类型都是`string`。

现在，让我们看一下方法体，即大括号之间的部分`{}`。我们可以看到，代码返回`firstName + lastName`，这意味着它正在连接这两个参数`firstName`和`lastName`，并返回`string`。因为我们打算从这个方法返回一个`string`，所以我们将方法的返回类型设置为`string`。另一个需要注意的是，这个方法的访问类型设置为`public`，这意味着任何其他类都可以访问它。

# 类的构造函数

在每个类中，都有一种特殊类型的方法，称为**构造函数**。你可以在一个类中创建一个构造函数并对其进行编程。如果你自己不创建一个，编译器将创建一个非常简单的构造函数并使用它。让我们来看看构造函数是什么，它的作用是什么。

构造函数是在创建类的对象时触发的方法。构造函数主要用于设置类的先决条件。例如，如果你正在创建`Human`类的对象，那个人的对象必须有一个`出生日期`。没有出生日期，就不会有人存在。你可以在构造函数中设置这个要求。你还可以配置构造函数，如果没有提供出生日期，则将出生日期设置为今天。这取决于你的应用程序的需求。另一个例子可能是`bank account`对象，你必须提供银行账户持有人。没有所有者，就不可能存在银行账户，所以你可以在构造函数中设置这个要求。

让我们来看一下构造函数的一般形式，如下面的代码所示：

```cs
access-modifier class-name(parameter-list) {
    // constructor body
}
```

在这里，我们可以看到构造函数和普通方法之间有一个区别，即构造函数没有返回类型。这是因为构造函数不能返回任何东西；它是用于初始化，而不是用于任何其他类型的操作。通常，构造函数的访问类型是`public`，因为否则无法实例化对象。如果你特别想阻止类的对象被实例化，你可以将构造函数设置为`private`。让我们看一个构造函数的例子，如下面的代码所示：

```cs
class BankAccount {
    public string owner;

    public BankAccount(){
        owner = "Some person";
    }
}
```

在这个例子中，我们可以看到有一个名为`BankAccount`的类，它有一个名为`owner`的变量。正如我们所知，没有所有者的银行账户是不存在的，所以我们需要在创建对象时为`owner`赋值。为了创建一个`构造函数`，我们只需将构造函数的访问类型设置为`public`，因为我们希望对象被实例化。我们还可以在构造函数中将银行账户所有者的姓名作为参数，并将其用于赋值给变量，如下面的代码所示：

```cs
class BankAccount {
    public string owner;

    public BankAccount(string theOwner){
        owner = theOwner;
    }
}
```

如果在构造函数中放入参数，那么在初始化对象时，需要传递参数，如下面的代码所示：

```cs
BankAccount account = new BankAccount("Some Person");
```

另一个有趣的事情是，你可以在一个类中有多个构造函数。你可能有一个构造函数带有一个参数，另一个不带任何参数。根据初始化对象的方式，将调用相应的构造函数。让我们看下面的例子：

```cs
class BankAccount {
    public string owner;

    public BankAccount(){
        owner = "Some person";
    }

    public BankAccount(string theOwner){
        owner = theOwner;
    }
}
```

在上面的例子中，我们可以看到`BankAccount`类有两个构造函数。如果在创建`BankAccount`对象时传递参数，它将调用第二个构造函数，这将设置值并创建对象。如果在创建对象时不传递参数，将调用第一个构造函数。如果这两个构造函数都没有，那么这种对象创建方法将不可用。

如果您不创建一个类，那么编译器会为该类创建一个空的构造函数，如下所示：

```cs
class BankAccount {
    public string owner;

    public BankAccount()
    {
    }
}
```

# 面向对象编程的特点

面向对象编程是当今最重要的编程方法之一。整个概念依赖于四个主要思想，被称为**面向对象编程的支柱**。这四个支柱如下：

+   继承

+   封装

+   多态

+   抽象

# 继承

**继承**一词意味着从其他地方接收或衍生出某物。在现实生活中，我们可能会谈论一个孩子从父母那里继承房子。在这种情况下，孩子对房子拥有与父母相同的权力。这种继承的概念是面向对象编程的支柱之一。在编程中，当一个类从另一个类派生时，这被称为继承。这意味着派生类将具有与父类相同的属性。在编程术语中，从另一个类派生的类被称为**父类**，而继承自这些类的类被称为**子类**。

让我们看一个例子：

```cs
public class Fruit {
    public string Name { get; set; }
    public string Color { get; set; }
}

public class Apple : Fruit {
    public int NumberOfSeeds { get; set; }
}
```

在上面的例子中，我们使用了继承。我们有一个名为`Fruit`的父类。这个类包含每种水果都有的共同属性：`Name`和`Color`。我们可以为所有水果使用这个`Fruit`类。

如果我们创建一个名为`Apple`的新类，这个类可以继承`Fruit`类，因为我们知道苹果是一种水果。`Fruit`类的属性也是`Apple`类的属性。如果`Apple`继承`Fruit`类，我们就不需要为`Apple`类编写相同的属性，因为它从`Fruit`类继承了这些属性。

# 封装

**封装**意味着隐藏或覆盖。在 C#中，封装是通过**访问修饰符**实现的。在 C#中可用的访问修饰符如下：

+   公共

+   私有

+   保护

+   内部

+   内部保护

封装是当您想要控制其他类对某个类的访问时使用的。比如说您有一个`BankAccount`类。出于安全原因，让这个类对所有类都可访问并不是一个好主意。最好将其设为`私有`或使用其他类型的访问修饰符。

您还可以限制对类的属性和变量的访问。例如，您可能需要保持`BankAccount`类对某些原因是`public`的，但将`AccountBalance`属性设为`private`，这样除了`BankAccount`类之外，其他类都无法访问这个属性。您可以这样做：

```cs
public class BankAccount {
    private double AccountBalance { get; set; }
}
```

像变量和属性一样，您还可以为方法使用访问修饰符。您可以编写不需要其他类使用的`private`方法，或者您不希望向其他类公开的方法。让我们看下面的例子：

```cs
public class BankAccount{
    private double AccountBalance { get; set; }
    private double TaxRate { get; set; }

    public double GetAccountBalance() {
        double balanceAfterTax = GetBalanceAfterTax();
        return balanceAfterTax;
    }

    private double GetBalanceAfterTax(){
        return AccountBalance * TaxRate;
    }
}
```

在上面的例子中，`GetBalanceAfterTax`方法是一个其他类不需要的方法。我们只想提供税后的`AccountBalance`，所以我们可以将这个方法设为私有。

封装是面向对象编程的一个非常重要的部分，因为它让我们对代码有控制权。

# 抽象

如果某物是抽象的，意味着它在现实中没有实例，但作为一个想法或概念存在。在编程中，我们使用这种技术来组织我们的思想。这是面向对象编程的支柱之一。在 C#中，我们有`abstract`类，它实现了抽象的概念。**抽象类**是没有任何实例的类，实现`abstract`类的类将实现该`abstract`类的属性和方法。让我们看一个`abstract`类的例子，如下面的代码所示：

```cs
public abstract class Vehicle {
    public abstract int GetNumberOfTyres();
}

public class Bicycle : Vehicle {
    public string Company { get; set; }
    public string Model { get; set; }
    public int NumberOfTyres { get; set; }

    public override int GetNumberOfTyres() {
        return NumberOfTyres;
    }
}

public class Car : Vehicle {
    public string Company { get; set; }
    public string Model { get; set; }
    public int FrontTyres { get; set; }
    public int BackTyres { get; set; }

    public override int GetNumberOfTyres() {
        return FrontTyres + BackTyres;
    }
}
```

在前面的例子中，我们有一个名为`Vehicle`的抽象类。它有一个名为`GetNumberOfTyres()`的抽象方法。由于它是一个抽象方法，这个方法必须被实现抽象类的类所覆盖。我们的`Bicycle`和`Car`类实现了`Vehicle`抽象类，因此它们也覆盖了抽象方法`GetNumberOfTyres()`。如果你看一下这两个类中这些方法的实现，你会发现实现是不同的，这是由于抽象性。

# 多态性

多态一词意味着许多形式。要正确理解多态的概念，让我们举个例子。让我们想想一个人，比如比尔·盖茨。我们都知道比尔·盖茨是一位伟大的软件开发者、商人、慈善家，也是一位伟大的人。他是一个人，但他有不同的角色和执行不同的任务。这就是多态性。当比尔·盖茨正在开发软件时，他扮演着软件开发者的角色。他在思考他正在编写的代码。后来，当他成为微软的首席执行官时，他开始管理人员并思考如何发展业务。他是同一个人，但担任不同的角色和不同的责任。

在 C#中，有两种多态性：静态多态性和动态多态性。静态多态性是一种多态性，其中方法的角色在编译时确定，而在动态多态性中，方法的角色在运行时确定。静态多态性的例子包括方法重载和运算符重载。让我们看一个方法重载的例子：

```cs
public class Calculator {
    public int AddNumbers(int firstNum, int secondNum){
        return firstNum + secondNum;
    }

    public double AddNumbers(double firstNum, double secondNum){
        return firstNum + secondNum;
    }
}
```

在这里，我们可以看到我们有两个同名的方法`AddNumbers`。通常情况下，我们不能有两个同名的方法；然而，由于这些方法的参数是不同的，编译器允许方法具有相同的名称。编写一个与另一个方法同名但参数不同的方法称为方法重载。这是一种多态性。

像方法重载一样，运算符重载也是一种静态多态性。让我们看一个运算符重载的例子来证明这一点：

```cs
public class MyCalc
{
    public int a;
    public int b;

    public MyCalc(int a, int b)
    {
        this.a = a;
        this.b = b;
    }

    public static MyCalc operator +(MyCalc a, MyCalc b)
    {
        return new MyCalc(a.a * 3 ,b.b * 3);
    }
}
```

在前面的例子中，我们可以看到加号（+）被重载为另一种计算。因此，如果你对两个`MyCalc`对象求和，你将得到一个重载的结果，而不是正常的和，这种重载发生在编译时，因此它是静态多态性。

**动态多态性**指的是使用抽象类。当你编写一个抽象类时，不能从该抽象类创建实例。当任何其他类使用或实现该抽象类时，该类也必须实现该抽象类的抽象方法。由于不同的类可以实现抽象类并且可以有不同的抽象方法实现，因此实现了多态行为。在这种情况下，我们有相同名称但不同实现的方法。

# 总结

这一章涵盖了类和对象，这是面向对象编程中最重要的构建模块。这些是我们在跳入面向对象编程的任何其他主题之前应该学习的两件事。在继续其他想法之前，确保我们的思想中清楚了这些概念是很重要的。在这一章中，我们了解了类是什么，以及为什么在面向对象编程中需要它。我们还看了如何在 C#中创建一个类以及如何定义一个对象。之后，我们看了类和对象之间的关系以及如何实例化一个类并使用它。我们还讨论了类中的变量和方法。最后，我们涵盖了面向对象编程的四大支柱。在下一章中，我们将学习更多关于继承和类层次结构的知识。


# 第三章：在 C#中实现面向对象编程

在前一章中，我们看了类、对象和面向对象编程的四个原则。在本章中，我们将学习一些使 C#语言成为面向对象编程语言的语言特性。如果不了解这些概念，使用 C#编程写面向对象的代码可能会很困难，或者会阻止你充分发挥其潜力。在第二章，*Hello OOP - Classes and Objects*中，我们学到了抽象、继承、封装和多态是面向对象编程的四个基本原则，但我们还没有学习 C#语言如何实现这些原则。我们将在本章讨论这个话题。

在本章中，我们将涵盖以下主题：

+   接口

+   抽象类

+   部分类

+   封闭类

+   元组

+   属性

+   类的访问修饰符

# 接口

类是一个蓝图，这意味着它包含了实例化对象将具有的成员和方法。**接口**也可以被归类为蓝图，但与类不同，接口没有任何方法实现。接口更像是实现接口的类的指南。

C#中接口的主要特点如下：

+   接口不能有方法体；它们只能有方法签名。

+   接口可以有方法、属性、事件和索引。

+   接口不能被实例化，因此不能创建接口的对象。

+   一个类可以扩展多个接口。

接口的一个主要用途是依赖注入。通过使用接口，可以减少系统中的依赖关系。让我们看一个接口的例子：

```cs
interface IBankAccount {
    void Debit(double amount);
    void Credit(double amount);
}
class BankAccount : IBankAccount {
    public void Debit(double amount){
        Console.WriteLine($"${amount} has been debited from your account!");
    } 
    public void Credit(double amount){
        Console.WriteLine($"${amount} has been credited to your account!");
    }
}
```

在前面的例子中，我们可以看到我们有一个接口，名为`IBankAccount`，它有两个成员：`Debit`和`Credit`。这两个方法在接口中没有实现。在接口中，方法签名更像是实现这个接口的类的指南或要求。如果任何类实现了这个接口，那么这个类必须实现方法体。这是面向对象编程概念继承的一个很好的用法。类将不得不给出在接口中提到的方法的实现。如果类没有实现接口的任何方法，编译器将抛出一个错误，表示类没有实现接口的所有方法。按照语言设计，如果一个类实现了一个接口，那么这个类的所有成员都必须在类中得到处理。因此，在前面的代码中，`BankAccount`类实现了`IBankAccount`接口，这就是为什么`Debit`和`Credit`这两个方法必须被实现的原因。

# 抽象类

**抽象类**是 C#编程语言中的一种特殊类。这个类与接口有类似的功能。例如，抽象类可以有带有和不带有实现的方法。因此，当一个类实现一个抽象类时，这个类必须重写抽象类的**抽象方法**。抽象类的一个主要特征是它不能被实例化。抽象类只能用于继承。它可能有也可能没有抽象方法和访问器。封闭和抽象修饰符不能放在同一个类中，因为它们有完全不同的含义。

让我们看一个抽象类的例子：

```cs
abstract class Animal {
    public string name;
    public int ageInMonths;
    public abstract void Move();
    public void Eat(){
        Console.WriteLine("Eating");
    }
}
class Dog : Animal {
    public override void Move() {
        Console.WriteLine("Moving");
    }
} 
```

在前面的例子中，我们看到`Dog`类实现了`Animal`类，而`Animal`类有一个名为`Move()`的抽象方法，`Dog`类必须重写它。

如果我们尝试实例化抽象类，编译器将抛出一个错误，如下所示：

```cs
using System;
namespace AnimalProject {
    abstract class Animal {
        public string name;
        public int ageInMonths;
        public abstract void Move();
        public void Eat(){
            Console.WriteLine("Eating");
        }
    }
    static void Main(){
        Animal animal = new Animal(); // Not possible as the Animal class is abstract class
```

```cs
    }
}
```

# 部分类

您可以将一个类、结构体或接口分割成可以放在不同代码文件中的较小部分。如果要这样做，必须使用关键字**partial**。即使代码在单独的代码文件中，编译时它们将被视为一个整体类。部分类有许多好处。一个好处是不同的开发人员可以同时在不同的代码文件上工作。另一个好处是，如果您正在使用自动生成的代码，并且想要扩展该自动生成的代码的某些功能，可以在单独的文件中使用部分类。因此，您不是直接触及自动生成的代码，而是在类中添加新功能。

部分类有一些要求，其中之一是所有类必须在其签名中有关键字`partial`。所有部分类还必须具有相同的名称，但文件名可以不同。部分类还必须具有相同的可访问性，如 public、private 等。

以下是部分类的示例：

```cs
// File name: Animal.cs
using System;
namespace AnimalProject {
    public partial class Animal {
        public string name;
        public int ageInMonths;

        public void Eat(){
            Console.WriteLine("Eating");
        }
     }
}
// File name: AnimalMoving.cs
using System;
namespace AnimalProject {
    public partial class Animal {

        public void Move(){
            Console.WriteLine("Moving");
        }
    }
}
```

如前面的代码所示，您可以创建一个类的许多部分类。这将增加代码的可读性，使代码组织更加结构化。

# 密封类

面向对象编程的原则之一是继承，但有时您可能需要限制代码中的继承，以符合应用程序的架构。C#提供了一个名为`sealed`的关键字。如果在类的签名之前放置这个关键字，该类被视为**密封类**。如果一个类是密封的，那个特定的类就不能被其他类继承。如果任何类尝试继承一个密封类，编译器将抛出一个错误。结构体也可以是密封的，在这种情况下，没有类可以继承该结构体。

让我们看一个密封类的示例：

```cs
sealed class Animal {
    public string name;
    public int ageInMonths;
    public void Move(){
        Console.WriteLine("Moving");
    }
    public void Eat(){
        Console.WriteLine("Eating");
    }
}
public static void Main(){
    Animal dog = new Animal();
    dog.name = "Doggy";
    dog.ageInMonths = 1;

    dog.Move();
    dog.Eat();
}
```

在前面的示例中，我们可以看到如何创建一个密封类。只需在`class`关键字之前使用`sealed`关键字即可使类成为密封类。在前面的示例中，我们创建了一个`Animal`密封类，在`main`方法中，我们实例化了该类并使用了它。现在一切都运行正常。然而，如果我们尝试创建一个将继承`Animal`类的`Dog`类，如下面的代码所示，那么编译器将抛出一个错误，说密封的`Animal`类不能被继承：

```cs
class Dog : Animal {
    public char gender;
}
```

这是编译器将显示的屏幕截图：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/6f52ff92-f316-4553-b8e9-d224d8e367c9.png)

# 元组

**元组**是一种保存一组数据的数据结构。当您想要对数据进行分组和使用时，元组通常很有帮助。通常，C#方法只能返回一个值。通过使用元组，可以从方法中返回多个值。`Tuple`类位于`System.Tuple`命名空间下。可以使用`Tuple<>`构造函数或`Tuple`类附带的名为`Create`的抽象方法来创建元组。

您可以固定元组中的任何数据类型，并使用`Item1`、`Item2`等进行访问。让我们看一个例子，以更好地理解这一点：

```cs
var person = new Tuple<string, int, string>("Martin Dew", 42, "Software Developer"); // name, age, occupation
or 
var person = new Tuple.Create("Martin Dew", 42, "Software Developer");
```

让我们看看如何通过以下代码从方法中返回一个元组：

```cs
public static Tuple<string, int, string> GetPerson() {
    var person = new Tuple<string, int, string>("Martin Dew", 42, "Software Developer");
    return person;
}
static void Main() {
    var developer = GetPerson();
    Console.WriteLine("The person is {0}. He is {1} years old. He is a {2}", developer.Item1, developer.Item2, developer.Item3 );
}
```

# 属性

出于安全原因，类的所有字段不应该暴露给外部世界。因此，在 C#中通过属性来暴露私有字段，这些属性是该类的成员。属性下面是称为**访问器**的特殊方法。属性包含两个访问器：`get`和`set`。`get`访问器从字段获取值，而`set`访问器将值设置到字段。属性有一个特殊的关键字，名为`value`。这代表了字段的值。

通过使用访问修饰符，属性可以具有不同的访问级别。属性可以是 `public`、`private`、`read only`、`open for read and write` 和 `write only`。如果只实现了 `set` 访问器，这意味着只有写入权限。如果同时实现了 `set` 和 `get` 访问器，这意味着该属性对读和写都是开放的。

C# 提供了一种聪明的方式来编写 `setter` 和 `getter` 方法。如果你在 C# 中创建一个属性，你不需要为特定字段手动编写 `setter` 和 `getter` 方法。因此，在 C# 中的常见做法是在类中创建属性，而不是为这些字段创建字段和 `setter` 和 `getter` 方法。

让我们看看如何在 C# 中创建属性，如下面的代码所示：

```cs
class Animal {
    public string Name {set; get;}
    public int Age {set; get;}
}
```

`Animal` 类有两个属性：`Name` 和 `Age`。这两个属性都有 `Public` 访问修饰符以及 `setter` 和 `getter` 方法。这意味着这两个属性都对读和写操作是开放的。约定是属性应该使用驼峰命名法。

如果你想修改你的 `set` 和 `get` 方法，你可以这样做：

```cs
class Animal {
    public string Name {
        set {
            name = value;
        }
        get {
            return name;
        }
    }
    public int Age {set; get;}
}
```

在上面的例子中，我们没有使用为 `Name` 属性创建 `setter` 和 `getter` 的快捷方式。我们广泛地写了 `set` 和 `get` 方法应该做什么。如果你仔细看，你会看到 `name` 字段是小写的。这意味着当你使用驼峰命名法创建属性时，一个同名的字段会在内部创建，但是是以帕斯卡命名法。`value` 是一个特殊关键字，实际上代表了该属性的值。

属性在后台工作，这使得代码更加清晰和易于使用。强烈建议您使用属性而不是本地字段。

# 类的访问修饰符

**访问修饰符**，或者**访问修饰符**，是一些保留关键字，用于确定类、方法、属性或其他实体的可访问性。在 C# 中，使用这些访问修饰符实现了面向对象的封装原则。总共有五个访问修饰符。让我们看看这些是什么，它们之间的区别是什么。

# 公共

**公共**访问修饰符意味着对正在修改的实体没有限制。如果将类或成员设置为 `public`，则可以被同一程序集中的其他类或程序、其他程序集甚至安装在运行该程序的操作系统中的其他程序访问。通常，应用程序的起点或主方法被设置为 `public`，这意味着它可以被其他人访问。要使类为 `public`，只需在关键字 class 前面放置一个 `public` 关键字，如下面的代码所示：

```cs
public class Animal {
}
```

上述的 `Animal` 类可以被任何其他类访问，而且由于成员 `Name` 也是公共的，它也可以从任何位置访问。

# 私有

**私有**修饰符是 C# 编程语言中最安全的访问修饰符。通过将类或类的成员设置为 `private`，你确定该类或成员将不允许其他类访问。`private` 成员的范围在类内。例如，如果你创建一个 `private` 字段，那个字段就不能在类外部被访问。那个 `private` 字段只能在该类内部使用。

让我们看一个带有 `private` 字段的类的例子：

```cs
public class Animal {
    private string name;
    public string GetName() {
        return name;
    }
}
```

在这里，由于 `GetName()` 方法和 `private` 字段 `name` 在同一个类中，该方法可以访问该字段。但是，如果 `Animal` 类之外的另一个方法尝试访问 `name` 字段，它将无法访问。

例如，在以下代码中，`Main` 方法正在尝试设置 `private` 字段 name，这是不允许的：

```cs
using System;
namespace AnimalProject {
    static void Main(){
        Animal animal = new Animal();
        animal.name = "Dog"; // Not possible, as the name field is private
        animal.GetName(); // Possible, as the GetName method is public
    }
}
```

# 内部

如果将`internal`设置为访问限定符，这意味着该实体只能在同一程序集内访问。程序集中的所有类都可以访问该类或成员。在.NET 中构建项目时，它会创建一个程序集文件，可以是`dll`或`exe`。一个解决方案中可能有多个程序集，而内部成员只能被那些特定程序集中的类访问。

让我们看一个示例，如下所示的代码：

```cs
using System;
namespage AnimalProject {
    static void Main(){
        Dog dog = new Dog();
        dog.GetName();
    }

    internal class Dog {
        internal string GetName(){
            return "doggy";
        }
    }
}
```

# 受保护的

受保护的成员可以被类本身访问，以及继承该类的子类。除此之外，没有其他类可以访问受保护的成员。受保护的访问修饰符在继承发生时非常有用。

让我们通过以下代码来学习如何使用这个：

```cs
using System;
namespage AnimalProject {
    static void Main(){
        Animal animal = new Animal();
        Dog dog = new Dog();
        animal.GetName(); // Not possible as Main is not a child of Animal
        dog.GetDogName();
    }

    class Animal {
        protected string GetName(){
            return "doggy";
        }
    }
    class Dog : Animal {
        public string GetDogName() {
            return base.GetName();
        }
    }
}
```

# 受保护的内部

**受保护的内部**是受保护的访问修饰符和内部访问修饰符的组合。其访问修饰符为`protected internal`的成员可以被同一程序集中的所有类访问，以及任何继承它的类，无论程序集如何。例如，假设您在名为`Assembly1.dll`的程序集中有一个名为`Animal`的类。在`Animal`类中，有一个受保护的内部方法叫做`GetName`。`Assembly1.dll`中的任何其他类都可以访问`GetName`方法。现在，假设还有另一个名为`Assembly2.dll`的程序集。在`Assembly2.dll`中，有一个名为`Dog`的类，它扩展了`Animal`类。由于`GetName`是受保护的内部，即使`Dog`类在一个单独的程序集中，它仍然可以访问`GetName`方法。

让我们通过以下示例来更清楚地理解这一点：

```cs
//Assembly1.dll
using System;
namespace AnimalProject {
    public class Animal {
        protected internal string GetName(){
            return "Nice Animal";
        }
    }
}
//Assembly2.dll
using System;
namespace AnimalProject2 {
    public class Dog : Animal {
        public string GetDogName(){
            return base.GetName(); // This will work
        }
    }
    public class Cat {
        Animal animal = new Animal();

        public string GetCatName(){
            return animal.GetName(); // This is not possible, as GetName is protected internal
        }
    }
}
```

# 总结

在本章中，我们看了类层次结构和一些其他特性，使 C#编程语言成为面向对象的语言。了解这些概念对于 C#开发人员至关重要。通过了解类层次结构，您可以设计系统，使其解耦且灵活。您需要知道如何在应用程序中使用继承来充分发挥面向对象的优势。接口、抽象类、密封类和部分类将帮助您更好地控制应用程序。在团队中工作时，正确定义类层次结构将有助于您维护代码质量和安全性。

了解元组和属性将提高您的代码清晰度，并在开发应用程序时使您的生活更加轻松。访问限定符是封装的面向对象编程概念的实现。熟悉这些概念非常重要。您需要知道哪些代码片段应该是公开的，哪些应该是私有的，哪些应该是受保护的。如果滥用这些访问限定符，您可能会陷入应用程序存在安全漏洞和代码重复的境地。

在下一章中，我们将讨论对象协作的重要和有趣的主题。


# 第四章：对象协作

正如我们在前几章中看到的，面向对象编程的重点是对象。当我们使用这种方法设计软件时，我们会牢记面向对象编程的概念。我们还会尝试将软件组件分解为更小的对象，并创建对象之间的适当关系，以便它们可以共同工作，为我们提供所需的输出。对象之间的这种关系称为**对象协作**。

在本章中，我们将涵盖以下主题：

+   什么是对象协作？

+   不同类型的协作

+   什么是依赖协作？

+   什么是关联？

+   什么是继承？

# 对象协作的示例

对象协作是面向对象编程中最重要的主题之一。如果对象在程序中不相互协作，就无法实现任何目标。例如，如果我们考虑一个简单的 Web 应用程序，我们可以看到不同对象之间的关系在构建应用程序中起着重要作用。例如，Twitter 有许多对象彼此相关，以使应用程序正常运行。`User`对象包括 Twitter 用户的用户名、密码、名字、姓氏、图片和其他用户相关信息。可能还有另一个名为`Tweet`的对象，其中包括消息、日期和时间、发布推文的用户的用户名以及其他一些属性。还可能有另一个名为`Message`的对象，其中包含消息的内容、消息的发送者和接收者、日期和时间。这是对 Twitter 这样一个大型应用程序的最简单的分解；它几乎肯定包含许多其他对象。但现在，让我们只考虑这三个对象，并尝试找到它们之间的关系。

首先，我们将看一下`User`对象。这是 Twitter 中最重要的对象之一，因为它保存了用户信息。在 Twitter 中，一切都是由用户制作或为用户执行的，因此我们可以假设应该有一些其他对象需要与`User`对象有关系。现在让我们尝试看看`Tweet`对象是否与`User`对象有关系。推文是一条消息，如果`Tweet`对象是公开的，所有用户都应该能看到它。如果是私密的，只有该用户的关注者才能看到。正如我们所看到的，`Tweet`对象与`User`对象有着非常紧密的关系。因此，根据面向对象编程的方法，我们可以说`User`对象在 Twitter 应用程序中与`Tweet`对象协作。

如果我们也尝试分析`User`和`Message`对象之间的关系，我们会发现`Message`对象也与`User`对象有着非常强的关系。消息是由一个用户发送给另一个用户的；因此，没有用户，`Message`对象就没有合适的实现。

但`Tweet`和`Message`对象之间有关系吗？从已经说过的内容来看，我们可以说这两个对象之间没有关系。并不是每个对象都必须与所有其他对象相关联，但一个对象通常至少与另一个对象有关系。现在让我们看看 C#中有哪些不同类型的对象协作。

# C#中不同类型的对象协作

在编程中，对象可以以许多种方式与其他对象协作。然而，在本章中，我们只会讨论三个最重要的协作规则。

我们将首先尝试解释每种类型，看一些示例来帮助我们理解它们。如果你无法将这些概念与你的工作联系起来，你可能很难理解对象协作的重要性，但相信我，这些概念对你成为一名优秀的软件开发人员非常重要。

当你与其他人讨论软件设计时，或者当你设计自己的软件时，所有这些概念和术语都会派上用场。因此，我的建议是专注于理解这些概念，并将它们与你的工作联系起来，以便从这些信息中获益。

现在，让我们看看我们将在本章中讨论的三种协作类型，如下列表所示：

+   依赖

+   联想

+   继承

让我们想象一个应用程序，并尝试将这些协作概念与该应用程序的对象联系起来。当你能将概念与现实世界联系起来时，学习会更容易、更有趣，因此这是我们在接下来的章节中将采取的方法。

# 案例研究

由于本章的主要目标是学习对象协作涉及的概念，而不是设计一个完全成熟的、超级棒的应用程序，我们将以简单和最小的方式设计我们的对象。

对于我们的示例，我们将开发一些餐厅管理软件。这可以是豪华餐厅，也可以是人们来喝咖啡放松的小咖啡馆。在我们的情况下，我们考虑的是价格中等的餐厅。要开始构建这个应用程序，让我们考虑我们需要哪些类和对象。我们将需要一个`Food`类，一个`Chef`类，一个`Waiter`类，也许还需要一个`Beverage`类。

当你读完本章后，不要直接跳到下一章。相反，花一些时间思考一些在本章中没有提到的对象，并尝试分析你所想到的对象之间的关系。这将帮助你发展对对象协作概念的了解。记住：软件开发不是一份打字的工作，它需要大量的脑力工作。因此，你越多地思考这些概念，你在软件开发方面就会变得更加优秀。

现在，让我们看看当我考虑了应该包括在我们想象的餐厅应用程序中的对象时，我想到了哪些对象：

+   食品

+   牛肉汉堡

+   意面

+   饮料

+   可乐

+   咖啡

+   订单

+   订单项目

+   员工

+   厨师

+   服务员

+   食品存储库

+   饮料存储库

+   员工存储库

现在，有些对象可能对你来说并没有太多意义。例如，`FoodRepository`、`BeverageRepository`和`StaffRepository`对象实际上并不是业务对象，而是帮助不同模块在应用程序中相互交互的辅助对象。例如，`FoodRepository`对象将用于从数据库和 UI 保存和检索`Food`对象。同样，`BeverageRepository`对象将处理饮料。我们还有一个名为`Food`的类，它是一种通用类型的类，以及更具体的食品对象，如`Beef Burger`和`Pasta`。这些对象是`Food`对象的子类别。作为软件开发人员，我们已经确定了开发此软件所需的对象。现在，是时候以解决软件将被用于的问题的方式使用这些对象了；然而，在我们开始编写代码之前，我们需要了解并弄清楚对象之间如何关联，以便应用程序能够达到最佳状态。让我们从依赖关系开始。

# 依赖

当一个对象使用另一个无关的对象来执行任务时，它们之间的关系被称为**依赖**。在软件世界中，我们也将这种关系称为**使用关系**。现在，让我们看看我们为餐厅应用程序所考虑的对象之间是否存在任何依赖关系。

如果我们分析一下`FoodRepository`对象，它将从数据库中保存和检索`Food`对象并将其传递给 UI，我们可以说`FoodRepository`对象必须使用`Food`对象。这意味着`Food`和`FoodRepository`对象之间的关系是一种依赖关系。如果我们考虑在前端创建新的`Food`对象时的流程，该对象将被传递给`FoodRepository`。然后，`FoodRepository`将把`Food`对象序列化为数据库数据以便将其保存在数据库中。如果`FoodRepository`不使用`Food`对象，那它怎么知道要序列化和存储在数据库中的内容呢？在这里，`FoodRepository`必须与`Food`对象存在依赖关系。让我们看看这段代码：

```cs
public class Food {
 public int? FoodId {get;set;}
 public string Name {get;set;}
 public decimal Price {get;set;}
}

public class FoodRepository {
 public int SaveFood(Food food){
 int result = SaveFoodInDatabase(food);
 return result;
 }

 public Food GetFood(int foodId){
 Food result = new Food();
 result = GetFoodFromDatabaseById(foodId);
 return result;
 }
}
```

在上面的代码中，我们可以看到`FoodRepository`类有两个方法。一个方法是`SaveFood`，另一个是`GetFood`。

`SaveFood`方法涉及获取一个`Food`对象并将其保存在数据库中。在将食品项目保存在数据库后，它将新创建的`foodId`返回给`FoodRepository`。然后，`FoodRepository`将新创建的`FoodId`传递给 UI，通知用户食品项目创建成功。另一方面，另一个`GetFood`方法从 UI 获取一个 ID 作为参数，并检查该 ID 是否是有效输入。如果是，`FoodRepository`将`FoodId`传递给`databasehandler`对象，该对象在数据库中搜索食品并将其映射回作为`Food`对象。之后，将`Food`对象返回给视图。

在这里，我们可以看到`FoodRepository`对象需要使用`Food`对象来完成其工作。这种关系称为**依赖关系**。我们还可以使用*uses a*短语来识别这种关系。`FoodRepository`使用`Food`对象来保存食品在数据库中。

与`FoodRepository`一样，`BeverageRepository`对`Beverage`对象做了同样的事情：它在数据库和 UI 中保存和检索饮料对象。现在让我们看看`BeverageRepository`的代码是什么样的：

```cs
public class Beverage {
    public int? BeverageId {get;set;}
    public string Name { get;set;}
    public decimal Price {get;set;}
}

public class BeverageRepository {
    public int SaveBeverage(Beverage beverage){
        int result = SaveBeverageInDatabase(beverage);
        return result;
    }

public Beverage GetBeverage(int beverageId) {
        Beverage result = new Beverage();
        result = GetBeverageFromDatabaseById(beverageId);
        return result;
    }
}
```

如果你看一下前面的代码，你会发现`BeverageRepository`有两个方法：`SaveBeverage`和`GetBeverage`。这两个方法都使用`Beverage`对象。这意味着`BeverageRepository`与`Beverage`对象存在依赖关系。

现在让我们来看一下我们迄今为止创建的两个类，如下所示的代码：

```cs
public class FoodRepository {
    public int SaveFood(Food food){
        int result = SaveFoodInDatabase(food);
        return result;
    }

    public Food GetFood(int foodId){
        Food result = new Food();
        result = GetFoodFromDatabaseById(foodId);
        return result;
    }
}

public class BeverageRepository {
    public int SaveBeverage(Beverage beverage){
        int result = SaveBeverageInDatabase(beverage);
        return result;
    }

public Beverage GetBeverage(int beverageId){
        Beverage result = new Beverage();
        result = GetBeverageFromDatabaseById(beverageId);
        return result;
    }
}
```

一个对象可以使用依赖关系与多个对象相关联。在面向对象编程中，这种关系非常常见。

让我们来看另一个依赖关系的例子。`程序员`和`计算机`之间的关系可能是一种依赖关系。怎么样？我们知道`程序员`很可能是一个人，而`计算机`是一台机器。`程序员`使用`计算机`来编写计算机程序，但`计算机`不是`程序员`的属性。`程序员`*使用*计算机，并且这不一定是一个特定的计算机——可以是任何计算机。那么我们可以说`程序员`和`计算机`之间的关系是一种依赖关系吗？是的，我们当然可以。让我们看看如何在代码中表示这一点：

```cs
public class Programmer {
    public string Name { get; set; }
    public string Age { get; set; }
    public List<ProgrammingLanguages> ProgrammingLanguages { get; set; }
    public ProgrammerType Type { get; set; } // Backend/Frontend/Full Stack/Web/Mobbile etc

    public bool WorkOnAProject(Project project, Computer computer){
        // use the provided computer to do the project
        // here we can see that the programmer is using a computer
    }
}

public class Computer {
    public int Id { get; set; }
    public string ModelNumber { get; set; }
    public Company Manufacturer { get; set; }
    public Ram Ram { get; set; }
    public MotherBoard MotherBoard { get; set; }
    public CPU CPU { get; set; }
}
```

在上面的例子中，我们可以清楚地看到`程序员`和`计算机`之间有一种依赖关系，但这并不总是如此：这取决于你如何设计你的对象。如果你设计了`程序员`类，使得每个程序员都必须有一台专用的计算机，你可以在`程序员`类中使用`计算机`作为属性，那么程序员和计算机之间的关系将会改变。因此，关系取决于对象的设计方式。

我在本节的主要目标是澄清依赖关系。我希望依赖关系的本质现在对你来说是清楚的。

现在让我们看看依赖关系在**统一建模语言**（**UML**）图表中是如何绘制的，如下图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/4ad50b5f-04ab-4fb3-829c-3e23eef738c8.png)

用实线表示依赖关系。

# 关联

另一种关系类型是关联关系。这种关系类型不同于依赖关系。在这种关系类型中，一个对象知道另一个对象并与之相关联。这种关系是通过将一个对象作为另一个对象的属性来实现的。在软件社区中，这种关系类型也被称为*拥有*关系。例如，汽车拥有引擎。如果你能想到任何可以用*拥有*短语来关联的对象，那么这种关系就是关联关系。在我们的汽车例子中，引擎是汽车的一部分。没有引擎，汽车无法执行任何功能。虽然引擎本身是一个独立的对象，但它是汽车的一部分，因此汽车和引擎之间存在关联。

这种关联关系可以分为以下两类：

+   聚合

+   组合

让我们看看这两种关系是什么，它们之间有什么不同。

# 聚合

当一个对象在其属性中有另一个独立的对象时，这被称为**聚合关系**。让我们看看前一节中的例子，试着看看这是否是一个聚合关系。

前面的例子是关于汽车和引擎之间的关系。我们都知道汽车必须有引擎，这就是为什么引擎是汽车的属性，如下代码所示：

```cs
public class Car {
    public Engine Engine { get; set; }
    // Other properties and methods
}
```

现在的问题是，这种关系是什么类型？决定因素是引擎是一个独立的对象，可以独立于汽车运行。制造商在制造汽车的其他零件时并不制造引擎：他们可以单独制造它。即使没有汽车，引擎也可以进行测试，甚至用于其他目的。因此，我们可以说汽车与引擎之间的关系是一种*聚合关系*。

现在让我们来看一下我们的餐厅管理软件的例子。如果我们分析`Food`和`Chef`对象之间的关系，很明显没有厨师就没有食物。必须有人来烹饪、烘焙和准备食物，食物本身无法做到这一点。因此，我们可以说食物有厨师。这意味着`Food`对象应该有一个名为`Chef`的属性，用来保存该`Food`的`Chef`对象。让我们来看一下这种关系的代码：

```cs
public class Food {
    public int? FoodId {get;set;}
    public string Name { get; set; }
    public string Price { get; set; }
    public Chef Chef { get; set; }
}
```

如果我们考虑`Beverage`对象，每种饮料都必须有一个公司或制造商。例如，商业饮料是由百事公司、可口可乐公司等公司生产的。这些公司生产的饮料是它们的合法财产。饮料也可以在本地制造，这种情况下公司名称将是当地商店的名称。然而，这里的主要观点是饮料必须有一个制造商公司。让我们看看`Beverage`类在代码中是什么样子的：

```cs
public class Beverage {
    public int? BeverageId {get;set;}
    public string Name { get; set; }
    public string Price { get; set; }
    public Manufacturer Manufacturer { get; set; }
}
```

在这两个例子中，`Chef`和`Manufacturer`对象都是`Food`和`Beverage`的属性。我们也知道`Chef`或`Manufacturer`公司是独立的。因此，`Food`和`Chef`之间的关系是一种聚合关系。`Beverage`和`Manufacturer`也是如此。

为了让事情更清晰，让我们看另一个聚合的例子。我们用于编程或执行任何其他任务的计算机由不同的组件组成。我们有主板、RAM、CPU、显卡、屏幕、键盘、鼠标和许多其他东西。一些组件与计算机具有聚合关系。例如，主板、RAM 和 CPU 是构建计算机所需的内部组件。所有这些组件都可以独立存在于计算机之外，因此所有这些组件都与计算机具有聚合关系。让我们看看`Computer`类如何与`MotherBoard`类相关联的以下代码：

```cs
public class Computer {
    public int Id { get; set; }
    public string ModelNumber { get; set; }
    public Company Manufacturer { get; set; }
    public Ram Ram { get; set; }
    public MotherBoard MotherBoard { get; set; }
    public CPU CPU { get; set; }
}

public class Ram {
    // Ram properties and methods
}

public class CPU {
    // CPU properties and methods
}

public class MotherBoard {
    // MotherBoard properties and methods
}
```

现在，让我们看看在 UML 图中如何绘制聚合关系。如果我们尝试用 RAM、CPU 和主板显示前面的计算机类聚合关系，那么它看起来会像下面这样：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/e0467b14-4fd0-4131-a993-b34defc2694b.jpg)

实线和菱形用于表示聚合关系。菱形放在持有属性的类的一侧，如下图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/a1c0dbc5-417b-4e68-86b3-c2d464f80da0.jpg)

# 组合

组合关系是一种关联关系。这意味着一个对象将另一个对象作为其属性，但与聚合的不同之处在于，在组合中，作为属性的对象不能独立存在；它必须借助另一个对象才能发挥作用。如果我们考虑`Chef`和`Manufacturer`类，这些类的存在并不完全依赖于`Food`和`Beverage`类。相反，这些类可以独立存在，因此具有聚合关系。

然而，如果我们考虑`Order`和`OrderItem`对象之间的关系，我们会发现`OrderItem`对象没有没有`Order`就没有意义。让我们看一下`Order`类的以下代码：

```cs
public class Order {
    public int OrderId { get; set; }
    public List<OrderItem> OrderItems { get; set; }
    public DateTime OrderTime { get; set; }
    public Customer Customer { get; set; }
}
```

在这里，我们可以看到`Order`对象中有一个`OrderItems`列表。这些`OrderItems`是顾客订购的`Food`项目。顾客可以订购一个菜或多个菜，这就是为什么`OrderItems`是一个列表类型。现在是时候证明我们的想法了。`OrderItem`是否真的与`Order`有组合关系？我们有没有犯任何错误？我们是否把聚合关系当作组合关系了？

要确定它是哪种类型的关联关系，我们必须问自己一些问题。`OrderItem`可以在没有`Order`的情况下存在吗？如果不能，那为什么？它是一个独立的对象！然而，如果你再深入思考一下，你会意识到没有`Order`，没有`OrderItem`可以存在，因为顾客必须订购商品，没有`Order`对象，`OrderItem`对象就无法跟踪。`OrderItem`无法提供给任何顾客，因为没有关于`OrderItem`是为哪个顾客的数据。因此，我们可以说`OrderItem`与`Order`对象有组合关系。

让我们看另一个组合的例子。在我们的学校系统中，我们有学生、老师、科目和成绩，对吧？现在，我会说`Subject`对象和`Grade`对象之间的关系是组合关系。让我证明我的答案。看看这两个类的以下代码：

```cs
public class Subject {
    public int Id { get; set; }
    public string Name { get; set; }
    public Grade Grade { get; set; }
}

public class Grade {
    public int Id { get; set; }
    public double Mark { get; set; }
    public char GradeSymbol { get; set; } // A, B, C, D, F etc
}
```

在这里，我们可以看到`Grade`对象保存了学生在特定科目的考试成绩。它还保存了`GradeSymbol`，比如`A`，`B`或`F`，取决于学校的评分规则。我们可以在`Subject`类中看到有一个叫做`Grade`的属性。这个属性保存了特定`Subject`对象的成绩。如果我们只是单独考虑`Grade`而不是与`Subject`类关联，我们会有点困惑，想知道成绩是为哪个科目的。

因此，`Grade`和`Subject`之间的关系是组合关系。

让我们看看如何在 UML 图中展示组合关系，使用`Subject`和`Grade`的前面的例子：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/21c4e007-c706-470e-9cb2-be5c87ffceae.jpg)

使用实线和黑色菱形表示组合关系。菱形放置在持有属性的类的一侧：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/44e0de3f-109f-439e-a5a6-c1b9c0288418.png)

# 继承

这是面向对象编程的四大支柱之一。**继承**是一个对象继承或重用另一个对象的属性或方法。被继承的类称为**基类**，继承基类的类通常称为**派生类**。继承关系可以被视为一个*是一个*的关系。例如，意大利面是一种`Food`。`Pasta`对象在数据库中有一个唯一的 ID，还有其他属性，比如名称、价格和厨师。因此，由于`Pasta`满足`Food`类的所有属性，它可以继承`Food`类并使用`Food`类的属性。让我们看一下代码：

```cs
public class Pasta : Food {
    public string Type { get; set; }
    public Sauce Sauce { get; set; }
    public string[] Spices { get; set; }
}
```

对于饮料也是一样的。例如，`Coffee`是一种饮料，具有`Beverage`对象具有的所有属性。咖啡有名称和价格，可能有糖、牛奶和咖啡豆。让我们编写`Coffee`类，看看它是什么样子的：

```cs
public class Coffee : Beverage {
    public int Sugar { get; set; }
    public int Milk { get; set; }
    public string LocationOfCoffeeBean { get; set; }
}
```

因此，我们可以说`Coffee`正在继承`Beverage`类。在这里，`Coffee`是派生类，`Beverage`是基类。

在之前的例子中，我们使用了`Programmer`对象。在这种情况下，你认为`Programmer`类实际上可以继承`Human`类吗？是的，当然可以。在这个例子中，程序员无非就是一个人。如果我们看一下`Programmer`的属性和`Human`的属性，我们会发现有一些共同的属性，比如姓名、年龄等。因此，我们可以修改`Programmer`类的代码如下：

```cs
public class Programmer : Human {
 // Name, Age properties can be inherited from Human
 public List<ProgrammingLanguages> ProgrammingLanguages { get; set; }
 public ProgrammerType Type { get; set; } // Backend/Frontend/Full Stack/Web/Mobbile etc

 public bool WorkOnAProject(Project project, Computer computer){
 // use the provided computer to do the project
 // here we can see that the programmer is using a computer
 }
}
```

现在，让我们看看如何为我们的`Programmer`类绘制 UML 图：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/3db18b8b-3f8e-460b-bf50-c4bd42c833d5.png)

继承由一条实线和一个三角形符号表示。这个三角形指向超类的方向：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/f549a7f4-2baa-4c24-865b-5fcfdc37d65d.png)

# 总结

我们在本章中看到的对象协作类型是 C#中最常用的类型。在设计应用程序或架构软件时，对象协作非常重要。它将定义软件的灵活性，可以添加多少新功能，以及维护代码的难易程度。对象协作非常重要。

在下一章中，我们将讨论异常处理。这也是编程中非常重要的一部分。
