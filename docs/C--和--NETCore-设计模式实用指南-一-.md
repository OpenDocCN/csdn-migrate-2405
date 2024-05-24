# C# 和 .NETCore 设计模式实用指南（一）

> 原文：[`zh.annas-archive.org/md5/99BBE5B6F8F1801CD147129EA46FD82D`](https://zh.annas-archive.org/md5/99BBE5B6F8F1801CD147129EA46FD82D)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

本书的目的是让读者对现代软件开发中的模式有一个广泛的理解，同时通过具体示例深入了解更多细节。在开发解决方案时使用的模式数量是庞大的，而且通常开发人员在不知情的情况下使用模式。本书涵盖了从低级代码到在云中运行的解决方案中使用的高级概念的模式。

尽管许多所呈现的模式不需要特定的语言，但 C#和.NET Core 将用于许多示例。选择 C#和.NET Core 是因为它们的流行和设计，支持从简单的控制台应用程序到大型企业分布式系统的解决方案构建。

本书涵盖了大量的模式，是对许多模式的很好的介绍，同时允许对一组特定模式进行更深入、实践性的探讨。所涵盖的具体模式之所以被选择，是因为它们说明了特定的观点或模式的方面。提供了额外资源的参考，以便读者深入研究特别感兴趣的模式。

从简单的网站到大型企业分布式系统，正确的模式可以决定成功、长寿的解决方案和因性能不佳和成本高而被视为失败的解决方案之间的区别。本书涵盖了许多可以应用于构建解决方案的模式，以处理在商业竞争中所需的不可避免的变化，以及实现现代应用程序所期望的健壮性和可靠性。

# 这本书是为谁写的

目标受众是在协作环境中工作的现代应用程序开发人员。故意地，这代表了许多不同的背景和行业，因为这些模式可以应用于各种解决方案。由于本书深入代码来解释所涵盖的模式，读者应该具有软件开发背景——本书不应被视为一本*如何编程*的书，而更像是一本*如何更好地编程*的书。因此，目标受众将从初级开发人员到高级开发人员、软件架构师和设计师都有，对于一些读者，内容将是新的；对于其他人，它将是一个复习。

# 本书涵盖的内容

第一章，《.NET Core 和 C#中面向对象编程概述》，包括了**面向对象编程**（**OOP**）的概述以及它如何应用于 C#。本章作为对 OOP 和 C#的重要构造和特性的复习，包括继承、封装和多态性。

第二章，《现代软件设计模式和原则》，对现代软件开发中使用的不同模式进行了分类和介绍。本章调查了许多模式和目录，如 SOLID、四人帮和企业集成模式，以及软件开发生命周期和其他软件开发实践的讨论。

第三章，《实现设计模式-基础部分 1》，深入探讨了用于在 C#中构建应用程序的设计模式。通过开发一个示例应用程序、测试驱动开发、最小可行产品和四人帮的其他模式来进行说明。

第四章，《实现设计模式-基础部分 2》，继续深入探讨了用于在 C#中构建应用程序的设计模式。还将介绍依赖注入和控制反转的概念，继续探讨包括单例模式和工厂模式在内的设计模式。

第五章，《实现设计模式-.NET Core》，在第三章和第四章的基础上，探讨了.NET Core 提供的模式。将使用.NET Core 框架重新讨论几种模式，包括依赖注入和工厂模式。

第六章，《为 Web 应用程序实现设计模式-第一部分》，继续探索.NET Core，通过继续构建示例应用程序来查看 Web 应用程序开发中支持的特性。本章提供了创建初始 Web 应用程序的指导，讨论了 Web 应用程序的重要特性，并介绍了如何创建 CRUD 网站页面。

第七章，《为 Web 应用程序实现设计模式-第二部分》，继续探讨使用.NET Core 进行 Web 应用程序开发，包括不同的架构模式和解决方案安全模式。还涵盖了身份验证和授权。还添加了单元测试，包括使用 Moq 模拟框架。

第八章，《.NET Core 中的并发编程》，深入讨论了 C#和.NET Core 应用程序开发中的并发性。探讨了 Async/await 模式，以及关于多线程和并发性的部分。还涵盖了并行 LINQ，包括延迟执行和线程优先级。

第九章，《函数式编程实践》，探讨了.NET Core 中的函数式编程。这包括说明支持函数式编程的 C#语言特性，并将其应用于示例应用程序，包括应用策略模式。

第十章，《响应式编程模式和技术》，继续探讨.NET Core Web 应用程序开发，探讨了用于构建响应式和可扩展网站的响应式编程模式和技术。在本章中，探讨了响应式编程的原则，包括响应式和 IObservable 模式。还讨论了不同的框架，包括流行的.NET Rx 扩展，以及**Model-view-viewmodel**（MVVM）模式的示例。

第十一章，《高级数据库设计和应用技术》，探讨了数据库设计中使用的模式，包括对数据库的讨论。展示了应用命令查询责任分离模式的实际示例，包括使用分类账式数据库设计。

第十二章，《云编程》，探讨了应用程序开发在云解决方案中的应用，包括可扩展性、可用性、安全性、应用程序设计和 DevOps 这五个关键问题。解释了云解决方案中使用的重要模式，包括不同类型的扩展和事件驱动架构、联合安全、缓存和遥测中使用的模式。

附录 A，《杂项最佳实践》，总结了模式的讨论，涵盖了其他模式和最佳实践。这包括用例建模、最佳实践以及空间架构和容器化应用程序等其他模式。

# 为了充分利用本书

本书假定读者对面向对象编程和 C#有一定的了解。尽管本书涵盖了高级主题，但它并不是一本全面的开发指南。相反，本书的目标是通过提供大量的模式、实践和原则来提高开发人员和设计师的技能水平。使用工具箱的类比，本书通过从低级代码设计到更高级的架构，以及当今常用的重要模式和原则，为现代应用程序开发人员提供了大量工具。

本书介绍了以下主要观点，这些观点是对读者知识的补充：

+   通过使用 C#7.x 和.NET Core 2.2 的编码示例，了解更多关于 SOLID 原则和最佳实践。

+   深入理解经典设计模式（四人帮模式）。

+   使用 C#语言的函数式编程原则及其工作示例。

+   架构模式（MVC、MVVM）的真实世界示例。

+   了解原生云、微服务等。

# 下载示例代码文件

您可以从您在[www.packt.com](http://www.packt.com)的帐户中下载本书的示例代码文件。如果您在其他地方购买了本书，您可以访问[www.packt.com/support](http://www.packt.com/support)并注册，以便文件直接发送到您的邮箱。

您可以按照以下步骤下载代码文件：

1.  登录或注册[www.packt.com](http://www.packt.com)。

1.  选择“支持”选项卡。

1.  单击“下载代码和勘误表”。

1.  在搜索框中输入书名，然后按照屏幕上的说明操作。

下载文件后，请确保使用最新版本的解压缩软件解压缩文件夹：

+   WinRAR/7-Zip for Windows

+   Zipeg/iZip/UnRarX for Mac

+   7-Zip/PeaZip for Linux

本书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/Hands-On-Design-Patterns-with-C-and-.NET-Core`](https://github.com/PacktPublishing/Hands-On-Design-Patterns-with-C-and-.NET-Core)。如果代码有更新，将在现有的 GitHub 存储库上进行更新。

我们还有来自丰富书籍和视频目录的其他代码包，可在**[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)**上找到。去看看吧！

# 实际运行的代码

单击以下链接查看代码实际运行情况：[`bit.ly/2KUuNgQ`](http://bit.ly/2KUuNgQ)。

# 下载彩色图像

我们还提供了一个 PDF 文件，其中包含本书中使用的屏幕截图/图表的彩色图像。您可以在这里下载：[`static.packt-cdn.com/downloads/9781789133646_ColorImages.pdf`](https://static.packt-cdn.com/downloads/9781789133646_ColorImages.pdf)。

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄。例如：“三个`CounterA()`、`CounterB()`和`CounterC()`方法代表一个单独的票务收集柜台。”

代码块设置如下：

```cs
3-counters are serving...
Next person from row
Person A is collecting ticket from Counter A
Person B is collecting ticket from Counter B
Person C is collecting ticket from Counter C
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目将以粗体显示：

```cs
public bool UpdateQuantity(string name, int quantity)
{
    lock (_lock)
    {
        _books[name].Quantity += quantity;
    }

    return true;
}
```

任何命令行输入或输出都以以下形式编写：

```cs
dotnet new sln
```

**粗体**：表示新术语、重要单词或屏幕上看到的单词。例如，菜单或对话框中的单词会以这种方式出现在文本中。例如：“从创建新产品，您可以添加新产品，而编辑将为您提供更新现有产品的功能。”

警告或重要说明会显示为这样。

提示和技巧会显示为这样。


# 第一部分：C#和.NET Core 中设计模式的基本要点

在本节中，读者将获得对设计模式的新视角。我们将学习面向对象编程、模式、实践和 SOLID 原则。到本节结束时，读者将准备好创建自己的设计模式。

本节包括以下章节：

+   第一章，*在.NET Core 和 C#中的面向对象编程概述*

+   第二章，*现代软件设计模式和原则*


# 第一章：.NET Core 和 C#中 OOP 的概述

20 多年来，最流行的编程语言都是基于面向对象编程（OOP）原则的。OOP 语言的流行主要是因为能够将复杂逻辑抽象成一个称为对象的结构，这样更容易解释，更重要的是在应用程序中更容易重用。实质上，OOP 是一种软件设计方法，即使用包含数据和功能的对象概念来开发软件的模式。随着软件行业的成熟，OOP 中出现了用于常见问题的模式，因为它们在解决相同问题时在不同的上下文和行业中都是有效的。随着软件从大型机移动到客户服务器，然后再到云端，出现了额外的模式，以帮助降低开发成本和提高可靠性。本书将探讨设计模式，从 OOP 的基础到面向云端软件的架构设计模式。

OOP 基于对象的概念。这个对象通常包含数据，称为属性和字段，以及代码或行为，称为方法。

设计模式是软件程序员在开发过程中面临的一般问题的解决方案，是根据经验构建的，这些解决方案经过多位开发人员在各种情况下的试验和测试。使用基于以前活动的模式的好处确保不会一遍又一遍地重复相同的努力。此外，使用模式会增加一种可靠性感，即问题将在不引入缺陷或问题的情况下得到解决。

本章将回顾 OOP 以及它如何应用于 C#。请注意，这只是一个简要介绍，不是 OOP 或 C#的完整入门；相反，本章将详细介绍这两个方面，以便向您介绍后续章节中将涵盖的设计模式。本章将涵盖以下主题：

+   OOP 的讨论以及类和对象的工作原理

+   继承

+   封装

+   多态性

# 技术要求

本章包含各种代码示例来解释这些概念。代码保持简单，仅用于演示目的。大多数示例涉及使用 C#编写的.NET Core 控制台应用程序。

要运行和执行代码，您需要以下内容：

+   Visual Studio 2019（您也可以使用 Visual Studio 2017 版本 3 或更高版本运行应用程序）

+   .NET Core

+   SQL Server（本章中使用 Express Edition）

# 安装 Visual Studio

为了运行这些代码示例，您需要安装 Visual Studio 或更高版本（也可以使用您喜欢的 IDE）。要做到这一点，请按照以下说明进行操作：

1.  从以下链接下载 Visual Studio：[`docs.microsoft.com/en-us/visualstudio/install/install-visual-studio`](https://docs.microsoft.com/en-us/visualstudio/install/install-visual-studio)。

1.  按照链接中包含的安装说明进行操作。有多个版本的 Visual Studio 可用；在本章中，我们使用的是 Windows 版的 Visual Studio。

# 设置.NET Core

如果您没有安装.NET Core，您需要按照以下说明进行操作：

1.  从以下链接下载.NET Core：[`www.microsoft.com/net/download/windows`](https://www.microsoft.com/net/download/windows)。

1.  按照相关库中的安装说明进行操作：[`dotnet.microsoft.com/download/dotnet-core/2.2`](https://dotnet.microsoft.com/download/dotnet-core/2.2)。

完整的源代码可以在 GitHub 上找到。本章中显示的源代码可能不完整，因此建议您检索源代码以运行示例（[`github.com/PacktPublishing/Hands-On-Design-Patterns-with-C-and-.NET-Core/tree/master/Chapter1`](https://github.com/PacktPublishing/Hands-On-Design-Patterns-with-C-and-.NET-Core/tree/master/Chapter1)）。

# 本书中使用的模型

作为学习辅助，本书将包含许多 C#代码示例，以及图表和图像，以帮助尽可能清楚地描述特定概念。本书不是**统一建模语言**（**UML**）书；然而，对于了解 UML 的人来说，许多图表应该看起来很熟悉。本节提供了本书中将使用的类图的描述。

在这里，一个类将被定义为包括由虚线分隔的字段和方法。如果讨论重要，可通过`-`表示私有，`+`表示公共，`#`表示受保护，`~`表示内部来指示可访问性。以下截图通过显示一个带有私有`_name`变量和公共`GetName()`方法的`Car`类来说明这一点：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/3d37335f-9e59-494a-bdf4-67d30cd832d0.png)

当展示对象之间的关系时，用实线表示关联，用开放的菱形表示聚合，用填充的菱形表示组合。如果讨论重要，多重性将显示在相关类旁边。以下图表说明了`Car`类有一个**Owner**和最多三个**Passengers**；它由四个**Wheels**组成：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/cc1fc18d-dc06-4b38-ae24-f7898b19c050.png)

**继承**使用实线在基类上显示一个开放的三角形。以下图表显示了`Account`基类与`CheckingAccount`和`SavingsAccount`子类之间的关系：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/7fe47763-223e-4667-8003-38f5116f7c82.png)

**接口**的显示方式与继承类似，但它们使用虚线以及额外的`<<interface>>`标签，如下图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/b9fa7abd-7fda-4877-acf8-971a8c3fc429.png)

本节概述了本书中使用的模型。选择这种风格/方法是因为希望大多数读者都能熟悉。

# 面向对象编程和类与对象的工作原理

面向对象编程是指使用类定义的对象的软件编程方法。这些定义包括字段，有时称为属性，用于存储数据和方法以提供功能。第一种面向对象编程语言是称为 Simula 的真实系统模拟语言（[`en.wikipedia.org/wiki/Simula`](https://en.wikipedia.org/wiki/Simula)），于 1960 年在挪威计算中心开发。第一种纯面向对象编程语言诞生于 1970 年，名为 Smalltalk（[`en.wikipedia.org/wiki/Smalltalk`](https://en.wikipedia.org/wiki/Smalltalk)）。这种语言旨在为 Alan Kay 创建的个人计算机 Dynabook（[`history-computer.com/ModernComputer/Personal/Dynabook.html`](http://history-computer.com/ModernComputer/Personal/Dynabook.html)）编程。从那时起，有几种面向对象编程语言发展而来，最流行的是 Java、C++、Python 和 C#。

面向对象编程是基于包含数据的对象。面向对象编程范式允许开发人员将代码组织成一个称为对象的抽象或逻辑结构。对象可以包含数据和行为。

通过使用面向对象的方法，我们正在做以下事情：

+   模块化：在这里，一个应用程序被分解成不同的模块。

+   **重用软件**：在这里，我们重新构建或组合一个应用程序，使用不同的（即现有的或新的）模块。

在接下来的章节中，我们将更详细地讨论和理解面向对象编程的概念。

# 解释面向对象编程

早期的编程方法有局限性，通常变得难以维护。面向对象编程提供了一种新的软件开发范式，优于其他方法。将代码组织成对象的概念并不难解释，这对于采用新模式是一个巨大的优势。可以从现实世界中找到许多例子来解释这个概念。复杂的系统也可以用更小的构建块（即*对象*）来描述。这使开发人员能够单独查看解决方案的各个部分，同时了解它们如何适应整个解决方案。

考虑到这一点，让我们定义一个程序如下：

程序是一系列指令的列表，指示语言编译器该做什么。

正如你所看到的，对象是以一种逻辑方式组织指令的一种方式。回到房子的例子，建筑师的指令帮助我们建造房子，但它们不是房子本身。相反，建筑师的指令是房子的抽象表示。类似的，类定义了对象的特征。然后从类的定义中创建对象。这通常被称为*实例化对象*。

为了更近距离地了解面向对象编程，我们应该提到另外两种重要的编程方法：

+   **结构化编程**：这是由 Edsger W. Dijkstra 在 1966 年创造的一个术语。结构化编程是一种解决问题的编程范式，将 1000 行代码分成小部分。这些小部分通常被称为**子程序**、**块结构**、**for**和**while**循环等。使用结构化编程技术的语言包括 ALGOL、Pascal、PL/I 等。

+   **过程式编程**：这是从结构化编程派生出来的一种范式，简单地基于我们如何进行调用（也称为**过程调用**）。使用过程式编程技术的语言包括 COBOL、Pascal 和 C。一个最近的例子是 2009 年发布的 Go 编程语言。

过程调用

程序调用是指一组语句，称为*过程*，被激活。有时这被称为*调用*的过程。

这两种方法的主要问题是，一旦程序变得更加复杂和庞大，就不容易管理。更复杂和更大的代码库会使这两种方法变得紧张，导致难以理解和难以维护的应用程序。为了克服这些问题，面向对象编程提供了以下功能：

+   继承

+   封装

+   多态

在接下来的几节中，我们将更详细地讨论这些功能。

继承、封装和多态有时被称为面向对象编程的三大支柱。

在开始之前，让我们讨论一些在面向对象编程中发现的结构。

# 一个类

**类**是描述对象的方法和变量的组或模板定义。换句话说，类是一个蓝图，包含了对所有类实例（称为对象）通用的变量和方法的定义。

让我们看一下以下代码示例：

```cs
public class PetAnimal
{
    private readonly string PetName;
    private readonly PetColor PetColor;

    public PetAnimal(string petName, PetColor petColor)
    {
        PetName = petName;
        PetColor = petColor;
    }

    public string MyPet() => $"My pet is {PetName} and its color is {PetColor}.";
}
```

在前面的代码中，我们有一个名为`PetAnimal`的类，其中有两个名为`PetName`和`PetColor`的私有字段，以及一个名为`MyPet()`的方法。

# 一个对象

在现实世界中，对象共享两个特征，即状态和行为。换句话说，我们可以说每个对象都有一个名字，颜色，等等；这些特征只是对象的状态。让我们以任何类型的宠物为例：狗和猫都有一个名字，它们被称为。所以，以这种方式，我的狗叫 Ace，我的猫叫 Clementine。同样，狗和猫有特定的行为，例如，狗会叫，猫会喵喵叫。

在*解释面向对象编程*部分，我们讨论了面向对象编程是一种旨在将状态或结构（数据）与行为（方法）结合起来以提供软件功能的编程模型。在之前的例子中，宠物的不同状态构成了实际数据，而宠物的行为则是方法。

对象通过属性存储信息（即数据），并通过方法展示其行为。

在面向对象的语言（如 C#）中，对象是类的一个实例。在我们之前的例子中，现实世界中的对象`Dog`将是`PetAnimal`类的一个对象。

对象可以是具体的（即现实世界中的对象，如狗或猫，或任何类型的文件，如物理文件或计算机文件），也可以是概念性的，如数据库模式或代码蓝图。

以下代码片段显示了一个对象包含数据和方法，以及如何使用它：

```cs
namespace OOPExample
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("OOP example");
            PetAnimal dog = new PetAnimal("Ace", PetColor.Black);
            Console.WriteLine(dog.MyPet());
            Console.ReadLine();
            PetAnimal cat = new PetAnimal("Clementine", PetColor.Brown);
            Console.WriteLine(cat.MyPet());
            Console.ReadLine();
        }
    }
}
```

在上面的代码片段中，我们创建了两个对象：`dog`和`cat`。这些对象是`PetAnimal`类的两个不同实例。可以看到，包含有关于动物的数据的字段或属性是通过构造方法赋值的。构造方法是用于创建类的实例的特殊方法。

让我们在下图中将这个例子可视化：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/831ba13f-467e-4a85-9819-0d19dad2a714.png)

上图是我们之前代码示例的图示表示，我们创建了两个不同的`Dog`和`Cat`对象，它们属于`PetAnimal`类。图示相对容易理解；它告诉我们`Dog`类的对象是`PetAnimal`类的一个实例，`Cat`对象也是如此。

# 关联

对象关联是面向对象编程的一个重要特性。现实世界中对象之间存在关系，在面向对象编程中，关联允许我们定义*拥有*关系；例如，自行车*拥有*骑手或猫*拥有*鼻子。

*拥有*关系的类型如下：

+   **关联**：关联用于描述对象之间的关系，不涉及所有权的描述，例如汽车和人之间的关系。汽车和人之间有一个关系，比如司机。一个人可以驾驶多辆汽车，一辆汽车也可以被多个人驾驶。

+   **聚合**：聚合是关联的一种特殊形式。与关联类似，对象在聚合中有自己的生命周期，但它涉及所有权。这意味着子对象不能属于另一个父对象。聚合是一种单向关系，对象的生命周期彼此独立。例如，子对象和父对象的关系是一种聚合，因为每个子对象都有一个父对象，但并不是每个父对象都有一个子对象。

+   **组合**：组合指的是一种依赖关系；它代表了两个对象之间的关系，其中一个对象（子对象）依赖于另一个对象（父对象）。如果父对象被删除，所有子对象将自动被删除。让我们以房子和房间为例。一个房子有多个房间，但一个房间不能属于多个房子。如果我们拆除了房子，房间将自动被删除。

让我们通过扩展之前的宠物示例并引入`PetOwner`类来在 C#中说明这些概念。`PetOwner`类可以与一个或多个`PetAnimal`实例相关联。由于`PetAnimal`类可以存在有或没有主人，所以这种关系是一种聚合。`PetAnimal`与`PetColor`相关联，在这个系统中，只有当`PetColor`与`PetAnimal`相关联时，`PetColor`才存在，使得关联成为一种组合。

以下图示说明了聚合和组合：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/d132053d-f041-4a26-a000-436ad74ddaa6.png)

上述模型是基于 UML 的，可能对你来说不太熟悉；所以，让我们指出一些关于图表的重要事项。类由一个包含类名以及其属性和方法（用虚线分隔）的方框表示。现在先忽略名称前面的符号，例如`+`或`-`，因为我们将在后面讨论封装时涵盖访问修饰符。关联关系用连接类的线表示。在组合的情况下，父类的一侧使用实心菱形，而聚合的情况下，父类的一侧使用空心菱形。此外，注意图表支持表示可能的子类数量的多重性值。在图表中，`PetOwner`类可以有`0`个或更多个`PetAnimal`类（注意*****表示关联数量没有限制）。

UML

UML 是一种专门为软件工程开发的建模语言。它已经发展了 20 多年，由**对象管理组**（**OMG**）管理。你可以参考[`www.uml.org/`](http://www.uml.org/)了解更多细节。

# 接口

在 C#中，**接口**定义了一个对象包含的内容，或者说它的契约；特别是对象的方法、属性、事件或索引。然而，接口不提供实现。接口不能包含属性。这与基类形成对比，基类既提供了契约又提供了实现。实现接口的类必须实现接口中指定的所有内容。

抽象类

抽象类是接口和基类之间的混合体，因为它既提供实现和属性，也提供必须在子类中定义的方法。

签名

术语*签名*也可以用来描述对象的契约。

# 继承

面向对象编程中最重要的概念之一是继承。类之间的继承允许我们定义一个*是一种*关系；例如，汽车*是一种*车辆。这个概念的重要性在于它允许相同类型的对象共享相似的特征。假设我们有一个在线书店管理不同产品的系统。我们可能有一个类用于存储关于实体书的信息，另一个类用于存储关于数字或在线书的信息。两者之间相似的特征，比如名称、出版商和作者，可以存储在另一个类中。然后实体书和数字书类可以继承自另一个类。

在继承中有不同的术语来描述类：*子类*或*派生类*继承自另一个类，而被继承的类可以被称为*父类*或*基类*。

在接下来的部分，我们将更详细地讨论继承。

# 继承的类型

继承帮助我们定义一个子类。这个子类继承了父类或基类的行为。

在 C#中，继承是用冒号(`:`)来表示的。

让我们来看看不同类型的继承：

+   **单继承**：作为最常见的继承类型，单继承描述了一个类从另一个类派生出来的情况。

让我们重新审视之前提到的`PetAnimal`类，并且使用继承来定义我们的`Dog`和`Cat`类。通过继承，我们可以定义一些两者共有的属性。例如，宠物的名字和颜色是共有的，所以它们会位于一个基类中。猫或狗的具体信息会在特定的类中定义；例如，猫和狗发出的声音。下图展示了一个`PetAnimal`基类和两个子类：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/dcf9f6cd-c935-4973-a43a-4139b3d6ff1d.png)

C#只支持单继承。

+   **多重继承**：多重继承发生在派生类继承多个基类的情况下。诸如 C++的语言支持多重继承。C#不支持多重继承，但我们可以通过接口实现类似多重继承的行为。

您可以参考以下帖子了解有关 C#和多重继承的更多信息：

[`blogs.msdn.microsoft.com/csharpfaq/2004/03/07/why-doesnt-c-supportmultiple-inheritance/`](https://blogs.msdn.microsoft.com/csharpfaq/2004/03/07/why-doesnt-c-supportmultiple-inheritance/)。

+   **分层继承**：当多个类从另一个类继承时发生分层继承。

+   **多级继承**：当一个类从已经是派生类的类中派生时，称为多级继承。

+   **混合继承**：混合继承是多种继承的组合。

C#不支持混合继承。

+   **隐式继承**：.NET Core 中的所有类型都隐式继承自`System.Object`类及其派生类。

# 封装

封装是面向对象编程中的另一个基本概念，其中类的细节，即属性和方法，可以在对象外部可见或不可见。通过封装，开发人员提供了关于如何使用类以及如何防止类被错误处理的指导。例如，假设我们只允许使用`AddPet（PetAnimal）`方法添加`PetAnimal`对象。我们可以通过将`PetOwner`类的`AddPet（PetAnimal）`方法设置为可用，同时将`Pets`属性限制为`PetAnimal`类之外的任何内容来实现这一点。在 C#中，通过将`Pets`属性设置为私有，这是可能的。这样做的一个原因是，如果需要在添加`PetAnimal`类时需要额外的逻辑，例如记录或验证`PetOwner`类是否可以拥有宠物。

C#支持可以在项上设置的不同访问级别。项可以是类、类的属性或方法，或枚举：

+   **Public**：表示该项可以在外部访问。

+   **Private**：表示只有对象可以访问该项。

+   **Protected**：表示只有对象（以及扩展了该类的类的对象）可以访问属性或方法。

+   **Internal**：表示只有同一程序集中的对象可以访问该项。

+   **Protected Internal**：表示只有对象（以及扩展了该类的类的对象）可以在同一程序集中访问属性或方法。

在下图中，访问修饰符已应用于`PetAnimal`：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/d4bb8946-f4a2-416c-938c-f39dc212a197.png)

例如，宠物的名称和颜色被设置为私有，以防止外部访问`PetAnimal`类。在这个例子中，我们限制了`PetName`和`PetColor`属性，所以只有`PetAnimal`类才能访问它们，以确保只有基类`PetAnimal`可以更改它们的值。`PetAnimal`的构造函数被保护，以确保只有子类可以访问它。在这个应用程序中，只有与`Dog`类相同的库中的类才能访问`RegisterInObedienceSchool（）`方法。

# 多态性

使用相同接口处理不同对象的能力称为多态性。这为开发人员提供了通过编写单个功能来构建灵活性的能力，只要它们共享一个公共接口，就可以应用于不同的形式。在面向对象编程中有不同的多态性定义，我们将区分两种主要类型：

+   **静态或早期绑定**：当应用程序编译时发生这种形式的多态性。

+   **动态或晚期绑定**：当应用程序正在运行时发生这种形式的多态性。

# 静态多态性

静态或早期绑定多态发生在编译时，主要由方法重载组成，其中一个类具有多个具有相同名称但具有不同参数的方法。这通常有助于传达方法背后的含义或简化代码。例如，在计算器中，为不同类型的数字添加多个方法比为每种情况使用不同的方法名更可读；让我们比较以下代码：

```cs
int Add(int a, int b) => a + b;
float Add(float a, float b) => a + b;
decimal Add(decimal a, decimal b) => a + b;
```

在下面的代码中，展示了相同功能的代码，但没有重载`Add()`方法：

```cs
int AddTwoIntegers(int a, int b) => a + b;
float AddTwoFloats(float a, float b) => a + b;
decimal AddTwoDecimals(decimal a, decimal b) => a + b;
```

在宠物的例子中，主人会使用不同的食物来喂养`cat`和`dog`类的对象。我们可以定义`PetOwner`类，其中有两个`Feed()`方法，如下所示：

```cs
public void Feed(PetDog dog)
{
    PetFeeder.FeedPet(dog, new Kibble());
}

public void Feed(PetCat cat)
{
    PetFeeder.FeedPet(cat, new Fish());
}
```

两种方法都使用`PetFeeder`类来喂养宠物，而`dog`类被给予`Kibble`，`cat`实例被给予`Fish`。`PetFeeder`类在*泛型*部分中描述。

# 动态多态

动态或后期绑定多态发生在应用程序运行时。有多种情况会发生这种情况，我们将涵盖 C#中的三种常见形式：接口、继承和泛型。

# 接口多态

接口定义了类必须实现的签名。在`PetAnimal`的例子中，假设我们将宠物食物定义为提供一定数量的能量，如下所示：

```cs
public interface IPetFood
{
    int Energy { get; }
}
```

接口本身不能被实例化，但描述了`IPetFood`的实例必须实现的内容。例如，`Kibble`和`Fish`可能提供不同级别的能量，如下面的代码所示：

```cs
public class Kibble : IPetFood
{
    public int Energy => 7;
}

public class Fish : IPetFood
{
    int IPetFood.Energy => 8;
}
```

在上面的代码片段中，`Kibble`提供的能量比`Fish`少。

# 继承多态

继承多态允许在运行时确定功能，类似于接口，但适用于类继承。在我们的例子中，宠物可以被喂食，所以我们可以定义一个新的`Feed(IPetFood)`方法，它使用之前定义的接口：

```cs
public virtual void Feed(IPetFood food)
{
    Eat(food);
}

protected void Eat(IPetFood food)
{
    _hunger -= food.Energy;
}
```

上面的代码表明，`PetAnimal`的所有实现都将有一个`Feed(IPetFood)`方法，子类可以提供不同的实现。`Eat(IPetFood food)`没有标记为虚拟，因为预期所有`PetAnimal`对象都将使用该方法，而无需覆盖其行为。它还被标记为受保护，以防止从对象外部访问它。

虚方法不必在子类中定义；这与接口不同，接口中的所有方法都必须被实现。

`PetDog`不会覆盖基类的行为，因为狗既吃`Kibble`又吃`Fish`。而猫更挑剔，如下面的代码所示：

```cs
public override void Feed(IPetFood food)
{
    if (food is Fish)
    {
        Eat(food);
    }
    else
    {
        Meow();
    }
}
```

使用 override 关键字，`PetCat`将改变基类的行为，导致猫只吃鱼。

# 泛型

泛型定义了可以应用于类的行为。这种常用形式在集合中使用，无论对象的类型如何，都可以使用相同的处理对象的方法。例如，可以使用相同的逻辑处理字符串列表或整数列表，而无需区分特定类型。

回到宠物，我们可以为喂养宠物定义一个通用类。这个类简单地给宠物和食物喂食，如下面的代码所示：

```cs
public static class PetFeeder
{
    public static void FeedPet<TP, TF>(TP pet, TF food) where TP : PetAnimal
                                                    where TF : IPetFood 
    {
        pet.Feed(food); 
    }
}
```

这里有几件有趣的事情要指出。首先，由于类和方法都被标记为静态，所以类不必被实例化。使用方法签名`FeedPet<TP, TF>`描述了通用方法。`where`关键字用于指示对`TP`和`TF`的额外要求。在这个例子中，`where`关键字将`TP`定义为必须是`PetAnimal`类型，而`TF`必须实现`IPetFood`接口。

# 摘要

在本章中，我们讨论了面向对象编程及其三个主要特征：继承、封装和多态性。使用这些特性，应用程序中的类可以被抽象化，以提供易于理解且受到保护的定义，以防止其被用于与其目的不一致的方式。这是面向对象编程与一些早期类型的软件开发语言（如结构化和过程化编程）之间的重要区别。通过抽象功能，增加了代码重用和维护的能力。

在下一章中，我们将讨论企业软件开发中使用的各种模式。我们将涵盖编程模式以及软件开发原则和在**软件开发生命周期**（**SDLC**）中使用的模式。

# 问题

以下问题将帮助您巩固本章中包含的信息：

1.  术语“晚绑定”和“早绑定”是指什么？

1.  C#支持多重继承吗？

1.  在 C#中，可以使用什么级别的封装来防止外部库访问类？

1.  聚合和组合之间有什么区别？

1.  接口可以包含属性吗？（这有点像是一个陷阱问题。）

1.  狗会吃鱼吗？


# 第二章：现代软件设计模式和原则

在上一章中，讨论了**面向对象编程**（**OOP**），为了探索不同的模式做了准备。由于许多模式依赖于 OOP 中的概念，因此介绍和/或重新访问这些概念非常重要。类之间的继承允许我们定义*是一种类型的关系*。这提供了更高程度的抽象。例如，通过继承，可以进行比较，比如*猫*是一种*动物*，*狗*是一种*动物*。封装提供了一种控制类的细节的可见性和访问性的方法。多态性提供了使用相同接口处理不同对象的能力。通过 OOP，可以实现更高级别的抽象，提供了一种更易于管理和理解的方式来处理大型解决方案。

本章目录和介绍了现代软件开发中使用的不同模式。本书对模式的定义非常宽泛。在软件开发中，模式是软件程序员在开发过程中面临的一般问题的任何解决方案。它们建立在经验之上，是对什么有效和什么无效的总结。此外，这些解决方案经过了许多开发人员在各种情况下的试验和测试。使用模式的好处基于过去的活动，既在不重复努力方面，也在保证问题将被解决而不会引入缺陷或问题方面。

特别是在考虑到技术特定模式时，有太多内容无法在一本书中涵盖，因此本章将重点介绍特定模式，以说明不同类型的模式。我们试图根据我们的经验挑选出最常见和最有影响力的模式。在随后的章节中，将更详细地探讨特定模式。

本章将涵盖以下主题：

+   包括 SOLID 在内的设计原则

+   模式目录，包括**四人帮**（**GoF**）模式和**企业集成模式**（**EIP**）

+   软件开发生命周期模式

+   解决方案开发、云开发和服务开发的模式和实践

# 技术要求

本章包含各种代码示例来解释这些概念。代码保持简单，仅用于演示目的。大多数示例涉及使用 C#编写的.NET Core 控制台应用程序。

要运行和执行代码，您需要以下内容：

+   Visual Studio 2019（您也可以使用 Visual Studio 2017 版本 3 或更高版本运行应用程序）

+   .NET Core

+   SQL Server（本章中使用 Express Edition）

# 安装 Visual Studio

要运行这些代码示例，您需要安装 Visual Studio，或者您可以使用您喜欢的 IDE。要做到这一点，请按照以下说明进行操作：

1.  从以下链接下载 Visual Studio：[`docs.microsoft.com/en-us/visualstudio/install/install-visual-studio`](https://docs.microsoft.com/en-us/visualstudio/install/install-visual-studio)。

1.  按照包含的安装说明进行安装。Visual Studio 有多个版本可供安装。在本章中，我们使用的是 Windows 版的 Visual Studio。

# 设置.NET Core

如果您尚未安装.NET Core，您需要按照以下说明进行操作：

1.  从以下链接下载.NET Core：[`www.microsoft.com/net/download/windows`](https://www.microsoft.com/net/download/windows)。

1.  遵循安装说明和相关库：[`dotnet.microsoft.com/download/dotnet-core/2.2`](https://dotnet.microsoft.com/download/dotnet-core/2.2)。

完整的源代码可在 GitHub 上找到。本章中显示的源代码可能不完整，因此建议检索源代码以运行示例：[`github.com/PacktPublishing/Hands-On-Design-Patterns-with-C-and-.NET-Core/tree/master/Chapter2`](https://github.com/PacktPublishing/Hands-On-Design-Patterns-with-C-and-.NET-Core/tree/master/Chapter2)。

# 设计原则

可以说，良好软件开发最重要的方面是软件设计。开发既功能准确又易于维护的软件解决方案具有挑战性，并且在很大程度上依赖于使用良好的开发原则。随着时间的推移，项目初期做出的一些决定可能导致解决方案变得过于昂贵，无法维护和扩展，迫使系统进行重写，而具有良好设计的其他解决方案可以根据业务需求和技术变化进行扩展和调整。有许多软件开发设计原则，本节将重点介绍一些您需要熟悉的流行和重要原则。

# DRY – 不要重复自己

**不要重复自己**（**DRY**）原则的指导思想是重复是时间和精力的浪费。重复可以采取过程和代码的形式。多次处理相同的需求是一种精力浪费，并在解决方案中造成混乱。首次查看此原则时，可能不清楚系统如何最终会重复处理过程或代码。例如，一旦有人确定了如何满足某个需求，为什么其他人还要努力复制相同的功能？在软件开发中存在许多这种情况，了解为什么会发生这种情况是理解这一原则的价值的关键。

以下是代码重复的一些常见原因：

+   **理解不足**：在大型解决方案中，开发人员可能不完全了解现有解决方案和/或不知道如何应用抽象来解决现有功能的问题。

+   **复制粘贴**：简而言之，代码在多个类中重复，而不是重构解决方案以允许多个类访问共享功能。

# KISS – 保持简单愚蠢

与 DRY 类似，**保持简单愚蠢**（**KISS**）多年来一直是软件开发中的重要原则。KISS 强调简单应该是目标，复杂应该被避免。关键在于避免不必要的复杂性，从而减少出错的可能性。

# YAGNI – 你不会需要它

**你不会需要它**（**YAGNI**）简单地表明功能只有在需要时才应该添加。有时在软件开发中，存在一种倾向，即为设计未来可能发生变化的情况而进行*未雨绸缪*。这可能会产生实际上当前或未来实际上不需要的需求：

“只有在实际需要时才实现事物，而不是在你预见到需要它时实现。”

*- Ron Jeffries*

# MVP – 最小可行产品

通过采用**最小可行产品**（**MVP**）方法，一项工作的范围被限制在最小的需求集上，以便产生一个可用的交付成果。MVP 经常与敏捷软件开发结合使用（请参见本章后面的*软件开发生命周期模式*部分），通过将需求限制在可管理的数量，可以进行设计、开发、测试和交付。这种方法非常适合较小的网站或应用程序开发，其中功能集可以在单个开发周期中进展到生产阶段。

在第三章中，*实现设计模式 - 基础部分 1*，MVP 将在一个虚构的场景中进行说明，该技术将被用于限制变更范围，并在设计和需求收集阶段帮助团队集中精力。

# SOLID

SOLID 是最有影响力的设计原则之一，我们将在第三章中更详细地介绍它，*实现设计模式-基础部分 1*。实际上，SOLID 由五个设计原则组成，其目的是鼓励更易于维护和理解的设计。这些原则鼓励更易于修改的代码库，并减少引入问题的风险。

在第三章中，*实现设计模式-基础部分 1*，将更详细地介绍 SOLID 在 C#应用中的应用。

# 单一责任原则

一个类应该只有一个责任。这一原则的目标是简化我们的类并在逻辑上对其进行结构化。具有多个责任的类更难理解和修改，因为它们更复杂。在这种情况下，责任简单地是变化的原因。另一种看待责任的方式是将其定义为功能的单一部分：

“一个类应该有一个，且仅有一个，改变的理由。”

*- Robert C. Martin*

# 开闭原则

开闭原则最好用面向对象编程来描述。一个类应该设计为具有继承作为扩展功能的手段。换句话说，在设计类时应该考虑到变化。通过定义并使用类实现的接口，应用了开闭原则。类是*开放*进行修改，而其描述，即接口，是*关闭*进行修改。

# 里氏替换原则

能够在运行时替换对象是里氏替换原则的基础。在面向对象编程中，如果一个类继承自基类或实现了一个接口，那么它可以被引用为基类或接口的对象。这可以用一个简单的例子来描述。

我们将为动物定义一个接口，并实现两种动物，`Cat`和`Dog`，如下所示：

```cs
interface IAnimal
{
     string MakeNoise();
}
class Dog : IAnimal
{
   public string MakeNoise()
     {
        return "Woof";
     }
}
class Cat : IAnimal
{
    public string MakeNoise()
    {
        return "Meouw";
    }
}
```

然后我们可以将`Cat`和`Dog`称为动物，如下所示：

```cs
var animals = new List<IAnimal> { new Cat(), new Dog() };

foreach(var animal in animals)
{
    Console.Write(animal.MakeNoise());
}
```

# 接口隔离原则

与单一责任原则类似，接口隔离原则规定接口应该仅包含与单一责任相关的方法。通过减少接口的复杂性，代码变得更容易重构和理解。遵循这一原则在系统中的一个重要好处是通过减少依赖关系来帮助解耦系统。

# 依赖反转原则

**依赖反转原则**（DIP），也称为依赖注入原则，规定模块不应该依赖于细节，而应该依赖于抽象。这一原则鼓励编写松散耦合的代码，以增强可读性和维护性，特别是在大型复杂的代码库中。

# 软件模式

多年来，许多模式已被编制成目录。本节将以两个目录作为示例。第一个目录是**GoF**的一组与面向对象编程相关的模式。第二个与系统集成相关，保持技术中立。在本章末尾，还有一些额外目录和资源的参考资料。

# GoF 模式

可能最有影响力和知名度的面向对象编程模式集合来自*GoF*的*可重用面向对象软件元素的设计模式*一书。该书中的模式的目标是在较低级别上，即对象创建和交互，而不是更大的软件架构问题。该集合包括可以应用于特定场景的模板，旨在产生坚实的构建模块，同时避免面向对象开发中的常见陷阱。

*Erich Gamma, John Vlissides, Richard Helm*和*Ralph Johnson*因在 1990 年代的广泛有影响的出版物而被称为 GoF。书籍*设计模式：可重用面向对象软件的元素*已被翻译成多种语言，并包含 C++和 Smalltalk 的示例。

该收藏分为三类：创建模式、结构模式和行为模式，将在以下部分进行解释。

# 创建模式

以下五种模式涉及对象的实例化：

+   **抽象工厂**：一种用于创建属于一组类的对象的模式。具体对象在运行时确定。

+   **生成器**：用于更复杂对象的有用模式，其中对象的构建由构建类外部控制。

+   **工厂方法**：一种用于在运行时确定特定类的对象的模式。

+   **原型**：用于复制或克隆对象的模式。

+   **单例**：用于强制类的仅一个实例的模式。

在第三章中，*实现设计模式 - 基础部分 1*，将更详细地探讨抽象工厂模式。在第四章中，*实现设计模式 - 基础部分 2*，将详细探讨单例和工厂方法模式，包括使用.NET Core 框架对这些模式的支持。

# 结构模式

以下模式涉及定义类和对象之间的关系：

+   **适配器**：用于提供两个不同类之间的匹配的模式

+   **桥接**：一种允许替换类的实现细节而无需修改类的模式

+   **组合**：用于创建树结构中类的层次结构

+   **装饰器**：一种用于在运行时替换类功能的模式

+   **外观**：用于简化复杂系统的模式

+   **享元**：用于减少复杂模型的资源使用的模式

+   **代理**：用于表示另一个对象，允许在调用和被调用对象之间增加额外的控制级别

# 装饰器模式

为了说明结构模式，让我们通过一个示例来更详细地了解装饰器模式。这个示例将在控制台应用程序上打印消息。首先，定义一个基本消息，并附带一个相应的接口：

```cs
interface IMessage
{
    void PrintMessage();
}

abstract class Message : IMessage
{
    protected string _text;
    public Message(string text)
    {
        _text = text;
    }
    abstract public void PrintMessage();
}
```

基类允许存储文本字符串，并要求子类实现`PrintMessage()`方法。然后将扩展为两个新类。

第一个类是`SimpleMessage`，它将给定文本写入控制台：

```cs
class SimpleMessage : Message
{
    public SimpleMessage(string text) : base(text) { }

    public override void PrintMessage()
    {
        Console.WriteLine(_text);
    }
}
```

第二个类是`AlertMessage`，它还将给定文本写入控制台，但也执行蜂鸣：

```cs
class AlertMessage : Message
{
    public AlertMessage(string text) : base(text) { }
    public override void PrintMessage()
    {
        Console.Beep();
        Console.WriteLine(_text);
    }
}
```

两者之间的区别在于`AlertMessage`类将发出蜂鸣声，而不仅仅像`SimpleMessage`类一样将文本打印到屏幕上。

接下来，定义一个基本装饰器类，该类将包含对`Message`对象的引用，如下所示：

```cs
abstract class MessageDecorator : IMessage
{
    protected Message _message;
    public MessageDecorator(Message message)
    {
        _message = message;
    }

    public abstract void PrintMessage();
}
```

以下两个类通过为现有的`Message`实现提供附加功能来说明装饰器模式。

第一个是`NormalDecorator`，它打印前景为绿色的消息：

```cs
class NormalDecorator : MessageDecorator
{
    public NormalDecorator(Message message) : base(message) { }

    public override void PrintMessage()
    {
        Console.ForegroundColor = ConsoleColor.Green;
        _message.PrintMessage();
        Console.ForegroundColor = ConsoleColor.White;
    }
}
```

`ErrorDecorator`使用红色前景色，使消息在打印到控制台时更加显著：

```cs

class ErrorDecorator : MessageDecorator
{
    public ErrorDecorator(Message message) : base(message) { }

    public override void PrintMessage()
    {
        Console.ForegroundColor = ConsoleColor.Red;
        _message.PrintMessage();
        Console.ForegroundColor = ConsoleColor.White;
    }
}
```

`NormalDecorator`将以绿色打印文本，而`ErrorDecorator`将以红色打印文本。这个示例的重要之处在于装饰器扩展了引用`Message`对象的行为。

为了完成示例，以下显示了如何使用新消息：

```cs
static void Main(string[] args)
{
    var messages = new List<IMessage>
    {
        new NormalDecorator(new SimpleMessage("First Message!")),
        new NormalDecorator(new AlertMessage("Second Message with a beep!")),
        new ErrorDecorator(new AlertMessage("Third Message with a beep and in red!")),
        new SimpleMessage("Not Decorated...")
    };
    foreach (var message in messages)
    {
        message.PrintMessage();
    }
    Console.Read();
}
```

运行示例将说明如何使用不同的装饰器模式来更改引用功能，如下所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/38b95d57-b790-4f1f-bb20-6984784a8d82.png)

这是一个简化的例子，但想象一种情景，项目中添加了一个新的要求。系统不再使用蜂鸣声，而是应该播放感叹号的系统声音。

```cs
class AlertMessage : Message
{
    public AlertMessage(string text) : base(text) { }
    public override void PrintMessage()
    {
        System.Media.SystemSounds.Exclamation.Play();
        Console.WriteLine(_text);
    }
}
```

由于我们已经有了处理这个的结构，所以修正是一个一行的更改，如前面的代码块所示。

# 行为模式

以下行为模式可用于定义类和对象之间的通信：

+   **责任链**：处理一组对象之间请求的模式

+   **命令**：用于表示请求的模式

+   **解释器**：一种用于定义程序中指令的语法或语言的模式

+   **迭代器**：一种在不详细了解集合中元素的情况下遍历集合的模式

+   **中介者**：简化类之间通信的模式

+   **备忘录**：用于捕获和存储对象状态的模式

+   **观察者**：一种允许对象被通知另一个对象状态变化的模式

+   **状态**：一种在对象状态改变时改变对象行为的模式

+   **策略**：一种在运行时应用特定算法的模式

+   **模板方法**：一种定义算法步骤的模式，同时将实现细节留在子类中

+   **访问者**：一种促进数据和功能之间松散耦合的模式，允许添加额外操作而无需更改数据类

# 责任链

您需要熟悉的一个有用模式是责任链模式，因此我们将以此为例使用它。使用此模式，我们将设置一个处理请求的集合或链。理念是请求将通过每个类，直到被处理。这个例子使用了一个汽车服务中心，每辆汽车将通过中心的不同部分，直到服务完成。

让我们首先定义一组标志，用于指示所需的服务：

```cs
[Flags]
enum ServiceRequirements
{
    None = 0,
    WheelAlignment = 1,
    Dirty = 2,
    EngineTune = 4,
    TestDrive = 8
}
```

在 C#中，`FlagsAttribute`是使用位字段来保存一组标志的好方法。单个字段将用于指示通过位操作*打开*的枚举值。

`Car`将包含一个字段来捕获所需的维护以及一个在服务完成时返回 true 的字段：

```cs
class Car
{
    public ServiceRequirements Requirements { get; set; }

    public bool IsServiceComplete
    {
        get
        {
            return Requirements == ServiceRequirements.None;
        }
    }
}
```

指出的一件事是，一辆“汽车”被认为在所有要求都完成后其服务已完成，这由`IsServiceComplete`属性表示。

将使用抽象基类来表示我们的每个服务技术人员，如下所示：

```cs
abstract class ServiceHandler
{
    protected ServiceHandler _nextServiceHandler;
    protected ServiceRequirements _servicesProvided;

    public ServiceHandler(ServiceRequirements servicesProvided)
    {
        _servicesProvided = servicesProvided;
    }
}
```

请注意，由扩展`ServiceHandler`类的类提供的服务，换句话说，技术人员，需要被传递进来。

然后将使用按位`NOT`操作（`~`）执行服务，*关闭*给定`Car`上的位，指示`Service`方法中需要服务：

```cs
public void Service(Car car)
{
    if (_servicesProvided == (car.Requirements & _servicesProvided))
    {
        Console.WriteLine($"{this.GetType().Name} providing {this._servicesProvided} services.");
        car.Requirements &= ~_servicesProvided;
    }

    if (car.IsServiceComplete || _nextServiceHandler == null)
        return;
    else
        _nextServiceHandler.Service(car);
}
```

如果汽车的所有服务都已完成和/或没有更多服务，则停止链条。如果有另一个服务并且汽车还没有准备好，那么将调用下一个服务处理程序。

这种方法需要设置链条，并且前面的例子显示了使用`SetNextServiceHandler()`方法来设置要执行的下一个服务：

```cs
public void SetNextServiceHandler(ServiceHandler handler)
{
    _nextServiceHandler = handler;
}
```

服务专家包括`Detailer`，`Mechanic`，`WheelSpecialist`和`QualityControl`工程师。代表`Detailer`的`ServiceHandler`在以下代码中显示：

```cs
class Detailer : ServiceHandler
{
    public Detailer() : base(ServiceRequirements.Dirty) { }
}
```

专门调校发动机的机械师在以下代码中显示：

```cs
class Mechanic : ServiceHandler
{
    public Mechanic() : base(ServiceRequirements.EngineTune) { }
}
```

以下代码显示了轮胎专家：

```cs
class WheelSpecialist : ServiceHandler
{
    public WheelSpecialist() : base(ServiceRequirements.WheelAlignment) { }
}
```

最后是质量控制，谁将驾驶汽车进行测试：

```cs
class QualityControl : ServiceHandler
{
    public QualityControl() : base(ServiceRequirements.TestDrive) { }
}
```

服务中心的技术人员已经定义好了，下一步是为一些汽车提供服务。这将在`Main`代码块中进行说明，首先是构造所需的对象：

```cs
static void Main(string[] args)
{ 
    var mechanic = new Mechanic();
    var detailer = new Detailer();
    var wheels = new WheelSpecialist();
    var qa = new QualityControl();
```

下一步将是为不同的服务设置处理顺序：

```cs
    qa.SetNextServiceHandler(detailer);
    wheels.SetNextServiceHandler(qa);
    mechanic.SetNextServiceHandler(wheels);
```

然后将会有两次调用技师，这是责任链的开始：

```cs
    Console.WriteLine("Car 1 is dirty");
    mechanic.Service(new Car { Requirements = ServiceRequirements.Dirty });

    Console.WriteLine();

    Console.WriteLine("Car 2 requires full service");
    mechanic.Service(new Car { Requirements = ServiceRequirements.Dirty | 
                                                ServiceRequirements.EngineTune | 
                                                ServiceRequirements.TestDrive | 
                                                ServiceRequirements.WheelAlignment });

    Console.Read();
}
```

一个重要的事情要注意的是链的设置顺序。对于这个服务中心，技师首先进行调整，然后进行车轮定位。然后进行一次试车，之后对车进行详细的工作。最初，试车是作为最后一步进行的，但服务中心确定，在下雨天，这需要重复进行车辆细节。这是一个有点愚蠢的例子，但它说明了以灵活的方式定义责任链的好处。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/50fb4e09-4160-462b-91f8-2a84ddde769c.png)

上述截图显示了我们的两辆车在接受服务后的显示。

# 观察者模式

一个值得更详细探讨的有趣模式是**观察者模式**。这种模式允许实例在另一个实例中发生特定事件时被通知。这样，就有许多观察者和一个单一的主题。以下图表说明了这种模式：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/c945ea79-025c-437f-a14b-f61c6af08216.png)

让我们通过创建一个简单的 C#控制台应用程序来提供一个例子，该应用程序将创建一个`Subject`类的单个实例和多个`Observer`实例。当`Subject`类中的数量值发生变化时，我们希望每个`Observer`实例都能收到通知。

`Subject`类包含一个私有的数量字段，由公共的`UpdateQuantity`方法更新：

```cs
class Subject
{
    private int _quantity = 0;

    public void UpdateQuantity(int value)
    {
        _quantity += value;

        // alert any observers
    }
}
```

为了通知任何观察者，我们使用 C#关键字`delegate`和`event`。`delegate`关键字定义了将被调用的格式或处理程序。当数量更新时要使用的委托如下代码所示：

```cs
public delegate void QuantityUpdated(int quantity);
```

委托将`QuantityUpdated`定义为一个接收整数并且不返回任何值的方法。然后，事件被添加到`Subject`类中，如下所示：

```cs
public event QuantityUpdated OnQuantityUpdated;
```

在`UpdateQuantity`方法中，它被调用如下：

```cs
public void UpdateQuantity(int value)
{
    _quantity += value;

    // alert any observers
    OnQuantityUpdated?.Invoke(_quantity);
}
```

在这个例子中，我们将在`Observer`类中定义一个具有与`QuantityUpdated`委托相同签名的方法：

```cs
class Observer
{
    ConsoleColor _color;
    public Observer(ConsoleColor color)
    {
        _color = color;
    }

    internal void ObserverQuantity(int quantity)
    {
        Console.ForegroundColor = _color;
        Console.WriteLine($"I observer the new quantity value of {quantity}.");
        Console.ForegroundColor = ConsoleColor.White;
    }
}
```

这个实现将在`Subject`实例的数量发生变化时得到通知，并以特定颜色在控制台上打印一条消息。

让我们将这些放在一个简单的应用程序中。在应用程序开始时，将创建一个`Subject`和三个`Observer`对象：

```cs
var subject = new Subject();
var greenObserver = new Observer(ConsoleColor.Green);
var redObserver = new Observer(ConsoleColor.Red);
var yellowObserver = new Observer(ConsoleColor.Yellow);
```

接下来，每个`Observer`实例将注册以在`Subject`的数量发生变化时得到通知：

```cs
subject.OnQuantityUpdated += greenObserver.ObserverQuantity;
subject.OnQuantityUpdated += redObserver.ObserverQuantity;
subject.OnQuantityUpdated += yellowObserver.ObserverQuantity;
```

然后，我们将更新数量两次，如下所示：

```cs
subject.UpdateQuantity(12);
subject.UpdateQuantity(5); 
```

当应用程序运行时，我们会得到三条不同颜色的消息打印出每个更新语句，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/6bd7a38b-7646-41ff-b808-139593727342.png)

这是一个使用 C# `event`关键字的简单示例，但希望它说明了这种模式如何被使用。这里的优势是它将主题与观察者松散地耦合在一起。主题不必知道不同观察者的情况，甚至不必知道是否存在观察者。

# 企业集成模式

**集成**是软件开发的一个学科，它极大地受益于利用他人的知识和经验。考虑到这一点，存在许多 EIP 目录，其中一些是技术无关的，而另一些则专门针对特定的技术堆栈。本节将重点介绍一些流行的集成模式。

*企业集成模式*，由*Gregor Hohpe*和*Bobby Woolf*提供了许多技术上的集成模式的可靠资源。在讨论 EIP 时，经常引用这本书。该书可在[`www.enterpriseintegrationpatterns.com/`](https://www.enterpriseintegrationpatterns.com/)上获得。

# 拓扑

企业集成的一个重要考虑因素是被连接系统的拓扑。一般来说，有两种不同的拓扑结构：中心枢纽和企业服务总线。

**中心枢纽**（中心枢纽）拓扑描述了一种集成模式，其中一个单一组件，中心枢纽，是集中的，并且它与每个应用程序进行显式通信。这种集中的通信使得中心枢纽只需要了解其他应用程序，如下图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/04877dd8-6fef-492a-9f17-cdde6bd30f1c.png)

图表显示了蓝色的中心枢纽具有如何与不同应用程序通信的明确知识。这意味着，当消息从 A 发送到 B 时，它是从 A 发送到中心枢纽，然后转发到 B。对于企业来说，这种方法的优势在于，与 B 的连接只需要在一个地方，即中心枢纽中定义和维护。这里的重要性在于安全性在一个中心位置得到控制和维护。

**企业服务总线**（**ESB**）依赖于由发布者和订阅者（Pub-Sub）组成的消息模型。发布者向总线提交消息，订阅者注册以接收已发布的消息。以下图表说明了这种拓扑：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/5707b39e-5129-49e1-aa5c-cac62cc3f58f.png)

在上图中，如果要将消息从**A**路由到**B**，**B**订阅 ESB 以接收从**A**发布的消息。当**A**发布新消息时，消息将发送到**B**。在实践中，订阅可能会更加复杂。例如，在订购系统中，可能会有两个订阅者，分别用于优先订单和普通订单。在这种情况下，优先订单可能会与普通订单有所不同。

# 模式

如果我们将两个系统之间的集成定义为具有不同步骤，那么我们可以在每个步骤中定义模式。让我们看一下以下图表，讨论一下集成管道：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/b23a2329-2813-437d-8cfa-914e26954910.png)

这个管道是简化的，因为根据使用的技术，管道中可能会有更多或更少的步骤。图表的目的是在我们查看一些常见的集成模式时提供一些背景。这些可以分为以下几类：

+   **消息传递**：与消息处理相关的模式

+   **转换**：与改变消息内容相关的模式

+   **路由**：与消息交换相关的模式

# 消息传递

与消息相关的模式可以采用消息构造和通道的形式。在这种情况下，通道是端点和/或消息进入和离开集成管道的方式。一些与构造相关的模式的例子如下：

+   **消息序列**：消息包含一个序列，表示特定的处理顺序。

+   **相关标识符**：消息包含一个标识相关消息的媒介。

+   **返回地址**：消息标识有关返回响应消息的信息。

+   **过期**：消息具有被视为有效的有限时间。

在*拓扑*部分，我们涵盖了一些与通道相关的模式，但以下是您在集成中应考虑的其他模式：

+   **竞争消费者**：多个进程可以处理相同的消息。

+   **选择性消费者**：消费者使用标准来确定要处理的消息。

+   **死信通道**：处理未成功处理的消息。

+   **可靠传递**：确保消息的可靠处理，不会丢失任何消息。

+   **事件驱动消费者：**消息处理基于已发布的事件。

+   **轮询消费者：**处理从源系统检索的消息。

# 转换

在集成复杂的企业系统时，转换模式允许以系统中处理消息的方式灵活处理。通过转换，可以改变和/或增强两个应用程序之间的消息。以下是一些与转换相关的模式：

+   **内容丰富器：**通过添加信息来*丰富*消息。

+   **规范数据模型：**将消息转换为应用程序中立的消息格式。

+   **消息转换器：**用于将一条消息转换为另一条消息的模式。

**规范数据模型**（**CDM**）是一个很好的模式来强调。通过这种模式，可以在多个应用程序之间交换消息，而无需为每种特定消息类型执行翻译。这最好通过多个系统交换消息的示例来说明，如下图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/00eb3fd5-9c81-45d5-8c3a-8c9703de4bed.png)

在图中，应用程序**A**和**C**希望以它们的格式将它们的消息发送到应用程序**B**和**D**。如果我们使用消息转换器模式，只有处理转换的过程需要知道如何从**A**转换到**B**，从**A**转换到**D**，以及**C**转换到**B**和**C**转换到**D**。随着应用程序数量的增加以及发布者可能不了解其消费者的细节，这变得越来越困难。通过 CDM，**A**和**B**的源应用程序消息被转换为中性模式 X。

规范模式

规范模式有时被称为中性模式，意味着它不直接与源系统或目标系统对齐。然后将模式视为中立的。

然后将中性模式格式的消息转换为**B**和**D**的消息格式，如下图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/16e7e2ad-8684-4ee0-beaf-add4d3bcb4d3.png)

在企业中，如果没有一些标准，这将变得难以管理，幸运的是，许多组织已经创建并管理了许多行业的标准，包括以下示例（但还有许多其他！）：

+   **面向行政、商业和运输的电子数据交换**（**EDIFACT**）：贸易的国际标准

+   **IMS 问题和测试互操作规范**（**QTI**）：由**信息管理系统**（**IMS**）**全球学习联盟**（**GLC**）制定的评估内容和结果的表示标准

+   **酒店业技术整合标准（HITIS）：**由美国酒店和汽车旅馆协会维护的物业管理系统标准

+   X12 EDI（X12）：由 X12 认可标准委员会维护的医疗保健、保险、政府、金融、交通运输和其他行业的模式集合

+   **业务流程框架**（**eTOM**）：由 TM 论坛维护的电信运营模型

# 路由

路由模式提供了处理消息的不同方法。以下是一些属于这一类别的模式示例：

+   **基于内容的路由：**路由或目标应用程序由消息中的内容确定。

+   **消息过滤器：**只有感兴趣的消息才会转发到目标应用程序。

+   **分裂器：**从单个消息生成多个消息。

+   **聚合器：**从多个消息生成单个消息。

+   **分散-聚合：**用于处理多条消息的广播并将响应聚合成单条消息的模式。

分散-聚合模式是一个非常有用的模式，因为它结合了分裂器和聚合器模式，是一个很好的探索示例。通过这种模式，可以建模更复杂的业务流程。

在我们的场景中，我们将考虑一个小部件订购系统的实现。好消息是，有几家供应商出售小部件，但小部件的价格经常波动。那么，哪家供应商的价格变化最好？使用散点-聚合模式，订购系统可以查询多个供应商，选择最佳价格，然后将结果返回给调用系统。

分流器模式将用于生成多个消息给供应商，如下图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/fb4565e5-a899-41d0-8c81-1d050bf2f76f.png)

路由然后等待供应商的回应。一旦收到回应，聚合器模式用于将结果编译成单个消息返回给调用应用程序：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/451c57f7-ef45-48ee-ae38-abd3ee2493e2.png)

值得注意的是，这种模式有许多变体和情况。散点-聚合模式可能要求所有供应商做出回应，也可能只需要其中一些供应商做出回应。另一种情况可能要求该过程等待供应商回应的时间限制。有些消息可能需要毫秒级的回应，而其他情况可能需要几天才能得到回应。

集成引擎是支持许多集成模式的软件。集成引擎可以是本地安装的服务，也可以是基于云的解决方案。一些更受欢迎的引擎包括微软 BizTalk、戴尔 Boomi、MuleSoft Anypoint Platform、IBM WebSphere 和 SAS Business Intelligence。

# 软件开发生命周期模式

管理软件开发有许多方法，最常见的两种软件开发生命周期（SDLC）模式是“瀑布”和“敏捷”。这两种 SDLC 方法有许多变体，通常组织会根据项目、团队以及公司文化来调整方法论。

瀑布和敏捷 SDLC 模式只是两个例子，还有其他几种软件开发模式，可能比其他模式更适合公司的文化、软件成熟度和行业。 

# 瀑布 SDLC

瀑布方法包括项目或工作逐个经历的明确定义的阶段。从概念上讲，它很容易理解，并且遵循其他行业使用的模式。以下是不同阶段的示例：

+   **需求阶段**：收集和记录要实施的所有需求。

+   **设计阶段**：使用上一步产生的文档，完成要实施的设计。

+   **开发阶段**：使用上一步的设计，实施更改。

+   **测试阶段**：对上一步实施的更改进行与指定要求的验证。

+   **部署阶段**：测试完成后，项目所做的更改被部署。

瀑布模型有许多优点。该模型易于理解和管理，因为每个阶段都清楚定义了每个阶段必须完成和交付的内容。通过具有一系列阶段，可以定义里程碑，从而更容易地报告进展情况。此外，有了明确定义的阶段，可以更容易地规划所需资源的角色和责任。

但是，如果出现了意外情况或事情发生了变化怎么办？瀑布式 SDLC 确实有一些缺点，其中许多缺点源于其对变更的灵活性不足，或者在发现事情时需要输入之前步骤的情况。在瀑布式中，如果出现需要来自前一阶段信息的情况，前一阶段将被重复。这带来了几个问题。由于阶段可能被报告，因此报告变得困难，因为项目（已通过阶段或里程碑的项目）现在正在重复该阶段。这可能会促进一种“寻找替罪羊”的公司文化，其中努力转向寻找责任，而不是采取措施防止问题再次发生。此外，资源可能不再可用，因为它们已被移至其他项目和/或已离开公司。

以下图表说明了成本和时间随着问题在各个阶段被发现的时间越晚而增加的情况：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/0fd85921-da03-4dc6-a7fa-96788393df98.png)

由于变更所带来的成本，瀑布式 SDLC 倾向于适用于风险较低的较小项目。较大和更复杂的项目增加了变更的可能性，因为在项目进行过程中需求可能会被改变或业务驱动因素发生变化。

# 敏捷 SDLC

敏捷 SDLC 方法试图接纳变化和不确定性。这是通过使用允许在项目或产品开发过程中发现问题的模式来实现的。关键概念是将项目分解为较小的开发迭代，通常称为开发周期。在每个周期中，基本的瀑布式阶段都会重复，因此每个周期都有需求、设计、开发、测试和部署阶段。

这只是一个简化，但将项目分解为周期的策略比瀑布式具有几个优点：

+   随着范围变小，业务需求变化的影响减小。

+   利益相关者比瀑布式更早地获得可见的工作系统。虽然不完整，但这提供了价值，因为它允许更早地将反馈纳入产品中。

+   资源配置可能会受益，因为资源类型的波动较少。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/f843873a-17d4-4174-8ca2-3a977d04bf18.png)

上图提供了两种方法的总结。

# 总结

在本章中，我们讨论了现代软件开发中使用的主要设计模式，这些模式是在上一章中介绍的。我们从讨论各种软件开发原则开始，如 DRY、KISS、YAGNI、MVP 和 SOLID 编程原则。然后，我们涵盖了软件开发模式，包括 GoF 和 EIPs。我们还涵盖了 SDLC 的方法，包括瀑布和敏捷。本章的目的是说明模式如何在软件开发的各个层次上使用。

随着软件行业的成熟，随着经验的积累、技术的进步，模式开始出现。一些模式已经被开发出来，以帮助 SDLC 的不同阶段。例如，在第三章中，将探讨**测试驱动开发**（TDD），其中测试的定义用于在开发阶段提供可衡量的进展和清晰的需求。随着章节的进展，我们将讨论软件开发中更高层次的抽象，包括 Web 开发的模式以及面向本地和基于云的解决方案的现代架构模式。

在下一章中，我们将从在.NET Core 中构建一个虚构的应用程序开始。此外，我们将解释本章讨论的各种模式，包括 SOLID 等编程原则，并说明几种 GoF 模式。

# 问题

以下问题将帮助您巩固本章中包含的信息：

1.  在 SOLID 中，S 代表什么？责任是什么意思？

1.  哪种 SDLC 方法是围绕循环构建的：瀑布还是敏捷？

1.  装饰者模式是创建型模式还是结构型模式？

1.  Pub-Sub 集成代表什么？


# 第二部分：深入研究.NET Core 中的实用程序和模式

在本节中，读者将亲身体验各种设计模式。在构建一个用于维护库存应用程序的过程中，将说明特定的模式。选择库存应用程序是因为它在概念上很简单，但在开发过程中足够复杂，可以从模式的使用中受益。某些模式和原则将被多次重提，如 SOLID、最小可行产品（MVP）和测试驱动开发（TDD）。到本节结束时，读者将能够借助各种模式编写整洁和干净的代码。

本节包括以下章节：

+   第三章，《实施设计模式-基础部分 1》

+   第四章，《实施设计模式-基础部分 2》

+   第五章，《实施设计模式-.Net Core》

+   第六章，《为 Web 应用程序实现设计模式-第一部分》

+   第七章，《为 Web 应用程序实现设计模式-第二部分》


# 第三章：实施设计模式 - 基础部分 1

在前两章中，我们介绍并定义了与软件开发生命周期（SDLC）相关的现代模式和实践的广泛范围，从较低级别的开发模式到高级解决方案架构模式。本章将在一个示例场景中应用其中一些模式，以便提供上下文和进一步理解这些定义。该场景是创建一个解决方案来管理电子商务书商的库存。

选择了这个场景，因为它提供了足够的复杂性来说明这些模式，同时概念相对简单。公司需要一种管理他们的库存的方式，包括允许用户订购他们的产品。组织需要尽快建立一个应用程序，以便他们能够跟踪他们的库存，但还有许多其他功能，包括允许客户订购产品并提供评论。随着场景的发展，所请求的功能数量增长到开发团队不知道从何处开始的地步。幸运的是，通过应用一些良好的实践来帮助管理期望和需求，开发团队能够简化他们的初始交付并重新回到正轨。此外，通过使用模式，他们能够建立一个坚实的基础，以帮助解决方案的扩展，随着新功能的添加。

本章将涵盖一个新项目的启动和应用程序的第一个发布。本章中将演示以下模式：

+   最小可行产品（MVP）

+   测试驱动开发（TDD）

+   抽象工厂模式（四人帮）

+   SOLID 原则

# 技术要求

本章包含各种代码示例来解释概念。代码保持简单，仅用于演示目的。大多数示例涉及使用 C#编写的.NET Core 控制台应用程序。

要运行和执行代码，您需要以下内容：

+   Visual Studio 2019（您也可以使用 Visual Studio 2017 版本 3 或更高版本来运行应用程序）

+   .NET Core

+   SQL Server（本章中使用 Express Edition）

# 安装 Visual Studio

要运行这些代码示例，您需要安装 Visual Studio 或者您可以使用您喜欢的集成开发环境。要做到这一点，请按照以下说明操作：

1.  从以下链接下载 Visual Studio：[`docs.microsoft.com/en-us/visualstudio/install/install-visual-studio`](https://docs.microsoft.com/en-us/visualstudio/install/install-visual-studio)。

1.  按照包含的安装说明操作。Visual Studio 有多个版本可供安装。在本章中，我们使用的是 Windows 版的 Visual Studio。

# 设置.NET Core

如果您尚未安装.NET Core，则需要按照以下说明操作：

1.  从以下链接下载.NET Core：[`www.microsoft.com/net/download/windows`](https://www.microsoft.com/net/download/windows)。

1.  按照安装说明和相关库：[`dotnet.microsoft.com/download/dotnet-core/2.2`](https://dotnet.microsoft.com/download/dotnet-core/2.2)。

完整的源代码可在 GitHub 上找到。本章中显示的源代码可能不完整，因此建议检索源代码以运行示例：[`github.com/PacktPublishing/Hands-On-Design-Patterns-with-C-and-.NET-Core/tree/master/Chapter3`](https://github.com/PacktPublishing/Hands-On-Design-Patterns-with-C-and-.NET-Core/tree/master/Chapter3)。

# 最小可行产品

本节涵盖了启动新项目以构建软件应用程序的初始阶段。这有时被称为项目启动或项目启动，其中收集应用程序的初始特性和功能（换句话说，需求收集）。

有许多方法可以视为模式，用于确定软件应用程序的功能。关于如何有效地建模、进行面试和研讨会、头脑风暴和其他技术的最佳实践超出了本书的范围。相反，本书描述了一种方法，即最小可行产品，以提供这些模式可能包含的示例。

该项目是针对一个假设情况，一个名为 FlixOne 的公司希望使用库存管理应用程序来管理其不断增长的图书收藏。这个新应用程序将被员工用于管理库存，也将被客户用于浏览和创建新订单。该应用程序需要具有可扩展性，并且作为业务的重要系统，计划在可预见的未来使用。

公司主要分为*业务用户*和*开发团队*，业务用户主要关注系统的功能，开发团队关注满足需求，以及保持系统的可维护性。这是一个简化；然而，组织并不一定如此整洁地组织，个人可能无法正确地归入一个分类或另一个分类。例如，**业务分析师**（**BA**）或**主题专家**（**SME**）经常代表业务用户和开发团队的成员。

由于这是一本技术书籍，我们将主要从开发团队的角度来看待这个情景，并讨论用于实现库存管理应用程序的模式和实践。

# 需求

在几次会议中，业务和开发团队讨论了新库存管理系统的需求。定义一组清晰的需求的进展缓慢，最终产品的愿景也不清晰。开发团队决定将庞大的需求列表削减到足够的功能，以便一个关键人物可以开始记录一些库存信息。这将允许简单的库存管理，并为业务提供一个可以扩展的基础。然后，每组新的需求都可以添加到初始发布中。

最小可行产品（MVP）

最小可行产品是应用程序的最小功能集，仍然可以发布并为用户群体提供足够的价值。

MVP 方法的优势在于它通过缩小应用程序的范围，为业务和开发团队提供了一个简化的交付需求的愿景。通过减少要交付的功能，确定需要做什么的工作变得更加集中。在 FlixOne 的情况下，会议的价值经常会降低到讨论一个功能的细节，尽管这个功能对产品的最终版本很重要，但需要在发布几个功能之前。例如，围绕面向客户的网站的设计让团队分散注意力，无法专注于存储在库存管理系统中的数据。

MVP 在需求复杂性不完全理解和/或最终愿景不明确的情况下非常有用。然而，仍然很重要要保持产品愿景，以避免开发可能在应用程序的最终版本中不需要的功能。

业务和开发团队能够为初始库存管理应用程序定义以下功能需求：

+   该应用程序应该是一个控制台应用程序：

+   它应该打印包含程序集版本的欢迎消息。

+   它应该循环直到给出退出命令。

+   如果给定的命令不成功或不被理解，那么它应该打印一个有用的消息。

+   应用程序应该对简单的不区分大小写的文本命令做出响应。

+   每个命令都应该有一个短形式，一个字符，和一个长形式。

+   如果命令有额外的参数：

+   每个都应按顺序输入，并使用回车键提交。

+   每个都应该有一个提示`输入{参数}：`，其中`{参数}`是参数的名称。

+   应该有一个帮助命令（`?`）：

+   打印可用命令的摘要。

+   打印每个命令的示例用法。

+   应该有一个退出命令（`q`，`quit`）：

+   打印一条告别消息

+   结束应用程序

+   应该有一个添加库存命令（`"a"`，`"addinventory"`）：

+   类型为字符串的`name`参数。

+   它应该向数据库中添加一个具有给定名称和 0 数量的条目。

+   应该有一个更新数量命令（`"u"`，`"updatequantity"`）：

+   类型为字符串的`name`参数。

+   `quantity`参数为正整数或负整数。

+   它应该通过添加给定数量来更新具有给定名称的书的数量值。

+   应该有一个获取库存命令（`"g"`，`"getinventory"`）：

+   返回数据库中所有书籍及其数量。

并且定义了以下非功能性要求：

+   除了操作系统提供的安全性外，不需要其他安全性。

+   命令的短格式是为了可用性，而命令的长格式是为了可读性。

FlixOne 示例是如何使用 MVP 来帮助聚焦和简化 SDLC 的示例。值得强调的是**概念验证**（PoC）和 MVP 之间的区别在每个组织中都会有所不同。在本书中，PoC 与 MVP 的不同之处在于所得到的应用程序不被视为一次性或不完整的。对于商业产品，这意味着最终产品可以出售，对于内部企业解决方案，该应用程序可以为组织增加价值。

# MVP 如何与未来的开发相适应？

使用 MVP 聚焦和包含需求的另一个好处是它与敏捷软件开发的协同作用。将开发周期分解为较小的开发周期是一种在传统瀑布式开发中获得流行的软件开发技术。驱动概念是需求和解决方案在应用程序的生命周期中演变，并涉及开发团队和最终用户之间的协作。通常，敏捷软件开发框架具有较短的发布周期，其中设计、开发、测试和发布新功能。然后重复发布周期，以包含额外的功能。当工作范围适合发布周期时，MVP 在敏捷开发中表现良好。

Scrum 和 Kanban 是基于敏捷软件开发的流行软件开发框架。

初始 MVP 要求的范围被保持在可以在敏捷周期内设计、开发、测试和发布的范围内。在下一个周期中，将向应用程序添加其他要求。挑战在于限制新功能的范围，使其能够在一个周期内完成。每个新功能的发布都限于基本要求或其 MVP。这里的原则是，通过使用迭代方法进行软件开发，应用程序的最终版本将对最终用户产生比使用需要提前定义所有要求的单个发布更大的好处。

以下图表总结了敏捷和瀑布式软件开发方法之间的区别：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/e56ad7fa-bc0c-4584-83f4-976b9a32daf3.png)

# 测试驱动开发

存在不同的**测试驱动开发**（**TDD**）方法，*测试*可以是在开发过程中按需运行的单元测试，也可以是在项目构建期间运行的单元测试，还可以是作为**用户验收测试**（**UAT**）一部分运行的测试脚本。同样，*测试*可以是代码，也可以是描述用户执行步骤以验证需求的文档。这是因为对于 TDD 试图实现的目标有不同的看法。对于一些团队来说，TDD 是一种在编写代码之前完善需求的技术，而对于其他人来说，TDD 是一种衡量或验证交付的代码的方式。

UAT

UAT 是在 SDLC 期间用于验证产品或项目是否满足指定要求的活动的术语。这通常由业务成员或一些客户执行。根据情况，这个阶段可以进一步分为 alpha 和 beta 阶段，其中 alpha 测试由开发团队执行，beta 测试由最终用户执行。

# 团队为什么选择 TDD？

开发团队决定使用 TDD 有几个原因。首先，团队希望在开发过程中清晰地衡量进展。其次，他们希望能够在后续的开发周期中重复使用测试，以便在添加新功能的同时继续验证现有功能。出于这些原因，团队将使用单元测试来验证编写的功能是否满足团队给定的要求。

以下图表说明了 TDD 的基础知识：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/4bfd18c6-4755-4bbf-8cf1-e0caff120847.png)

测试被添加并且代码库被更新，直到所有定义的测试都通过为止。重要的是要注意这是重复的。在每次迭代中，都会添加新的测试，并且在所有测试，新的和现有的，都通过之前，测试都不被认为是通过的。

FlixOne 开发团队决定将单元测试和 UAT 结合到一个敏捷周期中。在每个周期开始时，将确定新的验收标准。这将包括要交付的功能，以及在开发周期结束时如何验证或接受。这些验收标准将用于向项目添加测试。然后，开发团队将构建解决方案，直到新的和现有的测试都通过，然后准备一个用于验收测试的构建。然后，将运行验收测试，如果检测到任何问题，开发团队将根据失败定义新的测试或修改现有测试。应用程序将再次开发，直到所有测试都通过并准备一个新的构建。这将重复直到验收测试通过。然后，应用程序将部署，并开始一个新的开发周期。

以下图表说明了这种方法：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/9798b545-4ea5-418d-91d5-5963745c9089.png)

团队现在有了一个计划，让我们开始编码吧！

# 设置项目

在这种情况下，我们将使用**Microsoft Unit Test**（**MSTest**）框架。本节提供了一些使用.NET Core **命令行界面**（**CLI**）工具创建初始项目的说明。这些步骤也可以使用集成开发环境（IDE）如 Visual Studio 或 Visual Studio Code 完成。这里提供这些说明是为了说明 CLI 如何用于补充 IDE。

CLI

.NET Core CLI 工具是用于开发.NET 应用程序的跨平台实用程序，并且是更复杂工具的基础，例如 IDE。请参阅文档以获取更多信息：[`docs.microsoft.com/en-us/dotnet/core/tools`](https://docs.microsoft.com/en-us/dotnet/core/tools)。

本章的解决方案将包括三个项目：控制台应用程序、类库和测试项目。让我们创建解决方案目录 FlixOne，以包含解决方案和三个项目的子目录。在创建的目录中，以下命令将创建一个新的解决方案文件：

```cs
dotnet new sln
```

以下截图说明了创建目录和解决方案（注意：目前只创建了一个空解决方案文件）：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/c5472945-a2fe-4251-8d8a-7a9c1dd8b2c9.png)

类库`FlixOne.InventoryManagement`将包含我们的业务实体和逻辑。在后面的章节中，我们将把它们拆分成单独的库，但是由于我们的应用程序还很小，它们包含在一个单独的程序集中。创建项目的`dotnet`核心 CLI 命令如下所示：

```cs
dotnet new classlib --name FlixOne.InventoryManagement
```

请注意，在以下截图中，创建了一个包含新类库项目文件的新目录：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/7206ccd0-c6be-432b-bd5c-799896c79687.png)

应该从解决方案到新类库进行引用，使用以下命令：

```cs
dotnet sln add .\FlixOne.InventoryManagement\FlixOne.InventoryManagement.csproj
```

要创建一个新的控制台应用程序项目，应使用以下命令：

```cs
dotnet new console --name FlixOne.InventoryManagementClient
```

以下截图显示了`console`模板的恢复：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/d4670643-d4de-4934-b042-0772541e3e0d.png)

控制台应用程序需要引用类库（注意：该命令需要在将引用添加到其中的项目文件所在的目录中运行）：

```cs
dotnet add reference ..\FlixOne.InventoryManagement\FlixOne.InventoryManagement.csproj
```

将使用以下命令创建一个新的`MSTest`项目：

```cs
dotnet new mstest --name FlixOne.InventoryManagementTests
```

以下截图显示了创建 MSTest 项目，并应在与解决方案相同的文件夹中运行，FlixOne（注意包含所需 MSTest NuGet 包的命令中恢复的包）：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/f0e033e2-5bda-4b22-9b5e-5fa2600001ff.png)

测试项目还需要引用类库（注意：此命令需要在与 MSTest 项目文件相同的文件夹中运行）：

```cs
dotnet add reference ..\FlixOne.InventoryManagement\FlixOne.InventoryManagement.csproj
```

最后，通过在与解决方案文件相同的目录中运行以下命令，将控制台应用程序和 MSTest 项目添加到解决方案中：

```cs
dotnet sln add .\FlixOne.InventoryManagementClient\FlixOne.InventoryManagementClient.csproj
dotnet sln add .\FlixOne.InventoryManagementTests\FlixOne.InventoryManagementTests.csproj
```

从视觉上看，解决方案如下所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/7e47db76-ac52-4e8b-8866-1db9a03d4ebf.png)

现在我们的解决方案的初始结构已经准备好了，让我们首先开始添加到我们的单元测试定义。

# 初始单元测试定义

开发团队首先将需求转录成一些基本的单元测试。由于还没有设计或编写任何内容，因此这些测试大多以记录应该验证的功能为形式。随着设计和开发的进展，这些测试也将朝着完成的方向发展；例如，需要添加库存：

添加库存命令（“a”，“addinventory”）可用：

+   `name`参数为字符串类型。

+   使用给定的名称和`0`数量向数据库添加条目。

为了满足这个需求，开发团队创建了以下单元测试作为占位符：

```cs
[TestMethod]
private void AddInventoryCommand_Successful()
{
  // create an instance of the command
  // add a new book with parameter "name"
  // verify the book was added with the given name with 0 quantity

  Assert.Inconclusive("AddInventoryCommand_Successful has not been implemented.");
}
```

随着应用程序设计的逐渐明确和开发的开始，现有的测试将扩展，新的测试将被创建，如下所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/b2f6bef0-f8e8-481c-bc9c-83761e6bb255.png)

不确定测试的重要性在于它们向团队传达了需要完成的任务，并且在开发进行时提供了一种衡量。随着开发的进行，不确定和失败的测试将表明需要进行的工作，而成功的测试将表明朝着完成当前一组任务的进展。

# 抽象工厂设计模式

为了说明我们的第一个模式，让我们通过开发帮助命令和初始控制台应用程序来走一遍。初始版本的控制台应用程序如下所示：

```cs
private static void Main(string[] args)
{
    Greeting();

    // note: inline out variable introduced as part of C# 7.0
    GetCommand("?").RunCommand(out bool shouldQuit); 

    while (!shouldQuit)
    { 
        // handle the commands
        ...
    }

    Console.WriteLine("CatalogService has completed."); 
}
```

应用程序启动时，会显示问候语和帮助命令的结果。然后，应用程序将处理输入的命令，直到输入退出命令为止。

以下显示了处理命令的详细信息：

```cs
    while (!shouldQuit)
    { 
        Console.WriteLine(" > ");
        var input = Console.ReadLine();
        var command = GetCommand(input);

        var wasSuccessful = command.RunCommand(out shouldQuit);

        if (!wasSuccessful)
        {
            Console.WriteLine("Enter ? to view options.");
        }
    }
```

直到应用程序解决方案退出，应用程序将继续提示用户输入命令，如果命令没有成功处理，那么将显示帮助文本。

RunCommand(out bool shouldQuit)

C# 7.0 引入了一种更流畅的语法，用于创建`out`参数。这将在命令块的范围内声明变量。下面的示例说明了这一点，其中`shouldQuit`布尔值不是提前声明的。

# InventoryCommand 抽象类

关于初始控制台应用程序的第一件事是，团队正在使用**面向对象编程**（**OOP**）来创建处理命令的标准方式。团队从这个初始设计中学到的是，所有命令都将包含一个`RunCommand()`方法，该方法将返回两个布尔值，指示命令是否成功以及程序是否应该终止。例如，`HelpCommand()`将简单地在控制台上显示帮助消息，并且不应该导致程序结束。然后两个返回的布尔值将是*true*，表示命令成功运行，*false*，表示应用程序不应该终止。以下显示了初始版本：

这个...表示额外的声明，在这个特定的例子中，额外的`Console.WriteLine()`声明。

```cs
public class HelpCommand
{
    public bool RunCommand(out bool shouldQuit)
    {
        Console.WriteLine("USAGE:");
        Console.WriteLine("\taddinventory (a)");
        ...
        Console.WriteLine("Examples:");
        ...

        shouldQuit = false;
        return true;
    }
}
```

`QuitCommand`将显示一条消息，然后导致程序结束。最初的`QuitCommand`如下：

```cs
public class QuitCommand
{
    public bool RunCommand(out bool shouldQuit)
    {
        Console.WriteLine("Thank you for using FlixOne Inventory Management System");

        shouldQuit = true;
        return true;
    }
}
```

团队决定要么创建一个接口，两个类都实现，要么创建一个抽象类，两个类都继承。两者都可以实现所需的动态多态性，但团队选择使用抽象类，因为所有命令都将具有共享功能。

在 OOP 中，特别是在 C#中，多态性以三种主要方式得到支持：函数重载、泛型和子类型或动态多态性。

使用抽象工厂设计模式，团队创建了一个抽象类，命令将从中继承，`InventoryCommand`。`InventoryCommand`类有一个单一的方法，`RunCommand`，将执行命令并返回命令是否成功执行以及应用程序是否应该退出。该类是抽象的，意味着类包含一个或多个抽象方法。在这种情况下，`InternalCommand()`方法是抽象的，意图是从`InventoryCommand`类派生的类将使用特定命令功能实现`InternalCommand`方法。例如，`QuitCommand`将扩展`InventoryCommand`并为`InternalCommand()`方法提供具体实现。以下片段显示了带有抽象`InternalCommand()`方法的`InventoryCommand`抽象类：

```cs
public abstract class InventoryCommand
{
    private readonly bool _isTerminatingCommand;
    internal InventoryCommand(bool commandIsTerminating)
    {
        _isTerminatingCommand = commandIsTerminating; 
    }
    public bool RunCommand(out bool shouldQuit)
    {
        shouldQuit = _isTerminatingCommand;
        return InternalCommand();
    }

    internal abstract bool InternalCommand();
}
```

然后抽象方法将在每个派生类中实现，就像`HelpCommand`所示。`HelpCommand`简单地向控制台打印一些信息，然后返回`true`，表示命令成功执行：

```cs
public class HelpCommand : InventoryCommand
{
    public HelpCommand() : base(false) { }

    internal override bool InternalCommand()
    { 
        Console.WriteLine("USAGE:");
        Console.WriteLine("\taddinventory (a)");
        ...
        Console.WriteLine("Examples:");
        ... 
        return true;
    }
}
```

开发团队随后决定对`InventoryCommand`进行两个额外的更改。他们不喜欢的第一件事是`shouldQuit`布尔值作为*out*变量返回。因此，他们决定使用 C# 7 的新元组功能，而不是返回一个单一的`Tuple<bool,bool>`对象，如下所示：

```cs
public (bool wasSuccessful, bool shouldQuit) RunCommand()
{
    /* additional code hidden */

    return (InternalCommand(), _isTerminatingCommand);
}
```

元组

元组是 C#类型，提供了一种轻量级的语法，可以将多个值打包成一个单一对象。与定义类的缺点是你失去了继承和其他面向对象的功能。更多信息，请参见[`docs.microsoft.com/en-us/dotnet/csharp/tuples`](https://docs.microsoft.com/en-us/dotnet/csharp/tuples)。

另一个变化是引入另一个抽象类，指示命令是否是一个非终止命令；换句话说，不会导致解决方案退出或结束的命令。

如下代码所示，这个命令仍然是抽象的，因为它没有实现`InventoryCommand`的`InternalCommand`方法，但它向基类传递了一个 false 值：

```cs
internal abstract class NonTerminatingCommand : InventoryCommand
{
    protected NonTerminatingCommand() : base(commandIsTerminating: false)
    {
    }
}
```

这里的优势是现在不会导致应用程序终止的命令 - 换句话说，非终止命令 - 现在有了更简单的定义：

```cs
internal class HelpCommand : NonTerminatingCommand
{
    internal override bool InternalCommand()
    {
        Interface.WriteMessage("USAGE:");
        /* additional code hidden */

        return true;
    }
}
```

以下类图显示了`InventoryCommand`抽象类的继承：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/bc1bd371-98d9-4fec-8acc-1f26d74eb3ac.png)

只有一个终止命令，`QuitCommand`，而其他命令扩展了`NonTerminatingCommand`抽象类。还值得注意的是，`AddInventoryCommand`和`UpdateQuantityCommand`需要参数，并且`IParameterisedCommand`的使用将在*Liskov 替换原则*部分中解释。图表中的另一个微妙之处是除了基本的`InventoryCommand`之外，所有类型都不是公共的（对外部程序集可见）。这将在本章后面的*访问修饰符*部分变得相关。

# SOLID 原则

随着团队使用模式简化代码，他们还使用 SOLID 原则来帮助识别问题。通过简化代码，团队的目标是使代码更易于维护，并且更容易让新团队成员理解。通过使用一套原则审查代码的方法，在编写只做必要的事情并提供一层抽象的类时非常有用，这有助于编写更容易修改和理解的代码。

# 单一职责原则（SRP）

团队应用的第一个原则是**单一职责原则**（**SRP**）。团队发现写入控制台的实际机制不是`InventoryCommand`类的责任。因此，引入了一个负责与用户交互的`ConsoleUserInterface`类。SRP 将有助于保持`InventoryCommand`类更小，并避免重复相同的代码的情况。例如，应用程序应该有一种统一的方式提示用户输入信息和显示消息和警告。这种逻辑不是在`InventoryCommand`类中重复，而是封装在`ConsoleUserInterface`类中。

`ConsoleUserInteraface`将包括三种方法，如下所示：

```cs
public class ConsoleUserInterface
{
    // read value from console

    // message to the console

    // writer warning message to the console
}
```

第一种方法将用于从控制台读取输入：

```cs
public string ReadValue(string message)
{
    Console.ForegroundColor = ConsoleColor.Green;
    Console.Write(message);
    return Console.ReadLine();
}
```

第二种方法将使用绿色在控制台上打印一条消息：

```cs
public void WriteMessage(string message)
{
    Console.ForegroundColor = ConsoleColor.Green;
    Console.WriteLine(message);
}
```

最终的方法将使用深黄色在控制台上打印一条警告消息：

```cs
public void WriteWarning(string message)
{
    Console.ForegroundColor = ConsoleColor.DarkYellow;
    Console.WriteLine(message);
}
```

通过`ConsoleUserInterface`类，我们可以减少与用户交互方式的变化对我们的影响。随着解决方案的发展，我们可能会发现界面从控制台变为 Web 应用程序。理论上，我们将用`WebUserInterface`替换`ConsoleUserInterface`。如果我们没有将用户界面简化为单个类，这种变化的影响很可能会更加破坏性。

# 开闭原则（OCP）

开闭原则，SOLID 中的 O，由不同的`InventoryCommand`类表示。团队可以定义一个包含多个`if`语句的单个类，而不是为每个命令定义一个`InventoryCommand`类的实现。每个`if`语句将确定要执行的功能。例如，以下说明了团队如何打破这个原则：

```cs
internal bool InternalCommand(string command)
{
    switch (command)
    {
        case "?":
        case "help":
            return RunHelpCommand(); 
        case "a":
        case "addinventory":
            return RunAddInventoryCommand(); 
        case "q":
        case "quit":
            return RunQuitCommand();
        case "u":
        case "updatequantity":
            return RunUpdateInventoryCommand();
        case "g":
        case "getinventory":
            return RunGetInventoryCommand();
    }
    return false;
}
```

上述方法违反了这一原则，因为添加新命令会改变代码的行为。该原则的理念是它对于会*改变*其行为的修改是**封闭**的，而是**开放**的，以扩展类以支持附加行为。通过具有抽象的`InventoryCommand`和派生类（例如`QuitCommand`、`HelpCommand`和`AddInventoryCommand`）来实现这一点。尤其是与其他原则结合使用时，这是一个令人信服的理由，因为它导致简洁的代码，更易于维护和理解。

# 里氏替换原则（LSP）

退出、帮助和获取库存的命令不需要参数，而`AddInventory`和`UpdateQuantityCommand`需要。有几种处理方式，团队决定引入一个接口来标识这些命令，如下所示：

```cs
public interface IParameterisedCommand
{
    bool GetParameters();
}
```

通过应用**里氏替换原则**（**LSP**），只有需要参数的命令应该实现`GetParameters()`方法。例如，在`AddInventory`命令上，使用在基类`InventoryCommand`上定义的方法来实现`IParameterisedCommand`：

```cs
public class AddInventoryCommand : InventoryCommand, IParameterisedCommand
{
    public string InventoryName { get; private set; }

    /// <summary>
    /// AddInventoryCommand requires name
    /// </summary>
    /// <returns></returns>
    public bool GetParameters()
    {
        if (string.IsNullOrWhiteSpace(InventoryName))
            InventoryName = GetParameter("name");

        return !string.IsNullOrWhiteSpace(InventoryName);
    }    
}
```

`InventoryCommand`类上的`GetParameter`方法简单地使用`ConsoleUserInterface`从控制台读取值。该方法将在本章后面显示。在 C#中，有一个方便的语法，可以很好地显示 LSP 如何用于仅将功能应用于特定接口的对象。在`RunCommand`方法的第一行，使用`is`关键字来测试当前对象是否实现了`IParameterisedCommand`接口，并将对象强制转换为新对象：`parameterisedCommand`。以下代码片段中的粗体显示了这一点：

```cs
public (bool wasSuccessful, bool shouldQuit) RunCommand()
{
    if (this is IParameterisedCommand parameterisedCommand)
    {
        var allParametersCompleted = false;

        while (allParametersCompleted == false)
        {
            allParametersCompleted = parameterisedCommand.GetParameters();
        }
    }

    return (InternalCommand(), _isTerminatingCommand);
}
```

# 接口隔离原则（ISP）

处理带参数和不带参数的命令的一种方法是在`InventoryCommand`抽象类上定义另一个方法`GetParameters`，对于不需要参数的命令，只需返回 true 以指示已接收到所有（在本例中为零）参数。例如，`QuitCommand`、`**HelpCommand**`和`GetInventoryCommand`都将有类似以下实现：

```cs
internal override bool GetParameters()
{
    return true;
}
```

这将起作用，但它违反了**接口隔离原则**（**ISP**），该原则规定接口应仅包含所需的方法和属性。与 SRP 类似，适用于类的 ISP 适用于接口，并且在保持接口小型和专注方面非常有效。在我们的示例中，只有`AddInventoryCommand`和`UpdateQuantityCommand`类将实现`InventoryCommand`接口。

# 依赖反转原则

**依赖反转原则**（**DIP**），也称为**依赖注入原则**（**DIP**），模块不应依赖于细节，而应依赖于抽象。该原则鼓励编写松散耦合的代码，以增强可读性和维护性，特别是在大型复杂的代码库中。

如果我们重新访问之前介绍的`ConsoleUserInterface`类（在*单一职责原则*部分），我们可以在没有`QuitCommand`的情况下使用该类如下：

```cs
internal class QuitCommand : InventoryCommand
{
    internal override bool InternalCommand()
    {
        var console = new ConsoleUserInterface();
        console.WriteMessage("Thank you for using FlixOne Inventory Management System");

        return true;
    }
}
```

这违反了几个 SOLID 原则，但就 DIP 而言，它在`QuitCommand`和`ConsoleUserInterface`之间形成了紧密耦合。想象一下，如果控制台不再是向用户显示信息的手段，或者如果`ConsoleUserInterface`的构造函数需要额外的参数会怎么样？

通过应用 DIP 原则，进行了以下重构。首先引入了一个新的接口`IUserInterface`，其中包含了`ConsoleUserInterface`中实现的方法的定义。接下来，在`InventoryCommand`类中使用接口而不是具体类。最后，在`InventoryCommand`类的构造函数中传递了一个实现`IUserInterface`的对象的引用。这种方法保护了`InventoryCommand`类免受对`IUserInterface`类实现细节的更改，并为更轻松地替换`IUserInterface`的不同实现提供了一种机制，使代码库得以发展。

DIP 如下图所示，`QuitCommand`是本章的最终版本：

```cs
internal class QuitCommand : InventoryCommand
{
    public QuitCommand(IUserInterface userInterface) : 
           base(commandIsTerminating: true, userInteface: userInterface)
    {
    }

    internal override bool InternalCommand()
    {
        Interface.WriteMessage("Thank you for using FlixOne Inventory Management System");

        return true;
    }
}
```

请注意，该类扩展了`InventoryCommand`抽象类，提供了处理命令的通用方式，同时提供了共享功能。构造函数要求在实例化对象时注入`IUserInterface`依赖项。还要注意，`QuitCommand`实现了一个方法`InternalCommand()`，使`QuitCommand`简洁易读易懂。

为了完成整个图片，让我们来看最终的`InventoryCommand`基类。以下显示了构造函数和属性：

```cs
public abstract class InventoryCommand
{
    private readonly bool _isTerminatingCommand;
    protected IUserInterface Interface { get; }

    internal InventoryCommand(bool commandIsTerminating, IUserInterface userInteface)
    {
        _isTerminatingCommand = commandIsTerminating;
        Interface = userInteface;
    }
    ...
}
```

请注意，`IUserInterface`被传递到构造函数中，以及一个布尔值，指示命令是否终止。然后，`IUserInterface`对于所有`InventoryCommand`的实现都可用作`Interface`属性。

`RunCommand`是该类上唯一的公共方法：

```cs
public (bool wasSuccessful, bool shouldQuit) RunCommand()
{
    if (this is IParameterisedCommand parameterisedCommand)
    {
        var allParametersCompleted = false;

        while (allParametersCompleted == false)
        {
            allParametersCompleted = parameterisedCommand.GetParameters();
        }
    }

    return (InternalCommand(), _isTerminatingCommand);
}

internal abstract bool InternalCommand();
```

此外，`GetParameter`方法是所有`InventoryCommand`实现的公共方法，因此它被设置为内部方法：

```cs
internal string GetParameter(string parameterName)
{
    return Interface.ReadValue($"Enter {parameterName}:"); 
}
```

DIP 和 IoC

DIP 和**控制反转**（IoC）密切相关，都以稍微不同的方式解决相同的问题。IoC 及其专门形式的**服务定位器模式**（SLP）使用机制按需提供抽象的实现。因此，IoC 充当代理以提供所需的细节，而不是注入实现。在下一章中，将探讨.NET Core 对这些模式的支持。

# InventoryCommand 单元测试

随着`InventoryCommand`类的形成，让我们重新审视单元测试，以便开始验证到目前为止编写的内容，并确定任何缺失的要求。在这里，SOLID 原则将显示其价值。因为我们保持了类（SRP）和接口（ISP）的小型化，并且专注于所需的最小功能量（LSP），我们的测试也应该更容易编写和验证。例如，关于其中一个命令的测试将不需要验证控制台上消息的显示（例如颜色或文本大小），因为这不是`InventoryCommand`类的责任，而是`IUserInterface`的实现的责任。此外，通过依赖注入，我们将能够将测试隔离到仅涉及库存命令。以下图表说明了这一点，因为单元测试将仅验证绿色框中包含的内容：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/4cfda6fb-5968-451a-af94-5bee807667a1.png)

通过保持单元测试的范围有限，将更容易处理应用程序的变化。在某些情况下，由于类之间的相互依赖关系（换句话说，当未遵循 SOLID 原则时），更难以分离功能，测试可能会跨应用程序的较大部分，包括存储库。这些测试通常被称为集成测试，而不是单元测试。

# 访问修饰符

访问修饰符是处理类型和类型成员可见性的重要方式，通过封装代码来实现。通过使用清晰的访问策略，可以传达和强制执行程序集及其类型应该如何使用的意图。例如，在 FlixOne 应用程序中，只有应该由控制台直接访问的类型被标记为公共。这意味着控制台应用程序应该能够看到有限数量的类型和方法。这些类型和方法已标记为公共，而控制台不应该访问的类型和方法已标记为内部、私有或受保护。

请参阅 Microsoft 文档编程指南，了解有关访问修饰符的更多信息：

[`docs.microsoft.com/en-us/dotnet/csharp/programming-guide/classes-and-structs/access-modifiers`](https://docs.microsoft.com/en-us/dotnet/csharp/programming-guide/classes-and-structs/access-modifiers)

`InventoryCommand`抽象类被公开，因为控制台应用程序将使用`RunCommand`方法来处理命令。

在下面的片段中，请注意构造函数和接口被标记为受保护，以便给予子类访问权限：

```cs
public abstract class InventoryCommand
{
    private readonly bool _isTerminatingCommand;
    protected IUserInterface Interface { get; }

    protected InventoryCommand(bool commandIsTerminating, IUserInterface userInteface)
    {
        _isTerminatingCommand = commandIsTerminating;
        Interface = userInteface;
    }
    ...
}
```

在下面的片段中，请注意`RunCommand`方法被标记为公共，而`InternalCommand`被标记为内部：

```cs
public (bool wasSuccessful, bool shouldQuit) RunCommand()
{
    if (this is IParameterisedCommand parameterisedCommand)
    {
        var allParametersCompleted = false;

        while (allParametersCompleted == false)
        {
            allParametersCompleted = parameterisedCommand.GetParameters();
        }
    }

    return (InternalCommand(), _isTerminatingCommand);
}

internal abstract bool InternalCommand();
```

同样，`InventoryCommand`的实现被标记为内部，以防止它们被直接引用到程序集外部。这在`QuitCommand`中有所体现：

```cs
internal class QuitCommand : InventoryCommand
{
    internal QuitCommand(IUserInterface userInterface) : base(true, userInterface) { }

    protected override bool InternalCommand()
    {
        Interface.WriteMessage("Thank you for using FlixOne Inventory Management System");

        return true;
    }
}
```

因为不同实现的访问对于单元测试项目来说不会直接可见，所以需要额外的步骤来使内部类型可见。`assembly`指令可以放置在任何已编译的文件中，对于 FlixOne 应用程序，添加了一个包含程序集属性的`assembly.cs`文件：

```cs
using System.Runtime.CompilerServices;
[assembly: InternalsVisibleTo("FlixOne.InventoryManagementTests")]
```

在程序集已签名的情况下，`InternalsVisibleTo()`需要一个公钥。请参阅 Microsoft Docs C#指南，了解更多信息：[`docs.microsoft.com/en-us/dotnet/csharp/programming-guide/concepts/assemblies-gac/how-to-create-signed-friend-assemblies`](https://docs.microsoft.com/en-us/dotnet/csharp/programming-guide/concepts/assemblies-gac/how-to-create-signed-friend-assemblies)。

# Helper TestUserInterface

作为对`InventoryCommand`实现之一的单元测试的一部分，我们不希望测试引用的依赖关系。幸运的是，由于命令遵循 DIP，我们可以创建一个`helper`类来验证实现与依赖关系的交互。其中一个依赖是`IUserInterface`，它在构造函数中传递给实现。以下是接口的方法的提醒：

```cs
public interface IUserInterface : IReadUserInterface, IWriteUserInterface { }

public interface IReadUserInterface
{
    string ReadValue(string message);
}

public interface IWriteUserInterface
{
    void WriteMessage(string message);
    void WriteWarning(string message);
}
```

通过实现一个`helper`类，我们可以提供`ReadValue`方法所需的信息，并验证`WriteMessage`和`WriteWarning`方法中是否收到了适当的消息。在测试项目中，创建了一个名为`TestUserInterface`的新类，该类实现了`IUserInterface`接口。该类包含三个列表，包含预期的`WriteMessage`、`WriteWarning`和`ReadValue`调用，并跟踪调用次数。

例如，`WriteWarning`方法显示如下：

```cs
public void WriteWarning(string message)
{
    Assert.IsTrue(_expectedWriteWarningRequestsIndex < _expectedWriteWarningRequests.Count,
                  "Received too many command write warning requests.");

    Assert.AreEqual(_expectedWriteWarningRequests[_expectedWriteWarningRequestsIndex++], message,                             "Received unexpected command write warning message");
}
```

`WriteWarning`方法执行两个断言。第一个断言验证方法调用的次数不超过预期，第二个断言验证接收到的消息是否与预期消息匹配。

`ReadValue`方法类似，但它还将一个值返回给调用的`InventoryCommand`实现。这将模拟用户在控制台输入信息：

```cs
public string ReadValue(string message)
{
    Assert.IsTrue(_expectedReadRequestsIndex < _expectedReadRequests.Count,
                  "Received too many command read requests.");

    Assert.AreEqual(_expectedReadRequests[_expectedReadRequestsIndex].Item1, message, 
                    "Received unexpected command read message");

    return _expectedReadRequests[_expectedReadRequestsIndex++].Item2;
}
```

作为额外的验证步骤，在测试方法结束时，调用`TestUserInterface`来验证是否收到了预期数量的`ReadValue`、`WriteMessage`和`WriteWarning`请求：

```cs
public void Validate()
{
    Assert.IsTrue(_expectedReadRequestsIndex == _expectedReadRequests.Count, 
                  "Not all read requests were performed.");
    Assert.IsTrue(_expectedWriteMessageRequestsIndex == _expectedWriteMessageRequests.Count, 
                  "Not all write requests were performed.");
    Assert.IsTrue(_expectedWriteWarningRequestsIndex == _expectedWriteWarningRequests.Count, 
                  "Not all warning requests were performed.");
}
```

`TestUserInterface`类说明了如何模拟依赖项以提供存根功能，并提供断言来帮助验证预期的行为。在后面的章节中，我们将使用第三方包提供更复杂的模拟依赖项的框架。

# 单元测试示例 - QuitCommand

从`QuitCommand`开始，要求非常明确：命令应打印告别消息，然后导致应用程序结束。我们已经设计了`InventoryCommand`来返回两个布尔值，以指示应用程序是否应该退出以及命令是否成功结束：

```cs
[TestMethod]
public void QuitCommand_Successful()
{
    var expectedInterface = new Helpers.TestUserInterface(
        new List<Tuple<string, string>>(), // ReadValue()
        new List<string> // WriteMessage()
        {
            "Thank you for using FlixOne Inventory Management System"
        },
        new List<string>() // WriteWarning()
    );

    // create an instance of the command
    var command = new QuitCommand(expectedInterface);

    var result = command.RunCommand();

    expectedInterface.Validate();

    Assert.IsTrue(result.shouldQuit, "Quit is a terminating command.");
    Assert.IsTrue(result.wasSuccessful, "Quit did not complete Successfully.");
}
```

测试使用`TestUserInterface`来验证文本`"感谢您使用 FlixOne 库存管理系统"`是否发送到`WriteMessage`方法，并且没有接收到`ReadValue`或`WriteWarning`请求。这两个标准通过`expectedInterface.Validate()`调用进行验证。通过检查`shouldQuit`和`wasSuccessful`布尔值为 true 来验证`QuitCommand`的结果。

在 FlixOne 场景中，为了简化，要显示的文本在解决方案中是*硬编码*的。更好的方法是使用资源文件。资源文件提供了一种将文本与功能分开维护的方式，同时支持为不同文化本地化数据。

# 总结

本章介绍了在线书商 FlixOne 想要构建一个管理其库存的应用程序的情景。本章涵盖了开发团队在开发应用程序时可以使用的一系列模式和实践。团队使用 MVP 来帮助将初始交付的范围保持在可管理的水平，并帮助业务集中确定对组织最有益的需求。团队决定使用 TDD 来验证交付是否符合要求，并帮助团队衡量进展。基本项目以及单元测试框架 MSTest 已创建。团队还使用了 SOLID 原则来帮助以一种既有利于可读性又有利于代码库的维护的方式构建代码，随着对应用程序的新增增强。第一个四人帮模式，抽象工厂设计模式，用于为所有库存命令提供基础。

在下一章中，团队将继续构建初始库存管理项目，以满足 MVP 中定义的要求。团队将使用四人帮的 Singleton 模式和 Factory Method 模式。这些将在.NET Core 中支持这些功能的机制的情况下展示。

# 问题

以下问题将帮助您巩固本章中包含的信息：

1.  在为组织开发软件时，为什么有时很难确定需求？

1.  瀑布软件开发与敏捷软件开发的两个优点和缺点是什么？

1.  编写单元测试时，依赖注入如何帮助？

1.  为什么以下陈述是错误的？使用 TDD，您不再需要人们测试新软件部署。
