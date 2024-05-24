# Java 设计模式最佳实践（一）

> 原文：[Design Patterns and Best Practices in Java](https://libgen.rs/book/index.php?md5=096AE07A3FFC0E5B9926B8DE68424560)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 零、前言

拥有设计模式的知识可以帮助开发人员改进代码库，促进代码重用，并使架构更加健壮。随着语言的发展，新特性在被大量采用之前需要时间才能被完全理解。这本书的任务是简化最新趋势的采用，并为程序员提供良好的实践。

# 这本书是给谁的

这本书是为每一个想要编写高质量代码的 Java 开发人员准备的。这本书讨论了许多开发人员在编写代码时经常忽略的最佳实践。这本书还涵盖了许多设计模式。设计模式只不过是解决特定问题的最佳实践，这些问题已经过开发人员社区的尝试和测试。

# 充分利用这本书

有 Java 经验的读者将能够从本书中获得最大的收获。建议读者尝试探索和使用各章中提供的代码示例。

# 下载示例代码文件

您可以从您的帐户[下载本书的示例代码文件 www.packtpub.com](http://www.packtpub.com)。如果您在其他地方购买了本书，您可以访问[www.packtpub.com/support](http://www.packtpub.com/support)并注册，将文件直接通过电子邮件发送给您。

您可以通过以下步骤下载代码文件：

1.  在[登录或注册 www.packtpub.com](http://www.packtpub.com/support)。
2.  选择“支持”选项卡。
3.  点击代码下载和勘误表。
4.  在搜索框中输入图书名称，然后按照屏幕上的说明进行操作。

下载文件后，请确保使用最新版本的解压缩或解压缩文件夹：

*   用于 Windows 的 WinRAR/7-Zip
*   Mac 的 Zipeg/iZip/UnRarX
*   用于 Linux 的 7-Zip/PeaZip

这本书的代码包也托管[在 GitHub 上](https://github.com/PacktPublishing/Design-Patterns-and-Best-Practices-in-Java)。如果代码有更新，它将在现有的 GitHub 存储库中更新。

我们的丰富书籍和视频目录中还有其他代码包，可在[这个页面](https://github.com/PacktPublishing/)上找到。看看他们！

# 下载彩色图像

我们还提供了一个 PDF 文件，其中包含本书中使用的屏幕截图/图表的彩色图像。您可以从[这个页面](http://www.packtpub.com/sites/default/files/downloads/DesignPatternsandBestPracticesinJava_ColorImages.pdf)下载。

# 使用的约定

这本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码字、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄。下面是一个示例：“通过向其声明中添加`synchronized`关键字，使`getInstance`方法线程安全。”

代码块设置如下：

```java
public class Car extends Vehicle
{
  public Car(String name)
  {
    super(name)
  }
}
```

任何命令行输入或输出的编写方式如下：

```java
java --list-modules
```

**粗体**：表示一个新术语、一个重要单词或屏幕上显示的单词。例如，菜单或对话框中的单词会像这样出现在文本中。下面是一个示例：“在进行此更改之前，您需要将完整的 **Java 运行时环境**（**JRE**）作为一个整体加载到服务器或机器上以运行 Java 应用。”

警告或重要提示如下所示。

提示和窍门是这样出现的。

# 一、从面向对象到函数式编程

> 原文：[Design Patterns and Best Practices in Java](https://libgen.rs/book/index.php?md5=096AE07A3FFC0E5B9926B8DE68424560)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)
> 
> 贡献者：[飞龙](https://github.com/wizardforcel)
> 
> 本文来自[【ApacheCN Java 译文集】](https://github.com/apachecn/apachecn-java-zh)，采用[译后编辑（MTPE）](https://cn.bing.com/search?q=%E8%AF%91%E5%90%8E%E7%BC%96%E8%BE%91)流程来尽可能提升效率。

本章的目的是向读者介绍使用设计模式和 Java 中可用的最新特性编写健壮、可维护和可扩展代码的基本概念。为了实现我们的目标，我们将讨论以下主题：

*   什么是编程范式？
*   命令式范式
*   命令式和函数式范式
*   面向对象范式
*   统一建模语言综述
*   面向对象设计原则

# Java 简介

在 1995，一个新的编程语言被释放，灵感来自于著名的 C++ 和鲜为人知的 SimultalTalk。Java 是这门新语言的名字，它试图修复它的前身所具有的大部分局限性。例如，Java 的一个重要特性使它流行起来，那就是只需编写一次就可以在任何地方运行；也就是说，您可以在 Windows 机器上开发代码，然后在 Linux 或任何其他机器上运行，您所需要的只是一个 JVM。它还提供了垃圾收集等附加功能，使开发人员无需维护内存分配和释放；**即时编译器**（**JIT**）使 Java 智能化和快速化，删除指针等功能使其更加安全。前面提到的所有特性以及后来添加的 Web 支持使 Java 成为开发人员的热门选择。大约 22 年后，在一个新语言来去匆匆的世界里，java 10 已经成功地被社区发布和改编，这充分说明了 Java 的成功。

# Java 编程范式

什么是编程范式？自从软件开发开始，就有不同的方法来设计编程语言。对于每种编程语言，我们都有一套概念、原则和规则。这样一组概念、原则和规则称为编程范式。在理论上，语言被认为只属于一种范式，但在实践中，编程范式大多是在一种语言中结合起来的。

在下一节中，我们将重点介绍 Java 编程语言所基于的编程范式，以及描述这些范式的主要概念。它们是命令式、面向对象、声明式和函数式编程。

# 命令式程序设计

命令式编程是一种编程范式，在这种范式中，编写语句来改变程序的状态。这个概念出现在计算机的初期，非常接近计算机的内部结构。程序是在处理单元上运行的一组指令，它以命令式的方式改变状态（作为变量存储在内存中）。名称*命令*意味着执行的指令决定了程序的运行方式。

今天大多数最流行的编程语言都或多或少地基于命令式范式。主要是命令式语言的最好例子是 C。

# 现实生活中必不可少的例子

为了更好地理解命令式编程范式的概念，让我们举下面的例子：你在你的镇上和一个朋友见面，参加一个黑客竞赛，但他不知道如何去那里。我们将以一种必要的方式向他解释如何到达那里：

1.  从中心站乘有轨电车。
2.  在第三站下车。
3.  向右走，朝第六大道走，直到第三个路口。

# 面向对象范式

面向对象的范例通常与命令式编程相关联，但是在实践中，函数式范例和面向对象范例可以共存。Java 就是支持这种协作的活生生的证明。

在下一节中，我们将简要介绍主要的面向对象概念，因为它们是用 Java 语言实现的。

# 对象和类

对象是**面向对象编程**（**OOP**）语言的主要元素。对象同时包含状态和行为。

如果我们把类看作模板，那么对象就是模板的实现。例如，如果`Human`是一个类，它定义了一个人可以拥有的行为和属性，那么你和我就是这个`Human`类的对象，因为我们已经满足了作为一个人的所有要求。或者，如果我们认为汽车是一个阶级，一个特定的本田思域汽车将是这个阶级的对象。它将实现汽车的所有特性和行为，如发动机、方向盘、前照灯等，并具有前进、后退等行为。我们可以看到面向对象的范例是如何与现实世界联系在一起的。现实世界中几乎所有的东西都可以用类和对象来考虑，因此 OOP 变得轻松和流行。

面向对象编程基于四个基本原则：

*   封装
*   抽象
*   继承
*   多态（亚型多态）。

# 封装

**封装**基本上就是属性和行为的绑定。其思想是将对象的属性和行为保持在一个位置，以便易于维护和扩展。封装还提供了一种向用户隐藏不必要细节的机制。在 Java 中，我们可以为方法和属性提供访问说明符，以管理类用户可见的内容和隐藏的内容。

封装是面向对象语言的基本原则之一。它有助于不同模块的解耦。解耦模块可以或多或少地独立开发和维护。通过这种技术，解耦的模块/类/代码可以在不影响其外部公开行为的情况下进行内部更改，这种技术称为代码重构。

# 抽象

抽象与封装密切相关，在某种程度上，它与封装重叠。简单地说，抽象提供了一种机制，它公开了一个对象做什么，隐藏了这个对象如何做它应该做的事情。

一个真实的抽象例子是汽车。为了驾驶一辆汽车，我们并不需要知道汽车引擎盖下有什么，但我们需要知道它暴露给我们的数据和行为。数据显示在汽车的仪表板上，行为由我们可以用来驾驶汽车的控件表示。

# 继承

继承是将一个对象或类基于另一个对象或类的能力。有一个父类或基类，它为实体提供顶级行为。满足作为父类一部分的条件的每个子类实体或子类都可以从父类继承，并根据需要添加其他行为。

让我们举一个真实的例子。如果我们把`Vehicle`看作父类，我们就知道`Vehicle`可以有某些属性和行为。例如，它有一个引擎、门等等，而且它可以移动。现在，所有满足这些标准的实体，例如，`Car`、`Truck`、`Bike`等等，都可以从`Vehicle`继承并添加到给定的属性和行为之上。换句话说，我们可以说`Car`是`Vehicle`的*子类*。

让我们看看这将如何作为代码；我们将首先创建一个名为`Vehicle`的基类。该类有一个构造器，它接受一个`String`（车辆名称）：

```java
public class Vehicle 
{
  private Stringname;
  public Vehicle(Stringname)
  { 
    this.name=name;
  }
}
```

现在我们可以用构造器创建一个`Car`类。`Car`类派生自`Vehicle`类，因此继承并可以访问基类中声明为`protected`或`public`的所有成员和方法：

```java
public class Car extends Vehicle
{
  public Car(String name)
  {
    super(name)
  }
}
```

# 多态

广义地说，多态为我们提供了一种选择，可以为不同类型的实体使用相同的接口。多态有两种主要类型：编译时和运行时。假设你有一个`Shape`类，它有两个区域方法。一个返回圆的面积，它接受一个整数；也就是说，输入半径，它返回面积。另一种方法计算矩形的面积，并采用两种输入：长度和宽度。编译器可以根据调用中参数的数量来决定调用哪个`area`方法。这是多态的编译时类型。

有一群技术人员认为只有运行时多态才是真正的多态。运行时多态，有时也称为子类型多态，在子类继承超类并覆盖其方法时起作用。在这种情况下，编译器无法决定最终是执行子类实现还是执行超类实现，因此在运行时做出决定。

为了详细说明，让我们以前面的示例为例，向汽车类型添加一个新方法来打印对象的类型和名称：

```java
public String toString()
{
  return "Vehicle:"+name;
}
```

我们在派生的`Car`类中覆盖相同的方法：

```java
public String toString()
{ 
  return "Car:"+name;
}
```

现在我们可以看到子类型多态在起作用。我们创建一个`Vehicle`对象和一个`Car`对象。我们将每个对象分配给一个`Vehicle`变量类型，因为一个`Car`也是一个`Vehicle`。然后我们为每个对象调用`toString`方法。对于`vehicle1`，它是`Vehicle`类的一个实例，它将调用`Vehicle.toString()`类。`vehicle2`是`Car`类的实例，调用`Car`类的`toString`方法：

```java
Vehicle vehicle1 = new Vehicle("A Vehicle");
Vehicle vehicle2 = new Car("A Car")
System.out.println(vehicle1.toString());
System.out.println(vehicle2.toString());
```

# 声明式程序设计

让我们回到现实生活中的祈使式示例，在这个示例中，我们向朋友指示如何到达一个地方。当我们按照声明式编程范式思考时，我们可以简单地给他地址，让他知道如何到达那里，而不是告诉我们的朋友如何到达特定的位置。在这种情况下，我们告诉他该怎么做，而我们并不关心他是否使用地图或 GPS，或者他是否向某人请示：“早上 9:30 在第五大道和第九大道的交界处”。

与命令式编程相反，声明式编程是一种编程范式，它指定程序应该做什么，而不指定如何做。纯声明性语言包括数据库查询语言，如 SQL 和 XPath，以及正则表达式。

声明式编程语言比命令式编程语言更抽象。它们不模仿硬件结构，因此，它们不改变程序的状态，而是将程序转换为新的状态，更接近于数学逻辑。

一般来说，非强制性的编程风格被认为属于声明性的范畴。这就是为什么有许多类型的范式属于声明性范畴。在我们的探索中，我们将看到与我们的旅程范围相关的唯一一个：函数式编程。

# 函数式程序设计

函数式编程是声明式编程的一个子范式。与命令式编程相反，函数式编程不会改变程序的内部状态。

在命令式编程中，函数可以更多地看作是指令序列、例程或过程。它们不仅依赖于存储在内存中的状态，还可以改变这种状态。这样，调用具有相同参数的命令函数可以根据当前程序的状态产生不同的结果，同时，执行的函数可以更改程序的变量。

在函数式编程术语中，函数类似于数学函数，函数的输出只取决于它的参数，而不管程序的状态如何，同时不受函数执行的影响。

自相矛盾的是，虽然命令式编程自计算机诞生以来就已经存在，但函数式编程的基本概念可以追溯到这之前。大多数函数式语言都是基于 Lambda 演算的，Lambda 演算是由数学家 Alonzo Church 在 20 世纪 30 年代创建的一种形式化的数理逻辑系统。

函数式语言在那个时代如此流行的原因之一是它们可以很容易地在并行环境中运行。这不应与多线程混淆。允许函数式语言并行运行的主要特性是它们所依赖的基本原则：函数只依赖于输入参数，而不依赖于程序的状态。也就是说，它们可以在任何地方运行，然后将多个并行执行的结果连接起来并进一步使用。

# 使用集合与使用流

每个使用 Java 的人都知道集合。我们以一种强制性的方式使用集合：我们告诉程序如何做它应该做的事情。让我们以下面的示例为例，其中我们实例化了一个由 10 个整数组成的集合，从 1 到 10：

```java
List<Integer> list = new ArrayList<Integer>();
for (int i = 0; i < 10; i++)
{
  list.add(i);
}
```

现在，我们将创建另一个集合，在其中只过滤奇数：

```java
List<Integer> odds = new ArrayList<Integer>();
for (int val : list)
{
  if (val % 2 == 0)
  odds.add(val);
}
```

最后，我们要打印结果：

```java
for (int val : odds)
{
  System.out.print(val);
}
```

如您所见，我们编写了相当多的代码来执行三个基本操作：创建数字集合、过滤奇数，然后打印结果。当然，我们可以只在一个循环中完成所有的操作，但是如果我们完全不使用一个循环呢？毕竟，使用循环意味着我们告诉程序如何完成它的任务。从 Java8 开始，我们就可以使用流在一行代码中完成同样的任务：

```java
IntStream
.range(0, 10)
.filter(i -> i % 2 == 0)
.forEach( System.out::print );
```

流在`java.util.stream`包中定义，用于管理可以执行函数式操作的对象流。流是集合的功能对应者，为映射和归约操作提供支持。

我们将在后面的章节中进一步讨论 Java 中的流和函数编程支持。

# 统一建模语言简介

**统一建模语言**（**UML**）是一种建模语言，它帮助我们表示软件是如何构造的，不同的模块、类和对象是如何相互作用的，它们之间的关系是什么。

UML 经常与面向对象设计结合使用，但是它的范围更广。但是，这超出了本书的范围，因此，在下一节中，我们将重点介绍与本书相关的 UML 特性。

在 UML 中，我们可以定义一个系统的结构和行为，我们可以通过图表来可视化模型或部分模型。有两种类型的图表：

*   结构图用来表示系统的结构。有许多类型的结构图，但我们只对类图感兴趣。对象、包和组件图类似于类图。
*   行为图用于描述系统的行为。交互图是行为图的子集，用于描述系统不同组件之间的控制流和数据流。在行为图中，序列图在面向对象设计中得到了广泛的应用。

类图是在面向对象的设计和开发阶段使用最多的一种图。它们是一种结构图，用于说明类的结构以及它们之间的关系：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/dsn-ptn-bst-prac-java/img/63b89fcb-6f88-4e78-9446-ddb0c5ae8cd2.jpg)

类图对于描述类在应用中的结构非常有用。大多数情况下，只看结构就足以理解类是如何交互的，但有时这还不够。对于这些情况，我们可以使用行为图和交互图，其中序列图用于描述类和对象的交互。让我们用一个序列图来展示在继承和多态示例中，`Car`和`Vehicle`对象是如何交互的：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/dsn-ptn-bst-prac-java/img/aa49e427-57eb-4726-bb4e-ba65ca305a6e.png)

# 类的关系

在面向对象编程中，除了表示基本概念之一的继承关系外，还有一些其他类关系可以帮助我们建模和开发复杂的软件系统：

*   泛化与实现
*   依赖
*   关联、聚合和组合

# 泛化

继承也称为 **IS-A** 关系，因为从另一个类继承的类可以用作超类。

当一个类表示多个类的共享特征时，称为**泛化**；例如**车辆**是**自行车**、**轿车**、**卡车**的泛化。类似地，当一个类代表一个普通类的特殊实例时，它被称为**特化**，所以**轿车**是**车辆**的特化，如下图所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/dsn-ptn-bst-prac-java/img/ba825a8f-bf4e-4f82-9846-feb9c5df8d27.jpg)

在 UML 术语中，描述继承的关系称为泛化。

# 实现

如果泛化是 UML 中面向对象继承的对应术语，那么在 UML 中，实现表示面向对象编程中类对接口的实现。

假设我们创建了一个名为`Lockable`的接口，该接口仅由可锁定的`Car`实现。在本例中，前面的图的一个版本为`Car`类实现`Lockable`：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/dsn-ptn-bst-prac-java/img/a5bc9f3e-fbe5-451f-98a6-8d9ea4b4da02.png)

# 依赖

依赖关系是 UML 关系中最通用的类型之一。它用于定义一个类以某种方式依赖于另一个类，而另一个类可能依赖于也可能不依赖于第一个类。从属关系用于表示不属于以下各节所述情形之一的关系。依赖有时被称为 **USES-A** 关系。

通常，在面向对象编程语言中，依赖关系用于描述一个类是否在方法的签名中包含第二个类的参数，或者它是否通过将第二个类的实例传递给其他类而不使用它们（不调用其方法）来创建第二个类的实例：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/dsn-ptn-bst-prac-java/img/97a1ab93-81da-4488-93bd-14e843198581.png)

# 关联

关联表示两个实体之间的关系。有两种类型的关联，即组合和聚合。通常，关联由箭头表示，如下图所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/dsn-ptn-bst-prac-java/img/80357f18-8480-4a90-ac71-d11e3d0a00f8.png)

# 聚合

聚合是一种特殊的关联类型。如果继承被认为是 IS-A 关系，那么聚合可以被认为是 **HAS-A** 关系。

聚合用于描述两个或多个类之间的关系，从逻辑角度来看，一个类包含另一个类，但包含的类的实例可以独立于第一个类，在其上下文之外，或者可以在其他类之间共享。例如，一个**学院**有一个**老师**；另外，每个**老师**必须属于**学院**，但是如果**学院**不存在，一个**老师**仍然可以是活动的，如下图所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/dsn-ptn-bst-prac-java/img/203ed563-2000-44fb-a156-f3b26d3366dd.png)

# 组合

顾名思义，一个类是另一个类的组合。这在某种程度上类似于聚合，区别在于当主类不存在时，依赖类就不存在了。例如**房屋**由**房间**组成，但**房屋**被毁后**房间**不复存在，如下图所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/dsn-ptn-bst-prac-java/img/fbe52909-cff7-4a88-a6ba-92790a9f37f6.png)

在实践中，尤其是在 Java 等具有垃圾收集器的语言中，组合和聚合之间的边界没有得到很好的定义。对象不会被手动销毁；当它们不再被引用时，垃圾收集器会自动销毁它们。因此，从编码的角度来看，我们不应该真正关心我们是否处理组合或聚合关系，但是如果我们想在 UML 中有一个定义良好的模型，这一点很重要。

# 设计模式与原则

软件开发是一个不仅仅是编写代码的过程，无论您是在一个大型团队中工作还是在一个人的项目中工作。应用的结构方式对软件应用的成功程度有着巨大的影响。

当我们谈论一个成功的软件应用时，我们不仅要讨论应用是如何完成它应该做的事情，还要讨论我们在开发它上投入了多少精力，以及它是否易于测试和维护。如果不以正确的方式进行，飞涨的开发成本将导致一个没有人想要的应用。

软件应用是为了满足不断变化和发展的需求而创建的。一个成功的应用还应该提供一个简单的方法，通过它可以扩展以满足不断变化的期望。

幸运的是，我们不是第一个遇到这些问题的人。一些问题已经面临并得到处理。在软件的设计和开发过程中，应用一套面向对象的设计原则和模式，可以避免或解决这些常见问题。

面向对象的设计原则也称为**实体**。这些原则是在设计和开发软件时可以应用的一组规则，以便创建易于维护和开发的程序。它们最初是由 robertc.Martin 介绍的，它们是敏捷软件开发过程的一部分。实体原则包括单一责任原则、开闭原则、Liskov 替代原则、接口分离原则和依赖倒置原则。

除了设计原则之外，还有面向对象的设计模式。设计模式是可以应用于常见问题的通用可重用解决方案。遵循 Christopher Alexander 的概念，设计模式首先被 Kent Beck 和 Ward Cunningham 应用到编程中，并在 1994 年被所谓的**四人帮**（**GOF**）一书所推广。在下一节中，我们将介绍坚实的设计原则，在接下来的章节中，设计模式将遵循这些原则。

# 单一责任原则

单一责任原则是一种面向对象的设计原则，它规定软件模块只有一个改变的理由。在大多数情况下，在编写 Java 代码时，我们会将其应用于类。

单一责任原则可以被视为使封装发挥最佳效果的良好实践。更改的原因是触发更改代码的需要。如果一个类受到多个更改原因的影响，那么每个原因都可能引入影响其他原因的更改。当这些更改单独管理但影响同一模块时，一组更改可能会破坏与其他更改原因相关的功能。

另一方面，每一个改变的责任/理由都会增加新的依赖关系，使得代码不那么健壮，更难改变。

在我们的示例中，我们将使用数据库来持久化对象。假设`Car`类增加了方法来处理创建、读取、更新、删除的数据库操作，如下图所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/dsn-ptn-bst-prac-java/img/8db505f4-fe4c-4a8e-9c2a-e8b7615f4007.jpg)

在这种情况下，`Car`将不仅封装逻辑，而且封装数据库操作（两个职责是更改的两个原因）。这将使我们的类更难维护和测试，因为代码是紧密耦合的。`Car`类将依赖于数据库，因此如果将来要更改数据库系统，则必须更改`Car`代码。这可能会在`Car`逻辑中产生错误。

相反，更改`Car`逻辑可能会在数据持久性中产生错误。

该解决方案将创建两个类：一个封装`Car`逻辑，另一个负责持久性：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/dsn-ptn-bst-prac-java/img/1b8c5fbd-6819-47a2-8d2c-dbb2fc68823c.jpg)

# 开/关原则

这一原则如下：

模块、类和函数应该为扩展而打开，为修改而关闭

应用这一原则将有助于我们开发复杂而健壮的软件。我们必须想象我们开发的软件正在构建一个复杂的结构。一旦我们完成了它的一部分，我们就不应该再修改它，而应该在它的基础上进行构建。

开发软件的时候，也是一样的。一旦我们开发并测试了一个模块，如果我们想改变它，我们不仅要测试我们正在改变的功能，还要测试它负责的整个功能。这涉及到大量额外的资源，这些资源可能从一开始就无法估计，而且还可能带来额外的风险。一个模块中的更改可能会影响其他模块或整个模块的功能。以下为图示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/dsn-ptn-bst-prac-java/img/cb6c842d-fb85-46a2-a8cd-d458c780061a.jpg)

因此，最佳实践是在模块完成后保持不变，并通过使用继承和多态扩展模块来添加新功能。开/闭原则是最重要的设计原则之一，是大多数设计模式的基础。

# 里氏替换原则

barbaraliskov 指出，*派生类型必须完全可以替代它们的基类型*。**里氏替代原则**（**LSP**）与亚型多态密切相关。基于面向对象语言中的子类型多态，派生对象可以用其父类型替换。例如，如果我们有一个`Car`对象，它可以在代码中用作`Vehicle`。

LSP 声明，在设计模块和类时，我们必须确保从行为的角度来看派生类型是可替换的。当派生类型被其父类型替换时，其余代码将以子类型的形式对其进行操作。从这个角度来看，派生类型的行为应该和它的父类型一样，而不应该破坏它的行为。这被称为强行为亚型。

为了理解 LSP，让我们举一个违反原则的例子。在开发汽车服务软件时，我们发现需要对以下场景进行建模。当一辆汽车被留下来维修时，车主就离开了汽车。服务助理拿着钥匙，当车主离开时，他去检查他是否有正确的钥匙，是否发现了正确的车。他只需打开门锁，然后把钥匙放在一个指定的地方，上面有一张便条，这样修理工在检查汽车时就可以很容易地取起来。

我们已经定义了一个`Car`类。我们现在创建一个`Key`类，并在`Car`类中添加两个方法：`lock`和`unlock`。我们添加了相应的方法，以便助手检查钥匙是否与汽车匹配：

```java
public class Assistant
{
  void checkKey(Car car, Key key)
  {
    if ( car.lock(key) == false ) System.out.println("Alert! Wrong 
    key, wrong car or car lock is broken!");
  }  
}
```

示意图如下：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/dsn-ptn-bst-prac-java/img/b04f803c-be13-4f32-b095-4361b1ae4a74.jpg)

在使用我们的软件时，我们意识到，小车有时是通过汽车服务来维修的。由于小车是四轮车，我们创建了一个`Buggy`类，继承自`Car`：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/dsn-ptn-bst-prac-java/img/412d100b-a7cf-47f9-af4f-4e70d99b94ed.jpg)

四轮马车没有门，所以不能上锁或开锁。我们相应地实现我们的代码：

```java
public bool lock(Key key)
{
  // this is a buggy so it can not be locked return false;
}
```

我们设计的软件适用于汽车，不管它们是否是小车，因此将来我们可能会将其扩展到其他类型的汽车。一个问题可能是因为汽车需要上锁和开锁。

# 接口分离原则

以下引用自[这个页面](https://www.oodesign.com/interface-segregation-principle.html)：

“不应强迫客户依赖他们不使用的接口。”

应用时，**接口分离原则**（**ISP**）减少了代码耦合，使软件更健壮，更易于维护和扩展。ISP 最初是由 robertmartin 宣布的，当时他意识到，如果这个原则被打破，客户端被迫依赖于他们不使用的接口，那么代码就变得紧密耦合，几乎不可能为它添加新的功能。

为了更好地理解这一点，让我们再次以汽车服务为例（参见下图）。现在我们需要实现一个名为·Mechanic 的类。技工修车，所以我们增加了一种修车方法。在这种情况下，`Mechanic`类依赖于`Car`类。然而，`Car`类比`Mechanic`类需要更多的方法：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/dsn-ptn-bst-prac-java/img/0663ce8b-34f9-42a9-956d-168fa1ce414a.jpg)

这是一个糟糕的设计，因为如果我们想用另一辆车替换一辆车，我们需要在`Mechanic`类中进行更改，这违反了开/关原则。相反，我们必须创建一个只公开`Mechanic`类中所需的相关方法的接口，如下图所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/dsn-ptn-bst-prac-java/img/e4532531-c690-46b0-95e3-adf8b1e4a238.jpg)

# 依赖倒置原则

“高级模块不应依赖于低级模块。两者都应该依赖于抽象。”

“抽象不应该依赖于细节。细节应该取决于抽象。”

为了理解这一原理，我们必须解释耦合和解耦的重要概念。耦合是指软件系统的模块之间相互依赖的程度。依赖性越低，系统的维护和扩展就越容易。

有不同的方法来解耦系统的组件。其中之一是将高级逻辑与低级模块分开，如下图所示。在这样做的时候，我们应该通过使它们依赖于抽象来减少两者之间的依赖性。这样，可以在不影响其他模块的情况下更换或扩展其中任何模块：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/dsn-ptn-bst-prac-java/img/d18ae88d-58d2-42a4-be15-563b80d69ec4.jpg)

# 总结

在本章中，我们介绍了 Java 中使用的主要编程范式。我们已经了解到两种不同的范式，如命令式编程和函数式编程，可以在同一种语言中共存；我们还了解了 Java 如何从纯命令式面向对象编程发展到集成函数式编程元素。

尽管 Java 从版本 8 开始引入了新的功能元素，但它的核心仍然是一种面向对象的语言。为了编写易于扩展和维护的可靠而健壮的代码，我们学习了面向对象编程语言的基本原理。

开发软件的一个重要部分是设计程序组件的结构和所需的行为。这样，我们就可以在大型系统上工作，在大型团队中工作，在团队内部或团队之间共享我们的面向对象设计。为了能够做到这一点，我们重点介绍了与面向对象设计和编程相关的主要 UML 图和概念。我们在书中还广泛地使用 UML 来描述这些例子。

在介绍了类关系并展示了如何在图中表示它们之后，我们进入下一节，在这里我们描述了什么是面向对象的设计模式和原则，并介绍了主要原则。

在下一章中，我们将继续介绍一组处理对象创建的设计模式，使我们的代码具有健壮性和可扩展性。


# 二、创建型模式

> 原文：[Design Patterns and Best Practices in Java](https://libgen.rs/book/index.php?md5=096AE07A3FFC0E5B9926B8DE68424560)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)
> 
> 贡献者：[飞龙](https://github.com/wizardforcel)
> 
> 本文来自[【ApacheCN Java 译文集】](https://github.com/apachecn/apachecn-java-zh)，采用[译后编辑（MTPE）](https://cn.bing.com/search?q=%E8%AF%91%E5%90%8E%E7%BC%96%E8%BE%91)流程来尽可能提升效率。

本章的目的是学习创造模式。创造模式是处理对象创造的模式。在本章中，我们将介绍以下主题：

*   单例模式
*   简单工厂模式
*   工厂方法模式
*   抽象工厂模式
*   构建器模式
*   原型模式
*   对象池模式

# 单例模式

单例模式可能是自 Java 诞生以来使用最广泛的设计模式。这是一个简单的模式，易于理解和使用。有时它被过度使用，在不需要它的情况下。在这种情况下，使用它的缺点大于它带来的好处。因此，单例有时被认为是反模式。然而，有许多场景需要单例。

顾名思义，单例模式用于确保只能创建对象的单个实例。除此之外，它还提供对该实例的全局访问。下面的类图描述了单例模式的实现：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/dsn-ptn-bst-prac-java/img/370befdc-f771-4b59-b3b1-850cd0481247.png)

单例模式的实现非常简单，只包含一个类。为了确保单例实例是唯一的，所有单例构造器都应该是私有的。全局访问是通过一个静态方法完成的，可以全局访问该方法来获取单例实例，如下代码所示：

```java
public class Singleton
{
  private static Singleton instance;
  private Singleton()
  {
    System.out.println("Singleton is Instantiated.");
  }
  public static Singleton getInstance()
  {
    if (instance == null)
    instance = new Singleton();
    return instance;
  }
  public void doSomething()
  {
    System.out.println("Something is Done.");
  }
}
```

当我们需要在代码中的某个地方使用单例对象时，我们只需这样调用它：

```java
Singleton.getInstance().doSomething();
```

在`getInstance`方法中，我们检查实例是否为`null`。如果实例不为`null`，则表示该对象是在之前创建的；否则，我们将使用`new`操作符创建它。之后，无论哪种情况，它都不再为`null`，因此我们可以返回实例对象。

# 同步单例

同步单例的代码简单而有效，但是有一种情况我们应该考虑。如果我们在多线程应用中使用我们的代码，可能是两个线程在实例为`null`时同时调用`getInstance`方法。当发生这种情况时，可能是第一个线程继续使用`new`操作符实例化单例，在完成之前，第二个线程检查单例是否为`null`。因为第一个线程没有完成实例化，所以第二个线程会发现实例为空，所以它也会开始实例化它。

这种情况看起来几乎不可能，但是如果需要很长时间来实例化单例，那么发生这种情况的可能性就非常大，不可忽视。

这个问题的解决办法很简单。我们必须创建一个检查实例是否为空线程安全的块。这可以通过以下两种方式实现：

*   通过在其声明中添加`synchronized`关键字，使`getInstance`方法线程安全：

```java
public static synchronized Singleton getInstance()
```

*   将`if (instance == null)`状态包装在`synchronized`块中。当我们在这个上下文中使用`synchronized`块时，我们需要指定一个提供锁的对象。我们为此使用了`Singleton.class`对象，如下代码段所示：

```java
synchronized (SingletonSync2.class) 
{
  if (instance == null)
  instance = new SingletonSync2();
}
```

# 带有双检锁机制的同步单例

前面的实现是线程安全的，但它引入了不必要的延迟：检查实例是否已创建的块是同步的。这意味着块一次只能由一个线程执行，但只有在实例尚未创建时锁定才有意义。当单例实例已经创建时，每个线程都可以以不同步的方式获取当前实例。

在`synchronized`块前增加一个附加条件，只有在单例还没有实例化时，才会移动线程安全锁：

```java
if (instance == null)
{
  synchronized (SingletonSync2.class) 
  {
    if (instance == null)
    instance = new SingletonSync2();
  }
}
```

注意，`instance == null`被检查了两次。这是必要的，因为我们必须确保在`synchronized`块中也进行了检查。

# 无锁线程安全单例

Java 中单例模式的最佳实现之一依赖于一个类是一次加载的事实。通过在声明时直接实例化静态成员，我们可以确保只有一个类实例。此实现避免了锁定机制和查看实例是否已创建的附加检查：

```java
public class LockFreeSingleton
{
  private static final LockFreeSingleton instance = new 
  LockFreeSingleton();
  private LockFreeSingleton()
  {
    System.out.println("Singleton is Instantiated."); 
  }
  public static synchronized LockFreeSingleton getInstance()
  {
    return instance;
  }
  public void doSomething()
  {
    System.out.println("Something is Done.");
  }
}
```

# 提前和延迟加载

根据创建实例对象的时间，单例可以分为两类。如果单例是在应用启动时创建的，则认为它是一个**早期/急切实例化**。否则，如果第一次调用`getInstance`方法时调用了单例构造器，则认为是**惰性加载单例**。

上一个示例中提供的无锁线程安全单例被认为是 Java 第一个版本中的早期加载单例。然而，在最新版本的 Java 中，类是在需要时加载的，所以这个版本也是一个延迟加载版本。此外，类被加载的时刻取决于 JVM 实现，不同版本的类可能不同。应该避免基于 JVM 实现做出设计决策。

目前，Java 中没有可靠的选项来创建早期加载的单例。如果我们真的需要一个早期的实例化，我们应该在应用开始时强制它，只需调用`getInstance()`方法，如下代码所示：

```java
Singleton.getInstance();
```

# 工厂模式

如前一章所讨论的，继承是面向对象编程的基本概念之一。与亚型多态一起，它给出了 IS-A 关系。`Car`对象可以作为`Vehicle`对象处理。`Truck`对象也可以作为`Vehicle`对象处理。一方面，这种抽象使我们的代码更薄，因为同一段代码可以处理`Car`和`Truck`对象的操作。另一方面，它给我们提供了一个选项，通过简单地添加新的类，比如`Bike`和`Van`，而不修改它，就可以将代码扩展到新类型的`Vehicle`对象。

当我们处理这样的场景时，最棘手的部分之一就是对象的创建。在面向对象编程中，使用特定类的构造器实例化每个对象，如下代码所示：

```java
Vehicle vehicle = new Car();
```

这段代码意味着实例化对象的类和实例化对象的类之间的依赖关系。这样的依赖关系使得我们的代码紧密耦合，在不修改代码的情况下很难扩展。例如，如果我们需要用另一个类型替换`Car`，比如说`Truck`，我们需要相应地更改代码：

```java
Vehicle vehicle = new Truck();
```

但这里有两个问题。首先，我们的类应该为扩展而开放，为修改而关闭（开闭原则）。第二，每个类应该只有一个改变的理由（单一责任原则）。每次添加一个新类时更改主代码将打破开放/关闭原则，让主类除了功能外还负责实例化`vehicle`对象将打破单一责任原则。

在这种情况下，我们需要为代码提供更好的设计。我们可以添加一个新类来负责实例化`vehicle`对象。我们将基于这个`SimpleFactory`类调用模式。

# 简单工厂模式

工厂模式用于封装逻辑，以实例化通过公共接口引用的对象。只需稍作改动就可以添加新类。

下面的类图描述了简单工厂的实现：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/dsn-ptn-bst-prac-java/img/43b09446-d183-4a9c-a32b-93048a4062e3.png)

`SimpleFactory`类实现实例化`ConcreteProduct1`和`ConcreteProduct2`的代码。当客户端需要一个对象时，它调用`SimpleFactory`的`createProduct()`方法，参数表示它需要的对象的类型。`SimpleFactory`实例化对应的具体产品并返回。返回的产品被转换为基类类型，因此客户端将以相同的方式处理任何`Product`，而不管它是`ConcreteProduct1`还是`ConcreteProduct2`。

# 静态工厂

让我们编写一个简单的工厂来创建车辆实例。我们有一个抽象的`Vehicle`类和从中继承的三个具体类：`Bike`、`Car`和`Truck`。工厂，也称为静态工厂，将如下所示：

```java
public class VehicleFactory 
{
  public enum VehicleType
  {
    Bike,Car,Truck
  }
  public static Vehicle create(VehicleType type)
  {
    if (type.equals(VehicleType.Bike))
    return new Bike();
    if (type.equals(VehicleType.Car))
    return new Car();
    if (type.equals(VehicleType.Truck))
    return new Truck();
    else return null;
  }
}
```

工厂看起来非常简单，负责实例化`vehicle`类，遵循单一责任原则。它帮助我们减少耦合，因为客户端只依赖于`Vehicle`接口，符合依赖倒置原则。如果我们需要添加一个新的`vehicle`类，我们需要更改`VehicleFactory`类，这样就打破了开/关原则。

我们可以改进这个简单的工厂模式，通过使用一种机制来注册新的类，在需要时实例化这些类，从而使它在扩展时打开，在修改时关闭。有两种方法可以实现这一点：

*   注册产品类对象并使用反射实例化它们
*   注册产品对象，并向每个产品添加一个`newInstance`方法，该方法返回一个与其自身相同的类的新实例

# 使用反射执行类注册的简单工厂

对于此方法，我们将使用一个映射来保留产品 ID 及其相应的类：

```java
private Map<String, Class> registeredProducts = new HashMap<String,Class>();
```

然后，我们添加了一个注册新车的方法：

```java
public void registerVehicle(String vehicleId, Class vehicleClass)
{
  registeredProducts.put(vehicleId, vehicleClass);
}
```

`create`方法如下：

```java
public Vehicle createVehicle(String type) throws InstantiationException, IllegalAccessException
{
  Class productClass = registeredProducts.get(type);
  return (Vehicle)productClass.newInstance();
}
```

在某些情况下，进行反思要么是不可能的，要么是不鼓励的。反射需要在某些环境中可能不存在的运行时权限。如果性能是一个问题，反射可能会减慢程序，因此应该避免。

# 使用`Product.newInstance`执行类注册的简单工厂

在前面的代码中，我们使用反射来实例化新的车辆。如果我们必须避免反射，我们可以使用一个类似的工厂来注册工厂应该能够创建的新车辆类。我们将不向映射中添加类，而是添加要注册的每种类型的对象的实例。每个产品将能够创建自己的新实例。

我们首先在基类`Vehicle`中添加一个抽象方法：

```java
abstract public Vehicle newInstance();
```

对于每个产品，必须实现基类中声明为`abstract`的方法：

```java
@Override
public Car newInstance() 
{
  return new Car();
}
```

在`factory`类中，我们将更改映射以保留对象的 ID 以及`vehicle`对象：

```java
private Map<String, Vehicle> registeredProducts = new HashMap<String,Vehicle>();
```

然后我们通过传递一个实例来注册一个新类型的车辆：

```java
public void registerVehicle(String vehicleId, Vehicle vehicle)
{
  registeredProducts.put(vehicleId, vehicle);
}
```

我们相应地改变`createVehicle`方法：

```java
public AbstractProduct createVehicle(String vehicleId) 
{
  return registeredProducts.get(vehicleId).newInstance();
}
```

# 工厂方法模式

工厂方法模式是对静态工厂的改进。`factory`类是抽象的，实例化特定产品的代码被移动到实现抽象方法的子类中。这样，`factory`类就可以扩展而不需要修改。工厂方法模式的实现在以下类图中描述：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/dsn-ptn-bst-prac-java/img/7b9b05d9-b441-4fa4-a6f4-05bbda05524a.png)

现在是编写示例代码的时候了。假设我们有一个汽车工厂。目前，我们生产两种车型：小型跑车和大型家用车。在我们的软件中，客户可以决定他们是想要一辆小型车还是一辆大型车。首先，我们创建一个包含两个子类的`Vehicle`类：`SportCar`和`SedanCar`。

现在我们有了车辆结构，让我们建立抽象工厂。请注意，工厂没有创建新实例的任何代码：

```java
public abstract class VehicleFactory 
{
  protected abstract Vehicle createVehicle(String item);
  public Vehicle orderVehicle(String size, String color) 
  {
    Vehicle vehicle = createVehicle(size);
    vehicle.testVehicle();
    vehicle.setColor(color);
    return vehicle;
  }
}
```

为了添加代码来创建`Car`实例，我们将`VehicleFactory`子类化，创建一个`CarFactory`。汽车工厂必须实现从父类调用的`createVehicle`抽象方法。实际上，`VehicleFactory`将具体车辆的实例化委托给子类：

```java
public class CarFactory extends VehicleFactory 
{
  @Override
  protected Vehicle createVehicle(String size) 
  {
    if (size.equals("small"))
    return new SportCar();
    else if (size.equals("large"))
    return new SedanCar();
    return null;
  }
}
```

在客户端中，我们只需创建工厂并创建订单：

```java
VehicleFactory carFactory = new CarFactory();
carFactory.orderVehicle("large", "blue");
```

在这一点上，我们意识到一个汽车厂能带来多少利润。是时候扩展我们的业务了，我们的市场调查告诉我们，卡车的需求量很大。那么让我们构建一个`TruckFactory`：

```java
public class TruckFactory extends VehicleFactory 
{
  @Override
  protected Vehicle createVehicle(String size) 
  {
    if (size.equals("small"))
    return new SmallTruck();
    else if (size.equals("large"))
    return new LargeTruck();
    return null;
  }
}
```

启动订单时，我们使用以下代码：

```java
VehicleFactory truckFactory = new TruckFactory();
truckFactory.orderVehicle("large", "blue");
```

# 匿名具体工厂

我们继续前面的代码，添加了一个`BikeFactory`，客户可以从中选择一辆小自行车或一辆大自行车。我们不需要创建单独的类文件就可以做到这一点；我们可以简单地创建一个匿名类，直接在客户端代码中扩展`VehicleFactory`：

```java
VehicleFactory bikeFactory = new VehicleFactory() 
{
  @Override
  protected Vehicle createVehicle(String size) 
  {
    if (size.equals("small"))
    return new MountainBike();
    else if (size.equals("large"))
    return new CityBike();
    return null; 
  }
};
bikeFactory.orderVehicle("large", "blue");
```

# 抽象工厂

抽象工厂是工厂方法的扩展版本。它不是创建单一类型的对象，而是用于创建相关对象的族。如果工厂方法有一个`AbstractProduct`，则抽象工厂有几个`AbstractProduct`类。

factory 方法有一个抽象方法，由每个具体的工厂用代码来实例化抽象产品。抽象工厂对每个抽象产品都有一种方法。

如果我们采用抽象工厂模式，并将其应用于包含单个对象的族系，那么我们就有了工厂方法模式。工厂方法只是抽象工厂的一个特例。

抽象工厂模式的实现在以下类图中描述：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/dsn-ptn-bst-prac-java/img/06fa611e-4cc9-4253-b11b-b5010e23e9cc.png)

抽象工厂模式由以下类组成：

*   `AbstractFactory`：这个抽象类声明了创建产品类型的方法。它包含每个要创建的`AbstractProduct`的方法。
*   `ConcreteFactories`：实现`AbstractFactory`基类中声明的方法的具体类。每套混凝土产品都有一个工厂。
*   `AbstractProducts`：需要的对象的基本接口或类。一个相关产品系列由每个层次结构中的相似产品组成：`ProductA1`和`ProductB1`来自第一个类系列，由`ConcreteFactory1`实例化；第二个类系列`ProductA2`和`ProductB2`由`ConcreteFactory2`实例化。

# 简单工厂与工厂方法与抽象工厂

我们讨论了实现工厂模式的三种方法，即简单工厂、工厂方法和抽象工厂模式。如果您对这三种实现感到困惑，就不必责怪您，因为它们之间有很多重叠。此外，这些模式没有一个单一的定义，专家们在如何实现这些模式上可能存在分歧。

其思想是理解核心概念。我们可以说，工厂模式的核心是将创建适当对象的责任委托给工厂类。如果我们的工厂很复杂，也就是说，它应该服务于多种类型的对象或工厂，我们可以相应地修改代码。

# 构建器模式

构建器模式的作用与其他创造性模式相同，但它以不同的方式和出于不同的原因。在开发复杂的应用时，代码往往变得更加复杂。类倾向于封装更多的功能，同时，类结构变得更加复杂。随着功能的增长，需要覆盖更多的场景，对于这些场景，需要不同的类表示。

当我们有一个复杂的类需要实例化为具有不同结构或不同内部状态的不同对象时，我们可以使用不同的类来封装实例化逻辑。这些类被称为**构建器**。每次我们需要来自同一类的具有不同结构的对象时，我们都可以创建另一个构建器来创建这样的实例。

同样的概念不仅可以用于需要不同表示的类，也可以用于由其他对象组成的复杂对象。

创建构建器类来封装实例化复杂对象的逻辑符合单一责任原则和打开/关闭原则。实例化复杂对象的逻辑被移动到一个单独的**构建器**类。当我们需要不同结构的对象时，我们可以添加新的构建器类，这样代码就可以关闭进行修改，打开进行扩展，如图所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/dsn-ptn-bst-prac-java/img/be5faf3c-8da2-4ee3-8f78-d3692b71ae57.png)

构建器模式中涉及以下类：

*   `Product`：我们必须构建其对象的类。它是一个复杂的或复合的对象，我们需要不同的表示。
*   `Builder`：一个抽象类或接口，它声明了构建产品的各个部分。它的作用是只公开构建`Product`所需的功能，隐藏`Product`功能的其余部分；它将`Product`与构建它的高级类分离。
*   `ConcreteBuilder`：实现`Builder`接口中声明的方法的具体构建器。除了在`Builder`抽象类中声明的方法外，它还有一个`getResult`方法返回生成的产品。
*   `Director`：一个类，指导如何构建对象。在构建器模式的某些变体中，这个类被删除，它的角色由客户端或构建器承担。

# 汽车构建器示例

在本节中，我们将把构建器模式应用到汽车软件中。我们有一个`Car`类，我们需要创建它的实例。根据我们在汽车上添加的部件，我们可以制造轿车和跑车。当我们开始设计软件时，我们意识到：

*   `Car`类相当复杂，创建类对象也是一项复杂的操作。在`Car`构造器中添加所有实例化逻辑将使类变得相当大。
*   我们需要制造几种类型的汽车。通常，对于这个场景，我们会添加几个不同的构造器，但是我们的直觉告诉我们这不是最好的解决方案。
*   在未来，我们可能需要建立不同类型的汽车对象。对半自动汽车的需求已经相当高了，所以在不久的将来，我们应该准备好在不修改代码的情况下扩展我们的代码。

我们将创建以下类结构：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/dsn-ptn-bst-prac-java/img/c3a042d9-7a7b-4839-b7e9-c2fb94e31516.png)

`CarBuilder`是构建器基类，它包含四个抽象方法。我们创建了两个混凝土构建器：`ElectricCarBuilder`和`GasolineCarBuilder`。每个具体的构建器都必须实现所有的抽象方法。不需要的方法，例如`ElectricCarBuilder`的`addGasTank`被保留为空，或者它们可以抛出异常。电动汽车和汽油汽车有不同的内部结构。

`Director`类使用构建器来创建新的`Car`对象。`buildElectricCar`和`buildGasolineCar`可能相似，但略有不同：

```java
public Car buildElectricCar(CarBuilder builder)
{
  builder.buildCar();
  builder.addEngine("Electric 150 kW");
  builder.addBatteries("1500 kWh");
  builder.addTransmission("Manual");
  for (int i = 0; i < 4; i++)
  builder.addWheel("20x12x30");
  builder.paint("red");
  return builder.getCar();
}
```

但假设我们想制造一辆混合动力汽车，配备电动和汽油发动机：

```java
public Car buildHybridCar(CarBuilder builder)
{
  builder.buildCar();
  builder.addEngine("Electric 150 kW");
  builder.addBatteries("1500 kWh");
  builder.addTransmission("Manual");
  for (int i = 0; i < 4; i++)
  builder.addWheel("20x12x30");
  builder.paint("red");
  builder.addGasTank("1500 kWh");
  builder.addEngine("Gas 1600cc");
  return builder.getCar();
}
```

# 简化的构建器模式

在构建器模式的一些实现中，`Director`类可以被删除。在我们的类示例中，它封装的逻辑非常简单，因此在这种情况下，我们实际上不需要控制器。在本例中，简化的构建器模式如下所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/dsn-ptn-bst-prac-java/img/f83fa1cf-2400-42ea-8f9e-beeea0254f39.png)

在`Director`类中实现的代码被简单地移动到`Client`。当`Builder`和`Product`类太复杂或使用构建器从数据流构建对象时，不建议进行此更改。

# 具有方法链接的匿名构建器

如前所述，处理来自同一类且应采用不同形式的对象的最直观方法是为每个场景创建几个构造器来实例化它们。使用构建器模式来避免这种情况是一种很好的做法。在《Effective Java》中，Joshua Bloch 建议使用内部构建器类和方法链接来替换多个构造器。

方法链接是一种从某些方法返回当前对象（`this`）的技术。这样，可以在链中调用这些方法。例如：

```java
public Builder setColor()
{
  // set color
  return this;
}
```

在我们定义了更多这样的方法之后，我们可以在一个链中调用它们：

```java
builder.setColor("Blue")
.setEngine("1500cc")
.addTank("50")
.addTransmission("auto")
.build();
```

但是，在我们的例子中，我们将使`builder`成为`Car`对象的内部类。因此，当我们需要新客户时，我们可以执行以下操作：

```java
Car car = new Car.Builder.setColor("Blue")
.setEngine("1500cc")
.addTank("50")
.addTransmission("auto")
.build();
```

# 原型模式

原型模式是一种看起来比实际更复杂的模式。实际上，它只是一种克隆对象的方法。如今，实例化对象在性能上并不太昂贵，为什么我们需要克隆对象呢？有几种情况需要克隆已实例化的对象：

*   当新对象的创建依赖于外部资源或硬件密集型操作时
*   当我们需要一个具有相同状态的同一对象的副本，而不必重做所有操作以达到该状态时
*   当我们需要一个对象的实例而不知道它属于哪个具体类时

让我们看看下面的类图：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/dsn-ptn-bst-prac-java/img/d9e65cb7-be8c-4e98-8abc-506d3aaedf64.png)

在原型模式中，涉及以下类：

*   `Prototype`：这是基类，或者一个接口，它声明派生对象必须实现的`clone()`方法。在一个简单的场景中，我们可能没有基类，直接的具体类就足够了。
*   `ConcretePrototype`：这些类实现或扩展了`clone()`方法。应该始终实现此方法，因为它返回其类型的新实例。如果`clone()`方法是在基类中实现的，而我们没有在`ConcretePrototype`中实现，那么当我们在`ConcretePrototype`对象上调用`clone()`方法时，它会返回一个基类`Prototype`对象。

`clone()`方法可以在接口中声明，因此实现该方法的类必须实现该方法。这种强制是在编译时完成的。但是，对于继承自在具有多个级别的层次结构中实现`clone()`方法的类的类，不会强制执行该方法。

# 浅克隆与深克隆

在克隆物体时，我们应该意识到克隆的深度。当我们克隆一个包含简单数据类型的对象，比如`int`和`float`，或者不可变对象，比如字符串，我们应该简单地将这些字段复制到新对象，就这样。

当我们的对象包含对其他对象的引用时，问题就出现了。例如，如果我们必须为一个`Car`类实现一个克隆方法，这个类有一个引擎和一个四个轮子的列表，我们不仅要创建一个新的`Car`对象，还要创建一个新的`Engine`和四个新的`Wheel`对象。毕竟，两辆车不能共用同一台发动机和同一个车轮。这被称为**深克隆**。

浅层克隆是一种只克隆被克隆对象的方法。例如，如果我们必须为一个`Student`对象实现一个`clone`方法，我们就不会克隆它指向的`Course`对象。多个`Student`对象可以指向同一`Course`对象。

在实践中，我们应该根据每个场景来决定是需要深度克隆、浅层克隆还是混合克隆。通常，浅克隆对应于[第一章](1.html)，“从面向对象到函数式编程”中描述的聚合关系，而深克隆对应于组合关系。

# 对象池模式

就性能而言，对象的实例化是最昂贵的操作之一。虽然在过去这可能是一个问题，但现在我们不应该担心它。但是，当我们处理封装外部资源的对象（如数据库连接）时，创建新对象的成本会很高。

解决方案是实现一种机制，可以重用和共享创建成本高昂的对象。此解决方案称为对象池模式，它具有以下结构：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/dsn-ptn-bst-prac-java/img/aef3f759-2802-45cc-9ac8-edf5210c31ad.png)

对象池模式中使用的类如下：

*   `ResourcePool`：封装逻辑以保存和管理资源列表的类。
*   `Resource`：封装有限资源的类。`Resource`类总是被`ResourcePool`引用，所以只要`ResourcePool`没有被反分配，它们就永远不会被垃圾收集。
*   `Client`：使用资源的类。

当一个`Client`需要一个新的`Resource`时，它向`ResourcePool`请求。池检查并获取第一个可用资源并将其返回给客户端：

```java
public Resource acquireResource()
{
  if ( available.size() <= 0 )
  {
    Resource resource = new Resource();
    inuse.add(resource);
    return resource; 
  }
  else
  {
    return available.remove(0); 
  }
}
```

然后，当`Client`结束使用`Resource`时，它释放它。资源被添加回工具，以便可以重用。

```java
public void releaseResource(Resource resource)
{
  available.add(resource);
}
```

资源池的最佳示例之一是数据库连接池。我们维护一个数据库连接池，并让代码使用这个池中的连接。

# 总结

在这一章中，我们讨论了创造性的设计模式。我们讨论了单例、工厂、构建器、原型和对象池模式的变体。所有这些模式都用于实例化新对象，并在创建对象时提供代码灵活性和可重用性。在下一章中，我们将介绍行为模式。虽然创建模式帮助我们管理对象的创建，但行为模式提供了管理对象行为的简单方法。


# 三、行为模式

> 原文：[Design Patterns and Best Practices in Java](https://libgen.rs/book/index.php?md5=096AE07A3FFC0E5B9926B8DE68424560)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)
> 
> 贡献者：[飞龙](https://github.com/wizardforcel)
> 
> 本文来自[【ApacheCN Java 译文集】](https://github.com/apachecn/apachecn-java-zh)，采用[译后编辑（MTPE）](https://cn.bing.com/search?q=%E8%AF%91%E5%90%8E%E7%BC%96%E8%BE%91)流程来尽可能提升效率。

本章的目的是学习行为模式。行为模式是关注对象交互、通信和控制流的模式。大多数行为模式是基于组合和委托而不是继承的。我们将在本章中了解以下行为模式：

*   责任链模式
*   命令模式
*   解释器模式
*   迭代器模式
*   观察者模式
*   中介模式
*   备忘录模式
*   状态模式
*   策略模式
*   模板方法模式
*   空对象模式
*   访问者模式

# 责任链模式

计算机软件是用来处理信息的，构造和处理这些信息有不同的方法。我们已经知道，当我们谈论面向对象编程时，我们应该为每个类分配一个单独的职责，以便使我们的设计易于扩展和维护。

考虑一个场景，其中可以对客户端请求附带的一组数据执行多种类型的操作。我们可以维护负责不同类型操作的不同类，而不是在单个类中添加有关所有操作的信息。这有助于我们保持代码松散耦合和干净。

这些类称为处理器。第一个处理器将接收请求并在需要执行操作时进行调用，或者将其传递给第二个处理器。类似地，第二个处理器检查并可以将请求传递给链中的下一个处理器。

# 意图

责任链模式以这样一种方式将处理者链接起来：如果处理者不能处理请求，他们将能够处理请求或传递请求。

# 实现

下面的类图描述了责任链模式的结构和参与者：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/dsn-ptn-bst-prac-java/img/6a95c8e4-32d5-4cf8-9c37-420a05442514.png)

在前面的图表中涉及以下类：

*   `Client`：这是使用该模式的应用的主要结构。它负责实例化一系列处理器，然后在第一个对象上调用`handleRequest`方法。
*   `Handler`：这个抽象类继承了所有具体的`Handler`。它有一个`handleRequest`方法，接收应该处理的请求。
*   `ConcreteHandlers`：这些是具体的类，为每个案例实现一个`handleRequest`方法。每个`ConcreteHandler`都保留一个对链中下一个`ConcreteHandler`的引用，并且必须检查它是否能够处理请求；否则，它必须将其传递给链中的下一个`ConcreteHandler`。

每个处理器都应该实现一个方法，客户端使用该方法设置下一个处理器，如果无法处理请求，则应该将请求传递给该处理器。此方法可以添加到基`Handler`类中：

```java
protected Handler successor;
public void setSuccessor(Handler successor)
{
  this.successor = successor;
}
```

在每个`ConcreteHandler`类中，我们都有下面的代码，检查它是否能够处理请求；否则，它将传递请求：

```java
public void handleRequest(Request request)
{
  if (canHandle(request))
  {
    //code to handle the request 
  }
  else
  {
    successor.handleRequest();
  }
}
```

客户端负责在调用链的头之前构建处理器链。调用将被传播，直到找到可以处理请求的正确处理器。

让我们以汽车服务应用为例。我们意识到，每一次一辆坏了的车进来，它都会首先由技工检查，如果问题在他们的专业领域，技工就会修理它。如果他们做不到，就把它交给电工。如果他们不能修复它，他们会把它传给下一位专家。下面是图表的外观：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/dsn-ptn-bst-prac-java/img/92c9a22a-c460-4b2e-bd40-3aefd6ba6b9e.png)

# 适用性和示例

以下是责任链模式的适用性和示例：

*   **事件处理器**：例如，大多数 GUI 框架使用责任链模式来处理事件。比方说，一个窗口包含一个包含一些按钮的面板。我们必须编写按钮的事件处理器。如果我们决定跳过它并传递它，那么链中的下一个将能够处理请求：面板。如果面板跳过它，它将转到窗口。
*   **日志处理器**：与事件处理器类似，每个日志处理器都会根据自己的状态记录一个特定的请求，或者传递给下一个处理器。
*   **Servlet**：在 Java 中，[`javax.servlet.Filter`](http://docs.oracle.com/javaee/7/api/javax/servlet/Filter.html)用于过滤请求或响应。`doFilter`方法还接收过滤链作为参数，并将请求传递给其他方法。

# 命令模式

在面向对象编程中要做的最重要的事情之一就是采用一种可以使代码解耦的设计。例如，假设我们需要开发一个复杂的应用，在其中我们可以绘制图形形状：点、线、线段、圆、矩形等等。

随着代码绘制各种形状，我们需要实现许多操作来处理菜单操作。为了使我们的应用具有可维护性，我们将创建一个统一的方法来定义所有这些*命令*，这样它将对应用的其余部分（扮演客户端角色）隐藏实现细节。

# 意图

命令模式执行以下操作：

*   提供一种统一的方法来封装命令以及执行操作所需的参数
*   允许处理命令，例如将命令存储在队列中

# 实现

命令模式的类图如下：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/dsn-ptn-bst-prac-java/img/d9f47057-0b1c-4022-b666-7022515b7748.png)

在前面的实现图中，我们可以区分以下参与者：

*   `Command`：这是表示命令封装的抽象。它声明执行的抽象方法，该方法应由所有具体命令实现。
*   `ConcreteCommand`：这是`Command`的实际执行。它必须执行命令并处理与每个具体命令相关联的参数。它将命令委托给接收器。
*   `Receiver`：负责执行与命令相关联的动作的类。
*   `Invoker`：触发命令的类。这通常是一个外部事件，例如用户操作。
*   `Client`：这是实例化具体命令对象及其接收器的实际类。

最初，我们的冲动是在一个大的`if-else`块中处理所有可能的命令：

```java
public void performAction(ActionEvent e)
{
  Object obj = e.getSource();
  if (obj = fileNewMenuItem)
  doFileNewAction();
  else if (obj = fileOpenMenuItem)
  doFileOpenAction();
  else if (obj = fileOpenRecentMenuItem)
  doFileOpenRecentAction();
  else if (obj = fileSaveMenuItem)
  doFileSaveAction();
}
```

但是，我们可以决定将命令模式应用于绘图应用。我们首先创建一个命令接口：

```java
public interface Command
{
  public void execute();
}
```

下一步是将菜单项、按钮等所有对象定义为类，实现命令接口和`execute()`方法：

```java
public class OpenMenuItem extends JMenuItem implements Command
{
  public void execute()  
  {
    // code to open a document
  }
}
```

在我们重复前面的操作，为每个可能的操作创建一个类之后，我们将朴素实现中的`if-else`块替换为以下块：

```java
public void performAction(ActionEvent e)
{
  Command command = (Command)e.getSource();
  command.execute();
}
```

我们可以从代码中看到，调用程序（触发`performAction`方法的客户端）和接收器（实现命令接口的类）是解耦的。我们可以很容易地扩展我们的代码而不必更改它。

# 适用性和示例

命令模式的适用性和示例如下：

*   **撤销/重做操作**：命令模式允许我们将命令对象存储在队列中。这样，我们就可以实现撤消和重做操作。
*   **复合命令**：复合命令可以由使用复合模式的简单命令组成，并按顺序运行。这样，我们就可以以面向对象的设计方式构建宏。
*   **异步方法调用**：命令模式用于多线程应用。命令对象可以在后台单独的线程中执行。这个`java.lang.Runnable`是一个命令接口。

在下面的代码中，`runnable`接口作为命令接口，由`RunnableThread`实现：

```java
class RunnableThread implements Runnable
{
  public void run() 
  {
    // the command implementation code
  }
}
```

客户端调用命令以启动新线程：

```java
public class ClientThread 
{
  public static void main(String a[])
  {
    RunnableThread mrt = new RunnableThread();
    Thread t = new Thread(mrt);
    t.start();
  }
}
```

# 解释器模式

计算机应该用来解释句子或求值表达式。如果我们必须编写一系列代码来处理这样的需求，首先，我们需要知道结构；我们需要有表达式或句子的内部表示。在许多情况下，最适合使用的结构是基于复合模式的复合结构。我们将在第 4 章、“结构模式”中进一步讨论复合模式，目前我们可以将复合表示看作是将性质相似的对象分组在一起。

# 意图

解释器模式定义了语法的表示和解释。

# 实现

解释器模式使用复合模式来定义对象结构的内部表示。除此之外，它还添加了解释表达式并将其转换为内部结构的实现。因此，解释器模式属于行为模式范畴。类图如下：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/dsn-ptn-bst-prac-java/img/7150f64c-31b1-43c8-8cfd-92f2248e14d2.png)

解释器模式由以下类组成：

*   `Context`：用于封装对解释器来说是全局的，需要所有具体解释器访问的信息。
*   `AbstractExpression`：一个抽象类或接口，声明执行的解释方法，由所有具体的解释程序实现。
*   `TerminalExpression`：一个解释器类，实现与语法的终端符号相关的操作。这个类必须始终被实现和实例化，因为它标志着表达式的结束。
*   `NonTerminalExpression:`：这些类实现不同的语法规则或符号。对于每个类，应该创建一个类。

解释器模式在实际中用于解释正则表达式。对于这样的场景，实现解释器模式是一个很好的练习；但是，我们将选择一个简单的语法作为示例。我们将应用它来解析一个带有一个变量的简单函数：`f(x)`。

为了使它更简单，我们将选择反向波兰符号。这是一种将操作数加到运算符末尾的表示法。`1 + 2`变为`1 2 +`；`(1 + 2) * 3`变为`1 2 + 3 *`。优点是我们不再需要括号，所以它简化了我们的任务。

以下代码为表达式创建接口：

```java
public interface Expression 
{
  public float interpret();
}
```

现在我们需要实现具体的类。我们需要以下要素：

*   `Number`：解释数字
*   **运算符类**（`+, -, *, /`）：对于下面的示例，我们将使用加号（`+`）和减号（`-`）：

```java
public class Number implements Expression 
{
  private float number;
  public Number(float number) 
  {
    this.number = number; 
  }
  public float interpret() 
  {
    return number;
  }
}
```

现在我们到了困难的部分。我们需要实现运算符。运算符是复合表达式，由两个表达式组成：

```java
public class Plus implements Expression 
{
  Expression left;
  Expression right;
  public Plus(Expression left, Expression right) 
  {
    this.left = left;
    this.right = right; 
  }
  public float interpret() 
  {
    return left.interpret() + right.interpret();
  }
}
```

类似地，我们有一个负实现，如下所示：

```java
public class Minus implements Expression 
{
  Expression left;
  Expression right;
  public Minus(Expression left, Expression right) 
  {
    this.left = left;
    this.right = right;
  }
  public float interpret() 
  {
    return right.interpret() - left.interpret();
  }
}
```

现在我们可以看到，我们已经创建了类，这些类允许我们构建一个树，其中操作是节点，变量和数字是叶子。这个结构可能非常复杂，可以用来解释一个表达式。

现在我们必须编写代码，使用我们创建的类来构建树：

```java
public class Evaluator
{ 
  public float evaluate(String expression) 
  { 
    Stack<Expression> stack = new Stack<Expression>(); 
    float result =0; 
    for (String token : expression.split(" ")) 
    { 
      if  (isOperator(token)) 
      { 
        Expression exp = null; 
        if(token.equals("+")) 
        exp = stack.push(new Plus(stack.pop(), stack.pop())); 
        else if (token.equals("-")) 
        exp = stack.push(new Minus(stack.pop(), stack.pop())); 
        if(null!=exp) 
        { 
          result = exp.interpret(); 
          stack.push(new Number(result)); 
        } 
      } 
      if  (isNumber(token)) 
      { 
        stack.push(new Number(Float.parseFloat(token))); 
      } 
    } 
    return result; 
  } 
  private boolean isNumber(String token) 
  { 
    try 
    { 
      Float.parseFloat(token); 
      return true; 
    } 
    catch(NumberFormatException nan) 
    { 
      return false; 
    } 
  } 
  private boolean isOperator(String token) 
  { 
    if(token.equals("+") || token.equals("-")) 
    return true; 
    return false; 
  } 
  public static void main(String s[]) 
  { 
    Evaluator eval = new Evaluator(); 
    System.out.println(eval.evaluate("2 3 +")); 
    System.out.println(eval.evaluate("4 3 -")); 
    System.out.println(eval.evaluate("4 3 - 2 +")); 
  } 
} 
```

# 适用性和示例

解释器模式可以在表达式需要解释并转换为其内部表示时使用。模式不能应用于复杂语法，因为内部表示是基于复合模式的。

Java 实现了`java.util.Parser`中的解释器模式，用于解释正则表达式。首先，在解释正则表达式时，将返回`Matcher`对象。匹配器使用模式类基于正则表达式创建的内部结构：

```java
Pattern p = Pattern. compile("a*b");
Matcher m = p.matcher ("aaaaab");
boolean b = m.matches();
```

# 迭代器模式

迭代器模式可能是 Java 中最著名的模式之一。一些 Java 程序员在使用它时，并不知道集合包是迭代器模式的实现，而不管集合的类型是：数组、列表、集合或任何其他类型。

不管集合是列表还是数组，我们都可以用同样的方式处理它，这是因为它提供了一种在不暴露其内部结构的情况下遍历其元素的机制。此外，不同类型的集合使用相同的统一机制。这种机制称为迭代器模式。

# 意图

迭代器模式提供了一种顺序遍历聚合对象的元素而不暴露其内部表示的方法。

# 实现

迭代器模式基于两个抽象类或接口，可以通过一对具体类来实现。类图如下：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/dsn-ptn-bst-prac-java/img/dc480e83-6ac3-4091-bdb3-16ce8b9b6370.png)

迭代器模式中使用了以下类：

*   `Aggregate`：应该由所有类实现的抽象类，可以由迭代器遍历。这对应于`java.util.Collection`接口。
*   `Iterator`：迭代器抽象定义了遍历聚合对象的操作和返回对象的操作。
*   `ConcreteAggregate`：具体聚合可以实现内部不同的结构，但是暴露了具体迭代器，该迭代器负责遍历聚合。
*   `ConcreteIterator`：这是处理特定混凝土骨料类的混凝土迭代器。实际上，对于每个`ConcreteAggregate`，我们必须实现一个`ConcreteIterator`。

在 Java 中使用迭代器可能是每个程序员在日常生活中都要做的事情之一。让我们看看如何实现迭代器。首先，我们应该定义一个简单的迭代器接口：

```java
public interface Iterator
{
  public Object next();
  public boolean hasNext();
}
We create the aggregate:
public interface Aggregate
{
public Iterator createIterator();
}
```

然后我们实现一个简单的`Aggregator`，它维护一个字符串值数组：

```java
public class StringArray implements Aggregate 
{ 
  private String values[]; 
  public StringArray(String[] values) 
  { 
    this.values = values; 
  } 
  public Iterator createIterator() 
  { 
    return (Iterator) new StringArrayIterator(); 
  } 
  private class StringArrayIterator implements Iterator 
  { 
    private int position; 
    public boolean hasNext() 
    { 
      return (position < values.length); 
    }  
    public String next() 
    { 
      if (this.hasNext()) 
      return values[position++]; 
      else 
      return null; 
    } 
  } 
} 
```

我们在聚合中嵌套了迭代器类。这是最好的选择，因为迭代器需要访问聚合器的内部变量。我们可以在这里看到它的样子：

```java
String arr[]= {"a", "b", "c", "d"};
StringArray strarr = new StringArray(arr);
for (Iterator it = strarr.createIterator(); it.hasNext();)
System.out.println(it.next());
```

# 适用性和示例

迭代器现在在大多数编程语言中都很流行。它可能与`collections`包一起在 Java 中使用最广泛。当使用以下循环构造遍历集合时，它也在语言级别实现：

```java
for (String item : strCollection)
System.out.println(item);
```

迭代器模式可以使用泛型机制实现。这样，我们就可以确保避免强制转换产生的运行时错误。

在 Java 中实现新的容器和迭代器的好方法是实现现有的`java.util.Iterator<E>`和`java.util.Collection<E>`类。当我们需要具有特定行为的聚合器时，我们还应该考虑扩展`java.collection`包中实现的一个类，而不是创建一个新的类。

# 观察者模式

在本书中，我们不断提到解耦的重要性。当我们减少依赖性时，我们可以扩展、开发和测试不同的模块，而不必知道其他模块的实现细节。我们只需要知道它们实现的抽象。

然而，模块在实践中应该协同工作。一个对象中的变化被另一个对象知道，这并不少见。例如，如果我们在一个游戏中实现了一个`car`类，那么汽车的引擎应该知道油门何时改变位置。最简单的解决方案是有一个`engine`类，它会不时检查加速器的位置，看它是否发生了变化。一个更聪明的方法是让加速器给引擎打电话，让它知道这些变化。但是如果我们想拥有设计良好的代码，这是不够的。

如果`Accelerator`类保留了对`Engine`类的引用，那么当我们需要在屏幕上显示`Accelerator`的位置时会发生什么？这是最好的解决方案：与其让加速器依赖于引擎，不如让它们都依赖于抽象。

# 意图

观察者模式使一个对象的状态变化可以被其他对象观察到，这些对象被注册为被通知。

# 实现

观察者模式的类图如下：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/dsn-ptn-bst-prac-java/img/94a34ff4-dea6-46ba-93d5-d2906c1d22c3.png)

观察者模式依赖于以下类：

*   `Subject`：这通常是一个必须由类实现的接口，应该是可观察的。应通知的观察者使用`attach()`方法注册。当不必再通知他们更改时，将使用`detach()`方法取消注册。
*   `ConcreteSubject`：实现`Subject`接口的类。它处理观察者列表，并更新他们关于更改的信息。
*   `Observer`：这是一个由对象实现的接口，对象的变化需要更新这个接口。每个观察者都应该实现`update()`方法，该方法会通知他们新的状态变化。

# 中介模式

在许多情况下，当我们设计和开发软件应用时，我们会遇到许多场景，其中我们有必须相互通信的模块和对象。最简单的方法是让他们彼此了解，并且可以直接发送消息。

然而，这可能会造成混乱。例如，如果我们设想一个通信应用，其中每个客户端都必须连接到另一个客户端，那么客户端管理多个连接就没有意义了。更好的解决方案是连接到中央服务器，并由服务器管理客户端之间的通信。客户端将消息发送到服务器，服务器保持与所有客户端的连接处于活动状态，并且可以向所有所需的收件人广播消息。

另一个例子是需要一个专门的类在图形界面中的不同控件（如按钮、下拉列表和列表控件）之间进行中介。例如，GUI 中的图形控件可以相互引用，以便交互调用它们的方法。但显然，这将创建一个极为耦合的代码，其中每个控件都依赖于所有其他控件。更好的方法是让父级负责在需要执行某些操作时将消息广播到所有必需的控件。当控件中有修改时，它将通知窗口，窗口将检查哪些控件需要被通知，然后通知它们。

# 意图

中介模式定义了一个对象，该对象封装了一组对象如何交互，从而减少了它们之间的依赖性。

# 实现

中介模式基于两种抽象：`Mediator`和`Colleague`，如下图所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/dsn-ptn-bst-prac-java/img/fed68fc2-c734-4e79-86d3-4aba7ef0cfb4.png)

中介模式依赖于以下类：

*   `Mediator`：这定义了参与者是如何互动的。此接口或抽象类中声明的操作特定于每个场景。
*   `ConcreteMediator`：实现中介声明的操作。
*   `Colleague`：这是一个抽象类或接口，定义了需要中介的参与者应该如何进行交互。
*   `ConcreteColleague`：这些是实现`Colleague`接口的具体类。

# 适用性和示例

当有许多实体以类似的方式交互时，应该使用中介模式，并且这些实体应该解耦。

中介模式在 Java 库中用于实现`java.util.Timer`。`timer`类可以用来安排线程以固定的间隔运行一次或多次。线程对象对应于`ConcreteColleague`类。`timer`类实现了管理后台任务执行的方法。

# 备忘录模式

封装是面向对象设计的基本原则之一。我们也知道每个类都应该有一个单一的责任。当我们向对象添加功能时，我们可能会意识到我们需要保存其内部状态，以便能够在稍后的阶段恢复它。如果我们直接在类中实现这样的功能，那么类可能会变得太复杂，最终可能会打破单一责任原则。同时，封装阻止我们直接访问需要记忆的对象的内部状态。

# 意图

备忘录模式用于保存对象的内部状态而不破坏其封装，并在后期恢复其状态。

# 实现

备忘录模式依赖于三个类：`Originator`、`Memento`、`CareTaker`，如下图所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/dsn-ptn-bst-prac-java/img/07a8192f-105b-4200-9523-4c4db5134748.png)

备忘录模式依赖于以下类：

*   `Originator`：发起者是我们需要记忆状态的对象，以备在某个时候需要恢复状态。
*   `CareTaker`：这个类负责触发发端人的变化，或者触发一个动作，发端人通过这个动作返回到以前的状态。
*   `Memento`：这个类负责存储发起者的内部状态。`Memento`提供了两种设置和获取状态的方法，但是这些方法应该对管理员隐藏。

实际上，备忘录比听起来容易得多。让我们把它应用到我们的汽车服务应用中。我们的机修工必须测试每辆车。他们使用一个自动装置来测量不同参数（速度、档位、刹车等）下汽车的所有输出。他们执行所有的测试，必须重新检查那些看起来可疑的。

我们首先创建`originator`类。我们将其命名为`CarOriginator`，并添加两个成员变量。`state`表示测试运行时车辆的参数。这是我们要保存的对象的状态；第二个成员变量是`result`。这是测得的汽车输出，我们不需要存储在备忘录。这是一个空巢备忘录的发起者：

```java
public class CarOriginator 
{
  private String state;
  public void setState(String state) 
  {
    this.state = state;
  }
  public String getState() 
  {
    return this.state;
  }
  public Memento saveState() 
  {
    return new Memento(this.state);
  }
  public void restoreState(Memento memento) 
  {
    this.state = memento.getState();
  }
  /**
  * Memento class
  */
  public static class Memento 
  {
    private final String state;
    public Memento(String state) 
    {
      this.state = state;
    }
    private String getState() 
    {
      return state;
    }
  }
}
```

现在我们对不同的州进行汽车测试：

```java
public class CarCaretaker 
{
  public static void main(String s[]) 
  {
    new CarCaretaker().runMechanicTest(); 
  }
  public void runMechanicTest() 
  {
    CarOriginator.Memento savedState = new CarOriginator.
    Memento("");
    CarOriginator originator = new CarOriginator();
    originator.setState("State1");
    originator.setState("State2");
    savedState = originator.saveState();
    originator.setState("State3");
    originator.restoreState(savedState);
    System.out.println("final state:" + originator.getState());
  }
}
```

# 适用性

只要需要实现回滚操作，就使用备忘录模式。它可以用于所有类型的原子事务中，在这些事务中，如果其中一个操作失败，则必须将对象还原为初始状态。

# 状态模式

有限状态机是计算机科学中的一个重要概念。它有一个强大的数学基础，它代表了一个抽象的机器，可以在有限的状态数。有限状态机应用于计算机科学的所有领域。

状态模式只是面向对象设计中有限状态机的一种实现。类图如下：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/dsn-ptn-bst-prac-java/img/c0679c9a-7512-4b02-8542-088d150c2564.png)

# 策略模式

特定于行为模式的一种特殊情况是，当我们需要改变解决另一个问题的方式时。正如我们在第一章已经学到的，改变是不好的，而扩展是好的。因此，我们可以将它封装在一个类中，而不是将代码的一部分替换为另一部分。然后我们可以创建代码所依赖的类的抽象。从那时起，我们的代码变得非常灵活，因为我们现在可以使用任何实现我们刚刚创建的抽象的类。

# 意图

策略模式定义了一系列算法，将每个算法封装起来，并使它们可以互换。

# 实现

策略模式的结构实际上与状态模式相同。然而，实现和意图完全不同：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/dsn-ptn-bst-prac-java/img/9a79967e-6311-4c2a-a326-13cc1913487d.png)

策略模式非常简单：

*   `Strategy`：对特定策略的抽象
*   `ConcreteStrategy`：实现抽象策略的类
*   `Context`：运行特定策略的类

# 模板方法模式

顾名思义，模板方法模式为代码提供了一个模板，可以由实现不同功能的开发人员填写。理解这一点最简单的方法是从 HTML 模板的角度来考虑。你访问的大多数网站都遵循某种模板。例如，通常有一个页眉、一个页脚和一个侧边栏，在它们之间，我们有核心内容。这意味着模板是用页眉、页脚和侧边栏定义的，每个内容编写器都可以使用此模板添加内容。

# 意图

使用模板方法模式的想法是避免编写重复的代码，这样开发人员就可以专注于核心逻辑。

# 实现

模板方法模式最好使用抽象类实现。我们所知道的关于实现的区域将被提供；默认实现和保持开放以供实现的区域被标记为抽象的。

例如，设想一个非常高级别的数据库获取查询。我们需要执行以下步骤：

1.  创建连接
2.  创建查询
3.  执行查询
4.  解析并返回数据
5.  关闭连接

我们可以看到，创建和关闭连接部分将始终保持不变。因此，我们可以将其添加为模板实现的一部分。其余的方法可以根据不同的需要独立实现。

# 空对象模式

空对象模式是本书中介绍的最轻的模式之一。有时，它被认为只是策略模式的一个特例，但考虑到它在实践中的重要性，它有自己的部分。

如果我们使用测试驱动的方法开发程序，或者如果我们只是想开发一个模块而不需要应用的其余部分，我们可以简单地用一个模拟类来替换我们没有的类，模拟类具有相同的结构，但什么也不做。

# 实现

在下图中，我们可以看到我们只是创建了一个`NullClass`，它可以替换程序中的实际类。如前所述，这只是策略模式的一个特例，在这种模式中，我们选择无所事事的策略。类图如下：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/dsn-ptn-bst-prac-java/img/854cd250-7c36-44bd-b999-927ee29fe5e3.png)

# 访问者模式

让我们回到我们在讨论命令模式时介绍的形状应用。我们应用了命令模式，所以我们必须重做所实现的操作。是时候添加保存功能了。

我们可能会认为，如果我们向`Shape`基类添加一个抽象的`Save`方法，并对每个形状进行扩展，那么问题就解决了。这个解决方案也许是最直观的，但不是最好的。首先，每个类应该有一个单一的职责。

其次，如果需要更改保存每个形状的格式，会发生什么情况？如果我们要实现相同的方法来生成 XML 输出，那么我们是否必须更改为 JSON 格式？这种设计绝对不遵循开/关原则。

# 意图

访问者模式将操作与其操作的对象结构分离，允许添加新操作而不更改结构类。

# 实现

访问者模式在一个类中定义了一组操作：它为要操作的结构中的每种类型的对象定义了一个方法。只需创建另一个访问者，就可以添加一组新的操作。类图如下：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/dsn-ptn-bst-prac-java/img/4e1a433f-8105-460d-a053-1b4ed95d5d8b.png)

访问者模式基于以下类：

*   `Element`：表示对象结构的基类。结构中的所有类都是从它派生的，它们必须实现`accept(visitor:visitor)`方法。
*   `ConcreteElementA`和`ConcreteElementB`：这些都是具体的类，我们想向它们添加在`Visitor`类中实现的外部操作。
*   `Visitor`：这是基础`Visitor`类，它声明了每个`ConcreteElement`对应的方法。方法的名称是相同的，但每个方法都根据其接受的类型进行区分。我们可以采用这种解决方案，因为在 Java 中，我们可以使用相同名称和不同签名的方法；但是，如果需要，我们可以使用不同的名称声明方法。
*   `ConcreteVisitor`：这是访问者的实现。当我们需要一组单独的操作时，我们只需创建另一个访问者。

# 总结

在本节中，我们讨论了各种行为模式。我们研究了一些最常用的行为模式，如责任链模式、命令模式、解释器模式等等。这些模式帮助我们以可控的方式管理对象的行为。在下一章中，我们将研究有助于我们管理复杂结构的结构模式。


# 四、结构模式

> 原文：[Design Patterns and Best Practices in Java](https://libgen.rs/book/index.php?md5=096AE07A3FFC0E5B9926B8DE68424560)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)
> 
> 贡献者：[飞龙](https://github.com/wizardforcel)
> 
> 本文来自[【ApacheCN Java 译文集】](https://github.com/apachecn/apachecn-java-zh)，采用[译后编辑（MTPE）](https://cn.bing.com/search?q=%E8%AF%91%E5%90%8E%E7%BC%96%E8%BE%91)流程来尽可能提升效率。

本章的目的是学习结构模式。结构模式是通过利用对象和类之间的关系来创建复杂结构的模式。大多数结构模式都是基于继承的。在本章中，我们将只关注以下 GOF 模式：

*   适配器模式
*   代理模式
*   桥接模式
*   装饰模式
*   复合模式
*   外观模式
*   享元模式

我们可能无法详细介绍其他已确定的结构模式，但值得了解。具体如下：

*   **标记接口**：使用空接口标记特定类（如`Serializable`），从而可以按接口名进行搜索。有关更多信息，请阅读文章，[《第 37 项 -使用标记接口定义类型》](http://thefinestartist.com/effective-java/37)，引用了乔舒亚·布洛赫的《Effective Java（第二版）》。
*   **模块**：将类分组，实现软件模块的概念。模块化架构包含多种模式，Kirk knorenschild 在[这个页面](https://dzone.com/refcardz/patterns-modular-architecture)中对此进行了清晰的解释。Java9 模块就是这种模式的一个例子，请参阅[这个页面](https://labs.consol.de/development/2017/02/13/getting-started-with-java9-modules.html)。
*   **扩展对象**：在运行时改变现有的对象接口。更多信息请访问[这个页面](http://www.brockmann-consult.de/beam-wiki/display/BEAM/Extension+Object+Pattern)。
*   **孪生**：这为不支持多重继承的语言添加了多重继承功能。Java8 通过添加默认方法支持类型的多个继承。即便如此，孪生模式在某些情况下仍然有用。Java 设计模式站点在[这个页面](http://java-design-patterns.com/patterns/twin/)中对孪生模式有很好的描述。

# 适配器模式

适配器模式为代码重用提供了一个解决方案；它将现有的旧代码适配/包装到新的接口，这些接口在原始代码的设计时是未知的。1987 年，当 PS/2 端口被设计出来时，没有人想到它会连接到 9 年后设计的 USB 总线上。然而，我们仍然可以使用一个旧的 PS/2 键盘在我们最新的电脑连接到 USB 端口。

适配器模式通常在处理遗留代码时使用，因为通过包装现有代码并使其适应新的代码接口，我们可以立即访问已经测试过的旧功能。这可以通过使用多个继承（在 Java8 中默认的接口实现是可能的）来实现，也可以通过使用组合（旧对象成为类属性）来实现。适配器模式也称为**包装器**。

如果旧代码需要使用新代码，反之亦然，我们需要使用一个称为双向适配器的特殊适配器，它实现两个接口（旧接口和新接口）。

JDK 中的`java.io.InputStreamReader`和`java.io.OutputStreamWriter`类是适配器，因为它们将 JDK1.0 中的输入/输出流对象适配到稍后在 JDK1.1 中定义的读写器对象。

# 意图

其目的是将现有的旧接口应用到新的客户端接口。目标是尽可能地重用旧的和已经测试过的代码，同时可以自由地对新接口进行更改。

# 实现

下面的 UML 图对新客户端代码和修改后的代码之间的交互进行了建模。适配器模式通常是通过使用多重继承在其他语言中实现的，从 Java8 开始这是部分可能的。我们将使用另一种方法，这种方法也适用于较旧的 Java 版本；我们将使用聚合。它比继承更具限制性，因为我们无法访问受保护的内容，只能访问适配器公共接口：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/dsn-ptn-bst-prac-java/img/56380966-dcb3-4d46-afac-b8d1eddbc906.png)

我们可以从实现图中区分以下参与者：

*   `Client`：代码客户端
*   `Adapter`：将调用转发给被适配器的适配器类
*   `Adaptee`：需要修改的旧代码
*   `Target`：要支持的新接口

# 示例

下面的代码模拟在 USB 总线中使用 PS/2 键盘。它定义了一个 PS/2 键盘（适配器）、一个 USB 设备接口（目标）、一个 PS2ToUSBAdapter（适配器）和使设备工作的连接线：

```java
package gof.structural.adapter;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
class WireCap 
{
  WireCap link = WireCap.LooseCap;
  private Wire wire;
  publicstatic WireCap LooseCap = new WireCap(null);
  public WireCap(Wire wire) 
  {
    this.wire = wire; 
  }
  publicvoid addLinkTo(WireCap link) 
  {
    this.link = link;
  }
  public Wire getWire() 
  {
    return wire;
  }
  public String toString() 
  {
    if (link.equals(WireCap.LooseCap))
    return "WireCap belonging to LooseCap";
    return "WireCap belonging to " + wire + " is linked to " + 
    link.getWire();
  }
  public WireCap getLink() 
  {
    return link;
  }
}
```

顾名思义，`WireCap`类模型是每根导线的两端。默认情况下，所有导线都是松的；因此，我们需要一种方法来发出信号。这是通过使用空对象模式来完成的，`LooseCap`是我们的空对象（一个空替换，它不抛出`NullPointerException`）。请看下面的代码：

```java
class Wire 
{
  private String name;
  private WireCap left;
  private WireCap right;
  public Wire(String name) 
  {
    this.name = name;
    this.left = new WireCap(this);
    this.right = new WireCap(this);
  }
  publicvoid linkLeftTo(Wire link) 
  {
    left.addLinkTo(link.getRightWireCap());
    link.getRightWireCap().addLinkTo(left);
  }
  public WireCap getRightWireCap() 
  {
    return right;
  }
  publicvoid printWireConnectionsToRight() 
  {
    Wire wire = this;
    while (wire.hasLinkedRightCap()) 
    {
      wire.printRightCap();
      wire = wire.getRightLink();
    }
  }
  public Wire getRightLink() 
  {
    return getRightWireCap().getLink().getWire();
  }
  publicvoid printRightCap() 
  {
    System.out.println(getRightWireCap());
  }
  publicboolean hasLinkedRightCap() 
  {
    return !getRightWireCap().link.equals(WireCap.LooseCap);
  }
  public String getName() 
  {
    return name;
  }
  public String toString() 
  {
    return "Wire " + name;
  }
}
```

`Wire`类对来自 USB 或 PS/2 设备的电线进行建模。它有两端，默认情况下是松散的，如以下代码所示：

```java
class USBPort 
{
  publicfinal Wire wireRed = new Wire("USB Red5V");
  publicfinal Wire wireWhite = new Wire("USB White");
  publicfinal Wire wireGreen = new Wire("USB Green");
  publicfinal Wire wireBlack = new Wire("USB Black");
}
```

根据 USB 规范，USBPort 有四根导线：5V 红色、绿色和白色导线用于数据，黑色导线用于接地，如下代码所示：

```java
interface PS2Device
{
  staticfinal String GND = "PS/2 GND";
  staticfinal String BLUE = "PS/2 Blue";
  staticfinal String BLACK = "PS/2 Black";
  staticfinal String GREEN = "PS/2 Green";
  staticfinal String WHITE = "PS/2 White";
  staticfinal String _5V = "PS/2 5V";
  public List<Wire> getWires();
  publicvoid printWiresConnectionsToRight();
}
class PS2Keyboard implements PS2Device 
{
  publicfinal List<Wire> wires = Arrays.asList(
  new Wire(_5V),
  new Wire(WHITE),
  new Wire(GREEN),
  new Wire(BLACK),
  new Wire(BLUE),
  new Wire(GND));
  public List<Wire> getWires() 
  {
    return Collections.unmodifiableList(wires); 
  }
  publicvoid printWiresConnectionsToRight() 
  {
    for(Wire wire : wires)
    wire.printWireConnectionsToRight();
  }
}
```

`PS2Keyboard`是适配器。我们需要使用的是旧设备，如下代码所示：

```java
interface USBDevice 
{
  publicvoid plugInto(USBPort port);
}
```

`USBDevice`是目标接口。它知道如何与`USBPort`接口，如下代码所示：

```java
class PS2ToUSBAdapter implements USBDevice 
{
  private PS2Device device;
  public PS2ToUSBAdapter(PS2Device device) 
  {
    this.device = device;
  }
  publicvoid plugInto(USBPort port) 
  {
    List<Wire> ps2wires = device.getWires();
    Wire wireRed = getWireWithNameFromList(PS2Device._5V, 
    ps2wires);
    Wire wireWhite = getWireWithNameFromList(PS2Device.WHITE,
    ps2wires);
    Wire wireGreen = getWireWithNameFromList(PS2Device.GREEN,
    ps2wires);
    Wire wireBlack = getWireWithNameFromList(PS2Device.GND, 
    ps2wires);
    port.wireRed.linkLeftTo(wireRed);
    port.wireWhite.linkLeftTo(wireWhite);
    port.wireGreen.linkLeftTo(wireGreen);
    port.wireBlack.linkLeftTo(wireBlack);
    device.printWiresConnectionsToRight();
  }
  private Wire getWireWithNameFromList(String name, List<Wire>
  ps2wires) 
  {
    return ps2wires.stream()
    .filter(x -> name.equals(x.getName()))
    .findAny().orElse(null);
  }
}
```

`PS2ToUSBAdapter`是我们的适配器类。它知道如何布线，以便新的`USBPort`仍然可以使用旧的设备，如下代码所示：

```java
publicclass Main
{
  publicstaticvoid main (String[] args)
  {
    USBDevice adapter = new PS2ToUSBAdapter(new PS2Keyboard());
    adapter.plugInto(new USBPort());
  }
}
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/dsn-ptn-bst-prac-java/img/8dd12513-b286-44f6-9514-1a19d3d5fd8f.png)

正如预期的那样，我们的设备已连接到 USB 端口并准备好使用。所有接线都已完成，例如，如果 USB 端口将红线设置为 5 伏，则该值将到达键盘，如果键盘通过绿线发送数据，则该值将到达 USB 端口。

# 代理模式

每当您使用企业或 SpringBeans、模拟实例和实现 AOP 时，对具有相同接口的另一个对象进行 RMI 或 JNI 调用，或者直接/间接使用`java.lang.reflect.Proxy`，都会涉及到代理对象。它的目的是提供一个真实对象的代理，具有完全相同的封装外形。它在调用之前或之后执行其他操作时将工作委托给它。代理类型包括：

*   **远程代理**：将工作委托给远程对象（不同的进程、不同的机器），例如企业 bean。使用 JNI 手动或自动地使用 JNI 包装现有的非 Java 旧代码（例如，使用 SWIG 生成胶粘代码，参见[这个页面](http://www.swig.org/Doc1.3/Java.html#imclass)）是一种远程代理模式，因为它使用句柄（C/C++ 中的指针）访问实际对象。
*   **保护代理**：进行安全/权限检查。
*   **缓存代理**：使用记忆加速调用。最好的例子之一是 Spring `@Cacheable`方法，它缓存特定参数的方法结果，不调用实际代码，而是从缓存返回先前计算的结果。
*   **虚拟和智能代理**。这些增加了方法的功能，比如记录性能度量（创建一个`@Aspect`，为所需的方法定义一个`@Pointcut`，并定义一个`@Around`通知）或者进行延迟初始化。

适配器和代理之间的主要区别在于代理提供完全相同的接口。装饰器模式增强了接口，而适配器改变了接口。

# 意图

其目的是为真实对象提供代理，以便更好地控制它。它是一个实际对象的句柄，其行为类似于它，因此使客户端代码使用它就像使用实际对象一样。

# 实现

下图对代理模式进行了建模。请注意，由于真实和代理主题都实现了相同的接口，因此它们可以互换：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/dsn-ptn-bst-prac-java/img/687be95e-9a61-4304-99b4-5de30692b84b.png)

我们可以在实现图中区分以下参与者：

*   `Subject`：客户端使用的现有接口
*   `RealSubject`：真实对象的类
*   `ProxySubject`：代理类

# 示例

下面的代码模拟从 localhost EJB 上下文中查找 bean 的远程代理。我们的远程代理是在另一个 JVM 中运行的几何计算器。我们将使用工厂方法来制作代理和真实对象，以证明它们是可互换的。代理版本的计算时间更长，因为我们还模拟 JNI 查找部分并发送/检索结果。看看代码：

```java
package gof.structural.proxy;
publicclass Main
{
  publicstaticvoid main (String[] args) throws java.lang.Exception
  {
    GeometryCalculatorBean circle = GeometryCalculatorBeanFactory.
    REMOTE_PROXY.makeGeometryCalculator();
    System.out.printf("Circle diameter %fn",    
    circle.calculateCircleCircumference(new Circle()));
  }
}
class Circle 
{}
interface GeometryCalculatorBean 
{
  publicdouble calculateCircleCircumference(Circle circle);
}
```

这是我们的主题，我们要实现的接口。模拟`@RemoteInterface`和`@LocalInterface`接口的建模，如下代码所示：

```java
class GeometryBean implements GeometryCalculatorBean 
{
  publicdouble calculateCircleCircumference(Circle circle) 
  {
    return 0.1f;
  }
}
```

这是我们真正的主题，知道如何执行实际的几何计算，如以下代码所示：

```java
class GeometryBeanProxy implements GeometryCalculatorBean 
{
  private GeometryCalculatorBean bean;
  public GeometryBeanProxy() throws Exception 
  {
    bean = doJNDILookup("remote://localhost:4447", "user", 
    "password");
  }
  private GeometryCalculatorBean doJNDILookup
  (final String urlProvider, final String securityPrincipal, final  
  String securityCredentials)
  throws Exception 
  {
    System.out.println("Do JNDI lookup for bean");
    Thread.sleep(123);//simulate JNDI load for the remote location
    return GeometryCalculatorBeanFactory.LOCAL.
    makeGeometryCalculator();
  }
  publicdouble calculateCircleCircumference(Circle circle) 
  {
    return bean.calculateCircleCircumference(circle);
  }
}
```

这是我们的代理主题。请注意，它没有业务逻辑；它在设法建立对它的句柄之后，将它委托给真正的主题，如以下代码所示：

```java
enum GeometryCalculatorBeanFactory 
{
  LOCAL 
  {
    public GeometryCalculatorBean makeGeometryCalculator() 
    {
      returnnew GeometryBean();
    }
  },
  REMOTE_PROXY 
  {
    public GeometryCalculatorBean makeGeometryCalculator() 
    {
      try 
      {
        returnnew GeometryBeanProxy();
      } 
      catch (Exception e) 
      {
        // TODO Auto-generated catch block
        e.printStackTrace();
      }
      returnnull;
    }
  };
  publicabstract GeometryCalculatorBean makeGeometryCalculator();
}
```

以下输出显示代理成功链接到真实对象并执行所需的计算：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/dsn-ptn-bst-prac-java/img/0e7c9d90-f3b1-4a45-8369-fe10e6dd9713.png)

# 装饰器模式

有时我们需要在不影响现有代码的情况下，向现有代码添加或从现有代码中删除功能，有时创建子类是不实际的。在这些情况下，装饰器非常有用，因为它允许在不更改现有代码的情况下这样做。它通过实现相同的接口、聚合要修饰的对象、将所有公共接口调用委派给它，并在子类中实现新功能来实现这一点。将此模式应用于具有轻量级接口的类。在其他情况下，通过将所需的策略注入组件（策略模式）来扩展功能是更好的选择。这将保持特定方法的局部更改，而不需要重新实现其他方法。

装饰对象及其装饰器应该是可互换的。装饰器的接口必须完全符合装饰对象的接口。

因为它使用递归，所以可以通过组合装饰器来实现新功能。在这方面，它类似于复合模式，它将多个对象组合在一起，以形成作为一个对象的复杂结构。装饰器可以被视为护照上的一块玻璃或一张卡片（*安装在一块玻璃和一张卡片之间的图片或照片*），其中图片/照片本身就是装饰对象。另一方面，策略可以看作是艺术家在照片上的签名。

`JScrollPane`swing 类是装饰器的一个示例，因为它允许在现有容器周围添加新功能，例如滚动条，并且可以多次执行，如下代码所示：

```java
JTextArea textArea = new JTextArea(10, 50);
JScrollPane scrollPane1 = new JScrollPane(textArea);
JScrollPane scrollPane2 = new JScrollPane(scrollPane1);
```

# 意图

其目的是动态扩展现有对象的功能，而不更改其代码。它符合原始接口，并且能够通过使用组合（而不是子类化）在功能上扩展。

# 实现

下图对装饰器模式进行了建模。结果表明，扩展构件和修饰构件可以相互替换。装饰器可以递归地应用；它可以应用于现有的组件实现，但也可以应用于另一个装饰器，甚至应用于它自己。装饰器接口不是固定到组件接口的；它可以添加额外的方法，装饰器的子级可以使用这些方法，如图所示

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/dsn-ptn-bst-prac-java/img/2f78a8bc-9189-4132-9597-590ce8f39abf.png)

我们可以在实现图中区分以下参与者：

*   `Component`：抽象组件（可以是接口）
*   `ComponentImplementation`：这是我们要装饰的组件之一
*   `Decorator`：这是一个抽象的组件`Decorator`
*   `ExtendedComponent`：这是添加额外功能的组件装饰器

# 示例

下面的代码显示了如何增强简单的打印 ASCII 文本，以打印输入的十六进制等效字符串，以及实际文本：

```java
package gof.structural.decorator;
import java.util.stream.Collectors;
publicclass Main
{
  publicstaticvoid main (String[] args) throws java.lang.Exception
  {
    final String text = "text";
    final PrintText object = new PrintAsciiText();
    final PrintText printer = new PrintTextHexDecorator(object);
    object.print(text);
    printer.print(text);
  }
}
interface PrintText 
{
  publicvoid print(String text);
}
PrintText is the component interface:
class PrintAsciiText implements PrintText 
{
  publicvoid print(String text) 
  {
    System.out.println("Print ASCII: " + text); 
  }
}
```

`PrintASCIIText`是要装饰的构件。注意，它只知道如何打印`ASCII`文本。我们想让它也以十六进制打印；我们可以使用下面的代码

```java
class PrintTextHexDecorator implements PrintText 
{
  private PrintText inner;
  public PrintTextHexDecorator(PrintText inner) 
  {
    this.inner = inner;
  }  
  publicvoid print(String text) 
  {
    String hex = text.chars()
    .boxed()
    .map(x -> "0x" + Integer.toHexString(x))
    .collect(Collectors.joining(" "));
    inner.print(text + " -> HEX: " + hex);
  }
}
```

`PrintTextHexDecorator`是装饰师。也可应用于其它`PrintText`元件。假设我们要实现一个组件`PrintToUpperText`。我们可能仍然使用我们现有的装饰，使其打印十六进制以及。

以下输出显示当前功能（ASCII）和新添加的功能（十六进制显示）：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/dsn-ptn-bst-prac-java/img/a386e857-80fe-4faa-842f-eb9455095f8c.png)

# 桥接模式

在软件设计过程中，我们可能会面临一个问题，即同一个抽象可以有多个实现。这在进行跨平台开发时最为明显。例如 Linux 上的换行符换行符或 Windows 上存在注册表。需要通过运行特定操作系统调用来获取特定系统信息的 Java 实现肯定需要能够改变实现。一种方法是使用继承，但这会将子级绑定到特定接口，而该接口可能不存在于不同的平台上。

在这些情况下，建议使用桥接模式，因为它允许从扩展特定抽象的大量类转移到*嵌套泛化*，这是 Rumbaugh 创造的一个术语，在这里我们处理第一个泛化，然后处理另一个泛化，从而将所有组合相乘。如果所有子类都同等重要，并且多个接口对象使用相同的实现方法，那么这种方法就可以很好地工作。如果由于某种原因，大量代码被复制，这就表明这种模式不是解决特定问题的正确选择。

# 意图

其目的是将抽象与实现分离，以允许它们独立地变化。它通过在公共接口和实现中使用继承来实现这一点。

# 实现

下图显示了一个可能的网桥实现。请注意，抽象和实现都可以更改，不仅接口可以更改，实现代码也可以更改。例如，精化抽象可以利用只有`SpecificImplementation`提供的`doImplementation3()`：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/dsn-ptn-bst-prac-java/img/97eed6fb-6f8d-41df-a03b-10eee13f3460.png)

我们可以在实现图中区分以下参与者：

*   `Abstraction`：这是抽象组件
*   `Implementation`：这是抽象实现
*   `Refined`：这是具体组件
*   `SpecificImplementation`：这是具体实现

# 示例

下面的代码展示了一个电子邮件客户端，它使用了基于运行平台的实现。可以使用工厂方法模式对其进行增强，以创建特定的平台实现：

```java
package gof.structural.bridge;
publicclass Main
{
  publicstaticvoid main (String[] args) 
  {
    new AllMessageClient(new WindowsImplementation())
    .sendMessageToAll("abc@gmail.com", "Test");
  }
}
interface PlatformBridge 
{
  publicvoid forwardMessage(String msg);
}
```

`PlatformBridge`是我们的实现抽象类。它指定了每个实现需要提供什么—在我们的例子中，是转发文本给出的消息。以下两种实现（Windows 和 POSIX）都知道如何执行此任务：

```java
class WindowsImplementation implements PlatformBridge 
{
  publicvoid forwardMessage(String msg) 
  {
    System.out.printf("Sending message n%s nFrom the windows 
    machine", msg);
  }
}
class PosixImplementation implements PlatformBridge 
{
  publicvoid forwardMessage(String msg) 
  {
    System.out.printf("Sending message n%s nFrom the linux 
    machine", msg);
  }
}
class MessageSender 
{
  private PlatformBridge implementation;
  public MessageSender(PlatformBridge implementation) 
  {
    this.implementation = implementation;
  }
  publicvoid sendMessage(String from, String to, String body) 
  {
    implementation.forwardMessage(String.format("From : 
    %s nTo : %s nBody : %s", from, to, body));
  }
}
```

抽象`MessageSender`使用特定于平台的实现发送消息。`AllMessageClient`细化抽象向特定组`development_all@abc.com`发送消息。其他可能的精化抽象可以包括特定于平台的代码和对平台实现的调用。代码如下：

```java
class AllMessageClient extends MessageSender 
{
  private String to = "development_all@abc.com";
  public MyMessageClient(PlatformBridge implementation) 
  {
    super(implementation);
  }
  publicvoid sendMessageToAll(String from, String body) 
  {
    sendMessage(from, to, body);
  }
}
```

以下输出显示所有消息客户端都使用 Windows 实现发送了消息：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/dsn-ptn-bst-prac-java/img/9a2cf576-cd90-4390-a040-33a4f15b10ee.png)

# 复合模式

顾名思义，复合模式是在将对象组合成一个作为一个对象的复杂结构时使用的（请参阅下图）。在内部，它使用数据结构（如树、图形、数组或链表）来表示模型：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/dsn-ptn-bst-prac-java/img/d3840628-21ac-4275-a843-e610f2513e46.png)

JVM 提供了复合模式的最佳示例，因为它通常被实现为一个栈机器（出于可移植性的原因）。从当前线程栈中推送和弹出操作。例如，要计算`1+4-2`等于什么，它将按 1、按 4，然后执行加法。栈现在只有值 5，按下 2，然后执行减号。现在栈只有值 3，这是弹出的。操作`1+4+2-`（反向波兰符号）可以使用复合模式轻松建模，其中每个节点都是值、复数或操作数。每个节点都有一个执行操作的`perform`方法（`push`、`execute`和`pop`或`combine`，具体取决于类型）。

Composite 使用递归组合，其中客户端代码以相同的方式处理每个部分、叶或节点。

# 意图

其目的是将对象建模为树或图形结构，并以相同的方式处理它们。客户端代码不需要知道节点是单个对象（叶节点）还是对象的组合（具有子节点的节点，如根节点）；客户端代码可以对这些细节进行抽象并统一处理。

# 实现

下图显示客户端使用组件接口`doSomething()`方法。该方法在根节点和叶节点中的实现方式不同。根节点可以有 1 到`n`子节点；叶节点没有子节点。当子树的数目为 2 且不存在循环时，我们有一个二叉树的情况：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/dsn-ptn-bst-prac-java/img/5caeb982-741d-4769-9591-a8289f17dea4.png)

我们可以在实现图中区分以下参与者：

*   `Client`：客户端代码
*   `Component`：抽象节点
*   `Leaf`：叶子节点
*   `Composite`：具有子节点的复合节点，子节点可以是复合节点，也可以是叶节点

# 示例

下面的代码为算术表达式计算器建模。表达式被构造为复合表达式，并且只有一个方法-`getValue`。这将给出当前值；对于叶，它是叶数值，对于组合节点，它是子组合值：

```java
package gof.structural.composite;
publicclass Main
{
  publicstaticvoid main (String[] args) throws java.lang.Exception
  {
    ArithmeticComposite expr = new MinusOperand(
    new PlusOperand(new NumericValue(1), new NumericValue(4)),
    new NumericValue(2));
    System.out.printf("Value equals %dn", expr.getValue());
  }
}
```

客户端代码创建一个`(1 + 4) - 2`算术表达式并打印其值，如下代码所示：

```java
interface ArithmeticComposite 
{
  publicint getValue();
}
```

`ArithmeticComposite`是我们的复合接口，它只知道如何返回一个整数值，表示算术表达式的值（复合`ArithmeticOperand`）或持有值（叶子`NumericValue`），如下代码所示：

```java
class NumericValue implements ArithmeticComposite 
{
  privateint value;
  public NumericValue(int value) 
  {
    this.value = value;
  }
  publicint getValue() 
  {
    return value;
  }
}
abstractclass ArithmeticOperand implements ArithmeticComposite 
{
  protected ArithmethicComposite left;
  protected ArithmethicComposite right;
  public ArithmethicOperand(ArithmeticComposite left,   
  ArithmeticComposite right) 
  {
    this.left = left;
    this.right = right;
  }
}
class PlusOperand extends ArithmeticOperand 
{
  public PlusOperand(ArithmeticComposite left, 
  ArithmeticComposite right) 
  {
    super(left, right);
  }
  publicint getValue()  
  {
    return left.getValue() + right.getValue();
  }
}
class MinusOperand extends ArithmeticOperand 
{
  public MinusOperand(ArithmeticComposite left, 
  ArithmeticComposite right) 
  {
    super(left, right); 
  }
  publicint getValue() 
  {
    return left.getValue() - right.getValue();
  }
}
```

`PlusOperand`和`MinusOperand`是当前支持的算术类型。他们知道如何表示加号（+）和减号（-）的算术表达式。

如预期，`(1 + 4) - 2`算术表达式返回 3，并将值打印到控制台，如下图所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/dsn-ptn-bst-prac-java/img/f2cdc200-c021-41d4-af7c-9c654e878838.png)

# 外观模式

许多复杂的系统可以简化为它们的几个用例，由子系统公开。这样，客户端代码就不需要了解子系统的内部结构。换句话说，客户端代码与之解耦，开发人员使用它所花费的时间更少。这被称为外观模式，外观对象负责公开所有子系统的功能。这个概念类似于封装，即隐藏对象的内部。在外观中，我们隐藏了子系统的内部，只暴露了其本质。其结果是，用户仅限于由外观公开的功能，并且不能使用/重用子系统的特定功能。

外观模式需要采用内部子系统接口（多个接口）到客户端代码接口（一个接口）。它通过创建一个新接口来实现这一点，而适配器模式适应现有接口（有时需要多个旧类来为新代码提供所需的功能）。外观对结构的作用与中介对对象通信的作用一样，它统一并简化了使用。在第一种情况下，客户端代码通过使用外观对象访问子系统的功能；在第二种情况下，不知道彼此（松耦合）的对象可以通过使用中介器/促进者进行交互。

# 意图

其目的是为复杂的子系统提供一个统一的接口。这通过为最重要的用例提供接口简化了大型复杂系统的使用。

# 实现

下图显示了如何简化子系统的使用并将其与客户端代码解耦。外观是子系统的入口点；因此，子系统代码可以很容易地切换到不同的实现。客户端依赖关系也可以更容易地管理，并且更明显：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/dsn-ptn-bst-prac-java/img/dd39d2e8-9db2-41ca-8666-6cedea4117aa.png)

我们可以在实现图中区分以下参与者：

*   `Client`：子系统客户端代码
*   `Facade`：子系统接口
*   `SubSystem`：子系统中定义的类

# 示例

咖啡机就像咖啡研磨机和咖啡酿造机的正面，因为它们隐藏了它们的功能。下面的代码模拟了一台咖啡机，它可以研磨咖啡豆、冲泡咖啡并将其放入咖啡杯中。

从下面的代码中你会发现，问题是我们不能得到细磨咖啡（我们必须把咖啡豆磨得再久一点），因为`serveCoffee()`方法只知道如何制作粗磨咖啡。这对一些喝咖啡的人来说是好的，但对所有人来说不是这样：

```java
package gof.structural.facade;
publicclass Main
{
  publicstaticvoid main (String[] args) throws java.lang.Exception
  {
    CoffeeMachineFacade facade = new SuperstarCoffeeMachine();
    facade.serveCoffee();
  }
}
class GroundCoffee 
{}
class Water 
{}
class CoffeeCup 
{}
```

`GroundCoffee`、`Water`和`CoffeeCup`是我们将要使用的项目类：

```java
interface CoffeeMachineFacade 
{
  public CoffeeCup serveCoffee() throws Exception;
}
```

`CoffeeMachineFacade`是我们的正面。它提供了一个方法，返回一个包含`Coffee`的`CoffeCup`：

```java
interface CoffeeGrinder 
{
  publicvoid startGrinding();
  public GroundCoffee stopGrinding();
}
interface CoffeeMaker 
{
  publicvoid pourWater(Water water);
  publicvoid placeCup(CoffeeCup cup);
  publicvoid startBrewing(GroundCoffee groundCoffee);
  public CoffeeCup finishBrewing();
}
class SuperstarCoffeeGrinder implements CoffeeGrinder 
{
  publicvoid startGrinding() 
  {
    System.out.println("Grinding...");
  }
  public GroundCoffee stopGrinding () 
  {
    System.out.println("Done grinding");
    returnnew GroundCoffee();
  }
}
class SuperstarCoffeeMaker implements CoffeeMaker 
{
  public CoffeeCup finishBrewing() 
  {
    System.out.println("Done brewing. Enjoy!");
    returnnull;
  }
  @Override
  publicvoid pourWater(Water water) 
  {
    System.out.println("Pouring water...");
  }
  @Override
  publicvoid placeCup(CoffeeCup cup) 
  { 
    System.out.println("Placing the cup...");
  }
  @Override
  publicvoid startBrewing(GroundCoffee groundCoffee) 
  {
    System.out.println("Brewing...");
  }
}
```

为了煮咖啡，我们使用不同的机器，比如咖啡研磨机和咖啡机。它们都是巨星公司的产品。外观机器是一个虚拟机；它只是我们现有机器的一个接口，并且知道如何使用它们。不幸的是，它不是高度可配置的，但它完成了大多数现有的咖啡饮料者的工作。让我们看看这个代码：

```java
class SuperstarCoffeeMachine implements CoffeeMachineFacade 
{
  public CoffeeCup serveCoffee() throws InterruptedException 
  {
    CoffeeGrinder grinder = new SuperstarCoffeeGrinder();
    CoffeeMaker brewer = new SuperstarCoffeeMaker();
    CoffeeCup cup = new CoffeeCup();
    grinder.startGrinding();
    Thread.sleep(500);//wait for grind size coarse
    brewer.placeCup(cup);
    brewer.pourWater(new Water());
    brewer.startBrewing(grinder.stopGrinding());
    Thread.sleep(1000);//wait for the brewing process
    return brewer.finishBrewing();
  }
}
```

以下输出显示，我们的立面能够提供我们的早餐咖啡：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/dsn-ptn-bst-prac-java/img/06dd0adf-9667-482b-8137-4304b855a0d0.png)

# 享元模式

创建对象需要花费时间和资源。最好的例子是 Java 常量字符串创建、`Boolean.valueOf(boolean b)`或`Character valueOf(char c)`，因为它们从不创建实例；它们返回不可变的缓存实例。为了提高速度（并保持较低的内存占用），应用使用对象池。对象池模式和享元模式的区别在于，第一个（创建模式）是一个保存可变域对象的容器，而享元（结构模式）是一个不可变的域对象。因为它们是不可变的，所以它们的内部状态是在创建时设置的，外部状态是在每次方法调用时从外部给定的。

大多数 Web 应用使用连接池—创建/获取、使用数据库连接并将其发送回连接池。由于这种模式非常常见，因此它有一个名称：[连接享元](http://wiki.c2.com/?ConnectionFlyweight)。其他资源，如套接字或线程（线程池模式），也使用对象池。

享元和外观的区别在于前者知道如何制作许多小对象，而后者制作单个对象，简化并隐藏了由许多对象组成的子系统的复杂性。

# 意图

其目的是通过在相似对象之间共享状态来减少内存占用。只有将大量的对象减少到具有代表性的、不依赖于对象相等性的、并且它们的状态可以外化的少数对象，才能做到这一点。

# 实现

下图显示了享元对象是从池中返回的，为了运行，它需要将外部状态（extrinsic）作为参数传递。有些享元可以与其他享元共享状态，但这不是强制执行的规则：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/dsn-ptn-bst-prac-java/img/45661156-c9d3-4ba4-9bda-f8045cd6fcfa.png)

我们可以在实现图中区分以下参与者：

*   `Client`：客户端代码。
*   `FlyweightFactory`：如果享元不存在，则创建享元；如果享元存在，则从池中返回享元。
*   `Flyweight`：抽象享元。
*   `ConcreateShareableFlyweight`：设计为与对等方共享状态的享元。
*   `ConcreateUnshareableFlyweight`：不共享其状态的享元。它可以由多个混凝土享元组成，例如，一个由三维立方体和球体组成的结构。

# 示例

下面的代码使用附加的物理引擎模拟三维世界。因为创建新的 3D 对象在内存方面是沉重和昂贵的，一旦创建它们就会是相同的，只是从一个地方移动到另一个地方。想象一个有很多岩石、树木、灌木和不同纹理的 3D 世界。只有一种岩石，一棵树，一丛灌木（它们可以共享一些纹理），只要记住它们的位置，我们就节省了大量的内存，我们仍然能够用它们填充相当大的地形：

```java
package gof.structural.flyweight;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;
publicclass Main
{
  publicstaticvoid main (String[] args) throws java.lang.Exception
  {
    World world = new World();
    world.get3DObject(_3DObjectTypes.Cube).makeVisible().
    move(10d, -13.3d, 90.0d);
    world.get3DObject(_3DObjectTypes.Sphere).makeVisible().
    move(11d, -12.9d, 90.0d);
    world.get3DObject(_3DObjectTypes.Cube).makeVisible().
    move(9d, -12.9d, 90.0d);
  }
}
enum _3DObjectTypes 
{
  Cube,
 Sphere
}
```

我们的 3D 世界目前只由立方体和球体构成。它们可以组合在一起形成更复杂的形式，如以下代码所示：

```java
class PhysicsEngine 
{
  publicvoid animateCollision(_3DObject collider, _3DObject 
  collidee) 
  {
    System.out.println("Animate Collision between " + collider +
    " and " + collidee);
  }
}
class World 
{
  private PhysicsEngine engine = new PhysicsEngine();
  private Map<String, _3DObject> objects = new ConcurrentHashMap<>();
  private Map<String, Location> locations = new ConcurrentHashMap<>();
  public _3DObject get3DObject(_3DObjectTypes type) 
  {
    String name = type.toString();
    if (objects.containsKey(name))
    return objects.get(name);
    _3DObject obj = make3DObject(type);
    objects.put(obj.getName(), obj);
    return obj;
  }
  private _3DObject make3DObject(_3DObjectTypes type) 
  {
    switch (type) 
    {
      caseCube:
      returnnew Cube(this, type.toString());
      caseSphere:
      returnnew Sphere(this, type.toString());
      default:
      returnnew _3DObject(this, type.toString());
    }
  }
  publicvoid move(_3DObject obj, Location location) 
  {
    final List<String> nearObjectNames = getNearObjects(location);
    locations.put(obj.getName(), location);
    for (String nearObjectName: nearObjectNames) 
    {
      engine.animateCollision(objects.get(nearObjectName), obj);
    }
  }
  private List<String> getNearObjects(Location location) 
  {
    if (objects.size() < 2)
    returnnew ArrayList<>();
    return objects.values().stream()
    .filter(obj -> 
    {
      Location loc = locations.get(obj.getName());
      return loc != null && loc.isNear(location, 1);
    }) 
    .map(obj -> obj.getName())
    .collect(Collectors.toList());
  }
}
```

`World`类表示享元工厂。它知道如何构造它们，并把自己当作一种外在的状态。除了渲染部分外，`World`类还使用了昂贵的物理引擎，它知道如何对碰撞进行建模。让我们看看代码：

```java
class _3DObject 
{
  private World world;
  private String name;
  public _3DObject(World world, String name) 
  { 
    this.world = world;
    this.name = name;
  }
  public String getName() 
  {
    return name;
  }
  @Override
  public String toString() 
  {
    return name;
  }
  public _3DObject makeVisible() 
  {
    returnthis;
  }
  publicvoid move(double x, double y, double z) 
  {
    System.out.println("Moving object " + name + " in the world");
    world.move(this, new Location(x, y, z));
  }
}
class Cube extends _3DObject 
{
  public Cube(World world, String name) 
  {
    super(world, name);
  }
}
class Sphere extends _3DObject 
{
  public Sphere(World world, String name) 
  {
    super(world, name);
  }
}
```

三维物体`Sphere`和`Cube`是享元，它们没有同一性。`World`类知道它们的身份和属性（位置、颜色、纹理和大小）。请看下面的代码：

```java
class Location 
{
  public Location(double x, double y, double z) 
  {
    super();
  }
  publicboolean isNear(Location location, int radius) 
  {
    returntrue;
  }
}
```

下面的输出显示，即使在三维世界中已经有一个立方体，添加另一个立方体也会使它与现有对象（另一个立方体和一个球体）发生碰撞。他们都没有身份；他们都是他们类型的代表：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/dsn-ptn-bst-prac-java/img/46d8a038-d3e0-4b3c-a7c8-db69402955a5.png)

# 总结

在本章中，我们学习了 GOF 结构模式。我们查看了它们的描述和意图，并用示例代码说明了它们的用法。我们学习了为什么，何时，以及如何应用它们，同时也研究了它们之间的细微差别。我们还简要介绍了其他鲜为人知的结构模式。

在接下来的章节中，我们将看到这些模式中的一些是如何在函数式和反应式世界中发生变化的。
