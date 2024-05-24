# C# 和 Unity 2021 游戏开发学习手册（二）

> 原文：[`zh.annas-archive.org/md5/D5230158773728FED97C67760D6D7EA0`](https://zh.annas-archive.org/md5/D5230158773728FED97C67760D6D7EA0)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：使用类、结构和 OOP

出于明显的原因，本书的目标不是让您因信息过载而头痛欲裂。然而，接下来的主题将把您从初学者的小隔间带到**面向对象编程**（**OOP**）的开放空间。到目前为止，我们一直在依赖 C#语言中预定义的变量类型：底层的字符串、列表和字典都是类，这就是为什么我们可以创建它们并通过点表示法使用它们的属性。然而，依赖内置类型有一个明显的弱点——无法偏离 C#已经设定的蓝图。

创建您自己的类使您能够定义和配置设计的蓝图，捕获信息并驱动特定于您的游戏或应用程序的操作。实质上，自定义类和 OOP 是编程王国的关键；没有它们，独特的程序将寥寥无几。

在本章中，您将亲身体验从头开始创建类，并讨论类变量、构造函数和方法的内部工作原理。您还将了解引用类型和值类型对象之间的区别，以及这些概念如何在 Unity 中应用。随着您的学习，以下主题将会更详细地讨论：

+   引入 OOP

+   定义类

+   声明结构

+   理解引用类型和值类型

+   整合面向对象的思维方式

+   在 Unity 中应用 OOP

# 引入 OOP

在 C#编程时，OOP 是您将使用的主要编程范式。如果类和结构实例是我们程序的蓝图，那么 OOP 就是将所有东西都组合在一起的架构。当我们将 OOP 称为编程范式时，我们是说它对整个程序的工作和通信有特定的原则。

实质上，OOP 关注的是对象而不是纯粹的顺序逻辑——它们所持有的数据，它们如何驱动行动，以及最重要的是它们如何相互通信。

# 定义类

回到*第二章*，*编程的基本组成部分*，我们简要讨论了类是对象的蓝图，并提到它们可以被视为自定义变量类型。我们还了解到`LearningCurve`脚本是一个类，但是 Unity 可以将其附加到场景中的对象。关于类的主要事情要记住的是它们是*引用类型*——也就是说，当它们被分配或传递给另一个变量时，引用的是原始对象，而不是一个新的副本。在我们讨论结构之后，我们将深入讨论这一点。然而，在此之前，我们需要了解创建类的基础知识。

现在，我们将暂时搁置 Unity 中类和脚本的工作方式，专注于它们在 C#中是如何创建和使用的。类是使用`class`关键字创建的，如下所示：

```cs
accessModifier class UniqueName
{
    Variables 
    Constructors
    Methods
} 
```

在一个类内声明的任何变量或方法都属于该类，并通过其独特的类名访问。

为了使本章中的示例尽可能连贯，我们将创建和修改一个典型游戏可能拥有的简单`Character`类。我们还将摆脱代码截图，让您习惯于阅读和解释代码，就像在实际环境中看到的那样。然而，我们首先需要自己的自定义类，所以让我们创建一个。

在我们理解它们的内部工作原理之前，我们需要一个类来进行实践，所以让我们创建一个新的 C#脚本，从头开始。

1.  右键单击您在*第一章*中创建的`Scripts`文件夹，然后选择**创建** | **C#脚本**。

1.  将脚本命名为`Character`，在 Visual Studio 中打开它，并删除所有生成的代码。

1.  声明一个名为`Character`的公共类，后面跟着一对花括号，然后保存文件。您的类代码应该与以下代码完全匹配：

```cs
using System.Collections;
using System.Collections.Generic;
using UnityEngine;

public class Character
{ 
} 
```

1.  我们删除了生成的代码，因为我们不需要将这个脚本附加到 Unity 游戏对象上。

`Character`现在被注册为一个公共类蓝图。这意味着项目中的任何类都可以使用它来创建角色。然而，这些只是指示——创建角色需要额外的步骤。这个创建步骤被称为*实例化*，并且是下一节的主题。

## 实例化类对象

实例化是根据特定一组指令创建对象的行为，这个对象被称为实例。如果类是蓝图，实例就是根据它们的指令建造的房屋；每个新的`Character`实例都是它的对象，就像根据相同指令建造的两个房屋仍然是两个不同的物理结构一样。一个的变化对另一个没有任何影响。

在*第四章*，*控制流和集合类型*中，我们创建了列表和字典，这些是 C#默认的类，使用它们的类型和`new`关键字。我们可以对自定义类（比如`Character`）做同样的事情，这就是你接下来要做的。

我们将`Character`类声明为公共的，这意味着在任何其他类中都可以创建`Character`实例。由于我们已经在`LearningCurve`中工作了，让我们在`Start()`方法中声明一个新的角色。

在`Start()`方法中打开`LearningCurve`并声明一个名为`hero`的新的`Character`类型变量：

```cs
Character hero = new Character(); 
```

让我们一步一步来分解这个问题：

1.  变量类型被指定为`Character`，这意味着变量是该类的一个实例。

1.  变量名为`hero`，它是使用`new`关键字创建的，后面跟着`Character`类名和两个括号。这是实例在程序内存中创建的地方，即使类现在是空的。

1.  我们可以像处理到目前为止的任何其他对象一样使用`hero`变量。当`Character`类有了自己的变量和方法时，我们可以使用点符号从`hero`中访问它们。

在创建`hero`变量时，你也可以使用推断声明，就像这样：

```cs
var hero = new Character(); 
```

现在我们的角色类没有任何类字段的话就不能做太多事情。在接下来的几节中，你将添加类字段，以及更多内容。

## 添加类字段

向自定义类添加变量或字段与我们在`LearningCurve`中已经做过的事情没有什么不同。相同的概念适用，包括访问修饰符、变量作用域和值分配。然而，属于类的任何变量都是与类实例一起创建的，这意味着如果没有分配值，它们将默认为零或空。一般来说，选择设置初始值取决于它们将存储的信息：

+   如果一个变量在创建类实例时需要具有相同的起始值，设置初始值是一个很好的主意。这对于像经验点或起始分数之类的东西会很有用。

+   如果一个变量需要在每个类实例中进行自定义，比如`CharacterName`，就将其值保持未分配，并使用类构造函数（这是我们将在*使用构造函数*部分讨论的一个主题）。

每个角色类都需要一些基本字段；在接下来的部分中，你需要添加它们。

让我们加入两个变量来保存角色的名称和起始经验点数：

1.  在`Character`类的大括号内添加两个`public`变量——一个用于名称的`string`变量，一个用于经验点的`integer`变量。

1.  将`name`值留空，但将经验点设置为`0`，这样每个角色都从零开始：

```cs
public class Character
{
    public string name;
    public int exp = 0; 
} 
```

1.  在`Character`实例初始化后，在`LearningCurve`中添加一个调试日志。使用它来打印出新角色的`name`和`exp`变量，使用点符号表示法：

```cs
Character hero = new Character(); 
Debug.LogFormat("Hero: {0} - {1} EXP", hero.name, hero.exp); 
```

1.  当`hero`被初始化时，`name`被分配一个空值，在调试日志中显示为空格，而`exp`打印出`0`。请注意，我们不需要将`Character`脚本附加到场景中的任何游戏对象上；我们只是在`LearningCurve`中引用它们，Unity 会完成其余的工作。控制台现在将调试输出我们的角色信息，如下所示：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_05_01.png)

图 5.1：控制台中打印的自定义类属性的屏幕截图

到目前为止，我们的类可以工作，但是使用这些空值并不是很实用。您需要使用所谓的类构造函数来解决这个问题。

## 使用构造函数

类构造函数是特殊的方法，当创建类实例时会自动触发，这类似于`LearningCurve`中`Start`方法的运行方式。构造函数根据其蓝图构建类：

+   如果没有指定构造函数，C#会生成一个默认构造函数。默认构造函数将任何变量设置为它们的默认类型值——数值变量设置为零，布尔变量设置为 false，引用类型（类）设置为 null。

+   自定义构造函数可以带有参数，就像任何其他方法一样，并且用于在初始化时设置类变量的值。

+   一个类可以有多个构造函数。

构造函数的编写方式与常规方法相似，但有一些区别；例如，它们需要是公共的，没有返回类型，方法名始终是类名。例如，让我们向`Character`类添加一个没有参数的基本构造函数，并将名称字段设置为非 null 值。

将这段新代码直接添加到类变量下面，如下所示：

```cs
public string name;
public int exp = 0;
**public****Character****()**
**{**
 **name =** **"Not assigned"****;**
**}** 
```

在 Unity 中运行项目，您将看到`hero`实例使用这个新的构造函数。调试日志将显示英雄的名称为**未分配**，而不是空值：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_05_02.png)

图 5.2：控制台中打印的未分配的自定义类变量的屏幕截图

这是一个很好的进展，但是我们需要使类构造函数更加灵活。这意味着我们需要能够传入值，以便它们可以作为起始值使用，接下来您将要做的就是这个。

现在，`Character`类开始表现得更像一个真正的对象，但我们可以通过添加第二个构造函数来使其更好，以便在初始化时接受一个名称并将其设置为`name`字段：

1.  在`Character`中添加另一个接受`string`参数的构造函数，称为`name`。

1.  使用`this`关键字将参数分配给类的`name`变量。这被称为*构造函数重载*：

```cs
public Character(string name)
{
    this.name = name;
} 
```

为了方便起见，构造函数通常会具有与类变量同名的参数。在这些情况下，使用`this`关键字指定变量属于类。在这个例子中，`this.name`指的是类的名称变量，而`name`是参数；如果没有`this`关键字，编译器会发出警告，因为它无法区分它们。

1.  在`LearningCurve`中创建一个新的`Character`实例，称为`heroine`。在初始化时使用自定义构造函数传入一个名称，并在控制台中打印出详细信息：

```cs
Character heroine = new Character("Agatha");
Debug.LogFormat("Hero: {0} - {1} EXP", heroine.name,
        heroine.exp); 
```

当一个类有多个构造函数或一个方法有多个变体时，Visual Studio 会在自动完成弹出窗口中显示一组箭头，可以使用箭头键滚动浏览：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_05_03.png)

图 5.3：Visual Studio 中多个方法构造函数的屏幕截图

1.  现在，我们可以在初始化新的`Character`类时选择基本构造函数或自定义构造函数。`Character`类本身在配置不同情况下的不同实例时现在更加灵活了：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_05_04.png)

图 5.4：控制台中打印的多个自定义类实例的屏幕截图

现在真正的工作开始了；除了作为变量存储设施之外，我们的类还需要方法才能做任何有用的事情。您的下一个任务是将这个付诸实践。

## 声明类方法

将自定义类添加方法与将它们添加到`LearningCurve`没有任何区别。然而，这是一个很好的机会来谈谈良好编程的基本原则——**不要重复自己**（**DRY**）。DRY 是所有良好编写代码的基准。基本上，如果你发现自己一遍又一遍地写同样的代码行，那么是时候重新思考和重新组织了。这通常以创建一个新方法来保存重复的代码形式出现，这样可以更容易地修改和调用该功能，无论是在当前脚本中还是在其他脚本中。

在编程术语中，你会看到这被称为**抽象**出一个方法或特性。

我们已经有了相当多的重复代码，所以让我们看看在哪里可以增加脚本的可读性和效率。

我们重复的调试日志是一个很好的机会，可以将一些代码直接抽象到`Character`类中：

1.  向`Character`类添加一个名为`PrintStatsInfo`的新`public`方法，返回类型为`void`。

1.  将`LearningCurve`中的调试日志复制粘贴到方法体中。

1.  将变量更改为`name`和`exp`，因为现在可以直接从类引用它们。

```cs
public void PrintStatsInfo()
{
      Debug.LogFormat("Hero: {0} - {1} EXP", name, exp);
} 
```

1.  用对`PrintStatsInfo`的方法调用替换我们之前添加到`LearningCurve`中的角色调试日志，然后点击播放：

```cs
 Character hero = new Character();
 **hero.PrintStatsInfo();**
 Character heroine = new Character("Agatha");
 **heroine.PrintStatsInfo();** 
```

1.  现在`Character`类有了一个方法，任何实例都可以使用点表示法自由访问它。由于`hero`和`heroine`都是独立的对象，`PrintStatsInfo`会将它们各自的`name`和`exp`值调试到控制台。

这种行为比直接在`LearningCurve`中拥有调试日志要好。将功能组合到一个类中并通过方法驱动操作总是一个好主意。这样可以使代码更易读——因为我们的`Character`对象在打印调试日志时发出了命令，而不是重复代码。

整个`Character`类应该如下所示的代码：

```cs
using System.Collections;
using System.Collections.Generic;
using UnityEngine;

public class Character
{
    public string name;
    public int exp = 0;

    public Character()
    {
        name = "Not assigned";
    }

    public Character(string name)
    {
        this.name = name;
    }

    public void PrintStatsInfo()
    {
        Debug.LogFormat("Hero: {0} - {1} EXP", name, exp);
    }
} 
```

通过对类的讲解，你已经可以写出可读性强、轻量级且可重用的模块化代码了。现在是时候来解决类的表亲对象——结构体了！

# 声明结构体

**结构体**与类似，它们也是你想在程序中创建的对象的蓝图。主要区别在于它们是*值类型*，这意味着它们是按值传递而不是按引用传递的，就像类一样。当结构体被分配或传递给另一个变量时，会创建结构体的一个新副本，因此原始结构体根本没有被引用。我们将在下一节中更详细地讨论这一点。首先，我们需要了解结构体的工作原理以及创建它们时适用的具体规则。

结构体的声明方式与类相同，可以包含字段、方法和构造函数。

```cs
accessModifier struct UniqueName 
{
    Variables
    Constructors
    Methods
} 
```

与类一样，任何变量和方法都属于结构体，并且通过其唯一名称访问。

然而，结构体有一些限制：

+   除非标记为`static`或`const`修饰符，否则不能在结构体声明中使用值初始化变量——你可以在*第十章*，*重新审视类型、方法和类*中了解更多信息。

+   不允许没有参数的构造函数。

+   结构体带有一个默认构造函数，它会自动将所有变量设置为它们的默认值，根据它们的类型。

每个角色都需要一把好武器，这些武器是结构体对象的完美选择。我们将在本章的*理解引用和值类型*部分讨论为什么这样做。然而，首先，你要创建一个结构体来玩耍。

我们的角色需要好的武器来完成任务，这对于一个简单的结构体来说是一个很好的选择：

1.  右键单击`Scripts`文件夹，选择**创建**，然后选择**C#脚本**。

1.  将其命名为`Weapon`，在 Visual Studio 中打开它，然后删除`using UnityEngine`后面生成的所有代码。

1.  声明一个名为`Weapon`的公共结构体，然后保存文件。

1.  添加一个`string`类型的`name`字段和一个`int`类型的`damage`字段：

你可以在彼此嵌套的类和结构中，但这通常是不被赞同的，因为它会使代码变得混乱。

```cs
public struct Weapon
{
    public string name;
    public int damage;
} 
```

1.  使用`name`和`damage`参数声明一个构造函数，并使用`this`关键字设置结构字段：

```cs
public Weapon(string name, int damage)
{
    this.name = name;
    this.damage = damage;
} 
```

1.  在构造函数下面添加一个调试方法来打印武器信息：

```cs
public void PrintWeaponStats()
{
    Debug.LogFormat("Weapon: {0} - {1} DMG", name, damage);
} 
```

1.  在`LearningCurve`中，使用自定义构造函数和`new`关键字创建一个新的`Weapon`结构：

```cs
Weapon huntingBow = new Weapon("Hunting Bow", 105); 
```

1.  我们的新`huntingBow`对象使用了自定义构造函数，并在初始化时为两个字段提供了值。

将脚本限制为单个类是一个好主意，但看到仅由一个类专用的结构体包含在文件中是相当常见的。

现在我们已经有了引用（类）和值（结构）对象的例子，是时候熟悉它们各自的细节了。更具体地说，你需要了解这些对象是如何在内存中传递和存储的。

# 理解引用类型和值类型

除了关键字和初始字段值之外，到目前为止我们还没有看到类和结构之间有太大的区别。类最适合将复杂的操作和数据组合在一起，并且这些数据在程序运行过程中会发生变化；而结构更适合简单的对象和数据，这些数据在大部分时间内都保持不变。除了它们的用途之外，在一个关键领域它们有根本的不同——那就是它们是如何在变量之间传递或赋值的。类是*引用类型*，意味着它们是通过引用传递的；结构是*值类型*，意味着它们是通过值传递的。

## 引用类型

当我们的`Character`类的实例被初始化时，`hero`和`heroine`变量并不持有它们的类信息——相反，它们持有对象在程序内存中的位置的引用。如果我们将`hero`或`heroine`分配给同一类中的另一个变量，那么内存引用就会被分配，而不是角色数据。这有几个影响，其中最重要的是，如果我们有多个变量存储相同的内存引用，对其中一个的更改会影响它们全部。

这样的话题最好是通过演示而不是解释来展示；接下来就由你来在实际例子中尝试一下。

现在是时候测试`Character`类是引用类型了：

1.  在`LearningCurve`中，声明一个名为`hero2`的新`Character`变量。将`hero2`分配给`hero`变量，并使用`PrintStatsInfo`方法打印出两组信息。

1.  点击播放并查看在控制台中显示的两个调试日志：

```cs
Character hero = new Character();
**Character hero2 = hero;**

hero.PrintStatsInfo();
**hero2.PrintStatsInfo();** 
```

1.  两个调试日志将是相同的，因为在创建`hero2`时它被赋值给了`hero`。此时，`hero2`和`hero`都指向内存中`hero`所在的位置！[](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_05_05.png)

图 5.5：控制台打印的结构体统计信息的屏幕截图

1.  现在，将`hero2`的名字改成有趣的东西，然后再次点击播放：

```cs
Character hero2 = hero;
**hero2.name =** **"Sir Krane the Brave"****;** 
```

1.  你会看到现在`hero`和`hero2`都有相同的名字，即使只有一个角色的数据被改变了！[](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_05_06.png)

图 5.6：控制台打印的类实例属性的屏幕截图

这里的教训是，引用类型需要小心处理，不要在分配给新变量时进行复制。对一个引用的任何更改都会影响所有持有相同引用的其他变量。

如果你想复制一个类，要么创建一个新的独立实例，要么重新考虑是否结构体可能是你对象蓝图的更好选择。在接下来的部分中，你将更好地了解值类型。

## 值类型

当创建一个结构对象时，它的所有数据都存储在相应的变量中，没有引用或连接到它的内存位置。这使得结构对于创建需要快速高效地复制的对象非常有用，同时仍保留它们各自的身份。在接下来的练习中，尝试使用我们的`Weapon`结构来实现这一点。

让我们通过将`huntingBow`复制到一个新变量中并更新其数据来创建一个新的武器对象，以查看更改是否影响两个结构体：

1.  在`LearningCurve`中声明一个新的`Weapon`结构，并将`huntingBow`分配为其初始值：

```cs
Weapon huntingBow = new Weapon("Hunting Bow", 105);
**Weapon warBow = huntingBow;** 
```

1.  使用调试方法打印出每个武器的数据：

```cs
**huntingBow.PrintWeaponStats();**
**warBow.PrintWeaponStats();** 
```

1.  现在它们的设置方式是，`huntingBow`和`warBow`将有相同的调试日志，就像我们在改变任何数据之前的两个角色一样！

图 5.7：控制台中打印的结构体实例的屏幕截图

1.  将`warBow.name`和`warBow.damage`字段更改为你选择的值，然后再次点击播放：

```cs
 Weapon warBow = huntingBow;
 **warBow.name =** **"War Bow"****;**
 **warBow.damage =** **155****;** 
```

1.  控制台将显示只有与`warBow`相关的数据被更改，而`huntingBow`保留其原始数据。

图 5.8：打印到控制台的更新后的结构体属性的屏幕截图

从这个例子中可以得出的结论是，结构体很容易被复制和修改为它们各自的对象，而类则保留对原始对象的引用。现在我们对结构体和类在底层是如何工作有了一些了解，并确认了引用和值类型在它们的自然环境中的行为，我们可以开始谈论编程中最重要的一个主题，OOP，以及它如何适应编程领域。

# 整合面向对象的思维方式

物理世界中的事物在 OOP 的类似级别上运行；当你想要买一罐软饮料时，你拿的是一罐苏打水，而不是液体本身。这个罐子是一个对象，将相关信息和动作组合在一个自包含的包中。然而，在处理对象时有一些规则，无论是在编程中还是在杂货店——例如，谁可以访问它们。不同的变化和通用的动作都影响着我们周围所有对象的性质。

在编程术语中，这些规则是 OOP 的主要原则：*封装*、*继承*和*多态*。

## 封装

OOP 最好的一点是它支持封装——定义对象的变量和方法对外部代码的可访问性（有时被称为*调用代码*）。以我们的苏打罐为例——在自动售货机中，可能的互动是有限的。由于机器被锁住，不是每个人都可以过来拿一罐；如果你碰巧有合适的零钱，你将被允许有条件地访问它，但数量是有限制的。如果机器本身被锁在一个房间里，只有拿着门钥匙的人才会知道苏打罐的存在。

你现在要问自己的问题是，我们如何设置这些限制？简单的答案是，我们一直在使用封装，通过为我们的对象变量和方法指定访问修饰符。

如果你需要复习，请回到*第三章*，*深入变量、类型和方法*中的*访问修饰符*部分。

让我们尝试一个简单的封装示例，以了解这在实践中是如何工作的。我们的`Character`类是公共的，它的字段和方法也是公共的。但是，如果我们想要一个方法来将角色的数据重置为其初始值，会怎样呢？这可能会很方便，但如果意外调用了它，可能会造成灾难，这就是一个私有对象成员的完美候选者：

1.  在`Character`类中创建一个名为`Reset`的`private`方法，没有返回值。将`name`和`exp`变量分别设置为`"Not assigned"`和`0`：

```cs
private void Reset()
{
    this.name = "Not assigned";
    this.exp = 0;
} 
```

1.  尝试在打印出`hero2`数据后从`LearningCurve`中调用`Reset()`！

图 5.9：Character 类中一个无法访问的方法的屏幕截图

如果你想知道 Visual Studio 是否出了问题，它没有。将方法或变量标记为私有将使其在这个类或结构体内部使用点表示法时无法访问；如果你手动输入并悬停在`Reset()`上，你会看到有关该方法受保护的错误消息。

要实际调用这个私有方法，我们可以在类构造函数中添加一个重置命令：

```cs
public Character()
{
    Reset();
} 
```

封装确实允许对象具有更复杂的可访问性设置；然而，现在我们将坚持使用 `public` 和 `private` 成员。在下一章中，当我们开始完善游戏原型时，我们将根据需要添加不同的修饰符。

现在，让我们谈谈继承，在创建未来游戏中的类层次结构时，它将成为您的好朋友。

## 继承

C# 类可以按照另一个类的形象创建，共享其成员变量和方法，但能够定义其独特的数据。在面向对象编程中，我们将这称为*继承*，这是一种创建相关类的强大方式，而无需重复代码。再次以汽水为例，市场上有通用汽水，它们具有相同的基本属性，还有特殊汽水。特殊汽水共享相同的基本属性，但具有不同的品牌或包装，使它们与众不同。当您将两者并排看时，很明显它们都是汽水罐，但它们显然不是同一种。

原始类通常称为基类或父类，而继承类称为派生类或子类。任何使用 `public`、`protected` 或 `internal` 访问修饰符标记的基类成员都自动成为派生类的一部分，除了构造函数。类构造函数始终属于其包含类，但可以从派生类中使用，以将重复的代码最小化。现在不要太担心不同的基类情况。相反，让我们尝试一个简单的游戏示例。

大多数游戏都有多种类型的角色，因此让我们创建一个名为 `Paladin` 的新类，该类继承自 `Character` 类。您可以将这个新类添加到 `Character` 脚本中，也可以创建一个新的脚本。如果要将新类添加到 `Character` 脚本中，请确保它在 `Character` 类的花括号之外：

```cs
public class Paladin: Character
{
} 
```

就像 `LearningCurve` 从 `MonoBehavior` 继承一样，我们只需要添加一个冒号和我们想要继承的基类，C# 就会完成剩下的工作。现在，任何 `Paladin` 实例都可以访问 `name` 属性和 `exp` 属性，以及 `PrintStatsInfo` 方法。

通常最好为不同的类创建新的脚本，而不是将它们添加到现有的脚本中。这样可以分离脚本，并避免在任何单个文件中有太多行代码（称为臃肿文件）。

这很好，但继承类如何处理它们的构造？您可以在下一节中找到答案。

### 基础构造函数

当一个类从另一个类继承时，它们形成一种金字塔结构，成员变量从父类流向任何派生子类。父类不知道任何子类，但所有子类都知道它们的父类。然而，父类构造函数可以直接从子类构造函数中调用，只需进行简单的语法修改：

```cs
public class ChildClass: ParentClass
{
    public ChildClass(): **base****()**
    {
    }
} 
```

`base` 关键字代表父构造函数，这种情况下是默认构造函数。然而，由于 `base` 代表一个构造函数，构造函数是一个方法，子类可以将参数传递给其父类构造函数。

由于我们希望所有 `Paladin` 对象都有一个名称，而 `Character` 已经有一个处理这个问题的构造函数，我们可以直接从 `Paladin` 类调用 `base` 构造函数，而不必重写构造函数：

1.  为 `Paladin` 类添加一个构造函数，该构造函数接受一个 `string` 参数，称为 `name`。使用 `colon` 和 `base` 关键字调用父构造函数，传入 `name`：

```cs
public class Paladin: Character
{
**public****Paladin****(****string** **name****):** **base****(****name****)**
 **{**

 **}**
} 
```

1.  在 `LearningCurve` 中，创建一个名为 `knight` 的新 `Paladin` 实例。使用基础构造函数来分配一个值。从 `knight` 调用 `PrintStatsInfo`，并查看控制台：

```cs
Paladin knight = new Paladin("Sir Arthur");
knight.PrintStatsInfo(); 
```

1.  调试日志将与我们的其他`Character`实例相同，但名称将与我们分配给`Paladin`构造函数的名称相同：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_05_10.png)

图 5.10：基本角色构造函数属性的屏幕截图

当`Paladin`构造函数触发时，它将`name`参数传递给`Character`构造函数，从而设置`name`值。基本上，我们使用`Character`构造函数来为`Paladin`类做初始化工作，使`Paladin`构造函数只负责初始化其独特的属性，而在这一点上它还没有。

除了继承，有时你会想要根据其他现有对象的组合来创建新对象。想想乐高积木；你不是从零开始建造——你已经有了不同颜色和结构的积木块可以使用。在编程术语中，这被称为“组合”，我们将在下一节讨论。

## 构成

除了继承，类还可以由其他类组成。以我们的`Weapon`结构为例，`Paladin`可以在自身内部轻松包含一个`Weapon`变量，并且可以访问其所有属性和方法。让我们通过更新`Paladin`来接受一个起始武器并在构造函数中分配其值：

```cs
public class Paladin: Character
{
   **public** **Weapon weapon;**

    public Paladin(string name, **Weapon weapon**): base(name)
    {
        **this****.weapon = weapon;**
    }
} 
```

由于`weapon`是`Paladin`独有的，而不是`Character`的，我们需要在构造函数中设置其初始值。我们还需要更新`knight`实例以包含一个`Weapon`变量。所以，让我们使用`huntingBow`：

```cs
Paladin knight = new Paladin("Sir Arthur", **huntingBow**); 
```

如果现在运行游戏，你不会看到任何不同，因为我们使用的是`Character`类的`PrintStatsInfo`方法，它不知道`Paladin`类的`weapon`属性。为了解决这个问题，我们需要谈谈多态性。

## 多态性

多态是希腊词“多形”的意思，在面向对象编程中有两种不同的应用方式：

+   派生类对象被视为与父类对象相同。例如，一个`Character`对象数组也可以存储`Paladin`对象，因为它们是从`Character`派生而来的。

+   父类可以将方法标记为`virtual`，这意味着它们的指令可以被派生类使用`override`关键字修改。在`Character`和`Paladin`的情况下，如果我们可以为每个类从`PrintStatsInfo`中调试不同的消息，那将是有用的。

多态性允许派生类保留其父类的结构，同时也可以自由地调整动作以适应其特定需求。你标记为`virtual`的任何方法都将给你对象多态性的自由。让我们利用这个新知识并将其应用到我们的角色调试方法中。

让我们修改`Character`和`Paladin`以使用`PrintStatsInfo`打印不同的调试日志：

1.  在`Character`类中通过在`public`和`void`之间添加`virtual`关键字来更改`PrintStatsInfo`：

```cs
public **virtual** void PrintStatsInfo()
{
    Debug.LogFormat("Hero: {0} - {1} EXP", name, exp);
} 
```

1.  使用`override`关键字在`Paladin`类中声明`PrintStatsInfo`方法。添加一个调试日志，以你喜欢的方式打印`Paladin`属性：

```cs
public override void PrintStatsInfo()
{
    Debug.LogFormat("Hail {0} - take up your {1}!", name, 
             weapon.name);
} 
```

这可能看起来像重复的代码，我们已经说过这是不好的形式，但这是一个特殊情况。通过在`Character`类中将`PrintStatsInfo`标记为`virtual`，我们告诉编译器这个方法可以根据调用类的不同而有不同的形式。

1.  当我们在`Paladin`中声明了`PrintStatsInfo`的重写版本时，我们添加了仅适用于该类的自定义行为。多亏了多态性，我们不必选择从`Character`或`Paladin`对象调用哪个版本的`PrintStatsInfo`——编译器已经知道了：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_05_11.png)

图 5.11：多态角色属性的屏幕截图

我知道这是很多内容，所以让我们在接近终点时回顾一些面向对象编程的主要要点：

+   面向对象编程是将相关数据和操作分组到对象中——这些对象可以相互通信并独立行动。

+   可以使用访问修饰符来设置对类成员的访问，就像变量一样。

+   类可以继承自其他类，创建父/子关系的层级结构。

+   类可以拥有其他类或结构类型的成员。

+   类可以覆盖任何标记为`virtual`的父方法，允许它们执行自定义操作同时保留相同的蓝图。

OOP 并不是 C#唯一可用的编程范式，你可以在这里找到其他主要方法的实际解释：[`cs.lmu.edu/~ray/notes/paradigms`](http://cs.lmu.edu/~ray/notes/paradigms)。

在本章学到的所有 OOP 都直接适用于 C#世界。然而，我们仍需要将其与 Unity 放在适当的位置，这将是你在本章剩余时间里专注的内容。

# 在 Unity 中应用 OOP

如果你在 OOP 语言中待得足够长，你最终会听到像*一切都是对象*这样的短语在开发者之间像秘密祈祷一样被低声诉说。遵循 OOP 原则，程序中的一切都应该是一个对象，但 Unity 中的 GameObject 可以代表你的类和结构。然而，并不是说 Unity 中的所有对象都必须在物理场景中，所以我们仍然可以在幕后使用我们新发现的编程类。

## 对象是一个优秀的类

回到*第二章*，*编程的基本组成部分*，我们讨论了当脚本添加到 Unity 中的 GameObject 时，脚本会被转换为组件。从 OOP 的组合原则来看，GameObject 是父容器，它们可以由多个组件组成。这可能与每个脚本一个 C#类的想法相矛盾，但事实上，这更多是为了更好的可读性而不是实际要求。类可以嵌套在彼此内部——只是会变得很混乱。然而，将多个脚本组件附加到单个 GameObject 上可能非常有用，特别是在处理管理类或行为时。

总是试图将对象简化为它们最基本的元素，然后使用组合来构建更大、更复杂的对象。这样做比修改由大型笨重组成的 GameObject 更容易，因为 GameObject 由小型、可互换的组件组成。

让我们来看看**Main Camera**，看看它是如何运作的：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_05_12.png)

图 5.12：检视器中主摄像机对象的屏幕截图

在前面的屏幕截图中，每个组件（**Transform**、**Camera**、**Audio Listener**和**Learning Curve**脚本）最初都是 Unity 中的一个类。就像`Character`或`Weapon`的实例一样，当我们点击播放时，这些组件在计算机内存中变成对象，包括它们的成员变量和方法。

如果我们将`LearningCurve`（或任何脚本或组件）附加到 1,000 个 GameObject 上并点击播放，将创建并存储 1,000 个单独的`LearningCurve`实例。

我们甚至可以使用组件名称作为数据类型来创建这些组件的实例。与类一样，Unity 组件类是引用类型，可以像其他变量一样创建。然而，查找和分配这些 Unity 组件与你迄今为止所见到的略有不同。为此，你需要在下一节更多地了解 GameObject 的工作原理。

## 访问组件

现在我们知道了组件如何作用于 GameObject，那么我们如何访问它们的特定实例呢？幸运的是，Unity 中的所有 GameObject 都继承自`GameObject`类，这意味着我们可以使用它们的成员方法来在场景中找到我们需要的任何东西。有两种方法可以分配或检索当前场景中活动的 GameObject：

1.  通过`GameObject`类中的`GetComponent()`或`Find()`方法，这些方法可以使用公共和私有变量。

1.  通过将游戏对象直接从**Project**面板拖放到**Inspector**选项卡中的变量槽中。这个选项只适用于 C#中的公共变量，因为它们是唯一会出现在检查器中的变量。如果您决定需要在检查器中显示一个私有变量，可以使用`SerializeField`属性进行标记。

您可以在 Unity 文档中了解有关属性和`SerializeField`的更多信息：[`docs.unity3d.com/ScriptReference/SerializeField.html`](https://docs.unity3d.com/ScriptReference/SerializeField.html)。

让我们来看看第一个选项的语法。

### 在代码中访问组件

使用`GetComponent`相当简单，但它的方法签名与我们迄今为止看到的其他方法略有不同：

```cs
GameObject.GetComponent<ComponentType>(); 
```

我们只需要寻找的组件类型，`GameObject`类将返回该组件（如果存在）和`null`（如果不存在）。`GetComponent`方法还有其他变体，但这是最简单的，因为我们不需要了解我们要查找的`GameObject`类的具体信息。这被称为`通用`方法，我们将在*第十三章*“探索泛型、委托和更多内容”中进一步讨论。然而，现在让我们只使用摄像机的变换。

由于`LearningCurve`已经附加到**Main Camera**对象上，让我们获取摄像机的`Transform`组件并将其存储在一个公共变量中。`Transform`组件控制 Unity 中对象的位置、旋转和缩放，因此这是一个很好的例子：

1.  在`LearningCurve`中添加一个新的公共`Transform`类型变量，称为`CamTransform`：

```cs
public Transform CamTransform; 
```

1.  在`Start`中使用`GetComponent`方法从`GameObject`类初始化`CamTransform`。使用`this`关键字，因为`LearningCurve`附加到与`Transform`组件相同的`GameObject`组件上。

1.  使用点表示法访问和调试`CamTransform`的`localPosition`属性：

```cs
void Start()
{
    CamTransform = this.GetComponent<Transform>();
    Debug.Log(CamTransform.localPosition); 
} 
```

1.  我们在`LearningCurve`的顶部添加了一个未初始化的`public Transform`变量，并在`Start`中使用`GetComponent`方法进行了初始化。`GetComponent`找到了附加到此`GameObject`组件的`Transform`组件，并将其返回给`CamTransform`。现在`CamTransform`存储了一个`Transform`对象，我们可以访问它的所有类属性和方法，包括以下屏幕截图中的`localPosition`！[](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_05_13.png)

图 5.13：控制台中打印的 Transform 位置的屏幕截图

`GetComponent`方法非常适用于快速检索组件，但它只能访问调用脚本所附加到的游戏对象上的组件。例如，如果我们从附加到**Main Camera**的`LearningCurve`脚本中使用`GetComponent`，我们只能访问**Transform**、**Camera**和**Audio Listener**组件。

如果我们想引用另一个游戏对象上的组件，比如**Directional Light**，我们需要先使用`Find`方法获取对该对象的引用。只需要游戏对象的名称，Unity 就会返回适当的游戏对象供我们存储或操作。

要参考每个游戏对象的名称，可以在所选对象的**Inspector**选项卡顶部找到：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_05_14.png)

图 5.14：检查器中的 Directional Light 对象的屏幕截图

在 Unity 中找到游戏场景中的对象是至关重要的，因此您需要进行练习。让我们拿到手头的对象并练习查找和分配它们的组件。

让我们尝试一下`Find`方法，并从`LearningCurve`中检索**Directional Light**对象：

1.  在`CamTransform`下面的`LearningCurve`中添加两个变量，一个是`GameObject`类型，一个是`Transform`类型：

```cs
public GameObject DirectionLight;
public Transform LightTransform; 
```

1.  通过名称找到`Directional Light`组件，并在`Start()`方法中用它初始化`DirectionLight`：

```cs
void Start()
{
    DirectionLight = GameObject.Find("Directional Light"); 
} 
```

1.  将`LightTransform`的值设置为附加到`DirectionLight`的`Transform`组件，并调试其`localPosition`。由于`DirectionLight`现在是它的`GameObject`，`GetComponent`完美地工作：

```cs
LightTransform = DirectionLight.GetComponent<Transform>();
Debug.Log(LightTransform.localPosition); 
```

1.  在运行游戏之前，重要的是要理解方法调用可以链接在一起，以减少代码步骤。例如，我们可以通过组合`Find`和`GetComponent`来在一行中初始化`LightTransform`，而不必经过`DirectionLight`：

```cs
GameObject.Find("Directional Light").GetComponent<Transform>(); 
```

警告：长串链接的代码会导致可读性差和混乱，特别是在处理复杂应用程序时。避免超过这个示例的长行是个好的经验法则。

虽然在代码中查找对象总是有效的，但你也可以简单地将对象本身拖放到**Inspector**选项卡中。让我们在下一节中演示如何做到这一点。

### 拖放

既然我们已经介绍了代码密集的做事方式，让我们快速看一下 Unity 的拖放功能。虽然拖放比在代码中使用`GameObject`类要快得多，但 Unity 有时会在保存或导出项目时，或者在 Unity 更新时，丢失通过这种方式建立的对象和变量之间的连接。

当你需要快速分配几个变量时，尽管利用这个功能。但大多数情况下，我建议坚持编码。

让我们改变`LearningCurve`来展示如何使用拖放来分配一个`GameObject`组件：

1.  注释掉下面的代码行，我们使用`GameObject.Find()`来检索并将`Directional Light`对象分配给`DirectionLight`变量：

```cs
//DirectionLight = GameObject.Find("Directional Light"); 
```

1.  选择**Main Camera** GameObject，将**Directional Light**拖到**Learning Curve**组件的`Direction Light`字段中，然后点击播放：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_05_15.png)

图 5.15：将 Directional Light 拖到脚本属性的截图

1.  **Directional Light** GameObject 现在分配给了`DirectionLight`变量。没有涉及任何代码，因为 Unity 在内部分配了变量，而`LearningCurve`类没有发生变化。

在决定是使用拖放还是`GameObject.Find()`来分配变量时，理解一些重要的事情是很重要的。首先，`Find()`方法速度较慢，如果在多个脚本中多次调用该方法，可能会导致性能问题。其次，你需要确保你的 GameObject 在场景层次结构中都有唯一的名称；如果没有，可能会在有多个相同名称的对象或更改对象名称本身的情况下导致一些严重的错误。

# 总结

我们对类、结构和面向对象编程的探索标志着 C#基础知识的第一部分的结束。你已经学会了如何声明你的类和结构，这是你将来制作的每个应用程序或游戏的支架。你还确定了这两种对象在如何传递和访问上的差异，以及它们与面向对象编程的关系。最后，你通过继承、组合和多态来实现面向对象编程的原则。

识别相关的数据和操作，创建蓝图来赋予它们形状，并使用实例来构建交互，这是处理任何程序或游戏的坚实基础。再加上访问组件的能力，你就成为了一个 Unity 开发者的基础。

下一章将过渡到游戏开发的基础知识，并直接在 Unity 中编写对象行为脚本。我们将从详细说明简单的开放世界冒险游戏的要求开始，在场景中使用 GameObject，并最终完成一个为我们的角色准备好的白盒环境。

# 小测验 - 面向对象编程的一切

1.  哪个方法处理类内的初始化逻辑？

1.  作为值类型，结构是如何传递的？

1.  面向对象编程的主要原则是什么？

1.  你会使用哪个`GameObject`类方法来在调用类的同一对象上找到一个组件？

# 加入我们的 Discord！

与其他用户一起阅读本书，与 Unity/C#专家和 Harrison Ferrone 一起阅读。提出问题，为其他读者提供解决方案，通过*问我任何事*与作者交流，等等。

立即加入！

[`packt.link/csharpunity2021`](https://packt.link/csharpunity2021)

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/QR_Code_9781801813945.png)


# 第六章：在 Unity 中动手实践

创建游戏涉及的远不止在代码中模拟动作。设计、故事、环境、灯光和动画都在为玩家设定舞台中扮演着重要的角色。游戏首先是一种体验，单靠代码是无法实现的。

在过去的十年里，Unity 通过为程序员和非程序员带来先进的工具，将自己置于游戏开发的最前沿。动画和特效、音频、环境设计等等，所有这些都可以直接从 Unity 编辑器中获得，而不需要一行代码。我们将在定义我们的游戏的需求、环境和游戏机制时讨论这些话题。然而，首先，我们需要一个游戏设计的主题介绍。

游戏设计理论是一个庞大的研究领域，学习它的所有秘密可能需要整个职业生涯。然而，我们只会动手实践基础知识；其他一切都取决于你去探索！这一章将为我们打下基础，并涵盖以下话题：

+   游戏设计入门

+   建造一个关卡

+   灯光基础

+   在 Unity 中制作动画

# 游戏设计入门

在着手任何游戏项目之前，重要的是要有一个你想要构建的蓝图。有时，想法会在你的脑海中变得清晰明了，但一旦你开始创建角色类别或环境，事情似乎会偏离你最初的意图。这就是游戏设计允许你规划以下接触点的地方：

+   **概念**：游戏的大局观念和设计，包括它的类型和玩法风格。

+   **核心机制**：角色在游戏中可以进行的可玩特性或互动。常见的游戏机制包括跳跃、射击、解谜或驾驶。

+   **控制方案**：给玩家控制他们的角色、环境互动和其他可执行动作的按钮和/或键的地图。

+   **故事**：推动游戏的潜在叙事，创造玩家和他们所玩的游戏世界之间的共鸣和连接。

+   **艺术风格**：游戏的整体外观和感觉，从角色和菜单艺术到关卡和环境都保持一致。

+   **胜利和失败条件**：规定游戏如何获胜或失败的规则，通常包括潜在失败的目标或目标。

这些话题绝不是游戏设计所涉及的全部内容的详尽列表。然而，它们是开始构思所谓的游戏设计文件的好地方，这是你下一个任务！

## 游戏设计文件

谷歌游戏设计文件会得到一大堆模板、格式规则和内容指南，这可能会让新程序员准备放弃。事实上，设计文件是根据创建它们的团队或公司量身定制的，比互联网上的想象要容易得多。

一般来说，有三种类型的设计文档，如下：

+   **游戏设计文件**（**GDD**）：GDD 包含了游戏的玩法、氛围、故事以及它试图创造的体验。根据游戏的不同，这个文件可能只有几页长，也可能有几百页。

+   **技术设计文件**（**TDD**）：这个文件关注游戏的所有技术方面，从它将在哪种硬件上运行到类别和程序架构需要如何构建。和 GDD 一样，长度会根据项目的不同而变化。

+   **一页纸**：通常用于营销或推广情况，一页纸本质上是你游戏的快照。顾名思义，它应该只占据一页纸。

没有一种正确或错误的方式来格式化 GDD，所以这是一个让你的创造力茁壮成长的好地方。加入一些启发你的参考材料的图片；在布局上发挥创意——这是你定义你的愿景的地方。

我们将在本书的其余部分中一直致力于开发的游戏相当简单，不需要像 GDD 或 TDD 那样详细的东西。相反，我们将创建一个一页来跟踪我们的项目目标和一些背景信息。

## Hero Born 一页

为了使我们在前进时保持在正确的轨道上，我已经准备了一个简单的文档，概述了游戏原型的基础知识。在继续之前，请仔细阅读一遍，并尝试想象我们迄今学到的一些编程概念如何付诸实践：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_06_01.png)

图 6.1：Hero Born 一页文档

现在你已经对我们游戏的骨架有了一个高层次的了解，你可以开始建立一个原型关卡来容纳游戏体验。

# 建立一个关卡

在构建游戏关卡时，尝试从玩家的角度看事物总是一个好主意。你希望他们如何看待环境，如何与之交互，以及在其中行走时的感受？你实际上正在构建你的游戏存在的世界，所以要保持一致。

使用 Unity，你可以选择使用地形工具创建室外环境，用基本形状和几何图形来阻挡室内设置，或者两者的混合。你甚至可以从其他程序（如 Blender）导入 3D 模型，用作场景中的对象。

Unity 在[`docs.unity3d.com/Manual/script-Terrain.html`](https://docs.unity3d.com/Manual/script-Terrain.html)上有一个很好的地形工具介绍。如果你选择这条路线，Unity Asset Store 上还有一个名为 Terrain Toolkit 2017 的免费资产，可以在[`assetstore.unity.com/packages/tools/terrain/terrain-toolkit-2017-83490`](https://assetstore.unity.com/packages/tools/terrain/terrain-toolkit-2017-83490)找到。你也可以使用 Blender 等工具来创建你的游戏资产，可以在[`www.blender.org/features/modeling/`](https://www.blender.org/features/modeling/)找到。

对于*Hero Born*，我们将坚持简单的室内竞技场设置，这样可以轻松移动，但也有一些角落可以藏身。你将使用**primitives**——Unity 提供的基本对象形状——将所有这些组合在一起，因为它们在场景中创建、缩放和定位起来非常容易。

## 创建 primitives

看着你经常玩的游戏，你可能会想知道如何才能创建看起来如此逼真，以至于似乎可以伸手进屏幕抓住它们的模型和物体。幸运的是，Unity 有一组基本的 GameObject 可以供你选择，以便更快地创建原型。这些可能不会很华丽或高清，但当你在学习或开发团队中没有 3D 艺术家时，它们是救命稻草。

如果你打开 Unity，你可以进入**Hierarchy**面板，点击**+** | **3D Object**，你会看到所有可用的选项，但其中只有大约一半是 primitives 或常见形状，如下面的截图所示，用红色标出：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_06_02.png)

图 6.2：Unity Hierarchy 窗口，选择 Create 选项

其他 3D 对象选项，如**Terrain**，**Wind Zone**和**Tree**，对我们的需求来说有点太高级了，但如果你感兴趣，可以随意尝试它们。

你可以在[`docs.unity3d.com/Manual/CreatingEnvironments.html`](https://docs.unity3d.com/Manual/CreatingEnvironments.html)找到更多关于构建 Unity 环境的信息。

在我们跳得太远之前，当你脚下有地板时，四处走动通常更容易，所以让我们从以下步骤开始为我们的竞技场创建一个地面平面：

1.  在**Hierarchy**面板中，点击**+** | **3D Object** | **Plane**

1.  确保在**Hierarchy**选项卡中选择了新对象，在**Inspector**选项卡中将 GameObject 重命名为`Ground`

1.  在**Transform**下拉菜单中，将**Scale**更改为`3`，在**X**，**Y**和**Z**轴上：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_06_03.png)

图 6.3：Unity 编辑器中的地面平面

1.  如果你的场景中的光线看起来比之前的截图暗或不同，选择**层次**面板中的**定向光**，并将**定向光**组件的**强度**值设置为 1：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_06_04.png)

图 6.4：在检视器窗格中选择定向光对象

我们创建了一个平面 GameObject，并增加了它的大小，以便为我们未来的角色提供更多活动空间。这个平面将像一个受现实物理约束的 3D 对象一样，意味着其他物体不能穿过它。我们将在*第七章*“移动、摄像机控制和碰撞”中更多地讨论 Unity 物理系统及其工作原理。现在，我们需要开始以 3D 思维。

## 以 3D 思考

现在我们在场景中有了第一个对象，我们可以谈论 3D 空间——具体来说，一个对象的位置、旋转和比例在三维空间中的行为。如果你回想一下高中几何学，应该对具有*x*和*y*坐标系的图表很熟悉。要在图表上标出一个点，你必须有一个*x*值和一个*y*值。

Unity 支持 2D 和 3D 游戏开发，如果我们制作 2D 游戏，我们可以在这里结束解释。然而，在 Unity 编辑器中处理 3D 空间时，我们有一个额外的轴，称为*z*轴。*z*轴映射深度或透视，赋予了我们的空间和其中的物体 3D 的特性。

这可能一开始会让人困惑，但 Unity 有一些很好的视觉辅助工具，可以帮助你理清思路。在**场景**面板的右上方，你会看到一个几何图标，上面标有红色、绿色和蓝色的*x*、*y*和*z*轴。当在**层次**窗口中选择 GameObject 时，场景中的所有 GameObject 都会显示它们的轴箭头：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_06_05.png)

图 6.5：带有定向图标的场景视图

这将始终显示场景的当前方向和放置在其中的对象的方向。单击任何这些彩色轴将切换场景方向到所选轴。自己尝试一下，以便熟悉切换视角。

如果你在**检视器**窗格中查看**Ground**对象的**Transform**组件，你会看到位置、旋转和比例都由这三个轴决定。

位置决定了物体在场景中的放置位置，旋转决定了它的角度，而比例则决定了它的大小。这些值可以随时在**检视器**窗格或 C#脚本中进行更改：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_06_06.png)

图 6.6：在层次中选择的地面对象

现在，地面看起来有点无聊。让我们用材质来改变它。

## 材质

我们的地面平面现在并不是很有趣，但我们可以使用**材质**为关卡注入一些生气。材质控制着 GameObject 在场景中的渲染方式，这由材质的着色器决定。将**着色器**视为负责将光照和纹理数据组合成材质外观的部分。

每个 GameObject 都以默认的**材质**和**着色器**开始（在此处从**检视器**窗格中显示），将其颜色设置为标准白色：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_06_07.png)

图 6.7：对象上的默认材质

要改变对象的颜色，我们需要创建一个材质并将其拖到我们想要修改的对象上。记住，在 Unity 中一切都是对象——材质也不例外。材质可以在需要时重复使用在许多 GameObject 上，但对材质的任何更改也会传递到附加了该材质的任何对象上。如果我们在场景中有几个敌人对象，它们都使用一个将它们都设置为红色的材质，然后我们将基础材质颜色更改为蓝色，那么所有的敌人都会变成蓝色。

蓝色很吸引人；让我们将地面平面的颜色改成蓝色，并创建一个新的材质，将地面平面从沉闷的白色变成深沉而充满活力的蓝色：

1.  在**项目**面板中创建一个新文件夹，并将其命名为`Materials`。

1.  在**材质**文件夹中，右键单击**+** | **材质**，并将其命名为`Ground_Mat`。

1.  点击**反照率**属性旁边的颜色框，从弹出的颜色选择窗口中选择您的颜色，然后关闭它。

1.  从**项目**面板中拖动`Ground_Mat`对象，并将其放到**层次结构**面板中的`Ground`游戏对象上：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_06_08.png)

图 6.8：材质颜色选择器

您创建的新材质现在是一个项目资产。将`Ground_Mat`拖放到`Ground`游戏对象中改变了平面的颜色，这意味着对`Ground_Mat`的任何更改都将反映在`Ground`中。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_06_09.png)

图 6.9：更新颜色材质的地面平面

地面是我们的画布；然而，在 3D 空间中，它可以支持其表面上的其他 3D 对象。将由您来用有趣的障碍物来填充它，以供未来的玩家使用。

## 白盒设计

白盒设计是一个设计术语，用于使用占位符布置想法，通常是为了在以后用成品替换它们。在关卡设计中，白盒设计的做法是用原始游戏对象来阻挡环境，以便了解你想要它看起来的感觉。这是一个很好的开始方式，特别是在游戏原型阶段。

在深入研究 Unity 之前，我想先用简单的草图来描述我的关卡的基本布局和位置。这给了我们一点方向，并将有助于更快地布置我们的环境。

在下面的图中，您将能够看到我心目中的竞技场，中间有一个可以通过坡道进入的高台，每个角落都有小炮塔：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_06_10.png)

图 6.10：《英雄诞生》关卡竞技场的草图

不用担心如果你不是一个艺术家——我也不是。重要的是把你的想法写下来，巩固在你的脑海中，并在忙于在 Unity 中工作之前解决任何问题。

在全力以赴之前，您需要熟悉一些 Unity 编辑器的快捷方式，以使白盒设计更容易。

### 编辑器工具

当我们在*第一章*中讨论 Unity 界面时，我们略过了一些工具栏功能，现在我们需要重新讨论一下，以便知道如何有效地操作游戏对象。你可以在 Unity 编辑器的左上角找到它们：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_06_11.png)

图 6.11：Unity 编辑器工具栏

让我们分解一下在前面截图中从工具栏中可以使用的不同工具：

1.  **手**: 这允许您通过单击和拖动鼠标来平移和改变场景中的位置。

1.  **移动**：这让你通过拖动它们的相应箭头来沿着*x*、*y*和*z*轴移动物体。

1.  **旋转**：这让你通过转动或拖动其相应的标记来调整物体的旋转。

1.  **缩放**：这让你通过将其拖动到特定轴来修改物体的比例。

1.  **矩形变换**：这将移动、旋转和缩放工具功能合并为一个包。

1.  **变换**：这让你一次性访问物体的位置、旋转和缩放。

1.  **自定义编辑器工具**：这允许您访问您为编辑器构建的任何自定义工具。不用担心这个，因为它远远超出了我们的范围。如果您想了解更多，请参阅[`docs.unity3d.com/2020.1/Documentation/ScriptReference/EditorTools.EditorTool.html`](https://docs.unity3d.com/2020.1/Documentation/ScriptReference/EditorTools.EditorTool.html)中的文档。

你可以在**场景**面板中找到有关导航和定位游戏对象的更多信息，网址是[`docs.unity3d.com/Manual/PositioningGameObjects.html`](https://docs.unity3d.com/Manual/PositioningGameObjects.html)。值得注意的是，你可以使用**Transform**组件来移动、定位和缩放对象，就像我们在本章前面讨论的那样。

在场景中进行平移和导航可以使用类似的工具，尽管不是来自 Unity 编辑器本身：

+   要四处看，按住鼠标右键并拖动以使相机移动。

+   在使用相机时移动，继续按住鼠标右键，使用*W*、*A*、*S*和*D*键分别向前、向后、向左和向右移动。

+   按下*F*键，可以放大并聚焦在**层次**面板中已选择的游戏对象上。

这种场景导航更常被称为飞行模式，所以当我要求你专注于或导航到特定对象或视点时，请使用这些功能的组合。

在场景视图中移动有时可能是一项任务，但这一切都归结于反复练习。有关场景导航功能的更详细列表，请访问[`docs.unity3d.com/Manual/SceneViewNavigation.html`](https://docs.unity3d.com/Manual/SceneViewNavigation.html)。

尽管地面平面不会让我们的角色穿过它，但在这一点上我们仍然可以走到边缘。你的任务是将竞技场围起来，这样玩家就有了一个有限的移动区域。

### 英雄的试炼——安装石膏板

使用基本立方体和工具栏，使用**移动**、**旋转**和**缩放**工具将四面墙围绕主竞技场分隔开：

1.  在**层次**面板中，选择**+** | **3D 对象** | **立方体**来创建第一面墙，并将其命名为`Wall_01`。

1.  将其比例值设置为*x*轴 30，*y*轴 1.5，*z*轴 0.2。

请注意，平面的操作比对象大 10 倍——所以我们的长度为 3 的平面与长度为 30 的对象长度相同。

1.  在**层次**面板中选择`Wall_01`对象，切换到左上角的位置工具，并使用红色、绿色和蓝色箭头将墙定位在地面平面的边缘。

1.  重复*步骤 1-3*，直到你的区域周围有四面墙为止：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_06_12.png)

图 6.12：四面墙和地面平面的竞技场

从本章开始，我将给出一些墙的位置、旋转和缩放的基本值，但请随意尝试并发挥你的创造力。我希望你能尝试使用 Unity 编辑器工具，这样你就能更快地熟悉它们。

这有点施工，但竞技场开始成形了！在继续添加障碍和平台之前，你需要养成整理对象层次结构的习惯。我们将在下一节讨论这是如何工作的。

### 保持层次结构清晰

通常，我会把这种建议放在部分的结尾，但确保你的项目层次结构尽可能有条理是非常重要的，所以它需要有自己的小节。理想情况下，你会希望所有相关的游戏对象都在一个**父对象**下面。现在，这并不是一个风险，因为我们场景中只有几个对象；然而，在一个大型项目中，当数量增加到几百个时，你会很吃力。

保持层次结构清晰的最简单方法是将相关对象存储在一个父对象中，就像你在桌面上的文件夹中一样。我们的场景有一些需要组织的对象，Unity 通过让我们创建空的游戏对象来使这变得容易。空对象是一个完美的容器（或文件夹），用于保存相关的对象组，因为它不附带任何组件——它只是一个外壳。

让我们把我们的地面平面和四面墙都放在一个共同的空游戏对象下：

1.  在**层次结构**面板中选择**+** | **创建空对象**，并将新对象命名为`环境`

1.  将地面和四面墙拖放到**环境**中，使它们成为子对象

1.  选择**环境**空对象，并检查其**X**、**Y**和**Z**位置是否都设置为 0：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_06_13.png)

图 6.13：显示空 GameObject 父对象的层次结构面板

环境在**层次结构**选项卡中作为父对象存在，其子对象是竞技场对象。现在我们可以通过箭头图标展开或关闭**环境**对象的下拉列表，使**层次结构**面板变得不那么凌乱。

将**环境**对象的**X**、**Y**和**Z**位置设置为 0 是很重要的，因为子对象的位置现在是相对于父对象位置的。这带来了一个有趣的问题：我们设置的这些位置、旋转和缩放的原点是什么？答案是它们取决于我们使用的相对空间，而在 Unity 中，这些空间要么是**世界**空间，要么是**本地**空间：

+   **世界空间**使用场景中的一个固定原点作为所有 GameObject 的恒定参考。在 Unity 中，这个原点是 (0, 0, 0)，或者 *x*、*y* 和 *z* 轴上的 0。

+   **本地空间**使用对象的父级`Transform`组件作为其原点，从本质上改变了场景的透视。Unity 还将本地原点设置为 (0, 0, 0)。可以将其视为父级变换是宇宙的中心，其他所有东西都围绕它而轨道运行。

这两种方向在不同情况下都很有用，但是现在，在这一点上重置它会让每个人都从同一起跑线开始。

### 使用 Prefabs

Prefabs 是 Unity 中最强大的组件之一。它们不仅在关卡构建中很有用，而且在脚本编写中也很有用。将 Prefabs 视为 GameObject，可以保存并重复使用每个子对象、组件、C#脚本和属性设置。创建后，Prefab 就像一个类蓝图；在场景中使用的每个副本都是该 Prefab 的单独实例。因此，对基本 Prefab 的任何更改也会更改场景中所有活动实例。

竞技场看起来有点太简单，完全是敞开的，这使得它成为测试创建和编辑 Prefabs 的完美场所。由于我们希望在竞技场的每个角落都有四个相同的炮塔，它们是 Prefab 的完美案例，我们可以通过以下步骤创建：

我没有包含任何精确的屏障位置、旋转或缩放值，因为我希望你能亲自接触 Unity 编辑器工具。

未来，当你看到一个任务在你面前时，不包括特定的位置、旋转或缩放值，我希望你能通过实践学习。

1.  通过选择**+** | **创建空对象**在**环境**父对象内创建一个空的父对象，并将其命名为`屏障 _01`。

1.  使用**+** | **3D 对象** | **立方体**选择创建两个立方体，并将它们定位和缩放成 V 形的底座。

1.  创建两个更多的立方体原语，并将它们放在炮塔底座的两端：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_06_14.png)

图 6.14：由立方体组成的炮塔的屏幕截图

1.  在**项目**面板下的**资产**下创建一个名为`Prefabs`的新文件夹。然后，将**层次结构**面板中的**屏障 _01** GameObject 拖到项目视图中的**Prefabs**文件夹中：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_06_15.png)

图 6.15：Prefabs 文件夹中的屏障 Prefab

**屏障 _01** 及其所有子对象现在都是 Prefabs，这意味着我们可以通过从`Prefabs`文件夹中拖动副本或复制场景中的副本来重复使用它。**屏障 _01** 在**层次结构**选项卡中变成蓝色，表示其状态发生了变化，并在**检查器**选项卡中其名称下方添加了一排 Prefab 功能按钮：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_06_16.png)

图 6.16：在检查器窗格中突出显示的屏障 _01 Prefab

对原始预制件对象**Barrier_01**的任何编辑现在都会影响场景中的任何副本。由于我们需要第五个立方体来完成屏障，让我们更新并保存预制件，看看它的效果。

现在我们的炮塔中间有一个巨大的缺口，这对于保护我们的角色来说并不理想，所以让我们通过添加另一个立方体并应用更改来更新**Barrier_01**预制件：

1.  创建一个**立方体**原始对象，并将其放置在炮塔底座的交叉点处。

1.  新的**立方体**原始对象将在**层次结构**选项卡中以灰色标记，并在其名称旁边有一个小**+**图标。这意味着它还没有正式成为预制件的一部分！[](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_06_17.png)

图 6.17：层次结构窗口中标记的新预制件更新

1.  在**层次结构**面板中右键单击新的立方体原始对象，然后选择**添加** **游戏对象** | **应用于预制件'Barrier_01'**：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_06_18.png)

图 6.18：将预制件更改应用到基本预制件的选项

**Barrier_01**预制件现在已更新，包括新的立方体，并且整个预制件层次结构应该再次变为蓝色。现在你有一个看起来像前面截图的炮塔预制件，或者如果你感到有冒险精神，也可以是更有创意的东西。然而，我们希望这些在竞技场的每个角落都有。你的任务是添加它们！

现在我们有了一个可重复使用的屏障预制件，让我们构建出与本节开头的草图相匹配的关卡的其余部分：

1.  通过复制**Barrier_01**预制件三次，并将每个预制件放置在竞技场的不同角落。你可以通过将多个**Barrier_01**对象从**预制件**文件夹拖放到场景中，或者在**层次结构**中右键单击**Barrier_01**并选择复制来完成这个操作。

1.  在**环境**父对象内创建一个新的空游戏对象，并将其命名为`Raised_Platform`。

1.  创建一个**立方体**，并按下面的*图 6.19*所示进行缩放，形成一个平台。

1.  创建一个**平面**，并将其缩放成一个斜坡：

+   提示：围绕*x*或*y*轴旋转平面，可以创建一个倾斜的平面

+   然后，将其位置调整，使其连接平台和地面。

1.  通过在 Mac 上使用`Cmd` + `D`，或在 Windows 上使用`Ctrl` + `D`，复制斜坡对象。然后，重复旋转和定位步骤。

1.  重复上一步骤两次，直到总共有四个斜坡通向平台！[](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_06_19.png)

图 6.19：提升平台父游戏对象

你现在已经成功地创建了你的第一个游戏关卡的白盒模型！不过，不要太沉迷其中——我们只是刚刚开始。所有好的游戏都有玩家可以拾取或与之交互的物品。在接下来的挑战中，你的任务是创建一个生命值道具并将其制作成预制件。

#### 英雄的试炼-创建一个生命值道具

将我们在本章中学到的一切放在一起可能需要你花费几分钟的时间，但这是非常值得的。按照以下步骤创建拾取物品：

1.  通过选择**+** | **3D 对象** | **胶囊体**，创建一个名为`Health_Pickup`的**胶囊体**游戏对象。

1.  将*x*、*y*和*z*轴的比例设置为 0.3，然后切换到**移动**工具，并将其位置放置在你的屏障之一附近。

1.  为**Health_Pickup**对象创建并附加一个新的黄色**材质**。

1.  将**Health_Pickup**对象从**层次结构**面板拖动到**预制件**文件夹中。

参考以下截图，了解最终产品的样子：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_06_20.png)

图 6.20：场景中的拾取物品和屏障预制件

这就暂时结束了我们对关卡设计和布局的工作。接下来，你将在 Unity 中快速学习灯光，并且我们将在本章后面学习如何为我们的物品添加动画。

# 灯光基础知识

Unity 中的照明是一个广泛的主题，但可以归结为两类：实时和预计算。这两种类型的光都考虑了光的颜色和强度等属性，以及它在场景中的方向，这些都可以在**检视器**窗格中配置。区别在于 Unity 引擎计算光的方式。

*实时照明*是每帧计算的，这意味着任何通过其路径的物体都会投射出逼真的阴影，并且通常会像真实世界的光源一样行为。然而，这可能会显著减慢游戏速度，并且根据场景中的光源数量，会消耗大量的计算资源。另一方面，*预计算照明*将场景的照明存储在称为**光照贴图**的纹理中，然后将其应用或烘烤到场景中。虽然这节省了计算资源，但烘烤的照明是静态的。这意味着当物体在场景中移动时，它不会实时反应或改变。

还有一种混合类型的照明称为预计算实时全局照明，它弥合了实时和预计算过程之间的差距。这是一个高级的 Unity 特定主题，所以我们不会在本书中涵盖它，但可以随时查看[`docs.unity3d.com/Manual/GIIntro.html`](https://docs.unity3d.com/Manual/GIIntro.html)上的文档。

现在让我们看看如何在 Unity 场景中创建光对象。

## 创建光

默认情况下，每个场景都带有一个定向光组件，用作主要的照明源，但光可以像其他游戏对象一样在层次结构中创建。尽管控制光源的概念可能对您来说是新的，但它们是 Unity 中的对象，这意味着它们可以被定位，缩放和旋转以适应您的需求。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_06_21.png)

图 6.21：光照创建菜单选项

让我们看一些实时光对象及其性能的例子：

+   **定向光**非常适合模拟自然光，比如阳光。它们在场景中没有实际位置，但它们的光会像永远指向同一个方向一样照射到所有物体上。

+   **点光源**本质上是浮动的球体，从球体的中心点向所有方向发出光线。它们在场景中有定义的位置和强度。

+   **聚光灯**向特定方向发出光线，但它们受其角度的限制，并专注于场景的特定区域。可以将其视为现实世界中的聚光灯或泛光灯。

+   **区域光**的形状类似矩形，从矩形的一侧表面发出光线。

**反射探针**和**光探针组**超出了我们在*英雄诞生*中所需的范围；但是，如果您感兴趣，可以在[`docs.unity3d.com/Manual/ReflectionProbes.html`](https://docs.unity3d.com/Manual/ReflectionProbes.html)和[`docs.unity3d.com/Manual/LightProbes.html`](https://docs.unity3d.com/Manual/LightProbes.html)上了解更多。

像 Unity 中的所有游戏对象一样，光具有可以调整的属性，以赋予场景特定的氛围或主题。

## 光组件属性

以下截图显示了我们场景中定向光的**光**组件。所有这些属性都可以配置，以创建沉浸式环境，但我们需要注意的基本属性是**颜色**，**模式**和**强度**。这些属性控制光的色调，实时或计算效果以及一般强度：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_06_22.png)

图 6.22：检视器窗口中的光组件

与其他 Unity 组件一样，这些属性可以通过脚本和`Light`类访问，该类可以在[`docs.unity3d.com/ScriptReference/Light.html`](https://docs.unity3d.com/ScriptReference/Light.html)找到。

通过选择**+** | **Light** | **Point Light**来尝试一下，看看它对区域照明有什么影响。在调整了设置之后，通过在**Hierarchy**面板中右键单击它并选择**Delete**来删除点光源。

现在我们对如何点亮游戏场景有了更多了解，让我们把注意力转向添加一些动画！

# 在 Unity 中制作动画

在 Unity 中对对象进行动画处理可以从简单的旋转效果到复杂的角色移动和动作。你可以在代码中创建动画，也可以使用 Animation 和 Animator 窗口：

+   **动画**窗口是动画片段（称为片段）使用时间轴创建和管理的地方。对象属性沿着这个时间轴记录，然后播放回来创建动画效果。

+   **Animator**窗口使用叫做动画控制器的对象来管理这些片段及其转换。

你可以在[`docs.unity3d.com/Manual/AnimatorControllers.html`](https://docs.unity3d.com/Manual/AnimatorControllers.html)找到有关 Animator 窗口及其控制器的更多信息。

在片段中创建和操作目标对象将使你的游戏很快就动起来。对于我们在 Unity 动画中的短暂旅程，我们将在代码中和使用 Animator 创建相同的旋转效果。

## 在代码中创建动画

首先，我们将在代码中创建一个动画来旋转我们的生命物品拾取。由于所有的 GameObject 都有一个`Transform`组件，我们可以获取我们物品的`Transform`组件并无限旋转它。

要在代码中创建动画，需要执行以下步骤：

1.  在`Scripts`文件夹中创建一个新的脚本，命名为`ItemRotation`，并在 Visual Studio Code 中打开它。

1.  在新脚本的顶部和类内部，添加一个包含值`100`的`int`变量，名为`RotationSpeed`，和一个名为`ItemTransform`的`Transform`变量：

```cs
public int RotationSpeed = 100;
Transform ItemTransform; 
```

1.  在`Start()`方法体内，获取 GameObject 的`Transform`组件并将其分配给`ItemTransform`：

```cs
ItemTransform = this.GetComponent<Transform>(); 
```

1.  在`Update()`方法体内，调用`ItemTransform.Rotate`。这个`Transform`类方法接受三个轴，分别是*X*、*Y*和*Z*旋转，你想要执行。由于我们希望物品绕着末端旋转，我们将使用*x*轴，其他轴设置为`0`：

```cs
ItemTransform.Rotate(RotationSpeed * Time.deltaTime, 0, 0); 
```

您会注意到我们将`RotationSpeed`乘以一个叫做`Time.deltaTime`的东西。这是在 Unity 中标准化移动效果的方法，这样无论玩家的电脑运行速度快慢，效果都会看起来很平滑。一般来说，你应该总是将你的移动或旋转速度乘以`Time.deltaTime`。

1.  回到 Unity，在**项目**面板的`Prefabs`文件夹中选择`Health_Pickup`对象，滚动到**检视**窗口的底部。点击**添加组件**，搜索`ItemRotation`脚本，然后按`Enter`：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_06_23.png)

图 6.23：检视面板中的添加组件按钮

1.  现在我们的预制已经更新，移动**Main Camera**，这样你就可以看到`Health_Pickup`对象并点击播放！[](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_06_24.png)

图 6.24：焦点在生命物品上的相机截图

如你所见，生命物品现在围绕其*x*轴连续而平滑地旋转！现在你已经在代码中为物品添加了动画，我们将使用 Unity 内置的动画系统来复制我们的动画。

## 在 Unity 动画窗口中创建动画

任何你想要应用动画片段的 GameObject 都需要附加到一个设置了**动画控制器**的 Animator 组件上。如果在创建新片段时项目中没有控制器，Unity 将创建一个并保存在项目面板中，然后你可以用它来管理你的片段。你的下一个挑战是为拾取物品创建一个新的动画片段。

我们将开始通过创建一个新的动画片段来为`Health_Pickup`Prefab 添加动画，该动画将使对象无限循环旋转。要创建一个新的动画片段，我们需要执行以下步骤：

1.  导航到**窗口** | **动画** | **动画**，打开**动画**面板，并将**动画**选项卡拖放到**控制台**旁边。

1.  确保在**Hierarchy**中选择了`Health_Pickup`项目，然后在**Animation**面板中单击**Create**：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_06_25.png)

图 6.25：Unity 动画窗口的屏幕截图

1.  从下拉列表中创建一个名为`Animations`的新文件夹，然后将新片段命名为`Pickup_Spin`：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_06_26.png)

图 6.26：创建新动画窗口的屏幕截图

1.  确保新片段出现在**Animation**面板中：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_06_27.png)

图 6.27：动画窗口的屏幕截图，选择了一个片段

1.  由于我们没有任何**Animator**控制器，Unity 为我们在`Animation`文件夹中创建了一个名为**Health_Pickup**的控制器。选择**Health_Pickup**后，在**检查器**窗格中注意到，当我们创建了片段时，**Animator**组件也被添加到了 Prefab 中，但尚未使用**Health_Pickup**控制器正式保存到 Prefab 中。

1.  注意，**+**图标显示在**Animator**组件的左上角，这意味着它还没有成为**Health_Pickup**Prefab 的一部分：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_06_28.png)

图 6.28：检查器面板中的 Animator 组件

1.  选择右上角的三个垂直点图标，选择**添加组件** | **应用于 Prefab 'Health_Pickup'**：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_06_29.png)

图 6.29：应用于 Prefab 的新组件的屏幕截图

现在，您已经创建并添加了一个 Animator 组件到**Health_Pickup**Prefab，是时候开始记录一些动画帧了。当您想到动作片段时，就像电影一样，您可能会想到帧。当片段通过其帧移动时，动画会前进，产生移动的效果。在 Unity 中也是一样的；我们需要在不同的帧中记录我们的目标对象在不同的位置，这样 Unity 才能播放片段。

## 记录关键帧

现在我们有了一个可以使用的片段，您将在**Animation**窗口中看到一个空白的时间轴。基本上，当我们修改**Health_Pickup**Prefab 的*z*旋转，或者任何其他可以被动画化的属性时，时间轴将记录这些更改作为关键帧。然后 Unity 将这些关键帧组合成完整的动画，类似于模拟电影中的单个帧一起播放成为移动图片。

看一下以下的屏幕截图，并记住记录按钮和时间轴的位置：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_06_30.png)

图 6.30：动画窗口和关键帧时间轴的屏幕截图

现在，让我们让我们的物品旋转起来。对于旋转动画，我们希望**Health_Pickup**Prefab 在其*z*轴上每秒完成 360 度的旋转，这可以通过设置三个关键帧并让 Unity 处理其余部分来完成：

1.  在**Hierarchy**窗口中选择**Health_Pickup**对象，选择**添加属性** | **变换**，然后单击**旋转**旁边的**+**号：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_06_31.png)

图 6.31：添加用于动画的变换属性的屏幕截图

1.  单击记录按钮开始动画：

+   将光标放在时间轴上的**0:00**处，但将**Health_Pickup**Prefab 的*z*旋转保持在 0

+   将光标放在时间轴上的**0:30**处，并将*z*旋转设置为**180**

+   将光标放在时间轴上的**1:00**处，并将*z*旋转设置为**360**![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_06_32.png)

图 6.32：记录动画关键帧的屏幕截图

1.  单击记录按钮完成动画

1.  点击记录按钮右侧的播放按钮，查看动画循环

您会注意到我们的**Animator**动画覆盖了我们之前在代码中编写的动画。不用担心，这是预期的行为。您可以单击**Inspector**面板中任何组件右侧的小复选框来激活或停用它。如果停用**Animator**组件，**Health_Pickup**将再次使用我们的代码围绕*x*轴旋转。

**Health_Pickup**对象现在在*z*轴上每秒在 0、180 和 360 度之间旋转，创建循环旋转动画。如果您现在播放游戏，动画将无限期地运行，直到游戏停止：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_06_33.png)

图 6.33：在动画窗口中播放动画的屏幕截图

所有动画都有曲线，这些曲线决定了动画执行的特定属性。我们不会对这些做太多处理，但了解基础知识很重要。我们将在下一节中深入了解它们。

## 曲线和切线

除了对对象属性进行动画处理外，Unity 还允许我们使用动画曲线管理动画随时间的播放方式。到目前为止，我们一直处于**Dopesheet**模式，您可以在动画窗口底部进行更改。如果您点击**Curves**视图（如下屏幕截图所示），您将看到一个不同的图形，其中有重点放置在我们记录的关键帧的位置。

我们希望旋转动画是平滑的，也就是我们所说的线性，所以我们会保持一切不变。然而，可以通过拖动或调整曲线图上的点来加快、减慢或改变动画的运行过程中的任何时点的动画：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_06_34.png)

图 6.34：动画窗口中曲线时间轴的屏幕截图

虽然动画曲线处理了属性随时间的变化，但我们仍然需要一种方法来解决每次**Health_Pickup**动画重复时出现的停滞。为此，我们需要更改动画的切线，这会管理关键帧之间的平滑过渡。

这些选项可以通过在**Dopesheet**模式下右键单击时间轴上的任何关键帧来访问，您可以在这里看到：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_06_35.png)

图 6.35：关键帧平滑选项的屏幕截图

曲线和切线都是中级/高级内容，所以我们不会深入研究它们。如果您感兴趣，可以查看有关动画曲线和切线选项的文档：[`docs.unity3d.com/Manual/animeditor-AnimationCurves.html`](https://docs.unity3d.com/Manual/animeditor-AnimationCurves.html)。

如果您按照现在的旋转动画播放，物品完成完整旋转并开始新旋转之间会有轻微的暂停。您的任务是使其平滑，这是下一个挑战的主题。

让我们调整动画的第一帧和最后一帧的切线，使得旋转动画在重复时能无缝衔接：

1.  右键单击动画时间轴上第一个和最后一个关键帧的菱形图标，然后选择**Auto**：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_06_36.png)

图 6.36：更改关键帧平滑选项的屏幕截图

1.  如果您还没有这样做，请移动**Main Camera**，以便您可以看到`Health_Pickup`对象并点击播放：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_06_37.png)

图 6.37：最终平滑动画播放的屏幕截图

将第一个和最后一个关键帧的切线更改为**Auto**告诉 Unity 使它们的过渡平滑，从而消除动画循环时的突然停止/开始运动。

这就是本书中您需要的所有动画，但我鼓励您查看 Unity 在这个领域提供的全部工具。您的游戏将更具吸引力，您的玩家会感谢您！

# 总结

我们已经完成了另一个章节，其中有很多组成部分，对于那些对 Unity 还不太熟悉的人来说可能会有很多内容。

尽管这本书侧重于 C#语言及其在 Unity 中的实现，我们仍然需要花时间来了解游戏开发、文档和引擎的非脚本功能。虽然我们没有时间深入涉及照明和动画，但如果您打算继续创建 Unity 项目，了解它们是值得的。

在下一章中，我们将把重点转回到编程《英雄诞生》的核心机制，从设置可移动的玩家对象、控制摄像机，以及理解 Unity 的物理系统如何管理游戏世界开始。

# 弹出测验-基本 Unity 功能

1.  立方体、胶囊体和球体是什么类型的 GameObject 的例子？

1.  Unity 使用哪个轴来表示深度，从而赋予场景其 3D 外观？

1.  如何将 GameObject 转换为可重用的 Prefab？

1.  Unity 动画系统使用什么单位来记录对象动画？

# 加入我们的 Discord！

与其他用户、Unity/C#专家和 Harrison Ferrone 一起阅读本书。通过*问我任何事*会话与作者交流，提出问题，为其他读者提供解决方案，等等。

立即加入！

[`packt.link/csharpunity2021`](https://packt.link/csharpunity2021)

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/QR_Code_9781801813945.png)


# 第七章：移动、摄像机控制和碰撞

当玩家开始新游戏时，首先要做的事情之一就是尝试角色移动（当然，如果游戏有可移动的角色），以及摄像机控制。这不仅令人兴奋，而且让你的玩家知道他们可以期待什么样的游戏玩法。*Hero Born*中的角色将是一个可以使用`W`、`A`、`S`、`D`或箭头键分别移动和旋转的胶囊体对象。

我们将首先学习如何操作玩家对象的`Transform`组件，然后使用施加的力复制相同的玩家控制方案。这会产生更真实的移动效果。当我们移动玩家时，摄像机将从稍微在玩家后面和上方的位置跟随，这样在实现射击机制时瞄准会更容易。最后，我们将通过使用物品拾取预制件来探索 Unity 物理系统如何处理碰撞和物理交互。

所有这些将在可玩的水平上汇聚在一起，尽管目前还没有任何射击机制。这也将让我们初次尝试使用 C#来编写游戏功能，将以下主题联系在一起：

+   管理玩家移动

+   使用`Transform`组件移动玩家

+   编写摄像机行为

+   使用 Unity 物理系统。

# 管理玩家移动

当你决定如何最好地在虚拟世界中移动你的玩家角色时，请考虑什么看起来最真实，而不会因昂贵的计算而使游戏陷入困境。在大多数情况下，这在某种程度上是一种权衡，Unity 也不例外。

移动`GameObject`的三种最常见方式及其结果如下：

+   **选项 A**：使用`GameObject`的`Transform`组件进行移动和旋转。这是最简单的解决方案，也是我们首先要使用的解决方案。

+   **选项 B**：通过在`GameObject`上附加`Rigidbody`组件并在代码中施加力来使用真实世界的物理。`Rigidbody`组件为其附加的任何`GameObject`添加了模拟的真实世界物理。这种解决方案依赖于 Unity 的物理系统来进行繁重的工作，从而产生更真实的效果。我们将在本章后面更新我们的代码以使用这种方法，以便了解两种方法的感觉。

Unity 建议在移动或旋转`GameObject`时坚持一致的方法；要么操作对象的`Transform`组件，要么操作`Rigidbody`组件，但不能同时操作两者。

+   **选项 C**：附加一个现成的 Unity 组件或预制件，如 Character Controller 或 First Person Controller。这样可以减少样板代码，同时在加快原型设计时间的同时仍提供逼真的效果。

你可以在[`docs.unity3d.com/ScriptReference/CharacterController.html`](https://docs.unity3d.com/ScriptReference/CharacterController.html)找到有关 Character Controller 组件及其用途的更多信息。

第一人称控制器预制件可从标准资产包中获得，你可以从[`assetstore.unity.com/packages/essentials/asset-packs/standard-assets-32351`](https://assetstore.unity.com/packages/essentials/asset-packs/standard-assets-32351)下载。

由于你刚刚开始在 Unity 中进行玩家移动，你将在下一节开始使用玩家 Transform 组件，然后在本章后面转移到`Rigidbody`物理。

# 使用 Transform 组件移动玩家

我们希望为*Hero Born*创建一个第三人称冒险设置，因此我们将从一个可以通过键盘输入控制的胶囊体和一个可以跟随胶囊体移动的摄像机开始。尽管这两个 GameObject 将在游戏中一起工作，但我们将它们及其脚本分开以获得更好的控制。

在我们进行任何脚本编写之前，你需要在场景中添加一个玩家胶囊体，这是你的下一个任务。

我们可以在几个步骤中创建一个漂亮的玩家胶囊体：

1.  在**层次结构**面板中单击**+** | **3D 对象** | **胶囊**，然后命名为`Player`。

1.  选择`Player` GameObject，然后在**检视器**选项卡底部单击**添加组件**。搜索**Rigidbody**并按`Enter`添加。我们暂时不会使用这个组件，但是在开始时正确设置东西是很好的。

1.  展开**Rigidbody**组件底部的**约束**属性：

+   勾选**X**、**Y**和**Z**轴上的**冻结旋转**复选框，以便玩家除了通过我们稍后编写的代码之外不能以任何其他方式旋转：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_07_01.png)

图 7.1：刚体组件

1.  在**项目**面板中选择`Materials`文件夹，然后单击**创建** | **材质**。命名为`Player_Mat`。

1.  在**层次结构**中选择`Player_Mat`，然后在**检视器**中更改**反照率**属性为明亮绿色，并将材质拖动到**层次结构**面板中的**Player**对象上：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_07_02.png)

图 7.2：附加到胶囊的玩家材质

您已经使用胶囊原语、刚体组件和新的明亮绿色材质创建了**Player**对象。现在暂时不用担心刚体组件是什么——您现在需要知道的是它允许我们的胶囊与物理系统互动。在本章末尾讨论 Unity 的物理系统工作原理时，我们将详细介绍更多内容。在进行这些讨论之前，我们需要谈论 3D 空间中一个非常重要的主题：向量。

## 理解向量

现在我们有了一个玩家胶囊和摄像机设置，我们可以开始看如何使用其`Transform`组件移动和旋转 GameObject。`Translate`和`Rotate`方法是 Unity 提供的`Transform`类的一部分，每个方法都需要一个向量参数来执行其给定的功能。

在 Unity 中，向量用于在 2D 和 3D 空间中保存位置和方向数据，这就是为什么它们有两种类型——`Vector2`和`Vector3`。这些可以像我们见过的任何其他变量类型一样使用；它们只是保存不同的信息。由于我们的游戏是 3D 的，我们将使用`Vector3`对象，这意味着我们需要使用*x*、*y*和*z*值来构造它们。

对于 2D 向量，只需要*x*和*y*位置。请记住，您的 3D 场景中最新的方向将显示在我们在上一章*第六章*中讨论的右上方图形中：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_07_03.png)

图 7.3：Unity 编辑器中的向量图标

如果您想了解有关 Unity 中向量的更多信息，请参阅文档和脚本参考[`docs.unity3d.com/ScriptReference/Vector3.html`](https://docs.unity3d.com/ScriptReference/Vector3.html)。

例如，如果我们想要创建一个新的向量来保存场景原点的位置，我们可以使用以下代码：

```cs
Vector3 Origin = new Vector(0f, 0f, 0f); 
```

我们所做的只是创建了一个新的`Vector3`变量，并用* x *位置为`0`，* y *位置为`0`，* z *位置为`0`进行了初始化，按顺序排列。这将使玩家生成在游戏竞技场的原点。`Float`值可以带有或不带有小数点，但它们总是需要以小写`f`结尾。

我们还可以使用`Vector2`或`Vector3`类属性创建方向向量：

```cs
Vector3 ForwardDirection = Vector3.forward; 
```

`ForwardDirection`不是保存位置，而是引用我们场景中沿着 3D 空间中*z*轴的前进方向。使用 Vector3 方向的好处是，无论我们让玩家朝向哪个方向，我们的代码始终知道前进的方向。我们将在本章后面讨论使用向量，但现在只需习惯以*x*、*y*和*z*位置和方向来思考 3D 移动。

如果向量的概念对你来说是新的，不要担心——这是一个复杂的主题。Unity 的向量手册是一个很好的起点：[`docs.unity3d.com/Manual/VectorCookbook.html`](https://docs.unity3d.com/Manual/VectorCookbook.html)。

现在你对向量有了一些了解，你可以开始实现移动玩家胶囊的基本功能。为此，你需要从键盘上获取玩家输入，这是下一节的主题。

## 获取玩家输入

位置和方向本身是有用的，但没有玩家的输入，它们无法产生移动。这就是`Input`类的作用，它处理从按键和鼠标位置到加速度和陀螺仪数据的一切。

在*Hero Born*中，我们将使用`W`、`A`、`S`、`D`和箭头键进行移动，同时使用一个允许摄像机跟随玩家鼠标指向的脚本。为此，我们需要了解输入轴的工作原理。

首先，转到**Edit** | **Project Settings** | **Input Manager**，打开如下截图所示的**Input Manager**选项卡：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_07_04.png)

图 7.4：输入管理器窗口

Unity 2021 有一个新的输入系统，可以减少很多编码工作，使得在编辑器中设置输入动作更容易。由于这是一本编程书，我们将从头开始做事情。但是，如果你想了解新的输入系统是如何工作的，请查看这个很棒的教程：[`learn.unity.com/project/using-the-input-system-in-unity`](https://learn.unity.com/project/using-the-input-system-in-unity)。

你会看到一个很长的 Unity 默认输入已经配置好的列表，但让我们以**Horizontal**轴为例。你可以看到**Horizontal**输入轴的**Positive**和**Negative**按钮设置为`left`和`right`，而**Alt Negative**和**Alt Positive**按钮设置为`a`和`d`键。

每当从代码中查询输入轴时，它的值将在-1 和 1 之间。例如，当按下左箭头或`A`键时，水平轴会注册一个-1 的值。当释放这些键时，值返回到 0。同样，当使用右箭头或`D`键时，水平轴会注册一个值为 1 的值。这使我们能够使用一行代码捕获单个轴的四个不同输入，而不是为每个输入写出一个长长的`if-else`语句链。

捕获输入轴就像调用`Input.GetAxis()`并通过名称指定我们想要的轴一样，这就是我们将在接下来的部分中对`Horizontal`和`Vertical`输入所做的事情。作为一个附带的好处，Unity 应用了一个平滑滤波器，这使得输入与帧率无关。

默认输入可以按照需要进行修改，但你也可以通过增加输入管理器中的`Size`属性并重命名为你创建的副本来创建自定义轴。你必须增加`Size`属性才能添加自定义输入。

让我们开始使用 Unity 的输入系统和自定义的运动脚本让我们的玩家移动起来。

## 移动玩家

在让玩家移动之前，你需要将一个脚本附加到玩家胶囊上：

1.  在`Scripts`文件夹中创建一个新的 C#脚本，命名为`PlayerBehavior`，并将其拖放到**Hierarchy**面板中的**Player**胶囊上。

1.  添加以下代码并保存：

```cs
using System.Collections;
using System.Collections.Generic;
using UnityEngine; 
public class PlayerBehavior : MonoBehaviour 
{
    **// 1**
    public float MoveSpeed = 10f;
    public float RotateSpeed = 75f;
    **// 2**
    private float _vInput;
    private float _hInput;
    void Update()
    {
        **// 3**
        _vInput = Input.GetAxis("Vertical") * MoveSpeed;
        **// 4**
        _hInput = Input.GetAxis("Horizontal") * RotateSpeed;
        **// 5**
        this.transform.Translate(Vector3.forward * _vInput * 
        Time.deltaTime);
        **// 6**
        this.transform.Rotate(Vector3.up * _hInput * 
        Time.deltaTime);
    }
} 
```

使用`this`关键字是可选的。Visual Studio 2019 可能会建议你删除它以简化代码，但我更喜欢保留它以增加清晰度。当你有空的方法，比如`Start`，在这种情况下，删除它们是为了清晰度。

以下是上述代码的详细说明：

1.  声明两个公共变量用作乘数：

+   `MoveSpeed` 用于控制玩家前后移动的速度

+   `RotateSpeed` 用于控制玩家左右旋转的速度

1.  声明两个私有变量来保存玩家的输入；最初没有值：

+   `_vInput`将存储垂直轴输入。

+   `_hInput`将存储水平轴输入。

1.  `Input.GetAxis("Vertical")`检测上箭头、下箭头、`W`或`S`键被按下时，并将该值乘以`MoveSpeed`：

+   上箭头和`W`键返回值 1，这将使玩家向前（正方向）移动。

+   下箭头和`S`键返回-1，这会使玩家向负方向后退。

1.  `Input.GetAxis("Horizontal")`检测左箭头、右箭头、`A`和`D`键被按下时，并将该值乘以`RotateSpeed`：

+   右箭头和`D`键返回值 1，这将使胶囊向右旋转。

+   左箭头和`A`键返回-1，将胶囊向左旋转。

如果您想知道是否可能在一行上进行所有的移动计算，简单的答案是肯定的。然而，最好将您的代码分解，即使只有您自己在阅读它。

1.  使用`Translate`方法，它接受一个`Vector3`参数，来移动胶囊的 Transform 组件：

+   请记住，`this`关键字指定了当前脚本所附加的 GameObject，这种情况下是玩家胶囊。

+   `Vector3.forward`乘以`_vInput`和`Time.deltaTime`提供了胶囊需要沿着*z*轴向前/向后移动的方向和速度，速度是我们计算出来的。

+   `Time.deltaTime`将始终返回自游戏上一帧执行以来的秒数。它通常用于平滑值，这些值在`Update`方法中捕获或运行，而不是由设备的帧速率确定。

1.  使用`Rotate`方法来旋转相对于我们传递的向量的胶囊的 Transform 组件：

+   `Vector3.up`乘以`_hInput`和`Time.deltaTime`给我们想要的左/右旋转轴。

+   我们在这里使用`this`关键字和`Time.deltaTime`是出于同样的原因。

正如我们之前讨论的，使用`Translate`和`Rotate`函数中的方向向量只是其中一种方法。我们可以从我们的轴输入创建新的 Vector3 变量，并且像参数一样使用它们，同样容易。

当您点击播放时，您将能够使用上/下箭头键和`W`/`S`键向前/向后移动胶囊，并使用左/右箭头键和`A`/`D`键旋转或转向。

通过这几行代码，您已经设置了两个独立的控件，它们与帧速率无关，并且易于修改。然而，我们的摄像机不会随着胶囊的移动而移动，所以让我们在下一节中修复这个问题。

# 脚本化摄像机行为

让一个 GameObject 跟随另一个 GameObject 的最简单方法是将它们中的一个设置为另一个的子对象。当一个对象是另一个对象的子对象时，子对象的位置和旋转是相对于父对象的。这意味着任何子对象都会随着父对象的移动和旋转而移动和旋转。

然而，这种方法意味着发生在玩家胶囊上的任何移动或旋转也会影响摄像机，这并不是我们一定想要的。我们始终希望摄像机位于玩家的后方一定距离，并始终旋转以朝向玩家，无论发生什么。幸运的是，我们可以很容易地使用`Transform`类的方法相对于胶囊设置摄像机的位置和旋转。您的任务是在下一个挑战中编写摄像机逻辑。

由于我们希望摄像机行为与玩家移动完全分离，我们将控制摄像机相对于可以从“检视器”选项卡中设置的目标的位置：

1.  在`Scripts`文件夹中创建一个新的 C#脚本，命名为`CameraBehavior`，并将其拖放到“层次结构”面板中的“主摄像机”中。

1.  添加以下代码并保存：

```cs
using System.Collections;
using System.Collections.Generic;
using UnityEngine; 
public class CameraBehavior : MonoBehaviour 
{
    **// 1**
    public Vector3 CamOffset= new Vector3(0f, 1.2f, -2.6f);
    **// 2**
    private Transform _target;
    void Start()
    {
        **// 3**
        _target = GameObject.Find("Player").transform;
    }
    **// 4**
    void LateUpdate()
    {
        **// 5**
        this.transform.position = _target.TransformPoint(CamOffset);
        **// 6**
        this.transform.LookAt(_target);
    } 
} 
```

以下是前面代码的分解：

1.  声明一个`Vector3`变量来存储**主摄像机**和**玩家**胶囊之间的距离：

+   我们将能够在**检视器**中手动设置摄像头偏移的*x*、*y*和*z*位置，因为它是`public`的。

+   这些默认值是我认为看起来最好的，但请随意尝试。

1.  创建一个变量来保存玩家胶囊体的 Transform 信息：

+   这将使我们能够访问其位置、旋转和比例。

+   我们不希望任何其他脚本能够更改摄像头的目标，这就是为什么它是“私有”的原因。

1.  使用`GameObject.Find`按名称定位胶囊体并从场景中检索其 Transform 属性：

+   这意味着胶囊体的*x*、*y*和*z*位置在每一帧都会更新并存储在`_target`变量中。

+   在场景中查找对象是一项计算密集型的任务，因此最好的做法是只在`Start`方法中执行一次并存储引用。永远不要在`Update`方法中使用`GameObject.Find`，因为那样会不断地尝试找到你要找的对象，并有可能导致游戏崩溃。

1.  `LateUpdate`是一个`MonoBehavior`方法，就像`Start`或`Update`一样，在`Update`之后执行：

+   由于我们的`PlayerBehavior`脚本在其`Update`方法中移动胶囊体，我们希望`CameraBehavior`中的代码在移动发生后运行；这确保了`_target`具有最新的位置以供参考。

1.  为每一帧设置摄像头的位置为`_target.TransformPoint(CamOffset)`，从而产生以下效果：

+   `TransformPoint`方法计算并返回世界空间中的相对位置。

+   在这种情况下，它返回`target`（我们的胶囊体）的位置，偏移了*x*轴上的`0`，*y*轴上的`1.2`（将摄像头放在胶囊体上方），以及*z*轴上的`-2.6`（将摄像头略微放在胶囊体后方）。

1.  `LookAt`方法每一帧更新胶囊体的旋转，聚焦于我们传入的 Transform 参数，这种情况下是`_target`：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_07_05.png)

图 7.5：在播放模式下的胶囊体和跟随摄像头

这是很多内容，但如果你把它分解成按时间顺序的步骤，就会更容易处理：

1.  我们为摄像头创建了一个偏移位置。

1.  我们找到并存储了玩家胶囊体的位置。

1.  我们手动更新它的位置和旋转，以便它始终以固定距离跟随并注视玩家。

在使用提供特定平台功能的类方法时，始终记得将事情分解为最基本的步骤。这将帮助你在新的编程环境中保持头脑清醒。

虽然你编写的代码可以很好地管理玩家移动，但你可能已经注意到它在某些地方有点抖动。为了创建更平滑、更逼真的移动效果，你需要了解 Unity 物理系统的基础知识，接下来你将深入研究。

# 使用 Unity 物理系统

到目前为止，我们还没有讨论 Unity 引擎的工作原理，或者它如何在虚拟空间中创建逼真的交互和移动。我们将在本章的其余部分学习 Unity 物理系统的基础知识。

驱动 Unity 的 NVIDIA PhysX 引擎的两个主要组件如下：

+   **刚体**组件，允许游戏对象受到重力的影响，并添加**质量**和**阻力**等属性。如果刚体组件附加了碰撞器组件，它还可以受到施加的力的影响，从而产生更逼真的移动：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_07_06.png)

图 7.6：检视器窗格中的刚体组件

+   **碰撞器**组件，确定游戏对象如何以及何时进入和退出彼此的物理空间，或者简单地碰撞并弹开。虽然给定游戏对象只能附加一个刚体组件，但如果需要不同的形状或交互，可以附加多个碰撞器组件。这通常被称为复合碰撞器设置：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_07_07.png)

图 7.7：检视器窗格中的盒碰撞器组件

当两个 Collider 组件相互作用时，Rigidbody 属性决定了结果的互动。例如，如果一个 GameObject 的质量比另一个高，较轻的 GameObject 将以更大的力量弹开，就像在现实生活中一样。这两个组件负责 Unity 中的所有物理交互和模拟运动。

使用这些组件有一些注意事项，最好从 Unity 允许的运动类型的角度来理解：

+   *运动学*运动发生在一个 GameObject 上附加了 Rigidbody 组件，但它不会在场景中注册到物理系统。换句话说，运动学物体有物理交互，但不会对其做出反应，就像现实生活中的墙壁一样。这只在某些情况下使用，并且可以通过检查 Rigidbody 组件的**Is Kinematic**属性来启用。由于我们希望我们的胶囊与物理系统互动，我们不会使用这种运动。

+   *非运动学*运动是指通过施加力来移动或旋转 Rigidbody 组件，而不是手动更改 GameObject 的 Transform 属性。本节的目标是更新`PlayerBehavior`脚本以实现这种类型的运动。

我们现在的设置，也就是在使用 Rigidbody 组件与物理系统交互的同时操纵胶囊的 Transform 组件，是为了让你思考在 3D 空间中的移动和旋转。然而，这并不适用于生产，Unity 建议避免在代码中混合使用运动学和非运动学运动。

你的下一个任务是使用施加的力将当前的运动系统转换为更真实的运动体验。

## 运动中的 Rigidbody 组件

由于我们的玩家已经附加了 Rigidbody 组件，我们应该让物理引擎控制我们的运动，而不是手动平移和旋转 Transform。在应用力时有两个选项：

+   你可以直接使用 Rigidbody 类的方法，比如`AddForce`和`AddTorque`来分别移动和旋转一个物体。这种方法有它的缺点，通常需要额外的代码来补偿意外的物理行为，比如在碰撞期间产生的不需要的扭矩或施加的力。

+   或者，你可以使用其他 Rigidbody 类的方法，比如`MovePosition`和`MoveRotation`，它们仍然使用施加的力。

在下一节中，我们将采用第二种方法，让 Unity 为我们处理施加的物理效果，但如果你对手动施加力和扭矩到你的 GameObject 感兴趣，那么从这里开始：[`docs.unity3d.com/ScriptReference/Rigidbody.AddForce.html`](https://docs.unity3d.com/ScriptReference/Rigidbody.AddForce.html)。

这两种方法都会让玩家感觉更真实，并且允许我们在*第八章* *脚本游戏机制*中添加跳跃和冲刺机制。

如果你好奇一个没有 Rigidbody 组件的移动物体与装备了 Rigidbody 组件的环境物体互动时会发生什么，可以从玩家身上移除该组件并在竞技场周围跑一圈。恭喜你——你是一个鬼魂，可以穿墙走了！不过别忘了重新添加 Rigidbody 组件！

玩家胶囊已经附加了 Rigidbody 组件，这意味着你可以访问和修改它的属性。不过，首先你需要找到并存储该组件，这是你下一个挑战。

在修改之前，你需要访问并存储玩家胶囊上的 Rigidbody 组件。更新`PlayerBehavior`如下更改：

```cs
using System.Collections;
using System.Collections.Generic;
using UnityEngine;
public class PlayerBehavior : MonoBehaviour 
{
    public float MoveSpeed = 10f;
    public float RotateSpeed = 75f;
    private float _vInput;
    private float _hInput;
    **// 1**
    **private** **Rigidbody _rb;**
    **// 2**
    **void****Start****()**
    **{**
        **// 3**
        **_rb = GetComponent<Rigidbody>();**
    **}**
    void Update()
    {
      _vInput = Input.GetAxis("Vertical") * MoveSpeed;
      _hInput = Input.GetAxis("Horizontal") * RotateSpeed;
      **/***
      this.transform.Translate(Vector3.forward * _vInput * 
      Time.deltaTime);
      this.transform.Rotate(Vector3.up * _hInput * Time.deltaTime);
      ***/**
    }
} 
```

以下是前面代码的详细说明：

1.  添加一个私有变量，类型为`Rigidbody`，它将包含对胶囊 Rigidbody 组件的引用。

1.  `Start`方法在脚本在场景中初始化时触发，这发生在你点击播放时，并且应该在类的开始时使用任何需要设置的变量。

1.  `GetComponent`方法检查我们正在查找的组件类型（在本例中为`Rigidbody`）是否存在于脚本所附加的游戏对象上，并返回它：

+   如果组件没有附加到游戏对象上，该方法将返回`null`，但由于我们知道玩家上有一个组件，所以我们现在不用担心错误检查。

1.  在`Update`函数中注释掉`Transform`和`Rotate`方法的调用，这样我们就不会运行两种不同的玩家控制：

+   我们希望保留捕捉玩家输入的代码，以便以后仍然可以使用它。

您已经初始化并存储了玩家胶囊上的刚体组件，并注释掉了过时的`Transform`代码，为基于物理的运动做好了准备。角色现在已经准备好迎接下一个挑战，即添加力。

使用以下步骤移动和旋转刚体组件。在`Update`方法下面的`PlayerBehavior`中添加以下代码，然后保存文件：

```cs
// 1
void FixedUpdate()
{
    // 2
    Vector3 rotation = Vector3.up * _hInput;
    // 3
    Quaternion angleRot = Quaternion.Euler(rotation *
        Time.fixedDeltaTime);
    // 4
    _rb.MovePosition(this.transform.position +
        this.transform.forward * _vInput * Time.fixedDeltaTime);
     // 5
     _rb.MoveRotation(_rb.rotation * angleRot);
} 
```

以下是前面代码的详细说明：

1.  任何与物理或刚体相关的代码都应该放在`FixedUpdate`方法中，而不是`Update`或其他`MonoBehavior`方法中：

+   `FixedUpdate`是与帧率无关的，用于所有物理代码。

1.  创建一个新的`Vector3`变量来存储我们的左右旋转：

+   `Vector3.up * _hInput`是我们在上一个示例中使用`Rotate`方法的相同旋转向量。

1.  `Quaternion.Euler`接受一个`Vector3`参数并返回欧拉角中的旋转值：

+   我们需要一个`Quaternion`值而不是`Vector3`参数来使用`MoveRotation`方法。这只是一种转换为 Unity 所偏爱的旋转类型。

+   我们乘以`Time.fixedDeltaTime`的原因与我们在`Update`中使用`Time.deltaTime`的原因相同。

1.  在我们的`_rb`组件上调用`MovePosition`，它接受一个`Vector3`参数并相应地施加力：

+   使用的向量可以分解如下：胶囊在前进方向上的`Transform`位置，乘以垂直输入和`Time.fixedDeltaTime`。

+   刚体组件负责施加移动力以满足我们的向量参数。

1.  在`_rb`组件上调用`MoveRotation`方法，该方法还接受一个`Vector3`参数，并在幕后应用相应的力：

+   `angleRot`已经具有来自键盘的水平输入，因此我们所需要做的就是将当前的刚体旋转乘以`angleRot`，以获得相同的左右旋转。

请注意，对于非运动学游戏对象，`MovePosition`和`MoveRotation`的工作方式是不同的。您可以在刚体脚本参考中找到更多信息[`docs.unity3d.com/ScriptReference/Rigidbody.html`](https://docs.unity3d.com/ScriptReference/Rigidbody.html)。

如果现在点击播放，您将能够向前和向后移动，以及围绕*y*轴旋转。

施加的力产生的效果比转换和旋转 Transform 组件更强，因此您可能需要微调**Inspector**窗格中的`MoveSpeed`和`RotateSpeed`变量。现在，您已经重新创建了与之前相同类型的运动方案，只是使用了更真实的物理。

如果您跑上斜坡或从中央平台掉下来，您可能会看到玩家跳入空中，或者缓慢落到地面上。即使刚体组件设置为使用重力，它也相当弱。当我们实现跳跃机制时，我们将在下一章中处理将重力应用于玩家。现在，您的工作是熟悉 Unity 中 Collider 组件如何处理碰撞。

## 碰撞体和碰撞

碰撞体组件不仅允许 Unity 的物理系统识别游戏对象，还使交互和碰撞成为可能。将碰撞体想象成围绕游戏对象的无形力场；它们可以根据其设置被穿过或撞击，并且在不同的交互过程中会执行一系列方法。

Unity 的物理系统对 2D 和 3D 游戏有不同的工作方式，因此我们只会在本书中涵盖 3D 主题。如果你对制作 2D 游戏感兴趣，请参考[`docs.unity3d.com/Manual/class-Rigidbody2D.html`](https://docs.unity3d.com/Manual/class-Rigidbody2D.html)中的`Rigidbody2D`组件以及[`docs.unity3d.com/Manual/Collider2D.html`](https://docs.unity3d.com/Manual/Collider2D.html)中可用的 2D 碰撞体列表。

看一下**Health_Pickup**对象中**Capsule**的以下屏幕截图。如果你想更清楚地看到**胶囊碰撞体**，增加**半径**属性：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_07_08.png)

图 7.8：附加到拾取物品的胶囊碰撞体组件

对象周围的绿色形状是**胶囊碰撞体**，可以使用**中心**、**半径**和**高度**属性进行移动和缩放。

创建一个原始对象时，默认情况下，碰撞体与原始对象的形状匹配；因为我们创建了一个胶囊原始对象，它带有一个胶囊碰撞体。

碰撞体还有**盒形**、**球形**和**网格**形状，并且可以从**组件** | **物理**菜单或**检视器**中的**添加组件**按钮手动添加。

当碰撞体与其他组件接触时，它会发送所谓的消息或广播。任何添加了这些方法中的一个或多个的脚本都会在碰撞体发送消息时收到通知。这被称为*事件*，我们将在*第十四章* *旅程继续*中更详细地讨论这个主题。

例如，当两个带有碰撞体的游戏对象接触时，两个对象都会注册一个`OnCollisionEnter`事件，并附带对它们碰到的对象的引用。想象一下事件就像发送出的消息-如果你选择监听它，你会在这种情况下得到碰撞发生时的通知。这些信息可以用来跟踪各种交互事件，但最简单的是拾取物品。对于希望对象能够穿过其他对象的情况，可以使用碰撞触发器，我们将在下一节讨论。

可以在[`docs.unity3d.com/ScriptReference/Collider.html`](https://docs.unity3d.com/ScriptReference/Collider.html)的**消息**标题下找到碰撞体通知的完整列表。

只有当碰撞的对象属于特定的碰撞体、触发器和刚体组件的组合以及动力学或非动力学运动时，才会发送碰撞和触发事件。你可以在[`docs.unity3d.com/Manual/CollidersOverview.html`](https://docs.unity3d.com/Manual/CollidersOverview.html)的**碰撞动作矩阵**部分找到详细信息。

你之前创建的生命值物品是一个测试碰撞如何工作的完美场所。你将在下一个挑战中解决这个问题。

### 拾取物品

要使用碰撞逻辑更新`Health_Pickup`对象，需要执行以下操作：

1.  在`Scripts`文件夹中创建一个新的 C#脚本，命名为`ItemBehavior`，然后将其拖放到**层次结构**面板中的`Health_Pickup`对象上：

+   任何使用碰撞检测的脚本*必须*附加到带有碰撞体组件的游戏对象上，即使它是预制体的子对象。

1.  在**层次结构面板**中选择`Health_Pickup`，点击**检视器**右侧**项目行为（脚本）**组件旁边的三个垂直点图标，并选择**添加组件** | **应用于预制体'Health_Pickup'**：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_07_09.png)

图 7.9：将预制体更改应用到拾取物品

1.  将`ItemBehavior`中的默认代码替换为以下内容，然后保存：

```cs
using System.Collections;
using System.Collections.Generic;
using UnityEngine;
public class ItemBehavior : MonoBehaviour 
{
    **// 1**
    void OnCollisionEnter(Collision collision)
    {
        **// 2**
        if(collision.gameObject.name == "Player")
        {
            **// 3**
            Destroy(this.transform.gameObject);
            **// 4**
            Debug.Log("Item collected!");
        }
    }
} 
```

1.  点击播放并将玩家移动到胶囊体上以拾取它！

以下是前面代码的详细说明：

1.  当另一个对象碰到`Item`预制件时，Unity 会自动调用`OnCollisionEnter`方法：

+   `OnCollisionEnter`带有一个参数，用于存储撞到它的碰撞体的引用。

+   注意，碰撞的类型是`Collision`，而不是`Collider`。

1.  `Collision`类有一个名为`gameObject`的属性，它保存着与碰撞的游戏对象的碰撞体的引用：

+   我们可以使用这个属性来获取游戏对象的名称，并使用`if`语句来检查碰撞对象是否为玩家。

1.  如果碰撞对象是玩家，我们将调用`Destroy()`方法，该方法接受一个游戏对象参数并从场景中移除该对象。

1.  然后，它会在控制台上打印出一个简单的日志，说明我们已经收集了一个物品：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_07_10.png)

图 7.10：游戏对象被从场景中删除的示例

我们已经设置了`ItemBehavior`来监听与`Health_Pickup`对象预制件的任何碰撞。每当发生碰撞时，`ItemBehavior`使用`OnCollisionEnter()`并检查碰撞对象是否为玩家，如果是，则销毁（或收集）该物品。

如果你感到迷茫，可以将我们编写的碰撞代码视为`Health_Pickup`的通知接收器；每当它被击中时，代码就会触发。

还需要理解的是，我们可以创建一个类似的脚本，其中包含一个`OnCollisionEnter()`方法，将其附加到玩家上，然后检查碰撞对象是否为`Health_Pickup`预制件。碰撞逻辑取决于被碰撞对象的视角。

现在的问题是，如何设置碰撞而不会阻止碰撞对象相互穿过？我们将在下一节中解决这个问题。

## 使用碰撞体触发器

默认情况下，碰撞体的`isTrigger`属性未选中，这意味着物理系统将其视为实体对象，并在碰撞时触发碰撞事件。然而，在某些情况下，你可能希望能够通过碰撞体组件而不会停止你的游戏对象。这就是触发器的作用。勾选`isTrigger`后，游戏对象可以穿过它，但碰撞体将发送`OnTriggerEnter`、`OnTriggerExit`和`OnTriggerStay`通知。

当你需要检测游戏对象进入特定区域或通过特定点时，触发器是最有用的。我们将使用它来设置围绕我们敌人的区域；如果玩家走进触发区域，敌人将受到警报，并且稍后会攻击玩家。现在，你将专注于以下挑战中的敌人逻辑。

### 创建一个敌人

使用以下步骤创建一个敌人：

1.  在**层次结构**面板中使用**+** | **3D 对象** | **胶囊体**创建一个新的原语，并将其命名为`Enemy`。

1.  在`Materials`文件夹中，使用**+** | **Material**，命名为`Enemy_Mat`，并将其**Albedo**属性设置为鲜艳的红色：

+   将`Enemy_Mat`拖放到`Enemy`游戏对象中。

1.  选择`Enemy`，点击**添加组件**，搜索**Sphere Collider**，然后按`Enter`添加：

+   勾选**isTrigger**属性框，并将**Radius**更改为`8`：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_07_11.png)

图 7.11：附加到敌人对象的球体碰撞器组件

我们的新**Enemy**原语现在被一个 8 单位的球形触发半径所包围。每当另一个对象进入、停留在内部或离开该区域时，Unity 都会发送通知，我们可以捕获，就像我们处理碰撞时那样。你下一个挑战将是捕获该通知并在代码中对其进行操作。

要捕获触发器事件，需要按照以下步骤创建一个新的脚本：

1.  在`Scripts`文件夹中创建一个新的 C#脚本，命名为`EnemyBehavior`，然后将其拖放到**Enemy**中。

1.  添加以下代码并保存文件：

```cs
using System.Collections;
using System.Collections.Generic;
using UnityEngine;

public class EnemyBehavior : MonoBehaviour 
{
    **// 1**
    void OnTriggerEnter(Collider other)
    {
        **//2** 
        if(other.name == "Player")
        {
            Debug.Log("Player detected - attack!");
        }
    }
    **// 3**
    void OnTriggerExit(Collider other)
    {
        **// 4**
        if(other.name == "Player")
        {
            Debug.Log("Player out of range, resume patrol");
        }
    }
} 
```

1.  点击播放并走到敌人旁边以触发第一个通知，然后走开以触发第二个通知。

以下是前面代码的详细说明：

1.  当一个对象进入敌人球形碰撞体半径时，会触发`OnTriggerEnter()`：

+   与`OnCollisionEnter()`类似，`OnTriggerEnter()`存储了侵入对象的碰撞体组件的引用。

+   请注意，`other`是`Collider`类型，而不是`Collision`类型。

1.  我们可以使用`other`来访问碰撞游戏对象的名称，并使用`if`语句检查它是否是`Player`。如果是，控制台会打印出一个日志，说明`Player`处于危险区域。![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_07_12.png)

图 7.12：玩家和敌人对象之间的碰撞检测

1.  当一个对象离开敌人球形碰撞体半径时，会触发`OnTriggerExit()`：

+   这种方法还有一个引用到碰撞对象的碰撞体组件：

1.  我们使用另一个`if`语句通过名称检查离开球形碰撞体半径的对象：

+   如果是`Player`，我们会在控制台打印出另一个日志，说明他们是安全的！[](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_07_13.png)

图 7.13：碰撞触发器的示例

我们敌人的球形碰撞体在其区域被入侵时发送通知，而`EnemyBehavior`脚本捕获了其中的两个事件。每当玩家进入或离开碰撞半径时，控制台中会出现调试日志，以告诉我们代码正在运行。我们将在*第九章*“基本 AI 和敌人行为”中继续构建这一点。

Unity 使用了一种叫做组件设计模式的东西。不详细讨论，这是一种说对象（以及其类）应该负责其行为而不是将所有代码放在一个巨大文件中的花哨方式。这就是为什么我们在拾取物品和敌人上分别放置了单独的碰撞脚本，而不是让一个类处理所有事情。我们将在*第十四章*“旅程继续”中进一步讨论这个问题。

由于本书的目标是尽可能灌输良好的编程习惯，本章的最后一个任务是确保所有核心对象都转换为预制体。

### 英雄的试炼-所有的预制体！

为了让项目准备好迎接下一章，继续将`Player`和`Enemy`对象拖入**Prefabs**文件夹中。请记住，从现在开始，您总是需要右键单击**Hierarchy**面板中的预制体，然后选择**Added Component** | **Apply to Prefab**来巩固对这些游戏对象所做更改。

完成后，继续到*物理学总结*部分，确保在继续之前已经内化了我们所涵盖的所有主要主题。

## 物理学总结

在我们结束本章之前，这里有一些高层概念，以巩固我们到目前为止所学到的内容：

+   刚体组件为附加到其上的游戏对象添加了模拟真实世界的物理效果。

+   碰撞体组件与刚体组件以及对象进行交互：

+   如果碰撞体组件不是一个触发器，它就会作为一个实体对象。

+   如果碰撞体组件是一个触发器，它可以被穿过。

+   如果一个对象使用了刚体组件并且勾选了“Is Kinematic”，告诉物理系统忽略它，那么它就是*运动学*的。

+   如果一个对象使用了刚体组件并施加了力或扭矩来驱动其运动和旋转，那么它就是*非运动学*的。

+   碰撞体根据它们的交互发送通知。这些通知取决于碰撞体组件是否设置为触发器。通知可以从任一碰撞方接收，并且它们带有引用变量，保存了对象的碰撞信息。

请记住，像 Unity 物理系统这样广泛而复杂的主题不是一天就能学会的。将您在这里学到的知识作为一个跳板，让自己进入更复杂的主题！

# 总结

这结束了你第一次创建独立游戏行为并将它们整合成一个连贯但简单的游戏原型的经历。你已经使用向量和基本的向量数学来确定 3D 空间中的位置和角度，并且你熟悉玩家输入以及移动和旋转游戏对象的两种主要方法。你甚至深入了解了 Unity 物理系统的刚体物理、碰撞、触发器和事件通知。总的来说，《英雄诞生》有了一个很好的开端。

在下一章中，我们将开始解决更多的游戏机制，包括跳跃、冲刺、发射抛射物以及与环境的交互。这将让你更多地实践使用刚体组件的力量、收集玩家输入，并根据所需的情景执行逻辑。

# 小测验 - 玩家控制和物理

1.  你会使用什么数据类型来存储 3D 移动和旋转信息？

1.  Unity 内置的哪个组件允许你跟踪和修改玩家控制？

1.  哪个组件可以给游戏对象添加真实世界的物理效果？

1.  Unity 建议使用什么方法来执行游戏对象上与物理相关的代码？

# 加入我们的 Discord！

与其他用户、Unity/C#专家和 Harrison Ferrone 一起阅读本书。提出问题，为其他读者提供解决方案，通过“问我任何事”会话与作者交流等等。

立即加入！

[`packt.link/csharpunity2021`](https://packt.link/csharpunity2021)

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/QR_Code_9781801813945.png)
