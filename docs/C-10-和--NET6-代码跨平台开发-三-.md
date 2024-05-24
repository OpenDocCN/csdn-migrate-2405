# C#10 和 .NET6 代码跨平台开发（三）

> 原文：[`zh.annas-archive.org/md5/B053DEF9CB8C4C14E67E73C1EC2319CF`](https://zh.annas-archive.org/md5/B053DEF9CB8C4C14E67E73C1EC2319CF)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：使用面向对象编程构建自己的类型

本章是关于使用**面向对象编程**（**OOP**）创建自己的类型。你将了解类型可以拥有的所有不同类别的成员，包括存储数据的字段和执行操作的方法。你将使用 OOP 概念，如聚合和封装。你还将了解语言特性，如元组语法支持、输出变量、推断元组名称和默认文字。

本章将涵盖以下主题：

+   谈论 OOP

+   构建类库

+   使用字段存储数据

+   编写和调用方法

+   使用属性和索引器控制访问

+   使用对象进行模式匹配

+   使用记录

# 谈论 OOP

现实世界中的对象是某个事物，比如汽车或人，而在编程中，对象通常代表现实世界中的某个事物，比如产品或银行账户，但也可能是更抽象的东西。

在 C#中，我们使用`class`（大多数情况下）或`struct`（有时）C#关键字来定义对象类型。你将在*第六章*，*实现接口和继承类*中了解类和结构之间的区别。你可以将类型视为对象的蓝图或模板。

OOP 的概念简要描述如下：

+   **封装**是与对象相关的数据和操作的组合。例如，`BankAccount`类型可能具有数据，如`Balance`和`AccountName`，以及操作，如`Deposit`和`Withdraw`。在封装时，你通常希望控制可以访问这些操作和数据的内容，例如，限制从外部访问或修改对象的内部状态。

+   **组合**是关于对象由什么构成的。例如，`Car`由不同的部分组成，例如四个`Wheel`对象，几个`Seat`对象和一个`Engine`。

+   **聚合**是关于可以与对象结合的内容。例如，`Person`不是`Car`对象的一部分，但他们可以坐在驾驶员的`Seat`上，然后成为汽车的`Driver`——两个独立的对象聚合在一起形成一个新的组件。

+   **继承**是通过让**子类**从**基类**或**超类**派生来重用代码。基类中的所有功能都被继承并可在**派生**类中使用。例如，基类或超类`Exception`具有一些成员，这些成员在所有异常中具有相同的实现，而子类或派生类`SqlException`继承了这些成员，并且具有仅与 SQL 数据库异常发生时相关的额外成员，例如数据库连接的属性。

+   **抽象**是捕捉对象核心思想并忽略细节或具体内容的概念。C#有`abstract`关键字正式化这一概念。如果一个类没有明确地**抽象**，那么它可以被描述为**具体**的。基类或超类通常是抽象的，例如，超类`Stream`是抽象的，而它的子类，如`FileStream`和`MemoryStream`，是具体的。只有具体类可以用来创建对象；抽象类只能用作其他类的基类，因为它们缺少一些实现。抽象是一个棘手的平衡。如果你使一个类更抽象，更多的类将能够继承自它，但同时，可共享的功能将更少。

+   **多态性**是指允许派生类覆盖继承的操作以提供自定义行为。

# 构建类库

类库程序集将类型组合成易于部署的单元（DLL 文件）。除了学习单元测试时，你只创建了控制台应用程序或.NET Interactive 笔记本以包含你的代码。为了使你编写的代码可跨多个项目重用，你应该将其放入类库程序集中，就像 Microsoft 所做的那样。

## 创建类库

第一个任务是创建一个可重用的.NET 类库：

1.  使用你喜欢的编码工具创建一个新的类库，如下列表所定义：

    1.  项目模板：**类库** / `classlib`

    1.  工作区/解决方案文件和文件夹：`Chapter05`

    1.  项目文件和文件夹：`PacktLibrary`

1.  打开`PacktLibrary.csproj`文件，并注意默认情况下类库面向.NET 6，因此只能与其他.NET 6 兼容的程序集一起工作，如下面的标记所示：

    ```cs
    <Project Sdk="Microsoft.NET.Sdk">
      <PropertyGroup>
        <TargetFramework>net6.0</TargetFramework>
        <Nullable>enable</Nullable>
        <ImplicitUsings>enable</ImplicitUsings>
      </PropertyGroup>
    </Project> 
    ```

1.  将框架修改为目标.NET Standard 2.0，并删除启用可空引用类型和隐式 using 的条目，如下面的标记中突出显示的那样：

    ```cs
    <Project Sdk="Microsoft.NET.Sdk">
      <PropertyGroup>
     **<TargetFramework>netstandard****2.0****</TargetFramework>**
      </PropertyGroup>
    </Project> 
    ```

1.  保存并关闭文件。

1.  删除名为`Class1.cs`的文件。

1.  编译项目以便其他项目稍后可以引用它：

    1.  在 Visual Studio Code 中，输入以下命令：`dotnet build`。

    1.  在 Visual Studio 中，导航到**生成** | **生成 PacktLibrary**。

**最佳实践**：为了使用最新的 C#语言和.NET 平台特性，将类型放入.NET 6 类库中。为了支持如.NET Core、.NET Framework 和 Xamarin 等遗留.NET 平台，将可能重用的类型放入.NET Standard 2.0 类库中。

## 在命名空间中定义一个类

接下来的任务是定义一个代表人的类：

1.  添加一个名为`Person.cs`的新类文件。

1.  静态导入`System.Console`。

1.  将命名空间设置为`Packt.Shared`。

**良好实践**：我们这样做是因为将你的类放在逻辑命名的命名空间中很重要。更好的命名空间名称应该是特定领域的，例如，`System.Numerics`用于与高级数字相关的类型。在这种情况下，我们将创建的类型是`Person`，`BankAccount`和`WondersOfTheWorld`，它们没有典型的领域，因此我们将使用更通用的`Packt.Shared`。

你的类文件现在应该看起来像以下代码：

```cs
using System;
using static System.Console;
namespace Packt.Shared
{
  public class Person
  {
  }
} 
```

注意，C#关键字`public`在类之前应用。这个关键字是**访问修饰符**，它允许任何其他代码访问这个类。

如果你没有明确应用`public`关键字，那么它将只能在定义它的程序集中访问。这是因为类的默认访问修饰符是`internal`。我们需要这个类在程序集外部可访问，因此必须确保它是`public`。

### 简化命名空间声明

如果你针对的是.NET 6.0，因此使用 C# 10 或更高版本，你可以用分号结束命名空间声明并删除大括号，如下所示：

```cs
using System; 
namespace Packt.Shared; // the class in this file is in this namespace
public class Person
{
} 
```

这被称为文件范围的命名空间声明。每个文件只能有一个文件范围的命名空间。我们将在本章后面针对.NET 6.0 的类库中使用这个。

**良好实践**：将你创建的每个类型放在其自己的文件中，以便你可以使用文件范围的命名空间声明。

## 理解成员

这种类型还没有任何成员封装在其中。我们将在接下来的页面上创建一些。成员可以是字段、方法或两者的特殊版本。你将在这里找到它们的描述：

+   **字段**用于存储数据。还有三种特殊类别的字段，如下所示：

    +   **常量**：数据永不改变。编译器会将数据直接复制到任何读取它的代码中。

    +   **只读**：类实例化后数据不能改变，但数据可以在实例化时计算或从外部源加载。

    +   **事件**：数据引用一个或多个你希望在某些事情发生时执行的方法，例如点击按钮或响应来自其他代码的请求。事件将在*第六章*，*实现接口和继承类*中介绍。

+   **方法**用于执行语句。你在学习*第四章*，*编写、调试和测试函数*中的函数时看到了一些例子。还有四种特殊类别的方法：

    +   **构造函数**：当你使用`new`关键字分配内存以实例化类时执行语句。

    +   **属性**：当你获取或设置数据时执行语句。数据通常存储在字段中，但也可能存储在外部或在运行时计算。属性是封装字段的首选方式，除非需要暴露字段的内存地址。

    +   **索引器**：当你使用"数组"语法`[]`获取或设置数据时，执行这些语句。

    +   **运算符**：当你在你的类型的操作数上使用运算符如`+`和`/`时，执行这些语句。

## 实例化一个类

在本节中，我们将创建一个`Person`类的实例。

### 引用程序集

在我们能够实例化一个类之前，我们需要从另一个项目引用包含该类的程序集。我们将在控制台应用程序中使用该类：

1.  使用你偏好的编码工具，在`Chapter05`工作区/解决方案中添加一个名为`PeopleApp`的新控制台应用程序。

1.  如果你使用的是 Visual Studio Code：

    1.  选择`PeopleApp`作为活动 OmniSharp 项目。当你看到弹出警告消息说缺少必需资产时，点击**是**以添加它们。

    1.  编辑`PeopleApp.csproj`以添加对`PacktLibrary`的项目引用，如下所示突出显示：

        ```cs
        <Project Sdk="Microsoft.NET.Sdk">
          <PropertyGroup>
            <OutputType>Exe</OutputType>
            <TargetFramework>net6.0</TargetFramework>
            <Nullable>enable</Nullable>
            <ImplicitUsings>enable</ImplicitUsings>
          </PropertyGroup>
         **<ItemGroup>**
         **<ProjectReference Include=****"../PacktLibrary/PacktLibrary.csproj"** **/>**
         **</ItemGroup>**
        </Project> 
        ```

    1.  在终端中，输入命令编译`PeopleApp`项目及其依赖项`PacktLibrary`项目，如下所示：

        ```cs
        dotnet build 
        ```

1.  如果你使用的是 Visual Studio：

    1.  将解决方案的启动项目设置为当前选择。

    1.  **解决方案资源管理器**中，选择`PeopleApp`项目，导航至**项目** | **添加项目引用…**，勾选复选框选择`PacktLibrary`项目，然后点击**确定**。

    1.  导航至**生成** | **生成 PeopleApp**。

## 导入命名空间以使用类型

现在，我们准备好编写与`Person`类交互的语句了：

1.  在`PeopleApp`项目/文件夹中，打开`Program.cs`。

1.  在`Program.cs`文件顶部，删除注释，并添加语句以导入我们`Person`类的命名空间并静态导入`Console`类，如下所示：

    ```cs
    using Packt.Shared;
    using static System.Console; 
    ```

1.  在`Program.cs`中，添加以下语句：

    +   创建`Person`类型的实例。

    +   使用自身的文本描述输出实例。

    `new`关键字为对象分配内存并初始化任何内部数据。我们可以使用`var`代替`Person`类名，但随后我们需要在`new`关键字后指定`Person`，如下所示：

    ```cs
    // var bob = new Person(); // C# 1.0 or later
    Person bob = new(); // C# 9.0 or later
    WriteLine(bob.ToString()); 
    ```

    你可能会疑惑，“为什么`bob`变量有一个名为`ToString`的方法？`Person`类是空的！”别担心，我们即将揭晓！

1.  运行代码并查看结果，如下所示：

    ```cs
    Packt.Shared.Person 
    ```

## 理解对象

尽管我们的`Person`类没有明确选择继承自某个类型，但所有类型最终都直接或间接继承自一个名为`System.Object`的特殊类型。

`System.Object`类型中`ToString`方法的实现仅输出完整的命名空间和类型名称。

回到原始的`Person`类，我们本可以明确告诉编译器`Person`继承自`System.Object`类型，如下所示：

```cs
public class Person : System.Object 
```

当类 B 继承自类 A 时，我们称 A 为基类或父类，B 为派生类或子类。在这种情况下，`System.Object`是基类或父类，`Person`是派生类或子类。

你也可以使用 C#别名关键字`object`，如下列代码所示：

```cs
public class Person : object 
```

### 继承自 System.Object

让我们使我们的类显式继承自`object`，然后回顾所有对象拥有的成员：

1.  修改你的`Person`类，使其显式继承自`object`。

1.  点击`object`关键字内部，按 F12，或者右键点击`object`关键字并选择**转到定义**。

你将看到微软定义的`System.Object`类型及其成员。这方面的细节你目前无需了解，但请注意它有一个名为`ToString`的方法，如*图 5.1*所示：

![图形用户界面，文本，应用程序，电子邮件 描述自动生成](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_05_01.png)

**图 5.1**：System.Object 类定义

**最佳实践**：假设其他程序员知道，如果未指定继承，则类将继承自`System.Object`。

# 在字段中存储数据

在本节中，我们将定义类中的一系列字段，用于存储有关个人的信息。

## 定义字段

假设我们已决定一个人由姓名和出生日期组成。我们将把这两个值封装在一个人内部，并且这些值对外可见。

在`Person`类内部，编写语句以声明两个公共字段，用于存储一个人的姓名和出生日期，如下列代码所示：

```cs
public class Person : object
{
  // fields
  public string Name;
  public DateTime DateOfBirth;
} 
```

字段可以使用任何类型，包括数组和集合，如列表和字典。如果你需要在单个命名字段中存储多个值，这些类型就会派上用场。在本例中，一个人只有一个名字和一个出生日期。

## 理解访问修饰符

封装的一部分是选择成员的可见性。

请注意，正如我们对类所做的那样，我们明确地对这些字段应用了`public`关键字。如果我们没有这样做，那么它们将默认为`private`，这意味着它们只能在类内部访问。

有四个访问修饰符关键字，以及两种访问修饰符关键字的组合，你可以将其应用于类成员，如字段或方法，如下表所示：

| 访问修饰符 | 描述 |
| --- | --- |
| `private` | 成员仅在类型内部可访问。这是默认设置。 |
| `internal` | 成员在类型内部及同一程序集中的任何类型均可访问。 |
| `protected` | 成员在类型内部及其任何派生类型中均可访问。 |
| `public` | 成员在任何地方均可访问。 |
| `internal``protected` | 成员在类型内部、同一程序集中的任何类型以及任何派生类型中均可访问。相当于一个虚构的访问修饰符，名为`internal_or_protected`。 |
| `private``protected` | 成员在类型内部、任何派生类型以及同一程序集中均可访问。相当于一个虚构的访问修饰符，名为`internal_and_protected`。这种组合仅在 C# 7.2 或更高版本中可用。 |

**良好实践**：明确地对所有类型成员应用一个访问修饰符，即使你想要使用成员的隐式访问修饰符，即`private`。此外，字段通常应该是`private`或`protected`，然后你应该创建`public`属性来获取或设置字段值。这是因为它控制访问。你将在本章后面这样做。

## 设置和输出字段值

现在我们将在你的代码中使用这些字段：

1.  在`Program.cs`顶部，确保导入了`System`命名空间。我们需要这样做才能使用`DateTime`类型。

1.  实例化`bob`后，添加语句以设置他的姓名和出生日期，然后以美观的格式输出这些字段，如下所示：

    ```cs
    bob.Name = "Bob Smith";
    bob.DateOfBirth = new DateTime(1965, 12, 22); // C# 1.0 or later
    WriteLine(format: "{0} was born on {1:dddd, d MMMM yyyy}", 
      arg0: bob.Name,
      arg1: bob.DateOfBirth); 
    ```

    我们本可以使用字符串插值，但对于长字符串，它会在多行上换行，这在印刷书籍中可能更难以阅读。在本书的代码示例中，请记住`{0}`是`arg0`的占位符，依此类推。

1.  运行代码并查看结果，如下所示：

    ```cs
    Bob Smith was born on Wednesday, 22 December 1965 
    ```

    根据你的地区设置（即语言和文化），你的输出可能看起来不同。

    `arg1`的格式代码由几个部分组成。`dddd`表示星期几的名称。`d`表示月份中的日期号。`MMMM`表示月份的名称。小写的`m`用于时间值中的分钟。`yyyy`表示年份的完整数字。`yy`表示两位数的年份。

    你还可以使用花括号的简写**对象初始化器**语法初始化字段。让我们看看如何操作。

1.  在现有代码下方添加语句以创建另一个名为 Alice 的新人。注意在向控制台输出她的出生日期时使用的不同格式代码，如下所示：

    ```cs
    Person alice = new()
    {
      Name = "Alice Jones",
      DateOfBirth = new(1998, 3, 7) // C# 9.0 or later
    };
    WriteLine(format: "{0} was born on {1:dd MMM yy}",
      arg0: alice.Name,
      arg1: alice.DateOfBirth); 
    ```

1.  运行代码并查看结果，如下所示：

    ```cs
    Alice Jones was born on 07 Mar 98 
    ```

## 使用枚举类型存储值

有时，一个值需要是有限选项集中的一个。例如，世界上有七大古代奇迹，一个人可能有一个最喜欢的。在其他时候，一个值需要是有限选项集的组合。例如，一个人可能有一个他们想要访问的古代世界奇迹的遗愿清单。我们能够通过定义一个枚举类型来存储这些数据。

枚举类型是一种非常高效的方式来存储一个或多个选择，因为它内部使用整数值与`string`描述的查找表相结合：

1.  向`PacktLibrary`项目添加一个名为`WondersOfTheAncientWorld.cs`的新文件。

1.  修改`WondersOfTheAncientWorld.cs`文件，如下所示：

    ```cs
    namespace Packt.Shared
    {
      public enum WondersOfTheAncientWorld
      {
        GreatPyramidOfGiza,
        HangingGardensOfBabylon,
        StatueOfZeusAtOlympia,
        TempleOfArtemisAtEphesus,
        MausoleumAtHalicarnassus,
        ColossusOfRhodes,
        LighthouseOfAlexandria
      }
    } 
    ```

    **良好实践**：如果你在.NET Interactive 笔记本中编写代码，那么包含`enum`的代码单元格必须位于定义`Person`类的代码单元格之上。

1.  在`Person`类中，向字段列表添加以下语句：

    ```cs
    public WondersOfTheAncientWorld FavoriteAncientWonder; 
    ```

1.  在`Program.cs`中，添加以下语句：

    ```cs
    bob.FavoriteAncientWonder = WondersOfTheAncientWorld.StatueOfZeusAtOlympia;
    WriteLine(
      format: "{0}'s favorite wonder is {1}. Its integer is {2}.",
      arg0: bob.Name,
      arg1: bob.FavoriteAncientWonder,
      arg2: (int)bob.FavoriteAncientWonder); 
    ```

1.  运行代码并查看结果，如下所示：

    ```cs
    Bob Smith's favorite wonder is StatueOfZeusAtOlympia. Its integer is 2. 
    ```

`enum`值内部作为`int`存储以提高效率。`int`值从`0`开始自动分配，因此我们的`enum`中的第三个世界奇迹的值为`2`。你可以分配`enum`中未列出的`int`值。如果找不到匹配项，它们将输出为`int`值而不是名称。

## 使用枚举类型存储多个值

对于愿望清单，我们可以创建一个`enum`实例的数组或集合，本章后面将解释集合，但有一个更好的方法。我们可以使用`enum`**标志**将多个选择合并为一个值：

1.  通过为`enum`添加`[System.Flags]`属性进行修改，并为每个代表不同位列的奇迹显式设置一个`byte`值，如下列代码中突出显示的那样：

    ```cs
    namespace Packt.Shared
    {
     **[****System.Flags****]**
      public enum WondersOfTheAncientWorld **:** **byte**
      {
        **None                     =** **0b****_0000_0000,** **// i.e. 0**
        GreatPyramidOfGiza       **=** **0b****_0000_0001,** **// i.e. 1**
        HangingGardensOfBabylon  **=** **0b****_0000_0010,** **// i.e. 2**
        StatueOfZeusAtOlympia    **=** **0b****_0000_0100,** **// i.e. 4**
        TempleOfArtemisAtEphesus **=** **0b****_0000_1000,** **// i.e. 8**
        MausoleumAtHalicarnassus **=** **0b****_0001_0000,** **// i.e. 16**
        ColossusOfRhodes         **=** **0b****_0010_0000,** **// i.e. 32**
        LighthouseOfAlexandria   **=** **0b****_0100_0000** **// i.e. 64**
      }
    } 
    ```

    我们正在为每个选择分配明确的值，这些值在查看内存中存储的位时不会重叠。我们还应该用`System.Flags`属性装饰`enum`类型，以便当值返回时，它可以自动与多个值匹配，作为逗号分隔的`string`而不是返回`int`值。

    通常，`enum`类型内部使用`int`变量，但由于我们不需要那么大的值，我们可以通过告诉它使用`byte`变量来减少 75%的内存需求，即每个值 1 字节而不是 4 字节。

    如果我们想表明我们的愿望清单包括*巴比伦空中花园*和*哈利卡纳苏斯的摩索拉斯陵墓*这两大古代世界奇迹，那么我们希望将`16`和`2`位设置为`1`。换句话说，我们将存储值`18`：

    | 64 | 32 | 16 | 8 | 4 | 2 | 1 |
    | --- | --- | --- | --- | --- | --- | --- |
    | 0 | 0 | 1 | 0 | 0 | 1 | 0 |

1.  在`Person`类中，添加以下语句到你的字段列表中，如下列代码所示：

    ```cs
    public WondersOfTheAncientWorld BucketList; 
    ```

1.  在`Program.cs`中，添加语句使用`|`运算符（按位逻辑或）来组合`enum`值以设置愿望清单。我们也可以使用数字 18 强制转换为`enum`类型来设置值，如注释所示，但我们不应该这样做，因为这会使代码更难以理解，如下列代码所示：

    ```cs
    bob.BucketList = 
      WondersOfTheAncientWorld.HangingGardensOfBabylon
      | WondersOfTheAncientWorld.MausoleumAtHalicarnassus;
    // bob.BucketList = (WondersOfTheAncientWorld)18;
    WriteLine($"{bob.Name}'s bucket list is {bob.BucketList}"); 
    ```

1.  运行代码并查看结果，如下列输出所示：

    ```cs
    Bob Smith's bucket list is HangingGardensOfBabylon, MausoleumAtHalicarnassus 
    ```

**最佳实践**：使用`enum`值来存储离散选项的组合。如果有最多 8 个选项，则从`byte`派生`enum`类型；如果有最多 16 个选项，则从`ushort`派生；如果有最多 32 个选项，则从`uint`派生；如果有最多 64 个选项，则从`ulong`派生。

# 使用集合存储多个值

现在，让我们添加一个字段来存储一个人的子女。这是一个聚合的例子，因为子女是与当前人物相关联的类的实例，但并不属于该人物本身。我们将使用泛型`List<T>`集合类型，它可以存储任何类型的有序集合。你将在*第八章*，*使用常见的.NET 类型*中了解更多关于集合的内容。现在，只需跟随操作：

1.  在`Person.cs`中，导入`System.Collections.Generic`命名空间，如下面的代码所示：

    ```cs
    using System.Collections.Generic; // List<T> 
    ```

1.  在`Person`类中声明一个新字段，如下面的代码所示：

    ```cs
    public List<Person> Children = new List<Person>(); 
    ```

`List<Person>`读作“Person 列表”，例如，“名为`Children`的属性的类型是`Person`实例的列表。”我们明确地将类库的目标更改为.NET Standard 2.0（使用 C# 7 编译器），因此我们不能使用目标类型的新来初始化`Children`字段。如果我们保持目标为.NET 6.0，那么我们可以使用目标类型的新，如下面的代码所示：

```cs
public List<Person> Children = new(); 
```

我们必须确保在向集合添加项之前，集合已初始化为一个新的`Person`列表实例，否则字段将为`null`，当我们尝试使用其任何成员（如`Add`）时，将抛出运行时异常。

## 理解泛型集合

`List<T>`类型中的尖括号是 C#的一个特性，称为**泛型**，于 2005 年随 C# 2.0 引入。这是一个用于创建**强类型**集合的术语，即编译器明确知道集合中可以存储哪种类型的对象。泛型提高了代码的性能和正确性。

**强类型**与**静态类型**有不同的含义。旧的`System.Collection`类型静态地包含弱类型的`System.Object`项。新的`System.Collection.Generic`类型静态地包含强类型的`<T>`实例。

讽刺的是，*泛型*这一术语意味着我们可以使用更具体的静态类型！

1.  在`Program.cs`中，添加语句为`Bob`添加两个孩子，然后展示他有多少孩子以及他们的名字，如下面的代码所示：

    ```cs
    bob.Children.Add(new Person { Name = "Alfred" }); // C# 3.0 and later
    bob.Children.Add(new() { Name = "Zoe" }); // C# 9.0 and later
    WriteLine(
      $"{bob.Name} has {bob.Children.Count} children:");
    for (int childIndex = 0; childIndex < bob.Children.Count; childIndex++)
    {
      WriteLine($"  {bob.Children[childIndex].Name}");
    } 
    ```

    我们也可以使用`foreach`语句来遍历集合。作为额外的挑战，将`for`语句改为使用`foreach`输出相同的信息。

1.  运行代码并查看结果，如下面的输出所示：

    ```cs
    Bob Smith has 2 children:
      Alfred
      Zoe 
    ```

## 将字段设为静态

到目前为止我们创建的字段都是**实例**成员，意味着每个字段在创建的每个类实例中都有不同的值。`alice`和`bob`变量具有不同的`Name`值。

有时，您希望定义一个在所有实例中共享的单一值的字段。

这些被称为**静态** *成员*，因为字段不是唯一可以静态的成员。让我们看看使用`static`字段可以实现什么：

1.  在`PacktLibrary`项目中，添加一个名为`BankAccount.cs`的新类文件。

1.  修改类，使其具有三个字段，两个实例字段和一个静态字段，如下面的代码所示：

    ```cs
    namespace Packt.Shared
    {
      public class BankAccount
      {
        public string AccountName; // instance member
        public decimal Balance; // instance member
        public static decimal InterestRate; // shared member
      }
    } 
    ```

    每个`BankAccount`实例都将有自己的`AccountName`和`Balance`值，但所有实例将共享一个`InterestRate`值。

1.  在`Program.cs`中，添加语句以设置共享的利率，然后创建两个`BankAccount`类型的实例，如下面的代码所示：

    ```cs
    BankAccount.InterestRate = 0.012M; // store a shared value
    BankAccount jonesAccount = new(); // C# 9.0 and later
    jonesAccount.AccountName = "Mrs. Jones"; 
    jonesAccount.Balance = 2400;
    WriteLine(format: "{0} earned {1:C} interest.",
      arg0: jonesAccount.AccountName,
      arg1: jonesAccount.Balance * BankAccount.InterestRate);
    BankAccount gerrierAccount = new(); 
    gerrierAccount.AccountName = "Ms. Gerrier"; 
    gerrierAccount.Balance = 98;
    WriteLine(format: "{0} earned {1:C} interest.",
      arg0: gerrierAccount.AccountName,
      arg1: gerrierAccount.Balance * BankAccount.InterestRate); 
    ```

    `:C`是一个格式代码，告诉.NET 使用货币格式显示数字。在第八章《使用常见的.NET 类型》中，你将学习如何控制决定货币符号的文化。目前，它将使用你操作系统安装的默认设置。我住在英国伦敦，因此我的输出显示的是英镑（£）。

1.  运行代码并查看附加输出：

    ```cs
    Mrs. Jones earned £28.80 interest. 
    Ms. Gerrier earned £1.18 interest. 
    ```

字段并非唯一可声明为静态的成员。构造函数、方法、属性及其他成员也可以是静态的。

## 将字段设为常量

如果某个字段的值永远不会改变，你可以使用`const`关键字，并在编译时赋值一个字面量：

1.  在`Person.cs`中，添加以下代码：

    ```cs
     // constants
    public const string Species = "Homo Sapien"; 
    ```

1.  要获取常量字段的值，你必须写出类名，而不是类的实例名。在`Program.cs`中，添加一条语句，将 Bob 的名字和物种输出到控制台，如下所示：

    ```cs
    WriteLine($"{bob.Name} is a {Person.Species}"); 
    ```

1.  运行代码并查看结果，如下所示：

    ```cs
    Bob Smith is a Homo Sapien 
    ```

    微软类型中的`const`字段示例包括`System.Int32.MaxValue`和`System.Math.PI`，因为这两个值永远不会改变，如图 5.2 所示：

    ![图形用户界面，文本，应用程序，电子邮件 描述自动生成](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_05_02.png)

图 5.2：常量示例

**最佳实践**：常量并不总是最佳选择，原因有二：其值必须在编译时已知，并且必须能表示为字面量`string`、`Boolean`或数值。对`const`字段的每次引用在编译时都会被替换为字面量值，因此，如果未来版本中该值发生变化，且你未重新编译引用它的任何程序集以获取新值，则不会反映这一变化。

## 将字段设为只读

对于不应更改的字段，通常更好的选择是将其标记为只读：

1.  在`Person.cs`中，添加一条语句，声明一个实例只读字段以存储人的母星，如下所示：

    ```cs
    // read-only fields
    public readonly string HomePlanet = "Earth"; 
    ```

1.  在`Program.cs`中，添加一条语句，将 Bob 的名字和母星输出到控制台，如下所示：

    ```cs
    WriteLine($"{bob.Name} was born on {bob.HomePlanet}"); 
    ```

1.  运行代码并查看结果，如下所示：

    ```cs
    Bob Smith was born on Earth 
    ```

**最佳实践**：出于两个重要原因，建议使用只读字段而非常量字段：其值可以在运行时计算或加载，并且可以使用任何可执行语句来表达。因此，只读字段可以通过构造函数或字段赋值来设置。对字段的每次引用都是活跃的，因此任何未来的更改都将被调用代码正确反映。

你还可以声明`static` `readonly`字段，其值将在该类型的所有实例之间共享。

## 使用构造函数初始化字段

字段通常需要在运行时初始化。你可以在构造函数中执行此操作，该构造函数将在使用`new`关键字创建类的实例时被调用。构造函数在任何字段被使用该类型的代码设置之前执行。

1.  在`Person.cs`中，在现有的只读`HomePlanet`字段之后添加语句以定义第二个只读字段，然后在构造函数中设置`Name`和`Instantiated`字段，如下面的代码中突出显示的那样：

    ```cs
    // read-only fields
    public readonly string HomePlanet = "Earth";
    **public****readonly** **DateTime Instantiated;**
    **// constructors**
    **public****Person****()**
    **{**
    **// set default values for fields**
    **// including read-only fields**
     **Name =** **"Unknown"****;** 
     **Instantiated = DateTime.Now;**
    **}** 
    ```

1.  在`Program.cs`中，添加语句以实例化一个新的人，然后输出其初始字段值，如下面的代码所示：

    ```cs
    Person blankPerson = new();
    WriteLine(format:
      "{0} of {1} was created at {2:hh:mm:ss} on a {2:dddd}.",
      arg0: blankPerson.Name,
      arg1: blankPerson.HomePlanet,
      arg2: blankPerson.Instantiated); 
    ```

1.  运行代码并查看结果，如下面的输出所示：

    ```cs
    Unknown of Earth was created at 11:58:12 on a Sunday 
    ```

### 定义多个构造函数

一个类型中可以有多个构造函数。这对于鼓励开发者在字段上设置初始值特别有用：

1.  在`Person.cs`中，添加语句以定义第二个构造函数，允许开发者为人的姓名和家乡星球设置初始值，如下面的代码所示：

    ```cs
    public Person(string initialName, string homePlanet)
    {
      Name = initialName;
      HomePlanet = homePlanet;
      Instantiated = DateTime.Now;
    } 
    ```

1.  在`Program.cs`中，添加语句以使用带有两个参数的构造函数创建另一个人，如下面的代码所示：

    ```cs
    Person gunny = new(initialName: "Gunny", homePlanet: "Mars");
    WriteLine(format:
      "{0} of {1} was created at {2:hh:mm:ss} on a {2:dddd}.",
      arg0: gunny.Name,
      arg1: gunny.HomePlanet,
      arg2: gunny.Instantiated); 
    ```

1.  运行代码并查看结果：

    ```cs
    Gunny of Mars was created at 11:59:25 on a Sunday 
    ```

构造函数是一种特殊的方法类别。让我们更详细地看看方法。

# 编写和调用方法

**方法**是一种类型的成员，它执行一组语句。它们是属于某个类型的函数。

## 从方法中返回值

方法可以返回单个值或不返回任何值：

+   执行某些操作但不返回值的方法通过在方法名称前使用`void`类型来表示这一点。

+   执行某些操作并返回值的方法通过在方法名称前使用返回值的类型来表示这一点。

例如，在下一个任务中，你将创建两个方法：

+   `WriteToConsole`：这将执行一个动作（向控制台写入一些文本），但它不会从方法中返回任何内容，由`void`关键字表示。

+   `GetOrigin`：这将返回一个文本值，由`string`关键字表示。

让我们编写代码：

1.  在`Person.cs`中，添加语句以定义我之前描述的两种方法，如下面的代码所示：

    ```cs
    // methods
    public void WriteToConsole()
    {
      WriteLine($"{Name} was born on a {DateOfBirth:dddd}.");
    }
    public string GetOrigin()
    {
      return $"{Name} was born on {HomePlanet}.";
    } 
    ```

1.  在`Program.cs`中，添加语句以调用这两个方法，如下面的代码所示：

    ```cs
    bob.WriteToConsole(); 
    WriteLine(bob.GetOrigin()); 
    ```

1.  运行代码并查看结果，如下面的输出所示：

    ```cs
    Bob Smith was born on a Wednesday. 
    Bob Smith was born on Earth. 
    ```

## 使用元组组合多个返回值

每个方法只能返回一个具有单一类型的值。该类型可以是简单类型，如前例中的`string`，复杂类型，如`Person`，或集合类型，如`List<Person>`。

假设我们想要定义一个名为`GetTheData`的方法，该方法需要返回一个`string`值和一个`int`值。我们可以定义一个名为`TextAndNumber`的新类，其中包含一个`string`字段和一个`int`字段，并返回该复杂类型的实例，如下面的代码所示：

```cs
public class TextAndNumber
{
  public string Text;
  public int Number;
}
public class LifeTheUniverseAndEverything
{
  public TextAndNumber GetTheData()
  {
    return new TextAndNumber
    {
      Text = "What's the meaning of life?",
      Number = 42
    };
  }
} 
```

但仅仅为了组合两个值而定义一个类是不必要的，因为在现代版本的 C#中我们可以使用**元组**。元组是一种高效地将两个或更多值组合成单一单元的方式。我发音为 tuh-ples，但我听说其他开发者发音为 too-ples。番茄，西红柿，土豆，马铃薯，我想。

元组自 F#等语言的第一个版本以来就一直是其中的一部分，但.NET 直到 2010 年使用`System.Tuple`类型才在.NET 4.0 中添加了对它们的支持。

### 语言对元组的支持

直到 2017 年 C# 7.0，C#才通过使用圆括号字符`()`添加了对元组的语言语法支持，同时.NET 引入了一个新的`System.ValueTuple`类型，在某些常见场景下比旧的.NET 4.0 `System.Tuple`类型更高效。C#的元组语法使用了更高效的那个。

让我们来探索元组：

1.  在`Person.cs`中，添加语句以定义一个返回结合了`string`和`int`的元组的方法，如下列代码所示：

    ```cs
    public (string, int) GetFruit()
    {
      return ("Apples", 5);
    } 
    ```

1.  在`Program.cs`中，添加语句以调用`GetFruit`方法，然后自动输出名为`Item1`和`Item2`的元组字段，如下列代码所示：

    ```cs
    (string, int) fruit = bob.GetFruit();
    WriteLine($"{fruit.Item1}, {fruit.Item2} there are."); 
    ```

1.  运行代码并查看结果，如下列输出所示：

    ```cs
    Apples, 5 there are. 
    ```

### 命名元组的字段

要访问元组的字段，默认名称是`Item1`、`Item2`等。

你可以显式指定字段名称：

1.  在`Person.cs`中，添加语句以定义一个返回具有命名字段的元组的方法，如下列代码所示：

    ```cs
    public (string Name, int Number) GetNamedFruit()
    {
      return (Name: "Apples", Number: 5);
    } 
    ```

1.  在`Program.cs`中，添加语句以调用该方法并输出元组的命名字段，如下列代码所示：

    ```cs
    var fruitNamed = bob.GetNamedFruit();
    WriteLine($"There are {fruitNamed.Number} {fruitNamed.Name}."); 
    ```

1.  运行代码并查看结果，如下列输出所示：

    ```cs
    There are 5 Apples. 
    ```

### 推断元组名称

如果你是从另一个对象构建元组，你可以使用 C# 7.1 引入的特性，称为**元组名称推断**。

在`Program.cs`中，创建两个元组，每个元组由一个`string`和一个`int`值组成，如下列代码所示：

```cs
var thing1 = ("Neville", 4);
WriteLine($"{thing1.Item1} has {thing1.Item2} children.");
var thing2 = (bob.Name, bob.Children.Count); 
WriteLine($"{thing2.Name} has {thing2.Count} children."); 
```

在 C# 7.0 中，两者都会使用`Item1`和`Item2`命名方案。在 C# 7.1 及更高版本中，`thing2`可以推断出名称`Name`和`Count`。

### 解构元组

你也可以将元组解构成单独的变量。解构声明的语法与命名字段元组相同，但没有为元组指定名称的变量，如下列代码所示：

```cs
// store return value in a tuple variable with two fields
(string TheName, int TheNumber) tupleWithNamedFields = bob.GetNamedFruit();
// tupleWithNamedFields.TheName
// tupleWithNamedFields.TheNumber
// deconstruct return value into two separate variables
(string name, int number) = GetNamedFruit();
// name
// number 
```

这具有将元组分解为其各个部分并将这些部分分配给新变量的效果。

1.  在`Program.cs`中，添加语句以解构从`GetFruit`方法返回的元组，如下列代码所示：

    ```cs
    (string fruitName, int fruitNumber) = bob.GetFruit();
    WriteLine($"Deconstructed: {fruitName}, {fruitNumber}"); 
    ```

1.  运行代码并查看结果，如下列输出所示：

    ```cs
    Deconstructed: Apples, 5 
    ```

### 解构类型

元组并非唯一可被解构的类型。任何类型都可以有名为`Deconstruct`的特殊方法，这些方法能将对象分解为各个部分。让我们为`Person`类实现一些这样的方法：

1.  在`Person.cs`中，添加两个`Deconstruct`方法，为我们要分解的部分定义`out`参数，如下面的代码所示：

    ```cs
    // deconstructors
    public void Deconstruct(out string name, out DateTime dob)
    {
      name = Name;
      dob = DateOfBirth;
    }
    public void Deconstruct(out string name, 
      out DateTime dob, out WondersOfTheAncientWorld fav)
    {
      name = Name;
      dob = DateOfBirth;
      fav = FavoriteAncientWonder;
    } 
    ```

1.  在`Program.cs`中，添加语句以分解`bob`，如下面的代码所示：

    ```cs
    // Deconstructing a Person
    var (name1, dob1) = bob;
    WriteLine($"Deconstructed: {name1}, {dob1}");
    var (name2, dob2, fav2) = bob;
    WriteLine($"Deconstructed: {name2}, {dob2}, {fav2}"); 
    ```

1.  运行代码并查看结果，如下面的输出所示：

    ```cs
    Deconstructed: Bob Smith, 22/12/1965 00:00:00
    Deconstructed: Bob Smith, 22/12/1965 00:00:00, StatueOfZeusAtOlympia
    B 
    ```

## 定义和传递参数给方法

方法可以接收参数来改变其行为。参数的定义有点像变量声明，但位于方法的括号内，正如本章前面在构造函数中看到的那样。我们来看更多例子：

1.  在`Person.cs`中，添加语句以定义两种方法，第一种没有参数，第二种有一个参数，如下面的代码所示：

    ```cs
    public string SayHello()
    {
      return $"{Name} says 'Hello!'";
    }
    public string SayHelloTo(string name)
    {
      return $"{Name} says 'Hello {name}!'";
    } 
    ```

1.  在`Program.cs`中，添加语句以调用这两种方法，并将返回值写入控制台，如下面的代码所示：

    ```cs
    WriteLine(bob.SayHello()); 
    WriteLine(bob.SayHelloTo("Emily")); 
    ```

1.  运行代码并查看结果：

    ```cs
    Bob Smith says 'Hello!'
    Bob Smith says 'Hello Emily!' 
    ```

在输入调用方法的语句时，IntelliSense 会显示一个工具提示，其中包含任何参数的名称和类型，以及方法的返回类型，如*图 5.3*所示：

![图形用户界面，文本，网站 描述自动生成](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_05_03.png)

*图 5.3*：没有重载的方法的 IntelliSense 工具提示

## 方法重载

我们不必为两种不同的方法取不同的名字，可以给这两种方法取相同的名字。这是允许的，因为这两种方法的签名不同。

**方法签名**是一系列参数类型，可以在调用方法时传递。重载方法不能仅在返回类型上有所不同。

1.  在`Person.cs`中，将`SayHelloTo`方法的名称更改为`SayHello`。

1.  在`Program.cs`中，将方法调用更改为使用`SayHello`方法，并注意方法的快速信息告诉你它有一个额外的重载，1/2，以及 2/2，如*图 5.4*所示：![图形用户界面 描述自动生成，中等置信度](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_05_04.png)

*图 5.4*：有重载的方法的 IntelliSense 工具提示

**最佳实践**：使用重载方法简化类，使其看起来方法更少。

## 传递可选和命名参数

另一种简化方法的方式是使参数可选。通过在方法参数列表中赋予默认值，可以使参数成为可选参数。可选参数必须始终位于参数列表的最后。

我们现在将创建一个具有三个可选参数的方法：

1.  在`Person.cs`中，添加语句以定义该方法，如下面的代码所示：

    ```cs
    public string OptionalParameters(
      string command  = "Run!",
      double number = 0.0,
      bool active = true)
    {
      return string.Format(
        format: "command is {0}, number is {1}, active is {2}",
        arg0: command,
        arg1: number,
        arg2: active);
    } 
    ```

1.  在`Program.cs`中，添加一条语句以调用该方法，并将返回值写入控制台，如下面的代码所示：

    ```cs
    WriteLine(bob.OptionalParameters()); 
    ```

1.  随着你输入代码，观察 IntelliSense 的出现。你会看到一个工具提示，显示三个可选参数及其默认值，如*图 5.5*所示：![图形用户界面，文本，应用程序，聊天或短信 描述自动生成](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_05_05.png)

    图 5.5：IntelliSense 显示您键入代码时的可选参数

1.  运行代码并查看结果，如下所示：

    ```cs
    command is Run!, number is 0, active is True 
    ```

1.  在`Program.cs`中，添加一条语句，为`command`参数传递一个`string`值，为`number`参数传递一个`double`值，如下所示：

    ```cs
    WriteLine(bob.OptionalParameters("Jump!", 98.5)); 
    ```

1.  运行代码并查看结果，如下所示：

    ```cs
    command is Jump!, number is 98.5, active is True 
    ```

`command`和`number`参数的默认值已被替换，但`active`的默认值仍然是`true`。

### 调用方法时命名参数值

调用方法时，可选参数通常与命名参数结合使用，因为命名参数允许值以与声明不同的顺序传递。

1.  在`Program.cs`中，添加一条语句，为`command`参数传递一个`string`值，为`number`参数传递一个`double`值，但使用命名参数，以便它们传递的顺序可以互换，如下所示：

    ```cs
    WriteLine(bob.OptionalParameters(
      number: 52.7, command: "Hide!")); 
    ```

1.  运行代码并查看结果，如下所示：

    ```cs
    command is Hide!, number is 52.7, active is True 
    ```

    您甚至可以使用命名参数跳过可选参数。

1.  在`Program.cs`中，添加一条语句，按位置顺序为`command`参数传递一个`string`值，跳过`number`参数，并使用命名的`active`参数，如下所示：

    ```cs
    WriteLine(bob.OptionalParameters("Poke!", active: false)); 
    ```

1.  运行代码并查看结果，如下所示：

    ```cs
    command is Poke!, number is 0, active is False 
    ```

## 控制参数的传递方式

当参数传递给方法时，它可以以三种方式之一传递：

+   通过**值**（默认方式）：将其视为*仅输入*。

+   通过**引用**作为`ref`参数：将其视为*进出*。

+   作为`out`参数：将其视为*仅输出*。

让我们看一些参数传递的例子：

1.  在`Person.cs`中，添加语句以定义一个带有三个参数的方法，一个`in`参数，一个`ref`参数，以及一个`out`参数，如下所示：

    ```cs
    public void PassingParameters(int x, ref int y, out int z)
    {
      // out parameters cannot have a default
      // AND must be initialized inside the method
      z = 99;
      // increment each parameter
      x++; 
      y++; 
      z++;
    } 
    ```

1.  在`Program.cs`中，添加语句以声明一些`int`变量并将它们传递给方法，如下所示：

    ```cs
    int a = 10; 
    int b = 20; 
    int c = 30;
    WriteLine($"Before: a = {a}, b = {b}, c = {c}"); 
    bob.PassingParameters(a, ref b, out c); 
    WriteLine($"After: a = {a}, b = {b}, c = {c}"); 
    ```

1.  运行代码并查看结果，如下所示：

    ```cs
    Before: a = 10, b = 20, c = 30 
    After: a = 10, b = 21, c = 100 
    ```

    +   当默认传递变量作为参数时，传递的是其当前值，而不是变量本身。因此，`x`是`a`变量值的副本。`a`变量保持其原始值`10`。

    +   当将变量作为`ref`参数传递时，变量的引用被传递到方法中。因此，`y`是对`b`的引用。当`y`参数递增时，`b`变量也随之递增。

    +   当将变量作为`out`参数传递时，变量的引用被传递到方法中。因此，`z`是对`c`的引用。`c`变量的值被方法内部执行的代码所替换。我们可以在`Main`方法中简化代码，不将值`30`赋给`c`变量，因为它总是会被替换。

### 简化`out`参数

在 C# 7.0 及更高版本中，我们可以简化使用 out 变量的代码。

在`Program.cs`中，添加语句以声明更多变量，包括一个名为`f`的内联声明的`out`参数，如下所示：

```cs
int d = 10; 
int e = 20;
WriteLine($"Before: d = {d}, e = {e}, f doesn't exist yet!");
// simplified C# 7.0 or later syntax for the out parameter 
bob.PassingParameters(d, ref e, out int f); 
WriteLine($"After: d = {d}, e = {e}, f = {f}"); 
```

## 理解 ref 返回

在 C# 7.0 或更高版本中，`ref`关键字不仅用于向方法传递参数；它还可以应用于`return`值。这使得外部变量可以引用内部变量并在方法调用后修改其值。这在高级场景中可能有用，例如，在大数据结构中传递占位符，但这超出了本书的范围。

## 使用 partial 拆分类

在处理大型项目或与多个团队成员合作时，或者在处理特别庞大且复杂的类实现时，能够将类的定义拆分到多个文件中非常有用。您可以通过使用`partial`关键字来实现这一点。

设想我们希望向`Person`类添加由类似对象关系映射器（ORM）的工具自动生成的语句，该工具从数据库读取架构信息。如果该类定义为`partial`，那么我们可以将类拆分为一个自动生成代码文件和一个手动编辑代码文件。

让我们编写一些代码来模拟此示例：

1.  在`Person.cs`中，添加`partial`关键字，如下所示突出显示：

    ```cs
    namespace Packt.Shared
    {
      public **partial** class Person
      { 
    ```

1.  在`PacktLibrary`项目/文件夹中，添加一个名为`PersonAutoGen.cs`的新类文件。

1.  向新文件添加语句，如下所示：

    ```cs
    namespace Packt.Shared
    {
      public partial class Person
      {
      }
    } 
    ```

本章剩余代码将在`PersonAutoGen.cs`文件中编写。

# 通过属性和索引器控制访问

之前，您创建了一个名为`GetOrigin`的方法，该方法返回一个包含人员姓名和来源的`string`。诸如 Java 之类的语言经常这样做。C#有更好的方法：属性。

属性本质上是一个方法（或一对方法），当您想要获取或设置值时，它表现得像字段一样，从而简化了语法。

## 定义只读属性

一个`readonly`属性仅具有`get`实现。

1.  在`PersonAutoGen.cs`中，在`Person`类中，添加语句以定义三个属性：

    1.  第一个属性将使用适用于所有 C#版本的属性语法执行与`GetOrigin`方法相同的角色（尽管它使用了 C# 6 及更高版本中的字符串插值语法）。

    1.  第二个属性将使用 C# 6 及更高版本中的 lambda 表达式体`=>`语法返回一条问候消息。

    1.  第三个属性将计算该人的年龄。

    以下是代码：

    ```cs
    // a property defined using C# 1 - 5 syntax
    public string Origin
    {
      get
      {
        return $"{Name} was born on {HomePlanet}";
      }
    }
    // two properties defined using C# 6+ lambda expression body syntax
    public string Greeting => $"{Name} says 'Hello!'";
    public int Age => System.DateTime.Today.Year - DateOfBirth.Year; 
    ```

    **良好实践**：这不是计算某人年龄的最佳方法，但我们并非学习如何从出生日期计算年龄。若需正确执行此操作，请阅读以下链接中的讨论：[`stackoverflow.com/questions/9/how-do-i-calculate-someones-age-in-c`](https://stackoverflow.com/questions/9/how-do-i-calculate-someones-age-in-c)

1.  在`Program.cs`中，添加获取属性的语句，如下列代码所示：

    ```cs
    Person sam = new()
    {
      Name = "Sam",
      DateOfBirth = new(1972, 1, 27)
    };
    WriteLine(sam.Origin); 
    WriteLine(sam.Greeting); 
    WriteLine(sam.Age); 
    ```

1.  运行代码并查看结果，如下列输出所示：

    ```cs
    Sam was born on Earth 
    Sam says 'Hello!'
    49 
    ```

输出显示 49，因为我在 2021 年 8 月 15 日运行了控制台应用程序，当时 Sam 49 岁。

## 定义可设置的属性

要创建一个可设置的属性，您必须使用较旧的语法并提供一对方法——不仅仅是`get`部分，还包括`set`部分：

1.  在`PersonAutoGen.cs`中，添加语句以定义一个具有`get`和`set`方法（也称为 getter 和 setter）的`string`属性，如下列代码所示：

    ```cs
    public string FavoriteIceCream { get; set; } // auto-syntax 
    ```

    尽管您没有手动创建一个字段来存储某人的最爱冰淇淋，但它确实存在，由编译器自动为您创建。

    有时，您需要更多控制权来决定属性设置时发生的情况。在这种情况下，您必须使用更详细的语法并手动创建一个`private`字段来存储该属性的值。

1.  在`PersonAutoGen.cs`中，添加语句以定义一个`string`字段和一个具有`get`和`set`的`string`属性，如下列代码所示：

    ```cs
    private string favoritePrimaryColor;
    public string FavoritePrimaryColor
    {
      get
      {
        return favoritePrimaryColor;
      }
      set
      {
        switch (value.ToLower())
        {
          case "red":
          case "green":
          case "blue":
            favoritePrimaryColor = value;
            break;
          default:
            throw new System.ArgumentException(
              $"{value} is not a primary color. " + 
              "Choose from: red, green, blue.");
        }
      }
    } 
    ```

    **最佳实践**：避免在您的 getter 和 setter 中添加过多代码。这可能表明您的设计存在问题。考虑添加私有方法，然后在 setter 和 getter 中调用这些方法，以简化您的实现。

1.  在`Program.cs`中，添加语句以设置 Sam 的最爱冰淇淋和颜色，然后将其写出，如下列代码所示：

    ```cs
    sam.FavoriteIceCream = "Chocolate Fudge";
    WriteLine($"Sam's favorite ice-cream flavor is {sam.FavoriteIceCream}."); 
    sam.FavoritePrimaryColor = "Red";
    WriteLine($"Sam's favorite primary color is {sam.FavoritePrimaryColor}."); 
    ```

1.  运行代码并查看结果，如下列输出所示：

    ```cs
    Sam's favorite ice-cream flavor is Chocolate Fudge. 
    Sam's favorite primary color is Red. 
    ```

    如果您尝试将颜色设置为除红色、绿色或蓝色之外的任何值，则代码将抛出异常。调用代码随后可以使用`try`语句来显示错误消息。

    **最佳实践**：当您希望验证可以存储的值时，或者在希望进行 XAML 数据绑定时（我们将在*第十九章*，*使用.NET MAUI 构建移动和桌面应用*中介绍），以及当您希望在不使用`GetAge`和`SetAge`这样的方法对的情况下读写字段时，请使用属性而不是字段。

## 要求在实例化时设置属性

C# 10 引入了`required`修饰符。如果您将其用于属性，编译器将确保在实例化时为该属性设置一个值，如下列代码所示：

```cs
public class Book
{
  public required string Isbn { get; set; }
  public string Title { get; set; }
} 
```

如果您尝试实例化一个`Book`而不设置`Isbn`属性，您将看到一个编译器错误，如下列代码所示：

```cs
Book novel = new(); 
```

`required`关键字可能不会出现在.NET 6 的最终发布版本中，因此请将本节视为理论性的。

## 定义索引器

索引器允许调用代码使用数组语法来访问属性。例如，`string`类型定义了一个**索引器**，以便调用代码可以访问`string`中的单个字符。

我们将定义一个索引器，以简化对某人子女的访问：

1.  在`PersonAutoGen.cs`中，添加语句定义一个索引器，以使用孩子的索引获取和设置孩子，如下所示：

    ```cs
    // indexers
    public Person this[int index]
    {
      get
      {
        return Children[index]; // pass on to the List<T> indexer
      }
      set
      {
        Children[index] = value;
      }
    } 
    ```

    您可以重载索引器，以便不同的类型可以用于其参数。例如，除了传递一个`int`值外，您还可以传递一个`string`值。

1.  在`Program.cs`中，添加语句向`Sam`添加两个孩子，然后使用较长的`Children`字段和较短的索引器语法访问第一个和第二个孩子，如下所示：

    ```cs
    sam.Children.Add(new() { Name = "Charlie" }); 
    sam.Children.Add(new() { Name = "Ella" });
    WriteLine($"Sam's first child is {sam.Children[0].Name}"); 
    WriteLine($"Sam's second child is {sam.Children[1].Name}");
    WriteLine($"Sam's first child is {sam[0].Name}"); 
    WriteLine($"Sam's second child is {sam[1].Name}"); 
    ```

1.  运行代码并查看结果，如下所示：

    ```cs
    Sam's first child is Charlie 
    Sam's second child is Ella 
    Sam's first child is Charlie 
    Sam's second child is Ella 
    ```

# 对象的模式匹配

在*第三章*，*控制流程、转换类型和处理异常*中，您被介绍了基本的模式匹配。在本节中，我们将更详细地探讨模式匹配。

## 创建并引用.NET 6 类库

增强的模式匹配特性仅在支持 C# 9 或更高版本的现代.NET 类库中可用。

1.  使用您偏好的编码工具，在名为`Chapter05`的工作区/解决方案中添加一个名为`PacktLibraryModern`的新类库。

1.  在`PeopleApp`项目中，添加对`PacktLibraryModern`类库的引用，如下所示：

    ```cs
    <Project Sdk="Microsoft.NET.Sdk">
      <PropertyGroup>
        <OutputType>Exe</OutputType>
        <TargetFramework>net6.0</TargetFramework>
        <Nullable>enable</Nullable>
        <ImplicitUsings>enable</ImplicitUsings>
      </PropertyGroup>
      <ItemGroup>
        <ProjectReference Include="../PacktLibrary/PacktLibrary.csproj" />
     **<ProjectReference** 
     **Include=****"../PacktLibraryModern/PacktLibraryModern.csproj"** **/>**
      </ItemGroup>
    </Project> 
    ```

1.  构建`PeopleApp`项目。

## 定义飞行乘客

在本例中，我们将定义一些代表飞行中各种类型乘客的类，然后我们将使用带有模式匹配的 switch 表达式来确定他们的飞行费用。

1.  在`PacktLibraryModern`项目/文件夹中，将文件`Class1.cs`重命名为`FlightPatterns.cs`。

1.  在`FlightPatterns.cs`中，添加语句定义三种具有不同属性的乘客类型，如下所示：

    ```cs
    namespace Packt.Shared; // C# 10 file-scoped namespace
    public class BusinessClassPassenger
    {
      public override string ToString()
      {
        return $"Business Class";
      }
    }
    public class FirstClassPassenger
    {
      public int AirMiles { get; set; }
      public override string ToString()
      {
        return $"First Class with {AirMiles:N0} air miles";
      }
    }
    public class CoachClassPassenger
    {
      public double CarryOnKG { get; set; }
      public override string ToString()
      {
        return $"Coach Class with {CarryOnKG:N2} KG carry on";
      }
    } 
    ```

1.  在`Program.cs`中，添加语句定义一个包含五种不同类型和属性值的乘客对象数组，然后枚举它们，输出他们的飞行费用，如下所示：

    ```cs
    object[] passengers = {
      new FirstClassPassenger { AirMiles = 1_419 },
      new FirstClassPassenger { AirMiles = 16_562 },
      new BusinessClassPassenger(),
      new CoachClassPassenger { CarryOnKG = 25.7 },
      new CoachClassPassenger { CarryOnKG = 0 },
    };
    foreach (object passenger in passengers)
    {
      decimal flightCost = passenger switch
      {
        FirstClassPassenger p when p.AirMiles > 35000 => 1500M, 
        FirstClassPassenger p when p.AirMiles > 15000 => 1750M, 
        FirstClassPassenger _                         => 2000M,
        BusinessClassPassenger _                      => 1000M,
        CoachClassPassenger p when p.CarryOnKG < 10.0 => 500M, 
        CoachClassPassenger _                         => 650M,
        _                                             => 800M
      };
      WriteLine($"Flight costs {flightCost:C} for {passenger}");
    } 
    ```

    在审查前面的代码时，请注意以下几点：

    +   要对对象的属性进行模式匹配，您必须命名一个局部变量，该变量随后可以在表达式中使用，如`p`。

    +   仅对类型进行模式匹配时，可以使用`_`来丢弃局部变量。

    +   switch 表达式也使用`_`来表示其默认分支。

1.  运行代码并查看结果，如下所示：

    ```cs
    Flight costs £2,000.00 for First Class with 1,419 air miles 
    Flight costs £1,750.00 for First Class with 16,562 air miles 
    Flight costs £1,000.00 for Business Class
    Flight costs £650.00 for Coach Class with 25.70 KG carry on 
    Flight costs £500.00 for Coach Class with 0.00 KG carry on 
    ```

## C# 9 或更高版本中模式匹配的增强

前面的示例使用的是 C# 8。现在我们将看看 C# 9 及更高版本的一些增强功能。首先，进行类型匹配时不再需要使用下划线来丢弃：

1.  在`Program.cs`中，注释掉 C# 8 语法，添加 C# 9 及更高版本的语法，修改头等舱乘客的分支，使用嵌套的 switch 表达式和新的条件支持，如`>`，如下所示：

    ```cs
    decimal flightCost = passenger switch
    {
      /* C# 8 syntax
      FirstClassPassenger p when p.AirMiles > 35000 => 1500M,
      FirstClassPassenger p when p.AirMiles > 15000 => 1750M,
      FirstClassPassenger                           => 2000M, */
      // C# 9 or later syntax
      FirstClassPassenger p => p.AirMiles switch
      {
        > 35000 => 1500M,
        > 15000 => 1750M,
        _       => 2000M
      },
      BusinessClassPassenger                        => 1000M,
      CoachClassPassenger p when p.CarryOnKG < 10.0 => 500M,
      CoachClassPassenger                           => 650M,
      _                                             => 800M
    }; 
    ```

1.  运行代码以查看结果，并注意它们与之前相同。

您还可以结合使用关系模式和属性模式来避免嵌套的 switch 表达式，如下面的代码所示：

```cs
FirstClassPassenger { AirMiles: > 35000 } => 1500,
FirstClassPassenger { AirMiles: > 15000 } => 1750M,
FirstClassPassenger => 2000M, 
```

# 处理记录

在我们深入了解 C# 9 及更高版本的新记录语言特性之前，让我们先看看一些其他相关的新特性。

## Init-only 属性

您在本章中使用了对象初始化语法来实例化对象并设置初始属性。那些属性也可以在实例化后更改。

有时，您希望将属性视为`只读`字段，以便它们可以在实例化期间设置，但不能在此之后设置。新的`init`关键字使这成为可能。它可以用来替代`set`关键字：

1.  在`PacktLibraryModern`项目/文件夹中，添加一个名为`Records.cs`的新文件。

1.  在`Records.cs`中，定义一个不可变人员类，如下面的代码所示：

    ```cs
    namespace Packt.Shared; // C# 10 file-scoped namespace
    public class ImmutablePerson
    {
      public string? FirstName { get; init; }
      public string? LastName { get; init; }
    } 
    ```

1.  在`Program.cs`中，添加语句以实例化一个新的不可变人员，然后尝试更改其一个属性，如下面的代码所示：

    ```cs
    ImmutablePerson jeff = new() 
    {
      FirstName = "Jeff",
      LastName = "Winger"
    };
    jeff.FirstName = "Geoff"; 
    ```

1.  编译控制台应用程序并注意编译错误，如下面的输出所示：

    ```cs
    Program.cs(254,7): error CS8852: Init-only property or indexer 'ImmutablePerson.FirstName' can only be assigned in an object initializer, or on 'this' or 'base' in an instance constructor or an 'init' accessor. [/Users/markjprice/Code/Chapter05/PeopleApp/PeopleApp.csproj] 
    ```

1.  注释掉尝试在实例化后设置`FirstName`属性的代码。

## 理解记录

Init-only 属性为 C#提供了一些不可变性。您可以通过使用**记录**将这一概念进一步推进。这些是通过使用`record`关键字而不是`class`关键字来定义的。这可以使整个对象不可变，并且在比较时它表现得像一个值。我们将在*第六章*，*实现接口和继承类*中更详细地讨论类、记录和值类型的相等性和比较。

记录不应具有在实例化后更改的任何状态（属性和字段）。相反，想法是您从现有记录创建新记录，其中包含任何更改的状态。这称为非破坏性突变。为此，C# 9 引入了`with`关键字：

1.  在`Records.cs`中，添加一个名为`ImmutableVehicle`的记录，如下面的代码所示：

    ```cs
    public record ImmutableVehicle
    {
      public int Wheels { get; init; }
      public string? Color { get; init; }
      public string? Brand { get; init; }
    } 
    ```

1.  在`Program.cs`中，添加语句以创建一辆`车`，然后创建其变异副本，如下面的代码所示：

    ```cs
    ImmutableVehicle car = new() 
    {
      Brand = "Mazda MX-5 RF",
      Color = "Soul Red Crystal Metallic",
      Wheels = 4
    };
    ImmutableVehicle repaintedCar = car 
      with { Color = "Polymetal Grey Metallic" }; 
    WriteLine($"Original car color was {car.Color}.");
    WriteLine($"New car color is {repaintedCar.Color}."); 
    ```

1.  运行代码以查看结果，并注意变异副本中汽车颜色的变化，如下面的输出所示：

    ```cs
    Original car color was Soul Red Crystal Metallic.
    New car color is Polymetal Grey Metallic. 
    ```

## 记录中的位置数据成员

定义记录的语法可以通过使用位置数据成员大大简化。

### 简化记录中的数据成员

与其使用花括号的对象初始化语法，有时您可能更愿意提供带有位置参数的构造函数，正如您在本章前面所见。您还可以将此与析构函数结合使用，以将对象分解为各个部分，如下面的代码所示：

```cs
public record ImmutableAnimal
{
  public string Name { get; init; } 
  public string Species { get; init; }
  public ImmutableAnimal(string name, string species)
  {
    Name = name;
    Species = species;
  }
  public void Deconstruct(out string name, out string species)
  {
    name = Name;
    species = Species;
  }
} 
```

属性、构造函数和析构函数可以为您自动生成：

1.  在`Records.cs`中，添加语句以使用称为位置记录的简化语法定义另一个记录，如下面的代码所示：

    ```cs
    // simpler way to define a record
    // auto-generates the properties, constructor, and deconstructor
    public record ImmutableAnimal(string Name, string Species); 
    ```

1.  在`Program.cs`中，添加语句以构造和析构不可变动物，如下列代码所示：

    ```cs
    ImmutableAnimal oscar = new("Oscar", "Labrador");
    var (who, what) = oscar; // calls Deconstruct method 
    WriteLine($"{who} is a {what}."); 
    ```

1.  运行应用程序并查看结果，如下列输出所示：

    ```cs
    Oscar is a Labrador. 
    ```

当我们查看 C# 10 支持创建`struct`记录时，你将在*第六章*，*实现接口和继承类*中再次看到记录。

# 实践与探索

通过回答一些问题来测试你的知识和理解，进行一些实践操作，并深入研究本章的主题。

## 练习 5.1 – 测试你的知识

回答以下问题：

1.  访问修饰符关键字的六种组合是什么，它们各自的作用是什么？

1.  当应用于类型成员时，`static`、`const`和`readonly`关键字之间有何区别？

1.  构造函数的作用是什么？

1.  当你想要存储组合值时，为什么应该对`enum`类型应用`[Flags]`属性？

1.  为什么`partial`关键字有用？

1.  什么是元组？

1.  `record`关键字的作用是什么？

1.  重载是什么意思？

1.  字段和属性之间有什么区别？

1.  如何使方法参数变为可选？

## 练习 5.2 – 探索主题

使用以下页面上的链接来了解更多关于本章所涵盖主题的详细信息：

[`github.com/markjprice/cs10dotnet6/blob/main/book-links.md#chapter-5---building-your-own-types-with-object-oriented-programming`](https://github.com/markjprice/cs10dotnet6/blob/main/book-links.md#chapter-5---building-your-own-types-with-object-oriented-programming)

# 总结

在本章中，你学习了使用面向对象编程（OOP）创建自己的类型。你了解了类型可以拥有的不同类别的成员，包括用于存储数据的字段和执行操作的方法，并运用了 OOP 概念，如聚合和封装。你看到了如何使用现代 C#特性，如关系和属性模式匹配增强、仅初始化属性以及记录的示例。

在下一章中，你将通过定义委托和事件、实现接口以及继承现有类来进一步应用这些概念。


# 第六章：实现接口和继承类

本章是关于使用**面向对象编程**（**OOP**）从现有类型派生新类型的。你将学习定义运算符和局部函数以执行简单操作，以及委托和事件以在类型之间交换消息。你将实现接口以实现通用功能。你将了解泛型以及引用类型和值类型之间的区别。你将创建一个派生类以从基类继承功能，覆盖继承的类型成员，并使用多态性。最后，你将学习如何创建扩展方法以及如何在继承层次结构中的类之间进行类型转换。

本章涵盖以下主题：

+   设置类库和控制台应用程序

+   更多关于方法的内容

+   引发和处理事件

+   使用泛型安全地重用类型

+   实现接口

+   使用引用和值类型管理内存

+   处理空值

+   从类继承

+   在继承层次结构中进行类型转换

+   继承和扩展.NET 类型

+   使用分析器编写更好的代码

# 设置类库和控制台应用程序

我们将首先定义一个包含两个项目的工作区/解决方案，类似于在*第五章*，*使用面向对象编程构建自己的类型*中创建的那个。即使你完成了该章的所有练习，也要按照下面的说明操作，因为我们将在类库中使用 C# 10 特性，因此它需要面向.NET 6.0 而不是.NET Standard 2.0：

1.  使用你喜欢的编码工具创建一个名为`Chapter06`的新工作区/解决方案。

1.  添加一个类库项目，如下列表定义：

    1.  项目模板：**类库** / `classlib`

    1.  工作区/解决方案文件和文件夹：`Chapter06`

    1.  项目文件和文件夹：`PacktLibrary`

1.  添加一个控制台应用程序项目，如下列表定义：

    1.  项目模板：**控制台应用程序** / `console`

    1.  工作区/解决方案文件和文件夹：`Chapter06`

    1.  项目文件和文件夹：`PeopleApp`

1.  在`PacktLibrary`项目中，将名为`Class1.cs`的文件重命名为`Person.cs`。

1.  修改`Person.cs`文件内容，如下所示：

    ```cs
    using static System.Console;
    namespace Packt.Shared;
    public class Person : object
    {
      // fields
      public string? Name;    // ? allows null
      public DateTime DateOfBirth;
      public List<Person> Children = new(); // C# 9 or later
      // methods
      public void WriteToConsole() 
      {
        WriteLine($"{Name} was born on a {DateOfBirth:dddd}.");
      }
    } 
    ```

1.  在`PeopleApp`项目中，添加对`PacktLibrary`的项目引用，如以下标记中突出显示的那样：

    ```cs
    <Project Sdk="Microsoft.NET.Sdk">
      <PropertyGroup>
        <OutputType>Exe</OutputType>
        <TargetFramework>net6.0</TargetFramework>
        <Nullable>enable</Nullable>
        <ImplicitUsings>enable</ImplicitUsings>
      </PropertyGroup>
     **<ItemGroup>**
     **<ProjectReference**
     **Include=****"..\PacktLibrary\PacktLibrary.csproj"** **/>**
     **</ItemGroup>**
    </Project> 
    ```

1.  构建`PeopleApp`项目并注意输出，表明两个项目都已成功构建。

# 更多关于方法的内容

我们可能希望两个`Person`实例能够繁殖。我们可以通过编写方法来实现这一点。实例方法是对象对自己执行的操作；静态方法是类型执行的操作。

选择哪种方式取决于哪种对行动最有意义。

**最佳实践**：同时拥有静态方法和实例方法来执行类似操作通常是有意义的。例如，`string`类型既有`Compare`静态方法，也有`CompareTo`实例方法。这使得使用你的类型的程序员能够选择如何使用这些功能，为他们提供了更多的灵活性。

## 通过方法实现功能

让我们先通过使用静态和实例方法来实现一些功能：

1.  向`Person`类添加一个实例方法和一个静态方法，这将允许两个`Person`对象繁衍后代，如下面的代码所示：

    ```cs
    // static method to "multiply"
    public static Person Procreate(Person p1, Person p2)
    {
      Person baby = new()
      {
        Name = $"Baby of {p1.Name} and {p2.Name}"
      };
      p1.Children.Add(baby);
      p2.Children.Add(baby);
      return baby;
    }
    // instance method to "multiply"
    public Person ProcreateWith(Person partner)
    {
      return Procreate(this, partner);
    } 
    ```

    注意以下内容：

    +   在名为`Procreate`的`static`方法中，要繁衍后代的`Person`对象作为参数`p1`和`p2`传递。

    +   一个新的`Person`类名为`baby`，其名字由繁衍后代的两个人的名字组合而成。这可以通过设置返回的`baby`变量的`Name`属性来稍后更改。

    +   `baby`对象被添加到两个父母的`Children`集合中，然后返回。类是引用类型，意味着在内存中存储的`baby`对象的引用被添加，而不是`baby`对象的克隆。你将在本章后面学习引用类型和值类型之间的区别。

    +   在名为`ProcreateWith`的实例方法中，要与之繁衍后代的`Person`对象作为参数`partner`传递，它与`this`一起被传递给静态`Procreate`方法以重用方法实现。`this`是一个关键字，它引用当前类的实例。

    **最佳实践**：创建新对象或修改现有对象的方法应返回对该对象的引用，以便调用者可以访问结果。

1.  在`PeopleApp`项目中，在`Program.cs`文件的顶部，删除注释并导入我们的`Person`类和静态导入`Console`类型，如下面的代码所示：

    ```cs
    using Packt.Shared;
    using static System.Console; 
    ```

1.  在`Program.cs`中，创建三个人并让他们相互繁衍后代，注意要在`string`中添加双引号字符，你必须在其前面加上反斜杠字符，如下所示，`\"`，如下面的代码所示：

    ```cs
    Person harry = new() { Name = "Harry" }; 
    Person mary = new() { Name = "Mary" }; 
    Person jill = new() { Name = "Jill" };
    // call instance method
    Person baby1 = mary.ProcreateWith(harry); 
    baby1.Name = "Gary";
    // call static method
    Person baby2 = Person.Procreate(harry, jill);
    WriteLine($"{harry.Name} has {harry.Children.Count} children."); 
    WriteLine($"{mary.Name} has {mary.Children.Count} children."); 
    WriteLine($"{jill.Name} has {jill.Children.Count} children."); 
    WriteLine(
      format: "{0}'s first child is named \"{1}\".",
      arg0: harry.Name,
      arg1: harry.Children[0].Name); 
    ```

1.  运行代码并查看结果，如下面的输出所示：

    ```cs
    Harry has 2 children. 
    Mary has 1 children. 
    Jill has 1 children.
    Harry's first child is named "Gary". 
    ```

## 通过运算符实现功能

`System.String`类有一个名为`Concat`的`static`方法，它将两个字符串值连接起来并返回结果，如下面的代码所示：

```cs
string s1 = "Hello "; 
string s2 = "World!";
string s3 = string.Concat(s1, s2); 
WriteLine(s3); // Hello World! 
```

调用像`Concat`这样的方法是可以的，但对程序员来说，使用`+`符号运算符将两个`string`值“相加”可能更自然，如下面的代码所示：

```cs
string s3 = s1 + s2; 
```

一句广为人知的圣经格言是*去繁衍后代*，意指生育。让我们编写代码，使得`*`（乘法）符号能让两个`Person`对象繁衍后代。

我们通过为`*`符号定义一个`static`运算符来实现这一点。语法类似于方法，因为实际上，运算符*就是*一个方法，但使用符号代替方法名，使得语法更为简洁。

1.  在`Person.cs`中，创建一个`static`运算符用于`*`符号，如下所示：

    ```cs
    // operator to "multiply"
    public static Person operator *(Person p1, Person p2)
    {
      return Person.Procreate(p1, p2);
    } 
    ```

    **良好实践**：与方法不同，运算符不会出现在类型的 IntelliSense 列表中。对于您定义的每个运算符，都应同时创建一个方法，因为程序员可能不清楚该运算符可用。运算符的实现可以调用该方法，重用您编写的代码。提供方法的第二个原因是并非所有语言编译器都支持运算符；例如，尽管 Visual Basic 和 F#支持诸如*之类的算术运算符，但没有要求其他语言支持 C#支持的所有运算符。

1.  在`Program.cs`中，在调用`Procreate`方法和向控制台写入语句之前，使用`*`运算符再制造一个婴儿，如下所示：

    ```cs
    // call static method
    Person baby2 = Person.Procreate(harry, jill);
    **// call an operator**
    **Person baby3 = harry * mary;** 
    ```

1.  运行代码并查看结果，如下所示：

    ```cs
    Harry has 3 children. 
    Mary has 2 children. 
    Jill has 1 children.
    Harry's first child is named "Gary". 
    ```

## 使用局部函数实现功能

C# 7.0 引入的一个语言特性是能够定义**局部函数**。

局部函数相当于方法中的局部变量。换句话说，它们是仅在其定义的包含方法内部可访问的方法。在其他语言中，它们有时被称为**嵌套**或**内部函数**。

局部函数可以在方法内的任何位置定义：顶部、底部，甚至中间的某个位置！

我们将使用局部函数来实现阶乘计算：

1.  在`Person.cs`中，添加语句以定义一个`Factorial`函数，该函数在其内部使用局部函数来计算结果，如下所示：

    ```cs
    // method with a local function
    public static int Factorial(int number)
    {
      if (number < 0)
      {
        throw new ArgumentException(
          $"{nameof(number)} cannot be less than zero.");
      }
      return localFactorial(number);
      int localFactorial(int localNumber) // local function
      {
        if (localNumber < 1) return 1;
        return localNumber * localFactorial(localNumber - 1);
      }
    } 
    ```

1.  在`Program.cs`中，添加一条语句以调用`Factorial`函数并将返回值写入控制台，如下所示：

    ```cs
    WriteLine($"5! is {Person.Factorial(5)}"); 
    ```

1.  运行代码并查看结果，如下所示：

    ```cs
    5! is 120 
    ```

# 引发和处理事件

方法通常被描述为*对象可以执行的动作，无论是对自己还是对相关对象*。例如，`List<T>`可以向自身添加项目或清除自身，而`File`可以在文件系统中创建或删除文件。

事件通常被描述为*发生在对象上的动作*。例如，在用户界面中，`Button`有一个`Click`事件，点击是发生在按钮上的事情，而`FileSystemWatcher`监听文件系统的更改通知并引发`Created`和`Deleted`等事件，这些事件在目录或文件更改时触发。

另一种思考事件的方式是，它们提供了一种在两个对象之间交换消息的方法。

事件基于**委托**构建，因此让我们先了解一下委托是什么以及它们如何工作。

## 使用委托调用方法

你已经看到了调用或执行方法的最常见方式：使用 `.` 运算符通过其名称访问该方法。例如，`Console.WriteLine` 告诉 `Console` 类型访问其 `WriteLine` 方法。

调用或执行方法的另一种方式是使用委托。如果你使用过支持**函数指针**的语言，那么可以将委托视为**类型安全的方法指针**。

换句话说，委托包含与委托具有相同签名的方法的内存地址，以便可以安全地使用正确的参数类型调用它。

例如，假设 `Person` 类中有一个方法，它必须接受一个 `string` 类型的唯一参数，并返回一个 `int` 类型，如下所示：

```cs
public int MethodIWantToCall(string input)
{
  return input.Length; // it doesn't matter what the method does
} 
```

我可以在名为 `p1` 的 `Person` 实例上调用此方法，如下所示：

```cs
int answer = p1.MethodIWantToCall("Frog"); 
```

或者，我可以定义一个与签名匹配的委托来间接调用该方法。请注意，参数的名称不必匹配。只有参数类型和返回值必须匹配，如下所示：

```cs
delegate int DelegateWithMatchingSignature(string s); 
```

现在，我可以创建一个委托实例，将其指向该方法，最后，调用该委托（即调用该方法），如下所示：

```cs
// create a delegate instance that points to the method
DelegateWithMatchingSignature d = new(p1.MethodIWantToCall);
// call the delegate, which calls the method
int answer2 = d("Frog"); 
```

你可能会想，“这有什么意义？”嗯，它提供了灵活性。

例如，我们可以使用委托来创建一个方法队列，这些方法需要按顺序调用。在服务中排队执行操作以提供更好的可扩展性是很常见的。

另一个例子是允许多个操作并行执行。委托内置支持异步操作，这些操作在不同的线程上运行，并且可以提供更好的响应性。你将在*第十二章*，*使用多任务提高性能和可扩展性*中学习如何做到这一点。

最重要的例子是，委托允许我们实现事件，以便在不需要相互了解的不同对象之间发送消息。事件是组件之间松散耦合的一个例子，因为组件不需要了解彼此，它们只需要知道事件签名。

委托和事件是 C# 中最令人困惑的两个特性，可能需要几次尝试才能理解，所以如果你感到迷茫，不要担心！

## 定义和处理委托

Microsoft 为事件提供了两个预定义的委托，其签名简单而灵活，如下所示：

```cs
public delegate void EventHandler(
  object? sender, EventArgs e);
public delegate void EventHandler<TEventArgs>(
  object? sender, TEventArgs e); 
```

**最佳实践**：当你想在自己的类型中定义一个事件时，你应该使用这两个预定义委托之一。

让我们来探索委托和事件：

1.  向 `Person` 类添加语句，并注意以下几点，如下所示：

    +   它定义了一个名为 `Shout` 的 `EventHandler` 委托字段。

    +   它定义了一个 `int` 字段来存储 `AngerLevel`。

    +   它定义了一个名为 `Poke` 的方法。

    +   每次有人被戳时，他们的`AngerLevel`都会增加。一旦他们的`AngerLevel`达到三，他们就会引发`Shout`事件，但前提是至少有一个事件委托指向代码中其他地方定义的方法；也就是说，它不是`null`：

    ```cs
    // delegate field
    public EventHandler? Shout;
    // data field
    public int AngerLevel;
    // method
    public void Poke()
    {
      AngerLevel++;
      if (AngerLevel >= 3)
      {
        // if something is listening...
        if (Shout != null)
        {
          // ...then call the delegate
          Shout(this, EventArgs.Empty);
        }
      }
    } 
    ```

    在调用其方法之前检查对象是否不为`null`是非常常见的。C# 6.0 及更高版本允许使用`?`符号在`.`运算符之前简化内联的`null`检查，如以下代码所示：

    ```cs
    Shout?.Invoke(this, EventArgs.Empty); 
    ```

1.  在`Program.cs`底部，添加一个具有匹配签名的方法，该方法从`sender`参数获取`Person`对象的引用，并输出有关他们的信息，如以下代码所示：

    ```cs
    static void Harry_Shout(object? sender, EventArgs e)
    {
      if (sender is null) return;
      Person p = (Person)sender;
      WriteLine($"{p.Name} is this angry: {p.AngerLevel}.");
    } 
    ```

    微软对于处理事件的方法命名的约定是`对象名 _ 事件名`。

1.  在`Program.cs`中，添加一条语句，将方法分配给委托字段，如以下代码所示：

    ```cs
    harry.Shout = Harry_Shout; 
    ```

1.  在将方法分配给`Shout`事件后，添加语句调用`Poke`方法四次，如以下突出显示的代码所示：

    ```cs
    harry.Shout = Harry_Shout;
    **harry.Poke();**
    **harry.Poke();**
    **harry.Poke();**
    **harry.Poke();** 
    ```

1.  运行代码并查看结果，注意哈利在前两次被戳时什么也没说，只有在被戳至少三次后才足够生气以至于大喊，如以下输出所示：

    ```cs
    Harry is this angry: 3\. 
    Harry is this angry: 4. 
    ```

## 定义和处理事件

你现在看到了委托如何实现事件最重要的功能：定义一个方法签名，该签名可以由完全不同的代码块实现，然后调用该方法以及连接到委托字段的其他任何方法。

那么事件呢？它们可能比你想象的要简单。

在将方法分配给委托字段时，不应使用我们在前述示例中使用的简单赋值运算符。

委托是多播的，这意味着你可以将多个委托分配给单个委托字段。我们本可以使用`+=`运算符而不是`=`赋值，这样我们就可以向同一个委托字段添加更多方法。当委托被调用时，所有分配的方法都会被调用，尽管你无法控制它们被调用的顺序。

如果`Shout`委托字段已经引用了一个或多个方法，通过分配一个方法，它将替换所有其他方法。对于用于事件的委托，我们通常希望确保程序员仅使用`+=`运算符或`-=`运算符来分配和移除方法：

1.  为了强制执行这一点，在`Person.cs`中，将`event`关键字添加到委托字段声明中，如以下突出显示的代码所示：

    ```cs
    public **event** EventHandler? Shout; 
    ```

1.  构建`PeopleApp`项目，并注意编译器错误消息，如以下输出所示：

    ```cs
    Program.cs(41,13): error CS0079: The event 'Person.Shout' can only appear on the left hand side of += or -= 
    ```

    这就是`event`关键字所做的（几乎）所有事情！如果你永远不会将一个以上的方法分配给委托字段，那么从技术上讲，你不需要“事件”，但仍然是一种良好的实践，表明你的意图，并期望委托字段被用作事件。

1.  将方法赋值修改为使用`+=`，如下列代码所示：

    ```cs
    harry.Shout += Harry_Shout; 
    ```

1.  运行代码并注意它具有与之前相同的行为。

# 通过泛型安全地重用类型

2005 年，随着 C# 2.0 和.NET Framework 2.0 的推出，微软引入了一项名为**泛型**的功能，它使你的类型能更安全地重用且更高效。它通过允许程序员传递类型作为参数来实现这一点，类似于你可以传递对象作为参数的方式。

## 使用非泛型类型

首先，让我们看一个使用非泛型类型的例子，以便你能理解泛型旨在解决的问题，例如弱类型参数和值，以及使用`System.Object`导致性能问题。

`System.Collections.Hashtable`可用于存储多个值，每个值都有一个唯一键，稍后可用于快速查找其值。键和值都可以是任何对象，因为它们被声明为`System.Object`。虽然这为存储整数等值类型提供了灵活性，但它速度慢，且更容易引入错误，因为添加项时不会进行类型检查。

让我们写一些代码：

1.  在`Program.cs`中，创建一个非泛型集合`System.Collections.Hashtable`的实例，然后添加四个项，如下列代码所示：

    ```cs
    // non-generic lookup collection
    System.Collections.Hashtable lookupObject = new();
    lookupObject.Add(key: 1, value: "Alpha");
    lookupObject.Add(key: 2, value: "Beta");
    lookupObject.Add(key: 3, value: "Gamma");
    lookupObject.Add(key: harry, value: "Delta"); 
    ```

1.  添加语句定义一个值为`2`的`key`，并使用它在哈希表中查找其值，如下列代码所示：

    ```cs
    int key = 2; // lookup the value that has 2 as its key
    WriteLine(format: "Key {0} has value: {1}",
      arg0: key,
      arg1: lookupObject[key]); 
    ```

1.  添加语句使用`harry`对象查找其值，如下列代码所示：

    ```cs
    // lookup the value that has harry as its key
    WriteLine(format: "Key {0} has value: {1}",
      arg0: harry,
      arg1: lookupObject[harry]); 
    ```

1.  运行代码并注意它按预期工作，如下列输出所示：

    ```cs
    Key 2 has value: Beta
    Key Packt.Shared.Person has value: Delta 
    ```

尽管代码能运行，但存在出错的可能性，因为实际上任何类型都可以用作键或值。如果其他开发人员使用了你的查找对象，并期望所有项都是特定类型，他们可能会将其强制转换为该类型，并因某些值可能为不同类型而引发异常。包含大量项的查找对象也会导致性能不佳。

**良好实践**：避免使用`System.Collections`命名空间中的类型。

## 使用泛型类型

`System.Collections.Generic.Dictionary<TKey, TValue>`可用于存储多个值，每个值都有一个唯一键，稍后可用于快速查找其值。键和值可以是任何对象，但你必须在首次实例化集合时告诉编译器键和值的类型。你通过在尖括号`<>`中指定**泛型参数**的类型来实现这一点，即`TKey`和`TValue`。

**良好实践**：当泛型类型有一个可定义的类型时，应将其命名为`T`，例如`List<T>`，其中`T`是列表中存储的类型。当泛型类型有多个可定义的类型时，应使用`T`作为名称前缀，并取一个合理的名称，例如`Dictionary<TKey, TValue>`。

这提供了灵活性，速度更快，且更容易避免错误，因为添加项时会进行类型检查。

让我们编写一些代码，使用泛型来解决问题：

1.  在`Program.cs`中，创建泛型查找集合`Dictionary<TKey, TValue>`的实例，然后添加四个项目，如下面的代码所示：

    ```cs
    // generic lookup collection
    Dictionary<int, string> lookupIntString = new();
    lookupIntString.Add(key: 1, value: "Alpha");
    lookupIntString.Add(key: 2, value: "Beta");
    lookupIntString.Add(key: 3, value: "Gamma");
    lookupIntString.Add(key: harry, value: "Delta"); 
    ```

1.  注意使用`harry`作为键时出现的编译错误，如下面的输出所示：

    ```cs
    /Users/markjprice/Code/Chapter06/PeopleApp/Program.cs(98,32): error CS1503: Argument 1: cannot convert from 'Packt.Shared.Person' to 'int' [/Users/markjprice/Code/Chapter06/PeopleApp/PeopleApp.csproj] 
    ```

1.  将`harry`替换为`4`。

1.  添加语句将`key`设置为`3`，并使用它在字典中查找其值，如下面的代码所示：

    ```cs
    key = 3;
    WriteLine(format: "Key {0} has value: {1}",
      arg0: key,
      arg1: lookupIntString[key]); 
    ```

1.  运行代码并注意它按预期工作，如下面的输出所示：

    ```cs
    Key 3 has value: Gamma 
    ```

# 实现接口

接口是一种将不同类型连接起来以创建新事物的方式。将它们想象成乐高™积木顶部的凸起，使它们能够“粘合”在一起，或者是插头和插座的电气标准。

如果类型实现了接口，那么它就是在向.NET 的其余部分承诺它支持特定的功能。这就是为什么它们有时被描述为合同。

## 常见接口

以下是您的类型可能需要实现的一些常见接口：

| 接口 | 方法 | 描述 |
| --- | --- | --- |
| `IComparable` | `CompareTo(other)` | 这定义了一个比较方法，类型通过该方法实现对其实例的排序。 |
| `IComparer` | `Compare(first, second)` | 这定义了一个比较方法，辅助类型通过该方法实现对主类型实例的排序。 |
| `IDisposable` | `Dispose()` | 这定义了一个处置方法，以更有效地释放非托管资源，而不是等待终结器（有关详细信息，请参阅本章后面的*释放非托管资源*部分）。 |
| `IFormattable` | `ToString(format, culture)` | 这定义了一个文化感知的方法，将对象的值格式化为字符串表示。 |
| `IFormatter` | `Serialize(stream, object)``Deserialize(stream)` | 这定义了将对象转换为字节流以及从字节流转换回对象的方法，用于存储或传输。 |
| `IFormatProvider` | `GetFormat(type)` | 这定义了一个根据语言和区域格式化输入的方法。 |

## 排序时比较对象

您最常想要实现的接口之一是`IComparable`。它有一个名为`CompareTo`的方法。它有两种变体，一种适用于可空`object`类型，另一种适用于可空泛型类型`T`，如下面的代码所示：

```cs
namespace System
{
  public interface IComparable
  {
    int CompareTo(object? obj);
  }
  public interface IComparable<in T>
  {
    int CompareTo(T? other);
  }
} 
```

例如，`string`类型通过返回`-1`（如果`string`小于被比较的`string`）或`1`（如果它更大）来实现`IComparable`。`int`类型通过返回`-1`（如果`int`小于被比较的`int`）或`1`（如果它更大）来实现`IComparable`。

如果类型实现了`IComparable`接口之一，那么数组和集合就可以对其进行排序。

在我们为`Person`类实现`IComparable`接口及其`CompareTo`方法之前，让我们看看当我们尝试对`Person`实例数组进行排序时会发生什么：

1.  在`Program.cs`中，添加语句以创建`Person`实例的数组，并将项目写入控制台，然后尝试对数组进行排序，并将项目再次写入控制台，如下面的代码所示：

    ```cs
    Person[] people =
    {
      new() { Name = "Simon" },
      new() { Name = "Jenny" },
      new() { Name = "Adam" },
      new() { Name = "Richard" }
    };
    WriteLine("Initial list of people:"); 
    foreach (Person p in people)
    {
      WriteLine($"  {p.Name}");
    }
    WriteLine("Use Person's IComparable implementation to sort:");
    Array.Sort(people);
    foreach (Person p in people)
    {
      WriteLine($"  {p.Name}");
    } 
    ```

1.  运行代码，将会抛出异常。正如消息所述，要解决问题，我们的类型必须实现`IComparable`，如下面的输出所示：

    ```cs
    Unhandled Exception: System.InvalidOperationException: Failed to compare two elements in the array. ---> System.ArgumentException: At least one object must implement IComparable. 
    ```

1.  在`Person.cs`中，在继承自`object`之后，添加一个逗号并输入`IComparable<Person>`，如下面的代码所示：

    ```cs
    public class Person : object, IComparable<Person> 
    ```

    你的代码编辑器会在新代码下方画一条红色波浪线，警告你尚未实现承诺的方法。点击灯泡并选择**实现接口**选项，你的代码编辑器可以为你编写骨架实现。

1.  向下滚动至`Person`类的底部，找到为你编写的方法，并删除抛出`NotImplementedException`错误的语句，如以下代码中突出显示的部分所示：

    ```cs
    public int CompareTo(Person? other)
    {
    **throw****new** **NotImplementedException();**
    } 
    ```

1.  添加一条语句以调用`Name`字段的`CompareTo`方法，该方法使用`string`类型的`CompareTo`实现并返回结果，如下面的代码中突出显示的部分所示：

    ```cs
    public int CompareTo(Person? other)
    {
      if (Name is null) return 0;
    **return** **Name.CompareTo(other?.Name);** 
    } 
    ```

    我们选择通过比较`Person`实例的`Name`字段来比较两个`Person`实例。因此，`Person`实例将按其名称的字母顺序排序。为简单起见，我没有在这些示例中添加`null`检查。

1.  运行代码，并注意这次它按预期工作，如下面的输出所示：

    ```cs
    Initial list of people:
      Simon
      Jenny
      Adam
      Richard
    Use Person's IComparable implementation to sort:
      Adam
      Jenny
      Richard
      Simon 
    ```

**最佳实践**：如果有人想要对类型的数组或集合进行排序，那么请实现`IComparable`接口。

## 使用单独的类比较对象

有时，你可能无法访问类型的源代码，并且它可能未实现`IComparable`接口。幸运的是，还有另一种方法可以对类型的实例进行排序。你可以创建一个单独的类型，该类型实现一个略有不同的接口，名为`IComparer`：

1.  在`PacktLibrary`项目中，添加一个名为`PersonComparer.cs`的新类文件，其中包含一个实现`IComparer`接口的类，该接口将比较两个人，即两个`Person`实例。通过比较他们的`Name`字段的长度来实现它，如果名称长度相同，则按字母顺序比较名称，如下面的代码所示：

    ```cs
    namespace Packt.Shared;
    public class PersonComparer : IComparer<Person>
    {
      public int Compare(Person? x, Person? y)
      {
        if (x is null || y is null)
        {
          return 0;
        }
        // Compare the Name lengths...
        int result = x.Name.Length.CompareTo(y.Name.Length);
        // ...if they are equal...
        if (result == 0)
        {
          // ...then compare by the Names...
          return x.Name.CompareTo(y.Name);
        }
        else // result will be -1 or 1
        {
          // ...otherwise compare by the lengths.
          return result; 
        }
      }
    } 
    ```

1.  在`Program.cs`中，添加语句以使用此替代实现对数组进行排序，如下面的代码所示：

    ```cs
    WriteLine("Use PersonComparer's IComparer implementation to sort:"); 
    Array.Sort(people, new PersonComparer());
    foreach (Person p in people)
    {
      WriteLine($"  {p.Name}");
    } 
    ```

1.  运行代码并查看结果，如下面的输出所示：

    ```cs
    Use PersonComparer's IComparer implementation to sort:
      Adam
      Jenny
      Simon
      Richard 
    ```

这次，当我们对`people`数组进行排序时，我们明确要求排序算法使用`PersonComparer`类型，以便人们按名字最短的先排序，如 Adam，名字最长的后排序，如 Richard；当两个或多个名字长度相等时，按字母顺序排序，如 Jenny 和 Simon。

## 隐式与显式接口实现

接口可以隐式和显式实现。隐式实现更简单、更常见。只有当类型必须具有具有相同名称和签名的多个方法时，才需要显式实现。

例如，`IGamePlayer`和`IKeyHolder`可能都有一个名为`Lose`的方法，参数相同，因为游戏和钥匙都可能丢失。在必须实现这两个接口的类型中，只能有一个`Lose`方法作为隐式方法。如果两个接口可以共享相同的实现，那很好，但如果不能，则另一个`Lose`方法必须以不同的方式实现并显式调用，如下所示：

```cs
public interface IGamePlayer
{
  void Lose();
}
public interface IKeyHolder
{
  void Lose();
}
public class Person : IGamePlayer, IKeyHolder
{
  public void Lose() // implicit implementation
  {
    // implement losing a key
  }
  void IGamePlayer.Lose() // explicit implementation
  {
    // implement losing a game
  }
}
// calling implicit and explicit implementations of Lose
Person p = new();
p.Lose(); // calls implicit implementation of losing a key
((IGamePlayer)p).Lose(); // calls explicit implementation of losing a game
IGamePlayer player = p as IGamePlayer;
player.Lose(); // calls explicit implementation of losing a game 
```

## 定义具有默认实现的接口

C# 8.0 引入的一项语言特性是接口的**默认实现**。让我们看看它的实际应用：

1.  在`PacktLibrary`项目中，添加一个名为`IPlayable.cs`的新文件。

1.  修改语句以定义一个具有两个方法`Play`和`Pause`的公共`IPlayable`接口，如下所示：

    ```cs
    namespace Packt.Shared;
    public interface IPlayable
    {
      void Play();
      void Pause();
    } 
    ```

1.  在`PacktLibrary`项目中，添加一个名为`DvdPlayer.cs`的新类文件。

1.  修改文件中的语句以实现`IPlayable`接口，如下所示：

    ```cs
    using static System.Console;
    namespace Packt.Shared;
    public class DvdPlayer : IPlayable
    {
      public void Pause()
      {
        WriteLine("DVD player is pausing.");
      }
      public void Play()
      {
        WriteLine("DVD player is playing.");
      }
    } 
    ```

    这很有用，但如果我们决定添加一个名为`Stop`的第三个方法呢？在 C# 8.0 之前，一旦至少有一个类型实现了原始接口，这是不可能的。接口的主要特点之一是它是一个固定的契约。

    C# 8.0 允许接口在发布后添加新成员，只要它们具有默认实现。C#纯粹主义者可能不喜欢这个想法，但由于实用原因，例如避免破坏性更改或不得不定义一个全新的接口，它是有用的，其他语言如 Java 和 Swift 也启用了类似的技术。

    默认接口实现的支持需要对底层平台进行一些根本性的改变，因此只有在目标框架是.NET 5.0 或更高版本、.NET Core 3.0 或更高版本或.NET Standard 2.1 时，它们才受 C#支持。因此，它们不受.NET Framework 的支持。

1.  修改`IPlayable`接口以添加具有默认实现的`Stop`方法，如下所示突出显示：

    ```cs
    **using****static** **System.Console;**
    namespace Packt.Shared;
    public interface IPlayable
    {
      void Play();
      void Pause();
    **void****Stop****()** **// default interface implementation**
     **{**
     **WriteLine(****"Default implementation of Stop."****);**
     **}**
    } 
    ```

1.  构建`PeopleApp`项目并注意，尽管`DvdPlayer`类没有实现`Stop`，但项目仍能成功编译。将来，我们可以通过在`DvdPlayer`类中实现它来覆盖`Stop`的默认实现。

# 使用引用类型和值类型管理内存

我已经多次提到引用类型。让我们更详细地了解一下它们。

内存分为两类：**栈**内存和**堆**内存。在现代操作系统中，栈和堆可以在物理或虚拟内存的任何位置。

栈内存处理速度更快（因为它直接由 CPU 管理，并且采用后进先出机制，更有可能将数据保存在其 L1 或 L2 缓存中），但大小有限；而堆内存较慢，但资源丰富得多。

例如，在 macOS 终端中，我可以输入命令`ulimit -a`来发现栈大小被限制为 8192 KB，而其他内存则是“无限制”的。这种有限的栈内存量使得很容易填满它并导致“栈溢出”。

## 定义引用类型和值类型

定义对象类型时，可以使用三个 C#关键字：`class`、`record`和`struct`。它们都可以拥有相同的成员，如字段和方法。它们之间的一个区别在于内存分配方式。

当你使用`record`或`class`定义类型时，你定义的是**引用类型**。这意味着对象本身的内存是在堆上分配的，而只有对象的内存地址（以及少量开销）存储在栈上。

当你使用`record struct`或`struct`定义类型时，你定义的是**值类型**。这意味着对象本身的内存是在栈上分配的。

如果`struct`使用的字段类型不是`struct`类型，那么这些字段将存储在堆上，这意味着该对象的数据同时存储在栈和堆上！

以下是最常见的结构体类型：

+   **数字** `System` **类型**：`byte`、`sbyte`、`short`、`ushort`、`int`、`uint`、`long`、`ulong`、`float`、`double`和`decimal`

+   **其他** `System` **类型**：`char`、`DateTime`和`bool`

+   `System.Drawing` **类型**：`Color`、`Point`和`Rectangle`

几乎所有其他类型都是`class`类型，包括`string`。

除了类型数据在内存中存储位置的差异外，另一个主要区别是`struct`不支持继承。

## 引用类型和值类型在内存中的存储方式

想象一下，你有一个控制台应用程序，它声明了一些变量，如下面的代码所示：

```cs
int number1 = 49;
long number2 = 12;
System.Drawing.Point location = new(x: 4, y: 5);
Person kevin = new() { Name = "Kevin", 
  DateOfBirth = new(year: 1988, month: 9, day: 23) };
Person sally; 
```

让我们回顾一下执行这些语句时栈和堆上分配的内存，如*图 6.1*所示，并按以下列表描述：

+   `number1`变量是值类型（也称为`struct`），因此它在栈上分配，由于它是 32 位整数，所以占用 4 字节内存。其值 49 直接存储在变量中。

+   `number2`变量也是值类型，因此它也在栈上分配，由于它是 64 位整数，所以占用 8 字节。

+   `location`变量也是值类型，因此它在栈上分配，由于它由两个 32 位整数`x`和`y`组成，所以占用 8 字节。

+   `kevin`变量是引用类型（也称为`class`），因此在栈上分配了 64 位内存地址所需的 8 字节（假设是 64 位操作系统），并在堆上分配了足够字节来存储`Person`实例。

+   `sally`变量是引用类型，因此在 64 位内存地址的栈上分配了 8 字节。目前它为`null`，意味着堆上尚未为其分配内存。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_06_01.png)

图 6.1：值类型和引用类型在栈和堆上的分配方式

引用类型的所有已分配内存都存储在堆上。如果值类型如`DateTime`被用作引用类型如`Person`的字段，那么`DateTime`值将存储在堆上。

如果值类型有一个引用类型的字段，那么该部分值类型将存储在堆上。`Point`是一个值类型，由两个字段组成，这两个字段本身也是值类型，因此整个对象可以在栈上分配。如果`Point`值类型有一个引用类型的字段，如`string`，那么`string`字节将存储在堆上。

## 类型相等性

通常使用`==`和`!=`运算符比较两个变量。这两个运算符对于引用类型和值类型的行为是不同的。

当你检查两个值类型变量的相等性时，.NET 会直接比较这两个变量在栈上的值，如果它们相等，则返回`true`，如下列代码所示：

```cs
int a = 3;
int b = 3;
WriteLine($"a == b: {(a == b)}"); // true 
```

当你检查两个引用类型变量的相等性时，.NET 会比较这两个变量的内存地址，如果它们相等，则返回`true`，如下列代码所示：

```cs
Person a = new() { Name = "Kevin" };
Person b = new() { Name = "Kevin" };
WriteLine($"a == b: {(a == b)}"); // false 
```

这是因为它们并非同一对象。如果两个变量确实指向堆上的同一对象，那么它们将被视为相等，如下列代码所示：

```cs
Person a = new() { Name = "Kevin" };
Person b = a;
WriteLine($"a == b: {(a == b)}"); // true 
```

此行为的一个例外是`string`类型。它虽是引用类型，但其相等运算符已被重载，使其表现得如同值类型一般，如下列代码所示：

```cs
string a = "Kevin";
string b = "Kevin";
WriteLine($"a == b: {(a == b)}"); // true 
```

你可以对你的类进行类似操作，使相等运算符即使在它们不是同一对象（即堆上同一内存地址）时也返回`true`，只要它们的字段具有相同值即可，但这超出了本书的范围。或者，使用`record class`，因为它们的一个好处是为你实现了这种行为。

## 定义结构类型

让我们来探讨如何定义自己的值类型：

1.  在`PacktLibrary`项目中，添加一个名为`DisplacementVector.cs`的文件。

1.  按照下列代码所示修改文件，并注意以下事项：

    +   该类型使用`struct`声明而非`class`。

    +   它有两个名为`X`和`Y`的`int`字段。

    +   它有一个构造函数，用于设置`X`和`Y`的初始值。

    +   它有一个运算符，用于将两个实例相加，返回一个新实例，其中`X`与`X`相加，`Y`与`Y`相加。

    ```cs
    namespace Packt.Shared;
    public struct DisplacementVector
    {
      public int X;
      public int Y;
      public DisplacementVector(int initialX, int initialY)
      {
        X = initialX;
        Y = initialY;
      }
      public static DisplacementVector operator +(
        DisplacementVector vector1,
        DisplacementVector vector2)
      {
        return new(
          vector1.X + vector2.X,
          vector1.Y + vector2.Y);
      }
    } 
    ```

1.  在`Program.cs`文件中，添加语句以创建两个新的`DisplacementVector`实例，将它们相加，并输出结果，如下列代码所示：

    ```cs
    DisplacementVector dv1 = new(3, 5); 
    DisplacementVector dv2 = new(-2, 7); 
    DisplacementVector dv3 = dv1 + dv2;
    WriteLine($"({dv1.X}, {dv1.Y}) + ({dv2.X}, {dv2.Y}) = ({dv3.X}, {dv3.Y})"); 
    ```

1.  运行代码并查看结果，如下列输出所示：

    ```cs
    (3, 5) + (-2, 7) = (1, 12) 
    ```

**最佳实践**：如果类型中所有字段占用的总字节数不超过 16 字节，且仅使用值类型作为字段，并且你永远不希望从该类型派生，那么微软建议使用`struct`。如果你的类型使用的堆栈内存超过 16 字节，使用引用类型作为字段，或者可能希望继承它，那么应使用`class`。

## 处理记录结构类型

C# 10 引入了使用`record`关键字与`struct`类型以及`class`类型一起使用的能力。

我们可以定义`DisplacementVector`类型，如下列代码所示：

```cs
public record struct DisplacementVector(int X, int Y); 
```

即使`class`关键字可选，微软仍建议在定义`record class`时明确指定`class`，如下列代码所示：

```cs
public record class ImmutableAnimal(string Name); 
```

## 释放非托管资源

在前一章中，我们了解到构造器可用于初始化字段，且一个类型可以有多个构造器。设想一个构造器分配了一个非托管资源，即不由.NET 控制的任何资源，如操作系统控制下的文件或互斥体。由于.NET 无法使用其自动垃圾回收功能为我们释放这些资源，我们必须手动释放非托管资源。

垃圾回收是一个高级话题，因此对于这个话题，我将展示一些代码示例，但你无需亲自编写代码。

每种类型都可以有一个单一的**终结器**，当资源需要被释放时，.NET 运行时会调用它。终结器的名称与构造器相同，即类型名称，但前面加了一个波浪线`~`。

不要将终结器（也称为**析构器**）与`Deconstruct`方法混淆。析构器释放资源，即它在内存中销毁一个对象。`Deconstruct`方法将对象分解为其组成部分，并使用 C#解构语法，例如在处理元组时：

```cs
public class Animal
{
  public Animal() // constructor
  {
    // allocate any unmanaged resources
  }
  ~Animal() // Finalizer aka destructor
  {
    // deallocate any unmanaged resources
  }
} 
```

前面的代码示例是在处理非托管资源时你应做的最低限度。但仅提供终结器的问题在于，.NET 垃圾回收器需要两次垃圾回收才能完全释放该类型分配的资源。

虽然可选，但建议提供一个方法，让使用你类型的开发者能明确释放资源，以便垃圾回收器可以立即且确定性地释放非托管资源（如文件）的托管部分，并在一次垃圾回收中释放对象的托管内存部分，而不是经过两次垃圾回收。

通过实现`IDisposable`接口，有一个标准机制可以做到这一点，如下例所示：

```cs
public class Animal : IDisposable
{
  public Animal()
  {
    // allocate unmanaged resource
  }
  ~Animal() // Finalizer
  {
    Dispose(false);
  }
  bool disposed = false; // have resources been released?
  public void Dispose()
  {
    Dispose(true);
    // tell garbage collector it does not need to call the finalizer
    GC.SuppressFinalize(this); 
  }
  protected virtual void Dispose(bool disposing)
  {
    if (disposed) return;
    // deallocate the *unmanaged* resource
    // ...
    if (disposing)
    {
      // deallocate any other *managed* resources
      // ...
    }
    disposed = true;
  }
} 
```

存在两个`Dispose`方法，一个`public`，一个`protected`：

+   `public void Dispose`方法将由使用你类型的开发者调用。当被调用时，无论是非托管资源还是托管资源都需要被释放。

+   `protected virtual void Dispose`方法带有一个`bool`参数，内部用于实现资源的释放。它需要检查`disposing`参数和`disposed`字段，因为如果终结器线程已经运行并调用了`~Animal`方法，那么只需要释放非托管资源。

调用`GC.SuppressFinalize(this)`是为了通知垃圾收集器不再需要运行终结器，从而消除了进行第二次垃圾收集的需求。

## 确保 Dispose 方法被调用

当有人使用实现了`IDisposable`的类型时，他们可以使用`using`语句确保调用公共`Dispose`方法，如下列代码所示：

```cs
using (Animal a = new())
{
  // code that uses the Animal instance
} 
```

编译器将你的代码转换成类似下面的形式，这保证了即使发生异常，`Dispose`方法仍然会被调用：

```cs
Animal a = new(); 
try
{
  // code that uses the Animal instance
}
finally
{
  if (a != null) a.Dispose();
} 
```

你将在*第九章*，*文件、流和序列化操作*中看到使用`IDisposable`、`using`语句以及`try`...`finally`块释放非托管资源的实际示例。

# 处理 null 值

你已经知道如何在`struct`变量中存储像数字这样的基本值。但如果一个变量还没有值呢？我们该如何表示这种情况？C#中有一个`null`值的概念，可以用来表示变量尚未被赋值。

## 使值类型可空

默认情况下，像`int`和`DateTime`这样的值类型必须始终有值，因此得名。有时，例如在读取数据库中允许空、缺失或`null`值存储的值时，允许值类型为`null`会很方便。我们称这种类型为**可空值类型**。

你可以通过在声明变量时在类型后添加问号后缀来启用此功能。

让我们来看一个例子：

1.  使用你偏好的编程工具，在`Chapter06`工作区/解决方案中添加一个名为`NullHandling`的**控制台应用程序**。本节需要一个完整的应用程序，包含项目文件，因此你无法使用.NET Interactive 笔记本。

1.  在 Visual Studio Code 中，选择`NullHandling`作为活动的 OmniSharp 项目。在 Visual Studio 中，将`NullHandling`设置为启动项目。

1.  在`Program.cs`中，输入声明并赋值的语句，包括`null`，给`int`变量，如下列代码所示：

    ```cs
    int thisCannotBeNull  = 4; 
    thisCannotBeNull = null; // compile error!
    int? thisCouldBeNull = null; 
    WriteLine(thisCouldBeNull); 
    WriteLine(thisCouldBeNull.GetValueOrDefault());
    thisCouldBeNull = 7; 
    WriteLine(thisCouldBeNull); 
    WriteLine(thisCouldBeNull.GetValueOrDefault()); 
    ```

1.  注释掉导致编译错误的语句。

1.  运行代码并查看结果，如下列输出所示：

    ```cs
    0
    7
    7 
    ```

第一行是空白的，因为它输出了`null`值！

## 理解可空引用类型

在众多语言中，`null`值的使用非常普遍，以至于许多经验丰富的程序员从未质疑过其存在的必要性。但在许多情况下，如果我们不允许变量具有`null`值，就能编写出更优、更简洁的代码。

C# 8 中最显著的语言变化是引入了可空和不可空的引用类型。“但是等等！”你可能会想，“引用类型不是已经可空了吗！”

您说得没错，但在 C# 8 及更高版本中，引用类型可以通过设置文件级或项目级选项来配置，不再允许`null`值，从而启用这一有用的新特性。由于这对 C#来说是一个重大变化，微软决定让该功能为可选。

由于成千上万的现有库包和应用程序期望旧的行为，这项新的 C#语言特性需要多年时间才能产生影响。即使是微软，也直到.NET 6 才在所有主要的.NET 包中完全实现这一新特性。

在过渡期间，您可以为您的项目选择几种方法之一：

+   **默认**：无需更改。不支持不可空的引用类型。

+   **项目级选择加入，文件级选择退出**：在项目级别启用该功能，并为需要与旧行为保持兼容的任何文件选择退出。这是微软在更新其自己的包以使用此新功能时内部采用的方法。

+   **文件级选择加入**：仅对个别文件启用该功能。

## 启用可空和不可空的引用类型

要在项目级别启用该功能，请在项目文件中添加以下内容：

```cs
<PropertyGroup>
  ...
  <Nullable>enable</Nullable>
</PropertyGroup> 
```

这在面向.NET 6.0 的项目模板中现已默认完成。

要在文件级别禁用该功能，请在代码文件顶部添加以下内容：

```cs
#nullable disable 
```

要在文件级别启用该功能，请在代码文件顶部添加以下内容：

```cs
#nullable enable 
```

## 声明不可为空的变量和参数

如果您启用了可空引用类型，并且希望引用类型被赋予`null`值，那么您将不得不使用与使值类型可空相同的语法，即在类型声明后添加一个`?`符号。

那么，可空引用类型是如何工作的呢？让我们看一个例子。当存储地址信息时，您可能希望强制为街道、城市和地区提供值，但建筑可以留空，即`null`：

1.  在`NullHandling.csproj`中，在`Program.cs`文件底部，添加声明一个具有四个字段的`Address`类的语句，如下所示：

    ```cs
    class Address
    {
      public string? Building; 
      public string Street; 
      public string City; 
      public string Region;
    } 
    ```

1.  几秒钟后，注意关于不可为空的字段的警告，例如`Street`未初始化，如*图 6.2*所示：![Graphical user interface, text, application, chat or text message  Description automatically generated](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_06_02.png)

    图 6.2：PROBLEMS 窗口中关于不可为空的字段的警告信息

1.  将空`string`值分配给三个不可为空的字段中的每一个，如下所示：

    ```cs
    public string Street = string.Empty; 
    public string City = string.Empty; 
    public string Region = string.Empty; 
    ```

1.  在`Program.cs`中，在文件顶部，静态导入`Console`，然后添加语句来实例化一个`Address`并设置其属性，如下所示：

    ```cs
    Address address = new(); 
    address.Building = null; 
    address.Street = null; 
    address.City = "London"; 
    address.Region = null; 
    ```

1.  注意警告，如*图 6.3*所示：![图形用户界面，文本，应用程序，聊天或短信，电子邮件 自动生成描述](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_06_03.png)

    图 6.3：关于将 null 分配给不可空字段的警告消息

因此，这就是为什么新语言特性被命名为可空引用类型。从 C# 8.0 开始，未修饰的引用类型可以变为不可空，并且用于使引用类型可空的语法与用于值类型的语法相同。

## 检查是否为空

检查可空引用类型或可空值类型变量当前是否包含`null`很重要，因为如果不这样做，可能会抛出`NullReferenceException`，导致错误。在使用可空变量之前，应检查其是否为`null`，如下所示：

```cs
// check that the variable is not null before using it
if (thisCouldBeNull != null)
{
  // access a member of thisCouldBeNull
  int length = thisCouldBeNull.Length; // could throw exception
  ...
} 
```

C# 7 引入了`is`与`!`（非）运算符的组合作为`!=`的替代方案，如下所示：

```cs
if (!(thisCouldBeNull is null))
{ 
```

C# 9 引入了`is not`作为更清晰的替代方案，如下所示：

```cs
if (thisCouldBeNull is not null)
{ 
```

如果您尝试使用可能为`null`的变量的成员，请使用空条件运算符`?.`，如下所示：

```cs
string authorName = null;
// the following throws a NullReferenceException
int x = authorName.Length;
// instead of throwing an exception, null is assigned to y
int? y = authorName?.Length; 
```

有时您希望将变量分配给结果，或者如果变量为`null`，则使用备用值，例如`3`。您可以使用空合并运算符`??`执行此操作，如下所示：

```cs
// result will be 3 if authorName?.Length is null 
int result = authorName?.Length ?? 3; 
Console.WriteLine(result); 
```

**良好实践**：即使启用了可空引用类型，您仍应检查不可空参数是否为`null`并抛出`ArgumentNullException`。

### 在方法参数中检查是否为空

在定义带有参数的方法时，检查`null`值是良好的实践。

在早期版本的 C#中，您需要编写`if`语句来检查`null`参数值，并对任何为`null`的参数抛出`ArgumentNullException`，如下所示：

```cs
public void Hire(Person manager, Person employee)
{
  if (manager == null)
  {
    throw new ArgumentNullException(nameof(manager));
  }
  if (employee == null)
  {
    throw new ArgumentNullException(nameof(employee));
  }
  ...
} 
```

C# 11 可能会引入一个新的`!!`后缀，为您执行此操作，如下所示：

```cs
public void Hire(Person manager!!, Person employee!!)
{
  ...
} 
```

`if`语句和抛出异常的操作已为您完成。

# 继承自类

我们之前创建的`Person`类型派生（继承）自`object`，即`System.Object`的别名。现在，我们将创建一个从`Person`继承的子类：

1.  在`PacktLibrary`项目中，添加一个名为`Employee.cs`的新类文件。

1.  修改其内容以定义一个名为`Employee`的类，该类派生自`Person`，如下所示：

    ```cs
    using System;
    namespace Packt.Shared;
    public class Employee : Person
    {
    } 
    ```

1.  在`Program.cs`中，添加语句以创建`Employee`类的一个实例，如下所示：

    ```cs
    Employee john = new()
    {
      Name = "John Jones",
      DateOfBirth = new(year: 1990, month: 7, day: 28)
    };
    john.WriteToConsole(); 
    ```

1.  运行代码并查看结果，如下所示：

    ```cs
    John Jones was born on a Saturday. 
    ```

请注意，`Employee`类继承了`Person`类的所有成员。

## 扩展类以添加功能

现在，我们将添加一些特定于员工的成员以扩展该类。

1.  在`Employee.cs`中，添加语句以定义员工代码和雇佣日期这两个属性，如下所示：

    ```cs
    public string? EmployeeCode { get; set; } 
    public DateTime HireDate { get; set; } 
    ```

1.  在`Program.cs`中，添加语句以设置 John 的员工代码和雇佣日期，如下列代码所示：

    ```cs
    john.EmployeeCode = "JJ001";
    john.HireDate = new(year: 2014, month: 11, day: 23); 
    WriteLine($"{john.Name} was hired on {john.HireDate:dd/MM/yy}"); 
    ```

1.  运行代码并查看结果，如下列输出所示：

    ```cs
    John Jones was hired on 23/11/14 
    ```

## 隐藏成员

到目前为止，`WriteToConsole`方法是从`Person`继承的，它仅输出员工的姓名和出生日期。我们可能希望为员工改变此方法的功能：

1.  在`Employee.cs`中，添加语句以重新定义`WriteToConsole`方法，如下列高亮代码所示：

    ```cs
    **using****static** **System.Console;** 
    namespace Packt.Shared;
    public class Employee : Person
    {
      public string? EmployeeCode { get; set; }
      public DateTime HireDate { get; set; }
    **public****void****WriteToConsole****()**
     **{**
     **WriteLine(format:**
    **"{0} was born on {1:dd/MM/yy} and hired on {2:dd/MM/yy}"****,**
     **arg0: Name,**
     **arg1: DateOfBirth,**
     **arg2: HireDate);**
     **}**
    } 
    ```

1.  运行代码并查看结果，如下列输出所示：

    ```cs
    John Jones was born on 28/07/90 and hired on 01/01/01 
    John Jones was hired on 23/11/14 
    ```

你的编码工具会警告你，你的方法现在通过在方法名下划波浪线来隐藏来自`Person`的方法，**问题**/**错误列表**窗口包含更多细节，编译器会在你构建并运行控制台应用程序时输出警告，如*图 6.4*所示：

![图形用户界面，文本，应用程序，电子邮件 描述自动生成](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_06_04.png)

图 6.4：隐藏方法警告

正如警告所述，你可以通过将`new`关键字应用于该方法来隐藏此消息，以表明你是有意替换旧方法，如下列高亮代码所示：

```cs
public **new** void WriteToConsole() 
```

## 覆盖成员

与其隐藏一个方法，通常更好的做法是**覆盖**它。只有当基类选择允许覆盖时，你才能覆盖，这通过将`virtual`关键字应用于应允许覆盖的任何方法来实现。

来看一个例子：

1.  在`Program.cs`中，添加一条语句，使用其`string`表示形式将`john`变量的值写入控制台，如下列代码所示：

    ```cs
    WriteLine(john.ToString()); 
    ```

1.  运行代码并注意`ToString`方法是从`System.Object`继承的，因此实现返回命名空间和类型名称，如下列输出所示：

    ```cs
    Packt.Shared.Employee 
    ```

1.  在`Person.cs`中，通过添加一个`ToString`方法来覆盖此行为，该方法输出人的姓名以及类型名称，如下列代码所示：

    ```cs
    // overridden methods
    public override string ToString()
    {
      return $"{Name} is a {base.ToString()}";
    } 
    ```

    `base`关键字允许子类访问其超类的成员；即它继承或派生自的**基类**。

1.  运行代码并查看结果。现在，当调用`ToString`方法时，它输出人的姓名，并返回基类`ToString`的实现，如下列输出所示：

    ```cs
     John Jones is a Packt.Shared.Employee 
    ```

**最佳实践**：许多现实世界的 API，例如微软的 Entity Framework Core、Castle 的 DynamicProxy 和 Episerver 的内容模型，要求你在类中定义的属性标记为`virtual`，以便它们可以被覆盖。仔细决定你的哪些方法和属性成员应标记为`virtual`。

## 继承自抽象类

本章早些时候，你了解到接口可以定义一组成员，类型必须拥有这些成员才能达到基本的功能水平。这些接口非常有用，但主要局限在于，直到 C# 8 之前，它们无法提供任何自身的实现。

如果你仍然需要创建与.NET Framework 和其他不支持.NET Standard 2.1 的平台兼容的类库，这将是一个特定问题。

在那些早期平台中，你可以使用抽象类作为一种介于纯接口和完全实现类之间的半成品。

当一个类被标记为`abstract`时，这意味着它不能被实例化，因为你表明该类不完整。它需要更多的实现才能被实例化。

例如，`System.IO.Stream`类是抽象的，因为它实现了所有流都需要的一般功能，但并不完整，因此你不能使用`new Stream()`来实例化它。

让我们比较两种类型的接口和两种类型的类，如下代码所示：

```cs
public interface INoImplementation // C# 1.0 and later
{
  void Alpha(); // must be implemented by derived type
}
public interface ISomeImplementation // C# 8.0 and later
{
  void Alpha(); // must be implemented by derived type
  void Beta()
  {
    // default implementation; can be overridden
  }
}
public abstract class PartiallyImplemented // C# 1.0 and later
{
  public abstract void Gamma(); // must be implemented by derived type
  public virtual void Delta() // can be overridden
  {
    // implementation
  }
}
public class FullyImplemented : PartiallyImplemented, ISomeImplementation
{
  public void Alpha()
  {
    // implementation
  }
  public override void Gamma()
  {
    // implementation
  }
}
// you can only instantiate the fully implemented class
FullyImplemented a = new();
// all the other types give compile errors
PartiallyImplemented b = new(); // compile error!
ISomeImplementation c = new(); // compile error!
INoImplementation d = new(); // compile error! 
```

## 防止继承和覆盖

通过在其定义中应用`sealed`关键字，你可以防止其他开发者继承你的类。没有人能继承史高治·麦克达克，如下代码所示：

```cs
public sealed class ScroogeMcDuck
{
} 
```

.NET 中`sealed`的一个例子是`string`类。微软在`string`类内部实现了一些极端优化，这些优化可能会因你的继承而受到负面影响，因此微软阻止了这种情况。

你可以通过在方法上应用`sealed`关键字来防止某人进一步覆盖你类中的`virtual`方法。没有人能改变 Lady Gaga 的唱歌方式，如下代码所示：

```cs
using static System.Console;
namespace Packt.Shared;
public class Singer
{
  // virtual allows this method to be overridden
  public virtual void Sing()
  {
    WriteLine("Singing...");
  }
}
public class LadyGaga : Singer
{
  // sealed prevents overriding the method in subclasses
  public sealed override void Sing()
  {
    WriteLine("Singing with style...");
  }
} 
```

你只能密封一个被覆盖的方法。

## 理解多态性

你现在看到了两种改变继承方法行为的方式。我们可以使用`new`关键字*隐藏*它（称为**非多态继承**），或者我们可以*覆盖*它（称为**多态继承**）。

两种方式都可以使用`base`关键字访问基类或超类的成员，那么区别是什么呢？

这完全取决于持有对象引用的变量类型。例如，类型为`Person`的变量可以持有`Person`类或任何派生自`Person`的类型的引用。

让我们看看这如何影响你的代码：

1.  在`Employee.cs`中，添加语句以覆盖`ToString`方法，使其将员工的名字和代码写入控制台，如下代码所示：

    ```cs
    public override string ToString()
    {
      return $"{Name}'s code is {EmployeeCode}";
    } 
    ```

1.  在`Program.cs`中，编写语句以创建名为 Alice 的新员工，将其存储在类型为`Person`的变量中，并调用两个变量的`WriteToConsole`和`ToString`方法，如下代码所示：

    ```cs
    Employee aliceInEmployee = new()
      { Name = "Alice", EmployeeCode = "AA123" };
    Person aliceInPerson = aliceInEmployee; 
    aliceInEmployee.WriteToConsole(); 
    aliceInPerson.WriteToConsole(); 
    WriteLine(aliceInEmployee.ToString()); 
    WriteLine(aliceInPerson.ToString()); 
    ```

1.  运行代码并查看结果，如下输出所示：

    ```cs
    Alice was born on 01/01/01 and hired on 01/01/01 
    Alice was born on a Monday
    Alice's code is AA123 
    Alice's code is AA123 
    ```

当一个方法被`new`隐藏时，编译器不够智能，无法知道该对象是`Employee`，因此它调用`Person`中的`WriteToConsole`方法。

当一个方法被`virtual`和`override`覆盖时，编译器足够智能，知道尽管变量声明为`Person`类，但对象本身是`Employee`类，因此调用`Employee`的`ToString`实现。

成员修饰符及其效果总结在下表中：

| 变量类型 | 成员修饰符 | 执行的方法 | 所在类 |
| --- | --- | --- | --- |
| `Person` |  | `WriteToConsole` | `Person` |
| `Employee` | `new` | `WriteToConsole` | `Employee` |
| `Person` | `virtual` | `ToString` | `Employee` |
| `Employee` | `override` | `ToString` | `Employee` |

在我看来，多态性对大多数程序员来说是学术性的。如果你理解了这个概念，那很酷；但如果不理解，我建议你不必担心。有些人喜欢通过说理解多态性对所有 C#程序员学习很重要来让别人感到自卑，但在我看来并非如此。

你可以通过 C#拥有成功的职业生涯，而不必解释多态性，正如赛车手无需解释燃油喷射背后的工程原理一样。

**最佳实践**：应尽可能使用`virtual`和`override`而不是`new`来更改继承方法的实现。

# 继承层次结构内的强制转换

类型之间的强制转换与类型转换略有不同。强制转换是在相似类型之间进行的，例如 16 位整数和 32 位整数之间，或者超类及其子类之间。转换是在不同类型之间进行的，例如文本和数字之间。

## 隐式转换

在前面的示例中，你看到了如何将派生类型的实例存储在其基类型（或其基类型的基类型等）的变量中。当我们这样做时，称为**隐式转换**。

## 显式转换

反向操作是显式转换，你必须在要转换的类型周围使用括号作为前缀来执行此操作：

1.  在`Program.cs`中，添加一个语句，将`aliceInPerson`变量赋值给一个新的`Employee`变量，如下所示：

    ```cs
    Employee explicitAlice = aliceInPerson; 
    ```

1.  你的编码工具会显示红色波浪线和编译错误，如*图 6.5*所示：![图形用户界面，文本，应用程序，电子邮件，网站 自动生成描述](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_06_05.png)

    图 6.5：缺少显式转换的编译错误

1.  将语句更改为在赋值变量名前加上`Employee`类型的强制转换，如下所示：

    ```cs
    Employee explicitAlice = (Employee)aliceInPerson; 
    ```

## 避免强制转换异常

编译器现在满意了；但是，因为`aliceInPerson`可能是不同的派生类型，比如`Student`而不是`Employee`，我们需要小心。在更复杂的代码的实际应用程序中，此变量的当前值可能已被设置为`Student`实例，然后此语句将抛出`InvalidCastException`错误。

我们可以通过编写`try`语句来处理这种情况，但还有更好的方法。我们可以使用`is`关键字检查对象的类型：

1.  将显式转换语句包裹在`if`语句中，如下所示突出显示：

    ```cs
    **if** **(aliceInPerson** **is** **Employee)**
    **{**
     **WriteLine(****$"****{****nameof****(aliceInPerson)}** **IS an Employee"****);** 
      Employee explicitAlice = (Employee)aliceInPerson;
    **// safely do something with explicitAlice**
    **}** 
    ```

1.  运行代码并查看结果，如下所示：

    ```cs
    aliceInPerson IS an Employee 
    ```

    你可以通过使用声明模式进一步简化代码，这将避免需要执行显式转换，如下所示：

    ```cs
    if (aliceInPerson is Employee explicitAlice)  
    {
      WriteLine($"{nameof(aliceInPerson)} IS an Employee"); 
      // safely do something with explicitAlice
    } 
    ```

    或者，你可以使用`as`关键字进行转换。如果无法进行类型转换，`as`关键字不会抛出异常，而是返回`null`。

1.  在`Main`中，添加语句，使用`as`关键字转换 Alice，然后检查返回值是否不为空，如下所示：

    ```cs
    Employee? aliceAsEmployee = aliceInPerson as Employee; // could be null
    if (aliceAsEmployee != null)
    {
      WriteLine($"{nameof(aliceInPerson)} AS an Employee");
      // safely do something with aliceAsEmployee
    } 
    ```

    由于访问`null`变量的成员会抛出`NullReferenceException`错误，因此在使用结果之前应始终检查`null`。

1.  运行代码并查看结果，如下所示：

    ```cs
    aliceInPerson AS an Employee 
    ```

如果你想在 Alice 不是员工时执行一组语句，该怎么办？

在过去，你可能会使用`!`（非）运算符，如下所示：

```cs
if (!(aliceInPerson is Employee)) 
```

使用 C# 9 及更高版本，你可以使用`not`关键字，如下所示：

```cs
if (aliceInPerson is not Employee) 
```

**最佳实践**：使用`is`和`as`关键字避免在派生类型之间转换时抛出异常。如果不这样做，你必须为`InvalidCastException`编写`try`-`catch`语句。

# 继承和扩展.NET 类型

.NET 拥有预建的类库，包含数十万个类型。与其完全创建全新的类型，不如从微软的类型中派生，继承其部分或全部行为，然后覆盖或扩展它，从而获得先机。

## 继承异常

作为继承的一个例子，我们将派生一种新的异常类型：

1.  在`PacktLibrary`项目中，添加一个名为`PersonException.cs`的新类文件。

1.  修改文件内容，定义一个名为`PersonException`的类，包含三个构造函数，如下所示：

    ```cs
    namespace Packt.Shared;
    public class PersonException : Exception
    {
      public PersonException() : base() { }
      public PersonException(string message) : base(message) { }
      public PersonException(string message, Exception innerException)
        : base(message, innerException) { }
    } 
    ```

    与普通方法不同，构造函数不会被继承，因此我们必须显式声明并在`System.Exception`中显式调用基类构造函数实现，以便让可能希望使用这些构造函数的程序员能够使用我们自定义的异常。

1.  在`Person.cs`中，添加语句以定义一个方法，如果日期/时间参数早于某人的出生日期，则抛出异常，如下所示：

    ```cs
    public void TimeTravel(DateTime when)
    {
      if (when <= DateOfBirth)
      {
        throw new PersonException("If you travel back in time to a date earlier than your own birth, then the universe will explode!");
      }
      else
      {
        WriteLine($"Welcome to {when:yyyy}!");
      }
    } 
    ```

1.  在`Program.cs`中，添加语句以测试当员工 John Jones 试图穿越回太久远的时间时会发生什么，如下所示：

    ```cs
    try
    {
      john.TimeTravel(when: new(1999, 12, 31));
      john.TimeTravel(when: new(1950, 12, 25));
    }
    catch (PersonException ex)
    {
      WriteLine(ex.Message);
    } 
    ```

1.  运行代码并查看结果，如下所示：

    ```cs
    Welcome to 1999!
    If you travel back in time to a date earlier than your own birth, then the universe will explode! 
    ```

**最佳实践**：在定义自己的异常时，应提供与内置异常相同的三个构造函数，并显式调用它们。

## 当你无法继承时扩展类型

之前，我们了解到`sealed`修饰符可用于防止继承。

微软已将`sealed`关键字应用于`System.String`类，以确保无人能继承并可能破坏字符串的行为。

我们还能给字符串添加新方法吗？可以，如果我们使用名为**扩展方法**的语言特性，该特性是在 C# 3.0 中引入的。

### 使用静态方法重用功能

自 C#的第一个版本以来，我们就能创建`static`方法来重用功能，例如验证`string`是否包含电子邮件地址的能力。其实现将使用正则表达式，你将在*第八章*，*使用常见的.NET 类型*中了解更多相关内容。

让我们来编写一些代码：

1.  在`PacktLibrary`项目中，添加一个名为`StringExtensions`的新类，如下列代码所示，并注意以下事项：

    +   该类导入了一个用于处理正则表达式的命名空间。

    +   `IsValidEmail`方法是`static`的，它使用`Regex`类型来检查与一个简单的电子邮件模式匹配，该模式寻找`@`符号前后有效的字符。

    ```cs
    using System.Text.RegularExpressions;
    namespace Packt.Shared;
    public class StringExtensions
    {
      public static bool IsValidEmail(string input)
      {
        // use simple regular expression to check
        // that the input string is a valid email
        return Regex.IsMatch(input,
          @"[a-zA-Z0-9\.-_]+@[a-zA-Z0-9\.-_]+");
      }
    } 
    ```

1.  在`Program.cs`中，添加语句以验证两个电子邮件地址示例，如下列代码所示：

    ```cs
    string email1 = "pamela@test.com"; 
    string email2 = "ian&test.com";
    WriteLine("{0} is a valid e-mail address: {1}", 
      arg0: email1,
      arg1: StringExtensions.IsValidEmail(email1));
    WriteLine("{0} is a valid e-mail address: {1}",
      arg0: email2,
      arg1: StringExtensions.IsValidEmail(email2)); 
    ```

1.  运行代码并查看结果，如下列输出所示：

    ```cs
    pamela@test.com is a valid e-mail address: True 
    ian&test.com is a valid e-mail address: False 
    ```

这可行，但扩展方法能减少我们必须输入的代码量并简化此功能的使用。

### 使用扩展方法重用功能

将`static`方法转换为扩展方法很容易：

1.  在`StringExtensions.cs`中，在类前添加`static`修饰符，并在`string`类型前添加`this`修饰符，如下列代码中突出显示：

    ```cs
    public **static** class StringExtensions
    {
      public static bool IsValidEmail(**this** string input)
      { 
    ```

    这两个改动告诉编译器，应将该方法视为扩展`string`类型的方法。

1.  在`Program.cs`中，添加语句以使用扩展方法检查需要验证的`string`值是否为有效电子邮件地址，如下列代码所示：

    ```cs
    WriteLine("{0} is a valid e-mail address: {1}",
      arg0: email1,
      arg1: email1.IsValidEmail());
    WriteLine("{0} is a valid e-mail address: {1}", 
      arg0: email2,
      arg1: email2.IsValidEmail()); 
    ```

    注意调用`IsValidEmail`方法的语法中微妙的简化。较旧、较长的语法仍然有效。

1.  `IsValidEmail`扩展方法现在看起来就像是`string`类型的所有实际实例方法一样，例如`IsNormalized`和`Insert`，如*图 6.6*所示：![图形用户界面，文本，应用程序 自动生成的描述](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_06_06.png)

    图 6.6：扩展方法在 IntelliSense 中与实例方法并列显示

1.  运行代码并查看结果，其将与之前相同。

**良好实践**：扩展方法不能替换或覆盖现有实例方法。例如，你不能重新定义`Insert`方法。扩展方法会在 IntelliSense 中显示为重载，但具有相同名称和签名的实例方法会被优先调用。

尽管扩展方法可能看似没有带来巨大好处，但在*第十一章*，*使用 LINQ 查询和操作数据*中，你将看到扩展方法的一些极其强大的用途。

# 使用分析器编写更优质的代码

.NET 分析器能发现潜在问题并提出修复建议。**StyleCop**是一个常用的分析器，帮助你编写更优质的 C#代码。

让我们看看实际操作，指导如何在面向.NET 5.0 的控制台应用项目模板中改进代码，以便控制台应用已具备一个包含`Main`方法的`Program`类：

1.  使用您喜欢的代码编辑器添加一个控制台应用程序项目，如下表所定义：

    1.  项目模板：**控制台应用程序** / `console -f net5.0`

    1.  工作区/解决方案文件和文件夹：`Chapter06`

    1.  项目文件和文件夹：`CodeAnalyzing`

    1.  目标框架：**.NET 5.0（当前）**

1.  在 `CodeAnalyzing` 项目中，添加对 `StyleCop.Analyzers` 包的引用。

1.  向您的项目添加一个名为 `stylecop.json` 的 JSON 文件，以控制 StyleCop 设置。

1.  修改其内容，如下面的标记所示：

    ```cs
    {
      "$schema": "https://raw.githubusercontent.com/DotNetAnalyzers/StyleCopAnalyzers/master/StyleCop.Analyzers/StyleCop.Analyzers/Settings/stylecop.schema.json",
      "settings": {
      }
    } 
    ```

    `$schema` 条目在代码编辑器中编辑 `stylecop.json` 文件时启用 IntelliSense。

1.  编辑项目文件，将目标框架更改为 `net6.0`，添加条目以配置名为 `stylecop.json` 的文件，使其不在发布的部署中包含，并在开发期间作为附加文件进行处理，如下面的标记中突出显示的那样：

    ```cs
    <Project Sdk="Microsoft.NET.Sdk">
      <PropertyGroup>
        <OutputType>Exe</OutputType>
        <TargetFramework>net6.0</TargetFramework>
      </PropertyGroup>
     **<ItemGroup>**
     **<None Remove=****"stylecop.json"** **/>**
     **</ItemGroup>**
     **<ItemGroup>**
     **<AdditionalFiles Include=****"stylecop.json"** **/>**
     **</ItemGroup>**
      <ItemGroup>
        <PackageReference Include="StyleCop.Analyzers" Version="1.2.0-*">
          <PrivateAssets>all</PrivateAssets>
          <IncludeAssets>runtime; build; native; contentfiles; analyzers</IncludeAssets>
        </PackageReference>
      </ItemGroup>
    </Project> 
    ```

1.  构建您的项目。

1.  您将看到它认为有问题的所有内容的警告，如图 *6.7* 所示：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_06_07.png)

    图 6.7：StyleCop 代码分析器警告

1.  例如，它希望 `using` 指令放在命名空间声明内，如下面的输出所示：

    ```cs
    C:\Code\Chapter06\CodeAnalyzing\Program.cs(1,1): warning SA1200: Using directive should appear within a namespace declaration [C:\Code\Chapter06\CodeAnalyzing\CodeAnalyzing.csproj] 
    ```

## 抑制警告

要抑制警告，您有几种选择，包括添加代码和设置配置。

要抑制使用属性，如下面的代码所示：

```cs
[assembly:SuppressMessage("StyleCop.CSharp.OrderingRules", "SA1200:UsingDirectivesMustBePlacedWithinNamespace", Justification = "Reviewed.")] 
```

要抑制使用指令，如下面的代码所示：

```cs
#pragma warning disable SA1200 // UsingDirectivesMustBePlacedWithinNamespace
using System;
#pragma warning restore SA1200 // UsingDirectivesMustBePlacedWithinNamespace 
```

通过修改 `stylecop.json` 文件来抑制警告：

1.  在 `stylecop.json` 中，添加一个配置选项，将 `using` 语句设置为允许在命名空间外部使用，如下面的标记中突出显示的那样：

    ```cs
    {
      "$schema": "https://raw.githubusercontent.com/DotNetAnalyzers/StyleCopAnalyzers/master/StyleCop.Analyzers/StyleCop.Analyzers/Settings/stylecop.schema.json",
      "settings": {
        "orderingRules": {
          "usingDirectivesPlacement": "outsideNamespace"
        }
      }
    } 
    ```

1.  构建项目并注意警告 SA1200 已消失。

1.  在 `stylecop.json` 中，将 using 指令的位置设置为 `preserve`，允许 `using` 语句在命名空间内部和外部使用，如下面的标记所示：

    ```cs
    "orderingRules": {
      "usingDirectivesPlacement": "preserve"
    } 
    ```

### 修复代码

现在，让我们修复所有其他警告：

1.  在 `CodeAnalyzing.csproj` 中，添加一个元素以自动生成文档的 XML 文件，如下面的标记中突出显示的那样：

    ```cs
    <Project Sdk="Microsoft.NET.Sdk">
      <PropertyGroup>
        <OutputType>Exe</OutputType>
        <TargetFramework>net6.0</TargetFramework>
     **<GenerateDocumentationFile>****true****</GenerateDocumentationFile>**
      </PropertyGroup> 
    ```

1.  在 `stylecop.json` 中，添加一个配置选项，为公司名称和版权文本的文档提供值，如下面的标记中突出显示的那样：

    ```cs
    {
      "$schema": "https://raw.githubusercontent.com/DotNetAnalyzers/StyleCopAnalyzers/master/StyleCop.Analyzers/StyleCop.Analyzers/Settings/stylecop.schema.json",
      "settings": {
        "orderingRules": {
          "usingDirectivesPlacement": "preserve"
        },
    **"documentationRules"****: {**
    **"companyName"****:** **"Packt"****,**
    **"copyrightText"****:** **"Copyright (c) Packt. All rights reserved."**
     **}**
      }
    } 
    ```

1.  在 `Program.cs` 中，为文件头添加公司和版权文本的注释，将 `using System;` 声明移至命名空间内部，并为类和方法设置显式访问修饰符和 XML 注释，如下面的代码所示：

    ```cs
    // <copyright file="Program.cs" company="Packt">
    // Copyright (c) Packt. All rights reserved.
    // </copyright>
    namespace CodeAnalyzing
    {
      using System;
      /// <summary>
      /// The main class for this console app.
      /// </summary>
      public class Program
      {
        /// <summary>
        /// The main entry point for this console app.
        /// </summary>
        /// <param name="args">A string array of arguments passed to the console app.</param>
        public static void Main(string[] args)
        {
          Console.WriteLine("Hello World!");
        }
      }
    } 
    ```

1.  构建项目。

1.  展开 `bin/Debug/net6.0` 文件夹并注意名为 `CodeAnalyzing.xml` 的自动生成的文件，如下面的标记所示：

    ```cs
    <?xml version="1.0"?>
    <doc>
        <assembly>
            <name>CodeAnalyzing</name>
        </assembly>
        <members>
            <member name="T:CodeAnalyzing.Program">
                <summary>
                The main class for this console app.
                </summary>
            </member>
            <member name="M:CodeAnalyzing.Program.Main(System.String[])">
                <summary>
                The main entry point for this console app.
                </summary>
                <param name="args">A string array of arguments passed to the console app.</param>
            </member>
        </members>
    </doc> 
    ```

### 理解常见的 StyleCop 建议

在代码文件内部，应按以下列表所示顺序排列内容：

1.  外部别名指令

1.  使用指令

1.  命名空间

1.  委托

1.  枚举

1.  接口

1.  结构体

1.  类

在类、记录、结构或接口内部，应按以下列表所示顺序排列内容：

1.  字段

1.  构造函数

1.  析构函数（终结器）

1.  委托

1.  事件

1.  枚举

1.  接口

1.  属性

1.  索引器

1.  方法

1.  结构体

1.  嵌套类和记录

**良好实践**：你可以在以下链接了解所有 StyleCop 规则：[`github.com/DotNetAnalyzers/StyleCopAnalyzers/blob/master/DOCUMENTATION.md`](https://github.com/DotNetAnalyzers/StyleCopAnalyzers/blob/master/DOCUMENTATION.md)。

# 实践与探索

通过回答一些问题来测试你的知识和理解。通过更深入的研究，获得一些实践经验并探索本章的主题。

## 练习 6.1 – 测试你的知识

回答以下问题：

1.  什么是委托？

1.  什么是事件？

1.  基类和派生类是如何关联的，派生类如何访问基类？

1.  `is`和`as`操作符之间有什么区别？

1.  哪个关键字用于防止一个类被派生或一个方法被进一步重写？

1.  哪个关键字用于防止一个类通过`new`关键字实例化？

1.  哪个关键字用于允许成员被重写？

1.  析构函数和解构方法之间有什么区别？

1.  所有异常应具有的构造函数的签名是什么？

1.  什么是扩展方法，如何定义一个？

## 练习 6.2 – 实践创建继承层次结构

通过以下步骤探索继承层次结构：

1.  向你的`Chapter06`解决方案/工作区中添加一个名为`Exercise02`的新控制台应用程序。

1.  创建一个名为`Shape`的类，其属性名为`Height`、`Width`和`Area`。

1.  添加三个从它派生的类——`Rectangle`、`Square`和`Circle`——根据你认为合适的任何额外成员，并正确地重写和实现`Area`属性。

1.  在`Main`中，添加语句以创建每种形状的一个实例，如下列代码所示：

    ```cs
    Rectangle r = new(height: 3, width: 4.5);
    WriteLine($"Rectangle H: {r.Height}, W: {r.Width}, Area: {r.Area}"); 
    Square s = new(5);
    WriteLine($"Square H: {s.Height}, W: {s.Width}, Area: {s.Area}"); 
    Circle c = new(radius: 2.5);
    WriteLine($"Circle H: {c.Height}, W: {c.Width}, Area: {c.Area}"); 
    ```

1.  运行控制台应用程序，并确保结果与以下输出相符：

    ```cs
    Rectangle H: 3, W: 4.5, Area: 13.5
    Square H: 5, W: 5, Area: 25
    Circle H: 5, W: 5, Area: 19.6349540849362 
    ```

## 练习 6.3 – 探索主题

使用以下页面上的链接来了解更多关于本章涵盖的主题：

[`github.com/markjprice/cs10dotnet6/blob/main/book-links.md#chapter-6---implementing-interfaces-and-inheriting-classes`](https://github.com/markjprice/cs10dotnet6/blob/main/book-links.md#chapter-6---implementing-interfaces-and-inheriting-classes)

# 总结

在本章中，你学习了局部函数和操作符、委托和事件、实现接口、泛型以及使用继承和 OOP 派生类型。你还学习了基类和派生类，以及如何重写类型成员、使用多态性以及在类型之间进行转换。

在下一章中，你将学习.NET 是如何打包和部署的，以及在后续章节中，它为你提供的实现常见功能（如文件处理、数据库访问、加密和多任务处理）的类型。
