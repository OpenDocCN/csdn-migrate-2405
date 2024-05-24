# C#10 和 .NET6 代码跨平台开发（六）

> 原文：[`zh.annas-archive.org/md5/B053DEF9CB8C4C14E67E73C1EC2319CF`](https://zh.annas-archive.org/md5/B053DEF9CB8C4C14E67E73C1EC2319CF)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十一章：使用 LINQ 查询和操作数据

本章是关于**语言集成查询**（**LINQ**）表达式的。LINQ 是一系列语言扩展，它增加了处理项目序列的能力，然后对其进行过滤、排序，并将其投影到不同的输出中。

本章将涵盖以下主题：

+   编写 LINQ 表达式

+   使用 LINQ 处理集合

+   将 LINQ 与 EF Core 结合使用

+   用语法糖美化 LINQ 语法

+   使用并行 LINQ 进行多线程处理

+   创建自己的 LINQ 扩展方法

+   使用 LINQ to XML

# 编写 LINQ 表达式

尽管我们在*第十章*，*使用 Entity Framework Core 处理数据*中写了一些 LINQ 表达式，但它们并非重点，因此我没有适当地解释 LINQ 的工作原理，所以现在让我们花时间来正确理解它们。

## 何为 LINQ？

LINQ 包含多个部分；有些是必选的，有些是可选的：

+   **扩展方法（必选）**：这些包括`Where`、`OrderBy`和`Select`等示例。正是这些方法提供了 LINQ 的功能。

+   **LINQ 提供程序（必选）**：这些包括用于处理内存中对象的 LINQ to Objects、用于处理存储在外部数据库中并由 EF Core 建模的数据的 LINQ to Entities，以及用于处理存储为 XML 的数据的 LINQ to XML。这些提供程序是针对不同类型的数据执行 LINQ 表达式的方式。

+   **Lambda 表达式（可选）**：这些可以用来代替命名方法来简化 LINQ 查询，例如，用于`Where`方法的过滤条件逻辑。

+   **LINQ 查询理解语法（可选）**：这些包括`from`、`in`、`where`、`orderby`、`descending`和`select`等 C#关键字。它们是一些 LINQ 扩展方法的别名，使用它们可以简化你编写的查询，特别是如果你已经有其他查询语言（如**结构化查询语言**（**SQL**））的经验。

当程序员首次接触 LINQ 时，他们常常认为 LINQ 查询理解语法就是 LINQ，但讽刺的是，这是 LINQ 中可选的部分之一！

## 使用 Enumerable 类构建 LINQ 表达式

LINQ 扩展方法，如`Where`和`Select`，由`Enumerable`静态类附加到任何实现`IEnumerable<T>`的类型，这种类型被称为**序列**。

例如，任何类型的数组都实现了`IEnumerable<T>`类，其中`T`是数组中项目的类型。这意味着所有数组都支持 LINQ 来查询和操作它们。

所有泛型集合，如`List<T>`、`Dictionary<TKey, TValue>`、`Stack<T>`和`Queue<T>`，都实现了`IEnumerable<T>`，因此它们也可以用 LINQ 进行查询和操作。

`Enumerable`定义了超过 50 个扩展方法，如下表总结：

| 方法(s) | 描述 |
| --- | --- |
| `First`, `FirstOrDefault`, `Last`, `LastOrDefault` | 获取序列中的第一个或最后一个项，如果没有则抛出异常，或者返回类型的默认值，例如，`int`的`0`和引用类型的`null`。 |
| `Where` | 返回与指定筛选器匹配的项序列。 |
| `Single`, `SingleOrDefault` | 返回与特定筛选器匹配的项，如果没有恰好一个匹配项，则抛出异常，或者返回类型的默认值。 |
| `ElementAt`, `ElementAtOrDefault` | 返回指定索引位置的项，如果没有该位置的项，则抛出异常，或者返回类型的默认值。.NET 6 中新增了可以传入`Index`而不是`int`的重载，这在处理`Span<T>`序列时更高效。 |
| `Select`, `SelectMany` | 将项投影到不同形状，即不同类型，并展平嵌套的项层次结构。 |
| `OrderBy`, `OrderByDescending`, `ThenBy`, `ThenByDescending` | 按指定字段或属性排序项。 |
| `Reverse` | 反转项的顺序。 |
| `GroupBy`, `GroupJoin`, `Join` | 对两个序列进行分组和/或连接。 |
| `Skip`, `SkipWhile` | 跳过一定数量的项；或在表达式为`true`时跳过。 |
| `Take`, `TakeWhile` | 获取一定数量的项；或在表达式为`true`时获取。.NET 6 中新增了`Take`的重载，可以传入一个`Range`，例如，`Take(range: 3..⁵)`表示从开始处算起第 3 项到结束处算起第 5 项的子集，或者可以用`Take(4..)`代替`Skip(4)`。 |
| `Aggregate`, `Average`, `Count`, `LongCount`, `Max`, `Min`, `Sum` | 计算聚合值。 |
| `TryGetNonEnumeratedCount` | `Count()`检查序列上是否实现了`Count`属性并返回其值，或者枚举整个序列以计算其项数。.NET 6 中新增了这个方法，它仅检查`Count`，如果缺失则返回`false`并将`out`参数设置为`0`，以避免潜在的性能不佳的操作。 |
| `All`, `Any`, `Contains` | 如果所有或任何项匹配筛选器，或者序列包含指定项，则返回`true`。 |
| `Cast` | 将项转换为指定类型。在编译器可能抱怨的情况下，将非泛型对象转换为泛型类型时非常有用。 |
| `OfType` | 移除与指定类型不匹配的项。 |
| `Distinct` | 移除重复项。 |
| `Except`, `Intersect`, `Union` | 执行返回集合的操作。集合不能有重复项。尽管输入可以是任何序列，因此输入可以有重复项，但结果始终是一个集合。 |
| `Chunk` | 将序列分割成定长批次。 |
| `Append`, `Concat`, `Prepend` | 执行序列合并操作。 |
| `Zip` | 基于项的位置对两个序列执行匹配操作，例如，第一个序列中位置 1 的项与第二个序列中位置 1 的项匹配。.NET 6 中新增了对三个序列的匹配操作。以前，您需要运行两次两个序列的重载才能达到相同目的。 |
| `ToArray`, `ToList`, `ToDictionary`, `ToHashSet`, `ToLookup` | 将序列转换为数组或集合。这些是唯一执行 LINQ 表达式的扩展方法。 |
| `DistinctBy`, `ExceptBy`, `IntersectBy`, `UnionBy`, `MinBy`, `MaxBy` | .NET 6 中新增了`By`扩展方法。它们允许在项的子集上进行比较，而不是整个项。例如，您可以仅通过比较他们的`LastName`和`DateOfBirth`来移除重复项，而不是通过比较整个`Person`对象。 |

`Enumerable`类还包含一些非扩展方法，如下表所示：

| 方法 | 描述 |
| --- | --- |
| `Empty<T>` | 返回指定类型`T`的空序列。它对于向需要`IEnumerable<T>`的方法传递空序列非常有用。 |
| `Range` | 从`start`值开始返回包含`count`个整数的序列。例如，`Enumerable.Range(start: 5, count: 3)`将包含整数 5、6 和 7。 |
| `Repeat` | 返回一个包含相同`element`重复`count`次的序列。例如，`Enumerable.Repeat(element: "5", count: 3)`将包含字符串值“5”、“5”和“5”。 |

### 理解延迟执行

LINQ 使用**延迟执行**。重要的是要理解，调用这些扩展方法中的大多数并不会执行查询并获取结果。这些扩展方法中的大多数返回一个代表*问题*而非*答案*的 LINQ 表达式。让我们来探讨：

1.  使用您偏好的代码编辑器创建一个名为`Chapter11`的新解决方案/工作区。

1.  添加一个控制台应用项目，如下表所定义：

    1.  项目模板：**控制台应用程序** / `console`

    1.  工作区/解决方案文件和文件夹：`Chapter11`

    1.  项目文件和文件夹：`LinqWithObjects`

1.  在`Program.cs`中，删除现有代码并静态导入`Console`。

1.  添加语句以定义一个`string`值序列，表示在办公室工作的人员，如下列代码所示：

    ```cs
    // a string array is a sequence that implements IEnumerable<string>
    string[] names = new[] { "Michael", "Pam", "Jim", "Dwight", 
      "Angela", "Kevin", "Toby", "Creed" };
    WriteLine("Deferred execution");
    // Question: Which names end with an M?
    // (written using a LINQ extension method)
    var query1 = names.Where(name => name.EndsWith("m"));
    // Question: Which names end with an M?
    // (written using LINQ query comprehension syntax)
    var query2 = from name in names where name.EndsWith("m") select name; 
    ```

1.  要提出问题并获得答案，即执行查询，您必须**具体化**它，通过调用诸如`ToArray`或`ToLookup`之类的“To”方法之一，或者通过枚举查询，如下列代码所示：

    ```cs
    // Answer returned as an array of strings containing Pam and Jim
    string[] result1 = query1.ToArray();
    // Answer returned as a list of strings containing Pam and Jim
    List<string> result2 = query2.ToList();
    // Answer returned as we enumerate over the results
    foreach (string name in query1)
    {
      WriteLine(name); // outputs Pam
      names[2] = "Jimmy"; // change Jim to Jimmy
      // on the second iteration Jimmy does not end with an M
    } 
    ```

1.  运行控制台应用并注意结果，如下所示：

    ```cs
    Deferred execution
    Pam 
    ```

由于延迟执行，在输出第一个结果`Pam`后，如果原始数组值发生改变，那么当我们再次循环时，将不再有匹配项，因为`Jim`已变为`Jimmy`，且不再以`M`结尾，因此只输出`Pam`。

在我们深入细节之前，让我们放慢脚步，逐一查看一些常见的 LINQ 扩展方法及其使用方法。

## 使用 Where 过滤实体

LINQ 最常见的用途是使用`Where`扩展方法对序列中的项进行过滤。让我们通过定义一个名字序列，然后对其应用 LINQ 操作来探索过滤：

1.  在项目文件中，注释掉启用隐式引用的元素，如下列标记中高亮所示：

    ```cs
    <Project Sdk="Microsoft.NET.Sdk">
      <PropertyGroup>
        <OutputType>Exe</OutputType>
        <TargetFramework>net6.0</TargetFramework>
        <Nullable>enable</Nullable>
     **<!--<ImplicitUsings>enable</ImplicitUsings>-->**
      </PropertyGroup>
    </Project> 
    ```

1.  在`Program.cs`中，尝试对名字数组调用`Where`扩展方法，如下列代码所示：

    ```cs
    WriteLine("Writing queries"); 
    var query = names.W 
    ```

1.  当你尝试输入`Where`方法时，注意它从字符串数组的 IntelliSense 成员列表中缺失，如*图 11.1*所示：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_12_01.png)

    图 11.1：缺少 Where 扩展方法的 IntelliSense

    这是因为`Where`是一个扩展方法。它并不存在于数组类型上。为了使`Where`扩展方法可用，我们必须导入`System.Linq`命名空间。这在新的.NET 6 项目中默认是隐式导入的，但我们禁用了它。

1.  在项目文件中，取消注释启用隐式引用的元素。

1.  重新输入`Where`方法，并注意 IntelliSense 列表现在包括了由`Enumerable`类添加的扩展方法，如*图 11.2*所示：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_12_02.png)

    图 11.2：IntelliSense 显示 LINQ Enumerable 扩展方法

1.  当你输入`Where`方法的括号时，IntelliSense 告诉我们，要调用`Where`，我们必须传入一个`Func<string, bool>`委托的实例。

1.  输入一个表达式以创建`Func<string, bool>`委托的新实例，目前请注意我们尚未提供方法名，因为我们将在下一步定义它，如下列代码所示：

    ```cs
    var query = names.Where(new Func<string, bool>( )) 
    ```

`Func<string, bool>`委托告诉我们，对于传递给该方法的每个`string`变量，该方法必须返回一个`bool`值。如果方法返回`true`，则表示我们应该在结果中包含该`string`，如果方法返回`false`，则表示我们应该排除它。

## 针对命名方法

让我们定义一个只包含长度超过四个字符的名字的方法：

1.  在`Program.cs`底部，定义一个方法，该方法将只包含长度超过四个字符的名字，如下列代码所示：

    ```cs
    static bool NameLongerThanFour(string name)
    {
      return name.Length > 4;
    } 
    ```

1.  在`NameLongerThanFour`方法上方，将方法名传递给`Func<string, bool>`委托，然后遍历查询项，如下列高亮代码所示：

    ```cs
    var query = names.Where(
      new Func<string, bool>(**NameLongerThanFour**));
    **foreach** **(****string** **item** **in** **query)**
    **{**
     **WriteLine(item);**
    **}** 
    ```

1.  运行代码并查看结果，注意只有长度超过四个字母的名字被列出，如下列输出所示：

    ```cs
    Writing queries
    Michael 
    Dwight 
    Angela 
    Kevin 
    Creed 
    ```

## 通过移除显式委托实例化来简化代码

我们可以通过删除`Func<string, bool>`委托的显式实例化来简化代码，因为 C#编译器可以为我们实例化委托：

1.  为了帮助你通过逐步改进的代码学习，复制并粘贴查询

1.  注释掉第一个示例，如下面的代码所示：

    ```cs
    // var query = names.Where(
    //   new Func<string, bool>(NameLongerThanFour)); 
    ```

1.  修改副本以删除委托的显式实例化，如下面的代码所示：

    ```cs
    var query = names.Where(NameLongerThanFour); 
    ```

1.  运行代码并注意它具有相同的行为。

## 针对 lambda 表达式

我们可以使用**lambda 表达式**代替命名方法，进一步简化代码。

虽然一开始看起来可能很复杂，但 lambda 表达式只是一个*无名函数*。它使用`=>`（读作“转到”）符号来指示返回值：

1.  复制并粘贴查询，注释第二个示例，并修改查询，如下面的代码所示：

    ```cs
    var query = names.Where(name => name.Length > 4); 
    ```

    请注意，lambda 表达式的语法包括了`NameLongerThanFour`方法的所有重要部分，但仅此而已。lambda 表达式只需要定义以下内容：

    +   输入参数的名称：`name`

    +   返回值表达式：`name.Length > 4`

    `name`输入参数的类型是从序列包含`string`值这一事实推断出来的，并且返回类型必须是一个`bool`值，这是由`Where`工作的委托定义的，因此`=>`符号后面的表达式必须返回一个`bool`值。

    编译器为我们完成了大部分工作，因此我们的代码可以尽可能简洁。

1.  运行代码并注意它具有相同的行为。

## 对实体进行排序

其他常用的扩展方法是`OrderBy`和`ThenBy`，用于对序列进行排序。

如果前一个方法返回另一个序列，即实现`IEnumerable<T>`接口的类型，则可以链接扩展方法。

### 使用 OrderBy 按单个属性排序

让我们继续使用当前项目来探索排序：

1.  在现有查询的末尾添加对`OrderBy`的调用，如下面的代码所示：

    ```cs
    var query = names
      .Where(name => name.Length > 4)
      .OrderBy(name => name.Length); 
    ```

    **最佳实践**：将 LINQ 语句格式化，使每个扩展方法调用都发生在一行上，以便更容易阅读。

1.  运行代码并注意，现在名字按最短的先排序，如下面的输出所示：

    ```cs
    Kevin 
    Creed 
    Dwight 
    Angela 
    Michael 
    ```

要将最长的名字放在前面，您将使用`OrderByDescending`。

### 使用 ThenBy 按后续属性排序

我们可能希望按多个属性排序，例如，对相同长度的名字按字母顺序排序：

1.  在现有查询的末尾添加对`ThenBy`方法的调用，如下面的代码中突出显示的那样：

    ```cs
    var query = names
      .Where(name => name.Length > 4)
      .OrderBy(name => name.Length)
     **.ThenBy(name => name);** 
    ```

1.  运行代码并注意以下排序顺序的微小差异。在长度相同的名字组中，名字按`string`的完整值进行字母排序，因此`Creed`出现在`Kevin`之前，`Angela`出现在`Dwight`之前，如下面的输出所示：

    ```cs
    Creed 
    Kevin 
    Angela 
    Dwight 
    Michael 
    ```

## 使用 var 或指定类型声明查询

在编写 LINQ 表达式时，使用`var`声明查询对象很方便。这是因为随着您在 LINQ 表达式上的工作，类型经常发生变化。例如，我们的查询最初是`IEnumerable<string>`，目前是`IOrderedEnumerable<string>`：

1.  将鼠标悬停在`var`关键字上，并注意其类型为`IOrderedEnumerable<string>`

1.  将`var`替换为实际类型，如下面的代码中突出显示的那样：

    ```cs
    **IOrderedEnumerable<****string****>** query = names
      .Where(name => name.Length > 4)
      .OrderBy(name => name.Length)
      .ThenBy(name => name); 
    ```

**最佳实践**：一旦完成查询工作，您可以将声明的类型从`var`更改为实际类型，以使其更清楚地了解类型是什么。这很容易，因为您的代码编辑器可以告诉您它是什么。

## 按类型筛选

`Where`扩展方法非常适合按值筛选，例如文本和数字。但如果序列包含多种类型，并且您想要按特定类型筛选并尊重任何继承层次结构，该怎么办？

想象一下，您有一个异常序列。有数百种异常类型形成了一个复杂的层次结构，部分显示在*图 11.3*中：

![图表描述自动生成](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_12_04.png)

图 11.3：部分异常继承层次结构

让我们探讨按类型筛选：

1.  在`Program.cs`中，定义一个异常派生对象列表，如下面的代码所示：

    ```cs
    WriteLine("Filtering by type");
    List<Exception> exceptions = new()
    {
      new ArgumentException(), 
      new SystemException(),
      new IndexOutOfRangeException(),
      new InvalidOperationException(),
      new NullReferenceException(),
      new InvalidCastException(),
      new OverflowException(),
      new DivideByZeroException(),
      new ApplicationException()
    }; 
    ```

1.  使用`OfType<T>`扩展方法编写语句，以删除不是算术异常的异常，并将仅算术异常写入控制台，如下面的代码所示：

    ```cs
    IEnumerable<ArithmeticException> arithmeticExceptionsQuery = 
      exceptions.OfType<ArithmeticException>();
    foreach (ArithmeticException exception in arithmeticExceptionsQuery)
    {
      WriteLine(exception);
    } 
    ```

1.  运行代码并注意结果仅包括`ArithmeticException`类型的异常，或`ArithmeticException`派生的类型，如下面的输出所示：

    ```cs
    System.OverflowException: Arithmetic operation resulted in an overflow.
    System.DivideByZeroException: Attempted to divide by zero. 
    ```

## 使用 LINQ 处理集合和包

集合是数学中最基本的概念之一。**集合**是一个或多个唯一对象的集合。**多重集合**，又称**包**，是一个或多个对象的集合，可以有重复项。

您可能还记得在学校学过的维恩图。常见的集合操作包括集合之间的**交集**或**并集**。

让我们创建一个控制台应用程序，该应用程序将定义三个`string`值数组，用于学徒队列，然后对它们执行一些常见的集合和多重集合操作：

1.  使用您喜欢的代码编辑器，在`Chapter11`解决方案/工作区中添加一个名为`LinqWithSets`的新控制台应用程序：

    1.  在 Visual Studio 中，将解决方案的启动项目设置为当前选择。

    1.  在 Visual Studio Code 中，选择`LinqWithSets`作为活动 OmniSharp 项目。

1.  在`Program.cs`中，删除现有代码并静态导入`Console`类型，如下面的代码所示：

    ```cs
    using static System.Console; 
    ```

1.  在`Program.cs`底部，添加以下方法，该方法将任何`string`变量序列输出为以逗号分隔的单个`string`到控制台输出，以及一个可选描述，如下面的代码所示：

    ```cs
    static void Output(IEnumerable<string> cohort, string description = "")
    {
      if (!string.IsNullOrEmpty(description))
      {
        WriteLine(description);
      }
      Write(" ");
      WriteLine(string.Join(", ", cohort.ToArray()));
      WriteLine();
    } 
    ```

1.  在`Output`方法上方，添加语句以定义三个名称数组，输出它们，然后对它们执行各种集合操作，如下面的代码所示：

    ```cs
    string[] cohort1 = new[]
      { "Rachel", "Gareth", "Jonathan", "George" }; 
    string[] cohort2 = new[]
      { "Jack", "Stephen", "Daniel", "Jack", "Jared" }; 
    string[] cohort3 = new[]
      { "Declan", "Jack", "Jack", "Jasmine", "Conor" }; 
    Output(cohort1, "Cohort 1");
    Output(cohort2, "Cohort 2");
    Output(cohort3, "Cohort 3"); 
    Output(cohort2.Distinct(), "cohort2.Distinct()"); 
    Output(cohort2.DistinctBy(name => name.Substring(0, 2)), 
      "cohort2.DistinctBy(name => name.Substring(0, 2)):");
    Output(cohort2.Union(cohort3), "cohort2.Union(cohort3)"); 
    Output(cohort2.Concat(cohort3), "cohort2.Concat(cohort3)"); 
    Output(cohort2.Intersect(cohort3), "cohort2.Intersect(cohort3)"); 
    Output(cohort2.Except(cohort3), "cohort2.Except(cohort3)"); 
    Output(cohort1.Zip(cohort2,(c1, c2) => $"{c1} matched with {c2}"), 
      "cohort1.Zip(cohort2)"); 
    ```

1.  运行代码并查看结果，如下面的输出所示：

    ```cs
    Cohort 1
      Rachel, Gareth, Jonathan, George 
    Cohort 2
      Jack, Stephen, Daniel, Jack, Jared 
    Cohort 3
      Declan, Jack, Jack, Jasmine, Conor 
    cohort2.Distinct()
      Jack, Stephen, Daniel, Jared 
    cohort2.DistinctBy(name => name.Substring(0, 2)):
      Jack, Stephen, Daniel 
    cohort2.Union(cohort3)
      Jack, Stephen, Daniel, Jared, Declan, Jasmine, Conor 
    cohort2.Concat(cohort3)
      Jack, Stephen, Daniel, Jack, Jared, Declan, Jack, Jack, Jasmine, Conor 
    cohort2.Intersect(cohort3)
      Jack 
    cohort2.Except(cohort3)
      Stephen, Daniel, Jared 
    cohort1.Zip(cohort2)
      Rachel matched with Jack, Gareth matched with Stephen, Jonathan matched with Daniel, George matched with Jack 
    ```

使用`Zip`时，如果两个序列中的项数不相等，那么有些项将没有匹配的伙伴。没有伙伴的项，如`Jared`，将不会包含在结果中。

对于`DistinctBy`示例，我们不是通过比较整个名称来移除重复项，而是定义了一个 lambda 键选择器，通过比较前两个字符来移除重复项，因此`Jared`被移除，因为`Jack`已经是一个以`Ja`开头的名称。

到目前为止，我们使用了 LINQ to Objects 提供程序来处理内存中的对象。接下来，我们将使用 LINQ to Entities 提供程序来处理存储在数据库中的实体。

# 使用 LINQ 与 EF Core

我们已经看过过滤和排序的 LINQ 查询，但没有改变序列中项的形状的查询。这称为**投影**，因为它涉及将一种形状的项投影到另一种形状。为了学习投影，最好有一些更复杂的类型来操作，所以在下一个项目中，我们将不再使用`string`序列，而是使用来自 Northwind 示例数据库的实体序列。

我将给出使用 SQLite 的指令，因为它跨平台，但如果你更喜欢使用 SQL Server，请随意。我已包含一些注释代码，以便在你选择时启用 SQL Server。

## 构建 EF Core 模型

我们必须定义一个 EF Core 模型来表示我们将要操作的数据库和表。我们将手动定义模型以完全控制并防止在`Categories`和`Products`表之间自动定义关系。稍后，您将使用 LINQ 来连接这两个实体集：

1.  使用您喜欢的代码编辑器向`Chapter11`解决方案/工作区中添加一个名为`LinqWithEFCore`的新控制台应用程序。

1.  在 Visual Studio Code 中，选择`LinqWithEFCore`作为活动 OmniSharp 项目。

1.  在`LinqWithEFCore`项目中，添加对 SQLite 和/或 SQL Server 的 EF Core 提供程序的包引用，如下所示：

    ```cs
    <ItemGroup>
      <PackageReference
        Include="Microsoft.EntityFrameworkCore.Sqlite"
        Version="6.0.0" />
      <PackageReference
        Include="Microsoft.EntityFrameworkCore.SqlServer"
        Version="6.0.0" />
    </ItemGroup> 
    ```

1.  构建项目以恢复包。

1.  将`Northwind4Sqlite.sql`文件复制到`LinqWithEFCore`文件夹中。

1.  在命令提示符或终端中，执行以下命令创建 Northwind 数据库：

    ```cs
    sqlite3 Northwind.db -init Northwind4Sqlite.sql 
    ```

1.  请耐心等待，因为这个命令可能需要一段时间来创建数据库结构。最终，您将看到 SQLite 命令提示符，如下所示：

    ```cs
     -- Loading resources from Northwind.sql 
    SQLite version 3.36.0 2021-08-02 15:20:15
    Enter ".help" for usage hints.
    sqlite> 
    ```

1.  在 macOS 上按 cmd + D 或在 Windows 上按 Ctrl + C 退出 SQLite 命令模式。

1.  向项目中添加三个类文件，分别命名为`Northwind.cs`、`Category.cs`和`Product.cs`。

1.  修改名为`Northwind.cs`的类文件，如下所示：

    ```cs
    using Microsoft.EntityFrameworkCore; // DbContext, DbSet<T>
    namespace Packt.Shared;
    // this manages the connection to the database
    public class Northwind : DbContext
    {
      // these properties map to tables in the database
      public DbSet<Category>? Categories { get; set; }
      public DbSet<Product>? Products { get; set; }
      protected override void OnConfiguring(
        DbContextOptionsBuilder optionsBuilder)
      {
        string path = Path.Combine(
          Environment.CurrentDirectory, "Northwind.db");
        optionsBuilder.UseSqlite($"Filename={path}");
        /*
        string connection = "Data Source=.;" +
            "Initial Catalog=Northwind;" +
            "Integrated Security=true;" +
            "MultipleActiveResultSets=true;";
        optionsBuilder.UseSqlServer(connection);
        */
      }
      protected override void OnModelCreating(
        ModelBuilder modelBuilder)
      {
        modelBuilder.Entity<Product>()
          .Property(product => product.UnitPrice)
          .HasConversion<double>();
      }
    } 
    ```

1.  修改名为`Category.cs`的类文件，如下所示：

    ```cs
    using System.ComponentModel.DataAnnotations;
    namespace Packt.Shared;
    public class Category
    {
      public int CategoryId { get; set; }
      [Required]
      [StringLength(15)]
      public string CategoryName { get; set; } = null!;
      public string? Description { get; set; }
    } 
    ```

1.  修改名为`Product.cs`的类文件，如下所示：

    ```cs
    using System.ComponentModel.DataAnnotations; 
    using System.ComponentModel.DataAnnotations.Schema;
    namespace Packt.Shared;
    public class Product
    {
      public int ProductId { get; set; }
      [Required]
      [StringLength(40)]
      public string ProductName { get; set; } = null!;
      public int? SupplierId { get; set; }
      public int? CategoryId { get; set; }
      [StringLength(20)]
      public string? QuantityPerUnit { get; set; }
      [Column(TypeName = "money")] // required for SQL Server provider
      public decimal? UnitPrice { get; set; }
      public short? UnitsInStock { get; set; }
      public short? UnitsOnOrder { get; set; }
      public short? ReorderLevel { get; set; }
      public bool Discontinued { get; set; }
    } 
    ```

1.  构建项目并修复任何编译器错误。

    如果您使用的是 Windows 上的 Visual Studio 2022，那么编译后的应用程序将在`LinqWithEFCore\bin\Debug\net6.0`文件夹中执行，因此除非我们指示应始终将其复制到输出目录，否则它将找不到数据库文件。

1.  在**解决方案资源管理器**中，右键单击`Northwind.db`文件并选择**属性**。

1.  在**属性**中，将**复制到输出目录**设置为**始终复制**。

## 过滤和排序序列

现在让我们编写语句来过滤和排序来自表的行序列：

1.  在`Program.cs`中，静态导入`Console`类型和用于使用 EF Core 和实体模型进行 LINQ 操作的命名空间，如下列代码所示：

    ```cs
    using Packt.Shared; // Northwind, Category, Product
    using Microsoft.EntityFrameworkCore; // DbSet<T>
    using static System.Console; 
    ```

1.  在`Program.cs`底部，编写一个方法来过滤和排序产品，如下列代码所示：

    ```cs
    static void FilterAndSort()
    {
      using (Northwind db = new())
      {
        DbSet<Product> allProducts = db.Products;
        IQueryable<Product> filteredProducts = 
          allProducts.Where(product => product.UnitPrice < 10M);
        IOrderedQueryable<Product> sortedAndFilteredProducts = 
          filteredProducts.OrderByDescending(product => product.UnitPrice);
        WriteLine("Products that cost less than $10:");
        foreach (Product p in sortedAndFilteredProducts)
        {
          WriteLine("{0}: {1} costs {2:$#,##0.00}",
            p.ProductId, p.ProductName, p.UnitPrice);
        }
        WriteLine();
      }
    } 
    ```

    `DbSet<T>`实现`IEnumerable<T>`，因此 LINQ 可用于查询和操作为 EF Core 构建的模型中的实体集合。（实际上，我应该说`TEntity`而不是`T`，但此泛型类型的名称没有功能性影响。唯一的要求是类型是一个`class`。名称仅表示预期该类是一个实体模型。）

    您可能还注意到，序列实现的是`IQueryable<T>`（或在调用排序 LINQ 方法后实现`IOrderedQueryable<T>`）而不是`IEnumerable<T>`或`IOrderedEnumerable<T>`。

    这表明我们正在使用一个 LINQ 提供程序，该提供程序使用表达式树在内存中构建查询。它们以树状数据结构表示代码，并支持创建动态查询，这对于构建针对 SQLite 等外部数据提供程序的 LINQ 查询非常有用。

    LINQ 表达式将被转换成另一种查询语言，如 SQL。使用`foreach`枚举查询或调用`ToArray`等方法将强制执行查询并具体化结果。

1.  在`Program.cs`中的命名空间导入之后，调用`FilterAndSort`方法。

1.  运行代码并查看结果，如下列输出所示：

    ```cs
    Products that cost less than $10:
    41: Jack's New England Clam Chowder costs $9.65 
    45: Rogede sild costs $9.50
    47: Zaanse koeken costs $9.50
    19: Teatime Chocolate Biscuits costs $9.20 
    23: Tunnbröd costs $9.00
    75: Rhönbräu Klosterbier costs $7.75 
    54: Tourtière costs $7.45
    52: Filo Mix costs $7.00 
    13: Konbu costs $6.00
    24: Guaraná Fantástica costs $4.50 
    33: Geitost costs $2.50 
    ```

尽管此查询输出了我们所需的信息，但这样做效率低下，因为它从`Products`表中获取了所有列，而不是我们需要的三个列，这相当于以下 SQL 语句：

```cs
SELECT * FROM Products; 
```

在*第十章*，*使用 Entity Framework Core 处理数据*中，您学习了如何记录针对 SQLite 执行的 SQL 命令，以便您可以亲自查看。

## 将序列投影到新类型

在查看投影之前，我们需要回顾对象初始化语法。如果您定义了一个类，那么您可以使用类名、`new()`和花括号来设置字段和属性的初始值，如下列代码所示：

```cs
public class Person
{
  public string Name { get; set; }
  public DateTime DateOfBirth { get; set; }
}
Person knownTypeObject = new()
{
  Name = "Boris Johnson",
  DateOfBirth = new(year: 1964, month: 6, day: 19)
}; 
```

C# 3.0 及更高版本允许使用`var`关键字实例化**匿名类型**，如下列代码所示：

```cs
var anonymouslyTypedObject = new
{
  Name = "Boris Johnson",
  DateOfBirth = new DateTime(year: 1964, month: 6, day: 19)
}; 
```

尽管我们没有指定类型，但编译器可以从设置的两个属性`Name`和`DateOfBirth`推断出匿名类型。编译器可以从分配的值推断出这两个属性的类型：一个字符串字面量和一个新的日期/时间值实例。

当编写 LINQ 查询以将现有类型投影到新类型而不必显式定义新类型时，此功能特别有用。由于类型是匿名的，因此这只能与`var`声明的局部变量一起工作。

让我们通过添加对`Select`方法的调用，将`Product`类的实例投影到仅具有三个属性的新匿名类型的实例，从而使针对数据库表执行的 SQL 命令更高效：

1.  在`FilterAndSort`中，添加一条语句以扩展 LINQ 查询，使用`Select`方法仅返回我们需要的三个属性（即表列），并修改`foreach`语句以使用`var`关键字和投影 LINQ 表达式，如下所示高亮显示：

    ```cs
    IOrderedQueryable<Product> sortedAndFilteredProducts = 
      filteredProducts.OrderByDescending(product => product.UnitPrice);
    **var** **projectedProducts = sortedAndFilteredProducts**
     **.Select(product =>** **new****// anonymous type**
     **{**
     **product.ProductId,**
     **product.ProductName,** 
     **product.UnitPrice**
     **});**
    WriteLine("Products that cost less than $10:");
    foreach (**var** **p** **in** **projectedProducts**)
    { 
    ```

1.  将鼠标悬停在`Select`方法调用中的`new`关键字和`foreach`语句中的`var`关键字上，并注意它是一个匿名类型，如*图 11.4*所示：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_12_05.png)

    *图 11.4*：LINQ 投影期间使用的匿名类型

1.  运行代码并确认输出与之前相同。

## 连接和分组序列

连接和分组有两种扩展方法：

+   **Join**：此方法有四个参数：您想要连接的序列，要匹配的*左侧*序列上的属性或属性，要匹配的*右侧*序列上的属性或属性，以及一个投影。

+   **GroupJoin**：此方法具有相同的参数，但它将匹配项合并到一个组对象中，该对象具有用于匹配值的`Key`属性和用于多个匹配项的`IEnumerable<T>`类型。

### 连接序列

让我们在处理两个表：`Categories`和`Products`时探索这些方法：

1.  在`Program.cs`底部，创建一个方法来选择类别和产品，将它们连接起来并输出，如下所示：

    ```cs
    static void JoinCategoriesAndProducts()
    {
      using (Northwind db = new())
      {
        // join every product to its category to return 77 matches
        var queryJoin = db.Categories.Join(
          inner: db.Products,
          outerKeySelector: category => category.CategoryId,
          innerKeySelector: product => product.CategoryId,
          resultSelector: (c, p) =>
            new { c.CategoryName, p.ProductName, p.ProductId });
        foreach (var item in queryJoin)
        {
          WriteLine("{0}: {1} is in {2}.",
            arg0: item.ProductId,
            arg1: item.ProductName,
            arg2: item.CategoryName);
        }
      }
    } 
    ```

    在连接中，有两个序列，*外部*和*内部*。在前面的示例中，`categories`是外部序列，`products`是内部序列。

1.  在`Program.cs`顶部，注释掉对`FilterAndSort`的调用，改为调用`JoinCategoriesAndProducts`。

1.  运行代码并查看结果。请注意，对于 77 种产品中的每一种，都有一行输出，如下所示的输出（编辑后仅包括前 10 项）：

    ```cs
    1: Chai is in Beverages. 
    2: Chang is in Beverages.
    3: Aniseed Syrup is in Condiments.
    4: Chef Anton's Cajun Seasoning is in Condiments. 
    5: Chef Anton's Gumbo Mix is in Condiments.
    6: Grandma's Boysenberry Spread is in Condiments. 
    7: Uncle Bob's Organic Dried Pears is in Produce. 
    8: Northwoods Cranberry Sauce is in Condiments.
    9: Mishi Kobe Niku is in Meat/Poultry. 
    10: Ikura is in Seafood.
    ... 
    ```

1.  在现有查询的末尾，调用`OrderBy`方法按`CategoryName`排序，如下所示：

    ```cs
    .OrderBy(cp => cp.CategoryName); 
    ```

1.  运行代码并查看结果。请注意，对于 77 种产品中的每一种，都有一行输出，结果首先显示`Beverages`类别中的所有产品，然后是`Condiments`类别，依此类推，如下所示的部分输出：

    ```cs
    1: Chai is in Beverages. 
    2: Chang is in Beverages.
    24: Guaraná Fantástica is in Beverages. 
    34: Sasquatch Ale is in Beverages.
    35: Steeleye Stout is in Beverages. 
    38: Côte de Blaye is in Beverages. 
    39: Chartreuse verte is in Beverages. 
    43: Ipoh Coffee is in Beverages.
    67: Laughing Lumberjack Lager is in Beverages. 
    70: Outback Lager is in Beverages.
    75: Rhönbräu Klosterbier is in Beverages. 
    76: Lakkalikööri is in Beverages.
    3: Aniseed Syrup is in Condiments.
    4: Chef Anton's Cajun Seasoning is in Condiments.
    ... 
    ```

### 分组连接序列

1.  在`Program.cs`底部，创建一个方法来分组和连接，显示组名，然后显示每个组内的所有项，如下列代码所示：

    ```cs
    static void GroupJoinCategoriesAndProducts()
    {
      using (Northwind db = new())
      {
        // group all products by their category to return 8 matches
        var queryGroup = db.Categories.AsEnumerable().GroupJoin(
          inner: db.Products,
          outerKeySelector: category => category.CategoryId,
          innerKeySelector: product => product.CategoryId,
          resultSelector: (c, matchingProducts) => new
          {
            c.CategoryName,
            Products = matchingProducts.OrderBy(p => p.ProductName)
          });
        foreach (var category in queryGroup)
        {
          WriteLine("{0} has {1} products.",
            arg0: category.CategoryName,
            arg1: category.Products.Count());
          foreach (var product in category.Products)
          {
            WriteLine($" {product.ProductName}");
          }
        }
      }
    } 
    ```

    如果我们没有调用`AsEnumerable`方法，那么将会抛出一个运行时异常，如下列输出所示：

    ```cs
    Unhandled exception. System.ArgumentException:  Argument type 'System.Linq.IOrderedQueryable`1[Packt.Shared.Product]' does not match the corresponding member type 'System.Linq.IOrderedEnumerable`1[Packt.Shared.Product]' (Parameter 'arguments[1]') 
    ```

    这是因为并非所有 LINQ 扩展方法都能从表达式树转换为其他查询语法，如 SQL。在这些情况下，我们可以通过调用`AsEnumerable`方法将`IQueryable<T>`转换为`IEnumerable<T>`，这迫使查询处理仅使用 LINQ to EF Core 将数据带入应用程序，然后使用 LINQ to Objects 在内存中执行更复杂的处理。但通常，这效率较低。

1.  在`Program.cs`顶部，注释掉之前的方法调用，并调用`GroupJoinCategoriesAndProducts`。

1.  运行代码，查看结果，并注意每个类别内的产品已按其名称排序，正如查询中所定义，并在以下部分输出中所示：

    ```cs
    Beverages has 12 products.
      Chai
      Chang
      Chartreuse verte
      Côte de Blaye
      Guaraná Fantástica
      Ipoh Coffee
      Lakkalikööri
      Laughing Lumberjack Lager
      Outback Lager
      Rhönbräu Klosterbier
      Sasquatch Ale
      Steeleye Stout
    Condiments has 12 products.
      Aniseed Syrup
      Chef Anton's Cajun Seasoning
      Chef Anton's Gumbo Mix
    ... 
    ```

## 聚合序列

有 LINQ 扩展方法可执行聚合函数，如`Average`和`Sum`。让我们编写一些代码，看看这些方法如何从`Products`表中聚合信息：

1.  在`Program.cs`底部，创建一个方法来展示聚合扩展方法的使用，如下列代码所示：

    ```cs
    static void AggregateProducts()
    {
      using (Northwind db = new())
      {
        WriteLine("{0,-25} {1,10}",
          arg0: "Product count:",
          arg1: db.Products.Count());
        WriteLine("{0,-25} {1,10:$#,##0.00}",
          arg0: "Highest product price:",
          arg1: db.Products.Max(p => p.UnitPrice));
        WriteLine("{0,-25} {1,10:N0}",
          arg0: "Sum of units in stock:",
          arg1: db.Products.Sum(p => p.UnitsInStock));
        WriteLine("{0,-25} {1,10:N0}",
          arg0: "Sum of units on order:",
          arg1: db.Products.Sum(p => p.UnitsOnOrder));
        WriteLine("{0,-25} {1,10:$#,##0.00}",
          arg0: "Average unit price:",
          arg1: db.Products.Average(p => p.UnitPrice));
        WriteLine("{0,-25} {1,10:$#,##0.00}",
          arg0: "Value of units in stock:",
          arg1: db.Products
            .Sum(p => p.UnitPrice * p.UnitsInStock));
      }
    } 
    ```

1.  在`Program.cs`顶部，注释掉之前的方法调用，并调用`AggregateProducts`

1.  运行代码并查看结果，如下列输出所示：

    ```cs
    Product count:                    77
    Highest product price:       $263.50
    Sum of units in stock:         3,119
    Sum of units on order:           780
    Average unit price:           $28.87
    Value of units in stock:  $74,050.85 
    ```

# 用语法糖美化 LINQ 语法

C# 3.0 在 2008 年引入了一些新的语言关键字，以便有 SQL 经验的程序员更容易编写 LINQ 查询。这种语法糖有时被称为**LINQ 查询理解语法**。

考虑以下`string`值数组：

```cs
string[] names = new[] { "Michael", "Pam", "Jim", "Dwight", 
  "Angela", "Kevin", "Toby", "Creed" }; 
```

要筛选和排序名称，可以使用扩展方法和 lambda 表达式，如下列代码所示：

```cs
var query = names
  .Where(name => name.Length > 4)
  .OrderBy(name => name.Length)
  .ThenBy(name => name); 
```

或者，你可以使用查询理解语法实现相同的结果，如下列代码所示：

```cs
var query = from name in names
  where name.Length > 4
  orderby name.Length, name 
  select name; 
```

编译器会将查询理解语法转换为等效的扩展方法和 lambda 表达式。

`select`关键字在 LINQ 查询理解语法中始终是必需的。当使用扩展方法和 lambda 表达式时，`Select`扩展方法是可选的，因为如果你没有调用`Select`，那么整个项会被隐式选中。

并非所有扩展方法都有 C#关键字等效项，例如，常用的`Skip`和`Take`扩展方法，用于为大量数据实现分页。

使用查询理解语法无法编写跳过和获取的查询，因此我们可以使用所有扩展方法编写查询，如下列代码所示：

```cs
var query = names
  .Where(name => name.Length > 4)
  .Skip(80)
  .Take(10); 
```

或者，你可以将查询理解语法括在括号内，然后切换到使用扩展方法，如下列代码所示：

```cs
var query = (from name in names
  where name.Length > 4
  select name)
  .Skip(80)
  .Take(10); 
```

**良好实践**：学习使用 Lambda 表达式的扩展方法和查询理解语法两种编写 LINQ 查询的方式，因为你可能需要维护使用这两种方式的代码。

# 使用并行 LINQ 的多线程

默认情况下，LINQ 查询仅使用一个线程执行。**并行 LINQ**（**PLINQ**）是一种启用多个线程执行 LINQ 查询的简便方法。

**良好实践**：不要假设使用并行线程会提高应用程序的性能。始终测量实际的计时和资源使用情况。

## 创建一个从多线程中受益的应用

为了实际演示，我们将从一段仅使用单个线程计算 45 个整数的斐波那契数的代码开始。我们将使用`StopWatch`类型来测量性能变化。

我们将使用操作系统工具来监控 CPU 和 CPU 核心的使用情况。如果你没有多个 CPU 或至少多个核心，那么这个练习就不会显示太多信息！

1.  使用你偏好的代码编辑器，在`Chapter11`解决方案/工作区中添加一个名为`LinqInParallel`的新控制台应用。

1.  在 Visual Studio Code 中，选择`LinqInParallel`作为活动的 OmniSharp 项目。

1.  在`Program.cs`中，删除现有语句，然后导入`System.Diagnostics`命名空间，以便我们可以使用`StopWatch`类型，并静态导入`System.Console`类型。

1.  添加语句以创建一个秒表来记录时间，等待按键开始计时，创建 45 个整数，计算每个整数的最后一个斐波那契数，停止计时器，并显示经过的毫秒数，如下面的代码所示：

    ```cs
    Stopwatch watch = new(); 
    Write("Press ENTER to start. "); 
    ReadLine();
    watch.Start();
    int max = 45;
    IEnumerable<int> numbers = Enumerable.Range(start: 1, count: max);
    WriteLine($"Calculating Fibonacci sequence up to {max}. Please wait...");
    int[] fibonacciNumbers = numbers
      .Select(number => Fibonacci(number)).ToArray(); 
    watch.Stop();
    WriteLine("{0:#,##0} elapsed milliseconds.",
      arg0: watch.ElapsedMilliseconds);
    Write("Results:");
    foreach (int number in fibonacciNumbers)
    {
      Write($" {number}");
    }
    static int Fibonacci(int term) =>
      term switch
      {
        1 => 0,
        2 => 1,
        _ => Fibonacci(term - 1) + Fibonacci(term - 2)
      }; 
    ```

1.  运行代码，但不要按 Enter 键启动秒表，因为我们首先需要确保监控工具显示处理器活动。

### 使用 Windows

1.  如果你使用的是 Windows，那么右键点击 Windows **开始**按钮或按 Ctrl + Alt + Delete，然后点击**任务管理器**。

1.  在**任务管理器**窗口底部，点击**更多详细信息**。

1.  在**任务管理器**窗口顶部，点击**性能**选项卡。

1.  右键点击**CPU 利用率**图表，选择**更改图表为**，然后选择**逻辑处理器**。

### 使用 macOS

1.  如果你使用的是 macOS，那么启动**活动监视器**。

1.  导航至**视图** | **更新频率非常频繁（1 秒）**。

1.  要查看 CPU 图表，请导航至**窗口** | **CPU 历史**。

### 对于所有操作系统

1.  调整你的监控工具和代码编辑器，使它们并排显示。

1.  等待 CPU 稳定后，按 Enter 键启动秒表并运行查询。结果应显示为经过的毫秒数，如下面的输出所示：

    ```cs
    Press ENTER to start. 
    Calculating Fibonacci sequence up to 45\. Please wait...
    17,624 elapsed milliseconds.
    Results: 0 1 1 2 3 5 8 13 21 34 55 89 144 233 377 610 987 1597 2584 4181 6765 10946 17711 28657 46368 75025 121393 196418 317811 514229 832040 1346269 2178309 3524578 5702887 9227465 14930352 24157817 39088169 63245986 102334155 165580141 267914296 433494437 701408733 
    ```

    监控工具可能会显示，有一两个 CPU 使用率最高，随着时间交替变化，其他 CPU 可能同时执行后台任务，如垃圾收集器，因此其他 CPU 或核心不会完全空闲，但工作显然没有均匀分布在所有可能的 CPU 或核心上。还要注意，一些逻辑处理器达到了 100%的峰值。

1.  在`Program.cs`中，修改查询以调用`AsParallel`扩展方法并对结果序列进行排序，因为在并行处理时结果可能会变得无序，如下面的代码所示：

    ```cs
    int[] fibonacciNumbers = numbers.**AsParallel()**
      .Select(number => Fibonacci(number))
     **.OrderBy(number => number)**
      .ToArray(); 
    ```

    **最佳实践**：切勿在查询的末尾调用`AsParallel`。这没有任何作用。你必须在调用`AsParallel`之后至少执行一个操作，以便该操作可以并行化。.NET 6 引入了一个代码分析器，它会警告这种误用。

1.  运行代码，等待监控工具中的 CPU 图表稳定，然后按 Enter 键启动秒表并运行查询。这次，应用程序应该在更短的时间内完成（尽管可能不会像你希望的那样短——管理那些多线程需要额外的努力！）：

    ```cs
    Press ENTER to start. 
    Calculating Fibonacci sequence up to 45\. Please wait...
    9,028 elapsed milliseconds.
    Results: 0 1 1 2 3 5 8 13 21 34 55 89 144 233 377 610 987 1597 2584 4181 6765 10946 17711 28657 46368 75025 121393 196418 317811 514229 832040 1346269 2178309 3524578 5702887 9227465 14930352 24157817 39088169 63245986 102334155 165580141 267914296 433494437 701408733 
    ```

1.  监控工具应该显示所有 CPU 都平均用于执行 LINQ 查询，并注意没有逻辑处理器达到 100%的峰值，因为工作分布更为均匀。

你将在*第十二章*，*使用多任务提高性能和可扩展性*中了解更多关于管理多线程的知识。

# 创建自己的 LINQ 扩展方法

在*第六章*，*实现接口和继承类*中，你学习了如何创建自己的扩展方法。要创建 LINQ 扩展方法，你所需要做的就是扩展`IEnumerable<T>`类型。

**最佳实践**：将你自己的扩展方法放在一个单独的类库中，以便它们可以轻松地作为自己的程序集或 NuGet 包部署。

我们将以改进`Average`扩展方法为例。一个受过良好教育的学童会告诉你，*平均*可以指三种情况之一：

+   **均值**：将数字求和并除以计数。

+   **众数**：最常见的数字。

+   **中位数**：当数字排序时位于中间的数字。

微软实现的`Average`扩展方法计算的是*均值*。我们可能希望为`Mode`和`Median`定义自己的扩展方法：

1.  在`LinqWithEFCore`项目中，添加一个名为`MyLinqExtensions.cs`的新类文件。

1.  按照以下代码所示修改类：

    ```cs
    namespace System.Linq; // extend Microsoft's namespace
    public static class MyLinqExtensions
    {
      // this is a chainable LINQ extension method
      public static IEnumerable<T> ProcessSequence<T>(
        this IEnumerable<T> sequence)
      {
        // you could do some processing here
        return sequence;
      }
      public static IQueryable<T> ProcessSequence<T>(
        this IQueryable<T> sequence)
      {
        // you could do some processing here
        return sequence;
      }
      // these are scalar LINQ extension methods
      public static int? Median(
        this IEnumerable<int?> sequence)
      {
        var ordered = sequence.OrderBy(item => item);
        int middlePosition = ordered.Count() / 2;
        return ordered.ElementAt(middlePosition);
      }
      public static int? Median<T>(
        this IEnumerable<T> sequence, Func<T, int?> selector)
      {
        return sequence.Select(selector).Median();
      }
      public static decimal? Median(
        this IEnumerable<decimal?> sequence)
      {
        var ordered = sequence.OrderBy(item => item);
        int middlePosition = ordered.Count() / 2;
        return ordered.ElementAt(middlePosition);
      }
      public static decimal? Median<T>(
        this IEnumerable<T> sequence, Func<T, decimal?> selector)
      {
        return sequence.Select(selector).Median();
      }
      public static int? Mode(
        this IEnumerable<int?> sequence)
      {
        var grouped = sequence.GroupBy(item => item);
        var orderedGroups = grouped.OrderByDescending(
          group => group.Count());
        return orderedGroups.FirstOrDefault()?.Key;
      }
      public static int? Mode<T>(
        this IEnumerable<T> sequence, Func<T, int?> selector)
      {
        return sequence.Select(selector)?.Mode();
      }
      public static decimal? Mode(
        this IEnumerable<decimal?> sequence)
      {
        var grouped = sequence.GroupBy(item => item);
        var orderedGroups = grouped.OrderByDescending(
          group => group.Count());
        return orderedGroups.FirstOrDefault()?.Key;
      }
      public static decimal? Mode<T>(
        this IEnumerable<T> sequence, Func<T, decimal?> selector)
      {
        return sequence.Select(selector).Mode();
      }
    } 
    ```

如果这个类位于一个单独的类库中，要使用你的 LINQ 扩展方法，你只需引用类库程序集，因为`System.Linq`命名空间已经隐式导入。

**警告！**上述扩展方法中除一个外，都不能与`IQueryable`序列（如 LINQ to SQLite 或 LINQ to SQL Server 使用的序列）一起使用，因为我们没有实现将我们的代码翻译成底层查询语言（如 SQL）的方法。

### 尝试使用链式扩展方法

首先，我们将尝试将`ProcessSequence`方法与其他扩展方法链接起来：

1.  在`Program.cs`中，在`FilterAndSort`方法中，修改`Products`的 LINQ 查询以调用您的自定义链式扩展方法，如下面的代码中突出显示的那样：

    ```cs
    DbSet<Product>? allProducts = db.Products;
    if (allProducts is null)
    {
      WriteLine("No products found.");
      return;
    }
    **IQueryable<Product> processedProducts = allProducts.ProcessSequence();**
    IQueryable<Product> filteredProducts = **processedProducts**
      .Where(product => product.UnitPrice < 10M); 
    ```

1.  在`Program.cs`中，取消注释`FilterAndSort`方法，并注释掉对其他方法的任何调用。

1.  运行代码并注意您看到与之前相同的输出，因为您的方法没有修改序列。但现在您知道如何通过自己的功能扩展 LINQ 表达式。

### 尝试使用众数和中位数方法

其次，我们将尝试使用`Mode`和`Median`方法来计算其他类型的平均值：

1.  在`Program.cs`底部，创建一个方法来输出产品的`UnitsInStock`和`UnitPrice`的平均值、中位数和众数，使用您的自定义扩展方法和内置的`Average`扩展方法，如下面的代码所示：

    ```cs
    static void CustomExtensionMethods()
    {
      using (Northwind db = new())
      {
        WriteLine("Mean units in stock: {0:N0}",
          db.Products.Average(p => p.UnitsInStock));
        WriteLine("Mean unit price: {0:$#,##0.00}",
          db.Products.Average(p => p.UnitPrice));
        WriteLine("Median units in stock: {0:N0}",
          db.Products.Median(p => p.UnitsInStock));
        WriteLine("Median unit price: {0:$#,##0.00}",
          db.Products.Median(p => p.UnitPrice));
        WriteLine("Mode units in stock: {0:N0}",
          db.Products.Mode(p => p.UnitsInStock));
        WriteLine("Mode unit price: {0:$#,##0.00}",
          db.Products.Mode(p => p.UnitPrice));
      }
    } 
    ```

1.  在`Program.cs`中，注释掉任何之前的方法调用，并调用`CustomExtensionMethods`。

1.  运行代码并查看结果，如下面的输出所示：

    ```cs
    Mean units in stock: 41 
    Mean unit price: $28.87 
    Median units in stock: 26 
    Median unit price: $19.50 
    Mode units in stock: 0 
    Mode unit price: $18.00 
    ```

有四种产品的单价为$18.00。有五种产品的库存量为 0。

# 使用 LINQ to XML 进行工作

**LINQ to XML**是一种 LINQ 提供程序，允许您查询和操作 XML。

## 使用 LINQ to XML 生成 XML

让我们创建一个方法将`Products`表转换为 XML：

1.  在`LinqWithEFCore`项目中，在`Program.cs`顶部导入`System.Xml.Linq`命名空间。

1.  在`Program.cs`底部，创建一个方法以 XML 格式输出产品，如下面的代码所示：

    ```cs
    static void OutputProductsAsXml()
    {
      using (Northwind db = new())
      {
        Product[] productsArray = db.Products.ToArray();
        XElement xml = new("products",
          from p in productsArray
          select new XElement("product",
            new XAttribute("id",  p.ProductId),
            new XAttribute("price", p.UnitPrice),
           new XElement("name", p.ProductName)));
        WriteLine(xml.ToString());
      }
    } 
    ```

1.  在`Program.cs`中，注释掉之前的方法调用，并调用`OutputProductsAsXml`。

1.  运行代码，查看结果，并注意生成的 XML 结构与 LINQ to XML 语句在前述代码中声明性地描述的元素和属性相匹配，如下面的部分输出所示：

    ```cs
    <products>
      <product id="1" price="18">
        <name>Chai</name>
      </product>
      <product id="2" price="19">
        <name>Chang</name>
      </product>
    ... 
    ```

## 使用 LINQ to XML 读取 XML

您可能希望使用 LINQ to XML 轻松查询或处理 XML 文件：

1.  在`LinqWithEFCore`项目中，添加一个名为`settings.xml`的文件。

1.  修改其内容，如下面的标记所示：

    ```cs
    <?xml version="1.0" encoding="utf-8" ?>
    <appSettings>
      <add key="color" value="red" />
      <add key="size" value="large" />
      <add key="price" value="23.99" />
    </appSettings> 
    ```

    如果您使用的是 Windows 上的 Visual Studio 2022，那么编译后的应用程序将在`LinqWithEFCore\bin\Debug\net6.0`文件夹中执行，因此除非我们指示它始终复制到输出目录，否则它将找不到`settings.xml`文件。

1.  在**解决方案资源管理器**中，右键单击`settings.xml`文件并选择**属性**。

1.  在**属性**中，将**复制到输出目录**设置为**始终复制**。

1.  在`Program.cs`底部，创建一个方法来完成这些任务，如下面的代码所示：

    +   加载 XML 文件。

    +   使用 LINQ to XML 搜索名为`appSettings`的元素及其名为`add`的后代。

    +   将 XML 投影成具有`Key`和`Value`属性的匿名类型数组。

    +   遍历数组以显示结果：

    ```cs
    static void ProcessSettings()
    {
      XDocument doc = XDocument.Load("settings.xml");
      var appSettings = doc.Descendants("appSettings")
        .Descendants("add")
        .Select(node => new
        {
          Key = node.Attribute("key")?.Value,
          Value = node.Attribute("value")?.Value
        }).ToArray();
      foreach (var item in appSettings)
      {
        WriteLine($"{item.Key}: {item.Value}");
      }
    } 
    ```

1.  在`Program.cs`中，注释掉之前的方法调用，并调用`ProcessSettings`。

1.  运行代码并查看结果，如下所示：

    ```cs
    color: red 
    size: large 
    price: 23.99 
    ```

# 实践与探索

通过回答一些问题，进行一些实践练习，并深入研究本章涵盖的主题，来测试你的知识和理解。

## 练习 11.1 – 测试你的知识

回答以下问题：

1.  LINQ 的两个必要组成部分是什么？

1.  要返回一个类型的部分属性子集，你会使用哪个 LINQ 扩展方法？

1.  要过滤序列，你会使用哪个 LINQ 扩展方法？

1.  列出五个执行聚合操作的 LINQ 扩展方法。

1.  扩展方法`Select`和`SelectMany`之间有何区别？

1.  `IEnumerable<T>`与`IQueryable<T>`的区别是什么？以及如何在这两者之间切换？

1.  泛型`Func`委托（如`Func<T1, T2, T>`）中最后一个类型参数`T`代表什么？

1.  以`OrDefault`结尾的 LINQ 扩展方法有何好处？

1.  为什么查询理解语法是可选的？

1.  如何创建自己的 LINQ 扩展方法？

## 练习 11.2 – 实践 LINQ 查询

在`Chapter11`解决方案/工作区中，创建一个名为`Exercise02`的控制台应用程序，提示用户输入城市，然后列出该城市中 Northwind 客户的公司名称，如下所示：

```cs
Enter the name of a city: London 
There are 6 customers in London: 
Around the Horn
B's Beverages 
Consolidated Holdings 
Eastern Connection 
North/South
Seven Seas Imports 
```

然后，通过显示所有客户已居住的独特城市列表作为用户输入首选城市前的提示，来增强应用程序，如下所示：

```cs
Aachen, Albuquerque, Anchorage, Århus, Barcelona, Barquisimeto, Bergamo, Berlin, Bern, Boise, Bräcke, Brandenburg, Bruxelles, Buenos Aires, Butte, Campinas, Caracas, Charleroi, Cork, Cowes, Cunewalde, Elgin, Eugene, Frankfurt a.M., Genève, Graz, Helsinki, I. de Margarita, Kirkland, Kobenhavn, Köln, Lander, Leipzig, Lille, Lisboa, London, Luleå, Lyon, Madrid, Mannheim, Marseille, México D.F., Montréal, München, Münster, Nantes, Oulu, Paris, Portland, Reggio Emilia, Reims, Resende, Rio de Janeiro, Salzburg, San Cristóbal, San Francisco, Sao Paulo, Seattle, Sevilla, Stavern, Strasbourg, Stuttgart, Torino, Toulouse, Tsawassen, Vancouver, Versailles, Walla Walla, Warszawa 
```

## 练习 11.3 – 探索主题

使用以下页面上的链接，深入了解本章涉及的主题：

[`github.com/markjprice/cs10dotnet6/blob/main/book-links.md#chapter-11---querying-and-manipulating-data-using-linq`](https://github.com/markjprice/cs10dotnet6/blob/main/book-links.md#chapter-11---querying-and-manipulating-data-using-linq)

# 总结

本章中，你学习了如何编写 LINQ 查询来选择、投影、过滤、排序、连接和分组多种不同格式的数据，包括 XML，这些都是你每天要执行的任务。

下一章中，你将使用`Task`类型来提升应用程序的性能。


# 第十二章：使用多任务处理提高性能和可扩展性

本章旨在通过允许多个操作同时发生，以提高您构建的应用程序的性能、可扩展性和用户生产力。

本章我们将涵盖以下主题：

+   理解进程、线程和任务

+   监控性能和资源使用情况

+   异步运行任务

+   同步访问共享资源

+   理解`async`和`await`

# 理解进程、线程和任务

**进程**，例如我们创建的每个控制台应用程序，都分配有内存和线程等资源。

**线程**执行您的代码，逐条语句执行。默认情况下，每个进程只有一个线程，当我们需要同时执行多个任务时，这可能会导致问题。线程还负责跟踪当前已验证的用户以及应遵循的当前语言和区域的任何国际化规则等事项。

Windows 和大多数其他现代操作系统使用**抢占式多任务处理**，它模拟任务的并行执行。它将处理器时间分配给各个线程，为每个线程分配一个**时间片**，一个接一个。当当前线程的时间片结束时，它会被挂起，处理器随后允许另一个线程运行一个时间片。

当 Windows 从一个线程切换到另一个线程时，它会保存当前线程的上下文，并重新加载线程队列中下一个线程之前保存的上下文。这个过程需要时间和资源来完成。

作为开发者，如果您有少量复杂的工作且希望完全控制它们，那么您可以创建和管理单独的`Thread`实例。如果您有一个主线程和多个可以在后台执行的小任务，那么您可以使用`ThreadPool`类将指向这些作为方法实现的任务的委托实例添加到队列中，它们将自动分配给线程池中的线程。

在本章中，我们将使用`Task`类型以更高的抽象级别管理线程。

线程可能需要竞争和等待访问共享资源，例如变量、文件和数据库对象。本章后面您将看到用于管理这些资源的各种类型。

根据任务的不同，将执行任务的线程（工作者）数量加倍并不一定会将完成任务所需的时间减半。事实上，它可能会增加任务的持续时间。

**最佳实践**：切勿假设增加线程数量会提高性能！在未使用多线程的基准代码实现上运行性能测试，然后在使用了多线程的代码实现上再次运行。您还应在尽可能接近生产环境的预生产环境中进行性能测试。

# 监控性能和资源使用

在我们能够改进任何代码的性能之前，我们需要能够监控其速度和效率，以记录一个基准，然后我们可以据此衡量改进。

## 评估类型的效率

对于某个场景，最佳类型是什么？要回答这个问题，我们需要仔细考虑我们所说的“最佳”是什么意思，并通过这一点，我们应该考虑以下因素：

+   **功能性**：这可以通过检查类型是否提供了你所需的功能来决定。

+   **内存大小**：这可以通过类型占用的内存字节数来决定。

+   **性能**：这可以通过类型的运行速度来决定。

+   **未来需求**：这取决于需求和可维护性的变化。

在存储数字等场景中，将会有多种类型具有相同的功能，因此我们需要考虑内存和性能来做出选择。

如果我们需要存储数百万个数字，那么最佳类型将是占用内存字节数最少的那个。但如果我们只需要存储几个数字，而我们又需要对它们进行大量计算，那么最佳类型将是在特定 CPU 上运行最快的那个。

你已经见过使用`sizeof()`函数的情况，它显示了内存中一个类型实例所占用的字节数。当我们存储大量值在更复杂的数据结构中，如数组和列表时，我们需要一种更好的方法来测量内存使用情况。

你可以在网上和书籍中阅读大量建议，但确定哪种类型最适合你的代码的唯一方法是自己比较这些类型。

在下一节中，你将学习如何编写代码来监控使用不同类型时的实际内存需求和性能。

今天，`short`变量可能是最佳选择，但使用`int`变量可能是更好的选择，尽管它在内存中占用两倍的空间。这是因为我们将来可能需要存储更广泛的值。

开发者经常忽视的一个重要指标是维护性。这是衡量另一个程序员为了理解和修改你的代码需要付出多少努力的指标。如果你做出一个不明显的类型选择，并且没有用有帮助的注释解释这个选择，那么可能会让后来需要修复错误或添加功能的程序员感到困惑。

## 使用诊断监控性能和内存

`System.Diagnostics`命名空间包含许多用于监控代码的有用类型。我们将首先查看的有用类型是`Stopwatch`类型：

1.  使用你偏好的编程工具创建一个名为`Chapter12`的新工作区/解决方案。

1.  添加一个类库项目，如以下列表所定义：

    1.  项目模板：**类库** / `classlib`

    1.  工作区/解决方案文件和文件夹：`Chapter12`

    1.  项目文件和文件夹：`MonitoringLib`

1.  添加一个控制台应用程序项目，如下所列：

    1.  项目模板：**控制台应用程序** / `console`

    1.  工作区/解决方案文件和文件夹：`Chapter12`

    1.  项目文件和文件夹：`MonitoringApp`

1.  在 Visual Studio 中，将解决方案的启动项目设置为当前选择的项目。

1.  在 Visual Studio Code 中，选择`MonitoringApp`作为活动的 OmniSharp 项目。

1.  在`MonitoringLib`项目中，将`Class1.cs`文件重命名为`Recorder.cs`。

1.  在`MonitoringApp`项目中，添加对`MonitoringLib`类库的项目引用，如下所示：

    ```cs
    <ItemGroup> 
      <ProjectReference
        Include="..\MonitoringLib\MonitoringLib.csproj" />
    </ItemGroup> 
    ```

1.  构建`MonitoringApp`项目。

### 有用的 Stopwatch 和 Process 类型成员

`Stopwatch`类型有一些有用的成员，如下表所示：

| 成员 | 描述 |
| --- | --- |
| `Restart` 方法 | 这会将经过时间重置为零，然后启动计时器。 |
| `Stop` 方法 | 这会停止计时器。 |
| `Elapsed` 属性 | 这是以`TimeSpan`格式存储的经过时间（例如，小时:分钟:秒） |
| `ElapsedMilliseconds` 属性 | 这是以毫秒为单位的经过时间，存储为`Int64`值。 |

`Process`类型有一些有用的成员，如下表所示：

| 成员 | 描述 |
| --- | --- |
| `VirtualMemorySize64` | 这显示了为进程分配的虚拟内存量，单位为字节。 |
| `WorkingSet64` | 这显示了为进程分配的物理内存量，单位为字节。 |

### 实现一个 Recorder 类

我们将创建一个`Recorder`类，使监控时间和内存资源使用变得简单。为了实现我们的`Recorder`类，我们将使用`Stopwatch`和`Process`类：

1.  在`Recorder.cs`中，修改其内容以使用`Stopwatch`实例记录时间，并使用当前`Process`实例记录内存使用情况，如下所示：

    ```cs
    using System.Diagnostics; // Stopwatch
    using static System.Console;
    using static System.Diagnostics.Process; // GetCurrentProcess()
    namespace Packt.Shared;
    public static class Recorder
    {
      private static Stopwatch timer = new();
      private static long bytesPhysicalBefore = 0;
      private static long bytesVirtualBefore = 0;
      public static void Start()
      {
        // force two garbage collections to release memory that is
        // no longer referenced but has not been released yet
        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();
        // store the current physical and virtual memory use 
        bytesPhysicalBefore = GetCurrentProcess().WorkingSet64; 
        bytesVirtualBefore = GetCurrentProcess().VirtualMemorySize64; 
        timer.Restart();
      }
      public static void Stop()
      {
        timer.Stop();
        long bytesPhysicalAfter =
          GetCurrentProcess().WorkingSet64;
        long bytesVirtualAfter =
          GetCurrentProcess().VirtualMemorySize64;
        WriteLine("{0:N0} physical bytes used.",
          bytesPhysicalAfter - bytesPhysicalBefore);
        WriteLine("{0:N0} virtual bytes used.",
          bytesVirtualAfter - bytesVirtualBefore);
        WriteLine("{0} time span ellapsed.", timer.Elapsed);
        WriteLine("{0:N0} total milliseconds ellapsed.",
          timer.ElapsedMilliseconds);
      }
    } 
    ```

    `Recorder`类的`Start`方法使用`GC`类型（垃圾收集器）确保在记录已用内存量之前，收集任何当前已分配但未引用的内存。这是一种高级技术，您几乎不应在应用程序代码中使用。

1.  在`Program.cs`中，编写语句以在生成 10,000 个整数的数组时启动和停止`Recorder`，如下所示：

    ```cs
    using Packt.Shared; // Recorder
    using static System.Console;
    WriteLine("Processing. Please wait...");
    Recorder.Start();
    // simulate a process that requires some memory resources...
    int[] largeArrayOfInts = Enumerable.Range(
      start: 1, count: 10_000).ToArray();
    // ...and takes some time to complete
    Thread.Sleep(new Random().Next(5, 10) * 1000);
    Recorder.Stop(); 
    ```

1.  运行代码并查看结果，如下所示：

    ```cs
    Processing. Please wait...
    655,360 physical bytes used.
    536,576 virtual bytes used.
    00:00:09.0038702 time span ellapsed.
    9,003 total milliseconds ellapsed. 
    ```

请记住，时间间隔随机在 5 到 10 秒之间，您的结果可能会有所不同。例如，在我的 Mac mini M1 上运行时，虽然物理内存较少，但虚拟内存使用更多，如下所示：

```cs
Processing. Please wait...
294,912 physical bytes used.
10,485,760 virtual bytes used.
00:00:06.0074221 time span ellapsed.
6,007 total milliseconds ellapsed. 
```

## 测量字符串处理的效率

既然您已经了解了如何使用`Stopwatch`和`Process`类型来监控您的代码，我们将使用它们来评估处理`string`变量的最佳方式。

1.  在`Program.cs`中，通过使用多行注释字符`/* */`将之前的语句注释掉。

1.  编写语句以创建一个包含 50,000 个`int`变量的数组，然后使用`string`和`StringBuilder`类用逗号作为分隔符将它们连接起来，如下所示：

    ```cs
    int[] numbers = Enumerable.Range(
      start: 1, count: 50_000).ToArray();
    WriteLine("Using string with +");
    Recorder.Start();
    string s = string.Empty; // i.e. ""
    for (int i = 0; i < numbers.Length; i++)
    {
      s += numbers[i] + ", ";
    }
    Recorder.Stop();
    WriteLine("Using StringBuilder");
    Recorder.Start();
    System.Text.StringBuilder builder = new();
    for (int i = 0; i < numbers.Length; i++)
    {
      builder.Append(numbers[i]);
      builder.Append(", ");
    }
    Recorder.Stop(); 
    ```

1.  运行代码并查看结果，如下所示：

    ```cs
    Using string with +
    14,883,072 physical bytes used.
    3,609,728 virtual bytes used.
    00:00:01.6220879 time span ellapsed.
    1,622 total milliseconds ellapsed.
    Using StringBuilder
    12,288 physical bytes used.
    0 virtual bytes used.
    00:00:00.0006038 time span ellapsed.
    0 total milliseconds ellapsed. 
    ```

我们可以总结结果如下：

+   `string`类使用`+`运算符大约使用了 14 MB 的物理内存，1.5 MB 的虚拟内存，耗时 1.5 秒。

+   `StringBuilder`类使用了 12 KB 的物理内存，零虚拟内存，耗时不到 1 毫秒。

在这种情况下，`StringBuilder`在连接文本时速度快了 1000 多倍，内存效率提高了约 10000 倍！这是因为`string`连接每次使用时都会创建一个新的`string`，因为`string`值是不可变的，所以它们可以安全地池化以供重用。`StringBuilder`在追加更多字符时创建一个单一缓冲区。

**最佳实践**：避免在循环内部使用`String.Concat`方法或`+`运算符。改用`StringBuilder`。

既然你已经学会了如何使用.NET 内置类型来衡量代码的性能和资源效率，接下来让我们了解一个提供更复杂性能测量的 NuGet 包。

## 使用 Benchmark.NET 监控性能和内存

有一个流行的.NET 基准测试 NuGet 包，微软在其关于性能改进的博客文章中使用，因此对于.NET 开发者来说，了解其工作原理并用于自己的性能测试是很有益的。让我们看看如何使用它来比较`string`连接和`StringBuilder`的性能：

1.  使用您喜欢的代码编辑器，向名为`Benchmarking`的`Chapter12`解决方案/工作区添加一个新的控制台应用程序。

1.  在 Visual Studio Code 中，选择`Benchmarking`作为活动 OmniSharp 项目。

1.  添加对 Benchmark.NET 的包引用，记住您可以查找最新版本并使用它，而不是我使用的版本，如下所示：

    ```cs
    <ItemGroup>
      <PackageReference Include="BenchmarkDotNet" Version="0.13.1" />
    </ItemGroup> 
    ```

1.  构建项目以恢复包。

1.  在`Program.cs`中，删除现有语句，然后导入运行基准测试的命名空间，如下所示：

    ```cs
    using BenchmarkDotNet.Running; 
    ```

1.  添加一个名为`StringBenchmarks.cs`的新类文件。

1.  在`StringBenchmarks.cs`中，添加语句来定义一个包含每个基准测试所需方法的类，在这种情况下，两个方法都使用`string`连接或`StringBuilder`将二十个数字以逗号分隔进行组合，如下所示：

    ```cs
    using BenchmarkDotNet.Attributes; // [Benchmark]
    public class StringBenchmarks
    {
      int[] numbers;
      public StringBenchmarks()
      {
        numbers = Enumerable.Range(
          start: 1, count: 20).ToArray();
      }
      [Benchmark(Baseline = true)]
      public string StringConcatenationTest()
      {
        string s = string.Empty; // e.g. ""
        for (int i = 0; i < numbers.Length; i++)
        {
          s += numbers[i] + ", ";
        }
        return s;
      }
      [Benchmark]
      public string StringBuilderTest()
      {
        System.Text.StringBuilder builder = new();
        for (int i = 0; i < numbers.Length; i++)
        {
          builder.Append(numbers[i]);
          builder.Append(", ");
        }
        return builder.ToString();
      }
    } 
    ```

1.  在`Program.cs`中，添加一个语句来运行基准测试，如下所示：

    ```cs
    BenchmarkRunner.Run<StringBenchmarks>(); 
    ```

1.  在 Visual Studio 2022 中，在工具栏上，将**解决方案配置**设置为**发布**。

1.  在 Visual Studio Code 中，在终端中使用`dotnet run --configuration Release`命令。

1.  运行控制台应用并注意结果，包括一些报告文件等附属物，以及最重要的，一张总结表显示`string`拼接平均耗时 412.990 ns，而`StringBuilder`平均耗时 275.082 ns，如下部分输出及*图 12.1*所示：

    ```cs
    // ***** BenchmarkRunner: Finish  *****
    // * Export *
      BenchmarkDotNet.Artifacts\results\StringBenchmarks-report.csv
      BenchmarkDotNet.Artifacts\results\StringBenchmarks-report-github.md
      BenchmarkDotNet.Artifacts\results\StringBenchmarks-report.html
    // * Detailed results *
    StringBenchmarks.StringConcatenationTest: DefaultJob
    Runtime = .NET 6.0.0 (6.0.21.37719), X64 RyuJIT; GC = Concurrent Workstation
    Mean = 412.990 ns, StdErr = 2.353 ns (0.57%), N = 46, StdDev = 15.957 ns
    Min = 373.636 ns, Q1 = 413.341 ns, Median = 417.665 ns, Q3 = 420.775 ns, Max = 434.504 ns
    IQR = 7.433 ns, LowerFence = 402.191 ns, UpperFence = 431.925 ns
    ConfidenceInterval = [404.708 ns; 421.273 ns] (CI 99.9%), Margin = 8.282 ns (2.01% of Mean)
    Skewness = -1.51, Kurtosis = 4.09, MValue = 2
    -------------------- Histogram --------------------
    [370.520 ns ; 382.211 ns) | @@@@@@
    [382.211 ns ; 394.583 ns) | @
    [394.583 ns ; 411.300 ns) | @@
    [411.300 ns ; 422.990 ns) | @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
    [422.990 ns ; 436.095 ns) | @@@@@
    ---------------------------------------------------
    StringBenchmarks.StringBuilderTest: DefaultJob
    Runtime = .NET 6.0.0 (6.0.21.37719), X64 RyuJIT; GC = Concurrent Workstation
    Mean = 275.082 ns, StdErr = 0.558 ns (0.20%), N = 15, StdDev = 2.163 ns
    Min = 271.059 ns, Q1 = 274.495 ns, Median = 275.403 ns, Q3 = 276.553 ns, Max = 278.030 ns
    IQR = 2.058 ns, LowerFence = 271.409 ns, UpperFence = 279.639 ns
    ConfidenceInterval = [272.770 ns; 277.394 ns] (CI 99.9%), Margin = 2.312 ns (0.84% of Mean)
    Skewness = -0.69, Kurtosis = 2.2, MValue = 2
    -------------------- Histogram --------------------
    [269.908 ns ; 278.682 ns) | @@@@@@@@@@@@@@@
    ---------------------------------------------------
    // * Summary *
    BenchmarkDotNet=v0.13.1, OS=Windows 10.0.19043.1165 (21H1/May2021Update)
    11th Gen Intel Core i7-1165G7 2.80GHz, 1 CPU, 8 logical and 4 physical cores
    .NET SDK=6.0.100
      [Host]     : .NET 6.0.0 (6.0.21.37719), X64 RyuJIT
      DefaultJob : .NET 6.0.0 (6.0.21.37719), X64 RyuJIT
    |                  Method |     Mean |   Error |   StdDev | Ratio | RatioSD |
    |------------------------ |---------:|--------:|---------:|------:|--------:|
    | StringConcatenationTest | 413.0 ns | 8.28 ns | 15.96 ns |  1.00 |    0.00 |
    |       StringBuilderTest | 275.1 ns | 2.31 ns |  2.16 ns |  0.69 |    0.04 |
    // * Hints *
    Outliers
      StringBenchmarks.StringConcatenationTest: Default -> 7 outliers were removed, 14 outliers were detected (376.78 ns..391.88 ns, 440.79 ns..506.41 ns)
      StringBenchmarks.StringBuilderTest: Default       -> 2 outliers were detected (274.68 ns, 274.69 ns)
    // * Legends *
      Mean    : Arithmetic mean of all measurements
      Error   : Half of 99.9% confidence interval
      StdDev  : Standard deviation of all measurements
      Ratio   : Mean of the ratio distribution ([Current]/[Baseline])
      RatioSD : Standard deviation of the ratio distribution ([Current]/[Baseline])
      1 ns    : 1 Nanosecond (0.000000001 sec)
    // ***** BenchmarkRunner: End *****
    // ** Remained 0 benchmark(s) to run **
    Run time: 00:01:13 (73.35 sec), executed benchmarks: 2
    Global total time: 00:01:29 (89.71 sec), executed benchmarks: 2
    // * Artifacts cleanup * 
    ```

    ![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_13_02.png)

    图 12.1：总结表显示 StringBuilder 耗时为字符串拼接的 69%

`Outliers`部分尤为有趣，因为它表明不仅`string`拼接比`StringBuilder`慢，而且其耗时也更不稳定。当然，你的结果可能会有所不同。

你已经见识了两种性能测量方法。现在让我们看看如何异步运行任务以潜在提升性能。

# 异步执行任务

为了理解如何同时运行多个任务（同时进行），我们将创建一个需要执行三个方法的控制台应用程序。

需要执行三种方法：第一种耗时 3 秒，第二种耗时 2 秒，第三种耗时 1 秒。为了模拟这项工作，我们可以使用`Thread`类让当前线程休眠指定毫秒数。

## 同步执行多个操作

在我们让任务同时运行之前，我们将同步运行它们，即一个接一个地执行。

1.  使用你偏好的代码编辑器，在`Chapter12`解决方案/工作区中添加一个名为`WorkingWithTasks`的新控制台应用。

1.  在 Visual Studio Code 中，选择`WorkingWithTasks`作为活动 OmniSharp 项目。

1.  在`Program.cs`中，导入用于操作秒表的命名空间（与线程和任务相关的命名空间已隐式导入），并静态导入`Console`，如下代码所示：

    ```cs
    using System.Diagnostics; // Stopwatch
    using static System.Console; 
    ```

1.  在`Program.cs`底部，创建一个方法输出当前线程信息，如下代码所示：

    ```cs
    static void OutputThreadInfo()
    {
      Thread t = Thread.CurrentThread;
      WriteLine(
        "Thread Id: {0}, Priority: {1}, Background: {2}, Name: {3}",
        t.ManagedThreadId, t.Priority,
        t.IsBackground, t.Name ?? "null");
    } 
    ```

1.  在`Program.cs`底部，添加三个模拟工作的方法，如下代码所示：

    ```cs
    static void MethodA()
    {
      WriteLine("Starting Method A...");
      OutputThreadInfo();
      Thread.Sleep(3000); // simulate three seconds of work
      WriteLine("Finished Method A.");
    }
    static void MethodB()
    {
      WriteLine("Starting Method B...");
      OutputThreadInfo();
      Thread.Sleep(2000); // simulate two seconds of work
      WriteLine("Finished Method B.");
    }
    static void MethodC()
    {
      WriteLine("Starting Method C...");
      OutputThreadInfo();
      Thread.Sleep(1000); // simulate one second of work
      WriteLine("Finished Method C.");
    } 
    ```

1.  在`Program.cs`顶部，添加语句调用输出线程信息的方法，定义并启动秒表，调用三个模拟工作方法，然后输出经过的毫秒数，如下代码所示：

    ```cs
    OutputThreadInfo();
    Stopwatch timer = Stopwatch.StartNew();
    WriteLine("Running methods synchronously on one thread."); 
    MethodA();
    MethodB();
    MethodC();
    WriteLine($"{timer.ElapsedMilliseconds:#,##0}ms elapsed."); 
    ```

1.  运行代码，查看结果，并注意当仅有一个未命名前台线程执行任务时，所需总时间略超过 6 秒，如下输出所示：

    ```cs
    Thread Id: 1, Priority: Normal, Background: False, Name: null
    Running methods synchronously on one thread.
    Starting Method A...
    Thread Id: 1, Priority: Normal, Background: False, Name: null
    Finished Method A.
    Starting Method B...
    Thread Id: 1, Priority: Normal, Background: False, Name: null
    Finished Method B.
    Starting Method C...
    Thread Id: 1, Priority: Normal, Background: False, Name: null
    Finished Method C.
    6,017ms elapsed. 
    ```

## 使用任务异步执行多个操作

`Thread`类自.NET 的首个版本起就已存在，可用于创建新线程并管理它们，但直接使用可能较为棘手。

.NET Framework 4.0 于 2010 年引入了`Task`类，它是对线程的封装，使得创建和管理更为简便。通过管理多个封装在任务中的线程，我们的代码将能够同时执行，即异步执行。

每个`Task`都有一个`Status`属性和一个`CreationOptions`属性。`Task`有一个`ContinueWith`方法，可以通过`TaskContinuationOptions`枚举进行定制，并可以使用`TaskFactory`类进行管理。

### 启动任务

我们将探讨三种使用`Task`实例启动方法的方式。GitHub 仓库中的链接指向了讨论这些方法优缺点的文章。每种方法的语法略有不同，但它们都定义了一个`Task`并启动它：

1.  注释掉对三个方法及其相关控制台消息的调用，并添加语句以创建和启动三个任务，每个方法一个，如下所示：

    ```cs
    OutputThreadInfo();
    Stopwatch timer = Stopwatch.StartNew();
    **/***
    WriteLine("Running methods synchronously on one thread.");
    MethodA();
    MethodB();
    MethodC();
    ***/**
    **WriteLine(****"Running methods asynchronously on multiple threads."****);** 
    **Task taskA =** **new****(MethodA);**
    **taskA.Start();**
    **Task taskB = Task.Factory.StartNew(MethodB);** 
    **Task taskC = Task.Run(MethodC);**
    WriteLine($"{timer.ElapsedMilliseconds:#,##0}ms elapsed."); 
    ```

1.  运行代码，查看结果，并注意耗时毫秒数几乎立即出现。这是因为三个方法现在正由线程池分配的三个新后台工作线程执行，如下所示：

    ```cs
    Thread Id: 1, Priority: Normal, Background: False, Name: null
    Running methods asynchronously on multiple threads.
    Starting Method A...
    Thread Id: 4, Priority: Normal, Background: True, Name: .NET ThreadPool Worker
    Starting Method C...
    Thread Id: 7, Priority: Normal, Background: True, Name: .NET ThreadPool Worker
    Starting Method B...
    Thread Id: 6, Priority: Normal, Background: True, Name: .NET ThreadPool Worker
    6ms elapsed. 
    ```

甚至有可能控制台应用在任务有机会启动并写入控制台之前就结束了！

## 等待任务

有时，你需要等待一个任务完成后再继续。为此，你可以使用`Task`实例上的`Wait`方法，或者使用`Task`数组上的`WaitAll`或`WaitAny`静态方法，如下表所述：

| 方法 | 描述 |
| --- | --- |
| `t.Wait()` | 这会等待名为`t`的任务实例完成执行。 |
| `Task.WaitAny(Task[])` | 这会等待数组中的任意任务完成执行。 |
| `Task.WaitAll(Task[])` | 这会等待数组中的所有任务完成执行。 |

### 使用任务的等待方法

让我们看看如何使用这些等待方法来解决我们控制台应用的问题。

1.  在`Program.cs`中，在创建三个任务和输出耗时之间添加语句，将三个任务的引用合并到一个数组中，并将其传递给`WaitAll`方法，如下所示：

    ```cs
    Task[] tasks = { taskA, taskB, taskC };
    Task.WaitAll(tasks); 
    ```

1.  运行代码并查看结果，注意原始线程将在调用`WaitAll`时暂停，等待所有三个任务完成后再输出耗时，耗时略超过 3 秒，如下所示：

    ```cs
    Id: 1, Priority: Normal, Background: False, Name: null
    Running methods asynchronously on multiple threads.
    Starting Method A...
    Id: 6, Priority: Normal, Background: True, Name: .NET ThreadPool Worker
    Starting Method B...
    Id: 7, Priority: Normal, Background: True, Name: .NET ThreadPool Worker
    Starting Method C...
    Id: 4, Priority: Normal, Background: True, Name: .NET ThreadPool Worker
    Finished Method C.
    Finished Method B.
    Finished Method A.
    3,013ms elapsed. 
    ```

三个新线程同时执行其代码，并且它们可能以任意顺序启动。`MethodC`应该最先完成，因为它仅需 1 秒，接着是耗时 2 秒的`MethodB`，最后是耗时 3 秒的`MethodA`。

然而，实际的 CPU 使用对结果有很大影响。是 CPU 为每个进程分配时间片以允许它们执行其线程。你无法控制方法何时运行。

## 继续执行另一个任务

如果所有三个任务都能同时执行，那么等待所有任务完成就是我们所需做的全部。然而，通常一个任务依赖于另一个任务的输出。为了处理这种情况，我们需要定义**延续任务**。

我们将创建一些方法来模拟对返回货币金额的网络服务的调用，然后需要使用该金额来检索数据库中有多少产品成本超过该金额。从第一个方法返回的结果需要输入到第二个方法的输入中。这次，我们将使用`Random`类而不是等待固定时间，为每次方法调用等待 2 到 4 秒之间的随机间隔来模拟工作。

1.  在`Program.cs`底部，添加两个方法来模拟调用网络服务和数据库存储过程，如下面的代码所示：

    ```cs
    static decimal CallWebService()
    {
      WriteLine("Starting call to web service...");
      OutputThreadInfo();
      Thread.Sleep((new Random()).Next(2000, 4000));
      WriteLine("Finished call to web service.");
      return 89.99M;
    }
    static string CallStoredProcedure(decimal amount)
    {
      WriteLine("Starting call to stored procedure...");
      OutputThreadInfo();
      Thread.Sleep((new Random()).Next(2000, 4000));
      WriteLine("Finished call to stored procedure.");
      return $"12 products cost more than {amount:C}.";
    } 
    ```

1.  通过将它们包裹在多行注释字符`/* */`中来注释掉对前三个任务的调用。保留输出经过的毫秒数的语句。

1.  在现有语句之前添加语句以输出总时间，如下面的代码所示：

    ```cs
    WriteLine("Passing the result of one task as an input into another."); 
    Task<string> taskServiceThenSProc = Task.Factory
      .StartNew(CallWebService) // returns Task<decimal>
      .ContinueWith(previousTask => // returns Task<string>
        CallStoredProcedure(previousTask.Result));
    WriteLine($"Result: {taskServiceThenSProc.Result}"); 
    ```

1.  运行代码并查看结果，如下面的输出所示：

    ```cs
    Thread Id: 1, Priority: Normal, Background: False, Name: null
    Passing the result of one task as an input into another.
    Starting call to web service...
    Thread Id: 4, Priority: Normal, Background: True, Name: .NET ThreadPool Worker
    Finished call to web service.
    Starting call to stored procedure...
    Thread Id: 6, Priority: Normal, Background: True, Name: .NET ThreadPool Worker
    Finished call to stored procedure.
    Result: 12 products cost more than £89.99.
    5,463ms elapsed. 
    ```

您可能会看到不同的线程运行网络服务和存储过程调用，如上面的输出所示（线程 4 和 6），或者同一线程可能会被重用，因为它不再忙碌。

## 嵌套和子任务

除了定义任务之间的依赖关系外，您还可以定义嵌套和子任务。**嵌套任务**是在另一个任务内部创建的任务。**子任务**是必须在其父任务允许完成之前完成的嵌套任务。

让我们探索这些类型的任务是如何工作的：

1.  使用您喜欢的代码编辑器，在`Chapter12`解决方案/工作区中添加一个名为`NestedAndChildTasks`的新控制台应用程序。

1.  在 Visual Studio Code 中，选择`NestedAndChildTasks`作为活动 OmniSharp 项目。

1.  在`Program.cs`中，删除现有语句，静态导入`Console`，然后添加两个方法，其中一个方法启动一个任务来运行另一个方法，如下面的代码所示：

    ```cs
    static void OuterMethod()
    {
      WriteLine("Outer method starting...");
      Task innerTask = Task.Factory.StartNew(InnerMethod);
      WriteLine("Outer method finished.");
    }
    static void InnerMethod()
    {
      WriteLine("Inner method starting...");
      Thread.Sleep(2000);
      WriteLine("Inner method finished.");
    } 
    ```

1.  在方法上方，添加语句以启动一个任务来运行外部方法并在停止前等待其完成，如下面的代码所示：

    ```cs
    Task outerTask = Task.Factory.StartNew(OuterMethod);
    outerTask.Wait();
    WriteLine("Console app is stopping."); 
    ```

1.  运行代码并查看结果，如下面的输出所示：

    ```cs
    Outer method starting...
    Inner method starting...
    Outer method finished.
    Console app is stopping. 
    ```

    请注意，尽管我们等待外部任务完成，但其内部任务不必同时完成。事实上，外部任务可能完成，控制台应用程序可能结束，甚至在内部任务开始之前！

    要将这些嵌套任务链接为父任务和子任务，我们必须使用一个特殊选项。

1.  修改定义内部任务的现有代码，添加一个`TaskCreationOption`值为`AttachedToParent`，如下面的代码中突出显示所示：

    ```cs
    Task innerTask = Task.Factory.StartNew(InnerMethod,
      **TaskCreationOptions.AttachedToParent**); 
    ```

1.  运行代码，查看结果，并注意内部任务必须在完成外部任务之前完成，如下面的输出所示：

    ```cs
    Outer method starting...
    Inner method starting...
    Outer method finished.
    Inner method finished.
    Console app is stopping. 
    ```

尽管`OuterMethod`可以在`InnerMethod`之前完成，如其在控制台上的输出所示，但其任务必须等待，如控制台在内外任务都完成之前不会停止所示。

## 围绕其他对象包装任务

有时你可能有一个想要异步的方法，但返回的结果本身不是一个任务。你可以将返回值包装在一个成功完成的任务中，返回一个异常，或者通过使用下表中所示的方法来表示任务已被取消：

| 方法 | 描述 |
| --- | --- |
| `FromResult<TResult>(TResult)` | 创建一个`Task<TResult>`对象，其`Result`属性是非任务结果，其`Status`属性是`RanToCompletion`。 |
| `FromException<TResult>(Exception)` | 创建一个因指定异常而完成的`Task<TResult>`。 |
| `FromCanceled<TResult>(CancellationToken)` | 创建一个因指定取消令牌而完成的`Task<TResult>`。 |

这些方法在你需要时很有用：

+   实现具有异步方法的接口，但你的实现是同步的。这在网站和服务中很常见。

+   在单元测试期间模拟异步实现。

在《第七章：打包和分发.NET 类型》中，我们创建了一个类库，用于检查有效的 XML、密码和十六进制代码。

如果我们想让那些方法符合要求返回`Task<T>`的接口，我们可以使用这些有用的方法，如下面的代码所示：

```cs
using System.Text.RegularExpressions;
namespace Packt.Shared;
public static class StringExtensions
{
  public static Task<bool> IsValidXmlTagAsync(this string input)
  {
    if (input == null)
    {
      return Task.FromException<bool>(
        new ArgumentNullException("Missing input parameter"));
    }
    if (input.Length == 0)
    {
      return Task.FromException<bool>(
        new ArgumentException("input parameter is empty."));
    }
    return Task.FromResult(Regex.IsMatch(input,
      @"^<([a-z]+)([^<]+)*(?:>(.*)<\/\1>|\s+\/>)$"));
  }
  // other methods
} 
```

如果你需要实现的方法返回一个`Task`（相当于同步方法中的`void`），那么你可以返回一个预定义的已完成`Task`对象，如下面的代码所示：

```cs
public Task DeleteCustomerAsync()
{
  // ...
  return Task.CompletedTask;
} 
```

# 同步访问共享资源

当多个线程同时执行时，有可能两个或更多线程会同时访问同一变量或其他资源，从而可能导致问题。因此，你应该仔细考虑如何使你的代码**线程安全**。

实现线程安全最简单的机制是使用对象变量作为标志或交通灯，以指示何时对共享资源应用了独占锁。

在威廉·戈尔丁的《*蝇王*》中，皮吉和拉尔夫发现了一个海螺壳，并用它召集会议。男孩们自行制定了“海螺规则”，决定只有持有海螺的人才能发言。

我喜欢将用于实现线程安全代码的对象变量命名为“海螺”。当一个线程持有海螺时，其他任何线程都不应访问由该海螺表示的共享资源。请注意，我说的是“不应”。只有尊重海螺的代码才能实现同步访问。海螺不是锁。

我们将探讨几种可用于同步访问共享资源的类型：

+   `Monitor`：一个可被多个线程用来检查是否应在同一进程内访问共享资源的对象。

+   `Interlocked`：一个用于在 CPU 级别操作简单数值类型的对象。

## 多线程访问资源

1.  使用你偏好的代码编辑器，在`Chapter12`解决方案/工作区中添加一个名为`SynchronizingResourceAccess`的新控制台应用。

1.  在 Visual Studio Code 中，选择`SynchronizingResourceAccess`作为活动 OmniSharp 项目。

1.  在`Program.cs`中，删除现有语句，然后添加执行以下操作的语句：

    +   导入诊断类型（如`Stopwatch`）的命名空间。

    +   静态导入`Console`类型。

    +   在`Program.cs`底部，创建一个具有两个字段的静态类：

        +   生成随机等待时间的字段。

        +   一个`string`字段用于存储消息（这是一个共享资源）。

    +   在类上方，创建两个静态方法，它们在循环中五次向共享`string`添加字母 A 或 B，并为每次迭代等待最多 2 秒的随机间隔：

    ```cs
    static void MethodA()
    {
      for (int i = 0; i < 5; i++)
      {
        Thread.Sleep(SharedObjects.Random.Next(2000));
        SharedObjects.Message += "A";
        Write(".");
      }
    }
    static void MethodB()
    {
      for (int i = 0; i < 5; i++)
      {
        Thread.Sleep(SharedObjects.Random.Next(2000));
        SharedObjects.Message += "B";
        Write(".");
      }
    }
    static class SharedObjects
    {
      public static Random Random = new();
      public static string? Message; // a shared resource
    } 
    ```

1.  在命名空间导入之后，编写语句以使用一对任务在单独的线程上执行两个方法，并在输出经过的毫秒数之前等待它们完成，如下面的代码所示：

    ```cs
    WriteLine("Please wait for the tasks to complete.");
    Stopwatch watch = Stopwatch.StartNew();
    Task a = Task.Factory.StartNew(MethodA);
    Task b = Task.Factory.StartNew(MethodB);

    Task.WaitAll(new Task[] { a, b });
    WriteLine();
    WriteLine($"Results: {SharedObjects.Message}.");
    WriteLine($"{watch.ElapsedMilliseconds:N0} elapsed milliseconds."); 
    ```

1.  运行代码并查看结果，如下面的输出所示：

    ```cs
    Please wait for the tasks to complete.
    ..........
    Results: BABABAABBA.
    5,753 elapsed milliseconds. 
    ```

这表明两个线程都在并发地修改消息。在实际应用中，这可能是个问题。但我们可以通过对海螺对象应用互斥锁，并让两个方法在修改共享资源前自愿检查海螺，来防止并发访问，我们将在下一节中这样做。

## 对海螺应用互斥锁

现在，让我们使用海螺确保一次只有一个线程访问共享资源。

1.  在`SharedObjects`中，声明并实例化一个`object`变量作为海螺，如下面的代码所示：

    ```cs
    public static object Conch = new(); 
    ```

1.  在`MethodA`和`MethodB`中，在`for`循环周围添加一个`lock`语句，以锁定海螺，如下面的高亮代码所示：

    ```cs
    **lock** **(SharedObjects.Conch)**
    **{**
      for (int i = 0; i < 5; i++)
      {
        Thread.Sleep(SharedObjects.Random.Next(2000));
        SharedObjects.Message += "A";
        Write(".");
      }
    **}** 
    ```

    **最佳实践**：请注意，由于检查海螺是自愿的，如果你只在两个方法中的一个使用`lock`语句，共享资源将继续被两个方法访问。确保所有访问共享资源的方法都尊重海螺。

1.  运行代码并查看结果，如下面的输出所示：

    ```cs
    Please wait for the tasks to complete.
    ..........
    Results: BBBBBAAAAA.
    10,345 elapsed milliseconds. 
    ```

尽管耗时更长，但一次只能有一个方法访问共享资源。`MethodA`或`MethodB`可以先开始。一旦某个方法完成了对共享资源的操作，海螺就会被释放，另一个方法就有机会执行其任务。

### 理解锁语句

你可能会好奇`lock`语句在“锁定”对象变量时做了什么（提示：它并没有锁定对象！），如下面的代码所示：

```cs
lock (SharedObjects.Conch)
{
  // work with shared resource
} 
```

C#编译器将`lock`语句转换为使用`Monitor`类*进入*和*退出*海螺对象的`try`-`finally`语句（我喜欢将其视为*获取*和*释放*海螺对象），如下面的代码所示：

```cs
try
{
  Monitor.Enter(SharedObjects.Conch);
  // work with shared resource
}
finally
{
  Monitor.Exit(SharedObjects.Conch);
} 
```

当线程对任何对象（即引用类型）调用`Monitor.Enter`时，它会检查是否有其他线程已经获取了海螺。如果已经获取，线程等待。如果没有，线程获取海螺并继续处理共享资源。一旦线程完成其工作，它调用`Monitor.Exit`，释放海螺。如果另一个线程正在等待，现在它可以获取海螺并执行其工作。这要求所有线程通过适当调用`Monitor.Enter`和`Monitor.Exit`来尊重海螺。

### 避免死锁

了解`lock`语句如何被编译器转换为`Monitor`类上的方法调用也很重要，因为使用`lock`语句可能导致死锁。

当存在两个或多个共享资源（每个资源都有一个海螺来监控当前哪个线程正在处理该共享资源）时，可能会发生死锁，如果以下事件序列发生：

+   线程 X“锁定”海螺 A 并开始处理共享资源 A。

+   线程 Y“锁定”海螺 B 并开始处理共享资源 B。

+   线程 X 在仍在处理资源 A 的同时，也需要与资源 B 合作，因此它试图“锁定”海螺 B，但由于线程 Y 已经拥有海螺 B 而被阻塞。

+   线程 Y 在仍在处理资源 B 的同时，也需要与资源 A 合作，因此它试图“锁定”海螺 A，但由于线程 X 已经拥有海螺 A 而被阻塞。

防止死锁的一种方法是在尝试获取锁时指定超时。为此，你必须手动使用`Monitor`类而不是使用`lock`语句。

1.  修改你的代码，将`lock`语句替换为尝试在超时后进入海螺的代码，并输出错误，然后退出监视器，允许其他线程进入监视器，如下所示高亮显示的代码：

    ```cs
    **try**
    **{**
    **if** **(Monitor.TryEnter(SharedObjects.Conch, TimeSpan.FromSeconds(****15****)))**
      {
        for (int i = 0; i < 5; i++)
        {
          Thread.Sleep(SharedObjects.Random.Next(2000));
          SharedObjects.Message += "A";
          Write(".");
        }
      }
    **else**
     **{**
     **WriteLine(****"Method A timed out when entering a monitor on conch."****);**
     **}**
    **}**
    **finally**
    **{**
     **Monitor.Exit(SharedObjects.Conch);**
    **}** 
    ```

1.  运行代码并查看结果，结果应与之前相同（尽管 A 或 B 可能首先抓住海螺），但这是更好的代码，因为它将防止潜在的死锁。

**最佳实践**：仅在你能编写避免潜在死锁的代码时使用`lock`关键字。如果你无法避免潜在死锁，则始终使用`Monitor.TryEnter`方法代替`lock`，并结合`try`-`finally`语句，以便你可以提供超时，如果发生死锁，其中一个线程将退出。你可以在以下链接阅读更多关于良好线程实践的内容：[`docs.microsoft.com/en-us/dotnet/standard/threading/managed-threading-best-practices`](https://docs.microsoft.com/en-us/dotnet/standard/threading/managed-threading-best-practices)

## 同步事件

在*第六章*，*实现接口和继承类*中，你学习了如何引发和处理事件。但.NET 事件不是线程安全的，因此你应该避免在多线程场景中使用它们，并遵循我之前展示的标准事件引发代码。

在了解到.NET 事件不是线程安全的之后，一些开发者尝试在添加和移除事件处理程序或触发事件时使用独占锁，如下面的代码所示：

```cs
// event delegate field
public event EventHandler Shout;
// conch
private object eventLock = new();
// method
public void Poke()
{
  lock (eventLock) // bad idea
  {
    // if something is listening...
    if (Shout != null)
    {
      // ...then call the delegate to raise the event
      Shout(this, EventArgs.Empty);
    }
  }
} 
```

**最佳实践**：您可以在以下链接中了解更多关于事件和线程安全的信息：[`docs.microsoft.com/en-us/archive/blogs/cburrows/field-like-events-considered-harmful`](https://docs.microsoft.com/en-us/archive/blogs/cburrows/field-like-events-considered-harmful)

但这很复杂，正如 Stephen Cleary 在以下博客文章中所解释的：[`blog.stephencleary.com/2009/06/threadsafe-events.html`](https://blog.stephencleary.com/2009/06/threadsafe-events.html)

## 使 CPU 操作原子化

原子一词来自希腊语**atomos**，意为*不可分割*。理解多线程中哪些操作是原子的很重要，因为如果它们不是原子的，那么它们可能会在操作中途被另一个线程中断。C#的增量运算符是原子的吗，如下面的代码所示？

```cs
int x = 3;
x++; // is this an atomic CPU operation? 
```

它不是原子的！递增一个整数需要以下三个 CPU 操作：

1.  从实例变量加载一个值到寄存器。

1.  递增该值。

1.  将值存储在实例变量中。

一个线程在执行前两步后可能会被中断。第二个线程随后可以执行所有三个步骤。当第一个线程恢复执行时，它将覆盖变量中的值，第二个线程执行的增减操作的效果将会丢失！

有一个名为`Interlocked`的类型，可以对值类型（如整数和浮点数）执行原子操作。让我们看看它的实际应用：

1.  在`SharedObjects`类中声明另一个字段，用于计数已发生的操作次数，如下面的代码所示：

    ```cs
    public static int Counter; // another shared resource 
    ```

1.  在方法 A 和 B 中，在`for`语句内并在修改`string`值后，添加一个语句以安全地递增计数器，如下面的代码所示：

    ```cs
    Interlocked.Increment(ref SharedObjects.Counter); 
    ```

1.  输出经过的时间后，将计数器的当前值写入控制台，如下面的代码所示：

    ```cs
    WriteLine($"{SharedObjects.Counter} string modifications."); 
    ```

1.  运行代码并查看结果，如下面的输出所示：

    ```cs
    Please wait for the tasks to complete.
    ..........
    Results: BBBBBAAAAA.
    13,531 elapsed milliseconds.
    **10 string modifications.** 
    ```

细心的读者会意识到，现有的海螺对象保护了锁定代码块内访问的所有共享资源，因此在这个特定的例子中实际上不需要使用`Interlocked`。但如果我们没有保护另一个像`Message`这样的共享资源，那么使用`Interlocked`将是必要的。

## 应用其他类型的同步

`Monitor`和`Interlocked`是互斥锁，它们简单有效，但有时，您需要更高级的选项来同步对共享资源的访问，如下表所示：

| 类型 | 描述 |
| --- | --- |
| `ReaderWriterLock`和`ReaderWriterLockSlim` | 这些允许多个线程处于**读模式**，一个线程处于**写模式**，拥有写锁的独占所有权，以及一个线程，该线程具有对资源的读访问权限，并处于**可升级读模式**，从中线程可以升级到写模式，而无需放弃其对资源的读访问权限。 |
| `Mutex` | 类似于`Monitor`，它为共享资源提供独占访问，但用于进程间同步。 |
| `Semaphore`和`SemaphoreSlim` | 这些通过定义槽限制可以同时访问资源或资源池的线程数量。这被称为资源节流，而不是资源锁定。 |
| `AutoResetEvent`和`ManualResetEvent` | 事件等待句柄允许线程通过相互发送信号和等待彼此的信号来同步活动。 |

# 理解异步和等待

C# 5 在处理`Task`类型时引入了两个 C#关键字。它们特别适用于以下情况：

+   为**图形用户界面**(**GUI**)实现多任务处理。

+   提升 Web 应用和 Web 服务的可扩展性。

在*第十五章*，*使用模型-视图-控制器模式构建网站*中，我们将看到`async`和`await`关键字如何提升网站的可扩展性。

在*第十九章*，*使用.NET MAUI 构建移动和桌面应用*中，我们将看到`async`和`await`关键字如何实现 GUI 的多任务处理。

但现在，让我们先学习这两个 C#关键字被引入的理论原因，之后您将看到它们在实践中的应用。

## 提高控制台应用的响应性

控制台应用程序的一个限制是，您只能在标记为`async`的方法中使用`await`关键字，但 C# 7 及更早版本不允许将`Main`方法标记为异步！幸运的是，C# 7.1 引入了一个新特性，即支持`Main`中的`async`：

1.  使用您偏好的代码编辑器，向`Chapter12`解决方案/工作区中添加一个名为`AsyncConsole`的新控制台应用。

1.  在 Visual Studio Code 中，选择`AsyncConsole`作为活动的 OmniSharp 项目。

1.  在`Program.cs`中，删除现有语句并静态导入`Console`，如下所示：

    ```cs
    using static System.Console; 
    ```

1.  添加语句以创建`HttpClient`实例，请求 Apple 主页，并输出其字节数，如下所示：

    ```cs
    HttpClient client = new();
    HttpResponseMessage response =
      await client.GetAsync("http://www.apple.com/");
    WriteLine("Apple's home page has {0:N0} bytes.",
      response.Content.Headers.ContentLength); 
    ```

1.  构建项目并注意它成功构建。在.NET 5 及更早版本中，您会看到一条错误消息，如下所示：

    ```cs
    Program.cs(14,9): error CS4033: The 'await' operator can only be used within an async method. Consider marking this method with the 'async' modifier and changing its return type to 'Task'. [/Users/markjprice/Code/ Chapter12/AsyncConsole/AsyncConsole.csproj] 
    ```

1.  您本需要向`Main`方法添加`async`关键字并将其返回类型更改为`Task`。使用.NET 6 及更高版本，控制台应用项目模板利用顶级程序功能自动为您定义具有异步`Main`方法的`Program`类。

1.  运行代码并查看结果，由于苹果经常更改其主页，因此结果可能会有不同的字节数，如下面的输出所示：

    ```cs
    Apple's home page has 40,252 bytes. 
    ```

## 提高 GUI 应用程序的响应性

到目前为止，本书中我们只构建了控制台应用程序。当构建 Web 应用程序、Web 服务以及带有 GUI 的应用程序（如 Windows 桌面和移动应用程序）时，程序员的生活会变得更加复杂。

原因之一是，对于图形用户界面（GUI）应用程序，存在一个特殊的线程：**用户界面**（**UI**）线程。

在 GUI 中工作的两条规则：

+   不要在 UI 线程上执行长时间运行的任务。

+   不要在除 UI 线程以外的任何线程上访问 UI 元素。

为了处理这些规则，程序员过去不得不编写复杂的代码来确保长时间运行的任务由非 UI 线程执行，但一旦完成，任务的结果会安全地传递给 UI 线程以呈现给用户。这很快就会变得混乱！

幸运的是，使用 C# 5 及更高版本，你可以使用`async`和`await`。它们允许你继续以同步方式编写代码，这使得代码保持清晰易懂，但在底层，C#编译器创建了一个复杂的**状态机**并跟踪运行线程。这有点神奇！

让我们看一个例子。我们将使用 WPF 构建一个 Windows 桌面应用程序，该应用程序从 SQL Server 数据库中的 Northwind 数据库获取员工信息，使用低级类型如`SqlConnection`、`SqlCommand`和`SqlDataReader`。只有当你拥有 Windows 和存储在 SQL Server 中的 Northwind 数据库时，你才能完成此任务。这是本书中唯一不跨平台且现代的部分（WPF 已有 16 年历史！）。

此时，我们专注于使 GUI 应用程序具有响应性。你将在*第十九章*，*使用.NET MAUI 构建移动和桌面应用程序*中学习 XAML 和构建跨平台 GUI 应用程序。由于本书其他部分不涉及 WPF，我认为这是一个很好的机会，至少可以看到一个使用 WPF 构建的示例应用程序，即使我们不详细讨论它。

我们开始吧！

1.  如果你使用的是 Windows 上的 Visual Studio 2022，请向`Chapter12`解决方案中添加一个名为`WpfResponsive`的**WPF 应用程序[C#]**项目。如果你使用的是 Visual Studio Code，请使用以下命令：`dotnet new wpf`。

1.  在项目文件中，注意输出类型是 Windows EXE，目标框架是面向 Windows 的.NET 6（它不会在其他平台如 macOS 和 Linux 上运行），并且项目使用了 WPF。

1.  向项目中添加对`Microsoft.Data.SqlClient`的包引用，如下面的标记中突出显示的那样：

    ```cs
    <Project Sdk="Microsoft.NET.Sdk">
      <PropertyGroup>
        <OutputType>WinExe</OutputType>
        <TargetFramework>net6.0-windows</TargetFramework>
        <Nullable>enable</Nullable>
        <UseWPF>true</UseWPF>
      </PropertyGroup>
     **<ItemGroup>**
     **<PackageReference Include=****"Microsoft.Data.SqlClient"** **Version=****"3.0.0"** **/>**
     **</ItemGroup>**
    </Project> 
    ```

1.  构建项目以恢复包。

1.  在`MainWindow.xaml`中，在`<Grid>`元素内，添加元素以定义两个按钮、一个文本框和一个列表框，它们在堆栈面板中垂直布局，如下面的标记中突出显示的那样：

    ```cs
    <Grid>
    **<****StackPanel****>**
    **<****Button****Name****=****"GetEmployeesSyncButton"**
    **Click****=****"GetEmployeesSyncButton_Click"****>**
     **Get Employees Synchronously****</****Button****>**
    **<****Button****Name****=****"GetEmployeesAsyncButton"**
    **Click****=****"GetEmployeesAsyncButton_Click"****>**
     **Get Employees Asynchronously****</****Button****>**
    **<****TextBox****HorizontalAlignment****=****"Stretch"****Text****=****"Type in here"** **/>**
    **<****ListBox****Name****=****"EmployeesListBox"****Height****=****"400"** **/>**
    **</****StackPanel****>**
    </Grid> 
    ```

    Windows 上的 Visual Studio 2022 对构建 WPF 应用提供了良好的支持，并在编辑代码和 XAML 标记时提供 IntelliSense。Visual Studio Code 则不支持。

1.  在`MainWindow.xaml.cs`中，在`MainWindow`类中，导入`System.Diagnostics`和`Microsoft.Data.SqlClient`命名空间，然后创建两个`string`常量用于数据库连接字符串和 SQL 语句，并为两个按钮的点击创建事件处理程序，使用这些`string`常量打开与 Northwind 数据库的连接，并在列表框中填充所有员工的 ID 和姓名，如下所示：

    ```cs
    private const string connectionString = 
      "Data Source=.;" +
      "Initial Catalog=Northwind;" +
      "Integrated Security=true;" +
      "MultipleActiveResultSets=true;";
    private const string sql =
      "WAITFOR DELAY '00:00:05';" +
      "SELECT EmployeeId, FirstName, LastName FROM Employees";
    private void GetEmployeesSyncButton_Click(object sender, RoutedEventArgs e)
    {
      Stopwatch timer = Stopwatch.StartNew();
      using (SqlConnection connection = new(connectionString))
      {
        connection.Open();
        SqlCommand command = new(sql, connection);
        SqlDataReader reader = command.ExecuteReader();
        while (reader.Read())
        {
          string employee = string.Format("{0}: {1} {2}",
            reader.GetInt32(0), reader.GetString(1), reader.GetString(2));
          EmployeesListBox.Items.Add(employee);
        }
        reader.Close();
        connection.Close();
      }
      EmployeesListBox.Items.Add($"Sync: {timer.ElapsedMilliseconds:N0}ms");
    }
    private async void GetEmployeesAsyncButton_Click(
      object sender, RoutedEventArgs e)
    {
      Stopwatch timer = Stopwatch.StartNew();
      using (SqlConnection connection = new(connectionString))
      {
        await connection.OpenAsync();
        SqlCommand command = new(sql, connection);
        SqlDataReader reader = await command.ExecuteReaderAsync();
        while (await reader.ReadAsync())
        {
          string employee = string.Format("{0}: {1} {2}",
            await reader.GetFieldValueAsync<int>(0), 
            await reader.GetFieldValueAsync<string>(1), 
            await reader.GetFieldValueAsync<string>(2));
          EmployeesListBox.Items.Add(employee);
        }
        await reader.CloseAsync();
        await connection.CloseAsync();
      }
      EmployeesListBox.Items.Add($"Async: {timer.ElapsedMilliseconds:N0}ms");
    } 
    ```

    注意以下内容：

    +   SQL 语句使用 SQL Server 命令`WAITFOR DELAY`模拟耗时五秒的处理过程，然后从`Employees`表中选择三个列。

    +   `GetEmployeesSyncButton_Click`事件处理程序使用同步方法打开连接并获取员工行。

    +   `GetEmployeesAsyncButton_Click`事件处理程序标记为`async`，并使用带有`await`关键字的异步方法打开连接并获取员工行。

    +   两个事件处理程序均使用秒表记录操作耗费的毫秒数，并将其添加到列表框中。

1.  启动 WPF 应用，无需调试。

1.  点击文本框，输入一些文本，注意 GUI 响应。

1.  点击**同步获取员工**按钮。

1.  尝试点击文本框，注意 GUI 无响应。

1.  等待至少五秒钟，直到列表框中填满员工信息。

1.  点击文本框，输入一些文本，注意 GUI 再次响应。

1.  点击**异步获取员工**按钮。

1.  点击文本框，输入一些文本，注意在执行操作时 GUI 仍然响应。继续输入，直到列表框中填满员工信息。

1.  注意两次操作的时间差异。同步获取数据时 UI 被阻塞，而异步获取数据时 UI 保持响应。

1.  关闭 WPF 应用。

## 提升 Web 应用和 Web 服务的可扩展性。

`async`和`await`关键字在构建网站、应用程序和服务时也可应用于服务器端。从客户端应用程序的角度来看，没有任何变化（或者他们甚至可能注意到请求返回所需时间略有增加）。因此，从单个客户端的角度来看，使用`async`和`await`在服务器端实现多任务处理会使他们的体验变差！

在服务器端，创建额外的、成本较低的工作线程来等待长时间运行的任务完成，以便昂贵的 I/O 线程可以处理其他客户端请求，而不是被阻塞。这提高了 Web 应用或服务的整体可扩展性。可以同时支持更多客户端。

## 支持多任务处理的常见类型

许多常见类型都具有异步方法，你可以等待这些方法，如下表所示：

| 类型 | 方法 |
| --- | --- |
| `DbContext<T>` | `AddAsync`, `AddRangeAsync`, `FindAsync`, 和 `SaveChangesAsync` |
| `DbSet<T>` | `AddAsync`, `AddRangeAsync`, `ForEachAsync`, `SumAsync`, `ToListAsync`, `ToDictionaryAsync`, `AverageAsync`, 和 `CountAsync` |
| `HttpClient` | `GetAsync`, `PostAsync`, `PutAsync`, `DeleteAsync`, 和 `SendAsync` |
| `StreamReader` | `ReadAsync`, `ReadLineAsync`, 和 `ReadToEndAsync` |
| `StreamWriter` | `WriteAsync`, `WriteLineAsync`, 和 `FlushAsync` |

**良好实践**：每当看到以`Async`为后缀的方法时，检查它是否返回`Task`或`Task<T>`。如果是，那么你可以使用它代替同步的非`Async`后缀方法。记得使用`await`调用它，并为你的方法添加`async`修饰符。

## 在 catch 块中使用 await

在 C# 5 中首次引入`async`和`await`时，只能在`try`块中使用`await`关键字，而不能在`catch`块中使用。在 C# 6 及更高版本中，现在可以在`try`和`catch`块中都使用`await`。

## 处理异步流

随着.NET Core 3.0 的推出，微软引入了流异步处理。

你可以在以下链接完成关于异步流的教程：[`docs.microsoft.com/en-us/dotnet/csharp/tutorials/generate-consume-asynchronous-stream`](https://docs.microsoft.com/en-us/dotnet/csharp/tutorials/generate-consume-asynchronous-stream)

在 C# 8.0 和.NET Core 3.0 之前，`await`关键字仅适用于返回标量值的任务。.NET Standard 2.1 中的异步流支持允许`async`方法返回一系列值。

让我们看一个模拟示例，该示例返回三个随机整数作为异步流。

1.  使用你偏好的代码编辑器，在`Chapter12`解决方案/工作区中添加一个名为`AsyncEnumerable`的新控制台应用。

1.  在 Visual Studio Code 中，选择`AsyncEnumerable`作为活动的 OmniSharp 项目。

1.  在`Program.cs`中，删除现有语句并静态导入`Console`，如下面的代码所示：

    ```cs
    using static System.Console; // WriteLine() 
    ```

1.  在`Program.cs`底部，创建一个使用`yield`关键字异步返回三个随机数字序列的方法，如下面的代码所示：

    ```cs
    async static IAsyncEnumerable<int> GetNumbersAsync()
    {
      Random r = new();
      // simulate work
      await Task.Delay(r.Next(1500, 3000));
      yield return r.Next(0, 1001);
      await Task.Delay(r.Next(1500, 3000));
      yield return r.Next(0, 1001);
      await Task.Delay(r.Next(1500, 3000));
      yield return r.Next(0, 1001);
    } 
    ```

1.  在`GetNumbersAsync`上方，添加语句以枚举数字序列，如下面的代码所示：

    ```cs
    await foreach (int number in GetNumbersAsync())
    {
      WriteLine($"Number: {number}");
    } 
    ```

1.  运行代码并查看结果，如下面的输出所示：

    ```cs
    Number: 509
    Number: 813
    Number: 307 
    ```

# 实践与探索

通过回答一些问题，进行实践操作，并深入研究本章主题，来测试你的知识和理解。

## 练习 12.1 – 测试你的知识

回答以下问题：

1.  关于进程，你能了解到哪些信息？

1.  `Stopwatch`类的精确度如何？

1.  按照惯例，返回`Task`或`Task<T>`的方法应附加什么后缀？

1.  要在方法内部使用`await`关键字，方法声明必须应用什么关键字？

1.  如何创建子任务？

1.  为什么要避免使用`lock`关键字？

1.  何时应使用`Interlocked`类？

1.  何时应使用`Mutex`类而不是`Monitor`类？

1.  在网站或网络服务中使用`async`和`await`有何好处？

1.  你能取消一个任务吗？如果可以，如何操作？

## 练习 12.2 – 探索主题

请使用以下网页上的链接，以了解更多关于本章所涵盖主题的详细信息：

[第十二章 - 使用多任务提高性能和可扩展性](https://github.com/markjprice/cs10dotnet6/blob/main/book-links.md#chapter-12---improving-performance-and-scalability-using-multitasking)

# 总结

在本章中，你不仅学会了如何定义和启动任务，还学会了如何等待一个或多个任务完成，以及如何控制任务完成的顺序。你还学习了如何同步访问共享资源以及`async`和`await`背后的奥秘。

在接下来的七章中，你将学习如何为.NET 支持的**应用模型**，即**工作负载**，创建应用程序，例如网站和服务，以及跨平台的桌面和移动应用。
