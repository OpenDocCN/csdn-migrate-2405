# C# 和 Unity 2021 游戏开发学习手册（四）

> 原文：[`zh.annas-archive.org/md5/D5230158773728FED97C67760D6D7EA0`](https://zh.annas-archive.org/md5/D5230158773728FED97C67760D6D7EA0)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十一章：介绍堆栈、队列和 HashSet

在上一章中，我们重新访问了变量、类型和类，看看它们在书的开头介绍的基本功能之外还提供了什么。在本章中，我们将更仔细地研究新的集合类型，并了解它们的中级能力。请记住，成为一个好的程序员并不是关于记忆代码，而是选择合适的工具来完成合适的工作。

本章中的每种新集合类型都有特定的目的。在大多数需要数据集合的情况下，列表或数组都可以很好地工作。然而，当您需要临时存储或控制集合元素的顺序，或更具体地说，它们被访问的顺序时，可以使用堆栈和队列。当您需要执行依赖于集合中每个元素都是唯一的操作时，可以使用 HashSet。

在您开始下一节中的代码之前，让我们列出您将要学习的主题：

+   介绍堆栈

+   查看和弹出元素

+   使用队列

+   添加、移除和查看元素

+   使用 HashSet

+   执行操作

# 介绍堆栈

在其最基本的层面上，堆栈是相同指定类型的元素集合。堆栈的长度是可变的，这意味着它可以根据它所持有的元素数量而改变。堆栈与列表或数组之间的重要区别在于元素的存储方式。而列表或数组按索引存储元素，堆栈遵循**后进先出**（**LIFO**）模型，这意味着堆栈中的最后一个元素是第一个可访问的元素。这在您想要以相反顺序访问元素时非常有用。您应该注意它们可以存储`null`和重复值。一个有用的类比是一叠盘子——您放在堆栈上的最后一个盘子是您可以轻松拿到的第一个盘子。一旦它被移除，您堆叠的倒数第二个盘子就可以访问，依此类推。

本章中的所有集合类型都是`System.Collections.Generic`命名空间的一部分，这意味着您需要在要在其中使用它们的任何文件的顶部添加以下代码：

```cs
using System.Collections.Generic; 
```

现在您知道您将要处理的内容，让我们来看一下声明堆栈的基本语法。

堆栈变量声明需要满足以下要求：

+   `Stack`关键字，其元素类型在左右箭头字符之间，以及一个唯一名称

+   `new`关键字用于在内存中初始化堆栈，后跟`Stack`关键字和箭头字符之间的元素类型

+   由分号结束的一对括号

在蓝图形式中，它看起来像这样：

```cs
Stack<elementType> name = new Stack<elementType>(); 
```

与您之前使用过的其他集合类型不同，堆栈在创建时不能用元素初始化。相反，所有元素都必须在创建堆栈后添加。

C#支持不需要定义堆栈中元素类型的非通用版本：

```cs
Stack myStack = new Stack(); 
```

然而，这比使用前面的通用版本更不安全且更昂贵，因此建议使用上面的通用版本。您可以在[`github.com/dotnet/platform-compat/blob/master/docs/DE0006.md`](https://github.com/dotnet/platform-compat/blob/master/docs/DE0006.md)上阅读有关 Microsoft 的建议的更多信息。

您的下一个任务是创建自己的堆栈，并亲自体验使用其类方法。

为了测试这一点，您将使用堆栈修改*英雄诞生*中的现有物品收集逻辑，以存储可以收集的可能战利品。堆栈在这里很有效，因为我们不必担心提供索引来获取战利品，我们可以每次都获取最后添加的战利品：

1.  打开`GameBehavior.cs`并添加一个名为`LootStack`的新堆栈变量：

```cs
**// 1**
public Stack<string> LootStack = new Stack<string>(); 
```

1.  使用以下代码更新`Initialize`方法以向堆栈添加新项：

```cs
public void Initialize() 
{
    _state = "Game Manager initialized..";
    _state.FancyDebug();
    Debug.Log(_state);
    **// 2**
    **LootStack.Push(****"Sword of Doom"****);**
    **LootStack.Push(****"HP Boost"****);**
    **LootStack.Push(****"Golden Key"****);**
    **LootStack.Push(****"Pair of Winged Boots"****);**
    **LootStack.Push(****"Mythril Bracer"****);**
} 
```

1.  在脚本底部添加一个新方法来打印堆栈信息：

```cs
**// 3**
public void PrintLootReport()
{
    Debug.LogFormat("There are {0} random loot items waiting 
       for you!", LootStack.Count);
} 
```

1.  打开`ItemBehavior.cs`，并从`GameManager`实例中调用`PrintLootReport`：

```cs
void OnCollisionEnter(Collision collision)
{
    if(collision.gameObject.name == "Player")
    {
        Destroy(this.transform.parent.gameObject);
        Debug.Log("Item collected!");
        GameManager.Items += 1;

        **// 4**
        **GameManager.PrintLootReport();**
    }
} 
```

将其分解，它执行以下操作：

1.  创建一个空堆栈，其中包含字符串类型的元素，用于保存我们接下来要添加的战利品

1.  使用`Push`方法向堆栈中添加字符串元素（即战利品名称），每次增加其大小

1.  每当调用`PrintLootReport`方法时，都会打印出堆栈计数

1.  在`OnCollisionEnter`中调用`PrintLootReport`，每当玩家收集一个物品时都会调用，我们在之前的章节中使用 Collider 组件进行了设置。

在 Unity 中点击播放，收集一个物品预制件，并查看打印出来的新战利品报告。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_11_01.png)

图 11.1：使用堆栈的输出

现在您已经有一个可以保存所有游戏战利品的工作堆栈，您可以开始尝试使用堆栈类的`Pop`和`Peek`方法访问物品。

## 弹出和窥视

我们已经讨论过堆栈如何使用 LIFO 方法存储元素。现在，我们需要看一下如何访问熟悉但不同的集合类型中的元素——通过窥视和弹出：

+   `Peek`方法返回堆栈中的下一个物品，而不移除它，让您可以在不改变任何内容的情况下“窥视”它

+   `Pop`方法返回并移除堆栈中的下一个物品，实质上是“弹出”它并交给您

这两种方法可以根据您的需要单独或一起使用。在接下来的部分中，您将亲身体验这两种方法。

您的下一个任务是抓取添加到`LootStack`中的最后一个物品。在我们的示例中，最后一个元素是在`Initialize`方法中以编程方式确定的，但您也可以在`Initialize`中以编程方式随机排列添加到堆栈中的战利品的顺序。无论哪种方式，都要在`GameBehavior`中更新`PrintLootReport()`，使用以下代码：

```cs
public void PrintLootReport()
{
    **// 1**
    **var** **currentItem = LootStack.Pop();**
    **// 2**
    **var** **nextItem = LootStack.Peek();**
    **// 3**
    **Debug.LogFormat(****"You got a {0}! You've got a good chance of finding a {1} next!"****, currentItem, nextItem);**
    Debug.LogFormat("There are {0} random loot items waiting for you!", LootStack.Count);
} 
```

以下是正在发生的事情：

1.  在`LootStack`上调用`Pop`，移除堆栈中的下一个物品，并存储它。请记住，堆栈元素是按照 LIFO 模型排序的。

1.  在`LootStack`上调用`Peek`，并存储堆栈中的下一个物品，而不移除它。

1.  添加一个新的调试日志，打印出弹出的物品和堆栈中的下一个物品。

您可以从控制台看到，**秘银护腕**是最后添加到堆栈中的物品，被最先弹出，接着是**一双翅膀靴**，它被窥视但没有被移除。您还可以看到`LootStack`还有四个剩余的可以访问的元素：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_11_02.png)

图 11.2：从堆栈中弹出和窥视的输出

我们的玩家现在可以按照堆栈中添加的相反顺序拾取战利品。例如，首先拾取的物品将始终是**秘银护腕**，然后是**一双翅膀靴**，然后是**金色钥匙**，依此类推。

现在您知道如何创建、添加和查询堆栈中的元素，我们可以继续学习通过堆栈类可以访问的一些常见方法。

## 常见方法

本节中的每个方法仅用于示例目的，它们不包括在我们的游戏中，因为我们不需要这些功能。

首先，您可以使用`Clear`方法清空或删除堆栈的全部内容：

```cs
// Empty the stack and reverting the count to 0
LootStack**.Clear();** 
```

如果您想知道您的堆栈中是否存在某个元素，请使用`Contains`方法并指定您要查找的元素：

```cs
// Returns true for "Golden Key" item
var itemFound = LootStack**.Contains(****"Golden Key"****);** 
```

如果您需要将堆栈的元素复制到数组中，`CopyTo`方法将允许您指定目标和复制操作的起始索引。当您需要在数组的特定位置插入堆栈元素时，这个功能非常有用。请注意，您要将堆栈元素复制到的数组必须已经存在：

```cs
// Creates a new array of the same length as LootStack
string[] CopiedLoot = new string[5]; 
/* 
Copies the LootStack elements into the new CopiedLoot array at index 0\. The index parameter can be set to any index where you want the copied elements to be stored
*/
LootStack**.CopyTo(copiedLoot,** **0****);** 
```

如果您需要将堆栈转换为数组，只需使用`ToArray()`方法。这种转换会从您的堆栈中创建一个新数组，这与`CopyTo()`方法不同，后者将堆栈元素复制到现有数组中：

```cs
// Copies an existing stack to a new array
LootStack.ToArray(); 
```

您可以在 C#文档中找到完整的堆栈方法列表[`docs.microsoft.com/dotnet/api/system.collections.generic.stack-1?view=netcore-3.1`](https://docs.microsoft.com/dotnet/api/system.collections.generic.stack-1?view=netcore-3.1)。

这就结束了我们对堆栈的介绍，但是我们将在下一节中讨论它的堂兄，队列。

# 使用队列

与堆栈一样，队列是相同类型的元素或对象的集合。任何队列的长度都是可变的，就像堆栈一样，这意味着随着元素的添加或移除，其大小会发生变化。但是，队列遵循**先进先出**（**FIFO**）模型，这意味着队列中的第一个元素是第一个可访问的元素。您应该注意，队列可以存储`null`和重复的值，但在创建时不能用元素初始化。本节中的代码仅用于示例目的，不包括在我们的游戏中。

队列变量声明需要具备以下内容：

+   `Queue`关键字，其元素类型在左右箭头字符之间，以及一个唯一名称

+   使用`new`关键字在内存中初始化队列，然后是`Queue`关键字和箭头字符之间的元素类型

+   一对括号，以分号结束

以蓝图形式，队列如下所示：

```cs
Queue<elementType> name = new Queue<elementType>(); 
```

C#支持队列类型的非泛型版本，无需定义存储的元素类型：

```cs
Queue myQueue = new Queue(); 
```

但是，这比使用前面的泛型版本更不安全且更昂贵。您可以在[`github.com/dotnet/platform-compat/blob/master/docs/DE0006.md`](https://github.com/dotnet/platform-compat/blob/master/docs/DE0006.md)上阅读有关 Microsoft 建议的更多信息。

一个空的队列本身并不那么有用；您希望能够在需要时添加、移除和查看其元素，这是下一节的主题。

## 添加、移除和查看

由于前几节中的`LootStack`变量很容易成为队列，我们将保持以下代码不包含在游戏脚本中以提高效率。但是，您可以自由地探索这些类在您自己的代码中的差异或相似之处。

要创建一个字符串元素的队列，请使用以下方法：

```cs
// Creates a new Queue of string values.
Queue<string> activePlayers = new Queue<string>(); 
```

要向队列添加元素，请使用`Enqueue`方法并提供要添加的元素：

```cs
// Adds string values to the end of the Queue.
activePlayers**.Enqueue(****"Harrison"****);**
activePlayers**.Enqueue(****"Alex"****);**
activePlayers**.Enqueue(****"Haley"****);** 
```

要查看队列中的第一个元素而不移除它，请使用`Peek`方法：

```cs
// Returns the first element in the Queue without removing it.
var firstPlayer = activePlayers**.Peek();** 
```

要返回并移除队列中的第一个元素，请使用`Dequeue`方法：

```cs
// Returns and removes the first element in the Queue.
var firstPlayer = activePlayers**.Dequeue();** 
```

现在您已经了解了如何使用队列的基本特性，请随意探索队列类提供的更中级和高级方法。

## 常见方法

队列和堆栈几乎具有完全相同的特性，因此我们不会再次介绍它们。您可以在 C#文档中找到完整的方法和属性列表[`docs.microsoft.com/dotnet/api/system.collections.generic.queue-1?view=netcore-3.1`](https://docs.microsoft.com/dotnet/api/system.collections.generic.queue-1?view=netcore-3.1)。

在结束本章之前，让我们来看看 HashSet 集合类型及其独特适用的数学运算。

# 使用 HashSets

本章中我们将接触的最后一个集合类型是 HashSet。这个集合与我们遇到的任何其他集合类型都非常不同：它不能存储重复的值，也不是排序的，这意味着它的元素没有以任何方式排序。将 HashSets 视为只有键而不是键值对的字典。

它们可以执行集合操作和元素查找非常快，我们将在本节末尾进行探讨，并且最适合元素顺序和唯一性是首要考虑的情况。

HashSet 变量声明需要满足以下要求：

+   `HashSet`关键字，其元素类型在左右箭头字符之间，以及一个唯一名称

+   使用`new`关键字在内存中初始化 HashSet，然后是`HashSet`关键字和箭头字符之间的元素类型

+   由分号结束的一对括号

在蓝图形式中，它看起来如下：

```cs
HashSet<elementType> name = new HashSet<elementType>(); 
```

与栈和队列不同，你可以在声明变量时使用默认值初始化 HashSet：

```cs
HashSet<string> people = new HashSet<string>();
// OR
HashSet<string> people = new HashSet<string>() { "Joe", "Joan", "Hank"}; 
```

添加元素时，使用`Add`方法并指定新元素：

```cs
people**.Add(****"Walter"****);**
people**.Add(****"Evelyn"****);** 
```

要删除一个元素，调用`Remove`并指定你想要从 HashSet 中删除的元素：

```cs
people**.Remove(****"Joe"****);** 
```

这就是简单的内容了，在你的编程之旅中，这一点应该开始感觉相当熟悉了。集合操作是 HashSet 集合真正发光的地方，这是接下来章节的主题。

## 执行操作

集合操作需要两样东西：一个调用集合对象和一个传入的集合对象。

调用集合对象是你想要根据使用的操作修改的 HashSet，而传入的集合对象是由集合操作进行比较使用的。我们将在接下来的代码中详细介绍这一点，但首先，让我们先了解一下在编程场景中最常见的三种主要集合操作。

在以下定义中，`currentSet`指的是调用操作方法的 HashSet，而`specifiedSet`指的是传入的 HashSet 方法参数。修改后的 HashSet 始终是当前集合：

```cs
currentSet.Operation(specifiedSet); 
```

在接下来的这一部分，我们将使用三种主要操作：

+   `UnionWith`将当前集合和指定集合的元素添加在一起。

+   `IntersectWith`仅存储当前集合和指定集合中都存在的元素

+   `ExceptWith`从当前集合中减去指定集合的元素

还有两组处理子集和超集计算的集合操作，但这些针对特定用例，超出了本章的范围。你可以在[`docs.microsoft.com/dotnet/api/system.collections.generic.hashset-1?view=netcore-3.1`](https://docs.microsoft.com/dotnet/api/system.collections.generic.hashset-1?view=netcore-3.1)找到所有这些方法的相关信息。

假设我们有两组玩家名称的集合——一个是活跃玩家的集合，另一个是非活跃玩家的集合：

```cs
HashSet<string> activePlayers = new HashSet<string>() { "Harrison", "Alex", "Haley"};
HashSet<string> inactivePlayers = new HashSet<string>() { "Kelsey", "Basel"}; 
```

我们将使用`UnionWith()`操作来修改一个集合，以包括两个集合中的所有元素：

```cs
activePlayers.UnionWith(inactivePlayers);
/* activePlayers now stores "Harrison", "Alex", "Haley", "Kelsey", "Basel"*/ 
```

现在，假设我们有两个不同的集合——一个是活跃玩家的集合，另一个是高级玩家的集合：

```cs
HashSet<string> activePlayers = new HashSet<string>() { "Harrison", "Alex", "Haley"};
HashSet<string> premiumPlayers = new HashSet<string>() { "Haley", "Basel"}; 
```

我们将使用`IntersectWith()`操作来查找任何既是活跃玩家又是高级会员的玩家：

```cs
activePlayers.IntersectWith(premiumPlayers);
// activePlayers now stores only "Haley" 
```

如果我们想找到所有活跃玩家中不是高级会员的玩家怎么办？我们将通过调用`ExceptWith`来执行与`IntersectWith()`操作相反的操作：

```cs
HashSet<string> activePlayers = new HashSet<string>() { "Harrison", "Alex", "Haley"};
HashSet<string> premiumPlayers = new HashSet<string>() { "Haley",
  "Basel"};
activePlayers.ExceptWith(premiumPlayers);
// activePlayers now stores "Harrison" and "Alex" but removed "Haley" 
```

请注意，我在每个操作中使用了两个示例集合的全新实例，因为当前集合在执行每个操作后都会被修改。如果你一直使用相同的集合，你会得到不同的结果。

现在你已经学会了如何使用 HashSets 执行快速数学运算，是时候结束我们的章节，总结我们所学到的知识了。

# 中间集合总结

在你继续阅读总结和下一章之前，让我们再次强调一些我们刚刚学到的关键点。有时，与我们正在构建的实际游戏原型不总是一对一关系的主题需要额外的关注。

在这一点上，我确定你会问自己一个问题：为什么在任何情况下都要使用这些其他集合类型，而不是只使用列表呢？这是一个完全合理的问题。简单的答案是，当在正确的情况下应用时，栈、队列和 HashSets 比列表提供更好的性能。例如，当你需要按特定顺序存储项目并按特定顺序访问它们时，栈比列表更有效。

更复杂的答案是，使用不同的集合类型会强制规定您的代码如何与它们及其元素进行交互。这是良好代码设计的标志，因为它消除了您计划如何使用集合的任何歧义。到处都是列表，当您不记得要求它们执行什么功能时，事情就会变得混乱。

与本书中学到的一切一样，最好始终使用合适的工具来完成手头的工作。更重要的是，您需要有不同的工具可供选择。

# 摘要

恭喜，您几乎到达终点了！在本章中，您了解了三种新的集合类型，以及它们在不同情况下的用法。

如果您想以添加顺序的相反顺序访问集合元素，则堆栈非常适合，如果您想以顺序顺序访问元素，则队列是您的选择，两者都非常适合临时存储。这些集合类型与列表或数组之间的重要区别在于它们如何通过弹出和查看操作进行访问。最后，您了解了强大的 HashSet 及其基于性能的数学集合操作。在需要处理唯一值并对大型集合执行添加、比较或减法操作的情况下，这些是关键。

在下一章中，您将深入了解 C#的中级世界，包括委托、泛型等，因为您接近本书的结尾。即使您已经学到了所有知识，最后一页仍然只是另一段旅程的开始。

# 中级集合小测验

1.  哪种集合类型使用 LIFO 模型存储其元素？

1.  哪种方法让您查询堆栈中的下一个元素而不移除它？

1.  堆栈和队列能存储`null`值吗？

1.  如何从一个 HashSet 中减去另一个 HashSet？

# 加入我们的 Discord！

与其他用户、Unity/C#专家和 Harrison Ferrone 一起阅读本书。提出问题，为其他读者提供解决方案，通过*问我任何事*会话与作者交流等等。

立即加入！

[`packt.link/csharpunity2021`](https://packt.link/csharpunity2021)

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/QR_Code_9781801813945.png)


# 第十二章：保存、加载和序列化数据

您玩过的每个游戏都使用数据，无论是您的玩家统计数据、游戏进度还是在线多人游戏积分榜。您最喜欢的游戏还管理内部数据，这意味着程序员使用硬编码信息来构建级别、跟踪敌人统计数据并编写有用的实用程序。换句话说，数据无处不在。

在本章中，我们将从 C#和 Unity 如何处理计算机上的文件系统开始，并继续阅读、写入和序列化我们的游戏数据。我们的重点是处理您可能会遇到的三种最常见的数据格式：文本文件、XML 和 JSON。

在本章结束时，您将对计算机的文件系统、数据格式和基本的读写功能有一个基础的理解。这将是您构建游戏数据的基础，为玩家创造更丰富和引人入胜的体验。您还将有一个很好的起点，开始思考哪些游戏数据是重要的，以及您的 C#类和对象在不同的数据格式中会是什么样子。

在这个过程中，我们将涵盖以下主题：

+   介绍文本、XML 和 JSON 格式

+   了解文件系统

+   使用不同的流类型

+   阅读和写入游戏数据

+   序列化对象

# 介绍数据格式

数据在编程中可以采用不同的形式，但您在数据旅程开始时应熟悉的三种格式是：

+   **文本**，这就是您现在正在阅读的内容

+   **XML**（**可扩展标记语言**），这是一种编码文档信息的方式，使其对您和计算机可读

+   **JSON**（**JavaScript 对象表示**），这是一种由属性-值对和数组组成的可读文本格式

每种数据格式都有其自身的优势和劣势，以及在编程中的应用。例如，文本通常用于存储更简单、非分层或嵌套的信息。XML 更擅长以文档格式存储信息，而 JSON 在数据库信息和应用程序的服务器通信方面具有更广泛的能力。

您可以在[`www.xml.com`](https://www.xml.com)找到有关 XML 的更多信息，以及在[`www.json.org`](https://www.json.org)找到有关 JSON 的信息。

数据在任何编程语言中都是一个重要的主题，因此让我们从下两节中实际了解 XML 和 JSON 格式是什么样子开始。

## 分解 XML

典型的 XML 文件具有标准化格式。XML 文档的每个元素都有一个开放标签(`<element_name>`)，一个关闭标签(`</element_name>`)，并支持标签属性(`<element_name attribute= "attribute_name"></element_name>`)。一个基本文件将以正在使用的版本和编码开始，然后是起始或根元素，然后是元素项列表，最后是关闭元素。作为蓝图，它将如下所示：

```cs
<?xml version="1.0" encoding="utf-8"?>
<root_element>
    <element_item>[Information goes here]</element_item>
    <element_item>[Information goes here]</element_item>
    <element_item>[Information goes here]</element_item>
</root_element> 
```

XML 数据还可以通过使用子元素存储更复杂的对象。例如，我们将使用我们在本书中早些时候编写的`Weapon`类，将武器列表转换为 XML。由于每个武器都有其名称和伤害值的属性，它将如下所示：

```cs
// 1
<?xml version="1.0"?>
// 2
<ArrayOfWeapon>
     // 3
    <Weapon>
     // 4
        <name>Sword of Doom</name>
        <damage>100</damage>
     // 5
    </Weapon>
    <Weapon>
        <name>Butterfly knives</name>
        <damage>25</damage>
    </Weapon>
    <Weapon>
        <name>Brass Knuckles</name>
        <damage>15</damage>
    </Weapon>
// 6
</ArrayOfWeapon> 
```

让我们分解上面的示例，确保我们理解正确：

1.  XML 文档以正在使用的版本开头

1.  根元素使用名为`ArrayOfWeapon`的开放标签声明，它将保存所有我们的元素项

1.  使用开放标签`Weapon`创建了一个武器项目

1.  其子属性是通过单行上的开放和关闭标签添加的，用于`name`和`damage`

1.  武器项目已关闭，并添加了两个武器项目

1.  数组关闭，标志着文档的结束

好消息是我们的应用程序不必手动以这种格式编写我们的数据。C#有一个完整的类和方法库，可以帮助我们直接将简单文本和类对象转换为 XML。

稍后我们将深入实际的代码示例，但首先我们需要了解 JSON 的工作原理。

## 解析 JSON

JSON 数据格式类似于 XML，但没有标签。相反，一切都基于属性-值对，就像我们在*第四章*“控制流和集合类型”中使用的**Dictionary**集合类型一样。每个 JSON 文档都以一个父字典开始，其中包含您需要的许多属性-值对。字典使用开放和关闭的大括号（`{}`），冒号分隔每个属性和值，每个属性-值对之间用逗号分隔：

```cs
// Parent dictionary for the entire file
{
    // List of attribute-value pairs where you store your data
    "attribute_name": value,
    "attribute_name": value
} 
```

JSON 也可以通过将属性-值对的值设置为属性-值对数组来具有子结构。例如，如果我们想要存储一把武器，它会是这样的：

```cs
// Parent dictionary
{
    // Weapon attribute with its value set to an child dictionary
    "weapon": {
          // Attribute-value pairs with weapon data
          "name": "Sword of Doom",
          "damage": 100
    }
} 
```

最后，JSON 数据通常由列表、数组或对象组成。继续我们的例子，如果我们想要存储玩家可以选择的所有武器的列表，我们将使用一对方括号来表示一个数组：

```cs
// Parent dictionary
{
    // List of weapon attribute set to an array of weapon objects
    "weapons": [
        // Each weapon object stored as its own dictionary
        {
            "name": "Sword of Doom",
            "damage": 100
        },
        {
            "name": "Butterfly knives",
            "damage": 25
        },
        {
            "name": "Brass Knuckles",
            "damage": 15
        }
    ]
} 
```

您可以混合和匹配这些技术来存储您需要的任何类型的复杂数据，这是 JSON 的主要优势之一。但就像 XML 一样，不要被新的语法所吓倒——C#和 Unity 都有辅助类和方法，可以将文本和类对象转换为 JSON，而无需我们做任何繁重的工作。阅读 XML 和 JSON 有点像学习一门新语言——您使用得越多，它就会变得越熟悉。很快它就会成为第二天性！

现在我们已经初步了解了数据格式化的基础知识，我们可以开始讨论计算机上的文件系统是如何工作的，以及我们可以从 C#代码中访问哪些属性。

# 了解文件系统

当我们说文件系统时，我们指的是您已经熟悉的东西——文件和文件夹如何在计算机上创建、组织和存储。当您在计算机上创建一个新文件夹时，您可以为其命名并将文件或其他文件夹放入其中。它也由图标表示，这既是一种视觉提示，也是一种拖放和移动到任何您喜欢的位置的方式。

您可以在桌面上做的任何事情都可以在代码中完成。您只需要文件夹的名称，或者称为目录，以及存储它的位置。每当您想要添加文件或子文件夹时，您都需要引用父目录并添加新内容。

为了更好地理解文件系统，让我们开始构建`DataManager`类：

1.  在**Hierarchy**中右键单击并选择**Create Empty**，然后命名为**Data_Manager**：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_12_01.png)

图 12.1：Hierarchy 中的 Data_Manager

1.  在**Hierarchy**中选择**Data_Manager**对象，并将我们在*第十章*“重新审视类型、方法和类”中创建的`DataManager`脚本从**Scripts**文件夹拖放到**Inspector**中：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_12_02.png)

图 12.2：Inspector 中的 Data_Manager

1.  打开`DataManager`脚本，并使用以下代码更新它以打印出一些文件系统属性：

```cs
using System.Collections;
using System.Collections.Generic;
using UnityEngine;

**// 1**
**using** **System.IO;**

public class DataManager : MonoBehaviour, IManager
{
    // ... No variable changes needed ...

    public void Initialize()
    {
        _state = "Data Manager initialized..";
        Debug.Log(_state);

        **// 2**
        **FilesystemInfo();**
    }
    public void FilesystemInfo()
    {
        **// 3**
        **Debug.LogFormat(****"Path separator character: {0}"****,**
          **Path.PathSeparator);**
        **Debug.LogFormat(****"Directory separator character: {0}"****,**
          **Path.DirectorySeparatorChar);**
        **Debug.LogFormat(****"Current directory: {0}"****,**
          **Directory.GetCurrentDirectory());**
        **Debug.LogFormat(****"Temporary path: {0}"****,**
          **Path.GetTempPath());**
    }
} 
```

让我们分解代码：

1.  首先，我们添加`System.IO`命名空间，其中包含了我们需要处理文件系统的所有类和方法。

1.  我们调用我们在下一步创建的`FilesystemInfo`方法。

1.  我们创建`FilesystemInfo`方法来打印出一些文件系统属性。每个操作系统都以不同的方式处理其文件系统路径——路径是以字符串形式写入的目录或文件的位置。在 Mac 上：

+   路径由冒号(`:`)分隔

+   目录由斜杠(`/`)分隔

+   当前目录路径是*Hero Born*项目存储的位置

+   临时路径是您文件系统的临时文件夹的位置

如果您使用其他平台和操作系统，请在使用文件系统之前自行检查`Path`和`Directory`方法。

运行游戏并查看输出：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_12_03.png)

图 12.3：来自数据管理器的控制台消息

`Path`和`Directory`类是我们将在接下来的部分中用来存储数据的基础。然而，它们都是庞大的类，所以我鼓励您在继续数据之旅时查阅它们的文档。

您可以在[`docs.microsoft.com/en-us/dotnet/api/system.io.path`](https://docs.microsoft.com/en-us/dotnet/api/system.io.path)找到`Path`类的更多文档，以及在[`docs.microsoft.com/en-us/dotnet/api/system.io.directory`](https://docs.microsoft.com/en-us/dotnet/api/system.io.directory)找到`Directory`类的更多文档。

现在我们在`DataManager`脚本中打印出了文件系统属性的简单示例，我们可以创建一个文件系统路径，将数据保存到我们想要保存数据的位置。

## 处理资源路径

在纯 C#应用程序中，您需要选择要保存文件的文件夹，并将文件夹路径写入字符串中。然而，Unity 提供了一个方便的预配置路径作为`Application`类的一部分，您可以在其中存储持久游戏数据。持久数据意味着信息在每次程序运行时都会被保存和保留，这使得它非常适合这种玩家信息。

重要的是要知道，Unity 持久数据目录的路径是跨平台的，这意味着为 iOS、Android、Windows 等构建游戏时会有所不同。您可以在 Unity 文档中找到更多信息[`docs.unity3d.com/ScriptReference/Application-persistentDataPath.html`](https://docs.unity3d.com/ScriptReference/Application-persistentDataPath.html)。

我们需要对`DataManager`进行的唯一更新是创建一个私有变量来保存我们的路径字符串。我们将其设置为私有，因为我们不希望任何其他脚本能够访问或更改该值。这样，`DataManager`负责所有与数据相关的逻辑，而不会有其他东西。

在`DataManager.cs`中添加以下变量：

```cs
public class DataManager : MonoBehaviour, IManager
{
    // ... No other variable changes needed ...

    **// 1**
    **private****string** **_dataPath;**
    **// 2**
    **void****Awake****()**
    **{**
        **_dataPath = Application.persistentDataPath +** **"/Player_Data/"****;**

        **Debug.Log(_dataPath);**
    **}**

    // ... No other changes needed ...
} 
```

让我们分解一下我们的代码更新：

1.  我们创建了一个私有变量来保存数据路径字符串

1.  我们将数据路径字符串设置为应用程序的`persistentDataPath`值，使用开放和关闭的斜杠添加了一个名为**Player_Data**的新文件夹，并打印出完整路径：

+   重要的是要注意，`Application.persistentDataPath`只能在`MonoBehaviour`方法中使用，如`Awake()`、`Start()`、`Update()`等，游戏需要运行才能让 Unity 返回有效的路径。

图 12.4：Unity 持久数据文件的文件路径

由于我使用的是 Mac，我的持久数据文件夹嵌套在我的`/Users`文件夹中。如果您使用不同的设备，请记得查看[`docs.unity3d.com/ScriptReference/Application-persistentDataPath.html`](https://docs.unity3d.com/ScriptReference/Application-persistentDataPath.html)以找出您的数据存储在何处。

当您不使用类似 Unity 持久数据目录这样的预定义资源路径时，C#中有一个名为`Combine`的便利方法，位于`Path`类中，用于自动配置路径变量。`Combine()`方法最多可以接受四个字符串作为输入参数，或者表示路径组件的字符串数组。例如，指向您的`User`目录的路径可能如下所示：

```cs
var path = Path.Combine("/Users", "hferrone", "Chapter_12"); 
```

这解决了路径和目录中的分隔字符和反斜杠或正斜杠的任何潜在跨平台问题。

现在我们有了一个存储数据的路径，让我们在文件系统中创建一个新目录，或文件夹。这将使我们能够安全地存储我们的数据，并在游戏运行之间进行存储，而不是在临时存储中被删除或覆盖。

## 创建和删除目录

创建新目录文件夹很简单-我们检查是否已经存在具有相同名称和相同路径的目录，如果没有，我们告诉 C#为我们创建它。每个人都有自己处理文件和文件夹中重复内容的方法，因此在本章的其余部分中我们将重复相当多的重复检查代码。

我仍然建议在现实世界的应用程序中遵循**DRY**（**不要重复自己**）原则；重复检查代码只是为了使示例完整且易于理解而在这里重复。

1.  在`DataManager`中添加以下方法：

```cs
public void NewDirectory()
{
    // 1
    if(Directory.Exists(_dataPath))
    {
        // 2
        Debug.Log("Directory already exists...");
        return;
    }
    // 3
    Directory.CreateDirectory(_dataPath);
    Debug.Log("New directory created!");
} 
```

1.  在`Initialize()`中调用新方法：

```cs
public void Initialize()
{
    _state = "Data Manager initialized..";
    Debug.Log(_state);
    **NewDirectory();**
} 
```

让我们分解一下我们所做的事情：

1.  首先，我们使用上一步创建的路径检查目录文件夹是否已经存在

1.  如果已经创建，我们会在控制台中发送消息，并使用`return`关键字退出方法，不再继续执行

1.  如果目录文件夹不存在，我们将向`CreateDirectory()`方法传递我们的数据路径，并记录它已被创建

运行游戏，并确保您在控制台中看到正确的调试日志，以及您的持久数据文件夹中的新目录文件夹。

如果找不到它，请使用我们在上一步中打印出的`_dataPath`值。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_12_05.png)

图 12.5：新目录创建的控制台消息

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_12_06.png)

图 12.6：在桌面上创建的新目录

如果您第二次运行游戏，将不会创建重复的目录文件夹，这正是我们想要的安全代码。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_12_07.png)

图 12.7：重复目录文件夹的控制台消息

删除目录与创建方式非常相似-我们检查它是否存在，然后使用`Directory`类删除我们传入路径的文件夹。

在`DataManager`中添加以下方法：

```cs
public void DeleteDirectory()
{
    // 1
    if(!Directory.Exists(_dataPath))
    {
        // 2
        Debug.Log("Directory doesn't exist or has already been
deleted...");

        return;
    }
    // 3
    Directory.Delete(_dataPath, true);
    Debug.Log("Directory successfully deleted!");
} 
```

由于我们想保留我们刚刚创建的目录，您现在不必调用此函数。但是，如果您想尝试它，您只需要在`Initialize()`函数中用`DeleteDirectory()`替换`NewDirectory()`。

空目录文件夹并不是很有用，所以让我们创建我们的第一个文本文件并将其保存在新位置。

## 创建、更新和删除文件

与创建和删除目录类似，处理文件也是如此，因此我们已经拥有了我们需要的基本构件。为了确保我们不重复数据，我们将检查文件是否已经存在，如果不存在，我们将在新目录文件夹中创建一个新文件。

在本节中，我们将使用`File`类来处理文件，该类具有大量有用的方法来帮助我们实现我们的功能。您可以在[`docs.microsoft.com/en-us/dotnet/api/system.io.file`](https://docs.microsoft.com/en-us/dotnet/api/system.io.file)找到整个列表。

在我们开始之前，关于文件的一个重要观点是，在添加文本之前需要打开文件，并且在完成后需要关闭文件。如果不关闭正在程序化处理的文件，它将保持在程序的内存中。这既使用了计算能力，又可能导致内存泄漏。稍后在本章中会详细介绍。

我们将为我们想要执行的每个操作（创建、更新和删除）编写单独的方法。我们还将在每种情况下检查我们正在处理的文件是否存在，这是重复的。我构建了本书的这一部分，以便您可以牢固掌握每个过程。但是，在学会基础知识后，您绝对可以将它们合并为更经济的方法。

采取以下步骤：

1.  为新文本文件添加一个新的私有字符串路径，并在`Awake`中设置其值：

```cs
private string _dataPath;
**private****string** **_textFile;**
void Awake()
{
    _dataPath = Application.persistentDataPath + "/Player_Data/";

    Debug.Log(_dataPath);

    **_textFile = _dataPath +** **"Save_Data.txt"****;**
} 
```

1.  在`DataManager`中添加一个新方法：

```cs
public void NewTextFile()
{
    // 1
    if (File.Exists(_textFile))
    {
        Debug.Log("File already exists...");
        return;
    }
    // 2
    File.WriteAllText(_textFile, "<SAVE DATA>\n\n");
    // 3
    Debug.Log("New file created!");
} 
```

1.  在`Initialize()`中调用新方法：

```cs
public void Initialize()
{
    _state = "Data Manager initialized..";
    Debug.Log(_state);

    FilesystemInfo();
    NewDirectory();
    **NewTextFile();**
} 
```

让我们分解一下我们的新代码：

1.  我们检查文件是否已经存在，如果存在，我们将使用`return`退出方法以避免重复：

+   值得注意的是，这种方法适用于不会被更改的新文件。我们将在下一个练习中讨论更新和覆盖文件数据。

1.  我们使用`WriteAllText()`方法，因为它可以一次完成所有需要的操作：

+   使用我们的`_textFile`路径创建一个新文件

+   我们添加一个标题字符串，写着`<SAVE DATA>`，并添加两个新行，使用`\n`字符

+   然后文件会自动关闭

1.  我们打印一个日志消息，让我们知道一切顺利进行

现在玩游戏，你会在控制台看到调试日志和持久数据文件夹位置中的新文本文件：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_12_08.png)

图 12.8：新文件创建的控制台消息

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_12_09.png)

图 12.9：在桌面上创建的新文件

要更新我们的新文本文件，我们将进行类似的操作。知道新游戏何时开始总是很好，所以你的下一个任务是添加一个方法将这些信息写入我们的保存数据文件：

1.  在`DataManager`的顶部添加一个新的`using`指令：

```cs
using System.Collections;
using System.Collections.Generic;
using UnityEngine;
using System.IO;
**using** **System;** 
```

1.  在`DataManager`中添加一个新方法：

```cs
public void UpdateTextFile()
{
    // 1
    if (!File.Exists(_textFile))
    {
        Debug.Log("File doesn't exist...");
        return;
    }

    // 2
    File.AppendAllText(_textFile, $"Game started: {DateTime.Now}\n");
    // 3
    Debug.Log("File updated successfully!");
} 
```

1.  在`Initialize()`中调用新方法：

```cs
public void Initialize()
{
    _state = "Data Manager initialized..";
    Debug.Log(_state);

    FilesystemInfo();
    NewDirectory();
    NewTextFile();
    **UpdateTextFile();**
} 
```

让我们来分解上面的代码：

1.  如果文件存在，我们不想重复创建，所以我们只是退出方法而不采取进一步的行动

1.  如果文件存在，我们使用另一个名为`AppendAllText()`的一体化方法来添加游戏的开始时间：

+   这个方法打开文件

+   它添加一个作为方法参数传入的新文本行

+   它关闭文件

1.  打印一个日志消息，让我们知道一切顺利进行

再次玩游戏，你会看到我们的控制台消息和文本文件中的新行，显示了新游戏的日期和时间：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_12_10.png)

图 12.10：更新文本文件的控制台消息

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_12_11.png)

图 12.11：更新的文本文件数据

为了读取我们的新文件数据，我们需要一个方法来获取文件的所有文本并以字符串形式返回给我们。幸运的是，`File`类有相应的方法：

1.  在`DataManager`中添加一个新方法：

```cs
// 1
public void ReadFromFile(string filename)
{
    // 2
    if (!File.Exists(filename))
    {
        Debug.Log("File doesn't exist...");
        return;
    }

    // 3
    Debug.Log(File.ReadAllText(filename));
} 
```

1.  在`Initialize()`中调用新方法，并将`_textFile`作为参数传入：

```cs
public void Initialize()
{
    _state = "Data Manager initialized..";
    Debug.Log(_state);

    FilesystemInfo();
    NewDirectory();
    NewTextFile();
    UpdateTextFile();
    **ReadFromFile(_textFile);**
} 
```

让我们来分解下面的新方法代码：

1.  我们创建一个接受文件名参数的新方法

1.  如果文件不存在，就不需要采取任何行动，所以我们退出方法

1.  我们使用`ReadAllText()`方法将文件的所有文本数据作为字符串获取并打印到控制台

玩游戏，你会看到一个控制台消息，显示我们之前的保存和一个新的保存！

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_12_12.png)

图 12.12：从文件中读取的保存文本数据的控制台消息

最后，让我们添加一个方法来删除我们的文本文件。实际上，我们不会使用这个方法，因为我们想保持我们的文本文件不变，但你可以自己尝试一下：

```cs
public void DeleteFile(string filename)
{
    if (!File.Exists(filename))
    {
        Debug.Log("File doesn't exist or has already been deleted...");

        return;
    }

    File.Delete(_textFile);
    Debug.Log("File successfully deleted!");
} 
```

现在我们已经深入了一点文件系统的水域，是时候谈谈一个稍微升级的处理信息方式了——数据流！

# 使用流进行操作

到目前为止，我们一直让`File`类来处理我们的数据。我们还没有讨论的是`File`类，或者任何其他处理读写数据的类是如何在底层工作的。

对于计算机来说，数据由字节组成。把字节想象成计算机的原子，它们构成了一切——甚至有一个 C#的`byte`类型。当我们读取、写入或更新文件时，我们的数据被转换为字节数组，然后使用`Stream`将这些字节流到文件中或从文件中流出。数据流负责将数据作为字节序列传输到文件中或从文件中传输，充当我们的游戏应用程序和数据文件之间的翻译器或中介。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_12_13.png)

图 12.13：将数据流到文件的图示

`File`类自动为我们使用`Stream`对象，不同的`Stream`子类有不同的功能：

+   使用`FileStream`来读取和写入文件数据

+   使用`MemoryStream`来读取和写入数据到内存

+   使用`NetworkStream`来读取和写入数据到其他网络计算机

+   使用`GZipStream`来压缩数据以便更容易存储和下载

在接下来的章节中，我们将深入了解管理流资源，使用名为`StreamReader`和`StreamWriter`的辅助类来创建、读取、更新和删除文件。您还将学习如何使用`XmlWriter`类更轻松地格式化 XML。

## 管理您的流资源

我们还没有谈论的一个重要主题是资源分配。这意味着您的代码中的一些进程将把计算能力和内存放在一种类似分期付款的计划中，您无法触及它。这些进程将等待，直到您明确告诉您的程序或游戏关闭并将分期付款资源归还给您，以便您恢复到全功率。流就是这样一个进程，它们在使用完毕后需要关闭。如果您不正确地关闭流，您的程序将继续使用这些资源，即使您不再使用它们。

幸运的是，C#有一个方便的接口叫做`IDisposable`，所有的`Stream`类都实现了这个接口。这个接口只有一个方法，`Dispose()`，它告诉流何时将使用的资源归还给您。

您不必太担心这个问题，因为我们将介绍一种自动方式来确保您的流始终正确关闭。资源管理只是一个很好的编程概念需要理解。

在本章的其余部分，我们将使用`FileStream`，但我们将使用称为`StreamWriter`和`StreamReader`的便利类。这些类省去了将数据手动转换为字节的步骤，但仍然使用`FileStream`对象本身。

## 使用 StreamWriter 和 StreamReader

`StreamWriter`和`StreamReader`类都是`FileStream`的辅助类，用于将文本数据写入和读取到特定文件。这些类非常有帮助，因为它们创建、打开并返回一个流，您可以使用最少的样板代码。到目前为止，我们已经涵盖的示例代码对于小型数据文件来说是可以的，但是如果您处理大型和复杂的数据对象，流是最好的选择。

我们只需要文件的名称，我们就可以开始了。您的下一个任务是使用流将文本写入新文件：

1.  为新的流文本文件添加一个新的私有字符串路径，并在`Awake()`中设置其值：

```cs
private string _dataPath;
private string _textFile;
**private****string** **_streamingTextFile;**

void Awake()
{
    _dataPath = Application.persistentDataPath + "/Player_Data/";
    Debug.Log(_dataPath);

    _textFile = _dataPath + "Save_Data.txt";
    **_streamingTextFile = _dataPath +** **"Streaming_Save_Data.txt"****;**
} 
```

1.  向`DataManager`添加一个新的方法：

```cs
public void WriteToStream(string filename)
{
    // 1
    if (!File.Exists(filename))
    {
        // 2
        StreamWriter newStream = File.CreateText(filename);

        // 3
        newStream.WriteLine("<Save Data> for HERO BORN \n\n");
        newStream.Close();
        Debug.Log("New file created with StreamWriter!");
    }

    // 4
    StreamWriter streamWriter = File.AppendText(filename);

    // 5
    streamWriter.WriteLine("Game ended: " + DateTime.Now);
    streamWriter.Close();
    Debug.Log("File contents updated with StreamWriter!");
} 
```

1.  删除或注释掉我们在上一节中使用的`Initialize()`中的方法，并添加我们的新代码：

```cs
public void Initialize()
{
    _state = "Data Manager initialized..";
    Debug.Log(_state);

    FilesystemInfo();
    NewDirectory();
    **WriteToStream(_streamingTextFile);**
} 
```

让我们分解上述代码中的新方法：

1.  首先，我们检查文件是否不存在

1.  如果文件尚未创建，我们添加一个名为`newStream`的新`StreamWriter`实例，该实例使用`CreateText()`方法创建和打开新文件

1.  文件打开后，我们使用`WriteLine()`方法添加标题，关闭流，并打印出调试消息

1.  如果文件已经存在，我们只想要更新它，我们通过使用`AppendText()`方法的新`StreamWriter`实例来获取我们的文件，以便我们的现有数据不被覆盖

1.  最后，我们写入游戏数据的新行，关闭流，并打印出调试消息！[](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_12_14.png)

图 12.14：使用流写入和更新文本的控制台消息

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_12_15.png)

图 12.15：使用流创建和更新的新文件

从流中读取几乎与我们在上一节中创建的`ReadFromFile()`方法几乎完全相同。唯一的区别是我们将使用`StreamReader`实例来打开和读取信息。同样，当处理大数据文件或复杂对象时，您希望使用流，而不是使用`File`类手动创建和写入文件：

1.  向`DataManager`添加一个新的方法：

```cs
public void ReadFromStream(string filename)
{
    // 1
    if (!File.Exists(filename))
    {
        Debug.Log("File doesn't exist...");
        return;
    }

    // 2
    StreamReader streamReader = new StreamReader(filename);
    Debug.Log(streamReader.ReadToEnd());
} 
```

1.  在`Initialize()`中调用新方法，并将`_streamingTextFile`作为参数传入：

```cs
public void Initialize()
{
    _state = "Data Manager initialized..";
    Debug.Log(_state);

    FilesystemInfo();
    NewDirectory();
    WriteToStream(_streamingTextFile);
    **ReadFromStream(_streamingTextFile);**
} 
```

让我们分解一下我们的新代码：

1.  首先，我们检查文件是否不存在，如果不存在，我们打印出一个控制台消息并退出方法

1.  如果文件存在，我们使用要访问的文件的名称创建一个新的`StreamReader`实例，并使用`ReadToEnd`方法打印出整个内容！[](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_12_16.png)

图 12.16：控制台打印出从流中读取的保存数据

正如你将开始注意到的，我们的很多代码开始看起来一样。唯一的区别是我们使用流类来进行实际的读写工作。然而，重要的是要记住不同的用例将决定你采取哪种路线。回顾本节开头，了解每种流类型的不同之处。

到目前为止，我们已经介绍了使用文本文件的**CRUD**（**创建**，**读取**，**更新**和**删除**）应用程序的基本功能。但文本文件并不是你在 C#游戏和应用程序中使用的唯一数据格式。一旦你开始使用数据库和自己的复杂数据结构，你可能会看到大量的 XML 和 JSON，这些文本无法比拟的效率和存储。

在下一节中，我们将使用一些基本的 XML 数据，然后讨论一种更容易管理流的方法。

## 创建 XMLWriter

有时候你不只是需要简单的文本来写入和读取文件。你的项目可能需要 XML 格式的文档，这种情况下你需要知道如何使用常规的`FileStream`来保存和加载 XML 数据。

将 XML 数据写入文件并没有太大的不同，与我们之前使用文本和流的方式相似。唯一的区别是我们将显式创建一个`FileStream`并使用它来创建一个`XmlWriter`的实例。将`XmlWriter`类视为一个包装器，它接受我们的数据流，应用 XML 格式，并将我们的信息输出为 XML 文件。一旦我们有了这个，我们可以使用`XmlWriter`类的方法在适当的 XML 格式中构造文档并关闭文件。

你的下一个任务是为新的 XML 文档创建一个文件路径，并使用`DataManager`类的能力来将 XML 数据写入该文件：

1.  在`DataManager`类的顶部添加突出显示的`using`指令：

```cs
using System.Collections;
using System.Collections.Generic;
using UnityEngine;
using System.IO;
using System;
**using** **System.Xml;** 
```

1.  为新的 XML 文件添加一个新的私有字符串路径，并在`Awake()`中设置其值：

```cs
// ... No other variable changes needed ...
**private****string** **_xmlLevelProgress;**
void Awake()
{
     // ... No other changes needed ...
     **_xmlLevelProgress = _dataPath +** **"Progress_Data.xml"****;**
} 
```

1.  在`DataManager`类的底部添加一个新的方法：

```cs
public void WriteToXML(string filename)
{
    // 1
    if (!File.Exists(filename))
    {
        // 2
        FileStream xmlStream = File.Create(filename);

        // 3
        XmlWriter xmlWriter = XmlWriter.Create(xmlStream);

        // 4
        xmlWriter.WriteStartDocument();
        // 5
        xmlWriter.WriteStartElement("level_progress");

        // 6
        for (int i = 1; i < 5; i++)
        {
            xmlWriter.WriteElementString("level", "Level-" + i);
        }

        // 7
        xmlWriter.WriteEndElement();

        // 8
        xmlWriter.Close();
        xmlStream.Close();
    }
} 
```

1.  在`Initialize()`中调用新方法，并传入`_xmlLevelProgress`作为参数：

```cs
public void Initialize()
{
    _state = "Data Manager initialized..";
    Debug.Log(_state);

    FilesystemInfo();
    NewDirectory();
    **WriteToXML(_xmlLevelProgress);**
} 
```

让我们分解一下我们的 XML 写入方法：

1.  首先，我们检查文件是否已经存在

1.  如果文件不存在，我们使用我们创建的新路径变量创建一个新的`FileStream`

1.  然后我们创建一个新的`XmlWriter`实例，并将其传递给我们的新的`FileStream`。

1.  接下来，我们使用`WriteStartDocument`方法指定 XML 版本 1.0

1.  然后我们调用`WriteStartElement`方法添加名为`level_progress`的根元素标签

1.  现在我们可以使用`WriteElementString`方法向我们的文档添加单独的元素，通过使用`for`循环和其索引值`i`传入`level`作为元素标签和级别数字

1.  为了关闭文档，我们使用`WriteEndElement`方法添加一个闭合的`level`标签

1.  最后，我们关闭写入器和流，释放我们一直在使用的流资源

如果现在运行游戏，你会在我们的**Player_Data**文件夹中看到一个新的`.xml`文件，其中包含了级别进度信息：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_12_17.png)

图 12.17：使用文档数据创建的新 XML 文件

你会注意到没有缩进或格式化，这是预期的，因为我们没有指定任何输出格式。在这个例子中，我们不会使用任何输出格式，因为我们将在下一节中讨论一种更有效的写入 XML 数据的方法，即序列化。

你可以在[`docs.microsoft.com/dotnet/api/system.xml.xmlwriter#specifying-the-output-format`](https://docs.microsoft.com/dotnet/api/system.xml.xmlwriter#specifying-the-output-format)找到输出格式属性的列表。

好消息是，读取 XML 文件与读取任何其他文件没有任何区别。您可以在`initialize()`内部调用`readfromfile()`或`readfromstream()`方法，并获得相同的控制台输出：

```cs
public void Initialize()
{
    _state = "Data Manager initialized..";
    Debug.Log(_state);
    FilesystemInfo();
    NewDirectory();
    WriteToXML(_xmlLevelProgress);
    **ReadFromStream(_xmlLevelProgress);**
} 
```

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_12_18.png)

图 12.18：从读取 XML 文件数据的控制台输出

现在我们已经编写了一些使用流的方法，让我们看看如何高效地，更重要的是自动地关闭任何流。

## 自动关闭流

当您使用流时，将它们包装在`using`语句中会通过从我们之前提到的`IDisposable`接口调用`Dispose()`方法来自动关闭流。

这样，您就永远不必担心程序可能会保持打开但未使用的分配资源。

语法几乎与我们已经完成的内容完全相同，只是在行的开头使用`using`关键字，然后在一对括号内引用一个新的流，然后是一组花括号。我们想要流执行的任何操作，比如读取或写入数据，都是在花括号的代码块内完成的。例如，创建一个新的文本文件，就像我们在`WriteToStream()`方法中所做的那样：

```cs
// The new stream is wrapped in a using statement
using(StreamWriter newStream = File.CreateText(filename))
{
     // Any writing functionality goes inside the curly braces
     newStream.WriteLine("<Save Data> for HERO BORN \n");
} 
```

一旦流逻辑在代码块内部，外部的`using`语句将自动关闭流并将分配的资源返回给您的程序。从现在开始，我建议您始终使用这种语法来编写您的流代码。这样更有效率，更安全，并且将展示您对基本资源管理的理解！

随着我们的文本和 XML 流代码的运行，是时候继续前进了。如果你想知道为什么我们没有流传输任何 JSON 数据，那是因为我们需要向我们的数据工具箱中添加一个工具——序列化！

# 序列化数据

当我们谈论序列化和反序列化数据时，我们实际上在谈论翻译。虽然在之前的章节中我们一直在逐步翻译我们的文本和 XML，但能够一次性地将整个对象翻译成另一种格式是一个很好的工具。

根据定义：

+   **序列化**对象的行为是将对象的整个状态转换为另一种格式

+   **反序列化**的行为是相反的，它将数据从文件中恢复到其以前的对象状态

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_12_19.png)

图 12.19：将对象序列化为 XML 和 JSON 的示例

让我们从上面的图像中拿一个实际的例子——我们的`Weapon`类的一个实例。每个武器都有自己的名称和伤害属性以及相关的值，这被称为它的状态。对象的状态是独一无二的，这使得程序可以区分它们。

对象的状态还包括引用类型的属性或字段。例如，如果我们有一个`Character`类，它有一个`Weapon`属性，那么当序列化和反序列化时，C#仍然会识别武器的`name`和`damage`属性。您可能会在编程世界中听到具有引用属性的对象被称为对象图。

在我们开始之前，值得注意的是，如果您没有密切关注确保对象属性与文件中的数据匹配，反之亦然，那么序列化对象可能会很棘手。例如，如果您的类对象属性与正在反序列化的数据不匹配，序列化程序将返回一个空对象。当我们尝试在本章后面将 C#列表序列化为 JSON 时，我们将更详细地介绍这一点。

为了真正掌握这一点，让我们以我们的`Weapon`示例并将其转换为可工作的代码。

## 序列化和反序列化 XML

本章剩下的任务是将武器列表序列化和反序列化为 XML 和 JSON，首先是 XML！

1.  在`DataManager`类的顶部添加一个新的`using`指令：

```cs
using System.Collections;
using System.Collections.Generic;
using UnityEngine;
using System.IO;
using System;
using System.Xml;
**using** **System.Xml.Serialization;** 
```

1.  向`Weapon`类添加一个可序列化的属性，以便 Unity 和 C#知道该对象可以被序列化：

```cs
**[****Serializable****]**
public struct Weapon
{
    // ... No other changes needed ...
} 
```

1.  添加两个新变量，一个用于 XML 文件路径，一个用于武器列表：

```cs
// ... No other variable changes needed ...
**private****string** **_xmlWeapons;**
**private** **List<Weapon> weaponInventory =** **new** **List<Weapon>**
**{**
    **new** **Weapon(****"Sword of Doom"****,** **100****),**
    **new** **Weapon(****"Butterfly knives"****,** **25****),**
    **new** **Weapon(****"Brass Knuckles"****,** **15****),**
**};** 
```

1.  在`Awake`中设置 XML 文件路径值：

```cs
void Awake()
{
    // ... No other changes needed ...
    **_xmlWeapons = _dataPath +** **"WeaponInventory.xml"****;**
} 
```

1.  在`DataManager`类的底部添加一个新方法：

```cs
public void SerializeXML()
{
    // 1
    var xmlSerializer = new XmlSerializer(typeof(List<Weapon>));

    // 2
    using(FileStream stream = File.Create(_xmlWeapons))
    {
        // 3
        xmlSerializer.Serialize(stream, weaponInventory);
    }
} 
```

1.  在`Initialize`中调用新方法：

```cs
public void Initialize()
{
    _state = "Data Manager initialized..";
    Debug.Log(_state);

    FilesystemInfo();
    NewDirectory();
    **SerializeXML();**
} 
```

让我们来分解我们的新方法：

1.  首先，我们创建一个`XmlSerializer`实例，并传入我们要翻译的数据类型。在这种情况下，`weaponInventory`的类型是`List<Weapon>`，这是我们在`typeof`运算符中使用的类型：

+   `XmlSerializer`类是另一个有用的格式包装器，就像我们之前使用的`XmlWriter`类一样

1.  然后，我们使用`FileStream`创建一个`_xmlWeapons`文件路径，并包装在`using`代码块中以确保它被正确关闭。

1.  最后，我们调用`Serialize()`方法，并传入流和我们想要翻译的数据。

再次运行游戏，并查看我们创建的新 XML 文档，而无需指定任何额外的格式！

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_12_20.png)

图 12.20：武器清单文件中的 XML 输出

要将我们的 XML 读回武器列表，我们几乎设置了完全相同的一切，只是我们使用了`XmlSerializer`类的`Deserialize()`方法：

1.  在`DataManager`类的底部添加以下方法：

```cs
public void DeserializeXML()
{
    // 1
    if (File.Exists(_xmlWeapons))
    {
        // 2
        var xmlSerializer = new XmlSerializer(typeof(List<Weapon>));

        // 3
        using (FileStream stream = File.OpenRead(_xmlWeapons))
        {
           // 4
            var weapons = (List<Weapon>)xmlSerializer.Deserialize(stream);

           // 5
           foreach (var weapon in weapons)
           {
               Debug.LogFormat("Weapon: {0} - Damage: {1}", 
                 weapon.name, weapon.damage);
           }
        }
    }
} 
```

1.  在`Initialize`中调用新方法，并将`_xmlWeapons`作为参数传入：

```cs
public void Initialize()
{
    _state = "Data Manager initialized..";
    Debug.Log(_state);

    FilesystemInfo();
    NewDirectory();
    SerializeXML();
    **DeserializeXML();**
} 
```

让我们来分解`deserialize()`方法：

1.  首先，我们检查文件是否存在

1.  如果文件存在，我们创建一个`XmlSerializer`对象，并指定我们将把 XML 数据放回`List<Weapon>`对象中

1.  然后，我们用`FileStream`打开`_xmlWeapons`文件名：

+   我们使用`File.OpenRead()`来指定我们要打开文件进行读取，而不是写入

1.  接下来，我们创建一个变量来保存我们反序列化的武器列表：

+   我们在`Deserialize()`调用前放置了显式的`List<Weapon>`转换，以便我们从序列化程序中获得正确的类型

1.  最后，我们使用`foreach`循环在控制台中打印出每个武器的名称和伤害值

当您再次运行游戏时，您会看到我们从 XML 列表中反序列化的每个武器都会得到一个控制台消息。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_12_21.png)

图 12.21：从反序列化 XML 中的控制台输出

这就是我们对 XML 数据所需做的一切，但在我们完成本章之前，我们仍然需要学习如何处理 JSON！

## 序列化和反序列化 JSON

在序列化和反序列化 JSON 方面，Unity 和 C#并不完全同步。基本上，C#有自己的`JsonSerializer`类，它的工作方式与我们在先前示例中使用的`XmlSerializer`类完全相同。

为了访问 JSON 序列化程序，您需要`System.Text.Json`的`using`指令。这就是问题所在——Unity 不支持该命名空间。相反，Unity 使用`System.Text`命名空间，并实现了自己的 JSON 序列化程序类`JsonUtility`。

因为我们的项目在 Unity 中，我们将使用 Unity 支持的序列化类。但是，如果您正在使用非 Unity 的 C#项目，概念与我们刚刚编写的 XML 代码相同。

您可以在[`docs.microsoft.com/en-us/dotnet/standard/serialization/system-text-json-how-to#how-to-write-net-objects-as-json-serialize`](https://docs.microsoft.com/en-us/dotnet/standard/serialization/system-text-json-how-to#how-to-write-net-objects-as-json-serialize)找到包含来自 Microsoft 的完整操作指南和代码。

您的下一个任务是序列化单个武器，以熟悉`JsonUtility`类：

1.  在`DataManager`类的顶部添加一个新的`using`指令：

```cs
using System.Collections;
using System.Collections.Generic;
using UnityEngine;
using System.IO;
using System;
using System.Xml;
using System.Xml.Serialization;
**using** **System.Text;** 
```

1.  为新的 XML 文件添加一个私有字符串路径，并在`Awake()`中设置其值：

```cs
**private****string** **_jsonWeapons;**
void Awake()
{
    **_jsonWeapons = _dataPath +** **"WeaponJSON.json"****;**
} 
```

1.  在`DataManager`类的底部添加一个新方法：

```cs
public void SerializeJSON()
{
    // 1
    Weapon sword = new Weapon("Sword of Doom", 100);
    // 2
    string jsonString = JsonUtility.ToJson(sword, true);

    // 3
    using(StreamWriter stream = File.CreateText(_jsonWeapons))
    {
        // 4
        stream.WriteLine(jsonString);
    }
} 
```

1.  在`Initialize()`中调用新方法，并将`_jsonWeapons`作为参数传入：

```cs
public void Initialize()
{
    _state = "Data Manager initialized..";
    Debug.Log(_state);

    FilesystemInfo();
    NewDirectory();
    **SerializeJSON();**
} 
```

这是序列化方法的分解：

1.  首先，我们需要一个要处理的武器，因此我们使用我们的类初始化器创建一个

1.  然后，我们声明一个变量来保存格式化为字符串的翻译 JSON 数据，并调用`ToJson()`方法：

+   我们正在使用的`ToJson()`方法接受我们要序列化的`sword`对象和一个布尔值`true`，以便字符串以正确的缩进方式漂亮打印。如果我们没有指定`true`值，JSON 仍然会打印出来，只是一个常规字符串，不容易阅读。

1.  现在我们有一个要写入文件的文本字符串，我们创建一个`StreamWriter`流，并传入`_jsonWeapons`文件名

1.  最后，我们使用`WriteLine()`方法，并将`jsonString`值传递给它以写入文件。

运行程序并查看我们创建并写入数据的新 JSON 文件！

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_12_22.png)

图 12.22：序列化武器属性的 JSON 文件

现在让我们尝试序列化我们在 XML 示例中使用的武器列表，看看会发生什么。

更新`SerializeJSON()`方法，使用现有的武器列表而不是单个`sword`实例：

```cs
public void SerializeJSON()
{
    string jsonString = JsonUtility.ToJson(**weaponInventory,** true);

    using(StreamWriter stream = 
      File.CreateText(_jsonWeapons))
    {
        stream.WriteLine(jsonString);
    }
} 
```

当你再次运行游戏时，你会看到 JSON 文件数据被覆盖，我们最终得到的只是一个空数组：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_12_23.png)

图 12.23：序列化后为空对象的 JSON 文件

这是因为 Unity 处理 JSON 序列化的方式不支持单独的列表或数组。任何列表或数组都需要作为类对象的一部分，以便 Unity 的`JsonUtility`类能够正确识别和处理它。

不要惊慌，如果我们考虑一下，这是一个相当直观的修复方法——我们只需要创建一个具有武器列表属性的类，并在将数据序列化为 JSON 时使用它！

1.  打开`Weapon.cs`并在文件底部添加以下可序列化的`WeaponShop`类。一定要小心将新类放在`Weapon`类花括号之外：

```cs
[Serializable]
public class WeaponShop
{
    public List<Weapon> inventory;
} 
```

1.  在`DataManager`类中，使用以下代码更新`SerializeJSON()`方法：

```cs
public void SerializeJSON()
{
    // 1
    **WeaponShop shop =** **new** **WeaponShop();**
    **// 2**
    **shop.inventory = weaponInventory;**

    // 3
    string jsonString = JsonUtility.ToJson(**shop**, true);

    using(StreamWriter stream = File.CreateText(_jsonWeapons))
    {
        stream.WriteLine(jsonString);
    }
} 
```

让我们来分解刚刚做的更改：

1.  首先，我们创建一个名为`shop`的新变量，它是`WeaponShop`类的一个实例

1.  然后，我们将“库存”属性设置为我们已经声明的武器列表`weaponInventory`

1.  最后，我们将`shop`对象传递给`ToJson()`方法，并将新的字符串数据写入 JSON 文件

再次运行游戏，并查看我们创建的漂亮打印的武器列表：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_12_24.png)

图 12.24：列表对象正确序列化为 JSON

将 JSON 文本反序列化为对象是刚才所做的过程的逆过程：

1.  在`DataManager`类的底部添加一个新方法：

```cs
public void DeserializeJSON()
{
    // 1
    if(File.Exists(_jsonWeapons))
    {
        // 2
        using (StreamReader stream = new StreamReader(_jsonWeapons))
        {
            // 3
            var jsonString = stream.ReadToEnd();

            // 4
            var weaponData = JsonUtility.FromJson<WeaponShop>
              (jsonString);

            // 5
            foreach (var weapon in weaponData.inventory)
            {
                Debug.LogFormat("Weapon: {0} - Damage: {1}", 
                  weapon.name, weapon.damage);
            }
        }
    }
} 
```

1.  在`Initialize()`中调用新方法，并将`_jsonWeapons`作为参数传递：

```cs
public void Initialize()
{
    _state = "Data Manager initialized..";
    Debug.Log(_state);

    FilesystemInfo();
    NewDirectory();
    SerializeJSON();
    **DeserializeJSON();**
} 
```

让我们来分解下面的`DeserializeJSON()`方法：

1.  首先，我们检查文件是否存在

1.  如果存在，我们创建一个包装在`using`代码块中的`_jsonWeapons`文件路径的流

1.  然后，我们使用流的`ReadToEnd()`方法从文件中获取整个 JSON 文本

1.  接下来，我们创建一个变量来保存我们反序列化的武器列表，并调用`FromJson()`方法：

+   请注意，在传入 JSON 字符串变量之前，我们指定要将我们的 JSON 转换为`WeaponShop`对象的`<WeaponShop>`语法

1.  最后，我们循环遍历武器商店的“库存”列表属性，并在控制台中打印出每个武器的名称和伤害值

再次运行游戏，你会看到我们的 JSON 数据中为每个武器打印出一个控制台消息：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_12_25.png)

图 12.25：反序列化 JSON 对象列表的控制台输出

# 数据汇总

本章中涵盖的每个单独的模块和主题都可以单独使用，也可以组合使用以满足项目的需求。例如，您可以使用文本文件存储角色对话，并且只在需要时加载它。这比游戏每次运行时都跟踪它更有效，即使信息没有被使用。

你也可以将角色数据或敌人统计数据放入 XML 或 JSON 文件中，并在需要升级角色或生成新怪物时从文件中读取。最后，你可以从第三方数据库中获取数据并将其序列化为你自己的自定义类。这在存储玩家账户和外部游戏数据时非常常见。

你可以在[`docs.microsoft.com/en-us/dotnet/framework/wcf/feature-details/types-supported-by-the-data-contract-serializer`](https://docs.microsoft.com/en-us/dotnet/framework/wcf/feature-details/types-supported-by-the-data-contract-serializer)找到 C#中可以序列化的数据类型列表。Unity 处理序列化的方式略有不同，所以确保你在[`docs.unity3d.com/ScriptReference/SerializeField.html`](https://docs.unity3d.com/ScriptReference/SerializeField.html)上检查可用的类型。

我想要表达的是，数据无处不在，你的工作就是创建一个能够按照你的游戏需求处理数据的系统，一步一步地构建。

# 总结

关于处理数据的基础知识就介绍到这里了！恭喜你成功地完成了这一庞大的章节。在任何编程环境中，数据都是一个重要的话题，所以把这一章学到的东西当作一个起点。

你已经知道如何浏览文件系统，创建、读取、更新和删除文件。你还学会了如何有效地处理文本、XML 和 JSON 数据格式，以及数据流。你知道如何将整个对象的状态序列化或反序列化为 XML 和 JSON。总的来说，学习这些技能并不是一件小事。不要忘记多次复习和重温这一章；这里有很多东西可能不会在第一次阅读时变得很熟悉。

在下一章中，我们将讨论泛型编程的基础知识，获得一些关于委托和事件的实践经验，并最后概述异常处理。

# 快速测验-数据管理

1.  哪个命名空间让你可以访问`Path`和`Directory`类？

1.  在 Unity 中，你使用什么文件夹路径来在游戏运行之间保存数据？

1.  `Stream`对象使用什么数据类型来读写文件中的信息？

1.  当你将一个对象序列化为 JSON 时会发生什么？

# 加入我们的 Discord！

与其他用户、Unity/C#专家和 Harrison Ferrone 一起阅读本书。提出问题，为其他读者提供解决方案，通过*问我任何事*会话与作者交流，以及更多。

立即加入！

[`packt.link/csharpunity2021`](https://packt.link/csharpunity2021)

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/QR_Code_9781801813945.png)


# 第十三章：探索通用、委托和更多

你在编程中花费的时间越多，你就会开始思考系统。构建类和对象如何相互交互、通信和交换数据，这些都是我们迄今为止所使用的系统的例子；现在的问题是如何使它们更安全、更高效。

由于这将是本书的最后一个实用章节，我们将介绍通用编程概念、委托、事件创建和错误处理的示例。每个主题都是一个独立的大领域，所以在你的项目中学到的东西，可以进一步扩展。在完成我们的实际编码后，我们将简要概述设计模式以及它们在你未来编程之旅中的作用。

在本章中，我们将涵盖以下主题：

+   通用编程

+   使用委托

+   创建事件和订阅

+   抛出和处理错误

+   理解设计模式

# 介绍通用

到目前为止，我们的所有代码在定义和使用类型方面都非常具体。然而，会有一些情况，你需要一个类或方法以相同的方式处理其实体，而不管其类型，同时仍然是类型安全的。通用编程允许我们使用占位符而不是具体类型来创建可重用的类、方法和变量。

当在编译时创建通用类实例或使用方法时，将分配一个具体类型，但代码本身将其视为通用类型。能够编写通用代码是一个巨大的好处，当你需要以相同的方式处理不同的对象类型时，例如需要能够对元素执行相同操作的自定义集合类型，或者需要相同底层功能的类。虽然你可能会问为什么我们不只是子类化或使用接口，但在我们的例子中，你会看到通用类以不同的方式帮助我们。

我们已经在`List`类型中看到了这一点，它是一种通用类型。无论它存储整数、字符串还是单个字符，我们都可以访问它的所有添加、删除和修改函数。

## 通用对象

创建通用类的方式与创建非通用类的方式相同，但有一个重要的区别：它的通用类型参数。让我们看一个我们可能想要创建的通用集合类的例子，以更清晰地了解它是如何工作的：

```cs
public class SomeGenericCollection**<****T****>** {} 
```

我们声明了一个名为`SomeGenericCollection`的通用集合类，并指定其类型参数将被命名为`T`。现在，`T`将代表通用列表将存储的元素类型，并且可以在通用类内部像任何其他类型一样使用。

每当我们创建一个`SomeGenericCollection`的实例时，我们需要指定它可以存储的值的类型：

```cs
SomeGenericCollection**<****int****>** highScores = new SomeGenericCollection<int>(); 
```

在这种情况下，`highScores`存储整数值，`T`代表`int`类型，但`SomeGenericCollection`类将以相同的方式处理任何元素类型。

你完全可以控制通用类型参数的命名，但在许多编程语言中，行业标准是使用大写的`T`。如果你要为你的类型参数命名不同的名称，考虑以大写的`T`开头以保持一致性和可读性。

让我们接下来创建一个更加游戏化的例子，使用通用的`Shop`类来存储一些虚构的库存物品，具体步骤如下：

1.  在`Scripts`文件夹中创建一个新的 C#脚本，命名为`Shop`，并将其代码更新为以下内容：

```cs
using System.Collections;
using System.Collections.Generic;
using UnityEngine;

// 1
public class Shop<T>
{
    // 2
    public List<T> inventory = new List<T>();
} 
```

1.  在`GameBehavior`中创建一个`Shop`的新实例：

```cs
public class GameBehavior : MonoBehaviour, IManager
{
    // ... No other changes needed ...

    public void Initialize()
    {
        // 3
        var itemShop = new Shop<string>();
        // 4
        Debug.Log("There are " + itemShop.inventory.Count + " items for sale.");
    }
} 
```

让我们来分解一下代码：

1.  声明一个名为`IShop`的新通用类，带有`T`类型参数

1.  添加一个类型为`T`的库存`List<T>`，用于存储我们用通用类初始化的任何物品类型

1.  在`GameBehavior`中创建一个`Shop<string>`的新实例，并指定字符串值作为通用类型

1.  打印出一个带有库存计数的调试消息：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_13_01.png)

图 13.1：来自泛型类的控制台输出

在功能方面还没有发生任何新的事情，但是 Visual Studio 因为其泛型类型参数`T`而将`Shop`识别为泛型类。这使我们能够包括其他泛型操作，如添加库存项目或查找每种项目的数量。

值得注意的是，Unity Serializer 默认不支持泛型。如果要序列化泛型类，就像我们在上一章中对自定义类所做的那样，您需要在类的顶部添加`Serializable`属性，就像我们在`Weapon`类中所做的那样。您可以在[`docs.unity3d.com/ScriptReference/SerializeReference.html`](https://docs.unity3d.com/ScriptReference/SerializeReference.html)找到更多信息。

## 泛型方法

一个独立的泛型方法可以有一个占位符类型参数，就像一个泛型类一样，这使它可以根据需要包含在泛型或非泛型类中：

```cs
public void GenericMethod**<****T****>**(**T** genericParameter) {} 
```

`T`类型可以在方法体内使用，并在调用方法时定义：

```cs
GenericMethod**<****string****>(****"Hello World!"****)**; 
```

如果要在泛型类中声明泛型方法，则不需要指定新的`T`类型：

```cs
public class SomeGenericCollection<T> 
{
    public void NonGenericMethod(**T** genericParameter) {}
} 
```

当调用使用泛型类型参数的非泛型方法时，没有问题，因为泛型类已经处理了分配具体类型的问题：

```cs
SomeGenericCollection**<****int****>** highScores = new SomeGenericCollection
<int> ();
highScores.NonGenericMethod(**35**); 
```

泛型方法可以被重载并标记为静态，就像非泛型方法一样。如果您想要这些情况的具体语法，请查看[`docs.microsoft.com/en-us/dotnet/csharp/programming-guide/generics/generic-methods`](https://docs.microsoft.com/en-us/dotnet/csharp/programming-guide/generics/generic-methods)。

您的下一个任务是创建一个方法，将新的泛型项目添加到库存，并在`GameBehavior`脚本中使用它。

由于我们已经有了一个具有定义类型参数的泛型类，让我们添加一个非泛型方法来看它们如何一起工作：

1.  打开`Shop`并按以下方式更新代码：

```cs
public class Shop<T>
{
    public List<T> inventory = new List<T>();
    **// 1**
    **public****void****AddItem****(****T newItem****)**
    **{**

        **inventory.Add(newItem);**
    **}**
} 
```

1.  进入`GameBehavior`并向`itemShop`添加一个项目：

```cs
public class GameBehavior : MonoBehaviour, IManager
{
    // ... No other changes needed ...

     public void Initialize()
    {
        var itemShop = new Shop<string>();
        **// 2**
        itemShop**.AddItem(****"Potion"****);**
        itemShop**.AddItem(****"Antidote"****);**
       Debug.Log("There are " + itemShop.inventory.Count + " items for sale.");
    }
} 
```

让我们来分解代码：

1.  声明一个添加`newItems`的类型`T`到库存的方法

1.  使用`AddItem()`向`itemShop`添加两个字符串项目，并打印出调试日志：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_13_02.png)

图 13.2：向泛型类添加项目后的控制台输出

我们编写了`AddItem()`以接受与我们的泛型`Shop`实例相同类型的参数。由于`itemShop`被创建为保存字符串值，我们可以毫无问题地添加`"Potion"`和`"Antidote"`字符串值。

然而，如果尝试添加一个整数，例如，您将收到一个错误，指出`itemShop`的泛型类型不匹配：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_13_03.png)

图 13.3：泛型类中的转换错误

现在，您已经编写了一个泛型方法，需要知道如何在单个类中使用多个泛型类型。例如，如果我们想要向`Shop`类添加一个方法，找出库存中有多少个给定项目？我们不能再次使用类型`T`，因为它已经在类定义中定义了。那么我们该怎么办呢？

将以下方法添加到`Shop`类的底部：

```cs
// 1
public int GetStockCount<U>()
{
    // 2
    var stock = 0;
    // 3
    foreach (var item in inventory)
    {
        if (item is U)
        {
            stock++;
        }
    }
    // 4
    return stock;
} 
```

让我们来分解我们的新方法：

1.  声明一个方法，返回我们在库存中找到的类型`U`的匹配项目的 int 值

+   泛型类型参数的命名完全取决于您，就像命名变量一样。按照惯例，它们从`T`开始，然后按字母顺序继续。

1.  创建一个变量来保存我们找到的匹配库存项目的数量，并最终从库存中返回

1.  使用`foreach`循环遍历库存列表，并在找到匹配时增加库存值

1.  返回匹配库存项目的数量

问题在于我们在商店中存储字符串值，因此如果我们尝试查找我们有多少字符串项目，我们将得到完整的库存：

```cs
Debug.Log("There are " + itemShop.GetStockCount<string>() + " items for sale."); 
```

这将在控制台上打印出类似以下内容：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_13_04.png)

图 13.4：使用多个泛型字符串类型的控制台输出

另一方面，如果我们试图在我们的库存中查找整数类型，我们将得不到结果，因为我们只存储字符串：

```cs
Debug.Log("There are " + itemShop.GetStockCount<int>() + " items for sale."); 
```

这将在控制台上打印类似以下内容：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_13_05.png)

图 13.5：使用多个不匹配的泛型类型的控制台输出

这两种情况都不理想，因为我们无法确保我们的商店库存既存储又可以搜索相同的物品类型。但这就是泛型真正发挥作用的地方——我们可以为我们的泛型类和方法添加规则，以强制执行我们想要的行为，我们将在下一节中介绍。

## 约束类型参数

泛型的一大优点是它们的类型参数可以受限制。这可能与我们迄今为止学到的有所矛盾，但只是因为一个类*可以*包含任何类型，并不意味着应该允许它这样做。

为了约束泛型类型参数，我们需要一个新关键字和一个我们以前没有见过的语法：

```cs
public class SomeGenericCollection<T> where T: ConstraintType {} 
```

`where`关键字定义了`T`必须通过的规则，然后才能用作泛型类型参数。它基本上说`SomeGenericClass`可以接受任何`T`类型，只要它符合约束类型。约束规则并不神秘或可怕；它们是我们已经涵盖的概念：

+   添加`class`关键字将限制`T`为类类型

+   添加`struct`关键字将限制`T`为结构类型

+   添加接口，如`IManager`，作为类型将限制`T`为采用该接口的类型

+   添加自定义类，如`Character`，将限制`T`仅为该类类型

如果您需要更灵活的方法来考虑具有子类的类，您可以使用`where T：U`，它指定泛型`T`类型必须是`U`类型或派生自`U`类型。这对我们的需求来说有点高级，但您可以在[`docs.microsoft.com/en-us/dotnet/csharp/programming-guide/generics/constraints-on-type-parameters`](https://docs.microsoft.com/en-us/dotnet/csharp/programming-guide/generics/constraints-on-type-parameters)找到更多详细信息。

只是为了好玩，让我们将`Shop`限制为只接受一个名为`Collectable`的新类型：

1.  在`Scripts`文件夹中创建一个新脚本，命名为`Collectable`，并添加以下代码：

```cs
using System.Collections;
using System.Collections.Generic;
using UnityEngine;

public class Collectable
{
    public string name;
}

public class Potion : Collectable
{
    public Potion()
    {
        this.name = "Potion";
    }
}

public class Antidote : Collectable
{
    public Antidote()
    {
        this.name = "Antidote";
    }
} 
```

我们在这里所做的只是声明一个名为`Collectable`的新类，具有一个名称属性，并为药水和解毒剂创建了子类。有了这个结构，我们可以强制我们的`Shop`只接受`Collectable`类型，并且我们的库存查找方法也只接受`Collectable`类型，这样我们就可以比较它们并找到匹配项。

1.  打开`Shop`并更新类声明：

```cs
public class Shop<T> **where****T** **:** **Collectable** 
```

1.  更新`GetStockCount()`方法以将`U`约束为与初始泛型`T`类型相等：

```cs
public int GetStockCount<U>() **where** **U : T**
{
    var stock = 0;
    foreach (var item in inventory)
    {
        if (item is U)
        {
            stock++;
        }
    }
    return stock;
} 
```

1.  在`GameBehavior`中，将`itemShop`实例更新为以下代码：

```cs
var itemShop = new Shop<**Collectable**>();
itemShop.AddItem(**new** **Potion()**);
itemShop.AddItem(**new** **Antidote()**);
Debug.Log("There are " + itemShop.GetStockCount<**Potion**>() + " items for sale."); 
```

这将导致类似以下的输出：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_13_12.png)

图 13.6：更新后的 GameBehavior 脚本输出

在我们的示例中，我们可以确保只有可收集类型被允许在我们的商店中。如果我们在代码中意外地尝试添加不可收集类型，Visual Studio 将警告我们尝试违反我们自己的规则！

## 向 Unity 对象添加泛型

泛型也适用于 Unity 脚本和游戏对象。例如，我们可以轻松地创建一个通用的可销毁类，用于删除场景中的任何`MonoBehaviour`或对象`Component`。如果这听起来很熟悉，那就是我们的`BulletBehavior`为我们做的事情，但它不适用于除该脚本之外的任何东西。为了使其更具可扩展性，让我们使任何从`MonoBehaviour`继承的脚本都可销毁。

1.  在`Scripts`文件夹中创建一个新脚本，命名为`Destroyable`，并添加以下代码：

```cs
using System.Collections;
using System.Collections.Generic;
using UnityEngine;

public class Destroyable<T> : MonoBehaviour where T : MonoBehaviour
{
    public int OnscreenDelay;

    void Start()
    {
        Destroy(this.gameObject, OnscreenDelay);
    }
} 
```

1.  删除`BulletBehavior`中的所有代码，并继承自新的通用类：

```cs
public class BulletBehavior : **Destroyable****<****BulletBehavior****>**
{
} 
```

现在，我们已经将我们的`BulletBehavior`脚本转换为通用的可销毁对象。在 Bullet Prefab 中没有任何更改，但我们可以通过从通用的`Destroyable`类继承来使任何其他对象可销毁。在我们的示例中，如果我们创建了多个抛射物 Prefab 并希望它们都在不同的时间被销毁，那么这将提高代码效率和可重用性。

通用编程是我们工具箱中的一个强大工具，但是在掌握了基础知识之后，是时候谈谈编程旅程中同样重要的一个主题——委托了！

# 委托操作

有时您需要将一个文件中的方法执行委托给另一个文件。在 C#中，可以通过委托类型来实现这一点，它存储对方法的引用，并且可以像任何其他变量一样对待。唯一的限制是委托本身和任何分配的方法都需要具有相同的签名——就像整数变量只能保存整数和字符串只能保存文本一样。

创建委托是编写函数和声明变量的混合： 

```cs
public **delegate** returnType DelegateName(int param1, string param2); 
```

您首先使用访问修饰符，然后是`delegate`关键字，这将其标识为`delegate`类型。`delegate`类型可以像常规函数一样具有返回类型和名称，如果需要还可以有参数。但是，这种语法只是声明了`delegate`类型本身；要使用它，您需要像使用类一样创建一个实例：

```cs
public **DelegateName** someDelegate; 
```

声明了一个`delegate`类型变量后，很容易分配一个与委托签名匹配的方法：

```cs
public DelegateName someDelegate = **MatchingMethod**;
public void **MatchingMethod****(****int** **param1,** **string** **param2****)** 
{
    // ... Executing code here ...
} 
```

请注意，在将`MatchingMethod`分配给`someDelegate`变量时，不要包括括号，因为此时并不是在调用该方法。它所做的是将`MatchingMethod`的调用责任委托给`someDelegate`，这意味着我们可以如下调用该函数：

```cs
someDelegate(); 
```

在您的 C#技能发展到这一点时，这可能看起来很麻烦，但我向您保证，能够将方法存储和执行为变量将在未来派上用场。

## 创建一个调试委托

让我们创建一个简单的委托类型来定义一个接受字符串并最终使用分配的方法打印它的方法。打开`GameBehavior`并添加以下代码：

```cs
public class GameBehavior : MonoBehaviour, IManager
{
    // ... No other changes needed ...

    **// 1**
    **public****delegate****void****DebugDelegate****(****string** **newText****)****;**

    **// 2**
    **public** **DebugDelegate debug = Print;**

    public void Initialize() 
    {
        _state = "Game Manager initialized..";
        _state.FancyDebug();
        **// 3**
        **debug(_state);**
   // ... No changes needed ...
    }
    **// 4**
    **public****static****void****Print****(****string** **newText****)**
    **{**
        **Debug.Log(newText);**
    **}**
} 
```

让我们分解一下代码：

1.  声明一个名为`DebugDelegate`的`public delegate`类型，用于保存一个接受`string`参数并返回`void`的方法

1.  创建一个名为`debug`的新`DebugDelegate`实例，并为其分配一个具有匹配签名的方法`Print()`

1.  用`debug`委托实例替换`Initialize()`中的`Debug.Log(_state)`代码

1.  声明`Print()`为一个接受`string`参数并将其记录到控制台的`static`方法

图 13.7：委托操作的控制台输出

控制台中没有任何变化，但是现在`Initialize()`中不再直接调用`Debug.Log()`，而是将该操作委托给了`debug`委托实例。虽然这是一个简单的例子，但是当您需要存储、传递和执行方法作为它们的类型时，委托是一个强大的工具。

在 Unity 中，我们已经通过使用`OnCollisionEnter()`和`OnCollisionExit()`方法来处理委托的示例，这些方法是通过委托调用的。在现实世界中，自定义委托在与事件配对时最有用，我们将在本章的后面部分看到。

## 委托作为参数类型

既然我们已经看到如何创建委托类型来存储方法，那么委托类型本身也可以作为方法参数使用就是合情合理的。这与我们已经做过的并没有太大的不同，但是涵盖基础知识是个好主意。

让我们看看委托类型如何作为方法参数使用。使用以下代码更新`GameBehavior`：

```cs
public class GameBehavior : MonoBehaviour, IManager
{
    // ... No changes needed ...
    public void Initialize() 
    {
        _state = "Game Manager initialized..";
        _state.FancyDebug();
        debug(_state);
        **// 1**
        **LogWithDelegate(debug);**
    }
    **// 2**
    **public****void****LogWithDelegate****(****DebugDelegate del****)**
    **{**
        **// 3**
        **del(****"Delegating the debug task..."****);**
    **}**
} 
```

让我们分解一下代码：

1.  调用`LogWithDelegate()`并将我们的`debug`变量作为其类型参数传递

1.  声明一个新的方法，接受`DebugDelegate`类型的参数

1.  调用委托参数的函数，并传入一个字符串文字以打印出来：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_13_07.png)

图 13.8：委托作为参数类型的控制台输出

我们创建了一个接受`DebugDelegate`类型参数的方法，这意味着传入的实际参数将表示一个方法，并且可以被视为一个方法。将这个例子视为一个委托链，其中`LogWithDelegate()`距离实际进行调试的方法`Print()`有两个步骤。创建这样的委托链并不总是在游戏或应用程序场景中常见的解决方案，但是当您需要控制委托级别时，了解涉及的语法是很重要的。在涉及到委托链跨多个脚本或类的情况下，这一点尤为重要。

如果您错过了重要的心理联系，很容易在委托中迷失，所以回到本节开头的代码并查看文档：[`docs.microsoft.com/en-us/dotnet/csharp/programming-guide/delegates/`](https://docs.microsoft.com/en-us/dotnet/csharp/programming-guide/delegates/)。

现在您知道如何处理基本委托了，是时候谈谈事件如何用于在多个脚本之间高效地传递信息了。老实说，委托的最佳用例是与事件配对使用，接下来我们将深入探讨。

# 触发事件

C#事件允许您基本上创建一个基于游戏或应用程序中的操作的订阅系统。例如，如果您想在收集物品时发送事件，或者当玩家按下空格键时，您可以这样做。然而，当事件触发时，并不会自动有一个订阅者或接收者来处理任何需要在事件动作之后执行的代码。

任何类都可以通过调用事件被触发的类来订阅或取消订阅事件；就像在手机上注册接收 Facebook 上分享新帖子通知一样，事件形成了一种分布式信息高速公路，用于在应用程序中共享操作和数据。

声明事件类似于声明委托，因为事件具有特定的方法签名。我们将使用委托来指定我们希望事件具有的方法签名，然后使用`delegate`类型和`event`关键字创建事件：

```cs
public delegate void EventDelegate(int param1, string param2);
public **event** EventDelegate eventInstance; 
```

这个设置允许我们将`eventInstance`视为一个方法，因为它是一个委托类型，这意味着我们可以随时调用它来发送它：

```cs
eventInstance(35, "John Doe"); 
```

你的下一个任务是在`PlayerBehavior`内部创建一个自己的事件并在适当的位置触发它。

## 创建和调用事件

让我们创建一个事件，以便在玩家跳跃时触发。打开`PlayerBehavior`并添加以下更改：

```cs
public class PlayerBehavior : MonoBehaviour 
{
    // ... No other variable changes needed ...
    **// 1**
    **public****delegate****void****JumpingEvent****()****;**
    **// 2**
    **public****event** **JumpingEvent playerJump;**
    void Start()
    {
        // ... No changes needed ...
    }
    void Update() 
    {
        // ... No changes needed ...
;
    }
    void FixedUpdate()
    {
        if(IsGrounded() &&  _isJumping)
        {
            _rb.AddForce(Vector3.up * jumpVelocity,
               ForceMode.Impulse);
            **// 3**
            **playerJump();**
        }
    }
    // ... No changes needed in IsGrounded or OnCollisionEnter
} 
```

让我们来分解一下代码：

1.  声明一个返回`void`并且不带任何参数的新`delegate`类型

1.  创建一个`JumpingEvent`类型的事件，名为`playerJump`，可以被视为一个方法，与前面的委托的`void`返回和无参数签名相匹配

1.  在`Update()`中施加力后调用`playerJump`

我们已成功创建了一个简单的委托类型，它不带任何参数并且不返回任何内容，以及一个该类型的事件，以便在玩家跳跃时执行。每次玩家跳跃时，`playerJump`事件都会发送给所有订阅者，通知它们该操作。

事件触发后，由订阅者来处理它并执行任何额外的操作，我们将在*处理事件订阅*部分中看到。

## 处理事件订阅

现在，我们的`playerJump`事件没有订阅者，但更改很简单，非常类似于我们在上一节中将方法引用分配给委托类型的方式：

```cs
someClass.eventInstance += EventHandler; 
```

由于事件是属于声明它们的类的变量，而订阅者将是其他类，因此需要引用包含事件的类来进行订阅。`+=`运算符用于分配一个方法，当事件执行时将触发该方法，就像设置一个外出邮件一样。与分配委托一样，事件处理程序方法的方法签名必须与事件的类型匹配。在我们之前的语法示例中，这意味着`EventHandler`需要是以下内容：

```cs
public void EventHandler(int param1, string param2) {} 
```

在需要取消订阅事件的情况下，您只需使用`-=`运算符执行分配的相反操作：

```cs
someClass.eventInstance -= EventHandler; 
```

事件订阅通常在类初始化或销毁时处理，这样可以轻松管理多个事件，而不会出现混乱的代码实现。

现在您已经知道了订阅和取消订阅事件的语法，现在轮到您在`GameBehavior`脚本中将其付诸实践了。

现在，我们的事件每次玩家跳跃时都会触发，我们需要一种捕获该动作的方法：

1.  返回到`GameBehavior`并更新以下代码：

```cs
public class GameBehavior : MonoBehaviour, IManager
{
    // 1
    public PlayerBehavior playerBehavior;

    // 2
    void OnEnable()
    {
        // 3
        GameObject player = GameObject.Find("Player");
        // 4
        playerBehavior = player.GetComponent<PlayerBehavior>();
        // 5
        playerBehavior.playerJump += HandlePlayerJump;
        debug("Jump event subscribed...");
    }

    // 6
    public void HandlePlayerJump()
    {
         debug("Player has jumped...");
    **}**
    // ... No other changes ...
} 
```

让我们来分解一下代码：

1.  创建一个`PlayerBehavior`类型的公共变量

1.  声明`OnEnable()`方法，每当附加了脚本的对象在场景中变为活动状态时都会调用该方法

`OnEnable`是`MonoBehaviour`类中的一个方法，因此所有 Unity 脚本都可以访问它。这是一个很好的地方来放置事件订阅，而不是在`Awake`中执行，因为它只在对象活动时执行，而不仅仅是在加载过程中执行。

1.  在场景中查找`Player`对象并将其`GameObject`存储在一个局部变量中

1.  使用`GetComponent()`检索附加到`Player`的`PlayerBehavior`类的引用，并将其存储在`playerBehavior`变量中

1.  使用`+=`运算符订阅了在`PlayerBehavior`中声明的`playerJump`事件，并使用名为`HandlePlayerJump`的方法

1.  声明`HandlePlayerJump()`方法，其签名与事件的类型匹配，并使用调试委托每次接收到事件时记录成功消息！[](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_13_08.png)

图 13.9：委托事件订阅的控制台输出

为了正确订阅和接收`GameBehavior`中的事件，我们必须获取到玩家附加的`PlayerBehavior`类的引用。我们本可以一行代码完成所有操作，但将其拆分开来更加可读。然后，我们分配了一个方法给`playerJump`事件，每当接收到事件时都会执行该方法，并完成订阅过程。

现在每次跳跃时，您都会看到带有事件消息的调试消息：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_13_09.png)

图 13.10：委托事件触发的控制台输出

由于事件订阅是在脚本中配置的，并且脚本附加到 Unity 对象上，我们的工作还没有完成。当对象被销毁或从场景中移除时，我们仍然需要处理如何清理订阅，这将在下一节中介绍。

## 清理事件订阅

即使在我们的原型中，玩家永远不会被销毁，但在游戏中失去玩家是一个常见的特性。清理事件订阅非常重要，因为它们占用了分配的资源，正如我们在*第十二章*“保存、加载和序列化数据”中讨论的流一样。

我们不希望在订阅对象被销毁后仍然保留任何订阅，因此让我们清理一下我们的跳跃事件。在`OnEnable`方法之后，将以下代码添加到`GameBehavior`中：

```cs
// 1
private void OnDisable()
{
    // 2
    playerBehavior.playerJump -= HandlePlayerJump;
    debug("Jump event unsubscribed...");
} 
```

让我们来分解我们的新代码添加：

1.  声明`OnDisable()`方法，它属于`MonoBehavior`类，并且是我们之前使用的`OnEnable()`方法的伴侣

+   您需要编写的任何清理代码通常应该放在这个方法中，因为它在附加了脚本的对象处于非活动状态时执行

1.  使用`-=`运算符取消`HandlePlayerJump`中的`playerJump`事件的订阅，并打印出控制台消息

现在我们的脚本在游戏对象启用和禁用时正确订阅和取消订阅事件，不会在我们的游戏场景中留下未使用的资源。

这就结束了我们对事件的讨论。现在你可以从一个脚本广播它们到游戏的每个角落，并对玩家失去生命、收集物品或更新 UI 等情况做出反应。然而，我们仍然需要讨论一个非常重要的话题，没有它，没有程序能成功，那就是错误处理。

# 处理异常

高效地将错误和异常纳入代码中，是你编程之旅中的专业和个人标杆。在你开始大喊“我花了这么多时间避免错误，为什么要添加错误？！”之前，你应该知道我并不是指添加错误来破坏你现有的代码。相反，包括错误或异常，并在功能部分被错误使用时适当处理它们，会使你的代码库更加强大，更不容易崩溃，而不是更弱。

## 抛出异常

当我们谈论添加错误时，我们将这个过程称为*异常抛出*，这是一个恰当的视觉类比。抛出异常是防御性编程的一部分，这基本上意味着你在代码中积极有意识地防范不当或非计划的操作。为了标记这些情况，你从一个方法中抛出一个异常，然后由调用代码处理。

举个例子：假设我们有一个`if`语句，检查玩家的电子邮件地址是否有效，然后才允许他们注册。如果输入的电子邮件无效，我们希望我们的代码抛出异常：

```cs
public void ValidateEmail(string email)
{
    if(!email.Contains("@"))
    {
        **throw****new** **System.ArgumentException(****"Email is invalid"****);**
    }
} 
```

我们使用`throw`关键字来抛出异常，异常是使用`new`关键字后跟我们指定的异常创建的。`System.ArgumentException()`默认会记录关于异常在何时何地执行的信息，但也可以接受自定义字符串，如果你想更具体。

`ArgumentException`是`Exception`类的子类，并且通过之前显示的`System`类访问。C#带有许多内置的异常类型，包括用于检查空值、超出范围的集合值和无效操作的子类。异常是使用正确的工具来做正确的工作的一个典型例子。我们的例子只需要基本的`ArgumentException`，但你可以在[`docs.microsoft.com/en-us/dotnet/api/system.exception#Standard`](https://docs.microsoft.com/en-us/dotnet/api/system.exception#Standard)找到完整的描述列表。

在我们第一次尝试异常处理时，让事情保持简单，并确保我们只有在提供正的场景索引号时才重新开始关卡：

1.  打开`Utilities`并将以下代码添加到重载版本的`RestartLevel(int)`中：

```cs
public static class Utilities 
{
    // ... No changes needed ...
    public static bool RestartLevel(int sceneIndex) 
    {
        **// 1**
        **if****(sceneIndex <** **0****)**
        **{**
            **// 2**
            **throw****new** **System.ArgumentException(****"Scene index cannot be negative"****);**
         **}**

        Debug.Log("Player deaths: " + PlayerDeaths);
        string message = UpdateDeathCount(ref PlayerDeaths);
        Debug.Log("Player deaths: " + PlayerDeaths);
        Debug.Log(message);

        SceneManager.LoadScene(sceneIndex);
        Time.timeScale = 1.0f;

        return true;
    }
} 
```

1.  在`GameBehavior`中将`RestartLevel()`更改为接受负场景索引并且输掉游戏：

```cs
// 3
public void RestartScene()
{
    Utilities.RestartLevel(**-1**);
} 
```

让我们来分解一下代码：

1.  声明一个`if`语句来检查`sceneIndex`是否不小于 0 或负数

1.  如果传入一个负的场景索引作为参数，抛出一个带有自定义消息的`ArgumentException`

1.  使用场景索引为`-1`调用`RestartLevel()`：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_13_10.png)

图 13.11：抛出异常时的控制台输出

现在当我们输掉游戏时，会调用`RestartLevel()`，但由于我们使用`-1`作为场景索引参数，我们的异常会在任何场景管理逻辑执行之前被触发。我们目前游戏中没有配置其他场景，但这个防御性代码作为保障，不让我们执行可能导致游戏崩溃的操作（Unity 在加载场景时不支持负索引）。

现在你成功地抛出了一个错误，你需要知道如何处理错误的后果，这将引导我们进入下一节和`try-catch`语句。

## 使用 try-catch

现在我们已经抛出了一个错误，我们的工作是安全地处理调用`RestartLevel()`可能产生的可能结果，因为在这一点上，这没有得到适当的处理。要做到这一点，需要使用一种新的语句，称为`try-catch`：

```cs
try
{
    // Call a method that might throw an exception
}
catch (ExceptionType localVariable)
{
    // Catch all exception cases individually
} 
```

`try-catch`语句由连续的代码块组成，这些代码块在不同的条件下执行；它就像一个专门的`if`/`else`语句。我们在`try`块中调用可能引发异常的任何方法——如果没有引发异常，代码将继续执行而不中断。如果引发异常，代码将跳转到与抛出异常匹配的`catch`语句，就像`switch`语句与其 case 一样。`catch`语句需要定义它们要处理的异常，并指定一个本地变量名，该变量将在`catch`块内表示它。

您可以在`try`块之后链接多个`catch`语句，以处理从单个方法抛出的多个异常，只要它们捕获不同的异常。例如：

```cs
try
{
    // Call a method that might throw an exception
}
catch (ArgumentException argException)
{
    // Catch argument exceptions here
}
catch (FileNotFoundException fileException)
{
    // Catch exceptions for files not found here
} 
```

还有一个可选的`finally`块，可以在任何`catch`语句之后声明，无论是否抛出异常，它都将在`try-catch`语句的最后执行：

```cs
finally
{
    // Executes at the end of the try-catch no matter what
} 
```

您的下一个任务是使用`try-catch`语句处理重新启动关卡时抛出的任何错误。现在我们有一个在游戏失败时抛出的异常，让我们安全地处理它。使用以下代码更新`GameBehavior`，然后再次失败游戏：

```cs
public class GameBehavior : MonoBehaviour, IManager
{
    // ... No variable changes needed ...
    public void RestartScene()
    {
        // 1 
        try
        {
            Utilities.RestartLevel(-1);
            debug("Level successfully restarted...");
        }
        // 2
        catch (System.ArgumentException exception)
        {
            // 3
            Utilities.RestartLevel(0);
            debug("Reverting to scene 0: " + exception.ToString());
        }
        // 4
        finally
        {
            debug("Level restart has completed...");
        }
    }
} 
```

让我们分解一下代码：

1.  声明`try`块，并将调用`RestartLevel()`移至其中，并使用`debug`命令打印出重新启动是否完成而没有任何异常。

1.  声明`catch`块，并将`System.ArgumentException`定义为它将处理的异常类型，`exception`作为局部变量名。

1.  如果抛出异常，则在默认场景索引处重新启动游戏：

+   使用`debug`委托打印出自定义消息，以及可以从`exception`访问并使用`ToString()`方法将其转换为字符串的异常信息

由于`exception`是`ArgumentException`类型，因此与`Exception`类关联的有几个属性和方法，您可以访问这些属性和方法。当您需要关于特定异常的详细信息时，这些通常很有用。

1.  添加一个带有调试消息的`finally`块，以表示异常处理代码的结束！[](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_13_11.png)

图 13.12：完整的 try-catch 语句的控制台输出

当现在调用`RestartLevel()`时，我们的`try`块安全地允许其执行，如果出现错误，则在`catch`块内捕获。`catch`块在默认场景索引处重新启动关卡，代码继续执行到`finally`块，该块只是为我们记录一条消息。

了解如何处理异常很重要，但不应该养成在代码中随处放置异常的习惯。这将导致臃肿的类，并可能影响游戏的处理时间。相反，您应该在最需要的地方使用异常——无效或数据处理，而不是游戏机制。

C#允许您自由创建自己的异常类型，以满足代码可能具有的任何特定需求，但这超出了本书的范围。这只是一个未来要记住的好事情：[`docs.microsoft.com/en-us/dotnet/standard/exceptions/how-to-create-user-defined-exceptions`](https://docs.microsoft.com/en-us/dotnet/standard/exceptions/how-to-create-user-defined-exceptions)。

# 摘要

虽然本章将我们带到了 C#和 Unity 2020 的实际冒险的尽头，但我希望您的游戏编程和软件开发之旅刚刚开始。您已经学会了从创建变量、方法和类对象到编写游戏机制、敌人行为等方方面面的知识。

本章涵盖的主题已经超出了我们在大部分书中处理的水平，这是有充分理由的。你已经知道你的编程大脑是需要锻炼的肌肉，才能进入下一个阶段。泛型、事件和设计模式都只是编程阶梯上的下一个台阶。

在下一章中，我将为你提供资源、进一步阅读以及有关 Unity 社区和软件开发行业的大量其他有用（我敢说，很酷）的机会和信息。

编程愉快！

# 弹出测验-中级 C#

1.  泛型和非泛型类之间有什么区别？

1.  在为委托类型分配值时需要匹配什么？

1.  你如何取消订阅事件？

1.  在你的代码中，你会使用哪个 C#关键字来发送异常？

# 加入我们的 Discord！

与其他用户、Unity/C#专家和 Harrison Ferrone 一起阅读本书。提出问题，为其他读者提供解决方案，通过*问我任何事*与作者交流，以及更多。

立即加入！

[`packt.link/csharpunity2021`](https://packt.link/csharpunity2021)

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/QR_Code_9781801813945.png)
