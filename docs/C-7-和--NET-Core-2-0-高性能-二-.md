# C#7 和 .NET Core 2.0 高性能（二）

> 原文：[`zh.annas-archive.org/md5/7B34F69B3C37FC27C73A3C065B05D042`](https://zh.annas-archive.org/md5/7B34F69B3C37FC27C73A3C065B05D042)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：数据结构和在 C#中编写优化代码

数据结构是软件工程中存储数据的一种特定方式。它们在计算机中存储数据方面发挥着重要作用，以便可以有效地访问和修改数据，并为存储不同类型的数据提供不同的存储机制。有许多类型的数据结构，每种都设计用于存储一定类型的数据。在本章中，我们将详细介绍数据结构，并了解应该在特定场景中使用哪些数据结构以改善系统在数据存储和检索方面的性能。我们还将了解如何在 C#中编写优化代码以及什么主要因素可能影响性能，这有时在编写程序时被开发人员忽视。我们将学习一些可以用于优化性能有效的最佳实践。

在本章中，我们将涵盖以下主题：

+   数据结构是什么以及它们的特点

+   选择正确的数据结构进行性能优化

+   了解使用大 O 符号来衡量程序的性能和复杂性

+   在.NET Core 中编写代码时的最佳实践

# 什么是数据结构？

数据结构是一种以有效的方式存储和统一数据的方式。数据可以以多种方式存储。例如，我们可以有一个包含一些属性的`Person`对象，例如`PersonID`和`PersonName`，其中`PersonID`是整数类型，`PersonName`是*字符串*类型。这个`Person`对象将数据存储在内存中，并可以进一步用于将该记录保存在数据库中。另一个例子是名为`Countries`的*字符串*类型的*数组*，其中包含国家列表。我们可以使用`Countries`数组来检索国家名称并在程序中使用它。因此，存储数据的任何类型的对象都称为数据结构。所有原始类型，例如整数、字符串、字符和布尔值，都是不同类型的数据结构，而其他集合类型，例如`LinkedList`、`ArrayList`、`SortedList`等，也是可以以独特方式存储信息的数据结构类型。

以下图表说明了数据结构的类型及其相互关系：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-hiperf/img/00045.jpeg)

数据结构有两种类型：*原始*和*非原始*类型。原始类型是包括*有符号整数*、*无符号整数*、*Unicode 字符*、*IEEE 浮点*、*高精度小数*、*布尔*、*枚举*、*结构*和*可空*值类型的值类型。

以下是 C#中可用的原始数据类型列表：

| **原始类型** |
| --- |
| 有符号整数 | `sbyte`, `short`, `int`, `long` |
| 无符号整数 | `byte`, `ushort`, `uint`, `ulong` |
| Unicode 字符 | `Char` |
| IEEE 浮点 | `float`, `double` |
| 高精度小数 | `Decimal` |
| 布尔 | `Bool` |
| 字符串 | `String` |
| 对象 | `System.Object` |

非原始类型是用户定义的类型，并进一步分类为线性或非线性类型。在线性数据结构中，元素按顺序组织，例如*数组*、*链表*和其他相关类型，而在非线性数据结构中，元素存储在没有任何顺序的情况下，例如*树*和*图*。

以下表格显示了.NET Core 中可用的线性和非线性类的类型：

| **非原始类型 - 线性数据结构** |
| --- |
| 数组 | `ArrayList`, `String[]`, `原始类型数组`, `List`, `Dictionary`, `Hashtable`, `BitArray` |
| 栈 | `Stack<T>`, `SortedSet<T>`, `SynchronizedCollection<T>` |
| 队列 | `Queue<T>` |
| 链表 | `LinkedList<T>` |

.NET Core 不提供任何非原始、非线性类型来表示树形或图形格式的数据。但是，我们可以开发自定义类来支持这些类型。

例如，以下是编写存储数据的自定义树的代码格式：

```cs
class TreeNode 
{ 
  public TreeNode(string text, object tag) 
  { 
    this.NodeText = text; 
    this.Tag = tag; 
    Nodes = new List<TreeNode>(); 
  } 
  public string NodeText { get; set; } 
  public Object Tag { get; set; } 
  public List<TreeNode> Nodes { get; set; } 
} 
```

最后，我们可以编写一个程序，在控制台窗口上填充树视图如下：

```cs
static void Main(string[] args) 
{ 
  TreeNode node = new TreeNode("Root", null); 
  node.Nodes.Add(new TreeNode("Child 1", null)); 
  node.Nodes[0].Nodes.Add(new TreeNode("Grand Child 1", null)); 
  node.Nodes.Add(new TreeNode("Child 1 (Sibling)", null)); 
  PopulateTreeView(node, ""); 
  Console.Read(); 
} 

//Populates a Tree View on Console 
static void PopulateTreeView(TreeNode node, string space) 
{ 
  Console.WriteLine(space + node.NodeText); 
  space = space + " "; 
  foreach(var treenode in node.Nodes) 
  { 
    //Recurive call 
    PopulateTreeView(treenode, space); 
  } 
}
```

当您运行上述程序时，它会生成以下输出：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-hiperf/img/00046.gif)

# 理解使用大 O 符号来衡量算法的性能和复杂性

大 O 符号用于定义算法的复杂性和性能，以及在执行期间所消耗的时间或空间。这是一种表达算法性能并确定程序最坏情况复杂性的重要技术。

为了详细了解它，让我们通过一些代码示例并使用大 O 符号来计算它们的性能。

如果我们计算以下程序的复杂度，大 O 符号将等于*O(1)*：

```cs
static int SumNumbers(int a, int b) 
{ 
  return a + b; 
} 
```

这是因为无论参数如何指定，它只是添加并返回它。

让我们考虑另一个循环遍历列表的程序。大 O 符号将被确定为*O(N)*：

```cs
static bool FindItem(List<string> items, string value) 
{ 
  foreach(var item in items) 
  { 
    if (item == value) 
    { 
      return true; 
    } 
  } 
  return false; 
} 
```

在上面的示例中，程序正在循环遍历项目列表，并将传递的值与列表中的每个项目进行比较。如果找到项目，则程序返回`true`。

复杂度被确定为*O(N)*，因为最坏情况可能是一个循环向*N*个项目，其中*N*可以是第一个索引或任何索引，直到达到最后一个索引，即*N*。

现在，让我们看一个*选择排序*的例子，它被定义为*O(N2)*：

```cs
static void SelectionSort(int[] nums) 
{ 
  int i, j, min; 

  // One by one move boundary of unsorted subarray 
  for (i = 0; i <nums.Length-1; i++) 
  { 
    min = i; 
    for (j = i + 1; j < nums.Length; j++) 
    if (nums[j] < nums[min]) 
    min = j; 

    // Swap the found minimum element with the first element 
    int temp = nums[min]; 
    nums[min] = nums[i]; 
    nums[i] = temp; 
  } 
} 
```

在上面的示例中，我们有两个嵌套的循环。第一个循环从`0`遍历到最后一个索引，而第二个循环从下一个项目遍历到倒数第二个项目，并交换值以按升序排序数组。嵌套循环的数量与*N*的幂成正比，因此大 O 符号被定义为*O(N2)*。

接下来，让我们考虑一个递归函数，其中大 O 符号被定义为*O(2N)*，其中*2N*确定所需的时间，随着输入数据集中每个额外元素的加入而加倍。以下是一个递归调用方法的示例，该方法递归调用方法，直到计数器变为最大数字为止：

```cs
static void Main(string[] args){ 
  Fibonacci_Recursive(0, 1, 1, 10); 
} 

static void Fibonacci_Recursive(int a, int b, int counter, int maxNo) 
{ 
  if (counter <= maxNo) 
  { 
    Console.Write("{0} ", a); 
    Fibonacci_Recursive(b, a + b, counter + 1, len); 
  } 
} 
```

# 对数

对数运算是指数运算的完全相反。对数是表示必须将基数提高到产生给定数字的幂的数量。

例如，*2x = 32*，其中*x=5*，可以表示为*log2 32 =5*。

在这种情况下，上述表达式的对数是 5，表示固定数字 2 的幂，它被提高以产生给定数字 32。

考虑一个二分搜索算法，通过将项目列表分成两个数据集并根据数字使用特定数据集来更有效地工作。例如，假设我有一个按升序排列的不同数字列表：

*{1, 5, 6, 10, 15, 17, 20, 42, 55, 60, 67, 80, 100}*

假设我们要找到数字*55*。这样做的一种方法是循环遍历每个索引并逐个检查每个项目。更有效的方法是将列表分成两组，并检查我要查找的数字是否大于第一个数据集的最后一个项目，或者使用第二个数据集。

以下是一个二分搜索的示例，其大 O 符号将被确定为*O(LogN)*：

```cs
static int binarySearch(int[] nums, int startingIndex, int length, int itemToSearch) 
{ 
  if (length >= startingIndex) 
  { 
    int mid = startingIndex + (length - startingIndex) / 2; 

    // If the element found at the middle itself 
    if (nums[mid] == itemToSearch) 
    return mid; 

    // If the element is smaller than mid then it is 
    // present in left set of array 
    if (nums[mid] > itemToSearch) 
    return binarySearch(nums, startingIndex, mid - 1, itemToSearch); 

    // Else the element is present in right set of array 
    return binarySearch(nums, mid + 1, length, itemToSearch); 
  } 

  // If item not found return 1 
  return -1; 
} 
```

# 选择正确的数据结构进行性能优化

数据结构是计算机程序中组织数据的一种精确方式。如果数据没有有效地存储在正确的数据结构中，可能会导致一些影响应用程序整体体验的性能问题。

在本节中，我们将学习.NET Core 中可用的不同集合类型的优缺点，以及哪些类型适用于特定场景：

+   数组和列表

+   栈和队列

+   链表（单链表，双链表和循环链表）

+   字典，哈希表和哈希集

+   通用列表

# 数组

数组是保存相似类型元素的集合。可以创建值类型和引用类型的数组。

以下是数组有用的一些情况：

+   如果数据是固定的，长度固定，使用数组比其他集合更快，例如`arraylists`和通用列表

+   数组很适合以多维方式表示数据

+   它们占用的内存比其他集合少

+   使用数组，我们可以顺序遍历元素

以下表格显示了可以在数组中执行的每个操作的大 O 符号：

| **操作** | **大 O 符号** |
| --- | --- |
| 按索引访问 | *O(1)* |
| 搜索 | *O(n)* |
| 在末尾插入 | *O(n)* |
| 在末尾删除 | *O(n)* |
| 在最后一个元素之前的位置插入 | *O(n)* |
| 删除索引处的元素 | *O(1)* |

如前表所示，在特定位置搜索和插入项目会降低性能，而访问索引中的任何项目或从任何位置删除它对性能的影响较小。

# 列表

.NET 开发人员广泛使用列表。虽然在许多情况下最好使用它，但也存在一些性能限制。

当您想使用索引访问项目时，大多数情况下建议使用列表。与链表不同，链表需要使用枚举器迭代每个节点来搜索项目，而使用列表，我们可以轻松使用索引访问它。

以下是列表有用的一些建议：

+   建议在集合大小未知时使用列表。调整数组大小是一项昂贵的操作，而使用列表，我们可以根据需要轻松增加集合的大小。

+   与数组不同，列表在创建时不会为项目数量保留总内存地址空间。这是因为使用列表时不需要指定集合的大小。另一方面，数组依赖于初始化时的类型和大小，并在初始化期间保留地址空间。

+   使用列表，我们可以使用 lambda 表达式来过滤记录，按降序对项目进行排序，并执行其他操作。数组不提供排序、过滤或其他此类操作。

+   列表表示单维集合。

以下表格显示了可以在列表上执行的每个操作的大 O 符号：

| **操作** | **大 O 符号** |
| --- | --- |
| 按索引访问 | *O(1)* |
| 搜索 | *O(n)* |
| 在末尾插入 | *O(1)* |
| 从末尾删除 | *O(1)* |
| 在最后一个元素之前的位置插入 | *O(n)* |
| 删除索引处的元素 | *O(n)* |

# 堆栈

堆栈以**后进先出**（**LIFO**）顺序维护项目的集合。最后插入的项目首先被检索。堆栈只允许两种操作，即`push`和`pop`。堆栈的真正应用是`undo`操作，它将更改插入堆栈中，并在撤消时删除执行的最后一个操作：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-hiperf/img/00047.jpeg)

上图说明了如何将项目添加到堆栈中。最后插入的项目首先弹出，要访问首先插入的项目，我们必须弹出每个元素，直到达到第一个元素。

以下是一些堆栈有用的情况：

+   当访问其值时应删除项目的情况

+   需要在程序中实现`undo`操作

+   在 Web 应用程序上维护导航历史记录

+   递归操作

以下表格显示了可以在堆栈上执行的每个操作的大 O 符号：

| **操作** | **大 O 符号** |
| --- | --- |
| 访问第一个对象 | *O(1)* |
| 搜索 | *O(n)* |
| 推送项目 | *O(1)* |
| 弹出项目 | *O(1)* |

# 队列

队列以**先进先出**（**FIFO**）顺序维护项目的集合。首先插入队列的项目首先从队列中检索。队列中只允许三种操作，即`Enqueue`，`Dequeue`和`Peek`。

`Enqueue`将元素添加到队列的末尾，而`Dequeue`从队列的开头移除元素。`Peek`返回队列中最旧的元素，但不会将它们移除：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-hiperf/img/00048.gif)

上图说明了如何将项目添加到队列。首先插入的项目将首先从队列中移除，并且指针移动到队列中的下一个项目。`Peek`始终返回第一个插入的项目或指针所指向的项目，取决于是否移除了第一个项目。

以下是队列有用的一些情况：

+   按顺序处理项目

+   按先来先服务的顺序提供服务

以下表格显示了可以在队列上执行的每个操作的大 O 表示法：

| **操作** | **大 O 表示法** |
| --- | --- |
| 访问第一个插入的对象 | *O(1)* |
| 搜索 | *O(n)* |
| 队列项目 | *O(1)* |
| 入队项目 | *O(1)* |
| Peek 项目 | *O(1)* |

# 链表

链表是一种线性数据结构，其中列表中的每个节点都包含对下一个节点的引用指针，最后一个节点引用为 null。第一个节点称为头节点。有三种类型的链表，称为*单向*，*双向*和*循环*链表。

# 单链表

单链表只包含对下一个节点的引用。以下图表示单链表：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-hiperf/img/00049.gif)

# 双向链表

在双向链表中，节点包含对下一个节点和上一个节点的引用。用户可以使用引用指针向前和向后迭代。以下图像是双向链表的表示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-hiperf/img/00050.gif)

# 循环链表

在循环链表中，最后一个节点指向第一个节点。以下是循环链表的表示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-hiperf/img/00051.gif)

以下是链表有用的一些情况：

+   以顺序方式提供对项目的访问

+   在列表的任何位置插入项目

+   在任何位置或节点删除任何项目

+   当需要消耗更少的内存时，因为链表中没有数组复制

以下表格显示了可以在链表上执行的每个操作的大 O 表示法值：

| **操作** | **大 O 表示法** |
| --- | --- |
| 访问项目 | *O(1)* |
| 搜索项目 | *O(n)* |
| 插入项目 | *O(1)* |
| 删除项目 | *O(1)* |

# 字典，哈希表和哈希集

字典，哈希表和哈希集对象以键-值格式存储项目。但是，哈希集和字典适用于性能至关重要的场景。以下是这些类型有用的一些情况：

+   以键-值格式存储可以根据特定键检索的项目

+   存储唯一值

以下表格显示了可以在这些对象上执行的每个操作的大 O 表示法值：

| **操作** | **大 O 表示法** |
| --- | --- |
| 访问 | *O(n)* |
| 如果不知道键，则搜索值 | *O(n)* |
| 插入项目 | *O(n)* |
| 删除项目 | *O(n)* |

# 通用列表

通用列表是一种强类型的元素列表，可以使用索引访问。与数组不同，通用列表是可扩展的，列表可以动态增长；因此，它们被称为动态数组或向量。与数组不同，通用列表是一维的，是操作内存中元素集合的最佳选择之一。

我们可以定义一个通用列表，如下面的代码示例所示。代码短语`lstNumbers`只允许存储整数值，短语`lstNames`存储`only`字符串，`personLst`存储`Person`对象，等等：

```cs
List<int> lstNumbers = new List<int>();     
List<string> lstNames = new List<string>();     
List<Person> personLst = new List<Person>();              
HashSet<int> hashInt = new HashSet<int>();
```

以下表格显示了可以在这些对象上执行的每个操作的大 O 符号值：

| **操作** | **大 O 符号** |
| --- | --- |
| 通过索引访问 | *O(1)* |
| 搜索 | *O(n)* |
| 在末尾插入 | *O(1)* |
| 从末尾删除 | *O(1)* |
| 在最后一个元素之前的位置插入 | *O(n)* |
| 删除索引处的元素 | *O(n)* |

# 在 C#中编写优化代码的最佳实践

有许多因素会对.NET Core 应用程序的性能产生负面影响。有时这些是在编写代码时未考虑的小事情，并且不符合已接受的最佳实践。因此，为了解决这些问题，程序员经常求助于临时解决方案。然而，当不良实践结合在一起时，它们会产生性能问题。了解有助于开发人员编写更清洁的代码并使应用程序性能良好的最佳实践总是更好的。

在本节中，我们将学习以下主题：

+   装箱和拆箱开销

+   字符串连接

+   异常处理

+   `for`与`foreach`

+   委托

# 装箱和拆箱开销

装箱和拆箱方法并不总是好用的，它们会对关键任务应用程序的性能产生负面影响。装箱是将值类型转换为对象类型的方法，它是隐式完成的，而拆箱是将对象类型转换回值类型的方法，需要显式转换。

让我们通过一个例子来看，我们有两种方法执行 1000 万条记录的循环，每次迭代时都会将计数器加 1。`AvoidBoxingUnboxing`方法使用原始整数来初始化并在每次迭代时递增，而`BoxingUnboxing`方法是通过首先将数值赋给对象类型进行装箱，然后在每次迭代时进行拆箱以将其转换回整数类型，如下所示：

```cs
private static void AvoidBoxingUnboxing() 
{ 

  Stopwatch watch = new Stopwatch(); 
  watch.Start(); 
  //Boxing  
  int counter = 0; 
  for (int i = 0; i < 1000000; i++) 
  { 
    //Unboxing 
    counter = i + 1; 
  } 
  watch.Stop(); 
  Console.WriteLine($"Time taken {watch.ElapsedMilliseconds}"); 
} 

private static void BoxingUnboxing() 
{ 

  Stopwatch watch = new Stopwatch(); 
  watch.Start(); 
  //Boxing  
  object counter = 0; 
  for (int i = 0; i < 1000000; i++) 
  { 
    //Unboxing 
    counter = (int)i + 1; 
  } 
  watch.Stop(); 
  Console.WriteLine($"Time taken {watch.ElapsedMilliseconds}"); 
}
```

当我们运行这两种方法时，我们将清楚地看到性能上的差异。如下截图所示，`BoxingUnboxing`方法的执行速度比`AvoidBoxingUnboxing`方法慢了七倍：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-hiperf/img/00052.gif)

对于关键任务应用程序，最好避免装箱和拆箱。然而，在.NET Core 中，我们有许多其他类型，内部使用对象并执行装箱和拆箱。`System.Collections`和`System.Collections.Specialized`下的大多数类型在内部存储时使用对象和对象数组，当我们在这些集合中存储原始类型时，它们执行装箱并将每个原始值转换为对象类型，增加额外开销并对应用程序的性能产生负面影响。`System.Data`的其他类型，即`DateSet`，`DataTable`和`DataRow`，也在内部使用对象数组。

在性能是主要关注点时，`System.Collections.Generic`命名空间下的类型或类型化数组是最佳的方法。例如，`HashSet<T>`，`LinkedList<T>`和`List<T>`都是通用集合类型。

例如，这是一个将整数值存储在`ArrayList`中的程序：

```cs
private static void AddValuesInArrayList() 
{ 

  Stopwatch watch = new Stopwatch(); 
  watch.Start(); 
  ArrayList arr = new ArrayList(); 
  for (int i = 0; i < 1000000; i++) 
  { 
    arr.Add(i); 
  } 
  watch.Stop(); 
  Console.WriteLine($"Total time taken is 
  {watch.ElapsedMilliseconds}"); 
}
```

让我们编写另一个使用整数类型的通用列表的程序：

```cs
private static void AddValuesInGenericList() 
{ 

  Stopwatch watch = new Stopwatch(); 
  watch.Start(); 
  List<int> lst = new List<int>(); 
  for (int i = 0; i < 1000000; i++) 
  { 
    lst.Add(i); 
  } 
  watch.Stop(); 
  Console.WriteLine($"Total time taken is 
  {watch.ElapsedMilliseconds}"); 
} 
```

运行这两个程序时，差异是非常明显的。使用通用列表`List<int>`的代码比使用`ArrayList`的代码快了 10 倍以上。结果如下：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-hiperf/img/00053.gif)

# 字符串连接

在.NET 中，字符串是不可变对象。直到字符串值改变之前，两个字符串引用堆上的相同内存。如果任何一个字符串被改变，将在堆上创建一个新的字符串，并分配一个新的内存空间。不可变对象通常是线程安全的，并消除了多个线程之间的竞争条件。字符串值的任何更改都会在内存中创建并分配一个新对象，并避免与多个线程产生冲突的情况。

例如，让我们初始化字符串并将`Hello World`的值分配给`a`字符串变量：

```cs
String a = "Hello World"; 
```

现在，让我们将`a`字符串变量分配给另一个变量`b`：

```cs
String b = a;
```

`a`和`b`都指向堆上的相同值，如下图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-hiperf/img/00054.jpeg)

现在，假设我们将`b`的值更改为`Hope this helps`：

```cs
b= "Hope this helps"; 
```

这将在堆上创建另一个对象，其中`a`指向相同的对象，而`b`指向包含新文本的新内存空间：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-hiperf/img/00055.gif)

随着字符串的每次更改，对象都会分配一个新的内存空间。在某些情况下，这可能是一个过度的情况，其中字符串修改的频率较高，并且每次修改都会分配一个单独的内存空间，这会导致垃圾收集器在收集未使用的对象并释放空间时产生额外的工作。在这种情况下，强烈建议您使用`StringBuilder`类。

# 异常处理

不正确处理异常也会降低应用程序的性能。以下列表包含了在.NET Core 中处理异常的一些最佳实践：

+   始终使用特定的异常类型或可以捕获方法中的异常的类型。对所有情况使用`Exception`类型不是一个好的做法。

+   在可能引发异常的代码中，始终使用`try`、`catch`和`finally`块。通常使用最终块来清理资源，并返回调用代码期望的适当响应。

+   在嵌套深的代码中，不要使用`try catch`块，而是将其处理给调用方法或主方法。在多个堆栈上捕获异常会减慢性能，不建议这样做。

+   始终使用异常处理程序来处理终止程序的致命条件。

+   不建议对非关键条件使用异常，例如将值转换为整数或从空数组中读取值，并且应通过自定义逻辑进行处理。例如，将字符串值转换为整数类型可以使用`Int32.Parse`方法，而不是使用`Convert.ToInt32`方法，然后在字符串表示为数字时失败。

+   在抛出异常时，添加一个有意义的消息，以便用户知道异常实际发生的位置，而不是查看堆栈跟踪。例如，以下代码显示了抛出异常并根据所调用的方法和类添加自定义消息的方法：

```cs
static string GetCountryDetails(Dictionary<string, string> countryDictionary, string key)
{
  try
  {
    return countryDictionary[key];
  }
  catch (KeyNotFoundException ex)
  {
    KeyNotFoundException argEx = new KeyNotFoundException("
    Error occured while executing GetCountryDetails method. 
    Cause: Key not found", ex);
    throw argEx;
  }
}
```

+   抛出异常而不是返回自定义消息或错误代码，并在主调用方法中处理它。

+   在记录异常时，始终检查内部异常并阅读异常消息或堆栈跟踪。这是有帮助的，并且可以给出代码中实际引发错误的位置。

# `for`和`foreach`

`for`和`foreach`是在列表中进行迭代的两种替代方式。它们每个都以不同的方式运行。for 循环实际上首先将列表的所有项加载到内存中，然后使用索引器迭代每个元素，而 foreach 使用枚举器并迭代直到达到列表的末尾。

以下表格显示了适合在`for`和`foreach`中使用的集合类型：

| **类型** | **For/Foreach** |
| --- | --- |
| 类型化数组 | 适合使用 for 和 foreach |
| 数组列表 | 更适合使用 for |
| 通用集合 | 更适合使用 for |

# 委托

委托是.NET 中保存方法引用的一种类型。该类型相当于 C 或 C++中的函数指针。在定义委托时，我们可以指定方法可以接受的参数和返回类型。这样，引用方法将具有相同的签名。

这是一个简单的委托，它接受一个字符串并返回一个整数：

```cs
delegate int Log(string n);
```

现在，假设我们有一个`LogToConsole`方法，它具有与以下代码中所示的相同签名。该方法接受字符串并将其写入控制台窗口：

```cs
static int LogToConsole(string a) { Console.WriteLine(a); 
  return 1; 
}   
```

我们可以像这样初始化和使用这个委托：

```cs
Log logDelegate = LogToConsole; 
logDelegate ("This is a simple delegate call"); 
```

假设我们有另一个名为`LogToDatabase`的方法，它将信息写入数据库：

```cs
static int LogToDatabase(string a) 
{ 
  Console.WriteLine(a); 
  //Log to database 
  return 1; 
} 
```

这是新的`logDelegate`实例的初始化，它引用了`LogToDatabase`方法：

```cs
Log logDelegateDatabase = LogToDatabase; 
logDelegateDatabase ("This is a simple delegate call"); 
```

前面的委托是单播委托的表示，因为每个实例都引用一个方法。另一方面，我们也可以通过将`LogToDatabase`分配给相同的`LogDelegate`实例来创建多播委托，如下所示：

```cs
Log logDelegate = LogToConsole; 
logDelegate += LogToDatabase; 
logDelegate("This is a simple delegate call");     
```

前面的代码看起来非常直接和优化，但在底层，它有巨大的性能开销。在.NET 中，委托是由一个`MutlicastDelegate`类实现的，它经过优化以运行单播委托。它将方法的引用存储到目标属性，并直接调用该方法。对于多播委托，它使用调用列表，这是一个通用列表，并保存添加的每个方法的引用。对于多播委托，每个目标属性都保存对包含方法的通用列表的引用，并按顺序执行。然而，这会为多播委托增加开销，并且需要更多时间来执行。

# 总结

在这一章中，我们学习了关于数据结构的核心概念，数据结构的类型，以及它们的优缺点，接着是它们可以使用的最佳场景。我们还学习了大 O 符号，这是编写代码时需要考虑的核心主题之一，它帮助开发人员识别代码性能。最后，我们研究了一些最佳实践，并涵盖了诸如装箱和拆箱、字符串连接、异常处理、`for`和`foreach`循环以及委托等主题。

在下一章中，我们将学习一些在设计.NET Core 应用程序时可能有帮助的准则和最佳实践。


# 第五章：.NET Core 应用程序性能设计指南

架构和设计是任何应用程序的核心基础。遵循最佳实践和指南使应用程序具有高可维护性、高性能和可扩展性。应用程序可以是基于 Web 的应用程序、Web API、服务器/客户端基于 TCP 的消息传递应用程序、关键任务应用程序等等。然而，所有这些应用程序都应该遵循一定的实践，从而在各种方面获益。在本章中，我们将学习几种几乎所有应用程序中常见的实践。

以下是本章将学习的一些原则：

+   编码原则：

+   命名约定

+   代码注释

+   每个文件一个类

+   每个方法一个逻辑

+   设计原则：

+   KISS（保持简单，愚蠢）

+   YAGNI（你不会需要它）

+   DRY（不要重复自己）

+   关注点分离

+   SOLID 原则

+   缓存

+   数据结构

+   通信

+   资源管理

+   并发

# 编码原则

在本节中，我们将介绍一些基本的编码原则，这些原则有助于编写提高应用程序整体性能和可扩展性的优质代码。

# 命名约定

在每个应用程序中始终使用适当的命名约定，从解决方案名称开始，解决方案名称应提供有关您正在工作的项目的有意义的信息。项目名称指定应用程序的层或组件部分。最后，类应该是名词或名词短语，方法应该代表动作。

当我们在 Visual Studio 中创建一个新项目时，默认的解决方案名称设置为您为项目名称指定的内容。解决方案名称应始终与项目名称不同，因为一个解决方案可能包含多个项目。项目名称应始终代表系统的特定部分。例如，假设我们正在开发一个消息网关，该网关向不同的方发送不同类型的消息，并包含三个组件，即监听器、处理器和调度器；监听器监听传入的请求，处理器处理传入的消息，调度器将消息发送到目的地。命名约定可以如下：

+   解决方案名称：`MessagingGateway`（或任何代码词）

+   监听器项目名称：`ListenerApp`

+   处理器项目名称：`ProcessorAPI`（如果是 API）

+   调度项目名称：`DispatcherApp`

在.NET 中，我们通常遵循的命名约定是类和方法名称使用帕斯卡命名法。在帕斯卡命名法中，每个单词的第一个字符都是大写字母，而参数和其他变量则使用骆驼命名法。以下是一些示例代码，显示了在.NET 中应如何使用命名法。

```cs
public class MessageDispatcher 
{ 
  public const string SmtpAddress = "smpt.office365.com"; 

  public void SendEmail(string fromAddress, string toAddress, 
  string subject, string body) 
  { 

  } 
}
```

在上述代码中，我们有一个常量字段`SmtpAddress`和一个使用帕斯卡命名法的`SendEmail`方法，而参数则使用骆驼命名法。

以下表格总结了.NET 中不同工件的命名约定：

| **属性** | **命名约定** | **示例** |
| --- | --- | --- |
| 类 | 帕斯卡命名法 | `class PersonManager {}` |
| 方法 | 帕斯卡命名法 | `void SaveRecord(Person person) {}` |
| 参数/成员变量 | 骆驼命名法 | `bool isActive;` |
| 接口 | 帕斯卡命名法；以字母 I 开头 | `IPerson` |
| 枚举 | 帕斯卡命名法 | `enum Status {InProgress, New, Completed}` |

# 代码注释

任何包含适当注释的代码都可以在许多方面帮助开发人员。它不仅减少了理解代码的时间，还可以利用诸如*Sandcastle*或*DocFx*之类的工具，在生成完整的代码文档时即时共享给团队中的其他开发人员。此外，在谈论 API 时，Swagger 在开发人员社区中被广泛使用和受欢迎。Swagger 通过提供有关 API 的完整信息，可用方法，每个方法所需的参数等，来赋予 API 使用者权力。Swagger 还读取这些注释，以提供完整的文档和接口，以测试任何 API。

# 每个文件一个类

与许多其他语言不同，在.NET 中，我们不受限于为每个类创建单独的文件。我们可以创建一个单独的`.cs`文件，并在其中创建多个类。相反，这是一种不好的做法，当处理大型应用程序时会很痛苦。

# 每个方法一个逻辑

始终编写一次只执行一件事的方法。假设我们有一个方法，它从数据库中读取用户 ID，然后调用 API 来检索用户上传的文档列表。在这种情况下，最好的方法是有两个单独的方法，`GetUserID`和`GetUserDocuments`，分别首先检索用户 ID，然后检索文档：

```cs
public int GetUserId(string userName) 
{ 
  //Get user ID from database by passing the username 
} 

public List<Document> GetUserDocuments(int userID) 
{ 
  //Get list of documents by calling some API 
} 
```

这种方法的好处在于减少了代码重复。将来，如果我们想要更改任一方法的逻辑，我们只需在一个地方进行更改，而不是在所有地方复制它并增加错误的机会。

# 设计原则

遵循最佳实践开发清晰的架构会带来多种好处，应用程序性能就是其中之一。我们经常看到，应用程序背后使用的技术是强大而有效的，但应用程序的性能仍然不尽人意或不佳，这通常是因为糟糕的架构设计和在应用程序设计上投入较少的时间。

在这一部分，我们将讨论一些在.NET Core 中设计和开发应用程序时应该解决的常见设计原则：

+   KISS（保持简单，愚蠢）

+   YAGNI（你不会需要它）

+   DRY（不要重复自己）

+   关注点分离

+   SOLID 原则

+   缓存

+   数据结构

+   通信

+   资源管理

+   并发

# KISS（保持简单，愚蠢）

编写更清洁的代码并始终保持简单有助于开发人员在长期内理解和维护它。在代码中添加不必要的复杂性不仅使其难以理解，而且在需要时也难以维护和更改。这就是 KISS 所说的。在软件上下文中，KISS 可以在设计软件架构时考虑，使用**面向对象原则**（**OOP**），设计数据库，用户界面，集成等。添加不必要的复杂性会使软件的设计复杂化，并可能影响应用程序的可维护性和性能。

# YAGNI（你不会需要它）

YAGNI 是 XP（极限编程）的核心原则之一。XP 是一种软件方法，包含短期迭代，以满足客户需求，并在需要或由客户发起时欢迎变更。主要目标是满足客户的期望，并保持客户所需的质量和响应能力。它涉及成对编程和代码审查，以保持质量完整，并满足客户的期望。

YAGNI 最适合极限编程方法，该方法帮助开发人员专注于应用程序功能或客户需求的特性。做一些额外的事情，如果没有告知客户或不是迭代或需求的一部分，最终可能需要重新工作，并且会浪费时间。

# DRY（不要重复自己）

DRY（不要重复自己）也是编写更清晰代码的核心原则之一。它解决了开发人员在大型应用程序中不断更改或扩展功能或基础逻辑时所面临的挑战。根据该原则，它规定“系统中的每个知识片段必须有一个可靠的表示”。

在编写应用程序时，我们可以使用抽象来避免代码的重复，以避免冗余。这有助于适应变化，并让开发人员专注于需要更改的一个领域。如果相同的代码在多个地方重复，那么在一个地方进行更改需要在其他地方进行更改，这会消除良好的架构实践，从而引发更高的错误风险，并使应用程序代码更加错误。

# 关注点分离（SoC）

开发清晰架构的核心原则之一是**关注点分离**（**SoC**）。这种模式规定，每种不同类型的应用程序应该作为一个独立的组件单独构建，与其他组件几乎没有或没有紧密耦合。例如，如果一个程序将用户消息保存到数据库，然后一个服务随机选择消息并选择获胜者，你可以看到这是两个独立的操作，这就是所谓的关注点分离。通过关注点分离，代码被视为一个独立的组件，如果需要，任何定制都可以在一个地方完成。可重用性是另一个因素，它帮助开发人员在一个地方更改代码，以便在多个地方使用。然而，测试要容易得多，而且在出现问题的情况下，错误可以被隔离和延后修复。

# SOLID 原则

SOLID 是 5 个原则的集合，列举如下。这些是在开发软件设计时经常使用的常见设计原则：

+   **单一责任原则**（**SRP**）

+   **开闭原则**（**OCP**）

+   **里氏替换原则**（**LSP**）

+   **接口隔离原则**（**ISP**）

+   **依赖倒置原则**（**DIP**）

# 单一责任原则

单一责任原则规定类应该只有一个特定的目标，并且该责任应该完全封装在类中。如果有任何更改或需要适应新目标，应创建一个新的类或接口。

在软件设计中应用这一原则使我们的代码易于维护和理解。架构师通常在设计软件架构时遵循这一原则，但随着时间的推移，当许多开发人员在该代码/类中工作并进行更改时，它变得臃肿，并且违反了单一责任原则，最终使我们的代码难以维护。

这也涉及到内聚性和耦合的概念。内聚性指的是类中责任之间的关联程度，而耦合指的是每个类相互依赖的程度。我们应该始终专注于保持类之间的低耦合和类内的高内聚。

这是一个基本的`PersonManager`类，包含四个方法，即`GetPerson`、`SavePerson`、`LogError`和`LogInformation`：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-hiperf/img/00056.gif)

所有这些方法都使用数据库持久性管理器来读取/写入数据库中的记录。正如你可能已经注意到的那样，`LogError`和`LogInformation`与`PersonManager`类的内聚性不高，并且与`PersonManager`类紧密耦合。如果我们想在其他类中重用这些方法，我们必须使用`PersonManager`类，并且更改内部日志记录的逻辑也需要更改`PersonManager`类。因此，`PersonManager`违反了单一责任原则。

为了修复这个设计，我们可以创建一个单独的`LogManager`类，可以被`PersonManager`使用来记录执行操作时的信息或错误。下面是更新后的类图，表示关联关系：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-hiperf/img/00057.gif)

# 开闭原则

根据定义，开闭原则规定，类、方法、接口等软件实体应该对修改封闭，对扩展开放。这意味着我们不能修改现有代码，并通过添加额外的类、接口、方法等来扩展功能，以应对任何变化。

在任何应用程序中使用这个原则可以解决各种问题，列举如下：

+   在不改变现有代码的情况下添加新功能会产生更少的错误，并且不需要彻底测试

+   更少的涟漪效应通常在更改现有代码以添加或更新功能时经历

+   扩展通常使用新接口或抽象类来实现，其中现有代码是不必要的，而且破坏现有功能的可能性较小

为了实现开闭原则，我们应该使用抽象化，这是通过参数、继承和组合方法实现的。

# 参数

方法中可以设置特殊参数，用于控制该方法中编写的代码的行为。假设有一个`LogException`方法，它将异常保存到数据库，并发送电子邮件。现在，每当调用这个方法时，两个任务都会执行。没有办法从代码中停止发送电子邮件来处理特定的异常。然而，如果以某种方式表达，并使用一些参数来决定是否发送电子邮件，就可以控制。然而，如果现有代码不支持这个参数，那么就需要定制，但是在设计时，我们可以采用这种方法来暴露某些参数，以便处理方法的内部行为：

```cs
public void LogException(Exception ex) 
{ 
  SendEmail(ex); 
  LogToDatabase(ex); 
} 
```

推荐的实现如下：

```cs
public void LogException(Exception ex, bool sendEmail, bool logToDb) 
{ 
  if (sendEmail) 
  { 
    SendEmail(ex); 
  } 

  if (logToDb) 
  { 
    LogToDatabase(ex); 
  } 
}
```

# 继承

使用继承方法，我们可以使用模板方法模式。使用模板方法模式，我们可以在根类中创建默认行为，然后创建子类来覆盖默认行为并实现新功能。

例如，这里有一个`Logger`类，它将信息记录到文件系统中：

```cs
public class Logger 
{ 
  public virtual void LogMessage(string message) 
  { 
    //This method logs information into file system 
    LogToFileSystem(message); 
  } 

  private void LogtoFileSystem(string message) { 
    //Log to file system 
  } 
} 
```

我们有一个`LogMessage`方法，通过调用`LogToFileSystem`方法将消息记录到文件系统中。这个方法一直工作得很好，直到我们想要扩展功能。假设，以后我们提出了将这些信息也记录到数据库的要求。我们必须更改现有的`LogMessage`方法，并将代码编写到同一个类中。以后，如果出现其他要求，我们必须一遍又一遍地添加功能并修改这个类。根据开闭原则，这是一种违反。

使用模板方法模式，我们可以重新设计这段代码，遵循开闭原则，使其对扩展开放，对定制封闭。

遵循 OCP，这里是新设计，我们有一个包含`LogMessage`抽象方法的抽象类，以及两个具有自己实现的子类：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-hiperf/img/00058.gif)

有了这个设计，我们可以在不改变现有`Logger`类的情况下添加第 n 个扩展：

```cs
public abstract class Logger 
{ 
  public abstract void LogMessage(string message); 

} 

public class FileLogger : Logger 
{ 
  public override void LogMessage(string message) 
  { 
    //Log to file system 
  } 
} 

public class DatabaseLogger : Logger 
{ 
  public override void LogMessage(string message) 
  { 
    //Log to database 
  } 
} 

```

# 组合

第三种方法是组合，这可以通过策略模式实现。通过这种方法，客户端代码依赖于抽象，实际实现封装在一个单独的类中，该类被注入到暴露给客户端的类中。

让我们看一个实现策略模式的例子。基本要求是发送可能是电子邮件或短信的消息，并且我们需要以一种方式构造它，以便将来可以添加新的消息类型而不对主类进行任何修改：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-hiperf/img/00059.gif)

根据策略模式，我们有一个`MessageStrategy`抽象类，它公开一个抽象方法。每种工作类型都封装到继承`MessageStrategy`基本抽象类的单独类中。

这是`MessageStrategy`抽象类的代码：

```cs
public abstract class MessageStrategy 
{ 
  public abstract void SendMessage(Message message); 
}
```

我们有两个`MessageStrategy`的具体实现；一个用于发送电子邮件，另一个用于发送短信，如下所示：

```cs
public class EmailMessage : MessageStrategy 
{ 
  public override void SendMessage(Message message) 
  { 
    //Send Email 
  } 
} 

public class SMSMessage : MessageStrategy 
{ 
  public override void SendMessage(Message message) 
  { 
    //Send SMS  
  } 
} 
```

最后，我们有`MessageSender`类，客户端将使用它。在这个类中，客户端可以设置消息策略并调用`SendMessage`方法，该方法调用特定的具体实现类型来发送消息：

```cs
public class MessageSender 
{ 
  private MessageStrategy _messageStrategy; 
  public void SetMessageStrategy(MessageStrategy messageStrategy) 
  { 
    _messageStrategy = messageStrategy; 
  } 

  public void SendMessage(Message message) 
  { 
    _messageStrategy.SendMessage(message); 
  } 

} 

```

从主程序中，我们可以使用`MessageSender`，如下所示：

```cs
static void Main(string[] args) 
{ 
  MessageSender sender = new MessageSender(); 
  sender.SetMessageStrategy(new EmailMessage()); 
  sender.SendMessage(new Message { MessageID = 1, MessageTo = "jason@tfx.com", 
  MessageFrom = "donotreply@tfx.com", MessageBody = "Hello readers", 
  MessageSubject = "Chapter 5" }); 
}
```

# Liskov 原则

根据 Liskov 原则，通过基类对象使用派生类引用的函数必须符合基类的行为。

这意味着子类不应该删除基类的行为，因为这违反了它的不变性。通常，调用代码应该完全依赖于基类中公开的方法，而不知道其派生实现。

让我们举一个例子，首先违反 Liskov 原则的定义，然后修复它以了解它特别设计用于什么：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-hiperf/img/00060.gif)

`IMultiFunctionPrinter`接口公开了两种方法，如下所示：

```cs
public interface IMultiFunctionPrinter 
{ 
  void Print(); 
  void Scan(); 
}
```

这是一个可以由不同类型的打印机实现的接口。以下是实现`IMultiFunctionPrinter`接口的两种打印机，它们分别是：

```cs
public class OfficePrinter: IMultiFunctionPrinter 
{ 
  //Office printer can print the page 
  public void Print() { } 
  //Office printer can scan the page 
  public void Scan() { } 
} 

public class DeskjetPrinter : IMultiFunctionPrinter 
{ 
  //Deskjet printer print the page 
  public void Print() { } 
  //Deskjet printer does not contain this feature 
  public void Scan() => throw new NotImplementedException(); 
}
```

在前面的实现中，我们有一个提供打印和扫描功能的`OfficePrinter`，而另一个家用`DeskjetPrinter`只提供打印功能。当调用`Scan`方法时，`DeskjetPrinter`实际上违反了 Liskov 原则，因为它会抛出`NotImplementedException`。

作为对前面问题的补救，我们可以将`IMultiFunctionPrinter`拆分为两个接口，即`IPrinter`和`IScanner`，而`IMultiFunctionPrinter`也可以实现这两个接口以支持两种功能。`DeskjetPrinter`只实现了`IPrinter`接口，因为它不支持扫描：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-hiperf/img/00061.gif)

这是三个接口`IPrinter`，`IScanner`和`IMultiFunctionPrinter`的代码：

```cs
public interface IPrinter 
{ 
  void Print(); 
} 

public interface IScanner 
{ 
  void Scanner(); 
} 

public interface MultiFunctionPrinter : IPrinter, IScanner 
{  

} 
```

最后，具体实现将如下所示：

```cs
public class DeskjetPrinter : IPrinter 
{ 
  //Deskjet printer print the page 
  public void Print() { } 
} 

public class OfficePrinter: IMultiFunctionPrinter 
{ 
  //Office printer can print the page 
  public void Print() { } 
  //Office printer can scan the page 
  public void Scan() { } 
}
```

# 接口隔离原则

接口隔离原则规定，客户端代码只应依赖于客户端使用的东西，不应依赖于他们不使用的任何东西。这意味着你不能强迫客户端代码依赖于不需要的某些方法。

让我们举一个首先违反接口隔离原则的例子：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-hiperf/img/00062.gif)

在前面的图表中，我们有一个包含两种方法`WriteLog`和`GetLogs`的 ILogger 接口。`ConsoleLogger`类将消息写入应用程序控制台窗口，而`DatabaseLogger`类将消息存储到数据库中。`ConsoleLogger`在控制台窗口上打印消息并不持久化它；对于`GetLogs`方法，它抛出`NotImplementedException`，因此违反了接口隔离原则。

这是前面问题的代码：

```cs
public interface ILogger 
{ 
  void WriteLog(string message); 
  List<string> GetLogs(); 
} 

/// <summary> 
/// Logger that prints the information on application console window 
/// </summary> 
public class ConsoleLogger : ILogger 
{ 
  public List<string> GetLogs() => throw new NotImplementedException(); 
  public void WriteLog(string message) 
  { 
    Console.WriteLine(message); 
  } 
} 

/// <summary> 
/// Logger that writes the log into database and persist them 
/// </summary> 
public class DatabaseLogger : ILogger 
{ 
  public List<string> GetLogs() 
  { 
    //do some work to get logs stored in database, as the actual code 
    //in not written so returning null 
    return null;  
  } 
  public void WriteLog(string message) 
  { 
    //do some work to write log into database 
  } 
}
```

为了遵守**接口隔离原则**（**ISP**），我们分割了 ILogger 接口，并使其更精确和相关于其他实现者。ILogger 接口将仅包含`WriteLog`方法，并引入了一个新的`IPersistenceLogger`接口，它继承了 ILogger 接口并提供了`GetLogs`方法：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-hiperf/img/00063.gif)

以下是修改后的示例，如下所示：

```cs
public interface ILogger 
{ 
  void WriteLog(string message); 

} 

public interface PersistenceLogger: ILogger 
{ 
  List<string> GetLogs(); 
} 

/// <summary> 
/// Logger that prints the information on application console window 
/// </summary> 
public class ConsoleLogger : ILogger 
{ 
  public void WriteLog(string message) 
  { 
    Console.WriteLine(message); 
  } 
} 

/// <summary> 
/// Logger that writes the log into database and persist them 
/// </summary> 
public class DatabaseLogger : PersistenceLogger 
{ 
  public List<string> GetLogs() 
  { 
    //do some work to get logs stored in database, as the actual code 
    //in not written so returning null 
    return null; 
  } 
  public void WriteLog(string message) 
  { 
    //do some work to write log into database 
  } 
}
```

# 依赖倒置原则

依赖倒置原则规定，高级模块不应依赖于低级模块，它们两者都应该依赖于抽象。

软件应用程序包含许多类型的依赖关系。依赖关系可以是框架依赖关系、第三方库依赖关系、Web 服务依赖关系、数据库依赖关系、类依赖关系等。根据依赖倒置原则，这些依赖关系不应该紧密耦合在一起。

例如，在分层架构方法中，我们有一个表示层，其中定义了所有视图；服务层公开了表示层使用的某些方法；业务层包含系统的核心业务逻辑；数据库层定义了后端数据库连接器和存储库类。将其视为 ASP.NET MVC 应用程序，其中控制器调用服务，服务引用业务层，业务层包含系统的核心业务逻辑，并使用数据库层对数据库执行 CRUD（创建、读取、更新和删除）操作。依赖树将如下所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-hiperf/img/00064.gif)

根据依赖倒置原则，不建议直接从每个层实例化对象。这会在层之间创建紧密耦合。为了打破这种耦合，我们可以通过接口或抽象类实现抽象化。我们可以使用一些实例化模式，如工厂或依赖注入来实例化对象。此外，我们应该始终使用接口而不是类。假设在我们的服务层中，我们引用了我们的业务层，并且我们的服务契约正在使用`EmployeeManager`来执行一些 CRUD 操作。`EmployeeManager`包含以下方法：

```cs
public class EmployeeManager 
{ 

  public List<Employee> GetEmployees(int id) 
  { 
    //logic to Get employees 
    return null; 
  } 
  public void SaveEmployee(Employee emp) 
  { 
    //logic to Save employee 
  } 
  public void DeleteEmployee(int id) 
  { 
    //Logic to delete employee 
  } 

} 
```

在服务层中，我们可以使用 new 关键字实例化业务层`EmployeeManager`对象。在`EmployeeManager`类中添加更多方法将直接基于访问修饰符在服务层中使用。此外，对现有方法的任何更改都将破坏服务层代码。如果我们将接口暴露给服务层并使用一些工厂或**依赖注入**（**DI**）模式，它将封装底层实现并仅暴露所需的方法。

以下代码显示了从`EmployeeManager`类中提取出`IEmployeeManager`接口：

```cs
public interface IEmployeeManager 
{ 
  void DeleteEmployee(int id); 
  System.Collections.Generic.List<Employee> GetEmployees(int id); 
  void SaveEmployee(Employee emp); 
}
```

考虑到上述示例，我们可以使用依赖注入来注入类型，因此每当服务管理器被调用时，业务管理器实例将被初始化。

# 缓存

缓存是可以用来提高应用程序性能的最佳实践之一。它通常与数据一起使用，其中更改不太频繁。有许多可用的缓存提供程序，我们可以考虑使用它们来保存数据并在需要时检索数据。它比数据库操作更快。在 ASP.NET Core 中，我们可以使用内存缓存，它将数据存储在服务器的内存中，但对于部署到多个地方的 Web 农场或负载平衡场景，建议使用分布式缓存。Microsoft Azure 还提供了 Redis 缓存，它是一个分布式缓存，提供了一个端点，可以用来在云上存储值，并在需要时检索。

要在 ASP.NET Core 项目中使用内存缓存，我们可以简单地在`ConfigureServices`方法中添加内存缓存，如下所示：

```cs
public void ConfigureServices(IServiceCollection services) 
{ 
  services.AddMvc(); 
  services.AddMemoryCache(); 
}
```

然后，我们可以通过依赖注入在我们的控制器或页面模型中注入`IMemoryCache`，并使用`Set`和`Get`方法设置或获取值。

# 数据结构

选择正确的数据结构在应用程序性能中起着至关重要的作用。在选择任何数据结构之前，强烈建议考虑它是否是一种负担，或者它是否真正解决了特定的用例。在选择适当的数据结构时需要考虑的一些关键因素如下：

+   了解您需要存储的数据类型

+   了解数据增长的方式以及在增长时是否存在任何缺点

+   了解是否需要通过索引或键/值对访问数据，并选择适当的数据结构

+   了解是否需要同步访问，并选择线程安全的集合

选择正确的数据结构时还有许多其他因素，这些因素已经在第四章中涵盖，*C#中的数据结构和编写优化代码。*

# 通信

如今，通信已经成为任何应用程序中的重要缩影，主要因素是技术的快速发展。诸如基于 Web 的应用程序、移动应用程序、物联网应用程序和其他分布式应用程序在网络上执行不同类型的通信。我们可以以一个应用程序为例，该应用程序在某个云实例上部署了 Web 前端，调用了云中另一个实例上部署的某个服务，并对本地托管的数据库执行一些后端连接。此外，我们可以有一个物联网应用程序，通过互联网调用某个服务发送室温，等等。设计分布式应用程序时需要考虑的某些因素如下：

# 使用轻量级接口

避免多次往返服务器造成更多的网络延迟，降低应用程序性能。使用工作单元模式避免向服务器发送冗余操作，并执行一次单一操作以与后端服务通信。工作单元将所有消息分组为一个单元并将它们作为一个单元进行处理。

# 最小化消息大小

尽量减少与服务通信的数据量。例如，有一个 Person API 提供一些`GET`、`POST`、`PUT`和`DELETE`方法来对后端数据库执行 CRUD 操作。要删除一个人的记录，我们可以只传递该人的`ID`（主键）作为参数传递给服务，而不是将整个对象作为参数传递。此外，使用少量属性或方法的对象，提供最小的工件集。最好的情况是使用**POCO**（**Plain Old CLR object**）实体，它们对其他对象的依赖性很小，只包含必须发送到网络的属性。

# 排队通信

对于较大的对象或复杂操作，将单一的请求/响应通道与分布式消息通道解耦会提高应用程序的性能。对于大型、笨重的操作，我们可以将通信设计和分发到多个组件中。例如，有一个网站调用一个服务来上传图像，一旦上传完成，它会进行一些处理以提取缩略图并将其保存在数据库中。一种方法是在单个调用中同时进行上传和处理，但有时当用户上传较大的图像或图像处理需要更长时间时，用户可能会遇到请求超时异常，请求将终止。

通过排队架构，我们可以将这两个操作分开进行。用户上传图像，该图像将保存在文件系统中，并且图像路径将保存到存储中。后台运行的服务将获取该文件并异步进行处理。与此同时，当后端服务在处理时，控制权将返回给用户，用户可以看到一些正在进行的通知。最后，当缩略图生成时，用户将收到通知：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-hiperf/img/00065.jpeg)

# 资源管理

每台服务器都有一组有限的资源。无论服务器规格多么好，如果应用程序没有设计成以高效的方式利用资源，就会导致性能问题。在设计.NET Core 应用程序时，有一些需要注意的最佳实践来最大程度地利用服务器资源。

# 避免线程的不当使用

为每个任务创建一个新线程，而不监视或中止线程的生命周期是一种不好的做法。线程适合执行多任务和利用服务器的多个资源并行运行。然而，如果设计是为每个请求创建线程，这会减慢应用程序的性能，因为 CPU 在线程之间切换的上下文中花费的时间比执行实际工作更多。

每当使用线程时，我们应该尽量保持一个共享的线程池，任何需要执行的新项目都会在队列中等待，如果线程忙碌，则在可用时获取。这样，线程管理就变得简单，服务器资源也会被有效利用。

# 及时释放对象

**CLR**（**公共语言运行时**）提供自动内存管理，使用 new 关键字实例化的对象不需要显式进行垃圾回收；**GC**（**垃圾回收**）会处理。然而，非托管资源不会被 GC 自动释放，应该通过实现`IDisposable`接口来显式进行回收。这些资源可能是数据库连接、文件处理程序、套接字等。要了解更多关于在.NET Core 中处理非托管资源的信息，请参考第六章，*在.NET Core 中的内存管理技术*。

# 在需要时获取资源

只有在需要时才获取资源。提前实例化对象不是一个好的做法。这会占用不必要的内存并利用系统资源。此外，使用*try*、*catch*和*finally*来阻塞和释放*finally*块中的对象。这样，如果发生任何异常，方法内部实例化的对象将被释放。

# 并发

在并发编程中，许多对象可能同时访问同一资源，保持它们线程安全是主要目标。在.NET Core 中，我们可以使用锁来提供同步访问。然而，有些情况下，线程必须等待较长时间才能访问资源，这会导致应用程序无响应。

最佳实践是仅对那些需要线程安全的特定代码行应用同步访问，例如可以使用锁的地方，这些是数据库操作、文件处理、银行账户访问以及应用程序中许多其他关键部分。这些需要同步访问，以便一次处理一个线程。

# 总结

编写更清洁的代码，遵循架构和设计原则，并遵循最佳实践在应用程序性能中起着重要作用。如果代码臃肿和重复，会增加错误的机会，增加复杂性，并影响性能。

在本章中，我们学习了一些编码原则，使应用程序代码看起来更清晰，更容易理解。如果代码干净，它可以让其他开发人员完全理解，并在许多其他方面提供帮助。随后，我们学习了一些被认为是设计应用程序时的核心原则的基本设计原则。诸如 KISS、YAGNI、DRY、关注分离和 SOLID 等原则在软件设计中非常重要，缓存和选择正确的数据结构对性能有重大影响，如果使用得当可以提高性能。最后，我们学习了一些在处理通信、资源管理和并发时应考虑的最佳实践。

下一章是对内存管理的详细介绍，在这里我们将探讨.NET Core 中的一些内存管理技术。


# 第六章：.NET Core 中的内存管理技术

内存管理显著影响任何应用程序的性能。当应用程序运行时，.NET CLR（公共语言运行时）在内存中分配许多对象，并且它们会一直保留在那里，直到它们不再需要，直到创建新对象并分配空间，或者直到 GC 运行（偶尔会运行）以释放未使用的对象，并为其他对象提供更多空间。大部分工作由 GC 自己完成，它会智能地运行并通过删除不需要的对象来释放空间。然而，有一些实践可以帮助任何应用程序避免性能问题并平稳运行。

在第二章，*了解.NET Core 内部和性能测量*中，我们已经了解了垃圾回收的工作原理以及在.NET 中如何维护代。在本章中，我们将专注于一些推荐的最佳实践和模式，以避免内存泄漏并使应用程序性能良好。

我们将学习以下主题：

+   内存分配过程概述

+   通过 SOS 调试分析内存

+   内存碎片化

+   避免终结器

+   在.NET Core 中最佳的对象处理实践

# 内存分配过程概述

内存分配是应用程序运行时在内存中分配对象的过程。这是由**公共语言运行时**（**CLR**）完成的。当对象被初始化（使用`new`关键字）时，GC 会检查代是否达到阈值并执行垃圾回收。这意味着当系统内存达到其限制时，将调用 GC。当应用程序运行时，GC 寄存器本身会接收有关系统内存的事件通知，当系统达到特定限制时，它会调用垃圾回收。

另一方面，我们也可以使用`GC.Collect`方法以编程方式调用 GC。然而，由于 GC 是一个高度调优的算法，并且根据内存分配模式自动行为，显式调用可能会影响性能，因此强烈建议在生产中不要使用它。

# 通过.NET Core 中的 SOS 调试器分析 CLR 内部

SOS 是一个随 Windows 一起提供并且也适用于 Linux 的调试扩展。它通过提供有关 CLR 内部的信息，特别是内存分配、创建的对象数量以及有关 CLR 的其他详细信息，来帮助调试.NET Core 应用程序。我们可以在.NET Core 中使用 SOS 扩展来调试特定于每个平台的本机机器代码。

要在 Windows 上安装 SOS 扩展，需要从[`developer.microsoft.com/en-us/windows/hardware/download-kits-windows-hardware-development`](https://developer.microsoft.com/en-us/windows/hardware/download-kits-windows-hardware-development)安装**Windows Driver Kit**（**WDK**）。

安装了 Windows Driver Kit 后，我们可以使用各种命令来分析应用程序的 CLR 内部，并确定在堆中占用最多内存的对象，并相应地对其进行优化。

我们知道，在.NET Core 中，不会生成可执行文件，我们可以使用*dotnet cli*命令来执行.NET Core 应用程序。运行.NET Core 应用程序的命令如下：

+   `dotnet run`

+   `dotnet applicationpath/applicationname.dll`

我们可以运行上述任一命令来运行.NET Core 应用程序。对于 ASP.NET Core 应用程序，我们可以转到应用程序文件夹的根目录，其中包括`Views`、`wwwroot`、`Models`、`Controllers`和其他文件，并运行以下命令：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-hiperf/img/00066.gif)

另一方面，调试工具通常需要`.exe`文件或进程 ID 来转储与 CLR 内部相关的信息。要运行 SOS 调试器，我们可以转到 Windows Driver Kit 安装的路径（目录路径将是`{driveletter}:Program Files (x86)Windows Kits10Debuggersx64`），并运行以下命令：

```cs
windbg dotnet {application path}
```

以下是一个截图，显示了如何使用`windbg`命令运行 ASP.NET Core 应用程序：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-hiperf/img/00067.gif)

一旦你运行了上述命令，它会打开 Windbg 窗口和调试器，如下所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-hiperf/img/00068.jpeg)

你可以通过点击 Debug | Break 来停止调试器，并运行`SOS`命令来加载.NET Core CLR 的信息。

从 Windbg 窗口执行以下命令，然后按*Enter*：

```cs
.loadby sos coreclr
```

以下截图是一个界面，你可以在其中输入并运行上述命令：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-hiperf/img/00069.jpeg)

最后，我们可以运行`!DumpHeap`命令来查看对象堆的完整统计细节：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-hiperf/img/00070.gif)

在上述截图中，如下截图所示的前三列，代表每个方法的`地址`、`方法`表和`大小`：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-hiperf/img/00071.jpeg)

利用上述信息，它提供了按类型对堆上存储的对象进行分类的统计信息。`MT`是该类型的方法表，`Count`是该类型实例的总数，`TotalSize`是所有该类型实例占用的总内存大小，`Classname`代表在堆上占用该空间的实际类型。

还有一些其他命令，我们可以使用来获取特定的细节，列举如下：

| **开关** | **命令** | **描述** |
| --- | --- | --- |
| **统计信息** | `!DumpHeap -stat` | 仅显示统计细节 |
| **类型** | `!DumpHeap -type TypeName` | 显示堆上存储的特定类型的统计信息 |
| **Finalization queue** | `!FinalizationQueue` | 显示有关终结器的详细信息 |

这个工具帮助开发人员调查对象在堆上的分配情况。在实际场景中，我们可以在后台运行这个工具，运行我们的应用程序在测试或暂存服务器上，并检查关于堆上存储的对象的详细统计信息。

# 内存碎片化

内存碎片化是.NET 应用程序性能问题的主要原因之一。当对象被实例化时，它占用内存空间，当它不再需要时，它被垃圾回收，分配的内存块变得可用。当对象被分配了一个相对于该内存段/块中可用大小更大的空间，并等待空间变得可用时，就会发生这种情况。内存碎片化是一个问题，当大部分内存分配在较多的非连续块中时发生。当较大大小的对象存储或占用较大的内存块，而内存只包含较小的可用空闲块时，这会导致碎片化，系统无法在内存中分配该对象。

.NET 维护两种堆，即**小对象堆**（SOH）和**大对象堆**（LOH）。大于 85,000 字节的对象存储在 LOH 中。SOH 和 LOH 之间的关键区别在于 LOH 中没有 GC 进行的压缩。压缩是在垃圾回收时进行的过程，其中存储在 SOH 中的对象被移动以消除可用的较小空间块，并增加总可用空间，作为其他对象可以使用的一种大内存块的形式，从而减少碎片化。然而，在 LOH 中，GC 没有隐式地进行压缩。大小较大的对象存储在 LOH 中并创建碎片化问题。此外，如果我们将 LOH 与 SOH 进行比较，LOH 的压缩成本适度高，并涉及显着的开销，GC 需要两倍的内存空间来移动对象进行碎片整理。这也是为什么 LOH 不会被 GC 隐式地进行碎片整理的另一个原因。

以下是内存碎片的表示，其中白色块代表未分配的内存空间，后面跟着一个已分配的块：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-hiperf/img/00072.gif)

假设一个大小为 1.5 MB 的对象想要分配一些内存。即使总可用内存量为 1.8 MB，它也找不到任何可用的空间。这是由于内存碎片：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-hiperf/img/00073.jpeg)

另一方面，如果内存被碎片化，对象可以轻松使用可用的空间并被分配：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-hiperf/img/00074.jpeg)

在.NET Core 中，我们可以使用`GCSettings`显式地在 LOH 中执行压缩，如下所示：

```cs
GCSettings.LargeObjectHeapCompactionMode = GCLargeObjectHeapCompactionMode.CompactOnce; 
GC.Collect(); 
```

# 避免使用终结器

在.NET Core 应用程序中使用终结器不是一个好的实践。使用终结器的对象会在内存中停留更长时间，最终影响应用程序的性能。

在特定时间点，应用程序不需要的对象会留在内存中，以便调用它们的`Finalizer`方法。例如，如果 GC 认为对象在第 0 代中已经死亡，它将始终存活在第 1 代中。

在.NET Core 中，CLR 维护一个单独的线程来运行`Finalizer`方法。包含`Finalizer`方法的所有对象都被放置到终结队列中。应用程序不再需要的任何对象都被放置在 F-Reachable 队列中，然后由专用的终结线程执行。

以下图表显示了一个包含`Finalizer`方法的`object1`对象。`Finalizer`方法被放置在终结队列中，对象占据了 Gen0（第 0 代）堆中的内存空间：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-hiperf/img/00075.jpeg)

当对象不再需要时，它将从 Gen0（第 0 代）移动到 Gen1（第 1 代），并从终结队列移动到 F-Reachable 队列*：*

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-hiperf/img/00076.jpeg)

一旦终结线程在 F-Reachable 队列中运行方法，它将被 GC 从内存中移除。

在.NET Core 中，终结器可以定义如下：

```cs
public class FileLogger 
{ 
  //Finalizer implementation 
   ~FileLogger() 
  { 
    //dispose objects 
  } 
} 
```

通常，此方法用于处理非托管对象并包含一些代码。然而，代码可能包含影响性能的错误。例如，我们有三个对象排队在终结队列中，然后等待第一个对象被终结线程释放，以便它们可以被处理。现在，假设第一个`Finalizer`方法中存在问题并延迟了终结线程的返回和处理其余的方法。过一段时间，更多的对象将进入终结队列并等待终结线程处理，影响应用程序的性能。

处理对象的最佳实践是使用`IDisposable`接口而不是实现`Finalizer`方法。如果出于某种原因使用`Finalizer`方法，最好也实现`IDisposable`接口，并通过调用`GC.SuppressFinalize`方法来抑制终结。

# .NET Core 中释放对象的最佳实践

我们已经在前一节中学习了在.NET Core 中对象的处理是由 GC 自动完成的。然而，在您的代码中处理对象始终是一个良好的实践，并且在处理非托管对象时强烈推荐。在本节中，我们将探讨一些在.NET Core 中编写代码时可以用来释放对象的最佳实践。

# IDisposable 接口简介

`IDisposable`是一个简单的接口，包含一个`Dispose`方法，不带参数，并返回`void`：

```cs
public interface IDisposable 
{ 
  void Dispose(); 
} 
```

它用于释放非托管资源。因此，如果任何类实现了`IDisposable`接口，这意味着该类包含非托管资源，这些资源必须通过调用类的`Dispose`方法来释放。

# 什么是非托管资源？

任何超出应用程序边界的资源都被视为非托管资源。它可能是数据库、文件系统、Web 服务或类似的资源。为了访问数据库，我们使用托管的.NET API 来打开或关闭连接并执行各种命令。但是，实际的数据库连接是不受管理的。文件系统和 Web 服务也是如此，我们使用托管的.NET API 与它们交互，但它们在后台使用非托管资源。`IDisposable`接口是所有这些情况的最佳选择。

# 使用 IDisposable

这里有一个简单的`DataManager`类，它使用`System.Data.SQL` API 在 SQL 服务器数据库上执行数据库操作：

```cs
public class DataManager : IDisposable 
{ 
  private SqlConnection _connection; 

  //Returns the list of users from database 
  public DataTable GetUsers() 
  { 
    //Invoke OpenConnection to instantiate the _connection object 

    OpenConnection(); 

    //Executing command in a using block to dispose command object 
    using(var command =new SqlCommand()) 
    { 
      command.Connection = _connection; 
      command.CommandText = "Select * from Users"; 

      //Executing reader in a using block to dispose reader object 
      using (var reader = command.ExecuteReader()) 
      { 
        var dt = new DataTable(); 
        dt.Load(reader); 
        return dt; 
      } 

    } 
  } 
  private void OpenConnection() 
  { 
    if (_connection == null) 
    { 
      _connection = new SqlConnection(@"Integrated Security=SSPI;
      Persist Security Info=False;Initial Catalog=SampleDB;
      Data Source=.sqlexpress"); 
      _connection.Open(); 
    } 
  } 

  //Disposing _connection object 
  public void Dispose() { 
    Console.WriteLine("Disposing object"); 
    _connection.Close(); 
    _connection.Dispose(); 
  } 
} 
```

在前面的代码中，我们已经实现了`IDisposable`接口，该接口又实现了`Dispose`方法来清理 SQL 连接对象。我们还调用了连接的`Dispose`方法，这将在管道中链接该过程并关闭底层对象。

从调用程序中，我们可以使用`using`块来实例化`DatabaseManager`对象，该对象在调用`GetUsers`方法后调用`Dispose`方法：

```cs
static void Main(string[] args) 
{ 
  using(DataManager manager=new DataManager()) 
  { 
    manager.GetUsers(); 
  } 
} 
```

`using`块是 C#的一个构造，由编译器渲染为`try finally`块，并在`finally`块中调用`Dispose`方法。这意味着当您使用`using`块时，我们不必显式调用`Dispose`方法。另外，前面的代码也可以以以下方式编写，这种特定的代码格式由`using`块在内部管理：

```cs
static void Main(string[] args) 
{ 
  DataManager _manager; 
  try 
  { 
    _manager = new DataManager(); 
  } 
  finally 
  { 
    _manager.Dispose(); 
  } 
} 
```

# 何时实现 IDisposable 接口

我们已经知道，每当需要释放非托管资源时，应该使用`IDisposable`接口。但是，在处理对象的释放时，有一个标准规则应该被考虑。规则规定，如果类中的实例实现了`IDisposable`接口，我们也应该在使用该类时实现`IDisposable`。例如，前面的`DatabaseManager`类使用了`SqlConnection`，其中`SqlConnection`在内部实现了`IDisposable`接口。为了遵守这个规则，我们将实现`IDisposable`接口并调用实例的`Dispose`方法。

这里有一个更好的例子，它从`DatabaseManager Dispose`方法中调用`protected Dispose`方法，并传递一个表示对象正在被处理的`Boolean`值。最终，我们将调用`GC.SuppressFinalize`方法，告诉 GC 对象已经被清理，防止调用冗余的垃圾回收：

```cs
public void Dispose() { 
  Console.WriteLine("Disposing object"); 
  Dispose(true); 
  GC.SuppressFinalize(this); 
} 
protected virtual void Dispose(Boolean disposing) 
{ 
  if (disposing) 
  { 
    if (_connection != null) 
    { 
      _connection.Close(); 
      _connection.Dispose(); 
      //set _connection to null, so next time it won't hit this block 
      _connection = null; 
    } 
  } 
} 
}
```

我们将参数化的`Dispose`方法保持为`protected`和`virtual`，这样，如果从`DatabaseManager`类派生的子类可以重写`Dispose`方法并清理自己的资源。这确保了对象树中的每个类都将清理其资源。子类处理其资源并调用基类上的`Dispose`，依此类推。

# Finalizer 和 Dispose

`Finalizer`方法由 GC 调用，而`Dispose`方法必须由开发人员在程序中显式调用。GC 不知道类是否包含`Dispose`方法，并且需要在对象处置时调用以清理非托管资源。在这种情况下，我们需要严格清理资源而不是依赖调用者调用对象的`Dispose`方法时，应该实现`Finalizer`方法。

以下是实现`Finalizer`方法的`DatabaseManager`类的修改示例：

```cs
public class DataManager : IDisposable 
{ 
  private SqlConnection _connection; 
  //Returns the list of users from database 
  public DataTable GetUsers() 
  { 
    //Invoke OpenConnection to instantiate the _connection object 

    OpenConnection(); 

    //Executing command in a using block to dispose command object 
    using(var command =new SqlCommand()) 
    { 
      command.Connection = _connection; 
      command.CommandText = "Select * from Users"; 

      //Executing reader in a using block to dispose reader object 
      using (var reader = command.ExecuteReader()) 
      { 
        var dt = new DataTable(); 
        dt.Load(reader); 
        return dt; 
      } 
    } 
  } 
  private void OpenConnection() 
  { 
    if (_conn == null) 
    { 
      _connection = new SqlConnection(@"Integrated Security=SSPI;
      Persist Security Info=False;Initial Catalog=SampleDB;
      Data Source=.sqlexpress"); 
      _connection.Open(); 
    } 
  } 

  //Disposing _connection object 
  public void Dispose() { 
    Console.WriteLine("Disposing object"); 
    Dispose(true); 
    GC.SuppressFinalize(this); 
  } 

  private void Dispose(Boolean disposing) 
  { 
    if(disposing) { 
      //clean up any managed resources, if called from the 
      //finalizer, all the managed resources will already 
      //be collected by the GC 
    } 
    if (_connection != null) 
    { 
      _connection.Close(); 
      _connection.Dispose(); 
      //set _connection to null, so next time it won't hit this block 
      _connection = null; 
    } 

  } 

  //Implementing Finalizer 
  ~DataManager(){ 
    Dispose(false); 
  } 
}
Dispose method and added the finalizer using a destructor syntax, ~DataManager. When the GC runs, the finalizer is invoked and calls the Dispose method by passing a false flag as a Boolean parameter. In the Dispose method, we will clean up the connection object. During the finalization stage, the managed resources will already be cleaned up by the GC, so the Dispose method will now only clean up the unmanaged resources from the finalizer. However, a developer can explicitly dispose of objects by calling the Dispose method and passing a true flag as a Boolean parameter to clean up managed resources.
```

# 总结

本章重点是内存管理。我们学习了一些最佳实践，以及.NET 中内存管理的实际底层过程。我们探索了调试工具，开发人员可以使用它来调查堆上对象的内存分配。我们还学习了内存碎片化、终结器，以及如何通过实现`IDisposable`接口来实现清理资源的处理模式。

在下一章中，我们将创建一个遵循微服务架构的应用程序。微服务架构是一种高性能和可扩展的架构，可以帮助应用程序轻松扩展。接下来的章节将为您提供一个完整的理解，说明如何遵循最佳实践和原则开发应用程序。


# 第七章：在.NET Core 应用程序中保护和实施弹性

安全性和弹性是开发任何规模应用程序时应考虑的两个重要方面。安全性保护应用程序的机密信息，执行身份验证，并提供对安全内容的授权访问，而弹性在应用程序失败时保护应用程序，使其能够优雅地降级。弹性使应用程序高度可用，并允许应用程序在发生错误或处于故障状态时正常运行。它在微服务架构中被广泛使用，其中应用程序被分解为多个服务，并且每个服务与其他服务通信以执行操作。

在.NET Core 中有各种技术和库可用于实现安全性和弹性。在 ASP.NET Core 应用程序中，我们可以使用 Identity 来实现用户身份验证/授权，使用流行的 Polly 框架来实现诸如断路器、重试模式等模式。

在本章中，我们将讨论以下主题：

+   弹性应用程序简介

+   实施健康检查以监视应用程序性能

+   在 ASP.NET Core 应用程序中实施重试模式以重试瞬时故障上的操作

+   实施断路器模式以防止可能失败的调用

+   保护 ASP.NET Core 应用程序并使用 Identity 框架启用身份验证和授权

+   使用安全存储来存储应用程序机密

# 弹性应用程序简介

开发具有弹性作为重要因素的应用程序总是会让您的客户感到满意。今天，应用程序本质上是分布式的，并涉及大量的通信。当服务因网络故障而宕机或未能及时响应时，问题就会出现，这最终会导致客户操作终止之前的延迟。弹性的目的是使您的应用程序从故障中恢复，并使其再次响应。

当您调用一个服务，该服务调用另一个服务，依此类推时，复杂性会增加。在一长串操作中，考虑弹性是很重要的。这就是为什么它是微服务架构中最广泛采用的原则之一。

# 弹性政策

弹性政策分为两类：

+   反应性政策

+   积极的政策

在本章中，我们将使用 Polly 框架实施反应性和积极性政策，该框架可用于.NET Core 应用程序。

# 反应性政策

根据反应性政策，如果服务请求在第一次尝试时失败，我们应立即重试服务请求。要实施反应性政策，我们可以使用以下模式：

+   **重试**：在请求失败时立即重试

+   **断路器**：在故障状态下停止对服务的所有请求

+   **回退**：如果服务处于故障状态，则返回默认响应

# 实施重试模式

重试模式用于重试故障服务多次以获得响应。它在涉及服务之间的相互通信的场景中被广泛使用，其中一个服务依赖于另一个服务执行特定操作。当服务分别托管并通过网络进行通信时，最有可能是通过 HTTP 协议时，会发生瞬时故障。

以下图表示两个服务：一个用户注册服务，用于在数据库中注册和保存用户记录，以及一个电子邮件服务，用于向用户发送确认电子邮件，以便他们激活他们的帐户。假设电子邮件服务没有响应。这将返回某种错误，如果实施了重试模式，它将重试请求已实施的次数，并在失败时调用电子邮件服务：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-hiperf/img/00077.jpeg)

**用户注册服务**和**电子邮件服务**是 ASP.NET Core Web API 项目，其中用户注册实现了重试模式。我们将通过将其添加为 NuGet 包在用户注册服务中使用 Polly 框架。要添加 Polly，我们可以在 Visual Studio 的 NuGet 包管理器控制台窗口中执行以下命令：

```cs
Install-Package Polly
```

Polly 框架基于策略。您可以定义包含与您正在实现的模式相关的特定配置的策略，然后通过调用其`ExecuteAsync`方法来调用该策略。

这是包含实现重试模式以调用电子邮件服务的 POST 方法的`UserController`。

```cs
[Route("api/[controller]")] 
public class UserController : Controller 
{ 

  HttpClient _client; 
  public UserController(HttpClient client) 
  { 
    _client = client; 
  } 

  // POST api/values 
  [HttpPost] 
  public void Post([FromBody]User user) 
  { 

    //Email service URL 
    string emailService = "http://localhost:80/api/Email"; 

    //Serialize user object into JSON string 
    HttpContent content = new StringContent(JsonConvert.SerializeObject(user)); 

    //Setting Content-Type to application/json 
    _client.DefaultRequestHeaders 
    .Accept 
    .Add(new MediaTypeWithQualityHeaderValue("application/json")); 

    int maxRetries = 3; 

    //Define Retry policy and set max retries limit and duration between each retry to 3 seconds 
    var retryPolicy = Policy.Handle<HttpRequestException>().WaitAndRetryAsync(
    maxRetries, sleepDuration=> TimeSpan.FromSeconds(3)); 

    //Call service and wrap HttpClient PostAsync into retry policy 
    retryPolicy.ExecuteAsync(async () => { 
      var response =  _client.PostAsync(emailService, content).Result; 
      response.EnsureSuccessStatusCode(); 
    }); 

  }    
}
```

在前面的代码中，我们使用`HttpClient`类向电子邮件服务 API 发出 RESTful 请求。`HTTP POST`方法接收一个包含以下五个属性的用户对象：

```cs
public class User 
{ 
  public string FirstName { get; set; } 
  public string LastName { get; set; } 
  public string EmailAddress { get; set; }  
  public string UserName { get; set; } 
  public string Password { get; set; } 
}  
```

由于请求将以 JSON 格式发送，我们必须将`Content-Type`标头值设置为`application/json`。然后，我们必须定义重试策略以等待并重试每三秒一次的操作，最大重试次数为三次。最后，我们调用`ExecuteAsync`方法来调用`client.PostAsync`方法，以便调用电子邮件服务。

在运行上述示例后，如果电子邮件服务宕机或抛出异常，将重试三次以尝试获取所需的响应。

# 实施断路器

在调用通过网络通信的服务时，实现重试模式是一个很好的实践。然而，调用机制本身需要资源和带宽来执行操作并延迟响应。如果服务已经处于故障状态，不总是一个好的实践为每个请求重试多次。这就是断路器发挥作用的地方。

断路器有三种状态，如下图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-hiperf/img/00078.jpeg)

最初，断路器处于**关闭状态**，这意味着服务之间的通信正常工作，目标远程服务正在响应。如果目标远程服务失败，断路器将变为**打开状态**。当状态变为打开时，随后的所有请求都无法在特定的指定时间内调用目标远程服务，并直接将响应返回给调用者。一旦时间过去，断路器转为**半开状态**并尝试调用目标远程服务以获取响应。如果成功接收到响应，断路器将变回**关闭状态**，或者如果失败，状态将变回关闭并保持关闭，直到配置中指定的时间。

实现断路器模式，我们将使用相同的 Polly 框架，您可以从 NuGet 包中添加。我们可以按照以下方式添加断路器策略：

```cs
var circuitBreakerPolicy = Policy.HandleResult<HttpResponseMessage>(result => !result.IsSuccessStatusCode) 
  .CircuitBreakerAsync(3, TimeSpan.FromSeconds(10), OnBreak, OnReset, OnHalfOpen); 
```

在`Startup`类的`ConfigureServices`方法中添加上述断路器策略。将其定义在`Startup`类中的原因是通过**依赖注入**（**DI**）将断路器对象注入为单例对象。因此，所有请求将共享相同的实例，并且状态将得到适当维护。

在定义断路器策略时，我们将允许断开电路之前的事件数设置为三次，这将检查请求失败的次数，并在达到三次的阈值时断开电路。它将保持断路器在*打开*状态下 10 秒钟，然后在时间过去后的第一个请求到来时将状态更改为*半开*。

最后，如果远程服务仍然失败，断路器状态再次变为*Open*状态；否则，它将被设置为*Close*。我们还定义了`OnBreak`、`OnReset`和`OnHalfOpen`委托，当断路器状态改变时会被调用。如果需要，我们可以在数据库或文件系统中记录这些信息。在`Startup`类中添加这些委托方法：

```cs
private void OnBreak(DelegateResult<HttpResponseMessage> responseMessage, TimeSpan timeSpan) 
{ 
  //Log to file system 
} 
private void OnReset() 
{ 
  //log to file system 
} 
private void OnHalfOpen() 
{ 
  // log to file system 
}
```

现在，我们将在`Startup`类的`ConfigureServices`方法中使用 DI 添加`circuitBreakerPolicy`和`HttpClient`对象：

```cs
services.AddSingleton<HttpClient>(); 
  services.AddSingleton<CircuitBreakerPolicy<HttpResponseMessage>>(circuitBreakerPolgicy);
```

这是我们的`UserController`，它在参数化构造函数中接受`HttpClient`和`CircuitBreakerPolicy`对象：

```cs
public class UserController : Controller 
{ 
  HttpClient _client; 
  CircuitBreakerPolicy<HttpResponseMessage> _circuitBreakerPolicy; 
  public UserController(HttpClient client, 
  CircuitBreakerPolicy<HttpResponseMessage> circuitBreakerPolicy) 
  { 
    _client = client; 
    _circuitBreakerPolicy = circuitBreakerPolicy; 
  } 
} 
```

这是使用断路器策略并调用电子邮件服务的`HTTP POST`方法：

```cs
// POST api/values 
[HttpPost] 
public async Task<IActionResult> Post([FromBody]User user) 
{ 

  //Email service URL 
  string emailService = "http://localhost:80/api/Email"; 

  //Serialize user object into JSON string 
  HttpContent content = new StringContent(JsonConvert.SerializeObject(user)); 

  //Setting Content-Type to application/json 
  _client.DefaultRequestHeaders 
  .Accept 
  .Add(new MediaTypeWithQualityHeaderValue("application/json")); 

  //Execute operation using circuit breaker 
  HttpResponseMessage response = await _circuitBreakerPolicy.ExecuteAsync(() => 
  _client.PostAsync(emailService, content)); 

  //Check if response status code is success 
  if (response.IsSuccessStatusCode) 
  { 
    var result = response.Content.ReadAsStringAsync(); 
    return Ok(result); 
  } 

  //If the response status is not success, it returns the actual state 
  //followed with the response content 
  return StatusCode((int)response.StatusCode, response.Content.ReadAsStringAsync()); 
} 
```

这是经典的断路器示例。Polly 还提供了高级断路器，它在特定时间内基于失败请求的百分比来断开电路，这在需要在一定时间内处理大量事务的大型应用程序或涉及大量事务的应用程序中更有用。在一分钟内，有 2%到 5%的事务由于其他非瞬态故障问题而失败的可能性，因此我们不希望断路器中断。在这种情况下，我们可以实现高级断路器模式，并在我们的`ConfigureServices`方法中定义策略，如下所示：

```cs
public void ConfigureServices(IServiceCollection services) 
{ 

  var circuitBreakerPolicy = Policy.HandleResult<HttpResponseMessage>(
  result => !result.IsSuccessStatusCode) 
  .AdvancedCircuitBreaker(0.1, TimeSpan.FromSeconds(60),5, TimeSpan.FromSeconds(10), 
  OnBreak, OnReset, OnHalfOpen); 
  services.AddSingleton<HttpClient>(); 
  services.AddSingleton<CircuitBreakerPolicy<HttpResponseMessage>>(circuitBreakerPolicy); 
}
```

`AdvancedCircuitBreakerAsync`方法中的第一个参数包含了 0.1 的值，这是在指定的时间段内（60 秒）失败的请求的百分比，如第二个参数所指定的。第三个参数定义了值为 5，是在特定时间内（第二个参数为 60 秒）正在服务的请求的最小吞吐量。最后一个参数定义了如果任何请求失败并尝试再次服务请求的时间量，断路器保持打开状态的时间。其他参数只是在每个状态改变时调用的委托方法，与之前的经典断路器示例中的情况相同。

# 将断路器与重试包装起来

到目前为止，我们已经学习了如何使用 Polly 框架来使用和实现断路器和重试模式。重试模式用于在指定的时间内重试请求，如果请求失败，而断路器保持电路的状态，并根据失败请求的阈值打开电路，并停止调用远程服务一段时间，如配置中所指定的，以节省网络带宽。

使用 Polly 框架，我们可以将重试和断路器模式结合起来，并将断路器与重试模式包装在一起，以便在重试模式达到失败请求阈值限制的计数时打开断路器。

在本节中，我们将开发一个自定义的`HttpClient`类，该类提供`GET`、`POST`、`PUT`和`DELETE`等方法，并使用重试和断路器策略使其具有弹性。

创建一个新的`IResilientHttpClient`接口，并添加四个 HTTP `GET`、`POST`、`PUT`和`DELETE`方法：

```cs
public interface IResilientHttpClient 
{ 
  HttpResponseMessage Get(string uri); 

  HttpResponseMessage Post<T>(string uri, T item); 

  HttpResponseMessage Delete(string uri); 

  HttpResponseMessage Put<T>(string uri, T item); 
} 
```

现在，创建一个名为`ResilientHttpClient`的新类，该类实现了`IResilientHttpClient`接口。我们将添加一个参数化构造函数，以注入断路器策略和`HttpClient`对象，该对象将用于进行 HTTP `GET`、`POST`、`PUT`和`DELETE`请求。以下是`ResilientHttpClient`类的构造函数实现：

```cs
public class ResilientHttpClient : IResilientHttpClient 
{ 

  static CircuitBreakerPolicy<HttpResponseMessage> _circuitBreakerPolicy; 
  static Policy<HttpResponseMessage> _retryPolicy; 
  HttpClient _client; 

  public ResilientHttpClient(HttpClient client, 
  CircuitBreakerPolicy<HttpResponseMessage> circuitBreakerPolicy) 
  { 
    _client = client; 
    _client.DefaultRequestHeaders.Accept.Clear(); 
    _client.DefaultRequestHeaders.Accept.Add(
    new MediaTypeWithQualityHeaderValue("application/json")); 

    //circuit breaker policy injected as defined in the Startup class 
    _circuitBreakerPolicy = circuitBreakerPolicy; 

    //Defining retry policy 
    _retryPolicy = Policy.HandleResult<HttpResponseMessage>(x => 
    { 
      var result = !x.IsSuccessStatusCode; 
      return result; 
    })
    //Retry 3 times and for each retry wait for 3 seconds 
    .WaitAndRetry(3, sleepDuration => TimeSpan.FromSeconds(3)); 

  } 
} 
```

在前面的代码中，我们已经定义了`CircuitBreakerPolicy<HttpResponseMessage>`和`HttpClient`对象，它们是通过 DI 注入的。我们定义了重试策略，并将重试阈值设置为三次，每次重试都会在调用服务之前等待三秒钟。

```cs
ExecuteWithRetryandCircuitBreaker method:
```

```cs
//Wrap function body in Retry and Circuit breaker policies 
public HttpResponseMessage ExecuteWithRetryandCircuitBreaker(string uri, Func<HttpResponseMessage> func) 
{ 

  var res = _retryPolicy.Wrap(_circuitBreakerPolicy).Execute(() => func()); 
  return res; 
} 
```

我们将从我们的 GET、POST、PUT 和 DELETE 实现中调用此方法，并定义将在重试和断路器策略中执行的代码。

以下分别是 GET、POST、PUT 和 DELETE 方法的实现：

```cs
public HttpResponseMessage Get(string uri) 
{ 
  //Invoke ExecuteWithRetryandCircuitBreaker method that wraps the code 
  //with retry and circuit breaker policies 
  return ExecuteWithRetryandCircuitBreaker(uri, () => 
  { 
    try 
    { 
      var requestMessage = new HttpRequestMessage(HttpMethod.Get, uri); 
      var response = _client.SendAsync(requestMessage).Result; 
      return response; 
    }
    catch(Exception ex) 
    { 
      //Handle exception and return InternalServerError as response code 
      HttpResponseMessage res = new HttpResponseMessage(); 
      res.StatusCode = HttpStatusCode.InternalServerError;   
      return res; 
    } 
  }); 
} 

//To do HTTP POST request 
public HttpResponseMessage Post<T>(string uri, T item) 
{ 
  //Invoke ExecuteWithRetryandCircuitBreaker method that wraps the code 
  //with retry and circuit breaker policies 
  return ExecuteWithRetryandCircuitBreaker(uri, () => 
  { 
    try 
    { 
      var requestMessage = new HttpRequestMessage(HttpMethod.Post, uri); 

      requestMessage.Content = new StringContent(JsonConvert.SerializeObject(item), 
      System.Text.Encoding.UTF8, "application/json"); 

      var response = _client.SendAsync(requestMessage).Result; 

      return response; 

    }catch (Exception ex) 
    { 
      //Handle exception and return InternalServerError as response code 
      HttpResponseMessage res = new HttpResponseMessage(); 
      res.StatusCode = HttpStatusCode.InternalServerError; 
      return res; 
    } 
  }); 
} 

//To do HTTP PUT request 
public HttpResponseMessage Put<T>(string uri, T item) 
{ 
  //Invoke ExecuteWithRetryandCircuitBreaker method that wraps 
  //the code with retry and circuit breaker policies 
  return ExecuteWithRetryandCircuitBreaker(uri, () => 
  { 
    try 
    { 
      var requestMessage = new HttpRequestMessage(HttpMethod.Put, uri); 

      requestMessage.Content = new StringContent(JsonConvert.SerializeObject(item), 
      System.Text.Encoding.UTF8, "application/json"); 

      var response = _client.SendAsync(requestMessage).Result; 

      return response; 
    } 
    catch (Exception ex) 
    { 
    //Handle exception and return InternalServerError as response code 
    HttpResponseMessage res = new HttpResponseMessage(); 
    res.StatusCode = HttpStatusCode.InternalServerError; 
    return res; 
    } 

  }); 
} 

//To do HTTP DELETE request 
public HttpResponseMessage Delete(string uri) 
{ 
  //Invoke ExecuteWithRetryandCircuitBreaker method that wraps the code 
  //with retry and circuit breaker policies 
  return ExecuteWithRetryandCircuitBreaker(uri, () => 
  { 
    try 
    { 
      var requestMessage = new HttpRequestMessage(HttpMethod.Delete, uri); 

      var response = _client.SendAsync(requestMessage).Result; 

      return response; 

    } 
    catch (Exception ex) 
    { 
      //Handle exception and return InternalServerError as response code 
      HttpResponseMessage res = new HttpResponseMessage(); 
      res.StatusCode = HttpStatusCode.InternalServerError; 
      return res; 
    } 
  }); 

} 
```

最后，在我们的启动类中，我们将添加以下依赖项：

```cs
public void ConfigureServices(IServiceCollection services) 
{ 

  var circuitBreakerPolicy = Policy.HandleResult<HttpResponseMessage>(x=> { 
    var result = !x.IsSuccessStatusCode; 
    return result; 
  }) 
  .CircuitBreaker(3, TimeSpan.FromSeconds(60), OnBreak, OnReset, OnHalfOpen); 

   services.AddSingleton<HttpClient>(); 
   services.AddSingleton<CircuitBreakerPolicy<HttpResponseMessage>>(circuitBreakerPolicy); 

   services.AddSingleton<IResilientHttpClient, ResilientHttpClient>(); 
   services.AddMvc(); 
   services.AddSwaggerGen(c => 
   { 
     c.SwaggerDoc("v1", new Info { Title = "User Service", Version = "v1" }); 
   }); 
 } 
```

在我们的`UserController`类中，我们可以通过 DI 注入我们的自定义`ResilientHttpClient`对象，并修改 POST 方法，如下所示：

```cs
[Route("api/[controller]")] 
public class UserController : Controller 
{ 

  IResilientHttpClient _resilientClient; 

  HttpClient _client; 
  CircuitBreakerPolicy<HttpResponseMessage> _circuitBreakerPolicy; 
  public UserController(HttpClient client, IResilientHttpClient resilientClient) 
  { 
    _client = client; 
    _resilientClient = resilientClient; 

  } 

  // POST api/values 
  [HttpPost] 
  public async Task<IActionResult> Post([FromBody]User user) 
  { 

    //Email service URL 
    string emailService = "http://localhost:80/api/Email"; 

    var response = _resilientClient.Post(emailService, user); 
    if (response.IsSuccessStatusCode) 
    { 
      var result = response.Content.ReadAsStringAsync(); 
      return Ok(result); 
    } 

    return StatusCode((int)response.StatusCode, response.Content.ReadAsStringAsync()); 

  } 
} 
```

通过这种实现，当应用程序启动时，电路将最初关闭。当对`EmailService`进行请求时，如果服务没有响应，它将尝试三次调用服务，每个请求等待三秒。如果服务没有响应，电路将变为打开状态，并且对于所有后续请求，将停止调用电子邮件服务，并在 60 秒内将异常返回给用户，如断路器策略中指定的。60 秒后，下一个请求将发送到`EmailService`，并且断路器状态将变为半开放状态。如果它有响应，电路状态将再次变为关闭；否则，它将在接下来的 60 秒内保持打开状态。

# 带有断路器和重试的回退策略

Polly 还提供了一个回退策略，如果服务失败，它将返回一些默认响应。它可以与重试和断路器策略一起使用。回退的基本思想是向消费者发送默认响应，而不是在响应中返回实际错误。响应应该向用户提供一些与应用程序性质相关的有意义的信息。当您的服务被应用程序的外部消费者使用时，这是非常有益的。

我们可以修改上面的示例，并为重试和断路器异常添加回退策略。在`ResilientHttpClient`类中，我们将添加这两个变量：

```cs
static FallbackPolicy<HttpResponseMessage> _fallbackPolicy; 
static FallbackPolicy<HttpResponseMessage> _fallbackCircuitBreakerPolicy; 
```

接下来，我们将添加断路器策略来处理断路器异常，并返回带有我们自定义内容消息的`HttpResponseMessage`。在`ResilientHttpClient`类的参数化构造函数中添加以下代码：

```cs
_fallbackCircuitBreakerPolicy = Policy<HttpResponseMessage> 
.Handle<BrokenCircuitException>() 
.Fallback(new HttpResponseMessage(HttpStatusCode.OK) 
  { 
    Content = new StringContent("Please try again later[Circuit breaker is Open]") 
  } 
);
```

然后，我们将添加另一个回退策略，它将包装断路器以处理任何不是断路器异常的其他异常：

```cs
_fallbackPolicy = Policy.HandleResult<HttpResponseMessage>(r => r.StatusCode == HttpStatusCode.InternalServerError) 
.Fallback(new HttpResponseMessage(HttpStatusCode.OK) { 
  Content = new StringContent("Some error occured") 
}); 

```

最后，我们将修改`ExecuteWithRetryandCircuitBreaker`方法，并将重试和断路器策略包装在回退策略中，该策略将以 200 状态代码向用户返回通用消息：

```cs
public HttpResponseMessage ExecuteWithRetryandCircuitBreaker(string uri, Func<HttpResponseMessage> func) 
{ 

  PolicyWrap<HttpResponseMessage> resiliencePolicyWrap = 
  Policy.Wrap(_retryPolicy, _circuitBreakerPolicy); 

  PolicyWrap<HttpResponseMessage> fallbackPolicyWrap = 
  _fallbackPolicy.Wrap(_fallbackCircuitBreakerPolicy.Wrap(resiliencePolicyWrap)); 

  var res = fallbackPolicyWrap.Execute(() => func()); 
  return res; 
}
```

通过这种实现，用户将不会收到任何响应中的错误。内容包含实际错误，如下面从 Fiddler 中获取的快照所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-hiperf/img/00079.jpeg)

# 主动策略

根据主动策略，如果请求导致失败，我们应该主动响应。我们可以使用超时、缓存和健康检查等技术来主动监控应用程序的性能，并在发生故障时主动响应。

+   **超时**：如果请求花费的时间超过通常时间，它会结束请求

+   **缓存**：缓存先前的响应并在将来的请求中使用它们

+   **健康检查**：监控应用程序的性能，并在发生故障时调用警报

# 实施超时

超时是一种主动策略，在目标服务需要很长时间来响应的情况下适用，而不是让客户端等待响应，我们返回一个通用消息或响应。我们可以使用相同的 Polly 框架来定义超时策略，并且它也可以与我们之前学习的重试和断路器模式结合使用：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-hiperf/img/00080.jpeg)

在上图中，用户注册服务正在调用电子邮件服务发送电子邮件。现在，如果电子邮件服务在特定时间内没有响应，如超时策略中指定的，将引发超时异常。

要添加超时策略，请在`ResilientHttpClient`类中声明一个`_timeoutPolicy`变量：

```cs
static TimeoutPolicy<HttpResponseMessage> _timeoutPolicy; 
```

然后，添加以下代码来初始化超时策略：

```cs
_timeoutPolicy = Policy.Timeout<HttpResponseMessage>(1); 
```

最后，我们将包装超时策略并将其添加到`resiliencyPolicyWrap`中。以下是`ExecuteWithRetryandCircuitBreaker`方法的修改代码：

```cs
public HttpResponseMessage ExecuteWithRetryandCircuitBreaker(string uri, Func<HttpResponseMessage> func) 
{ 

  PolicyWrap<HttpResponseMessage> resiliencePolicyWrap = 
  Policy.Wrap(_timeoutPolicy, _retryPolicy, _circuitBreakerPolicy); 

  PolicyWrap<HttpResponseMessage> fallbackPolicyWrap = 
  _fallbackPolicy.Wrap(_fallbackCircuitBreakerPolicy.Wrap(resiliencePolicyWrap)); 

  var res = fallbackPolicyWrap.Execute(() => func()); 
  return res; 
} 
```

# 实施缓存

在进行网络请求或调用远程服务时，Polly 可用于缓存来自远程服务的响应，并提高应用程序响应时间的性能。Polly 缓存分为两种，即内存缓存和分布式缓存。我们将在本节中配置内存缓存。

首先，我们需要从 NuGet 添加另一个`Polly.Caching.MemoryCache`包。添加完成后，我们将修改我们的`Startup`类，并将`IPolicyRegistry`添加为成员变量：

```cs
private IPolicyRegistry<string> _registry; 
```

在`ConfigurationServices`方法中，我们将初始化注册表并通过 DI 将其添加为单例对象：

```cs
_registry = new PolicyRegistry();
services.AddSingleton(_registry);
```

在配置方法中，我们将定义缓存策略，该策略需要缓存提供程序和缓存响应的时间。由于我们使用的是内存缓存，我们将初始化内存缓存提供程序，并在策略中指定如下：

```cs
Polly.Caching.MemoryCache.MemoryCacheProvider memoryCacheProvider = new MemoryCacheProvider(memoryCache); 

CachePolicy<HttpResponseMessage> cachePolicy = Policy.Cache<HttpResponseMessage>(memoryCacheProvider, TimeSpan.FromMinutes(10)); 
```

最后，我们将在`ConfigurationServices`方法中初始化`cachepolicy`并将其添加到我们的注册表中。我们将我们的注册表命名为`cache`。

```cs
_registry.Add("cache", cachePolicy); 
```

修改我们的`UserController`类，并声明通用的`CachePolicy`如下：

```cs
CachePolicy<HttpResponseMessage> _cachePolicy;
```

现在，我们将修改我们的`UserController`构造函数，并添加通过 DI 注入的注册表。此注册表对象用于获取在`Configure`方法中定义的缓存。

以下是`UserController`类的修改后构造函数：

```cs
public UserController(HttpClient client, IResilientHttpClient resilientClient, IPolicyRegistry<string> registry) 
{ 
  _client = client; 
  // _circuitBreakerPolicy = circuitBreakerPolicy; 
  _resilientClient = resilientClient; 

  _cachePolicy = registry.Get<CachePolicy<HttpResponseMessage>>("cache"); 
} 
```

最后，我们将定义一个`GET`方法，调用另一个服务以获取用户列表并将其缓存在内存中。为了缓存响应，我们将使用缓存策略的`Execute`方法包装我们的自定义弹性客户端 GET 方法，如下所示：

```cs
[HttpGet] 
public async Task<IActionResult> Get() 
{ 
  //Specify the name of the Response. If the method is taking    
  //parameter, we can append the actual parameter to cache unique 
  //responses separately 
  Context policyExecutionContext = new Context($"GetUsers"); 

  var response = _cachePolicy.Execute(()=>   
  _resilientClient.Get("http://localhost:7637/api/users"), policyExecutionContext); 
  if (response.IsSuccessStatusCode) 
  { 
    var result = response.Content.ReadAsStringAsync(); 
    return Ok(result); 
  } 

  return StatusCode((int)response.StatusCode, response.Content.ReadAsStringAsync()); 
}
```

当请求返回时，它将检查缓存上下文是否为空或已过期，并且请求将被缓存 10 分钟。在此期间的所有后续请求将从内存缓存存储中读取响应。一旦缓存过期，根据设置的时间限制，它将再次调用远程服务并缓存响应。

# 实施健康检查

健康检查是积极策略的一部分，可以及时监控服务的健康状况。它们还允许您在任何服务未响应或处于故障状态时采取积极的行动。

在 ASP.NET Core 中，我们可以通过使用`HealthChecks`库轻松实现健康检查，该库可作为 NuGet 包使用。要使用`HealthChecks`，我们只需将以下 NuGet 包添加到我们的 ASP.NET Core MVC 或 Web API 项目中：

```cs
Microsoft.AspNetCore.HealthChecks
```

我们必须将此包添加到监视服务和需要监视健康状况的服务的应用程序中。

在用于检查服务健康状况的应用程序的`Startup`类的`ConfigureServices`方法中添加以下代码：

```cs
services.AddHealthChecks(checks => 
{ 
  checks.AddUrlCheck(Configuration["UserServiceURL"]); 
  checks.AddUrlCheck(Configuration["EmailServiceURL"]); 
}); 
```

在上述代码中，我们已添加了两个服务端点来检查健康状态。这些端点在`appsettings.json`文件中定义。

健康检查库通过`AddUrlCheck`方法检查指定服务的健康状况。但是，需要通过`Startup`类对需要由外部应用程序或服务监视健康状况的服务进行一些修改。我们必须将以下代码片段添加到所有服务中，以返回其健康状态：

```cs
services.AddHealthChecks(checks => 
{ 
  checks.AddValueTaskCheck("HTTP Endpoint", () => new 
  ValueTask<IHealthCheckResult>(HealthCheckResult.Healthy("Ok"))); 
});
```

如果它们的健康状况良好且服务正在响应，它将返回`Ok`。

最后，我们可以在监视应用程序中添加 URI，这将触发健康检查中间件来检查服务的健康状况并显示健康状态。我们必须添加`UseHealthChecks`并指定用于触发服务健康状态的端点：

```cs
public static IWebHost BuildWebHost(string[] args) => 
WebHost.CreateDefaultBuilder(args) 
.UseHealthChecks("/hc") 
.UseStartup<Startup>() 
.Build(); 
```

当我们运行我们的监视应用程序并访问 URI 时，例如`http://{base_address}/hc`以获取健康状态，如果所有服务都正常工作，我们应该看到以下响应：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-hiperf/img/00081.gif)

# 使用应用程序机密存储敏感信息

每个应用程序都有一些包含敏感信息的配置，例如数据库连接字符串、一些第三方提供商的密钥以及其他敏感信息，通常存储在配置文件或数据库中。将所有敏感信息进行安全保护，以保护这些资源免受入侵者的侵害，这总是一个更好的选择。Web 应用程序通常托管在服务器上，这些信息可以通过导航到服务器路径并访问文件来读取，尽管服务器始终具有受保护的访问权限，只有授权用户有资格访问数据。然而，将信息以明文形式存储并不是一个好的做法。

在.NET Core 中，我们可以使用 Secret Manager 工具来保护应用程序的敏感信息。Secret Manager 工具允许您将信息存储在`secrets.json`文件中，该文件不存储在应用程序文件夹本身中。相反，该文件保存在不同平台的以下路径：

```cs
Windows: %APPDATA%microsoftUserSecrets{userSecretsId}secrets.json
Linux: ~/.microsoft/usersecrets/{userSecretsId}/secrets.json
Mac: ~/.microsoft/usersecrets/{userSecretsId}/secrets.json
```

`{userSecretId}`是与您的应用程序关联的唯一 ID（GUID）。由于这保存在单独的路径中，每个开发人员都必须在自己的目录下的`UserSecrets`目录下定义或创建此文件。这限制了开发人员检入相同的文件到源代码控制中，并将信息保持分离到每个用户。有些情况下，开发人员使用自己的帐户凭据进行数据库认证，因此这有助于将某些信息与其他信息隔离开来。

从 Visual Studio 中，我们可以通过右键单击项目并选择管理用户机密选项来简单地添加`secrets.json`文件，如下所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-hiperf/img/00082.jpeg)

当您选择管理用户机密时，Visual Studio 会创建一个`secrets.json`文件并在 Visual Studio 中打开它，以 JSON 格式添加配置设置。如果您打开项目文件，您会看到`UserSecretsId`存储在项目文件中的条目：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-hiperf/img/00083.jpeg)

因此，如果您意外关闭了`secrets.json`文件，您可以从`UserSecretsId`是用户机密路径内的子文件夹中打开它，如上图所示。

以下是`secrets.json`文件的示例内容，其中包含日志信息、远程服务 URL 和连接字符串：

```cs
{ 
  "Logging": { 
    "IncludeScopes": false, 
    "Debug": { 
      "LogLevel": { 
        "Default": "Warning" 
      } 
    }, 
    "Console": { 
      "LogLevel": { 
        "Default": "Warning" 
      } 
    } 
  }, 
  "EmailServiceURL": "http://localhost:6670/api/values", 
  "UserServiceURL": "http://localhost:6546/api/user", 
  "ConnectionString": "Server=OVAISPC\sqlexpress;Database=FraymsVendorDB;
  User Id=sa;Password=P@ssw0rd;" 
} 

```

要在 ASP.NET Core 应用程序中访问此内容，我们可以在我们的`Startup`类中添加以下命名空间：

```cs
using Microsoft.Extensions.Configuration;
```

然后，注入`IConfiguration`对象并将其分配给`Configuration`属性：

```cs
public Startup(IConfiguration configuration) 
{ 
  Configuration = configuration; 
} 
public IConfiguration Configuration { get; } 
```

最后，我们可以使用`Configuration`对象访问变量，如下所示：

```cs
var UserServicesURL = Configuration["UserServiceURL"] 
services.AddEntityFrameworkSqlServer() 
.AddDbContext<VendorDBContext>(options => 
{ 
  options.UseSqlServer(Configuration["ConnectionString"], 
  sqlServerOptionsAction: sqlOptions => 
  { 
    sqlOptions.MigrationsAssembly(typeof(Startup)
    .GetTypeInfo().Assembly.GetName().Name); 
    sqlOptions.EnableRetryOnFailure(maxRetryCount: 10, 
    maxRetryDelay: TimeSpan.FromSeconds(30), errorNumbersToAdd: null); 
  }); 
}, ServiceLifetime.Scoped 
); 
} 
```

# 保护 ASP.NET Core API

保护 Web 应用程序是任何企业级应用程序的重要里程碑，不仅可以保护数据，还可以保护免受恶意网站的不同攻击。

在任何 Web 应用程序中，安全性都是一个重要因素的各种场景：

+   通过网络发送的信息包含敏感信息。

+   API 是公开暴露的，并且被用户用于执行批量操作。

+   API 托管在服务器上，用户可以使用一些工具进行数据包嗅探并读取敏感数据。

为了解决上述挑战并保护我们的应用程序，我们应该考虑以下选项：

# SSL（安全套接字层）

在传输或网络层添加安全性，当数据从客户端发送到服务器时，应该加密。**SSL**（安全套接字层）是在网络上传输信息的推荐方式。在 Web 应用程序中使用 SSL 加密从客户端浏览器发送到服务器的所有数据，在服务器级别解密。显然，这似乎会增加性能开销，但由于我们在今天的世界中拥有的服务器资源的规格，这似乎是相当可忽略的。

# 在 ASP.NET Core 应用程序中启用 SSL

在我们的 ASP.NET Core 项目中启用 SSL，我们可以在`Startup`类的`ConfigureServices`方法中定义的`AddMvc`方法中添加过滤器。过滤器用于过滤 HTTP 调用并采取某些操作：

```cs
services.AddMvc(options => 
{ 
  options.Filters.Add(new RequireHttpsAttribute()) 
}); 
launchSettings.json file to use the HTTPS port and enable SSL for our project. One way to do this is to enable SSL from the Debug tab in the Visual Studio project properties window, which is shown as follows:
```

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-hiperf/img/00084.jpeg)

这还修改了`launchSettings.json`文件并添加了 SSL。另一种方法是直接从`launchSetttings.json`文件本身修改端口号。以下是使用端口`44326`进行 SSL 的`launchsettings.json`文件，已添加到`iisSettings`下：

```cs
{ 
  "iisSettings": { 
    "windowsAuthentication": false, 
    "anonymousAuthentication": true, 
    "iisExpress": { 
      "applicationUrl": "http://localhost:3743/", 
      "sslPort": 44326 
    } 
  }, 
```

在上述代码中显示的默认 HTTP 端口设置为`*3743*`。由于在`AddMvc`中间件中，我们已经指定了一个过滤器来对所有传入请求使用 SSL。它将自动重定向到 HTTPS 并使用端口`44326`。

要在 IIS 上托管 ASP.NET Core，请参阅以下链接。网站运行后，可以通过 IIS 中的站点绑定选项添加 HTTPS 绑定：[`docs.microsoft.com/en-us/aspnet/core/host-and-deploy/iis/index?tabs=aspnetcore2x`](https://docs.microsoft.com/en-us/aspnet/core/host-and-deploy/iis/index?tabs=aspnetcore2x)

# 防止 CSRF（跨站点请求伪造）攻击

CSRF 是一种代表经过身份验证的用户执行未经请求的操作的攻击。由于攻击者无法伪造请求的响应，因此它主要涉及`HTTP POST`，`PUT`和`DELETE`方法，这些方法用于修改服务器上的数据。

ASP.NET Core 提供了内置令牌以防止 CSRF 攻击，您可以在向`Startup`类的`ConfigureServices`方法中添加 MVC 时自行添加`ValidateAntiForgeryTokenAttribute`过滤器。以下是向 ASP.NET Core 应用程序全局添加防伪标记的代码：

```cs
public void ConfigureServices(IServiceCollection services)
{
services.AddMvc(options => { options.Filters.Add(new ValidateAntiForgeryTokenAttribute()); });
 }
```

或者，我们还可以在特定的控制器操作方法上添加`ValidateAntyForgeryToken`。在这种情况下，我们不必在`Startup`类的`ConfigureServices`方法中添加`ValidateAntiForgeryTokenAttribute`过滤器。以下是保护`HTTP POST`操作方法免受 CSRF 攻击的代码：

```cs
[HttpPost]

[ValidateAntiForgeryToken]
public async Task<IActionResult> Submit()
{
  return View();
}
CORS (Cross Origin Security)
```

第二个选项是为经过身份验证的来源、标头和方法启用`CORS（跨源安全）`。设置 CORS 允许您的 API 仅从配置的来源访问。在 ASP.NET Core 中，可以通过添加中间件并定义其策略来轻松设置 CORS。

`ValidateAntiForgery`属性告诉 ASP.NET Core 将令牌放在表单中，当提交时，它会验证并确保令牌是有效的。这通过验证每个`HTTP POST`，`PUT`和其他 HTTP 请求的令牌来防止您的应用程序受到 CSRF 攻击，并保护表单免受恶意发布。

# 加强安全标头

许多现代浏览器提供了额外的安全功能。如果响应包含这些标头，浏览器运行您的站点时将自动启用这些安全功能。在本节中，我们将讨论如何在我们的 ASP.NET Core 应用程序中添加这些标头，并在浏览器中启用额外的安全性。

要调查我们的应用程序中缺少哪些标头，我们可以使用[www.SecurityHeaders.io](http://www.SecurityHeaders.io)网站。但是，要使用此功能，我们需要使我们的站点在互联网上公开访问。

或者，我们可以使用`ngrok`将 HTTP 隧道到我们的本地应用程序，从而使我们的站点可以从互联网访问。可以从以下链接下载`ngrok`工具：[`ngrok.com/download`](https://ngrok.com/download)。

您可以选择您拥有的操作系统版本并相应地下载特定的安装程序。

安装`ngrok`后，您可以打开它并运行以下命令。请注意，在执行以下命令之前，您的站点应在本地运行：

```cs
ngrok http -host-header localhost 7204
```

您可以将`localhost`替换为您的服务器 IP，将`7204`替换为应用程序侦听的端口。

运行上述命令将生成公共网址，如`Forwarding`属性中所指定的那样：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-hiperf/img/00085.jpeg)

我们现在可以在[www.securityheaders.io](http://www.securityheaders.io)中使用这个公共网址，扫描我们的网站并得到结果。它对网站进行分类，并提供从 A 到 F 的字母表，其中 A 是一个优秀的分数，表示网站包含所有安全标头，而 F 表示网站不安全且不包含安全标头。从默认模板生成的默认 ASP.NET Core 网站扫描得到 F 的分数，如下所示。它还显示了缺失的标头，用红色框起来：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-hiperf/img/00086.jpeg)

首先，我们应该在我们的网站上启用 HTTPS。要启用 HTTPS，请参阅与 SSL 相关的部分。接下来，我们将从 NuGet 添加`NWebsec.AspNetCore.Middleware`包，如下所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-hiperf/img/00087.jpeg)

NWebsec 提供了各种中间件，可以从`Startup`类的`Configure`方法中添加到我们的应用程序中。

# 添加 HTTP 严格传输安全标头

严格传输安全标头是一个出色的功能，通过获取用户代理并强制其使用 HTTPS 来加强**TLS**（传输层安全）的实现。我们可以通过在`Startup`类的`Configure`方法中添加以下中间件来添加严格传输安全标头：

```cs
app.UseHsts(options => options.MaxAge(days:365).IncludeSubdomains());
```

此中间件强制执行您的网站，以便在一年内只能通过 HTTPS 访问。这也适用于子域。

# 添加 X-Content-Type-Options 标头

此标头阻止浏览器尝试`MIME-sniff`内容类型，并强制其遵循声明的内容类型。我们可以在`Startup`类的`Configure`方法中添加此中间件，如下所示：

```cs
app.UseXContentTypeOptions();
```

# 添加 X-Frame-Options 标头

此标头允许浏览器保护您的网站免受在框架内呈现的攻击。通过使用以下中间件，我们可以防止我们的网站被框架化，从而可以防御不同的攻击，其中最著名的是点击劫持：

```cs
app.UseXfo(options => options.SameOrigin());
```

# 添加 X-Xss-Protection 标头

此标头允许浏览器在检测到跨站脚本攻击时停止页面加载。我们可以在`Startup`类的`Configure`方法中添加此中间件，如下所示：

```cs
app.UseXXssProtection(options => options.EnabledWithBlockMode());
```

# 添加内容安全策略标头

*内容安全策略*标头通过列入批准内容的来源并阻止浏览器加载恶意资源来保护您的应用程序。这可以通过从 NuGet 添加`NWebsec.Owin`包并在`Startup`类的`Configure`方法中定义来实现，如下所示：

```cs
app.UseCsp(options => options
.DefaultSources(s => s.Self())
.ScriptSources(s => s.Self()));
```

在上述代码中，我们已经提到了`DefaultSources`和`ScriptSources`，以从同一来源加载所有资源。如果有任何需要从外部来源加载的脚本或图像，我们可以定义自定义来源，如下所示：

```cs
app.UseCsp(options => options
  .DefaultSources(s => s.Self()).ScriptSources(s => s.Self().CustomSources("https://ajax.googleapis.com")));
```

有关此主题的完整文档，请参阅以下网址：[`docs.nwebsec.com/en/4.1/nwebsec/Configuring-csp.html`](https://docs.nwebsec.com/en/4.1/nwebsec/Configuring-csp.html)。

# 添加引荐策略标头

当用户浏览网站并点击链接到其他网站时，目标网站通常会收到有关用户来源网站的信息。引荐标头让您控制标头中应该存在的信息，目标网站可以读取该信息。我们可以在`Startup`类的`Configure`方法中添加引荐策略中间件，如下所示：

```cs
app.UseReferrerPolicy(opts => opts.NoReferrer());
```

`NoReferrer`选项意味着不会向目标网站发送引荐信息。

在我们的 ASP.NET Core 应用程序中启用所有前面的中间件后，当我们通过[securityheaders.io](http://securityheaders.io)网站进行扫描时，我们将看到我们有一个安全报告摘要，得到 A+的分数，这意味着网站完全安全：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-hiperf/img/00088.jpeg)

# 在 ASP.NET Core 应用程序中启用 CORS

CORS 代表跨域资源共享，它受到浏览器的限制，以防止跨域 API 请求。例如，我们在浏览器上运行一个 SPA（单页应用程序），使用类似 Angular 或 React 的客户端框架调用托管在另一个域上的 Web API，比如我的 SPA 站点具有一个域（[*mychapter8webapp.com*](http://mychapter8webapp.com)）并访问另一个域（[appservices.com](http://appservices.com)）的 API，这是受限制的。浏览器限制了对托管在其他服务器和域上的服务的调用，用户将无法调用这些 API。在服务器端启用 CORS 可以解决这个问题。

要在 ASP.NET Core 项目中启用 CORS，我们可以在`ConfigureServices`方法中添加 CORS 支持：

```cs
services.AddCors(); 
```

在`Configure`方法中，我们可以通过调用`UseCors`方法并定义策略来使用 CORS 以允许跨域请求。以下代码允许从任何标头、来源或方法发出请求，并且还允许我们在请求标头中传递凭据：

```cs
app.UseCors(config => { 
  config.AllowAnyHeader(); 
  config.AllowAnyMethod(); 
  config.AllowAnyOrigin(); 
  config.AllowCredentials(); 
});
```

上述代码将允许应用程序全局使用 CORS。或者，我们也可以根据不同的情况定义 CORS 策略，并在特定控制器上启用它们。

以下表格定义了定义 CORS 时使用的基本术语：

| **术语** | **描述** | **示例** |
| --- | --- | --- |
| 标头 | 允许在请求中传递的请求标头 | 内容类型、接受等 |
| 方法 | 请求的 HTTP 动词 | GET、POST、DELETE、PUT 等 |
| 来源 | 域或请求 URL | [`techframeworx.com`](http://techframeworx.com) |

要定义策略，我们可以在`ConfigureServices`方法中添加 CORS 支持时添加一个策略。以下代码显示了在添加 CORS 支持时定义的两个策略：

```cs
services.AddCors(config => 
{ 
  //Allow only HTTP GET Requests 
  config.AddPolicy("AllowOnlyGet", builder => 
  { 
    builder.AllowAnyHeader(); 
    builder.WithMethods("GET"); 
    builder.AllowAnyOrigin(); 
  }); 

  //Allow only those requests coming from techframeworx.com 
  config.AddPolicy("Techframeworx", builder => { 
    builder.AllowAnyHeader(); 
    builder.AllowAnyMethod(); 
    builder.WithOrigins("http://techframeworx.com"); 
  }); 
});
```

`AllowOnlyGet`策略将只允许进行`GET`请求的请求；`Techframeworx`策略将只允许来自[techframeworx.com](http://www.techframeworx.com/)的请求。

我们可以通过使用`EnableCors`属性并指定属性的名称在控制器和操作上使用这些策略：

```cs
[EnableCors("AllowOnlyGet")] 
public class SampleController : Controller 
{ 

 } 
```

# 身份验证和授权

安全的 API 只允许经过身份验证的用户访问。在 ASP.NET Core 中，我们可以使用 ASP.NET Core Identity 框架对用户进行身份验证，并为受保护的资源提供授权访问。

# 使用 ASP.NET Core Identity 进行身份验证和授权

一般来说，安全性分为两种机制，如下：

+   身份验证

+   授权

# 身份验证

身份验证是通过获取用户的用户名、密码或身份验证令牌进行用户访问的认证过程，然后从后端数据库或服务进行验证。一旦用户通过了身份验证，将进行一些操作，其中包括在浏览器中设置一个 cookie 或向用户返回一个令牌，以便在请求消息中传递以访问受保护的资源。

# 授权

授权是用户认证后进行的过程。授权用于了解访问资源的用户的权限。即使用户已经通过了身份验证，也并不意味着所有受保护或安全的资源都是可访问的。这就是授权发挥作用的地方，它只允许用户访问他们被允许访问的资源。

# 使用 ASP.NET Core Identity 框架实现身份验证和授权

ASP.NET Core Identity 是由 Microsoft 开发的安全框架，现在由开源社区贡献。这允许开发人员在 ASP.NET Core 应用程序中启用用户身份验证和授权。它提供了在数据库中存储用户身份、角色和声明的完整系统。它包含用于用户身份、角色等的某些类，可以根据要求进一步扩展以支持更多属性。它使用 Entity Framework Core 代码为第一个模型创建后端数据库，并可以轻松集成到现有数据模型或应用程序的特定表中。

在本节中，我们将创建一个简单的应用程序，从头开始添加 ASP.NET Core Identity，并修改`IdentityUser`类以定义附加属性，并使用基于 cookie 的身份验证来验证请求并保护 ASP.NET MVC 控制器。

在创建 ASP.NET Core 项目时，我们可以将身份验证选项更改为个人用户帐户身份验证，该选项为您的应用程序生成所有与安全相关的类并配置安全性：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-hiperf/img/00089.jpeg)

这将创建一个`AccountController`和`PageModels`来注册、登录、忘记密码和其他与用户管理相关的页面。

`Startup`类还包含一些与安全相关的条目。这是`ConfigureServices`方法，其中添加了一些特定于安全性的代码。

```cs
public void ConfigureServices(IServiceCollection services) 
{ 
  services.AddDbContext<ApplicationDbContext>(options => 
  options.UseSqlServer(Configuration.GetConnectionString("DefaultConnection"))); 

  services.AddIdentity<ApplicationUser, IdentityRole>() 
  .AddEntityFrameworkStores<ApplicationDbContext>() 
  .AddDefaultTokenProviders(); 

  services.AddMvc() 
  .AddRazorPagesOptions(options => 
  { 
    options.Conventions.AuthorizeFolder("/Account/Manage"); 
    options.Conventions.AuthorizePage("/Account/Logout"); 
  }); 

  services.AddSingleton<IEmailSender, EmailSender>(); 
} 
```

`AddDbContext`使用 SQL 服务器在数据库中创建 Identity 表，如下所示：`DefaultConnection`键。

+   `services.AddIdentity`用于在我们的应用程序中启用 Identity。它接受`ApplicationUser`和`IdentityRole`，并定义`ApplicationDbContext`用作 Entity Framework，用于存储创建的实体。

+   `AddDefaultTokenProviders` 被定义为生成重置密码、更改电子邮件、更改电话号码和双因素身份验证的令牌。

在`Configure`方法中，它添加了`UseAuthentication`中间件，该中间件启用了身份验证并保护了已配置为授权请求的页面或控制器。这是在管道中启用身份验证的`Configure`方法。定义的中间件按顺序执行。因此，`UseAuthentication`中间件在`UseMvc`中间件之前定义，以便所有调用控制器的请求首先经过身份验证：

```cs
public void Configure(IApplicationBuilder app, IHostingEnvironment env) 
{ 
  if (env.IsDevelopment()) 
  { 
    app.UseBrowserLink(); 
    app.UseDeveloperExceptionPage(); 
    app.UseDatabaseErrorPage(); 
  } 
  else 
  { 
    app.UseExceptionHandler("/Error"); 
  } 

  app.UseStaticFiles(); 

  app.UseAuthentication(); 

  app.UseMvc(); 
} 
```

# 在用户表中添加更多属性

`IdentityUser`是基类，包含与用户相关的属性，如电子邮件、密码和电话号码。当我们创建 ASP.NET Core 应用程序时，它会创建一个空的`ApplicationUser`类，该类继承自`IdentityUser`类。在`ApplicationUser`类中，我们可以添加更多属性，这些属性将在运行实体框架迁移时创建。我们将在我们的`ApplicationUser`类中添加`FirstName`、`LastName`和`MobileNumber`属性，这些属性在创建表时将被考虑：

```cs
public class ApplicationUser : IdentityUser 
{ 
  public string FirstName { get; set; } 
  public string LastName { get; set; } 
  public string MobileNumber { get; set; } 
} 
```

在运行迁移之前，请确保`Startup`类的`ConfigureServices`方法中指定的`DefaultConnection`字符串是有效的。

我们可以从 Visual Studio 的包管理器控制台或通过*dotnet CLI*工具集运行迁移。从 Visual Studio 中，选择特定项目并运行`Add-Migration`命令，指定迁移名称，在我们的情况下是 Initial：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-hiperf/img/00090.jpeg)

上述命令创建了`{timestamp}_Initial`类文件，其中包含`Up`和`Down`方法。`Up`方法用于发布后端数据库中的更改，而`Down`方法用于撤消数据库中的更改。要将更改应用于后端数据库，我们将运行`Update-Database`命令，该命令将创建一个包含`AspNet`相关表的数据库，这些表是身份框架的一部分。如果您以设计模式打开`AspNetUsers`表，您将看到自定义列`FirstName`、`LastName`和`MobileNumber`：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore2-hiperf/img/00091.jpeg)

我们可以运行应用程序并使用注册选项创建用户。为了保护我们的 API，我们必须在`Controller`或`Action`级别添加`Authorize`属性。当请求到来并且用户经过身份验证时，方法将被执行；否则，它将重定向请求到登录页面。

# 摘要

在本章中，我们学习了弹性，这是在.NET Core 中开发高性能应用程序时非常重要的因素。我们了解了不同的策略，并使用 Polly 框架在.NET Core 中使用这些策略。我们还学习了安全存储机制以及如何在开发环境中使用它们，以便将敏感信息与项目存储库分开。在本章的结尾，我们学习了一些核心基础知识，包括 SSL、CSRF、CORS、启用安全标头以及 ASP.NET Core 身份框架，以保护 ASP.NET Core 应用程序。

在下一章中，我们将学习一些关键的指标和必要的工具，以监控.NET Core 应用程序的性能。
