# C# 数据结构和算法（二）

> 原文：[`zh.annas-archive.org/md5/66e5287ccd1157bc24ed3bd6a5b7c4bf`](https://zh.annas-archive.org/md5/66e5287ccd1157bc24ed3bd6a5b7c4bf)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第三章：堆栈和队列

到目前为止，您已经学到了很多关于数组和列表的知识。然而，这些结构并不是唯一可用的。除此之外，还有一组更专业的数据结构，它们被称为**有限访问数据结构**。

这意味着什么？为了解释这个名字，让我们暂时回到数组的话题，数组属于**随机访问数据结构**的一部分。它们之间的区别只有一个词，即有限或随机。正如您已经知道的那样，数组允许您存储数据并使用索引访问各种元素。因此，您可以轻松地从数组中获取第一个、中间、*n*^(th)或最后一个元素。因此，它可以被称为随机访问数据结构。

然而，*有限*是什么意思？答案非常简单——对于有限访问数据结构，您无法访问结构中的每个元素。因此，获取元素的方式是严格指定的。例如，您只能获取第一个或最后一个元素，但无法从数据结构中获取第*n*个元素。有限访问数据结构的常见代表是堆栈和队列。

在本章中，将涵盖以下主题：

+   堆栈

+   队列

+   优先队列

# 堆栈

首先，让我们谈谈**堆栈**。它是一种易于理解的数据结构，可以用许多盘子堆叠的例子来表示。您只能将新盘子添加到堆叠的顶部，并且只能从堆叠的顶部获取盘子。您无法在不从顶部取出前六个盘子的情况下移除第七个盘子，也无法在堆叠的中间添加盘子。

堆栈的操作方式与队列完全相同！它允许您在顶部添加新元素（**push**操作）并通过从顶部移除元素来获取元素（**pop**操作）。因此，堆栈符合**LIFO**原则，即**后进先出**。根据我们堆盘子的例子，最后添加的盘子（最后进）将首先从堆中移除（先出）。

堆栈的推送和弹出操作的图示如下：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dsal/img/a4fcda16-874b-42c5-afb0-e7012d152bcd.png)

看起来非常简单，不是吗？的确如此，您可以通过使用`System.Collections.Generic`命名空间中的内置通用`Stack`类来从堆栈的特性中受益。值得一提的是该类中的三种方法，即：

+   `Push`，在堆栈顶部插入元素

+   `Pop`，从堆栈顶部移除元素并返回

+   `Peek`，从堆栈顶部返回元素而不移除它

当然，您还可以使用其他方法，例如从堆栈中删除所有元素（`Clear`）或检查给定元素是否可用于堆栈（`Contains`）。您可以使用`Count`属性获取堆栈中的元素数量。

值得注意的是，如果容量不需要增加，`Push`方法是*O(1)*操作，否则是*O(n)*，其中*n*是堆栈中的元素数量。`Pop`和`Peek`都是*O(1)*操作。

您可以在[`msdn.microsoft.com/library/3278tedw.aspx`](https://msdn.microsoft.com/library/3278tedw.aspx)找到有关`Stack`通用类的更多信息。

现在是时候看一些例子了。让我们开始吧！

# 示例-反转单词

首先，让我们尝试使用堆栈来反转一个单词。您可以通过迭代形成字符串的字符，将每个字符添加到堆栈的顶部，然后从堆栈中移除所有元素来实现这一点。最后，您将得到反转的单词，如下图所示，它展示了反转**MARCIN**单词的过程：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dsal/img/a555d667-5a6c-4e2d-b410-bcede9eda7cc.png)

应添加到`Program`类中的`Main`方法的实现代码如下所示：

```cs
Stack<char> chars = new Stack<char>(); 
foreach (char c in "LET'S REVERSE!") 
{ 
    chars.Push(c); 
} 

while (chars.Count > 0) 
{ 
    Console.Write(chars.Pop()); 
} 
Console.WriteLine(); 
```

在第一行，创建了`Stack`类的一个新实例。值得一提的是，在这种情况下，堆栈只能包含`char`元素。然后，您使用`foreach`循环遍历所有字符，并通过在`Stack`实例上调用`Push`方法将每个字符插入堆栈顶部。代码的剩余部分包括`while`循环，该循环执行直到堆栈为空。使用`Count`属性来检查此条件。在每次迭代中，从堆栈中移除顶部元素（通过调用`Pop`）并在控制台中写入（使用`Console`类的`Write`静态方法）。

运行代码后，您将收到以下结果：

```cs
    !ESREVER S'TEL
```

# 示例 - 汉诺塔

下一个示例是堆栈的一个显着更复杂的应用。它与数学游戏**汉诺塔**有关。让我们从规则开始。游戏需要三根杆，您可以在上面放置圆盘。每个圆盘的大小都不同。开始时，所有圆盘都放在第一根杆上，形成堆栈，从最小的（顶部）到最大的（底部）排序如下：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dsal/img/48184ab8-6fd5-4a9e-bb5d-7a656bc8591d.png)

游戏的目标是将所有圆盘从第一个杆（**FROM**）移动到第二个杆（**TO**）。然而，在整个游戏过程中，您不能将较大的圆盘放在较小的圆盘上。此外，您一次只能移动一个圆盘，当然，您只能从任何杆的顶部取一个圆盘。您如何在杆之间移动圆盘以符合上述规则？问题可以分解为子问题。

让我们从只移动一个圆盘的示例开始。这种情况很简单，您只需要将一个圆盘从**FROM**杆移动到**TO**杆，而不使用**AUXILIARY**杆。

稍微复杂一点的情况是移动两个圆盘。在这种情况下，您应该将一个圆盘从**FROM**杆移动到**AUXILIARY**杆。然后，您将剩下的圆盘从**FROM**移动到**TO**。最后，您只需要将一个圆盘从**AUXILIARY**移动到**TO**。

如果要移动三个圆盘，您应该从**FROM**移动两个圆盘到**AUXILIARY**，使用前面描述的机制。操作将涉及**TO**杆作为辅助杆。然后，您将剩余的圆盘从**FROM**移动到**TO**，然后从**AUXILIARY**移动两个圆盘到**TO**，使用**FROM**作为辅助杆。

正如您所看到的，您可以通过将*n-1*个圆盘从**FROM**移动到**AUXILIARY**，使用**TO**作为辅助杆来解决移动*n*个圆盘的问题。然后，您应该将剩余的圆盘从**FROM**移动到**TO**。最后，您只需要将*n-1*个圆盘从**AUXILIARY**移动到**TO**，使用**FROM**作为辅助杆。

就是这样！现在您知道了基本规则，让我们继续进行代码。

首先，让我们专注于包含与游戏相关逻辑的`HanoiTower`类。代码的一部分如下所示：

```cs
public class HanoiTower 
{ 
    public int DiscsCount { get; private set; } 
    public int MovesCount { get; private set; } 
    public Stack<int> From { get; private set; } 
    public Stack<int> To { get; private set; } 
    public Stack<int> Auxiliary { get; private set; } 
    public event EventHandler<EventArgs> MoveCompleted; (...) 
} 
```

该类包含五个属性，存储总圆盘数（`DiscsCount`），执行的移动数（`MovesCount`）以及三个杆的表示（`From`，`To`，`Auxiliary`）。还声明了`MoveCompleted`事件。每次移动后都会触发它，以通知用户界面应该刷新。因此，您可以显示适当的内容，说明杆的当前状态。

除了属性和事件之外，该类还具有以下构造函数：

```cs
public HanoiTower(int discs) 
{ 
    DiscsCount = discs; 
    From = new Stack<int>(); 
    To = new Stack<int>(); 
    Auxiliary = new Stack<int>(); 
    for (int i = 1; i <= discs; i++) 
    { 
        int size = discs - i + 1; 
        From.Push(size); 
    } 
} 
```

构造函数只接受一个参数，即圆盘数量（`discs`），并将其设置为`DiscsCount`属性的值。然后，创建了`Stack`类的新实例，并将它们的引用存储在`From`、`To`和`Auxiliary`属性中。最后，使用`for`循环来创建必要数量的圆盘，并将元素添加到第一个堆栈（`From`）中。值得注意的是，`From`、`To`和`Auxiliary`堆栈只存储整数值（`Stack<int>`）。每个整数值表示特定圆盘的大小。由于移动圆盘的规则，这些数据是至关重要的。

通过调用`Start`方法来启动算法的操作，其代码如下所示：

```cs
public void Start() 
{ 
    Move(DiscsCount, From, To, Auxiliary); 
} 
```

该方法只是调用`Move`递归方法，将总圆盘数和三个堆栈的引用作为参数传递。但是，`Move`方法中发生了什么？让我们来看一下：

```cs
public void Move(int discs, Stack<int> from, Stack<int> to,  
    Stack<int> auxiliary) 
{ 
    if (discs > 0) 
    { 
        Move(discs - 1, from, auxiliary, to); 

        to.Push(from.Pop()); 
        MovesCount++; 
        MoveCompleted?.Invoke(this, EventArgs.Empty); 

        Move(discs - 1, auxiliary, to, from); 
    } 
} 
```

如您已经知道的，此方法是递归调用的。因此，有必要指定一些退出条件，以防止方法被无限调用。在这种情况下，当`discs`参数的值等于或小于零时，该方法将不会调用自身。如果该值大于零，则调用`Move`方法，但是堆栈的顺序会改变。然后，从由第二个参数（`from`）表示的堆栈中移除元素，并将其插入到由第三个参数（`to`）表示的堆栈的顶部。在接下来的几行中，移动次数（`MovesCount`）递增，并触发`MoveCompleted`事件。最后，再次调用`Move`方法，使用另一种杆顺序的配置。通过多次调用此方法，圆盘将从第一个（`From`）移动到第二个（`To`）杆。`Move`方法中执行的操作与在本示例的介绍中解释的在杆之间移动*n*个圆盘的问题的描述一致。

创建了关于汉诺塔游戏的逻辑的类之后，让我们看看如何创建用户界面，以便呈现算法的下一步移动。`Program`类中的必要更改如下：

```cs
private const int DISCS_COUNT = 10; 
private const int DELAY_MS = 250; 
private static int _columnSize = 30; 
```

首先，声明了两个常量，即整体圆盘数量（`DISCS_COUNT`，设置为`10`）和算法中两次移动之间的延迟（以毫秒为单位）（`DELAY_MS`，设置为`250`）。此外，声明了一个私有静态字段，表示用于表示单个杆的字符数（`_columnSize`，设置为`30`）。

`Program`类中的`Main`方法如下所示：

```cs
static void Main(string[] args) 
{ 
    _columnSize = Math.Max(6, GetDiscWidth(DISCS_COUNT) + 2); 
    HanoiTower algorithm = new HanoiTower(DISCS_COUNT); 
    algorithm.MoveCompleted += Algorithm_Visualize; 
    Algorithm_Visualize(algorithm, EventArgs.Empty); 
    algorithm.Start(); 
} 
```

首先，使用辅助的`GetDiscWidth`方法计算了单个列（表示杆）的宽度，其代码稍后将显示。然后，创建了`HanoiTower`类的新实例，并指示在触发`MoveCompleted`事件时将调用`Algorithm_Visualize`方法。接下来，调用了上述的`Algorithm_Visualize`方法来呈现游戏的初始状态。最后，调用`Start`方法来开始在杆之间移动圆盘。

`Algorithm_Visualize`方法的代码如下：

```cs
private static void Algorithm_Visualize( 
    object sender, EventArgs e) 
{ 
    Console.Clear(); 

    HanoiTowers algorithm = (HanoiTowers)sender; 
    if (algorithm.DiscsCount <= 0) 
    { 
        return; 
    } 

    char[][] visualization = InitializeVisualization(algorithm); 
    PrepareColumn(visualization, 1, algorithm.DiscsCount,  
        algorithm.From); 
    PrepareColumn(visualization, 2, algorithm.DiscsCount,  
        algorithm.To); 
    PrepareColumn(visualization, 3, algorithm.DiscsCount,  
        algorithm.Auxiliary); 

    Console.WriteLine(Center("FROM") + Center("TO") +  
        Center("AUXILIARY")); 
    DrawVisualization(visualization); 
    Console.WriteLine(); 
    Console.WriteLine($"Number of moves: {algorithm.MovesCount}"); 
    Console.WriteLine($"Number of discs: {algorithm.DiscsCount}"); 

    Thread.Sleep(DELAY_MS); 
} 
```

算法的可视化应该在控制台中呈现游戏的当前状态。因此，每当需要刷新时，`Algorithm_Visualize`方法清除控制台的当前内容（通过调用`Clear`方法）。然后，它调用`InitializeVisualization`方法来准备应该写入控制台的内容的交错数组。这样的内容包括三列，通过调用`PrepareColumn`方法准备。调用后，`visualization`数组包含应该只是呈现在控制台中的数据，没有任何额外的转换。为此，调用`DrawVisualization`方法。当然，标题和额外的解释使用`Console`类的`WriteLine`方法写入控制台。

重要的角色由代码的最后一行执行，其中调用了`System.Threading`命名空间中`Thread`类的`Sleep`方法。它暂停当前线程`DELAY_MS`毫秒。这样一行代码被添加以便以方便的方式呈现算法的以下步骤给用户。

让我们来看看`InitializeVisualization`方法的代码：

```cs
private static char[][] InitializeVisualization( 
    HanoiTowers algorithm) 
{ 
    char[][] visualization = new char[algorithm.DiscsCount][]; 

    for (int y = 0; y < visualization.Length; y++) 
    { 
        visualization[y] = new char[_columnSize * 3]; 
        for (int x = 0; x < _columnSize * 3; x++) 
        { 
            visualization[y][x] = ' '; 
        } 
    } 

    return visualization; 
} 
```

该方法声明了一个交错数组，行数等于总盘数（`DiscsCount`属性）。列数等于`_columnSize`字段的值乘以`3`（表示三根杆）。在方法内部，使用两个`for`循环来迭代遍历行（第一个`for`循环）和所有列（第二个`for`循环）。默认情况下，数组中的所有元素都被初始化为单个空格。最后，初始化的数组被返回。

要用当前杆的状态的插图填充上述的交错数组，需要调用`PrepareColumn`方法，其代码如下：

```cs
private static void PrepareColumn(char[][] visualization,  
    int column, int discsCount, Stack<int> stack) 
{ 
    int margin = _columnSize * (column - 1); 
    for (int y = 0; y < stack.Count; y++) 
    { 
        int size = stack.ElementAt(y); 
        int row = discsCount - (stack.Count - y); 
        int columnStart = margin + discsCount - size; 
        int columnEnd = columnStart + GetDiscWidth(size); 
        for (int x = columnStart; x <= columnEnd; x++) 
        { 
            visualization[row][x] = '='; 
        } 
    } 
} 
```

首先，计算左边距以在整体数组中的正确部分添加数据，即在正确的列范围内。然而，方法的主要部分是`for`循环，其中迭代次数等于给定堆栈中的盘数。在每次迭代中，使用`ElementAt`扩展方法（来自`System.Linq`命名空间）读取当前盘的大小。接下来，计算应该显示盘的行的索引，以及列的起始和结束索引。最后，使用`for`循环将等号（`=`）插入到作为`visualization`参数传递的交错数组的适当位置。

下一个与可视化相关的方法是`DrawVisualization`，其代码如下：

```cs
private static void DrawVisualization(char[][] visualization) 
{ 
    for (int y = 0; y < visualization.Length; y++) 
    { 
        Console.WriteLine(visualization[y]); 
    } 
} 
```

该方法只是遍历作为`visualization`参数传递的交错数组的所有元素，并为交错数组中的每个数组调用`WriteLine`方法。结果是，整个数组中的数据被写入控制台。

其中一个辅助方法是`Center`。它的目的是在参数中传递的文本之前和之后添加额外的空格，以使文本在列中居中。该方法的代码如下：

```cs
private static string Center(string text) 
{ 
    int margin = (_columnSize - text.Length) / 2; 
    return text.PadLeft(margin + text.Length) 
        .PadRight(_columnSize); 
} 
```

另一个方法是`GetDiscWidth`，它只返回以参数指定大小呈现的盘所需的字符数。其代码如下：

```cs
private static int GetDiscWidth(int size) 
{ 
    return 2 * size - 1; 
} 
```

您已经添加了运行应用程序所需的代码，该应用程序将呈现汉诺塔数学游戏的以下移动。让我们启动应用程序并看看它的运行情况！

在程序启动后，您将看到类似以下的结果，其中所有盘都位于第一根杆（`FROM`）中：

```cs
            FROM                  TO                AUXILIARY
             ==
            ====
           ======
          ========
         ==========
        ============
       ==============
      ================
     ==================
    ====================

```

在下一步中，最小的盘从第一根杆（`FROM`）的顶部移动到第三根杆（`AUXILIARY`）的顶部，如下图所示：

```cs
            FROM                  TO                AUXILIARY    

            ====
           ======
          ========
         ==========
        ============
       ==============
      ================
     ==================
    ====================                               ==

```

在进行许多其他移动时，您可以看到盘在三根杆之间移动。其中一个中间状态如下：

```cs
            FROM                  TO                AUXILIARY          

            ====
         ==========
        ============
       ==============
      ================
     ==================         ======
    ====================       ========                ==

```

当完成必要的移动后，所有圆盘都从第一个圆盘（`FROM`）移动到第二个圆盘（`TO`）。最终结果如下图所示：

```cs
            FROM                  TO                AUXILIARY
                                  ==
                                 ====
                                ======
                               ========
                              ==========
                             ============
                            ==============
                           ================
                          ==================
                         ====================

```

最后，值得一提的是完成汉诺塔游戏所需的移动次数。在 10 个圆盘的情况下，移动次数为 1,023。如果只使用三个圆盘，移动次数只有七次。一般来说，可以用公式*2^n-1*来计算移动次数，其中*n*是圆盘的数量。

就这些了！在本节中，您已经学习了第一个有限访问数据结构，即栈。现在，是时候更多地了解队列了。让我们开始吧！

# 队列

**队列**是一种数据结构，可以用在商店结账时等待的人排队的例子中。新人站在队伍的末尾，下一个人从队伍的开头被带到结账处。不允许您从中间选择一个人并按不同的顺序为他或她服务。

队列数据结构的操作方式完全相同。您只能在队列的末尾添加新元素（**enqueue**操作），并且只能从队列的开头删除一个元素（**dequeue**操作）。因此，这种数据结构符合**FIFO**原则，即**先进先出**。在商店结账时等待的人排队的例子中，先来的人（先进）将在后来的人之前（先出）被服务。

队列的操作如下图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dsal/img/3f5f553b-30ad-467b-bc7e-54e3f368fd89.png)

值得一提的是，队列是一个**递归数据结构**，与栈类似。这意味着队列可以是空的，也可以由第一个元素和其余队列组成，后者也形成一个队列，如下图所示（队列的开始标记为灰色）：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dsal/img/64556717-48c1-4468-b84a-4b91eec6cce8.png)

队列数据结构似乎很容易理解，与栈类似，除了删除元素的方式。这是否意味着您也可以在程序中使用内置类来使用队列？幸运的是，可以！可用的通用类名为`Queue`，定义在`System.Collections.Generic`命名空间中。

`Queue`类包含一组方法，例如：

+   `Enqueue`，在队列末尾添加一个元素

+   `Dequeue`，从开头删除一个元素并返回它

+   `Peek`，从开头返回一个元素而不删除它

+   `Clear`，从队列中删除所有元素

+   `Contains`，检查队列是否包含给定元素

`Queue`类还包含`Count`属性，返回队列中的元素总数。它可以用于轻松检查队列是否为空。

值得一提的是，如果内部数组不需要重新分配，则`Enqueue`方法是*O(1)*操作，否则为*O(n)*，其中*n*是队列中的元素数量。`Dequeue`和`Peek`都是*O(1)*操作。

您可以在[`msdn.microsoft.com/library/7977ey2c.aspx`](https://msdn.microsoft.com/library/7977ey2c.aspx)找到有关`Queue`类的更多信息。

在想要从多个线程同时使用队列的情况下，需要额外的注释。在这种情况下，需要选择线程安全的队列变体，即`System.Collections.Concurrent`命名空间中的`ConcurrentQueue`通用类。该类包含一组内置方法，用于执行线程安全队列的各种操作，例如：

+   `Enqueue`，在队列末尾添加一个元素

+   `TryDequeue`，尝试从开头删除一个元素并返回它

+   `TryPeek`，尝试从开头返回一个元素而不删除它

值得一提的是，`TryDequeue`和`TryPeek`都有一个带有`out`关键字的参数。如果操作成功，这些方法将返回`true`，并将结果作为`out`参数的值返回。此外，`ConcurrentQueue`类还包含两个属性，即`Count`用于获取集合中存储的元素数量，以及`IsEmpty`用于返回一个值，指示队列是否为空。

您可以在[`msdn.microsoft.com/library/dd267265.aspx`](https://msdn.microsoft.com/library/dd267265.aspx)找到有关`ConcurrentQueue`类的更多信息。

在这个简短的介绍之后，您应该准备好继续进行两个示例，代表呼叫中心中的队列，有许多呼叫者和一个或多个顾问。

# 示例 - 仅有一个顾问的呼叫中心

这个第一个示例代表了呼叫中心解决方案的简单方法，其中有许多呼叫者（具有不同的客户标识符），以及只有一个顾问，他按照呼叫出现的顺序接听等待的电话。这种情况在下图中呈现：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dsal/img/ac923287-81b8-49c7-87d8-cff86e481094.png)

正如您在前面的图表中所看到的，呼叫者执行了四次呼叫。它们被添加到等待电话呼叫的队列中，即来自客户**#1234**，**#5678**，**#1468**和**#9641**。当顾问可用时，他或她会接听电话。通话结束后，顾问可以接听下一个等待的电话。根据这个规则，顾问将按照以下顺序与客户交谈：**#1234**，**#5678**，**#1468**和**#9641**。

让我们来看一下第一个类`IncomingCall`的代码，它代表了呼叫中心中由呼叫者执行的单个呼入呼叫。其代码如下：

```cs
public class IncomingCall 
{ 
    public int Id { get; set; } 
    public int ClientId { get; set; } 
    public DateTime CallTime { get; set; } 
    public DateTime StartTime { get; set; } 
    public DateTime EndTime { get; set; } 
    public string Consultant { get; set; } 
} 
```

该类包含六个属性，代表呼叫的标识符（`Id`），客户标识符（`ClientId`），呼叫开始的日期和时间（`CallTime`），呼叫被接听的日期和时间（`StartTime`），呼叫结束的日期和时间（`EndTime`），以及顾问的姓名（`Consultant`）。

这个实现中最重要的部分与`CallCenter`类相关，它代表了与呼叫相关的操作。其片段如下：

```cs
public class CallCenter 
{ 
    private int _counter = 0; 
    public Queue<IncomingCall> Calls { get; private set; } 

    public CallCenter() 
    { 
        Calls = new Queue<IncomingCall>(); 
    } 
} 
```

`CallCenter`类包含`_counter`字段，其中包含最后一次呼叫的标识符，以及`Calls`队列（带有`IncomingCall`实例），其中存储了等待呼叫的数据。在构造函数中，创建了`Queue`泛型类的新实例，并将其引用分配给`Calls`属性。

当然，该类还包含一些方法，比如`Call`，代码如下：

```cs
public void Call(int clientId) 
{ 
    IncomingCall call = new IncomingCall() 
    { 
        Id = ++_counter, 
        ClientId = clientId, 
        CallTime = DateTime.Now 
    }; 
    Calls.Enqueue(call); 
} 
```

在这里，您创建了`IncomingCall`类的新实例，并设置了其属性的值，即其标识符（连同预增量`_counter`字段）、客户标识符（使用`clientId`参数）和呼叫时间。通过调用`Enqueue`方法，将创建的实例添加到队列中。

下一个方法是`Answer`，它代表了回答呼叫的操作，来自队列中等待时间最长的人，也就是位于队列开头的人。`Answer`方法如下所示：

```cs
public IncomingCall Answer(string consultant) 
{ 
    if (Calls.Count > 0) 
    { 
        IncomingCall call = Calls.Dequeue(); 
        call.Consultant = consultant; 
        call.StartTime = DateTime.Now; 
        return call; 
    } 
    return null; 
} 
```

在这个方法中，您检查队列是否为空。如果是，该方法返回`null`，这意味着顾问没有可以接听的电话。否则，呼叫将从队列中移除（使用`Dequeue`方法），并通过设置顾问姓名（使用`consultant`参数）和开始时间（为当前日期和时间）来更新其属性。最后，返回呼叫的数据。

除了`Call`和`Answer`方法，您还应该实现`End`方法，每当顾问结束与特定客户的通话时都会调用该方法。在这种情况下，您只需设置结束时间，如下面的代码片段所示：

```cs
public void End(IncomingCall call) 
{ 
    call.EndTime = DateTime.Now; 
} 
```

`CallCenter`类中的最后一个方法名为`AreWaitingCalls`。它使用`Queue`类的`Count`属性返回一个值，指示队列中是否有任何等待的呼叫。其代码如下：

```cs
public bool AreWaitingCalls() 
{ 
    return Calls.Count > 0; 
} 
```

让我们继续到`Program`类和它的`Main`方法：

```cs
static void Main(string[] args) 
{ 
    Random random = new Random(); 

    CallCenter center = new CallCenter(); 
    center.Call(1234); 
    center.Call(5678); 
    center.Call(1468); 
    center.Call(9641); 

    while (center.AreWaitingCalls()) 
    { 
        IncomingCall call = center.Answer("Marcin"); 
        Log($"Call #{call.Id} from {call.ClientId}  
            is answered by {call.Consultant}."); 
        Thread.Sleep(random.Next(1000, 10000)); 
        center.End(call); 
        Log($"Call #{call.Id} from {call.ClientId}  
            is ended by {call.Consultant}."); 
    } 
} 
```

在这里，你创建了`Random`类的一个新实例（用于获取随机数），以及`CallCenter`类的一个实例。然后，你通过呼叫者模拟了一些呼叫，即使用以下客户标识符：`1234`，`5678`，`1468`和`9641`。代码中最有趣的部分位于`while`循环中，该循环执行直到队列中没有等待的呼叫为止。在循环内，顾问接听呼叫（使用`Answer`方法），并生成日志（使用`Log`辅助方法）。然后，线程暂停一段随机毫秒数（在 1,000 到 10,000 之间）以模拟呼叫的不同长度。当时间到达后，呼叫结束（通过调用`End`方法），并生成适当的日志。

这个示例中必要的最后一部分代码是`Log`方法：

```cs
private static void Log(string text) 
{ 
    Console.WriteLine($"[{DateTime.Now.ToString("HH:mm:ss")}]  
        {text}"); 
} 
```

当你运行这个示例时，你会收到类似以下的结果：

```cs
    [15:24:36] Call #1 from 1234 is answered by Marcin.
    [15:24:40] Call #1 from 1234 is ended by Marcin.
    [15:24:40] Call #2 from 5678 is answered by Marcin.
    [15:24:48] Call #2 from 5678 is ended by Marcin.
    [15:24:48] Call #3 from 1468 is answered by Marcin.
    [15:24:53] Call #3 from 1468 is ended by Marcin.
    [15:24:53] Call #4 from 9641 is answered by Marcin.
    [15:24:57] Call #4 from 9641 is ended by Marcin.

```

就是这样！你刚刚完成了关于队列数据结构的第一个示例。如果你想了解更多关于队列的线程安全版本，让我们继续到下一部分，看看下一个示例。

# 示例 - 带有多个顾问的呼叫中心

在前面的部分中显示的示例被故意简化，以使理解队列变得更简单。然而，现在是时候让它更相关于现实世界的问题了。在这一部分，你将看到如何扩展它以支持多个顾问，如下图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dsal/img/40966381-d05b-420f-bf0e-78608de68883.png)

重要的是，呼叫者和顾问将同时工作。如果有更多的呼叫比可用的顾问多，新的呼叫将被添加到队列中，并等待直到有顾问可以接听呼叫。如果顾问过多而呼叫过少，顾问将等待呼叫。为了执行这个任务，你需要创建一些线程，它们将访问队列。因此，你需要使用`ConcurrentQueue`类的线程安全版本。

让我们看一下代码！首先，你需要声明`IncomingCall`类，其代码与前面的示例完全相同：

```cs
public class IncomingCall 
{ 
    public int Id { get; set; } 
    public int ClientId { get; set; } 
    public DateTime CallTime { get; set; } 
    public DateTime StartTime { get; set; } 
    public DateTime EndTime { get; set; } 
    public string Consultant { get; set; } 
} 
```

`CallCenter`类中需要进行各种修改，比如用`ConcurrentQueue`泛型类的实例替换`Queue`类的实例。适当的代码片段如下所示：

```cs
public class CallCenter 
{ 
    private int _counter = 0; 
    public ConcurrentQueue<IncomingCall> Calls  
        { get; private set; } 

    public CallCenter() 
    { 
        Calls = new ConcurrentQueue<IncomingCall>(); 
    } 
} 
```

由于`Enqueue`方法在`Queue`和`ConcurrentQueue`类中都可用，所以在`Call`方法的最重要部分不需要进行任何修改。然而，在将新呼叫添加到队列后，引入了一个小的修改来返回等待呼叫的数量。修改后的代码如下：

```cs
public int Call(int clientId) 
{ 
    IncomingCall call = new IncomingCall() 
    { 
        Id = ++_counter, 
        ClientId = clientId, 
        CallTime = DateTime.Now 
    }; 
    Calls.Enqueue(call); 
    return Calls.Count; 
} 
```

`ConcurrentQueue`类中不存在`Dequeue`方法。因此，你需要稍微修改`Answer`方法，使用`TryDequeue`方法，该方法返回一个值，指示元素是否已从队列中移除。移除的元素使用`out`参数返回。适当的代码部分如下：

```cs
public IncomingCall Answer(string consultant) 
{ 
    if (Calls.Count > 0  
        && Calls.TryDequeue(out IncomingCall call)) 
    { 
        call.Consultant = consultant; 
        call.StartTime = DateTime.Now; 
        return call; 
    } 
    return null; 
} 
```

在`CallCenter`类中声明的剩余方法`End`和`AreWaitingCalls`中不需要进行进一步的修改。它们的代码如下：

```cs
public void End(IncomingCall call) 
{ 
    call.EndTime = DateTime.Now; 
}

public bool AreWaitingCalls() 
{ 
    return Calls.Count > 0; 
}
```

在`Program`类中需要进行更多的修改。在这里，你需要启动四个线程。第一个代表呼叫者，而其他三个代表顾问。首先，让我们看一下`Main`方法的代码：

```cs
static void Main(string[] args) 
{ 
    CallCenter center = new CallCenter(); 
    Parallel.Invoke( 
        () => CallersAction(center), 
        () => ConsultantAction(center, "Marcin",  
                  ConsoleColor.Red), 
        () => ConsultantAction(center, "James",  
                  ConsoleColor.Yellow), 
        () => ConsultantAction(center, "Olivia",  
                  ConsoleColor.Green)); 
} 
```

在这里，在创建`CallCenter`实例后，您使用`System.Threading.Tasks`命名空间中`Parallel`类的`Invoke`静态方法开始执行四个操作，即代表呼叫者和三个咨询师，使用 lambda 表达式来指定将被调用的方法，即呼叫者相关操作的`CallersAction`和咨询师相关任务的`ConsultantAction`。您还可以指定其他参数，比如给定咨询师的名称和颜色。

`CallersAction` 方法代表了许多呼叫者循环执行的操作。其代码如下所示：

```cs
private static void CallersAction(CallCenter center) 
{ 
    Random random = new Random(); 
    while (true) 
    { 
        int clientId = random.Next(1, 10000); 
        int waitingCount = center.Call(clientId); 
        Log($"Incoming call from {clientId},  
            waiting in the queue: {waitingCount}"); 
        Thread.Sleep(random.Next(1000, 5000)); 
    } 
}
```

代码中最重要的部分是无限执行的`while`循环。在其中，您会得到一个随机数作为客户的标识符（`clientId`），并调用`Call`方法。等待呼叫的数量被记录下来，连同客户标识符。最后，呼叫者相关的线程将暂停一段随机毫秒数，范围在 1,000 毫秒到 5,000 毫秒之间，即 1 到 5 秒之间，以模拟呼叫者进行另一个呼叫之间的延迟。

下一个方法名为`ConsultantAction`，并在每个咨询师的单独线程上执行。该方法接受三个参数，即`CallCenter`类的一个实例，以及咨询师的名称和颜色。代码如下：

```cs
private static void ConsultantAction(CallCenter center,  
    string name, ConsoleColor color) 
{ 
    Random random = new Random(); 
    while (true) 
    { 
        IncomingCall call = center.Answer(name); 
        if (call != null) 
        { 
            Console.ForegroundColor = color; 
            Log($"Call #{call.Id} from {call.ClientId} is answered  
                by {call.Consultant}."); 
            Console.ForegroundColor = ConsoleColor.Gray; 

            Thread.Sleep(random.Next(1000, 10000)); 
            center.End(call); 

            Console.ForegroundColor = color; 
            Log($"Call #{call.Id} from {call.ClientId}  
                is ended by {call.Consultant}."); 
            Console.ForegroundColor = ConsoleColor.Gray; 

            Thread.Sleep(random.Next(500, 1000)); 
        } 
        else 
        { 
            Thread.Sleep(100); 
        } 
    } 
} 
```

与`CallersAction`方法类似，最重要和有趣的操作是在无限的`while`循环中执行的。在其中，咨询师尝试使用`Answer`方法回答第一个等待的呼叫。如果没有等待的呼叫，线程将暂停 100 毫秒。否则，根据当前咨询师的情况，以适当的颜色呈现日志。然后，线程将暂停 1 到 10 秒之间的随机时间。在此时间之后，咨询师结束呼叫，通过调用`End`方法来指示，并生成日志。最后，线程将暂停 500 毫秒到 1,000 毫秒之间的随机时间，这代表了呼叫结束和另一个呼叫开始之间的延迟。

最后一个辅助方法名为`Log`，与前一个示例中的方法完全相同。其代码如下：

```cs
private static void Log(string text) 
{ 
    Console.WriteLine($"[{DateTime.Now.ToString("HH:mm:ss")}]  
        {text}"); 
} 
```

当您运行程序并等待一段时间后，您将收到类似于以下截图所示的结果：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dsal/img/0a800625-5b63-44b0-a245-6919a7f84ff7.png)

恭喜！您刚刚完成了两个示例，代表了呼叫中心场景中队列的应用。

修改程序的各种参数是一个好主意，比如咨询师的数量，以及延迟时间，特别是呼叫者之间的延迟时间。然后，您将看到算法在呼叫者或咨询师过多的情况下是如何工作的。

然而，如何处理具有优先支持的客户呢？在当前解决方案中，他们将与标准支持计划的客户一起等待在同一个队列中。您需要创建两个队列并首先从优先队列中取客户吗？如果是这样，如果您引入另一个支持计划会发生什么？您需要添加另一个队列并在代码中引入这样的修改吗？幸运的是，不需要！您可以使用另一种数据结构，即优先队列，来支持这样的情景，如下一节中详细解释的那样。

# 优先队列

**优先级队列**使得可以通过为队列中的每个元素设置**优先级**来扩展队列的概念。值得一提的是，优先级可以简单地指定为整数值。然而，较小或较大的值是否表示更高的优先级取决于实现。在本章中，假设最高优先级等于 0，而较低的优先级由 1、2、3 等指定。因此，**出队**操作将返回具有最高优先级的元素，该元素首先添加到队列中，如下图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dsal/img/fc121dc6-2124-4ec7-8ba1-033cd63f35e9.png)

让我们分析一下图表。首先，优先级队列包含两个具有相同优先级（等于**1**）的元素，即**Marcin**和**Lily**。然后，添加了具有更高优先级（**0**）的**Mary**元素，这意味着该元素位于队列的开头，即在**Marcin**之前。在下一步中，具有最低优先级（**2**）的**John**元素被添加到优先级队列的末尾。第三列显示了具有优先级等于**1**的**Emily**元素的添加，即与**Marcin**和**Lily**相同。因此，**Emily**元素在**Lily**之后添加。根据前述规则，您添加以下元素，即优先级设置为**0**的**Sarah**和优先级等于**1**的**Luke**。最终顺序显示在前述图表的右侧。

当然，可以自己实现优先级队列。但是，您可以通过使用其中一个可用的 NuGet 包，即`OptimizedPriorityQueue`来简化此任务。有关此包的更多信息，请访问[`www.nuget.org/packages/OptimizedPriorityQueue`](https://www.nuget.org/packages/OptimizedPriorityQueue)。

您知道如何将此包添加到您的项目中吗？如果不知道，您应该按照以下步骤进行：

1.  从解决方案资源管理器窗口中的项目节点的上下文菜单中选择管理 NuGet 包。

1.  选择打开窗口中的浏览选项卡。

1.  在搜索框中键入`OptimizedPriorityQueue`。

1.  单击 OptimizedPriorityQueue 项目。

1.  在右侧单击安装按钮。

1.  在预览更改窗口中单击确定。

1.  等待直到在输出窗口中显示完成消息。

`OptimizedPriorityQueue`库显着简化了在各种应用程序中应用优先级队列。其中，可用`SimplePriorityQueue`泛型类，其中包含一些有用的方法，例如：

+   `Enqueue`，向优先级队列中添加元素

+   `Dequeue`，从开头删除元素并返回它

+   `GetPriority`，返回元素的优先级

+   `UpdatePriority`，更新元素的优先级

+   `Contains`，检查优先级队列中是否存在元素

+   `Clear`，从优先级队列中删除所有元素

您可以使用`Count`属性获取队列中元素的数量。如果要从优先级队列的开头获取元素而不将其删除，可以使用`First`属性。此外，该类包含一组方法，这些方法在多线程场景中可能很有用，例如`TryDequeue`和`TryRemove`。值得一提的是，`Enqueue`和`Dequeue`方法都是*O(log n)*操作。

在对优先级队列的主题进行了简短介绍之后，让我们继续介绍具有优先级支持的呼叫中心的示例，该示例在以下部分中进行了描述。

# 示例 - 具有优先级支持的呼叫中心

作为优先级队列的示例，让我们介绍一种简单的方法，即呼叫中心示例，其中有许多呼叫者（具有不同的客户标识符），并且只有一个顾问，他首先从优先级队列中回答等待的呼叫，然后从具有标准支持计划的客户那里回答。

上述情景在以下图表中呈现。标有**-**的是标准优先级的呼叫，而标有*****的是优先级支持的呼叫，如下所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dsal/img/207dd920-227c-43c6-aa0d-851366641327.png)

让我们来看看优先级队列中元素的顺序。目前，它只包含三个元素，将按以下顺序提供服务：**#5678**（具有优先级支持），**#1234**和**#1468**。然而，来自标识符**#9641**的客户的呼叫导致顺序变为**#5678**，**#9641**（由于优先级支持），**#1234**和**#1468**。

是时候写一些代码了！首先，不要忘记将`OptimizedPriorityQueue`包添加到项目中，如前所述。当库配置正确时，您可以继续实现`IncomingCall`类：

```cs
public class IncomingCall 
{ 
    public int Id { get; set; } 
    public int ClientId { get; set; } 
    public DateTime CallTime { get; set; } 
    public DateTime StartTime { get; set; } 
    public DateTime EndTime { get; set; } 
    public string Consultant { get; set; } 
    public bool IsPriority { get; set; } 
} 
```

在这里，与之前呈现的简单呼叫中心应用程序的情景相比，只有一个变化，即添加了`IsPriority`属性。它指示当前呼叫是否具有优先级支持（`true`）或标准支持（`false`）。

`CallCenter`类中也需要进行一些修改，其片段如下代码片段所示：

```cs
public class CallCenter 
{ 
    private int _counter = 0; 
    public SimplePriorityQueue<IncomingCall> Calls  
        { get; private set; } 

    public CallCenter() 
    { 
        Calls = new SimplePriorityQueue<IncomingCall>(); 
    } 
} 
```

如您所见，`Calls`属性的类型已从`Queue`更改为`SimplePriorityQueue`泛型类。在`Call`方法中需要进行以下更改，代码如下所示：

```cs
public void Call(int clientId, bool isPriority = false) 
{ 
    IncomingCall call = new IncomingCall() 
    { 
        Id = ++_counter, 
        ClientId = clientId, 
        CallTime = DateTime.Now, 
        IsPriority = isPriority 
    }; 
    Calls.Enqueue(call, isPriority ? 0 : 1); 
} 
```

在这个方法中，使用参数设置了`IsPriority`属性（前面提到的）。此外，在调用`Enqueue`方法时，使用了两个参数，不仅是元素的值（`IncomingCall`类的实例），还有一个优先级的整数值，即在优先级支持的情况下为`0`，否则为`1`。

在`CallCenter`类的方法中不需要进行更多的修改，即`Answer`，`End`和`AreWaitingCalls`方法。相关代码如下：

```cs
public IncomingCall Answer(string consultant) 
{ 
    if (Calls.Count > 0) 
    { 
        IncomingCall call = Calls.Dequeue(); 
        call.Consultant = consultant; 
        call.StartTime = DateTime.Now; 
        return call; 
    } 
    return null; 
}

public void End(IncomingCall call) 
{ 
    call.EndTime = DateTime.Now; 
}

public bool AreWaitingCalls() 
{ 
    return Calls.Count > 0; 
} 
```

最后，让我们来看看`Program`类中`Main`和`Log`方法的代码：

```cs
static void Main(string[] args) 
{ 
    Random random = new Random(); 

    CallCenter center = new CallCenter(); 
    center.Call(1234); 
    center.Call(5678, true); 
    center.Call(1468); 
    center.Call(9641, true); 

    while (center.AreWaitingCalls()) 
    { 
        IncomingCall call = center.Answer("Marcin"); 
        Log($"Call #{call.Id} from {call.ClientId}  
            is answered by {call.Consultant} /  
            Mode: {(call.IsPriority ? "priority" : "normal")}."); 
        Thread.Sleep(random.Next(1000, 10000)); 
        center.End(call); 
        Log($"Call #{call.Id} from {call.ClientId}  
            is ended by {call.Consultant}."); 
    } 
} 
private static void Log(string text) 
{ 
    Console.WriteLine($"[{DateTime.Now.ToString("HH:mm:ss")}]  
        {text}"); 
} 
```

您可能会惊讶地发现，在代码的这一部分只需要进行两个更改！原因是使用的数据结构的逻辑被隐藏在`CallCenter`类中。在`Program`类中，您调用了一些方法并使用了`CallCenter`类公开的属性。您只需要修改向队列添加呼叫的方式，并调整呼叫被顾问接听时呈现的日志，以展示呼叫的优先级。就是这样！

运行应用程序时，您将收到类似以下的结果：

```cs
    [15:40:26] Call #2 from 5678 is answered by Marcin / Mode:    
 **priority**.
    [15:40:35] Call #2 from 5678 is ended by Marcin.
    [15:40:35] Call #4 from 9641 is answered by Marcin / Mode: 
 **priority**.
    [15:40:39] Call #4 from 9641 is ended by Marcin.
    [15:40:39] Call #1 from 1234 is answered by Marcin / Mode: **normal**.
    [15:40:48] Call #1 from 1234 is ended by Marcin.
    [15:40:48] Call #3 from 1468 is answered by Marcin / Mode: **normal**.
    [15:40:57] Call #3 from 1468 is ended by Marcin.

```

如您所见，呼叫按正确的顺序提供服务。这意味着具有优先级支持的客户的呼叫比具有标准支持计划的客户的呼叫更早得到服务，尽管这类呼叫需要等待更长时间才能得到答复。

# 总结

在本章中，您已经了解了三种有限访问数据结构，即栈、队列和优先级队列。值得记住的是，这些数据结构都有严格指定的访问元素的方式。它们都有各种各样的现实世界应用，本书中已经提到并描述了其中一些。

首先，您看到了栈如何按照 LIFO 原则运作。在这种情况下，您只能在栈的顶部添加元素（推送操作），并且只能从顶部移除元素（弹出操作）。栈已在两个示例中展示，即用于颠倒一个单词和解决汉诺塔数学游戏。

在本章的后续部分，您了解了队列作为一种数据结构，它根据 FIFO 原则运作。在这种情况下，介绍了入队和出队操作。队列已通过两个示例进行了解释，都涉及模拟呼叫中心的应用程序。此外，您还学会了如何运行几个线程，以及如何在 C#语言开发应用程序时使用线程安全的队列变体。

本章介绍的第三种数据结构称为优先队列，是队列的扩展，支持特定元素的优先级。为了更容易地使用这种数据结构，您已经学会了如何使用外部 NuGet 包。例如，呼叫中心场景已扩展为处理两种支持计划。

这只是本书的第三章，您已经学到了很多关于各种数据结构和算法的知识，这些知识在 C#应用程序开发中非常有用！您是否有兴趣通过学习字典和集合来增加您的知识？如果是的话，让我们继续下一章，了解更多关于这些数据结构的知识！


# 第四章：字典和集

本章将重点介绍与字典和集相关的数据结构。正确应用这些数据结构可以将键映射到值，并进行快速查找，以及对集合进行各种操作。为了简化对字典和集的理解，本章将包含插图和代码片段。

在本章的前几部分，您将学习字典的非泛型和泛型版本，即由键和值组成的一对集合。然后，还将介绍字典的排序变体。您还将看到字典和列表之间的一些相似之处。

本章的剩余部分将向您展示如何使用哈希集，以及名为“排序”集的变体。是否可能有一个“排序”集？在阅读最后一节时，您将了解如何理解这个主题。

本章将涵盖以下主题：

+   哈希表

+   字典

+   排序字典

+   哈希集

+   “排序”集

# 哈希表

让我们从第一个数据结构开始，即**哈希表**，也称为**哈希映射**。它允许将键**映射**到特定值，如下图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dsal/img/e874bb03-d53d-432d-a1b6-cfb25bae7204.png)

哈希表最重要的假设之一是可以非常快速地查找基于**Key**的**Value**，这应该是*O(1)*操作。为了实现这一目标，使用了**哈希函数**。它将**Key**生成一个桶的索引，**Value**可以在其中找到。

因此，如果您需要查找键的值，您不需要遍历集合中的所有项，因为您可以使用哈希函数轻松定位适当的桶并获取值。由于哈希表的出色性能，在许多现实世界的应用程序中经常使用这样的数据结构，例如用于关联数组、数据库索引或缓存系统。

正如您所看到的，哈希函数的作用至关重要，理想情况下应该为所有键生成唯一的结果。然而，可能会为不同的键生成相同的结果。这种情况被称为**哈希冲突**，需要处理。

从头开始实现哈希表的实现似乎相当困难，特别是涉及使用哈希函数、处理哈希冲突以及将特定键分配给桶。幸运的是，在 C#语言中开发应用程序时可以使用合适的实现，而且使用起来非常简单。

哈希表相关类有两个变体，即非泛型（`Hashtable`）和泛型（`Dictionary`）。第一个在本节中描述，而另一个在下一节中描述。如果可以使用强类型的泛型版本，我强烈建议使用它。

让我们来看看`System.Collections`命名空间中的`Hashtable`类。如前所述，它存储了一组成对的集合，每个集合包含一个键和一个值。一对由`DictionaryEntry`实例表示。

您可以轻松地使用索引器访问特定元素。由于`Hashtable`类是与哈希表相关类的非泛型变体，您需要将返回的结果转换为适当的类型（例如`string`），如下所示：

```cs
string value = (string)hashtable["key"]; 
```

类似地，您可以设置值：

```cs
hashtable["key"] = "value"; 
```

值得一提的是，`null`值对于元素的`key`是不正确的，但对于元素的`value`是可以接受的。

除了索引器之外，该类还配备了一些属性，可以获取存储的元素数量（`Count`），以及返回键或值的集合（分别为`Keys`和`Values`）。此外，您可以使用一些可用的方法，例如添加新元素（`Add`），删除元素（`Remove`），删除所有元素（`Clear`），以及检查集合是否包含特定键（`Contains`和`ContainsKey`）或给定值（`ContainsValue`）。

如果要从哈希表中获取所有条目，可以使用`foreach`循环来迭代存储在集合中的所有对，如下所示：

```cs
foreach (DictionaryEntry entry in hashtable) 
{ 
    Console.WriteLine($"{entry.Key} - {entry.Value}"); 
} 
```

循环中使用的变量具有`DictionaryEntry`类型。因此，您需要使用其`Key`和`Value`属性分别访问键和值。

您可以在[`msdn.microsoft.com/library/system.collections.hashtable.aspx`](https://msdn.microsoft.com/library/system.collections.hashtable.aspx)找到有关`Hashtable`类的更多信息。

在这个简短的介绍之后，现在是时候看一个例子了。

# 示例-电话簿

例如，您将创建一个电话簿应用程序。`Hashtable`类将用于存储条目，其中人名是键，电话号码是值，如下图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dsal/img/b596dbfa-5ace-48a2-be5f-68657c98bb64.png)

该程序将演示如何向集合中添加元素，检查存储的项目数量，遍历所有项目，检查是否存在具有给定键的元素，以及如何基于键获取值。

此处呈现的整个代码应放在`Program`类的`Main`方法的主体中。首先，让我们创建`Hashtable`类的新实例，并使用一些条目对其进行初始化，如下面的代码所示：

```cs
Hashtable phoneBook = new Hashtable() 
{ 
    { "Marcin Jamro", "000-000-000" }, 
    { "John Smith", "111-111-111" } 
}; 
phoneBook["Lily Smith"] = "333-333-333"; 
```

您可以以各种方式向集合中添加元素，例如在创建类的新实例时（在前面的示例中为`Marcin Jamro`和`John Smith`的电话号码），通过使用索引器（`Lily Smith`），以及使用`Add`方法（`Mary Fox`），如下面的代码部分所示：

```cs
try 
{ 
    phoneBook.Add("Mary Fox", "222-222-222"); 
} 
catch (ArgumentException) 
{ 
    Console.WriteLine("The entry already exists."); 
} 
```

如您所见，`Add`方法的调用位于`try-catch`语句中。为什么？答案很简单——您不能添加具有相同键的多个元素，在这种情况下会抛出`ArgumentException`。为了防止应用程序崩溃，使用`try-catch`语句，并在控制台中显示适当的消息，通知用户情况。

当您使用索引器为特定键设置值时，如果已经存在具有给定键的项目，它不会抛出任何异常。在这种情况下，将更新此元素的值。

在代码的下一部分中，您将遍历集合中的所有对，并在控制台中呈现结果。当没有项目时，将向用户呈现附加信息，如下面的代码片段所示：

```cs
Console.WriteLine("Phone numbers:"); 
if (phoneBook.Count == 0) 
{ 
    Console.WriteLine("Empty"); 
} 
else 
{ 
    foreach (DictionaryEntry entry in phoneBook) 
    { 
        Console.WriteLine($" - {entry.Key}: {entry.Value}"); 
    } 
} 
```

您可以使用`Count`属性检查集合中是否没有元素，并将其值与`0`进行比较。通过`foreach`循环的可用性，遍历所有对的方式变得更加简单。但是，您需要记住，`Hashtable`类中的单个对由`DictionaryEntry`实例表示，您可以使用`Key`和`Value`属性访问其键和值。

最后，让我们看看如何检查特定键是否存在于集合中，以及如何获取其值。第一个任务可以通过调用`Contains`方法来完成，该方法返回一个值，指示是否存在合适的元素（`true`）或不存在（`false`）。另一个任务（获取值）使用索引器，并且需要将返回的值转换为适当的类型（在本例中为`string`）。这个要求是由哈希表相关类的非泛型版本引起的。代码如下：

```cs
Console.WriteLine(); 
Console.Write("Search by name: "); 
string name = Console.ReadLine(); 
if (phoneBook.Contains(name)) 
{ 
    string number = (string)phoneBook[name]; 
    Console.WriteLine($"Found phone number: {number}"); 
} 
else 
{ 
    Console.WriteLine("The entry does not exist."); 
} 
```

您的第一个使用哈希表的程序已经准备好了！启动后，您将收到类似以下的结果：

```cs
    Phone numbers:
     - John Smith: 111-111-111
     - Mary Fox: 222-222-222
     - Lily Smith: 333-333-333
     - Marcin Jamro: 000-000-000

    Search by name: Mary Fox
    Found phone number: 222-222-222

```

值得注意的是，使用`Hashtable`类存储的键值对的顺序与它们添加或键的顺序不一致。因此，如果需要呈现排序后的结果，您需要自行对元素进行排序，或者使用另一个数据结构，即稍后在本书中描述的`SortedDictionary`。

然而，现在让我们来看一下在 C#中开发时最常用的类之一，即`Dictionary`，它是哈希表相关类的泛型版本。

# 字典

在上一节中，您了解了`Hashtable`类作为哈希表相关类的非泛型变体。但是，它有一个重要的限制，因为它不允许您指定键和值的类型。`DictionaryEntry`类的`Key`和`Value`属性都是`object`类型。因此，即使所有键和值都具有相同的类型，您仍需要执行装箱和拆箱操作。

如果要使用强类型变体，可以使用`Dictionary`泛型类，这是本章节的主要内容。

首先，在创建`Dictionary`类的实例时，您应该指定两种类型，即键的类型和值的类型。此外，可以使用以下代码定义字典的初始内容：

```cs
Dictionary<string, string> dictionary = 
    new Dictionary<string, string> 
{ 
    { "Key 1", "Value 1" }, 
    { "Key 2", "Value 2" } 
}; 
```

在上面的代码中，创建了`Dictionary`类的一个新实例。它存储基于`string`的键和值。默认情况下，字典中存在两个条目，即键`Key 1`和`Key 2`。它们的值分别是`Value 1`和`Value 2`。

与`Hashtable`类类似，您也可以使用索引器来访问集合中的特定元素，如下面的代码行所示：

```cs
string value = dictionary["key"]; 
```

值得注意的是，不需要将类型转换为`string`类型，因为`Dictionary`是哈希表相关类的强类型版本。因此，返回的值已经具有正确的类型。

如果集合中不存在具有给定键的元素，则会抛出`KeyNotFoundException`。为了避免问题，您可以选择以下之一：

+   将代码行放在`try-catch`块中

+   检查元素是否存在（通过调用`ContainsKey`）

+   使用`TryGetValue`方法

您可以使用索引器添加新元素或更新现有元素的值，如下面的代码行所示：

```cs
dictionary["key"] = "value"; 
```

与非泛型变体类似，`key`不能等于`null`，但`value`可以，当然，如果允许存储在集合中的值的类型。此外，获取元素的值、添加新元素或更新现有元素的性能接近*O(1)*操作。

`Dictionary`类配备了一些属性，可以获取存储元素的数量（`Count`），以及返回键或值的集合（分别是`Keys`和`Values`）。此外，您可以使用可用的方法，例如添加新元素（`Add`），删除项目（`Remove`），删除所有元素（`Clear`），以及检查集合是否包含特定键（`ContainsKey`）或给定值（`ContainsValue`）。您还可以使用`TryGetValue`方法尝试获取给定键的值并返回它（如果元素存在），否则返回`null`。

虽然通过给定键返回值（使用索引器或`TryGetValue`）和检查给定键是否存在（`ContainsKey`）的场景接近*O(1)*操作，但检查集合是否包含给定值（`ContainsValue`）的过程是*O(n)*操作，并且需要您搜索整个集合以查找特定值。

如果要遍历集合中存储的所有对，可以使用`foreach`循环。但是，循环中使用的变量是`KeyValuePair`泛型类的实例，具有`Key`和`Value`属性，允许您访问键和值。`foreach`循环显示在以下代码片段中：

```cs
foreach (KeyValuePair<string, string> pair in dictionary) 
{ 
    Console.WriteLine($"{pair.Key} - {pair.Value}"); 
} 
```

您还记得上一章中一些类的线程安全版本吗？如果记得，那么在`Dictionary`类的情况下，情况看起来与`ConcurrentDictionary`类相当相似，因为`System.Collections.Concurrent`命名空间中提供了`ConcurrentDictionary`类。它配备了一组方法，例如`TryAdd`、`TryUpdate`、`AddOrUpdate`和`GetOrAdd`。

您可以在[`msdn.microsoft.com/library/xfhwa508.aspx`](https://msdn.microsoft.com/library/xfhwa508.aspx)找到有关`Dictionary`泛型类的更多信息，而有关线程安全替代方案`ConcurrentDictionary`的详细信息则显示在[`msdn.microsoft.com/library/dd287191.aspx`](https://msdn.microsoft.com/library/dd287191.aspx)。

让我们开始编码！在接下来的部分，您将找到两个展示字典的示例。

# 示例-产品位置

第一个示例是帮助商店员工找到产品应放置的位置的应用程序。假设每个员工都有一部手机，上面安装了您的应用程序，用于扫描产品的代码，应用程序会告诉他们产品应放置在**A1**或**C9**区域。听起来很有趣，不是吗？

由于商店中的产品数量通常非常庞大，因此有必要快速找到结果。因此，产品的数据以及其位置将存储在哈希表中，使用泛型`Dictionary`类。键将是条形码，而值将是区域代码，如下图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dsal/img/47f0b01a-098f-4b52-b227-d3d1daf4b0ce.png)

让我们看一下应该添加到`Program`类的`Main`方法中的代码。首先，您需要创建一个新的集合，并添加一些数据：

```cs
Dictionary<string, string> products = 
    new Dictionary<string, string> 
{ 
    { "5900000000000", "A1" }, 
    { "5901111111111", "B5" }, 
    { "5902222222222", "C9" } 
}; 
products["5903333333333"] = "D7"; 
```

代码显示了向集合中添加元素的两种方法，即在创建类的新实例时传递它们的数据和使用索引器。还存在第三种解决方案，使用`Add`方法，如代码的以下部分所示：

```cs
try 
{ 
    products.Add("5904444444444", "A3"); 
} 
catch (ArgumentException) 
{ 
    Console.WriteLine("The entry already exists."); 
} 
```

在`Hashtable`类的情况下提到，如果您想要添加与集合中已存在的元素具有相同键的元素，则会抛出`ArgumentException`。您可以通过使用`try-catch`块来防止应用程序崩溃。

在代码的下一部分中，您会展示系统中所有可用产品的数据。为此，您使用`foreach`循环，但在此之前，您要检查字典中是否有任何元素。如果没有，则向用户呈现适当的消息。否则，控制台中显示所有对的键和值。值得一提的是，在`foreach`循环中的变量类型是`KeyValuePair<string, string>`，因此其`Key`和`Value`属性是`string`类型，而不是`object`类型，与非泛型变体的情况相同。代码如下所示：

```cs
Console.WriteLine("All products:"); 
if (products.Count == 0) 
{ 
    Console.WriteLine("Empty"); 
} 
else 
{ 
    foreach (KeyValuePair<string, string> product in products) 
    { 
        Console.WriteLine($" - {product.Key}: {product.Value}"); 
    } 
}
```

最后，让我们看一下代码的一部分，该代码使得可以通过其条形码找到产品的位置。为此，您使用`TryGetValue`来检查元素是否存在。如果是，控制台中会显示带有目标位置的消息。否则，会显示其他信息。重要的是，`TryGetValue`方法使用`out`参数来返回找到的元素的值。代码如下：

```cs
Console.WriteLine(); 
Console.Write("Search by barcode: "); 
string barcode = Console.ReadLine(); 
if (products.TryGetValue(barcode, out string location)) 
{ 
    Console.WriteLine($"The product is in the area {location}."); 
} 
else 
{ 
    Console.WriteLine("The product does not exist."); 
} 
```

运行程序时，您将看到商店中所有产品的列表，并且程序会要求您输入条形码。输入后，您将收到带有区域代码的消息。控制台中显示的结果将类似于以下内容：

```cs
    All products:
     - 5900000000000: A1
     - 5901111111111: B5
     - 5902222222222: C9
     - 5903333333333: D7
     - 5904444444444: A3

    Search by barcode: 5902222222222
    The product is in the area C9.
```

您刚刚完成了第一个示例！让我们继续到下一个。

# 示例-用户详细信息

第二个示例将向您展示如何在字典中存储更复杂的数据。在这种情况下，您将创建一个应用程序，根据用户的标识符显示用户的详细信息，如下图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dsal/img/12009a61-2e0f-4ab3-9a8a-de5495759aff.png)

程序应该以三个用户的数据开始。您应该能够输入标识符并查看找到的用户的详细信息。当然，应该通过在控制台中呈现适当的信息来处理给定用户不存在的情况。

首先，让我们添加`Employee`类，它只存储员工的数据，即名字、姓氏和电话号码。代码如下：

```cs
public class Employee 
{ 
    public string FirstName { get; set; } 
    public string LastName { get; set; } 
    public string PhoneNumber { get; set; } 
} 
```

下面的修改将在`Program`类的`Main`方法中执行。在这里，您创建了`Dictionary`类的一个新实例，并使用`Add`方法添加了三个员工的数据，如下面的代码片段所示：

```cs
Dictionary<int, Employee> employees =  
    new Dictionary<int, Employee>(); 
employees.Add(100, new Employee() { FirstName = "Marcin",  
    LastName = "Jamro", PhoneNumber = "000-000-000" }); 
employees.Add(210, new Employee() { FirstName = "Mary",  
    LastName = "Fox", PhoneNumber = "111-111-111" }); 
employees.Add(303, new Employee() { FirstName = "John",  
    LastName = "Smith", PhoneNumber = "222-222-222" }); 
```

最有趣的操作是在以下`do-while`循环中执行的：

```cs
bool isCorrect = true; 
do 
{ 
    Console.Write("Enter the employee identifier: "); 
    string idString = Console.ReadLine(); 
    isCorrect = int.TryParse(idString, out int id); 
    if (isCorrect) 
    { 
        Console.ForegroundColor = ConsoleColor.White; 
        if (employees.TryGetValue(id, out Employee employee)) 
        { 
            Console.WriteLine("First name: {1}{0}Last name:  
                {2}{0}Phone number: {3}", 
                Environment.NewLine, 
                employee.FirstName, 
                employee.LastName, 
                employee.PhoneNumber); 
        } 
        else 
        { 
            Console.WriteLine("The employee with the given  
                identifier does not exist."); 
        } 
        Console.ForegroundColor = ConsoleColor.Gray; 
    } 
} 
while (isCorrect); 
```

首先，用户被要求输入员工的标识符，然后将其解析为整数值。如果此操作成功完成，则使用`TryGetValue`方法尝试获取用户的详细信息。如果找到用户，即`TryGetValue`返回`true`，则在控制台中呈现详细信息。否则，显示`“给定标识符的员工不存在。”`消息。循环执行，直到提供的标识符无法解析为整数值为止。

当您运行应用程序并输入一些数据时，您将收到以下结果：

```cs
    Enter the employee identifier: 100
    First name: Marcin
    Last name: Jamro
    Phone number: 000-000-000
    Enter the employee identifier: 500
    The employee with the given identifier does not exist.
```

就是这样！您刚刚完成了两个示例，展示了如何在 C#语言中开发应用程序时使用字典。

然而，在关于`Hashtable`类的部分提到了另一种字典，即有序字典。您是否有兴趣了解它的作用以及如何在程序中使用它？如果是的话，让我们继续到下一节。

# 有序字典

与哈希表相关的类的非泛型和泛型变体都不保留元素的顺序。因此，如果您需要按键排序的方式呈现来自集合的数据，您需要在呈现之前对它们进行排序。但是，您可以使用另一种数据结构，**有序字典**，来解决这个问题，并始终保持键的排序。因此，您可以在必要时轻松获取排序后的集合。

有序字典实现为`SortedDictionary`泛型类，位于`System.Collections.Generic`命名空间中。您可以在创建`SortedDictionary`类的新实例时指定键和值的类型。此外，该类包含与`Dictionary`类类似的属性和方法。

首先，您可以使用索引器访问集合中的特定元素，如下面的代码行所示：

```cs
string value = dictionary["key"]; 
```

您应该确保元素存在于集合中。否则，将抛出`KeyNotFoundException`。

您可以添加新元素或更新现有元素的值，如下所示的代码：

```cs
dictionary["key"] = "value"; 
```

与`Dictionary`类类似，键不能等于`null`，但值可以，当然，如果允许存储在集合中的值的类型允许的话。

该类配备了一些属性，可以获取存储元素的数量（`Count`），以及返回键和值的集合（`Keys`和`Values`）。此外，您可以使用可用的方法，例如添加新元素（`Add`），删除项目（`Remove`），删除所有元素（`Clear`），以及检查集合是否包含特定键（`ContainsKey`）或给定值（`ContainsValue`）。您可以使用`TryGetValue`方法尝试获取给定键的值并返回它（如果元素存在），否则返回`null`。

如果您想要遍历集合中存储的所有键值对，可以使用`foreach`循环。循环中使用的变量是`KeyValuePair`泛型类的实例，具有`Key`和`Value`属性，允许您访问键和值。

尽管自动排序有优势，但与`Dictionary`相比，`SortedDictionary`类在性能上有一些缺点，因为检索、插入和删除都是*O(log n)*操作，其中*n*是集合中的元素数量，而不是*O(1)*。此外，`SortedDictionary`与第二章中描述的`SortedList`非常相似，*数组和列表*。然而，它们在与内存相关和性能相关的结果上有所不同。这两个类的检索都是*O(log n)*操作，但对于未排序的数据，`SortedDictionary`的插入和删除是*O(log n)*，而`SortedList`是*O(n)*。当然，`SortedDictionary`需要比`SortedList`更多的内存。正如您所看到的，选择合适的数据结构并不是一件容易的事，您应该仔细考虑特定数据结构将被使用的场景，并考虑其优缺点。

您可以在[`msdn.microsoft.com/library/f7fta44c.aspx`](https://msdn.microsoft.com/library/f7fta44c.aspx)找到关于`SortedDictionary`泛型类的更多信息。

让我们通过创建一个示例来看看排序字典的实际操作。

# 示例-定义

例如，您可以创建一个简单的百科全书，可以添加条目，并显示其完整内容。百科全书可以包含数百万条目，因此至关重要的是为其用户提供按正确顺序浏览条目的可能性，按键的字母顺序排列，以及快速找到条目。因此，在这个例子中，排序字典是一个很好的选择。

百科全书的概念如下图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dsal/img/9915bf6c-68cd-49a8-8a8b-98078a4c5462.png)

当程序启动时，它会显示一个简单的菜单，包括两个选项，即`[a] - add`和`[l] - list`。按下*A*键后，应用程序会要求您输入条目的名称和解释。如果提供的数据是正确的，新条目将被添加到百科全书中。如果用户按下*L*键，则按键排序的所有条目数据将显示在控制台中。当按下其他键时，会显示额外的确认信息，如果确认，则程序退出。

让我们来看看代码，它应该放在`Program`类的`Main`方法的主体中：

```cs
SortedDictionary<string, string> definitions =  
    new SortedDictionary<string, string>(); 
do 
{ 
    Console.Write("Choose an option ([a] - add, [l] - list): "); 
    ConsoleKeyInfo keyInfo = Console.ReadKey(); 
    Console.WriteLine(); 
    if (keyInfo.Key == ConsoleKey.A) 
    { 
        Console.ForegroundColor = ConsoleColor.White; 
        Console.Write("Enter the name: "); 
        string name = Console.ReadLine(); 
        Console.Write("Enter the explanation: "); 
        string explanation = Console.ReadLine(); 
        definitions[name] = explanation; 
        Console.ForegroundColor = ConsoleColor.Gray; 
    } 
    else if (keyInfo.Key == ConsoleKey.L) 
    { 
        Console.ForegroundColor = ConsoleColor.White; 
        foreach (KeyValuePair<string, string> definition  
            in definitions) 
        { 
            Console.WriteLine($"{definition.Key}:  
                {definition.Value}"); 
        } 
        Console.ForegroundColor = ConsoleColor.Gray; 
    } 
    else 
    { 
        Console.ForegroundColor = ConsoleColor.White; 
        Console.WriteLine("Do you want to exit the program?  
            Press [y] (yes) or [n] (no)."); 
        Console.ForegroundColor = ConsoleColor.Gray; 
        if (Console.ReadKey().Key == ConsoleKey.Y) 
        { 
            break; 
        } 
    } 
} 
while (true); 
```

首先，创建了`SortedDictionary`类的新实例，它表示具有基于`string`的键和基于`string`的值的一组对。然后，使用无限的`do-while`循环。在其中，程序会等待用户按下任意键。如果是*A*键，程序将从用户输入的值中获取条目的名称和解释。然后，使用索引器将新条目添加到字典中。因此，如果具有相同键的条目已经存在，它将被更新。如果按下*L*键，则使用`foreach`循环显示所有输入的条目。当按下其他键时，会向用户显示另一个问题，并等待确认。如果用户按下*Y*，则跳出循环。

当运行程序时，您可以输入一些条目，并将它们显示出来。控制台的结果如下所示：

```cs
    Choose an option ([a] - add, [l] - list): a
    Enter the name: Zakopane
    Enter the explanation: a city located in Tatra mountains in Poland
    Choose an option ([a] - add, [l] - list): a
    Enter the name: Rzeszow
    Enter the explanation: a capital of the Subcarpathian voivodeship 
    in Poland
    Choose an option ([a] - add, [l] - list): a
    Enter the name: Warszawa
    Enter the explanation: a capital city of Poland
    Choose an option ([a] - add, [l] - list): a
    Enter the name: Lancut
    Enter the explanation: a city located near Rzeszow with 
    a beautiful castle
    Choose an option ([a] - add, [l] - list): l
    Lancut: a city located near Rzeszow with a beautiful castle
    Rzeszow: a capital of the Subcarpathian voivodeship in Poland
    Warszawa: a capital city of Poland
    Zakopane: a city located in Tatra mountains in Poland
    Choose an option ([a] - add, [l] - list): q
    Do you want to exit the program? Press [y] (yes) or [n] (no).
    yPress any key to continue . . .

```

到目前为止，您已经学习了三个与字典相关的类，分别是`Hashtable`、`Dictionary`和`SortedDictionary`。它们都有一些特定的优势，并且可以在各种场景中使用。为了更容易理解它们，我们提供了一些示例，并附有详细的解释。

然而，你知道还有一些其他只存储键而没有值的数据结构吗？想要了解更多吗？如果是的话，让我们继续到下一节。

# 哈希集

在一些算法中，有必要对具有不同数据的集合执行操作。但是，什么是**集合**？集合是一组不重复元素的集合，没有重复的元素，也没有特定的顺序。因此，你只能知道给定的元素是否在集合中。集合与数学模型和操作紧密相关，如并集、交集、差集和对称差。

集合可以存储各种数据，如整数或字符串值，如下图所示。当然，你也可以创建一个包含用户定义类实例的集合，并随时向集合中添加和删除元素。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dsal/img/711ea288-1b69-41e1-bc10-ce9441ca8978.png)

在看到集合的实际操作之前，值得提醒一下可以对两个集合**A**和**B**执行的一些基本操作。让我们从并集和交集开始，如下图所示。如你所见，**并集**（左侧显示为**A∪B**）是一个包含属于**A**或**B**的所有元素的集合。**交集**（右侧显示为**A∩B**）仅包含属于**A**和**B**的元素：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dsal/img/d5053aab-bdec-4534-a3a4-65677880f858.png)

另一个常见的操作是**集合减法**。**A \ B**的结果集包含属于**A**而不属于**B**的元素。在下面的示例中，分别呈现了**A \ B**和**B \ A**：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dsal/img/7c8d365f-f84c-4d1c-abaf-abe4805fad0e.png)

在对集合执行操作时，还值得提到**对称差**，如下图左侧所示的**A ∆ B**。最终集合可以解释为两个集合的并集，即（**A \ B**）和（**B \ A**）。因此，它包含属于只属于一个集合的元素，要么是**A**，要么是**B**。属于两个集合的元素被排除在结果之外：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dsal/img/ba83077a-cb31-42c0-bc5b-2df29ff3445e.png)

另一个重要的主题是集合之间的**关系**。如果**B**的每个元素也属于**A**，那么**B**是**A**的**子集**，如前图中右侧所示。同时，**A**是**B**的**超集**。此外，如果**B**是**A**的子集，但**B**不等于**A**，那么**B**是**A**的**真子集**，而**A**是**B**的**真超集**。

在 C#语言中开发应用程序时，你可以从`System.Collections.Generic`命名空间中的`HashSet`类提供的高性能操作中受益。该类包含一些属性，包括返回集合中元素数量的`Count`。此外，你可以使用许多方法来执行集合操作，如下面所述。

第一组方法使得可以修改当前集合（调用方法的集合）以创建以下集合，其中传递的集合作为参数：

+   并集（`UnionWith`）

+   交集（`IntersectWith`）

+   差集（`ExceptWith`）

+   对称差（`SymmetricExceptWith`）

你还可以检查两个集合之间的关系，例如检查调用方法的当前集合是否是：

+   传递的集合的子集（`IsSubsetOf`）

+   传递的集合的超集（`IsSupersetOf`）

+   传递的集合的真子集（`IsProperSubsetOf`）

+   传递的集合的真超集（`IsProperSupersetOf`）

此外，你可以验证两个集合是否包含相同的元素（`SetEquals`），或者两个集合是否至少有一个公共元素（`Overlaps`）。

除了上述操作，您还可以向集合中添加新元素（`Add`），删除特定元素（`Remove`）或删除所有元素（`Clear`），以及检查给定元素是否存在于集合中（`Contains`）。

您可以在[`msdn.microsoft.com/library/bb359438.aspx`](https://msdn.microsoft.com/library/bb359438.aspx)找到有关`HashSet`泛型类的更多信息。

在这个介绍之后，尝试将学到的信息付诸实践是一个好主意。因此，让我们继续进行两个示例，它们将向您展示如何在应用程序中应用哈希集。

# 示例 - 优惠券

第一个示例代表了一个系统，用于检查一次性优惠券是否已经被使用。如果是，应向用户呈现适当的消息。否则，系统应通知用户优惠券有效，并且应标记为已使用，不能再次使用。由于优惠券数量众多，有必要选择一种数据结构，可以快速检查某个集合中是否存在元素。因此，哈希集被选择为存储已使用优惠券的标识符的数据结构。因此，您只需要检查输入的标识符是否存在于集合中。

让我们来看看应该添加到`Program`类的`Main`方法的代码。第一部分如下所示：

```cs
HashSet<int> usedCoupons = new HashSet<int>(); 
do 
{ 
    Console.Write("Enter the coupon number: "); 
    string couponString = Console.ReadLine(); 
    if (int.TryParse(couponString, out int coupon)) 
    { 
        if (usedCoupons.Contains(coupon)) 
        { 
            Console.ForegroundColor = ConsoleColor.Red; 
            Console.WriteLine("It has been already used :-("); 
            Console.ForegroundColor = ConsoleColor.Gray; 
        } 
        else 
        { 
            usedCoupons.Add(coupon); 
            Console.ForegroundColor = ConsoleColor.Green; 
            Console.WriteLine("Thank you! :-)"); 
            Console.ForegroundColor = ConsoleColor.Gray; 
        } 
    } 
    else 
    { 
        break; 
    } 
} 
while (true); 
```

首先，创建存储整数值的`HashSet`泛型类的新实例。然后，大多数操作都在`do-while`循环内执行。在这里，程序会等待用户输入优惠券标识符。如果无法解析为整数值，则跳出循环。否则，将检查集合是否已包含等于优惠券标识符的元素（使用`Contains`方法）。如果是，将呈现适当的警告信息。但是，如果不存在，则将其添加到已使用优惠券的集合中（使用`Add`方法）并通知用户。

当您跳出循环时，您只需要显示已使用优惠券的标识符的完整列表。您可以使用`foreach`循环实现此目标，遍历集合，并在控制台中写入其元素，如下面的代码所示：

```cs
Console.WriteLine(); 
Console.WriteLine("A list of used coupons:"); 
foreach (int coupon in usedCoupons) 
{ 
    Console.WriteLine(coupon); 
} 
```

现在您可以启动应用程序，输入一些数据，然后查看它的运行情况。控制台中的结果如下所示：

```cs
    Enter the coupon number: 100
    Thank you! :-)
    Enter the coupon number: 101
    Thank you! :-)
    Enter the coupon number: 500
    Thank you! :-)
    Enter the coupon number: 345
    Thank you! :-)
    Enter the coupon number: 101
    It has been already used :-(
    Enter the coupon number: l

    A list of used coupons:
    100
    101
    500
    345

```

这是第一个示例的结束。让我们继续进行下一个示例，在这个示例中，您将看到一个使用哈希集的更复杂的解决方案。

# 示例 - 游泳池

这个例子展示了一个 SPA 中心的系统，有四个游泳池，分别是休闲、比赛、温泉和儿童。每位访客都会收到一个特殊的手腕带，可以进入所有游泳池。但是，必须在进入任何游泳池时扫描手腕带，您的程序可以使用这些数据来创建各种统计数据。

在这个例子中，哈希集被选择为存储已经在每个游泳池入口扫描的手腕带的唯一编号的数据结构。将使用四个集合，每个游泳池一个，如下图所示。此外，它们将被分组在字典中，以简化和缩短代码，以及使未来的修改更容易：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dsal/img/5e73a997-35ca-427f-8258-207a9986b8a1.png)

为了简化测试应用程序，初始数据将被随机设置。因此，您只需要创建统计数据，即按游泳池类型统计的访客人数，最受欢迎的游泳池，至少访问过一个游泳池的人数，以及访问过所有游泳池的人数。所有统计数据将使用集合。

让我们从`PoolTypeEnum`枚举开始（在`PoolTypeEnum.cs`文件中声明），它表示可能的游泳池类型，如下面的代码所示：

```cs
public enum PoolTypeEnum 
{ 
    RECREATION, 
    COMPETITION, 
    THERMAL, 
    KIDS 
}; 
```

接下来，向`Program`类添加`random`私有静态字段。它将用于使用一些随机值填充哈希集。代码如下：

```cs
private static Random random = new Random(); 
```

然后，在`Program`类中声明`GetRandomBoolean`静态方法，返回`true`或`false`值，根据随机值。代码如下所示：

```cs
private static bool GetRandomBoolean() 
{ 
    return random.Next(2) == 1; 
} 
```

接下来的更改只需要在`Main`方法中进行。第一部分如下：

```cs
Dictionary<PoolTypeEnum, HashSet<int>> tickets =  
    new Dictionary<PoolTypeEnum, HashSet<int>>() 
{ 
    { PoolTypeEnum.RECREATION, new HashSet<int>() }, 
    { PoolTypeEnum.COMPETITION, new HashSet<int>() }, 
    { PoolTypeEnum.THERMAL, new HashSet<int>() }, 
    { PoolTypeEnum.KIDS, new HashSet<int>() } 
}; 
```

在这里，你创建了一个`Dictionary`的新实例。它包含四个条目。每个键都是`PoolTypeEnum`类型，每个值都是`HashSet<int>`类型，也就是一个包含整数值的集合。

在接下来的部分，你会用随机值填充集合，如下所示：

```cs
for (int i = 1; i < 100; i++) 
{ 
    foreach (KeyValuePair<PoolTypeEnum, HashSet<int>> type  
        in tickets) 
    { 
        if (GetRandomBoolean()) 
        { 
            type.Value.Add(i); 
        } 
    } 
}
```

为此，你使用两个循环，即`for`和`foreach`。第一个循环 100 次，模拟 100 个手环。其中有一个`foreach`循环，遍历所有可用的游泳池类型。对于每一个，你随机检查访客是否进入了特定的游泳池。通过获取一个随机的布尔值来检查。如果收到`true`，则将标识符添加到适当的集合中。`false`值表示具有给定手环号（`i`）的用户没有进入当前游泳池。

剩下的代码与生成各种统计数据有关。首先，让我们按游泳池类型呈现访客人数。这样的任务非常简单，因为你只需要遍历字典，以及写入游泳池类型和集合中的元素数量（使用`Count`属性），如下面的代码部分所示：

```cs
Console.WriteLine("Number of visitors by a pool type:"); 
foreach (KeyValuePair<PoolTypeEnum, HashSet<int>> type in tickets) 
{ 
    Console.WriteLine($" - {type.Key.ToString().ToLower()}:  
        {type.Value.Count}"); 
} 
```

接下来的部分找到了访客人数最多的游泳池。这是使用 LINQ 及其方法执行的，即：

+   `OrderByDescending`按集合中元素的数量降序排序元素

+   `Select`来选择游泳池类型

+   `FirstOrDefault`来获取第一个结果

然后，你只需呈现结果。做这件事的代码如下所示：

```cs
PoolTypeEnum maxVisitors = tickets 
    .OrderByDescending(t => t.Value.Count) 
    .Select(t => t.Key) 
    .FirstOrDefault(); 
Console.WriteLine($"Pool '{maxVisitors.ToString().ToLower()}'  
    was the most popular.");
```

然后，你需要获取至少访问了一个游泳池的人数。你可以通过创建所有集合的并集并获取最终集合的计数来执行此任务。首先，创建一个新的集合，并用有关休闲游泳池的标识符填充它。在代码的下面几行中，你调用`UnionWith`方法创建与以下三个集合的并集。代码的这部分如下所示：

```cs
HashSet<int> any =  
    new HashSet<int>(tickets[PoolTypeEnum.RECREATION]); 
any.UnionWith(tickets[PoolTypeEnum.COMPETITION]); 
any.UnionWith(tickets[PoolTypeEnum.THERMAL]); 
any.UnionWith(tickets[PoolTypeEnum.KIDS]); 
Console.WriteLine($"{any.Count} people visited at least  
    one pool."); 
```

最后的统计数据是在 SPA 中心一次访问中访问了所有游泳池的人数。要执行这样的计算，你只需要创建所有集合的交集，并获取最终集合的计数。为此，让我们创建一个新的集合，并用有关休闲游泳池的标识符填充它。然后，调用`IntersectWith`方法创建与以下三个集合的交集。最后，使用`Count`属性获取集合中的元素数量，并呈现结果，如下所示：

```cs
HashSet<int> all =  
    new HashSet<int>(tickets[PoolTypeEnum.RECREATION]); 
all.IntersectWith(tickets[PoolTypeEnum.COMPETITION]); 
all.IntersectWith(tickets[PoolTypeEnum.THERMAL]); 
all.IntersectWith(tickets[PoolTypeEnum.KIDS]); 
Console.WriteLine($"{all.Count} people visited all pools."); 
```

就是这样！当你运行应用程序时，你可能会收到类似以下的结果：

```cs
 Number of visitors by a pool type:
     - recreation: 54
     - competition: 44
     - thermal: 48
     - kids: 51

 Pool 'recreation' was the most popular.
 93 people visited at least one pool.
 5 people visited all pools.
```

你刚刚完成了两个关于哈希集的例子。尝试修改代码并添加新功能是了解这种数据结构的更好方法。当你准备好学习下一个数据结构时，让我们继续阅读。

# “排序”集合

前面描述的`HashSet`类可以被理解为一个只存储键而没有值的字典。所以，如果有`SortedDictionary`类，也许还有`SortedSet`类？确实有！但是，一个集合可以被“排序”吗？为什么“排序”一词用引号括起来？答案很简单——根据定义，一个集合存储一组不重复的对象，没有重复的元素，也没有特定的顺序。如果一个集合不支持顺序，它怎么能被“排序”呢？因此，“排序”集合可以被理解为`HashSet`和`SortedList`的组合，而不是一个集合本身。

如果您想要一个排序的不重复元素集合，可以使用“sorted”集合。适当的类名为`SortedSet`，并且位于`System.Collections.Generic`命名空间中。它具有一组方法，类似于已经描述的`HashSet`类的方法，例如`UnionWith`，`IntersectWith`，`ExceptWith`，`SymmetricExceptWith`，`Overlaps`，`IsSubsetOf`，`IsSupersetOf`，`IsProperSubsetOf`和`IsProperSupersetOf`。但是，它还包含用于返回最小值和最大值（分别为`Min`和`Max`）的附加属性。还值得一提的是`GetViewBetween`方法，它返回一个具有给定范围内的值的`SortedSet`实例。

您可以在[`msdn.microsoft.com/library/dd412070.aspx`](https://msdn.microsoft.com/library/dd412070.aspx)找到有关`SortedSet`泛型类的更多信息。

让我们继续进行一个简单的示例，看看如何在代码中使用“sorted”集合。

# 示例 - 删除重复项

例如，您将创建一个简单的应用程序，从名称列表中删除重复项。当然，名称的比较应该是不区分大小写的，因此不允许在同一集合中同时拥有`"Marcin"`和`"marcin"`。

要查看如何实现此目标，让我们将以下代码添加为`Program`类中`Main`方法的主体：

```cs
List<string> names = new List<string>() 
{ 
    "Marcin", 
    "Mary", 
    "James", 
    "Albert", 
    "Lily", 
    "Emily", 
    "marcin", 
    "James", 
    "Jane" 
}; 
SortedSet<string> sorted = new SortedSet<string>( 
    names, 
    Comparer<string>.Create((a, b) =>  
        a.ToLower().CompareTo(b.ToLower()))); 
foreach (string name in sorted) 
{ 
    Console.WriteLine(name); 
} 
```

首先，创建一个包含九个元素的名称列表，并初始化，包括`"Marcin"`和`"marcin"`。然后，创建`SortedSet`类的新实例，传递两个参数，即名称列表和不区分大小写的比较器。最后，只需遍历集合以在控制台中写入名称。

运行应用程序后，您将看到以下结果：

```cs
    Albert
    Emily
    James
    Jane
    Lily
    Marcin
    Mary

```

这是本章中展示的最后一个例子。因此，让我们继续进行总结。

# 总结

本书的第四章着重介绍了哈希表、字典和集合。所有这些集合都是有趣的数据结构，可以在各种场景中使用。通过详细描述和示例介绍这些集合，您已经看到选择适当的数据结构并不是一项微不足道的任务，需要分析与性能相关的主题，因为其中一些在检索值方面运行更好，而另一些则促进数据的添加和删除。

首先，您学习了如何使用哈希表的两个变体，即非泛型（`Hashtable`类）和泛型（`Dictionary`）。这些的巨大优势是基于键进行值查找的非常快速，接近*O(1)*的操作。为了实现这个目标，使用了哈希函数。此外，已经介绍了排序字典作为解决集合中无序项目问题并始终保持键排序的有趣解决方案。

随后，介绍了高性能解决方案的集合操作。它使用`HashSet`类，表示一个没有重复元素和特定顺序的对象集合。该类使得可以对集合执行各种操作，如并集、交集、差集和对称差。然后，介绍了“sorted”集合（`SortedSet`类）的概念，作为一个排序的不重复元素集合。

您是否想深入了解数据结构和算法，同时在 C#语言中开发应用程序？如果是这样，让我们继续进行下一章，介绍树。


# 第五章：树的变体

在前几章中，您已经了解了许多数据结构，从简单的数组开始。现在，是时候让您了解一组显著更复杂的数据结构，即**树**。

在本章的开头，将介绍基本树，以及在 C#语言中的实现和一些示例展示它的运行情况。然后，将介绍二叉树，详细描述其实现并举例说明其应用。二叉搜索树是另一种树的变体，是许多算法中使用的最流行的树类型之一。接下来的两节将涵盖自平衡树，即 AVL 和红黑树。

本章的其余部分将专门介绍堆作为基于树的数据结构。将介绍三种堆：二叉堆、二项式堆和斐波那契堆。这些类型将被简要介绍，并将展示这些数据结构的应用，使用外部包。

数组、列表、栈、队列、字典、集合，现在...树。您准备好提高难度并学习下一组数据结构了吗？如果是这样，让我们开始阅读！

在本章中，将涵盖以下主题：

+   基本树

+   二叉树

+   二叉搜索树

+   AVL 树

+   红黑树

+   二叉堆

+   二项式堆

+   斐波那契堆

# 基本树

让我们从介绍树开始。它们是什么？您对这样的数据结构应该是什么样子有任何想法吗？如果没有，让我们看一下以下图表，其中描述了一个带有关于其特定元素的标题的树：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dsal/img/7c15bf17-435a-40a2-a6ab-3b2768d96d92.png)

树由多个**节点**组成，包括一个**根**（图表中的**100**）。根不包含**父**节点，而所有其他节点都包含。例如，节点**1**的父元素是**100**，而节点**96**的父元素是**30**。此外，每个节点可以有任意数量的**子**节点，例如**根**的情况下有三个**子**节点（即**50**、**1**和**150**）。同一节点的子节点可以被称为**兄弟**，就像节点**70**和**61**的情况一样。没有子节点的节点称为**叶子**，例如图表中的**45**和**6**。看一下包含三个节点（即**30**、**96**和**9**）的矩形。树的这一部分可以称为**子树**。当然，您可以在树中找到许多子树。

让我们简要讨论节点的最小和最大子节点数。一般来说，这些数字是没有限制的，每个节点可以包含零、一个、两个、三个，甚至更多的子节点。然而，在实际应用中，子节点的数量通常限制为两个，正如您将在以下部分中看到的。

# 实现

基本树的 C#实现似乎是相当明显和不复杂的。为此，您可以声明两个类，表示单个节点和整个树，如下一节所述。

# 节点

第一个类名为`TreeNode`，声明为通用类，以便为开发人员提供指定存储在每个节点中的数据类型的能力。因此，您可以创建强类型化的解决方案，从而消除了将对象转换为目标类型的必要性。代码如下：

```cs
public class TreeNode<T> 
{ 
    public T Data { get; set; } 
    public TreeNode<T> Parent { get; set; } 
    public List<TreeNode<T>> Children { get; set; } 

    public int GetHeight() 
    { 
        int height = 1; 
        TreeNode<T> current = this; 
        while (current.Parent != null) 
        { 
            height++; 
            current = current.Parent; 
        } 
        return height; 
    } 
} 
```

该类包含三个属性：节点中存储的数据（`Data`）是在创建类的实例时指定的类型（`T`）的引用，指向父节点（`Parent`）的引用，以及指向子节点（`Children`）的引用的集合。

除了属性之外，`TreeNode`类还包含`GetHeight`方法，该方法返回节点的高度，即到根节点的距离。该方法的实现非常简单，因为它只是使用`while`循环从节点向上移动，直到没有父元素（达到根时）。

# 树

下一个必要的类名为`Tree`，它代表整个树。它的代码甚至比前一节中呈现的更简单，如下所示：

```cs
public class Tree<T> 
{ 
    public TreeNode<T> Root { get; set; } 
} 
```

该类只包含一个属性，`Root`。您可以使用此属性访问根节点，然后可以使用其`Children`属性获取树中其他节点的数据。

值得注意的是，`TreeNode`和`Tree`类都是泛型的，这些类使用相同的类型。例如，如果树节点应存储`string`值，则在`Tree`和`TreeNode`类的实例中应使用`string`类型。

# 示例 - 标识符的层次结构

您想看看如何在基于 C#的应用程序中使用树吗？让我们看看第一个示例。目标是构建具有几个节点的树，如下图所示。只有深色背景的节点组将在代码中呈现。但是，调整代码以自行扩展此树是一个好主意。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dsal/img/6afd0e1c-87c6-4057-a278-d08277502586.png)

正如您在示例中看到的那样，每个节点都存储一个整数值。因此，`int`将是`Tree`和`TreeNode`类都使用的类型。以下代码的一部分应放在`Program`类的`Main`方法中：

```cs
Tree<int> tree = new Tree<int>(); 
tree.Root = new TreeNode<int>() { Data = 100 }; 
tree.Root.Children = new List<TreeNode<int>> 
{ 
    new TreeNode<int>() { Data = 50, Parent = tree.Root }, 
    new TreeNode<int>() { Data = 1, Parent = tree.Root }, 
    new TreeNode<int>() { Data = 150, Parent = tree.Root } 
}; 
tree.Root.Children[2].Children = new List<TreeNode<int>>() 
{ 
    new TreeNode<int>()  
        { Data = 30, Parent = tree.Root.Children[2] } 
}; 
```

代码看起来相当简单，不是吗？

首先，创建`Tree`类的新实例。然后，通过创建`TreeNode`类的新实例，设置`Data`属性的值（为`100`），并将对`TreeNode`实例的引用分配给`Root`属性来配置根节点。

在接下来的几行中，指定了根节点的子节点，其值分别为`50`，`1`和`150`。对于每个节点，`Parent`属性的值都设置为对先前添加的根节点的引用。

代码的其余部分显示了如何为给定节点添加子节点，即根节点的第三个子节点，即值等于`150`的节点。在这里，只添加了一个节点，其值设置为`30`。当然，您还需要指定对父节点的引用。

就是这样！您已经创建了使用树的第一个程序。现在可以运行它，但您在控制台中看不到任何输出。如果要查看节点数据是如何组织的，可以调试程序并在调试时查看变量的值。

# 示例 - 公司结构

在前面的示例中，您看到如何将整数值用作树中每个节点的数据。但是，还可以将用户定义的类的实例存储在节点中。在此示例中，您将看到如何创建一个树，展示公司的结构，分为三个主要部门：开发、研究和销售。

在每个部门中都可以有另一个结构，例如开发团队的情况。在这里，**John Smith**是**开发部门主管**。他是**Chris Morris**的上司，后者是两名初级开发人员**Eric Green**和**Ashley Lopez**的经理。后者还是**Emily Young**的主管，后者是**开发实习生**。

以下是示例树的示意图：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dsal/img/d22420a3-eabe-4864-abeb-a7c8eeb5b16b.png)

正如您所看到的，每个节点应存储的信息不仅仅是一个整数值。应该有一个标识符、一个名称和一个角色。这些数据存储为`Person`类实例的属性值，如下面的代码片段所示：

```cs
public class Person 
{ 
    public int Id { get; set; } 
    public string Name { get; set; } 
    public string Role { get; set; } 

    public Person() { } 

    public Person(int id, string name, string role) 
    { 
        Id = id; 
        Name = name; 
        Role = role; 
    } 
} 
```

该类包含三个属性（`Id`，`Name`和`Role`），以及两个构造函数。第一个构造函数不带任何参数，而另一个带有三个参数，并设置特定属性的值。

除了创建一个新类之外，还需要在`Program`类的`Main`方法中添加一些代码。必要的行如下：

```cs
Tree<Person> company = new Tree<Person>(); 
company.Root = new TreeNode<Person>() 
{ 
    Data = new Person(100, "Marcin Jamro", "CEO"), 
    Parent = null 
}; 
company.Root.Children = new List<TreeNode<Person>>() 
{ 
    new TreeNode<Person>() 
    { 
        Data = new Person(1, "John Smith", "Head of Development"), 
        Parent = company.Root 
    }, 
    new TreeNode<Person>() 
    { 
        Data = new Person(50, "Mary Fox", "Head of Research"), 
        Parent = company.Root 
    }, 
    new TreeNode<Person>() 
    { 
        Data = new Person(150, "Lily Smith", "Head of Sales"), 
        Parent = company.Root 
    } 
}; 
company.Root.Children[2].Children = new List<TreeNode<Person>>() 
{ 
    new TreeNode<Person>() 
    {
        Data = new Person(30, "Anthony Black", "Sales Specialist"),
        Parent = company.Root.Children[2]
    } 
}; 
```

在第一行，创建了`Tree`类的一个新实例。值得一提的是，在创建`Tree`和`TreeNode`类的新实例时，使用了`Person`类作为指定类型。因此，你可以轻松地为每个节点存储多个简单数据。

代码的其余部分看起来与基本树的第一个示例相似。在这里，你还指定了根节点（`CEO`角色），然后配置了它的子元素（`John Smith`，`Mary Fox`和`Lily Smith`），并为现有节点之一设置了一个子节点，即`Head of Sales`的节点。

看起来简单明了吗？在下一节中，你将看到一种更受限制但非常重要和著名的树的变体：二叉树。

# 二叉树

一般来说，基本树中的每个节点可以包含任意数量的子节点。然而，在**二叉树**的情况下，一个节点不能包含超过两个子节点。这意味着它可以包含零个、一个或两个子节点。这一要求对二叉树的形状有重要影响，如下图所示展示了二叉树：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dsal/img/97d1ae70-d6ba-4cba-bddc-beef55c0cba2.png)

如前所述，二叉树中的节点最多可以包含两个子节点。因此，它们被称为**左子节点**和**右子节点**。在前面图中左侧显示的二叉树中，节点**21**有两个子节点，**68**为左子节点，**12**为右子节点，而节点**100**只有一个左子节点。

你有没有想过如何遍历树中的所有节点？在树的遍历过程中，你如何指定节点的顺序？有三种常见的方法：前序遍历、中序遍历和后序遍历，如下图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dsal/img/6203e8c5-d23c-41ca-b4ec-f7addeb54a82.png)

正如你在图中所看到的，这些方法之间存在明显的差异。然而，你有没有想过如何在二叉树中应用前序遍历、中序遍历或后序遍历？让我们详细解释所有这些方法。

如果你想使用**前序遍历**方法遍历二叉树，首先需要访问根节点。然后，访问左子节点。最后，访问右子节点。当然，这样的规则不仅适用于根节点，而且适用于树中的任何节点。因此，你可以理解前序遍历的顺序为首先访问当前节点，然后访问它的左子节点（使用前序遍历递归地遍历整个左子树），最后访问它的右子节点（以类似的方式遍历右子树）。

解释可能听起来有点复杂，所以让我们看一个简单的例子，关于前面图中左侧显示的树。首先，访问根节点（即**1**）。然后，分析它的左子节点。因此，下一个访问的节点是当前节点**9**。下一步是它的左子节点的前序遍历。因此，访问**5**。由于这个节点不包含任何子节点，你可以返回到遍历时**9**是当前节点的阶段。它已经被访问过，它的左子节点也是，所以现在是时候继续到它的右子节点。在这里，首先访问当前节点**6**，然后转到它的左子节点**3**。你可以应用相同的规则来继续遍历树。最终的顺序是**1**，**9**，**5**，**6**，**3**，**4**，**2**，**7**，**8**。

如果这听起来有点令人困惑，下图应该消除任何困惑：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dsal/img/7b456784-0ec6-474b-9b66-0f372d545dfb.png)

该图展示了前序遍历的以下步骤，并附有额外的指示：**C**表示**当前节点**，**L**表示**左子节点**，**R**表示**右子节点**。

第二个遍历模式称为**中序遍历**。它与前序遍历方法的区别在于节点访问的顺序：首先是左子节点，然后是当前节点，然后是右子节点。如果您看一下图表中显示的具有所有三种遍历模式的示例，您会发现第一个访问的节点是**5**。为什么？开始时，分析根节点，但不访问，因为中序遍历从左子节点开始。因此，它分析节点**9**，但它也有一个左子节点**5**，所以您继续到这个节点。由于此节点没有任何子节点，因此访问当前节点（**5**）。然后，返回到当前节点为**9**的步骤，并且 - 由于其左子节点已经被访问 - 您还访问当前节点。接下来，您转到右子节点，但它有一个左子节点**3**，应该先访问。根据相同的规则，您访问二叉树中的剩余节点。最终顺序是**5**，**9**，**3**，**6**，**1**，**4**，**7**，**8**，**2**。

最后的遍历模式称为**后序遍历**，支持以下节点遍历顺序：左子节点，右子节点，然后是当前节点。让我们分析图表右侧显示的后序遍历示例。开始时，分析根节点，但不访问，因为后序遍历从左子节点开始。因此 - 与中序遍历方法一样 - 继续到节点**9**，然后**5**。然后，需要分析节点**9**的右子节点。然而，节点**6**有左子节点（**3**），应该先访问。因此，在**5**之后，访问**3**，然后**6**，然后是**9**。有趣的是，二叉树的根节点在最后访问。最终顺序是**5**，**3**，**6**，**9**，**8**，**7**，**2**，**4**，**1**。

您可以在[`en.wikipedia.org/wiki/Binary_tree`](https://en.wikipedia.org/wiki/Binary_tree)找到有关二叉树的更多信息。

在这个简短的介绍之后，让我们继续进行基于 C#的实现。

# 实现

二叉树的实现真的很简单，特别是如果您使用了已经描述的基本树的代码。为了您的方便，整个必要的代码都放在了以下部分，但只有它的新部分被详细解释。

# 节点

二叉树中的节点由`BinaryTreeNode`的实例表示，它继承自`TreeNode`泛型类，具有以下代码：

```cs
public class TreeNode<T> 
{ 
    public T Data { get; set; } 
    public TreeNode<T> Parent { get; set; } 
    public List<TreeNode<T>> Children { get; set; } 

    public int GetHeight() 
    { 
        int height = 1; 
        TreeNode<T> current = this; 
        while (current.Parent != null) 
        { 
            height++; 
            current = current.Parent; 
        } 
        return height; 
    } 
} 
```

在`BinaryTreeNode`类中，需要声明两个属性`Left`和`Right`，它们分别表示节点的两个可能的子节点。代码的相关部分如下：

```cs
public class BinaryTreeNode<T> : TreeNode<T> 
{ 
    public BinaryTreeNode() => Children =  
        new List<TreeNode<T>>() { null, null }; 

    public BinaryTreeNode<T> Left 
    { 
        get { return (BinaryTreeNode<T>)Children[0]; } 
        set { Children[0] = value; } 
    } 

    public BinaryTreeNode<T> Right 
    { 
        get { return (BinaryTreeNode<T>)Children[1]; } 
        set { Children[1] = value; } 
    } 
} 
```

此外，您需要确保子节点的集合包含确切两个项目，最初设置为`null`。您可以通过在构造函数中为`Children`属性分配默认值来实现此目标，如前面的代码所示。因此，如果要添加子节点，应将对其的引用放置为列表（`Children`属性）的第一个或第二个元素。因此，这样的集合始终具有确切两个元素，并且可以访问第一个或第二个元素而不会出现任何异常。如果它设置为任何节点，则返回对其的引用，否则返回`null`。

# 树

下一个必要的类名为`BinaryTree`。它表示整个二叉树。通过使用泛型类，您可以轻松指定存储在每个节点中的数据类型。`BinaryTree`类的实现的第一部分如下：

```cs
public class BinaryTree<T> 
{ 
    public BinaryTreeNode<T> Root { get; set; } 
    public int Count { get; set; } 
} 
```

`BinaryTree`类包含两个属性：`Root`，表示根节点（作为`BinaryTreeNode`类的实例），以及`Count`，表示树中放置的节点的总数。当然，这些不是类的唯一成员，因为它还可以配备一组关于遍历树的方法。

本书中描述的第一个遍历方法是先序遍历。作为提醒，它首先访问当前节点，然后是其左子节点，最后是右子节点。`TraversePreOrder`方法的代码如下：

```cs
private void TraversePreOrder(BinaryTreeNode<T> node,  
    List<BinaryTreeNode<T>> result) 
{ 
    if (node != null) 
    { 
        result.Add(node); 
        TraversePreOrder(node.Left, result); 
        TraversePreOrder(node.Right, result); 
    } 
} 
```

该方法接受两个参数：当前节点（`node`）和已访问节点的列表（`result`）。递归实现非常简单。首先，通过确保参数不等于`null`来检查节点是否存在。然后，将当前节点添加到已访问节点的集合中，开始对左子节点执行相同的遍历方法，最后对右子节点执行相同的遍历方法。

类似的实现也适用于中序和后序遍历模式。让我们从`TraverseInOrder`方法的代码开始：

```cs
private void TraverseInOrder(BinaryTreeNode<T> node,  
    List<BinaryTreeNode<T>> result) 
{ 
    if (node != null) 
    { 
        TraverseInOrder(node.Left, result); 
        result.Add(node); 
        TraverseInOrder(node.Right, result); 
    } 
} 
```

在这里，您递归调用`TraverseInOrder`方法来处理左子节点，将当前节点添加到已访问节点的列表中，并开始对右子节点进行中序遍历。

下一个方法与后序遍历模式有关，如下所示：

```cs
private void TraversePostOrder(BinaryTreeNode<T> node,  
    List<BinaryTreeNode<T>> result) 
{ 
    if (node != null) 
    { 
        TraversePostOrder(node.Left, result); 
        TraversePostOrder(node.Right, result); 
        result.Add(node); 
    } 
} 
```

该代码与已描述的方法非常相似，但是应用了另一种访问节点的顺序。在这里，您首先访问左子节点，然后访问右子节点，最后访问当前节点。

最后，让我们添加用于以各种模式遍历树的公共方法，该方法调用先前介绍的私有方法。相关代码如下：

```cs
public List<BinaryTreeNode<T>> Traverse(TraversalEnum mode) 
{ 
    List<BinaryTreeNode<T>> nodes = new List<BinaryTreeNode<T>>(); 
    switch (mode) 
    { 
        case TraversalEnum.PREORDER: 
            TraversePreOrder(Root, nodes); 
            break; 
        case TraversalEnum.INORDER: 
            TraverseInOrder(Root, nodes); 
            break; 
        case TraversalEnum.POSTORDER: 
            TraversePostOrder(Root, nodes); 
            break; 
    } 
    return nodes; 
} 
```

该方法只接受一个参数，即`TraversalEnum`枚举的值，选择适当的先序、中序和后序模式。`Traverse`方法使用`switch`语句根据参数的值调用适当的私有方法。

为了使用`Traverse`方法，还需要声明`TraversalEnum`枚举，如下所示：

```cs
public enum TraversalEnum 
{ 
    PREORDER, 
    INORDER, 
    POSTORDER 
} 
```

本节中描述的最后一个方法是`GetHeight`。它返回树的高度，可以理解为从任何叶节点到根节点所需的最大步数。实现如下：

```cs
public int GetHeight() 
{ 
    int height = 0; 
    foreach (BinaryTreeNode<T> node  
        in Traverse(TraversalEnum.PREORDER)) 
    { 
        height = Math.Max(height, node.GetHeight()); 
    } 
    return height; 
} 
```

该代码只是使用先序遍历遍历树的所有节点，读取当前节点的高度（使用先前描述的`TreeNode`类的`GetHeight`方法），如果大于当前最大值，则将其保存为最大值。最后返回计算出的高度。

在介绍了二叉树的主题之后，让我们看一个示例，其中使用这种数据结构来存储简单测验中的问题和答案。

# 示例 - 简单的测验

作为二叉树的一个示例，将使用一个简单的测验应用程序。测验由几个问题和答案组成，根据先前做出的决定显示。应用程序呈现问题，等待用户按下*Y*（是）或*N*（否），然后继续下一个问题或显示答案。

测验的结构以二叉树的形式创建，如下所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dsal/img/2679026d-3aac-4d4d-8868-2b46f7dfbe2f.png)

首先，用户被问及是否有应用程序开发经验。如果是，程序会询问他或她是否已经作为开发人员工作了五年以上。在肯定答案的情况下，将呈现关于申请成为高级开发人员的结果。当然，在用户做出不同决定的情况下，还会显示其他答案和问题。

简单测验的实现需要`BinaryTree`和`BinaryTreeNode`类，这些类在先前已经介绍和解释过。除此之外，还应该声明`QuizItem`类来表示单个项目，例如问题或答案。每个项目只包含文本内容，存储为`Text`属性的值。适当的实现如下：

```cs
public class QuizItem 
{ 
    public string Text { get; set; } 
    public QuizItem(string text) => Text = text; 
} 
```

在`Program`类中需要进行一些修改。让我们来看一下修改后的`Main`方法：

```cs
static void Main(string[] args) 
{ 
    BinaryTree<QuizItem> tree = GetTree(); 
    BinaryTreeNode<QuizItem> node = tree.Root; 
    while (node != null) 
    { 
        if (node.Left != null || node.Right != null) 
        { 
            Console.Write(node.Data.Text); 
            switch (Console.ReadKey(true).Key) 
            { 
                case ConsoleKey.Y: 
                    WriteAnswer(" Yes"); 
                    node = node.Left; 
                    break; 
                case ConsoleKey.N: 
                    WriteAnswer(" No"); 
                    node = node.Right; 
                    break; 
            } 
        } 
        else 
        { 
            WriteAnswer(node.Data.Text); 
            node = null; 
        } 
    } 
} 
```

在方法中的第一行，调用`GetTree`方法（如下面的代码片段所示）来构建具有问题和答案的树。然后，将根节点作为当前节点，直到到达答案为止。

首先，检查左侧或右侧子节点是否存在，即是否为问题（而不是答案）。然后，在控制台中写入文本内容，并等待用户按键。如果等于*Y*，则显示有关选择*是*选项的信息，并使用当前节点的左子节点作为当前节点。在选择*否*的情况下执行类似的操作，但然后使用当前节点的右子节点。

当用户做出的决定导致答案显示时，它会在控制台中呈现，并将`null`赋给`node`变量。因此，您会跳出`while`循环。

如前所述，`GetTree`方法用于构建具有问题和答案的二叉树。其代码如下所示：

```cs
private static BinaryTree<QuizItem> GetTree() 
{ 
    BinaryTree<QuizItem> tree = new BinaryTree<QuizItem>(); 
    tree.Root = new BinaryTreeNode<QuizItem>() 
    { 
        Data = new QuizItem("Do you have experience in developing  
            applications?"), 
        Children = new List<TreeNode<QuizItem>>() 
        { 
            new BinaryTreeNode<QuizItem>() 
            { 
                Data = new QuizItem("Have you worked as a  
                    developer for more than 5 years?"), 
                Children = new List<TreeNode<QuizItem>>() 
                { 
                    new BinaryTreeNode<QuizItem>() 
                    { 
                        Data = new QuizItem("Apply as a senior  
                            developer!") 
                    }, 
                    new BinaryTreeNode<QuizItem>() 
                    { 
                        Data = new QuizItem("Apply as a middle  
                            developer!") 
                    } 
                } 
            }, 
            new BinaryTreeNode<QuizItem>() 
            { 
                Data = new QuizItem("Have you completed  
                    the university?"), 
                Children = new List<TreeNode<QuizItem>>() 
                { 
                    new BinaryTreeNode<QuizItem>() 
                    { 
                        Data = new QuizItem("Apply for a junior  
                            developer!") 
                    }, 
                    new BinaryTreeNode<QuizItem>() 
                    { 
                        Data = new QuizItem("Will you find some  
                            time during the semester?"), 
                        Children = new List<TreeNode<QuizItem>>() 
                        { 
                            new BinaryTreeNode<QuizItem>() 
                            { 
                                Data = new QuizItem("Apply for our  
                                   long-time internship program!") 
                            }, 
                            new BinaryTreeNode<QuizItem>() 
                            { 
                                Data = new QuizItem("Apply for  
                                   summer internship program!") 
                            } 
                        } 
                    } 
                } 
            } 
        } 
    }; 
    tree.Count = 9; 
    return tree; 
} 
```

首先，创建`BinaryTree`泛型类的新实例。还配置每个节点包含`QuizItem`类的实例的数据。然后，将`Root`属性分配给`BinaryTreeNode`的新实例。

有趣的是，即使在以编程方式创建问题和答案时，您也会创建某种类似树的结构，因为您使用`Children`属性并直接在这些结构中指定项目。因此，您无需为所有问题和答案创建许多本地变量。值得注意的是，与问题相关的节点是`BinaryTreeNode`类的实例，具有两个子节点（用于*是*和*否*决定），而与答案相关的节点不能包含任何子节点。

在所提供的解决方案中，`BinaryTreeNode`实例的`Parent`属性的值未设置。如果要使用它们或获取节点或树的高度，则应自行设置它们。

最后一个辅助方法是`WriteAnswer`，代码如下：

```cs
private static void WriteAnswer(string text) 
{ 
    Console.ForegroundColor = ConsoleColor.White; 
    Console.WriteLine(text); 
    Console.ForegroundColor = ConsoleColor.Gray; 
} 
```

该方法只是在控制台中以白色显示传递的文本参数。它用于显示用户做出的决定和答案的文本内容。

简单的测验应用程序已准备就绪！您可以构建项目，启动它，并回答一些问题以查看结果。然后，让我们关闭程序并继续到下一部分，介绍二叉树数据结构的变体。

# 二叉搜索树

二叉树是一种有趣的数据结构，允许创建元素的层次结构，每个节点最多可以包含两个子节点，但没有关于节点之间关系的任何规则。因此，如果要检查二叉树是否包含给定值，需要检查每个节点，使用三种可用模式之一遍历树：前序，中序或后序。这意味着查找时间是线性的，即*O(n)*。

如果树中存在一些关于节点关系的明确规则呢？假设有这样一种情况，左子树包含小于根值的节点，而右子树包含大于根值的节点。然后，您可以将搜索值与当前节点进行比较，并决定是否应继续在左侧或右侧子树中搜索。这种方法可以显著限制检查树是否包含给定值所需的操作数量。这似乎很有趣，不是吗？

这种方法应用于**二叉搜索树**数据结构，也称为**BST**。它是一种二叉树，引入了两个关于树中节点关系的严格规则。规则规定对于任何节点：

+   其左子树中所有节点的值必须小于其值

+   其右子树中所有节点的值必须大于其值

一般来说，二叉搜索树可以包含两个或更多具有相同值的元素。但是，在本书中给出了一个简化版本，不接受多个具有相同值的元素。

实际上是什么样子？让我们看一下以下二叉搜索树的图表：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dsal/img/3cf99bb5-d124-494d-a022-c15038af2e46.png)

左侧显示的树包含 12 个节点。让我们检查它是否符合二叉搜索树的规则。您可以通过分析树中除了叶节点以外的每个节点来进行检查。

让我们从根节点（值为**50**）开始，它在左子树中包含四个后代节点（**40**、**30**、**45**、**43**），都小于**50**。根节点在右子树中包含七个后代节点（**60**、**80**、**70**、**65**、**75**、**90**、**100**），都大于**50**。这意味着根节点满足了二叉搜索树的规则。如果您想检查节点**80**的二叉搜索树规则，您会发现左子树中所有后代节点的值（**70**、**65**、**75**）都小于**80**，而右子树中的值（**90**、**100**）都大于**80**。您应该对树中的所有节点执行相同的验证。同样，您可以确认图表右侧的二叉搜索树遵守了规则。

然而，这两个二叉搜索树在拓扑结构上有很大的不同。它们的高度相同，但节点的数量不同——12 和 7。左边的看起来很胖，而另一个则相对瘦。哪一个更好？为了回答这个问题，让我们考虑一下在树中搜索一个值的算法。例如，搜索值**43**的过程在下图中描述和展示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dsal/img/32e6b37f-f619-4268-b1b6-0c81a8af6846.png)

开始时，您取根节点的值（即**50**）并检查给定的值（**43**）是较小还是较大。它较小，所以您继续在左子树中搜索。因此，您将**43**与**40**进行比较。这次选择右子树，因为**43**大于**40**。接下来，**43**与**45**进行比较，并选择左子树。在这里，您将**43**与**43**进行比较。因此，找到了给定的值。如果您看一下树，您会发现只需要四次比较，对性能的影响是显而易见的。

因此，很明显树的形状对查找性能有很大影响。当然，拥有高度有限的胖树要比高度更大的瘦树好得多。性能提升是由于在继续在左子树或右子树中搜索时做出决策，而无需分析所有节点的值。如果节点没有两个子树，对性能的积极影响将受到限制。在最坏的情况下，当每个节点只包含一个子节点时，搜索时间甚至是线性的。然而，在理想的二叉搜索树中，查找时间是*O(log n)*操作。

您可以在[`en.wikipedia.org/wiki/Binary_search_tree`](https://en.wikipedia.org/wiki/Binary_search_tree)找到更多关于二叉搜索树的信息。

在这个简短的介绍之后，让我们继续使用 C#语言进行实现。最后，您将看到一个示例，展示了如何在实践中使用这种数据结构。

# 实现

二叉搜索树的实现比先前描述的树的变体更困难。例如，它要求您准备树中节点的插入和删除操作，这些操作不会违反二叉搜索树中元素排列的规则。此外，您需要引入一个比较节点的机制。

# 节点

让我们从表示树中单个节点的类开始。幸运的是，您可以使用已经描述的二叉树类（`BinaryTreeNode`）的实现作为基础。修改后的代码如下：

```cs
public class BinaryTreeNode<T> : TreeNode<T> 
{ 
    public BinaryTreeNode() => Children =  
        new List<TreeNode<T>>() { null, null }; 

    public BinaryTreeNode<T> Parent { get; set; } 

    public BinaryTreeNode<T> Left 
    { 
        get { return (BinaryTreeNode<T>)Children[0]; } 
        set { Children[0] = value; } 
    } 

    public BinaryTreeNode<T> Right 
    { 
        get { return (BinaryTreeNode<T>)Children[1]; } 
        set { Children[1] = value; } 
    } 

    public int GetHeight() 
    { 
        int height = 1; 
        BinaryTreeNode<T> current = this; 
        while (current.Parent != null) 
        { 
            height++; 
            current = current.Parent; 
        } 
        return height; 
    } 
} 
```

由于 BST 是二叉树的一种变体，每个节点都有对其左右子节点（如果不存在则为`null`）以及父节点的引用。节点还存储给定类型的值。正如您在前面的代码中所看到的，`BinaryTreeNode`类添加了两个成员，即`Parent`属性（`BinaryTreeNode`类型）和`GetHeight`方法。它们是从`TreeNode`类的实现中移动和调整的。最终代码如下：

```cs
public class TreeNode<T> 
{ 
    public T Data { get; set; } 
    public List<TreeNode<T>> Children { get; set; } 
} 
```

修改的原因是为开发人员提供一种简单的方法，以便在不需要从`TreeNode`到`BinaryTreeNode`进行转换的情况下访问给定节点的父节点。

# 树

整个树由`BinarySearchTree`类的实例表示，该类继承自`BinaryTree`泛型类，如下面的代码片段所示：

```cs
public class BinarySearchTree<T> : BinaryTree<T>  
    where T : IComparable 
{ 
} 
```

值得一提的是，每个节点中存储的数据类型应该是可比较的。因此，它必须实现`IComparable`接口。这种要求是必要的，因为算法需要了解值之间的关系。

当然，这不是`BinarySearchTree`类实现的最终版本。在接下来的部分中，您将看到如何添加新功能，比如查找、插入和删除节点。

# 查找

让我们来看一下`Contains`方法，它检查树中是否包含具有给定值的节点。当然，此方法考虑了有关节点排列的 BST 规则，以限制比较的数量。代码如下：

```cs
public bool Contains(T data) 
{ 
    BinaryTreeNode<T> node = Root; 
    while (node != null) 
    { 
        int result = data.CompareTo(node.Data); 
        if (result == 0) 
        { 
            return true; 
        } 
        else if (result < 0) 
        { 
            node = node.Left; 
        } 
        else 
        { 
            node = node.Right; 
        } 
    } 
    return false; 
} 
```

该方法只接受一个参数，即应在树中找到的值。在方法内部，存在`while`循环。在其中，将搜索的值与当前节点的值进行比较。如果它们相等（比较返回`0`作为结果），则找到该值，并返回`true`布尔值以通知搜索成功完成。如果搜索的值小于当前节点的值，则算法继续在以当前节点的左子节点为根的子树中搜索。否则，使用右子树。

`CompareTo`方法由`System`命名空间中的`IComparable`接口的实现提供。这种方法使得比较值成为可能。如果它们相等，则返回`0`。如果调用该方法的对象大于参数，则返回大于`0`的值。否则，返回小于`0`的值。

循环执行直到找到节点或没有合适的子节点可以跟随。

# 插入

下一个必要的操作是将节点插入 BST。这项任务有点复杂，因为您需要找到一个不会违反 BST 规则的新元素添加位置。让我们来看一下`Add`方法的代码：

```cs
public void Add(T data) 
{ 
    BinaryTreeNode<T> parent = GetParentForNewNode(data); 
    BinaryTreeNode<T> node = new BinaryTreeNode<T>()  
        { Data = data, Parent = parent }; 

    if (parent == null) 
    { 
        Root = node; 
    } 
    else if (data.CompareTo(parent.Data) < 0) 
    { 
        parent.Left = node; 
    } 
    else 
    { 
        parent.Right = node; 
    } 

    Count++; 
} 
```

该方法接受一个参数，即应添加到树中的值。在方法内部，找到应将新节点添加为子节点的父元素（使用`GetParentForNewNode`辅助方法），然后创建`BinaryTreeNode`类的新实例，并设置其`Data`和`Parent`属性的值。

在方法的后续部分，您检查找到的父元素是否等于`null`。这意味着树中没有节点，新节点应该被添加为根节点，这在将节点的引用分配给`Root`属性的行中很明显。下一个比较检查要添加的值是否小于父节点的值。在这种情况下，新节点应该被添加为父节点的左子节点。否则，新节点将被放置为父节点的右子节点。最后，树中存储的元素数量增加。

让我们来看看用于查找新节点的父元素的辅助方法：

```cs
private BinaryTreeNode<T> GetParentForNewNode(T data) 
{ 
    BinaryTreeNode<T> current = Root; 
    BinaryTreeNode<T> parent = null; 
    while (current != null) 
    { 
        parent = current; 
        int result = data.CompareTo(current.Data); 
        if (result == 0) 
        { 
            throw new ArgumentException( 
                $"The node {data} already exists."); 
        } 
        else if (result < 0) 
        { 
            current = current.Left; 
        } 
        else 
        { 
            current = current.Right; 
        } 
    } 

    return parent; 
} 
```

该方法名为`GetParentForNewNode`，只需要一个参数，即新节点的值。在这个方法中，您声明了两个变量，表示当前分析的节点（`current`）和父节点（`parent`）。这些值在`while`循环中被修改，直到算法找到新节点的合适位置。

在循环中，您将当前节点的引用存储为潜在的父节点。然后，进行比较，就像在先前描述的代码片段中一样。首先，您检查要添加的值是否等于当前节点的值。如果是，将抛出异常，因为不允许向分析版本的 BST 中添加多个具有相同值的元素。如果要添加的值小于当前节点的值，则算法继续在左子树中搜索新节点的位置。否则，使用当前节点的右子树。最后，将`parent`变量的值返回以指示找到新节点的位置。

# 删除

现在你知道如何创建一个新的 BST，向其中添加一些节点，并检查树中是否已经存在给定的值。但是，你也能从树中删除一个项目吗？当然可以！您将在本节中学习如何实现这一目标。

从树中删除节点的主要方法名为`Remove`，只需要一个参数，即应该被删除的节点的值。`Remove`方法的实现如下：

```cs
public void Remove(T data) 
{ 
    Remove(Root, data); 
} 
```

正如您所看到的，该方法只是调用另一个名为`Remove`的方法。该方法的实现更加复杂，如下所示：

```cs
private void Remove(BinaryTreeNode<T> node, T data) 
{ 
    if (node == null)
    {
        throw new ArgumentException(
            $"The node {data} does not exist.");
    }
    else if (data.CompareTo(node.Data) < 0) 
    { 
        Remove(node.Left, data); 
    } 
    else if (data.CompareTo(node.Data) > 0) 
    { 
        Remove(node.Right, data); 
    } 
    else 
    { 
        if (node.Left == null && node.Right == null) 
        { 
            ReplaceInParent(node, null); 
            Count--; 
        } 
        else if (node.Right == null) 
        { 
            ReplaceInParent(node, node.Left); 
            Count--; 
        } 
        else if (node.Left == null) 
        { 
            ReplaceInParent(node, node.Right); 
            Count--; 
        } 
        else 
        { 
            BinaryTreeNode<T> successor =  
                FindMinimumInSubtree(node.Right); 
            node.Data = successor.Data; 
            Remove(successor, successor.Data); 
        } 
    } 
} 
```

在开始时，该方法检查当前节点（`node`参数）是否存在。如果不存在，则会抛出异常。然后，`Remove`方法尝试找到要删除的节点。通过将当前节点的值与要删除的值进行比较，并递归调用`Remove`方法，尝试在当前节点的左子树或右子树中找到要删除的节点。这些操作在条件语句中执行，条件为`data.CompareTo(node.Data) < 0`和`data.CompareTo(node.Data) > 0`。

最有趣的操作是在方法的以下部分执行的。在这里，您需要处理节点删除的四种情况，即：

+   删除叶节点

+   只有左子节点的节点

+   只有右子节点的节点

+   删除具有左右子节点的节点

在第一种情况中，您只需更新父元素中对被删除节点的引用。因此，父节点到被删除节点的引用将不存在，无法在遍历树时到达。

第二种情况也很简单，因为您只需要用被删除节点的左子节点替换父元素中对被删除节点的引用。这种情况在下图中显示，演示了如何删除只有左子节点的节点**80**：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dsal/img/a8d6e2e8-5b7d-4c51-a014-bcc3cc5a5750.png)

第三种情况与第二种情况非常相似。因此，您只需用被删除节点的右子节点替换对被删除节点（在父元素中）的引用。

所有这三种情况都通过调用辅助方法（`ReplaceInParent`）在代码中以类似的方式处理。它接受两个参数：要删除的节点和应该在父节点中替换它的节点。因此，如果要删除叶节点，只需将`null`作为第二个参数传递，因为您不希望用其他任何东西替换已删除的节点。在仅具有一个子节点的情况下，您将传递到左侧或右侧子节点的引用。当然，您还需要递减存储在树中的元素数量的计数器。

代码的相关部分如下（对于不同情况有所不同）：

```cs
ReplaceInParent(node, node.Left); 
Count--; 
```

当然，最复杂的情况是删除具有两个子节点的节点。在这种情况下，您会在要删除的节点的右子树中找到具有最小值的节点。然后，您交换要删除的节点的值与找到的节点的值。最后，您只需要对找到的节点递归调用`Remove`方法。代码的相关部分如下所示：

```cs
BinaryTreeNode<T> successor = FindMinimumInSubtree(node.Right); 
node.Data = successor.Data; 
Remove(successor, successor.Data); 
```

重要的角色由`ReplaceInParent`辅助方法执行，其代码如下：

```cs
private void ReplaceInParent(BinaryTreeNode<T> node,  
    BinaryTreeNode<T> newNode) 
{ 
    if (node.Parent != null) 
    { 
        if (node.Parent.Left == node) 
        { 
            node.Parent.Left = newNode; 
        } 
        else 
        { 
            node.Parent.Right = newNode; 
        } 
    } 
    else 
    { 
        Root = newNode; 
    } 

    if (newNode != null) 
    { 
        newNode.Parent = node.Parent; 
    } 
} 
```

该方法接受两个参数：要删除的节点（`node`）和应该在父节点中替换它的节点（`newNode`）。如果要删除的节点不是根，则检查它是否是父节点的左子节点。如果是，则更新适当的引用，也就是将新节点设置为要删除的节点的父节点的左子节点。以类似的方式，该方法处理了要删除的节点是父节点的右子节点的情况。如果要删除的节点是根，则将替换节点设置为根。

最后，您检查新节点是否不等于`null`，也就是说，您没有删除叶节点。在这种情况下，您将`Parent`属性的值设置为指示新节点应该与要删除的节点具有相同父节点。

最后的辅助方法名为`FindMinimumInSubtree`，代码如下：

```cs
private BinaryTreeNode<T> FindMinimumInSubtree( 
    BinaryTreeNode<T> node) 
{ 
    while (node.Left != null) 
    { 
        node = node.Left; 
    } 
    return node; 
} 
```

该方法只接受一个参数，即应找到最小值的子树的根。在方法内部，使用`while`循环来获取最左边的元素。当没有左子节点时，返回`node`变量的当前值。

所呈现的 BST 实现基于[`en.wikipedia.org/wiki/Binary_search_tree`](https://en.wikipedia.org/wiki/Binary_search_tree)上显示的代码。

代码看起来相当简单，不是吗？但是，在实践中它是如何工作的呢？让我们看一下图表，描述了删除具有两个子节点的节点的过程：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dsal/img/ee7545af-cf87-4982-bbd0-9c8dd810140b.png)

该图显示了如何删除值为**40**的节点。为此，您需要找到继承者，也就是要删除的节点右子树中具有最小值的节点。继承者是节点**42**，它替换了节点**40**。

# 示例-BST 可视化

在阅读有关 BST 的部分时，您已经了解了有关数据结构的很多知识。因此，现在是时候创建一个示例程序，以查看这种树的变体如何运作。该应用程序将展示如何创建 BST，手动添加一些节点（使用先前呈现的插入方法），删除节点，遍历树，并在控制台中可视化树。

让我们调整`Program`类的代码，如下所示：

```cs
class Program 
{ 
    private const int COLUMN_WIDTH = 5; 

    public static void Main(string[] args) 
    { 
        Console.OutputEncoding = Encoding.UTF8; 

        BinarySearchTree<int> tree = new BinarySearchTree<int>(); 
        tree.Root = new BinaryTreeNode<int>() { Data = 100 }; 
        tree.Root.Left = new BinaryTreeNode<int>()  
            { Data = 50, Parent = tree.Root }; 
        tree.Root.Right = new BinaryTreeNode<int>()  
            { Data = 150, Parent = tree.Root }; 
        tree.Count = 3; 
        VisualizeTree(tree, "The BST with three nodes  
            (50, 100, 150):"); 

        tree.Add(75); 
        tree.Add(125); 
        VisualizeTree(tree, "The BST after adding two nodes  
            (75, 125):"); (...) 

        tree.Remove(25); 
        VisualizeTree(tree,  
            "The BST after removing the node 25:"); (...) 

        Console.Write("Pre-order traversal:\t"); 
        Console.Write(string.Join(", ", tree.Traverse( 
            TraversalEnum.PREORDER).Select(n => n.Data))); 
        Console.Write("\nIn-order traversal:\t"); 
        Console.Write(string.Join(", ", tree.Traverse( 
            TraversalEnum.INORDER).Select(n => n.Data))); 
        Console.Write("\nPost-order traversal:\t"); 
        Console.Write(string.Join(", ", tree.Traverse( 
            TraversalEnum.POSTORDER).Select(n => n.Data))); 
    } 
```

一开始，通过创建`BinarySearchTree`类的新实例来准备一个新树（其中节点存储整数值）。通过手动配置，添加了三个节点，并指示了适当的子节点和父节点元素的引用。代码的相关部分如下：

```cs
BinarySearchTree<int> tree = new BinarySearchTree<int>(); 
tree.Root = new BinaryTreeNode<int>() { Data = 100 }; 
tree.Root.Left = new BinaryTreeNode<int>()  
    { Data = 50, Parent = tree.Root }; 
tree.Root.Right = new BinaryTreeNode<int>()  
    { Data = 150, Parent = tree.Root }; 
tree.Count = 3; 
```

然后，使用`Add`方法向树中添加一些节点，并使用`VisualizeTree`方法可视化树的当前状态，如下所示：

```cs
tree.Add(125); 
VisualizeTree(tree, "The BST after adding two nodes (75, 125):"); 
```

接下来的一系列操作与从树中删除各种节点以及可视化特定更改相关。代码如下：

```cs
tree.Remove(25); 
VisualizeTree(tree, "The BST after removing the node 25:"); 
```

最后，展示了所有三种遍历模式。与前序遍历相关的代码部分如下：

```cs
Console.WriteLine("Pre-order traversal:\t"); 
Console.Write(string.Join(", ",  
    tree.Traverse(TraversalEnum.PREORDER).Select(n => n.Data))); 
```

另一个有趣的任务是在控制台中开发树的可视化。这样的功能非常有用，因为它允许舒适快速地观察树，而无需在 IDE 中调试应用程序并展开工具提示中的当前变量值。然而，在控制台中呈现树并不是一项简单的任务。幸运的是，您不需要担心，因为您将在本节中学习如何实现这样的功能。

首先，让我们看一下`VisualizeTree`方法：

```cs
private static void VisualizeTree( 
    BinarySearchTree<int> tree, string caption) 
{ 
    char[][] console = InitializeVisualization( 
        tree, out int width); 
    VisualizeNode(tree.Root, 0, width / 2, console, width); 
    Console.WriteLine(caption); 
    foreach (char[] row in console) 
    { 
        Console.WriteLine(row); 
    } 
} 
```

该方法接受两个参数：代表整个树的`BinarySearchTree`类的实例，以及应该显示在可视化上方的标题。在方法内部，使用`InitializeVisualization`辅助方法初始化了不规则数组（其中包含应在控制台中显示的字符）。然后，调用`VisualizeNode`递归方法，将不同部分的不规则数组填充为有关树中特定节点的数据。最后，在控制台中写入标题和缓冲区（由不规则数组表示）中的所有行。

下一个有趣的方法是`InitializeVisualization`，它创建了前面提到的不规则数组，如下面的代码片段所示：

```cs
private static char[][] InitializeVisualization( 
    BinarySearchTree<int> tree, out int width) 
{ 
    int height = tree.GetHeight(); 
    width = (int)Math.Pow(2, height) - 1; 
    char[][] console = new char[height * 2][]; 
    for (int i = 0; i < height * 2; i++) 
    { 
        console[i] = new char[COLUMN_WIDTH * width]; 
    } 
    return console; 
}
```

不规则数组包含的行数等于树的高度乘以`2`，以便为连接节点与父节点的线留出空间。列数根据公式*宽度* * 2*^(高度)* - 1 计算，其中*宽度*是常量值`COLUMN_WIDTH`，*高度*是树的高度。如果您在控制台中查看结果，这些值可能更容易理解：

```cs
                                        100
                    ┌-------------------+-------------------┐
                    50                                      150
          ┌---------+---------┐                  ┌---------+---------┐
          25                  75                  125                 175
                               +----┐        ┌----+----┐
                                   90        110       135

```

在这里，不规则数组有 8 个元素。每个都是一个包含 75 个元素的数组。当然，您可以将其理解为具有 8 行和 75 列的屏幕缓冲区。

在`VisualizeTree`方法中，调用了`VisualizeNode`。您是否有兴趣了解它是如何工作的，以及如何呈现节点的值以及线条？如果是的话，让我们看一下它的代码，如下所示：

```cs
private static void VisualizeNode(BinaryTreeNode<int> node, 
    int row, int column, char[][] console, int width) 
{ 
    if (node != null) 
    { 
        char[] chars = node.Data.ToString().ToCharArray(); 
        int margin = (COLUMN_WIDTH - chars.Length) / 2; 
        for (int i = 0; i < chars.Length; i++) 
        { 
            console[row][COLUMN_WIDTH * column + i + margin]  
                = chars[i]; 
        } 

        int columnDelta = (width + 1) /  
            (int)Math.Pow(2, node.GetHeight() + 1); 
        VisualizeNode(node.Left, row + 2, column - columnDelta,  
            console, width); 
        VisualizeNode(node.Right, row + 2, column + columnDelta,  
            console, width); 
        DrawLineLeft(node, row, column, console, columnDelta); 
        DrawLineRight(node, row, column, console, columnDelta); 
    } 
} 
```

`VisualizeNode`方法接受五个参数：用于可视化的当前节点（`node`）、行的索引（`row`）、列的索引（`column`）、作为缓冲区的不规则数组（`console`）和宽度（`width`）。在方法内部，检查当前节点是否存在。如果存在，则获取节点的值作为`char`数组，计算边距，并将`char`数组（表示值的基于字符的表示）写入缓冲区（`console`变量）。

在接下来的代码中，为当前节点的左右子节点调用了`VisualizeNode`方法。当然，您需要调整行的索引（加`2`）和列的索引（加或减计算出的值）。

最后，通过调用`DrawLineLeft`和`DrawLineRight`方法来绘制线条。第一个方法在以下代码片段中呈现：

```cs
private static void DrawLineLeft(BinaryTreeNode<int> node,  
    int row, int column, char[][] console, int columnDelta) 
{ 
    if (node.Left != null) 
    { 
        int startColumnIndex =  
            COLUMN_WIDTH * (column - columnDelta) + 2; 
        int endColumnIndex = COLUMN_WIDTH * column + 2; 
        for (int x = startColumnIndex + 1;  
            x < endColumnIndex; x++) 
        { 
            console[row + 1][x] = '-'; 
        } 
        console[row + 1][startColumnIndex] = '\u250c'; 
        console[row + 1][endColumnIndex] = '+'; 
    } 
} 
```

该方法还接受五个参数：应该绘制线的当前节点（`node`）、行索引（`row`）、列索引（`column`）、作为缓冲区的嵌套数组（`console`）和在`VisualizeNode`方法中计算的增量值（`columnDelta`）。首先，你检查当前节点是否包含左子节点，因为只有在这种情况下才需要绘制线的左部分。如果是这样，你计算列的起始和结束索引，并用破折号填充嵌套数组的适当元素。最后，在绘制的线将与另一个元素的右线连接的地方，加入加号到嵌套数组中。此外，Unicode 字符┌（`\u250c`）也被添加到线的另一侧，以创建用户友好的可视化。

几乎以相同的方式，你可以为当前节点绘制右线。当然，你需要调整代码以计算列的起始和结束索引，并更改用于表示线方向变化的字符。`DrawLineRight`方法的最终代码版本如下：

```cs
private static void DrawLineRight(BinaryTreeNode<int> node, 
    int row, int column, char[][] console, int columnDelta) 
{ 
    if (node.Right != null) 
    { 
        int startColumnIndex = COLUMN_WIDTH * column + 2; 
        int endColumnIndex =  
            COLUMN_WIDTH * (column + columnDelta) + 2; 
        for (int x = startColumnIndex + 1;  
            x < endColumnIndex; x++) 
        { 
            console[row + 1][x] = '-'; 
        } 
        console[row + 1][startColumnIndex] = '+'; 
        console[row + 1][endColumnIndex] = '\u2510'; 
    } 
} 
```

就是这样！你已经编写了构建项目、启动程序并看到它运行所需的全部代码。启动后，你将看到第一个 BST，如下所示：

```cs
    The BST with three nodes (50, 100, 150):
          100
     ┌----+----┐
     50        150 
```

在添加了下一个两个节点`75`和`125`之后，BST 看起来有点不同：

```cs
    The BST after adding two nodes (75, 125):
                    100
          ┌---------+---------┐
          50                  150
           +----┐        ┌----+
               75        125
```

然后，你执行下一个五个元素的插入操作。这些操作对树形状有非常明显的影响，如在控制台中呈现的那样：

```cs
    The BST after adding five nodes (25, 175, 90, 110, 135):
                                        100
                    ┌-------------------+-------------------┐
                    50                                      150
          ┌---------+---------┐                  ┌---------+---------┐
          25                  75                  125                 175
                               +----┐        ┌----+----┐
                                   90        110       135  
```

在添加了 10 个元素后，程序展示了删除特定节点对树形状的影响。首先，让我们删除值为`25`的叶节点：

```cs
    The BST after removing the node 25:
                                        100
                    ┌-------------------+-------------------┐
                    50                                      150
                    +---------┐                   ┌---------+---------┐
                              75                  125                 175
                              +----┐         ┌----+----┐
                                   90        110       135 
```

然后，程序检查删除只有一个子节点的节点，即右侧节点。有趣的是右子节点也有一个右子节点。然而，在这种情况下，呈现的算法也能正常工作，你会得到以下结果：

```cs
    The BST after removing the node 50:
                                        100
                    ┌-------------------+-------------------┐
                    75                                      150
                    +----┐                        ┌---------+---------┐
                         90                       125                 175
                                             ┌----+----┐
                                             110       135  
```

最后的删除操作是最复杂的，因为它需要你删除具有两个子节点的节点，并且还扮演着根的角色。在这种情况下，找到根的右子树中最左边的元素，并替换要删除的节点，如树的最终视图所示：

```cs
    The BST after removing the node 100:
                                        110
                     ┌-------------------+-------------------┐
                    75                                      150
                    +---------┐                   ┌---------+---------┐
                              90                  125                 175
                                                  +----┐
                                                       135
```

还有一组操作剩下——以三种不同的方式遍历树：前序、中序和后序。应用程序呈现以下结果：

```cs
    Pre-order traversal:    110, 75, 90, 150, 125, 135, 175
    In-order traversal:     75, 90, 110, 125, 135, 150, 175
    Post-order traversal:   90, 75, 135, 125, 175, 150, 110
```

创建的应用程序看起来相当令人印象深刻，不是吗？你不仅从头开始创建了二叉搜索树的实现，还为在控制台中可视化它做好了准备。干得好！

让我们再来看看中序遍历方法的结果。正如你所看到的，它会给出二叉搜索树中按升序排序的节点。

然而，你能看到创建的解决方案存在潜在问题吗？如果你只从树的给定区域删除节点，或者插入已排序的值，会怎么样？这可能意味着，具有适当宽度深度比的胖树可能变成瘦树。在最坏的情况下，它甚至可能被描述为一个列表，其中所有节点只有一个子节点。你有没有想法如何解决不平衡树的问题，并始终保持它们平衡？如果没有，让我们继续到下一节，介绍两种自平衡树的变体。

# AVL 树

在这一节中，你将了解一种自平衡树的变体，它在添加和删除节点时始终保持树的平衡。然而，为什么这么重要呢？如前所述，查找时间的性能取决于树的形状。在节点的组织不当形成列表的情况下，查找给定值的过程可能是*O(n)*操作。通过正确排列树，性能可以显著提高到*O(log n)*。

您知道 BST 很容易变成**失衡树**吗？让我们对树添加以下九个数字进行简单测试，从 1 到 9。然后，您将得到左侧图表中显示的形状的树。然而，相同的值可以以另一种方式排列，作为**平衡树**，具有明显更好的宽度深度比，如右侧图表所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dsal/img/1c2951c6-4cf9-43dd-88e7-a0b612a15078.png)

您知道什么是失衡和平衡树，以及自平衡树的目的，但 AVL 树是什么？它是如何工作的？在使用这种数据结构时应该考虑哪些规则？

AVL 树是具有附加要求的二叉搜索树，对于每个节点，其左右子树的高度不能相差超过一。当然，在向树中添加和删除节点后，必须保持这个规则。**旋转**起着重要作用，用于修复节点的不正确排列。

在谈论 AVL 树时，还必须指出这种数据结构的性能。在这种情况下，插入、删除和查找的平均和最坏情况都是*O(log n)*，因此与二叉搜索树相比，在最坏情况下有显着的改进。

您可以在[`en.wikipedia.org/wiki/AVL_tree`](https://en.wikipedia.org/wiki/AVL_tree)找到有关 AVL 树的更多信息。

在这个简短的介绍之后，让我们继续实现。

# 实现

AVL 树的实现，包括保持树平衡状态所需的各种旋转，似乎相当复杂。幸运的是，您不需要从头开始创建其实现，因为您可以使用其中一个可用的 NuGet 包，例如**Adjunct**，它将用于创建我们的示例。

有关 Adjunct 库的更多信息可以在以下网址找到：

+   [`adjunct.codeplex.com/`](http://adjunct.codeplex.com/)

+   [`www.nuget.org/packages/adjunct-System.DataStructures.AvlTree/`](https://www.nuget.org/packages/adjunct-System.DataStructures.AvlTree/)。

该软件包为开发人员提供了一些类，可用于创建基于 C#的应用程序。让我们专注于`AvlTree`泛型类，它代表 AVL 树。该类非常易于使用，因此您无需了解 AVL 树的所有内部细节，就可以轻松地从中受益。

例如，`AvlTree`类配备有`Add`方法，该方法在树中的适当位置插入新节点。您可以使用`Remove`方法轻松删除节点。此外，您可以通过调用`Height`方法获取给定节点的高度。还可以使用`GetBalanceFactor`获取给定节点的平衡因子，该平衡因子是左右子树高度之差计算得出的。

另一个重要的类是`AvlTreeNode`。它实现了`IBinaryTreeNode`接口，并包含四个属性，表示节点的高度（`Height`），左右节点的引用（`Left`和`Right`），以及节点中存储的值（`Value`），在创建类的实例时指定了类型。

# 示例-保持树平衡

AVL 树的介绍中提到，有一个非常简单的测试可以导致 BST 树失衡。您只需添加有序数字即可创建一个又长又瘦的树。因此，让我们尝试创建一个使用`Adjunct`库实现的 AVL 树的示例，添加完全相同的数据集。

`Program`类中`Main`方法中的代码如下：

```cs
AvlTree<int> tree = new AvlTree<int>(); 
for (int i = 1; i < 10; i++) 
{ 
    tree.Add(i); 
} 

Console.WriteLine("In-order: "  
    + string.Join(", ", tree.GetInorderEnumerator())); 
Console.WriteLine("Post-order: "  
    + string.Join(", ", tree.GetPostorderEnumerator())); 
Console.WriteLine("Breadth-first: "  
    + string.Join(", ", tree.GetBreadthFirstEnumerator())); 

AvlTreeNode<int> node = tree.FindNode(8); 
Console.WriteLine($"Children of node {node.Value} (height =  
    {node.Height}): {node.Left.Value} and {node.Right.Value}."); 
```

首先，创建`AvlTree`类的新实例，并指示节点将存储整数值。然后，使用`for`循环将以下数字（从 1 到 9）添加到树中，使用`Add`方法。循环执行后，树应包含 9 个节点，按照 AVL 树的规则排列。

此外，您可以使用常规方法遍历树：中序（`GetInorderEnumerator`），后序（`GetPostorderEnumerator`）和广度优先（`GetBreadthFirstEnumerator`）方法。您已经了解了前两种方法，但是**广度优先遍历**是什么？它的目的是首先访问同一深度上的所有节点，然后继续到下一深度，直到达到最大深度。

当您运行应用程序时，您将收到以下遍历的结果：

```cs
    In-order: 1, 2, 3, 4, 5, 6, 7, 8, 9
    Post-order: 1, 3, 2, 5, 7, 9, 8, 6, 4
    Breadth-first: 4, 2, 6, 1, 3, 5, 8, 7, 9
```

代码的最后部分显示了 AVL 树的查找功能，使用`FindNode`方法。它用于获取表示具有给定值的节点的`AvlTreeNode`实例。然后，您可以轻松地获取有关节点的各种数据，例如其高度，以及`AvlTreeNode`类的属性的左右子节点的值。有关查找功能的控制台输出部分如下：

```cs
    Children of node 8 (height = 2): 7 and 9.
```

简单、方便，而且不需要太多的开发工作——这很准确地描述了应用其中一个可用包来支持 AVL 树的过程。通过使用它，您无需自己准备复杂的代码，可能出现的问题数量也可以得到显著减少。

# 红黑树

**红黑树**，也称为**RBT**，是自平衡二叉搜索树的下一个变体。作为 BST 的变体，这种数据结构要求维护标准的 BST 规则。此外，必须考虑以下规则：

+   每个节点必须被着为红色或黑色。因此，您需要为存储颜色的节点添加额外的数据。

+   所有具有值的节点不能是叶节点。因此，NIL 伪节点应该用作树中的叶子节点，而所有其他节点都是内部节点。此外，所有 NIL 伪节点必须是黑色的。

+   如果一个节点是红色，那么它的两个子节点必须是黑色。

+   对于任何节点，到后代叶子节点（即 NIL 伪节点）的路径上黑色节点的数量必须相同。

适当的 RBT 如下图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dsal/img/897476a0-63da-4e1d-9ae4-d1330f1566d1.png)

树由九个节点组成，每个节点都着为红色或黑色。值得一提的是 NIL 伪节点，它们被添加为叶子节点。如果您再次查看前面列出的规则集，您可以确认在这种情况下所有这些规则都得到了遵守。

与 AVL 树类似，RBT 在添加或删除节点后也必须维护规则。在这种情况下，恢复 RBT 属性的过程更加复杂，因为它涉及**重新着色**和**旋转**。幸运的是，您无需了解和理解内部细节，这些细节相当复杂，才能从这种数据结构中受益并将其应用于您的项目中。

在谈论这种自平衡 BST 的变体时，还值得注意性能。在平均和最坏情况下，插入、删除和查找都是*O(log n)*操作，因此它们与 AVL 树的情况相同，并且在最坏情况下与 BST 相比要好得多。

您可以在[`en.wikipedia.org/wiki/Red-black_tree`](https://en.wikipedia.org/wiki/Red-black_tree)找到有关 RBT 的更多信息。

您已经学习了一些关于 RBT 的基本信息，所以让我们继续使用其中一个可用的库来实现。

# 实施

如果您想在应用程序中使用 RBT，您可以从头开始实现它，也可以使用其中一个可用的库，例如`TreeLib`，您可以使用 NuGet 软件包管理器轻松安装它。该库支持几种树，其中包括 RBT。

您可以在[`programmatom.github.io/TreeLib/`](http://programmatom.github.io/TreeLib/)和[`www.nuget.org/packages/TreeLib`](https://www.nuget.org/packages/TreeLib)找到有关该库的更多信息。

由于该库为开发人员提供了许多类，因此最好查看与 RBT 相关的类。第一个类名为`RedBlackTreeList`，表示 RBT。它是一个通用类，因此您可以轻松指定存储在每个节点中的数据类型。

该类包含一组方法，包括`Add`用于向树中插入新元素，`Remove`用于删除具有特定值的节点，`ContainsKey`用于检查树是否包含给定值，以及`Greatest`和`Least`用于返回树中存储的最大和最小值。此外，该类配备了几种遍历节点的变体，包括枚举器。

# 示例-RBT 相关功能

与 AVL 树一样，让我们使用外部库为 RBT 准备示例。简单的程序将展示如何创建新树，添加元素，删除特定节点，并从库的其他功能中受益。

让我们看一下以下代码片段，它应该添加到`Program`类中的`Main`方法中。第一部分如下：

```cs
RedBlackTreeList<int> tree = new RedBlackTreeList<int>(); 
for (int i = 1; i <= 10; i++) 
{ 
    tree.Add(i); 
} 
```

在这里，创建了`RedBlackTreeList`类的新实例。指定节点将存储整数值。然后，使用`for`循环将 10 个数字（从 1 到 10 排序）添加到树中，使用`Add`方法。执行后，具有 10 个元素的正确排列的 RBT 应该准备就绪。

在下一行中，使用`Remove`方法删除值等于 9 的节点：

```cs
tree.Remove(9); 
```

以下代码行检查树是否包含值等于`5`的节点。然后使用返回的布尔值在控制台中呈现消息：

```cs
bool contains = tree.ContainsKey(5); 
Console.WriteLine( 
    "Does value exist? " + (contains ? "yes" : "no")); 
```

代码的下一部分显示了如何使用`Count`属性以及`Greatest`和`Least`方法。这些功能允许计算树中元素的总数，以及存储在其中的最小和最大值。相关的代码行如下：

```cs
uint count = tree.Count; 
tree.Greatest(out int greatest); 
tree.Least(out int least); 
Console.WriteLine( 
    $"{count} elements in the range {least}-{greatest}"); 
```

在使用树数据结构时，您可能需要一种获取节点值的方法。您可以使用`GetEnumerable`方法来实现这个目标，如下所示：

```cs
Console.WriteLine( 
    "Values: " + string.Join(", ", tree.GetEnumerable())); 
```

在树中遍历节点的另一种方法涉及`foreach`循环，如以下代码片段所示：

```cs
Console.Write("Values: "); 
foreach (EntryList<int> node in tree) 
{ 
    Console.Write(node + " "); 
} 
```

正如您所看到的，使用`TreeLib`库非常简单，您可以在几分钟内将其添加到您的应用程序中。但是，在启动程序后控制台中显示的结果是什么？让我们看看：

```cs
    Does value exist? yes
    9 elements in the range 1-10
    Values: 1, 2, 3, 4, 5, 6, 7, 8, 10
    Values: 1 2 3 4 5 6 7 8 10

```

值得注意的是，`TreeLib`并不是唯一支持 RBT 的软件包，因此最好看看各种解决方案，并选择最适合您需求的软件包。

您已经到达关于自平衡二叉搜索树部分的章节的末尾。现在，让我们继续进行与堆相关的最后一部分。它们是什么，为什么它们位于树的章节中？您很快就会得到这些问题的答案以及许多其他问题的答案！

# 二叉堆

**堆**是树的另一种变体，存在两个版本：**最小堆**和**最大堆**。对于它们中的每一个，必须满足一个额外的属性：

+   对于最小堆：每个节点的值必须大于或等于其父节点的值

+   对于最大堆：每个节点的值必须小于或等于其父节点的值

这些规则起着非常重要的作用，因为它们规定了根节点始终包含最小值（在最小堆中）或最大值（在最大堆中）。因此，它是实现优先队列的便捷数据结构，详见第三章 *栈和队列*。

堆有许多变体，包括**二叉堆**，这是本节的主题。在这种情况下，堆必须符合先前提到的规则之一（取决于种类：最小堆或最大堆），并且必须遵守**完全二叉树**规则，该规则要求每个节点不能包含超过两个子节点，以及树的所有层都必须是完全填充的，除了最后一层，该层必须从左到右填充，并且右侧可能有一些空间。

让我们来看一下以下两个二叉堆：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dsal/img/57b79610-a0d6-41ec-beea-325932ddc8fa.png)

您可以轻松检查两个堆是否遵守所有规则。例如，让我们验证最小堆变体（左侧显示）中值等于**20**的节点的堆属性。该节点有两个子节点，值分别为**35**和**50**，均大于**20**。同样，您可以检查堆中的其余节点。二叉树规则也得到了遵守，因为每个节点最多包含两个子节点。最后一个要求是树的每一层都是完全填充的，除了最后一层不需要完全填充，但必须从左到右包含节点。在最小堆示例中，有三个层是完全填充的（分别有一个、两个和四个节点），而最后一层包含两个节点（**25**和**70**），位于最左边的两个位置。同样，您可以确认右侧显示的最大堆是否正确配置。

在这个关于堆的简短介绍，特别是关于二叉堆的介绍中，值得一提的是其广泛的应用范围。正如前面提到的，这种数据结构是实现优先队列的便捷方式，可以插入新值并移除最小值（在最小堆中）或最大值（在最大堆中）。此外，堆还用于堆排序算法，该算法将在接下来的示例中进行描述。该数据结构还有许多其他应用，例如在图算法中。

您可以在[`en.wikipedia.org/wiki/Binary_heap`](https://en.wikipedia.org/wiki/Binary_heap)找到有关二叉堆的更多信息。

您准备好看堆的实现了吗？如果是的话，让我们继续到下一节，介绍支持堆的可用库之一。

# 实现

二叉堆可以从头开始实现，也可以使用一些已有的实现。其中一个解决方案名为`Hippie`，可以通过 NuGet 软件包管理器安装到项目中。该库包含了堆的几个变体的实现，包括二叉堆、二项式堆和斐波那契堆，这些都在本书的本章中进行了介绍和描述。

您可以在[`github.com/pomma89/Hippie`](https://github.com/pomma89/Hippie)和[`www.nuget.org/packages/Hippie`](https://www.nuget.org/packages/Hippie)找到有关该库的更多信息。

该库包含了一些类，比如通用类`MultiHeap`，它适用于各种堆的变体，包括二叉堆。但是，如果同一个类用于二叉堆、二项式堆和斐波那契堆，那么您如何选择要使用哪种类型的堆呢？您可以使用`HeapFactory`类的静态方法来解决这个问题。例如，可以使用`NewBinaryHeap`方法创建二叉堆，如下所示：

```cs
MultiHeap<int> heap = HeapFactory.NewBinaryHeap<int>(); 
```

`MultiHeap`类配备了一些属性，例如用于获取堆中元素总数的`Count`和用于检索最小值的`Min`。此外，可用的方法允许添加新元素（`Add`），删除特定项（`Remove`），删除最小值（`RemoveMin`），删除所有元素（`Clear`），检查给定值是否存在于堆中（`Contains`）以及合并两个堆（`Merge`）。

# 示例-堆排序

作为使用`Hippie`库实现的二进制堆的示例，堆排序算法如下所示。应该将基于 C#的实现添加到`Program`类中的`Main`方法中，如下所示：

```cs
List<int> unsorted = new List<int>() { 50, 33, 78, -23, 90, 41 }; 
MultiHeap<int> heap = HeapFactory.NewBinaryHeap<int>(); 
unsorted.ForEach(i => heap.Add(i)); 
Console.WriteLine("Unsorted: " + string.Join(", ", unsorted)); 

List<int> sorted = new List<int>(heap.Count); 
while (heap.Count > 0) 
{ 
    sorted.Add(heap.RemoveMin()); 
} 
Console.WriteLine("Sorted: " + string.Join(", ", sorted)); 
```

正如您所看到的，实现非常简单和简短。首先，您创建一个包含未排序整数值的列表作为算法的输入。然后，准备一个新的二进制堆，并将每个输入值添加到堆中。在这个阶段，从输入列表中的元素写入控制台。

在代码的下一部分中，创建了一个新列表。它将包含排序后的值，因此它将包含算法的结果。然后，使用`while`循环在每次迭代中从堆中删除最小值。循环执行，直到堆中没有元素为止。最后，在控制台中显示排序后的列表。

堆排序算法的时间复杂度为*O(n * log(n))*。

当构建项目并运行应用程序时，您将看到以下结果：

```cs
    Unsorted: 50, 33, 78, -23, 90, 41
    Sorted: -23, 33, 41, 50, 78, 90

```

如前所述，二进制堆并不是堆的唯一变体。除其他外，二项堆是非常有趣的方法之一，这是下一节的主题。

# 二项堆

另一种堆是**二项堆**。这种数据结构由一组具有不同顺序的**二项树**组成。顺序为*0*的二项树只是一个单个节点。您可以使用两个顺序为*n-1*的二项树构造顺序为*n*的树。其中一个应该作为第一个树的父节点的最左子节点附加。听起来有点复杂，但以下图表应该消除任何困惑：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dsal/img/6d4e9b3e-b52d-44ad-a437-08ea02ad2aa7.png)

如前所述，顺序为**0**的二项树只是一个单个节点，如左侧所示。顺序为**1**的树由两个顺序为**0**的树（用虚线边框标记）连接在一起。在顺序为**2**的树的情况下，使用两个顺序为**1**的树。第二个作为第一个树的父节点的最左子节点附加。以同样的方式，您可以配置具有以下顺序的二项树。

然而，您如何知道二项堆中应该放置多少个二项树，以及它们应该包含多少个节点？答案可能有点令人惊讶，因为您需要准备节点数的二进制表示。例如，让我们创建一个包含**13**个元素的二项堆。数字**13**的二进制表示如下：**1101**，即*1*2⁰ + 0*2¹ + 1*2² + 1*2³*。

需要获取集合位的基于零的位置，即在这个例子中的**0**，**2**和**3**。这些位置表示应该配置的二项树的顺序：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dsal/img/9c7fc557-a3a4-4140-a694-2fff25163a83.png)

此外，在二项堆中不能有两个具有相同顺序（例如两个顺序为**2**的树）。还值得注意的是，每个二项树必须保持最小堆属性。

您可以在[`en.wikipedia.org/wiki/Binomial_heap`](https://en.wikipedia.org/wiki/Binomial_heap)找到有关二项堆的更多信息。

二项堆的实现比二进制堆复杂得多。因此，最好使用现有的实现之一，而不是从头开始编写自己的实现。正如在二进制堆的情况下所述，`Hippie`库是一个支持各种堆变体的解决方案，包括二项堆。

可能会让人惊讶，但与二进制堆的示例相比，代码中唯一的区别是在创建`MultiHeap`类的新实例的那一行进行了修改。为了支持二项堆，你需要使用`HeapFactory`类中的`NewBinomialHeap`方法，如下所示：

```cs
MultiHeap<int> heap = HeapFactory.NewBinomialHeap<int>(); 
```

不需要进行更多的更改！现在你可以执行剩下的操作，比如插入或删除元素，方式与二进制堆的情况完全相同。

你已经了解了两种堆，即二进制堆和二项堆。在接下来的部分中，将简要介绍斐波那契堆。

# 斐波那契堆

**斐波那契堆**是堆的一个有趣的变体，某些方面类似于二项堆。首先，它也由许多树组成，但对于每棵树的形状没有约束，因此比二项堆灵活得多。此外，堆中允许有多棵具有完全相同形状的树。

斐波那契堆的一个示例如下：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs-dsal/img/6ebf3b19-9827-4b21-b359-3ed027961a35.png)

其中一个重要的假设是每棵树都是最小堆。因此，整个斐波那契堆中的最小值肯定是其中一棵树的根节点。此外，所呈现的数据结构支持以“懒惰”的方式执行各种操作。这意味着除非真正必要，否则不执行额外的复杂操作。例如，它可以将一个新节点添加为只有一个节点的新树。

你可以在[`en.wikipedia.org/wiki/Fibonacci_heap`](https://en.wikipedia.org/wiki/Fibonacci_heap)找到更多关于斐波那契堆的信息。

与二项堆类似，斐波那契堆的实现也不是一项简单的任务，需要对这种数据结构的内部细节有很好的理解。因此，如果你需要在你的应用程序中使用斐波那契堆，最好使用现有的实现之一，而不是从头开始编写自己的实现。正如之前所述，`Hippie`库是一个支持许多堆变体的解决方案，包括斐波那契堆。

值得一提的是，与二进制和二项堆相比，代码中唯一的区别是在创建`MultiHeap`类的新实例的那一行进行了修改。为了支持斐波那契堆，你需要使用`HeapFactory`类中的`NewFibonacciHeap`方法，如下所示：

```cs
MultiHeap<int> heap = HeapFactory.NewFibonacciHeap<int>(); 
```

就是这样！你刚刚读了一个关于斐波那契堆的简要介绍，作为堆的另一种变体，因此也是树的另一种类型。这是本章的最后一个主题，所以是时候进行总结了。

# 总结

当前章节是本书迄今为止最长的章节。然而，它包含了许多关于树变体的信息。这些数据结构在许多算法中扮演着非常重要的角色，了解更多关于它们的知识以及如何在你的应用程序中使用它们是很有益的。因此，本章不仅包含简短的理论介绍，还包括图表、解释和代码示例。

一开始描述了树的概念。作为提醒，树由节点组成，包括一个根。根节点不包含父节点，而所有其他节点都包含。每个节点可以有任意数量的子节点。同一节点的子节点可以被称为兄弟节点，而没有子节点的节点被称为叶子节点。

树的各种变体都遵循这种结构。章节中描述的第一种是二叉树。在这种情况下，一个节点最多可以包含两个子节点。然而，BST 的规则更加严格。对于这种树中的任何节点，其左子树中所有节点的值必须小于节点的值，而右子树中所有节点的值必须大于节点的值。BST 具有非常广泛的应用，并且可以显著提高查找性能。不幸的是，很容易在向树中添加排序值时使树失衡。因此，性能的积极影响可能会受到限制。

为了解决这个问题，可以使用某种自平衡树，它在添加或删除节点时始终保持平衡。在本章中，介绍了两种自平衡树的变体：AVL 树和 RBT。第一种类型有额外的要求，即对于每个节点，其左右子树的高度不能相差超过一。RBT 稍微复杂一些，因为它引入了将节点着色为红色或黑色的概念，以及 NIL 伪节点。此外，要求如果一个节点是红色，那么它的两个子节点必须是黑色，并且对于任何节点，到后代叶子的路径上的黑色节点数量必须相同。正如您在分析这些数据结构时所看到的，它们的实现要困难得多。因此，本章还介绍了可通过 NuGet 软件包管理器下载的额外库。

本章剩下的部分与堆有关。作为提醒，堆是树的另一种变体，有两个版本，最小堆和最大堆。值得注意的是，每个节点的值必须大于或等于（对于最小堆）或小于或等于（对于最大堆）其父节点的值。堆存在许多变体，包括二叉堆、二项式堆和斐波那契堆。本章简要介绍了所有这些类型，以及关于使用来自 NuGet 软件包之一的实现的信息。

让我们继续讨论下一章的主题——图！
