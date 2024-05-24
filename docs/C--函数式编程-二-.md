# C# 函数式编程（二）

> 原文：[`zh.annas-archive.org/md5/BA6B40D466733162BD57D5FED41DF818`](https://zh.annas-archive.org/md5/BA6B40D466733162BD57D5FED41DF818)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第三章：使用 Lambda 表达式表达匿名方法

在上一章中，我们已经讨论了委托，因为它是理解匿名方法和 lambda 表达式的先决条件，而这也是本章的主题。通过使用匿名方法，我们可以创建一个不需要单独方法的委托实例。通过使用 lambda 表达式，我们可以为匿名方法创建一种简写语法。在本章中，我们将深入研究匿名方法以及 Lambda 表达式。本章的主题如下：

+   应用委托来创建和使用匿名方法

+   将匿名方法转换为 lambda 表达式

+   了解表达式树及其与 lambda 的关系

+   使用 lambda 表达式订阅事件

+   在使用函数式编程中阐述 lambda 表达式的好处

# 了解匿名方法

在上一章中，我们已经讨论了如何使用命名方法声明委托。当使用命名方法时，我们必须首先创建一个方法，给它一个名称，然后将其与委托关联起来。为了提醒我们，与命名方法关联的简单委托声明如下所示：

```cs
delegate void DelDelegate(int x); 
void DoSomething(int i) { /* Implementation */ } 
DelDelegate d = DoSomething; 

```

从上述代码中，我们简单地创建了一个名为`DelDelegate`的委托数据类型，并且创建了一个名为`DoSomething`的方法。当我们有了一个命名方法后，我们可以将委托与该方法关联起来。幸运的是，C# 2.0 中宣布了匿名方法，以简化委托的使用。它们为我们提供了一种快捷方式来创建一个简单且短小的方法，该方法将被使用一次。声明匿名方法的语法如下：

```cs
delegate([parameters]) { implementation } 

```

匿名方法语法的每个元素的解释如下：

+   **委托**：我们需要的关键字，以便初始化委托。

+   **参数**：我们分配给该委托的方法所需的参数列表。

+   **实现**：方法将执行的代码。如果方法需要返回一个值，可以应用返回语句。

从上述语法中，我们可以看到匿名方法是一种没有名称的方法。我们只需要定义方法的参数和实现。

## 创建匿名方法

为了进一步讨论，让我们创建一个简单的匿名方法，可以在`SimpleAnonymousMethods.csproj`项目中找到，如下所示：

```cs
public partial class Program 
{ 
  static Func<string, string> displayMessageDelegate = 
    delegate (string str) 
  { 
    return String.Format("Message: {0}", str); 
  }; 
} 

```

我们现在有一个匿名方法，我们将其分配给`displayMessageDelegate`委托。我们使用`Func`内置委托创建`displayMessageDelegate`委托，该委托只接受一个字符串参数，并且也返回一个字符串值。如果我们需要运行匿名方法，可以按照以下方式调用委托：

```cs
public partial class Program 
{ 
  static void Main(string[] args) 
  { 
    Console.WriteLine( 
      displayMessageDelegate( 
          "A simple anonymous method sample.")); 
  } 
} 

```

运行上述代码后，我们将在控制台上获得以下输出：

![创建匿名方法](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/fn-cs/img/Image00021.jpg)

正如我们在输出控制台窗口中所看到的，我们成功地通过调用委托名称调用了匿名方法。现在，让我们回到上一章，从中使用一些代码并将其重构为匿名方法。我们将重构`SimpleDelegates.csproj`的代码，这是我们在上一章中讨论过的。以下是匿名方法的声明，可以在`SimpleDelegatesRefactor.csproj`项目中找到：

```cs
public partial class Program 
{ 
  private static Func<int, int, int> AreaRectangleDelegate = 
    delegate (int a, int b) 
  { 
    return a * b; 
  }; 

  private static Func<int, int, int> AreaSquareDelegate = 
    delegate (int x, int y) 
  { 
    return x * y; 
  }; 
} 

```

在我们之前的代码中有两个匿名方法。我们还使用了`Func`委托，这是我们在上一章中讨论过的内置委托。要调用这些方法，我们可以按照以下方式调用委托名称：

```cs
public partial class Program 
{ 
  static void Main(string[] args) 
  { 
    int i = AreaRectangleDelegate(1, 2); 
    int j = AreaSquareDelegate(2, 3); 
    Console.WriteLine("i = " + i); 
    Console.WriteLine("j = " + j); 
  } 
} 

```

如果我们运行该项目，将会得到以下输出：

![创建匿名方法](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/fn-cs/img/Image00022.jpg)

与`SimpleDelegates.csproj`项目中的代码相比，我们在上述`SimpleDelegatesRefactor.csproj`项目中的代码变得更简单更短，因为我们不需要声明委托。委托与匿名方法的创建同时进行，例如以下代码片段：

```cs
private static Func<int, int, int> AreaRectangleDelegate = 
  delegate (int a, int b) 
{ 
  return a * b; 
}; 

```

以下是我们在上一章中使用的代码，名为`SimpleDelegates.csproj`：

```cs
public partial class Program 
{ 
  private delegate int AreaCalculatorDelegate(int x, int y); 
  static int Square(int x, int y) 
  { 
    return x * y; 
  } 
} 

```

使用匿名委托，我们简化了我们的代码，与上一章中生成的代码相比。

## 将匿名方法用作参数

我们现在已经执行了一个匿名方法。但是，匿名方法也可以作为参数传递给方法。让我们看一下以下代码，可以在`AnonymousMethodAsArgument.csproj`项目中找到：

```cs
public partial class Program 
{ 
  private static bool IsMultipleOfSeven(int i) 
  { 
    return i % 7 == 0; 
  } 
} 

```

首先，在这个项目中有一个名为`FindMultipleOfSeven`的方法。该方法将被传递给以下方法的参数：

```cs
public partial class Program 
{ 
  private static int FindMultipleOfSeven(List<int> numList) 
  { 
    return numList.Find(IsMultipleOfSeven); 
  } 
} 

```

然后，我们从以下方法调用`FindMultipleOfSeven()`方法：

```cs
public partial class Program 
{ 
  private static void PrintResult() 
  { 
    Console.WriteLine( 
      "The Multiple of 7 from the number list is {0}", 
      FindMultipleOfSeven(numbers)); 
  } 
} 

```

我们还可以定义以下`List`变量，以便传递给`FindMultipleOfSeven()`方法的参数：

```cs
public partial class Program 
{ 
  static List<int> numbers = new List<int>() 
  { 
    54, 24, 91, 70, 72, 44, 61, 93, 
    73, 3, 56, 5, 38, 60, 29, 32, 
    86, 44, 34, 25, 22, 44, 66, 7, 
    9, 59, 70, 47, 55, 95, 6, 42 
  }; 
} 

```

如果我们调用`PrintResult()`方法，我们将得到以下输出：

![将匿名方法用作参数](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/fn-cs/img/Image00023.jpg)

上述程序的目标是从数字列表中找到一个乘以七的数字。由于`91`是满足此条件的第一个数字，因此`FindMultipleOfSeven()`方法返回该数字。

在`FindMultipleOfSeven()`方法内部，我们可以找到将`IsMultipleOfSeven()`方法作为参数传递给`Find()`方法，如下面的代码片段所示：

```cs
return numList.Find(IsMultipleOfSeven); 

```

如果我们愿意，我们可以用匿名方法替换这个方法，如下所示：

```cs
public partial class Program 
{ 
  private static int FindMultipleOfSevenLambda( 
    List<int> numList) 
  { 
    return numList.Find( 
      delegate(int i) 
      { 
        return i % 7 == 0; 
      } 
    ); 
  } 
} 

```

现在我们有了`FindMultipleOfSevenLambda()`方法，它调用`Find()`方法并将匿名方法传递给方法参数。由于我们传递了匿名方法，我们不再需要`FindMultipleOfSeven()`方法。我们可以使用`PrintResultLambda()`方法调用`FindMultipleOfSevenLambda()`方法，如下所示：

```cs
public partial class Program 
{ 
  private static void PrintResultLambda() 
  { 
    Console.WriteLine( 
      "({0}) The Multiple of 7 from the number list is {1}", 
      "Lambda", 
      FindMultipleOfSevenLambda(numbers)); 
  } 
} 

```

在执行了`PrintResultLambda()`方法后，我们将得到以下输出：

![将匿名方法用作参数](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/fn-cs/img/Image00024.jpg)

从输出窗口中可以看到，我们仍然得到`91`作为`7`的乘积的结果。但是，我们已成功将匿名方法作为方法参数传递。

## 编写匿名方法-一些指导方针

在编写匿名方法时，以下是一些我们应该牢记的事情：

+   匿名方法在其声明中没有返回类型。考虑以下代码片段：

```cs
        delegate (int a, int b) 
        { 
          return a * b; 
        }; 

```

### 注意

在前面的委托声明中，我们找不到返回类型，尽管在方法实现中找到了`return`关键字。这是因为编译器根据委托签名推断返回类型。

+   我们必须将委托签名的声明与方法的参数匹配。这将类似于将命名方法分配给委托。让我们看一下以下代码片段：

```cs
        private static Func<int, int, int> AreaRectangleDelegate = 
          delegate (int a, int b) 
        { 
          return a * b; 
        }; 

```

### 注意

在上面的代码片段中，我们声明了一个接受两个 int 参数并返回 int 值的委托。参考委托签名；我们在声明匿名方法时使用相同的签名。

+   我们不允许声明变量的名称与已声明的匿名方法的变量冲突。看一下以下代码片段：

```cs
        public partial class Program 
        { 
          private static void Conflict() 
          { 
            for (int i = 0; i < numbers.Count; i++) 
            { 
              Action<int> actDelegate = delegate(int i) 
              { 
                Console.WriteLine("{0}", i); 
              }; 
              actDelegate(i); 
            } 
          } 
        } 

```

### 注意

我们永远无法编译上述代码，因为我们在`Conflict()`方法和`actDelegate`委托中都声明了变量`i`。

## 匿名方法的优势

以下是使用匿名方法的一些优点：

+   由于我们不给方法附加名称，如果我们只想调用该方法一次，它们是一个很好的解决方案。

+   我们可以在原地编写代码，而不是在代码的其他部分编写逻辑。

+   我们不需要声明匿名方法的返回类型，因为它将根据分配给匿名方法的委托的签名推断出来。

+   我们可以从匿名方法中访问外部方法的局部变量。外部变量被捕获在匿名方法内部。

+   对于只调用一次的逻辑片段，我们不需要创建一个命名方法。

# Lambda 表达式

现在我们知道，匿名方法可以帮助我们创建简单而简短的方法。然而，在 C# 3.0 中，lambda 表达式被宣布为补充匿名方法的方式，提供了一种简写的方法来创建匿名方法。事实上，当编写新代码时，lambda 表达式成为首选方式。

现在，让我们来看一下最简单的 lambda 表达式语法，如下所示：

```cs
([parameters]) => expression; 

```

在 lambda 表达式语法中，我们只找到两个元素，即`parameters`和`expression`。像任何方法一样，lambda 表达式具有由参数表示的参数。lambda 表达式的实现由表达式表示。如果只需要一个参数，我们还可以省略参数的括号。

让我们创建一个简单的 lambda 表达式，我们可以在`SimpleLambdaExpression.csproj`项目中找到，如下所示：

```cs
public partial class Program 
{ 
  static Func<string, string> displayMessageDelegate = 
    str => String.Format(Message: {0}", str); 
} 

```

在前面的代码中，我们声明了`displayMessageDelegate`委托，并使用 lambda 表达式将其分配给`Func`委托。与`SimpleDelegates.csproj`项目中的方法类似，为了调用委托，我们使用以下代码：

```cs
public partial class Program 
{ 
  static void Main(string[] args) 
  { 
    Console.WriteLine( 
      displayMessageDelegate( 
      "A simple lambda expression sample.")); 
  } 
} 

```

我们像调用方法名一样调用`displayMessageDelegate`委托。输出将被发送到控制台，如下所示：

![Lambda 表达式](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/fn-cs/img/Image00025.jpg)

现在，让我们比较`SimpleAnonymousMethods.csproj`中的匿名方法和`SimpleLambdaExpression.csproj`项目中的 lambda 表达式的方法声明：

```cs
static Func<string, string> displayMessageDelegate = 
  delegate (string str) 
{ 
  return String.Format("Message: {0}", str); 
}; 

```

前面的代码片段是一个匿名方法声明，比命名方法声明更短、更简单。

```cs
static Func<string, string> displayMessageDelegate = 
  str => String.Format("Message: {0}", str); 

```

前面的代码片段是一个 lambda 表达式声明，比匿名方法更短、更简单。与匿名方法相比，lambda 表达式更为简洁。

## 将匿名方法转换为 lambda 表达式

现在，让我们讨论将匿名方法转换为 lambda 表达式。我们有以下匿名方法：

```cs
delegate (string str) 
{ 
  return String.Format("Message: {0}", str); 
}; 

```

我们想将其转换为 lambda 表达式，如下所示：

```cs
str => String.Format("Message: {0}", str); 

```

首先，我们去掉了`delegate`关键字，因为我们不再需要它；所以，代码将如下所示：

```cs
(string str) 
{ 
  return String.Format("Message: {0}", str); 
}; 

```

然后，我们用`=>`lambda 运算符取代大括号，使其成为内联 lambda 表达式：

```cs
(string str) => return String.Format("Message: {0}", str); 

```

我们也可以去掉`return`关键字，因为它只是返回一个值的单行代码。代码将如下所示：

```cs
(string str) => String.Format("Message: {0}", str); 

```

由于前面的语法现在是一个表达式而不是一个完整的语句，所以可以从前面的代码中删除分号，代码将如下所示：

```cs
(string str) => String.Format("Message: {0}", str); 

```

前面的表达式是一个有效的 lambda 表达式。然而，为了充分利用 lambda 表达式，我们可以进一步简化代码。代码将如下所示：

```cs
(str) => String.Format("Message: {0}", str); 

```

由于我们已经去掉了`string`数据类型，我们现在也可以去掉括号：

```cs
str => String.Format("Message: {0}", str); 

```

前面的语法是我们最终的 lambda 表达式。正如我们所看到的，现在我们的代码变得更易读了，因为它更简单了。

### 注意

如果参数列表中只包含一个参数，则可以省略 lambda 表达式的括号。

使用 lambda 表达式，我们实际上可以在匿名方法中创建委托和表达式树类型。现在，让我们找出这两种类型之间的区别。

## 使用 lambda 表达式创建委托类型

我们在`SimpleLambdaExpression.csproj`项目中创建代码时讨论了委托类型中的 lambda 表达式。现在，让我们创建另一个项目名称，以便通过以下代码进行讨论：

```cs
public partial class Program 
{ 
  private static Func<int, int, int> AreaRectangleDelegate = 
    (a, b) => a * b; 
  private static Func<int, int, int> AreaSquareDelegate = 
    (x, y) => x * y; 
} 

```

再次，我们重构`SimpleDelegatesRefactor.csproj`项目，并用 lambda 表达式替换匿名方法。正如我们所看到的，lambda 表达式被分配给了一个类型为委托的变量。在这里，我们在委托类型中创建了一个 lambda 表达式。我们可以使用在`SimpleDelegatesRefactor.csproj`项目中使用的`Main()`方法来调用`AreaRectangleDelegate`和`AreaSquareDelegate`。这两个项目的结果将完全相同。

## 表达式树和 lambda 表达式

除了创建委托，我们还可以创建表达式树，这是一种代表表达式元素（表达式、项、因子）的数据结构。通过遍历树，我们可以解释表达式树，或者我们可以改变树中的节点来转换代码。在编译器术语中，表达式树被称为**抽象语法树**（**AST**）。

现在，让我们看一下以下代码片段，以便将 lambda 表达式分配给我们之前讨论过的委托：

```cs
Func<int, int, int> AreaRectangleDelegate = 
  (a, b) => a * b; 

```

正如我们所看到的，前面的陈述中有三个部分。它们如下：

+   **一个变量类型的委托声明**：`Func<int, int, int> AreaRectangleDelegate`

+   **一个等号操作符**：`=`

+   **一个 lambda 表达式**：`(a, b) => a * b`

我们将把前面的代码陈述翻译成数据。为了实现这个目标，我们需要创建`Expression<T>`类型的实例，其中`T`是委托类型。`Expression<T>`类型在`System.Linq.Expressions`命名空间中定义。在项目中使用这个命名空间后，我们可以将我们前面的代码转换成表达式树，如下所示：

```cs
public partial class Program 
{ 
  static void Main(string[] args) 
  { 
    Expression<Func<int, int, int>> expression = 
      (a, b) => a * b; 
  } 
} 

```

我们已经将前面的委托 lambda 表达式转换成了声明为`Expression<T>`类型的表达式树。前面代码中的变量表达式不是可执行代码，而是一个叫做表达式树的数据结构。`Expression<T>`类中有四个基本属性，我们将详细讨论它们。它们如下：

+   **主体**：这包含了表达式的主体

+   **参数**：这包含了 lambda 表达式的参数

+   **NodeType**：这包含了树中节点的`ExpressionType`类型

+   **类型**：这包含了表达式的静态类型

现在，让我们在表达式变量中添加一个断点，并通过在`LambdaExpressionInExpressionTree.csproj`项目中按下**F5**来运行调试过程。在执行表达式声明行之后，我们可以在 Visual Studio IDE 的变量窗口中窥视，并得到以下截图：

![表达式树和 lambda 表达式](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/fn-cs/img/Image00026.jpg)

从前面的截图中，我们有一个包含`{(a * b)}`的`Body`属性，`NodeType`包含 Lambda，`Type`包含具有三个模板的`Func`委托，并且有两个参数。如果我们在变量窗口中展开`Body`信息，我们将得到类似以下截图所示的结果：

![表达式树和 lambda 表达式](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/fn-cs/img/Image00027.jpg)

从前面的截图中，我们可以看到`Left`属性包含`{a}`，`Right`属性包含`{b}`。使用这些属性，我们也可以以编程方式探索表达式树的主体。以下代码是`exploreBody()`方法，它将探索`Body`的属性：

```cs
public partial class Program 
{ 
  private static void exploreBody( 
    Expression<Func<int, int, int>> expr) 
  { 
    BinaryExpression body = 
      (BinaryExpression)expr.Body; 
    ParameterExpression left = 
      (ParameterExpression)body.Left; 
    ParameterExpression right = 
      (ParameterExpression)body.Right; 
    Console.WriteLine(expr.Body); 
    Console.WriteLine( 
      "\tThe left part of the expression: {0}\n" + 
      "\tThe NodeType: {1}\n" + 
      "\tThe right part: {2}\n" + 
      "\tThe Type: {3}\n", 
      left.Name, 
      body.NodeType, 
      right.Name, 
      body.Type); 
  } 
} 

```

如果我们运行前面的`exploreBody()`方法，我们将得到以下输出：

![表达式树和 lambda 表达式](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/fn-cs/img/Image00028.jpg)

在前面的代码中，我们以编程方式访问了`Expression<T>`的`Body`属性。为了获取`Body`内容，我们需要创建一个`BinaryExpression`数据类型，并且为了获取`Left`和`Right`属性的内容，我们需要创建一个`ParameterExpression`。`BinaryExpression`和`ParameterExpression`数据的代码片段如下：

```cs
BinaryExpression body = 
  (BinaryExpression)expr.Body; 
ParameterExpression left = 
  (ParameterExpression)body.Left; 
ParameterExpression right = 
  (ParameterExpression)body.Right; 

```

我们已经成功地从表达式树中的代码创建了一个数据结构。如果我们愿意，我们可以通过编译表达式将这些数据转换回代码。我们现在有的表达式如下：

```cs
Expression<Func<int, int, int>> expression = 
  (a, b) => a * b; 

```

因此，我们可以编译表达式，并使用以下`compilingExpr()`方法运行表达式中的代码：

```cs
public partial class Program 
{ 
  private static void compilingExpr( 
    Expression<Func<int, int, int>> expr) 
  { 
    int a = 2; 
    int b = 3; 
    int compResult = expr.Compile()(a, b); 
    Console.WriteLine( 
      "The result of expression {0}"+ 
      " with a = {1} and b = {2} is {3}", 
      expr.Body, 
      a, 
      b, 
      compResult); 
  } 
} 

```

如果我们运行`compilingExpr()`方法，将在控制台窗口上显示以下输出：

![表达式树和 lambda 表达式](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/fn-cs/img/Image00029.jpg)

正如我们所看到的，我们使用表达式类中的`Compile()`方法编译了表达式：

```cs
int compResult = expr.Compile()(a, b); 

```

`expr.Compile()`方法根据表达式的类型生成`Func<int, int, int>`类型的委托。我们根据其签名给`Compile()`方法传递参数`a`和`b`，然后它返回`int`值。

# 使用 lambda 表达式订阅事件

在 C#中，对象或类可以用来在发生某事时通知其他对象或类，这就是事件。事件中有两种类，它们是发布者和订阅者。发布者是发送（或引发）事件的类或对象，而订阅者是接收（或处理）事件的类或对象。幸运的是，lambda 表达式也可以用来处理事件。让我们看一下以下代码来进一步讨论事件：

```cs
public class EventClassWithoutEvent 
{ 
  public Action OnChange { get; set; } 
  public void Raise() 
  { 
    if (OnChange != null) 
    { 
      OnChange(); 
    } 
  } 
} 

```

前面的代码可以在`EventsInLambda.csproj`项目中找到。正如我们所看到的，项目中创建了一个名为`EventClassWithoutEvent`的类。该类有一个名为`OnChange`的属性。该属性的作用是存储订阅类并在调用`Raise()`方法时运行。现在，让我们使用以下代码调用`Raise()`方法：

```cs
public partial class Program 
{ 
  private static void CreateAndRaiseEvent() 
  { 
    EventClassWithoutEvent ev = new EventClassWithoutEvent(); 
    ev.OnChange += () => 
      Console.WriteLine("1st: Event raised"); 
    ev.OnChange += () => 
      Console.WriteLine("2nd: Event raised"); 
    ev.OnChange += () => 
      Console.WriteLine("3rd: Event raised"); 
    ev.OnChange += () => 
      Console.WriteLine("4th: Event raised"); 
    ev.OnChange += () => 
      Console.WriteLine("5th: Event raised"); 
    ev.Raise(); 
  } 
} 

```

如果我们运行前面的`CreateAndRaiseEvent()`方法，将在控制台上获得以下输出：

![使用 lambda 表达式订阅事件](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/fn-cs/img/Image00030.jpg)

从代码中，我们可以看到当调用`CreateAndRaiseEvent()`方法时，代码实例化了一个`EventClassWithoutEvent`类。然后它在 lambda 表达式中订阅了五种不同的方法，然后通过调用`Raise()`方法引发了事件。以下代码片段将进一步解释这一点：

```cs
EventClassWithoutEvent ev = new EventClassWithoutEvent(); 
ev.OnChange += () => 
  Console.WriteLine("1st: Event raised"); 
ev.Raise(); 

```

从前面的代码片段中，我们可以看到 lambda 表达式可以用来订阅事件，因为它使用委托来存储订阅的方法。然而，前面的代码仍然存在一个弱点。看一下这段代码中的最后一个`OnChange`赋值：

```cs
ev.OnChange += () => 
  Console.WriteLine("5th: Event raised"); 

```

现在，假设我们将其更改为这样：

```cs
ev.OnChange = () => 
  Console.WriteLine("5th: Event raised"); 

```

然后，我们将删除所有四个先前的订阅者。另一个弱点是`EventClassWithoutEvent`引发了事件，但没有任何东西可以阻止类的用户引发此事件。通过调用`OnChange()`，类的所有用户都可以向所有订阅者引发事件。

## 使用事件关键字

使用`event`关键字可以解决我们之前的问题，因为它将强制类的用户只能使用`+=`或`-=`运算符订阅某些内容。让我们看一下以下代码来进一步解释这一点：

```cs
public class EventClassWithEvent 
{ 
  public event Action OnChange = () => { }; 
  public void Raise() 
  { 
    OnChange(); 
  } 
} 

```

从前面的代码中，我们可以看到我们不再使用公共属性，而是使用`EventClassWithEvent`类中的公共字段。使用`event`关键字，编译器将保护我们的字段免受未经授权的访问。事件关键字还将保护订阅列表，因为它不能使用`=`运算符分配给任何 lambda 表达式，而必须与`+=`或`-=`运算符一起使用。现在，让我们看一下以下代码来证明这一点：

```cs
public partial class Program 
{ 
  private static void CreateAndRaiseEvent2() 
  { 
    EventClassWithEvent ev = new EventClassWithEvent(); 
    ev.OnChange += () => 
      Console.WriteLine("1st: Event raised"); 
    ev.OnChange += () => 
      Console.WriteLine("2nd: Event raised"); 
    ev.OnChange += () => 
      Console.WriteLine("3rd: Event raised"); 
    ev.OnChange += () => 
      Console.WriteLine("4th: Event raised"); 
    ev.OnChange = () => 
      Console.WriteLine("5th: Event raised"); 
    ev.Raise(); 
  } 
} 

```

现在我们有一个名为`CreateAndRaiseEvent2()`的方法，它与`CreateAndRaiseEvent()`方法完全相同，只是最后的`OnChange`赋值使用了`=`运算符而不是`+=`运算符。然而，由于我们已经将事件关键字应用于`OnChange`字段，代码无法编译，将出现`CS0070`错误代码，如下面的屏幕截图所示：

![使用事件关键字](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/fn-cs/img/Image00031.jpg)

由于事件关键字限制了`=`运算符的使用，不再存在风险。`event`关键字还阻止了类的外部用户引发事件。只有定义事件的类的部分才能引发事件。让我们来看一下`EventClassWithoutEvent`和`EventClassWithEvent`类之间的区别：

```cs
public partial class Program 
{ 
  private static void CreateAndRaiseEvent3() 
  { 
    EventClassWithoutEvent ev = new EventClassWithoutEvent(); 
    ev.OnChange += () => 
      Console.WriteLine("1st: Event raised"); 
    ev.OnChange += () => 
      Console.WriteLine("2nd: Event raised"); 
    ev.OnChange += () => 
      Console.WriteLine("3rd: Event raised"); 
    ev.OnChange(); 
    ev.OnChange += () => 
      Console.WriteLine("4th: Event raised"); 
    ev.OnChange += () => 
      Console.WriteLine("5th: Event raised"); 
    ev.Raise(); 
  } 
} 

```

前面的`CreateAndRaiseEvent3()`方法的引用是`CreateAndRaiseEvent()`，但我们在第三个事件和第四个事件之间插入了`ev.OnChange()`。如果我们运行该方法，它将成功运行，并且我们将在控制台上看到以下输出：

![使用事件关键字](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/fn-cs/img/Image00032.jpg)

从输出中可以看出，`EventClassWithoutEvent`类中的`OnChange()`可以引发事件。与`EventClassWithEvent`类相比，如果我们在任何订阅事件之间插入`OnChange()`，编译器将创建编译错误，如下面的代码所示：

```cs
public partial class Program 
{ 
  private static void CreateAndRaiseEvent4() 
  { 
    EventClassWithEvent ev = new EventClassWithEvent(); 
    ev.OnChange += () => 
      Console.WriteLine("1st: Event raised"); 
    ev.OnChange += () => 
      Console.WriteLine("2nd: Event raised"); 
    ev.OnChange += () => 
      Console.WriteLine("3rd: Event raised"); 
    ev.OnChange(); 
    ev.OnChange += () => 
      Console.WriteLine("4th: Event raised"); 
    ev.OnChange += () => 
      Console.WriteLine("5th: Event raised"); 
    ev.Raise(); 
  } 
} 

```

如果我们编译前面的代码，将再次得到`CS0070`错误代码，因为我们在第三个事件和第四个事件之间插入了`ev.OnChange()`。

## 使用 EventHandler 或 EventHandler<T>

实际上，C#有一个名为`EventHandler`或`EventHandler<T>`的类，我们可以使用它来初始化事件，而不是使用`Action`类。`EventHandler`类接受一个发送者对象和事件参数。发送者是引发事件的对象。使用`EventHandler<T>`，我们可以定义事件参数的类型。让我们看一下在`EventWithEventHandler.csproj`项目中找到的以下代码：

```cs
public class MyArgs : EventArgs 
{ 
  public int Value { get; set; } 
  public MyArgs(int value) 
  { 
    Value = value; 
  } 
} 
public class EventClassWithEventHandler 
{ 
  public event EventHandler<MyArgs> OnChange = 
    (sender, e) => { }; 
  public void Raise() 
  { 
    OnChange(this, new MyArgs(100)); 
  } 
} 

```

我们有两个类，名为`MyArgs`和`EventClassWithEventHandler`。`EventClassWithEventHandler`类使用`EventHandler<MyArgs>`，它定义了事件参数的类型。在引发事件时，我们需要传递`MyArgs`的一个实例。事件的订阅者可以访问并使用参数。现在，让我们看一下以下`CreateAndRaiseEvent()`方法的代码：

```cs
public partial class Program 
{ 
  private static void CreateAndRaiseEvent() 
  { 
    EventClassWithEventHandler ev = 
      new EventClassWithEventHandler(); 
    ev.OnChange += (sender, e) 
      => Console.WriteLine( 
          "Event raised with args: {0}", e.Value); 
    ev.Raise(); 
  } 
} 

```

如果我们运行前面的代码，将在控制台上看到以下输出：

![使用 EventHandler 或 EventHandler<T>](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/fn-cs/img/Image00033.jpg)

从前面的代码中，我们可以看到 lambda 表达式发挥了订阅事件的作用，如下所示：

```cs
ev.OnChange += (sender, e) 
  => Console.WriteLine( 
      "Event raised with args: {0}", e.Value); 

```

# 在函数式编程中使用 lambda 表达式的优势

Lambda 表达式不仅是提供匿名方法的简写符号的强大方式，而且还在函数式编程中使用。在本节中，我们将讨论在函数式编程的上下文中使用 lambda 表达式的优势。

## 一流函数

在第一章中，*在 C#中品尝函数式风格*，我们在讨论函数式编程时讨论了一流函数的概念。如果函数是一流函数，函数遵循值语义。它们可以作为参数传递，从函数返回，等等。如果我们回到关于 lambda 表达式的早期话题，我们有一个名为`SimpleLambdaExpression.csproj`的项目，其中包含以下简单的 lambda 表达式：

```cs
public partial class Program 
{ 
  static Func<string, string> displayMessageDelegate = 
    str => String.Format(Message: {0}", str); 
} 

```

然后，我们可以将以下`firstClassConcept()`方法添加到项目中，以演示使用 lambda 表达式的一流函数：

```cs
public partial class Program 
{ 
  static private void firstClassConcept() 
  { 
    string str = displayMessageDelegate( 
      "Assign displayMessageDelegate() to variable"); 
      Console.WriteLine(str); 
  } 
} 

```

如我们所见，我们已成功将`displayMessageDelegate()`方法分配给名为`str`的变量，如下所示：

```cs
string str = displayMessageDelegate( 
  "Assign displayMessageDelegate() to variable"); 

```

如果我们运行代码，将在控制台上看到以下输出：

![一流函数](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/fn-cs/img/Image00034.jpg)

我们还可以将 lambda 表达式作为其他函数的参数传递。使用`displayMessageDelegate`，让我们看一下以下代码：

```cs
public partial class Program 
{ 
  static private void firstClassConcept2( 
    Func<string, string> funct, 
    string message) 
  { 
    Console.WriteLine(funct(message)); 
  } 
} 

```

我们有一个名为`firstClassConcept2`的方法，它接受`Func`和字符串参数。我们可以按以下方式运行该方法：

```cs
public partial class Program 
{ 
  static void Main(string[] args) 
  { 
    firstClassConcept2( 
      displayMessageDelegate, 
      "Pass lambda expression to argument"); 
  } 
} 

```

如我们所见，我们将 lambda 表达式`displayMessageDelegate`传递给`firstClassConcept2()`方法。如果我们运行该项目，将在控制台窗口上看到以下输出：

![一流函数](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/fn-cs/img/Image00035.jpg)

由于我们已经成功地将一个函数分配给一个变量，并将一个函数传递给另一个函数参数，我们可以说 lambda 表达式是在函数式编程中创建一流函数的强大工具。

## 闭包

闭包是一个能够被分配给一个变量（第一类函数）的函数，它具有自由变量，这些变量在词法环境中被绑定。自由变量是一个不是参数的变量；或者是一个局部变量。在闭包中，任何未绑定的变量都将从定义闭包的词法环境中捕获。为了避免对这个术语感到困惑，让我们看一下以下代码，在`Closure.csproj`项目中可以找到：

```cs
public partial class Program 
{ 
  private static Func<int, int> GetFunction() 
  { 
    int localVar = 1; 
    Func<int, int> returnFunc = scopeVar => 
    { 
      localVar *= 2; 
      return scopeVar + localVar; 
    }; 
  return returnFunc; 
  } 
} 

```

从上面的代码中，我们可以看到我们有一个名为`localVar`的局部变量，当调用`GetFunction()`方法时，它将乘以 2。`localVar`变量在`returnValue`返回时绑定在 lambda 表达式中。通过分析前面的代码而不运行它，我们可能会猜测`GetFunction()`将返回`returnFunc`，每次传递给相同的参数时都将返回相同的值。这是因为`localVar`每次调用`GetFunction()`时都将始终为*1*，因为它是一个局部变量。正如我们在编程中学到的，局部变量是在堆栈上创建的，当方法执行完毕时它们将消失。现在，让我们调用`GetFunction()`方法来证明我们的猜测，使用以下代码：

```cs
public partial class Program 
{ 
  static void Main(string[] args) 
  { 
    Func<int, int> incrementFunc = GetFunction(); 
    for (int i = 0; i < 10; i++) 
    { 
      Console.WriteLine( 
        "Invoking {0}: incrementFunc(1) = {1}", 
        i, 
        incrementFunc(1)); 
    } 
  } 
} 

```

我们将调用`incrementFunc()`方法，这是`GetFunction()`方法的返回值，调用十次，但我们总是传递 1 作为参数。根据我们之前的猜测，我们可以说`incrementFunc(1)`方法在所有十次调用中都将返回`3`。现在，让我们运行项目，我们将在控制台上看到以下输出：

![Closure](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/fn-cs/img/Image00036.jpg)

根据前面的输出，我们猜错了。`localVar`变量与`GetFunction()`方法一起存在。它在每次调用方法时都会存储其值乘以 2。我们已经成功地在词法环境中绑定了一个自由变量，这就是我们所说的闭包。

# 总结

在本章中，我们发现匿名方法是一种没有名称的方法。我们只需要定义方法的参数和实现。这是从委托中的简写表示。然后，我们看了 lambda 表达式，这是函数式编程中的强大工具，可以提供匿名方法的简写表示。

lambda 表达式也可以用来形成表达式树，当我们需要用常规 C#表达我们的代码，解构它，检查它和解释它时，这将非常有用。表达式树就像是代码的解释。如果我们有一个`<Func<int, int, int>>`表达式，它解释了如果我们给代码两个整数，它将提供一个`int`返回。

通过 lambda 表达式也可以订阅事件。事件中有两种类，发布者和订阅者，我们可以使用 lambda 表达式订阅事件。无论我们使用`event`关键字还是`EventHandler`关键字，lambda 表达式都可以用来订阅事件。

第一类函数概念也可以通过 lambda 表达式来实现，因为通过使用它，我们可以将函数分配给变量或将函数作为其他函数的参数传递。使用 lambda 表达式，我们还可以应用闭包概念，使局部变量在函数内部保持活动状态。

目前，讨论 lambda 表达式就足够了。但是，当我们在第五章中讨论 LINQ 时，我们将再次更详细地讨论 lambda 表达式，*使用 LINQ 轻松查询任何集合*。而在下一章中，我们将讨论可以用来扩展方法能力的扩展方法。


# 第四章：使用扩展方法扩展对象功能

正如我们在上一章中已经提到的，我们将在本章中更详细地讨论扩展方法。当我们在下一章中讨论 LINQ 时，这将是有帮助的，LINQ 是 C#中函数式编程的基本技术。以下是本章我们将涵盖的主题：

+   练习使用扩展方法并在 IntelliSense 中获得这个新方法

+   从其他程序集调用扩展方法

+   为接口、集合、枚举和其他对象创建新方法

+   与函数式编程相关的扩展方法的优势

+   扩展方法的限制

# 接近扩展方法

扩展方法是一种能够扩展现有类或类型的能力，而不对现有类或类型进行任何修改。这意味着扩展方法使我们能够向现有类或类型添加方法，而无需创建新的派生类型或重新编译。

扩展方法是在 C# 3.0 中引入的，可以应用于我们自己的类型或.NET 中现有的类型。扩展方法在函数式编程中将被广泛使用，因为它符合方法链的概念，我们在第一章中已经使用了*在 C#中品尝函数式风格*，在以函数式风格重构代码时。

## 创建扩展方法

扩展方法必须声明在一个静态、非泛型和非嵌套的类中。它们是静态类中的静态方法。要创建扩展方法，首先我们必须创建一个`public static`类，因为扩展方法必须包含在`static`类中。成功创建`public static`类后，我们在类中定义一个方法，并在第一个方法参数中添加`this`关键字，以指示它是一个`扩展`方法。具有`this`关键字的方法中的第一个参数必须引用我们要扩展的类的特定实例。为了使解释更清晰，让我们看一下以下代码，创建一个扩展方法，我们可以在`Palindrome.csproj`项目中找到：

```cs
public static class ExtensionMethods 
{ 
  public static bool IsPalindrome(this string str) 
  { 
    char[] array = str.ToCharArray(); 
    Array.Reverse(array); 
    string backwards = new string(array); 
    return str == backwards; 
  } 
} 

```

现在让我们解剖上述代码，以了解如何创建扩展方法。首先，我们必须成功创建`public static`类，如下面的代码片段所示：

```cs
public static class ExtensionMethods 
{ 
  ... 
} 

```

然后，我们在类中创建一个`static`方法，如下面的代码片段所示：

```cs
public static bool IsPalindrome(this string str) 
{ 
  ... 
} 

```

正如我们在前面的方法中所看到的，我们在方法的第一个参数中添加了`this`关键字。这表明该方法是一个`扩展`方法。此外，第一个参数的类型，即字符串，表示我们要扩展的类型是`string`数据类型。现在，通过为`string`类型定义`IsPalindrome()`扩展方法，所有字符串实例都具有`IsPalindrome()`方法。让我们看一下以下代码来证明这一点：

```cs
public class Program 
{ 
  static void Main(string[] args) 
  { 
    string[] strArray = { 
      "room", 
      "level", 
      "channel", 
      "heat", 
      "burn", 
      "madam", 
      "machine", 
      "jump", 
      "radar", 
      "brain" 
    }; 
    foreach (string s instrArray) 
    { 
      Console.WriteLine("{0} = {1}", s, s.IsPalindrome()); 
    } 
  } 
} 

```

上述的`Main()`函数将检查`strArray`数组的所有成员，无论它是否是回文。我们可以从`string`类型的变量`s`中调用`IsPalindrome()`方法。当从字符串类型的实例调用`IsPalindrome()`方法时，代码片段如下：

```cs
foreach (string s instrArray) 
{ 
  Console.WriteLine("{0} = {1}", s, s.IsPalindrome()); 
} 

```

如果我们运行`Palindrome.csproj`项目，我们可以在控制台上获得以下输出：

![创建扩展方法](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/fn-cs/img/Image00037.jpg)

由于回文是一个单词或另一个字符序列，无论我们是向后读还是向前读，只有`level`，`madam`和`radar`如果我们对它们调用`IsPalindrome()`方法，将返回`true`。我们的扩展方法已成功创建并运行。

## 代码 IntelliSense 中的扩展方法

当我们为实例创建扩展方法时，与类或类型中已存在的方法相比，没有明显的区别。这是因为在调用扩展方法或实际在类型中定义的方法时，我们将执行相同的操作。然而，我们可以检查代码智能感知来了解类型内部的方法是否是扩展方法，因为扩展方法将显示在智能感知中。当`IsPalindrome()`扩展方法尚未定义时，以下截图是字符串实例的方法列表：

![代码智能感知中的扩展方法](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/fn-cs/img/Image00038.jpg)

当`IsPalindrome()`扩展方法已经定义时，以下截图是字符串实例的方法列表：

![代码智能感知中的扩展方法](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/fn-cs/img/Image00039.jpg)

我们可以从前面两张图片中看到，扩展方法将在 Visual Studio 的代码智能感知中列出。然而，我们现在可以找到扩展方法和实际在类型中定义的方法之间的区别。扩展方法的图标有一个向下的箭头，尽管我们在实际定义的方法中找不到它。这是因为图标不同，但我们调用方法的方式完全相同。

# 在其他程序集中调用扩展方法

我们已经成功在上一节中创建了`IsPalindrome()`扩展方法。调用扩展方法非常容易，因为它是在与调用方法相同的命名空间中定义的。换句话说，`IsPalindrome()`扩展方法和`Main()`方法在同一个命名空间中。我们不需要添加对任何模块的引用，因为该方法与调用者一起存在。然而，在通常的实践中，我们可以在其他程序集中创建扩展方法，通常称为类库。使用该类库将简化扩展方法的使用，因为它可以被重用，所以我们可以在许多项目中使用该扩展方法。

## 引用命名空间

我们将在`类库`中创建一个扩展方法，并在另一个项目中调用它。让我们创建一个名为`ReferencingNamespaceLib.csproj`的新`类库`项目，并将以下代码插入`ExtensionMethodsClass.cs`文件中：

```cs
using System; 
namespaceReferencingNamespaceLib 
{ 
  public static class ExtensionMethodsClass 
  { 
    public static byte[] ConvertToHex(this string str) 
    { 
      int i = 0; 
      byte[] HexArray = new byte[str.Length]; 
      foreach (char ch in str) 
      { 
        HexArray[i++] = Convert.ToByte(ch); 
      } 
      returnHexArray; 
    } 
  } 
} 

```

从前面的代码中，我们可以看到我们在`ReferencingNamespaceLib`命名空间的`ExtensionMethodsClass`类中创建了`ConvertToHex()`扩展方法。`ConvertToHex()`扩展方法的用途是将字符串中的每个字符转换为 ASCII 码并将其存储在字节数组中。现在让我们看一下以下代码，它将调用我们可以在`ReferencingNamespace.csproj`项目中找到的扩展方法：

```cs
using System; 
using ReferencingNamespaceLib; 
namespace ReferencingNamespace 
{ 
  class Program 
  { 
    static void Main(string[] args) 
    { 
      int i = 0; 
      string strData = "Functional in C#"; 
      byte[] byteData = strData.ConvertToHex(); 
      foreach (char c in strData) 
      { 
        Console.WriteLine("{0} = 0x{1:X2} ({2})", 
        c.ToString(), 
        byteData[i], 
        byteData[i++]); 
      } 
    } 
  } 
} 

```

从前面的代码中，我们可以看到我们如何从字符串实例`strData`中调用`ConvertToHex()`扩展方法，如下所示：

```cs
string strData = "Functional in C#"; 
byte[] byteData = strData.ConvertToHex(); 

```

然而，为了从字符串实例中调用`ConvertToHex()`方法，我们必须引用`ReferencingNamespaceLib`程序集，并且还要导入引用程序集的命名空间。要导入程序集，我们必须使用`using`以及`ReferencingNamespaceLib`，如下面的代码片段所示：

```cs
usingReferencingNamespaceLib; 

```

如果我们运行`ReferencingNamespace.csproj`项目，我们将在控制台上得到以下输出：

![引用命名空间](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/fn-cs/img/Image00040.jpg)

正如我们所看到的，C#句子中的每个字符都被转换为 ASCII 码，通过引用命名空间调用了我们为字符串类型创建的扩展方法，以十六进制和十进制格式显示。这也证明了我们已经成功在另一个程序集中。

## 搭便车命名空间

如果我们愿意，我们可以依赖存储字符串类型的`System`命名空间，这样我们就不需要导入自定义命名空间来使用扩展方法。依赖命名空间对于我们的标准编程方法也是有好处的。让我们使用`PiggybackingNamespaceLib.csproj`项目中的以下代码重构我们之前的`ReferencingNamespaceLib.csproj`代码：

```cs
namespace System 
{ 
  public static class ExtensionMethodsClass 
  { 
    public static byte[] ConvertToHex(this string str) 
    { 
      int i = 0; 
      byte[] HexArray = new byte[str.Length]; 
      foreach (char ch in str) 
      { 
        HexArray[i++] = Convert.ToByte(ch); 
      } 
      return HexArray; 
    } 
  } 
} 

```

如果我们观察类名、`ConvertToHex()`方法签名或方法的实现，我们会发现`ReferencingNamespaceLib.csproj`和`PiggybackingNamespaceLib.csproj`项目之间没有区别。但是，如果我们看命名空间名称，我们会发现现在是`System`而不是`PiggybackingNamespaceLib`。我们使用`System`命名空间的原因是在所选命名空间中创建扩展方法。由于我们想要扩展`System`命名空间中的字符串类型的能力，我们也必须扩展`System`命名空间。我们不需要使用`using`关键字导入`System`命名空间，因为`ConvertToHex()`方法位于`System`命名空间中。现在，让我们看一下以下代码，以便在`PiggybackingNamespace.csproj`项目中调用`System`命名空间中的`ConvertToHex()`方法：

```cs
using System; 
namespace PiggybackingNamespace 
{ 
  class Program 
  { 
    static void Main(string[] args) 
    { 
      int i = 0; 
      string strData = "Piggybacking"; 
      byte[] byteData = strData.ConvertToHex(); 
      foreach (char c in strData) 
      { 
        Console.WriteLine("{0} = 0x{1:X2} ({2})", 
        c.ToString(), 
        byteData[i], 
        byteData[i++]); 
      } 
    } 
  } 
} 

```

我们重构了`ReferencingNamespace.csproj`项目中的前面的代码，再次发现`PiggybackingNamespace.csproj`项目和`ReferencingNamespace.csproj`项目之间没有任何区别，除了`PiggybackingNamespace.csproj`项目中没有导入自定义命名空间，而`ReferencingNamespace.csproj`项目有：

```cs
using ReferencingNamespaceLib; 

```

由于我们在`System`命名空间中创建了扩展方法，所以我们不需要导入自定义命名空间。但是，我们仍然需要引用定义扩展方法的程序集。我们可以期望得到如下截图所示的输出：

![依赖命名空间](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/fn-cs/img/Image00041.jpg)

我们已成功调用了`ConvertToHex()`扩展方法，并发现它对从字符串数据类型获取 ASCII 代码很有用。

# 利用接口、集合和对象

不仅类和类型可以应用扩展方法，接口、集合和任何其他对象也可以使用扩展方法进行功能扩展。我们将在接下来的部分讨论这个问题。

## 扩展接口

我们可以以与在类或类型中扩展方法相同的方式扩展接口中的方法。我们仍然需要`public static`类和`public static`方法。通过扩展接口的能力，我们可以在创建扩展方法后立即使用它，而无需在我们从接口继承的类中创建实现，因为实现是在我们声明扩展方法时完成的。让我们看一下`ExtendingInterface.csproj`项目中的以下`DataItem`类：

```cs
namespace ExtendingInterface 
{ 
  public class DataItem 
  { 
    public string Name { get; set; } 
    public string Gender { get; set; } 
  } 
} 

```

我们还有以下`IDataSource`接口：

```cs
namespace ExtendingInterface 
{ 
  public interface IDataSource 
  { 
    IEnumerable<DataItem> GetItems(); 
  } 
} 

```

正如我们所看到的，`IDataSource`接口只有一个名为`GetItems()`的方法签名，返回`IEnumerable<DataItem>`。现在，我们可以创建一个类来继承`IDataSource`接口，我们给它一个名字`ClubMember`；它有`GetItems()`方法的实现，如下所示：

```cs
public partial class ClubMember : IDataSource 
{ 
  public IEnumerable<DataItem> GetItems() 
  { 
    foreach (var item in DataItemList) 
    { 
      yield return item; 
    } 
  } 
} 

```

从前面的类中，`GetItems()`方法将产生`DataItemList`中的所有数据，其内容将如下所示：

```cs
public partial class ClubMember : IDataSource 
{ 
  List<DataItem> DataItemList = new List<DataItem>() 
  { 
    newDataItem{ 
      Name ="Dorian Villarreal", 
      Gender ="Male"}, 
    newDataItem{ 
      Name ="Olivia Bradley", 
      Gender ="Female"}, 
    newDataItem{ 
      Name ="Jocelyn Garrison", 
      Gender ="Female"}, 
    newDataItem{ 
      Name ="Connor Hopkins", 
      Gender ="Male"}, 
    newDataItem{ 
      Name ="Rose Moore", 
      Gender ="Female"}, 
    newDataItem{ 
      Name ="Conner Avery", 
      Gender ="Male"}, 
    newDataItem{ 
      Name ="Lexie Irwin", 
      Gender ="Female"}, 
    newDataItem{ 
      Name ="Bobby Armstrong", 
      Gender ="Male"}, 
    newDataItem{ 
      Name ="Stanley Wilson", 
      Gender ="Male"}, 
    newDataItem{ 
      Name ="Chloe Steele", 
      Gender ="Female"} 
  }; 
} 

```

在`DataItemList`中有十个`DataItem`类。我们可以通过`GetItems()`方法显示`DataItemList`中的所有项目，如下所示：

```cs
public class Program 
{ 
static void Main(string[] args) 
  { 
    ClubMember cm = new ClubMember(); 
    foreach (var item in cm.GetItems()) 
    { 
      Console.WriteLine( 
        "Name: {0}\tGender: {1}", 
          item.Name, 
            item.Gender); 
    } 
  } 
} 

```

正如我们在上述代码中所看到的，由于我们已将`ClubMember`类继承到`IDataSource`接口，并实现了`GetItems()`方法，因此`ClubMember`的实例`cm`可以调用`GetItems()`方法。当我们运行项目时，输出将如下截图所示：

![扩展接口](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/fn-cs/img/Image00042.jpg)

现在，如果我们想要在不修改接口的情况下向其添加方法，我们可以为接口创建一个方法扩展。考虑到我们要向`IDataSource`接口添加`GetItemsByGender()`方法，我们可以创建如下的扩展方法：

```cs
namespaceExtendingInterface 
{ 
  public static class IDataSourceExtension 
  { 
    public static IEnumerable<DataItem>
      GetItemsByGender(thisIDataSourcesrc,string gender) 
    { 
      foreach (DataItem item in src.GetItems()) 
      { 
        if (item.Gender == gender) 
          yield return item; 
      } 
    } 
  } 
} 

```

通过创建上述扩展方法，`ClubMember`类的实例现在有一个名为`GetItemsByGender()`的方法。我们可以像使用方法类一样使用这个扩展方法，如下所示：

```cs
public class Program 
{ 
  static void Main(string[] args) 
  { 
    ClubMember cm = new ClubMember(); 
    foreach (var item in cm.GetItemsByGender("Female")) 
    { 
      Console.WriteLine( 
        "Name: {0}\tGender: {1}", 
        item.Name, 
        item.Gender); 
    } 
  } 
} 

```

`GetItemsByGender()`方法将返回`DataItemList`所选性别的`IEnumerable`接口。由于我们只需要获取列表中的所有女性成员，输出将如下所示：

![扩展接口](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/fn-cs/img/Image00043.jpg)

我们现在可以扩展接口中的方法，而不需要在继承的类中实现该方法，因为在扩展方法定义中已经完成了。

## 扩展集合

在我们之前的讨论中，我们发现我们应用`IEnumerable`接口以收集所需的所有数据。我们还可以扩展`IEnumerable`接口，这是一种集合类型，以便我们可以在集合类型的实例中添加方法。

以下是`ExtendingCollection.csproj`项目中的代码，我们仍然使用`ExtendingInterface.csproj`项目中使用的`DataItem.cs`和`IDataSource.cs`。让我们看一下以下代码：

```cs
public static partial class IDataSourceCollectionExtension 
{ 
  public static IEnumerable<DataItem>
    GetAllItemsByGender_IEnum(thisIEnumerablesrc,string gender) 
  { 
    var items = new List<DataItem>(); 
    foreach (var s in src) 
    { 
      var refDataSource = s as IDataSource; 
      if (refDataSource != null) 
      { 
        items.AddRange(refDataSource.GetItemsByGender(gender)); 
       } 
    } 
    return items; 
  } 
} 

```

上述代码是`IEnumerable`类型的扩展方法。为了防止出现错误，我们必须使用以下代码片段对所有源项的类型进行转换：

```cs
var refDataSource = s as IDataSource; 

```

我们还可以扩展`IEnumerable<T>`类型，如下所示：

```cs
public static partial class IDataSourceCollectionExtension 
{ 
  public static IEnumerable<DataItem> 
  GetAllItemsByGender_IEnumTemplate
    (thisIEnumerable<IDataSource> src, string gender) 
  { 
    return src.SelectMany(x =>x.GetItemsByGender(gender)); 
  } 
} 

```

使用上述方法，我们可以扩展`IEnumerable<T>`类型，以拥有一个名为`GetAllItemsByGender_IEnumTemplate()`的方法，用于按特定性别获取项目。

现在，我们准备调用这两个扩展方法。但在调用它们之前，让我们创建以下两个类，名为`ClubMember1`和`ClubMember2`：

```cs
public class ClubMember1 : IDataSource 
{ 
  public IEnumerable<DataItem> GetItems() 
  { 
    return new List<DataItem> 
    { 
      newDataItem{ 
        Name ="Dorian Villarreal", 
        Gender ="Male"}, 
      newDataItem{ 
        Name ="Olivia Bradley", 
        Gender ="Female"}, 
      newDataItem{ 
        Name ="Jocelyn Garrison", 
        Gender ="Female"}, 
      newDataItem{ 
        Name ="Connor Hopkins", 
        Gender ="Male"}, 
      newDataItem{ 
        Name ="Rose Moore", 
        Gender ="Female"} 
    }; 
  } 
} 
public class ClubMember2 : IDataSource 
{ 
  public IEnumerable<DataItem> GetItems() 
  { 
    return new List<DataItem> 
    { 
      newDataItem{ 
        Name ="Conner Avery", 
        Gender ="Male"}, 
      newDataItem{ 
        Name ="Lexie Irwin", 
        Gender ="Female"}, 
      newDataItem{ 
        Name ="Bobby Armstrong", 
        Gender ="Male"}, 
      newDataItem{ 
        Name ="Stanley Wilson", 
        Gender ="Male"}, 
      newDataItem{ 
        Name ="Chloe Steele", 
        Gender ="Female"} 
    }; 
  } 
} 

```

现在，我们将调用`GetAllItemsByGender_IEnum()`和`GetAllItemsByGender_IEnumTemplate()`扩展方法。代码将如下所示：

```cs
public class Program 
{ 
  static void Main(string[] args) 
  { 
    var sources = new IDataSource[] 
    { 
      new ClubMember1(), 
      new ClubMember2() 
    }; 
    var items = sources.GetAllItemsByGender_IEnum("Female"); 
    Console.WriteLine("Invoking GetAllItemsByGender_IEnum()"); 
    foreach (var item in items) 
    { 
      Console.WriteLine( 
        "Name: {0}\tGender: {1}", 
        item.Name, 
        item.Gender); 
    } 
  } 
} 

```

从上述代码中，首先我们创建一个包含`IDataSource`数组的`sources`变量。我们从`ClubMember1`和`ClubMember2`类获取`sources`的数据。由于源是`IDataSource`的集合，因此可以将`GetAllItemsByGender_IEnum()`方法应用于它。如果我们运行上述`Main()`方法，将在控制台上显示以下输出：

![扩展集合](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/fn-cs/img/Image00044.jpg)

我们已成功调用了`GetAllItemsByGender_IEnum()`扩展方法。现在，让我们尝试使用以下代码调用`GetAllItemsByGender_IEnumTemplate`扩展方法：

```cs
public class Program 
{ 
  static void Main(string[] args) 
  { 
    var sources = new List<IDataSource> 
    { 
      new ClubMember1(), 
      new ClubMember2() 
    }; 
    var items = 
      sources.GetAllItemsByGender_IEnumTemplate("Female"); 
    Console.WriteLine(
      "Invoking GetAllItemsByGender_IEnumTemplate()"); 
    foreach (var item in items) 
    { 
      Console.WriteLine("Name: {0}\tGender: {1}", 
        item.Name,item.Gender); 
    } 
  } 
} 

```

我们在尚未显示的代码中声明了`sources`变量，方式与之前的`Main()`方法中声明它的方式相同。此外，我们可以将`GetAllItemsByGender_IEnumTemplate()`扩展方法应用于源变量。如果我们运行上述代码，输出将如下所示：

![扩展集合](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/fn-cs/img/Image00045.jpg)

通过比较输出的两个图像，我们可以看到它们之间没有区别，尽管它们扩展了不同的集合类型。

## 扩展对象

我们不仅可以扩展接口和集合，还可以扩展对象，这意味着我们可以扩展一切。为了讨论这一点，让我们看一下在`ExtendingObject.csproj`项目中可以找到的以下代码：

```cs
public static class ObjectExtension 
{ 
  public static void WriteToConsole(this object o,    stringobjectName) 
  { 
    Console.WriteLine(
      String.Format(
        "{0}: {1}\n",
        objectName,
        o.ToString())); 
  } 
} 

```

我们有一个名为`WriteToConsole()`的方法扩展，它可以应用于 C#中的所有对象，因为它扩展了`Object`类。要使用它，我们可以将它应用于各种对象，如下面的代码所示：

```cs
public class Program 
{ 
  static void Main(string[] args) 
  { 
    var obj1 = UInt64.MaxValue; 
    obj1.WriteToConsole(nameof(obj1)); 
    var obj2 = new DateTime(2016, 1, 1); 
    obj2.WriteToConsole(nameof(obj2)); 
    var obj3 = new DataItem 
    { 
      Name = "Marcos Raymond", 
      Gender = "Male" 
    }; 
    obj3.WriteToConsole(nameof(obj3)); 
    IEnumerable<IDataSource> obj4 =new List<IDataSource> 
    { 
      new ClubMember1(), 
      new ClubMember2() 
    }; 
    obj4.WriteToConsole(nameof(obj4)); 
  } 
} 

```

在我们分解前面的代码之前，让我们运行这个`Main()`方法，我们将在控制台上得到以下输出：

![扩展对象](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/fn-cs/img/Image00046.jpg)

从前面的代码中，我们可以看到所有`UInt64`，`DateTime`，`DataItem`和`IEnumerable<IDataSource>`对象都可以调用我们声明的`WriteToConsole()`扩展方法，该方法使用`this`对象作为参数。

### 提示

在对象类型中创建扩展方法会导致框架中的所有类型都能够访问该方法。我们必须确保该方法的实现可以应用于框架支持的不同类型。

# 在函数式编程中使用扩展方法的优势

函数式编程中的方法链依赖于扩展方法。正如我们在第一章中已经讨论过的那样，*在 C#中品尝函数式风格*，方法链将使我们的代码更易于阅读，因为它可以减少代码行数。为了提高扩展方法的代码可读性，让我们看一下以下代码，可以在`CodeReadability.csproj`项目中找到：

```cs
using System.Linq; 
namespace CodeReadability 
{ 
  public static class HelperMethods 
  { 
    public static string TrimAllSpace(string str) 
    { 
      string retValue = ""; 
      foreach (char c in str) 
      { 
        retValue +=!char.IsWhiteSpace(c) ?c.ToString() :""; 
      } 
      return retValue; 
    } 
    public static string Capitalize(string str) 
    { 
      string retValue = ""; 
      string[] allWords = str.Split(' '); 
      foreach (string s inallWords) 
      { 
        retValue += s.First() 
        .ToString() 
        .ToUpper() 
        + s.Substring(1) 
        + " "; 
      } 
      return retValue.Trim(); 
    } 
  } 
} 

```

前面的代码是`static`类中的`static`方法。它不是扩展方法，因为在方法参数中我们没有使用`this`关键字。我们可以在`HelperMethods.cs`文件中找到它。`TrimAllSpace()`方法的用途是从字符串中删除所有空格字符，而`Capitalize()`方法的用途是将字符串中的第一个字母大写。我们还有完全相同的方法`HelperMethods`，可以在`ExtensionMethods.cs`文件中找到。让我们看一下以下代码，其中我们将`TrimAllSpace()`和`Capitalize()`声明为扩展方法：

```cs
using System.Linq; 
namespace CodeReadability 
{ 
  public static class ExtensionMethods 
  { 
    public static string TrimAllSpace(this string str) 
    { 
      string retValue = ""; 
      foreach (char c in str) 
      { 
        retValue +=!char.IsWhiteSpace(c) ?c.ToString() :""; 
      } 
      return retValue; 
    } 
    public static string Capitalize(string str) 
    { 
      string retValue = ""; 
      string[] allWords = str.Split(' '); 
      foreach (string s inallWords) 
      { 
        retValue += s.First() 
          .ToString() 
          .ToUpper() 
          + s.Substring(1) 
          + " "; 
      } 
      return retValue.Trim(); 
    } 
  } 
} 

```

现在，我们将创建代码，将修剪给定字符串中的所有空格，然后将句子中的每个字符串大写。以下是在`HelperMethods`类中实现的代码：

```cs
static void Main(string[] args) 
{ 
  string sntc = ""; 
  foreach (string str in sentences) 
  { 
    string strTemp = str; 
    strTemp = HelperMethods.TrimAllSpace(strTemp); 
    strTemp = HelperMethods.Capitalize(strTemp); 
    sntc += strTemp + " "; 
  } 
  Console.WriteLine(sntc.Trim()); 
} 

```

我们还声明了一个名为`sentences`的字符串数组，如下所示：

```cs
static string[] sentences = new string[] 
{ 
  " h o w ", 
  " t o ", 
  " a p p l y ", 
  " e x t e n s i o n ", 
  " m e t h o d s ", 
  " i n ", 
  " c s h a r p ", 
  " p r o g r a m mi n g " 
}; 

```

前面的代码将产生以下输出：

![在函数式编程中使用扩展方法的优势](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/fn-cs/img/Image00047.jpg)

如果我们愿意，我们可以简化前面使用`HelperMethods`的`Main()`方法，使用我们已经创建的扩展方法，如下所示：

```cs
static void Main(string[] args) 
{ 
  string sntc = ""; 
  foreach (string str in sentences) 
  { 
    sntc += str.TrimAllSpace().Capitalize() + " "; 
  } 
  Console.WriteLine(sntc.Trim()); 
} 

```

如果我们运行前面的`Main()`方法，我们将在控制台上得到完全相同的输出。但是，我们已经重构了以下代码片段：

```cs
string strTemp = str; 
strTemp = HelperMethods.TrimAllSpace(strTemp); 
strTemp = HelperMethods.Capitalize(strTemp); 
sntc += strTemp + " "; 

```

使用扩展方法，我们只需要这一行代码来替换四行代码：

```cs
sntc += str.TrimAllSpace().Capitalize() + " "; 

```

关键是我们已经减少了代码行数，使其变得更简单和更易读，流程也更清晰了。

# 扩展方法的限制

尽管扩展方法是实现函数式编程的强大工具，但这种技术仍然存在一些局限性。在这里，我们详细阐述了扩展方法所面临的限制，以便我们避免使用它们。

## 扩展静态类

随着我们进一步讨论扩展方法，我们知道扩展方法是具有公共可访问性的静态方法，位于具有公共可访问性的静态类内。扩展方法将出现在我们目标的类型或类中。但是，并非所有类都可以使用扩展方法进行扩展。现有的静态类将无法进行扩展。例如，`Math`类是由.NET 提供的。即使该类提供了我们通常使用的数学功能，有时我们可能需要向`Math`类添加其他功能。

然而，由于`Math`类是一个静态类，几乎不可能通过向其添加单个方法来扩展此类。假设我们想要添加`Square()`方法来找到一个数字与自身相乘的结果。以下是代码，我们可以在`ExtendingStaticClass.csproj`项目中找到，如果我们尝试向`Math`类添加扩展方法：

```cs
public static class StaticClassExtensionMethod 
{ 
  public static int Square(this Math m, inti) 
  { 
    return i * i; 
  } 
} 

```

当我们编译上述代码时，将会出现类似于以下截图所示的错误：

![扩展静态类](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/fn-cs/img/Image00048.jpg)

错误消息显示`Math`静态方法不能作为`Square()`扩展方法的参数使用。为了克服这个限制，我们现在可以扩展类型而不是`Math`类。我们可以通过向`int`类型添加`Square()`方法来扩展`int`类型。以下是扩展`int`类的代码：

```cs
public static class StaticClassExtensionMethod 
{ 
  public static int Square(this inti) 
  { 
    return i * i; 
  } 
} 

```

正如我们所看到的，我们扩展了`int`类型，这样如果我们想要调用`Square()`方法，我们可以使用以下代码来调用它：

```cs
public class Program 
{ 
  static void Main(string[] args) 
  { 
    int i = 60; 
    Console.WriteLine(i.Square()); 
  } 
} 

```

然而，使用这种技术，我们还需要扩展其他类型，如`float`和`double`，以适应各种数据类型中的`Square()`功能。

## 修改现有类或类型中的方法实现

尽管扩展方法可以应用于现有的类和类型，但我们不能修改现有方法的实现。我们可以尝试使用以下代码，我们可以在`ModifyingExistingMethod.csproj`项目中找到：

```cs
namespace ModifyingExistingMethod 
{ 
  public static class ExtensionMethods 
  { 
    public static string ToString(this string str) 
    { 
      return "ToString() extension method"; 
    } 
  } 
} 

```

在上述代码中，我们尝试用前面代码中的`ToString()`扩展方法替换字符串类型已有的`ToString()`方法。幸运的是，该代码将能够成功编译。现在，让我们在项目的`Main()`方法中添加以下代码：

```cs
namespace ModifyingExistingMethod 
{ 
  public class Program 
  { 
    static void Main(string[] args) 
    { 
      stringstr = "This is string"; 
      Console.WriteLine(str.ToString()); 
    } 
  } 
} 

```

然而，如果我们运行该项目，`ToString()`扩展方法将永远不会被执行。我们将从现有的`ToString()`方法中获得输出。

# 总结

扩展方法为我们提供了一种简单的方法，可以向现有类或类型添加新方法，而无需修改原始类或类型。此外，我们无需重新编译代码，因为在创建扩展方法后，代码将立即识别它。扩展方法必须声明为静态方法，位于静态类中。与类或类型中的现有方法相比，该方法没有明显的区别，该方法也将出现在 IntelliSense 中。

扩展方法也可以在另一个程序集中声明，并且我们必须引用定义了该方法的静态类的命名空间，存储在其他程序集中。然而，我们可以使用附加命名空间技术，使用现有命名空间，这样我们就不需要再引用任何其他命名空间了。我们不仅可以扩展类和类型的功能，还可以扩展接口、集合和框架中的任何对象。

与其他 C#技术一样，扩展方法也有其优点和局限性。与函数式编程相关的一个优点是，扩展方法将使我们的代码应用方法链，以便应用函数式方法。然而，我们不能扩展静态类，也不能修改现有类或类型中的方法实现，这是扩展方法的局限性。

在下一章中，我们将深入研究 LINQ 技术，因为我们已经对委托、Lambda 表达式和扩展方法有足够的了解。我们还将讨论 LINQ 提供的编写函数式程序的便捷方式。


# 第五章：使用 LINQ 轻松查询任何集合

在讨论了委托、lambda 表达式和扩展方法之后，我们现在准备继续讨论 LINQ。在本章中，我们将深入探讨 LINQ，这在组成功能代码中是至关重要的。在这里，我们将讨论以下主题：

+   介绍 LINQ 查询

+   理解 LINQ 中的延迟执行

+   比较 LINQ 流畅语法和 LINQ 查询表达式语法

+   枚举 LINQ 运算符

# 开始使用 LINQ

**语言集成查询**（**LINQ**）是 C# 3.0 中引入的.NET Framework 的语言特性，它使我们能够轻松查询实现`IEnumerable<T>`接口的集合中的数据，例如`ArrayList<T>`，`List<T>`，XML 文档和数据库。使用 LINQ，查询集合中的任何数据变得更容易，因为我们不需要为不同的数据源学习不同的语法。例如，如果数据源是数据库，我们就不需要学习 SQL，而是使用 LINQ。同样，使用 LINQ 时，我们不必学习 XQuery，而是处理 XML 文档。幸运的是，LINQ 为我们提供了一个通用的语法，适用于所有数据源。

LINQ 中有两种基本数据单元；它们是序列，包括实现`IEnumerable<T>`的任何对象，和元素，包括序列中的项目。假设我们有以下名为`intArray`的`int`数组：

```cs
int[] intArray = 
{ 
  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 
  10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 
  20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 
  30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 
  40, 41, 42, 43, 44, 45, 46, 47, 48, 49 
}; 

```

从之前的集合中，我们可以说`intArray`是一个序列，数组的内容，包括从 0 到 49 的数字，是元素。

可以使用称为查询运算符的方法来转换序列。查询运算符接受输入序列，然后生成转换后的序列。当枚举序列时，查询将转换序列。查询至少包括一个输入序列和一个运算符。让我们看一下以下代码，我们可以在`SequencesAndElements.csproj`项目中找到，它将从我们之前的集合`intArray`中查找素数：

```cs
public partial class Program 
{  
  public static void ExtractArray() 
  { 
    IEnumerable<int> extractedData = 
      System.Linq.Enumerable.Where 
      (intArray, i => i.IsPrime()); 
    Console.WriteLine 
      ("Prime Number from 0 - 49 are:"); 
    foreach (int i in extractedData) 
      Console.Write("{0} \t", i); 
    Console.WriteLine(); 
  } 
} 

```

`IsPrime()`扩展方法将有以下实现：

```cs
public static class ExtensionMethods 
{ 
  public static bool IsPrime(this int i) 
  { 
    if ((i % 2) == 0) 
    { 
      return i == 2; 
    } 
    int sqrt = (int)Math.Sqrt(i); 
    for (int t = 3; t <= sqrt; t = t + 2) 
    { 
      if (i % t == 0) 
      { 
        return false; 
      } 
    } 
    return i != 1; 
  } 
} 

```

从我们之前的代码中，我们可以看到我们使用`Where`运算符，它可以在`System.Linq.Enumerable`类中找到，将`intArray`序列转换为`extractedData`序列，如下面的代码片段所示：

```cs
IEnumerable<int> extractedData = 
  System.Linq.Enumerable.Where 
    (intArray, i => i.IsPrime()); 

```

`extractedData`集合现在将包含从`intArray`集合中获得的素数。如果我们运行项目，将在控制台上获得以下输出：

![开始使用 LINQ](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/fn-cs/img/Image00049.jpg)

我们实际上可以以更简单的方式修改我们之前的代码片段，因为所有查询运算符都是扩展方法，可以直接在集合中使用。修改之前的代码片段如下：

```cs
IEnumerable<int> extractedData = 
  intArray.Where(i => i.IsPrime()); 

```

通过修改`Where`运算符的调用，我们将获得完整的实现，如下所示：

```cs
public partial class Program 
{ 
  public static void ExtractArrayWithMethodSyntax() 
  { 
    IEnumerable<int> extractedData = 
       intArray.Where(i => i.IsPrime()); 
    Console.WriteLine("Prime Number from 0 - 49 are:"); 
    foreach (int i in extractedData) 
      Console.Write("{0} \t", i); 
    Console.WriteLine(); 
  } 
} 

```

如果我们运行前面的`ExtractArrayWithMethodSyntax()`方法，将得到与`ExtractArray()`方法完全相同的输出。

# 延迟 LINQ 执行

当我们从集合中查询数据时，LINQ 实现了延迟执行的概念。这意味着查询不会在构造函数中执行，而是在枚举过程中执行。例如，我们使用`Where`运算符从集合中查询数据。实际上，直到我们枚举它时，查询才会被执行。我们可以使用`foreach`操作调用`MoveNext`命令来枚举查询。为了更详细地讨论延迟执行，让我们看一下以下代码，我们可以在`DeferredExecution.csproj`项目中找到：

```cs
public partial class Program 
{ 
  public static void DeferredExecution() 
  { 
    List memberList = new List() 
    { 
      new Member 
      { 
        ID = 1, 
        Name = "Eddie Morgan", 
        Gender = "Male", 
        MemberSince = new DateTime(2016, 2, 10) 
      }, 
      new Member 
      { 
        ID = 2, 
        Name = "Millie Duncan", 
        Gender = "Female", 
        MemberSince = new DateTime(2015, 4, 3) 
      }, 
      new Member 
      { 
        ID = 3, 
        Name = "Thiago Hubbard", 
        Gender = "Male", 
        MemberSince = new DateTime(2014, 1, 8) 
      }, 
      new Member 
      { 
        ID = 4, 
        Name = "Emilia Shaw", 
        Gender = "Female", 
        MemberSince = new DateTime(2015, 11, 15) 
      } 
    }; 
    IEnumerable<Member> memberQuery = 
      from m in memberList 
      where m.MemberSince.Year > 2014 
      orderby m.Name 
      select m; 
      memberList.Add(new Member 
      { 
        ID = 5, 
        Name = "Chloe Day", 
        Gender = "Female", 
        MemberSince = new DateTime(2016, 5, 28) 
      }); 
    foreach (Member m in memberQuery) 
    { 
      Console.WriteLine(m.Name); 
    } 
  } 
} 

```

如前面的`DeferredExecution()`方法的实现所示，我们构造了一个名为`memberList`的`List<Member>`成员列表，其中包含每个加入俱乐部的成员的四个实例。`Member`类本身如下所示：

```cs
public class Member 
{ 
  public int ID { get; set; } 
  public string Name { get; set; } 
  public string Gender { get; set; } 
  public DateTime MemberSince { get; set; } 
} 

```

在构造`memberList`之后，我们从`memberList`中查询数据，其中包括 2014 年后加入的所有成员。在这里，我们可以确认只有四个成员中的三个满足要求。它们是 Eddie Morgan，Millie Duncan 和 Emilia Shaw，当然，因为我们在查询中使用了`orderby m.Name`短语，所以它们是按升序排列的。

在我们有了查询之后，我们向`memberList`添加了一个新成员，然后运行`foreach`操作以枚举查询。接下来会发生什么是，因为大多数查询操作符实现了延迟执行，只有在枚举过程中才会执行，所以在枚举查询后，我们将有四个成员，因为我们添加到`memberList`的最后一个成员满足查询要求。为了搞清楚这一点，让我们看一下在调用`DeferredExecution()`方法后我们在控制台上得到的以下输出：

![延迟执行 LINQ](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/fn-cs/img/Image00050.jpg)

正如您所看到的，`Chloe Day`，作为最后一个加入俱乐部的成员，也包含在查询结果中。这就是延迟执行发挥作用的地方。

几乎所有查询操作符都提供延迟执行，但不包括以下操作符：

+   返回标量值或单个元素，例如`Count`和`First`。

+   转换查询结果，例如`ToList`，`ToArray`，`ToDictionary`和`ToLookup`。它们也被称为转换操作符。

`Count()`和`First()`方法将立即执行，因为它们返回单个对象，所以几乎不可能提供延迟执行以及转换操作符。使用转换操作符，我们可以获得查询结果的缓存副本，并且可以避免由于延迟执行中的重新评估操作而重复该过程。现在，让我们看一下以下代码，我们可以在`NonDeferredExecution.csproj`项目中找到，以演示非延迟执行过程：

```cs
public partial class Program 
{ 
  private static void NonDeferred() 
  { 
    List<int> intList = new List<int> 
    { 
      0,  1,  2,  3,  4,  5,  6,  7,  8,  9 
    }; 
    IEnumerable<int> queryInt = intList.Select(i => i * 2); 
    int queryIntCount = queryInt.Count(); 
    List<int> queryIntCached = queryInt.ToList(); 
    int queryIntCachedCount = queryIntCached.Count(); 
    intList.Clear(); 
    Console.WriteLine( 
      String.Format( 
        "Enumerate queryInt.Count {0}.", queryIntCount)); 
    foreach (int i in queryInt) 
    { 
      Console.WriteLine(i); 
    } 
    Console.WriteLine(String.Format( 
      "Enumerate queryIntCached.Count {0}.",
      queryIntCachedCount)); 
    foreach (int i in queryIntCached) 
    { 
      Console.WriteLine(i); 
    } 
  } 
} 

```

首先，在前面的代码中，我们有一个名为`intList`的`List<int>`整数列表，其中包含从`0`到`9`的数字。然后，我们创建一个名为`queryInt`的查询，以选择`intList`的所有成员并将它们乘以`2`。我们还使用`Count()`方法计算查询数据的总数。由于`queryInt`尚未执行，我们创建了一个名为`queryIntCached`的新查询，它使用`ToList()`转换操作符将`queryInt`转换为`List<int>`。我们还计算了该查询中数据的总数。现在我们有两个查询，`queryInt`和`queryIntCached`。然后我们清除`intList`并枚举这两个查询。以下是它们在控制台上显示的结果：

![延迟执行 LINQ](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/fn-cs/img/Image00051.jpg)

正如您在前面的控制台中所看到的，对`queryInt`的枚举结果没有任何项目。这很明显，因为我们已经移除了所有`intList`项目，所以`queryInt`在`intList`中找不到任何项目。然而，`queryInt`被计为十个项目，因为我们在清除`intList`之前运行了`Count()`方法，并且该方法在构造后立即执行。与`queryInt`相反，当我们枚举`queryIntCached`时，我们有十个项目的数据。这是因为我们调用了`ToList()`转换操作符，并且它也立即执行了。

### 注意

还有一种延迟执行的类型。当我们在`Select`方法之后链`OrderBy`方法时，就会发生这种情况。例如，`Select`方法只会在必须生成元素时检索一个元素，而`OrderBy`方法必须在返回第一个元素之前消耗整个输入序列。因此，当我们在`Select`方法之后链`OrderBy`方法时，执行将被延迟，直到我们检索第一个元素，然后`OrderBy`方法将要求`Select`提供所有元素。

# 在流畅语法和查询表达式语法之间进行选择

从我们之前的讨论中，到目前为止我们发现了两种类型的查询语法。让我们通过区分这两种语法来进一步讨论这个问题。

```cs
IEnumerable<int> queryInt = 
  intList.Select(i => i * 2); 
int queryIntCount = queryInt.Count(); 

```

前面的代码片段是流畅语法类型。我们通过调用 `Enumerable` 类中的扩展方法来调用 `Select` 和 `Count` 运算符。使用流畅语法，我们还可以链接方法，使其接近函数式编程，如下所示：

```cs
IEnumerable<int> queryInt = 
  intList 
    .Select(i => i * 2); 
    .Count(); 

```

我们在 LINQ 中查询数据时可以使用的另一种语法类型是查询表达式语法。我们在上一个主题中讨论延迟执行时应用了这种语法类型。查询表达式语法的代码片段如下：

```cs
IEnumerable<Member> memberQuery = 
  from m in memberList 
  where m.MemberSince.Year > 2014 
  orderby m.Name 
  select m; 

```

事实上，流畅语法和查询表达式语法将执行相同的操作。它们之间的区别只是语法。查询表达式语法中的每个关键字在 `Enumerable` 类中都有其自己的扩展方法。为了证明这一点，我们可以将前面的代码片段重构为以下流畅语法类型：

```cs
IEnumerable<Member> memberQuery = 
  memberList 
  .Where(m => m.MemberSince.Year > 2014) 
  .OrderBy(m => m.Name) 
  .Select(m => m); 

```

实际上，这两种类型的语法将得到完全相同的输出。然而，流畅语法比查询表达式语法更接近函数式方法。

## 理解 LINQ 流畅语法

基本上，LINQ 流畅语法是在 `Enumerable` 类中找到的扩展方法。该方法将扩展任何实现 `IEnumerable<T>` 接口的变量。流畅语法采用 lambda 表达式作为参数，表示将在序列枚举中执行的逻辑。正如我们之前讨论过的，流畅语法实现了方法链，以便在函数式方法中使用。在本章的开头，我们还讨论了扩展方法，可以直接使用其类的静态方法来调用查询运算符，即 `Enumerable` 类。然而，通过直接从其类调用方法，我们无法实现通常在函数式方法中使用的方法链。让我们看一下以下代码，我们可以在 `FluentSyntax.csproj` 项目中找到，以演示通过调用扩展方法而不是传统的 `static` 方法来使用流畅语法的优势：

```cs
public partial class Program 
{ 
  private static void UsingExtensionMethod() 
  { 
    IEnumerable<string> query = names 
      .Where(n => n.Length > 4) 
      .OrderBy(n => n[0]) 
      .Select(n => n.ToUpper()); 
    foreach (string s in query) 
    { 
      Console.WriteLine(s); 
    } 
  } 
} 

```

我们在前面的代码中使用的名称集合如下：

```cs
public partial class Program 
{ 
  static List<string> names = new List<string> 
  { 
    "Howard", "Pat", 
    "Jaclyn", "Kathryn", 
    "Ben", "Aaron", 
    "Stacey", "Levi", 
    "Patrick", "Tara", 
    "Joe", "Ruby", 
    "Bruce", "Cathy", 
    "Jimmy", "Kim", 
    "Kelsey", "Becky", 
    "Scott", "Dick" 
  }; 
} 

```

正如您所看到的，当我们在前面的代码中从集合中查询数据时，我们使用了三个查询运算符。它们是 `Where`、`OrderBy` 和 `Select` 运算符。让我们看一下以下代码片段，以澄清这一点：

```cs
IEnumerable<string> query =  
  names 
  .Where(n => n.Length > 4) 
  .OrderBy(n => n[0]) 
  .Select(n => n.ToUpper()); 

```

根据前面的查询，我们将得到一个字符串集合，其中每个字符串包含超过四个字符。该集合将按其第一个字母的升序排列，并且字符串将以大写字符显示。如果我们运行以下截图中显示的 `UsingExtensionMethod()` 方法，我们将在控制台上看到以下内容：

![理解 LINQ 流畅语法](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/fn-cs/img/Image00052.jpg)

现在，让我们重构前面的查询，使用传统的静态方法。但在我们进行之前，这里是我们在前面的查询中使用的三个方法的签名：

```cs
public static IEnumerable<TSource> Where<TSource>( 
  this IEnumerable<TSource> source, 
  Func<TSource, bool> predicate 
) 

public static IEnumerable<TSource> OrderBy<TSource, TKey>( 
  this IEnumerable<TSource> source, 
  Func<TSource, TKey> keySelector 
) 

public static IEnumerable<TResult> Select<TSource, TResult>( 
  this IEnumerable<TSource> source, 
  Func<TSource, TResult> selector 
) 

```

正如您所看到的，所有三个方法都以 `IEnumerable<TSource>` 作为第一个参数，并且还返回 `IEnumerable<TResult>`。我们可以利用这种相似性，使第一个方法的返回值可以作为第二个方法的参数，第二个方法的返回值可以作为第三个方法的参数，依此类推。

在 `Where()` 方法中，我们使用第二个参数 predicate 来基于它过滤序列。它是一个 `Func<TSource, bool>` 委托，所以我们可以在这里使用 lambda 表达式。在 `OrderBy()` 方法的第二个参数中也可以找到 `Func<TSource, TKey>` 委托，它用作对序列元素进行升序排序的键。它可以由匿名方法提供。最后是 `Select()` 方法，在其中我们使用它的第二个参数 `selector`，将序列中的每个元素投影为新形式。匿名方法也可以作为参数使用。

根据我们在之前的 `UsingExtensionMethod()` 方法中使用的方法的签名，我们可以重构查询如下：

```cs
IEnumerable<string> query = Enumerable.Select(
  Enumerable.OrderBy(Enumerable.Where(names, n => n.Length > 4),
  n => n[0]), n => n.ToUpper());
```

以下是完整的 `UsingStaticMethod()` 方法，这是当我们使用传统的静态方法而不是扩展方法时的重构代码：

```cs
public partial class Program 
{ 
  private static void UsingStaticMethod() 
  { 
    IEnumerable<string> query = 
     Enumerable.Select( 
      Enumerable.OrderBy( 
       Enumerable.Where( 
        names, n => n.Length > 4),  
         n => n[0]), n => n.ToUpper()); 
    foreach (string s in query) 
    { 
      Console.WriteLine(s); 
    } 
  } 
} 

```

通过运行 `UsingStaticMethod()` 方法，我们将在控制台上获得与 `UsingExtensionMethod()` 方法相比完全相同的输出。

## 理解 LINQ 查询表达式语法

LINQ 查询表达式语法是一种简写语法，我们可以使用它执行 LINQ 查询。在查询表达式语法中，.NET Framework 为每个查询操作符提供关键字，但并非所有操作符。通过使用查询语法，我们可以像在数据库中使用 SQL 查询数据一样调用操作符。当我们使用查询表达式语法时，我们的代码将更易读，并且在编写时需要更少的代码。

在流畅语法讨论中，我们创建了一个查询，从包含超过四个字符的字符串列表中提取字符串，按其第一个字母的升序排序，并转换为大写字符。我们可以使用查询表达式语法来执行此操作，如下面的代码所示，我们可以在 `QueryExpressionSyntax.csproj` 项目中找到：

```cs
public partial class Program 
{ 
  private static void InvokingQueryExpression() 
  { 
    IEnumerable<string> query = 
      from n in names 
      where n.Length > 4 
      orderby n[0] 
      select n.ToUpper(); 
    foreach (string s in query) 
    { 
      Console.WriteLine(s); 
    } 
  } 
} 

```

正如你所看到的，我们已经重构了之前的代码，它使用了查询表达式语法的流畅语法。事实上，如果我们运行 `InvokingQueryExpression()` 方法，与 `UsingExtensionMethod()` 方法相比，将显示完全相同的输出。

不幸的是，有几个 LINQ 操作符在查询表达式语法中没有关键字，例如 `distinct` 操作符，因为它不接受 lambda 表达式。在这种情况下，如果我们仍然想使用它，我们必须至少部分使用流畅语法。以下是在查询表达式语法中具有关键字的操作符：

+   `Where`

+   `Select`

+   `SelectMany`

+   `OrderBy`

+   `ThenBy`

+   `OrderByDescending`

+   `ThenByDescending`

+   `GroupBy`

+   `Join`

+   `GroupJoin`

### 提示

实际上，编译器在编译过程中将查询表达式语法转换为流畅语法。虽然查询表达式语法有时更容易阅读，但我们不能使用它执行所有操作；相反，我们必须使用流畅语法，例如我们在 *延迟 LINQ 执行* 主题中讨论的 `count` 操作符。我们在查询表达式语法中编写的内容也可以用流畅语法编写。因此，在使用 LINQ 编码时，特别是在功能方法中，流畅语法是最佳方法。

# 枚举标准查询操作符

在 `System.Linq` 命名空间中包含的 `Enumerable` 类中有 50 多个查询操作符。它们也被称为标准查询操作符。根据操作符的功能，我们可以将它们分为几个操作。在这里，我们将讨论 .NET Framework 提供的所有 LINQ 查询操作符。

## 过滤

过滤是一个操作，它将评估数据的元素，以便只选择满足条件的元素。有六个过滤操作符；它们是 `Where` 、`Take` 、`Skip` 、`TakeWhile` 、`SkipWhile` 和 `Distinct` 。正如我们所知，我们已经在之前的示例代码中讨论了 `Where` 操作符，无论是在流畅语法还是查询表达式语法中，并且知道它将返回满足谓词给定条件的元素子集。由于我们对 `Where` 操作符已经足够清楚，我们可以跳过它，继续使用剩下的五个过滤操作符。

`Take` 操作符返回前 `n` 个元素并丢弃其余的元素。相反，`Skip` 操作符忽略前 `n` 个元素并返回其余的元素。让我们来看一下 `FilteringOperation.csproj` 项目中的以下代码：

```cs
public partial class Program 
{ 
  public static void SimplyTakeAndSkipOperator() 
  { 
    IEnumerable<int> queryTake = 
       intList.Take(10); 
    Console.WriteLine("Take operator"); 
    foreach (int i in queryTake) 
    { 
      Console.Write(String.Format("{0}\t", i)); 
    } 
    Console.WriteLine(); 
    IEnumerable<int> querySkip = intList.Skip(10); 
    Console.WriteLine("Skip operator"); 
    foreach (int i in querySkip) 
    { 
      Console.Write(String.Format("{0}\t", i)); 
    } 
    Console.WriteLine(); 
  } 
} 

```

在上面的代码中，我们有两个查询，`queryTake`应用了`Take`操作符，`querySkip`应用了`Skip`操作符。它们都消耗`intList`，实际上是一个包含以下数据的整数列表：

```cs
public partial class Program 
{ 
static List<int> intList = new List<int> 
  { 
    0,  1,  2,  3,  4, 
    5,  6,  7,  8,  9, 
    10, 11, 12, 13, 14, 
    15, 16, 17, 18, 19 
  }; 
} 

```

如果我们运行前面的`SimplyTakeAndSkipOperator()`方法，将会得到以下输出：

![Filtering](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/fn-cs/img/Image00053.jpg)

前面的`Take`和`Skip`操作符示例是简单的代码，因为它处理的是一个只包含二十个元素的集合。事实上，当我们处理大量集合或者数据库时，`Take`和`Skip`操作符非常有用，可以方便用户访问数据。假设我们有一个包含一百万个整数的集合，我们要找到其中一个元素，它乘以二和七。如果不使用`Take`和`Skip`操作符，将会得到大量结果，如果在控制台上显示，会使控制台显示混乱。让我们看一下下面的代码来证明这一点：

```cs
public partial class Program 
{ 
  public static void NoTakeSkipOperator() 
  { 
    IEnumerable<int> intCollection = 
       Enumerable.Range(1, 1000000); 
    IEnumerable<int> hugeQuery = 
        intCollection 
      .Where(h => h % 2 == 0 && h % 7 == 0); 
    foreach (int x in hugeQuery) 
    { 
      Console.WriteLine(x); 
    } 
  } 
} 

```

正如你在这里所看到的，我们有一个包含大量数据的`hugeQuery`。如果我们运行该方法，需要大约十秒钟来完成所有元素的迭代。如果我们想要获取`hugeQuery`实际包含的元素，我们也可以添加`Count`操作符，即*71428*个元素。

现在，我们可以通过在`foreach`循环周围添加`Take`和`Skip`操作符来修改代码，如下所示：

```cs
public partial class Program 
{ 
  public static void TakeAndSkipOperator() 
  { 
    IEnumerable<int> intCollection = 
       Enumerable.Range(1, 1000000); 
    IEnumerable<int> hugeQuery = 
       intCollection 
         .Where(h => h % 2 == 0 && h % 7 == 0); 
    int pageSize = 10; 
    for (int i = 0; i < hugeQuery.Count()/ pageSize; i++) 
    { 
      IEnumerable<int> paginationQuery =hugeQuery 
        .Skip(i * pageSize) 
        .Take(pageSize); 
      foreach (int x in paginationQuery) 
      { 
        Console.WriteLine(x); 
      } 
      Console.WriteLine( 
         "Press Enter to continue, " + 
           "other key will stop process!"); 
      if (Console.ReadKey().Key != ConsoleKey.Enter) 
        break; 
    } 
  } 
} 

```

在前面的`TakeAndSkipOperator()`方法中，我们在高亮显示的行中添加了一些代码。现在，尽管我们有很多数据，但当我们运行该方法时，输出将会很方便地显示如下：

![Filtering](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/fn-cs/img/Image00054.jpg)

如你所见，整个结果并没有全部显示在控制台上，每次只显示十个整数。用户可以按**Enter**键，如果他们想要继续阅读其余的数据。这通常被称为分页。`Take`和`Skip`操作符已经很好地实现了这一点。

除了讨论`Take`和`Skip`操作符，我们还将讨论过滤操作符中的`TakeWhile`和`SkipWhile`操作符。在`TakeWhile`操作符中，输入集合将被枚举，每个元素将被发送到查询，直到谓词为`false`。相反，在`SkipWhile`中，当输入集合被枚举时，当谓词为`true`时，元素将被发送到查询。现在，让我们看一下下面的代码来演示`TakeWhile`和`SkipWhile`操作符：

```cs
public partial class Program 
{ 
  public static void TakeWhileAndSkipWhileOperators() 
  { 
    int[] intArray = { 10, 4, 27, 53, 2, 96, 48 }; 
    IEnumerable<int> queryTakeWhile = 
       intArray.TakeWhile(n => n < 50); 
    Console.WriteLine("TakeWhile operator"); 
    foreach (int i in queryTakeWhile) 
    { 
      Console.Write(String.Format("{0}\t", i)); 
    } 
    Console.WriteLine(); 
    IEnumerable<int> querySkipWhile = 
       intArray.SkipWhile(n => n < 50); 
    Console.WriteLine("SkipWhile operator"); 
    foreach (int i in querySkipWhile) 
    { 
      Console.Write(String.Format("{0}\t", i)); 
    } 
    Console.WriteLine(); 
  } 
} 

```

当我们运行前面的方法时，将在控制台上得到以下输出：

![Filtering](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/fn-cs/img/Image00055.jpg)

由于在谓词中有`n < 50`，在`TakeWhile`中，枚举将会发出元素，直到达到`53`，而在`SkipWhile`中，当枚举到达`53`时，元素开始被发出。

在这个过滤操作中，我们还有`Distinct`操作符。`Distinct`操作符将返回没有任何重复元素的输入序列。假设我们有以下代码：

```cs
public partial class Program 
{ 
  public static void DistinctOperator() 
  { 
    string words = "TheQuickBrownFoxJumpsOverTheLazyDog"; 
       IEnumerable <char> queryDistinct = words.Distinct(); 
    string distinctWords = ""; 
    foreach (char c in queryDistinct) 
    { 
      distinctWords += c.ToString(); 
    } 
    Console.WriteLine(distinctWords); 
  } 
} 

```

在上面的代码中，我们有一个字符串，我们打算删除该字符串中的所有重复字母。我们使用`Distinct`操作符来获取查询，然后枚举它。结果将如下所示：

![Filtering](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/fn-cs/img/Image00056.jpg)

如你所见，由于使用了`Distinct`操作符，一些字母已经消失了。在这种情况下，没有重复的字母出现。

## 投影

投影是将对象转换为新形式的操作。有两个投影操作符，它们是`Select`和`SelectMany`。使用`Select`操作符，我们可以根据给定的 lambda 表达式转换每个输入元素，而使用`SelectMany`操作符，我们可以转换每个输入元素，然后通过连接它们来将结果序列扁平化为一个序列。

当我们讨论延迟执行 LINQ 时，我们应用了`Select`操作符。以下是使用`Select`操作符的代码片段，我们从延迟执行 LINQ 主题的示例中提取出来的：

```cs
IEnumerable<Member> memberQuery = 
  from m in memberList 
  where m.MemberSince.Year > 2014 
  orderby m.Name 
  select m; 

```

正如你所看到的，我们使用了`Select`操作符，这里是`Select`关键字，因为我们使用了查询表达式语法，来选择所有由`Where`关键字过滤的结果元素。正如我们从`Select`操作符中知道的，对象可以被转换成另一种形式，我们可以使用以下代码将以`Member`类对象类型的元素转换为以`RecentMember`类对象类型的元素：

```cs
IEnumerable<RecentMember> memberQuery = 
  from m in memberList 
  where m.MemberSince.Year > 2014 
  orderby m.Name 
  select new RecentMember{ 
    FirstName = m.Name.GetFirstName(), 
    LastName = m.Name.GetLastName(), 
    Gender = m.Gender, 
    MemberSince = m.MemberSince, 
    Status = "Valid" 
}; 

```

使用前面的代码，我们假设有一个名为`RecentMember`的类，如下所示：

```cs
public class RecentMember 
{ 
  public string FirstName { get; set; } 
  public string LastName { get; set; } 
  public string Gender { get; set; } 
  public DateTime MemberSince { get; set; } 
  public string Status { get; set; } 
} 

```

从前面的代码片段中，我们可以看到我们使用`Select`操作符来转换每个输入元素。我们可以将代码片段插入到以下完整的源代码中：

```cs
public partial class Program 
{ 
  public static void SelectOperator() 
  { 
    List<Member> memberList = new List<Member>() 
    { 
      new Member 
      { 
        ID = 1, 
        Name = "Eddie Morgan", 
        Gender = "Male", 
        MemberSince = new DateTime(2016, 2, 10) 
      }, 
      new Member 
      { 
        ID = 2, 
        Name = "Millie Duncan", 
        Gender = "Female", 
        MemberSince = new DateTime(2015, 4, 3) 
      }, 
      new Member 
      { 
        ID = 3, 
        Name = "Thiago Hubbard", 
        Gender = "Male", 
        MemberSince = new DateTime(2014, 1, 8) 
      }, 
      new Member 
      { 
        ID = 4, 
        Name = "Emilia Shaw", 
        Gender = "Female", 
        MemberSince = new DateTime(2015, 11, 15) 
      } 
    }; 
    IEnumerable<RecentMember> memberQuery = 
      from m in memberList 
      where m.MemberSince.Year > 2014 
      orderby m.Name 
      select new RecentMember{ 
        FirstName = m.Name.GetFirstName(), 
        LastName = m.Name.GetLastName(), 
        Gender = m.Gender, 
        MemberSince = m.MemberSince, 
        Status = "Valid" 
      }; 
    foreach (RecentMember rm in memberQuery) 
    { 
      Console.WriteLine( 
         "First Name  : " + rm.FirstName); 
      Console.WriteLine( 
         "Last Name   : " + rm.LastName); 
      Console.WriteLine( 
         "Gender      : " + rm.Gender); 
      Console.WriteLine 
         ("Member Since: " + rm.MemberSince.ToString("dd/MM/yyyy")); 
      Console.WriteLine( 
         "Status      : " + rm.Status); 
      Console.WriteLine(); 
    } 
  } 
} 

```

由于我们已经使用`foreach`迭代器枚举了查询，并使用`Console.WriteLine()`方法将元素写入控制台，在运行前面的`SelectOperator()`方法后，我们将在控制台上得到以下输出：

![Projection](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/fn-cs/img/Image00057.jpg)

从前面的控制台截图中，我们可以看到我们成功地将`Member`类型的输入元素转换为`RecentMember`类型的输出元素。我们也可以使用流畅语法来产生完全相同的结果，如下面的代码片段所示：

```cs
IEnumerable<RecentMember> memberQuery = 
   memberList 
  .Where(m => m.MemberSince.Year > 2014) 
  .OrderBy(m => m.Name) 
  .Select(m => new RecentMember 
{ 
  FirstName = m.Name.GetFirstName(), 
  LastName = m.Name.GetLastName(), 
  Gender = m.Gender, 
  MemberSince = m.MemberSince, 
  Status = "Valid" 
}); 

```

现在，让我们继续讨论`SelectMany`操作符。使用这个操作符，我们可以选择多个序列，然后将结果展平成一个序列。假设我们有两个集合，我们要选择它们的所有元素；我们可以使用以下代码实现这个目标：

```cs
public partial class Program 
{ 
  public static void SelectManyOperator() 
  { 
    List<string> numberTypes = new List<string>() 
    { 
      "Multiplied by 2", 
      "Multiplied by 3" 
    }; 
    List<int> numbers = new List<int>() 
    { 
      6, 12, 18, 24 
    }; 
    IEnumerable<NumberType> query = 
       numbers.SelectMany( 
          num => numberTypes,  
          (n, t) =>new NumberType 
          { 
            TheNumber = n, 
            TheType = t 
          }); 
    foreach (NumberType nt in query) 
    { 
      Console.WriteLine(String.Format( 
         "Number: {0,2} - Types: {1}", 
           nt.TheNumber, 
             nt.TheType)); 
    } 
  } 
} 

```

正如你所看到的，我们有两个名为`numberTypes`和`numbers`的集合，想要从它们的元素中取出任何可能的组合。结果是以新形式`NumberType`的形式，定义如下：

```cs
public class NumberType 
{ 
  public int TheNumber { get; set; } 
  public string TheType { get; set; } 
} 

```

如果我们运行前面的`SelectManyOperator()`方法，将在控制台上显示以下输出：

![Projection](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/fn-cs/img/Image00058.jpg)

在这段代码中，我们实际上迭代了两个集合，构造了两个集合的组合，因为`SelectMany`操作符的实现如下：

```cs
public static IEnumerable<TResult> SelectMany<TSource, TResult>( 
  this IEnumerable<TSource> source, 
  Func<TSource, IEnumerable<TResult>> selector) 
{ 
  foreach (TSource element in source) 
  foreach (TResult subElement in selector (element)) 
  yield return subElement; 
} 

```

我们还可以应用查询表达式语法来替换前面的流畅语法，使用以下代码片段：

```cs
IEnumerable<NumberType> query = 
  from n in numbers 
  from t in numberTypes 
  select new NumberType 
{ 
  TheNumber = n, 
  TheType = t 
}; 

```

使用查询表达式语法的输出将与流畅语法完全相同。

### 注意

`from`关键字在查询表达式语法中有两个不同的含义。当我们在语法的开头使用关键字时，它将引入原始范围变量和输入序列。当我们在任何位置使用关键字时，它将被转换为`SelectMany`操作符。

## 连接

连接是一种将不具有直接对象模型关系的不同源序列融合成单个输出序列的操作。然而，每个源中的元素都必须共享一个可以进行相等比较的值。在 LINQ 中有两个连接操作符；它们是`Join`和`GroupJoin`。

`Join`操作符使用查找技术来匹配两个序列的元素，然后返回一个扁平的结果集。为了进一步解释这一点，让我们看一下在`Joining.csproj`项目中可以找到的以下代码：

```cs
public partial class Program 
{ 
  public static void JoinOperator() 
  { 
    Course hci = new Course{ 
      Title = "Human Computer Interaction", 
      CreditHours = 3}; 
    Course iis = new Course{ 
      Title = "Information in Society", 
      CreditHours = 2}; 
    Course modr = new Course{ 
      Title = "Management of Digital Records", 
      CreditHours = 3}; 
    Course micd = new Course{ 
      Title = "Moving Image Collection Development", 
      CreditHours = 2}; 
    Student carol = new Student{ 
      Name = "Carol Burks", 
      CourseTaken = modr}; 
    Student river = new Student{ 
      Name = "River Downs", 
      CourseTaken = micd}; 
    Student raylee = new Student{ 
      Name = "Raylee Price", 
      CourseTaken = hci}; 
    Student jordan = new Student{ 
      Name = "Jordan Owen", 
      CourseTaken = modr}; 
    Student denny = new Student{ 
      Name = "Denny Edwards", 
      CourseTaken = hci}; 
    Student hayden = new Student{ 
      Name = "Hayden Winters", 
      CourseTaken = iis}; 
    List<Course> courses = new List<Course>{
      hci, iis, modr, micd};
    List<Student> students = new List<Student>{
      carol, river, raylee, jordan, denny, hayden}; 
    var query = courses.Join( 
      students, 
      course => course, 
      student => student.CourseTaken, 
      (course, student) => 
        new {StudentName = student.Name, 
          CourseTaken = course.Title }); 
    foreach (var item in query) 
    { 
      Console.WriteLine( 
        "{0} - {1}", 
        item.StudentName, 
        item.CourseTaken); 
    } 
  } 
} 

```

前面的代码使用了以下实现的`Student`和`Course`类：

```cs
public class Student 
{ 
  public string Name { get; set; } 
  public Course CourseTaken { get; set; } 
} 
public class Course 
{ 
  public string Title { get; set; } 
  public int CreditHours { get; set; } 
} 

```

如果我们运行前面的`JoinOperator()`方法，我们将在控制台上得到以下输出：

![Joining](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/fn-cs/img/Image00059.jpg)

从前面的代码中，我们可以看到我们有两个序列，它们是`courses`和`students`。我们可以使用`Join`操作符连接这两个序列，然后创建一个匿名类型作为结果。我们也可以使用查询表达式语法来连接这两个序列。以下是我们必须在之前的查询创建中替换的代码片段：

```cs
var query = 
from c in courses 
join s in students on c.Title equals s.CourseTaken.Title 
select new { 
  StudentName = s.Name, 
  CourseTaken = c.Title }; 

```

如果我们再次运行`JoinOperator()`方法，我们将在控制台上得到完全相同的输出。

`GroupJoin`操作符使用与`Join`操作符相同的技术，但返回一个分层结果集。让我们看一下下面解释`GroupJoin`操作符的代码：

```cs
public partial class Program 
{ 
  public static void GroupJoinOperator() 
  { 
    Course hci = new Course{ 
      Title = "Human Computer Interaction", 
      CreditHours = 3}; 

    Course iis = new Course{ 
      Title = "Information in Society", 
      CreditHours = 2}; 

    Course modr = new Course{ 
      Title = "Management of Digital Records", 
      CreditHours = 3}; 

    Course micd = new Course{ 
      Title = "Moving Image Collection Development", 
      CreditHours = 2}; 

    Student carol = new Student{ 
      Name = "Carol Burks", 
      CourseTaken = modr}; 

    Student river = new Student{ 
      Name = "River Downs", 
      CourseTaken = micd}; 

    Student raylee = new Student{ 
      Name = "Raylee Price", 
      CourseTaken = hci}; 

    Student jordan = new Student{ 
      Name = "Jordan Owen", 
      CourseTaken = modr}; 

    Student denny = new Student{ 
      Name = "Denny Edwards", 
      CourseTaken = hci}; 

    Student hayden = new Student{ 
      Name = "Hayden Winters", 
      CourseTaken = iis}; 

    List<Course> courses = new List<Course>{ 
      hci, iis, modr, micd}; 

    List<Student> students = new List<Student>{ 
      carol, river, raylee, jordan, denny, hayden}; 

    var query = courses.GroupJoin( 
      students, 
      course => course, 
      student => student.CourseTaken, 
      (course, studentCollection) => 
      new{ 
        CourseTaken = course.Title, 
        Students =  
        studentCollection 
        .Select(student => student.Name) 
      }); 

      foreach (var item in query) 
      { 
        Console.WriteLine("{0}:", item.CourseTaken); 
        foreach (string stdnt in item.Students) 
        { 
          Console.WriteLine("  {0}", stdnt); 
        } 
      } 
    } 
} 

```

前面的代码与我们之前讨论过的 Join 操作符代码类似。不同之处在于我们创建查询的方式。在`GroupJoin`操作符中，我们将两个序列与一个键合并为另一个序列。让我们调用前面的`GroupJoinOperator()`方法，我们将在控制台上得到以下输出：

![Joining](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/fn-cs/img/Image00060.jpg)

如您在输出中所见，我们对所有选修特定课程的学生进行分组，然后枚举查询以获得结果。

## 排序

排序是一种操作，它将使用默认比较器对输入序列的返回序列进行排序。例如，如果我们有一个字符串类型的序列，那么默认比较器将按字母顺序从 A 到 Z 进行排序。让我们看一下以下代码，可以在`Ordering.csproj`项目中找到：

```cs
public partial class Program 
{ 
  public static void OrderByOperator() 
  { 
    IEnumerable<string> query = 
      nameList.OrderBy(n => n); 

    foreach (string s in query) 
    { 
      Console.WriteLine(s); 
    } 
  } 
} 

```

对于我们必须提供给查询的序列，代码如下：

```cs
public partial class Program 
{ 
  static List<string> nameList = new List<string>() 
  { 
    "Blair", "Lane", "Jessie", "Aiden", 
    "Reggie", "Tanner", "Maddox", "Kerry" 
  }; 
} 

```

如果我们运行前面的`OrderByOperator()`方法，将在控制台上得到以下输出：

![Ordering](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/fn-cs/img/Image00061.jpg)

如您所见，我们使用默认比较器执行了排序操作，因此序列按字母顺序排序。我们还可以使用查询表达式语法来替换以下代码片段：

```cs
IEnumerable<string> query = 
  nameList.OrderBy(n => n); 

```

我们对序列的查询表达式语法如下代码片段所示：

```cs
IEnumerable<string> query = 
  from n in nameList 
  orderby n 
  select n; 

```

我们可以创建自己的比较器作为键选择器，通过每个元素的最后一个字符对序列进行排序；以下是我们可以使用`IComparer<T>`接口来实现这一点的代码。假设我们要对先前的序列进行排序：

```cs
public partial class Program 
{ 
  public static void OrderByOperatorWithComparer() 
  { 
    IEnumerable<string> query = 
      nameList.OrderBy( 
       n => n,  
      new LastCharacterComparer()); 
    foreach (string s in query) 
    { 
      Console.WriteLine(s); 
    } 
  } 
} 

```

我们还创建了一个新类`LastCharacterComparer`，它继承了`IComparer<string>`接口，如下所示：

```cs
public class LastCharacterComparer : IComparer<string> 
{ 
  public int Compare(string x, string y) 
  { 
    return string.Compare( 
     x[x.Length - 1].ToString(), 
      y[y.Length - 1].ToString()); 
  } 
} 

```

当我们运行前面的`OrderByOperatorWithComparer()`方法时，将在控制台上得到以下输出：

![Ordering](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/fn-cs/img/Image00062.jpg)

如您所见，我们现在有一个有序的序列，但排序键是每个元素的最后一个字符。这是通过我们自定义的比较器实现的。不幸的是，自定义比较器只能在流畅语法中使用。换句话说，我们不能在查询表达式方法中使用它。

当我们对序列进行排序时，可以有多个比较器作为条件。在调用`OrderBy`方法后，我们可以使用`ThenBy`扩展方法来进行第二个条件的排序。让我们看一下以下代码来演示这一点：

```cs
public partial class Program 
{ 
  public static void OrderByThenByOperator() 
  { 
    IEnumerable<string> query = nameList 
      .OrderBy(n => n.Length) 
      .ThenBy(n => n); 
    foreach (string s in query) 
    { 
      Console.WriteLine(s); 
    } 
  } 
} 

```

从前面的代码中，我们按每个元素的长度对序列进行排序，然后按字母顺序对结果进行排序。如果我们调用`OrderByThenByOperator()`方法，将得到以下输出：

![Ordering](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/fn-cs/img/Image00063.jpg)

当我们需要使用两个条件对序列进行排序时，也可以使用查询表达式语法，如下面的代码片段所示：

```cs
IEnumerable<string> query = 
  from n in nameList 
  orderby n.Length, n 
  select n; 

```

如果我们在用查询表达式语法替换查询操作后再次运行`OrderByThenByOperator()`方法，我们将得到与使用流畅语法时相同的输出。然而，在查询表达式语法中没有`ThenBy`关键字。我们只需要用逗号分隔条件。

我们也可以在使用`ThenBy`方法时使用自定义比较器。让我们看一下以下代码来尝试这个：

```cs
public partial class Program 
{ 
  public static void OrderByThenByOperatorWithComparer() 
  { 
    IEnumerable<string> query = nameList 
      .OrderBy(n => n.Length) 
      .ThenBy(n => n, new LastCharacterComparer()); 
    foreach (string s in query) 
    { 
      Console.WriteLine(s); 
    } 
  } 
} 

```

在这段代码中，我们使用了与`OrderByOperatorWithComparer()`方法中相同的`LastCharacterComparer`类。如果我们调用`OrderByThenByOperatorWithComparer()`方法，将在控制台上得到以下输出：

![Ordering](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/fn-cs/img/Image00064.jpg)

除了升序排序，我们还有降序排序。在流畅语法中，我们可以简单地使用`OrderByDescending()`和`ThenByDescending()`方法。在代码中的使用方式与按升序排序的代码完全相同。然而，在查询表达式语法中，我们有 descending 关键字来实现这个目标。我们在`orderby`关键字中定义条件后，使用这个关键字，如下面的代码所示：

```cs
public partial class Program 
{ 
  public static void OrderByDescendingOperator() 
  { 
    IEnumerable<string> query = 
      from n in nameList 
      orderby n descending 
      select n; 
    foreach (string s in query) 
    { 
      Console.WriteLine(s); 
    } 
  } 
} 

```

如您所见，代码中也有一个 descending 关键字。实际上，我们可以用 ascending 关键字替换 descending 关键字，以按升序对序列进行排序。然而，在 LINQ 中，升序排序是默认排序，因此可以省略 ascending 关键字。如果运行代码并调用`OrderByDescendingOperator()`方法，将得到以下输出：

![排序](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/fn-cs/img/Image00065.jpg)

## 分组

分组是一种操作，将生成一系列`IGrouping<TKey, TElement>`对象，这些对象根据`TKey`键值进行分组。例如，我们将按照它们文件名的第一个字母，将一个目录中的路径地址文件序列进行分组。以下代码可以在`Grouping.csproj`项目文件中找到，并将搜索`G:\packages`中的所有文件，这是 Visual Studio 2015 Community Edition 的安装文件。您可以根据计算机上的驱动器号和文件夹名称调整驱动器号和文件夹名称。

```cs
public partial class Program 
{ 
  public static void GroupingByFileNameExtension() 
  { 
    IEnumerable<string> fileList =  
      Directory.EnumerateFiles( 
        @"G:\packages", "*.*",  
        SearchOption.AllDirectories); 
    IEnumerable<IGrouping<string, string>> query = 
      fileList.GroupBy(f => 
      Path.GetFileName(f)[0].ToString()); 
    foreach (IGrouping<string, string> g in query) 
    { 
      Console.WriteLine(); 
      Console.WriteLine( 
         "File start with the letter: " +  
           g.Key); 
      foreach (string filename in g) 
      Console.WriteLine( 
         "..." + Path.GetFileName(filename)); 
     } 
  } 
} 

```

前面的代码将在`G:\packages`文件夹中（包括所有子目录）找到所有文件，然后根据它们文件名的第一个字母进行分组。如您所见，当我们使用`foreach`循环枚举查询时，我们有`g.Key`，它是用于对字符串列表进行分组的键选择器。如果运行`GroupingByFileNameExtension()`方法，将在控制台上得到以下输出：

![分组](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/fn-cs/img/Image00066.jpg)

`GroupBy`扩展方法还有一个子句，可以在查询表达式语法中使用。我们可以使用的子句是`group`和`by`。以下代码片段可以替换我们先前代码中的查询：

```cs
IEnumerable<IGrouping<string, string>> query = 
  from f in fileList 
  group f by Path.GetFileName(f)[0].ToString(); 

```

我们仍然会得到与流畅语法输出相同的输出，尽管我们使用查询表达式语法替换了查询。如您所见，LINQ 中的分组操作只对序列进行分组，而不进行排序。我们可以使用 LINQ 提供的`OrderBy`操作符对结果进行排序。

在前面的查询表达式语法中，我们看到由于 group 子句也会结束查询，因此我们不需要再次使用 select 子句。然而，当使用 group 子句并添加查询继续子句时，我们仍然需要 select 子句。现在让我们看一下以下代码，它应用了查询继续子句来对序列进行排序：

```cs
public partial class Program 
{ 
  public static void GroupingByInto() 
  { 
    IEnumerable<string> fileList = 
      Directory.EnumerateFiles( 
        @"G:\packages", "*.*", 
        SearchOption.AllDirectories); 
    IEnumerable<IGrouping<string, string>> query = 
      from f in fileList 
      group f  
        by Path.GetFileName(f)[0].ToString() 
        into g 
      orderby g.Key 
      select g; 
    foreach (IGrouping<string, string> g in query) 
    { 
      Console.WriteLine( 
        "File start with the letter: " + g.Key); 
      //foreach (string filename in g) 
      Console.WriteLine(           "..." + Path.GetFileName(filename)); 
    } 
  } 
} 

```

如前面的代码所示，我们通过添加查询继续子句和`orderby`操作符来修改查询，以对序列结果进行排序。我们使用的查询继续子句是`into`关键字。使用`into`关键字，我们存储分组结果，然后再次操作分组。如果运行前面的代码，将在控制台上得到以下输出：

![分组](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/fn-cs/img/Image00067.jpg)

我们故意删除了每个组的元素，因为我们现在要检查的是键本身。现在我们可以看到键是按升序排列的。这是因为我们首先存储了分组的结果，然后按升序对键进行排序。

## 集合操作

集合操作是一种基于相同或不同集合中等价元素的存在或不存在而返回结果集的操作。LINQ 提供了四种集合操作符，它们是`Concat`，`Union`，`Intersect`和`Except`。对于这四种集合操作符，都没有查询表达式关键字。

让我们从`Concat`和`Union`开始。使用`Concat`运算符，我们将得到第一个序列的所有元素，然后是第二个序列的所有元素。`Union`使用`Concat`运算符执行此操作，但对于重复的元素只返回一个元素。以下代码在`SetOperation.csproj`项目中可以找到，演示了`Concat`和`Union`之间的区别：

```cs
public partial class Program 
{ 
  public static void ConcatUnionOperator() 
  { 
    IEnumerable<int> concat = sequence1.Concat(sequence2); 
    IEnumerable<int> union = sequence1.Union(sequence2); 
    Console.WriteLine("Concat"); 
    foreach (int i in concat) 
    { 
      Console.Write(".." + i); 
    } 
    Console.WriteLine(); 
    Console.WriteLine(); 
    Console.WriteLine("Union"); 
    foreach (int i in union) 
    { 
      Console.Write(".." + i); 
    } 
    Console.WriteLine(); 
    Console.WriteLine(); 
  } 
} 

```

我们有两个序列如下：

```cs
public partial class Program 
{ 
  static int[] sequence1 = { 1, 2, 3, 4, 5, 6 }; 
  static int[] sequence2 = { 3, 4, 5, 6, 7, 8 }; 
} 

```

我们之前的代码尝试使用`Concat`和`Union`运算符。根据我们的讨论，如果我们运行`ConcatUnionOperator()`方法，将得到以下输出：

![集合操作](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/fn-cs/img/Image00068.jpg)

`Intersect`和`Except`也是集合运算符。`Intersect`返回两个输入序列中都存在的元素。`Except`返回第一个输入序列中不在第二个序列中的元素。以下代码解释了`Intersect`和`Except`之间的区别：

```cs
public partial class Program 
{ 
  public static void IntersectExceptOperator() 
  { 
    IEnumerable<int> intersect = sequence1.Intersect(sequence2); 
    IEnumerable<int> except1 = sequence1.Except(sequence2); 
    IEnumerable<int> except2 = sequence2.Except(sequence1); 
    Console.WriteLine("Intersect of Sequence"); 
    foreach (int i in intersect) 
    { 
      Console.Write(".." + i); 
    } 
    Console.WriteLine(); 
    Console.WriteLine(); 
    Console.WriteLine("Except1"); 
    foreach (int i in except1) 
    { 
      Console.Write(".." + i); 
    } 
    Console.WriteLine(); 
    Console.WriteLine(); 
    Console.WriteLine("Except2"); 
    foreach (int i in except2) 
    { 
      Console.Write(".." + i); 
    } 
    Console.WriteLine(); 
    Console.WriteLine(); 
  } 
} 

```

如果我们调用`IntersectExceptOperator()`方法，将在控制台屏幕上显示以下输出：

![集合操作](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/fn-cs/img/Image00069.jpg)

我们将之前在`ConcatUnionOperator()`方法中使用的两个序列作为输入。从上述控制台截图中可以看出，在`Intersect`操作中，只返回重复的元素。在`Except`操作中，只返回唯一的元素。

## 转换方法

转换方法的主要作用是将一种类型的集合转换为其他类型的集合。在这里，我们将讨论 LINQ 提供的转换方法；它们是`OfType`、`Cast`、`ToArray`、`ToList`、`ToDictionary`和`ToLookup`。

`OfType`和`Cast`方法具有类似的功能；它们将`IEnumerable`转换为`IEnumerable<T>`。不同之处在于，`OfType`将丢弃错误类型的元素（如果有的话），而`Cast`将在存在错误类型元素时抛出异常。让我们来看一下以下代码，在`ConversionMethods.csproj`项目中可以找到：

```cs
public partial class Program 
{ 
  public static void OfTypeCastSimple() 
  { 
    ArrayList arrayList = new ArrayList(); 
    arrayList.AddRange(new int[] { 1, 2, 3, 4, 5 }); 

    IEnumerable<int> sequenceOfType = arrayList.OfType<int>(); 
    IEnumerable<int> sequenceCast = arrayList.Cast<int>(); 

    Console.WriteLine( 
      "OfType of arrayList"); 
    foreach (int i in sequenceOfType) 
    { 
      Console.Write(".." + i); 
    } 
    Console.WriteLine(); 
    Console.WriteLine(); 

    Console.WriteLine( 
      "Cast of arrayList"); 
    foreach (int i in sequenceCast) 
    { 
      Console.Write(".." + i); 
    } 
    Console.WriteLine(); 
    Console.WriteLine(); 
  } 
} 

```

上述代码是使用`OfType`和`Cast`转换的一个简单示例。我们有一个只包含`int`元素的数组。实际上，它们可以很容易地转换。如果我们运行`OfTypeCastSimple()`方法，将得到以下输出：

![转换方法](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/fn-cs/img/Image00070.jpg)

### 注意

在.NET Core 中，`ArrayList`的定义位于`System.Collections.NonGeneric.dll`中。因此，我们必须在[`www.nuget.org/packages/System.Collections.NonGeneric/`](https://www.nuget.org/packages/System.Collections.NonGeneric/)上下载 NuGet 包。

现在让我们向上述代码添加几行代码。代码现在将如下所示：

```cs
public partial class Program 
{ 
  public static void OfTypeCastComplex() 
  { 
    ArrayList arrayList = new ArrayList(); 
    arrayList.AddRange( 
      new int[] { 1, 2, 3, 4, 5 }); 

    arrayList.AddRange( 
       new string[] {"Cooper", "Shawna", "Max"}); 
    IEnumerable<int> sequenceOfType = 
       arrayList.OfType<int>(); 
    IEnumerable<int> sequenceCast = 
       arrayList.Cast<int>(); 

    Console.WriteLine( 
      "OfType of arrayList"); 
    foreach (int i in sequenceOfType) 
    { 
      Console.Write(".." + i); 
    } 
    Console.WriteLine(); 
    Console.WriteLine(); 

    Console.WriteLine( 
       "Cast of arrayList"); 
    foreach (int i in sequenceCast) 
    { 
      Console.Write(".." + i); 
    } 
    Console.WriteLine(); 
    Console.WriteLine(); 
  } 
} 

```

从上述代码中，我们可以看到，我们将方法名称更改为`OfTypeCastComplex`，并插入了将字符串元素添加到`arrayList`的代码。如果我们运行该方法，`OfType`转换将成功运行并仅返回`int`元素，而`Cast`转换将抛出异常，因为输入序列中有一些字符串元素。

其他的转换方法包括`ToArray()`和`ToList()`。它们之间的区别在于，`ToArray()`将序列转换为数组，而`ToList()`将转换为通用列表。此外，还有`ToDictionary()`和`ToLookup()`方法可用于转换。`ToDictionary()`将根据指定的键选择器函数从序列中创建`Dictionary<TKey, TValue>`，而`ToLookup()`将根据指定的键选择器和元素选择器函数从序列中创建`Lookup<TKey, TElement>`。

## 元素操作

元素操作是根据它们的索引或使用谓词从序列中提取单个元素的操作。LINQ 中存在几个元素运算符；它们是`First`，`FirstOrDefault`，`Last`，`Single`，`SingleOrDefault`，`ElementAt`和`DefaultIfEmpty`。让我们使用示例代码来了解所有这些元素运算符的功能。

以下是演示元素运算符的代码，我们可以在`ElementOperation.csproj`项目中找到：

```cs
public partial class Program 
{ 
  public static void FirstLastOperator() 
  { 
    Console.WriteLine( 
      "First Operator: {0}", 
      numbers.First()); 
    Console.WriteLine( 
      "First Operator with predicate: {0}", 
      numbers.First(n => n % 3 == 0)); 
    Console.WriteLine( 
      "Last Operator: {0}", 
      numbers.Last()); 
    Console.WriteLine( 
      "Last Operator with predicate: {0}", 
      numbers.Last(n => n % 4 == 0)); 
  } 
} 

```

前面的代码演示了`First`和`Last`运算符的使用。数字数组如下：

```cs
public partial class Program 
{ 
  public static int[] numbers = { 
    1, 2, 3, 
    4, 5, 6, 
    7, 8, 9 
  }; 
} 

```

在我们进一步进行之前，让我们花一点时间看一下如果运行`FirstLastOperator()`方法，控制台上的以下输出：

![元素操作](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/fn-cs/img/Image00071.jpg)

从输出中，我们可以发现`First`运算符将返回序列的第一个元素，而`Last`运算符将返回最后一个元素。我们还可以使用 lambda 表达式来过滤序列的`First`和`Last`运算符。在前面的示例中，我们过滤了只能被四整除的数字序列。

不幸的是，`First`和`Last`运算符不能返回空值；相反，它们会抛出异常。让我们检查以下代码，关于使用`First`运算符，它将返回一个空序列：

```cs
public partial class Program 
{ 
  public static void FirstOrDefaultOperator() 
  { 
    Console.WriteLine( 
      "First Operator with predicate: {0}", 
      numbers.First(n => n % 10 == 0)); 
    Console.WriteLine( 
      "First Operator with predicate: {0}", 
      numbers.FirstOrDefault(n => n % 10 == 0)); 
  } 
} 

```

如果我们取消注释前面代码中的所有注释代码行，由于没有可以被`10`整除的数字，该方法将抛出异常。为了解决这个问题，我们可以使用`FirstOrDefault`运算符，它将返回默认值，因为数字是整数序列。因此，它将返回整数的默认值，即`0`。

我们还有`Single`和`SingleOrDefault`作为元素运算符，我们可以看一下它们在以下代码中的使用：

```cs
public partial class Program 
{ 
  public static void SingleOperator() 
  { 
    Console.WriteLine( 
      "Single Operator for number can be divided by 7: {0}", 
      numbers.Single(n => n % 7 == 0)); 
    Console.WriteLine( 
      "Single Operator for number can be divided by 2: {0}", 
      numbers.Single(n => n % 2 == 0)); 

    Console.WriteLine( 
      "SingleOrDefault Operator: {0}", 
      numbers.SingleOrDefault(n => n % 10 == 0)); 

    Console.WriteLine( 
      "SingleOrDefault Operator: {0}", 
      numbers.SingleOrDefault(n => n % 3 == 0)); 
  } 
} 

```

如果我们运行前面的代码，由于以下代码片段，将会抛出异常：

```cs
Console.WriteLine( 
  "Single Operator for number can be divided by 2: {0}", 
  numbers.Single(n => n % 2 == 0)); 

```

此外，以下代码片段会导致错误：

```cs
Console.WriteLine( 
  "SingleOrDefault Operator: {0}", 
  numbers.SingleOrDefault(n => n % 3 == 0)); 

```

错误发生是因为`Single`运算符只能有一个匹配的元素。在第一个代码片段中，我们得到了`2`，`4`，`6`和`8`作为结果。在第二个代码片段中，我们得到了`3`，`6`和`9`作为结果。

`Element`操作还有`ElementAt`和`ElementAtOrDefault`运算符，用于从序列中获取第 n 个元素。让我们看一下以下代码，演示这些运算符的使用：

```cs
public partial class Program 
{ 
  public static void ElementAtOperator() 
  { 
    Console.WriteLine( 
      "ElementAt Operator: {0}", 
      numbers.ElementAt(5)); 

    //Console.WriteLine( 
      //"ElementAt Operator: {0}", 
      //numbers.ElementAt(11)); 

    Console.WriteLine( 
      "ElementAtOrDefault Operator: {0}", 
      numbers.ElementAtOrDefault(11)); 
  } 
} 

```

与`First`和`Last`运算符一样，`ElementAt`也必须返回值。在前面的代码中，注释的代码行将抛出异常，因为在索引`11`中没有元素。但是，我们可以使用`ElementAtOrDefault`来解决这个问题，然后注释的行将返回`int`的默认值。

元素操作中的最后一个是`DefaultIfEmpty`运算符，如果在输入序列中找不到元素，它将返回序列中的默认值。以下代码将演示`DefaultIfEmpty`运算符：

```cs
public partial class Program 
{ 
  public static void DefaultIfEmptyOperator() 
  { 
    List<int> numbers = new List<int>(); 

    //Console.WriteLine( 
      //"DefaultIfEmpty Operator: {0}", 
      //numbers.DefaultIfEmpty()); 

    foreach (int number in numbers.DefaultIfEmpty()) 
    { 
      Console.WriteLine( 
        "DefaultIfEmpty Operator: {0}", number); 
    } 
  } 
} 

```

由于`DefaultIfEmpty`运算符的返回值是`IEnumerable<T>`，我们必须对其进行枚举，即使它只包含一个元素。正如您在前面的代码中所看到的，我们注释了对 numbers 变量的直接访问，因为它将返回变量的类型，而不是变量的值。相反，我们必须枚举 numbers 查询，以获取存储在`IEnumerable<T>`变量中的唯一值。

# 总结

LINQ 使我们查询集合的任务变得更容易，因为我们不需要学习太多语法来访问不同类型的集合。它实现了延迟执行的概念，这意味着查询不会在构造函数中执行，而是在枚举过程中执行。几乎所有查询运算符都提供了延迟执行的概念；但是，对于执行以下操作的运算符，存在例外情况：

返回标量值或单个元素，例如`Count`和`First`。

将查询的结果转换为`ToList`，`ToArray`，`ToDictionary`和`ToLookup`。它们也被称为转换操作符。

换句话说，返回序列的方法实现了延迟执行，例如`Select`方法`(IEnumerable<X>-> Select -> IEnumerable<Y>)`，而返回单个对象的方法不实现延迟执行，例如`First`方法`(IEnumerable<X>-> First -> Y)`。

LINQ 有两种查询语法；它们是流畅语法和查询表达式语法。前者采用 lambda 表达式作为参数，表示将在序列枚举中执行的逻辑。后者是一种简写语法，我们可以使用它来执行 LINQ 查询。在查询表达式语法中，.NET Framework 为每个查询操作符提供关键字，但并非所有操作符。当我们使用查询表达式语法时，我们的代码将更易读，编码量也会减少。然而，流畅语法和查询语法都会做同样的事情。它们之间的区别只在于语法。查询表达式语法中的每个关键字都在`Enumerable`类中有自己的扩展方法。

通过理解 LINQ，我们现在已经有足够的知识来创建函数式编程。在下一章中，我们将讨论异步编程，以增强代码的响应性，从而构建用户友好的应用程序。
