# C# 编程学习手册（三）

> 原文：[`zh.annas-archive.org/md5/43CC9F8096F66361F01960142D9E6C0F`](https://zh.annas-archive.org/md5/43CC9F8096F66361F01960142D9E6C0F)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：泛型

在上一章中，我们学习了 C#中的面向对象编程。在本章中，我们将探讨泛型的概念。泛型允许我们以一种类型安全的环境中使用不同的数据类型创建类、结构、接口、方法和委托。泛型是作为 C# 2.0 版本的一部分添加的。它促进了代码的可重用性和可扩展性，是 C#最强大的特性之一。

在本章中，我们将学习以下概念：

+   泛型类和泛型继承

+   泛型接口和变体泛型接口

+   泛型结构

+   泛型方法

+   类型约束

通过本章结束时，您将具备编写泛型类型、方法和变体泛型接口以及使用类型约束所需的技能。

# 理解泛型

简而言之，泛型是用其他类型参数化的类型。正如我们之前提到的，我们可以创建一个类、结构、接口、方法或委托，它们接受一个或多个数据类型作为参数。这些参数被称为**类型参数**，充当编译时传递的实际数据类型的*占位符*。

例如，我们可以创建一个模拟列表的类，它是相同类型元素的可变长度序列。我们可以创建一个泛型类，它具有指定其元素实际类型的类型参数。然后，当我们实例化类时，我们将在编译时指定实际类型。

使用泛型的优点包括以下内容：

+   **泛型提供了可重用性**：我们可以创建代码的单个版本，并将其用于不同的数据类型。

+   **泛型提倡类型安全**：在使用泛型时，我们不需要执行显式类型转换。类型转换由编译器处理。

+   将`object`类型转换为引用类型是耗时的。因此，通过避免这些操作，它们有助于提高执行时间。

泛型类型和方法可以受限，以便只有满足要求的类型可以用作类型参数。关于实际类型的信息用于实例化可以在运行时使用反射获得的泛型类型。

泛型最常见的用途是创建集合或包装类。集合将是下一章的主题。

# 泛型类型

引用类型和值类型都可以是泛型的。我们已经在本书的早期看到了泛型类型的例子，比如`Nullable<T>`和`List<T>`。

在本节中，我们将学习如何创建泛型类、结构和接口。

## 泛型类

创建泛型类与创建非泛型类没有区别。唯一不同的是类型参数列表及其在类中作为实际类型的占位符的使用。让我们看一个泛型类的例子：

```cs
public class GenericDemo<T>
{
    public T Value { get; private set; }
    public GenericDemo(T value)
    {
        Value = value;
    }
    public override string ToString() => $"{typeof(T)} : {Value}";
}
```

在这里，我们定义了一个泛型类`GenericDemo`，它接受一个类型参数`T`。我们定义了一个名为`Value`的`T`类型属性，并在类构造函数中对其进行了初始化。构造函数接受`T`类型的参数。重写的方法`ToString()`将返回一个包含属性类型和值的字符串。

要实例化这个泛型类的对象，我们将按以下步骤进行：

```cs
var obj1 = new GenericDemo<int>(10);
var obj2 = new GenericDemo<string>("Hello World");
```

在这个例子中，我们在创建泛型类`GenericDemo<T>`的对象时为类型参数指定了数据类型。`obj1`和`obj2`都是相同泛型类型的实例，但它们的类型参数不同：一个是`int`，另一个是`string`。因此，它们彼此不兼容。这意味着如果我们尝试将一个对象分配给另一个对象，将导致编译时错误。

我们可以使用反射来获取关于这些对象类型和它们的通用类型参数的信息（我们将在第十一章“反射和动态编程”中进行讨论），如下面的示例所示：

```cs
var t1 = obj1.GetType();
Console.WriteLine(t1.Name);
Console.WriteLine(t1.GetGenericArguments()
                    .FirstOrDefault().Name);
var t2 = obj2.GetType();
Console.WriteLine(t2.Name);
Console.WriteLine(t2.GetGenericArguments()
                    .FirstOrDefault().Name);
Console.WriteLine(obj1);
Console.WriteLine(obj2);
```

执行后，我们将看到以下输出：

![图 6.1 - 显示类型反射内容的控制台截图](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-prog/img/Figure_6.1_B12346.jpg)

图 6.1 - 显示类型反射内容的控制台截图

我们可以为泛型类型声明多个类型参数。在这种情况下，我们需要将所有类型参数指定为角括号内的逗号分隔值。以下是一个示例：

```cs
class Pair<T, U>
{
    public T Item1 { get; private set; }
    public U Item2 { get; private set; }
    public Pair(T item1, U item2)
    {
        Item1 = item1;
        Item2 = item2;
    }
}
var p1 = new Pair<int, int>(1, 2);
var p2 = new Pair<int, double>(1, 42.99);
var p3 = new Pair<string, bool>("true", true);
```

在这里，`Pair<T, U>`是一个需要两个类型参数的类。我们使用不同类型的组合来实例化对象`p1`、`p2`和`p3`。

这个类实际上与.NET 类`KeyValueType<TKey`,`TValue>`非常相似，它来自`System.Collections.Generic`命名空间。实际上，框架提供了许多泛型类。您应该在可能的情况下使用现有类型，而不是定义自己的类型。

## 泛型类的继承

泛型类可以作为*基类*或*派生类*。当从泛型类派生时，子类必须指定基类所需的类型参数。这些类型参数可以是实际类型，也可以是派生类的类型参数，即泛型类。

让我们通过这里展示的示例来理解泛型类的继承是如何工作的：

```cs
public abstract class Shape<T>
{
    public abstract T Area { get; }
}
```

我们定义了一个泛型抽象类`Shape`，其中包含一个表示形状面积的单个抽象属性`Area`。该属性的类型也是`T`。考虑这里的类定义：

```cs
public class Square : Shape<int>
{
    public int Length { get; set; }
    public Square(int length)
    {
        Length = length;
    }
    public override int Area => Length * Length;
}
```

在这里，我们定义了一个名为`Square`的类，它继承自泛型抽象类`Shape`。我们使用`int`类型作为类型参数。我们为`Square`类定义了一个名为`Length`的属性，并在构造函数中对其进行了初始化。我们重写了`Area`属性以计算正方形的面积。现在，考虑下面的另一个类定义：

```cs
public class Circle : Shape<double>
{
    public double Radius { get; set; }
    public Circle(double radius)
    {
        Radius = radius;
    }
    public override double Area => Math.PI * Radius * Radius;
}
```

`Circle`类也继承自泛型抽象类`Shape<T>`。父类`Shape`的类型参数现在指定为`double`。定义了`Radius`属性来存储圆的半径。我们再次重写了`Area`属性以计算圆的面积。我们可以如下使用这些派生类：

```cs
Square objSquare = new Square(10);
Console.WriteLine($"The area of square is {objSquare.Area}");
Circle objCircle = new Circle(7.5);
Console.WriteLine($"The area of circle is {objCircle.Area}");
```

我们创建`Square`和`Circle`的实例，并将每个形状的面积打印到控制台上。执行后，我们将看到以下输出：

![图 6.2 - 正方形和圆的面积显示在控制台上](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-prog/img/Figure_6.2_B12346.jpg)

图 6.2 - 正方形和圆的面积显示在控制台上

重要的是要注意，尽管`Square`和`Circle`都是从`Shape<T>`派生出来的，但这些类型不能被多态地对待。一个是`Shape<int>`，另一个是`Shape<double>`。因此，`Square`和`Circle`的实例不能放在同质容器中。唯一可能的解决方案是使用`object`类型来保存对这些实例的引用，然后执行类型转换。

在这个例子中，`Shape<T>`是一个泛型类型。`Shape<int>`是从`Shape<T>`构造出来的类型，通过用`int`替换类型参数`T`。这样的类型被称为**构造类型**。这也是一个*封闭构造类型*，因为所有类型参数都已被替换。非泛型类型都是*封闭类型*。泛型类型是*开放类型*。构造泛型类型可以是开放的或封闭的。开放构造类型是具有未被替换的类型参数的类型。封闭构造类型是任何不是开放的类型。

创建通用类型时另一个重要的事情是，一些运算符，比如算术运算符，不能与类型参数的对象一起使用。让我们看下面的代码来举例说明这种情况：

```cs
public class Square<T> : Shape<T>
{
    public T Length { get; set; }
    public Square(T length)
    {
        Length = length;
    }
    /* ERROR: Operator '*' cannot be applied to operands 
    of type 'T' and 'T' */
    public override T Area => Length * Length;
}
```

`Square`类型现在是一个通用类型。类型参数`T`用于基类的类型参数以及`Length`属性。然而，在计算面积时，使用`*`运算符会产生编译错误。这是因为编译器不知道`T`将使用什么具体类型，以及它们是否已重载`*`运算符。为了确保在任何情况下都不会发生无效实例化，编译器会生成错误。

可以确保只有符合预定义约束的类型在编译时用于实例化通用类型或调用通用方法。这些被称为*类型约束*，将在本章的*类型参数约束*部分中讨论。

现在我们已经看到如何创建和使用通用类，让我们看看如何使用通用接口。

## 通用接口

在前面的例子中，通用类`Shape<T>`除了一个抽象属性之外什么也没有。这不是一个好的类候选，它应该是一个接口。通用接口与非通用接口的区别与通用类与非通用类的区别相同。以下是一个通用接口的例子：

```cs
public interface IShape<T>
{
    public T Area { get; }
}
```

类型参数的指定方式与类或结构相同。这个接口可以这样实现：

```cs
public class Square : IShape<int>
{
    public int Length { get; set; }
    public Square(int length)
    {
        Length = length;
    }
    public int Area => Length * Length;
}
public class Circle : IShape<double>
{
    public double Radius { get; set; }
    public Circle(double radius)
    {
        Radius = radius;
    }
    public double Area => Math.PI * Radius * Radius;
}
```

`Square`和`Circle`类的实现与前一节中所见的略有不同。

具体类，比如这里的`Square`和`Circle`，可以实现封闭构造的接口，比如`IShape<int>`或`IShape<double>`。如果类参数列表提供了接口所需的所有类型参数，通用类也可以实现通用或封闭构造的接口。另一方面，通用接口可以继承非通用接口；然而，通用类必须是逆变的。

通用接口的变异将在下一节中讨论。

## 变异通用接口

可以将通用接口中的类型参数声明为*协变*或*逆变*：

+   *协变*类型参数用`out`关键字声明，允许接口方法具有比指定类型参数更多派生的返回类型。

+   *逆变*类型参数用`in`关键字声明，允许接口方法具有比指定类型参数更少派生的参数。

具有协变或逆变类型参数的通用接口称为**变异通用接口**。变异只支持引用类型。

为了理解协变是如何工作的，让我们看看`System.IEnumerable<T>`通用接口。这是一个变异接口，因为它的类型参数声明为协变。接口定义如下：

```cs
public interface IEnumerable
{
    IEnumerator GetEnumerator();
}
public interface IEnumerable<out T> : IEnumerable
{
    IEnumerator<T> GetEnumerator();
}
```

实现`IEnumerable<T>`（和其他接口）的类是`List<T>`。因为`T`是协变的，我们可以编写以下代码：

```cs
IEnumerable<string> names = 
   new List<string> { "Marius", "Ankit", "Raffaele" };
IEnumerable<object> objects = names;
```

在这个例子中，`names`是`IEnumerable<string>`，`objects`是`IEnumerable<object>`。前者不派生自后者，但`string`派生自`object`，并且因为`T`是协变的，我们可以将`names`赋值给`objects`。然而，这只有在使用变异接口时才可能。

实现变异接口的类本身不是变异的，而是不变的。这意味着下面的例子，我们用`List<T>`替换`IEnumerable<T>`，将产生编译错误，因为`List<string>`不能赋值给`List<object>`：

```cs
IEnumerable<string> names = 
   new List<string> { "Marius", "Ankit", "Raffaele" };
List<object> objects = names; // error
```

如前所述，值类型不支持变异。`IEnumerable<int>`不能赋值给`IEnumerable<object>`：

```cs
IEnumerable<int> numbers = new List<int> { 1, 1, 2, 3, 5, 8 };
IEnumerable<object> objects = numbers; // error
```

总之，接口中的协变类型参数必须：

+   必须以`out`关键字为前缀

+   只能用作方法的返回类型，而不能用作方法参数的类型

+   不能用作接口方法的泛型约束

逆变是处理传递给接口方法的参数的另一种变体形式。为了理解它是如何工作的，让我们考虑一个情况，我们想要比较各种形状的大小，定义如下：

```cs
public interface IShape
{
    public double Area { get; }
}
public class Square : IShape
{
    public double Length { get; set; }
    public Square(int length)
    {
        Length = length;
    }
    public double Area => Length * Length;
}
public class Circle : IShape
{
    public double Radius { get; set; }
    public Circle(double radius)
    {
        Radius = radius;
    }
    public double Area => Math.PI * Radius * Radius;
}
```

这些与之前使用的类型略有不同，因为`IShape`不再是泛型，以保持示例简单。我们想要的是能够比较形状。为此，提供了一系列类，如下所示：

```cs
public class ShapeComparer : IComparer<IShape>
{
    public int Compare(IShape x, IShape y)
    {
        if (x is null) return y is null ? 0 : -1;
        if (y is null) return 1;
        return x.Area.CompareTo(y.Area);
    }
}
public class SquareComparer : IComparer<Square>
{
    public int Compare(Square x, Square y)
    {
        if (x is null) return y is null ? 0 : -1;
        if (y is null) return 1;
        return x.Length.CompareTo(y.Length);
    }
}
public class CircleComparer : IComparer<Circle>
{
    public int Compare(Circle x, Circle y)
    {
        if (x is null) return y is null ? 0 : -1;
        if (y is null) return 1;
        return x.Radius.CompareTo(y.Radius);
    }
}
```

在这里，`ShapeComparer`通过它们的面积比较`IShape`对象，`SquareComparer`通过它们的长度比较正方形，`CircleComparer`通过它们的半径比较圆。所有这些类都实现了`System.Collections.Generic`命名空间中的`IComparer<T>`接口。该接口定义如下：

```cs
public interface IComparer<in T>
{
    int Compare(T x, T y);
}
```

这个接口有一个名为`Compare()`的方法，它接受两个`T`类型的对象并返回以下之一：

+   如果第一个小于第二个，则为负数

+   如果它们相等，则为 0

+   如果第一个大于第二个，则为正数

然而，其定义的关键是使用类型参数的`in`关键字，使其逆变。因此，可以在期望`Square`或`Circle`的地方传递`IShape`引用。这意味着我们可以安全地传递`IComparer<IShape>`到需要`IComparer<Square>`的地方。让我们看一个具体的例子。

以下类包含一个检查`Square`对象是否比另一个大的方法。`IsBigger()`方法还接受一个实现`IComparer<Square>`的对象的引用：

```cs
public class SquareComparison
{
    public static bool IsBigger(Square a, Square b,
                                IComparer<Square> comparer)
    {
        return comparer.Compare(a, b) >= 0;
    }
}
```

我们可以调用这个方法传递`SquareComparer`或`ShapeComparer`，结果将是相同的：

```cs
Square sqr1 = new Square(4);
Square sqr2 = new Square(5);
SquareComparison.IsBigger(sqr1, sqr2, new SquareComparer());
SquareComparison.IsBigger(sqr1, sqr2, new ShapeComparer());
```

如果`IComparer<T>`接口是不变的，传递`ShapeComparer`将导致编译错误。如果我们尝试传递`CircleComparer`，也会发出编译错误，因为`Circle`不是`Square`的派生类，它实际上是继承层次结构中的同级。

总之，接口中的逆变类型参数：

+   必须以`in`关键字为前缀

+   只能用于方法参数，而不能作为返回类型

+   可以用作接口方法的泛型约束

可以定义一个既是*协变又是逆变*的接口，如下所示：

```cs
interface IMultiVariant<out T, in U>
{
    T Make();
    void Take(U arg);
}
```

在前面的片段中显示的`IMultiVariant<T, U>`接口对`T`是协变的，对`U`是逆变的。

## 泛型结构

与泛型类类似，我们也可以创建泛型结构。泛型结构的语法与泛型类相同。在前面的示例中使用的`Circle`和`Square`类型很小，可以定义为结构而不是类：

```cs
public struct Square : IShape<int>
{
    public int Length { get; set; }
    public Square(int length)
    {
        Length = length;
    }
    public int Area => Length * Length;
}
public struct Circle : IShape<double>
{
    public double Radius { get; set; }
    public Circle(double radius)
    {
        Radius = radius;
    }
    public double Area => Math.PI * Radius * Radius;
}
```

所有适用于泛型类的规则也适用于泛型结构。因为值类型不支持继承，结构不能从其他泛型类型派生，但可以实现任意数量的泛型或非泛型接口。

# 泛型方法

C#允许我们创建接受一个或多个泛型类型参数的泛型方法。我们可以在泛型类内部创建泛型方法，也可以在非泛型类内部创建泛型方法。静态方法和非静态方法都可以是泛型的。类型推断的规则对所有类型都是相同的。类型参数必须在方法名之后、参数列表之前的尖括号内声明，就像我们对类型所做的那样。

让我们通过以下示例来了解如何使用泛型方法：

```cs
class CompareObjects
{
    public bool Compare<T>(T input1, T input2)
    {
        return input1.Equals(input2);
    }
}
```

非泛型类`CompareObjects`包含一个泛型方法`Compare`，用于比较两个对象。该方法接受两个参数——`input1`和`input2`。我们使用`System.Object`基类的`Equals()`方法来比较输入参数。该方法将根据输入是否相等返回一个布尔值。考虑下面的代码：

```cs
CompareObjects comps = new CompareObjects();
Console.WriteLine(comp.Compare<int>(10, 10));
Console.WriteLine(comp.Compare<double>(10.5, 10.8));
Console.WriteLine(comp.Compare<string>("a", "a"));
Console.WriteLine(comp.Compare<string>("a", "b"));
```

我们正在创建`CompareObjects`类的对象，并为各种数据类型调用`Compare()`方法。在这个例子中，类型参数是显式指定的。然而，编译器能够从参数中推断出来，因此可以省略，如下所示：

```cs
CompareObjects comp = new CompareObjects();
Console.WriteLine(comp.Compare(10, 10));
Console.WriteLine(comp.Compare(10.5, 10.8));
Console.WriteLine(comp.Compare("a", "a"));
Console.WriteLine(comp.Compare("a", "b"));
```

如果泛型方法具有与定义它的类、结构或接口的类型参数相同的类型参数，编译器会发出警告，因为方法类型参数隐藏了外部类型的类型参数，如下面的代码所示：

```cs
class ConflictingGenerics<T>
{
    public void DoSomething<T>(T arg) // warning
    { 
    }
}
```

泛型方法和泛型类型都支持类型参数约束来对类型施加限制。这个主题将在本章的下一节中讨论。

# 类型参数约束

泛型类型或方法中的类型参数可以被任何有效类型替换。然而，在某些情况下，我们希望限制可以用作类型参数的类型。例如，我们之前看到的泛型`Shape<T>`类或`IShape<T>`接口。

类型参数`T`被用于`Area`属性的类型。我们期望它要么是整数类型，要么是浮点类型。但是没有限制，有人可以使用`bool`，`string`或任何其他类型。当然，根据类型参数的使用方式，这可能导致各种编译错误。然而，能够限制用于实例化泛型类型或调用泛型方法的类型是有用的。

为此，我们可以对类型参数应用约束。约束用于告诉编译器类型参数必须具有什么样的能力。如果我们不指定约束，那么类型参数可以被任何类型替换。应用约束将限制可以用作类型参数的类型。

约束使用关键字`where`来指定。C#定义了以下八种泛型约束类型：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-prog/img/Chapter_6Table_1_01.jpg)

约束应该在类型参数之后指定。我们可以通过逗号分隔它们来使用多个约束。对于使用这些约束有一些规则：

+   `struct`约束意味着`new()`约束，因此所有值类型必须有一个公共的无参数构造函数。这两个约束，`struct`和`new()`，不能一起使用。

+   `unmanaged`约束意味着`struct`约束；因此，这两个不能一起使用。它也不能与`new()`约束一起使用。

+   在使用多个约束时，`new()`约束必须在约束列表中最后提及。

+   `notnull`约束从 C# 8 开始可用，必须在可空上下文中使用，否则编译器会生成警告。当约束被违反时，编译器不会生成错误，而是生成警告。

+   从 C# 7.3 开始，`System.Enum`，`System.Delegate`和`System.MulticastDelegate`可以用作基类约束。

没有约束的类型参数称为*无界*。无界类型参数有几条规则：

+   你不能使用`!=`和`==`运算符来处理这些类型，因为不可能知道具体类型是否重载了它们。

+   它们可以与`null`进行比较。对于值类型，这种比较总是返回`false`。

+   它们可以转换为和从`System.Object`。

+   它们可以转换为任何接口类型。

为了理解约束的工作原理，让我们从以下泛型结构的示例开始：

```cs
struct Point<T>
{
    public T X { get; }
    public T Y { get; }
    public Point(T x, T y)
    {
        X = x;
        Y = y;
    }
}
```

`Point<T>`是表示二维空间中的点的结构。这个类是泛型的，因为我们可能希望使用整数值作为点坐标或实数值（浮点值）。但是，我们可以使用任何类型来实例化该类，例如`bool`，`string`或`Circle`，如下例所示：

```cs
Point<int> p1 = new Point<int>(3, 4);
Point<double> p2 = new Point<double>(3.12, 4.55);
Point<bool> p3 = new Point<bool>(true, false);
Point<string> p4 = new Point<string>("alpha", "beta");
```

为了将`Point<T>`的实例化限制为数字类型（即整数和浮点类型），我们可以为类型参数`T`编写约束，如下所示：

```cs
struct Point<T>
    where T : struct, 
              IComparable, IComparable<T>,
              IConvertible,
              IEquatable<T>,
              IFormattable
{
    public T X { get; }
    public T Y { get; }
    public Point(T x, T y)
    {
        X = x;
        Y = y;
    }
}
```

我们使用了两种类型的约束：`struct`约束和接口约束，并且它们用逗号分隔列出。不幸的是，没有约束可以将类型定义为数字，但这些约束是表示数字类型的最佳组合，因为所有数字类型都是值类型，并且它们都实现了这里列出的五个接口。`bool`类型实现了前四个，但没有实现`IFormattable`。因此，使用`bool`或`string`实例化`Point<T>`现在将产生编译错误。

类型或方法可以有多个类型参数，每个类型参数都可以有自己的约束。我们可以在下面的示例中看到这一点：

```cs
class RestrictedDictionary<TKey, TValue> : Dictionary<TKey, List<TValue>>
    where TKey : System.Enum
    where TValue : class, new()
{
    public T Make<T>(TKey key) where T : TValue, new()
    {
        var value = new T();
        if (!TryGetValue(key, out List<TValue> list))
            Add(key, new List<TValue>() { value });
        else
            list.Add(value);
        return value;
    }
}
```

`RestrictedDictionary<TKey, TValue>`类是一个特殊的字典，它只允许枚举类型作为键类型。为此，它使用了基类约束`System.Enum`。值的类型必须是具有公共默认构造函数的引用类型。为此，它使用了`class`和`new()`约束。这个类有一个名为`Make<T>()`的公共泛型方法。

类型参数`T`必须是`TValue`或从`TValue`派生的类型，并且还必须具有公共默认构造函数。此方法创建类型`T`的新实例，将其添加到与指定键关联的字典中的列表中，并返回对新创建对象的引用。

让我们也考虑以下形状类的层次结构。请注意，为简单起见，这些被保持在最低限度：

```cs
enum ShapeType { Sharp, Rounded };
class Shape { }
class Ellipsis  : Shape { }
class Circle    : Shape { }
class Rectangle : Shape { }
class Square    : Shape { }
```

我们可以像这样使用`RestrictedDictionary`类：

```cs
var dictionary = new RestrictedDictionary<ShapeType, Shape>();
var c = dictionary.Make<Circle>(ShapeType.Rounded);
var e = dictionary.Make<Ellipsis>(ShapeType.Rounded);
var r = dictionary.Make<Rectangle>(ShapeType.Sharp);
var s = dictionary.Make<Square>(ShapeType.Sharp);
```

在这个例子中，我们将几种形状（圆形、椭圆形、矩形和正方形）添加到受限制的字典中。键类型是`ShapeType`，值类型是`Shape`。`Make()`方法接受`ShapeType`类型的参数，并返回对形状对象的引用。每种类型都必须派生自`Shape`并具有公共默认构造函数。否则，代码将产生错误。

# 总结

在本章中，我们学习了 C#中的泛型。泛型允许我们在 C#中创建参数化类型。泛型增强了代码的可重用性并确保类型安全。我们探讨了如何创建泛型类和泛型结构。我们还在泛型类中实现了继承。

我们学习了如何在泛型类型或方法的类型参数上实现约束。约束允许我们限制可以用作类型参数的数据类型。我们还学习了如何创建泛型方法和泛型接口。

您可以主要用于创建集合和包装的泛型。在下一章中，我们将探讨.NET 中最重要的集合。

# 测试你所学到的

1.  泛型是什么，它们提供了什么好处？

1.  什么是类型参数？

1.  如何定义泛型类？泛型方法呢？

1.  一个类可以从泛型类型派生吗？结构呢？

1.  什么是构造类型？

1.  泛型接口的协变类型参数是什么？

1.  泛型接口的逆变类型参数是什么？

1.  什么是类型参数约束，以及如何指定它们？

1.  `new()`类型参数约束是做什么的？

1.  C# 8 中引入了什么类型参数约束，它是做什么的？


# 第七章：集合

在上一章中，我们学习了 C#中的泛型编程。泛型的最重要的应用之一就是创建泛型集合。**集合**是一组对象。我们学习了如何在*第二章*，*数据类型和运算符*中使用数组。然而，数组是固定大小的序列，在大多数情况下，我们需要处理可变大小的序列。

.NET 框架提供了代表各种类型集合的泛型类，如列表、队列、集合、映射等。使用这些类，我们可以轻松地对对象集合执行插入、更新、删除、排序和搜索等操作。

在本章中，您将学习以下泛型集合：

+   `List<T>`集合

+   `Stack<T>`集合

+   `Queue<T>`集合

+   `LinkedList<T>`集合

+   `Dictionary<TKey, TValue>`集合

+   `HashSet<T>`集合

在本章结束时，您将对.NET 中最重要的集合有很好的理解，它们模拟了什么数据结构，它们之间的区别是什么，以及何时应该使用它们。

之前提到的所有集合都不是线程安全的。这意味着它们不能在多线程场景中使用，当一个线程可能在读取时，另一个线程可能在写入相同的集合，而不使用外部同步机制。然而，.NET 还提供了几个线程安全的集合，它们位于`System.Collections.Concurrent`命名空间中，使用高效的锁定或无锁同步机制，在许多情况下，提供比使用外部锁更好的性能。在本章中，我们还将介绍这些集合，并了解何时适合使用它们。

让我们通过查看`System.Collections.Generic`命名空间来概述泛型集合库，这是所有泛型集合的所在地。

# 介绍 System.Collections.Generic 命名空间

我们将在本章介绍的泛型集合类是`System.Collections.Generic`命名空间的一部分。该命名空间包含定义泛型集合和操作的接口和类。所有泛型集合都实现了一系列泛型接口，这些接口也在该命名空间中定义。这些接口可以大致分为两类：

+   可变的，支持更改集合内容的操作，如添加新元素或删除现有元素。

+   只读集合，不提供更改集合内容的方法。

表示可变集合的接口如下：

+   `IEnumerable<T>`：这是所有其他接口的基本接口，并公开一个支持遍历`T`类型集合元素的枚举器。

+   `ICollection<T>`：这定义了操作泛型集合的方法——`Add()`、`Clear()`、`Contains()`、`CopyTo()`和`Remove()`——以及`Count`等属性。这些成员应该是*不言自明*的。

+   `IList<T>`：表示可以通过*索引*访问其元素的泛型集合。它定义了三种方法：`IndexOf()`，用于检索元素的索引，`Insert()`，用于在指定索引处插入元素，`RemoveAt()`，用于移除指定索引处的元素，此外，它还提供了一个用于直接访问元素的索引器。

+   `ISet<T>`：这是抽象集合集合的基本接口。它定义了诸如`Add()`、`ExceptWith()`、`IntersetWith()`、`UnionWith()`、`IsSubsetOf()`和`IsSupersetOf()`等方法。

+   `IDictionary<TKey, TValue>`：这是抽象出键值对集合的基本接口。它定义了`Add()`、`ContainsKey()`、`Remove()`和`TryGetValue()`方法，以及一个索引器和`Keys`和`Values`属性，分别返回键和值的集合。

这些接口之间的关系如下图所示：

![图 7.1 - System.Collections.Generic 命名空间中通用集合接口的层次结构。](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-prog/img/Figure_7.1_B12346.jpg)

图 7.1 - System.Collections.Generic 命名空间中通用集合接口的层次结构。

代表只读集合的接口如下：

+   `IReadOnlyCollection<T>`：这代表了一个只读的元素的通用集合。它只定义了一个成员：`Count`属性。

+   `IReadOnlyList<T>`：这代表了一个只读的可以通过索引访问的元素的通用集合。它只定义了一个成员：一个只读的索引器。

+   `IReadOnlyDictionary<TKey, TValue>`：这代表了一个只读的键值对的通用集合。这个接口定义了`ContainsKey()`和`TryGetValue()`方法，以及`Keys`和`Values`属性和一个只读的索引器。

再次，这些接口的关系如下图所示：

![图 7.2 - 只读通用集合接口的层次结构。](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-prog/img/Figure_7.2_B12346.jpg)

图 7.2 - 只读通用集合接口的层次结构。

每个通用集合都实现了几个这些接口。例如，`List<T>`实现了`IList<T>`、`ICollection<T>`、`IEnumerable<T>`、`IReadOnlyCollection<T>`和`IReadOnlyList<T>`。下图显示了我们将在本章学习的通用集合所实现的所有接口：

![图 7.3 - 一个类图显示了最重要的通用集合和它们实现的接口。](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-prog/img/Figure_7.3_B12346.jpg)

图 7.3 - 一个类图显示了最重要的通用集合和它们实现的接口。

这些图表中显示的继承层次实际上是实际继承层次的简化。所有的通用集合都有一个非通用的等价物。例如，`IEnumerable<T>`是`IEnumerable`的通用等价物，`ICollection<T>`是`ICollection`的通用等价物，`IList<T>`是`Ilist`的通用等价物，依此类推。这些是由`ArrayList`、`Queue`、`Stack`、`DictionaryBase`、`Hashtable`等遗留集合实现的遗留接口，所有这些都在`System.Collections`命名空间中可用。这些非通用的遗留集合没有强类型。出于几个原因，使用通用集合是首选的：`

+   它们提供了类型安全的好处。不需要从基本集合派生并实现特定类型的成员。

+   对于值类型，它们具有更好的性能，因为没有元素的装箱和拆箱，这是非通用集合中必要的过程。

+   一些通用集合提供了非通用集合中不可用的功能，比如接受委托用于搜索或对每个元素执行操作的方法。

当你需要将集合作为参数传递给函数或从函数返回集合时，应该避免使用具体的实现，而是使用接口。当你只想遍历元素时，`IEnumerable<T>`是合适的，但如果你需要多次这样做，你可以使用`IReadOnlyCollection<T>`。只读集合应该在两种情况下被优先选择：

+   当一个方法不修改作为参数传递的集合时

+   当你返回一个集合，如果集合已经在内存中，调用者不应该修改它

最终，最合适的接口因情况而异。

在接下来的几节中，我们将介绍最常用的类型安全的泛型集合。非泛型集合在遗留代码之外几乎没有什么意义。

# List<T> 集合

`List<T>` 泛型类表示可以通过索引访问其元素的集合。`List<T>` 与数组非常相似，只是集合的大小不是固定的，而是可变的，可以随着元素的添加或删除而增长或减少。事实上，`List<T>` 的实现使用数组来存储元素。当元素的数量超过数组的大小时，将分配一个新的更大的数组，并将先前数组的内容复制到新数组中。这意味着 `List<T>` 在连续的内存位置中存储元素。但是，对于值类型，这些位置包含值，但对于引用类型，它们包含对实际对象的引用。可以将对同一对象的多个引用添加到列表中。

`List<T>` 类实现了一系列泛型和非泛型接口，如下面的类声明所示：

```cs
public class List<T> : ICollection<T>, ICollection
                       IEnumerable<T>, IEnumerable, 
                       IList<T>, IList,
                       IReadOnlyCollection<T>, IReadOnlyList<T> {}
```

列表可以通过几种方式创建：

+   使用默认构造函数，这会导致一个具有默认容量的空列表。

+   通过指定特定的容量但没有初始元素，这会再次使列表为空。

+   从一系列元素中。

在以下示例中，`numbers` 是一个空的整数列表，`words` 是一个空的字符串列表：

```cs
var numbers = new List<int>();
var words = new List<string>();
```

另一方面，以下示例初始化了一些元素的列表。第一个列表将包含六个整数，第二个列表将包含两个字符串：

```cs
var numbers = new List<int> { 1, 2, 3, 5, 7, 11 };
var words = new List<string> { "one", "two" };
```

这个类支持你从这样的集合中期望的所有典型操作——添加、删除和搜索元素。有几种方法可以向列表中添加元素：

+   `Add()` 将元素添加到列表的末尾。

+   `AddRange()` 将一系列元素（以 `IEnumerable<T>` 的形式）添加到列表的末尾。

+   `Insert()` 在指定位置插入一个元素。位置必须是有效的索引，在列表的范围内；否则，将抛出 `ArgumentOutOfRangeException` 异常。

+   `InsertRange()` 在指定的索引处插入一系列元素（以 `IEnumerable<T>` 的形式），该索引必须在列表的范围内。

如果内部数组的容量超过了，所有这些操作可能需要重新分配存储元素的内部数组。如果不需要分配空间，`Add()` 是一个 *O(1)* 操作，当需要分配空间时，为 *O(n)*。

如果不需要分配空间，`AddRange()` 的时间复杂度为 *O(n)*，如果需要分配空间，则为 *O(n+k)*。`Insert()` 操作始终为 *O(n)*，`InsertRange()` 如果不需要分配空间，则为 *O(n)*，如果需要分配空间，则为 *O(n+k)*。在这个表示法中，*n* 是列表中的元素数量，*k* 是要添加的元素数量。我们可以在以下示例中看到这些操作的示例：

```cs
var numbers = new List<int> {1, 2, 3}; // 1 2 3
numbers.Add(5);                        // 1 2 3 5
numbers.AddRange(new int[] { 7, 11 }); // 1 2 3 5 7 11
numbers.Insert(5, 1);                  // 1 2 3 5 7 1 11
numbers.Insert(5, 1);                  // 1 2 3 5 7 1 1 11
numbers.InsertRange(                   // 1 13 17 19 2 3 5..
    1, new int[] {13, 17, 19});        // ..7 1 1 11
```

使用不同的方法也可以以几种方式删除元素：

+   `Remove()` 从列表中删除指定的元素。

+   `RemoveAt()` 删除指定索引处的元素，该索引必须在列表的范围内。

+   `RemoveRange()` 删除指定数量的元素，从给定的索引开始。

+   `RemoveAll()` 删除列表中满足提供的谓词要求的所有元素。

+   `Clear()` 删除列表中的所有元素。

所有这些操作都在 *O(n)* 中执行，其中 *n* 是列表中的元素数量。`RemoveAt()` 是一个例外，其中 *n* 是 `Count - index`。原因是在删除一个元素后，必须在内部数组中移动元素。使用这些函数的示例在以下代码片段中显示：

```cs
numbers.Remove(1);              // 13 17 19  2  3  5  7  1  
                                // 1 11
numbers.RemoveRange(2, 3);      // 13 17  5  7  1  1 11
numbers.RemoveAll(e => e < 10); // 13 17 11
numbers.RemoveAt(1);            // 13 11
numbers.Clear();                // empty
```

可以通过指定谓词来搜索列表中的元素。

信息框

**谓词** 是返回布尔值的委托。它们通常用于过滤元素，例如在搜索集合时。

有几种可以用于搜索元素的方法：

+   `Find()` 返回与谓词匹配的第一个元素，如果找不到则返回`T`的默认值。

+   `FindLast()` 返回与谓词匹配的最后一个元素，如果找不到则返回`T`的默认值。

+   `FindAll()` 返回与谓词匹配的所有元素的`List<T>`，如果找不到则返回一个空列表。

所有这些方法都在*O(n)*中执行，如下面的代码片段所示：

```cs
var numbers = new List<int> { 1, 2, 3, 5, 7, 11 };
var a = numbers.Find(e => e < 10);      // 1
var b = numbers.FindLast(e => e < 10);  // 7
var c = numbers.FindAll(e => e < 10);   // 1 2 3 5 7
```

还可以搜索元素的从零开始的索引。有几种方法允许我们这样做：

+   `IndexOf()` 返回与提供的参数相等的第一个元素的索引。

+   `LastIndexOf()` 返回搜索元素的最后一个索引。

+   `FindIndex()` 返回满足提供的谓词的第一个元素的索引。

+   `FindLastIndex()` 返回满足提供的谓词的最后一个元素的索引。

+   `BinarySearch()` 使用二进制搜索返回满足提供的元素或比较器的第一个元素的索引。此函数假定列表已经排序；否则，结果是不正确的。

`BinarySearch()` 在*O(log n)*中执行，而其他所有操作都在*O(n)*中执行。这是因为它们使用线性搜索。如果找不到满足搜索条件的元素，它们都返回`-1`。示例如下所示：

```cs
var numbers = new List<int> { 1, 1, 2, 3, 5, 8, 11 };
var a = numbers.FindIndex(e => e < 10);     // 0
var b = numbers.FindLastIndex(e => e < 10); // 5
var c = numbers.IndexOf(5);                 // 4
var d = numbers.LastIndexOf(1);             // 1
var e = numbers.BinarySearch(8);            // 5
```

有一些方法允许我们修改列表的内容，例如对元素进行排序或反转：

+   `Sort()` 根据默认或指定的条件对列表进行排序。有几个重载允许我们指定比较委托或`IComparer<T>`对象，甚至是要排序的列表的子范围。在大多数情况下，此操作在*O(n log n)*中执行，但在最坏的情况下为*O(n2)*。

+   `Reverse()` 反转列表中的元素。有一个重载允许您指定要恢复的子范围。此操作在*O(n)*中执行。

以下是使用这些函数的示例：

```cs
var numbers = new List<int> { 1, 5, 3, 11, 8, 1, 2 };
numbers.Sort();     // 1 1 2 3 5 8 11
numbers.Reverse();  // 11 8 5 3 2 1 1
```

`List<T>`类中有更多的方法，不仅限于此处显示的方法。但是，浏览所有这些方法超出了本书的范围。您应该在线查阅该类的官方文档，以获取该类所有成员的完整参考。

# `Stack<T>`集合

栈是一种线性数据结构，允许我们按特定顺序插入和删除项目。新项目添加到栈顶。如果要从栈中移除项目，只能移除顶部项目。由于只允许从一端插入和删除，因此最后插入的项目将是首先删除的项目。因此，栈被称为**后进先出（LIFO）**集合。

以下图表描述了一个栈，其中*push*表示向栈中添加项目，*pop*表示从栈中删除项目：

![图 7.4 - 栈的概念表示。](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-prog/img/Figure_7.4_B12346.png)

图 7.4 - 栈的概念表示。

.NET 提供了用于处理栈的通用`Stack<T>`类。该类包含几个构造函数，允许我们创建空栈或使用元素集合初始化栈。看一下以下代码片段，我们正在创建一个包含三个初始元素和一个空整数栈的字符串栈：

```cs
var arr = new string[] { "Ankit", "Marius", "Raffaele" };
Stack<string> names = new Stack<string>(arr);
Stack<int> numbers = new Stack<int>();
```

栈支持的主要操作如下：

+   `Push()`: 在栈顶插入一个项目。如果不需要重新分配，则这是一个*O(1)*操作，否则为*O(n)*。

+   `Pop()`: 从栈顶移除并返回项目。这是一个*O(1)*操作。

+   `Peek()`: 返回栈顶的项目，而不移除它。这是一个*O(1)*操作。

+   `Clear()`: 从栈中移除所有元素。这是一个*O(n)*操作。

让我们通过以下示例来理解它们是如何工作的，在左侧，您可以看到每个操作后栈的内容：

```cs
var numbers = new Stack<int>(new int[]{ 1, 2, 3 });// 3 2 1
numbers.Push(5);                                   // 5 3 2 1
numbers.Push(7);                                   // 7 5 3 2 1
numbers.Pop();                                     // 5 3 2 1
var n = numbers.Peek();                            // 5 3 2 1
numbers.Push(11);                                 // 11 5 3 2 1
numbers.Clear();                                  // empty
```

`Pop()`和`Peek()`方法如果栈为空会抛出`InvalidOperationException`异常。在.NET Core 中，自 2.0 版本以来，有两种替代的非抛出方法可用——`TryPop()`和`TryPeek()`。这些方法返回一个布尔值，指示是否找到了顶部元素，如果找到了，它将作为`out`参数返回。

# 队列<T>集合

队列是一种线性数据结构，其中插入和删除元素是从两个不同的端口执行的。新项目从队列的后端添加，现有项目的删除从前端进行。因此，要首先插入的项目将是要首先删除的项目。因此，队列被称为**先进先出（FIFO）**集合。下图描述了一个队列，其中**Enqueue**表示向队列添加项目，**Dequeue**表示从队列中删除项目：

![图 7.5 – 队列的概念表示。](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-prog/img/Figure_7.5_B12346.jpg)

图 7.5 – 队列的概念表示。

在.NET 中，实现通用队列的类是`Queue<T>`。类似于`Stack<T>`，有重载的构造函数，允许我们创建一个空队列或一个从`IEnumerable<T>`集合中的元素初始化的队列。看一下下面的代码片段，我们正在创建一个包含三个初始元素的字符串队列和一个空的整数队列：

```cs
var arr = new string[] { "Ankit", "Marius", "Raffaele" };
Queue<string> names = new Queue<string>(arr);
Queue<int> numbers = new Queue<int>();
```

队列支持的主要操作如下：

+   `Enqueue()`: 在队列的末尾插入一个项目。这是一个*O(1)*操作，除非需要重新分配内部数组，否则它将成为一个*O(n)*操作。

+   `Dequeue()`: 从队列的前端移除并返回一个项目。这是一个*O(1)*操作。

+   `Peek()`: 从队列的前端返回一个项目，但不移除它。这是一个*O(1)*操作。

+   `Clear()`: 从队列中移除所有元素。这是一个*O(n)*操作。

要了解这些方法如何工作，让我们看下面的例子：

```cs
var numbers = new Queue<int>(new int[] { 1, 2, 3 });// 1 2 3
numbers.Enqueue(5);                                 // 1 2 3 5
numbers.Enqueue(7);                                // 1 2 3 5 7
numbers.Dequeue();                                 // 2 3 5 7
var n = numbers.Peek();                            // 2 3 5 7
numbers.Enqueue(11);                              // 2 3 5 7 11
numbers.Clear();                                 // empty
```

`Dequeue()`和`Peek()`方法如果队列为空会抛出`InvalidOperationException`异常。在.NET Core 中，自 2.0 版本以来，有两种替代的非抛出方法可用——`TryDequeue()`和`TryPeek()`。这些方法返回一个布尔值，指示是否找到了顶部元素，如果找到了，它将作为一个 out 参数返回。

从这些示例中可以看出，`Stack<T>`和`Queue<T>`有非常相似的实现，尽管语义不同。它们的公共成员几乎相同，不同之处在于栈操作称为`Push()`和`Pop()`，队列操作称为`Enqueue()`和`Dequeue()`。

# LinkedList<T>集合

链表是一种线性数据结构，由一组节点组成，每个节点包含数据以及一个或多个节点的地址。这里有四种类型的链表，如下所述：

+   **单链表**：包含存储值和对节点序列中下一个节点的引用的节点。最后一个节点的下一个节点的引用将指向 null。

+   **双向链表**：在这里，每个节点包含两个链接——第一个链接指向前一个节点，下一个链接指向序列中的下一个节点。第一个节点的上一个节点的引用和最后一个节点的下一个节点的引用将指向 null。

+   **循环单链表**：最后一个节点的下一个节点的引用将指向第一个节点，从而形成一个循环链。

+   **双向循环链表**：在这种类型的链表中，最后一个节点的下一个节点的引用将指向第一个节点，第一个节点的上一个节点的引用将指向最后一个节点。

双向链表的概念表示如下：

![图 7.6 – 双向链表的概念表示。](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-prog/img/Figure_7.6_B12346.jpg)

图 7.6 – 双向链表的概念表示。

在这里，每个节点包含一个值和两个指针。**Next** 指针包含对序列中下一个节点的引用，并允许在链表的正向方向上进行简单导航。**Prev** 指针包含对序列中前一个节点的引用，并允许我们在链表中向后移动。

.NET 提供了 `LinkedList<T>` 类，表示双向链表。该类包含 `LinkedListNode<T>` 类型的项。插入和删除操作在 *O(1)* 中执行，搜索在 *O(n)* 中执行。节点可以从同一链表对象或另一个链表中移除和重新插入。列表维护内部计数，因此使用 `Count` 属性检索列表的大小也是 *O(1)* 操作。链表不支持循环、分割、链接或其他可能使列表处于不一致状态的操作。

`LinkedListNode<T>` 类具有以下四个属性：

+   `List`：此属性将返回对 `LinkedList<T>` 对象的引用，该对象属于 `LinkedListNode<T>`。

+   `Next`：表示对 `LinkedList<T>` 对象中下一个节点的引用，如果当前节点是最后一个节点，则为 `null`。

+   `Previous`：表示对 `LinkedList<T>` 对象中前一个节点的引用，如果当前节点是第一个节点，则为 `null`。

+   `Value`：此属性的类型为 `T`，表示节点中包含的值。

对于值类型，`LinkedListNode<T>` 包含实际值，而对于引用类型，它包含对对象的引用。

该类具有重载的构造函数，使我们能够创建一个空的链表或一个以 `IEnumerable<T>` 形式的元素序列进行初始化的链表。看一下以下示例，看一些示例：

```cs
var arr = new string[] { "Ankit", "Marius", "Raffaele" };
var words = new LinkedList<string>(arr);
var numbers = new LinkedList<int>();
```

使用以下方法可以以多种方式向链表添加新元素：

+   `AddFirst()` 在列表开头添加一个新节点或值。

+   `AddLast()` 在列表末尾添加一个新节点或值。

+   `AddAfter()` 在指定节点之后的列表中添加一个新节点或值。

+   `AddBefore()` 在指定节点之前的列表中添加一个新节点或值。

我们可以在以下示例中看到为这些方法添加新值的重载的示例：

```cs
var numbers = new LinkedList<int>();
var n2 = numbers.AddFirst(2);      // 2
var n1 = numbers.AddFirst(1);      // 1 2
var n7 = numbers.AddLast(7);       // 1 2 7
var n11 = numbers.AddLast(11);     // 1 2 7 11
var n3 = numbers.AddAfter(n2, 3);  // 1 2 3 7 11
var n5 = numbers.AddBefore(n7, 5); // 1 2 3 5 7 11
```

可以使用以下方法之一在链表中搜索元素：

+   `Contains()`：这检查指定的值是否在列表中，并返回一个布尔值以指示成功或失败。

+   `Find()`：查找并返回包含指定值的第一个节点。

+   `FindLast()`：查找并返回包含指定值的最后一个节点。

以下是使用这些函数的示例：

```cs
var fn1 = numbers.Find(5);
var fn2 = numbers.FindLast(5);
Console.WriteLine(fn1 == fn2);           // True
Console.WriteLine(numbers.Contains(3));  // True
Console.WriteLine(numbers.Contains(13)); // False
```

使用以下方法可以以多种方式从列表中移除元素：

+   `RemoveFirst()` 从列表中移除第一个节点。

+   `RemoveLast()` 移除列表中的最后一个节点。

+   `Remove()` 从列表中移除指定的节点或指定值的第一个出现。

+   `Clear()` 从列表中移除所有元素。

您可以在以下列表中看到所有这些方法的工作方式：

```cs
numbers.RemoveFirst(); // 2 3 5 7 11
numbers.RemoveLast();  // 2 3 5 7
numbers.Remove(3);     // 2 5 7
numbers.Remove(n5);    // 2 7
numbers.Clear();       // empty
```

链表类还具有几个属性，包括 `Count`，它返回列表中的元素数量，`First`，它返回第一个节点，以及 `Last`，它返回最后一个节点。如果列表为空，则 `Count` 为 `0`，`First` 和 `Last` 都设置为 `null`。

# `Dictionary<TKey, TValue>` 集合

字典是一组键值对，允许根据键进行快速查找。添加、搜索和删除项目都是非常快速的操作，并且在 *O(1)* 中执行。唯一的例外是在必须增加容量时添加新值，此时它变为 *O(n)*。

在.NET 中，泛型`Dictionary<TKey,TValue>`类实现了一个字典。`TKey`表示键的类型，`TValue`表示值的类型。字典的元素是`KeyValuePair<TKey,TValue>`对象。

`Dictionary<TKey, TValue>`有几个重载的构造函数，允许我们创建一个空字典或一个填充了一些初始值的字典。该类的默认构造函数将创建一个空字典。看一下以下代码片段：

```cs
var languages = new Dictionary<int, string>(); 
```

在这里，我们正在创建一个名为`languages`的空字典，它具有`int`类型的键和`string`类型的值。我们还可以在声明时初始化字典。考虑以下代码片段：

```cs
var languages = new Dictionary<int, string>()
{
    {1, "C#"}, 
    {2, "Java"}, 
    {3, "Python"}, 
    {4, "C++"}
};
```

在这里，我们正在创建一个字典，该字典初始化了四个具有键`1`、`2`、`3`和`4`的值。这在语义上等同于以下初始化：

```cs
var languages = new Dictionary<int, string>()
{
    [1] = "C#",
    [2] = "Java",
    [3] = "Python",
    [4] = "C++"
};
```

字典必须包含唯一的键；但是，值可以是*重复*的。同样，键不能是`null`，但是值（如果是引用类型）可以是`null`。要添加、删除或搜索字典值，我们可以使用以下方法：

+   `Add()`：这向字典中添加具有指定键的新值。如果键为`null`或键已存在于字典中，则会抛出异常。

+   `Remove()`：这删除具有指定键的值。

+   `Clear()`：这从字典中删除所有值。

+   `ContainsKey()`：这检查字典是否包含指定的键，并返回一个布尔值以指示。

+   `ContainsValue()`：这检查字典是否包含指定的值，并返回一个布尔值以指示。该方法执行线性搜索；因此，它是一个*O(n)*操作。

+   `TryGetValue()`：这检查字典是否包含指定的键，如果是，则将关联的值作为`out`参数返回。如果成功获取了值，则该方法返回`true`，否则返回`false`。如果键不存在，则输出参数设置为`TValue`类型的默认值（即数值类型为`0`，布尔类型为`false`，引用类型为`null`）。

在.NET Core 2.0 及更高版本中，还有一个名为`TryAdd()`的额外方法，它尝试向字典中添加新值。该方法仅在键尚未存在时成功。它返回一个布尔值以指示成功或失败。

该类还包含一组属性，其中最重要的是以下属性：

+   `Count`：这返回字典中键值对的数量。

+   `Keys`：这返回一个集合（类型为`Dictionary<TKey,TValue>.KeyCollection`）包含字典中的所有键。此集合中键的顺序未指定。

+   `Values`：这返回一个集合（类型为`Dictionary<TKey,TValue>.ValueCollection`）包含字典中的所有值。此集合中值的顺序未指定，但保证与`Keys`集合中的关联键的顺序相同。

+   `Item[]`：这是一个索引器，用于获取或设置与指定键关联的值。索引器可用于向字典中添加值。如果键不存在，则会添加新的键值对。如果键已存在，则值将被覆盖。

看一下以下示例，我们在创建一个字典，然后以几种方式添加键值对：

```cs
var languages = new Dictionary<int, string>()
{
    {1, "C#"},
    {2, "Java"},
    {3, "Python"},
    {4, "C++"}
};
languages.Add(5, "JavaScript");
languages.TryAdd(5, "JavaScript");
languages[6] = "F#";
languages[5] = "TypeScript";
```

最初，字典包含了对[1, C#] [2, Java] [3, Python] [4, C++]的配对，然后我们两次添加了[5, JavaScript]。但是，因为第二次使用了`TryAdd()`，操作将在不抛出任何异常的情况下发生。然后我们使用索引器添加了另一对[6, F#]，并且还更改了现有键（即 5）的值，即从 JavaScript 更改为 TypeScript。

我们可以使用前面提到的方法搜索字典：

```cs
Console.WriteLine($"Has 5: {languages.ContainsKey(5)}");
Console.WriteLine($"Has C#: {languages.ContainsValue("C#")}");
if (languages.TryGetValue(1, out string lang))
    Console.WriteLine(lang);
else
    Console.WriteLine("Not found!");
```

我们还可以通过枚举器遍历字典的元素，在这种情况下，键值对被检索为`KeyValuePair<TKey, TValue>`对象：

```cs
foreach(var kvp in languages)
{
    Console.WriteLine($"[{kvp.Key}] = {kvp.Value}");
}
```

要删除元素，我们可以使用`Remove()`或`Clear()`，后者用于从字典中删除所有键值对：

```cs
languages.Remove(5);
languages.Clear();
```

另一个基于哈希的集合，只维护键或唯一值的集合，是`HashSet<T>`。我们将在下一节中看到它。

# HashSet<T>集合

集合是一个只包含不同项的集合，可以是任何顺序。.NET 提供了`HashSet<T>`类来处理集合。该类包含处理集合元素的方法，还包含建模数学集合操作如**并集**或**交集**的方法。

与所有其他集合一样，`HashSet<T>`包含多个重载的构造函数，允许我们创建空集或填充有初始值的集合。要声明一个空集，我们使用默认构造函数（即没有参数的构造函数）：

```cs
HashSet<int> numbers = new HashSet<int>();
```

但我们也可以使用一些值初始化集合，如下例所示：

```cs
HashSet<int> numbers = new HashSet<int>()
{
    1, 1, 2, 3, 5, 8, 11
};
```

要使用集合，我们可以使用以下方法：

+   `Add()` 如果元素尚未存在，则将新元素添加到集合中。该函数返回一个布尔值以指示成功或失败。

+   `Remove()` 从集合中移除指定的元素。

+   `RemoveWhere()` 从集合中删除与提供的谓词匹配的所有元素。

+   `Clear()` 从集合中移除所有元素。

+   `Contains()` 检查指定的元素是否存在于集合中。

我们可以在以下示例中看到这些方法的运行情况：

```cs
HashSet<int> numbers = new HashSet<int>() { 11, 3, 8 };
numbers.Add(1);                       // 11 3 8 1
numbers.Add(1);                       // 11 3 8 1
numbers.Add(2);                       // 11 3 8 1 2
numbers.Add(5);                       // 11 3 8 1 2 5
Console.WriteLine(numbers.Contains(1));
Console.WriteLine(numbers.Contains(7));
numbers.Remove(1);                    // 11 3 8 2 5
numbers.RemoveWhere(n => n % 2 == 0); // 11 3 5
numbers.Clear();                      // empty
```

如前所述，`HashSet<T>`类提供了以下数学集合操作的方法：

+   `UnionWith()`: 这执行两个集合的并集。当前集合对象通过添加来自提供的集合中不在集合中的所有元素来进行修改。

+   `IntersectWith()`: 这执行两个集合的交集。当前集合对象被修改，以便它仅包含在提供的集合中也存在的元素。

+   `ExceptWith()`: 这执行集合减法。当前集合对象通过移除在提供的集合中也存在的所有元素来进行修改。

+   `SymmetricExceptWith()`: 这执行集合对称差。当前集合对象被修改为仅包含存在于集合或提供的集合中的元素，但不包含两者都存在的元素。

使用这些方法的示例在以下清单中显示：

```cs
HashSet<int> a = new HashSet<int>() { 1, 2, 5, 6, 9};
HashSet<int> b = new HashSet<int>() { 1, 2, 3, 4};
var s1 = new HashSet<int>(a);
s1.IntersectWith(b);               // 1 2
var s2 = new HashSet<int>(a);
s2.UnionWith(b);                   // 1 2 5 6 9 3 4
var s3 = new HashSet<int>(a);
s3.ExceptWith(b);                  // 5 6 9
var s4 = new HashSet<int>(a);
s4.SymmetricExceptWith(b);         // 4 3 5 6 9
```

除了这些数学集合操作，该类还提供了用于确定集合相等性、重叠或一个集合是否是另一个集合的子集或超集的方法。其中一些方法列在这里：

+   `Overlaps()` 确定当前集合和提供的集合是否包含任何共同元素。如果至少存在一个共同元素，则该方法返回`true`，否则返回`false`。

+   `IsSubsetOf()` 确定当前集合是否是另一个集合的子集，这意味着它的所有元素也存在于另一个集合中。空集是任何集合的子集。

+   `IsSupersetOf()` 确定当前集合是否是另一个集合的超集，这意味着当前集合包含另一个集合的所有元素。

使用这些方法的示例在以下片段中显示：

```cs
HashSet<int> a = new HashSet<int>() { 1, 2, 5, 6, 9 };
HashSet<int> b = new HashSet<int>() { 1, 2, 3, 4 };
HashSet<int> c = new HashSet<int>() { 2, 5 };
Console.WriteLine(a.Overlaps(b));     // True
Console.WriteLine(a.IsSupersetOf(c)); // True
Console.WriteLine(c.IsSubsetOf(a));   // True
```

`HashSet<T>`类包含其他方法和属性。您应该查看在线文档以获取该类成员的完整参考。

## 选择正确的集合类型

到目前为止，我们已经看过最常用的泛型集合类型，尽管基类库提供了更多。在单独查看每个集合后出现的关键问题是何时应该使用这些集合。在本节中，我们将提供一些选择正确集合的指南。让我们来看一下：

+   `List<T>` 是在需要连续存储元素并直接访问它们时的默认集合，而且没有其他特定约束时可以使用。列表的元素可以通过它们的索引直接访问。在末尾添加和删除元素非常高效，但在开头或中间这样做是昂贵的，因为它涉及移动至少一些元素。

+   `Stack<T>` 是在需要按 LIFO 方式检索后通常丢弃元素的顺序列表时的典型选择。元素从栈顶添加和移除，这两个操作都需要恒定时间。

+   `Queue<T>` 是在需要按 FIFO 方式检索后也通常丢弃元素的顺序列表时的一个不错的选择。元素在末尾添加并从队列顶部移除。这两个操作都非常快。

+   `LinkedList<T>` 在需要快速添加和删除列表中的许多元素时非常有用。然而，这是以牺牲通过索引随机访问列表元素的能力为代价。链表不会连续存储其元素，您必须从一端遍历列表以找到一个元素。

+   `Dictionary<TKey, TValue>` 应该在需要存储与键关联的值时使用。插入、删除和查找都非常快 - 无论字典的大小如何，都需要恒定时间。实现使用哈希表，这意味着键被哈希，因此键的类型必须实现 `GetHashCode()` 和 `Equals()`。或者，您需要在构建字典对象时提供 `IEqualityComparer` 实现。字典的元素是无序存储的，这会阻止您以特定顺序遍历字典中的值。

+   `HashSet<T>` 是在需要唯一值列表时可以使用的集合。插入、删除和查找非常高效。元素无序但连续存储。哈希集合在逻辑上类似于字典，其中值也是键，尽管它是一个非关联容器。因此，其元素的类型必须实现 `GetHashCode()` 和 `Equals()`，或者在构建哈希集合时必须提供 `IEqualityComparer` 实现。

以下表格总结了前面列表中的信息：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-prog/img/Chapter_7Table_1_01.jpg)

如果性能对您的应用程序至关重要，那么无论您基于指南和最佳实践做出何种选择，都很重要的是要进行测量，以查看所选的集合类型是否符合您的要求。此外，请记住，基类库中有比本章讨论的更多的集合。在某些特定场景中，`SortedList<TKey, TValue>`、`SortedDictionary<TKey, TValue>` 和 `SortedSet<T>` 也可能很有价值。

# 使用线程安全集合

到目前为止我们看到的泛型集合都不是线程安全的。这意味着在多线程场景中使用它们时，您需要使用外部锁来保护对这些集合的访问，这在许多情况下可能会降低性能。.NET 提供了几种线程安全的集合，它们使用高效的锁定和无锁同步机制来实现线程安全。这些集合提供在 `System.Collections.Concurrent` 命名空间中，并应在多个线程同时访问集合的场景中使用。然而，实际的好处可能比使用外部锁保护的标准集合要小或大。本节稍后将讨论这个问题。

信息框

多线程和异步编程的主题将在*第十二章*中进行讨论，*多线程和异步编程*，您将学习有关线程和任务、同步机制、等待/异步模型等内容。

尽管`System.Collections.Concurrent`命名空间中的集合是线程安全的，但不能保证通过扩展方法或显式接口实现对其元素的访问也是线程安全的，可能需要调用者进行额外的显式同步。

线程安全的通用集合是可用的，并将在以下小节中进行讨论。

## IProducerConsumerCollection<T>

这不是一个实际的集合，而是一个定义了操作线程安全集合的方法的接口。它提供了两个名为`TryAdd()`和`TryTake()`的方法，可以以线程安全的方式向集合添加和移除元素，并且还支持使用`CancellationToken`对象进行取消。

此外，它还有一个`ToArray()`方法，它将元素从基础集合复制到一个新数组，并且有`CopyTo()`的重载，它将集合的元素复制到从指定索引开始的数组。所有实现都必须确保此接口的所有方法都是线程安全的。`ConcurrentBag<T>`、`ConcurrentStack<T>`、`ConcurrentQueue<T>`和`BlockingCollection<T>`都实现了这个接口。如果标准实现不满足您的需求，您也可以提供自己的实现。

## BlockingCollection<T>

这是一个实现了`IProducerConsumerCollection<T>`接口定义的生产者-消费者模式的类。它实际上是`IProducerConsumerCollection<T>`接口的简单包装器，并没有内部基础存储；相反，必须提供一个（实现了`IProducerConsumerCollection<T>`接口的集合）。如果没有提供实现，它将默认使用`ConcurrentQueue<T>`类。

`BlockingCollection<T>`类支持**限制**和**阻塞**。限制意味着您可以设置集合的容量。这意味着当集合达到最大容量时，任何生产者（向集合添加元素的线程）将被阻塞，直到消费者（从集合中移除元素的线程）移除一个元素。

另一方面，任何想要在集合为空时移除元素块的消费者，直到生产者向集合添加元素。添加和移除可以使用`Add()`和`Take()`，也可以使用`TryAdd()`和`TryTake()`版本，与前者不同，它们支持取消操作。还有一个`CompleteAdding()`方法，它将集合标记为完成，这种情况下进一步添加将不再可能，并且在集合为空时尝试移除元素将不再被阻塞。

让我们看一个例子来理解这是如何工作的。在以下示例代码中，我们有一个任务正在向`BlockingCollection<int>`中生产元素，还有两个任务正在从中消费。集合创建如下：

```cs
using var bc = new BlockingCollection<int>();
```

这使用了类的默认构造函数，它将使用`ConcurrentQueue<int>`类作为集合的基础存储来实例化它。生产者任务使用阻塞集合添加数字，在这种特殊情况下是斐波那契序列的前 12 个元素。请注意，最后，我们调用`CompleteAdding()`来标记集合为完成。进一步尝试添加将失败：

```cs
using var producer = Task.Run(() => {
   int a = 1, b = 1;
   bc.Add(a);
   bc.Add(b);
   for(int i = 0; i < 10; ++i)
   {
      int c = a + b;
      bc.Add(c);
      a = b;
      b = c;
   }
   bc.CompleteAdding();
});
```

第一个消费者是一个任务，它通过集合无限迭代，每次取一个元素。如果集合为空，调用`Take()`会阻塞调用线程。但是，如果集合为空并且已标记为完成，该操作将抛出`InvalidOperationException`：

```cs
using var consumer1 = Task.Run(() => { 
   try
   {
      while (true)
         Console.WriteLine($"[1] {bc.Take()}");
   }
   catch (InvalidOperationException)
   {
      Console.WriteLine("[1] collection completed");
   }
   Console.WriteLine("[1] work done");
});
```

第二个消费者是一个执行非常相似工作的任务。但是，它使用`foreach`语句而不是使用无限循环。这是因为`BlockingCollection<T>`有一个名为`GetConsumingEnumerable()`的方法，它检索`IEnumerable<T>`，使得可以使用`foreach`循环或`Parallel.ForEach`从集合中移除项目。

与无限循环不同，枚举器提供项目，直到集合被标记为已完成。如果集合为空但未标记为已完成，则该操作将阻塞，直到有一个项目可用。在调用`GetConsumingEnumerable()`时，检索操作也可以通过使用`CancellationToken`对象进行取消：

```cs
using var consumer2 = Task.Run(() => {
   foreach(var n in bc.GetConsumingEnumerable())
      Console.WriteLine($"[2] {n}");
   Console.WriteLine("[2] work done");
});
```

有了这三个任务，我们应该等待它们全部完成：

```cs
await Task.WhenAll(producer, consumer1, consumer2); 
```

执行此示例的可能输出如下：

![图 7.7 - 前面片段执行的可能输出。](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-prog/img/Figure_7.7_B12346.jpg)

图 7.7 - 前面片段执行的可能输出。

请注意，输出将因不同运行而异（这意味着处理元素的顺序将不同且来自同一任务）。

## ConcurrentQueue<T>

这是一个队列（即 FIFO 集合）的线程安全实现。它提供了三种方法：`Enqueue()`，将元素添加到集合的末尾，`TryPeek()`，尝试返回队列开头的元素而不移除它，`TryDequeue()`，尝试移除并返回集合开头的元素。它还为`IProducerConsumerCollection<T>`接口提供了显式实现。

## ConcurrentStack<T>

这个类实现了一个线程安全的堆栈（即 LIFO 集合）。它提供了四种方法：`Push()`，在堆栈顶部添加一个元素，`TryPeek()`，尝试返回顶部的元素而不移除它，`TryPop()`，尝试移除并返回顶部的元素，`TryPopRange()`，尝试移除并返回堆栈顶部的多个对象。此外，它还为`IProducerConsumerCollection<T>`接口提供了显式实现。

## ConcurrentBag<T>

这个类表示一个线程安全的无序对象集合。当您想要存储对象（包括重复项）且它们的顺序不重要时，这可能很有用。该实现针对同一线程既是生产者又是消费者的情况进行了优化。添加使用`Add()`完成，移除使用`TryPeek()`和`TryTake()`完成。您还可以通过调用`Clear()`来移除包中的所有元素。与并发堆栈和队列实现一样，该类还为`IProducerConsumerCollection<T>`接口提供了显式实现。

## ConcurrentDictionary<TKey, TValue>

这代表了一个线程安全的键值对集合。它提供了诸如`TryAdd()`（尝试添加新的键值对）、`TryUpdate()`（尝试更新现有项）、`AddOrUpdate()`（添加新项或更新现有项）和`GetOrAdd()`（检索现有项或添加新项（如果找不到键））等方法。

这些操作是原子的，并且是线程安全的，但其重载除外，它们采用委托。这些在锁之外执行，因此它们的代码不是操作的原子性的一部分。此外，`TryGetValue()`尝试获取指定键的值，`TryRemove()`尝试移除并返回与指定键关联的值。

## 选择正确的并发集合类型

现在我们已经了解了并发集合是什么，重要的问题是何时应该使用它们，特别是与非线程安全集合相关。一般来说，您可以按以下方式使用它们：

+   `BlockingCollection<T>`用于需要边界和阻塞场景。

+   当处理时间至少为 500 时，应优先选择`ConcurrentQueue<T>`而不是带有外部锁的`Queue<T>`。`ConcurrentQueue<T>`在一个线程进行入队操作，另一个线程进行出队操作时表现最佳。

+   如果同一个线程可以添加或移除元素，则应优先选择`ConcurrentStack<T>`而不是带有外部锁的`Stack<T>`，在这种情况下，无论处理时间长短都更快。然而，如果一个线程添加，另一个线程移除元素，则`ConcurrentStack<T>`和带有外部锁的`Stack<T>`的性能相对相同。但是当线程数量增加时，`Stack<T>`实际上可能表现更好。

+   在所有同时进行多线程添加和更新的场景中，`ConcurrentDictionary<TKey, TValue>`的性能优于`Dictionary<TKey, TValue>`，尽管如果更新频繁但读取很少，则好处非常小。如果读取和更新都频繁，那么`ConcurrentDictionary<TKey, TValue>`会显著更快。`Dictionary<TKey, TValue>`只适用于所有线程只进行读取而不进行更新的场景。

+   `ConcurrentBag<T>`适用于同一个线程既添加又消耗元素的场景。然而，在只添加或只移除的场景中，它比所有其他并发集合都慢。

请记住，前面的列表只代表指南和一般行为，可能并不适用于所有情况。一般来说，当你处理并发和并行时，你需要考虑你的场景的特定方面。无论你使用什么算法和数据结构，你都必须对它们的执行进行分析，看它们的表现如何，无论是与顺序实现还是其他并发替代方案相比。

# 总结

在本章中，我们了解了.NET 中的通用集合，它们模拟的数据结构以及它们实现的接口。我们看了`System.Collections.Generic`命名空间中最重要的集合，`List<T>`、`Stack<T>`、`Queue<T>`、`LinkedList<T>`、`Dictionary<TKey, TValue>`和`HashSet<T>`，并学习了如何使用它们以及执行添加、移除或搜索元素等操作。在本章的最后部分，我们还看了`System.Collection.Concurrent`命名空间和它提供的线程安全集合。然后，我们了解了每个集合的特点以及它们适合使用的典型场景。

在下一章中，我们将探讨一些高级主题，如委托和事件、元组、正则表达式、模式匹配和扩展方法。

# 测试你所学到的知识

1.  通用集合位于哪个命名空间下？

1.  所有定义通用集合功能的其他接口的基本接口是什么？

1.  使用通用集合而不是非通用集合的好处是什么？

1.  `List<T>`是什么，如何向其中添加或移除元素？

1.  `Stack<T>`是什么，如何向其中添加或移除元素？

1.  `Queue<T>`是什么？它的`Dequeue()`和`Peek()`方法有什么区别？

1.  `LinkedList<T>`是什么？你可以使用哪些方法向集合中添加元素？

1.  `Dictionary<K, V>`是什么，它的元素是什么类型？

1.  `HashSet<T>`是什么，它与`Dictionary<K, V>`有什么不同？

1.  `BlockingCollection<T>`是什么？它适用于哪些并发场景？


# 第八章：高级主题

在前几章中，我们学习了语言语法、数据类型、类和结构的使用、泛型、集合等主题，这些知识使你能够编写至少简单的 C#程序。然而，语言还有更多内容，本章中我们将探讨更高级的概念。这将包括委托，它对于我们后面在本书中涵盖的函数式和异步编程至关重要，以及各种形式的模式匹配，包括用于文本的正则表达式。

我们将讨论的主题如下：

+   委托和事件

+   匿名类型

+   元组

+   模式匹配

+   正则表达式

+   扩展方法

完成本章后，你将了解如何使用委托来响应应用程序中发生的事件，如何使用元组处理多个值而不引入新类型，如何在代码中执行模式匹配，以及如何使用正则表达式搜索和替换文本。最后但同样重要的是，你将学会如何使用扩展方法在不修改其实际源代码的情况下扩展类型。

让我们通过学习委托和事件来开始本章。

# 委托和事件

**回调**是一个函数（或更一般地说，任何可执行代码），它作为参数传递给另一个函数，以便立即调用（**同步回调**）或在以后的某个时间调用（**异步回调**）。操作系统（如 Windows）广泛使用回调来允许应用程序响应鼠标事件或按键事件等事件。回调的另一个典型例子是通用算法，它使用回调来处理来自集合的元素，例如比较它们以对其进行排序或筛选。

在诸如 C 和 C++之类的语言中，回调只是一个*函数指针*（即函数的地址）。然而，在.NET 中，回调是*强类型对象*，它不仅保存了一个或多个方法的引用，还保存了关于它们的参数和返回类型的信息。在.NET 和 C#中，回调由委托表示。

## 委托

`delegate`关键字。声明看起来像一个函数签名，但编译器实际上引入了一个类，该类可以保存与委托签名匹配的方法的引用。委托可以保存对*静态*或*实例方法*的引用。

为了更好地理解委托的定义和使用方式，我们将考虑以下例子。

我们有一个表示引擎的类。引擎可以做不同的事情，但我们将专注于启动和停止这个引擎。当这些事件发生时，我们希望让使用引擎的客户端知道这一点，并给他们机会做一些事情。简单起见，客户端只会将事件记录到控制台。在这个简单的模型中，引擎可以处于这两种状态中的任何一种：`StatusChange`：

```cs
public enum Status { Started, Stopped }
public delegate void StatusChange(Status status);
```

`StatusChange`不是一个函数，而是一个*类型*。我们将用它来声明引擎中保存回调方法引用的变量。表示引擎的类如下：

```cs
public class Engine
{
    private StatusChange statusChangeHandler;
    public void RegisterStatusChangeHandler(StatusChange handler)
    {
        statusChangeHandler = handler;
    }
    public void Start()
    {
        // start the engine
        if (statusChangeHandler != null)
            statusChangeHandler(Status.Started);
    }
    public void Stop()
    {
        // stop the engine
        if (statusChangeHandler != null)
            statusChangeHandler(Status.Stopped);
    }
}
```

这里有几件事情需要注意：

+   首先，`RegisterStatusChangeHandler()` 方法接受委托类型（`StatusChange`）的参数，并将其分配给`statusChangeHandler`成员字段。

+   其次，`Start()`和`Stop()`方法实际上并没有做太多事情（仅为简单起见），但你可以想象它们正在启动和停止引擎。然而，在此之后，它们调用回调函数，就像普通函数一样，传递所有必要的参数。

+   在这个例子中，委托不返回任何值，但委托可以返回任何东西。然而，在调用回调方法之前，会执行*空引用检查*。如果委托没有被分配到一个方法的引用，调用委托会导致`NullReferenceException`。

客户端代码创建了`Engine`类的一个实例，注册了状态更改的处理程序，然后启动和停止它。代码如下：

```cs
class Program
{
    static void Main(string[] args)
    {
        Engine engine = new Engine();
        engine.RegisterStatusChangeHandler
          (OnEngineStatusChanged); 
        engine.Start();
        engine.Stop();
    }
    private static void OnEngineStatusChanged(Status status)
    {
        Console.WriteLine($"Engine is now {status}");
    }
}
```

静态方法`OnEngineStatusChanged()`用作引擎启动和停止事件的回调。其签名与委托的类型匹配。执行此程序将产生以下输出：

```cs
Engine is now Started
Engine is now Stopped
```

.NET 委托的一个重要方面是它们支持*多播*。这意味着您实际上可以设置对要调用的任意多个方法的引用；然后委托将按照它们被添加的顺序调用它们。多播委托由`System.MulticastDelegate`类表示。该类在内部具有称为*调用列表*的委托链表。此列表可以有任意数量的元素。当调用多播委托时，调用列表中的所有委托按照它们在列表中出现的顺序（即它们被添加的顺序）被调用。此操作是同步的，如果在调用列表的执行过程中出现任何错误，将抛出异常。

另一方面，当您不再希望调用某个方法时，可以从委托中移除对该方法的引用。这两个方面将在以下示例中得到说明，其中我们改变了`Engine`类以允许多个回调不仅被注册，而且还可以被注销：

```cs
public class Engine
{
    private StatusChange statusChangeHandler;
    public void RegisterStatusChangeHandler(StatusChange handler)
    {
        statusChangeHandler += handler;
    }
    public void UnregisterStatusChangeHandler(StatusChange handler)
    {
        statusChangeHandler -= handler;
    }
    public void Start()
    {
        statusChangeHandler?.Invoke(Status.Started);
    }
    public void Stop()
    {
        statusChangeHandler?.Invoke(Status.Stopped);
    }
}
```

再次，这里有两件事需要注意：

+   首先，`RegisterStatusChangeHandler()`方法不再简单地将其参数分配给`statusChangeHandler`字段，而是实际上使用`+=`运算符向委托内部持有的列表添加一个新引用。因此，`UnregisterStatusChangeHandler()`方法使用`-=`运算符从委托中移除一个引用。`+=`和`-=`运算符已被委托类型重载。

+   其次，`Start()`和`Stop()`中的代码略有改变。使用空值条件运算符（`?.`）仅在对象不为`null`时调用`Invoke()`方法。

另一方面，主程序中的更改如下：

```cs
class Program
{
    static void Main(string[] args)
    {
        Engine engine = new Engine();
        engine.RegisterStatusChangeHandler
          (OnEngineStatusChanged); 
        engine.RegisterStatusChangeHandler
          (OnEngineStatusChanged2); 
        engine.Start();
        engine.Stop();
        engine.UnregisterStatusChangeHandler
          (OnEngineStatusChanged2);
        engine.Start();
    }
    private static void OnEngineStatusChanged(Status status)
    {
        Console.WriteLine($"Engine is now {status}");
    }
    private static void OnEngineStatusChanged2(Status status)
    {
        File.AppendAllText(@"c:\temp\engine.log",
                           $"Engine is now {status}\n");
    }
}
```

这次，我们注册了两个回调：

+   一个在*控制台*上记录事件。

+   一个记录到*文件*的回调。

我们启动和停止引擎，然后注销记录到磁盘文件的回调函数。最后，我们再次启动引擎。因此，控制台上的输出将如下所示：

```cs
Engine is now Started
Engine is now Stopped
Engine is now Started
```

然而，只有前两行也出现在磁盘文件上，因为在重新启动引擎之前已经移除了第二个回调函数。

在这个第二个示例中，我们使用`Invoke()`方法调用委托引用的方法。`Invoke()`方法是从哪里来的呢？在幕后，当您声明委托类型时，编译器会生成一个从`System.MulticastDelegate`派生的密封类，该类又从`System.Delegate`派生。这些都是您不允许显式派生的系统类型。但是，它们提供了我们迄今为止看到的所有功能，例如能够向委托的调用列表中添加和移除方法的能力。

编译器创建的类包含三种方法——`Invoke()`（用于以*同步方式*调用回调函数）、`BeginInvoke()`和`EndInvoke()`（用于以*异步方式*调用回调函数）。有关异步委托的示例，请参考其他参考资料。您实际上可以通过在反汇编器（如**ildasm.exe**或**ILSpy**）中打开程序集来检查编译器生成的代码。

## 事件

到目前为止，我们编写的代码有点太*显式*了。我们不得不创建方法来注册和取消注册对回调方法的引用。这是因为在类中，持有这些引用的委托是私有的。我们可以将其设为公共的，但这样会破坏封装性，并有风险允许客户端错误地覆盖委托的调用列表。为了帮助处理这些方面，.NET 和 C#提供了*事件*，它们只是我们之前为注册和取消注册回调编写的显式代码的语法糖。事件是用`event`关键字引入的。

引擎的最后一个实现将更改为以下内容：

```cs
public class Engine
{
    public event StatusChange StatusChanged;
    public void Start()
    {
        StatusChanged?.Invoke(Status.Started);
    }
    public void Stop()
    {
        StatusChanged?.Invoke(Status.Stopped);
    }
}
```

请注意，我们不再有用于注册和取消注册回调的方法，只有一个名为`StatusChanged`的事件对象。这些是在客户端代码中在事件对象上完成的，使用`+=`（添加对方法的引用）和`-=`（删除对方法的引用）操作符。我们可以在以下代码中看到客户端代码。

在这个例子中，我们创建了一个`Engine`对象，并为`StatusChanged`事件注册了回调函数——一个是对`OnEngineStatusChanged()`方法的引用（将事件记录到文件中），另一个是一个 lambda 表达式（将事件记录到控制台）：

```cs
class Program
{
    static void Main(string[] args)
    {
        Engine engine = new Engine();
        engine.StatusChanged += OnEngineStatusChanged;
        engine.StatusChanged += 
            status => Console.WriteLine(
                        $"Engine is now {status}");
        engine.Start();
        engine.Stop();
        engine.StatusChanged -= OnEngineStatusChanged;
        engine.Start();
    }
    private static void OnEngineStatusChanged(Status status)
    {
        File.AppendAllText(@"c:\temp\engine.log",
                           $"Engine is now {status}\n");
    }
}
```

启动和停止引擎后，我们取消对`OnEngineStatusChanged()`的引用，然后重新启动引擎。执行此程序的结果与先前的程序相同。

到目前为止，所有的例子中，委托类型都有一个参数，即引擎的状态。然而，事件模式的正确实现（在整个.NET Framework 中都使用）是有两个参数：

+   第一个参数是`System.Object`，它保存了生成事件的对象的引用。由调用的客户端决定是否使用此引用。

+   第二个参数是从`System.EventArgs`派生的类型，其中包含与事件相关的所有信息。

为了符合这种模式，我们的`Engine`的实现将更改为以下内容：

```cs
public class EngineEventArgs : EventArgs
{
    public Status Status { get; private set; }
    public EngineEventArgs(Status s)
    {
        Status = s;
    }
}
public delegate void StatusChange(
         object sender, EngineEventArgs args);
public class Engine
{
    public event StatusChange StatusChanged;
    public void Start()
    {
        StatusChanged?.Invoke(this, 
           new EngineEventArgs(Status. Started));
    }
    public void Stop()
    {
        StatusChanged?.Invoke(this, 
           new EngineEventArgs(Status.Stopped));
    }
}
```

我们将留给读者练习对主程序进行必要的更改，以使用`Engine`类的新实现。

有关委托和事件的关键要点如下：

+   委托允许将方法作为参数传递，以便稍后调用，可以同步或异步调用。

+   委托支持多播，即调用多个回调方法。

+   静态方法、实例方法、匿名方法和 lambda 表达式都可以作为委托的回调使用。

+   委托可以是泛型的。

+   事件是一种语法糖，有助于注册和移除回调。

本章讨论的下一个主题是匿名类型。

# 匿名类型

有时需要构造临时对象来保存一些值，通常是某个较大对象的子集。为了避免仅为此目的创建特定类型，语言提供了所谓的*匿名类型*。这些是一种使用后即忘记的类型，通常与**语言集成查询**（**LINQ**）一起在查询表达式中使用。这个主题将在*第十章*中讨论，*Lambda、LINQ 和函数式编程*。

这些类型被称为匿名，因为在源代码中没有指定名称。名称由编译器分配。它们只包含只读属性；不允许任何其他成员类型。只读属性的类型不能显式指定，而是由编译器推断。

使用`new`关键字引入匿名类型，后面跟着一系列属性（对象初始化器）的尖括号。以下代码片段显示了一个例子：

```cs
var o = new { Name = "M270 Turbo", Capacity = 1600, 
Power = 75.0 };
Console.WriteLine($"{o.Name} {o.Capacity / 1000.0}l 
{o.Power}kW");
```

在这里，我们定义了一个具有三个属性`Name`、`Capacity`和`Power`的匿名类型。这些属性的类型由编译器从它们的初始化值中推断出来。在这种情况下，它们分别是`Name`的`string`，`Capacity`的`int`和`Power`的`double`。

当从表达式初始化属性时，必须指定属性的名称。但是，如果它是从另一个对象的字段或属性初始化的，名称是可选的。在这种情况下，编译器使用与用于初始化它的成员相同的名称。举个例子，让我们考虑以下类型：

```cs
class Engine
{
    public string Name { get; }
    public int Capacity { get; }
    public double Power { get; }

    public Engine(string name, int capacity, double power)
    {
        Name = name;
        Capacity = capacity;
        Power = power;
    }
}
```

有了这个，我们可以写如下：

```cs
var e = new Engine("M270 Turbo", 1600, 75.0);
var o = new { e.Name, e.Power };
Console.WriteLine($"{o.Name} {o.Power}kW");
```

我们已经创建了`Engine`类的一个实例。从这个实例中，我们创建了另一个匿名类型的对象，它有两个属性，编译器称之为`Name`和`Power`，因为它们是从`Engine`类的`Name`和`Power`属性初始化的。

匿名类型具有以下属性：

+   它们被实现为密封类，因此是引用类型。CLI 不会区分匿名类型和其他引用类型。

+   它们直接派生自`System.Object`，只能转换为`System.Object`。

+   它们只能包含只读属性。不允许其他成员。

+   它们不能用作字段、属性、事件、方法的返回类型或方法、构造函数或索引器的参数类型。

+   您可以为匿名类型的只读属性指定名称。这在从表达式初始化时是强制性的，但在从字段或属性初始化时是可选的。在这种情况下，编译器使用成员的名称作为属性的名称。

+   用于初始化属性的表达式不能为 null、匿名函数或指针类型。

+   匿名类型的作用域是定义它的方法。

+   当声明匿名类型的变量时，必须使用`var`作为类型名称的占位符。

元组提供了一种类似的临时类型概念，但具有不同的语义，这是下一节的主题。

# 元组

`out`或`ref`参数，或者当您想要将多个值作为单个对象传递给方法时。

这个方面代表了匿名类型和元组之间的关键区别。前者用于在单个方法的范围内使用，不能作为参数传递或从方法返回。后者则是为了这个确切的目的而设计的。

在 C#中，有两种类型的元组：

+   `System.Tuple`类

+   `System.ValueTuple`结构

在下一小节中，我们将看看这两种类型。

## 元组类

引用元组是在.NET Framework 4.0 中引入的。泛型类`System.Tuple`可以容纳最多八个不同类型的值。如果需要超过八个值的元组，您将不得不创建嵌套元组。元组可以通过以下两种方式实例化：

+   通过使用`Tuple<T>`的*构造函数*

+   通过使用*辅助方法*，`Tuple.Create()`

以下两行是等价的：

```cs
var engine = new Tuple<string, int, double>("M270 Turbo", 1600, 75);
var engine = Tuple.Create("M270 Turbo", 1600, 75);
```

这里的第二行更好，因为它更简单，你不必指定每个值的类型。这是因为编译器从参数中推断出类型。

元组的元素可以通过名为`Item1`、`Item2`、`Item3`、`Item4`、`Item5`、`Item6`、`Item7`和`Rest`的属性访问。在下面的示例中，我们使用`Item1`、`Item2`和`Item3`属性将引擎名称、容量和功率打印到控制台上：

```cs
Console.WriteLine(
    $"{engine.Item1} {engine.Item2/1000.0}l {engine.Item3}kW");
```

当需要超过八个元素时，可以使用嵌套元组。在这种情况下，将嵌套元组放在最后一个元素是有意义的。以下示例创建了一个具有 10 个值的元组，其中最后三个值（表示不同功率的发动机功率，单位为千瓦）被分组在第二个嵌套元组中：

```cs
var engine = Tuple.Create(
    "M270 DE16 LA R", 1595, 83, 73.7, 180, "gasoline", 2015, 
    Tuple.Create(75, 90, 115));
Console.WriteLine($"{engine.Item1} powers: {engine.Rest.Item1}");
```

请注意这里我们使用的是`Rest.Item1`而不是简单的`Rest`。该程序的输出如下：

```cs
M270 DE16 LA R powers: (75, 90, 115)
```

这是因为变量 engine 的推断类型是 `Tuple<string, int, int, double, int, string, int, Tuple<Tuple<int, int, int>>>`。因此，`Rest` 表示一个包含单个值的元组，该值也是包含三个 `int` 值的元组。要访问嵌套元组的元素，您必须使用，对于这种情况，`Rest.Item1.Item1`、`Rest.Item1.Item2` 和 `Rest.Item1.Item3`。

要创建类型为 `Tuple<string, int, int, double, int, string, int, Tuple<int, int, int>>` 的元组，必须使用构造函数的显式语法：

```cs
var engine = new Tuple<string, int, int, double, int, string, int, Tuple<int, int, int>>
    ("M270 DE16 LA R", 1595, 83, 73.7, 180, "gasoline", 2015,
    new Tuple<int, int, int>(75, 90, 115));
Console.WriteLine($"{engine.Item1} powers: {engine.Rest}");
```

`System.Tuple` 是一个引用类型，因此此类型的对象分配在堆上。如果在程序执行过程中发生许多小对象的分配，可能会影响性能。

这增加了我们之前看到的限制——元素数量和未命名属性。为了克服这些问题，C# 7.0、.NET Framework 4.7 和 .NET Standard 2.0 引入了值类型元组，我们将在下一节中探讨。

## 值元组

这些由 `System.ValueTuple` 结构表示。如果您的项目不针对 .NET Framework 4.7 或更高版本，或 .NET Standard 2.0 或更高版本，您仍然可以通过将其安装为 NuGet 包来使用 `ValueTuple`。

在几个 7.x 版本的语言中添加了各种值元组功能。这里描述的功能与 C# 8 对齐。

除了值语义之外，值元组在几个重要方面与引用元组不同：

+   它们可以容纳任意数量的元素序列，但至少需要两个。

+   它们可能具有编译时命名字段。

+   它们具有更简单但更丰富的语法，用于创建、赋值、解构和比较值。

使用*括号语法*和指定的值来创建值元组。以下三个声明是等价的：

```cs
ValueTuple<string, int, double> engine = ("M270 Turbo", 1600, 75.0);
(string, int, double) engine = ("M270 Turbo", 1600, 75.0);
var engine = ("M270 Turbo", 1600, 75.0);
```

在所有这些情况下，变量 engine 的类型是 `ValueTuple<string, int, double>`，元组被称为*未命名*。在这种情况下，它的值可以在公共字段中访问——`Item1`、`Item2` 和 `Item3`，这些是编译器隐式分配的名称：

```cs
Console.WriteLine(
    $"{engine.Item1} {engine.Item2/1000.0}l {engine.Item3}kW");
```

但是，在创建值元组时，您可以选择为值指定名称，从而为字段创建同义词，如 `Item1`、`Item2` 等。这种值元组称为**命名元组**。您可以在以下代码片段中看到一个命名元组的示例：

```cs
var engine = (Name: "M270 Turbo", Capacity: 1600, Power: 75.0);
Console.WriteLine(
    $"{engine.name} {engine.capacity / 1000.0}l {engine.power}kW");
```

这些同义词仅在编译时可用，因为 IDE 利用 Roslyn API 从源代码中为您提供它们，但在编译器中间语言代码中，它们不可用，只有未命名字段——`Item1`、`Item2` 等。

字段的名称可以出现在赋值的任一侧；此外，它们可以同时出现在两侧，在这种情况下，*左侧名称* 将*优先*，*右侧名称* 将*被忽略*。以下两个声明将产生一个与前面代码中看到的命名值元组相同的命名值元组：

```cs
(string Name, int Capacity, double Power) engine = 
    ("M270 Turbo", 1600, 75.0);
(string Name, int Capacity, double Power) engine = 
    (name: "M270 Turbo", cap: 1600, pow: 75.0);
```

字段的名称也可以从用于初始化值元组的变量中推断出（如 C# 7.1）。在以下示例中，值元组将具有名为 `name`、`capacity`（小写）和 `Item3` 的字段，因为最后一个值是一个没有明确指定名称的文字：

```cs
var name = "M270 Turbo";
var capacity = 1600;
var engine = (name, capacity, 75);
Console.WriteLine(
    $"{engine.name} {engine.capacity / 1000.0}l {engine.Item3}kW");
```

从方法返回值元组非常简单。在以下示例中，`GetEngine()` 函数返回一个未命名的值类型：

```cs
(string, int, double) GetEngine()
{
    return ("M270 Turbo", 1600, 75.0);
}
```

但是，您可以选择返回一个命名值类型，在这种情况下，您需要指定字段的名称，如下所示：

```cs
(string Name, int Capacity, double Power) GetEngine2()
{
    return ("M270 Turbo", 1600, 75.0);
}
```

从 C# 7.3 开始，可以使用`==`和`!=`运算符测试值元组的*相等性*和*不相等性*。这些运算符通过按顺序比较左侧的每个元素与右侧的每个元素来工作。当第一对不相等时，比较停止。但是，这仅在元组的形状相同时发生，即字段的数量和它们的类型。名称不参与相等性或不相等性的测试。下一个示例比较了两个值元组：

```cs
var e1 = ("M270 Turbo", 1600, 75.0);
var e2 = (Name: "M270 Turbo", Capacity: 1600, Power: 75.0);
Console.WriteLine(e1 == e2);
```

**元组相等**如果一个元组是可空元组，则执行*提升转换*，以及对两个元组的每个成员进行*隐式转换*。后者包括提升转换、扩展转换或其他隐式转换。例如，以下元组是相等的：

```cs
(int, long) t1 = (1, 2);
(long, int) t2 = (1, 2);
Console.WriteLine(t1 == t2);
```

可以解构元组的值。可以通过显式指定变量的类型或使用`var`来实现。以下声明都是等效的。在以下和最后一个示例中，`var`的使用与显式类型名称相结合：

```cs
(string name, int capacity, double power) = GetEngine();
(var name, var capacity, var power) = GetEngine();
var (name, capacity, power) = GetEngine();
(var name, var capacity, double power) = GetEngine();
```

如果有您不感兴趣的值，可以使用`_`占位符来忽略它们，如下所示：

```cs
(var name, _, _) = GetEngine();
```

可以对任何.NET 类型进行解构，只要提供了一个名为`Deconstruct`的方法，该方法具有您想要检索的每个值的`out`参数。

在下面的示例中，`Engine`类有三个属性：`Name`，`Capacity`和`Power`。`Deconstruct()`公共方法使用三个输出参数匹配这些属性。这使得可以使用元组语法对此类型的对象进行解构。以下清单显示了提供元组解构的`Engine`类的实现：

```cs
class Engine
{
    public string Name { get; }
    public int Capacity { get; }
    public double Power { get; }
    public Engine(string name, int capacity, double power)
    {
        Name = name;
        Capacity = capacity;
        Power = power;
    }
    public void Deconstruct(out string name, out int capacity, 
                            out double power)
    {
        name = Name;
        capacity = Capacity;
        power = Power;
    }
}
var engine = new Engine("M270 Turbo", 1600, 75.0);
var (Name, Capacity, Power) = engine;
```

`Deconstruct`方法可以作为扩展方法提供，使您能够为您没有编写的类型提供解构语义，前提是您只需要解构通过类型的公共接口可访问的值。这里展示了一个示例：

```cs
class Engine
{
    public string Name { get; }
    public int Capacity { get; }
    public double Power { get; }
    public Engine(string name, int capacity, double power)
    {
        Name = name;
        Capacity = capacity;
        Power = power;
    } 
}
static class EngineExtension
{
    public static void Deconstruct(this Engine engine, 
                                   out string name, 
                                   out int capacity, 
                                   out double power)
    {
        name = engine.Name;
        capacity = engine.Capacity;
        power = engine.Power;
    }
}
```

如果您有一个类的层次结构，并且提供了`Deconstruct()`方法，则必须确保不会引入歧义，例如在不同重载具有相同数量的参数的情况下。应该注意，解构运算符不参与测试相等性。因此，以下示例将生成编译器错误：

```cs
var engine = new Engine("M270 Turbo", 1600, 75.0);
Console.WriteLine(engine == ("M270 Turbo", 1600, 75.0));
```

总结一下，C# 7 中对值元组的支持使得在关键场景中更容易使用元组，比如保存临时值或来自数据库的记录。这可以在不引入新类型或返回多个值的情况下完成，而不使用`out`或`ref`参数。通过值语义的性能优势以及基于名称的元素访问的改进，以及其他关键特性，命名值是本节开始时看到的引用类型元组的重要改进。

# 模式匹配

在`if`和`switch`语句中，我们检查对象是否具有某个值，然后继续从中提取信息。然而，这是一种基本形式的模式匹配。

在 C# 7 中，对`is`和`switch`语句添加了新的功能，以实现模式匹配功能，从而更好地分离数据和代码，并导致更简洁和可读的代码。C# 8 中的新功能扩展了模式匹配功能。您将在*第十五章*中了解这些内容，*C# 8 的新功能*。

## is 表达式

在运行时，`is`运算符检查对象是否与给定类型兼容（一般形式为`expr is type`）。然而，在 C# 7 中，这被扩展为包括几种形式的模式匹配：

+   `expr is type varname`形式，检查表达式是否可以转换为指定类型，如果可以，则将其转换为指定类型的变量。

+   `expr is constant`形式，检查表达式是否评估为指定的常量。特定常量是`null`，其模式为`expr is null`。

+   `expr is var varname`形式，总是成功并将值绑定到一个新的局部变量。与类型模式的一个关键区别是`null`总是匹配，并且新变量被赋值为`null`。

为了理解这些工作原理，我们将使用几个代表车辆的类：

```cs
class Airplane
{
    public void Fly() { }
}
class Bike
{
    public void Ride() { }
}
class Car
{
    public bool HasAutoDrive { get; }
    public void Drive() { }
    public void AutoDrive() { }
}
```

这些车辆类不是类层次结构的一部分，但它们有设置车辆运动的公共方法，根据其类型。例如，飞机飞行，自行车骑行，汽车驾驶。下一个代码清单显示了使用几种形式的模式匹配的函数：

```cs
void SetInMotion(object vehicle)
{
    if (vehicle is null)
        throw new ArgumentNullException(
            message: "Vehicle must not be null",
            paramName: nameof(vehicle));
    else if (vehicle is Airplane a)
        a.Fly();
    else if (vehicle is Bike b)
        b.Ride();
    else if (vehicle is Car c)
    {
        if (c.HasAutoDrive) c.AutoDrive();
        else c.Drive();
    }
    else
        throw new ArgumentException(
           message: "Unexpected vehicle type", 
           paramName: nameof(vehicle)); 
}
```

该函数根据其特定的方式使车辆运动起来。像`if(vehicle is Airplane a)`这样的语句测试变量 vehicle 是否可以转换为`Airplane`类型，如果是，则将其分配给`Airplane`类型的新变量（在本例中为`a`）。这适用于值类型和引用类型。

这里看到的变量`a`、`b`和`c`只在`if`或`else`语句的局部范围内。然而，只有在匹配成功时，这些变量才在范围内并被赋值。这可以防止您在模式匹配表达式未匹配时访问结果。

除了类型模式，这里还使用了常量模式。`if (vehicle is null)`语句是一个测试，用于查看引用是否实际设置为对象的实例；如果没有，就会抛出异常。然而，如前所述，常量模式匹配可以与任何常量一起使用——文字值、用 const 修饰符声明的变量，或者枚举值。常量表达式的评估方式如下：

+   如果`expr`和常量都是整数类型，它基本上评估`expr == constant`表达式。

+   否则，它调用静态方法`Object.Equals(expr, constant)`。

以下函数显示了更多的常量模式匹配示例。`IsTrue()`函数将提供的参数转换为布尔值。布尔值（`true`），整数值（`1`），字符串（`"1"`）和字符串（`"true"`）都转换为`true`；包括`null`在内的其他所有内容都转换为`false`：

```cs
bool IsTrue(object value)
{
    if (value is null) return false;
    else if (value is 1) return true;
    else if (value is true) return true;
    else if (value is "true") return true;
    else if (value is "1") return true;
    return false;
}
Console.WriteLine(IsTrue(null));   // False
Console.WriteLine(IsTrue(0));      // False
Console.WriteLine(IsTrue(1));      // True
Console.WriteLine(IsTrue(true));   // True
Console.WriteLine(IsTrue("true")); // True
Console.WriteLine(IsTrue("1"));    // True
Console.WriteLine(IsTrue("demo")); // False
```

## switch 表达式

您需要检查的模式越多，编写这些`if-else`语句就越繁琐。自然地，您会想用`switch`替换它们。相同类型的模式匹配也支持`switch`语句，具有类似的语法。

直到 C# 7.0，`switch`语句支持整数类型和字符串的常量模式匹配。自 C# 7.0 以来，前面看到的类型模式也支持在`switch`语句中。

在前一节中显示的`SetInMotion()`函数可以修改为使用`switch`语句：

```cs
void SetInMotion(object vehicle)
{
    switch (vehicle)
    {
        case Airplane a:
            a.Fly();
            break;
        case Bike b:
            b.Ride();
            break;
        case Car c:
            if (c.HasAutoDrive) c.AutoDrive();
            else c.Drive();
            break;
        case null:
            throw new ArgumentNullException(
                message: "Vehicle must not be null",
                paramName: nameof(vehicle));
        default:
            throw new ArgumentException(
               message: "Unexpected vehicle type", 
               paramName: nameof(vehicle));
    }
}
```

使用常量模式匹配的`switch`语句只能有一个与`switch`表达式的值匹配的情况标签。此外，`switch`部分不能穿过下一个部分，而必须以`break`、`return`或`goto`结束。然而，它们可以以任何顺序排列，而不会影响程序语义和执行的行为。

使用类型模式匹配，规则会发生变化。`switch`部分可以穿过下一个，`goto`不再支持作为跳转机制。情况标签表达式按照它们在文本中出现的顺序进行评估，只有在没有任何情况标签与模式匹配时才执行默认情况。默认情况可以出现在`switch`的任何位置，但始终在最后执行。

如果默认情况缺失，并且没有任何现有的情况标签与模式匹配，执行将在`switch`语句之后继续，而不会执行任何情况标签中的代码。

`switch`表达式的类型模式匹配还支持`when`子句。以下示例展示了`SetInMotion()`方法的另一个版本，它使用了两个 case 标签来匹配`Car`类型，但其中一个带有条件——即`Car`对象的`HasAutoDrive`属性设置为`true`：

```cs
void SetInMotion(object vehicle)
{
    switch (vehicle)
    {
        case Airplane a:
            a.Fly();
            break;
        case Bike b:
            b.Ride();
            break;
        case Car c when c.HasAutoDrive:
            c.AutoDrive();
            break;
        case Car c:
            c.Drive();
            break;
        case null:
            throw new ArgumentNullException(
                message: "Vehicle must not be null",
                paramName: nameof(vehicle));
        default:
            throw new ArgumentException(
              message: "Unexpected vehicle type", 
              paramName: nameof(vehicle)); 
    }
}
```

需要注意的是，匹配类型模式保证了*非空值*，因此不需要进一步测试`null`。对于在语言中匹配`null`有特殊规则。`null`值不匹配类型模式，无论变量的类型如何。可以在具有类型模式匹配的 switch 表达式中添加一个用于特别处理`null`值的模式匹配的 case 标签。在前面的实现中就有这样的例子。

一种特殊的类型模式匹配形式是使用`var`。规则与`is`表达式相似——类型是从 switch 表达式的静态类型中推断出来的，而`null`值总是匹配的。因此，在使用`var`模式时，您必须添加显式的`null`检查，因为值实际上可能是`null`。`var`声明可能与默认情况匹配相同的条件；在这种情况下，即使存在默认情况，它也永远不会执行。

让我们看一下以下函数，它执行作为字符串参数接收的命令：

```cs
void ExecuteCommand(string command)
{
    switch(command)
    {
        case "add":  /* add */    break;
        case "del":  /* delete */ break;
        case "exit": /* exit */   break;
        case var o when (o?.Trim().Length ?? 0) == 0:
            /* do nothing */
            break;
        default:
            /* invalid command */
            break;
    }
}
```

这个函数尝试匹配`add`、`del`和`exit`命令，并适当地执行它们。但是，如果参数是`null`、空或只包含空格，它将不执行任何操作。但这与不支持或无法识别的实际命令是不同的情况。`var`模式匹配有助于以简单而优雅的方式区分这两种情况。

以下是本主题的关键要点：

+   C# 7.0 中添加的模式匹配功能是对已有简单模式匹配能力的增量更新。

+   新支持的模式包括常量模式、类型模式和`var`模式。

+   模式匹配与`is`表达式和`switch`语句中的 case 块一起工作。

+   `switch`表达式模式匹配支持`where`子句。

+   `var`模式始终匹配任何值，包括`null`，因此需要进行`null`测试。

C# 8.0 还为 switch 表达式模式匹配引入了更多功能：属性模式、元组模式和位置模式。您可以在*第十五章*中了解这些内容，*C# 8 的新功能*。

# 正则表达式

另一种模式匹配形式是正则表达式。`System.Text.RegularExpressions`命名空间。在接下来的页面中，我们将看看如何使用这个类来匹配输入文本，找到其中的部分，或替换文本的部分。

正则表达式由常量（代表字符串集合）和操作符号（代表对这些集合进行操作的操作符）组成。构建正则表达式的实际语言比本章节的范围所能描述的更加复杂。如果您对正则表达式不熟悉，我们建议您使用其他资源来学习。您也可以使用在线工具（例如 https://regex101.com/或 https://regexr.com/）构建和测试您的正则表达式。

## 概述

.NET 中的正则表达式是基于 Perl 5 正则表达式构建的。因此，大多数 Perl 5 正则表达式与.NET 正则表达式兼容。另一方面，该框架支持另一种表达式风格，称为**ECMAScript**，这基本上是 JavaScript 的另一个名称（**ECMAScript**实际上是脚本语言的 ECMA 标准，JavaScript 是其最著名的实现）。但是，在使用正则表达式时，您必须明确指定此风格。自.NET 2.0 以来，.NET 正则表达式的实现保持不变，在.NET Core 中也是如此。

以下是此实现支持的一些功能：

+   不区分大小写匹配

+   从右到左搜索（用于具有从右到左书写系统的语言，如阿拉伯语、希伯来语或波斯语）

+   多行或单行搜索模式，改变一些符号的含义，如`ˆ`、`$`或`.`（点）

+   将正则表达式编译为程序集，并在使用模式搜索大量字符串时提高性能的可能性

+   无限宽度的后行断言使我们能够向后移动到任意长度，并在字符串中检查后行断言内的文本是否可以在那里匹配

+   字符类减法允许您从另一个字符类中指定一个字符类来减去

+   平衡组允许您确保子表达式与另一个子表达式匹配的类型数量相等

其中一些功能是通过作为`Regex`类构造函数参数提供的标志来启用的。`RegexOptions`枚举提供以下标志，可以组合使用：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-prog/img/Chapter_8_Table_1_01.jpg)

在我们转到下一节来看如何在 C#中实际使用正则表达式之前，还有两件重要的事情要提到：

+   首先，正则表达式具有一组特殊字符。其中之一是`\`（反斜杠）。与另一个文字字符结合使用时，这将创建一个具有特殊含义的新标记。例如，`\d`匹配 0 到 9 之间的任何单个数字。由于反斜杠在 C#中也是一个特殊字符，用于引入字符转义序列，因此在字符串中编写正则表达式时，您需要使用双反斜杠，例如`"(\\d+)"`。但是，您可以使用逐字字符串来避免这种情况，并保持正则表达式的自然形式。前面的示例可以写成`@"(\d+)"`。

+   另一个重要的事情是`Regex`类隐式假定要匹配的字符串采用 UTF-8 编码。这意味着`\w`、`\d`和`\s`标记匹配任何 UTF-8 代码点，该代码点是任何语言中的有效字符、数字或空白字符。例如，如果您使用`\d+`来匹配任意数量的数字，您可能会惊讶地发现它不仅匹配 0-9，还匹配以下字符：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-prog/img/Figure_8.1_B12346.jpg)

如果要将匹配限制为`\d`的英文数字，`\w`的英文数字和字母以及下划线，以及`\s`的标准空白字符，则需要使用`RegexOptions.ECMAScript`选项。

现在让我们看看如何定义正则表达式并使用它们来确定某些文本是否与表达式匹配。

## 匹配输入文本

正则表达式提供的最简单功能是检查输入字符串是否具有所需的格式。这对于执行验证非常有用，例如检查字符串是否是有效的电子邮件地址、IP 地址、日期等。

为了理解这是如何工作的，我们将验证输入文本是否是有效的 ISO 8061 日期。为简单起见，我们只考虑*YYYY-MM-DD*的形式，但是作为练习，您可以扩展此以支持其他格式。我们将用于此的正则表达式是`(\d{4})-(1[0-2]|0[1-9]|[0-9]{1})-(3[01]|[12][0-9]|0[1-9]|[1-9]{1})`。

分解成部分，子表达式如下：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-prog/img/Chapter_8_Table_2_01.jpg)

以下两个例子是等价的。`Regex`类对于`IsMatch()`有静态和非静态的重载，你可以使用任何一个得到相同的结果。其他方法也是如此，我们将在接下来的章节中看到，比如`Match()`、`Matches()`、`Replace()`和`Split()`：

```cs
var pattern = @"(\d{4})-(1[0-2]|0[1-9]|[1-9]{1})-(3[01]|[12][0-9]|0[1-9]|[1-9]{1})";
var success = Regex.IsMatch("2019-12-25", pattern);
// or
var regex = new Regex(pattern);
var success = regex.IsMatch("2019-12-25");
```

如果你只需要匹配一个模式一次或几次，那么你可以使用静态方法，因为它们更简单。然而，如果你需要匹配数万次或更多次相同的模式，使用类的实例并调用非静态成员可能更快。对于大多数常见的用法，情况并非如此。在下面的例子中，我们将只使用静态方法。

`IsMatch()`方法有一些重载，使我们能够为正则表达式指定选项和超时时间间隔。当正则表达式过于复杂，或者输入文本过长，解析所需的时间超过了期望的时间时，这是很有用的。看下面的例子：

```cs
var success = Regex.IsMatch("2019-12-25",
                            pattern,
                            RegexOptions.ECMAScript,
                            TimeSpan.FromMilliseconds(1));
```

在这里，我们启用了正则表达式的 ECMAScript 兼容行为，并设置了一毫秒的超时值。

现在我们已经看到了如何匹配文本，让我们学习如何搜索子字符串和模式的多次出现。

## 查找子字符串

到目前为止的例子中，我们只检查了输入文本是否符合特定的模式。但也可以获取有关结果的信息。例如，每个标题组中匹配的文本、整个匹配值、输入文本中的位置等。为了做到这一点，必须使用另一组重载。

`Match()`方法检查输入字符串中与正则表达式匹配的子字符串，并返回第一个匹配项。`Matches()`方法也进行相同的搜索，但返回所有匹配项。前者的返回类型是`System.Text.RegularExpressions.Match`（表示单个匹配项），后者的返回类型是`System.Text.RegularExpressions.MatchCollection`（表示匹配项的集合）。考虑下面的例子：

```cs
var pattern =
    @"(\d{4})-(1[0-2]|0[1-9]|[1-9]{1})-(3[01]|[12][0-9]|0[1-9]|[1-9]{1})";
var match = Regex.Match("2019-12-25", pattern);
Console.WriteLine(match.Value);
Console.WriteLine(
    $"{match.Groups[1]}.{match.Groups[2]}.{match.Groups[3]}");
```

控制台打印的第一个值是`2019-12-25`，因为这是整个匹配的值。第二个值是由每个捕获组的单独值组成的，但是用点(`.`)作为分隔符。因此，输出文本是`2019.12.25`。

捕获组可能有名称；形式为`(?<name>...)`。在下面的例子中，我们称正则表达式的三个捕获组为`year`、`month`和`day`：

```cs
var pattern =
    @"(?<year>\d{4})-(?<month>1[0-2]|0[1-9]|[1-9]{1})-(?<day>3[01]|[12][0-9]|0[1-9]|[1-9]{1})";
var match = Regex.Match("2019-12-25", pattern);
Console.WriteLine(
    $"{match.Groups["year"]}-{match.Groups["month"]}-{match.Groups["day"]}");
```

如果输入文本有多个与模式匹配的子字符串，我们可以使用`Matches()`函数获取所有这些子字符串。在下面的例子中，日期每行提供一个，但最后两个日期不合法（`2019-13-21`和`2019-1-32`）；因此，这些在结果中找不到。为了解析字符串，我们使用了多行选项，这样`^`和`$`就分别指向每行的开头和结尾，而不是整个字符串，如下面的例子所示：

```cs
var text = "2019-05-01\n2019-5-9\n2019-12-25\n2019-13-21\n2019-1-32";
var pattern =
    @"^(\d{4})-(1[0-2]|0[1-9]|[1-9]{1})-(3[01]|[12][0-9]|0[1-9]|[1-9]{1})$";
var matches = Regex.Matches(
  text, pattern, RegexOptions. Multiline); 
foreach(Match match in matches)
{
    Console.WriteLine(
      $"[{match.Index}..{match.Length}]={match. Value}");
}
```

程序的输出如下：

```cs
[0..10]=2019-05-01
[11..8]=2019-5-9
[20..10]=2019-12-25
```

有时，我们不仅想要找到输入文本的子字符串；我们还想用其他东西替换它们。这个主题在下一节中讨论。

## 替换文本的部分

正则表达式也可以用来用另一个字符串替换匹配正则表达式的字符串的部分。`Replace()`方法有一组重载，你可以指定一个字符串或一个所谓的`Match`参数，并返回一个字符串。在下面的例子中，我们将使用这个方法将日期的格式从*YYYY-MM-DD*改为*MM/DD/YYYY*：

```cs
var text = "2019-12-25";
var pattern = @"(\d{4})-(1[0-2]|0[1-9]|[1-9]{1})-(3[01]|[12]
    [0-9]|0[1-9]|[1-9]{1})";
var result = Regex.Replace(
    text, pattern,
    m => $"{m.Groups[2]}/{m.Groups[3]}/{m.Groups[1]}");
```

作为进一步的练习，你可以编写一个程序，将形式为 2019-12-25 的输入日期转换为 Dec 25, 2019 的形式。

作为本节的总结，正则表达式提供了丰富的模式匹配功能。.NET 提供了代表具有丰富功能的正则表达式引擎的 `Regex` 类。在本节中，我们已经看到了如何基于模式匹配、搜索和替换文本。这些是您将在各种应用程序中遇到的常见操作。您可以选择这些方法的静态和实例重载，并使用各种选项自定义它们的工作方式。

# 扩展方法

有时候，向类型添加功能而不改变实现、创建派生类型或重新编译代码是很有用的。我们可以通过在辅助类中创建方法来实现这一点。假设我们想要一个函数来颠倒字符串的内容，因为 `System.String` 没有这样的函数。这样的函数可以实现如下：

```cs
static class StringExtensions
{
    public static string Reverse(string s)
    {
        var charArray = s.ToCharArray();
        Array.Reverse(charArray);
        return new string(charArray);
    }
}
```

可以按以下方式调用：

```cs
var text = "demo";
var rev = StringExtensions.Reverse(text);
```

C#语言允许我们以一种使我们能够调用它就像它是 `System.String` 的实际成员的方式来定义这个函数。这样的函数被称为 `Reverse()` 方法，使其成为扩展方法。新的实现如下所示：

```cs
static class StringExtensions
{
    public static string Reverse(this string s)
    {
        var charArray = s.ToCharArray();
        Array.Reverse(charArray);
        return new string(charArray);
    }
}
```

请注意，实现的唯一变化是在函数参数前面加上了 `this` 关键字。通过这些变化，函数可以被调用，就好像它是字符串类的一部分：

```cs
var text = "demo";
var rev = text.Reverse();
```

扩展方法的定义和行为适用以下规则：

+   它们可以扩展类、结构和枚举。

+   它们必须声明为静态、非嵌套、非泛型类的静态方法。

+   它们的第一个参数是它们要添加功能的类型。该参数前面带有 `this` 关键字。

+   它们只能调用它们扩展的类型的公共成员。

+   只有当它们声明的命名空间通过 `using` 指令引入到当前范围时，扩展方法才可用。

+   如果一个扩展方法（在当前范围内可用）与类的实例方法具有相同的签名，编译器将始终优先选择实例成员，扩展方法将永远不会被调用。

以下示例显示了一个名为 `AllMessages()` 的扩展方法，它扩展了 `System.Exception` 类型的功能。这代表了一个异常，有一个消息，但也可能包含内部异常。这个扩展方法返回一个由所有嵌套异常的所有消息连接而成的字符串。布尔参数指示是否应该从主异常到最内部异常连接消息，还是以相反的顺序：

```cs
static class ExceptionExtensions
{
    public static string AllMessages(this Exception exception, 
                                     bool reverse = false)
    {
        var messages = new List<string>();
        var ex = exception;
        while(ex != null)
        {
            messages.Add(ex.Message);
            ex = ex.InnerException;
        }
        if (reverse) messages.Reverse();
        return string.Join(Environment.NewLine, messages);
    }
}
```

然后可以按以下方式调用扩展方法：

```cs
var exception = 
    new InvalidOperationException(
        "An invalid operation occurred",
        new NotSupportedException(
            "The operation is not supported",
            new InvalidCastException(
                "Cannot apply cast!")));
Console.WriteLine(exception.AllMessages());
Console.WriteLine(exception.AllMessages(true));
```

来自.NET 的最常见的扩展方法是扩展 `IEnumerable` 和 `IEnumerable<T>` 类型的 LINQ 标准运算符。我们将在*第十章* *Lambdas, LINQ, and Functional Programming*中探讨 LINQ。如果您实现扩展方法来扩展无法更改的类型，您必须牢记将来对类型的更改可能会破坏扩展方法。

# 总结

在本章中，我们讨论了一系列高级语言特性。我们从实现强类型回调的委托和事件开始。我们继续讨论了匿名类型和元组，这些是轻量级类型，可以保存任何值，并帮助我们避免定义新的显式类型。然后我们看了模式匹配，这是检查值是否具有特定形状以及提取有关它的信息的过程。我们继续讨论了正则表达式，这是具有明确定义的语法的模式，可以与文本匹配。最后，我们学习了扩展方法，它使我们能够向类型添加功能，而不改变它们的实现，比如当我们不拥有源代码时。

在下一章中，我们将讨论垃圾回收和资源管理。

# 测试你学到的知识

1.  什么是回调函数，它们与委托有什么关系？

1.  你如何定义委托？事件又是什么？

1.  有多少种类型的元组？它们之间的主要区别是什么？

1.  什么是命名元组，如何创建它们？

1.  什么是模式匹配，它可以与哪些语句一起使用？

1.  模式匹配空值的规则是什么？

1.  哪个类实现了正则表达式，它默认使用什么编码？

1.  这个类的`Match()`和`Matches()`方法有什么区别？

1.  什么是扩展方法，它们为什么有用？

1.  你如何定义一个扩展方法？
