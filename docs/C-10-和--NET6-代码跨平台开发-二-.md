# C#10 和 .NET6 代码跨平台开发（二）

> 原文：[`zh.annas-archive.org/md5/B053DEF9CB8C4C14E67E73C1EC2319CF`](https://zh.annas-archive.org/md5/B053DEF9CB8C4C14E67E73C1EC2319CF)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第三章：控制流程、类型转换和异常处理

本章是关于编写对变量执行简单操作、做出决策、执行模式匹配、重复语句或代码块、将变量或表达式的值从一种类型转换为另一种类型、处理异常以及检查数字变量溢出的代码。

本章涵盖以下主题：

+   操作变量

+   理解选择语句

+   理解迭代语句

+   类型之间的转换和强制转换

+   处理异常

+   检查溢出

# 操作变量

**运算符**对**操作数**（如变量和字面值）执行简单的操作，如加法和乘法。它们通常返回一个新值，即操作的结果，该结果可以分配给一个变量。

大多数运算符是二元的，意味着它们作用于两个操作数，如下面的伪代码所示：

```cs
var resultOfOperation = firstOperand operator secondOperand; 
```

二元运算符的例子包括加法和乘法，如下面的代码所示：

```cs
int x = 5;
int y = 3;
int resultOfAdding = x + y;
int resultOfMultiplying = x * y; 
```

一些运算符是单目的，意味着它们作用于单个操作数，并且可以应用于操作数之前或之后，如下面的伪代码所示：

```cs
var resultOfOperation = onlyOperand operator; 
var resultOfOperation2 = operator onlyOperand; 
```

单目运算符的例子包括增量器和获取类型或其大小（以字节为单位），如下面的代码所示：

```cs
int x = 5;
int postfixIncrement = x++;
int prefixIncrement = ++x;
Type theTypeOfAnInteger = typeof(int); 
int howManyBytesInAnInteger = sizeof(int); 
```

三元运算符作用于三个操作数，如下面的伪代码所示：

```cs
var resultOfOperation = firstOperand firstOperator 
  secondOperand secondOperator thirdOperand; 
```

## 探索单目运算符

两个常用的单目运算符用于增加（`++`）和减少（`--`）一个数字。让我们写一些示例代码来展示它们是如何工作的：

1.  如果你已经完成了前面的章节，那么你将已经有一个`Code`文件夹。如果没有，那么你需要创建它。

1.  使用你喜欢的编程工具创建一个新的控制台应用程序，如下表所定义：

    1.  项目模板：**控制台应用程序** / `console`

    1.  工作区/解决方案文件和文件夹：`Chapter03`

    1.  项目文件和文件夹：`Operators`

1.  在`Program.cs`顶部，静态导入`System.Console`。

1.  在`Program.cs`中，声明两个整型变量`a`和`b`，将`a`设置为`3`，在将结果赋给`b`的同时增加`a`，然后输出它们的值，如下面的代码所示：

    ```cs
    int a = 3; 
    int b = a++;
    WriteLine($"a is {a}, b is {b}"); 
    ```

1.  在运行控制台应用程序之前，问自己一个问题：你认为输出时`b`的值会是多少？一旦你考虑了这一点，运行代码，并将你的预测与实际结果进行比较，如下面的输出所示：

    ```cs
    a is 4, b is 3 
    ```

    变量`b`的值为`3`，因为`++`运算符在赋值*之后*执行；这被称为**后缀运算符**。如果你需要在赋值*之前*增加，那么使用**前缀运算符**。

1.  复制并粘贴这些语句，然后修改它们以重命名变量并使用前缀运算符，如下面的代码所示：

    ```cs
    int c = 3;
    int d = ++c; // increment c before assigning it
    WriteLine($"c is {c}, d is {d}"); 
    ```

1.  重新运行代码并注意结果，如下面的输出所示：

    ```cs
    a is 4, b is 3
    c is 4, d is 4 
    ```

    **最佳实践**：由于增量和减量运算符的前缀和后缀结合赋值时的混淆，Swift 编程语言设计者在版本 3 中决定不再支持此运算符。我建议在 C#中使用时，切勿将`++`和`--`运算符与赋值运算符`=`结合使用。将这些操作作为单独的语句执行。

## 探索二元算术运算符

增量和减量是一元算术运算符。其他算术运算符通常是二元的，允许你对两个数字执行算术运算，如下所示：

1.  添加语句以声明并赋值给两个名为`e`和`f`的整型变量，然后对这两个数字应用五个常见的二元算术运算符，如下面的代码所示：

    ```cs
    int e = 11; 
    int f = 3;
    WriteLine($"e is {e}, f is {f}"); 
    WriteLine($"e + f = {e + f}"); 
    WriteLine($"e - f = {e - f}"); 
    WriteLine($"e * f = {e * f}"); 
    WriteLine($"e / f = {e / f}"); 
    WriteLine($"e % f = {e % f}"); 
    ```

1.  运行代码并注意结果，如下面的输出所示：

    ```cs
    e is 11, f is 3 
    e + f = 14
    e - f = 8 
    e * f = 33 
    e / f = 3 
    e % f = 2 
    ```

    要理解应用于整数的除法`/`和模`%`运算符，你需要回想小学时期。想象你有十一颗糖果和三个朋友。

    你如何将糖果分给你的朋友们？你可以给每位朋友三颗糖果，剩下两颗。那两颗糖果就是**模数**，也称为除法后的**余数**。如果你有十二颗糖果，那么每位朋友得到四颗，没有剩余，所以余数为 0。

1.  添加语句以声明并赋值给一个名为`g`的`double`变量，以展示整数和实数除法的区别，如下面的代码所示：

    ```cs
    double g = 11.0;
    WriteLine($"g is {g:N1}, f is {f}"); 
    WriteLine($"g / f = {g / f}"); 
    ```

1.  运行代码并注意结果，如下面的输出所示：

    ```cs
    g is 11.0, f is 3
    g / f = 3.6666666666666665 
    ```

如果第一个操作数是浮点数，例如值为`11.0`的`g`，那么除法运算符返回一个浮点值，例如`3.6666666666665`，而不是整数。

## 赋值运算符

你已经一直在使用最常见的赋值运算符，`=`。

为了使你的代码更简洁，你可以将赋值运算符与其他运算符如算术运算符结合使用，如下面的代码所示：

```cs
int p = 6;
p += 3; // equivalent to p = p + 3;
p -= 3; // equivalent to p = p - 3;
p *= 3; // equivalent to p = p * 3;
p /= 3; // equivalent to p = p / 3; 
```

## 探索逻辑运算符

逻辑运算符操作于布尔值，因此它们返回`true`或`false`。让我们探索操作于两个布尔值的二元逻辑运算符：

1.  使用你偏好的编程工具，在`Chapter03`工作区/解决方案中添加一个名为`BooleanOperators`的新控制台应用。

    1.  在 Visual Studio Code 中，选择`BooleanOperators`作为活动的 OmniSharp 项目。当你看到弹出警告消息说缺少必需资产时，点击**是**以添加它们。

    1.  在 Visual Studio 中，将解决方案的启动项目设置为当前选择的项目。

        **最佳实践**：记得静态导入`System.Console`类型以简化语句。

1.  在 `Program.cs` 中，添加语句以声明两个布尔变量，其值分别为 `true` 和 `false`，然后输出应用 AND、OR 和 XOR（异或）逻辑运算符的结果的真值表，如下面的代码所示：

    ```cs
    bool a = true;
    bool b = false;
    WriteLine($"AND  | a     | b    ");
    WriteLine($"a    | {a & a,-5} | {a & b,-5} ");
    WriteLine($"b    | {b & a,-5} | {b & b,-5} ");
    WriteLine();
    WriteLine($"OR   | a     | b    ");
    WriteLine($"a    | {a | a,-5} | {a | b,-5} ");
    WriteLine($"b    | {b | a,-5} | {b | b,-5} ");
    WriteLine();
    WriteLine($"XOR  | a     | b    ");
    WriteLine($"a    | {a ^ a,-5} | {a ^ b,-5} ");
    WriteLine($"b    | {b ^ a,-5} | {b ^ b,-5} "); 
    ```

1.  运行代码并注意结果，如下面的输出所示：

    ```cs
    AND  | a     | b    
    a    | True  | False 
    b    | False | False 
    OR   | a     | b    
    a    | True  | True  
    b    | True  | False 
    XOR  | a     | b    
    a    | False | True  
    b    | True  | False 
    ```

对于 AND `&` 逻辑运算符，两个操作数都必须为 `true` 才能使结果为 `true`。对于 OR `|` 逻辑运算符，任一操作数为 `true` 即可使结果为 `true`。对于 XOR `^` 逻辑运算符，任一操作数可以为 `true`（但不能同时为 `true`！）以使结果为 `true`。

## 探索条件逻辑运算符

条件逻辑运算符类似于逻辑运算符，但你需要使用两个符号而不是一个，例如，`&&` 代替 `&`，或者 `||` 代替 `|`。

在 *第四章*，*编写、调试和测试函数* 中，你将更详细地了解函数，但我现在需要介绍函数以解释条件逻辑运算符，也称为短路布尔运算符。

函数执行语句然后返回一个值。该值可以是用于布尔运算的布尔值，例如 `true`。让我们利用条件逻辑运算符：

1.  在 `Program.cs` 底部，编写语句以声明一个向控制台写入消息并返回 `true` 的函数，如下面的代码所示：

    ```cs
    static bool DoStuff()
    {
      WriteLine("I am doing some stuff.");
      return true;
    } 
    ```

    **最佳实践**：如果你使用的是 .NET 交互式笔记本，请在单独的代码单元格中编写 `DoStuff` 函数，然后执行它，以便其上下文可供其他代码单元格使用。

1.  在前面的 `WriteLine` 语句之后，对 `a` 和 `b` 变量以及调用函数的结果执行 AND `&` 操作，如下面的代码所示：

    ```cs
    WriteLine();
    WriteLine($"a & DoStuff() = {a & DoStuff()}"); 
    WriteLine($"b & DoStuff() = {b & DoStuff()}"); 
    ```

1.  运行代码，查看结果，并注意该函数被调用了两次，一次是为 a，一次是为 b，如以下输出所示：

    ```cs
    I am doing some stuff. 
    a & DoStuff() = True
    I am doing some stuff. 
    b & DoStuff() = False 
    ```

1.  将 `&` 运算符更改为 `&&` 运算符，如下面的代码所示：

    ```cs
    WriteLine($"a && DoStuff() = {a && DoStuff()}"); 
    WriteLine($"b && DoStuff() = {b && DoStuff()}"); 
    ```

1.  运行代码，查看结果，并注意当与 `a` 变量结合时，函数确实运行了。当与 `b` 变量结合时，它不会运行，因为 `b` 变量是 `false`，所以结果无论如何都将是 `false`，因此不需要执行该函数，如下面的输出所示：

    ```cs
    I am doing some stuff. 
    a && DoStuff() = True
    b && DoStuff() = False // DoStuff function was not executed! 
    ```

    **最佳实践**：现在你可以明白为什么条件逻辑运算符被描述为短路运算符。它们可以使你的应用程序更高效，但它们也可能在假设函数总是被调用的情况下引入微妙的错误。当与产生副作用的函数结合使用时，最安全的是避免使用它们。

## 探索位运算和二进制移位运算符

位运算符影响数字中的位。二进制移位运算符可以比传统运算符更快地执行一些常见的算术计算，例如，任何乘以 2 的倍数。

让我们探索位运算和二进制移位运算符：

1.  使用您喜欢的编码工具，在`Chapter03`工作区/解决方案中添加一个新的**控制台应用程序**，命名为`BitwiseAndShiftOperators`。

1.  在 Visual Studio Code 中，选择`BitwiseAndShiftOperators`作为活动 OmniSharp 项目。当看到弹出警告消息提示缺少必需资产时，点击**是**以添加它们。

1.  在`Program.cs`中，键入语句以声明两个整数变量，值分别为 10 和 6，然后输出应用 AND、OR 和 XOR 位运算符的结果，如下面的代码所示：

    ```cs
    int a = 10; // 00001010
    int b = 6;  // 00000110
    WriteLine($"a = {a}");
    WriteLine($"b = {b}");
    WriteLine($"a & b = {a & b}"); // 2-bit column only 
    WriteLine($"a | b = {a | b}"); // 8, 4, and 2-bit columns 
    WriteLine($"a ^ b = {a ^ b}"); // 8 and 4-bit columns 
    ```

1.  运行代码并注意结果，如下面的输出所示：

    ```cs
    a = 10
    b = 6
    a & b = 2 
    a | b = 14
    a ^ b = 12 
    ```

1.  在`Program.cs`中，添加语句以输出应用左移运算符将变量`a`的位移动三列、将`a`乘以 8 以及右移变量`b`的位一列的结果，如下面的代码所示：

    ```cs
    // 01010000 left-shift a by three bit columns
    WriteLine($"a << 3 = {a << 3}");
    // multiply a by 8
    WriteLine($"a * 8 = {a * 8}");
    // 00000011 right-shift b by one bit column
    WriteLine($"b >> 1 = {b >> 1}"); 
    ```

1.  运行代码并注意结果，如下面的输出所示：

    ```cs
    a << 3 = 80
    a * 8 = 80
    b >> 1 = 3 
    ```

结果`80`是因为其中的位向左移动了三列，因此 1 位移动到了 64 位和 16 位列，64 + 16 = 80。这相当于乘以 8，但 CPU 可以更快地执行位移。结果 3 是因为`b`中的 1 位向右移动了一列，进入了 2 位和 1 位列。

**良好实践**：记住，当操作整数值时，`&`和`|`符号是位运算符，而当操作布尔值如`true`和`false`时，`&`和`|`符号是逻辑运算符。

我们可以通过将整数值转换为零和一的二进制字符串来演示这些操作：

1.  在`Program.cs`底部，添加一个函数，将整数值转换为最多包含八个零和一的二进制（Base2）`字符串`，如下面的代码所示：

    ```cs
    static string ToBinaryString(int value)
    {
      return Convert.ToString(value, toBase: 2).PadLeft(8, '0');
    } 
    ```

1.  在函数上方，添加语句以输出`a`、`b`以及各种位运算符的结果，如下面的代码所示：

    ```cs
    WriteLine();
    WriteLine("Outputting integers as binary:");
    WriteLine($"a =     {ToBinaryString(a)}");
    WriteLine($"b =     {ToBinaryString(b)}");
    WriteLine($"a & b = {ToBinaryString(a & b)}");
    WriteLine($"a | b = {ToBinaryString(a | b)}");
    WriteLine($"a ^ b = {ToBinaryString(a ^ b)}"); 
    ```

1.  运行代码并注意结果，如下面的输出所示：

    ```cs
    Outputting integers as binary:
    a =     00001010
    b =     00000110
    a & b = 00000010
    a | b = 00001110
    a ^ b = 00001100 
    ```

## 杂项运算符

`nameof`和`sizeof`是在处理类型时方便的运算符：

+   `nameof`返回变量、类型或成员的简短名称（不包含命名空间）作为`字符串`值，这在输出异常消息时非常有用。

+   `sizeof`返回简单类型的大小（以字节为单位），这对于确定数据存储的效率非常有用。

还有许多其他运算符；例如，变量与其成员之间的点称为**成员访问运算符**，函数或方法名称末尾的圆括号称为**调用运算符**，如下面的代码所示：

```cs
int age = 47;
// How many operators in the following statement?
char firstDigit = age.ToString()[0];
// There are four operators:
// = is the assignment operator
// . is the member access operator
// () is the invocation operator
// [] is the indexer access operator 
```

# 理解选择语句

每个应用程序都需要能够从选项中选择并沿不同的代码路径分支。C#中的两种选择语句是`if`和`switch`。你可以使用`if`来编写所有代码，但`switch`可以在某些常见场景中简化你的代码，例如当存在一个可以有多个值的单一变量，每个值都需要不同的处理时。

## if 语句的分支

`if`语句通过评估一个布尔表达式来决定执行哪个分支。如果表达式为`true`，则执行该代码块。`else`块是可选的，如果`if`表达式为`false`，则执行`else`块。`if`语句可以嵌套。

`if`语句可以与其他`if`语句结合，形成`else if`分支，如下列代码所示：

```cs
if (expression1)
{
  // runs if expression1 is true
}
else if (expression2)
{
  // runs if expression1 is false and expression2 if true
}
else if (expression3)
{
  // runs if expression1 and expression2 are false
  // and expression3 is true
}
else
{
  // runs if all expressions are false
} 
```

每个`if`语句的布尔表达式都是独立的，与`switch`语句不同，它不需要引用单一值。

让我们编写一些代码来探索像`if`这样的选择语句：

1.  使用你喜欢的编程工具，在`Chapter03`工作区/解决方案中添加一个名为`SelectionStatements`的新**控制台应用程序**。

1.  在 Visual Studio Code 中，选择`SelectionStatements`作为活动 OmniSharp 项目。

1.  在`Program.cs`中，输入语句以检查密码是否至少有八个字符，如下列代码所示：

    ```cs
    string password = "ninja";
    if (password.Length < 8)
    {
      WriteLine("Your password is too short. Use at least 8 characters.");
    }
    else
    {
      WriteLine("Your password is strong.");
    } 
    ```

1.  运行代码并注意结果，如下列输出所示：

    ```cs
     Your password is too short. Use at least 8 characters. 
    ```

### 为什么你应该始终在 if 语句中使用大括号

由于每个代码块内只有一条语句，前面的代码可以不使用花括号编写，如下列代码所示：

```cs
if (password.Length < 8)
  WriteLine("Your password is too short. Use at least 8 characters."); 
else
  WriteLine("Your password is strong."); 
```

应避免这种风格的`if`语句，因为它可能引入严重的错误，例如苹果 iPhone iOS 操作系统中臭名昭著的#gotofail 错误。

在苹果发布 iOS 6 后的 18 个月内，即 2012 年 9 月，其**安全套接字层**（**SSL**）加密代码中存在一个错误，这意味着任何使用 Safari（设备上的网页浏览器）尝试连接到安全网站（如银行）的用户都没有得到适当的保护，因为一个重要的检查被意外跳过了。

仅仅因为你可以在没有花括号的情况下编写代码，并不意味着你应该这样做。没有它们的代码并不会“更高效”；相反，它更难以维护，且可能更危险。

## if 语句的模式匹配

引入 C# 7.0 及更高版本的一个特性是模式匹配。`if`语句可以通过结合使用`is`关键字和声明一个局部变量来使代码更安全：

1.  添加语句，以便如果存储在名为`o`的变量中的值是`int`，则该值被赋给局部变量`i`，然后可以在`if`语句中使用。这比使用名为`o`的变量更安全，因为我们确信`i`是一个`int`变量，而不是其他东西，如下列代码所示：

    ```cs
    // add and remove the "" to change the behavior
    object o = "3"; 
    int j = 4;
    if (o is int i)
    {
      WriteLine($"{i} x {j} = {i * j}");
    }
    else
    {
      WriteLine("o is not an int so it cannot multiply!");
    } 
    ```

1.  运行代码并查看结果，如下列输出所示：

    ```cs
    o is not an int so it cannot multiply! 
    ```

1.  删除围绕`"3"`值的双引号字符，以便存储在名为`o`的变量中的值是`int`类型而不是`string`类型。

1.  重新运行代码以查看结果，如下面的输出所示：

    ```cs
    3 x 4 = 12 
    ```

## 使用 switch 语句进行分支

`switch`语句与`if`语句不同，因为`switch`将单个表达式与多个可能的`case`语句列表进行比较。每个`case`语句都与单个表达式相关。每个`case`部分必须以：

+   使用`break`关键字（如下面的代码中的 case 1）

+   或者使用`goto` `case`关键字（如下面的代码中的 case 2）

+   或者它们可以没有任何语句（如下面的代码中的 case 3）

+   或者`goto`关键字，它引用一个命名标签（如下面的代码中的 case 5）

+   或者使用`return`关键字离开当前函数（未在代码中显示）

让我们编写一些代码来探索`switch`语句：

1.  为`switch`语句编写语句。您应该注意到倒数第二条语句是一个可以跳转到的标签，而第一条语句生成一个介于 1 和 6 之间的随机数（代码中的数字 7 是上限）。`switch`语句分支基于这个随机数的值，如下面的代码所示：

    ```cs
    int number = (new Random()).Next(1, 7); 
    WriteLine($"My random number is {number}");
    switch (number)
    {
      case 1: 
        WriteLine("One");
        break; // jumps to end of switch statement
      case 2:
        WriteLine("Two");
        goto case 1;
      case 3: // multiple case section
      case 4:
        WriteLine("Three or four");
        goto case 1;
      case 5:
        goto A_label;
      default:
        WriteLine("Default");
        break;
    } // end of switch statement
    WriteLine("After end of switch");
    A_label:
    WriteLine($"After A_label"); 
    ```

    **最佳实践**：您可以使用`goto`关键字跳转到另一个 case 或标签。大多数程序员对`goto`关键字持反对态度，但在某些情况下，它可以是解决代码逻辑的好方法。但是，您应该谨慎使用它。

1.  多次运行代码以查看随机数在各种情况下的结果，如下面的示例输出所示：

    ```cs
    // first random run
    My random number is 4 
    Three or four
    One
    After end of switch
    After A_label
    // second random run
    My random number is 2 
    Two
    One
    After end of switch
    After A_label
    // third random run
    My random number is 6
    Default
    After end of switch
    After A_label
    // fourth random run
    My random number is 1 
    One
    After end of switch
    After A_label
    // fifth random run
    My random number is 5
    After A_label 
    ```

## 使用 switch 语句进行模式匹配

与`if`语句一样，`switch`语句在 C# 7.0 及更高版本中支持模式匹配。`case`值不再需要是文字值；它们可以是模式。

让我们看一个使用文件夹路径的`switch`语句进行模式匹配的示例。如果您使用的是 macOS，则交换设置路径变量的注释语句，并将我的用户名替换为您的用户文件夹名称：

1.  添加语句以声明一个`string`路径到文件，将其打开为只读或可写流，然后根据流的类型和功能显示一条消息，如下面的代码所示：

    ```cs
    // string path = "/Users/markjprice/Code/Chapter03";
    string path = @"C:\Code\Chapter03";
    Write("Press R for read-only or W for writeable: "); 
    ConsoleKeyInfo key = ReadKey();
    WriteLine();
    Stream? s;
    if (key.Key == ConsoleKey.R)
    {
      s =  File.Open(
        Path.Combine(path, "file.txt"), 
        FileMode.OpenOrCreate, 
        FileAccess.Read);
    }
    else
    {
      s =  File.Open( 
        Path.Combine(path, "file.txt"), 
        FileMode.OpenOrCreate, 
        FileAccess.Write);
    }
    string message; 
    switch (s)
    {
      case FileStream writeableFile when s.CanWrite:
        message = "The stream is a file that I can write to.";
        break;
      case FileStream readOnlyFile:
        message = "The stream is a read-only file.";
        break;
      case MemoryStream ms:
        message = "The stream is a memory address.";
        break;
      default: // always evaluated last despite its current position
        message = "The stream is some other type.";
        break;
      case null:
        message = "The stream is null.";
        break;
    }
    WriteLine(message); 
    ```

1.  运行代码并注意名为`s`的变量被声明为`Stream`类型，因此它可以是流的任何子类型，例如内存流或文件流。在此代码中，流是通过`File.Open`方法创建的，该方法返回一个文件流，并根据您的按键，它将是可写的或只读的，因此结果将是一条描述情况的 message，如下面的输出所示：

    ```cs
    The stream is a file that I can write to. 
    ```

在.NET 中，`Stream`有多个子类型，包括`FileStream`和`MemoryStream`。在 C# 7.0 及更高版本中，你的代码可以根据流子类型更简洁地分支，并声明和赋值一个局部变量以安全使用。你将在*第九章*，*文件、流和序列化操作*中了解更多关于`System.IO`命名空间和`Stream`类型的信息。

此外，`case`语句可以包含`when`关键字以执行更具体的模式匹配。在前述代码的第一个 case 语句中，`s`仅在流为`FileStream`且其`CanWrite`属性为`true`时匹配。

## 使用 switch 表达式简化 switch 语句

C# 8.0 及以上版本中，你可以使用**switch 表达式**简化`switch`语句。

大多数`switch`语句虽然简单，但需要大量输入。`switch`表达式旨在简化所需代码，同时在所有情况都返回值以设置单个变量的情况下，仍表达相同意图。`switch`表达式使用 lambda `=>`表示返回值。

让我们将之前使用`switch`语句的代码实现为`switch`表达式，以便比较两种风格：

1.  使用`switch`表达式，根据流的类型和功能输入语句设置消息，如下列代码所示：

    ```cs
    message = s switch
    {
      FileStream writeableFile when s.CanWrite
        => "The stream is a file that I can write to.", 
      FileStream readOnlyFile
        => "The stream is a read-only file.", 
      MemoryStream ms
        => "The stream is a memory address.", 
      null
        => "The stream is null.",
      _
        => "The stream is some other type."
    };
    WriteLine(message); 
    ```

    主要区别在于移除了`case`和`break`关键字。下划线字符`_`用于表示默认返回值。

1.  运行代码，并注意结果与之前相同。

# 理解迭代语句

迭代语句重复一个语句块，要么在条件为真时，要么对集合中的每个项。选择使用哪种语句基于解决问题逻辑的易理解性和个人偏好。

## while 语句循环

`while`语句评估布尔表达式，并在其为真时继续循环。让我们探索迭代语句：

1.  使用你偏好的编程工具，在`Chapter03`工作区/解决方案中添加一个名为`IterationStatements`的**控制台应用程序**。

1.  在 Visual Studio Code 中，选择`IterationStatements`作为活动 OmniSharp 项目。

1.  在`Program.cs`中，输入语句定义一个`while`语句，当整型变量值小于 10 时循环，如下列代码所示：

    ```cs
    int x = 0;
    while (x < 10)
    {
      WriteLine(x);
      x++;
    } 
    ```

1.  运行代码并查看结果，应显示数字 0 至 9，如下列输出所示：

    ```cs
    0
    1
    2
    3
    4
    5
    6
    7
    8
    9 
    ```

## do 语句循环

与`while`类似，`do`语句在代码块底部而非顶部检查布尔表达式，这意味着代码块至少会执行一次，如下所示：

1.  输入语句定义一个`do`循环，如下列代码所示：

    ```cs
    string? password;
    do
    {
      Write("Enter your password: "); 
      password = ReadLine();
    }
    while (password != "Pa$$w0rd");
    WriteLine("Correct!"); 
    ```

1.  运行代码，并注意你需要反复输入密码，直到输入正确，如下列输出所示：

    ```cs
    Enter your password: password 
    Enter your password: 12345678 
    Enter your password: ninja
    Enter your password: correct horse battery staple 
    Enter your password: Pa$$w0rd
    Correct! 
    ```

1.  作为可选挑战，添加语句，以便用户只能在出现错误消息之前尝试十次。

## 使用 for 语句循环

`for`语句类似于`while`，只不过它更为简洁。它结合了：

+   一个**初始化表达式**，它在循环开始时执行一次。

+   一个**条件表达式**，它在每次迭代开始时执行，以检查循环是否应继续。

+   一个**迭代器表达式**，它在每次循环的底部执行。

`for`语句通常与整数计数器一起使用。让我们探讨一些代码：

1.  键入一个`for`语句以输出数字 1 到 10，如下所示：

    ```cs
    for (int y = 1; y <= 10; y++)
    {
      WriteLine(y);
    } 
    ```

1.  运行代码以查看结果，结果应为数字 1 到 10。

## 使用 foreach 语句循环

`foreach`语句与之前的三种迭代语句略有不同。

它用于对序列（例如数组或集合）中的每个项执行一组语句。通常，每个项都是只读的，如果在迭代期间修改序列结构（例如，通过添加或删除项），则会抛出异常。

尝试以下示例：

1.  键入语句以创建一个字符串变量数组，然后输出每个变量的长度，如下所示：

    ```cs
    string[] names = { "Adam", "Barry", "Charlie" };
    foreach (string name in names)
    {
      WriteLine($"{name} has {name.Length} characters.");
    } 
    ```

1.  运行代码并查看结果，如下所示：

    ```cs
    Adam has 4 characters. 
    Barry has 5 characters. 
    Charlie has 7 characters. 
    ```

### 理解 foreach 内部工作原理

任何表示多个项（如数组或集合）的类型的创建者应确保程序员可以使用`foreach`语句枚举该类型的项。

从技术上讲，`foreach`语句将适用于遵循以下规则的任何类型：

1.  该类型必须具有一个名为`GetEnumerator`的方法，该方法返回一个对象。

1.  返回的对象必须具有名为`Current`的属性和名为`MoveNext`的方法。

1.  `MoveNext`方法必须更改`Current`的值，并在还有更多项要枚举时返回`true`，或在无更多项时返回`false`。

存在名为`IEnumerable`和`IEnumerable<T>`的接口，它们正式定义了这些规则，但编译器实际上并不要求类型实现这些接口。

编译器将前面的示例中的`foreach`语句转换为类似以下伪代码的内容：

```cs
IEnumerator e = names.GetEnumerator();
while (e.MoveNext())
{
  string name = (string)e.Current; // Current is read-only!
  WriteLine($"{name} has {name.Length} characters.");
} 
```

由于使用了迭代器，`foreach`语句中声明的变量不能用于修改当前项的值。

# 类型之间的转换和转换

你经常需要在不同类型的变量之间转换值。例如，数据输入通常作为控制台上的文本输入，因此最初存储在`string`类型的变量中，但随后需要将其转换为日期/时间，或数字，或其他数据类型，具体取决于应如何存储和处理。

有时在进行计算之前，你需要在整数和浮点数等数字类型之间进行转换。

转换也称为**类型转换**，它有两种形式：**隐式**和**显式**。隐式转换会自动发生，是安全的，意味着不会丢失任何信息。

显式转换必须手动执行，因为它可能会丢失信息，例如数字的精度。通过显式转换，你告诉 C#编译器你理解并接受这种风险。

## 隐式和显式转换数字

将`int`变量隐式转换为`double`变量是安全的，因为不会丢失任何信息，如下所示：

1.  使用你喜欢的编码工具在`Chapter03`工作区/解决方案中添加一个新的**控制台应用程序**，命名为`CastingConverting`。

1.  在 Visual Studio Code 中，选择`CastingConverting`作为活动 OmniSharp 项目。

1.  在`Program.cs`中，输入语句以声明和赋值一个`int`变量和一个`double`变量，然后当将整数值赋给`double`变量时隐式转换整数值，如下所示：

    ```cs
    int a = 10;
    double b = a; // an int can be safely cast into a double
    WriteLine(b); 
    ```

1.  输入语句以声明和赋值一个`double`变量和一个`int`变量，然后当将`double`值赋给`int`变量时隐式转换`double`值，如下所示：

    ```cs
    double c = 9.8;
    int d = c; // compiler gives an error for this line
    WriteLine(d); 
    ```

1.  运行代码并注意错误消息，如下所示：

    ```cs
    Error: (6,9): error CS0266: Cannot implicitly convert type 'double' to 'int'. An explicit conversion exists (are you missing a cast?) 
    ```

    此错误消息也会出现在 Visual Studio 错误列表或 Visual Studio Code 问题窗口中。

    你不能隐式地将`double`变量转换为`int`变量，因为这可能不安全且可能丢失数据，例如小数点后的值。你必须使用一对圆括号将要转换的`double`类型括起来，显式地将`double`变量转换为`int`变量。这对圆括号是**类型转换运算符**。即便如此，你也必须注意，小数点后的部分将被截断而不会警告，因为你选择执行显式转换，因此理解其后果。

1.  修改`d`变量的赋值语句，如下所示：

    ```cs
    int d = (int)c;
    WriteLine(d); // d is 9 losing the .8 part 
    ```

1.  运行代码以查看结果，如下所示：

    ```cs
    10
    9 
    ```

    当在较大整数和较小整数之间转换值时，我们必须执行类似的操作。再次提醒，你可能会丢失信息，因为任何过大的值都会复制其位，然后以你可能意想不到的方式进行解释！

1.  输入语句以声明和赋值一个长 64 位变量到一个 int 32 位变量，两者都使用一个小值和一个过大的值，如下所示：

    ```cs
    long e = 10; 
    int f = (int)e;
    WriteLine($"e is {e:N0} and f is {f:N0}"); 
    e = long.MaxValue;
    f = (int)e;
    WriteLine($"e is {e:N0} and f is {f:N0}"); 
    ```

1.  运行代码以查看结果，如下所示：

    ```cs
    e is 10 and f is 10
    e is 9,223,372,036,854,775,807 and f is -1 
    ```

1.  将`e`的值修改为 50 亿，如下所示：

    ```cs
    e = 5_000_000_000; 
    ```

1.  运行代码以查看结果，如下所示：

    ```cs
    e is 5,000,000,000 and f is 705,032,704 
    ```

## 使用 System.Convert 类型进行转换

使用类型转换操作符的替代方法是使用`System.Convert`类型。`System.Convert`类型可以转换为和从所有 C#数字类型，以及布尔值、字符串和日期时间值。

让我们写一些代码来实际看看：

1.  在`Program.cs`顶部，静态导入`System.Convert`类，如下所示：

    ```cs
    using static System.Convert; 
    ```

1.  在`Program.cs`底部，输入语句声明并赋值给一个`double`变量，将其转换为整数，然后将两个值写入控制台，如下所示：

    ```cs
    double g = 9.8;
    int h = ToInt32(g); // a method of System.Convert
    WriteLine($"g is {g} and h is {h}"); 
    ```

1.  运行代码并查看结果，如下所示：

    ```cs
    g is 9.8 and h is 10 
    ```

类型转换和转换之间的一个区别是，转换将`double`值`9.8`向上取整为`10`，而不是截去小数点后的部分。

## 取整数字

你现在已经看到，类型转换操作符会截去实数的小数部分，而`System.Convert`方法则会上下取整。但是，取整的规则是什么呢？

### 理解默认的取整规则

在英国 5 至 11 岁儿童的初等学校中，学生被教导如果小数部分为.5 或更高，则向上取整；如果小数部分小于.5，则向下取整。

让我们探究一下 C#是否遵循相同的初等学校规则：

1.  输入语句声明并赋值给一个`double`数组，将每个值转换为整数，然后将结果写入控制台，如下所示：

    ```cs
    double[] doubles = new[]
      { 9.49, 9.5, 9.51, 10.49, 10.5, 10.51 };
    foreach (double n in doubles)
    {
      WriteLine($"ToInt32({n}) is {ToInt32(n)}");
    } 
    ```

1.  运行代码并查看结果，如下所示：

    ```cs
    ToInt32(9.49) is 9
    ToInt32(9.5) is 10
    ToInt32(9.51) is 10
    ToInt32(10.49) is 10
    ToInt32(10.5) is 10
    ToInt32(10.51) is 11 
    ```

我们已经表明，C#中的取整规则与初等学校的规则略有不同：

+   如果小数部分小于中点.5，它总是向下取整。

+   如果小数部分大于中点.5，它总是向上取整。

+   如果小数部分是中点.5，且非小数部分为*奇数*，则向上取整；但如果非小数部分为*偶数*，则向下取整。

这一规则被称为**银行家取整**，因其通过交替上下取整来减少偏差，所以被优先采用。遗憾的是，其他语言如 JavaScript 使用的是初等学校的规则。

## 掌握取整规则

你可以通过使用`Math`类的`Round`方法来控制取整规则：

1.  输入语句，使用“远离零”取整规则（也称为“向上”取整）对每个`double`值进行取整，然后将结果写入控制台，如下所示：

    ```cs
    foreach (double n in doubles)
    {
      WriteLine(format:
        "Math.Round({0}, 0, MidpointRounding.AwayFromZero) is {1}",
        arg0: n,
        arg1: Math.Round(value: n, digits: 0,
                mode: MidpointRounding.AwayFromZero));
    } 
    ```

1.  运行代码并查看结果，如下所示：

    ```cs
    Math.Round(9.49, 0, MidpointRounding.AwayFromZero) is 9
    Math.Round(9.5, 0, MidpointRounding.AwayFromZero) is 10
    Math.Round(9.51, 0, MidpointRounding.AwayFromZero) is 10
    Math.Round(10.49, 0, MidpointRounding.AwayFromZero) is 10
    Math.Round(10.5, 0, MidpointRounding.AwayFromZero) is 11
    Math.Round(10.51, 0, MidpointRounding.AwayFromZero) is 11 
    ```

    **最佳实践**：对于你使用的每种编程语言，检查其取整规则。它们可能不会按照你预期的方式工作！

## 将任何类型转换为字符串

最常见的转换是将任何类型转换为`string`变量，以便输出为人类可读的文本，因此所有类型都从`System.Object`类继承了一个名为`ToString`的方法。

`ToString`方法将任何变量的当前值转换为文本表示。某些类型无法合理地表示为文本，因此它们返回其命名空间和类型名称。

让我们将一些类型转换为`字符串`：

1.  键入语句以声明一些变量，将它们转换为其`字符串`表示，并将它们写入控制台，如下所示：

    ```cs
    int number = 12; 
    WriteLine(number.ToString());
    bool boolean = true; 
    WriteLine(boolean.ToString());
    DateTime now = DateTime.Now; 
    WriteLine(now.ToString());
    object me = new(); 
    WriteLine(me.ToString()); 
    ```

1.  运行代码并查看结果，如下所示：

    ```cs
    12
    True
    02/28/2021 17:33:54
    System.Object 
    ```

## 从二进制对象转换为字符串

当您有一个二进制对象（如图像或视频）想要存储或传输时，有时您不希望发送原始位，因为您不知道这些位可能会如何被误解，例如，通过传输它们的网络协议或其他正在读取存储二进制对象的操作系统。

最安全的方法是将二进制对象转换为安全的字符`字符串`。程序员称这种编码为**Base64**。

`Convert`类型有一对方法，`ToBase64String`和`FromBase64String`，它们为您执行此转换。让我们看看它们的实际应用：

1.  键入语句以创建一个随机填充字节值的字节数组，将每个字节格式化良好地写入控制台，然后将相同的字节转换为 Base64 写入控制台，如下所示：

    ```cs
    // allocate array of 128 bytes
    byte[] binaryObject = new byte[128];
    // populate array with random bytes
    (new Random()).NextBytes(binaryObject); 
    WriteLine("Binary Object as bytes:");
    for(int index = 0; index < binaryObject.Length; index++)
    {
      Write($"{binaryObject[index]:X} ");
    }
    WriteLine();
    // convert to Base64 string and output as text
    string encoded = ToBase64String(binaryObject);
    WriteLine($"Binary Object as Base64: {encoded}"); 
    ```

    默认情况下，`int`值会假设为十进制表示法输出，即基数 10。您可以使用`：X`等格式代码以十六进制表示法格式化该值。

1.  运行代码并查看结果，如下所示：

    ```cs
    Binary Object as bytes:
    B3 4D 55 DE 2D E BB CF BE 4D E6 53 C3 C2 9B 67 3 45 F9 E5 20 61 7E 4F 7A 81 EC 49 F0 49 1D 8E D4 F7 DB 54 AF A0 81 5 B8 BE CE F8 36 90 7A D4 36 42
    4 75 81 1B AB 51 CE 5 63 AC 22 72 DE 74 2F 57 7F CB E7 47 B7 62 C3 F4 2D
    61 93 85 18 EA 6 17 12 AE 44 A8 D B8 4C 89 85 A9 3C D5 E2 46 E0 59 C9 DF
    10 AF ED EF 8AA1 B1 8D EE 4A BE 48 EC 79 A5 A 5F 2F 30 87 4A C7 7F 5D C1 D
    26 EE
    Binary Object as Base64: s01V3i0Ou8++TeZTw8KbZwNF +eUgYX5PeoHsSfBJHY7U99tU r6CBBbi+zvg2kHrUNkIEdYEbq1HOBWOsInLedC9Xf8vnR7diw/QtYZOFGOoGFxKuRKgNuEyJha k81eJG4FnJ3xCv7e+KobGN7kq+SO x5pQpfLzCHSsd/XcENJu4= 
    ```

## 从字符串解析到数字或日期和时间

第二常见的转换是从字符串到数字或日期和时间值。

`ToString`的相反操作是`Parse`。只有少数类型具有`Parse`方法，包括所有数字类型和`DateTime`。

让我们看看`Parse`的实际应用：

1.  键入语句以从字符串解析整数和日期时间值，然后将结果写入控制台，如下所示：

    ```cs
    int age = int.Parse("27");
    DateTime birthday = DateTime.Parse("4 July 1980");
    WriteLine($"I was born {age} years ago."); 
    WriteLine($"My birthday is {birthday}."); 
    WriteLine($"My birthday is {birthday:D}."); 
    ```

1.  运行代码并查看结果，如下所示：

    ```cs
    I was born 27 years ago.
    My birthday is 04/07/1980 00:00:00\. 
    My birthday is 04 July 1980. 
    ```

    默认情况下，日期和时间值以短日期和时间格式输出。您可以使用`D`等格式代码仅以长日期格式输出日期部分。

    **最佳实践**：使用标准日期和时间格式说明符，如下所示：[`docs.microsoft.com/en-us/dotnet/standard/base-types/standard-date-and-time-format-strings#table-of-format-specifiers`](https://docs.microsoft.com/en-us/dotnet/standard/base-types/standard-date-and-time-format-strings#table-of-format-specifiers)

### 使用 Parse 时的错误

`Parse`方法的一个问题是，如果`字符串`无法转换，它会给出错误。

1.  键入语句以尝试将包含字母的字符串解析为整数变量，如下所示：

    ```cs
    int count = int.Parse("abc"); 
    ```

1.  运行代码并查看结果，如下所示：

    ```cs
    Unhandled Exception: System.FormatException: Input string was not in a correct format. 
    ```

除了上述异常消息外，你还会看到堆栈跟踪。由于堆栈跟踪占用太多空间，本书中未包含。

### 使用 TryParse 方法避免异常

为了避免错误，你可以使用`TryParse`方法。`TryParse`尝试转换输入的`string`，如果能够转换则返回`true`，否则返回`false`。

`out`关键字是必需的，以便`TryParse`方法在转换成功时设置计数变量。

让我们看看`TryParse`的实际应用：

1.  将`int` `count`声明替换为使用`TryParse`方法的语句，并要求用户输入鸡蛋的数量，如下所示：

    ```cs
    Write("How many eggs are there? "); 
    string? input = ReadLine(); // or use "12" in notebook
    if (int.TryParse(input, out int count))
    {
      WriteLine($"There are {count} eggs.");
    }
    else
    {
      WriteLine("I could not parse the input.");
    } 
    ```

1.  运行代码，输入`12`，查看结果，如下所示：

    ```cs
    How many eggs are there? 12
    There are 12 eggs. 
    ```

1.  运行代码，输入`twelve`（或在笔记本中将`string`值更改为`"twelve"`），查看结果，如下所示：

    ```cs
    How many eggs are there? twelve
    I could not parse the input. 
    ```

你还可以使用`System.Convert`类型的方法将`string`值转换为其他类型；然而，与`Parse`方法类似，如果无法转换，它会报错。

# 处理异常

你已经看到了几种类型转换时发生错误的场景。有些语言在出现问题时返回错误代码。.NET 使用异常，这些异常比返回值更丰富，专门用于失败报告，而返回值有多种用途。当这种情况发生时，我们说*运行时异常已被抛出*。

当抛出异常时，线程会被挂起，如果调用代码定义了`try-catch`语句，那么它就有机会处理这个异常。如果当前方法没有处理它，那么它的调用方法就有机会处理，以此类推，直到调用栈顶。

如你所见，控制台应用程序或.NET Interactive 笔记本的默认行为是输出有关异常的消息，包括堆栈跟踪，然后停止运行代码。应用程序终止。这比允许代码在可能损坏的状态下继续执行要好。你的代码应该只捕获和处理它理解并能正确修复的异常。

**良好实践**：尽量避免编写可能抛出异常的代码，或许可以通过执行`if`语句检查来实现。有时你做不到，有时最好让更高层次的组件来捕获调用你代码时抛出的异常。你将在*第四章*，*编写、调试和测试函数*中学习如何做到这一点。

## 将易出错的代码包裹在 try 块中

当你知道某个语句可能引发错误时，应该将该语句包裹在`try`块中。例如，从文本解析为数字可能引发错误。`catch`块中的任何语句只有在`try`块中的语句抛出异常时才会执行。

我们无需在`catch`块中做任何事情。让我们看看实际操作：

1.  使用您喜欢的编码工具，在`Chapter03`工作区/解决方案中添加一个新的**控制台应用程序**，命名为`HandlingExceptions`。

1.  在 Visual Studio Code 中，选择`HandlingExceptions`作为活动 OmniSharp 项目。

1.  输入语句以提示用户输入他们的年龄，然后将他们的年龄写入控制台，如下所示：

    ```cs
    WriteLine("Before parsing"); 
    Write("What is your age? "); 
    string? input = ReadLine(); // or use "49" in a notebook
    try
    {
      int age = int.Parse(input); 
      WriteLine($"You are {age} years old.");
    }
    catch
    {
    }
    WriteLine("After parsing"); 
    ```

    您将看到以下编译器消息：`Warning CS8604 Possible null reference argument for parameter 's' in 'int int.Parse(string s)'`。在新建的.NET 6 项目中，默认情况下，Microsoft 已启用可空引用类型，因此您会看到更多此类编译器警告。在生产代码中，您应添加代码以检查`null`并适当地处理这种可能性。在本书中，我不会包含这些`null`检查，因为代码示例并非设计为生产质量，并且到处都是`null`检查会使得代码杂乱无章，占用宝贵的页面。在这种情况下，`input`不可能为`null`，因为用户必须按 Enter 键，`ReadLine`才会返回，而那将返回一个空`string`。您将在本书的代码示例中看到数百个可能为`null`的变量。对于本书的代码示例，这些警告可以安全地忽略。只有在编写自己的生产代码时，您才需要类似的警告。您将在*第六章*，*实现接口和继承类*中了解更多关于空处理的内容。

    此代码包含两个消息，以指示*解析前*和*解析后*，使代码流程更清晰。随着示例代码变得更加复杂，这些将特别有用。

1.  运行代码，输入`49`，查看结果，如下所示：

    ```cs
    Before parsing
    What is your age? 49
    You are 49 years old. 
    After parsing 
    ```

1.  运行代码，输入`Kermit`，查看结果，如下所示：

    ```cs
    Before parsing
    What is your age? Kermit
    After parsing 
    ```

当代码执行时，错误异常被捕获，默认消息和堆栈跟踪未输出，控制台应用程序继续运行。这比默认行为更好，但查看发生的错误类型可能会有所帮助。

**良好实践**：在生产代码中，您绝不应使用像这样的空`catch`语句，因为它会“吞噬”异常并隐藏潜在问题。如果您无法或不想妥善处理异常，至少应记录该异常，或者重新抛出它，以便更高级别的代码可以决定如何处理。您将在*第四章*，*编写、调试和测试函数*中学习有关日志记录的内容。

### 捕获所有异常

要获取可能发生的任何类型异常的信息，您可以在`catch`块中声明一个类型为`System.Exception`的变量：

1.  在`catch`块中添加一个异常变量声明，并使用它将有关异常的信息写入控制台，如下所示：

    ```cs
    catch (Exception ex)
    {
      WriteLine($"{ex.GetType()} says {ex.Message}");
    } 
    ```

1.  再次运行代码，输入`Kermit`，查看结果，如下所示：

    ```cs
    Before parsing
    What is your age? Kermit
    System.FormatException says Input string was not in a correct format. 
    After parsing 
    ```

### 捕获特定异常

既然我们知道发生了哪种类型的特定异常，我们可以通过仅捕获该类型的异常并自定义向用户显示的消息来改进我们的代码：

1.  保留现有的`catch`块，并在其上方添加一个新的`catch`块，用于格式异常类型，如下面的突出显示代码所示：

    ```cs
    **catch (FormatException)**
    **{**
     **WriteLine(****"The age you entered is not a valid number format."****);**
    **}**
    catch (Exception ex)
    {
      WriteLine($"{ex.GetType()} says {ex.Message}");
    } 
    ```

1.  运行代码，再次输入`Kermit`，并查看结果，如下面的输出所示：

    ```cs
    Before parsing
    What is your age? Kermit
    The age you entered is not a valid number format. 
    After parsing 
    ```

    我们希望保留下面更一般的 catch 块的原因是，可能会有其他类型的异常发生。

1.  运行代码，输入`9876543210`，并查看结果，如下面的输出所示：

    ```cs
    Before parsing
    What is your age? 9876543210
    System.OverflowException says Value was either too large or too small for an Int32.
    After parsing 
    ```

    让我们为这种类型的异常再添加一个`catch`块。

1.  保留现有的`catch`块，并添加一个新的`catch`块，用于溢出异常类型，如下面的突出显示代码所示：

    ```cs
    **catch (OverflowException)**
    **{**
     **WriteLine(****"Your age is a valid number format but it is either too big or small."****);**
    **}**
    catch (FormatException)
    {
      WriteLine("The age you entered is not a valid number format.");
    } 
    ```

1.  运行代码，输入`9876543210`，并查看结果，如下面的输出所示：

    ```cs
    Before parsing
    What is your age? 9876543210
    Your age is a valid number format but it is either too big or small. 
    After parsing 
    ```

捕获异常的顺序很重要。正确的顺序与异常类型的继承层次结构有关。您将在*第五章*，*使用面向对象编程构建自己的类型*中学习继承。不过，不必过于担心这一点——如果异常顺序错误，编译器会给您构建错误。

**最佳实践**：避免过度捕获异常。通常应允许它们向上传播到调用堆栈，以便在更了解情况的层级处理，这可能会改变处理逻辑。您将在*第四章*，*编写、调试和测试函数*中学习到这一点。

### 使用过滤器捕获

您还可以使用`when`关键字在 catch 语句中添加过滤器，如下面的代码所示：

```cs
Write("Enter an amount: ");
string? amount = ReadLine();
try
{
  decimal amountValue = decimal.Parse(amount);
}
catch (FormatException) when (amount.Contains("$"))
{
  WriteLine("Amounts cannot use the dollar sign!");
}
catch (FormatException)
{
  WriteLine("Amounts must only contain digits!");
} 
```

# 检查溢出

之前，我们看到在数字类型之间转换时，可能会丢失信息，例如，将`long`变量转换为`int`变量时。如果存储在类型中的值太大，它将溢出。

## 使用 checked 语句抛出溢出异常

`checked`语句告诉.NET 在发生溢出时抛出异常，而不是默认允许它静默发生，这是出于性能原因。

我们将一个`int`变量的初始值设为其最大值减一。然后，我们将它递增几次，每次输出其值。一旦它超过其最大值，它就会溢出到最小值，并从那里继续递增。让我们看看这个过程：

1.  使用您喜欢的编程工具，在`Chapter03`工作区/解决方案中添加一个新的**控制台应用程序**，命名为`CheckingForOverflow`。

1.  在 Visual Studio Code 中，选择`CheckingForOverflow`作为活动的 OmniSharp 项目。

1.  在`Program.cs`中，键入语句以声明并赋值一个整数，其值为其最大可能值减一，然后递增它并在控制台上写入其值三次，如下面的代码所示：

    ```cs
    int x = int.MaxValue - 1; 
    WriteLine($"Initial value: {x}"); 
    x++;
    WriteLine($"After incrementing: {x}"); 
    x++;
    WriteLine($"After incrementing: {x}"); 
    x++;
    WriteLine($"After incrementing: {x}"); 
    ```

1.  运行代码并查看结果，显示值无声溢出并环绕至大负值，如下所示：

    ```cs
    Initial value: 2147483646
    After incrementing: 2147483647
    After incrementing: -2147483648
    After incrementing: -2147483647 
    ```

1.  现在，让我们通过使用`checked`语句块包裹这些语句，让编译器警告我们关于溢出的问题，如下所示：

    ```cs
    **checked**
    **{**
      int x = int.MaxValue - 1; 
      WriteLine($"Initial value: {x}"); 
      x++;
      WriteLine($"After incrementing: {x}"); 
      x++;
      WriteLine($"After incrementing: {x}"); 
      x++;
      WriteLine($"After incrementing: {x}");
    **}** 
    ```

1.  运行代码并查看结果，显示溢出检查导致异常抛出，如下所示：

    ```cs
    Initial value: 2147483646
    After incrementing: 2147483647
    Unhandled Exception: System.OverflowException: Arithmetic operation resulted in an overflow. 
    ```

1.  与其他异常一样，我们应该将这些语句包裹在`try`语句块中，并为用户显示更友好的错误消息，如下所示：

    ```cs
    try
    {
      // previous code goes here
    }
    catch (OverflowException)
    {
      WriteLine("The code overflowed but I caught the exception.");
    } 
    ```

1.  运行代码并查看结果，如下所示：

    ```cs
    Initial value: 2147483646
    After incrementing: 2147483647
    The code overflowed but I caught the exception. 
    ```

## 使用 unchecked 语句禁用编译器溢出检查

上一节讨论了*运行时*默认的溢出行为以及如何使用`checked`语句改变这种行为。本节将探讨*编译时*溢出行为以及如何使用`unchecked`语句改变这种行为。

相关关键字是`unchecked`。此关键字在代码块内关闭编译器执行的溢出检查。让我们看看如何操作：

1.  在之前的语句末尾输入以下语句。编译器不会编译此语句，因为它知道这将导致溢出：

    ```cs
    int y = int.MaxValue + 1; 
    ```

1.  将鼠标悬停在错误上，注意编译时检查显示为错误消息，如*图 3.1*所示：![图形用户界面，文本，应用程序，电子邮件 自动生成描述](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_03_01.png)

    图 3.1：PROBLEMS 窗口中的编译时检查

1.  要禁用编译时检查，将语句包裹在`unchecked`块中，将`y`的值写入控制台，递减它，并重复，如下所示：

    ```cs
    unchecked
    {
      int y = int.MaxValue + 1; 
      WriteLine($"Initial value: {y}"); 
      y--;
      WriteLine($"After decrementing: {y}"); 
      y--;
      WriteLine($"After decrementing: {y}");
    } 
    ```

1.  运行代码并查看结果，如下所示：

    ```cs
    Initial value: -2147483648
    After decrementing: 2147483647
    After decrementing: 2147483646 
    ```

当然，你很少会想要明确关闭这种检查，因为它允许溢出发生。但或许你能想到一个可能需要这种行为的场景。

# 实践与探索

通过回答一些问题来测试你的知识和理解，进行一些实践操作，并深入研究本章的主题。

## 练习 3.1 – 测试你的知识

回答以下问题：

1.  当`int`变量除以`0`时，会发生什么？

1.  当`double`变量除以`0`时，会发生什么？

1.  当`int`变量的值超出其范围（即溢出）时，会发生什么？

1.  `x = y++;`和`x = ++y;`之间有何区别？

1.  在循环语句中使用`break`、`continue`和`return`有何区别？

1.  `for`语句的三个部分是什么，哪些是必需的？

1.  `=`和`==`操作符之间有何区别？

1.  以下语句能否编译？

    ```cs
    for ( ; true; ) ; 
    ```

1.  在`switch`表达式中，下划线`_`代表什么？

1.  对象必须实现什么接口才能通过`foreach`语句进行枚举？

## 练习 3.2 – 探索循环和溢出

如果执行这段代码会发生什么？

```cs
int max = 500;
for (byte i = 0; i < max; i++)
{
  WriteLine(i);
} 
```

在`Chapter03`中创建一个名为`Exercise02`的控制台应用程序，并输入前面的代码。运行控制台应用程序并查看输出。发生了什么？

你可以添加什么代码（不要更改前面的任何代码）来警告我们这个问题？

## 练习 3.3 – 练习循环和运算符

**FizzBuzz** 是一种团体文字游戏，旨在教孩子们关于除法的知识。玩家轮流递增计数，用单词*fizz*替换任何可被三整除的数字，用单词*buzz*替换任何可被五整除的数字，用*fizzbuzz*替换任何可被两者整除的数字。

在`Chapter03`中创建一个名为`Exercise03`的控制台应用程序，输出一个模拟的 FizzBuzz 游戏，计数到 100。输出应类似于*图 3.2*：

![文本描述自动生成](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_03_02.png)

图 3.2：模拟的 FizzBuzz 游戏输出

## 练习 3.4 – 练习异常处理

在`Chapter03`中创建一个名为`Exercise04`的控制台应用程序，要求用户输入两个 0-255 范围内的数字，然后将第一个数字除以第二个数字：

```cs
Enter a number between 0 and 255: 100
Enter another number between 0 and 255: 8
100 divided by 8 is 12 
```

编写异常处理程序以捕获任何抛出的错误，如下面的输出所示：

```cs
Enter a number between 0 and 255: apples
Enter another number between 0 and 255: bananas 
FormatException: Input string was not in a correct format. 
```

## 练习 3.5 – 测试你对运算符的知识

执行以下语句后，`x`和`y`的值是什么？

1.  增量和加法运算符：

    ```cs
    x = 3;
    y = 2 + ++x; 
    ```

1.  二进制移位运算符：

    ```cs
    x = 3 << 2;
    y = 10 >> 1; 
    ```

1.  位运算符：

    ```cs
    x = 10 & 8;
    y = 10 | 7; 
    ```

## 练习 3.6 – 探索主题

使用下一页上的链接，详细了解本章涵盖的主题：

[`github.com/markjprice/cs10dotnet6/blob/main/book-links.md#chapter-3---controlling-flow-and-converting-types`](https://github.com/markjprice/cs10dotnet6/blob/main/book-links.md#chapter-3---controlling-flow-and-converting-types)

# 总结

本章中，你尝试了一些运算符，学习了如何分支和循环，如何进行类型转换，以及如何捕获异常。

你现在准备好学习如何通过定义函数重用代码块，如何向它们传递值并获取返回值，以及如何追踪代码中的错误并消除它们！


# 第四章：编写、调试和测试函数

本章是关于编写可重用代码的函数，开发过程中调试逻辑错误，运行时记录异常，单元测试代码以消除错误，并确保稳定性和可靠性。

本章涵盖以下主题：

+   编写函数

+   开发过程中的调试

+   运行时日志记录

+   单元测试

+   在函数中抛出和捕获异常

# 编写函数

编程的一个基本原则是 **不要重复自己** (**DRY**)。

编程时，如果你发现自己一遍又一遍地写相同的语句，那么将这些语句转换成一个函数。函数就像完成一项小任务的小程序。例如，你可能会编写一个计算销售税的函数，然后在财务应用程序的许多地方重用该函数。

与程序一样，函数通常有输入和输出。它们有时被描述为黑盒子，你在一端输入一些原材料，另一端就会产生成品。一旦创建，你不需要考虑它们是如何工作的。

## 乘法表示例

假设你想帮助你的孩子学习乘法表，因此你希望轻松生成任意数字的乘法表，例如 12 的乘法表：

```cs
1 x 12 = 12
2 x 12 = 24
...
12 x 12 = 144 
```

你之前在这本书中学过 `for` 语句，因此你知道它可以用来生成重复的输出行，当存在规律模式时，例如 12 的乘法表，如下列代码所示：

```cs
for (int row = 1; row <= 12; row++)
{
  Console.WriteLine($"{row} x 12 = {row * 12}");
} 
```

然而，我们不想只输出 12 的乘法表，而是希望使其更灵活，以便它可以输出任意数字的乘法表。我们可以通过创建一个函数来实现这一点。

### 编写乘法表函数

让我们通过创建一个输出 0 到 255 的任意数字乘以 1 到 12 的乘法表的函数来探索函数：

1.  使用你喜欢的编程工具创建一个新的控制台应用程序，如下表所定义：

    1.  项目模板：**控制台应用程序** / `console`

    1.  工作区/解决方案文件和文件夹：`Chapter04`

    1.  项目文件和文件夹：`WritingFunctions`

1.  静态导入 `System.Console`。

1.  在 `Program.cs` 中，编写语句以定义名为 `TimesTable` 的函数，如下列代码所示：

    ```cs
    static void TimesTable(byte number)
    {
      WriteLine($"This is the {number} times table:");
      for (int row = 1; row <= 12; row++)
      {
        WriteLine($"{row} x {number} = {row * number}");
      }
      WriteLine();
    } 
    ```

    在前面的代码中，请注意以下几点：

    +   `TimesTable` 方法必须接收一个名为 `number` 的 `byte` 类型参数。

    +   `TimesTable` 是一个 `static` 方法，因为它将由 `static` 方法 `Main` 调用。

    +   `TimesTable` 不向调用者返回值，因此它在其名称前声明了 `void` 关键字。

    +   `TimesTable` 使用一个 `for` 语句来输出传入的 `number` 的乘法表。

1.  在静态导入 `Console` 类和 `TimesTable` 函数之前，调用该函数并传入一个 `byte` 类型的 `number` 参数值，例如 `6`，如下列代码中突出显示的那样：

    ```cs
    using static System.Console;
    **TimesTable(****6****);** 
    ```

    **良好实践**：如果一个函数有一个或多个参数，仅传递值可能不足以表达其含义，那么你可以选择性地指定参数的名称及其值，如下所示：`TimesTable(number: 6)`。

1.  运行代码，然后查看结果，如下所示：

    ```cs
    This is the 6 times table:
    1 x 6 = 6
    2 x 6 = 12
    3 x 6 = 18
    4 x 6 = 24
    5 x 6 = 30
    6 x 6 = 36
    7 x 6 = 42
    8 x 6 = 48
    9 x 6 = 54
    10 x 6 = 60
    11 x 6 = 66
    12 x 6 = 72 
    ```

1.  将传递给`TimesTable`函数的数字更改为其他`byte`值，范围在`0`到`255`之间，并确认输出乘法表是否正确。

1.  注意，如果你尝试传递一个非`byte`类型的数字，例如`int`、`double`或`string`，将会返回一个错误，如下所示：

    ```cs
    Error: (1,12): error CS1503: Argument 1: cannot convert from 'int' to 'byte' 
    ```

## 编写一个返回值的函数

之前的函数执行了操作（循环和写入控制台），但没有返回值。假设你需要计算销售税或增值税（VAT）。在欧洲，VAT 税率可以从瑞士的 8%到匈牙利的 27%不等。在美国，州销售税率可以从俄勒冈州的 0%到加利福尼亚州的 8.25%不等。

税率随时在变化，且受多种因素影响。无需联系我告知弗吉尼亚州的税率是 6%，谢谢。

让我们实现一个计算全球各地税收的函数：

1.  添加一个名为`CalculateTax`的函数，如下所示：

    ```cs
    static decimal CalculateTax(
      decimal amount, string twoLetterRegionCode)
    {
      decimal rate = 0.0M;
      switch (twoLetterRegionCode)
      {
        case "CH": // Switzerland
          rate = 0.08M;
          break;
        case "DK": // Denmark
        case "NO": // Norway
          rate = 0.25M;
          break;
        case "GB": // United Kingdom
        case "FR": // France
          rate = 0.2M;
          break;
        case "HU": // Hungary
          rate = 0.27M;
          break;
        case "OR": // Oregon
        case "AK": // Alaska
        case "MT": // Montana
          rate = 0.0M;
          break;
        case "ND": // North Dakota
        case "WI": // Wisconsin
        case "ME": // Maine
        case "VA": // Virginia
          rate = 0.05M;
          break;
        case "CA": // California
          rate = 0.0825M;
          break;
        default: // most US states
          rate = 0.06M;
          break;
      }
      return amount * rate;
    } 
    ```

    在前述代码中，请注意以下几点：

    +   `CalculateTax`有两个输入：一个名为`amount`的参数，表示花费的金额，以及一个名为`twoLetterRegionCode`的参数，表示花费金额的地区。

    +   `CalculateTax`将使用`switch`语句进行计算，并返回该金额应缴纳的销售税或增值税作为`decimal`值；因此，在函数名前，我们声明了返回值的数据类型为`decimal`。

1.  注释掉`TimesTable`方法的调用，并调用`CalculateTax`方法，传入金额值如`149`和有效的地区代码如`FR`，如下所示：

    ```cs
    // TimesTable(6);
    decimal taxToPay = CalculateTax(amount: 149, twoLetterRegionCode: "FR"); 
    WriteLine($"You must pay {taxToPay} in tax."); 
    ```

1.  运行代码并查看结果，如下所示：

    ```cs
    You must pay 29.8 in tax. 
    ```

我们可以通过使用`{taxToPay:C}`将`taxToPay`的输出格式化为货币，但它会根据您的本地文化来决定如何格式化货币符号和小数。例如，在英国的我，会看到`£29.80`。

你能想到`CalculateTax`函数按原样编写可能存在的问题吗？如果用户输入一个代码如`fr`或`UK`会发生什么？如何重写该函数以改进它？使用`switch`*表达式*而不是`switch`*语句*是否会更为清晰？

## 将数字从基数转换为序数

用于计数的数字称为**基数**数字，例如 1、2 和 3，而用于排序的数字称为**序数**数字，例如 1st、2nd 和 3rd。让我们创建一个将基数转换为序数的函数：

1.  编写一个名为`CardinalToOrdinal`的函数，该函数将基数`int`值转换为序数`string`值；例如，它将 1 转换为 1st，2 转换为 2nd，依此类推，如下所示：

    ```cs
    static string CardinalToOrdinal(int number)
    {
      switch (number)
      {
        case 11: // special cases for 11th to 13th
        case 12:
        case 13:
          return $"{number}th";
        default:
          int lastDigit = number % 10;
          string suffix = lastDigit switch
          {
            1 => "st",
            2 => "nd",
            3 => "rd",
            _ => "th"
          };
          return $"{number}{suffix}";
      }
    } 
    ```

    从前面的代码中，请注意以下内容：

    +   `CardinalToOrdinal`有一个输入：名为`number`的`int`类型参数，一个输出：`string`类型的返回值。

    +   使用`switch`*语句*来处理 11、12 和 13 的特殊情况。

    +   然后使用`switch`*表达式*处理所有其他情况：如果最后一个数字是 1，则使用`st`作为后缀；如果最后一个数字是 2，则使用`nd`作为后缀；如果最后一个数字是 3，则使用`rd`作为后缀；如果最后一个数字是其他任何数字，则使用`th`作为后缀。

1.  编写一个名为`RunCardinalToOrdinal`的函数，该函数使用`for`语句从 1 循环到 40，对每个数字调用`CardinalToOrdinal`函数，并将返回的`字符串`写入控制台，以空格字符分隔，如下所示：

    ```cs
    static void RunCardinalToOrdinal()
    {
      for (int number = 1; number <= 40; number++)
      {
        Write($"{CardinalToOrdinal(number)} ");
      }
      WriteLine();
    } 
    ```

1.  注释掉`CalculateTax`语句，并调用`RunCardinalToOrdinal`方法，如下所示：

    ```cs
    // TimesTable(6);
    // decimal taxToPay = CalculateTax(amount: 149, twoLetterRegionCode: "FR"); 
    // WriteLine($"You must pay {taxToPay} in tax.");
    RunCardinalToOrdinal(); 
    ```

1.  运行代码并查看结果，如下所示：

    ```cs
    1st 2nd 3rd 4th 5th 6th 7th 8th 9th 10th 11th 12th 13th 14th 15th 16th 17th 18th 19th 20th 21st 22nd 23rd 24th 25th 26th 27th 28th 29th 30th 31st 32nd 33rd 34th 35th 36th 37th 38th 39th 40th 
    ```

## 使用递归计算阶乘

5 的阶乘是 120，因为阶乘是通过将起始数乘以比自身小 1 的数，然后再乘以小 1 的数，依此类推，直到数减至 1 来计算的。一个例子可以在这里看到：5 x 4 x 3 x 2 x 1 = 120。

阶乘这样表示：5!，其中感叹号读作 bang，所以 5! = 120，即*五 bang 等于一百二十*。Bang 是阶乘的好名字，因为它们的大小增长非常迅速，就像爆炸一样。

我们将编写一个名为`Factorial`的函数；这将计算传递给它的`int`参数的阶乘。我们将使用一种称为**递归**的巧妙技术，这意味着一个函数在其实现中调用自身，无论是直接还是间接：

1.  添加一个名为`Factorial`的函数，以及一个调用它的函数，如下所示：

    ```cs
    static int Factorial(int number)
    {
      if (number < 1)
      {
        return 0;
      }
      else if (number == 1)
      {
        return 1;
      }
      else
      {
        return number * Factorial(number - 1);
      }
    } 
    ```

    如前所述，前面的代码中有几个值得注意的元素，包括以下内容：

    +   如果输入参数`number`为零或负数，`Factorial`返回`0`。

    +   如果输入参数`number`为`1`，`Factorial`返回`1`，因此停止调用自身。

    +   如果输入参数`number`大于 1，在所有其他情况下都会如此，`Factorial`函数会将该数乘以调用自身并传递比`number`小 1 的结果。这使得函数具有递归性。

    **更多信息**：递归虽然巧妙，但可能导致问题，如因函数调用过多而导致的栈溢出，因为每次函数调用都会占用内存来存储数据，最终会消耗过多内存。在 C#等语言中，迭代是一种更实用（尽管不那么简洁）的解决方案。您可以在以下链接了解更多信息：[`en.wikipedia.org/wiki/Recursion_(computer_science)#Recursion_versus_iteration`](https://en.wikipedia.org/wiki/Recursion_(computer_science)#Recursion_versus_iteration)。

1.  添加一个名为`RunFactorial`的函数，该函数使用`for`语句输出 1 到 14 的阶乘，在循环内部调用`Factorial`函数，然后使用代码`N0`格式化输出结果，这意味着数字格式使用千位分隔符且无小数位，如下所示：

    ```cs
    static void RunFactorial()
    {
      for (int i = 1; i < 15; i++)
      {
        WriteLine($"{i}! = {Factorial(i):N0}");
      }
    } 
    ```

1.  注释掉`RunCardinalToOrdinal`方法调用，并调用`RunFactorial`方法。

1.  运行代码并查看结果，如下所示：

    ```cs
    1! = 1
    2! = 2
    3! = 6
    4! = 24
    5! = 120
    6! = 720
    7! = 5,040
    8! = 40,320
    9! = 362,880
    10! = 3,628,800
    11! = 39,916,800
    12! = 479,001,600
    13! = 1,932,053,504
    14! = 1,278,945,280 
    ```

在前面的输出中并不立即明显，但 13 及以上的阶乘会溢出`int`类型，因为它们太大了。12!是 479,001,600，大约是半十亿。`int`变量能存储的最大正数值大约是二十亿。13!是 6,227,020,800，大约是六十亿，当存储在 32 位整数中时，它会无声地溢出，不会显示任何问题。

你还记得我们可以做什么来获知数值溢出吗？

当发生溢出时，你应该怎么做才能得到通知？当然，我们可以通过使用`long`（64 位整数）而不是`int`（32 位整数）来解决 13!和 14!的问题，但我们很快会再次遇到溢出限制。

本节的重点是理解数字可能溢出以及如何显示溢出而非忽略它，并非特定于如何计算高于 12 的阶乘。

1.  修改`Factorial`函数以检查溢出，如下所示高亮显示：

    ```cs
    **checked** **// for overflow**
    **{**
      return number * Factorial(number - 1);
    **}** 
    ```

1.  修改`RunFactorial`函数以处理在调用`Factorial`函数时发生的溢出异常，如下所示高亮显示：

    ```cs
    **try**
    **{**
      WriteLine($"{i}! = {Factorial(i):N0}");
    **}**
    **catch (System.OverflowException)**
    **{**
     **WriteLine(****$"****{i}****! is too big for a 32-bit integer."****);**
    **}** 
    ```

1.  运行代码并查看结果，如下所示：

    ```cs
    1! = 1
    2! = 2
    3! = 6
    4! = 24
    5! = 120
    6! = 720
    7! = 5,040
    8! = 40,320
    9! = 362,880
    10! = 3,628,800
    11! = 39,916,800
    12! = 479,001,600
    13! is too big for a 32-bit integer.
    14! is too big for a 32-bit integer. 
    ```

## 使用 XML 注释记录函数

默认情况下，当调用如`CardinalToOrdinal`这样的函数时，代码编辑器会显示一个包含基本信息的工具提示，如*图 4.1*所示：

![图形用户界面，文本，应用程序 描述自动生成](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_04_01.png)

图 4.1：显示默认简单方法签名的工具提示

让我们通过添加额外信息来改进工具提示：

1.  如果你使用的是带有**C#**扩展的 Visual Studio Code，你应该导航到**视图** | **命令面板** | **首选项：打开设置（UI）**，然后搜索`formatOnType`并确保其已启用。C# XML 文档注释是 Visual Studio 2022 的内置功能。

1.  在`CardinalToOrdinal`函数上方的一行中，键入三个正斜杠`///`，并注意它们扩展成一个 XML 注释，该注释识别到函数有一个名为`number`的单个参数。

1.  为`CardinalToOrdinal`函数的 XML 文档注释输入合适的信息，以总结并描述输入参数和返回值，如下所示：

    ```cs
    /// <summary>
    /// Pass a 32-bit integer and it will be converted into its ordinal equivalent.
    /// </summary>
    /// <param name="number">Number is a cardinal value e.g. 1, 2, 3, and so on.</param>
    /// <returns>Number as an ordinal value e.g. 1st, 2nd, 3rd, and so on.</returns> 
    ```

1.  现在，在调用函数时，您将看到更多细节，如*图 4.2*所示：![图形用户界面，文本，应用程序，聊天或短信，电子邮件 自动生成描述](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_04_03.png)

图 4.2：显示更详细方法签名的工具提示

在编写第六版时，C# XML 文档注释在.NET Interactive 笔记本中不起作用。

**良好实践**：为所有函数添加 XML 文档注释。

## 在函数实现中使用 lambda 表达式

F#是微软的强类型函数优先编程语言，与 C#一样，它编译为 IL，由.NET 执行。函数式语言从 lambda 演算演变而来；一个仅基于函数的计算系统。代码看起来更像数学函数，而不是食谱中的步骤。

函数式语言的一些重要属性定义如下：

+   **模块化**：在 C#中定义函数的相同好处也适用于函数式语言。将大型复杂代码库分解为较小的部分。

+   **不可变性**：C#意义上的变量不存在。函数内部的任何数据值都不能更改。相反，可以从现有数据值创建新的数据值。这减少了错误。

+   **可维护性**：代码更简洁明了（对于数学倾向的程序员而言！）。

自 C# 6 以来，微软一直致力于为该语言添加功能，以支持更函数化的方法。例如，在 C# 7 中添加**元组**和**模式匹配**，在 C# 8 中添加**非空引用类型**，以及改进模式匹配并添加记录，即 C# 9 中的**不可变对象**。

C# 6 中，微软增加了对**表达式体函数成员**的支持。我们现在来看一个例子。

数字序列的**斐波那契数列**总是以 0 和 1 开始。然后，序列的其余部分按照前两个数字相加的规则生成，如下列数字序列所示：

```cs
0 1 1 2 3 5 8 13 21 34 55 ... 
```

序列中的下一个项将是 34 + 55，即 89。

我们将使用斐波那契数列来说明命令式和声明式函数实现之间的区别：

1.  添加一个名为`FibImperative`的函数，该函数将以命令式风格编写，如下所示：

    ```cs
    static int FibImperative(int term)
    {
      if (term == 1)
      {
        return 0;
      }
      else if (term == 2)
      {
        return 1;
      }
      else
      {
        return FibImperative(term - 1) + FibImperative(term - 2);
      }
    } 
    ```

1.  添加一个名为`RunFibImperative`的函数，该函数在从 1 到 30 的`for`循环中调用`FibImperative`，如下所示：

    ```cs
    static void RunFibImperative()
    {
      for (int i = 1; i <= 30; i++)
      {
        WriteLine("The {0} term of the Fibonacci sequence is {1:N0}.",
          arg0: CardinalToOrdinal(i),
          arg1: FibImperative(term: i));
      }
    } 
    ```

1.  注释掉其他方法调用，并调用`RunFibImperative`方法。

1.  运行代码并查看结果，如下所示：

    ```cs
    The 1st term of the Fibonacci sequence is 0.
    The 2nd term of the Fibonacci sequence is 1.
    The 3rd term of the Fibonacci sequence is 1.
    The 4th term of the Fibonacci sequence is 2.
    The 5th term of the Fibonacci sequence is 3.
    The 6th term of the Fibonacci sequence is 5.
    The 7th term of the Fibonacci sequence is 8.
    The 8th term of the Fibonacci sequence is 13.
    The 9th term of the Fibonacci sequence is 21.
    The 10th term of the Fibonacci sequence is 34.
    The 11th term of the Fibonacci sequence is 55.
    The 12th term of the Fibonacci sequence is 89.
    The 13th term of the Fibonacci sequence is 144.
    The 14th term of the Fibonacci sequence is 233.
    The 15th term of the Fibonacci sequence is 377.
    The 16th term of the Fibonacci sequence is 610.
    The 17th term of the Fibonacci sequence is 987.
    The 18th term of the Fibonacci sequence is 1,597.
    The 19th term of the Fibonacci sequence is 2,584.
    The 20th term of the Fibonacci sequence is 4,181.
    The 21st term of the Fibonacci sequence is 6,765.
    The 22nd term of the Fibonacci sequence is 10,946.
    The 23rd term of the Fibonacci sequence is 17,711.
    The 24th term of the Fibonacci sequence is 28,657.
    The 25th term of the Fibonacci sequence is 46,368.
    The 26th term of the Fibonacci sequence is 75,025.
    The 27th term of the Fibonacci sequence is 121,393.
    The 28th term of the Fibonacci sequence is 196,418.
    The 29th term of the Fibonacci sequence is 317,811.
    The 30th term of the Fibonacci sequence is 514,229. 
    ```

1.  添加一个名为`FibFunctional`的函数，采用声明式风格编写，如下列代码所示：

    ```cs
    static int FibFunctional(int term) => 
      term switch
      {
        1 => 0,
        2 => 1,
        _ => FibFunctional(term - 1) + FibFunctional(term - 2)
      }; 
    ```

1.  在`for`语句中添加一个调用它的函数，该语句从 1 循环到 30，如下列代码所示：

    ```cs
    static void RunFibFunctional()
    {
      for (int i = 1; i <= 30; i++)
      {
        WriteLine("The {0} term of the Fibonacci sequence is {1:N0}.",
          arg0: CardinalToOrdinal(i),
          arg1: FibFunctional(term: i));
      }
    } 
    ```

1.  注释掉`RunFibImperative`方法调用，并调用`RunFibFunctional`方法。

1.  运行代码并查看结果（与之前相同）。

# 开发过程中的调试

在本节中，你将学习如何在开发时调试问题。你必须使用具有调试工具的代码编辑器，如 Visual Studio 或 Visual Studio Code。在撰写本文时，你不能使用.NET Interactive Notebooks 来调试代码，但预计未来会添加此功能。

**更多信息**：有些人发现为 Visual Studio Code 设置 OmniSharp 调试器很棘手。我已包含最常见问题的解决方法，但如果你仍有困难，尝试阅读以下链接中的信息：[`github.com/OmniSharp/omnisharp-vscode/blob/master/debugger.md`](https://github.com/OmniSharp/omnisharp-vscode/blob/master/debugger.md)

## 创建带有故意错误的代码

让我们通过创建一个带有故意错误的控制台应用程序来探索调试，然后我们将使用代码编辑器中的调试工具来追踪并修复它：

1.  使用您偏好的编程工具，在`Chapter04`工作区/解决方案中添加一个名为`Debugging`的**控制台应用程序**。

1.  在 Visual Studio Code 中，选择`Debugging`作为活动 OmniSharp 项目。当看到提示缺少必需资产的弹出警告消息时，点击**是**以添加它们。

1.  在 Visual Studio 中，将解决方案的启动项目设置为当前选择。

1.  在`Program.cs`中，添加一个带有故意错误的函数，如下列代码所示：

    ```cs
    static double Add(double a, double b)
    {
      return a * b; // deliberate bug!
    } 
    ```

1.  在`Add`函数下方，编写语句以声明并设置一些变量，然后使用有缺陷的函数将它们相加，如下列代码所示：

    ```cs
    double a = 4.5;
    double b = 2.5;
    double answer = Add(a, b); 
    WriteLine($"{a} + {b} = {answer}");
    WriteLine("Press ENTER to end the app.");
    ReadLine(); // wait for user to press ENTER 
    ```

1.  运行控制台应用程序并查看结果，如下列部分输出所示：

    ```cs
    4.5 + 2.5 = 11.25 
    ```

但是等等，有个错误！4.5 加上 2.5 应该是 7，而不是 11.25！

我们将使用调试工具来追踪并消除这个错误。

## 设置断点并开始调试

断点允许我们在想要暂停以检查程序状态和查找错误的代码行上做标记。

### 使用 Visual Studio 2022

让我们设置一个断点，然后使用 Visual Studio 2022 开始调试：

1.  点击声明名为`a`的变量的语句。

1.  导航至**调试** | **切换断点**或按 F9。随后，左侧边距栏中将出现一个红色圆圈，语句将以红色高亮显示，表明已设置断点，如*图 4.3*所示：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_04_04.png)

    *图 4.3*：使用 Visual Studio 2022 切换断点

    断点可以通过相同的操作关闭。你也可以在边距处左键点击来切换断点的开启和关闭，或者右键点击断点以查看更多选项，例如删除、禁用或编辑现有断点的条件或操作。

1.  导航至**调试** | **开始调试**或按 F5。Visual Studio 启动控制台应用程序，并在遇到断点时暂停。这称为中断模式。额外的窗口标题为**局部变量**（显示当前局部变量的值），**监视 1**（显示你定义的任何监视表达式），**调用堆栈**，**异常设置**和**即时窗口**出现。**调试**工具栏出现。下一条将要执行的行以黄色高亮显示，黄色箭头从边距栏指向该行，如图*4.4*所示：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_04_05.png)

图 4.4：Visual Studio 2022 中的中断模式

如果你不想了解如何使用 Visual Studio Code 开始调试，则可以跳过下一节，继续阅读标题为*使用调试工具栏导航*的部分。

### 使用 Visual Studio Code

让我们设置一个断点，然后使用 Visual Studio Code 开始调试：

1.  点击声明名为`a`的变量的语句。

1.  导航至**运行** | **切换断点**或按 F9。边距栏左侧将出现一个红色圆圈，表示已设置断点，如图*4.5*所示：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_04_06.png)

    图 4.5：使用 Visual Studio Code 切换断点

    断点可以通过相同的操作关闭。你也可以在边距处左键点击来切换断点的开启和关闭，或者右键点击断点以查看更多选项，例如删除、禁用或编辑现有断点的条件或操作；或者在没有断点时添加断点、条件断点或日志点。

    日志点，也称为跟踪点，表示你希望记录某些信息而不必实际停止在该点执行代码。

1.  导航至**视图** | **运行**，或在左侧导航栏中点击**运行和调试**图标（三角形“播放”按钮和“错误”），如图*4.5*所示。

1.  在**调试**窗口顶部，点击**开始调试**按钮（绿色三角形“播放”按钮）右侧的下拉菜单，并选择**.NET Core 启动（控制台）（调试）**，如图*4.6*所示：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_04_07.png)

    图 4.6：使用 Visual Studio Code 选择要调试的项目

    **最佳实践**：如果在**调试**项目的下拉列表中没有看到选项，那是因为该项目没有所需的调试资产。这些资产存储在 `.vscode` 文件夹中。要为项目创建 `.vscode` 文件夹，请导航至**视图** | **命令面板**，选择 **OmniSharp: 选择项目**，然后选择**调试**项目。几秒钟后，当提示**调试中缺少构建和调试所需的资产。添加它们？**时，点击**是**以添加缺失的资产。

1.  在**调试**窗口顶部，点击**开始调试**按钮（绿色三角形“播放”按钮），或导航至**运行** | **开始调试**，或按 F5。Visual Studio Code 启动控制台应用程序，并在遇到断点时暂停。这称为断点模式。接下来要执行的行以黄色高亮显示，黄色方块从边距栏指向该行，如*图 4.7* 所示：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_04_08.png)

    *图 4.7*：Visual Studio Code 中的断点模式

## 使用调试工具栏导航

Visual Studio Code 显示一个浮动工具栏，上面有按钮，方便访问调试功能。Visual Studio 2022 在**标准**工具栏上有一个按钮用于开始或继续调试，另外还有一个单独的**调试**工具栏用于其他工具。

两者均在*图 4.8* 中展示，并按以下列表描述：

![图形用户界面 描述自动生成，中等置信度](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_04_09.png)

*图 4.8*：Visual Studio 2022 和 Visual Studio Code 中的调试工具栏

+   **继续** / F5：此按钮将从当前位置继续运行程序，直到程序结束或遇到另一个断点。

+   **单步执行** / F10，**单步进入** / F11，**单步退出** / Shift + F11（蓝色箭头在点上）：这些按钮以不同方式逐条执行代码语句，稍后你将看到。

+   **重新启动** / Ctrl 或 Cmd + Shift + F5（圆形箭头）：此按钮将停止程序，然后立即重新启动，同时再次附加调试器。

+   **停止** / Shift + F5（红色方块）：此按钮将停止调试会话。

## 调试窗口

在调试时，Visual Studio Code 和 Visual Studio 都会显示额外的窗口，以便你在逐步执行代码时监控诸如变量等有用信息。

以下列表描述了最有用的窗口：

+   **变量**，包括**局部变量**，自动显示任何局部变量的名称、值和类型。在逐步执行代码时，请留意此窗口。

+   **监视**，或**监视 1**，显示你手动输入的变量和表达式的值。

+   **调用堆栈**，显示函数调用堆栈。

+   **断点**，显示所有断点并允许对其进行更精细的控制。

在断点模式下，编辑区域底部还有一个有用的窗口：

+   **DEBUG CONSOLE**或**即时窗口**使您能够与代码实时交互。您可以查询程序状态，例如，通过输入变量名。例如，您可以通过输入`1+2`并按 Enter 键来提问“1+2 等于多少？”，如图*4.9*所示：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_04_10.png)

图 4.9：查询程序状态

## 逐行执行代码

让我们探索一些使用 Visual Studio 或 Visual Studio Code 逐行执行代码的方法：

1.  导航至**运行/调试** | **逐语句**，或点击工具栏中的**逐语句**按钮，或按 F11。黄色高亮将前进一行。

1.  导航至**运行/调试** | **逐过程**，或点击工具栏中的**逐过程**按钮，或按 F10。黄色高亮将前进一行。目前，您可以看到使用**逐语句**或**逐过程**没有区别。

1.  您现在应该位于调用`Add`方法的行上，如图*4.10*所示：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_04_11.png)

    图 4.10：逐语句进入和跳过代码

    **逐语句**与**逐过程**的区别在于即将执行方法调用时：

    +   如果点击**逐语句**，调试器将进入方法内部，以便您可以逐行执行该方法。

    +   如果点击**逐过程**，整个方法将一次性执行；它不会跳过该方法而不执行。

1.  点击**逐语句**以进入方法内部。

1.  将鼠标悬停在代码编辑窗口中的`a`或`b`参数上，注意会出现一个工具提示，显示它们的当前值。

1.  选中表达式`a * b`，右键点击表达式，并选择**添加到监视**或**添加监视**。该表达式被添加到**监视**窗口，显示此运算符正在将`a`乘以`b`以得到结果`11.25`。

1.  在**监视**或**监视 1**窗口中，右键点击表达式并选择**删除表达式**或**删除监视**。

1.  通过在`Add`函数中将`*`更改为`+`来修复错误。

1.  停止调试，重新编译，并通过点击圆形箭头**重新启动**按钮或按 Ctrl 或 Cmd + Shift + F5 重新开始调试。

1.  跳过该函数，花一分钟注意它现在如何正确计算，然后点击**继续**按钮或按**F5**。

1.  使用 Visual Studio Code 时，请注意，在调试期间向控制台写入内容时，输出显示在**DEBUG CONSOLE**窗口中，而不是**TERMINAL**窗口中，如图*4.11*所示：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_04_13.png)

    图 4.11：调试期间向 DEBUG CONSOLE 写入内容

## 自定义断点

创建更复杂的断点很容易：

1.  若仍在调试中，点击调试工具栏中的**停止**按钮，或导航至**运行/调试** | **停止调试**，或按 Shift + F5。

1.  导航至**运行** | **删除所有断点**或**调试** | **删除所有断点**。

1.  点击输出答案的`WriteLine`语句。

1.  通过按 F9 或导航至**运行/调试** | **切换断点**来设置断点。

1.  在 Visual Studio Code 中，右键点击断点并选择**编辑断点...**，然后输入一个表达式，例如`answer`变量必须大于 9，注意表达式必须计算为真才能激活断点，如图*4.12*所示：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_04_14.png)

    图 4.12：使用 Visual Studio Code 通过表达式自定义断点

1.  在 Visual Studio 中，右键点击断点并选择**条件...**，然后输入一个表达式，例如`answer`变量必须大于 9，注意表达式必须计算为真才能激活断点。

1.  开始调试并注意断点未被命中。

1.  停止调试。

1.  编辑断点或其条件，并将其表达式更改为小于 9。

1.  开始调试并注意断点被命中。

1.  停止调试。

1.  编辑断点或其条件，（在 Visual Studio 中点击**添加条件**）并选择**命中计数**，然后输入一个数字，如`3`，意味着断点需被命中三次才会激活，如图*4.13*所示：![图形用户界面，文本，应用程序 自动生成描述](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_04_15.png)

    图 4.13：使用 Visual Studio 2022 通过表达式和热计数自定义断点

1.  将鼠标悬停在断点的红色圆圈上以查看摘要，如图*4.14*所示：![图形用户界面，文本，应用程序 自动生成描述](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_04_16.png)

    图 4.14：Visual Studio Code 中自定义断点的摘要

您现在已使用一些调试工具修复了一个错误，并看到了设置断点的一些高级可能性。

# 开发和运行时日志记录

一旦您认为代码中的所有错误都已被移除，您将编译发布版本并部署应用程序，以便人们可以使用它。但没有任何代码是完全无错误的，运行时可能会发生意外错误。

最终用户通常不擅长记忆、承认，然后准确描述他们在错误发生时正在做什么，因此您不应依赖他们准确提供有用信息来重现问题以理解问题原因并进行修复。相反，您可以**检测您的代码**，这意味着记录感兴趣的事件。

**最佳实践**：在应用程序中添加代码以记录正在发生的事情，特别是在异常发生时，以便您可以审查日志并使用它们来追踪问题并修复问题。虽然我们将在*第十章*，*使用 Entity Framework Core 处理数据*，以及*第十五章*，*使用模型-视图-控制器模式构建网站*中再次看到日志记录，但日志记录是一个庞大的主题，因此本书只能涵盖基础知识。

## 理解日志记录选项

.NET 包含一些内置方法，通过添加日志记录功能来检测您的代码。本书将介绍基础知识。但日志记录是一个领域，第三方已经创建了一个丰富的生态系统，提供了超越微软所提供的强大解决方案。我无法做出具体推荐，因为最佳日志记录框架取决于您的需求。但我在此列出了一些常见选项：

+   Apache log4net

+   NLog

+   Serilog

## 使用调试和跟踪进行检测

有两种类型可用于向代码添加简单日志记录：`Debug`和`Trace`。

在我们深入探讨它们之前，让我们先快速概览一下每个：

+   `Debug`类用于添加仅在开发期间写入的日志记录。

+   `Trace`类用于添加在开发和运行时都会写入的日志记录。

您已见过`Console`类型的使用及其`WriteLine`方法向控制台窗口输出的情况。还有一对名为`Debug`和`Trace`的类型，它们在输出位置上更具灵活性。

`Debug`和`Trace`类向任何跟踪监听器写入。跟踪监听器是一种类型，可以配置为在调用`WriteLine`方法时将输出写入您喜欢的任何位置。.NET 提供了几种跟踪监听器，包括一个输出到控制台的监听器，您甚至可以通过继承`TraceListener`类型来创建自己的监听器。

### 写入默认跟踪监听器

一个跟踪监听器，即`DefaultTraceListener`类，是自动配置的，并写入 Visual Studio Code 的**DEBUG CONSOLE**窗口或 Visual Studio 的**Debug**窗口。您可以通过代码配置其他跟踪监听器。

让我们看看跟踪监听器的作用：

1.  使用您偏好的编码工具，在`Chapter04`工作区/解决方案中添加一个名为`Instrumenting`的新**控制台应用程序**。

1.  在 Visual Studio Code 中，选择`Instrumenting`作为活动 OmniSharp 项目。当您看到弹出警告消息提示所需资产缺失时，点击**是**以添加它们。

1.  在`Program.cs`中，导入`System.Diagnostics`命名空间。

1.  按照以下代码所示，从`Debug`和`Trace`类中写入一条消息：

    ```cs
    Debug.WriteLine("Debug says, I am watching!");
    Trace.WriteLine("Trace says, I am watching!"); 
    ```

1.  在 Visual Studio 中，导航至**视图** | **输出**，并确保**显示输出自：** **调试**被选中。

1.  开始调试`Instrumenting`控制台应用程序，并注意 Visual Studio Code 中的**DEBUG CONSOLE**或 Visual Studio 2022 中的**Output**窗口显示了这两条消息，以及其他调试信息，如加载的程序集 DLL，如*图 4.15*和*4.16*所示：![图形用户界面，文本，网站 描述自动生成](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_04_17.png)

    *图 4.15*：Visual Studio Code DEBUG CONSOLE 以蓝色显示两条消息

    ![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_04_18.png)

    *图 4.16*：Visual Studio 2022 Output 窗口显示包括两条消息在内的调试输出

## 配置跟踪监听器

现在，我们将配置另一个将写入文本文件的跟踪监听器：

1.  在`Debug`和`Trace`的`WriteLine`调用之前，添加一个语句以在桌面上创建一个新的文本文件，并将其传递给一个新的跟踪监听器，该监听器知道如何写入文本文件，并为缓冲区启用自动刷新，如下面的代码中突出显示的那样：

    ```cs
    **// write to a text file in the project folder**
    **Trace.Listeners.Add(****new** **TextWriterTraceListener(**
     **File.CreateText(Path.Combine(Environment.GetFolderPath(**
     **Environment.SpecialFolder.DesktopDirectory),** **"log.txt"****))));**
    **// text writer is buffered, so this option calls**
    **// Flush() on all listeners after writing**
    **Trace.AutoFlush =** **true****;**
    Debug.WriteLine("Debug says, I am watching!");
    Trace.WriteLine("Trace says, I am watching!"); 
    ```

    **良好实践**：任何表示文件的类型通常都会实现一个缓冲区以提高性能。数据不是立即写入文件，而是写入内存缓冲区，只有当缓冲区满时，数据才会一次性写入文件。这种行为在调试时可能会令人困惑，因为我们不会立即看到结果！启用`AutoFlush`意味着在每次写入后自动调用`Flush`方法。

1.  在 Visual Studio Code 中，通过在`Instrumenting`项目的**TERMINAL**窗口中输入以下命令来运行控制台应用的发布配置，并注意到似乎没有任何事情发生：

    ```cs
    dotnet run --configuration Release 
    ```

1.  在 Visual Studio 2022 中，在标准工具栏上，从**解决方案配置**下拉列表中选择**Release**，如图*4.17*所示：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_04_19.png)

    图 4.17：在 Visual Studio 中选择 Release 配置

1.  在 Visual Studio 2022 中，通过导航到**Debug** | **开始不调试**来运行控制台应用的发布配置。

1.  在您的桌面上，打开名为`log.txt`的文件，并注意到它包含消息`Trace says, I am watching!`。

1.  在 Visual Studio Code 中，通过在`Instrumenting`项目的**TERMINAL**窗口中输入以下命令来运行控制台应用的调试配置：

    ```cs
    dotnet run --configuration Debug 
    ```

1.  在 Visual Studio 中，在标准工具栏上，从**解决方案配置**下拉列表中选择**Debug**，然后通过导航到**Debug** | **开始调试**来运行控制台应用。

1.  在您的桌面上，打开名为`log.txt`的文件，并注意到它包含了消息`Debug says, I am watching!`和`Trace says, I am watching!`。

**良好实践**：当使用`Debug`配置运行时，`Debug`和`Trace`均处于激活状态，并将写入任何跟踪监听器。当使用`Release`配置运行时，只有`Trace`会写入任何跟踪监听器。因此，您可以在代码中自由使用`Debug.WriteLine`调用，知道在构建应用程序的发布版本时它们会自动被移除，从而不会影响性能。

## 切换跟踪级别

`Trace.WriteLine`调用即使在发布后仍保留在代码中。因此，能够精细控制它们的输出时机将非常有益。这可以通过**跟踪开关**实现。

跟踪开关的值可以使用数字或单词设置。例如，数字`3`可以替换为单词`Info`，如下表所示：

| 编号 | 单词 | 描述 |
| --- | --- | --- |
| 0 | Off | 这将不输出任何内容。 |
| 1 | Error | 这将仅输出错误。 |
| 2 | Warning | 这将输出错误和警告。 |
| 3 | 信息 | 这将输出错误、警告和信息。 |
| 4 | 详细 | 这将输出所有级别。 |

让我们探索使用跟踪开关。首先，我们将向项目添加一些 NuGet 包，以启用从 JSON `appsettings`文件加载配置设置。

### 在 Visual Studio Code 中向项目添加包

Visual Studio Code 没有向项目添加 NuGet 包的机制，因此我们将使用命令行工具：

1.  导航到`Instrumenting`项目的**终端**窗口。

1.  输入以下命令：

    ```cs
    dotnet add package Microsoft.Extensions.Configuration 
    ```

1.  输入以下命令：

    ```cs
    dotnet add package Microsoft.Extensions.Configuration.Binder 
    ```

1.  输入以下命令：

    ```cs
    dotnet add package Microsoft.Extensions.Configuration.Json 
    ```

1.  输入以下命令：

    ```cs
    dotnet add package Microsoft.Extensions.Configuration.FileExtensions 
    ```

    `dotnet add package`向项目文件添加对 NuGet 包的引用。它将在构建过程中下载。`dotnet add reference`向项目文件添加项目到项目的引用。如果需要，将在构建过程中编译引用的项目。

### 在 Visual Studio 2022 中向项目添加包

Visual Studio 具有添加包的图形用户界面。

1.  在**解决方案资源管理器**中，右键单击**Instrumenting**项目并选择**管理 NuGet 包**。

1.  选择**浏览**选项卡。

1.  在搜索框中，输入`Microsoft.Extensions.Configuration`。

1.  选择这些 NuGet 包中的每一个，然后点击**安装**按钮，如图*4.18*所示：

    1.  `Microsoft.Extensions.Configuration`

    1.  `Microsoft.Extensions.Configuration.Binder`

    1.  `Microsoft.Extensions.Configuration.Json`

    1.  `Microsoft.Extensions.Configuration.FileExtensions`![图形用户界面，文本，应用程序 描述自动生成](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_04_20.png)

    图 4.18：使用 Visual Studio 2022 安装 NuGet 包

**最佳实践**：还有用于从 XML 文件、INI 文件、环境变量和命令行加载配置的包。为项目设置配置选择最合适的技术。

### 审查项目包

添加 NuGet 包后，我们可以在项目文件中看到引用：

1.  打开`Instrumenting.csproj`（在 Visual Studio 的**解决方案资源管理器**中双击**Instrumenting**项目），并注意添加了 NuGet 包的`<ItemGroup>`部分，如下所示高亮显示：

    ```cs
    <Project Sdk="Microsoft.NET.Sdk">
      <PropertyGroup>
        <OutputType>Exe</OutputType>
        <TargetFramework>net6.0</TargetFramework>
        <Nullable>enable</Nullable>
        <ImplicitUsings>enable</ImplicitUsings>
      </PropertyGroup>
     **<ItemGroup>**
     **<PackageReference**
     **Include=****"Microsoft.Extensions.Configuration"**
     **Version=****"6.0.0"** **/>**
     **<PackageReference**
     **Include=****"Microsoft.Extensions.Configuration.Binder"**
     **Version=****"6.0.0"** **/>**
     **<PackageReference**
     **Include=****"Microsoft.Extensions.Configuration.FileExtensions"**
     **Version=****"6.0.0"** **/>**
     **<PackageReference**
     **Include=****"Microsoft.Extensions.Configuration.Json"**
     **Version=****"6.0.0"** **/>**
     **</ItemGroup>**
    </Project> 
    ```

1.  向`Instrumenting`项目文件夹添加一个名为`appsettings.json`的文件。

1.  修改`appsettings.json`以定义一个名为`PacktSwitch`的设置，其`Level`值如下所示：

    ```cs
    {
      "PacktSwitch": {
        "Level": "Info"
      }
    } 
    ```

1.  在 Visual Studio 2022 中，在**解决方案资源管理器**中右键单击`appsettings.json`，选择**属性**，然后在**属性**窗口中，将**复制到输出目录**更改为**如果较新则复制**。这是必要的，因为与在项目文件夹中运行控制台应用程序的 Visual Studio Code 不同，Visual Studio 在`Instrumenting\bin\Debug\net6.0`或`Instrumenting\bin\Release\net6.0`中运行控制台应用程序。

1.  在`Program.cs`顶部，导入`Microsoft.Extensions.Configuration`命名空间。

1.  在`Program.cs`末尾添加一些语句，以创建一个配置构建器，该构建器会在当前文件夹中查找名为`appsettings.json`的文件，构建配置，创建跟踪开关，通过绑定到配置来设置其级别，然后输出四个跟踪开关级别，如下面的代码所示：

    ```cs
    ConfigurationBuilder builder = new();
    builder.SetBasePath(Directory.GetCurrentDirectory())
      .AddJsonFile("appsettings.json", 
        optional: true, reloadOnChange: true);
    IConfigurationRoot configuration = builder.Build(); 
    TraceSwitch ts = new(
      displayName: "PacktSwitch",
      description: "This switch is set via a JSON config."); 
    configuration.GetSection("PacktSwitch").Bind(ts);
    Trace.WriteLineIf(ts.TraceError, "Trace error"); 
    Trace.WriteLineIf(ts.TraceWarning, "Trace warning"); 
    Trace.WriteLineIf(ts.TraceInfo, "Trace information"); 
    Trace.WriteLineIf(ts.TraceVerbose, "Trace verbose"); 
    ```

1.  在`Bind`语句上设置断点。

1.  开始调试`Instrumenting`控制台应用。在**变量**或**局部变量**窗口中，展开`ts`变量表达式，并注意其`级别`为`Off`，其`TraceError`、`TraceWarning`等均为`false`，如图 *4.19* 所示：![图形用户界面，文本，应用程序 自动生成的描述](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_04_21.png)

    图 4.19：在 Visual Studio 2022 中观察跟踪开关变量属性

1.  通过点击**步入**或**步过**按钮，或按 F11 或 F10，步入对`Bind`方法的调用，并注意`ts`变量监视表达式更新至`Info`级别。

1.  步入或步过对`Trace.WriteLineIf`的四次调用，并注意所有级别直至`Info`都被写入到**DEBUG CONSOLE**或**输出 - 调试**窗口，但不包括`Verbose`，如图 *4.20* 所示：![图形用户界面，文本，应用程序 自动生成的描述](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_04_22.png)

    图 4.20：在 Visual Studio Code 的 DEBUG CONSOLE 中显示的不同跟踪级别

1.  停止调试。

1.  修改`appsettings.json`，将其级别设置为`2`，即警告，如下面的 JSON 文件所示：

    ```cs
    {
      "PacktSwitch": { 
        "Level": "2"
      }
    } 
    ```

1.  保存更改。

1.  在 Visual Studio Code 中，通过在`Instrumenting`项目的**TERMINAL**窗口中输入以下命令来运行控制台应用程序：

    ```cs
    dotnet run --configuration Release 
    ```

1.  在 Visual Studio 的标准工具栏中，从**解决方案配置**下拉列表中选择**发布**，然后通过导航到**调试** | **启动而不调试**来运行控制台应用。

1.  打开名为`log.txt`的文件，并注意这次只有跟踪错误和警告级别是四个潜在跟踪级别的输出，如下面的文本文件所示：

    ```cs
    Trace says, I am watching! 
    Trace error
    Trace warning 
    ```

如果没有传递参数，默认的跟踪开关级别为`Off`（0），因此不会输出任何开关级别。

# 单元测试

修复代码中的 bug 成本高昂。在开发过程中越早发现 bug，修复它的成本就越低。

单元测试是早期开发过程中发现 bug 的好方法。一些开发者甚至遵循程序员应在编写代码之前创建单元测试的原则，这称为**测试驱动开发**（**TDD**）。

微软有一个专有的单元测试框架，称为**MS Test**。还有一个名为**NUnit**的框架。然而，我们将使用免费且开源的第三方框架**xUnit.net**。xUnit 是由构建 NUnit 的同一团队创建的，但他们修正了之前感觉错误的方面。xUnit 更具扩展性，并拥有更好的社区支持。

## 理解测试类型

单元测试只是众多测试类型中的一种，如下表所述：

| 测试类型 | 描述 |
| --- | --- |
| 单元 | 测试代码的最小单元，通常是一个方法或函数。单元测试是通过模拟其依赖项（如果需要）来隔离代码单元进行的。每个单元应该有多个测试：一些使用典型输入和预期输出，一些使用极端输入值来测试边界，还有一些使用故意错误的输入来测试异常处理。 |
| 集成 | 测试较小的单元和较大的组件是否能作为一个软件整体协同工作。有时涉及与没有源代码的外部组件的集成。 |
| 系统 | 测试你的软件将运行的整个系统环境。 |
| 性能 | 测试你的软件性能；例如，你的代码必须在 20 毫秒内向访问者返回一个充满数据的网页。 |
| 负载 | 测试你的软件在保持所需性能的同时可以处理多少请求，例如，一个网站可以同时容纳 10,000 名访问者。 |
| 用户接受度 | 测试用户是否能愉快地使用你的软件完成他们的工作。 |

## 创建一个需要测试的类库

首先，我们将创建一个需要测试的函数。我们将在类库项目中创建它。类库是一个可以被其他.NET 应用程序分发和引用的代码包：

1.  使用你偏好的编码工具，在`Chapter04`工作区/解决方案中添加一个新的**类库**，命名为`CalculatorLib`。`dotnet new`模板名为`classlib`。

1.  将文件名为`Class1.cs`重命名为`Calculator.cs`。

1.  修改文件以定义一个`Calculator`类（故意包含一个错误！），如下所示的代码：

    ```cs
    namespace Packt
    {
      public class Calculator
      {
        public double Add(double a, double b)
        {
          return a * b;
        }
      }
    } 
    ```

1.  编译你的类库项目：

    1.  在 Visual Studio 2022 中，导航到**构建** | **构建 CalculatorLib**。

    1.  在 Visual Studio Code 中，在**终端**中输入命令`dotnet build`。

1.  使用你偏好的编码工具，在`Chapter04`工作区/解决方案中添加一个新的**xUnit 测试项目[C#]**，命名为`CalculatorLibUnitTests`。`dotnet new`模板名为`xunit`。

1.  如果你使用的是 Visual Studio，在**解决方案资源管理器**中，选择`CalculatorLibUnitTests`项目，导航到**项目** | **添加项目引用…**，勾选框选择`CalculatorLib`项目，然后点击**确定**。

1.  如果你使用的是 Visual Studio Code，使用`dotnet add reference`命令或点击名为`CalculatorLibUnitTests.csproj`的文件，并修改配置以添加一个项目参考到`CalculatorLib`项目，如下所示的高亮标记：

    ```cs
    <Project Sdk="Microsoft.NET.Sdk">
      <PropertyGroup>
        <TargetFramework>net6.0</TargetFramework>
        <Nullable>enable</Nullable>
        <IsPackable>false</IsPackable>
      </PropertyGroup>
      <ItemGroup>
        <PackageReference Include="Microsoft.NET.Test.Sdk" Version="16.10.0" />
        <PackageReference Include="xunit" Version="2.4.1" />
        <PackageReference Include="xunit.runner.visualstudio" Version="2.4.3">
          <IncludeAssets>runtime; build; native; contentfiles; 
            analyzers; buildtransitive</IncludeAssets>
          <PrivateAssets>all</PrivateAssets>
        </PackageReference>
        <PackageReference Include="coverlet.collector" Version="3.0.2">
          <IncludeAssets>runtime; build; native; contentfiles; 
            analyzers; buildtransitive</IncludeAssets>
          <PrivateAssets>all</PrivateAssets>
        </PackageReference>
      </ItemGroup>
     **<ItemGroup>**
     **<ProjectReference**
     **Include=****"..\CalculatorLib\CalculatorLib.csproj"** **/>**
     **</ItemGroup>**
    </Project> 
    ```

1.  构建`CalculatorLibUnitTests`项目。

## 编写单元测试

一个编写良好的单元测试将包含三个部分：

+   **准备**: 这一部分将声明并实例化输入和输出的变量。

+   **执行**: 这一部分将执行你正在测试的单元。在我们的例子中，这意味着调用我们想要测试的方法。

+   **断言**：这一部分将做出一个或多个关于输出的断言。断言是一种信念，如果它不成立，则表明测试失败。例如，当加 2 和 2 时，我们期望结果是 4。

现在，我们将为`Calculator`类编写一些单元测试：

1.  将文件`UnitTest1.cs`重命名为`CalculatorUnitTests.cs`，然后打开它。

1.  在 Visual Studio Code 中，将类重命名为`CalculatorUnitTests`。（当你重命名文件时，Visual Studio 会提示你重命名类。）

1.  导入`Packt`命名空间。

1.  修改`CalculatorUnitTests`类，使其有两个测试方法，分别用于加 2 和 2，以及加 2 和 3，如下面的代码所示：

    ```cs
    using Packt; 
    using Xunit;
    namespace CalculatorLibUnitTests
    {
      public class CalculatorUnitTests
      {
        [Fact]
        public void TestAdding2And2()
        {
          // arrange 
          double a = 2; 
          double b = 2;
          double expected = 4;
          Calculator calc = new();
          // act
          double actual = calc.Add(a, b);
          // assert
          Assert.Equal(expected, actual);
        }
        [Fact]
        public void TestAdding2And3()
        {
          // arrange 
          double a = 2; 
          double b = 3;
          double expected = 5;
          Calculator calc = new();
          // act
          double actual = calc.Add(a, b);
          // assert
          Assert.Equal(expected, actual);
        }
      }
    } 
    ```

### 使用 Visual Studio Code 运行单元测试

现在我们准备好运行单元测试并查看结果：

1.  在`CalculatorLibUnitTest`项目的**终端**窗口中运行测试，如下面的命令所示：

    ```cs
    dotnet test 
    ```

1.  注意结果显示两个测试运行，一个测试通过，一个测试失败，如图*4.21*所示：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_04_23.png)

    *图 4.21*：Visual Studio Code 的终端中的单元测试结果

### 使用 Visual Studio 运行单元测试

现在我们准备好运行单元测试并查看结果：

1.  导航到**测试** | **运行所有测试**。

1.  在**测试资源管理器**中，注意结果显示两个测试运行，一个测试通过，一个测试失败，如图*4.22*所示：![图形用户界面，文本，应用程序，电子邮件 描述自动生成](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_04_24.png)

*图 4.22*：Visual Studio 2022 的测试资源管理器中的单元测试结果

### 修复错误

现在你可以修复错误：

1.  修复`Add`方法中的错误。

1.  再次运行单元测试，看看错误现在是否已被修复，两个测试都通过。

# 在函数中抛出和捕获异常

在*第三章*，*控制流程、转换类型和处理异常*中，你被介绍了异常以及如何使用`try-catch`语句来处理它们。但你应该只在有足够信息来缓解问题时才捕获和处理异常。如果没有，那么你应该允许异常通过调用堆栈传递到更高级别。

## 理解使用错误和执行错误

**使用错误**是指程序员错误地使用了一个函数，通常是通过传递无效的参数值。这些错误可以通过程序员修改代码以传递有效值来避免。一些初学 C#和.NET 的程序员有时认为异常总是可以避免的，因为他们假设所有错误都是使用错误。使用错误应在生产运行时之前全部修复。

**执行错误**是指在运行时发生的事情，无法通过编写“更好”的代码来修复。执行错误可分为**程序错误**和**系统错误**。如果您尝试访问网络资源但网络已关闭，您需要能够通过记录异常来处理该系统错误，并可能暂时退避并尝试再次访问。但某些系统错误，如内存耗尽，根本无法处理。如果您尝试打开一个不存在的文件，您可能能够捕获该错误并通过编程方式处理它，即创建一个新文件。程序错误可以通过编写智能代码来编程修复。系统错误通常无法通过编程方式修复。

## 函数中常见的抛出异常

您很少应该定义新的异常类型来指示使用错误。.NET 已经定义了许多您应该使用的异常。

在定义带有参数的自己的函数时，您的代码应检查参数值，并在它们具有阻止您的函数正常工作的值时抛出异常。

例如，如果一个参数不应为 `null`，则抛出 `ArgumentNullException`。对于其他问题，抛出 `ArgumentException`、`NotSupportedException` 或 `InvalidOperationException`。对于任何异常，都应包含一条消息，描述问题所在，以便需要阅读它的人（通常是类库和函数的开发者受众，或如果是 GUI 应用的最高级别，则为最终用户），如下列代码所示：

```cs
static void Withdraw(string accountName, decimal amount)
{
  if (accountName is null)
  {
    throw new ArgumentNullException(paramName: nameof(accountName));
  }
  if (amount < 0)
  {
    throw new ArgumentException(
      message: $"{nameof(amount)} cannot be less than zero.");
  }
  // process parameters
} 
```

**最佳实践**：如果一个函数无法成功执行其操作，应将其视为函数失败，并通过抛出异常来报告。

您永远不需要编写 `try-catch` 语句来捕获这些使用类型的错误。您希望应用程序终止。这些异常应促使调用函数的程序员修复其代码以防止问题。它们应在生产部署之前修复。这并不意味着您的代码不需要抛出使用错误类型的异常。您应该这样做——以强制其他程序员正确调用您的函数！

## 理解调用栈

.NET 控制台应用程序的入口点是 `Program` 类的 `Main` 方法，无论您是否明确定义了这个类和方法，或者它是否由顶级程序功能为您创建。

`Main` 方法会调用其他方法，这些方法又会调用其他方法，依此类推，这些方法可能位于当前项目或引用的项目和 NuGet 包中，如*图 4.23*所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs10-dn6-mod-xplat-dev/img/B17442_04_25.png)

*图 4.23*：创建调用栈的方法调用链

让我们创建一个类似的方法链，以探索我们可以在哪里捕获和处理异常：

1.  使用您偏好的编程工具，在 `Chapter04` 工作区/解决方案中添加一个名为 `CallStackExceptionHandlingLib` 的**类库**。

1.  将 `Class1.cs` 文件重命名为 `Calculator.cs`。

1.  打开`Calculator.cs`并修改其内容，如下面的代码所示：

    ```cs
    using static System.Console;
    namespace Packt;
    public class Calculator
    {
      public static void Gamma() // public so it can be called from outside
      {
        WriteLine("In Gamma");
        Delta();
      }
      private static void Delta() // private so it can only be called internally
      {
        WriteLine("In Delta");
        File.OpenText("bad file path");
      }
    } 
    ```

1.  使用你喜欢的编码工具，在`Chapter04`工作区/解决方案中添加一个名为`CallStackExceptionHandling`的新**控制台应用程序**。

1.  在 Visual Studio Code 中，选择`CallStackExceptionHandling`作为活动 OmniSharp 项目。当看到弹出警告消息提示缺少必需资产时，点击**是**以添加它们。

1.  在`CallStackExceptionHandling`项目中，添加对`CallStackExceptionHandlingLib`项目的引用。

1.  在`Program.cs`中，添加语句以定义两个方法并链接调用它们，以及类库中的方法，如下面的代码所示：

    ```cs
    using Packt;
    using static System.Console;
    WriteLine("In Main");
    Alpha();
    static void Alpha()
    {
      WriteLine("In Alpha");
      Beta();
    }
    static void Beta()
    {
      WriteLine("In Beta");
      Calculator.Gamma();
    } 
    ```

1.  运行控制台应用程序，并注意结果，如下面的部分输出所示：

    ```cs
    In Main
    In Alpha
    In Beta
    In Gamma
    In Delta
    Unhandled exception. System.IO.FileNotFoundException: Could not find file 'C:\Code\Chapter04\CallStackExceptionHandling\bin\Debug\net6.0\bad file path'.
       at Microsoft.Win32.SafeHandles.SafeFileHandle.CreateFile(...
       at Microsoft.Win32.SafeHandles.SafeFileHandle.Open(...
       at System.IO.Strategies.OSFileStreamStrategy..ctor(...
       at System.IO.Strategies.FileStreamHelpers.ChooseStrategyCore(...
       at System.IO.Strategies.FileStreamHelpers.ChooseStrategy(...
       at System.IO.StreamReader.ValidateArgsAndOpenPath(...
       at System.IO.File.OpenText(String path) in ...
       at Packt.Calculator.Delta() in C:\Code\Chapter04\CallStackExceptionHandlingLib\Calculator.cs:line 16
       at Packt.Calculator.Gamma() in C:\Code\Chapter04\CallStackExceptionHandlingLib\Calculator.cs:line 10
       at <Program>$.<<Main>$>g__Beta|0_1() in C:\Code\Chapter04\CallStackExceptionHandling\Program.cs:line 16
       at <Program>$.<<Main>$>g__Alpha|0_0() in C:\Code\Chapter04\CallStackExceptionHandling\Program.cs:line 10
       at <Program>$.<Main>$(String[] args) in C:\Code\Chapter04\CallStackExceptionHandling\Program.cs:line 5 
    ```

注意以下几点：

+   调用堆栈是颠倒的。从底部开始，你会看到：

    +   第一次调用是调用自动生成的`Program`类中的`Main`入口点函数。这是将参数作为`string`数组传递的地方。

    +   第二次调用是调用`Alpha`函数。

    +   第三次调用是调用`Beta`函数。

    +   第四次调用是调用`Gamma`函数。

    +   第五次调用是调用`Delta`函数。该函数试图通过传递错误的文件路径来打开文件。这会导致抛出异常。任何具有`try-catch`语句的函数都可以捕获此异常。如果它们没有捕获，异常会自动向上传递到调用堆栈的顶部，在那里.NET 输出异常（以及此调用堆栈的详细信息）。

## 在哪里捕获异常

程序员可以选择在故障点附近捕获异常，或者在调用堆栈的更高层集中处理。这使得代码更简化、标准化。你可能知道调用异常可能会抛出一种或多种类型的异常，但在当前调用堆栈点无需处理任何异常。

## 重新抛出异常

有时你想要捕获异常，记录它，然后重新抛出它。在`catch`块内重新抛出异常有三种方法，如下表所示：

1.  要使用其原始调用堆栈抛出捕获的异常，请调用`throw`。

1.  要将捕获的异常抛出，就像它在当前调用堆栈级别抛出一样，调用`throw`并传入捕获的异常，例如`throw ex`。这通常是不良实践，因为你丢失了一些可能对调试有用的信息。

1.  为了将捕获的异常包装在另一个异常中，该异常可以在消息中包含更多信息，这可能有助于调用者理解问题，抛出一个新异常，并将捕获的异常作为`innerException`参数传递。

如果在调用`Gamma`函数时可能发生错误，那么我们可以捕获异常，然后执行三种重新抛出异常技术中的一种，如下面的代码所示：

```cs
try
{
  Gamma();
}
catch (IOException ex)
{
  LogException(ex);
  // throw the caught exception as if it happened here
  // this will lose the original call stack
  throw ex;
  // rethrow the caught exception and retain its original call stack
  throw;
  // throw a new exception with the caught exception nested within it
  throw new InvalidOperationException(
    message: "Calculation had invalid values. See inner exception for why.",
    innerException: ex);
} 
```

让我们通过调用堆栈示例来看看这一操作：

1.  在`CallStackExceptionHandling`项目中，在`Program.cs`文件的`Beta`函数中，围绕对`Gamma`函数的调用添加一个`try-catch`语句，如下所示：

    ```cs
    static void Beta()
    {
      WriteLine("In Beta");
    **try**
     **{**
     **Calculator.Gamma();**
     **}**
     **catch (Exception ex)**
     **{**
     **WriteLine(****$"Caught this:** **{ex.Message}****"****);**
    **throw** **ex;**
     **}**
    } 
    ```

1.  注意`ex`下面的绿色波浪线，它会警告你将丢失调用堆栈信息。

1.  运行控制台应用并注意输出排除了调用堆栈的一些细节，如下所示：

    ```cs
    Caught this: Could not find file 'C:\Code\Chapter04\CallStackExceptionHandling\bin\Debug\net6.0\bad file path'.
    Unhandled exception. System.IO.FileNotFoundException: Could not find file 'C:\Code\Chapter04\CallStackExceptionHandling\bin\Debug\net6.0\bad file path'.
    File name: 'C:\Code\Chapter04\CallStackExceptionHandling\bin\Debug\net6.0\bad file path'
       at <Program>$.<<Main>$>g__Beta|0_1() in C:\Code\Chapter04\CallStackExceptionHandling\Program.cs:line 25
       at <Program>$.<<Main>$>g__Alpha|0_0() in C:\Code\Chapter04\CallStackExceptionHandling\Program.cs:line 11
       at <Program>$.<Main>$(String[] args) in C:\Code\Chapter04\CallStackExceptionHandling\Program.cs:line 6 
    ```

1.  在重新抛出异常时删除`ex`。

1.  运行控制台应用并注意输出包括了调用堆栈的所有细节。

## 实现测试者-执行者模式

**测试者-执行者模式**可以避免一些抛出的异常（但不能完全消除它们）。此模式使用一对函数：一个执行测试，另一个执行如果测试未通过则会失败的操作。

.NET 本身实现了这种模式。例如，在通过调用`Add`方法向集合添加项之前，你可以测试它是否为只读，这会导致`Add`失败并因此抛出异常。

例如，在从银行账户取款前，你可能会测试账户是否透支，如下所示：

```cs
if (!bankAccount.IsOverdrawn())
{
  bankAccount.Withdraw(amount);
} 
```

### 测试者-执行者模式的问题

测试者-执行者模式可能会增加性能开销，因此你也可以实现**try 模式**，它实际上将测试和执行部分合并为一个函数，正如我们在`TryParse`中看到的那样。

测试者-执行者模式的另一个问题出现在使用多线程时。在这种情况下，一个线程可能调用测试函数并返回正常。但随后另一个线程执行改变了状态。然后原始线程继续执行，假设一切正常，但实际上并非如此。这称为竞态条件。我们将在*第十二章*，*使用多任务提高性能和可扩展性*中看到如何处理它。

如果你实现自己的 try 模式函数且失败了，记得将`out`参数设置为其类型的默认值，然后返回`false`，如下所示：

```cs
static bool TryParse(string? input, out Person value)
{
  if (someFailure)
  {
    value = default(Person);
    return false;
  }
  // successfully parsed the string into a Person
  value = new Person() { ... };
  return true;
} 
```

# 实践和探索

通过回答一些问题来测试你的知识和理解，进行一些实践操作，并深入研究本章涵盖的主题。

## 练习 4.1 – 测试你的知识

回答以下问题。如果你卡住了，必要时尝试通过谷歌搜索答案，同时记住如果你完全卡住了，答案在附录中：

1.  C#关键字`void`是什么意思？

1.  命令式和函数式编程风格之间有哪些区别？

1.  在 Visual Studio Code 或 Visual Studio 中，按 F5、Ctrl 或 Cmd + F5、Shift + F5 以及 Ctrl 或 Cmd + Shift + F5 之间有何区别？

1.  `Trace.WriteLine`方法将输出写入到哪里？

1.  五个跟踪级别是什么？

1.  `Debug`类和`Trace`类之间有何区别？

1.  编写单元测试时，三个“A”是什么？

1.  在使用 xUnit 编写单元测试时，你必须用什么属性来装饰测试方法？

1.  执行 xUnit 测试的`dotnet`命令是什么？

1.  要重新抛出名为`ex`的捕获异常而不丢失堆栈跟踪，应使用什么语句？

## 练习 4.2 – 实践编写带有调试和单元测试的函数

质因数是能乘积得到原数的最小质数的组合。考虑以下示例：

+   4 的质因数是：2 x 2

+   7 的质因数是：7

+   30 的质因数是：5 x 3 x 2

+   40 的质因数是：5 x 2 x 2 x 2

+   50 的质因数是：5 x 5 x 2

创建一个名为`PrimeFactors`的工作区/解决方案，包含三个项目：一个类库，其中有一个名为`PrimeFactors`的方法，当传入一个`int`变量作为参数时，返回一个显示其质因数的`string`；一个单元测试项目；以及一个控制台应用程序来使用它。

为简化起见，你可以假设输入的最大数字将是 1,000。

使用调试工具并编写单元测试，以确保你的函数能正确处理多个输入并返回正确的输出。

## 练习 4.3 – 探索主题

使用以下页面上的链接来了解更多关于本章涵盖主题的详细信息：

[第四章 - 编写、调试和测试函数](https://github.com/markjprice/cs10dotnet6/blob/main/book-links.md#chapter-4---writing-debugging-and-testing-functions)

# 总结

在本章中，你学习了如何编写可重用的函数，这些函数具有输入参数和返回值，既采用命令式风格也采用函数式风格，然后如何使用 Visual Studio 和 Visual Studio Code 的调试和诊断功能来修复其中的任何错误。最后，你学习了如何在函数中抛出和捕获异常，并理解调用堆栈。

在下一章中，你将学习如何使用面向对象编程技术构建自己的类型。
