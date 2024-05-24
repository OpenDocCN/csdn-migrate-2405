# C++ 函数式编程学习手册（三）

> 原文：[`annas-archive.org/md5/8ba9d5d0c71497e4f1c908aec7505b42`](https://annas-archive.org/md5/8ba9d5d0c71497e4f1c908aec7505b42)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：使用元编程优化代码

我们在上一章讨论了使用惰性评估的优化技术，并使用了延迟处理、缓存技术和记忆化来使我们的代码运行更快。在本章中，我们将使用**元编程**来优化代码，我们将创建一个将创建更多代码的代码。本章我们将讨论的主题如下：

+   元编程简介

+   构建模板元编程的部分

+   将流程控制重构为模板元编程

+   在编译时执行代码

+   模板元编程的优缺点

# 元编程简介

简单来说，元编程是一种通过使用代码来创建代码的技术。实现元编程时，我们编写一个计算机程序，操作其他程序并将它们视为数据。此外，模板是 C++中的一种编译时机制，它是**图灵完备**的，这意味着任何可以由计算机程序表达的计算都可以在运行时之前以某种形式通过模板元编程来计算。它还大量使用递归，并具有不可变变量。因此，在元编程中，我们创建的代码将在编译代码时运行。

# 使用宏预处理代码

要开始我们关于元编程的讨论，让我们回到 ANSI C 编程语言流行的时代。为了简单起见，我们使用了 C 预处理器创建了一个宏。C 参数化宏也被称为**元函数**，是元编程的一个例子。考虑以下参数化宏：

```cpp
    #define MAX(a,b) (((a) > (b)) ? (a) : (b))

```

由于 C++编程语言对 C 语言的兼容性有缺陷，我们可以使用 C++编译器编译前面的宏。让我们创建代码来使用前面的宏，代码如下：

```cpp
    /* macro.cpp */
    #include <iostream>

    using namespace std;

    // Defining macro
    #define MAX(a,b) (((a) > (b)) ? (a) : (b))

    auto main() -> int
    {
      cout << "[macro.cpp]" << endl;

      // Initializing two int variables
      int x = 10;
      int y = 20;

      // Consuming the MAX macro
      // and assign the result to z variable
      int z = MAX(x,y);

      // Displaying the result
      cout << "Max number of " << x << " and " << y;
      cout << " is " << z << endl;

      return 0;
    }

```

如前面的`macro.cpp`代码所示，我们将两个参数传递给`MAX`宏，因为它是一个参数化的宏，这意味着参数可以从用户那里获得。如果我们运行前面的代码，应该在控制台上看到以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-fp/img/c3415c09-ba2c-4b3c-9377-afd18f2d9d30.png)

正如我们在本章开头讨论的那样，元编程是在编译时运行的代码。通过在前面的代码中使用宏，我们可以展示从`MAX`宏生成的新代码。预处理器将在编译时解析宏并带来新的代码。在编译时，编译器将修改代码如下：

```cpp
    auto main() -> int
    {
      // same code
      // ...

      int z = (((a) > (b)) ? (a) : (b)); // <-- Notice this section

      // same code
      // ...

      return 0;
    }

```

除了单行宏预处理器之外，我们还可以生成多行宏元函数。为了实现这一点，我们可以在每行末尾使用反斜杠字符。假设我们需要交换两个值。我们可以创建一个名为`SWAP`的参数化宏，并像下面的代码一样使用它：

```cpp
    /* macroswap.cpp */
    #include <iostream>

    using namespace std;

    // Defining multi line macro
    #define SWAP(a,b) { \
      (a) ^= (b); \
      (b) ^= (a); \
      (a) ^= (b); \
    }

    auto main() -> int
    {
      cout << "[macroswap.cpp]" << endl;

      // Initializing two int variables
      int x = 10;
      int y = 20;

      // Displaying original variable value
      cout << "before swapping" << endl;
      cout << "x = " << x << ", y = " << y ;
      cout << endl << endl;

      // Consuming the SWAP macro
      SWAP(x,y);

      // Displaying swapped variable value
      cout << "after swapping" << endl;
      cout << "x = " << x << ", y = " << y;
      cout << endl;

      return 0;
    }

```

如前面的代码所示，我们将创建一个多行预处理器宏，并在每行末尾使用反斜杠字符。每次调用`SWAP`参数化宏时，它将被替换为宏的实现。如果我们运行前面的代码，将在控制台上看到以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-fp/img/502d5c3f-23b1-4998-b4c8-04ea9ef089bf.png)

现在我们对元编程有了基本的了解，特别是在元函数中，我们可以在下一个主题中进一步学习。

在每个宏预处理器的实现中，我们为每个变量使用括号，因为预处理器只是用宏的实现替换我们的代码。假设我们有以下宏：

`MULTIPLY(a,b) (a * b)` 如果我们将数字作为参数传递，那么这不会成为问题。然而，如果我们将一个操作作为参数传递，就会出现问题。例如，如果我们像下面这样使用`MULTIPLY`宏：

`MULTIPLY(x+2,y+5);`

然后编译器将其替换为`(x+2*y+5)`。这是因为宏只是用`x + 2`表达式替换`a`变量，用`y + 5`表达式替换`b`变量，而没有额外的括号。因为乘法的顺序高于加法，我们将得到以下结果：

`(x+2y+5)`

这并不是我们期望的结果。因此，最好的方法是在参数的每个变量中使用括号。

# 解剖标准库中的模板元编程

我们在第一章中讨论了标准库，*深入现代 C++*，并在上一章中也处理了它。C++语言中提供的标准库主要是一个包含不完整函数的模板。然而，它将用于生成完整的函数。模板元编程是 C++模板，用于在编译时生成 C++类型和代码。

让我们挑选标准库中的一个类--`Array`类。在`Array`类中，我们可以为其定义一个数据类型。当我们实例化数组时，编译器实际上会生成我们定义的数据类型的数组的代码。现在，让我们尝试构建一个简单的`Array`模板实现，如下所示：

```cpp
    template<typename T>
    class Array
    {
      T element;
    };

```

然后，我们实例化`char`和`int`数组如下：

```cpp
    Array<char> arrChar;
    Array<int> arrInt;

```

编译器所做的是基于我们定义的数据类型创建这两个模板的实现。虽然我们在代码中看不到这一点，但编译器实际上创建了以下代码：

```cpp
    class ArrayChar
    {
      char element;
    };

    class ArrayInt
    {
      int element;
    };

    ArrayChar arrChar;
    ArrayInt arrInt;

```

正如我们在前面的代码片段中所看到的，模板元编程是在编译时创建另一个代码的代码。

# 构建模板元编程

在进一步讨论模板元编程之前，最好讨论一下构建模板元编程的骨架。有四个因素构成模板元编程--**类型**，**值**，**分支**和**递归**。在这个话题中，我们将深入探讨构成模板的因素。

# 在模板中添加一个值到变量

在本章的开头，我们讨论了元函数的概念，当我们谈到宏预处理器时。在宏预处理器中，我们明确地操纵源代码；在这种情况下，宏（元函数）操纵源代码。相反，在 C++模板元编程中，我们使用类型。这意味着元函数是一个与类型一起工作的函数。因此，使用模板元编程的更好方法是尽可能只使用类型参数。当我们谈论模板元编程中的变量时，实际上它并不是一个变量，因为它上面的值是不能被修改的。我们需要的是变量的名称，这样我们才能访问它。因为我们将使用类型编码，命名的值是`typedef`，正如我们在以下代码片段中所看到的：

```cpp
    struct ValueDataType
    {
      typedef int valueDataType;
    };

```

通过使用前面的代码，我们将`int`类型存储到`valueDataType`别名中，这样我们就可以使用`valueDataType`变量来访问数据类型。如果我们需要将值而不是数据类型存储到变量中，我们可以使用`enum`，这样它将成为`enum`本身的数据成员。如果我们想要存储值，让我们看一下以下代码片段：

```cpp
    struct ValuePlaceHolder
    {
      enum 
       { 
        value = 1 
       };
    };

```

基于前面的代码片段，我们现在可以访问`value`变量以获取其值。

# 将函数映射到输入参数

我们可以将变量添加到模板元编程中。现在，我们接下来要做的是检索用户参数并将它们映射到一个函数。假设我们想要开发一个`Multiplexer`函数，它将两个值相乘，我们必须使用模板元编程。以下代码片段可用于解决这个问题：

```cpp
    template<int A, int B>
    struct Multiplexer
    {
      enum 
      {
        result = A * B 
      };
    };

```

正如我们在前面的代码片段中所看到的，模板需要用户提供两个参数`A`和`B`，它将使用它们来通过将这两个参数相乘来获取`result`变量的值。我们可以使用以下代码访问结果变量：

```cpp
    int i = Multiplexer<2, 3>::result;

```

如果我们运行前面的代码片段，`i`变量将存储`6`，因为它将计算`2`乘以`3`。

# 根据条件选择正确的过程

当我们有多个函数时，我们必须根据某些条件选择其中一个。我们可以通过提供`template`类的两个替代特化来构建条件分支，如下所示：

```cpp
    template<typename A, typename B>
    struct CheckingType
    {
      enum 
      { 
        result = 0 
      };
    };

    template<typename X>
    struct CheckingType<X, X>
    {
      enum 
      { 
        result = 1 
      };
    };

```

正如我们在前面的`template`代码中所看到的，我们有两个模板，它们的类型分别为`X`和`A`/`B`。当模板只有一个类型，即`typename X`时，这意味着我们比较的两种类型（`CheckingType <X, X>`）完全相同。否则，这两种数据类型是不同的。以下代码片段可以用来使用前面的两个模板：

```cpp
    if (CheckingType<UnknownType, int>::result)
    {
      // run the function if the UnknownType is int
    } 
    else 
    { 
      // otherwise run any function 
    }

```

正如我们在前面的代码片段中所看到的，我们试图将`UnknownType`数据类型与`int`类型进行比较。`UnknownType`数据类型可能来自其他过程。然后，我们可以通过使用模板来比较这两种类型来决定我们想要运行的下一个过程。

到目前为止，你可能会想知道模板多编程如何帮助我们进行代码优化。很快我们将使用模板元编程来优化代码。然而，我们需要讨论其他事情来巩固我们在模板多编程中的知识。现在，请耐心阅读。

# 递归重复这个过程

我们已经成功地将值和数据类型添加到模板中，然后根据当前条件创建了一个分支来决定下一个过程。在基本模板中，我们还需要考虑重复这个过程。然而，由于模板中的变量是不可变的，我们无法迭代序列。相反，我们必须像我们在第四章中讨论的那样，通过递归算法重复这个过程。

假设我们正在开发一个模板来计算阶乘值。我们首先要做的是开发一个将`I`值传递给函数的通用模板，如下所示：

```cpp
    template <int I>
    struct Factorial
    {
      enum 
      { 
        value = I * Factorial<I-1>::value 
      };
    };

```

正如我们在前面的代码中所看到的，我们可以通过运行以下代码来获得阶乘的值：

```cpp
    Factorial<I>::value;

```

在前面的代码中，`I`是一个整数。

接下来，我们必须开发一个模板来确保它不会陷入无限循环。我们可以创建以下模板，将零（`0`）作为参数传递给它：

```cpp
    template <>
    struct Factorial<0>
    {
      enum 
      { 
        value = 1 
      };
    };

```

现在我们有一对模板，可以在编译时生成阶乘的值。以下是一个示例代码，用于在编译时获取`Factorial(10)`的值：

```cpp
    int main()
    {
      int fact10 = Factorial<10>::value;
    }

```

如果我们运行前面的代码，我们将得到`10`的阶乘的结果`3628800`。

# 在编译时选择类型

正如我们在前面的主题中讨论的，`type`是模板的基本部分。然而，我们可以根据用户的输入选择特定的类型。让我们创建一个模板，可以决定变量中应该使用什么类型。以下的`types.cpp`代码将展示模板的实现：

```cpp
    /* types.cpp */
    #include <iostream>

    using namespace std;

 // Defining a data type
 // in template
 template<typename T>
 struct datatype
 {
 using type = T;
 };

    auto main() -> int
    {
      cout << "[types.cpp]" << endl;

      // Selecting a data type in compile time
      using t = typename datatype<int>::type;

      // Using the selected data type
      t myVar = 123;

      // Displaying the selected data type
      cout << "myVar = " << myVar;

      return 0;
    }

```

正如我们在前面的代码中所看到的，我们有一个名为`datatype`的模板。这个模板可以用来选择我们传递给它的`type`。我们可以使用`using`关键字将一个变量分配给`type`。从前面的`types.cpp`代码中，我们将把一个变量`t`分配给`datatype`模板中的`type`。现在，`t`变量将是`int`，因为我们将`int`数据类型传递给了模板。

我们还可以创建一个代码来根据当前条件选择正确的数据类型。我们将有一个`IfElseDataType`模板，它接受三个参数，即`predicate`，当`predicate`参数为 true 时的数据类型，以及当`predicate`参数为 false 时的数据类型。代码将如下所示：

```cpp
    /* selectingtype.cpp */
    #include <iostream>

    using namespace std;

    // Defining IfElseDataType template
    template<
      bool predicate,
      typename TrueType,
      typename FalseType>
      struct IfElseDataType
      {
      };

    // Defining template for TRUE condition
    // passed to 'predicate' parameter
    template<
      typename TrueType,
      typename FalseType>
      struct IfElseDataType<
       true,
       TrueType,
       FalseType>
       {
         typedef TrueType type;
       };

    // Defining template for FALSE condition
    // passed to 'predicate' parameter
    template<
      typename TrueType,
      typename FalseType>
      struct IfElseDataType<
      false,
      TrueType,
      FalseType>
      {
         typedef FalseType type;
      };

    auto main() -> int
    {
      cout << "[types.cpp]" << endl;

      // Consuming template and passing
      // 'SHRT_MAX == 2147483647'
      // It will be FALSE
      // since the maximum value of short
      // is 32767
      // so the data type for myVar
      // will be 'int'
      IfElseDataType<
        SHRT_MAX == 2147483647,
        short,
        int>::type myVar;

      // Assigning myVar to maximum value
      // of 'short' type
      myVar = 2147483647;

      // Displaying the data type of myVar
      cout << "myVar has type ";
      cout << typeid(myVar).name() << endl;

      return 0;
    }

```

现在，通过`IfElseDataType`模板，我们可以根据我们的条件选择正确的类型给变量。假设我们想要将`2147483647`赋给一个变量，以便我们可以检查它是否是一个短数字。如果是，`myVar`将是`short`类型，否则将是`int`类型。此外，由于`short`类型的最大值是`32767`，通过给定谓词为`SHRT_MAX == 2147483647`将导致`FALSE`。因此，`myVar`的类型将是`int`类型，如我们将在控制台上看到的以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-fp/img/c9f65a57-9612-429f-82b7-55741f74cc50.png)

# 使用模板元编程进行流程控制

代码流是编写程序的重要方面。在许多编程语言中，它们有`if-else`，`switch`和`do-while`语句来安排代码的流程。现在，让我们将通常的代码流重构为基于模板的流程。我们将首先使用`if-else`语句，然后是`switch`语句，最后以模板的形式结束`do-while`语句。

# 根据当前条件决定下一个过程

现在是时候使用我们之前讨论过的模板了。假设我们有两个函数，我们必须根据某个条件进行选择。我们通常会使用`if-else`语句，如下所示：

```cpp
    /* condition.cpp */
    #include <iostream>

    using namespace std;

    // Function that will run
    // if the condition is TRUE
    void TrueStatement()
    {
      cout << "True Statement is run." << endl;
    }

    // Function that will run
    // if the condition is FALSE
    void FalseStatement()
    {
      cout << "False Statement is run." << endl;
    }

    auto main() -> int
    {
      cout << "[condition.cpp]" << endl;

      // Choosing the function
      // based on the condition
      if (2 + 3 == 5)
        TrueStatement();
      else
        FalseStatement();

      return 0;
    }

```

正如我们在前面的代码中所看到的，我们有两个函数--`TrueStatement()`和`FalseStatement()`。我们在代码中还有一个条件--`2 + 3 == 5`。由于条件是`TRUE`，因此`TrueStatement()`函数将被运行，如我们在下面的截图中所看到的：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-fp/img/9e5c6760-bbad-42e6-9208-48d2213aca67.png)

现在，让我们重构前面的`condition.cpp`代码。我们将在这里创建三个模板。首先，输入条件的初始化模板如下：

```cpp
    template<bool predicate> class IfElse

```

然后，我们为每个条件创建两个模板--`TRUE`或`FALSE`。名称将如下：

```cpp
    template<> class IfElse<true>
    template<> class IfElse<false> 

```

前面代码片段中的每个模板将运行我们之前创建的函数--`TrueStatement()`和`FalseStatement()`函数。我们将得到完整的代码，如下所示的`conditionmeta.cpp`代码：

```cpp
    /* conditionmeta.cpp */
    #include <iostream>

    using namespace std;

    // Function that will run
    // if the condition is TRUE
    void TrueStatement()
    {
      cout << "True Statement is run." << endl;
    }

    // Function that will run
    // if the condition is FALSE
    void FalseStatement()
    {
      cout << "False Statement is run." << endl;
    }

    // Defining IfElse template
    template<bool predicate>
    class IfElse
    {
    };

    // Defining template for TRUE condition
    // passed to 'predicate' parameter
    template<>
    class IfElse<true>
    {
      public:
        static inline void func()
        {
          TrueStatement();
        }
    };

    // Defining template for FALSE condition
    // passed to 'predicate' parameter
    template<>
    class IfElse<false>
    {
      public:
        static inline void func()
        {
          FalseStatement();
        }
    };

    auto main() -> int
    {
      cout << "[conditionmeta.cpp]" << endl;

      // Consuming IfElse template
      IfElse<(2 + 3 == 5)>::func();

      return 0;
    }

```

正如我们所看到的，我们将条件放在`IfElse`模板的括号中，然后在模板内调用`func()`方法。如果我们运行`conditionmeta.cpp`代码，我们将得到与`condition.cpp`代码完全相同的输出，如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-fp/img/52dfab6d-8e80-4036-9e19-95f40d013725.png)

现在我们有了`if-else`语句来流动我们的模板元编程代码。

# 选择正确的语句

在 C++编程中，以及其他编程语言中，我们使用`switch`语句根据我们给`switch`语句的值来选择某个过程。如果值与 switch case 中的一个匹配，它将运行该 case 下的过程。让我们看一下下面的`switch.cpp`代码，它实现了`switch`语句：

```cpp
    /* switch.cpp */
    #include <iostream>

    using namespace std;

    // Function to find out
    // the square of an int
    int Square(int a)
    {
      return a * a;
    }

    auto main() -> int
    {
      cout << "[switch.cpp]" << endl;

      // Initializing two int variables
      int input = 2;
      int output = 0;

      // Passing the correct argument
      // to the function
      switch (input)
      {
        case 1:
            output = Square(1);
            break;
        case 2:
            output = Square(2);
            break;
        default:
            output = Square(0);
            break;
      }

      // Displaying the result
      cout << "The result is " << output << endl;

      return 0;
    }

```

正如我们在前面的代码中所看到的，我们有一个名为`Square()`的函数，它接受一个参数。我们传递给它的参数是基于我们给 switch 语句的值。由于我们传递给 switch 的值是`2`，`Square(2)`方法将被运行。下面的截图是我们将在控制台屏幕上看到的内容：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-fp/img/bb934a6e-293e-47b9-b771-cb7d9da4832f.png)

要将`switch.cpp`代码重构为模板元编程，我们必须创建三个包含我们计划运行的函数的模板。首先，我们将创建初始化模板以从用户那里检索值，如下所示：

```cpp
    template<int val> class SwitchTemplate 

```

前面的初始化模板也将用于默认值。接下来，我们将为每个可能的值添加两个模板，如下所示：

```cpp
    template<> class SwitchTemplate<1>
    template<> class SwitchTemplate<2> 

```

每个前面的模板将运行`Square()`函数并根据模板的值传递参数。完整的代码如下所示：

```cpp
    /* switchmeta.cpp */
    #include <iostream>

    using namespace std;

    // Function to find out
    // the square of an int
    int Square(int a)
    {
      return a * a;
    }

    // Defining template for
    // default output
    // for any input value
    template<int val>
    class SwitchTemplate
    {
      public:
        static inline int func()
        {
          return Square(0);
        }
    };

    // Defining template for
    // specific input value
    // 'val' = 1
    template<>
    class SwitchTemplate<1>
    {
       public:
         static inline int func()
         {
           return Square(1);
         }
    };

    // Defining template for
    // specific input value
    // 'val' = 2
    template<>
    class SwitchTemplate<2>
    {
       public:
         static inline int func()
         {
            return Square(2);
         }
    };

    auto main() -> int
    {
      cout << "[switchmeta.cpp]" << endl;

      // Defining a constant variable
      const int i = 2;

      // Consuming the SwitchTemplate template
      int output = SwitchTemplate<i>::func();

      // Displaying the result
      cout << "The result is " << output << endl;

      return 0;
    }

```

如我们所见，我们与`conditionmeta.cpp`做的一样--我们调用模板内的`func()`方法来运行所选的函数。此`switch-case`条件的值是我们放在尖括号中的模板。如果我们运行前面的`switchmeta.cpp`代码，我们将在控制台上看到以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-fp/img/eeb896aa-2598-4995-b3b0-bbb61386f762.png)

如前面的截图所示，与`switch.cpp`代码相比，我们对`switchmeta.cpp`代码得到了完全相同的输出。因此，我们已成功将`switch.cpp`代码重构为模板元编程。

# 循环该过程

当我们迭代某些内容时，通常使用`do-while`循环。假设我们需要打印某些数字，直到达到零（`0`）。代码如下所示：

```cpp
    /* loop.cpp */
    #include <iostream>

    using namespace std;

    // Function for printing
    // given number
    void PrintNumber(int i)
    {
      cout << i << "\t";
    }

    auto main() -> int
    {
      cout << "[loop.cpp]" << endl;

      // Initializing an int variable
      // marking as maximum number
      int i = 100;

      // Looping to print out
      // the numbers below i variable
      cout << "List of numbers between 100 and 1";
      cout << endl;
      do
      {
        PrintNumber(i);
      }
      while (--i > 0);
      cout << endl;

      return 0;
    }

```

如前面的代码所示，我们将打印数字`100`，减少其值，并再次打印。它将一直运行，直到数字达到零（`0`）。控制台上的输出应该如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-fp/img/1a84c23b-dd08-4dfc-99a6-273c36918e06.png)

现在，让我们将其重构为模板元编程。在这里，我们只需要两个模板来实现模板元编程中的`do-while`循环。首先，我们将创建以下模板：

```cpp
    template<int limit> class DoWhile

```

前面代码中的限制是传递给`do-while`循环的值。为了不使循环变成无限循环，当它达到零（`0`）时，我们必须设计`DoWhile`模板，如下所示：

```cpp
    template<> class DoWhile<0>

```

前面的模板将什么也不做，因为它只用于中断循环。对`do-while`循环的完全重构如下`loopmeta.cpp`代码：

```cpp
    /* loopmeta.cpp */
    #include <iostream>

    using namespace std;

    // Function for printing
    // given number
    void PrintNumber(int i)
    {
      cout << i << "\t";
    }

    // Defining template for printing number
    // passing to its 'limit' parameter
    // It's only run
    // if the 'limit' has not been reached
    template<int limit>
    class DoWhile
    {
       private:
         enum
         {
           run = (limit-1) != 0
         };

       public:
         static inline void func()
         {
           PrintNumber(limit);
           DoWhile<run == true ? (limit-1) : 0>
            ::func();
         }
    };

    // Defining template for doing nothing
    // when the 'limit' reaches 0
    template<>
    class DoWhile<0>
    {
      public:
        static inline void func()
        {
        }
    };

    auto main() -> int
    {
      cout << "[loopmeta.cpp]" << endl;

      // Defining a constant variable
      const int i = 100;

      // Looping to print out
      // the numbers below i variable
      // by consuming the DoWhile
      cout << "List of numbers between 100 and 1";
      cout << endl;
      DoWhile<i>::func();
      cout << endl;

      return 0;
    }

```

然后我们调用模板内的`func()`方法来运行我们想要的函数。如果我们运行代码，我们将在屏幕上看到以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-fp/img/b5fd496c-ddac-483e-b0db-523307b3c91e.png)

同样，我们已成功将`loop.cpp`代码重构为`loopmeta.cpp`代码，因为两者的输出完全相同。

# 在编译时执行代码

正如我们之前讨论的，模板元编程将通过创建新代码在编译时运行代码。现在，让我们看看如何获取编译时常量并在本节生成编译时类。

# 获取编译时常量

为了检索编译时常量，让我们创建一个包含斐波那契算法模板的代码。我们将使用模板，这样编译器将在编译时提供值。代码应该如下所示：

```cpp
    /* fibonaccimeta.cpp */
    #include <iostream>

    using namespace std;

    // Defining Fibonacci template
    // to calculate the Fibonacci sequence
    template <int number>
    struct Fibonacci
    {
      enum
      {
        value =
            Fibonacci<number - 1>::value +
            Fibonacci<number - 2>::value
      };
    };

    // Defining template for
    // specific input value
    // 'number' = 1
    template <>
    struct Fibonacci<1>
    {
      enum
      {
        value = 1
      };
    };

    // Defining template for
    // specific input value
    // 'number' = 0
    template <>
    struct Fibonacci<0>
    {
      enum
      {
        value = 0
      };
    };

    auto main() -> int
    {
      cout << "[fibonaccimeta.cpp]" << endl;

      // Displaying the compile-time constant
      cout << "Getting compile-time constant:";
      cout << endl;
      cout << "Fibonacci(25) = ";
      cout << Fibonacci<25>::value;
      cout << endl;

      return 0;
    }

```

如前面的代码所示，斐波那契模板中的值变量将提供编译时常量。如果我们运行前面的代码，我们将在控制台屏幕上看到以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-fp/img/015e83df-4905-4a3c-aa49-c8f233a2282c.png)

现在，我们有`75025`，这是由编译器生成的编译时常量。

# 使用编译时类生成生成类

除了生成编译时常量之外，我们还将在编译时生成类。假设我们有一个模板来找出范围为`0`到`X`的质数。以下的`isprimemeta.cpp`代码将解释模板元编程的实现以找到质数：

```cpp
    /* isprimemeta.cpp */
    #include <iostream>

    using namespace std;

    // Defining template that decide
    // whether or not the passed argument
    // is a prime number
    template <
      int lastNumber,
      int secondLastNumber>
    class IsPrime
    {
      public:
        enum
        {
          primeNumber = (
            (lastNumber % secondLastNumber) &&
            IsPrime<lastNumber, secondLastNumber - 1>
                ::primeNumber)
        };
     };

    // Defining template for checking
    // the number passed to the 'number' parameter
    // is a prime number
    template <int number>
    class IsPrime<number, 1>
    {
      public:
        enum
        {
          primeNumber = 1
        };
    };

    // Defining template to print out
    // the passed argument is it's a prime number
    template <int number>
    class PrimeNumberPrinter
    {
      public:
        PrimeNumberPrinter<number - 1> printer;

      enum
      {
        primeNumber = IsPrime<number, number - 1>
            ::primeNumber
      };

      void func()
      {
        printer.func();

        if (primeNumber)
        {
            cout << number << "\t";
        }
      }
    };

    // Defining template to just ignoring the number
    // we pass 1 as argument to the parameter
    // since 1 is not prime number
    template<>
    class PrimeNumberPrinter<1>
    {
      public:
        enum
        {
          primeNumber = 0
        };

        void func()
        {
        }
    };

    int main()
    {
      cout << "[isprimemeta.cpp]" << endl;

      // Displaying the prime numbers between 1 and 500
      cout << "Filtering the numbers between 1 and 500 ";
      cout << "for of the prime numbers:" << endl;

      // Consuming PrimeNumberPrinter template
      PrimeNumberPrinter<500> printer;

      // invoking func() method from the template
      printer.func();

      cout << endl;
      return 0;
    }

```

有两种不同角色的模板--**质数检查器**，确保传递的数字是质数，以及**打印机**，将质数显示到控制台。当代码访问`PrimeNumberPrinter<500> printer`和`printer.func()`时，编译器将在编译时生成类。当我们运行前面的`isprimemeta.cpp`代码时，我们将在控制台屏幕上看到以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-fp/img/1377d14f-9287-4e54-93b8-39bf5906fe43.png)

由于我们将`500`传递给模板，我们将从`0`到`500`得到质数。前面的输出证明了编译器成功生成了一个编译时类，因此我们可以得到正确的值。

# 元编程的利与弊

在我们讨论完模板元编程之后，以下是我们得到的优点：

+   模板元编程没有副作用，因为它是不可变的，所以我们不能修改现有类型

+   与不实现元编程的代码相比，代码可读性更好

+   它减少了代码的重复

尽管我们可以从模板元编程中获得好处，但也有一些缺点，如下所示：

+   语法相当复杂。

+   编译时间较长，因为现在我们在编译时执行代码。

+   编译器可以更好地优化生成的代码并执行内联，例如 C 中的`qsort()`函数和 C++中的`sort`模板。在 C 中，`qsort()`函数接受一个指向比较函数的指针，因此将有一个未内联的`qsort`代码副本。它将通过指针调用比较例程。在 C++中，`std::sort`是一个模板，它可以接受一个`functor`对象作为比较器。对于每种不同类型用作比较器，都有一个不同的`std::sort`副本。如果我们使用一个具有重载的`operator()`函数的`functor`类，比较器的调用可以轻松地内联到`std::sort`的这个副本中。

# 总结

元编程，特别是模板元编程，可以自动为我们创建新的代码，这样我们就不需要在源代码中编写大量的代码。通过使用模板元编程，我们可以重构代码的流程控制，并在编译时执行代码。

在下一章中，我们将讨论并发技术，这将为我们构建的应用程序带来响应性增强。我们可以使用并行技术同时运行代码中的进程。


# 第七章：使用并发运行并行执行

在前一章中，我们讨论了模板元编程，它将使代码在编译时执行。它还将改善我们的代码流程控制，因为我们可以使用模板重构流程。现在，在本章中，我们将讨论 C++中的并发，当我们同时运行两个或更多个进程时，我们必须再次控制流程。在本章中，我们将讨论以下主题：

+   在 C++编程中运行单个和多个线程

+   同步线程以避免死锁

+   在 Windows 中使用**handle**资源创建线程

# C++中的并发

许多编程语言今天都提供了对并发的支持。在并发编程中，代码的计算在重叠的时间段内执行，而不是顺序执行。这将使我们的程序响应迅速，因为代码不需要等待所有计算完成。假设我们想开发一个可以同时播放视频和下载大型视频文件的程序。如果没有并发技术，我们必须等待视频成功下载后才能播放另一个视频文件。通过使用这种技术，我们可以分割这两个任务，播放和下载视频，然后同时并发运行它们。

在 C++11 宣布之前，C++程序员依赖于`Boost::thread`来使用多线程技术创建并发程序。在多线程中，我们将进程分解为最小的序列，并同时运行这些小进程。现在，在 C++11 库中，我们得到了`thread`类来满足我们使用多线程技术的并发需求。

# 处理单线程代码

要使用`thread`类，我们只需要创建一个`std::thread`的实例，并将函数名作为参数传递。然后我们调用`std::join()`来暂停进程，直到所选线程完成其进程。让我们看一下以下`singlethread.cpp`的代码：

```cpp
    /* singlethread.cpp */
    #include <thread>
    #include <iostream>

    using namespace std;

    void threadProc()
    {
      cout << "Thread ID: ";
      cout << this_thread::get_id() << endl;
    }

    auto main() -> int
    {
      cout << "[singlethread.cpp]" << endl;

      thread thread1(threadProc);
      thread1.join();

      return 0;
    }

```

正如我们在前面的代码中所看到的，我们有一个名为`threadProc()`的函数，并将其传递给`main()`函数中的`thread1`初始化。初始化后，我们调用`join()`方法来执行`thread1`对象。我们在控制台上看到的输出应该如下：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-fp/img/86d5d8c0-8176-4e09-8737-4e31bd48ba43.png)

我们已经成功地在我们的代码中运行了一个线程。现在，让我们在`main()`函数中添加一行代码，来迭代一行代码。我们将同时并发运行它们。`singlethread2.cpp`的代码如下：

```cpp
    /* singlethread2.cpp */
    #include <thread>
    #include <chrono>
    #include <iostream>

    using namespace std;

    void threadProc()
    {
      for (int i = 0; i < 5; i++)
      {
        cout << "thread: current i = ";
        cout << i << endl;
      }
    }

    auto main() -> int
    {
      cout << "[singlethread2.cpp]" << endl;

      thread thread1(threadProc);

      for (int i = 0; i < 5; i++)
 {
 cout << "main : current i = " << i << endl;

        this_thread::sleep_for(
            chrono::milliseconds(5)); }

      thread1.join();

      return 0;
    }

```

正如我们在前面的代码中所看到的，我们添加了一个`for`循环来迭代一些代码，并与`thread1`同时运行。为了理解它，我们也在`threadProc()`函数中添加了一个`for`循环。让我们看一下以下截图，以弄清楚我们将得到什么输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-fp/img/8aa03435-bafd-4bef-a608-028751070653.png)

我们看到`threadProc()`函数和`main()`函数中的代码同时并发运行。你们可能会得到不同的结果，但没关系，因为结果是无法预测的，这取决于设备本身。然而，目前我们已经能够同时运行两个进程。

我多次运行了前面的代码，以获得我们在前面截图中看到的输出。你可能会看到`threadProc()`和`main()`函数之间的不同顺序，或者得到混乱的输出，因为线程的流程是不可预测的。

# 处理多线程代码

在多线程技术中，我们同时运行两个或更多个线程。假设我们同时运行五个线程。我们可以使用以下`multithread.cpp`代码，将这五个线程存储在一个数组中：

```cpp
    /* multithread.cpp */
    #include <thread>
    #include <iostream>

    using namespace std;

    void threadProc()
    {
      cout << "Thread ID: ";
      cout << this_thread::get_id() << endl;
    }

    auto main() -> int
    {
      cout << "[multithread.cpp]" << endl;

      thread threads[5];

      for (int i = 0; i < 5; ++i)
      {
        threads[i] = thread(threadProc);
      }

      for (auto& thread : threads)
      {
        thread.join();
      }

      return 0;
    }

```

在我们根据前面的代码初始化这五个线程之后，我们将运行`join()`方法来执行所有线程。通过使用`join()`方法，程序将等待调用线程中的所有进程完成，然后继续下一个进程（如果有的话）。我们在控制台中看到的结果如下：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-fp/img/808eb931-b775-4816-b4c6-e756f8d99112.png)

在前面的截图中，我们看到所有五个线程都已成功执行。我们也可以使用 Lambda 表达式来初始化线程。下面的`lambdathread.cpp`代码是从前面使用 Lambda 而不是创建一个单独的函数进行重构的代码：

```cpp
    /* lambdathread.cpp */
    #include <thread>
    #include <iostream>

    using namespace std;

    auto main() -> int
    {
      cout << "[lambdathread.cpp]" << endl;

      thread threads[5];

      for (int i = 0; i < 5; ++i)
      {
 threads[i] = thread([]()
 {
 cout << "Thread ID: ";
 cout << this_thread::get_id() << endl;
 });
       }

      for (auto& thread : threads)
      {
        thread.join();
      }

      return 0;
    }

```

如果我们看`lambdathread.cpp`代码与`multithread.cpp`代码，没有什么显著的变化。然而，由于该函数只会被调用一次，最好使用 Lambda，这样更容易维护。我们在控制台上看到的输出如下截图所示，与`multithread.cpp`代码的输出相比并没有太大的不同：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-fp/img/533c3423-6bf0-450e-99a6-6988f42d3d61.png)

尽管在运行`lambdathread.cpp`与`multithread.cpp`代码进行比较时我们得到了相同的输出，但是当我们使用 Lambda 表达式初始化线程时，我们有一个清晰的代码。我们不需要创建另一个方法传递给`Thread`，例如`threadProc()`，因为这个方法实际上只使用一次。

再次注意，您在屏幕上看到的结果可能与我给出的截图不同。

# 使用互斥锁同步线程

到目前为止，我们已经成功地执行了一个多线程代码。然而，如果我们在线程内部使用一个共享对象并对其进行操作，就会出现问题。这被称为**同步**。在本节中，我们将尝试通过应用`mutex`技术来避免这个问题。

# 避免同步问题

正如我们之前讨论的，在这一部分，我们必须确保在线程中运行的共享对象在执行时给出正确的值。假设我们有一个名为`counter`的全局变量，并且我们计划在我们拥有的所有五个线程中增加它的值。每个线程将执行`10000`次增量迭代，因此我们期望得到所有五个线程的结果为`50000`。代码如下：

```cpp
    /* notsync.cpp */
    #include <thread>
    #include <iostream>

    using namespace std;

    auto main() -> int
    {
      cout << "[notsync.cpp]" << endl;

      int counter = 0;

      thread threads[5];

      for (int i = 0; i < 5; ++i)
      {
        threads[i] = thread([&counter]()
        {
 for (int i = 0; i < 10000; ++i)
 {
 ++counter;
 cout << "Thread ID: ";
 cout << this_thread::get_id();
 cout << "\tCurrent Counter = ";
 cout << counter << endl;
 }
        });
      }

      for (auto& thread : threads)
      {
        thread.join();
      }

      cout << "Final result = " << counter << endl;

      return 0;
    }

```

现在，让我们看一下当我们运行前面的代码时，我们可能在控制台上看到的以下截图：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-fp/img/e0d31bea-b6e2-49db-acff-172784871ce3.png)

不幸的是，根据前面的截图，我们没有得到我们期望的结果。这是因为增量过程不是一个原子操作，原子操作将保证并发进程的隔离。

如果您得到了不同的输出，不要担心，我们仍然在正确的轨道上，因为这个程序展示了同步问题，接下来您将看到。

如果我们深入追踪输出，我们会看到有两个线程执行`counter`变量的完全相同的值，正如我们在下面的截图中所看到的：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-fp/img/8f7a5eff-9464-4f99-b4e6-3bb1f2553f25.png)

我们看到 ID 为`2504`和`5524`的线程在`counter`变量的值为`44143`时访问了该变量。这就是当我们运行前面的代码时为什么会得到意外的结果。现在我们需要使增量操作成为一个原子操作，这样就可以在操作期间不允许其他进程读取或更改被读取或更改的状态。

为了解决这个问题，我们可以使用`mutex`类来使我们的计数器变量`线程安全`。这意味着在线程访问计数器变量之前，它必须确保该变量不被其他线程访问。我们可以使用`mutex`类中的`lock()`和`unlock()`方法来锁定和解锁目标变量。让我们看一下下面的`mutex.cpp`代码来演示`mutex`的实现：

```cpp
    /* mutex.cpp */
    #include <thread>
    #include <mutex>
    #include <iostream>

    using namespace std;

    auto main() -> int
    {
      cout << "[mutex.cpp]" << endl;

      mutex mtx;
      int counter = 0;

      thread threads[5];

      for (int i = 0; i < 5; ++i)
      {
        threads[i] = thread([&counter, &mtx]()
        {
           for (int i = 0; i < 10000; ++i)
           {
             mtx.lock();
             ++counter;
             mtx.unlock();

             cout << "Thread ID: ";
             cout << this_thread::get_id();
             cout << "\tCurrent Counter = ";
             cout << counter << endl;
           }
        });
      }

      for (auto& thread : threads)
      {
        thread.join();
      }

      cout << "Final result = " << counter << endl;

      return 0;
    }

```

在前面的代码中，我们可以看到，在代码递增`counter`变量之前，它调用了`lock()`方法。之后，它调用`unlock()`方法来通知其他线程，`counter`变量现在可以自由操作。如果我们运行前面的代码，应该在控制台上看到以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-fp/img/0e60f03b-94fb-43c7-aa0e-2e9ede5261b2.png)

通过使用`mutex`类，现在我们得到了我们期望的结果，如前面的截图所示。

# 自动解锁变量

现在我们知道如何锁定变量，以确保没有两个线程同时处理相同的值。然而，如果在线程调用`unlock()`方法之前抛出异常，问题就会发生。如果变量的状态保持锁定，程序将完全被锁定。为了解决这个问题，我们可以使用`lock_guard<mutex>`来锁定变量，并确保无论发生什么情况，它都将在作用域结束时解锁。以下代码片段是通过添加`lock_guard<mutex>`功能从前面的代码重构而来的：

```cpp
    /* automutex.cpp */
    #include <thread>
    #include <mutex>
    #include <iostream>

    using namespace std;

    auto main() -> int
    {
      cout << "[automutex.cpp]" << endl;

      mutex mtx;
      int counter = 0;

      thread threads[5];

      for (int i = 0; i < 5; ++i)
      {
        threads[i] = thread([&counter, &mtx]()
        {
          for (int i = 0; i < 10000; ++i)
          {
            {
              lock_guard <mutex> guard(mtx);
              ++counter;
             }

             cout << "Thread ID: ";
             cout << this_thread::get_id();
             cout << "\tCurrent Counter = ";
             cout << counter << endl;
          }
         });
       }

       for (auto& thread : threads)
       {
          thread.join();
       }

      cout << "Final result = " << counter << endl;

      return 0;
    }

```

从前面的`automutex.cpp`代码中可以看出，在递增`counter`变量之前，它调用了`lock_guard <mutex> guard(mtx)`。如果我们运行代码，我们将得到与`mutex.cpp`代码完全相同的输出。然而，现在我们有一个不会不可预测地被锁定的程序。

# 使用递归互斥量避免死锁

在前一节中，我们使用`lock_guard`来确保变量不被多个线程访问。然而，如果多个`lock_guard`获取锁，我们仍然会面临问题。在下面的代码片段中，我们有两个函数将调用`lock_guard`--`Multiplexer()`和`Divisor()`。除此之外，我们还有一个函数将调用这两个函数--`RunAll()`，它将在调用这两个函数之前先调用`lock_guard`。代码应该如下所示：

```cpp
    /* deadlock.cpp */
    #include <thread>
    #include <mutex>
    #include <iostream>

    using namespace std;

    struct Math
    {
      mutex mtx;
      int m_content;

      Math() : m_content(0)
      {
      }

      // This method will lock the mutex
      void Multiplexer(int i)
      {
        lock_guard<mutex> lock(mtx);
        m_content *= i;
        cout << "Multiplexer() is called. m_content = ";
        cout << m_content << endl;
      }

      // This method will lock the mutex also
      void Divisor(int i)
      {
        lock_guard<mutex> lock(mtx);
        m_content /= i;
        cout << "Divisor() is called. m_content = ";
        cout << m_content << endl;
      }

      // This method will invoke 
      // the two preceding methods
      // which each method locks the mutex
      void RunAll(int a)
      {
        lock_guard<mutex> lock(mtx);
        Multiplexer(a);
        Divisor(a);
      }
    };

    auto main() -> int
    {
      cout << "[deadlock.cpp]" << endl;

      // Instantiating Math struct
      // and invoking the RunAll() method 
      Math math;
      math.RunAll(10);

      return 0;
    }

```

我们将成功编译以下代码片段。然而，如果我们运行前面的代码，由于**死锁**，程序将无法退出。这是因为同一个互斥量不能被多个线程两次获取。当调用`RunAll()`函数时，它会获取`lock`对象。`RunAll()`函数内部的`Multiplexer()`函数也想要获取`lock`。然而，`lock`已经被`RunAll()`函数锁定。为了解决这个问题，我们可以将`lock_guard<mutex>`替换为`lock_guard<recursive_mutex>`，如下面的代码片段所示：

```cpp
    /* recursivemutex.cpp */
    #include <thread>
    #include <mutex>
    #include <iostream>

    using namespace std;

    struct Math
    {
 recursive_mutex mtx;
      int m_content;

      Math() : m_content(1)
      {
      }

      // This method will lock the mutex
      void Multiplexer(int i)
      {
        lock_guard<recursive_mutex> lock(mtx);
        m_content *= i;
        cout << "Multiplexer() is called. m_content = ";
        cout << m_content << endl;
      }

      // This method will lock the mutex also
      void Divisor(int i)
      {
        lock_guard<recursive_mutex> lock(mtx);
        m_content /= i;
        cout << "Divisor() is called. m_content = ";
        cout << m_content << endl;
      }

      // This method will invoke 
      // the two preceding methods
      // which each method locks the mutex
      void RunAll(int a)
      {
        lock_guard<recursive_mutex> lock(mtx);
        Multiplexer(a);
        Divisor(a);
      }
    };

    auto main() -> int
    {
      cout << "[recursivemutex.cpp]" << endl;

      // Instantiating Math struct
      // and invoking the RunAll() method 
      Math math;
      math.RunAll(10);

      return 0;
    }

```

现在，我们可以成功编译和运行前面的代码。我们可以使用`lock_guard<recursive_mutex>`类，它允许多次锁定互斥量而不会陷入死锁。当我们运行前面的代码时，控制台上将看到以下截图：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-fp/img/7faafdd2-15bc-4f57-82ca-d50df7296692.png)

现在，我们知道如果我们想要调用递归锁定相同的`mutex`的函数，我们需要使用一个递归`mutex`。

# 了解 Windows 操作系统中的线程处理

让我们转向一个被许多用户计算机广泛使用的特定操作系统，那就是 Windows。我们的代码必须在来自领先操作系统供应商的商业平台上运行，比如微软。因此，我们现在将在 Windows 操作系统中运行线程。在这个操作系统中，线程是一个内核资源，这意味着它是由操作系统内核创建和拥有的对象，并且存在于内核中。内核本身是一个核心程序，对系统中的一切都有完全控制。在本节中，我们将在 Windows 操作系统中开发一个线程，以便我们的程序可以在这个操作系统中正常工作。

# 使用句柄处理

在 Windows 操作系统中，句柄是对资源的抽象引用值。在本讨论中，我们将使用抽象引用来持有线程。假设我们有一个`threadProc()`函数，将在`hnd`变量中持有的线程中调用。代码如下：

```cpp
    /* threadhandle.cpp */
    #include <iostream>
    #include <windows.h>

    using namespace std;

    auto threadProc(void*) -> unsigned long
    {
      cout << "threadProc() is run." << endl;
      return 100;
    }

    auto main() -> int
    {
      cout << "[threadhandle.cpp]" << endl;

      auto hnd = HANDLE
      {
        CreateThread(
            nullptr,
            0,
            threadProc,
            nullptr,
            0,
            nullptr)
      };

      if (hnd)
      {
        WaitForSingleObject(hnd, INFINITE);

        unsigned long exitCode;
        GetExitCodeThread(hnd, &exitCode);

        cout << "The result = " << exitCode << endl;

        CloseHandle(hnd);
      }

      return 0;
    }

```

如前所述，我们使用`windows.h`头文件提供的`CreateThread()`函数生成线程。目前，我们只传递`nullptr`值作为默认参数，除了`threadProc`作为我们将从线程中调用的函数。

在我们初始化线程的句柄之后，我们可以确保`hnd`变量包含线程的句柄，然后调用`WaitForSingleObject()`函数。这类似于我们在前面一节中使用的`join()`方法，它将运行线程并等待直到线程完成。由于线程句柄是我们使用的资源，请不要忘记使用`CloseHandle()`函数释放它。如果我们运行上述代码，我们将在控制台屏幕上看到以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-fp/img/b74afe83-9bdb-431b-b75f-7a7da30e77ba.png)

正如我们所看到的，我们成功地运行了线程，因为我们从`threadProc()`函数中得到了预期的进程。

# 重构为唯一句柄

现在，为了简化我们的编程过程，我们将创建一个名为`NullHandle`的类，它将在我们不再需要它时自动释放资源。它将从我们也将开发的`UniqueHandle`类构造而来。这些类可以在`uniquehandle.h`文件中找到。`UniqueHandle`的实现如下：

```cpp
    template <typename C>
    class UniqueHandle
    {
      private:
        HANDLE m_val;

        void Close()
        {
          if (*this)
          {
            C::Exit(m_val);
          }
        }

      public:
        // Copy assignment operator 
        UniqueHandle(UniqueHandle const &) = delete;
        auto operator=(UniqueHandle const &)->UniqueHandle & = delete;

        // UniqueHandle constructor
        explicit UniqueHandle(HANDLE value = C::Invalid()) :
        m_val{ value }
        {
        }

        // Move assignment operator
        UniqueHandle(UniqueHandle && other) :
        m_val{ other.Release() }
        {
        }

        // Move assignment operator
        auto operator=(UniqueHandle && other) -> UniqueHandle &
        {
          if (this != &other)
          {
            Reset(other.Release());
          }

          return *this;
        }

        // Destructor of UniqueHandle class
        ~UniqueHandle()
        {
          Close();
        }

        // bool operator for equality
        explicit operator bool() const 
        {
          return m_val != C::Invalid();
        }

        // Method for retrieving the HANDLE value
        HANDLE Get() const
        {
          return m_val;
        }

       // Method for releasing the HANDLE value
       HANDLE Release()
       {
         auto value = m_val;
         m_val = C::Invalid();
         return value;
       }

       // Method for reseting the HANDLE
       bool Reset(HANDLE value = C::Invalid())
       {
        if (m_val != value)
        {
           Close();
           m_val = value;
        }

         return static_cast<bool>(*this);
       }
    };

```

如我们所见，我们有一个完整的`UniqueHandle`类实现，可以被实例化，并且将在其析构函数中自动关闭句柄。要使用`NullHandle`对象，我们将使用以下代码：

```cpp
    using NullHandle = UniqueHandle<NullHandleCharacteristics>;

```

`NullHandleCharacteristics`结构的实现如下：

```cpp
    struct NullHandleCharacteristics
    {
      // Returning nullptr when the HANDLE is invalid
      static HANDLE Invalid()
      {
         return nullptr;
      }

      // Exit the HANDLE by closing it
      static void Exit(HANDLE val)
      {
         CloseHandle(val);
      }
    };

```

现在，让我们重构之前的`threadhandle.cpp`代码。我们将用`NullHandle`替换`HANDLE`，代码如下：

```cpp
    auto hnd = NullHandle
    {
      CreateThread(
        nullptr,
        0,
        threadProc,
        nullptr,
        0,
        nullptr)
    };

```

然后，我们将创建一个名为`WaitOneThread()`的新函数来调用线程本身，并等待直到它完成。实现应该如下：

```cpp
    auto WaitOneThread(
      HANDLE const h,
      DWORD const ms = INFINITE) -> bool
      {
        auto const r = WaitForSingleObject(
        h,
        ms);

        // Inform that thread is not idle
        if (r == WAIT_OBJECT_0)
          return true;

        // Inform that thread is not idle
        if (r == WAIT_TIMEOUT)
          return false;

        throw WinException();
      }

```

通过使用`WaitOneThread()`函数，我们可以知道线程是否已经运行。`WinException`结构可以实现如下：

```cpp
    struct WinException
    {
      unsigned long error;

      explicit WinException(
        unsigned long value = GetLastError()) :
        error{ value }
       {
       }
    };

```

现在，在我们初始化`hnd` HANDLE 之后，我们可以添加以下代码片段到`main()`函数中：

```cpp
    if (hnd)
    {
      if (WaitOneThread(hnd.Get(), 0))
        cout << "Before running thread" << endl;

      WaitOneThread(hnd.Get());

      if (WaitOneThread(hnd.Get(), 0))
        cout << "After running thread" << endl;

      unsigned long exitCode;
      GetExitCodeThread(hnd.Get(), &exitCode);

      cout << "The result = " << exitCode << endl;
    }

```

从上述代码中可以看出，我们调用`WaitOneThread()`函数，并将`0`作为`ms`参数传递给`WaitForSingleObject()`函数调用，以了解其状态。我们可以将`INFINITE`值传递给它，以调用线程并等待直到它完成。以下是从`threadhandle.cpp`代码重构而来并使用了`UniqueHandle`类的`threaduniquehandle.cpp`代码：

```cpp
    /* threaduniquehandle.cpp */
    #include <iostream>
    #include <windows.h>
    #include "../uniquehandle_h/uniquehandle.h"

    using namespace std;

    unsigned long threadProc(void*)
    {
      cout << "threadProc() is run." << endl;
      return 100;
    }

    struct WinException
    {
      unsigned long error;
      explicit WinException(
        unsigned long value = GetLastError()) :
        error{ value }
        {
        }
    };

    auto WaitOneThread(
      HANDLE const h,
      DWORD const ms = INFINITE) -> bool
      {
        auto const r = WaitForSingleObject(
        h,
        ms);

       // Inform that thread is not idle
       if (r == WAIT_OBJECT_0)
         return true;

       // Inform that thread is not idle
       if (r == WAIT_TIMEOUT)
         return false;

       throw WinException();
      }

    auto main() -> int
    {
      cout << "[threaduniquehandle.cpp]" << endl;

      auto hnd = NullHandle
      {
        CreateThread(
            nullptr,
            0,
            threadProc,
            nullptr,
            0,
            nullptr)
      };

      if (hnd)
      {
        if (WaitOneThread(hnd.Get(), 0))
          cout << "Before running thread" << endl;

        WaitOneThread(hnd.Get());

        if (WaitOneThread(hnd.Get(), 0))
          cout << "After running thread" << endl;

        unsigned long exitCode;
        GetExitCodeThread(hnd.Get(), &exitCode);

        cout << "The result = " << exitCode << endl;
      }

     return 0;
    }

```

以下截图是我们应该在控制台屏幕上看到的输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-fp/img/70059c6e-2e41-4913-86c8-d05ada792004.png)

从上述截图中可以看出，我们没有`Before running thread`行。这是因为每次未调用线程时，我们将得到`WAIT_TIMEOUT`输出。而且，我们成功执行了`threadProc()`函数中的代码。

# 触发事件

在 Windows 中玩耍线程之后，让我们尝试另一种并发类型--`Event`。它是系统可以触发的动作。要进一步了解它，让我们看一下以下代码片段，其中我们创建了一个名为`Event`的新类，它实现了`UniqueHandle`：

```cpp
    class Event
    {
      private:
        NullHandle hnd;

      public:
        Event(Event const &) = delete;
        auto operator=(Event const &)->Event & = delete;
        ~Event() = default;

        explicit Event(bool manual) :
         hnd
         {
           CreateEvent(nullptr,
            manual, false, nullptr)
         }
         {
           if (!hnd)
            throw WinException();
         }

        explicit Event(EventType evType) :
         hnd
         {
           CreateEvent(
            nullptr,
            static_cast<BOOL>(evType),
            false,
            nullptr)
         }
         {
           if (!hnd)
            throw WinException();
         }

         Event(Event && other) throw() :
           hnd
           {
             other.hnd.Release()
           }
           {
           }

         auto operator=(Event && other) throw()->Event &
         {
           hnd = move(other.hnd);
         }

         void Set()
         {
           cout << "The event is set" << endl;
           SetEvent(hnd.Get());
         }

         void Clear()
         {
           cout << "The event is cleared" << endl;
           ResetEvent(hnd.Get());
         }

         auto Wait(
           DWORD const ms = INFINITE) -> bool
           {
             auto const result = WaitForSingleObject(
             hnd.Get(), ms);

            return result == WAIT_OBJECT_0;
           }
     };

```

如我们在上述`Event`类实现中所看到的，我们有`Set()`、`Clear()`和`Wait()`方法来分别设置事件、清除事件和等待事件完成。我们有两种事件类型，即自动重置和手动重置，声明如下：

```cpp
    enum class EventType
    {
      AutoReset,
      ManualReset
    };

```

现在，我们将在`main()`函数中创建内容。我们首先实例化`Event`类，然后检查事件信号。如果没有被标记，我们将设置事件。相反，我们将清除事件。代码将是下面的`event.cpp`代码：

```cpp
    /* event.cpp */
    #include <iostream>
    #include <windows.h>
    #include "../uniquehandle_h/uniquehandle.h"

    using namespace std;

    struct WinException
    {
      unsigned long error;

      explicit WinException(
        unsigned long value = GetLastError()) :
        error{ value }
        {
        }
    };

    enum class EventType
    {
      AutoReset,
      ManualReset
    };

    class Event
    {
      private:
        NullHandle hnd;

      public:
        Event(Event const &) = delete;
        auto operator=(Event const &)->Event & = delete;
        ~Event() = default;

        explicit Event(bool manual) :
         hnd
         {
           CreateEvent(nullptr,
           manual, false, nullptr)
         }
         {
           if (!hnd)
            throw WinException();
         }

         explicit Event(EventType evType) :
          hnd
          {
            CreateEvent(
            nullptr,
            static_cast<BOOL>(evType),
            false,
            nullptr)
          }
          {
            if (!hnd)
             throw WinException();
          }

          Event(Event && other) throw() :
            hnd
            {
              other.hnd.Release()
            }
            {
            }

          auto operator=(Event && other) throw() -> Event &
          {
              hnd = move(other.hnd);
          }

          void Set()
          {
              cout << "The event is set" << endl;
              SetEvent(hnd.Get());
          }

          void Clear()
          {
               cout << "The event is cleared" << endl;
               ResetEvent(hnd.Get());
          }

          auto Wait(
            DWORD const ms = INFINITE) -> bool
              {
                auto const result = WaitForSingleObject(
                  hnd.Get(), ms);

                return result == WAIT_OBJECT_0;
             }
          };

          void CheckEventSignaling( bool b)
          {
            if (b)
            {
              cout << "The event is signaled" << endl;
            }
            else
            {
             cout << "The event is not signaled" << endl;
            }
         }

         auto main() -> int
         {
           cout << "[event.cpp]" << endl;

           auto ev = Event{
             EventType::ManualReset };

             CheckEventSignaling(ev.Wait(0));

             ev.Set();

             CheckEventSignaling(ev.Wait(0));

             ev.Clear();

             CheckEventSignaling(ev.Wait(0));

             return 0;
          }

```

正如我们在前面的代码中所看到的，这是代码的作用：

1.  它在`main()`函数中创建了`Event`类的实例，并手动重置了事件。

1.  它调用`CheckEventSignaling()`函数，通过将`Wait()`函数传递给`CheckEventSignaling()`函数来找出事件的状态，然后调用`WaitForSingleObject()`函数。

1.  它调用了`Set()`和`Reset()`函数。

1.  现在运行前面的`event.cpp`代码。您将在控制台上看到以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-fp/img/72bfd423-0b5b-4915-9711-490b1b27b46f.png)

如果我们看一下前面的截图，首先`Event`类的初始化没有被标记。然后我们设置了事件，现在它被标记为`CheckEventSignaling()`方法的状态。在这里，我们可以通过调用`WaitForSingleObject()`函数来检查标记事件的状态。

# 从线程调用事件

现在，让我们使用线程调用`Event`类。但在此之前，我们必须能够包装多个线程，一起调用它们，并等待它们的进程完成。以下代码块是将打包线程的`Wrap()`函数：

```cpp
    void Wrap(HANDLE *)
    {
    }

    template <typename T, typename... Args>
    void Wrap(
      HANDLE * left,
      T const & right,
      Args const & ... args)
      {
        *left = right.Get();
        Wrap(++left, args...);
      }

```

当我们加入所有线程时，我们将调用前面的`Wrap()`函数。因此，我们将需要另一个名为`WaitAllThreads()`的函数，正如我们在下面的代码片段中所看到的：

```cpp
    template <typename... Args>
    void WaitAllThreads(Args const & ... args)
    {
      HANDLE handles[sizeof...(Args)];

      Wrap(handles, args...);

      WaitForMultipleObjects(
        sizeof...(Args),
        handles,
        true,
        INFINITE);
    }

```

现在，我们可以创建我们的完整代码，将使用以下`eventthread.cpp`代码运行两个线程：

```cpp
    /* eventthread.cpp */
    #include <iostream>
    #include <windows.h>
    #include "../uniquehandle_h/uniquehandle.h"

    using namespace std;

    void Wrap(HANDLE *)
    {
    }

    template <typename T, typename... Args>
    void Wrap(
      HANDLE * left,
      T const & right,
      Args const & ... args)
      {
        *left = right.Get();
        Wrap(++left, args...);
      }

    template <typename... Args>
    void WaitAllThreads(Args const & ... args)
    {
      HANDLE handles[sizeof...(Args)];

      Wrap(handles, args...);

      WaitForMultipleObjects(
        sizeof...(Args),
        handles,
        true,
        INFINITE);
    }

    auto threadProc(void*) -> unsigned long
    {
      cout << "Thread ID: ";
      cout << GetCurrentThreadId() << endl;
      return 120;
    }

    auto main() -> int
    {
      cout << "[eventthread.cpp]" << endl;

      auto thread1 = NullHandle
      {
        CreateThread(
          nullptr,
          0,
          threadProc,
          nullptr,
          CREATE_SUSPENDED,
          nullptr)
      };

      auto thread2 = NullHandle
      {
        CreateThread(
          nullptr,
          0,
          threadProc,
          nullptr,
          CREATE_SUSPENDED,
          nullptr)
     };

 ResumeThread(thread1.Get());
 ResumeThread(thread2.Get());

     WaitAllThreads(thread1, thread2);

     return 0;
    }

```

此外，如果我们运行前面的`eventthread.cpp`代码，我们将在控制台屏幕上看到以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-fp/img/0a60a3d6-c786-4791-b43d-797e4d01e1e6.png)

我们已成功触发了一个`Event`，因此它可以被设置为标记，并且可以在`event.cpp`代码中被清除为未标记。我们还成功地包装了多个线程，然后在`eventthread.cpp`代码中一起调用它们。现在，让我们将这两个代码连接起来，这样我们就可以从线程中访问事件。代码应该像下面的`eventthread2.cpp`代码一样：

```cpp
    /* eventthread2.cpp */
    #include <iostream>
    #include <windows.h>
    #include "../uniquehandle_h/uniquehandle.h"

    using namespace std;

    struct WinException
    {
      unsigned long error;

      explicit WinException(
        unsigned long value = GetLastError()) :
        error{ value }
        {
        }
    };

    enum class EventType
    {
      AutoReset,
      ManualReset
     };

    class Event
    {
      private:
        NullHandle hnd;

      public:
        Event(Event const &) = delete;
        auto operator=(Event const &)->Event & = delete;
        ~Event() = default;

        explicit Event(bool manual) :
          hnd
          {
            CreateEvent(nullptr,
            manual, false, nullptr)
          }
          {
            if (!hnd)
             throw WinException();
          }

        explicit Event(EventType evType) :
          hnd
          {
            CreateEvent(
              nullptr,
              static_cast<BOOL>(evType),
              false,
              nullptr)
           }
           {
             if (!hnd)
              throw WinException();
           }

        Event(Event && other) throw() :
          hnd
          {
            other.hnd.Release()
          }
          {
          }

        auto operator=(Event && other) throw() -> Event &
        {
          hnd = move(other.hnd);
        }

        void Set()
        {
          cout << "The event is set" << endl;
          SetEvent(hnd.Get());
        }

        void Clear()
        {
          cout << "The event is cleared" << endl;
          ResetEvent(hnd.Get());
        }

        auto Wait( DWORD const ms = INFINITE) -> bool
        {
           auto const result = WaitForSingleObject(
            hnd.Get(), ms);

           return result == WAIT_OBJECT_0;
        }
     };

        void Wrap(HANDLE *)
        {
        }

        template <typename T, typename... Args>
        void Wrap(
        HANDLE * left,
        T const & right,
        Args const & ... args)
        {
          *left = right.Get();
           Wrap(++left, args...);
        }

        template <typename... Args>
        void WaitAllThreads(Args const & ... args)
        {
        HANDLE handles[sizeof...(Args)];

        Wrap(handles, args...);

        WaitForMultipleObjects(
          sizeof...(Args),
          handles,
          true,
          INFINITE);
        }

        static auto ev = Event{
        EventType::ManualReset };

        auto threadProc(void*) -> unsigned long
        {
          cout << "Thread ID: ";
          cout << GetCurrentThreadId() << endl;

          ev.Wait();

          cout << "Run Thread ID: ";
          cout << GetCurrentThreadId() << endl;

          return 120;
        }

        auto main() -> int
        {
          cout << "[eventthread2.cpp]" << endl;

          auto thread1 = NullHandle
          {
            CreateThread(
              nullptr,
              0,
              threadProc,
              nullptr,
              0,
              nullptr)
          };

          auto thread2 = NullHandle
          {
            CreateThread(
              nullptr,
              0,
              threadProc,
              nullptr,
              0,
              nullptr)
         };

 Sleep(100);
 ev.Set();
 Sleep(100);

         WaitAllThreads(thread1, thread2);

         return 0;
    }

```

在前面的`eventthread2.cpp`代码中，我们尝试使用线程触发事件。首先我们初始化了两个`NullHandle`对象线程。然后，我们设置了事件，并调用`Sleep()`函数使事件激活。然后`WaitAllThreads()`函数调用`threadProc()`函数并运行每个线程。这将通过调用`ev.Wait()`函数来触发事件。然后线程将运行。以下截图是我们将在控制台屏幕上看到的输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-fp/img/94bc604a-76c4-49b3-9325-383479e5379f.png)

前面的代码是我们手动设置为重置事件的事件。这意味着我们必须说明何时清除事件。现在，我们将`AutoReset`传递给事件实例。我们还将稍微修改`threadProc()`函数。我们正在谈论的是以下`eventthread3.cpp`代码：

```cpp
    /* eventthread3.cpp */
    #include <iostream>
    #include <windows.h>
    #include "../uniquehandle_h/uniquehandle.h"

    using namespace std;

    struct WinException
    {
      unsigned long error;

      explicit WinException(
        unsigned long value = GetLastError()) :
        error{ value }
        {
        }
    };

    enum class EventType
    {
      AutoReset,
      ManualReset
    };

    class Event
    {
       private:
         NullHandle hnd;

       public:
         Event(Event const &) = delete;
         auto operator=(Event const &)->Event & = delete;
         ~Event() = default;

         explicit Event(bool manual) :
           hnd
           {
             CreateEvent(nullptr,
             manual, false, nullptr)
           }
           {
             if (!hnd)
              throw WinException();
           }

          explicit Event(EventType evType) :
             hnd
             {
               CreateEvent(
                 nullptr,
                 static_cast<BOOL>(evType),
                 false,
                 nullptr)
             }
             {
               if (!hnd)
                throw WinException();
             }

         Event(Event && other) throw() :
           hnd
           {
             other.hnd.Release()
           }
           {
           }

         auto operator=(Event && other) throw() -> Event &
           {
              hnd = move(other.hnd);
           }

          void Set()
          {
             cout << "The event is set" << endl;
             SetEvent(hnd.Get());
          }

          void Clear()
          {
              cout << "The event is cleared" << endl;
              ResetEvent(hnd.Get());
          }

          auto Wait(
            DWORD const ms = INFINITE) -> bool
            {
              auto const result = WaitForSingleObject(
                hnd.Get(), ms);

             return result == WAIT_OBJECT_0;
            }
       };

         void Wrap(HANDLE *)
         {
         }

         template <typename T, typename... Args>
         void Wrap(
           HANDLE * left,
           T const & right,
           Args const & ... args)
           {
             *left = right.Get();
             Wrap(++left, args...);
           }

           template <typename... Args>
           void WaitAllThreads(Args const & ... args)
           {
              HANDLE handles[sizeof...(Args)];

              Wrap(handles, args...);

              WaitForMultipleObjects(
                sizeof...(Args),
                handles,
                true,
                INFINITE);
           }

 static auto ev = Event{
 EventType::AutoReset };

           auto threadProc(void*) -> unsigned long
           {
             cout << "Thread ID: ";
             cout << GetCurrentThreadId() << endl;

             ev.Wait();

             cout << "Run Thread ID: ";
             cout << GetCurrentThreadId() << endl;

             Sleep(1000);
 ev.Set();

             return 120;
           }

           auto main() -> int
           {
             cout << "[eventthread3.cpp]" << endl;

             auto thread1 = NullHandle
             {
               CreateThread(
                 nullptr,
                 0,
                 threadProc,
                 nullptr,
                 0,
                 nullptr)
             };

             auto thread2 = NullHandle
             {
                CreateThread(
                  nullptr,
                  0,
                  threadProc,
                  nullptr,
                  0,
                  nullptr)
             };

             Sleep(100);
             ev.Set();
             Sleep(100);

             WaitAllThreads(thread1, thread2);

             return 0;
       }

```

正如我们在前面的代码中所看到的，我们将事件的`Set()`方法从`main()`函数移动到`threadProc()`函数中。现在，每次调用`threadProc()`函数时，事件都会自动设置。以下截图是我们应该在控制台屏幕上看到的输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-fp/img/c3e50f9d-5157-4271-a317-35d79fff8152.png)

# 总结

在本章中，我们学习了 C++并发的概念。我们现在可以处理单个线程以及多线程。我们还可以同步多线程，使其可以平稳运行；因此，我们可以避免同步问题和死锁。最后，我们可以使用 Windows 中的句柄资源来创建线程，并使用该事件触发事件。

在下一章中，我们将运用前几章学到的知识以函数式的方式来制作一个应用程序。它还将解释如何测试使用 C++语言构建的应用程序。
