# C++ 高级编程秘籍（二）

> 原文：[`annas-archive.org/md5/24e080e694c59b3f8e0220d0902724b0`](https://annas-archive.org/md5/24e080e694c59b3f8e0220d0902724b0)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第三章：实现移动语义

在本章中，我们将学习一些高级的 C++移动语义。我们将首先讨论大五，这是一种鼓励程序员显式定义类的销毁和移动/复制语义的习语。接下来，我们将学习如何定义移动构造函数和移动赋值运算符；移动语义的不同组合（包括仅移动和不可复制）；不可移动的类；以及如何实现这些类以及它们的重要性。

本章还将讨论一些常见的陷阱，比如为什么`const &&`移动毫无意义，以及如何克服左值与右值引用类型。本章的示例非常重要，因为一旦启用 C++11 或更高版本，移动语义就会启用，这会改变 C++在许多情况下处理类的方式。本章的示例为在 C++中编写高效的代码提供了基础，使其行为符合预期。

本章的示例如下：

+   使用编译器生成的特殊类成员函数和大五

+   使您的类可移动

+   仅移动类型

+   实现`noexcept`移动构造函数

+   学会谨慎使用`const &&`

+   引用限定的成员函数

+   探索无法移动或复制的对象

# 技术要求

要编译和运行本章中的示例，您必须具有管理权限的计算机运行 Ubuntu 18.04，并具有正常的互联网连接。在运行这些示例之前，您必须安装以下内容：

```cpp
> sudo apt-get install build-essential git cmake 
```

如果这是安装在 Ubuntu 18.04 以外的任何操作系统上，则需要 GCC 7.4 或更高版本和 CMake 3.6 或更高版本。

# 使用编译器生成的特殊类成员函数和大五

在使用 C++11 或更高版本时，如果您没有在类定义中显式提供它们，编译器将为您的 C++类自动生成某些函数。在本示例中，我们将探讨这是如何工作的，编译器将为您创建哪些函数，以及这如何影响您程序的性能和有效性。总的来说，本示例的目标是证明每个类应该至少定义大五，以确保您的类明确地说明了您希望如何管理资源。

# 准备工作

开始之前，请确保满足所有的技术要求，包括安装 Ubuntu 18.04 或更高版本，并在终端窗口中运行以下命令：

```cpp
> sudo apt-get install build-essential git
```

这将确保您的操作系统具有编译和执行本示例中的示例所需的适当工具。完成后，打开一个新的终端。我们将使用这个终端来下载、编译和运行我们的示例。

# 如何做...

您需要执行以下步骤来尝试这个示例：

1.  从新的终端运行以下命令以下载源代码：

```cpp
> cd ~/
> git clone https://github.com/PacktPublishing/Advanced-CPP-CookBook.git
> cd Advanced-CPP-CookBook/chapter03
```

1.  编译源代码，请运行以下命令：

```cpp
> cmake .
> make recipe01_examples
```

1.  源代码编译完成后，您可以通过运行以下命令来执行本示例中的每个示例：

```cpp
> ./recipe01_example01
The answer is: 42

> ./recipe01_example02
The answer is: 42

> ./recipe01_example03
The answer is: 42

> ./recipe01_example04
The answer is: 42
```

在下一节中，我们将逐个介绍这些示例，并解释每个示例程序的作用以及它与本示例中所教授的课程的关系。

# 它是如何工作的...

在这个示例中，我们将探讨移动和复制之间的区别，以及这与大五的关系，大五是指所有类都应该显式定义的五个函数。首先，让我们先看一个简单的例子，一个在其构造函数中输出整数值的类：

```cpp
class the_answer
{
    int m_answer{42};

public:

    ~the_answer()
    {
        std::cout << "The answer is: " << m_answer << '\n';
    }
};
```

在前面的示例中，当类被销毁时，它将输出到`stdout`。该类还有一个在构造时初始化的整数成员变量。前面示例的问题在于，我们定义了类的析构函数，因此隐式的复制和移动语义被抑制了。

大五是以下函数，每个类都应该定义这些函数中的至少一个（也就是说，如果你定义了一个，你必须定义它们全部）：

```cpp
~the_answer() = default;

the_answer(the_answer &&) noexcept = default;
the_answer &operator=(the_answer &&) noexcept = default;

the_answer(const the_answer &) = default;
the_answer &operator=(const the_answer &) = default;
```

如上所示，Big Five 包括析构函数、移动构造函数、移动赋值运算符、复制构造函数和复制赋值运算符。这些类的作者不需要实现这些函数，而是应该至少*定义*这些函数，明确说明删除、复制和移动应该如何进行（如果有的话）。这确保了如果这些函数中的一个被定义，类的其余移动、复制和销毁语义是正确的，就像这个例子中一样：

```cpp
class the_answer
{
    int m_answer{42};

public:

    the_answer()
    {
        std::cout << "The answer is: " << m_answer << '\n';
    }

public:

    virtual ~the_answer() = default;

    the_answer(the_answer &&) noexcept = default;
    the_answer &operator=(the_answer &&) noexcept = default;

    the_answer(const the_answer &) = default;
    the_answer &operator=(const the_answer &) = default;
};
```

在前面的示例中，通过定义虚拟析构函数（意味着该类能够参与运行时多态），将类标记为`virtual`。不需要实现（通过将析构函数设置为`default`），但定义本身是显式的，告诉编译器我们希望该类支持虚拟函数。这告诉类的用户，可以使用该类的指针来删除从它派生的任何类的实例。它还告诉用户，继承将利用运行时多态而不是组合。该类还声明允许复制和移动。

让我们看另一个例子：

```cpp
class the_answer
{
    int m_answer{42};

public:

    the_answer()
    {
        std::cout << "The answer is: " << m_answer << '\n';
    }

public:

    ~the_answer() = default;

    the_answer(the_answer &&) noexcept = default;
    the_answer &operator=(the_answer &&) noexcept = default;

    the_answer(const the_answer &) = delete;
    the_answer &operator=(const the_answer &) = delete;
};
```

在前面的示例中，复制被明确删除（这与定义移动构造函数但未定义复制语义相同）。这定义了一个仅移动的类，这意味着该类只能被移动；它不能被复制。标准库中的一个这样的类的例子是`std::unique_ptr`。

下一个类实现了相反的功能：

```cpp
class the_answer
{
    int m_answer{42};

public:

    the_answer()
    {
        std::cout << "The answer is: " << m_answer << '\n';
    }

public:

    ~the_answer() = default;

    the_answer(the_answer &&) noexcept = delete;
    the_answer &operator=(the_answer &&) noexcept = delete;

    the_answer(const the_answer &) = default;
    the_answer &operator=(const the_answer &) = default;
};
```

在前面的示例中，我们明确定义了一个仅复制的类。

有许多不同的 Big Five 的组合。这个教程的重点是显示明确定义这五个函数可以确保类的作者对类本身的意图是明确的。这涉及到它应该如何操作以及用户应该如何使用类。明确确保类的作者并不打算获得一种类型的行为，而是因为编译器将根据编译器的实现和 C++规范的定义隐式构造类，而获得另一种类型的行为。

# 使您的类可移动

在 C++11 或更高版本中，对象可以被复制或移动，这可以用来决定对象的资源是如何管理的。复制和移动之间的主要区别很简单：复制会创建对象管理的资源的副本，而移动会将资源从一个对象转移到另一个对象。

在本教程中，我们将解释如何使一个类可移动，包括如何正确添加移动构造函数和移动赋值运算符。我们还将解释可移动类的一些微妙细节以及如何在代码中使用它们。这个教程很重要，因为在很多情况下，移动对象而不是复制对象可以提高程序的性能并减少内存消耗。然而，如果不正确使用可移动对象，可能会引入一些不稳定性。

# 准备工作

开始之前，请确保满足所有技术要求，包括安装 Ubuntu 18.04 或更高版本，并在终端窗口中运行以下命令：

```cpp
> sudo apt-get install build-essential git
```

这将确保您的操作系统具有编译和执行本教程中示例所需的适当工具。完成后，打开一个新的终端。我们将使用这个终端来下载、编译和运行我们的示例。

# 如何做...

您需要执行以下步骤来尝试这个教程：

1.  从新的终端中，运行以下命令来下载源代码：

```cpp
> cd ~/
> git clone https://github.com/PacktPublishing/Advanced-CPP-CookBook.git
> cd Advanced-CPP-CookBook/chapter03
```

1.  要编译源代码，请运行以下命令：

```cpp
> cmake .
> make recipe02_examples
```

1.  一旦源代码编译完成，您可以通过运行以下命令来执行本教程中的每个示例：

```cpp
> ./recipe02_example01
The answer is: 42
> ./recipe02_example02
The answer is: 42
The answer is: 42

The answer is: 42
```

在下一节中，我们将逐个介绍这些示例，并解释每个示例程序的作用以及它与本教程所教授的课程的关系。

# 工作原理...

在这个示例中，我们将学习如何使一个类可移动。首先，让我们来看一个基本的类定义：

```cpp
#include <iostream>

class the_answer
{
    int m_answer{42};

public:

    the_answer() = default;

public:

    ~the_answer()
    {
        std::cout << "The answer is: " << m_answer << '\n';
    }
};

int main(void)
{
    the_answer is;
    return 0;
}
```

在前面的例子中，我们创建了一个简单的类，它有一个私有的整数成员，被初始化。然后我们定义了一个默认构造函数和一个析构函数，当类的实例被销毁时，它会输出到`stdout`。默认情况下，这个类是可移动的，但移动操作模拟了一个复制（换句话说，这个简单的例子中移动和复制没有区别）。

要真正使这个类可移动，我们需要添加移动构造函数和移动赋值运算符，如下所示：

```cpp
the_answer(the_answer &&other) noexcept;
the_answer &operator=(the_answer &&other) noexcept;
```

一旦我们添加了这两个函数，我们就能够使用以下方法将我们的类从一个实例移动到另一个实例：

```cpp
instance2 = std::move(instance1);
```

为了支持这一点，在前面的类中，我们不仅添加了移动构造函数和赋值运算符，还实现了一个默认构造函数，为我们的示例类提供了一个有效的移动状态，如下所示：

```cpp
#include <iostream>

class the_answer
{
    int m_answer{};

public:

    the_answer() = default;

    explicit the_answer(int answer) :
        m_answer{answer}
    { }
```

如上所示，该类现在有一个默认构造函数和一个显式构造函数，它接受一个整数参数。默认构造函数初始化整数内存变量，表示我们的移动来源或无效状态：

```cpp
public:

    ~the_answer()
    {
        if (m_answer != 0) {
            std::cout << "The answer is: " << m_answer << '\n';
        }
    }
```

如前面的例子所示，当类被销毁时，我们输出整数成员变量的值，但在这种情况下，我们首先检查整数变量是否有效：

```cpp
    the_answer(the_answer &&other) noexcept
    {
        *this = std::move(other);
    }

    the_answer &operator=(the_answer &&other) noexcept
    {
        if (&other == this) {
            return *this;
        }

        m_answer = std::exchange(other.m_answer, 0);        
        return *this;
    }

    the_answer(const the_answer &) = default;
    the_answer &operator=(const the_answer &) = default;
};
```

最后，我们实现了移动构造函数和赋值运算符。移动构造函数简单地调用移动赋值运算符，以防止重复（因为它们执行相同的操作）。移动赋值运算符首先检查我们是否在将自己移动。这是因为这样做会导致损坏，因为用户期望类仍然包含一个有效的整数，但实际上，内部整数会无意中被设置为`0`。

然后我们交换整数值并将原始值设置为`0`。这是因为，再一次强调，移动不是复制。移动将值从一个实例转移到另一个实例。在这种情况下，被移动到的实例开始为`0`，并被赋予一个有效的整数，而被移出的实例开始有一个有效的整数，移动后被设置为`0`，导致只有`1`个实例包含一个有效的整数。

还应该注意，我们必须定义复制构造函数和赋值运算符。这是因为，默认情况下，如果你提供了移动构造函数和赋值运算符，C++会自动删除复制构造函数和赋值运算符，如果它们没有被显式定义的话。

在这个例子中，我们将比较移动和复制，因此我们定义了复制构造函数和赋值运算符，以确保它们不会被隐式删除。一般来说，最好的做法是为你定义的每个类定义析构函数、移动构造函数和赋值运算符，以及复制构造函数和赋值运算符。这确保了你编写的每个类的复制/移动语义都是明确和有意义的：

```cpp
int main(void)
{
    {
        the_answer is;
        the_answer is_42{42};
        is = is_42;
    }

    std::cout << '\n';

    {
        the_answer is{23};
        the_answer is_42{42};
        is = std::move(is_42);
    }

    return 0;
}
```

当执行上述代码时，我们得到了以下结果：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/bc7cc97b-8542-42e5-9ada-0634f0017fbc.png)

在我们的主函数中，我们运行了两个不同的测试：

+   第一个测试创建了我们类的两个实例，并将一个实例的内容复制到另一个实例。

+   第二个测试创建了我们类的两个实例，然后将一个实例的内容移动到另一个实例。

当执行这个例子时，我们看到第一个测试的输出被写了两次。这是因为我们的类的第一个实例得到了第二个实例的一个副本，而第二个实例有一个有效的整数值。第二个测试的输出只被写了一次，因为我们正在将一个实例的有效状态转移到另一个实例，导致在任何给定时刻只有一个实例具有有效状态。

这里有一些值得一提的例子：

+   移动构造函数和赋值运算符不应该抛出异常。具体来说，移动操作将一个类型的实例的有效状态转移到该类型的另一个实例。在任何时候，这个操作都不应该失败，因为没有状态被创建或销毁。它只是被转移。此外，往往很难*撤消*移动操作。因此，这些函数应该始终被标记为`noexcept`（参考[`github.com/isocpp/CppCoreGuidelines/blob/master/CppCoreGuidelines.md#Rc-move-noexcept`](https://github.com/isocpp/CppCoreGuidelines/blob/master/CppCoreGuidelines.md#Rc-move-noexcept)）。

+   移动构造函数和赋值运算符在其函数签名中不包括`const`类型，因为被移动的实例不能是`const`，因为其内部状态正在被转移，这暗示着写操作正在发生。更重要的是，如果将移动构造函数或赋值运算符标记为`const`，则可能会发生复制。

+   除非您打算创建一个副本，否则应该使用移动，特别是对于大型对象。就像将`const T&`作为函数参数传递以防止发生复制一样，当调用函数时，当资源被移动到另一个变量而不是被复制时，应该使用移动代替复制。

+   编译器在可能的情况下会自动生成移动操作而不是复制操作。例如，如果您在函数中创建一个对象，配置该对象，然后返回该对象，编译器将自动执行移动操作。

现在您知道如何使您的类可移动了，在下一个食谱中，我们将学习什么是只可移动类型，以及为什么您可能希望在应用程序中使用它们。

# 只可移动类型

在这个食谱中，我们将学习如何使一个类成为只可移动的。一个很好的例子是`std::unique_ptr`和`std::shared_ptr`之间的区别。

`std::unique_ptr`的目的是强制动态分配类型的单一所有者，而`std::shared_ptr`允许动态分配类型的多个所有者。两者都允许用户将指针类型的内容从一个实例移动到另一个实例，但只有`std::shared_ptr`允许用户复制指针（因为复制指针会创建多个所有者）。

在这个食谱中，我们将使用这两个类来展示如何制作一个只可移动的类，并展示为什么这种类型的类在 C++中被如此广泛地使用（因为大多数时候我们希望移动而不是复制）。

# 准备工作

开始之前，请确保满足所有技术要求，包括安装 Ubuntu 18.04 或更高版本，并在终端窗口中运行以下命令：

```cpp
> sudo apt-get install build-essential git
```

这将确保您的操作系统具有正确的工具来编译和执行本食谱中的示例。完成后，打开一个新的终端。我们将使用这个终端来下载、编译和运行我们的示例。

# 如何做...

您需要执行以下步骤来尝试这个食谱：

1.  从新的终端运行以下命令以下载源代码：

```cpp
> cd ~/
> git clone https://github.com/PacktPublishing/Advanced-CPP-CookBook.git
> cd Advanced-CPP-CookBook/chapter03
```

1.  要编译源代码，请运行以下命令：

```cpp
> cmake .
> make recipe03_examples
```

1.  一旦源代码编译完成，您可以通过运行以下命令来执行本食谱中的每个示例：

```cpp
> ./recipe03_example01
The answer is: 42

> ./recipe03_example03
count: 2
The answer is: 42
The answer is: 42

count: 1
The answer is: 42
```

在下一节中，我们将逐个介绍每个示例，并解释每个示例程序的作用以及它与本食谱中所教授的课程的关系。

# 工作原理...

只可移动类是一种可以移动但不能复制的类。为了探索这种类型的类，让我们在以下示例中包装`std::unique_ptr`，它本身是一个只可移动的类：

```cpp
class the_answer
{
    std::unique_ptr<int> m_answer;

public:

    explicit the_answer(int answer) :
        m_answer{std::make_unique<int>(answer)}
    { }

    ~the_answer()
    {
        if (m_answer) {
            std::cout << "The answer is: " << *m_answer << '\n';
        }
    }

public:

    the_answer(the_answer &&other) noexcept
    {
        *this = std::move(other);
    }

    the_answer &operator=(the_answer &&other) noexcept
    {
        m_answer = std::move(other.m_answer);
        return *this;
    }
};
```

前面的类将`std::unique_ptr`作为成员变量存储，并在构造时用整数值实例化内存变量。在销毁时，类会检查`std::unique_ptr`是否有效，如果有效，则将值输出到`stdout`。

乍一看，我们可能会想知道为什么我们必须检查 `std::unique_ptr` 的有效性，因为 `std::unique_ptr` 总是被构造。`std::unique_ptr` 可能变得无效的原因是在移动期间。由于我们正在创建一个只能移动的类（而不是一个不可复制、不可移动的类），我们实现了移动构造函数和移动赋值运算符，它们移动 `std::unique_ptr`。`std::unique_ptr` 在移动时将其内部指针的内容从一个类转移到另一个类，导致该类从存储无效指针（即 `nullptr`）移动。换句话说，即使这个类不能被空构造，如果它被移动，它仍然可以存储 `nullptr`，就像下面的例子一样：

```cpp
int main(void)
{
    the_answer is_42{42};
    the_answer is = std::move(is_42);

    return 0;
}
```

正如前面的例子所示，只有一个类输出到 `stdout`，因为只有一个实例是有效的。与 `std::unique_ptr` 一样，只能移动的类确保你总是有一个资源被创建的总数与实际发生的实例化总数之间的 1:1 关系。

需要注意的是，由于我们使用了 `std::unique_ptr`，我们的类无论我们是否喜欢，都变成了一个只能移动的类。例如，尝试添加复制构造函数或复制赋值运算符以启用复制功能将导致编译错误：

```cpp
the_answer(const the_answer &) = default;
the_answer &operator=(const the_answer &) = default;
```

换句话说，每个包含只能移动的类作为成员的类也会成为只能移动的类。尽管这可能看起来不太理想，但你首先必须问自己：你真的需要一个可复制的类吗？很可能答案是否定的。实际上，在大多数情况下，即使在 C++11 之前，我们使用的大多数类（如果不是全部）都应该是只能移动的。当一个类应该被移动而被复制时，会导致资源浪费、损坏等问题，这也是为什么在规范中添加了移动语义的原因之一。移动语义允许我们定义我们希望分配的资源如何处理，并且它为我们提供了一种在编译时强制执行所需语义的方法。

你可能会想知道前面的例子如何转换以允许复制。以下示例利用了 shared pointer 来实现这一点：

```cpp
#include <memory>
#include <iostream>

class the_answer
{
    std::shared_ptr<int> m_answer;

public:

    the_answer() = default;

    explicit the_answer(int answer) :
        m_answer{std::make_shared<int>(answer)}
    { }

    ~the_answer()
    {
        if (m_answer) {
            std::cout << "The answer is: " << *m_answer << '\n';
        }
    }

    auto use_count()
    { return m_answer.use_count(); }
```

前面的类使用了 `std::shared_ptr` 而不是 `std::unique_ptr`。在内部，`std::shared_ptr` 跟踪被创建的副本数量，并且只有在总副本数为 `0` 时才删除它存储的指针。实际上，你可以使用 `use_count()` 函数查询总副本数。

接下来，我们定义移动构造函数，移动赋值运算符，复制构造函数和复制赋值运算符，如下所示：

```cpp
public:

    the_answer(the_answer &&other) noexcept
    {
        *this = std::move(other);
    }

    the_answer &operator=(the_answer &&other) noexcept
    {
        m_answer = std::move(other.m_answer);
        return *this;
    }

    the_answer(const the_answer &other)
    {
        *this = other;
    }

    the_answer &operator=(const the_answer &other)
    {
        m_answer = other.m_answer;
        return *this;
    }
};
```

这些定义也可以使用 `=` 默认语法来编写，因为这些实现是相同的。最后，我们使用以下方式测试这个类：

```cpp
int main(void)
{
    {
        the_answer is_42{42};
        the_answer is = is_42;
        std::cout << "count: " << is.use_count() << '\n';
    }

    std::cout << '\n';

    {
        the_answer is_42{42};
        the_answer is = std::move(is_42);
        std::cout << "count: " << is.use_count() << '\n';
    }

    return 0;
}
```

如果我们执行前面的代码，我们会得到以下结果：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/80128ca4-0b35-4b29-b649-c871a64b025f.png)

在前面的测试中，我们首先创建了一个类的副本，并输出了总副本数，以查看实际上创建了两个副本。第二个测试执行了 `std::move()` 而不是复制，结果只创建了一个预期中的副本。

# 实现 noexcept 移动构造函数

在本示例中，我们将学习如何确保移动构造函数和移动赋值运算符永远不会抛出异常。C++ 规范并不阻止移动构造函数抛出异常（因为确定这样的要求实际上太难以强制执行，即使在标准库中也存在太多合法的例子）。然而，在大多数情况下，确保不会抛出异常应该是可能的。具体来说，移动通常不会创建资源，而是转移资源，因此应该可能提供强异常保证。一个创建资源的好例子是 `std::list`，即使在移动时也必须提供有效的 `end()` 迭代器。

# 准备工作

开始之前，请确保满足所有技术要求，包括安装 Ubuntu 18.04 或更高版本，并在终端窗口中运行以下命令：

```cpp
> sudo apt-get install build-essential git
```

这将确保您的操作系统具有编译和执行本文示例所需的适当工具。完成后，打开一个新的终端。我们将使用这个终端来下载、编译和运行我们的示例。

# 如何做...

您需要执行以下步骤来尝试这个示例：

1.  从新的终端中运行以下命令来下载源代码：

```cpp
> cd ~/
> git clone https://github.com/PacktPublishing/Advanced-CPP-CookBook.git
> cd Advanced-CPP-CookBook/chapter03
```

1.  要编译源代码，请运行以下命令：

```cpp
> cmake .
> make recipe04_examples
```

1.  一旦源代码编译完成，您可以通过运行以下命令来执行本文中每个示例：

```cpp
> ./recipe04_example01
failed to move

The answer is: 42
```

在下一节中，我们将逐个介绍每个示例，并解释每个示例程序的作用以及它与本文所教授的课程的关系。

# 工作原理...

如前所述，移动不应该抛出异常，以确保强异常保证（即，移动对象的行为不会破坏对象），在大多数情况下，这是可能的，因为移动（不像复制）不会创建资源，而是转移资源。确保您的移动构造函数和移动赋值操作符不会抛出异常的最佳方法是只使用`std::move()`来转移成员变量，就像以下示例中所示的那样：

```cpp
m_answer = std::move(other.m_answer);
```

假设您移动的成员变量不会抛出异常，那么您的类也不会。使用这种简单的技术将确保您的移动构造函数和操作符永远不会抛出异常。但如果这个操作不能使用怎么办？让我们通过以下示例来探讨这个问题：

```cpp
#include <vector>
#include <iostream>

class the_answer
{
    std::vector<int> m_answer;

public:

    the_answer() = default;

    explicit the_answer(int answer) :
        m_answer{{answer}}
    { }

    ~the_answer()
    {
        if (!m_answer.empty()) {
            std::cout << "The answer is: " << m_answer.at(0) << '\n';
        }
    }
```

在前面的示例中，我们创建了一个具有向量作为成员变量的类。向量可以通过默认方式初始化为空，或者可以初始化为单个元素。在销毁时，如果向量有值，我们将该值输出到`stdout`。我们实现`move`构造函数和操作符如下：

```cpp
public:

    the_answer(the_answer &&other) noexcept
    {
        *this = std::move(other);
    }

    the_answer &operator=(the_answer &&other) noexcept
    {
        if (&other == this) {
            return *this;
        }

        try {
            m_answer.emplace(m_answer.begin(), other.m_answer.at(0));
            other.m_answer.erase(other.m_answer.begin());
        }
        catch(...) {
            std::cout << "failed to move\n";
        }

        return *this;
    }
};
```

如图所示，移动操作符将单个元素从一个实例转移到另一个实例（这不是实现移动的最佳方式，但这种实现可以演示要点而不会过于复杂）。如果向量为空，这个操作将抛出异常，就像下面的例子一样：

```cpp
int main(void)
{
    {
        the_answer is_42{};
        the_answer is_what{};

        is_what = std::move(is_42);
    }

    std::cout << '\n';

    {
        the_answer is_42{42};
        the_answer is_what{};

        is_what = std::move(is_42);
    }

    return 0;
}
```

最后，我们尝试在两个不同的测试中移动这个类的一个实例。在第一个测试中，两个实例都是默认构造的，这导致空的类，而第二个测试构造了一个带有单个元素的向量，这导致有效的移动。在这种情况下，我们能够防止移动抛出异常，但应该注意的是，结果类实际上并没有执行移动，导致两个对象都不包含所需的状态。这就是为什么移动构造函数不应该抛出异常。即使我们没有捕获异常，也很难断言抛出异常后程序的状态。移动是否发生？每个实例处于什么状态？在大多数情况下，这种类型的错误应该导致调用`std::terminate()`，因为程序进入了一个损坏的状态。

复制不同，因为原始类保持不变。复制是无效的，程序员可以优雅地处理这种情况，因为被复制的实例的原始状态不受影响（因此我们将其标记为`const`）。

然而，由于被移动的实例是可写的，两个实例都处于损坏状态，没有很好的方法来知道如何处理程序的继续运行，因为我们不知道原始实例是否处于可以正确处理的状态。

# 学会谨慎使用 const&&

在这个食谱中，我们将学习为什么移动构造函数或操作符不应标记为`const`（以及为什么复制构造函数/操作符总是标记为`const`）。这很重要，因为它涉及到移动和复制之间的区别。C++中的移动语义是其最强大的特性之一，了解为什么它如此重要以及它实际上在做什么对于编写良好的 C++代码至关重要。

# 准备工作

开始之前，请确保满足所有技术要求，包括安装 Ubuntu 18.04 或更高版本，并在终端窗口中运行以下命令：

```cpp
> sudo apt-get install build-essential git
```

这将确保您的操作系统具有适当的工具来编译和执行本食谱中的示例。完成后，打开一个新的终端。我们将使用这个终端来下载、编译和运行我们的示例。

# 如何做…

您需要执行以下步骤来尝试这个食谱：

1.  从新的终端中运行以下命令来下载源代码：

```cpp
> cd ~/
> git clone https://github.com/PacktPublishing/Advanced-CPP-CookBook.git
> cd Advanced-CPP-CookBook/chapter03
```

1.  要编译源代码，请运行以下命令：

```cpp
> cmake .
> make recipe05_examples
```

1.  一旦源代码编译完成，您可以通过运行以下命令来执行本食谱中的每个示例：

```cpp
> ./recipe05_example01
copy
```

在下一节中，我们将逐个介绍这些示例，并解释每个示例程序的作用以及它与本食谱中所教授的课程的关系。

# 工作原理…

在这个食谱中，我们将学习为什么`const&&`构造函数或操作符没有意义，并将导致意外行为。移动会转移资源，这就是为什么它标记为非`const`。这是因为转移假定两个实例都被写入（一个实例接收资源，而另一个实例被取走资源）。复制会创建资源，这就是为什么它们并不总是标记为`noexcept`（创建资源绝对可能会抛出异常），并且它们被标记为`const`（因为原始实例被复制，而不是修改）。`const&&`构造函数声称是一个不转移的移动，这必须是一个复制（如果您没有写入原始实例，您不是在移动—您在复制），就像这个例子中一样：

```cpp
#include <iostream>

class copy_or_move
{
public:

    copy_or_move() = default;

public:

    copy_or_move(copy_or_move &&other) noexcept
    {
        *this = std::move(other);
    }

    copy_or_move &operator=(copy_or_move &&other) noexcept
    {
        std::cout << "move\n";
        return *this;
    }

    copy_or_move(const copy_or_move &other)
    {
        *this = other;
    }

    copy_or_move &operator=(const copy_or_move &other)
    {
        std::cout << "copy\n";
        return *this;
    }
};

int main(void)
{
    const copy_or_move test1;
    copy_or_move test2;

    test2 = std::move(test1);
    return 0;
}
```

在前面的示例中，我们创建了一个实现默认移动和复制构造函数/操作符的类。唯一的区别是我们向`stdout`添加了输出，告诉我们是执行了复制还是移动。

然后我们创建了两个类的实例，实例被移动，从被标记为`const`。然后我们执行移动，输出的是一个复制。这是因为即使我们要求移动，编译器也使用了复制。我们可以实现一个`const &&`移动构造函数/操作符，但没有办法将移动写成移动，因为我们标记了被移动的对象为`const`，所以我们无法获取它的资源。这样的移动实际上会被实现为一个复制，与编译器自动为我们做的没有区别。

在下一个食谱中，我们将学习如何向我们的成员函数添加限定符。

# 引用限定成员函数

在这个食谱中，我们将学习什么是引用限定的成员函数。尽管 C++语言的这一方面使用和理解较少，但它很重要，因为它为程序员提供了根据类在调用函数时处于 l-value 还是 r-value 状态来处理资源操作的能力。

# 准备工作

开始之前，请确保满足所有技术要求，包括安装 Ubuntu 18.04 或更高版本，并在终端窗口中运行以下命令：

```cpp
> sudo apt-get install build-essential git
```

这将确保您的操作系统具有适当的工具来编译和执行本食谱中的示例。完成后，打开一个新的终端。我们将使用这个终端来下载、编译和运行我们的示例。

# 如何做…

您需要执行以下步骤来尝试这个食谱：

1.  从新的终端中运行以下命令来下载源代码：

```cpp
> cd ~/
> git clone https://github.com/PacktPublishing/Advanced-CPP-CookBook.git
> cd Advanced-CPP-CookBook/chapter03
```

1.  要编译源代码，请运行以下命令：

```cpp
> cmake .
> make recipe06_examples
```

1.  源代码编译后，您可以通过运行以下命令来执行本文中每个示例：

```cpp
> ./recipe06_example01
the answer is: 42
the answer is not: 0
the answer is not: 0
```

在下一节中，我们将逐个介绍这些示例，并解释每个示例程序的作用以及它与本文所教授的课程的关系。

# 工作原理...

在这个例子中，我们将看看什么是引用限定的成员函数。为了解释什么是引用限定的成员函数，让我们看下面的例子：

```cpp
#include <iostream>

class the_answer
{
public:

 ~the_answer() = default;

 void foo() &
 {
 std::cout << "the answer is: 42\n";
 }

 void foo() &&
 {
 std::cout << "the answer is not: 0\n";
 }

public:

 the_answer(the_answer &&other) noexcept = default;
 the_answer &operator=(the_answer &&other) noexcept = default;

 the_answer(const the_answer &other) = default;
 the_answer &operator=(const the_answer &other) = default;
};
```

在这个例子中，我们实现了一个 `foo()` 函数，但是我们有两个不同的版本。第一个版本在末尾有 `&`，而第二个版本在末尾有 `&&`。`foo()` 函数的执行取决于实例是 l-value 还是 r-value，就像下面的例子中一样：

```cpp
int main(void)
{
    the_answer is;

    is.foo();
    std::move(is).foo();
    the_answer{}.foo();
}
```

执行时会得到以下结果：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/19571c4b-ebb1-4680-a183-82571ec2416c.png)

如前面的例子所示，`foo()` 的第一次执行是一个 l-value，因为执行了 `foo()` 的 l-value 版本（即末尾带有 `&` 的函数）。`foo()` 的最后两次执行是 r-value，因为执行了 `foo()` 的 r-value 版本。

参考限定成员函数可用于确保函数仅在正确的上下文中调用。使用这些类型的函数的另一个原因是确保只有当存在 l-value 或 r-value 引用时才调用该函数。

例如，您可能不希望允许 `foo()` 作为 r-value 被调用，因为这种类型的调用并不能确保类的实例在调用本身之外实际上具有生命周期，就像前面的例子中所示的那样。

在下一个示例中，我们将学习如何创建一个既不能移动也不能复制的类，并解释为什么要这样做。

# 探索不能移动或复制的对象

在本文中，我们将学习如何创建一个既不能移动也不能复制的对象，以及为什么要创建这样一个类。复制一个类需要能够复制类的内容，在某些情况下可能是不可能的（例如，复制内存池并不简单）。移动一个类假设该类被允许存在于潜在的无效状态（例如，`std::unique_ptr` 移动时会取得一个 `nullptr` 值，这是无效的）。这样的情况也可能是不希望发生的（现在必须检查有效性）。一个既不能移动也不能复制的类可以克服这些问题。

# 准备工作

开始之前，请确保满足所有技术要求，包括安装 Ubuntu 18.04 或更高版本，并在终端窗口中运行以下命令：

```cpp
> sudo apt-get install build-essential git
```

这将确保您的操作系统具有正确的工具来编译和执行本文中的示例。完成后，打开一个新的终端。我们将使用这个终端来下载、编译和运行我们的示例。

# 操作步骤...

您需要执行以下步骤来尝试这个示例：

1.  从新的终端中运行以下命令以下载源代码：

```cpp
> cd ~/
> git clone https://github.com/PacktPublishing/Advanced-CPP-CookBook.git
> cd Advanced-CPP-CookBook/chapter03
```

1.  要编译源代码，请运行以下命令：

```cpp
> cmake .
> make recipe07_examples
```

1.  源代码编译后，您可以通过运行以下命令来执行本文中每个示例：

```cpp
> ./recipe07_example01
The answer is: 42
Segmentation fault (core dumped)
```

在下一节中，我们将逐个介绍这些示例，并解释每个示例程序的作用以及它与本文所教授的课程的关系。

# 工作原理...

仅移动类可以阻止类被复制，在某些情况下，这可能是性能的提升。仅移动类还确保了创建的资源与分配的资源之间的 1:1 关系，因为副本是不存在的。然而，移动类可能导致类变为无效，就像这个例子中一样：

```cpp
#include <iostream>

class the_answer
{
    std::unique_ptr<int> m_answer;

public:

    explicit the_answer(int answer) :
        m_answer{std::make_unique<int>(answer)}
    { }

    ~the_answer()
    {
        std::cout << "The answer is: " << *m_answer << '\n';
    }

public:

    the_answer(the_answer &&other) noexcept = default;
    the_answer &operator=(the_answer &&other) noexcept = default;
};

int main(void)
{
    the_answer is_42{42};
    the_answer is_what{42};

    is_what = std::move(is_42);
    return 0;
}
```

如果我们运行上述代码，我们会得到以下结果：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/f6a0a4c9-5084-4fae-8a30-69fb5fff3ce5.png)

在上面的例子中，我们创建了一个可以移动的类，它存储了`std::unique_ptr`。在类的析构函数中，我们对类进行了解引用并输出了它的值。我们没有检查`std::unique_ptr`的有效性，因为我们编写了一个强制有效`std::unique_ptr`的构造函数，忘记了移动可能会撤消这种显式的有效性。结果是，当执行移动操作时，我们会得到一个分段错误。

为了克服这一点，我们需要提醒自己做出了以下假设：

```cpp
class the_answer
{
 std::unique_ptr<int> m_answer;

public:

 explicit the_answer(int answer) :
 m_answer{std::make_unique<int>(answer)}
 { }

 ~the_answer()
 {
 std::cout << "The answer is: " << *m_answer << '\n';
 }

public:

 the_answer(the_answer &&other) noexcept = delete;
 the_answer &operator=(the_answer &&other) noexcept = delete;

 the_answer(const the_answer &other) = delete;
 the_answer &operator=(const the_answer &other) = delete;
};
```

前面的类明确删除了复制和移动操作，这是我们期望的意图。现在，如果我们意外地移动这个类，我们会得到以下结果：

```cpp
/home/user/book/chapter03/recipe07.cpp: In function ‘int main()’:
/home/user/book/chapter03/recipe07.cpp:106:30: error: use of deleted function ‘the_answer& the_answer::operator=(the_answer&&)’
is_what = std::move(is_42);
^
/home/user/book/chapter03/recipe07.cpp:95:17: note: declared here
the_answer &operator=(the_answer &&other) noexcept = delete;
^~~~~~~~
```

这个错误告诉我们，假设这个类是有效的，因此不支持移动。我们要么需要正确地支持移动（这意味着我们必须维护对无效的`std::unique_ptr`的支持），要么我们需要删除`move`操作。正如所示，一个不能被移动或复制的类可以确保我们的代码按预期工作，为编译器提供一种机制，当我们对类做了我们不打算做的事情时，它会警告我们。


# 第四章：使用模板进行通用编程

在本章中，我们将学习高级模板编程技术。这些技术包括根据提供的类型来改变模板类的实现方式，如何处理不同类型的参数以及如何正确地转发它们，如何在运行时和编译时优化代码，以及如何使用 C++17 中添加的一些新特性。这很重要，因为它可以更好地理解模板编程的工作原理，以及如何确保模板的性能符合预期。

经常情况下，我们编写模板代码时假设它以某种方式执行，而实际上它以另一种方式执行，可能会生成不可靠的代码、意外的性能损失，或者两者兼而有之。本章将解释如何避免这些问题，并为编写正确的通用程序奠定基础。

本章中的示例如下：

+   实现 SFINAE

+   学习完美转发

+   使用`if constexpr`

+   使用元组处理参数包

+   使用特性来改变模板实现的行为

+   学习如何实现`template<auto>`

+   使用显式模板声明

# 技术要求

要编译和运行本章中的示例，您必须具有管理权限的计算机，运行 Ubuntu 18.04，并具有正常的互联网连接。在运行这些示例之前，安装以下内容：

```cpp
> sudo apt-get install build-essential git cmake
```

如果这安装在 Ubuntu 18.04 以外的任何操作系统上，则需要 GCC 7.4 或更高版本和 CMake 3.6 或更高版本。

# 实现 SFINAE

在这个示例中，我们将学习如何使用**Substitution Failure Is Not An Error**（**SFINAE**）。这个示例很重要，因为我们经常创建模板时没有确保传递给模板的类型是我们期望的。这可能导致意外行为、性能不佳，甚至是错误的、不可靠的代码。

SFINAE 允许我们明确指定我们在模板中期望的类型。它还为我们提供了一种根据我们提供的类型来改变模板行为的方法。对于一些人来说，SFINAE 的问题在于这个概念很难理解。我们在本示例中的目标是揭开 SFINAE 的神秘面纱，并展示您如何在自己的代码中使用它。

# 准备工作

开始之前，请确保满足所有技术要求，包括安装 Ubuntu 18.04 或更高版本，并在终端窗口中运行以下命令：

```cpp
> sudo apt-get install build-essential git cmake
```

这将确保您的操作系统具有编译和执行本示例中示例的必要工具。完成后，打开一个新的终端。我们将使用这个终端来下载、编译和运行我们的示例。

# 操作步骤...

要尝试这个示例，您需要执行以下步骤：

1.  从新的终端中运行以下命令以下载源代码：

```cpp
> cd ~/
> git clone https://github.com/PacktPublishing/Advanced-CPP-CookBook.git
> cd Advanced-CPP-CookBook/chapter04
```

1.  要编译源代码，请运行以下命令：

```cpp
> cmake .
> make recipe01_examples
```

1.  编译源代码后，您可以通过运行以下命令来执行本示例中的每个示例：

```cpp
> ./recipe01_example01
The answer is: 23
The answer is: 42

> ./recipe01_example02
The answer is: 42

> ./recipe01_example03
The answer is: 42

> ./recipe01_example04
The answer is: 42

> ./recipe01_example05
The answer is: 42
The answer is: 42
The answer is: 42.12345678
```

在下一节中，我们将逐个介绍这些示例，并解释每个示例程序的作用以及它与本示例中所教授的课程的关系。

# 工作原理...

在本示例中，您将学习如何在自己的代码中使用 SFINAE。首先，我们必须先了解 SFINAE 是什么，以及标准库如何使用它来实现`type`特性。如果不了解`type`特性是如何实现的，就很难理解如何使用它们。

首先，理解 SFINAE 最重要的事情是理解它的名字，即*substitution failure is not an error*。这意味着当模板类型被替换时，如果发生失败，编译器将*不会*生成错误。例如，我们可以编写以下内容：

```cpp
#include <iostream>

struct the_answer
{
    using type = unsigned;
};

template<typename T>
void foo(typename T::type t)
{
    std::cout << "The answer is not: " << t << '\n';
}

template<typename T>
void foo(T t)
{
    std::cout << "The answer is: " << t << '\n';
}

int main(void)
{
    foo<the_answer>(23);
    foo<int>(42);

    return 0;
}
```

每个示例的输出如下所示：

```cpp
The answer is: 23
The answer is: 42
```

在这个例子中，我们创建了`foo()`函数的两个版本。第一个版本接受具有我们用来创建函数参数的`type`别名的`T`类型。第二个版本只接受`T`类型本身。然后我们使用`foo()`函数的两个版本，一个使用整数，另一个使用定义了`type`别名的结构。

从前面的例子中可以得出的结论是，当我们调用`foo<int>()`版本的`foo()`函数时，编译器在尝试将`int`类型与具有`type`别名的`foo()`函数的版本进行匹配时不会生成错误。这就是 SFINAE。它只是说，当编译器尝试获取给定类型并将其与模板匹配时，如果发生失败，编译器不会生成错误。唯一会发生错误的情况是，如果编译器找不到合适的替换。例如，如果我们注释掉`foo()`的第二个版本会发生什么？让我们看看：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/84d28ad2-c0bd-49a0-879d-ad42f5add912.png)

从前面的错误输出中可以看出，编译器甚至说错误是一个替换错误。我们提供的模板不是基于提供的类型的有效候选。

从这个例子中得出的另一个重要结论是，编译器能够根据提供的类型在两个不同版本的`foo()`函数之间进行选择。我们可以利用这一点。具体来说，这给了我们根据提供的类型做不同事情的能力。我们所需要的只是一种方法来编写我们的`foo()`函数，以便我们可以根据我们提供的类型启用/禁用模板的不同版本。

这就是`std::enable_if`发挥作用的地方。`std::enable_if`将 SFINAE 的思想推向了下一步，允许我们在其参数为 true 时定义一个类型。否则，它将生成一个替换错误，故意迫使编译器选择模板的不同版本。`std::enable_if`的定义如下：

```cpp
template<bool B, class T = void>
struct enable_if {};

template<class T>
struct enable_if<true, T> { typedef T type; };
```

首先定义了一个结构，它接受`bool B`和一个默认为`void`的`T`类型。然后定义了这个`struct`类型的一个特化，当`bool`为 true 时。具体来说，当`bool`值为`true`时，返回提供的类型，这个类型默认为`void`。为了看到这是如何使用的，让我们看一个例子：

```cpp
#include <iostream>
#include <type_traits>

template<typename T>
constexpr auto is_int()
{ 
    return false; 
}

template<>
constexpr auto is_int<int>()
{ 
    return true; 
}

template<
    typename T,
    std::enable_if_t<is_int<T>(), int> = 0
    >
void the_answer(T is)
{
    std::cout << "The answer is: " << is << '\n';
}

int main(void)
{
    the_answer(42);
    return 0;
}
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/395bc1d6-02a2-4609-be80-8855f53d6acc.png)

在这个例子中，我们创建了一个名为`is_int()`的函数，它总是返回`false`。然后我们为`int`创建了这个函数的模板特化，返回`true`。接下来，我们创建了一个接受任何类型的函数，但我们在使用我们的`is_int()`函数的模板定义中添加了`std::enable_if_t`（添加的`_t`部分是 C++17 中为`::type`添加的简写）。如果提供的`T`类型是`int`，我们的`is_int()`函数将返回`true`。

`std::enable_if`默认情况下什么也不做。但如果它为`true`，它会返回一个`type`别名，在前面的例子中，就是我们作为`std::enable_if`第二个参数传递的`int`类型。这意味着如果`std::enable_if`为`true`，它将返回一个`int`类型。然后我们将这个`int`类型设置为`0`，这是一个有效的操作。这不会产生失败；我们的模板函数成为一个有效的替换，因此被使用。总之，如果`T`是`int`类型，`std::enable_if`会变成一个`int`类型本身，然后我们将其设置为`0`，这样就可以编译而不会出现问题。如果我们的`T`类型不是`int`，`std::enable_if`会变成什么也没有。试图将什么也没有设置为`0`会导致编译错误，但由于这是 SFINAE，编译器错误不会变成更多的替换错误。

让我们看看错误的情况。如果我们将`42`设置为`42.0`，这是一个`double`，而不是`int`，我们会得到以下结果：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/3eadc479-fa00-4c25-9a68-b82cb13ee914.png)

正如您从上面的错误中看到的，编译器说在`enable_if`中没有名为`type`的类型。如果您查看`std::enable_if`的定义，这是预期的，因为如果为 false，`std::enable_if`不会执行任何操作。它只有在为 true 时才创建一个名为`type`的类型。

为了更好地理解这是如何工作的，让我们看另一个例子：

```cpp
#include <iostream>
#include <type_traits>

template<
    typename T,
    std::enable_if_t<std::is_integral_v<T>>* = nullptr
    >
void the_answer(T is)
{
    std::cout << "The answer is: " << is << '\n';
}

int main(void)
{
    the_answer(42);
    return 0;
}
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/cb55d047-89b4-4e40-815a-273456762831.png)

在上面的示例中，我们使用了`std::is_integral_v`，它与我们的`is_int()`函数做了相同的事情，不同之处在于它是由标准库提供的，并且可以处理 CV 类型。事实上，标准库有一个巨大的不同版本的这些函数列表，包括不同的类型、继承属性、CV 属性等等。如果您需要检查任何类型的`type`属性，很有可能标准库有一个`std:is_xxx`函数可以使用。

上面的例子几乎与我们之前的例子相同，不同之处在于我们在`std::enable_if`方法中不返回`int`。相反，我们使用`* = nullptr`。这是因为`std::enable_if`默认返回`void`。`*`字符将这个 void 转换为一个 void 指针，然后我们将其设置为`nullptr`。

在下一个例子中，我们展示了另一个变化：

```cpp
#include <iostream>
#include <type_traits>

template<typename T>
std::enable_if_t<std::is_integral_v<T>>
the_answer(T is)
{
    std::cout << "The answer is: " << is << '\n';
}

int main(void)
{
    the_answer(42);
    return 0;
}

```

输出如下：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/5ca6a189-e687-45a2-a8cd-422d3e2f274e.png)

在这个例子中，我们的函数的`void`是由`std::enable_if`创建的。如果`T`不是整数，就不会返回`void`，我们会看到这个错误（而不是首先编译和允许我们执行它）：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/d7ec86d0-edec-409d-8dd5-76b3abfa3978.png)

总之，`std::enable_if`将创建一个名为`type`的类型，该类型基于您提供的类型。默认情况下，这是`void`，但您可以传入任何您想要的类型。这种功能不仅可以用于强制执行模板的类型，还可以根据我们提供的类型定义不同的函数，就像在这个示例中所示的那样：

```cpp
#include <iostream>
#include <type_traits>
#include <iomanip>

template<
    typename T,
    std::enable_if_t<std::is_integral_v<T>>* = nullptr
    >
void the_answer(T is)
{
    std::cout << "The answer is: " << is << '\n';
}

template<
    typename T,
    std::enable_if_t<std::is_floating_point_v<T>>* = nullptr
    >
void the_answer(T is)
{
    std::cout << std::setprecision(10);
    std::cout << "The answer is: " << is << '\n';
}

int main(void)
{
    the_answer(42);
    the_answer(42U);
    the_answer(42.12345678);

    return 0;
}

```

上面代码的输出如下：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/1c12f216-9fc9-4b34-9868-9ccf45ae4fb7.png)

就像本教程中的第一个例子一样，我们创建了相同函数的两个不同版本。SFINAE 允许编译器根据提供的类型选择最合适的版本。

# 学习完美转发

在这个教程中，我们将学习如何使用完美转发。这个教程很重要，因为在编写模板时，通常我们将模板参数传递给其他函数。如果我们不使用完美转发，我们可能会无意中将 r 值引用转换为 l 值引用，导致潜在的复制发生，而不是移动，在某些情况下，这可能是不太理想的。完美转发还为编译器提供了一些提示，可以用来改进函数内联和展开。

# 准备工作

在开始之前，请确保满足所有技术要求，包括安装 Ubuntu 18.04 或更高版本，并在终端窗口中运行以下命令：

```cpp
> sudo apt-get install build-essential git cmake
```

这将确保您的操作系统具有编译和执行本教程中示例所需的适当工具。完成后，打开一个新的终端。我们将使用这个终端来下载、编译和运行我们的示例。

# 如何做...

您需要执行以下步骤来尝试这个教程：

1.  从一个新的终端，运行以下命令来下载源代码：

```cpp
> cd ~/
> git clone https://github.com/PacktPublishing/Advanced-CPP-CookBook.git
> cd Advanced-CPP-CookBook/chapter04
```

1.  要编译源代码，请运行以下命令：

```cpp
> cmake .
> make recipe02_examples
```

1.  一旦源代码编译完成，您可以通过运行以下命令来执行本教程中的每个示例：

```cpp
> ./recipe02_example01
l-value
l-value

> ./recipe02_example02
l-value
r-value

> ./recipe02_example03
l-value: 42
r-value: 42
```

在下一节中，我们将逐个介绍这些示例，并解释每个示例程序的作用以及它与本教程中所教授的课程的关系。

# 工作原理...

在这个示例中，我们将学习如何使用完美转发来确保当我们在模板中传递参数时（也就是转发我们的参数），我们以不会抹去 r-value 特性的方式进行。为了更好地理解这个问题，让我们看下面的例子：

```cpp
#include <iostream>

struct the_answer
{ };

void foo2(const the_answer &is)
{
    std::cout << "l-value\n";
}

void foo2(the_answer &&is)
{
    std::cout << "r-value\n";
}

template<typename T>
void foo1(T &&t)
{
    foo2(t);
}

int main(void)
{
    the_answer is;
    foo1(is);
    foo1(the_answer());

    return 0;
}

```

输出如下：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/eb4f4cb0-e924-4b6e-af1a-617c8e3183b0.png)

在前面的示例中，我们有`foo()`函数的两个不同版本：一个接受 l-value 引用，一个接受 r-value 引用。然后我们从模板函数中调用`foo()`。这个模板函数接受一个转发引用（也称为通用引用），它是一个 r-value 引用，配合`auto`或模板函数。最后，从我们的主函数中，我们调用我们的模板来看哪个`foo()`函数被调用。第一次调用我们的模板时，我们传入一个 l-value。由于我们得到了一个 l-value，通用引用变成了 l-value，并且调用了我们的`foo()`函数的 l-value 版本。问题是，第二次调用我们的模板函数时，我们给它一个 r-value，但它调用了我们的`foo()`函数的 l-value 版本，即使它得到了一个 r-value。

这里的常见错误是，即使模板函数接受一个通用引用，我们也有一个接受 r-value 的`foo()`函数的版本，我们假设会调用这个`foo()`函数。Scott Meyers 在他关于通用引用的许多讲座中很好地解释了这一点。问题在于，一旦使用通用引用，它就变成了 l-value。传递`names`参数的行为，意味着它必须是 l-value。它迫使编译器将其转换为 l-value，因为它看到你在使用它，即使你只是在传递参数。值得注意的是，我们的示例在优化时无法编译，因为编译器可以安全地确定变量没有被使用，从而可以优化掉 l-value。

为了防止这个问题，我们需要告诉编译器我们希望转发参数。通常，我们会使用`std::move()`来实现。问题是，如果我们最初得到的是 l-value，我们不能使用`std::move()`，因为那样会将 l-value 转换为 r-value。这就是标准库有`std::forward()`的原因，它是使用以下方式实现的：

```cpp
static_cast<T&&>(t)
```

`std::forward()`的作用如下：将参数强制转换回其原始引用类型。这告诉编译器明确地将参数视为 r-value，如果它最初是 r-value，就像以下示例中一样：

```cpp
#include <iostream>

struct the_answer
{ };

void foo2(const the_answer &is)
{
    std::cout << "l-value\n";
}

void foo2(the_answer &&is)
{
    std::cout << "r-value\n";
}

template<typename T>
void foo1(T &&t)
{
    foo2(std::forward<T>(t));
}

int main(void)
{
    the_answer is;
    foo1(is);
    foo1(the_answer());

    return 0;
}

```

输出如下：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/c64d9b68-b5d8-4ce2-ba02-17195ee8906d.png)

前面的示例与第一个示例相同，唯一的区别是我们在模板函数中使用`std::forward()`传递参数。这一次，当我们用 r-value 调用我们的模板函数时，它调用我们的`foo()`函数的 r-value 版本。这被称为**完美转发**。它确保我们在传递参数时保持 CV 属性和 l-/r-value 属性。值得注意的是，完美转发只在使用模板函数或`auto`时有效。这意味着完美转发通常只在编写包装器时有用。标准库包装器的一个很好的例子是`std::make_unique()`。

`std::make_unique()`这样的包装器的一个问题是，你可能不知道需要传递多少个参数。也就是说，你可能最终需要在你的包装器中使用可变模板参数。完美转发通过以下方式支持这一点：

```cpp
#include <iostream>

struct the_answer
{ };

void foo2(const the_answer &is, int i)
{
    std::cout << "l-value: " << i << '\n';
}

void foo2(the_answer &&is, int i)
{
    std::cout << "r-value: " << i << '\n';
}

template<typename... Args>
void foo1(Args &&...args)
{
    foo2(std::forward<Args>(args)...);
}

int main(void)
{
    the_answer is;

    foo1(is, 42);
    foo1(the_answer(), 42);

    return 0;
}
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/6a2956d6-ac8c-4113-b411-eb131555a556.png)

前面的示例之所以有效，是因为传递给我们的`foo()`函数的可变模板参数被替换为逗号分隔的完美转发列表。

# 使用 if constexpr

在这个教程中，我们将学习如何使用 C++17 中的一个新特性`constexpr if`。这个教程很重要，因为它将教会你如何创建在运行时评估的`if`语句。具体来说，这意味着分支逻辑是在编译时选择的，而不是在运行时。这允许您在编译时更改函数的行为，而不会牺牲性能，这是过去只能通过宏来实现的，而在模板编程中并不实用，正如我们将展示的那样。

# 准备工作

开始之前，请确保满足所有技术要求，包括安装 Ubuntu 18.04 或更高版本，并在终端窗口中运行以下命令：

```cpp
> sudo apt-get install build-essential git
```

这将确保您的操作系统具有编译和执行本教程中示例所需的适当工具。完成后，打开一个新的终端。我们将使用这个终端来下载、编译和运行我们的示例。

# 操作步骤...

您需要执行以下步骤来尝试这个教程：

1.  从新的终端运行以下命令来下载源代码：

```cpp
> cd ~/
> git clone https://github.com/PacktPublishing/Advanced-CPP-CookBook.git
> cd Advanced-CPP-CookBook/chapter04
```

1.  要编译源代码，请运行以下命令：

```cpp
> cmake .
> make recipe03_examples
```

1.  源代码编译完成后，您可以通过运行以下命令来执行本教程中的每个示例：

```cpp
> ./recipe03_example01
The answer is: 42

> ./recipe03_example02
The answer is: 42
The answer is: 42.12345678
```

在下一节中，我们将逐个介绍这些示例，并解释每个示例程序的作用，以及它与本教程所教授的课程的关系。

# 工作原理...

有时，我们希望改变程序的行为，但我们创建的代码始终是常量，这意味着编译器能够确定分支本身的值，就像这个示例中所示的那样：

```cpp
if (!NDEBUG) {}
```

这是一个常见的`if`语句，在很多代码中都有，包括标准库。如果启用了调试，这段代码将评估为`true`。我们可以通过向代码添加调试语句来使用它，这些语句可以被关闭。编译器足够聪明，能够看到`NDEBUG`是`true`还是`false`，并且会添加代码或完全删除代码。换句话说，编译器可以进行简单的优化，减小代码的大小，并且在运行时永远不会改变这个`if`语句的值。问题是，这个技巧依赖于编译器的智能。逻辑的移除是隐式信任的，这经常导致对编译器正在做什么的假设。C++17 添加了一个`constexpr if`语句，允许我们明确地进行。它允许我们告诉编译器：我提供的语句应该在编译时而不是在运行时进行评估。这真正强大的地方在于，当这个假设不成立时，我们会在编译时获得编译时错误，这意味着我们以前隐式信任编译器执行的优化，现在可以在编译时进行验证，如果假设是错误的，我们会得到通知，以便我们可以解决问题，就像这个示例中所示的那样：

```cpp
#include <iostream>

constexpr auto answer = 42;

int main(void)
{
    if constexpr (answer == 42) {
        std::cout << "The answer is: " << answer << '\n';
    }
    else {
        std::cout << "The answer is not: " << answer << '\n';
    }

    return 0;
}

```

输出如下：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/cf8bb6b4-07e7-4b3e-a97e-3a558cfc3533.png)

在前面的示例中，我们创建了`constexpr`并在编译时而不是在运行时进行了评估。如果我们将`constexpr`更改为实际变量，`constexpr if`将导致以下错误：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/9474112b-7528-4649-b754-1e6702247c6c.png)

然后我们可以在我们的模板函数中使用它来根据我们给定的类型改变我们的模板函数的行为，就像这个示例中所示的那样：

```cpp
#include <iostream>
#include <iomanip>

template<typename T>
constexpr void foo(T &&t)
{
    if constexpr (std::is_floating_point_v<T>) {
        std::cout << std::setprecision(10);
    }

    std::cout << "The answer is: " << std::forward<T>(t) << '\n';
}

int main(void)
{
    foo(42);
    foo(42.12345678);
    return 0;
}
```

在前面的示例中，我们使用`std::is_floating_point_v`类型特征来确定我们提供的类型是否是浮点类型。如果类型不是浮点类型，这将返回`constexpr false`，编译器可以优化掉。由于我们使用了`constexpr if`，我们可以确保我们的`if`语句实际上是`constexpr`而不是运行时条件。

# 使用元组处理参数包

在本教程中，我们将学习如何使用`std::tuple`处理可变参数列表。这很重要，因为可变参数列表是用于包装函数的，包装器不知道传递给它的参数，而是将这些参数转发给了解这些参数的东西。然而，也有一些用例，你会关心传递的参数，并且必须有一种方法来处理这些参数。本教程将演示如何做到这一点，包括如何处理任意数量的参数。

# 准备工作

开始之前，请确保满足所有技术要求，包括安装 Ubuntu 18.04 或更高版本，并在终端窗口中运行以下命令：

```cpp
> sudo apt-get install build-essential git cmake
```

这将确保您的操作系统具有正确的工具来编译和执行本教程中的示例。完成后，打开一个新的终端。我们将使用这个终端来下载、编译和运行我们的示例。

# 操作步骤

您需要执行以下步骤来尝试本教程：

1.  从新的终端中运行以下命令以下载源代码：

```cpp
> cd ~/
> git clone https://github.com/PacktPublishing/Advanced-CPP-CookBook.git
> cd Advanced-CPP-CookBook/chapter04
```

1.  要编译源代码，请运行以下命令：

```cpp
> cmake .
> make recipe04_examples
```

1.  源代码编译完成后，可以通过运行以下命令执行本教程中的每个示例：

```cpp
> ./recipe04_example01

> ./recipe04_example02
the answer is: 42

> ./recipe04_example03
The answer is: 42

> ./recipe04_example04
2
2

> ./recipe04_example05
The answer is: 42
```

在下一节中，我们将逐个介绍这些示例，并解释每个示例程序的作用以及它与本教程中所教授的内容的关系。

# 工作原理

可变模板使程序员能够定义模板函数，而无需定义所有参数。这些在包装函数中被广泛使用，因为它们防止包装器必须了解函数的参数，如下例所示：

```cpp
#include <iostream>

template<typename... Args>
void foo(Args &&...args)
{ }

int main(void)
{
    foo("The answer is: ", 42);
    return 0;
}
```

如前面的示例所示，我们创建了一个可以接受任意数量参数的`foo`函数。在这个例子中，我们使用了通用引用符号`Args &&...args`，它确保了 CV 限定符和 l-/r-值性得到保留，这意味着我们可以使用`std::forward()`将可变参数列表传递给任何其他函数，尽可能少地降低性能损失。诸如`std::make_unique()`之类的函数大量使用可变参数。

然而，有时您可能希望访问提供的参数列表中的一个参数。为此，我们可以使用`std::tuple`。这是一个接受可变数量参数并提供`std::get()`函数从`std::tuple`获取任何数据的数据结构，如下例所示：

```cpp
#include <tuple>
#include <iostream>

int main(void)
{
    std::tuple t("the answer is: ", 42);
    std::cout << std::get<0>(t) << std::get<1>(t) << '\n';
    return 0;
}
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/e3147713-d2d1-4d27-b867-d95407e67851.png)

在前面的示例中，我们创建了`std::tuple`，然后使用`std::get()`函数将`std::tuple`的内容输出到`stdout`。如果尝试访问超出范围的数据，编译器将在编译时知道，并给出类似于以下的错误：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/f0d35dc0-05d0-44ae-9202-1dbc5da6503c.png)

使用`std::tuple`，我们可以按以下方式访问可变参数列表中的数据：

```cpp
#include <tuple>
#include <iostream>

template<typename... Args>
void foo(Args &&...args)
{
    std::tuple t(std::forward<Args>(args)...);
    std::cout << std::get<0>(t) << std::get<1>(t) << '\n';
}

int main(void)
{
    foo("The answer is: ", 42);
    return 0;
}
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/fac54cfd-01a0-4fc8-a4e1-80bb81c1fd5f.png)

在前面的示例中，我们创建了一个带有可变参数列表的函数。然后，我们使用`std::forward()`传递此列表以保留 l-/r-值性到`std::tuple`。最后，我们使用`std::tuple`来访问这些参数。如果我们不使用`std::forward()`，我们将得到传递给`std::tuple`的数据的 l-value 版本。

上面例子的明显问题是，我们在`std::tuple`中硬编码了`0`和`1`索引。可变参数不是运行时的、动态的参数数组。相反，它们是一种说“我不关心我收到的参数”的方式，这就是为什么它们通常被包装器使用的原因。包装器是包装一些关心参数的东西。在`std::make_unique()`的情况下，该函数正在创建`std::unique_ptr`。为此，`std::make_unique()`将为您分配`std::unique_ptr`，使用可变参数列表来初始化新分配的类型，然后将指针提供给`std::unique_ptr`，就像这个例子中所示的那样：

```cpp
template<
    typename T, 
    typename... Args
    >
void make_unique(Args &&...args)
{
    return unique_ptr<T>(new T(std::forward<Args>(args)...));
}
```

包装器不关心传递的参数。`T`的构造函数关心。如果你尝试访问可变参数，你就是在说“我关心这些参数”，在这种情况下，如果你关心，你必须对传递的参数的布局有一些想法。

有一些技巧可以让你处理未知数量的参数，然而。尝试这样做的最大问题是处理可变参数的库设施最好在运行时使用，这在大多数情况下并不起作用，就像这个例子中所示的那样：

```cpp
#include <tuple>
#include <iostream>

template<typename... Args>
void foo(Args &&...args)
{
    std::cout << sizeof...(Args) << '\n';
    std::cout << std::tuple_size_v<std::tuple<Args...>> << '\n';
}

int main(void)
{
    foo("The answer is: ", 42);
    return 0;
}

```

输出如下：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/3e437b68-faa5-4a2b-a2e5-1353d8935542.png)

在上面的例子中，我们试图获取可变参数列表中参数的总大小。我们可以使用`sizeof()`函数的可变版本，也可以使用`std::tuple_size`特性来实现这一点。问题是，这并不能在编译时帮助我们，因为我们无法使用这个大小信息来循环遍历参数（因为编译时逻辑没有`for`循环）。

为了克服这一点，我们可以使用一种称为编译时递归的技巧。这个技巧使用模板来创建一个递归模板函数，它将循环遍历可变参数列表中的所有参数。看看这个例子：

```cpp
#include <tuple>
#include <iostream>

template<
    std::size_t I = 0,
    typename ... Args,
    typename FUNCTION
    >
constexpr void
for_each(const std::tuple<Args...> &t, FUNCTION &&func)
{
    if constexpr (I < sizeof...(Args)) {
        func(std::get<I>(t));
        for_each<I + 1>(t, std::forward<FUNCTION>(func));
    }
}
```

我们从一个执行所有魔术的模板函数开始。第一个模板参数是`I`，它是一个从`0`开始的整数。接下来是一个可变模板参数，最后是一个函数类型。我们的模板函数接受我们希望迭代的`std::tuple`（在这种情况下，我们展示了一个常量版本，但我们也可以重载它以提供一个非常量版本），以及我们希望对`std::tuple`中的每个元素调用的函数。换句话说，这个函数将循环遍历`std::tuple`中的每个元素，并对每个迭代的元素调用提供的函数，就像我们在其他语言或 C++库中运行时使用的`for_each()`一样。

在这个函数内部，我们检查是否已经达到了元组的总大小。如果没有，我们获取元组中当前值为`I`的元素，将其传递给提供的函数，然后再次调用我们的`for_each()`函数，传入`I++`。要使用这个`for_each()`函数，我们可以这样做：

```cpp
template<typename... Args>
void foo(Args &&...args)
{
    std::tuple t(std::forward<Args>(args)...);
    for_each(t, [](const auto &arg) {
        std::cout << arg;
    });
}
```

在这里，我们得到了一个可变参数列表，我们希望迭代这个列表并将每个参数输出到`stdout`。为此，我们创建了`std::tuple`，就像以前一样，但这次，我们将`std::tuple`传递给我们的`for_each()`函数：

```cpp
int main(void)
{
    foo("The answer is: ", 42);
    std::cout << '\n';

    return 0;
}
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/d6d45daa-3d12-43cd-b947-93a9aa3990f1.png)

就像我们在之前的例子中所做的那样，我们调用我们的`foo`函数，并传入一些文本，我们希望将其输出到`stdout`，从而演示如何使用`std:tuple`处理可变函数参数，即使我们不知道将收到的参数的总数。

# 使用类型特征来重载函数和对象

C++11 创建时，C++需要处理的一个问题是如何处理`std::vector`的调整大小，它能够接受任何类型，包括从`std::move()`抛出异常的类型。调整大小时，会创建新的内存，并将旧向量的元素移动到新向量。这很好地工作，因为如果`std::move()`不能抛出异常，那么一旦调整大小函数开始将元素从一个数组移动到另一个数组，就不会发生错误。

然而，如果`std::move()`可能会抛出异常，那么在循环进行到一半时可能会发生错误。然而，`resize()`函数无法将旧内存恢复正常，因为尝试移动到旧内存也可能会引发异常。在这种情况下，`resize()`执行复制而不是移动。复制确保旧内存有每个对象的有效副本；因此，如果抛出异常，原始数组保持不变，并且可以根据需要抛出异常。

在本示例中，我们将探讨如何通过更改模板类的行为来实现这一点。

# 准备工作

开始之前，请确保满足所有技术要求，包括安装 Ubuntu 18.04 或更高版本，并在终端窗口中运行以下命令：

```cpp
> sudo apt-get install build-essential git cmake
```

这将确保您的操作系统具有编译和执行本示例的适当工具。完成后，打开一个新的终端。我们将使用此终端来下载、编译和运行示例。

# 如何做...

要尝试此示例，需要执行以下步骤：

1.  从新的终端运行以下命令以下载源代码：

```cpp
> cd ~/
> git clone https://github.com/PacktPublishing/Advanced-CPP-CookBook.git
> cd Advanced-CPP-CookBook/chapter04
```

1.  要编译源代码，请运行以下命令：

```cpp
> cmake .
> make recipe05_examples
```

1.  编译源代码后，可以通过运行以下命令来执行本示例中的每个示例：

```cpp
> ./recipe05_example01
noexcept: r-value
can throw: l-value

> ./recipe05_example02
move
move
move
move
move
--------------
copy
copy
copy
copy
copy
```

在下一节中，我们将逐步介绍每个示例，并解释每个示例程序的作用以及它与本示例中所教授的课程的关系。

# 工作原理...

C++添加了一个名为`std::move_if_noexcept()`的函数。如果移动构造函数/赋值运算符不能抛出异常，此函数将转换为右值，否则将转换为左值。例如，看一下以下代码：

```cpp
#include <iostream>

struct the_answer_noexcept
{
    the_answer_noexcept() = default;

    the_answer_noexcept(const the_answer_noexcept &is) noexcept
    {
        std::cout << "l-value\n";
    }

    the_answer_noexcept(the_answer_noexcept &&is) noexcept
    {
        std::cout << "r-value\n";
    }
};
```

要尝试这样做，我们将执行以下步骤：

1.  首先，我们将创建一个类，该类具有一个不能抛出异常的移动/复制构造函数：

```cpp
struct the_answer_can_throw
{
    the_answer_can_throw() = default;

    the_answer_can_throw(const the_answer_can_throw &is)
    {
        std::cout << "l-value\n";
    }

    the_answer_can_throw(the_answer_can_throw &&is)
    {
        std::cout << "r-value\n";
    }
};
```

1.  接下来，我们将提供一个具有可能抛出异常的移动/复制构造函数的类。最后，让我们使用`std::move_if_noexcept()`来查看在尝试移动这些先前类的实例时是发生移动还是复制：

```cpp
int main(void)
{
    the_answer_noexcept is1;
    the_answer_can_throw is2;

    std::cout << "noexcept: ";
    auto is3 = std::move_if_noexcept(is1);

    std::cout << "can throw: ";
    auto is4 = std::move_if_noexcept(is2);

    return 0;
}

```

上述代码的输出如下：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/0308a282-75f7-42fd-82e6-4debaf2bd0d2.png)

如前面的示例所示，在一种情况下，调用移动构造函数，在另一种情况下，调用复制构造函数，这取决于类型在执行移动时是否会抛出异常。

1.  现在，让我们创建一个简单的模拟向量，并添加一个调整大小函数，以演示如何使用特性更改我们的`template`类的行为：

```cpp
#include <memory>
#include <iostream>
#include <stdexcept>

template<typename T>
class mock_vector
{
public:
    using size_type = std::size_t;

    mock_vector(size_type s) :
        m_size{s},
        m_buffer{std::make_unique<T[]>(m_size)}
    { }

    void resize(size_type size)
        noexcept(std::is_nothrow_move_constructible_v<T>)
    {
        auto tmp = std::make_unique<T[]>(size);

        for (size_type i = 0; i < m_size; i++) {
            tmp[i] = std::move_if_noexcept(m_buffer[i]);
        }

        m_size = size;
        m_buffer = std::move(tmp);
    }

private:
    size_type m_size{};
    std::unique_ptr<T[]> m_buffer{};
};
```

我们的模拟向量有一个内部缓冲区和一个大小。当创建向量时，我们使用给定的大小分配内部缓冲区。然后我们提供一个`resize()`函数，可以用来调整内部缓冲区的大小。我们首先创建新的内部缓冲区，然后循环遍历每个元素，并将一个缓冲区的元素复制到另一个缓冲区。如果`T`不能抛出异常，在循环执行过程中不会触发任何异常，此时新缓冲区将是有效的。如果`T`可以抛出异常，将会发生复制。如果发生异常，旧缓冲区尚未被新缓冲区替换。相反，新缓冲区将被删除，以及所有被复制的元素。

要使用这个，让我们创建一个在移动构造函数/赋值运算符中可能抛出异常的类：

```cpp
struct suboptimal
{
    suboptimal() = default;

    suboptimal(suboptimal &&other)
    {
        *this = std::move(other);
    }

    suboptimal &operator=(suboptimal &&)
    {
        std::cout << "move\n";
        return *this;
    }

    suboptimal(const suboptimal &other)
    {
        *this = other;
    }

    suboptimal &operator=(const suboptimal &)
    {
        std::cout << "copy\n";
        return *this;
    }
};
```

让我们还添加一个在移动构造函数/赋值运算符中不能抛出异常的类：

```cpp
struct optimal
{
    optimal() = default;

    optimal(optimal &&other) noexcept
    {
        *this = std::move(other);
    }

    optimal &operator=(optimal &&) noexcept
    {
        std::cout << "move\n";
        return *this;
    }

    optimal(const optimal &other)
    {
        *this = other;
    }

    optimal &operator=(const optimal &)
    {
        std::cout << "copy\n";
        return *this;
    }
};
```

最后，我们将使用这两个类创建一个向量，并尝试调整其大小：

```cpp
int main(void)
{
    mock_vector<optimal> d1(5);
    mock_vector<suboptimal> d2(5);

    d1.resize(10);
    std::cout << "--------------\n";
    d2.resize(10);

    return 0;
}

```

前面的代码的输出如下：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/e9bee1c2-cc4a-4a6b-8b40-d2f08e9c28b8.png)

如前面的示例所示，当我们尝试调整类的大小时，如果移动不能抛出异常，则执行移动操作，否则执行复制操作。换句话说，类的行为取决于`T`类型的特征。

# 学习如何实现 template<auto>

C++很长时间以来就具有创建模板的能力，这使程序员可以根据类型创建类和函数的通用实现。但是，您也可以提供非类型参数。

在 C++17 中，您现在可以使用`auto`来提供通用的非类型模板参数。在本示例中，我们将探讨如何使用此功能。这很重要，因为它允许您在代码中创建更通用的模板。

# 准备工作

在开始之前，请确保满足所有技术要求，包括安装 Ubuntu 18.04 或更高版本，并在终端窗口中运行以下命令：

```cpp
> sudo apt-get install build-essential git cmake
```

这将确保您的操作系统具有适当的工具来编译和执行本示例中的示例。完成后，打开一个新的终端。我们将使用此终端来下载、编译和运行示例。

# 操作步骤...

您需要执行以下步骤来尝试此示例：

1.  从新的终端运行以下命令以下载源代码：

```cpp
> cd ~/
> git clone https://github.com/PacktPublishing/Advanced-CPP-CookBook.git
> cd Advanced-CPP-CookBook/chapter04
```

1.  要编译源代码，请运行以下命令：

```cpp
> cmake .
> make recipe06_examples
```

1.  源代码编译完成后，可以通过运行以下命令来执行本文中的每个示例：

```cpp
> ./recipe06_example01
The answer is: 42
> ./recipe06_example02
The answer is: 42
The answer is: 42
> ./recipe06_example03
The answer is: 42
```

在下一节中，我们将逐个介绍每个示例，并解释每个示例程序的作用以及它与本示例中所教授的课程的关系。

# 工作原理...

在 C++17 之前，您可以在模板中提供非类型模板参数，但是您必须在定义中声明变量类型，就像本示例中所示的那样：

```cpp
#include <iostream>

template<int answer>
void foo()
{
    std::cout << "The answer is: " << answer << '\n';
}

int main(void)
{
    foo<42>();
    return 0;
}

```

输出如下：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/e5ae3433-362c-4d0d-a865-298472d67d5c.png)

在前面的示例中，我们创建了一个`int`类型的模板参数变量，并将此变量的值输出到`stdout`。在 C++17 中，我们现在可以这样做：

```cpp
#include <iostream>

template<auto answer>
void foo()
{
    std::cout << "The answer is: " << answer << '\n';
}

int main(void)
{
    foo<42>();
    return 0;
}
```

以下是输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/dee00755-5e4b-4fe9-8067-fe5306327929.png)

如前所示，我们现在可以使用`auto`而不是`int`。这使我们能够创建一个可以接受多个非类型模板参数的函数。我们还可以使用类型特征来确定允许使用哪些非类型参数，就像本示例中所示的那样：

```cpp
#include <iostream>
#include <type_traits>

template<
    auto answer,
 std::enable_if_t<std::is_integral_v<decltype(answer)>, int> = 0
 >
void foo()
{
    std::cout << "The answer is: " << answer << '\n';
}

int main(void)
{
    foo<42>();
    return 0;
}
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/08ad857b-3e01-41e9-885d-ceea78bc65f1.png)

在前面的示例中，我们的模板非类型参数只能是整数类型。

# 使用显式模板声明

在本示例中，我们将探讨如何通过创建显式模板声明来加快模板类的编译速度。这很重要，因为模板需要编译器根据需要创建类的实例。在某些情况下，显式模板声明可能为程序员提供一种加快编译速度的方法，通过缓存最有可能使用的模板类型，从而避免包含整个模板定义的需要。

# 准备工作

在开始之前，请确保满足所有技术要求，包括安装 Ubuntu 18.04 或更高版本，并在终端窗口中运行以下命令：

```cpp
> sudo apt-get install build-essential git cmake
```

这将确保您的操作系统具有适当的工具来编译和执行本示例中的示例。完成后，打开一个新的终端。我们将使用此终端来下载、编译和运行示例。

# 操作步骤...

您需要执行以下步骤来尝试此示例：

1.  从新的终端运行以下命令以下载源代码：

```cpp
> cd ~/
> git clone https://github.com/PacktPublishing/Advanced-CPP-CookBook.git
> cd Advanced-CPP-CookBook/chapter04
```

1.  要编译源代码，请运行以下命令：

```cpp
> cmake .
> make recipe07_examples
```

1.  源代码编译完成后，可以通过运行以下命令来执行本文中的每个示例：

```cpp
> ./recipe07_example01 
The answer is: 42
The answer is: 42
The answer is: 42.1
> ./recipe07_example02 
The answer is: 4
```

在下一节中，我们将逐个介绍这些例子，并解释每个例子程序的作用以及它与本教程中所教授的课程的关系。

# 工作原理...

每当编译器看到使用给定类型的模板类时，它会隐式地创建该类型的一个版本。然而，这可能会发生多次，降低编译器的速度。然而，如果预先知道要使用的类型，这个问题可以通过显式模板特化来解决。看看这个例子：

```cpp
#include <iostream>

template<typename T>
class the_answer
{
public:
    the_answer(T t)
    {
        std::cout << "The answer is: " << t << '\n';
    }
};
```

之前，我们创建了一个简单的结构，在构造过程中输出到`stdout`。通常，一旦看到类的第一个特化，编译器就会创建这个类。然而，我们可以执行以下操作：

```cpp
template class the_answer<int>;
template class the_answer<unsigned>;
template class the_answer<double>;
```

这类似于一个类原型，它明确地创建了我们期望使用的特化。这些必须在它们在代码中使用之前声明（这意味着它们通常在模板的定义之后声明）；然而，一旦声明了，它们可以如下使用：

```cpp
int main(void)
{
    the_answer{42};
    the_answer{42U};
    the_answer{42.1};

    return 0;
}
```

代码的输出如下：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/cdc10992-381a-45a6-80a6-aff500c8753f.png)

在前面的示例中，我们可以像平常一样创建模板的实例，但是在这种情况下，我们可以加快编译器在大量使用这个类的情况下的速度。这是因为在源代码中，我们不需要包含模板的实现。为了证明这一点，让我们看另一个更复杂的例子。在一个头文件（名为`recipe07.h`）中，我们将使用以下内容创建我们的模板：

```cpp
template<typename T>
struct the_answer
{
    T m_answer;

    the_answer(T t);
    void print();
};
```

如你所见，我们有一个没有提供函数实现的`template`类。然后，我们将提供这个模板的实现，使用以下内容在它自己的源文件中：

```cpp
#include <iostream>
#include "recipe07.h"

template<typename T>
the_answer<T>::the_answer(T t) :
    m_answer{t}
{ }

template<typename T>
void the_answer<T>::print()
{
    std::cout << "The answer is: " << m_answer << '\n';
}

template class the_answer<int>;
```

正如你在前面的例子中所看到的，我们添加了显式的模板声明。这确保我们生成了我们期望的类的实现。编译器将为我们期望的类显式地创建实例，就像我们通常编写的任何其他源代码一样。不同之处在于，我们可以明确地为任何类型定义这个类。最后，我们将调用这段代码如下：

```cpp
#include "recipe07.h"

int main(void)
{
    the_answer is{42};
    is.print();

    return 0;
}
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/b30b50ca-8f48-4791-80c2-83b5886b15f3.png)

如你所见，我们可以以与使用显式类型定义的类相同的方式调用我们的类，而不是使用一个小型的头文件，它没有完整的实现，从而使编译器加快速度。
