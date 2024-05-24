# C++ 高级编程秘籍（六）

> 原文：[`annas-archive.org/md5/24e080e694c59b3f8e0220d0902724b0`](https://annas-archive.org/md5/24e080e694c59b3f8e0220d0902724b0)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十二章：仔细观察类型推断

在本章中，您将学习 C++中类型推断的所有细节，包括 C++17 中的一些新添加。本章非常重要，因为它将教会您编译器将如何尝试自动推断类型信息。如果不了解 C++中类型推断的工作原理，可能会创建出现预期之外的代码，特别是在使用`auto`和模板编程时。从本章中获得的知识将为您提供在自己的应用程序中正确利用类型推断的技能。

本章中的示例如下：

+   使用 auto 和类型推断

+   学习`decltype`类型推断规则的工作方式

+   使用模板函数类型推断

+   在 C++17 中利用模板类类型推断

+   在 C++17 中使用用户定义的类型推断

# 技术要求

要编译和运行本章中的示例，您必须具有对运行 Ubuntu 18.04 的计算机的管理访问权限，并具有功能正常的互联网连接。在运行这些示例之前，您必须安装以下内容：

```cpp
> sudo apt-get install build-essential git cmake 
```

如果此软件安装在 Ubuntu 18.04 以外的任何操作系统上，则需要 GCC 7.4 或更高版本和 CMake 3.6 或更高版本。

本章的代码文件可以在[`github.com/PacktPublishing/Advanced-CPP-CookBook/tree/master/chapter12`](https://github.com/PacktPublishing/Advanced-CPP-CookBook/tree/master/chapter12)找到。

# 使用 auto 和类型推断

在本示例中，我们将学习编译器如何处理`auto`关键字，特别是类型推断。本示例很重要，因为`auto`的处理方式并不直观，如果不清楚`auto`的工作原理，您的代码可能会包含错误和性能问题。本示例中包括`auto`的一般描述、类型推断、转发（或通用）引用、l 值和 r 值。

# 准备工作

开始之前，请确保满足所有技术要求，包括安装 Ubuntu 18.04 或更高版本，并在终端窗口中运行以下命令：

```cpp
> sudo apt-get install build-essential git cmake
```

这将确保您的操作系统具有编译和执行本示例中的示例所需的适当工具。完成后，打开一个新的终端。我们将使用此终端来下载、编译和运行我们的示例。

# 如何做...

按照以下步骤尝试本示例：

1.  从新的终端运行以下命令以下载源代码：

```cpp
> cd ~/
> git clone https://github.com/PacktPublishing/Advanced-CPP-CookBook.git
> cd Advanced-CPP-CookBook/chapter12
```

1.  要编译源代码，请运行以下命令：

```cpp
> cmake .
> make recipe01_examples
```

1.  编译源代码后，可以通过运行以下命令执行本示例中的每个示例：

```cpp
> ./recipe01_example01
i1 = int
i2 = int
i3 = std::initializer_list<int>
i4 = std::initializer_list<int>
c = char
r = int

> ./recipe01_example02
i1 = int
i2 = const int
i3 = volatile int
i4 = const volatile int

> ./recipe01_example03
i1 = int
i2 = int&
a1 = int
a2 = int
a3 = int
a4 = int&
i3 = int&&
a5 = int&
a6 = int&
a7 = int&
a8 = int&
a9 = int&&
a10 = int&&

> ./recipe01_example04
i1 = int
i2 = const int&
i3 = const int&&
```

在下一节中，我们将逐个介绍这些示例，并解释每个示例程序的作用及其与本示例中所教授的课程的关系。

# 它是如何工作的...

`auto`关键字是 C++11 中添加的一个特性，称为**占位类型说明符**。换句话说，`auto`关键字用于告诉编译器变量的类型将从其初始化程序中推断出来。与其他使用占位类型的语言不同，`auto`关键字仍然必须遵守 C++的严格类型系统，这意味着`auto`不应与`std::any`混淆。

例如，使用`std::any`可以实现以下功能：

```cpp
std::any i = 42;
i = "The answer is: 42";
```

以下是不允许使用`auto`的情况：

```cpp
auto i = 42;
i = "The answer is: 42";
```

在第一个示例中，我们定义了`std::any`，它存储一个整数。然后，我们用 C 风格的字符串替换`std::any`中的整数。就`auto`而言，这是不可能的，因为一旦编译器在初始化时推断出变量的类型，类型就不能改变（与 C++中的任何其他变量一样）。

让我们看一个使用`auto`初始化变量的简单示例：

```cpp
int main(void)
{
    auto i1 = 42;
    auto i2{42};
    auto i3 = {42};
    auto i4 = {4, 8, 15, 16, 23, 42};

    show_type(i1);
    show_type(i2);
    show_type(i3);
    show_type(i4);

    char c = 0;
    auto r = c + 42;

    show_type(c);
    show_type(r);
}
```

运行此示例将产生以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/2a971f5a-11f4-4d46-a47e-a62cfab04dbe.png)

如前面的代码所示，我们使用`auto`创建了四个变量，对它们进行初始化，然后使用一个名为`show_type()`的函数返回变量类型的输出。

有关`show_type()`函数的更多信息，请参阅本章附带的代码（在阅读完整个章节后，这个函数的细节会更容易理解）。

我们示例中的第一个变量`i1`被推断为整数。这是因为 C++中的数值类型总是被推断为整数，我们在示例中的`c`和`r`变量中也看到了这一点。原因是编译器允许在编译期间增加任何变量的大小，这意味着当编译器看到`c + 42`时，它首先将`c`的值存储在一个临时整数中，然后完成加法。

在我们的示例中，第二个变量`i2`也被推断为整数，因为`{}`符号是 C++中任何类型的另一种初始化形式，具有一些额外的规则。具体来说，`i3`和`i4`被推断为整数的`std::initializer_list`，因为最后两个使用了`= {}`符号，根据 C++17 的规定，它们总是被推断为`std::initializer_list`。值得注意的是，这假设编译器遵守规范，在这个特定的例子中并不总是如此，这就是为什么像 AUTOSAR 这样的关键系统规范不允许这种类型的初始化。

`auto`关键字也可以与 CV 限定符（即`const`/`volatile`）结合使用。看看这个例子：

```cpp
int main(void)
{
    auto i1 = 42;
    const auto i2 = 42;
    volatile auto i3 = 42;
    const volatile auto i4 = 42;

    show_type(i1);
    show_type(i2);
    show_type(i3);
    show_type(i4);
}
```

前面的例子产生了以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/a4a02c94-dc87-4f79-b3bf-e2e8118cf556.png)

如前面的截图所示，每个变量都带有适当的 CV 限定符。

到目前为止，在每个示例中，我们可以简单地用`int`替换`auto`，什么都不会改变，这就引出了一个问题，为什么要首先使用`auto`？有几个原因：

+   使用除`auto`之外的东西意味着你的代码很可能会两次指定变量的类型。例如，`int *ptr = new int;`表示`ptr`变量是整数两次：一次在变量声明中，一次在变量的初始化中。

+   C++中的一些类型非常长（例如迭代器），使用`auto`可以极大地简化代码的冗长，例如`auto i = v.begin()`。

+   在编写模板代码时，`auto`需要正确处理引用类型，比如转发引用。

处理引用是使用`auto`变得混乱的地方，也是大多数人犯错误的地方。为了更好地解释，让我们看看以下例子：

```cpp
int main(void)
{
    int i = 42;

    int i1 = i;
    int &i2 = i;

    show_type(i1);
    show_type(i2);

    auto a1 = i1;
    auto a2 = i2;

    show_type(a1);
    show_type(a2);
}
```

这导致了以下输出：

```cpp
i1 = int
i2 = int&
a1 = int
a2 = int
```

如前面的示例所示，我们创建了一个整数`i`，并将其设置为`42`。然后我们创建了另外两个整数：一个是`i`的副本，另一个是对`i`的引用。如输出所示，我们得到了预期的类型，`int`和`int&`。使用`auto`关键字，我们可以期望，如果我们说类似`auto a = i2`，我们会得到`int&`类型，因为`i2`是对整数的引用，而且由于`auto`根据初始化方式推断其类型，我们应该得到`int&`。问题是，我们没有。相反，我们得到了`int`。

这是因为`auto`的类型是根据它的初始化方式确定的，而不包括引用类型。换句话说，示例中对`auto`的使用只是捕捉了`i2`的类型，而没有注意`i2`是整数还是整数的引用。要强制`auto`成为整数的引用，我们必须使用以下语法：

```cpp
auto a3 = i1;
auto &a4 = i2;

show_type(a3);
show_type(a4);
```

这导致了以下输出：

```cpp
a3 = int
a4 = int&
```

这个输出是预期的。相同的规则也适用于右值引用，但会变得更加复杂。例如，考虑以下代码：

```cpp
int &&i3 = std::move(i);
show_type(i3);
```

这导致了以下输出：

```cpp
i3 = int&&
```

这个输出再次符合预期。根据我们已经学到的知识，我们期望以下内容需要才能获得 r 值引用：

```cpp
auto &&a5 = i3;
show_type(a6);
```

问题在于这导致了以下输出：

```cpp
a5 = int&
```

如前面的例子所示，我们没有得到预期的 r 值引用。在 C++中，任何标记为`auto &&`的东西都被认为是一个转发引用（这也被称为通用引用，这是 Scott Meyers 创造的术语）。通用引用将根据初始化的内容推导为 l 值或 r 值引用。

因此，例如，考虑以下代码：

```cpp
auto &&a6 = i1;
show_type(a6);
```

这段代码导致了以下结果：

```cpp
a6 = int&
```

这是因为`i1`之前被定义为整数，所以`a6`变成了`i1`的 l 值引用。以下也是真的：

```cpp
auto &&a7 = i2;
show_type(a7);
```

前面的代码导致了以下结果：

```cpp
a7 = int&
```

这是因为`i2`之前被定义为整数的 l 值引用，这意味着通用引用也变成了整数的 l 值引用。

混乱的结果如下，如前面的代码片段中已经显示的那样：

```cpp
auto &&a8 = i3;
show_type(a8);
```

这再次导致了以下结果：

```cpp
a8 = int&
```

在这里，`i3`之前被定义为整数的 r 值引用（根据结果输出），但通用引用没有从`i3`中转发 r 值。这是因为，尽管`i3`被定义为 r 值引用，一旦被使用，它就变成了 l 值引用。正如 Scott Meyer 过去所说的，如果一个变量有一个名字（在我们的例子中是`i3`），它就是一个 l 值，即使它起初是一个 r 值。另一种看待这个问题的方式是，一旦一个变量被使用（即以任何方式被访问），这个变量就是一个 l 值。因此，前面的代码实际上是按照预期工作的。`i3`，尽管被定义为 r 值，是一个 l 值，因此通用引用变成了整数的 l 值引用，就像`i1`和`i2`一样。

要使用`auto`获得 r 值引用，你必须像不使用`auto`一样做相同的事情：

```cpp
auto &&a9 = std::move(i3);
show_type(a9);
```

这导致了以下结果：

```cpp
a9 = int&&
```

如前面的代码片段所示，思考`auto`的最佳方式就是简单地用实际类型（在本例中为`int`）替换`auto`，并且实际类型适用的规则也适用于`auto`。不同之处在于，如果你尝试写`int &&blah = i`，你会得到一个错误，因为编译器会认识到你试图从一个 l 值引用创建一个 r 值引用，这是不可能的（因为你只能从另一个 r 值引用创建一个 r 值引用）。

前面的例子之所以如此重要，是因为`auto`不会引起编译器的投诉。相反，它会在你想要创建 r 值时产生一个 l 值，这可能导致效率低下或错误。关于使用`auto`最重要的一点是，如果它有一个名字，它就是一个 l 值；否则，它就是一个 r 值。

例如，考虑以下代码：

```cpp
auto &&a10 = 42;
show_type(a10);
```

这段代码导致了以下结果：

```cpp
a10 = int&&
```

由于数值`42`没有变量名，它是一个常数，因此通用引用变成了整数的 r 值引用。

还应该注意，使用`auto`在处理引用时会继承 CV 限定符，这可能会让人感到困惑。看看这个例子：

```cpp
int main(void)
{
    const int i = 42;

    auto i1 = i;
    auto &i2 = i;
    auto &&i3 = std::move(i);

    show_type(i1);
    show_type(i2);
    show_type(i3);
}
```

这导致了以下结果：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/638a9ffc-4c76-48bd-9656-a209fb3c43b6.png)

如前面的屏幕截图所示，第一个整数仍然是`int`类型，因为`const int`的副本是`int`。然而，`i2`和`i3`都变成了对`const int`的引用。如果我们用`auto`替换`int`，我们将得到一个编译器错误，因为您不能创建对`const int`的非`const`引用，但是使用`auto`将乐意将您的非`const`变量转换为`const`变量。这样做的问题是，当您尝试修改变量时，您将得到奇怪的错误消息，抱怨变量是只读的，而实际上，您并没有明确地将变量定义为`const`。一般来说，如果您期望`const`，则将使用`auto`定义的变量标记为`const`，如果您不期望`const`，则将其标记为非`const`，以防止这些有时难以识别的错误。

# 学习 decltype 类型推断规则的工作方式

在本教程中，我们将学习`decltype()`和`decltype(auto)`的类型推断工作原理，以及如何使用`decltype(auto)`来避免`auto`处理引用的问题。

这个教程很重要，因为`auto`在处理引用时有一些奇怪的行为，而`decltype()`则提供了一种更可预测地处理类型推断的方式，特别是在使用 C++模板时。

# 准备工作

开始之前，请确保满足所有技术要求，包括安装 Ubuntu 18.04 或更高版本，并在终端窗口中运行以下命令：

```cpp
> sudo apt-get install build-essential git cmake
```

这将确保您的操作系统具有适当的工具来编译和执行本教程中的示例。完成后，打开一个新的终端。我们将使用这个终端来下载、编译和运行我们的示例。

# 如何做...

执行以下步骤来尝试这个教程：

1.  从新的终端中，运行以下命令来下载源代码：

```cpp
> cd ~/
> git clone https://github.com/PacktPublishing/Advanced-CPP-CookBook.git
> cd Advanced-CPP-CookBook/chapter12
```

1.  编译源代码，请运行以下命令：

```cpp
> cmake .
> make recipe02_examples
```

1.  源代码编译完成后，您可以通过运行以下命令来执行本教程中的每个示例：

```cpp
> ./recipe02_example01
i = int

> ./recipe02_example02
i = short int

> ./recipe02_example03
i = short int

> ./recipe02_example04
i1 = int
i2 = int

> ./recipe02_example05
i1 = int
i2 = const int
i3 = volatile int
i4 = const volatile int

> ./recipe02_example06
i1 = int
i2 = int&
i3 = int&&
a1 = int
a2 = int
a3 = int
a4 = int
a5 = int&
a6 = int&&
d1 = int
d2 = int&
d3 = int&&
```

在下一节中，我们将逐个介绍这些示例，并解释每个示例程序的作用以及它与本教程中所教授的课程的关系。

# 工作原理...

在 C++中，`auto`和`typename`都不能提供获取变量类型并使用该信息创建新类型的能力。为了更好地解释为什么您可能想要这样做，让我们看下面的例子：

```cpp
template<typename FUNC>
auto question(FUNC &&func)
{
    auto x = func() + 10;
    return x;
}
```

我们从一个接受任何函数作为输入并返回此函数的结果加上`10`的函数开始。然后我们可以执行此函数如下：

```cpp
short the_answer()
{
    return 32;
}

int main(void)
{
    auto i = question(the_answer);
    show_type(i);
}
```

如前面的示例所示，我们将`question()`函数传递给另一个返回`short`的函数的指针。在执行此函数时，我们存储结果，然后使用一个名为`show_type()`的函数，该函数旨在输出所提供类型的类型。结果如下：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/e8f08892-9ea4-4d72-9d86-197819b5e39f.png)

这个示例的问题在于返回的类型与我们给定的类型不同。C++允许根据需要增加任何变量的大小，并且通常会对 short 进行增加，特别是当您尝试对具有数值值的 short 执行算术运算时，因为数值值被表示为整数。

由于我们不知道`question()`函数中提供的函数的返回类型，因此无法解决此问题。输入`decltype()`。为了解释清楚，让我们更新我们的示例来解决前面的问题：

```cpp
template<typename FUNC>
auto question(FUNC &&func)
{
    decltype(func()) x = func() + 10;
    return x;
}
```

如前面的示例所示，我们用`decltype(func())`替换了`auto`。这告诉编译器获取`func()`的返回类型，并使用该类型来定义`x`。结果，编译器将此模板转换为以下函数：

```cpp
short question(short(*func)())
{
    short x = func() + 10;
    return x;
}
```

这发生在最初预期的以下情况：

```cpp
int question(short(*func)())
{
    int x = func() + 10;
    return x;
}
```

然后在执行时会得到以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/74f2a492-4468-4399-82cf-1bcb78645046.png)

如前面的屏幕截图所示，我们现在从我们的`question()`函数中得到了正确的类型返回。使用 C++14，我们可以进一步将此示例编写为：

```cpp
template<typename FUNC>
constexpr auto question(FUNC &&func) -> decltype(func())
{
    return func() + 10;
}
```

在前面代码片段的示例中，我们将`question()`函数转换为`constexpr`，这允许编译器优化掉函数调用，用`func() + 10`语句替换对`question()`的调用。我们还通过显式告诉编译器我们希望函数返回的类型来消除了对基于堆栈的变量的需求，使用`-> decltype()`函数返回语法。需要注意的是，由于以下内容不会编译，因此需要此语法：

```cpp
template<typename FUNC>
constexpr decltype(func()) question(FUNC &&func)
{
    return func() + 10;
}
```

前面的代码将无法编译，因为编译器还没有`func()`的定义，因此不知道它的类型。`->`语法通过将返回类型放在函数定义的末尾而不是开头来解决了这个问题。

`decltype()`说明符也可以用于替代`auto`，如下所示：

```cpp
int main(void)
{
    decltype(auto) i1 = 42;
    decltype(auto) i2{42};

    show_type(i1);
    show_type(i2);
}
```

这导致了以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/fb6593f6-0f30-46a3-9beb-ca5ecc548089.png)

在这个例子中，我们使用`decltype(auto)`创建了两个整数，并将它们初始化为`42`。在这种特定情况下，`decltype(auto)`和`auto`的操作完全相同。两者都将占位符类型定义为整数，因为两者都使用了默认的`int`初始化为数值，这是默认的。 

与`auto`一样，您可以使用 CV 限定符（即`const`/`volatile`）装饰`decltype(auto)`，如下所示：

```cpp
int main(void)
{
    decltype(auto) i1 = 42;
    const decltype(auto) i2 = 42;
    volatile decltype(auto) i3 = 42;
    const volatile decltype(auto) i4 = 42;

    show_type(i1);
    show_type(i2);
    show_type(i3);
    show_type(i4);
}
```

这导致了以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/ded88455-57d8-42c0-bf42-bf31d47ed56a.png)

`decltype(auto)`的真正魔力在于它如何处理引用。为了证明这一点，让我们从以下示例开始：

```cpp
int main(void)
{
    int i = 42;

    int i1 = i;
    int &i2 = i;
    int &&i3 = std::move(i);

    show_type(i1);
    show_type(i2);
    show_type(i3);
}
```

执行后，我们看到以下输出：

```cpp
i1 = int
i2 = int&
i3 = int&&
```

如前面的示例所示，我们创建了一个整数，一个整数的左值引用和一个整数的右值引用。让我们看看如果尝试使用`auto`而不是`int`会发生什么：

```cpp
auto a1 = i1;
auto a2 = i2;
auto a3 = std::move(i3);

show_type(a1);
show_type(a2);
show_type(a3);
```

然后我们看到以下输出：

```cpp
a1 = int
a2 = int
a3 = int
```

如前面的示例所示，我们只得到了整数。所有引用都被移除了。使用`auto`获取引用的唯一方法是如果我们明确定义它们，如下所示：

```cpp
auto a4 = i1;
auto &a5 = i2;
auto &&a6 = std::move(i3);

show_type(a4);
show_type(a5);
show_type(a6);
```

这导致了以下预期的输出：

```cpp
a4 = int
a5 = int&
a6 = int&&
```

必须添加额外的`&`运算符来显式定义引用类型的问题在于，这假设在我们的模板代码中，我们实际上知道引用应该是什么。如果没有这些信息，我们将无法编写模板函数，并且不知道是否可以创建左值引用或右值引用，很可能会导致复制。

为了克服这一点，`decltype(auto)`不仅在初始化期间继承类型和 CV 限定符，还继承引用关系，如下所示：

```cpp
decltype(auto) d1 = i1;
decltype(auto) d2 = i2;
decltype(auto) d3 = std::move(i3);

show_type(d1);
show_type(d2);
show_type(d3);
```

执行前面的代码会导致以下结果：

```cpp
d1 = int
d2 = int&
d3 = int&&
```

如前面的示例所示，`decltype(auto)`可以用于继承被初始化的值的所有类型信息，包括引用关系。

# 使用模板函数类型推断

在本示例中，我们将学习模板函数类型推断的工作原理。具体来说，本示例将教你模板函数类型推断与`auto`类型推断相同的工作方式，以及如何将函数类型推断与一些奇怪的类型（例如 C 风格数组）一起使用。

这个示例很重要，因为它将教会你如何正确地编写函数模板，消除在调用函数模板时显式定义类型信息的需要。

# 准备工作

开始之前，请确保满足所有技术要求，包括安装 Ubuntu 18.04 或更高版本，并在终端窗口中运行以下命令：

```cpp
> sudo apt-get install build-essential git cmake
```

这将确保您的操作系统具有正确的工具来编译和执行本示例中的示例。完成后，打开一个新的终端。我们将使用此终端来下载、编译和运行我们的示例。

# 如何做...

按照以下步骤尝试这个配方：

1.  从新的终端运行以下命令以下载源代码：

```cpp
> cd ~/
> git clone https://github.com/PacktPublishing/Advanced-CPP-CookBook.git
> cd Advanced-CPP-CookBook/chapter12
```

1.  要编译源代码，请运行以下命令：

```cpp
> cmake .
> make recipe03_examples
```

1.  源代码编译后，可以通过运行以下命令执行本文中的每个示例：

```cpp
> ./recipe03_example01 
t = int
t = int

> ./recipe03_example02
t = const int&

> ./recipe03_example03
t = int&

> ./recipe03_example04
t = int&

> ./recipe03_example05
t = int&&

> ./recipe03_example06
t = int&&

> ./recipe03_example07
t = const int&

> ./recipe03_example08
t = const int&&

> ./recipe03_example09
t = int (&&)[6]
```

在下一节中，我们将逐个介绍这些示例，并解释每个示例程序的作用以及它与本文所教授的课程的关系。

# 工作原理...

在 C++11 中，标准委员会添加了根据传递给函数的参数自动推断模板函数类型信息的能力。

看看这个例子：

```cpp
template<typename T>
void foo(T t)
{
    show_type(t);
}
```

前面的函数创建了一个标准模板函数，执行一个名为`show_type()`的函数，用于输出提供的类型信息。

在 C++11 之前，我们会这样使用这个函数：

```cpp
int main(void)
{
    int i = 42;

    foo<int>(i);
    foo<int>(42);
}
```

编译器已经知道模板应该将`T`类型定义为整数，因为这就是函数提供的内容。C++11 去除了这种冗余，允许以下操作：

```cpp
int main(void)
{
    int i = 42;

    foo(i);
    foo(42);
}
```

执行时会得到以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/acf27d37-b223-47d6-8cca-91327b06bcef.png)

然而，与`auto`一样，当使用 r 值引用时，这种类型推断变得有趣，如下所示：

```cpp
template<typename T>
void foo(T &&t)
{
    show_type(t);
}
```

前面的示例将`t`定义为转发引用（也称为通用引用）。通用引用接受传递给它的任何引用类型。例如，我们可以这样调用这个函数：

```cpp
int main(void)
{
    int i = 42;
    foo(i);
}
```

我们得到以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/55fe5e8f-d61e-4087-9c56-e55f50384a8a.png)

前面的输出显示，模板函数得到了一个整数的 l 值引用。这是因为在我们的主函数中，`i`是一个 l 值，即使函数似乎要求一个 r 值引用。要获得一个 r 值引用，我们必须提供一个 r 值，如下所示：

```cpp
int main(void)
{
    int i = 42;
    foo(std::move(i));
}
```

执行时会得到以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/04ac53de-9f09-4000-afe6-8a9a9d78835b.png)

如前面的屏幕截图所示，现在我们已经给了通用引用一个 r 值，我们得到了一个 r 值。应该注意的是，通用引用只有以下签名：

```cpp
template<typename T>
void foo(T &&t)
```

例如，以下不是通用引用：

```cpp
template<typename T>
void foo(const T &&t)
```

以下也不是通用引用：

```cpp
void foo(int &&t)
```

前面的两个例子都是 r 值引用，因此需要提供一个 r 值（换句话说，这两个函数都定义了移动操作）。通用引用将接受 l 值和 r 值引用。尽管这似乎是一个优势，但它的缺点是有时很难知道你的模板函数接收了一个 l 值还是一个 r 值。目前，确保你的模板函数像一个 r 值引用而不是一个通用引用的最佳方法是使用 SFINAE：

```cpp
std::is_rvalue_reference_v<decltype(t)>
```

最后，还可以对不常见的类型进行类型推断，比如 C 风格数组，就像这个例子中所示：

```cpp
template<typename T, size_t N>
void foo(T (&&t)[N])
{
    show_type(t);
}
```

前面的函数说明我们希望将类型为`T`且大小为`N`的 C 风格数组传递给函数，然后在执行时输出其类型。我们可以这样使用这个函数：

```cpp
int main(void)
{
    foo({4, 8, 15, 16, 23, 42});
}
```

这自动推断为一个类型为`int`且大小为`6`的 C 风格数组的 r 值引用。正如本文所示，C++提供了几种机制，允许编译器确定在模板函数中使用了哪些类型。

# 在 C++17 中利用模板类类型推断

在本文中，我们将学习 C++17 中类模板的类类型推断是如何工作的。这个配方很重要，因为 C++17 增加了从构造函数中推断模板类类型的能力，从而减少了代码的冗长和冗余。

从这个配方中获得的知识将使您能够编写 C++类，这些类可以从类构造函数中正确推断其类型，而无需显式类型声明。

# 准备工作

开始之前，请确保满足所有技术要求，包括安装 Ubuntu 18.04 或更高版本，并在终端窗口中运行以下命令：

```cpp
> sudo apt-get install build-essential git cmake
```

这将确保您的操作系统具有正确的工具来编译和执行本教程中的示例。完成后，打开一个新的终端。我们将使用这个终端来下载、编译和运行我们的示例。

# 如何做...

按照以下步骤尝试这个教程：

1.  从新的终端中，运行以下命令下载源代码：

```cpp
> cd ~/
> git clone https://github.com/PacktPublishing/Advanced-CPP-CookBook.git
> cd Advanced-CPP-CookBook/chapter12
```

1.  要编译源代码，请运行以下命令：

```cpp
> cmake .
> make recipe04_examples
```

1.  源代码编译后，您可以通过运行以下命令来执行本教程中的每个示例：

```cpp
> ./recipe04_example01
t = int
t = int

> ./recipe04_example02
t = int&

> ./recipe04_example03
t = int&&
t = int&&

> ./recipe04_example04
t = int&&
u = int&

> ./recipe04_example05
t = int&&

> ./recipe04_example06
t = const char (&)[16]
u = int&&
```

在下一节中，我们将逐个介绍这些示例，并解释每个示例程序的作用，以及它们与本教程中所教授的课程的关系。

# 它是如何工作的...

类模板类型推断是 C++17 中新增的一个功能，它提供了从构造函数中推断模板类的类型的能力。假设我们有以下类模板：

```cpp
template<typename T>
class the_answer
{

public:
    the_answer(T t)
    {
        show_type(t);
    }
};
```

如上面的代码片段所示，我们有一个简单的类模板，在构造时接受一个类型`T`，并使用`show_type()`函数输出它所给定的任何类型。在 C++17 之前，这个类将使用以下方式实例化：

```cpp
int main(void)
{
    the_answer<int> is(42);
}
```

使用 C++17，我们现在可以实例化这个类如下：

```cpp
int main(void)
{
    the_answer is(42);
}
```

这样做的原因是类的构造函数接受一个类型`T`作为参数。由于我们提供了一个数字整数作为参数，类的类型`T`被推断为整数。这种类型推断也包括对引用的支持。查看以下示例：

```cpp
template<typename T>
class the_answer
{

public:
    the_answer(T &t)
    {
        show_type(t);
    }
};
```

在上面的示例中，我们的类在构造函数中以`T&`作为参数，这使我们可以实例化类如下：

```cpp
int main(void)
{
    int i = 42;
    the_answer is(i);
}
```

执行时会产生以下结果：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/b10d531e-b7d8-49ce-b509-30aa6f695860.png)

如上面的示例所示，类的类型`T`被推断为整数的左值引用。大多数适用于函数模板的类型推断规则也适用于类模板，但也有一些例外。例如，类模板的构造函数不支持转发引用（通用引用）。考虑以下代码：

```cpp
template<typename T>
class the_answer
{

public:
    the_answer(T &&t)
    {
        show_type(t);
    }
};
```

上面的构造函数不是一个通用引用；它是一个 r 值引用，这意味着我们不能做以下操作：

```cpp
the_answer is(i);
```

这是不可能的，因为这将尝试将一个左值绑定到一个右值，这是不允许的。相反，像任何其他 r 值引用一样，我们必须使用以下方式实例化类：

```cpp
the_answer is(std::move(i));
```

或者我们可以使用以下方式绑定它：

```cpp
the_answer is(42);
```

通用引用不支持类模板类型推断的原因是，类模板类型推断使用构造函数来推断类型，然后根据推断出的类型填充类的其余部分的类型，这意味着在构造函数编译时，它看起来像这样：

```cpp
class the_answer
{

public:
    the_answer(int &&t)
    {
        show_type(t);
    }
};
```

这定义了一个 r 值引用。

要在构造函数或任何其他函数中获得一个通用引用，您必须使用一个成员函数模板，它本身仍然可以支持类型推断，但不用于推断类的任何类型。查看以下示例：

```cpp
template<typename T>
class the_answer
{

public:

    template<typename U>
    the_answer(T &&t, U &&u)
    {
        show_type(t);
        show_type(u);
    }
};
```

在上面的示例中，我们创建了一个带有类型`T`的类模板，并将构造函数定义为成员函数模板。构造函数本身接受`T &&t`和`U &&u`。然而，在这种情况下，`t`是一个 r 值引用，`u`是一个通用引用，尽管它们看起来相同。在 C++17 中，编译器可以推断两者如下：

```cpp
int main(void)
{
    int i = 42;
    the_answer is(std::move(i), i);
}
```

还应该注意，构造函数不必按任何特定顺序具有所有类型才能进行推断。唯一的要求是构造函数的参数中包含所有类型。例如，考虑以下代码：

```cpp
template<typename T>
class the_answer
{

public:
    the_answer(size_t size, T &&t)
    {
        show_type(t);
    }
};
```

上面的示例可以实例化如下：

```cpp
int main(void)
{
    the_answer is_2(42, 42);
}
```

最后，类型推导还支持多个模板类型，就像这个例子中一样：

```cpp
template<typename T, typename U>
class the_answer
{

public:
    the_answer(const T &t, U &&u)
    {
        show_type(t);
        show_type(u);
    }
};
```

上面的示例创建了一个具有两个通用类型的类模板。这个类的构造函数创建了对类型`T`的`const`左值引用，同时还接受了对类型`U`的右值引用。可以这样实例化这个类：

```cpp
int main(void)
{
    the_answer is("The answer is: ", 42);
}
```

这将产生以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/137fb1ac-46dc-4fe1-b8f4-6d95dcdbdfcf.png)

如上例所示，`T`和`U`都成功推导出来了。

# 在 C++17 中使用用户定义的类型推导

在这个示例中，我们将学习如何使用用户定义的推导指南来帮助编译器进行类模板类型推导。大多数情况下，不需要用户定义的推导指南，但在某些情况下，为了确保编译器推断出正确的类型，可能需要使用它们。这个示例很重要，因为如果没有用户定义的类型推导，某些类型的模板方案根本不可能，这将会被证明。

# 准备工作

开始之前，请确保满足所有技术要求，包括安装 Ubuntu 18.04 或更高版本，并在终端窗口中运行以下命令：

```cpp
> sudo apt-get install build-essential git cmake
```

这将确保您的操作系统具有编译和执行本示例中的示例所需的适当工具。完成后，打开一个新的终端。我们将使用这个终端来下载、编译和运行我们的示例。

# 如何做...

执行以下步骤来尝试这个示例：

1.  从新的终端运行以下命令来下载源代码：

```cpp
> cd ~/
> git clone https://github.com/PacktPublishing/Advanced-CPP-CookBook.git
> cd Advanced-CPP-CookBook/chapter12
```

1.  要编译源代码，请运行以下命令：

```cpp
> cmake .
> make recipe05_examples
```

1.  源代码编译完成后，可以通过运行以下命令来执行本示例中的每个示例：

```cpp
> ./recipe05_example01
t = unsigned int
t = int

> ./recipe05_example02
t = unsigned int

> ./recipe05_example03
t = std::__cxx11::basic_string<char>
```

在下一节中，我们将逐个介绍这些示例，并解释每个示例程序的作用以及它与本示例中所教授的课程的关系。

# 工作原理...

类模板类型推导是 C++17 中一个非常需要的特性，因为它有助于减少我们的 C++中的冗余和冗长。然而，在某些情况下，编译器会推断出错误的类型，如果我们不依赖于类型推导，这个问题是可以解决的。为了更好地理解这种问题，让我们看一下下面的例子：

```cpp
template<typename T>
class the_answer
{

public:
    the_answer(T t)
    {
        show_type(t);
    }
};
```

在上面的示例中，我们创建了一个简单的类模板，其构造函数接受类型`T`，并使用`show_type()`函数输出给定的任何类型。现在假设我们希望使用这个类来实例化一个接受无符号整数的版本。有两种方法可以做到这一点：

```cpp
the_answer<unsigned> is(42);
```

上述方法是最明显的，因为我们明确告诉编译器我们希望拥有的类型，而根本不使用类型推导。获取无符号整数的另一种方法是使用正确的数字文字语法，如下所示：

```cpp
the_answer is(42U);
```

在上面的示例中，我们利用了类型推导，但我们必须确保始终将`U`添加到我们的整数上。这种方法的优点是代码是显式的。这种方法的缺点是，如果我们忘记添加`U`来表示我们希望有一个无符号整数，我们可能会无意中创建一个具有`int`类型而不是`unsigned`类型的类。

为了防止这个问题，我们可以利用用户定义的类型推导来告诉编译器，如果它看到一个整数类型，我们真正想要的是一个无符号类型，如下所示：

```cpp
the_answer(int) -> the_answer<unsigned>;
```

上面的语句告诉编译器，如果它看到一个带有`int`类型的构造函数，`int`应该产生一个具有`unsigned`类型的类。

左侧采用构造函数签名，右侧采用类模板签名。

使用这种方法，我们可以将我们看到的任何构造函数签名转换为我们希望的类模板类型，就像这个例子中一样：

```cpp
the_answer(const char *) -> the_answer<std::string>;
```

用户定义的类型推导指南告诉编译器，如果它看到一个 C 风格的字符串，应该创建`std::string`。然后我们可以通过以下方式运行我们的示例：

```cpp
int main(void)
{
    the_answer is("The answer is: 42");
}
```

然后我们得到以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/33a212a7-2507-4906-af8c-813b8dcb6bc0.png)

正如前面的屏幕截图所示，该类是使用`std::string`（或至少是 GCC 内部表示的`std::string`）构建的，而不是 C 风格的字符串。


# 第十三章：奖励-使用 C++20 功能

在本章中，您将快速了解一些即将添加到 C++20 中的功能。本章很重要，因为与 C++14 和 C++17 不同，C++20 为语言添加了几个改变游戏规则的功能。

它始于对 C++20 概念的介绍，这是一种定义任意类型要求的新机制。C++20 概念承诺改变我们使用模板和`auto`编程的方式，提供了一种定义类型要求的机制。然后我们将转向 C++20 模块，这是一个新功能，消除了`#include`的需要，改变了我们在 C++中定义接口的方式。C++模块是语言的巨大变化，需要完全改变整个标准库以及我们的构建工具。接下来，我们将快速查看`std::span`和 C++范围。最后，我们将简要介绍 C++20 的另一个改变游戏规则的功能，称为协程。

本章的示例如下：

+   查看 C++20 中的概念

+   使用 C++20 中的模块

+   介绍`std::span`，数组的新视图

+   在 C++20 中使用范围

+   学习如何在 C++20 中使用协程

# 技术要求

要编译和运行本章中的示例，您必须具有管理访问权限，可以访问具有功能性互联网连接的运行 Ubuntu 19.04 的计算机。请注意，本书的其余部分使用的是 Ubuntu 18.04。由于我们将讨论仍在开发中的 C++20，因此在本章中需要最新和最好的 GCC 版本。在运行这些示例之前，您必须安装以下内容：

```cpp
> sudo apt-get install build-essential git cmake
```

如果这是安装在 Ubuntu 18.04 之外的任何操作系统上，则需要 GCC 7.4 或更高版本和 CMake 3.6 或更高版本。

本章的代码文件可以在[//github.com/PacktPublishing/Advanced-CPP-CookBook/tree/master/chapter13](https://github.com/PacktPublishing/Advanced-CPP-CookBook/tree/master/chapter13https://github.com/PacktPublishing/Advanced-CPP-CookBook/tree/master/chapter13)找到。

# 查看 C++20 中的概念

在本教程中，我们将讨论 C++20 的即将添加的一个功能，它承诺彻底改变我们对模板编程的思考方式，称为 C++20 概念。如今，C++在很大程度上依赖于使用 SFINAE 来约束适用于任何给定模板函数的类型。正如在第四章中所见，*使用模板进行通用编程*，SFINAE 很难编写，阅读起来令人困惑，编译速度慢。本教程很重要，因为 C++20 后的模板编程不仅更容易编码和调试，而且还将减少模板编程的人力成本，使其更易于阅读和理解。

# 准备工作

开始之前，请确保满足所有技术要求，包括安装 Ubuntu 19.04 或更高版本，并在终端窗口中运行以下命令：

```cpp
> sudo apt-get install build-essential git cmake
```

这将确保您的操作系统具有编译和执行本教程中示例所需的适当工具。完成后，打开一个新的终端。我们将使用此终端来下载、编译和运行我们的示例。

# 如何做...

您需要执行以下步骤来尝试本教程：

1.  从新的终端运行以下命令以下载源代码：

```cpp
> cd ~/
> git clone https://github.com/PacktPublishing/Advanced-CPP-CookBook.git
> cd Advanced-CPP-CookBook/chapter13
```

1.  要编译源代码，请运行以下命令：

```cpp
> cmake .
> make recipe01_examples
```

1.  一旦源代码被编译，您可以通过运行以下命令来执行本教程中的每个示例：

```cpp
> ./recipe01_example01
The answer is: 42
The answer is not: 43

> ./recipe01_example02
The answer is: 42
The answer is not: 43
```

在下一节中，我们将逐个介绍这些示例，并解释每个示例程序的作用以及它与本教程中所教授的课程的关系。

# 工作原理...

为了最好地解释 C++20 概念如何帮助模板编程，我们将从今天在 C++中编程接口的一个简单示例开始。接口在对象导向编程中被广泛使用，用于将 API 的接口与其实现细节分离开来。

让我们从以下纯虚接口开始：

```cpp
class interface
{
public:
    virtual ~interface() = default;
    virtual void foo() = 0;
};
```

C++中的前述纯虚接口定义了一个`foo()`函数。这个 API 的客户端不需要知道`foo()`是如何实现的。他们关心的只是接口的定义和`foo()`的函数签名，以了解`foo()`应该如何行为。使用这个接口，我们可以定义一个接口的实现，如下所示：

```cpp
class A :
    public interface
{
public:
    void foo() override
    {
        std::cout << "The answer is: 42\n";
    }
};
```

如前面的示例所示，我们创建了一个名为`A`的类，它继承了接口并重写了`foo()`函数以给它一个实现。我们可以用另一个实现做同样的事情，如下所示：

```cpp
class B :
    public interface
{
public:
    void foo() override
    {
        std::cout << "The answer is not: 43\n";
    }
};
```

如前面的示例所示，`B`类提供了接口的另一种实现。这个接口的客户端可以像下面这样使用接口：

```cpp
class client
{
    interface &m_i;

public:
    client(interface &i) :
        m_i{i}
    { }

    void bar()
    {
        m_i.foo();
    }
};
```

客户端实际上不需要知道关于`A`或`B`的任何东西。它只包括接口的定义，并使用接口来访问任何特定的实现。我们可以像下面这样使用这个客户端：

```cpp
int main(void)
{
    A a;
    B b;

    client c1(a);
    client c2(b);

    c1.bar();
    c2.bar();
}
```

如前面的示例所示，我们首先创建了`A`和`B`的实例，然后创建了两个不同的客户端，它们分别给了`A`和`B`的接口实现。最后，我们执行了每个客户端的`bar()`函数，得到了以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/de930bf3-bf6d-44a0-8b41-446a2d7e0f6d.png)

如前面的截图所示，客户端并不知道接口是以两种不同的方式定义的，因为客户端只关心接口。这种技术在很多 C++文献中都有展示，特别是为了实现所谓的 S.O.L.I.D 面向对象设计原则。S.O.L.I.D 设计原则代表以下内容：

+   **单一职责原则**：这确保了如果一个对象必须改变，它只会因为一个原因而改变（也就是说，一个对象不会提供多于一个的职责）。

+   **开闭原则**：这确保了一个对象可以被扩展而不被修改。

+   **里氏替换原则**：这确保了在使用继承时，子类实现了它们重写的函数的行为，而不仅仅是函数的签名。

+   **接口隔离原则**：这确保了一个对象具有尽可能小的接口，这样对象的客户端就不会被迫依赖他们不使用的 API。

+   **依赖反转原则**：这确保了对象只依赖于接口而不依赖于实现。

这些原则的结合旨在确保您在 C++中使用面向对象编程更容易理解和维护。然而，现有的 S.O.L.I.D 和 C++文献存在一个问题，即它倡导大量使用纯虚接口，这是有代价的。每个类必须给出一个额外的虚表（即 vTable），并且所有函数调用都会遇到虚函数重载的额外开销。

解决这个问题的一种方法是使用静态接口（这在现有文献中很少谈到）。为了最好地解释这是如何工作的，让我们从我们接口的定义开始，如下所示：

```cpp
#include <iostream>

template<typename DERIVED>
class interface
{
public:
    constexpr void foo()
    {
        static_cast<DERIVED *>(this)->foo_override();
    }
};
```

如前面的示例所示，我们将利用静态多态性来实现我们的接口。前述类采用了一个名为`DERIVED`的类型，并将接口的实例转换为`DERIVED`类，调用一个已被重写的`foo`函数的版本。现在`A`的实现看起来是这样的：

```cpp
class A :
    public interface<A>
{
public:
    void foo_override()
    {
        std::cout << "The answer is: 42\n";
    }
};
```

如前面的示例所示，`A`现在不再继承接口，而是继承`A`的接口。当调用接口的`foo()`函数时，接口将调用`A`的`foo_override()`函数。我们可以使用相同的方法实现`B`：

```cpp
class B :
    public interface<B>
{
public:
    void foo_override()
    {
        std::cout << "The answer is not: 43\n";
    }
};
```

如前面的示例所示，`B`能够提供自己的接口实现。需要注意的是，到目前为止，在这种设计模式中，我们还没有使用`virtual`，这意味着我们已经创建了一个接口及其实现，而不需要虚拟继承，因此这种设计没有额外的开销。事实上，编译器能够消除从`foo()`到`foo_override()`的调用重定向，确保抽象的使用不会比使用纯虚拟接口带来任何额外的运行时成本。

`A`和`B`的客户端可以这样实现：

```cpp
template<typename T>
class client
{
    interface<T> &m_i;

public:
    client(interface<T> &i) :
        m_i{i}
    { }

    void bar()
    {
        m_i.foo();
    }
};
```

如前面的代码片段所示，这个示例中的客户端与前一个示例中的客户端唯一的区别在于这个客户端是一个模板类。静态多态性要求在编译时知道接口的类型信息。在大多数设计中，这通常是可以接受的，因为早期使用纯虚拟接口并不是因为我们想要执行运行时多态和类型擦除的能力，而是为了确保客户端只遵循接口而不是实现。在这两种情况下，每个客户端的实现都是静态的，并且在编译时已知。

为了使用客户端，我们可以使用一些 C++17 的类类型推导来确保我们的`main()`函数保持不变，如下所示：

```cpp
int main(void)
{
    A a;
    B b;

    client c1(a);
    client c2(b);

    c1.bar();
    c2.bar();
}
```

执行上述示例会得到以下结果：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/417c5648-2521-4327-9b35-d507866b6af7.png)

如前面的截图所示，代码执行相同。两种方法之间唯一的区别在于一种使用纯虚拟继承，这会带来运行时成本，而第二种方法使用静态多态性，这会带来人为成本。特别是对于大多数初学者来说，前面的例子很难理解。在具有嵌套依赖关系的大型项目中，使用静态多态性可能非常难以理解和阅读。

上述示例的另一个问题是编译器对接口及其客户端的信息不足，无法在给出错误类型时提供合理的错误消息。看看这个例子：

```cpp
int main(void)
{
    client c(std::cout);
}
```

这导致了以下编译器错误：

```cpp
/home/user/book/chapter13/recipe01.cpp: In function ‘int main()’:
/home/user/book/chapter13/recipe01.cpp:187:23: error: class template argument deduction failed:
  187 | client c(std::cout);
      | ^
/home/user/book/chapter13/recipe01.cpp:187:23: error: no matching function for call to ‘client(std::ostream&)’
/home/user/book/chapter13/recipe01.cpp:175:5: note: candidate: ‘template<class T> client(interface<T>&)-> client<T>’
  175 | client(interface<T> &i) :
      | ^~~~~~

...
```

上述错误消息几乎没有用，特别是对于初学者来说。为了克服这些问题，C++20 Concepts 承诺提供一个更清晰的模板编程实现。为了更好地解释这一点，让我们看看如何使用 C++20 Concepts 来实现接口：

```cpp
template <typename T>
concept interface = requires(T t)
{
    { t.foo() } -> void;
};
```

如前面的示例所示，我们定义了一个名为`interface`的 C++20 概念。给定一个类型`T`，这个概念要求`T`提供一个名为`foo()`的函数，不接受任何输入并且不返回任何输出。然后我们可以这样定义`A`：

```cpp
class A
{
public:
    void foo()
    {
        std::cout << "The answer is: 42\n";
    }
};
```

如前面的代码片段所示，`A`不再需要使用继承。它只需提供一个给定普通 C++类定义的`foo()`函数。`B`的实现方式也是一样的：

```cpp
class B
{
public:
    void foo()
    {
        std::cout << "The answer is not: 43\n";
    }
};
```

再次强调，不再需要继承。这个接口的客户端实现如下：

```cpp
template<interface T>
class client
{
    T &m_i;

public:
    client(T &i) :
        m_i{i}
    { }

    void bar()
    {
        m_i.foo();
    }
};
```

如前面的示例所示，我们定义了一个接受模板类型`T`并调用其`foo()`函数的类。在我们之前的静态多态示例中，我们可以以完全相同的方式实现客户端。但这种方法的问题在于客户端无法确定类型`T`是否遵守接口。结合 SFINAE 的静态断言，比如`std::is_base_of()`，可以解决这个问题，但依赖接口的每个对象都必须包含这个逻辑。然而，使用 C++20 概念，可以在不需要继承或任何复杂的模板技巧（如 SFINAE）的情况下实现这种简单性。因此，让我们看看我们可以使用以下内容代替：

```cpp
template<typename T>
```

可以使用以下内容代替：

```cpp
template<interface T>
```

当今 C++模板编程的问题在于`typename`关键字并不能告诉编译器有关类型本身的任何信息。SFINAE 提供了一种解决方法，通过以巨大的人力成本定义有关类型的某些特征，因为 SFINAE 更加复杂难以理解，当出现问题时导致的编译器错误也毫无用处。C++20 概念通过定义类型的属性（称为概念），然后在`typename`的位置使用该概念，解决了所有这些问题，为编译器提供了确定给定类型是否符合概念的所有信息。当出现问题时，编译器可以提供有关所提供类型缺少什么的简单错误消息。

C++20 概念是一个令人兴奋的新功能，即将推出，它承诺彻底改变我们使用 C++模板的方式，减少了与模板工作相关的整体人力成本，但以更复杂的编译器和 C++规范为代价。

# 在 C++20 中使用模块

在本示例中，我们将学习有关 C++20 的一个新功能，称为模块。本示例很重要，因为 C++20 模块消除了向前移动`#include`的需要。当今的 C++代码通常在头文件和源文件之间划分。每个源文件都是单独编译的，并且必须重新编译它包含的头文件（以及包含的头文件包含的任何头文件），导致编译时间缓慢、依赖顺序问题以及对 C 风格宏的过度使用。相反，可以使用 C++20 模块来选择性地包含库，改变我们编写甚至是简单应用程序（如“Hello World”）的方式。

# 准备工作

开始之前，请确保满足所有技术要求，包括安装 Ubuntu 19.04 或更高版本，并在终端窗口中运行以下命令：

```cpp
> sudo apt-get install build-essential git cmake
```

这将确保您的操作系统具有编译和执行本示例所需的适当工具。完成后，打开一个新的终端。我们将使用这个终端来下载、编译和运行我们的示例。

# 如何做...

您需要执行以下步骤来尝试本示例：

1.  从新的终端中，运行以下命令下载源代码：

```cpp
> cd ~/
> git clone https://github.com/PacktPublishing/Advanced-CPP-CookBook.git
> cd Advanced-CPP-CookBook/chapter13
```

1.  要编译源代码，请运行以下命令：

```cpp
> cmake .
> make recipe02_examples
```

1.  源代码编译完成后，可以通过运行以下命令来执行本示例中的每个示例：

```cpp
> ./recipe02_example01
Hello World

> ./recipe02_example03
The answer is: 42
```

在下一节中，我们将逐个介绍这些示例，并解释每个示例程序的作用以及它与本示例中所教授的课程的关系。需要注意的是，源代码中的示例 2 和 4 在撰写本文时无法编译，因为截至目前，GCC 尚不支持 C++模块。

# 它是如何工作的...

C++20 模块提供了一种新的方式来包含 C++中使用的 API 的定义。让我们看看如何在 C++中编写一个简单的`Hello World`应用程序的以下示例：

```cpp
#include <iostream>

int main(void)
{
    std::cout << "Hello World\n";
}
```

要使用 C++20 模块编写相同的应用程序，可以执行以下操作：

```cpp
import std.core;

int main(void)
{
    std::cout << "Hello World\n";
}
```

尽管差异微妙，但在幕后，为了使前面的代码成为可能，发生了很多变化。让我们看一个更复杂的示例，如下所示：

```cpp
#include <string>

template<size_t number>
class the_answer
{
public:
    auto operator()() const
    {
        return "The answer is: " + std::to_string(number);
    }
};

#define CHECK(a) (a() == "The answer is: 42")
```

在前面的代码中，我们定义了一个头文件，定义了一个名为`the_answer`的类模板。要实现这个模板，我们必须包含`string`库。我们还在这个头文件中添加了一个宏来测试我们的类。我们可以这样使用这个头文件：

```cpp
#include <iostream>
#include "header.h"

int main(void)
{
    the_answer<42> is;
    std::cout << is() << '\n';
}
```

如前面的代码片段所示，我们包括了我们的头文件，创建了我们模板类的一个实例，并用它输出了一条消息。执行时，我们得到了以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/bdf986f5-0d0d-4ff1-a0f9-edbf1528f356.png)

尽管这是一个简单的例子，展示了一个实现 C++函数对象的类模板，但这段代码存在一些问题：

+   `the_answer`的实现取决于`string`库。这意味着每当你使用`header.h`时，你不仅包含了`the_answer`的定义，还包含了`string`库的完整定义，包括它的所有依赖项。这种类型的依赖链导致了大量的构建时间成本。

+   `CHECK()`宏也对客户端可访问。在 C++中，没有办法给宏命名空间，这导致了宏冲突的可能性。

+   前面的例子很小，因此很容易编译，但假设我们的头文件有`30,000`行模板代码，混合了几个自己的包含。现在，假设我们必须在数百个源文件中包含我们的头文件。这种情况的结果将是非常长的编译时间，因为每次编译一个源文件时，它都必须一遍又一遍地重新编译相同的庞大头文件。

要了解 C++模块如何解决这些问题，让我们看看使用模块的相同代码会是什么样子：

```cpp
import std.string;
export module answers;

export
template<size_t number>
class the_answer
{
public:
    auto operator()() const
    {
        return "The answer is: " + std::to_string(number);
    }
};

#define CHECK(a) (a() == "The answer is: 42")
```

如前面的代码片段所示，我们的自定义库包括了字符串的定义，然后使用`export`模块创建了一个名为`answers`的新 C++模块。然后我们使用`export`定义定义了我们的类模板。每当一个头文件被编译（实际上，每当任何代码被编译）时，编译器通常首先将人类可读的 C++语法转换为一种叫做**中间表示**（**IR**）的东西。然后将这个 IR 转换为二进制汇编。问题在于头文件包含了无法转换为这种表示的代码（如宏和包含），这意味着每次编译器看到一个头文件时，它都必须将代码转换为 IR，然后再转换为二进制。

C++模块提供了一种语法和一组规则，使编译器能够将头文件转换为 IR，并将这个 IR 的结果与其余的对象文件一起存储。编译器可以使用这个 IR 多次，无需不断执行 IR 转换过程的代码。要了解前面的代码如何使用，让我们看看以下内容：

```cpp
import answers;
import std.core;

int main(void)
{
    the_answer<42> is;
    std::cout << is();
}
```

如图所示，我们包括了`std::cout`的定义和我们的`answers`模块。不同之处在于`main()`函数不必将`answers`和`std.core`的定义从 C++语法转换为编译器的 IR，从而减少了`main()`源文件的编译时间。`main()`源文件还可以创建一个名为`CHECK()`的宏，而不会与我们的`answers`模块中的相同宏发生冲突，因为宏无法被导出。

# 引入 std::span，数组的新视图

在这个示例中，我们将学习如何使用`std::span`，这是 C++20 中的一个新功能。这个示例很重要，因为`std::span`是 Guideline Support Library 的`gsl::span`的后代，它是用于确保你的 C++符合核心指导方针的库的核心组件。在这个示例中，我们不仅介绍了`std::span`，还解释了如何在自己的代码中使用它，以及为什么它有助于封装一个带有大小的数组，并为处理数组提供了一个方便的 API。

# 准备就绪

开始之前，请确保满足所有技术要求，包括安装 Ubuntu 19.04 或更高版本，并在终端窗口中运行以下命令：

```cpp
> sudo apt-get install build-essential git cmake
```

这将确保您的操作系统具有编译和执行本示例的正确工具。完成后，打开一个新的终端。我们将使用此终端来下载、编译和运行我们的示例。

# 如何做到...

您需要执行以下步骤来尝试本示例：

1.  从新的终端运行以下命令以下载源代码：

```cpp
> cd ~/
> git clone https://github.com/PacktPublishing/Advanced-CPP-CookBook.git
> cd Advanced-CPP-CookBook/chapter13
```

1.  要编译源代码，请运行以下命令：

```cpp
> cmake .
> make recipe03_examples
```

1.  编译源代码后，您可以通过运行以下命令执行本示例中的每个示例：

```cpp
> ./recipe03_example01
4 8 15 16 23 42 

> ./recipe03_example02
4 8 15 16 23 42 

> ./recipe03_example03
4 8 15 16 23 42 

> ./recipe03_example04
4 8 15 16 23 42 

> ./recipe03_example05
size: 6
size (in bytes): 24
size: 6
size (in bytes): 24
size: 6
size (in bytes): 24

> ./recipe03_example06
42 
```

在下一节中，我们将逐个介绍这些示例，并解释每个示例程序的作用，以及它与本示例中所教授的课程的关系。

# 工作原理...

在本示例中，我们将探讨`std::span`是什么以及为什么需要它。在 C++（甚至在 C 中），要将数组传递给函数，实现如下：

```cpp
void foo(const int *array, size_t size)
{
    for (auto i = 0; i < size; i++) {
        std::cout << array[i] << ' ';
    }

    std::cout << '\n';
}
```

如前面的示例所示，我们创建了一个名为`foo()`的函数，该函数接受一个指向数组的指针以及数组的大小。然后我们使用这些信息将数组的内容输出到`stdout`。

我们可以按以下方式执行此函数：

```cpp
int main(void)
{
    int array[] = {4, 8, 15, 16, 23, 42};
    foo(array, sizeof(array)/sizeof(array[0]));
}
```

这将产生以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/94681bc8-2828-4927-8427-fec635cdd27a.png)

前面的代码问题在于它不符合 C++核心准则。具体来说，我们被迫独立存储数组的大小。如果数组和其大小不同步（在大型项目中可能会发生），这可能会导致问题。指针与数组相关联还阻止了使用范围`for`循环，这意味着我们必须手动遍历数组，这也可能导致潜在的稳定性问题，如果`for`循环没有正确构造。最后，我们需要手动计算数组的大小，这是一个容易出错的操作，使用`sizeof()`。

解决此问题的一种方法是使用模板函数，如下所示：

```cpp
template<size_t N>
void foo(const int (&array)[N])
{
    for (auto i = 0; i < N; i++) {
        std::cout << array[i] << ' ';
    }

    std::cout << '\n';
}
```

如前面的代码片段所示，我们定义了一个模板函数，该函数接受大小为`N`的整数数组的引用。然后我们可以使用`N`来遍历这个数组。我们甚至可以在数组上使用范围`for`循环，因为编译器知道数组的大小是在编译时确定的。这段代码可以这样使用：

```cpp
int main(void)
{
    int array[] = {4, 8, 15, 16, 23, 42};
    foo(array);
}
```

如此所示，我们进行了几项改进。我们不再传递可能导致`NULL`指针违规的指针。我们不再使用`sizeof()`手动计算数组的大小，也不再需要独立存储数组的大小。前面的代码问题在于每次数组的大小发生变化时，我们必须编译一个完全不同版本的`foo()`函数。如果`foo()`函数很大，这可能是一个问题。此代码还不支持动态分配的数组（即数组是否使用`std::unique_ptr`分配）。

为了解决这个问题，C++20 添加了`std::span`类。查看以下示例：

```cpp
void foo(const std::span<int> &s)
{
    for (auto i = 0; i < s.size(); i++) {
        std::cout << s[i] << ' ';
    }

    std::cout << '\n';
}
```

如前面的代码片段所示，我们使用`std::span`创建了`foo()`函数，它存储了一个整数数组。与大多数其他 C++容器一样，我们可以获取数组的大小，并且可以使用下标运算符访问数组的各个元素。要使用此函数，我们只需像使用模板函数一样调用它，如下所示：

```cpp
int main(void)
{
    int array[] = {4, 8, 15, 16, 23, 42};
    foo(array);
}
```

使用`std::span`，我们现在可以为不同大小的数组提供相同的`foo()`函数，并且甚至可以使用动态内存（即`std::unique_ptr`）分配数组，而无需重新实现`foo()`函数。范围`for`循环甚至可以正常工作：

```cpp
void foo(const std::span<int> &s)
{
    for (const auto &elem : s) {
        std::cout << elem << ' ';
    }

    std::cout << '\n';
}
```

使用动态内存和`foo()`，我们可以这样做：

```cpp
int main(void)
{
    auto ptr1 = new int[6]();
    foo({ptr1, 6});
    delete [] ptr1;

    std::vector<int> v(6);
    foo({v.data(), v.size()});

    auto ptr2 = std::make_unique<int>(6);
    foo({ptr2.get(), 6});
}
```

如前面的示例所示，我们使用三种不同类型的动态创建的内存运行了`foo()`函数。第一次运行`foo()`时，我们使用`new()`/`delete()`分配了内存。如果您试图保持符合 C++核心准则，您可能对这种方法不感兴趣。第二和第三种方法分配了使用`std::vector`或`std::unique_ptr`的内存。两者都有其固有的缺点：

+   `std::vector`存储自己的`size()`，但也存储其容量，并且默认初始化内存。

+   `std::unique_ptr`不存储自己的`size()`，它也会默认初始化内存。

目前，C++没有能够分配未初始化内存的动态数组并存储数组大小（仅存储大小）的数组类型。然而，`std::span`可以与前述方法的某些组合一起使用，根据您的需求来管理数组。

还应该注意，在前面的示例中，当我们创建`std::span`时，我们根据元素的总数而不是字节的总数传递了数组的大小。`std::span`能够为您提供这两者，如下所示：

```cpp
void foo(const std::span<int> &s)
{
    std::cout << "size: " << s.size() << '\n';
    std::cout << "size (in bytes): " << s.size_bytes() << '\n';
}
```

如果我们运行上述的`foo()`实现，并使用前面提到的动态内存示例，我们会得到以下结果：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/5cd2b8ea-8b69-4e72-8ea6-39e36b056750.png)

最后，我们可以使用 span 来创建额外的子 span，如下所示：

```cpp
void foo2(const std::span<int> &s)
{
    for (const auto &elem : s) {
        std::cout << elem << ' ';
    }

    std::cout << '\n';
}
```

在前面的`foo2()`函数中，我们使用 span 并使用范围`for`循环输出其所有元素。然后我们可以使用以下方法创建子 span：

```cpp
void foo1(const std::span<int> &s)
{
    foo2(s.subspan(5, 1));
}
```

`subspan()`函数的结果是另一个`std::span`。不同之处在于它内部存储的指针已经提前了`5`个元素，并且 span 存储的`size()`现在是`1`。

# 在 C++20 中使用范围

在本教程中，我们将学习如何使用 C++ Ranges，这是 C++20 带来的新功能集。Ranges 提供了方便的函数，用于处理模拟对象或值范围的任何内容。例如，4, 8, 15, 16, 23, 42 是一个整数范围。在当今的 C++中，根据您的操作，处理范围可能会很麻烦。本教程很重要，因为 C++范围消除了与处理范围相关的许多复杂性，确保您的代码随着时间的推移更容易阅读和维护。

# 准备工作

开始之前，请确保满足所有技术要求，包括安装 Ubuntu 19.04 或更高版本，并在终端窗口中运行以下命令：

```cpp
> sudo apt-get install build-essential git cmake
```

这将确保您的操作系统具有适当的工具来编译和执行本教程中的示例。完成后，打开一个新的终端。我们将使用此终端来下载、编译和运行我们的示例。

# 如何做...

要执行此操作，请执行以下步骤：

1.  从新的终端运行以下命令以下载源代码：

```cpp
> cd ~/
> git clone https://github.com/PacktPublishing/Advanced-CPP-CookBook.git
> cd Advanced-CPP-CookBook/chapter13
```

1.  要编译源代码，请运行以下命令：

```cpp
> cmake .
> make recipe04_examples
```

1.  源代码编译后，您可以通过运行以下命令执行本教程中的每个示例：

```cpp
> ./recipe04_example01 
1

> ./recipe04_example02
42

> ./recipe04_example03
42

> ./recipe04_example04
4 8 15 16 23 42 

> ./recipe04_example05
4 8 15 16 23 42 

> ./recipe04_example06
4 8 15 16 23 42 
```

在下一节中，我们将逐个介绍这些示例，并解释每个示例程序的作用以及它与本教程中所教授的课程的关系。

# 工作原理...

C++ Ranges 是 C++20 的一个受欢迎的补充，因为它提供了一种简单的方法来处理任何对象或值列表。为了最好地解释这是如何工作的，让我们看一下以下示例（请注意，在这些示例中，我们将使用 Ranges v3，而我们等待 GCC 支持 Ranges，因为 v3 是 C++20 采用的实现）：

```cpp
#include <iostream>
#include <range/v3/algorithm/count.hpp>

int main(void)
{
    auto list = {4, 8, 15, 16, 23, 42};
    std::cout << ranges::count(list, 42) << '\n';
}
```

如前面的代码片段所示，我们已经创建了一个整数列表（在这种特定情况下，我们创建了一个简单的初始化列表）。然后我们使用`ranges::count()`函数来计算列表中值为`42`的出现次数，得到以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/29bc917b-ce5c-4907-ac11-e21b6e099e03.png)

范围也可以用于搜索：

```cpp
#include <iostream>
#include <range/v3/algorithm/find.hpp>

int main(void)
{
    auto list = {4, 8, 15, 16, 23, 42};
    if (auto i = ranges::find(list, 42); i != ranges::end(list)) {
        std::cout << *i << '\n';
    }
}
```

如前面的示例所示，我们创建了相同的整数初始化列表，并使用 ranges 返回一个迭代器。这个迭代器可以用来遍历列表或获取定位的值。初始化列表已经支持迭代器，而 Ranges 所做的一件事是将这个功能扩展到其他类型，包括简单的 C 风格数组：

```cpp
#include <iostream>
#include <range/v3/algorithm/find.hpp>

int main(void)
{
    int list[] = {4, 8, 15, 16, 23, 42};
    if (auto i = ranges::find(list, 42); i != ranges::end(list)) {
        std::cout << *i << '\n';
    }
}
```

前面的示例使用了 C 风格数组而不是初始化列表，并且如所示，Ranges 提供了一个迭代器来处理 C 风格数组，这是目前不可能的。

Ranges 还提供了一些方便的算法。例如，考虑以下代码：

```cpp
#include <iostream>
#include <range/v3/algorithm/for_each.hpp>

int main(void)
{
    auto list = {4, 8, 15, 16, 23, 42};

    ranges::for_each(list, [](const int &val){
        std::cout << val << ' ';
    });

    std::cout << '\n';
}
```

在前面的示例中，我们创建了一个整数列表。然后我们循环遍历整数的整个范围，并在这个列表上执行一个 lambda。虽然这可以使用传统的循环来完成，比如 C++11 中添加的基于范围的循环，`for_each`可以简化您的逻辑（取决于您的用例）。

Ranges 还提供了将一个列表转换为另一个列表的能力。考虑以下示例：

```cpp
#include <iostream>
#include <range/v3/view/transform.hpp>

class my_type
{
    int m_i;

public:
    my_type(int i) :
        m_i{i}
    { }

    auto get() const
    {
        return m_i;
    }
};
```

我们将从创建我们自己的类型开始这个示例。如前面的代码片段所示，我们有一个名为`my_type`的新类型，它是用一个整数构造的，并使用`get()`函数返回整数。然后我们可以扩展我们之前的示例，将我们的整数列表转换为我们自定义类型的列表，如下所示：

```cpp
int main(void)
{
    using namespace ranges::views;

    auto list1 = {4, 8, 15, 16, 23, 42};
    auto list2 = list1 | transform([](int val){
        return my_type(val);
    });

    for(const auto &elem : list2) {
        std::cout << elem.get() << ' ';
    }

    std::cout << '\n';
}
```

如前面的示例所示，我们创建了初始的整数列表，然后使用`ranges::views::transform`函数将这个列表转换为我们自定义类型的第二个列表。然后我们可以使用传统的基于范围的`for`循环来迭代这个新列表。

最后，Ranges 还提供了一些操作，让您实际修改现有的范围。例如，考虑以下代码：

```cpp
#include <vector>
#include <iostream>
#include <range/v3/action/sort.hpp>

int main(void)
{
    using namespace ranges;

    std::vector<int> list = {4, 42, 15, 8, 23, 16};
    list |= actions::sort;

    for(const auto &elem : list) {
        std::cout << elem << ' ';
    }

    std::cout << '\n';
}
```

在前面的示例中，我们使用`actions::sort`函数对我们的向量列表进行排序，得到以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/2017152b-aba7-4295-99e7-bbbadae2dde7.png)

如前面的示例所示，C++20 Ranges 为我们提供了一种简单的方法，使用管道运算符而不是使用`std::sort`来对`std::vector`进行排序，显式定义我们的起始和结束迭代器。

# 学习如何在 C++20 中使用协程

在这个示例中，我们将简要介绍 C++20 中即将推出的一个特性，称为协程。与 C++20 中正在添加的其他一些特性不同，协程在当前的 C++中是不可能的。协程提供了暂停函数执行和产生结果的能力。一旦结果被使用，函数可以在离开的地方恢复执行。这个示例很重要，因为 C++20 将为 C++添加一流支持（即新关键字）来支持协程，很可能这个新特性将在不久的将来开始出现在库和示例中。

# 准备工作

在开始之前，请确保满足所有的技术要求，包括安装 Ubuntu 19.04 或更高版本，并在终端窗口中运行以下命令：

```cpp
> sudo apt-get install build-essential git cmake
```

这将确保您的操作系统具有正确的工具来编译和执行本教程中的示例。完成后，打开一个新的终端。我们将使用这个终端来下载、编译和运行我们的示例。

# 如何做...

要尝试这个示例，请执行以下步骤：

1.  从一个新的终端，运行以下命令来下载源代码：

```cpp
> cd ~/
> git clone https://github.com/PacktPublishing/Advanced-CPP-CookBook.git
> cd Advanced-CPP-CookBook/chapter13
```

1.  要编译源代码，请运行以下命令：

```cpp
> cmake .
> make recipe05_examples
```

1.  一旦源代码被编译，您可以通过运行以下命令来执行本教程中的每个示例：

```cpp
> ./recipe05_example01 
0 2 4 6 8 10 
```

在下一节中，我们将逐个介绍这些示例，并解释每个示例程序的作用以及它与本教程所教授的课程的关系。

# 它是如何工作的...

如前所述，协程提供了暂停和恢复函数执行的能力。为了演示这在 C++20 中将如何工作，我们将简要地看一个简单的例子：

```cpp
auto
even_numbers(size_t s, size_t e)
{
    std::vector<int> nums;

    if (s % 2 != 0 || e % 2 != 0) {
        std::terminate();
    }

    for (auto i = s; i <= e; i += 2) {
        nums.push_back(i);
    }

    return nums;
}
```

在上面的例子中，我们创建了一个名为`even_numbers()`的函数，给定一个范围，返回偶数的`std::vector`。我们可以这样使用这个函数：

```cpp
int main(void)
{
    for (const auto &num : even_numbers(0, 10)) {
        std::cout << num << ' ';
    }

    std::cout << '\n';
}
```

这导致了以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/e8884a7b-b906-4296-a575-a6701c548375.png)

前面实现的问题在于这段代码需要使用`std::vector`来创建一个数字范围进行迭代。有了协程，我们将能够实现这个函数如下：

```cpp
generator<int>
even_numbers(size_t s, size_t e)
{
    if (s % 2 != 0 || e % 2 != 0) {
        std::terminate();
    }

    for (auto i = s; i < e; i += 2) {
        co_yield i;
    }

    co_return e;
}
```

从前面的代码中，我们看到了以下内容：

+   现在我们不再返回`std::vector`，而是返回`generator<int>`。

+   当我们在循环中遍历每个偶数值时，我们调用`co_yield`。这会导致`even_numbers()`函数返回提供的值，并保存它的位置。

+   一旦`even_numbers()`函数被恢复，它会回到最初执行`co_yield`的地方，这意味着函数现在可以继续执行并产生下一个偶数。

+   这个过程会一直持续，直到`for`循环结束并且协程返回最后一个偶数。

要使用这个函数，我们的`main()`代码不需要改变：

```cpp
int main(void)
{
    for (const auto &num : even_numbers(0, 10)) {
        std::cout << num << ' ';
    }

    std::cout << '\n';
}
```

不同之处在于我们不再返回`std::vector`，而是返回协程提供的整数。
