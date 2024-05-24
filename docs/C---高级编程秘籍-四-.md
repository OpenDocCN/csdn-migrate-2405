# C++ 高级编程秘籍（四）

> 原文：[`annas-archive.org/md5/24e080e694c59b3f8e0220d0902724b0`](https://annas-archive.org/md5/24e080e694c59b3f8e0220d0902724b0)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：调试和测试

在本章中，您将学习如何正确测试和调试您的 C++应用程序。这很重要，因为没有良好的测试和调试，您的 C++应用程序很可能包含难以检测的错误，这将降低它们的整体可靠性、稳定性和安全性。

本章将从全面概述单元测试开始，这是在单元级别测试代码的行为，并且还将介绍如何利用现有库加快编写测试的过程。接下来，它将演示如何使用 ASAN 和 UBSAN 动态分析工具来检查内存损坏和未定义行为。最后，本章将简要介绍如何在自己的代码中利用`NDEBUG`宏来添加调试逻辑以解决问题。

本章包含以下教程：

+   掌握单元测试

+   使用 ASAN，地址检查器

+   使用 UBSAN，未定义行为检查器

+   使用`#ifndef NDEBUG`条件性地执行额外的检查

# 技术要求

要编译和运行本章中的示例，您必须具有管理访问权限的计算机，该计算机运行 Ubuntu 18.04，并具有功能正常的互联网连接。在运行这些示例之前，您必须安装以下内容：

```cpp
> sudo apt-get install build-essential git cmake
```

如果这是安装在 Ubuntu 18.04 以外的任何操作系统上，则需要 GCC 7.4 或更高版本和 CMake 3.6 或更高版本。

本章的代码文件可以在[`github.com/PacktPublishing/Advanced-CPP-CookBook/tree/master/chapter07`](https://github.com/PacktPublishing/Advanced-CPP-CookBook/tree/master/chapter07)找到。

# 掌握单元测试

在这个教程中，我们将学习如何对我们的 C++代码进行单元测试。有几种不同的方法可以确保您的 C++代码以可靠性、稳定性、安全性和规范性执行。

单元测试是在基本单元级别测试代码的行为，是任何测试策略的关键组成部分。这个教程很重要，不仅因为它将教会您如何对代码进行单元测试，还因为它将解释为什么单元测试如此关键，以及如何利用现有库加快对 C++代码进行单元测试的过程。

# 准备工作

在开始之前，请确保满足所有技术要求，包括安装 Ubuntu 18.04 或更高版本，并在终端窗口中运行以下命令：

```cpp
> sudo apt-get install build-essential git cmake
```

这将确保您的操作系统具有编译和执行本教程中示例所需的适当工具。完成后，打开一个新的终端。我们将使用这个终端来下载、编译和运行我们的示例。

# 如何做...

按照以下步骤进行教程：

1.  从新的终端运行以下命令以下载源代码：

```cpp
> cd ~/
> git clone https://github.com/PacktPublishing/Advanced-CPP-CookBook.git
> cd Advanced-CPP-CookBook/chapter07
```

1.  要编译源代码，请运行以下命令：

```cpp
> cmake .
> make recipe01_examples
```

1.  源代码编译完成后，您可以通过运行以下命令来执行本教程中的每个示例：

```cpp
> ./recipe01_example01
===========================================================================
All tests passed (1 assertion in 1 test case)

> ./recipe01_example02
===========================================================================
All tests passed (6 assertions in 1 test case)

> ./recipe01_example03
===========================================================================
All tests passed (8 assertions in 1 test case)

> ./recipe01_example04
===========================================================================
All tests passed (1 assertion in 1 test case)

> ./recipe01_example05
...
===========================================================================
test cases: 1 | 1 passed
assertions: - none -

> ./recipe01_example06
...
===========================================================================
test cases: 5 | 3 passed | 2 failed
assertions: 8 | 6 passed | 2 failed

> ./recipe01_example07
===========================================================================
test cases: 1 | 1 passed
assertions: - none -

> ./recipe01_example08
===========================================================================
All tests passed (3 assertions in 1 test case)
```

在下一节中，我们将逐个介绍这些示例，并解释每个示例程序的作用以及它与本教程所教授的课程的关系。

# 它是如何工作的...

仅仅编写您的 C++应用程序，并希望它按预期工作而不进行任何测试，肯定会导致可靠性、稳定性和安全性相关的错误。这个教程很重要，因为在发布之前测试您的应用程序可以确保您的应用程序按预期执行，最终为您节省时间和金钱。

有几种不同的方法可以测试您的代码，包括系统级、集成、长期稳定性以及静态和动态分析等。在这个教程中，我们将专注于**单元测试**。单元测试将应用程序分解为功能**单元**，并测试每个单元以确保其按预期执行。通常，在实践中，每个函数和对象（即类）都是一个应该独立测试的单元。

有几种不同的理论，关于如何执行单元测试，整本书都是关于这个主题的。有些人认为应该测试函数或对象中的每一行代码，利用覆盖率工具来确保合规性，而另一些人认为单元测试应该是需求驱动的，采用黑盒方法。一种常见的开发过程称为**测试驱动开发**，它规定所有测试，包括单元测试，都应该在编写任何源代码之前编写，而**行为驱动开发**则进一步采用特定的、以故事为驱动的方法来进行单元测试。

每种测试模型都有其优缺点，您选择的方法将基于您正在编写的应用程序类型、您遵循的软件开发过程类型以及您可能需要或不需要遵循的任何政策。不管您做出什么选择，单元测试可能会成为您测试方案的一部分，这个示例将为您提供如何对 C++应用程序进行单元测试的基础。

尽管可以使用标准的 C++进行单元测试（例如，这就是`libc++`进行单元测试的方法），但单元测试库有助于简化这个过程。在这个示例中，我们将利用`Catch2`单元测试库，可以在以下网址找到

[`github.com/catchorg/Catch2.git`](https://github.com/catchorg/Catch2.git)。

尽管我们将回顾 Catch2，但正在讨论的原则适用于大多数可用的单元测试库，甚至适用于标准的 C++，如果您选择不使用辅助库。要利用 Catch2，只需执行以下操作：

```cpp
> git clone https://github.com/catchorg/Catch2.git catch
> cd catch
> mkdir build
> cd build
> cmake ..
> make
> sudo make install
```

您还可以使用 CMake 的`ExternalProject_Add`，就像我们在 GitHub 上的示例中所做的那样，来利用库的本地副本。

要了解如何使用 Catch2，让我们看下面这个简单的例子：

```cpp
#define CATCH_CONFIG_MAIN
#include <catch.hpp>

TEST_CASE("the answer")
{
   CHECK(true);
}
```

运行时，我们看到以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/82b7302a-7165-4cf8-92f1-83a6491e786f.png)

在前面的例子中，我们首先定义了`CATCH_CONFIG_MAIN`。这告诉 Catch2 库我们希望它为我们创建`main()`函数。这必须在我们包含 Catch2`include`语句之前定义，这是我们在前面的代码中所做的。

下一步是定义一个测试用例。每个单元都被分解成测试单元，测试所讨论的单元。每个测试用例的粒度由您决定：有些人选择为每个被测试的单元设置一个单独的测试用例，而其他人，例如，选择为每个被测试的函数设置一个测试用例。`TEST_CASE()`接受一个字符串，允许您提供测试用例的描述，当测试失败时，这对于帮助您确定测试代码中失败发生的位置是有帮助的，因为 Catch2 将输出这个字符串。我们简单示例中的最后一步是使用`CHECK()`宏。这个宏执行一个特定的测试。每个`TEST_CASE()`可能会有几个`CHECK()`宏，旨在为单元提供特定的输入，然后验证生成的输出。

一旦编译和执行，单元测试库将提供一些输出文本，描述如何执行测试。在这种情况下，库说明所有测试都通过了，这是期望的结果。

为了更好地理解如何在自己的代码中利用单元测试，让我们看下面这个更复杂的例子：

```cpp
#define CATCH_CONFIG_MAIN
#include <catch.hpp>

#include <vector>
#include <iostream>
#include <algorithm>

TEST_CASE("sort a vector")
{
    std::vector<int> v{4, 8, 15, 16, 23, 42};
    REQUIRE(v.size() == 6);

    SECTION("sort descending order") {
        std::sort(v.begin(), v.end(), std::greater<int>());

        CHECK(v.front() == 42);
        CHECK(v.back() == 4);
    }

    SECTION("sort ascending order") {
        std::sort(v.begin(), v.end(), std::less<int>());

        CHECK(v.front() == 4);
        CHECK(v.back() == 42);
    }
}
```

像前面的例子一样，我们使用`CATCH_CONFIG_MAIN`宏包含 Catch2，然后定义一个带有描述的单个测试用例。在这个例子中，我们正在测试对向量进行排序的能力，所以这是我们提供的描述。我们在测试中要做的第一件事是创建一个包含预定义整数列表的整数向量。

接下来我们使用`REQUIRE()`宏进行测试，确保向量中有`6`个元素。`REQUIRE()`宏类似于`CHECK()`，因为两者都检查宏内部的语句是否为真。不同之处在于，`CHECK()`宏将报告错误，然后继续执行，而`REQUIRE()`宏将停止执行，中止单元测试。这对于确保单元测试基于测试可能做出的任何假设正确构建是有用的。随着时间的推移，单元测试的成熟度越来越重要，其他程序员会添加和修改单元测试，以确保单元测试不会引入错误，因为没有比测试和调试单元测试更糟糕的事情了。

`SECTION()`宏用于进一步分解我们的测试，并提供添加每个测试的常见设置代码的能力。在前面的示例中，我们正在测试向量的`sort()`函数。`sort()`函数可以按不同的方向排序，这个单元测试必须验证。如果没有`SECTION()`宏，如果测试失败，将很难知道失败是由于按升序还是按降序排序。此外，`SECTION()`宏确保每个测试不会影响其他测试的结果。

最后，我们使用`CHECK()`宏来确保`sort()`函数按预期工作。单元测试也应该检查异常。在下面的示例中，我们将确保异常被正确抛出：

```cpp
#define CATCH_CONFIG_MAIN
#include <catch.hpp>

#include <vector>
#include <iostream>
#include <algorithm>

void foo(int val)
{
    if (val != 42) {
        throw std::invalid_argument("The answer is: 42");
    }
}

TEST_CASE("the answer")
{
    CHECK_NOTHROW(foo(42));
    REQUIRE_NOTHROW(foo(42));

    CHECK_THROWS(foo(0));
    CHECK_THROWS_AS(foo(0), std::invalid_argument);
    CHECK_THROWS_WITH(foo(0), "The answer is: 42");

    REQUIRE_THROWS(foo(0));
    REQUIRE_THROWS_AS(foo(0), std::invalid_argument);
    REQUIRE_THROWS_WITH(foo(0), "The answer is: 42");
}
```

与前面的示例一样，我们定义了`CATCH_CONFIG_MAIN`宏，添加了我们需要的包含文件，并定义了一个`TEST_CASE()`。我们还定义了一个`foo()`函数，如果`foo()`函数的输入无效，则会抛出异常。

在我们的测试用例中，我们首先使用有效的输入测试`foo()`函数。由于`foo()`函数没有输出（即函数返回`void`），我们通过使用`CHECK_NOTHROW()`宏来确保函数已经正确执行，确保没有抛出异常。值得注意的是，与`CHECK()`宏一样，`CHECK_NOTHROW()`宏有等效的`REQUIRE_NOTHROW()`，如果检查失败，将停止执行。

最后，我们确保`foo()`函数在其输入无效时抛出异常。有几种不同的方法可以做到这一点。`CHECK_THROWS()`宏只是确保抛出了异常。`CHECK_THROWS_AS()`宏确保不仅抛出了异常，而且异常是`std::runtime_error`类型。这两者都必须为测试通过。最后，`CHECK_THROWS_WITH()`宏确保抛出异常，并且异常的`what()`字符串返回与我们期望的异常匹配。与其他版本的`CHECK()`宏一样，每个宏也有`REQUIRE()`版本。

尽管 Catch2 库提供了宏，让您深入了解每种异常类型的具体细节，但应该注意，除非异常类型和字符串在您的 API 要求中明确定义，否则应该使用通用的`CHECK_THROWS()`宏。例如，规范中定义了`at()`函数在索引无效时始终返回`std::out_of_range`异常。在这种情况下，应该使用`CHECK_THROWS_AS()`宏来确保`at()`函数符合规范。规范中未指定此异常返回的字符串，因此应避免使用`CHECK_THROWS_WITH()`。这很重要，因为编写单元测试时常见的错误是编写过度规范的单元测试。过度规范的单元测试通常在被测试的代码更新时必须进行更新，这不仅成本高，而且容易出错。

单元测试应该足够详细，以确保单元按预期执行，但又足够通用，以确保对源代码的修改不需要更新单元测试本身，除非 API 的要求发生变化，从而产生一组能够长期使用的单元测试，同时仍然提供确保可靠性、稳定性、安全性甚至合规性所必需的测试。

一旦您有一组单元测试来验证每个单元是否按预期执行，下一步就是确保在修改代码时执行这些单元测试。这可以手动完成，也可以由**持续集成**（**CI**）服务器自动完成，例如 TravisCI；然而，当您决定这样做时，请确保单元测试返回正确的错误代码。在前面的例子中，当单元测试通过并打印简单的字符串表示所有测试都通过时，单元测试本身退出时使用了`EXIT_SUCCESS`。对于大多数 CI 来说，这已经足够了，但在某些情况下，让 Catch2 以易于解析的格式输出结果可能是有用的。

例如，考虑以下代码：

```cpp
#define CATCH_CONFIG_MAIN
#include <catch.hpp>

TEST_CASE("the answer")
{
    CHECK(true);
}
```

让我们用以下方式运行：

```cpp
> ./recipe01_example01 -r xml
```

如果我们这样做，我们会得到以下结果：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/181d1cbf-5814-44ae-8f95-b7577da6c8e5.png)

在前面的例子中，我们创建了一个简单的测试用例（与本配方中的第一个例子相同），并指示 Catch2 使用`-r xml`选项将测试结果输出为 XML。Catch2 有几种不同的输出格式，包括 XML 和 JSON。

除了输出格式之外，Catch2 还可以用来对我们的代码进行基准测试。例如，考虑以下代码片段：

```cpp
#define CATCH_CONFIG_MAIN
#define CATCH_CONFIG_ENABLE_BENCHMARKING
#include <catch.hpp>

#include <vector>
#include <iostream>

TEST_CASE("the answer")
{
    std::vector<int> v{4, 8, 15, 16, 23, 42};

    BENCHMARK("sort vector") {
        std::sort(v.begin(), v.end());
    };
}
```

在上面的例子中，我们创建了一个简单的测试用例，对预定义的向量数字进行排序。然后我们在`BENCHMARK()`宏中对这个列表进行排序，当执行时会得到以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/6ba0ee12-7624-4e52-897e-5182f5487f0e.png)

如前面的屏幕截图所示，Catch2 执行了该函数多次，平均花费`197`纳秒来对向量进行排序。`BENCHMARK()`宏对于确保代码不仅按预期执行并给出特定输入的正确输出，而且还确保代码在特定时间内执行非常有用。配合更详细的输出格式，比如 XML 或 JSON，这种类型的信息可以用来确保随着源代码的修改，生成的代码执行时间保持不变或更快。

为了更好地理解单元测试如何真正改进您的 C++，我们将用两个额外的例子来结束这个配方，这些例子旨在提供更真实的场景。

在第一个例子中，我们将创建一个**向量**。与 C++中的`std::vector`不同，它是一个动态的 C 风格数组，数学中的向量是*n*维空间中的一个点（在我们的例子中，我们将其限制为 2D 空间），其大小是点与原点（即 0,0）之间的距离。我们在示例中实现这个向量如下：

```cpp
#define CATCH_CONFIG_MAIN
#include <catch.hpp>

#include <cmath>
#include <climits>

class vector
{
    int m_x{};
    int m_y{};
```

除了通常的宏和包含之外，我们要做的第一件事是定义一个带有`x`和`y`坐标的类：

```cpp
public:

    vector() = default;

    vector(int x, int y) :
        m_x{x},
        m_y{y}
    { }

    auto x() const
    { return m_x; }

    auto y() const
    { return m_y; }

    void translate(const vector &p)
    {
        m_x += p.m_x;
        m_y += p.m_y;
    }

    auto magnitude()
    {
        auto a2 = m_x * m_x;
        auto b2 = m_y * m_y;

        return sqrt(a2 + b2);
    }
};
```

接下来，我们添加一些辅助函数和构造函数。默认构造函数创建一个没有方向或大小的向量，因为*x*和*y*被设置为原点。为了创建具有方向和大小的向量，我们还提供了另一个构造函数，允许您提供向量的初始*x*和*y*坐标。为了获取向量的方向，我们提供了返回向量*x*和*y*值的 getter。最后，我们提供了两个辅助函数。第一个辅助函数**translates**向量，在数学上是改变向量的*x*和*y*坐标的另一个术语。最后一个辅助函数返回向量的大小，即如果向量的*x*和*y*值用于构造三角形的斜边的长度（也就是说，我们必须使用勾股定理来计算向量的大小）。接下来，我们继续添加运算符，具体如下：

```cpp
bool operator== (const vector &p1, const vector &p2)
{ return p1.x() == p2.x() && p1.y() == p2.y(); }

bool operator!= (const vector &p1, const vector &p2)
{ return !(p1 == p2); }

constexpr const vector origin;
```

我们添加了一些等价运算符，用于检查两个向量是否相等。我们还定义了一个表示原点的向量，其*x*和*y*值都为 0。

为了测试这个向量，我们添加了以下测试：

```cpp
TEST_CASE("default constructor")
{
    vector p;

    CHECK(p.x() == 0);
    CHECK(p.y() == 0);
}

TEST_CASE("origin")
{
    CHECK(vector{0, 0} == origin);
    CHECK(vector{1, 1} != origin);
}

TEST_CASE("translate")
{
    vector p{-4, -8};
    p.translate({46, 50});

    CHECK(p.x() == 42);
    CHECK(p.y() == 42);
}

TEST_CASE("magnitude")
{
    vector p(1, 1);
    CHECK(Approx(p.magnitude()).epsilon(0.1) == 1.4);
}

TEST_CASE("magnitude overflow")
{
    vector p(INT_MAX, INT_MAX);
    CHECK(p.magnitude() == 65536);
}
```

第一个测试确保默认构造的向量实际上是原点。我们的下一个测试确保我们的全局**origin**向量是原点。这很重要，因为我们不应该假设原点是默认构造的，也就是说，未来有人可能会意外地将原点更改为`0,0`之外的其他值。这个测试用例确保原点实际上是`0,0`，这样在未来，如果有人意外更改了这个值，这个测试就会失败。由于原点必须导致*x*和*y*都为 0，所以这个测试并没有过度规定。

接下来，我们测试 translate 和 magnitude 函数。在 magnitude 测试用例中，我们使用`Approx()`宏。这是因为返回的大小是一个浮点数，其大小和精度取决于硬件，并且与我们的测试无关。`Approx()`宏允许我们声明要验证`magnitude()`函数结果的精度级别，该函数使用`epsilon()`修饰符来实际声明精度。在这种情况下，我们只希望验证到小数点后一位。

最后一个测试用例用于演示这些函数的所有输入应该被测试。如果一个函数接受一个整数，那么应该测试所有有效的、无效的和极端的输入。在这种情况下，我们为*x*和*y*都传递了`INT_MAX`。结果的`magnitude()`函数没有提供有效的结果。这是因为计算大小的过程溢出了整数类型。这种类型的错误应该在代码中考虑到（也就是说，您应该检查可能的溢出并抛出异常），或者 API 的规范应该指出这些类型的问题（也就是说，C++规范可能会声明这种类型输入的结果是未定义的）。无论哪种方式，如果一个函数接受一个整数，那么所有可能的整数值都应该被测试，并且这个过程应该对所有输入类型重复。

这个测试的结果如下：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/64400718-2c26-405a-9f0f-f9581dec0119.png)

如前面的屏幕截图所示，该单元测试未通过最后一个测试。如前所述，为了解决这个问题，magnitude 函数应该被更改为在发生溢出时抛出异常，找到防止溢出的方法，或者删除测试并声明这样的输入是未定义的。

在我们的最后一个例子中，我们将演示如何处理不返回值而是操作输入的函数。

让我们通过创建一个写入文件的类和另一个使用第一个类将字符串写入该文件的类来开始这个例子，如下所示：

```cpp
#define CATCH_CONFIG_MAIN
#include <catch.hpp>

#include <string>
#include <fstream>

class file
{
    std::fstream m_file{"test.txt", std::fstream::out};

public:

    void write(const std::string &str)
    {
        m_file.write(str.c_str(), str.length());
    }
};

class the_answer
{
public:

    the_answer(file &f)
    {
        f.write("The answer is: 42\n");
    }
};
```

如前面的代码所示，第一个类写入一个名为`test.txt`的文件，而第二个类将第一个类作为输入，并使用它来向文件中写入一个字符串。

我们测试第二个类如下：

```cpp
TEST_CASE("the answer")
{
    file f;
    the_answer{f};
}
```

前面测试的问题在于我们没有任何`CHECK()`宏。这是因为除了`CHECK_NOTHROW()`之外，我们没有任何需要检查的东西。在这个测试中，我们测试以确保`the_answer{}`类调用`file{}`类和`write()`函数正确。我们可以打开`test.txt`文件并检查它是否用正确的字符串写入，但这是很多工作。这种类型的检查也会过度指定，因为我们不是在测试`file{}`类，我们只是在测试`the_answer{}`类。如果将来我们决定`file{}`类应该写入网络文件而不是磁盘上的文件，单元测试将不得不改变。

为了克服这个问题，我们可以利用一个叫做**mocking**的概念。`Mock`类是一个假装是输入类的类，为单元测试提供了**seams**，允许单元测试验证测试的结果。这与`Stub`不同，后者提供了虚假的输入。不幸的是，与其他语言相比，C++对 mocking 的支持并不好。辅助库，如 GoogleMock，试图解决这个问题，但需要所有可 mock 的类都包含一个 vTable（即继承纯虚拟基类）并在你的代码中定义每个可 mock 的类两次（一次在你的代码中，一次在你的测试中，使用 Google 定义的一组 API）。这远非最佳选择。像 Hippomocks 这样的库试图解决这些问题，但需要一些 vTable 黑魔法，只能在某些环境中工作，并且当出现问题时几乎不可能进行调试。尽管 Hippomocks 可能是最好的选择之一（即直到 C++启用本地 mocking），但以下示例是使用标准 C++进行 mocking 的另一种方法，唯一的缺点是冗长：

```cpp
#define CATCH_CONFIG_MAIN
#include <catch.hpp>

#include <string>
#include <fstream>

class file
{
    std::fstream m_file{"test.txt", std::fstream::out};

public:
    VIRTUAL ~file() = default;

    VIRTUAL void write(const std::string &str)
    {
        m_file.write(str.c_str(), str.length());
    }
};

class the_answer
{
public:
    the_answer(file &f)
    {
        f.write("The answer is: 42\n");
    }
};
```

与我们之前的示例一样，我们创建了两个类。第一个类写入一个文件，而第二个类使用第一个类向该文件写入一个字符串。不同之处在于我们添加了`VIRTUAL`宏。当代码编译到我们的应用程序中时，`VIRTUAL`被设置为空，这意味着它被编译器从代码中移除。然而，当代码在我们的测试中编译时，它被设置为`virtual`，这告诉编译器给类一个 vTable。由于这只在我们的测试期间完成，所以额外的开销是可以接受的。

现在我们的类在我们的测试用例中支持继承，我们可以创建我们的`file{}`类的一个子类版本如下：

```cpp
class mock_file : public file
{
public:
    void write(const std::string &str)
    {
        if (str == "The answer is: 42\n") {
            passed = true;
        }
        else {
            passed = false;
        }
    }

    bool passed{};
};
```

前面的类定义了我们的 mock。我们的 mock 不是写入文件，而是检查特定的字符串是否被写入我们的假文件，并根据测试的结果设置一个全局变量为`true`或`false`。

然后我们可以测试我们的`the_answer{}`类如下：

```cpp
TEST_CASE("the answer")
{
    mock_file f;
    REQUIRE(f.passed == false);

    f.write("The answer is not: 43\n");
    REQUIRE(f.passed == false);

    the_answer{f};
    CHECK(f.passed);
}
```

当执行此操作时，我们会得到以下结果：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/289a2554-23b1-4e41-9c45-6bc8b34eb163.png)

如前面的屏幕截图所示，我们现在可以检查我们的类是否按预期写入文件。值得注意的是，我们使用`REQUIRE()`宏来确保在执行我们的测试之前，mock 处于`false`状态。这确保了如果我们的实际测试被注册为通过，那么它确实已经通过，而不是因为我们测试逻辑中的错误而被注册为通过。

# 使用 ASAN，地址消毒剂

在这个示例中，我们将学习如何利用谷歌的**地址消毒剂**（**ASAN**）——这是一个动态分析工具——来检查代码中的内存损坏错误。这个示例很重要，因为它提供了一种简单的方法来确保你的代码既可靠又稳定，而对你的构建系统的更改数量很少。

# 准备工作

开始之前，请确保满足所有技术要求，包括安装 Ubuntu 18.04 或更高版本，并在终端窗口中运行以下命令：

```cpp
> sudo apt-get install build-essential git cmake
```

这将确保您的操作系统具有编译和执行本食谱中示例所需的适当工具。完成后，打开一个新的终端。我们将使用这个终端来下载、编译和运行我们的示例。

# 如何操作...

按照以下步骤执行该食谱：

1.  从新的终端运行以下命令以下载源代码：

```cpp
> cd ~/
> git clone https://github.com/PacktPublishing/Advanced-CPP-CookBook.git
> cd Advanced-CPP-CookBook/chapter07
```

1.  要编译源代码，请运行以下命令：

```cpp
> cmake -DCMAKE_BUILD_TYPE=ASAN ..
> make recipe02_examples
```

1.  编译源代码后，可以通过运行以下命令执行本食谱中的每个示例：

```cpp
> ./recipe02_example01
...

> ./recipe02_example02
...

> ./recipe02_example03
...

> ./recipe02_example04
...

> ./recipe02_example05
...
```

在下一节中，我们将逐个介绍这些示例，并解释每个示例程序的作用以及它与本食谱中所教授的课程的关系。

# 它是如何工作的...

Google 的地址消毒剂是对 GCC 和 LLVM 编译器的一组修改，以及一组必须在测试时链接到应用程序中的库。为了实现这一点，我们在编译用于测试的代码时必须添加以下编译器标志（但不要将这些标志添加到生产版本中）：

```cpp
-fsanitize=address 
-fno-optimize-sibling-calls 
-fsanitize-address-use-after-scope 
-fno-omit-frame-pointer 
-g -O1
```

这里需要特别注意的最重要的标志是`-fsanitize=address`标志，它告诉编译器启用 ASAN。其余的标志是卫生间所需的，最值得注意的标志是`-g`和`-01`。`-g`标志启用调试，`-O1`标志将优化级别设置为 1，以提供一些性能改进。请注意，一旦启用 ASAN 工具，编译器将自动尝试链接到 ASAN 库，这些库必须存在于您的计算机上。

为了演示这个消毒剂是如何工作的，让我们看几个例子。

# 内存泄漏错误

`AddressSanitizer`是一种动态分析工具，旨在识别内存损坏错误。它类似于 Valgrind，但直接内置到您的可执行文件中。最容易用一个示例来演示这一点（也是最常见的错误类型之一）是内存泄漏，如下所示：

```cpp
int main(void)
{
    new int;
}
```

这导致以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/4cdecfde-c17e-47ba-b109-8dd637af2a5d.png)

在上面的示例中，我们在程序中使用`new`运算符分配了一个整数，但在退出程序之前我们将永远不会释放这个分配的内存。ASAN 工具能够检测到这个问题，并在应用程序完成执行时输出错误。

# 内存两次删除

检测内存泄漏的能力非常有帮助，但这并不是 ASAN 能够检测到的唯一类型的错误。另一种常见的错误类型是多次删除内存。例如，考虑以下代码片段：

```cpp
int main(void)
{
    auto p = new int;
    delete p;

    delete p;
}
```

执行后，我们看到以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/01d887f8-4fcc-4efc-8691-67831ec8b13a.png)

在上面的示例中，我们使用`new`运算符分配了一个整数，然后使用删除运算符删除了该整数。由于先前分配的内存的指针仍然在我们的`p`变量中，我们可以再次删除它，这是我们在退出程序之前所做的。在某些系统上，这将生成一个分段错误，因为这是未定义的行为。ASAN 工具能够检测到这个问题，并输出一个错误消息，指出发生了`double-free`错误。

# 访问无效内存

另一种错误类型是尝试访问从未分配的内存。这通常是由代码尝试对空指针进行解引用引起的，但也可能发生在指针损坏时，如下所示：

```cpp
int main(void)
{
    int *p = (int *)42;
    *p = 0;
}
```

这导致以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/ebd30496-bc91-49e1-b20c-1e5f580db297.png)

在前面的示例中，我们创建了一个指向整数的指针，然后为它提供了一个损坏的值`42`（这不是一个有效的指针）。然后我们尝试对损坏的指针进行解引用，结果导致分段错误。应该注意的是，ASAN 工具能够检测到这个问题，但它无法提供任何有用的信息。这是因为 ASAN 工具是一个库，它钩入内存分配例程，跟踪每个分配以及分配的使用方式。如果一个分配从未发生过，它将不会有任何关于发生了什么的信息，除了典型的 Unix 信号处理程序已经提供的信息，其他动态分析工具，比如 Valgrind，更适合处理这些情况。

# 在删除后使用内存

为了进一步演示地址消毒剂的工作原理，让我们看看以下示例：

```cpp
int main(void)
{
    auto p = new int;
    delete p;

    *p = 0;
}
```

当我们执行这个时，我们会看到以下内容：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/c01185c7-a10c-4464-be43-c60816cfcd63.png)

前面的示例分配了一个整数，然后删除了这个整数。然后我们尝试使用先前删除的内存。由于这个内存位置最初是分配的，ASAN 已经缓存了地址。当对先前删除的内存进行解引用时，ASAN 能够检测到这个问题，作为`heap-use-after-free`错误。它之所以能够检测到这个问题，是因为这块内存先前被分配过。

# 删除从未分配的内存

最后一个例子，让我们看看以下内容：

```cpp
int main(void)
{
    int *p = (int *)42;
    delete p;
}
```

这导致了以下结果：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/ed7e5106-c3d4-478f-8085-45a6ed4f62fb.png)

在前面的示例中，我们创建了一个指向整数的指针，然后再次为它提供了一个损坏的值。与我们之前的示例不同，在这个示例中，我们尝试删除这个损坏的指针，结果导致分段错误。再一次，ASAN 能够检测到这个问题，但由于从未发生过分配，它没有任何有用的信息。

应该注意的是，C++核心指南——这是一个现代 C++的编码标准——在防止我们之前描述的问题类型方面非常有帮助。具体来说，核心指南规定`new()`、`delete()`、`malloc()`、`free()`和其他函数不应该直接使用，而应该使用`std::unique_ptr`和`std::shared_ptr`来进行*所有内存分配*。这些 API 会自动为您分配和释放内存。如果我们再次看一下前面的示例，很容易看出，使用这些 API 来分配内存而不是手动使用`new()`和`delete()`可以防止这些问题发生，因为大多数前面的示例都与无效使用`new()`和`delete()`有关。

# 使用 UBSAN，未定义行为消毒剂

在这个配方中，我们将学习如何在我们的 C++应用程序中使用 UBSAN 动态分析工具，它能够检测未定义的行为。在我们的应用程序中可能会引入许多不同类型的错误，未定义的行为很可能是最常见的类型，因为 C 和 C++规范定义了几种可能发生未定义行为的情况。

这个配方很重要，因为它将教会你如何启用这个简单的功能，以及它如何在你的应用程序中使用。

# 准备工作

开始之前，请确保满足所有技术要求，包括安装 Ubuntu 18.04 或更高版本，并在终端窗口中运行以下命令：

```cpp
> sudo apt-get install build-essential git cmake
```

这将确保您的操作系统具有适当的工具来编译和执行本配方中的示例。完成后，打开一个新的终端。我们将使用这个终端来下载、编译和运行我们的示例。

# 如何做...

按照以下步骤进行配方：

1.  从一个新的终端，运行以下命令来下载源代码：

```cpp
> cd ~/
> git clone https://github.com/PacktPublishing/Advanced-CPP-CookBook.git
> cd Advanced-CPP-CookBook/chapter07
```

1.  要编译源代码，请运行以下命令：

```cpp
> cmake -DCMAKE_BUILD_TYPE=UBSAN .
> make recipe03_examples
```

1.  源代码编译后，可以通过运行以下命令来执行本示例中的每个示例：

```cpp
> ./recipe03_example01
Floating point exception (core dumped)

> ./recipe03_example02
Segmentation fault (core dumped)

> ./recipe03_example03
Segmentation fault (core dumped)

> ./recipe03_example04

```

在下一节中，我们将逐个讲解这些示例，并解释每个示例程序的作用以及它与本示例中所教授的课程的关系。

# 工作原理...

UBSAN 工具能够检测到几种类型的未定义行为，包括以下内容：

+   越界错误

+   浮点错误

+   除零

+   整数溢出

+   空指针解引用

+   缺少返回值

+   有符号/无符号转换错误

+   不可达代码

在这个示例中，我们将看一些这样的例子，但首先，我们必须在我们的应用程序中启用 UBSAN 工具。为此，我们必须在应用程序的构建系统中启用以下标志：

```cpp
-fsanitize=undefined
```

这个标志将告诉 GCC 或 LLVM 使用 UBSAN 工具，它会向我们的应用程序添加额外的逻辑，并链接到 UBSAN 库。值得注意的是，UBSAN 工具的功能会随着时间的推移而增强。因此，GCC 和 LLVM 对 UBSAN 的支持水平不同。为了充分利用这个工具，你的应用程序应该同时针对 GCC 和 LLVM 进行编译，并且应该尽可能使用最新的编译器。

# 除零错误

使用 UBSAN 最容易演示的一个例子是除零错误，如下所示：

```cpp
int main(void)
{
    int n = 42;
    int d = 0;

    auto f = n/d;
}
```

当运行时，我们看到以下内容：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/698ed489-e92b-4080-a0dc-fb224466ddf7.png)

在上面的示例中，我们创建了两个整数（一个分子和一个分母），分母设置为`0`。然后我们对分子和分母进行除法运算，导致除零错误，UBSAN 检测到并在程序崩溃时输出。

# 空指针解引用

在 C++中更常见的问题类型是空指针解引用，如下所示：

```cpp
int main(void)
{
    int *p = 0;
    *p = 42;
}
```

这导致了以下结果：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/61d56d5b-161b-470f-8181-68dafa5ab7ab.png)

在上面的示例中，我们创建了一个指向整数的指针，并将其设置为`0`（即`NULL`指针）。然后我们对`NULL`指针进行解引用并设置其值，导致分段错误，UBSAN 能够检测到程序崩溃。

# 越界错误

前面的两个示例都可以使用 Unix 信号处理程序来检测。在下一个示例中，我们将访问一个超出边界的数组，这在 C++规范中是未定义的，而且更难以检测：

```cpp
int main(void)
{
    int numbers[] = {4, 8, 15, 16, 23, 42};
    numbers[10] = 0;
}
```

执行时，我们得到以下结果：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/19eaa37d-90b8-4910-bc6a-bc96ec98f7dd.png)

如上面的示例所示，我们创建了一个有 6 个元素的数组，然后尝试访问数组中的第 10 个元素，这个元素并不存在。尝试访问数组中的这个元素并不一定会生成分段错误。不管怎样，UBSAN 能够检测到这种类型的错误，并在退出时将问题输出到`stderr`。

# 溢出错误

最后，我们还可以检测有符号整数溢出错误，这在 C++中是未定义的，但极不可能导致崩溃，而是会导致程序进入一个损坏的状态（通常产生无限循环、越界错误等）。考虑以下代码：

```cpp
#include <climits>

int main(void)
{
    int i = INT_MAX;
    i++;
}
```

这导致了以下结果：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/0db50c0b-0249-4600-9a72-c62b3fc591b0.png)

如上面的示例所示，我们创建了一个整数，并将其设置为最大值。然后我们尝试增加这个整数，这通常会翻转整数的符号，这是 UBSAN 能够检测到的错误。

# 使用#ifndef NDEBUG 条件执行额外检查

在这个示例中，我们将学习如何利用`NDEBUG`宏，它代表*no debug*。这个示例很重要，因为大多数构建系统在编译*发布*或*生产*版本时会自动定义这个宏，这可以用来在创建这样的构建时禁用调试逻辑。

# 准备就绪

开始之前，请确保满足所有技术要求，包括安装 Ubuntu 18.04 或更高版本，并在终端窗口中运行以下命令：

```cpp
> sudo apt-get install build-essential git cmake
```

这将确保您的操作系统具有正确的工具来编译和执行本配方中的示例。完成后，打开一个新的终端。我们将使用此终端来下载、编译和运行我们的示例。

# 如何做...

按照以下步骤来完成这个配方：

1.  从新的终端运行以下命令来下载源代码：

```cpp
> cd ~/
> git clone https://github.com/PacktPublishing/Advanced-CPP-CookBook.git
> cd Advanced-CPP-CookBook/chapter07
```

1.  要编译源代码，请运行以下命令：

```cpp
> cmake .
> make recipe04_examples
```

1.  一旦源代码编译完成，您可以通过运行以下命令来执行本配方中的每个示例：

```cpp
> ./recipe04_example01
The answer is: 42

> ./recipe04_example02
recipe04_example02: /home/user/book/chapter07/recipe04.cpp:45: int main(): Assertion `42 == 0' failed.
Aborted (core dumped)
```

在下一节中，我们将逐个介绍这些示例，并解释每个示例程序的作用以及它与本配方中所教授的课程的关系。

# 工作原理...

`NDEBUG`宏源自 C 语言，用于更改`assert()`函数的行为。`assert()`函数可以编写如下：

```cpp
void __assert(int val, const char *str)
{
    if (val == 0) {
        fprintf(stderr, "Assertion '%s' failed.\n", str);
        abort();
    }
}

#ifndef NDEBUG
    #define assert(a) __assert(a, #a)
#else
    #define assert(a)
#endif 
```

如前面的代码所示，如果`__assert()`函数得到一个求值为`false`的布尔值（在 C 中，这是一个等于`0`的整数），则会向`stderr`输出错误消息，并中止应用程序。然后使用`NDEBUG`宏来确定`assert()`函数是否存在，如果应用程序处于发布模式，则会删除所有断言逻辑，从而减小应用程序的大小。在使用 CMake 时，我们可以使用以下命令启用`NDEBUG`标志：

```cpp
> cmake -DCMAKE_BUILD_TYPE=Release ..
```

这将自动定义`NDEBUG`宏并启用优化。要防止定义此宏，我们可以做相反的操作：

```cpp
> cmake -DCMAKE_BUILD_TYPE=Debug ..
```

上面的 CMake 代码将*不*定义`NDEBUG`宏，而是启用调试，并禁用大多数优化（尽管这取决于编译器）。

在我们自己的代码中，`assert`宏可以如下使用：

```cpp
#include <cassert>

int main(void)
{
    assert(42 == 0);
}
```

结果如下：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/285a3fe5-641d-4c56-8521-9fe0e4ffbceb.png)

如前面的示例所示，我们创建了一个应用程序，该应用程序使用`assert()`宏来检查一个错误的语句，结果是应用程序中止。

尽管`NDEBUG`宏被`assert()`函数使用，但您也可以自己使用它，如下所示：

```cpp
int main(void)
{
#ifndef NDEBUG
    std::cout << "The answer is: 42\n";
#endif
}
```

如前面的代码所示，如果应用程序未以*release*模式编译（即在编译时未在命令行上定义`NDEBUG`宏），则应用程序将输出到`stdout`。您可以在整个代码中使用相同的逻辑来创建自己的调试宏和函数，以确保在*release*模式下删除调试逻辑，从而可以根据需要添加任意数量的调试逻辑，而无需修改交付给客户的最终应用程序。


# 第八章：创建和实现自己的容器

在本章中，你将学习如何通过利用 C++标准模板库已经提供的现有容器来创建自己的自定义容器。这一章很重要，因为在很多情况下，你的代码将对标准模板库容器执行常见操作，这些操作在整个代码中都是重复的（比如实现线程安全）。本章的食谱将教你如何将这些重复的代码轻松地封装到一个自定义容器中，而无需从头开始编写自己的容器，也不会在代码中散布难以测试和验证的重复逻辑。

在整个本章中，你将学习实现自定义包装器容器所需的技能，能够确保`std::vector`始终保持排序顺序。第一个食谱将教你如何创建这个包装器的基础知识。第二个食谱将在第一个基础上展开，教你如何根据容器的操作方式重新定义容器的接口。在这种情况下，由于容器始终是有序的，你将学习为什么提供`push_back()`函数是没有意义的，即使我们只是创建一个包装器（包装器的添加改变了容器本身的概念）。在第三个食谱中，你将学习使用迭代器的技能，以及为什么在这个例子中只能支持`const`迭代器。最后，我们将向我们的容器添加几个额外的 API，以提供完整的实现。

本章中的食谱如下：

+   使用简单的 std::vector 包装器

+   添加 std::set API 的相关部分

+   使用迭代器

+   添加 std::vector API 的相关部分

# 技术要求

要编译和运行本章中的示例，读者必须具有对运行 Ubuntu 18.04 的计算机的管理访问权限，并且有一个正常的互联网连接。在运行这些示例之前，读者必须安装以下内容：

```cpp
> sudo apt-get install build-essential git cmake
```

如果这安装在 Ubuntu 18.04 以外的任何操作系统上，则需要 GCC 7.4 或更高版本和 CMake 3.6 或更高版本。

本章的代码文件可以在[`github.com/PacktPublishing/Advanced-CPP-CookBook/tree/master/chapter08`](https://github.com/PacktPublishing/Advanced-CPP-CookBook/tree/master/chapter08)找到。

# 使用简单的 std::vector 包装器

在本食谱中，我们将学习如何通过包装现有的标准模板库容器来创建自己的自定义容器，以提供所需的自定义功能。在后续的食谱中，我们将在这个自定义容器的基础上构建，最终创建一个基于`std::vector`的完整容器。

这个食谱很重要，因为经常情况下，利用现有容器的代码伴随着每次使用容器时都会重复的常见逻辑。这个食谱（以及整个章节）将教会你如何将这些重复的逻辑封装到你自己的容器中，以便可以独立测试。

# 准备工作

在开始之前，请确保满足所有的技术要求，包括安装 Ubuntu 18.04 或更高版本，并在终端窗口中运行以下命令：

```cpp
> sudo apt-get install build-essential git cmake
```

这将确保您的操作系统具有编译和执行本食谱中示例的必要工具。完成后，打开一个新的终端。我们将使用这个终端来下载、编译和运行我们的示例。

# 如何做...

按照以下步骤尝试本食谱：

1.  从一个新的终端，运行以下命令来下载源代码：

```cpp
> cd ~/
> git clone https://github.com/PacktPublishing/Advanced-CPP-CookBook.git
> cd Advanced-CPP-CookBook/chapter08
```

1.  要编译源代码，请运行以下命令：

```cpp
> cmake .
> make recipe01_examples
```

1.  一旦源代码编译完成，你可以通过运行以下命令来执行本食谱中的每个示例：

```cpp
> ./recipe01_example01
1
2
3
4
5
6
7
8

> ./recipe01_example02
1
2
3

> ./recipe01_example03
3
elements: 4 42 
3
elements: 4 8 15 42 
3
elements: 4 8 15 16 23 42 
```

在下一节中，我们将逐步介绍每个示例，并解释每个示例的作用以及它与本食谱中所教授的课程的关系。

# 它是如何工作的...

在本教程中，我们将学习如何在`std::vector`周围创建一个简单的包装容器。大多数情况下，**标准模板库**（**STL**）容器足以执行应用程序可能需要的任务，通常应避免创建自己的容器，因为它们很难正确实现。

然而，有时您可能会发现自己在容器上重复执行相同的操作。当发生这种情况时，将这些常见操作封装到一个包装容器中通常是有帮助的，可以独立进行单元测试，以确保容器按预期工作。例如，STL 容器不是线程安全的。如果您需要一个容器在每次访问时都能够与线程安全一起使用，您首先需要确保您对容器有独占访问权限（例如，通过锁定`std::mutex`），然后才能进行容器操作。这种模式将在您的代码中重复出现，增加了进入死锁的机会。通过创建一个容器包装器，为容器的每个公共成员添加一个`std::mutex`，可以避免这个问题。

在本教程中，让我们考虑一个例子，我们创建一个向量（即，在连续内存中有直接访问权限的元素数组），它必须始终保持排序状态。首先，我们需要一些头文件：

```cpp
#include <vector>
#include <algorithm>
#include <iostream>
```

为了实现我们的容器，我们将利用`std::vector`。虽然我们可以从头开始实现自己的容器，但大多数情况下这是不需要的，应该避免，因为这样的任务非常耗时和复杂。我们将需要`algorithm`头文件用于`std::sort`和`iostream`用于测试。因此让我们添加如下内容：

```cpp
template<
    typename T,
    typename Compare = std::less<T>,
    typename Allocator = std::allocator<T>
    >
class container
{
    using vector_type = std::vector<T, Allocator>;
    vector_type m_v;

public:
```

容器的定义将从其模板定义开始，与`std::vector`的定义相同，增加了一个`Compare`类型，用于定义我们希望容器排序的顺序。默认情况下，容器将按升序排序，但可以根据需要进行更改。最后，容器将有一个私有成员变量，即该容器包装的`std::vector`的实例。

为了使容器能够与 C++工具、模板函数甚至一些关键语言特性正常工作，容器需要定义与`std::vector`相同的别名，如下所示：

```cpp
    using value_type = typename vector_type::value_type;
    using allocator_type = typename vector_type::allocator_type;
    using size_type = typename vector_type::size_type;
    using difference_type = typename vector_type::difference_type;
    using const_reference = typename vector_type::const_reference;
    using const_pointer = typename vector_type::const_pointer;
    using compare_type = Compare;
```

如您所见，我们无需手动定义别名。相反，我们可以简单地从`std::vector`本身转发别名的声明。唯一的例外是`compare_type`别名，因为这是我们添加到包装容器中的一个别名，表示模板类用于比较操作的类型，最终将提供给`std::sort`。

我们也不包括引用别名的非 const 版本。原因是我们的容器必须始终保持`std::vector`处于排序状态。如果我们为用户提供对`std::vector`中存储的元素的直接写访问权限，用户可能会使`std::vector`处于无序状态，而我们的自定义容器无法按需重新排序。

接下来，让我们定义我们的构造函数（与`std::vector`提供的相同构造函数相对应）。

# 默认构造函数

以下是我们的默认构造函数的定义：

```cpp
    container() noexcept(noexcept(Allocator()))
    {
        std::cout << "1\n";
    }
```

由于`std::vector`的默认构造函数产生一个空向量，我们不需要添加额外的逻辑，因为空向量默认是排序的。接下来，我们必须定义一个接受自定义分配器的构造函数。

# 自定义分配器构造函数

我们的自定义分配器构造函数定义如下：

```cpp
    explicit container(
        const Allocator &alloc
    ) noexcept :
        m_v(alloc)
    {
        std::cout << "2\n";
    }
```

与前一个构造函数一样，这个构造函数创建一个空向量，但使用已经存在的分配器。

# 计数构造函数

接下来的两个构造函数允许 API 的用户设置向量的最小大小如下：

```cpp
    container(
        size_type count,
        const T &value,
        const Allocator &alloc = Allocator()
    ) :
        m_v(count, value, alloc)
    {
        std::cout << "3\n";
    }

    explicit container(
        size_type count,
        const Allocator &alloc = Allocator()
    ) :
        m_v(count, alloc)
    {
        std::cout << "4\n";
    }
```

第一个构造函数将创建一个包含`count`个元素的向量，所有元素都用`value`的值初始化，而第二个构造函数将使用它们的默认值创建元素（例如，整数向量将被初始化为零）。

# 复制/移动构造函数

为了支持复制和移动容器的能力，我们需要实现一个复制和移动构造函数，如下所示：

```cpp
    container(
        const container &other,
        const Allocator &alloc
    ) :
        m_v(other.m_v, alloc)
    {
        std::cout << "5\n";
    }

    container(
        container &&other
    ) noexcept :
        m_v(std::move(other.m_v))
    {
        std::cout << "6\n";
    }
```

由于我们的自定义包装容器必须始终保持排序顺序，因此将一个容器复制或移动到另一个容器不会改变容器中元素的顺序，这意味着这些构造函数也不需要进行排序操作。然而，我们需要特别注意确保通过复制或移动我们的容器封装的内部`std::vector`来正确进行复制或移动。

为了完整起见，我们还提供了一个移动构造函数，允许我们像`std::vector`一样在提供自定义分配器的同时移动。

```cpp
    container(
        container &&other,
        const Allocator &alloc
    ) :
        m_v(std::move(other.m_v), alloc)
    {
        std::cout << "7\n";
    }
```

接下来，我们将提供一个接受初始化列表的构造函数。

# 初始化列表构造函数

最后，我们还将添加一个接受初始化列表的构造函数，如下所示：

```cpp
    container(
        std::initializer_list<T> init,
        const Allocator &alloc = Allocator()
    ) :
        m_v(init, alloc)
    {
        std::sort(m_v.begin(), m_v.end(), compare_type());
        std::cout << "8\n";
    }
```

如前面的代码所示，初始化列表可以以任何顺序为`std::vector`提供初始元素。因此，我们必须在向量初始化后对列表进行排序。

# 用法

让我们测试这个容器，以确保每个构造函数都按预期工作：

```cpp
int main(void)
{
    auto alloc = std::allocator<int>();

    container<int> c1;
    container<int> c2(alloc);
    container<int> c3(42, 42);
    container<int> c4(42);
    container<int> c5(c1, alloc);
    container<int> c6(std::move(c1));
    container<int> c7(std::move(c2), alloc);
    container<int> c8{4, 42, 15, 8, 23, 16};

    return 0;
}
```

如前面的代码块所示，我们通过调用每个构造函数来测试它们，结果如下：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/d05b7686-5517-4965-80e9-17420fc8564b.png)

如您所见，每个构造函数都成功按预期执行。

# 向容器添加元素

构造函数就位后，我们还需要提供手动向容器添加数据的能力（例如，如果我们最初使用默认构造函数创建了容器）。

首先，让我们专注于`std::vector`提供的`push_back()`函数：

```cpp
    void push_back(const T &value)
    {
        m_v.push_back(value);
        std::sort(m_v.begin(), m_v.end(), compare_type());

        std::cout << "1\n";
    }

    void push_back(T &&value)
    {
        m_v.push_back(std::move(value));
        std::sort(m_v.begin(), m_v.end(), compare_type());

        std::cout << "2\n";
    }
```

如前面的代码片段所示，`push_back()`函数具有与`std::vector`提供的版本相同的函数签名，允许我们简单地将函数调用转发到`std::vector`。问题是，向`std::vector`的末尾添加值可能导致`std::vector`进入无序状态，需要我们在每次推送时重新排序`std::vector`（要求`std::vector`始终保持排序状态的结果）。

解决这个问题的一种方法是向容器包装器添加另一个成员变量，用于跟踪`std::vector`何时被污染。实现这些函数的另一种方法是按排序顺序添加元素（即按照排序顺序遍历向量并将元素放在适当的位置，根据需要移动剩余元素）。如果很少向`std::vector`添加元素，那么这种方法可能比调用`std::sort`更有效。然而，如果向`std::vector`频繁添加元素，那么污染的方法可能表现更好。

创建容器包装器的一个关键优势是，可以实现和测试这些类型的优化，而不必更改依赖于容器本身的代码。可以实现、测试和比较这两种实现（或其他实现），以确定哪种优化最适合您的特定需求，而使用容器的代码永远不会改变。这不仅使代码更清晰，而且这种增加的封装打击了面向对象设计的核心，确保代码中的每个对象只有一个目的。对于容器包装器来说，其目的是封装维护`std::vector`的排序顺序的操作。

为了完整起见，我们还将添加`push_back()`的`emplace_back()`版本，就像`std::vector`一样：

```cpp
    template<typename... Args>
    void emplace_back(Args&&... args)
    {
        m_v.emplace_back(std::forward<Args>(args)...);
        std::sort(m_v.begin(), m_v.end(), compare_type());

        std::cout << "3\n";
    }
```

与`std::vector`等效的`emplace_back()`函数的区别在于，我们的版本不返回对创建的元素的引用。这是因为排序会使引用无效，从而无法返回有效的引用。

# push/emplace 的用法

最后，让我们测试我们的`push_back()`和`emplace`函数，以确保它们被正确调用，如下所示：

```cpp
int main(void)
{
    int i = 42;
    container<int> c;

    c.push_back(i);
    c.push_back(std::move(i));
    c.emplace_back(42);

    return 0;
}
```

如前面的代码片段所示，我们调用了`push_back()`的每个版本以及`emplace_back()`函数，以确保它们被正确调用，结果如下：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/51e13fb0-f3e4-460b-8109-137c99e246ed.png)

我们可以进一步添加更好的测试数据到我们的测试容器，如下所示：

```cpp
int main(void)
{
    int i = 42;
    container<int> c;

    c.emplace_back(4);
    c.push_back(i);
    c.emplace_back(15);
    c.push_back(8);
    c.emplace_back(23);
    c.push_back(std::move(16));

    return 0;
}
```

如前面的代码片段所示，我们向我们的向量添加整数`4`、`42`、`15`、`8`、`23`和`16`。在下一个示例中，我们将从`std::set`中窃取 API，以提供更好的`push`和`emplace`API 给我们的容器，以及一个输出函数，以更好地了解`std::vector`包含的内容以及其包含元素的顺序。

# 向 std::set API 添加相关部分

在本示例中，我们将学习如何从`std::set`中添加 API 到我们在第一个示例中创建的自定义容器。具体来说，我们将学习为什么`std::vector::push_back()`和`std::vector::emplace_back()`在与始终保持内部元素排序顺序的自定义容器一起使用时是没有意义的。

# 准备工作

开始之前，请确保满足所有技术要求，包括安装 Ubuntu 18.04 或更高版本，并在终端窗口中运行以下命令：

```cpp
> sudo apt-get install build-essential git cmake
```

这将确保您的操作系统具有编译和执行本示例中的示例所需的适当工具。完成后，打开一个新的终端。我们将使用这个终端来下载、编译和运行我们的示例。

# 操作步骤...

按照以下步骤尝试这个示例：

1.  从新的终端运行以下命令以下载源代码：

```cpp
> cd ~/
> git clone https://github.com/PacktPublishing/Advanced-CPP-CookBook.git
> cd Advanced-CPP-CookBook/chapter08
```

1.  编译源代码，运行以下命令：

```cpp
> cmake .
> make recipe02_examples
```

1.  源代码编译完成后，可以通过运行以下命令来执行本示例中的每个示例：

```cpp
> ./recipe02_example01 
elements: 4 
elements: 4 42 
elements: 4 15 42 
elements: 4 8 15 42 
elements: 4 8 15 23 42 
elements: 4 8 15 16 23 42 
```

在下一节中，我们将逐步介绍每个示例，并解释每个示例程序的作用，以及它与本示例中所教授的课程的关系。

# 工作原理...

在本章的第一个示例中，我们创建了一个自定义容器包装器，模拟了`std::vector`，但确保向量中的元素始终保持排序顺序，包括添加`std::vector::push_back()`函数和`std::vector::emplace_back()`函数。在本示例中，我们将向我们的自定义容器添加`std::set::insert()`和`std::set::emplace()`函数。

由于我们的容器包装器始终确保`std::vector`处于排序状态，因此无论将元素添加到向量的前端、后端还是中间，都没有区别。无论将元素添加到向量的哪个位置，都必须在访问向量之前对其进行排序，这意味着无论将元素添加到哪个位置，其添加顺序都可能会发生变化。

对于添加元素的位置，我们不必担心，这与`std::set`类似。`std::set`向集合添加元素，然后根据被测试的元素是否是集合的成员，稍后返回`true`或`false`。`std::set`提供了`insert()`和`emplace()`函数来向集合添加元素。让我们向我们的自定义容器添加这些 API，如下所示：

```cpp
    void insert(const T &value)
    {
        push_back(value);
    }

    void insert(T &&value)
    {
        push_back(std::move(value));
    }

    template<typename... Args>
    void emplace(Args&&... args)
    {
        emplace_back(std::forward<Args>(args)...);
    }
```

如前面的代码片段所示，我们添加了一个`insert()`函数（包括复制和移动），以及一个`emplace()`函数，它们只是调用它们的`push_back()`和`emplace_back()`等效函数，确保正确转发传递给这些函数的参数。这些 API 与我们在上一个教程中添加的 API 之间唯一的区别是函数本身的名称。

尽管这样的改变可能看起来微不足道，但这对于重新定义容器的 API 与用户之间的概念是很重要的。`push_back()`和`emplace_back()`函数表明元素被添加到向量的末尾，但实际上并非如此。相反，它们只是简单地添加到`std::vector`中，并且`std::vector`的顺序会根据添加的元素值而改变。因此，需要`push_back()`和`emplace_back()`函数，但应将它们重命名或标记为私有，以确保用户只使用`insert()`和`emplace()`版本来正确管理期望。在编写自己的容器时（即使是包装器），重要的是要遵循最少惊讶原则，以确保用户使用的 API 将按照 API 可能暗示的方式工作。

# 使用迭代器

在本教程中，我们将学习如何为我们在第一个教程中开始的自定义容器添加迭代器支持，该容器包装了一个`std::vector`，确保其内容始终保持排序顺序。

为了添加迭代器支持，我们将学习如何转发`std::vector`已提供的迭代器（我们不会从头开始实现迭代器，因为这超出了本书的范围，从头开始实现容器非常困难）。

# 准备工作

开始之前，请确保满足所有技术要求，包括安装 Ubuntu 18.04 或更高版本，并在终端窗口中运行以下命令：

```cpp
> sudo apt-get install build-essential git cmake
```

这将确保您的操作系统具有编译和执行本教程中示例所需的正确工具。完成后，打开一个新的终端。我们将使用此终端来下载、编译和运行我们的示例。

# 操作步骤

要尝试本教程，需要按照以下步骤进行：

1.  从新终端运行以下命令以下载源代码：

```cpp
> cd ~/
> git clone https://github.com/PacktPublishing/Advanced-CPP-CookBook.git
> cd Advanced-CPP-CookBook/chapter08
```

1.  要编译源代码，请运行以下命令：

```cpp
> cmake .
> make recipe03_examples
```

1.  源代码编译完成后，可以通过运行以下命令来执行本教程中的每个示例：

```cpp
> ./recipe03_example01 
elements: 4 8 15 16 23 42 

> ./recipe03_example02 
elements: 4 8 15 16 23 42 
elements: 4 8 15 16 23 42 
elements: 42 23 16 15 8 4 
elements: 1 4 8 15 16 23 42 
elements: 4 8 15 16 23 42 
elements: 
```

在下一节中，我们将逐个介绍这些示例，并解释每个示例程序的作用以及它与本教程中所教授的课程的关系。

# 工作原理

我们的自定义容器包装的`std::vector`已经提供了一个有效的迭代器实现，可以用于处理我们的容器。但是，我们需要转发`std::vector`提供的特定部分 API，以确保迭代器正常工作，包括关键的 C++特性，如基于范围的 for 循环。

首先，让我们向我们的自定义容器添加`std::vector`提供的最后一个剩余构造函数：

```cpp
    template <typename Iter>
    container(
        Iter first,
        Iter last,
        const Allocator &alloc = Allocator()
    ) :
        m_v(first, last, alloc)
    {
        std::sort(m_v.begin(), m_v.end(), compare_type());
    }
```

如前面的代码片段所示，我们得到的迭代器类型未定义。迭代器可以来自我们容器的另一个实例，也可以直接来自`std::vector`，后者不会按排序顺序存储其元素。即使迭代器来自我们自定义容器的一个实例，迭代器存储元素的顺序可能与容器元素的顺序不同。因此，我们必须在初始化后对`std::vector`进行排序。

除了构造之外，我们的自定义容器还必须包括`std::vector`提供的基于迭代器的别名，因为这些别名对于容器与 C++ API 的正确工作是必需的。以下是一个示例代码片段：

```cpp
    using const_iterator = typename vector_type::const_iterator;
    using const_reverse_iterator = typename vector_type::const_reverse_iterator;
```

正如前面的代码片段所示，与第一个示例中定义的别名一样，我们只需要前向声明`std::vector`已经提供的别名，以便我们的自定义容器也可以利用它们。不同之处在于，我们不包括这些迭代器别名的非 const 版本。由于我们的自定义容器必须始终保持有序，我们必须限制用户直接修改迭代器内容的能力，因为这可能导致更改容器元素的顺序，而我们的容器无法根据需要重新排序。相反，对容器的修改应通过使用`insert()`、`emplace()`和`erase()`来进行。

基于 C++模板的函数依赖于这些别名来正确实现它们的功能，这也包括基于范围的 for 循环。

最后，有一系列基于迭代器的成员函数，`std::vector`提供了这些函数，也应该通过我们的自定义容器进行转发。以下代码描述了这一点：

```cpp
    const_iterator begin() const noexcept
    {
        return m_v.begin();
    }

    const_iterator cbegin() const noexcept
    {
        return m_v.cbegin();
    }
```

第一组成员函数是`begin()`函数，它提供表示`std::vector`中第一个元素的迭代器。与别名一样，我们不转发这些成员函数的非 const 版本。此外，出于完整性考虑，我们包括这些函数的`c`版本。在 C++17 中，这些是可选的，如果愿意，可以使用`std::as_const()`代替。接下来的迭代器是`end()`迭代器，它提供表示`std::vector`末尾的迭代器（不要与表示`std::vector`中最后一个元素的迭代器混淆）。以下代码显示了这一点：

```cpp
    const_iterator end() const noexcept
    {
        return m_v.end();
    }

    const_iterator cend() const noexcept
    {
        return m_v.cend();
    }
```

正如前面的代码片段所示，与大多数这些成员函数一样，我们只需要将 API 转发到我们的自定义容器封装的私有`std::vector`。这个过程也可以重复用于`rbegin()`和`rend()`，它们提供与之前相同的 API，但返回一个反向迭代器，以相反的顺序遍历`std::vector`。

接下来，我们实现基于迭代器的`emplace()`函数，如下所示：

```cpp
    template <typename... Args>
    void emplace(const_iterator pos, Args&&... args)
    {
        m_v.emplace(pos, std::forward<Args>(args)...);
        std::sort(m_v.begin(), m_v.end(), compare_type());
    }
```

尽管提供`emplace()` API 提供了更完整的实现，但应该注意的是，只有在进一步优化以利用元素添加到容器的预期位置的方式时，它才会有用。这与更好地排序`std::vector`的方法相结合。

尽管前面的实现是有效的，但它可能与我们在第一个示例中实现的`emplace()`版本表现类似。由于自定义容器始终保持排序顺序，因此将元素插入`std::vector`的位置是无关紧要的，因为`std::vector`的新顺序将改变添加元素的位置。当然，除非位置参数的添加提供了一些额外的支持来更好地优化添加，而我们的实现没有这样做。因此，除非使用`pos`参数进行优化，前面的函数可能是多余且不必要的。

与前面的`emplace()`函数一样，我们不尝试返回表示添加到容器的元素的迭代器，因为在排序后，此迭代器将变为无效，并且关于添加到`std::vector`的内容的信息不足以重新定位迭代器（例如，如果存在重复项，则无法知道实际添加的是哪个元素）。

最后，我们实现了`erase`函数，如下所示：

```cpp
    const_iterator erase(const_iterator pos)
    {
        return m_v.erase(pos);
    }

    const_iterator erase(const_iterator first, const_iterator last)
    {
        return m_v.erase(first, last);
    }
```

与`emplace()`函数不同，从`std::vector`中移除元素不会改变`std::vector`的顺序，因此不需要排序。还应该注意的是，我们的`erase()`函数版本返回`const`版本。再次强调，这是因为我们无法支持迭代器的非 const 版本。

最后，现在我们有能力访问容器中存储的元素，让我们创建一些测试逻辑，以确保我们的容器按预期工作：

```cpp
int main(void)
{
    container<int> c{4, 42, 15, 8, 23, 16};
```

首先，我们将从不带顺序的整数初始化列表创建一个容器。创建完容器后，存储这些元素的`std::vector`应该是有序的。为了证明这一点，让我们循环遍历容器并输出结果：

```cpp
    std::cout << "elements: ";

    for (const auto &elem : c) {
        std::cout << elem << ' ';
    }

    std::cout << '\n';
```

如前面的代码片段所示，我们首先向`stdout`输出一个标签，然后使用范围 for 循环遍历我们的容器，逐个输出每个元素。最后，在所有元素都输出到`stdout`后，我们输出一个新行，导致以下输出：

```cpp
elements: 4 8 15 16 23 42
```

此输出按预期的顺序排序。

需要注意的是，我们的范围 for 循环必须将每个元素定义为`const`。这是因为我们不支持迭代器的非 const 版本。任何尝试使用这些迭代器的非 const 版本都会导致编译错误，如下例所示：

```cpp
    for (auto &elem : c) {
        elem = 42;
    }
```

上述代码将导致以下编译错误（这是预期的）：

```cpp
/home/user/book/chapter08/recipe03.cpp: In function ‘int main()’:
/home/user/book/chapter08/recipe03.cpp:396:14: error: assignment of read-only reference ‘elem’
  396 | elem = 42;
```

发生这种编译错误的原因是因为范围 for 循环也可以写成以下形式：

```cpp
    std::cout << "elements: ";

    for (auto iter = c.begin(); iter != c.end(); iter++) {
        auto &elem = *iter;
        std::cout << elem << ' ';
    }

    std::cout << '\n';
```

如前面的代码片段所示，元素未标记为`const`，因为范围 for 循环使用`begin()`和`end()`成员函数，导致读写迭代器（除非您明确声明为`const`）。

我们还可以为我们的新`emplace()`函数创建一个测试，如下所示：

```cpp
    c.emplace(c.cend(), 1);

    std::cout << "elements: ";
    for (const auto &elem : c) {
        std::cout << elem << ' ';
    }
    std::cout << '\n';
```

这将产生以下输出：

```cpp
elements: 1 4 8 15 16 23 42
```

如前面的输出所示，数字`1`按预期的顺序被添加到我们的容器中，即使我们告诉容器将我们的元素添加到`std::vector`的末尾。

我们还可以反转上述操作并验证我们的`erase()`函数是否正常工作，如下所示：

```cpp
    c.erase(c.cbegin());

    std::cout << "elements: ";
    for (const auto &elem : c) {
        std::cout << elem << ' ';
    }
    std::cout << '\n';
```

这将产生以下输出：

```cpp
elements: 4 8 15 16 23 42
```

如您所见，新添加的`1`已成功被移除。

# 添加 std::vector API 的相关部分

在本文中，我们将通过添加`std::vector`已经提供的剩余 API 来完成我们在本章前三个示例中构建的自定义容器。在此过程中，我们将删除不合理的 API，或者我们无法支持的 API，因为我们的自定义容器必须保持`std::vector`中的元素有序。

本文很重要，因为它将向您展示如何正确创建一个包装容器，该容器可用于封装现有容器的逻辑（例如，线程安全，或者在我们的情况下，元素顺序）。

# 准备工作

开始之前，请确保满足所有技术要求，包括安装 Ubuntu 18.04 或更高版本，并在终端窗口中运行以下命令：

```cpp
> sudo apt-get install build-essential git cmake
```

这将确保您的操作系统具有编译和执行本文示例所需的适当工具。完成后，打开一个新的终端。我们将使用此终端来下载、编译和运行我们的示例。

# 如何做...

按照以下步骤尝试本文：

1.  从新的终端运行以下命令来下载源代码：

```cpp
> cd ~/
> git clone https://github.com/PacktPublishing/Advanced-CPP-CookBook.git
> cd Advanced-CPP-CookBook/chapter08
```

1.  要编译源代码，请运行以下命令：

```cpp
> cmake .
> make recipe04_examples
```

1.  源代码编译完成后，可以通过运行以下命令来执行本文中的每个示例：

```cpp
> ./recipe04_example01 
elements: 4 8 15 16 23 42 
elements: 4 8 15 16 23 42 
elements: 4 8 15 16 23 42 
elements: 42 
elements: 4 8 15 16 23 42 
elements: 4 8 15 16 23 42 
c1.at(0): 4
c1.front(): 4
c1.back(): 42
c1.data(): 0xc01eb0
c1.empty(): 0
c1.size(): 6
c1.max_size(): 2305843009213693951
c1.capacity(): 42
c1.capacity(): 6
c1.size(): 0
c1.size(): 42
c1.size(): 0
c1.size(): 42
elements: 4 8 15 16 23 
==: 0
!=: 1
 <: 1
<=: 1
 >: 0
>=: 0
```

在接下来的部分中，我们将逐个介绍每个示例，并解释每个示例程序的作用以及它与本文教授的课程的关系。

# 工作原理...

目前，我们的自定义容器能够被构建、添加、迭代和擦除。然而，该容器不支持直接访问容器或支持简单操作，比如`std::move()`或比较。为了解决这些问题，让我们首先添加缺失的`operator=()`重载：

```cpp
    constexpr container &operator=(const container &other)
    {
        m_v = other.m_v;
        return *this;
    }

    constexpr container &operator=(container &&other) noexcept
    {
        m_v = std::move(other.m_v);
        return *this;
    }    
```

第一个`operator=()`重载支持复制赋值，而第二个重载支持移动赋值。由于我们只有一个提供适当复制和移动语义的私有成员变量，我们不需要担心自赋值（或移动），因为`std::vector`函数的复制和移动实现会为我们处理这个问题。

如果您自己的自定义容器有额外的私有元素，可能需要进行自赋值检查。例如，考虑以下代码：

```cpp
    constexpr container &operator=(container &&other) noexcept
    {
        if (&other == this) {
            return *this;
        }

        m_v = std::move(other.m_v);
        m_something = other.m_something;

        return *this;
    }
```

剩下的`operator=()`重载接受一个初始化列表，如下所示：

```cpp
    constexpr container &operator=(std::initializer_list<T> list)
    {
        m_v = list;
        std::sort(m_v.begin(), m_v.end(), compare_type());

        return *this;
    }
```

在上面的代码片段中，与初始化列表构造函数一样，我们必须在赋值后重新排序`std::vector`，因为初始化列表可以以任何顺序提供。

要实现的下一个成员函数是`assign()`函数。以下代码片段显示了这一点：

```cpp
    constexpr void assign(size_type count, const T &value)
    {
        m_v.assign(count, value);
    }

    template <typename Iter>
    constexpr void assign(Iter first, Iter last)
    {
        m_v.assign(first, last);
        std::sort(m_v.begin(), m_v.end(), compare_type());
    }

    constexpr void assign(std::initializer_list<T> list)
    {
        m_v.assign(list);
        std::sort(m_v.begin(), m_v.end(), compare_type());
    }
```

这些函数类似于`operator=()`重载，但不提供返回值或支持其他功能。让我们看看：

+   第一个`assign()`函数用特定的`value`次数填充`std::vector`。由于值永远不会改变，`std::vector`将始终按排序顺序排列，在这种情况下，不需要对列表进行排序。

+   第二个`assign()`函数接受与构造函数版本相似的迭代器范围。与该函数类似，传递给此函数的迭代器可以来自原始`std::vector`或我们自定义容器的另一个实例，但排序顺序不同。因此，我们必须在赋值后对`std::vector`进行排序。

+   最后，`assign()`函数还提供了与我们的`operator=()`重载相同的初始化列表版本。

还应该注意到，我们已经为每个函数添加了`constexpr`。这是因为我们自定义容器中的大多数函数只是将调用从自定义容器转发到`std::vector`，并且在某些情况下调用`std::sort()`。添加`constexpr`告诉编译器将代码视为编译时表达式，使其能够在启用优化时（如果可能）优化掉额外的函数调用，确保我们的自定义包装器具有尽可能小的开销。

过去，这种优化是使用`inline`关键字执行的。在 C++11 中添加的`constexpr`不仅能够向编译器提供`inline`提示，还告诉编译器这个函数可以在编译时而不是运行时使用（这意味着编译器可以在代码编译时执行函数以执行自定义的编译时逻辑）。然而，在我们的例子中，`std::vector`的运行时使用是不可能的，因为需要分配。因此，使用`constexpr`只是为了优化，在大多数编译器上，`inline`关键字也会提供类似的好处。

`std::vector`还支持许多其他函数，例如`get_allocator()`、`empty()`、`size()`和`max_size()`，所有这些都只是直接转发。让我们专注于直到现在为止从我们的自定义容器中缺失的访问器：

```cpp
    constexpr const_reference at(size_type pos) const
    {
        return m_v.at(pos);
    }
```

我们提供的第一个直接访问`std::vector`的函数是`at()`函数。与我们的大多数成员函数一样，这是一个直接转发。但与`std::vector`不同的是，我们没有计划添加`std::vector`提供的`operator[]()`重载。`at()`函数和`operator[]()`重载之间的区别在于，`operator[]()`不会检查提供的索引是否在范围内（也就是说，它不会访问`std::vector`范围之外的元素）。

`operator[]()`重载的设计类似于标准 C 数组。这个运算符（称为下标运算符）的问题在于缺乏边界检查，这为可靠性和安全性错误进入程序打开了大门。因此，C++核心指南不鼓励使用下标运算符或任何其他形式的指针算术（任何试图通过指针计算数据位置而没有显式边界检查的东西）。

为了防止使用`operator[]()`重载，我们不包括它。

像`std::vector`一样，我们也可以添加`front()`和`back()`访问器，如下所示：

```cpp
    constexpr const_reference front() const
    {
        return m_v.front();
    }

    constexpr const_reference back() const
    {
        return m_v.back();
    }
```

前面的额外访问器支持获取我们的`std::vector`中的第一个和最后一个元素。与`at()`函数一样，我们只支持`std::vector`已经提供的这些函数的`const_reference`版本的使用。

现在让我们看一下`data()`函数的代码片段：

```cpp
    constexpr const T* data() const noexcept
    {
        return m_v.data();
    }
```

`data()`函数也是一样的。我们只能支持这些成员函数的`const`版本，因为提供这些函数的非 const 版本将允许用户直接访问`std::vector`，从而使他们能够插入无序数据，而容器无法重新排序。

现在让我们专注于比较运算符。我们首先定义比较运算符的原型，作为我们容器的友元。这是必要的，因为比较运算符通常被实现为非成员函数，因此需要对容器进行私有访问，以比较它们包含的`std::vector`实例。

例如，考虑以下代码片段：

```cpp
    template <typename O, typename Alloc>
    friend constexpr bool operator==(const container<O, Alloc> &lhs,
                                     const container<O, Alloc> &rhs);

    template <typename O, typename Alloc>
    friend constexpr bool operator!=(const container<O, Alloc> &lhs,
                                     const container<O, Alloc> &rhs);

    template <typename O, typename Alloc>
    friend constexpr bool operator<(const container<O, Alloc> &lhs,
                                    const container<O, Alloc> &rhs);

    template <typename O, typename Alloc>
    friend constexpr bool operator<=(const container<O, Alloc> &lhs,
                                     const container<O, Alloc> &rhs);

    template <typename O, typename Alloc>
    friend constexpr bool operator>(const container<O, Alloc> &lhs,
                                    const container<O, Alloc> &rhs);

    template <typename O, typename Alloc>
    friend constexpr bool operator>=(const container<O, Alloc> &lhs,
                                     const container<O, Alloc> &rhs);
```

最后，我们按照以下方式实现比较运算符：

```cpp
template <typename O, typename Alloc>
bool constexpr operator==(const container<O, Alloc> &lhs,
                          const container<O, Alloc> &rhs)
{
    return lhs.m_v == rhs.m_v;
}

template <typename O, typename Alloc>
bool constexpr operator!=(const container<O, Alloc> &lhs,
                          const container<O, Alloc> &rhs)
{
    return lhs.m_v != rhs.m_v;
}
```

与成员函数一样，我们只需要将调用转发到`std::vector`，因为没有必要实现自定义逻辑。剩下的比较运算符也是一样。

例如，我们可以按照以下方式实现`>`、`<`、`>=`和`<=`比较运算符：

```cpp
template <typename O, typename Alloc>
bool constexpr operator<(const container<O, Alloc> &lhs,
                         const container<O, Alloc> &rhs)
{
    return lhs.m_v < rhs.m_v;
}

template <typename O, typename Alloc>
bool constexpr operator<=(const container<O, Alloc> &lhs,
                          const container<O, Alloc> &rhs)
{
    return lhs.m_v <= rhs.m_v;
}

template <typename O, typename Alloc>
bool constexpr operator>(const container<O, Alloc> &lhs,
                         const container<O, Alloc> &rhs)
{
    return lhs.m_v > rhs.m_v;
}

template <typename O, typename Alloc>
bool constexpr operator>=(const container<O, Alloc> &lhs,
                          const container<O, Alloc> &rhs)
{
    return lhs.m_v >= rhs.m_v;
}
```

就是这样！这就是通过利用现有容器来实现自己的容器的方法。

正如我们所看到的，在大多数情况下，除非你需要的容器无法使用 C++标准模板库已经提供的容器来实现，否则没有必要从头开始实现一个容器。

使用这种方法，不仅可以创建自己的容器，更重要的是可以将代码中重复的功能封装到一个单独的容器中，这样可以独立测试和验证。这不仅提高了应用程序的可靠性，而且还使其更易于阅读和维护。

在下一章中，我们将探讨如何在 C++中使用智能指针。


# 第九章：探索类型擦除

在本章中，您将学习类型擦除（也称为类型擦除）是什么，以及如何在自己的应用程序中使用它。本章很重要，因为类型擦除提供了在不需要对象共享公共基类的情况下使用不同类型对象的能力。

本章从简单解释类型擦除开始，解释了在 C 语言中类型擦除的工作原理，以及如何在 C++中使用继承来执行类型擦除。下一个示例将提供使用 C++模板的不同方法来进行类型擦除，这将教会您如何使用 C++概念来定义类型的规范，而不是类型本身。

接下来，我们将学习经典的 C++类型擦除模式。本示例将教会您擦除类型信息的技能，从而能够创建类型安全的通用代码。最后，我们将通过一个全面的示例来结束，该示例使用类型擦除来实现委托模式，这是一种提供包装任何类型的可调用对象的能力的模式，并且被诸如 ObjC 等语言广泛使用。

本章的示例如下：

+   如何使用继承来擦除类型

+   使用 C++模板编写通用函数

+   学习 C++类型擦除模式

+   实现委托模式

# 技术要求

要编译和运行本章中的示例，您必须具有对运行 Ubuntu 18.04 的计算机的管理访问权限，并且具有正常的互联网连接。在运行这些示例之前，您必须安装以下内容：

```cpp
> sudo apt-get install build-essential git cmake
```

如果这安装在 Ubuntu 18.04 以外的任何操作系统上，则需要 GCC 7.4 或更高版本和 CMake 3.6 或更高版本。

本章的代码文件可以在[`github.com/PacktPublishing/Advanced-CPP-CookBook/tree/master/chapter09`](https://github.com/PacktPublishing/Advanced-CPP-CookBook/tree/master/chapter09)找到。

# 如何使用继承来擦除类型

在本示例中，我们将学习如何使用继承来擦除类型。当讨论类型擦除时，通常不考虑继承，但实际上，继承是 C++中最常见的类型擦除形式。本示例很重要，因为它将讨论类型擦除是什么，以及为什么它在日常应用中非常有用，而不仅仅是简单地移除类型信息——这在 C 中很常见。

# 准备工作

在开始之前，请确保满足所有技术要求，包括安装 Ubuntu 18.04 或更高版本，并在终端窗口中运行以下命令：

```cpp
> sudo apt-get install build-essential git cmake
```

这将确保您的操作系统具有正确的工具来编译和执行本示例中的示例。完成后，打开一个新的终端。我们将使用这个终端来下载、编译和运行我们的示例。

# 如何做...

让我们尝试按照以下步骤进行本示例：

1.  从新的终端运行以下命令以下载源代码：

```cpp
> cd ~/
> git clone https://github.com/PacktPublishing/Advanced-CPP-CookBook.git
> cd Advanced-CPP-CookBook/chapter09
```

1.  要编译源代码，请运行以下命令：

```cpp
> cmake .
> make recipe01_examples
```

1.  一旦源代码编译完成，您可以通过运行以下命令来执行本示例中的每个示例：

```cpp
> ./recipe01_example01 
1
0
```

在接下来的部分，我们将逐个介绍这些示例，并解释每个示例程序的作用以及它与本示例中所教授的课程的关系。

# 工作原理...

类型擦除（或类型擦除）简单地是移除、隐藏或减少有关对象、函数等的类型信息。在 C 语言中，类型擦除经常被使用。看看这个例子：

```cpp
int array[10];
memset(array, 0, sizeof(array));
```

在上面的例子中，我们创建了一个包含`10`个元素的数组，然后使用`memset()`函数将数组清零。在 C 中，`memset()`函数看起来像这样：

```cpp
void *memset(void *ptr, int value, size_t num)
{
    size_t i;
    for (i = 0; i < num; i++) {
        ((char *)ptr)[i] = value;    
    }

    return ptr;
}
```

在上面的代码片段中，`memset()`函数的第一个参数是`void*`。然而，在我们之前的例子中，数组是一个整数数组。`memset()`函数实际上并不关心你提供的是什么类型，只要你提供了指向该类型的指针和表示该类型总字节数的大小。然后，`memset()`函数将提供的指针强制转换为表示字节的类型（在 C 中通常是`char`或无符号`char`），然后逐字节设置类型的值。

在 C 中使用`void*`是一种类型擦除的形式。在 C++中，这种类型（双关语）的擦除通常是不鼓励的，因为要恢复类型信息的唯一方法是使用`dynamic_cast()`，这很慢（需要运行时类型信息查找）。尽管有许多种方法可以在 C++中执行类型擦除而不需要`void*`，让我们专注于继承。

继承在大多数文献中通常不被描述为类型擦除，但它很可能是最广泛使用的形式之一。为了更好地探讨这是如何工作的，让我们看一个常见的例子。假设我们正在创建一个游戏，其中用户可以选择多个超级英雄。每个超级英雄在某个时候都必须攻击坏家伙，但超级英雄如何攻击坏家伙因英雄而异。

例如，考虑以下代码片段：

```cpp
class spiderman
{
public:
    bool attack(int x, int) const
    {
        return x == 0 ? true : false;
    }
};
```

如上所示，在我们的第一个英雄中，不关心坏家伙是在地面上还是在空中（也就是说，无论坏家伙的垂直距离如何，英雄都能成功击中坏家伙），但如果坏家伙不在特定的水平位置，英雄就会错过坏家伙。同样，我们可能还有另一个英雄如下：

```cpp
class captain_america
{
public:
    bool attack(int, int y) const
    {
        return y == 0 ? true : false;
    }
};
```

第二个英雄与我们的第一个完全相反。这个英雄可以成功地击中地面上的坏家伙，但如果坏家伙在地面以上的任何地方，他就会错过（英雄可能无法到达他们）。

在下面的例子中，两个超级英雄同时与坏家伙战斗：

```cpp
    for (const auto &h : heroes) {
        std::cout << h->attack(0, 42) << '\n';
    }
```

虽然我们可以在战斗中一个一个地召唤每个超级英雄，但如果我们可以只循环遍历每个英雄并检查哪个英雄击中了坏家伙，哪个英雄错过了坏家伙，那将更加方便。

在上面的例子中，我们有一个假想的英雄数组，我们循环遍历，检查哪个英雄击中了，哪个英雄错过了。在这个例子中，我们不关心英雄的类型（也就是说，我们不关心英雄是否特别是我们的第一个还是第二个英雄），我们只关心每个英雄实际上是一个英雄（而不是一个无生命的物体），并且英雄能够攻击坏家伙。换句话说，我们需要一种方法来擦除每个超级英雄的类型，以便我们可以将两个英雄放入单个数组中（除非每个英雄都是相同的，否则这是不可能的）。

正如你可能已经猜到的那样，在 C++中实现这一点的最常见方法是使用继承（但正如我们将在本章后面展示的那样，这并不是唯一的方法）。首先，我们必须定义一个名为`hero`的基类，每个英雄都将从中继承，如下所示：

```cpp
class hero
{
public:
    virtual ~hero() = default;
    virtual bool attack(int, int) const = 0;
};
```

在我们的例子中，每个英雄之间唯一的共同函数是它们都可以攻击坏家伙，`attack()`函数对所有英雄都是相同的。因此，我们创建了一个纯虚基类，其中包含一个名为`attack()`的单个纯虚函数，每个英雄都必须实现。还应该注意的是，为了使一个类成为纯虚类，所有成员函数必须设置为`0`，并且类的析构函数必须显式标记为`virtual`。

现在我们已经定义了什么是英雄，我们可以修改我们的英雄，使其继承这个纯虚基类，如下所示：

```cpp
class spiderman : public hero
{
public:
    bool attack(int x, int) const override
    {
        return x == 0 ? true : false;
    }
};

class captain_america : public hero
{
public:
    bool attack(int, int y) const override
    {
        return y == 0 ? true : false;
    }
};
```

如上所示，两个英雄都继承了英雄的纯虚定义，并根据需要重写了`attack()`函数。通过这种修改，我们现在可以按以下方式创建我们的英雄列表：

```cpp
int main(void)
{
    std::array<std::unique_ptr<hero>, 2> heros {
        std::make_unique<spiderman>(),
        std::make_unique<captain_america>()
    };

    for (const auto &h : heros) {
        std::cout << h->attack(0, 42) << '\n';
    }

    return 0;
}
```

从上面的代码中，我们观察到以下内容：

+   我们创建了一个`hero`指针数组（使用`std::unique_ptr`来存储英雄的生命周期，这是下一章将讨论的一个主题）。

+   然后，该数组被初始化为包含两个英雄（每个英雄一个）。

+   最后，我们循环遍历每个英雄，看英雄是否成功攻击坏人或者错过。

+   当调用`hero::attack()`函数时，调用会自动路由到正确的`spiderman::attack()`和`captain_america::attack()`函数，通过继承来实现。

该数组以类型安全的方式擦除了每个英雄的类型信息，将每个英雄放入单个容器中。

# 使用 C++模板编写通用函数

在本示例中，我们将学习如何使用 C++模板来擦除（或忽略）类型信息。您将学习如何使用 C++模板来实现 C++概念，以及这种类型擦除在 C++标准库中的使用。这个示例很重要，因为它将教会您如何更好地设计您的 API，使其不依赖于特定类型（或者换句话说，如何编写通用代码）。

# 准备工作

开始之前，请确保满足所有技术要求，包括安装 Ubuntu 18.04 或更高版本，并在终端窗口中运行以下命令：

```cpp
> sudo apt-get install build-essential git cmake
```

这将确保您的操作系统具有适当的工具来编译和执行本示例中的示例。完成后，打开一个新的终端。我们将使用这个终端来下载、编译和运行我们的示例。

# 如何做...

让我们按照以下步骤尝试这个示例：

1.  从新的终端运行以下命令以下载源代码：

```cpp
> cd ~/
> git clone https://github.com/PacktPublishing/Advanced-CPP-CookBook.git
> cd Advanced-CPP-CookBook/chapter09
```

1.  要编译源代码，请运行以下命令：

```cpp
> cmake .
> make recipe02_examples
```

1.  源代码编译后，可以通过运行以下命令来执行本文中的每个示例：

```cpp
> ./recipe02_example01 
hero won fight
hero lost the fight :(
```

在接下来的部分中，我们将逐个步骤地介绍每个示例，并解释每个示例程序的作用以及它与本示例中所教授的课程的关系。

# 工作原理...

C++最古老和最广泛使用的功能之一是 C++模板。与继承一样，C++模板通常不被描述为一种类型擦除，但它们实际上是。类型擦除只不过是删除或在这种情况下忽略类型信息的行为。

然而，与 C 语言不同，C++中的类型擦除通常试图避免删除类型信息，而是绕过类型的严格定义，同时保留类型安全。实现这一点的一种方法是通过使用 C++模板。为了更好地解释这一点，让我们从一个 C++模板的简单示例开始：

```cpp
template<typename T>
T pow2(T t)
{
    return t * t;
}
```

在上面的示例中，我们创建了一个简单的函数，用于计算任何给定输入的平方。例如，我们可以这样调用这个函数：

```cpp
std::cout << pow2(42U) << '\n'
std::cout << pow2(-1) << '\n'
```

当编译器看到`pow2()`函数的使用时，它会在幕后自动生成以下代码：

```cpp
unsigned pow2(unsigned t)
{
    return t * t;
}

int pow2(int t)
{
    return t * t;
}
```

在上面的代码片段中，编译器创建了`pow2()`函数的两个版本：一个接受无符号值并返回无符号值，另一个接受整数并返回整数。编译器创建了这两个版本，是因为我们第一次使用`pow2()`函数时，我们提供了一个无符号值，而第二次使用`pow2()`函数时，我们提供了`int`。

就我们的代码而言，我们实际上并不关心函数提供的类型是什么，只要提供的类型能够成功执行`operator*()`。换句话说，`pow2()`函数的使用者和`pow2()`函数的作者都安全地忽略（或擦除）了从概念上传递给函数的类型信息。然而，编译器非常清楚正在提供的类型，并且必须根据需要安全地处理每种类型。

这种类型擦除形式在 API 的规范处执行擦除，在 C++中，这种规范被称为概念。与大多数 API 不同，后者规定了输入和输出类型（例如，`sleep()`函数接受一个无符号整数，只接受无符号整数），概念特别忽略类型，而是定义了给定类型必须提供的属性。

例如，前面的`pow2()`函数有以下要求：

+   提供的类型必顺要么是整数类型，要么提供`operator *()`。

+   提供的类型必须是可复制构造或可移动构造的。

如前面的代码片段所示，`pow2()`函数不关心它所接收的类型，只要所提供的类型满足一定的最小要求。让我们来看一个更复杂的例子，以演示 C++模板如何被用作类型擦除的一种形式。假设我们有两个不同的英雄在与一个坏家伙战斗，每个英雄都提供了攻击坏家伙的能力，如下所示：

```cpp
class spiderman
{
public:
    bool attack(int x, int) const
    {
        return x == 0 ? true : false;
    }
};

class captain_america
{
public:
    bool attack(int, int y) const
    {
        return y == 0 ? true : false;
    }
};
```

如前面的代码片段所示，每个英雄都提供了攻击坏家伙的能力，但除了两者都提供具有相同函数签名的`attack()`函数之外，两者没有任何共同之处。我们也无法为每个英雄添加继承（也许我们的设计无法处理继承所增加的额外`vTable`开销，或者英雄定义是由其他人提供的）。

现在假设我们有一个复杂的函数，必须为每个英雄调用`attack()`函数。我们可以为每个英雄编写相同的逻辑（即手动复制逻辑），或者我们可以编写一个 C++模板函数来处理这个问题，如下所示：

```cpp
template<typename T>
auto attack(const T &t, int x, int y)
{
    if (t.attack(x, y)) {
        std::cout << "hero won fight\n";
    }
    else {
        std::cout << "hero lost the fight :(\n";
    }
}
```

如前面的代码片段所示，我们可以利用 C++模板的类型擦除特性，将我们的攻击逻辑封装到一个单一的模板函数中。前面的代码不关心所提供的类型是什么，只要该类型提供了一个接受两个整数类型并返回一个整数类型（最好是`bool`，但任何整数都可以）的`attack()`函数。换句话说，只要所提供的类型符合约定的概念，这个模板函数就会起作用，为编译器提供一种处理类型特定逻辑的方法。

我们可以按照以下方式调用前面的函数：

```cpp
int main(void)
{
    attack(spiderman{}, 0, 42);
    attack(captain_america{}, 0, 42);

    return 0;
}
```

这将产生以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/70426f57-68a7-48bf-ac42-6ee95388297b.png)

尽管这个示例展示了 C++模板如何被用作类型擦除的一种形式（至少用于创建概念的规范），但是当讨论类型擦除时，有一种特定的模式称为类型擦除模式或者只是类型擦除。在下一个示例中，我们将探讨如何利用我们在前两个示例中学到的知识来擦除类型信息，同时仍然支持诸如容器之类的简单事物。

# 还有更多...

在这个示例中，我们学习了如何使用概念来忽略（或擦除）特定类型的知识，而是要求类型实现一组最小的特性。这些特性可以使用 SFINAE 来强制执行，这是我们在第四章中更详细讨论的一个主题，*使用模板进行通用编程*。

# 另请参阅

在第十三章中，*奖励-使用 C++20 功能*，我们还将讨论如何使用 C++20 新增的功能来执行概念的强制执行。

# 学习 C++类型擦除模式

在本菜谱中，我们将学习 C++中类型擦除模式是什么，以及我们如何利用它来通用地擦除类型信息，而不会牺牲类型安全性或要求我们的类型继承纯虚拟基类。这个菜谱很重要，因为类型擦除模式在 C++标准库中被大量使用，并提供了一种简单的方式来封装不共享任何共同之处的数据类型，除了提供一组类似的 API，同时还支持诸如容器之类的东西。

# 准备工作

开始之前，请确保满足所有技术要求，包括安装 Ubuntu 18.04 或更高版本，并在终端窗口中运行以下命令：

```cpp
> sudo apt-get install build-essential git cmake
```

这将确保您的操作系统具有编译和执行本菜谱中示例所需的适当工具。完成后，打开一个新的终端。我们将使用这个终端来下载、编译和运行我们的示例。

# 如何做...

让我们尝试以下步骤来制作这个菜谱：

1.  从一个新的终端中，运行以下命令来下载源代码：

```cpp
> cd ~/
> git clone https://github.com/PacktPublishing/Advanced-CPP-CookBook.git
> cd Advanced-CPP-CookBook/chapter09
```

1.  编译源代码，请运行以下命令：

```cpp
> cmake .
> make recipe03_examples
```

1.  源代码编译完成后，您可以通过运行以下命令来执行本菜谱中的每个示例：

```cpp
> ./recipe03_example01 
1
0
```

在下一节中，我们将逐个介绍这些示例，并解释每个示例程序的作用，以及它与本菜谱中所教授的课程的关系。

# 工作原理...

当我们通常考虑 C++类型擦除时，这就是我们想到的例子。当我们必须将一组对象视为相关对象使用时，可能并不共享一个共同的基类（也就是说，它们要么不使用继承，要么如果使用继承，可能它们不继承自相同的一组类）时，就需要类型擦除模式。

例如，假设我们有以下类：

```cpp
class spiderman
{
public:
    bool attack(int x, int) const
    {
        return x == 0 ? true : false;
    }
};

class captain_america
{
public:
    bool attack(int, int y) const
    {
        return y == 0 ? true : false;
    }
};
```

如前面的代码片段所示，每个类定义了不同类型的英雄。我们想要做的事情如下：

```cpp
for (const auto &h : heros) {
    // something
}
```

问题是，每个类都不继承自相似的基类，所以我们不能只创建每个类的实例并将它们添加到`std::array`中，因为编译器会抱怨这些类不相同。我们可以在`std::array`中存储每个类的原始`void *`指针，但是当使用`void *`时，我们将不得不使用`dynamic_cast()`来将其转换回每种类型以执行任何有用的操作，如下所示：

```cpp
    std::array<void *, 2> heros {
        new spiderman,
        new captain_america
    };

    for (const auto &h : heros) {
        if (ptr = dynamic_cast<spiderman>(ptr)) {
            // something
        }

        if (ptr = dynamic_cast<captain_america>(ptr)) {
            // something
        }
    }
```

使用`void *`是一种类型擦除的形式，但这远非理想，因为使用`dynamic_cast()`很慢，每添加一种新类型都只会增加`if`语句的数量，而且这种实现远非符合 C++核心指南。

然而，还有另一种方法可以解决这个问题。假设我们希望运行`attack()`函数，这个函数在每个英雄类之间是相同的（也就是说，每个英雄类至少遵循一个共享概念）。如果每个类都使用了以下基类，我们可以使用继承，如下所示：

```cpp
class base
{
public:
    virtual ~base() = default;
    virtual bool attack(int, int) const = 0;
};
```

问题是，我们的英雄类没有继承这个基类。因此，让我们创建一个继承它的包装器类，如下所示：

```cpp
template<typename T>
class wrapper :
    public base
{
    T m_t;

public:
    bool attack(int x, int y) const override
    {
        return m_t.attack(x, y);
    }
};
```

如前面的代码片段所示，我们创建了一个模板包装类，它继承自我们的基类。这个包装器存储给定类型的实例，然后覆盖了在纯虚拟基类中定义的`attack()`函数，该函数将调用转发给包装器存储的实例。

现在，我们可以创建我们的数组，如下所示：

```cpp
    std::array<std::unique_ptr<base>, 2> heros {
        std::make_unique<wrapper<spiderman>>(),
        std::make_unique<wrapper<captain_america>>()
    };
```

`std::array`存储了指向我们基类的`std::unique_ptr`，然后我们使用每种需要的类型创建我们的包装器类（它继承自基类），以存储在数组中。编译器为我们需要存储在数组中的每种类型创建了包装器的版本，由于包装器继承了基类，无论我们给包装器什么类型，数组总是可以按需存储结果包装器。

现在，我们可以从这个数组中执行以下操作：

```cpp
    for (const auto &h : heros) {
        std::cout << h->attack(0, 42) << '\n';
    }
```

就是这样：C++中的类型擦除。这种模式利用 C++模板，即使对象本身没有直接使用继承，也可以给对象赋予继承的相同属性。

# 使用类型擦除实现委托

在这个示例中，我们将学习如何实现委托模式，这是一个已经存在多年的模式（并且被一些其他语言，比如 ObjC，广泛使用）。这个示例很重要，因为它将教会你什么是委托，以及如何在你自己的应用程序中利用这种模式，以提供更好的可扩展性，而不需要你的 API 使用继承。

# 准备工作

在开始之前，请确保满足所有技术要求，包括安装 Ubuntu 18.04 或更高版本，并在终端窗口中运行以下命令：

```cpp
> sudo apt-get install build-essential git cmake
```

这将确保您的操作系统具有编译和执行本示例中的示例所需的适当工具。完成后，打开一个新的终端。我们将使用这个终端来下载、编译和运行我们的示例。

# 如何做...

让我们按照以下步骤尝试这个示例：

1.  从一个新的终端中，运行以下命令来下载源代码：

```cpp
> cd ~/
> git clone https://github.com/PacktPublishing/Advanced-CPP-CookBook.git
> cd Advanced-CPP-CookBook/chapter09
```

1.  要编译源代码，请运行以下命令：

```cpp
> cmake .
> make recipe04_examples
```

1.  一旦源代码编译完成，您可以通过运行以下命令执行本示例中的每个示例：

```cpp
> ./recipe04_example01
1
0

> ./recipe04_example02
1
0

> ./recipe04_example03
1
0

> ./recipe04_example04
0
1
0
```

在下一节中，我们将逐个介绍这些示例，并解释每个示例程序的作用以及它与本示例中所教授的课程的关系。

# 它是如何工作的...

如果你曾经读过一本关于 C++的书，你可能已经看过苹果和橙子的例子，它演示了面向对象编程的工作原理。思路如下：

+   苹果是一种水果。

+   橙子是一种水果。

+   苹果不是橙子，但两者都是水果。

这个例子旨在教你如何使用继承将代码组织成逻辑对象。一个苹果和一个橙子共享的逻辑被写入一个叫做`fruit`的对象中，而特定于苹果或橙子的逻辑被写入继承自基类`fruit`的`apple`或`orange`对象中。

这个例子也展示了如何扩展水果的功能。通过对水果进行子类化，我可以创建一个苹果，它能够做比`fruit`基类更多的事情。这种*扩展*类功能的想法在 C++中很常见，通常我们会考虑使用继承来实现它。在这个示例中，我们将探讨如何在不需要苹果或橙子使用继承的情况下实现这一点，而是使用一种称为委托的东西。

假设你正在创建一个游戏，并希望实现一个英雄和坏人在战斗中战斗的战场。在代码的某个地方，战斗中的每个英雄都需要攻击坏人。问题是英雄在战斗中来来去去，因为他们需要时间恢复，所以你真的需要维护一个能够攻击坏人的英雄列表，并且你只需要循环遍历这个动态变化的英雄列表，看看他们的攻击是否成功。

每个英雄都可以存储一个子类化共同基类的英雄列表，然后运行一个`attack()`函数，每个英雄都会重写，但这将需要使用继承，这可能不是期望的。我们也可以使用类型擦除模式来包装每个英雄，然后存储指向我们包装器的基类的指针，但这将特定于我们的`attack()`函数，并且我们相信将需要其他这些类型的扩展的情况。

进入委托模式，这是类型擦除模式的扩展。使用委托模式，我们可以编写如下代码：

```cpp
int main(void)
{
    spiderman s;
    captain_america c;

    std::array<delegate<bool(int, int)>, 3> heros {
        delegate(attack),
        delegate(&s, &spiderman::attack),
        delegate(&c, &captain_america::attack)
    };

    for (auto &h : heros) {
        std::cout << h(0, 42) << '\n';
    }

    return 0;
}
```

如前面的代码片段所示，我们定义了两个不同的类的实例，然后创建了一个存储三个委托的数组。委托的模板参数采用`bool(int, int)`的函数签名，而委托本身似乎是从函数指针以及我们之前创建的类实例的两个成员函数指针创建的。然后我们能够循环遍历每个委托并调用它们，有效地独立调用函数指针和每个成员函数指针。

委托模式提供了将不同的可调用对象封装到一个具有共同类型的单个对象中的能力，该对象能够调用可调用对象，只要它们共享相同的函数签名。更重要的是，委托可以封装函数指针和成员函数指针，为 API 的用户提供了必要时存储私有状态的能力。

为了解释这是如何工作的，我们将从简单的开始，然后逐步构建我们的示例，直到达到最终实现。让我们从一个基类开始：

```cpp
template<
    typename RET,
    typename... ARGS
    >
class base
{
public:
    virtual ~base() = default;
    virtual RET func(ARGS... args) = 0;
};
```

如前面的代码片段所示，我们创建了一个纯虚基类的模板。模板参数是`RET`（定义返回值）和`ARGS...`（定义可变参数列表）。然后我们创建了一个名为`func()`的函数，它接受我们的参数列表并返回模板返回类型。

接下来，让我们定义一个从基类继承的包装器，使用类型擦除模式（如果您还没有阅读之前的示例，请现在阅读）：

```cpp
template<
    typename T,
    typename RET,
    typename... ARGS
    >
class wrapper :
    public base<RET, ARGS...>
{
    T m_t{};
    RET (T::*m_func)(ARGS...);

public:

    wrapper(RET (T::*func)(ARGS...)) :
        m_func{func}
    { }

    RET func(ARGS... args) override
    {
        return std::invoke(m_func, &m_t, args...);
    }
};
```

就像类型擦除模式一样，我们有一个包装器类，它存储我们的类型的实例，然后提供包装器可以调用的函数。不同之处在于可以调用的函数不是静态定义的，而是由提供的模板参数定义的。此外，我们还存储具有相同函数签名的函数指针，该函数指针由包装器的构造函数初始化，并在`func()`函数中使用`std::invoke`调用。

与典型的类型擦除示例相比，这个额外的逻辑提供了定义我们希望从我们在包装器中存储的对象中调用的任何函数签名的能力，而不是提前定义（意味着我们希望调用的函数可以在运行时而不是编译时确定）。

然后我们可以创建我们的委托类如下：

```cpp
template<
    typename RET,
    typename... ARGS
    >
class delegate
{
    std::unique_ptr<base<RET, ARGS...>> m_wrapper;

public:

    template<typename T>
    delegate(RET (T::*func)(ARGS...)) :
        m_wrapper{
            std::make_unique<wrapper<T, RET, ARGS...>>(func)
        }
    { }

    RET operator()(ARGS... args)
    {
        return m_wrapper->func(args...);
    }
};
```

与类型擦除模式一样，我们将指针存储在包装器中，该包装器是从委托的构造函数中创建的。要注意的重要细节是`T`类型在委托本身中未定义。相反，`T`类型仅在创建委托时才知道，用于创建包装器的实例。这意味着每个委托实例都是相同的，即使委托存储了包装不同类型的包装器。这使我们可以像下面这样使用委托。

假设我们有两个英雄，它们没有共同的基类，但提供了相同签名的`attack()`函数：

```cpp
class spiderman
{
public:
    bool attack(int x, int)
    {
        return x == 0 ? true : false;
    }
};

class captain_america
{
public:
    bool attack(int, int y)
    {
        return y == 0 ? true : false;
    }
};
```

我们可以利用我们的委托类来存储我们的英雄类的实例，并调用它们的攻击函数如下：

```cpp
int main(void)
{
    std::array<delegate<bool, int, int>, 2> heros {
        delegate(&spiderman::attack),
        delegate(&captain_america::attack)
    };

    for (auto &h : heros) {
        std::cout << h(0, 42) << '\n';
    }

    return 0;
}
```

这导致以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/36666375-3829-4923-ab93-fc4ef67966c3.png)

尽管我们已经在创建我们的委托中取得了重大进展（它至少可以工作），但这个早期实现还存在一些问题：

+   委托的签名是`bool, int, int`，这是误导性的，因为我们真正想要的是一个函数签名，比如`bool(int, int)`，这样代码就是自说明的（委托的类型是单个函数签名，而不是三种不同的类型）。

+   这个委托不能处理标记为`const`的函数。

+   我们必须在包装器内部存储被委托对象的实例，这样我们就无法为同一对象创建多个函数的委托。

+   我们不支持非成员函数。

让我们逐个解决这些问题。

# 向我们的代理添加函数签名

尽管在不需要 C++17 的情况下可以向我们的代理添加函数签名作为模板参数，但是 C++17 中的用户定义类型推导使这个过程变得简单。以下代码片段展示了这一点：

```cpp
template<
    typename T,
    typename RET,
    typename... ARGS
    >
delegate(RET(T::*)(ARGS...)) -> delegate<RET(ARGS...)>;
```

如前所示的代码片段显示，用户定义的类型推导告诉编译器如何将我们的代理构造函数转换为我们希望使用的模板签名。没有这个用户定义的类型推导指南，`delegate(RET(T::*)(ARGS...))`构造函数将导致代理被推断为`delegate<RET, ARGS...>`，这不是我们想要的。相反，我们希望编译器推断`delegate<RET(ARGS...)>`。我们的代理实现的其他方面都不需要改变。我们只需要告诉编译器如何执行类型推断。

# 向我们的代理添加 const 支持

我们的代理目前无法接受标记为`const`的成员函数，因为我们没有为我们的代理提供能够这样做的包装器。例如，我们英雄的`attack()`函数目前看起来像这样：

```cpp
class spiderman
{
public:
    bool attack(int x, int)
    {
        return x == 0 ? true : false;
    }
};
```

然而，我们希望我们的英雄`attack()`函数看起来像以下这样，因为它们不修改任何私有成员变量：

```cpp
class spiderman
{
public:
    bool attack(int x, int) const
    {
        return x == 0 ? true : false;
    }
};
```

为了支持这个改变，我们必须创建一个支持这一点的包装器，如下所示：

```cpp
template<
    typename T,
    typename RET,
    typename... ARGS
    >
class wrapper_const :
    public base<RET, ARGS...>
{
    T m_t{};
    RET (T::*m_func)(ARGS...) const;

public:

    wrapper_const(RET (T::*func)(ARGS...) const) :
        m_func{func}
    { }

    RET func(ARGS... args) override
    {
        return std::invoke(m_func, &m_t, args...);
    }
};
```

如前所示，这个包装器与我们之前的包装器相同，不同之处在于我们存储的函数签名具有额外的`const`实例。为了使代理使用这个额外的包装器，我们还必须提供另一个代理构造函数，如下所示：

```cpp
    template<typename T>
    delegate(RET (T::*func)(ARGS...) const) :
        m_wrapper{
            std::make_unique<wrapper_const<T, RET, ARGS...>>(func)
        }
    { }
```

这意味着我们还需要另一个用户定义的类型推导指南，如下所示：

```cpp
template<
    typename T,
    typename RET,
    typename... ARGS
    >
delegate(RET(T::*)(ARGS...) const) -> delegate<RET(ARGS...)>;
```

通过这些修改，我们现在可以支持标记为`const`的成员函数。

# 向我们的代理添加一对多的支持

目前，我们的包装器存储每种类型的实例。这种方法通常与类型擦除一起使用，但在我们的情况下，它阻止了为同一个对象创建多个代理的能力（即不支持一对多）。为了解决这个问题，我们将在我们的包装器中存储对象的指针，而不是对象本身，如下所示：

```cpp
template<
    typename T,
    typename RET,
    typename... ARGS
    >
class wrapper :
    public base<RET, ARGS...>
{
    const T *m_t{};
    RET (T::*m_func)(ARGS...);

public:

    wrapper(const T *t, RET (T::*func)(ARGS...)) :
        m_t{t},
        m_func{func}
    { }

    RET func(ARGS... args) override
    {
        return std::invoke(m_func, m_t, args...);
    }
};
```

如前所示，我们所做的唯一改变是我们存储一个指向我们包装的对象的指针，而不是对象本身，这也意味着我们需要在构造函数中初始化这个指针。为了使用这个新的包装器，我们必须修改我们的代理构造函数如下：

```cpp
    template<typename T>
    delegate(const T *t, RET (T::*func)(ARGS...)) :
        m_wrapper{
            std::make_unique<wrapper<T, RET, ARGS...>>(t, func)
        }
    { }
```

这又意味着我们必须更新我们的用户定义类型推导指南，如下所示：

```cpp
template<
    typename T,
    typename RET,
    typename... ARGS
    >
delegate(const T *, RET(T::*)(ARGS...)) -> delegate<RET(ARGS...)>;
```

通过这些修改，我们现在可以创建我们的代理，如下所示：

```cpp
int main(void)
{
    spiderman s;
    captain_america c;

    std::array<delegate<bool(int, int)>, 2> heros {
        delegate(&s, &spiderman::attack),
        delegate(&c, &captain_america::attack)
    };

    for (auto &h : heros) {
        std::cout << h(0, 42) << '\n';
    }

    return 0;
}
```

如前所示，代理接受每个对象的指针，这意味着我们可以创建任意数量的这些代理，包括根据需要创建对其他成员函数指针的代理的能力。

# 向我们的代理添加对非成员函数的支持

最后，我们需要修改代理以支持非成员函数。看看这个例子：

```cpp
bool attack(int x, int y)
{
    return x == 42 && y == 42 ? true : false;
}
```

为了做到这一点，我们只需要添加另一个包装器，如下所示：

```cpp
template<
    typename RET,
    typename... ARGS
    >
class fun_wrapper :
    public base<RET, ARGS...>
{
    RET (*m_func)(ARGS...);

public:

    fun_wrapper(RET (*func)(ARGS...)) :
        m_func{func}
    { }

    RET func(ARGS... args) override
    {
        return m_func(args...);
    }
};
```

如前所示，与我们的原始包装器一样，我们存储我们希望调用的函数的指针，但在这种情况下，我们不需要存储对象的指针，因为没有对象（因为这是一个非成员函数包装器）。为了使用这个新的包装器，我们必须添加另一个代理构造函数，如下所示：

```cpp
    delegate(RET (func)(ARGS...)) :
        m_wrapper{
            std::make_unique<fun_wrapper<RET, ARGS...>>(func)
        }
    { }
```

这意味着我们还必须提供另一个用户定义的类型推导指南，如下所示：

```cpp
template<
    typename RET,
    typename... ARGS
    >
delegate(RET(*)(ARGS...)) -> delegate<RET(ARGS...)>;
```

通过所有这些修改，我们最终能够使用我们在本篇文章开头定义的代理：

```cpp
int main(void)
{
    spiderman s;
    captain_america c;

    std::array<delegate<bool(int, int)>, 3> heros {
        delegate(attack),
        delegate(&s, &spiderman::attack),
        delegate(&c, &captain_america::attack)
    };

    for (auto &h : heros) {
        std::cout << h(0, 42) << '\n';
    }

    return 0;
}
```

当这个被执行时，我们得到以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp-prog-cb/img/59994462-e91d-48fa-bcaf-1538fa6e4e37.png)

这个委托可以进一步扩展以支持 lambda 函数，方法是添加另一组包装器，并且可以通过使用一个小缓冲区来替换委托中的`std::unique_pointer`，从而避免动态内存分配，这个小缓冲区的大小与成员函数包装器相同（或者换句话说，实现小尺寸优化）。
