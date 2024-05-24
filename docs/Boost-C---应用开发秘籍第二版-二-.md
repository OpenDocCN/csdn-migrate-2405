# Boost C++ 应用开发秘籍第二版（二）

> 原文：[`annas-archive.org/md5/8a1821d22bcd421390c328e6f1d92500`](https://annas-archive.org/md5/8a1821d22bcd421390c328e6f1d92500)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第三章：转换和转型

在本章中，我们将涵盖：

+   将字符串转换为数字

+   将数字转换为字符串

+   将数字转换为数字

+   将用户定义的类型转换为/从字符串

+   转换智能指针

+   转换多态对象

+   解析简单输入

+   解析复杂输入

# 介绍

现在，我们知道了一些基本的 Boost 类型，是时候了解数据转换函数了。在本章中，我们将看到如何将字符串、数字、指针和用户定义的类型相互转换，如何安全地转换多态类型，以及如何在 C++源文件中编写小型和大型解析器。

# 将字符串转换为数字

在 C++中将字符串转换为数字会让很多人感到沮丧，因为它们效率低下且不友好。看看如何将字符串`100`转换为`int`：

```cpp
#include <sstream> 

void sample1() {
    std::istringstream iss("100");
    int i;
    iss >> i;

    // ...
}
```

最好不要去想，之前的转换中发生了多少不必要的操作、虚函数调用、原子操作和内存分配。顺便说一句，我们不再需要`iss`变量，但它会一直存在直到作用域结束。

C 方法也不好：

```cpp
#include <cstdlib> 

void sample2() {
    char * end;
    const int i = std::strtol ("100", &end, 10);

    // ...
}
```

它是否将整个值转换为`int`，还是在中途停止了？要理解这一点，我们必须检查`end`变量的内容。之后，我们将有一个无用的`end`变量一直存在直到作用域结束。而我们想要一个`int`，但`strtol`返回`long int`。转换后的值是否适合`int`？

# 做好准备

此配方只需要基本的 C++和标准库知识。

# 如何做...

Boost 中有一个库，可以帮助您应对令人沮丧的字符串到数字转换困难。它被称为`Boost.LexicalCast`，包括一个`boost::bad_lexical_cast`异常类和一些`boost::lexical_cast`和`boost::conversion::try_lexical_convert`函数：

```cpp
#include <boost/lexical_cast.hpp> 

void sample3() {
    const int i = boost::lexical_cast<int>("100");
    // ...
}
```

它甚至可以用于非零终止的字符串：

```cpp
#include <boost/lexical_cast.hpp>

void sample4() {
    char chars[] = {'x', '1', '0', '0', 'y' }; 
    const int i = boost::lexical_cast<int>(chars + 1, 3); 
    assert(i == 100); 
}
```

# 它是如何工作的...

`boost::lexical_cast`函数接受字符串作为输入，并将其转换为三角括号中指定的类型。`boost::lexical_cast`函数甚至会为您检查边界：

```cpp
#include <boost/lexical_cast.hpp>
#include <iostream>

void sample5() {
    try {
        // short usually may not store values greater than 32767
        const short s = boost::lexical_cast<short>("1000000");
        assert(false); // Must not reach this line.
    } catch (const boost::bad_lexical_cast& e) {
        std::cout << e.what() << '\n';
    }
}
```

前面的代码输出：

```cpp
bad lexical cast: source type value could not be interpreted as target.
```

它还检查输入的正确语法，并在输入错误时抛出异常：

```cpp
#include <boost/lexical_cast.hpp>
#include <iostream>

void sample6() {
    try {
        const int i = boost::lexical_cast<int>("This is not a number!");
        assert(false); // Must not reach this line.
    } catch (const boost::bad_lexical_cast& /*e*/) {}
}
```

自 Boost 1.56 以来，有一个`boost::conversion::try_lexical_convert`函数，通过返回代码报告错误。它可能在性能关键的地方很有用，那里经常会出现错误的输入：

```cpp
#include <boost/lexical_cast.hpp>
#include <cassert>

void sample7() {
    int i = 0;
    const bool ok = boost::conversion::try_lexical_convert("Bad stuff", i);
    assert(!ok);
}
```

# 还有更多...

`lexical_cast`，就像所有`std::stringstream`类一样，使用`std::locale`并且可以转换本地化数字，但也具有对**C 语言环境**和没有数字分组的环境的令人印象深刻的优化集：

```cpp
#include <boost/lexical_cast.hpp>
#include <locale> 

void sample8() {
    try {
        std::locale::global(std::locale("ru_RU.UTF8"));
        // In Russia coma sign is used as a decimal separator.
        float f = boost::lexical_cast<float>("1,0");
        assert(f < 1.01 && f > 0.99);
        std::locale::global(std::locale::classic()); // Restoring C locale
    } catch (const std::runtime_error&) { /* locale is not supported */ }
} 
```

C++标准库没有`lexical_cast`，但自 C++17 以来有`std::from_chars`函数，可以用于创建惊人快速的通用转换器。请注意，这些转换器根本不使用区域设置，因此它们具有略有不同的功能。`std::from_chars`函数旨在不分配内存，不抛出异常，并且没有原子或其他繁重的操作。

# 另请参阅

+   有关`boost::lexical_cast`性能的信息，请参阅*将数字转换为字符串*配方。

+   `Boost.LexicalCast`的官方文档包含一些示例、性能测量和常见问题的答案。它可以在[`boost.org/libs/lexical_cast`](http://boost.org/libs/lexical_cast)上找到。

# 将数字转换为字符串

在这个配方中，我们将继续讨论词法转换，但现在我们将使用`Boost.LexicalCast`将数字转换为字符串。与往常一样，`boost::lexical_cast`将提供一种非常简单的方法来转换数据。

# 做好准备

此配方只需要基本的 C++和标准库知识。

# 如何做...

让我们使用`boost::lexical_cast`将整数`100`转换为`std::string`：

```cpp
#include <cassert>
#include <boost/lexical_cast.hpp> 

void lexical_cast_example() {
    const std::string s = boost::lexical_cast<std::string>(100);
    assert(s == "100");
}
```

与传统的 C++转换方法进行比较：

```cpp
#include <cassert>
#include <sstream> 

void cpp_convert_example() {
    std::stringstream ss;  // Slow/heavy default constructor.
    ss << 100;
    std::string s;
    ss >> s;

    // Variable 'ss' will dangle all the way, till the end
    // of scope. Multiple virtual methods and heavy 
    // operations were called during the conversion.
    assert(s == "100");
}
```

以及与 C 转换方法相比：

```cpp
#include <cassert>
#include <cstdlib> 

void c_convert_example() {
     char buffer[100];
     std::sprintf(buffer, "%i", 100);

     // You will need an unsigned long long int type to 
     // count how many times errors were made in 'printf' 
     // like functions all around the world. 'printf' 
     // functions are a constant security threat! 

     // But wait, we still need to construct a std::string.
     const std::string s = buffer;
     // Now we have a 'buffer' variable that is not used.

     assert(s == "100");
}
```

# 它是如何工作的...

`boost::lexical_cast`函数也可以接受数字作为输入，并将它们转换为模板参数（三角括号中）指定的字符串类型。这与我们在上一个食谱中所做的非常接近。

# 还有更多...

细心的读者会注意到，在`lexical_cast`的情况下，我们有一个额外的调用来复制字符串构造函数，这样的调用会降低性能。这是真的，但只对旧的或不好的编译器有效。现代编译器实现了**命名返回值优化**（**NRVO**），它消除了不必要的复制构造函数和析构函数的调用。即使 C++11 兼容的编译器没有检测到 NRVO，它们也会使用`std::string`的移动构造函数，这是快速和高效的。`Boost.LexicalCast`文档的*性能*部分显示了不同编译器对不同类型的转换速度。在大多数情况下，`lexical_cast`比`std::stringstream`和`printf`函数更快。

如果将`boost::array`或`std::array`作为输出参数类型传递给`boost::lexical_cast`，将会发生较少的动态内存分配（或者根本不会有内存分配，这取决于`std::locale`的实现）。

C++11 有`std::to_string`和`std::to_wstring`函数，它们声明在`<string>`头文件中。这些函数使用区域设置，并且行为非常接近`boost::lexical_cast<std::string>`和`boost::lexical_cast<std::wstring>`。C++17 有`std::to_chars`函数，可以将数字转换为字符数组，速度非常快。`std::to_chars`不分配内存，不抛出异常，并且可以使用错误代码报告错误。如果需要真正快速的转换函数而不使用区域设置，那么使用`std::to_chars`。

# 另请参阅

+   Boost 官方文档包含了比较`lexical_cast`性能与其他转换方法的表格。在大多数情况下，`lexical_cast`比其他方法更快[`boost.org/libs/lexical_cast`](http://boost.org/libs/lexical_cast)。

+   *将字符串转换为数字*食谱。

+   *将用户定义的类型转换为/从字符串*食谱。

# 将数字转换为数字

您可能还记得写以下代码的情况：

```cpp
void some_function(unsigned short param); 
int foo(); 

void do_something() {
    // Some compilers may warn, that int is being converted to  
    // unsigned short and that there is a possibility of loosing  
    // data.
    some_function(foo());
} 
```

通常，程序员会通过将`unsigned short`数据类型隐式转换来忽略这些警告，就像以下代码片段中所示：

```cpp
// Warning suppressed.
some_function( 
    static_cast<unsigned short>(foo()) 
); 
```

但是，如果`foo()`返回的数字不适合`unsigned short`怎么办？这会导致难以检测的错误。这样的错误可能存在多年，直到被捕获和修复。看一下`foo()`的定义：

```cpp
// Returns -1 if error occurred.
int foo() { 
    if (some_extremely_rare_condition()) { 
        return -1; 
    } else if (another_extremely_rare_condition()) { 
        return 1000000; 
    } 
    return 42; 
}
```

# 准备工作

此食谱需要对 C++的基本知识。

# 如何做...

库`Boost.NumericConversion`为这种情况提供了解决方案。只需用`boost::numeric_cast`替换`static_cast`。当源值无法存储在目标中时，后者将抛出异常：

```cpp
#include <boost/numeric/conversion/cast.hpp> 

void correct_implementation() { 
    // 100% correct.
    some_function( 
        boost::numeric_cast<unsigned short>(foo()) 
    ); 
} 

void test_function() {
    for (unsigned int i = 0; i < 100; ++i) {
        try {
            correct_implementation();
        } catch (const boost::numeric::bad_numeric_cast& e) {
            std::cout << '#' << i << ' ' << e.what() << std::endl;
        }
    }
}
```

现在，如果我们运行`test_function()`，它将输出如下：

```cpp
#47 bad numeric conversion: negative overflow 
#58 bad numeric conversion: positive overflow 
```

我们甚至可以检测特定的溢出类型：

```cpp
void test_function1() { 
   for (unsigned int i = 0; i < 100; ++i) { 
       try { 
           correct_implementation(); 
       } catch (const boost::numeric::positive_overflow& e) { 
           // Do something specific for positive overflow. 
           std::cout << "POS OVERFLOW in #" << i << ' '
                     << e.what() << std::endl; 
       } catch (const boost::numeric::negative_overflow& e) { 
           // Do something specific for negative overflow. 
           std::cout <<"NEG OVERFLOW in #" << i << ' '
                     << e.what() << std::endl; 
       } 
   } 
} 
```

`test_function1()`函数将输出如下：

```cpp
NEG OVERFLOW in #47 bad numeric conversion: negative overflow 
POS OVERFLOW in #59 bad numeric conversion: positive overflow 
```

# 工作原理...

`boost::numeric_cast`检查输入参数的值是否适合新类型，而不会丢失数据，并且如果在转换过程中丢失了数据，则会抛出异常。

`Boost.NumericConversion`库有一个非常快的实现。它可以在编译时完成大量工作，例如，当转换为更宽范围的类型时，源将通过`static_cast`转换为目标类型。

# 还有更多...

`boost::numeric_cast`函数是通过`boost::numeric::converter`实现的，可以调整使用不同的溢出、范围检查和舍入策略。但通常，`numeric_cast`就是您需要的。

以下是一个小例子，演示了如何为`boost::numeric::cast`制作我们自己的溢出处理程序：

```cpp
template <class SourceT, class TargetT> 
struct mythrow_overflow_handler {
    void operator() (boost::numeric::range_check_result r) { 
        if (r != boost::numeric::cInRange) { 
            throw std::logic_error("Not in range!"); 
        } 
    } 
}; 

template <class TargetT, class SourceT> 
TargetT my_numeric_cast(const SourceT& in) { 
    typedef boost::numeric::conversion_traits<
        TargetT, SourceT
    > conv_traits; 
    typedef boost::numeric::converter < 
        TargetT, 
        SourceT, 
        conv_traits, // default conversion traits
        mythrow_overflow_handler<SourceT, TargetT> // !!! 
    > converter; 

    return converter::convert(in); 
} 
```

以下是如何使用我们的自定义转换器：

```cpp
void example_with_my_numeric_cast() {
    short v = 0;
    try {
        v = my_numeric_cast<short>(100000);
    } catch (const std::logic_error& e) {
        std::cout << "It works! " << e.what() << std::endl;
    }
}
```

前面的代码输出如下：

```cpp
It works! Not in range!
```

即使 C++17 也没有提供安全的数字转换功能。然而，这方面的工作正在进行中。我们有望在 2020 年后看到这样的功能。

# 参见

Boost 的官方文档包含了对数字转换器模板参数的详细描述；可以在以下链接找到：[`boost.org/libs/numeric/conversion`](http://boost.org/libs/numeric/conversion)

# 将用户定义的类型转换为字符串和从字符串转换为数字

`Boost.LexicalCast`中有一个功能，允许用户使用自己的类型进行`lexical_cast`。这需要用户为该类型编写正确的`std::ostream`和`std::istream`操作符。

# 如何做...

1.  你只需要提供`operator<<`和`operator>>`流操作符。如果你的类已经可以进行流操作，就不需要做任何事情：

```cpp
#include <iostream>
#include <stdexcept>

// Negative number that does not store minus sign.
class negative_number {
    unsigned short number_; 

public:
    explicit negative_number(unsigned short number = 0)
        : number_(number)
    {} 

    // ...
    unsigned short value_without_sign() const {
        return number_;
    }
}; 

inline std::ostream&
    operator<<(std::ostream& os, const negative_number& num)
{
    os << '-' << num.value_without_sign();
    return os;
}

inline std::istream& operator>>(std::istream& is, negative_number& num)
{
    char ch;
    is >> ch;
    if (ch != '-') {
        throw std::logic_error(
            "negative_number class stores ONLY negative values"
        );
    }

    unsigned short s;
    is >> s;
    num = negative_number(s);
    return is;
}
```

1.  现在，我们可以使用`boost::lexical_cast`将`negative_number`类转换为字符串和从字符串转换为`negative_number`类。这里有一个例子：

```cpp
#include <boost/lexical_cast.hpp>
#include <boost/array.hpp>
#include <cassert>

void example1() {
    const negative_number n
        = boost::lexical_cast<negative_number>("-100");
    assert(n.value_without_sign() == 100);

    const int i = boost::lexical_cast<int>(n);
    assert(i == -100);

    typedef boost::array<char, 10> arr_t;
    const arr_t arr = boost::lexical_cast<arr_t>(n);
    assert(arr[0] == '-');
    assert(arr[1] == '1');
    assert(arr[2] == '0');
    assert(arr[3] == '0');
    assert(arr[4] == 0);
} 
```

# 它是如何工作的...

`boost::lexical_cast`函数可以检测并使用流操作符来转换用户定义的类型。

`Boost.LexicalCast`库对基本类型有许多优化，当用户定义的类型被转换为基本类型，或者基本类型被转换为用户定义的类型时，这些优化将被触发。

# 还有更多...

`boost::lexical_cast`函数也可以将转换为宽字符字符串，但需要正确的`basic_istream`和`basic_ostream`操作符重载：

```cpp
template <class CharT> 
std::basic_ostream<CharT>& 
    operator<<(std::basic_ostream<CharT>& os, const negative_number& num)
{ 
    os << static_cast<CharT>('-') << num.value_without_sign(); 
    return os; 
} 

template <class CharT> 
std::basic_istream<CharT>& 
    operator>>(std::basic_istream<CharT>& is, negative_number& num)
{ 
    CharT ch; 
    is >> ch; 
    if (ch != static_cast<CharT>('-')) { 
        throw std::logic_error(
            "negative_number class stores ONLY negative values"
        ); 
    } 
    unsigned short s; 
    is >> s; 
    num = negative_number(s); 
    return is; 
} 

void example2() { 
    const negative_number n = boost::lexical_cast<negative_number>(L"-1"); 
    assert(n.value_without_sign() == 1); 

    typedef boost::array<wchar_t, 10> warr_t; 
    const warr_t arr = boost::lexical_cast<warr_t>(n); 
    assert(arr[0] == L'-'); 
    assert(arr[1] == L'1'); 
    assert(arr[2] == 0); 
} 
```

`Boost.LexicalCast`库不是 C++的一部分。许多 Boost 库都使用它，我希望它也能让你的生活变得更轻松。

# 参见

+   `Boost.LexicalCast`文档包含了一些示例、性能测量和常见问题的解答；链接为[`boost.org/libs/lexical_cast`](http://boost.org/libs/lexical_cast)

+   *将字符串转换为数字*的方法

+   *将数字转换为字符串*的方法

# 转换智能指针

这里有一个问题：

1.  你有一个名为`some_class`的类：

```cpp
struct base {
    virtual void some_methods() = 0;
    virtual ~base();
};

struct derived: public base {
    void some_methods() /*override*/;
    virtual void derived_method() const;

    ~derived() /*override*/;
};
```

1.  你有一个第三方 API，返回通过共享指针构造的`derived`，并在其他函数中接受共享指针到`const derived`：

```cpp
#include <boost/shared_ptr.hpp>
boost::shared_ptr<const base> construct_derived();
void im_accepting_derived(boost::shared_ptr<const derived> p);
```

1.  你必须让以下代码工作：

```cpp
void trying_hard_to_pass_derived() {
    boost::shared_ptr<const base> d = construct_derived();

    // Oops! Compile time error:
    // ‘const struct base; has no member named ‘derived_method;.
    d->derived_method();

    // Oops! Compile time error:
    // could not convert ‘d; to ‘boost::shared_ptr<const derived>;.
    im_accepting_derived(d);
}
```

如何以一种好的方式解决这个问题？

# 入门

这个配方需要对 C++和智能指针有基本的了解。

# 如何做...

解决方案是使用智能指针的特殊转换。在这种特殊情况下，我们需要使用`dynamic_cast`功能，因此我们使用`boost::dynamic_pointer_cast`：

```cpp
void trying_hard_to_pass_derived2() {
    boost::shared_ptr<const derived> d
        = boost::dynamic_pointer_cast<const derived>(
            construct_derived()
        );

    if (!d) {
        throw std::runtime_error(
            "Failed to dynamic cast"
        );
    }

    d->derived_method();
    im_accepting_derived(d);
} 
```

# 它是如何工作的...

Boost 库有很多用于智能指针转换的函数。所有这些函数都接受一个智能指针和一个模板参数`T`，其中`T`是智能指针的所需模板类型。这些转换操作符模仿了内置转换的行为，同时正确管理引用计数和其他智能指针内部：

+   `boost::static_pointer_cast<T>(p)` - 执行`static_cast<T*>(p.get())`

+   `boost::dynamic_pointer_cast<T>(p)` - 执行`dynamic_cast<T*>(p.get())`

+   `boost::const_pointer_cast<T>(p)` - 执行`const_cast<T*>(p.get())`

+   `boost::reinterpret_pointer_cast<T>(p)` - 执行`reinterpret_cast<T*>(p.get())`

# 还有更多...

所有的`boost::*_pointer_cast`函数都可以使用标准库和 C 指针的智能指针，只要包含`<boost/pointer_cast.hpp>`。

在 C++11 中，标准库在`<memory>`头文件中定义了`std::static_pointer_cast`、`std::dynamic_pointer_cast`和`std::const_pointer_cast`，但只适用于`std::shared_ptr`。C++17 标准库有`std::reinterpret_pointer_cast`，但只适用于`std::shared_ptr`。

# 参见

+   `Boost.SmartPointer`库文档包含了有关标准库指针转换的更多示例，链接为[`boost.org/libs/smart_ptr/pointer_cast.html`](http://boost.org/libs/smart_ptr/pointer_cast.html)

+   `boost::shared_ptr`的转换参考可在[`boost.org/libs/smart_ptr/shared_ptr.htm`](http://boost.org/libs/smart_ptr/shared_ptr.htm)上找到

+   本章中的*Casting polymorphic objects*食谱将向您展示进行动态转换的更好方法

# 转换多态对象

想象一下，某个程序员设计了一个如下糟糕的接口（这是接口不应该编写的一个很好的例子）：

```cpp
struct object { 
    virtual ~object() {} 
}; 

struct banana: public object { 
    void eat() const {} 
    virtual ~banana(){} 
}; 

struct penguin: public object { 
    bool try_to_fly() const {
        return false; // penguins do not fly
    }
    virtual ~penguin(){} 
}; 

object* try_produce_banana(); 
```

我们的任务是编写一个吃香蕉的函数，并在有其他东西代替香蕉时抛出异常（`try_produce_banana()`可能返回`nullptr`），因此如果我们在不检查的情况下解引用它返回的值，我们有可能解引用空指针。

# 入门

本食谱需要基本的 C++知识。

# 如何做...

因此，我们需要编写以下代码：

```cpp
void try_eat_banana_impl1() { 
    const object* obj = try_produce_banana(); 
    if (!obj) { 
        throw std::bad_cast(); 
    } 
    dynamic_cast<const banana&>(*obj).eat(); 
} 
```

丑陋，不是吗？`Boost.Conversion`提供了一个稍微更好的解决方案：

```cpp
#include <boost/cast.hpp> 

void try_eat_banana_impl2() { 
    const object* obj = try_produce_banana(); 
    boost::polymorphic_cast<const banana*>(obj)->eat(); 
} 
```

# 它是如何工作的...

`boost::polymorphic_cast`函数只是包装了第一个示例中的代码，就是这样。它检查输入是否为空，然后尝试进行动态转换。在这些操作期间的任何错误都将抛出`std::bad_cast`异常。

# 还有更多...

`Boost.Conversion`库还有一个`polymorphic_downcast`函数，仅应用于肯定会成功的向下转换。在调试模式下（未定义`NDEBUG`时），它将使用`dynamic_cast`检查正确的向下转换。当定义了`NDEBUG`时，`polymorphic_downcast`函数将执行`static_cast`操作。这是一个在性能关键部分使用的好函数，仍然具有在调试编译中检测错误的能力。

自 Boost 1.58 以来，在 Boost.Conversion 库中有一个`boost::polymorphic_pointer_downcast`和`boost::polymorphic_pointer_cast`函数。这些函数允许您安全地转换智能指针，并具有与`boost::polymorphic_cast`和`boost::polymorphic_downcast`相同的特性。

C++标准库缺乏`polymorphic_cast`和`polymorphic_downcast`。

# 另请参阅

+   最初，`polymorphic_cast`的想法是在书籍*The C++ Programming Language*，*Bjarne Stroustrup*中提出的。有关更多信息和一些关于不同主题的好主意，请参考此书。

+   官方文档也可能有所帮助；可在[`boost.org/libs/conversion`](http://boost.org/libs/conversion)上找到。

+   有关转换智能指针的更多信息，请参考前一篇食谱。

# 解析简单输入

解析小文本是一项常见任务。这种情况总是一个两难选择：我们应该使用一些第三方专业和良好的解析工具，如 Bison 或 ANTLR，还是应该尝试仅使用 C++和标准库手动编写？第三方工具适用于处理复杂文本的解析，并且很容易使用它们编写解析器，但它们需要额外的工具来从它们的语法创建 C++或 C 代码，并为您的项目添加更多依赖项。

手写解析器通常难以维护，但除了 C++编译器外，不需要任何东西。

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/boost-cpp-appdev-cb-2e/img/00005.jpeg)

让我们从一个非常简单的任务开始，解析 ISO 格式的日期如下：

```cpp
YYYY-MM-DD 
```

以下是可能输入的示例：

```cpp
2013-03-01 
2012-12-31  // (woo-hoo, it almost a new year!) 
```

我们需要从以下链接获取解析器的语法[`www.ietf.org/rfc/rfc333:`](http://www.ietf.org/rfc/rfc3339.txt:)

```cpp
   date-fullyear   = 4DIGIT 
   date-month      = 2DIGIT  ; 01-12 
   date-mday       = 2DIGIT  ; 01-28, 01-29, 01-30, 01-31 based on 
                             ; month/year 
   full-date       = date-fullyear "-" date-month "-" date-mday 
```

# 准备工作

确保您熟悉占位符的概念，或者阅读第一章中的*重新排列函数的参数*和*将值绑定为函数参数*的示例，*开始编写您的应用程序*。了解解析工具的基本知识会很有帮助。

# 如何做...

让我向你介绍一下`Boost.Spirit`库。它允许直接在 C++代码中编写解析器（以及词法分析器和生成器），这些解析器可以立即执行（不需要额外的工具来生成 C++代码）。`Boost.Spirit`的语法非常接近**扩展巴科斯-瑙尔范式**（**EBNF**），这是许多标准用于表达语法并被其他流行的解析器理解的语法。本章开头的语法就是 EBNF：

1.  我们需要包括以下头文件：

```cpp
#include <boost/spirit/include/qi.hpp>
#include <boost/spirit/include/phoenix_core.hpp>
#include <boost/spirit/include/phoenix_operator.hpp>
#include <cassert>
```

1.  现在，是时候创建一个`date`结构来保存解析的数据了：

```cpp
struct date {
    unsigned short year;
    unsigned short month;
    unsigned short day;
};
```

1.  让我们来看看解析器（如何工作的逐步说明可以在下一节中找到）：

```cpp
// See recipe "Type 'reference to string'" for a better type
// than std::string for parameter 's'
date parse_date_time1(const std::string& s) {
    using boost::spirit::qi::_1;
    using boost::spirit::qi::ushort_;
    using boost::spirit::qi::char_;
    using boost::phoenix::ref;

    date res;
    const char* first = s.data();
    const char* const end = first + s.size();
    const bool success = boost::spirit::qi::parse(first, end,

        // Implementation of 'full-date' rule from EBNF grammar.
        ushort_[ ref(res.year) = _1 ] >> char_('-')
           >> ushort_[ ref(res.month) = _1 ] >> char_('-')
           >> ushort_[ ref(res.day) = _1 ]

    ); 

    if (!success || first != end) {
        throw std::logic_error("Parsing failed");
    }
    return res;
}
```

1.  现在，我们可以在任何地方使用这个解析器：

```cpp
int main() {
    const date d = parse_date_time1("2017-12-31");
    assert(d.year == 2017);
    assert(d.month == 12);
    assert(d.day == 31);
}
```

# 它是如何工作的...

这是一个非常简单的实现；它不检查数字的位数。解析发生在`boost::spirit::qi::parse`函数中。让我们简化一下，去掉成功解析时的动作：

```cpp
const bool success = boost::spirit::qi::parse(first, end, 
     ushort_ >> char_('-') >> ushort_ >> char_('-') >> ushort_ 
); 
```

`first`参数指向要解析的数据的开头。它必须是一个非常量变量，因为`parse`函数将修改它，使其指向解析序列的末尾。

`end`参数指向解析的最后一个元素之后的位置。`first`和`end`必须是迭代器或指针。

函数的第三个参数是解析规则。它看起来就像 EBNF 规则一样：

```cpp
date-fullyear "-" date-month "-" date-md 
```

我们只是用`>>`运算符替换了空格。

`parse`函数在成功时返回`true`。如果我们想确保整个字符串被成功解析，我们需要检查解析器的返回值以及`end`和修改后的`first`迭代器的相等性。

现在，我们需要处理成功解析时的动作，然后这个示例就结束了。`Boost.Spirit`中的语义动作写在`[]`中，可以使用函数指针、函数对象、`boost::bind`、`std::bind`（或其他`bind()`实现）或 C++11 lambda 函数来编写。

因此，你也可以使用 C++11 lambda 为`YYYY`编写规则：

```cpp
const auto y = &res { res.year = s; };
// ...

ushort_[y] >> char_('-') >> // ...
```

你不能直接将 lambda 定义放在`[]`中，因为 C++编译器会认为它是一个属性。作为一种解决方法，你可以在其中创建一个带有 lambda 函数的`auto`变量，并在解析器规则描述中使用该变量（就像在前面的代码片段中所做的那样）。

现在，让我们更仔细地看一下月份的语义动作：

```cpp
ushort_[ ref(res.month) = _1 ] 
```

对于从头开始阅读本书的人来说，前面的代码提醒了`boost::bind`、`boost::ref`和占位符。`ref(res.month)`表示将`res.month`作为可修改的引用传递，`_1`表示第一个输入参数，即一个数字（`ushort_`解析的结果）。

# 还有更多...

现在让我们修改我们的解析器，使其能够处理数字的位数。为此，我们将使用`unit_parser`类模板，并设置正确的参数：

```cpp
date parse_date_time2(const std::string& s) { 
    using boost::spirit::qi::_1; 
    using boost::spirit::qi::uint_parser; 
    using boost::spirit::qi::char_; 
    using boost::phoenix::ref; 

    date res; 

    // Use unsigned short as output type; require Radix 10 and
    // from 2 to 2 digits.
    uint_parser<unsigned short, 10, 2, 2> u2_; 

    // Use unsigned short as output type; require Radix 10 and
    // from 4 to 4 digits.
    uint_parser<unsigned short, 10, 4, 4> u4_; 

    const char* first = s.data(); 
    const char* const end = first + s.size(); 
    const bool success = boost::spirit::qi::parse(first, end, 

        u4_ [ ref(res.year) = _1 ] >> char_('-') 
            >> u2_ [ ref(res.month) = _1 ] >> char_('-')
            >> u2_ [ ref(res.day) = _1 ] 

    ); 
    if (!success || first != end) { 
        throw std::logic_error("Parsing failed"); 
    } 
    return res; 
} 
```

如果这些例子看起来复杂，不要担心。第一次我也被`Boost.Spirit`吓到了，但现在它真的简化了我的生活。如果这段代码不吓到你，那么你真的很勇敢。

不要在头文件中编写解析器，因为这会增加项目的编译时间。在源文件中编写解析器，并将所有`Boost.Spirit`的内部内容隐藏在该文件中。如果我们调整前面的例子来遵循这个规则，那么头文件将如下所示：

```cpp
// Header file.
#ifndef MY_PROJECT_PARSE_DATE_TIME
#define MY_PROJECT_PARSE_DATE_TIME

#include <string>

struct date { 
    unsigned short year; 
    unsigned short month; 
    unsigned short day; 
}; 

date parse_date_time2(const std::string& s);

#endif // MY_PROJECT_PARSE_DATE_TIME
```

还要注意传递给`boost::spirit::parse`函数的迭代器类型。你使用的迭代器类型越少，二进制文件的大小就越小。

如果你现在认为手动使用标准库解析日期更简单，那么你是对的！但仅限于现在。看看下一个示例，它将为你提供更多关于`Boost.Spirit`的用法，并扩展这个例子，以处理手动编写解析器比使用`Boost.Spirit`更困难的情况。

`Boost.Spirit`库不是 C++的一部分，并且在不久的将来也不会被提议包含在其中。但是，它与现代 C++特性非常兼容，因此如果您的编译器支持 C++11，请使用它们：

```cpp
date parse_date_time2_cxx(const std::string& s) {
    using boost::spirit::qi::uint_parser; 
    using boost::spirit::qi::char_; 

    date res; 

    uint_parser<unsigned short, 10, 2, 2> u2_; 
    uint_parser<unsigned short, 10, 4, 4> u4_; 

    const auto y = &res { res.year = s; };
    const auto m = &res { res.month = s; };
    const auto d = &res { res.day = s; };

    const char* first = s.data(); 
    const char* const end = first + s.size();
    const bool success = boost::spirit::qi::parse(first, end, 
        u4_[y] >> char_('-') >> u2_[m] >> char_('-') >> u2_[d] 
    );

    if (!success || first != end) { 
        throw std::logic_error("Parsing failed"); 
    } 
    return res;
}
```

# 另请参阅

+   在第一章的*开始编写您的应用程序*中的*重新排列函数参数*教程。

+   *将值绑定为函数参数*教程。

+   `Boost.Spirit`是一个庞大的仅头文件库。可以单独编写一本书来介绍它。请随时使用其文档[`boost.org/libs/spirit`](http://boost.org/libs/spirit)。

# 解析复杂输入

在上一个教程中，我们编写了一个简单的日期解析器。想象一下，一些时间已经过去，任务已经改变。现在，我们需要编写一个支持多种输入格式和区域偏移的日期时间解析器。我们的解析器必须理解以下输入：

```cpp
2012-10-20T10:00:00Z      // date time with zero zone offset 
2012-10-20T10:00:00       // date time without zone offset 
2012-10-20T10:00:00+09:15 // date time with zone offset 
2012-10-20-09:15          // date time with zone offset 
10:00:09+09:15            // time with zone offset 
```

# 准备工作

我们将使用在*解析简单输入*教程中描述的`Boost.Spirit`库。在开始本教程之前，请先阅读该教程。

# 如何做...

1.  让我们首先编写一个日期时间结构，用于保存解析的结果：

```cpp
#include <stdexcept>
#include <cassert>

struct datetime {
    enum zone_offsets_t {
        OFFSET_NOT_SET,
        OFFSET_Z,
        OFFSET_UTC_PLUS,
        OFFSET_UTC_MINUS
    };

private:
    unsigned short year_;
    unsigned short month_;
    unsigned short day_;

    unsigned short hours_;
    unsigned short minutes_;
    unsigned short seconds_;

    zone_offsets_t zone_offset_type_;
    unsigned int zone_offset_in_min_;

    static void dt_assert(bool v, const char* msg) {
        if (!v) {
            throw std::logic_error(
                "Assertion failed in datetime: " + std::string(msg)
            );
        }
    }

public:
    datetime()
        : year_(0), month_(0), day_(0)
        , hours_(0), minutes_(0), seconds_(0)
        , zone_offset_type_(OFFSET_NOT_SET), zone_offset_in_min_(0)
    {}

    // Getters: year(), month(), day(), hours(), minutes(),
    // seconds(), zone_offset_type(), zone_offset_in_min()
    // ...

    // Setters: set_year(unsigned short), set_day(unsigned short), ...
    //
    // void set_*(unsigned short val) {
    //     Some dt_assert.
    //     Setting the '*_' to 'val'.
    // }
    // ...

}; 
```

1.  现在，让我们编写一个设置区域偏移的函数：

```cpp
void set_zone_offset(datetime& dt, char sign, unsigned short hours
    , unsigned short minutes)
{
    dt.set_zone_offset(
        sign == '+'
        ? datetime::OFFSET_UTC_PLUS
        : datetime::OFFSET_UTC_MINUS
    );
    dt.set_zone_offset_in_min(hours * 60 + minutes);
}
```

1.  编写解析器可以分为编写几个简单的解析器。我们首先编写一个区域偏移解析器：

```cpp
// Default includes for Boost.Spirit.
#include <boost/spirit/include/qi.hpp>
#include <boost/spirit/include/phoenix_core.hpp>
#include <boost/spirit/include/phoenix_operator.hpp>

// We'll use bind() function from Boost.Spirit,
// because it interates better with parsers.
#include <boost/spirit/include/phoenix_bind.hpp>

datetime parse_datetime(const std::string& s) {
    using boost::spirit::qi::_1;
    using boost::spirit::qi::_2;
    using boost::spirit::qi::_3;
    using boost::spirit::qi::uint_parser;
    using boost::spirit::qi::char_;
    using boost::phoenix::bind;
    using boost::phoenix::ref;

    datetime ret;

    // Use unsigned short as output type; require Radix 10 and
    // from 2 to 2 digits.
    uint_parser<unsigned short, 10, 2, 2> u2_;

    // Use unsigned short as output type; require Radix 10 and
    // from 4 to 4 digits.
    uint_parser<unsigned short, 10, 4, 4> u4_;

    boost::spirit::qi::rule<const char*, void()> timezone_parser
        = -( // unary minus means optional rule

            // Zero offset
            char_('Z')[ bind(
                &datetime::set_zone_offset, &ret, datetime::OFFSET_Z
            ) ]

            | // OR

            // Specific zone offset
            ((char_('+')|char_('-')) >> u2_ >> ':' >> u2_) [
                bind(&set_zone_offset, ref(ret), _1, _2, _3)
            ]
        );
```

1.  让我们通过编写剩余的解析器来完成我们的示例：

```cpp
    boost::spirit::qi::rule<const char*, void()> date_parser =
           u4_ [ bind(&datetime::set_year, &ret, _1) ] >> '-'
        >> u2_ [ bind(&datetime::set_month, &ret, _1) ] >> '-'
        >> u2_ [ bind(&datetime::set_day, &ret, _1) ]; 

    boost::spirit::qi::rule<const char*, void()> time_parser =
            u2_ [ bind(&datetime::set_hours, &ret, _1) ] >> ':'
         >> u2_ [ bind(&datetime::set_minutes, &ret, _1) ] >> ':'
         >> u2_ [ bind(&datetime::set_seconds, &ret, _1) ]; 

    const char* first = s.data();
    const char* const end = first + s.size();
    const bool success = boost::spirit::qi::parse(first, end,
        (
            (date_parser >> 'T' >> time_parser)
            | date_parser
            | time_parser
        )
        >> timezone_parser
    );

    if (!success || first != end) {
        throw std::logic_error("Parsing of '" + s + "' failed");
    }
    return ret;
} // end of parse_datetime() function
```

# 它是如何工作的...

这里非常有趣的一个变量是`boost::spirit::qi::rule<const char*, void()>`。它擦除了结果解析器的确切类型，并允许您为递归语法编写解析器。它还允许您在源文件中编写解析器并将其导出到头文件，而不会显著影响项目的编译时间。例如：

```cpp
// Somewhere in header file 
class example_1 { 
    boost::spirit::qi::rule<const char*, void()> some_rule_; 
public: 
    example_1(); 
}; 

// In source file 
example_1::example_1() { 
    some_rule_ = /* ... a lot of parser code ... */; 
} 
```

请注意，这个类意味着编译器的优化障碍，因此在不需要时不要使用它。

有时我们使用`>> ':'`而不是`>> char_(':')`。第一种方法更有限：您无法将操作绑定到它，也无法通过组合字符来创建新规则（例如，您无法只使用`char_`就写出`char_('+')|char_('-')`）。但是为了更好的性能，请使用第一种方法，因为一些编译器可能会对其进行轻微优化。

# 还有更多...

通过删除进行类型擦除的`rule<>`对象，可以使我们的示例稍微更快。只需用 C++11 的`auto`关键字替换它们。

`Boost.Spirit`库生成非常快速的解析器；官方网站上有一些性能指标。官方文档包含了编写更快解析器的高级建议。

使用`boost::phoenix::bind`并不是强制的，但是如果不使用它，`timezone_parser`中解析特定区域偏移的规则将会处理

`boost::fusion::vector<char, unsigned short, unsigned short>`类型。使用`bind(&set_zone_offset, ref(ret), _1, _2, _3)`似乎是一个更易读的解决方案。

在解析大文件时，请考虑阅读第十一章的*读取文件的最快方法*教程，因为与文件的不正确处理相比，解析可能会使您的程序变慢得多。

使用`Boost.Spirit`（或`Boost.Fusion`）库的代码编译可能需要很长时间，因为模板实例化的数量非常庞大。在尝试`Boost.Spirit`库时，请使用现代编译器，它们提供更好的编译时间。

# 另请参阅

`Boost.Spirit`库值得单独编写一本书，无法在几个教程中描述其所有特性，因此参考文档将帮助您获取更多信息。它可以在[`boost.org/libs/spirit`](http://boost.org/libs/spirit)找到。在那里，您将找到更多示例、准备好的解析器，以及如何使用 Boost 直接在 C++11 代码中编写词法分析器和生成器的信息。


# 第四章：编译时技巧

在本章中，我们将涵盖以下内容：

+   在编译时检查大小

+   为整数类型启用函数模板使用

+   禁用真实类型的函数模板使用

+   从数字创建一个类型

+   实现一个类型特征

+   为模板参数选择最佳操作符

+   在 C++03 中获取表达式的类型

# 介绍

在本章中，我们将看到一些基本的例子，说明 Boost 库如何在编译时检查、调整算法和其他元编程任务中使用。

一些读者可能会问，"为什么我们要关心编译时的事情？"那是因为程序的发布版本只编译一次，运行多次。我们在编译时做的越多，运行时剩下的工作就越少，从而产生更快速和可靠的程序。运行时检查只有在执行带有检查的代码部分时才会执行。编译时检查将阻止您的程序编译，理想情况下会有有意义的编译器错误消息。

这一章可能是最重要的之一。如果没有理解 Boost 源码和其他类似 Boost 的库，是不可能的。

# 在编译时检查大小

假设我们正在编写一些序列化函数，将值存储在指定大小的缓冲区中：

```cpp
#include <cstring> 
#include <boost/array.hpp> 

// C++17 has std::byte out of the box!
// Unfortunately this is as C++03 example. 
typedef unsigned char byte_t;

template <class T, std::size_t BufSizeV> 
void serialize_bad(const T& value, boost::array<byte_t, BufSizeV>& buffer) { 
    // TODO: check buffer size.
    std::memcpy(&buffer[0], &value, sizeof(value)); 
}
```

这段代码有以下问题：

+   缓冲区的大小没有被检查，所以可能会溢出

+   这个函数可以用于**非平凡可复制**类型，这可能导致不正确的行为

我们可以通过添加一些断言来部分修复它，例如：

```cpp
template <class T, std::size_t BufSizeV> 
void serialize_bad(const T& value, boost::array<byte_t, BufSizeV>& buffer) {  
    // TODO: think of something better.
    assert(BufSizeV >= sizeof(value));
    std::memcpy(&buffer[0], &value, sizeof(value)); 
}
```

但是，这是一个不好的解决方案。如果函数没有被调用，调试模式下的运行时检查不会触发断言。在发布模式下，运行时检查甚至可能被优化掉，所以可能会发生非常糟糕的事情。

`BufSizeV`和`sizeof(value)`的值在编译时是已知的。这意味着，我们可以强制这段代码在缓冲区太小的情况下失败编译，而不是有一个运行时断言。

# 准备工作

这个方法需要一些关于 C++模板和`Boost.Array`库的知识。

# 如何做...

让我们使用`Boost.StaticAssert`和`Boost.TypeTraits`库来纠正解决方案。下面是方法：

```cpp
#include <boost/static_assert.hpp> 
#include <boost/type_traits/has_trivial_copy.hpp> 

template <class T, std::size_t BufSizeV> 
void serialize(const T& value, boost::array<byte_t, BufSizeV>& buffer) { 
    BOOST_STATIC_ASSERT(BufSizeV >= sizeof(value)); 
    BOOST_STATIC_ASSERT(boost::has_trivial_copy<T>::value); 

    std::memcpy(&buffer[0], &value, sizeof(value)); 
}
```

# 它是如何工作的...

`BOOST_STATIC_ASSERT`宏只能在断言表达式可以在编译时评估并且可以隐式转换为`bool`时使用。这意味着您只能在`BOOST_STATIC_ASSERT`中使用`sizeof()`、静态常量、constexpr 变量、在编译时已知参数的 constexpr 函数和其他常量表达式。如果断言表达式评估为`false`，`BOOST_STATIC_ASSERT`将停止编译。在`serialize`函数的情况下，如果第一个静态断言失败，这意味着用户错误使用了`serialize`函数并提供了一个非常小的缓冲区。

这里有一些更多的例子：

```cpp
BOOST_STATIC_ASSERT(3 >= 1); 

struct some_struct { enum enum_t { value = 1}; }; 
BOOST_STATIC_ASSERT(some_struct::value); 

template <class T1, class T2> 
struct some_templated_struct 
{ 
    enum enum_t { value = (sizeof(T1) == sizeof(T2))}; 
}; 
BOOST_STATIC_ASSERT((some_templated_struct<int, unsigned int>::value));

template <class T1, class T2>
struct some_template { 
    BOOST_STATIC_ASSERT(sizeof(T1) == sizeof(T2));
};
```

如果`BOOST_STATIC_ASSERT`宏的断言表达式中有逗号，我们必须用额外的括号将整个表达式包起来。

最后一个例子非常接近我们在`serialize()`函数的第二行看到的内容。现在是时候更多地了解`Boost.TypeTraits`库了。这个库提供了大量的编译时元函数，允许我们获取有关类型的信息并修改类型。元函数的用法看起来像`boost::function_name<parameters>::value`或`boost::function_name<parameters>::type`。元函数`boost::has_trivial_copy<T>::value`只有在`T`是一个简单可复制的类型时才返回`true`。

让我们再看一些例子：

```cpp
#include <iostream> 
#include <boost/type_traits/is_unsigned.hpp> 
#include <boost/type_traits/is_same.hpp> 
#include <boost/type_traits/remove_const.hpp> 

template <class T1, class T2> 
void type_traits_examples(T1& /*v1*/, T2& /*v2*/)  { 
    // Returns true if T1 is an unsigned number 
    std::cout << boost::is_unsigned<T1>::value; 

    // Returns true if T1 has exactly the same type, as T2 
    std::cout << boost::is_same<T1, T2>::value; 

    // This line removes const modifier from type of T1\. 
    // Here is what will happen with T1 type if T1 is: 
    // const int => int 
    // int => int 
    // int const volatile => int volatile 
    // const int& => const int& 
    typedef typename boost::remove_const<T1>::type t1_nonconst_t; 
}
```

一些编译器甚至可以在没有`typename`关键字的情况下编译这段代码，但这种行为违反了 C++标准，因此强烈建议写上`typename`。

# 还有更多...

`BOOST_STATIC_ASSSERT`宏有一个更冗长的变体，称为`BOOST_STATIC_ASSSERT_MSG`，如果断言失败，它会尝试在编译器日志（或 IDE 窗口）中输出错误消息。看一下下面的代码：

```cpp
template <class T, std::size_t BufSizeV> 
void serialize2(const T& value, boost::array<byte_t, BufSizeV>& buf) { 
    BOOST_STATIC_ASSERT_MSG(boost::has_trivial_copy<T>::value, 
        "This serialize2 function may be used only " 
        "with trivially copyable types." 
    ); 

    BOOST_STATIC_ASSERT_MSG(BufSizeV >= sizeof(value), 
        "Can not fit value to buffer. " 
        "Make the buffer bigger." 
    ); 

    std::memcpy(&buf[0], &value, sizeof(value)); 
} 

int main() { 
    // Somewhere in code: 
    boost::array<unsigned char, 1> buf; 
    serialize2(std::string("Hello word"), buf);
}
```

在 C++11 模式下，使用 g++ 编译器编译上述代码将得到以下结果：

```cpp
boost/static_assert.hpp:31:45: error: static assertion failed: This serialize2 function may be used only with trivially copyable types.
 #     define BOOST_STATIC_ASSERT_MSG( ... ) static_assert(__VA_ARGS__)
 ^
Chapter04/01_static_assert/main.cpp:76:5: note: in expansion of macro ‘BOOST_STATIC_ASSERT_MSG;
 BOOST_STATIC_ASSERT_MSG(boost::has_trivial_copy<T>::value,
 ^~~~~~~~~~~~~~~~~~~~~~~

boost/static_assert.hpp:31:45: error: static assertion failed: Can not fit value to buffer. Make the buffer bigger.
 #     define BOOST_STATIC_ASSERT_MSG( ... ) static_assert(__VA_ARGS__)
 ^
Chapter04/01_static_assert/main.cpp:81:5: note: in expansion of macro ‘BOOST_STATIC_ASSERT_MSG;
 BOOST_STATIC_ASSERT_MSG(BufSizeV >= sizeof(value),
 ^~~~~~~~~~~~~~~~~~~~~~~
```

`BOOST_STATIC_ASSSERT`，`BOOST_STATIC_ASSSERT_MSG` 或任何类型特征实体都不会导致运行时惩罚。所有这些函数都在编译时执行，不会向生成的二进制文件添加任何汇编指令。C++11 标准具有`static_assert(condition, "message")`，它等效于 Boost 的 `BOOST_STATIC_ASSSERT_MSG`。C++17 中提供了在编译时断言而无需用户提供消息的`BOOST_STATIC_ASSERT`功能。您不必包含头文件即可使用编译器内置的`static_assert`。

`Boost.TypeTraits` 库部分被接受到 C++11 标准中。因此，您可以在 `std::` 命名空间的 `<type_traits>` 头文件中找到特征。C++11 `<type_traits>` 具有一些在 `Boost.TypeTraits` 中不存在的函数，但是一些其他元函数只存在于 Boost 中。以`has_`开头的元函数在标准库中被重命名为以`is_`开头的元函数。因此，`has_trivial_copy` 变成了 `is_trivially_copyable` 等等。

C++14 和 Boost 1.65 为所有具有 `::type` 成员的类型特征提供了快捷方式。这些快捷方式允许您编写 `remove_const_t<T1>` 而不是 `typename remove_const<T1>::type`。请注意，在 Boost 1.65 的情况下，这些快捷方式需要一个兼容 C++11 的编译器，因为它们只能使用**类型别名**来实现：

```cpp
template <class T>
using remove_const_t = typename remove_const<T>::type;
```

C++17 为具有 `::value` 的类型特征添加了 `_v` 快捷方式。自 C++17 起，您可以只写 `std::is_unsigned_v<T1>` 而不是 `std::is_unsigned<T1>::value`。这个技巧通常是使用`变量模板`来实现的：

```cpp
template <class T>
inline constexpr bool is_unsigned_v = is_unsigned<T>::value;
```

当 Boost 和标准库中存在类似的特征时，如果您正在编写必须在 C++11 之前的编译器上工作的项目，请选择 Boost 版本。否则，在极少数情况下，标准库版本可能效果稍好。

# 另请参阅

+   本章的下一个示例将为您提供更多示例和想法，说明静态断言和类型特征可以如何使用。

+   阅读`Boost.StaticAssert`的官方文档，了解更多示例：

[`boost.org/libs/static_assert.`](http://boost.org/libs/static_assert)

# 为整数类型启用函数模板使用

这是一个常见的情况，当我们有一个实现某些功能的类模板时：

```cpp
// Generic implementation.
template <class T> 
class data_processor { 
    double process(const T& v1, const T& v2, const T& v3); 
};
```

现在，想象一下，我们有该类的另外两个版本，一个用于整数，另一个用于实数：

```cpp
// Integral types optimized version. 
template <class T>
class data_processor_integral {
    typedef int fast_int_t;
    double process(fast_int_t v1, fast_int_t v2, fast_int_t v3);
}; 

// SSE optimized version for float types.
template <class T>
class data_processor_sse {
    double process(double v1, double v2, double v3);
};
```

现在的问题是：如何使编译器自动为指定类型选择正确的类？

# 准备工作

本示例需要一些 C++ 模板知识。

# 如何做...

我们将使用 `Boost.Core` 和 `Boost.TypeTraits` 来解决这个问题：

1.  让我们从包含头文件开始：

```cpp
#include <boost/core/enable_if.hpp>
#include <boost/type_traits/is_integral.hpp>
#include <boost/type_traits/is_float.hpp>
```

1.  让我们向我们的通用实现添加一个带有默认值的额外模板参数：

```cpp
// Generic implementation.
template <class T, class Enable = void>
class data_processor {
    // ...
};
```

1.  修改优化版本如下，现在它们将被编译器视为模板部分特化：

```cpp
// Integral types optimized version.
template <class T>
class data_processor<
    T,
    typename boost::enable_if_c<boost::is_integral<T>::value >::type
>
{
    // ...
};

// SSE optimized version for float types.
template <class T>
class data_processor<
    T,
    typename boost::enable_if_c<boost::is_float<T>::value >::type
>
{
    // ...
};
```

1.  就是这样！现在，编译器将自动选择正确的类：

```cpp
template <class T>
double example_func(T v1, T v2, T v3) {
    data_processor<T> proc;
    return proc.process(v1, v2, v3);
}

int main () {
    // Integral types optimized version
    // will be called.
    example_func(1, 2, 3);
    short s = 0;
    example_func(s, s, s);

    // Real types version will be called.
    example_func(1.0, 2.0, 3.0);
    example_func(1.0f, 2.0f, 3.0f);

    // Generic version will be called.
    example_func("Hello", "word", "processing");
}
```

# 它是如何工作的...

`boost::enable_if_c` 模板是一个棘手的模板。它利用了**替换失败不是错误**（**SFINAE**）原则，该原则在**模板实例化**期间使用。这就是原则的工作方式；如果在函数或类模板的实例化过程中形成了无效的参数或返回类型，则该实例化将从重载解析集中移除，并且不会导致编译错误。现在棘手的部分是，`boost::enable_if_c<true>` 有一个通过 `::type` 访问的成员类型，但 `boost::enable_if_c<false>` 没有 `::type`。让我们回到我们的解决方案，看看 SFINAE 如何与作为 `T` 参数传递给 `data_processor` 类的不同类型一起使用。

如果我们将 `int` 作为 `T` 类型传递，首先编译器将尝试从 *步骤 3* 实例化模板部分特化，然后再使用我们的非特定通用版本。当它尝试实例化一个 `float` 版本时，`boost::is_float<T>::value` 元函数返回 `false`。`boost::enable_if_c<false>::type` 元函数无法正确实例化，因为 `boost::enable_if_c<false>` 没有 `::type`，这就是 SFINAE 起作用的地方。因为无法实例化类模板，这必须被解释为不是错误，编译器跳过这个模板特化。下一个部分特化是针对整数类型进行优化的。`boost::is_integral<T>::value` 元函数返回 `true`，并且可以实例化 `boost::enable_if_c<true>::type`，这使得整个 `data_processor` 特化可以实例化。编译器找到了匹配的部分特化，因此不需要尝试实例化非特定方法。

现在，让我们尝试传递一些非算术类型（例如 `const char *`），看看编译器会做什么。首先，编译器尝试实例化模板部分特化。具有 `is_float<T>::value` 和 `is_integral<T>::value` 的特化无法实例化，因此编译器尝试实例化我们的通用版本并成功。

如果没有 `boost::enable_if_c<>`，所有部分特化版本可能会同时实例化为任何类型，这会导致模糊和编译失败。

如果您正在使用模板，并且编译器报告无法在两个模板类或方法之间进行选择，那么您可能需要 `boost::enable_if_c<>`。

# 还有更多...

这个方法的另一个版本称为 `boost::enable_if`，末尾没有 `_c`。它们之间的区别在于 `enable_if_c` 接受常量作为模板参数；短版本接受具有 `value` 静态成员的对象。例如，`boost::enable_if_c<boost::is_integral<T>::value >::type` 等于 `boost::enable_if<boost::is_integral<T> >::type`。

在 Boost 1.56 之前，`boost::enable_if` 元函数定义在头文件 `<boost/utility/enable_if.hpp>` 中，而不是 `<boost/core/enable_if.hpp>`。

C++11 在 `<type_traits>` 头文件中定义了 `std::enable_if`，它的行为与 `boost::enable_if_c` 完全相同。它们之间没有区别，只是 Boost 的版本也适用于非 C++11 编译器，提供更好的可移植性。

C++14 中有一个快捷方式 `std::enable_if_t`，它必须在没有 `typename` 和 `::type` 的情况下使用：

```cpp
template <class T> 
class data_processor<
    T, std::enable_if_t<boost::is_float<T>::value >
>;
```

所有启用函数仅在编译时执行，不会在运行时增加性能开销。但是，添加额外的模板参数可能会在 `typeid(your_class).name()` 中产生更大的类名，并在某些平台上比较两个 `typeid()` 结果时增加极小的性能开销。

# 另请参阅

+   下一篇文章将为您提供更多关于 `enable_if` 使用的示例。

+   您还可以查阅 `Boost.Core` 的官方文档。其中包含许多示例和许多有用的类（在本书中广泛使用）。请访问链接 [`boost.org/libs/core`](http://boost.org/libs/core) 了解更多信息。

+   您还可以阅读一些关于模板部分特化的文章 [`msdn.microsoft.com/en-us/library/3967w96f%28v=vs.110%29.aspx`](http://msdn.microsoft.com/en-us/library/3967w96f%28v=vs.110%29.aspx)。

# 禁用真实类型的函数模板使用

我们继续使用 Boost 元编程库。在上一个示例中，我们看到了如何在类中使用 `enable_if_c`；现在是时候看看它在模板函数中的用法了。

想象一下，在您的项目中，您有一个可以处理所有可用类型的模板函数：

```cpp
template <class T> 
T process_data(const T& v1, const T& v2, const T& v3);
```

该函数存在已经很长时间了。你已经写了很多使用它的代码。突然间，你想到了`process_data`函数的一个优化版本，但只适用于具有`T::operator+=(const T&)`的类型：

```cpp
template <class T> 
T process_data_plus_assign(const T& v1, const T& v2, const T& v3);
```

你有一个庞大的代码库，可能需要几个月的时间才能手动将`process_data`更改为具有正确运算符的`process_data_plus_assign`。因此，你不想改变已经编写的代码。相反，你希望强制编译器在可能的情况下自动使用优化函数来替代默认函数。

# 准备工作

阅读前面的配方，了解`boost::enable_if_c`的作用，并理解 SFINAE 的概念。仍然需要基本的模板知识。

# 如何做...

可以使用 Boost 库进行模板魔术。让我们看看如何做：

1.  我们将需要`boost::has_plus_assign<T>`元函数和`<boost/enable_if.hpp>`头文件：

```cpp
#include <boost/core/enable_if.hpp>
#include <boost/type_traits/has_plus_assign.hpp>
```

1.  现在，我们禁用具有`plus assign`运算符的类型的默认实现：

```cpp
// Modified generic version of process_data
template <class T>
typename boost::disable_if_c<boost::has_plus_assign<T>::value,T>::type
    process_data(const T& v1, const T& v2, const T& v3);
```

1.  为具有`plus assign`运算符的类型启用优化版本：

```cpp
// This process_data will call a process_data_plus_assign.
template <class T>
typename boost::enable_if_c<boost::has_plus_assign<T>::value, T>::type
    process_data(const T& v1, const T& v2, const T& v3)
{
    return process_data_plus_assign(v1, v2, v3);
}
```

1.  现在，优化版本在可能的情况下被使用：

```cpp
int main() {
    int i = 1;
    // Optimized version.
    process_data(i, i, i);

    // Default version.
    // Explicitly specifing template parameter.
    process_data<const char*>("Testing", "example", "function");
}
```

# 它是如何工作的...

`boost::disable_if_c<bool_value>::type`元函数在`bool_value`等于`true`时禁用该方法。它的工作方式与`boost::enable_if_c<!bool_value>::type`相同。

作为`boost::enable_if_c`或`boost::disable_if_c`的第二个参数传递的类在成功替换的情况下通过`::type`返回。换句话说，`boost::enable_if_c<true, T>::type`与`T`相同。

让我们逐步进行`process_data(i, i, i)`的案例。我们将`int`作为`T`类型传递，编译器搜索函数`process_data(int, int, int)`。因为没有这样的函数，下一步是实例化`process_data`的模板版本。然而，有两个模板`process_data`函数。例如，编译器开始实例化我们的第二个（优化）版本的模板；在这种情况下，它成功地评估了`typename boost::enable_if_c<boost::has_plus_assign<T>::value, T>::type`表达式，并得到了`T`返回类型。但是，编译器并没有停止；它继续实例化尝试，并尝试实例化我们函数的第一个版本。在替换`typename boost::disable_if_c<boost::has_plus_assign<T>::value`时发生了失败，由于 SFINAE 规则，这不被视为错误。没有更多的模板`process_data`函数，所以编译器停止实例化。如你所见，如果没有`enable_if_c`和`disable_if_c`，编译器将能够实例化两个模板，并且会产生歧义。

# 还有更多...

与`enable_if_c`和`enable_if`一样，还有一个禁用函数的`disable_if`版本：

```cpp
// First version 
template <class T> 
typename boost::disable_if<boost::has_plus_assign<T>, T>::type 
    process_data2(const T& v1, const T& v2, const T& v3); 

// process_data_plus_assign 
template <class T> 
typename boost::enable_if<boost::has_plus_assign<T>, T>::type 
    process_data2(const T& v1, const T& v2, const T& v3);
```

C++11 中没有`disable_if_c`或`disable_if`，但你可以自由使用`std::enable_if<!bool_value>::type`。

在 Boost 1.56 之前，`boost::disable_if`元函数被定义在`<boost/utility/enable_if.hpp>`头文件中，而不是`<boost/core/enable_if.hpp>`。

在前面的配方中提到，所有的启用和禁用函数都只在编译时执行，并且不会在运行时增加性能开销。

# 另请参阅

+   从头开始阅读本章，以获取更多编译时技巧的示例。

+   考虑阅读`Boost.TypeTraits`官方文档，了解更多示例和元函数的完整列表，网址为[`boost.org/libs/type_traits`](http://boost.org/libs/type_traits)。

+   `Boost.Core`库可能会为你提供更多关于`boost::enable_if`的用法示例；在[`boost.org/libs/core`](http://boost.org/libs/core)上了解更多信息。

# 从数字创建类型

我们已经看到了如何使用`boost::enable_if_c`来在函数之间进行选择的示例。让我们在本章中忘记这种技术，使用一种不同的方法。考虑以下示例，我们有一个用于处理 POD 数据类型的通用方法：

```cpp
#include <boost/static_assert.hpp> 
#include <boost/type_traits/is_pod.hpp> 

// Generic implementation. 
template <class T> 
T process(const T& val) { 
    BOOST_STATIC_ASSERT((boost::is_pod<T>::value)); 
    // ... 
}
```

我们还有一些针对 1、4 和 8 字节大小进行优化的处理函数。我们如何重写`process`函数，以便它可以分派调用到优化处理函数？

# 准备工作

强烈建议阅读本章至少第一个配方，这样您就不会被这里发生的一切搞糊涂。模板和元编程不会吓到您（或者只是准备好看到很多这样的东西）。

# 如何做...

我们将看到模板类型的大小如何转换为某种类型的变量，以及该变量如何用于推断正确的函数重载。

1.  让我们定义我们的`process_impl`函数的通用版本和优化版本：

```cpp
#include <boost/mpl/int.hpp> 

namespace detail {
    // Generic implementation.
    template <class T, class Tag>
    T process_impl(const T& val, Tag /*ignore*/) {
        // ...
    }

    // 1 byte optimized implementation.
    template <class T>
    T process_impl(const T& val, boost::mpl::int_<1> /*ignore*/) {
        // ...
    }

    // 4 bytes optimized implementation.
    template <class T>
    T process_impl(const T& val, boost::mpl::int_<4> /*ignore*/) {
        // ...
    }

    // 8 bytes optimized implementation.
    template <class T>
    T process_impl(const T& val, boost::mpl::int_<8> /*ignore*/) {
        // ...
    }
} // namespace detail
```

1.  现在，我们准备编写一个处理函数：

```cpp
// Dispatching calls:
template <class T>
T process(const T& val) {
    BOOST_STATIC_ASSERT((boost::is_pod<T>::value));
    return detail::process_impl(val, boost::mpl::int_<sizeof(T)>());
}
```

# 工作原理...

这里最有趣的部分是`boost::mpl::int_<sizeof(T)>()`。`sizeof(T)`在编译时执行，因此其输出可以用作模板参数。类`boost::mpl::int_<>`只是一个空类，它保存了一个整数类型的编译时值。在`Boost.MPL`库中，这样的类被称为**整数常量**。可以按照以下代码实现：

```cpp
template <int Value> 
struct int_ { 
    static const int value = Value; 
    typedef int_<Value> type; 
    typedef int value_type; 
};
```

我们需要这个类的一个实例，这就是为什么在`boost::mpl::int_<sizeof(T)>()`末尾有一个圆括号的原因。

现在，让我们更仔细地看看编译器将如何决定使用哪个`process_impl`函数。首先，编译器尝试匹配具有非模板第二参数的函数。如果`sizeof(T)`为 4，编译器尝试搜索具有类似`process_impl(T, boost::mpl::int_<4>)`签名的函数，并从`detail`命名空间中找到我们的 4 字节优化版本。如果`sizeof(T)`为 34，编译器找不到具有类似`process_impl(T, boost::mpl::int_<34>)`签名的函数，并使用模板函数`process_impl(const T& val, Tag /*ignore*/)`。

# 还有更多...

`Boost.MPL`库有几种用于元编程的数据结构。在这个配方中，我们只是触及了冰山一角。您可能会发现 MPL 中的以下整数常量类有用：

+   `bool_`

+   `int_`

+   `long_`

+   `size_t`

+   `char_`

所有`Boost.MPL`函数（除了`for_each`运行时函数）都在编译时执行，不会增加运行时开销。

`Boost.MPL`库不是 C++的一部分。然而，C++从该库中重用了许多技巧。C++11 在头文件`type_traits`中有一个`std::integral_constant<type, value>`类，可以像前面的示例中那样使用。您甚至可以使用它定义自己的**类型别名**：

```cpp
template <int Value>
using int_ = std::integral_constant<int, Value>;
```

# 另请参阅

+   第八章的配方，“元编程”，将为您提供更多`Boost.MPL`库用法的示例。如果您感到自信，您也可以尝试阅读[`boost.org/libs/mpl`](http://boost.org/libs/mpl)链接的库文档。

+   在[`boost.org/libs/type_traits/doc/html/boost_typetraits/examples/fill.html`](http://boost.org/libs/type_traits/doc/html/boost_typetraits/examples/fill.html)和[`boost.org/libs/type_traits/doc/html/boost_typetraits/examples/copy.html`](http://boost.org/libs/type_traits/doc/html/boost_typetraits/examples/copy.html)上阅读标签用法的更多示例。

# 实现类型特性

我们需要实现一个类型特性，如果将`std::vector`类型作为模板参数传递给它，则返回`true`，否则返回`false`。

# 准备工作

需要一些关于`Boost.TypeTrait`或标准库类型特性的基本知识。

# 如何做...

让我们看看如何实现类型特性：

```cpp
#include <vector> 
#include <boost/type_traits/integral_constant.hpp> 

template <class T> 
struct is_stdvector: boost::false_type {}; 

template <class T, class Allocator> 
struct is_stdvector<std::vector<T, Allocator> >: boost::true_type  {};
```

# 工作原理...

几乎所有的工作都是由`boost::true_type`和`boost::false_type`类完成的。`boost::true_type`类中有一个布尔`::value`静态常量，其值为`true`。`boost::false_type`类中有一个布尔`::value`静态常量，其值为`false`。这两个类还有一些`typedef`，以便与`Boost.MPL`库很好地配合。

我们的第一个`is_stdvector`结构是一个通用结构，当找不到模板专门化版本时将始终使用它。我们的第二个`is_stdvector`结构是`std::vector`类型的模板专门化（注意它是从`true_type`派生的）。因此，当我们将`std::vector`类型传递给`is_stdvector`结构时，编译器会选择模板专门化版本。如果我们传递的数据类型不是`std::vector`，那么就会使用从`false_type`派生的通用版本。

在我们的特性中，在`boost::false_type`和`boost::true_type`之前没有 public 关键字，因为我们使用了`struct`关键字，并且默认情况下它使用公共继承。

# 还有更多...

那些使用 C++11 兼容编译器的读者可以使用`<type_traits>`头文件中声明的`true_type`和`false_type`类型来创建自己的类型特征。自 C++17 以来，标准库有一个`bool_constant<true_or_false>`类型别名，您可以方便地使用它。

通常情况下，Boost 版本的类和函数更具可移植性，因为它们可以在 C++11 之前的编译器上使用。

# 另请参阅

+   本章中几乎所有的示例都使用了类型特征。请参考`Boost.TypeTraits`文档，了解更多示例和信息，网址为[`boost.org/libs/type_traits`](http://boost.org/libs/type_traits)

+   查看前面的示例以获取有关整数常量以及如何从头开始实现`true_type`和`false_type`的更多信息。

# 为模板参数选择最佳操作符

假设我们正在使用来自不同供应商的类，这些类实现了不同数量的算术操作，并且具有从整数构造函数。我们确实希望制作一个函数，它可以递增任何一个传递给它的类。而且，我们希望这个函数是有效的！请看下面的代码：

```cpp
template <class T> 
void inc(T& value) { 
    // TODO:
    // call ++value 
    // or call value ++ 
    // or value += T(1); 
    // or value = value + T(1); 
}
```

# 准备工作

需要一些关于 C++模板和`Boost.TypeTrait`或标准库类型特征的基本知识。

# 如何做...

所有的选择都可以在编译时完成。这可以通过使用`Boost.TypeTraits`库来实现，如下所示：

1.  让我们首先创建正确的函数对象：

```cpp
namespace detail {
    struct pre_inc_functor {
    template <class T>
        void operator()(T& value) const {
           ++ value;
        }
    };

    struct post_inc_functor {
    template <class T>
        void operator()(T& value) const {
            value++;
        }
    };

    struct plus_assignable_functor {
    template <class T>
        void operator()(T& value) const {
            value += T(1);
        }
    };

    struct plus_functor {
    template <class T>
        void operator()(T& value) const {
            value = value + T(1);
        }
    };
}
```

1.  之后，我们将需要一堆类型特征：

```cpp
#include <boost/type_traits/conditional.hpp>
#include <boost/type_traits/has_plus_assign.hpp>
#include <boost/type_traits/has_plus.hpp>
#include <boost/type_traits/has_post_increment.hpp>
#include <boost/type_traits/has_pre_increment.hpp>
```

1.  我们已经准备好推断出正确的函数对象并使用它：

```cpp
template <class T>
void inc(T& value) {
    // call ++value
    // or call value ++
    // or value += T(1);
    // or value = value + T(1);

    typedef detail::plus_functor step_0_t;

    typedef typename boost::conditional<
      boost::has_plus_assign<T>::value,
      detail::plus_assignable_functor,
      step_0_t
    >::type step_1_t; 

    typedef typename boost::conditional<
      boost::has_post_increment<T>::value,
      detail::post_inc_functor,
      step_1_t
    >::type step_2_t;

    typedef typename boost::conditional<
      boost::has_pre_increment<T>::value,
      detail::pre_inc_functor,
      step_2_t
    >::type step_3_t;

    step_3_t() // Default construction of the functor.
        (value); // Calling operator() of the functor.
}
```

# 工作原理...

所有的魔法都是通过`conditional<bool Condition, class T1, class T2>`元函数完成的。当`true`作为第一个参数传递给元函数时，它通过`::type` `typedef`返回`T1`。当`false`作为第一个参数传递给元函数时，它通过`::type` `typedef`返回`T2`。它的作用类似于一种编译时的`if`语句。

因此，`step0_t`保存了`detail::plus_functor`元函数，`step1_t`保存了`step0_t`或`detail::plus_assignable_functor`。`step2_t`类型保存了`step1_t`或`detail::post_inc_functor`。`step3_t`类型保存了`step2_t`或`detail::pre_inc_functor`。每个`step*_t` `typedef`保存的内容是通过类型特征推断出来的。

# 还有更多...

在`std::`命名空间的`<type_traits>`头文件中有这个函数的 C++11 版本。Boost 在不同的库中有多个版本的这个函数；例如，`Boost.MPL`有函数`boost::mpl::if_c`，它的行为与`boost::conditional`完全相同。它还有一个版本`boost::mpl::if_`（末尾没有`c`），它对其第一个模板参数调用`::type`；如果它是从`boost::true_type`派生的，则在`::type`调用期间返回其第二个参数。否则，它返回最后一个模板参数。我们可以重写我们的`inc()`函数以使用`Boost.MPL`，如下面的代码所示：

```cpp
#include <boost/mpl/if.hpp> 

template <class T> 
void inc_mpl(T& value) { 
    typedef detail::plus_functor step_0_t;

    typedef typename boost::mpl::if_<
      boost::has_plus_assign<T>,
      detail::plus_assignable_functor,
      step_0_t
    >::type step_1_t;

    typedef typename boost::mpl::if_<
      boost::has_post_increment<T>,
      detail::post_inc_functor,
      step_1_t
    >::type step_2_t;

    typedef typename boost::mpl::if_<
      boost::has_pre_increment<T>,
      detail::pre_inc_functor,
      step_2_t
    >::type step_3_t;

    step_3_t()   // Default construction of the functor.
        (value); // Calling operator() of the functor.
}
```

C++17 有一个`if constexpr`结构，使前面的示例变得更简单：

```cpp
template <class T> 
void inc_cpp17(T& value) { 
    if constexpr (boost::has_pre_increment<T>()) {
        ++value;
    } else if constexpr (boost::has_post_increment<T>()) {
        value++;
    } else if constexpr(boost::has_plus_assign<T>()) {
        value += T(1);
    } else {
        value = value + T(1);
    }
}
```

标准库中的整数常量，`Boost.MPL`和`Boost.TypeTraits`具有 constexpr 转换运算符。例如，这意味着`std::true_type`的实例可以转换为`true`值。在前面的例子中，`boost::has_pre_increment<T>`表示一种类型，附加`()`，或者 C++11 的大括号`{}`创建该类型的实例，可以转换为`true`或`false`值。

# 另请参阅

+   *启用整数类型的模板函数使用。*

+   *禁用实数类型的模板函数使用。*

+   `Boost.TypeTraits`文档中列出了所有可用的元函数。点击链接[`boost.org/libs/type_traits`](http://boost.org/libs/type_traits)阅读更多信息。

+   来自第八章的示例，*元编程*，将为您提供更多`Boost.MPL`库的使用示例。如果您感到自信，您也可以尝试阅读其文档，链接为[`boost.org/libs/mpl`](http://boost.org/libs/mpl)。

# 在 C++03 中获取表达式的类型

在之前的示例中，我们看到了一些`boost::bind`的使用示例。它可能是 C++11 之前的一个有用工具，但是在 C++03 中很难将`boost::bind`的结果存储为变量。

```cpp
#include <functional> 
#include <boost/bind.hpp> 

const ??? var = boost::bind(std::plus<int>(), _1, _1);
```

在 C++11 中，我们可以使用`auto`关键字代替`???`，这样就可以工作了。在 C++03 中有没有办法做到这一点呢？

# 准备工作

了解 C++11 的`auto`和`decltype`关键字可能有助于您理解这个示例。

# 如何做...

我们将需要`Boost.Typeof`库来获取表达式的返回类型：

```cpp
#include <boost/typeof/typeof.hpp>

BOOST_AUTO(var, boost::bind(std::plus<int>(), _1, _1));
```

# 它是如何工作的...

它只是创建一个名为`var`的变量，表达式的值作为第二个参数传递。`var`的类型是从表达式的类型中检测出来的。

# 还有更多...

有经验的 C++读者会注意到，在 C++11 中有更多用于检测表达式类型的关键字。也许`Boost.Typeof`也有一个宏。让我们看一下以下的 C++11 代码：

```cpp
typedef decltype(0.5 + 0.5f) type;
```

使用`Boost.Typeof`，前面的代码可以这样写：

```cpp
typedef BOOST_TYPEOF(0.5 + 0.5f) type;
```

C++11 版本的`decltype(expr)`推断并返回`expr`的类型。

```cpp
template<class T1, class T2> 
auto add(const T1& t1, const T2& t2) ->decltype(t1 + t2) { 
    return t1 + t2; 
};
```

使用`Boost.Typeof`，前面的代码可以这样写：

```cpp
// Long and portable way:
template<class T1, class T2>
struct result_of {
    typedef BOOST_TYPEOF_TPL(T1() + T2()) type;
};

template<class T1, class T2>
typename result_of<T1, T2>::type add(const T1& t1, const T2& t2) {
    return t1 + t2;
};

// ... or ...

// Shorter version that may crush some compilers.
template<class T1, class T2>
BOOST_TYPEOF_TPL(T1() + T2()) add(const T1& t1, const T2& t2) {
    return t1 + t2;
};
```

C++11 在函数声明的末尾有一种特殊的语法来指定返回类型。不幸的是，这在 C++03 中无法模拟，所以我们不能在宏中使用`t1`和`t2`变量。

您可以在模板和任何其他编译时表达式中自由使用`BOOST_TYPEOF()`函数的结果：

```cpp
#include <boost/static_assert.hpp> 
#include <boost/type_traits/is_same.hpp> 
BOOST_STATIC_ASSERT((
    boost::is_same<BOOST_TYPEOF(add(1, 1)), int>::value
));
```

不幸的是，这种魔法并不总是能够自行完成。例如，用户定义的类并不总是被检测到，因此以下代码可能在某些编译器上失败：

```cpp
namespace readers_project { 
    template <class T1, class T2, class T3> 
    struct readers_template_class{}; 
} 

#include <boost/tuple/tuple.hpp> 

typedef 
    readers_project::readers_template_class<int, int, float> 
readers_template_class_1; 

typedef BOOST_TYPEOF(boost::get<0>( 
    boost::make_tuple(readers_template_class_1(), 1) 
)) readers_template_class_deduced; 

BOOST_STATIC_ASSERT(( 
    boost::is_same< 
        readers_template_class_1, 
        readers_template_class_deduced 
    >::value 
));
```

在这种情况下，您可以给`Boost.Typeof`一点帮助并注册一个模板：

```cpp
BOOST_TYPEOF_REGISTER_TEMPLATE( 
        readers_project::readers_template_class /*class name*/, 
        3 /*number of template classes*/ 
)
```

然而，三个最流行的编译器在没有`BOOST_TYPEOF_REGISTER_TEMPLATE`的情况下，甚至没有 C++11 的情况下也能正确检测到类型。

# 另请参阅

`Boost.Typeof`的官方文档有更多示例。点击链接[`boost.org/libs/typeof`](http://boost.org/libs/typeof)阅读更多信息。
