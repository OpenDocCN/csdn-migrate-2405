# C++ 现代编程（六）

> 原文：[`annas-archive.org/md5/F02528C543403FA60BC7527E0C58459D`](https://annas-archive.org/md5/F02528C543403FA60BC7527E0C58459D)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十章：探索函数

本章包含的示例如下：

+   默认和删除的函数

+   使用 lambda 与标准算法

+   使用通用 lambda

+   编写递归 lambda

+   编写具有可变数量参数的函数模板

+   使用折叠表达式简化可变参数函数模板

+   实现高阶函数 map 和 fold

+   将函数组合成高阶函数

+   统一调用任何可调用的东西

# 默认和删除的函数

在 C++中，类有特殊成员（构造函数、析构函数和运算符），可以由编译器默认实现，也可以由开发人员提供。然而，可以默认实现的规则有点复杂，可能会导致问题。另一方面，开发人员有时希望阻止对象以特定方式被复制、移动或构造。通过使用这些特殊成员实现不同的技巧是可能的。C++11 标准通过允许函数被删除或默认实现简化了许多这样的问题，我们将在下一节中看到。

# 入门

对于这个示例，你需要知道什么是特殊成员函数，以及可复制和可移动的含义。

# 如何做...

使用以下语法指定如何处理函数：

+   要默认一个函数，使用`=default`而不是函数体。只有具有默认值的特殊类成员函数可以被默认：

```cpp
        struct foo 
        { 
          foo() = default; 
        };
```

+   要删除一个函数，使用`=delete`而不是函数体。任何函数，包括非成员函数，都可以被删除：

```cpp
        struct foo 
        { 
          foo(foo const &) = delete; 
        }; 

        void func(int) = delete;
```

使用默认和删除的函数来实现各种设计目标，例如以下示例：

+   要实现一个不可复制且隐式不可移动的类，将复制操作声明为已删除：

```cpp
        class foo_not_copyable 
        { 
        public: 
          foo_not_copyable() = default; 

          foo_not_copyable(foo_not_copyable const &) = delete; 
          foo_not_copyable& operator=(foo_not_copyable const&) = delete; 
        };
```

+   要实现一个不可复制但可移动的类，将复制操作声明为已删除，并显式实现移动操作（并提供任何需要的其他构造函数）：

```cpp
        class data_wrapper 
        { 
          Data* data; 
        public: 
          data_wrapper(Data* d = nullptr) : data(d) {} 
          ~data_wrapper() { delete data; } 

          data_wrapper(data_wrapper const&) = delete; 
          data_wrapper& operator=(data_wrapper const &) = delete; 

          data_wrapper(data_wrapper&& o) :data(std::move(o.data))  
          {  
            o.data = nullptr;  
          } 

          data_wrapper& operator=(data_wrapper&& o) 
          { 
            if (this != &o) 
            { 
              delete data; 
              data = std::move(o.data); 
              o.data = nullptr; 
            } 

            return *this; 
          } 
        };
```

+   为了确保一个函数只能被特定类型的对象调用，并可能防止类型提升，为函数提供已删除的重载（以下示例中的自由函数也可以应用于任何类成员函数）：

```cpp
        template <typename T> 
        void run(T val) = delete; 

        void run(long val) {} // can only be called with long integers
```

# 工作原理...

一个类有几个特殊成员，可以由编译器默认实现。这些是默认构造函数、复制构造函数、移动构造函数、复制赋值、移动赋值和析构函数。如果你不实现它们，那么编译器会这样做，以便可以创建、移动、复制和销毁类的实例。然而，如果你显式提供了其中一个或多个特殊方法，那么编译器将根据以下规则不生成其他方法：

+   如果存在用户定义的构造函数，则默认构造函数不会被默认生成。

+   如果存在用户定义的虚拟析构函数，则默认构造函数不会被默认生成。

+   如果存在用户定义的移动构造函数或移动赋值运算符，则默认不会生成复制构造函数和复制赋值运算符。

+   如果存在用户定义的复制构造函数、移动构造函数、复制赋值运算符、移动赋值运算符或析构函数，则默认不会生成移动构造函数和移动赋值运算符。

+   如果存在用户定义的复制构造函数或析构函数，则默认生成复制赋值运算符。

+   如果存在用户定义的复制赋值运算符或析构函数，则默认生成复制构造函数。

请注意，前面列表中的最后两条规则是被弃用的规则，可能不再被你的编译器支持。

有时，开发人员需要提供这些特殊成员的空实现或隐藏它们，以防止以特定方式构造类的实例。一个典型的例子是一个不应该被复制的类。这种情况的经典模式是提供一个默认构造函数并隐藏复制构造函数和复制赋值运算符。虽然这样可以工作，但显式定义的默认构造函数确保了该类不再被视为平凡的，因此不再是 POD 类型。这种情况的现代替代方法是使用前面部分所示的删除函数。

当编译器在函数定义中遇到`=default`时，它将提供默认实现。之前提到的特殊成员函数的规则仍然适用。如果函数是内联的，函数可以在类的主体之外声明为`=default`：

```cpp
    class foo 
    { 
    public: 
      foo() = default; 

      inline foo& operator=(foo const &); 
    }; 

    inline foo& foo::operator=(foo const &) = default;
```

当编译器在函数定义中遇到`=delete`时，它将阻止调用该函数。但是，在重载解析期间仍然会考虑该函数，只有在删除的函数是最佳匹配时，编译器才会生成错误。例如，通过为`run()`函数给出先前定义的重载，只有长整数的调用是可能的。对于任何其他类型的参数，包括`int`，其中存在自动类型提升为`long`的情况，将确定删除的重载被认为是最佳匹配，因此编译器将生成错误：

```cpp
    run(42);  // error, matches a deleted overload 
    run(42L); // OK, long integer arguments are allowed
```

请注意，之前声明的函数不能被删除，因为`=delete`定义必须是翻译单元中的第一个声明：

```cpp
    void forward_declared_function(); 
    // ... 
    void forward_declared_function() = delete; // error
```

经验法则（也称为*五大法则*）适用于类特殊成员函数，即，如果您明确定义了任何复制构造函数、移动构造函数、复制赋值运算符、移动赋值运算符或析构函数，则您必须明确定义或默认所有这些函数。

# 使用标准算法与 lambda

C++最重要的现代特性之一是 lambda 表达式，也称为 lambda 函数或简单的 lambda。Lambda 表达式使我们能够定义可以捕获作用域中的变量并被调用或作为参数传递给函数的匿名函数对象。Lambda 在许多方面都很有用，在这个配方中，我们将看到如何将它们与标准算法一起使用。

# 准备就绪

在这个配方中，我们讨论了接受作为其迭代的元素的函数或谓词参数的标准算法。您需要了解什么是一元和二元函数，以及什么是谓词和比较函数。您还需要熟悉函数对象，因为 lambda 表达式是函数对象的语法糖。

# 如何做...

您应该更倾向于使用 lambda 表达式将回调传递给标准算法，而不是函数或函数对象：

+   如果您只需要在一个地方使用 lambda，则在调用的地方定义匿名 lambda 表达式：

```cpp
        auto numbers =  
          std::vector<int>{ 0, 2, -3, 5, -1, 6, 8, -4, 9 }; 
        auto positives = std::count_if( 
          std::begin(numbers), std::end(numbers),  
          [](int const n) {return n > 0; });
```

+   如果您需要在多个地方调用 lambda，则定义一个命名 lambda，即分配给变量的 lambda（通常使用`auto`指定符为类型）：

```cpp
        auto ispositive = [](int const n) {return n > 0; }; 
        auto positives = std::count_if( 
          std::begin(numbers), std::end(numbers), ispositive);
```

+   如果您需要在参数类型上有所不同的 lambda，则使用通用 lambda 表达式（自 C++14 起可用）：

```cpp
        auto positives = std::count_if( 
          std::begin(numbers), std::end(numbers),  
          [](auto const n) {return n > 0; });
```

# 它是如何工作的...

在之前的第二个项目符号中显示的非通用 lambda 表达式接受一个常量整数，并在大于`0`时返回`true`，否则返回`false`。编译器定义了一个具有 lambda 表达式签名的无名函数对象的调用运算符：

```cpp
    struct __lambda_name__ 
    { 
      bool operator()(int const n) const { return n > 0; } 
    };
```

编译器定义的未命名函数对象的方式取决于我们定义 lambda 表达式的方式，它可以捕获变量，使用`mutable`说明符或异常规范，或具有尾部返回类型。之前显示的`__lambda_name__`函数对象实际上是编译器生成的简化版本，因为它还定义了默认的复制和移动构造函数，默认的析构函数和已删除的赋值运算符。

必须充分理解，lambda 表达式实际上是一个类。为了调用它，编译器需要实例化一个类的对象。从 lambda 表达式实例化的对象称为*lambda 闭包*。

在下一个例子中，我们想要计算范围内大于或等于 5 且小于或等于 10 的元素的数量。在这种情况下，lambda 表达式将如下所示：

```cpp
    auto numbers = std::vector<int>{ 0, 2, -3, 5, -1, 6, 8, -4, 9 }; 
    auto start{ 5 }; 
    auto end{ 10 }; 
    auto inrange = std::count_if( 
             std::begin(numbers), std::end(numbers),  
             start, end {
                return start <= n && n <= end;});
```

此 lambda 通过复制（即值）捕获两个变量`start`和`end`。编译器创建的结果未命名函数对象看起来非常像我们之前定义的那个。通过前面提到的默认和已删除的特殊成员，该类如下所示：

```cpp
    class __lambda_name_2__ 
    { 
      int start_; 
      int end_; 
    public: 
      explicit __lambda_name_2__(int const start, int const end) : 
        start_(start), end_(end) 
      {} 

      __lambda_name_2__(const __lambda_name_2__&) = default; 
      __lambda_name_2__(__lambda_name_2__&&) = default; 
      __lambda_name_2__& operator=(const __lambda_name_2__&)  
         = delete; 
      ~__lambda_name_2__() = default; 

      bool operator() (int const n) const 
      { 
        return start_ <= n && n <= end_; 
      } 
    };
```

lambda 表达式可以通过复制（或值）或引用捕获变量，两者的不同组合是可能的。但是，不可能多次捕获变量，并且只能在捕获列表的开头使用`&`或`=`。

lambda 只能捕获封闭函数范围内的变量。它不能捕获具有静态存储期限的变量（即在命名空间范围内声明或使用`static`或`external`说明符声明的变量）。

以下表格显示了 lambda 捕获语义的各种组合。

| 描述 |
| --- |
| 不捕获任何东西 |
| 通过引用捕获一切 |
| 通过复制捕获一切 |
| 仅通过引用捕获`x` |
| 仅通过复制捕获`x` |
| 通过引用捕获包扩展`x` |
| 通过复制捕获包扩展`x` |
| 通过引用捕获一切，除了通过复制捕获的`x` |
| 通过复制捕获一切，除了通过引用捕获的`x` |
| 通过引用捕获一切，除了指针`this`被复制捕获（`this`始终被复制捕获） |
| 错误，`x`被捕获两次 |
| 错误，一切都被引用捕获，不能再次指定通过引用捕获`x` |
| 错误，一切都被复制捕获，不能再次指定通过复制捕获`x` |
| 错误，指针`this`始终被复制捕获 |
| 错误，不能同时通过复制和引用捕获一切 |

截至 C++17，lambda 表达式的一般形式如下：

```cpp
    capture-list mutable constexpr exception attr -> ret
    { body }
```

此语法中显示的所有部分实际上都是可选的，除了捕获列表，但是可以为空，并且主体也可以为空。如果不需要参数，则可以省略参数列表。不需要指定返回类型，因为编译器可以从返回表达式的类型推断出来。`mutable`说明符（告诉编译器 lambda 实际上可以修改通过复制捕获的变量），`constexpr`说明符（告诉编译器生成`constexpr`调用运算符），异常说明符和属性都是可选的。

最简单的 lambda 表达式是`[]{}`，尽管通常写作`[](){}`。

# 还有更多...

有时 lambda 表达式只在其参数的类型上有所不同。在这种情况下，lambda 可以以通用的方式编写，就像模板一样，但是使用`auto`说明符作为类型参数（不涉及模板语法）。这在下一个配方中讨论，见*另请参阅*部分。

# 另请参阅

+   *使用通用 lambda*

+   *编写递归 lambda*

# 使用通用 lambda：

在前面的文章中，我们看到了如何编写 lambda 表达式并将其与标准算法一起使用。在 C++中，lambda 基本上是未命名函数对象的语法糖，这些函数对象是实现调用运算符的类。然而，就像任何其他函数一样，这可以通过模板来实现。C++14 利用了这一点，并引入了通用 lambda，它们不需要为参数指定实际类型，而是使用`auto`关键字。虽然没有用这个名字，通用 lambda 基本上就是 lambda 模板。它们在我们想要使用相同 lambda 但参数类型不同的情况下非常有用。

# 入门

建议在继续阅读本文之前，先阅读前一篇文章《使用 lambda 与标准算法》。

# 操作步骤如下：

编写通用 lambda：

+   使用`auto`关键字而不是实际类型来定义 lambda 表达式的参数。

+   当需要使用多个 lambda，它们之间只有参数类型不同。

以下示例展示了一个通用 lambda 首先与整数向量一起使用`std::accumulate()`算法，然后与字符串向量一起使用。

```cpp
        auto numbers =
          std::vector<int>{0, 2, -3, 5, -1, 6, 8, -4, 9};  
        auto texts =  
          std::vector<std::string>{"hello"s, " "s, "world"s, "!"s}; 

        auto lsum = [](auto const s, auto const n) {return s + n;}; 

        auto sum = std::accumulate( 
          std::begin(numbers), std::end(numbers), 0, lsum); 
          // sum = 22 

        auto text = std::accumulate( 
          std::begin(texts), std::end(texts), ""s, lsum); 
          // sum = "hello world!"s
```

# 工作原理：

在前一节的示例中，我们定义了一个命名的 lambda 表达式，也就是说，一个具有其闭包分配给变量的 lambda 表达式。然后将这个变量作为参数传递给`std::accumulate()`函数。这个通用算法接受定义范围的开始和结束迭代器，一个初始值进行累积，并一个函数，该函数应该将范围内的每个值累积到总和中。这个函数接受一个表示当前累积值的第一个参数和一个表示要累积到总和中的当前值的第二个参数，并返回新的累积值。

请注意，我没有使用术语`add`，因为它不仅仅用于加法。它也可以用于计算乘积、连接或其他将值聚合在一起的操作。

在这个例子中，两次调用`std::accumulate()`几乎相同，只是参数的类型不同：

+   在第一个调用中，我们传递整数范围的迭代器（来自`vector<int>`），初始和为 0，并传递一个将两个整数相加并返回它们的和的 lambda。这将产生范围内所有整数的和；在这个例子中，结果是 22。

+   在第二次调用中，我们传递字符串范围的迭代器（来自`vector<string>`），一个空字符串作为初始值，并传递一个将两个字符串连接在一起并返回结果的 lambda。这将产生一个包含范围内所有字符串的字符串，这个例子中结果是"hello world!"。

虽然通用 lambda 可以在调用它们的地方匿名定义，但这实际上没有意义，因为通用 lambda（基本上就是前面提到的 lambda 表达式模板）的目的是被重用，就像在*操作步骤如下*部分的示例中所示的那样。

在定义用于多次调用`std::accumulate()`的 lambda 表达式时，我们使用了`auto`关键字而不是具体类型来指定 lambda 参数（比如`int`或`std::string`），让编译器推断类型。当遇到 lambda 表达式的参数类型带有`auto`关键字时，编译器会生成一个没有名字的函数对象，该对象具有调用运算符模板。在这个例子中，通用 lambda 表达式的函数对象如下：

```cpp
    struct __lambda_name__ 
    { 
      template<typename T1, typename T2> 
      auto operator()(T1 const s, T2 const n) const { return s + n; } 

       __lambda_name__(const __lambda_name__&) = default; 
       __lambda_name__(__lambda_name__&&) = default; 
       __lambda_name__& operator=(const __lambda_name__&) = delete; 
       ~__lambda_name__() = default; 
    };
```

调用运算符是一个模板，对于 lambda 中使用`auto`指定的每个参数，都有一个类型参数。调用运算符的返回类型也是`auto`，这意味着编译器将从返回值的类型中推断出它。这个操作符模板将使用编译器在使用通用 lambda 的上下文中识别的实际类型进行实例化。

# 另请参阅

+   *使用标准算法与 lambda*

+   *尽可能使用 auto* 第八章 的配方，*学习现代核心语言特性*

# 编写递归 lambda

Lambda 基本上是无名函数对象，这意味着应该可以递归调用它们。事实上，它们可以被递归调用；但是，这样做的机制并不明显，因为它需要将 lambda 分配给函数包装器，并通过引用捕获包装器。虽然可以说递归 lambda 实际上并没有太多意义，函数可能是更好的设计选择，但在这个配方中，我们将看看如何编写递归 lambda。

# 准备工作

为了演示如何编写递归 lambda，我们将考虑著名的斐波那契函数的例子。在 C++中通常以递归方式实现如下：

```cpp
    constexpr int fib(int const n) 
    { 
      return n <= 2 ? 1 : fib(n - 1) + fib(n - 2); 
    }
```

# 如何做...

为了编写递归 lambda 函数，您必须执行以下操作：

+   在函数范围内定义 lambda。

+   将 lambda 分配给`std::function`包装器。

+   通过引用在 lambda 中捕获`std::function`对象，以便递归调用它。

以下是递归 lambda 的示例：

+   在从定义它的范围调用的函数范围内的递归斐波那契 lambda 表达式：

```cpp
        void sample() 
        { 
          std::function<int(int const)> lfib =  
            &lfib 
            { 
              return n <= 2 ? 1 : lfib(n - 1) + lfib(n - 2); 
            }; 

          auto f10 = lfib(10); 
        }
```

+   通过函数返回的递归斐波那契 lambda 表达式，可以从任何范围调用：

```cpp
        std::function<int(int const)> fib_create() 
        { 
          std::function<int(int const)> f = [](int const n)  
          { 
            std::function<int(int const)> lfib = &lfib 
            { 
              return n <= 2 ? 1 : lfib(n - 1) + lfib(n - 2); 
            }; 
            return lfib(n); 
          }; 
          return f; 
        } 

        void sample() 
        { 
          auto lfib = fib_create(); 
          auto f10 = lfib(10); 
        }
```

# 它是如何工作的...

编写递归 lambda 时需要考虑的第一件事是，lambda 表达式是一个函数对象，为了从 lambda 的主体递归调用它，lambda 必须捕获其闭包（即 lambda 的实例化）。换句话说，lambda 必须捕获自身，这有几个含义：

+   首先，lambda 必须有一个名称；无名 lambda 不能被捕获以便再次调用。

+   其次，lambda 只能在函数范围内定义。原因是 lambda 只能捕获函数范围内的变量；它不能捕获任何具有静态存储期的变量。在命名空间范围内或使用 static 或 external 说明符定义的对象具有静态存储期。如果 lambda 在命名空间范围内定义，它的闭包将具有静态存储期，因此 lambda 将无法捕获它。

+   第三个含义是 lambda 闭包的类型不能保持未指定，也就是说，不能使用 auto 说明符声明它。因为在处理初始化程序时，变量的类型是未知的，所以无法使用 auto 类型说明符声明的变量出现在自己的初始化程序中。因此，您必须指定 lambda 闭包的类型。我们可以使用通用目的的函数包装器`std::function`来做到这一点。

+   最后但并非最不重要的是，lambda 闭包必须通过引用捕获。如果我们通过复制（或值）捕获，那么将会创建函数包装器的副本，但是当捕获完成时，包装器将未初始化。我们最终得到一个无法调用的对象。尽管编译器不会抱怨通过值捕获，但当调用闭包时，会抛出`std::bad_function_call`。

在*如何做...*部分的第一个示例中，递归 lambda 是在另一个名为`sample()`的函数内部定义的。lambda 表达式的签名和主体与介绍部分中定义的常规递归函数`fib()`的相同。lambda 闭包被分配给一个名为`lfib`的函数包装器，然后被 lambda 引用并从其主体递归调用。由于闭包被引用捕获，它将在必须从 lambda 的主体中调用时初始化。

在第二个示例中，我们定义了一个函数，该函数返回一个 lambda 表达式的闭包，该闭包又定义并调用了一个递归 lambda，并使用它被调用的参数。当需要从函数返回递归 lambda 时，必须实现这种模式。这是必要的，因为在递归 lambda 被调用时，lambda 闭包仍然必须可用。如果在那之前它被销毁，我们将得到一个悬空引用，并且调用它将导致程序异常终止。这种错误的情况在以下示例中得到了说明：

```cpp
    // this implementation of fib_create is faulty
    std::function<int(int const)> fib_create() 
    { 
      std::function<int(int const)> lfib = &lfib 
      { 
        return n <= 2 ? 1 : lfib(n - 1) + lfib(n - 2); 
      }; 

      return lfib; 
    } 

    void sample() 
    { 
      auto lfib = fib_create();
      auto f10 = lfib(10);       // crash 
    }
```

解决方案是在*如何做...*部分中创建两个嵌套的 lambda 表达式。`fib_create()`方法返回一个函数包装器，当调用时创建捕获自身的递归 lambda。这与前面示例中的实现略有不同，但基本上是不同的。外部的`f` lambda 不捕获任何东西，特别是不捕获引用；因此，我们不会遇到悬空引用的问题。然而，当调用时，它创建了嵌套 lambda 的闭包，我们感兴趣的实际 lambda，并返回将递归的`lfib` lambda 应用于其参数的结果。

# 编写具有可变数量参数的函数模板

有时编写具有可变数量参数的函数或具有可变数量成员的类是很有用的。典型的例子包括`printf`这样的函数，它接受格式和可变数量的参数，或者`tuple`这样的类。在 C++11 之前，前者只能通过使用可变宏（只能编写不安全类型的函数）实现，而后者根本不可能。C++11 引入了可变模板，这是具有可变数量参数的模板，可以编写具有可变数量参数的类型安全函数模板，也可以编写具有可变数量成员的类模板。在本示例中，我们将看看如何编写函数模板。

# 准备工作

具有可变数量参数的函数称为*可变函数*。具有可变数量参数的函数模板称为*可变函数模板*。学习如何编写可变函数模板并不需要了解 C++可变宏（`va_start`、`va_end`、`va_arg`和`va_copy`、`va_list`），但它代表了一个很好的起点。

我们已经在之前的示例中使用了可变模板，但这个示例将提供详细的解释。

# 如何做...

要编写可变函数模板，必须执行以下步骤：

1.  如果可变函数模板的语义要求，可以定义一个带有固定数量参数的重载来结束编译时递归（参见以下代码中的`[1]`）。

1.  定义一个模板参数包，引入一个可以容纳任意数量参数的模板参数，包括零个；这些参数可以是类型、非类型或模板（参见`[2]`）。

1.  定义一个函数参数包，用于保存任意数量的函数参数，包括零个；模板参数包的大小和相应的函数参数包的大小相同，并且可以使用`sizeof...`运算符确定（参见`[3]`）。

1.  扩展参数包，以替换为提供的实际参数（参考`[4]`）。

以下示例说明了所有前面的观点，是一个可变参数函数模板，它使用`operator+`来添加可变数量的参数：

```cpp
    template <typename T>                 // [1] overload with fixed 
    T add(T value)                        //     number of arguments 
    { 
      return value; 
    } 

    template <typename T, typename... Ts> // [2] typename... Ts 
    T add(T head, Ts... rest)             // [3] Ts... rest 
    { 
      return head + add(rest...);         // [4] rest...  
    }
```

# 它是如何工作的...

乍一看，前面的实现看起来像是递归，因为函数`add()`调用了自身，从某种意义上来说确实是，但它是一种不会产生任何运行时递归和开销的编译时递归。编译器实际上会生成几个具有不同参数数量的函数，基于可变参数函数模板的使用，因此只涉及函数重载，而不涉及任何递归。然而，实现是按照参数会以递归方式处理并具有结束条件的方式进行的。

在前面的代码中，我们可以识别出以下关键部分：

+   `Typename... Ts`是指示可变数量模板类型参数的模板参数包。

+   `Ts... rest`是指示可变数量函数参数的函数参数包。

+   `Rest...`是函数参数包的扩展。

省略号的位置在语法上并不重要。`typename... Ts`，`typename ... Ts`和`typename ...Ts`都是等效的。

在`add(T head, Ts... rest)`参数中，`head`是参数列表的第一个元素，`...rest`是列表中其余参数的包（可以是零个或多个）。在函数的主体中，`rest...`是函数参数包的扩展。这意味着编译器会用它们的顺序替换参数包中的元素。在`add()`函数中，我们基本上将第一个参数添加到其余参数的总和中，这给人一种递归处理的印象。当只剩下一个参数时，递归就会结束，在这种情况下，将调用第一个`add()`重载（带有单个参数）并返回其参数的值。

这个函数模板`add()`的实现使我们能够编写如下代码：

```cpp
    auto s1 = add(1, 2, 3, 4, 5);  
    // s1 = 15 
    auto s2 = add("hello"s, " "s, "world"s, "!"s);  
    // s2 = "hello world!"
```

当编译器遇到`add(1, 2, 3, 4, 5)`时，它会生成以下函数（`arg1`，`arg2`等等，并不是编译器生成的实际名称），显示这实际上只是对重载函数的调用，而不是递归：

```cpp
    int add(int head, int arg1, int arg2, int arg3, int arg4)  
    {return head + add(arg1, arg2, arg3, arg4);} 
    int add(int head, int arg1, int arg2, int arg3)  
    {return head + add(arg1, arg2, arg3);} 
    int add(int head, int arg1, int arg2)  
    {return head + add(arg1, arg2);} 
    int add(int head, int arg1)  
    {return head + add(arg1);} 
    int add(int value)  
    {return value;}
```

使用 GCC 和 Clang，您可以使用`__PRETTY_FUNCTION__`宏来打印函数的名称和签名。

通过在我们编写的两个函数的开头添加`std::cout << __PRETTY_FUNCTION__ << std::endl`，在运行代码时我们得到以下结果：

```cpp
    T add(T, Ts ...) [with T = int; Ts = {int, int, int, int}] 
    T add(T, Ts ...) [with T = int; Ts = {int, int, int}] 
    T add(T, Ts ...) [with T = int; Ts = {int, int}] 
    T add(T, Ts ...) [with T = int; Ts = {int}] 
    T add(T) [with T = int]
```

由于这是一个函数模板，它可以与支持`operator+`的任何类型一起使用。另一个例子，`add("hello"s, " "s, "world"s, "!"s)`，产生了字符串`"hello world!"`。然而，`std::basic_string`类型有不同的`operator+`重载，包括一个可以将字符串连接到字符的重载，因此我们应该也能够编写以下内容：

```cpp
    auto s3 = add("hello"s, ' ', "world"s, '!');  
    // s3 = "hello world!"
```

然而，这将生成如下的编译器错误（请注意，我实际上用字符串“hello world”替换了`std::basic_string<char, std::char_traits<char>, std::allocator<char> >`以简化）：

```cpp
In instantiation of 'T add(T, Ts ...) [with T = char; Ts = {string, char}]': 
16:29:   required from 'T add(T, Ts ...) [with T = string; Ts = {char, string, char}]' 
22:46:   required from here 
16:29: error: cannot convert 'string' to 'char' in return 
 In function 'T add(T, Ts ...) [with T = char; Ts = {string, char}]': 
17:1: warning: control reaches end of non-void function [-Wreturn-type]
```

发生的情况是，编译器生成了下面显示的代码，其中返回类型与第一个参数的类型相同。然而，第一个参数是`std::string`或`char`（再次，`std::basic_string<char, std::char_traits<char>, std::allocator<char> >`被替换为`string`以简化）。在第一个参数的类型为`char`的情况下，返回值的类型`head+add(...)`是`std::string`，它与函数返回类型不匹配，并且没有隐式转换为它：

```cpp
    string add(string head, char arg1, string arg2, char arg3)  
    {return head + add(arg1, arg2, arg3);} 
    char add(char head, string arg1, char arg2)  
    {return head + add(arg1, arg2);} 
    string add(string head, char arg1)  
    {return head + add(arg1);} 
    char add(char value)  
    {return value;}
```

我们可以通过修改可变参数函数模板，将返回类型改为`auto`而不是`T`来解决这个问题。在这种情况下，返回类型总是从返回表达式中推断出来，在我们的例子中，它将始终是`std::string`。

```cpp
    template <typename T, typename... Ts> 
    auto add(T head, Ts... rest) 
    { 
      return head + add(rest...); 
    }
```

还应该进一步补充的是，参数包可以出现在大括号初始化中，并且可以使用`sizeof...`运算符确定其大小。此外，可变函数模板并不一定意味着编译时递归，正如我们在本配方中所示的那样。所有这些都在以下示例中展示，其中我们定义了一个创建具有偶数成员的元组的函数。我们首先使用`sizeof...(a)`来确保我们有偶数个参数，并通过生成编译器错误来断言否则。`sizeof...`运算符既可以用于模板参数包，也可以用于函数参数包。`sizeof...(a)`和`sizeof...(T)`将产生相同的值。然后，我们创建并返回一个元组。模板参数包`T`被展开（使用`T...`）为`std::tuple`类模板的类型参数，并且函数参数包`a`被展开（使用`a...`）为元组成员的值，使用大括号初始化：

```cpp
    template<typename... T> 
    auto make_even_tuple(T... a) 
    { 
      static_assert(sizeof...(a) % 2 == 0,  
                    "expected an even number of arguments"); 
      std::tuple<T...> t { a... }; 

      return t; 
    } 

    auto t1 = make_even_tuple(1, 2, 3, 4); // OK 

    // error: expected an even number of arguments 
    auto t2 = make_even_tuple(1, 2, 3);
```

# 另请参阅

+   *使用折叠表达式简化可变函数模板*

+   *在第九章的*创建原始用户定义字面量*配方中，*使用数字和*

*字符串*

# 使用折叠表达式简化可变函数模板

在本章中，我们多次讨论了折叠；这是一种将二元函数应用于一系列值以产生单个值的操作。我们在讨论可变函数模板时已经看到了这一点，并且将在高阶函数中再次看到。事实证明，在编写可变函数模板中参数包的展开基本上是一种折叠操作的情况相当多。为了简化编写这样的可变函数模板，C++17 引入了折叠表达式，它将参数包的展开折叠到二元运算符上。在本配方中，我们将看到如何使用折叠表达式来简化编写可变函数模板。

# 准备工作

本配方中的示例基于我们在上一个配方*编写具有可变数量参数的函数模板*中编写的可变函数模板`add()`。该实现是一个左折叠操作。为简单起见，我们再次呈现该函数：

```cpp
    template <typename T> 
    T add(T value) 
    { 
      return value; 
    } 

    template <typename T, typename... Ts> 
    T add(T head, Ts... rest) 
    { 
      return head + add(rest...); 
    }
```

# 如何做...

要在二元运算符上折叠参数包，请使用以下形式之一：

+   一元形式的左折叠`(... op pack)`：

```cpp
        template <typename... Ts> 
        auto add(Ts... args) 
        { 
          return (... + args); 
        }
```

+   二元形式的左折叠`(init op ... op pack)`：

```cpp
        template <typename... Ts> 
        auto add_to_one(Ts... args) 
        { 
          return (1 + ... + args); 
        }
```

+   一元形式的右折叠`(pack op ...)`：

```cpp
        template <typename... Ts> 
        auto add(Ts... args) 
        { 
          return (args + ...); 
        }
```

+   一元形式的右折叠`(pack op ... op init)`：

```cpp
        template <typename... Ts> 
        auto add_to_one(Ts... args) 
        { 
          return (args + ... + 1); 
        }
```

上面显示的括号是折叠表达式的一部分，不能省略。

# 它是如何工作的...

当编译器遇到折叠表达式时，它会将其扩展为以下表达式之一：

| **表达式** | **展开** |
| --- | --- |
| `(... op pack)` | ((pack$1 op pack$2) op ...) op pack$n |
| `(init op ... op pack)` | (((init op pack$1) op pack$2) op ...) op pack$n |
| `(pack op ...)` | pack$1 op (... op (pack$n-1 op pack$n)) |
| `(pack op ... op init)` | pack$1 op (... op (pack$n-1 op (pack$n op init))) |

当使用二元形式时，省略号的左右两侧的运算符必须相同，并且初始化值不能包含未展开的参数包。

以下二元运算符支持折叠表达式：

| 加 | 减 | 乘 | 除 | 取余 | 指数 | 与 | 或 | 等于 | 小于 | 大于 | 左移 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| >> | += | -= | *= | /= | %= | ^= | &= | &#124;= | <<= | >>= | == |
| != | <= | >= | && | &#124;&#124; | , | .* | ->*. |  |  |  |  |

在使用一元形式时，只允许使用诸如`*`，`+`，`&`，`|`，`&&`，`||`和`,`（逗号）等运算符与空参数包一起。在这种情况下，空包的值如下：

| `+` | `0` |
| --- | --- |
| `*` | `1` |
| `&` | `-1` |
| `&#124;` | `0` |
| `&&` | `true` |
| `&#124;&#124;` | `false` |
| `,` | `void()` |

现在我们已经实现了之前的函数模板（让我们考虑左折叠版本），我们可以编写以下代码：

```cpp
    auto sum = add(1, 2, 3, 4, 5);         // sum = 15 
    auto sum1 = add_to_one(1, 2, 3, 4, 5); // sum = 16
```

考虑到`add(1, 2, 3, 4, 5)`的调用，它将产生以下函数：

```cpp
    int add(int arg1, int arg2, int arg3, int arg4, int arg5) 
    { 
      return ((((arg1 + arg2) + arg3) + arg4) + arg5); 
    }
```

由于现代编译器进行优化的激进方式，这个函数可以被内联，最终得到一个表达式，如`auto sum = 1 + 2 + 3 + 4 + 5`。

# 还有更多...

Fold 表达式适用于所有支持的二元运算符的重载，但不适用于任意的二元函数。可以通过提供一个包装类型来实现对此的解决方法，以保存一个值和一个重载的运算符来实现：

```cpp
    template <typename T> 
    struct wrapper 
    { 
      T const & value; 
    }; 

    template <typename T> 
    constexpr auto operator<(wrapper<T> const & lhs,  
                             wrapper<T> const & rhs)  
    { 
      return wrapper<T> { 
        lhs.value < rhs.value ? lhs.value : rhs.value}; 
    } 

    template <typename... Ts> 
    constexpr auto min(Ts&&... args)  
    { 
      return (wrapper<Ts>{args} < ...).value; 
    }
```

在前面的代码中，`wrapper`是一个简单的类模板，它保存了类型为`T`的值的常量引用。为这个类模板提供了重载的`operator<`；这个重载并不返回一个布尔值来指示第一个参数是否小于第二个参数，而是实际上返回`wrapper`类类型的一个实例，以保存这两个参数的最小值。可变函数模板`min()`使用这个重载的`operator<`来将展开为`wrapper`类模板实例的参数包进行折叠：

```cpp
    auto m = min(1, 2, 3, 4, 5); // m = 1
```

# 另请参阅

+   *实现高阶函数 map 和 fold*

# 实现高阶函数 map 和 fold

在本书的前面几个示例中，我们使用了通用算法`std::transform()`和`std::accumulate()`，例如实现字符串工具来创建字符串的大写或小写副本，或者对范围的值进行求和。这些基本上是高阶函数`map`和`fold`的实现。高阶函数是一个接受一个或多个其他函数作为参数并将它们应用于范围（列表、向量、映射、树等）的函数，产生一个新的范围或值。在这个示例中，我们将看到如何实现`map`和`fold`函数来处理 C++标准容器。

# 准备工作

*Map*是一个高阶函数，它将一个函数应用于范围的元素，并按相同的顺序返回一个新的范围。

*Fold*是一个高阶函数，它将一个组合函数应用于范围的元素，产生一个单一的结果。由于处理的顺序可能很重要，通常有两个版本的这个函数--`foldleft`，从左到右处理元素，和**`foldright`**，从右到左组合元素。

大多数对 map 函数的描述表明它适用于`list`，但这是一个通用术语，可以表示不同的顺序类型，如列表、向量和数组，还有字典（即映射）、队列等。因此，我更喜欢在描述这些高阶函数时使用术语范围。

# 如何做...

要实现`map`函数，您应该：

+   在支持迭代和对元素进行赋值的容器上使用`std::transform`，如`std::vector`或`std::list`：

```cpp
        template <typename F, typename R> 
        R mapf(F&& f, R r) 
        { 
          std::transform( 
            std::begin(r), std::end(r), std::begin(r),  
            std::forward<F>(f)); 
          return r; 
        }
```

+   对于不支持对元素进行赋值的容器，如`std::map`，请使用显式迭代和插入等其他方法：

```cpp
        template<typename F, typename T, typename U> 
        std::map<T, U> mapf(F&& f, std::map<T, U> const & m) 
        { 
          std::map<T, U> r; 
          for (auto const kvp : m) 
            r.insert(f(kvp)); 
          return r; 
        } 

        template<typename F, typename T> 
        std::queue<T> mapf(F&& f, std::queue<T> q) 
        { 
          std::queue<T> r; 
          while (!q.empty()) 
          { 
            r.push(f(q.front())); 
            q.pop(); 
          } 
          return r; 
        }
```

要实现`fold`函数，您应该：

+   在支持迭代的容器上使用`std::accumulate()`：

```cpp
        template <typename F, typename R, typename T> 
        constexpr T foldl(F&& f, R&& r, T i) 
        { 
          return std::accumulate( 
            std::begin(r), std::end(r),  
            std::move(i),  
            std::forward<F>(f)); 
        } 

        template <typename F, typename R, typename T> 
        constexpr T foldr(F&& f, R&& r, T i) 
        { 
          return std::accumulate( 
            std::rbegin(r), std::rend(r),  
            std::move(i),  
            std::forward<F>(f)); 
        }
```

+   使用其他方法显式处理不支持迭代的容器，如`std::queue`：

```cpp
        template <typename F, typename T> 
        constexpr T foldl(F&& f, std::queue<T> q, T i) 
        { 
          while (!q.empty()) 
          { 
            i = f(i, q.front()); 
            q.pop(); 
          } 
          return i; 
        }
```

# 它是如何工作的...

在前面的示例中，我们以一种功能方式实现了 map，没有副作用。这意味着它保留了原始范围并返回了一个新的范围。函数的参数是要应用的函数和范围。为了避免与`std::map`容器混淆，我们将这个函数称为`mapf`。有几个`mapf`的重载，如前面所示：

+   第一个重载适用于支持迭代和对其元素赋值的容器；这包括`std::vector`、`std::list`和`std::array`，还有类似 C 的数组。该函数接受一个对函数的`rvalue`引用和一个范围，其中`std::begin()`和`std::end()`被定义。范围通过值传递，这样修改本地副本不会影响原始范围。通过应用给定函数对每个元素使用标准算法`std::transform()`来转换范围；然后返回转换后的范围。

+   第二个重载专门针对不支持直接赋值给其元素（`std::pair<T, U>`）的`std::map`。因此，这个重载创建一个新的映射，然后使用基于范围的 for 循环遍历其元素，并将应用输入函数的结果插入到新映射中。

+   第三个重载专门针对`std::queue`，这是一个不支持迭代的容器。可以说队列不是一个典型的映射结构，但为了演示不同的可能实现，我们考虑它。为了遍历队列的元素，必须改变队列--需要从前面弹出元素，直到列表为空。这就是第三个重载所做的--它处理输入队列的每个元素（通过值传递），并将应用给定函数的结果推送到剩余队列的前端元素。

现在我们已经实现了这些重载，我们可以将它们应用到许多容器中，如下面的例子所示（请注意，这里使用的 map 和 fold 函数在附带书籍的代码中实现在名为 funclib 的命名空间中，因此显示为完全限定名称）：

+   保留向量中的绝对值。在这个例子中，向量包含负值和正值。应用映射后，结果是一个只包含正值的新向量。

```cpp
        auto vnums =  
          std::vector<int>{0, 2, -3, 5, -1, 6, 8, -4, 9};  
        auto r = funclib::mapf([](int const i) { 
          return std::abs(i); }, vnums);  
        // r = {0, 2, 3, 5, 1, 6, 8, 4, 9}
```

+   对列表中的数值进行平方。在这个例子中，列表包含整数值。应用映射后，结果是一个包含初始值的平方的列表。

```cpp
        auto lnums = std::list<int>{1, 2, 3, 4, 5}; 
        auto l = funclib::mapf([](int const i) { 
          return i*i; }, lnums); 
        // l = {1, 4, 9, 16, 25}
```

+   浮点数的四舍五入金额。在这个例子中，我们需要使用`std::round()`；然而，这个函数对所有浮点类型都有重载，这使得编译器无法选择正确的重载。因此，我们要么编写一个接受特定浮点类型参数并返回应用于该值的`std::round()`值的 lambda，要么创建一个函数对象模板，包装`std::round()`并仅对浮点类型启用其调用运算符。这种技术在下面的例子中使用：

```cpp
        template<class T = double> 
        struct fround 
        {   
          typename std::enable_if< 
            std::is_floating_point<T>::value, T>::type 
          operator()(const T& value) const 
          { 
            return std::round(value); 
          } 
        }; 

        auto amounts =  
          std::array<double, 5> {10.42, 2.50, 100.0, 23.75, 12.99}; 
        auto a = funclib::mapf(fround<>(), amounts); 
        // a = {10.0, 3.0, 100.0, 24.0, 13.0}
```

+   将单词映射的地图键大写（其中键是单词，值是在文本中出现的次数）。请注意，创建字符串的大写副本本身就是一个映射操作。因此，在这个例子中，我们使用`mapf`将`toupper()`应用于表示键的字符串的元素，以产生一个大写副本。

```cpp
        auto words = std::map<std::string, int>{  
          {"one", 1}, {"two", 2}, {"three", 3}  
        }; 
        auto m = funclib::mapf( 
          [](std::pair<std::string, int> const kvp) { 
            return std::make_pair( 
              funclib::mapf(toupper, kvp.first),  
              kvp.second); 
          }, 
          words); 
        // m = {{"ONE", 1}, {"TWO", 2}, {"THREE", 3}}
```

+   从优先级队列中规范化数值--最初，数值范围是 1 到 100，但我们希望将它们规范化为两个值，1=高和 2=正常。所有初始优先级的值最多为 30 的变为高优先级，其他的变为正常优先级：

```cpp
        auto priorities = std::queue<int>(); 
        priorities.push(10); 
        priorities.push(20); 
        priorities.push(30); 
        priorities.push(40); 
        priorities.push(50); 
        auto p = funclib::mapf( 
          [](int const i) { return i > 30 ? 2 : 1; },  
          priorities); 
        // p = {1, 1, 1, 2, 2}
```

要实现`fold`，我们实际上必须考虑两种可能的折叠类型，即从左到右和从右到左。因此，我们提供了两个名为`foldl`（用于左折叠）和`foldr`（用于右折叠）的函数。在前一节中显示的实现非常相似--它们都接受一个函数、一个范围和一个初始值，并调用`std::algorithm()`将范围的值折叠成一个值。然而，`foldl`使用直接迭代器，而`foldr`使用反向迭代器来遍历和处理范围。第二个重载是`std::queue`类型的特化，它没有迭代器。

基于这些折叠实现，我们可以进行以下示例：

+   添加整数向量的值。在这种情况下，左折叠和右折叠将产生相同的结果。在以下示例中，我们传递一个 lambda，它接受一个和一个数字并返回一个新的和，或者从标准库中使用`std::plus<>`函数对象，它将`operator+`应用于相同类型的两个操作数（基本上类似于 lambda 的闭包）：

```cpp
        auto vnums =  
           std::vector<int>{0, 2, -3, 5, -1, 6, 8, -4, 9};  

        auto s1 = funclib::foldl( 
           [](const int s, const int n) {return s + n; },  
           vnums, 0);                // s1 = 22 

        auto s2 = funclib::foldl( 
           std::plus<>(), vnums, 0); // s2 = 22 

        auto s3 = funclib::foldr( 
           [](const int s, const int n) {return s + n; },  
           vnums, 0);                // s3 = 22 

        auto s4 = funclib::foldr( 
           std::plus<>(), vnums, 0); // s4 = 22
```

+   将字符串从向量连接成一个字符串：

```cpp
        auto texts =  
           std::vector<std::string>{"hello"s, " "s, "world"s, "!"s}; 

        auto txt1 = funclib::foldl( 
           [](std::string const & s, std::string const & n) { 
           return s + n;},  
           texts, ""s);    // txt1 = "hello world!" 

        auto txt2 = funclib::foldr( 
           [](std::string const & s, std::string const & n) { 
           return s + n; },  
           texts, ""s);    // txt2 = "!world hello"
```

+   将字符数组连接成一个字符串：

```cpp
        char chars[] = {'c','i','v','i','c'}; 

        auto str1 = funclib::foldl(std::plus<>(), chars, ""s);  
        // str1 = "civic" 

        auto str2 = funclib::foldr(std::plus<>(), chars, ""s);  
        // str2 = "civic"
```

+   根据`map<string, int>`中已计算出现次数的单词数量来计算文本中单词的数量：

```cpp
        auto words = std::map<std::string, int>{  
           {"one", 1}, {"two", 2}, {"three", 3} }; 

        auto count = funclib::foldl( 
           [](int const s, std::pair<std::string, int> const kvp) { 
              return s + kvp.second; }, 
           words, 0); // count = 6
```

# 还有更多...

这些函数可以被串联，也就是说，它们可以用另一个函数调用另一个函数的结果。以下示例将整数范围映射为正整数范围，方法是将`std::abs()`函数应用于其元素。然后将结果映射到另一个平方范围。然后通过在范围上应用左折叠将它们相加：

```cpp
    auto vnums = std::vector<int>{ 0, 2, -3, 5, -1, 6, 8, -4, 9 }; 

    auto s = funclib::foldl( 
      std::plus<>(), 
      funclib::mapf( 
        [](int const i) {return i*i; },  
        funclib::mapf( 
          [](int const i) {return std::abs(i); }, 
          vnums)), 
      0); // s = 236
```

作为练习，我们可以按照前面配方中所见的方式，将 fold 函数实现为一个可变参数函数模板。执行实际折叠的函数作为参数提供：

```cpp
    template <typename F, typename T1, typename T2> 
    auto foldl(F&&f, T1 arg1, T2 arg2) 
    { 
      return f(arg1, arg2); 
    } 

    template <typename F, typename T, typename... Ts> 
    auto foldl(F&& f, T head, Ts... rest) 
    { 
      return f(head, foldl(std::forward<F>(f), rest...)); 
    }
```

当我们将这与我们在配方*编写具有可变数量参数的函数模板*中编写的`add()`函数模板进行比较时，我们可以注意到几个不同之处：

+   第一个参数是一个函数，在递归调用`foldl`时可以完全转发。

+   结束情况是一个需要两个参数的函数，因为我们用于折叠的函数是一个二元函数（接受两个参数）。

+   我们编写的两个函数的返回类型声明为`auto`，因为它必须匹配提供的二元函数`f`的返回类型，直到我们调用`foldl`为止，这是不知道的：

```cpp
    auto s1 = foldl(std::plus<>(), 1, 2, 3, 4, 5);  
    // s1 = 15 
    auto s2 = foldl(std::plus<>(), "hello"s, ' ', "world"s, '!');  
    // s2 = "hello world!" 
    auto s3 = foldl(std::plus<>(), 1); // error, too few arguments
```

# 参见

+   *创建字符串助手库* 第九章的配方[9830e5b8-a9ca-41e8-b565-8800a82d9caa.xhtml]，*处理数字和字符串*

+   *编写具有可变数量参数的函数模板*

+   *将函数组合成高阶函数*

# 将函数组合成高阶函数

在上一个配方中，我们实现了两个高阶函数，map 和 fold，并看到了它们的各种使用示例。在配方的结尾，我们看到它们如何可以被串联起来，在对原始数据进行多次转换后产生最终值。管道是一种组合形式，意味着从两个或更多给定函数创建一个新函数。在上述示例中，我们实际上并没有组合函数；我们只是调用了一个函数，其结果由另一个函数产生，但在这个配方中，我们将看到如何将函数实际组合到一起成为一个新函数。为简单起见，我们只考虑一元函数（只接受一个参数的函数）。

# 准备工作

在继续之前，建议您阅读前一篇配方*实现高阶函数 map 和 fol*d。这不是理解本配方的必要条件，但我们将引用这里实现的 map 和 fold 函数。 

# 操作步骤

要将一元函数组合成高阶函数，您应该：

+   要组合两个函数，提供一个接受两个函数`f`和`g`作为参数并返回一个新函数（lambda）的函数，该函数返回`f(g(x))`，其中`x`是组合函数的参数：

```cpp
        template <typename F, typename G> 
        auto compose(F&& f, G&& g) 
        {  
          return = { return f(g(x)); }; 
        } 

        auto v = compose( 
          [](int const n) {return std::to_string(n); }, 
          [](int const n) {return n * n; })(-3); // v = "9"
```

+   要组合可变数量的函数，提供先前描述的函数的可变模板重载：

```cpp
        template <typename F, typename... R> 
        auto compose(F&& f, R&&... r) 
        { 
          return = { return f(compose(r...)(x)); }; 
        } 

        auto n = compose( 
          [](int const n) {return std::to_string(n); }, 
          [](int const n) {return n * n; }, 
          [](int const n) {return n + n; }, 
          [](int const n) {return std::abs(n); })(-3); // n = "36"
```

# 工作原理...

将两个一元函数组合成一个新函数相对较简单。创建一个我们在之前的示例中称为`compose()`的模板函数，它有两个参数--`f`和`g`--代表函数，并返回一个接受一个参数`x`并返回`f(g(x))`的函数。但是重要的是，`g`函数返回的值的类型与`f`函数的参数的类型相同。`compose`函数的返回值是一个闭包，即一个 lambda 的实例。

在实践中，能够组合不止两个函数是很有用的。这可以通过编写`compose()`函数的可变模板版本来实现。可变模板在*编写具有可变数量参数的函数模板*配方中有更详细的解释。可变模板意味着通过扩展参数包进行编译时递归。这个实现与`compose()`的第一个版本非常相似，只是如下：

+   它接受可变数量的函数作为参数。

+   返回的闭包使用扩展的参数包递归调用`compose()`；递归在只剩下两个函数时结束，在这种情况下，调用先前实现的重载。

即使代码看起来像是发生了递归，这并不是真正的递归。这可以称为编译时递归，但是随着每次扩展，我们会得到对另一个具有相同名称但不同数量参数的方法的调用，这并不代表递归。

现在我们已经实现了这些可变模板重载，我们可以重写上一个配方*实现高阶函数 map 和 fold*中的最后一个示例。有一个初始整数向量，我们通过对每个元素应用`std::abs()`将其映射到只有正值的新向量。然后，将结果映射到一个新向量，方法是将每个元素的值加倍。最后，将结果向量中的值通过将它们添加到初始值 0 来折叠在一起：

```cpp
    auto s = compose( 
      [](std::vector<int> const & v) { 
        return foldl(std::plus<>(), v, 0); }, 
      [](std::vector<int> const & v) { 
        return mapf([](int const i) {return i + i; }, v); }, 
      [](std::vector<int> const & v) { 
        return mapf([](int const i) {return std::abs(i); }, v); })(vnums);
```

# 还有更多...

组合通常用点（`.`）或星号（`*`）表示，比如`f . g`或`f * g`。我们实际上可以在 C++中做类似的事情，通过重载`operator*`（尝试重载操作符点没有多大意义）。与`compose()`函数类似，`operator*`应该适用于任意数量的参数；因此，我们将有两个重载，就像在`compose()`的情况下一样：

+   第一个重载接受两个参数并调用`compose()`返回一个新函数。

+   第二个重载是一个可变模板函数，再次通过扩展参数包调用`operator*`：

```cpp
    template <typename F, typename G> 
    auto operator*(F&& f, G&& g) 
    { 
      return compose(std::forward<F>(f), std::forward<G>(g)); 
    } 

    template <typename F, typename... R> 
    auto operator*(F&& f, R&&... r) 
```

```cpp
    { 
      return operator*(std::forward<F>(f), r...); 
    }
```

现在，我们可以通过应用`operator*`来简化函数的实际组合，而不是更冗长地调用 compose：

```cpp
    auto n = 
      ([](int const n) {return std::to_string(n); } * 
       [](int const n) {return n * n; } * 
       [](int const n) {return n + n; } * 
       [](int const n) {return std::abs(n); })(-3); // n = "36" 

    auto c =  
      [](std::vector<int> const & v) { 
        return foldl(std::plus<>(), v, 0); } * 
      [](std::vector<int> const & v) { 
        return mapf([](int const i) {return i + i; }, v); } * 
      [](std::vector<int> const & v) { 
        return mapf([](int const i) {return std::abs(i); }, v); }; 

    auto s = c(vnums); // s = 76
```

# 另请参阅

+   *编写具有可变数量参数的函数模板*

# 统一调用任何可调用对象

开发人员，特别是那些实现库的人，有时需要以统一的方式调用可调用对象。这可以是一个函数，一个指向函数的指针，一个指向成员函数的指针，或者一个函数对象。这种情况的例子包括`std::bind`，`std::function`，`std::mem_fn`和`std::thread::thread`。C++17 定义了一个名为`std::invoke()`的标准函数，可以使用提供的参数调用任何可调用对象。这并不意味着要取代对函数或函数对象的直接调用，但在模板元编程中实现各种库函数时非常有用。

# 准备就绪

对于这个配方，您应该熟悉如何定义和使用函数指针。

为了举例说明 `std::invoke()` 如何在不同的上下文中使用，我们将使用以下函数和类：

```cpp
    int add(int const a, int const b) 
    { 
      return a + b; 
    } 

    struct foo 
    { 
      int x = 0; 

      void increment_by(int const n) { x += n; } 
    };
```

# 如何做...

`std::invoke()` 函数是一个可变参数的函数模板，它将可调用对象作为第一个参数，并传递给调用的可变参数列表。`std::invoke()` 可以用来调用以下内容：

+   自由函数：

```cpp
        auto a1 = std::invoke(add, 1, 2);   // a1 = 3
```

+   通过函数指针调用自由函数：

```cpp
        auto a2 = std::invoke(&add, 1, 2);  // a2 = 3 
        int(*fadd)(int const, int const) = &add; 
        auto a3 = std::invoke(fadd, 1, 2);  // a3 = 3
```

+   通过成员函数指针调用成员函数：

```cpp
        foo f; 
        std::invoke(&foo::increment_by, f, 10);
```

+   数据成员：

```cpp
        foo f; 
        auto x1 = std::invoke(&foo::x, f);  // x1 = 0
```

+   函数对象：

```cpp
        foo f; 
        auto x3 = std::invoke(std::plus<>(),  
          std::invoke(&foo::x, f), 3); // x3 = 3
```

+   Lambda 表达式：

```cpp
        auto l = [](auto a, auto b) {return a + b; }; 
        auto a = std::invoke(l, 1, 2); // a = 3
```

在实践中，`std::invoke()` 应该在模板元编程中被用来调用带有任意数量参数的函数。为了举例说明这样的情况，我们提供了我们的 `std::apply()` 函数的可能实现，以及作为 C++17 标准库的一部分的一个调用函数的实现，通过将元组的成员解包成函数的参数：

```cpp
    namespace details 
    { 
      template <class F, class T, std::size_t... I> 
      auto apply(F&& f, T&& t, std::index_sequence<I...>) 
      { 
        return std::invoke( 
          std::forward<F>(f), 
          std::get<I>(std::forward<T>(t))...); 
      } 
    } 

    template <class F, class T> 
    auto apply(F&& f, T&& t) 
    { 
      return details::apply( 
        std::forward<F>(f), 
        std::forward<T>(t), 
        std::make_index_sequence< 
          std::tuple_size<std::decay_t<T>>::value> {}); 
    }
```

# 它是如何工作的...

在我们看到 `std::invoke()` 如何工作之前，让我们简要看一下不同可调用对象如何被调用。给定一个函数，显然，调用它的普遍方式是直接传递必要的参数给它。然而，我们也可以使用函数指针来调用函数。函数指针的问题在于定义指针的类型可能很麻烦。使用 `auto` 可以简化事情（如下面的代码所示），但在实践中，通常需要先定义函数指针的类型，然后定义一个对象并用正确的函数地址进行初始化。以下是几个例子：

```cpp
    // direct call 
    auto a1 = add(1, 2);    // a1 = 3 

    // call through function pointer 
    int(*fadd)(int const, int const) = &add; 
    auto a2 = fadd(1, 2);   // a2 = 3 

    auto fadd2 = &add; 
    auto a3 = fadd2(1, 2);  // a3 = 3
```

当您需要通过一个是类的实例的对象来调用类函数时，通过函数指针进行调用变得更加麻烦。定义成员函数的指针和调用它的语法并不简单：

```cpp
    foo f; 
    f.increment_by(3); 
    auto x1 = f.x;    // x1 = 3 

    void(foo::*finc)(int const) = &foo::increment_by; 
    (f.*finc)(3); 
    auto x2 = f.x;    // x2 = 6 

    auto finc2 = &foo::increment_by; 
    (f.*finc2)(3); 
    auto x3 = f.x;    // x3 = 9
```

无论这种调用看起来多么麻烦，实际问题是编写能够以统一方式调用任何这些类型的可调用对象的库组件（函数或类）。这就是实践中从标准函数（如 `std::invoke()`）中受益的地方。

`std::invoke()` 的实现细节很复杂，但它的工作原理可以用简单的术语来解释。假设调用的形式是 `invoke(f, arg1, arg2, ..., argN)`，那么考虑以下情况：

+   如果 `f` 是 `T` 类的成员函数的指针，那么调用等价于：

+   `(arg1.*f)(arg2, ..., argN)`，如果 `arg1` 是 `T` 的一个实例

+   `(arg1.get().*f)(arg2, ..., argN)`，如果 `arg1` 是 `reference_wrapper` 的一个特化

+   `((*arg1).*f)(arg2, ..., argN)`，如果是其他情况

+   如果 `f` 是 `T` 类的数据成员的指针，并且有一个参数，换句话说，调用的形式是 `invoke(f, arg1)`，那么调用等价于：

+   `arg1.*f`，如果 `arg1` 是 `T` 类的一个实例

+   `arg1.get().*f`，如果 `arg1` 是 `reference_wrapper` 的一个特化

+   `(*arg1).*f`，如果是其他情况

+   如果 `f` 是一个函数对象，那么调用等价于 `f(arg1, arg2, ..., argN)`

# 另请参阅

+   *编写一个带有可变数量参数的函数模板*


# 第十一章：标准库容器、算法和迭代器

本章中将涵盖以下教程：

+   将向量用作默认容器

+   使用位集处理固定大小的位序列

+   使用`vector<bool>`来处理可变大小的位序列

+   在范围内查找元素

+   对范围进行排序

+   初始化范围

+   在范围上使用集合操作

+   使用迭代器在容器中插入新元素

+   编写自己的随机访问迭代器

+   使用非成员函数访问容器

# 将向量用作默认容器

标准库提供了各种类型的容器，用于存储对象的集合；库包括序列容器（如`vector`、`array`或`list`）、有序和无序关联容器（如`set`和`map`），以及不存储数据但提供适应接口向序列容器提供适配的容器适配器（如`stack`和`queue`）。它们都是作为类模板实现的，这意味着它们可以与任何类型一起使用（只要满足容器要求）。虽然您应该始终使用最适合特定问题的容器（不仅在插入、删除、访问元素和内存使用速度方面提供良好性能，而且使代码易于阅读和维护），但默认选择应该是`vector`。在本教程中，我们将看到为什么`vector`应该是首选容器，并且`vector`的最常见操作是什么。

# 准备工作

读者应该熟悉类 C 数组，包括静态分配和动态分配。

类模板`vector`在`<vector>`头文件中的`std`命名空间中可用。

# 如何做...

要初始化`std::vector`类模板，可以使用以下任何一种方法，但您不仅限于这些：

+   从初始化列表初始化：

```cpp
        std::vector<int> v1 { 1, 2, 3, 4, 5 };
```

+   从类 C 数组初始化：

```cpp
        int arr[] = { 1, 2, 3, 4, 5 }; 
        std::vector<int> v2(arr, arr + 5); // { 1, 2, 3, 4, 5 }
```

+   从另一个容器初始化：

```cpp
        std::list<int> l{ 1, 2, 3, 4, 5 }; 
        std::vector<int> v3(l.begin(), l.end()); //{ 1, 2, 3, 4, 5 }
```

+   从计数和值初始化：

```cpp
        std::vector<int> v4(5, 1); // {1, 1, 1, 1, 1}
```

要修改`std::vector`的内容，请使用以下任何一种方法，但您不仅限于这些：

+   使用`push_back()`在向量末尾添加一个元素：

```cpp
        std::vector<int> v1{ 1, 2, 3, 4, 5 };
        v1.push_back(6); // v1 = { 1, 2, 3, 4, 5, 6 }
```

+   使用`pop_back()`从向量末尾删除一个元素：

```cpp
        v1.pop_back();
```

+   使用`insert()`在向量中的任何位置插入：

```cpp
        int arr[] = { 1, 2, 3, 4, 5 };
        std::vector<int> v2;
        v2.insert(v2.begin(), arr, arr + 5); // v2 = { 1, 2, 3, 4, 5 }
```

+   使用`emplace_back()`在向量末尾创建一个元素：

```cpp
        struct foo
        {
          int a;
          double b;
          std::string c;

          foo(int a, double b, std::string const & c) :
            a(a), b(b), c(c) {}
        };

        std::vector<foo> v3;
        v3.emplace_back(1, 1.0, "one"s); 
        // v3 = { foo{1, 1.0, "one"} }
```

+   通过`emplace()`在向量中的任何位置创建元素插入：

```cpp
        v3.emplace(v3.begin(), 2, 2.0, "two"s);
        // v3 = { foo{2, 2.0, "two"}, foo{1, 1.0, "one"} }
```

要修改向量的整个内容，请使用以下任何一种方法，但您不仅限于这些：

+   使用`operator=`从另一个向量分配；这将替换容器的内容：

```cpp
        std::vector<int> v1{ 1, 2, 3, 4, 5 };
        std::vector<int> v2{ 10, 20, 30 };
        v2 = v1; // v1 = { 1, 2, 3, 4, 5 }
```

+   使用`assign()`方法从由开始和结束迭代器定义的另一个序列分配；这将替换容器的内容：

```cpp
        int arr[] = { 1, 2, 3, 4, 5 };
        std::vector<int> v3;
        v3.assign(arr, arr + 5); // v3 = { 1, 2, 3, 4, 5 }
```

+   使用`swap()`方法交换两个向量的内容：

```cpp
        std::vector<int> v4{ 1, 2, 3, 4, 5 };
        std::vector<int> v5{ 10, 20, 30 };
        v4.swap(v5); // v4 = { 10, 20, 30 }, v5 = { 1, 2, 3, 4, 5 }
```

+   使用`clear()`方法删除所有元素：

```cpp
        std::vector<int> v6{ 1, 2, 3, 4, 5 };
        v6.clear(); // v6 = { }
```

+   使用`erase()`方法删除一个或多个元素（需要定义要删除的向量元素范围的迭代器或一对迭代器）：

```cpp
        std::vector<int> v7{ 1, 2, 3, 4, 5 };
        v7.erase(v7.begin() + 2, v7.begin() + 4); // v7 = { 1, 2, 5 }
```

要获取向量中第一个元素的地址，通常将向量的内容传递给类 C API，可以使用以下任何一种方法：

+   使用`data()`方法，返回指向第一个元素的指针，直接访问存储向量元素的底层连续内存序列；这仅在 C++11 之后才可用：

```cpp
        void process(int const * const arr, int const size) 
        { /* do something */ }

        std::vector<int> v{ 1, 2, 3, 4, 5 };
        process(v.data(), static_cast<int>(v.size()));
```

+   获取第一个元素的地址：

```cpp
        process(&v[0], static_cast<int>(v.size()));
```

+   获取由`front()`方法引用的元素的地址：

```cpp
        process(&v.front(), static_cast<int>(v.size()));
```

+   使用从`begin()`返回的迭代器指向的元素的地址：

```cpp
        process(&*v.begin(), static_cast<int>(v.size()));
```

# 它是如何工作的...

`std::vector`类被设计为 C++中最类似和可互操作的 C 类似数组的容器。向量是一个可变大小的元素序列，保证在内存中连续存储，这使得向量的内容可以轻松地传递给一个类似 C 的函数，该函数接受一个指向数组元素的指针，通常还有一个大小。使用向量而不是 C 类似的数组有许多好处，这些好处包括：

+   开发人员不需要进行直接的内存管理，因为容器在内部执行这些操作，分配内存，重新分配和释放。

请注意，向量用于存储对象实例。如果需要存储指针，请不要存储原始指针，而是智能指针。否则，您需要处理指向对象的生命周期管理。

+   +   修改向量大小的可能性。

+   简单的赋值或两个向量的连接。

+   直接比较两个向量。

`vector`类是一个非常高效的容器，所有实现都提供了许多优化，大多数开发人员无法使用 C 类似的数组进行。对其元素的随机访问以及在向量末尾的插入和删除是一个常数*O(1)*操作（前提是不需要重新分配内存），而在其他任何地方的插入和删除是一个线性*O(n)*操作。

与其他标准容器相比，向量具有各种好处：

+   它与类似 C 的数组和类似 C 的 API 兼容；其他容器的内容（除了`std::array`）需要在传递给期望数组的类似 C 的 API 之前复制到向量中。

+   它具有所有容器中元素的最快访问速度。

+   存储元素的每个元素内存开销为零，因为元素存储在连续的空间中，就像 C 数组一样（不像其他容器，如`list`需要额外的指针指向其他元素，或者需要哈希值的关联容器）。

`std::vector`在语义上与类似 C 的数组非常相似，但大小可变。向量的大小可以增加和减少。有两个属性定义了向量的大小：

+   *Capacity*是向量在不执行额外内存分配的情况下可以容纳的元素数量；这由`capacity()`方法表示。

+   *Size*是向量中实际元素的数量；这由`size()`方法表示。

大小始终小于或等于容量。当大小等于容量并且需要添加新元素时，需要修改容量，以便向量有更多元素的空间。在这种情况下，向量分配新的内存块，并将先前的内容移动到新位置，然后释放先前分配的内存。尽管这听起来很耗时（而且确实如此），但实现会按指数增加容量，每次需要更改时将其加倍。因此，平均而言，向量的每个元素只需要移动一次（这是因为在增加容量时向量的所有元素都会移动，但然后可以添加相等数量的元素而不需要进行更多的移动，因为插入是在向量的末尾进行的）。

如果事先知道要插入向量的元素数量，可以首先调用`reserve()`方法将容量增加到至少指定的数量（如果指定的大小小于当前容量，则此方法不执行任何操作），然后再插入元素。

另一方面，如果您需要释放额外保留的内存，可以使用`shrink_to_fit()`方法来请求，但是否释放任何内存是一个实现决定。自 C++11 以来，可用的另一种非绑定方法是与临时的空向量进行交换：

```cpp
    std::vector<int> v{ 1, 2, 3, 4, 5 };
    std::vector<int>().swap(v); // v.size = 0, v.capacity = 0
```

调用`clear()`方法只会从向量中删除所有元素，但不会释放任何内存。

应该注意，向量实现了特定于其他类型容器的操作：

+   `stack`：使用`push_back()`和`emplace_back()`在末尾添加，使用`pop_back()`从末尾移除。请记住，`pop_back()`不会返回已移除的最后一个元素。如果有必要，您需要显式访问它，例如，在移除元素之前使用`back()`方法。

+   `list`：使用`insert()`和`emplace()`在序列中间添加元素，使用`erase()`从序列中的任何位置移除元素。

# 还有更多...

C++容器的经验法则是：除非有充分的理由使用其他容器，否则使用`std::vector`作为默认容器。

# 另请参阅

+   *使用 bitset 表示固定大小的位序列*

+   *使用`vector<bool>`表示可变大小的位序列*

# 使用 bitset 表示固定大小的位序列

开发人员通常会使用位标志进行操作；这可能是因为他们使用操作系统 API（通常用 C 编写），这些 API 接受各种类型的参数（例如选项或样式）以位标志的形式，或者因为他们使用执行类似操作的库，或者仅仅因为某些类型的问题自然而然地使用位标志来解决。可以考虑使用与位和位操作相关的替代方案，例如定义具有每个选项/标志的一个元素的数组，或者定义一个具有成员和函数来模拟位标志的结构，但这些通常更加复杂，而且如果您需要将表示位标志的数值传递给函数，则仍然需要将数组或结构转换为位序列。因此，C++标准提供了一个称为`std::bitset`的固定大小位序列的容器。

# 准备工作

对于本示例，您必须熟悉位操作（与、或、异或、非和移位）。

`bitset`类位于`<bitset>`头文件中的`std`命名空间中。bitset 表示固定大小的位序列，其大小在编译时定义。为方便起见，在本示例中，所有示例都将使用 8 位的位集。

# 如何做到...

要构造一个`std::bitset`对象，请使用其中一个可用的构造函数：

+   所有位都设置为 0 的空位集：

```cpp
        std::bitset<8> b1; // [0,0,0,0,0,0,0,0]
```

+   从数值创建一个位集：

```cpp
        std::bitset<8> b2{ 10 }; // [0,0,0,0,1,0,1,0]
```

+   从包含`'0'`和`'1'`的字符串创建一个位集：

```cpp
        std::bitset<8> b3{ "1010"s }; // [0,0,0,0,1,0,1,0]
```

+   从包含表示`'0'`和`'1'`的任意两个字符的字符串创建一个位集；在这种情况下，我们必须指定哪个字符表示 0，哪个字符表示 1：

```cpp
        std::bitset<8> b4 
          { "ooooxoxo"s, 0, std::string::npos, 'o', 'x' }; 
          // [0,0,0,0,1,0,1,0]
```

测试集合中的单个位或整个集合的特定值，可以使用任何可用的方法：

+   `count()` 以获取设置为 1 的位数：

```cpp
        std::bitset<8> bs{ 10 };
        std::cout << "has " << bs.count() << " 1s" << std::endl;
```

+   `any()` 用于检查是否至少有一个位设置为 1：

```cpp
        if (bs.any()) std::cout << "has some 1s" << std::endl;
```

+   `all()` 以检查是否所有位都设置为 1：

```cpp
        if (bs.all()) std::cout << "has only 1s" << std::endl;
```

+   `none()` 以检查是否所有位都设置为 0：

```cpp
        if (bs.none()) std::cout << "has no 1s" << std::endl;
```

+   `test()` 用于检查单个位的值：

```cpp
        if (!bs.test(0)) std::cout << "even" << std::endl;
```

+   `operator[]` 用于访问和测试单个位：

```cpp
        if(!bs[0]) std::cout << "even" << std::endl;
```

要修改位集的内容，请使用以下任何方法：

+   成员运算符`|=`, `&=`, `^= `和`~` 以执行二进制或、与、异或和非操作，或非成员运算符`|`, `&`, 和`^`：

```cpp
        std::bitset<8> b1{ 42 }; // [0,0,1,0,1,0,1,0]
        std::bitset<8> b2{ 11 }; // [0,0,0,0,1,0,1,1]
        auto b3 = b1 | b2;       // [0,0,1,0,1,0,1,1]
        auto b4 = b1 & b2;       // [0,0,0,0,1,0,1,0]
        auto b5 = b1 ^ b2;       // [1,1,0,1,1,1,1,0]
        auto b6 = ~b1;           // [1,1,0,1,0,1,0,1]
```

+   成员运算符`<<=`, `<<`, `>>=`, `>>` 以执行移位操作：

```cpp
        auto b7 = b1 << 2;       // [1,0,1,0,1,0,0,0]
        auto b8 = b1 >> 2;       // [0,0,0,0,1,0,1,0]
```

+   `flip()` 以将整个集合或单个位从 0 切换为 1 或从 1 切换为 0：

```cpp
        b1.flip();               // [1,1,0,1,0,1,0,1]
        b1.flip(0);              // [1,1,0,1,0,1,0,0]
```

+   `set()` 以将整个集合或单个位更改为`true`或指定的值：

```cpp
        b1.set(0, true);         // [1,1,0,1,0,1,0,1]
        b1.set(0, false);        // [1,1,0,1,0,1,0,0]
```

+   `reset()` 以将整个集合或单个位更改为 false：

```cpp
        b1.reset(2);             // [1,1,0,1,0,0,0,0]
```

要将位集转换为数值或字符串值，请使用以下方法：

+   `to_ulong()` 和 `to_ullong()` 以转换为`unsigned long`或`unsigned long long`：

```cpp
        std::bitset<8> bs{ 42 };
        auto n1 = bs.to_ulong();  // n1 = 42UL
        auto n2 = bs.to_ullong(); // n2 = 42ULL
```

+   `to_string()` 以转换为`std::basic_string`；默认情况下，结果是一个包含`'0'`和`'1'`的字符串，但您可以为这两个值指定不同的字符：

```cpp
        auto s1 = bs.to_string();         // s1 = "00101010"
        auto s2 = bs.to_string('o', 'x'); // s2 = "ooxoxoxo"
```

# 工作原理...

如果您曾经使用过 C 或类似 C 的 API，那么您可能写过或至少看过操作位来定义样式、选项或其他类型值的代码。这通常涉及操作，例如：

+   定义位标志；这些可以是枚举、类中的静态常量，或者是 C 风格中使用`#define`引入的宏。通常，有一个表示无值的标志（样式、选项等）。由于这些被认为是位标志，它们的值是 2 的幂。

+   从集合（即数值）中添加和移除标志。使用位或运算符（`value |= FLAG`）添加位标志，使用位与运算符和取反的标志（`value &= ~FLAG`）来移除位标志。

+   测试标志是否已添加到集合中（`value & FLAG == FLAG`）。

+   调用带有标志作为参数的函数。

以下是一个简单的示例，显示了定义控件边框样式的标志，该控件可以在左侧、右侧、顶部或底部有边框，或者包括这些任意组合，甚至没有边框：

```cpp
    #define BORDER_NONE   0x00
    #define BORDER_LEFT   0x01
    #define BORDER_TOP    0x02
    #define BORDER_RIGHT  0x04
    #define BORDER_BOTTOM 0x08

    void apply_style(unsigned int const style)
    {
      if (style & BORDER_BOTTOM) { /* do something */ }
    }

    // initialize with no flags
    unsigned int style = BORDER_NONE;
    // set a flag
    style = BORDER_BOTTOM;
    // add more flags
    style |= BORDER_LEFT | BORDER_RIGHT | BORDER_TOP;
    // remove some flags
    style &= ~BORDER_LEFT;
    style &= ~BORDER_RIGHT;
    // test if a flag is set
    if ((style & BORDER_BOTTOM) == BORDER_BOTTOM) {}
    // pass the flags as argument to a function
    apply_style(style);
```

标准的`std::bitset`类旨在作为 C++中使用位集的 C 风格工作方式的替代方案。它使我们能够编写更健壮和更安全的代码，因为它通过成员函数抽象了位操作，尽管我们仍然需要确定集合中的每个位表示什么：

+   使用`set()`和`reset()`方法来添加和移除标志，这些方法将位的值设置为 1 或 0（或`true`和`false`）；或者，我们可以使用索引运算符来达到相同的目的。

+   使用`test()`方法来测试位是否被设置。

+   通过构造函数从整数或字符串进行转换，通过成员函数将值转换为整数或字符串，以便可以在期望整数的地方使用 bitset 的值（例如作为函数的参数）。

除了上述操作，`bitset`类还有其他用于执行位操作、移位、测试等的附加方法，这些方法在前一节中已经展示过。

从概念上讲，`std::bitset`是一个表示数值的类，它使您能够访问和修改单个位。然而，在内部，bitset 具有一个整数值数组，它执行位操作。bitset 的大小不限于数值类型的大小；它可以是任何大小，只要它是一个编译时常量。

前一节中的控制边框样式示例可以以以下方式使用`std::bitset`来编写：

```cpp
    struct border_flags
    {
      static const int left = 0;
      static const int top = 1;
      static const int right = 2;
      static const int bottom = 3;
    };

    // initialize with no flags
    std::bitset<4> style;
    // set a flag
    style.set(border_flags::bottom);
    // set more flags
    style
      .set(border_flags::left)
      .set(border_flags::top)
      .set(border_flags::right);
    // remove some flags
    style[border_flags::left] = 0;
    style.reset(border_flags::right);
    // test if a flag is set
    if (style.test(border_flags::bottom)) {}
    // pass the flags as argument to a function
    apply_style(style.to_ulong());
```

# 还有更多...

bitset 可以从整数创建，并可以使用`to_ulong()`或`to_ullong()`方法将其值转换为整数。但是，如果 bitset 的大小大于这些数值类型的大小，并且请求的数值类型大小之外的任何位被设置为`1`，那么这些方法会抛出`std::overflow_error`异常，因为该值无法表示为`unsigned long`或`unsigned long long`。为了提取所有位，我们需要执行以下操作，如下面的代码所示：

+   清除超出`unsigned long`或`unsigned long long`大小的位。

+   将值转换为`unsigned long`或`unsigned long long`。

+   将位集向左移动`unsigned long`或`unsigned long long`位数。

+   一直执行此操作，直到检索到所有位。

```cpp
    template <size_t N>
    std::vector<unsigned long> bitset_to_vectorulong(std::bitset<N> bs)
    {
      auto result = std::vector<unsigned long> {};
      auto const size = 8 * sizeof(unsigned long);
      auto const mask = std::bitset<N>{ static_cast<unsigned long>(-1)};

      auto totalbits = 0;
      while (totalbits < N)
      {
        auto value = (bs & mask).to_ulong();
        result.push_back(value);
        bs >>= size;
        totalbits += size;
      }

      return result;
    }

    std::bitset<128> bs =
           (std::bitset<128>(0xFEDC) << 96) |
           (std::bitset<128>(0xBA98) << 64) |
           (std::bitset<128>(0x7654) << 32) |
           std::bitset<128>(0x3210);

    std::cout << bs << std::endl;

    auto result = bitset_to_vectorulong(bs);
    for (auto const v : result) 
      std::cout << std::hex << v << std::endl;
```

对于无法在编译时知道 bitset 大小的情况，替代方案是`std::vector<bool>`，我们将在下一个示例中介绍。

# 另请参阅

+   *使用`vector<bool>`来表示可变大小的位序列*

# 使用`vector<bool>`来表示可变大小的位序列

在前面的示例中，我们看到了如何使用`std::bitset`来表示固定大小的位序列。然而，有时`std::bitset`不是一个好选择，因为在编译时你不知道位的数量，只是定义一个足够大的位集也不是一个好主意，因为你可能会遇到实际上不够大的情况。这种情况的标准替代方案是使用`std::vector<bool>`容器，它是`std::vector`的一个特化，具有空间和速度优化，因为实现实际上不存储布尔值，而是为每个元素存储单独的位。

然而，因此，`std::vector<bool>`不符合标准容器或顺序容器的要求，`std::vector<bool>::iterator`也不符合前向迭代器的要求。因此，这种特化不能在期望向量的通用代码中使用。另一方面，作为一个向量，它具有与`std::bitset`不同的接口，并且不能被视为数字的二进制表示。没有直接的方法可以从数字或字符串构造`std::vector<bool>`，也不能将其转换为数字或字符串。

# 准备就绪...

本示例假设您熟悉`std::vector`和`std::bitset`。如果您没有阅读之前的示例，*将向量用作默认容器*和*使用 bitset 来表示固定大小的位序列*，请在继续之前阅读。

`vector<bool>`类在`<vector>`头文件中的`std`命名空间中可用。

# 如何做...

要操作`std::vector<bool>`，可以使用与`std::vector<T>`相同的方法，如下例所示：

+   创建一个空向量：

```cpp
        std::vector<bool> bv; // []
```

+   向向量中添加位：

```cpp
        bv.push_back(true);  // [1]
        bv.push_back(true);  // [1, 1]
        bv.push_back(false); // [1, 1, 0]
        bv.push_back(false); // [1, 1, 0, 0]
        bv.push_back(true);  // [1, 1, 0, 0, 1]
```

+   设置单个位的值：

```cpp
        bv[3] = true;        // [1, 1, 0, 1, 1]
```

+   使用通用算法：

```cpp
        auto count_of_ones = std::count(bv.cbegin(), bv.cend(), true);
```

+   从向量中删除位：

```cpp
        bv.erase(bv.begin() + 2); // [1, 1, 1, 1]
```

# 它是如何工作的...

`std::vector<bool>`不是标准向量，因为它旨在通过存储每个元素的单个位而不是布尔值来提供空间优化。因此，它的元素不是以连续序列存储的，也不能替代布尔数组。由于这个原因：

+   索引运算符不能返回对特定元素的引用，因为元素不是单独存储的：

```cpp
        std::vector<bool> bv;
        bv.resize(10);
        auto& bit = bv[0];      // error
```

+   出于前面提到的同样原因，解引用迭代器不能产生对`bool`的引用：

```cpp
        auto& bit = *bv.begin(); // error
```

+   不能保证单个位可以在不同线程中同时独立操作。

+   向量不能与需要前向迭代器的算法一起使用，比如`std::search()`。

+   如果这样的代码需要在列表中提到的任何操作，`std::vector<T>`无法满足预期，那么向量就不能在一些通用代码中使用。

`std::vector<bool>`的替代方案是`std::dequeu<bool>`，它是一个标准容器（双端队列），满足所有容器和迭代器的要求，并且可以与所有标准算法一起使用。然而，这不会像`std::vector<bool>`提供空间优化。

# 还有更多...

`std::vector<bool>`接口与`std::bitset`非常不同。如果想以类似的方式编写代码，可以创建一个在`std::vector<bool>`上的包装器，看起来像`std::bitset`。以下实现提供了类似于`std::bitset`中可用的成员：

```cpp
    class bitvector
    {
      std::vector<bool> bv;
    public:
      bitvector(std::vector<bool> const & bv) : bv(bv) {}
      bool operator[](size_t const i) { return bv[i]; }

      inline bool any() const {
        for (auto b : bv) if (b) return true;
          return false;
      }

      inline bool all() const {
        for (auto b : bv) if (!b) return false;
          return true;
      }

      inline bool none() const { return !any(); }

      inline size_t count() const {
        return std::count(bv.cbegin(), bv.cend(), true);
      }

      inline size_t size() const { return bv.size(); }

      inline bitvector & add(bool const value) {
        bv.push_back(value);
        return *this;
      }

      inline bitvector & remove(size_t const index) {
        if (index >= bv.size())
          throw std::out_of_range("Index out of range");
        bv.erase(bv.begin() + index);
        return *this;
      }

      inline bitvector & set(bool const value = true) {
        for (size_t i = 0; i < bv.size(); ++i)
          bv[i] = value;
        return *this;
      }

      inline bitvector& set(size_t const index, bool const value = true) {
        if (index >= bv.size())
          throw std::out_of_range("Index out of range");
        bv[index] = value;
        return *this;
      }

      inline bitvector & reset() {
        for (size_t i = 0; i < bv.size(); ++i) bv[i] = false;
        return *this;
      }

      inline bitvector & reset(size_t const index) {
        if (index >= bv.size())
          throw std::out_of_range("Index out of range");
        bv[index] = false;
        return *this;
      }

      inline bitvector & flip() {
        bv.flip();
        return *this;
      }

      std::vector<bool>& data() { return bv; }
    };
```

这只是一个基本的实现，如果要使用这样的包装器，应该添加额外的方法，比如位逻辑操作、移位、也许从流中读取和写入等等。然而，通过上述代码，我们可以写出以下例子：

```cpp
    bitvector bv;
    bv.add(true).add(true).add(false); // [1, 1, 0]
    bv.add(false);                     // [1, 1, 0, 0]
    bv.add(true);                      // [1, 1, 0, 0, 1]

    if (bv.any()) std::cout << "has some 1s" << std::endl;
    if (bv.all()) std::cout << "has only 1s" << std::endl;
    if (bv.none()) std::cout << "has no 1s" << std::endl;
    std::cout << "has " << bv.count() << " 1s" << std::endl;

    bv.set(2, true);                   // [1, 1, 1, 0, 1]
    bv.set();                          // [1, 1, 1, 1, 1]

    bv.reset(0);                       // [0, 1, 1, 1, 1]
    bv.reset();                        // [0, 0, 0, 0, 0]

    bv.flip();                         // [1, 1, 1, 1, 1]
```

# 另请参阅

+   *将向量用作默认容器*

+   *使用 bitset 来表示固定大小的位序列*

# 在范围内查找元素

在任何应用程序中，我们经常做的最常见的操作之一就是搜索数据。因此，标准库提供了许多用于搜索标准容器或任何可以表示范围并由开始和结束迭代器定义的东西的通用算法，这并不奇怪。在这个示例中，我们将看到这些标准算法是什么，以及它们如何使用。

# 准备工作

在这个示例中的所有示例中，我们将使用`std::vector`，但所有算法都适用于由开始和结束迭代器定义的范围，无论是输入迭代器还是前向迭代器，具体取决于算法（有关各种类型迭代器的更多信息，请参阅示例*编写自己的随机访问迭代器*）。所有这些算法都在`<algorithm>`头文件中的`std`命名空间中可用。

# 如何做...

以下是可以用于在范围中查找元素的算法列表：

+   使用`std::find()`来在范围中查找值；这个算法返回一个迭代器，指向第一个等于该值的元素：

```cpp
        std::vector<int> v{ 1, 1, 2, 3, 5, 8, 13 };

        auto it = std::find(v.cbegin(), v.cend(), 3);
        if (it != v.cend()) std::cout << *it << std::endl;
```

+   使用`std::find_if()`来查找范围中满足一元谓词条件的值；这个算法返回一个迭代器，指向谓词返回`true`的第一个元素：

```cpp
        std::vector<int> v{ 1, 1, 2, 3, 5, 8, 13 };

        auto it = std::find_if(v.cbegin(), v.cend(), 
                               [](int const n) {return n > 10; });
        if (it != v.cend()) std::cout << *it << std::endl;
```

+   使用`std::find_if_not()`来查找范围中不满足一元谓词的条件的值；这个算法返回一个迭代器，指向谓词返回`false`的第一个元素：

```cpp
        std::vector<int> v{ 1, 1, 2, 3, 5, 8, 13 };

        auto it = std::find_if_not(v.cbegin(), v.cend(), 
                            [](int const n) {return n % 2 == 1; });
        if (it != v.cend()) std::cout << *it << std::endl;
```

+   使用`std::find_first_of()`在另一个范围中搜索来自另一个范围的任何值的出现；这个算法返回一个迭代器，指向找到的第一个元素：

```cpp
        std::vector<int> v{ 1, 1, 2, 3, 5, 8, 13 };
        std::vector<int> p{ 5, 7, 11 };

        auto it = std::find_first_of(v.cbegin(), v.cend(),
                                     p.cbegin(), p.cend());
        if (it != v.cend()) 
          std::cout << "found " << *it
                    << " at index " << std::distance(v.cbegin(), it)
                    << std::endl;
```

+   使用`std::find_end()`来查找范围中元素子范围的最后出现；这个算法返回一个迭代器，指向范围中最后一个子范围的第一个元素：

```cpp
        std::vector<int> v1{ 1, 1, 0, 0, 1, 0, 1, 0, 1, 0, 1, 1 };
        std::vector<int> v2{ 1, 0, 1 };

        auto it = std::find_end(v1.cbegin(), v1.cend(),
                                v2.cbegin(), v2.cend());
        if (it != v1.cend())
          std::cout << "found at index "
                    << std::distance(v1.cbegin(), it) << std::endl;
```

+   使用`std::search()`来查找范围中子范围的第一个出现；这个算法返回一个迭代器，指向范围中子范围的第一个元素：

```cpp
        auto text = "The quick brown fox jumps over the lazy dog"s;
        auto word = "over"s;

        auto it = std::search(text.cbegin(), text.cend(),
                              word.cbegin(), word.cend());

        if (it != text.cend())
          std::cout << "found " << word
                    << " at index " 
                    << std::distance(text.cbegin(), it) << std::endl;
```

+   使用带有*searcher*的`std::search()`，*searcher*是实现搜索算法并满足一些预定义标准的类。这个重载的`std::search()`是在 C++17 中引入的，可用的标准 searchers 实现了*Boyer-Moore*和*Boyer-Moore-Horspool*字符串搜索算法：

```cpp
        auto text = "The quick brown fox jumps over the lazy dog"s;
        auto word = "over"s;

        auto it = std::search(
          text.cbegin(), text.cend(),
          std::make_boyer_moore_searcher(word.cbegin(), word.cend()));

        if (it != text.cend())
          std::cout << "found " << word
                    << " at index " 
                    << std::distance(text.cbegin(), it) << std::endl;
```

+   使用`std::search_n()`来在范围中搜索值的*N*个连续出现；这个算法返回一个迭代器，指向范围中找到的序列的第一个元素：

```cpp
        std::vector<int> v{ 1, 1, 0, 0, 1, 0, 1, 0, 1, 0, 1, 1 };

        auto it = std::search_n(v.cbegin(), v.cend(), 2, 0);
        if (it != v.cend())
          std::cout << "found at index " 
                    << std::distance(v.cbegin(), it) << std::endl;
```

+   使用`std::adjacent_find()`来查找范围中相邻的两个元素，它们相等或满足二元谓词；这个算法返回一个迭代器，指向找到的第一个元素：

```cpp
        std::vector<int> v{ 1, 1, 2, 3, 5, 8, 13 };

        auto it = std::adjacent_find(v.cbegin(), v.cend());
        if (it != v.cend())
          std::cout << "found at index " 
                    << std::distance(v.cbegin(), it) << std::endl;

       auto it = std::adjacent_find(
         v.cbegin(), v.cend(),
         [](int const a, int const b) {
           return IsPrime(a) && IsPrime(b); });

        if (it != v.cend())
          std::cout << "found at index " 
                    << std::distance(v.cbegin(), it) << std::endl;
```

+   使用`std::binary_search()`来查找排序范围中是否存在元素；这个算法返回一个布尔值，指示是否找到了该值：

```cpp
        std::vector<int> v{ 1, 1, 2, 3, 5, 8, 13 };

        auto success = std::binary_search(v.cbegin(), v.cend(), 8);
        if (success) std::cout << "found" << std::endl;
```

+   使用`std::lower_bound()`来查找范围中第一个不小于指定值的元素；这个算法返回一个指向元素的迭代器：

```cpp
        std::vector<int> v{ 1, 1, 2, 3, 5, 8, 13 };

        auto it = std::lower_bound(v.cbegin(), v.cend(), 1);
        if (it != v.cend())
          std::cout << "lower bound at "
                    << std::distance(v.cbegin(), it) << std::endl;
```

+   使用`std::upper_bound()`来查找范围中大于指定值的第一个元素；这个算法返回一个指向元素的迭代器：

```cpp
        std::vector<int> v{ 1, 1, 2, 3, 5, 8, 13 };

        auto it = std::upper_bound(v.cbegin(), v.cend(), 1);
        if (it != v.cend())
          std::cout << "upper bound at "
                    << std::distance(v.cbegin(), it) << std::endl;
```

+   使用`std::equal_range()`来查找范围中值等于指定值的子范围。这个算法返回一对迭代器，定义了子范围的第一个和结束迭代器；这两个迭代器等同于`std::lower_bound()`和`std::upper_bound()`返回的迭代器：

```cpp
        std::vector<int> v{ 1, 1, 2, 3, 5, 8, 13 };

        auto bounds = std::equal_range(v.cbegin(), v.cend(), 1);
        std::cout << "range between indexes "
                  << std::distance(v.cbegin(), bounds.first)
                  << " and "
                  << std::distance(v.cbegin(), bounds.second)
                  << std::endl;
```

# 工作原理...

这些算法的工作方式非常相似：它们都以定义可搜索范围的迭代器和依赖于每个算法的其他参数作为参数。除了`std::search()`返回一个布尔值，`std::equal_range()`返回一对迭代器之外，它们都返回指向搜索元素或子范围的迭代器。这些迭代器必须与范围的结束迭代器（即最后一个元素之后的位置）进行比较，以检查搜索是否成功。如果搜索没有找到元素或子范围，则返回值是结束迭代器。

所有这些算法都有多个重载，但在*如何做...*部分，我们只看了一个特定的重载，以展示如何使用该算法。要获取所有重载的完整参考，请参阅其他来源。

在所有前面的示例中，我们使用了常量迭代器，但是所有这些算法都可以使用可变迭代器和反向迭代器。因为它们以迭代器作为输入参数，所以它们可以使用标准容器、类 C 数组或任何表示序列并具有迭代器的东西。

有必要特别注意`std::binary_search()`算法：定义要搜索的范围的迭代器参数至少应满足前向迭代器的要求。无论提供的迭代器的类型如何，比较的次数始终与范围的大小的对数成正比。但是，如果迭代器是随机访问的，则迭代器的增量数量是不同的，在这种情况下，增量的数量也是对数的，或者不是随机访问的，这种情况下，它是线性的，并且与范围的大小成正比。

除了`std::find_if_not()`之外，所有这些算法在 C++11 之前就已经存在。但是，它们的一些重载已经在更新的标准中引入。例如，`std::search()`在 C++17 中引入了几个重载。其中一个重载的形式如下：

```cpp
    template<class ForwardIterator, class Searcher>
    ForwardIterator search(ForwardIterator first, ForwardIterator last,
                           const Searcher& searcher );
```

此重载搜索由搜索器函数对象定义的模式的出现，标准提供了几种实现：

+   `default_searcher` 基本上将搜索委托给标准的`std::search()`算法。

+   `boyer_moore_searcher` 实现了 Boyer-Moore 算法用于字符串搜索。

+   `boyer_moore_horspool_algorithm` 实现了 Boyer-Moore-Horspool 算法用于字符串搜索。

# 还有更多...

许多标准容器都有一个成员函数`find()`，用于在容器中查找元素。当这样的方法可用且符合您的需求时，应优先使用这些成员函数，因为这些成员函数是根据每个容器的特点进行了优化。

# 另请参阅

+   *使用向量作为默认容器*

+   *初始化范围*

+   *在范围上使用集合操作*

+   *对范围进行排序*

# 对范围进行排序

在前面的食谱中，我们看了搜索范围的标准通用算法。我们经常需要做的另一个常见操作是对范围进行排序，因为许多例程，包括一些搜索算法，都需要排序的范围。标准库提供了几个用于对范围进行排序的通用算法，在本食谱中，我们将看到这些算法是什么，以及它们如何使用。

# 准备工作

排序通用算法使用由开始和结束迭代器定义的范围，并且可以对标准容器、类 C 数组或任何表示序列并具有随机迭代器的东西进行排序。但是，本食谱中的所有示例都将使用`std::vector`。

# 如何做...

以下是搜索范围的标准通用算法列表：

+   使用`std::sort()`对范围进行排序：

```cpp
        std::vector<int> v{3, 13, 5, 8, 1, 2, 1};

        std::sort(v.begin(), v.end());
        // v = {1, 1, 2, 3, 5, 8, 13}

        std::sort(v.begin(), v.end(), std::greater<>());
        // v = {13, 8, 5, 3, 2, 1 ,1}
```

+   使用`std::stable_sort()`对范围进行排序，但保持相等元素的顺序：

```cpp
        struct Task
        {
          int priority;
          std::string name;
        };

        bool operator<(Task const & lhs, Task const & rhs) {
          return lhs.priority < rhs.priority;
        }

        bool operator>(Task const & lhs, Task const & rhs) {
          return lhs.priority > rhs.priority;
        }

        std::vector<Task> v{ 
          { 10, "Task 1"s }, { 40, "Task 2"s }, { 25, "Task 3"s },
          { 10, "Task 4"s }, { 80, "Task 5"s }, { 10, "Task 6"s },
        };

        std::stable_sort(v.begin(), v.end());
        // {{ 10, "Task 1" },{ 10, "Task 4" },{ 10, "Task 6" },
        //  { 25, "Task 3" },{ 40, "Task 2" },{ 80, "Task 5" }}

        std::stable_sort(v.begin(), v.end(), std::greater<>());
        // {{ 80, "Task 5" },{ 40, "Task 2" },{ 25, "Task 3" },
        //  { 10, "Task 1" },{ 10, "Task 4" },{ 10, "Task 6" }}
```

+   使用`std::partial_sort()`对范围的一部分进行排序（并使其余部分处于未指定的顺序）：

```cpp
        std::vector<int> v{ 3, 13, 5, 8, 1, 2, 1 };

        std::partial_sort(v.begin(), v.begin() + 4, v.end());
        // v = {1, 1, 2, 3, ?, ?, ?}

        std::partial_sort(v.begin(), v.begin() + 4, v.end(),
                          std::greater<>());
        // v = {13, 8, 5, 3, ?, ?, ?}
```

+   使用`std::partial_sort_copy()`对范围的一部分进行排序，通过将已排序的元素复制到第二个范围并保持原始范围不变：

```cpp
        std::vector<int> v{ 3, 13, 5, 8, 1, 2, 1 };
        std::vector<int> vc(v.size());

        std::partial_sort_copy(v.begin(), v.end(), 
                               vc.begin(), vc.end());
        // v = {3, 13, 5, 8, 1, 2, 1}
        // vc = {1, 1, 2, 3, 5, 8, 13}

        std::partial_sort_copy(v.begin(), v.end(), 
                               vc.begin(), vc.end(), std::greater<>());
        // vc = {13, 8, 5, 3, 2, 1, 1}
```

+   使用`std::nth_element()`对范围进行排序，使得第*N*个元素是如果范围完全排序时将在该位置的元素，并且它之前的元素都更小，之后的元素都更大，没有任何保证它们也是有序的：

```cpp
        std::vector<int> v{ 3, 13, 5, 8, 1, 2, 1 };

        std::nth_element(v.begin(), v.begin() + 3, v.end());
        // v = {1, 1, 2, 3, 5, 8, 13}

        std::nth_element(v.begin(), v.begin() + 3, v.end(),
                         std::greater<>());
        // v = {13, 8, 5, 3, 2, 1, 1}
```

+   使用`std::is_sorted()`来检查一个范围是否已排序：

```cpp
        std::vector<int> v { 1, 1, 2, 3, 5, 8, 13 };

        auto sorted = std::is_sorted(v.cbegin(), v.cend());
        sorted = std::is_sorted(v.cbegin(), v.cend(), 
                                std::greater<>());
```

+   使用`std::is_sorted_until()`来从范围的开头找到一个已排序的子范围：

```cpp
        std::vector<int> v{ 3, 13, 5, 8, 1, 2, 1 };

        auto it = std::is_sorted_until(v.cbegin(), v.cend());
        auto length = std::distance(v.cbegin(), it);
```

# 它是如何工作的...

所有前面的一般算法都接受随机迭代器作为参数来定义要排序的范围，并且其中一些还额外接受一个输出范围。它们都有重载，一个需要比较函数来对元素进行排序，另一个不需要，并使用`operator<`来比较元素。

这些算法的工作方式如下：

+   +   `std::sort()`修改输入范围，使其元素根据默认或指定的比较函数进行排序；排序的实际算法是一个实现细节。

+   `std::stable_sort()`类似于`std::sort()`，但它保证保留相等元素的原始顺序。

+   `std::partial_sort()`接受三个迭代器参数，表示范围中的第一个、中间和最后一个元素，其中中间可以是任何元素，而不仅仅是自然中间位置的元素。结果是一个部分排序的范围，使得原始范围的前`middle - first`个最小元素，即`[first, last)`，在`[first, middle)`子范围中找到，其余元素以未指定的顺序在`[middle, last)`子范围中。

+   `std::partial_sort_copy()`不是`std::partial_copy()`的变体，正如名称可能暗示的那样，而是`std::sort()`的变体。它对范围进行排序，而不改变它，通过将其元素复制到输出范围。算法的参数是输入范围和输出范围的第一个和最后一个迭代器。如果输出范围的大小*M*大于或等于输入范围的大小*N*，则输入范围完全排序并复制到输出范围；输出范围的前*N*个元素被覆盖，最后*M-N*个元素保持不变。如果输出范围小于输入范围，则只有输入范围中的前*M*个排序元素被复制到输出范围（在这种情况下，输出范围完全被覆盖）。

+   `std::nth_element()`基本上是选择算法的实现，这是一种用于找到范围中第*N*个最小元素的算法。该算法接受三个迭代器参数，表示范围的第一个、第*N*个和最后一个元素，并部分排序范围，以便在排序后，第*N*个元素是如果范围已完全排序时将在该位置的元素。在修改后的范围中，第*n*个元素之前的所有*N-1*个元素都小于它，第*n*个元素之后的所有元素都大于它。但是，这些其他元素的顺序没有保证。

+   `std::is_sorted()`检查指定范围是否根据指定或默认的比较函数进行排序，并返回一个布尔值来指示。

+   `std::is_sorted_until()`找到指定范围的已排序子范围，从开头开始，使用提供的比较函数或默认的`operator<`。返回的值是表示已排序子范围的上界的迭代器，也是最后一个已排序元素的迭代器。

# 还有更多...

一些标准容器，如`std::list`和`std::forward_list`，提供了一个成员函数`sort()`，该函数针对这些容器进行了优化。应优先使用这些成员函数，而不是一般的标准算法`std::sort()`。

# 另请参阅

+   *使用 vector 作为默认容器*

+   *初始化一个范围*

+   *在范围上使用集合操作*

+   *在范围内查找元素*

# 初始化范围

在之前的示例中，我们探索了用于在范围内搜索和对范围进行排序的一般标准算法。算法库提供了许多其他一般算法，其中包括用于填充范围值的几个算法。在本示例中，您将了解这些算法是什么以及应该如何使用它们。

# 准备工作

本示例中的所有示例都使用`std::vector`。但是，像所有一般算法一样，我们将在本示例中看到的算法使用迭代器来定义范围的边界，因此可以与任何标准容器、类似 C 的数组或定义了前向迭代器的表示序列的自定义类型一起使用。

除了`std::iota()`，它在`<numeric>`头文件中可用，所有其他算法都在`<algorithm>`头文件中找到。

# 操作步骤...

要为范围分配值，请使用以下任何标准算法：

+   `std::fill()` 用于为范围内的所有元素分配一个值；范围由第一个和最后一个前向迭代器定义：

```cpp
        std::vector<int> v(5);
        std::fill(v.begin(), v.end(), 42);
        // v = {42, 42, 42, 42, 42}
```

+   `std::fill_n()` 用于为范围内的多个元素分配值；范围由第一个前向迭代器和一个计数器定义，该计数器指示应分配指定值的元素数量：

```cpp
        std::vector<int> v(10);
        std::fill_n(v.begin(), 5, 42);
        // v = {42, 42, 42, 42, 42, 0, 0, 0, 0, 0}
```

+   `std::generate()` 用于将函数返回的值分配给范围内的元素；范围由第一个和最后一个前向迭代器定义，并且该函数为范围内的每个元素调用一次：

```cpp
        std::random_device rd{};
        std::mt19937 mt{ rd() };
        std::uniform_int_distribution<> ud{1, 10};
        std::vector<int> v(5);
        std::generate(v.begin(), v.end(), 
                      [&ud, &mt] {return ud(mt); }); 
```

+   `std::generate_n()` 用于将函数返回的值分配给范围内的多个元素；范围由第一个前向迭代器和一个计数器定义，该计数器指示应为每个元素调用一次的函数分配值：

```cpp
        std::vector<int> v(5);
        auto i = 1;
        std::generate_n(v.begin(), v.size(), [&i] { return i*i++; });
        // v = {1, 4, 9, 16, 25}
```

+   `std::iota()` 用于为范围内的元素分配顺序递增的值；范围由第一个和最后一个前向迭代器定义，并且使用从指定初始值开始的前缀`operator++`递增值：

```cpp
        std::vector<int> v(5);
        std::iota(v.begin(), v.end(), 1);
        // v = {1, 2, 3, 4, 5}
```

# 工作原理...

`std::fill()` 和 `std::fill_n()` 的工作方式类似，但在指定范围的方式上有所不同：前者由第一个和最后一个迭代器指定，后者由第一个迭代器和计数指定。第二个算法返回一个迭代器，如果计数大于零，则表示代表最后一个分配的元素，否则表示范围的第一个元素的迭代器。

`std::generate()` 和 `std::generate_n()` 也类似，只是在指定范围的方式上有所不同。第一个使用两个迭代器定义范围的下限和上限，第二个使用第一个元素的迭代器和计数。与`std::fill_n()`一样，`std::generate_n()`也返回一个迭代器，如果计数大于零，则表示代表最后一个分配的元素，否则表示范围的第一个元素的迭代器。这些算法为范围内的每个元素调用指定的函数，并将返回的值分配给元素。生成函数不接受任何参数，因此不能将参数的值传递给函数，因为这是用于初始化范围元素的函数。如果需要使用元素的值来生成新值，则应使用`std::transform()`。

`std::iota()` 的名称取自 APL 编程语言中的 ι (iota) 函数，尽管它是最初的 STL 的一部分，但它仅在 C++11 中的标准库中包含。此函数接受范围的第一个和最后一个迭代器以及分配给范围的第一个元素的初始值，然后使用前缀`operator++`为范围中的其余元素生成顺序递增的值。

# 另请参阅

+   *使用向量作为默认容器*

+   *对范围进行排序*

+   *在范围上使用集合操作*

+   *在范围内查找元素*

+   *生成伪随机数* 第九章的示例，*使用数字和字符串*

+   *初始化伪随机数生成器的内部状态的所有位* 第九章的示例，*使用数字和字符串*

# 在范围上使用集合操作

标准库提供了几种用于集合操作的算法，使我们能够对排序范围进行并集、交集或差异操作。在本示例中，我们将看到这些算法是什么以及它们是如何工作的。

# 准备工作

集合操作的算法使用迭代器，这意味着它们可以用于标准容器、类似 C 的数组或任何表示具有输入迭代器的序列的自定义类型。本示例中的所有示例都将使用`std::vector`。

对于下一节中的所有示例，我们将使用以下范围：

```cpp
    std::vector<int> v1{ 1, 2, 3, 4, 4, 5 };
    std::vector<int> v2{ 2, 3, 3, 4, 6, 8 };
    std::vector<int> v3;
```

# 操作步骤...

使用以下通用算法进行集合操作：

+   `std::set_union()`计算两个范围的并集并将结果存储到第三个范围中：

```cpp
        std::set_union(v1.cbegin(), v1.cend(),
                       v2.cbegin(), v2.cend(),
                       std::back_inserter(v3));
        // v3 = {1, 2, 3, 3, 4, 4, 5, 6, 8}
```

+   `std::merge()`将两个范围的内容合并到第三个范围中；这类似于`std::set_union()`，不同之处在于它将输入范围的整个内容复制到输出范围中，而不仅仅是它们的并集：

```cpp
        std::merge(v1.cbegin(), v1.cend(),
                   v2.cbegin(), v2.cend(),
                   std::back_inserter(v3));
        // v3 = {1, 2, 2, 3, 3, 3, 4, 4, 4, 5, 6, 8}
```

+   `std::set_intersection()`计算两个范围的交集并将结果存储到第三个范围中：

```cpp
        std::set_intersection(v1.cbegin(), v1.cend(),
                              v2.cbegin(), v2.cend(),
                              std::back_inserter(v3));
        // v3 = {2, 3, 4}
```

+   `std::set_difference()`计算两个范围的差异并将结果存储到第三个范围中；输出范围将包含来自第一个范围的元素，这些元素在第二个范围中不存在：

```cpp
        std::set_difference(v1.cbegin(), v1.cend(),
                            v2.cbegin(), v2.cend(),
                            std::back_inserter(v3));
        // v3 = {1, 4, 5}
```

+   `std::set_symmetric_difference()`计算两个范围的对称差并将结果存储到第三个范围中；输出范围将包含存在于任一输入范围中但仅存在于一个输入范围中的元素：

```cpp
        std::set_symmetric_difference(v1.cbegin(), v1.cend(),
                                      v2.cbegin(), v2.cend(),
                                      std::back_inserter(v3));
        // v3 = {1, 3, 4, 5, 6, 8}
```

+   `std::includes()`用于检查一个范围是否是另一个范围的子集（即，它的所有元素也存在于另一个范围中）：

```cpp
        std::vector<int> v1{ 1, 2, 3, 4, 4, 5 };
        std::vector<int> v2{ 2, 3, 3, 4, 6, 8 };
        std::vector<int> v3{ 1, 2, 4 };
        std::vector<int> v4{ };

        auto i1 = std::includes(v1.cbegin(), v1.cend(), 
                                v2.cbegin(), v2.cend()); // i1 = false
        auto i2 = std::includes(v1.cbegin(), v1.cend(), 
                                v3.cbegin(), v3.cend()); // i2 = true
        auto i3 = std::includes(v1.cbegin(), v1.cend(), 
                                v4.cbegin(), v4.cend()); // i3 = true
```

# 工作原理...

所有从两个输入范围产生新范围的集合操作实际上具有相同的接口，并且以类似的方式工作：

+   它们接受两个输入范围，每个范围由第一个和最后一个输入迭代器定义。

+   它们接受一个输出迭代器，指向将插入元素的输出范围。

+   它们有一个重载，接受一个额外的参数，表示必须返回`true`的比较二进制函数对象，如果第一个参数小于第二个参数。当未指定比较函数对象时，将使用`operator<`。

+   它们返回一个指向构造的输出范围结尾的迭代器。

+   输入范围必须使用`operator<`或提供的比较函数进行排序，具体取决于所使用的重载。

+   输出范围不得与两个输入范围重叠。

我们将使用 POD 类型`Task`的向量进行额外示例，这与我们之前使用的类型相同：

```cpp
    struct Task
    {
      int priority;
      std::string name;
    };

    bool operator<(Task const & lhs, Task const & rhs) {
      return lhs.priority < rhs.priority;
    } 

    bool operator>(Task const & lhs, Task const & rhs) {
      return lhs.priority > rhs.priority;
    }

    std::vector<Task> v1{
      { 10, "Task 1.1"s },
      { 20, "Task 1.2"s },
      { 20, "Task 1.3"s },
      { 20, "Task 1.4"s },
      { 30, "Task 1.5"s },
      { 50, "Task 1.6"s },
    };

    std::vector<Task> v2{
      { 20, "Task 2.1"s },
      { 30, "Task 2.2"s },
      { 30, "Task 2.3"s },
      { 30, "Task 2.4"s },
      { 40, "Task 2.5"s },
      { 50, "Task 2.6"s },
    };
```

每个算法产生输出范围的特定方式在此处描述：

+   `std::set_union()`将输入范围中存在的所有元素复制到输出范围，生成一个新的排序范围。如果一个元素在第一个范围中出现*M*次，在第二个范围中出现*N*次，那么第一个范围中的所有*M*个元素将按其现有顺序复制到输出范围中，然后如果*N > M*，则从第二个范围中复制* N-M *个元素到输出范围中，否则为 0 个元素：

```cpp
        std::vector<Task> v3;
        std::set_union(v1.cbegin(), v1.cend(),
                       v2.cbegin(), v2.cend(),
                       std::back_inserter(v3));
        // v3 = {{10, "Task 1.1"},{20, "Task 1.2"},{20, "Task 1.3"},
        //       {20, "Task 1.4"},{30, "Task 1.5"},{30, "Task 2.3"},
        //       {30, "Task 2.4"},{40, "Task 2.5"},{50, "Task 1.6"}}
```

+   `std::merge()`将两个输入范围中的所有元素复制到输出范围中，生成一个新的排序范围，其排序方式与比较函数有关：

```cpp
        std::vector<Task> v4;
        std::merge(v1.cbegin(), v1.cend(),
                   v2.cbegin(), v2.cend(),
                   std::back_inserter(v4));
        // v4 = {{10, "Task 1.1"},{20, "Task 1.2"},{20, "Task 1.3"},
        //       {20, "Task 1.4"},{20, "Task 2.1"},{30, "Task 1.5"},
        //       {30, "Task 2.2"},{30, "Task 2.3"},{30, "Task 2.4"},
        //       {40, "Task 2.5"},{50, "Task 1.6"},{50, "Task 2.6"}}
```

+   `std::set_intersection()`将在两个输入范围中找到的所有元素复制到输出范围中，生成一个新的排序范围，其排序方式与比较函数有关：

```cpp
        std::vector<Task> v5;
        std::set_intersection(v1.cbegin(), v1.cend(),
                              v2.cbegin(), v2.cend(),
                              std::back_inserter(v5));
        // v5 = {{20, "Task 1.2"},{30, "Task 1.5"},{50, "Task 1.6"}}
```

+   `std::set_difference()`将第一个输入范围中所有未在第二个输入范围中找到的元素复制到输出范围。对于在两个范围中找到的等效元素，适用以下规则：如果一个元素在第一个范围中出现*M*次，在第二个范围中出现*N*次，如果*M > N*，则复制*M-N*次；否则不复制：

```cpp
        std::vector<Task> v6;
        std::set_difference(v1.cbegin(), v1.cend(),
                            v2.cbegin(), v2.cend(),
                            std::back_inserter(v6));
        // v6 = {{10, "Task 1.1"},{20, "Task 1.3"},{20, "Task 1.4"}}
```

+   `std::set_symmetric_difference()`将在两个输入范围中找到的元素中不在两者中都找到的元素复制到输出范围。如果一个元素在第一个范围中出现*M*次，在第二个范围中出现*N*次，则如果*M > N*，则将第一个范围中的最后*M-N*个元素复制到输出范围中，否则将第二个范围中的最后*N-M*个元素复制到输出范围中：

```cpp
        std::vector<Task> v7;
        std::set_symmetric_difference(v1.cbegin(), v1.cend(),
                                      v2.cbegin(), v2.cend(),
                                      std::back_inserter(v7));
        // v7 = {{10, "Task 1.1"},{20, "Task 1.3"},{20, "Task 1.4"}
        //       {30, "Task 2.3"},{30, "Task 2.4"},{40, "Task 2.5"}}
```

另一方面，`std::includes()`不会产生输出范围；它只检查第二个范围是否包含在第一个范围中。如果第二个范围为空或其所有元素都包含在第一个范围中，则返回`true`；否则返回`false`。它还有两个重载，其中一个指定比较二进制函数对象。

# 另请参阅

+   *将向量用作默认容器*

+   *对范围进行排序*

+   *初始化范围*

+   *使用迭代器在容器中插入新元素*

+   *在范围中查找元素*

# 使用迭代器在容器中插入新元素

在使用容器时，通常有必要在开头、结尾或中间某处插入新元素。有一些算法，比如我们在前面的食谱中看到的那些*在范围上使用集合操作*，需要一个范围的迭代器来插入，但如果你简单地传递一个迭代器，比如`begin()`返回的迭代器，它不会插入，而是覆盖容器的元素。此外，使用`end()`返回的迭代器无法在末尾插入。为了执行这样的操作，标准库提供了一组迭代器和迭代器适配器，使这些情况成为可能。

# 准备就绪

本食谱中讨论的迭代器和适配器在`<iterator>`头文件中的`std`命名空间中可用。如果包括诸如`<algorithm>`之类的头文件，则不必显式包括`<iterator>`。

# 如何做到...

使用以下迭代器适配器在容器中插入新元素：

+   `std::back_inserter()`用于在末尾插入元素，适用于具有`push_back()`方法的容器：

```cpp
        std::vector<int> v{ 1,2,3,4,5 };
        std::fill_n(std::back_inserter(v), 3, 0);
        // v={1,2,3,4,5,0,0,0}
```

+   `std::front_inserter()`用于在开头插入元素，适用于具有`push_front()`方法的容器：

```cpp
        std::list<int> l{ 1,2,3,4,5 };
        std::fill_n(std::front_inserter(l), 3, 0);
        // l={0,0,0,1,2,3,4,5}
```

+   `std::inserter()`用于在容器中的任何位置插入，适用于具有`insert()`方法的容器：

```cpp
        std::vector<int> v{ 1,2,3,4,5 };
        std::fill_n(std::inserter(v, v.begin()), 3, 0);
        // v={0,0,0,1,2,3,4,5}

        std::list<int> l{ 1,2,3,4,5 };
        auto it = l.begin();
        std::advance(it, 3);
        std::fill_n(std::inserter(l, it), 3, 0);
        // l={1,2,3,0,0,0,4,5}
```

# 工作原理...

`std::back_inserter()`、`std::front_inserter()`和`std::inserter()`都是创建类型为`std::back_insert_iterator`、`std::front_insert_iterator`和`std::insert_iterator`的迭代器适配器的辅助函数。这些都是输出迭代器，用于向它们构造的容器追加、前置或插入。增加和取消引用这些迭代器不会做任何事情。但是，在赋值时，这些迭代器调用容器的以下方法：

+   `std::back_insterter_iterator`调用`push_back()`

+   `std::front_inserter_iterator`调用`push_front()`

+   `std::insert_iterator`调用`insert()`

以下是`std::back_inserter_iterator`的过度简化实现：

```cpp
    template<class C>
    class back_insert_iterator {
    public:
      typedef back_insert_iterator<C> T;
      typedef typename C::value_type V;

      explicit back_insert_iterator( C& c ) :container( &c ) { }

      T& operator=( const V& val ) { 
        container->push_back( val );
        return *this;
      }

      T& operator*() { return *this; }

      T& operator++() { return *this; }

      T& operator++( int ) { return *this; }
      protected:
      C* container;
    };
```

由于赋值运算符的工作方式，这些迭代器只能与一些标准容器一起使用：

+   `std::back_insert_iterator`可以与`std::vector`、`std::list`、`std::deque`和`std::basic_string`一起使用。

+   `std::front_insert_iterator`可与`std::list`、`std::forward_list`和`std:deque`一起使用。

+   `std::insert_iterator`可以与所有标准容器一起使用。

以下示例在`std::vector`的开头插入了三个值为 0 的元素：

```cpp
    std::vector<int> v{ 1,2,3,4,5 };
    std::fill_n(std::inserter(v, v.begin()), 3, 0);
    // v={0,0,0,1,2,3,4,5}
```

`std::inserter()`适配器接受两个参数：容器和元素应该插入的迭代器。在容器上调用`insert()`时，`std::insert_iterator`会增加迭代器，因此在再次分配时，它可以在下一个位置插入一个新元素。以下是为这个迭代器适配器实现的赋值运算符：

```cpp
    T& operator=(const V& v)
    {  
      iter = container->insert(iter, v);
      ++iter;
      return (*this);
    }
```

# 还有更多...

这些迭代器适配器旨在与将多个元素插入范围的算法或函数一起使用。当然，它们也可以用于插入单个元素，但在这种情况下，只需调用`push_back()`、`push_front()`或`insert()`就更简单和直观了。应避免以下示例：

```cpp
    std::vector<int> v{ 1,2,3,4,5 };
    *std::back_inserter(v) = 6; // v = {1,2,3,4,5,6}

    std::back_insert_iterator<std::vector<int>> it(v);
    *it = 7;                    // v = {1,2,3,4,5,6,7}
```

# 另请参阅

+   *在范围上使用集合操作*

# 编写自己的随机访问迭代器

在第八章中，*学习现代核心语言特性*，我们看到了如何通过实现迭代器和自由的`begin()`和`end()`函数来启用自定义类型的范围-based for 循环，以返回自定义范围的第一个和最后一个元素的迭代器。您可能已经注意到，在该示例中提供的最小迭代器实现不符合标准迭代器的要求，因为它不能被复制构造或分配，也不能被递增。在这个示例中，我们将建立在这个示例的基础上，展示如何创建一个满足所有要求的随机访问迭代器。

# 准备工作

对于这个示例，您应该了解标准定义的迭代器类型及其不同之处。它们的要求的很好的概述可以在[`www.cplusplus.com/reference/iterator/`](http://www.cplusplus.com/reference/iterator/)上找到。

为了举例说明如何编写随机访问迭代器，我们将考虑在第八章的*为自定义类型启用基于范围的 for 循环*示例中使用的`dummy_array`类的变体，这是一个非常简单的数组概念，除了作为演示迭代器的代码库之外，没有实际价值：

```cpp
    template <typename Type, size_t const SIZE>
    class dummy_array
    {
      Type data[SIZE] = {};
    public:
      Type& operator[](size_t const index)
      {
        if (index < SIZE) return data[index];
        throw std::out_of_range("index out of range");
      }

     Type const & operator[](size_t const index) const
     {
       if (index < SIZE) return data[index];
       throw std::out_of_range("index out of range");
     }

      size_t size() const { return SIZE; }
    };
```

下一节中显示的所有代码，迭代器类、`typedef`和`begin()`和`end()`函数，都将成为这个类的一部分。

# 如何做...

为了为前面部分显示的`dummy_array`类提供可变和常量随机访问迭代器，将以下成员添加到类中：

+   迭代器类模板，它是用元素的类型和数组的大小参数化的。该类必须有以下公共的`typedef`，定义标准的同义词：

```cpp
        template <typename T, size_t const Size>
        class dummy_array_iterator
        {
        public:
          typedef dummy_array_iterator            self_type;
          typedef T                               value_type;
          typedef T&                              reference;
          typedef T*                              pointer;
          typedef std::random_access_iterator_tag iterator_category;
          typedef ptrdiff_t                       difference_type;
        };
```

+   迭代器类的私有成员：指向数组数据的指针和数组中的当前索引：

```cpp
        private:
           pointer ptr = nullptr;
           size_t index = 0;
```

+   迭代器类的私有方法，用于检查两个迭代器实例是否指向相同的数组数据：

```cpp
        private:
          bool compatible(self_type const & other) const
          {
            return ptr == other.ptr;
          }
```

+   迭代器类的显式构造函数：

```cpp
        public:
           explicit dummy_array_iterator(pointer ptr, 
                                         size_t const index) 
             : ptr(ptr), index(index) { }
```

+   迭代器类成员以满足所有迭代器的通用要求：可复制构造，可复制分配，可销毁，前缀和后缀可递增。在这个实现中，后递增运算符是根据前递增运算符实现的，以避免代码重复：

```cpp
        dummy_array_iterator(dummy_array_iterator const & o) 
           = default;
        dummy_array_iterator& operator=(dummy_array_iterator const & o) 
           = default;
        ~dummy_array_iterator() = default;

        self_type & operator++ ()
        {
           if (index >= Size) 
             throw std::out_of_range("Iterator cannot be incremented past 
                                      the end of range.");
          ++index;
          return *this;
        }

        self_type operator++ (int)
        {
          self_type tmp = *this;
          ++*this;
          return tmp;
        }
```

+   迭代器类成员以满足输入迭代器要求：测试相等/不相等，作为右值解引用：

```cpp
        bool operator== (self_type const & other) const
        {
          assert(compatible(other));
          return index == other.index;
        }

        bool operator!= (self_type const & other) const
        {
          return !(*this == other);
        }

        reference operator* () const
        {
          if (ptr == nullptr)
            throw std::bad_function_call();
          return *(ptr + index);
        }

        reference operator-> () const
        {
          if (ptr == nullptr)
            throw std::bad_function_call();
          return *(ptr + index);
        }
```

+   迭代器类成员以满足前向迭代器要求：默认可构造：

```cpp
        dummy_array_iterator() = default;
```

+   迭代器类成员以满足双向迭代器要求：可递减：

```cpp
        self_type & operator--()
        {
          if (index <= 0) 
            throw std::out_of_range("Iterator cannot be decremented 
                                     past the end of range.");
          --index;
          return *this;
        }

        self_type operator--(int)
        {
          self_type tmp = *this;
          --*this;
          return tmp;
        }
```

+   迭代器类成员以满足随机访问迭代器要求：算术加和减，与其他迭代器不相等的可比性，复合赋值，和偏移解引用：

```cpp
        self_type operator+(difference_type offset) const
        {
          self_type tmp = *this;
          return tmp += offset;
        }

        self_type operator-(difference_type offset) const
        {
          self_type tmp = *this;
          return tmp -= offset;
        }

        difference_type operator-(self_type const & other) const
        {
          assert(compatible(other));
          return (index - other.index);
        }

        bool operator<(self_type const & other) const
        {
          assert(compatible(other));
          return index < other.index;
        }

        bool operator>(self_type const & other) const
        {
          return other < *this;
        }

        bool operator<=(self_type const & other) const
        {
          return !(other < *this);
        }

        bool operator>=(self_type const & other) const
        {
          return !(*this < other);
        }

        self_type & operator+=(difference_type const offset)
        {
          if (index + offset < 0 || index + offset > Size)
            throw std::out_of_range("Iterator cannot be incremented 
                                     past the end of range.");
          index += offset;
          return *this;
        }

        self_type & operator-=(difference_type const offset)
        {
          return *this += -offset;
        }

        value_type & operator[](difference_type const offset)
        {
          return (*(*this + offset));
        }

        value_type const & operator[](difference_type const offset) const
        {
          return (*(*this + offset));
        }
```

+   为`dummy_array`类添加可变和常量迭代器的`typedef`：

```cpp
        public:
           typedef dummy_array_iterator<Type, SIZE> 
                   iterator;
           typedef dummy_array_iterator<Type const, SIZE> 
                   constant_iterator;
```

+   添加公共的`begin()`和`end()`函数到`dummy_array`类中，以返回数组中第一个和最后一个元素的迭代器：

```cpp
        iterator begin() 
        {
          return iterator(data, 0);
        }

        iterator end()
        {
          return iterator(data, SIZE);
        }

        constant_iterator begin() const
        {
          return constant_iterator(data, 0);
        }

        constant_iterator end() const
        {
          return constant_iterator(data, SIZE);
        }
```

# 它是如何工作的...

标准库定义了五种迭代器类别：

+   *输入迭代器*：这是最简单的类别，仅保证单遍历顺序算法的有效性。增加后，之前的副本可能会变得无效。

+   *输出迭代器*：这些基本上是可以用来写入指定元素的输入迭代器。

+   *前向迭代器*：这些可以读取（和写入）指定元素的数据。它们满足输入迭代器的要求，并且此外，必须支持默认构造，并且必须支持多遍历场景而不使之前的副本无效。

+   *双向迭代器*：这些是前向迭代器，此外，还支持递减，因此可以向两个方向移动。

+   *随机访问迭代器*：这些支持在常数时间内访问容器中的任何元素。它们实现了双向迭代器的所有要求，并且还支持算术运算`+`和`-`，复合赋值`+=`和`-=`，与其他迭代器的比较`<`，`<=`，`>`，`>=`，以及偏移解引用运算符。

还实现了输出迭代器要求的前向、双向和随机访问迭代器称为*可变迭代器*。

在前一节中，我们看到了如何实现随机访问迭代器，逐步介绍了每个迭代器类别的要求（因为每个迭代器类别包括前一个迭代器类别的要求并添加新的要求）。迭代器类模板对于常量和可变迭代器是通用的，我们定义了两个同义词，称为`iterator`和`constant_iterator`。

在实现内部迭代器类模板之后，我们还定义了`begin()`和`end()`成员函数，返回数组中第一个和最后一个元素的迭代器。这些方法有重载，根据`dummy_array`类实例是可变的还是常量的，返回可变或常量迭代器。

有了`dummy_array`类及其迭代器的这种实现，我们可以编写以下示例。有关更多示例，请查看本书附带的源代码：

```cpp
    dummy_array<int, 3> a;
    a[0] = 10;
    a[1] = 20;
    a[2] = 30;

    std::transform(a.begin(), a.end(), a.begin(), 
                   [](int const e) {return e * 2; });

    for (auto&& e : a) std::cout << e << std::endl;

    auto lp = [](dummy_array<int, 3> const & ca)
    {
      for (auto const & e : ca) 
        std::cout << e << std::endl;
    };

    lp(a);

    dummy_array<std::unique_ptr<Tag>, 3> ta;
    ta[0] = std::make_unique<Tag>(1, "Tag 1");
    ta[1] = std::make_unique<Tag>(2, "Tag 2");
    ta[2] = std::make_unique<Tag>(3, "Tag 3");

    for (auto it = ta.begin(); it != ta.end(); ++it)
      std::cout << it->id << " " << it->name << std::endl;
```

# 还有更多...

除了`begin()`和`end()`之外，容器可能还有其他方法，例如`cbegin()`/`cend()`（用于常量迭代器），`rbegin()`/`rend()`（用于可变反向迭代器），以及`crbegin()`/`crend()`（用于常量反向迭代器）。实现这一点留作练习给你。

另一方面，在现代 C++中，返回第一个和最后一个迭代器的这些函数不必是成员函数，而可以作为非成员函数提供。实际上，这是下一个配方的主题，*使用非成员函数访问容器*。

# 另请参阅

+   第八章的*学习现代核心语言特性*配方中的为自定义类型启用基于范围的 for 循环

+   第八章的*学习现代核心语言特性*配方中的创建类型别名和别名模板

# 使用非成员函数访问容器

标准容器提供了`begin()`和`end()`成员函数，用于检索容器的第一个和最后一个元素的迭代器。实际上有四组这样的函数。除了`begin()`/`end()`，容器还提供了`cbegin()`/`cend()`来返回常量迭代器，`rbegin()`/`rend()`来返回可变的反向迭代器，以及`crbegin()`/`crend()`来返回常量反向迭代器。在 C++11/C++14 中，所有这些都有非成员等价物，可以与标准容器、类 C 数组和任何专门化它们的自定义类型一起使用。在 C++17 中，甚至添加了更多的非成员函数；`std::data()`--返回指向包含容器元素的内存块的指针，`std::size()`--返回容器或数组的大小，`std::empty()`--返回给定容器是否为空。这些非成员函数用于通用代码，但可以在代码的任何地方使用。

# 准备工作

在这个配方中，我们将以我们在上一个配方中实现的`dummy_array`类及其迭代器为例。在继续本配方之前，您应该先阅读那个配方。

非成员`begin()`/`end()`函数和其他变体，以及非成员`data()`、`size()`和`empty()`在`std`命名空间中的`<iterator>`头文件中可用，该头文件隐式地包含在以下任何一个头文件中：`<array>`、`<deque>`、`<forward_list>`、`<list>`、`<map>`、`<regex>`、`<set>`、`<string>`、`<unordered_map>`、`<unordered_set>`和`<vector>`。

在这个配方中，我们将提到`std::begin()`/`std::end()`函数，但讨论的一切也适用于其他函数：`std::cbegin()`/`std::cend()`、`std::rbegin()`/`std::rend()`和`std::crbegin()`/`std::crend()`。

# 如何做...

使用非成员`std::begin()`/`std::end()`函数和其他变体，以及`std::data()`、`std::size()`和`std::empty()`与：

+   标准容器：

```cpp
        std::vector<int> v1{ 1, 2, 3, 4, 5 };
        auto sv1 = std::size(v1);  // sv1 = 5
        auto ev1 = std::empty(v1); // ev1 = false
        auto dv1 = std::data(v1);  // dv1 = v1.data()
        for (auto i = std::begin(v1); i != std::end(v1); ++i)
          std::cout << *i << std::endl;

        std::vector<int> v2;
        std::copy(std::cbegin(v1), std::cend(v1),
                  std::back_inserter(v2));
```

+   （类似 C 的）数组：

```cpp
        int a[5] = { 1, 2, 3, 4, 5 };
        auto pos = std::find_if(std::crbegin(a), std::crend(a), 
                                [](int const n) {return n % 2 == 0; });
        auto sa = std::size(a);  // sa = 5
        auto ea = std::empty(a); // ea = false
        auto da = std::data(a);  // da = a
```

+   提供相应成员函数`begin()`/`end()`、`data()`、`empty()`或`size()`的自定义类型：

```cpp
        dummy_array<std::string, 5> sa;
        dummy_array<int, 5> sb;
        sa[0] = "1"s;
        sa[1] = "2"s;
        sa[2] = "3"s;
        sa[3] = "4"s;
        sa[4] = "5"s;

        std::transform(
          std::begin(sa), std::end(sa), 
          std::begin(sb), 
          [](std::string const & s) {return std::stoi(s); });
        // sb = [1, 2, 3, 4, 5]

        auto sa_size = std::size(sa); // sa_size = 5
```

+   类型未知的通用代码：

```cpp
        template <typename F, typename C>
        void process(F&& f, C const & c)
        {
          std::for_each(std::begin(c), std::end(c), 
                        std::forward<F>(f));
        }

        auto l = [](auto const e) {std::cout << e << std::endl; };

        process(l, v1); // std::vector<int>
        process(l, a);  // int[5]
        process(l, sa); // dummy_array<std::string, 5>
```

# 工作原理...

这些非成员函数是在不同版本的标准中引入的，但它们在 C++17 中都被修改为返回`constexpr auto`：

+   C++11 中的`std::begin()`和`std::end()`

+   `std::cbegin()`/`std::cend()`，`std::rbegin()`/`std::rend()`和`std::crbegin()`/`std::crend()`在 C++14 中

+   C++17 中的`std::data()`、`std::size()`和`std::empty()`

`begin()`/`end()`函数族有容器类和数组的重载，它们所做的只是：

+   返回调用容器对应成员函数的结果。

+   返回数组的第一个或最后一个元素的指针。

`std::begin()`/`std::end()`的实际典型实现如下：

```cpp
    template<class C>
    constexpr auto inline begin(C& c) -> decltype(c.begin())
    {
      return c.begin();
    }
    template<class C>
    constexpr auto inline end(C& c) -> decltype(c.end())
    {
      return c.end();
    }

    template<class T, std::size_t N>
    constexpr T* inline begin(T (&array)[N])
    {
      return array;
    }

    template<class T, std::size_t N>
    constexpr T* inline begin(T (&array)[N])
    {
      return array+N;
    }
```

可以为没有相应的`begin()`/`end()`成员但仍可迭代的容器提供自定义专门化。标准库实际上为`std::initializer_list`和`std::valarray`提供了这样的专门化。

必须在定义原始类或函数模板的相同命名空间中定义专门化。因此，如果要专门化任何`std::begin()`/`std::end()`对，必须在`std`命名空间中执行。

C++17 中引入的用于容器访问的其他非成员函数也有几个重载：

+   `std::data()`有几个重载；对于类`C`，它返回`c.data()`，对于数组，它返回数组，对于`std::initializer_list<T>`，它返回`il.begin()`。

```cpp
        template <class C> 
        constexpr auto data(C& c) -> decltype(c.data())
        {
          return c.data();
        }

        template <class C> 
        constexpr auto data(const C& c) -> decltype(c.data())
        {
          return c.data();
        }

        template <class T, std::size_t N>
        constexpr T* data(T (&array)[N]) noexcept
        {
          return array;
        }

        template <class E> 
        constexpr const E* data(std::initializer_list<E> il) noexcept
        {
          return il.begin();
        }
```

+   `std::size()`有两个重载；对于类`C`，它返回`c.size()`，对于数组，它返回大小`N`。

```cpp
        template <class C> 
        constexpr auto size(const C& c) -> decltype(c.size())
        {
          return c.size();
        }

        template <class T, std::size_t N>
        constexpr std::size_t size(const T (&array)[N]) noexcept
        {
          return N;
        }
```

+   `std::empty()` 有几种重载形式；对于类 `C`，它返回 `c.empty()`，对于数组它返回 `false`，对于 `std::initializer_list<T>` 它返回 `il.size() == 0`。

```cpp
        template <class C> 
        constexpr auto empty(const C& c) -> decltype(c.empty())
        {
          return c.empty();
        }

        template <class T, std::size_t N> 
        constexpr bool empty(const T (&array)[N]) noexcept
        {
          return false;
        }

        template <class E> 
        constexpr bool empty(std::initializer_list<E> il) noexcept
        {
          return il.size() == 0;
        }
```

# 还有更多...

这些非成员函数主要用于模板代码，其中容器类型未知，可以是标准容器、类似 C 的数组或自定义类型。使用这些函数的非成员版本使我们能够编写更简单、更少的代码，可以处理所有这些类型的容器。

然而，使用这些函数并不应该局限于通用代码。虽然这更多是个人偏好的问题，但保持一致并在代码中的任何地方使用它们可能是一个好习惯。所有这些方法都有轻量级的实现，很可能会被编译器内联，这意味着与使用相应的成员函数相比，不会有任何额外开销。

# 另请参阅

+   *编写自己的随机访问迭代器*
