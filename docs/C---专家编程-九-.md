# C++ 专家编程（九）

> 原文：[`annas-archive.org/md5/57ea316395e58ce0beb229274ec493fc`](https://annas-archive.org/md5/57ea316395e58ce0beb229274ec493fc)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第二十七章：字符串、流类和正则表达式

我们将在本章中涵盖以下内容：

+   创建、连接和转换字符串

+   从字符串的开头和结尾修剪空白

+   在不构造`std::string`对象的情况下获得`std::string`的舒适性

+   从用户输入中读取值

+   计算文件中的所有单词

+   使用 I/O 流操纵器格式化输出

+   从文件输入初始化复杂对象

+   从`std::istream`迭代器填充容器

+   使用`std::ostream`迭代器进行通用打印

+   将输出重定向到特定代码段的文件

+   通过继承`std::char_traits`创建自定义字符串类

+   使用正则表达式库对输入进行标记化

+   在不同上下文中舒适地漂亮地打印数字

+   从`std::iostream`错误中捕获可读的异常

# 介绍

本章专门讨论任意数据的字符串处理、解析和打印。对于这样的工作，STL 提供了其*I/O 流库*。该库基本上由以下类组成，每个类都用灰色框表示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/11e3bdf6-16ba-4b13-a4f1-07d22b52f7b8.png)

箭头显示了类的继承结构。这一开始可能看起来很压抑，但在本章中我们将使用大多数这些类，并逐个熟悉它们。当查看 C++ STL 文档中的这些类时，我们将无法直接找到它们的*确切*名称。这是因为图表中的名称是我们作为应用程序员看到的，但它们实际上大多只是带有`basic_`类名前缀的类的 typedef（例如，我们将更容易地在 STL 文档中搜索`basic_istream`而不是`istream`）。`basic_*` I/O 流类是可以为不同字符类型进行特化的模板。图表中的类是针对`char`值进行特化的。我们将在整本书中使用这些特化。如果我们在这些类名前加上`w`字符，我们会得到`wistream`，`wostream`等等--这些是`wchar_t`的特化 typedef，而不是`char`，例如。

在图表的顶部，我们看到`std::ios_base`。我们基本上永远不会直接使用它，但它被列出是为了完整性，因为所有其他类都继承自它。下一个特化是`std::ios`，它体现了维护数据流的对象的概念，可以处于*良好*状态、运行*空*数据状态（EOF）或某种*失败*状态。

我们将实际使用的第一个特化是`std::istream`和`std::ostream`。`"i"`和`"o"`前缀代表输入和输出。我们在 C++编程的最早期就已经见过它们，以最简单的形式出现在`std::cout`和`std::cin`（但也有`std::cerr`）的对象中。这些是这些类的实例，它们始终全局可用。我们通过`ostream`进行数据输出，通过`istream`进行输入。

同时继承自`istream`和`ostream`的类是`iostream`。它结合了输入和输出功能。当我们了解到来自`istream`，`ostream`和`iostream`三者组成的所有类可以如何使用时，我们基本上已经准备好立即使用所有接下来的类了：

`ifstream`，`ofstream`和`fstream`分别继承自`istream`，`ostream`和`iostream`，但它们提升了它们的能力，以重定向 I/O 从计算机的*文件系统*到文件。

`istringstream`，`ostringstream`和`iostringstream`的工作方式非常类似。它们帮助在内存中构建字符串，并/或从中消耗数据。

# 创建、连接和转换字符串

即使是非常古老的 C++程序员也会知道`std::string`。在 C 中，特别是在解析、连接、复制字符串等方面，字符串处理是繁琐且痛苦的，而`std::string`在简单性和安全性方面确实是一大进步。

由于 C++11，当我们想要将所有权转移到其他函数或数据结构时，我们甚至不需要再复制字符串，因为我们可以*移动*它们。这样，在大多数情况下，几乎没有太多的开销。

`std::string`在过去几个标准增量中有一些新功能。C++17 中完全新的是`std::string_view`。我们将稍微玩弄一下两者（但还有另一个配方，更集中于`std::string_view`的特性），以便对它们有所了解，并了解它们在 C++17 时代的工作方式。

# 如何做到...

在本节中，我们将创建字符串和字符串视图，并对它们进行基本的连接和转换：

1.  像往常一样，我们首先包括头文件并声明我们使用`std`命名空间：

```cpp
      #include <iostream>
      #include <string>
      #include <string_view>
      #include <sstream>
      #include <algorithm>      

      using namespace std;
```

1.  首先让我们创建字符串对象。最明显的方法是实例化一个`string`类的对象`a`。我们通过给构造函数传递一个 C 风格的字符串来控制它的内容（在编译后作为包含字符的静态数组嵌入到二进制文件中）。构造函数将复制它并将其作为字符串对象`a`的内容。或者，我们可以使用字符串字面量操作符`""s`来初始化它，而不是从 C 风格字符串初始化它。它可以即时创建一个字符串对象。使用它来构造对象`b`，我们甚至可以使用自动类型推断：

```cpp
      int main()
      {
          string a { "a"  };
          auto   b ( "b"s );
```

1.  我们刚刚创建的字符串是将它们的输入从构造函数参数复制到它们自己的缓冲区中。为了不复制，而是*引用*底层字符串，我们可以使用`string_view`实例。这个类也有一个字面操作符，称为`""sv`：

```cpp
          string_view c { "c"   };
          auto        d ( "d"sv );
```

1.  好的，现在让我们玩一下我们的字符串和字符串视图。对于这两种类型，`std::ostream`类都有`operator<<`的重载，因此它们可以轻松地打印出来：

```cpp
          cout << a << ", " << b << 'n';
          cout << c << ", " << d << 'n';
```

1.  字符串类重载了`operator+`，所以我们可以*添加*两个字符串并得到它们的连接作为结果。这样，`"a" + "b"`的结果是`"ab"`。以这种方式连接`a`和`b`很容易。对于`a`和`c`，情况就不那么容易了，因为 c 不是一个`string`，而是一个`string_view`。我们首先必须从`c`中获取字符串，然后将其添加到`a`中。此时，有人可能会问，“等等，为什么你要将`c`复制到一个中间字符串对象中，然后再将其添加到`a`中？你不能通过使用`c.data()`来避免那个复制吗？”这是一个好主意，但它有一个缺陷--`string_view`实例不一定要携带零终止的字符串。这是一个可能导致缓冲区溢出的问题：

```cpp
          cout << a + b << 'n';
          cout << a + string{c} << 'n';
```

1.  让我们创建一个新的字符串，其中包含我们刚刚创建的所有字符串和字符串视图。通过使用`std::ostringstream`，我们可以将任何变量*打印*到一个行为完全像`std::cout`的流对象中，但它不会打印到 shell。相反，它会打印到*字符串缓冲区*中。在我们使用`operator<<`将所有变量流到一起并在它们之间使用一些分隔空间后，我们可以从中构造并打印一个新的字符串对象`o.str()`：

```cpp
          ostringstream o;

          o << a << " " << b << " " << c << " " << d;
          auto concatenated (o.str());
          cout << concatenated << 'n';
```

1.  现在我们还可以通过将所有字母转换为大写来转换这个新字符串，例如。C 库函数`toupper`，它将小写字符映射为大写字符并保持其他字符不变，已经可用，并且可以与`std::transform`结合使用，因为字符串基本上也是一个具有`char`项的可迭代容器对象：

```cpp
          transform(begin(concatenated), end(concatenated), 
                    begin(concatenated), ::toupper);
          cout << concatenated << 'n';
      }
```

1.  编译和运行程序会产生以下输出，这正是我们所期望的：

```cpp
      $ ./creating_strings 
      a, b
      c, d
      ab
      ac
      a b c d
      A B C D
```

# 它是如何工作的...

显然，字符串可以像数字一样使用`+`运算符进行相加，但这与数学无关，而是产生*连接*的字符串。为了将其与`string_view`混合使用，我们需要首先转换为`std::string`。

然而，非常重要的一点是，当在代码中混合字符串和字符串视图时，我们绝不能假设`string_view`背后的基础字符串是*零终止*的！这就是为什么我们宁愿写`"abc"s + string{some_string_view}`而不是`"abc"s + some_string_view.data()`。除此之外，`std::string`提供了一个成员函数`append`，可以处理`string_view`实例，但它会改变字符串，而不是返回一个新的带有字符串视图内容的字符串。

`std::string_view`很有用，但在与字符串和字符串函数混合使用时要小心。我们不能假设它们是以零结尾的，这在标准字符串环境中会很快出问题。幸运的是，通常有适当的函数重载，可以正确处理它们。

然而，如果我们想要进行复杂的字符串连接和格式化等操作，我们不应该逐个在字符串实例上执行。`std::stringstream`、`std::ostringstream`和`std::istringstream`类更适合这样做，因为它们在附加时增强了内存管理，并提供了我们从一般流中了解的所有格式化功能。在本节中，我们选择了`std::ostringstream`类，因为我们要创建一个字符串而不是解析它。`std::istringstream`实例可以从现有字符串实例中实例化，然后我们可以轻松地将其解析为其他类型的变量。如果我们想要结合两者，`std::stringstream`是完美的全能选手。

# 修剪字符串开头和结尾的空格。

特别是在从用户输入中获取字符串时，它们经常被不需要的空格污染。在另一个示例中，我们去除了单词之间出现的多余空格。

现在让我们看看被空格包围的字符串并去除它。`std::string`有一些很好的辅助函数可以完成这项工作。

阅读了这个使用普通字符串对象执行此操作的示例后，确保还阅读以下示例。在那里，我们将看到如何避免不必要的副本或数据修改，使用新的`std::string_view`类。

# 如何做...

在本节中，我们将编写一个辅助函数，用于识别字符串中的周围空格并返回一个不包含它的副本，然后我们将对其进行简要测试。

1.  和往常一样，首先是头文件包含和使用指令：

```cpp
      #include <iostream>
      #include <string>
      #include <algorithm>
      #include <cctype>

      using namespace std;
```

1.  我们的修剪字符串周围空格的函数接受一个现有字符串的常量引用。它将返回一个没有任何周围空格的新字符串：

```cpp
      string trim_whitespace_surrounding(const string &s)
      {
```

1.  `std::string`提供了两个很有用的函数，这些函数对我们非常有帮助。第一个是`string::find_first_not_of`，它接受一个包含我们要跳过的所有字符的字符串。这当然是空格，意味着空格字符 `' '`, 制表符 `'t'` 和换行符 `'n'`。它会返回第一个非空格字符的位置。如果字符串中只有空格，它会返回`string::npos`。这意味着如果我们从中修剪空格，只剩下一个空字符串。因此，在这种情况下，让我们返回一个空字符串：

```cpp
          const char whitespace[] {" tn"};
          const size_t first (s.find_first_not_of(whitespace));
          if (string::npos == first) { return {}; }
```

1.  我们现在知道新字符串应该从哪里开始，但我们还不知道它应该在哪里结束。因此，我们使用另一个方便的字符串函数`string::find_last_not_of`。它将返回字符串中最后一个非空白字符的位置：

```cpp
          const size_t last (s.find_last_not_of(whitespace));
```

1.  使用`string::substr`，我们现在可以返回由空格包围但不包含空格的字符串部分。这个函数接受两个参数--一个*位置*，表示从字符串的哪个位置开始，以及在这个位置之后的*字符数*：

```cpp
          return s.substr(first, (last - first + 1));
      }
```

1.  就是这样。让我们编写一个主函数，在其中创建一个字符串，用各种空格包围文本句子，以便对其进行修剪：

```cpp
      int main()
      {
          string s {" tn string surrounded by ugly"
                    " whitespace tn "};
```

1.  我们打印字符串的未修剪和修剪版本。通过用括号括起字符串，更容易看出修剪前它包含的空格：

```cpp
          cout << "{" << s << "}n";
          cout << "{" 
               << trim_whitespace_surrounding(s) 
               << "}n";
      }
```

1.  编译和运行程序会产生我们预期的输出：

```cpp
      $ ./trim_whitespace 
      {  
        string surrounded by ugly whitespace    
         }
      {string surrounded by ugly whitespace}
```

# 它是如何工作的...

在这一部分，我们使用了`string::find_first_not_of`和`string::find_last_not_of`。这两个函数都接受一个 C 风格的字符串，它作为一个应该在搜索不同字符时跳过的字符列表。如果我们有一个携带字符串`"foo bar"`的字符串实例，并且在它上调用`find_first_not_of("bfo ")`，它将返回值`5`，因为`'a'`字符是第一个不在`"bfo "`字符串中的字符。参数字符串中字符的顺序并不重要。

相同的函数也存在相反的逻辑，尽管我们在这个示例中没有使用它们：`string::find_first_of`和`string::find_last_of`。

与基于迭代器的函数类似，我们需要检查这些函数是否返回字符串中的实际位置，还是表示它们*没有*找到满足约束条件的字符位置的值。如果它们没有找到，它们会返回`string::npos`。

从我们的辅助函数中检索到的字符位置，我们建立了一个不包含周围空白的子字符串，使用`string::substring`。这个函数接受一个相对偏移和一个字符串长度，然后返回一个新的字符串实例，其中包含了那个子字符串。例如，`string{"abcdef"}.substr(2, 2)`将返回一个新的字符串`"cd"`。

# 获得 std::string 的便利性，而不需要构造 std::string 对象的成本

`std::string`类是一个非常有用的类，因为它极大地简化了处理字符串的过程。一个缺点是，如果我们想传递它的子字符串，我们需要传递一个指针和一个长度变量，两个迭代器，或者子字符串的副本。我们在上一个示例中做到了这一点，我们通过获取不包含周围空白的子字符串范围的副本来实现了这一点。

如果我们想要将字符串或子字符串传递给甚至不支持`std::string`的库，我们只能提供一个原始字符串指针，这有点令人失望，因为它让我们回到了旧的 C 语言时代。就像子字符串问题一样，原始指针并不携带有关字符串长度的信息。这样，一个人将不得不实现一个指针和字符串长度的捆绑。

以简化的方式来说，这正是`std::string_view`。它自 C++17 起可用，并提供了一种将指向某个字符串的指针与该字符串的大小配对的方法。它体现了为数据数组提供引用类型的想法。

如果我们设计的函数以前接受`std::string`实例作为参数，但没有改变它们以需要字符串实例重新分配保存实际字符串负载的内存的方式，我们现在可以使用`std::string_view`，并且更兼容于 STL-agnostic 的库。我们可以让其他库提供对其复杂字符串实现背后的负载字符串的`string_view`视图，然后在我们的 STL 代码中使用它。这样，`string_view`类就充当了一个最小且有用的接口，可以在不同的库之间共享。

另一个很酷的事情是，`string_view`可以被用作对更大的字符串对象的子字符串的非复制引用。有很多可以利用它的可能性。在这一部分，我们将使用`string_view`来玩耍，以便对其优势和劣势有所了解。我们还将看到如何通过调整字符串视图而不是修改或复制实际字符串来隐藏字符串的周围空白。这种方法避免了不必要的复制或数据修改。

# 如何做...

我们将实现一个依赖于一些`string_view`特性的函数，然后，我们将看到我们可以将多少不同类型的数据输入到其中：

1.  首先是头文件包含和使用指令：

```cpp
      #include <iostream>
      #include <string_view>

      using namespace std;
```

1.  我们实现了一个函数，它只接受一个`string_view`作为参数：

```cpp
      void print(string_view v)
      {
```

1.  在对输入字符串进行任何操作之前，我们去除任何前导和尾随空白。我们不会改变字符串，但是通过将其缩小到实际的非空白部分，*视图*会改变。`find_first_not_of`函数将找到字符串中第一个不是空格（`' '`）、制表符（`'t'`）和换行符（`'n'`）的字符。通过`remove_prefix`，我们将内部的`string_view`指针移动到第一个非空白字符。如果字符串只包含空白，`find_first_not_of`函数将返回值`npos`，即`size_type(-1)`。由于`size_type`是无符号变量，这将变成一个非常大的数字。因此，我们取两者中较小的一个：`words_begin`或字符串视图的大小：

```cpp
          const auto words_begin (v.find_first_not_of(" tn"));
          v.remove_prefix(min(words_begin, v.size()));
```

1.  我们对尾随空白做同样的处理。`remove_suffix`会缩小视图的大小变量：

```cpp
          const auto words_end (v.find_last_not_of(" tn"));
          if (words_end != string_view::npos) {
              v.remove_suffix(v.size() - words_end - 1);
          }
```

1.  现在我们可以打印字符串视图及其长度：

```cpp
          cout << "length: " << v.length()
               << " [" << v << "]n";
      }
```

1.  在我们的主函数中，我们通过使用完全不同的参数类型来玩弄新的`print`函数。首先，我们给它一个运行时的`char*`字符串，来自`argv`指针。在运行时，它包含了我们可执行文件的文件名。然后，我们给它一个空的`string_view`实例。然后，我们用 C 风格的静态字符字符串和`""sv`字面量来给它提供参数，这会在我们的程序中构造一个`string_view`。最后，我们给它一个`std::string`。好处是，为了调用`print`函数，这些参数都没有被修改或复制。没有堆分配发生。对于许多和/或大字符串，这是非常高效的。

```cpp
      int main(int argc, char *argv[])
      {
          print(argv[0]);
          print({});
          print("a const char * array");
          print("an std::string_view literal"sv);
          print("an std::string instance"s);
```

1.  我们没有测试去除空白的功能。所以，让我们给它一个有很多前导和尾随空白的字符串：

```cpp
          print(" tn foobar n t ");
```

1.  另一个很酷的功能是，`string_view`给我们访问的字符串不必是*零终止*的。如果我们构造一个字符串，比如`"abc"`，没有尾随零，`print`函数仍然可以安全地处理它，因为`string_view`也携带了它指向的字符串的大小：

```cpp
          char cstr[] {'a', 'b', 'c'};
          print(string_view(cstr, sizeof(cstr)));
      }
```

1.  编译和运行程序会产生以下输出。所有字符串都被正确处理。我们填充了大量前导和尾随空白的字符串被正确过滤，没有零终止的`abc`字符串也被正确打印，没有任何缓冲区溢出：

```cpp
      $ ./string_view 
      length: 17 [./string_view]
      length: 0 []
      length: 20 [a const char * array]
      length: 27 [an std::string_view literal]
      length: 23 [an std::string instance]
      length: 6 [foobar]
      length: 3 [abc]
```

# 它是如何工作的...

我们刚刚看到，我们可以调用接受`string_view`参数的函数，基本上可以使用任何类似字符串的东西，它以连续方式存储字符。在我们的`print`调用中，没有对基础字符串进行任何*复制*。 

有趣的是，在我们的`print(argv[0])`调用中，字符串视图自动确定了字符串长度，因为这是一个约定的零结尾字符串。反过来，不能假设可以通过计算直到达到零终止符为止的项目数来确定`string_view`实例的数据长度。因此，我们必须始终小心地处理`string_view::data()`指向的字符串视图数据的指针。通常的字符串函数大多假定零终止，因此，使用指向字符串视图有效载荷的原始指针可能会非常严重地缓冲区溢出。最好使用已经期望字符串视图的接口。

除此之外，我们已经从`std::string`中知道了很多豪华的接口。

使用`std::string_view`来传递字符串或子字符串，可以避免复制或堆分配，同时不失去字符串类的便利性。但要注意`std::string_view`放弃了字符串以零结尾的假设。

# 从用户输入读取值

这本书中的许多食谱都从输入源（如标准输入或文件）中读取数值，并对其进行处理。这次我们只关注读取，并学习更多关于错误处理的知识，如果从流中读取的内容出现问题，我们需要处理它，而不是终止整个程序。

在这个食谱中，我们只会从用户输入中读取，但一旦我们知道如何做到这一点，我们也知道如何从任何其他流中读取。用户输入是通过`std::cin`读取的，这本质上是一个输入流对象，就像`ifstream`和`istringstream`的实例一样。

# 如何做...

在本节中，我们将读取用户输入到不同的变量中，并看看如何处理错误，以及如何将输入复杂化为有用的块：

1.  这次我们只需要`iostream`。因此，让我们包含这个单一的头文件，并声明我们默认使用`std`命名空间：

```cpp
      #include <iostream>

      using namespace std;
```

1.  首先提示用户输入两个数字。我们将把它们解析成一个`int`和一个`double`变量。用户可以用空格分隔它们。例如，`1 2.3`是一个有效的输入：

```cpp
      int main()
      {
          cout << "Please Enter two numbers:n> ";
          int x;
          double y;
```

1.  解析和错误检查同时在`if`分支的条件部分完成。只有在两个数字都能解析出来时，它们对我们才有意义，我们才会打印它们：

```cpp
          if (cin >> x >> y) {
              cout << "You entered: " << x 
                   << " and " << y << 'n';
```

1.  如果由于任何原因解析失败，我们会告诉用户解析没有成功。`cin`流对象现在处于*失败状态*，直到我们再次清除失败状态之前，它不会给我们其他输入。为了能够解析新的输入，我们调用`cin.clear()`并丢弃到目前为止收到的所有输入。丢弃是用`cin.ignore`完成的，我们指定丢弃最大数量的字符，直到最终看到换行符，然后将其丢弃。之后的所有内容又变得有趣起来：

```cpp
          } else {
              cout << "Oh no, that did not go well!n";
              cin.clear();
              cin.ignore(
                  std::numeric_limits<std::streamsize>::max(),
                  'n');
          }
```

1.  现在让我们要求输入其他内容。我们让用户输入名字。由于名字可以由多个用空格分隔的单词组成，空格字符不再是一个好的分隔符。因此，我们使用`std::getline`，它接受一个流对象，比如`cin`，一个字符串引用，它将把输入复制到其中，以及一个分隔字符。让我们选择逗号（`,`）作为分隔字符。通过不仅仅使用`cin`，而是使用`cin >> ws`作为`getline`的流参数，我们可以使`cin`在任何名字之前丢弃任何前导空格。在每个循环步骤中，我们打印当前的名字，但如果一个名字是空的，我们就退出循环：

```cpp
          cout << "now please enter some "
                  "comma-separated names:n> ";

          for (string s; getline(cin >> ws, s, ',');) {
              if (s.empty()) { break; }
              cout << "name: "" << s << ""n";
          }
      }
```

1.  编译和运行程序会产生以下输出，假设我们只输入了有效的输入。数字是`"1 2"`，被正确解析，然后我们输入一些名字，它们也被正确列出。以两个连续逗号的形式输入空名字会退出循环：

```cpp
      $ ./strings_from_user_input 
      Please Enter two numbers:
      > 1 2
      You entered: 1 and 2
      now please enter some comma-separated names:
      > john doe,  ellen ripley,       alice,    chuck norris,,
      name: "john doe"
      name: "ellen ripley"
      name: "alice"
      name: "chuck norris"
```

1.  当再次运行程序时，在开始输入错误的数字时，我们看到程序正确地选择了另一个分支，丢弃了错误的输入，并正确地继续了名字的输入。尝试使用`cin.clear()`和`cin.ignore(...)`行，看看它们如何影响名字读取代码：

```cpp
      $ ./strings_from_user_input
      Please Enter two numbers:
      > a b
      Oh no, that did not go well!
      now please enter some comma-separated names:
      > bud spencer, terence hill,,
      name: "bud spencer"
      name: "terence hill"
```

# 工作原理...

在本节中，我们进行了一些复杂的输入检索。首先要注意的是，我们总是同时进行检索和错误检查。

表达式`cin >> x`的结果再次是对`cin`的引用。这样，我们可以写`cin >> x >> y >> z >> ...`。同时，它也可以在布尔上下文中转换为布尔值，比如`if`条件中。布尔值告诉我们最后一次读取是否成功。这就是为什么我们能够写`if (cin >> x >> y) {...}`。

例如，如果我们尝试读取一个整数，但输入包含`"foobar"`作为下一个标记，那么将其解析为整数是不可能的，流对象进入*失败状态*。这只对解析尝试很重要，但对整个程序并不重要。重置它然后尝试其他任何事情都是可以的。在我们的配方程序中，我们尝试在尝试读取两个数字失败后读取一系列名称。在尝试读取这些数字失败的情况下，我们使用`cin.clear()`将`cin`恢复到工作状态。但是，它的内部光标仍然停留在我们键入的内容而不是数字上。为了丢弃这个旧输入并清除名称输入的管道，我们使用了非常长的表达式`cin.ignore(std::numeric_limits<std::streamsize>::max(), 'n');`。这是必要的，因为我们想要从一个真正新鲜的缓冲区开始，当我们要求用户提供一系列名称时。

下面的循环一开始可能看起来很奇怪：

```cpp
for (string s; getline(cin >> ws, s, ',');) { ... }
```

在`for`循环的条件部分中，我们使用`getline`。`getline`函数接受一个输入流对象，一个字符串引用作为输出参数，以及一个分隔符字符。默认情况下，分隔符字符是换行符。在这里，我们将其定义为逗号（`,`）字符，因此列表中的所有名称，例如`"john, carl, frank"`，都将被单独读取。

到目前为止，一切都很好。但是将`cin >> ws`函数作为流对象提供是什么意思呢？这使得`cin`首先刷新所有空白字符，这些空白字符位于下一个非空白字符之前和最后一个逗号之后。回顾一下`"john, carl, frank"`的例子，我们将得到子字符串`"john"`，`" carl"`和`" frank"`，而不使用`ws`。注意`carl`和`frank`的不必要的前导空格字符？由于我们对输入流的`ws`预处理，这些实际上消失了。

# 在文件中计算所有单词

假设我们读取一个文本文件，并且想要计算文本中的单词数。我们定义一个单词是两个空格字符之间的字符范围。我们该如何做呢？

我们可以计算空格的数量，例如，因为单词之间必须有空格。在句子`"John has a funny little dog."`中，我们有五个空格字符，所以我们可以说有六个单词。

如果我们有一个带有空格噪音的句子，例如`" John has t anfunny little dog ."`？这个字符串中有太多不必要的空格，甚至不仅仅是空格。从本书的其他配方中，我们已经学会了如何去除这种多余的空格。因此，我们可以首先将字符串预处理为正常的句子形式，然后应用计算空格字符的策略。是的，这是可行的，但有一个*更*简单的方法。为什么我们不使用 STL 已经提供给我们的东西呢？

除了为这个问题找到一个优雅的解决方案之外，我们还将让用户选择是否从标准输入或文本文件中计算单词。

# 如何做...

在本节中，我们将编写一个一行函数，用于计算输入缓冲区中的单词，并让用户选择输入缓冲区的读取位置：

1.  首先让我们包括所有必要的头文件，并声明我们使用`std`命名空间：

```cpp
      #include <iostream>
      #include <fstream>
      #include <string>
      #include <algorithm>
      #include <iterator>      

      using namespace std;
```

1.  我们的`wordcount`函数接受一个输入流，例如`cin`。它创建一个`std::input_iterator`迭代器，该迭代器从流中标记字符串，然后将它们传递给`std::distance`。`distance`参数接受两个迭代器作为参数，并尝试确定从一个迭代器位置到另一个迭代器位置需要多少递增步骤。对于*随机访问*迭代器来说，这很简单，因为它们实现了数学差异操作（`operator-`）。这样的迭代器可以像指针一样相互减去。然而，`istream_iterator`是*前向*迭代器，必须一直前进直到等于结束迭代器。最终，所需的步骤数就是单词数：

```cpp
      template <typename T>
      size_t wordcount(T &is)
      {
          return distance(istream_iterator<string>{is}, {});
      }
```

1.  在我们的主函数中，我们让用户选择输入流是`std::cin`还是输入文件：

```cpp
      int main(int argc, char **argv)
      {
          size_t wc;
```

1.  如果用户在 shell 中与文件名一起启动程序（例如`$ ./count_all_words some_textfile.txt`），那么我们将从`argv`命令行参数数组中获取该文件名，并打开它，以便将新的输入文件流输入到`wordcount`中：

```cpp
          if (argc == 2) {
              ifstream ifs {argv[1]};
              wc = wordcount(ifs);
```

1.  如果用户在没有任何参数的情况下启动程序，我们假设输入来自标准输入：

```cpp
          } else {
              wc = wordcount(cin);
          }
```

1.  就是这样，所以我们只需打印我们保存在变量`wc`中的单词数：

```cpp
          cout << "There are " << wc << " wordsn";
      };
```

1.  让我们编译并运行程序。首先，我们从标准输入中输入程序，没有任何文件参数。我们可以通过管道将 echo 调用与一些单词一起输入，或者启动程序并从键盘输入一些单词。在后一种情况下，我们可以通过按*Ctrl*+*D*来停止输入。这是将一些单词回显到程序中的方式：

```cpp
      $ echo "foo bar baz" | ./count_all_words 
      There are 3 words
```

1.  当以源代码文件作为输入启动程序时，它将计算它由多少个单词组成：

```cpp
      $ ./count_all_words count_all_words.cpp
      There are 61 words
```

# 它是如何工作的...

没有太多要说的了；大部分内容在实现时已经解释过了，因为这个程序非常简短。我们可以详细介绍一点的是，我们完全可以以相互替换的方式使用`std::cin`和`std::ifstream`实例。`cin`是`std::istream`类型，而`std::ifstream`继承自`std::istream`。看一下本章开头的类继承图表。这样，它们在运行时是完全可以互换的。

通过使用流抽象来保持代码模块化。这有助于解耦源代码部分，并使您的代码易于测试，因为您可以注入任何其他匹配类型的流。

# 使用 I/O 流操纵器格式化输出

在许多情况下，仅仅打印字符串和数字是不够的。有时，数字需要以十进制数打印，有时以十六进制数打印，有时甚至以八进制数打印。有时我们希望在十六进制数前面看到`"0x"`前缀，有时不希望。

在打印浮点数时，我们可能也有很多事情想要影响。小数值是否总是以相同的精度打印？它们是否应该被打印？或者，也许我们想要科学计数法？

除了科学表示法和十六进制、八进制等，我们还希望以整洁的形式呈现用户输出。有些输出可以以表格的形式排列，以使其尽可能可读。

当然，所有这些都可以通过输出流实现。当从输入流中*解析*值时，其中一些设置也很重要。在本教程中，我们将通过玩弄这些所谓的**I/O 操纵器**来感受一下。有时，它们看起来很棘手，所以我们也会深入一些细节。

# 如何做...

在本节中，我们将使用各种格式设置打印数字，以便熟悉 I/O 操纵器：

1.  首先，我们包括所有必要的标头，并声明我们默认使用`std`命名空间：

```cpp
      #include <iostream>
      #include <iomanip>
      #include <locale>      

      using namespace std;
```

1.  接下来，我们定义一个辅助函数，它以不同的样式打印单个整数值。它接受填充宽度和填充字符，默认为空格`' '`：

```cpp
      void print_aligned_demo(int val, 
                              size_t width, 
                              char fill_char = ' ')
      {
```

1.  使用`setw`，我们可以设置打印数字时的最小字符数。例如，如果我们以宽度为`6`打印`123`，我们会得到`" 123"`或`"123 "`。我们可以使用`std::left`、`std::right`和`std::internal`控制填充发生在哪一侧。在以十进制形式打印数字时，`internal`看起来与`right`相同。但是，例如，如果我们以宽度为`6`和`internal`打印值`0x1`，我们会得到`"0x 6"`。`setfill`操纵器定义了用于填充的字符。我们将尝试不同的样式：

```cpp
          cout << "================n";
          cout << setfill(fill_char);
          cout << left << setw(width) << val << 'n';
          cout << right << setw(width) << val << 'n';
          cout << internal << setw(width) << val << 'n';
      }
```

1.  在主函数中，我们开始使用刚刚实现的函数。首先，我们打印值`12345`，宽度为`15`。我们这样做两次，但第二次，我们使用`'_'`字符进行填充：

```cpp
      int main()
      {
          print_aligned_demo(123456, 15);
          print_aligned_demo(123456, 15, '_');
```

1.  之后，我们以与之前相同的宽度打印值`0x123abc`。但在这之前，我们应用了`std::hex`和`std::showbase`，告诉输出流对象`cout`应该以十六进制格式打印数字，并且应该在它们前面添加`"0x"`，以便明确表示它们应该被解释为十六进制：

```cpp
          cout << hex << showbase;
          print_aligned_demo(0x123abc, 15);
```

1.  我们也可以使用`oct`做同样的事情，告诉`cout`使用八进制系统来打印数字。`showbase`仍然有效，因此`0`将被添加到每个打印的数字前面：

```cpp
          cout << oct;
          print_aligned_demo(0123456, 15);
```

1.  使用`hex`和`uppercase`，我们得到了`"0x"`中的`'x'`大写打印。`'0x123abc'`中的`'abc'`也是大写的：

```cpp
          cout << "A hex number with upper case letters: "
               << hex << uppercase << 0x123abc << 'n';
```

1.  如果我们想再次以十进制格式打印`100`，我们必须记住之前已经将流切换为`hex`。通过使用`dec`，我们可以将其恢复为正常状态：

```cpp
          cout << "A number: " << 100 << 'n';
          cout << dec;

          cout << "Oops. now in decimal again: " << 100 << 'n';
```

1.  我们还可以配置布尔值的打印方式。默认情况下，`true`打印为`1`，`false`打印为`0`。使用`boolalpha`，我们可以将其设置为文本表示：

```cpp
          cout << "true/false values: " 
               << true << ", " << false << 'n';
          cout << boolalpha
               << "true/false values: "
               << true << ", " << false << 'n';
```

1.  让我们来看看`float`和`double`类型的浮点变量。如果我们打印一个数字，比如`12.3`，它当然会打印为`12.3`。如果我们有一个数字，比如`12.0`，输出流将会去掉小数点，我们可以使用`showpoint`来改变这一点。使用这个，小数点总是会显示：

```cpp
          cout << "doubles: "
               << 12.3 << ", "
               << 12.0 << ", "
               << showpoint << 12.0 << 'n';
```

1.  浮点数的表示可以是科学或固定的。`scientific`表示数字被*标准化*为这样一种形式，即小数点前只有一个数字，然后打印出指数，这是将数字乘回其实际大小所需的。例如，值`300.0`将被打印为`"3.0E2"`，因为`300`等于`3.0 * 10²`。`fixed`则恢复为正常的十进制表示法：

```cpp
          cout << "scientific double: " << scientific 
               << 123000000000.123 << 'n';
          cout << "fixed      double: " << fixed 
               << 123000000000.123 << 'n';
```

1.  除了表示法，我们还可以决定浮点数打印的精度。让我们创建一个非常小的值，并以小数点后 10 位的精度打印它，然后再以小数点后只有一位的精度打印它：

```cpp
          cout << "Very precise double: " 
               << setprecision(10) << 0.0000000001 << 'n';
          cout << "Less precise double: " 
               << setprecision(1)  << 0.0000000001 << 'n';
      }
```

1.  编译并运行程序会产生以下冗长的输出。前四个输出块是打印助手函数的输出，该函数对`setw`和`left`/`right`/`internal`修饰符进行了调整。之后，我们对基本表示、布尔表示和浮点数格式进行了调整。熟悉每种格式是个好主意：

```cpp
      $ ./formatting 
      ================
      123456         
               123456
               123456
      ================
      123456_________
      _________123456
      _________123456
      ================
      0x123abc       
             0x123abc
      0x       123abc
      ================
      0123456        
              0123456
              0123456
      A hex number with upper case letters: 0X123ABC
      A number: 0X64
      Oops. now in decimal again: 100
      true/false values: 1, 0
      true/false values: true, false
      doubles: 12.3, 12, 12.0000
      scientific double: 1.230000E+11
      fixed      double: 123000000000.123001
      Very precise double: 0.0000000001
      Less precise double: 0.0
```

# 它是如何工作的...

所有这些有时相当长的`<< foo << bar`流表达式如果读者不清楚每个表达式的含义，会让人感到困惑。因此，让我们来看一下现有格式修饰符的表格。它们都应该放在`input_stream >> modifier`或`output_stream << modifier`表达式中，然后影响接下来的输入或输出：

| **符号** | **含义** |
| --- | --- |
| `setprecision(int n)` | 设置打印或解析浮点值时的精度参数。 |
| `showpoint` / `noshowpoint` | 启用或禁用打印浮点数的小数点，即使它们没有任何小数位 |
| `fixed` / `scientific` / `hexfloat` / `defaultfloat` | 数字可以以固定样式（这是最直观的样式）或科学样式打印。`fixed`和`scientific`代表这些模式。`hexfloat`激活这两种模式，它以十六进制浮点表示法格式化浮点数。`defaultfloat`取消这两种模式。 |
| `showpos` / `noshowpos` | 启用或禁用打印正浮点值的`'+'`前缀 |
| `setw(int n)` | 读取或写入确切的`n`个字符。在读取时，这会截断输入。在打印时，如果输出长度小于`n`个字符，则会应用填充。 |
| `setfill(char c)` | 在应用填充（参见`setw`）时，用字符值`c`填充输出。默认值是空格（`' '`）。 |
| `internal` / `left` / `right` | `left`和`right`控制固定宽度打印（参见`setw`）的填充位置。`internal`将填充字符放在整数及其负号、十六进制前缀和十六进制打印值，或货币单位和值之间的中间位置。 |
| `dec` / `hex` / `oct` | 可以在十进制、十六进制和八进制基数系统中打印和解析整数值 |
| `setbase(int n)` | 这是`dec`/`hex`/`oct`的数值同义函数，如果与值`10`/`16`/`8`一起使用，则它们是等效的。其他值会将基础选择重置为`0`，这将再次导致十进制打印，或者根据输入的前缀进行解析。 |
| `quoted(string)` | 以引号打印字符串或从带引号的输入中解析字符串，然后删除引号。`string`可以是 String 类实例或 C 风格的字符数组。 |
| `boolalpha` / `noboolalpha` | 以字母表示形式而不是`1`/`0`字符串打印或解析布尔值 |
| `showbase` / `noshowbase` | 在打印或解析数字时启用或禁用基数前缀。对于`hex`，这是`0x`；对于`octal`，这是`0`。 |
| `uppercase` / `nouppercase` | 在打印浮点和十六进制值时启用或禁用大写或字母字符 |

熟悉它们的最佳方法是稍微研究它们的多样性并与它们玩耍。

然而，在与它们玩耍时，我们可能已经注意到这些修改器中的大多数似乎是*粘性的*，而其中一些则不是。粘性意味着一旦应用，它们似乎会永久地影响输入/输出，直到它们再次被重置。此表中唯一不粘性的是`setw`和`quoted`。它们只影响输入/输出中的下一项。这是很重要的，因为如果我们以某种格式打印一些输出，我们应该在之后整理我们的流对象格式设置，因为来自不相关代码的下一个输出可能看起来很疯狂。同样适用于输入解析，其中错误的 I/O 操作器选项可能会导致问题。

我们并没有真正使用它们中的任何一个，因为它们与格式无关，但出于完整性的原因，我们也应该看一下其他一些流状态操作器：

| **符号** | **含义** |
| --- | --- |
| `skipws` / `noskipws` | 启用或禁用输入流跳过空白的功能 |
| `unitbuf` / `nounitbuf` | 启用或禁用任何输出操作后立即刷新输出缓冲区 |
| `ws` | 可以在输入流上使用，以跳过流头部的任何空白 |
| `ends` | 在流中写入一个字符串终止`''`字符 |
| `flush` | 立即刷新输出缓冲区中的内容 |
| `endl` | 在输出流中插入一个 `'n'` 字符并刷新输出 |

从中，只有`skipws`/`noskipws`和`unitbuf`/`nounitbuf`是粘性的。

# 从文件输入初始化复杂对象

读取单独的整数、浮点数和单词字符串非常容易，因为输入流对象的 `>>` 操作符已经为所有这些类型重载了，并且输入流方便地为我们删除了所有中间的空白。

但是，如果我们有一个更复杂的结构，我们想要从输入流中读取，如果我们需要读取包含多个单词的字符串（因为它们通常会被分成单个单词，因为空白会被跳过），那该怎么办呢？

对于任何类型，都可以提供另一个输入流 `operator>>` 重载，我们将看到如何做到这一点。

# 如何做...

在本节中，我们将定义一个自定义数据结构，并提供从标准输入流中读取这些项目的功能：

1.  首先，我们需要包含一些头文件，并且为了方便起见，我们声明默认使用 `std` 命名空间：

```cpp
      #include <iostream>
      #include <iomanip>
      #include <string>
      #include <algorithm>
      #include <iterator>
      #include <vector>      

      using namespace std;
```

1.  作为一个复杂对象的例子，我们定义了一个 `city` 结构。一个城市应该有一个名称、一个人口数量和地理坐标：

```cpp
      struct city {
          string name;
          size_t population;
          double latitude;
          double longitude;
      };
```

1.  为了能够从串行输入流中读取这样一个城市，我们需要重载流函数 `operator>>`。在这个操作符中，我们首先使用 `ws` 跳过所有前导空白，因为我们不希望空白污染城市名称。然后，我们读取一整行文本输入。这意味着在输入文件中，只有一整行文本只携带城市对象的名称。然后，在换行符之后，跟着一个以空格分隔的数字列表，表示人口数量、地理纬度和经度：

```cpp
      istream& operator>>(istream &is, city &c)
      {
          is >> ws;
          getline(is, c.name);
          is >> c.population 
             >> c.latitude 
             >> c.longitude;
          return is;
      }
```

1.  在我们的主函数中，我们创建了一个可以容纳一系列城市项目的向量。我们使用 `std::copy` 来填充它。复制调用的输入是一个 `istream_iterator` 范围。通过将 `city` 结构类型作为模板参数传递给它，它将使用我们刚刚实现的 `operator>>` 函数重载：

```cpp
      int main()
      {
          vector<city> l;

          copy(istream_iterator<city>{cin}, {}, 
               back_inserter(l));
```

1.  为了查看我们的城市解析是否正确，我们打印了列表中的内容。I/O 格式化，`left << setw(15) <<`，导致城市名称被填充了空白，所以我们得到了一个很好的可读形式的输出：

```cpp
          for (const auto &[name, pop, lat, lon] : l) {
              cout << left << setw(15) << name
                   << " population=" << pop
                   << " lat=" << lat
                   << " lon=" << lon << 'n';
          }
      }
```

1.  我们将喂给我们的程序的文本文件看起来像这样。有四个示例城市及其人口数量和地理坐标：

```cpp
      Braunschweig
      250000 52.268874 10.526770
      Berlin
      4000000 52.520007 13.404954
      New York City
      8406000 40.712784 -74.005941
      Mexico City
      8851000 19.432608 -99.133208
```

1.  编译和运行程序产生了以下输出，这正是我们所期望的。尝试通过在城市名称之前添加一些不必要的空白来篡改输入文件，以查看它是如何被过滤掉的：

```cpp
      $ cat cities.txt  | ./initialize_complex_objects
      Braunschweig    population=250000 lat=52.2689 lon=10.5268
      Berlin          population=4000000 lat=52.52 lon=13.405
      New York City   population=8406000 lat=40.7128 lon=-74.0059
      Mexico City     population=8851000 lat=19.4326 lon=-99.1332
```

# 它是如何工作的...

这又是一个简短的示例。我们所做的唯一的事情就是创建一个新的结构 `city`，然后为这种类型重载 `std::istream` 迭代器的 `operator>>`，就是这样。这已经使我们能够从标准输入中反序列化城市项目使用 `istream_iterator<city>`。

关于错误检查可能还有一个未解决的问题。让我们再次看看 `operator>>` 的实现：

```cpp
      istream& operator>>(istream &is, city &c)
      {
          is >> ws;
          getline(is, c.name);
          is >> c.population >> c.latitude >> c.longitude;
          return is;
      }
```

我们正在读取很多不同的东西。如果其中一个失败了，下一个又怎么样？这是否意味着我们可能会用错误的“偏移量”读取所有后续的项目？不，这是不可能的。一旦这些项目中的一个无法从输入流中解析出来，输入流对象就会进入错误状态，并拒绝进一步解析任何内容。这意味着，例如 `c.population` 或 `c.latitude` 无法解析，剩余的 `>>` 操作数就会“跳过”，我们将以一个半反序列化的城市对象离开这个操作符函数范围。

在调用方面，当我们写 `if (input_stream >> city_object)` 时，我们会得到通知。当作为条件表达式使用时，这样的流表达式会被隐式转换为一个布尔值。如果输入流对象处于错误状态，则返回 `false`。知道这一点后，我们可以重置流并执行适当的操作。

在这个示例中，我们没有自己编写这样的`if`条件，因为我们让`std::istream_iterator<city>`进行反序列化。这个迭代器类的`operator++`实现在解析时也会检查错误。如果发生任何错误，它将拒绝进一步迭代。在这种状态下，当它与结束迭代器进行比较时，它将返回`true`，这使得`copy`算法终止。这样，我们就安全了。

# 从 std::istream 迭代器填充容器

在上一个示例中，我们学会了如何从输入流中组装复合数据结构，然后用它们填充列表或向量。

这一次，我们通过标准输入填充一个`std::map`，使问题变得有点困难。这里的问题是，我们不能只是用值填充单个结构，然后将其推回线性容器，比如列表或向量，因为`map`将其有效负载分为键和值部分。然而，它并不完全不同，正如我们将看到的那样。

学习了这个示例之后，我们将会对从字符流中序列化和反序列化复杂的数据结构感到满意。

# 如何做...

我们将定义另一个类似上一个示例的结构，但这次我们将把它填充到一个地图中，这使得它变得更加复杂，因为这个容器从键到值的映射，而不仅仅是在列表中保存所有值：

1.  首先，我们包括所有需要的头文件，并声明我们默认使用`std`命名空间：

```cpp
      #include <iostream>
      #include <iomanip>
      #include <map>
      #include <iterator>
      #include <algorithm>
      #include <numeric>      

      using namespace std;
```

1.  我们想要维护一个小的互联网迷因数据库。假设一个迷因有一个名称、一个描述以及它诞生或发明的年份。我们将把它们保存在一个`std::map`中，其中名称是键，而其他信息则作为与键关联的值打包在一个结构中：

```cpp
      struct meme {
          string description;
          size_t year;
      };
```

1.  让我们首先忽略键，只为`struct meme`实现一个流`operator>>`函数重载。我们假设描述被引号包围，后面跟着年份。这在文本文件中看起来像`"一些描述" 2017`。由于描述被引号包围，它可以包含空格，因为我们知道引号之间的所有内容都属于它。通过使用`is >> quoted(m.description)`读取，引号会自动用作分隔符，并在之后被丢弃。这非常方便。就在那之后，我们读取年份数字：

```cpp
      istream& operator>>(istream &is, meme &m) {
          return is >> quoted(m.description) >> m.year;
      }
```

1.  好的，现在我们考虑将迷因的名称作为地图的键。为了将迷因插入地图，我们需要一个`std::pair<key_type, value_type>`实例。`key_type`当然是`string`，而`value_type`是`meme`。名称也允许包含空格，所以我们使用与描述相同的`quoted`包装。`p.first`是名称，`p.second`是与之关联的整个`meme`结构。它将被馈送到我们刚刚实现的另一个`operator>>`实现中：

```cpp
      istream& operator >>(istream &is, 
                           pair<string, meme> &p) {
          return is >> quoted(p.first) >> p.second;
      }
```

1.  好的，就是这样。让我们编写一个主函数，实例化一个地图，并填充该地图。因为我们重载了流函数`operator>>`，`istream_iterator`可以直接处理这种类型。我们让它从标准输入反序列化我们的迷因项目，并使用`inserter`迭代器将它们泵入地图中：

```cpp
      int main()
      {
          map<string, meme> m;

          copy(istream_iterator<pair<string, meme>>{cin},
               {},
               inserter(m, end(m)));
```

1.  在打印我们拥有的内容之前，让我们首先找出地图中*最长*的迷因名称是什么。我们使用`std::accumulate`来实现这一点。它得到一个初始值`0u`（`u`表示无符号），并将按元素访问地图，以便将它们*合并*在一起。在`accumulate`中，合并通常意味着*添加*。在我们的情况下，我们不想得到任何数值的*总和*，而是最大的字符串长度。为了实现这一点，我们提供了一个辅助函数`max_func`给`accumulate`，它接受当前最大尺寸变量（必须是`unsigned`，因为字符串长度是无符号的）并将其与当前项目的迷因名称字符串长度进行比较，以便取两个值中的最大值。这将对每个元素发生。`accumulate`函数的最终返回值是最大的迷因名称长度：

```cpp
          auto max_func ([](size_t old_max, 
                            const auto &b) {
              return max(old_max, b.first.length());
          });
          size_t width {accumulate(begin(m), end(m), 
                                   0u, max_func)};
```

1.  现在，让我们快速地循环遍历 map 并打印每个项。我们使用`<< left << setw(width)`来获得一个漂亮的类似表格的打印：

```cpp
          for (const auto &[meme_name, meme_desc] : m) {
              const auto &[desc, year] = meme_desc;

              cout << left << setw(width) << meme_name
                   << " : " << desc
                   << ", " << year << 'n';
          }
      }
```

1.  就是这样。我们需要一个小的互联网迷因数据库文件，所以让我们用一些示例填充一个文本文件：

```cpp
      "Doge" "Very Shiba Inu. so dog. much funny. wow." 2013
      "Pepe" "Anthropomorphic frog" 2016
      "Gabe" "Musical dog on maximum borkdrive" 2016
      "Honey Badger" "Crazy nastyass honey badger" 2011
      "Dramatic Chipmunk" "Chipmunk with a very dramatic look" 2007
```

1.  使用示例 meme 数据库编译和运行程序产生以下输出：

```cpp
      $ cat memes.txt | ./filling_containers 
      Doge              : Very Shiba Inu. so dog. much funny. wow., 2013
      Dramatic Chipmunk : Chipmunk with a very dramatic look, 2007
      Gabe              : Musical dog on maximum borkdrive, 2016
      Honey Badger      : Crazy nastyass honey badger, 2011
      Pepe              : Anthropomorphic frog, 2016
```

# 它是如何工作的...

在这个示例中有三个特殊之处。一个是我们没有从串行字符流中填充普通向量或列表，而是从`std::map`这样的更复杂的容器中填充。另一个是我们使用了那些神奇的`quoted`流操作器。最后一个是`accumulate`调用，它找出了最大的键字符串大小。

让我们从`map`部分开始。我们的`struct meme`只包含一个`description`字段和`year`。互联网迷因的名称不是这个结构的一部分，因为它被用作 map 的键。当我们向 map 中插入东西时，我们可以提供一个具有键类型和值类型的`std::pair`。这就是我们所做的。我们首先为`struct meme`实现了流`operator>>`，然后我们为`pair<string, meme>`做了同样的事情。然后我们使用`istream_iterator<**pair<string, meme>**>{cin}`从标准输入中获取这些项，并使用`inserter(m, end(m))`将它们插入 map 中。

当我们从流中反序列化 meme 项时，我们允许名称和描述包含空格。这是很容易实现的，尽管我们每个 meme 只使用一行，因为我们对这些字段进行了引用。一行格式的示例如下：`"Name with spaces" "Description with spaces" 123`

处理输入和输出中的带引号字符串时，`std::quoted`是一个很好的帮助。如果我们有一个字符串`s`，使用`cout << quoted(s)`来打印它会加上引号。如果我们通过流反序列化一个字符串，例如，通过`cin >> quoted(s)`，它将读取下一个引号，用后面的内容填充字符串，并继续直到看到下一个引号，无论涉及多少空格。

在我们的累积调用中，最后一个看起来奇怪的是`max_func`：

```cpp
auto max_func ([](size_t old_max, const auto &b) {
    return max(old_max, b.first.length());
});

size_t width {accumulate(begin(m), end(m), 0u, max_func)};
```

显然，`max_func`接受一个`size_t`参数和另一个`auto-`类型的参数，结果是来自 map 的`pair`项。这一开始看起来很奇怪，因为大多数二进制缩减函数接受相同类型的参数，然后使用某种操作将它们合并在一起，就像`std::plus`一样。在这种情况下，情况确实很不同，因为我们不是合并实际的`pair`项。我们只从每对中选择键字符串长度，*丢弃*其余部分，然后使用`max`函数减少结果的`size_t`值。

在累积调用中，`max_func`的第一个调用得到我们最初提供的`0u`值作为左参数，并得到右侧的第一个 pair 项的引用。这导致`max(0u, string_length)`的返回值，这是*下一个*调用的左参数，下一个 pair 项作为右参数，依此类推。

# 使用 std::ostream 迭代器进行通用打印

使用输出流打印任何东西都很容易，因为 STL 已经为大多数基本类型提供了许多有用的`operator<<`重载。这样，包含这些类型项的数据结构可以很容易地使用`std::ostream_iterator`类进行打印，这在本书中我们已经经常做过。

在这个示例中，我们将集中讨论如何使用自定义类型以及在调用方面不需要太多代码的情况下，我们可以通过模板类型选择来操纵打印。

# 如何做...

我们将通过启用与新自定义类的组合来玩`std::ostream_iterator`，并查看其隐式转换能力，这可以帮助我们进行打印：

1.  首先是包含文件，然后我们声明默认使用`std`命名空间：

```cpp
      #include <iostream>
      #include <vector>
      #include <iterator>
      #include <unordered_map>
      #include <algorithm>      

      using namespace std;
```

1.  让我们实现一个转换函数，将数字映射到字符串。它应该为值`1`返回`"one"`，为值`2`返回`"two"`，依此类推：

```cpp
      string word_num(int i) {
```

1.  我们用我们需要的映射填充哈希映射，以便以后访问它们：

```cpp
          unordered_map<int, string> m {
              {1, "one"}, {2, "two"}, {3, "three"},
              {4, "four"}, {5, "five"}, //...
          };
```

1.  现在，我们可以使用哈希映射的 `find` 函数来查找参数 `i`，并返回它找到的内容。如果找不到任何内容，因为给定数字没有翻译，我们将返回字符串 `"unknown"`：

```cpp
          const auto match (m.find(i));
          if (match == end(m)) { return "unknown"; }
          return match->second;
      };
```

1.  我们稍后将使用的另一件事是 `struct bork`。它只包含一个整数，并且也可以从整数*隐式*构造出来。它有一个 `print` 函数，接受一个输出流引用，并根据其成员整数 `borks` 的值重复打印 `"bork"` 字符串：

```cpp
      struct bork {
          int borks;

          bork(int i) : borks{i} {}

          void print(ostream& os) const {
              fill_n(ostream_iterator<string>{os, " "}, 
                     borks, "bork!"s);
          }
      };
```

1.  为了方便使用 `bork::print`，我们为流对象重载了 `operator<<`，因此每当 `bork` 对象被流到输出流中时，它们会自动调用 `bork::print`。

```cpp
      ostream& operator<<(ostream &os, const bork &b) {
          b.print(os);
          return os;
      }
```

1.  现在我们终于可以开始实现实际的主函数了。我们最初只是创建了一个带有一些示例值的向量：

```cpp
      int main()
      {
          const vector<int> v {1, 2, 3, 4, 5};
```

1.  `ostream_iterator` 类型的对象需要一个模板参数，该参数表示它们可以打印哪种类型的变量。如果我们写 `ostream_iterator<**T**>`，它将在打印时使用 `ostream& operator(ostream&, const **T**&)`。这正是我们之前为 `bork` 类型实现的。这一次，我们只是打印整数，所以是 `ostream_iterator<**int**>`。它将使用 `cout` 进行打印，因此我们将其作为构造函数参数提供。我们在循环中遍历我们的向量，并将每个项目 `i` 分配给解引用的输出迭代器。这也是 STL 算法使用流迭代器的方式：

```cpp
          ostream_iterator<int> oit {cout};

          for (int i : v) { *oit = i; }
          cout << 'n';
```

1.  我们刚刚生成的迭代器的输出是正常的，但它打印数字时没有任何分隔符。如果我们希望在所有打印的项目之间有一些分隔空格，我们可以将自定义的间隔字符串作为输出流迭代器构造函数的第二个参数提供。这样，它将打印 `"1, 2, 3, 4, 5, "` 而不是 `"12345"`。不幸的是，我们无法轻松地告诉它在最后一个数字之后删除逗号空格字符串，因为迭代器在到达最后一个数字之前不知道它的结束：

```cpp
          ostream_iterator<int> oit_comma {cout, ", "};

          for (int i : v) { *oit_comma = i; }
          cout << 'n';
```

1.  将项目分配给输出流迭代器以便打印它们并不是使用它的错误方式，但这不是它们被发明的目的。想法是将它们与算法结合使用。最简单的算法是 `std::copy`。我们可以将向量的开始和结束迭代器作为输入范围，将输出流迭代器作为输出迭代器。它将打印向量的所有数字。让我们用输出迭代器和之前编写的循环来比较一下：

```cpp
          copy(begin(v), end(v), oit);
          cout << 'n';

          copy(begin(v), end(v), oit_comma);
          cout << 'n';
```

1.  还记得函数 `word_num` 吗，它将数字映射到字符串，比如 `1` 对应 `"one"`，`2` 对应 `"two"`，依此类推？是的，我们也可以用它们来打印。我们只需要使用一个输出流操作符，它是针对 `string` 进行模板专门化的，因为我们不再打印整数。而且我们使用 `std::transform` 而不是 `std::copy`，因为它允许我们在将每个项目复制到输出范围之前对输入范围中的每个项目应用转换函数：

```cpp
          transform(begin(v), end(v), 
                    ostream_iterator<string>{cout, " "}, 
                    word_num);
          cout << 'n';
```

1.  程序中的最后一行最终使用了 `struct bork`。我们可以为 `std::transform` 提供一个转换函数，但我们没有这样做。相反，我们可以在 `std::copy` 调用中创建一个专门针对 `bork` 类型的输出流迭代器。这将导致从输入范围整数*隐式*创建 `bork` 实例。这将给我们一些有趣的输出：

```cpp
          copy(begin(v), end(v), 
               ostream_iterator<bork>{cout, "n"});
      }
```

1.  编译和运行程序会产生以下输出。前两行与接下来的两行完全相同，这是我们预料到的。然后，我们得到了漂亮的、写出来的数字字符串，然后是大量的 `bork!` 字符串。这些出现在多行中，因为我们使用了 `"n"` 分隔字符串而不是空格：

```cpp
      $ ./ostream_printing 
      12345
      1, 2, 3, 4, 5, 
      12345
      1, 2, 3, 4, 5, 
      one two three four five 
      bork! 
      bork! bork! 
      bork! bork! bork! 
      bork! bork! bork! bork! 
      bork! bork! bork! bork! bork! 
```

# 它是如何工作的...

我们已经看到`std::ostream_iterator`实际上只是一个*语法技巧*，它将打印的行为压缩成迭代器的形式和语法。递增这样的迭代器*没有任何作用*。对其进行解引用只会返回一个代理对象，其赋值运算符将其参数转发到输出流。

对于类型`T`（如`ostream_iterator<T>`）进行特化的输出流迭代器可以使用提供了`ostream& operator<<(ostream&, const T&)`实现的所有类型。

`ostream_iterator`总是尝试调用其模板参数指定的类型的`operator<<`，它将尝试隐式转换类型（如果允许）。当我们迭代`A`类型的项目范围，但将这些项目复制到`output_iterator<B>`实例时，如果`A`可以隐式转换为`B`，这将起作用。我们对`struct bork`也是完全相同的操作：`bork`实例可以从整数值隐式转换。这就是为什么很容易将大量`"bork!"`字符串抛到用户 shell 上。

如果隐式转换不可能，我们可以自己做，使用`std::transform`，这就是我们与`word_num`函数结合使用的方法。

请注意，通常*允许自定义类型进行隐式转换*是*不好的风格*，因为这是一个常见的*bug 来源*，后期很难找到。在我们的示例用例中，隐式构造函数比危险更有用，因为该类除了打印之外没有其他用途。

# 将输出重定向到特定代码段的文件

`std::cout`提供了一个非常好的方法，可以在任何时候打印我们想要的内容，因为它简单易用，易于扩展，并且全局可访问。即使我们想要打印特殊消息，比如错误消息，我们想要将其与普通消息隔离开来，我们可以使用`std::cerr`，它与`cout`相同，但是将内容打印到标准错误通道而不是标准输出通道。

有时我们可能对日志记录有更复杂的需求。例如，我们想要将函数的输出*重定向*到文件，或者我们想要*静音*函数的输出，而不改变函数本身。也许它是一个我们无法访问源代码的库函数。也许它从未被设计为写入文件，但我们希望将其输出到文件中。

确实可以重定向流对象的输出。在本教程中，我们将看到如何以非常简单和优雅的方式做到这一点。

# 如何做到...

我们将实现一个辅助类，解决重定向流和再次恢复重定向的问题，使用构造函数/析构函数的魔法。然后我们看看如何使用它：

1.  这次我们只需要输入、输出和文件流的头文件。并将`std`命名空间声明为查找的默认命名空间：

```cpp
      #include <iostream>
      #include <fstream>     

      using namespace std;
```

1.  我们实现了一个类，它包含一个文件流对象和一个指向流缓冲区的指针。作为流对象的`cout`有一个内部流缓冲区，我们可以简单地交换。在交换的同时，我们可以保存之前的内容，以便稍后可以*撤消*任何更改。我们可以在 C++参考中查找其类型，但我们也可以使用`decltype`来找出`cout.rdbuf()`返回的类型。这通常不是所有情况下的良好做法，但在这种情况下，它只是一个指针类型：

```cpp
      class redirect_cout_region
      {
          using buftype = decltype(cout.rdbuf());

          ofstream ofs;
          buftype  buf_backup;
```

1.  我们的类的构造函数接受一个文件名字符串作为其唯一参数。文件名用于初始化文件流成员`ofs`。初始化后，我们可以将其输入`cout`作为新的流缓冲区。接受新缓冲区的相同函数也返回旧缓冲区的指针，因此我们可以保存它以便稍后恢复它：

```cpp
      public:
          explicit 
          redirect_cout_region (const string &filename)
              : ofs{filename}, 
                buf_backup{cout.rdbuf(ofs.rdbuf())}
          {}
```

1.  默认构造函数与其他构造函数的作用相同。不同之处在于它不会打开任何文件。将默认构造的文件流缓冲区输入到`cout`流缓冲区会导致`cout`被*停用*。它只会*丢弃*我们给它的输入进行打印。在某些情况下，这也是有用的：

```cpp
          redirect_cout_region()
              : ofs{}, 
                buf_backup{cout.rdbuf(ofs.rdbuf())}
          {}
```

1.  析构函数只是恢复了我们的更改。当这个类的对象超出范围时，`cout`的流缓冲区再次变为旧的：

```cpp
          ~redirect_cout_region() { 
              cout.rdbuf(buf_backup); 
          }
      };
```

1.  让我们模拟一个*输出密集*的函数，这样我们以后可以玩耍：

```cpp
      void my_output_heavy_function()
      {
          cout << "some outputn";
          cout << "this function does really heavy workn";
          cout << "... and lots of it...n";
          // ...
      }
```

1.  在主函数中，我们首先产生一些完全正常的输出：

```cpp
      int main()
      {
          cout << "Readable from normal stdoutn";
```

1.  现在我们正在打开另一个作用域，这个作用域中的第一件事就是用文本文件参数实例化我们的新类。文件流默认以读写模式打开文件，因此它为我们创建了这个文件。任何后续的输出现在都将重定向到这个文件，尽管我们使用`cout`进行打印：

```cpp
          {
              redirect_cout_region _ {"output.txt"};
              cout << "Only visible in output.txtn";
              my_output_heavy_function();
          }
```

1.  离开作用域后，文件被关闭，输出重新重定向到正常的标准输出。现在让我们在另一个作用域中实例化相同的类，但是通过它的默认构造函数。这样，下面打印的文本行将不会在任何地方可见。它只会被丢弃：

```cpp
          {
              redirect_cout_region _;
              cout << "This output will "
                      "completely vanishn";
          }
```

1.  离开那个作用域后，我们的标准输出被恢复，最后一行文本输出将再次在 shell 中可读：

```cpp
          cout << "Readable from normal stdout againn";
      }
```

1.  编译和运行程序产生了我们预期的输出。在 shell 中只有第一行和最后一行输出可见：

```cpp
      $ ./log_regions 
      Readable from normal stdout
      Readable from normal stdout again
```

1.  我们可以看到，创建了一个名为`output.txt`的新文件，并包含了第一个作用域的输出。第二个作用域的输出完全消失了。

```cpp
      $ cat output.txt 
      Only visible in output.txt
      some output
      this function does really heavy work
      ... and lots of it...
```

# 工作原理...

每个流对象都有一个内部缓冲区，它充当前端。这些缓冲区是可交换的。如果我们有一个流对象`s`，想要将其缓冲区保存到变量`a`中，并安装一个新的缓冲区`b`，则如下所示：`a = s.rdbuf(b)`。恢复它可以简单地使用`s.rdbuf(a)`来完成。

这正是我们在这个示例中所做的。另一个很酷的事情是我们可以*堆叠*这些`redirect_cout_region`助手：

```cpp
{
    cout << "print to standard outputn";

    redirect_cout_region la {"a.txt"};
    cout << "print to a.txtn";

    redirect_cout_region lb {"b.txt"};
    cout << "print to b.txtn";
}
cout << "print to standard output againn";
```

这是因为对象的销毁顺序与它们的构造顺序相反。使用对象的构造和销毁之间的紧密耦合的模式的概念被称为**资源获取即初始化**（**RAII**）。

有一件非常重要的事情应该提到--`redirect_cout_region`类的成员变量的*初始化顺序*：

```cpp
class redirect_cout_region {
    using buftype = decltype(cout.rdbuf());

    ofstream ofs;
    buftype  buf_backup;

public:
    explicit 
    redirect_cout_region(const string &filename)
        : ofs{filename}, 
          buf_backup{cout.rdbuf(ofs.rdbuf())}
    {}

...
```

正如我们所看到的，成员`buf_backup`是从取决于`ofs`的表达式构造的。这显然意味着`ofs`需要在`buf_backup`之前初始化。有趣的是，这些成员初始化的顺序*并不*取决于初始化列表项的顺序。初始化顺序只取决于*成员声明*的顺序！

如果一个类成员变量需要在另一个成员变量之后初始化，它们在类成员声明中也*必须*按照这个顺序出现。它们在构造函数的初始化列表中出现的顺序并不重要。

# 通过继承自 std::char_traits 创建自定义字符串类

`std::string`非常有用。然而，一旦人们需要一个具有略有不同语义的字符串处理的字符串类，一些人就倾向于编写自己的字符串类。

编写自己的字符串类很少是一个好主意，因为安全的字符串处理很困难。幸运的是，`std::string`只是模板类`std::basic_string`的专门类型定义。这个类包含了所有复杂的内存处理内容，但它不会对字符串的复制、比较等施加任何策略。这是通过接受一个包含特性类的模板参数导入到`basic_string`中的。

在本教程中，我们将看到如何构建我们自己的特性类，以此方式创建自定义字符串而无需重新实现任何内容。

# 如何做...

我们将实现两种不同的自定义字符串类：`lc_string`和`ci_string`。第一个类从任何字符串输入构造小写字符串。另一个类不转换任何字符串，但可以进行不区分大小写的字符串比较：

1.  让我们首先包含一些必要的头文件，然后声明我们默认使用`std`命名空间：

```cpp
      #include <iostream>
      #include <algorithm>
      #include <string>      

      using namespace std;
```

1.  然后我们重新实现了`std::tolower`函数，它已经在`<cctype>`中定义。已经存在的函数很好，但它不是`constexpr`。自 C++17 以来，一些`string`函数是`constexpr`，我们希望能够利用我们自己的自定义字符串特性类。该函数将大写字符映射到小写字符，并保持其他字符不变：

```cpp
      static constexpr char tolow(char c) {
          switch (c) {
          case 'A'...'Z': return c - 'A' + 'a';
          default:        return c;
          }
      }
```

1.  `std::basic_string`类接受三个模板参数：基础字符类型、字符特性类和分配器类型。在本节中，我们只更改字符特性类，因为它定义了字符串的行为。为了仅重新实现与普通字符串不同的部分，我们公开继承标准特性类：

```cpp
      class lc_traits : public char_traits<char> {
      public:
```

1.  我们的类接受输入字符串但将它们转换为小写。有一个函数，它逐个字符地执行此操作，因此我们可以在这里放置我们自己的`tolow`函数。这个函数是`constexpr`的，这就是为什么我们重新实现了一个`constexpr`的`tolow`函数：

```cpp
          static constexpr 
          void assign(char_type& r, const char_type& a ) {
              r = tolow(a);
          }
```

1.  另一个函数处理整个字符串复制到自己的内存中。我们使用`std::transform`调用将所有字符从源字符串复制到内部目标字符串，并同时将每个字符映射到其小写版本：

```cpp
          static char_type* copy(char_type* dest, 
                                 const char_type* src, 
                                 size_t count) {
              transform(src, src + count, dest, tolow);
              return dest;
          }
      };
```

1.  另一个特性有助于构建一个有效地将字符串转换为小写的字符串类。我们将编写另一个特性，它保持实际的字符串有效负载不变，但在比较字符串时不区分大小写。我们再次从现有的标准字符特性类继承，并且这次，我们重新定义了一些其他成员函数：

```cpp
      class ci_traits : public char_traits<char> {
      public:
```

1.  `eq`函数告诉我们两个字符是否相等。我们也这样做，但是我们比较它们的小写版本。这样`'A'`等于`'a'`：

```cpp
          static constexpr bool eq(char_type a, char_type b) {
              return tolow(a) == tolow(b);
          }
```

1.  `lt`函数告诉我们`a`的值是否小于`b`的值。我们在将两个字符再次转换为小写后，应用正确的逻辑运算符：

```cpp
          static constexpr bool lt(char_type a, char_type b) {
              return tolow(a) < tolow(b);
          }
```

1.  最后两个函数处理逐个字符的输入，接下来的两个函数处理逐个字符串的输入。`compare`函数类似于老式的`strncmp`函数。如果两个字符串在`count`定义的长度内相等，则返回`0`。如果它们不同，则返回一个负数或正数，告诉哪个输入字符串在词典顺序上更小。当然，必须在它们的小写版本上计算每个位置的字符之间的差异。好处是自 C++14 以来，这整个循环代码一直是`constexpr`函数的一部分：

```cpp
          static constexpr int compare(const char_type* s1,
                                       const char_type* s2,
                                       size_t count) {
              for (; count; ++s1, ++s2, --count) {
                  const char_type diff (tolow(*s1) - tolow(*s2));
                  if      (diff < 0) { return -1; }
                  else if (diff > 0) { return +1; }
              }
              return 0;
          }
```

1.  我们需要为我们的不区分大小写的字符串类实现的最后一个函数是`find`。对于给定的输入字符串`p`和长度`count`，它找到字符`ch`的位置。然后，它返回指向该字符的第一个出现的指针，如果没有，则返回`nullptr`。该函数中的比较必须使用`tolow`“眼镜”来进行，以使搜索不区分大小写。不幸的是，我们不能使用`std::find_if`，因为它不是`constexpr`，必须自己编写一个循环：

```cpp
          static constexpr 
          const char_type* find(const char_type* p,
                                size_t count,
                                const char_type& ch) {
              const char_type find_c {tolow(ch)};

              for (; count != 0; --count, ++p) {
                  if (find_c == tolow(*p)) { return p; }
              }

              return nullptr;
          }
      };
```

1.  好的，特性就是这些。既然我们现在已经有了它们，我们可以定义两种新的字符串类类型。`lc_string`表示*小写字符串*。`ci_string`表示*不区分大小写的字符串*。这两个类与`std::string`唯一的区别在于它们的字符特性类：

```cpp
      using lc_string = basic_string<char, lc_traits>;
      using ci_string = basic_string<char, ci_traits>;
```

1.  为了使输出流接受这些新的类进行打印，我们需要快速重载流`operator<<`：

```cpp
      ostream& operator<<(ostream& os, const lc_string& str) {
          return os.write(str.data(), str.size());
      }

      ostream& operator<<(ostream& os, const ci_string& str) {
          return os.write(str.data(), str.size());
      }
```

1.  现在我们终于可以开始实现实际的程序了。让我们实例化一个普通字符串、一个小写字符串和一个不区分大小写的字符串，并立即打印它们。它们在终端上应该都看起来正常，但小写字符串应该都是小写的：

```cpp
      int main()
      {
          cout << "   string: " 
               << string{"Foo Bar Baz"} << 'n'
               << "lc_string: " 
               << lc_string{"Foo Bar Baz"} << 'n'
               << "ci_string: "
               << ci_string{"Foo Bar Baz"} << 'n';
```

1.  为了测试不区分大小写的字符串，我们可以实例化两个基本相等但在某些字符的大小写上有所不同的字符串。当进行真正的不区分大小写比较时，它们应该看起来是相等的：

```cpp
          ci_string user_input {"MaGiC PaSsWoRd!"};
          ci_string password   {"magic password!"};
```

1.  因此，让我们比较它们，并打印出它们是否匹配：

```cpp
          if (user_input == password) {
              cout << "Passwords match: "" << user_input
                   << "" == "" << password << ""n";
          }
      }
```

1.  编译和运行程序会产生我们预期的结果。当我们首先以不同类型三次打印相同的字符串时，我们得到了不变的结果，但`lc_string`实例全部是小写的。只有在字符大小写不同的两个字符串的比较确实成功，并产生了正确的输出：

```cpp
      $ ./custom_string 
         string: Foo Bar Baz
      lc_string: foo bar baz
      ci_string: Foo Bar Baz
      Passwords match: "MaGiC PaSsWoRd!" == "magic password!"
```

# 它是如何工作的...

我们所做的所有子类化和函数重新实现对于初学者来说肯定看起来有点疯狂。我们从哪里得到所有这些函数签名，我们*神奇地*知道我们需要重新实现？

让我们首先看看`std::string`真正来自哪里：

```cpp
template <
    class CharT, 
    class Traits    = std::char_traits<CharT>, 
    class Allocator = std::allocator<CharT>
    > 
class basic_string;
```

`std::string`实际上是一个`std::basic_string<char>`，它扩展为`std::basic_string<char, std::char_traits<char>, std::allocator<char>>`。好吧，这是一个很长的类型描述，但是它是什么意思呢？所有这一切的重点是，可以基于单字节`char`项以及其他更大的类型来构建字符串。这使得可以处理更多的字符集，而不仅仅是典型的美国 ASCII 字符集。这不是我们现在要研究的东西。

然而，`char_traits<char>`类包含了`basic_string`在其操作中需要的算法。它知道如何比较、查找和复制字符和字符串。

`allocator<char>`类也是一个特性类，但它的特殊工作是处理字符串的分配和释放。这对我们来说现在并不重要，因为默认行为满足我们的需求。

如果我们希望字符串类的行为有所不同，我们可以尝试尽可能多地重用`basic_string`和`char_traits`已经提供的内容。这就是我们所做的。我们实现了两个`char_traits`子类，分别称为`case_insentitive`和`lower_caser`，并通过将它们用作标准`char_traits`类型的替代品，配置了两种全新的字符串类型。

为了探索其他可能性，以适应`basic_string`到您自己的需求，查阅 C++ STL 文档中的`std::char_traits`，看看它还有哪些其他函数可以重新实现。

# 使用正则表达式库对输入进行标记化

在复杂的字符串解析或转换以及将其分成块时，*正则表达式*是一个很好的帮助。在许多编程语言中，它们已经内置，因为它们非常有用和方便。

如果您还不了解正则表达式，请查看关于它们的*维基百科*文章，例如。当解析任何类型的文本时，它们肯定会扩展您的视野，因为很容易看到它们的有用性。例如，正则表达式可以测试电子邮件地址字符串或 IP 地址字符串是否有效，找到并提取符合复杂模式的大字符串中的子字符串等等。

在这个示例中，我们将从 HTML 文件中提取所有链接并列出给用户。代码将非常简短，因为自 C++11 以来，我们在 C++ STL 中内置了正则表达式支持。

# 如何做...

我们将定义一个检测链接的正则表达式，并将其应用于 HTML 文件，以便漂亮地打印出该文件中出现的所有链接：

1.  让我们首先包括所有必要的头文件，并声明我们默认使用`std`命名空间：

```cpp
      #include <iostream>
      #include <iterator>
      #include <regex>
      #include <algorithm>
      #include <iomanip>      

      using namespace std;
```

1.  稍后我们将生成一个可迭代范围，其中包含字符串。这些字符串总是成对出现，一个是链接，一个是链接描述。因此，让我们编写一个小帮助函数，漂亮地打印这些：

```cpp
      template <typename InputIt>
      void print(InputIt it, InputIt end_it)
      {
          while (it != end_it) {
```

1.  在每个循环步骤中，我们将迭代器递增两次，并复制链接和链接描述。在两个迭代器解引用之间，我们添加了另一个保护`if`分支，检查我们是否过早地到达了可迭代范围的末尾，只是为了安全起见：

```cpp
              const string link {*it++};
              if (it == end_it) { break; }
              const string desc {*it++};
```

1.  现在，让我们以一个漂亮的格式打印链接及其描述，就这样：

```cpp
              cout << left << setw(28) << desc 
                   << " : " << link << 'n';
          }
      }
```

1.  在主函数中，我们正在读取来自标准输入的所有内容。为了做到这一点，我们通过输入流迭代器从整个标准输入构造一个字符串。为了防止标记化，因为我们希望整个用户输入保持原样，我们使用`noskipws`。这个修饰符取消了空格跳过和标记化：

```cpp
      int main()
      {
          cin >> noskipws;
          const std::string in {istream_iterator<char>{cin}, {}};
```

1.  现在我们需要定义一个正则表达式，描述我们如何假设 HTML 链接的外观。正则表达式中的括号`()`定义了组。这些是我们想要访问的链接的部分--它链接到的 URL 及其描述：

```cpp
          const regex link_re {
              "<a href="([^"]*)"[^<]*>([^<]*)</a>"};
```

1.  `sregex_token_iterator`类与`istream_iterator`具有相同的外观和感觉。我们将整个字符串作为可迭代输入范围，并使用刚刚定义的正则表达式。还有第三个参数`{1, 2}`，它是一个整数值的初始化列表。它定义了我们要迭代表达式捕获的组 1 和 2：

```cpp
          sregex_token_iterator it {
              begin(in), end(in), link_re, {1, 2}};
```

1.  现在我们有一个迭代器，如果找到任何内容，它将发出链接和链接描述。我们将它与相同类型的默认构造的迭代器一起提供给我们之前实现的`print`函数：

```cpp
          print(it, {});
      }
```

1.  编译和运行程序后，我们得到以下输出。我在 ISO C++主页上运行了`curl`程序，它只是从互联网上下载了一个 HTML 页面。当然，也可以写`cat some_html_file.html | ./link_extraction`。我们使用的正则表达式基本上是固定的，假设了 HTML 文档中链接的外观。你可以尝试使它更通用：

```cpp
      $ curl -s "https://isocpp.org/blog" | ./link_extraction 
      Sign In / Suggest an Article : https://isocpp.org/member/login
      Register                     : https://isocpp.org/member/register
      Get Started!                 : https://isocpp.org/get-started
      Tour                         : https://isocpp.org/tour
      C++ Super-FAQ                : https://isocpp.org/faq
      Blog                         : https://isocpp.org/blog
      Forums                       : https://isocpp.org/forums
      Standardization              : https://isocpp.org/std
      About                        : https://isocpp.org/about
      Current ISO C++ status       : https://isocpp.org/std/status
      (...and many more...)
```

# 它的工作原理...

正则表达式（或简称*regex*）非常有用。它们可能看起来很神秘，但值得学习它们的工作原理。如果我们手动进行匹配，一个简短的正则表达式就可以节省我们编写许多行代码。

在这个示例中，我们首先实例化了一个 regex 类型的对象。我们将其构造函数与描述正则表达式的字符串一起使用。一个非常简单的正则表达式是`"."`，它匹配*每个*字符，因为点是正则表达式通配符。如果我们写`"a"`，那么这只匹配`'a'`字符。如果我们写`"ab*"`，那么这意味着"一个`a`，以及零个或任意多个`b`字符"。等等。正则表达式是另一个大的主题，在维基百科和其他网站或文献上有很好的解释。

让我们再看看我们假设是 HTML 链接的正则表达式。一个简单的 HTML 链接可能看起来像`<a href="some_url.com/foo">A great link</a>`。我们想要`some_url.com/foo`部分，以及`A great link`。因此，我们想出了以下正则表达式，其中包含用于匹配子字符串的*组*：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/f6d75901-b27a-455d-bbb6-118f376bef15.png)

整个匹配本身始终是**Group 0**。在这种情况下，这是完整的`<a href ..... </a>`字符串。包含链接到的 URL 的引用`href`部分是**Group 1**。正则表达式中的`( )`括号定义了这样一个。另一个是在`<a ...>`和`</a>`之间的部分，其中包含链接描述。

有各种 STL 函数接受正则表达式对象，但我们直接使用了正则表达式令牌迭代器适配器，这是一个高级抽象，它在底层使用`std::regex_search`来自动化重复匹配工作。我们像这样实例化它：

```cpp
sregex_token_iterator it {begin(in), end(in), link_re, {1, 2}};
```

开始和结束部分表示我们的输入字符串，正则表达式令牌迭代器将在其上迭代并匹配所有链接。当然，这是我们实现的复杂正则表达式，用于匹配链接。`{1, 2}`部分是下一个看起来复杂的东西。它指示令牌迭代器在每次完全匹配时停止，并首先产生第 1 组，然后在递增迭代器后产生第 2 组，再次递增后，最终在字符串中搜索下一个匹配项。这种智能行为确实为我们节省了一些代码行。

让我们看另一个例子，确保我们理解了这个概念。假设正则表达式是`"a(b*)(c*)"`。它将匹配包含`a`字符的字符串，然后是零个或任意多个`b`字符，然后是零个或任意多个`c`字符：

```cpp
const string s {" abc abbccc "};
const regex re {"a(b*)(c*)"};

sregex_token_iterator it {begin(s), end(s), re, {1, 2}};

print( *it ); // prints b
++it;
print( *it ); // prints c
++it;
print( *it ); // prints bb
++it;
print( *it ); // prints ccc
```

还有`std::regex_iterator`类，它发出*在*正则表达式匹配之间的子字符串。

# 舒适地根据上下文动态地以不同方式打印数字

在上一个示例中，我们学会了如何使用输出流格式化输出。在做同样的事情时，我们意识到了两个事实：

+   大多数 I/O 操纵器是*粘性*的，因此我们必须在使用后恢复它们的效果，以免干扰其他不相关的代码，也会打印

+   如果我们不得不设置长链的 I/O 操纵器才能以特定格式打印出少量变量，这将非常乏味，看起来也不太可读。

很多人不喜欢 I/O 流，甚至在 C++中，他们仍然使用`printf`来格式化他们的字符串。

在这个示例中，我们将看到如何在代码中减少 I/O 操纵器的噪音，动态地格式化类型。

# 如何做...

我们将实现一个名为`format_guard`的类，它可以自动恢复任何格式设置。此外，我们添加了一个包装类型，它可以包含任何值，但在打印时，它以特殊格式显示，而不会给我们带来 I/O 操纵器的噪音：

1.  首先，我们包含一些头文件，并声明我们使用`std`命名空间：

```cpp
      #include <iostream>
      #include <iomanip>      

      using namespace std;
```

1.  帮助类`format_guard`会为我们整理流格式设置。它的构造函数保存了`std::cout`在那一刻设置的格式标志。它的析构函数将它们恢复到构造函数调用时的状态。这实际上撤销了在之间应用的任何格式设置：

```cpp
      class format_guard {
          decltype(cout.flags()) f {cout.flags()};

      public:
          ~format_guard() { cout.flags(f); }
      };
```

1.  另一个小帮助类是`scientific_type`。因为它是一个类模板，它可以将任何有效载荷类型包装为成员变量。它基本上什么也不做：

```cpp
      template <typename T>
      struct scientific_type {
          T value;

          explicit scientific_type(T val) : value{val} {}
      };
```

1.  我们可以为任何类型定义完全自定义的格式设置，这些类型在之前被包装成`scientific_type`，因为如果我们为其重载流`operator>>`，那么当打印这些类型时，流库会执行完全不同的代码。这样，我们可以以科学浮点表示法打印科学值，使用大写格式和显式的`+`前缀（如果它们具有正值）。我们还使用我们的`format_guard`类来在离开此函数时整理所有设置：

```cpp
      template <typename T>
      ostream& operator<<(ostream &os, const scientific_type<T> &w) {
          format_guard _;
          os << scientific << uppercase << showpos;
          return os << w.value;
      }
```

1.  在主函数中，我们首先尝试使用`format_guard`类。我们打开一个新的作用域，首先获得该类的一个实例，然后我们对`std::cout`应用一些疯狂的格式标志：

```cpp
      int main()
      {
          {
              format_guard _;
              cout << hex << scientific << showbase << uppercase;

              cout << "Numbers with special formatting:n";
              cout << 0x123abc << 'n';
              cout << 0.123456789 << 'n';
          }
```

1.  在启用了许多格式标志的情况下打印了一些数字后，我们再次离开了作用域。在此期间，`format_guard`的析构函数整理了格式。为了测试这一点，我们*再次*打印完全相同的数字。它们应该看起来不同：

```cpp
          cout << "Same numbers, but normal formatting again:n";
          cout << 0x123abc << 'n';
          cout << 0.123456789 << 'n';
```

1.  现在我们要使用`scientific_type`。让我们依次打印三个浮点数。我们将第二个数字包装在`scientific_type`中。这样，它将以我们特殊的科学样式打印，但它之前和之后的数字将采用默认格式。同时，我们避免了丑陋的格式化行*噪音*：

```cpp
          cout << "Mixed formatting: "
               << 123.0 << " "
               << scientific_type{123.0} << " "
               << 123.456 << 'n';
      }
```

1.  编译和运行程序会产生以下结果。前两个数字以特定格式打印。接下来的两个数字以默认格式显示，这表明我们的`format_guard`工作得很好。最后一行的三个数字看起来也正如预期的那样。只有中间的数字具有`scientific_type`的格式，其余的都是默认格式：

```cpp
      $ ./pretty_print_on_the_fly 
      Numbers with special formatting:
      0X123ABC
      1.234568E-01
      Same numbers, but normal formatting again:
      1194684
      0.123457
      Mixed formatting: 123 +1.230000E+02 123.456
```

# 捕获 std::iostream 错误的可读异常

在本章的*任何*食谱中，我们都没有使用*异常*来捕获错误。虽然这是可能的，但在没有异常的情况下使用流对象已经非常方便。如果我们尝试解析 10 个值，但在中间某个地方失败了，整个流对象就会将自己设置为失败状态并停止进一步解析。这样，我们就不会遇到从流中错误的偏移解析变量的危险。我们可以在条件语句中进行解析，比如`if (cin >> foo >> bar >> ...)`。如果失败了，我们就处理它。在`try { ... } catch ...`块中进行解析似乎并不是很有利。

事实上，在 C++中引入异常之前，C++ I/O 流库已经存在。异常支持是后来添加的，这可能解释了为什么它们不是流库中的一流支持特性。

为了在流库中使用异常，我们必须单独配置每个流对象，以便在将自身设置为失败状态时抛出异常。不幸的是，异常对象中的错误解释并没有得到彻底的标准化。正如我们将在本节中看到的那样，这导致了不太有用的错误消息。如果我们真的想要在流对象中使用异常，我们可以*另外*轮询 C 库以获取文件系统错误状态以获得一些额外信息。

在本节中，我们将编写一个可以以不同方式失败的程序，使用异常处理这些失败，并看看如何在之后从中挤取更多信息。

# 如何做...

我们将实现一个程序，打开一个文件（可能失败），然后我们将从中读取一个整数（这也可能失败）。我们在激活异常的情况下进行这些操作，然后看看我们如何处理这些异常：

1.  首先，我们包含一些头文件，并声明我们使用`std`命名空间：

```cpp
      #include <iostream>
      #include <fstream>
      #include <system_error>
      #include <cstring>      

      using namespace std;
```

1.  如果我们想要在流对象中使用异常，我们必须首先启用它们。为了使文件流对象在访问的文件不存在或存在解析错误时抛出异常，我们需要在异常掩码中设置一些失败位。如果我们之后做了一些失败的事情，它将触发异常。通过激活`failbit`和`badbit`，我们为文件系统错误和解析错误启用了异常：

```cpp
      int main()
      {
          ifstream f;
          f.exceptions(f.failbit | f.badbit);
```

1.  现在我们可以打开一个`try`块并访问一个文件。如果打开文件成功，我们尝试从中读取一个整数。只有在两个步骤都成功的情况下，我们才打印整数：

```cpp
          try {
              f.open("non_existant.txt");

              int i;
              f >> i;

              cout << "integer has value: " << i << 'n';
          }
```

1.  在两种预期的错误可能性中，都会抛出`std::ios_base::failure`的实例。这个对象有一个`what()`成员函数，应该解释触发异常的原因。不幸的是，这条消息的标准化被省略了，它并没有提供太多信息。然而，我们至少可以区分是否存在*文件系统*问题（例如文件不存在）或格式*解析*问题。全局变量`errno`甚至在 C++发明之前就存在了，并且被设置为一个错误值，我们现在可以检查。`strerror`函数将错误号转换为可读的字符串。如果`errno`为`0`，那么至少没有文件系统错误：

```cpp
          catch (ios_base::failure& e) {
              cerr << "Caught error: ";
              if (errno) {
                  cerr << strerror(errno) << 'n';
              } else {
                  cerr << e.what() << 'n';
              }
          }
      }
```

1.  编译程序并在两种不同的情况下运行它会产生以下输出。如果要打开的文件存在，但无法从中解析出整数，则会得到一个`iostream_category`错误消息：

```cpp
      $ ./readable_error_msg 
      Caught error: ios_base::clear: unspecified iostream_category error
```

1.  如果文件*不存在*，我们将收到一个不同于`strerror(errno)`的消息通知我们：

```cpp
      $ ./readable_error_msg
      Caught error: No such file or directory
```

# 它是如何工作的...

我们已经看到，我们可以通过`s.exceptions(s.failbit | s.badbit)`为流对象`s`启用异常。这意味着，例如，如果我们想在打开文件时无法打开文件时得到异常，就无法使用`std::ifstream`实例的构造函数：

```cpp
ifstream f {"non_existant.txt"};
f.exceptions(...); // too late for an exception

```

这是一个遗憾，因为异常实际上承诺它们使错误处理变得不那么笨拙，与老式的 C 风格代码相比，后者充斥着大量的`if`分支，处理每一步之后的错误。

如果我们尝试引发流失败的各种原因，我们会意识到没有抛出不同的异常。这样，我们只能找出*何时*发生错误，而不是*什么*具体的错误（当然，这对于*一般*的异常处理来说是*不*正确的，但对于 STL 流库来说是正确的）。这就是为什么我们另外查看了`errno`的值。这个全局变量是一个古老的构造，在旧日当没有 C++或一般的异常时就已经被使用。

如果任何与系统相关的函数遇到错误条件，它可以将`errno`变量设置为非`0`的值（`0`表示没有错误），然后调用者可以读取该错误号并查找其值的含义。唯一的问题是，当我们有一个多线程应用程序，并且所有线程都使用可以设置此错误变量的函数时，*它是谁*的错误值？如果我们即使没有错误也读取它，它可能携带一个错误值，因为在*不同线程*中运行的*其他*系统函数可能已经遇到了错误。幸运的是，自 C++11 以来，这个缺陷已经消失，进程中的每个线程都可以看到自己的`errno`变量。

不详细阐述古老的错误指示方法的利弊，当异常在基于系统的事物上触发时，它可以给我们提供有用的额外信息。异常告诉我们*何时*发生了，而`errno`可以告诉我们*发生了什么*，如果它是在系统级别发生的。


# 第二十八章：实用类

在本章中，我们将涵盖以下配方：

+   使用`std::ratio`在不同时间单位之间转换

+   使用`std::chrono`在绝对时间和相对时间之间进行转换

+   使用`std::optional`安全地标记失败

+   在元组上应用函数

+   使用`std::tuple`快速组合数据结构

+   使用`std::any`替换`void*`以获得更多类型安全性

+   使用`std::variant`存储不同类型

+   使用`std::unique_ptr`自动处理资源

+   使用`std::shared_ptr`自动处理共享堆内存

+   处理指向共享对象的弱指针

+   简化智能指针处理遗留 API 的资源处理

+   共享同一对象的不同成员值

+   生成随机数并选择正确的随机数引擎

+   生成随机数并让 STL 形成特定分布

# 介绍

本章专门介绍了对解决特定任务非常有用的实用类。其中一些确实非常有用，以至于我们很可能在将来的任何 C++程序片段中经常看到它们，或者至少已经在本书的所有其他章节中看到它们。

前两个配方是关于测量和获取*时间*的。我们还将看到如何在不同时间单位之间转换以及如何在时间点之间跳转。

然后，我们将研究`optional`、`variant`和`any`类型（这些类型都是 C++14 和 C++17 中引入的），以及另外五个配方中的一些`tuple`技巧。

自 C++11 以来，我们还获得了复杂的智能指针类型，即`unique_ptr`、`shared_ptr`和`weak_ptr`，它们在*内存管理*方面提供了极大的帮助，这就是为什么我们将专门介绍它们的五个配方。

最后，我们将全面了解 STL 库中与生成*随机数*有关的部分。除了学习 STL 随机引擎的最重要特性外，我们还将学习如何对随机数应用形状，以获得符合我们实际需求的分布。

# 使用 std::ratio 在不同时间单位之间转换

自 C++11 以来，STL 包含了一些新类型和函数，用于获取、测量和显示时间。这部分库存在于`std::chrono`命名空间中，并具有一些复杂的细节。

在这个配方中，我们将集中在测量时间跨度以及如何在单位之间转换测量结果，比如秒、毫秒和微秒。STL 提供了设施，使我们能够定义自己的时间单位并在它们之间无缝转换。

# 如何做到...

在本节中，我们将编写一个小*游戏*，提示用户输入特定的单词。用户需要在键盘上输入这个单词所需的时间将被测量并以多种时间单位显示出来：

1.  首先，我们需要包含所有必要的头文件。出于舒适的原因，我们声明默认使用`std`命名空间：

```cpp
      #include <iostream>
      #include <chrono>
      #include <ratio>
      #include <cmath>
      #include <iomanip>
      #include <optional>      

      using namespace std;
```

1.  `chrono::duration`作为时间持续的类型通常指的是秒的倍数或分数。所有 STL 时间持续单位都是整数类型的持续特化。在这个配方中，我们将专门研究`double`。在这个配方之后，我们将更多地集中在 STL 中已经内置的时间单位定义上：

```cpp
      using seconds = chrono::duration<double>;
```

1.  一毫秒是秒的一部分，因此我们通过参考秒来定义这个单位。`ratio_multiply`模板参数将 STL 预定义的`milli`因子应用于`seconds::period`，从而给我们提供了所需的分数。`ratio_multiply`模板基本上是一个用于乘法比例的元编程函数：

```cpp
      using milliseconds = chrono::duration<
          double, ratio_multiply<seconds::period, milli>>;
```

1.  微秒也是一样的。虽然毫秒是秒的“毫”分之一，但微秒是秒的“微”分之一：

```cpp
      using microseconds = chrono::duration<
          double, ratio_multiply<seconds::period, micro>>;
```

1.  现在我们将实现一个函数，该函数从用户输入中读取一个字符串，并测量用户输入该字符串所需的时间。它不带参数，并返回用户输入字符串以及经过的时间，捆绑在一对中：

```cpp
      static pair<string, seconds> get_input()
      {
          string s;
```

1.  我们需要在用户输入发生的期间开始和结束之后获取时间。获取时间快照看起来像这样：

```cpp
          const auto tic (chrono::steady_clock::now());
```

1.  现在进行实际的用户输入捕获。如果我们不成功，我们只返回一个默认初始化的元组。调用者将看到他得到了一个空的输入字符串：

```cpp
          if (!(cin >> s)) {
              return {{}, {}};
          }
```

1.  在成功的情况下，我们继续获取另一个时间快照。然后我们返回输入字符串和两个时间点之间的差异。请注意，这两个时间点都是绝对时间点，但通过计算差异，我们得到一个持续时间：

```cpp
          const auto toc (chrono::steady_clock::now());

          return {s, toc - tic};
      }
```

1.  现在让我们实现实际的程序。我们循环直到用户正确输入输入字符串。在每个循环步骤中，我们要求用户输入字符串`"C++17"`，然后调用我们的`get_input`函数：

```cpp
      int main()
      {
          while (true) {
              cout << "Please type the word "C++17" as"
                      " fast as you can.n> ";

              const auto [user_input, diff] = get_input();
```

1.  然后我们检查输入。如果输入为空，我们将其解释为请求退出整个程序：

```cpp
              if (user_input == "") { break; }
```

1.  如果用户正确输入了`"C++17"`，我们表示祝贺，然后打印用户正确输入该单词所需的时间。`diff.count()`方法返回浮点数秒数。如果我们使用原始的 STL`seconds`持续时间类型，那么我们将得到一个*四舍五入*的整数值，而不是一个分数。通过在调用`count()`之前使用我们的`diff`变量来喂入毫秒或微秒`constructor`，我们可以得到相同的值转换为不同的单位：

```cpp
              if (user_input == "C++17") {
                  cout << "Bravo. You did it in:n" 
                       << fixed << setprecision(2)
                       << setw(12) << diff.count() 
                       << " seconds.n"
                       << setw(12) << milliseconds(diff).count()
                       << " milliseconds.n"
                       << setw(12) << microseconds(diff).count()
                       << " microseconds.n";
                  break;
```

1.  如果用户在输入中出现拼写错误，我们让他再试一次：

```cpp
              } else {
                  cout << "Sorry, your input does not match."
                          " You may try again.n";
              }
          }
      }
```

1.  编译和运行程序会产生以下输出。首先，有拼写错误，程序会反复要求正确输入单词。在正确输入单词后，它会显示我们输入该单词所用的三种不同时间单位的时间：

```cpp
      $ ./ratio_conversion 
      Please type the word "C++17" as fast as you can.
      > c+17
      Sorry, your input does not match. You may try again.
      Please type the word "C++17" as fast as you can.
      > C++17
      Bravo. You did it in:
              1.48 seconds.
           1480.10 milliseconds.
        1480099.00 microseconds.
```

# 它是如何工作的...

虽然本节主要是关于不同时间单位之间的转换，但我们首先必须选择三个可用时钟对象中的一个。通常在`std::chrono`命名空间中可以选择`system_clock`、`steady_clock`和`high_resolution_clock`之间。它们之间有什么区别？让我们仔细看一下：

| **时钟** **特征** |
| --- |
| `system_clock`代表系统范围内的实时“墙”时钟。如果我们想要获取本地时间，这是正确的选择。 |
| `steady_clock`这个时钟被承诺是*单调*的。这意味着它永远不会被任何时间量倒退。当其他时钟的时间被最小量校正时，或者当时间在冬夏时间之间切换时，其他时钟可能会发生这种情况。 |
| `high_resolution_clock`这是 STL 实现可以提供的最精细粒度时钟滴答周期的时钟。 |

由于我们测量了从一个绝对时间点到另一个绝对时间点的时间距离或持续时间（我们在变量`tic`和`toc`中捕获了这些时间点），我们不关心这些时间点是否在全球范围内偏移。即使时钟晚了 112 年、5 小时、10 分钟和 1 秒（或其他任何时间），这对它们之间的*差异*没有影响。唯一重要的是，在我们保存时间点`tic`之后并在保存时间点`toc`之前，时钟不能进行微调（这在许多系统中不时发生），因为这会扭曲我们的测量。对于这些要求，`steady_clock`是最佳选择。它的实现可以基于处理器的时间戳计数器，该计数器自系统启动以来一直单调递增。

好了，现在通过正确的时间对象选择，我们能够通过`chrono::steady_clock::now()`保存时间点。`now`函数会返回一个`chrono::time_point<chrono::steady_clock>`类型的值。两个这样的值之间的差异（如`toc - tic`）是一个*时间跨度*，或者是`chrono::duration`类型的*持续时间*。由于这是本节的核心类型，现在变得有点复杂。让我们更仔细地看看`duration`的模板类型接口：

```cpp
template<
    class Rep, 
    class Period = std::ratio<1> 
> class duration;
```

我们可以更改的参数称为`Rep`和`Period`。`Rep`很容易解释：这只是用于保存时间值的数值变量类型。对于现有的 STL 时间单位，这通常是`long long int`。在这个示例中，我们选择了`double`。由于我们的选择，我们可以默认保存秒为单位的时间值，然后将其转换为毫秒或微秒。如果我们将`1.2345`秒的时间持续保存在`chrono::seconds`类型中，那么它将四舍五入为一秒。这样，我们将必须将`tik`和`toc`之间的时间差保存在`chrono::microseconds`中，然后可以转换为较不精细的单位。由于我们选择了`double`作为`Rep`，我们可以向上和向下转换，只会丢失一点点精度，这在这个例子中并不会有影响。

我们对所有时间单位使用了`Rep = double`，因此它们只在我们选择的`Period`参数上有所不同：

```cpp
using seconds      = chrono::duration<double>;
using milliseconds = chrono::duration<double, 
 ratio_multiply<seconds::period, milli>>;
using microseconds = chrono::duration<double, 
 ratio_multiply<seconds::period, micro>>;
```

虽然`seconds`是最简单的单位，因为它使用`Period = ratio<1>`，但其他单位必须进行调整。由于一毫秒是一秒的千分之一，我们将`seconds::period`（这只是一个获取函数，用于`Period`参数）与`milli`相乘，`milli`是`std::ratio<1, 1000>`的类型别名（`std::ratio<a, b>`表示分数值`a/b`）。`ratio_multiply`类型基本上是一个*编译时函数*，它表示从一个比率类型乘以另一个比率类型得到的类型。

也许这听起来太复杂了，所以让我们看一个例子：`ratio_multiply<ratio<2, 3>, ratio<4, 5>>`的结果是`ratio<8, 15>`，因为`(2/3) * (4/5) = 8/15`。

我们的结果类型定义等同于以下定义：

```cpp
using seconds      = chrono::duration<double, ratio<1, 1>>;
using milliseconds = chrono::duration<double, ratio<1, 1000>>;
using microseconds = chrono::duration<double, ratio<1, 1000000>>;
```

有了这些类型的对齐，它们之间的转换就变得很容易。如果我们有一个类型为`seconds`的时间持续时间`d`，我们可以通过将其传递到另一种类型的构造函数中，即`milliseconds(d)`，将其转换为`milliseconds`。

# 还有更多...

在其他教程或书籍中，当时间持续时间被转换时，你可能会遇到`duration_cast`。例如，如果我们有一个类型为`chrono::milliseconds`的持续时间值，并且想要将其转换为`chrono::hours`，我们确实需要写`duration_cast<chrono::hours>(milliseconds_value)`，因为这些单位依赖于*整数*类型。从细粒度单位转换为较不精细的单位会导致*精度损失*，这就是为什么我们需要一个`duration_cast`。对于基于`double`或`float`的持续时间单位，这是不需要的。

# 使用 std::chrono 在绝对时间和相对时间之间进行转换

直到 C++11，获取墙上的时钟时间并*仅仅打印*它是相当麻烦的，因为 C++没有自己的时间库。总是需要调用 C 库的函数，这看起来非常古老，考虑到这些调用可以很好地封装到它们自己的类中。

自 C++11 以来，STL 提供了`chrono`库，使得与时间相关的任务更容易实现。

在这个示例中，我们将获取本地时间，打印它，并通过添加不同的时间偏移量来玩耍，这是使用`std::chrono`非常方便的事情。

# 如何做...

我们将保存当前时间并打印它。此外，我们的程序将向保存的时间点添加不同的偏移量，并打印出结果时间点：

1.  典型的包含行首先出现；然后，我们声明默认使用`std`命名空间：

```cpp
      #include <iostream>
      #include <iomanip>
      #include <chrono>      

      using namespace std;
```

1.  我们将打印绝对时间点。这些将以`chrono::time_point`类型模板的形式出现，所以我们只需为其重载输出流运算符。有不同的方法可以打印时间点的日期和/或时间部分。我们将只使用`%c`标准格式。当然，我们也可以只打印时间、只打印日期、只打印年份，或者任何我们想到的东西。在我们最终应用`put_time`之前，所有不同类型之间的转换看起来有点笨拙，但我们只需要做一次：

```cpp
      ostream& operator<<(ostream &os, 
                    const chrono::time_point<chrono::system_clock> &t)
      {
          const auto tt   (chrono::system_clock::to_time_t(t));
          const auto loct (std::localtime(&tt));
          return os << put_time(loct, "%c");
      }
```

1.  STL 已经为`seconds`、`minutes`、`hours`等定义了类型。现在我们将添加`days`类型。这很容易；我们只需通过引用`hours`来专门化`chrono::duration`模板，并乘以`24`，因为一整天有 24 小时：

```cpp
      using days = chrono::duration<
          chrono::hours::rep,
          ratio_multiply<chrono::hours::period, ratio<24>>>;
```

1.  为了能够以最优雅的方式表示多天的持续时间，我们可以定义自己的`days`字面量运算符。现在，我们可以写`3_days`来构造一个代表三天的值：

```cpp
      constexpr days operator ""_days(unsigned long long h)
      {
          return days{h};
      }
```

1.  在实际程序中，我们将拍摄一个时间快照，然后简单地打印出来。这非常容易和舒适，因为我们已经为此实现了正确的运算符重载：

```cpp
      int main()
      {
          auto now (chrono::system_clock::now());

          cout << "The current date and time is " << now << 'n';
```

1.  将当前时间保存在`now`变量中后，我们可以向其中添加任意持续时间并打印出来。让我们在当前时间上加 12 小时，并打印出 12 小时后的时间：

```cpp
          chrono::hours chrono_12h {12};

          cout << "In 12 hours, it will be "
               << (now + chrono_12h)<< 'n';
```

1.  通过默认声明我们使用`chrono_literals`命名空间，我们解锁了所有现有的持续时间字面量，如小时、秒等。这样，我们可以优雅地打印 12 小时 15 分钟前的时间，或者 7 天前的时间：

```cpp
          using namespace chrono_literals;

          cout << "12 hours and 15 minutes ago, it was "
               << (now - 12h - 15min) << 'n'
               << "1 week ago, it was "
               << (now - 7_days) << 'n';
      }
```

1.  编译并运行程序后，会得到以下输出。因为我们在时间格式化的格式字符串中使用了`%c`，所以我们得到了一个相当完整的描述，以特定格式呈现。通过尝试不同的格式字符串，我们可以得到任何我们喜欢的格式。请注意，时间格式不是 12 小时制的 AM/PM，而是 24 小时制，因为该应用在欧洲系统上运行：

```cpp
 $ ./relative_absolute_times 
      The current date and time is Fri May  5 13:20:38 2017
      In 12 hours, it will be Sat May  6 01:20:38 2017
      12 hours and 15 minutes ago, it was Fri May  5 01:05:38 2017
      1 week ago, it was Fri Apr 28 13:20:38 2017
```

# 工作原理...

我们从`std::chrono::system_clock`获得了当前时间点。这个 STL 时钟类是唯一一个可以将其时间点值转换为可以显示为人类可读时间描述字符串的时间结构的类。

为了打印这样的时间点，我们实现了输出流的`operator<<`：

```cpp
ostream& operator<<(ostream &os, 
                    const chrono::time_point<chrono::system_clock> &t)
{
    const auto tt   (chrono::system_clock::to_time_t(t));
    const auto loct (std::localtime(&tt));
    return os << put_time(loct, "%c");
}
```

这里首先发生的是，我们从`chrono::time_point<chrono::system_clock>`转换为`std::time_t`。这种类型的值可以转换为本地墙钟相关的时间值，我们使用`std::localtime`进行转换。这个函数返回一个指向转换值的指针（不用担心指针后面的内存维护；它是一个静态对象，不是在堆上分配的），现在我们可以最终打印出来了。

`std::put_time`函数接受这样一个对象和一个时间格式字符串。`"%c"`显示标准的日期时间字符串，如`Sun Mar 12 11:33:40 2017`。我们也可以写`"%m/%d/%y"`；那么程序将以`03/12/17`的格式打印时间。现有的时间格式字符串修饰符列表非常长，但在在线 C++参考文档中有完整的文档。

除了打印外，我们还向时间点添加了时间偏移。这很容易，因为我们可以将时间持续时间表示为“12 小时 15 分钟”这样的表达式，如`12h + 15min`。`chrono_literals`命名空间已经为小时（`h`）、分钟（`min`）、秒（`s`）、毫秒（`ms`）、微秒（`us`）和纳秒（`ns`）提供了方便的类型字面量。

将这样的持续时间值添加到时间点值会创建一个新的时间点值，因为这些类型具有正确的`operator+`和`operator-`重载，这就是为什么在时间中添加和显示偏移如此简单的原因。

# 使用 std::optional 安全地标记失败

当程序与外部世界通信并依赖于从那里得到的值时，各种故障都可能发生。

这意味着每当我们编写一个应该返回一个值的函数，但也可能失败时，这必须在函数接口的某些改变中得到体现。我们有几种可能性。让我们看看如何设计一个将返回一个字符串但也可能失败的函数的接口：

+   使用表示成功的返回值和输出参数：`bool get_string(string&);`

+   返回一个指针（或智能指针），如果失败则可以设置为`nullptr`：`string* get_string();`

+   在失败的情况下抛出异常，并保持函数签名非常简单：`string get_string();`

所有这些方法都有不同的优点和缺点。自 C++17 以来，有一种新类型可以用来以不同的方式解决这样的问题：`std::optional`。可选值的概念来自纯函数式编程语言（有时被称为`Maybe`类型），可以导致非常优雅的代码。

我们可以在我们自己的类型周围包装`optional`，以便表示*空*或*错误*的值。在这个示例中，我们将学习如何做到这一点。

# 如何做到...

在本节中，我们将实现一个程序，从用户那里读取整数并将它们求和。因为用户总是可以输入随机的东西而不是数字，我们将看到`optional`如何改进我们的错误处理：

1.  首先，我们包括所有需要的头文件，并声明我们使用`std`命名空间：

```cpp
      #include <iostream>
      #include <optional>     

      using namespace std;
```

1.  让我们定义一个整数类型，*可能*包含一个值。`std::optional`类型正是这样做的。通过将任何类型包装成`optional`，我们为其赋予了一个额外的可能状态，这反映了它当前*没有*值：

```cpp
      using oint = optional<int>;
```

1.  通过定义了一个可选整数类型，我们可以表达通常返回整数的函数也可能失败。如果我们从用户输入中获取一个整数，这可能会失败，因为用户可能并不总是输入一个整数，即使我们要求他这样做。在这种情况下，返回一个可选整数是完美的。如果读取整数成功，我们将其传递给`optional<int>`构造函数。否则，我们返回一个默认构造的可选值，这表示失败或空：

```cpp
      oint read_int()
      {
          int i;
          if (cin >> i) { return {i}; }
          return {};
      }
```

1.  我们可以做的不仅仅是从可能失败的函数中返回整数。如果我们计算两个可选整数的和会怎样？只有当操作数都包含实际值时，这才可能导致真正的数值和。在任何其他情况下，我们返回一个空的可选变量。这个函数需要更多的解释：通过隐式转换`optional<int>`变量`a`和`b`为布尔表达式（通过写`!a`和`!b`），我们可以知道它们是否包含实际值。如果它们包含实际值，我们可以通过简单地用`*a`和`*b`对它们进行解引用来访问它们，就像指针或迭代器一样：

```cpp
      oint operator+(oint a, oint b)
      {
          if (!a || !b) { return {}; }

          return {*a + *b};
      }
```

1.  将一个普通整数添加到一个可选整数遵循相同的逻辑：

```cpp
      oint operator+(oint a, int b)
      {
          if (!a) { return {}; }

          return {*a + b};
      }
```

1.  现在让我们编写一个程序，对可选整数进行操作。我们让用户输入两个数字：

```cpp
      int main()
      {
          cout << "Please enter 2 integers.n> ";

          auto a {read_int()};
          auto b {read_int()};
```

1.  然后我们添加这些输入数字，并额外添加值 10 到它们的和。由于`a`和`b`是可选整数，`sum`也将是一个可选整数类型的变量：

```cpp
          auto sum (a + b + 10);
```

1.  如果`a`和/或`b`不包含值，那么`sum`也不可能包含值。现在我们的可选整数的好处是，我们不需要显式检查`a`和`b`。当我们对空的可选值求和时会发生什么是完全合理和定义良好的行为，因为我们已经为这些类型安全地定义了`operator+`。这样，我们可以任意地添加许多可能为空的可选整数，我们只需要检查结果的可选值。如果它包含一个值，那么我们可以安全地访问并打印它：

```cpp
          if (sum) {
             cout << *a << " + " << *b << " + 10 = "
                  << *sum << 'n';
```

1.  如果用户输入非数字内容，我们会报错：

```cpp
          } else {
             cout << "sorry, the input was "
                     "something else than 2 numbers.n";
          }
      }
```

1.  就是这样。当我们编译并运行程序时，我们会得到以下输出：

```cpp
      $ ./optional 
      Please enter 2 integers.
      > 1 2
      1 + 2 + 10 = 13
```

1.  再次运行程序并输入非数字内容会产生我们为这种情况准备的错误消息：

```cpp
      $ ./optional 
      Please enter 2 integers.
      > 2 z
      sorry, the input was something else than 2 numbers.
```

# 它是如何工作的...

使用`optional`通常非常简单和方便。如果我们想要将可能失败或可选性的概念附加到任何类型`T`，我们只需将其包装到`std::optional<T>`中，就可以了。

每当我们从某个地方得到这样一个值时，我们必须检查它是否处于空状态或者是否包含了一个真实的值。`bool optional::has_value()`函数为我们做到了这一点。如果它返回`true`，我们可以访问该值。访问可选值的值可以使用`T& optional::value()`来完成。

我们可以使用`if (x) {...}`和`*x`来代替总是写`if (x.has_value()) {...}`和`x.value()`。`std::optional`类型以这样一种方式定义了对`bool`和`operator*`的显式转换，以便处理可选类型类似于处理指针。

另一个方便的操作符助手是`optional`的`operator->`重载。如果我们有一个`struct Foo { int a; string b; }`类型，并且想通过一个`optional<Foo>`变量`x`访问它的成员之一，那么我们可以写`x->a`或`x->b`。当然，我们应该首先检查`x`是否真的有一个值。

如果我们尝试访问一个可选值，即使它没有值，那么它将抛出`std::logic_error`。这样，我们可以在不总是检查它们的情况下处理大量可选值。使用`try-catch`子句，我们可以编写以下形式的代码：

```cpp
cout << "Please enter 3 numbers:n";

try {
    cout << "Sum: " 
         << (*read_int() + *read_int() + *read_int()) 
         << 'n';
} catch (const std::bad_optional_access &) {
    cout << "Unfortunately you did not enter 3 numbersn";
}
```

`std::optional`的另一个妙招是`optional::value_or`。如果我们想取一个可选的值，并在它处于空状态时返回一个默认值，那么这就有帮助了。`x = optional_var.value_or(123)`在一行简洁的代码中完成了这项工作，其中`123`是备用默认值。

# 应用函数到元组

自 C++11 以来，STL 提供了`std::tuple`。这种类型允许我们将多个值偶尔*捆绑*到单个变量中并在周围到达它们。元组的概念在许多编程语言中已经存在很长时间了，本书中的一些示例已经致力于这种类型，因为它非常适用。

然而，有时我们最终会得到一个捆绑在元组中的值，然后需要使用它们的各个成员调用函数。为每个函数参数单独解包成员非常乏味（如果我们在某个地方引入了拼写错误，那么容易出错）。繁琐的形式看起来像这样：`func(get<0>(tup), get<1>(tup), get<2>(tup), ...);`。

在这个示例中，您将学习如何以一种优雅的方式将值打包到元组中并从元组中解包，以便调用一些不知道元组的函数。

# 如何做...

我们将实现一个程序，将值打包到元组中并从元组中解包。然后，我们将看到如何使用元组中的值调用不知道元组的函数：

1.  首先，我们包括了许多头文件，并声明我们使用`std`命名空间：

```cpp
      #include <iostream>
      #include <iomanip>
      #include <tuple>
      #include <functional>
      #include <string>
      #include <list>      

      using namespace std;
```

1.  让我们首先定义一个函数，它接受描述学生的多个参数并打印它们。许多传统或 C 函数接口看起来很相似。

```cpp
      static void print_student(size_t id, const string &name, double gpa)
      {
          cout << "Student " << quoted(name) 
               << ", ID: "   << id 
               << ", GPA: "  << gpa << 'n';
      }
```

1.  在实际程序中，我们动态定义了一个元组类型，并用有意义的学生数据填充它：

```cpp
      int main()
      {
          using student = tuple<size_t, string, double>;
          student john {123, "John Doe"s, 3.7};
```

1.  为了打印这样的对象，我们可以将其分解为其各个成员，并使用这些单独的变量调用`print_student`：

```cpp
          {
              const auto &[id, name, gpa] = john;
              print_student(id, name, gpa);
          }
          cout << "-----n";
```

1.  让我们创建一个以学生元组的初始化列表形式的整套学生：

```cpp
          auto arguments_for_later = {
              make_tuple(234, "John Doe"s,  3.7),
              make_tuple(345, "Billy Foo"s, 4.0),
              make_tuple(456, "Cathy Bar"s, 3.5),
          };
```

1.  我们仍然可以相对舒适地打印它们所有，但是为了分解元组，我们需要关心这样的元组有多少个元素。如果我们不得不编写这样的代码，那么我们也将不得不在函数调用接口发生变化的情况下对其进行重构：

```cpp
          for (const auto &[id, name, gpa] : arguments_for_later) {
              print_student(id, name, gpa);
          }
          cout << "-----n";
```

1.  我们可以做得更好。即使不知道`print_student`的参数类型或学生元组中的成员数量，我们也可以直接使用`std::apply`将元组的内容传递给函数。这个函数接受一个函数指针或函数对象和一个元组，然后*解包*元组以便使用元组成员作为参数调用函数：

```cpp
          apply(print_student, john);
          cout << "-----n";
```

1.  这在循环中也可以很好地工作：

```cpp
          for (const auto &args : arguments_for_later) {
              apply(print_student, args);
          }
          cout << "-----n";
      }
```

1.  编译和运行程序显示，两种方式都可以正常工作，正如我们所假设的那样：

```cpp
      $ ./apply_functions_on_tuples 
      Student "John Doe", ID: 123, GPA: 3.7
      -----
      Student "John Doe", ID: 234, GPA: 3.7
      Student "Billy Foo", ID: 345, GPA: 4
      Student "Cathy Bar", ID: 456, GPA: 3.5
      -----
      Student "John Doe", ID: 123, GPA: 3.7
      -----
      Student "John Doe", ID: 234, GPA: 3.7
      Student "Billy Foo", ID: 345, GPA: 4
      Student "Cathy Bar", ID: 456, GPA: 3.5
      -----
```

# 工作原理...

`std::apply`是一个在编译时帮助我们更不受我们代码中处理的类型的影响的辅助程序。

假设我们有一个包含值`(123, "abc"s, 456.0)`的元组`t`。这个元组的类型是`tuple<int, string, double>`。另外，假设我们有一个签名为`int f(int, string, double)`的函数`f`（类型也可以是引用）。

然后，我们可以写`x = apply(f, t)`，这将导致一个函数调用，`x = f(123, "abc"s, 456.0)`。`apply`方法甚至会返回`f`的返回值。

# 使用 std::tuple 快速组合数据结构

让我们来看一个我们很可能已经知道的元组的基本用例。我们可以定义一个结构如下，以便只是捆绑一些变量：

```cpp
struct Foo {
    int a;
    string b;
    float c;
};
```

我们可以定义一个元组，而不是像前面的例子中那样定义一个结构：

```cpp
using Foo = tuple<int, string, float>;
```

我们可以使用类型列表中的类型的索引号来访问元组的项。为了访问元组的第一个成员，我们可以使用`std::get<0>(t)`，要访问第二个成员，我们写`std::get<1>`，依此类推。如果索引号太大，编译器甚至会安全地报错。

在整本书中，我们已经使用了 C++17 的元组分解功能。它们允许我们通过只需编写`auto [a, b, c] = some_tuple`来快速分解元组，以便访问其各个项。

组合和分解单个数据结构并不是我们可以使用元组做的唯一事情。我们还可以连接或拆分元组，或者进行各种魔术。在这个示例中，我们将玩弄这些功能，以便学习如何做到这一点。

# 如何做...

在本节中，我们将编写一个可以即时打印任何元组的程序。除此之外，我们还将编写一个可以*zip*元组的函数：

1.  首先，我们需要包含一些头文件，然后我们声明默认使用`std`命名空间：

```cpp
      #include <iostream>
      #include <tuple>
      #include <list>
      #include <utility>
      #include <string>
      #include <iterator>
      #include <numeric>
      #include <algorithm>      

      using namespace std;
```

1.  由于我们将处理元组，因此展示它们的内容将是有趣的。因此，我们现在将实现一个非常通用的函数，可以打印任何由可打印类型组成的元组。该函数接受一个输出流引用`os`，用于实际打印，以及一个可变参数列表，其中包含所有元组成员。我们将所有参数分解为第一个元素并将其放入参数`v`中，其余部分存储在参数包`vs...`中：

```cpp
      template <typename T, typename ... Ts>
      void print_args(ostream &os, const T &v, const Ts &...vs)
      {
          os << v;
```

1.  如果参数包`vs`中还有参数，这些参数将使用`initializer_list`扩展技巧交错打印`", "`。您在第二十一章中学习了这个技巧，*Lambda 表达式*：

```cpp
          (void)initializer_list<int>{((os << ", " << vs), 0)...};
      }
```

1.  现在，我们可以通过编写`print_args(cout, 1, 2, "foo", 3, "bar")`来打印任意一组参数，例如。但这与元组无关。为了打印元组，我们通过实现一个模板函数重载流输出运算符`<<`来匹配任何元组特化的情况：

```cpp
      template <typename ... Ts>
      ostream& operator<<(ostream &os, const tuple<Ts...> &t)
      {
```

1.  现在变得有点复杂了。我们首先使用一个 lambda 表达式，任意接受许多参数。每当它被调用时，它将`os`参数放在这些参数之前，然后调用`print_args`，并使用结果新的参数列表。这意味着对`capt_tup(...一些参数...)`的调用会导致对`print_args(os, ...一些参数...)`的调用：

```cpp
          auto print_to_os (&os {
              print_args(os, xs...);
          });
```

1.  现在我们可以进行实际的元组解包魔术。我们使用`std::apply`来解包元组。所有的值都将从元组中取出，然后作为函数参数排列给我们提供的函数。这意味着如果我们有一个元组`t = (1, 2, 3)`，并调用`apply(capt_tup, t)`，那么这将导致一个函数调用`capt_tup(1, 2, 3)`，这又将导致函数调用`print_args(os, 1, 2, 3)`。这正是我们需要的。作为一个很好的额外，我们用括号括起来打印：

```cpp
          os << "(";
          apply(print_to_os, t);
          return os << ")";
      }
```

1.  好的，现在我们写了一些复杂的代码，当我们想要打印一个元组时，这将使我们的生活变得更容易。但是我们可以用元组做更多的事情。例如，让我们编写一个函数，接受一个可迭代的范围，比如一个向量或一组数字的列表，作为参数。这个函数将遍历该范围，然后返回范围中所有数字的*总和*，并将其与所有值的*最小值*、*最大值*和*平均数*捆绑在一起。通过将这四个值打包成一个元组，我们可以将它们作为单个对象返回，而无需定义额外的结构类型：

```cpp
      template <typename T>
      tuple<double, double, double, double>
      sum_min_max_avg(const T &range)
      {
```

1.  `std::minmax_element`函数返回一对迭代器，分别指向输入范围的最小值和最大值。`std::accumulate`方法对其输入范围中的所有值进行求和。这就是我们需要返回适合我们元组的四个值的全部内容！

```cpp
          auto min_max (minmax_element(begin(range), end(range)));
          auto sum     (accumulate(begin(range), end(range), 0.0));
          return {sum, *min_max.first, *min_max.second, 
                  sum / range.size()};
      }
```

1.  在实现主程序之前，我们将实现一个最后的魔术辅助函数。我称它为魔术，因为一开始看起来确实很复杂，但在理解它的工作原理之后，它将变得非常流畅和有用。它将两个元组进行压缩。这意味着如果我们给它一个元组`(1, 2, 3)`，和另一个元组`('a', 'b', 'c')`，它将返回一个元组`(1, 'a', 2, 'b', 3, 'c')`：

```cpp
      template <typename T1, typename T2>
      static auto zip(const T1 &a, const T2 &b)
      {
```

1.  现在我们来到了这个食谱中最复杂的代码行。我们创建了一个函数对象`z`，它接受任意数量的参数。然后它返回另一个函数对象，它捕获所有这些参数在一个参数包`xs`中，但也接受另一个任意数量的参数。让我们沉浸在其中片刻。在这个内部函数对象中，我们可以以参数包`xs`和`ys`的形式访问两个参数列表。现在让我们看看我们实际上如何处理这些参数包。表达式`make_tuple(xs, ys)...`将参数包逐项分组。这意味着如果我们有`xs = 1, 2, 3`和`ys = 'a', 'b', 'c'`，这将导致一个新的参数包`(1, 'a'), (2, 'b'), (3, 'c')`。这是一个逗号分隔的三个元组的列表。为了将它们全部分组在*一个*元组中，我们使用`std::tuple_cat`，它接受任意数量的元组并将它们重新打包成一个元组。这样我们就得到了一个漂亮的`(1, 'a', 2, 'b', 3, 'c')`元组：

```cpp
          auto z ([](auto ...xs) {
              return xs... {
                  return tuple_cat(make_tuple(xs, ys) ...);
              };
          });
```

1.  最后一步是从输入元组`a`和`b`中解包所有值，并将它们推入`z`。表达式`apply(z, a)`将`a`中的所有值放入参数包`xs`中，`apply(..., b)`将`b`中的所有值放入参数包`ys`中。结果的元组是大的压缩元组，我们将其返回给调用者：

```cpp
          return apply(apply(z, a), b);
      }
```

1.  我们在辅助/库代码中投入了相当多的行。现在让我们最终将它们投入使用。首先，我们构造一些任意的元组。`student`包含学生的 ID、姓名和 GPA 分数。`student_desc`包含描述这些字段在人类可读形式中意味着什么的字符串。`std::make_tuple`是一个非常好的辅助函数，因为它自动推断所有参数的类型并创建一个合适的元组类型：

```cpp
      int main()
      {
          auto student_desc (make_tuple("ID", "Name", "GPA"));
          auto student      (make_tuple(123456, "John Doe", 3.7));
```

1.  让我们打印一下我们所拥有的。这很简单，因为我们刚刚为它实现了正确的`operator<<`重载：

```cpp
          cout << student_desc << 'n'
               << student      << 'n';
```

1.  我们还可以使用`std::tuple_cat`在飞行中对元组进行分组并像这样打印它们：

```cpp
          cout << tuple_cat(student_desc, student) << 'n';
```

1.  我们还可以使用我们的`zip`函数创建一个新的*zipped*元组，并打印它：

```cpp
          auto zipped (zip(student_desc, student));
          cout << zipped << 'n';
```

1.  不要忘记我们的`sum_min_max_avg`函数。我们创建了一个包含一些数字的初始化列表，并将其传递给这个函数。为了使它变得更加复杂，我们创建了另一个相同大小的元组，其中包含一些描述字符串。通过压缩这些元组，我们得到了一个漂亮的、交错的输出，当我们运行程序时会看到：

```cpp
          auto numbers = {0.0, 1.0, 2.0, 3.0, 4.0};
          cout << zip(
                  make_tuple("Sum", "Minimum", "Maximum", "Average"),
                  sum_min_max_avg(numbers))
               << 'n';
      }
```

1.  编译和运行程序产生以下输出。前两行只是单独的`student`和`student_desc`元组。第 3 行是我们通过使用`tuple_cat`得到的元组组合。第 4 行包含了压缩的学生元组。在最后一行，我们看到了我们上次创建的数字列表的总和、最小值、最大值和平均值。由于压缩，很容易看出每个值的含义：

```cpp
      $ ./tuple
      (ID, Name, GPA)
      (123456, John Doe, 3.7)
      (ID, Name, GPA, 123456, John Doe, 3.7)
      (ID, 123456, Name, John Doe, GPA, 3.7)
      (Sum, 10, Minimum, 0, Maximum, 4, Average, 2)
```

# 它是如何工作的...

这一部分的一些代码确实很复杂。我们为元组编写了一个`operator<<`实现，看起来非常复杂，但支持所有由可打印类型组成的元组。然后我们实现了`sum_min_max_avg`函数，它只返回一个元组。我们头脑中非常复杂的另一件事是`zip`函数。

最容易的部分是`sum_min_max_avg`。关于它的要点是，当我们定义一个返回实例`tuple<Foo`，`Bar`，`Baz> f()`的函数时，我们可以在该函数中写`return {foo_instance, bar_instance, baz_instance};`来构造这样一个元组。如果您对我们在`sum_min_max_avg`函数中使用的 STL 算法有困难，那么您可能想看看本书的第二十二章 *STL 算法基础*，在那里我们已经仔细研究了它们。

其他代码太复杂了，我们将专门的辅助程序分配给它们自己的子部分：

# 元组的 operator<<

在我们甚至触及输出流的`operator<<`之前，我们实现了`print_args`函数。由于它的可变参数性质，它接受任意数量和类型的参数，只要第一个参数是`ostream`实例：

```cpp
template <typename T, typename ... Ts>
void print_args(ostream &os, const T &v, const Ts &...vs)
{
    os << v;

    (void)initializer_list<int>{((os << ", " << vs), 0)...};
}
```

这个函数打印第一个项目`v`，然后打印参数包`vs`中的所有其他项目。我们单独打印第一个项目，因为我们希望所有项目都与`", "`交错，但我们不希望这个字符串领先或尾随整个列表（就像`"1, 2, 3, "`或`", 1, 2, 3"`）。我们在第二十一章 *Lambda 表达式*的*使用相同输入调用多个函数*中学习了`initializer_list`扩展技巧。

有了这个函数，我们就可以打印元组所需的一切。我们的`operator<<`实现如下：

```cpp
template <typename ... Ts>
ostream& operator<<(ostream &os, const tuple<Ts...> &t)
{
    auto capt_tup (&os {
        print_args(os, xs...);
    });

    os << "(";
    apply(capt_tup, t);
    return os << ")";
}
```

我们要做的第一件事是定义函数对象`capt_tup`。当我们调用`capt_tup(foo, bar, whatever)`时，这会导致调用`print_args(**os,** foo, bar, whatever)`。这个函数对象唯一要做的就是将输出流对象`os`放在它的可变参数列表之前。

之后，我们使用`std::apply`来解包元组`t`中的所有项目。如果这一步看起来太复杂，请看看这之前的一篇文章，专门介绍了`std::apply`的工作原理。

# 元组的 zip 函数

`zip`函数接受两个元组，但看起来非常复杂，尽管它有一个非常清晰的实现：

```cpp
template <typename T1, typename T2>
auto zip(const T1 &a, const T2 &b)
{
    auto z ([](auto ...xs) {
        return xs... {
            return tuple_cat(make_tuple(xs, ys) ...);
        };
    });
    return apply(apply(z, a), b);
}
```

为了更好地理解这段代码，想象一下元组`a`携带值`1, 2, 3`，元组`b`携带值`'a', 'b', 'c'`。

在这种情况下，调用`apply(z, a)`会导致调用`z(1, 2, 3)`的函数调用，它返回另一个捕获这些值`1, 2, 3`的函数对象，放入参数包`xs`中。然后，当这个函数对象被`apply(z(1, 2, 3), b)`调用时，它会将值`'a', 'b', 'c'`填入参数包`ys`中。这基本上与直接调用`z(1, 2, 3)('a', 'b', 'c')`是一样的。

好了，现在我们有了`xs = (1, 2, 3)`和`ys = ('a', 'b', 'c')`，然后会发生什么？表达式`tuple_cat(make_tuple(xs, ys) ...)`进行了以下魔术；看一下图表：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/54ce6577-8405-4849-a5bb-40c6235b6d5b.png)

首先，`xs`和`ys`中的项目通过成对交错地进行了配对。这种“成对交错”发生在`make_tuple(xs, ys) ...`表达式中。这最初只导致一个包含两个项目的元组的可变列表。为了获得*一个大*元组，我们对它们应用`tuple_cat`，然后最终得到一个包含初始元组的所有成员的大的串联元组。

# 用 std::any 替换 void*以获得更多的类型安全

有时我们希望在变量中存储*任何*类型的项目。对于这样的变量，我们需要能够检查它是否包含*任何东西*，如果包含，我们需要能够区分*它包含什么*。所有这些都需要以类型安全的方式发生。

在过去，我们基本上能够在`void*`指针中存储指向各种对象的指针。`void`类型的指针本身无法告诉我们它指向什么类型的对象，因此我们需要手工制作一种额外的机制来告诉我们应该期望什么。这样的代码很快就会导致看起来古怪和不安全的代码。

C++17 对 STL 的另一个补充是`std::any`类型。它旨在保存任何类型的变量，并提供了使其能够进行类型安全检查和访问的功能。

在这个示例中，我们将使用这种实用类型来感受一下它。

# 如何做...

我们将实现一个函数，试图能够打印一切。它使用`std::any`作为参数类型：

1.  首先，我们包含一些必要的头文件，并声明我们使用`std`命名空间：

```cpp
      #include <iostream>
      #include <iomanip>
      #include <list>
      #include <any>
      #include <iterator>     

      using namespace std;
```

1.  为了减少以下程序中尖括号语法的数量，我们为`list<int>`定义了一个别名，稍后我们将使用它：

```cpp
      using int_list = list<int>;
```

1.  让我们实现一个声称能够打印任何东西的函数。承诺是以`std::any`变量的形式打印任何提供的参数：

```cpp
      void print_anything(const std::any &a)
      {
```

1.  我们需要检查的第一件事是参数是否包含*任何东西*，或者它只是一个空的`any`实例。如果是空的，那么试图弄清楚如何打印它就没有意义：

```cpp
          if (!a.has_value()) {
              cout << "Nothing.n";
```

1.  如果不为空，我们可以尝试将其与不同的类型进行比较，直到找到匹配项。首先要尝试的类型是`string`。如果是`string`，我们可以使用`std::any_cast`将`a`转换为`string`类型的引用，并直接打印它。我们将字符串放在引号中是为了美观的原因：

```cpp
          } else if (a.type() == typeid(string)) {
              cout << "It's a string: "
                   << quoted(any_cast<const string&>(a)) << 'n';
```

1.  如果不是`string`，可能是`int`。如果这种类型匹配，我们可以使用`any_cast<int>`来获取实际的`int`值：

```cpp
          } else if (a.type() == typeid(int)) {
              cout << "It's an integer: "
                   << any_cast<int>(a) << 'n';
```

1.  `std::any`不仅适用于`string`和`int`等简单类型。我们还可以将整个映射或列表或任何组成的复杂数据结构放入`any`变量中。让我们看看输入是否是整数列表，如果是，我们可以像打印列表一样打印它：

```cpp
          } else if (a.type() == typeid(int_list)) {
              const auto &l (any_cast<const int_list&>(a));

              cout << "It's a list: ";
              copy(begin(l), end(l), 
                   ostream_iterator<int>{cout, ", "});
              cout << 'n';
```

1.  如果这些类型都不匹配，我们就无法猜测类型了。在这种情况下，让我们放弃，并告诉用户我们不知道如何打印这个：

```cpp
          } else {
              cout << "Can't handle this item.n";
          }
      }
```

1.  在主函数中，我们现在可以使用任意类型调用这个函数。我们可以使用空的`any`变量`{}`调用它，或者用字符串`"abc"`或整数来调用它。因为`std::any`可以从这些类型隐式构造，所以没有语法开销。我们甚至可以构造一个完整的列表并将其传递给这个函数：

```cpp
      int main()
      {
          print_anything({});
          print_anything("abc"s);
          print_anything(123);
          print_anything(int_list{1, 2, 3});
```

1.  如果我们要将真正昂贵的对象放入`any`变量中，我们也可以执行*就地*构造。让我们尝试一下我们的列表类型。`in_place_type_t<int_list>{}`表达式是一个空对象，它给`any`的构造函数提供了足够的信息，以知道我们将要构造什么。第二个参数`{1, 2, 3}`只是一个初始化列表，将被馈送到嵌入在`any`变量中用于构造的`int_list`中。这样，我们避免了不必要的复制或移动：

```cpp
          print_anything(any(in_place_type_t<int_list>{}, {1, 2, 3}));
      }
```

1.  编译和运行程序产生了以下输出，这正是我们所期望的：

```cpp
      $ ./any 
      Nothing.
      It's a string: "abc"
      It's an integer: 123
      It's a list: 1, 2, 3, 
      It's a list: 1, 2, 3, 
```

# 它是如何工作的...

`std::any`类型在一个方面类似于`std::optional`--它有一个`has_value()`方法，告诉实例是否携带值。但除此之外，它可以包含任何东西，因此与`optional`相比，处理起来更加复杂。

在访问`any`变量的内容之前，我们需要找出它携带的*是什么*类型，然后将其*转换*为该类型。

找出`any`实例是否持有类型`T`值可以通过比较来完成：`x.type() == typeid(T)`。如果这个比较结果为`true`，那么我们可以使用`any_cast`来获取内容。

请注意，`any_cast<T>(x)`返回`x`中内部`T`值的*副本*。如果我们想要一个*引用*，以避免复制复杂对象，我们需要使用`any_cast<T&>(x)`。这就是我们在本节代码中访问内部`string`或`list<int>`对象时所做的。

如果我们将`any`的实例转换为错误的类型，它将抛出一个`std::bad_any_cast`异常。

# 使用 std::variant 存储不同类型

在 C++中不仅有`struct`和`class`原语可以让我们组合类型。如果我们想表达某个变量可以容纳类型`A`或类型`B`（或`C`，或其他任何类型），我们可以使用`union`。联合的问题在于它们无法告诉我们它们实际上是初始化为可以容纳的类型中的哪一个。

考虑以下代码：

```cpp
union U { 
    int    a;
    char  *b; 
    float  c;
};

void func(U u) { std::cout << u.b << 'n'; }
```

如果我们使用一个初始化为通过成员`a`持有整数的联合来调用`func`函数，没有任何阻止我们访问它的东西，就好像它是通过成员`b`持有指向字符串的指针初始化的一样。这样的代码可能传播各种错误。在我们开始用一个辅助变量来打包我们的联合，告诉我们它是为了获得一些安全性而初始化的之前，我们可以直接使用 C++17 中提供的`std::variant`。

`variant`有点像*新式*、类型安全和高效的联合类型。它不使用堆，因此它与基于联合的手工制作的解决方案一样空间和时间高效，因此我们不必自己实现它。它可以存储除了引用、数组或`void`类型之外的任何东西。

在这个示例中，我们将构建一个利用`variant`来获得如何使用 STL 这个新功能的示例。

# 如何做...

让我们实现一个程序，它知道类型`cat`和`dog`，并且存储了一个混合的猫和狗列表，而不使用任何运行时多态：

1.  首先，我们包括所有需要的头文件，并定义我们使用`std`命名空间：

```cpp
      #include <iostream>
      #include <variant>
      #include <list>
      #include <string>
      #include <algorithm>      

      using namespace std;
```

1.  接下来，我们实现两个具有类似功能的类，但彼此之间没有任何其他关联，与那些例如继承自相同接口或类似接口的类相反。第一个类是`cat`。一个`cat`对象有一个名字，可以说*meow*：

```cpp
      class cat {
          string name;

      public:
          cat(string n) : name{n} {}

          void meow() const {
              cout << name << " says Meow!n";
          }
      };
```

1.  另一个类是`dog`。一个`dog`对象不会说*meow*，而是*woof*，当然：

```cpp
      class dog {
          string name;

      public:
          dog(string n) : name{n} {}

          void woof() const {
              cout << name << " says Woof!n";
          }
      };
```

1.  现在我们可以定义一个`animal`类型，它只是一个到`std::variant<dog, cat>`的类型别名。这基本上与老式联合相同，但具有`variant`提供的所有额外功能：

```cpp
      using animal = variant<dog, cat>;
```

1.  在编写主程序之前，我们首先实现了两个帮助器。一个帮助器是一个动物谓词。通过调用`is_type<cat>(...)`或`is_type<dog>(...)`，我们可以找出动物变体实例是否持有`cat`或`dog`。实现只是调用`holds_alternative`，这是一个用于变体类型的通用谓词函数：

```cpp
      template <typename T>
      bool is_type(const animal &a) {
          return holds_alternative<T>(a);
      }
```

1.  第二个帮助器是一个充当函数对象的结构。它是一个双重的函数对象，因为它实现了两次`operator()`。一个实现是一个重载，接受狗，另一个接受猫。对于这些类型，它只是调用`woof`或`meow`函数：

```cpp
      struct animal_voice
      {
          void operator()(const dog &d) const { d.woof(); }
          void operator()(const cat &c) const { c.meow(); }
      };
```

1.  让我们把这些类型和帮助器用起来。首先，我们定义了一个`animal`变体实例列表，并用猫和狗填充它：

```cpp
      int main()
      {
          list<animal> l {cat{"Tuba"}, dog{"Balou"}, cat{"Bobby"}};
```

1.  现在，我们将三次打印列表的内容，每次以不同的方式。一种方法是使用`variant::index()`。因为`animal`是`variant<dog, cat>`的别名，返回值为`0`意味着变体持有`dog`实例。索引`1`表示它是`cat`。这里关键是变体专门化中类型的顺序。在 switch case 块中，我们使用`get<T>`访问变体，以获取内部的实际`cat`或`dog`实例：

```cpp
          for (const animal &a : l) {
              switch (a.index()) {
              case 0: 
                  get<dog>(a).woof();
                  break;
              case 1:
                  get<cat>(a).meow();
                  break;
              }
          }
          cout << "-----n";
```

1.  我们可以明确要求每种类型，而不是使用类型的数字索引。`get_if<dog>`返回一个指向内部`dog`实例的`dog`类型指针。如果内部没有`dog`实例，则指针为`null`。这样，我们可以尝试获取不同类型，直到最终成功：

```cpp
          for (const animal &a : l) {
              if (const auto d (get_if<dog>(&a)); d) {
                  d->woof();
              } else if (const auto c (get_if<cat>(&a)); c) {
                  c->meow();
              }
          }
          cout << "-----n";
```

1.  最后，最优雅的方法是`variant::visit`。此函数接受一个函数对象和一个变体实例。函数对象必须为变体可以容纳的所有可能类型实现不同的重载。我们之前实现了一个具有正确`operator()`重载的结构，因此可以在这里使用它：

```cpp
          for (const animal &a : l) {
              visit(animal_voice{}, a);
          }
          cout << "-----n";
```

1.  最后，我们将计算变体列表中猫和狗的数量。`is_type<T>`谓词可以专门用于`cat`和`dog`，然后可以与`std::count_if`结合使用，以返回此类型的实例数：

```cpp
          cout << "There are "
               << count_if(begin(l), end(l), is_type<cat>)
               << " cats and "
               << count_if(begin(l), end(l), is_type<dog>)
               << " dogs in the list.n";
      }
```

1.  首先编译和运行程序会打印相同的列表三次。之后，我们看到`is_type`谓词与`count_if`结合使用效果很好：

```cpp
      $ ./variant 
      Tuba says Meow!
      Balou says Woof!
      Bobby says Meow!
      -----
      Tuba says Meow!
      Balou says Woof!
      Bobby says Meow!
      -----
      Tuba says Meow!
      Balou says Woof!
      Bobby says Meow!
      -----
      There are 2 cats and 1 dogs in the list.
```

# 它是如何工作的...

`std::variant`类型有点类似于`std::any`，因为两者都可以持有不同类型的对象，并且我们需要在运行时区分它们确切地持有什么，然后再尝试访问它们的内容。

另一方面，`std::variant`与`std::any`不同之处在于，我们必须声明它应该能够以模板类型列表的形式存储什么。`std::variant<A, B, C>`的实例*必须*持有`A`、`B`或`C`类型的一个实例。没有可能持有*它们中的任何一个*，这意味着`std::variant`没有*可选性*的概念。

类型为`variant<A, B, C>`的变体模拟了一个联合类型，可能如下所示：

```cpp
union U {
    A a;
    B b;
    C c;
};
```

联合的问题在于我们需要构建自己的机制来区分它是用`A`、`B`还是`C`变量初始化的。`std::variant`类型可以在不费吹灰之力的情况下为我们做到这一点。

在本节的代码中，我们使用了三种不同的方法来处理变体变量的内容。

第一种方法是`variant`的`index()`函数。对于变体类型`variant<A, B, C>`，如果它被初始化为持有`A`类型，则可以返回索引`0`，对于`B`，则为`1`，对于`C`，则为`2`，对于更复杂的变体，依此类推。

接下来的方法是`get_if<T>`函数。它接受一个变体对象的地址，并返回一个`T`类型的指针指向其内容。如果`T`类型错误，那么这个指针将是一个`null`指针。还可以在变体变量上调用`get<T>(x)`，以便获得对其内容的引用，但如果失败，此函数会抛出异常（在进行这种`get`-casts 之前，可以使用布尔谓词`holds_alternative<T>(x)`来检查正确的类型）。

访问 variant 的最后一种方式是 `std::visit` 函数。它接受一个函数对象和一个 `variant` 实例。`visit` 函数然后检查 variant 的内容是哪种类型，然后调用函数对象的正确的 `operator()` 重载。

正是为了这个目的，我们实现了 `animal_voice` 类型，因为它可以与 `visit` 和 `variant<dog, cat>` 结合使用：

```cpp
struct animal_voice
{
    void operator()(const dog &d) const { d.woof(); }
    void operator()(const cat &c) const { c.meow(); }
};
```

访问 variant 的 `visit` 方式可以被认为是最优雅的，因为实际访问 variant 的代码部分不需要硬编码到 variant 可以保存的类型。这使得我们的代码更容易扩展。

`variant` 类型不能保存 *没有* 值的说法并不完全正确。通过将 `std::monostate` 类型添加到其类型列表中，它确实可以被初始化为 *没有* 值。

# 使用 std::unique_ptr 自动处理资源

自 C++11 以来，STL 提供了智能指针，可以真正帮助跟踪动态内存及其处理。即使在 C++11 之前，也有一个称为 `auto_ptr` 的类，它已经能够进行自动内存处理，但很容易以错误的方式使用。

然而，使用 C++11 生成的智能指针，我们很少需要自己编写 `new` 和 `delete`，这是一件非常好的事情。智能指针是自动内存管理的一个光辉例子。如果我们使用 `unique_ptr` 维护动态分配的对象，我们基本上不会有内存泄漏，因为在其销毁时，该类会自动调用 `delete` 来释放它维护的对象。

唯一指针表示对其指向的对象的所有权，并在不再使用时遵循释放其内存的责任。这个类有潜力永远解决我们的内存泄漏问题（至少与其伴侣 `shared_ptr` 和 `weak_ptr` 一起，但在这个示例中，我们只集中在 `unique_ptr` 上）。最好的是，与使用原始指针和手动内存管理的代码相比，它对空间和运行时性能没有额外的开销。（好吧，它在销毁指向的对象后在内部将其内部原始指针设置为 `nullptr`，这不能总是被优化掉。大多数手动编写管理动态内存的代码也是这样。）

在这个示例中，我们将看看 `unique_ptr` 以及如何使用它。

# 如何做...

我们将编写一个程序，通过创建一个自定义类型，该类型在其构造和销毁时添加一些调试消息，以显示我们如何使用 `unique_ptr` 处理内存。然后，我们将使用唯一指针来维护动态分配的实例：

1.  首先，我们包含必要的头文件，并声明我们使用 `std` 命名空间：

```cpp
      #include <iostream>
      #include <memory>  

      using namespace std;
```

1.  我们将为我们将使用 `unique_ptr` 管理的对象实现一个小类。它的构造函数和析构函数会打印到终端，这样我们以后就可以看到它何时被自动删除。

```cpp
      class Foo
      {
      public:
          string name;

          Foo(string n)
              : name{move(n)}
          { cout << "CTOR " << name << 'n'; }

          ~Foo() { cout << "DTOR " << name << 'n'; }
      };
```

1.  为了查看接受唯一指针作为参数的函数有什么限制，我们只需实现一个函数。它通过打印其名称来 *处理* 一个 Foo 项。请注意，虽然唯一指针很聪明，没有额外开销，并且非常安全，但它们仍然可能是 `null`。这意味着我们在解引用它们之前仍然需要检查它们：

```cpp
      void process_item(unique_ptr<Foo> p)
      {
          if (!p) { return; }

          cout << "Processing " << p->name << 'n';
      }
```

1.  在主函数中，我们将打开另一个作用域，在堆上创建两个 `Foo` 对象，并使用唯一指针管理两个对象。我们使用 `new` 运算符显式在堆上创建第一个对象，然后将其放入 `unique_ptr<Foo>` 变量 `p1` 的构造函数中。我们通过调用 `make_unique<Foo>` 创建唯一指针 `p2`，并使用我们否则直接提供给 `Foo` 构造函数的参数。这是更加优雅的方式，因为我们可以使用自动类型推断，而且第一次访问对象时，它已经由 `unique_ptr` 管理：

```cpp
      int main()
      {
          {
              unique_ptr<Foo> p1 {new Foo{"foo"}};
              auto            p2 (make_unique<Foo>("bar"));
          }
```

1.  我们离开作用域后，两个对象立即被销毁，它们的内存被释放到堆中。现在让我们来看一下`process_item`函数以及如何在`unique_ptr`中使用它。如果我们在函数调用中构造一个由`unique_ptr`管理的新的`Foo`实例，那么它的生命周期将缩短到函数的作用域。当`process_item`返回时，对象被销毁：

```cpp
          process_item(make_unique<Foo>("foo1"));
```

1.  如果我们想要使用已经存在的对象调用`process_item`，那么我们需要*转移所有权*，因为该函数通过值传递了一个`unique_ptr`，这意味着调用它会导致复制。但`unique_ptr`不能被复制，它只能被*移动*。让我们创建两个新的`Foo`对象，并将其中一个移动到`process_item`中。通过稍后查看终端输出，我们将看到`foo2`在`process_item`返回时被销毁，因为我们将所有权转移到了它。`foo3`将继续存在，直到主函数返回：

```cpp
          auto p1 (make_unique<Foo>("foo2"));
          auto p2 (make_unique<Foo>("foo3"));

          process_item(move(p1));

          cout << "End of main()n";
      }
```

1.  让我们编译并运行程序。首先，我们看到了`foo`和`bar`的构造函数和析构函数调用。它们确实在程序离开额外的作用域后立即被销毁。请注意，对象的销毁顺序与它们的创建顺序相反。下一个构造函数行来自`foo1`，这是我们在`process_item`调用期间创建的项目。它确实在函数调用后立即被销毁。然后我们创建了`foo2`和`foo3`。`foo2`在我们转移所有权的`process_item`调用后立即被销毁。而另一个项目`foo3`则是在主函数的最后一行代码后被销毁：

```cpp
      $ ./unique_ptr 
      CTOR foo
      CTOR bar
      DTOR bar
      DTOR foo
      CTOR foo1
      Processing foo1
      DTOR foo1
      CTOR foo2
      CTOR foo3
      Processing foo2
      DTOR foo2
      End of main()
      DTOR foo3
```

# 它的工作原理...

使用`std::unique_ptr`处理堆对象非常简单。在初始化唯一指针以持有指向某个对象的指针后，我们*无法*在某些代码路径上意外*忘记*删除它。

如果我们将某个新指针分配给唯一指针，那么它将始终首先删除它指向的旧对象，然后存储新指针。在唯一指针变量`x`上，我们还可以调用`x.reset()`来立即删除它指向的对象，而不分配新指针。通过`x = new_pointer`重新分配的另一个等效替代方法是`x.reset(new_pointer)`。

确实有一种方法可以释放`unique_ptr`管理的对象，而不删除它。`release`函数可以做到这一点，但在大多数情况下不建议使用这个函数。

由于指针在实际解引用之前需要进行检查，它们以一种使它们能够模拟原始指针的方式重载了正确的运算符。条件语句如`if (p) {...}`和`if (p != nullptr) {...}`的执行方式与我们检查原始指针的方式相同。

通过`get()`函数可以对唯一指针进行解引用，该函数返回一个可以进行解引用的对象的原始指针，或者直接通过`operator*`进行解引用，这再次模拟了原始指针。

`unique_ptr`的一个重要特性是，它的实例不能被*复制*，但可以从一个`unique_ptr`变量*移动*到另一个。这就是为什么我们必须将现有的唯一指针移动到`process_item`函数中的原因。如果我们能够复制一个唯一指针，那么这意味着被指向的对象由*两个*唯一指针拥有，尽管这与*唯一*指针的设计相矛盾，它是底层对象的*唯一* *所有者*（后来是“*删除器”*）。

由于存在`unique_ptr`和`shared_ptr`等数据结构，因此很少有理由直接使用`new`创建堆对象并手动`delete`它们。无论何时都要使用这些类！特别是`unique_ptr`在运行时*没有*开销。

# 使用 std::shared_ptr 自动处理共享堆内存

在上一个示例中，我们学习了如何使用`unique_ptr`。这是一个非常有用和重要的类，因为它帮助我们管理动态分配的对象。但它只能处理*单一*所有权。不可能让*多个*对象拥有相同的动态分配对象，因为这样，谁后来删除它将是不清楚的。

指针类型`shared_ptr`专门为这种情况而设计。共享指针可以任意*复制*。内部引用计数机制跟踪有多少对象仍然维护对载荷对象的指针。只有最后一个共享指针离开范围时，才会调用载荷对象的`delete`。这样，我们可以确保我们不会因为对象在使用后自动删除而导致内存泄漏。同时，我们可以确保它们不会过早或过频繁地被删除（每个创建的对象只能被删除*一次*）。

在这个示例中，您将学习如何使用`shared_ptr`来自动管理在多个所有者之间共享的动态对象，并了解与`unique_ptr`相比有何不同的地方：

# 如何做...

我们将编写一个类似于我们在`unique_ptr`示例中编写的程序，以便深入了解`shared_ptr`的用法和原则：

1.  首先，我们只包括必要的头文件，并声明我们默认使用`std`命名空间：

```cpp
      #include <iostream>
      #include <memory>      

      using namespace std;
```

1.  然后我们定义一个小的辅助类，它可以帮助我们看到它的实例何时被创建和销毁。我们将使用`shared_ptr`来管理它的实例：

```cpp
      class Foo
      {
      public:
          string name;

          Foo(string n)
              : name{move(n)}
          { cout << "CTOR " << name << 'n'; }

          ~Foo() { cout << "DTOR " << name << 'n'; }
      };
```

1.  接下来，我们实现一个函数，该函数通过值接受一个指向`Foo`实例的共享指针。通过值接受共享指针作为参数比通过引用接受更有趣，因为在这种情况下，它们需要被复制，这会改变它们的内部引用计数，我们将会看到：

```cpp
      void f(shared_ptr<Foo> sp)
      {
          cout << "f: use counter at " 
               << sp.use_count() << 'n';
      }
```

1.  在主函数中，我们声明一个空的共享指针。通过默认构造它，它实际上是一个`null`指针：

```cpp
      int main()
      {
          shared_ptr<Foo> fa;
```

1.  接下来，我们打开另一个范围并实例化两个`Foo`对象。我们使用`new`运算符创建第一个对象，然后将其传递给一个新的`shared_ptr`的构造函数。然后我们使用`make_shared<Foo>`创建第二个实例，它从我们提供的参数创建一个`Foo`实例。这是更优雅的方法，因为我们可以使用自动类型推断，并且在我们有机会第一次访问它时，对象已经被管理。在这一点上，这与`unique_ptr`示例非常相似：

```cpp
          {
              cout << "Inner scope beginn";

              shared_ptr<Foo> f1 {new Foo{"foo"}};
              auto            f2 (make_shared<Foo>("bar"));
```

1.  由于共享指针可以被共享，它们需要跟踪有多少方共享它们。这是通过内部引用计数或*use*计数来完成的。我们可以使用`use_count`打印它的值。此时的值正好是`1`，因为我们还没有复制它。我们可以将`f1`复制到`fa`，这会将使用计数增加到`2`。

```cpp
              cout << "f1's use counter at " << f1.use_count() << 'n';
              fa = f1;
              cout << "f1's use counter at " << f1.use_count() << 'n';
```

1.  在我们离开范围时，共享指针`f1`和`f2`被销毁。`f1`变量的引用计数再次减少到`1`，使`fa`成为`Foo`实例的唯一所有者。当`f2`被销毁时，它的引用计数减少到`0`。在这种情况下，`shared_ptr`指针的析构函数将调用`delete`来处理它：

```cpp
          }
          cout << "Back to outer scopen";

          cout << fa.use_count() << 'n';
```

1.  现在，让我们以两种不同的方式使用我们的共享指针调用`f`函数。首先，我们通过复制`fa`来天真地调用它。`f`函数将打印出引用计数为`2`的值。在对`f`的第二次调用中，我们将指针移动到函数中。这使得`f`成为对象的唯一所有者：

```cpp
          cout << "first f() calln";
          f(fa);
          cout << "second f() calln";
          f(move(fa));
```

1.  在`f`被返回后，`Foo`实例立即被销毁，因为我们不再拥有它。因此，当主函数返回时，所有对象都已经被销毁：

```cpp
          cout << "end of main()n";
      }
```

1.  编译和运行程序产生以下输出。一开始，我们看到`"foo"`和`"bar"`被创建。在我们复制`f1`（指向`"foo"`）时，它的引用计数增加到`2`。在离开作用域时，"bar"被销毁，因为指向它的共享指针是唯一的所有者。输出中的单个`1`是`fa`的引用计数，它现在是`"foo"`的唯一所有者。之后，我们调用函数`f`两次。在第一次调用时，我们将`fa`复制到其中，这再次给它一个引用计数为`2`。在第二次调用时，我们将其移动到`f`中，这不会改变它的引用计数。此外，因为此时`f`是`"foo"`的唯一所有者，对象在`f`离开作用域后立即被销毁。这样，在`main`中的最后一行打印后，没有其他堆对象被销毁：

```cpp
      $ ./shared_ptr
      Inner scope begin
      CTOR foo
      CTOR bar
      f1's use counter at 1
      f1's use counter at 2
      DTOR bar
      Back to outer scope
      1
      first f() call
      f: use counter at 2
      second f() call
      f: use counter at 1
      DTOR foo
      end of main()
```

# 它是如何工作的...

在构造和删除对象时，`shared_ptr`的工作原理基本上与`unique_ptr`相似。构造共享指针的方式与创建唯一指针类似（尽管有一个函数`make_shared`，它创建共享对象作为`unique_ptr`指针的`make_unique`函数的对应物）。

与`unique_ptr`的主要区别在于我们可以复制`shared_ptr`实例，因为共享指针与它们管理的对象一起维护一个所谓的*控制块*。控制块包含指向有效负载对象的指针和引用计数或*使用*计数器。如果有`N`个`shared_ptr`实例指向对象，则使用计数器的值也为`N`。每当`shared_ptr`实例被销毁时，它的析构函数会递减这个内部使用计数器。对于这样一个对象的最后一个共享指针将满足条件，在其销毁期间将使用计数器递减到`0`。这是，然后，共享指针实例，它在有效负载对象上调用`delete`运算符！这样，我们不可能遭受内存泄漏，因为对象的使用计数会自动跟踪。

为了更好地说明这一点，让我们来看一下下面的图表：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/4d305c80-4368-4efd-945c-8a4debac7d23.png)

在第 1 步中，我们有两个管理类型为`Foo`的对象的`shared_ptr`实例。使用计数器的值为`2`。然后，`shared_ptr2`被销毁，这将使用计数器减少到`1`。`Foo`实例尚未被销毁，因为还有另一个共享指针。在第 3 步中，最后一个共享指针也被销毁。这导致使用计数器减少到`0`。第 4 步发生在第 3 步之后立即。控制块和`Foo`实例都被销毁，它们的内存被释放到堆上。

有了`shared_ptr`和`unique_ptr`，我们可以自动处理大多数动态分配的对象，而不必再担心内存泄漏。然而，有一个重要的警告需要考虑——想象一下，我们在堆上有两个包含彼此的共享指针的对象，还有其他共享指针从其他地方指向其中一个。如果外部共享指针超出范围，那么两个对象仍然具有*非零*值的使用计数，因为它们相互引用。这会导致*内存泄漏*。在这种情况下不应该使用共享指针，因为这样的循环引用链会阻止这些对象的使用计数永远达到`0`。

# 还有更多...

看看下面的代码。如果告诉你它包含潜在的*内存泄漏*，会怎么样？

```cpp
void function(shared_ptr<A>, shared_ptr<B>, int);
// "function" is defined somewhere else

// ...somewhere later in the code:
function(new A{}, new B{}, other_function());
```

"内存泄漏在哪里？"，有人可能会问，因为新分配的对象`A`和`B`立即被输入到`shared_ptr`类型中，*然后*我们就不再担心内存泄漏了。

是的，事实上，一旦指针被捕获在`shared_ptr`实例中，我们就不再担心内存泄漏了。问题有点棘手，需要理解。

当我们调用一个函数，`f(x(), y(), z())`，编译器需要组装代码，先调用`x()`，`y()`和`z()`，这样它才能将它们的返回值转发给`f`。与之前的例子结合起来，这样做会让我们非常糟糕，因为编译器可以以*任何*顺序执行这些函数调用到`x`，`y`和`z`。

回顾一下这个例子，如果编译器决定以一种方式构造代码，首先调用`new A{}`，然后调用`other_function()`，最后调用`new B{}`，然后再将这些函数的结果最终传递给`function`，如果`other_function()`抛出异常，我们会得到一个内存泄漏，因为我们仍然在堆上有一个未管理的对象`A`，因为我们刚刚分配了它，但没有机会将其交给`shared_ptr`的管理。无论我们如何捕获异常，对象的句柄都已经*消失*，我们*无法删除*它！

有两种简单的方法可以避免这个问题：

```cpp
// 1.)
function(make_shared<A>(), make_shared<B>(), other_function());

// 2.)
shared_ptr<A> ap {new A{}};
shared_ptr<B> bp {new B{}};
function(ap, bp, other_function());
```

这样，对象已经由`shared_ptr`管理，无论之后谁抛出了什么异常。

# 处理指向共享对象的弱指针

在关于`shared_ptr`的配方中，我们学会了共享指针是多么有用和易于使用。与`unique_ptr`一起，它们为需要管理动态分配的对象的代码提供了无价的改进。

每当我们复制`shared_ptr`时，我们都会增加它的内部引用计数。只要我们持有共享指针的副本，被指向的对象就不会被删除。但是如果我们想要一种*弱*指针，它使我们能够在对象存在的情况下访问它，但不会阻止它的销毁呢？我们如何确定对象是否仍然存在呢？

在这种情况下，`weak_ptr`是我们的伙伴。它比`unique_ptr`和`shared_ptr`更复杂一些，但在遵循这个配方之后，我们将准备好使用它。

# 如何做...

我们将实现一个程序，用`shared_ptr`实例维护对象，然后，我们混入`weak_ptr`，看看这如何改变智能指针内存处理的行为：

1.  首先，我们包括必要的头文件，并声明我们默认使用`std`命名空间：

```cpp
      #include <iostream>
      #include <iomanip>
      #include <memory>      

      using namespace std;
```

1.  接下来，我们实现一个类，在其析构函数实现中打印一条消息。这样，我们可以简单地检查稍后在程序输出中何时实际销毁一个项目：

```cpp
      struct Foo {
          int value;

          Foo(int i) : value{i} {}
          ~Foo() { cout << "DTOR Foo " << value << 'n'; }
      };
```

1.  让我们还实现一个函数，打印关于弱指针的信息，这样我们就可以在程序的不同点打印弱指针的状态。`weak_ptr`的`expired`函数告诉我们它指向的对象是否仍然存在，因为持有一个对象的弱指针不会延长它的生命周期！`use_count`计数器告诉我们当前有多少`shared_ptr`实例指向所讨论的对象：

```cpp
      void weak_ptr_info(const weak_ptr<Foo> &p)
      {
          cout << "---------" << boolalpha
               << "nexpired:   " << p.expired()
               << "nuse_count: " << p.use_count()
               << "ncontent:   ";
```

1.  如果我们想要访问实际对象，我们需要调用`lock`函数。它会返回一个指向对象的共享指针。如果对象*不再存在*，我们从中得到的共享指针实际上是一个`null`指针。我们需要检查一下，然后我们就可以访问它了：

```cpp
          if (const auto sp (p.lock()); sp) {
              cout << sp->value << 'n';
          } else {
              cout << "<null>n";
          }
      }
```

1.  让我们在主函数中实例化一个空的弱指针，并打印它的内容，当然，一开始是空的：

```cpp
      int main()
      {
          weak_ptr<Foo> weak_foo;

          weak_ptr_info(weak_foo);
```

1.  在一个新的作用域中，我们用`Foo`类的一个新实例实例化一个新的共享指针，然后将其复制到弱指针中。请注意，这不会增加共享指针的引用计数。引用计数器为`1`，因为只有一个*共享*指针拥有它：

```cpp
          {
              auto shared_foo (make_shared<Foo>(1337));
              weak_foo = shared_foo;
```

1.  在我们*离开*作用域之前，让我们调用弱指针函数，然后在离开作用域*后*再次调用。`Foo`实例应该立即被销毁，*尽管*有一个弱指针指向它：

```cpp
              weak_ptr_info(weak_foo);
          }

          weak_ptr_info(weak_foo);
      }
```

1.  编译和运行程序会使我们得到`weak_ptr_info`函数的输出三次。在第一次调用中，弱指针为空。在第二次调用中，它已经指向我们创建的`Foo`实例，并且在*锁定*之后能够解引用它。在第三次调用之前，我们离开了内部范围，这触发了`Foo`实例的析构函数，正如我们所预期的那样。之后，不再可能通过弱指针访问已删除的`Foo`项目的内容，弱指针正确地识别出它已经过期：

```cpp
      $ ./weak_ptr 
      ---------
      expired:   true
      use_count: 0
      content:   <null>
      ---------
      expired:   false
      use_count: 1
      content:   1337
      DTOR Foo 1337
      ---------
      expired:   true
      use_count: 0
      content:   <null>
```

# 工作原理...

弱指针为我们提供了一种指向由共享指针维护的对象的方式，而不增加其使用计数器。好吧，原始指针也可以做同样的事情，但原始指针无法告诉我们它是否悬空。而弱指针可以！

为了理解弱指针作为共享指针的补充是如何工作的，让我们直接跳到一个说明性的图表：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/583fb0b1-7b58-4bab-ac2a-41fa81b5a685.png)

流程与关于共享指针的配方中的图表类似。在步骤 1 中，我们有两个共享指针和一个指向类型为`Foo`的对象的弱指针。尽管有三个对象指向它，但只有共享指针操作其使用计数器，这就是为什么它的值为`2`。弱指针只操作控制块的*弱计数器*。在步骤 2 和 3 中，共享指针实例被销毁，逐步导致使用计数器为`0`。在步骤 4 中，这导致`Foo`对象被删除，但控制块*仍然存在*。弱指针仍然需要控制块来区分它是否悬空。只有当*最后一个*仍然指向控制块的*弱*指针也超出范围时，控制块才会被删除。

我们还可以说悬空的弱指针已经*过期*。为了检查这个属性，我们可以询问`weak_ptr`指针的`expired`方法，它返回一个布尔值。如果为`true`，那么我们不能解引用弱指针，因为没有对象可以再解引用了。

为了解引用弱指针，我们需要调用`lock()`。这是安全和方便的，因为这个函数返回给我们一个共享指针。只要我们持有这个共享指针，它后面的对象就不会消失，因为我们通过锁定它来增加了使用计数器。如果对象在`lock()`调用之前被删除，那么它返回的共享指针实际上是一个`null`指针。

# 使用智能指针简化遗留 API 的资源处理

智能指针（`unique_ptr`、`shared_ptr`和`weak_ptr`）非常有用，通常可以安全地说，程序员应该*始终*使用这些指针，而不是手动分配和释放内存。

但是，如果对象不能使用`new`运算符进行分配和/或不能使用`delete`再次释放呢？许多遗留库都带有自己的分配/销毁函数。看起来这可能是一个问题，因为我们学到智能指针依赖于`new`和`delete`。如果特定类型的对象的创建和/或销毁依赖于特定工厂函数的删除器接口，这是否会阻止我们获得智能指针的巨大好处呢？

一点也不。在这个配方中，我们将看到我们只需要对智能指针进行非常少量的定制，以便让它们遵循特定对象的分配和销毁的特定程序。

# 如何做...

在本节中，我们将定义一种类型，不能直接使用`new`进行分配，也不能使用`delete`进行释放。由于这阻止了它直接与智能指针一起使用，我们对`unique_ptr`和`smart_ptr`的实例进行了必要的小调整：

1.  和往常一样，我们首先包含必要的头文件，并声明我们默认使用`std`命名空间：

```cpp
      #include <iostream>
      #include <memory>
      #include <string>      

      using namespace std;
```

1.  接下来，我们声明一个类，其构造函数和析构函数声明为`private`。这样，我们模拟了我们需要访问特定函数来创建和销毁它的实例的问题：

```cpp
      class Foo
      {
          string name;

          Foo(string n)
              : name{n}
          { cout << "CTOR " << name << 'n'; }

          ~Foo() { cout << "DTOR " << name << 'n';}
```

1.  静态方法`create_foo`和`destroy_foo`然后创建和销毁`Foo`实例。它们使用原始指针。这模拟了一个遗留的 C API 的情况，它阻止我们直接使用普通的`shared_ptr`指针：

```cpp
      public:
          static Foo* create_foo(string s) { 
             return new Foo{move(s)};
          }

          static void destroy_foo(Foo *p) { delete p; }
      };
```

1.  现在，让我们通过`shared_ptr`来管理这样的对象。当然，我们可以将从`create_foo`得到的指针放入 shared 指针的构造函数中。只有销毁是棘手的，因为`shared_ptr`的默认删除器会做错。诀窍在于我们可以给`shared_ptr`一个*自定义删除器*。删除器函数或可调用对象需要具有的函数签名已经与`destroy_foo`函数的相同。如果我们需要调用更复杂的函数来销毁对象，我们可以简单地将其包装成 lambda 表达式：

```cpp
      static shared_ptr<Foo> make_shared_foo(string s)
      {
          return {Foo::create_foo(move(s)), Foo::destroy_foo};
      }
```

1.  请注意，`make_shared_foo`返回一个通常的`shared_ptr<Foo>`实例，因为给它一个自定义的删除器并没有改变它的类型。这是因为`shared_ptr`使用虚函数调用来隐藏这些细节。唯一指针不会施加任何开销，这使得对它们来说同样的技巧不可行。在这里，我们需要改变`unique_ptr`的类型。作为第二个模板参数，我们给它`void (*)(Foo*)`，这正是指向函数`destroy_foo`的指针的类型：

```cpp
      static unique_ptr<Foo, void (*)(Foo*)> make_unique_foo(string s)
      {
          return {Foo::create_foo(move(s)), Foo::destroy_foo};
      }
```

1.  在主函数中，我们只是实例化了一个 shared 指针和一个 unique 指针实例。在程序输出中，我们将看到它们是否真的、正确地自动销毁了：

```cpp
      int main()
      {
          auto ps (make_shared_foo("shared Foo instance"));
          auto pu (make_unique_foo("unique Foo instance"));
      }
```

1.  编译和运行程序产生了以下输出，幸运的是正是我们所期望的：

```cpp
      $ ./legacy_shared_ptr 
      CTOR shared Foo instance
      CTOR unique Foo instance
      DTOR unique Foo instance
      DTOR shared Foo instance
```

# 它是如何工作的...

通常，`unique_ptr`和`shared_ptr`只是在它们应该销毁维护的对象时在内部指针上调用`delete`。在本节中，我们构造了一个类，它既不能使用`x = new Foo{123}`的 C++方式分配，也不能直接使用`delete x`来销毁。

`Foo::create_foo`函数只是返回一个新构造的`Foo`实例的普通原始指针，因此这不会引起进一步的问题，因为智能指针无论如何都可以使用原始指针。

我们需要解决的问题是，如果默认方式不正确，我们需要教`unique_ptr`和`shared_ptr`如何*销毁*一个对象。

在这方面，智能指针类型有一点不同。为了为`unique_ptr`定义自定义删除器，我们必须改变它的类型。因为`Foo`删除器的类型签名是`void Foo::destroy_foo(Foo*);`，维护`Foo`实例的`unique_ptr`的类型必须是`unique_ptr<Foo, void (*)(Foo*)>`。现在，它可以持有一个指向`destroy_foo`的函数指针，我们在`make_unique_foo`函数中将其作为第二个构造参数提供给它。

如果给`unique_ptr`一个自定义的删除器函数强迫我们改变它的类型，那么为什么我们能够在`shared_ptr`上做同样的事情而*不*改变它的类型呢？我们在那里唯一需要做的事情就是给`shared_ptr`一个第二个构造参数，就是这样。为什么对于`unique_ptr`来说不能像对`shared_ptr`那样容易呢？

之所以可以很简单地为`shared_ptr`提供某种可调用的删除对象，而不改变共享指针的类型，是因为共享指针的本质在于维护一个控制块。共享指针的控制块是一个具有虚函数的对象。这意味着标准共享指针的控制块与具有自定义删除器的共享指针的控制块的类型是*不同*的！当我们想让唯一指针使用自定义删除器时，这会改变唯一指针的类型。当我们想让共享指针使用自定义删除器时，这会改变内部*控制块*的类型，这对我们来说是不可见的，因为这种差异被隐藏在虚函数接口的背后。

*可能*使用唯一指针做同样的技巧，但这将意味着在它们上面有一定的运行时开销。这不是我们想要的，因为唯一指针承诺在运行时完全没有开销。

# 共享同一对象的不同成员值

让我们想象一下，我们正在维护一个指向某个复杂、组合和动态分配的对象的共享指针。然后，我们想要启动一个新的线程，对这个复杂对象的成员进行一些耗时的工作。如果我们现在想释放这个共享指针，那么在其他线程仍在访问它时，对象将被删除。如果我们不想给线程对象整个复杂对象的指针，因为那会破坏我们的良好接口，或者出于其他原因，这是否意味着我们现在必须进行手动内存管理？

不。可以使用共享指针，一方面指向一个大型共享对象的成员，另一方面对整个初始对象执行自动内存管理。

在这个例子中，我们将创建这样的一个场景（为了简单起见，不使用线程），以便对`shared_ptr`的这一便利功能有所感受。

# 如何做...

我们将定义一个由多个成员组成的结构。然后，我们在堆上分配这个结构的一个实例，并由共享指针维护。从这个共享指针，我们获得更多的共享指针，它们不指向实际对象，而是指向它的成员：

1.  首先包括必要的头文件，然后声明我们默认使用`std`命名空间：

```cpp
      #include <iostream>
      #include <memory>
      #include <string>      

      using namespace std;
```

1.  然后我们定义一个具有不同成员的类。我们将让共享指针指向各个成员。为了能够看到类何时被创建和销毁，我们让它的构造函数和析构函数打印消息：

```cpp
      struct person {
          string name;
          size_t age;

          person(string n, size_t a)
              : name{move(n)}, age{a}
          { cout << "CTOR " << name << 'n'; }

          ~person() { cout << "DTOR " << name << 'n'; }
      };
```

1.  让我们定义共享指针，使其具有正确的类型，可以指向`person`类实例的`name`和`age`成员变量：

```cpp
      int main()
      {
          shared_ptr<string> shared_name;
          shared_ptr<size_t> shared_age;
```

1.  接下来，我们进入一个新的作用域，创建这样一个人物对象，并让一个共享指针管理它：

```cpp
          {
              auto sperson (make_shared<person>("John Doe", 30));
```

1.  然后，我们让前两个共享指针指向它的名称和年龄成员。诀窍在于我们使用了`shared_ptr`的特定构造函数，该构造函数接受一个共享指针和一个指向共享对象成员的指针。这样，我们可以管理对象，而不是直接指向对象本身！

```cpp
              shared_name = shared_ptr<string>(sperson, &sperson->name);
              shared_age  = shared_ptr<size_t>(sperson, &sperson->age);
          }
```

1.  离开作用域后，我们打印人的姓名和年龄值。只有在对象仍然分配时才合法：

```cpp
          cout << "name: "  << *shared_name
               << "nage: " << *shared_age << 'n';
      }
```

1.  编译和运行程序产生以下输出。从析构函数的消息中，我们看到当我们通过成员指针访问人的姓名和年龄值时，对象确实仍然存活和分配！

```cpp
      $ ./shared_members 
      CTOR John Doe
      name: John Doe
      age:  30
      DTOR John Doe
```

# 它是如何工作的...

在这一部分，我们首先创建了一个管理动态分配的`person`对象的共享指针。然后，我们让另外两个智能指针指向该人物对象，但它们都没有*直接*指向该人物对象本身，而是指向它的成员，`name`和`age`。

总结一下我们刚刚创建的场景，让我们看一下下面的图表：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/835d6935-4712-4ccb-9e5c-8ff335816245.png)

请注意，`shared_ptr1`直接指向`person`对象，而`shared_name`和`shared_age`指向同一对象的`name`和`age`成员。显然，它们仍然管理对象的整个生命周期。这是可能的，因为内部控制块指针仍然指向相同的控制块，无论个别共享指针指向哪个子对象。

在这种情况下，控制块的使用计数为`3`。这样，当`shared_ptr1`被销毁时，`person`对象不会被销毁，因为其他共享指针仍然拥有该对象。

当创建指向共享对象成员的这种共享指针实例时，语法看起来有点奇怪。为了获得指向共享人员的名称成员的`shared_ptr<string>`，我们需要写如下内容：

```cpp
auto sperson (make_shared<person>("John Doe", 30));
auto sname   (shared_ptr<string>(sperson, &sperson->name));
```

为了获得共享对象成员的特定指针，我们使用共享指针实例化一个类型特化的成员。这就是为什么我们写`shared_ptr<**string**>`。然后，在构造函数中，我们首先提供维护`person`对象的原始共享指针，作为第二个参数，我们提供新共享指针在解引用时将使用的对象的地址。

# 生成随机数和选择正确的随机数引擎

为了获得任何目的的随机数，C++程序员通常在 C++11 之前基本上使用 C 库的`rand()`函数。自 C++11 以来，已经有了一整套不同目的和不同特性的随机数生成器。

这些生成器并不完全自解释，所以我们将在本教程中查看它们。最后，我们将看到它们之间的区别，如何选择正确的生成器，以及我们很可能永远不会使用它们全部。

# 如何做...

我们将实现一个过程，打印一个漂亮的直方图，显示随机生成器生成的数字。然后，我们将运行所有 STL 随机数生成器引擎通过这个过程，并从结果中学习。这个程序包含许多重复的行，所以最好直接从附带本书互联网代码库中复制源代码，而不是手动输入所有重复的代码。

1.  首先，我们包含所有必要的头文件，然后声明我们默认使用`std`命名空间：

```cpp
      #include <iostream>
      #include <string>
      #include <vector>
      #include <random>
      #include <iomanip>
      #include <limits>
      #include <cstdlib>
      #include <algorithm>      

      using namespace std;
```

1.  然后，我们实现一个辅助函数，它帮助我们维护和打印每种随机数引擎的一些统计信息。它接受两个参数：*分区*的数量和*样本*的数量。我们将立即看到这些是什么。随机生成器的类型是通过模板参数`RD`定义的。在这个函数中，我们做的第一件事是为生成器返回的数字的结果数值类型定义一个别名类型。我们还确保至少有 10 个分区：

```cpp
      template <typename RD>
      void histogram(size_t partitions, size_t samples)
      {
          using rand_t = typename RD::result_type;
          partitions = max<size_t>(partitions, 10);
```

1.  接下来，我们实例化一个类型为`RD`的实际生成器实例。然后，我们定义一个称为`div`的除数变量。所有随机数引擎发出的随机数范围为`0`到`RD::max()`。函数参数`partitions`允许调用者选择我们将每个随机数范围划分为多少个分区。通过将最大可能值除以分区数，我们知道每个分区有多大：

```cpp
          RD rd;
          rand_t div ((double(RD::max()) + 1) / partitions);
```

1.  接下来，我们实例化一个计数器变量的向量。它的大小正好等于我们拥有的分区数。然后，我们从随机引擎中获取与变量`samples`相同数量的随机值。表达式`rd()`从生成器中获取一个随机数，并将其内部状态移位，以准备返回下一个随机数。通过将每个随机数除以`div`，我们得到它所在的分区号，并可以增加计数器向量中的正确计数器：

```cpp
          vector<size_t> v (partitions);
          for (size_t i {0}; i < samples; ++i) { 
              ++v[rd() / div];
          }
```

1.  现在我们有了一个样本值的粗略直方图。为了打印它，我们需要了解更多关于其实际计数器值的信息。让我们使用`max_element`算法提取其最大值。然后我们将这个最大计数器值除以`100`。这样，我们可以将所有计数器值除以`max_div`并在终端上打印大量星号，而不会超过`100`的宽度。如果最大计数器包含的数字小于`100`，因为我们没有使用太多样本，我们使用`max`来获得`1`的最小除数：

```cpp
          rand_t max_elm (*max_element(begin(v), end(v)));
          rand_t max_div (max(max_elm / 100, rand_t(1)));
```

1.  现在让我们将直方图打印到终端上。每个分区在终端上都有自己的一行。通过将其计数器值除以`max_div`并打印相应数量的星号`'*'`，我们可以得到适合终端的直方图行：

```cpp
          for (size_t i {0}; i < partitions; ++i) {
              cout << setw(2) << i << ": "
                   << string(v[i] / max_div, '*') << 'n';
          }
      }
```

1.  好的，就是这样。现在到主程序。我们让用户定义应该使用多少个分区和样本：

```cpp
      int main(int argc, char **argv)
      {
          if (argc != 3) {
              cout << "Usage: " << argv[0] 
                   << " <partitions> <samples>n";
              return 1;
          }
```

1.  然后我们从命令行读取这些变量。当然，命令行由字符串组成，我们可以使用`std::stoull`（`stoull`是**s**tring **to** **u**nsigned **l**ong **l**ong 的缩写）将其转换为数字：

```cpp
          size_t partitions {stoull(argv[1])};
          size_t samples    {stoull(argv[2])};
```

1.  现在我们对 STL 提供的*每个*随机数引擎调用我们的直方图辅助函数。这使得这个示例非常冗长和重复。最好从互联网上复制示例。这个程序的输出真的很有趣。我们从`random_device`开始。这个设备试图将随机性均匀分布在所有可能的值上：

```cpp
          cout << "random_device" << 'n';
          histogram<random_device>(partitions, samples);
```

1.  我们尝试的下一个随机引擎是`default_random_engine`。这种类型引用的引擎是特定于实现的。它可以是以下任何一种随机引擎：

```cpp
          cout << "ndefault_random_engine" << 'n';
          histogram<default_random_engine>(partitions, samples);
```

1.  然后我们在所有其他引擎上尝试一下：

```cpp
          cout << "nminstd_rand0" << 'n';
          histogram<minstd_rand0>(partitions, samples);
          cout << "nminstd_rand" << 'n';
          histogram<minstd_rand>(partitions, samples);

          cout << "nmt19937" << 'n';
          histogram<mt19937>(partitions, samples);
          cout << "nmt19937_64" << 'n';
          histogram<mt19937_64>(partitions, samples);

          cout << "nranlux24_base" << 'n';
          histogram<ranlux24_base>(partitions, samples);
          cout << "nranlux48_base" << 'n';
          histogram<ranlux48_base>(partitions, samples);

          cout << "nranlux24" << 'n';
          histogram<ranlux24>(partitions, samples);
          cout << "nranlux48" << 'n';
          histogram<ranlux48>(partitions, samples);

          cout << "nknuth_b" << 'n';
          histogram<knuth_b>(partitions, samples);
      }
```

1.  编译和运行程序会产生有趣的结果。我们将看到一个很长的输出列表，并且我们会看到所有随机引擎具有不同的特征。让我们首先使用`10`个分区和只有`1000`个样本运行程序：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/ff7076af-b140-497a-9d23-c4453a43415f.png)

1.  然后，我们再次运行相同的程序。这次仍然是`10`个分区，但是`1,000,000`个样本。很明显，当我们从中取更多的样本时，直方图看起来会更*清晰*。这是一个重要的观察：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/8178317e-d792-4766-be8a-d4e0e6a06d3c.png)

# 它是如何工作的...

一般来说，任何随机数生成器在使用之前都需要实例化为对象。生成的对象可以像没有参数的函数一样调用，因为它重载了`operator()`。每次调用都会产生一个新的随机数。就是这么简单。

在本节中，我们编写了一个比以往更复杂的程序，以便更多地了解随机数生成器。请通过使用不同的命令行参数启动生成的程序来玩耍，并意识到以下事实：

+   我们取样的样本越多，我们的分区计数器看起来就越均匀。

+   分区计数器的不平等在各个单独的引擎之间差异很大。

+   对于大量样本，个别随机引擎的*性能*差异变得明显。

+   多次以低数量的样本运行程序。分布模式始终看起来*相同*--随机引擎重复产生*相同*的随机数序列，这意味着它们*根本不是随机*。这样的引擎被称为*确定性*，因为它们的随机数可以被预测。唯一的例外是`std::random_device`。

正如我们所看到的，有一些特征需要考虑。对于大多数标准应用程序，`std::default_random_engine`将完全足够。密码学专家或类似安全敏感主题的专家将明智地在使用的引擎之间进行选择，但对于我们这些普通程序员来说，在编写带有一些随机性的应用程序时，这并不太重要。

我们应该从这个示例中得出以下三个事实：

1.  通常，`std::default_random_engine` 对于一般的应用来说是一个很好的默认选择。

1.  如果我们真的需要非确定性的随机数，`std::random_device`可以提供给我们这样的随机数。

1.  我们可以用`std::random_device`的一个*真正*的随机数（或者可能是系统时钟的时间戳）来给任何随机引擎的构造函数提供种子，以便使其每次产生不同的随机数。这就是所谓的*种子*。

请注意，`std::random_device`*可能*会退回到其中一个确定性引擎，如果库不支持非确定性随机引擎。

# 生成随机数并让 STL 塑造特定分布

在上一个示例中，我们学习了一些关于 STL 随机数引擎的知识。生成随机数这样或那样往往只是工作的一半。

另一个问题是，我们需要这些数字做什么？我们是在程序上“抛硬币”吗？人们过去常常使用`rand() % 2`来做这个，这会得到`0`和`1`的值，然后可以映射到*正面*或*反面*。好吧，我们不需要为此使用库（尽管随机性专家知道，仅使用随机数的最低几位并不总是会得到高质量的随机数）。

如果我们想要建模一个骰子呢？那么，我们肯定可以写`(rand() % 6) + 1`，以表示掷骰子后的结果。对于这样简单的任务，还不需要使用库。

如果我们想要建模一个发生的概率恰好为 66%的事件怎么办？好吧，那么我们可以想出一个公式，比如`bool yesno = (rand() % 100 > 66)`。（哦等等，应该是`>=`，还是`>`正确？）

除此之外，我们如何建模一个*不公平*的骰子，其各面的概率并不相同？或者如何建模更复杂的分布？这些问题很快就会演变成科学任务。为了集中精力解决我们的主要问题，让我们先看看 STL 已经提供了什么来帮助我们。

STL 包含了十几种分布算法，可以为特定的需求塑造随机数。在这个示例中，我们将简要地查看所有这些算法，并更仔细地研究其中最常用的几种。

# 如何做到...

我们将生成随机数，塑造它们，并将它们的分布模式打印到终端。这样，我们可以了解它们，并理解最重要的那些，这对于我们如果需要以随机性为基础来建模某些特定的事物是很有用的。

1.  首先，我们包含所有需要的头文件，并声明我们使用`std`命名空间：

```cpp
      #include <iostream>
      #include <iomanip>
      #include <random>
      #include <map>
      #include <string>
      #include <algorithm>     

      using namespace std;
```

1.  对于 STL 提供的每个分布，我们将打印一个直方图，以便看到它的特征，因为每个分布看起来都很特别。它接受一个分布作为参数，以及应该从中取样的样本数。然后，我们实例化默认的随机引擎和一个地图。地图将从我们从分布中获得的值映射到计数器，计算每个值出现的次数。之所以总是实例化一个随机引擎，是因为所有分布只是用作随机数的*塑造函数*，而随机数仍然需要由随机引擎生成：

```cpp
      template <typename T>
      void print_distro(T distro, size_t samples)
      {
          default_random_engine e;
          map<int, size_t> m;
```

1.  我们取样本数与`samples`变量相同，并用它们来填充地图计数器。这样，我们就得到了一个漂亮的直方图。调用`e()`会得到一个原始的随机数，而`distro(e)`则通过分布对象塑造了随机数。

```cpp
          for (size_t i {0}; i < samples; ++i) {
              m[distro(e)] += 1;
          }
```

1.  为了得到一个适合终端窗口的终端输出，我们需要知道*最大*计数器值。`max_element`函数帮助我们找到最大值，通过比较地图中所有相关的计数器，并返回一个指向最大计数器节点的迭代器。知道了这个值，我们就可以确定需要将所有计数器值除以多少，以便将输出适应终端窗口：

```cpp
          size_t max_elm (max_element(begin(m), end(m),
              [](const auto &a, const auto &b) { 
                   return a.second < b.second; 
              })->second);
          size_t max_div (max(max_elm / 100, size_t(1)));
```

1.  现在，我们遍历映射并为所有具有显着大小的计数器打印一个星号符号`'*'`的条形。我们放弃其他计数器，因为一些分布引擎将数字分布在如此大的域上，以至于它会完全淹没我们的终端窗口：

```cpp
          for (const auto [randval, count] : m) {
              if (count < max_elm / 200) { continue; }

              cout << setw(3) << randval << " : "
                   << string(count / max_div, '*') << 'n';
          }
      }
```

1.  在主函数中，我们检查用户是否向我们提供了一个参数，该参数告诉我们从每个分布中取多少个样本。如果用户没有提供或提供了多个参数，我们会报错。

```cpp
      int main(int argc, char **argv)
      {
          if (argc != 2) {
              cout << "Usage: " << argv[0] 
                   << " <samples>n";
              return 1;
          }
```

1.  我们使用`std::stoull`将命令行参数字符串转换为数字：

```cpp
          size_t samples {stoull(argv[1])};
```

1.  首先，我们尝试`uniform_int_distribution`和`normal_distribution`。这些是在需要随机数时使用的最典型的分布。在学校学习随机过程的人很可能已经听说过这些了。均匀分布接受两个值，表示它们将在其上分布随机值的范围的下限和上限。通过选择`0`和`9`，我们将得到在（包括）`0`和`9`之间出现的值。正态分布接受*均值*和*标准偏差*作为参数：

```cpp
          cout << "uniform_int_distributionn";
          print_distro(uniform_int_distribution<int>{0, 9}, samples);

          cout << "normal_distributionn";
          print_distro(normal_distribution<double>{0.0, 2.0}, samples);
```

1.  另一个非常有趣的分布是`piecewise_constant_distribution`。它接受两个输入范围作为参数。第一个范围包含数字，表示区间的限制。通过将其定义为`0, 5, 10, 30`，我们得到一个从`0`到`4`的区间，然后是一个从`5`到`9`的区间，最后一个从`10`到`29`的区间。另一个输入范围定义了输入范围的权重。通过将这些权重设置为`0.2, 0.3, 0.5`，区间被随机数命中的概率分别为 20％，30％和 50％。在每个区间内，所有值都具有相等的概率被命中：

```cpp
          initializer_list<double> intervals {0, 5, 10, 30};
          initializer_list<double> weights {0.2, 0.3, 0.5};
          cout << "piecewise_constant_distributionn";
          print_distro(
              piecewise_constant_distribution<double>{
                  begin(intervals), end(intervals), 
                  begin(weights)}, 
             samples);
```

1.  `piecewise_linear_distribution`的构造方式类似，但其权重特性完全不同。对于每个区间边界点，都有一个权重值。在从一个边界过渡到另一个边界时，概率是线性插值的。我们使用相同的区间列表，但是不同的权重值列表。

```cpp
          cout << "piecewise_linear_distributionn";
          initializer_list<double> weights2 {0, 1, 1, 0};
          print_distro(
              piecewise_linear_distribution<double>{
                  begin(intervals), end(intervals), begin(weights2)}, 
              samples);
```

1.  伯努利分布是另一个重要的分布，因为它只分布具有特定概率的*是/否*、*命中/未命中*或*正面/反面*值。其输出值只有`0`或`1`。另一个有趣的分布，在许多情况下都很有用，是`discrete_distribution`。在我们的情况下，我们将其初始化为离散值`1, 2, 4, 8`。这些值被解释为可能的输出值`0`到`3`的权重：

```cpp
          cout << "bernoulli_distributionn";
          print_distro(std::bernoulli_distribution{0.75}, samples);

          cout << "discrete_distributionn";
          print_distro(discrete_distribution<int>{{1, 2, 4, 8}}, samples);
```

1.  还有很多其他不同的分布引擎。它们非常特殊，在非常特定的情况下非常有用。如果你从未听说过它们，它们*可能*不适合你。然而，由于我们的程序将产生漂亮的分布直方图，出于好奇的原因，我们将打印它们全部：

```cpp
          cout << "binomial_distributionn";
          print_distro(binomial_distribution<int>{10, 0.3}, samples);
          cout << "negative_binomial_distributionn";
          print_distro(
              negative_binomial_distribution<int>{10, 0.8}, 
              samples);
          cout << "geometric_distributionn";
          print_distro(geometric_distribution<int>{0.4}, samples);
          cout << "exponential_distributionn";
          print_distro(exponential_distribution<double>{0.4}, samples);
          cout << "gamma_distributionn";
          print_distro(gamma_distribution<double>{1.5, 1.0}, samples);
          cout << "weibull_distributionn";
          print_distro(weibull_distribution<double>{1.5, 1.0}, samples);
          cout << "extreme_value_distributionn";
          print_distro(
              extreme_value_distribution<double>{0.0, 1.0}, 
              samples);
          cout << "lognormal_distributionn";
          print_distro(lognormal_distribution<double>{0.5, 0.5}, samples);
          cout << "chi_squared_distributionn";
          print_distro(chi_squared_distribution<double>{1.0}, samples);
          cout << "cauchy_distributionn";
          print_distro(cauchy_distribution<double>{0.0, 0.1}, samples);
          cout << "fisher_f_distributionn";
          print_distro(fisher_f_distribution<double>{1.0, 1.0}, samples);
          cout << "student_t_distributionn";
          print_distro(student_t_distribution<double>{1.0}, samples);
      }
```

1.  编译和运行程序产生以下输出。让我们首先以每个分布`1000`个样本运行程序：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/5ba7d1ee-ef21-4b2d-ae4f-6d68d5bc6ab5.png)

1.  另一个以每个分布`1,000,000`个样本运行的结果显示，直方图看起来更加干净，更加典型。但我们也可以看到哪些是慢的，哪些是快的，当它们被生成时：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/0297daeb-5434-4bf4-8aa6-7f23b5036413.png)

# 它的工作原理...

通常情况下，我们不太关心随机数引擎，只要它快速并且产生尽可能随机的数字，分布是我们*应该*根据我们想要解决（或创建）的问题明智选择的东西。

为了使用任何分布，我们首先需要从中实例化一个分布对象。我们已经看到不同的分布需要不同的构造参数。在食谱描述中，我们对一些分布引擎描述得有点太简要了，因为它们中的大多数都太特殊和/或太复杂，无法在这里涵盖。但不要担心，它们在 C++ STL 文档中都有详细的文档。

然而，一旦我们实例化了一个分布，我们就可以像调用函数一样调用它，它只接受一个随机引擎对象作为其唯一参数。然后发生的是，分布引擎从随机引擎中取一个随机值，应用一些魔术形状（当然完全取决于分布引擎的选择），然后返回给我们一个*形状*的随机值。这导致了完全不同的直方图，就像我们在执行程序后看到的那样。

了解不同分布的最全面的方法是*玩弄*我们刚刚编写的程序。除此之外，让我们总结一下最重要的分布。对于我们程序中出现但下表中没有的所有分布，请参阅 C++ STL 文档（如果您感兴趣）：

| **分布** | **描述** |
| --- | --- |
| `uniform_int_distribution` | 这个分布接受下限和上限值作为构造参数。然后，它给我们的随机数总是落在（包括）这些边界之间的区间内。这个区间内每个值的概率是相同的，这给我们一个*平坦*形状的直方图。这个分布代表了掷骰子，因为骰子的每一面出现的概率都是相同的。 |
| `normal_distribution` | 正态分布或高斯分布在自然界几乎无处不在。它的 STL 版本接受平均值和标准偏差值作为构造函数参数，并在直方图中形成一个*屋顶*形状。如果我们比较人类或其他动物的身体大小或智商，或者学生的成绩，我们会意识到这些数字也是正态分布的。 |
| `bernoulli_distribution` | 伯努利分布非常适合我们想要抛硬币或得到是/否答案的情况。它只发出值`0`或`1`，其唯一的构造函数参数是值`1`的概率。 |
| `discrete_distribution` | 离散分布在我们只想要一个非常有限的、离散的值集合，并且想要为每个单独的值定义概率时是很有趣的。它的构造函数接受一个权重列表，并将根据它们的权重发出具有不同概率的随机数。如果我们想要模拟随机分布的血型，其中只有四种不同的血型具有特定的概率，那么这个引擎就是一个完美的选择。 |
