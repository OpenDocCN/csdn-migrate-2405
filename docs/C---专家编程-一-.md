# C++ 专家编程（一）

> 原文：[`annas-archive.org/md5/57ea316395e58ce0beb229274ec493fc`](https://annas-archive.org/md5/57ea316395e58ce0beb229274ec493fc)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

学习路径和技术简介。

# 这个学习路径适合谁

这个学习路径适合想要提升并学习如何在最新版本的 Java 中构建健壮应用程序的 Java 开发人员。

# 这个学习路径涵盖了什么

*第 1 部分*，*精通 C++编程*，介绍了 C++17 和 STL 中的最新功能。它鼓励在 C++中使用清晰的代码实践，并演示了在 C++中开发 GUI 应用程序的选项。您将获得有关使用智能指针避免内存泄漏的提示。*第 2 部分*，*精通 C++多线程*，您将看到多线程编程如何帮助您实现应用程序的并发性。我们首先简要介绍了多线程和并发概念的基础知识。然后我们深入研究了这些概念在硬件级别的工作方式，以及操作系统和框架如何使用这些低级功能。您将学习自 2011 年修订以来 C++中可用的本机多线程和并发支持，线程之间的同步和通信，调试并发 C++应用程序以及 C++中的最佳编程实践。

*第 3 部分*，*C++17 STL Cookbook*，您将深入了解 C++标准模板库；我们展示了特定于实现的问题解决方法，这将帮助您快速克服障碍。您将学习核心 STL 概念，如容器、算法、实用类、lambda 表达式、迭代器等，并在实际的实际场景中工作。这些示例将帮助您充分利用 STL，并向您展示如何以更好的方式进行编程。

# 充分利用这个学习路径

1.  强烈建议对 C++语言有深入的理解，因为这本书是为有经验的开发人员准备的。

1.  您需要在您的系统上安装任何操作系统（Windows、Linux 或 macOS）和任何 C++编译器才能开始。

# 下载示例代码文件

您可以从[www.packtpub.com](http://www.packtpub.com)的帐户中下载这个学习路径的示例代码文件。如果您在其他地方购买了这个学习路径，您可以访问[www.packtpub.com/support](http://www.packtpub.com/support)注册并直接将文件发送到您的邮箱。

您可以按照以下步骤下载代码文件：

1.  在[www.packtpub.com](http://www.packtpub.com/support)登录或注册。

1.  选择 SUPPORT 选项卡。

1.  点击“代码下载和勘误”。

1.  在搜索框中输入学习路径的名称，然后按照屏幕上的说明操作。

下载文件后，请确保使用最新版本的解压缩或提取文件夹：

+   Windows 上的 WinRAR/7-Zip

+   Mac 上的 Zipeg/iZip/UnRarX

+   Linux 上的 7-Zip/PeaZip

学习路径的代码包也托管在 GitHub 上，网址是[`github.com/PacktPublishing/Learning-Path-Name`](https://github.com/PacktPublishing)。我们还有其他代码包来自我们丰富的图书和视频目录，可以在[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)找到。去看看吧！

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：指示文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄。这是一个例子："将下载的`WebStorm-10*.dmg`磁盘映像文件挂载为系统中的另一个磁盘。"

代码块设置如下：

```cpp
html, body, #map {
 height: 100%; 
 margin: 0;
 padding: 0
}
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目将以粗体显示：

```cpp
[default]
exten => s,1,Dial(Zap/1|30)
exten => s,2,Voicemail(u100)
exten => s,102,Voicemail(b100)
exten => i,1,Voicemail(s0)
```

任何命令行输入或输出都按照以下格式编写：

```cpp
$ mkdir css
$ cd css
```

**粗体**：表示一个新术语、一个重要词或者您在屏幕上看到的词。例如，菜单或对话框中的单词会在文本中出现。这里有一个例子：“从管理面板中选择系统信息。”

警告或重要提示会以这种方式出现。

技巧和窍门会以这种方式出现。


# 第一章：精通 C++编程

*现代 C++ 17 触手可及*


# 第二章：介绍 C++17 标准模板库

正如您所知，C++语言是 Bjarne Stroustrup 于 1979 年开发的产物。C++编程语言由国际标准化组织（ISO）标准化。最初的标准化于 1998 年发布，通常称为 C++98，下一个标准化 C++03 于 2003 年发布，主要是一个修复错误的版本，只有一个语言特性用于值初始化。2011 年 8 月，C++11 标准发布，对核心语言进行了多项增加，包括对标准模板库（STL）的一些重大有趣的更改；C++11 基本上取代了 C++03 标准。C++14 于 2014 年 12 月发布，带有一些新功能，后来，C++17 标准于 2017 年 7 月 31 日发布。在撰写本书时，C++17 是 C++编程语言的最新修订版。

本章需要支持 C++17 特性的编译器：gcc 版本 7 或更高。由于 gcc 版本 7 是撰写本书时的最新版本，本章将使用 gcc 版本 7.1.0。

本章将涵盖以下主题：

+   STL 概述

+   STL 架构

+   容器

+   迭代器

+   算法

+   函数对象

+   STL 容器

+   序列

+   关联

+   无序

+   适配器

让我们在接下来的章节逐个了解 STL 的主题。

# 标准模板库架构

C++标准模板库（STL）提供了现成的通用容器、可应用于容器的算法以及用于导航容器的迭代器。STL 是用 C++模板实现的，模板允许在 C++中进行通用编程。

STL 鼓励 C++开发人员专注于手头的任务，摆脱了编写低级数据结构和算法的束缚。STL 是一个经过时间考验的库，可以实现快速应用程序开发。

STL 是一项有趣的工作和架构。它的秘密公式是编译时多态性。为了获得更好的性能，STL 避免了动态多态性，告别了虚函数。总的来说，STL 有以下四个组件：

+   算法

+   函数对象

+   迭代器

+   容器

STL 架构将所有上述四个组件连接在一起。它具有许多常用的算法，并提供性能保证。有趣的是，STL 算法可以在不了解包含数据的容器的情况下无缝工作。这是由于迭代器提供了高级遍历 API，完全抽象了容器内部使用的底层数据结构。STL 广泛使用运算符重载。让我们逐个了解 STL 的主要组件，以便对 STL 的概念有一个良好的理解。

# 算法

STL 算法由 C++模板驱动；因此，相同的算法可以处理任何数据类型，独立于容器中数据的组织方式。有趣的是，STL 算法足够通用，可以使用模板支持内置和用户定义的数据类型。事实上，算法通过迭代器与容器交互。因此，算法关心的是容器支持的迭代器。然而，算法的性能取决于容器内部使用的数据结构。因此，某些算法仅适用于特定的容器，因为 STL 支持的每个算法都期望一种特定类型的迭代器。

# 迭代器

迭代器是一种设计模式，但有趣的是，STL 的工作开始得早于此

*四人帮*将他们与设计模式相关的工作发布给了软件社区。迭代器本身是允许遍历容器以访问、修改和操作容器中存储的数据的对象。迭代器以如此神奇的方式进行操作，以至于我们并不意识到或需要知道数据存储和检索的位置和方式。

以下图像直观地表示了一个迭代器：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/540e553e-34b4-4deb-94d0-2b1671b4c429.png)

从前面的图像中，您可以理解每个迭代器都支持`begin()` API，它返回第一个元素的位置，`end()` API 返回容器中最后一个元素的下一个位置。

STL 广泛支持以下五种类型的迭代器：

+   输入迭代器

+   输出迭代器

+   前向迭代器

+   双向迭代器

+   随机访问迭代器

容器实现了迭代器，让我们可以轻松地检索和操作数据，而不需要深入了解容器的技术细节。

以下表格解释了这五种迭代器中的每一种：

| 迭代器的类型 | 描述 |
| --- | --- |
| 输入迭代器 |

+   它用于从指定的元素读取数据

+   它只能用于单次导航，一旦到达容器的末尾，迭代器将失效

+   它支持前置和后置递增运算符

+   它不支持递减运算符

+   它支持解引用

+   它支持`==`和`!=`运算符来与其他迭代器进行比较

+   `istream_iterator`迭代器是输入迭代器

+   所有的容器都支持这种迭代器

|

| 输出迭代器 |
| --- |

+   它用于修改指定的元素

+   它只能用于单次导航，一旦到达容器的末尾，迭代器将失效

+   它支持前置和后置递增运算符

+   它不支持递减运算符

+   它支持解引用

+   它不支持`==`和`!=`运算符

+   `ostream_iterator`、`back_inserter`、`front_inserter`迭代器是输出迭代器的例子

+   所有的容器都支持这种迭代器

|

| 前向迭代器 |
| --- |

+   它支持输入迭代器和输出迭代器的功能

+   它允许多次导航

+   它支持前置和后置递增运算符

+   它支持解引用

+   `forward_list`容器支持前向迭代器

|

| 双向迭代器 |
| --- |

+   它是一个支持双向导航的前向迭代器

+   它允许多次导航

+   它支持前置和后置递增运算符

+   它支持前置和后置递减运算符

+   它支持解引用

+   它支持`[]`运算符

+   `list`、`set`、`map`、`multiset`和`multimap`容器支持双向迭代器

|

| 随机访问迭代器 |
| --- |

+   可以使用任意偏移位置访问元素

+   它支持前置和后置递增运算符

+   它支持前置和后置递减运算符

+   它支持解引用

+   它是最功能完备的迭代器，因为它支持前面列出的其他类型迭代器的所有功能

+   `array`、`vector`和`deque`容器支持随机访问迭代器

+   支持随机访问的容器自然也支持双向和其他类型的迭代器

|

# 容器

STL 容器通常是动态增长和收缩的对象。容器使用复杂的数据结构来存储数据，并提供高级函数来访问数据，而不需要我们深入了解数据结构的复杂内部实现细节。STL 容器非常高效且经过时间考验。

每个容器使用不同类型的数据结构以高效地存储、组织和操作数据。尽管许多容器可能看起来相似，但它们在内部的行为却有所不同。因此，选择错误的容器会导致应用程序性能问题和不必要的复杂性。

容器有以下几种类型：

+   顺序

+   关联

+   容器适配器

容器中存储的对象是复制或移动的，而不是引用。我们将在接下来的章节中用简单而有趣的示例探索每种类型的容器。

# 函数对象

函数对象是行为类似于常规函数的对象。美妙之处在于函数对象可以替代函数指针。函数对象是方便的对象，可以让您扩展或补充 STL 函数的行为，而不会违反面向对象编程原则。

函数对象易于实现；您只需重载函数运算符。函数对象也被称为函数对象。

以下代码将演示如何实现一个简单的函数对象：

```cpp
#include <iostream>
#include <vector>
#include <iterator>
#include <algorithm>
using namespace std;

template <typename T>
class Printer {
public:
  void operator() ( const T& element ) {
    cout << element << "t";
  }
};

int main () {
  vector<int> v = { 10, 20, 30, 40, 50 };

  cout << "nPrint the vector entries using Functor" << endl;

  for_each ( v.begin(), v.end(), Printer<int>() );

  cout << endl;

  return 0;
}
```

让我们快速使用以下命令编译程序：

```cpp
g++ main.cpp -std=c++17
./a.out
```

让我们检查程序的输出：

```cpp
Print the vector entries using Functor
10  20  30  40  50
```

希望您意识到函数对象是多么简单和酷。

# 序列容器

STL 支持一系列有趣的序列容器。序列容器以线性方式存储同类数据类型，可以按顺序访问。STL 支持以下序列容器：

+   数组

+   向量

+   列表

+   `forward_list`

+   双端队列

由于存储在 STL 容器中的对象只是值的副本，STL 期望用户定义的数据类型满足一定的基本要求，以便将这些对象存储在容器中。存储在 STL 容器中的每个对象都必须提供以下最低要求：

+   默认构造函数

+   一个复制构造函数

+   赋值运算符

让我们在以下小节中逐一探索序列容器。

# 数组

STL 数组容器是一个固定大小的序列容器，就像 C/C++内置数组一样，只是 STL 数组具有大小感知，并且比内置的 C/C++数组更智能。让我们通过一个示例了解 STL 数组：

```cpp
#include <iostream>
#include <array>
using namespace std;
int main () {
  array<int,5> a = { 1, 5, 2, 4, 3 };

  cout << "nSize of array is " << a.size() << endl;

  auto pos = a.begin();

  cout << endl;
  while ( pos != a.end() ) 
    cout << *pos++ << "t";
  cout << endl;

  return 0;
}
```

前面的代码可以编译，并且可以使用以下命令查看输出：

```cpp
g++ main.cpp -std=c++17
./a.out 
```

程序的输出如下：

```cpp
Size of array is 5
1     5     2     4     3
```

# 代码演示

以下行声明了一个固定大小（`5`）的数组，并用五个元素初始化数组：

```cpp
array<int,5> a = { 1, 5, 2, 4, 3 };
```

一旦声明，大小就无法更改，就像 C/C++内置数组一样。`array::size()`方法返回数组的大小，不管初始化列表中初始化了多少个整数。`auto pos = a.begin()`方法声明了一个`array<int,5>`的迭代器，并将数组的起始位置赋给它。`array::end()`方法指向数组中最后一个元素之后的一个位置。迭代器的行为类似于或模仿 C++指针，对迭代器进行解引用会返回迭代器指向的值。迭代器的位置可以向前和向后移动，分别使用`++pos`和`--pos`。

# 数组中常用的 API

以下表格显示了一些常用的数组 API：

| **API** | **描述** |
| --- | --- |
| `at( int index )` | 这返回索引指向的位置存储的值。索引是从零开始的。如果索引超出数组的索引范围，此 API 将抛出`std::out_of_range`异常。 |
| `operator [ int index ]` | 这是一个不安全的方法，如果索引超出数组的有效范围，它不会抛出任何异常。这比`at`略快，因为此 API 不执行边界检查。 |
| `front()` | 这返回数组中的第一个元素。 |
| `back()` | 这返回数组中的最后一个元素。 |
| `begin()` | 这返回数组中第一个元素的位置 |
| `end()` | 这返回数组中最后一个元素的位置之后的一个位置 |
| `rbegin()` | 这返回反向开始位置，即返回数组中最后一个元素的位置 |
| `rend()` | 这返回反向结束位置，即返回数组中第一个元素之前的一个位置 |
| `size()` | 这返回数组的大小 |

数组容器支持随机访问；因此，给定一个索引，数组容器可以以*O(1)*或常量时间的运行复杂度获取一个值。

数组容器元素可以使用反向迭代器以反向方式访问：

```cpp
#include <iostream>
#include <array>
using namespace std;

int main () {

    array<int, 6> a;
    int size = a.size();
    for (int index=0; index < size; ++index)
         a[index] = (index+1) * 100;   

    cout << "nPrint values in original order ..." << endl;

    auto pos = a.begin();
    while ( pos != a.end() )
        cout << *pos++ << "t";
    cout << endl;

    cout << "nPrint values in reverse order ..." << endl;

    auto rpos = a.rbegin();
    while ( rpos != a.rend() )
    cout << *rpos++ << "t";
    cout << endl;

    return 0;
}
```

我们将使用以下命令来获取输出：

```cpp
./a.out
```

输出如下：

```cpp
Print values in original order ...
100   200   300   400   500   600

Print values in reverse order ...
600   500   400   300   200   100
```

# Vector

向量是一个非常有用的序列容器，它的工作方式与数组完全相同，只是向量可以在运行时增长和缩小，而数组的大小是固定的。然而，在数组和向量底层使用的数据结构是一个简单的内置 C/C++风格数组。

让我们看下面的例子更好地理解向量：

```cpp
#include <iostream>
#include <vector>
#include <algorithm>
using namespace std;

int main () {
  vector<int> v = { 1, 5, 2, 4, 3 };

  cout << "nSize of vector is " << v.size() << endl;

  auto pos = v.begin();

  cout << "nPrint vector elements before sorting" << endl;
  while ( pos != v.end() )
    cout << *pos++ << "t";
  cout << endl;

  sort( v.begin(), v.end() );

  pos = v.begin();

  cout << "nPrint vector elements after sorting" << endl;

  while ( pos != v.end() )
    cout << *pos++ << "t";
  cout << endl;

  return 0;
}
```

可以编译上述代码，并使用以下命令查看输出：

```cpp
g++ main.cpp -std=c++17
./a.out
```

程序的输出如下：

```cpp
Size of vector is 5

Print vector elements before sorting
1     5     2     4     3

Print vector elements after sorting
1     2     3     4     5
```

# 代码演示

以下行声明了一个向量，并用五个元素初始化了向量：

```cpp
vector<int> v = { 1, 5, 2, 4, 3 };
```

然而，向量还允许使用`vector::push_back<data_type>( value )` API 将值附加到向量的末尾。`sort()`算法接受两个表示必须排序的数据范围的随机访问迭代器。由于向量在内部使用内置的 C/C++数组，就像 STL 数组容器一样，向量也支持随机访问迭代器；因此，`sort()`函数是一个运行时复杂度为对数的高效算法，即*O(N log2 (N))*。

# 常用的向量 API

以下表格显示了一些常用的向量 API：

| **API** | **描述** |
| --- | --- |
| `at ( int index )` | 返回存储在索引位置的值。如果索引无效，则会抛出`std::out_of_range`异常。 |
| `operator [ int index ]` | 返回存储在索引位置的值。这个函数比`at( int index )`更快，因为它不执行边界检查。 |
| `front()` | 返回向量中存储的第一个值。 |
| `back()` | 返回向量中存储的最后一个值。 |
| `empty()` | 如果向量为空，则返回 true，否则返回 false。 |
| `size()` | 返回向量中存储的值的数量。 |
| `reserve( int size )` | 这会保留向量的初始大小。当向量大小达到其容量时，插入新值需要向量调整大小。这使得插入消耗*O(N)*的运行复杂度。`reserve()`方法是对描述的问题的一种解决方法。 |
| `capacity()` | 返回向量的总容量，而大小是向量中实际存储的值。 |
| `clear()` | 这会清除所有的值。 |
| `push_back<data_type>( value )` | 这会在向量的末尾添加一个新值。 |

使用`istream_iterator`和`ostream_iterator`从向量中读取和打印会非常有趣和方便。以下代码演示了向量的使用：

```cpp
#include <iostream>
#include <vector>
#include <algorithm>
#include <iterator>
using namespace std;

int main () {
    vector<int> v;

    cout << "nType empty string to end the input once you are done feeding the vector" << endl;
    cout << "nEnter some numbers to feed the vector ..." << endl;

    istream_iterator<int> start_input(cin);
    istream_iterator<int> end_input;

    copy ( start_input, end_input, back_inserter( v ) );

    cout << "nPrint the vector ..." << endl;
    copy ( v.begin(), v.end(), ostream_iterator<int>(cout, "t") );
    cout << endl;

    return 0;
}
```

请注意，程序的输出被跳过，因为输出取决于您输入的输入。请随意在命令行上尝试这些指令。

# 代码演示

基本上，复制算法接受一系列迭代器，其中前两个参数表示源，第三个参数表示目标，这恰好是向量：

```cpp
istream_iterator<int> start_input(cin);
istream_iterator<int> end_input;

copy ( start_input, end_input, back_inserter( v ) );
```

`start_input`迭代器实例定义了一个从`istream`和`cin`接收输入的`istream_iterator`迭代器，而`end_input`迭代器实例定义了一个文件结束分隔符，默认情况下是一个空字符串(`""`)。因此，输入可以通过在命令行输入终端中键入`""`来终止。

同样，让我们了解下面的代码片段：

```cpp
cout << "nPrint the vector ..." << endl;
copy ( v.begin(), v.end(), ostream_iterator<int>(cout, "t") );
cout << endl;
```

复制算法用于将向量中的值逐个复制到`ostream`中，并用制表符(`t`)分隔输出。

# 向量的缺陷

每个 STL 容器都有自己的优点和缺点。没有一个 STL 容器在所有情况下都表现更好。向量在内部使用数组数据结构，而在 C/C++中数组的大小是固定的。因此，当您尝试在向量中添加新值时，如果向量的大小已经达到了最大容量，那么向量将分配新的连续位置，可以容纳旧值和新值，并且在连续位置开始复制旧值。一旦所有数据元素都被复制，向量将使旧位置无效。

每当这种情况发生时，向量插入将需要*O(N)*的运行时复杂度。随着向量大小随时间增长，*O(N)*的运行时复杂度将导致性能相当糟糕。如果您知道所需的最大大小，可以预留足够的初始大小来克服这个问题。然而，并不是在所有情况下都需要使用向量。当然，向量支持动态大小和随机访问，在某些情况下具有性能优势，但您正在处理的功能可能并不真正需要随机访问，这种情况下列表、双端队列或其他某些容器可能更适合您。

# 列表

列表 STL 容器在内部使用双向链表数据结构。因此，列表仅支持顺序访问，在最坏的情况下在列表中搜索随机值可能需要*O(N)*的运行时复杂度。然而，如果您确定只需要顺序访问，列表确实提供了自己的好处。列表 STL 容器允许您以常数时间复杂度在末尾、前面或中间插入数据元素，即在最佳、平均和最坏的情况下都是*O(1)*的运行时复杂度。

以下图片展示了列表 STL 使用的内部数据结构：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/90865fd4-3858-4fbc-bdd2-60c23f16c550.png)

让我们编写一个简单的程序来亲身体验使用列表 STL：

```cpp
#include <iostream>
#include <list>
#include <iterator>
#include <algorithm>
using namespace std;

int main () {

  list<int> l;

  for (int count=0; count<5; ++count)
    l.push_back( (count+1) * 100 );

  auto pos = l.begin();

  cout << "nPrint the list ..." << endl;
  while ( pos != l.end() )
    cout << *pos++ << "-->";
  cout << " X" << endl;

  return 0;
}
```

我相信到现在为止，您已经品尝到了 C++ STL 的优雅和强大之处。观察到语法在所有 STL 容器中保持不变，是不是很酷？您可能已经注意到，无论您使用数组、向量还是列表，语法都保持不变。相信我，当您探索其他 STL 容器时，也会有同样的感觉。

话虽如此，前面的代码是不言自明的，因为我们在其他容器中做了几乎相同的事情。

让我们尝试对列表进行排序，如下面的代码所示：

```cpp
#include <iostream>
#include <list>
#include <iterator>
#include <algorithm>
using namespace std;

int main () {

    list<int> l = { 100, 20, 80, 50, 60, 5 };

    auto pos = l.begin();

    cout << "nPrint the list before sorting ..." << endl;
    copy ( l.begin(), l.end(), ostream_iterator<int>( cout, "-->" ));
    cout << "X" << endl;

    l.sort();

    cout << "nPrint the list after sorting ..." << endl;
    copy ( l.begin(), l.end(), ostream_iterator<int>( cout, "-->" ));
    cout << "X" << endl; 

    return 0;
}
```

您注意到了`sort()`方法吗？是的，列表容器有自己的排序算法。列表容器支持自己版本的排序算法的原因是，通用的`sort()`算法需要一个随机访问迭代器，而列表容器不支持随机访问。在这种情况下，相应的容器将提供自己的高效算法来克服这个缺点。

有趣的是，列表支持的`sort`算法的运行时复杂度为*O(N log2 N)*。

# 列表中常用的 API

以下表格显示了 STL 列表中最常用的 API：

| **API** | **描述** |
| --- | --- |
| `front()` | 这返回列表中存储的第一个值 |
| `back() ` | 这返回列表中存储的最后一个值 |
| `size()` | 这返回列表中存储的值的数量 |
| `empty()` | 当列表为空时返回`true`，否则返回`false` |
| `clear()` | 这会清除列表中存储的所有值 |
| `push_back<data_type>( value )` | 这在列表的末尾添加一个值 |
| `push_front<data_type>( value )` | 这在列表的前面添加一个值 |
| `merge( list )` | 这将两个相同类型值的排序列表合并 |
| `reverse()` | 这会反转列表 |
| `unique()` | 这从列表中删除重复的值 |
| `sort()` | 这会对列表中存储的值进行排序 |

# Forward list

STL 的`forward_list`容器是建立在单向链表数据结构之上的；因此，它只支持向前导航。由于`forward_list`在内存和运行时方面每个节点消耗一个较少的指针，因此与列表容器相比，它被认为更有效。然而，作为性能优势的额外代价，`forward_list`必须放弃一些功能。

以下图表显示了`forward_list`中使用的内部数据结构：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/149c8d91-7bb4-4194-9635-f9bf4a0ead5e.png)

让我们来探索以下示例代码：

```cpp
#include <iostream>
#include <forward_list>
#include <iterator>
#include <algorithm>
using namespace std;

int main ( ) {

  forward_list<int> l = { 10, 10, 20, 30, 45, 45, 50 };

  cout << "nlist with all values ..." << endl;
  copy ( l.begin(), l.end(), ostream_iterator<int>(cout, "t") );

  cout << "nSize of list with duplicates is " << distance( l.begin(), l.end() ) << endl;

  l.unique();

  cout << "nSize of list without duplicates is " << distance( l.begin(), l.end() ) << endl;

  l.resize( distance( l.begin(), l.end() ) );

  cout << "nlist after removing duplicates ..." << endl;
  copy ( l.begin(), l.end(), ostream_iterator<int>(cout, "t") );
  cout << endl;

  return 0;

}
```

输出可以通过以下命令查看：

```cpp
./a.out
```

输出将如下所示：

```cpp
list with all values ...
10    10    20    30    45    45    50
Size of list with duplicates is 7

Size of list without duplicates is 5

list after removing duplicates ...
10    20   30   45   50
```

# 代码演示

以下代码声明并初始化了`forward_list`容器，其中包含一些唯一的值和一些重复的值：

```cpp
forward_list<int> l = { 10, 10, 20, 30, 45, 45, 50 };
```

由于`forward_list`容器不支持`size()`函数，我们使用`distance()`函数来找到列表的大小：

```cpp
cout << "nSize of list with duplicates is " << distance( l.begin(), l.end() ) << endl;
```

以下`forward_list<int>::unique()`函数会移除重复的整数，只保留唯一的值：

```cpp
l.unique();
```

# `forward_list`容器中常用的 API

下表显示了常用的`forward_list` API：

| **API** | **描述** |
| --- | --- |
| `front()` | 这返回`forward_list`容器中存储的第一个值 |
| `empty()` | 当`forward_list`容器为空时返回 true，否则返回 false。 |
| `clear()` | 这会清除`forward_list`中存储的所有值。 |
| `push_front<data_type>( value )` | 这会将一个值添加到`forward_list`的前面。 |
| `merge( list )` | 这会合并两个排序的`forward_list`容器，其值类型相同 |
| `reverse()` | 这会颠倒`forward_list`容器 |
| `unique()` | 这会从`forward_list`容器中移除重复的值。 |
| `sort()` | 这会对`forward_list`中存储的值进行排序 |

让我们再来看一个例子，以更好地理解`forward_list`容器：

```cpp
#include <iostream>
#include <forward_list>
#include <iterator>
#include <algorithm>
using namespace std;

int main () {

    forward_list<int> list1 = { 10, 20, 10, 45, 45, 50, 25 };
    forward_list<int> list2 = { 20, 35, 27, 15, 100, 85, 12, 15 };

    cout << "nFirst list before sorting ..." << endl;
    copy ( list1.begin(), list1.end(), ostream_iterator<int>(cout, "t") );
    cout << endl; 

    cout << "nSecond list before sorting ..." << endl;
    copy ( list2.begin(), list2.end(), ostream_iterator<int>(cout, "t") );
    cout << endl;

    list1.sort();
    list2.sort();

    cout << "nFirst list after sorting ..." << endl;
    copy ( list1.begin(), list1.end(), ostream_iterator<int>(cout, "t") );
    cout << endl; 

    cout << "nSecond list after sorting ..." << endl;
    copy ( list2.begin(), list2.end(), ostream_iterator<int>(cout, "t") );
    cout << endl;    

    list1.merge ( list2 );

    cout << "nMerged list ..." << endl;
    copy ( list1.begin(), list1.end(), ostream_iterator<int>(cout, "t") );

    cout << "nMerged list after removing duplicates ..." << endl;
    list1.unique(); 
    copy ( list1.begin(), list1.end(), ostream_iterator<int>(cout, "t") );

    return 0;
}
```

上面的代码片段是一个有趣的例子，演示了`sort()`、`merge()`和`unique()` STL 算法的实际用途。

输出可以通过以下命令查看：

```cpp
./a.out
```

程序的输出如下：

```cpp
First list before sorting ...
10   20   10   45   45   50   25
Second list before sorting ...
20   35   27   15   100  85   12   15

First list after sorting ...
10   10   20   25   45   45   50
Second list after sorting ...
12   15   15   20   27   35   85   100

Merged list ...
10   10   12   15   15   20   20   25   27   35   45   45  50   85  100
Merged list after removing duplicates ...
10   12   15   20   25   27   35   45   50   85  100
```

输出和程序都很容易理解。

# Deque

deque 容器是一个双端队列，其使用的数据结构可以是动态数组或向量。在 deque 中，可以在前面和后面插入元素，时间复杂度为*O(1)*，而在向量中，插入元素在后面的时间复杂度为*O(1)*，而在前面的时间复杂度为*O(N)*。deque 不会遭受向量遭受的重新分配问题。然而，deque 具有向量的所有优点，只是在性能方面略优于向量，因为每一行都有几行动态数组或向量。

以下图表显示了 deque 容器中使用的内部数据结构：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/69ccaa1c-1be2-4f91-89b2-fa780a1d54b0.png)

让我们编写一个简单的程序来尝试 deque 容器：

```cpp
#include <iostream>
#include <deque>
#include <algorithm>
#include <iterator>
using namespace std;

int main () {
  deque<int> d = { 10, 20, 30, 40, 50 };

  cout << "nInitial size of deque is " << d.size() << endl;

  d.push_back( 60 );
  d.push_front( 5 );

  cout << "nSize of deque after push back and front is " << d.size() << endl;

  copy ( d.begin(), d.end(), ostream_iterator<int>( cout, "t" ) );
  d.clear();

  cout << "nSize of deque after clearing all values is " << d.size() <<
endl;

  cout << "nIs the deque empty after clearing values ? " << ( d.empty()
? "true" : "false" ) << endl;

return 0;
}
```

输出可以通过以下命令查看：

```cpp
./a.out
```

程序的输出如下：

```cpp
Intitial size of deque is 5

Size of deque after push back and front is 7

Print the deque ...
5  10  20  30  40  50  60
Size of deque after clearing all values is 0

Is the deque empty after clearing values ? true
```

# deque 中常用的 API

下表显示了常用的 deque API：

| **API** | **描述** |
| --- | --- |
| `at ( int index )` | 这返回存储在索引位置的值。如果索引无效，则会抛出`std::out_of_range`异常。 |
| `operator [ int index ]` | 这返回存储在索引位置的值。与`at( int index )`相比，此函数不执行边界检查，因此速度更快。 |
| `front()` | 这返回 deque 中存储的第一个值。 |
| `back() ` | 这返回 deque 中存储的最后一个值。 |
| `empty()` | 如果 deque 为空则返回`true`，否则返回`false`。 |
| `size() ` | 这返回 deque 中存储的值的数量。 |
| `capacity()` | 这会返回 deque 的总容量，而`size()`返回 deque 中实际存储的值的数量。 |
| `clear()` | 这会清除所有值。 |
| `push_back<data_type>( value )` | 这会在 deque 的末尾添加一个新值。 |

# 关联容器

关联容器以排序的方式存储数据，与序列容器不同。因此，关联容器不会保留插入数据的顺序。关联容器在搜索值时非常高效，具有*O(log n)*的运行时复杂度。每次向容器添加新值时，如果需要，容器将重新排序内部存储的值。

STL 支持以下类型的关联容器：

+   集合

+   映射

+   多重集

+   多重映射

+   无序集合

+   无序多重集

+   无序映射

+   无序多重映射

关联容器将数据组织为键-值对。数据将根据键进行排序，以实现随机和更快的访问。关联容器有两种类型：

+   有序

+   无序

以下关联容器属于有序容器，因为它们以特定的方式排序。有序关联容器通常使用某种形式的**二叉搜索树**（**BST**）；通常使用红黑树来存储数据：

+   集合

+   映射

+   多重集

+   多重映射

以下关联容器属于无序容器，因为它们没有以任何特定方式排序，并且它们使用哈希表：

+   无序集合

+   无序映射

+   无序多重集

+   无序多重映射

让我们在以下小节中通过示例了解先前提到的容器。

# 集合

集合容器以排序的方式仅存储唯一的值。集合使用值作为键来组织值。集合容器是不可变的，也就是说，存储在集合中的值不能被修改；但是，值可以被删除。集合通常使用红黑树数据结构，这是一种平衡二叉搜索树。集合操作的时间复杂度保证为*O(log N)*。

让我们使用一个集合编写一个简单的程序：

```cpp
#include <iostream>
#include <set>
#include <vector>
#include <iterator>
#include <algorithm>
using namespace std;

int main( ) {
    set<int> s1 = { 1, 3, 5, 7, 9 };
    set<int> s2 = { 2, 3, 7, 8, 10 };

    vector<int> v( s1.size() + s2.size() );

    cout << "nFirst set values are ..." << endl;
    copy ( s1.begin(), s1.end(), ostream_iterator<int> ( cout, "t" ) );
    cout << endl;

    cout << "nSecond set values are ..." << endl;
    copy ( s2.begin(), s2.end(), ostream_iterator<int> ( cout, "t" ) );
    cout << endl;

    auto pos = set_difference ( s1.begin(), s1.end(), s2.begin(), s2.end(), v.begin() ); 
    v.resize ( pos - v.begin() );

    cout << "nValues present in set one but not in set two are ..." << endl;
    copy ( v.begin(), v.end(), ostream_iterator<int> ( cout, "t" ) );
    cout << endl; 

    v.clear();

    v.resize ( s1.size() + s2.size() );

    pos = set_union ( s1.begin(), s1.end(), s2.begin(), s2.end(), v.begin() );

    v.resize ( pos - v.begin() );

    cout << "nMerged set values in vector are ..." << endl;
    copy ( v.begin(), v.end(), ostream_iterator<int> ( cout, "t" ) );
    cout << endl; 

    return 0;
}
```

可以使用以下命令查看输出：

```cpp
./a.out
```

程序的输出如下：

```cpp
First set values are ...
1   3   5   7   9

Second set values are ...
2   3   7   8   10

Values present in set one but not in set two are ...
1   5   9

Merged values of first and second set are ...
1   2   3   5   7   8   9  10
```

# 代码演示

以下代码声明并初始化了两个集合`s1`和`s2`：

```cpp
set<int> s1 = { 1, 3, 5, 7, 9 };
set<int> s2 = { 2, 3, 7, 8, 10 };
```

以下行将确保向量有足够的空间来存储结果向量中的值：

```cpp
vector<int> v( s1.size() + s2.size() );
```

以下代码将打印`s1`和`s2`中的值：

```cpp
cout << "nFirst set values are ..." << endl;
copy ( s1.begin(), s1.end(), ostream_iterator<int> ( cout, "t" ) );
cout << endl;

cout << "nSecond set values are ..." << endl;
copy ( s2.begin(), s2.end(), ostream_iterator<int> ( cout, "t" ) );
cout << endl;
```

`set_difference()`算法将使用集合`s1`中仅存在而不在`s2`中的值填充向量`v`。迭代器`pos`将指向向量中的最后一个元素；因此，向量`resize`将确保向量中的额外空间被移除：

```cpp
auto pos = set_difference ( s1.begin(), s1.end(), s2.begin(), s2.end(), v.begin() ); 
v.resize ( pos - v.begin() );
```

以下代码将打印向量`v`中填充的值：

```cpp
cout << "nValues present in set one but not in set two are ..." << endl;
copy ( v.begin(), v.end(), ostream_iterator<int> ( cout, "t" ) );
cout << endl;
```

`set_union()`算法将合并集合`s1`和`s2`的内容到向量中，然后调整向量的大小以适应合并后的值：

```cpp
pos = set_union ( s1.begin(), s1.end(), s2.begin(), s2.end(), v.begin() );
v.resize ( pos - v.begin() );
```

以下代码将打印向量`v`中填充的合并值：

```cpp
cout << "nMerged values of first and second set are ..." << endl;
copy ( v.begin(), v.end(), ostream_iterator<int> ( cout, "t" ) );
cout << endl;
```

# 集合中常用的 API

以下表格描述了常用的集合 API：

| **API** | **描述** |
| --- | --- |
| `insert( value )` | 这会将一个值插入到集合中 |
| `clear()` | 这会清除集合中的所有值 |
| `size()` | 这会返回集合中存在的条目总数 |
| `empty()` | 如果集合为空，则会打印`true`，否则返回`false` |
| `find()` | 这会查找具有指定键的元素并返回迭代器位置 |
| `equal_range()` | 这会返回与特定键匹配的元素范围 |
| `lower_bound()` | 这会返回指向第一个不小于给定键的元素的迭代器 |
| `upper_bound()` | 这会返回指向第一个大于给定键的元素的迭代器 |

# 映射

映射按键组织值。与集合不同，映射每个值都有一个专用键。映射通常使用红黑树作为内部数据结构，这是一种平衡的 BST，可以保证在映射中搜索或定位值的*O(log N)*运行时效率。映射中存储的值根据键使用红黑树进行排序。映射中使用的键必须是唯一的。映射不会保留输入的顺序，因为它根据键重新组织值，也就是说，红黑树将被旋转以平衡红黑树高度。

让我们写一个简单的程序来理解映射的用法：

```cpp
#include <iostream>
#include <map>
#include <iterator>
#include <algorithm>
using namespace std;
int main ( ) {

  map<string, long> contacts;

  contacts["Jegan"] = 123456789;
  contacts["Meena"] = 523456289;
  contacts["Nitesh"] = 623856729;
  contacts["Sriram"] = 993456789;

  auto pos = contacts.find( "Sriram" );

  if ( pos != contacts.end() )
    cout << pos->second << endl;

  return 0;
}
```

让我们编译并检查程序的输出：

```cpp
g++ main.cpp -std=c++17
./a.out
```

输出如下：

```cpp
Mobile number of Sriram is 8901122334
```

# 代码漫游

以下行声明了一个映射，其中`string`名称作为键，`long`手机号作为存储在映射中的值：

```cpp
map< string, long > contacts;
```

以下代码片段添加了四个按名称组织的联系人：

```cpp
 contacts[ "Jegan" ] = 1234567890;
 contacts[ "Meena" ] = 5784433221;
 contacts[ "Nitesh" ] = 4567891234;
 contacts[ "Sriram" ] = 8901122334;
```

以下行将尝试在联系人映射中查找名为`Sriram`的联系人；如果找到`Sriram`，则`find()`函数将返回指向键值对位置的迭代器；否则返回`contacts.end()`位置：

```cpp
 auto pos = contacts.find( "Sriram" );
```

以下代码验证迭代器`pos`是否已达到`contacts.end()`并打印联系人号码。由于映射是一个关联容器，它存储`key=>value`对；因此，`pos->first`表示键，`pos->second`表示值：

```cpp
 if ( pos != contacts.end() )
 cout << "nMobile number of " << pos->first << " is " << pos->second << endl;
 else
 cout << "nContact not found." << endl;
```

# 映射中常用的 API

以下表格显示了常用的映射 API：

| **API** | **描述** |
| --- | --- |
| `at ( key )` | 如果找到键，则返回相应键的值；否则抛出`std::out_of_range`异常 |
| `operator[ key ]` | 如果找到键，则更新相应键的现有值；否则，将添加一个具有相应`key=>value`的新条目 |
| `empty()` | 如果映射为空，则返回`true`，否则返回`false` |
| `size()` | 返回映射中存储的`key=>value`对的数量 |
| `clear()` | 清除映射中存储的条目 |
| `count()` | 返回与给定键匹配的元素数量 |
| `find()` | 查找具有指定键的元素 |

# 多重集合

多重集合容器的工作方式与集合容器类似，只是集合只允许存储唯一的值，而多重集合允许存储重复的值。如你所知，在集合和多重集合容器的情况下，值本身被用作键来组织数据。多重集合容器就像一个集合；它不允许修改存储在多重集合中的值。

让我们写一个使用多重集合的简单程序：

```cpp
#include <iostream>
#include <set>
#include <iterator>
#include <algorithm>
using namespace std;

int main() {
  multiset<int> s = { 10, 30, 10, 50, 70, 90 };

  cout << "nMultiset values are ..." << endl;

  copy ( s.begin(), s.end(), ostream_iterator<int> ( cout, "t" ) );
  cout << endl;

  return 0;
}
```

可以使用以下命令查看输出：

```cpp
./a.out
```

程序的输出如下：

```cpp
Multiset values are ...
10 30 10 50 70 90
```

有趣的是，在前面的输出中，你可以看到多重集合包含重复的值。

# 多重映射

多重映射与映射完全相同，只是多重映射容器允许使用相同的键存储多个值。

让我们用一个简单的例子来探索多重映射容器：

```cpp
#include <iostream>
#include <map>
#include <vector>
#include <iterator>
#include <algorithm>
using namespace std;

int main() {
  multimap< string, long > contacts = {
    { "Jegan", 2232342343 },
    { "Meena", 3243435343 },
    { "Nitesh", 6234324343 },
    { "Sriram", 8932443241 },
    { "Nitesh", 5534327346 }
  };

  auto pos = contacts.find ( "Nitesh" );
  int count = contacts.count( "Nitesh" );
  int index = 0;

  while ( pos != contacts.end() ) { 
  cout << "\nMobile number of " << pos->first << " is " << 
  pos->second << endl; 
  ++index; 
  ++pos;
  if ( index == count )
     break; 
}
  return 0;
}
```

该程序可以编译，并且可以使用以下命令查看输出：

```cpp
g++ main.cpp -std=c++17

./a.out
```

程序的输出如下：

```cpp
Mobile number of Nitesh is 6234324343
Mobile number of Nitesh is 5534327346
```

# 无序集合

无序集合的工作方式与集合类似，只是这些容器的内部行为不同。集合使用红黑树，而无序集合使用哈希表。集合操作的时间复杂度为*O(log N)*，而无序集合操作的时间复杂度为*O(1)*；因此，无序集合比集合更快。

无序集合中存储的值没有特定的顺序，不像集合那样以排序的方式存储值。如果性能是标准，那么无序集合是一个不错的选择；然而，如果需要以排序的方式迭代值，那么集合是一个不错的选择。

# 无序映射

无序映射的工作方式类似于映射，只是这些容器的内部行为不同。映射使用红黑树，而无序映射使用哈希表。映射操作的时间复杂度为*O(log N)*，而无序映射操作的时间复杂度为*O(1)*；因此，无序映射比映射更快。

无序映射中存储的值没有任何特定的顺序，不像映射中的值按键排序。

# 无序多重集

无序多重集的工作方式类似于多重集，只是这些容器的内部行为不同。多重集使用红黑树，而无序多重集使用哈希表。多重集操作的时间复杂度为*O(log N)*，而无序多重集操作的时间复杂度为*O(1)*。因此，无序多重集比多重集更快。

无序多重集中存储的值没有任何特定的顺序，不像多重集中的值以排序的方式存储。如果性能是标准，无序多重集是一个不错的选择；然而，如果需要以排序的方式迭代值，则多重集是一个不错的选择。

# 无序多重映射

无序多重映射的工作方式类似于多重映射，只是这些容器的内部行为不同。多重映射使用红黑树，而无序多重映射使用哈希表。多重映射操作的时间复杂度为*O(log N)*，而无序多重映射操作的时间复杂度为*O(1)*；因此，无序多重映射比多重映射更快。

无序多重映射中存储的值没有任何特定的顺序，不像多重映射中的值按键排序。如果性能是标准，那么无序多重映射是一个不错的选择；然而，如果需要以排序的方式迭代值，则多重映射是一个不错的选择。

# 容器适配器

容器适配器通过组合而不是继承来适配现有容器以提供新的容器。

STL 容器不能通过继承来扩展，因为它们的构造函数不是虚拟的。在整个 STL 中，您可以观察到，虽然在运算符重载和模板方面都使用了静态多态性，但出于性能原因，动态多态性是有意避免的。因此，通过对现有容器进行子类化来扩展 STL 并不是一个好主意，因为容器类并没有设计成像基类一样行为，这会导致内存泄漏。

STL 支持以下容器适配器：

+   栈

+   队列

+   优先队列

让我们在以下小节中探索容器适配器。

# 栈

栈不是一个新的容器；它是一个模板适配器类。适配器容器包装现有容器并提供高级功能。栈适配器容器提供栈操作，同时隐藏对栈不相关的不必要功能。STL 栈默认使用双端队列容器；然而，在栈实例化期间，我们可以指示栈使用任何满足栈要求的现有容器。

双端队列、列表和向量满足栈适配器的要求。

栈遵循**后进先出**（**LIFO**）的原则。

# 栈中常用的 API

以下表格显示了常用的栈 API：

| **API** | **描述** |
| --- | --- |
| `top()` | 这将返回栈中的顶部值，即最后添加的值 |
| `push<data_type>( value )` | 这将提供的值推送到栈的顶部 |
| `pop()` | 这将从栈中移除顶部的值 |
| `size()` | 这将返回栈中存在的值的数量 |
| `empty()` | 如果栈为空，则返回`true`；否则返回`false` |

是时候动手了；让我们编写一个简单的程序来使用栈：

```cpp
#include <iostream>
#include <stack>
#include <iterator>
#include <algorithm>
using namespace std;

int main ( ) {

  stack<string> spoken_languages;

  spoken_languages.push ( "French" );
  spoken_languages.push ( "German" );
  spoken_languages.push ( "English" );
  spoken_languages.push ( "Hindi" );
  spoken_languages.push ( "Sanskrit" );
  spoken_languages.push ( "Tamil" );

  cout << "nValues in Stack are ..." << endl;
  while ( ! spoken_languages.empty() ) {
              cout << spoken_languages.top() << endl;
        spoken_languages.pop();
  }
  cout << endl;

  return 0;
}
```

程序可以编译，并且可以使用以下命令查看输出：

```cpp
g++ main.cpp -std=c++17

./a.out
```

程序的输出如下：

```cpp
Values in Stack are ...
Tamil
Kannada
Telugu
Sanskrit
Hindi
English
German
French
```

从前面的输出中，我们可以看到栈的 LIFO 行为。

# 队列

队列基于**先进先出**（FIFO）原则工作。队列不是一个新的容器；它是一个模板化的适配器类，它包装了一个现有的容器，并提供了队列操作所需的高级功能，同时隐藏了对队列无关的不必要功能。STL 队列默认使用双端队列容器；然而，我们可以在队列实例化期间指示队列使用满足队列要求的任何现有容器。

在队列中，新值可以添加到后面并从前面删除。双端队列、列表和向量满足队列适配器的要求。

# 队列中常用的 API

以下表格显示了常用的队列 API：

| **API** | **描述** |
| --- | --- |
| `push()` | 这在队列的后面追加一个新值 |
| `pop()` | 这删除队列前面的值 |
| `front()` | 这返回队列前面的值 |
| `back()` | 这返回队列的后面的值 |
| `empty()` | 当队列为空时返回`true`；否则返回`false` |
| `size()` | 这返回存储在队列中的值的数量 |

让我们在以下程序中使用队列：

```cpp
#include <iostream>
#include <queue>
#include <iterator>
#include <algorithm>
using namespace std;

int main () {
  queue<int> q;

  q.push ( 100 );
  q.push ( 200 );
  q.push ( 300 );

  cout << "nValues in Queue are ..." << endl;
  while ( ! q.empty() ) {
    cout << q.front() << endl;
    q.pop();
  }

  return 0;
}
```

程序可以编译，并且可以使用以下命令查看输出：

```cpp
g++ main.cpp -std=c++17

./a.out
```

程序的输出如下：

```cpp
Values in Queue are ...
100
200
300
```

从前面的输出中，您可以观察到值以它们被推入的相同顺序弹出，即 FIFO。

# 优先队列

优先队列不是一个新的容器；它是一个模板化的适配器类，它包装了一个现有的容器，并提供了优先队列操作所需的高级功能，同时隐藏了对优先队列无关的不必要功能。优先队列默认使用向量容器；然而，双端队列容器也满足优先队列的要求。因此，在优先队列实例化期间，您可以指示优先队列也使用双端队列。

优先队列以这样的方式组织数据，使得最高优先级的值首先出现；换句话说，值按降序排序。

双端队列和向量满足优先队列适配器的要求。

# 优先队列中常用的 API

以下表格显示了常用的优先队列 API：

| **API** | **描述** |
| --- | --- |
| `push()` | 这在优先队列的后面追加一个新值 |
| `pop()` | 这删除优先队列前面的值 |
| `empty()` | 当优先队列为空时返回`true`；否则返回`false` |
| `size()` | 这返回存储在优先队列中的值的数量 |
| `top()` | 这返回优先队列前面的值 |

让我们编写一个简单的程序来理解`priority_queue`：

```cpp
#include <iostream>
#include <queue>
#include <iterator>
#include <algorithm>
using namespace std;

int main () {
  priority_queue<int> q;

  q.push( 100 );
  q.push( 50 );
  q.push( 1000 );
  q.push( 800 );
  q.push( 300 );

  cout << "nSequence in which value are inserted are ..." << endl;
  cout << "100t50t1000t800t300" << endl;
  cout << "Priority queue values are ..." << endl;

  while ( ! q.empty() ) {
    cout << q.top() << "t";
    q.pop();
  }
  cout << endl;

  return 0;
}
```

程序可以编译，并且可以使用以下命令查看输出：

```cpp
g++ main.cpp -std=c++17

./a.out
```

程序的输出如下：

```cpp
Sequence in which value are inserted are ...
100   50   1000  800   300

Priority queue values are ...
1000  800   300   100   50
```

从前面的输出中，您可以观察到`priority_queue`是一种特殊类型的队列，它重新排列输入，使得最高值首先出现。

# 总结

在本章中，您学习了现成的通用容器、函数对象、迭代器和算法。您还学习了集合、映射、多重集和多重映射关联容器，它们的内部数据结构以及可以应用于它们的常见算法。此外，您还学习了如何使用各种容器与实际的代码示例。

在下一章中，您将学习模板编程，这将帮助您掌握模板的基本知识。


# 第三章：模板编程

在本章中，我们将涵盖以下主题：

+   泛型编程

+   函数模板

+   类模板

+   重载函数模板

+   泛型类

+   显式类特化

+   部分特化

现在让我们开始学习泛型编程。

# 泛型编程

泛型编程是一种编程风格，可以帮助您开发可重用的代码或通用算法，可以应用于各种数据类型。每当调用通用算法时，数据类型将以特殊的语法作为参数提供。

假设我们想要编写一个`sort()`函数，它接受一个需要按升序排序的输入数组。其次，我们需要`sort()`函数来对`int`、`double`、`char`和`string`数据类型进行排序。有几种方法可以解决这个问题：

+   我们可以为每种数据类型编写四个不同的`sort()`函数

+   我们也可以编写一个单一的宏函数

好吧，这两种方法都有各自的优点和缺点。第一种方法的优点是，由于`int`、`double`、`char`和`string`数据类型都有专门的函数，如果提供了不正确的数据类型，编译器将能够执行类型检查。第一种方法的缺点是，尽管所有函数的逻辑都相同，但我们必须编写四个不同的函数。如果在算法中发现了错误，必须分别在所有四个函数中进行修复；因此，需要进行大量的维护工作。如果我们需要支持另一种数据类型，我们将不得不编写另一个函数，随着需要支持更多的数据类型，这种情况将不断增加。

第二种方法的优点是，我们可以为所有数据类型编写一个宏。然而，一个非常令人沮丧的缺点是，编译器将无法执行类型检查，这种方法更容易出现错误，并可能引发许多意外的麻烦。这种方法与面向对象的编码原则背道而驰。

C++通过模板支持泛型编程，具有以下优点：

+   我们只需要使用模板编写一个函数

+   模板支持静态多态

+   模板提供了前面两种方法的所有优点，没有任何缺点

+   泛型编程实现了代码重用

+   生成的代码是面向对象的

+   C++编译器可以在编译时执行类型检查

+   易于维护

+   支持各种内置和用户定义的数据类型

然而，缺点如下：

+   并不是所有的 C++程序员都感到舒适编写基于模板的代码，但这只是一个初始的阻碍

+   在某些情况下，模板可能会使代码膨胀并增加二进制占用空间，导致性能问题

# 函数模板

函数模板允许您对数据类型进行参数化。之所以称之为泛型编程，是因为单个模板函数将支持许多内置和用户定义的数据类型。模板化函数的工作原理类似于**C 风格的宏**，只是 C++编译器在调用模板函数时会对函数进行类型检查，以确保我们在调用模板函数时提供的数据类型是兼容的。

通过一个简单的例子来更容易理解模板的概念，如下所示：

```cpp
#include <iostream>
#include <algorithm>
#include <iterator>
using namespace std;

template <typename T, int size>
void sort ( T input[] ) {

     for ( int i=0; i<size; ++i) { 
         for (int j=0; j<size; ++j) {
              if ( input[i] < input[j] )
                  swap (input[i], input[j] );
         }
     }

}

int main () {
        int a[10] = { 100, 10, 40, 20, 60, 80, 5, 50, 30, 25 };

        cout << "nValues in the int array before sorting ..." << endl;
        copy ( a, a+10, ostream_iterator<int>( cout, "t" ) );
        cout << endl;

        ::sort<int, 10>( a );

        cout << "nValues in the int array after sorting ..." << endl;
        copy ( a, a+10, ostream_iterator<int>( cout, "t" ) );
        cout << endl;

        double b[5] = { 85.6d, 76.13d, 0.012d, 1.57d, 2.56d };

        cout << "nValues in the double array before sorting ..." << endl;
        copy ( b, b+5, ostream_iterator<double>( cout, "t" ) );
        cout << endl;

        ::sort<double, 5>( b );

        cout << "nValues in the double array after sorting ..." << endl;
        copy ( b, b+5, ostream_iterator<double>( cout, "t" ) );
        cout << endl;

        string names[6] = {
               "Rishi Kumar Sahay",
               "Arun KR",
               "Arun CR",
               "Ninad",
               "Pankaj",
               "Nikita"
        };

        cout << "nNames before sorting ..." << endl;
        copy ( names, names+6, ostream_iterator<string>( cout, "n" ) );
        cout << endl;

        ::sort<string, 6>( names );

        cout << "nNames after sorting ..." << endl;
        copy ( names, names+6, ostream_iterator<string>( cout, "n" ) );
        cout << endl;

        return 0;
}

```

运行以下命令：

```cpp
g++ main.cpp -std=c++17
./a.out
```

上述程序的输出如下：

```cpp
Values in the int array before sorting ...
100  10   40   20   60   80   5   50   30   25

Values in the int array after sorting ...
5    10   20   25   30   40   50   60   80   100

Values in the double array before sorting ...
85.6d 76.13d 0.012d 1.57d 2.56d

Values in the double array after sorting ...
0.012   1.57   2.56   76.13   85.6

Names before sorting ...
Rishi Kumar Sahay
Arun KR
Arun CR
Ninad
Pankaj
Nikita

Names after sorting ...
Arun CR
Arun KR
Nikita
Ninad
Pankaj
Rich Kumar Sahay
```

看到一个模板函数就能完成所有的魔术，是不是很有趣？是的，这就是 C++模板的酷之处！

你是否好奇看到模板实例化的汇编输出？使用命令**`g++ -S main.cpp`**。

# 代码演示

以下代码定义了一个函数模板。关键字`template <typename T, int size>`告诉编译器接下来是一个函数模板：

```cpp
template <typename T, int size>
void sort ( T input[] ) {

 for ( int i=0; i<size; ++i) { 
     for (int j=0; j<size; ++j) {
         if ( input[i] < input[j] )
             swap (input[i], input[j] );
     }
 }

}
```

`void sort ( T input[] )`这一行定义了一个名为`sort`的函数，返回`void`，接收类型为`T`的输入数组。`T`类型不表示任何特定的数据类型。`T`将在编译时实例化函数模板时推导出来。

以下代码用一些未排序的值填充一个整数数组，并将其打印到终端上：

```cpp
 int a[10] = { 100, 10, 40, 20, 60, 80, 5, 50, 30, 25 };
 cout << "nValues in the int array before sorting ..." << endl;
 copy ( a, a+10, ostream_iterator<int>( cout, "t" ) );
 cout << endl;
```

以下行将实例化一个`int`数据类型的函数模板实例。此时，`typename T`被替换，为`int`创建了一个专门的函数。在`sort`前面的作用域解析运算符，即`::sort()`，确保它调用我们在全局命名空间中定义的自定义函数`sort()`；否则，C++编译器将尝试调用`std 命名空间`中定义的`sort()`算法，或者如果存在这样的函数，则从任何其他命名空间中调用。`<int, 10>`变量告诉编译器创建一个函数实例，用`int`替换`typename T`，`10`表示模板函数中使用的数组的大小：

```cpp
::sort<int, 10>( a );
```

以下行将实例化另外两个支持`5`个元素的`double`数组和`6`个元素的`string`数组的实例：

```cpp
::sort<double, 5>( b );
::sort<string, 6>( names );
```

如果您想了解有关 C++编译器如何实例化函数模板以支持`int`、`double`和`string`的更多细节，可以尝试使用 Unix 实用程序`nm`和`c++filt`。`nm` Unix 实用程序将列出符号表中的符号，如下所示：

```cpp
nm ./a.out | grep sort

00000000000017f1 W _Z4sortIdLi5EEvPT_
0000000000001651 W _Z4sortIiLi10EEvPT_
000000000000199b W _Z4sortINSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEELi6EEvPT_
```

正如您所看到的，二进制文件中有三个不同的重载`sort`函数；然而，我们只定义了一个模板函数。由于 C++编译器对函数重载进行了名称混淆，我们很难解释这三个函数中的哪一个是为`int`、`double`和`string`数据类型设计的。

然而，有一个线索：第一个函数是为`double`设计的，第二个是为`int`设计的，第三个是为`string`设计的。对于`double`，名称混淆的函数为`_Z4sortIdLi5EEvPT_`，对于`int`，为`_Z4sortIiLi10EEvPT_`，对于`string`，为`_Z4sortINSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEELi6EEvPT_`。还有一个很酷的 Unix 实用程序可以帮助您轻松解释函数签名。检查`c++filt`实用程序的以下输出：

```cpp
c++filt _Z4sortIdLi5EEvPT_
void sort<double, 5>(double*)

c++filt _Z4sortIiLi10EEvPT_
void sort<int, 10>(int*)

c++filt _Z4sortINSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEELi6EEvPT_
void sort<std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >, 6>(std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >*)
```

希望您在使用 C++模板时会发现这些实用程序有用。我相信这些工具和技术将帮助您调试任何 C++应用程序。

# 重载函数模板

函数模板的重载与 C++中的常规函数重载完全相同。但是，我将帮助您回顾 C++函数重载的基础知识。

C++编译器对函数重载的规则和期望如下：

+   重载的函数名称将是相同的。

+   C++编译器将无法区分仅通过返回值不同的重载函数。

+   重载函数参数的数量、数据类型或它们的顺序应该不同。除了其他规则外，当前项目符号中描述的这些规则中至少应满足一个，但更多的符合也不会有坏处。

+   重载的函数必须在同一个命名空间或同一个类范围内。

如果上述任何规则没有得到满足，C++编译器将不会将它们视为重载函数。如果在区分重载函数时存在任何歧义，C++编译器将立即报告它为编译错误。

现在是时候通过以下程序示例来探索一下了：

```cpp
#include <iostream>
#include <array>
using namespace std;

void sort ( array<int,6> data ) {

     cout << "Non-template sort function invoked ..." << endl;

     int size = data.size();

     for ( int i=0; i<size; ++i ) { 
          for ( int j=0; j<size; ++j ) {
                if ( data[i] < data[j] )
                    swap ( data[i], data[j] );
          }
     }

}

template <typename T, int size>
void sort ( array<T, size> data ) {

     cout << "Template sort function invoked with one argument..." << endl;

     for ( int i=0; i<size; ++i ) {
         for ( int j=0; j<size; ++j ) {
             if ( data[i] < data[j] )
                swap ( data[i], data[j] );
         }
     }

}

template <typename T>
void sort ( T data[], int size ) {
     cout << "Template sort function invoked with two arguments..." << endl;

     for ( int i=0; i<size; ++i ) {
         for ( int j=0; j<size; ++j ) {
             if ( data[i] < data[j] )
                swap ( data[i], data[j] );
         }
     }

}

int main() {

    //Will invoke the non-template sort function
    array<int, 6> a = { 10, 50, 40, 30, 60, 20 };
    ::sort ( a );

    //Will invoke the template function that takes a single argument
    array<float,6> b = { 10.6f, 57.9f, 80.7f, 35.1f, 69.3f, 20.0f };
    ::sort<float,6>( b );

    //Will invoke the template function that takes a single argument
    array<double,6> c = { 10.6d, 57.9d, 80.7d, 35.1d, 69.3d, 20.0d };
    ::sort<double,6> ( c );

    //Will invoke the template function that takes two arguments
    double d[] = { 10.5d, 12.1d, 5.56d, 1.31d, 81.5d, 12.86d };
    ::sort<double> ( d, 6 );

    return 0;

}
```

运行以下命令：

```cpp
g++ main.cpp -std=c++17

./a.out
```

上述程序的输出如下：

```cpp
Non-template sort function invoked ...

Template sort function invoked with one argument...

Template sort function invoked with one argument...

Template sort function invoked with two arguments...
```

# 代码演示

以下代码是我们自定义`sort()`函数的非模板版本：

```cpp
void sort ( array<int,6> data ) { 

     cout << "Non-template sort function invoked ..." << endl;

     int size = data.size();

     for ( int i=0; i<size; ++i ) { 
         for ( int j=0; j<size; ++j ) {
             if ( data[i] < data[j] )
                 swap ( data[i], data[j] );
         }
     }

}
```

非模板函数和模板函数可以共存并参与函数重载。上述函数的一个奇怪行为是数组的大小是硬编码的。

我们的`sort()`函数的第二个版本是一个模板函数，如下面的代码片段所示。有趣的是，我们在第一个非模板`sort()`版本中注意到的奇怪问题在这里得到了解决：

```cpp
template <typename T, int size>
void sort ( array<T, size> data ) {

     cout << "Template sort function invoked with one argument..." << endl;

     for ( int i=0; i<size; ++i ) {
         for ( int j=0; j<size; ++j ) {
             if ( data[i] < data[j] )
                swap ( data[i], data[j] );
         }
     }

}
```

在上述代码中，数据类型和数组的大小都作为模板参数传递，然后传递给函数调用参数。这种方法使函数通用，因为这个函数可以为任何数据类型实例化。

我们自定义的`sort()`函数的第三个版本也是一个模板函数，如下面的代码片段所示：

```cpp
template <typename T>
void sort ( T data[], int size ) {

     cout << "Template sort function invoked with two argument..." << endl;

     for ( int i=0; i<size; ++i ) {
         for ( int j=0; j<size; ++j ) {
             if ( data[i] < data[j] )
                swap ( data[i], data[j] );
         }
     }

}
```

上述模板函数接受 C 风格数组；因此，它也期望用户指示其大小。然而，数组的大小可以在函数内计算，但出于演示目的，我需要一个接受两个参数的函数。前一个函数不推荐使用，因为它使用了 C 风格数组；理想情况下，我们会使用 STL 容器之一。

现在，让我们理解主函数代码。以下代码声明并初始化了 STL 数组容器，其中包含六个值，然后将其传递给我们在默认命名空间中定义的`sort()`函数：

```cpp
 //Will invoke the non-template sort function
 array<int, 6> a = { 10, 50, 40, 30, 60, 20 };
 ::sort ( a );
```

上述代码将调用非模板`sort()`函数。需要注意的重要一点是，每当 C++遇到函数调用时，它首先寻找非模板版本；如果 C++找到匹配的非模板函数版本，它的搜索正确函数定义就在那里结束。如果 C++编译器无法识别与函数调用签名匹配的非模板函数定义，那么它开始寻找任何可以支持函数调用的模板函数，并为所需的数据类型实例化一个专门的函数。

让我们理解以下代码：

```cpp
//Will invoke the template function that takes a single argument
array<float,6> b = { 10.6f, 57.9f, 80.7f, 35.1f, 69.3f, 20.0f };
::sort<float,6>( b );
```

这将调用接收单个参数的模板函数。由于没有接收`array<float,6>`数据类型的非模板`sort()`函数，C++编译器将从我们定义的接收单个参数的`sort()`模板函数中实例化这样的函数。

同样，以下代码触发编译器实例化接收`array<double, 6>`的`double`版本的模板`sort()`函数：

```cpp
  //Will invoke the template function that takes a single argument
 array<double,6> c = { 10.6d, 57.9d, 80.7d, 35.1d, 69.3d, 20.0d };
 ::sort<double,6> ( c );
```

最后，以下代码将实例化一个接收两个参数并调用函数的模板`sort()`的实例：

```cpp
 //Will invoke the template function that takes two arguments
 double d[] = { 10.5d, 12.1d, 5.56d, 1.31d, 81.5d, 12.86d };
 ::sort<double> ( d, 6 );
```

如果您已经走到这一步，我相信您会喜欢迄今为止讨论的 C++模板主题。

# 类模板

C++模板将函数模板概念扩展到类，使我们能够编写面向对象的通用代码。在前面的部分中，您学习了函数模板和重载的用法。在本节中，您将学习编写模板类，这将开启更有趣的通用编程概念。

`class`模板允许您通过模板类型表达式在类级别上对数据类型进行参数化。

让我们通过以下示例理解一个`class`模板：

```cpp
//myalgorithm.h
#include <iostream>
#include <algorithm>
#include <array>
#include <iterator>
using namespace std;

template <typename T, int size>
class MyAlgorithm {

public:
        MyAlgorithm() { } 
        ~MyAlgorithm() { }

        void sort( array<T, size> &data ) {
             for ( int i=0; i<size; ++i ) {
                 for ( int j=0; j<size; ++j ) {
                     if ( data[i] < data[j] )
                         swap ( data[i], data[j] );
                 }
             }
        }

        void sort ( T data[size] );

};

template <typename T, int size>
inline void MyAlgorithm<T, size>::sort ( T data[size] ) {
       for ( int i=0; i<size; ++i ) {
           for ( int j=0; j<size; ++j ) {
               if ( data[i] < data[j] )
                  swap ( data[i], data[j] );
           }
       }
}
```

C++模板函数重载是静态或编译时多态的一种形式。

让我们在以下`main.cpp`程序中使用`myalgorithm.h`如下：

```cpp
#include "myalgorithm.h"

int main() {

    MyAlgorithm<int, 10> algorithm1;

    array<int, 10> a = { 10, 5, 15, 20, 25, 18, 1, 100, 90, 18 };

    cout << "nArray values before sorting ..." << endl;
    copy ( a.begin(), a.end(), ostream_iterator<int>(cout, "t") );
    cout << endl;

    algorithm1.sort ( a );

    cout << "nArray values after sorting ..." << endl;
    copy ( a.begin(), a.end(), ostream_iterator<int>(cout, "t") );
    cout << endl;

    MyAlgorithm<int, 10> algorithm2;
    double d[] = { 100.0, 20.5, 200.5, 300.8, 186.78, 1.1 };

    cout << "nArray values before sorting ..." << endl;
    copy ( d.begin(), d.end(), ostream_iterator<double>(cout, "t") );
    cout << endl;

    algorithm2.sort ( d );

    cout << "nArray values after sorting ..." << endl;
    copy ( d.begin(), d.end(), ostream_iterator<double>(cout, "t") );
    cout << endl;

    return 0;  

}
```

让我们使用以下命令快速编译程序：

```cpp
g++ main.cpp -std=c++17

./a.out
```

输出如下：

```cpp

Array values before sorting ...
10  5   15   20   25   18   1   100   90   18

Array values after sorting ...
1   5   10   15   18   18   20   25   90   100

Array values before sorting ...
100   20.5   200.5   300.8   186.78   1.1

Array values after sorting ...
1.1     20.5   100   186.78  200.5  300.8
```

# 代码演示

以下代码声明了一个类模板。关键字`template <typename T, int size>`可以替换为`<class T, int size>`。这两个关键字可以在函数和类模板中互换使用；然而，作为行业最佳实践，`template<class T>`只能用于类模板，以避免混淆：

```cpp
template <typename T, int size>
class MyAlgorithm 
```

重载的`sort()`方法之一内联定义如下：

```cpp
 void sort( array<T, size> &data ) {
      for ( int i=0; i<size; ++i ) {
          for ( int j=0; j<size; ++j ) {
              if ( data[i] < data[j] )
                 swap ( data[i], data[j] );
          }
      }
 } 
```

第二个重载的`sort()`函数只是在类范围内声明，没有任何定义，如下所示：

```cpp
template <typename T, int size>
class MyAlgorithm {
      public:
           void sort ( T data[size] );
};
```

前面的`sort()`函数是在类范围之外定义的，如下面的代码片段所示。奇怪的是，我们需要为在类模板之外定义的每个成员函数重复模板参数：

```cpp
template <typename T, int size>
inline void MyAlgorithm<T, size>::sort ( T data[size] ) {
       for ( int i=0; i<size; ++i ) {
           for ( int j=0; j<size; ++j ) {
               if ( data[i] < data[j] )
                  swap ( data[i], data[j] );
           }
       }
}
```

否则，类模板的概念与函数模板的概念相同。

您想看看模板的编译器实例化代码吗？使用**`g++ -fdump-tree-original main.cpp -std=c++17`**命令。

# 显式类特化

到目前为止，在本章中，您已经学会了如何使用函数模板和类模板进行通用编程。当您理解类模板时，单个模板类可以支持任何内置和用户定义的数据类型。然而，有时我们需要对某些数据类型进行特殊处理，以便与其他数据类型有所区别。在这种情况下，C++为我们提供了显式类特化支持，以处理具有差异处理的选择性数据类型。

考虑 STL `deque`容器；虽然`deque`看起来适合存储，比如说，`string`、`int`、`double`和`long`，但如果我们决定使用`deque`来存储一堆`boolean`类型，`bool`数据类型至少占用一个字节，而根据编译器供应商的实现可能会有所不同。虽然一个位可以有效地表示真或假，但布尔值至少占用一个字节，即 8 位，剩下的 7 位没有被使用。这可能看起来没问题；但是，如果您必须存储一个非常大的`deque`布尔值，这绝对不是一个有效的想法，对吧？您可能会想，有什么大不了的？我们可以为`bool`编写另一个专门的类或模板类。但这种方法要求最终用户明确为不同的数据类型使用不同的类，这也不是一个好的设计，对吧？这正是 C++的显式类特化派上用场的地方。

显式模板特化也被称为完全模板特化。

如果您还不信服，没关系；下面的例子将帮助您理解显式类特化的必要性以及显式类特化的工作原理。

让我们开发一个`DynamicArray`类来支持任何数据类型的动态数组。让我们从一个类模板开始，如下面的程序所示：

```cpp
#include <iostream>
#include <deque>
#include <algorithm>
#include <iterator>
using namespace std;

template < class T >
class DynamicArray {
      private:
           deque< T > dynamicArray;
           typename deque< T >::iterator pos;

      public:
           DynamicArray() { initialize(); }
           ~DynamicArray() { }

           void initialize() {
                 pos = dynamicArray.begin();
           }

           void appendValue( T element ) {
                 dynamicArray.push_back ( element );
           }

           bool hasNextValue() { 
                 return ( pos != dynamicArray.end() );
           }

           T getValue() {
                 return *pos++;
           }

};
```

前面的`DynamicArray`模板类在内部使用了 STL `deque`类。因此，您可以将`DynamicArray`模板类视为自定义适配器容器。让我们探索如何在`main.cpp`中使用`DynamicArray`模板类，以下是代码片段：

```cpp
#include "dynamicarray.h"
#include "dynamicarrayforbool.h"

int main () {

    DynamicArray<int> intArray;

    intArray.appendValue( 100 );
    intArray.appendValue( 200 );
    intArray.appendValue( 300 );
    intArray.appendValue( 400 );

    intArray.initialize();

    cout << "nInt DynamicArray values are ..." << endl;
    while ( intArray.hasNextValue() )
          cout << intArray.getValue() << "t";
    cout << endl;

    DynamicArray<char> charArray;
    charArray.appendValue( 'H' );
    charArray.appendValue( 'e' );
    charArray.appendValue( 'l' );
    charArray.appendValue( 'l' );
    charArray.appendValue( 'o' );

    charArray.initialize();

    cout << "nChar DynamicArray values are ..." << endl;
    while ( charArray.hasNextValue() )
          cout << charArray.getValue() << "t";
    cout << endl;

    DynamicArray<bool> boolArray;

    boolArray.appendValue ( true );
    boolArray.appendValue ( false );
    boolArray.appendValue ( true );
    boolArray.appendValue ( false );

    boolArray.initialize();

    cout << "nBool DynamicArray values are ..." << endl;
    while ( boolArray.hasNextValue() )
         cout << boolArray.getValue() << "t";
    cout << endl;

    return 0;

}
```

让我们快速使用以下命令编译程序：

```cpp
g++ main.cpp -std=c++17

./a.out
```

输出如下：

```cpp
Int DynamicArray values are ...
100   200   300   400

Char DynamicArray values are ...
H   e   l   l   o

Bool DynamicArray values are ...
1   0   1   0
```

太好了！我们自定义的适配器容器似乎工作正常。

# 代码演示

让我们放大并尝试理解前面的程序是如何工作的。以下代码告诉 C++编译器接下来是一个类模板：

```cpp
template < class T >
class DynamicArray {
      private:
           deque< T > dynamicArray;
           typename deque< T >::iterator pos;
```

正如您所看到的，`DynamicArray`类在内部使用了 STL `deque`，并且为`deque`声明了名为`pos`的迭代器。这个迭代器`pos`被`Dynamic`模板类用于提供高级方法，比如`initialize()`、`appendValue()`、`hasNextValue()`和`getValue()`方法。

`initialize()`方法将`deque`迭代器`pos`初始化为`deque`中存储的第一个数据元素。`appendValue( T element )`方法允许您在`deque`的末尾添加数据元素。`hasNextValue()`方法告诉`DynamicArray`类是否有更多的数据值存储--`true`表示有更多的值，`false`表示`DynamicArray`导航已经到达`deque`的末尾。当需要时，`initialize()`方法可以用来重置`pos`迭代器到起始点。`getValue()`方法返回`pos`迭代器在那一刻指向的数据元素。`getValue()`方法不执行任何验证；因此，在调用`getValue()`之前，必须与`hasNextValue()`结合使用，以安全地访问存储在`DynamicArray`中的值。

现在，让我们理解`main()`函数。以下代码声明了一个存储`int`数据类型的`DynamicArray`类；`DynamicArray<int> intArray`将触发 C++编译器实例化一个专门针对`int`数据类型的`DynamicArray`类：

```cpp
DynamicArray<int> intArray;

intArray.appendValue( 100 );
intArray.appendValue( 200 );
intArray.appendValue( 300 );
intArray.appendValue( 400 );
```

值`100`、`200`、`300`和`400`依次存储在`DynamicArray`类中。以下代码确保`intArray`迭代器指向第一个元素。一旦迭代器初始化，存储在`DynamicArray`类中的值将通过`getValue()`方法打印出来，而`hasNextValue()`确保导航没有到达`DynamicArray`类的末尾：

```cpp
intArray.initialize();
cout << "nInt DynamicArray values are ..." << endl;
while ( intArray.hasNextValue() )
      cout << intArray.getValue() << "t";
cout << endl;
```

在主函数中，创建了一个`char DynamicArray`类，填充了一些数据，并进行了打印。让我们跳过`char` `DynamicArray`，直接转到存储`bool`的`DynamicArray`类。

```cpp
DynamicArray<bool> boolArray;

boolArray.appendValue ( "1010" );

boolArray.initialize();

cout << "nBool DynamicArray values are ..." << endl;

while ( boolArray.hasNextValue() )
      cout << boolArray.getValue() << "t";
cout << endl;
```

从前面的代码片段中，我们可以看到一切都很正常，对吗？是的，前面的代码完全正常；然而，`DynamicArray`的设计方法存在性能问题。虽然`true`可以用`1`表示，`false`可以用`0`表示，只需要 1 位，但前面的`DynamicArray`类却使用了 8 位来表示`1`和 8 位来表示`0`，我们必须解决这个问题，而不强迫最终用户选择一个对`bool`有效率的不同`DynamicArray`类。

让我们通过使用显式类模板特化来解决这个问题，以下是代码：

```cpp
#include <iostream>
#include <bitset>
#include <algorithm>
#include <iterator>
using namespace std;

template <>
class DynamicArray<bool> {
      private:
          deque< bitset<8> *> dynamicArray;
          bitset<8> oneByte;
          typename deque<bitset<8> * >::iterator pos;
          int bitSetIndex;

          int getDequeIndex () {
              return (bitSetIndex) ? (bitSetIndex/8) : 0;
          }
      public:
          DynamicArray() {
              bitSetIndex = 0;
              initialize();
          }

         ~DynamicArray() { }

         void initialize() {
              pos = dynamicArray.begin();
              bitSetIndex = 0;
         }

         void appendValue( bool value) {
              int dequeIndex = getDequeIndex();
              bitset<8> *pBit = NULL;

              if ( ( dynamicArray.size() == 0 ) || ( dequeIndex >= ( dynamicArray.size()) ) ) {
                   pBit = new bitset<8>();
                   pBit->reset();
                   dynamicArray.push_back ( pBit );
              }

              if ( !dynamicArray.empty() )
                   pBit = dynamicArray.at( dequeIndex );

              pBit->set( bitSetIndex % 8, value );
              ++bitSetIndex;
         }

         bool hasNextValue() {
              return (bitSetIndex < (( dynamicArray.size() * 8 ) ));
         }

         bool getValue() {
              int dequeIndex = getDequeIndex();

              bitset<8> *pBit = dynamicArray.at(dequeIndex);
              int index = bitSetIndex % 8;
              ++bitSetIndex;

              return (*pBit)[index] ? true : false;
         }
};
```

你注意到模板类声明了吗？模板类特化的语法是`template <> class DynamicArray<bool> { };`。`class`模板表达式是空的`<>`，对于所有数据类型都适用的`class`模板的名称和适用于`bool`数据类型的类的名称与模板表达式`<bool>`保持一致。

如果你仔细观察，你会发现，专门为`bool`设计的`DynamicArray`类内部使用了`deque<bitset<8>>`，即 8 位的`bitset`的`deque`，在需要时，`deque`会自动分配更多的`bitset<8>`位。`bitset`变量是一个内存高效的 STL 容器，只消耗 1 位来表示`true`或`false`。

让我们来看一下`main`函数：

```cpp
#include "dynamicarray.h"
#include "dynamicarrayforbool.h"

int main () {

    DynamicArray<int> intArray;

    intArray.appendValue( 100 );
    intArray.appendValue( 200 );
    intArray.appendValue( 300 );
    intArray.appendValue( 400 );

    intArray.initialize();

    cout << "nInt DynamicArray values are ..." << endl;

    while ( intArray.hasNextValue() )
          cout << intArray.getValue() << "t";
    cout << endl;

    DynamicArray<char> charArray;

    charArray.appendValue( 'H' );
    charArray.appendValue( 'e' );
    charArray.appendValue( 'l' );
    charArray.appendValue( 'l' );
    charArray.appendValue( 'o' );

    charArray.initialize();

    cout << "nChar DynamicArray values are ..." << endl;
    while ( charArray.hasNextValue() )
          cout << charArray.getValue() << "t";
    cout << endl;

    DynamicArray<bool> boolArray;

    boolArray.appendValue ( true );
    boolArray.appendValue ( false );
    boolArray.appendValue ( true );
    boolArray.appendValue ( false );

    boolArray.appendValue ( true );
    boolArray.appendValue ( false );
    boolArray.appendValue ( true );
    boolArray.appendValue ( false );

    boolArray.appendValue ( true );
    boolArray.appendValue ( true);
    boolArray.appendValue ( false);
    boolArray.appendValue ( false );

    boolArray.appendValue ( true );
    boolArray.appendValue ( true);
    boolArray.appendValue ( false);
    boolArray.appendValue ( false );

    boolArray.initialize();

    cout << "nBool DynamicArray values are ..." << endl;
    while ( boolArray.hasNextValue() )
          cout << boolArray.getValue() ;
    cout << endl;

    return 0;

}
```

有了类模板特化，我们可以从以下代码中观察到，对于`bool`、`char`和`double`，主要代码似乎是相同的，尽管主模板类`DynamicArray`和专门化的`DynamicArray<bool>`类是不同的：

```cpp
DynamicArray<char> charArray;
charArray.appendValue( 'H' );
charArray.appendValue( 'e' );

charArray.initialize();

cout << "nChar DynamicArray values are ..." << endl;
while ( charArray.hasNextValue() )
cout << charArray.getValue() << "t";
cout << endl;

DynamicArray<bool> boolArray;
boolArray.appendValue ( true );
boolArray.appendValue ( false );

boolArray.initialize();

cout << "nBool DynamicArray values are ..." << endl;
while ( boolArray.hasNextValue() )
      cout << boolArray.getValue() ;
cout << endl;
```

我相信你会发现这个 C++模板特化功能非常有用。

# 部分模板特化

与显式模板特化不同，显式模板特化用自己特定数据类型的完整定义替换主模板类，而部分模板特化允许我们专门化主模板类支持的某个子集的模板参数，而其他通用类型可以与主模板类相同。

当部分模板特化与继承结合时，可以做更多的事情，如下例所示：

```cpp
#include <iostream>
using namespace std;

template <typename T1, typename T2, typename T3>
class MyTemplateClass {
public:
     void F1( T1 t1, T2 t2, T3 t3 ) {
          cout << "nPrimary Template Class - Function F1 invoked ..." << endl;
          cout << "Value of t1 is " << t1 << endl;
          cout << "Value of t2 is " << t2 << endl;
          cout << "Value of t3 is " << t3 << endl;
     }

     void F2(T1 t1, T2 t2) {
          cout << "nPrimary Tempalte Class - Function F2 invoked ..." << endl;
          cout << "Value of t1 is " << t1 << endl;
          cout << "Value of t2 is " << 2 * t2 << endl;
     }
};
```

```cpp
template <typename T1, typename T2, typename T3>
class MyTemplateClass< T1, T2*, T3*> : public MyTemplateClass<T1, T2, T3> {
      public:
          void F1( T1 t1, T2* t2, T3* t3 ) {
               cout << "nPartially Specialized Template Class - Function F1 invoked ..." << endl;
               cout << "Value of t1 is " << t1 << endl;
               cout << "Value of t2 is " << *t2 << endl;
               cout << "Value of t3 is " << *t3 << endl;
          }
};
```

`main.cpp`文件将包含以下内容：

```cpp
#include "partiallyspecialized.h"

int main () {
    int x = 10;
    int *y = &x;
    int *z = &x;

    MyTemplateClass<int, int*, int*> obj;
    obj.F1(x, y, z);
    obj.F2(x, x);

    return 0;
}
```

从前面的代码中，你可能已经注意到，主模板类名称和部分特化类名称与完全或显式模板类特化的情况相同。然而，在模板参数表达式中有一些语法变化。在完全模板类特化的情况下，模板参数表达式将为空，而在部分特化的模板类的情况下，列出的表达式会出现，如下所示：

```cpp
template <typename T1, typename T2, typename T3>
class MyTemplateClass< T1, T2*, T3*> : public MyTemplateClass<T1, T2, T3> { };
```

表达式`template<typename T1, typename T2, typename T3>`是主类模板类中使用的模板参数表达式，`MyTemplateClass< T1, T2*, T3*>`是第二类所做的部分特化。正如你所看到的，第二类对`typename T2`和`typename T3`进行了一些特化，因为它们在第二类中被用作指针；然而，`typename T1`在第二类中被直接使用。

除了迄今为止讨论的事实之外，第二类还继承了主模板类，这有助于第二类重用主模板类的公共和受保护的方法。然而，部分模板特化并不会阻止特化类支持其他函数。

虽然主模板类中的`F1`函数被部分特化的模板类替换，但它通过继承重用了主模板类中的`F2`函数。

让我们使用以下命令快速编译程序：

```cpp
g++ main.cpp -std=c++17

./a.out
```

程序的输出如下：

```cpp
Partially Specialized Template Classs - Function F1 invoked ...
Value of t1 is 10
Value of t2 is 10
Value of t3 is 10

Primary Tempalte Class - Function F2 invoked ...
Value of t1 is 10
Value of t2 is 20
```

希望你觉得部分特化的模板类有用。

# 总结

在本章中，你学到了以下内容：

+   你现在知道了使用泛型编程的动机

+   你现在熟悉了函数模板

+   你知道如何重载函数模板

+   你知道类模板

+   你知道何时使用显式模板特化以及何时使用部分特化的模板特化

恭喜！总的来说，你对 C++的模板编程有很好的理解。

在下一章中，你将学习智能指针。
