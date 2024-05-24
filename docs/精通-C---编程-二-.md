# 精通 C++ 编程（二）

> 原文：[`annas-archive.org/md5/0E32826EC8D4CA7BCD89E795AD6CBF05`](https://annas-archive.org/md5/0E32826EC8D4CA7BCD89E795AD6CBF05)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第三章：模板编程

在本章中，我们将涵盖以下主题：

+   泛型编程

+   函数模板

+   类模板

+   函数模板重载

+   泛型类

+   显式类特化

+   部分特化

现在让我们开始学习泛型编程。

# 泛型编程

泛型编程是一种编程风格，可以帮助您开发可重用的代码或通用算法，可应用于各种数据类型。每当调用通用算法时，数据类型将以特殊语法作为参数提供。

假设我们想要编写一个`sort()`函数，它接受一个需要按升序排序的输入数组。其次，我们需要`sort()`函数来对`int`、`double`、`char`和`string`数据类型进行排序。有几种方法可以解决这个问题：

+   我们可以为每种数据类型编写四个不同的`sort()`函数

+   我们也可以编写一个单一的宏函数

嗯，这两种方法都有各自的优点和缺点。第一种方法的优点是，由于为`int`、`double`、`char`和`string`数据类型专门有函数，如果提供了不正确的数据类型，编译器将能够执行类型检查。第一种方法的缺点是，尽管所有函数的逻辑保持不变，但我们必须编写四个不同的函数。如果在算法中发现了错误，必须分别在所有四个函数中进行修复；因此，需要进行大量的维护工作。如果我们需要支持另一种数据类型，我们将不得不编写另一个函数，并且随着需要支持更多数据类型，这种情况将不断增加。

第二种方法的优点是我们可以为所有数据类型编写一个宏。然而，一个非常令人沮丧的缺点是编译器将无法执行类型检查，这种方法更容易出现错误，并可能引发许多意外的麻烦。这种方法与面向对象编码原则背道而驰。

C++支持使用模板进行泛型编程，具有以下好处：

+   我们只需要使用模板编写一个函数

+   模板支持静态多态

+   模板提供了前述两种方法的所有优点，没有任何缺点

+   泛型编程实现了代码重用

+   结果代码是面向对象的

+   C++编译器可以在编译时执行类型检查

+   易于维护

+   支持各种内置和用户定义的数据类型

然而，缺点如下：

+   并非所有 C++程序员都感到舒适编写基于模板的编码，但这只是最初的阻碍

+   在某些情况下，模板可能会使您的代码膨胀并增加二进制占用空间，导致性能问题

# 函数模板

函数模板允许您将数据类型参数化。之所以称之为泛型编程，是因为单个模板函数将支持许多内置和用户定义的数据类型。模板化函数的工作方式类似于**C 风格宏**，只是 C++编译器在我们在调用模板函数时提供不兼容的数据类型时会对函数进行类型检查。

通过一个简单的示例来理解模板概念会更容易，如下所示：

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

        cout << "\nValues in the int array before sorting ..." << endl;
        copy ( a, a+10, ostream_iterator<int>( cout, "\t" ) );
        cout << endl;

        ::sort<int, 10>( a );

        cout << "\nValues in the int array after sorting ..." << endl;
        copy ( a, a+10, ostream_iterator<int>( cout, "\t" ) );
        cout << endl;

        double b[5] = { 85.6d, 76.13d, 0.012d, 1.57d, 2.56d };

        cout << "\nValues in the double array before sorting ..." << endl;
        copy ( b, b+5, ostream_iterator<double>( cout, "\t" ) );
        cout << endl;

        ::sort<double, 5>( b );

        cout << "\nValues in the double array after sorting ..." << endl;
        copy ( b, b+5, ostream_iterator<double>( cout, "\t" ) );
        cout << endl;

        string names[6] = {
               "Rishi Kumar Sahay",
               "Arun KR",
               "Arun CR",
               "Ninad",
               "Pankaj",
               "Nikita"
        };

        cout << "\nNames before sorting ..." << endl;
        copy ( names, names+6, ostream_iterator<string>( cout, "\n" ) );
        cout << endl;

        ::sort<string, 6>( names );

        cout << "\nNames after sorting ..." << endl;
        copy ( names, names+6, ostream_iterator<string>( cout, "\n" ) );
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

看到一个模板函数就能完成所有魔术，是不是很有趣？是的，这就是 C++模板的酷之处！

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

`void sort ( T input[] )`这一行定义了一个名为`sort`的函数，它返回`void`并接收类型为`T`的输入数组。`T`类型并不表示任何特定的数据类型。`T`将在编译时实例化函数模板的时候推断出来。

以下代码用一些未排序的值填充一个整数数组，并将其打印到终端上：

```cpp
 int a[10] = { 100, 10, 40, 20, 60, 80, 5, 50, 30, 25 };
 cout << "\nValues in the int array before sorting ..." << endl;
 copy ( a, a+10, ostream_iterator<int>( cout, "\t" ) );
 cout << endl;
```

以下一行将为`int`数据类型实例化一个函数模板的实例。在这一点上，`typename T`被替换，为`int`数据类型创建了一个专门的函数。在`sort`前面的作用域解析运算符，即`::sort()`，确保它调用我们自定义的`sort()`函数，该函数定义在全局命名空间中；否则，C++编译器将尝试调用`std namespace`中定义的`sort()`算法，或者如果存在这样的函数，则来自任何其他命名空间。`<int, 10>`变量告诉编译器创建一个函数的实例，用`int`替换`typename T`，`10`表示模板函数中使用的数组的大小：

```cpp
::sort<int, 10>( a );
```

以下行将实例化另外两个支持`5`个元素的`double`数组和`6`个元素的`string`数组的实例：

```cpp
::sort<double, 5>( b );
::sort<string, 6>( names );
```

如果您想了解有关 C++编译器如何实例化函数模板以支持`int`、`double`和`string`的更多细节，可以尝试 Unix 实用程序`nm`和`c++filt`。`nm` Unix 实用程序将列出符号表中的符号，如下所示：

```cpp
nm ./a.out | grep sort

00000000000017f1 W _Z4sortIdLi5EEvPT_
0000000000001651 W _Z4sortIiLi10EEvPT_
000000000000199b W _Z4sortINSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEELi6EEvPT_
```

正如您所看到的，在二进制文件中有三个不同的重载`sort`函数；然而，我们只定义了一个模板函数。由于 C++编译器对函数重载进行了名称混编，我们很难解释这三个函数中的哪一个是为`int`、`double`和`string`数据类型准备的。

然而，有一个线索：第一个函数是为`double`准备的，第二个是为`int`准备的，第三个是为`string`准备的。名称混编函数对于`double`是`_Z4sortIdLi5EEvPT_`，对于`int`是`_Z4sortIiLi10EEvPT_`，对于`string`是`_Z4sortINSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEELi6EEvPT_`。还有另一个很酷的 Unix 实用程序，可以帮助您轻松解释函数签名。检查`c++filt`实用程序的以下输出：

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

重载函数模板的工作方式与 C++中的常规函数重载完全相同。不过，我将帮助您回顾一下 C++函数重载的基础知识。

C++编译器对重载函数的规则和期望如下：

+   重载函数的名称将是相同的。

+   C++编译器将无法区分仅通过返回值不同的重载函数。

+   重载函数参数的数量、这些参数的数据类型或它们的顺序应该是不同的。除了其他规则之外，当前项目符号表中描述的这些规则中至少应满足一个，但更多的符合也不会有害。

+   重载函数必须在相同的命名空间或相同的类作用域内。

如果这些前述规则中的任何一个没有得到满足，C++编译器将不会将它们视为重载函数。如果在区分重载函数方面存在任何歧义，C++编译器将立即报告为编译错误。

现在是时候通过下面的示例来探索一下了：

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

前述程序的输出如下：

```cpp
Non-template sort function invoked ...

Template sort function invoked with one argument...

Template sort function invoked with one argument...

Template sort function invoked with two arguments...
```

# 代码演示

以下代码是我们自定义的`sort()`函数的非模板版本：

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

非模板函数和模板函数可以共存并参与函数重载。前面函数的一个奇怪行为是数组的大小是硬编码的。

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

在前面的代码中，数组的数据类型和大小都作为模板参数传递，然后传递给函数调用参数。这种方法使函数通用，因为这个函数可以为任何数据类型实例化。

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

前面的模板函数接受 C 风格的数组；因此，它也期望用户指示其大小。然而，数组的大小可以在函数内计算，但出于演示目的，我需要一个接受两个参数的函数。不建议使用前面的函数，因为它使用了 C 风格的数组；理想情况下，我们应该使用 STL 容器之一。

现在，让我们理解主函数代码。以下代码声明并初始化了包含六个值的 STL 数组容器，然后将其传递给我们在默认命名空间中定义的`sort()`函数：

```cpp
 //Will invoke the non-template sort function
 array<int, 6> a = { 10, 50, 40, 30, 60, 20 };
 ::sort ( a );
```

前面的代码将调用非模板`sort()`函数。需要注意的一个重要点是，每当 C++遇到函数调用时，它首先寻找非模板版本；如果 C++找到匹配的非模板函数版本，它的搜索正确函数定义的过程就结束了。如果 C++编译器无法识别与函数调用签名匹配的非模板函数定义，那么它开始寻找任何可以支持函数调用的模板函数，并为所需的数据类型实例化一个专门的函数。

让我们理解以下代码：

```cpp
//Will invoke the template function that takes a single argument
array<float,6> b = { 10.6f, 57.9f, 80.7f, 35.1f, 69.3f, 20.0f };
::sort<float,6>( b );
```

这将调用接收单个参数的模板函数。由于没有接收`array<float,6>`数据类型的非模板`sort()`函数，C++编译器将从我们定义的接收单个参数的`sort()`模板函数中实例化这样一个函数，该函数接收`array<float, 6>`。

同样，以下代码触发编译器实例化模板`sort()`函数的`double`版本，该函数接收`array<double, 6>`：

```cpp
  //Will invoke the template function that takes a single argument
 array<double,6> c = { 10.6d, 57.9d, 80.7d, 35.1d, 69.3d, 20.0d };
 ::sort<double,6> ( c );
```

最后，以下代码将实例化模板`sort()`的一个实例，该实例接收两个参数并调用函数：

```cpp
 //Will invoke the template function that takes two arguments
 double d[] = { 10.5d, 12.1d, 5.56d, 1.31d, 81.5d, 12.86d };
 ::sort<double> ( d, 6 );
```

如果您已经走到这一步，我相信您会喜欢迄今为止讨论的 C++模板主题。

# 类模板

C++模板将函数模板概念扩展到类，使我们能够编写面向对象的通用代码。在前面的部分，您学习了函数模板和重载的用法。在本节中，您将学习编写模板类，从而开启更有趣的通用编程概念。

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

让我们在以下`main.cpp`程序中使用`myalgorithm.h`如下所示：

```cpp
#include "myalgorithm.h"

int main() {

    MyAlgorithm<int, 10> algorithm1;

    array<int, 10> a = { 10, 5, 15, 20, 25, 18, 1, 100, 90, 18 };

    cout << "\nArray values before sorting ..." << endl;
    copy ( a.begin(), a.end(), ostream_iterator<int>(cout, "\t") );
    cout << endl;

    algorithm1.sort ( a );

    cout << "\nArray values after sorting ..." << endl;
    copy ( a.begin(), a.end(), ostream_iterator<int>(cout, "\t") );
    cout << endl;

    MyAlgorithm<int, 10> algorithm2;
    double d[] = { 100.0, 20.5, 200.5, 300.8, 186.78, 1.1 };

    cout << "\nArray values before sorting ..." << endl;
    copy ( d.begin(), d.end(), ostream_iterator<double>(cout, "\t") );
    cout << endl;

    algorithm2.sort ( d );

    cout << "\nArray values after sorting ..." << endl;
    copy ( d.begin(), d.end(), ostream_iterator<double>(cout, "\t") );
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

以下代码声明了一个类模板。关键字`template <typename T, int size>`可以替换为`<class T, int size>`。这两个关键字可以在函数和类模板中互换使用；然而，作为行业最佳实践，`template<class T>`只能用于类模板，以避免混淆。

```cpp
template <typename T, int size>
class MyAlgorithm 
```

其中一个重载的`sort()`方法内联定义如下：

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

前面的`sort()`函数是在类范围之外定义的，如下面的代码片段所示。奇怪的是，我们需要为每个在类模板之外定义的成员函数重复模板参数：

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

你想看看模板的编译器实例化代码吗？使用**`g++ -fdump-tree-original main.cpp -std=c++17`**命令。

# 显式类特化

到目前为止，在本章中，你已经学会了如何使用函数模板和类模板进行泛型编程。当你理解了类模板时，一个模板类可以支持任何内置和用户定义的数据类型。然而，有时我们需要对某些数据类型进行特殊处理。在这种情况下，C++为我们提供了显式类特化支持，以处理具有不同处理方式的选择性数据类型。

考虑 STL `deque`容器；虽然`deque`看起来适合存储，比如说，`string`、`int`、`double`和`long`，但如果我们决定使用`deque`来存储一堆`boolean`类型，`bool`数据类型至少占用一个字节，而根据编译器供应商的实现可能会有所不同。虽然一个位可以有效地表示真或假，但布尔值至少占用一个字节，即 8 位，剩下的 7 位没有被使用。这可能看起来没问题；然而，如果你必须存储一个非常大的布尔值`deque`，这显然不是一个高效的想法，对吧？你可能会想，有什么大不了的？我们可以为`bool`编写另一个专门的类或模板类。但这种方法要求最终用户明确为不同的数据类型使用不同的类，这也不是一个好的设计，对吧？这正是 C++的显式类特化派上用场的地方。

显式模板特化也被称为完全模板特化。

如果你还不相信，没关系；下面的例子将帮助你理解显式类特化的需求以及显式类特化的工作原理。

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

前面的`DynamicArray`模板类内部使用了 STL `deque`类。因此，你可以将`DynamicArray`模板类视为自定义适配器容器。让我们看看`DynamicArray`模板类如何在`main.cpp`中使用，如下面的代码片段所示：

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

    cout << "\nInt DynamicArray values are ..." << endl;
    while ( intArray.hasNextValue() )
          cout << intArray.getValue() << "\t";
    cout << endl;

    DynamicArray<char> charArray;
    charArray.appendValue( 'H' );
    charArray.appendValue( 'e' );
    charArray.appendValue( 'l' );
    charArray.appendValue( 'l' );
    charArray.appendValue( 'o' );

    charArray.initialize();

    cout << "\nChar DynamicArray values are ..." << endl;
    while ( charArray.hasNextValue() )
          cout << charArray.getValue() << "\t";
    cout << endl;

    DynamicArray<bool> boolArray;

    boolArray.appendValue ( true );
    boolArray.appendValue ( false );
    boolArray.appendValue ( true );
    boolArray.appendValue ( false );

    boolArray.initialize();

    cout << "\nBool DynamicArray values are ..." << endl;
    while ( boolArray.hasNextValue() )
         cout << boolArray.getValue() << "\t";
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

太好了！我们的自定义适配器容器似乎工作正常。

# 代码演示

让我们放大并尝试理解前面的程序是如何工作的。下面的代码告诉 C++编译器接下来是一个类模板：

```cpp
template < class T >
class DynamicArray {
      private:
           deque< T > dynamicArray;
           typename deque< T >::iterator pos;
```

如你所见，`DynamicArray`类内部使用了 STL `deque`，并且为`deque`声明了名为`pos`的迭代器。这个迭代器`pos`被`Dynamic`模板类用于提供高级方法，比如`initialize()`、`appendValue()`、`hasNextValue()`和`getValue()`方法。

`initialize()`方法将`deque`迭代器`pos`初始化为存储在`deque`中的第一个数据元素。`appendValue( T element )`方法允许您在`deque`的末尾添加数据元素。`hasNextValue()`方法告诉`DynamicArray`类是否有进一步存储的数据值--`true`表示有更多的值，`false`表示`DynamicArray`导航已经到达`deque`的末尾。当需要时，`initialize()`方法可以用来重置`pos`迭代器到起始点。`getValue()`方法返回`pos`迭代器指向的数据元素。`getValue()`方法不执行任何验证；因此，在调用`getValue()`之前，必须与`hasNextValue()`结合使用，以安全地访问存储在`DynamicArray`中的值。

现在，让我们了解`main()`函数。以下代码声明了一个存储`int`数据类型的`DynamicArray`类；`DynamicArray<int> intArray`将触发 C++编译器实例化一个专门用于`int`数据类型的`DynamicArray`类。

```cpp
DynamicArray<int> intArray;

intArray.appendValue( 100 );
intArray.appendValue( 200 );
intArray.appendValue( 300 );
intArray.appendValue( 400 );
```

值`100`、`200`、`300`和`400`被依次存储在`DynamicArray`类中。以下代码确保`intArray`迭代器指向第一个元素。一旦迭代器初始化，存储在`DynamicArray`类中的值将通过`getValue()`方法打印出来，而`hasNextValue()`确保导航没有到达`DynamicArray`类的末尾。

```cpp
intArray.initialize();
cout << "\nInt DynamicArray values are ..." << endl;
while ( intArray.hasNextValue() )
      cout << intArray.getValue() << "\t";
cout << endl;
```

在同样的情况下，在主函数中，创建了一个`char DynamicArray`类，填充了一些数据，并打印出来。让我们跳过`char` `DynamicArray`，直接转到存储`bool`的`DynamicArray`类。

```cpp
DynamicArray<bool> boolArray;

boolArray.appendValue ( "1010" );

boolArray.initialize();

cout << "\nBool DynamicArray values are ..." << endl;

while ( boolArray.hasNextValue() )
      cout << boolArray.getValue() << "\t";
cout << endl;
```

从前面的代码片段中，我们可以看到一切看起来都很好，对吗？是的，前面的代码运行得很好；然而，`DynamicArray`的设计方法存在性能问题。虽然`true`可以用`1`表示，`false`可以用`0`表示，只需要 1 位，但前面的`DynamicArray`类使用 8 位来表示`1`，另外 8 位来表示`0`，我们必须修复，而不强迫最终用户选择一个对`bool`有效率的`DynamicArray`类。

让我们通过以下代码使用显式类模板特化来解决这个问题：

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

如果你仔细观察，专门为`bool`的`DynamicArray`类在内部使用了`deque< bitset<8> >`，即 8 位的`bitset`的`deque`，在需要时，`deque`将自动分配更多的`bitset<8>`位。`bitset`变量是一个内存高效的 STL 容器，只消耗 1 位来表示`true`或`false`。

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

    cout << "\nInt DynamicArray values are ..." << endl;

    while ( intArray.hasNextValue() )
          cout << intArray.getValue() << "\t";
    cout << endl;

    DynamicArray<char> charArray;

    charArray.appendValue( 'H' );
    charArray.appendValue( 'e' );
    charArray.appendValue( 'l' );
    charArray.appendValue( 'l' );
    charArray.appendValue( 'o' );

    charArray.initialize();

    cout << "\nChar DynamicArray values are ..." << endl;
    while ( charArray.hasNextValue() )
          cout << charArray.getValue() << "\t";
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

    cout << "\nBool DynamicArray values are ..." << endl;
    while ( boolArray.hasNextValue() )
          cout << boolArray.getValue() ;
    cout << endl;

    return 0;

}
```

有了类模板特化，我们可以观察到以下的主要代码对于`bool`、`char`和`double`似乎是相同的，尽管主模板类`DynamicArray`和专门化的`DynamicArray<bool>`类是不同的。

```cpp
DynamicArray<char> charArray;
charArray.appendValue( 'H' );
charArray.appendValue( 'e' );

charArray.initialize();

cout << "\nChar DynamicArray values are ..." << endl;
while ( charArray.hasNextValue() )
cout << charArray.getValue() << "\t";
cout << endl;

DynamicArray<bool> boolArray;
boolArray.appendValue ( true );
boolArray.appendValue ( false );

boolArray.initialize();

cout << "\nBool DynamicArray values are ..." << endl;
while ( boolArray.hasNextValue() )
      cout << boolArray.getValue() ;
cout << endl;
```

我相信你会发现这个 C++模板特化特性非常有用。

# 部分模板特化

与显式模板特化不同，显式模板特化用自己的完整定义替换特定数据类型的主模板类，部分模板特化允许我们专门化主模板类支持的某个子集的模板参数，而其他通用类型可以与主模板类相同。

当部分模板特化与继承结合时，可以做更多的奇迹，如下例所示。

```cpp
#include <iostream>
using namespace std;

template <typename T1, typename T2, typename T3>
class MyTemplateClass {
public:
     void F1( T1 t1, T2 t2, T3 t3 ) {
          cout << "\nPrimary Template Class - Function F1 invoked ..." << endl;
          cout << "Value of t1 is " << t1 << endl;
          cout << "Value of t2 is " << t2 << endl;
          cout << "Value of t3 is " << t3 << endl;
     }

     void F2(T1 t1, T2 t2) {
          cout << "\nPrimary Tempalte Class - Function F2 invoked ..." << endl;
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
               cout << "\nPartially Specialized Template Class - Function F1 invoked ..." << endl;
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

从前面的代码中，你可能已经注意到主模板类的名称和部分特化类的名称与完全或显式模板类特化的情况相同。然而，在模板参数表达式中有一些语法上的变化。在完全模板类特化的情况下，模板参数表达式将为空，而在部分特化的模板类的情况下，列出的表达式会出现，如下所示：

```cpp
template <typename T1, typename T2, typename T3>
class MyTemplateClass< T1, T2*, T3*> : public MyTemplateClass<T1, T2, T3> { };
```

表达式`template<typename T1, typename T2, typename T3>`是主类模板中使用的模板参数表达式，`MyTemplateClass< T1, T2*, T3*>`是第二类进行的部分特化。你可以看到，第二类对`typename T2`和`typename T3`进行了一些特化，因为它们在第二类中被用作指针；然而，`typename T1`在第二类中被原样使用。

除了迄今为止讨论的事实之外，第二类还继承了主模板类，这有助于第二类重用主模板类的公共和受保护方法。然而，部分模板特化并不会阻止特定类支持其他函数。

当主模板类的`F1`函数被部分特化的模板类替换时，它通过继承重用了主模板类的`F2`函数。

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

希望你会发现部分特化的模板类有用。

# 总结

在本章中，你学会了以下内容：

+   你现在知道使用泛型编程的动机

+   你现在熟悉了函数模板

+   你知道如何重载函数模板

+   你知道类模板

+   你知道何时使用显式模板特化以及何时使用部分特化的模板特化

恭喜！总的来说，你对 C++的模板编程有很好的理解。

在下一章中，你将学习智能指针。


# 第四章：智能指针

在上一章中，您了解了模板编程和泛型编程的好处。在本章中，您将学习以下智能指针主题：

+   内存管理

+   原始指针的问题

+   循环依赖

+   智能指针：

+   `auto_ptr`

+   智能指针

+   `shared_ptr`

+   `weak_ptr`

让我们探讨 C++提供的内存管理设施。

# 内存管理

在 C++中，内存管理通常是软件开发人员的责任。这是因为 C++标准不强制在 C++编译器中支持垃圾回收；因此，这取决于编译器供应商的选择。特别是，Sun C++编译器带有一个名为`libgc`的垃圾回收库。

C++语言拥有许多强大的特性。其中，指针无疑是其中最强大和最有用的特性之一。指针非常有用，但它们也有自己的奇怪问题，因此必须负责使用。当内存管理没有得到认真对待或者没有做得很好时，会导致许多问题，包括应用程序崩溃、核心转储、分段错误、难以调试的问题、性能问题等等。悬空指针或者流氓指针有时会干扰其他无关的应用程序，而罪魁祸首应用程序却悄无声息地执行；事实上，受害应用程序可能会被多次责怪。内存泄漏最糟糕的部分在于，有时会变得非常棘手，即使是经验丰富的开发人员最终也会花费数小时来调试受害代码，而罪魁祸首代码却毫发未损。有效的内存管理有助于避免内存泄漏，并让您开发内存高效的高性能应用程序。

由于每个操作系统的内存模型都不同，因此在相同的内存泄漏问题上，每个操作系统可能在不同的时间点表现不同。内存管理是一个大课题，C++提供了许多有效的方法来处理它。我们将在以下章节讨论一些有用的技术。

# 原始指针的问题

大多数 C++开发人员有一个共同点：我们都喜欢编写复杂的东西。你问一个开发人员，“嘿，伙计，你想重用已经存在并且可用的代码，还是想自己开发一个？”虽然大多数开发人员会委婉地说在可能的情况下重用已有的代码，但他们的内心会说，“我希望我能自己设计和开发它。”复杂的数据结构和算法往往需要指针。原始指针在遇到麻烦之前确实很酷。

在使用前，原始指针必须分配内存，并且在使用后需要释放内存；就是这么简单。然而，在一个产品中，指针分配可能发生在一个地方，而释放可能发生在另一个地方。如果内存管理决策没有做出正确的选择，人们可能会认为释放内存是调用者或被调用者的责任，有时内存可能不会从任何地方释放。还有另一种可能性，同一个指针可能会从不同的地方被多次删除，这可能导致应用程序崩溃。如果这种情况发生在 Windows 设备驱动程序中，很可能会导致蓝屏。

想象一下，如果出现应用程序异常，并且抛出异常的函数有一堆在异常发生前分配了内存的指针？任何人都能猜到：会有内存泄漏。

让我们看一个使用原始指针的简单例子：

```cpp
#include <iostream>
using namespace std;

class MyClass {
      public:
           void someMethod() {

                int *ptr = new int();
                *ptr = 100;
                int result = *ptr / 0;  //division by zero error expected
                delete ptr;

           }
};

int main ( ) {

    MyClass objMyClass;
    objMyClass.someMethod();

    return 0;

}
```

现在，运行以下命令：

```cpp
g++ main.cpp -g -std=c++17
```

查看此程序的输出：

```cpp
main.cpp: In member function ‘void MyClass::someMethod()’:
main.cpp:12:21: warning: division by zero [-Wdiv-by-zero]
 int result = *ptr / 0;
```

现在，运行以下命令：

```cpp
./a.out
[1] 31674 floating point exception (core dumped) ./a.out
```

C++编译器真的很酷。看看警告消息，它指出了问题。我喜欢 Linux 操作系统。Linux 在发现行为不端的恶意应用程序方面非常聪明，并且及时将它们关闭，以免对其他应用程序或操作系统造成任何损害。核心转储实际上是好事，但在庆祝 Linux 方法时却被诅咒。猜猜，微软的 Windows 操作系统同样聪明。当它们发现一些应用程序进行可疑的内存访问时，它们会进行错误检查，Windows 操作系统也支持迷你转储和完整转储，这相当于 Linux 操作系统中的核心转储。

让我们看一下 Valgrind 工具的输出，以检查内存泄漏问题：

```cpp
valgrind --leak-check=full --show-leak-kinds=all ./a.out

==32857== Memcheck, a memory error detector
==32857== Copyright (C) 2002-2015, and GNU GPL'd, by Julian Seward et al.
==32857== Using Valgrind-3.12.0 and LibVEX; rerun with -h for copyright info
==32857== Command: ./a.out
==32857== 
==32857== 
==32857== Process terminating with default action of signal 8 (SIGFPE)
==32857== Integer divide by zero at address 0x802D82B86
==32857== at 0x10896A: MyClass::someMethod() (main.cpp:12)
==32857== by 0x1088C2: main (main.cpp:24)
==32857== 
==32857== HEAP SUMMARY:
==32857== in use at exit: 4 bytes in 1 blocks
==32857== total heap usage: 2 allocs, 1 frees, 72,708 bytes allocated
==32857== 
==32857== 4 bytes in 1 blocks are still reachable in loss record 1 of 1
==32857== at 0x4C2E19F: operator new(unsigned long) (in /usr/lib/valgrind/vgpreload_memcheck-amd64-linux.so)
==32857== by 0x108951: MyClass::someMethod() (main.cpp:8)
==32857== by 0x1088C2: main (main.cpp:24)
==32857== 
==32857== LEAK SUMMARY:
==32857== definitely lost: 0 bytes in 0 blocks
==32857== indirectly lost: 0 bytes in 0 blocks
==32857== possibly lost: 0 bytes in 0 blocks
==32857== still reachable: 4 bytes in 1 blocks
==32857== suppressed: 0 bytes in 0 blocks
==32857== 
==32857== For counts of detected and suppressed errors, rerun with: -v
==32857== ERROR SUMMARY: 0 errors from 0 contexts (suppressed: 0 from 0)
[1] 32857 floating point exception (core dumped) valgrind --leak-check=full --show-leak-kinds=all ./a.out
```

在这个输出中，如果你注意**粗体**部分的文本，你会注意到 Valgrind 工具指出了导致这个核心转储的源代码行号。`main.cpp`文件中的第 12 行如下：

```cpp
 int result = *ptr / 0; //division by zero error expected 
```

在`main.cpp`文件的第 12 行发生异常时，异常下面出现的代码将永远不会被执行。在`main.cpp`文件的第 13 行，由于异常，将永远不会执行`delete`语句：

```cpp
 delete ptr;
```

在堆栈展开过程中，由于指针指向的内存在堆栈展开过程中没有被释放，因此前面的原始指针分配的内存没有被释放。每当函数抛出异常并且异常没有被同一个函数处理时，堆栈展开是有保证的。然而，只有自动本地变量在堆栈展开过程中会被清理，而不是指针指向的内存。这导致内存泄漏。

这是使用原始指针引发的奇怪问题之一；还有许多其他类似的情况。希望你现在已经相信，使用原始指针的乐趣是有代价的。但所付出的代价并不值得，因为在 C++中有很好的替代方案来解决这个问题。你是对的，使用智能指针是提供使用指针的好处而不付出原始指针附加成本的解决方案。

因此，智能指针是在 C++中安全使用指针的方法。

# 智能指针

在 C++中，智能指针让你专注于手头的问题，摆脱了处理自定义垃圾收集技术的烦恼。智能指针让你安全地使用原始指针。它们负责清理原始指针使用的内存。

C++支持许多类型的智能指针，可以在不同的场景中使用：

+   `auto_ptr`

+   `unique_ptr`

+   `shared_ptr`

+   `weak_ptr`

`auto_ptr`智能指针是在 C++11 中引入的。`auto_ptr`智能指针在超出范围时自动释放堆内存。然而，由于`auto_ptr`从一个`auto_ptr`实例转移所有权的方式，它已被弃用，并且`unique_ptr`被引入作为其替代品。`shared_ptr`智能指针帮助多个共享智能指针引用同一个对象，并负责内存管理负担。`weak_ptr`智能指针帮助解决由于应用程序设计中存在循环依赖问题而导致的`shared_ptr`使用的内存泄漏问题。

还有其他类型的智能指针和相关内容，它们并不常用，并列在以下项目列表中。然而，我强烈建议你自己探索它们，因为你永远不知道什么时候会发现它们有用：

+   无主

+   `enable_shared_from_this`

+   `bad_weak_ptr`

+   `default_delete`

`owner_less`智能指针帮助比较两个或更多个智能指针是否共享相同的原始指向对象。`enable_shared_from_this`智能指针帮助获取`this`指针的智能指针。`bad_weak_ptr`智能指针是一个异常类，意味着使用无效智能指针创建了`shared_ptr`。`default_delete`智能指针指的是`unique_ptr`使用的默认销毁策略，它调用`delete`语句，同时也支持用于数组类型的部分特化，使用`delete[]`。

在本章中，我们将逐一探讨`auto_ptr`，`shared_ptr`，`weak_ptr`和`unique-ptr`。

# auto_ptr

`auto_ptr`智能指针接受一个原始指针，封装它，并确保原始指针指向的内存在`auto_ptr`对象超出范围时被释放。在任何时候，只有一个`auto_ptr`智能指针可以指向一个对象。因此，当一个`auto_ptr`指针被赋值给另一个`auto_ptr`指针时，所有权被转移到接收赋值的`auto_ptr`实例；当一个`auto_ptr`智能指针被复制时也是如此。

通过一个简单的例子来观察这些内容将会很有趣，如下所示：

```cpp
#include <iostream>
#include <string>
#include <memory>
#include <sstream>
using namespace std;

class MyClass {
      private:
           static int count;
           string name;
      public:
           MyClass() {
                 ostringstream stringStream(ostringstream::ate);
                 stringStream << "Object";
                 stringStream << ++count;
                 name = stringStream.str();
                 cout << "\nMyClass Default constructor - " << name << endl;
           }
           ~MyClass() {
                 cout << "\nMyClass destructor - " << name << endl;
           }

           MyClass ( const MyClass &objectBeingCopied ) {
                 cout << "\nMyClass copy constructor" << endl;
           }

           MyClass& operator = ( const MyClass &objectBeingAssigned ) {
                 cout << "\nMyClass assignment operator" << endl;
           }

           void sayHello( ) {
                cout << "Hello from MyClass " << name << endl;
           }
};

int MyClass::count = 0;

int main ( ) {

   auto_ptr<MyClass> ptr1( new MyClass() );
   auto_ptr<MyClass> ptr2( new MyClass() );

   return 0;

}
```

前面程序的编译输出如下：

```cpp
g++ main.cpp -std=c++17

main.cpp: In function ‘int main()’:
main.cpp:40:2: warning: ‘template<class> class std::auto_ptr’ is deprecated [-Wdeprecated-declarations]
 auto_ptr<MyClass> ptr1( new MyClass() );

In file included from /usr/include/c++/6/memory:81:0,
 from main.cpp:3:
/usr/include/c++/6/bits/unique_ptr.h:49:28: note: declared here
 template<typename> class auto_ptr;

main.cpp:41:2: warning: ‘template<class> class std::auto_ptr’ is deprecated [-Wdeprecated-declarations]
 auto_ptr<MyClass> ptr2( new MyClass() );

In file included from /usr/include/c++/6/memory:81:0,
 from main.cpp:3:
/usr/include/c++/6/bits/unique_ptr.h:49:28: note: declared here
 template<typename> class auto_ptr;
```

正如你所看到的，C++编译器警告我们使用`auto_ptr`已经被弃用。因此，我不建议再使用`auto_ptr`智能指针；它已被`unique_ptr`取代。

现在，我们可以忽略警告并继续，如下所示：

```cpp
g++ main.cpp -Wno-deprecated

./a.out

MyClass Default constructor - Object1

MyClass Default constructor - Object2

MyClass destructor - Object2

MyClass destructor - Object1 
```

正如你在前面的程序输出中所看到的，分配在堆中的`Object1`和`Object2`都被自动删除了。这要归功于`auto_ptr`智能指针。

# 代码演示 - 第 1 部分

从`MyClass`的定义中，你可能已经了解到，它定义了默认的`构造函数`，`复制`构造函数和析构函数，一个`赋值`运算符和`sayHello()`方法，如下所示：

```cpp
//Definitions removed here to keep it simple 
class MyClass {
public:
      MyClass() { }  //Default constructor
      ~MyClass() { } //Destructor 
      MyClass ( const MyClass &objectBeingCopied ) {} //Copy Constructor 
      MyClass& operator = ( const MyClass &objectBeingAssigned ) { } //Assignment operator
      void sayHello();
}; 
```

`MyClass`的方法只是一个打印语句，表明方法被调用；它们纯粹是为了演示目的而设计的。

`main()`函数创建了两个`auto_ptr`智能指针，它们指向两个不同的`MyClass`对象，如下所示：

```cpp
int main ( ) {

   auto_ptr<MyClass> ptr1( new MyClass() );
   auto_ptr<MyClass> ptr2( new MyClass() );

   return 0;

}
```

正如你所理解的，`auto_ptr`是一个封装了原始指针而不是指针的本地对象。当控制流达到`return`语句时，堆栈展开过程开始，作为这一过程的一部分，堆栈对象`ptr1`和`ptr2`被销毁。这反过来调用了`auto_ptr`的析构函数，最终删除了堆栈对象`ptr1`和`ptr2`指向的`MyClass`对象。

我们还没有完成。让我们探索`auto_ptr`的更多有用功能，如下所示的`main`函数：

```cpp
int main ( ) {

    auto_ptr<MyClass> ptr1( new MyClass() );
    auto_ptr<MyClass> ptr2( new MyClass() );

    ptr1->sayHello();
    ptr2->sayHello();

    //At this point the below stuffs happen
    //1\. ptr2 smart pointer has given up ownership of MyClass Object 2
    //2\. MyClass Object 2 will be destructed as ptr2 has given up its 
    //   ownership on Object 2
    //3\. Ownership of Object 1 will be transferred to ptr2
    ptr2 = ptr1;

    //The line below if uncommented will result in core dump as ptr1 
    //has given up its ownership on Object 1 and the ownership of 
    //Object 1 is transferred to ptr2.
    // ptr1->sayHello();

    ptr2->sayHello();

    return 0;

}
```

# 代码演示 - 第 2 部分

我们刚刚看到的`main()`函数代码演示了许多有用的技术和一些`auto_ptr`智能指针的争议行为。以下代码创建了两个`auto_ptr`的实例，即`ptr1`和`ptr2`，它们封装了在堆中创建的两个`MyClass`对象：

```cpp
 auto_ptr<MyClass> ptr1( new MyClass() );
 auto_ptr<MyClass> ptr2( new MyClass() );
```

接下来，以下代码演示了如何使用`auto_ptr`调用`MyClass`支持的方法：

```cpp
 ptr1->sayHello();
 ptr2->sayHello();
```

希望你注意到了`ptr1->sayHello()`语句。它会让你相信`auto_ptr` `ptr1`对象是一个指针，但实际上，`ptr1`和`ptr2`只是作为本地变量在堆栈中创建的`auto_ptr`对象。由于`auto_ptr`类重载了`->`指针运算符和`*`解引用运算符，它看起来像一个指针。事实上，`MyClass`暴露的所有方法只能使用`->`指针运算符访问，而所有`auto_ptr`方法可以像访问堆栈对象一样访问。

以下代码演示了`auto_ptr`智能指针的内部行为，所以请密切关注；这将会非常有趣：

```cpp
ptr2 = ptr1;
```

尽管上述代码看起来像是一个简单的`赋值`语句，但它在`auto_ptr`中触发了许多活动。由于前面的`赋值`语句，发生了以下活动：

+   `ptr2`智能指针将放弃对`MyClass`对象 2 的所有权。

+   `ptr2`放弃了对`object 2`的所有权，因此`MyClass`对象 2 将被销毁。

+   `object 1`的所有权将被转移到`ptr2`。

+   此时，`ptr1`既不指向`object 1`，也不负责管理`object 1`使用的内存。

以下注释行包含一些信息：

```cpp
// ptr1->sayHello();
```

由于`ptr1`智能指针已经释放了对`object 1`的所有权，因此尝试访问`sayHello()`方法是非法的。这是因为`ptr1`实际上不再指向`object 1`，而`object 1`由`ptr2`拥有。当`ptr2`超出范围时，释放`object 1`使用的内存是`ptr2`智能指针的责任。如果取消注释上述代码，将导致核心转储。

最后，以下代码让我们使用`ptr2`智能指针在`object 1`上调用`sayHello()`方法：

```cpp
ptr2->sayHello();
return 0;
```

我们刚刚看到的`return`语句将在`main()`函数中启动堆栈展开过程。这将最终调用`ptr2`的析构函数，进而释放`object 1`使用的内存。美妙的是，所有这些都是自动发生的。在我们专注于手头的问题时，`auto_ptr`智能指针在幕后为我们努力工作。

然而，由于以下原因，从`C++11`开始，`auto_ptr`已经被弃用：

+   `auto_ptr`对象不能存储在 STL 容器中

+   `auto_ptr`复制构造函数将从原始源头那里移除所有权，也就是说，``auto_ptr``

+   `auto_ptr`复制`赋值`运算符将从原始源头那里移除所有权，也就是说，`auto_ptr`

+   `auto_ptr`的复制构造函数和`赋值`运算符违反了原始意图，因为`auto_ptr`的复制构造函数和`赋值`运算符将从右侧对象中移除源对象的所有权，并将所有权分配给左侧对象

# unique_ptr

`unique_ptr`智能指针的工作方式与`auto_ptr`完全相同，只是`unique_ptr`解决了`auto_ptr`引入的问题。因此，`unique_ptr`是`C++11`开始的`auto_ptr`的替代品。`unique_ptr`智能指针只允许一个智能指针独占拥有堆分配的对象。只能通过`std::move()`函数将一个`unique_ptr`实例的所有权转移给另一个实例。

因此，让我们重构我们之前的示例，使用`unique_ptr`来替代`auto_ptr`。

重构后的代码示例如下：

```cpp
#include <iostream>
#include <string>
#include <memory>
#include <sstream>
using namespace std;

class MyClass {
      private:
          static int count;
          string name;

      public:
          MyClass() {
                ostringstream stringStream(ostringstream::ate);
                stringStream << "Object";
                stringStream << ++count;
                name = stringStream.str();
                cout << "\nMyClass Default constructor - " << name << endl;
          }

          ~MyClass() {
                cout << "\nMyClass destructor - " << name << endl;
          }

          MyClass ( const MyClass &objectBeingCopied ) {
                cout << "\nMyClass copy constructor" << endl;
          }

          MyClass& operator = ( const MyClass &objectBeingAssigned ) {
                cout << "\nMyClass assignment operator" << endl;
          }

          void sayHello( ) {
                cout << "\nHello from MyClass" << endl;
          }

};

int MyClass::count = 0;

int main ( ) {

 unique_ptr<MyClass> ptr1( new MyClass() );
 unique_ptr<MyClass> ptr2( new MyClass() );

 ptr1->sayHello();
 ptr2->sayHello();

 //At this point the below stuffs happen
 //1\. ptr2 smart pointer has given up ownership of MyClass Object 2
 //2\. MyClass Object 2 will be destructed as ptr2 has given up its 
 // ownership on Object 2
 //3\. Ownership of Object 1 will be transferred to ptr2
 ptr2 = move( ptr1 );

 //The line below if uncommented will result in core dump as ptr1 
 //has given up its ownership on Object 1 and the ownership of 
 //Object 1 is transferred to ptr2.
 // ptr1->sayHello();

 ptr2->sayHello();

 return 0;
}
```

上述程序的输出如下：

```cpp
g++ main.cpp -std=c++17

./a.out

MyClass Default constructor - Object1

MyClass Default constructor - Object2

MyClass destructor - Object2

MyClass destructor - Object1 
```

在上述输出中，您可以注意到编译器没有报告任何警告，并且程序的输出与`auto_ptr`的输出相同。

# 代码演示

重要的是要注意`main()`函数中`auto_ptr`和`unique_ptr`之间的区别。让我们来看一下以下代码中所示的`main()`函数。这段代码在堆中创建了两个`MyClass`对象的实例，分别用`ptr1`和`ptr2`包装起来：

```cpp
 unique_ptr<MyClass> ptr1( new MyClass() );
 unique_ptr<MyClass> ptr2( new MyClass() );
```

接下来，以下代码演示了如何使用`unique_ptr`调用`MyClass`支持的方法：

```cpp
 ptr1->sayHello();
 ptr2->sayHello();
```

就像`auto_ptr`一样，`unique_ptr`智能指针`ptr1`对象重载了`->`指针运算符和`*`解引用运算符；因此，它看起来像一个指针。

以下代码演示了`unique_ptr`不支持将一个`unique_ptr`实例分配给另一个实例，只能通过`std::move()`函数实现所有权转移：

```cpp
ptr2 = std::move(ptr1);
```

`move`函数触发以下活动：

+   `ptr2`智能指针放弃了对`MyClass`对象 2 的所有权

+   `ptr2`放弃了对`object 2`的所有权，因此`MyClass`对象 2 被销毁

+   `object 1` 的所有权已转移到 `ptr2`

+   此时，`ptr1` 既不指向 `object 1`，也不负责管理 `object 1` 使用的内存

如果取消注释以下代码，将导致核心转储：

```cpp
// ptr1->sayHello();
```

最后，以下代码让我们使用 `ptr2` 智能指针调用 `object 1` 的 `sayHello()` 方法：

```cpp
ptr2->sayHello();
return 0;
```

我们刚刚看到的 `return` 语句将在 `main()` 函数中启动堆栈展开过程。这将最终调用 `ptr2` 的析构函数，从而释放 `object 1` 使用的内存。请注意，`unique_ptr` 对象可以存储在 STL 容器中，而 `auto_ptr` 对象则不行。

# shared_ptr

当一组 `shared_ptr` 对象共享堆分配的对象的所有权时，使用 `shared_ptr` 智能指针。当所有 `shared_ptr` 实例完成对共享对象的使用时，`shared_ptr` 指针释放共享对象。`shared_ptr` 指针使用引用计数机制来检查对共享对象的总引用；每当引用计数变为零时，最后一个 `shared_ptr` 实例将删除共享对象。

让我们通过一个示例来检查 `shared_ptr` 的使用，如下所示：

```cpp
#include <iostream>
#include <string>
#include <memory>
#include <sstream>
using namespace std;

class MyClass {
  private:
    static int count;
    string name;
  public:
    MyClass() {
      ostringstream stringStream(ostringstream::ate);
      stringStream << "Object";
      stringStream << ++count;

      name = stringStream.str();

      cout << "\nMyClass Default constructor - " << name << endl;
    }

    ~MyClass() {
      cout << "\nMyClass destructor - " << name << endl;
    }

    MyClass ( const MyClass &objectBeingCopied ) {
      cout << "\nMyClass copy constructor" << endl;
    }

    MyClass& operator = ( const MyClass &objectBeingAssigned ) {
      cout << "\nMyClass assignment operator" << endl;
    }

    void sayHello() {
      cout << "Hello from MyClass " << name << endl;
    }

};

int MyClass::count = 0;

int main ( ) {

  shared_ptr<MyClass> ptr1( new MyClass() );
  ptr1->sayHello();
  cout << "\nUse count is " << ptr1.use_count() << endl;

  {
      shared_ptr<MyClass> ptr2( ptr1 );
      ptr2->sayHello();
      cout << "\nUse count is " << ptr2.use_count() << endl;
  }

  shared_ptr<MyClass> ptr3 = ptr1;
  ptr3->sayHello();
  cout << "\nUse count is " << ptr3.use_count() << endl;

  return 0;
}
```

前面程序的输出如下：

```cpp
MyClass Default constructor - Object1
Hello from MyClass Object1
Use count is 1

Hello from MyClass Object1
Use count is 2

Number of smart pointers referring to MyClass object after ptr2 is destroyed is 1

Hello from MyClass Object1
Use count is 2

MyClass destructor - Object1
```

# 代码漫游

以下代码创建了一个指向堆分配的 `MyClass` 对象的 `shared_ptr` 对象实例。与其他智能指针一样，`shared_ptr` 也有重载的 `->` 和 `*` 运算符。因此，可以调用所有 `MyClass` 对象的方法，就好像使用原始指针一样。`use_count()` 方法告诉指向共享对象的智能指针的数量：

```cpp
 shared_ptr<MyClass> ptr1( new MyClass() );
 ptr1->sayHello();
 cout << "\nNumber of smart pointers referring to MyClass object is "
      << ptr1->use_count() << endl;
```

在以下代码中，智能指针 `ptr2` 的作用域被包含在花括号括起来的块中。因此，`ptr2` 将在以下代码块的末尾被销毁。代码块内的预期 `use_count` 函数为 2：

```cpp
 { 
      shared_ptr<MyClass> ptr2( ptr1 );
      ptr2->sayHello();
      cout << "\nNumber of smart pointers referring to MyClass object is "
           << ptr2->use_count() << endl;
 }
```

在以下代码中，预期的 `use_count` 值为 1，因为 `ptr2` 已被删除，这将减少 1 个引用计数：

```cpp
 cout << "\nNumber of smart pointers referring to MyClass object after ptr2 is destroyed is "
 << ptr1->use_count() << endl; 
```

以下代码将打印一个 Hello 消息，后跟 `use_count` 为 2。这是因为 `ptr1` 和 `ptr3` 现在都指向堆中的 `MyClass` 共享对象：

```cpp
shared_ptr<MyClass> ptr3 = ptr2;
ptr3->sayHello();
cout << "\nNumber of smart pointers referring to MyClass object is "
     << ptr2->use_count() << endl;
```

`main` 函数末尾的 `return 0;` 语句将销毁 `ptr1` 和 `ptr3`，将引用计数减少到零。因此，我们可以观察到输出末尾打印 `MyClass` 析构函数的语句。

# weak_ptr

到目前为止，我们已经讨论了 `shared_ptr` 的正面作用，并举例说明。但是，当应用程序设计中存在循环依赖时，`shared_ptr` 无法清理内存。要么必须重构应用程序设计以避免循环依赖，要么可以使用 `weak_ptr` 来解决循环依赖问题。

您可以查看我的 YouTube 频道，了解 `shared_ptr` 问题以及如何使用 `weak_ptr` 解决该问题：[`www.youtube.com/watch?v=SVTLTK5gbDc`](https://www.youtube.com/watch?v=SVTLTK5gbDc)。

考虑有三个类：A、B 和 C。类 A 和 B 都有一个 C 的实例，而 C 有 A 和 B 的实例。这里存在一个设计问题。A 依赖于 C，而 C 也依赖于 A。同样，B 依赖于 C，而 C 也依赖于 B。

考虑以下代码：

```cpp
#include <iostream>
#include <string>
#include <memory>
#include <sstream>
using namespace std;

class C;

class A {
      private:
           shared_ptr<C> ptr;
      public:
           A() {
                 cout << "\nA constructor" << endl;
           }

           ~A() {
                 cout << "\nA destructor" << endl;
           }

           void setObject ( shared_ptr<C> ptr ) {
                this->ptr = ptr;
           }
};

class B {
      private:
           shared_ptr<C> ptr;
      public:
           B() {
                 cout << "\nB constructor" << endl;
           }

           ~B() {
                 cout << "\nB destructor" << endl;
           }

           void setObject ( shared_ptr<C> ptr ) {
                this->ptr = ptr;
           }
};

class C {
      private:
           shared_ptr<A> ptr1;
           shared_ptr<B> ptr2;
      public:
           C(shared_ptr<A> ptr1, shared_ptr<B> ptr2) {
                   cout << "\nC constructor" << endl;
                   this->ptr1 = ptr1;
                   this->ptr2 = ptr2;
           }

           ~C() {
                   cout << "\nC destructor" << endl;
           }
};

int main ( ) {
                shared_ptr<A> a( new A() );
                shared_ptr<B> b( new B() );
                shared_ptr<C> c( new C( a, b ) );

                a->setObject ( shared_ptr<C>( c ) );
                b->setObject ( shared_ptr<C>( c ) );

                return 0;
}
```

前面程序的输出如下：

```cpp
g++ problem.cpp -std=c++17

./a.out

A constructor

B constructor

C constructor
```

在前面的输出中，您可以观察到，即使我们使用了`shared_ptr`，对象 A、B 和 C 使用的内存从未被释放。这是因为我们没有看到各自类的析构函数被调用。原因是`shared_ptr`在内部使用引用计数算法来决定是否共享对象必须被销毁。然而，它在这里失败了，因为除非删除对象 C，否则无法删除对象 A。除非删除对象 A，否则无法删除对象 C。同样，除非删除对象 A 和 B，否则无法删除对象 C。同样，除非删除对象 C，否则无法删除对象 A，除非删除对象 C，否则无法删除对象 B。

问题的关键是这是一个循环依赖设计问题。为了解决这个问题，从 C++11 开始，C++引入了`weak_ptr`。`weak_ptr`智能指针不是一个强引用。因此，所引用的对象可以在任何时候被删除，不像`shared_ptr`。

# 循环依赖

循环依赖是一个问题，如果对象 A 依赖于 B，而对象 B 又依赖于 A。现在让我们看看如何通过`shared_ptr`和`weak_ptr`的组合来解决这个问题，最终打破循环依赖，如下所示：

```cpp
#include <iostream>
#include <string>
#include <memory>
#include <sstream>
using namespace std;

class C;

class A {
      private:
 weak_ptr<C> ptr;
      public:
           A() {
                  cout << "\nA constructor" << endl;
           }

           ~A() {
                  cout << "\nA destructor" << endl;
           }

           void setObject ( weak_ptr<C> ptr ) {
                  this->ptr = ptr;
           }
};

class B {
      private:
 weak_ptr<C> ptr;
      public:
           B() {
               cout << "\nB constructor" << endl;
           }

           ~B() {
               cout << "\nB destructor" << endl;
           }

           void setObject ( weak_ptr<C> ptr ) {
                this->ptr = ptr;
           }
};

class C {
      private:
           shared_ptr<A> ptr1;
           shared_ptr<B> ptr2;
      public:
           C(shared_ptr<A> ptr1, shared_ptr<B> ptr2) {
                   cout << "\nC constructor" << endl;
                   this->ptr1 = ptr1;
                   this->ptr2 = ptr2;
           }

           ~C() {
                   cout << "\nC destructor" << endl;
           }
};

int main ( ) {
         shared_ptr<A> a( new A() );
         shared_ptr<B> b( new B() );
         shared_ptr<C> c( new C( a, b ) );

         a->setObject ( weak_ptr<C>( c ) );
         b->setObject ( weak_ptr<C>( c ) );

         return 0;
}
```

重构代码的输出如下：

```cpp
g++ solution.cpp -std=c++17

./a.out

A constructor

B constructor

C constructor

C destructor

B destructor

A destructor
```

# 摘要

在本章中，您了解到

+   由于原始指针而引起的内存泄漏问题

+   关于赋值和复制构造函数的`auto_ptr`的问题

+   `unique_ptr`及其优势

+   `shared_ptr`在内存管理中的作用及其与循环依赖相关的限制。

+   您还可以使用`weak_ptr`解决循环依赖问题。

在下一章中，您将学习如何在 C++中开发 GUI 应用程序。


# 第五章：在 C++中开发 GUI 应用程序

在本章中，您将学习以下主题：

+   Qt 简要概述

+   Qt 框架

+   在 Ubuntu 上安装 Qt

+   开发 Qt 核心应用程序

+   开发 Qt GUI 应用程序

+   在 Qt GUI 应用程序中使用布局

+   理解事件处理的信号和槽

+   在 Qt 应用程序中使用多个布局

Qt 是一个用 C++开发的跨平台应用程序框架。它支持多个平台，包括 Windows、Linux、Mac OS、Android、iOS、嵌入式 Linux、QNX、VxWorks、Windows CE/RT、Integrity、Wayland、X11、嵌入式设备等。它主要用作人机界面（HMI）或图形用户界面（GUI）框架；但也用于开发命令行界面（CLI）应用程序。正确发音为“cute”。Qt 应用程序框架有两种版本：开源版本和商业许可版本。

Qt 是 Haavard Nord 和 Eirik Chambe-Eng 的心血结晶，他们是最初的开发人员，在 1991 年开发了它。

由于 C++语言本身不支持 GUI，你可能已经猜到了，C++语言本身并不支持事件管理。因此，Qt 需要支持自己的事件处理机制，这导致了信号和槽技术的出现。在底层，信号和槽使用了观察者设计模式，允许 Qt 对象相互通信。这听起来太难理解了吗？别担心！信号只是事件，比如按钮点击或窗口关闭，而槽是事件处理程序，可以以你希望的方式对这些事件做出响应。

为了使我们在 Qt 应用程序开发方面的生活更加轻松，Qt 支持各种宏和 Qt 特定的关键字。由于这些关键字不会被 C++理解，Qt 必须将它们和宏转换为纯粹的 C++代码，以便 C++编译器可以像往常一样工作。为了使这一切更加顺利，Qt 支持一种称为“元对象编译器”的东西，也被称为“moc”。

Qt 是 C++项目的自然选择，因为它是纯粹的 C++代码；因此，作为 C++开发人员，在应用程序中使用 Qt 时会感到宾至如归。一个典型的应用程序将同时具有复杂的逻辑和令人印象深刻的 UI。在小型产品团队中，通常一个开发人员会做多种工作，这既有利也有弊。

一般来说，专业开发人员具有良好的问题解决能力。问题解决能力对于以最佳方式解决复杂问题并选择良好的数据结构和算法至关重要。

开发令人印象深刻的 UI 需要创造性的设计技能。虽然有一定数量的开发人员擅长问题解决或创造性 UI 设计，但并非所有开发人员都擅长这两者。这就是 Qt 的优势所在。

比如，一家初创公司想要为内部目的开发一个应用程序。对于这个目的，一个简单的 GUI 应用程序就足够了，一个看起来不错的 HMI/GUI 可能对团队有用，因为应用程序只是为内部目的而设计的。在这种情况下，整个应用程序可以使用 C++和 Qt Widgets 框架开发。唯一的前提是开发团队必须精通 C++。

然而，在必须开发移动应用程序的情况下，令人印象深刻的 HMI 变得必不可少。同样，移动应用程序可以使用 C++和 Qt Widgets 开发。但现在这个选择有两个部分。好的一面是移动应用程序团队只需要擅长 C++。这个选择的坏处是，并不是所有擅长 C++的开发人员都擅长设计移动应用程序的 HMI/GUI。

假设团队有一两个专门的 Photoshop 专业人员，擅长创建引人注目的图像，可以在 GUI 中使用，还有一两个 UI 设计师，可以使用 Photoshop 专家创建的图像制作出令人印象深刻的 HMI/GUI。通常，UI 设计师擅长前端技术，如 JavaScript、HTML 和 CSS。强大的 Qt 框架可以开发复杂的业务逻辑，而 HMI/GUI 可以在 QML 中开发。

QML 是与 Qt 应用程序框架一起提供的一种声明性脚本语言。它类似于 JavaScript，并具有 Qt 特定的扩展。它非常适合快速应用程序开发，并允许 UI 设计师专注于 HMI/GUI，而 C++开发人员则专注于可以在 Qt 框架中开发的复杂业务逻辑。

由于 C++ Qt 框架和 QML 都是同一 Qt 应用程序框架的一部分，它们可以无缝地配合使用。

Qt 是一个庞大而强大的框架；因此，本章将重点介绍 Qt 的基本要点，以帮助您开始使用 Qt。如果您想了解更多信息，您可能想查看我正在撰写的另一本即将推出的书，名为*精通 Qt 和 QML 编程*。

# Qt

Qt 框架是用 C++开发的，因此可以保证对任何优秀的 C++开发人员来说都是易如反掌。它支持 CLI 和基于 GUI 的应用程序开发。在撰写本章时，Qt 应用程序框架的最新版本是 Qt 5.7.0。当您阅读本书时，可能会有不同版本的 Qt 可供您下载。您可以从[`www.qt.io`](https://www.qt.io)下载最新版本。

# 在 Ubuntu 16.04 中安装 Qt 5.7.0

在本章中，我将使用 Ubuntu 16.04 操作系统；但是，本章中列出的程序应该适用于支持 Qt 的任何平台。

有关详细的安装说明，请参阅[`wiki.qt.io/install_Qt_5_on_Ubuntu`](https://wiki.qt.io/install_Qt_5_on_Ubuntu)。

在这一点上，您应该在系统上安装了 C++编译器。如果不是这种情况，请首先确保您安装了 C++编译器，方法如下：

```cpp
sudo apt-get install build-essential
```

从 Ubuntu 终端，您应该能够下载 Qt 5.7.0，如下命令所示：

```cpp
w**get** **http://download.qt.io/official_releases/qt/5.7/5.7.0/qt-
opensource-linux-x64-5.7.0.run** 
```

为下载的安装程序提供执行权限，如下命令所示：

```cpp
chmod +x qt-opensource-linux-x64-5.7.0.run 
```

我强烈建议您安装 Qt 及其源代码。如果您喜欢用极客的方式查找 Qt 帮助，您可以直接从源代码获取帮助。

启动安装程序，如下命令所示：

```cpp
./qt-opensource-linux-x64-5.7.0.run
```

由于 Qt 使用 OpenGL，请确保在开始编写 Qt 中的第一个程序之前安装以下内容。要安装`libfontconfig1`，请运行以下命令：

```cpp
 sudo apt-get install libfontconfig1
```

要安装`mesa-common-dev`，请运行以下命令：

```cpp
sudo apt-get install mesa-common-dev  
```

在这一点上，您应该有一个可用的 Qt 设置。您可以通过在 Linux 终端中发出以下命令来验证安装：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/65eecd53-89f0-449e-8cab-d9358b5d29c6.png)

图 5.1

如果`qmake`命令无法识别，请确保导出 Qt 安装文件夹的`bin`路径，如前面的屏幕截图所示。此外，创建软链接也可能很有用。此命令如下：

```cpp
 sudo ln -s /home/jegan/Qt5.7.0/5.7/gcc_64/bin/qmake /usr/bin/qmake  
```

Qt 在您的系统上安装的路径可能与我的不同，请相应地替换 Qt 路径。

# Qt Core

Qt Core 是 Qt 支持的模块之一。该模块具有大量有用的类，例如`QObject`、`QCoreApplication`、`QDebug`等。几乎每个 Qt 应用程序都需要此模块，因此它们会被 Qt 框架隐式链接。每个 Qt 类都继承自`QObject`，而`QObject`类为 Qt 应用程序提供事件处理支持。`QObject`是支持事件处理机制的关键部分；有趣的是，即使是基于控制台的应用程序也可以在 Qt 中支持事件处理。

# 编写我们的第一个 Qt 控制台应用程序

如果您得到了类似于*图 5.1*所示的输出，那么您已经准备好动手了。让我们编写我们的第一个 Qt 应用程序，如下面的屏幕截图所示：

**![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/460071b9-e368-4f76-b890-59164cb1120a.png)**

图 5.2

在第一行中，我们从**QtCore**模块中包含了 QDebug 头文件。如果您仔细观察，`qDebug()`函数类似于 C++的`cout ostream`操作符。在 Qt 世界中，当您调试代码时，`qDebug()`函数将成为您的好朋友。`QDebug`类已经重载了 C++的`ostream`操作符，以支持 Qt 数据类型，这些类型不受 C++编译器支持。

以老派的方式，我对终端有点着迷，可以在编码时实现几乎任何功能，而不是使用一些花哨的**集成开发环境**（**IDE**）。您可能会喜欢或讨厌这种方法，这是很自然的。好处是在 Qt/C++中，您可以使用简单而强大的文本编辑器，如 Vim、Emacs、Sublime Text、Atom、Brackets 或 Neovim，学习几乎所有 Qt 项目和 qmake 的基本知识；IDE 可以让您的生活变得更轻松，但它们隐藏了许多每个严肃开发人员都必须了解的基本内容。所以这是一个权衡。我把决定权交给您，决定是使用您喜欢的纯文本编辑器、Qt Creator IDE 还是其他花哨的 IDE。我将坚持使用经过重构的 Vim 编辑器 Neovim，看起来真的很酷。*图 5.2*将给您一个关于 Neovim 编辑器外观和感觉的想法。

让我们回到正题。让我们看看如何以极客的方式在命令行中编译这段代码。在此之前，您可能想了解一下`qmake`工具。它是 Qt 的专有`make`实用程序。`qmake`实用程序不过是一个 make 工具，但它知道 Qt 特定的东西，因此它了解 moc、signals、slots 等，而典型的`make`实用程序则不知道。

以下命令应该帮助您创建一个`.pro`文件。`.pro`文件的名称将由`qmake`实用程序根据项目文件夹名称决定。`.pro`文件是 Qt Creator IDE 将相关文件组合为单个项目的方式。由于我们不打算使用 Qt Creator，我们将使用`.pro`文件创建`Makefile`，以便编译我们的 Qt 项目，就像编译普通的 C++项目一样。

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/9c35fec8-d8ec-4996-91cb-6efd36564961.png)

图 5.3

当您发出`qmake -project`命令时，qmake 将扫描当前文件夹和当前文件夹下的所有子文件夹，并在`Ex1.pro`中包含头文件和源文件。顺便说一句，`.pro`文件是一个纯文本文件，可以使用任何文本编辑器打开，如*图 5.4*所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/590b8f23-7f56-44bd-b213-1003080d7ab9.png)

图 5.4

现在是时候创建`Makefile`，以`Ex1.pro`作为输入文件。由于`Ex1.pro`文件存在于当前目录中，我们不必显式提供`Ex1.pro`作为自动生成`Makefile`的输入文件。这个想法是，一旦我们有了`.pro`文件，我们只需要从`.pro`文件生成`Makefile`，发出命令：`qmake`。这将完成创建一个完整的`Makefile`的魔术，您可以使用`make`实用程序构建您的项目，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/cd138708-cae8-4ef5-bb3e-92cc989c010f.png)

图 5.5

这是我们一直在等待的时刻，对吧？是的，让我们执行我们的第一个 Qt Hello World 程序，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/acf0f31e-0484-41dc-970f-16c32065772d.png)

图 5.6

恭喜！您已经完成了您的第一个 Qt 应用程序。在这个练习中，您学会了如何在 Ubuntu 中设置和配置 Qt，以及如何编写一个简单的 Qt 控制台应用程序，然后构建和运行它。最好的部分是您从命令行学会了所有这些。

# Qt 小部件

Qt Widgets 是一个有趣的模块，支持许多小部件，如按钮、标签、编辑、组合、列表、对话框等。`QWidget`是所有小部件的基类，而`QObject`是几乎每个 Qt 类的基类。许多编程语言称之为 UI 控件，Qt 称之为小部件。尽管 Qt 可以在许多平台上运行，但它的主要平台仍然是 Linux；小部件在 Linux 世界中很常见。

# 编写我们的第一个 Qt GUI 应用程序

我们的第一个控制台应用程序真的很酷，不是吗？让我们继续探索。这一次，让我们编写一个简单的基于 GUI 的 Hello World 程序。过程基本上是一样的，只是在`main.cpp`中有一些小的改变。请参考以下完整的代码：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/6c567df7-c593-487b-b19b-ad47dec36316.png)

图 5.7

等一下。让我解释一下为什么第 23 行和第 29 行需要`QApplication`。每个 Qt GUI 应用程序必须有一个`QApplication`实例。`QApplication`为我们的应用程序提供了命令行开关的支持，因此需要提供**参数计数**（**argc**）和**参数值**（**argv**）。基于 GUI 的应用程序是事件驱动的，因此它们必须响应 Qt 世界中的事件或者更准确地说是信号。在第 29 行，`exec`函数启动了`event`循环，这确保应用程序等待用户交互，直到用户关闭窗口。所有用户事件将被接收到`QApplication`实例的事件队列中，然后通知给它的`Child`小部件。事件队列确保队列中存放的所有事件按照它们发生的顺序处理，即**先进先出**（**FIFO**）。

如果你好奇地想要检查一下，如果你注释掉第 29 行会发生什么，应用程序仍然会编译和运行，但你可能看不到任何窗口。原因是`main`线程或`main`函数在第 25 行创建了一个`QWidget`的实例，这就是我们启动应用程序时看到的窗口。

在第 27 行，窗口实例被显示，但在没有第 29 行的情况下，`main`函数将立即终止应用程序，而不给你检查你的第一个 Qt GUI 应用程序的机会。值得一试，所以继续看看有没有第 29 行会发生什么。

让我们生成`Makefile`，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/dc59da08-63b8-4545-9836-1c38e2c4189d.png)

图 5.8

现在让我们尝试使用`make`工具编译我们的项目，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/ff336644-971b-4307-b438-2ffe7361eaf6.png)

图 5.9

有趣，对吧？我们全新的 Qt GUI 程序无法编译。你注意到致命错误了吗？没关系，让我们了解一下为什么会发生这种情况。原因是我们还没有链接 Qt Widgets 模块，因为`QApplication`类是 Qt Widgets 模块的一部分。在这种情况下，你可能会想知道为什么你的第一个 Hello World 程序可以编译而没有任何问题。在我们的第一个程序中，`QDebug`类是**QtCore**模块的一部分，它隐式地被链接，而其他模块必须显式地被链接。让我们看看如何解决这个问题：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/45cc4ead-89d9-4f78-9f2e-5dea69c94b2e.png)

图 5.10

我们需要在`Ex2.pro`文件中添加`QT += widgets`，这样`qmake`工具就能理解在创建最终可执行文件时需要链接 Qt Widgets 的**共享对象**（在 Linux 中是`.so`文件），也就是在 Windows 中被称为**动态链接库**（`.dll`文件）。一旦这个问题得到解决，我们必须运行`qmake`，这样`Makefile`就能反映出我们`Ex2.pro`文件中的新变化，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/14886507-41d6-436d-81fa-40f95117fbdc.png)

图 5.11

很好。现在让我们检查我们的第一个基于 GUI 的 Qt 应用程序。在我的系统中，应用程序输出如*图 5.12*所示；如果一切顺利，您也应该得到类似的输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/0f688d71-2a1a-4879-8c9f-84179d1e1e82.png)

图 5.12

如果我们将窗口的标题设置为`Hello Qt`，那就太好了，对吧？让我们马上做到这一点：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/37d8967f-b767-4ab1-8b00-ea6011eda546.png)

图 5.13

添加第 26 行呈现的代码，以确保在测试新更改之前使用`make`实用程序构建项目：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/0600d685-72d1-43bb-94c3-902244b571d6.png)

图 5.14

# 布局

Qt 是跨平台应用程序框架，因此支持诸如布局之类的概念，用于开发在所有平台上看起来一致的应用程序，而不管不同的屏幕分辨率如何。当我们开发基于 GUI/HMI 的 Qt 应用程序时，在一个系统中开发的应用程序不应该在具有不同屏幕大小和分辨率的另一个系统上看起来不同。这是通过布局在 Qt 框架中实现的。布局有不同的风格。这有助于开发人员通过在窗口或对话框中组织各种小部件来设计专业外观的 HMI/GUI。布局在安排其子小部件的方式上有所不同。一个布局以水平方式排列其子小部件，另一个则以垂直或网格方式排列。当窗口或对话框调整大小时，布局会调整其子小部件，以便它们不会被截断或失焦。

# 使用水平布局编写 GUI 应用程序

让我们编写一个 Qt 应用程序，在对话框中放置一些按钮。Qt 支持各种有用的布局管理器，它们充当一个无形的画布，在那里可以将许多`QWidgets`排列好，然后再将它们附加到窗口或对话框上。每个对话框或窗口只能有一个布局。每个小部件只能添加到一个布局中；但是，可以组合多个布局来设计专业的用户界面。

现在让我们开始编写代码。在这个项目中，我们将以模块化的方式编写代码，因此我们将创建三个文件，分别命名为`MyDlg.h`、`MyDlg.cpp`和`main.cpp`。

游戏计划如下：

1.  创建`QApplication`的单个实例。

1.  通过继承`QDialog`创建自定义对话框。

1.  创建三个按钮。

1.  创建一个水平框布局。

1.  将三个按钮添加到不可见的水平框布局中。

1.  将水平框布局的实例设置为我们对话框的布局。

1.  显示对话框。

1.  在`QApplication`上启动事件循环。

重要的是，我们遵循清晰的代码规范，以便我们的代码易于理解，并且可以由任何人维护。由于我们将遵循行业最佳实践，让我们在名为`MyDlg.h`的头文件中声明对话框，在名为`MyDlg.cpp`的源文件中定义对话框，并在具有`main`函数的`main.cpp`中使用`MyDlg.cpp`。每次`MyDlg.cpp`需要一个头文件时，让我们养成一个习惯，只在`MyDlg.h`中包含所有头文件；通过这样做，我们在`MyDlg.cpp`中看到的唯一头文件将是`MyDlg.h`。

顺便说一句，我有没有告诉过你 Qt 遵循驼峰命名约定？是的，我刚刚提到了。到目前为止，您可能已经注意到所有 Qt 类都以字母*Q*开头，因为 Qt 的发明者喜欢 Emacs 中的字母“Q”，他们对该字体类型如此着迷，以至于决定在 Qt 中到处使用字母 Q。

最后一个建议。如果文件名和类名相似，其他人是否会更容易找到对话框类？我可以听到你说是的。一切准备就绪！让我们开始编写我们的 Qt 应用程序。首先，参考以下屏幕截图：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/3a3adb3b-5468-4eec-9d3d-74288453c48c.png)

图 5.15

在前面的屏幕截图中，我们声明了一个名为`MyDlg`的类。它有一个布局，三个按钮和一个构造函数。现在请参考这个屏幕截图：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/144ade69-a5a6-4eb9-bfa6-8ee0f7d1e614.png)

图 5.16

正如您在前面的屏幕截图中所看到的，我们定义了`MyDlg`构造函数并实例化了布局和三个按钮。在第 27 到 29 行，我们向布局添加了三个按钮。在第 31 行，我们将布局与我们的对话框关联起来。就是这样。在下一个屏幕截图中，我们定义了我们的`main`函数，它创建了一个`QApplication`的实例：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/3de3ec35-9b38-486c-9213-c70fc7b1ce81.png)

图 5.17

接着，我们创建了我们的自定义对话框实例并显示了对话框。最后，在第 27 行，我们启动了`event`循环，以便`MyDlg`可以响应用户交互。请参考以下屏幕截图：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/b95f5be3-8fee-4e72-995d-6dc4c40cb130.png)

图 5.18

前面的屏幕截图演示了构建和执行过程，还有我们可爱的应用程序。实际上，您可以尝试使用对话框来更好地理解水平布局。首先，水平拉伸对话框，注意所有按钮的宽度增加；然后，看看是否可以减小对话框的宽度以注意到所有按钮的宽度减小。这是任何布局管理器的工作。布局管理器安排小部件并检索窗口的大小，并在所有子小部件之间平均分配高度和宽度。布局管理器不断通知所有子小部件有关任何调整大小事件。但是，由各自的子小部件决定他们是否要调整大小或忽略布局调整信号。

要检查这种行为，请尝试垂直拉伸对话框。当您增加对话框的高度时，对话框的高度应该增加，但按钮不会增加其高度。这是因为每个 Qt 小部件都有自己的首选大小策略；根据其大小策略，它们可能会响应或忽略某些布局调整信号。

如果您希望按钮在垂直方向上也能拉伸，`QPushButton`提供了一种方法来实现这一点。实际上，`QPushButton`与任何其他小部件一样都是从`QWidget`继承的。`setSizePolicy()`方法来自`QWidget`的基类，即`QPushButton`：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/ab724d3c-fea2-4b78-8e93-452c4f47a3fd.png)

图 5.19

您注意到了第 37 行吗？是的，我在`MyDlg`的构造函数中设置了窗口标题，以保持我们的`main`函数简洁和干净。

在启动应用程序之前，请确保使用`make`实用程序构建了您的项目：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/6df8dfd7-47b0-4bb6-b60d-58a35c1dd6fa.png)

图 5.20

在突出显示的部分，我们覆盖了所有按钮的默认大小策略。在第 27 行，第一个参数`QSizePolicy::Expanding`是指水平策略，第二个参数是指垂直策略。要查找`QSizePolicy`的其他可能值，请参考 Qt API 参考中随时可用的助手，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/67710ba2-8d4f-4912-a0a6-d6019fc02a68.png)

图 5.21

# 使用垂直布局编写 GUI 应用程序

在上一节中，您学会了如何使用水平框布局。在本节中，您将看到如何在应用程序中使用垂直框布局。

事实上，水平和垂直框布局只在它们如何排列小部件方面有所不同。例如，水平框布局将以从左到右的水平方式排列其子小部件，而垂直框布局将以从上到下的垂直方式排列其子小部件。

您可以从上一节中复制源代码，因为更改的性质很小。一旦您复制了代码，您的项目目录应该如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/10c56178-6d0b-460b-8c0d-4c0fa46fefd2.png)

图 5.22

让我从`MyDlg.h`头文件开始演示更改，如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/63c0b936-c4f1-4f08-b18c-09cadc8da460.png)

图 5.23

我已经用`QVBoxLayout`替换了`QHBoxLayout`；就是这样。是的，让我们继续进行与`MyDlg.cpp`相关的文件更改：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/d7c45242-efb4-4030-b8bf-c6ef897a184b.png)

图 5.24

`main.cpp`中没有要做的更改；但是，我已经展示了`main.cpp`供您参考，如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/ee30bcb7-c152-400d-bdb2-525969afb1ca.png)

图 5.25

现在我们需要做的就是自动生成`Makefile`，然后编译和运行程序，如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/7f2e631e-18c5-4b13-b952-538fbb5b7d11.png)

图 5.26

让我们执行我们全新的程序并检查输出。以下输出演示了`QVBoxLayout`以垂直的从上到下的方式排列小部件。当窗口被拉伸时，所有按钮的宽度将根据窗口的拉伸程度增加/减少：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/142bbe72-7b70-48ce-8ce4-4f5e36ba4b6f.png)

图 5.27

# 使用框布局编写 GUI 应用程序

在前面的章节中，你学会了如何使用`QHBoxLayout`和`QVBoxLayout`。实际上，这两个类都是`QBoxLayout`的便利类。在`QHBoxLayout`的情况下，`QHBoxLayout`类已经成为`QBoxLayout`的子类，并配置了`QBoxLayout::Direction`为`QBoxLayout::LeftToRight`，而`QVBoxLayout`类已经成为`QBoxLayout`的子类，并配置了`QBoxLayout::Direction`为`QBoxLayout::TopToBottom`。

除了这些值，`QBoxLayout::Direction`还支持其他各种值，如下所示：

+   `QBoxLayout::LeftToRight`：这将从左到右排列小部件

+   `QBoxLayout::RightToLeft`：这将从右到左排列小部件

+   `QBoxLayout::TopToBottom`：这将从上到下排列小部件

+   `QBoxLayout::BottomToTop`：这将从下到上排列小部件

让我们使用`QBoxLayout`和五个按钮编写一个简单的程序。

让我们从`MyDlg.h`头文件开始。我在`MyDlg`类中声明了五个按钮指针和一个`QBoxLayout`指针：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/5d082e8f-d0fd-4411-b77a-611aca0ac21f.png)

图 5.28

让我们看看我们的`MyDlg.cpp`源文件。如果你注意到截图中的第 21 行，`QBoxLayout`构造函数需要两个参数。第一个参数是你希望排列小部件的方向，第二个参数是一个可选参数，期望布局实例的父地址。

正如你可能已经猜到的那样，`this`指针指的是`MyDlg`实例指针，它恰好是布局的父指针。

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/6e2eac95-3aa9-4a94-b45a-2162642703bc.png)

图 5.29

再次，正如你可能已经猜到的那样，`main.cpp`文件不会改变，就像在下面的截图中所示的那样：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/19b90e2a-596c-463d-bad1-5ff2b362040c.png)

图 5.30

让我们编译和运行我们的程序，如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/90aef4bb-5118-4e93-b092-8d121e54bea9.png)

图 5.31

如果你注意到输出，它看起来像是一个水平框布局的输出，对吧？确实，因为我们已经将方向设置为`QBoxLayout::LeftToRight`。如果你将方向修改为，比如`QBoxLayout::RightToLeft`，那么按钮 1 将出现在右侧，按钮 2 将出现在按钮 1 的左侧，依此类推。因此，输出将如下截图所示：

+   如果方向设置为`QBoxLayout::RightToLeft`，你会看到以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/d7470732-aadf-410b-b650-a79d0a8bb76a.png)

图 5.32

+   如果方向设置为`QBoxLayout::TopToBottom`，你会看到以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/3e04081c-dd1a-4bcc-b4e3-56e3dbaadad7.png)

图 5.33

+   如果方向设置为`QBoxLayout::BottomToTop`，你会看到以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/733e373e-9738-4faf-b285-4d370eefee75.png)

图 5.34

在所有前述的情况下，按钮都是按照相同的顺序添加到布局中，从按钮 1 到按钮 5。然而，根据`QBoxLayout`构造函数中选择的方向，框布局将安排按钮，因此输出会有所不同。

# 使用网格布局编写 GUI 应用程序

网格布局允许我们以表格方式排列小部件。这很容易，就像盒式布局一样。我们只需要指定每个小部件必须添加到布局的行和列。由于行和列索引从基于零的索引开始，因此行 0 的值表示第一行，列 0 的值表示第一列。理论够了；让我们开始写一些代码。

让我们声明 10 个按钮，并将它们添加到两行和五列中。除了特定的`QGridLayout`差异外，其余的东西将与以前的练习保持一致，因此，如果您已经理解了到目前为止讨论的概念，请继续创建`MyDlg.h`，`MyDl.cpp`和`main.cpp`。

让我在以下截图中呈现`MyDlg.h`源代码：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/c4c76aa2-b3b5-4b31-afa6-395bfe97f078.png)

图 5.35

以下是`MyDlg.cpp`的代码片段：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/fe8972d9-c42f-4b37-972f-e2e8dc75951c.png)

图 5.36

`main.cpp`源文件内容将与我们以前的练习保持一致；因此，我已经跳过了`main.cpp`的代码片段。由于您熟悉构建过程，我也跳过了它。如果您忘记了这一点，只需查看以前的部分以了解构建过程。

如果您已正确输入代码，则应该获得以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/af657f1a-8876-4fc0-b9e9-ee467bd00b1c.png)

图 5.37

实际上，网格布局还有更多功能可供使用。让我们探索如何使按钮跨越多个单元格。我保证您将看到的内容更有趣。

我将修改`MyDlg.h`和`MyDlg.cpp`，并保持`main.cpp`与以前的练习相同：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/d51e3923-f36d-4920-8b16-9b36e96b0aa7.png)

图 5.38

这是我们的`MyDlg.cpp`：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/f2a8a9d8-8b10-49e5-b873-d9968a02567a.png)

图 5.39

注意第 35 到 38 行。现在让我们详细讨论`addWidget()`函数。

在第 35 行，`pLayout->addWidget(pBttn1, 0, 0, 1, 1)`代码执行以下操作：

+   前三个参数将“按钮 1”添加到网格布局的第一行和第一列

+   第四个参数`1`指示按钮 1 将仅占用一行

+   第五个参数`1`指示按钮 1 将仅占用一列

+   因此，很明显`pBttn1`应该呈现在单元格（0,0）处，它应该只占用一个网格单元

在第 36 行，`pLayout->addWidget(pBttn2, 0, 1, 1, 2)`代码执行以下操作：

+   前三个参数将“按钮 2”添加到网格布局的第一行和第二列

+   第四个参数指示“按钮 2”将占用一行

+   第五个参数指示“按钮 2”将占用两列（即第一行的第二列和第三列）

+   在底部行，“按钮 2”将呈现在单元格（0,1）处，它应该占用一行和两列

在第 37 行，`pLayout->addWidget(pBttn3, 0, 3, 2, 1)`代码执行以下操作：

+   前三个参数将“按钮 3”添加到网格布局的第一行和第四列

+   第四个参数指示“按钮 3”将占用两行（即第一行和第四列以及第二行和第四列）

+   第五个参数指示“按钮 3”将占用一列

在第 38 行，`pLayout->addWidget(pBttn4, 1, 0, 1, 3)`代码执行以下操作：

+   前三个参数将“按钮 4”添加到网格布局的第二行和第一列

+   第四个参数指示“按钮 4”将占用一行

+   第五个参数指示“按钮 4”将占用三列（即第二行的第一列，然后是第二列和第三列）

检查程序的输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/1872682b-e251-4ff5-adbd-28fd1a5ac2db.png)

图 5.40

# 信号和槽

信号和槽是 Qt 框架的一个重要部分。到目前为止，我们编写了一些简单但有趣的 Qt 应用程序，但我们还没有处理事件。现在是时候了解如何在我们的应用程序中支持事件了。

让我们编写一个简单的应用程序，只有一个按钮。当点击按钮时，检查是否可以在控制台上打印一些内容。

`MyDlg.h`头文件演示了如何声明`MyDlg`类：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/7d50a778-9a10-43fa-b724-d9afd6315c10.png)

图 5.41

以下截图演示了如何定义`MyDlg`构造函数以向对话框窗口添加一个按钮：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/6ba01a0d-7362-4ba9-a7aa-d3f8ead60b96.png)

图 5.42

`main.cpp`如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/ebeea2e4-cdea-45cb-b3b0-79f67fef12f4.png)

图 5.43

让我们构建并运行我们的程序，然后添加对信号和槽的支持。如果你正确地按照说明操作，你的输出应该类似于以下截图：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/0e296050-9288-4558-b0b5-4fa80a5b8834.png)

图 5.44

如果你点击按钮，你会注意到什么都没有发生，因为我们还没有在我们的应用程序中添加对信号和槽的支持。好吧，是时候揭示一个秘密指令，这将帮助你使按钮响应按钮点击信号。等一下，是时候获取更多信息了。别担心，这和 Qt 有关。

Qt 信号只是事件，槽函数是事件处理程序函数。有趣的是，信号和槽都是普通的 C++函数；只有当它们被标记为信号或槽时，Qt 框架才能理解它们的目的并提供必要的样板代码。

Qt 中的每个小部件都支持一个或多个信号，也可以选择支持一个或多个槽。因此，在我们编写任何进一步的代码之前，让我们探索一下`QPushButton`支持哪些信号。

让我们使用 Qt 助手进行 API 参考：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/9f329dcb-c999-4440-b838-6cf1ac7df528.png)

图 5.45

如果你观察前面的截图，它有一个似乎涵盖了公共槽的内容部分，但我们没有看到任何列出的信号。这是很多信息。如果内容部分没有列出信号，`QPushButton`就不会直接支持信号。然而，也许它的基类，即`QAbstractButton`，会支持一些信号。`QPushButton`类部分提供了大量有用的信息，比如头文件名，必须链接到应用程序的 Qt 模块，即必须添加到`.pro`文件的 qmake 条目等。它还提到了`QPushButton`的基类。如果你继续向下滚动，你的 Qt 助手窗口应该看起来像这样：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/c26ffb57-4b25-428e-b3b7-c28a23363a7a.png)

图 5.46

如果你观察到`Additional Inherited Members`下面的突出部分，显然 Qt 助手暗示`QPushButton`已经从`QAbstractButton`继承了四个信号。因此，我们需要探索`QAbstractButton`支持的信号，以便在`QPushButton`中支持这些信号。

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/b59281a2-2562-49bf-8baf-4518b9ed3768.png)

图 5.47

通过 Qt 助手的帮助，如前面的截图所示，很明显`QAbstractButton`类支持四个信号，这些信号也适用于`QPushButton`，因为`QPushButton`是`QAbstractButton`的子类。因此，让我们在这个练习中使用`clicked()`信号。

我们需要在`MyDlg.h`和`MyDlg.cpp`中进行一些小的更改，以便使用`clicked()`信号。因此，我已经在以下截图中呈现了这两个文件，并突出显示了更改：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/88feed21-ddd1-416c-ae24-b77ef4aff1ae.png)

图 5.48

正如你所知，`QDebug`类用于调试目的。它为 Qt 应用程序提供了类似于`cout`的功能，但实际上并不需要用于信号和槽。我们在这里使用它们只是为了调试目的。在*图 5.48*中，第 34 行，`MyDlg::onButtonClicked()`是我们打算用作事件处理程序函数的槽函数，必须在按钮点击时调用。

以下的屏幕截图应该让你了解在`MyDlg.cpp`中需要进行哪些更改以支持信号和槽：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/d58b2aa7-c768-4f29-b336-f198fbc67422.png)

图 5.49

如果你观察前面屏幕截图中的第 40 到 42 行，`MyDlg::onButtonClicked()`方法是一个槽函数，必须在按钮被点击时调用。但是除非按钮的`clicked()`信号映射到`MyDlg::onButtonClicked()`槽，否则 Qt 框架不会知道它必须在按钮被点击时调用`MyDlg::onButtonClicked()`。因此，在 32 到 37 行，我们将按钮信号`clicked()`与`MyDlg`实例的`onButtonClicked()`槽函数连接起来。connect 函数是从`QDialog`继承的。这又从它的最终基类`QObject`继承了这个函数。

关键是，每个希望参与信号和槽通信的类都必须是`QObject`或其子类。`QObject`提供了相当多的信号和槽支持，`QObject`是`QtCore`模块的一部分。令人惊奇的是，Qt 框架甚至为命令行应用程序提供了信号和槽支持。这就是为什么信号和槽支持内置到最终基类`QObject`中的原因，它是`QtCore`模块的一部分。

好的，让我们构建和运行我们的程序，看看信号在我们的应用程序中是否起作用：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/f2941fec-a600-491b-a3a3-89a453ec7f2f.png)

图 5.50

有趣的是，我们并没有得到编译错误，但当我们点击按钮时，突出显示的警告消息会自动出现。这是 Qt 框架的提示，表明我们错过了一个重要的程序，这是使信号和槽工作所必需的。

让我们回顾一下我们在头文件和源文件中自动生成`Makefile`的过程：

1.  `qmake -project`命令确保当前文件夹中存在的所有头文件和源文件都包含在`.pro`文件中。

1.  `qmake`命令会读取当前文件夹中的`.pro`文件，并为我们的项目生成`Makefile`。

1.  `make`命令将调用`make`实用程序。然后在当前目录中执行`Makefile`，并根据`Makefile`中定义的 make 规则构建我们的项目。

在第 1 步中，`qmake`实用程序扫描我们所有的自定义头文件，并检查它们是否需要信号和槽支持。任何具有`Q_OBJECT`宏的头文件都会提示`qmake`实用程序需要信号和槽支持。因此，我们必须在我们的`MyDlg.h`头文件中使用`Q_OBJECT`宏：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/48974fec-be32-4a9a-9619-cd2cf91f5f19.png)

图 5.51

一旦在头文件中进行了推荐的更改，我们需要确保发出`qmake`命令。现在`qmake`实用程序将打开`Ex8.pro`文件，获取我们的项目头文件和源文件。当`qmake`解析`MyDlg.h`并找到`Q_OBJECT`宏时，它将了解到我们的`MyDlg.h`需要信号和槽，然后它将确保在`MyDlg.h`上调用 moc 编译器，以便在一个名为`moc_MyDlg.cpp`的文件中自动生成样板代码。然后，它将继续添加必要的规则到`Makefile`中，以便自动生成的`moc_MyDlg.cpp`文件与其他源文件一起构建。

现在你知道了 Qt 信号和槽的秘密，继续尝试这个过程，并检查你的按钮点击是否打印了“按钮点击...”的消息。我已经根据建议对我们的项目进行了构建。在下面的截图中，我已经突出显示了幕后发生的有趣的事情；这些是在命令行中工作与使用花哨的 IDE 时会得到的一些优势：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/70c69c4b-3796-4773-bdec-395bf62d9a83.png)

图 5.52

现在是时候测试我们支持信号和槽的酷而简单的应用程序的输出了。输出如下截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/b3c2b725-57d1-4e46-814a-0301e48cd9d6.png)

图 5.53

恭喜！你可以为自己鼓掌。你已经学会了在 Qt 中做一些很酷的东西。

# 在 Qt 应用程序中使用堆叠布局

由于你已经了解了信号和槽，所以在这一部分，让我们探讨如何在具有多个窗口的应用程序中使用堆叠布局；每个窗口可以是**QWidget**或**QDialog**。每个页面可能有自己的子窗口部件。我们即将开发的应用程序将演示堆叠布局的使用以及如何在堆叠布局中从一个窗口导航到另一个窗口。

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/48d99ea8-fb90-4158-9a92-e1fb06f4a6aa.png)

图 5.54

这个应用程序将需要相当多的代码，因此很重要的是我们确保我们的代码结构良好，以满足结构和功能质量，尽量避免代码异味。

让我们创建四个可以堆叠在堆叠布局中的小部件/窗口，其中每个页面可以作为一个单独的类分割成两个文件：`HBoxDlg.h`和`HBoxDlg.cpp`等等。

让我们从`HBoxDlg.h`开始。由于你熟悉布局，所以在这个练习中，我们将使用一个布局创建每个对话框，这样在子窗口之间导航时，你可以区分页面。否则，堆叠布局和其他布局之间将没有连接。

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/648725bf-2273-4c88-85a2-edf4bad4aeed.png)

图 5.55

以下代码片段来自`HBoxDlg.cpp`文件：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/82c5a5d3-a595-431c-815f-ca283191e6aa.png)

图 5.56

同样，让我们按照以下方式编写`VBoxDlg.h`：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/92f5c298-a8c2-41ee-8069-922eed5ef25c.png)

图 5.57

让我们按照以下方式创建第三个对话框`BoxDlg.h`，使用框布局：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/366c132e-4488-4695-b5c1-b171ce04c694.png)

图 5.58

相应的`BoxDlg.cpp`源文件如下：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/3add6abe-d750-47fd-9505-3e32e4404528.png)

图 5.59

我们想要堆叠的第四个对话框是`GridDlg`，所以让我们看看`GridDlg.h`可以如何编写，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/f82f99e2-26a0-40a9-b490-fa7ea0f81cd3.png)

图 5.60

相应的`GridDlg.cpp`将如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/757214dd-790a-4858-94d6-15d2684afa1b.png)

图 5.61

很好，我们已经创建了四个可以堆叠在`MainDlg`中的小部件。`MainDlg`将使用`QStackedLayout`，所以这个练习的关键是理解堆叠布局的工作原理。

让我们看看`MainDlg.h`应该如何编写：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/fa25ec43-d0c3-4493-8c97-57857582caa7.png)

图 5.62

在`MainDlg`中，我们声明了三个槽函数，每个按钮一个，以支持四个窗口之间的导航逻辑。堆叠布局类似于选项卡小部件，只是选项卡小部件将提供自己的视觉方式来在选项卡之间切换，而在堆叠布局的情况下，由我们提供切换逻辑。

`MainDlg.cpp`将如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/1aa26b3a-b763-434b-8644-81e84a7e4422.png)图 5.63

你可以选择一个框布局来容纳这三个按钮，因为我们希望按钮对齐到右边。然而，为了确保额外的空间被一些看不见的粘合剂占用，我们在第 44 行添加了一个拉伸项。

在 30 到 33 行之间，我们已经将所有四个子窗口添加到堆叠布局中，以便窗口可以逐个显示。`HBox`对话框添加到索引 0，`VBox`对话框添加到索引 1，依此类推。

53 到 58 行展示了如何将上一个按钮的点击信号与其对应的`MainDlg::onPrevPage()`槽函数连接起来。类似的连接必须为下一个和退出按钮配置：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/f3016f3b-3565-444f-94e7-060d9d85adcd.png)

图 5.64

78 行的`if`条件确保只有在我们处于第二个或更后续的子窗口时才发生切换逻辑。由于水平对话框位于索引 0，所以在当前窗口是水平对话框的情况下，我们无法导航到上一个窗口。类似的验证也适用于在 85 行切换到下一个子窗口。

堆叠布局支持`setCurrentIndex()`方法以切换到特定的索引位置；或者，如果在您的情况下更有效，也可以尝试`setCurrentWidget()`方法。

`main.cpp`看起来简短而简单，如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/d25aba55-f0d3-4f49-80c4-b5ba45675cda.png)

图 5.65

我们`main`函数的最好部分是，无论应用程序逻辑的复杂性如何，`main`函数都没有任何业务逻辑。这使得我们的代码清晰易懂，易于维护。

# 编写一个简单的数学应用程序，结合多个布局

在本节中，让我们探讨如何编写一个简单的数学应用程序。作为这个练习的一部分，我们将使用`QLineEdit`和`QLabel`小部件以及`QFormLayout`。我们需要设计一个 UI，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/82d57bed-0031-4138-a002-611c3d9f7934.png)

图 5.66

`QLabel`是一个通常用于静态文本的小部件，`QLineEdit`允许用户提供单行输入。如前面的屏幕截图所示，我们将使用`QVBoxLayout`作为主要布局，以便以垂直方式排列`QFormLayout`和`QBoxLayout`。`QFormLayout`在需要创建一个表单的情况下非常方便，在左侧将有一个标题，右侧将有一些小部件。`QGridLayout`也可能适用，但在这种情况下使用`QFormLayout`更容易。

在这个练习中，我们将创建三个文件，分别是`MyDlg.h`、`MyDlg.cpp`和`main.cpp`。让我们从`MyDlg.h`源代码开始，然后再转到其他文件：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/d55649f7-978f-487a-8ca6-7358f1977612.png)

图 5.67

在上图中，声明了三种布局。垂直框布局用作主要布局，而框布局用于以右对齐的方式排列按钮。表单布局用于添加标签，即行编辑小部件。这个练习还将帮助您了解如何结合多个布局来设计专业的 HMI。

Qt 没有记录在单个窗口中可以组合的布局数量的限制。然而，如果可能的话，考虑使用最少的布局来设计 HMI 是一个好主意，特别是如果您正在努力开发一个内存占用小的应用程序。否则，在您的应用程序中使用多个布局也没有坏处。

在下面的屏幕截图中，您将了解到`MyDlg.cpp`源文件应该如何实现。在`MyDlg`构造函数中，所有按钮都被实例化并在框布局中以右对齐的方式布局。表单布局用于以类似网格的方式容纳`QLineEdit`小部件和它们对应的`QLabel`小部件。`QLineEdit`小部件通常用于提供单行输入；在这个特定的练习中，它们帮助我们提供必须根据用户的选择进行加法、减法等操作的数字输入。

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/6a4b7279-2794-43b7-ab4a-d41d7e5445a9.png)

图 5.68

我们`main.cpp`源文件的最好部分是，它基本上保持不变，无论我们的应用程序的复杂性如何。在这个练习中，我想告诉你一个关于`MyDlg`的秘密。你有没有注意到`MyDlg`的构造函数是在堆栈中实例化的，而不是在堆中？这个想法是，当`main()`函数退出时，`main`函数使用的堆栈会被解开，最终释放堆栈中存在的所有堆栈变量。当`MyDlg`被释放时，会导致调用`MyDlg`的析构函数。在 Qt 框架中，每个窗口部件构造函数都接受一个可选的父窗口部件指针，这个指针被顶层窗口的析构函数用来释放它的子窗口部件。有趣的是，Qt 维护一个类似树的数据结构来管理所有子窗口部件的内存。因此，如果一切顺利，Qt 框架将负责自动释放所有子窗口部件的内存位置。

这有助于 Qt 开发人员专注于应用程序方面，而 Qt 框架将负责内存管理。

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/5dce506b-58e0-4325-99b9-b4f43fbff988.png)

图 5.69

你是不是很兴奋地想要检查我们新应用程序的输出？如果你构建并执行应用程序，那么你应该得到类似以下截图的输出。当然，我们还没有添加信号和槽支持，但设计 GUI 满意后再转向事件处理是个好主意：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/9f4f2619-07f8-4a7b-957e-3a0efdeea9a4.png)

图 5.70

如果你仔细观察，尽管按钮在`QBoxLayout`上是从右到左排列的，但按钮并没有对齐到右边。这种行为的原因是当窗口被拉伸时，框布局似乎已经将额外的水平空间分配给了所有的按钮。因此，让我们在框布局的最左边位置添加一个拉伸项，这样拉伸就会占据所有额外的空间，让按钮没有空间可以扩展。这样就可以得到右对齐的效果。添加拉伸后，代码将如下截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/f18dca21-9c3a-456a-b302-61e669805250.png)

图 5.71

继续检查你的输出是否与以下截图一样。有时，作为开发人员，我们会急于看到输出而忘记编译我们的更改，所以确保项目再次构建。如果你没有看到输出中的任何变化，不用担心；只需尝试水平拉伸窗口，你应该会看到右对齐的效果，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/ddf4ea30-7cc3-4d86-ad69-0be08675e87b.png)

图 5.72

现在，既然我们有了一个看起来不错的应用程序，让我们添加信号和槽支持来响应按钮点击。我们不要急于现在包括加法和减法功能。我们将使用一些`qDebug()`打印语句来检查信号和槽是否连接正确，然后逐渐用实际功能替换它们。

如果你还记得之前的信号和槽练习，任何有兴趣支持信号和槽的 Qt 窗口都必须是`QObject`，并且应该在`MyDlg.h`头文件中包含`Q_OBJECT`宏，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/82424603-a5f1-40e6-b887-5a0de59c643a.png)

图 5.73

从第 41 行到 45 行开始，私有部分声明了四个槽方法。槽函数是常规的 C++函数，可以像其他 C++函数一样直接调用。然而，在这种情况下，槽函数只打算与`MyDlg`一起调用。因此它们被声明为私有函数，但如果你认为其他人可能会发现连接到你的公共槽有用，它们也可以被设为公共的。

很好，如果您已经走到这一步，这意味着您已经理解了到目前为止讨论的内容。好吧，让我们继续并在`MyDlg.cpp`中实现槽函数的定义，然后将“clicked（）”按钮的信号连接到相应的槽函数：

！[](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/369bc1df-bea7-42fb-b1e6-31a158593ea3.png)

图 5.74

现在是将信号连接到它们各自的槽的时间。正如您可能已经猜到的那样，我们需要在`MyDlg`构造函数中使用`connect`函数，如下面的屏幕截图所示，以将按钮点击传递到相应的槽中：

！[](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/08482ed2-2a04-4e2c-aa8e-0c7250b6891c.png)

图 5.75

我们已经准备好了。是的，现在是展示时间。由于我们已经处理了大部分事情，让我们编译并检查我们小小的 Qt 应用程序的输出：

！[](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/8ccc8ebe-6f19-4eab-8e26-60c76d2e28cb.png)

图 5.76

哎呀！我们遇到了一些链接器错误。这个问题的根本原因是我们在启用应用程序中的信号和槽支持后忘记调用`qmake`。别担心，让我们调用`qmake`和`make`，然后运行我们的应用程序：

！[](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/4fd3db0f-e95a-46f0-8683-b88d34daa45b.png)

图 5.77

太好了，我们已经解决了问题。这次制作工具似乎没有发出任何声音，我们能够启动应用程序。让我们检查信号和槽是否按预期工作。为此，请单击“添加”按钮，看看会发生什么：

！[](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/b62dd11c-18ca-416c-ad2c-cbdbcb6fbf0a.png)

图 5.78

哇！当我们点击“添加”按钮时，“qDebug（）”控制台消息确认“MyDlg :: onAddButtonClicked（）”槽被调用。如果您想要检查其他按钮的槽，请继续尝试点击其他按钮。

我们的应用程序将不完整，没有业务逻辑。因此，让我们将业务逻辑添加到“MyDlg :: onAddButtonClicked（）”槽函数中，以执行添加并显示结果。一旦您学会了如何集成添加的业务逻辑，您可以遵循相同的方法并实现其余的槽函数：

！[](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/31e93df6-fc6e-4c0f-b5b6-2d334173592e.png)

图 5.79

在“MyDlg :: onAddButtonClicked（）”函数中，业务逻辑已经集成。在第 82 行和第 83 行，我们试图提取用户在`QLineEdit`小部件中键入的值。`QLineEdit`中的“text（）”函数返回`QString`。 `QString`对象提供了“toInt（）”，非常方便地提取由`QString`表示的整数值。一旦将值添加并存储在结果变量中，我们需要将结果整数值转换回`QString`，如第 86 行所示，以便将结果输入到`QLineEdit`中，如第 88 行所示。

类似地，您可以继续并集成其他数学运算的业务逻辑。一旦您彻底测试了应用程序，就可以删除“qDebug（）”控制台的输出。我们添加了“qDebug（）”消息以进行调试，因此现在可以清理它们了。

# 总结

在本章中，您学会了使用 Qt 应用程序框架开发 C ++ GUI 应用程序。以下是要点。

+   您学会了在 Linux 中安装 Qt 和所需的工具。

+   您学会了使用 Qt 框架编写简单的基于控制台的应用程序。

+   您学会了使用 Qt 框架编写简单的基于 GUI 的应用程序。

+   您学会了使用 Qt 信号和槽机制进行事件处理，以及元对象编译器如何帮助我们生成信号和槽所需的关键样板代码。

+   您学会了在应用程序开发中使用各种 Qt 布局来开发吸引人的 HMI，在许多 Qt 支持的平台上看起来很棒。

+   您学会了将多个布局组合到单个 HMI 中，以开发专业的 HMI。

+   您学会了许多 Qt 小部件，以及它们如何帮助您开发令人印象深刻的 HMI。

+   总的来说，您学会了使用 Qt 应用程序框架开发跨平台 GUI 应用程序。

在下一章中，您将学习在 C ++ 中进行多线程编程和 IPC。
