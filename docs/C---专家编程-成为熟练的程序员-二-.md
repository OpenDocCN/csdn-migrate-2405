# C++ 专家编程：成为熟练的程序员（二）

> 原文：[`annas-archive.org/md5/f9404739e16292672f830e964de1c2e4`](https://annas-archive.org/md5/f9404739e16292672f830e964de1c2e4)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：理解和设计模板

模板是 C++的一个独特特性，通过它，函数和类能够支持通用数据类型——换句话说，我们可以实现一个与特定数据类型无关的函数或类；例如，客户可能会请求一个`max()`函数来处理不同的数据类型。我们可以通过模板来实现一个`max()`，并将数据类型作为参数传递，而不是通过函数重载来实现和维护许多类似的函数。此外，模板可以与多重继承和运算符重载一起工作，以在 C++中创建强大的通用数据结构和算法，如**标准模板库**（**STL**）。此外，模板还可以应用于编译时计算、编译时和运行时代码优化等。

在本章中，我们将学习函数和类模板的语法，它们的实例化和特化。然后，我们将介绍*可变参数*模板及其应用。接下来，我们将讨论模板参数及用于实例化它们的相应参数。之后，我们将学习如何实现类型*特性*，以及如何利用这种类型的信息来优化算法。最后，我们将介绍在程序执行时可以使用的加速技术，包括编译时计算、编译时代码优化和静态多态性。

本章将涵盖以下主题：

+   探索函数和类模板

+   理解可变参数模板

+   理解模板参数和参数

+   什么是特性？

+   模板元编程及其应用

# 技术要求

本章的代码可以在本书的 GitHub 存储库中找到：[`github.com/PacktPublishing/Expert-CPP`](https://github.com/PacktPublishing/Expert-CPP)。

# 探索函数和类模板

我们将从介绍函数模板的语法及其实例化、推导和特化开始这一部分。然后，我们将转向类模板，并查看类似的概念和示例。

# 动机

到目前为止，当我们定义函数或类时，我们必须提供输入、输出和中间参数。例如，假设我们有一个函数来执行两个 int 类型整数的加法。我们如何扩展它，以便处理所有其他基本数据类型，如 float、double、char 等？一种方法是使用函数重载，手动复制、粘贴和稍微修改每个函数。另一种方法是定义一个宏来执行加法操作。这两种方法都有各自的副作用。

此外，如果我们修复一个 bug 或为一个类型添加一个新功能，这个更新需要在以后的所有其他重载函数和类中完成吗？除了使用这种愚蠢的复制-粘贴-替换方法外，我们有没有更好的方法来处理这种情况？

事实上，这是任何计算机语言都可能面临的一个通用问题。1973 年由通用函数式编程**元语言**（**ML**）首创，ML 允许编写通用函数或类型，这些函数或类型在使用时只在它们操作的类型集合上有所不同，从而减少了重复。后来受到**特许人寿保险师**（**CLU**）提供的参数化模块和 Ada 提供的泛型的启发，C++采用了模板概念，允许函数和类使用通用类型。换句话说，它允许函数或类在不需要重写的情况下处理不同的数据类型。

实际上，从抽象的角度来看，C++函数或类模板（如饼干模具）用作创建其他类似函数或类的模式。这背后的基本思想是创建一个函数或类模板，而无需指定某些或所有变量的确切类型。相反，我们使用占位符类型来定义函数或类模板，称为**模板类型参数**。一旦我们有了函数或类模板，我们可以通过在其他编译器中实现的算法自动生成函数或类。

C++中有三种模板：*函数*模板、*类*模板和*可变参数*模板。我们接下来将看看这些。

# 函数模板

函数模板定义了如何生成一组函数。这里的一组函数指的是行为类似的一组函数。如下图所示，这包括两个阶段：

+   创建函数模板；即编写它的规则。

+   模板实例化；即用于从模板生成函数的规则：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/4ba0b575-0a51-403e-8a1f-1f3b03c37817.png)

函数模板格式

在上图的**part I**中，我们讨论了用于创建通用类型函数模板的格式，但是关于**专门化模板**，我们也称之为**主模板**。然后，在**part II**中，我们介绍了从模板生成函数的三种方式。最后，专门化和重载子节告诉我们如何为特殊类型自定义**主模板**（通过改变其行为）。

# 语法

有两种定义函数模板的方式，如下面的代码所示：

```cpp
template <typename identifier_1, …, typename identifier_n > 
function_declaration;

template <class identifier_1,…, class identifier_n> 
function_declaration;
```

在这里，`identifier_i (i=1,…,n)`是类型或类参数，`function_declaration`声明了函数体部分。在前两个声明中唯一的区别是关键字 - 一个使用`class`，而另一个使用`typename`，但两者的含义和行为都是相同的。由于类型（如基本类型 - int、float、double、enum、struct、union 等）不是类，因此引入了`typename`关键字方法以避免混淆。

例如，经典的查找最大值函数模板`app_max()`可以声明如下：

```cpp
template <class T>
T app_max (T a, T b) {
  return (a>b?a:b);   //note: we use ((a)>(b) ? (a):(b)) in macros  
}                     //it is safe to replace (a) by a, and (b) by b now
```

只要存在可复制构造的类型，其中 *a>b *表达式有效，这个函数模板就可以适用于许多数据类型或类。对于用户定义的类，这意味着必须定义大于号（>）。

请注意，函数模板和模板函数是不同的东西。函数模板指的是一种模板，用于由编译器生成函数，因此编译器不会为其生成任何目标代码。另一方面，模板函数意味着来自函数模板的实例。由于它是一个函数，编译器会生成相应的目标代码。然而，最新的 C++标准文档建议避免使用不精确的术语模板函数。因此，在本书中我们将使用函数模板和成员函数模板。

# 实例化

由于我们可能有无限多种类型和类，函数模板的概念不仅节省了源代码文件中的空间，而且使代码更易于阅读和维护。然而，与为应用程序中使用的不同数据类型编写单独的函数或类相比，它并不会产生更小的目标代码。例如，考虑使用`app_max()`的 float 和 int 版本的程序：

```cpp
cout << app_max<int>(3,5) << endl;
cout << app_max<float>(3.0f,5.0f) << endl;
```

编译器将在目标文件中生成两个新函数，如下所示：

```cpp
int app_max<int> ( int a, int b) {
  return (a>b?a:b);
}

float app_max<float> (float a, float b) {
  return (a>b?a:b);
}
```

从函数模板声明中创建函数的新定义的过程称为**模板实例化**。在这个实例化过程中，编译器确定模板参数，并根据应用程序的需求生成实际的功能代码。通常有三种形式：*显式实例化*，*隐式实例化*和*模板推断*。在接下来的部分，让我们讨论每种形式。

# 显式实例化

许多非常有用的 C++函数模板可以在不使用显式实例化的情况下编写和使用，但我们将在这里描述它们，只是让您知道如果您需要它们，它们确实存在。首先，让我们看一下 C++11 之前显式实例化的语法。有两种形式，如下所示：

```cpp
template return-type 
function_name < template_argument_list > ( function_parameter-list ) ;

template return-type 
function_name ( function_parameter_list ) ;
```

显式实例化定义，也称为**指令**，强制为特定类型的函数模板实例化，无论将来将调用哪个模板函数。显式实例化的位置可以在函数模板的定义之后的任何位置，并且在源代码中对于给定的参数列表只允许出现一次。

自 C++11 以来，显式实例化指令的语法如下。在这里，我们可以看到在`template`关键字之前添加了`extern`关键字：

```cpp
extern template return-type 
function_name < template_argument_list > (function_parameter_list ); 
(since C++11)

extern template return-type 
function_name ( function_parameter_list ); (since C++11)
```

使用`extern`关键字可以防止该函数模板的隐式实例化（有关更多详细信息，请参阅下一节）。

关于之前声明的`app_max()`函数模板，可以使用以下代码进行显式实例化：

```cpp
template double app_max<double>(double, double); 
template int app_max<int>(int, int);
```

也可以使用以下代码进行显式实例化：

```cpp
extern template double app_max<double>(double, double);//(since c++11)
extren template int app_max<int>(int, int);            //(since c++11)
```

这也可以以模板参数推断的方式完成：

```cpp
template double f(double, double);
template int f(int, int);
```

最后，这也可以这样做：

```cpp
extern template double f(double, double); //(since c++11)
extern template int f(int, int);          //(since c++11)
```

此外，显式实例化还有一些其他规则。如果您想了解更多，请参考*进一步阅读*部分[10]以获取更多详细信息。

# 隐式实例化

当调用函数时，该函数的定义需要存在。如果这个函数没有被显式实例化，将会采用隐式实例化的方法，其中模板参数的列表需要被显式提供或从上下文中推断出。以下程序的 A 部分提供了`app_max()`的隐式实例化的一些示例。

```cpp
//ch4_2_func_template_implicit_inst.cpp
#include <iostream>
template <class T>
T app_max (T a, T b) { return (a>b?a:b); }
using namespace std;
int main(){
 //Part A: implicit instantiation in an explicit way 
 cout << app_max<int>(5, 8) << endl;       //line A 
 cout << app_max<float>(5.0, 8.0) << endl; //line B
 cout << app_max<int>(5.0, 8) << endl;     //Line C
 cout << app_max<double>(5.0, 8) << endl;  //Line D

 //Part B: implicit instantiation in an argument deduction way
 cout << app_max(5, 8) << endl;           //line E 
 cout << app_max(5.0f, 8.0f) << endl;     //line F 

 //Part C: implicit instantiation in a confuse way
 //cout<<app_max(5, 8.0)<<endl;          //line G  
 return 0;
}
```

行`A`，`B`，`C`和`D`的隐式实例化分别是`int app_max<int>(int,int)`，`float app_max<float>(float, float>)`，`int app_max<int>(int,int)`和`double app_max<double>(double, double)`。

# 推断

当调用模板函数时，编译器首先需要确定模板参数，即使没有指定每个模板参数。大多数情况下，它会从函数参数中推断出缺失的模板参数。例如，在上一个函数的 B 部分中，当在行`E`中调用`app_max(5, 8)`时，编译器会推断模板参数为 int 类型，即`(int app_max<int>(int,int))`，因为输入参数`5`和`8`都是整数。同样，行`F`将被推断为浮点类型，即`float app_max<float>(float,float)`。

然而，如果在实例化过程中出现混淆会发生什么？例如，在上一个程序中对`G`的注释行中，根据编译器的不同，可能会调用`app_max<double>(double, double)`，`app_max<int>(int, int)`，或者只是给出一个编译错误消息。帮助编译器推断类型的最佳方法是通过显式给出模板参数来调用函数模板。在这种情况下，如果我们调用`app_max<double>(5, 8.0)`，任何混淆都将得到解决。

从编译器的角度来看，有几种方法可以进行模板参数推导——从函数调用中推导，从类型中推导，自动类型推导和非推导上下文[4]。然而，从程序员的角度来看，你不应该编写花哨的代码来滥用函数模板推导的概念，以混淆其他程序员，比如前面示例中的 G 行。

# 专门化和重载

专门化允许我们为给定的模板参数集自定义模板代码。它允许我们为特定的模板参数定义特殊行为。专门化仍然是一个模板；你仍然需要一个实例化来获得真正的代码（由编译器自动完成）。

在下面的示例代码中，主要函数模板`T app_max(T a, T b)`将根据`operator *a>b,*`的返回值返回`a`或`b`，但我们可以将其专门化为`T = std::string`，这样我们只比较`a`和`b`的第 0 个元素；也就是说，`a[0] >b[0]`：

```cpp
//ch4_3_func_template_specialization.cpp
#include <iostream>
#include <string>

//Part A: define a  primary template
template <class T> T app_max (T a, T b) { return (a>b?a:b); }

//Part B: explicit specialization for T=std::string, 
template <> std::string app_max<std::string> (std::string a, std::string b){ 
    return (a[0]>b[0]?a:b);
}

//part C: test function
using namespace std; 
void main(){
 string a = "abc", b="efg";
 cout << app_max(5, 6) << endl; //line A 
 cout << app_max(a, b) << endl; //line B 

 //question: what's the output if un-comment lines C and D?
 //char *x = "abc", *y="efg";     //Line C
 //cout << app_max(x, y) << endl; //line D
}
```

前面的代码首先定义了一个主模板，然后将`T`显式专门化为`std::string`；也就是说，我们只关心`a`和`b`的`a[0]`和`b[0]`（`app_max()`的行为被专门化）。在测试函数中，`行 A`调用`app_max<int>(int,int)`，`行 B`调用专门化版本，因为在推导时没有歧义。如果我们取消注释`C`和`D`行，将调用主函数模板`char* app_max<char > (char*, char*)`，因为`char*`和`std::string`是不同的数据类型。

从某种程度上讲，专门化与函数重载解析有些冲突：编译器需要一种算法来解决这种冲突，找到模板和重载函数中的正确匹配。选择正确函数的算法包括以下两个步骤：

1.  在常规函数和非专门化模板之间进行重载解析。

1.  如果选择了非专门化的模板，请检查是否存在一个更适合它的专门化。

例如，在下面的代码块中，我们声明了主要（`行 0`）和专门化的函数模板（`行 1-4`），以及`f()`的重载函数（`行 5-6`）：

```cpp
template<typename T1, typename T2> void f( T1, T2 );// line 0
template<typename T> void f( T );                   // line 1
template<typename T> void f( T, T );                // line 2
template<typename T> void f( int, T* );             // line 3
template<> void f<int>( int );                      // line 4
void f( int, double );                              // line 5
void f( int );                                      // line 6
```

`f()`将在下面的代码块中被多次调用。根据前面的两步规则，我们可以在注释中显示选择了哪个函数。我们将在此之后解释这样做的原因：

```cpp
int i=0; 
double d=0; 
float x=0;
complex<double> c;
f(i);      //line A: choose f() defined in line 6
f(i,d);    //line B: choose f() defined in line 5
f<int>(i); //line C: choose f() defined in line 4
f(c);      //line D: choose f() defined in line 1
f(i,i);    //line E: choose f() defined in line 2
f(i,x);    //line F: choose f() defined in line 0
f(i, &d);  //line G: choose f() defined in line 3

```

对于`行 A`和`行 B`，由于`行 5`和`行 6`中定义的`f()`是常规函数，它们具有最高的优先级被选择，所以`f(i)`和`f(i,d)`将分别选择它们。对于`行 C`，因为存在专门化的模板，从`行 4`生成的`f()`比从`行 1`生成的更匹配。对于`行 D`，由于`c`是`complex<double>`类型，只有在`行 1`中定义的主要函数模板与之匹配。`行 E`将选择由`行 2`创建的`f()`，因为两个输入变量是相同类型。最后，`行 F`和`行 G`将分别选择`行 0`和`行 3`中的模板创建的函数。

在了解了函数模板之后，我们现在将转向类模板。

# 类模板

类模板定义了一组类，并且通常用于实现容器。例如，C++标准库包含许多类模板，如`std::vector`、`std::map`、`std::deque`等。在 OpenCV 中，`cv::Mat`是一个非常强大的类模板，它可以处理具有内置数据类型的 1D、2D 和 3D 矩阵或图像，如`int8_t`、`uint8_t`、`int16_t`、`uint16_t`、`int32_t`、`uint32_t`、`float`、`double`等。

与函数模板类似，如下图所示，类模板的概念包含模板创建语法、其专门化以及其隐式和显式实例化：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/2f784eca-cdaf-490e-9514-942bf80883ac.png)

在前面的图表的**part I**中，使用特定的语法格式，我们可以为通用类型创建一个类模板，也称为主模板，并且可以根据应用的需求为特殊类型定制不同的成员函数和/或变量。一旦有了类模板，在**part II**中，编译器将根据应用的需求显式或隐式地将其实例化为模板类。

现在，让我们看一下创建类模板的语法。

# 语法

创建类模板的语法如下：

```cpp
[export] template <template_parameter_list> class-declaration 
```

在这里，我们有以下内容：

+   `template_parameter-list`（参见*进一步阅读*上下文中的链接[10]）是模板参数的非空逗号分隔列表，每个参数都是非类型参数、类型参数、模板参数或任何这些的参数包。

+   `class-declaration`是用于声明包含类名和其主体的类的部分，用大括号括起来。通过这样做，声明的类名也成为模板名。

例如，我们可以定义一个类模板`V`，使其包含各种 1D 数据类型：

```cpp
template <class T>
class V {
public:
  V( int n = 0) : m_nEle(n), m_buf(0) { creatBuf();}
  ~V(){  deleteBuf();  }
  V& operator = (const V &rhs) { /* ... */}
  V& operator = (const V &rhs) { /* ... */}
  T getMax(){ /* ... */ }
protected:
  void creatBuf() { /* ... */}
  void deleteBuf(){ /* ... */}

public:
  int m_nEle;
  T * m_buf;
};
```

一旦有了这个类模板，编译器就可以在实例化过程中生成类。出于我们在*函数模板*子节中提到的原因，我们将避免在本书中使用不精确的术语`template`类。相反，我们将使用类模板。

# 实例化

考虑到前一节中我们定义的类模板`V`，我们假设后面会出现以下声明：

```cpp
V<char> cV;
V<int>  iV(10);
V<float> fV(5);
```

然后，编译器将创建`V`类的三个实例，如下所示：

```cpp
class V<char>{
public:
  V(int n=0);
 // ...
public:
  int  m_nEle;
  char *m_buf;
};
class V<int>{
public:
  V(int n=0);
 // ...
public:
  int  m_nEle;
  int *m_buf;
};
class V<float>{
public:
  V(int n = 0);
  // ...
public:
  int   m_nEle;
  float *m_buf;
};
```

与函数模板实例化类似，类模板实例化有两种形式 - 显式实例化和隐式实例化。让我们来看看它们。

# 显式实例化

显式实例化的语法如下：

```cpp
template class template_name < argument_list >;
extern template class template_name < argument_list >;//(since C++11)
```

显式实例化定义会强制实例化它们所引用的类、结构或联合体。在 C++0x 标准中，模板特化或其成员的隐式实例化被抑制。与函数模板的显式实例化类似，这种显式实例化的位置可以在其模板定义之后的任何位置，并且在整个程序中只允许定义一次。

此外，自 C++11 以来，显式实例化声明（extern template）将绕过隐式实例化步骤，这可以用于减少编译时间。

回到模板类`V`，我们可以显式实例化它如下：

```cpp
template class V<int>;
template class V<double>;
```

或者，我们可以这样做（自 C++11 以来）：

```cpp
extern template class V<int>;
extern template class V<double>;
```

如果我们显式实例化函数或类模板，但程序中没有相应的定义，编译器将给出错误消息，如下所示：

```cpp
//ch4_4_class_template_explicit.cpp
#include <iostream>
using namespace std;
template <typename T>       //line A
struct A {
  A(T init) : val(init) {}
  virtual T foo();
  T val;
};                         //line B
                           //line C 
template <class T> //T in this line is template parameter
T A<T>::foo() {    //the 1st T refers to function return type,
                   //the T in <> specifies that this function's template
                   //parameter is also the class template parameter
  return val;
}                        //line D

extern template struct A<int>;  //line E
#if 0                           //line F
int A<int>::foo() {  
    return val+1;    
}                    
#endif                         //line G

int main(void) {
  A<double> x(5);
  A<int> y(5);
  cout<<"fD="<<x.foo()<<",fI="<<y.foo()<< endl;
  return 0;        //output: fD=5,fI=6
}
```

在前面的代码块中，我们在 A 行和 B 行之间定义了一个类模板，然后我们从 C 行到 D 行实现了它的成员函数`foo()`。接下来，我们在 E 行明确地为`int`类型实例化了它。由于在 F 行和 G 行之间的代码块被注释掉了（这意味着对于这个显式的`int`类型实例化，没有相应的`foo()`定义），我们会得到一个链接错误。为了解决这个问题，我们需要在 F 行用`#if 1`替换`#if 0`。

最后，显式实例化声明还有一些额外的限制，如下所示：

+   静态：静态类成员可以命名，但静态函数不能在显式实例化声明中允许。

+   内联：在显式实例化声明中，内联函数没有影响，内联函数会被隐式实例化。

+   类及其成员：显式实例化类及其所有成员没有等价物。

# 隐式实例化

当引用模板类时，如果没有显式实例化或显式专门化，编译器将只在需要时从其模板生成代码。这称为**隐式实例化**，其语法如下：

```cpp
class_name<argument list> object_name; //for non-pointer object 
class_name<argument list> *p_object_name; //for pointer object
```

对于非指针对象，模板类被实例化并创建其对象，但只生成此对象使用的成员函数。对于指针对象，除非程序中使用了成员，否则不会实例化。

考虑以下示例，在该示例中，我们在`ch4_5_class_template_implicit_inst.h`文件中定义了一个名为`X`的类模板。

```cpp
//file ch4_5_class_template_implicit_inst.h
#ifndef __CH4_5_H__ 
#define __CH4_5_H__ 
#include <iostream>
template <class T>
class X {
public:
    X() = default;
    ~X() = default;
    void f() { std::cout << "X::f()" << std::endl; };
    void g() { std::cout << "X::g()" << std::endl; };
};
#endif
```

然后，它被以下四个`cpp`文件包含，每个文件中都有`ain()`：

```cpp
//file ch4_5_class_template_implicit_inst_A.cpp
#include "ch4_5_class_template_implicit_inst.h"
void main()
{
    //implicit instantiation generates class X<int>, then create object xi
    X<int>   xi ;  
    //implicit instantiation generates class X<float>, then create object xf
    X<float> xf;
    return 0;  
}
```

在`ch4_5_class_template_implicit_inst_A.cpp`中，编译器将隐式实例化`X<int>`和`X<float>`类，然后创建`xi`和`xf`对象。但由于未使用`X::f()`和`X::g()`，它们不会被实例化。

现在，让我们看一下`ch4_5_class_template_implicit_inst_B.cpp`：

```cpp
//file ch4_5_class_template_implicit_inst_B.cpp
#include "ch4_5_class_template_implicit_inst.h"
void main()
{
    //implicit instantiation generates class X<int>, then create object xi
    X<int> xi;    
    xi.f();      //and generates function X<int>::f(), but not X<int>::g()

    //implicit instantiation generates class X<float>, then create object
    //xf and generates function X<float>::g(), but not X<float>::f()
    X<float> xf;  
    xf.g() ;   
}
```

在这里，编译器将隐式实例化`X<int>`类，创建`xi`对象，然后生成`X<int>::f()`函数，但不会生成`X<int>::g()`。类似地，它将实例化`X<float>`类，创建`xf`对象，并生成`X<float>::g()`函数，但不会生成`X<float>::f()`。

然后，我们有`ch4_5_class_template_implicit_inst_C.cpp`：

```cpp
//file ch4_5_class_template_implicit_inst_C.cpp
#include "ch4_5_class_template_implicit_inst.h"
void main()
{
   //inst. of class X<int> is not required, since p_xi is pointer object
   X<int> *p_xi ;   
   //inst. of class X<float> is not required, since p_xf is pointer object
   X<float> *p_xf ; 
}
```

由于`p_xi`和`p_xf`是指针对象，因此无需通过编译器实例化它们对应的模板类。

最后，我们有`ch4_5_class_template_implicit_inst_D.cpp`：

```cpp
//file ch4_5_class_template_implicit_inst_D.cpp
#include "ch4_5_class_template_implicit_inst.h"
void main()
{
//inst. of class X<int> is not required, since p_xi is pointer object
 X<int> *p_xi; 

 //implicit inst. of X<int> and X<int>::f(), but not X<int>::g()
 p_xi = new X<int>();
 p_xi->f(); 

//inst. of class X<float> is not required, since p_xf is pointer object
 X<float> *p_xf; 
 p_xf = new X<float>();//implicit inst. of X<float> occurs here
 p_xf->f();            //implicit inst. X<float>::f() occurs here
 p_xf->g();            //implicit inst. of X<float>::g() occurs here

 delete p_xi;
 delete p_xf;
}
```

这将隐式实例化`X<int>`和`X<int>::f()`，但不会实例化`X<int>::g()`；同样，对于`X<float>`，将实例化`X<float>::f()`和`X<float>::g()`。

# 专门化

与函数专门化类似，当将特定类型作为模板参数传递时，类模板的显式专门化定义了主模板的不同实现。但是，它仍然是一个类模板，您需要通过实例化来获得真正的代码。

例如，假设我们有一个`struct X`模板，可以存储任何数据类型的一个元素，并且只有一个名为`increase()`的成员函数。但是对于 char 类型数据，我们希望`increase()`有不同的实现，并且需要为其添加一个名为`toUpperCase()`的新成员函数。因此，我们决定为该类型声明一个类模板专门化。我们可以这样做：

1.  声明一个主类模板：

```cpp
template <typename T>
struct X {
  X(T init) : m(init) {}
  T increase() { return ++m; }
  T m;
};
```

这一步声明了一个主类模板，其中它的构造函数初始化了`m`成员变量，`increase()`将`m`加一并返回其值。

1.  接下来，我们需要为 char 类型数据执行专门化：

```cpp
template <>  //Note: no parameters inside <>, it tells compiler 
             //"hi i am a fully specialized template"
struct X<char> { //Note: <char> after X, tells compiler
                 // "Hi, this is specialized only for type char"
  X(char init) : m(init) {}
  char increase() { return (m<127) ? ++m : (m=-128); }
  char toUpperCase() {
    if ((m >= 'a') && (m <= 'z')) m += 'A' - 'a';
    return m;
  }
  char m;
};
```

这一步为 char 类型数据创建了一个专门化（相对于主类模板），并为其添加了一个额外的成员函数`toUpperCase()`。

1.  现在，我们进行测试：

```cpp
int main() {
 X<int> x1(5);         //line A
 std::cout << x1.increase() << std::endl;

 X<char> x2('b');     //line B
 std::cout << x2.toUpperCase() << std::endl;
 return 0;
}
```

最后，我们有一个`main()`函数来测试它。在 A 行，`x1`是一个从主模板`X<T>`隐式实例化的对象。由于`x1.m`的初始值是`5`，所以`x1.increase()`将返回`6`。在 B 行，`x2`是从专门化模板`X<char>`实例化的对象，当它执行时，`x2.m`的值是`b`。在调用`x2.toUpperCase()`之后，`B`将是返回值。

此示例的完整代码可以在`ch4_6_class_template_specialization.cpp`中找到。

总之，在类模板的显式专门化中使用的语法如下：

```cpp
template <> class[struct] class_name<template argument list> { ... }; 
```

在这里，空的模板参数列表`template <>`用于显式声明它为模板专门化，`<template argument list>`是要专门化的类型参数。例如，在`ex4_6_class_template_specialization.cpp`中，我们使用以下内容：

```cpp
template <> struct X<char> { ... };
```

在`X`之后的`<char>`标识了我们要为其声明模板类专门化的类型。

此外，当我们为模板类进行特化时，即使在主模板中相同的成员也必须被定义，因为在模板特化期间没有主模板的继承概念。

接下来，我们将看一下部分特化。这是显式特化的一般陈述。与只有模板参数列表的显式特化格式相比，部分特化需要模板参数列表和参数列表。对于模板实例化，如果用户的模板参数列表与模板参数的子集匹配，编译器将选择部分特化模板，然后编译器将从部分特化模板生成新的类定义。

在下面的示例中，对于主类模板`A`，我们可以为参数列表中的 const `T`进行部分特化。请注意，它们的参数列表相同，即`<typename T>`：

```cpp
//primary class template A
template <typename T>  class A{ /* ... */ }; 

//partial specialization for const T
template <typename T>  class A<const T>{ /* ... */ };  

```

在下面的示例中，主类模板`B`有两个参数：`<typename T1`和`typename T2 >`。我们通过`T1=int`进行部分特化，保持`T2`不变：

```cpp
//primary class template B
template <typename T1, typename T2> class B{ /* ... */ };          

//partial specialization for T1 = int
template <typename T2> class B<int, T2>{ /* ... */};  
```

最后，在下面的示例中，我们可以看到部分特化中的模板参数数量不必与原始主模板中出现的参数数量匹配。然而，模板参数的数量（出现在尖括号中的类名后面）必须与主模板中的参数数量和类型匹配：

```cpp
//primary class template C: template one parameter
template <typename T> struct C { T type; };  

//specialization: two parameters in parameter list 
//but still one argument (<T[N]>) in argument list
template <typename T, int N> struct C<T[N]>          
{T type; };                                 
```

同样，类模板的部分特化仍然是一个类模板。您必须为其成员函数和数量变量分别提供定义。

结束本节，让我们总结一下我们到目前为止学到的内容。在下表中，您可以看到函数和类模板、它们的实例化和特化之间的比较：

| | **函数模板** | **类模板** | **注释** |
| --- | --- | --- | --- |
| 声明 | `template <class T1, class T2>` `void f(T1 a, T2 b) { ... }` | `template <class T1, class T2>` `class X { ... };` | 声明定义了一个函数/类模板，`<class T1, class T2>`称为模板参数。 |
| 显式实例化 | `template void f <int, int >( int, int);`或`extern template`void f <int, int >( int, int);`（自 C++11 起） | `template class X<int, float>;`或`extern template class X<int,float>;`（自 C++11 起） | 实例化后现在有函数/类，但它们被称为模板函数/类。 |
| 隐式实例化 | {...`f(3, 4.5);` `f<char, float>(120, 3.14);`} | {...`X<int,float> obj;` `X<char, char> *p;`} | 当函数调用或类对象/指针声明时，如果没有被显式实例化，则使用隐式实例化方法。 |
| 特化 | `template <>` `void f<int,float>(int a, float b)` | `template <>` `class X <int, float>{ ... };` | 主模板的完全定制版本（无参数列表）仍然需要被实例化。 |
| 部分特化 | `template <class T>` `void f<T, T>(T a, T b)` | `template <class T>` `class X <T, T>` | 主模板的部分定制版本（有参数列表）仍然需要被实例化。 |

这里需要强调五个概念：

+   **声明**：我们需要遵循用于定义函数或类模板的语法。此时，函数或类模板本身不是类型、函数或任何其他实体。换句话说，在源文件中只有模板定义，没有代码可以编译成对象文件。

+   **隐式实例化**：对于任何代码的出现，都必须实例化一个模板。在这个过程中，必须确定模板参数，以便编译器可以生成实际的函数或类。换句话说，它们是按需编译的，这意味着在给定特定模板参数的实例化之前，模板函数或类的代码不会被编译。

+   **显式实例化**：告诉编译器使用给定类型实例化模板，无论它们是否被使用。通常用于提供库。

+   ****完全特化****：这没有参数列表（完全定制）；它只有一个参数列表。模板特化最有用的一点是，您可以为特定类型参数创建特殊模板。

+   **部分特化**：这类似于完全特化，但是部分参数列表（部分定制）和部分参数列表。

# 理解可变模板

在前一节中，我们学习了如何编写具有固定数量类型参数的函数或类模板。但自 C++11 以来，标准通用函数和类模板可以接受可变数量的类型参数。这被称为**可变模板**，它是 C++的扩展，详情请参阅*Further reading* [6]。我们将通过示例学习可变模板的语法和用法。

# 语法

如果一个函数或类模板需要零个或多个参数，可以定义如下：

```cpp
//a class template with zero or more type parameters
template <typename... Args> class X { ... };     

//a function template with zero or more type parameters
template <typename... Args> void foo( function param list) { ...}                                                                      
```

在这里，`<typename ... Args>`声明了一个参数包。请注意，这里的`Args`不是关键字；您可以使用任何有效的变量名。前面的类/函数模板可以接受任意数量的`typename`作为其需要实例化的参数，如下所示：

```cpp
X<> x0;                       //with 0 template type argument
X<int, std::vector<int> > x1; //with 2 template type arguments

//with 4 template type arguments
X<int, std::vector<int>, std::map<std::string, std::vector<int>>> x2; 

//with 2 template type arguments 
foo<float, double>( function argument list ); 

//with 3 template type arguments
foo<float, double, std::vector<int>>( function argument list );
```

如果可变模板需要至少一个类型参数，则使用以下定义：

```cpp
template <typename A, typename... Rest> class Y { ... }; 

template <typename A, typename... Rest> 
void goo( const int a, const float b) { ....};
```

同样，我们可以使用以下代码来实例化它们：

```cpp
Y<int > y1;                                         
Y<int, std::vector<int>, std::map<std::string, std::vector<int>>> y2;
goo<int, float>(  const int a, const float b );                        
goo<int,float, double, std::vector<int>>(  const int a, const float b );      
```

在前面的代码中，我们创建了`y1`和`y2`对象，它们是通过具有一个和三个模板参数的可变类模板`Y`的实例化而得到的。对于可变函数`goo`模板，我们将它实例化为两个模板函数，分别具有两个和三个模板参数。

# 示例

以下可能是最简单的示例，展示了使用可变模板来查找任何输入参数列表的最小值。这个示例使用了递归的概念，直到达到`my_min(double n)`为止：

```cpp
//ch4_7_variadic_my_min.cpp
//Only tested on g++ (Ubuntu/Linaro 7.3.0-27 ubuntu1~18.04)
//It may have compile errors for other platforms
#include <iostream>
#include <math.h> 
double my_min(double n){
  return n;
}
template<typename... Args>
double my_min(double n, Args... args){
  return fmin(n, my_min(args...));
}
int main() {
  double x1 = my_min(2);
  double x2 = my_min(2, 3);
  double x3 = my_min(2, 3, 4, 5, 4.7,5.6, 9.9, 0.1);
  std::cout << "x1="<<x1<<", x2="<<x2<<", x3="<<x3<<std::endl;
  return 0;
}
```

`printf()`可变参数函数可能是 C 或 C++中最有用和强大的函数之一；但是，它不是类型安全的。在下面的代码块中，我们采用了经典的类型安全`printf()`示例来演示可变模板的用处。首先，我们需要定义一个基本函数`void printf_vt(const char *s)`，它结束了递归：

```cpp
//ch4_8_variadic_printf.cpp part A: base function - recursive end
void printf_vt(const char *s)
{
  while (*s){
    if (*s == '%' && *(++s) != '%')
      throw std::runtime_error("invalid format string: missing arguments");
     std::cout << *s++;
  }
}
```

然后，在其可变模板函数`printf_vt()`中，每当遇到`%`时，该值被打印，其余部分被传递给递归，直到达到基本函数：

```cpp
//ch4_8_variadic_printf.cpp part B: recursive function
template<typename T, typename... Rest>
void printf_vt(const char *s, T value, Rest... rest)
{
  while (*s) {
    if (*s == '%' && *(++s) != '%') {
      std::cout << value;
      printf_vt(s, rest...); //called even when *s is 0, 
      return;                //but does nothing in that case
    }
    std::cout << *s++;
  }
}
```

最后，我们可以使用以下代码进行测试和比较传统的`printf()`。

```cpp
//ch4_8_variadic_printf.cpp Part C: testing
int main() {
  int x = 10;
  float y = 3.6;
  std::string s = std::string("Variadic templates");
  const char* msg1 = "%s can accept %i parameters (or %s), x=%d, y=%f\n";
  printf(msg1, s, 100, "more",x,y);  //replace 's' by 's.c_str()' 
                                     //to prevent the output bug
  const char* msg2 = "% can accept % parameters (or %); x=%,y=%\n";
  printf_vt(msg2, s, 100, "more",x,y);
  return 0;
}
```

前面代码的输出如下：

```cpp
p.]ï¿½U can accept 100 parameters (or more), x=10, y=3.600000
Variadic templates can accept 100 parameters (or more); x=10,y=3.6
```

在第一行的开头，我们可以看到一些来自`printf()`的 ASCII 字符，因为`%s`的相应变量类型应该是指向字符的指针，但我们给它一个`std::string`类型。为了解决这个问题，我们需要传递`s.c_str()`。然而，使用可变模板版本的函数，我们就没有这个问题。此外，我们只需要提供`%`，这甚至更好 - 至少对于这个实现来说是这样。

总之，本节简要介绍了可变模板及其应用。可变模板提供了以下好处（自 C++11 以来）：

+   这是模板家族的一个轻量级扩展。

+   它展示了在不使用丑陋的模板和预处理宏的情况下实现大量模板库的能力。因此，实现代码可以被理解和调试，并且还节省了编译时间。

+   它使`printf()`可变参数函数的类型安全实现成为可能。

接下来，我们将探讨模板参数和参数。

# 探索模板参数和参数

在前两节中，我们学习了函数和类模板及其实例化。我们知道，在定义模板时，需要给出其参数列表。而在实例化时，必须提供相应的参数列表。在本节中，我们将进一步研究这两个列表的分类和细节。

# 模板参数

回想一下以下语法，用于定义类/函数模板。在`template`关键字后面有一个`<>`符号，在其中必须给出一个或多个模板参数：

```cpp
//class template declaration
template <*parameter-list*> class-declaration

//function template declaration
template <parameter-list> function-declaration
```

参数列表中的参数可以是以下三种类型之一：

+   `非类型模板参数`：指的是编译时常量值，如整数和指针，引用静态实体。这些通常被称为非类型参数。

+   `类型模板参数`：指的是内置类型名称或用户定义的类。

+   `模板模板参数`：表示参数是其他模板。

我们将在接下来的小节中更详细地讨论这些内容。

# 非类型模板参数

非类型模板参数的语法如下：

```cpp
//for a non-type template parameter with an optional name
type name(optional)

//for a non-type template parameter with an optional name 
//and a default value
type name(optional)=default  

//For a non-type template parameter pack with an optional name
type ... name(optional) (since C++11) 
```

在这里，`type`是以下类型之一 - 整数类型、枚举、对象或函数的指针、对象或函数的`lvalue`引用、成员对象或成员函数的指针，以及`std::nullptr_t`（自 C++11 起）。此外，我们可以在模板声明中放置数组和/或函数类型，但它们会自动替换为数据和/或函数指针。

以下示例显示了一个使用非类型模板参数`int N`的类模板。在`main()`中，我们实例化并创建了一个对象`x`，因此`x.a`有五个初始值为`1`的元素。在将其第四个元素的值设置为`10`后，我们打印输出：

```cpp
//ch4_9_none_type_template_param1.cpp
#include <iostream>
template<int N>
class V {
public:
  V(int init) { 
    for (int i = 0; i<N; ++i) { a[i] = init; } 
  }
  int a[N];
};

int main()
{
  V<5> x(1); //x.a is an array of 5 int, initialized as all 1's 
  x.a[4] = 10;
  for( auto &e : x.a) {
    std::cout << e << std::endl;
  }
}
```

以下是一个使用`const char*`作为非类型模板参数的函数模板示例：

```cpp
//ch4_10_none_type_template_param2.cpp
#include <iostream>
template<const char* msg>
void foo() {
  std::cout << msg << std::endl;
}

// need to have external linkage
extern const char str1[] = "Test 1"; 
constexpr char str2[] = "Test 2";
extern const char* str3 = "Test 3";
int main()
{
  foo<str1>();                   //line 1
  foo<str2>();                   //line 2 
  //foo<str3>();                 //line 3

  const char str4[] = "Test 4";
  constexpr char str5[] = "Test 5";
  //foo<str4>();                 //line 4
  //foo<str5>();                 //line 5
  return 0;
}
```

在`main()`中，我们成功地用`str1`和`str2`实例化了`foo()`，因为它们都是编译时常量值并且具有外部链接。然后，如果我们取消注释第 3-5 行，编译器将报告错误消息。出现这些编译器错误的原因如下：

+   **第 3 行**：`str3`不是一个 const 变量，所以`str3`指向的值不能被改变。然而，`str3`的值可以被改变。

+   **第 4 行**：`str4`不是`const char*`类型的有效模板参数，因为它没有链接。

+   **第 5 行**：`str5`不是`const char*`类型的有效模板参数，因为它没有链接。

非类型参数的最常见用法之一是数组的大小。如果您想了解更多，请访问[`stackoverflow.com/questions/33234979`](https://stackoverflow.com/questions/33234979)。

# 类型模板参数

类型模板参数的语法如下：

```cpp
//A type Template Parameter (TP) with an optional name
typename |class name(optional)               

//A type TP with an optional name and a default
typename[class] name(optional) = default         

//A type TP pack with an optional name
typename[class] ... name(optional) (since C++11) 
```

**注意：**在这里，我们可以互换使用`typename`和`class`关键字。在模板声明的主体内，类型参数的名称是`typedef-name`。当模板被实例化时，它将别名为提供的类型。

现在，让我们看一些例子：

+   没有默认值的类型模板参数：

```cpp
Template<class T>               //with name
class X { /* ... */ };     

Template<class >               //without name
class Y { /* ... */ };
```

+   带有默认值的类型模板参数：

```cpp
Template<class T = void>    //with name 
class X { /* ... */ };     

Template<class = void >     //without name
class Y { /* ... */ };
```

+   类型模板参数包：

```cpp
template<typename... Ts>   //with name
class X { /* ... */ };

template<typename... >   //without name
class Y { /* ... */ };

```

这个模板参数包可以接受零个或多个模板参数，并且仅适用于 C++11 及以后的版本。

# 模板模板参数

模板模板参数的语法如下：

```cpp
//A template template parameter with an optional name
template <parameter-list> class *name*(optional) 

//A template template parameter with an optional name and a default
template <parameter-list> class *name*(optional) = default          

//A template template parameter pack with an optional name
template <parameter-list> class ... *name*(optional) (since C++11)                                                                                               
```

**注意**：在模板模板参数声明中，只能使用`class`关键字；不允许使用`typename`。在模板声明的主体中，参数的名称是`template-name`，我们需要参数来实例化它。

现在，假设您有一个函数，它充当对象列表的流输出运算符：

```cpp
template<typename T>
static inline std::ostream &operator << ( std::ostream &out, 
    std::list<T> const& v)
{ 
    /*...*/ 
}
```

从前面的代码中，您可以看到对于序列容器（如向量，双端队列和多种映射类型），它们是相同的。因此，使用模板模板参数的概念，可以有一个单一的运算符`<<`来控制它们。这种情况的示例可以在`exch4_tp_c.cpp`中找到：

```cpp
/ch4_11_template_template_param.cpp (courtesy: https://stackoverflow.com/questions/213761)
#include <iostream>
#include <vector>
#include <deque>
#include <list>
using namespace std;
template<class T, template<class, class...> class X, class... Args>
std::ostream& operator <<(std::ostream& os, const X<T, Args...>& objs) {
  os << __PRETTY_FUNCTION__ << ":" << endl;
  for (auto const& obj : objs)
    os << obj << ' ';
  return os;
}

int main() {
  vector<float> x{ 3.14f, 4.2f, 7.9f, 8.08f };
  cout << x << endl;

  list<char> y{ 'E', 'F', 'G', 'H', 'I' };
  cout << y << endl;

  deque<int> z{ 10, 11, 303, 404 };
  cout << z << endl;
  return 0;
}
```

前面程序的输出如下：

```cpp
class std::basic_ostream<char,struct std::char_traits<char> > &__cdecl operator
<<<float,class std::vector,class std::allocator<float>>(class std::basic_ostream
<char,struct std::char_traits<char> > &,const class std::vector<float,class std:
:allocator<float> > &):
3.14 4.2 7.9 8.08
class std::basic_ostream<char,struct std::char_traits<char> > &__cdecl operator
<<<char,class std::list,class std::allocator<char>>(class std::basic_ostream<cha
r,struct std::char_traits<char> > &,const class std::list<char,class std::alloca
tor<char> > &):
E F G H I
class std::basic_ostream<char,struct std::char_traits<char> > &__cdecl operator
<<<int,class std::deque,class std::allocator<int>>(class std::basic_ostream<char
,struct std::char_traits<char> > &,const class std::deque<int,class std::allocat
or<int> > &):
10 11 303 404 
```

如预期的那样，每次调用的输出的第一部分是`pretty`格式的模板函数名称，而第二部分输出每个容器的元素值。

# 模板参数

要实例化模板，必须用相应的模板参数替换所有模板参数。参数可以是显式提供的，从初始化程序中推导出（对于类模板），从上下文中推导出（对于函数模板），或者默认值。由于有三种模板参数类别，我们也将有三个相应的模板参数。这些是模板非类型参数，模板类型参数和模板模板参数。除此之外，我们还将讨论默认模板参数。

# 模板非类型参数

请注意，非类型模板参数是指编译时常量值，如整数，指针和对静态实体的引用。在模板参数列表中提供的非类型模板参数必须与这些值中的一个匹配。通常，非类型模板参数用于类初始化或类容器的大小规格。

尽管讨论每种类型（整数和算术类型，指向对象/函数/成员的指针，`lvalue`引用参数等）的详细规则超出了本书的范围，但总体的一般规则是模板非类型参数应转换为相应模板参数的常量表达式。

现在，让我们看下面的例子：

```cpp
//part 1: define template with non-type template parameters
template<const float* p> struct U {}; //float pointer non-type parameter
template<const Y& b> struct V {};     //L-value non-type parameter
template<void (*pf)(int)> struct W {};//function pointer parameter

//part 2: define other related stuff
void g(int,float);   //declare function g() 
void g(int);         //declare an overload function of g() 
struct Y {           //declare structure Y 
    float m1;
    static float m2;
};         
float a[10]; 
Y y; //line a: create a object of Y

//part 3: instantiation template with template non-type arguments
U<a> u1;      //line b: ok: array to pointer conversion
U<&y> u2;     //line c: error: address of Y
U<&y.m1> u3;  //line d: error: address of non-static member
U<&y.m2> u4;  //line e: ok: address of static member
V<y> v;       //line f: ok: no conversion needed
W<&g> w;      //line g: ok: overload resolution selects g(int)
```

在前面的代码中，在`part 1`中，我们定义了具有不同非类型模板参数的三个模板结构。然后，在`part 2`中，我们声明了两个重载函数和`struct Y`。最后，在`part 3`中，我们看了通过不同的非类型参数正确实例化它们的方法。

# 模板类型参数

与模板非类型参数相比，模板类型参数（用于类型模板参数）的规则很简单，要求必须是`typeid`。在这里，`typeid`是一个标准的 C++运算符，它在运行时返回类型识别信息。它基本上返回一个可以与其他`type_info`对象进行比较的`type_info`对象。

现在，让我们看下面的例子：

```cpp
//ch4_12_template_type_argument.cpp
#include <iostream>
#include <typeinfo>
using namespace std;

//part 1: define templates
template<class T> class C  {}; 
template<class T> void f() { cout << "T" << endl; }; 
template<int i>   void f() { cout << i << endl; };     

//part 2: define structures
struct A{};            // incomplete type 
typedef struct {} B; // type alias to an unnamed type

//part 3: main() to test
int main() {
  cout << "Tid1=" << typeid(A).name() << "; "; 
  cout << "Tid2=" << typeid(A*).name() << "; ";    
  cout << "Tid3=" << typeid(B).name()  << "; ";
  cout << "Tid4=" << typeid(int()).name() << endl;

  C<A> x1;    //line A: ok,'A' names a type
  C<A*> x2;   //line B: ok, 'A*' names a type
  C<B> x3;    //line C: ok, 'B' names a type
  f<int()>(); //line D: ok, since int() is considered as a type, 
              //thus calls type template parameter f()
  f<5>();     //line E: ok, this calls non-type template parameter f() 
  return 0;
}
```

在这个例子中，在`part 1`中，我们定义了三个类和函数模板：具有其类型模板参数的类模板 C，具有类型模板参数的两个函数模板，以及一个非类型模板参数。在`part 2`中，我们有一个不完整的`struct A`和一个无名类型`struct B`。最后，在`part 3`中，我们对它们进行了测试。在 Ubuntu 18.04 中四个`typeid()`的输出如下：

```cpp
Tid1=A; Tid2=P1A; Tid3=1B; Tid4=FivE
```

从 x86 MSVC v19.24，我们有以下内容：

```cpp
Tid1=struct A; Tid2=struct A; Tid3=struct B; Tid4=int __cdecl(void)
```

另外，由于`A`，A*，`B`和`int()`具有 typeid，因此从 A 到 D 行的代码段与模板类型类或函数相关联。只有 E 行是从非类型模板参数函数模板实例化的，即`f()`。

# 模板模板参数

对于模板模板参数，其对应的模板参数是类模板或模板别名的名称。在查找与模板模板参数匹配的模板时，只考虑主类模板。

这里，主模板是指正在进行特化的模板。即使它们的参数列表可能匹配，编译器也不会考虑与模板模板参数的部分特化。

以下是模板模板参数的示例：

```cpp
//ch4_13_template_template_argument.cpp
#include <iostream>
#include <typeinfo>
using namespace std;

//primary class template X with template type parameters
template<class T, class U> 
class X {
public:
    T a;
    U b;
};

//partially specialization of class template X
template<class U> 
class X<int, U> {
public:
    int a;  //customized a
    U b;
};

//class template Y with template template parameter
template<template<class T, class U> class V> 
class Y {
public:
    V<int, char> i;
    V<char, char> j;
};

Y<X> c;
int main() {
    cout << typeid(c.i.a).name() << endl; //int
    cout << typeid(c.i.b).name() << endl; //char
    cout << typeid(c.j.a).name() << endl; //char
    cout << typeid(c.j.b).name() << endl; //char
    return 0;
}
```

在这个例子中，我们定义了一个主类模板`X`及其特化，然后是一个带有模板模板参数的类模板`Y`。接下来，我们隐式实例化`Y`，并使用模板模板参数`X`创建一个对象`c`。最后，`main()`输出了四个`typeid()`的名称，结果分别是`int`、`char`、`char`和`char`。

# 默认模板参数

在 C++中，通过传递参数来调用函数，并且函数使用这些参数。如果在调用函数时未传递参数，则使用默认值。与函数参数默认值类似，模板参数可以有默认参数。当我们定义模板时，可以设置其默认参数，如下所示：

```cpp
/ch4_14_default_template_arguments.cpp       //line 0
#include <iostream>                          //line 1  
#include <typeinfo>                          //line 2
template<class T1, class T2 = int> class X;  //line 3
template<class T1 = float, class T2> class X;//line 4
template<class T1, class T2> class X {       //line 5
public:                                      //line 6   
 T1 a;                                       //line 7
 T2 b;                                       //line 8  
};                                           //line 9
using namespace std;
int main() { 
 X<int> x1;          //<int,int>
 X<float>x2;         //<float,int>
 X<>x3;              //<float,int>
 X<double, char> x4; //<double, char>
 cout << typeid(x1.a).name() << ", " << typeid(x1.b).name() << endl;
 cout << typeid(x2.a).name() << ", " << typeid(x2.b).name() << endl;
 cout << typeid(x3.a).name() << ", " << typeid(x3.b).name() << endl;
 cout << typeid(x4.a).name() << ", " << typeid(x4.b).name() << endl;
 return 0
}
```

在设置模板参数的默认参数时，需要遵循一些规则：

+   声明顺序很重要——默认模板参数的声明必须在主模板声明的顶部。例如，在前面的例子中，不能将代码移动到第 3 行和第 4 行之后的第 9 行之后。

+   如果一个参数有默认参数，那么它后面的所有参数也必须有默认参数。例如，以下代码是不正确的：

```cpp
template<class U = char, class V, class W = int> class X { };  //Error 
template<class V, class U = char,  class W = int> class X { }; //OK
```

+   在同一作用域中不能给相同的参数设置默认参数两次。例如，如果使用以下代码，将收到错误消息：

```cpp
template<class T = int> class Y;

//compiling error, to fix it, replace "<class T = int>" by "<class T>"
template<class T = int> class Y { 
    public: T a;  
};
```

在这里，我们讨论了两个列表：`template_parameter_list`和`template_argument_list`。这些分别用于函数或类模板的创建和实例化。

我们还了解了另外两个重要规则：

+   当我们定义类或函数模板时，需要给出其`template_parameter_list`：

```cpp
template <template_parameter_list> 
class X { ... }

template <template_parameter_list> 
void foo( function_argument_list ) { ... } //assume return type is void
```

+   当我们实例化它们时，必须提供相应的`argument_list`：

```cpp
class X<template_argument_list> x
void foo<template_argument_list>( function_argument_list )
```

这两个列表中的参数或参数类型可以分为三类，如下表所示。请注意，尽管顶行是用于类模板，但这些属性也适用于函数模板：

|  | **定义模板时****template** **<template_parameter_list> class X { ... }** | **实例化模板时****class X<template_argument_list> x** |
| --- | --- | --- |

| 非类型 | 此参数列表中的实体可以是以下之一：

+   整数或枚举

+   对象指针或函数指针

+   对对象的`lvalue`引用或对函数的`lvalue`引用

+   成员指针

+   C++11 std `::nullptr_t` C++11 结束

|

+   此列表中的非类型参数是在编译时可以确定其值的表达式。

+   这些参数必须是常量表达式、具有外部链接的函数或对象的地址，或者静态类成员的地址。

+   非类型参数通常用于初始化类或指定类成员的大小。

|

| 类型 | 此参数列表中的实体可以是以下之一：

+   必须以 typename 或 class 开头。

+   在模板声明的主体中，类型参数的名称是`typedef-name`。当模板被实例化时，它将别名为提供的类型。

|

+   参数的类型必须有`typeid`。

+   它不能是局部类型、没有链接的类型、无名类型或由这些类型中的任何一个构成的类型。

|

| 模板 | 此参数列表中的实体可以是以下之一：

+   `template <parameter-list>` class name

+   `template <parameter-list>` class ... name (optional) (自 C++11 起)

| 此列表中的模板参数是类模板的名称。 |
| --- |

在接下来的部分中，我们将探讨如何在 C++中实现特征，并使用它们优化算法。

# 探索特征

泛型编程意味着编写适用于特定要求下的任何数据类型的代码。这是在软件工程行业中提供可重用高质量代码的最有效方式。然而，在泛型编程中有时候泛型并不够好。每当类型之间的差异过于复杂时，一个高效的泛型优化常见实现就会变得非常困难。例如，当实现排序函数模板时，如果我们知道参数类型是链表而不是数组，就会实现不同的策略来优化性能。

尽管模板特化是克服这个问题的一种方法，但它并不能以广泛的方式提供与类型相关的信息。类型特征是一种用于收集有关类型信息的技术。借助它，我们可以做出更明智的决策，开发高质量的优化算法。

在本节中，我们将介绍如何实现类型特征，然后向您展示如何使用类型信息来优化算法。

# 类型特征实现

为了理解类型特征，我们将看一下`boost::is_void`和`boost::is_pointer`的经典实现。

# boost::is_void

首先，让我们来看一下最简单的特征类之一，即由 boost 创建的`is_void`特征类。它定义了一个通用模板，用于实现默认行为；也就是说，接受 void 类型，但其他任何类型都是 void。因此，我们有`is_void::value = false`。

```cpp
//primary class template is_void
template< typename T >
struct is_void{
    static const bool value = false;  //default value=false 
};
```

然后，我们对 void 类型进行了完全特化：

```cpp
//"<>" means a full specialization of template class is_void
template<> 
struct is_void< void >{             //fully specialization for void
    static const bool value = true; //only true for void type
};
```

因此，我们有一个完整的特征类型，可以用来检测任何给定类型`T`是否通过检查以下表达式`is_void`。

```cpp
is_void<T>::value
```

接下来，让我们学习如何在`boost::is_pointer`特征中使用部分特化。

# boost::is_pointer

与`boost::avoid`特征类类似，首先定义了一个主类模板：

```cpp
//primary class template is_pointer
template< typename T > 
struct is_pointer{
    static const bool value = false;
};
```

然后，它对所有指针类型进行了部分特化：

```cpp
//"typename T" in "<>" means partial specialization
template< typename T >   
struct is_pointer< T* >{ //<T*> means partial specialization only for type T* 
  static const bool value = true;  //set value as true
};
```

现在，我们有一个完整的特征类型，可以用来检测任何给定类型`T`是否通过检查以下表达式`is_pointer`。

```cpp
is_pointer<T>::value
```

由于 boost 类型特征功能已经正式引入到 C++ 11 标准库中，我们可以在下面的示例中展示`std::is_void`和`std::is_pointer`的用法，而无需包含前面的源代码：

```cpp
//ch4_15_traits_boost.cpp
#include <iostream>
#include <type_traits>  //since C++11
using namespace std;
struct X {};
int main()
{
 cout << boolalpha; //set the boolalpha format flag for str stream.
 cout << is_void<void>::value << endl;          //true
 cout << is_void<int>::value << endl;           //false
 cout << is_pointer<X *>::value << endl;        //true
 cout << is_pointer<X>::value << endl;          //false
 cout << is_pointer<X &>::value << endl;        //false
 cout << is_pointer<int *>::value << endl;      //true
 cout << is_pointer<int **>::value << endl;     //true
 cout << is_pointer<int[10]>::value << endl;    //false
 cout << is_pointer< nullptr_t>::value << endl; //false
}
```

前面的代码在字符串流的开头设置了`boolalpha`格式标志。通过这样做，所有的布尔值都以它们的文本表示形式提取，即 true 或 false。然后，我们使用几个`std::cout`来打印`is_void<T>::value`和`is_pointer<T>::value`的值。每个值的输出显示在相应的注释行末尾。

# 使用特征优化算法

我们将使用一个经典的优化复制示例来展示类型特征的用法，而不是以一种泛型抽象的方式来讨论这个主题。考虑标准库算法`copy`：

```cpp
template<typename It1, typename It2> 
It2 copy(It1 first, It1 last, It2 out);
```

显然，我们可以为任何迭代器类型编写`copy()`的通用版本，即这里的`It1`和`It2`。然而，正如 boost 库的作者所解释的那样，有些情况下复制操作可以通过`memcpy()`来执行。如果满足以下所有条件，我们可以使用`memcpy()`：

+   `It1`和`It2`这两种迭代器都是指针。

+   `It1`和`It2`必须指向相同的类型，除了 const 和 volatile 限定符

+   `It1`指向的类型必须提供一个平凡的赋值运算符。

这里，平凡的赋值运算符意味着该类型要么是标量类型，要么是以下类型之一：

+   该类型没有用户定义的赋值运算符。

+   该类型内部没有数据成员的引用类型。

+   所有基类和数据成员对象必须定义平凡的赋值运算符。

在这里，标量类型包括算术类型、枚举类型、指针、成员指针，或者这些类型的 const 或 volatile 修饰版本。

现在，让我们看一下原始实现。它包括两部分 - 复制器类模板和用户界面函数，即`copy()`：

```cpp
namespace detail{
//1\. Declare primary class template with a static function template
template <bool b>
struct copier {
    template<typename I1, typename I2>
    static I2 do_copy(I1 first, I1 last, I2 out);
};
//2\. Implementation of the static function template
template <bool b>
template<typename I1, typename I2>
I2 copier<b>::do_copy(I1 first, I1 last, I2 out) {
    while(first != last) {
        *out = *first; 
         ++out;
         ++first;
    }
    return out;
};
//3\. a full specialization of the primary function template
template <>
struct copier<true> {
    template<typename I1, typename I2>
    static I2* do_copy(I1* first, I1* last, I2* out){
        memcpy(out, first, (last-first)*sizeof(I2));
        return out+(last-first);
    }
};
}  //end namespace detail
```

如注释行中所述，前面的复制器类模板有两个静态函数模板 - 一个是主要的，另一个是完全专门化的。主要的函数模板进行逐个元素的硬拷贝，而完全专门化的函数模板通过`memcpy()`一次性复制所有元素：

```cpp
//copy() user interface 
template<typename I1, typename I2>
inline I2 copy(I1 first, I1 last, I2 out) {
    typedef typename boost::remove_cv
    <typename std::iterator_traits<I1>::value_type>::type v1_t;

    typedef typename boost::remove_cv
    <typename std::iterator_traits<I2>::value_type>::type v2_t;

    enum{ can_opt = boost::is_same<v1_t, v2_t>::value
                    && boost::is_pointer<I1>::value
                    && boost::is_pointer<I2>::value
                    && boost::has_trivial_assign<v1_t>::value 
   };
   //if can_opt= true, using memcpy() to copy whole block by one 
   //call(optimized); otherwise, using assignment operator to 
   //do item-by-item copy
   return detail::copier<can_opt>::do_copy(first, last, out);
}
```

为了优化复制操作，前面的用户界面函数定义了两个`remove_cv`模板对象，`v1_t`和`v2_t`，然后评估`can_opt`是否为真。之后，调用`do_copy()`模板函数。通过使用 boost 实用程序库中发布的测试代码（`algo_opt_ examples.cpp`），我们可以看到使用优化实现有显著改进；即对于复制 char 或 int 类型的数据，速度可能提高 8 倍或 3 倍。

最后，让我们用以下要点总结本节：

+   特征除了类型之外还提供额外的信息。它通过模板特化来实现。

+   按照惯例，特征总是作为结构体实现。用于实现特征的结构体称为特征类。

+   Bjarne Stroustrup 说我们应该将特征视为一个小对象，其主要目的是携带另一个对象或算法使用的信息，以确定策略或实现细节。*进一步阅读*上下文[4]

+   Scott Meyers 还总结说我们应该使用特征类来收集有关类型的信息*进一步阅读*上下文[5]。

+   特征可以帮助我们以高效/优化的方式实现通用算法。

接下来，我们将探讨 C++中的模板元编程。

# 探索模板元编程

一种计算机程序具有将其他程序视为其数据的能力的编程技术被称为**元编程**。这意味着程序可以被设计为读取、生成、分析或转换其他程序，甚至在运行时修改自身。一种元编程是编译器，它以文本格式程序作为输入语言（C、Fortran、Java 等），并以另一种二进制机器代码格式程序作为输出语言。

C++ **模板元编程**（**TMP**）意味着使用模板在 C++中生成元程序。它有两个组成部分 - 必须定义一个模板，并且必须实例化已定义的模板。TMP 是图灵完备的，这意味着它至少在原则上有能力计算任何可计算的东西。此外，因为在 TMP 中变量都是不可变的（变量是常量），所以递归而不是迭代用于处理集合的元素。

为什么我们需要 TMP？因为它可以加速程序的执行时间！但在优化世界中并没有免费的午餐，我们为 TMP 付出的代价是更长的编译时间和/或更大的二进制代码大小。此外，并非每个问题都可以用 TMP 解决；它只在我们在编译时计算某些常量时才起作用；例如，找出小于常量整数的所有质数，常量整数的阶乘，展开常量次数的循环或迭代等。

从实际角度来看，模板元编程有能力解决以下三类问题：编译时计算、编译时优化，以及通过在运行时避免虚拟表查找，用静态多态性替换动态多态性。在接下来的小节中，我们将提供每个类别的示例，以演示元编程的工作原理。

# 编译时计算

通常，如果任务的输入和输出在编译时已知，我们可以使用模板元编程来在编译期间进行计算，从而节省任何运行时开销和内存占用。这在实时强度 CPU 利用项目中非常有用。

让我们来看一下计算`*n*!`的阶乘函数。这是小于或等于*n*的所有正整数的乘积，其中根据定义 0!=1。由于递归的概念，我们可以使用一个简单的函数来实现这一点，如下所示：

```cpp
//ch4_17_factorial_recursion.cpp
#include <iostream>
uint32_t f1(const uint32_t n) {
  return (n<=1) ? 1 : n * f1(n - 1);
}

constexpr uint32_t f2(const uint32_t n) {
  return ( n<=1 )? 1 : n * f2(n - 1);
}

int main() {
  uint32_t a1 = f1(10);         //run-time computation 
  uint32_t a2 = f2(10);         //run-time computation 
  const uint32_t a3 = f2(10);   //compile-time computation 
  std::cout << "a1=" << a1 << ", a2=" << a2 << std::endl;
}
```

`f1()`在运行时进行计算，而`f2()`可以根据使用情况在运行时或编译时进行计算。

同样，通过使用带有非类型参数的模板，它的特化和递归概念，这个问题的模板元编程版本如下：

```cpp
//ch4_18_factorial_metaprogramming.cpp
#include <iostream>
//define a primary template with non-type parameters
template <uint32_t n> 
struct fact {
  ***const static uint32_t*** value = n * fact<n - 1>::value;
  //use next line if your compiler does not support declare and initialize
  //a constant static int type member inside the class declaration 
  //enum { value = n * fact<n - 1>::value }; 
};

//fully specialized template for n as 0
template <> 
struct fact<0> { 
    const static uint32_t value = 1;
    //enum { value = 1 };
};
using namespace std;
int main() {
    cout << "fact<0>=" << fact<0>::value << endl;   //fact<0>=1
    cout << "fact<10>=" << fact<10>::value << endl; //fact<10>=3628800

    //Lab: uncomments the following two lines, build and run 
    //     this program, what are you expecting? 
    //uint32_t m=5;
    //std::cout << fact<m>::value << std::endl;
}
```

在这里，我们创建了一个带有非类型参数的类模板，与其他 const 表达式一样，`const static uint32_t`或枚举常量的值在编译时计算。这种编译时评估约束意味着只有 const 变量有意义。此外，由于我们只使用类，静态对象才有意义。

当编译器看到模板的新参数时，它会创建模板的新实例。例如，当编译器看到`fact<10>::value`并尝试使用参数为 10 创建`fact`的实例时，结果是必须创建`fact<9>`。对于`fact<9>`，它需要`fact<8>`等等。最后，编译器使用`fact<0>::value`（即 1），并且在编译时的递归终止。这个过程可以在以下代码块中看到：

```cpp
fact<10>::value = 10* fact<9>::value;
fact<10>::value = 10* 9 * fact<8>::value;
fact<10>::value = 10* 9 * 8 * fact<7>::value;
.
.
.
fact<10>::value = 10* 9 * 8 *7*6*5*4*3*2*fact<1>::value;
fact<10>::value = 10* 9 * 8 *7*6*5*4*3*2*1*fact<0>::value;
...
fact<10>::value = 10* 9 * 8 *7*6*5*4*3*2*1*1;
```

请注意，为了能够以这种方式使用模板，我们必须在模板参数列表中提供一个常量参数。这就是为什么如果取消注释代码的最后两行，编译器会投诉：`fact:template parameter n: m: a variable with non-static storage duration cannot be used as a non-type argument`。

最后，让我们通过简要比较**constexpr 函数**（CF）和 TMP 来结束本小节：

+   **计算时间**：CF 根据使用情况在编译时或运行时执行，但 TMP 只在编译时执行。

+   **参数列表**：CF 只能接受值，但 TMP 可以接受值和类型参数。

+   控制结构：CF 可以使用递归、条件和循环，但 TMP 只能使用递归。

# 编译时代码优化

尽管前面的例子可以在编译时计算常量整数的阶乘，但我们可以使用运行时循环来展开两个-*n*向量的点积（其中*n*在编译时已知）。传统长度-*n*向量的好处是可以展开循环，从而产生非常优化的代码。

例如，传统的点积函数模板可以以以下方式实现：

```cpp
//ch4_19_loop_unoolling_traditional.cpp
#include <iostream>
using namespace std;
template<typename T>
T dotp(int n, const T* a, const T* b)
{
  T ret = 0;
  for (int i = 0; i < n; ++i) {
      ret += a[i] * b[i];
  }
  return ret;
}

int main()
{
  float a[5] = { 1, 2, 3, 4, 5 };
  float b[5] = { 6, 7, 8, 9, 10 };
  cout<<"dot_product(5,a,b)=" << dotp<float>(5, a, b) << '\n'; //130
  cout<<"dot_product(5,a,a)=" << dotp<float>(5, a, a) << '\n'; //55
}
```

**循环展开**意味着如果我们可以优化`dotp()`函数内部的 for 循环为`a[0]*b[0] + a[1]*b[1] + a[2]*b[2] + a[3]*b[3] + a[4]*b[4]`，那么它将节省更多的运行时计算。这正是元编程在以下代码块中所做的：

```cpp
//ch4_20_loop_unroolling_metaprogramming.cpp
#include <iostream>

//primary template declaration
template <int N, typename T>    
class dotp {
public:
  static T result(T* a, T* b) {
    return (*a) * (*b) + dotp<N - 1, T>::result(a + 1, b + 1);
  }
};

//partial specialization for end condition
template <typename T>   
class dotp<1, T> {
public:
  static T result(T* a, T* b) {
    return (*a) * (*b);
  }
};

int main()
{
  float a[5] = { 1, 2, 3, 4, 5 };
  float b[5] = { 6, 7, 8, 9, 10 };
  std::cout << "dot_product(5,a,b) = " 
            << dotp<5, float>::result( a, b) << '\n'; //130
  std::cout << "dot_product(5,a,a) = " 
            << dotp<5,float>::result( a, a) << '\n'; //55
}
```

类似于阶乘元编程示例，在`dotp<5, float>::result(a, b)`语句中，实例化过程递归执行以下计算：

```cpp
dotp<5, float>::result( a, b)
= *a * *b + dotp<4,float>::result(a+1,b+1)
= *a * *b + *(a+1) * *(b+1) + dotp<3,float>::result(a+2,b+2)
= *a * *b + *(a+1) * *(b+1) + *(a+2) * *(b+2) 
  + dotp<2,float>::result(a+3,b+3)
= *a * *b + *(a+1) * *(b+1) + *(a+2) * *(b+2) + *(a+3) * *(b+3) 
  + dotp<1,float>::result(a+4,b+4)
= *a * *b + *(a+1) * *(b+1) + *(a+2) * *(b+2) + *(a+3) * *(b+3) 
  + *(a+4) * *(b+4)
```

由于*N*为 5，它递归调用`dotp<n, float>::results()`模板函数四次，直到达到`dotp<1, float>::results()`。由`dotp<5, float>::result(a, b)`计算的最终表达式显示在前面块的最后两行中。

# 静态多态

多态意味着多个函数具有相同的名称。动态多态允许用户在运行时确定要执行的实际函数方法，而静态多态意味着在编译时已知要调用的实际函数（或者一般来说，要运行的实际代码）。默认情况下，C++通过检查类型和/或参数的数量在编译时匹配函数调用与正确的函数定义。这个过程也被称为静态绑定或重载。然而，通过使用虚函数，编译器也可以在运行时进行动态绑定或覆盖。

例如，在以下代码中，虚函数`alg()`在基类 B 和派生类 D 中都有定义。当我们使用派生对象指针`p`作为基类的实例指针时，`p->alg()`函数调用将调用派生类中定义的`alg()`：

```cpp
//ch4_21_polymorphism_traditional.cpp
#include <iostream>
class B{
public:
    B() = default;
    virtual void alg() { 
        std::cout << "alg() in B"; 
    }
};

class D : public B{
public:
    D() = default; 
    virtual void alg(){
        std::cout << "alg() in D"; 
    }
};

int main()
{
    //derived object pointer p as an instance pointer of the base class
    B *p = new D();
    p->alg();       //outputs "alg() in D"
    delete p;
    return 0;
}
```

然而，在多态行为不变且可以在编译时确定的情况下，可以使用奇异递归模板模式（CRTP）来实现静态多态，模拟静态多态并在编译时解析绑定。因此，程序将在运行时摆脱对虚拟查找表的检查。以下代码以静态多态的方式实现了前面的示例：

```cpp
//ch4_22_polymorphism_metaprogramming.cpp
#include <iostream>
template <class D> struct B {
    void ui() {
        static_cast<D*>(this)->alg();
    }
};

struct D : B<D> {
    void alg() {
        cout << "D::alg()" << endl;
     }
};

int main(){
    B<D> b;
    b.ui();
    return 0;
}
```

总之，模板元编程的一般思想是让编译器在编译时进行一些计算。通过这种方式，可以在一定程度上解决运行时开销的问题。我们之所以能够在编译时计算某些东西，是因为在运行时之前，某些东西是常量。

如进一步阅读中提到的，C++ TMP 是一种非常强大的方法，可以在编译时执行计算任务。第一种方法并不容易，我们必须非常小心处理编译错误，因为模板树是展开的。从实际角度来看，boost 元编程库（MPL）是一个很好的起点。它以通用方式提供了用于算法、序列和元函数的编译时 TMP 框架。此外，C++17 中的新特性 std::variant 和 std::visit 也可以用于静态多态，适用于没有相关类型共享继承接口的情况。

# 总结

在本章中，我们讨论了 C++中与泛型编程相关的主题。从回顾 C 宏和函数重载开始，我们介绍了 C++模板的开发动机。然后，我们介绍了具有固定数量参数的类和函数模板的语法，以及它们的特化和实例化。自 C++11 以来，标准泛型函数和类模板已经接受可变参数模板。基于此，我们进一步将模板参数和参数分为三类：非类型模板参数/参数，类型模板参数/参数和模板模板参数/参数。

我们还学习了特性和模板元编程。作为模板特化的副产品，特性类可以为我们提供有关类型的更多信息。借助类型信息，最终可以实现实现通用算法的优化。类和/或函数模板的另一个应用是通过递归在编译时计算一些常量任务，这被称为模板元编程。它具有执行编译时计算和/或优化的能力，并且可以避免在运行时进行虚拟表查找。

现在，你应该对模板有了深入的了解。你应该能够在应用程序中创建自己的函数和类模板，并练习使用特性来优化你的算法，并使用模板元编程来进行编译时计算以进行额外的优化。

在下一章中，我们将学习有关内存和管理相关主题的内容，例如内存访问、分配和释放技术的概念，以及垃圾收集基础知识。这是 C++最独特的特性，因此每个 C++开发人员都必须了解。

# Questions

1.  宏的副作用是什么？

1.  什么是类/函数模板？什么是模板类/函数？

1.  什么是模板参数列表？什么是模板参数列表？一旦我们有了一个类模板，我们可以显式或隐式地实例化它。在什么样的情况下，显式实例化是必要的？

1.  在 C++中，多态是什么意思？函数重载和函数覆盖之间有什么区别？

1.  什么是类型特征？我们如何实现类型特征？

1.  在`ch4_5_class_template_implicit_inst_B.cpp`文件中，我们说隐式实例化生成了`X<int>`类，然后创建了`xi`对象并生成了`X<int>::f()`函数，但没有生成`X<int>::g()`。如何验证`X<int>::g()`没有生成？

1.  使用模板元编程解决*f(x,n) = x^n*的问题，其中*n*是一个 const，*x*是一个变量。

1.  将`ch4_17_loop_unrolling_metaprogramming.cpp`扩展到 n=10,100,10³,10⁴,10⁶，直到达到系统内存限制。比较编译时间、目标文件大小和运行 CPU 时间。

# Further reading

正如本章中所引用的，查看以下来源，以了解本章涵盖的更多内容：

+   Milner, R., Morris, L., Newey, M. (1975). *A Logic for Computable Functions with Reflexive and Polymorphic Types.* Proceedings of the Conference on Proving and Improving Programs.

+   [`www.research.ed.ac.uk/portal/en/publications/a-logic-for-computable-functions-with-reflexive-and-polymorphic-types(9a69331e-b562-4061-8882-2a89a3c473bb).html`](https://www.research.ed.ac.uk/portal/en/publications/a-logic-for-computable-functions-with-reflexive-and-polymorphic-types(9a69331e-b562-4061-8882-2a89a3c473bb).html)

+   *Curtis, Dorothy (2009-11-06). CLU home page.*Programming Methodology Group, Computer Science and Artificial Intelligence Laboratory. Massachusetts Institute of Technology.

+   [`www.pmg.csail.mit.edu/CLU.html`](http://www.pmg.csail.mit.edu/CLU.html)

+   *Technical Corrigendum for Ada 2012*, published by ISO. Ada Resource Association. 2016-01-29.

+   https://www.adaic.org/2016/01/technical-corrigendum-for-ada-2012-published-by-iso/

+   B. Stroustrup, *C++.*

+   [`dl.acm.org/doi/10.5555/1074100.1074189`](https://dl.acm.org/doi/10.5555/1074100.1074189)

+   *S. Meyers, Effective C++ 55 Specific Ways to Improve Your Programs and Designs (3rd Edition), Chapter 7.*

+   [`www.oreilly.com/library/view/effective-c-55/0321334876/`](https://www.oreilly.com/library/view/effective-c-55/0321334876/)

+   D. Gregor and J. Järvi (February 2008). *Variadic Templates for C++0x.*Journal of Object Technology. pp. 31–51

[`www.jot.fm/issues/issue_2008_02/article2.pdf`](http://www.jot.fm/issues/issue_2008_02/article2.pdf)

+   [`www.boost.org/`](https://www.boost.org/) for type traits, unit testing etc.

+   [`www.ibm.com/support/knowledgecenter/ssw_ibm_i_72/rzarg/templates.htm`](https://www.ibm.com/support/knowledgecenter/ssw_ibm_i_72/rzarg/templates.htm) for generic templates discussions.

+   [`stackoverflow.com/questions/546669/c-code-analysis-tool`](https://stackoverflow.com/questions/546669/c-code-analysis-tool) for code analysis tools.

+   [`en.cppreference.com`](https://en.cppreference.com) for template explicit instantiations.

+   [`www.cplusplus.com`](http://www.cplusplus.com) for library references and usage examples.

+   [`www.drdobbs.com/cpp/c-type-traits/184404270`](http://www.drdobbs.com/cpp/c-type-traits/184404270) for type-traits.

+   [`accu.org/index.php/journals/424`](https://accu.org/index.php/journals/424) for template metaprogramming.

+   [`en.wikipedia.org/wiki/Template_metaprogramming`](https://en.wikipedia.org/wiki/Template_metaprogramming) 用于模板元编程。

+   K. Czarnecki, U. W. Eisenecker, *Generative Programming: Methods, Tools, and Applications*, 第十章。

+   N. Josuttis; D. Gregor 和 D. Vandevoorde, *C++ Templates: The Complete Guide (2nd Edition)*, Addison-Wesley Professional 2017。


# 第五章：深入 STL 中的数据结构和算法

您可以在此章节中找到使用的源文件[`github.com/PacktPublishing/Expert-CPP`](https://github.com/PacktPublishing/Expert-CPP)。

技术要求

内存分配和释放始于对函数的简单调用。调用函数通常意味着向其传递参数。函数需要空间来存储这些参数。为了简化生活，这些都是自动处理的。当我们在代码中声明对象时，同样会发生自动分配。它们的生命周期取决于它们声明的范围。无论何时它们超出范围，它们都将被自动释放。大多数编程语言为动态内存提供类似的自动释放功能。动态分配的内存 - 与自动分配相对 - 是程序员用来识别根据需求请求新内存的代码部分的术语。例如，在存储客户请求列表的程序中，当客户数量增加时会使用这种功能来请求新的内存空间。

大多数语言提供了简化的方法来访问动态内存，而不必担心其释放策略，将繁重的工作留给运行时支持环境。C++程序员必须处理内存管理的低级细节。无论是由于语言的哲学、结构还是年龄，C++都没有提供高级内存管理功能。因此，对内存结构及其管理的深入理解对于每个 C++程序员来说都是必不可少的。让我们在本章中揭示内存和适当的内存管理技术背后的奥秘。

我们将使用电路、继电器和逻辑门来设计一个能够存储位的简单设备。本节的目的是了解内存在其最低级别的结构。在本章中，我们将涵盖以下主题：

+   什么是内存，我们如何在 C++中访问它？

+   很难描述设备如何存储这些变量。为了在那个神奇的过程中投下一些光芒，让我们试着设计一个存储一点信息的设备。

+   内存管理技术和习惯用法

+   详细的内存分配

# 垃圾收集基础知识

使用`g++`编译器和选项`-std=c++2a`编译本章中的示例。

在最低级别的表示中，内存是一个存储位状态的设备。假设我们正在发明一个可以存储单个位信息的设备。现在，这似乎既毫无意义又神奇。毫无意义是因为发明已经在很久以前就已经发明了。神奇是因为程序员现在有幸福的稳定多功能环境，提供了大量的库、框架和工具来创建程序，甚至不需要了解它们的内部工作。声明变量或分配动态内存已经变得非常容易，就像下面的代码片段所示：

# 在 C++中，内存管理是有代价的。关心的程序员经常抱怨 C++因为它需要手动内存管理。而像 C#和 Java 这样的语言使用自动内存管理，使得程序运行速度比它们的 C++对应程序慢。手动内存管理经常容易出错和不安全。正如我们在前几章中已经看到的，程序代表数据和指令。几乎每个程序都在某种程度上使用计算机内存。很难想象一个有用的程序不需要内存分配。

理解计算机内存

```cpp
int var;
double* pd = new double(4.2);
```

为了在内存管理的*类型*之间进行某种区分，无论是自动还是手动，程序员都使用内存分段。程序操作多个内存段，堆栈、堆、只读段等等，尽管它们都具有相同的结构并且是同一虚拟内存的一部分。

# 设计一个内存存储设备

内存管理和智能指针

这是一个简单的电路示例，您可能在物理课上熟悉：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/e049c87e-55a0-431d-96bf-28b605e4c07e.png)

它由一根连接电池和灯泡的**导线**组成。**导线**上有一个控制灯泡状态的**开关**。当开关关闭时，灯泡亮起，否则灯泡熄灭。我们将在这个电路中添加两个 NOR 逻辑元件。NOR 是非或的缩写。通常用以下方式表示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/4072ad42-c9a2-495f-aee5-06d736ddb9c9.png)

它有两个输入（导线引入元件），每个代表一个电信号。如果两个输入都为 0，我们说输出（从元件出来的导线）为 1。这就是为什么我们称它为*非或*，因为如果任何一个输入为 1，OR 元件就会输出 1。前述 NOR 元件只是使用两个继电器构建的。继电器是使用电磁铁来闭合和打开触点的开关。看看下面的图表：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/99bb5ce8-b8cc-4b27-b767-ec65c76b7ddc.png)

当**继电器**的两个**开关**关闭（意味着**继电器**正在工作并拉下电路的**开关**）时，灯泡是*关闭*的。当我们将**继电器**的两个**开关**移动到开放位置时，灯泡就会*亮起*。上图是描述 NOR 门的一种方式。此时，我们可以使用电线、灯泡、电池和继电器创建逻辑元件。现在让我们看看两个 NOR 元件的奇怪组合，引发了一个有趣的发现：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/767e57ea-e066-4eef-b2eb-afc2868604c2.png)

上图是典型的**R-S 触发器**的表示。**R**代表*复位*，**S**代表*设置*。前述方案构建的设备可以存储一个位。输出**Q**是我们可以读取设备内容的导线。如果我们设置触发器来存储位，输出将为 1。您应该仔细检查图表，并想象逐个或同时向其输入传递信号，并查看**Q**的输出。当输入**S**为 1 时，**Q**变为 1。当**R**为 1 时，**Q**变为 0。这样我们就可以*设置*或*复位*位。只要我们向设备提供电流，它就会存储位。

现在想象一下，将之前设计的许多设备相互连接，以便存储多于一个位的信息。这样，我们可以构建复杂的内存设备，存储字节甚至**千字节**（**KB**）的数据。

前述设备类似于在晶体管发明之前计算机中使用的设备。晶体管是一种更小的设备，能够存储位。晶体管有不同的类型。现代设备不使用继电器；相反，它们集成了数百万个晶体管来存储和操作数据。**中央处理单元**（**CPU**）寄存器就是利用晶体管存储指定数量位的设备的一个例子。通常，通用寄存器最多可以存储 64 位数据。但是，您不能仅使用寄存器来存储所有程序和数据。计算机内存的组织要复杂得多。现在让我们从更高层次的角度来研究计算机内存的层次结构。

# 从更高层次的角度理解计算机内存

了解计算机内存和数据存储的细节对于编写专业程序至关重要。当程序员提到“内存”一词时，大多数情况下他们指的是虚拟内存。虚拟内存是由操作系统（OS）支持的抽象，用于控制和为进程提供内存空间。每个进程都有其地址空间，表示为几个段的集合。我们在《使用 C++进行低级编程》的第二章中讨论了有哪些内存段，以及给定程序如何使用每个内存段。从程序员的角度来看，访问内存空间主要限于对象声明和使用。无论我们在堆栈、堆还是静态内存中声明对象，我们都访问相同的内存抽象——虚拟内存。虽然复杂，但虚拟内存使生活变得更加轻松。直接使用物理内存更加困难，尽管这是程序员技能的重大进步。你至少应该知道有哪些内存存储单元，以及如何利用这些知识来编写更好的代码。

在本节中，我们已经讨论了物理内存层次结构。我们称之为“层次结构”，因为较低级别的每个内存单元提供更快的访问速度，但空间较小。每个连续更高级别的内存提供更多的空间，但访问速度较慢。

我们讨论物理内存层次结构是因为它将帮助我们设计更好的代码。了解每个级别的内存如何工作可以提高我们作为程序员的水平，并使我们能够更好地组织数据操作。以下图表说明了内存层次结构：

（图片）

寄存器是放置在 CPU 中的最快可访问的内存单元。寄存器的数量是有限的，因此我们无法将所有程序数据都保存在其中。另一方面，动态 RAM 能够存储程序的各种数据。由于其物理结构和与 CPU 的距离，从 DRAM 中访问数据需要更长的时间。CPU 通过数据总线访问 DRAM，数据总线是一组在 CPU 和 DRAM 之间传输数据的导线。为了向 DRAM 控制器发出读取或写入数据的信号，CPU 使用控制总线。我们将 DRAM 称为“主内存”。让我们详细看看内存层次结构。

# 寄存器

寄存器保存固定数量的数据。CPU 字长通常由寄存器的最大长度定义，例如八字节或四字节。我们无法直接从 C++程序中访问寄存器。

C++支持使用`asm`声明嵌入汇编代码，例如`asm("mov edx, 4")`。这是一种特定于平台的人为代码增强，因此我们不建议使用它。

在较早版本的语言中，我们可以在声明变量时使用`register`关键字：

```cpp
register int num = 14;
```

修饰符指定编译器将变量存储在寄存器中。这样，它给程序员一种虚假的代码优化感觉。

编译器是将高级 C++代码转换为机器代码的复杂工具。在翻译过程中，代码经历了多次转换，包括代码优化。当程序员对代码的一部分应用“技巧”来强制编译器优化时，编译器将其视为建议而不是命令。

例如，在循环中访问变量，如果将该变量放在寄存器中而不是 DRAM 中，访问速度将更快。例如，以下循环一百万次访问对象：

```cpp
auto number{42};
for (int ix = 0; ix < 10000000; ++ix) {
 int res{number + ix};
  // do something with res
}
```

正如我们所知，`number`具有自动存储期限（与`auto`关键字无关），并放置在堆栈上。堆栈是虚拟内存中的一个段，虚拟内存是对物理 DRAM 的抽象。从寄存器中访问对象比从 DRAM 中访问对象要快得多。假设从 DRAM 中读取`number`的值比从`寄存器`中读取的值慢五倍。显然，通过使用`寄存器`关键字来优化前面的循环似乎是显而易见的，如下所示：

```cpp
register auto number{42};
// the loop omitted for code brevity
```

然而，现在编译器进行了更好的优化，因此对修改器的需求随着时间的推移而减弱，现在已经是一个不推荐使用的语言特性。更好的优化是完全摆脱`number`对象。

例如，以下代码表示使用实际值而不是通过驻留在 DRAM 中的变量访问该值的编译优化版本：

```cpp
for (int ix = 0; ix < 1000000; ++ix) {
 int res{42 + ix};
  // do something with res
}
```

尽管前面的示例可以说是简单的，但我们应该考虑在编译过程中进行的编译器优化。

发现寄存器可以提高我们对程序执行细节的理解。关键是 CPU 执行的所有操作都是通过寄存器进行的，包括 CPU 应该解码和执行的指令都是使用特定的寄存器访问的，通常称为**指令指针**。当我们运行程序时，CPU 访问其指令并解码和执行它们。从主存中读取数据和向内存写入数据是通过从寄存器复制数据来执行的。通常，通用寄存器用于在 CPU 对其执行操作时临时保存数据。以下图表描述了**CPU**及其通过总线与主存的交互的抽象视图：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/b98cbe03-4c6c-4b6c-acb8-5079eee59237.png)

正如您所看到的，CPU 和 DRAM 之间的通信是通过各种总线进行的。在第二章中，我们讨论了 C++程序的低级表示 - 您应该快速查看以更好地理解以下示例。

现在，让我们看看寄存器的运行情况。以下 C++代码声明了两个变量，并将它们的和存储在第三个变量中：

```cpp
int a{40}, b{2};
int c{a + b};
```

要执行求和指令，CPU 将变量`a`和`b`的值移入其寄存器。在计算总和后，它将结果移入另一个寄存器。程序的汇编伪代码表示类似于以下内容：

```cpp
mov eax, a
mov ebx, b
add eax, ebx
```

编译器不一定要生成将每个变量映射到一个寄存器的代码 - 寄存器的数量是有限的。您只需要记住，应该将经常访问的变量保持足够小，以适应其中一个寄存器。对于较大的对象，高速缓存内存会发挥作用。让我们看看。

# 高速缓存内存

缓存的概念在编程和计算机系统中很常见。在浏览器中加载的图像会被缓存，以避免在用户再次访问网站时向 Web 服务器发出进一步的请求以下载它。缓存使程序运行更快。这个概念可以以许多形式利用，包括在单个函数中。例如，以下递归函数计算一个数字的阶乘：

```cpp
long factorial(long n) {
  if (n <= 1) { return 1; }
  return n * factorial(n - 1);
}
```

该函数不记得其先前计算的值，因此以下调用分别导致五次和六次递归调用：

```cpp
factorial(5); // calls factorial(4), which calls factorial(3), and so on
factorial(6); // calls factorial(5), which calls factorial(4), and so on
```

我们可以通过将它们存储在全局可访问的变量中来缓存每一步已计算的值。

```cpp
std::unordered_map<long, long> cache;

long factorial(long n) {
  if (n <= 1) return 1;
 if (cache.contains(n)) return cache[n];
 cache[n] = n * factorial(n - 1);
 return cache[n];
}
```

修改进一步调用函数的优化：

```cpp
factorial(4);
// the next line calls factorial(4), stores the result in cache[5], which then calls factorial(3)
// and stores the result in cache[4] and so on
factorial(5);
factorial(6); // calls the factorial(5) which returns already calculated value in cache[5]
```

与缓存概念使阶乘函数运行更快的方式相同，CPU 内部实际存储设备名为**缓存**。该设备存储最近访问的数据，以便使对该数据的进一步访问更快。以下图表描述了 CPU 内部的**寄存器**和**缓存内存**：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/3ab977f8-8e12-4e36-b903-b72c9da9b7ff.png)

缓存的大小通常范围从 2KB 到 64KB（很少为 128KB）。虽然对于诸如 Photoshop 之类的应用程序来说，缓存的大小可能远远不够，因为图像数据的大小可能远远大于缓存本身，但在许多情况下，它确实会有所帮助。例如，假设我们在一个向量中存储了超过 1000 个数字：

```cpp
std::vector<int> vec;
vec.push_back(1);
...
vec.push_back(9999);
```

以下代码打印向量项：

```cpp
for (auto it: vec) {
  std::cout << it;
}
// 1
// 2
// 3
// ...
// 9999
```

假设要打印该项，**CPU**将其从内存复制到 rax 寄存器，然后调用运算符`<<`，将 rax 的值打印到屏幕上。在循环的每次迭代中，**CPU**将向 rax 寄存器复制向量的下一项，并调用函数打印其值。每次复制操作都需要**CPU**将该项的地址放在**地址总线**上，并将**控制总线**设置为读模式。**DRAM**微控制器通过地址总线接收到的地址访问数据，并将其值复制到数据总线，从而将数据发送给**CPU**。**CPU**将值传递给 rax 寄存器，然后执行指令打印其值。下图显示了**CPU**和**DRAM**之间的交互：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/38e99ee6-c6b8-4007-8a8b-3705975066fd.png)

为了优化循环，CPU 保持了**数据局部性**的概念，即将整个向量复制到缓存中，并从缓存中访问向量项，省略了对 DRAM 的不必要请求。在下图中，您可以看到通过数据总线从 DRAM 接收的数据然后存储在**缓存内存**中：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/a638de34-c3d8-4c57-9edc-078fb8563b94.png)

存储在 CPU 中的缓存被称为**一级**（**L1**）**缓存**。这是容量最小的缓存，位于 CPU 内部。许多体系结构都有**二级**（**L2**）**缓存**，它位于 CPU 外部（尽管比主存储器更接近），并且与 DRAM 的访问方式相同。L2 缓存和 DRAM 之间的区别在于物理结构和数据访问模式。L2 缓存代表**静态 RAM**（**SRAM**），比 DRAM 更快，但也更昂贵。

一些运行时环境在实现垃圾回收时利用了缓存的概念。它们根据对象的生命周期将对象分成不同的类别，生命周期最短的对象，比如在代码的局部范围内分配的对象，被放入缓存中以便更快地访问和释放。

新的缓存级别用作较低级别的缓存。例如，L2 缓存用作 L1 缓存的缓存内存。当 CPU 遇到缓存未命中时，它会请求 L2 缓存，依此类推。

# 主存储器

DRAM 的物理结构迫使它刷新其电荷以保持数据稳定，而 SRAM 不需要像 DRAM 那样刷新。我们之所以称 DRAM 为主存储器，主要是因为程序加载到其中；操作系统维护虚拟内存并将其映射到 DRAM。所有实际的工作都是通过主存储器进行的。

正如我们之前讨论的，主存储器代表了一系列可寻址的数据字节。每个字节都有自己独特的地址，并且可以使用该地址进行访问。我们之前提到过，CPU 将数据的地址放在地址总线上，从而让 DRAM 微控制器获取请求的数据并通过数据总线发送出去。

正如我们所知，操作系统引入了虚拟内存作为对物理内存的抽象。它将虚拟内存的内容映射到物理内存，这涉及到 CPU 的**转换旁路缓存**（**TLB**）。TLB 是另一种缓存内存的形式：它存储了**虚拟内存**到**物理内存**的最近转换，从而为将来的请求进行缓存。如下图所示，**CPU**与**TLB**协调以正确地将虚拟地址转换为物理地址：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/38b916ec-a8a1-40f4-aa32-f99bc44eaebf.png)

尽管内存管理很复杂，但操作系统为我们提供了一个足够简单的抽象来管理程序所需的内存。我们有能力使用堆栈自动分配内存，也可以在堆上动态分配内存。自动内存分配实际上并不涉及太多问题和困难；我们只需声明对象，它们就会放在堆栈上，然后在执行离开作用域时自动删除。在动态内存的情况下（不要与前面提到的硬件 DRAM 混淆），分配和释放都应该手动完成，这会导致可能导致内存泄漏的错误。

# 永久存储

当我们关闭计算机时，主内存的内容会被擦除（因为电荷不再刷新）。为了在断电时永久存储数据，计算机配备了硬盘驱动器（HDD）或固态硬盘驱动器（SSD）。从程序员的角度来看，永久存储用于存储程序及其必要的数据。我们已经知道，为了运行程序，它应该被加载到主内存中，也就是从硬盘驱动器复制到 DRAM 中。操作系统使用加载器处理这个过程，并在内存中创建一个程序映像，通常称为进程。当程序完成或用户关闭它时，操作系统将进程的地址范围标记为可用。

假设我们使用文本编辑器在学习 C++时写笔记。在编辑器中键入的文本将驻留在主内存中，除非我们将其保存在硬盘驱动器上。这一点很重要，因为大多数程序会跟踪最近的用户活动，并允许用户修改程序设置。为了保持用户修改后的设置，即使程序重新启动，程序会将它们存储为硬盘上的单独的*设置*文件。下次程序运行时，它首先从硬盘驱动器中读取相应的设置文件，然后更新自身以应用最近的设置修改。

通常，永久存储的容量比主内存大得多，这使得可以将硬盘驱动器用作虚拟内存的备份。操作系统可以维护虚拟内存并伪装其大小，使其比物理 DRAM 更大。例如，启动几个重量级应用程序可能会迅速耗尽 DRAM 的最大容量。然而，操作系统仍然可以通过将其额外的空间备份到硬盘驱动器来维护更大的虚拟内存。当用户在应用程序之间切换时，操作系统将虚拟内存的超出字节复制到硬盘驱动器，并将当前运行的应用程序映射到物理内存。

这使得程序和操作系统运行得更慢，但允许我们保持它们打开，而不必担心主内存的有限大小。现在让我们深入了解 C++中的内存管理。

# 内存管理的基础

大多数情况下，内存管理中出现的问题是程序员忘记释放内存空间。这导致内存泄漏。内存泄漏是几乎每个程序中普遍存在的问题。当程序请求新的内存空间来存储其数据时，操作系统会将提供的空间标记为“忙碌”。也就是说，程序的任何其他指令或任何其他程序都无法请求该忙碌的内存空间。当程序部分完成内存空间时，理想情况下，它必须通知操作系统去除忙碌标签，以便为其他程序释放空间。一些语言提供对动态分配内存的自动控制，使程序员只需担心应用程序的逻辑，而不必不断担心释放内存资源。然而，C++假设程序员是负责和聪明的（这并不总是事实）。动态分配的内存管理是程序员的责任。这就是为什么语言提供了“new”和“delete”运算符来处理内存空间，其中 new 运算符分配内存空间，而 delete 运算符释放内存空间。换句话说，处理动态分配内存的理想代码如下所示：

```cpp
T* p = new T(); // allocate memory space
p->do_something(); // use the space to do something useful
delete p; // deallocate memory space
```

忘记调用 delete 运算符会使分配的内存空间“永远忙碌”。所谓的“永远”，是指程序运行的时间。现在想象一下一个总是在用户计算机上打开的网络浏览器。这里发生的内存泄漏可能会导致内存饥饿，最终用户不得不重新启动程序，甚至更糟糕的是重新启动操作系统。

这个问题适用于我们使用的任何资源，无论是我们忘记关闭的文件还是套接字（关于套接字的更多信息请参见第十二章，*网络和安全*）。为了解决这个问题，C++程序员使用**资源获取即初始化**（**RAII**）习惯用法，该习惯用法规定资源应该在初始化时获取，这样可以在以后正确释放它。让我们看看它的实际应用。

# 内存管理的一个例子

考虑以下函数，该函数动态分配了一个包含 420 个`shorts`的数组，从用户输入中读取它们的值，按升序打印它们，并释放数组：

```cpp
void print_sorted() {
  short* arr{new short[420]};
  for (int ix = 0; ix < 420; ++ix) {
    std::cin >> arr[ix];
  }
  std::sort(arr, arr + 420);
  for (int ix = 0; ix < 420; ++ix) {
    std::cout << arr[ix];
  }
  delete arr; // very bad!
}
```

在前面的代码中，我们已经犯了一个错误，即使用错误的`delete`运算符来释放内存。要释放数组，我们必须使用`delete[]`运算符，否则代码会导致内存泄漏。以下是我们如何说明数组的分配：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/073fb3c2-f36b-4002-bfc3-fecbeb34ecdf.png)

假设我们使用`delete`而不是`delete[]`来释放空间。它将把`arr`视为一个 short 指针，因此将删除从`arr`指针中包含的地址开始的前两个字节，如下图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/50d84dee-769a-47cc-b579-5967570ec8ed.png)

现在我们从 420 个项目中移除了第一个项目，剩下的 419 个`shorts`保持在堆上不变。每当我们需要堆上的新空间时，包含 419 个“untouchables”的小部分将永远不会被再次重用。虽然 new 和 delete 运算符的家族是实现定义的，但我们不应该真的指望最好的实现来避免内存泄漏。

让我们修改前面的代码，正确释放数组的分配内存，并确保消除输入负数的可能性：

```cpp
void print_sorted() {
 short* arr{new short[420]};
  for (int ix = 0; ix < 420; ++ix) {
    std::cin >> arr[ix];
 if (arr[ix] < 0) return;
  }
  std::sort(arr, arr + 420);
  // print the sorted array, code omitted for brevity
 delete[] arr;
}
```

前面的修改是可能的内存泄漏的另一个例子，尽管我们显然为了简单起见写了丑陋的代码。关键是，每当用户输入一个负数时，函数就会返回。这让我们有 420 个应该被释放的`shorts`孤立。然而，分配的内存的唯一访问是`arr`指针，它在堆栈上声明，因此当函数返回时它将被自动删除（指针变量，而不是指向它的内存空间）。为了消除内存泄漏的可能性，我们应该在函数退出之前简单地调用`delete[]`运算符：

```cpp
void print_sorted() {
 short* arr{new short[420]};
  for(int ix = 0; ix < 420; ++ix) {
    std::cin >> arr[ix];
 if (arr[ix] < 0) {
 delete[] arr;
 return;
 }
  }
  // sort and print the sorted array, code omitted for brevity
 delete[] arr;
}
```

代码变得有些丑陋，但它修复了内存泄漏。如果我们进一步修改函数并使用第三方库函数来对数组进行排序：

```cpp
import <strange_sort.h>;

void print_sorted() {
  short* arr{new short[420]};
  for (...) { /* code omitted for brevity */ }
 strange_sort::sort(arr, arr + 420);
  // print the sorted array, code omitted for brevity
  delete[] arr;
}  
```

事实证明，`strange_sort::sort`在数组项的值超过 420 时会抛出异常（毕竟这就是一个奇怪的排序）。如果异常没有被捕获，它将冒泡到调用者函数，除非它在某处被捕获，或者程序崩溃。未捕获的异常导致堆栈展开，这导致`arr`变量（指针）的自动销毁，因此我们面临另一个内存泄漏的可能性。为了解决这个问题，我们可以将`strange_sort::sort`包装在 try-catch 块中：

```cpp
try {
  strange_sort::sort(arr, arr + 420);
} catch (ex) { delete[] arr; }
```

C++程序员不断寻求处理内存泄漏的方法，例如 RAII 习惯用法和智能指针，我们将在接下来的章节中讨论。

# 使用智能指针

有许多支持自动垃圾收集的语言。例如，为对象获取的内存由运行时环境跟踪。当具有对它的引用的对象超出范围时，它将释放内存空间。例如，考虑以下情况：

```cpp
// a code sample of the language (not-C++) supporting automated garbage collection
void foo(int age) {
  Person p = new Person("John", 35);
  if (age <= 0) { return; }
  if (age > 18) {
   p.setAge(18);
  }
  // do something useful with the "p"
}
// no need to deallocate memory manually
```

在前面的代码块中，`p`引用（通常，垃圾收集语言中的引用类似于 C++中的指针）指的是`new`运算符返回的内存位置。自动垃圾收集器管理`new`运算符创建的对象的生命周期。它还跟踪对该对象的引用。每当对象没有引用时，垃圾收集器就会释放其空间。通过在 C++中使用 RAII 习惯用法，可以实现类似的功能。让我们看看它的实际应用。

# 利用 RAII 习惯用法

如前所述，RAII 习惯用法建议在初始化时获取资源。看看下面的类：

```cpp
template <typename T>
class ArrayManager {
public:
  ArrayManager(T* arr) : arr_{arr} {}
  ~ArrayManager() { delete[] arr_; }

  T& operator[](int ix) { return arr_[ix]; }

  T* raw() { return arr_; }
};
```

`print_sorted`函数现在可以使用`ArrayManager`来正确释放分配的数组：

```cpp
void print_sorted() {
 ArrayManager<short> arr{new short[420]};
  for (int ix = 0; ix < 420; ++ix) {
    std::cin >> arr[ix];
  }
  strange_sort::sort(arr.raw(), arr.raw() + 420);
  for (int ix = 0; ix < 420; ++ix) {
    std::cout << arr[ix];
  }
}
```

我们建议使用标准容器，如`std::vector`，而不是`ArrayManager`，尽管它是 RAII 应用的一个很好的例子：在初始化时获取资源。我们创建了一个`ArrayManager`的实例，并用内存资源对其进行了初始化。从那时起，我们可以忘记它的释放，因为实际的释放发生在`ArrayManager`的析构函数中。由于我们在堆栈上声明了`ArrayManager`实例，当函数返回或发生未捕获的异常时，它将被自动销毁，并且析构函数将被调用。

在这种情况下，使用标准容器是首选，因此让我们为单个指针实现 RAII 习惯用法。以下代码动态为`Product`实例分配内存：

```cpp
Product* apple{new Product};
apple->set_name("Red apple");
apple->set_price(0.42);
apple->set_available(true);
// use the apple
// don't forget to release the resource
delete apple;
```

如果我们将 RAII 习惯用法应用于前面的代码，它将在代码执行的适当点释放资源：

```cpp
ResourceManager<Product> res{new Product};
res->set_name("Red apple");
res->set_price(0.42);
res->set_available(true);
// use the res the way we use a Product
// no need to delete the res, it will automatically delete when gets out of the scope
```

`ResourceManager`类还应该重载运算符`*`和`->`，因为它必须像指针一样行为，以便正确获取和管理指针：

```cpp
template <typename T>
class ResourceManager {
public:
  ResourceManager(T* ptr) : ptr_{ptr} {}
  ~ResourceManager() { delete ptr_; }

 T& operator*() { return *ptr_; }
 T* operator->() { return ptr_; }
};
```

`ResourceManager`类关心 C++中的智能指针的概念。C++11 引入了几种类型的智能指针。我们将它们称为*智能*，是因为它们包装资源并管理其自动释放。这仅仅是因为当对象被设置为销毁时，对象的析构函数将被调用。也就是说，我们通过具有自动存储期的对象操作动态分配的空间。当处理程序对象超出范围时，其析构函数执行必要的操作以释放底层资源。

然而，智能指针可能带来额外的问题。在前面段落讨论的简单智能指针中，最终会出现几个问题。例如，我们没有处理`ResourceManager`的复制：

```cpp
void print_name(ResourceManager<Product> apple) {
  std::cout << apple->name();
}

ResourceManager<Product> res{new Product};
res->set_name("Red apple");
print_name(res);
res->set_price(0.42);
// ...
```

前面的代码会导致未定义的行为。以下图表显示了伪装的问题：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/8a9ce9cc-43a7-4a58-a6f1-53b386cae052.png)

**res**和**apple**都获取了相同的资源。每当它们中的一个超出范围（**apple**），底层资源就会被释放，这会导致另一个`ResourceManager`实例拥有悬空指针。当另一个`ResourceManager`实例超出范围时，它将尝试两次删除指针。通常，程序员会意识到在特定情况下需要哪种智能指针。这就是为什么 C++提供了几种类型的智能指针，我们将进一步讨论。要在程序中使用它们，您应该导入`<memory>`头文件。

# std::unique_ptr

与我们之前实现的`ResourceManager`实例类似，`std::unique_ptr`代表了一个基本的智能指针。例如，要使用这个智能指针来管理`Product`对象，我们这样做：

```cpp
std::unique_ptr<Product> res{new Product};
res->set_name("Red apple");
// res will delete its acquired resource when goes out of scope
```

请注意我们如何访问`Product`成员函数`set_name`。我们将`res`对象视为具有类型`Pointer*`的东西。

`unique_ptr`之所以被称为 unique，是因为它提供了严格所有权的语义-它有责任销毁所获得的对象。更有趣的是，`unique_ptr`不能被复制。它没有复制构造函数或赋值运算符。这就是为什么它的**所有权**是*严格*的。当然，这并不意味着我们不能移动`unique_ptr`类。在这种情况下，我们完全将所有权转移到唯一指针的另一个实例。

智能指针的主要要求之一是保持它们的轻量级。我们肯定会同意这一点。虽然`unique_ptr`是一个完整的类，有几个成员函数，但它不会通过附加数据成员来“污染”。它只是一个围绕分配对象的原始指针的包装器。我们可以通过调用`unique_ptr`的`release()`成员函数来访问该原始指针，如下所示：

```cpp
Product* p = res.release();
// now we should delete p manually to deallocate memory
```

请注意，`release()`函数不会调用删除运算符。它只是归还所有权。调用`release()`函数后，`unique_ptr`不再拥有资源。要重用已拥有资源的`unique_ptr`，您应该使用`reset()`成员函数。它调用底层指针的删除运算符并“重置”唯一指针以供进一步使用。另一方面，如果要获取底层对象而不释放所有权，应该调用`get()`成员函数：

```cpp
std::unique_ptr<Product> up{new Product()};
Product* p = res.get();
// now p also points to the object managed by up
```

我们无法在以下情况中使用`unique_ptr`类，因为它无法被复制：

```cpp
// Don't do this
void print_name(std::unique_ptr<Product> apple) {
  std::cout << apple->name();
}
std::unique_ptr<Product> res{new Product};
res->set_name("Red apple");
print_name(res); // bad code
res->set_price(0.42);
// ...
```

然而，这并不是我们在前面的代码中寻找的。您可以将前面的代码视为糟糕的设计，因为它混淆了所有权细节。让我们继续讨论 C++中的下一个智能指针，它解决了将`unique_ptr`传递给函数的问题。

# std::shared_ptr 和 std::weak_ptr

我们需要一个提供*共享所有权*的智能指针。我们需要的东西在 C++11 中被引入，称为`std::shared_ptr`。实现具有共享所有权的智能指针更难，因为您应该注意正确释放资源。例如，当前面代码块中的`print_name()`函数完成其工作时，它的参数和局部对象将被销毁。销毁智能指针会导致所拥有的资源得到适当的释放。智能指针如何知道该资源是否仍然被另一个智能指针所拥有呢？其中一个流行的解决方案是保持对资源的引用计数。`shared_ptr`类也是如此：它保持指向底层对象的指针的数量，并在使用计数变为 0 时删除它。因此，几个共享指针可以拥有相同的对象。

现在，我们刚才讨论的示例应该重写如下：

```cpp
void print_name(std::shared_ptr<Product> apple) {
  std::cout << apple->name();
}
std::shared_ptr<Product> res{new Product};
res->set_name("Red apple");
print_name(res);
res->set_price(0.42);
// ...
```

调用`print_name()`函数后，共享指针的使用计数增加了 1。当函数完成其工作时，使用计数将减少 1，但托管对象不会被释放。这是因为`res`对象尚未超出范围。让我们稍微修改示例以打印对共享对象的引用计数：

```cpp
void print_name(std::shared_ptr<Product> apple) {
  std::cout << apple.use_count() << " eyes on the " << apple->name();
}

std::shared_ptr<Product> res{new Product};
res->set_name("Red apple");
std::cout << res.use_count() << std::endl;
print_name(res);
std::cout << res.use_count() << std::endl;
res->set_price(0.42);
// ...
```

前面的代码将在屏幕上打印如下内容：

```cpp
1
2 eyes on the Red apple
1
```

当最后一个`shared_ptr`超出范围时，它也会销毁底层对象。然而，在共享指针之间共享对象时，您应该小心。以下代码显示了共享所有权的一个明显问题：

```cpp
std::shared_ptr<Product> ptr1{new Product()};
Product* temp = ptr1.get();
if (true) {
  std::shared_ptr<Product> ptr2{temp};
  ptr2->set_name("Apple of truth");
}
ptr1->set_name("Peach"); // danger!
```

`ptr1`和`ptr2`都指向同一个对象，但它们彼此不知道。因此，当我们通过`ptr2`修改`Product`对象时，它会影响`ptr1`。当`ptr2`超出范围（在`if`语句之后）时，它将销毁底层对象，而该对象仍然被`ptr1`拥有。这是因为我们通过将原始的`temp`指针传递给它，使`ptr2`拥有了该对象。`ptr1`无法跟踪到这一点。

只能使用`std::shared_ptr`的复制构造函数或赋值运算符来共享所有权。这样，我们避免了如果它正在被另一个`shared_ptr`实例使用时删除对象。共享指针使用控制块实现共享所有权。每个共享指针持有两个指针，一个指向它管理的对象，一个指向控制块。控制块表示动态分配的空间，包含资源的使用计数。它还包含对于`shared_ptr`至关重要的其他几个东西，例如资源的`allocator`和`deleter`。我们将在下一节介绍分配器。`deleter`通常是常规的`delete`运算符。

控制块还包含弱引用的数量。这是因为所拥有的资源也可能被弱指针指向。`std::weak_ptr`是`std::shared_ptr`的小兄弟。它指的是由`shared_ptr`实例管理的对象，但并不拥有它。`weak_ptr`是一种访问和使用由`shared_ptr`拥有的资源而不拥有它的方法。然而，有一种方法可以使用`lock()`成员函数将`weak_ptr`实例转换为`shared_ptr`。

`unique_ptr`和`shared_ptr`都可以用于管理动态分配的数组。必须正确指定模板参数：

```cpp
std::shared_ptr<int[]> sh_arr{new int[42]};
sh_arr[11] = 44;
```

为了访问底层数组的元素，我们使用共享指针的`[]`运算符。还要注意，当在动态多态性中使用智能指针时，不会有缺点。例如，假设我们有以下类层次结构：

```cpp
struct Base
{
  virtual void test() { std::cout << "Base::test()" << std::endl; }
}; 

struct Derived : Base
{
  void test() override { std::cout << "Derived::test()" << std::endl; }
};
```

以下代码按预期工作，并将`Derived::test()`输出到屏幕上。

```cpp
std::unique_ptr<Base> ptr = std::make_unique_default_init<Derived>();
ptr->test();
```

尽管使用智能指针可能会破坏指针的美感，但建议大量使用智能指针以避免内存泄漏。然而，值得注意的是，用`unique_ptr`或`shared_ptr`指针替换所有指针，也无法解决所有内存泄漏问题。它们也有缺点。在应用它们解决问题之前，考虑一种平衡的方法，或者更好地彻底了解问题和智能指针本身的细节。

在 C++程序中管理内存是有代价的。我们讨论的最重要的事情是正确释放内存空间。该语言不支持自动内存释放，但值得一提的是垃圾收集器。然而，要有一个完整的垃圾收集器，我们需要语言级别的支持。C++没有提供任何支持。让我们尝试在 C++中模拟垃圾收集器。

# 垃圾收集

垃圾收集器通常是可解释语言的运行时环境中的一个单独模块。例如，C#和 Java 都有垃圾收集器，这使得程序员的生活变得更加轻松。垃圾收集器跟踪代码中的所有对象分配，并在它们不再使用时释放。它被称为**垃圾收集器**，因为它在使用后删除内存资源：它收集程序员留下的垃圾。

据说 C++程序员不会留下垃圾，这就是为什么该语言不支持垃圾收集器的原因。尽管程序员倾向于辩护该语言，称其之所以没有垃圾收集器是因为它是一种快速的语言，但事实是它可以在没有垃圾收集器的情况下生存。

像 C#这样的语言将程序编译成中间字节码表示，然后由运行时环境解释和执行。垃圾收集器是环境的一部分，并且积极跟踪所有对象分配。它是一个复杂的机制，尽最大努力在合理的时间内管理内存。以下图表描述了典型的运行时环境，该环境分配由垃圾收集器监督的内存：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/2421ee02-8ebd-4784-8109-1c53318b8124.png)

即使使用智能指针，我们仍然需要手动调用`delete`运算符来释放 C++中的内存空间。智能指针只是在获取对象时获取对象，并在对象超出范围时删除对象。关键点是，即使智能指针引入了一些半自动行为，它们仍然表现得好像程序员没有忘记在代码的指定点释放资源。垃圾收集器会自动执行这些操作，并通常使用单独的执行线程。它尽力不要减慢实际程序执行速度。

一些垃圾收集实现技术包括根据对象的生命周期持续时间对对象进行分类。分类使垃圾收集器访问对象并在对象不再使用时释放内存空间。为了加快这个过程，应该更频繁地访问生命周期短的对象，而不是生命周期长的对象。例如，考虑以下代码：

```cpp
struct Garbage {
  char ch;
  int i;
};

void foo() {
  Garbage* g1 = new Garbage();
  if (true) {
    Garbage* g2 = new Garbage();
  }
}

int main() {
  static Garbage* g3 = new Garbage();
}
```

如果 C++有垃圾收集器，那么对象`g1`、`g2`和`g3`将在程序执行的不同时间段被删除。如果垃圾收集器根据它们的生命周期持续时间对它们进行分类，那么`g2`的生命周期将是最短的，并且应该首先被访问以释放它。

要真正在 C++中实现垃圾收集器，我们应该将其作为程序的一部分。垃圾收集器应该首先负责分配内存来跟踪并删除它：

```cpp
class GarbageCollector {
public:
 template <typename T>
 static T* allocate() { 
   T* ptr{new T()};
 objects_[ptr] = true;
   return ptr;
 }

 static void deallocate(T* p) {
   if (objects_[p]) {
     objects_[p] = false;
     delete p;
   }
 } private:
 std::unordered_map<T*, bool> objects_;
};
```

前面的类通过静态的`allocate()`函数跟踪通过分配的对象。如果对象正在使用，则通过`deallocate()`函数删除它。以下是`GarbageCollector`的使用方法：

```cpp
int* ptr = GarbageCollector::allocate<int>();
*ptr = 42;
GarbageCollector::deallocate(ptr);
```

实际上，这个类使得内存管理比智能指针稍微困难一些。基本上，在 C++中没有必要实现垃圾收集器，因为智能指针几乎可以处理关于*自动*内存释放的任何情况。

然而，让我们看看一种技巧，它将允许垃圾收集器正确释放某个指针指向的空间。在我们最简单的前面的实现中，我们跟踪了我们提供给用户的所有指针。每个指针指向堆上的一些空间，应该在程序执行的某个时刻被释放。在`GarbageCollector`中，我们将使用标准的`delete`运算符。问题是，它如何知道应该释放多少字节？看看下面的例子：

```cpp
Student* ptr = new Student;
int* ip = new int{42};
// do something with ptr and ip
delete ptr;
delete ip;
```

假设一个`Student`实例占用 40 个字节的内存，一个整数占用 4 个字节。我们应该以某种方式将这些信息传递给删除运算符。在前面的代码中，我们删除了`ptr`和`ip`，它们分别指向不同大小的内存空间。那么它如何知道在`ptr`的情况下应该将 40 个字节标记为自由，而在`ip`的情况下应该将 4 个字节标记为自由？对于这个问题有不止一种解决方案，让我们看看其中一种。

每当我们分配内存时，`new`运算符将分配空间的大小放在实际内存空间之前，如下图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/10cfb979-45e6-41f9-9d2f-7fcb0fff9408.png)

这些信息然后被`delete`运算符使用，它通过读取内存空间之前放置的相应字节来读取内存空间的大小。C++的一个主要关注点是管理数据集合的内存。STL 容器，如`std::vector`和`std::list`，在第六章中描述的《深入 STL 中的数据结构和算法》中，对处理内存有不同的模型。默认情况下，容器有一个指定的内存分配器，用于处理容器元素的内存分配和释放。让我们更详细地了解一下分配器。

# 使用分配器

分配器的理念是为容器内存管理提供控制。简单来说，分配器是 C++容器的高级垃圾收集器。虽然我们在容器内存管理范围内讨论分配器，但您肯定可以将这个想法扩展到通用的垃圾收集器。在本节的开头，我们实现了一个设计不良的垃圾收集器。当研究分配器时，您会发现`GarbageCollector`类和 C++中的默认分配器之间有很多相似之处。默认分配器在`<memory>`中定义，它有两个基本函数-`allocate()`和`deallocate()`。`allocate()`函数定义如下：

```cpp
[[nodiscard]] constexpr T* allocate(std::size_t num);
```

`allocate()`函数获取类型为`T`的`num`个对象的空间。注意`[[nodiscard]]`属性-这意味着调用者不应该丢弃返回值。否则，编译器将打印警告消息。

让我们使用分配器为五个整数获取空间：

```cpp
import <memory>;

int main()
{
  std::allocator<int> IntAlloc;
  int* ptr = IntAlloc.allocate(5);
  // construct an integer at the second position
 std::allocator_traits<IntAlloc>::construct(IntAlloc, ptr + 1, 42);
  IntAlloc.deallocate(ptr, 5); // deallocate all
}
```

注意我们如何使用`std::allocator_traits`在分配的空间中构造对象。下图显示了

`deallocate()`函数定义如下：

```cpp
constexpr void deallocate(T* p, std::size_t n)
```

在上一个代码片段中，我们使用`allocate()`函数返回的指针来调用`deallocate()`函数。

您可能不会直接在项目中使用分配器，但是每当您需要自定义内存管理行为时，使用现有的或引入新的分配器可能会有所帮助。STL 容器主要使用分配器，因为它们在结构和行为上有所不同，这导致需要为内存分配和释放具有专门的行为。我们将在下一章更详细地讨论 STL 容器。

# 总结

像 C#这样的语言中的垃圾收集器是由环境提供的。它们与用户程序并行工作，并在程序看起来有效时尝试清理。我们无法在 C++中做同样的事情；我们能做的只是在程序中直接实现垃圾收集器，提供一种半自动的方式来释放已使用的内存资源。自 C++11 以来，这种机制已经得到了语言中智能指针的适当覆盖。

内存管理是每个计算机程序的关键组成部分之一。程序应该能够在执行过程中动态请求内存。优秀的程序员了解内存管理的内部细节。这有助于他们设计和实现性能更好的应用程序。虽然手动内存管理被认为是一种优势，但在较大的应用程序中往往变得痛苦。在本章中，我们已经学会了如何通过智能指针避免错误并处理内存释放。有了这种基本的理解，您应该对设计避免内存泄漏的程序更有信心。

在下一章中，我们将学习 STL，重点关注数据结构和算法，并深入研究它们的 STL 实现。除了比较数据结构和算法，我们还将介绍 C++20 中一个显著的新特性：概念。

# 问题

1.  解释计算机内存。

1.  什么是虚拟内存？

1.  用于内存分配和释放的运算符是哪些？

1.  `delete`和`delete[]`之间有什么区别？

1.  什么是垃圾收集器，为什么 C++不支持垃圾收集器？

# 进一步阅读

有关更多信息，请参阅以下链接：

+   每个程序员都应该了解的关于内存的知识，作者乌尔里希·德雷珀，网址为[`people.freebsd.org/~lstewart/articles/cpumemory.pdf`](https://people.freebsd.org/~lstewart/articles/cpumemory.pdf)

+   《代码：计算机硬件和软件的隐藏语言》，作者查尔斯·佩兹德，网址为[`www.amazon.com/Code-Language-Computer-Hardware-Software/dp/0735611319/`](https://www.amazon.com/Code-Language-Computer-Hardware-Software/dp/0735611319/)
