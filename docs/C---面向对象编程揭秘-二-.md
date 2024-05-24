# C++ 面向对象编程揭秘（二）

> 原文：[`zh.annas-archive.org/md5/BCB2906673DC89271C447ACAA17D3E00`](https://zh.annas-archive.org/md5/BCB2906673DC89271C447ACAA17D3E00)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第二部分：在 C++中实现面向对象的概念

本节的目标是了解如何使用 C++语言特性和成熟的编程技术来实现 OO 设计。C++可以用于许多编码范式；程序员必须努力以 OO 方式编程（这不是自动的）。这是本书最大的部分，因为理解如何将语言特性和实现技术映射到 OO 概念是至关重要的。

本节的第一章详细探讨了类，首先描述了封装和信息隐藏的面向对象概念。语言特性，如成员函数、this 指针、详细访问区域、详细构造函数（包括复制构造函数）、析构函数、成员函数的限定符（const、static、inline）以及数据成员的限定符（const、static）都得到了深入审查。

本节的下一章介绍了单一继承的基础知识，涉及泛化和特化的 OO 概念，详细介绍了通过成员初始化列表继承的构造函数、构造和析构的顺序，以及理解继承的访问区域。本章通过探讨公共与受保护和私有基类以及这些语言特性如何改变继承的 OO 含义，深入挖掘了这一主题。

接下来的章节深入探讨了关于多态性的 OO 概念，以及在 C++中使用虚函数实现该概念。方法的动态绑定被审查。虚函数表被探讨以解释运行时绑定。下一章详细解释了抽象类，将 OO 概念与使用纯虚函数的实现配对。介绍了接口的 OO 概念（在 C++中没有明确表示），并审查了一种实现方法。向上和向下继承层次的转换完成了本章。

接下来的一章探讨了多重继承以及可能出现的问题。虚基类以及判别器的 OO 概念也被详细介绍，以帮助确定多重继承是否是给定场景的最佳设计，或者是否存在其他设计。

本节的最后一章介绍了关联、聚合和组合的概念，以及如何使用指针或引用、指针集或嵌入对象来实现这些常见的对象关系。

本节包括以下章节：

+   [*第五章*]，详细探讨类

+   [*第六章*]，使用单一继承实现层次结构

+   [*第七章*]，通过多态性利用动态绑定

+   [*第八章*]，掌握抽象类

+   [*第九章*]，探索多重继承

+   [*第十章*]，实现关联、聚合和组合


# 第五章：深入探讨类

本章将开始我们对 C++中**面向对象编程**（OOP）的追求。我们将首先介绍**面向对象**（OO）的概念，然后逐渐理解这些概念如何在 C++中实现。许多时候，实现 OOP 思想将通过*直接语言支持*来实现，比如本章中的特性。然而，有时我们将利用各种编程技术来实现面向对象的概念。这些技术将在后面的章节中看到。在所有情况下，重要的是理解面向对象的概念以及这些概念如何与深思熟虑的设计相关联，然后清楚地理解如何用健壮的代码实现这些设计。

本章将详细介绍 C++类的使用。微妙的特性和细微差别将超越基础知识进行详细说明。本章的目标是让您了解 OO 概念，并开始以面向对象编程的方式思考。拥抱核心的 OO 理念，如封装和信息隐藏，将使您能够编写更易于维护的代码，并使您更容易修改他人的代码。

在本章中，我们将涵盖以下主要主题：

+   定义面向对象的术语和概念 - 对象、类、实例、封装和信息隐藏

+   应用类和成员函数的基础知识

+   检查成员函数的内部；“this”指针

+   使用访问标签和访问区域

+   理解构造函数 - 默认、重载、复制和转换构造函数

+   理解析构函数及其正确使用

+   对数据成员和成员函数应用限定符 - 内联、常量和静态

在本章结束时，您将了解适用于类的核心面向对象术语，并了解关键的 OO 思想，如封装和信息隐藏，将导致更易于维护的软件。

您还将了解 C++如何提供内置语言特性来支持面向对象编程。您将熟练掌握成员函数的使用，并理解它们通过`this`指针的基本实现。您将了解如何正确使用访问标签和访问区域来促进封装和信息隐藏。

您将了解如何使用构造函数来初始化对象，以及从基本到典型（重载）到复制构造函数，甚至转换构造函数的多种类型的构造函数。同样，您将了解如何在对象存在结束之前正确使用析构函数。

您还将了解如何将限定符，如 const、static 和 inline，应用于成员函数，以支持面向对象的概念或效率。同样，您将了解如何将限定符，如 const 和 static，应用于数据成员，以进一步支持 OO 理念。

C++可以用作面向对象的编程语言，但这并不是自动的。为此，您必须理解 OO 的概念、意识形态和语言特性，这将使您能够支持这一努力。让我们开始追求编写更易于修改和维护的代码，通过理解在面向对象 C++ OO 程序中找到的核心和基本构建块和语言特性，C++类。

# 技术要求

完整程序示例的在线代码可以在以下 GitHub URL 找到：[`github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter05`](https://github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/tree/master/Chapter05)。每个完整程序示例都可以在 GitHub 存储库中的适当章节标题（子目录）下找到，文件名为该章节号，后跟破折号，再跟该章节中的示例编号。例如，本章的第一个完整程序可以在名为`Chp5-Ex1.cpp`的文件中的`Chapter05`子目录中找到。

本章的 CiA 视频可在以下链接观看：[`bit.ly/2OQgiz9`](https://bit.ly/2OQgiz9)。

# 介绍面向对象的术语和概念

在本节中，我们将介绍核心面向对象的概念以及适用的术语，这些术语将伴随着这些关键思想。虽然本章中会出现新术语，但我们将从必须理解的术语开始，以便在本节开始我们的旅程。

面向对象的系统因为封装和信息隐藏，因此更容易维护。用户定义类型的升级和修改可以快速进行，而不会对整个系统产生影响。

让我们从基本的面向对象术语开始。

## 理解面向对象的术语

我们将从基本的面向对象术语开始，然后在介绍新概念时，我们将扩展术语以包括 C++特定的术语。

对象、类和实例这些术语都是重要且相关的术语，我们可以从这些术语开始定义。**对象**体现了一组特征和行为的有意义的组合。对象可以被操作，可以接收行为的动作或后果。对象可能会经历变化，并且随着时间的推移可以反复改变。对象可以与其他对象互动。

术语对象有时可能用来描述类似项的组合的蓝图。术语**类**可能与对象的这种用法互换使用。术语对象也可能（更常见）用来描述这种组合中的特定项。术语**实例**可能与对象的这种含义互换使用。使用上下文通常会清楚地表明术语*对象*的哪种含义被应用。为避免潜在的混淆，最好使用术语*类*和*实例*。

让我们考虑一些例子，使用上述术语：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/dmst-oop-cpp/img/Figure_5.1_B15930.jpg)

对象也有组成部分。类的特征被称为**属性**。类的行为被称为**操作**。行为或操作的具体实现被称为其**方法**。换句话说，方法是操作的实现方式，或者定义函数的代码体，而操作是函数的原型或使用协议。

让我们考虑一些高级例子，使用上述术语：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/dmst-oop-cpp/img/Figure_5.2_B15930.jpg)

类的每个实例很可能具有其属性的不同值。例如：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/dmst-oop-cpp/img/Figure_5.3_B15930.jpg)

现在我们已经掌握了基本的面向对象术语，让我们继续介绍与本章相关的重要面向对象概念。

## 理解面向对象的概念

与本章相关的关键面向对象概念是*封装*和*信息隐藏*。将这些相关的想法纳入到你的设计中，将为编写更易于修改和可维护的程序提供基础。

将有意义的特征（属性）和行为（操作）捆绑在一起形成一个单一单元的过程称为**封装**。在 C++中，我们通常将这些项目组合在一个类中。通过模拟与每个类相关的行为的操作，可以通过每个类实例的接口进行访问。这些操作还可以通过改变其属性的值来修改对象的内部状态。在类中隐藏属性并提供操作这些细节的接口，使我们能够探索信息隐藏的支持概念。

**信息隐藏**是指将执行操作的细节抽象成类方法的过程。也就是说，用户只需要了解要使用哪个操作以及其整体目的；实现细节被隐藏在方法中（函数体）。通过这种方式，改变底层实现（方法）不会改变操作的接口。信息隐藏还可以指保持类属性的底层实现隐藏。当我们介绍访问区域时，我们将进一步探讨这一点。信息隐藏是实现类的正确封装的一种手段。正确封装的类将实现正确的类抽象，从而支持 OO 设计。

面向对象的系统因为类允许快速升级和修改而本质上更易于维护，这是由于封装和信息隐藏而不会对整个系统产生影响。

# 理解类和成员函数的基础

C++中的**类**是 C++中的基本构建块，允许程序员指定用户定义的类型，封装相关数据和行为。C++类定义将包含属性、操作，有时还包括方法。C++类支持封装。

创建类类型的变量称为**实例化**。在 C++中，类中的属性称为**数据成员**。在 C++中，类中的操作称为**成员函数**，用于模拟行为。在 OO 术语中，操作意味着函数的签名，或者它的原型（声明），方法意味着其底层实现或函数的主体（定义）。在一些 OO 语言中，术语*方法*更松散地用于暗示操作或其方法，根据使用上下文而定。在 C++中，最常使用的术语是*数据成员*和*成员函数*。

成员函数的原型必须放在类定义中。大多数情况下，成员函数定义放在类定义之外。然后使用作用域解析运算符`::`将给定的成员函数定义与其所属的类关联起来。点`.`或箭头`->`符号用于访问所有类成员，包括成员函数，取决于我们是通过实例还是通过指向实例的指针访问成员。

C++结构也可以用于封装数据及其相关行为。C++的`struct`可以做任何 C++的`class`可以做的事情；实际上，在 C++中，`class`是以`struct`的方式实现的。尽管结构和类可能行为相同（除了默认可见性），类更常用于模拟对象，模拟对象类型之间的关系，并实现面向对象的系统。

让我们看一个简单的例子，我们将实例化一个`class`和一个`struct`，每个都有成员函数，以便进行比较。我们将这个例子分成几个部分。完整的程序示例可以在 GitHub 存储库中找到：

https://github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter05/Chp5-Ex1.cpp

```cpp
#include <iostream>
#include <cstring>
using namespace std;
struct student
{
    char name[20];
    float gpa;
    void Initialize(const char *, float);  // fn. prototype
    void Print();
};
class University
{
public:
    char name[30];
    int numStudents;
    void Initialize(const char *, int);   // fn. prototype
    void Print();
};
```

在前面的例子中，我们首先使用`struct`定义了一个`student`类型，使用`class`定义了一个`University`类型。请注意，按照惯例，使用结构创建的用户定义类型不以大写字母开头，而使用类创建的用户定义类型以大写字母开头。还要注意，`class`定义需要在其定义的开头使用`public:`标签。我们将在本章的后面探讨这个标签的使用；但是，现在`public`标签的存在是为了让这个`class`的成员具有与`struct`相同的默认可见性。

在`class`和`struct`的定义中，注意`Initialize()`和`Print()`的函数原型。我们将在下一个程序段中使用`::`，作用域解析运算符，将这些原型与成员函数定义联系起来。

让我们来看看各种成员函数的定义：

```cpp
void student::Initialize(const char *n, float avg)
{ 
    strcpy(name, n);
    gpa = avg;
}
void student::Print()
{ 
    cout << name << " GPA: " << gpa << endl;
}
void University::Initialize(const char *n, int num)
{ 
    strcpy(name, n);
    numStudents = num;
} 
void University::Print()
{ 
    cout << name << " Enrollment: " << numStudents << endl;
}
```

现在，让我们回顾一下每个用户定义类型的各种成员函数定义。在上面的片段中，`void student::Initialize(const char *, float)`、`void student::Print()`、`void University::Initialize(const char *, int)`和`void University::Print()`的定义是连续的。注意作用域解析运算符`::`如何允许我们将相关的函数定义与其所属的`class`或`struct`联系起来。

另外，请注意，在每个`Initialize()`成员函数中，输入参数被用作值来加载特定类类型的特定实例的相关数据成员。例如，在`void University::Initialize(const char *n, int num)`的函数定义中，输入参数`num`被用来初始化特定`University`实例的`numStudents`。

注意

作用域解析运算符`::`将成员函数定义与其所属的类（或结构）关联起来。

让我们通过考虑这个例子中的`main()`来看看成员函数是如何被调用的：

```cpp
int main()
{ 
    student s1;  // instantiate a student (struct instance)
    s1.Initialize("Gabby Doone", 4.0);
    s1.Print();
    University u1;  // instantiate a University (class)
    u1.Initialize("GWU", 25600);
    u1.Print();
    University *u2;         // pointer declaration
    u2 = new University();  // instantiation with new()
    u2->Initialize("UMD", 40500);  
    u2->Print();  // or alternatively: (*u2).Print();
    delete u2;  
    return 0;
}
```

在`main()`中，我们简单地定义了一个`student`类型的变量`s1`和一个`University`类型的变量`u1`。在面向对象的术语中，最好说`s1`是`student`的一个实例，`u1`是`University`的一个实例。实例化发生在为对象分配内存时。因此，使用`University *u2;`声明指针变量`u2`并不会实例化`University`；它只是声明了一个可能的未来实例的指针。相反，在下一行`u2 = new University();`中，当分配内存时，我们实例化了一个`University`。

对于每个实例，我们通过调用它们各自的`Initialize()`成员函数来初始化它们的数据成员，比如`s1.Initialize("Gabby Doone", 4.0);`或`u1.Initialize("UMD", 4500);`。然后我们通过每个相应的实例调用`Print()`，比如`u2->Print();`。请记住，`u2->Print();`也可以写成`(*u2).Print();`，这样更容易让我们记住这个实例是`*u2`，而`u2`是指向该实例的指针。

注意，当我们通过`s1`调用`Initialize()`时，我们调用`student::Initialize()`，因为`s1`的类型是`student`，我们在这个函数的主体中初始化了`s1`的数据成员。同样，当我们通过`u1`或`*u2`调用`Print()`时，我们调用`University::Print()`，因为`u1`和`*u2`的类型是`University`，我们随后打印出特定大学的数据成员。

由于实例`u1`是在堆上动态分配的，我们有责任在`main()`的末尾使用`delete()`释放它的内存。

伴随这个程序的输出如下：

```cpp
Gabby Doone GPA: 4.4
GWU Enrollment: 25600
UMD Enrollment: 40500
```

现在，我们正在创建具有其关联的成员函数定义的类定义，重要的是要知道开发人员通常如何在文件中组织他们的代码。大多数情况下，一个类将被分成一个头（`.h`）文件，其中包含类定义，和一个源代码（`.cpp`）文件，它将`#include`头文件，然后跟随成员函数定义本身。例如，名为`University`的类将有一个`University.h`头文件和一个`University.cpp`源代码文件。

现在，让我们通过检查`this`指针来继续了解成员函数工作的细节。

# 检查成员函数内部；"this"指针

到目前为止，我们已经注意到成员函数是通过对象调用的。我们已经注意到，在成员函数的范围内，可以使用调用函数的特定对象的数据成员（和其他成员函数）（除了任何输入参数）。然而，这是如何以及为什么起作用的呢？

事实证明，大多数情况下，成员函数是通过对象调用的。每当以这种方式调用成员函数时，该成员函数会接收一个指向调用函数的实例的指针。然后，将调用函数的对象的指针作为隐式的第一个参数传递给函数。这个指针的名称是**this**。

虽然在每个成员函数的定义中可能会显式引用`this`指针，但通常不会这样做。即使没有显式使用，函数范围内使用的数据成员属于`this`，即调用函数的对象的指针。

让我们来看一个完整的程序示例。虽然示例被分成了段落，但完整的程序可以在以下 GitHub 位置找到：

[`github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter05/Chp5-Ex2.cpp`](https://github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter05/Chp5-Ex2.cpp)

```cpp
#include <iostream>
#include <cstring>
using namespace std;
class Student
{
public:  // for now, let's put everything public access region
    char *firstName;  // data members
    char *lastName;
    char middleInitial;
    float gpa;
    char *currentCourse;
    // member function prototypes
    void Initialize(const char *, const char *, char, 
                    float, const char *);
    void Print();
};
```

在程序的第一部分中，我们定义了类`Student`，其中包含各种数据成员和两个成员函数原型。现在，我们将把所有内容放在`public`访问区域。

现在，让我们来看一下`void Student::Initialize()`和`void Student::Print()`的成员函数定义。我们还将内部查看每个函数的样子，对于 C++来说：

```cpp
// Member function definition
void Student::Initialize(const char *fn, const char *ln, 
                       char mi, float gpa, const char *course)
{
    firstName = new char [strlen(fn) + 1];
    strcpy(firstName, fn);
    lastName = new char [strlen(ln) + 1];
    strcpy(lastName, ln);
    this->middleInitial = mi;  // optional use of 'this'
    this->gpa = gpa;  // required, explicit use of 'this'
    currentCourse = new char [strlen(course) + 1];
    strcpy(currentCourse, course);
}
// It is as if Student::Initialize() is written as:
// void 
// Student_Initialize_constchar*_constchar*_float_constchar*
//     (Student *const this, const char *fn, const char *ln,
//      char mi, float avg, char *course) 
// {
//    this->firstName = new char [strlen(fn) + 1];
//    strcpy(this->firstName, fn);
//    this->lastName = new char [strlen(ln) + 1];
//    strcpy(this->lastName, ln);
//    this->middleInitial = mi;
//    this->gpa = avg;
//    this->currentCourse = new char [strlen(course) + 1];
//    strcpy(this->currentCourse, course);
// }
// Member function definition
void Student::Print()
{
   cout << firstName << " ";
   cout << middleInitial << ". ";
   cout << lastName << " has a gpa of: ";
   cout << gpa << " and is enrolled in: ";
   cout << currentCourse << endl;
}
// It is as if Student::Print() is written as:
// void Student_Print(Student *const this)
// {
//    cout << this->firstName << " ";
//    cout << this->middleInitial << ". " 
//    cout << this->lastName << " has a gpa of: ";
//    cout << this->gpa << " and is enrolled in: ";
//    cout << this->currentCourse << endl;
// }
```

首先，我们看到了`void Student::Initialize()`的成员函数定义，它接受各种参数。请注意，在这个函数的主体中，我们为数据成员`firstName`分配了足够的字符来容纳输入参数`fn`所需的内容（再加上一个终止的空字符）。然后，我们使用`strcpy()`将输入参数`fn`的字符串复制到数据成员`firstName`中。我们使用输入参数`ln`对数据成员`lastName`做同样的操作。然后，我们类似地使用各种输入参数来初始化将调用此函数的特定对象的各种数据成员。

另外，在`void Student::Initialize()`中注意赋值`this->middleInitial = mi;`。在这里，我们可以选择性地显式使用`this`指针。在这种情况下，没有必要或习惯性地用`this`限定`middleInitial`，但我们可以选择这样做。然而，在赋值`this->gpa = gpa;`中，使用`this`是必需的。为什么？注意输入参数的名称是`gpa`，数据成员也是`gpa`。简单地赋值`gpa = gpa;`会将最局部版本的`gpa`（输入参数）设置为自身，并不会影响数据成员。在这里，通过在赋值的左侧用`this`来消除`gpa`，表示设置数据成员`gpa`，该数据成员由`this`指向，为输入参数`gpa`的值。另一个解决方案是在形式参数列表中对数据成员和输入参数使用不同的名称，比如将形式参数列表中的`gpa`重命名为`avg`（我们将在此代码的后续版本中这样做）。

现在，注意`void Student::Initialize()`的注释掉的版本，它在使用的`void Student::Initialize()`的下面。在这里，我们可以看到大多数成员函数是如何在内部表示的。首先，注意函数的名称被*名称混编*以包括其参数的数据类型。这是函数在内部表示的方式，因此允许函数重载（即，两个看似相同名称的函数；在内部，每个函数都有一个唯一的名称）。接下来，注意在输入参数中，有一个额外的第一个输入参数。这个额外的（隐藏的）输入参数的名称是`this`，它被定义为`Student *const this`。

现在，在`void Student::Initialize()`的内部化函数视图的主体中，注意每个数据成员的名称前面都有`this`。事实上，我们正在访问由`this`指向的对象的数据成员。`this`在哪里定义？回想一下，`this`是这个函数的隐式第一个输入参数，并且是一个指向调用这个函数的对象的常量指针。

类似地，我们可以回顾`void Student::Print()`的成员函数定义。在这个函数中，每个数据成员都是用`cout`和插入运算符`<<`清晰地打印出来。然而，注意在这个函数定义下面的`void Student::Print()`的注释掉的内部版本。同样，`this`实际上是一个类型为`Student *const`的隐式输入参数。此外，每个数据成员的使用都是通过`this`指针进行的，比如`this->gpa`。同样，我们可以清楚地看到特定实例的成员是如何在成员函数的范围内被访问的；这些成员是通过`this`指针隐式访问的。

最后，注意在成员函数的主体中允许显式使用`this`。我们几乎总是可以在成员函数的主体中使用数据成员或成员函数之前，用显式使用`this`。在本章的后面，我们将看到一个相反的情况（使用静态方法）。此外，在本书的后面，我们将看到需要显式使用`this`来实现更中级的面向对象概念的情况。

尽管如此，让我们通过检查`main()`来完成这个程序示例：

```cpp
int main()
{
    Student s1;   // instance
    Student *s2 = new Student; // ptr to an instance
    s1.Initialize("Mary", "Jacobs", 'I', 3.9, "C++");
    s2->Initialize("Sam", "Nelson", 'B', 3.2, "C++");
    s1.Print();
    s2->Print(); // or use (*s2).Print();
    delete s1.firstName;  // delete dynamically allocated
    delete s1.lastName;   // data members
    delete s1.currentCourse;
    delete s2->firstName;
    delete s2->lastName;
    delete s2->currentCourse;
    delete s2;    // delete dynamically allocated instance
    return 0;
}
```

在这个程序的最后一部分，我们在`main()`中实例化了两次`Student`。`Student` `s1`是一个实例，而`s2`是一个指向`Student`的指针。接下来，我们通过每个相关实例使用`.`或`->`符号来调用各种成员函数。

注意，当`s1`调用`Initialize()`时，`this`指针（在成员函数的范围内）将指向`s1`。这将好像`&s1`被传递为该函数的第一个参数一样。同样，当`*s2`调用`Initialize`时，`this`指针将指向`s2`；就好像`s2`（已经是一个指针）被作为该函数的隐式第一个参数传递一样。

在每个实例调用`Print()`以显示每个`Student`的数据成员之后，请注意我们释放各种级别的动态分配内存。我们从每个实例的动态分配数据成员开始，使用`delete()`释放每个这样的成员。然后，因为`s2`是我们动态分配的一个实例的指针，我们还必须记得释放包括实例本身的堆内存。我们再次使用`delete s2;`来完成这个操作。

以下是完整程序示例的输出：

```cpp
Mary I. Jacobs has a gpa of: 3.9 and is enrolled in: C++
Sam B. Nelson has a gpa of: 3.2 and is enrolled in: C++
```

现在，让我们通过检查访问标签和区域来增进对类和信息隐藏的理解。

# 使用访问标签和访问区域

标签可以被引入到类（或结构）定义中，以控制类（或结构）成员的访问或可见性。通过控制应用程序中各种范围的直接访问成员，我们可以支持封装和信息隐藏。也就是说，我们可以坚持要求我们类的用户使用我们选择的函数，以我们选择的协议来操作数据和类中的其他成员函数，以我们程序员认为合理和可接受的方式。此外，我们可以通过仅向用户公布给定类的所需公共接口来隐藏类的实现细节。

数据成员或成员函数，统称为**成员**，可以单独标记，或者组合到访问区域中。可以指定的三个标签或**访问区域**如下：

+   **private**：此访问区域中的数据成员和成员函数只能在类的范围内访问。类的范围包括该类的成员函数。

+   `private`直到我们引入继承。当引入继承时，`protected`将提供一种机制，允许在派生类范围内访问。

+   **public**：此访问区域中的数据成员和成员函数可以从程序中的任何范围访问。

提醒

几乎总是通过实例访问数据成员和成员函数。你会问，*我的实例在什么范围内？*以及*我可以从这个特定的范围访问特定的成员吗？*

程序员可以将尽可能多的成员分组到给定的标签或`private`下。如果在结构定义中省略了访问标签，则默认成员访问是`public`。当明确引入访问标签时，而不是依赖于默认可见性，`class`和`struct`是相同的。尽管如此，在面向对象编程中，我们倾向于使用类来定义用户定义的类型。

让我们通过一个例子来说明访问区域。尽管这个例子将被分成几个部分，但完整的例子将被展示，并且也可以在 GitHub 存储库中找到。

[`github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter05/Chp5-Ex3.cpp`](https://github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter05/Chp5-Ex3.cpp)

```cpp
#include <iostream>
#include <cstring>
using namespace std;
class Student
{
// private members are accessible only within the scope of
// the class (e.g. within member functions or friends) 
private: 
    char *firstName;   // data members
    char *lastName;
    char middleInitial;
    float gpa;
    char *currentCourse;
    char *studentId;  
public:   // public members are accessible from any scope
    // member function prototypes
    void Initialize();  
    void Initialize(const char *, const char *, char, float, 
                    const char *, const char *);
    void CleanUp();
    void Print();
};
```

在这个例子中，我们首先定义了`Student`类。请注意，我们在类定义的顶部附近添加了一个`private`访问区域，并将所有数据成员放在这个区域内。这样的安排将确保这些数据成员只能在这个类的范围内直接访问和修改，这意味着只能由这个类的成员函数（和我们稍后将看到的友元）来访问。通过仅限制数据成员的访问只能在其自己类的成员函数中，可以确保对这些数据成员的安全处理；只有通过类设计者自己引入的预期和安全函数的访问将被允许。

接下来，请注意在类定义之前的成员函数原型中添加了`public`标签。这意味着这些函数将在我们程序的任何范围内可访问。当然，我们通常需要通过实例分别访问这些函数。但是，当实例访问这些公共成员函数时，实例可以在`main()`或任何其他函数的范围内（甚至在另一个类的成员函数的范围内）。这被称为类的`public`接口。

访问区域支持封装和信息隐藏

一个很好的经验法则是将数据成员放在私有访问区域中，然后使用公共成员函数指定一个安全、适当的公共接口。通过这样做，对数据成员的唯一访问是类设计者打算的方式，通过类设计者编写的经过充分测试的成员函数。采用这种策略，类的底层实现也可以更改，而不会导致对公共接口的调用发生变化。这种做法支持封装和信息隐藏。

让我们继续看看我们程序中各种成员函数的定义：

```cpp
void Student::Initialize()
{
    firstName = lastName = 0;  // NULL pointer
    middleInitial = '\0';      // null character
    gpa = 0.0;
    currentCourse = studentId = 0;
}
// Overloaded member function definition
void Student::Initialize(const char *fn, const char *ln, 
      char mi, float avg, const char *course, const char *id) 
{
    firstName = new char [strlen(fn) + 1];
    strcpy(firstName, fn);
    lastName = new char [strlen(ln) + 1];
    strcpy(lastName, ln);
    middleInitial = mi; 
    gpa = avg;   
    currentCourse = new char [strlen(course) + 1];
    strcpy(currentCourse, course);
    studentId = new char [strlen(id) + 1];
    strcpy (studentId, id); 
}
// Member function definition
void Student::CleanUp()
{
    delete firstName;
    delete lastName;
    delete currentCourse;
    delete studentId;
}
// Member function definition
void Student::Print()
{
    cout << firstName << " " << middleInitial << ". ";
    cout << lastName << " with id: " << studentId;
    cout << " has gpa: " << gpa << " and enrolled in: ";
    cout << currentCourse << endl;
}
```

在这里，我们定义了在我们的类定义中原型化的各种成员函数。请注意使用作用域解析运算符`::`将类名与成员函数名绑定在一起。在内部，这两个标识符被*名称混淆*在一起，以提供一个唯一的内部函数名。请注意，`void Student::Initialize()`函数已被重载；一个版本只是将所有数据成员初始化为某种空值或零，而重载的版本使用输入参数来初始化各种数据成员。

现在，让我们继续通过检查以下代码段中的`main()`函数来继续：

```cpp
int main()
{
    Student s1;
    // Initialize() is public; accessible from any scope
    s1.Initialize("Ming", "Li", 'I', 3.9, "C++", "178GW"); 
    s1.Print();  // Print() is public, accessible from main() 
    // Error! firstName is private; not accessible in main()
    // cout << s1.firstName << endl;  
    // CleanUp() is public, accessible from any scope
    s1.CleanUp(); 
    return 0;
}
```

在上述的`main()`函数中，我们首先用声明`Student s1;`实例化了一个`Student`。接下来，`s1`调用了与提供的参数匹配的`Initialize()`函数。由于这个成员函数在`public`访问区域中，它可以在我们程序的任何范围内访问，包括`main()`。同样，`s1`调用了`Print()`，这也是`public`的。这些函数是`Student`类的公共接口，并代表了操纵任何给定`Student`实例的一些核心功能。

接下来，在被注释掉的代码行中，请注意`s1`试图直接使用`s1.firstName`访问`firstName`。因为`firstName`是`private`的，这个数据成员只能在其自己的类的范围内访问，这意味着其类的成员函数（以及稍后的友元）。`main()`函数不是`Student`的成员函数，因此`s1`不能在`main()`的范围内访问`firstName`，也就是说，在其自己的类的范围之外。

最后，我们调用了`s1.CleanUp();`，这也是可以的，因为`CleanUp()`是`public`的，因此可以从任何范围（包括`main()`）访问。

这个完整示例的输出是：

```cpp
Ming I. Li with id: 178GW has gpa: 3.9 and is enrolled in: C++
```

既然我们了解了访问区域是如何工作的，让我们继续通过检查一个称为构造函数的概念，以及 C++中可用的各种类型的构造函数。

# 理解构造函数

你是否注意到本章节中的程序示例有多么方便，每个`class`或`struct`都有一个`Initialize()`成员函数？当然，为给定实例初始化所有数据成员是可取的。更重要的是，确保任何实例的数据成员具有真实的值是至关重要的，因为我们知道 C++不会提供*干净*或*清零*的内存。访问未初始化的数据成员，并将其值用作真实值，是等待粗心的程序员的潜在陷阱。

每次实例化一个类时单独初始化每个数据成员可能是繁琐的工作。如果我们简单地忽略了设置一个值会怎么样？如果这些值是`private`，因此不能直接访问呢？我们已经看到，`Initialize()`函数是有益的，因为一旦编写，它就提供了为给定实例设置所有数据成员的方法。唯一的缺点是程序员现在必须记住在应用程序中的每个实例上调用`Initialize()`。相反，如果有一种方法可以确保每次实例化一个类时都调用`Initialize()`函数会怎么样？如果我们可以重载各种版本来初始化一个实例，并且根据当时可用的数据调用适当的版本会怎么样？这个前提是 C++中构造函数的基础。语言提供了一系列重载的初始化函数，一旦实例的内存可用，它们就会被自动调用。

让我们通过检查 C++构造函数来看一下这组初始化成员函数的家族。

## 应用构造函数基础知识和构造函数重载

一个`class`（或`struct`）用于定义初始化对象的多种方法。构造函数的返回类型可能不会被指定。

如果您的`class`或`struct`不包含构造函数，系统将为您创建一个公共访问区域中没有参数的构造函数。这被称为默认构造函数。在幕后，每当实例化一个对象时，编译器都会插入一个构造函数调用。当一个没有构造函数的类被实例化时，默认构造函数会被插入为一个函数调用，紧随实例化之后。这个系统提供的成员函数将有一个空的主体（方法），并且它将被链接到您的程序中，以便在实例化时可以发生任何编译器添加的隐式调用，而不会出现链接器错误。通常，程序员会编写自己的默认（无参数）构造函数；也就是说，用于默认实例化的构造函数。

大多数程序员至少会提供一个构造函数，除了他们自己的无参数默认构造函数。请记住，构造函数可以被重载。重要的是要注意，如果您自己提供了任何构造函数，那么您将不会收到系统提供的无参数默认构造函数，因此在实例化时使用这样的接口将导致编译器错误。

提醒

构造函数与类名相同。您不能指定它们的返回类型。它们可以被重载。如果您的类没有提供任何构造函数（或实例化的方法），编译器只会创建一个公共的默认（无参数）构造函数。

让我们介绍一个简单的例子来理解构造函数的基础知识：

[`github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter05/Chp5-Ex4.cpp`](https://github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter05/Chp5-Ex4.cpp)

```cpp
#include <iostream>
#include <cstring>
using namespace std;
class University
{
private:
    char name[30];
    int numStudents;
public: 
    // constructor prototypes
    University(); // default constructor
    University(const char *, int);
    void Print();
};
University::University()
{
    name[0] = '\0';
    numStudents = 0;
}
University::University(const char * n, int num)
{
    strcpy(name, n);
    numStudents = num;
}
void University::Print()
{
    cout << "University: " << name;
    cout << " Enrollment: " << numStudents << endl;
}
int main()
{
    University u1; // Implicit call to default constructor
    University u2("University of Delaware", 23800);
    u1.Print();
    u2.Print();
    return 0;
}
```

在上一个程序段中，我们首先定义了`class University`；数据成员是`private`，而三个成员函数是`public`。请注意，首先原型化的两个成员函数是构造函数。两者都与类名相同；都没有指定返回类型。这两个构造函数是重载的，因为它们的签名不同。

接下来，请注意三个成员函数的定义。注意在它们的定义中，在每个成员函数名之前都使用了作用域解析运算符`::`。每个构造函数都提供了一个不同的初始化实例的方法。`void University::Print()`成员函数仅提供了一个简单输出的方法，供我们的示例使用。

现在，在`main()`中，让我们创建两个`University`的实例。第一行代码`University u1;`实例化一个`University`，然后隐式调用默认构造函数来初始化数据成员。在下一行代码`University u2("University of Delaware", 23800);`中，我们实例化了第二个`University`。一旦在`main()`中为该实例在堆栈上分配了内存，将隐式调用与提供的参数签名匹配的构造函数，即`University::University(const char *, int)`，来初始化该实例。

我们可以看到，根据我们实例化对象的方式，我们可以指定我们希望代表我们调用哪个构造函数来执行初始化。

这个示例的输出是：

```cpp
University: Enrollment: 0
University: University of Delaware Enrollment: 23800
```

接下来，让我们通过检查复制构造函数来增加对构造函数的了解。

## 创建复制构造函数

**复制构造函数**是一种专门的构造函数，每当可能需要复制对象时就会被调用。复制构造函数可能在构造另一个对象时被调用。它们也可能在通过输入参数以值传递给函数，或者从函数中以值返回对象时被调用。

通常，复制一个对象并稍微修改副本比从头开始构造一个新对象更容易。如果程序员需要一个经历了应用程序生命周期中的许多变化的对象的副本，这一点尤为真实。可能无法回忆起可能已应用于问题对象的各种转换的顺序，以创建一个副本。相反，拥有复制对象的手段是可取的，可能是至关重要的。

复制构造函数的签名是`ClassName::ClassName(const ClassName &);`。请注意，一个对象被显式地作为参数传递，并且该参数将是对常量对象的引用。与大多数成员函数一样，复制构造函数将接收一个隐式参数`this`指针。复制构造函数的定义目的将是复制显式参数以初始化`this`指向的对象。

如果`class`（或`struct`）的设计者没有实现复制构造函数，系统会为您提供一个（在`public`访问区域）执行浅层成员复制的复制构造函数。如果您的类中有指针类型的数据成员，这可能不是您想要的。相反，最好的做法是自己编写一个复制构造函数，并编写它以执行深层复制（根据需要分配内存）以用于指针类型的数据成员。

如果程序员希望在构造过程中禁止复制，可以在复制构造函数的原型中使用关键字`delete`，如下所示：

```cpp
    // disallow copying during construction
    Student(const Student &) = delete;   // prototype
```

或者，如果程序员希望禁止对象复制，可以在`private`访问区域中原型化一个复制构造函数。在这种情况下，编译器将链接默认的复制构造函数（执行浅复制），但它将被视为私有。因此，在类的范围之外使用复制构造函数的实例化将被禁止。自从`=delete`出现以来，这种技术的使用频率较低；然而，它可能出现在现有代码中，因此了解它是有用的。

让我们从类定义开始检查一个复制构造函数。尽管程序是以几个片段呈现的，完整的程序示例可以在 GitHub 存储库中找到：

[`github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter05/Chp5-Ex5.cpp`](https://github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter05/Chp5-Ex5.cpp)

```cpp
#include <iostream>  
#include <cstring>    
using namespace std;
class Student
{
private: 
    // data members
    char *firstName;
    char *lastName;
    char middleInitial;
    float gpa;
    char *currentCourse;  
public:
    // member function prototypes
    Student();  // default constructor
    Student(const char *, const char *, char, float, 
            const char *); 
    Student(const Student &);  // copy constructor prototype
    void CleanUp();
    void Print();
};
```

在这个程序片段中，我们首先定义了`class Student`。请注意通常的`private`数据成员和`public`成员函数原型，包括默认构造函数和重载构造函数。还请注意复制构造函数`Student(const Student &);`的原型。

接下来，让我们来看一下我们程序的下一部分，成员函数的定义：

```cpp
// default constructor
Student::Student()
{
    firstName = lastName = 0;  // NULL pointer
    middleInitial = '\0';
    gpa = 0.0;
    currentCourse = 0;
}
// Alternate constructor member function definition
Student::Student(const char *fn, const char *ln, char mi, 
                 float avg, const char *course)
{
    firstName = new char [strlen(fn) + 1];
    strcpy(firstName, fn);
    lastName = new char [strlen(ln) + 1];
    strcpy(lastName, ln);
    middleInitial = mi;
    gpa = avg;
    currentCourse = new char [strlen(course) + 1];
    strcpy(currentCourse, course);
}
// Copy constructor definition – implement a deep copy
Student::Student(const Student &s)
{
    // allocate necessary memory for destination string
    firstName = new char [strlen(s.firstName) + 1];
    // then copy source to destination string
    strcpy(firstName, s.firstName);
    lastName = new char [strlen(s.lastName) + 1];
    // data members which are not pointers do not need their
    // space allocated for deep copy, such as is done above
    strcpy(lastName, s.lastName);
    middleInitial = s.middleInitial;
    gpa = s.gpa;
    // allocate destination string space, then copy contents
    currentCourse = new char [strlen(s.currentCourse) + 1];
    strcpy(currentCourse, s.currentCourse);
}
// Member function definition
void Student::CleanUp()
{
    delete firstName;
    delete lastName;
    delete currentCourse;
}

// Member function definition
void Student::Print()
{
    cout << firstName << " " << middleInitial << ". ";
    cout << lastName << " has a gpa of: " << gpa;
    cout << " and is enrolled in: " << currentCourse << endl;
}
```

在上述代码片段中，我们有各种成员函数的定义。特别要注意的是复制构造函数的定义，它是具有`Student::Student(const Student &s)`签名的成员函数。

请注意，输入参数`s`是一个指向`Student`的`const`引用。这意味着我们将要复制的源对象可能不会被修改。我们将要复制到的目标对象将是由`this`指针指向的对象。

当我们仔细浏览复制构造函数时，请注意我们逐步为属于`this`指向的对象的任何指针数据成员分配空间。分配的空间与`s`引用的数据成员所需的大小相同。然后我们小心地从源数据成员复制到目标数据成员。我们确保在目标对象中对源对象进行精确复制。

请注意，我们在目标对象中进行了*深复制*。也就是说，我们不是简单地将`s.firstName`中包含的指针复制到`this->firstName`，而是为`this->firstName`分配空间，然后复制源数据。浅复制的结果将是每个对象中的指针数据成员共享相同的解引用内存（即，每个指针指向的内存）。这很可能不是您在复制时想要的。还要记住，系统提供的复制构造函数的默认行为是从源对象到目标对象提供浅复制。

现在，让我们来看一下我们的`main()`函数，看看复制构造函数可能被调用的各种方式：

```cpp
int main()
{ 
    // instantiate two Students
    Student s1("Zachary", "Moon", 'R', 3.7, "C++");
    Student s2("Gabrielle", "Doone", 'A', 3.7, "C++");
   // These initializations implicitly invoke copy constructor
    Student s3(s1);  
    Student s4 = s2;
    strcpy(s3.firstName, "Zack");// alter each object slightly
    strcpy(s4.firstName, "Gabby"); 
    // This sequence does not invoke copy constructor 
    // This is instead an assignment.
    // Student s5("Giselle", "LeBrun", 'A', 3.1, "C++);
    // Student s6;
    // s6 = s5;  // this is an assignment, not initialization
    S1.Print();   // print each instance
    S3.Print();
    s2.Print();
    s4.Print();
    s1.CleanUp();  // Since some data members are pointers,
    s2.CleanUp(); // let's call a function to delete() them
    s3.CleanUp();
    s4.CleanUp();
    return 0;
}
```

在`main()`中，我们声明了两个`Student`的实例，`s1`和`s2`，并且每个都使用与`Student::Student(const char *, const char *, char, float, const char *);`签名匹配的构造函数进行初始化。请注意，实例化中使用的签名是我们选择隐式调用哪个构造函数的方式。

接下来，我们实例化`s3`，并将对象`s1`作为参数传递给它的构造函数，`Student s3(s1);`。在这里，`s1`是`Student`类型，因此这个实例化将匹配接受`Student`引用的构造函数，即复制构造函数。一旦进入复制构造函数，我们知道我们将对`this`指针在复制构造函数方法的范围内指向的新实例化对象`s3`进行`deep copy`。

此外，我们使用以下代码实例化`s4`：`Student s4 = s2;`。在这里，因为这行代码是一个初始化（也就是说，`s4`在同一语句中被声明并赋值），复制构造函数也将被调用。复制的源对象将是`s2`，目标对象将是`s4`。请注意，然后我们通过修改它们的`firstName`数据成员轻微修改了每个副本（`s3`和`s4`）。

接下来，在代码的注释部分，我们实例化了两个`Student`类型的对象`s5`和`s6`。然后我们尝试将一个赋值给另一个`s5 = s6;`。虽然这看起来与`s4`和`s2`之间的初始化类似，但实际上并不是。行`s5 = s6;`是一个赋值。每个对象之前都已存在。因此，复制构造函数在这段代码中不会被调用。尽管如此，这段代码是合法的，并且具有与赋值运算符类似的含义。我们将在本书后面讨论运算符重载时，详细研究这些细节*第十二章*，*运算符重载和友元*。

然后我们打印出对象`s1`、`s2`、`s3`和`s4`。然后我们对这四个对象中的每一个调用`Cleanup()`。为什么？每个对象都包含了指针数据成员，因此在这些外部栈对象超出范围之前，删除每个实例中包含的堆内存（即选择的指针数据成员）是合适的。

以下是完整程序示例的输出：

```cpp
Zachary R. Moon has a gpa of: 3.7 and is enrolled in: C++
Zack R. Moon has a gpa of: 3.7 and is enrolled in: C++
Gabrielle A. Doone has a gpa of: 3.7 and is enrolled in: C++
Gabby A. Doone has a gpa of: 3.7 and is enrolled in: C++
```

这个例子的输出显示了每个原始的`Student`实例，以及它的副本。请注意，每个副本都与原始副本略有不同（`firstName`不同）。

相关主题

有趣的是，赋值运算符与复制构造函数有许多相似之处，它可以允许数据从源实例复制到目标实例。然而，复制构造函数在初始化新对象时会被隐式调用，而赋值运算符在执行两个现有对象之间的赋值时会被调用。尽管如此，它们的方法看起来非常相似！我们将在*第十二章*中研究重载赋值运算符，以定制其行为以执行深度赋值（类似于深复制），*友元和运算符重载*。

现在我们对复制构造函数有了深入的了解，让我们来看看最后一种构造函数的变体，转换构造函数。

## 创建转换构造函数

类型转换可以从一个用户定义的类型转换为另一个用户定义的类型，或者从标准类型转换为用户定义的类型。转换构造函数是一种语言机制，允许这种转换发生。

**转换构造函数**是一个接受标准或用户定义类型的一个显式参数，并对该对象应用合理的转换或转换以初始化正在实例化的对象的构造函数。

让我们来看一个说明这个想法的例子。虽然例子将被分成几个片段并且也有所缩写，完整的程序可以在 GitHub 存储库中找到：

[`github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter05/Chp5-Ex6.cpp`](https://github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter05/Chp5-Ex6.cpp)

```cpp
#include <iostream>   
#include <cstring>   
using namespace std;
class Student;  // forward declaration of Student class
class Employee
{
private:
    char firstName[20];
    char lastName[20];
    float salary;
public:
    Employee();
    Employee(const char *, const char *, float);
    Employee(Student &);  // conversion constructor
    void Print();
};
class Student
{
private: // data members
    char *firstName;
    char *lastName;
    char middleInitial;
    float gpa;
    char *currentCourse;
public:
    // constructor prototypes
    Student();  // default constructor
    Student(const char *, const char *, char, float, 
            const char *);
    Student(const Student &);  // copy constructor
    void Print();
    void CleanUp();
    float GetGpa(); // access function for private data member
    const char *GetFirstName();
    const char *GetLastName();
};
```

在前面的程序片段中，我们首先包含了对`class Student;`的前向声明——这个声明允许我们在定义之前引用`Student`类型。然后我们定义`class Employee`。请注意，这个类包括几个`public`数据成员和三个构造函数原型——默认、替代和转换构造函数。值得一提的是，没有程序员指定的复制构造函数。这意味着编译器将提供默认（浅）复制构造函数。在这种情况下，由于没有指针数据成员，浅复制是可以接受的。

尽管如此，让我们继续通过检查转换构造函数的原型来进行。请注意，在原型中，这个构造函数接受一个参数。这个参数是`Student &`，这就是为什么我们需要对`Student`进行前向声明。最好的情况下，我们可能会使用`const Student &`作为参数类型，但为了这样做，我们需要了解 const 成员函数（本章后面会介绍）。将发生的类型转换将是将`Student`转换为新构造的`Employee`。我们的工作是在转换构造函数的定义中提供一个有意义的转换来实现这一点，我们很快就会看到。

接下来，我们定义我们的`Student`类，它与我们在以前的示例中看到的大致相同。

现在，让我们继续以示例来看`Employee`和`Student`的成员函数定义，以及我们的`main()`函数，在以下代码段中。为了节省空间，选择性地省略了一些成员函数定义；然而，在在线代码中将显示完整的程序。

继续前进，我们的`Employee`和`Student`的成员函数如下：

```cpp
Employee::Employee()  // default constructor
{
    firstName[0] = lastName[0] = '\0';  // null character
    salary = 0.0;
}
// alternate constructor
Employee::Employee(const char *fn, const char *ln, 
                   float money)
{
    strcpy(firstName, fn);
    strcpy(lastName, ln);
    salary = money;
}
// conversion constructor – argument is a Student not Employee
Employee::Employee(Student &s)
{
    strcpy(firstName, s.GetFirstName());
    strcpy(lastName, s.GetLastName());
    if (s.GetGpa() >= 4.0)
        salary = 75000;
    else if (s.GetGpa() >= 3.0)
        salary = 60000;
    else
        salary = 50000; 
}
void Employee::Print()
{
    cout << firstName << " " << lastName << " " << salary;
    cout << endl;
}
// Definitions for Student's default, alternate, copy
// constructors, Print()and CleanUp() have been omitted 
// for space, but are same as the prior Student example.
float Student::GetGpa()
{
    return gpa;
}
const char *Student::GetFirstName()
{
    return firstName;
}
const char *Student::GetLastName()
{
    return lastName;
}
```

在之前的代码段中，我们注意到了`Employee`的几个构造函数定义。我们有默认、替代和转换构造函数。

检查`Employee`转换构造函数的定义，注意源对象的形式参数是`s`，类型为`Student`。目标对象将是正在构造的`Employee`，它将由`this`指针指向。在这个函数的主体中，我们仔细地从`Student &s`复制`firstName`和`lastName`到新实例化的`Employee`。请注意，我们使用了访问函数`const char *Student::GetFirstName()`和`const char *Student::GetLastName()`来做到这一点（通过`Student`的一个实例），因为这些数据成员是`private`的。

让我们继续使用转换构造函数。我们的工作是提供一种有意义的从一种类型到另一种类型的转换。在这个努力中，我们试图根据源`Student`对象的`gpa`来为`Employee`建立一个初始工资。因为`gpa`是`private`的，所以使用访问函数`Student::GetGpa()`来检索这个值（通过源`Student`）。请注意，因为`Employee`没有任何动态分配的数据成员，所以我们不需要在这个函数的主体中分配内存来辅助深度复制。

为了节省空间，已省略了`Student`默认、替代和复制构造函数的成员函数定义，以及`void Student::Print()`和`void Student::CleanUp()`成员函数的定义。然而，它们与之前展示`Student`类的完整程序示例中的相同。

注意`Student`中`private`数据成员的访问函数，比如`float Student::GetGpa()`，已经被添加以提供对这些数据成员的安全访问。请注意，从堆栈返回的`float Student::GetGpa()`的值是`gpa`数据成员的副本。原始的`gpa`不会因为使用这个函数而受到侵犯。对于成员函数`const char *Student::GetFirstName()`和`const char *Student::GetLastName()`也是一样，它们每个都返回一个`const char *`，确保将返回的数据不会被侵犯。

让我们通过检查我们的`main()`函数来完成我们的程序：

```cpp
int main()
{
    Student s1("Giselle", "LeBrun", 'A', 3.5, "C++");
    Employee e1(s1);  // conversion constructor
    e1.Print();
    s1.CleanUp();  // CleanUp() will delete() s1's dynamically
    return 0;      // allocated data members
}
```

在我们的`main()`函数中，我们实例化了一个`Student`，即`s1`，它隐式地使用匹配的构造函数进行初始化。然后我们使用转换构造函数实例化了一个`Employee`，`e1`，在调用`Employee e1(s1);`时。乍一看，似乎我们正在使用`Employee`的复制构造函数。但是，仔细观察，我们注意到实际参数`s1`的类型是`Student`，而不是`Employee`。因此，我们使用`Student s1`作为初始化`Employee e1`的基础。请注意，在这种转换中，`Student` `s1`并没有受到任何伤害或改变。因此，最好将源对象定义为形式参数列表中的`const Student＆`；一旦我们理解了 const 成员函数，这将成为转换构造函数体中所需的内容，我们就可以这样做。

为了完成这个程序，我们使用`Employee::Print()`打印出`Employee`，这使我们能够可视化我们对`Student`到`Employee`的转换。

这是我们示例的输出：

```cpp
Giselle LeBrun 60000
```

在我们继续之前，有一个关于转换构造函数的最后一个微妙细节非常重要，需要理解。

重要说明

任何只带有一个参数的构造函数都被视为转换构造函数，它可能被用来将参数类型转换为它所属的类的对象类型。例如，如果`Student`类中有一个只接受 float 的构造函数，这个构造函数不仅可以像上面的示例那样使用，还可以在期望`Student`类型的参数（例如函数调用）的地方使用，而实际提供的是 float 类型的参数。这可能不是您的意图，这就是为什么要提出这个有趣的特性。如果您不希望进行隐式转换，可以通过在其原型的开头声明带有`explicit`关键字的构造函数来禁用此行为。

现在我们已经了解了 C++中的基本、替代、复制和转换构造函数，让我们继续探索构造函数的补充成员函数，C++析构函数。

# 理解析构函数

您是否还记得类构造函数多么方便地为我们提供了初始化新实例对象的方法？而不是必须记住为给定类型的每个实例调用`Initialize()`方法，构造函数允许自动初始化。在构造中使用的签名有助于指定应使用一系列构造函数中的哪一个。

对象清理呢？许多类包含动态分配的数据成员，这些数据成员通常在构造函数中分配。当程序员完成实例后，组成这些数据成员的内存不应该被释放吗？当然。我们为几个示例程序编写了`CleanUp()`成员函数。并且我们记得调用`CleanUp()`。方便的是，与构造函数类似，C++具有一个自动内置的功能作为清理函数。这个函数被称为析构函数。

让我们看看析构函数以了解其正确的使用方法。

## 应用析构函数的基础知识和正确使用

**析构函数**是一个成员函数，其目的是释放对象在其存在期间可能获取的资源。当类或结构实例：

+   超出范围（这适用于非指针变量）

+   显式使用 delete 进行释放（对于对象指针）

析构函数应该（通常）清理构造函数可能分配的任何内存。析构函数的名称是`~`字符后跟`class`名称。析构函数不带参数；因此，它不能被重载。最后，析构函数的返回类型可能不被指定。类和结构都可以有析构函数。

除了释放构造函数可能分配的内存之外，析构函数还可以用于执行实例的其他生命周期任务，例如将值记录到数据库中。更复杂的任务可能包括通知类数据成员指向的对象（其内存未被释放）即将结束的对象。如果链接的对象包含指向终止对象的指针，则这可能很重要。我们将在本书的后面看到这方面的例子，在*第十章*，*实现关联、聚合和组合*。

如果您没有提供析构函数，编译器将创建并链接一个带空体的`public`析构函数。这是必要的，因为析构函数调用会在本地实例被弹出堆栈之前自动打补丁，并且在应用`delete()`到动态分配的实例之前自动打补丁。对于编译器来说，总是打补丁比不断查看您的类是否有析构函数更容易。一个好的经验法则是始终自己提供类析构函数。

还有一些潜在的陷阱。例如，如果您忘记删除动态分配的实例，那么析构函数调用将不会为您打补丁。C++是一种给予您灵活性和权力来做（或不做）任何事情的语言。如果您不使用给定标识符删除内存（也许两个指针引用相同的内存），请记住以后通过其他标识符删除它。

还有一件值得一提的事情。虽然您可以显式调用析构函数，但您很少需要这样做。析构函数调用会在编译器自动为您打补丁在上述情况下。只有在非常少数的高级编程情况下，您才需要自己显式调用析构函数。

让我们看一个简单的例子，说明一个类析构函数，它将被分为三个部分。完整的示例可以在此处列出的 GitHub 存储库中看到：

[`github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter05/Chp5-Ex7.cpp`](https://github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter05/Chp5-Ex7.cpp)

```cpp
#include <iostream>  
#include <cstring> 
using namespace std;
class University
{
private:
    char *name;
    int numStudents;
public: 
    // constructor prototypes
    University(); // default constructor
    University(const char *, int);  // alternate constructor
    University(const University &);  // copy constructor
    ~University();  // destructor prototype
    void Print();
};
```

在上一段代码中，我们首先定义了`class University`。请注意`private`访问区域中填充了数据成员，以及`public`接口，其中包括默认、替代和复制构造函数的原型，以及析构函数和`Print()`方法。

接下来，让我们看一下各种成员函数的定义：

```cpp
University::University()  // default constructor
{
    name = 0;  // NULL pointer
    numStudents = 0;
}
University::University(const char * n, int num) 
{
    name = new char [strlen(n) + 1];
    strcpy(name, n);
    numStudents = num;
}
University::University(const University &u) // copy const
{
    name = new char [strlen(u.name) + 1];  // deep copy
    strcpy(name, u.name);
    numStudents = u.numStudents;
}
University::~University()  // destructor definition
{
    delete name;
    cout << "Destructor called " << this << endl;
}
void University::Print()
{
    cout << "University: " << name;
    cout << " Enrollment: " << numStudents << endl;
}
```

在上述代码片段中，我们看到了我们现在习惯于看到的各种重载构造函数，以及`void University::Print()`。新添加的是析构函数定义。

请注意析构函数`University::~University()`不带参数；它可能不会被重载。析构函数只是释放可能在任何构造函数中分配的内存。请注意，我们只是`delete name;`，无论`name`指向有效地址还是包含空指针（是的，将 delete 应用于空指针是可以的）。此外，我们在析构函数中打印`this`指针，只是为了好玩，这样我们就可以看到即将不存在的实例的地址。

接下来，让我们看一下`main()`，看看何时可能调用析构函数：

```cpp
int main()
{
    University u1("Temple University", 39500);
    University *u2 = new University("Boston U", 32500);
    u1.Print();
    u2->Print();
    delete u2;   // destructor will be called before delete()
                 // destructor for u1 will be called before
    return 0;    // program completes 
}
```

在这里，我们实例化了两个`University`实例；`u1`是一个实例，`u2`指向一个实例。我们知道`u2`在其内存可用时被实例化，并且一旦内存可用，就会调用适用的构造函数。接下来，我们为两个实例调用`University::Print()`以获得一些输出。

最后，在`main()`的末尾，我们删除`u2`，将这块内存返回给堆管理设施。就在调用`delete()`之前，C++会插入一个调用`u2`指向的对象的析构函数的指令。就好像在`delete u2;`之前，一个秘密的函数调用`u2->~University();`已经被插入了一样（注意，这是自动完成的；你不需要自己这样做）。隐式调用析构函数将删除类中可能已经分配的任何数据成员的内存。现在，对于`u2`，内存释放已经完成。

那么实例`u1`呢？它的析构函数会被调用吗？会的；`u1`是一个栈实例。在`main()`中，就在其内存被弹出栈之前，编译器会插入一个调用其析构函数的指令，就好像为你添加了`u1.~University();`的调用一样（同样，你不需要自己这样做）。对于实例`u1`，析构函数也会释放为数据成员分配的任何内存。同样，对于`u1`，内存释放现在已经完成。

请注意，在每次析构函数调用时，我们都打印了一条消息，以说明析构函数何时被调用，并且还打印了`this`的内存地址，以便让你在每个特定的实例被析构时进行可视化。

这是我们完整程序示例的输出：

```cpp
University: Temple University Enrollment: 39500
University: Boston U Enrollment: 32500
Destructor called 0x10d1958
Destructor called 0x60fe74
```

通过这个例子，我们现在已经检查了析构函数，这是一系列类构造函数的补充。让我们继续讨论与类相关的另一组有用主题：数据成员和成员函数的各种关键字资格。

# 对数据成员和成员函数应用限定符

在本节中，我们将调查可以添加到数据成员和成员函数的限定符。各种限定符——`inline`、`const`和`static`——可以支持程序的效率，帮助保持私有数据成员的安全，支持封装和信息隐藏，并且还可以用于实现各种面向对象的概念。

让我们开始了解各种成员资格的类型。

## 为了提高效率添加内联函数

想象一下你的程序中有一组短的成员函数，它们会被各种实例重复调用。作为一个面向对象的程序员，你喜欢使用`public`成员函数来提供对`private`数据的安全和受控访问。然而，对于非常短的函数，你担心效率问题，也就是说，重复调用一个小函数会带来开销。当然，直接粘贴包含函数的两三行代码会更有效率。但是，你会抵制这样做，因为这可能意味着提供对本来隐藏的类信息（如数据成员）的`public`访问，这是你不愿意做的。内联函数可以解决这个困境，它允许你拥有一个成员函数来访问和操作你的私有数据的安全性，同时又能够执行几行代码而不需要函数调用的开销。

**inline**函数是一个其调用被替换为函数本身的函数。内联函数可以帮助消除调用非常小的函数所带来的开销。

为什么调用函数会有开销？当调用函数时，输入参数（包括`this`）被推送到栈上，为函数的返回值保留空间（尽管有时会使用寄存器），转移到代码的另一个部分需要在寄存器中存储信息以跳转到代码的那一部分，等等。用内联函数替换非常小的函数体可以提高程序的效率。

内联函数可以通过以下方式之一指定：

+   将函数定义放在类定义内部

+   在（典型的）函数定义中，在类定义之外找到关键字`inline`之前的返回类型。

在上述两种方式中将函数指定为`inline`只是一个请求，要求编译器考虑将函数体替换为其函数调用。这种替换不能保证。编译器何时可能不实际内联给定的函数？如果一个函数是递归的，它就不能被内联。同样，如果一个函数很长，编译器就不会内联这个函数。此外，如果函数调用是动态绑定的，具体实现在运行时确定（虚函数），它就不能被内联。

`inline`函数定义应该在头文件中与相应的类定义一起声明。这将允许对函数的任何修订在需要时重新扩展正确。

让我们看一个使用`inline`函数的例子。程序将被分成两个部分，其中一些众所周知的函数被移除。然而，完整的程序可以在 GitHub 存储库中看到：

[`github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter05/Chp5-Ex8.cpp`](https://github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter05/Chp5-Ex8.cpp)

```cpp
#include <iostream>  
#include <cstring> 
using namespace std;
class Student
{
private: 
    // data members
    char *firstName;
    char *lastName;
    char middleInitial;
    float gpa;
    char *currentCourse;
public:
    // member function prototypes
    Student();  // default constructor
    Student(const char *, const char *, char, float, 
            const char *); 
    Student(const Student &);  // copy constructor
    ~Student();  // destructor
    void Print();
    // inline function definitions
    const char *GetFirstName() { return firstName; }  
    const char *GetLastName() { return lastName; }    
    char GetMiddleInitial() { return middleInitial; }
    float GetGpa() { return gpa; }
    const char *GetCurrentCourse() { return currentCourse; }
    // prototype only, see inline function definition below
    void SetCurrentCourse(const char *);
};
inline void Student::SetCurrentCourse(const char *c)
{
    delete currentCourse;  
    currentCourse = new char [strlen(c) + 1];
    strcpy(currentCourse, c); 
}
```

在前面的程序片段中，让我们从类定义开始。注意，在类定义中已经添加了几个访问函数定义，即`GetFirstName()`、`GetLastName()`等函数。仔细看；这些函数实际上是在类定义内部定义的。例如，`float GetGpa() { return gpa; }`不仅仅是原型，而是完整的函数定义。由于函数放置在类定义内部，这样的函数被认为是`inline`。

这些小函数提供了对私有数据成员的安全访问。例如，注意`const char *GetFirstName()`。这个函数返回一个指向`firstName`的指针，它在类中存储为`char *`。但是因为这个函数的返回值是`const char *`，这意味着调用这个函数的任何人都必须将返回值视为`const char *`，这意味着将其视为不可修改。如果这个函数的返回值被存储在一个变量中，那么这个变量也必须被定义为`const char *`。通过将这个指针向上转换为不可修改版本的自身，我们添加了一个规定，即没有人可以得到一个`private`数据成员（指针），然后改变它的值。

现在注意一下类定义的末尾，我们有一个`void SetCurrentCourse(const char *);`的原型。然后，在类定义之外，我们将看到这个成员函数的定义。注意在这个函数定义的`void`返回类型之前有关键字`inline`。由于这个函数是在类定义之外定义的，必须明确使用关键字。请记住，无论使用哪种`inline`方法，`inline`规范只是一个请求，要求编译器将函数体替换为函数调用。

让我们继续通过检查我们程序的其余部分来继续这个例子：

```cpp
// Definitions for default, alternate, copy constructor,
// and Print() have been omitted for space,
// but are same as last example for class Student
// the destructor is shown because we have not yet seen
// an example destructor for the Student class
Student::~Student()
{
    delete firstName;
    delete lastName;
    delete currentCourse;
}
int main()
{
    Student s1("Jo", "Muritz", 'Z', 4.0, "C++"); 
    cout << s1.GetFirstName() << " " << s1.GetLastName();
    cout << " Enrolled in: " << s1.GetCurrentCourse() << endl;
    s1.SetCurrentCourse("Advanced C++ Programming"); 
    cout << s1.GetFirstName() << " " << s1.GetLastName();
    cout << " New course: " << s1.GetCurrentCourse() << endl;
    return 0;
}
```

请注意，在我们的程序示例的其余部分中，省略了几个成员函数定义。这些函数的主体与前面的示例中完整展示了`Student`类的函数体相同，也可以在线查看。

让我们转而关注我们的`main()`函数。在这里，我们实例化了一个`Student`，名为`s1`。然后通过`s1`调用了几个`inline`函数，比如`s1.GetFirstName();`。因为`Student::GetFirstName()`是内联的，所以就好像我们直接访问数据成员`firstName`一样，因为这个函数的主体只有一个`return firstName;`语句。我们既可以使用函数来访问`private`数据成员（意味着在类的范围之外没有人可以修改这个数据成员），又可以使用`inline`函数的代码扩展来消除函数调用的开销。

在`main()`中，我们以相同的方式对`inline`函数进行了几次调用，包括`s1.SetCurrentCourse();`。现在我们既有封装访问的安全性，又可以使用小型的`inline`函数直接访问数据成员，从而提高速度。

以下是我们完整程序示例的输出：

```cpp
Jo Muritz Enrolled in: C++
Jo Muritz New course: Advanced C++ Programming
```

现在让我们继续探讨我们可以添加到类成员的另一个限定符，即`const`限定符。

## 添加 const 数据成员和成员初始化列表

在本书的前面，我们已经看到了如何对变量进行常量限定以及这样做的影响。简而言之，向变量添加`const`限定符的含义是变量在声明时必须被初始化，并且其值可能永远不会被修改。我们之前还看到了如何向指针添加`const`限定，以便我们可以对被指向的数据、指针本身或两者都进行限定。现在让我们来看看向类内的数据成员添加`const`限定符意味着什么，以及了解必须使用的特定语言机制来初始化这些数据成员。

永远不应该被修改的数据成员应该被限定为`const`。一个`const`变量，*永远不会被修改*意味着该数据成员不能使用自己的标识符进行修改。那么我们的工作就是确保我们不会用非`const`标记的对象初始化我们的指向`const`对象的数据成员（以免为修改私有数据提供后门）。

请记住，在 C++中，程序员总是可以将指针变量的 const 性质去除。尽管他们不应该这样做。尽管如此，我们将采取安全措施，确保通过使用访问区域和从访问函数返回适当的值，我们不会轻易提供对`private`数据成员的可修改访问。

**成员初始化列表**必须在构造函数中用于初始化任何常量数据成员或引用。成员初始化列表提供了一种机制，用于初始化可能永远不会成为赋值的 l-values 的数据成员。成员初始化列表也可以用于初始化非 const 数据成员。出于性能原因，成员初始化列表通常是初始化任何数据成员（const 或非 const）的首选方式。

成员初始化列表可以出现在任何构造函数中，只需在形式参数列表后面放置一个`:`，然后是一个逗号分隔的数据成员列表，每个数据成员都与括号中的初始值配对。例如，在这里我们使用成员初始化列表来设置两个数据成员，`studentId`和`gpa`：

```cpp
Student::Student(): studentId(0), gpa(0.0)
{
   firstName = lastName = 0;  // NULL pointer
   middleInitial = '\0';
   currentCourse = 0;
}
```

有趣的是，引用必须使用成员初始化列表，因为引用被实现为常量指针。也就是说，指针本身指向特定的其他对象，不得指向其他地方。该对象的值可能会改变，但引用始终引用特定的对象，即初始化时的对象。

使用指针与`const`限定符可能会让人难以确定哪些情况需要使用初始化列表，哪些情况不需要。例如，指向常量对象的指针不需要使用成员初始化列表进行初始化。指针可以指向任何对象，但一旦指向对象后，就不能改变所引用的值。然而，常量指针必须使用成员初始化列表进行初始化，因为指针本身被固定在特定的地址上。

让我们看一个`const`数据成员的例子，以及如何使用成员初始化列表在完整的程序示例中初始化它的值。我们还将看到如何使用这个列表来初始化非 const 数据成员。虽然这个例子被分割并没有完整显示，但完整的程序可以在 GitHub 存储库中找到：

[`github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter05/Chp5-Ex9.cpp`](https://github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter05/Chp5-Ex9.cpp)

```cpp
#include <iostream>  
#include <cstring> 
using namespace std;
class Student
{
private: 
    // data members
    char *firstName;
    char *lastName;
    char middleInitial;
    float gpa;
    char *currentCourse;
    const int studentId;   // constant data member
public:
    // member function prototypes
    Student();  // default constructor
    Student(const char *, const char *, char, float, 
            const char *, int); 
    Student(const Student &);  // copy constructor
    ~Student();  // destructor
    void Print();
    const char *GetFirstName() { return firstName; }  
    const char *GetLastName() { return lastName; }    
    char GetMiddleInitial() { return middleInitial; }
    float GetGpa() { return gpa; }
    const char *GetCurrentCourse() { return currentCourse; }
    void SetCurrentCourse(const char *);  // prototype only
};
```

在上述的`Student`类中，注意我们已经在类定义中添加了一个数据成员`const int studentId;`。这个数据成员将需要使用成员初始化列表来初始化每个构造函数中的这个常量数据成员。

让我们看看成员初始化列表如何在构造函数中工作：

```cpp
// Usual definitions for the destructor, Print(), and 
// SetCurrentCourse() have been omitted to save space.
Student::Student(): studentId(0), gpa(0.0) // mbr. Init. list
{
   firstName = lastName = 0;  // NULL pointer
   middleInitial = '\0';
   currentCourse = 0;
}
Student::Student(const char *fn, const char *ln, char mi,
         float avg, const char *course, int id): 
         studentId (id), gpa (avg), middleInitial(mi)
{
   firstName = new char [strlen(fn) + 1];
   strcpy(firstName, fn);
   lastName = new char [strlen(ln) + 1];
   strcpy(lastName, ln);
   currentCourse = new char [strlen(course) + 1];
   strcpy(currentCourse, course);
}
Student::Student(const Student &s): studentId (s.studentId)
{
   firstName = new char [strlen(s.firstName) + 1];
   strcpy(firstName, s.firstName);
   lastName = new char [strlen(s.lastName) + 1];
   strcpy(lastName, s.lastName);
   middleInitial = s.middleInitial;
   gpa = s.gpa;
   currentCourse = new char [strlen(s.currentCourse) + 1];
   strcpy(currentCourse, s.currentCourse);
}
int main()
{ 
    Student s1("Renee", "Alexander", 'Z', 3.7, "C++", 1290);
    cout << s1.GetFirstName() << " " << s1.GetLastName();
    cout << " has gpa of: " << s1.GetGpa() << endl;
    return 0;
}
```

在上面的代码片段中，我们看到了三个`Student`构造函数。注意每个构造函数的形式参数列表后面都有一个`:`指定的各种成员初始化列表。

每个构造函数将使用成员初始化列表来设置`const`数据成员的值，比如`studentId`。此外，成员初始化列表可以作为一种简单的方式来初始化任何其他数据成员。我们可以通过查看默认或替代构造函数中的成员初始化列表来看到成员初始化列表被用来简单地设置非 const 数据成员的例子，例如`Student::Student() : studentId(0), gpa(0.0)`。在这个例子中，`gpa`不是`const`，所以在成员初始化列表中使用它是可选的。

这是我们完整程序示例的输出：

```cpp
Renee Alexander has gpa of: 3.7
```

接下来，让我们通过向成员函数添加`const`限定符来继续前进。

## 使用 const 成员函数

我们现在已经相当详尽地看到了常量限定符与数据一起使用。它也可以与成员函数一起使用。C++提供了一种语言机制来确保选定的函数不会修改数据；这种机制就是作用于成员函数的`const`限定符。

**const 成员函数**是指定（并强制执行）该方法只能对调用该函数的对象执行只读操作的成员函数。

常量成员函数意味着`this`的任何部分都不能被修改。然而，因为 C++允许类型转换，可以将`this`转换为它的非 const 对应部分，然后修改数据成员。然而，如果类设计者真的希望能够修改数据成员，他们简单地不会将成员函数标记为`const`。

程序中声明的常量实例只能调用`const`成员函数。否则这些对象可能会被直接修改。

要将成员函数标记为`const`，关键字`const`应该在函数原型和函数定义的参数列表之后指定。

让我们看一个例子。它将被分成两个部分，有些部分被省略了；然而，完整的例子可以在 GitHub 存储库中看到：

[`github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter05/Chp5-Ex10.cpp`](https://github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter05/Chp5-Ex10.cpp)

```cpp
#include <iostream>  
#include <cstring> 
using namespace std;
class Student
{
private: 
    // data members
    char *firstName;
    char *lastName;
    char middleInitial;
    float gpa;
    char *currentCourse;
    const int studentId;   // constant data member
public:
    // member function prototypes
    Student();  // default constructor
    Student(char *, char *, char, float, char *, int); 
    Student(const Student &);  // copy constructor
    ~Student();  // destructor
    void Print() const;
    const char *GetFirstName() const { return firstName; }  
    const char *GetLastName() const { return lastName; }    
    char GetMiddleInitial() const { return middleInitial; }
    float GetGpa() const { return gpa; }
    const char *GetCurrentCourse() const
        { return currentCourse; }
    int GetStudentId() const { return studentId; }
    void SetCurrentCourse(const char *);  // prototype only
};
```

在前面的程序片段中，我们看到了`Student`的类定义，这对我们来说已经非常熟悉了。然而，请注意，我们已经将`const`限定符添加到大多数访问成员函数中，也就是说，那些只提供只读访问数据的方法。

例如，让我们考虑`float GetGpa() const { return gpa; }`。参数列表后面的`const`关键字表示这是一个常量成员函数。请注意，这个函数不修改`this`指向的任何数据成员。它不能这样做，因为它被标记为`const`成员函数。

现在，让我们继续探讨这个例子的其余部分：

```cpp
// Definitions for the constructors, destructor, and 
// SetCurrentCourse() have been omitted to save space.
// Student::Print() has been revised, so it is shown below:
void Student::Print() const
{
    cout << firstName << " " << middleInitial << ". ";
    cout << lastName << " with id: " << studentId;
    cout << " and gpa: " << gpa << " is enrolled in: ";
    cout << currentCourse << endl;
}
int main()
{
    Student s1("Zack", "Moon", 'R', 3.75, "C++", 1378); 
    cout << s1.GetFirstName() << " " << s1.GetLastName();
    cout << " Enrolled in " << s1.GetCurrentCourse() << endl;
    s1.SetCurrentCourse("Advanced C++ Programming");  
    cout << s1.GetFirstName() << " " << s1.GetLastName();
    cout << " New course: " << s1.GetCurrentCourse() << endl;
    const Student s2("Gabby", "Doone", 'A', 4.0, "C++", 2239);
    s2.Print();
    // Not allowed, s2 is const
    // s2.SetCurrentCourse("Advanced C++ Programming");  
    return 0;
}
```

在本程序的其余部分中，请注意，我们再次选择不包括我们已经熟悉的成员函数的定义，比如构造函数、析构函数和`void Student::SetCurrentCourse()`。

相反，让我们把注意力集中在具有签名`void Student::Print() const`的成员函数上。在这里，参数列表后面的`const`关键字表示在这个函数的范围内，`this`指向的任何数据成员都不能被修改。同样，`void Student::Print()`中调用的任何成员函数也必须是`const`成员函数。否则，它们可能会修改`this`。

继续检查我们的`main()`函数，我们实例化了一个`Student`，即`s1`。这个`Student`调用了几个成员函数，包括一些是`const`的。然后，`Student s1`使用`Student::SetCurrentCourse()`改变了他们的当前课程，然后打印了这门课的新值。

接下来，我们实例化了另一个`Student`，`s2`，它被限定为`const`。请注意，一旦这个学生被实例化，只有那些被标记为`const`的成员函数才能应用于`s2`。否则，实例可能会被修改。然后，我们使用`Student::Print();`打印了`s2`的数据，这是一个`const`成员函数。

你注意到了被注释掉的代码行：`s2.SetCurrentCourse("Advanced C++ Programming");`吗？这行代码是非法的，不会编译通过，因为`SetCurrentCourse()`不是一个常量成员函数，因此不能通过常量实例（如`s2`）调用。

让我们来看一下完整程序示例的输出：

```cpp
Zack Moon Enrolled in C++
Zack Moon New course: Advanced C++ Programming
Gabby A. Doone with id: 2239 and gpa: 3.9 is enrolled in: C++
```

既然我们已经充分探讨了`const`成员函数，让我们继续到本章的最后一部分，深入研究`static`数据成员和`static`成员函数。

## 利用静态数据成员和静态成员函数

现在我们已经开始使用 C++类来定义和实例化对象，让我们通过探索类属性的概念来增加我们对面向对象概念的了解。一个旨在被特定类的所有实例共享的数据成员被称为**类属性**。

通常，给定类的每个实例都有其数据成员的不同值。然而，偶尔，让给定类的所有实例共享一个包含单个值的数据成员可能是有用的。在 C++中，可以使用**静态数据成员**来建模类属性的面向对象概念。

`static`数据成员本身被建模为外部（全局）变量，其作用域通过*名称修饰*与相关类绑定。因此，每个静态数据成员的作用域可以限制在相关类中。

为了模拟`static`数据成员，必须在类定义中的`static`数据成员规范之后，跟随一个外部变量定义，位于类外部。这个*类成员*的存储是通过外部变量及其底层实现获得的。

类或结构中的`static`数据成员。`static`成员函数不接收`this`指针；因此，它只能操作`static`数据成员和其他外部（全局）变量。

要指示一个`static`成员函数，必须在成员函数原型的返回类型前指定关键字`static`。关键字`static`不得出现在成员函数定义中。如果关键字`static`出现在函数定义中，该函数将在 C 编程意义上另外成为`static`；也就是说，该函数将被限制在定义它的文件中。

让我们来看一个`static`数据成员和成员函数的使用示例。以下示例将被分成几个部分；但是，它将以完整形式出现，没有省略或缩写任何函数，因为它是本章的最终示例。它也可以在 GitHub 存储库中完整找到：

[`github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter05/Chp5-Ex11.cpp`](https://github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter05/Chp5-Ex11.cpp)

```cpp
#include <iostream>  
#include <cstring> 
using namespace std;
class Student
{
private: 
    // data members
    char *firstName;
    char *lastName;
    char middleInitial;
    float gpa;
    char *currentCourse;
    const char *studentId;  // pointer to constant string
    static int numStudents; // static data member
public:
    // member function prototypes
    Student();  // default constructor
    Student(const char *, const char *, char, float, 
            const char *, const char *); 
    Student(const Student &);  // copy constructor
    ~Student();  // destructor
    void Print() const;
    const char *GetFirstName() const { return firstName; }  
    const char *GetLastName() const { return lastName; } 
    char GetMiddleInitial() const { return middleInitial; }
    float GetGpa() const { return gpa; }
    const char *GetCurrentCourse() const 
        { return currentCourse; }
    const char *GetStudentId() const { return studentId; }
    void SetCurrentCourse(const char *);
    static int GetNumberStudents(); // static member function 
};
// definition for static data member 
// (which is implemented as an external variable)
int Student::numStudents = 0;  // notice initial value of 0
// Definition for static member function
inline int Student::GetNumberStudents()
{
    return numStudents;
}
inline void Student::SetCurrentCourse(const char *c) 
{
    delete currentCourse;  
    currentCourse = new char [strlen(c) + 1];
    strcpy(currentCourse, c); 
}
```

在我们完整示例的第一个代码段中，我们有我们的`Student`类定义。在`private`访问区域中，我们添加了一个数据成员`static int numStudents;`，以模拟面向对象的概念，即类属性，这是一个将被该类的所有实例共享的数据成员。

接下来，请注意在这个类定义的末尾，我们添加了一个`static`成员函数`static int GetNumberStudents();`，以提供对`private`数据成员`numStudents`的封装访问。请注意，关键字`static`只在原型中添加。如果我们在类定义之外查看`int Student::GetNumberStudents()`的成员函数定义，我们会注意到在该函数定义本身中没有使用`static`关键字。这个成员函数的主体只是返回共享的`numStudents`，即静态数据成员。

还要注意，在类定义的下面，有一个外部变量定义，以支持静态数据成员的实现：`int Student::numStudents = 0;`。请注意，这个声明使用`::`（作用域解析运算符）将类名与标识符`numStudents`关联起来。尽管这个数据成员被实现为外部变量，因为数据成员被标记为`private`，它只能被`Student`类中的成员函数访问。将`static`数据成员实现为外部变量有助于我们理解这个共享数据的内存来自哪里；它不是类的任何实例的一部分，而是作为一个单独的实体存储在全局命名空间中。还要注意，声明`int Student::numStudents = 0;`将这个共享变量初始化为零。

作为一个有趣的侧面，注意在我们的`Student`类的这个新版本中，数据成员`studentId`已经从`const int`更改为`const char *studentId;`。请记住，这意味着`studentId`是一个指向常量字符串的指针，而不是一个常量指针。因为指针本身的内存不是`const`，所以这个数据成员不需要使用成员初始化列表进行初始化，但它将需要一些特殊处理。

让我们继续审查构成这个类的其他成员函数：

```cpp
Student::Student(): studentId (0) // default constructor
{
    firstName = lastName = 0;  // NULL pointer
    middleInitial = '\0';
    gpa = 0.0;
    currentCourse = 0;
    numStudents++;       // increment static counter
}
// Alternate constructor member function definition
Student::Student(const char *fn, const char *ln, char mi, 
          float avg, const char *course, const char *id) 
{
    firstName = new char [strlen(fn) + 1];
    strcpy(firstName, fn);
    lastName = new char [strlen(ln) + 1];
    strcpy(lastName, ln);
    middleInitial = mi;
    gpa = avg;
    currentCourse = new char [strlen(course) + 1];
    strcpy(currentCourse, course);
    char *temp = new char [strlen(id) + 1];
    strcpy (temp, id);  // studentId can't be an lvaue,  
    studentId = temp;   // but temp can!
    numStudents++;      // increment static counter
}
Student::Student(const Student &s)   // copy constructor 
{
    firstName = new char [strlen(s.firstName) + 1];
    strcpy(firstName, s.firstName);
    lastName = new char [strlen(s.lastName) + 1];
    strcpy(lastName, s.lastName);
    middleInitial = s.middleInitial;
    gpa = s.gpa;
    currentCourse = new char [strlen(s.currentCourse) + 1];
    strcpy(currentCourse, s.currentCourse);
    char *temp = new char [strlen(s.studentId) + 1];
    strcpy (temp, s.studentId); //studentId can't be an lvaue, 
    studentId = temp;           // but temp can!
    numStudents++;    // increment static counter
}

Student::~Student()    // destructor definition
{
    delete firstName;
    delete lastName;
    delete currentCourse;
    delete (char *) studentId; // cast is necessary for delete
    numStudents--;   // decrement static counter
}
void Student::Print() const
{
   cout << firstName << " " << middleInitial << ". ";
   cout << lastName << " with id: " << studentId;
   cout << " and gpa: " << gpa << " and is enrolled in: ";
   cout << currentCourse << endl;
}
```

在成员函数的上一个程序段中，大多数成员函数看起来我们已经习惯看到的样子，但也有一些细微的差异。

一个与我们的`static`数据成员相关的不同之处是，`numStudents`在每个构造函数中递增，并在析构函数中递减。由于这个`static`数据成员被`class Student`的所有实例共享，每次实例化一个新的`Student`，计数器都会增加，当一个`Student`实例停止存在并且它的析构函数被隐式调用时，计数器将递减以反映这样一个实例的移除。这样，`numStudents`将准确反映我们的应用程序中存在多少`Student`实例。

这段代码还有一些其他有趣的细节需要注意，与`static`数据成员和成员函数无关。例如，在我们的类定义中，我们将`studentId`从`const int`更改为`const char *`。这意味着指向的数据是常量，而不是指针本身，因此我们不需要使用成员初始化列表来初始化这个数据成员。

尽管如此，在默认构造函数中，我们选择使用成员初始化列表将`studentId`初始化为`0`，意味着一个空指针。回想一下，我们可以使用成员初始化列表来初始化任何数据成员，但我们必须使用它来初始化`const`数据成员。也就是说，如果`const`部分等同于为实例分配的内存。由于在数据成员`studentId`的实例中分配的内存是一个指针，并且该数据成员的指针部分不是`const`（只是指向的数据），我们不需要为这个数据成员使用成员初始化列表。我们只是选择这样做。

然而，因为`studentId`是一个`const char *`，这意味着标识符`studentId`可能不作为 l 值，或者在赋值的左侧。在替代和复制构造函数中，我们希望初始化`studentId`，并且需要能够使用`studentId`作为 l 值。但我们不能。我们通过声明一个辅助变量`char *temp;`来规避这个困境，并分配它来包含我们需要加载所需数据的内存量。然后我们将所需的数据加载到`temp`中，最后我们让`studentId`指向`temp`来为`studentId`建立一个值。当我们离开每个构造函数时，局部指针`temp`被弹出堆栈；然而，内存现在被`studentId`捕获并被视为`const`。

最后，在析构函数中，请注意，为了删除与`const char *studentid`相关联的内存，我们需要将`studentId`强制转换为非常量`char *`，因为`delete()`操作符期望的是非常量限定的指针。

现在我们已经完成了对成员函数中新细节的审查，让我们继续通过检查程序示例的最后部分来进行：

```cpp
int main()
{
    Student s1("Nick", "Cole", 'S', 3.65, "C++", "112HAV"); 
    Student s2("Alex", "Tost", 'A', 3.78, "C++", "674HOP"); 
    cout << s1.GetFirstName() << " " << s1.GetLastName();
    cout << " Enrolled in " << s1.GetCurrentCourse() << endl;
    cout << s2.GetFirstName() << " " << s2.GetLastName();
    cout << " Enrolled in " << s2.GetCurrentCourse() << endl;

    // call a static member function in the preferred manner
    cout << "There are " << Student::GetNumberStudents(); 
    cout << " students" << endl;
    // Though not preferable, we could also use:
    // cout << "There are " << s1.GetNumberStudents(); 
    // cout << " students" << endl;
    return 0;
}
```

在我们程序的`main()`函数中，我们首先实例化两个`Students`，`s1`和`s2`。当每个实例被构造初始化时，共享数据成员值`numStudents`被递增以反映我们应用程序中的学生数量。请注意，外部变量`Student::numStudents`，它保存了这个共享数据成员的内存，在程序开始时被初始化为`0`，在我们的代码中之前的语句：`int Student::numStudents = 0;`。

在为每个`Student`打印一些细节之后，我们使用`static`访问函数`Student::GetNumStudents()`打印出`static`数据成员`numStudents`。调用这个函数的首选方式是`Student::GetNumStudents();`。因为`numStudents`是`private`的，只有`Student`类的方法才能访问这个数据成员。我们现在使用`static`成员函数提供了对`static`数据成员的安全、封装访问。

有趣的是，要记住`static`成员函数不会接收到`this`指针，因此它们可能操作的唯一数据将是类中的`static`数据（或其他外部变量）。同样，它们可能调用的唯一其他函数将是同一类中的其他`static`成员函数，或者外部非成员函数。

有趣的是，我们似乎可以通过任何实例调用`Student::GetNumStudents()`，比如`s1.GetNumStudents();`，就像我们在代码的注释部分中看到的那样。尽管看起来我们是通过一个实例调用成员函数，但函数不会接收到`this`指针。相反，编译器会重新解释调用，似乎是通过一个实例，然后用对内部的*name-mangled*函数的调用替换这个调用。从编程的角度来看，使用第一种调用方法来调用`static`成员函数更清晰，而不是似乎是通过一个永远不会传递给函数本身的实例来调用。

最后，这是我们完整程序示例的输出：

```cpp
Nick Cole Enrolled in C++
Alex Tost Enrolled in C++
There are 2 students
```

现在我们已经回顾了本章的最后一个例子，是时候总结我们所学到的一切了。

# 总结

在本章中，我们已经开始了面向对象编程的旅程。我们学习了许多面向对象的概念和术语，并看到了 C++如何直接支持实现这些概念。我们看到了 C++类如何支持封装和信息隐藏，并且实现支持这些理想的设计如何导致更容易修改和维护的代码。

我们已经详细介绍了类的基础知识，包括成员函数。我们通过深入研究成员函数的内部，包括理解`this`指针是什么，以及它的工作原理 - 包括隐式接收`this`指针的成员函数的底层实现。

我们已经探讨了访问标签和访问区域。通过将数据成员分组在`private`访问区域，并提供一套`public`成员函数来操作这些数据成员，我们发现我们可以提供一种安全、受控和经过充分测试的手段来从每个类的范围内操作数据。我们已经看到，对类进行更改可以限制在成员函数本身。类的用户不需要知道数据成员的底层表示 - 这些细节是隐藏的，并且可以根据需要进行更改，而不会在应用程序的其他地方引起一系列更改。

我们已经深入探讨了构造函数的许多方面，通过检查默认、典型（重载）构造函数，复制构造函数，甚至转换构造函数。我们已经介绍了析构函数，并了解了它的正确用法。

我们通过对数据成员和成员函数使用各种限定符，如`inline`以提高效率，`const`以保护数据并确保函数也是如此，`static`数据成员以模拟类属性的 OO 概念，以及`static`方法来提供对这些`static`数据成员的安全接口，为我们的类增添了额外的特色。

通过沉浸在面向对象编程中，我们获得了与 C++中类相关的一套全面的技能。拥有一套全面的技能和使用类的经验，以及对面向对象编程的欣赏，我们现在可以继续前进，学习如何通过*第六章*，*使用单继承实现层次结构*，来构建一系列相关类的层次结构。让我们继续前进！

# 问题

1.  创建一个 C++程序来封装一个`Student`。您可以使用之前练习的部分。尝试自己做这个，而不是依赖任何在线代码。您将需要这个类作为未来示例的基础；现在是一个很好的时机来尝试每个功能。具体来说：

a. 创建或修改你之前的`Student`类，完全封装一个学生。确保包含几个动态分配的数据成员。提供多个重载的构造函数来初始化你的类。确保包含一个拷贝构造函数。还要包含一个析构函数来释放任何动态分配的数据成员。

b. 为你的类添加一系列访问函数，以提供对类内数据成员的安全访问。决定为哪些数据成员提供`GetDataMember()`接口，以及这些数据成员中是否有任何可以在构造后重置的能力，使用`SetDataMember()`接口。根据需要对这些方法应用`const`和`inline`限定符。

c. 确保使用适当的访问区域 - 对于数据成员使用`private`，可能对一些辅助成员函数使用`private`来分解一个较大的任务。根据需要添加`public`成员函数，超出上面的访问函数。

d. 在你的类中至少包含一个`const`数据成员，并利用成员初始化列表来设置这个成员。添加至少一个`static`数据成员和一个`static`成员函数。

e. 使用每个构造函数签名实例化一个`Student`，包括拷贝构造函数。使用`new()`动态分配多个实例。确保在使用完毕后`delete()`每个实例（这样它们的析构函数将被调用）。


# 第六章：使用单继承实现层次结构

本章将扩展我们在 C++中面向对象编程的追求。我们将首先介绍额外的面向对象概念，如**泛化**和**特化**，然后理解这些概念如何通过*直接语言支持*在 C++中实现。我们将开始构建相关类的层次结构，并理解每个类如何成为我们应用程序中更易于维护、可重复使用的构建模块。我们将理解本章介绍的新的面向对象概念将支持精心规划的设计，并清楚地了解如何在 C++中使用健壮的代码来实现这些设计。

在本章中，我们将涵盖以下主要主题：

+   面向对象的泛化和特化概念，以及 Is-A 关系

+   单继承基础-定义派生类，访问继承成员，理解继承访问标签和区域

+   单继承层次结构中的构造和销毁顺序；使用成员初始化列表选择基类构造函数

+   修改基类列表中的访问标签-公共与私有和受保护的基类-以改变继承的 OO 目的为实现继承

通过本章结束时，您将了解泛化和特化的面向对象概念，并将知道如何在 C++中使用继承作为实现这些理想的机制。您将了解基类和派生类等术语，以及构建层次结构的面向对象动机，例如支持 Is-A 关系或支持实现继承。

具体来说，您将了解如何使用单继承来扩展继承层次结构，以及如何访问继承的数据成员和成员函数。您还将了解根据其定义的访问区域，您可以直接访问哪些继承成员。

您将了解当实例化和销毁派生类类型的实例时，构造函数和析构函数的调用顺序。您将知道如何利用成员初始化列表来选择派生类对象可能需要利用作为其自身构造的一部分的潜在组中的继承构造函数。

您还将了解如何更改基类列表中的访问标签会改变您正在扩展的继承层次结构的 OO 含义。通过检查公共与私有和受保护的基类，您将了解不同类型的层次结构，例如那些用于支持 Is-A 关系的层次结构，与那些用于支持实现继承的层次结构。

通过理解 C++中单继承的直接语言支持，您将能够实现泛化和特化的面向对象概念。您的层次结构中的每个类将成为更易于维护的组件，并且可以作为创建新的、更专业化组件的潜在构建模块。让我们通过详细介绍单继承来进一步了解 C++作为面向对象编程语言。

# 技术要求

完整程序示例的在线代码可在以下 GitHub URL 找到：[`github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter06`](https://github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter06)。每个完整程序示例都可以在 GitHub 存储库中的适当章节标题（子目录）下找到，文件名与所在章节编号相对应，后跟破折号，再跟上该章节中的示例编号。例如，本章的第一个完整程序可以在名为`Chp6-Ex1.cpp`的文件中的子目录`Chapter06`中找到。

本章的 CiA 视频可在以下链接观看：[`bit.ly/3tJJJBK`](https://bit.ly/3tJJJBK)。

# 扩展面向对象的概念和术语

在本节中，我们将介绍基本的面向对象概念，以及将伴随这些关键思想的适用术语。

从*第五章* *详细探讨类*，你现在了解了封装和信息隐藏的关键面向对象思想，以及 C++如何通过 C++类支持这些理念。现在，我们将看看如何通过使用一个非常通用的类作为基础模块来构建一系列相关类的层次结构，然后通过创建更具体的类来扩展该类。通过以这种重复的方式构建一系列相关类的层次结构，面向对象系统提供了潜在的重复使用的基础模块。层次结构中的每个类都是封装的，因此可以更轻松地对特定类进行维护和升级，而不会影响整个系统。通过逐步将每个类与更具体和更详细的类相结合，构建一系列相关类的层次结构，可以在一个专注的维护和更改领域内进行每个组件的具体维护。

让我们从扩展我们的基本面向对象术语开始。

## 理解泛化和特化

本章延伸的主要面向对象概念是*泛化*和*特化*。将这些原则纳入设计中将为编写更易于修改和可维护的代码提供基础，并且可能在相关应用中重复使用代码。

**泛化**描述了从一组类中抽象出共同点并创建一个更通用的类来容纳这些共同的属性和行为的过程。更通用的类可以被称为**基类**（或**父类**）。泛化也可以用于将单个类的更一般的属性和行为收集到一个基类中，期望新的通用类以后可以作为附加的、更具体（派生）的类的基础或基础。

**特化**描述了从现有的通用基类派生出一个新类的过程，目的是添加特定的、可区分的属性和行为，以充分代表新类。特化类也可以称为**派生**（或**子类**）类。通过特化，类的层次结构可以逐步完善其各自的属性和行为。

尽管重复使用很难实现，但面向对象的概念，如泛化和特化，使得重复使用更容易实现。重复使用可以在性质相似的应用程序中实现，或者在同一项目领域中，或者在现有项目的延续中，或者在相关领域中实现，至少可以最大程度地重复使用最通用的类和相关组件。

构建层次结构是 C++的基本语言特性。让我们通过探索单继承来将这个想法付诸实践。

# 理解单继承的基本知识

**继承**是 C++语言机制，允许实现泛化和特化的概念。**单继承**是指给定类只有一个直接的基类。C++支持单继承和多继承，但在本章中我们将专注于单继承，并将在后面的章节中介绍多继承。

在 C++中可以使用类和结构来构建继承层次结构。然而，通常使用类而不是结构来支持继承和面向对象编程。

为了支持泛化和特化的目的而扩展继承层次结构，我们可以说*一个学生是一个人*。也就是说，`Student`是`Person`的特化，添加了基类`Person`提供的额外数据成员和成员函数。通过泛化和特化指定 Is-A 关系是使用继承创建基类和派生类的最典型原因。在本章的后面，我们将看到另一个使用继承的原因。

让我们开始看一下 C++中指定基类和派生类以及定义继承层次结构的语言机制。

## 定义基类和派生类，并访问继承的成员

在单一继承中，派生类指定了它的直接祖先或基类是谁。基类不指定它有任何派生类。

派生类只需通过在其类名后添加`:`，然后是关键字`public`（暂时），然后是特定的基类名，来创建一个基类列表。每当你在基类列表中看到一个`public`关键字，这意味着我们正在使用继承来指定 Is-A 关系。

这里有一个简单的例子来说明基本语法：

+   `Student`是`Person`的派生类：

```cpp
class Person  // base class
{
private:
    char *name;
    char *title;
public:
    // constructors, destructor, 
    // public access functions, public interface etc …
    const char *GetTitle() const { return title; }
};
class StudentPerson, and the derived class is Student. The derived class need only define additional data members and member functions that augment those specified in the base class. Instances of a derived class may generally access `public` members specified by the derived class or by any ancestor of the derived class. Inherited members are accessed in the same fashion as those specified by the derived class. Recall, `.` dot notation is used to access members of objects, and `->` arrow notation is used to access members of pointers to objects. Of course, to make this example complete, we will need to add the applicable constructors, which we currently assume exist. Naturally, there will be nuances with constructors relating to inheritance, which we will soon cover in this chapter. 
```

+   可以使用上述类来简单访问继承的成员，如下所示：

```cpp
int main()
{   
    // Let's assume the applicable constructors exist
    Person p1("Cyrus Bond", "Mr.");
    Student *s1 = new Student("Anne Lin", "Ms.", 4.0);
    cout << p1.GetTitle() << " " << s1->GetTitle();
    cout << s1->GetGpa() << endl;
    return 0;
}
```

在前面的代码片段中，由`s1`指向的派生类实例`Student`可以访问基类和派生类成员，比如`Person::GetTitle()`和`Student::GetGpa()`。基类实例`Person`，`p1`，只能访问自己的成员，比如`Person::GetTitle()`。

查看上面示例的内存模型，我们有：

![图 6.1 - 当前示例的内存模型](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/dmst-oop-cpp/img/Figure_6.1_B15702.jpg)

图 6.1 - 当前示例的内存模型

在前面的内存模型中，`Student`实例由`Person`子对象组成。也就是说，在指示`*s1`的内存地址上，一个`Student`，我们首先看到它的`Person`数据成员的内存布局。然后，我们看到它额外的`Student`数据成员的内存布局。当然，`p1`，它是一个`Person`，只包含`Person`数据成员。

基类和派生类成员的访问将受到每个类指定的访问区域的限制。让我们看看继承的访问区域是如何工作的。

## 检查继承的访问区域

访问区域，包括继承的访问区域，定义了从哪个范围直接访问成员，包括继承的成员。

派生类继承了其基类中指定的所有成员。然而，对这些成员的直接访问受到基类指定的访问区域的限制。

从*基类*继承的成员（包括数据和函数）按照基类强加的访问区域对*派生类*是可访问的。继承的访问区域及其与派生类访问的关系如下：

+   在基类中定义的**private**成员在基类的范围之外是不可访问的。类的范围包括该类的成员函数。

+   在基类中定义的**protected**成员在基类的范围内和派生类或其后代的范围内是可访问的。这意味着这些类的成员函数。

+   在基类中定义的**public**成员可以从任何范围访问，包括派生类的范围。

在前面的简单示例中，我们注意到`Person`和`Student`实例都从`main()`的范围内访问了`public`成员函数`Person::GetTitle()`。此外，我们注意到`Student`实例从`main()`访问了它的`public`成员`Student::GetGpa()`。通常，在给定类的范围之外，只有公共接口中的成员是可访问的，就像在这个例子中一样。

本章我们将很快看到一个更大的完整程序示例，展示`protected`访问区域。但首先，让我们回顾一下继承的构造函数和析构函数，以便我们的完整程序示例可以提供更大的整体效用。

# 理解继承的构造函数和析构函数

通过单一继承，我们可以构建一组相关的类。我们已经看到，当我们实例化派生类对象时，其基类数据成员的内存将被额外需要的派生类数据成员的内存所跟随。每个子对象都需要被构造。幸运的是，每个类都将为此目的定义一套构造函数。然后我们需要理解语言如何被利用来允许我们在实例化和构造派生类对象时指定适当的基类构造函数。

同样，当不再需要派生类类型的对象并且将被销毁时，重要的是要注意，将为组成派生类实例的每个子对象隐式调用析构函数。

让我们来看一下单一继承层次结构中的构造函数和析构函数顺序，以及当一个基类子对象在派生类实例中找到多个构造函数可用时，我们如何做出选择。

## 隐式构造函数和析构函数调用

构造函数和析构函数是两种不被派生类显式继承的成员函数。这意味着基类构造函数的签名不能用来实例化派生类对象。然而，我们将看到，当实例化派生类对象时，整体对象的基类和派生类部分的内存将分别使用各自的构造函数进行初始化。

当实例化派生类类型的对象时，不仅将调用其构造函数，还将调用其每个前面基类的构造函数。最一般的基类构造函数将首先被执行，然后一直沿着层次结构调用构造函数，直到达到与手头实例相同类型的派生类构造函数。

同样，当派生类实例超出范围（或对实例的指针进行显式释放）时，所有相关的析构函数将被调用，但顺序与构造相反。首先，派生类析构函数将被执行，然后将依次调用和执行每个前面基类的析构函数，直到达到最一般的基类。

现在你可能会问，当我实例化一个派生类时，我如何从一组潜在的基类构造函数中选择适合我的基类子对象？让我们更详细地看一下成员初始化列表，找到解决方案。

## 使用成员初始化列表来选择基类构造函数

成员初始化列表可以用来指定在实例化派生类对象时应调用哪个基类构造函数。每个派生类构造函数可以指定使用不同的基类构造函数来初始化派生类对象的给定基类部分。

如果派生类构造函数的成员初始化列表没有指定应使用哪个基类构造函数，则将调用默认的基类构造函数。

成员初始化列表在派生类构造函数的参数列表后使用`:`来指定。为了指定应该使用哪个基类构造函数，可以指定基类构造函数的名称，后跟括号，包括要传递给该基类构造函数的任何值。根据在基类名称后的基类列表中参数的签名，将选择适当的基类构造函数来初始化派生类对象的基类部分。

这是一个简单的示例，用来说明基类构造函数选择的基本语法：

+   让我们从基本的类定义开始（请注意，许多成员函数被省略）：

```cpp
class Person
{
private:
    char *name;
    char *title;
public:
    Person();  // various constructors
    Person(const char *, const char *); 
    Person(const Person &);
    ~Person();  // destructor
// Assume the public interface, access functions exist
};
class Student: public Person
{
private:
    float gpa;
public:
    Student();
    Student(const char *, const char *, float);
    ~Student();
// Assume the public interface, access functions exist
};
```

+   之前的类定义的构造函数如下（请注意，两个派生类构造函数使用了成员初始化列表）：

```cpp
// Base class constructors
Person::Person()
{
    name = title = 0;  // null pointer
}
Person::Person(const char *n, const char *t)
{    // implementation as expected
}
Person::Person(const Person &p)
{   // implementation as expected
}
// Derived class constructors
Student::Student()   // default constructor
{
    gpa = 0.0;
}
Student::Student(const char *n, const char *t, 
                 float g)Student::Student(), does not utilize the member initialization list to specify which Person constructor should be used. Because none has been selected, the default Person constructor (with no arguments) is called. Next, notice in the alternate derived class constructor, `Student::Student(const char *, const char *, float)`, the use of the member initialization list. Here, the `Person` constructor matching the signature of `Person::Person(const char *, const char *)` is selected to initialize the `Person` sub-object at hand. Also, notice that parameters from the `Student` constructor, `n` and `t`, are passed up to the aforementioned `Person` constructor to help complete the `Person` sub-object initialization.Now, notice in the copy constructor for the derived class, `Student::Student(const Student &)`, the member initialization list is used to select the `Person` copy constructor, passing `s` as a parameter to the `Person` copy constructor. Here, the object referenced by `s` is a `Student`, however, the top part of `Student` memory contains `Person` data members. Hence, it is acceptable to up-cast the `Student` to a `Person` to allow the `Person` copy constructor to initialize the `Person` sub-object. In the body of the `Student` copy constructor, the additional data members added by the `Student` class definition are initialized in the body of this function. Namely, by setting `gpa = s.gpa;`.
```

现在我们知道如何利用成员初始化列表来指定基类构造函数，让我们继续进行一个完整的程序示例。

## 将所有部分组合在一起

到目前为止，在本章中，我们已经看到了许多部分构成了一个完整的程序示例。重要的是要看到我们的代码在运行中，以及它的各个组件。我们需要看到继承的基本机制，成员初始化列表是如何用来指定应该隐式调用哪个基类构造函数的，以及`protected`访问区域的重要性。

让我们来看一个更复杂的完整程序示例，以充分说明单一继承。这个示例将被分成几个部分；完整的程序可以在以下 GitHub 位置找到：

[`github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter06/Chp6-Ex1.cpp`](https://github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter06/Chp6-Ex1.cpp)

```cpp
#include <iostream>
#include <iomanip>
#include <cstring>
using namespace std;
class Person
{
private: 
   // data members
   char *firstName;
   char *lastName;
   char middleInitial;
   char *title;  // Mr., Ms., Mrs., Miss, Dr., etc.
protected: // make available to derived classes in their scope
   void ModifyTitle(const char *); 
public:
   Person();   // default constructor
   Person(const char *, const char *, char, const char *);  
   Person(const Person &);  // copy constructor
   ~Person();  // destructor
   // inline function definitions
   const char *GetFirstName() const { return firstName; }  
   const char *GetLastName() const { return lastName; }    
   const char *GetTitle() const { return title; } 
   char GetMiddleInitial() const { return middleInitial; }
};
```

在之前的类定义中，我们现在有了一个完整的`Person`类定义，比我们在本节中以前使用的简单语法示例要详细得多。请注意，我们引入了一个`protected`访问区域，并将成员函数`void ModifyTitle(const char *);`放在这个访问区域中。

继续前进，让我们来看一下`Person`的非内联成员函数定义：

```cpp
Person::Person()
{
   firstName = lastName = 0;  // NULL pointer
   middleInitial = '\0';
   title = 0;
}
Person::Person(const char *fn, const char *ln, char mi, 
               const char *t)
{
   firstName = new char [strlen(fn) + 1];
   strcpy(firstName, fn);
   lastName = new char [strlen(ln) + 1];
   strcpy(lastName, ln);
   middleInitial = mi;
   title = new char [strlen(t) + 1];
   strcpy(title, t);
}
Person::Person(const Person &pers)
{
   firstName = new char [strlen(pers.firstName) + 1];
   strcpy(firstName, pers.firstName);
   lastName = new char [strlen(pers.lastName) + 1];
   strcpy(lastName, pers.lastName);
   middleInitial = pers.middleInitial;
   title = new char [strlen(pers.title) + 1];
   strcpy(title, pers.title);
}
Person::~Person()
{
   delete firstName;
   delete lastName;
   delete title;
}
void Person::ModifyTitle(const char *newTitle)
{
   delete title;  // delete old title
   title = new char [strlen(newTitle) + 1];
   strcpy(title, newTitle);
}
```

上述`Person`成员函数的实现如预期的那样。现在，让我们添加派生类`Student`的类定义，以及它的内联函数定义：

```cpp
class Student: public Person
{
private: 
   // data members
   float gpa;
   char *currentCourse;
   const char *studentId;  
public:
   // member function prototypes
   Student();  // default constructor
   Student(const char *, const char *, char, const char *,
           float, const char *, const char *); 
   Student(const Student &);  // copy constructor
   ~Student();  // destructor
   void Print() const;
   void EarnPhD();  // public interface to inherited 
                    // protected member
   // inline function definitions
   float GetGpa() const { return gpa; }
   const char *GetCurrentCourse() const 
       { return currentCourse; }
   const char *GetStudentId() const { return studentId; }
   // prototype only, see inline function definition below
   void SetCurrentCourse(const char *);
};
inline void Student::SetCurrentCourse(const char *c)
{
   delete currentCourse;   // delete existing course
   currentCourse = new char [strlen(c) + 1];
   strcpy(currentCourse, c); 
}
```

在之前的`Student`定义中，`class Student`是通过`public`继承（即公共基类）从`Person`派生的，支持 Is-A 关系。请注意，在派生类定义中的基类列表后面的`:`之后有一个`public`访问标签（即`class Student: public Person`）。请注意，我们的`Student`类添加了数据成员和成员函数，超出了它从`Person`自动继承的那些。

接下来，添加非内联的`Student`成员函数，我们继续完善我们的代码：

```cpp
Student::Student() : studentId (0)   // default constructor
{
   gpa = 0.0;
   currentCourse = 0;
}
// alternate constructor
Student::Student(const char *fn, const char *ln, char mi, 
                 const char *t, float avg, const char *course,
                 const char *id): Person(fn, ln, mi, t)
{
   gpa = avg;
   currentCourse = new char [strlen(course) + 1];
   strcpy(currentCourse, course);
   char *temp = new char [strlen(id) + 1];
   strcpy (temp, id); 
   studentId = temp;
}
// copy constructor
Student::Student(const Student &ps): Person(ps)
{
   gpa = ps.gpa;
   currentCourse = new char [strlen(ps.currentCourse) + 1];
   strcpy(currentCourse, ps.currentCourse);
   char *temp = new char [strlen(ps.studentId) + 1];
   strcpy (temp, ps.studentId); 
   studentId = temp;
}

// destructor definition
Student::~Student()
{
   delete currentCourse;
   delete (char *) studentId;
}
void Student::Print() const
{
   // Private members of Person are not directly accessible
   // within the scope of Student, so we use access functions 
   cout << GetTitle() << " " << GetFirstName() << " ";
   cout << GetMiddleInitial() << ". " << GetLastName();
   cout << " with id: " << studentId << " gpa: ";
   cout << setprecision(2) << gpa;
   cout << " course: " << currentCourse << endl;
}
void Student::EarnPhD()
{
   // Protected members defined by the base class are
   // accessible within the scope of the derived class.
   // EarnPhd() provides a public interface to this
   // functionality for derived class instances. 
   ModifyTitle("Dr.");  
}
```

在上述代码段中，我们定义了`Student`的非内联成员函数。请注意，默认构造函数仅使用成员初始化列表来初始化数据成员，就像我们在上一章中所做的那样。由于在默认`Student`构造函数的成员初始化列表中没有指定`Person`构造函数，所以在实例化具有默认构造函数的`Student`时，将使用默认的`Person`构造函数来初始化`Person`子对象。

接下来，`Student`的替代构造函数使用成员初始化列表来指定应该使用`Person`的替代构造函数来构造给定`Student`实例中包含的`Person`子对象。请注意，所选的构造函数将匹配签名`Person::Person(char *, char *, char, char *)`，并且将从`Student`构造函数中选择的输入参数（即`fn`，`ln`，`mi`和`t`）作为参数传递给`Person`的替代构造函数。

在`Student`的复制构造函数中，使用成员初始化列表指定应调用`Person`的复制构造函数来初始化正在构造的`Student`实例中包含的`Person`子对象。`Student &`将被隐式向上转型为`Person &`，因为调用了`Person`的复制构造函数。请记住，`Student`对象的顶部部分*Is-A*`Person`，所以这是可以的。接下来，在`Student`的复制构造函数的主体中，我们初始化了`Student`类定义的任何剩余数据成员。

继续向前，我们看到了`Student`的析构函数。隐式地，作为这个方法中的*最后*一行代码，编译器为我们补充了对`Person`析构函数的调用。这就是析构函数序列是如何自动化的。因此，对象的最专业化部分，即`Student`部分，将首先被销毁，然后隐式调用`Person`析构函数来销毁基类子对象。

接下来，在`Student`的`Print()`方法中，请注意我们想要打印出从`Person`继承的各种数据成员。遗憾的是，这些数据成员是`private`的。我们不能在`Person`类的范围之外访问它们。然而，`Person`类留下了一个公共接口，比如`Person::GetTitle()`和`Person::GetFirstName()`，这样我们就可以从我们应用程序的任何范围访问这些数据成员，包括从`Student::Print()`中。

最后，我们来到`Student::EarnPhD()`方法。请注意，这个方法所做的就是调用`protected`成员函数`Person::ModifyTitle("Dr.");`。请记住，基类定义的`protected`成员在派生类的范围内是可访问的。`Student::EarnPhD()`是派生类的成员函数。`EarnPhD()`提供了一个公共接口来修改`Person`的头衔，也许在检查学生是否达到毕业要求之后。因为`Person::ModifyTitle()`不是`public`，`Person`或`Student`的实例必须通过受控的`public`接口来更改它们各自的头衔。这样的接口可能包括诸如`Student::EarnPhD()`或`Person::GetMarried()`等方法。

尽管如此，让我们通过检查`main()`来完成我们的完整程序示例：

```cpp
int main()
{
    Student s1("Jo", "Li", 'U', "Ms.", 3.8, "C++", "178PSU"); 
    // Public members of Person and Student are accessible
    // outside the scope of their respective classes....
    s1.Print();
    s1.SetCurrentCourse("Doctoral Thesis");
    s1.EarnPhD();
    s1.Print();
    return 0;
}
```

在程序的最后一部分，在`main()`中，我们只是实例化了一个`Student`，即`s1`。`Student`利用`Student::Print()`来打印其当前数据。然后，`Student`将她当前的课程设置为“博士论文”，然后调用`Student::EarnPhD();`。请注意，`Student`或`Person`的任何`public`成员都可以在类的范围之外被`s1`使用，比如在`main()`中。为了完成示例，`s1`使用`Student::Print()`重新打印她的详细信息。

以下是完整程序示例的输出：

```cpp
Ms. Jo U. Li with id: 178PSU gpa: 3.9 course: C++
Dr. Jo U. Li with id: 178PSU gpa: 3.9 course: Doctoral Thesis
```

现在我们已经掌握了单继承的基本机制，并且已经使用单继承来模拟 Is-A 关系，让我们继续看看继承如何用于模拟不同的概念，通过探索受保护和私有基类。

# 实现继承-改变继承的目的

到目前为止，我们已经演示了使用公共基类，也称为*公共继承*。公共基类用于建模 Is-A 关系，并为构建继承层次结构提供了主要动机。这种用法支持泛化和特化的概念。

偶尔，继承可能被用作一种工具，以另一个类的术语来实现一个类，也就是说，一个类使用另一个类作为其基础实现。这被称为**实现继承**，它不支持概括和特化的理想。然而，实现继承可以提供一种快速和易于重用的实现一个类的方式。它快速且相对无误。许多类库在不知晓其类用户的情况下使用这个工具。重要的是要区分实现继承和传统层次结构构建的动机，以指定 Is-A 关系。

在 C++中支持使用私有和受保护的基类来实现实现继承，这是 C++独有的。其他面向对象的语言选择只支持用于建模 Is-A 关系的继承，而 C++通过公共基类支持这一点。面向对象的纯粹主义者会努力只使用继承来支持概括和特化（*Is-A*）。然而，使用 C++，我们将理解实现继承的适当用法，以便明智地使用这种语言特性。

让我们继续了解我们可能如何以及为什么使用这种类型的继承。

## 通过使用受保护或私有基类修改基类列表中的访问标签

重申一下，通常的继承类型是`public`继承。在给定派生类的基类列表中使用`public`标签。然而，在基类列表中，关键字`protected`和`private`也是可选项。

也就是说，除了在类或结构定义中标记访问区域之外，访问标签还可以在派生类定义的基类列表中使用，以指定基类中定义的成员如何被派生类继承。

继承成员只能比在基类中指定的更加严格。当派生类指定继承成员应以更加严格的方式对待时，该派生类的任何后代也将受到这些规定的约束。

让我们看一个*基类列表*的快速示例：

+   请记住，基类列表中通常会指定`public`访问标签。

+   在这个例子中，使用`public`访问标签来指定`Person`是`Student`的`public`基类。也就是说，`Student` *Is-A* `Person`：

```cpp
class Student: public Person
{
    // usual class definition
};
```

在*基类列表*中指定的访问标签会修改继承的访问区域，如下所示：

+   **public**：基类中的公共成员可以从任何范围访问；基类中的受保护成员可以从基类和派生类的范围访问。我们熟悉使用公共基类。

+   **protected**：基类中的公共和受保护成员在派生类中的作用就像它们被派生类定义为受保护的一样（即可以从基类和派生类的范围以及派生类的任何后代中访问）。

+   **private**：基类中的公共和受保护成员在派生类中的作用就像它们被定义为私有的一样，允许这些成员在派生类的范围内访问，但不允许在任何派生类的后代范围内访问。

注意

在所有情况下，在类定义中标记为私有的类成员只能在定义类的范围内访问。修改基类列表中的访问标签只能更加严格地处理继承成员，而不能更加宽松地处理。

在与基类一起指定的访问标签缺失时，如果用户定义的类型是`class`，则假定为`private`，如果用户定义的类型是`struct`，则默认为`public`。一个好的经验法则是在派生类（或结构）定义的基类列表中始终包括访问标签。

## 创建一个基类来说明实现继承

为了理解实现继承，让我们回顾一个可能作为实现其他类基础的基类。我们将检查一对典型的类，以实现封装的`LinkList`。尽管这个例子将被分成几个部分，但完整的例子将被展示，并且也可以在 GitHub 上找到：

[`github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter06/Chp6-Ex2.cpp`](https://github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter06/Chp6-Ex2.cpp)

```cpp
#include <iostream>
using namespace std;
typedef int Item;  
class LinkListElement  // one 'node' or element in a LinkList
{
private:
    void *data;
    LinkListElement *next;
public:
    LinkListElement() { data = 0; next = 0; }
    LinkListElement(Item *i) { data = i; next = 0; }
    ~LinkListElement() { delete (Item *) data; next = 0; }
    void *GetData() { return data; }
    LinkListElement *GetNext() { return next; }
    void SetNext(LinkListElement *e) { next = e; }
};
class LinkList   // an encapsulated LinkList
{
private:
    LinkListElement *head;
    LinkListElement *tail;
    LinkListElement *current;
public:
    LinkList();
    LinkList(LinkListElement *);
   ~LinkList();
    void InsertAtFront(Item *);
    LinkListElement *RemoveAtFront();
    void DeleteAtFront();
    int IsEmpty() { return head == 0; } 
    void Print();  
};
```

我们从上一段代码开始，定义了`LinkListElement`和`LinkList`的类定义。`LinkList`类将包含指向`LinkList`中`head`，`tail`和`current`元素的指针的数据成员。这些指针都是`LinkListElement`类型。包括各种典型的`LinkList`处理方法，如`InsertAtFront()`，`RemoveAtFront()`，`DeleteAtFront()`，`IsEmpty()`和`Print()`。让我们快速查看这些方法的实现，下一段代码中会有。

```cpp
LinkList::LinkList()
{
    head = tail = current = 0;
}
LinkList::LinkList(LinkListElement *element)
{
    head = tail = current = element;
}
void LinkList::InsertAtFront(Item *theItem)
{
    LinkListElement *temp = new LinkListElement(theItem);
    temp->SetNext(head);  // temp->next = head;
    head = temp;
}
LinkListElement *LinkList::RemoveAtFront()
{
    LinkListElement *remove = head;
    head = head->GetNext();  // head = head->next;
    current = head;    // reset current for usage elsewhere
    return remove;
}

void LinkList::DeleteAtFront()
{
    LinkListElement *deallocate;
    deallocate = RemoveAtFront();
    delete deallocate;  // destructor will both delete data 
}                       // and will set next to NULL

void LinkList::Print()
{
    Item output;
    if (!head)
       cout << "<EMPTY>";
    current = head;
    while (current)
    {
        output = *((Item *) current->GetData());
        cout << output << " ";
        current = current->GetNext();
    }
    cout << endl;
}
LinkList::~LinkList()
{
    while (!IsEmpty())
        DeleteAtFront();
}
```

在前面提到的成员函数定义中，我们注意到`LinkList`可以为空或带有一个元素构造（注意两个可用的构造函数）。`LinkList::InsertAtFront()`在列表的前面添加一个项目以提高效率。`LinkList::RemoveAtFront()`删除一个项目并将其返回给用户，而`LinkList::DeleteAtFront()`删除前面的项目。`LinkList::Print()`函数允许我们在必要时查看`LinkList`。

接下来，让我们看一个典型的`main()`函数，以说明如何实例化和操作`LinkList`。

```cpp
int main()
{
    // Create a few items, to be data for LinkListElements
    Item *item1 = new Item;
    *item1 = 100;
    Item *item2 = new Item(200);
    // create an element for the Linked List
    LinkListElement *element1 = new LinkListElement(item1);
    // create a linked list and initialize with one element
    LinkList list1(element1);
    // Add some new items to the list and print
    list1.InsertAtFront(item2);   
    list1.InsertAtFront(new Item(50)); // add a nameless item
    cout << "List 1: ";
    list1.Print();         // print out contents of list
    // delete elements from list, one by one
    while (!(list1.IsEmpty()))
    {
        list1.DeleteAtFront();
        cout << "List 1 after removing an item: ";
        list1.Print();
    }
    // create a second linked list, add some items and print
    LinkList list2;
    list2.InsertAtFront(new Item (3000));
    list2.InsertAtFront(new Item (600));
    list2.InsertAtFront(new Item (475));
    cout << "List 2: ";
    list2.Print();
    // delete elements from list, one by one
    while (!(list2.IsEmpty()))
    {
        list2.DeleteAtFront();
        cout << "List 2 after removing an item: ";
        list2.Print();
    }
    return 0;
}
```

在`main()`中，我们创建了几个项目，类型为`Item`，这些项目稍后将成为`LinkListElement`的数据。然后，我们实例化了一个`LinkListElement`，即`element1`，并将其添加到新构造的`LinkList`中，使用`LinkList list1(element1);`。然后，我们使用`LinkList::InsertAtFront()`向列表中添加了几个项目，并调用`LinkList::Print()`来打印出`list1`作为基线。接下来，我们逐个从`list1`中删除元素，打印删除的元素，使用`LinkList::DeleteAtFront()`和`LinkList::Print()`。

现在，我们实例化了第二个`LinkList`，即`list2`，它开始为空。我们逐渐使用`LinkList::InsertAtFront()`插入几个项目，然后打印列表，然后使用`LinkList::DeleteAtFront()`逐个删除每个元素，打印每个步骤后的修订列表。

这个例子的重点不是详尽地审查这段代码的内部工作原理。毫无疑问，您对`LinkList`的概念非常熟悉。更重要的是，要将`LinkListElement`和`LinkList`这组类作为一组构建块，可以构建多个抽象数据类型。

尽管如此，上述示例的输出是：

```cpp
List 1: 50 200 100
List 1 after removing an item: 200 100
List 1 after removing an item: 100
List 1 after removing an item: <EMPTY>
List 2: 475 600 3000
List 2 after removing an item: 600 3000
List 2 after removing an item: 3000
List 2 after removing an item: <EMPTY>
```

接下来，让我们看看`LinkList`如何作为私有基类使用。

## 使用私有基类来实现一个类以另一个类为基础

我们刚刚创建了一个`LinkList`类，以支持封装的链表数据结构的基本处理。现在，让我们想象一下，我们想要实现`Push()`，`Pop()`，`IsEmpty()`，也许还有`Print()`。

你可能会问栈是如何实现的。答案是实现并不重要，只要它支持被建模的 ADT 的预期接口。也许栈是使用数组实现的，或者它是在文件中实现的。也许它是使用`LinkedList`实现的。每种实现都有优缺点。事实上，ADT 的底层实现可能会改变，但 ADT 的用户不应受到这种变化的影响。这就是*实现继承*的基础。派生类是基类的实现，但派生类的底层细节是有效隐藏的。这些细节不能直接被派生类的实例（在这种情况下是 ADT）使用。尽管如此，基类默默地为派生类提供实现。

我们将使用这种方法来使用`LinkedList`作为其底层实现来实现一个`Stack`。为此，我们将让`class Stack`扩展`LinkedList`，使用一个`private`基类。`Stack`将为其用户定义一个公共接口，以建立这个 ADT 的接口，比如`Push()`、`Pop()`、`IsEmpty()`和`Print()`。这些成员函数的实现将使用选定的`LinkedList`成员函数，但`Stack`的用户将看不到这一点，`Stack`的实例也不能直接使用任何`LinkList`成员。

在这里，我们并不是说`Stack`*是一个*`LinkList`，而是说，一个`Stack`是目前以`LinkedList`为基础实现的——而这个底层实现可能会改变！

实现`Stack`的代码很简单。假设我们使用了前面例子中的`LinkList`和`LinkListElement`类。让我们在这里添加`Stack`类。完整的程序示例可以在我们的 GitHub 上找到：

[`github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter06/Chp6-Ex3.cpp`](https://github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter06/Chp6-Ex3.cpp)

```cpp
class Stack: private LinkList
{
private:
    // no new data members are necessary
public:
    Stack() : LinkList() { }
    ~Stack() { }
    // the public interface for Stack 
    void Push(Item *i) { InsertAtFront(i); }
    Item *Pop(); 
    // It is necessary to redefine these operation because
    // LinkList is a private base class of Stack
    int IsEmpty() { return LinkList::IsEmpty(); }  
    void Print() { LinkList::Print(); }
};
Item *Stack::Pop()
{
    LinkListElement *temp;
    temp = RemoveAtFront();
    // copy temp's data
    Item *item = new Item(*((Item *) temp->GetData()));  
    delete temp;
    return item;
}
int main()
{
    Stack stack1;     // create a Stack
    // Add some items to the stack, using public interface 
    stack1.Push(new Item (3000)); 
    stack1.Push(new Item (600));
    stack1.Push(new Item (475));
    cout << "Stack 1: ";
    stack1.Print();
    // Pop elements from stack, one by one
    while (!(stack1.IsEmpty()))
    {
        stack1.Pop();
        cout << "Stack 1 after popping an item: ";
        stack1.Print();
    }
    return 0;
} 
```

注意我们的`Stack`类的上述代码是多么紧凑！我们首先指定`Stack`有一个`private`的基类`LinkList`。回想一下，一个`private`的基类意味着从`LinkList`继承的`protected`和`public`成员就好像是由`Stack`定义为`private`一样（只能在`Stack`的范围内访问，也就是`Stack`的成员函数）。这意味着`Stack`的实例可能不能使用`LinkList`的*原来的*公共接口。这也意味着`Stack`作为`LinkList`的底层实现是有效隐藏的。当然，`LinkList`的实例不受任何影响，可以像往常一样使用它们的`public`接口。

我们很容易定义`Stack::Push()`来简单调用`LinkList::InsertAtFront()`，就像`Stack::Pop()`做的不仅仅是调用`LinkList::RemoveAtFront()`。尽管`Stack`很想简单地使用`LinkList::IsEmpty()`和`LinkList::Print()`的继承实现，但由于`LinkList`是一个`private`基类，这些函数不是`Stack`的公共接口的一部分。因此，`Stack`添加了一个`IsEmpty()`方法，它只是调用`LinkList::IsEmpty()`。注意使用作用域解析运算符来指定`LinkList::IsEmpty()`方法；没有基类限定，我们将添加一个递归函数调用！这个对基类方法的调用是允许的，因为`Stack`成员函数可以调用`LinkList`的*曾经的*方法（它们现在在`Stack`内部被视为`private`）。同样，`Stack::Print()`只是调用`LinkList::Print()`。

在`main()`的范围内，我们实例化了一个`Stack`，即`stack1`。使用`Stack`的公共接口，我们可以很容易地使用`Stack::Push()`、`Stack::Pop()`、`Stack::IsEmpty()`和`Stack::Print()`来操作`stack1`。

这个例子的输出是：

```cpp
Stack 1: 475 600 3000
Stack 1 after popping an item: 600 3000
Stack 1 after popping an item: 3000
Stack 1 after popping an item: <EMPTY>
```

重要的是要注意，`Stack`实例的指针不能向上转型为`LinkList`的指针进行存储。在`private`基类边界上不允许向上转型。这将允许`Stack`揭示其底层实现；C++不允许这种情况发生。在这里，我们只是说`Stack`仅仅是以`LinkList`的方式实现；我们并没有说`Stack` *Is-A* `LinkedList`。这是实现继承的最佳例子；这个例子有利地说明了实现继承。

接下来，让我们继续看看如何使用`protected`基类，以及这与使用实现继承的`private`基类有何不同。

## 使用 protected 基类来实现一个类以另一个类为基础

我们刚刚使用`private`基类以`LinkList`的方式实现了`Stack`。现在，让我们实现一个`Queue`和一个`PriorityQueue`。我们将使用`LinkList`作为`protected`基类来实现`Queue`，并使用`Queue`作为`public`基类来实现`PriorityQueue`。

再次强调，`Queue`和`PriorityQueue`都是 ADT。`Queue`的实现方式（相对）不重要。底层实现可能会改变。实现继承允许我们使用`LinkedList`来实现我们的`Queue`，而不会向`Queue`类的用户透露底层实现。

现在，我们的`Queue`类将使用`LinkedList`作为`protected`基类。`Queue`将为其用户定义一个公共接口，以建立该 ADT 的预期接口，如`Enqueue()`、`Dequeue()`、`IsEmpty()`和`Print()`。这些成员函数的实现将使用选定的`LinkedList`成员函数，但`Queue`用户将看不到这一点，`Queue`实例也无法直接使用任何`LinkList`成员。

此外，我们的`PriorityQueue`类将使用`public`继承来扩展`Queue`。没错，我们又回到了 Is-A。我们在说`PriorityQueue` *Is-A* `Queue`，而`Queue`是使用`LinkedList`实现的。

我们将在我们的`PriorityQueue`类中添加一个优先级入队方法；这个类将很乐意从`Queue`继承`public`接口（但显然不会从`LinkList`继承，幸运的是，它被隐藏在其父级的`protected`基类后面）。

实现`Queue`和`PriorityQueue`的代码再次很简单。需要扩展`LinkList`基类以使其更加完整功能才能继续。`LinkListElement`类可以保持不变。我们将展示经过修订的`LinkList`类的基本定义。`Queue`和`PriorityQueue`的完整代码将在单独的段落中显示。完整的程序示例可以在我们的 GitHub 上找到：

[`github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter06/Chp6-Ex4.cpp`](https://github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter06/Chp6-Ex4.cpp)

```cpp
// class LinkListElement is as shown previously
// The enhanced class definition of LinkList is:
class LinkList
{
private:
    LinkListElement *head;
    LinkListElement *tail;
    LinkListElement *current;
public:
    LinkList();
    LinkList(LinkListElement *);
    ~LinkList();
    void InsertAtFront(Item *);  
    LinkListElement *RemoveAtFront();
    void DeleteAtFront();
    // Notice additional member functions added
    void InsertBeforeItem(Item *, Item *); 
    LinkListElement *RemoveSpecificItem(Item *);
    void DeleteSpecificItem(Item *);
    void InsertAtEnd(Item *);
    LinkListElement *RemoveAtEnd();
    void DeleteAtEnd();
    int IsEmpty() { return head == 0; } 
    void Print();  
};
// Assume we have the implementation for the methods here…
```

请注意，`LinkList`已经扩展为具有更完整的功能集，例如能够在`LinkList`内的各个位置添加、删除和删除元素。为了节省示例空间，我们将不展示这些方法的实现。

现在，让我们在下一个代码段中添加`Queue`和`PriorityQueue`的类定义：

```cpp
class Queue: protected LinkList
{
private:
    // no new data members are necessary
public:
    Queue() : LinkList() { }
    virtual ~Queue() { }  // we'll discuss virtual in Chp. 7
    // public interface of Queue
    void Enqueue(Item *i) { InsertAtEnd(i); }
    Item *Dequeue(); 
    // redefine these methods --LinkList is a prot. base class
    int IsEmpty() { return LinkList::IsEmpty(); }
    void Print() { LinkList::Print(); }
};
Item *Queue::Dequeue()
{
    LinkListElement *temp;
    temp = RemoveAtFront();
    // make copy of temp's data
    Item *item = new Item(*((Item *) temp->GetData())); 
    delete temp; 
    return item;
}
class PriorityQueue: public Queue
{
private:
    // no new data members are necessary
public:
    PriorityQueue() : Queue() { }
    virtual ~PriorityQueue() { } // we'll see virtual in Chp 7
    void PriorityEnqueue(Item *i1, Item *i2) 
    {  InsertBeforeItem(i1, i2); } // accessible in this scope
};
```

在之前的代码段中，我们定义了`Queue`和`PriorityQueue`类。请注意，`Queue`具有`LinkList`的`protected`基类。使用`protected`基类时，从`LinkList`继承的`protected`和`public`成员就好像是由`Queue`定义为`protected`一样，这意味着这些继承的成员不仅可以在`Queue`的范围内访问，还可以在`Queue`的任何潜在后代内访问。与之前一样，这些限制仅适用于`Queue`类、它的后代和它们的实例；`LinkList`类及其实例不受影响。

在`Queue`类中，不需要新的数据成员。内部实现由`LinkList`处理。通过`protected`基类，我们表明`Queue`是使用`LinkList`实现的。尽管如此，我们必须为`Queue`提供`public`接口，我们通过添加诸如`Queue::Enqueue()`、`Queue::Dequeue()`、`Queue::IsEmpty()`和`Queue::Print()`等方法来实现。请注意，在它们的实现中，这些方法仅调用`LinkList`方法来执行必要的操作。`Queue`的用户必须使用`Queue`的公共接口；*曾经公共的*`LinkList`接口对于`Queue`实例是隐藏的。

接下来，我们定义了`PriorityQueue`，另一个 ADT。请注意，`PriorityQueue`将`Queue`定义为`public`基类。我们又回到了继承，以支持 Is-A 关系。`PriorityQueue` *Is-A* `Queue`，可以做任何`Queue`能做的事情，而且还多一点。因此，`PriorityQueue`通常从`Queue`继承，包括`Queue`的公共接口。`PriorityQueue`只需要添加一个额外的方法来进行优先级入队，即`PriorityQueue::PriorityEnqueue()`。

由于`Queue`有一个`LinkList`的受保护基类，因此`LinkList`的`public`接口被视为对`Queue`及其后代（包括`PriorityQueue`）是`protected`的，以便`LinkList`的*曾经公共*方法对于`Queue`和`PriorityQueue`都是`protected`的。请注意，`PriorityQueue::PriorityEnqueue()`使用了`LinkList::InsertBeforeItem()`。如果`LinkList`是`Queue`的`private`基类而不是`protected`，这是不可能的。

有了类定义和实现，让我们继续我们的`main()`函数：

```cpp
int main()
{
    Queue q1;   // Queue instance
    q1.Enqueue(new Item(50));
    q1.Enqueue(new Item(67));
    q1.Enqueue(new Item(80));
    q1.Print();
    while (!(q1.IsEmpty()))
    {
        q1.Dequeue();
        q1.Print();
    }
    PriorityQueue q2;   // PiorityQueue instance
    Item *item = new Item(167); // save a handle to item
    q2.Enqueue(new Item(67));   // first item added
    q2.Enqueue(item);           // second item
    q2.Enqueue(new Item(180));  // third item
    // add new item before an existing item
    q2.PriorityEnqueue(new Item(100), item); // fourth item
    q2.Print();
    while (!(q2.IsEmpty()))
    {
       q2.Dequeue();
       q2.Print();
    }
    return 0;
}
```

现在，在`main()`中，我们实例化了一个`Queue`，即`q1`，它使用了`Queue`的公共接口。请注意，`q1`可能不使用`LinkList`的*曾经公共*接口。`Queue`只能像`Queue`一样行为，而不是像`LinkList`一样行为。`Queue`的 ADT 被保留了。

最后，我们实例化了一个`PriorityQueue`，即`q2`，它使用了`Queue`和`PriorityQueue`的公共接口，比如`Queue::Enqueue()`和`PriorityQueue::PriorityEnqueue()`。因为`Queue` *Is-A* `PriorityQueue`（`Queue`是`public`基类），继承的典型机制已经就位，允许`PriorityQueue`利用其祖先的公共接口。

这个例子的输出是：

```cpp
50 67 80
67 80
80
<EMPTY>
67 100 167 180
100 167 180
167 180
180
<EMPTY>
```

最后，我们看到了使用实现继承的两个例子；这并不是 C++经常使用的特性。然而，现在你了解了`protected`或`private`基类，如果在库代码、你正在维护的应用程序代码中遇到它们，或者在你可能遇到的编程任务中，这种技术可能会有用。

我们现在已经介绍了 C++中单一继承的基本特性。在转到下一章之前，让我们快速回顾一下我们之前讨论过的内容。

# 总结

在本章中，我们已经进一步深入了解面向对象编程。我们添加了额外的 OO 概念和术语，并看到 C++对这些概念有直接的语言支持。我们已经看到 C++中的继承支持泛化和特化。我们已经看到如何逐步构建一组相关类的层次结构。

我们已经看到了如何使用单一继承来扩展继承层次结构，以及如何访问继承的数据成员和成员函数。我们已经回顾了访问区域，以了解基类中定义的成员可以直接访问的继承成员，基于这些成员在基类中定义的访问区域。我们知道拥有一个`public`基类等同于定义一个 Is-A 关系，支持泛化和特化的理想，这是继承最常用的原因。

我们已经详细说明了当派生类类型的实例被实例化和销毁时构造函数和析构函数的调用顺序。我们已经看到了成员初始化列表，以选择派生类对象可能选择利用作为其自身构造的一部分的继承构造函数。

我们已经看到，在基类列表中更改访问标签会改变所使用的继承类型的面向对象意义。通过比较`public`与`private`和`protected`基类，我们现在了解了不同类型的层次结构，例如那些用于支持 Is-A 关系的层次结构，与那些用于支持实现继承的层次结构。

我们已经看到了我们层次结构中的基类可能作为更专业组件的潜在构建块，从而导致潜在的重用。任何现有代码的潜在重用都可以节省开发时间，并减少重复代码的维护。

通过扩展我们的面向对象编程知识，我们获得了一组与 C++中的继承和层次结构构建相关的初步技能。通过掌握单一继承的基本机制，我们现在可以继续学习更多有趣的面向对象的概念和与继承相关的细节。继续到*第七章*，*通过多态性利用动态绑定*，我们将学习如何将方法动态绑定到相关类的层次结构中的操作。

# 问题

1.  使用你的*第五章*解决方案，创建一个 C++程序来构建一个继承层次结构，将`Person`泛化为`Student`的派生类。

a. 决定`Student`类的哪些数据成员和成员函数更通用，应该更好地放置在`Person`类中。使用这些成员构建你的`Person`类，包括适当的构造函数（默认，替代和复制），析构函数，访问成员函数和合适的公共接口。确保将数据成员放在私有访问区域。

b. 使用一个`public`基类，从`Person`派生`Student`。从`Student`中删除现在在`Person`中表示的成员。相应地调整构造函数和析构函数。使用成员初始化列表根据需要指定基类构造函数。

c. 实例化`Student`和`Person`多次，并利用每个适当的`public`接口。确保动态分配多个实例。

d. 在每个构造函数的第一行和析构函数的第一行使用`cout`添加一条消息，以便您可以看到每个实例的构造和销毁顺序。

1.  （可选）完成包括`LinkList`，`Queue`和`PriorityQueue`的类层次结构，使用在线代码作为基础。完成`LinkList`类中的其余操作，并根据需要在`Queue`和`PriorityQueue`的公共接口中调用它们。

a. 确保为每个类添加复制构造函数（或在私有访问区域原型它们，或使用`= delete`在原型中抑制复制）。

b. 使用任一构造函数实例化`LinkList`，然后演示每个操作的工作方式。确保在添加或删除元素后调用`Print()`。

c. 实例化`Queue`和`PriorityQueue`，并演示它们的`public`接口中的每个操作是否正常工作。记住要演示`Queue`的`public`接口中继承的操作，适用于`PriorityQueue`的实例。
