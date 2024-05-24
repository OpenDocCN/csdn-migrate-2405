# C++ 面向对象编程揭秘（一）

> 原文：[`zh.annas-archive.org/md5/BCB2906673DC89271C447ACAA17D3E00`](https://zh.annas-archive.org/md5/BCB2906673DC89271C447ACAA17D3E00)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

公司需要利用 C++的速度。然而，面向对象的软件设计会导致更容易修改和维护的代码。了解如何将 C++作为面向对象的语言使用是至关重要的。在 C++中编程并不能保证面向对象编程-必须理解面向对象的概念以及它们如何映射到 C++语言特性以及面向对象编程技术。此外，程序员还希望掌握超出面向对象编程的额外技能，以使代码更通用、更健壮，并采用经过充分测试的创造性解决方案，这些解决方案可以在流行的设计模式中找到。

学习如何将 C++作为面向对象语言使用的程序员将成为有价值的 C++开发人员。一个没有面向对象理解和技能的 C++程序员，其代码将难以被其他人维护、修改或理解。成为 C++中的面向对象程序员是公司需要利用这种语言的宝贵技能。

本书详细解释了基本的面向对象概念，并配有实际的代码示例，通常还附有图表，以便您真正理解事物的工作原理和原因。自我评估问题可用于测试您的技能。

本书首先提供了必要的技能构建模块（可能不是面向对象的），这些模块为面向对象的基本知识打下了基础。接下来，将描述面向对象的概念，并配以语言特性和编码技巧，以便您能够成功地将 C++作为面向对象的语言使用。此外，还添加了更高级的技能，包括友元函数/类、运算符重载、模板（用于构建更通用的代码）、异常处理（用于构建健壮的代码）、STL 基础，以及设计模式和习语。

通过本书，您将了解基本和高级的面向对象概念，以及如何在 C++中实现这些概念。您将学会不仅如何使用 C++，还要如何将其作为面向对象的语言使用。此外，您还将了解如何使代码更健壮、更易于维护，以及如何在编程中使用经过充分测试的设计模式。

# 这本书适合谁

本书的目标读者是专业程序员以及熟练的大学生，他们希望了解如何利用 C++作为面向对象编程语言来编写健壮、易于维护的代码。本书假设读者是程序员，但不一定熟悉 C++。早期章节简要回顾了核心语言特性，并作为主要面向对象编程章节、高级特性和设计模式的基石。

# 本书涵盖的内容

[*第一章*]，*理解基本的 C++假设*，提供了本书中假定的基本语言特性的简要回顾，现有程序员可以快速掌握。

[*第二章*]，*添加语言必需品*，回顾了关键的非面向对象特性，这些特性是 C++的基本构建模块：const 修饰符、函数原型（默认值）和函数重载。

[*第三章*]，*间接寻址-指针*，回顾了 C++中的指针，包括内存分配/释放、指针使用/解引用、在函数参数中的使用和 void *。

[*第四章*]，*间接寻址-引用*，介绍了引用作为指针的替代方法，包括初始化、函数参数/返回值和 const 修饰。

第五章《详细探讨类》首先介绍了面向对象编程，探讨了封装和信息隐藏的概念，然后详细介绍了类的特性：成员函数、`this`指针、访问标签和区域、构造函数、析构函数以及数据成员和成员函数的限定符（`const`、`static`、`inline`）。

第六章《使用单一继承实现层次结构》详细介绍了使用单一继承进行概括和特化。它涵盖了继承成员、基类构造函数的使用、继承的访问区域、构造/析构的顺序，以及公共与私有和受保护的基类，以及这如何改变继承的含义。

第七章《通过多态性利用动态绑定》描述了多态性的面向对象概念，然后区分了操作和方法，并详细介绍了虚函数和方法的运行时绑定（包括 v 表的工作原理）。

第八章《掌握抽象类》解释了抽象类的面向对象概念，它们使用纯虚拟函数进行实现，接口的面向对象概念以及如何实现它，以及在公共继承层次结构中进行向上和向下转换。

第九章《探索多重继承》详细介绍了如何使用多重继承以及在面向对象设计中的争议。它涵盖了虚基类、菱形继承结构，以及通过检查鉴别器的面向对象概念来考虑替代设计的时机。

第十章《实现关联、聚合和组合》描述了关联、聚合和组合的面向对象概念以及如何使用指针、指针集、包含和有时引用来实现每个概念。

第十一章《处理异常》解释了如何通过考虑许多异常情况来`try`、`throw`和`catch`异常。它还展示了如何扩展异常处理层次结构。

第十二章《友元和运算符重载》解释了友元函数和类的正确使用，并检查了运算符重载（可能使用友元）以使运算符与用户定义的类型以与标准类型相同的方式工作。

第十三章《使用模板》详细介绍了模板函数和类，以使某些类型的代码通用化以适用于任何数据类型。它还展示了如何通过运算符重载使选定的代码更通用，以进一步支持模板的使用。

第十四章《理解 STL 基础》介绍了 C++中的标准模板库，并演示了如何使用常见的容器，如`list`、`iterator`、`deque`、`stack`、`queue`、`priority_queue`和`map`。此外，还介绍了 STL 算法和函数对象。

第十五章《测试类和组件》说明了使用经典类形式进行面向对象测试方法，用于测试类的驱动程序，并展示了如何通过继承、关联和聚合来测试相关类，并使用异常处理来测试类。

第十六章《使用观察者模式》介绍了设计模式的整体概念，然后通过深入示例解释了观察者模式，说明了模式的各个组成部分。

*第十七章*，*应用工厂模式*，介绍了工厂方法模式，并展示了其在有或没有对象工厂的情况下的实现。还比较了对象工厂和抽象工厂。

*第十八章*，*应用适配器模式*，探讨了适配器模式，提供了使用继承与关联来实现该模式的策略和示例。此外，它演示了一个包装类作为简单的适配器。

*第十九章*，*使用单例模式*，详细探讨了单例模式，以及一个复杂的成对类实现。还介绍了单例注册表。

*第二十章*，*使用 pImpl 模式去除实现细节*，描述了 pImpl 模式，以减少代码中的编译时间依赖关系。使用了独特指针来探讨了详细的实现。还探讨了与该模式相关的性能问题。

# 充分利用本书

假设您有一个当前的 C++编译器可用。您可以尝试许多在线代码示例！您可以使用任何 C++编译器；但建议使用 17 版或更高版本。所呈现的代码将符合 C++20 标准，但在 17 版中同样有效。请至少从[`gcc.gnu.org`](https://gcc.gnu.org)下载 g++。

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/dmst-oop-cpp/img/B15702_Preface_Table_01.jpg)

*请记住，虽然 C++有一个 ISO 标准，但一些编译器会有所不同，并以微小的差异解释标准。*

如果您使用的是本书的数字版本，我们建议您自己输入代码或通过 GitHub 存储库（链接在下一节中提供）访问代码。这样做将有助于避免与复制和粘贴代码相关的任何潜在错误。

*强烈建议您在阅读本书时尝试编码示例。完成评估将进一步加强您对每个新概念的理解。*

# 下载示例代码文件

您可以从[www.packt.com](http://www.packt.com)的帐户中下载本书的示例代码文件。如果您在其他地方购买了本书，您可以访问[www.packtpub.com/support](http://www.packtpub.com/support)并注册，以便直接通过电子邮件接收文件。

该书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP`](https://github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP)。如果代码有更新，将在现有的 GitHub 存储库上进行更新。

我们还有其他代码包，来自我们丰富的图书和视频目录，可在[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)上找到。去看看吧！

# 下载彩色图片

我们还提供了一个 PDF 文件，其中包含本书中使用的屏幕截图/图表的彩色图片。您可以在此处下载：

[`static.packt-cdn.com/downloads/9781839218835_ColorImages.pdf`](https://static.packt-cdn.com/downloads/9781839218835_ColorImages.pdf)

# 实战代码

请访问以下链接查看 CiA 视频：[`bit.ly/2P1UXlI`](https://bit.ly/2P1UXlI)

# 使用的约定

本书中使用了许多文本约定。

`文本中的代码`：表示文本中的代码单词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄。以下是书中的一个例子："回顾我们前面的`main()`函数，我们首先创建一个`STL`的`list`，其中包含`list<Humanoid *> allies;`。"

代码块或程序段设置如下：

```cpp
char name[10] = "Dorothy"; 
float grades[20];  
grades[0] = 4.0;
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目将以粗体显示：

```cpp
cout << "Hello " << name << flush;
cout << ". GPA is: " << setprecision(3) << gpa << endl;
```

任何命令行输入或输出都将按如下方式编写：

```cpp
Ms. Giselle R. LeBrun
Dr. Zack R. Moon
Dr. Gabby A. Doone
```

**粗体**：表示一个新术语，一个重要的词，或者你在屏幕上看到的词。例如，菜单或对话框中的单词会以这种方式出现在文本中。这里有一个例子：“pImpl 模式（**p**ointer to **Impl**ementation idiom）是一种结构设计模式，它将类的实现与其公共接口分离开来。”

提示或重要说明

会以这种方式出现。


# 第一部分：C++构建块基础

本节的目标是确保您在构建即将到来的 C++面向对象编程技能之前具有扎实的非面向对象 C++技能背景。这是本书最短的部分，旨在快速让您适应面向对象编程和更高级的书籍章节。

第一章快速回顾了本书中所假设的先前技能：基本语言语法，循环结构，运算符，函数使用，用户定义类型基础（结构体，typedef 和类基础，枚举），以及命名空间基础。接下来的章节讨论了 const 限定变量，函数原型，带有默认值的原型，以及函数重载。

接下来的章节涵盖了使用指针进行间接寻址，介绍了 new()和 delete()来分配基本类型的数据，动态分配 1、2 和 N 维数组，使用 delete 管理内存，将参数作为函数参数传递，以及使用 void 指针。本节以一章结束，介绍了使用引用进行间接寻址，将带您回顾引用基础，引用现有对象，以及作为函数参数。

本节包括以下章节：

+   *第一章**，理解基本 C++假设*

+   *第二章**，添加语言必需品*

+   *第三章**，间接寻址 - 指针*

+   *第四章**，间接寻址 - 引用*


# 第一章：理解基本的 C++假设

本章将简要介绍 C++的基本语言语法、结构和特性，这些您应该已经熟悉了，无论是来自 C++、C、Java 或类似语言的基本语法。这些核心语言特性将被简要回顾。如果在完成本章后这些基本语法技能对您来说不熟悉，请先花时间探索更基本的基于语法的 C++文本，然后再继续阅读本书。本章的目标不是详细教授每个假定的技能，而是简要提供每个基本语言特性的概要，以便您能够快速回忆起应该已经掌握的技能。

本章中，我们将涵盖以下主要主题：

+   基本语言语法

+   基本输入/输出

+   控制结构、语句和循环

+   运算符

+   函数基础

+   用户定义类型基础

+   命名空间基础

通过本章结束时，您将对您应该熟练掌握的非常基本的 C++语言技能进行简要回顾。这些技能将是成功进入下一章所必需的。因为大多数这些特性不使用 C++的面向对象特性，我将尽量避免使用面向对象的术语，并在我们进入本书的面向对象部分时引入适当的面向对象术语。

# 技术要求

请确保您有一个当前的 C++编译器可用；您会想要尝试许多在线代码示例。至少，请从[`gcc.gnu.org`](https://gcc.gnu.org)下载 g++。

完整程序示例的在线代码可以在以下 GitHub URL 找到：[`github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter01`](https://github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter01)。每个完整程序示例都可以在 GitHub 存储库中找到，位于相应章节标题（子目录）下的文件中，文件名由章节号和当前章节中的示例号组成。例如，本章的第一个完整程序可以在子目录`Chapter01`中的名为`Chp1-Ex1.cpp`的文件中找到，位于上述 GitHub 目录中。

本章的 CiA 视频可以在以下链接观看：[`bit.ly/3c6oQdK`](https://bit.ly/3c6oQdK)。

# 回顾基本的 C++语言语法

在本节中，我们将简要回顾基本的 C++语法。我们假设您要么是具有非面向对象编程技能的 C++程序员，要么是在 C、Java 或类似的强类型检查语言中编程过，并且熟悉相关语法。您也可能是一个长期从事专业编程的程序员，能够快速掌握另一种语言的基础知识。让我们开始我们的简要回顾。

## 变量声明和标准数据类型

变量可以是任意长度，并且可以由字母、数字和下划线组成。变量区分大小写，并且必须以字母或下划线开头。C++中的标准数据类型包括：

+   `int`：用于存储整数

+   `float`：用于存储浮点值

+   `double`：用于存储双精度浮点值

+   `char`：用于存储单个字符

+   `bool`：用于布尔值 true 或 false

以下是使用上述标准数据类型的一些简单示例：

```cpp
int x = 5;
int a = x;
float y = 9.87; 
float y2 = 10.76f;  // optional 'f' suffix on float literal
float b = y;
double yy = 123456.78;
double c = yy;
char z = 'Z';
char d = z;
bool test = true;
bool e = test;
bool f = !test;
```

回顾前面的代码片段，注意变量可以被赋予文字值，比如`int x = 5;`，或者变量可以被赋予另一个变量的值或内容，比如`int a = x;`。这些例子展示了对各种标准数据类型的能力。注意对于`bool`类型，值可以被设置为`true`或`false`，或者使用`!`（非）来设置为这些值的相反值。

## 变量和数组基础

数组可以声明为任何数据类型。数组名称表示与数组内容相关的连续内存的起始地址。在 C++中，数组是从零开始的，这意味着它们的索引从数组`element[0]`开始，而不是从数组`element[1]`开始。最重要的是，在 C++中不对数组执行范围检查；如果访问超出数组大小的元素，那么您正在访问属于另一个变量的内存，您的代码很快可能会出错。

让我们回顾一些简单的数组声明、初始化和赋值：

```cpp
char name[10] = "Dorothy"; 
float grades[20];  
grades[0] = 4.0;
```

上面注意到，第一个数组`name`包含 10 个`char`元素，它们被初始化为字符串字面值`"Dorothy"`中的七个字符，后面跟着空字符(`'\0'`)。数组目前有两个未使用的元素。可以使用`name[0]`到`name[9]`来单独访问数组中的元素，因为 C++中的数组是从零开始的。同样，上面的数组，由变量`grades`标识，有 20 个元素，没有一个被初始化。在初始化或赋值之前访问任何数组值都可以包含任何值；对于任何未初始化的变量都是如此。注意，在声明数组`grades`后，它的零元素被赋值为`4.0`。

字符数组经常被概念化为字符串。许多标准字符串函数存在于诸如`<cstring>`的库中。如果要将字符数组作为字符串处理，应该以空字符结尾。当用字符数组的字符串初始化时，空字符会被自动添加。然而，如果通过赋值逐个添加字符到数组中，那么程序员就需要在数组中添加空字符(`'\0'`)作为最后一个元素。让我们看一些基本的例子：

```cpp
char book1[20] = "C++ Programming":
char book2[25];
strcpy(book2, "OO Programming with C++");
strcmp(book1, book2);
length = strlen(book2);
```

上面，第一个变量`book1`被声明为长度为 20 个字符，并初始化为字符串字面值`"C++ Programming"`。接下来，变量`book2`被声明为长度为 25 个字符的数组，但没有用值初始化。然后，使用`<cstring>`中的`strcpy()`函数将字符串字面值`"OO Programming with C++"`复制到变量`book2`中。注意，`strcpy()`将自动添加空字符到目标字符串。在下一行，也来自`<cstring>`的`strcmp()`函数用于按字典顺序比较变量`book1`和`book2`的内容。该函数返回一个整数值，可以存储在另一个变量中或用于比较。最后，使用`strlen()`函数来计算`book2`中的字符数（不包括空字符）。

## 注释风格

C++中有两种注释风格：

+   `/* */`风格提供了跨越多行代码的注释。这种风格不能与同一风格的其他注释嵌套。

+   `//`风格的注释提供了一个简单的注释，直到当前行的末尾。

同时使用两种注释风格可以允许嵌套注释，在调试代码时可能会很有用。

现在我们已经成功地回顾了基本的 C++语言特性，比如变量声明、标准数据类型、数组基础和注释风格，让我们继续回顾 C++的另一个基本语言特性：使用`<iostream>`库进行基本键盘输入和输出。

# 基本 I/O 回顾

在这一部分，我们将简要回顾使用键盘和显示器进行简单基于字符的输入和输出。还将简要介绍简单的操作符，以解释 I/O 缓冲区的基本机制，并提供基本的增强和格式化。

## iostream 库

在 C++中，最简单的输入和输出机制之一是使用`<iostream>`库。头文件`<iostream>`包含了`cin`、`cout`和`cerr`的数据类型定义，通过包含`std`命名空间来使用。`<iostream>`库简化了简单的 I/O：

+   `cin`可以与提取运算符`>>`一起用于输入

+   `cout`可以与插入运算符`<<`一起用于输出

+   `cerr`也可以与插入运算符一起使用，但用于错误

让我们回顾一个展示简单 I/O 的例子：

[`github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter01/Chp1-Ex1.cpp`](https://github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter01/Chp1-Ex1.cpp)

```cpp
#include <iostream>
using namespace std;
int main()
{
    char name[20];
    int age;
    cout << "Please enter a name and an age: ";
    cin >> name >> age;
    cout << "Hello " << name;
    cout << ". You are " << age << " years old." << endl;
    return 0;
}
```

首先，我们包含`<iostream>`库，并指示我们使用`std`命名空间来使用`cin`和`cout`（本章后面将更多介绍命名空间）。接下来，我们引入了`main()`函数，这是我们应用程序的入口点。在这里，我们声明了两个变量，`name`和`age`，都没有初始化。接下来，我们通过在与`cout`相关的缓冲区中放置字符串`"Please enter a name and an age: "`来提示用户输入。当与`cout`相关的缓冲区被刷新时，用户将在屏幕上看到这个提示。

然后，使用提取运算符`<<`将键盘输入的字符串放入与`cout`相关的缓冲区。方便的是，自动刷新与`cout`相关的缓冲区的机制是使用`cin`将键盘输入读入变量，比如下一行我们将用户输入读入变量`name`和`age`中。

接下来，我们向用户打印出一个问候语`"Hello"`，然后是输入的姓名，再然后是他们的年龄，从第二个用户输入中获取。这一行末尾的`endl`既将换行符`'\n'`放入输出缓冲区，又确保输出缓冲区被刷新 - 更多内容请看下文。`return 0;`声明只是将程序退出状态返回给编程外壳，这里是值`0`。请注意，`main()`函数指示了一个`int`类型的返回值，以确保这是可能的。

## 基本 iostream 操纵器

通常，希望能够操作与`cin`、`cout`和`cerr`相关的缓冲区的内容。操纵器允许修改这些对象的内部状态，从而影响它们相关的缓冲区的格式和操作。操纵器在`<iomanip>`头文件中定义。常见的操纵器示例包括：

+   `endl`: 将换行符放入与`cout`相关的缓冲区，然后刷新缓冲区

+   `flush`: 清除输出流的内容

+   `setprecision(int)`: 设置浮点数精度

+   `setw(int)`: 设置输入和输出的宽度

+   `ws`: 从缓冲区中移除空白字符

让我们看一个简单的例子：

[`github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter01/Chp1-Ex2.cpp`](https://github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter01/Chp1-Ex2.cpp)

```cpp
#include <iostream>
#include <iomanip>
using namespace std;
int main()
{
    char name[20];
    float gpa;   // grade point average
    cout << "Please enter a name and a gpa: "; 
    cin >> setw(20) >> name >> gpa;
    cout << "Hello " << name << flush;
    cout << ". GPA is: " << setprecision(3) << gpa << endl;
    return 0;
}
```

在这个例子中，首先注意到包含了`<iomanip>`头文件。还要注意到，`setw(20)`用于确保我们不会溢出名字变量，它只有 20 个字符长；`setw()`会自动减去一个提供的大小，以确保有空间放置空字符。注意第二个输出行上使用了`flush` - 这里不需要刷新输出缓冲区；这个操纵器只是演示了如何应用`flush`。在最后一个`cout`输出行上，注意使用了`setprecision(3)`来打印浮点数`gpa`。三位精度包括小数点和小数点右边的两位。

现在我们已经回顾了使用`<iostream>`库进行简单输入和输出，让我们继续通过简要回顾控制结构、语句和循环结构。

# 重新审视控制结构、语句和循环

C++有各种控制结构和循环结构，允许非顺序程序流。每个都可以与简单或复合语句配对。简单语句以分号结束；更复杂的语句则用一对大括号`{}`括起来。在本节中，我们将重新讨论各种类型的控制结构（`if`，`else if`和`else`）和循环结构（`while`，`do while`和`for`），以回顾代码中非顺序程序流的简单方法。

## 控制结构：if，else if 和 else

使用`if`，`else if`和`else`进行条件语句可以与简单语句或一组语句一起使用。请注意，`if`子句可以在没有后续`else if`或`else`子句的情况下使用。实际上，`else if`实际上是`else`子句的一种简化版本，其中包含一个嵌套的`if`子句。实际上，开发人员将嵌套使用展平为`else if`格式，以提高可读性并节省多余的缩进。让我们看一个例子：

[`github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter01/Chp1-Ex3.cpp`](https://github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter01/Chp1-Ex3.cpp)

```cpp
#include <iostream>
using namespace std;
int main()
{
    int x;
    cout << "Enter an integer: ";
    cin >> x;
    if (x == 0) 
        cout << "x is 0" << endl;
    else if (x < 0)
        cout << "x is negative" << endl;
    else
    {
        cout << "x is positive";
        cout << "and ten times x is: " << x * 10 << endl;
    }  
    return 0;
}
```

请注意，在上面的`else`子句中，多个语句被捆绑成一个代码块，而在`if`和`else if`条件中，每个条件后面只有一个语句。另外，需要注意的是，在 C++中，任何非零值都被视为 true。因此，例如，测试`if (x)`会暗示`x`不等于零 - 无需写`if (x !=0)`，除非可能是为了可读性。

## 循环结构：while，do while 和 for 循环

C++有几种循环结构。让我们花点时间来回顾每种样式的简短示例，从`while`和`do while`循环结构开始。

[`github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter01/Chp1-Ex4.cpp`](https://github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter01/Chp1-Ex4.cpp)

```cpp
#include <iostream>
using namespace std;
int main()
{
    int i = 0;
    while (i < 10)
    {
        cout << i << endl;
        i++;
    }
    i = 0;
    do 
    {
        cout << i << endl;
        i++;
    } while (i < 10);
    return 0;
}
```

使用`while`循环时，进入循环的条件必须在每次进入循环体之前求值为 true。然而，使用`do while`循环时，保证第一次进入循环体 - 然后在再次迭代循环体之前求值条件。在上面的示例中，`while`和`do while`循环都执行 10 次，每次打印变量`i`的值为 0-9。

接下来，让我们回顾一下典型的`for`循环。`for`循环在`()`内有三部分。首先，有一个语句，它只执行一次，通常用于初始化循环控制变量。接下来，在`()`的中心两侧用分号分隔的是一个表达式。这个表达式在进入循环体之前每次都会被求值。只有当这个表达式求值为 true 时，才会进入循环体。最后，在`()`内的第三部分是第二个语句。这个语句在执行完循环体后立即执行，并且通常用于修改循环控制变量。在执行完这个第二个语句后，中心的表达式会被重新求值。以下是一个例子：

[`github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter01/Chp1-Ex5.cpp`](https://github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter01/Chp1-Ex5.cpp)

```cpp
#include <iostream>
using namespace std;
int main()
{
    int i;
    for (i = 0; i < 10; i++) 
        cout << i << endl;
    for (int j = 0; j < 10; j++)
        cout << j << endl;
    return 0;
}
```

在上面，我们有两个`for`循环。在第一个循环之前，变量`i`被声明。然后在循环括号`()`之间的语句 1 中用值`0`初始化变量`i`。测试循环条件，如果为真，则进入并执行循环体，然后在重新测试循环条件之前执行语句 2。这个循环对`i`的值从 0 到 9 执行 10 次。第二个`for`循环类似，唯一的区别是变量`j`在循环结构的语句 1 中声明和初始化。请注意，变量`j`只在`for`循环本身的范围内，而变量`i`在其声明点之后的整个块的范围内。

让我们快速看一个使用嵌套循环的示例。循环结构可以是任何类型，但下面我们将回顾嵌套的`for`循环。

[`github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter01/Chp1-Ex6.cpp`](https://github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter01/Chp1-Ex6.cpp)

```cpp
#include <iostream>
using namespace std;
int main()
{
    for (int i = 0; i < 10; i++) 
    {
        cout << i << endl;
        for (int j = 0; j < 10; j++)
            cout << j << endl;
        cout << "\n";
    }
    return 0;
}
```

在上面的外部循环中，`i`的值从 0 到 9 执行 10 次。对于每个`i`的值，内部循环将执行 10 次，`j`的值从 0 到 9。请记住，使用`for`循环时，循环控制变量会在循环结构内部自动递增`i++`或`j++`。如果使用了`while`循环，程序员需要记住在每个这样的循环体的最后一行递增循环控制变量。

现在我们已经回顾了 C++中的控制结构、语句和循环结构，我们可以通过简要回顾 C++的运算符来继续前进。

# 回顾 C++运算符

一元、二元和三元运算符都存在于 C++中。C++允许运算符根据使用的上下文具有不同的含义。C++还允许程序员重新定义至少一个用户定义类型的上下文中使用的选定运算符的含义。以下是运算符的简明列表。我们将在本节的其余部分和整个课程中看到这些运算符的示例。以下是 C++中二元、一元和三元运算符的概要：

![表 1.1 - 二元运算符](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/dmst-oop-cpp/img/Table_1.1_B15702.jpg)

表 1.1 - 二元运算符

在上述二元运算符列表中，注意到许多运算符在与赋值运算符`=`配对时具有“快捷”版本。例如，`a = a * b`可以使用快捷操作符`a *= b`等效地编写。让我们看一个包含各种运算符使用的示例，包括快捷操作符的使用：

```cpp
score += 5;
score++;
if (score == 100)
    cout << "You have a perfect score!" << endl;
else
    cout << "Your score is: " << score << endl;
// equivalent to if - else above, but using ?: operator
(score == 100)? cout << "You have a perfect score" << endl :
                cout << "Your score is: " << score << endl; 
```

在前面的代码片段中，注意到了快捷操作符`+=`的使用。在这里，语句`score += 5;`等同于`score = score + 5;`。接下来，使用一元递增运算符`++`来将`score`增加 1。然后我们看到等号运算符`==`用于将分数与 100 进行比较。最后，我们看到了三元运算符`?:`的示例，用于替换简单的`if`-`else`语句。值得注意的是，一些程序员不喜欢使用`?:`，但总是有趣的回顾其使用示例。

现在我们已经简要回顾了 C++中的运算符，让我们重新审视函数基础知识。

# 重新审视函数基础知识

函数标识符必须以字母或下划线开头，也可以包含数字。函数的返回类型、参数列表和返回值都是可选的。C++函数的基本形式如下：

```cpp
<return type> functionName (<argumentType argument1, …>)
{
    expression 1…N;
    <return value/expression;>
}
```

让我们回顾一个简单的函数：

[`github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter01/Chp1-Ex7.cpp`](https://github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter01/Chp1-Ex7.cpp)

```cpp
#include <iostream>
using namespace std;
int minimum(int a, int b)
{
    if (a < b)
        return a;
    else
        return b;
}
int main()
{
    int x, y;
    cout << "Enter two integers: ";
    cin >> x >> y;
    cout << "The minimum is: " << minimum(x, y) << endl;
    return 0;
}
```

在上面的简单示例中，首先定义了一个`minimum()`函数。它的返回类型是`int`，它接受两个整数参数：形式参数`a`和`b`。在`main()`函数中，使用实际参数`x`和`y`调用了`minimum()`。在`cout`语句中允许调用`minimum()`，因为`minimum()`返回一个整数值；这个值随后传递给提取运算符（`<<`），与打印一起使用。实际上，字符串`"The minimum is: "`首先被放入与`cout`关联的缓冲区中，然后是调用函数`minimum()`的返回值。然后输出缓冲区被`endl`刷新（它首先在刷新之前将换行符放入缓冲区）。

请注意，函数首先在文件中定义，然后在文件的`main()`函数中稍后调用。通过比较参数类型和它们在函数调用中的使用，对函数的调用执行了强类型检查。然而，当函数调用在其定义之前时会发生什么？或者如果对函数的调用在与其定义不同的文件中呢？

在这些情况下，编译器的默认操作是假定函数的某种*签名*，比如整数返回类型，并且形式参数将匹配函数调用中的参数类型。通常，默认假设是不正确的；当编译器在文件中稍后遇到函数定义（或者链接另一个文件时），将会引发错误，指示函数调用和定义不匹配。

这些问题在历史上已经通过在将调用函数的文件顶部包含函数的前向声明来解决。前向声明由函数返回类型、函数名称和类型以及参数数量组成。在 C++中，前向声明已经得到改进，而被称为函数原型。由于围绕函数原型存在许多有趣的细节，这个主题将在下一章中得到合理详细的介绍。

当我们在本书的面向对象部分（*第五章*，*详细探讨类*，以及更多）中学习时，我们将了解到有关函数的许多更多细节和相当有趣的特性。尽管如此，我们已经充分回顾了前进所需的基础知识。接下来，让我们继续我们的 C++语言回顾，学习用户定义类型。

# 回顾用户定义类型的基础

C++提供了几种机制来创建用户定义的类型。将类似特征捆绑成一个数据类型（稍后，我们还将添加相关的行为）将形成面向对象概念的封装的基础，这将在本文的后面部分中进行介绍。现在，让我们回顾一下将数据仅捆绑在`struct`、`class`和`typedef`（在较小程度上）中的基本机制。我们还将回顾枚举类型，以更有意义地表示整数列表。

## struct

C++结构在其最简单的形式中可以用来将共同的数据元素收集在一个单一的单元中。然后可以声明复合数据类型的变量。点运算符用于访问每个结构变量的特定成员。这是以最简单方式使用的结构：

https://github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter01/Chp1-Ex8.cpp

```cpp
#include <iostream>
#include <cstring>
using namespace std;
struct student
{
    char name[20];
    float semesterGrades[5];
    float gpa;
};
int main()
{
    student s1;
    strcpy(s1.name, "George Katz");
    s1.semesterGrades[0] = 3.0;
    s1.semesterGrades[1] = 4.0;
    s1.gpa = 3.5;
    cout << s1.name << " has GPA: " << s1.gpa << endl;
    return 0;
}
```

从风格上看，使用结构体时，类型名称通常是小写的。在上面的例子中，我们使用`struct`声明了用户定义类型`student`。类型`student`有三个字段或数据成员：`name`，`semesterGrades`和`gpa`。在`main()`函数中，声明了一个类型为 student 的变量`s1`；点运算符用于访问变量的每个数据成员。由于在 C++中，结构体通常不用于面向对象编程，因此我们还不会介绍与其使用相关的重要面向对象术语。值得注意的是，在 C++中，标签`student`也成为类型名称（与 C 中需要在变量声明之前使用`struct`一词不同）。

## typedef

`typedef`可以用于为数据类型提供更易记的表示。在 C++中，使用`struct`时相对不需要`typedef`。在 C 中，`typedef`允许将关键字`struct`和结构标签捆绑在一起，创建用户定义的类型。然而，在 C++中，由于结构标签自动成为类型，因此对于`struct`来说，`typedef`变得完全不必要。Typedefs 仍然可以与标准类型一起使用，以增强代码的可读性，但在这种情况下，typedef 并不像`struct`那样用于捆绑数据元素。让我们看一个简单的 typedef：

```cpp
typedef float dollars; 
```

在上面的声明中，新类型`dollars`可以与类型`float`互换使用。展示结构体的古老用法并不具有生产力，因此让我们继续前进，看看 C++中最常用的用户定义类型，即`class`。

## class

`class`在其最简单的形式中几乎可以像`struct`一样用于将相关数据捆绑成单个数据类型。在*第五章*，*详细探讨类*中，我们将看到`class`通常也用于将相关函数与新数据类型捆绑在一起。将相关数据和行为分组到该数据是封装的基础。现在，让我们看一个`class`的最简单形式，就像`struct`一样：

[`github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter01/Chp1-Ex9.cpp`](https://github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter01/Chp1-Ex9.cpp)

```cpp
#include <iostream>
#include <cstring>
using namespace std;
class Student
{
public:
    char name[20];
    float semesterGrades[5];
    float gpa;
};
int main()
{
    Student s1;
    strcpy(s1.name, "George Katz");
    s1.semesterGrades[0] = 3.0;
    s1.semesterGrades[1] = 4.0;
    s1.gpa = 3.5;
    cout << s1.name << " has GPA: " << s1.gpa << endl;
    return 0;
}
```

请注意上面的代码与`struct`示例中使用的代码非常相似。主要区别是关键字`class`而不是关键字`struct`，以及在类定义的开头添加访问标签`public:`（更多内容请参见*第五章*，*详细探讨类*）。从风格上看，类似`Student`这样的数据类型的首字母大写是典型的。我们将看到类具有丰富的特性，是面向对象编程的基本组成部分。我们将介绍新的术语，例如*实例*，而不是*变量*。然而，本节只是对假定技能的复习，因此我们需要等待才能了解语言的令人兴奋的面向对象特性。剧透警告：所有类将能够做的美妙事情也适用于结构体；然而，我们将看到，从风格上讲，结构体不会被用来举例说明面向对象编程。

## enum

枚举类型可以用来记忆地表示整数列表。除非另有初始化，枚举中的整数值从零开始，并在整个列表中递增一。两个枚举类型不能使用相同的枚举器名称。现在让我们看一个例子：

[`github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter01/Chp1-Ex10.cpp`](https://github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter01/Chp1-Ex10.cpp)

```cpp
#include <iostream>
using namespace std;
enum day {Sunday,  Monday, Tuesday, Wednesday, Thursday,
          Friday, Saturday};
enum workDay {Mon = 1, Tues, Wed, Thurs, Fri};
int main()
{
    day birthday = Monday;
    workDay payday = Fri;
    cout << "Birthday is " << birthday << endl;
    cout << "Payday is " << payday << endl;
    return 0;
}
```

在上一个例子中，枚举类型`day`的值从`Sunday`开始，从 0 到 6。枚举类型`workDay`的值从`Mon`开始，从 1 到 5。请注意，显式使用`Mon = 1`作为枚举类型中的第一项已被用来覆盖默认的起始值 0。有趣的是，我们可能不会在两个枚举类型之间重复枚举器。因此，您会注意到`Mon`在`workDay`中被用作枚举器，因为`Monday`已经在枚举类型`day`中使用过。现在，当我们创建变量如`birthday`或`payday`时，我们可以使用有意义的枚举类型来初始化或赋值，比如`Monday`或`Fri`。尽管枚举器在代码中可能是有意义的，请注意，当操作或打印值时，它们将是相应的整数值。

现在我们已经重新访问了 C++中的简单用户定义类型，包括`struct`、`typedef`、`class`和`enum`，我们准备继续审查我们下一个语言必需品，即`namespace`。

# 命名空间基础回顾

命名空间实用程序被添加到 C++中，以在全局范围之外添加一个作用域级别到应用程序。这个特性可以用来允许两个或更多库被使用，而不必担心它们可能包含重复的数据类型、函数或标识符。程序员需要在应用程序的每个相关部分使用关键字`using`来激活所需的命名空间。程序员还可以创建自己的命名空间（通常用于创建可重用的库代码），并在适用时激活每个命名空间。在上面的例子中，我们已经看到了简单使用`std`命名空间来包括`cin`和`cout`，它们是`istream`和`ostream`的实例（它们的定义可以在`<iostream>`中找到）。让我们回顾一下如何创建自己的命名空间：

[`github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter01/Chp1-Ex11.cpp`](https://github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter01/Chp1-Ex11.cpp)

```cpp
#include <iostream>
using namespace std;
namespace DataTypes
{
    int total;
    class LinkList
    {  // full class definition … 
    };
    class Stack
    {  // full class definition …
    };
};
namespace AbstractDataTypes
{
    class Stack
    {  // full class definition …
    };
    class Queue
    {  // full class description …
    };
};
// Add entries to the AbstractDataTypes namespace
namespace AbstractDataTypes   
{
    int total;
    class Tree
    {  // full class definition …
    };
};
int main()
{
    using namespace AbstractDataTypes; // activate namespace
    using DataTypes::LinkList;    // activate only LinkList 
    LinkList list1;     // LinkList is found in DataTypes
    Stack stack1;       // Stack is found in AbstractDataTypes
    total = 5;          // total from active AbstractDataTypes
    DataTypes::total = 85; // specify non-active member, total
    cout << "total " << total << "\n";
    cout << "DataTypes::total " << DataTypes::total << endl;
    return 0;
}
```

在上面的第二行代码中，我们使用关键字`using`表示我们想要使用或激活`std`命名空间。我们可以利用`using`来打开包含有用类的现有库；关键字`using`激活给定库可能属于的命名空间。接下来在代码中，使用`namespace`关键字创建了一个名为`DataTypes`的用户创建的命名空间。在这个命名空间中存在一个变量`total`和两个类定义：`LinkList`和`Stack`。在这个命名空间之后，创建了第二个命名空间`AbstractDataTypes`，其中包括两个类定义：`Stack`和`Queue`。此外，命名空间`AbstractDataTypes`通过第二次*namespace*定义的出现增加了一个变量`total`和一个`Tree`的类定义。

在`main()`函数中，首先使用关键字`using`打开了`AbstractDataTypes`命名空间。这激活了这个命名空间中的所有名称。接下来，关键字`using`与作用域解析运算符(`::`)结合，只激活了`DataTypes`命名空间中的`LinkList`类定义。如果`AbstractDataType`命名空间中也有一个`LinkList`类，那么初始可见的`LinkList`现在将被`DataTypes::LinkList`的激活所隐藏。

接下来，声明了一个类型为`LinkList`的变量，其定义来自`DataTypes`命名空间。接下来声明了一个类型为`Stack`的变量；虽然两个命名空间都有`Stack`类的定义，但由于只激活了一个`Stack`，所以没有歧义。接下来，我们使用`cin`读取到来自`AbstractDataTypes`命名空间的`total`。最后，我们使用作用域解析运算符显式地读取到`DataTypes::total`，否则该名称将被隐藏。需要注意的一点是：如果两个或更多的命名空间包含相同的“名称”，则最后打开的命名空间将主导，隐藏所有先前的出现。

# 总结

在本章中，我们回顾了核心 C++语法和非面向对象语言特性，以刷新您现有的技能。这些特性包括基本语言语法，使用`<iostream>`进行基本 I/O，控制结构/语句/循环，运算符基础，函数基础，简单的用户定义类型以及命名空间。最重要的是，您现在已经准备好进入下一章，在这一章中，我们将扩展一些这些想法，包括`const`限定变量，理解和使用原型（包括默认值），以及函数重载等额外的语言必需品。

下一章中的想法开始让我们更接近面向对象编程的目标，因为许多这些聚合技能经常被使用，并且随着我们深入语言，它们变得理所当然。重要的是要记住，在 C++中，你可以做任何事情，无论你是否有意这样做。语言中有巨大的力量，对其许多微妙和特性有一个坚实的基础是至关重要的。在接下来的几章中，将奠定坚实的基础，以掌握一系列非面向对象的 C++技能，这样我们就可以以高水平的理解和成功实现在 C++中进行面向对象编程。

# 问题

1.  描述一种情况，在这种情况下，`flush`而不是`endl`可能对清除与`cout`关联的缓冲区的内容有用。

1.  一元运算符`++`可以用作前置或后置递增运算符，例如`i++`或`++i`。你能描述一种情况，在这种情况下，选择前置递增还是后置递增对代码会产生不同的后果吗？

1.  创建一个简单的程序，使用`struct`或`class`为`Book`创建一个用户定义类型。为标题、作者和页数添加数据成员。创建两个类型为`Book`的变量，并使用点运算符`.`为每个实例填写数据成员。使用`iostreams`提示用户输入值，并在完成时打印每个`Book`实例。只使用本节介绍的功能。


# 第二章：添加语言必需性

本章将介绍 C++的非面向对象特性，这些特性是 C++面向对象特性的重要基石。本章介绍的特性代表了从本章开始在本书中将被毫不犹豫地使用的主题。C++是一门笼罩在灰色地带的语言；从本章开始，您将不仅熟悉语言特性，还将熟悉语言的微妙之处。本章的目标将是从一个普通的 C++程序员的技能开始，使其能够成功地在创建可维护的代码的同时在语言的微妙之处中操作。

在本章中，我们将涵盖以下主要主题：

+   `const`限定符

+   函数原型

+   函数重载

通过本章结束时，您将了解非面向对象的特性，如`const`限定符，函数原型（包括使用默认值），函数重载（包括标准类型转换如何影响重载函数选择并可能创建潜在的歧义）。许多这些看似简单的主题包括各种有趣的细节和微妙之处。这些技能将是成功地继续阅读本书后续章节所必需的。

# 技术要求

完整程序示例的在线代码可以在以下 GitHub URL 找到：[`github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter02`](https://github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter02)。每个完整的程序示例都可以在 GitHub 存储库中的适当章节标题（子目录）下找到，文件名与所在章节号相对应，后跟破折号，再跟随所在章节中的示例编号。例如，*第二章*，*添加语言必需性*中的第一个完整程序可以在名为`Chp2-Ex1.cpp`的文件中的`Chapter02`子目录中找到上述 GitHub 目录下。

本章的 CiA 视频可在以下链接观看：[`bit.ly/3cTYgnB`](https://bit.ly/3cTYgnB)。

# 使用 const 限定符

在本节中，我们将向变量添加`const`限定符，并讨论如何将其添加到函数的输入参数和返回值中。随着我们在 C++语言中的进一步学习，`const`限定符将被广泛使用。使用`const`可以使值被初始化，但永远不会再次修改。函数可以声明它们不会修改其输入参数，或者它们的返回值只能被捕获（但不能被修改）使用`const`。`const`限定符有助于使 C++成为一种更安全的语言。让我们看看`const`的实际应用。

## 常量变量

一个`const`限定的变量是一个必须被初始化的变量，永远不能被赋予新值。将`const`和变量一起使用似乎是一个悖论-`const`意味着不改变，然而变量的概念本质上是持有不同的值。尽管如此，拥有一个在运行时可以确定其唯一值的强类型检查变量是有用的。关键字`const`被添加到变量声明中。

让我们在以下程序中考虑一些例子。我们将把这个程序分成两个部分，以便更有针对性地解释，但是完整的程序示例可以在以下链接中找到：

[`github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter02/Chp2-Ex1.cpp`](https://github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter02/Chp2-Ex1.cpp)

```cpp
#include <iostream>
#include <iomanip>
#include <cstring>
using namespace std;
// simple const variable declaration and initialization
const int MAX = 50; 
int minimum(int a, int b)  // function definition with
{                          // formal parameters
    return (a < b)? a : b;   // conditional operator ?: 
}
```

在前面的程序段中，请注意我们在数据类型之前使用`const`限定符声明变量。在这里，`const int MAX = 50;`简单地将`MAX`初始化为`50`。`MAX`不能通过赋值在代码中后期修改。按照惯例，简单的`const`限定变量通常大写。接下来，我们有函数`minimum()`的定义；请注意在这个函数体中使用了三元条件运算符`?:`。接下来，让我们继续查看`main()`函数的主体，继续进行本程序的其余部分：

```cpp
int main()
{
    int x, y;
    cout << "Enter two values: ";
    cin >> x >> y;
    const int MIN = minimum(x, y);  // const var initialized 
                             // with a function's return value
    cout << "Minimum is: " << MIN << endl;
    char bigName[MAX];      // const var used to size an array
    cout << "Enter a name: ";
    cin >> setw(MAX) >> bigName;
    const int NAMELEN = strlen(bigName); // another const
    cout << "Length of name: " << NAMELEN << endl;
    return 0;
}
```

在`main()`中，让我们考虑代码的顺序，提示用户将“输入两个值：”分别存入变量`x`和`y`中。在这里，我们调用函数`minimum(x,y)`，并将我们刚刚使用`cin`和提取运算符`>>`读取的两个值`x`和`y`作为实际参数传递。请注意，除了`MIN`的`const`变量声明之外，我们还使用函数调用`minimum()`的返回值初始化了`MIN`。重要的是要注意，设置`MIN`被捆绑为单个声明和初始化。如果这被分成两行代码--变量声明后跟一个赋值--编译器将会标记一个错误。`const`变量只能在声明后用一个值初始化，不能在声明后赋值。

在上面的最后一段代码中，请注意我们使用`MAX`（在这个完整程序示例的早期部分定义）来定义固定大小数组`bigName`的大小：`char bigName[MAX];`。然后，我们在`setw(MAX)`中进一步使用`MAX`来确保我们在使用`cin`和提取运算符`>>`读取键盘输入时不会溢出`bigName`。最后，我们使用函数`strlen(bigname)`的返回值初始化变量`const int NAMELEN`，并使用`cout`打印出这个值。

上面完整程序示例的输出如下：

```cpp
Enter two values: 39 17
Minimum is: 17
Enter a name: Gabby
Length of name: 5
```

现在我们已经看到了如何对变量进行`const`限定，让我们考虑对函数进行`const`限定。

## 函数的 const 限定

关键字`const`也可以与函数一起使用。`const`限定符可以用于参数中，表示参数本身不会被修改。这是一个有用的特性--函数的调用者将了解到以这种方式限定的输入参数不会被修改。然而，因为非指针（和非引用）变量被作为“按值”传递给函数，作为实际参数在堆栈上的副本，对这些固有参数的`const`限定并没有任何意义。因此，对标准数据类型的参数进行`const`限定是不必要的。

相同的原则也适用于函数的返回值。函数的返回值可以被`const`限定，然而，除非返回一个指针（或引用），作为返回值传回堆栈的项目是一个副本。因此，当返回类型是指向常量对象的指针时，`const`限定返回值更有意义（我们将在*第三章*中介绍，*间接寻址：指针*及以后内容）。作为`const`的最后一个用途，我们可以在类的 OO 细节中使用这个关键字，以指定特定成员函数不会修改该类的任何数据成员。我们将在*第五章*中探讨这种情况，*详细探讨类*。

现在我们了解了`const`限定符用于变量，并看到了与函数一起使用`const`的潜在用途，让我们继续前进到本章的下一个语言特性：函数原型。

# 使用函数原型

在本节中，我们将研究函数原型的机制，比如在文件中的必要放置和跨多个文件以实现更大的程序灵活性。我们还将为原型参数添加可选名称，并了解我们为什么可以选择向 C++原型添加默认值。函数原型确保了 C++代码的强类型检查。

在继续讨论函数原型之前，让我们花一点时间回顾一些必要的编程术语。**函数定义**指的是组成函数的代码主体。而函数的声明（也称为**前向声明**）仅仅是引入了函数名及其返回类型和参数类型，前向声明允许编译器通过将调用与前向声明进行比较而执行强类型检查。前向声明很有用，因为函数定义并不总是在函数调用之前出现在一个文件中；有时，函数定义出现在与它们的调用分开的文件中。

## 定义函数原型

**函数原型**是对函数的前向声明，描述了函数应该如何被正确调用。原型确保了函数调用和定义之间的强类型检查。函数原型包括：

+   函数的返回类型

+   函数的名称

+   函数的类型和参数数量

函数原型允许函数调用在函数的定义之前，或者允许调用存在于不同的文件中的函数。让我们来看一个简单的例子：

[`github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter02/Chp2-Ex2.cpp`](https://github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter02/Chp2-Ex2.cpp)

```cpp
#include <iostream>
using namespace std;
int minimum(int, int);     // function prototype

int main()
{
    int x = 5, y = 89;
    // function call with actual parameters
    cout << minimum(x, y) << endl;     
    return 0;                          
}
int minimum(int a, int b)  // function definition with
{                          // formal parameters
    return (a < b)? a : b;  
}
```

注意，我们在上面的例子中在开头原型了`int minimum(int, int);`。这个原型让编译器知道对`minimum()`的任何调用都应该带有两个整数参数，并且应该返回一个整数值（我们将在本节后面讨论类型转换）。

接下来，在`main()`函数中，我们调用函数`minimum(x, y)`。此时，编译器检查函数调用是否与前面提到的原型匹配，包括参数的类型和数量以及返回类型。也就是说，这两个参数是整数（或者可以轻松转换为整数），返回类型是整数（或者可以轻松转换为整数）。返回值将被用作`cout`打印的值。最后，在文件中定义了函数`minimum()`。如果函数定义与原型不匹配，编译器将引发错误。

原型的存在允许对给定函数的调用在编译器看到函数定义之前进行完全的类型检查。上面的例子当然是为了演示这一点而捏造的；我们也可以改变`minimum()`和`main()`在文件中出现的顺序。然而，想象一下`minimum()`的定义包含在一个单独的文件中（更典型的情况）。在这种情况下，原型将出现在调用这个函数的文件的顶部（以及头文件的包含），以便函数调用可以完全根据原型进行类型检查。

在上述的多文件情况下，包含函数定义的文件将被单独编译。然后链接器的工作是确保当这两个文件链接在一起时，函数定义和原型匹配，以便链接器可以解析对这样的函数调用的任何引用。如果原型和定义不匹配，链接器将无法将代码的这两部分链接成一个编译单元。

让我们来看一下这个例子的输出：

```cpp
5
```

现在我们了解了函数原型基础知识，让我们看看如何向函数原型添加可选参数名称。

## 在函数原型中命名参数

函数原型可以选择包含名称，这些名称可能与形式参数或实际参数列表中的名称不同。参数名称会被编译器忽略，但通常可以增强可读性。让我们重新看一下我们之前的示例，在函数原型中添加可选参数名称。

[`github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter02/Chp2-Ex3.cpp`](https://github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter02/Chp2-Ex3.cpp)

```cpp
#include <iostream>
using namespace std;
int minimum(int arg1, int arg2);    // function prototype with
                                    // optional argument names
int main()
{
    int x = 5, y = 89;
    cout << minimum(x, y) << endl;   // function call
    return 0;
}
int minimum(int a, int b)            // function definition
{
    return (a < b)? a : b;  
}
```

这个示例几乎与前面的示例相同。但是，请注意函数原型包含了命名参数`arg1`和`arg2`。这些标识符会被编译器立即忽略。因此，这些命名参数不需要与函数的形式参数或实际参数匹配，仅仅是为了增强可读性而可选地存在。

与上一个示例相同，此示例的输出如下：

```cpp
5
```

接下来，让我们通过向函数原型添加一个有用的功能来继续我们的讨论：默认值。

## 向函数原型添加默认值

**默认值**可以在函数原型中指定。这些值将在函数调用中没有实际参数时使用，并将作为实际参数本身。默认值必须符合以下标准：

+   必须从右到左在函数原型中指定默认值，不能省略任何值。

+   实际参数在函数调用中从左到右进行替换；因此，在原型中从右到左指定默认值的顺序是重要的。

函数原型可以有全部、部分或没有默认值填充，只要默认值符合上述规定。

让我们看一个使用默认值的示例：

[`github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter02/Chp2-Ex4.cpp`](https://github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter02/Chp2-Ex4.cpp)

```cpp
#include <iostream>
using namespace std;
int minimum(int arg1, int arg2 = 100000);  // fn. prototype
                                    // with one default value
int main()
{
    int x = 5, y = 89;
    cout << minimum(x) << endl; // function call with only
                                // one argument (uses default)
    cout << minimum(x, y) << endl; // no default values used
    return 0;
}
int minimum(int a, int b)            // function definition
{
    return (a < b)? a : b;  
}
```

在这个示例中，请注意在函数原型`int minimum(int arg1, int arg2 = 100000);`中向最右边的参数添加了一个默认值。这意味着当从`main()`中调用`minimum`时，可以使用一个参数调用：`minimum(x)`，也可以使用两个参数调用：`minimum(x, y)`。当使用一个参数调用`minimum()`时，单个参数绑定到函数的形式参数中的最左边参数，而默认值绑定到形式参数列表中的下一个顺序参数。但是，当使用两个参数调用`minimum()`时，实际参数都绑定到函数中的形式参数；默认值不会被使用。

这个示例的输出如下：

```cpp
5
5
```

现在我们已经掌握了函数原型中的默认值，让我们通过在各种程序作用域中使用不同的默认值来扩展这个想法。

## 在不同作用域中使用不同默认值进行原型化

函数可以在不同的作用域中使用不同的默认值进行原型化。这允许函数在多个应用程序中以通用方式构建，并通过原型在多个代码部分中进行定制。

这是一个示例，演示了相同函数的多个原型（在不同的作用域中）使用不同的默认值。

[`github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter02/Chp2-Ex5.cpp`](https://github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter02/Chp2-Ex5.cpp)

```cpp
#include <iostream>
using namespace std;
int minimum(int, int);   // standard function prototype
void function1(int x)
{   
    int minimum(int arg1, int arg2 = 500); // local prototype
                                           // with default value
    cout << minimum(x) << endl; 
}
void function2(int x)
{
    int minimum(int arg1, int arg2 = 90);  // local prototype
                                           // with default value
    cout << minimum(x) << endl; 
}

int minimum(int a, int b)            // function definition
{ 
    return (a < b)? a : b;   
}
int main()
{
    function1(30);    
    function2(450);
    return 0;
}
```

在这个示例中，请注意在文件顶部附近原型化了`int minimum(int, int);`，然后注意在`function1()`的更局部范围内重新定义了`minimum()`，作为`int minimum(int arg1, int arg2 = 500);`，为其最右边的参数指定了默认值`500`。同样，在`function2()`的范围内，函数`minimum()`被重新定义为：`int minimum(int arg1, int arg2 = 90);`，为其最右边的参数指定了默认值`90`。当在`function1()`或`function2()`中调用`minimum()`时，将分别使用每个函数范围内的本地原型-每个都有自己的默认值。

通过这种方式，程序的特定部分可以很容易地使用默认值进行定制，这些默认值在应用程序的特定部分可能是有意义的。但是，请确保*仅*在调用函数的范围内使用重新定义函数的个性化默认值，以确保这种定制可以轻松地包含在非常有限的范围内。永远不要在全局范围内重新定义具有不同默认值的函数原型-这可能会导致意外和容易出错的结果。

示例的输出如下：

```cpp
30
90
```

在单个和多个文件中探索了函数原型的默认用法，使用原型中的默认值，并在不同范围内重新定义函数以及使用个别默认值后，我们现在可以继续进行本章的最后一个主要主题：函数重载。

# 理解函数重载

C++允许两个或更多个函数共享相似的目的，但在它们所接受的参数类型或数量上有所不同，以相同的函数名称共存。这被称为**函数重载**。这允许进行更通用的函数调用，让编译器根据使用函数的变量（对象）的类型选择正确的函数版本。在本节中，我们将在函数重载的基础上添加默认值，以提供灵活性和定制。我们还将学习标准类型转换如何影响函数重载，以及可能出现的歧义（以及如何解决这些类型的不确定性）。

## 学习函数重载的基础知识

当存在两个或更多个同名函数时，这些相似函数之间的区别因素将是它们的签名。通过改变函数的签名，两个或更多个在同一命名空间中具有相同名称的函数可以存在。函数重载取决于函数的签名，如下所示：

+   **函数的签名**指的是函数的名称，以及其参数的类型和数量。

+   函数的返回类型不包括在其签名中。

+   两个或更多个具有相同目的的函数可以共享相同的名称，只要它们的签名不同。

函数的签名有助于为每个函数提供一个内部的“混淆”名称。这种编码方案保证每个函数在编译器内部都有唯一的表示。

让我们花几分钟来理解一个稍微复杂的示例，其中将包含函数重载。为了简化解释，这个示例被分成了三个部分；然而，完整的程序可以在以下链接中找到：

[`github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter02/Chp2-Ex6.cpp`](https://github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter02/Chp2-Ex6.cpp)

```cpp
#include <iostream>
#include <cmath>
using namespace std;
const float PI = 3.14159;
class Circle        // user defined type declarations
{
public:
   float radius;
   float area;
};
class Rectangle
{
public:
   float length;
   float width;
   float area;
};
void display(Circle);     // 'overloaded' function prototypes
void display(Rectangle);  // since they differ in signature
```

在这个例子的开头，注意我们用 `#include <cmath>` 包含了 math 库，以便访问基本的数学函数，比如 `pow()`。接下来，注意 `Circle` 和 `Rectangle` 的类定义，每个类都有相关的数据成员（`Circle` 的 `radius` 和 `area`；`Rectangle` 的 `length`、`width` 和 `area`）。一旦这些类型被定义，就会显示两个重载的显示函数的原型。由于这两个显示函数的原型使用了用户定义的类型 `Circle` 和 `Rectangle`，所以很重要的是 `Circle` 和 `Rectangle` 必须先被定义。现在，让我们继续查看 `main()` 函数的主体部分：

```cpp
int main()
{
    Circle myCircle;
    Rectangle myRect;
    Rectangle mySquare;
    myCircle.radius = 5.0;
    myCircle.area = PI * pow(myCircle.radius, 2.0);
    myRect.length = 2.0;
    myRect.width = 4.0;
    myRect.area = myRect.length * myRect.width;
    mySquare.length = 4.0;
    mySquare.width = 4.0;
    mySquare.area = mySquare.length * mySquare.width;
    display(myCircle);     // invoke: void display(Circle)
    display(myRect);       // invoke: void display(Rectangle)
    display(mySquare);
    return 0;
}
```

现在，在 `main()` 函数中，我们声明了一个 `Circle` 类型的变量和两个 `Rectangle` 类型的变量。然后我们使用适当的值在 `main()` 中使用点运算符 `.` 加载了每个变量的数据成员。接下来，在 `main()` 中，有三次对 `display()` 的调用。第一个函数调用 `display(myCircle)`，将调用以 `Circle` 作为形式参数的 `display()` 版本，因为传递给这个函数的实际参数实际上是用户定义的类型 `Circle`。接下来的两个函数调用 `display(myRect)` 和 `display(mySquare)`，将调用重载版本的 `display()`，因为这两个调用中传递的实际参数本身就是 `Rectangle`。让我们通过查看 `display()` 的两个函数定义来完成这个程序：

```cpp
void display (Circle c)
{
   cout << "Circle with radius " << c.radius;
   cout << " has an area of " << c.area << endl; 
}

void display (Rectangle r)
{
   cout << "Rectangle with length " << r.length;
   cout << " and width " << r.width;
   cout << " has an area of " << r.area << endl; 
}
```

请注意在这个示例的最后部分，定义了 `display()` 的两个版本。其中一个函数以 `Circle` 作为形式参数，重载版本以 `Rectangle` 作为形式参数。每个函数体访问特定于其形式参数类型的数据成员，但每个函数的整体功能都是相似的，因为在每种情况下都显示了一个特定的形状（`Circle` 或 `Rectangle`）。

让我们来看看这个完整程序示例的输出：

```cpp
Circle with radius 5 has an area of 78.5397
Rectangle with length 2 and width 4 has an area of 8
Rectangle with length 4 and width 4 has an area of 16
```

接下来，让我们通过理解标准类型转换如何允许一个函数被多个数据类型使用，来扩展我们对函数重载的讨论。这可以让函数重载更有选择性地使用。

## 通过标准类型转换消除过多的重载

编译器可以自动将基本语言类型从一种类型转换为另一种类型。这使得语言可以提供一个更小的操作符集来操作标准类型，而不需要更多的操作符。标准类型转换也可以消除函数重载的需要，当保留函数参数的确切数据类型不是至关重要的时候。标准类型之间的提升和降级通常是透明处理的，在包括赋值和操作的表达式中，不需要显式转换。

这是一个示例，说明了简单的标准类型转换。这个例子不包括函数重载。

[`github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter02/Chp2-Ex7.cpp`](https://github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter02/Chp2-Ex7.cpp)

```cpp
#include <iostream>
using namespace std; 
int maximum(double, double);      // function prototype

int main()
{
    int result;
    int m = 6, n = 10;
    float x = 5.7, y = 9.89;

    result =  maximum(x, y); 
    cout << "Result is: " << result << endl;
    cout << "The maximum is: " << maximum(m, n) << endl;
    return 0;
}
int maximum(double a, double b)  // function definition
{
    return (a > b)? a : b;
}
```

在这个例子中，`maximum()` 函数以两个双精度浮点数作为参数，并将结果作为 `int` 返回。首先，注意在程序的顶部附近原型化了 `int maximum(double, double);`，并且在同一个文件的底部定义了它。

现在，在`main（）`函数中，请注意我们定义了三个 int 变量：`result`，`a`和`x`。后两者分别初始化为`6`和`10`的值。我们还定义并初始化了两个浮点数：`float x = 5.7, y = 9.89;`。在第一次调用`maximum（）`函数时，我们使用`x`和`y`作为实际参数。这两个浮点数被提升为双精度浮点数，并且函数被按预期调用。

这是标准类型转换的一个例子。让我们注意`int maximum(double, double)`的返回值是一个整数 - 而不是双精度。这意味着从这个函数返回的值（形式参数`a`或`b`）将首先被截断为整数，然后作为返回值使用。这个返回值被整洁地赋给了`result`，它在`main（）`中被声明为`int`。这些都是标准类型转换的例子。

接下来，`maximum（）`被调用，实际参数为`m`和`n`。与前一个函数调用类似，整数`m`和`n`被提升为双精度，并且函数被按预期调用。返回值也将被截断为`int`，并且该值将作为整数传递给`cout`进行打印。

这个示例的输出是：

```cpp
Result is: 9
The maximum is: 10
```

现在我们了解了函数重载和标准类型转换的工作原理，让我们来看一个情况，其中两者结合可能会产生一个模棱两可的函数调用。

## 函数重载和类型转换引起的歧义

当调用函数时，形式和实际参数在类型上完全匹配时，不会出现关于应该调用哪个重载函数的歧义 - 具有完全匹配的函数是显而易见的选择。然而，当调用函数时，形式和实际参数在类型上不同时，可能需要对实际参数进行标准类型转换。然而，在形式和实际参数类型不匹配且存在重载函数的情况下，编译器可能难以选择哪个函数应该被选为最佳匹配。在这些情况下，编译器会生成一个错误，指示可用的选择与函数调用本身是模棱两可的。显式类型转换或在更局部的范围内重新原型化所需的选择可以帮助纠正这些否则模棱两可的情况。

让我们回顾一个简单的函数，说明函数重载、标准类型转换和潜在的歧义。

[`github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter02/Chp2-Ex8.cpp`](https://github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter02/Chp2-Ex8.cpp)

```cpp
#include <iostream>
using namespace std;
int maximum (int, int);     // overloaded function prototypes
float maximum (float, float); 
int main()
{
    char a = 'A', b = 'B';
    float x = 5.7, y = 9.89;
    int m = 6, n = 10;
    cout << "The max is: " << maximum(a, b) << endl;
    cout << "The max is: " << maximum(x, y) << endl;
    cout << "The max is: " << maximum(m, n) << endl;
    // The following (ambiguous) line generates a compiler 
    // error since there are two equally good fn. candidates 
    // cout << "The maximum is: " << maximum(a, y) << endl;
    // We can force a choice by using an explicit typecast
    cout << "The max is: " << maximum((float)a, y) << endl;
    return 0;
}
int maximum (int arg1, int arg2)        // function definition
{
    return (arg1 > arg2)? arg1 : arg2;
}
float maximum (float arg1, float arg2)  // overloaded function
{                                    
    return (arg1 > arg2)? arg1 : arg2;
}
```

在前面的简单示例中，`maximum（）`的两个版本都被原型化和定义。这些函数被重载；请注意它们的名称相同，但它们在使用的参数类型上不同。还要注意它们的返回类型不同；但是，由于返回类型不是函数签名的一部分，因此返回类型不需要匹配。

接下来，在`main（）`中，声明并初始化了两个`char`，`int`和`float`类型的变量。接下来，调用`maximum（a，b）`，两个`char`实际参数被转换为整数（使用它们的 ASCII 等价物）以匹配该函数的`maximum(int, int)`版本。这是与`a`和`b`的`char`参数类型最接近的匹配：`maximum(int, int)`与`maximum(float, float)`。然后，使用两个浮点数调用`maximum（x，y）`，这个调用将完全匹配该函数的`maximum(float, float)`版本。类似地，`maximum（m，n）`将被调用，并且将完全匹配该函数的`maximum(int, int)`版本。

现在，注意下一个函数调用（不巧的是，它被注释掉了）：`maximum(a, y)`。在这里，第一个实际参数完全匹配 `maximum(int, int)` 中的第一个参数，但第二个实际参数完全匹配 `maximum(float, float)` 中的第二个参数。对于不匹配的参数，可以应用类型转换——但没有！相反，编译器将此函数调用标记为模棱两可的函数调用，因为任何一个重载函数都可能是一个合适的匹配。

在代码行 `maximum((float) a, y)` 上，注意到对 `maximum((float) a, y)` 的函数调用强制对第一个实际参数 `a` 进行显式类型转换，解决了调用哪个重载函数的潜在歧义。现在，参数 `a` 被转换为 `float`，这个函数调用很容易匹配 `maximum(float, float)`，不再被视为模棱两可。类型转换可以是一个工具，用来消除这类疯狂情况的歧义。

以下是与我们示例配套的输出：

```cpp
The maximum is: 66
The maximum is: 9.89
The maximum is: 10
The maximum is: 65
```

# 总结

在本章中，我们学习了额外的非面向对象的 C++ 特性，这些特性是构建 C++ 面向对象特性所必需的基本组成部分。这些语言必需品包括使用 `const` 限定符，理解函数原型，使用原型中的默认值，函数重载，标准类型转换如何影响重载函数的选择，以及可能出现的歧义如何解决。

非常重要的是，您现在已经准备好进入下一章，我们将在其中详细探讨使用指针进行间接寻址。您在本章积累的事实技能将帮助您更轻松地导航每一个逐渐更详细的章节，以确保您准备好轻松应对从*第五章* 开始的面向对象概念，*详细探索类*。

请记住，C++ 是一种充满了比大多数其他语言更多灰色地带的语言。您积累的微妙细微之处将增强您作为 C++ 开发人员的价值——一个不仅可以导航和理解现有微妙代码的人，还可以创建易于维护的代码。

# 问题

1.  函数的签名是什么，函数的签名如何与 C++ 中的名称修饰相关联？您认为这如何促进编译器内部处理重载函数？

1.  编写一个小的 C++ 程序，提示用户输入有关 `学生` 的信息，并打印出数据。

a. `学生` 信息应至少包括名字、姓氏、GPA 和 `学生` 注册的当前课程。这些信息可以存储在一个简单的类中。您可以利用数组来表示字符串字段，因为我们还没有涉及指针。此外，您可以在主函数中读取这些信息，而不是创建一个单独的函数来读取数据（因为后者需要指针或引用的知识）。请不要使用全局（即 extern 变量）。

b. 创建一个函数来打印 `学生` 的所有数据。记得对这个函数进行原型声明。在这个函数的原型中，使用默认值 4.0 作为 GPA。以两种方式调用这个函数：一次显式传入每个参数，一次使用默认的 GPA。

c. 现在，重载 `Print` 函数，其中一个打印出选定的数据（即姓氏和 GPA），或者使用接受 `Student` 作为参数的版本的函数（但不是 `Student` 的指针或引用——我们稍后会做）。记得对这个函数进行原型声明。

d. 使用 iostream 进行 I/O。


# 第三章：间接寻址：指针

本章将全面介绍如何在 C++中利用指针。虽然假定您具有一些间接寻址的先前经验，但我们将从头开始。指针是语言中的一个基本和普遍的特性 - 您必须彻底理解并能够轻松地利用它。许多其他语言仅通过引用使用间接寻址，然而，在 C++中，您必须动手理解如何正确有效地使用和返回堆内存。您将看到其他程序员在代码中大量使用指针；无法忽视它们的使用。错误使用指针可能是程序中最难找到的错误。在 C++中，彻底理解使用指针进行间接寻址是创建成功和可维护代码的必要条件。

本章的目标是建立或增强您对使用指针进行间接寻址的理解，以便您可以轻松理解和修改他人的代码，以及能够自己编写原始、复杂、无错误的 C++代码。

在本章中，我们将涵盖以下主要主题：

+   指针基础知识，包括访问、内存分配和释放 - 适用于标准和用户定义类型

+   动态分配`1`、`2`、`N`维数组，并管理它们的内存释放

+   指针作为函数的参数和从函数返回的值

+   向指针变量添加`const`限定符

+   使用 void 指针 - 指向未指定类型的对象的指针

通过本章结束时，您将了解如何使用`new()`从堆中分配内存，用于简单和复杂的数据类型，以及如何使用`delete()`标记内存以返回给堆管理设施。您将能够动态分配任何数据类型和任意维数的数组，并且了解释放内存的基本内存管理，以避免在应用程序中不再需要时发生内存泄漏。您将能够将指针作为参数传递给具有任何间接级别的函数 - 即，指向数据的指针，指向指向数据的指针，依此类推。您将了解如何以及为什么将`const`限定符与指针结合使用 - 对数据、对指针本身，或对两者都是。最后，您将了解如何声明和使用没有类型的通用指针 - void 指针 - 并了解它们可能证明有用的情况。这些技能将是成功地继续阅读本书后续章节所必需的。

# 技术要求

完整程序示例的在线代码可以在以下 GitHub 网址找到：[`github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter03`](https://github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter03)。每个完整程序示例都可以在 GitHub 存储库中找到，位于相应章节标题（子目录）下的文件中，文件名与所在章节编号相对应，后跟该章节中的示例编号。例如，本章的第一个完整程序可以在子目录`Chapter03`中的名为`Chp3-Ex1.cpp`的文件中找到，位于上述 GitHub 目录下。

本章的 CiA 视频可在以下网址观看：[`bit.ly/2OY41sn`](https://bit.ly/2OY41sn)

# 理解指针基础知识和内存分配

在本节中，我们将回顾指针的基础知识，并介绍适用于指针的运算符，如取地址运算符、解引用运算符以及`new()`和`delete()`运算符。我们将使用取地址运算符`&`来计算现有变量的地址，反之，我们将应用解引用运算符`*`到指针变量，以访问变量中包含的地址。我们将看到堆上的内存分配示例，以及如何在完成后将同一内存标记为可重新使用，将其返回到空闲列表。

使用指针变量使我们的应用程序具有更大的灵活性。在运行时，我们可以确定可能需要的某种数据类型的数量（例如在动态分配的数组中），在数据结构中组织数据以便进行排序（例如在链表中），或者通过将大块数据的地址传递给函数来提高速度（而不是传递整个数据块的副本）。指针有许多用途，我们将在本章和整个课程中看到许多示例。让我们从指针的基础知识开始。

## 重新审视指针的基础知识

首先，让我们回顾一下指针变量的含义。指针变量可能包含一个地址，而在该地址可能包含相关数据。通常说指针变量“指向”包含相关数据的地址。指针变量本身的值是一个地址，而不是我们要找的数据。当我们去到那个地址时，我们找到感兴趣的数据。这被称为间接寻址。总之，指针变量的内容是一个地址；如果你去到那个地址，你会找到数据。这是单级间接寻址。

指针变量可以指向非指针变量的现有内存，也可以指向在堆上动态分配的内存。后一种情况是最常见的情况。除非指针变量被正确初始化或分配一个值，否则指针变量的内容是没有意义的，也不代表可用的地址。一个常见的错误是假设指针变量已经被正确初始化，而实际上可能并没有。让我们看一些与指针有用的基本运算符。我们将从取地址`&`和解引用运算符`*`开始。

## 使用取地址和解引用运算符

取地址运算符`&`可以应用于变量，以确定其在内存中的位置。解引用运算符`*`可以应用于指针变量，以获取指针变量中包含的有效地址处的数据值。

让我们看一个简单的例子：

```cpp
int x = 10;
int *pointerToX;   // pointer variable which may someday
                   // point to an integer
pointerToX = &x;  // assign memory location of x to pointerToX
cout << "x is " << x << " and *pointerToX is " << *pointerToX;
```

请注意，在前面的代码片段中，我们首先声明并初始化变量`x`为`10`。接下来，我们声明`int *pointerToX;`来说明变量`pointerToX`可能有一天会指向一个整数。在这个声明时，这个指针变量是未初始化的，因此不包含有效的内存地址。

在代码中继续到`pointerToX = &x;`这一行，我们使用取地址运算符（`&`）将`x`的内存位置分配给`pointerToX`，它正在等待用某个整数的有效地址填充。在这段代码片段的最后一行，我们打印出`x`和`*pointerToX`。在这里，我们使用变量`pointerToX`的解引用运算符`*`。解引用运算符告诉我们去到变量`pointerToX`中包含的地址。在那个地址，我们找到整数`10`的数据值。

以下是这个片段作为完整程序将生成的输出：

```cpp
x is 10 and *pointerToX is 10
```

重要提示

为了效率，C++ 在应用程序启动时不会将所有内存清零初始化，也不会确保内存与变量配对时方便地为空，没有值。内存中只是存储了先前存储在那里的内容；C++ 内存不被认为是 *干净* 的。因为在 C++ 中内存不是 *干净* 的，所以除非正确初始化或分配一个值，否则新声明的指针变量的内容不应被解释为包含有效地址。

在前面的例子中，我们使用取地址操作符 `&` 来计算内存中现有整数的地址，并将我们的指针变量设置为指向该内存。相反，让我们引入 `new()` 和 `delete()` 操作符，以便我们可以利用动态分配的堆内存来使用指针变量。

## 使用 `new()` 和 `delete()` 操作符

`new()` 操作符可以用来从堆中获取动态分配的内存。指针变量可以选择指向在运行时动态分配的内存，而不是指向另一个变量的现有内存。这使我们可以灵活地决定何时分配内存，以及我们可以选择拥有多少块这样的内存。然后，`delete()` 操作符可以应用于指针变量，标记我们不再需要的内存，并将内存返回给堆管理设施以供应用程序以后重用。重要的是要理解，一旦我们 `delete()` 一个指针变量，我们不应再使用该变量中包含的地址作为有效地址。

让我们来看一个简单的数据类型的内存分配和释放：

```cpp
int *y;    // y is a pointer which may someday point to an int
y = new int;  // y points to memory allocated on the heap
*y = 17;   // dereference y to load the newly allocated memory
           // with a value of 17
cout << "*y is: " << *y << endl;
delete y;  // relinquish the allocated memory
```

在前面的程序段中，我们首先声明指针变量 `y` 为 `int *y;`。在这里，`y` 可能会包含一个整数的地址。在下一行，我们从堆中分配了足够容纳一个整数的内存，使用 `y = new int;` 将该地址存储在指针变量 `y` 中。接下来，使用 `*y = 17;` 我们对 `y` 进行解引用，并将值 `17` 存储在 `y` 指向的内存位置。在打印出 `*y` 的值后，我们决定我们已经完成了 `y` 指向的内存，并通过使用 `delete()` 操作符将其返回给堆管理设施。重要的是要注意，变量 `y` 仍然包含它通过调用 `new()` 获得的内存地址，但是，`y` 不应再使用这个放弃的内存。

重要提示

程序员有责任记住，一旦内存被释放，就不应再次对该指针变量进行解引用；请理解该地址可能已经通过程序中的另一个 `new()` 调用重新分配给另一个变量。

现在我们了解了简单数据类型的指针基础知识，让我们继续通过分配更复杂的数据类型，并理解必要的符号来使用和访问用户定义的数据类型的成员。

## 创建和使用指向用户定义类型的指针

接下来，让我们来看看如何声明指向用户定义类型的指针，以及如何在堆上分配它们的关联内存。要动态分配用户定义类型，指针首先必须声明为该类型。然后，指针必须初始化或分配一个有效的内存地址 - 内存可以是现有变量的内存，也可以是新分配的堆内存。一旦适当内存的地址被放入指针变量中，`->` 操作符可以用来访问结构体或类的成员。另外，`(*ptr).member` 符号也可以用来访问结构体或类的成员。

让我们看一个基本的例子：

[`github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter03/Chp3-Ex1.cpp`](https://github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter03/Chp3-Ex1.cpp)

```cpp
include <iostream>
using namespace std;
struct collection
{
    int x;
    float y;
};

int main()  
{
    collection *item;      // pointer declaration 
    item = new collection; // memory allocation 
    item->x = 9;        // use -> to access data member x
    (*item).y = 120.77; // alt. notation to access member y
    cout << (*item).x << " " << item->y << endl;
    delete item;           // relinquish memory
    return 0;
}
```

首先，在上述程序中，我们声明了一个名为`collection`的用户定义类型，其中包含数据成员`x`和`y`。接下来，我们用`collection *item;`声明`item`作为指向该类型的指针。然后，我们为`item`分配堆内存，使用`new()`运算符指向。现在，我们分别为`item`的`x`和`y`成员赋值，使用`->`运算符或`(*).member`访问表示法。在任一情况下，表示法意味着首先取消引用指针，然后选择适当的数据成员。使用`(*).`表示法非常简单-括号告诉我们指针解除引用首先发生，然后使用`.`（成员选择运算符）选择成员。`->`简写表示指针解除引用后选择成员。在我们使用`cout`和插入运算符`<<`打印适当的值后，我们决定不再需要与`item`相关的内存，并发出`delete item;`来标记此段堆内存以返回到空闲列表。

让我们来看一下这个例子的输出：

```cpp
9 120.77
```

让我们也来看一下这个例子的内存布局。使用的内存地址（9000）是任意的-只是一个可能由`new()`生成的示例地址。

![图 3.1-Chp3-Ex1.cpp 的内存模型](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/dmst-oop-cpp/img/B15702_03_01.jpg)

图 3.1-Chp3-Ex1.cpp 的内存模型

现在我们知道如何为用户定义的类型分配和释放内存，让我们继续动态分配任何数据类型的数组。

# 在运行时分配和释放数组

数组可以动态分配，以便在运行时确定其大小。动态分配的数组可以是任何类型，包括用户定义的类型。在运行时确定数组大小可以节省空间，并为我们提供编程灵活性。您可以根据运行时的各种因素分配所需的大小，而不是分配可能浪费空间的最大可能数量的固定大小数组。您还可以在需要更改数组大小时删除和重新分配数组。可以动态分配任意维数的数组。

在本节中，我们将研究如何动态分配基本数据类型和用户定义数据类型的数组，以及单维和多维数组。让我们开始吧。

## 动态分配单维数组

单维数组可以动态分配，以便在运行时确定其大小。我们将使用指针来表示每个数组，并将使用`new()`运算符分配所需的内存。一旦数组被分配，可以使用标准数组表示法来访问每个数组元素。

让我们来看一个简单的例子。我们将把它分成两个部分，但是完整的程序示例可以在下面的链接中找到：

[`github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter03/Chp3-Ex2.cpp`](https://github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter03/Chp3-Ex2.cpp)

```cpp
#include <iostream>
using namespace std;
struct collection
{
    int x;
    float y;
};

int main()
{
    int numElements;
    int *intArray;                // pointer declarations 
    collection *collectionArray;  // to eventual arrays
    cout << "How many elements would you like? " << flush;
    cin >> numElements;
    intArray = new int[numElements]; // allocate array bodies
    collectionArray = new collection[numElements];
    // continued …
```

在程序的第一部分中，我们首先声明了一个使用结构体的用户定义类型`collection`。接下来，我们声明一个整数变量来保存我们希望提示用户输入以选择作为两个数组大小的元素数量。我们还声明一个指向整数的指针`int *intArray;`和一个指向`collection`的指针`collection *collectionArray;`。这些声明表明这些指针有一天可能分别指向一个或多个整数，或一个或多个`collection`类型的对象。一旦分配，这些变量将组成我们的两个数组。

提示用户使用`cin`和提取运算符`>>`输入所需元素的数量后，我们动态分配了一个整数数组和一个相同大小的集合数组。我们在两种情况下都使用了`new()`运算符：`intArray = new int[numElements];`和`collectionArray = new collection[numElements];`。括号中的`numElements`表示为每种数据类型请求的内存块将足够大，以容纳相应数据类型的这么多个连续元素。也就是说，`intArray`将分配内存以容纳`numElements`乘以整数所需的大小。注意，对象的数据类型是已知的，因为指针声明本身包含了将要指向的数据类型。对于`collectionArray`，将以类似的方式提供适当数量的内存。

让我们继续检查这个示例程序中的剩余代码：

```cpp
    // load each array with values
    for (int i 0; i < numElements; i++)
    {
        intArray[i] = i;           // load each array w values
        collectionArray[i].x = i;  // using array notation []
        collectionArray[i].y = i + .5;
        // alternatively use ptr notation to print two values
        cout << *(intArray + i) << " ";
        cout << (*(collectionArray + i)).y << endl;
    }
    delete intArray;     // mark memory for deletion
    delete [] collectionArray;
    return 0;
}
```

接下来，当我们继续使用`for`循环来进行这个示例时，请注意，我们使用了典型的`[]`数组表示法来访问两个数组的每个元素，即使这些数组已经被动态分配。因为`collectionArray`是一个动态分配的用户定义类型数组，我们必须使用`.`符号来访问每个数组元素内的单个数据成员。虽然使用标准数组表示法使得访问动态数组非常简单，但您也可以使用指针表示法来访问内存。

在循环中，请注意我们逐渐打印`intArray`的元素和`collectionArray`的`y`成员，使用指针表示法。在表达式`*(intArray +i)`中，标识符`intArray`表示数组的起始地址。通过向该地址添加`i`偏移量，现在您位于该数组中第`i`个元素的地址。通过使用`*`对这个复合地址进行解引用，您现在将转到正确的地址以检索相关的整数数据，然后使用`cout`和插入运算符`<<`进行打印。同样，在`(*(collectionArray + i)).y`中，我们首先将`i`添加到`collectionArray`的起始地址，然后使用`()`对该地址进行解引用。由于这是一个用户定义的类型，我们必须使用`.`来选择适当的数据成员`y`。

最后，在这个示例中，我们演示了如何使用`delete()`释放我们不再需要的内存。对于动态分配的标准类型数组，简单的`delete intArray;`语句就足够了，而对于用户定义类型的数组，需要更复杂的`delete [] collectionArray;`语句才能正确删除。在两种情况下，与每个动态分配的数组相关联的内存将返回到空闲列表中，并且可以在后续调用`new()`运算符分配堆内存时重新使用。在指针变量的内存被标记为删除后，记住不要对指针变量进行解引用是至关重要的。尽管该地址将保留在指针变量中，直到您为指针分配新地址（或空指针），但一旦内存被标记为删除，该内存可能已经被程序中其他地方对`new()`的后续调用重用。这是在 C++中使用指针时必须要谨慎的许多方式之一。

完整程序示例的输出如下：

```cpp
How many elements would you like? 3
0 0.5
1 1.5
2 2.5
```

让我们进一步看一下这个示例的内存布局。使用的内存地址（8500 和 9500）是任意的 - 它们是堆上可能由`new()`生成的示例地址。

![图 3.2 - Chp3-Ex2.cpp 的内存模型](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/dmst-oop-cpp/img/B15702_03_02.png)

图 3.2 - Chp3-Ex2.cpp 的内存模型

接下来，让我们继续讨论通过分配多维数组来动态分配数组。

## 动态分配 2-D 数组：指针数组

二维或更高维的数组也可以动态分配。对于 2-D 数组，列维度可以动态分配，而行维度可以保持固定，或者两个维度都可以动态分配。动态分配一个或多个维度允许程序员考虑数组大小的运行时决策。

首先考虑一种情况，即我们有固定数量的行，以及每行中可变数量的条目（即列维度）。为简单起见，我们假设每行中的条目数量从一行到另一行是相同的，但实际上并非如此。我们可以使用指针数组来模拟具有固定行数和运行时确定的每行中的条目数量（列维度）的二维数组。

让我们考虑一个例子来说明动态分配列维度的二维数组。

[`github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter03/Chp3-Ex3.cpp`](https://github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter03/Chp3-Ex3.cpp)

```cpp
#include <iostream>
using namespace std;
const int NUMROWS = 5;
int main()
{
    float *TwoDimArray[NUMROWS];  // array of pointers
    int numColumns;
    cout << "Enter number of columns: ";
    cin >> numColumns;
    for (int i = 0; i < NUMROWS; i++)
    {
        // allocate column quantity for each row
        TwoDimArray[i] = new float [numColumns];
        // load each column entry with data
        for (int j = 0; j < numColumns; j++)
        {
            TwoDimArray[i][j] = i + j + .05;
            cout << TwoDimArray[i][j] << " ";
        }
        cout << endl;  // print newline between rows
    }
    for (int i = 0; i < NUMROWS; i++)
        delete TwoDimArray[i];  // delete column for each row
    return 0;
}
```

在这个例子中，请注意我们最初使用`float *TwoDimArray[NUMROWS];`声明了一个指向浮点数的指针数组。有时，从右向左阅读指针声明是有帮助的；也就是说，我们有一个包含指向浮点数的指针的数组`NUMROWS`。更具体地说，我们有一个固定大小的指针数组，其中每个指针条目可以指向一个或多个连续的浮点数。每行指向的条目数量构成了列维度。

接下来，我们提示用户输入列条目的数量。在这里，我们假设每行将有相同数量的条目（以形成列维度），但是可能每行的总条目数量是不同的。通过假设每行将有统一数量的条目，我们可以使用`i`来简单地循环分配每行的列数量，使用`TwoDimArray[i] = new float [numColumns];`。

在使用`j`作为索引的嵌套循环中，我们简单地为外部循环指定的行的每个列条目加载值。任意赋值`TwoDimArray[i][j] = i + j + .05;`将一个有趣的值加载到每个元素中。在以`j`为索引的嵌套循环中，我们还打印出每行`i`的每个列条目。

最后，该程序说明了如何释放动态分配的内存。由于内存是在固定数量的行上循环分配的 - 为了收集组成每行列条目的内存而进行的一次内存分配 - 因此释放工作方式类似。对于每一行，我们使用语句`delete TwoDimArray[i];`。

示例的输出如下：

```cpp
Enter number of columns: 3
0.05 1.05 2.05
1.05 2.05 3.05
2.05 3.05 4.05
3.05 4.05 5.05
4.05 5.05 6.05
```

接下来，让我们来看一下这个例子的内存布局。与以前的内存图一样，所使用的内存地址是任意的 - 它们是堆上的示例地址，可能由`new()`生成。

![图 3.3 - Chp3-Ex3.cpp 的内存模型](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/dmst-oop-cpp/img/B15702_03_03.jpg)

图 3.3 - Chp3-Ex3.cpp 的内存模型

现在我们已经看到如何利用指针数组来模拟二维数组，让我们继续看看如何使用指向指针的指针来模拟二维数组，以便我们可以在运行时选择两个维度。

## 动态分配 2-D 数组：指向指针的指针

为数组动态分配行和列维度可以为程序添加必要的运行时灵活性。为了实现这种最终的灵活性，可以使用所需数据类型的指针来模拟一个 2-D 数组。最初，表示行数的维度将被分配。接下来，对于每一行，将分配每行中的元素数量。与上一个示例中使用指针数组一样，每行中的元素数量（列条目）不需要在行之间的大小上是一致的。然而，为了准确地模拟 2-D 数组的概念，假定列的大小将从一行到另一行均匀分配。

让我们考虑一个例子来说明一个动态分配了行和列维度的 2-D 数组。

[`github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter03/Chp3-Ex4.cpp`](https://github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter03/Chp3-Ex4.cpp)

```cpp
#include <iostream>
using namespace std;
int main()
{
    int numRows, numColumns;
    float **TwoDimArray;    // pointer to a pointer
    cout << "Enter number of rows: " << flush;
    cin >> numRows;
    TwoDimArray = new float * [numRows];  // allocate row ptrs
    cout << "Enter number of Columns: ";
    cin >> numColumns;
    for (int i = 0; i < numRows; i++)
    {
        // allocate column quantity for each row
        TwoDimArray[i] = new float [numColumns];
        // load each column entry with data
        for (int j = 0; j < numColumns; j++)
        {
            TwoDimArray[i][j] = i + j + .05;
            cout << TwoDimArray[i][j] << " ";
        }
        cout << end;  // print newline between rows
    }
    for (i = 0; i < numRows; i++)
        delete TwoDimArray[i];  // delete columns for each row
    delete TwoDimArray;  // delete allocated rows
    return 0;
}
```

在这个例子中，注意我们最初声明了一个指向`float`类型的指针的指针，使用`float **TwoDimArray;`。从右向左阅读这个声明，我们有`TwoDimArray`是指向`float`的指针的指针。更具体地说，我们理解`TwoDimArray`将包含一个或多个连续指针的地址，每个指针可能指向一个或多个连续的浮点数。

现在，我们提示用户输入行条目的数量。我们在这个输入之后分配给一组`float`指针，`TwoDimArray = new float * [numRows];`。这个分配创建了`numRows`数量的`float`指针。

就像在上一个示例中一样，我们提示用户希望每行有多少列。就像以前一样，在以`i`为索引的外部循环中，我们为每行分配列条目。在以`j`为索引的嵌套循环中，我们再次为数组条目赋值并打印它们，就像以前一样。

最后，程序继续进行内存释放。与之前一样，每行的列条目在循环内被释放。然而，此外，我们需要释放动态分配的行条目数量。我们使用`delete TwoDimArray;`来做到这一点。

该程序的输出稍微灵活一些，因为我们可以在运行时输入所需行和列的数量：

```cpp
Enter number of rows: 3
Enter number of columns: 4
0.05 1.05 2.05 3.05
1.05 2.05 3.05 4.05
2.05 3.05 4.05 5.05
```

让我们再次看一下这个程序的内存模型。作为提醒，就像以前的内存图一样，使用的内存地址是任意的 - 它们是堆上可能由`new()`生成的示例地址。

![图 3.4 – Chp3-Ex4.cpp 的内存模型](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/dmst-oop-cpp/img/B15702_03_04.jpg)

图 3.4 – Chp3-Ex4.cpp 的内存模型

现在我们已经看到了如何利用指向指针来模拟 2-D 数组，让我们继续看看如何使用指向指针的指针来模拟任意维度的数组，等等。在 C++中，只要你能想象得到，就可以模拟任意维度的动态分配数组！

## 动态分配 N-D 数组：指向指针的指针

在 C++中，你可以模拟任意维度的动态分配数组。你只需要能够想象它，声明适当级别的指针，并进行所需级别的内存分配（和最终的释放）。

让我们来看一下你需要遵循的模式：

[`github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter03/Chp3-Ex5.cpp`](https://github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter03/Chp3-Ex5.cpp)

```cpp
int main()
{
    int dim1, dim1, dim3;
    int ***ThreeDimArray;   // 3-D dynamically allocated array
    cout << "Enter dim 1, dim 2, dim 3: ";
    cin >> dim1 >> dim2 >> dim3;
    ThreeDimArray = new int ** [dim1]; // allocate dim 1
    for (int i = 0; i < dim1; i++)
    {
        ThreeDimArray[i] = new int * [dim2]; // allocate dim 2
        for (int j = 0; j < dim2; j++)
        {
            // allocate dim 3
            ThreeDimArray[i][j] = new int [dim3];
            for (int k = 0; k < dim3; k++)
            {
               ThreeDimArray[i][j][k] = i + j + k; 
               cout << ThreeDimArray[i][j][k] << " ";
            }
            cout << endl;  // print newline between dimensions
        }
        cout << end;  // print newline between dimensions
    }
    for (int i = 0; i < dim1; i++)
    {
        for (int j = 0; j < dim2; j++)
           delete ThreeDimArray[i][j]; // release dim 3
        delete ThreeDimArray[i];  // release dim 2
    }
    delete ThreeDimArray;   // release dim 1
    return 0;
}
```

在这个例子中，请注意我们使用三级间接来指定表示 3-D 数组的变量`int ***ThreeDimArray;`。然后我们为每个间接分配所需的内存。第一个分配是`ThreeDimArray = new int ** [dim1];`，它分配了维度 1 的指针到指针。接下来，在一个循环中迭代`i`，对于维度 1 中的每个元素，我们分配`ThreeDimArray[i] = new int * [dim2];`来为数组的第二维度分配整数指针。在一个嵌套循环中迭代`j`，对于第二维度中的每个元素，我们分配`ThreeDimArray[i][j] = new int [dim3];`来分配由`dim3`指定的整数本身的数量。

与前两个例子一样，我们在内部循环中初始化数组元素并打印它们的值。此时，您无疑会注意到这个程序与其前身之间的相似之处。一个分配的模式正在出现。

最后，我们将以与分配级别相反的方式释放三个级别的内存。我们使用一个嵌套循环来迭代`j`来释放最内层级别的内存，然后在外部循环中迭代`i`来释放内存。最后，我们通过简单调用`delete ThreeDimArray;`来放弃初始维度的内存。

这个例子的输出如下：

```cpp
Enter dim1, dim2, dim3: 2 4 3
0 1 2
1 2 3
2 3 4
3 4 5
1 2 3
2 3 4
3 4 5
4 5 6
```

现在我们已经看到了如何使用指针来模拟 3-D 数组，一个模式已经出现，向我们展示了如何声明所需级别和数量的指针来模拟 N-D 数组。我们还可以看到必要分配的模式。多维数组可能会变得非常大，特别是如果你被迫使用最大潜在必要的固定大小数组来模拟它们。使用指针来模拟必要的多维数组的每个级别，可以精确地分配可能在运行时确定的大小。为了方便使用，可以使用`[]`的数组表示法作为指针表示法的替代，以访问动态分配的数组中的元素。C++具有许多源自指针的灵活性。动态分配的数组展示了这种灵活性之一。

现在让我们继续深入了解指针，并考虑它们在函数中的使用。

# 在函数中使用指针

C++中的函数无疑会带有参数。我们在前几章中看到了许多例子，说明了函数原型和函数定义。现在，让我们通过将指针作为参数传递给函数，并将指针用作函数的返回值来增进我们对函数的理解。

## 将指针作为函数参数传递

在函数调用中，从实际参数到形式参数传递的参数默认上是在堆栈上复制的。为了修改作为函数参数的变量的内容，必须使用该参数的指针作为函数参数。

在 C++中，任何时候实际参数被传递给函数，都会在堆栈上复制一份内容并传递给该函数。例如，如果将整数作为实际参数传递给函数，将复制该整数并将其传递到堆栈上，以便在函数中接收为形式参数。在函数范围内更改形式参数只会更改传递到函数中的数据的副本。

如果我们需要修改函数的参数，那么有必要将所需数据的指针作为函数的参数传递。在 C++中，将指针作为实际参数传递会在堆栈上复制该地址，并且该地址的副本将作为形式参数接收到函数中。然而，使用地址的副本，我们仍然可以访问所需的数据并对其进行更改。

重申一下，在 C++中，当你传递参数时，总是在堆栈上复制某些东西。如果你传递一个非指针变量，你会得到一个在堆栈上传递给函数的数据副本。在该函数的范围内对该数据所做的更改只是局部的，当函数返回时不会持续。局部副本在函数结束时会被简单地从堆栈中弹出。然而，如果你将指针传递给函数，尽管指针变量中存储的地址仍然被复制到堆栈上并传递给函数，你仍然可以解引用指针的副本来访问所需地址处的真实数据。

你总是需要比你想修改的东西多一步。如果你想改变一个标准数据类型，传递一个指向该类型的指针。如果你想改变指针本身（地址）的值，你必须将指向该指针的指针作为函数的参数传递。记住，在堆栈上将某物的副本传递给函数。你不能在函数的范围之外改变那个副本。传递你想要改变的地址 - 你仍然传递那个地址的副本，但使用它将让你访问真正的数据。

让我们花几分钟来理解一个例子，说明将指针作为函数参数传递。在这里，我们将首先检查两个函数，它们构成以下完整程序示例的一部分。

[`github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter03/Chp3-Ex6.cpp`](https://github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter03/Chp3-Ex6.cpp)

```cpp
void TryToAddOne(int arg)
{
   arg++;
}
void AddOne(int *arg)
{
   (*arg)++;
}
```

在上面的函数中，请注意`TryToAddOne()`以`int`作为形式参数，而`AddOne()`以`int *`作为形式参数。

在`TryToAddOne()`中，传递给函数的整数只是实际参数的副本。这个参数在形式参数列表中被称为`arg`。在函数体中将`arg`的值增加一是`TryToAddOne()`内部的局部改变。一旦函数完成，形式参数`arg`将从堆栈中弹出，并且调用该函数时的实际参数将不会被修改。

然而，请注意`AddOne()`以`int *`作为形式参数。实际整数参数的地址将被复制到堆栈上，并作为形式参数`arg`接收。使用该地址的副本，我们使用`*`来解引用指针`arg`，然后在代码行`(*arg)++;`中递增该地址处的整数值。当这个函数完成时，实际参数将被修改，因为我们传递了指向该整数的指针的副本，而不是整数本身的副本。

让我们检查这个程序的其余部分：

```cpp
#include <iostream>
using namespace std;
void TryToAddOne(int); // function prototypes
void AddOne(int *);
int main()
{
   int x = 10, *y;
   y = new int;    // allocate y's memory
   *y = 15;        // dereference y to assign a value
   cout << "x: " << x << " and *y: " << *y << endl;
   TryToAddOne(x);   // unsuccessful, call by value
   TryToAddOne(*y);  // still unsuccessful
   cout << "x: " << x << " and *y: " << *y << endl;
   AddOne(&x);   // successful, passing an address 
   AddOne(y);    // also successful
   cout << "x: " << x << " and *y: " << *y << endl;
   return 0;
}
```

注意程序段顶部的函数原型。它们将与前一段代码中的函数定义相匹配。现在，在`main()`函数中，我们声明并初始化`int x = 10;`，并声明一个指针：`int *y;`。我们使用`new()`为`y`分配内存，然后通过解引用指针`*y = 15;`来赋值。我们打印出`x`和`*y`的各自值作为基线。

接下来，我们调用`TryToAddOne(x);`，然后是`TryToAddOne(*y);`。在这两种情况下，我们都将整数作为实际参数传递给函数。变量`x`被声明为整数，`*y`指的是`y`指向的整数。这两个函数调用都不会导致实际参数被更改，我们可以通过使用`cout`和插入运算符`<<`打印它们的值来验证。

最后，我们调用`AddOne(&x);`，然后是`AddOne(y);`。在这两种情况下，我们都将一个地址的副本作为实际参数传递给函数。当然，`&x`是变量`x`的地址，所以这样可以。同样，`y`本身就是一个地址 - 它被声明为指针变量。回想一下，在`AddOne()`函数内部，形式参数首先被解引用，然后在函数体中递增`(*arg)++;`。我们可以使用指针的副本来访问实际数据。

以下是完整程序示例的输出：

```cpp
x: 10 and *y: 15
x: 10 and *y: 15
x: 11 and *y: 16
```

接下来，让我们通过使用指针作为函数的返回值来扩展我们对使用指针与函数的讨论。

## 使用指针作为函数的返回值

函数可以通过它们的返回语句返回指向数据的指针。当通过函数的返回语句返回指针时，确保指向的内存在函数调用完成后仍然存在。不要返回指向函数内部局部栈内存的指针。也就是说，不要返回在函数内部定义的局部变量的指针。然而，有时返回指向在函数内部使用`new()`分配的内存的指针是可以接受的。由于分配的内存将位于堆上，它将存在于函数调用之后。

让我们看一个例子来说明这些概念：

[`github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter03/Chp3-Ex7.cpp`](https://github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter03/Chp3-Ex7.cpp)

```cpp
#include <iostream>
#include <iomanip>
using namespace std; 
const int MAX = 20;
char *createName();  // function prototype
int main()    
{
   char *name;   // pointer declaration
   name = createName();  // function will allocate memory
   cout << "Name: " << name << endl;
   delete name;  // delete allocated memory
   return 0;
}
char *createName()
{
   char *temp = new char[MAX];
   cout << "Enter name: " << flush;
   cin >> setw(MAX) >> temp; 
   return temp;
}
```

在这个例子中，`const int MAX = 20;`被定义，然后`char *createName();`被原型化，表明这个函数不带参数，但返回一个或多个字符的指针。

在`main()`函数中，定义了一个局部变量：`char *name;`，但没有初始化。接下来，调用`createName()`，并将其返回值用于赋值给`name`。注意`name`和函数的返回类型都是`char *`类型。

在调用`createName()`时，注意到一个局部变量`char *temp = new char[MAX];`被定义并分配到堆上的固定内存量，使用`new()`操作符。然后提示用户输入一个名称，并将该名称存储在`temp`中。然后从`createName()`返回局部变量`temp`。

在`createName()`中，很重要的是`temp`的内存由堆内存组成，以便它在函数的范围之外存在。在这里，存储在`temp`中的地址的副本将被复制到堆栈中为函数的返回值保留的区域。幸运的是，该地址指向堆内存。在`main()`中的赋值`name = createName();`将捕获这个地址，并将其复制存储到`name`变量中，该变量是`main()`中的局部变量。由于在`createName()`中分配的内存位于堆上，所以一旦函数完成，这个内存将存在。

同样重要的是，如果在`createName()`中定义`char temp[MAX];`，那么组成`temp`的内存将存在于堆栈上，并且将局限于`createName()`。一旦`createName()`返回到`main`，这个变量的内存将从堆栈中弹出，并且将无法正确使用 - 即使该地址已经在`main()`中的指针变量中被捕获。这是 C++中另一个潜在的指针陷阱。当从函数返回指针时，始终确保指针指向的内存存在于函数的范围之外。

这个例子的输出是：

```cpp
Enter name: Gabrielle
Name: Gabrielle
```

现在我们了解了指针如何在函数的参数中使用以及作为函数的返回值，让我们继续通过进一步研究指针的微妙之处。

# 使用指针的 const 限定符

`const`限定符可以以几种不同的方式用于限定指针。关键字`const`可以应用于指向的数据，指针本身，或两者都可以。通过以这种多种方式使用`const`限定符，C++提供了保护程序中可能被初始化但永远不会再次修改的值的手段。让我们检查每种不同的情况。我们还将结合`const`限定指针与函数返回值，以了解哪些情况是合理实现的。

## 使用指向常量对象的指针

可以指定指向常量对象的指针，以便不能直接修改指向的对象。对这个对象进行解引用后，不能将其用作任何赋值中的 l 值。l 值表示可以修改的值，并且出现在赋值的左侧。

让我们举一个简单的例子来理解这种情况：

```cpp
// const qualified strings; the data pointed to will be const
const char *constData = "constant"; 
const char *moreConstData;  
// regular strings, defined. One is loaded using strcpy()  
char *regularString;
char *anotherRegularString = new char[8];
strcpy(anotherRegularString, "regular"); 
// Trying to modify data marked as const will not work
// strcpy(constData, "Can I do this? ");  // NO! 
// Trying to circumvent by having a char * point to
// a const char * also will not work
// regularString = constData; // NO! 
// But we can treat a char * more strictly by assigning it to
// a const char *. It will be const from that viewpoint only
moreConstData = anotherRegularString; // Yes, I can do this!
```

在这里，我们引入了`const char *constData = "constant";`。指针指向初始化的数据，通过这个标识符可能永远不会再次修改。例如，如果我们尝试使用`strcpy`来更改这个值，其中`constData`是目标字符串，编译器将发出错误。

此外，试图通过将`constData`存储在相同类型（但不是`const`）的指针中来规避这种情况，也会生成编译器错误，比如代码行`regularString = constData;`。当然，在 C++中，如果你足够努力，你可以做任何事情，所以这里的显式类型转换会起作用，但故意没有显示。显式类型转换仍会生成编译器警告，以便你质疑这是否真的是你打算做的事情。当我们继续使用 OO 概念时，我们将介绍进一步保护数据的方法，以消除这种规避。

在前面代码的最后一行，请注意我们将常规字符串的地址存储在`const char *moreConstData`中。这是允许的-你总是可以对待某物比它定义的更尊重（只是不能更少）。这意味着使用标识符`moreConstData`，这个字符串可能不会被修改。然而，使用它自己的标识符，定义为`char *anotherRegularString;`，这个字符串可能会被更改。这似乎是不一致的，但实际上并不是。`const char *`变量选择指向`char *`-提升了它对特定情况的保护。如果`const char *`真的想指向一个不可变对象，它本应选择指向另一个`const char *`变量。

接下来，让我们看一个与此主题相关的变化。

## 使用常量指针指向对象

指向对象的常量指针是初始化为指向特定对象的指针。这个指针可能永远不会被分配给指向另一个对象。这个指针本身不能在赋值中用作 l 值。

让我们回顾一个简单的例子：

```cpp
// Define, allocate, load two regular strings using strcpy()
char *regularString = new char[36];
strcpy(regularString, "I am a string which can be modified");
char *anotherRegularString = new char[21];
strcpy(anotherRegularString, "I am also modifiable"); 
// Define a const pointer to a string. It must be initialized
char *const constPtrString = regularString; // Ok
// You may not modify a const pointer to point elsewhere
// constPtrString = anotherRegularString;  //No! 
// But you may change the data which you point to
strcpy(constPtrString, "I can change the value"); // Yes
```

在这个例子中，定义了两个常规的`char *`变量（`regularString`和`anotherRegularString`），并加载了字符串文字。接下来，定义并初始化了`char *const constPtrString = regularString;`，指向可修改的字符串。因为`const`限定符是应用于指针本身而不是指向的数据，所以指针本身必须在声明时初始化。请注意，代码行`constPtrString = anotherRegularString;`会生成编译器错误，因为`const`指针不能出现在赋值的左侧。然而，因为`const`限定符不适用于指向的数据，所以可以使用`strcpy`来修改数据的值，就像在`strcpy(constPtrString, "I can change the value");`中看到的那样。

接下来，让我们将`const`限定符应用于指针和指向的数据。

## 使用常量指针指向常量对象

指向常量对象的常量指针是指向特定对象和不可修改数据的指针。指针本身必须初始化为给定对象，该对象（希望）用适当的值初始化。对象或指针都不能在赋值中被修改或用作左值。

这是一个例子：

```cpp
// Define two regular strings and load using strcpy()
char *regularString = new char[36];
strcpy(regularString, "I am a string which can be modified");
char *anotherRegularString = new char[21];
strcpy(anotherRegularString, "I am also modifiable"); 
// Define a const ptr to a const object. Must be initialized
const char *const constStringandPtr = regularString; // Ok 
// Trying to change the pointer or the data is illegal
constStringandPtr = anotherRegularString; //No! Can't mod addr
strcpy(constStringandPtr, "Nope"); // No! Can't mod data
```

在这个例子中，我们声明了两个常规的`char *`变量，`regularString`和`anotherRegularString`。每个都用字符串字面值初始化。接下来，我们引入了`const char *const constStringandPtr = regularString;`，这是一个对数据进行 const 限定的指针，也被视为 const。注意，这个变量必须初始化，因为指针本身不能在后续赋值中成为左值。您还需要确保这个指针用有意义的值进行初始化，因为指向的数据也不能被更改（如`strcpy`语句所示，这将生成编译器错误）。在指针和指向的数据上结合使用 const 是一种严格的保护数据的方式。

提示-解读指针声明

阅读复杂的指针声明时，通常从右向左阅读声明会有所帮助。例如，指针声明`const char *p1 = "hi!";`可以解释为`p1`是指向（一个或多个）常量字符的指针。声明`const char *const p2 = p1;`可以解释为`p2`是指向（一个或多个）常量字符的常量指针。

最后，让我们继续了解作为函数参数或函数返回值的指针的 const 限定的含义。

## 使用指向常量对象的指针作为函数参数和函数返回类型

在堆栈上复制用户定义类型的参数可能是耗时的。将指针作为函数参数传递速度更快，但允许在函数范围内修改解引用的对象。将指向常量对象的指针作为函数参数既提供了速度又保证了参数的安全性。在问题函数的范围内，解引用的指针可能不是一个左值。同样的原则也适用于函数的返回值。对指向的数据进行 const 限定要求函数的调用者也必须将返回值存储在指向常量对象的指针中，确保对象的长期不可变性。

让我们看一个例子来检验这些想法：

[`github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter03/Chp3-Ex8.cpp`](https://github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter03/Chp3-Ex8.cpp)

```cpp
#include <iostream>
#include <cstring>
using namespace std;
char suffix = 'A';
const char *genId(const char *);  // function prototype
int main()    
{
    const char *newId1, *newId2;   // pointer declarations
    newId1 = genId("Group");  // function will allocate memory
    newId2 = genId("Group");  
    cout << "New ids: " << newId1 << " " << newId2 << endl;
    delete newId1;  // delete allocated memory  
    delete newId2;
    return 0;
}
const char *genId(const char *base)
{
    char *temp = new char[strlen(base) + 2]; 
    strcpy(temp, base);  // use base to initialize string
    temp[strlen(base)] = suffix++; // Append suffix to base
    temp[strlen(base) + 1] = '\0'; // Add null character
    return temp; // temp will be up-cast to a const char *
}                // to be treated more restrictively than 
                 // it was defined
```

在这个例子中，我们从一个全局变量开始存储一个初始后缀：`char *suffix = 'A';`和函数`const char *genId(const char *base);`的原型。在`main()`中，我们声明但不初始化`const char* newId1, *newId2;`，它们最终将保存`genId()`生成的 ID。

接下来，我们调用`genId()`两次，将字符串字面值`"Group"`作为实际参数传递给这个函数。这个参数作为形式参数`const char *base`接收。这个函数的返回值将分别用于赋值给`newId1`和`newId2`。

更仔细地看，调用`genId("Group")`将字符串字面值`"Group"`作为实际参数传递，这在函数定义的形式参数列表中被接收为`const char *base`。这意味着使用标识符`base`，这个字符串是不可修改的。

接下来，在 `genId()` 中，我们在堆栈上声明了局部指针变量 `temp`，并分配了足够的堆内存给 `temp` 指向，以容纳 `base` 指向的字符串加上一个额外的字符用于添加后缀，再加上一个用于终止新字符串的空字符。请注意，`strlen()` 计算字符串中的字符数，不包括空字符。现在，使用 `strcpy()`，将 `base` 复制到 `temp` 中。然后，使用赋值 `temp[strlen(base)] = suffix++;`，将存储在 `suffix` 中的字母添加到 `temp` 指向的字符串中（并且 `suffix` 递增到下一次调用此函数时的下一个字母）。请记住，在 C++中数组是从零开始的，当向给定字符串的末尾添加字符时。例如，如果 `"Group"` 包含 5 个字符，分别位于数组 `temp` 的位置 0 到 4，那么下一个字符（来自 `suffix`）将被添加到 `temp` 的位置 5（覆盖当前的空字符）。在代码的下一行，空字符被重新添加到 `temp` 指向的新字符串的末尾，因为所有字符串都需要以空字符结尾。请注意，虽然 `strcpy()` 会自动以空字符结尾字符串，但是一旦你开始进行单个字符的替换，比如将后缀添加到字符串中，你就需要自己重新添加新整体字符串的空字符。

最后，在这个函数中，`temp` 被返回。请注意，虽然 `temp` 被声明为 `char *`，但它以 `const char *` 的形式返回。这意味着在返回到 `main()` 时，该字符串将以更严格的方式对待，而不是在函数体中对待的那样。实质上，它已经被向上转型为 `const char *`。这意味着由于此函数的返回值是 `const char *`，因此只有类型为 `const char *` 的指针才能捕获此函数的返回值。这是必需的，以便字符串不能以比 `genId()` 函数的创建者意图更不严格的方式对待。如果 `newId1` 和 `newId2` 被声明为 `char *` 而不是 `const char *`，它们将不被允许作为 l 值来捕获 `genId()` 的返回值。

在 `main()` 的末尾，我们删除了与 `newId1` 和 `newId2` 相关联的内存。请注意，这些指针变量的内存是在程序的不同作用域中分配和释放的。程序员必须始终注意在 C++中跟踪内存分配和释放。忘记释放内存可能导致应用程序中的内存泄漏。

这是我们示例的输出的附加部分：

```cpp
New ids: GroupA GroupB
```

现在我们已经了解了如何以及为什么要对指针进行 `const` 限定，让我们通过考虑 void 指针来看看如何以及为什么选择通用指针类型。

# 使用未指定类型的对象指针

有时程序员会问为什么他们不能简单地拥有一个通用指针。也就是说，为什么我们总是要声明指针最终将指向的数据类型，比如 `int *ptr;`？C++确实允许我们创建没有关联类型的指针，但是 C++要求程序员自己来跟踪通常由编译器代劳的事情。尽管如此，在本节中我们将看到为什么 void 指针很有用，以及程序员在使用更通用的 `void` 指针时必须承担的任务。

要理解`void`指针，让我们首先考虑为什么类型通常与指针变量相关联。通常，使用指针声明类型会让 C++了解如何进行指针算术或索引到该指针类型的动态数组。也就是说，如果我们分配了`int *ptr = new int [10];`，我们有 10 个连续的整数。使用`ptr[3] = 5;`的数组表示法或`*(ptr + 3) = 5;`的指针算术来访问这个动态分配集合中的一个元素依赖于数据类型`int`的大小，以便 C++内部理解每个元素的大小以及如何从一个元素移动到下一个元素。数据类型还告诉 C++，一旦它到达适当的内存地址，如何解释内存。例如，`int`和`float`在给定机器上可能具有相同的存储大小，但是`int`的二进制补码内存布局与`float`的尾数、指数布局是完全不同的。C++对如何解释给定内存的了解至关重要，指针的数据类型正是做到这一点的。

然而，仍然存在需要更通用指针的需求。例如，你可能希望一个指针在一种情况下指向一个整数，而在另一种情况下指向一组用户定义的类型。使用`void`指针可以实现这一点。但是类型呢？当你对`void`指针进行取消引用时会发生什么？如果 C++不知道如何从一个集合中的一个元素走到另一个元素，它如何索引到动态分配的`void`指针数组中？一旦到达地址，它将如何解释字节？类型是什么？

答案是，你，程序员，必须随时记住你指向的是什么。没有与指针相关联的类型，编译器无法为你做到这一点。当需要对`void`指针进行取消引用时，你将负责正确记住所涉及的最终类型，并对该指针执行适当的类型转换。

让我们来看看所涉及的机制和逻辑。

## 创建 void 指针

使用`void *`可以指定未指定类型的对象的指针。然后，`void`指针可以指向任何类型的对象。在 C++中，必须使用显式转换来对`void *`指向的实际内存进行取消引用。在 C++中，还必须使用显式转换将`void *`指向的内存分配给已知类型的指针变量。程序员有责任确保取消引用的数据类型在进行赋值之前是相同的。如果程序员错误，那么在代码的其他地方将会有一个难以找到的指针错误。

这里有一个例子：

[`github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter03/Chp3-Ex9.cpp`](https://github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter03/Chp3-Ex9.cpp)

```cpp
#include <iostream>
using namespace std;
int main()
{
    void *unspecified;  // void * may point to any data type
    int *x;
    unspecified = new int; // the void * now points to an int
    // void * must be cast to int * before it is dereferenced
    *((int *) unspecified) = 89;
    // let x point to the memory which unspecified points to
    x = (int *) unspecified;
    cout << *x << " " << *((int *) unspecified) << endl;
    return 0;
}
```

在这个例子中，声明`void *unspecified;`创建了一个未初始化的指针，它可能有一天指向任何数据类型的内存。声明`int *x;`声明了一个可能有一天指向一个或多个连续整数的指针。

赋值`*((int *) unspecified = 89;`首先使用显式类型转换将`unspecified`转换为`(int *)`，然后取消引用`int *`将值`89`放入内存。重要的是要注意，在对`unspecified`进行取消引用之前必须进行此类型转换-否则 C++无法理解如何解释`unspecified`指向的内存。还要注意，如果你意外地将`unspecified`转换为错误的类型，编译器将允许你继续进行，因为类型转换被视为对编译器的"*just do it*"命令。作为程序员，你的工作是记住你的`void *`指向的数据类型。

最后，我们希望`x`指向`unspecified`指向的位置。变量`x`是一个整数，需要指向一个或多个整数。变量`unspecified`确实指向一个整数，但由于 unspecified 的数据类型是`void *`，我们必须使用显式类型转换使以下赋值生效：`x = (int *) unspecified;`。此外，从程序上看，我们希望我们正确地记住了`unspecified`确实指向一个`int`；知道正确的内存布局对于`int *`如果被取消引用是很重要的。否则，我们只是强制了不同类型指针之间的赋值，在我们的程序中留下了潜在的错误。

以下是与我们的程序配套的输出：

```cpp
89 89
```

在 C++中有许多`void`指针的创造性用途。有一些技术使用`void *`进行通用指针操作，并将这种内部处理与在顶部添加的薄层配对，以将数据转换为已知的数据类型。薄顶层可以进一步通过 C++的模板特性进行泛型化。使用模板，程序员只需维护一个显式类型转换的版本，但实际上可以为您提供许多版本-每个实际的具体数据类型需要一个版本。这些想法涵盖了高级技术，但我们将在接下来的章节中看到其中的一些，从*第十三章*，*使用模板*开始。

# 摘要

在本章中，我们学习了 C++中指针的许多方面。我们已经看到如何使用`new()`从堆中分配内存，以及如何使用`delete()`将该内存交还给堆管理设施。我们已经看到了使用标准类型和用户定义类型的示例。我们还了解了为什么我们可能希望动态分配数组，并且已经了解了如何为 1、2 和 N 维数组这样做。我们已经看到了如何使用`delete[]`释放相应的内存。我们通过将指针添加为函数的参数和从函数返回值来回顾函数。我们还学习了如何对指针进行`const`限定以及它们指向的数据（或两者）以及为什么要这样做。最后，我们已经看到了通过引入`void`指针来泛化指针的一种方法。

本章中使用指针的所有技能将在接下来的章节中自由使用。C++希望程序员能够很好地使用指针。指针使语言具有很大的自由度和效率，可以利用大量的数据结构并采用创造性的编程解决方案。然而，指针可能会为程序引入大量错误，如内存泄漏，返回指向不再存在的内存的指针，取消引用已被删除的指针等。不用担心，我们将在接下来的示例中使用许多指针，以便您能够轻松地操纵指针。

最重要的是，您现在已经准备好继续前进到*第四章*，*间接寻址-引用*，在这一章中，我们将使用引用来探索间接寻址。一旦您了解了间接寻址的两种类型-指针和引用-并且可以轻松地操纵其中任何一种，我们将在本书中探讨核心面向对象的概念，从*第五章*，*详细探讨类*开始。

# 问题

1.  修改并增强您的 C++程序，从*第二章*，*添加语言必需性*，*练习 2*如下所示：

a. 创建一个名为`ReadData()`的函数，该函数接受一个指向`Student`的指针作为参数，以允许在函数内从键盘输入`firstName`、`lastName`、`gpa`和`currentCourseEnrolled`，并将其存储为输入参数的数据。

b. 修改`firstName`，`lastName`和`currentCourseEnrolled`，在您的`Student`类中将它们建模为`char *`，而不是使用固定大小的数组（就像在*第二章*中可能已经建模的那样，*添加语言必需性*）。您可以利用一个固定大小的`temp`变量，最初捕获这些值的用户输入，然后为这些数据成员分配适当的大小。

c. 如果需要，重新编写您在*第二章*解决方案中的`Print()`函数，以便为`Print()`接受`Student`作为参数。

d. 重载`Print()`函数，使用一个以`const Student *`为参数的函数。哪一个更有效？为什么？

e. 在`main()`中，创建一个指向`Student`的指针数组，以容纳 5 个学生。为每个`Student`分配内存，为每个`Student`调用`ReadData()`，然后使用上述函数中的选择`Print()`每个`Student`。完成后，请记得为每个分配的学生`delete()`内存。

f. 同样在`main()`中，创建一个`void`指针数组，大小与指向`Student`的指针数组相同。将`void`指针数组中的每个元素设置为指向`Student`指针数组中相应的`Student`。对`void *`数组中的每个元素调用以`const Student *`为参数的`Print()`版本。提示：在进行某些赋值和函数调用之前，您需要将`void *`元素转换为`Student *`类型。

1.  写下以下指针声明，其中包括`const`修饰：

a. 为指向常量对象的指针编写声明。假设对象的类型为`Student`。提示：从右向左阅读您的声明以验证其正确性。

b. 为指向非常量对象的常量指针编写声明。再次假设对象的类型为`Student`。

c. 为指向常量对象的常量指针编写声明。对象将再次是`Student`类型。

1.  为什么在上面的程序中将类型为`const Student *`的参数传递给`Print()`是有意义的，为什么传递类型为`Student * const`的参数是没有意义的？

1.  您能想到可能需要动态分配的 3D 数组的编程情况吗？动态分配具有更多维度的数组呢？


# 第四章：间接寻址：引用

本章将探讨如何在 C++中利用引用。引用通常可以用作间接寻址的替代方案，但并非总是如此。尽管您在上一章中使用指针有间接寻址的经验，我们将从头开始理解 C++引用。

引用和指针一样，是您必须能够轻松使用的语言特性。许多其他语言使用引用进行间接寻址，而不需要像 C++那样深入理解才能正确使用指针和引用。与指针一样，您会经常在其他程序员的代码中看到引用的使用。与指针相比，使用引用在编写应用程序时提供了更简洁的表示方式，这可能会让您感到满意。

遗憾的是，在所有需要间接寻址的情况下，引用不能替代指针。因此，在 C++中，深入理解使用指针和引用进行间接寻址是成功创建可维护代码的必要条件。

本章的目标是通过了解如何使用 C++引用作为替代方案来补充您对使用指针进行间接寻址的理解。了解两种间接寻址技术将使您成为一名更优秀的程序员，轻松理解和修改他人的代码，并自己编写原始、成熟和有竞争力的 C++代码。

在本章中，我们将涵盖以下主要主题：

+   引用基础 - 声明、初始化、访问和引用现有对象

+   将引用用作函数的参数和返回值

+   在引用中使用 const 限定符

+   理解底层实现，以及引用不能使用的情况

在本章结束时，您将了解如何声明、初始化和访问引用；您将了解如何引用内存中现有的对象。您将能够将引用用作函数的参数，并了解它们如何作为函数的返回值使用。

您还将了解 const 限定符如何适用于引用作为变量，并且如何与函数的参数和返回类型一起使用。您将能够区分引用何时可以替代指针，以及它们不能替代指针的情况。这些技能将是成功阅读本书后续章节的必要条件。

# 技术要求

完整程序示例的在线代码可以在以下 GitHub URL 找到：[`github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter04`](https://github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/tree/master/Chapter04)。每个完整程序示例都可以在 GitHub 存储库中的适当章节标题（子目录）下找到，文件名与所在章节编号相对应，后跟破折号，再跟随所在章节中的示例编号。例如，本章的第一个完整程序可以在名为`Chp4-Ex1.cpp`的文件中的`Chapter04`子目录中找到。

本章的 CiA 视频可在以下链接观看：[`bit.ly/2OM7GJP`](https://bit.ly/2OM7GJP)

# 理解引用基础

在本节中，我们将重新讨论引用基础，并介绍适用于引用的运算符，如引用运算符`&`。我们将使用引用运算符`&`来建立对现有变量的引用。与指针变量一样，引用变量指向在其他地方定义的内存。

使用引用变量允许我们使用比指针间接访问内存时更简单的符号。许多程序员欣赏引用与指针变量的符号的清晰度。但是，在幕后，内存必须始终被正确分配和释放；被引用的一部分内存可能来自堆。程序员无疑需要处理指针来处理其整体代码的一部分。

我们将分辨引用和指针何时可以互换使用，何时不可以。让我们从声明和使用引用变量的基本符号开始。

## 声明、初始化和访问引用

让我们从引用变量的含义开始。C++中的`&`。引用必须在声明时初始化，并且永远不能被分配给引用另一个对象。引用和初始化器必须是相同类型。由于引用和被引用的对象共享相同的内存，任一变量都可以用来修改共享内存位置的内容。

引用变量，在幕后，可以与指针变量相比较——因为它保存了它引用的变量的地址。与指针变量不同，引用变量的任何使用都会自动取消引用变量以转到它包含的地址；取消引用运算符`*`在引用中是不需要的。取消引用是自动的，并且隐含在每次使用引用变量时。

让我们看一个说明引用基础的例子：

[`github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter04/Chp4-Ex1.cpp`](https://github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter04/Chp4-Ex1.cpp)

```cpp
#include <iostream>
using namespace std;
int main()
{
    int x = 10;
    int *p = new int;    // allocate memory for ptr variable
    *p = 20;             // dereference and assign value 
    int &refInt1 = x;  // reference to an integer
    int &refInt2 = *p; // also a reference to an integer
    cout << x << " " << *p << " ";
    cout << refInt1 << " " << refInt2 << endl;
    x++;      // updates x and refInt1
    (*p)++;   // updates *p and refInt2
    cout << x << " " << *p << " ";
    cout << refInt1 << " " << refInt2 << endl;
    refInt1++;    // updates refInt1 and x
    refInt2++;    // updates refInt2 and *p
    cout << x << " " << *p << " ";
    cout << refInt1 << " " << refInt2 << endl;
    return 0;
}
```

在前面的例子中，我们首先声明并初始化`int x = 10;`，然后声明并分配`int *p = new int;`。然后我们将整数值 20 分配给`*p`。

接下来，我们声明并初始化两个引用变量，`refInt1`和`refInt2`。在第一个引用声明和初始化中，`int &refInt1 = x;`，我们建立`refInt1`引用变量指向变量`x`。从右向左阅读引用声明有助于理解。在这里，我们说要使用`x`来初始化`refInt1`，它是一个整数的引用（`&`）。注意初始化器`x`是一个整数，并且`refInt1`声明为整数的引用；它们的类型匹配。这很重要。如果类型不同，代码将无法编译。同样，声明和初始化`int &refInt2 = *p;`也将`refInt2`建立为整数的引用。哪一个？由`p`指向的那个。这就是为什么使用`*`对`p`进行取消引用以获得整数本身。

现在，我们打印出`x`、`*p`、`refInt1`和`refInt2`；我们可以验证`x`和`refInt1`的值相同为`10`，而`*p`和`refInt2`的值也相同为`20`。

接下来，使用原始变量，我们将`x`和`*p`都增加一。这不仅增加了`x`和`*p`的值，还增加了`refInt1`和`refInt2`的值。重复打印这四个值，我们再次注意到`x`和`refInt1`的值为`11`，而`*p`和`refInt2`的值为`21`。

最后，我们使用引用变量来增加共享内存。我们将`refInt1`和`*refint2`都增加一，这也增加了原始变量`x`和`*p`的值。这是因为内存是原始变量和引用到该变量的相同。也就是说，引用可以被视为原始变量的别名。我们通过再次打印这四个变量来结束程序。

以下是输出：

```cpp
10 20 10 20
11 21 11 21
12 22 12 22
```

重要提示

记住，引用变量必须初始化为它将引用的变量。引用永远不能被分配给另一个变量。引用和它的初始化器必须是相同类型。

现在我们已经掌握了如何声明简单引用，让我们更全面地看一下引用现有对象，比如用户定义类型的对象。

## 引用现有的用户定义类型的对象

如果定义一个`struct`或`class`类型的对象的引用，那么被引用的对象可以简单地使用`.`（成员选择运算符）访问。同样，不需要（就像指针一样）首先使用取消引用运算符来访问被引用的对象，然后选择所需的成员。

让我们看一个引用用户定义类型的例子：

[`github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter04/Chp4-Ex2.cpp`](https://github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter04/Chp4-Ex2.cpp)

```cpp
#include <iostream>
#include <cstring>
using namespace std;
class Student
{
public:
    char name[20];
    float gpa;
};
int main()
{
    Student s1;
    Student &sRef = s1;  // establish a reference to s1
    strcpy(s1.name, "Katje Katz");   // fill in the data
    s1.gpa = 3.75;
    cout << s1.name << " has GPA: " << s1.gpa << endl; 
    cout << sRef.name << " has GPA: " << sRef.gpa << endl; 
    strcpy(sRef.name, "George Katz");  // change the data
    sRef.gpa = 3.25;
    cout << s1.name << " has GPA: " << s1.gpa << endl; 
    cout << sRef.name << " has GPA: " << sRef.gpa << endl; 
    return 0;
}
```

在程序的第一部分中，我们使用`class`定义了一个用户定义类型`Student`。接下来，我们使用`Student s1;`声明了一个类型为`Student`的变量`s1`。现在，我们使用`Student &sRef = s1;`声明并初始化了一个`Student`的引用。在这里，我们声明`sRef`引用特定的`Student`，即`s1`。注意，`s1`是`Student`类型，而`sRef`的引用类型也是`Student`类型。

现在，我们使用`strcpy()`加载一些初始数据到`s1`中，然后进行简单赋值。因此，这改变了`sRef`的值，因为`s1`和`sRef`引用相同的内存。也就是说，`sRef`是`S1`的别名。

我们打印出`s1`和`sRef`的各种数据成员，并注意到它们包含相同的值。

现在，我们加载新的值到`sRef`中，也使用`strcpy()`和简单赋值。同样，我们打印出`s1`和`sRef`的各种数据成员，并注意到它们的值再次发生了改变。我们可以看到它们引用相同的内存。

程序输出如下：

```cpp
Katje Katz has GPA: 3.75
Katje Katz has GPA: 3.75
George Katz has GPA: 3.25
George Katz has GPA: 3.25
```

现在，让我们通过考虑在函数中使用引用来进一步了解引用的用法。

# 使用引用与函数

到目前为止，我们已经通过使用引用来为现有变量建立别名来最小程度地演示了引用。相反，让我们提出引用的有意义用法，比如在函数调用中使用它们。我们知道 C++中的大多数函数将接受参数，并且在前几章中我们已经看到了许多示例，说明了函数原型和函数定义。现在，让我们通过将引用作为函数的参数传递，并使用引用作为函数的返回值来增进我们对函数的理解。

## 将引用作为函数的参数传递

引用可以作为函数的参数来实现按引用传递，而不是按值传递参数。引用可以减轻在所涉及的函数范围内以及调用该函数时使用指针表示的需要。对于引用的形式参数，使用对象或`.`（成员选择）表示法来访问`struct`或`class`成员。

为了修改作为参数传递给函数的变量的内容，必须使用对该参数的引用（或指针）作为函数参数。就像指针一样，当引用传递给函数时，传递给函数的是表示引用的地址的副本。然而，在函数内部，任何使用引用作为形式参数的用法都会自动隐式地取消引用，允许用户使用对象而不是指针表示。与传递指针变量一样，将引用变量传递给函数将允许修改由该参数引用的内存。

在检查函数调用时（除了其原型），如果传递给该函数的对象是按值传递还是按引用传递，这将不明显。也就是说，整个对象是否将在堆栈上复制，还是堆栈上将传递对该对象的引用。这是因为在操作引用时使用对象表示法，并且这两种情况的函数调用将使用相同的语法。

勤奋使用函数原型将解决函数定义的外观以及其参数是对象还是对象引用的神秘。请记住，函数定义可以在与该函数的任何调用分开的文件中定义，并且不容易查看。请注意，指定在函数调用中的指针不会出现这种模棱两可的情况；根据变量的声明方式，立即就能明显地知道地址被发送到函数。

让我们花几分钟来理解一个示例，说明将引用作为参数传递给函数。在这里，我们将从检查有助于以下完整程序示例的三个函数开始：

[`github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter04/Chp4-Ex3.cpp`](https://github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/tree/master/Chapter04/Chp4-Ex3.cpp)

```cpp
void AddOne(int &arg)   // These two functions are overloaded
{
    arg++;
}
void AddOne(int *arg)   // Overloaded function definition
{
    (*arg)++;
}
void Display(int &arg)  // This fn passes a reference to arg
{                       
    cout << arg << " " << flush;
}
```

在上面的函数中，注意`AddOne（int＆arg）`将引用作为形式参数，而`AddOne（int *arg）`将指针作为形式参数。这些函数是重载的。它们的实际参数的类型将决定调用哪个版本。

现在让我们考虑`Display（int＆arg）`。此函数接受对整数的引用。请注意，在此函数的定义中，使用对象（而不是指针）表示法来打印`arg`。

现在，让我们检查此程序的其余部分：

```cpp
#include <iostream>
using namespace std;
void AddOne(int &);    // function prototypes
void AddOne(int *);
void Display(int &);
int main()
{
    int x = 10, *y;
    y = new int;    // allocate y's memory
    *y = 15;        // dereference y to assign a value
    Display(x);
    Display(*y);

    AddOne(x);    // calls reference version (with an object) 
    AddOne(*y);   // also calls reference version 
    Display(x);   // Based on prototype, we see we are passing
    Display(*y);  // by reference. Without prototype, we might
                  // have guessed it was by value.
    AddOne(&x);   // calls pointer version
    AddOne(y);    // also calls pointer version
    Display(x);
    Display(*y);
    return 0;
}
```

请注意此程序段顶部的函数原型。它们将与先前代码段中的函数定义匹配。现在，在`main（）`函数中，我们声明并初始化`int x = 10;`并声明一个指针`int *y;`。我们使用`new（）`为`y`分配内存，然后通过解引用指针赋值`*y = 15;`。我们使用连续调用`Display（）`打印出`x`和`*y`的相应值作为基线。

接下来，我们调用`AddOne（x）`，然后是`AddOne（*y）`。变量`x`被声明为整数，`*y`指的是`y`指向的整数。在这两种情况下，我们都将整数作为实际参数传递给带有签名`void AddOne（int＆）`的重载函数版本。在这两种情况下，形式参数将在函数中更改，因为我们是通过引用传递的。当它们的相应值在接下来的连续调用`Display（）`中打印时，我们可以验证这一点。请注意，在函数调用`AddOne（x）`中，实际参数`x`的引用是在函数调用时由形式参数`arg`（在函数的参数列表中）建立的。

相比之下，我们接下来调用`AddOne（＆x）`，然后是`AddOne（y）`。在这两种情况下，我们都调用了带有签名`void AddOne（int *）`的此函数的重载版本。在每种情况下，我们都将地址的副本作为实际参数传递给函数。自然地，`＆x`是变量`x`的地址，所以这有效。同样，`y`本身就是一个地址-它被声明为指针变量。我们再次验证它们的相应值是否再次更改，使用两次`Display（）`调用。

请注意，在每次调用`Display()`时，我们都传递了一个`int`类型的对象。仅仅看函数调用本身，我们无法确定这个函数是否将以实际参数`int`（这意味着值不能被更改）或者以实际参数`int &`（这意味着值可以被修改）的形式接受。这两种情况都是可能的。然而，通过查看函数原型，我们可以清楚地看到这个函数以`int &`作为参数，从中我们可以理解参数很可能会被修改。这是函数原型有帮助的众多原因之一。

以下是完整程序示例的输出：

```cpp
10 15 11 16 12 17
```

现在，让我们通过使用引用作为函数的返回值来扩展我们对使用引用的讨论。

## 使用引用作为函数返回值

函数可以通过它们的返回语句返回对数据的引用。我们将在*第十二章*中看到需要通过引用返回数据的情况，*友元和运算符重载*。使用运算符重载，使用指针从函数返回值将不是一个选项，以保留运算符的原始语法；我们必须返回一个引用（或者一个带有 const 限定符的引用）。此外，了解如何通过引用返回对象将是有用的，因为我们在*第十四章*中探讨 C++标准模板库时会用到，*理解 STL 基础*。

当通过函数的返回语句返回引用时，请确保被引用的内存在函数调用完成后仍然存在。**不要**返回对函数内部栈上定义的局部变量的引用；这些内存将在函数完成时从栈上弹出。

由于我们无法从函数内部返回对局部变量的引用，并且因为返回对外部变量的引用是没有意义的，您可能会问我们返回的引用所指向的数据将存放在哪里？这些数据将不可避免地位于堆上。堆内存将存在于函数调用的范围之外。在大多数情况下，堆内存将在其他地方分配；然而，在很少的情况下，内存可能已经在此函数内分配。在这种情况下，当不再需要时，您必须记得放弃已分配的堆内存。

通过引用（而不是指针）变量删除堆内存将需要您使用取地址运算符`&`将所需的地址传递给`delete()`运算符。即使引用变量包含它们引用的对象的地址，但引用标识符的使用始终处于其取消引用状态。很少会出现使用引用变量删除内存的情况；我们将在*第十章*中讨论一个有意义（但很少）的例子，*实现关联、聚合和组合*。

让我们看一个例子来说明使用引用作为函数返回值的机制：

[`github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter04/Chp4-Ex4.cpp`](https://github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/tree/master/Chapter04/Chp4-Ex4.cpp)

```cpp
#include <iostream>
using namespace std;
int &CreateId();  // function prototype

int main()    
{
    int &id1 = CreateId();  // reference established
    int &id2 = CreateId();
    cout << "Id1: " << id1 << " Id2: " << id2 << endl;
    delete &id1;  // Here, '&' is address-of, not reference
    delete &id2;  // to calculate address to pass delete()
    return 0;
}
int &CreateId()   // Function returns a reference to an int
{
    static int count = 100;  // initialize with first id 
    int *memory = new int;
    *memory = count++;  // use count as id, then increment
    return *memory;
}
```

在这个例子中，我们看到程序顶部有`int &CreateId();`的原型。这告诉我们`CreateId()`将返回一个整数的引用。返回值必须用来初始化一个`int &`类型的变量。

在程序底部，我们看到了`CreateId()`的函数定义。请注意，此函数首先声明了一个`static`计数器，它被初始化为`100`。因为这个局部变量是`static`的，它将保留从函数调用到函数调用的值。然后我们在几行后递增这个计数器。静态变量`count`将被用作生成唯一 ID 的基础。

接下来在`CreateId()`中，我们在堆上为一个整数分配空间，并使用局部变量`memory`指向它。然后我们将`*memory`加载为`count`的值，然后为下一次进入这个函数增加`count`。然后我们使用`*memory`作为这个函数的返回值。请注意，`*memory`是一个整数（由变量`memory`在堆上指向的整数）。当我们从函数中返回它时，它作为对该整数的引用返回。当从函数中返回引用时，始终确保被引用的内存存在于函数的范围之外。

现在，让我们看看我们的`main()`函数。在这里，我们使用第一次调用`CreateId()`的返回值初始化了一个引用变量`id1`，如下所示的函数调用和初始化：`int &id1 = CreateId();`。请注意，引用`id1`在声明时必须被初始化，我们已经通过上述代码行满足了这个要求。

我们重复这个过程，用`CreateId()`的返回值初始化这个引用`id2`。然后我们打印`id1`和`id2`。通过打印`id1`和`id2`，您可以看到每个 id 变量都有自己的内存并保持自己的数据值。

接下来，我们必须记得释放`CreateId()`分配的内存。我们必须使用`delete()`运算符。等等，`delete()`运算符需要一个指向将被删除的内存的指针。变量`id1`和`id2`都是引用，而不是指针。是的，它们各自包含一个地址，因为每个都是作为指针实现的，但是它们各自的标识符的任何使用总是处于解引用状态。为了规避这个困境，我们只需在调用`delete()`之前取引用变量`id1`和`id2`的地址，比如`delete &id1;`。*很少*情况下，您可能需要通过引用变量删除内存，但现在您知道在需要时如何做。

这个例子的输出是：

```cpp
Id1: 100 Id2: 101
```

现在我们了解了引用如何在函数参数中使用以及作为函数的返回值，让我们继续通过进一步研究引用的微妙之处。

# 使用 const 限定符与引用

`const`限定符可以用来限定引用初始化或*引用的*数据。我们还可以将`const`限定的引用用作函数的参数和函数的返回值。

重要的是要理解，在 C++中，引用被实现为一个常量指针。也就是说，引用变量中包含的地址是一个固定的地址。这解释了为什么引用变量必须初始化为它将引用的对象，并且不能以后使用赋值来更新。这也解释了为什么仅对引用本身（而不仅仅是它引用的数据）进行常量限定是没有意义的。这种`const`限定的变体已经隐含在其底层实现中。

让我们看看在引用中使用`const`的各种情况。

## 使用对常量对象的引用

`const`限定符可以用来指示引用初始化的数据是不可修改的。这样，别名总是引用一个固定的内存块，该变量的值不能使用别名本身来改变。一旦指定为常量，引用意味着既不会改变引用本身，也不会改变其值。同样，由于其底层实现为常量限定指针，`const`限定的引用不能在任何赋值中用作*l 值*。

注意

回想一下，左值意味着可以修改的值，并且出现在赋值的左侧。

让我们举一个简单的例子来理解这种情况：

https://github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter04/Chp4-Ex5.cpp

```cpp
#include <iostream>
using namespace std;
int main()
{
   int x = 5;
   const int &refInt = x;
   cout << x << " " << refInt << endl;
   // refInt = 6;  // Illegal -- refInt is const 
   x = 7;   // we can inadvertently change refInt
   cout << x << " " << refInt << endl;
   return 0;
}
```

在前面的例子中，注意我们声明`int x = 5;`，然后我们用声明`const int &refInt = x;`建立对该整数的常量引用。接下来，我们打印出基线的两个值，并注意它们是相同的。这是有道理的，它们引用相同的整数内存。

接下来，在被注释掉的代码片段中，`//refInt = 6;`，我们试图修改引用所指向的数据。因为`refInt`被限定为`const`，这是非法的；因此这就是我们注释掉这行代码的原因。

然而，在下一行代码中，我们给`x`赋值为`7`。由于`refInt`引用了相同的内存，它的值也将被修改。等等，`refInt`不是常量吗？是的，通过将`refInt`限定为`const`，我们指示使用标识符`refInt`时其值不会被修改。这个内存仍然可以使用`x`来修改。

但等等，这不是一个问题吗？不，如果`refInt`真的想要引用不可修改的东西，它可以用`const int`而不是`int`来初始化自己。这是 C++中一个微妙的点，因此你可以编写完全符合你意图的代码，理解每种选择的重要性和后果。

这个例子的输出是：

```cpp
5 5
7 7
```

接下来，让我们看一下`const`限定符主题的变化。

## 使用指向常量对象的指针作为函数参数和作为函数的返回类型

使用`const`限定符与函数参数可以允许通过引用传递参数的速度，但通过值传递参数的安全性。这是 C++中一个有用的特性。

一个函数将一个对象的引用作为参数通常比将对象的副本作为参数的函数版本具有更少的开销。当在堆栈上复制的对象类型很大时，这种情况最为明显。将引用作为形式参数传递更快，但允许在函数范围内可能修改实际参数。将常量对象的引用作为函数参数提供了参数的速度和安全性。在参数列表中限定为`const`的引用在所讨论的函数范围内可能不是一个左值。

`const`限定符引用的同样好处也存在于函数的返回值中。常量限定所引用的数据坚持要求函数的调用者也必须将返回值存储在对常量对象的引用中，确保对象不会被修改。

让我们看一个例子：

https://github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter04/Chp4-Ex6.cpp

```cpp
#include <iostream>      
using namespace std;
class Collection
{
public:
    int x;
    float y;
};
void Update(Collection &);   // function prototypes
void Print(const Collection &);
int main()
{
    Collection collect1, *collect2;
    collect2 = new Collection;  // allocate memory from heap
    Update(collect1);   // a ref to the object will be passed
    Update(*collect2);  // same here -- *collect2 is an object
    Print(collect1);  
    Print(*collect2);
    delete collect2;    // delete heap memory
    return 0;
}
void Update(Collection &c)
{
    cout << "Enter x and y members: ";
    cin >> c.x >> c.y;
}

void Print(const Collection &c)
{
    cout << "x member: " << c.x;
    cout << "   y member: " << c.y << endl;
}
```

在这个例子中，我们首先定义了一个简单的`class Collection`，其中包含数据成员`x`和`y`。接下来，我们原型化了`Update(Collection &);`和`Print(const Collection &);`。请注意，`Print()`对被引用的数据进行了常量限定作为输入参数。这意味着该函数将通过引用传递此参数，享受传递参数的速度，但通过值传递参数的安全性。

注意，在程序的末尾，我们看到了`Update()`和`Print()`的定义。两者都采用引用作为参数，但是`Print()`的参数是常量限定的：`void Print(const Collection &);`。请注意，两个函数在每个函数体内使用`.`（成员选择）符号来访问相关的数据成员。

在`main()`中，我们声明了两个变量，`collect1`类型为`Collection`，`collect2`是指向`Collection`的指针（并且其内存随后被分配）。我们为`collect1`和`*collect2`都调用了`Update()`，在每种情况下，都将适用对象的引用传递给`Update()`函数。对于`collect2`，它是一个指针变量，实际参数必须首先解引用`*collect2`，然后调用此函数。

最后，在`main()`中，我们连续为`collect1`和`*collect2`调用`Print()`。在这里，`Print()`将引用每个对象作为常量限定的引用数据，确保在`Print()`函数范围内不可能修改任何输入参数。

这是我们示例的输出：

```cpp
Enter x and y members: 33 23.77
Enter x and y members: 10 12.11
x member: 33   y member: 23.77
x member: 10   y member: 12.11
```

现在我们已经了解了`const`限定引用何时有用，让我们看看何时可以使用引用代替指针，以及何时不可以。

# 实现底层实现和限制

引用可以简化间接引用所需的符号。但是，在某些情况下，引用根本无法取代指针。要了解这些情况，有必要回顾一下 C++中引用的底层实现。

引用被实现为常量指针，因此必须初始化。一旦初始化，引用就不能引用不同的对象（尽管被引用的对象的值可以更改）。

为了理解实现，让我们考虑一个样本引用声明：`int &intVar = x;`。从实现的角度来看，前一个变量声明实际上被声明为`int *const intVar = &x;`。请注意，初始化左侧显示的`&`符号具有引用的含义，而初始化或赋值右侧显示的`&`符号意味着取地址。这两个声明说明了引用的定义与其底层实现。

接下来，让我们了解在哪些情况下不能使用引用。

## 了解何时必须使用指针而不是引用

根据引用的底层实现（作为`const`指针），大多数引用使用的限制都是有道理的。例如，不允许引用引用；每个间接级别都需要提前初始化，这通常需要多个步骤，例如使用指针。也不允许引用数组（每个元素都需要立即初始化）；尽管如此，指针数组始终是一个选择。还不允许指向引用的指针；但是，允许引用指针（以及指向指针的指针）。

让我们来看看一个有趣的允许引用的机制，这是我们尚未探讨的。

[`github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter04/Chp4-Ex7.cpp`](https://github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/tree/master/Chapter04/Chp4-Ex7.cpp)

```cpp
#include <iostream>   
using namespace std;
int main()
{
    int *ptr = new int;
    *ptr = 20;
    int *&refPtr = ptr;  // establish a reference to a pointer
    cout << *ptr << " " << *refPtr << endl; 
    return 0;
}
```

在这个例子中，我们声明`int *ptr;`，然后为`ptr`分配内存（在一行上合并）。然后我们给`*p`赋值为`20`。

接下来，我们声明`int *&refPtr = ptr;`，这是一个指向`int`类型指针的引用。最好从右向左阅读声明。因此，我们使用`ptr`来初始化`refPtr`，它是指向`int`的指针的引用。在这种情况下，两种类型匹配：`ptr`是指向`int`的指针，因此`refPtr`必须引用指向`int`的指针。然后我们打印出`*ptr`和`*refPtr`的值，可以看到它们是相同的。

以下是我们程序的输出：

```cpp
20 20
```

通过这个例子，我们看到了另一个有趣的引用用法。我们也了解了使用引用所施加的限制，所有这些限制都是由它们的基础实现驱动的。

# 总结

在本章中，我们学习了 C++引用的许多方面。我们花时间了解了引用的基础知识，比如声明和初始化引用变量到现有对象，以及如何访问基本类型和用户定义类型的引用组件。

我们已经看到如何在函数中有意义地利用引用，既作为输入参数，又作为返回值。我们还看到了何时合理地对引用应用`const`限定符，以及如何将这个概念与函数的参数和返回值相结合。最后，我们看到了引用的基础实现。这有助于解释引用所包含的一些限制，以及帮助我们理解间接寻址的哪些情况将需要使用指针而不是引用。

与指针一样，本章中使用引用的所有技能将在接下来的章节中自由使用。C++允许程序员使用引用来更方便地进行间接寻址的表示；然而，程序员预计可以相对轻松地利用指针进行间接寻址。

最后，您现在可以继续前往*第五章*，*详细探讨类*，在这一章中，我们将开始 C++的面向对象特性。这就是我们一直在等待的；让我们开始吧！

# 问题

1.  修改并增强您的 C++程序，从*第三章*，*间接寻址-指针*，*练习 1*，如下所示：

a. 重载您的`ReadData()`函数，使用接受`Student &`参数的版本，以允许从键盘在函数内输入`firstName`、`lastName`、`currentCourseEnrolled`和`gpa`。

b. 替换您先前解决方案中的`Print()`函数，该函数取一个`Student`，而是取一个`const``Student &`作为`Print()`的参数。

c. 在`main()`中创建`Student`类型和`Student *`类型的变量。现在，调用各种版本的`ReadData()`和`Print()`。指针变量是否必须调用接受指针的这些函数的版本，非指针变量是否必须调用接受引用的这些函数的版本？为什么？
