# C++ 面向对象编程揭秘（五）

> 原文：[`zh.annas-archive.org/md5/BCB2906673DC89271C447ACAA17D3E00`](https://zh.annas-archive.org/md5/BCB2906673DC89271C447ACAA17D3E00)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十五章：测试类和组件

本章将继续探索如何通过探索测试组成我们面向对象程序的类和组件的方法，来增加您的 C++编程技能库。我们将探索各种策略，以确保我们编写的代码经过充分测试并且健壮。

本章将展示如何通过测试单个类以及测试一起工作的各种组件来测试您的面向对象程序。

在本章中，我们将涵盖以下主要主题：

+   理解规范类形式；创建健壮的类

+   创建驱动程序来测试类

+   测试通过继承、关联或聚合相关的类

+   测试异常处理机制

通过本章结束时，您将掌握各种技术，确保您的代码在投入生产之前经过充分测试。具备持续产生健壮代码的技能将帮助您成为更有益的程序员。

让我们通过研究各种面向对象测试技术来增强我们的 C++技能。

# 技术要求

完整程序示例的在线代码可以在以下 GitHub URL 找到：[`github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter15`](https://github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter15)。每个完整程序示例都可以在 GitHub 存储库中的适当章节标题（子目录）下找到，文件名对应于章节号，后跟破折号，再跟随该章节中的示例编号。例如，本章的第一个完整程序可以在名为`Chp15-Ex1.cpp`的文件中的`Chapter15`子目录中找到上述 GitHub 目录下。

本章的 CiA 视频可在以下链接观看：[`bit.ly/314TI8h`](https://bit.ly/314TI8h)。

# 思考面向对象测试

在部署任何代码之前，软件测试非常重要。测试面向对象的软件将需要不同于其他类型软件的技术。因为面向对象的软件包含类之间的关系，我们必须了解如何测试可能存在的类之间的依赖关系和关系。此外，每个对象可能会根据对每个实例应用操作的顺序以及与相关对象的特定交互而进入不同的状态（例如，通过关联）。与过程性应用程序相比，面向对象应用程序的整体控制流程要复杂得多，因为应用于给定对象的操作的组合和顺序以及相关对象的影响是多种多样的。

然而，我们可以应用指标和流程来测试面向对象的软件。这些范围从理解我们可以应用于类规范的习语和模式，到创建驱动程序来独立测试类以及它们与其他类的关系。这些流程还可以包括创建场景，以提供对象可能经历的事件或状态的可能序列。对象之间的关系，如继承、关联和聚合，在测试中变得非常重要；相关对象可以影响现有对象的状态。

让我们从理解我们经常可以应用于开发的类的简单模式开始，来开始我们在测试面向对象软件中的探索。这种习语将确保一个类可能是完整的，没有意外的行为。我们将从规范类形式开始。

# 理解规范类形式

对于 C++中的许多类来说，遵循类规范的模式是合理的，以确保新类包含所需的全部组件。规范类形式是一个强大的类规范，使得类实例能够在初始化、赋值、参数传递和从函数返回值的使用等方面提供统一的行为（类似于标准数据类型）。规范类形式将适用于大多数既用于实例化的类，又用于作为新派生类的公共基类的类。打算作为私有或受保护基类的类（即使它们可能被实例化）可能不遵循这种习惯的所有部分。

遵循正统规范形式的类将包括：

+   一个默认构造函数

+   一个复制构造函数

+   一个过载的赋值运算符

+   虚析构函数

遵循扩展规范形式的类还将包括：

+   一个“移动”复制构造函数

+   一个“移动”赋值运算符

让我们在下面的子节中看看规范类形式的每个组件。

## 默认构造函数

简单实例化需要一个默认构造函数。虽然如果一个类不包含构造函数，将会提供一个默认（空）构造函数，但重要的是要记住，如果一个类包含其他签名的构造函数，将不会提供默认构造函数。最好提供一个合理的基本初始化的默认构造函数。

此外，在成员初始化列表中没有指定替代基类构造函数的情况下，将调用给定类的基类的默认构造函数。如果基类没有这样的默认构造函数（并且没有提供另一个签名的构造函数），则对基类构造函数的隐式调用将被标记为错误。

让我们还考虑多重继承情况，其中出现了菱形继承结构，并且使用虚基类来消除最派生类实例中大多数基类子对象的重复。在这种情况下，除非在负责创建菱形形状的派生类的成员初始化列表中另有规定，否则现在*共享*基类子对象的默认构造函数将被调用。即使在中间级别指定了非默认构造函数，当中间级别指定了一个可能共享的虚基类时，这些规定也会被忽略。

## 复制构造函数

对于包含指针数据成员的所有对象来说，复制构造函数是至关重要的。除非程序员提供了复制构造函数，否则系统将在应用程序中必要时链接系统提供的复制构造函数。系统提供的复制构造函数执行所有数据成员的成员逐一（浅层）复制。这意味着一个类的多个实例可能包含指向共享内存块的指针，这些内存块代表应该是个体化的数据。此外，记得在派生类的复制构造函数中使用成员初始化列表来指定基类的复制构造函数以复制基类的数据成员。当然，在深度方式中复制基类子对象是至关重要的；此外，基类数据成员不可避免地是私有的，因此在派生类的成员初始化列表中选择基类复制构造函数非常重要。

通过指定一个复制构造函数，我们还帮助提供了一个对象通过值从函数传递（或返回）的预期方式。在这些情况下确保深层复制是至关重要的。用户可能认为这些复制是“通过值”，但如果它们的指针数据成员实际上与源实例共享，那么它实际上并不是通过值传递（或返回）对象。

## 过载的赋值运算符

一个**重载的赋值运算符**，就像复制构造函数一样，对于所有包含指针数据成员的对象也是至关重要的。系统提供的赋值运算符的默认行为是从源对象到目标对象的浅赋值。同样，当数据成员是指针时，强烈建议重载赋值运算符以为任何这样的指针数据成员分配空间。

另外，请记住，重载的赋值运算符不会*继承*；每个类都负责编写自己的版本。这是有道理的，因为派生类不可避免地有更多的数据成员需要复制，而其基类中的赋值运算符则可能是私有的或无法访问的。然而，在派生类中重载赋值运算符时，请记住调用基类的赋值运算符来执行继承的基类成员的深度赋值（这些成员可能是私有的或无法访问的）。

## 虚析构函数

虚析构函数在使用公共继承时是必需的。通常，派生类实例被收集在一组中，并由一组基类指针进行泛化。请记住，以这种方式进行向上转型只可能对公共基类进行（而不是对受保护或私有基类）。当以这种方式对对象的指针进行泛化时，虚析构函数对于通过动态（即运行时）绑定确定正确的析构函数起始点至关重要，而不是静态绑定。请记住，静态绑定会根据指针的类型选择起始析构函数，而不是对象实际的类型。一个很好的经验法则是，如果一个类有一个或多个虚函数，请确保你也有一个虚析构函数。

## 移动复制构造函数

一个`this`。然后我们必须将源对象的指针置空，以便这两个实例不共享动态分配的数据成员。实质上，我们已经移动了（内存中的）指针数据成员。

那么非指针数据成员呢？这些数据成员的内存将像往常一样被复制。非指针数据成员的内存和指针本身的内存（而不是指针指向的内存）仍然驻留在源实例中。因此，我们能做的最好的事情就是为源对象的指针指定一个空值，并在非指针数据成员中放置一个`0`（或类似的）值，以指示这些成员不再相关。

我们将使用 C++标准库中的`move()`函数来指示移动复制构造函数如下：

```cpp
Person p1("Alexa", "Gutierrez", 'R', "Ms.");
Person p2(move(p1));  // move copy constructor
Person p3 = move(p2); // also the move copy constructor
```

此外，对于通过继承相关的类，我们还将在派生类构造函数的成员初始化列表中使用`move()`。这将指定基类移动复制构造函数来帮助初始化子对象。

## 移动赋值运算符

**移动赋值运算符**与重载的赋值运算符非常相似，但其目标是再次通过*移动*源对象的动态分配数据来节省内存（而不是执行深度赋值）。与重载的赋值运算符一样，我们将测试自我赋值，然后从（已存在的）目标对象中删除任何先前动态分配的数据成员。然后，我们将简单地将源对象中的指针数据成员复制到目标对象中的指针数据成员。我们还将将源对象中的指针置空，以便这两个实例不共享这些动态分配的数据成员。

此外，就像移动复制构造函数一样，非指针数据成员将简单地从源对象复制到目标对象，并在源对象中用`0`值替换以指示不使用。

我们将再次使用`move()`函数如下：

```cpp
Person p3("Alexa", "Gutierrez", 'R', "Ms.");
Person p5("Xander", "LeBrun", 'R', "Dr.");
p5 = move(p3);  // move assignment; replaces p5
```

此外，对于通过继承相关的类，我们可以再次指定派生类的移动赋值运算符将调用基类的移动赋值运算符来帮助完成任务。

## 将规范类形式的组件结合在一起

让我们看一个采用规范类形式的一对类的例子。我们将从我们的`Person`类开始。这个例子可以在我们的 GitHub 上找到一个完整的程序：

[`github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter15/Chp15-Ex1.cpp`](https://github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter15/Chp15-Ex1.cpp)

```cpp
class Person
{
private:    // Assume all usual data members exist
protected:  // Assume usual protected member functions exist 
public:
    Person();                // default constructor
    // Assume other usual constructors exist  
    Person(const Person &);  // copy constructor
    Person(Person &&);       // move copy constructor
    virtual ~Person();       // virtual destructor
    // Assume usual access functions and virtual fns. exist 
    Person &operator=(const Person &);  // assignment operator
    Person &operator=(Person &&);  // move assignment operator
};
// copy constructor
Person::Person(const Person &pers)     
{  
    // Assume deep copy is implemented here  
}
// overloaded assignment operator
Person &Person::operator=(const Person &p)
{
    if (this != &p)  // check for self-assignment
    {
       // Delete existing Person ptr data members for 'this',
       // then re-allocate correct size and copy from source
    }
    return *this;  // allow for cascaded assignments
}
```

在先前的类定义中，我们注意到`Person`包含默认构造函数、复制构造函数、重载赋值运算符和虚析构函数。在这里，我们已经采用了正统的规范类形式作为一个模式，适用于可能有一天作为公共基类的类。还要注意，我们已经添加了移动复制构造函数和移动赋值运算符的原型，以进一步采用扩展的规范类形式。

移动复制构造函数`Person(Person &&);`和移动赋值运算符`Person &operator=(Person &&);`的原型包含类型为`Person &&`的参数。这些是`Person &`的例子，将绑定到原始复制构造函数和重载赋值运算符，而 r 值引用参数将绑定到适用的移动方法。

现在让我们看一下有助于`Person`扩展规范类形式的方法定义 - 移动复制构造函数和移动赋值运算符：

```cpp
// move copy constructor
Person::Person(const Person &&pers)   
{   // overtake source object's dynamically allocated memory
    // and null-out source object's pointers to that memory
    firstName = pers.firstName;
    pers.firstName = 0;
    lastName = pers.lastName;
    pers.lastName = 0;
    middleInitial = pers.middleInitial;
    pers.middleInitial = '\0'; // null char indicates non-use
    title = pers.title;
    pers.title = 0;
}
// move overloaded assignment operator
Person &Person::operator=(const Person &p)
{ 
    if (this != &p)       // check for self-assignment
    {
        delete firstName;  // or call ~Person(); (unusual)
        delete lastName;   // Delete existing object's
        delete title;      // allocated data members
        // overtake source object's dynamically alloc memory
        // and null source object's pointers to that memory
        firstName = p.firstName;
        p.firstName = 0;
        lastName = p.lastName;
        p.lastName = 0;
        middleInitial = p.middleInitial;
        p.middleInitial = '\0'; // null char indicates non-use
        title = p.title;
        p.title = 0;   
    }
    return *this;  // allow for cascaded assignments  
}
```

请注意，在前面的移动复制构造函数中，我们通过简单的指针赋值（而不是内存分配，如我们在深复制构造函数中所使用的）接管源对象的动态分配内存。然后我们在源对象的指针数据成员中放置一个空值。对于非指针数据成员，我们只是将值从源对象复制到目标对象，并在源对象中放置一个零值（例如`p.middleInitial`的`'\0'`）以表示其进一步的非使用。

在移动赋值运算符中，我们检查自我赋值，然后采用相同的方案，仅仅通过简单的指针赋值将动态分配的内存从源对象移动到目标对象。我们也复制简单的数据成员，并且当然用空指针或零值替换源对象数据值，以表示进一步的非使用。`*this`的返回值允许级联赋值。

现在，让我们看看派生类`Student`如何在利用其基类组件来辅助实现选定的成语方法时，同时使用正统和扩展的规范类形式：

```cpp
class Student: public Person
{
private:  // Assume usual data members exist
public:
    Student();                 // default constructor
    // Assume other usual constructors exist  
    Student(const Student &);  // copy constructor
    Student(Student &&);       // move copy constructor
    virtual ~Student();        // virtual destructor
    // Assume usual access functions exist 
    // as well as virtual overrides and additional methods
    Student &operator=(const Student &);  // assignment op.
    Student &operator=(Student &&);  // move assignment op.
};
// copy constructor
Student::Student(const Student &s): Person(s)
{   // Use member init. list to specify base copy constructor
    // to initialize base sub-object
    // Assume deep copy for Student is implemented here  
}
// Overloaded assignment operator
Student &Student::operator=(const Student &s)
{
   if (this != &s)   // check for self-assignment
   {
       Person::operator=(s);  // call base class assignment op
       // delete existing Student ptr data members for 'this'
       // then reallocate correct size and copy from source
   }
}
```

在先前的类定义中，我们再次看到`Student`包含默认构造函数、复制构造函数、重载赋值运算符和虚析构函数，以完成正统的规范类形式。

然而，请注意，在`Student`复制构造函数中，我们通过成员初始化列表指定了`Person`复制构造函数的使用。同样，在`Student`重载赋值运算符中，一旦我们检查自我赋值，我们调用`Person`中的重载赋值运算符来帮助我们使用`Person::operator=(s);`完成任务。

现在让我们看一下有助于`Student`扩展规范类形式的方法定义 - 移动复制构造函数和移动赋值运算符：

```cpp
// move copy constructor
Student::Student(Student &&ps): Person(move(ps))   
{   // Use member init. list to specify base move copy 
    // constructor to initialize base sub-object
    gpa = ps.gpa;
    ps.gpa = 0.0;
    currentCourse = ps.currentCourse;
    ps.currentCourse = 0;
    studentId = ps.studentId;  
    ps.studentId = 0;
}
// move assignment operator
Student &Student::operator=(Student &&s)
{
   // make sure we're not assigning an object to itself
   if (this != &s)
   {
      Person::operator=(move(s));  // call base move oper=
      delete currentCourse;  // delete existing data members
      delete studentId;
      gpa = s.gpa;  
      s.gpa = 0.0;
      currentCourse = s.currentCourse;
      s.currentCourse = 0;
      studentId = s.studentId;
      s.studentId = 0;
   }
   return *this;  // allow for cascaded assignments
}
```

请注意，在先前列出的`Student`移动复制构造函数中，我们在成员初始化列表中指定了基类的移动复制构造函数的使用。`Student`移动复制构造函数的其余部分与`Person`基类中的类似。

同样，让我们注意，在`Student`移动赋值运算符中，调用基类的移动`operator=`与`Person::operator=(move(s);`。这个方法的其余部分与基类中的类似。

一个很好的经验法则是，大多数非平凡的类应该至少使用正统的规范类形式。当然，也有例外。例如，一个只用作受保护或私有基类的类不需要具有虚析构函数，因为派生类实例不能通过非公共继承边界向上转型。同样，如果我们有充分的理由不希望复制或禁止赋值，我们可以在这些方法的扩展签名中使用`= delete`规范来禁止复制或赋值。

尽管如此，规范类形式将为采用这种习惯的类增加健壮性。采用这种习惯的类在初始化、赋值和参数传递方面的统一性将受到程序员的重视。

让我们继续来看看与规范类形式相辅相成的一个概念，即健壮性。

## 确保类是健壮的

C++的一个重要特性是能够构建用于广泛重用的类库。无论我们希望实现这个目标，还是只是希望为我们自己组织的使用提供可靠的代码，重要的是我们的代码是健壮的。一个健壮的类将经过充分测试，应该遵循规范的类形式（除了在受保护和私有基类中需要虚析构函数），并且是可移植的（或包含在特定平台的库中）。任何候选重用的类，或者将在任何专业环境中使用的类，绝对必须是健壮的。

健壮的类必须确保给定类的所有实例都完全构造。**完全构造的对象**是指所有数据成员都得到适当初始化的对象。必须验证给定类的所有构造函数（包括复制构造函数）以初始化所有数据成员。应检查加载数据成员的值是否适合范围。记住，未初始化的数据成员是潜在的灾难！应该在给定构造函数未能正确完成或数据成员的初始值不合适的情况下采取预防措施。

可以使用各种技术来验证完全构造的对象。一种基本的技术是在每个类中嵌入一个状态数据成员（或派生或嵌入一个状态祖先/成员）。在成员初始化列表中将状态成员设置为`0`，并在构造函数的最后一行将其设置为`1`。在实例化后探测这个值。这种方法的巨大缺陷是用户肯定会忘记探测*完全构造*的成功标志。

一个更好的技术是利用异常处理。在每个构造函数内嵌异常处理是理想的。如果数据成员未在合适范围内初始化，首先尝试重新输入它们的值，或者例如打开备用数据库进行输入。作为最后手段，您可以抛出异常来报告*未完全构造的对象*。我们将在本章后面更仔细地研究关于测试的异常处理。

与此同时，让我们继续使用一种技术来严格测试我们的类和组件——创建驱动程序来测试类。

# 创建驱动程序来测试类

在*第五章*中，*详细探讨类*，我们简要讨论了将代码分解为源文件和头文件的方法。让我们简要回顾一下。通常，头文件将以类的名称命名（如`Student.h`），并包含类定义，以及任何内联成员函数定义。通过将内联函数放在头文件中，它们将在其实现更改时被正确地重新扩展（因为头文件随后包含在每个源文件中，与该头文件创建了依赖关系）。

每个类的方法实现将被放置在相应的源代码文件中（比如`Student.cpp`），它将包括它所基于的头文件（即`#include "Student.h"`）。请注意，双引号意味着这个头文件在我们当前的工作目录中；我们也可以指定一个路径来找到头文件。相比之下，C++库使用的尖括号告诉预处理器在编译器预先指定的目录中查找。另外，请注意，每个派生类的头文件将包括其基类的头文件（以便它可以看到成员函数的原型）。

考虑到这种头文件和源代码文件结构，我们现在可以创建一个驱动程序来测试每个单独的类或每组紧密相关的类（例如通过关联或聚合相关的类）。通过继承相关的类可以在它们自己的单独的驱动程序文件中进行测试。每个驱动程序文件可以被命名为反映正在测试的类的名称，比如`StudentDriver.cpp`。驱动程序文件将包括正在测试的类的相关头文件。当然，所涉及类的源文件将作为编译过程的一部分被编译和链接到驱动程序文件中。

驱动程序文件可以简单地包含一个`main()`函数，作为一个测试平台来实例化相关的类，并作为测试每个成员函数的范围。驱动程序将测试默认实例化、典型实例化、复制构造、对象之间的赋值，以及类中的每个附加方法。如果存在虚析构函数或其他虚函数，我们应该实例化派生类实例（在派生类的驱动程序中），将这些实例向上转型为基类指针进行存储，然后调用虚函数以验证发生了正确的行为。在虚析构函数的情况下，我们可以通过删除动态分配的实例（或等待栈实例超出范围）并通过调试器逐步验证一切是否符合预期来跟踪销毁顺序的入口点。

我们还可以测试对象是否完全构造；我们很快将在这个主题上看到更多。

假设我们有我们通常的`Person`和`Student`类层次结构，这里有一个简单的驱动程序来测试`Student`类。这个驱动程序可以在我们的 GitHub 存储库中找到。为了创建一个完整的程序，您还需要编译和链接在同一目录中找到的`Student.cpp`和`Person.cpp`文件。这是驱动程序的 GitHub URL：

[`github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter15/Chp15-Ex2.cpp`](https://github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter15/Chp15-Ex2.cpp)

```cpp
#include "Person.h"    // include relevant class header files
#include "Student.h"
using namespace std;
const int MAX = 3;
int main()   // Driver to test Student class. Stored in above
{            // filename for chapter example consistency 
    // Test all means for instantiation, including copy const.
    Student s0; // Default construction
    // alternate constructor
    Student s1("Jo", "Li", 'H', "Ms.", 3.7, "C++", "UD1234");
    Student s2("Sam", "Lo", 'A', "Mr.", 3.5, "C++", "UD2245");
    // These initializations implicitly invoke copy const.
    Student s3(s1);
    Student s4 = s2;   // This is also initialization
    // Test the assignment operator
    Student s5("Ren", "Ze", 'A', "Dr.", 3.8, "C++", "BU5563");
    Student s6;
    s6 = s5;  // this is an assignment, not initialization
    // Test each public method. A sample is shown here
    s1.Print();  // Be sure to test each method! 

    // Generalize derived instances as base types 
    // Do the polymorphic operations work as expected?
    Person *people[MAX];
    // base instance for comparison
    people[0] = new Person("Juliet", "Martinez", 'M', "Ms.");
    // derived instances, generalized with base class ptrs.   
    people[1] = new Student("Zack", "Moon", 'R', "Dr.", 3.8,
                            "C++", "UMD1234");  
    people[2] = new Student("Gabby", "Doone", 'A', "Dr.", 3.9,
                            "C++", "GWU4321");
    for (int i = 0; i < MAX; i++)
    {
       people[i]->IsA();
       cout << "  ";
       people[i]->Print();
    }
    // Test destruction sequence (dynam. allocated instances)
    for (int i = 0; i < MAX; i++)
       delete people[i];   // engage virtual dest. sequence
    return 0;
}
```

简要回顾前面的程序片段，我们可以看到我们已经测试了每种实例化方式，包括复制构造函数。我们还测试了赋值运算符，验证了每个成员函数的工作（示例方法显示了），并验证了虚函数（包括虚析构函数）按预期工作。

既然我们已经看到了一个基本的驱动程序测试我们的类，让我们考虑一些额外的指标，当测试通过继承、关联或聚合相关的类时可以使用。

# 测试相关类

对于面向对象的程序，仅仅测试单个类的完整性和健壮性是不够的，尽管这些是很好的起点。完整性不仅包括遵循规范的类形式，还包括确保数据成员具有安全的访问方式，使用适当的访问方法（在不修改实例时标记为`const`）。完整性还验证了按照面向对象设计规范实现了所需的接口。

健壮性要求我们验证所有上述方法是否在适当的驱动程序中进行了测试，评估其平台独立性，并验证每种实例化方式是否导致完全构造的对象。我们可以通过对实例的数据成员进行阈值测试来增强这种类型的测试，注意当抛出异常时。完整性和健壮性，尽管看似全面，实际上是 OO 组件测试最直接的手段。

测试相关类之间交互的一种更具挑战性的手段是测试聚合和关联之间的交互。

## 通过继承、关联或聚合相关的类进行测试

通过各种对象关系相关的类需要各种额外的组件测试手段。具有各种关系的对象之间的相互影响可能会影响应用程序中给定实例的生命周期内的状态变化。这种类型的测试将需要最详细的努力。我们会发现场景对于帮助我们捕捉相关对象之间的常规交互是有用的，从而导致更全面的测试相互交互的类的方式。

让我们首先考虑如何测试通过继承相关的类。

### 添加测试继承的策略

通过公共继承相关的类需要验证虚函数。例如，所有预期的派生类方法是否已被覆盖？记住，如果基类行为在派生类级别仍然被认为是适当的，那么派生类不需要覆盖其基类中指定的所有虚函数。将需要将实现与设计进行比较，以确保我们已经用适当的方法覆盖了所有必需的多态操作。

当然，虚函数的绑定是在运行时完成的（即动态绑定）。重要的是创建派生类实例并使用基类指针存储它们，以便可以应用多态操作。然后我们需要验证派生类的行为是否突出。如果没有，也许我们会发现自己处于一个意外的函数隐藏情况，或者基类操作没有像预期的那样标记为虚拟（请记住，虚拟和覆盖关键字在派生类级别，虽然很好并且推荐，但是是可选的，不会影响动态行为）。

尽管通过继承相关的类具有独特的测试策略，但要记住实例化将创建一个单一对象，即基类或派生类类型的对象。当我们实例化这样的类型时，我们有一个实例，而不是一对共同工作的实例。派生类仅具有基类子对象，该子对象是其自身的一部分。让我们考虑一下这与关联对象或聚合物的比较，它们可以是单独的对象（关联），可能与其伴侣进行交互。

### 添加测试聚合和关联的策略

通过关联或聚合相关的类可能是多个实例之间的通信，并且彼此引起状态变化。这显然比继承的对象关系更复杂。

通过聚合相关的类通常比通过关联相关的类更容易测试。考虑到最常见的聚合形式（组合），内嵌（内部）对象是外部（整体）对象的一部分。当实例化外部对象时，我们得到内部对象嵌入在“整体”中的内存。与包含基类子对象的派生类实例的内存布局相比，内存布局并没有非常不同（除了可能的排序）。在每种情况下，我们仍然处理单个实例（即使它有嵌入的“部分”）。然而，与测试进行比较的重点是，应用于“整体”的操作通常被委托给“部分”或组件。我们将严格需要测试整体上的操作，以确保它们将必要的信息委托给每个部分。

通过一般聚合的较少使用的形式相关的类（其中整体包含指向部分的指针，而不是典型的组合的嵌入对象实现）与关联有类似的问题，因为实现是相似的。考虑到这一点，让我们来看看与相关对象有关的测试问题。

通过关联相关的类通常是独立存在的对象，在应用程序的某个时刻彼此创建了链接。在应用于一个对象上的操作可能会导致关联对象的变化。例如，让我们考虑一个“学生”和一个“课程”。两者可能独立存在，然后在应用程序的某个时刻，“学生”可能通过`Student::AddCourse()`添加一个“课程”。通过这样做，不仅特定的“学生”实例现在包含到特定的“课程”实例的链接中，而且`Student::AddCourse()`操作已经导致了“课程”类的变化。特定的“学生”实例现在是特定“课程”实例名单的一部分。在任何时候，“课程”可能被取消，从而影响到所有已经在该“课程”中注册的“学生”实例。这些变化反映了每个关联对象可能存在的状态。例如，“学生”可能处于“当前注册”或“退出”“课程”的状态。有很多可能性。我们如何测试它们？

### 添加场景以帮助测试对象关系

在面向对象分析中，场景的概念被提出作为创建 OO 设计和测试的手段。**场景**是对应用程序中可能发生的一系列事件的描述性步行。场景将展示类以及它们如何在特定情况下相互作用。许多相关场景可以被收集到 OO 概念的**用例**中。在 OO 分析和设计阶段，场景有助于确定应用程序中可能存在的类，以及每个类可能具有的操作和关系。在测试中，场景可以被重复使用，形成测试各种对象关系的驱动程序创建的基础。考虑到这一点，可以开发一系列驱动程序来测试多种场景（即用例）。这种建模方式将更彻底地为相关对象提供一个测试基础，而不仅仅是最初的简单测试完整性和健壮性的手段。

与任何类型的相关类之间的另一个关注领域是版本控制。例如，如果基类定义或默认行为发生了变化会发生什么？这将如何影响派生类？这将如何影响相关对象？随着每次变化，我们不可避免地需要重新审视所有相关类的组件测试。

接下来，让我们考虑异常处理机制如何影响 OO 组件测试。

# 测试异常处理机制

现在我们可以创建驱动程序来测试每个类（或一组相关类），我们将想要了解我们代码中哪些方法可能会抛出异常。对于这些情况，我们将希望在驱动程序中添加 try 块，以确保我们知道如何处理每个可能抛出的异常。在这样做之前，我们应该问自己，在开发过程中我们的代码是否包含了足够的异常处理？例如，考虑实例化，我们的构造函数是否检查对象是否完全构造？如果没有，它们会抛出异常吗？如果答案是否定的，我们的类可能不像我们预期的那样健壮。

让我们考虑将异常处理嵌入到构造函数中，以及我们如何构建一个驱动程序来测试所有可能的实例化方式。

## 将异常处理嵌入到构造函数中以创建健壮的类

我们可能还记得我们最近的*第十一章*，*处理异常*，我们可以创建自己的异常类，从 C++标准库`exception`类派生而来。假设我们已经创建了这样一个类，即`ConstructionException`。如果在构造函数的任何时候我们无法正确初始化给定实例以提供一个完全构造的对象，我们可以从任何构造函数中抛出`ConstructionException`。潜在抛出`ConstructionException`的含义是我们现在应该在 try 块中封闭实例化，并添加匹配的 catch 块来预期可能抛出的`ConstructionException`。然而，请记住，在 try 块范围内声明的实例只在 try-catch 配对内部有效。

好消息是，如果一个对象没有完成构造（也就是说，在构造函数完成之前抛出异常），那么这个对象在技术上就不存在。如果一个对象在技术上不存在，就不需要清理部分实例化的对象。然而，我们需要考虑如果我们预期的实例没有完全构造，这对我们的应用意味着什么。这将如何改变我们代码中的进展？测试的一部分是确保我们已经考虑了我们的代码可能被使用的所有方式，并相应地进行防护！

重要的是要注意，引入`try`和`catch`块可能会改变我们的程序流程，包括这种类型的测试对我们的驱动程序是至关重要的。我们可能会寻找考虑`try`和`catch`块的场景，当我们进行测试时。

我们现在已经看到了如何增强我们的测试驱动程序以适应可能抛出异常的类。在本章中，我们还讨论了在我们的驱动程序中添加场景，以帮助跟踪具有关系的对象之间的状态，当然，我们还讨论了可以遵循的简单类习惯，以便为成功做好准备。在继续下一章之前，让我们简要回顾一下这些概念。

# 总结

在本章中，我们通过检查各种 OO 类和组件测试实践和策略，增强了成为更好的 C++程序员的能力。我们的主要目标是确保我们的代码是健壮的，经过充分测试，并且可以无错误地部署到我们的各个组织中。

我们已经考虑了编程习惯，比如遵循规范的类形式，以确保我们的类是完整的，并且在构造/销毁、赋值以及在参数传递和作为函数返回值中的使用方面具有预期的行为。我们已经讨论了创建健壮类的含义 - 一个遵循规范的类形式，也经过充分测试，独立于平台，并且针对完全构造的对象进行了测试。

我们还探讨了如何创建驱动程序来测试单个类或一组相关类。我们已经建立了一个测试单个类的项目清单。我们更深入地研究了对象关系，以了解彼此交互的对象需要更复杂的测试。也就是说，当对象从一种状态转移到另一种状态时，它们可能会受到相关对象的影响，这可能会进一步改变它们的进展方向。我们已经添加了使用场景作为我们的驱动程序的测试用例，以更好地捕捉实例可能在应用程序中移动的动态状态。

最后，我们已经看了一下异常处理机制如何影响我们测试代码，增强我们的驱动程序以考虑 try 和 catch 块在我们的应用程序中可能操纵的控制流。

我们现在准备继续我们书的下一部分，C++中的设计模式和习惯用法。我们将从*第十六章*开始，*使用观察者模式*。在剩下的章节中，我们将了解如何应用流行的设计模式，在我们的编码中使用它们。这些技能将使我们成为更好的程序员。让我们继续前进！

# 问题

1.  考虑一对包含对象关系的类，来自你以前的练习（提示：公共继承比关联更容易考虑）。

a. 你的类遵循规范的类形式吗？是正统的还是扩展的？为什么？如果不是，而应该是，修改类以遵循这种习惯用法。

b. 你认为你的类健壮吗？为什么？为什么不？

1.  创建一个（或两个）驱动程序来测试你的一对类。

a. 确保测试通常的项目清单（构造、赋值、销毁、公共接口、向上转型（如果适用）和使用虚函数）。

b.（可选）如果您选择了两个与关联相关的类，请创建一个单独的驱动程序，以详细描述这两个类的交互的典型场景。

c. 确保在您的一个测试驱动程序中包括异常处理的测试。

1.  创建一个`ConstructionException`类（从 C++标准库`exception`派生）。在样本类的构造函数中嵌入检查，以在必要时抛出`ConstructionException`。确保将此类的所有实例化形式都包含在适当的`try`和`catch`块配对中。


# 第四部分：C++中的设计模式和习惯用法

本节的目标是扩展您的 C++技能，超越面向对象编程和其他必要的技能，包括核心设计模式的知识。设计模式提供了解决面向对象问题的经过验证的技术和策略。本节介绍了常见的设计模式，并深入演示了如何通过在书中以创造性的方式构建在先前示例的基础上应用这些模式。每一章都包含详细的代码示例来说明每个模式。

本节的初始章节介绍了设计模式的概念，并讨论了在编码解决方案中利用这些模式的优势。初始章节还介绍了观察者模式，并提供了一个深入的程序来欣赏这种模式的各个组成部分。

下一章解释了工厂方法模式，并提供了详细的程序，展示了如何使用对象工厂来实现工厂方法模式。此外，本章还将对象工厂与抽象工厂进行了比较。

下一章介绍了适配器模式，并提供了使用继承与关联来实现适配器类的实现策略和程序示例。此外，还说明了适配器作为一个简单的包装类。

下一章将讨论单例模式。在介绍一个简单的例子之后，将演示一个配对类的实现，并提供详细的示例。还介绍了用于容纳单例的注册表。

本节和本书的最后一章介绍了 pImpl 模式，以减少代码中的编译时间依赖关系。提供了一个基本的实现，然后使用唯一指针进行了扩展。还进一步探讨了与这种模式相关的性能问题。

本节包括以下章节：

+   [*第十六章*]（B15702_16_Final_NM_ePub.xhtml#_idTextAnchor622）*，使用观察者模式*

+   [*第十七章*]（B15702_17_Final_NM_ePub.xhtml#_idTextAnchor649）*，应用工厂模式*

+   [*第十八章*]（B15702_18_Final_NM_ePub.xhtml#_idTextAnchor682）*，应用适配器模式*

+   [*第十九章*]（B15702_19_Final_NM_ePub.xhtml#_idTextAnchor718）*，使用单例模式*

+   [*第二十章*]（B15702_20_Final_NM_ePub.xhtml#_idTextAnchor756）*，使用 pImpl 模式去除实现细节*


# 第十六章：使用观察者模式

本章将开始我们的探索，将您的 C++编程技能库扩展到 OOP 概念之外，目标是使您能够通过利用常见的设计模式来解决重复出现的编码问题。设计模式还将增强代码维护，并为潜在的代码重用提供途径。本书的第四部分，从本章开始，旨在演示和解释流行的设计模式和习语，并学习如何在 C++中有效实现它们。

在本章中，我们将涵盖以下主要主题：

+   理解利用设计模式的优势

+   理解观察者模式及其对面向对象编程的贡献

+   理解如何在 C++中实现观察者模式

通过本章结束，您将了解在您的代码中使用设计模式的效用，以及了解流行的**观察者模式**。我们将在 C++中看到这种模式的示例实现。利用常见的设计模式将帮助您成为一个更有益和有价值的程序员，使您能够接纳更复杂的编程技术。

让我们通过研究各种设计模式来增强我们的编程技能，从本章开始使用观察者模式。

# 技术要求

完整程序示例的在线代码可以在以下 GitHub URL 找到：[`github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter16`](https://github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter16)。每个完整程序示例都可以在 GitHub 存储库中找到，位于相应章节标题（子目录）下的文件中，该文件与所在章节编号对应，后跟破折号，再跟所在章节中示例编号。例如，本章的第一个完整程序可以在子目录`Chapter16`中的名为`Chp16-Ex1.cpp`的文件中找到，该文件位于上述 GitHub 目录下。

本章的 CiA 视频可以在以下链接观看：[`bit.ly/3vYprq2`](https://bit.ly/3vYprq2)。

# 利用设计模式

**设计模式**代表了针对重复出现的编程难题的一组经过充分测试的编程解决方案。设计模式代表了设计问题的高级概念，以及类之间的通用协作如何提供解决方案，可以以多种方式实现。

在过去 25 年多的软件开发中，已经识别和描述了许多设计模式。我们将在本书的剩余章节中查看一些流行的模式，以便让您了解如何将流行的软件设计解决方案纳入我们的编码技术库中。

为什么我们选择使用设计模式？首先，一旦我们确定了一种编程问题类型，我们可以利用其他程序员充分测试过的*经过验证的*解决方案。此外，一旦我们使用了设计模式，其他程序员在沉浸于我们的代码（用于维护或未来增强）时，将对我们选择的技术有基本的了解，因为核心设计模式已成为行业标准。

一些最早的设计模式大约 50 年前出现，随着**模型-视图-控制器**范式的出现，后来有时简化为**主题-视图**。例如，主题-视图是一个基本的模式，其中一个感兴趣的对象（**主题**）将与其显示方法（**视图**）松散耦合。主题及其视图之间有一对一的关联。有时主题可以有多个视图，这种情况下，主题与许多视图对象相关联。如果一个视图发生变化，状态更新可以发送到主题，然后主题可以向其他视图发送必要的消息，以便它们也可以更新以反映新状态可能如何修改它们的特定视图。

最初的**模型-视图-控制器**（**MVC**）模式，源自早期的面向对象编程语言，如 Smalltalk，具有类似的前提，只是控制器对象在模型（即主题）和其视图（或视图）之间委托事件。这些初步范例影响了早期的设计模式；主题-视图或 MVC 的元素在概念上可以被视为今天核心设计模式的基础。

我们将在本书的其余部分中审查的许多设计模式都是由*四人组*（Erich Gamma，Richard Helm，Ralph Johnson 和 John Vlissides）在*设计模式，可重用面向对象软件的元素*中最初描述的模式的改编。我们将应用和调整这些模式来解决我们在本书早期章节中介绍的应用程序所引发的问题。

让我们开始我们对理解和利用流行设计模式的追求，通过调查一个正在实施的模式。我们将从一个被称为**观察者模式**的行为模式开始。

# 理解观察者模式

在**观察者模式**中，一个感兴趣的对象将维护一个对主要对象状态更新感兴趣的观察者列表。观察者将维护与他们感兴趣的对象的链接。我们将主要感兴趣的对象称为**主题**。感兴趣的对象列表统称为**观察者**。主题将通知任何观察者相关状态的变化。一旦观察者被通知主题的任何状态变化，它们将自行采取任何适当的下一步行动（通常通过主题在每个观察者上调用的虚函数来执行）。

我们已经可以想象如何使用关联来实现观察者模式。事实上，观察者代表了一对多的关联。例如，主题可以使用 STL 的`list`（或`vector`）来收集一组观察者。每个观察者将包含与主题的关联。我们可以想象主题上的一个重要操作，对应于主题中的状态改变，发出对其观察者列表的更新，以*通知*它们状态的改变。`Notify()`方法实际上是在主题的状态改变时被调用，并统一地应用于主题的观察者列表上的多态观察者`Update()`方法。在我们陷入实现之前，让我们考虑构成观察者模式的关键组件。

观察者模式将包括：

+   主题，或感兴趣的对象。主题将维护一个观察者对象的列表（多边关联）。

+   主题将提供一个接口来`Register()`或`Remove()`一个观察者。

+   主题将包括一个`Notify()`接口，当主题的状态发生变化时，将更新其观察者。主题将通过在其集合中的每个观察者上调用多态的`Update()`方法来`Notify()`观察者。

+   观察者类将被建模为一个抽象类（或接口）。

+   观察者接口将提供一个抽象的、多态的`Update()`方法，当其关联的主题改变其状态时将被调用。

+   从每个 Observer 到其 Subject 的关联将在一个具体类中维护，该类派生自 Observer。这样做将减轻尴尬的转换（与在抽象 Observer 类中维护 Subject 链接相比）。

+   两个类将能够维护它们的当前状态。

上述的 Subject 和 Observer 类是通用指定的，以便它们可以与各种具体类（主要通过继承）结合使用观察者模式。通用的 Subject 和 Observer 提供了很好的重用机会。通过设计模式，模式的许多核心元素通常可以更通用地设置，以允许代码本身更大程度的重用，不仅是解决方案概念的重用。

让我们继续看观察者模式的一个示例实现。

# 实现观察者模式

为了实现观察者模式，我们首先需要定义我们的`Subject`和`Observer`类。然后，我们需要从这些类派生具体类，以合并我们的应用程序特定内容并启动我们的模式。让我们开始吧！

## 创建 Observer、Subject 和特定领域的派生类

在我们的示例中，我们将创建`Subject`和`Observer`类来建立*注册*`Observer`与`Subject`以及`Subject`通知其一组观察者可能存在的状态更改的框架。然后，我们将从这些基类派生出我们习惯看到的派生类 - `Course`和`Student`，其中`Course`将是我们的具体`Subject`，而`Student`将成为我们的具体`Observer`。

我们将建模的应用程序涉及课程注册系统和等待列表的概念。正如我们之前在*第十章*的*问题 2*中所看到的，*实现关联、聚合和组合*，我们将对`Student`进行建模，将其与许多`Course`实例关联，并且`Course`与许多`Student`实例关联。当我们建模我们的等待列表时，观察者模式将发挥作用。

我们的`Course`类将派生自`Subject`。我们的`Course`将继承的观察者列表将代表这个`Course`等待列表上的`Student`实例。 `Course`还将有一个`Student`实例列表，代表已成功注册该课程的学生。

我们的`Student`类将派生自`Person`和`Observer`。 `Student`将包括`Student`当前注册的`Course`实例列表。 `Student`还将有一个成员，`waitList`，它将对应于`Student`正在等待的`Course`的关联。这个*等待列表*`Course`代表我们将收到通知的`Subject`。通知将对应于状态更改，指示`Course`现在有空间让`Student`添加`Course`。

正是从`Observer`那里，`Student`将继承多态操作`Update()`，这将对应于`Student`被通知现在`Course`中有一个空位。在这里，在`Student::Update()`中，我们将添加机制，将`Student`从等待列表（有一个`waitList`数据成员）移动到`Course`中的实际当前学生列表（以及该学生的当前课程列表）。

### 指定 Observer 和 Subject

让我们将我们的示例分解成组件，从指定我们的`Observer`和`Subject`类开始。完整的程序可以在我们的 GitHub 上找到：

[`github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter16/Chp16-Ex1.cpp`](https://github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter16/Chp16-Ex1.cpp)

```cpp
#include <list>   // partial list of #includes
#include <iterator>
using namespace std;
const int MAXCOURSES = 5, MAXSTUDENTS = 5;
class Subject;  // forward declarations
class Student;
class Observer  // Observer is an abstract class
{
private:
    int observerState;
protected:
    Observer() { observerState = 0; }
    Observer(int s) { observerState = s; }
    void SetState(int s) { observerState = s; }
public:
    int GetState() const { return observerState; }
    virtual ~Observer() {}
    virtual void Update() = 0;
};
```

在前面的类定义中，我们介绍了我们的抽象`Observer`类。在这里，我们包括一个`observerState`和受保护的构造函数来初始化这个状态。我们包括一个受保护的`SetState()`方法，以便从派生类的范围更新这个状态。我们还包括一个公共的`GetState()`方法。`GetState()`的添加将通过允许我们轻松检查`Observer`的状态是否已更改，有助于在我们的`Subject`的`Notify()`方法中实现。尽管状态信息历来是添加到`Observer`和`Subject`的派生类中，但我们将在这些基类中通用化状态信息。这将使我们的派生类保持更加独立于模式，并集中于应用程序的本质。

请注意，我们的析构函数是虚拟的，并且我们引入了一个抽象方法`virtual void Update() = 0;`来指定我们的`Subject`将在其观察者列表上调用的接口，以将更新委托给这些`Observer`实例。

现在，让我们来看看我们的`Subject`基类：

```cpp
class Subject   // Treated as an abstract class, due to
{               // protected constructors. However, there's no 
private:        // pure virtual function
    list<class Observer *> observers;
    int numObservers;
    int subjectState;
    list<Observer *>::iterator newIter;
protected:
    Subject() { subjectState = 0; numObservers = 0; }
    Subject(int s) { subjectState = s; numObservers = 0; }
    void SetState(int s) { subjectState = s; }
public:
    int GetState() const { return subjectState; }
    int GetNumObservers() const { return numObservers; }
    virtual ~Subject() {}
    virtual void Register(Observer *);
    virtual void Release(Observer *);
    virtual void Notify();
};
```

在上述的`Subject`类定义中，我们看到我们的`Subject`包括一个 STL`list`来收集它的`Observer`实例。它还包括`subjectState`和一个计数器来反映观察者的数量。此外，我们还包括一个数据成员来跟踪一个未损坏的迭代器。一旦我们擦除一个元素（`list::erase()`是一个会使当前迭代器失效的操作），我们将看到这将会很方便。

我们的`Subject`类还将具有受保护的构造函数和一个`SetState()`方法，该方法初始化或设置`Subject`的状态。虽然这个类在技术上不是抽象的（它不包含纯虚函数），但它的构造函数是受保护的，以模拟抽象类；这个类只打算作为派生类实例中的子对象来构造。

在公共接口中，我们有一些访问函数来获取当前状态或观察者的数量。我们还有一个虚析构函数，以及`Register()`、`Release()`和`Notify()`的虚函数。我们将在这个基类级别为后三个方法提供实现。

接下来让我们看看在我们的`Subject`基类中`Register()`、`Release()`和`Notify()`的默认实现。

```cpp
void Subject::Register(Observer *ob)
{
    observers.push_back(ob);   // Add an Observer to the list
    numObservers++;
}
void Subject::Release(Observer *ob) // Remove an Observer 
{                                   // from the list
    bool found;
    // loop until we find the desired Observer
    for (list<Observer *>::iterator iter = observers.begin();
         iter != observers.end() && !found; iter++)
    {
        Observer *temp = *iter;
        if (temp == ob)  // if we found observer which we seek
        {
            // erase() element, iterator is now corrupt; Save
            // returned (good) iterator, we'll need it later
            newIter = observers.erase(iter);
            found = true;  // exit loop after found
            numObservers--;
        }
    }
}
void Subject::Notify()
{   // Notify all Observers
    for (list<Observer *>::iterator iter = observers.begin(); 
         iter != observers.end(); iter++)
    {
        Observer *temp = *iter;
        temp->Update(); // AddCourse, then Release Observer   
        // State 1 means we added course, got off waitlist 
        // (waitlist had a Release), so update the iterator
        if (temp->GetState() == 1)
            iter = newIter;  // update the iterator since
    }                        // erase() invalidated this one
    if (observers.size() != 0)
    {   // Update last item on waitlist
        Observer *last = *newIter; 
        last->Update();
    }
}
```

在上述的`Subject`成员函数中，让我们从检查`void Subject::Register(Observer *)`方法开始。在这里，我们只是将指定的`Observer *`添加到我们的 STL 观察者列表中（并增加观察者数量的计数）。

接下来，让我们通过审查`void Subject::Release(Observer *)`来考虑`Register()`的反向操作。在这里，我们遍历观察者列表，直到找到我们正在寻找的观察者。然后我们在当前项目上调用`list::erase()`，将我们的`found`标志设置为`true`（以退出循环），并减少观察者的数量。还要注意，我们保存了`list::erase()`的返回值，这是更新的（有效的）观察者列表的迭代器。循环中的迭代器`iter`在我们调用`list::erase()`时已经失效。我们将这个修改后的迭代器保存在一个数据成员`newIter`中，以便稍后访问它。

最后，让我们来看看`Subject`中的`Notify()`方法。一旦`Subject`中有状态变化，就会调用这个方法。目标是`Update()`所有`Subject`观察者列表上的观察者。为了做到这一点，我们逐个查看我们的列表。我们使用`Observer *temp = *iter;`使用列表迭代器逐个获取`Observer`。我们使用`temp->Update();`在当前`Observer`上调用`Update()`。我们可以通过检查观察者的状态`if (temp->GetState() == 1)`来判断给定`Observer`的更新是否成功。状态为`1`时，我们知道观察者的操作将导致我们刚刚审查的`Release()`函数被调用。因为`Release()`中使用的`list::erase()`已经使迭代器无效，所以我们现在使用`iter = newIter;`获取正确和修订后的迭代器。最后，在循环外，我们在观察者列表中的最后一项上调用`Update()`。

### 从 Subject 和 Observer 派生具体类

让我们继续向前推进这个例子，看看我们从`Subject`或`Observer`派生的具体类。让我们从`Course`开始：

```cpp
class Course: public Subject  
{ // inherits Observer list; represents Students on wait-list
private:
    char *title;
    int number, totalStudents; // course num; total students
    Student *students[MAXSTUDENTS];  // students cur. enrolled
public:
    Course(const char *title, int num): number(num)
    {
        this->title = new char[strlen(title) + 1];
        strcpy(this->title, title);
        totalStudents = 0;
        for (int i = 0; i < MAXSTUDENTS; i++)
            students[i] = 0; 
    }
    virtual ~Course() { delete title; } // There's more work!
    int GetCourseNum() const { return number; }
    const char *GetTitle() const { return title; }
    void Open() { SetState(1); Notify(); } 
    void PrintStudents();
};
bool Course::AddStudent(Student *s)
{  // Should also check Student isn't already added to Course.
    if (totalStudents < MAXSTUDENTS)  // course not full
    {
        students[totalStudents++] = s;
        return true;
    }
    else return false;
}
void Course::PrintStudents()
{
    cout << "Course: (" << GetTitle() << ") has the following
             students: " << endl;
    for (int i = 0; i < MAXSTUDENTS && students[i] != 0; i++)
    {
        cout << "\t" << students[i]->GetFirstName() << " ";
        cout << students[i]->GetLastName() << endl;
    }
}
```

在上述的`Course`类中，我们包括了课程标题和编号的数据成员，以及当前已注册学生的总数。我们还有我们当前已注册学生的列表，用`Student *students[MAXNUMBERSTUDENTS];`表示。此外，请记住我们从基类`Subject`继承了`Observer`的 STL`list`。这个`Observer`实例列表将代表`Course`的等待列表中的`Student`实例。

`Course`类另外包括一个构造函数，一个虚析构函数和简单的访问函数。请注意，虚析构函数的工作比所示的更多 - 如果一个`Course`被销毁，我们必须首先记住从`Course`中删除（但不删除）`Student`实例。我们的`bool Course::AddStudent(Student *)`接口将允许我们向`Course`添加一个`Student`。当然，我们应该确保在这个方法的主体中`Student`尚未添加到`Course`中。

我们的`void Course::Open();`方法将在`Course`上调用，表示该课程现在可以添加学生。在这里，我们首先将状态设置为`1`（表示*开放招生*），然后调用`Notify()`。我们基类`Subject`中的`Notify()`方法循环遍历每个`Observer`，对每个观察者调用多态的`Update()`。每个观察者都是一个`Student`；`Student::Update()`将允许等待列表上的每个`Student`尝试添加现在可以接收学生的`Course`。成功添加到课程的当前学生列表后，`Student`将请求在等待列表上释放其位置（作为`Observer`）。

接下来，让我们来看看我们从`Person`和`Observer`派生的具体类`Student`的类定义：

```cpp
class Person { };  // Assume this is our typical Person class
class Student: public Person, public Observer
{
private:
    float gpa;
    const char *studentId;
    int currentNumCourses;
    Course *courses[MAXCOURSES]; // currently enrolled courses
    // Course we'd like to take - we're on the waitlist. 
    Course *waitList;// This is our Subject (specialized form)
public:
    Student();  // default constructor
    Student(const char *, const char *, char, const char *, 
            float, const char *, Course *);
    Student(const char *, const char *, char, const char *,
            float, const char *);
    Student(const Student &) = delete;  // Copies disallowed
    virtual ~Student();  
    void EarnPhD();
    float GetGpa() const { return gpa; }
    const char *GetStudentId() const { return studentId; }
    virtual void Print() const override;
    virtual void IsA() override;
    virtual void Update() override;
    virtual void Graduate();   // newly introduced virtual fn.
    bool AddCourse(Course *);
    void PrintCourses();
};
```

简要回顾上述`Student`类的类定义，我们可以看到这个类是通过多重继承从`Person`和`Observer`派生的。让我们假设我们的`Person`类就像我们过去多次使用的那样。

除了我们`Student`类的通常组件之外，我们还添加了数据成员`Course *waitList;`，它将模拟与我们的`Subject`的关联。这个数据成员将模拟我们非常希望添加的`Course`，但目前无法添加的*等待列表*课程的概念。请注意，这个链接是以派生类型`Course`而不是基本类型`Subject`声明的。这在观察者模式中很典型，并将帮助我们避免在`Student`中覆盖`Update()`方法时可怕的向下转换。通过这个链接，我们将与我们的`Subject`进行交互，并通过这种方式接收我们的`Subject`状态的更新。

我们还注意到在`Student`中有`virtual void Update() override;`的原型。这个方法将允许我们覆盖`Observer`指定的纯虚拟`Update()`方法。

接下来，让我们审查`Student`的各种新成员函数的选择：

```cpp
// Assume most Student member functions are as we are
// accustomed to seeing. Let's look at those which may differ:
Student::Student(const char *fn, const char *ln, char mi,
                const char *t, float avg, const char *id,
                Course *c) : Person(fn, ln, mi, t), Observer()
{
    // Most data members are set as usual - see online code 
    waitList = c;      // Set waitlist to Course (Subject)
    c->Register(this); // Add the Student (Observer) to 
}                      // the Subject's list of Observers
bool Student::AddCourse(Course *c)
{ 
    // Should also check that Student isn't already in Course
    if (currentNumCourses < MAXCOURSES)
    {
        courses[currentNumCourses++] = c;  // set association
        c->AddStudent(this);               // set back-link
        return true;
    }
    else  // if we can't add the course,
    {     // add Student (Observer) to the Course's Waitlist, 
        c->Register(this);  // stored in Subject base class
        waitList = c;// set Student (Observer) link to Subject
        return false;
    }
}
```

让我们回顾之前列出的成员函数。由于我们已经习惯了`Student`类中大部分必要的组件和机制，我们将专注于新添加的`Student`方法，从一个替代构造函数开始。在这里，让我们假设我们像往常一样设置了大部分数据成员。这里的关键额外代码行是`waitList = c;`将我们的等待列表条目设置为所需的`Course`（`Subject`），以及`c->Register(this);`，其中我们将`Student`（`Observer`）添加到`Subject`的列表（课程的正式等待列表）。

接下来，在我们的`bool Student::AddCourse(Course *)`方法中，我们首先检查是否已超过最大允许的课程数。如果没有，我们将通过机制来添加关联，以在两个方向上链接`Student`和`Course`。也就是说，`courses[currentNumCourses++] = c;`将学生当前的课程列表包含到新的`Course`的关联中，以及`c->AddStudent(this);`要求当前的`Course`将`Student`（`this`）添加到其已注册学生列表中。

让我们继续审查`Student`的其余新成员函数：

```cpp
void Student::Update()
{   // Course state changed to 'Open' so we can now add it.
    if (waitList->GetState() == 1)  
    {
        if (AddCourse(waitList))  // if success in Adding 
        {
            cout << GetFirstName() << " " << GetLastName();
            cout << " removed from waitlist and added to ";
            cout << waitList->GetTitle() << endl;
            SetState(1); // set Obser's state to "Add Success"
            // Remove Student from Course's waitlist
            waitList->Release(this); // Remove Obs from Subj
            waitList = 0;  // Set our link to Subject to Null
        }
    }
}
void Student::PrintCourses()
{
    cout << "Student: (" << GetFirstName() << " ";
    cout << GetLastName() << ") enrolled in: " << endl;
    for (int i = 0; i < MAXCOURSES && courses[i] != 0; i++)
        cout << "\t" << courses[i]->GetTitle() << endl;
}
```

继续我们之前提到的`Student`成员函数的其余部分，接下来，在我们的多态`void Student::Update()`方法中，我们进行了所需的等待列表课程添加。回想一下，当我们的`Subject`（`Course`）上有状态变化时，`Notify()`将被调用。这样的状态变化可能是当一个`Course`*开放注册*，或者可能是在`Student`退出`Course`后现在存在*新的空位可用*的状态。`Notify()`然后在每个`Observer`上调用`Update()`。我们在`Student`中重写了`Update()`来获取`Course`（`Subject`）的状态。如果状态表明`Course`现在*开放注册*，我们尝试`AddCourse(waitList);`。如果成功，我们将`Student`（`Observer`）的状态设置为`1`（*添加成功*），以表明我们在我们的`Update()`中取得了成功，这意味着我们已经添加了`Course`。接下来，因为我们已经将所需的课程添加到了我们当前的课程列表中，我们现在可以从`Course`的等待列表中移除自己。也就是说，我们将使用`waitList->Release(this);`将自己（`Student`）从`Subject`（`Course`的等待列表）中移除。现在我们已经添加了我们想要的等待列表课程，我们还可以使用`waitList = 0;`来移除我们与`Subject`的链接。

最后，我们上述的`Student`代码包括一个方法来打印`Student`当前注册的课程，即`void Student::PrintCourses();`。这个方法非常简单。

### 将模式组件组合在一起

让我们现在通过查看我们的`main()`函数来将所有各种组件组合在一起，看看我们的观察者模式是如何被编排的：

```cpp
int main()
{   // Instantiate several courses
    Course *c1 = new Course("C++", 230);  
    Course *c2 = new Course("Advanced C++", 430);
    Course *c3 = new Course("Design Patterns in C++", 550);
    // Instantiate Students, select a course to be on the 
    // waitlist for -- to be added when registration starts
    Student s1("Anne", "Chu", 'M', "Ms.", 3.9, "555CU", c1);
    Student s2("Joley", "Putt", 'I', "Ms.", 3.1, "585UD", c1);
    Student s3("Geoff", "Curt", 'K', "Mr.", 3.1, "667UD", c1);
    Student s4("Ling", "Mau", 'I', "Ms.", 3.1, "55UD", c1);
    Student s5("Jiang", "Wu", 'Q', "Dr.", 3.8, "883TU", c1);
    cout << "Registration is Open. Waitlist Students to be
             added to Courses" << endl;
    // Sends a message to Students that Course is Open. 
    c1->Open();   // Students on wait-list will automatically
    c2->Open();   // be Added (as room allows)
    c3->Open();
    // Now that registration is open, add more courses 
    cout << "During open registration, Students now adding
             additional courses" << endl;
    s1.AddCourse(c2);  // Try to add more courses
    s2.AddCourse(c2);  // If full, we'll be added to wait-list
    s4.AddCourse(c2);  
    s5.AddCourse(c2);  
    s1.AddCourse(c3);  
    s3.AddCourse(c3);  
    s5.AddCourse(c3);
    cout << "Registration complete\n" << endl;
    c1->PrintStudents();   // print each Course's roster
    c2->PrintStudents();
    c3->PrintStudents();
    s1.PrintCourses();     // print each Student's course list
    s2.PrintCourses();
    s3.PrintCourses();
    s4.PrintCourses();
    s5.PrintCourses();
    delete c1;
    delete c2;
    delete c3;
    return 0;
}
```

回顾我们之前提到的`main()`函数，我们首先实例化了三个`Course`实例。接下来，我们实例化了五个`Student`实例，利用一个构造函数，允许我们在课程注册开始时提供每个`Student`想要添加的初始`Course`。请注意，这些`Students`（`Observers`）将被添加到他们所需课程的等待列表（`Subject`）。在这里，一个`Subject`（`Course`）将有一个希望在注册开放时添加课程的`Observers`（`Students`）列表。

接下来，我们看到许多`Student`实例都希望的`Course`变为*开放注册*，使用`c1->Open();`进行注册。 `Course::Open()`将`Subject`的状态设置为`1`，表示课程*开放注册*，然后调用`Notify()`。正如我们所知，`Subject::Notify()`将在`Subject`的观察者列表上调用`Update()`。在这里，初始等待列表的`Course`实例将被添加到学生的日程表中，并随后从`Subject`的等待列表中作为`Observer`被移除。

现在注册已经开放，每个`Student`将尝试以通常的方式添加更多课程，比如使用`bool Student::AddCourse(Course *)`，比如`s1.AddCourse(c2);`。如果一个`Course`已满，该`Student`将被添加到`Course`的等待列表（作为继承的`Subject`的观察者列表）。记住，`Course`继承自`Subject`，它保留了对特定课程感兴趣的学生的列表（观察者的等待列表）。当`Course`状态变为*新空间可用*时，等待列表上的学生（观察者）将收到通知，并且每个`Student`的`Update()`方法随后将为该`Student`调用`AddCourse()`。

一旦我们添加了各种课程，我们将看到每个`Course`打印其学生名单，比如`c2->PrintStudents()`。同样，我们将看到每个`Student`打印他们所注册的课程，比如`s5.PrintCourses();`。

让我们来看一下这个程序的输出：

```cpp
Registration is Open. Waitlist Students to be added to Courses
Anne Chu removed from waitlist and added to C++
Goeff Curt removed from waitlist and added to C++
Jiang Wu removed from waitlist and added to C++
Joley Putt removed from waitlist and added to C++
Ling Mau removed from waitlist and added to C++
During open registration, Students now adding more courses
Registration complete
Course: (C++) has the following students:
        Anne Chu
        Goeff Curt
        Jiang Wu
        Joley Putt
        Ling Mau
Course: (Advanced C++) has the following students:
        Anne Chu
        Joley Putt
        Ling Mau
        Jiang Wu
Course: (Design Patterns in C++) has the following students:
        Anne Chu
        Goeff Curt
        Jiang Wu
Student: (Anne Chu) enrolled in:
        C++
        Advanced C++
        Design Patterns in C++
Student: (Joley Putt) enrolled in:
        C++
        Advanced C++
Student: (Goeff Curt) enrolled in:
        C++
        Design Patterns in C++
Student: (Ling Mau) enrolled in:
        C++
        Advanced C++
Student: (Jiang Wu) enrolled in:
        C++
        Advanced C++
        Design Patterns in C++
```

我们现在已经看到了观察者模式的实现。我们已经将更通用的`Subject`和`Observer`类折叠到了我们习惯看到的类的框架中，即`Course`、`Person`和`Student`。让我们现在简要回顾一下我们在模式方面学到的东西，然后继续下一章。

# 总结

在本章中，我们已经开始通过将我们的技能范围扩展到包括设计模式的利用，来使自己成为更好的 C++程序员。我们的主要目标是通过应用常见的设计模式来解决重复类型的编程问题，从而使您能够使用*经过验证的*解决方案。

我们首先理解了设计模式的目的，以及在我们的代码中使用它们的优势。然后，我们具体理解了观察者模式的前提以及它对面向对象编程的贡献。最后，我们看了一下如何在 C++中实现观察者模式。

利用常见的设计模式，比如观察者模式，将帮助您更轻松地解决其他程序员理解的重复类型的编程问题。面向对象编程的一个关键原则是尽可能地重用组件。通过利用设计模式，您将为更复杂的编程技术做出可重用的解决方案。

我们现在准备继续前进，进入我们下一个设计模式[*第十七章*]（B15702_17_Final_NM_ePub.xhtml#_idTextAnchor649），*实现工厂模式*。向我们的技能集合中添加更多的模式将使我们成为更多才多艺和受人重视的程序员。让我们继续前进！

# 问题

1.  使用本章示例中的在线代码作为起点，并使用之前练习的解决方案（*问题 3*，[*第十章*]（B15702_10_Final_NM_ePub.xhtml#_idTextAnchor386），*实现关联、聚合和组合*）：

a. 实现（或修改之前的）`Student::DropCourse()`。当一个`Student`退课时，这个事件将导致`Course`的状态变为状态`2`，*新空间可用*。状态改变后，`Course`（`Subject`）上的`Notify()`将被调用，然后`Update()`将更新观察者列表（等待列表上的学生）。间接地，`Update()`将允许等待列表上的`Student`实例，如果有的话，现在添加这门`Course`。

b. 最后，在`DropCourse()`中，记得从学生当前的课程列表中移除已经退课的课程。

1.  你能想象其他容易融入观察者模式的例子吗？


# 第十七章：应用工厂模式

本章将继续扩展您的 C++编程技能，超越核心面向对象编程概念，目标是使您能够利用常见的设计模式解决重复出现的编码问题。我们知道，应用设计模式可以增强代码维护性，并为潜在的代码重用提供途径。

继续演示和解释流行的设计模式和习语，并学习如何在 C++中有效实现它们，我们将继续我们的探索，工厂模式，更准确地说是**工厂方法模式**。

在本章中，我们将涵盖以下主要主题：

+   理解工厂方法模式及其对面向对象编程的贡献

+   理解如何使用对象工厂和不使用对象工厂来实现工厂方法模式；比较对象工厂和抽象工厂

在本章结束时，您将理解流行的工厂方法模式。我们将在 C++中看到这种模式的两个示例实现。将额外的核心设计模式添加到您的编程技能中，将使您成为一个更复杂和有价值的程序员。

让我们通过研究这种常见的设计模式，工厂方法模式，来增加我们的编程技能。

# 技术要求

本章示例程序的完整代码可在以下 GitHub 链接找到：[`github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter17`](https://github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter17)。每个完整的示例程序都可以在 GitHub 存储库中的适当章节标题（子目录）下找到，文件名与所在章节的章节号对应，后跟破折号，再跟上所在章节中的示例编号。例如，本章的第一个完整程序可以在子目录`Chapter17`中的名为`Chp17-Ex1.cpp`的文件中找到，位于上述 GitHub 目录下。

本章的 CiA 视频可在以下链接观看：[`bit.ly/2PdlSLB`](https://bit.ly/2PdlSLB)。

# 理解工厂方法模式

**工厂模式**或**工厂方法模式**是一种创建型设计模式，允许创建对象而无需指定将实例化的确切（派生）类。工厂方法模式提供了一个创建对象的接口，但允许创建方法内的细节决定实例化哪个（派生）类。

工厂方法模式也被称为**虚拟构造函数**。就像虚拟析构函数具有特定的析构函数（这是销毁序列的入口点）在运行时通过动态绑定确定一样，虚拟构造函数的概念是所需的对象在运行时统一确定。

使用工厂方法模式，我们将指定一个抽象类（或接口）来收集和指定我们希望创建的派生类的一般行为。在这种模式中，抽象类或接口被称为**产品**。然后我们创建我们可能想要实例化的派生类，覆盖任何必要的抽象方法。各种具体的派生类被称为**具体产品**。

然后我们指定一个工厂方法，其目的是为了统一创建具体产品的实例。工厂方法可以放在抽象产品类中，也可以放在单独的对象工厂类中；对象工厂代表一个负责创建具体产品的类。如果将工厂方法放在抽象产品类中，那么这个工厂（创建）方法将是静态的，如果放在对象工厂类中，那么它可以选择是静态的。工厂方法将根据一致的输入参数列表决定要制造哪个具体产品，然后返回一个通用的产品指针给具体产品。多态方法可以应用于新创建的对象，以引出其特定的行为。

工厂方法模式将包括以下内容：

+   一个抽象产品类（或接口）。

+   多个具体产品派生类。

+   在抽象产品类或单独的对象工厂类中的工厂方法。工厂方法将具有一个统一的接口来创建任何具体产品类型的实例。

+   具体产品将由工厂方法作为通用产品实例返回。

请记住，工厂方法（无论是在对象工厂中）都会生产产品。工厂方法提供了一种统一的方式来生产许多相关的产品类型。

让我们继续看两个工厂方法模式的示例实现。

# 实现工厂方法模式

我们将探讨工厂方法模式的两种常见实现。每种实现都有设计权衡，值得讨论！

让我们从将工厂方法放在抽象产品类中的技术开始。

## 包括工厂方法在产品类中

要实现工厂方法模式，我们首先需要创建我们的抽象产品类以及我们的具体产品类。这些类定义将为我们构建模式奠定基础。

在我们的例子中，我们将使用一个我们习惯看到的类`Student`来创建我们的产品。然后我们将创建具体的产品类，即`GradStudent`，`UnderGradStudent`和`NonDegreeStudent`。我们将在我们的产品（`Student`）类中包含一个工厂方法，以创建任何派生产品类型的统一接口。

我们将通过添加类来区分学生的教育学位目标，为我们现有的`Student`应用程序补充我们的框架。新的组件为大学入学（新生入学）系统提供了基础。

假设我们的应用程序不是实例化一个`Student`，而是实例化各种类型的`Student` - `GradStudent`，`UnderGradStudent`或`NonDegreeStudent` - 基于他们的学习目标。`Student`类将包括一个抽象的多态`Graduate()`操作；每个派生类将使用不同的实现重写这个方法。例如，寻求博士学位的`GradStudent`可能在`GradStudent::Graduate()`方法中有更多与学位相关的标准要满足，而其他`Student`的专业化可能不需要。他们可能需要验证学分小时数，验证通过的平均成绩，以及验证他们的论文是否被接受。相比之下，`UnderGradStudent`可能只需要验证他们的学分小时数和总体平均成绩。

抽象产品类将包括一个静态方法`MatriculateStudent()`，作为创建各种类型学生（具体产品类型）的工厂方法。

### 定义抽象产品类

让我们首先看一下我们的工厂方法实现的机制，从检查我们的抽象产品类`Student`的定义开始。这个例子可以在我们的 GitHub 存储库中找到一个完整的程序：

[`github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter17/Chp17-Ex1.cpp`](https://github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter17/Chp17-Ex1.cpp)

```cpp
// Assume Person class exists with its usual implementation
class Student: public Person  // Notice that Student is now  
{                             // an abstract class
private:
    float gpa;
    char *currentCourse;
    const char *studentId;
public:
    Student();  // default constructor
    Student(const char *, const char *, char, const char *,
            float, const char *, const char *);
    Student(const Student &);  // copy constructor
    virtual ~Student();  // destructor
    float GetGpa() const { return gpa; }
    const char *GetCurrentCourse() const 
       { return currentCourse; }
    const char *GetStudentId() const { return studentId; }
    void SetCurrentCourse(const char *); // prototype only
    virtual void Print() const override;
    virtual const char *IsA() override { return "Student"; }
    virtual void Graduate() = 0;  // Now Student is abstract
    // Creates a derived Student type based on degree sought
    static Student *MatriculateStudent(const char *,
       const char *, const char *, char, const char *,
       float, const char *, const char *);
};
// Assume all the usual Student member functions exist 
```

在之前的类定义中，我们介绍了抽象的`Student`类，它是从`Person`（一个具体的、因此可实例化的类）派生出来的。这是通过引入抽象方法`virtual void Graduate() = 0;`来实现的。在我们的学生入学示例中，我们将遵循一个设计决策，即只有特定类型的学生应该被实例化；也就是说，`GradStudent`、`UnderGradStudent`和`NonDegreeStudent`的派生类类型。

在前面的类定义中，注意我们的工厂方法，具有`static Student *MatriculateStudent();`原型。这个方法将使用统一的接口，并提供了创建各种`Student`派生类类型的手段。一旦我们看到了派生类的类定义，我们将详细研究这个方法。

### 定义具体产品类

现在，让我们来看看我们的具体产品类，从`GradStudent`开始：

```cpp
class GradStudent: public Student
{
private:
    char *degree;  // PhD, MS, MA, etc.
public:
    GradStudent() { degree = 0; }  // default constructor
    GradStudent(const char *, const char *, const char *,
       char, const char *, float, const char *, const char *);
    GradStudent(const GradStudent &);  // copy constructor
    virtual ~GradStudent() { delete degree; } // destructor
    void EarnPhD();
    virtual const char *IsA() override 
       { return "GradStudent"; }
    virtual void Graduate() override;
};
// Assume alternate and copy constructors are implemented
// as expected. See online code for full implementation.
void GradStudent::EarnPhD()
{
    if (!strcmp(degree, "PhD")) // only PhD candidates can 
        ModifyTitle("Dr.");     // EarnPhd(), not MA and MS 
}                               // candidates
void GradStudent::Graduate()
{   // Here, we can check that the required number of credits
    // have been met with a passing gpa, and that their 
    // doctoral or master's thesis has been completed.
    EarnPhD();  // Will change title only if a PhD candidate
    cout << "GradStudent::Graduate()" << endl;
}
```

在上述的`GradStudent`类定义中，我们添加了一个`degree`数据成员，用于指示`"PhD"`、“MS”或`"MA"`学位，并根据需要调整构造函数和析构函数。我们已经将`EarnPhD()`移到`GradStudent`，因为这个方法并不适用于所有的`Student`实例。相反，`EarnPhD()`适用于`GradStudent`实例的一个子集；我们只会授予`"Dr."`头衔给博士候选人。

在这个类中，我们重写了`IsA()`，返回`"GradStudent"`。我们还重写了`Graduate()`，以便进行适用于研究生的毕业清单，如果满足了这些清单项目，就调用`EarnPhD()`。

现在，让我们来看看我们的下一个具体产品类，`UnderGradStudent`：

```cpp
class UnderGradStudent: public Student
{
private:
    char *degree;  // BS, BA, etc
public:
    UnderGradStudent() { degree = 0; }  // default constructor
    UnderGradStudent(const char *, const char *, const char *,
       char, const char *, float, const char *, const char *);
    UnderGradStudent(const UnderGradStudent &);  
    virtual ~UnderGradStudent() { delete degree; } 
    virtual const char *IsA() override 
        { return "UnderGradStudent"; }
    virtual void Graduate() override;
};
// Assume alternate and copy constructors are implemented
// as expected. See online code for full implementation.
void UnderGradStudent::Graduate()
{   // Verify that number of credits and gpa requirements have
    // been met for major and any minors or concentrations.
    // Have all applicable university fees been paid?
    cout << "UnderGradStudent::Graduate()" << endl;
}
```

快速看一下之前定义的`UnderGradStudent`类，我们注意到它与`GradStudent`非常相似。这个类甚至包括一个`degree`数据成员。请记住，并非所有的`Student`实例都会获得学位，所以我们不希望通过在`Student`中定义它来概括这个属性。虽然我们可以引入一个共享的基类`DegreeSeekingStudent`，用于收集`UnderGradStudent`和`GradStudent`的共同点，但这种细粒度的层次几乎是不必要的。这里的重复是一个设计权衡。

这两个兄弟类之间的关键区别是重写的`Graduate()`方法。我们可以想象，本科生毕业的清单可能与研究生不同。因此，我们可以合理地区分这两个类。否则，它们基本上是一样的。

现在，让我们来看看我们的下一个具体产品类，`NonDegreeStudent`：

```cpp
class NonDegreeStudent: public Student
{
public:
    NonDegreeStudent() { }  // default constructor
    NonDegreeStudent(const char *, const char *, char, 
       const char *, float, const char *, const char *);
    NonDegreeStudent(const NonDegreeStudent &s): Student(s){ }  
    virtual ~NonDegreeStudent() { } // destructor
    virtual const char *IsA() override 
       { return "NonDegreeStudent"; }
    virtual void Graduate() override;
};
// Assume alternate constructor is implemented as expected.
// Notice copy constructor is inline above (as is default)
// See online code for full implementation.
void NonDegreeStudent::Graduate()
{   // Check if applicable tuition has been paid. 
    // There is no credit or gpa requirement.
    cout << "NonDegreeStudent::Graduate()" << endl;
}
```

快速看一下上述的`NonDegreeStudent`类，我们注意到这个具体产品与它的兄弟类相似。然而，在这个类中没有学位数据成员。此外，重写的`Graduate()`方法需要进行的验证比`GradStudent`或`UnderGradStudent`类中的重写版本少。

### 检查工厂方法定义

接下来，让我们来看看我们的工厂方法，即我们产品（`Student`）类中的静态方法：

```cpp
// Creates a Student based on the degree they seek
// This is a static method of Student (keyword in prototype)
Student *Student::MatriculateStudent(const char *degree, 
    const char *fn, const char *ln, char mi, const char *t,
    float avg, const char *course, const char *id)
{
    if (!strcmp(degree, "PhD") || !strcmp(degree, "MS") 
        || !strcmp(degree, "MA"))
        return new GradStudent(degree, fn, ln, mi, t, avg,
                               course, id);
    else if (!strcmp(degree, "BS") || !strcmp(degree, "BA"))
        return new UnderGradStudent(degree, fn, ln, mi, t,
                                    avg, course, id);
    else if (!strcmp(degree, "None"))
        return new NonDegreeStudent(fn, ln, mi, t, avg,
                                    course, id);
}
```

前面提到的`Student`的静态方法`MatriculateStudent()`代表了工厂方法，用于创建各种产品（具体`Student`实例）。在这里，根据`Student`所寻求的学位类型，将实例化`GradStudent`，`UnderGradStudent`或`NonDegreeStudent`中的一个。请注意，`MatriculateStudent()`的签名可以处理任何派生类构造函数的参数要求。还要注意，任何这些专门的实例类型都将作为抽象产品类型（`Student`）的基类指针返回。

工厂方法`MatriculateStudent()`中的一个有趣选项是，这个方法并不一定要实例化一个新的派生类实例。相反，它可以重用之前可能仍然可用的实例。例如，想象一下，一个`Student`暂时未在大学注册（因为费用支付迟到），但仍然被保留在*待定学生*名单上。`MatriculateStudent()`方法可以选择返回指向这样一个现有`Student`的指针。*回收*是工厂方法中的一种替代方法！

### 将模式组件整合在一起

最后，让我们通过查看我们的`main()`函数来将所有不同的组件整合在一起，看看我们的工厂方法模式是如何被编排的：

```cpp
int main()
{
    Student *scholars[MAX];
    // Student is now abstract....cannot instantiate directly
    // Use the Factory Method to make derived types uniformly
    scholars[0] = Student::MatriculateStudent("PhD", "Sara",
                "Kato", 'B', "Ms.", 3.9, "C++", "272PSU");
    scholars[1] = Student::MatriculateStudent("BS", "Ana",
                "Sato", 'U', "Ms.", 3.8, "C++", "178PSU");
    scholars[2] = Student::MatriculateStudent("None", "Elle",
                "LeBrun", 'R', "Miss", 3.5, "C++", "111BU");
    for (int i = 0; i < MAX; i++)
    {
       scholars[i]->Graduate();
       scholars[i]->Print();
    }
    for (int i = 0; i < MAX; i++)
       delete scholars[i];   // engage virtual dest. sequence
    return 0;
}
```

回顾我们前面提到的`main()`函数，我们首先创建一个指向潜在专业化`Student`实例的指针数组，以它们的一般化`Student`形式。接下来，我们在抽象产品类中调用静态工厂方法`Student::MatriculateStudent()`来创建适当的具体产品（派生`Student`类类型）。我们创建每个派生`Student`类型 - `GradStudent`，`UnderGradStudent`和`NonDegreeStudent`各一个。

然后，我们通过我们的一般化集合循环，为每个实例调用`Graduate()`，然后调用`Print()`。对于获得博士学位的学生（`GradStudent`实例），他们的头衔将被`GradStudent::Graduate()`方法更改为`"Dr."`。最后，我们通过另一个循环来释放每个实例的内存。幸运的是，`Student`已经包含了一个虚析构函数，以便销毁顺序从适当的级别开始。

让我们来看看这个程序的输出：

```cpp
GradStudent::Graduate()
  Dr. Sara B. Kato with id: 272PSU GPA:  3.9 Course: C++
UnderGradStudent::Graduate()
  Ms. Ana U. Sato with id: 178PSU GPA:  3.8 Course: C++
NonDegreeStudent::Graduate()
  Miss Elle R. LeBrun with id: 111BU GPA:  3.5 Course: C++
```

前面实现的一个优点是它非常直接。然而，我们可以看到抽象产品类包含工厂方法（用于构造派生类类型）和派生具体产品之间存在着紧密的耦合。然而，在面向对象编程中，基类通常不会了解任何派生类型。

这种紧密耦合实现的一个缺点是，抽象产品类必须在其静态创建方法`MatriculateStudent()`中包含每个后代的实例化手段。添加新的派生类现在会影响抽象基类的定义 - 需要重新编译。如果我们没有访问这个基类的源代码怎么办？有没有一种方法来解耦工厂方法和工厂方法将创建的产品之间存在的依赖关系？是的，有一种替代实现。

让我们现在来看一下工厂方法模式的另一种实现。我们将使用一个对象工厂类来封装我们的`MatriculateStudent()`工厂方法，而不是将这个方法包含在抽象产品类中。

## 创建一个对象工厂类来封装工厂方法

对于工厂方法模式的另一种实现，我们将对抽象产品类进行轻微偏离其先前的定义。然而，我们将像以前一样创建我们的具体产品类。这些类定义将再次开始构建我们模式的框架。

在我们修改后的示例中，我们将再次将我们的产品定义为`Student`类。我们还将再次派生具体的产品类`GradStudent`，`UnderGradStudent`和`NonDegreeStudent`。然而，这一次，我们不会在我们的产品（`Student`）类中包含工厂方法。相反，我们将创建一个单独的对象工厂类，其中将包括工厂方法。与之前一样，工厂方法将具有统一的接口来创建任何派生产品类型。工厂方法不需要是静态的，就像在我们上一次的实现中一样。

我们的对象工厂类将包括`MatriculateStudent()`作为工厂方法来创建各种`Student`实例（具体产品类型）。

### 定义不包含工厂方法的抽象产品类

让我们来看看我们对工厂方法模式的替代实现的机制，首先检查我们的抽象产品类`Student`的定义。这个例子可以在我们的 GitHub 存储库中找到一个完整的程序：

[`github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter17/Chp17-Ex2.cpp`](https://github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter17/Chp17-Ex2.cpp)

```cpp
// Assume Person class exists with its usual implementation
class Student: public Person   // Notice Student is 
{                              // an abstract class
private:
    float gpa;
    char *currentCourse;
    const char *studentId;
public:
    Student();  // default constructor
    Student(const char *, const char *, char, const char *,
            float, const char *, const char *);
    Student(const Student &);  // copy constructor
    virtual ~Student();  // destructor
    float GetGpa() const { return gpa; }
    const char *GetCurrentCourse() const 
       { return currentCourse; }
    const char *GetStudentId() const { return studentId; }
    void SetCurrentCourse(const char *); // prototype only
    virtual void Print() const override;
    virtual const char *IsA() override { return "Student"; }
    virtual void Graduate() = 0;  // Student is abstract
};
```

在我们上述的`Student`类定义中，与我们之前的实现的关键区别是，这个类不再包含一个静态的`MatriculateStudent()`方法作为工厂方法。`Student`只是一个抽象基类。

### 定义具体产品类

有了这个想法，让我们来看看派生（具体产品）类：

```cpp
class GradStudent: public Student
{   // Implemented as in our last example
};
class UnderGradStudent: public Student
{   // Implemented as in our last example
};
class NonDegreeStudent: public Student
{   // Implemented as in our last example
};
```

在我们之前列出的类定义中，我们可以看到我们的具体派生产品类与我们在第一个示例中实现这些类的方式是相同的。

### 将对象工厂类添加到工厂方法

接下来，让我们介绍一个包括我们工厂方法的对象工厂类：

```cpp
class StudentFactory    // Object Factory class
{
public:   
    // Factory Method – creates Student based on degree sought
    Student *MatriculateStudent(const char *degree, 
       const char *fn, const char *ln, char mi, const char *t,
       float avg, const char *course, const char *id)
    {
        if (!strcmp(degree, "PhD") || !strcmp(degree, "MS") 
            || !strcmp(degree, "MA"))
            return new GradStudent(degree, fn, ln, mi, t, 
                                   avg, course, id);
        else if (!strcmp(degree, "BS") || 
                 !strcmp(degree, "BA"))
            return new UnderGradStudent(degree, fn, ln, mi, t,
                                        avg, course, id);
        else if (!strcmp(degree, "None"))
            return new NonDegreeStudent(fn, ln, mi, t, avg,
                                        course, id);
    }
};
```

在上述的对象工厂类定义（`StudentFactory`类）中，我们最少包括工厂方法规范，即`MatriculateStudent()`。该方法与我们之前的示例中的方法非常相似。然而，通过在对象工厂中捕获具体产品的创建，我们已经解耦了抽象产品和工厂方法之间的关系。

### 将模式组件结合在一起

接下来，让我们将我们的`main()`函数与我们原始示例的函数进行比较，以可视化我们修改后的组件如何实现工厂方法模式：

```cpp
int main()
{
    Student *scholars[MAX];
    // Create an Object Factory for Students
    StudentFactory *UofD = new StudentFactory();
    // Student is now abstract....cannot instantiate directly
    // Ask the Object Factory to create a Student
    scholars[0] = UofD->MatriculateStudent("PhD", "Sara", 
                  "Kato", 'B', "Ms.", 3.9, "C++", "272PSU");
    scholars[1] = UofD->MatriculateStudent("BS", "Ana", "Sato"
                  'U', "Dr.", 3.8, "C++", "178PSU");
    scholars[2] = UofD->MatriculateStudent("None", "Elle",
                  "LeBrun", 'R', "Miss", 3.5, "c++", "111BU");
    for (int i = 0; i < MAX; i++)
    {
       scholars[i]->Graduate();
       scholars[i]->Print();
    }
    for (int i = 0; i < MAX; i++)
       delete scholars[i];   // engage virtual dest. sequence
    return 0;
}
```

考虑到我们之前列出的`main()`函数，我们可以看到我们再次创建了指向抽象产品类型（`Student`）的指针数组。然后，我们实例化了一个可以创建各种具体产品类型的`Student`实例的对象工厂，即`StudentFactory *UofD = new StudentFactory();`。与之前的示例一样，对象工厂根据每个学生所寻求的学位类型创建了每个派生类型的`GradStudent`，`UnderGradStudent`和`NonDegreeStudent`的一个实例。`main()`中的其余代码与我们之前的示例中一样。

我们的输出将与我们上一个示例相同。

对象工厂类的优势在于，我们已经从抽象产品类（在工厂方法中）中移除了对象创建的依赖，并知道派生类类型是什么。也就是说，如果我们扩展层次结构以包括新的具体产品类型，我们不必修改抽象产品类。当然，我们需要访问修改我们的对象工厂类`StudentFactory`，以增强我们的`MatriculateStudent()`工厂方法。

与这种实现相关的一种模式，**抽象工厂**，是另一种模式，它允许具有类似目的的单个工厂被分组在一起。抽象工厂可以被指定为提供统一类似对象工厂的方法；它是一个将创建工厂的工厂，为我们原始模式添加了另一层抽象。

我们现在已经看到了工厂方法模式的两种实现。我们已经将产品和工厂方法的概念融入了我们习惯看到的类框架中，即`Student`和`Student`的派生类。在继续前往下一章之前，让我们简要地回顾一下我们在模式方面学到的东西。

# 总结

在本章中，我们继续努力成为更好的 C++程序员，扩展我们对设计模式的知识。特别是，我们从概念上和通过两种常见的实现探讨了工厂方法模式。我们的第一个实现包括将工厂方法放在我们的抽象产品类中。我们的第二个实现通过添加一个对象工厂类来包含我们的工厂方法，消除了我们的抽象产品和工厂方法之间的依赖关系。我们还非常简要地讨论了抽象工厂的概念。

利用常见的设计模式，比如工厂方法模式，将帮助您更轻松地解决其他程序员理解的重复类型的编程问题。通过利用核心设计模式，您将为使用更复杂的编程技术提供了被理解和可重用的解决方案。

我们现在准备继续前进到我们的下一个设计模式*第十八章*，*实现适配器模式*。向我们的技能集合中添加更多的模式使我们成为更多才多艺和有价值的程序员。让我们继续前进吧！

# 问题

1.  使用*问题 1*中的解决方案，*第八章*，*掌握抽象类*：

a. 实现工厂方法模式来创建各种形状。您已经创建了一个名为 Shape 的抽象基类，以及派生类，比如 Rectangle、Circle、Triangle，可能还有 Square。

b. 选择在`Shape`中将工厂方法实现为静态方法，或者作为`ShapeFactory`类中的方法（如果需要的话引入后者类）。

1.  您能想象其他哪些例子可能很容易地融入工厂方法模式？


# 第十八章：应用适配器模式

本章将扩展我们的探索，超越核心面向对象编程概念，旨在使您能够利用常见的设计模式解决重复出现的编码问题。在编码解决方案中应用设计模式不仅可以提供优雅的解决方案，还可以增强代码的维护性，并为代码重用提供潜在机会。

我们将学习如何在 C++中有效实现**适配器模式**。

在本章中，我们将涵盖以下主要主题：

+   理解适配器模式及其对面向对象编程的贡献

+   理解如何在 C++中实现适配器模式

本章结束时，您将了解基本的适配器模式以及如何使用它来允许两个不兼容的类进行通信，或者将不合适的代码升级为设计良好的面向对象代码。向您的知识库中添加另一个关键设计模式将使您的编程技能得到提升，帮助您成为更有价值的程序员。

让我们通过研究另一个常见的设计模式，即适配器模式，来增加我们的编程技能。

# 技术要求

完整程序示例的在线代码可以在以下 GitHub URL 找到：[`github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter18`](https://github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter18)。每个完整程序示例都可以在 GitHub 存储库中的适当章节标题（子目录）下找到，文件名与所在章节编号相对应，后跟该章节中的示例编号。例如，本章的第一个完整程序可以在上述 GitHub 目录中的`Chapter18`子目录中的名为`Chp18-Ex1.cpp`的文件中找到。

本章的 CiA 视频可在以下链接观看：[`bit.ly/2Pfg9VA`](https://bit.ly/2Pfg9VA)。

# 理解适配器模式

**适配器模式**是一种结构设计模式，提供了一种将现有类的不良接口转换为另一个类所期望的接口的方法。**适配器类**将成为两个现有组件之间通信的链接，调整接口以便两者可以共享和交换信息。适配器允许两个或更多类一起工作，否则它们无法这样做。

理想情况下，适配器不会添加功能，而是会添加所需的接口以便允许一个类以预期的方式使用，或者使两个不兼容的类相互通信。在其最简单的形式中，适配器只是将现有的类转换为支持 OO 设计中可能指定的预期接口。

适配器可以与其提供自适应接口的类相关联或派生自该类。如果使用继承，适合使用私有或受保护的基类来隐藏底层实现。如果适配器类与具有不良接口的类相关联，适配器类中的方法（具有新接口）将仅将工作委托给其关联类。

适配器模式还可以用于为一系列函数或其他类添加 OO 接口（即*在一系列函数或其他类周围包装 OO 接口*），从而使各种现有组件在 OO 系统中更自然地被利用。这种特定类型的适配器称为`extern C`，以允许链接器解析两种语言之间的链接约定。

利用适配器模式有好处。适配器允许通过提供共享接口来重用现有代码，以便否则无关的类进行通信。面向对象的程序员现在可以直接使用适配器类，从而更容易地维护应用程序。也就是说，大多数程序员的交互将是与设计良好的适配器类，而不是与两个或更多奇怪的组件。使用适配器的一个小缺点是由于增加了代码层，性能略有下降。然而，通常情况下，通过提供清晰的接口来支持它们的交互来重用现有组件是一个成功的选择，尽管会有（希望是小的）性能折衷。

适配器模式将包括以下内容：

+   一个**Adaptee**类，代表具有可取用功能的类，但以不合适或不符合预期的形式存在。

+   一个**适配器**类，它将适配 Adaptee 类的接口以满足所需接口的需求。

+   一个**目标**类，代表应用程序所需接口的具体接口。一个类可以既是目标又是适配器。

+   可选的**客户端**类，它们将与目标类交互，以完全定义正在进行的应用程序。

适配器模式允许重用合格的现有组件，这些组件不符合当前应用程序设计的接口需求。

让我们继续看适配器模式的两个常见应用；其中一个将有两种潜在的实现方式。

# 实现适配器模式

让我们探讨适配器模式的两种常见用法。即，创建一个适配器来弥合两个不兼容的类接口之间的差距，或者创建一个适配器来简单地用 OO 接口包装一组现有函数。

我们将从使用*适配器*提供连接器来连接两个（或更多）不兼容的类开始。*Adaptee*将是一个经过充分测试的类，我们希望重用它（但它具有不理想的接口），*Target*类将是我们在进行中的应用程序的 OO 设计中指定的类。现在让我们指定一个适配器，以使我们的 Adaptee 能够与我们的 Target 类一起工作。

## 使用适配器为现有类提供必要的接口

要实现适配器模式，我们首先需要确定我们的 Adaptee 类。然后我们将创建一个适配器类来修改 Adaptee 的接口。我们还将确定我们的 Target 类，代表我们需要根据我们的 OO 设计来建模的类。有时，我们的适配器和目标可能会合并成一个单一的类。在实际应用中，我们还将有客户端类，代表着最终应用程序中的所有类。让我们从 Adaptee 和 Adapter 类开始，因为这些类定义将为我们构建模式奠定基础。

在我们的例子中，我们将指定我们习惯看到的 Adaptee 类为`Person`。我们将想象我们的星球最近意识到许多其他能够支持生命的系外行星，并且我们已经与每个文明友好地结盟。进一步想象，地球上的各种软件系统希望欢迎和包容我们的新朋友，包括`Romulans`和`Orkans`，我们希望调整一些现有软件以轻松适应我们系外行星邻居的新人口统计。考虑到这一点，我们将通过创建一个适配器类`Humanoid`来将我们的`Person`类转换为包含更多系外行星术语。

在我们即将实现的代码中，我们将使用私有继承来从`Person`（被适配者）继承`Humanoid`（适配器），从而隐藏被适配者的底层实现。我们也可以将`Humanoid`关联到`Person`（这也是我们将在本节中审查的一种实现）。然后，我们可以在我们的层次结构中完善一些`Humanoid`的派生类，比如`Orkan`、`Romulan`和`Earthling`，以适应手头的星际应用。`Orkan`、`Romulan`和`Earthling`类可以被视为我们的目标类，或者我们的应用将实例化的类。我们选择将我们的适配器类`Humanoid`设为抽象，以便它不能直接实例化。因为我们的具体派生类（目标类）可以在我们的应用程序（客户端）中由它们的抽象基类类型（`Humanoid`）进行泛化，所以我们也可以将`Humanoid`视为目标类。也就是说，`Humanoid`可以被视为主要是一个适配器，但次要是一个泛化的目标类。

我们的各种客户端类可以利用`Humanoid`的派生类，创建每个具体后代的实例。这些实例可以存储在它们自己的专门类型中，或者使用`Humanoid`指针进行泛型化。我们的实现是对广泛使用的适配器设计模式的现代化改进。

### 指定被适配者和适配器（私有继承技术）

让我们来看看我们的适配器模式的第一个用法的机制，首先回顾我们的被适配者类`Person`的定义。这个例子可以在我们的 GitHub 存储库中找到一个完整的程序。

[`github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter18/Chp18-Ex1.cpp`](https://github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter18/Chp18-Ex1.cpp)

```cpp
// Person is the Adaptee class; the class requiring adaptation
class Person
{
private:
    char *firstName, *lastName, *title, *greeting;
    char middleInitial;
protected:
    void ModifyTitle(const char *);  
public:
    Person();   // default constructor
    Person(const char *, const char *, char, const char *);  
    Person(const Person &);  // copy constructor
    Person &operator=(const Person &); // assignment operator
    virtual ~Person();  // destructor
    const char *GetFirstName() const { return firstName; }  
    const char *GetLastName() const { return lastName; }    
    const char *GetTitle() const { return title; }
    char GetMiddleInitial() const { return middleInitial; }
    void SetGreeting(const char *);
    virtual const char *Speak() { return greeting; }
    virtual void Print();
};
// Assume constructors, destructor, and non-inline methods are 
// implemented as expected (see online code)
```

在前面的类定义中，我们注意到我们的`Person`类定义与本书中许多其他示例中看到的一样。这个类是可实例化的；然而，在我们的星际应用中，`Person`不是一个适当的类来实例化。相反，预期的接口应该是利用`Humanoid`中找到的接口。

考虑到这一点，让我们来看看我们的适配器类`Humanoid`：

```cpp
class Humanoid: private Person   // Humanoid is abstract
{                           
protected:
    void SetTitle(const char *t) { ModifyTitle(t); }
public:
    Humanoid();   
    Humanoid(const char *, const char *, const char *,
             const char *);
    Humanoid(const Humanoid &h) : Person(h) { }  
    Humanoid &operator=(const Humanoid &h) 
        { return (Humanoid &) Person::operator=(h); }
    virtual ~Humanoid() { }  
    const char *GetSecondaryName() const 
        { return GetFirstName(); }  
    const char *GetPrimaryName() const 
        { return GetLastName(); } 
    // scope resolution needed in method to avoid recursion 
    const char *GetTitle() const { return Person::GetTitle();}
    void SetSalutation(const char *m) { SetGreeting(m); }
    virtual void GetInfo() { Print(); }
    virtual const char *Converse() = 0;  // abstract class
};
Humanoid::Humanoid(const char *n2, const char *n1, 
    const char *planetNation, const char *greeting):
    Person(n2, n1, ' ', planetNation)
{
    SetGreeting(greeting);
}
const char *Humanoid::Converse()  // default definition for  
{                           // pure virtual function - unusual                           
    return Speak();
}
```

在上述的`Humanoid`类中，我们的目标是提供一个适配器，以满足我们星际应用所需的接口。我们只需使用私有继承，将`Humanoid`从`Person`派生，将`Person`中的公共接口隐藏在`Humanoid`的范围之外。我们知道目标应用（客户端）不希望`Person`中的公共接口被`Humanoid`的各种子类型实例使用。请注意，我们并没有添加功能，只是在适配接口。

然后，我们注意到`Humanoid`中引入的公共方法，为目标类提供了所需的接口。这些接口的实现通常很简单。我们只需调用`Person`中定义的继承方法，就可以轻松完成手头的任务（但使用了不可接受的接口）。例如，我们的`Humanoid::GetPrimaryName()`方法只是调用`Person::GetLastName();`来完成任务。然而，`GetPrimaryName()`可能更多地代表适当的星际术语，而不是`Person::GetLastName()`。我们可以看到`Humanoid`是作为`Person`的适配器。

请注意，在`Humanoid`方法中调用`Person`基类方法时，不需要在调用前加上`Person::`（除非`Humanoid`方法调用`Person`中同名的方法，比如`GetTitle()`）。`Person::`的作用域解析用法避免了这些情况中的潜在递归。

我们还注意到`Humanoid`引入了一个抽象的多态方法（即纯虚函数），其规范为`virtual const char *Converse() = 0;`。我们已经做出了设计决策，即只有`Humanoid`的派生类才能被实例化。尽管如此，我们理解公共的派生类仍然可以被其基类类型`Humanoid`收集。在这里，`Humanoid`主要作为适配器类，其次作为一个目标类，提供一套可接受的接口。

请注意，我们的纯虚函数`virtual const char *Converse() = 0;`包括一个默认实现。这是罕见的，但只要实现不是内联写的，就是允许的。在这里，我们利用机会通过简单调用`Person::Speak()`来为`Humanoid::Converse()`指定默认行为。

### 从适配器派生具体类

接下来，让我们扩展我们的适配器（`Humanoid`）并看看我们的一个具体的、派生的目标类`Orkan`：

```cpp
class Orkan: public Humanoid
{
public:
    Orkan();   // default constructor
    Orkan(const char *n2, const char *n1, const char *t): 
       Humanoid(n2, n1, t, "Nanu nanu") { }
    Orkan(const Orkan &h) : Humanoid(h) { }  
    Orkan &operator=(const Orkan &h) 
        { return (Orkan &) Humanoid::operator=(h); }
    virtual ~Orkan() { }  
    virtual const char *Converse() override;  
};
const char *Orkan::Converse()  // Must override to make
{                              // Orkan a concrete class
    return Humanoid::Converse(); // use scope resolution to
}                                // avoid recursion
```

在我们前面提到的`Orkan`类中，我们使用公共继承来从`Humanoid`派生`Orkan`。`Orkan` *是一个* `Humanoid`。因此，`Humanoid`中的所有公共接口都对`Orkan`实例可用。请注意，我们的替代构造函数将默认问候消息设置为`"Nanu nanu"`，符合`Orkan`方言。

因为我们希望`Orkan`是一个具体的、可实例化的类，所以我们必须重写`Humanoid::Converse()`并在`Orkan`类中提供一个实现。然而，请注意，`Orkan::Converse()`只是调用了`Humanoid::Converse();`。也许`Orkan`认为其基类中的默认实现是可以接受的。请注意，我们在`Orkan::Converse()`方法中使用`Humanoid::`作用域解析来限定`Converse()`，以避免递归。

有趣的是，如果`Humanoid`不是一个抽象类，`Orkan`就不需要重写`Converse()` - 默认行为会自动继承。然而，由于`Humanoid`被定义为抽象类，所以在`Orkan`中重写`Converse()`是必要的，否则`Orkan`也会被视为抽象类。别担心！我们可以通过在`Orkan::Converse()`中调用`Humanoid::Converse()`来利用`Humanoid::Converse()`的默认行为。这将满足使`Orkan`具体化的要求，同时允许`Humanoid`保持抽象，同时为`Converse()`提供罕见的默认行为！

现在，让我们看一下我们的下一个具体的目标类`Romulan`：

```cpp
class Romulan: public Humanoid
{
public:
    Romulan();   // default constructor
    Romulan(const char *n2, const char *n1, const char *t): 
        Humanoid(n2, n1, t, "jolan'tru") { }
    Romulan(const Romulan &h) : Humanoid(h) { } 
    Romulan &operator=(const Romulan &h) 
        { return (Romulan &) Humanoid::operator=(h); }
    virtual ~Romulan() { }  
    virtual const char *Converse() override;  
};
const char *Romulan::Converse()   // Must override to make
{                                 // Romulan a concrete class
    return Humanoid::Converse();   // use scope resolution to
}                                  // avoid recursion                  
```

快速看一下前面提到的`Romulan`类，我们注意到这个具体的目标与其兄弟类`Orkan`相似。我们注意到传递给我们基类构造函数的默认问候消息是`"jolan'tru"`，以反映`Romulan`方言。虽然我们可以使`Romulan::Converse()`的实现更加复杂，但我们选择不这样做。我们可以快速理解这个类的全部范围。

接下来，让我们看一下我们的第三个目标类`Earthling`：

```cpp
class Earthling: public Humanoid
{
public:
    Earthling();   // default constructor
    Earthling(const char *n2, const char *n1, const char *t):
        Humanoid(n2, n1, t, "Hello") { }
    Earthling(const Romulan &h) : Humanoid(h) { }  
    Earthling &operator=(const Earthling &h) 
        { return (Earthling &) Humanoid::operator=(h); }
    virtual ~Earthling() { }  
    virtual const char *Converse() override;  
};
const char *Earthling::Converse()   // Must override to make
{                                // Earthling a concrete class  
    return Humanoid::Converse();  // use scope resolution to
}                                 // avoid recursion
```

再次快速看一下前面提到的`Earthling`类，我们注意到这个具体的目标与其兄弟类`Orkan`和`Romulan`相似。

现在我们已经定义了我们的被适配者、适配器和多个目标类，让我们通过检查程序的客户端部分来将这些部分组合在一起。

### 将模式组件结合在一起

最后，让我们考虑一下我们整个应用程序中的一个示例客户端可能是什么样子。当然，它可能由许多文件和各种类组成。在其最简单的形式中，如下所示，我们的客户端将包含一个`main()`函数来驱动应用程序。

现在让我们看一下我们的`main()`函数，看看我们的模式是如何被编排的：

```cpp
int main()
{
    list<Humanoid *> allies;
    Orkan *o1 = new Orkan("Mork", "McConnell", "Orkan");
    Romulan *r1 = new Romulan("Donatra", "Jarok", "Romulan");
    Earthling *e1 = new Earthling("Eve", "Xu", "Earthling");
    // Add each specific type of Humanoid to the generic list
    allies.push_back(o1);
    allies.push_back(r1);
    allies.push_back(e1);
    // Create a list iterator; set to first item in the list
    list <Humanoid *>::iterator listIter = allies.begin();
    while (listIter != allies.end())
    {
        (*listIter)->GetInfo();
        cout << (*listIter)->Converse() << endl;
        listIter++;
    }
    // Though each type of Humanoid has a default Salutation,
    // each may expand their skills with an alternate language
    e1->SetSalutation("Bonjour");
    e1->GetInfo();
    cout << e1->Converse() << endl;  // Show the Earthling's 
                             // revised language capabilities
    delete o1;   // delete the heap instances
    delete r1;
    delete e1;
    return 0;
}
```

回顾我们上述的`main()`函数，我们首先创建一个`STL` `list` of `Humanoid`指针，使用`list<Humanoid *> allies;`。然后，我们实例化一个`Orkan`，`Romulan`和一个`Earthling`，并使用`allies.push_back()`将它们添加到列表中。再次使用`STL`，我们接下来创建一个列表迭代器，以遍历指向`Humanoid`实例的指针列表。当我们遍历我们的盟友的通用列表时，我们对列表中的每个项目调用`GetInfo()`和`Converse()`的批准接口（也就是说，对于每种特定类型的`Humanoid`）。

接下来，我们指定一个特定的`Humanoid`，一个`Earthling`，并通过调用`e1->SetSalutation("Bonjour");`来更改这个实例的默认问候语。通过再次在这个实例上调用`Converse()`（我们首先在上述循环中以通用方式这样做），我们可以请求`Earthling`使用`"Bonjour"`来向盟友打招呼，而不是使用`"Hello"`（`Earthling`的默认问候语）。

让我们来看看这个程序的输出：

```cpp
Orkan Mork McConnell
Nanu nanu
Romulan Donatra Jarok
jolan'tru
Earthling Eve Xu
Hello
Earthling Eve Xu
Bonjour
```

在上述输出中，请注意每个`Humanoid`的行星规格（`Orkan`，`Romulan`，`Earthling`），然后显示它们的次要和主要名称。然后显示特定`Humanoid`的适当问候语。请注意，`Earthling` `Eve Xu`首先使用`"Hello"`进行对话，然后稍后使用`"Bonjour"`进行对话。

前述实现的优点（使用私有基类从 Adaptee 派生 Adapter）是编码非常简单。通过这种方法，Adaptee 类中的任何受保护的方法都可以轻松地传递下来在 Adapter 方法的范围内使用。我们很快会看到，如果我们改用关联作为连接 Adapter 到 Adaptee 的手段，受保护的成员将成为一个问题。

前述方法的缺点是它是一个特定于 C++的实现。其他语言不支持私有基类。另外，使用公共基类来定义 Adapter 和 Adaptee 之间的关系将无法隐藏不需要的 Adaptee 接口，并且是一个非常糟糕的设计选择。

### 考虑 Adaptee 和 Adapter 的替代规范（关联）

现在，让我们简要地考虑一下稍微修改过的上述 Adapter 模式实现。我们将使用关联来模拟 Adaptee 和 Adapter 之间的关系。具体的派生类（Targets）仍将像以前一样从 Adapter 派生。

这是我们 Adapter 类`Humanoid`的另一种实现，使用 Adapter 和 Adaptee 之间的关联。虽然我们只会审查与我们最初的方法不同的代码部分，但完整的实现可以在我们的 GitHub 上找到作为一个完整的程序：

[`github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter18/Chp18-Ex2.cpp`](https://github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter18/Chp18-Ex2.cpp)

```cpp
// Assume that Person exists mostly as before – however,
// Person::ModifyTitle() must be moved from protected to
// public - or be unused if modifying Person is not possible.
// Let's assume we moved Person::ModifyTitle() to public.
class Humanoid    // Humanoid is abstract
{
private:
    Person *life;  // delegate all requests to assoc. object
protected:
    void SetTitle(const char *t) { life->ModifyTitle(t); }
public:
    Humanoid() { life = 0; }
    Humanoid(const char *, const char *, const char *, 
             const char *);
    Humanoid(const Humanoid &h);
    Humanoid &operator=(const Humanoid &);
    virtual ~Humanoid() { delete life; }  
    const char *GetSecondaryName() const 
        { return life->GetFirstName(); }
    const char *GetPrimaryName() const 
        { return life->GetLastName(); }    
    const char *GetTitle() const { return life->GetTitle(); }
    void SetSalutation(const char *m) { life->SetGreeting(m);}
    virtual void GetInfo() { life->Print(); }
    virtual const char *Converse() = 0;  // abstract class
};
Humanoid::Humanoid(const char *n2, const char *n1, 
          const char *planetNation, const char *greeting)
{
    life = new Person(n2, n1, ' ', planetNation);
    life->SetGreeting(greeting);
}
Humanoid::Humanoid(const Humanoid &h)
{  // Remember life data member is of type Person
    delete life;  // delete former associated object
    life = new Person(h.GetSecondaryName(),
                      h.GetPrimaryName(),' ', h.GetTitle());
    life->SetGreeting(h.life->Speak());  
}
Humanoid &Humanoid::operator=(const Humanoid &h)
{
    if (this != &h)
        life->Person::operator=((Person &) h);
    return *this;
}
const char *Humanoid::Converse() //default definition for
{                                // pure virtual fn - unusual
    return life->Speak();
}
```

请注意，在我们上述的 Adapter 类的实现中，`Humanoid`不再是从`Person`派生的。相反，`Humanoid`将添加一个私有数据成员`Person *life;`，它将表示 Adapter（`Humanoid`）和 Adaptee（`Person`）之间的关联。在我们的 Humanoid 构造函数中，我们需要分配 Adaptee（`Person`）的基础实现。我们还需要在析构函数中删除 Adaptee（`Person`）。

与我们上次的实现类似，`Humanoid`在其公共接口中提供相同的成员函数。但是，请注意，每个`Humanoid`方法通过关联对象委托调用适当的 Adaptee 方法。例如，`Humanoid::GetSecondaryName()`仅调用`life->GetFirstName();`来委托请求（而不是调用继承的相应 Adaptee 方法）。

与我们最初的实现一样，我们从`Humanoid`（`Orkan`，`Romulan`和`Earthling`）派生的类以相同的方式指定，我们的客户端也在`main()`函数中。

### 选择被适配者和适配器之间的关系

在选择适配器和被适配者之间的关系时，一个有趣的点是选择私有继承还是关联的关系，这取决于被适配者是否包含任何受保护的成员。回想一下，`Person`的原始代码包括一个受保护的`ModifyTitle()`方法。如果被适配者类中存在受保护的成员，私有基类实现允许在适配器类的范围内继续访问这些继承的受保护成员（也就是适配器的方法）。然而，使用基于关联的实现，被适配者（`Person`）中的受保护方法在适配器的范围内是无法使用的。为了使这个例子工作，我们需要将`Person::ModifyTitle()`移到公共访问区域。然而，修改被适配者类并不总是可能的，也不一定推荐。考虑到受保护成员的问题，我们最初使用私有基类的实现是更强大的实现，因为它不依赖于我们修改被适配者（`Person`）的类定义。

现在让我们简要地看一下适配器模式的另一种用法。我们将简单地使用一个适配器类作为包装类。我们将为一个本来松散排列的一组函数添加一个面向对象的接口，这些函数工作得很好，但缺乏我们的应用程序（客户端）所需的接口。

## 使用适配器作为包装器

作为适配器模式的另一种用法，我们将在一组相关的外部函数周围包装一个面向对象的接口。也就是说，我们将创建一个包装类来封装这些函数。

在我们的示例中，外部函数将代表一套现有的数据库访问函数。我们将假设核心数据库功能对于我们的数据类型（`Person`）已经经过了充分测试，并且已经被无问题地使用。然而，这些外部函数本身提供了一个不可取和意外的功能接口。

相反，我们将通过创建一个适配器类来封装这些外部函数的集体功能。我们的适配器类将是`CitizenDataBase`，代表了一个封装的方式，用于从数据库中读取和写入`Person`实例。我们现有的外部函数将为我们的`CitizenDataBase`成员函数提供实现。让我们假设在我们的适配器类中定义的面向对象的接口满足我们的面向对象设计的要求。

让我们来看看我们简单包装的适配器模式的机制，首先要检查提供数据库访问功能的外部函数。这个例子可以在我们的 GitHub 仓库中找到一个完整的程序：

[`github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter18/Chp18-Ex3.cpp`](https://github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter18/Chp18-Ex3.cpp)

```cpp
// Assume Person class exists with its usual implementation
Person objectRead;  // holds the object from the current read
                    // to support a simulation of a DB read
void db_open(const char *dbName)
{   // Assume implementation exists
    cout << "Opening database: " << dbName << endl;
}
void db_close(const char *dbName)
{   // Assume implementation exists
    cout << "Closing database: " << dbName << endl;
}
Person &db_read(const char *dbName, const char *key)
{   // Assume implementation exists
    cout << "Reading from: " << dbName << " using key: ";
    cout << key << endl;
    // In a true implementation, we would read the data
    // using the key and return the object we read in
    return objectRead;  // a non-stack instance for simulation
}
const char *db_write(const char *dbName, Person &data)
{   // Assume implementation exists
    const char *key = data.GetLastName();
    cout << "Writing: " << key << " to: " << dbName << endl;
    return key;
}
```

在我们之前定义的外部函数中，让我们假设所有函数都经过了充分测试，并且允许从数据库中读取或写入`Person`实例。为了支持这个模拟，我们创建了一个外部`Person`实例`Person objectRead;`，提供了一个简短的、非堆栈位置的存储位置，用于新读取的实例（被`db_read()`使用），直到新读取的实例被捕获为返回值。请记住，现有的外部函数并不代表一个封装的解决方案。

现在，让我们创建一个简单的包装类来封装这些外部函数。包装类`CitizensDataBase`将代表我们的适配器类：

```cpp
// CitizenDataBase is the Adapter class 
class CitizenDataBase  (Adapter wraps the undesired interface)
{
private:
    char *name;
public:
    // No default constructor (unusual)
    CitizenDataBase(const char *);
    CitizenDataBase(const CitizenDataBase &) = delete;
    CitizenDataBase &operator=(const CitizenDataBase &) 
                               = delete;  
    virtual ~CitizenDataBase();  
    Person &Read(const char *);
    const char *Write(Person &);
};
CitizenDataBase::CitizenDataBase(const char *n)
{
    name = new char [strlen(n) + 1];
    strcpy(name, n);
    db_open(name);   // call existing external function
}
CitizenDataBase::~CitizenDataBase()
{
    db_close(name);  // close database with external function
    delete name;
}
Person &CitizenDataBase::Read(const char *key)
{
    return db_read(name, key);   // call external function
}
const char *CitizenDataBase::Write(Person &data)
{
    return db_write(name, data);  // call external function
}
```

在我们上述的适配器类定义中，我们只是在`CitizenDataBase`类中封装了外部数据库功能。在这里，`CitizenDataBase`不仅是我们的适配器类，也是我们的目标类，因为它包含了我们手头应用程序（客户端）期望的接口。

现在，让我们来看看我们的`main()`函数，这是一个客户端的简化版本：

```cpp
int main()
{
    const char *key;
    char name[] = "PersonData"; // name of database
    Person p1("Curt", "Jeffreys", 'M', "Mr.");
    Person p2("Frank", "Burns", 'W', "Mr.");
    Person p3;
    CitizenDataBase People(name);   // open requested Database
    key = People.Write(p1); // write a Person object
    p3 = People.Read(key);  // using a key, retrieve Person
    return 0;
}                           // destruction will close database
```

在上述的`main()`函数中，我们首先实例化了三个`Person`实例。然后实例化了一个`CitizenDataBase`，以提供封装的访问权限，将我们的`Person`实例写入或从数据库中读取。我们的`CitizenDataBase`构造函数的方法调用外部函数`db_open()`来打开数据库。同样，析构函数调用`db_close()`。正如预期的那样，我们的`CitizenDataBase`的`Read()`和`Write()`方法分别调用外部函数`db_read()`或`db_write()`。

让我们来看看这个程序的输出：

```cpp
Opening database: PersonData
Writing: Jeffreys to: PersonData
Reading from: PersonData using key: Jeffreys
Closing database: PersonData
```

在上述输出中，我们可以注意到各个成员函数与包装的外部函数之间的相关性，通过构造、调用写入和读取，然后销毁数据库。

我们简单的`CitizenDataBase`包装器是适配器模式的一个非常简单但合理的用法。有趣的是，我们的`CitizenDataBase`也与**数据访问对象模式**有共同之处，因为这个包装器提供了一个干净的接口来访问数据存储机制，隐藏了对底层数据库的实现（访问）。

我们现在已经看到了适配器模式的三种实现。我们已经将适配器、被适配者、目标和客户端的概念融入到我们习惯看到的类的框架中，即`Person`，以及我们适配器的后代（`Orkan`、`Romulan`、`Earthling`，就像我们前两个例子中的那样）。让我们现在简要地回顾一下我们在移动到下一章之前学到的与模式相关的知识。

# 总结

在本章中，我们通过扩展我们对设计模式的知识，进一步提高了成为更好的 C++程序员的追求。我们已经在概念和多种实现中探讨了适配器模式。我们的第一个实现使用私有继承从被适配者类派生适配器。我们将适配器指定为抽象类，然后使用公共继承根据适配器类提供的接口引入了几个基于接口的目标类。我们的第二个实现则使用关联来建模适配器和被适配者之间的关系。然后我们看了一个适配器作为包装器的示例用法，简单地为现有基于函数的应用组件添加了面向对象的接口。

利用常见的设计模式，比如适配器模式，将帮助你更容易地重用现有的经过充分测试的代码部分，以一种其他程序员能理解的方式。通过利用核心设计模式，你将为更复杂的编程技术做出贡献，提供了被理解和可重用的解决方案。

我们现在准备继续前进，进入我们的下一个设计模式[*第十九章*]，*使用单例模式*。增加更多的模式到我们的编程技能库中，使我们成为更多才多艺和有价值的程序员。让我们继续前进！

# 问题

1.  使用本章中找到的适配器示例：

a. 实现一个`CitizenDataBase`，用于存储各种类型的`Humanoid`实例（`Orkan`、`Romulan`、`Earthling`，也许还有`Martian`）。决定你是使用私有基类适配器-被适配者关系，还是适配器和被适配者之间的关联关系（提示：私有继承版本会更容易）。

b. 注意`CitizenDataBase`处理`Person`实例，这个类是否可以原样用来存储各种类型的`Humanoid`实例，还是必须以某种方式进行适配？请记住，`Person`是`Humanoid`的基类（如果你选择了这种实现方式），但也要记住我们永远不能向上转型超出非公共继承边界。

1.  你能想象哪些其他例子可能很容易地应用适配器模式？


# 第十九章：使用单例模式

本章将继续扩展您的 C++编程技能，超越核心面向对象编程概念，旨在让您能够利用核心设计模式解决重复出现的编码难题。在编码解决方案中使用设计模式不仅可以提供精炼的解决方案，还有助于更轻松地维护代码，并为代码重用提供潜在机会。

我们将学习如何在 C++中有效实现**单例模式**，这是下一个核心设计模式。

在本章中，我们将涵盖以下主要主题：

+   理解单例模式及其对面向对象编程的贡献

+   在 C++中实现单例模式（使用简单的对类方法和配对类方法的方法）；使用注册表允许多个类利用单例模式

通过本章结束时，您将了解单例模式以及如何使用它来确保给定类型只能存在一个实例。将另一个核心设计模式添加到您的知识体系中，将进一步增强您的编程技能，帮助您成为更有价值的程序员。

通过研究另一个常见的设计模式，单例模式，来增强我们的编程技能。

# 技术要求

本章中完整程序示例的代码可以在以下 GitHub URL 找到：[`github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter19`](https://github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter19)。每个完整程序示例都可以在 GitHub 存储库中的适当章节标题（子目录）下找到，文件名与当前章节号对应，后跟当前章节中的示例编号。例如，本章中的第一个完整程序可以在名为`Chp19-Ex1.cpp`的文件中的`Chapter19`子目录中找到上述 GitHub 存储库中。

本章的 CiA 视频可在以下链接观看：[`bit.ly/3f2dKZb`](https://bit.ly/3f2dKZb)。

# 理解单例模式

单例模式是一种创建型设计模式，它保证了一个类只会存在一个实例；该类型的两个或更多实例根本不可能同时存在。采用这种模式的类被称为**单例**。

单例模式可以使用静态数据成员和静态方法来实现。这意味着单例将在全局范围内访问当前实例。这一影响起初似乎很危险；将全局状态信息引入代码是对单例模式的一种批评，有时会被认为是一种反模式。然而，通过对定义单例的静态数据成员使用访问区域的适当使用，我们可以坚持只使用当前类的适当静态方法访问单例（除了初始化），从而减轻这种潜在的模式问题。

该模式的另一个批评是它不是线程安全的。可能存在竞争条件，以进入创建单例实例的代码段。如果不保证对该关键代码区域的互斥性，单例模式将会破坏，允许多个这样的实例存在。因此，如果将使用多线程编程，必须使用适当的锁定机制来保护创建单例的关键代码区域。使用静态内存实现的单例存储在同一进程中的线程之间的共享内存中；有时会因为垄断资源而批评单例。

Singleton 模式可以利用多种实现技术。每种实现方式都必然会有利弊。我们将使用一对相关的类`Singleton`和`SingletonDestroyer`来强大地实现该模式。虽然还有更简单、直接的实现方式（我们将简要回顾其中一种），但最简单的技术留下了 Singleton 可能不会被充分销毁的可能性。请记住，析构函数可能包括重要和必要的活动。

Singleton 通常具有长寿命；因此，在应用程序终止之前销毁 Singleton 是合适的。许多客户端可能有指向 Singleton 的指针，因此没有一个客户端应该删除 Singleton。我们将看到`Singleton`将是*自行创建*的，因此它应该理想地*自行销毁*（即通过其`SingletonDestroyer`的帮助）。因此，配对类方法虽然不那么简单，但将确保正确的`Singleton`销毁。请注意，我们的实现也将允许直接删除 Singleton；这是罕见的，但我们的代码也将处理这种情况。

带有配对类实现的 Singleton 模式将包括以下内容：

+   一个代表实现 Singleton 概念所需的核心机制的**Singleton**类。

+   一个**SingletonDestroyer**类，它将作为 Singleton 的辅助类，确保给定的 Singleton 被正确销毁。

+   从 Singleton 派生的类，代表我们希望确保在特定时间只能创建一个其类型实例的类。这将是我们的**目标**类。

+   可选地，目标类可以既从 Singleton 派生，又从另一个类派生，这个类可能代表我们想要专门化或简单包含的现有功能（即*混入*）。在这种情况下，我们将从一个特定于应用程序的类和 Singleton 类中继承。

+   可选的**客户端**类，它们将与目标类交互，以完全定义手头的应用程序。

+   或者，Singleton 也可以在目标类内部实现，将类的功能捆绑在一个单一类中。

+   真正的 Singleton 模式可以扩展到允许创建多个（离散的）实例，但不是一个确定数量的实例。这是罕见的。

我们将专注于传统的 Singleton 模式，以确保在任何给定时间只存在一个类的实例。

让我们继续前进，首先检查一个简单的实现，然后是我们首选的配对类实现，Singleton 模式。

# 实现 Singleton 模式

Singleton 模式将用于确保给定类只能实例化该类的单个实例。然而，真正的 Singleton 模式还将具有扩展功能，以允许多个（但数量明确定义的）实例被创建。这种 Singleton 模式的罕见且不太为人所知的特殊情况。

我们将从一个简单的 Singleton 实现开始，以了解其局限性。然后我们将进一步实现 Singleton 的更强大的配对类实现，最常见的模式目标是只允许在任何给定时间内实例化一个目标类。

## 使用简单实现

为了实现一个非常简单的 Singleton，我们将使用一个简单的单类规范来定义 Singleton 本身。我们将定义一个名为`Singleton`的类来封装该模式。我们将确保我们的构造函数是私有的，这样它们就不能被应用超过一次。我们还将添加一个静态的`instance()`方法来提供`Singleton`对象的实例化接口。这个方法将确保私有构造只发生一次。

让我们先来看一下这个简单的实现，可以在我们的 GitHub 存储库中找到：

[`github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter19/Chp19-Ex1.cpp`](https://github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter19/Chp19-Ex1.cpp)

```cpp
class Singleton
{
private:
    static Singleton *theInstance;
    Singleton();  // private to prevent multiple instantiation
public:
    static Singleton *instance(); // interface for creation
    virtual ~Singleton();  // never called, unless you delete
};                         // Singleton explicitly, which is
                           // unlikely and atypical
Singleton *Singleton::theInstance = NULL; // external variable
                                         // to hold static mbr
Singleton::Singleton()
{
    cout << "Constructor" << endl;
    theInstance = NULL;
}
Singleton::~Singleton()  // the destructor is not called in
{                        // the typical pattern usage
    cout << "Destructor" << endl;
    if (theInstance != NULL)  
    {  
       Singleton *temp = theInstance;
       theInstance = NULL;       // removes ptr to Singleton
       temp->theInstance = NULL; // prevents recursion
       delete temp;              // delete the Singleton
    }                 
}
Singleton *Singleton::instance()
{
    if (theInstance == NULL)
        theInstance = new Singleton();  // allocate Singleton
    return theInstance;
}
int main()
{
    Singleton *s1 = Singleton::instance(); // create Singleton
    Singleton *s2 = Singleton::instance(); // returns existing
    cout << s1 << " " << s2 << endl; // addresses are the same
}                                         
```

在上述的类定义中，我们注意到包括数据成员`static Singleton *theInstance;`来表示`Singleton`实例本身。我们的构造函数是私有的，这样就不能多次使用它来创建多个`Singleton`实例。相反，我们添加了一个`static Singleton *instance()`方法来创建`Singleton`。在这个方法中，我们检查数据成员`theInstance`是否为`NULL`，如果是，我们就实例化唯一的`Singleton`实例。

在类定义之外，我们看到了外部变量（及其初始化）来支持静态数据成员的内存需求，定义为`Singleton *Singleton::theInstance = NULL;`。我们还看到在`main()`中，我们调用静态的`instance()`方法来使用`Singleton::instance()`创建一个 Singleton 实例。对这个方法的第一次调用将实例化一个`Singleton`，而对这个方法的后续调用将仅仅返回指向现有`Singleton`对象的指针。我们可以通过打印这些对象的地址来验证这些实例是相同的。

让我们来看一下这个简单程序的输出：

```cpp
Constructor
0xee1938 0xee1938
```

在上述输出中，我们注意到了一些意外的事情 - 析构函数没有被调用！如果析构函数有关键的任务要执行怎么办呢？

### 理解简单 Singleton 实现的一个关键缺陷

在简单实现中，我们的`Singleton`的析构函数没有被调用，仅仅是因为我们没有通过`s1`或`s2`标识符删除动态分配的`Singleton`实例。为什么呢？显然可能有多个指针（句柄）指向一个`Singleton`对象。决定哪个句柄应该负责删除`Singleton`是很难确定的 - 这些句柄至少需要合作或使用引用计数。

此外，`Singleton`往往存在于应用程序的整个生命周期。这种长期存在进一步表明，`Singleton`应该负责自己的销毁。但是如何做呢？我们很快将看到一个实现，它将允许`Singleton`通过一个辅助类来控制自己的销毁。然而，使用简单实现，我们可能只能举手投降，并建议操作系统在应用程序终止时回收内存资源 - 包括这个小`Singleton`的堆内存。这是正确的；然而，如果在析构函数中需要完成重要任务呢？我们在简单模式实现中遇到了限制。

如果我们需要调用析构函数，我们是否应该允许其中一个句柄使用，例如`delete s1;`来删除实例？我们之前已经讨论过是否允许任何一个句柄执行删除的问题，但现在让我们进一步检查析构函数本身可能存在的问题。例如，如果我们的析构函数假设只包括`delete theInstance;`，我们将会有一个递归函数调用。也就是说，调用`delete s1;`将调用`Singleton`的析构函数，然后在析构函数体内部调用`delete theInstance;`将把`theInstance`识别为`Singleton`类型，并再次调用`Singleton`的析构函数 - *递归*。

不用担心！如所示，我们的析构函数通过首先检查`theInstance`数据成员是否不是`NULL`，然后安排`temp`指向`theInstance`来管理递归，以保存我们需要删除的实例的句柄。然后我们进行`temp->theInstance = NULL;`的赋值，以防止在`delete temp;`时递归。为什么？因为`delete temp;`也会调用`Singleton`的析构函数。在这个析构函数调用时，`temp`将绑定到`this`，并且在第一次递归函数调用时不满足条件测试`if (theInstance != NULL)`，使我们退出持续的递归。请注意，我们即将使用成对类方法的实现不会有这个潜在问题。

重要的是要注意，在实际应用中，我们不会创建一个领域不明确的`Singleton`实例。相反，我们将应用程序分解到设计中以使用该模式。毕竟，我们希望有一个有意义的类类型的`Singleton`实例。要使用我们简单的`Singleton`类作为基础来做到这一点，我们只需将我们的目标（特定于应用程序）类从`Singleton`继承。目标类也将有私有构造函数 - 接受足以充分实例化目标类的参数。然后，我们将静态的`instance()`方法从`Singleton`移到目标类，并确保`instance()`的参数列表接受传递给私有目标构造函数的必要参数。

总之，我们简单的实现存在固有的设计缺陷，即`Singleton`本身没有保证的适当销毁。让操作系统在应用程序终止时收集内存不会调用析构函数。选择一个可以删除内存的`Singleton`句柄虽然可能，但需要协调，也破坏了模式的通常应用，即允许`Singleton`在应用程序的持续时间内存在。

现在，因为我们理解了简单的`Singleton`实现的局限性，我们将转而前进到首选的成对类实现 Singleton 模式。成对类方法将确保我们的`Singleton`在应用程序允许`Singleton`在应用程序终止之前被销毁（最常见的情况）或者在应用程序中罕见地提前销毁`Singleton`时，能够进行适当的销毁。

## 使用更健壮的成对类实现

为了以一种良好封装的方式实现成对类方法的 Singleton 模式，我们将定义一个 Singleton 类，纯粹添加创建单个实例的核心机制。我们将把这个类命名为`Singleton`。然后，我们将添加一个辅助类到`Singleton`，称为`SingletonDestroyer`，以确保我们的`Singleton`实例在应用程序终止之前始终进行适当的销毁。这一对类将通过聚合和关联进行关联。更具体地说，`Singleton`类将在概念上包含一个`SingletonDestroyer`（聚合），而`SingletonDestroyer`类将持有一个关联到（外部）`Singleton`的关联。因为`Singleton`和`SingletonDestroyer`的实现是通过静态数据成员，聚合是概念性的 - 静态成员被存储为外部变量。

一旦定义了这些核心类，我们将考虑如何将 Singleton 模式纳入我们熟悉的类层次结构中。假设我们想要实现一个类来封装“总统”的概念。无论是一个国家的总统还是大学的校长，都很重要的是在特定时间只有一个总统。 “总统”将是我们的目标类；因此，“总统”是一个很好的候选者来利用我们的 Singleton 模式。

有趣的是，尽管在特定时间只会有一位总统，但是可以替换总统。例如，美国总统的任期一次只有四年，可以连任一届。大学校长可能也有类似的条件。总统可能因辞职、弹劾或死亡而提前离任，或者在任期到期后简单地离任。一旦现任总统的存在被移除，那么实例化一个新的 Singleton `President`就是可以接受的。因此，我们的 Singleton 模式在特定时间只允许一个 Target 类的 Singleton。

反思我们如何最好地实现`President`类，我们意识到`President` *是* `Person`，并且还需要*混入* `Singleton`的功能。有了这个想法，我们现在有了我们的设计。`President`将使用多重继承来扩展`Person`的概念，并混入`Singleton`的功能。

当然，我们可以从头开始构建一个`President`类，但是当`President`类的`Person`组件在一个经过充分测试和可用的类中表示时，为什么要这样做呢？同样，当然，我们可以将`Singleton`类的信息嵌入到我们的`President`类中，而不是继承一个单独的`Singleton`类。绝对，这也是一个选择。然而，我们的应用程序将封装解决方案的每个部分。这将使未来的重用更容易。尽管如此，设计选择很多。

### 指定 Singleton 和 SingletonDestroyer 类

让我们来看看我们的 Singleton 模式的机制，首先检查`Singleton`和`SingletonDestroyer`类的定义。这些类合作实现 Singleton 模式。这个例子可以在我们的 GitHub 存储库中找到完整的程序。

https://github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter19/Chp19-Ex2.cpp

```cpp
class Singleton;    // Necessary forward class declarations
class SingletonDestroyer;
class Person;
class President;
class SingletonDestroyer   
{
private:
    Singleton *theSingleton;
public:
    SingletonDestroyer(Singleton *s = 0) { theSingleton = s; }
    SingletonDestroyer(const SingletonDestroyer &) = delete; 
    SingletonDestroyer &operator=(const SingletonDestroyer &)                                  = delete; 
    ~SingletonDestroyer(); // destructor shown further below
    void setSingleton(Singleton *s) { theSingleton = s; }
    Singleton *getSingleton() { return theSingleton; }
};
```

在上述代码段中，我们从几个前向类声明开始，比如`class Singleton;`。这些声明允许在编译器看到它们的完整类定义之前就可以引用这些数据类型。

接下来，让我们来看看我们的`SingletonDestroyer`类定义。这个简单的类包含一个私有数据成员`Singleton *theSingleton;`，表示`SingletonDestroyer`将来将负责释放的`Singleton`的关联（我们将很快检查`SingletonDestroyer`的析构函数定义）。请注意，我们的析构函数不是虚拟的，因为这个类不打算被专门化。

请注意，我们的构造函数为`Singleton *`指定了默认值`0`（`NULL`）。`SingletonDestroyer`还包含两个成员函数`setSingleton()`和`getSingleton()`，仅提供了设置和获取相关`Singleton`成员的方法。

还要注意，`SingletonDestroyer`中的复制构造函数和重载赋值运算符在其原型中使用`=delete`进行了禁止。

在我们检查这个类的析构函数之前，让我们先看看`Singleton`的类定义。

```cpp
// Singleton will be mixed-in using inheritance with a Target
// class. If Singleton is used stand-alone, the data members
// would be private, and add a Static *Singleton instance();
// method to the public access region.
class Singleton
{
protected:
    static Singleton *theInstance;
    static SingletonDestroyer destroyer;
protected:
    Singleton() {}
    Singleton(const Singleton &) = delete; // disallow copies
    Singleton &operator=(const Singleton &) = delete; // and =
    friend class SingletonDestroyer;
    virtual ~Singleton() 
        { cout << "Singleton destructor" << endl; }
};
```

上述的`Singleton`类包含受保护的数据成员`static Singleton *theInstance;`，它将表示为采用 Singleton 习惯用法分配给类的唯一实例的指针。

受保护的数据成员`static SingletonDestroyer destroyer`代表一个概念上的聚合或包含成员。这种包含实际上只是概念性的，因为静态数据成员不存储在任何实例的内存布局中；它们实际上存储在外部内存中，并且*name-mangled*以显示为类的一部分。这个（概念上的）聚合子对象`destroyer`将负责正确销毁`Singleton`。请记住，`SingletonDestroyer`与唯一的`Singleton`有关，代表了`SingletonDestroyer`概念上包含的外部对象。这种关联是`SingletonDestroyer`将如何访问 Singleton 的方式。

当实现静态数据成员`static SingletonDestroyer destroyer;`的外部变量的内存在应用程序结束时消失时，将调用`SingletonDestroyer`（静态的概念性子对象）的析构函数。这个析构函数将运行`delete theSingleton;`，确保外部动态分配的`Singleton`对象将有适当的析构顺序运行。因为`Singleton`中的析构函数是受保护的，所以需要将`SingletonDestructor`指定为`Singleton`的友元类。

请注意，`Singleton`中复制构造函数和重载赋值运算符的使用都已经在它们的原型中使用`=delete`禁止了。

在我们的实现中，我们假设`Singleton`将通过继承混入到派生的目标类中。在派生类（打算使用 Singleton 习惯用法的类）中，我们提供了所需的静态`instance()`方法来创建`Singleton`实例。请注意，如果`Singleton`被用作独立类来创建单例，我们将在`Singleton`的公共访问区域中添加`static Singleton* instance()`。然后我们将数据成员从受保护的访问区域移动到私有访问区域。然而，拥有一个与应用程序无关的 Singleton 只能用来演示概念。相反，我们将把 Singleton 习惯用法应用到需要使用这种习惯用法的实际类型上。

有了我们的`Singleton`和`SingletonDestroyer`类定义，让我们接下来检查这些类的其余必要实现需求：

```cpp
// External (name mangled) variables to hold static data mbrs
Singleton *Singleton::theInstance = 0;
SingletonDestroyer Singleton::destroyer;
// SingletonDestroyer destructor definition must appear after 
// class definition for Singleton because it is deleting a 
// Singleton (so its destructor can be seen)
// This is not an issue when using header and source files.
SingletonDestroyer::~SingletonDestroyer()
{   
    if (theSingleton == NULL)
        cout << "SingletonDestroyer destructor: Singleton                  has already been destructed" << endl;
    else
    {
        cout << "SingletonDestroyer destructor" << endl;
        delete theSingleton;   
    }                          
}
```

在上述代码片段中，首先注意两个外部变量定义，提供内存以支持`Singleton`类中的两个静态数据成员——即`Singleton *Singleton::theInstance = 0;`和`SingletonDestroyer Singleton::destroyer;`。请记住，静态数据成员不存储在其指定类的任何实例中。相反，它们存储在外部变量中；这两个定义指定了内存。请注意，数据成员都标记为受保护。这意味着虽然我们可以直接定义它们的外部存储，但我们不能通过`Singleton`的静态成员函数以外的方式访问这些数据成员。这将给我们一些安心。虽然静态数据成员有潜在的全局访问点，但它们的受保护访问区域要求使用`Singleton`类的适当静态方法来正确操作这些重要成员。

接下来，注意`SingletonDestroyer`的析构函数。这个巧妙的析构函数首先检查它是否与它负责的`Singleton`的关联是否为`NULL`。这将很少发生，并且只会在非常不寻常的情况下发生，即客户端直接使用显式的`delete`释放`Singleton`对象。

`SingletonDestroyer`析构函数中的通常销毁场景将是执行`else`子句，其中`SingletonDestructor`作为静态对象将负责删除其配对的`Singleton`，从而销毁它。请记住，`Singleton`中将包含一个`SingletonDestroyer`对象。这个静态（概念上的）子对象的内存不会在应用程序结束之前消失。请记住，静态内存实际上并不是任何实例的一部分。因此，当`SingletonDestroyer`被销毁时，它通常的情况将是`delete theSingleton;`，这将释放其配对的 Singleton 的内存，使得`Singleton`能够被正确销毁。

单例模式背后的驱动设计决策是，单例是一个长期存在的对象，它的销毁通常应该在应用程序的最后发生。单例负责创建自己的内部目标对象，因此单例不应该被客户端删除（因此也不会被销毁）。相反，首选的机制是，当作为静态对象移除时，`SingletonDestroyer`会删除其配对的`Singleton`。

尽管如此，偶尔也会有合理的情况需要在应用程序中间删除一个`Singleton`。如果一个替代的`Singleton`从未被创建，我们的`SingletonDestroyer`析构函数仍将正确工作，识别到其配对的`Singleton`已经被释放。然而，更有可能的情况是我们的`Singleton`将在应用程序的某个地方被另一个`Singleton`实例替换。回想一下我们的应用程序示例，总统可能会被弹劾、辞职或去世，但会被另一位总统取代。在这些情况下，直接删除`Singleton`是可以接受的，然后创建一个新的`Singleton`。在这种情况下，`SingletonDestroyer`现在将引用替代的`Singleton`。

### 从 Singleton 派生目标类

接下来，让我们看看如何从`Singleton`创建我们的目标类`President`：

```cpp
// Assume our Person class definition is as we are accustomed
// A President Is-A Person and also mixes-in Singleton 
class President: public Person, public Singleton
{
private:
    President(const char *, const char *, char, const char *);
public:
    virtual ~President();
    President(const President &) = delete;  // disallow copies
    President &operator=(const President &) = delete; // and =
    static President *instance(const char *, const char *,
                               char, const char *);
};
President::President(const char *fn, const char *ln, char mi,
    const char *t) : Person(fn, ln, mi, t), Singleton()
{
}
President::~President()
{
    destroyer.setSingleton(NULL);  
    cout << "President destructor" << endl;
}
President *President::instance(const char *fn, const char *ln,
                               char mi, const char *t)
{
    if (theInstance == NULL)
    {
        theInstance = new President(fn, ln, mi, t);
        destroyer.setSingleton(theInstance);
        cout << "Creating the Singleton" << endl;
    }
    else
        cout << "Singleton previously created.                  Returning existing singleton" << endl;
    return (President *) theInstance; // cast necessary since
}                              // theInstance is a Singleton * 
```

在我们上述的目标类`President`中，我们仅仅使用公共继承从`Person`继承`President`，然后通过多重继承从`Singleton`继承`President`来*混入*`Singleton`机制。

我们将构造函数放在私有访问区域。静态方法`instance()`将在内部使用这个构造函数来创建唯一允许的`Singleton`实例，以符合模式。没有默认构造函数（不寻常），因为我们不希望允许创建没有相关细节的`President`实例。请记住，如果我们提供了替代的构造函数接口，C++将不会链接默认构造函数。由于我们不希望复制`President`或将`President`分配给另一个潜在的`President`，我们已经在这些方法的原型中使用`=delete`规范来禁止复制和分配。

我们的`President`析构函数很简单，但至关重要。在我们明确删除`Singleton`对象的情况下，我们通过设置`destroyer.setSingleton(NULL);`来做好准备。请记住，`President`继承了受保护的`static SingletonDestroyer destroyer;`数据成员。在这里，我们将销毁者的关联`Singleton`设置为`NULL`。然后，我们的`President`析构函数中的这行代码使得`SingletonDestroyer`的析构函数能够准确地依赖于检查其关联的`Singleton`是否已经在开始其`Singleton`对应部分的通常删除之前被删除。

最后，我们定义了一个静态方法，为我们的`President`提供`Singleton`的创建接口，使用`static President *instance(const char *, const char *, char, const char *);`。在`instance()`的定义中，我们首先检查继承的受保护数据成员`Singleton *theInstance`是否为`NULL`。如果我们还没有分配`Singleton`，我们使用上述的私有构造函数分配`President`并将这个新分配的`President`实例分配给`theInstance`。这是从`President *`向`Singleton *`的向上转型，在公共继承边界上没有问题。然而，如果在`instance()`方法中，我们发现`theInstance`不是`NULL`，我们只需返回指向先前分配的`Singleton`对象的指针。由于用户无疑会想要将此对象用作`President`来享受继承的`Person`功能，我们将`theInstance`向下转型为`President *`，作为此方法的返回值。

最后，让我们考虑一下我们整个应用程序中一个示例客户端的后勤。在其最简单的形式中，我们的客户端将包含一个`main()`函数来驱动应用程序并展示我们的 Singleton 模式。

### 将模式组件在客户端中组合在一起

现在让我们来看看我们的`main()`函数是如何组织我们的模式的：

```cpp
int main()
{ 
    // Create a Singleton President
    President *p1 = President::instance("John", "Adams", 
                                        'Q', "President");
    // This second request will fail, returning orig. instance
    President *p2 = President::instance("William", "Harrison",
                                        'H', "President");
    if (p1 == p2)   // Verification there's only one object
        cout << "Same instance (only one Singleton)" << endl;
    p1->Print();
    // SingletonDestroyer will release Singleton at end
    return 0;
}
```

回顾我们在前面的代码中的`main()`函数，我们首先使用`President *p1 = President::instance("John", "Adams", 'Q', "President");`分配一个 Singleton `President`。然后我们尝试在下一行代码中分配另一个`President`，使用`*p2`。因为我们只能有一个`Singleton`（`President` *混入*了一个`Singleton`），一个指针被返回到我们现有的`President`并存储在`p2`中。我们通过比较`p1 == p2`来验证只有一个`Singleton`；指针确实指向同一个实例。

接下来，我们利用我们的`President`实例以其预期的方式使用，比如使用从`Person`继承的一些成员函数。例如，我们调用`p1->Print();`。当然，我们的`President`类可以添加适合在我们的客户端中使用的专门功能。

现在，在`main()`的末尾，我们的静态对象`SingletonDestroyer Singleton::destroyer;`将在其内存被回收之前被适当地销毁。正如我们所看到的，`SingletonDestroyer`的析构函数（通常）会使用`delete theSingleton;`向其关联的`Singleton`（实际上是`President`）发出`delete`。这将触发我们的`President`析构函数、`Singleton`析构函数和`Person`析构函数分别被调用和执行（从最专门的到最一般的子对象）。由于我们的`Singleton`析构函数是虚拟的，我们保证从正确的级别开始销毁并包括所有析构函数。

让我们看看这个程序的输出：

```cpp
Creating the Singleton
Singleton previously created. Returning existing singleton
Same instance (only one Singleton)
President John Q Adams
SingletonDestroyer destructor
President destructor
Singleton destructor
Person destructor
```

在前面的输出中，我们可以看到 Singleton `President`的创建，以及第二个`instance()`请求一个`President`只是返回现有的`President`。然后我们看到打印出的`President`的细节。

最有趣的是，我们可以看到`Singleton`的销毁顺序，这是由`SingletonDestroyer`的静态对象回收驱动的。通过在`SingletonDestroyer`析构函数中正确删除`Singleton`，我们看到`President`、`Singleton`和`Person`的析构函数都被调用，因为它们共同构成了完整的`President`对象。

### 检查显式单例删除及其对 SingletonDestroyer 析构函数的影响

让我们看看客户端的另一个版本，其中有一个替代的`main()`函数。在这里，我们强制删除我们的`Singleton`；这是罕见的。在这种情况下，我们的`SingletonDestroyer`不会删除其配对的`Singleton`。这个例子可以在我们的 GitHub 存储库中找到作为一个完整的程序。

[`github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter19/Chp19-Ex3.cpp`](https://github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter19/Chp19-Ex3.cpp)

```cpp
int main()
{
    President *p1 = President::instance("John", "Adams", 
                                        'Q', "President");
    President *p2 = President::instance("William", "Harrison",
                                        'H', "President");
    if (p1 == p2)  // Verification there's only one object
        cout << "Same instance (only one Singleton)" << endl;
    p1->Print();
    delete p1;  // Delete the Singleton – unusual.
    return 0;   // Upon checking, the SingletonDestroyer will
}           // no longer need to destroy its paired Singleton
```

在上述的`main()`函数中，注意我们明确地使用`delete p1;`来释放我们的单例`President`，而不是让实例在程序结束时通过静态对象删除来回收。幸运的是，我们在我们的`SingletonDestroyer`析构函数中包含了一个测试，让我们知道`SingletonDestroyer`是否必须删除其关联的`Singleton`，或者这个删除已经发生。

让我们来看一下修改后的输出，注意与我们原来的`main()`函数的区别：

```cpp
Creating the Singleton
Singleton previously created. Returning existing singleton
Same instance (only one Singleton)
President John Q Adams
President destructor
Singleton destructor
Person destructor
SingletonDestroyer destructor: Singleton has already been destructed
```

在我们修改后的客户端的输出中，我们可以再次看到单例`President`的创建，第二个`President`的*失败*创建请求，等等。

让我们注意一下销毁顺序以及它与我们第一个客户端的不同之处。在这里，单例`President`被明确地释放。我们可以看到`President`的正确删除，通过在`President`，`Singleton`和`Person`中的析构函数的调用和执行。现在，当应用程序即将结束并且静态`SingletonDestroyer`即将回收其内存时，我们可以看到`SingletonDestroyer`上的析构函数被调用。然而，这个析构函数不再删除其关联的`Singleton`。

### 理解设计的优势和劣势

前面（成对类）实现的单例模式的一个优点（无论使用哪个`main()`）是，我们保证了`Singleton`的正确销毁。这不管`Singleton`是长寿命的，并且通过其关联的`SingletonDestroyer`以通常方式被删除，还是在应用程序中较早地直接删除（一个罕见的情况）。

这种实现的一个缺点是继承自`Singleton`的概念。也就是说，只能有一个派生类`Singleton`包含`Singleton`类的特定机制。因为我们从`Singleton`继承了`President`，我们正在使用`President`和`President`独自使用的单例逻辑（即静态数据成员，存储在外部变量中）。如果另一个类希望从`Singleton`派生以采用这种习惯用法，`Singleton`的内部实现已经被用于`President`。哎呀！这看起来不公平。

不用担心！我们的设计可以很容易地扩展，以适应希望使用我们的`Singleton`基类的多个类。我们将扩展我们的设计以容纳多个`Singleton`对象。然而，我们仍然假设每个类类型只有一个`Singleton`实例。

现在让我们简要地看一下如何扩展单例模式来解决这个问题。

## 使用注册表允许多个类使用单例

让我们更仔细地检查一下我们当前单例模式实现的一个缺点。目前，只能有一个派生类`Singleton`能有效地利用`Singleton`类。为什么呢？`Singleton`是一个带有外部变量定义的类，用于支持类内的静态数据成员。代表`theInstance`的静态数据成员（使用外部变量`Singleton *Singleton::theInstance`实现）只能设置为一个`Singleton`实例。*不是每个类一个* - 只有一组外部变量创建了关键的`Singleton`数据成员`theInstance`和`destroyer`的内存。问题就在这里。

相反，我们可以指定一个`Registry`类来跟踪应用单例模式的类。有许多**Registry**的实现，我们将审查其中一种实现。

在我们的实现中，`Registry`将是一个类，它将类名（对于使用 Singleton 模式的类）与每个注册类的单个允许实例的`Singleton`指针配对。我们仍然将每个 Target 类从`Singleton`派生（以及根据我们的设计认为合适的任何其他类）。

我们从`Singleton`派生的每个类中的`instance()`方法将被修改如下：

+   我们在`instance()`中的第一个检查将是调用`Registry`方法（使用派生类的名称），询问该类是否以前创建过`Singleton`。如果`Registry`方法确定已经为请求的派生类型实例化了`Singleton`，则`instance()`将返回对现有实例的指针。

+   相反，如果`Registry`允许分配`Singleton`，`instance()`将分配`Singleton`，就像以前一样，将`theInstance`的继承受保护数据成员设置为分配的派生`Singleton`。静态`instance()`方法还将通过使用`setSingleton()`设置继承受保护的销毁者数据成员的反向链接。然后，我们将新实例化的派生类实例（即`Singleton`）传递给`Registry`方法，以在`Registry`中`Store()`新分配的`Singleton`。

我们注意到存在四个指向相同`Singleton`的指针。一个是从我们的派生类`instance()`方法返回的派生类类型的专用指针。这个指针将被传递给我们的客户端进行应用使用。第二个`Singleton`指针将是存储在我们继承的受保护数据成员`theInstance`中的指针。第三个`Singleton`指针将是存储在`SingletonDestroyer`中的指针。第四个指向`Singleton`的指针将存储在`Registry`中。没有问题，我们可以有多个指向`Singleton`的指针。这是`SingletonDestroyer`在其传统销毁功能中使用的一个原因-它将在应用程序结束时销毁每种类型的唯一`Singleton`。

我们的`Registry`将维护每个使用`Singleton`模式的类的一对，包括类名和相应类的（最终）指针到特定`Singleton`。每个特定`Singleton`实例的指针将是一个静态数据成员，并且还需要一个外部变量来获取其底层内存。结果是每个拥抱 Singleton 模式的类的一个额外的外部变量。

`Registry`的想法如果我们选择另外容纳 Singleton 模式的罕见使用，可以进一步扩展。如果我们选择另外容纳 Singleton 模式的罕见使用，`Registry`的想法可以进一步扩展。在这种扩展模式中的一个例子可能是，我们选择对一个只有一个校长但有多个副校长的高中进行建模。`Principal`将是`Singleton`的一个预期派生类，而多个副校长将代表`Vice-Principal`类的固定数量的实例（派生自`Singleton`）。我们的注册表可以扩展到允许`Vice-Principal`类型的`N`个注册的`Singleton`对象。

我们现在已经看到了使用成对类方法实现 Singleton 模式。我们已经将`Singleton`、`SingetonDestroyer`、Target 和 Client 的概念折叠到我们习惯看到的类框架中，即`Person`，以及我们的`Singleton`和`Person`的后代类（`President`）。让我们现在简要回顾一下我们在模式方面学到的东西，然后继续下一章。

# 总结

在本章中，我们通过接受另一个设计模式来扩展我们的编程技能，从而实现了成为更好的 C++程序员的目标。我们首先采用了一种简单的方法来探讨 Singleton 模式，然后使用`Singleton`和`SingletonDestroyer`进行了成对类的实现。我们的方法使用继承将 Singleton 的实现合并到我们的 Target 类中。可选地，我们使用多重继承将一个有用的现有基类合并到我们的 Target 类中。

利用核心设计模式，如 Singleton 模式，将帮助您更轻松地重用现有的经过充分测试的代码部分，以一种其他程序员理解的方式。通过使用熟悉的设计模式，您将为众所周知和可重用的解决方案做出贡献，采用前卫的编程技术。

现在，我们准备继续前往我们的最终设计模式，在*第二十章*中，*使用 pImpl 模式去除实现细节*。将更多的模式添加到我们的编程技能库中，使我们成为更多才多艺和有价值的程序员。让我们继续前进！

# 问题

1.  使用本章中找到的 Singleton 模式示例：

a. 实现一个`President`到`辞职()`的接口，或者实现一个接口来`弹劾()`一个`President`。您的方法应删除当前的 Singleton`President`（并从`SingletonDestroyer`中删除该链接）。`SingletonDestroyer`有一个`setSingleton()`，可能有助于帮助您删除反向链接。

b. 注意到前任的 Singleton`President`已被移除，使用`President::instance()`创建一个新的`President`。验证新的`President`已经安装。

c.（*可选*）创建一个`Registry`，允许在多个类中有效地使用`Singleton`（不是互斥的，而是当前的实现）。

1.  为什么不能将`Singleton`中的`static instance()`方法标记为虚拟，并在`President`中重写它？

1.  您能想象哪些其他例子可能很容易地融入 Singleton 模式？
