# C++ 面向对象编程揭秘（三）

> 原文：[`zh.annas-archive.org/md5/BCB2906673DC89271C447ACAA17D3E00`](https://zh.annas-archive.org/md5/BCB2906673DC89271C447ACAA17D3E00)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：通过多态利用动态绑定

本章将进一步扩展我们对 C++中面向对象编程的知识。我们将首先介绍一个强大的面向对象概念，**多态**，然后理解这一概念是如何通过*直接语言支持*在 C++中实现的。我们将使用虚函数在相关类的层次结构中实现多态，并理解如何将特定派生类方法的运行时绑定到更通用的基类操作。我们将理解本章中呈现的多态的面向对象概念将支持多样化和健壮的设计，并在 C++中轻松实现可扩展的代码。

在本章中，我们将涵盖以下主要主题：

+   理解多态的面向对象概念以及它对面向对象编程的重要性。

+   定义虚函数，理解虚函数如何覆盖基类方法，泛化派生类对象，虚析构函数的必要性以及函数隐藏

+   理解方法对操作的动态（运行时）绑定

+   对**虚函数表**（**v-table**）的详细理解

通过本章结束时，您将理解多态的面向对象概念，以及如何通过虚函数在 C++中实现这一概念。您将理解虚函数如何使得 C++中方法对操作的运行时绑定成为可能。您将看到如何在基类中指定一个操作，并在派生类中用首选实现进行覆盖。您将理解何时以及为何重要利用虚析构函数。

您将看到派生类的实例通常使用基类指针存储的原因，以及这一点的重要性。我们将发现，无论实例是如何存储的（作为其自身类型还是作为基类的类型），虚函数的正确版本始终会通过动态绑定应用。具体来说，当我们检查 C++中的虚函数指针和虚函数表时，您将看到运行时绑定是如何在幕后工作的。

通过理解 C++中虚函数对多态的直接语言支持，您将能够创建一组相关类的可扩展层次结构，实现方法对操作的动态绑定。让我们通过详细介绍这些理想来增进对 C++作为面向对象编程语言的理解。

# 技术要求

完整程序示例的在线代码可在以下 GitHub 网址找到：[`github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter07`](https://github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter07)。每个完整程序示例都可以在 GitHub 存储库中找到，位于相应章节标题（子目录）下的文件中，文件名由章节号后跟当前章节中的示例号组成。例如，本章的第一个完整程序可以在名为`Chp7-Ex1.cpp`的文件中的`Chapter07`子目录下找到。

本章的 CiA 视频可在以下网址观看：[`bit.ly/317dxf3`](https://bit.ly/317dxf3)。

# 理解多态的面向对象概念

在本节中，我们将介绍一个重要的面向对象概念，多态。

从*第五章* *详细探索类*，和*第六章* *使用单继承实现层次结构*，您现在理解了封装、信息隐藏、泛化和特化的关键面向对象的思想。您知道如何封装一个类，使用单继承构建继承层次结构，以及构建层次结构的各种原因（例如支持 Is-A 关系或支持实现继承的较少使用的原因）。让我们通过探索**多态**来扩展我们的基本面向对象术语。

当基类指定一个操作，使得派生类可以用更合适的方法重新定义该操作时，该操作被称为**多态的**。让我们重新审视我们对操作和方法的定义，以及它们的含义，以了解这些概念如何为多态性奠定基础：

+   在 C++中，**操作**映射到成员函数的完整签名（名称加上参数的类型和数量 - 没有返回类型）。

+   此外，在 C++中，**方法**映射到操作的定义或主体（即成员函数的实现或主体）。

+   回顾一下，在面向对象的术语中，**操作**实现了类的行为。基类操作的实现可以通过几个不同的派生类**方法**来实现。

`Student` 是 `Person`。然而，多态操作将允许在`Student`对象上显示`Student`行为，即使它们已经*采用了*`Person`的形式。

在本章中，我们将看到派生类对象采用其公共基类的形式，即采用*多种形式*（**多态性**）。我们将看到如何在基类中指定多态操作，并在派生类中用首选实现进行重写。

让我们从 C++语言特性开始，这些特性允许我们实现多态性，即虚函数。

# 使用虚函数实现多态性

多态性允许将方法动态绑定到操作。将方法动态绑定到操作是重要的，因为派生类实例可能被基类对象指向（即，通过基类类型的指针）。在这些情况下，指针类型无法提供关于应该应用于引用实例的正确方法的足够信息。我们需要另一种方式 - 在运行时完成 - 来确定哪种方法适用于每个实例。

通常情况下，指向派生类实例的指针会被泛化为指向基类类型的指针。当对指针应用操作时，应该应用对象真正的方法，而不是对泛化指针类型似乎合适的方法。

让我们从定义虚函数所需的相关关键字和逻辑开始，以便我们可以实现多态性。

## 定义虚函数并重写基类方法

C++中的**虚函数**直接支持多态性。**虚函数**是：

+   一个成员函数，允许为给定操作的方法在层次结构中被连续重写以提供更合适的定义。

+   允许动态绑定方法而不是通常的静态绑定的成员函数。

使用关键字**virtual**指定虚函数。更具体地说：

+   关键字`virtual`应该在函数原型中的返回类型之前。

+   在派生类中具有与任何祖先类中虚函数相同名称和签名的函数会重新定义这些基类中的虚函数。在这里，关键字`virtual`是可选的，但在派生类原型中是推荐的。

+   在派生类中具有相同名称但不同签名的函数不会重新定义其基类中的虚函数；而是隐藏其基类中的方法。

+   在派生类原型中，可以选择性地添加关键字`override`作为扩展签名的一部分。这种推荐做法将允许编译器在预期重写的方法的签名与基类中指定的签名不匹配时标记错误。`override`关键字可以消除意外的函数隐藏。

派生类如果继承的方法适用，就不需要重新定义基类中指定的虚函数。然而，如果派生类用新方法重新定义一个操作，必须使用与被覆盖方法相同的签名（由基类指定）。此外，派生类应该只重新定义虚函数。

这里有一个简单的例子来说明基本语法：

+   `Print()`是在基类`Person`中定义的虚函数。它将被`Student`类中更合适的实现所覆盖：

```cpp
class Person  // base class
{
private:
    char *name;
    char *title;
public:
    // constructors, destructor, 
    // public access functions, public interface etc. …
    Person introduces a virtual function, Print(). By labeling this function as virtual, the Person class is inviting any future descendants to redefine this function with a more suitable implementation or method, should they be so motivated.
```

+   在基类`Person`中定义的虚函数实际上是在`Student`类中用更合适的实现进行了覆盖：

```cpp
class Student: public Person  // derived class
{
private:
    float gpa;
public:
    // constructors, destructor specific to Student,
    // public access functions, public interface, etc. …
    Student introduces a new implementation of Print() that will override (that is, replace), the definition in Person. Note that if the implementation of Person::Print() were acceptable to Student, Student would not be obligated to override this function, even if it is marked as virtual in the base class. The mechanics of public inheritance would simply allow the derived class to inherit this method.But because this function is `virtual` in `Person`, `Student` may opt to redefine this operation with a more suitable method. Here, it does. In the `Student::Print()` implementation, `Student` first calls `Person::Print()` to take advantage of the aforementioned base class function, then prints additional information itself. `Student::Print()` is choosing to call a base class function for help; it is not required to do so if the desired functionality can be implemented fully within its own class scope. Notice that when `Student::Print()` is defined to override `Person::Print()`, the same signature as specified by the base class is used. This is important. Should a new signature have been used, we would get into a potential function hiding scenario, which we will soon discuss in our sub-section, *Considering function hiding*, within this chapter.Note that though the virtual functions in `Person` and `Student` are written inline, a virtual function will never be expanded as inline code by the compiler since the specific method for the operation must be determined at runtime.
```

记住，多态函数的目的是具有覆盖或替换给定函数的基类版本的能力。函数重写与函数重载不同。

重要区别

**函数重写**是通过在相关类的层次结构中引入相同的函数名称和签名（通过虚函数）来定义的，而派生类版本旨在替换基类版本。相比之下，**函数重载**是在程序的同一作用域中存在两个或更多具有相同名称但不同签名的函数时定义的（比如在同一个类中）。

此外，在基类定义中最初未指定为虚拟的操作也不是多态的，因此不应该在任何派生类中被覆盖。这意味着，如果基类在定义操作时没有使用关键字`virtual`，那么基类并不打算让派生类用更合适的派生类方法重新定义这个操作。相反，基类坚持认为它提供的实现适用于*任何*它的后代。如果派生类尝试重新定义一个非虚拟的基类操作，将会在应用程序中引入一个微妙的错误。错误将是，使用派生类指针存储的派生类实例将使用派生类方法，而使用基类指针存储的派生类实例将使用基类定义。实例应该始终使用自己的行为，而不管它们是如何存储的 - 这就是多态的意义。永远不要重新定义非虚函数。

重要说明

在 C++中，未在基类中指定为虚拟的操作不是多态的，也不应该被派生类覆盖。

让我们继续前进，发现我们可能希望通过基类类型收集派生类对象的情况，以及我们可能需要将我们的析构函数标记为虚拟的情况。

## 泛化派生类对象

当我们查看继承层次结构时，通常是使用公共基类的层次结构；也就是说，这是一个使用公共继承来表达 Is-A 关系的层次结构。以这种方式使用继承时，我们可能会被激励将相关实例的组合在一起。例如，`Student`专业化的层次结构可能包括`GraduateStudent`、`UnderGraduateStudent`和`NonDegreeStudent`。假设这些派生类中的每一个都有一个名为`Student`的公共基类，那么说`GraduateStudent` *是一个* `Student`，等等，就是合适的。

我们可能会在我们的应用程序中找到一个理由，将这些类似的实例组合到一个共同的集合中。例如，想象一下，我们正在为一所大学实现一个计费系统。大学可能希望我们将所有学生，无论其派生类类型如何，收集到一个集合中以便统一处理，比如计算他们的学期账单。

`Student`类可能有一个多态操作`CalculateSemesterBill()`，它在`Student`中作为一个虚拟函数实现了一个默认方法。然而，选择的派生类，比如`GraduateStudent`，可能有他们希望通过在自己的类中覆盖操作来提供的首选实现。例如，`GraduateStudent`可能有一个不同的方法来计算他们的总账单与`NonDegreeStudent`。因此，每个派生类可以覆盖其类中`CalculateSemesterBill()`的默认实现。

尽管如此，在我们的财务应用程序中，我们可以创建一个`Student`类型的指针集合，尽管每个指针最终都会指向派生类类型的实例，比如`GraduateStudent`、`UnderGraduateStudent`和`NonDegreeStudent`。当以这种方式泛化派生类类型的实例时，适用于集合指针类型的基类级别中定义的函数（通常是虚拟函数）是合适的。虚拟函数允许这些泛化的实例调用多态操作，以产生它们各自的派生类方法或这些函数的实现。这正是我们想要的。但是，还有更多细节需要理解。

这个推广派生类实例的基本前提将使我们理解为什么我们可能需要在许多类定义中使用虚拟析构函数。让我们来看一下。

## 利用虚拟析构函数

现在我们可以概念化一下，将派生类实例按其共同的基类类型分组，并通过虚拟函数允许它们的不同行为显现出来可能是有用的情况。通过它们的基类类型收集同类派生类实例，并利用虚拟函数允许它们独特的行为显现出来，实际上是非常强大的。

但是，当存储在基类指针中的派生类实例的内存消失时会发生什么呢？我们知道它的析构函数被调用了，但是哪一个？实际上，我们知道一系列的析构函数被调用，从问题对象类型的析构函数开始。但是，如果实例通过存储使用基类指针而被泛型化，我们如何知道实际的派生类对象类型呢？一个**虚拟析构函数**解决了这个问题。

通过将析构函数标记为`virtual`，我们允许它被覆盖为类及其后代的销毁序列的*起点*。选择使用哪个析构函数作为销毁的入口点将推迟到运行时，使用动态绑定，基于对象的实际类型，而不是引用它的指针类型。我们很快将看到，这个过程是如何通过检查 C++的底层虚拟函数表自动化的。

与所有其他虚拟函数不同，虚拟析构函数实际上指定了要执行的一系列函数的起点。回想一下，作为析构函数的最后一行代码，编译器会自动修补一个调用来调用直接基类的析构函数，依此类推，直到我们达到层次结构中的初始基类。销毁链的存在是为了提供一个释放给定实例的所有子对象中动态分配的数据成员的论坛。将这种行为与其他虚拟函数进行对比，其他虚拟函数仅允许执行函数的单一正确版本（除非程序员选择在派生方法实现期间调用相同函数的基类版本作为辅助函数）。

你可能会问为什么在正确的级别开始销毁序列很重要？也就是说，在与对象的实际类型匹配的级别（而不是通用指针类型，可能指向对象）。请记住，每个类可能有动态分配的数据成员。析构函数将释放这些数据成员。从正确级别的析构函数开始将确保您不会通过放弃适当的析构函数及其相应的内存释放而引入任何内存泄漏到您的应用程序中。

虚析构函数总是必要的吗？这是一个很好的问题！当使用公共基类层次结构时，即使用公共继承时，虚析构函数总是必要的。请记住，公共基类支持 Is-A 关系，这很容易导致允许使用其基类类型的指针存储派生类实例。例如，`研究生` *是* `学生`，因此我们有时可以将`研究生`存储为`学生`，以便在需要更通用的处理时与其兄弟类型一起处理。我们可以始终以这种方式在公共继承边界上进行向上转型。然而，当我们使用实现继承（即私有或受保护的基类）时，不允许向上转型。因此，在使用私有或受保护继承的层次结构中，虚析构函数是不必要的，因为向上转型是被简单地禁止的；因此，对于私有和受保护基类层次结构中的类，哪个析构函数应该是入口点永远不会是模糊的。作为第二个例子，在*第六章*中，我们的`LinkedList`类中没有包含虚析构函数；因此，`LinkedList`应该只作为受保护或私有基类扩展。然而，我们在`Queue`和`PriorityQueue`类中包含了虚析构函数，因为`PriorityQueue`使用`Queue`作为公共基类。`PriorityQueue`可以向上转型为`Queue`（但不能向上转型为`LinkedList`），因此在层次结构中的`Queue`及其后代级别引入虚析构函数是必要的。

在重写虚析构函数时，是否建议使用可选关键字`virtual`和`override`？这也是一个很好的问题。我们知道，重写的析构函数只是销毁顺序的起点。我们也知道，与其他虚函数不同，派生类的析构函数将与基类的析构函数有一个唯一的名称。尽管派生类的析构函数会自动重写已声明为`virtual`的基类析构函数，但在派生类析构函数原型中使用*可选*关键字`virtual`是为了文档化而推荐的。然而，在派生类析构函数中通常不使用*可选*关键字`override`。原因是`override`关键字旨在提供一个安全网，以捕捉原始定义和重写函数之间的拼写错误。对于析构函数，函数名称并不相同，因此这个安全网并不是一个错误检查的优势。

让我们继续把所有必要的部分放在一起，这样我们就可以看到各种类型的虚函数，包括析构函数，如何发挥作用。

## 把所有的部分放在一起

到目前为止，在本章中，我们已经了解了虚函数的微妙之处，包括虚析构函数。重要的是要看到我们的代码在实际操作中，以及它的各种组件和细节。我们需要在一个连贯的程序中看到基本语法来指定虚函数，包括如何通过基类类型收集派生类实例，以及虚析构函数如何发挥作用。

让我们看一个更复杂的、完整的程序示例，以完全说明多态性，使用 C++中的虚函数实现。这个例子将被分成许多段；完整的程序可以在以下 GitHub 位置找到：

[`github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter07/Chp7-Ex1.cpp`](https://github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter07/Chp7-Ex1.cpp)

```cpp
#include <iostream>
#include <iomanip>
#include <cstring>
using namespace std;
const int MAX = 5;
class Person
{
private: // data members
    char *firstName;
    char *lastName;
    char middleInitial;
    char *title;  // Mr., Ms., Mrs., Miss, Dr., etc.
protected:
    void ModifyTitle(const char *); 
public:
    Person();   // default constructor
    Person(const char *, const char *, char, const char *);  
    Person(const Person &);  // copy constructor
    virtual ~Person();  // virtual destructor
    const char *GetFirstName() const { return firstName; }  
    const char *GetLastName() const { return lastName; }    
    const char *GetTitle() const { return title; } 
    char GetMiddleInitial() const { return middleInitial; }
    virtual void Print() const;
    virtual void IsA();  
    virtual void Greeting(const char *);
};
```

在上述的类定义中，我们对`Person`这个熟悉的类进行了扩充，添加了四个虚函数，即析构函数(`~Person()`)，`Print()`，`IsA()`和`Greeting(const char *)`。请注意，我们只是在每个成员函数的返回类型（如果有的话）前面加上了关键字`virtual`。类定义的其余部分就像我们在上一章中深入探讨过的那样。

现在，让我们来看一下`Person`的非内联成员函数定义：

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
void Person::Print() const
{
    cout << title << " " << firstName << " ";
    cout << middleInitial << ". " << lastName << endl;
}
void Person::IsA()
{
    cout << "Person" << endl;
}
void Person::Greeting(const char *msg)
{
    cout << msg << endl;
}
```

在之前的代码段中，我们指定了`Person`的所有非内联成员函数。请注意，这四个虚函数——析构函数，`Print()`，`IsA()`和`Greeting()`——在方法（即成员函数定义）本身中不包括`virtual`关键字。

接下来，让我们来看一下`Student`类的定义：

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
    virtual ~Student();  // destructor
    void EarnPhD();  
    // inline function definitions
    float GetGpa() const { return gpa; }
    const char *GetCurrentCourse() const
        { return currentCourse; }
    const char *GetStudentId() const { return studentId; }
    void SetCurrentCourse(const char *); // prototype only

    // In the derived class, the keyword virtual is optional, 
    // but recommended for clarity. Same for override.
    virtual void Print() const override;
    virtual void IsA() override;
    // note: we choose not to redefine 
    // Person::Greeting(const char *)
};
inline void Student::SetCurrentCourse(const char *c)
{
    delete currentCourse;   // delete existing course
    currentCourse = new char [strlen(c) + 1];
    strcpy(currentCourse, c); 
}
```

在之前的`Student`类定义中，我们再次看到了构成这个类的所有各种组件。另外，请注意，我们定义了三个虚函数——析构函数，`Print()`和`IsA()`。这些首选定义基本上取代了这些操作在基类中指定的默认方法。然而，请注意，我们选择不重新定义`void Person::Greeting(const char *)`，这个方法在`Person`类中被引入为虚函数。如果我们发现继承的定义对`Student`类的实例是可以接受的，那么简单地继承这个方法就可以了。

请记住，当虚函数与析构函数配对时，它的含义是独特的，它并不意味着派生类的析构函数取代了基类的析构函数。相反，它意味着当由派生类实例发起*销毁链*序列时，派生类析构函数是正确的起始点（无论它们是如何存储的）。

还要记住，`Student`的派生类不需要覆盖在`Person`中定义的虚函数。如果`Student`类发现基类方法是可以接受的，它会自动继承。虚函数只是允许派生类在需要时用更合适的方法重新定义操作。

接下来，让我们来看一下`Student`类的非内联成员函数：

```cpp
Student::Student(): studentId (0) 
{
    gpa = 0.0;
    currentCourse = 0;
}
// Alternate constructor member function definition
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
// Copy constructor definition
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
void Student::EarnPhD()
{
    ModifyTitle("Dr.");  
}
void Student::Print() const
{   // need to use access functions as these data members are
    // defined in Person as private
    cout << GetTitle() << " " << GetFirstName() << " ";
    cout << GetMiddleInitial() << ". " << GetLastName();
    cout << " with id: " << studentId << " GPA: ";
    cout << setprecision(3) <<  " " << gpa;
    cout << " Course: " << currentCourse << endl;
}
void Student::IsA()
{
    cout << "Student" << endl;
}
```

在之前列出的代码段中，我们列出了`Student`的非内联成员函数定义。同样，请注意，关键字`virtual`不会出现在任何非内联成员函数定义本身中，只会出现在它们各自的原型中。

最后，让我们来看一下`main()`函数：

```cpp
int main()
{
    Person *people[MAX];
    people[0] = new Person("Juliet", "Martinez", 'M', "Ms.");
    people[1] = new Student("Hana", "Sato", 'U', "Dr.", 3.8,
                            "C++", "178PSU"); 
    people[2] = new Student("Sara", "Kato", 'B', "Dr.", 3.9,
                            "C++", "272PSU"); 
    people[3] = new Person("Giselle", "LeBrun", 'R', "Miss");
    people[4] = new Person("Linus", "Van Pelt", 'S', "Mr.");
    for (int i = 0; i < MAX; i++)
    {
       people[i]->IsA();
       cout << "  ";
       people[i]->Print();
    } 
    for (int i = 0; i < MAX; i++)
       delete people[i];   // engage virtual dest. sequence
    return 0;
}
```

在`main()`中，我们声明了一个指向`Person`的指针数组。这样做可以让我们在这个集合中收集`Person`和`Student`的实例。当然，我们可以对以这种泛化方式存储的实例应用的唯一操作是在基类`Person`中找到的操作。

接下来，我们分配了几个`Person`和几个`Student`的实例，将每个实例通过一个指针的泛化集合中的元素存储起来。当以这种方式存储`Student`时，会执行向基类类型的向上转型（但实例本身不会被改变）。请记住，当我们在*第六章*中查看单继承的层次结构的内存布局时，我们注意到`Student`实例首先包括`Person`的内存布局，然后是`Student`数据成员所需的额外内存。这种向上转型只是指向这个集体内存的起始点。

现在，我们通过循环将`Person`类中找到的操作应用于这个泛化集合中的所有实例。这些操作恰好是多态的。也就是说，虚拟函数允许通过运行时绑定调用方法的具体实现，以匹配实际对象类型（不管对象是否存储在泛化指针中）。

最后，我们通过循环删除动态分配的`Person`和`Student`实例，再次使用泛化的`Person`指针。因为我们知道`delete()`会调用析构函数，我们明智地将析构函数设为`virtual`，使得动态绑定可以选择适当的起始析构函数（在销毁链中）来销毁每个对象。

当我们查看上述程序的输出时，可以看到对于每个虚拟函数，都适当地调用了每个对象的特定方法，包括销毁序列。以下是完整程序示例的输出：

```cpp
Person
  Ms. Juliet M. Martinez
Student
  Dr. Hana U. Sato with id: 178PSU GPA:  3.8 Course: C++
Student
  Dr. Sara B. Kato with id: 272PSU GPA:  3.9 Course: C++
Person
  Miss Giselle R. LeBrun
Person
  Mr. Linus S. Van Pelt
```

现在我们已经掌握了多态的概念和虚拟函数的机制，让我们来看一下与虚拟函数相关的不太常见的情况，即函数隐藏。

## 考虑函数隐藏

**函数隐藏**并不是 C++中经常使用的特性。事实上，它经常是意外使用的！让我们回顾一下我们对继承成员函数的了解。当一个操作由基类指定时，它旨在为所有派生类方法提供使用和重新定义的协议（对于虚函数的情况）。

有时，派生类会改变一个方法的签名，这个方法是用来重新定义基类指定的操作（比如虚函数）。在这种情况下，新的函数与祖先类中指定的操作在签名上不同，将不被视为继承操作的虚拟重新定义。事实上，它会*隐藏*祖先类中具有相同名称的虚拟函数的继承方法。

当程序编译时，会将每个函数的签名与类定义进行比较，以确保正确使用。通常情况下，当在类中找不到与实例类型*看似*匹配的成员函数时，会向上遍历继承链，直到找到匹配项或者继承链耗尽为止。让我们更仔细地看一下编译器考虑的内容：

+   当找到一个与所寻找的函数同名的函数时，将检查其签名，看它是否与函数调用完全匹配，或者是否可以应用类型转换。当找到函数时，但无法应用类型转换时，正常的遍历顺序就结束了。

+   通常情况下，隐藏虚拟函数的函数会中止这种向上搜索序列，从而隐藏了本来可能被调用的虚拟函数。请记住，在编译时，我们只是检查语法（而不是决定调用哪个版本的虚拟函数）。但如果我们找不到匹配项，就会报错。

+   函数隐藏实际上被认为是有帮助的，并且是语言所期望的。如果类设计者提供了一个具有特定签名和接口的特定函数，那么该函数应该用于该类型的实例。在这种特定情况下，不应该使用在继承链中之前隐藏或未知的函数。

考虑对我们之前的完整程序示例进行以下修改，首先说明函数隐藏，然后提供一个更灵活的解决方案来管理函数隐藏：

+   请记住，`Person`类引入了没有参数的`virtual void Print()`。想象一下，`Student`不是用相同的签名覆盖`Print()`，而是将签名更改为`virtual void Print(const char *)`。

```cpp
class Person  // base class
{
    // data members
public:  // member functions, etc. 
    Print() has changed from a base to a derived class. The derived class function does not redefine the virtual void Print(); of its base class. It is a new function that will in fact hide the existence of Person::Print(). This is actually what was intended, since you may not recall that the base class offers such an operation and tracking upward might cause surprising results in your application if you intended Print(const char *) to be called and if Print() is called instead. By adding this new function, the derived class designer is dictating this interface is the appropriate Print() for instances of Student.However, nothing is straightforward in C++. For situations where a `Student` is up-cast to a `Person`, the `Person::Print()` with no arguments will be called. The `Student::Print(const char *)` is not a virtual redefinition because it does not have the same signature. Hence, the `Person::Print()` will be called for generalized `Student` instances. And yet `Student::Print(const char *)` will be called for `Student` instances stored in `Student` variables. Unfortunately, this is inconsistent in how an instance will behave if it is stored in its own type versus a generalized type. Though function hiding was meant to work in this fashion, it may inevitably not be what you would like to happen. Programmers beware!
```

让我们来看一些可能出现的冗长代码：

+   可能需要显式向下转型或使用作用域解析运算符来揭示一个被隐藏的函数：

```cpp
int main()
{ 
    Person *people[2];
    people[0] = new Person("Jim", "Black", 'M', "Mr.");
    people[1] = new Student("Kim", "Lin", 'Q', "Dr.",
                            3.55, "C++", "334UD"); 
    people[1]->Print();  // ok, Person::Print() defined
    // people[1]->Print("Go Team!"); // error!
    // explicit downcast to derived type assumes you
    // correctly recall what the object is
    ((Student *)people[1])->Print("I have to study");

    // Student stored in its own type
    Student s1("Jafari", "Kanumba", 'B', "Dr.", 3.9,
               "C++", "845BU"); 
    // s1.Print();  // error, base class version hidden
    s1.Print("I got an A!"); // works for type Student
    s1.Person::Print(); // works using scope resolution
                        // to base class type
    return 0;
}
```

在上述示例中，我们有一个包含两个`Person`指针的广义集合。一个指向`Person`，一个指向`Student`。一旦`Student`被泛化，唯一适用的操作就是在`Person`基类中找到的操作。因此，对`people[1]->Print();`的调用有效，而对`people[1]->Print("Go Team!");`的调用无效。对`Print(const char *)`的后者调用在广义基类级别上是一个错误，尽管对象实际上是`Student`。

如果我们希望从一个广义指针调用层次结构中`Student`级别的特定函数，我们就需要将实例向下转型回其自身类型（`Student`）。我们通过调用`((Student *) people[1])->Print("I have to study");`来进行向下转型。在这里，我们承担了一定的风险 - 如果`people[1]`实际上是`Person`而不是`Student`，这将生成运行时错误。

接下来，我们实例化`Student s1;`。如果我们尝试调用`s1.Print()`，我们将会得到一个编译器错误 - `Student::Print(const char *)`隐藏了`Person::Print()`的存在。请记住，`s1`存储在其自身类型`Student`中，因此找到`Student::Print(const char *)`后，向上遍历以揭示`Person::Print()`被阻止了。

尽管如此，我们对`s1.Print("I got an A!");`的调用是成功的，因为`Print(const char *)`在`Student`类级别找到了。最后，请注意，对`s1.Person::Print();`的调用是有效的，但需要了解被隐藏的函数。通过使用作用域解析运算符（`::`），我们可以找到`Print()`的基类版本。即使`Print()`在基类中是虚拟的（意味着动态绑定），使用作用域解析操作将此调用恢复为静态绑定的函数调用。

假设我们想要向派生类添加一个新的接口，其中的函数会隐藏基类函数。了解函数隐藏后，我们应该怎么做？我们可以简单地在派生类中重写基类中找到的虚函数，并且可以重载该函数以添加额外的接口。是的，我们现在既重写又重载。也就是说，我们重写了基类函数，并在派生类中重载了被重写的函数。

让我们看看我们现在会得到什么：

+   以下是添加新成员函数的更灵活接口，同时保留原本可能被隐藏的现有接口：

```cpp
class Person  // base class
{
    // data members
public:  // member functions, etc.
    Student class both overrides Person::Print() with Student::Print() and overloads Student::Print() with Student::Print(const char *) to envelop the additional desired interface. Now, for Student objects stored in Student variables, both interfaces are available – the base class interface is no longer hidden. Of course, Student objects referenced by Person pointers only have the Person::Print() interface, which is to be expected. 
```

总的来说，函数隐藏并不经常出现。但当出现时，通常会给人带来不必要的惊喜。现在你了解了可能发生的情况以及原因，这会让你成为一个更好的程序员。

现在我们已经看过了所有关于虚函数的用法，让我们来看看为什么虚函数能够支持将特定方法动态绑定到操作上。为了彻底理解运行时绑定，我们需要看一下虚函数表。让我们继续前进！

# 理解动态绑定

现在我们已经看到了多态是如何通过虚函数实现的，以允许将操作动态绑定到特定的实现或方法，让我们了解为什么虚函数允许运行时绑定。

非虚函数在编译时静态绑定。也就是说，所涉及函数的地址是在编译时确定的，基于手头对象的假定类型。例如，如果实例化了类型为`Student`的对象，函数调用将从`Student`类开始验证其原型，并且如果找不到，将向上遍历每个基类，如`Person`，以寻找匹配的原型。找到后，正确的函数调用将被修补。这就是静态绑定的工作原理。

然而，虚函数是 C++中一种在运行时使用动态绑定的函数类型。在编译时，任何虚函数调用都仅仅被替换为一个查找机制，以延迟绑定直到运行时。当然，每个编译器供应商在自动化虚函数方面的实现可能有所不同。然而，有一种广泛使用的实现涉及虚函数指针、虚函数表和包含虚函数的每种对象类型的虚函数表条目。

让我们继续调查 C++中动态绑定是如何常见实现的。

## 理解方法与操作的运行时绑定

我们知道虚函数允许将操作（在基类中指定）动态绑定到特定的实现或方法（通常在派生类中指定）。这是如何工作的？

当基类指定一个或多个新的虚函数（不仅仅是祖先虚函数的重新定义）时，在给定类型的实例的内存下方将创建一个**虚函数指针**（vptr）。这发生在运行时，当为实例创建内存时（在堆栈、堆或静态/外部区域）。当涉及的实例被构造时，不仅将调用适当的构造函数来初始化实例，而且这个 VPTR 将被初始化为指向该类类型的**虚函数指针表**（v-table）条目。

给定类类型的虚函数表（v-table）条目将由一组函数指针组成。这些函数指针通常组织成一个函数指针数组。**函数指针**是指向实际函数的指针。通过解引用这个指针，您实际上会调用指针所指向的函数。有机会向函数传递参数，但是为了通过函数指针进行通用调用，参数必须对该指针可能指向的任何版本的函数都是统一的。函数指针的前提条件使我们能够指向特定函数的不同版本。也就是说，我们可以指向给定操作的不同方法。这是我们可以在 C++中为虚函数自动绑定动态的基础。

让我们考虑特定对象类型的虚函数表条目。我们知道这个表条目将由一组函数指针组成，例如函数指针数组。这些函数指针排列的顺序将与给定类引入的虚函数的顺序一致。重写现有虚函数的函数将简单地用要调用的函数的首选版本替换表条目，但不会导致在函数指针数组中分配额外的条目。

因此，当程序开始运行时，首先在全局内存中（作为隐藏的外部变量），将设置一个虚函数表。该表将包含包含虚函数的每种对象类型的条目。给定对象类型的条目将包含一组函数指针（例如函数指针数组），它组织和初始化该类的动态绑定函数。函数指针的特定顺序将与引入虚函数的顺序相对应（可能是由它们的祖先类引入的），并且特定的函数指针将被初始化为该类类型的特定函数的首选版本。也就是说，函数指针可能指向其自己类级别指定的重写方法。

然后，当实例化给定类型的对象时，该对象内部的 vptr（每个新引入的子对象级别的虚函数，而不是重新定义的虚函数，将有一个）将被设置为指向该实例的相应 v-table 条目。

通过代码和内存图，看到这些细节将是有用的。让我们深入了解代码的运行情况！

## 详细解释虚函数表（v-table）

为了详细说明内存模型并查看运行时设置的底层 C++机制，让我们考虑来自本节的详细完整程序示例，其中包括基类`Person`和派生类`Student`的关键元素。作为提醒，我们将展示程序的关键元素：

+   `Person`和`Student`类的缩写定义（我们将省略数据成员和大多数成员函数定义以节省空间）：

```cpp
class Person
{
private:   // data members will be as before
protected: // assume all member function are as before,
public:  // but we will show only virtual functions here
    Person and Student class definitions are as expected. Assume that the data members and member functions are as shown in the full program example. For brevity, we have just included the virtual functions introduced or redefined at each level. 
```

+   重新审视我们`main()`函数的关键元素，以缩写形式：

```cpp
int main()
{
    Person *people[3];
    people[0] = new Person("Joy", "Lin", 'M', "Ms.");
    people[1] = new Student("Renee", "Alexander", 'Z',
                    "Dr.", 3.95, "C++", "21-MIT"); 
    people[2] = new Student("Gabby", "Doone", 'A', 
                    "Ms.", 3.95, "C++", "18-GWU"); 
    for (int i = 0; i < 3; i++)
    {                 // at compile time, modified to:
        people[i]->IsA();  // *(people[i]->vptr[2])()
        people[i]->Print();
        people[i]->Greeting();
        delete people[i];
    }
    return 0;
}
```

在我们的`main()`函数中，注意我们实例化了一个`Person`实例和两个`Student`实例。所有这些都存储在基类类型`Person`的指针的通用数组中。然后，我们通过集合进行迭代，对每个实例调用虚函数，即`IsA()`，`Print()`，`Greeting()`和析构函数（在我们删除每个实例时隐式调用）。

考虑到先前示例的内存模型，我们有以下图表：

![图 7.1 - 当前示例的内存模型](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/dmst-oop-cpp/img/Figure_7.1_B15702.jpg)

图 7.1 - 当前示例的内存模型

在上述的内存图中（遵循前面的程序），请注意我们有一个指向`Person`的通用化实例的指针数组。第一个实例实际上是一个`Person`，而另外两个实例是`Student`类型。但是，由于`Student` *是* `Person`，因此将`Student`向上转型为`Person`是可以接受的。内存布局的顶部部分实际上是每个`Student`实例的`Person`。对于实际上是`Student`类型的实例，`Student`的额外数据成员将跟随`Person`子对象所需的所有内存。

注意，`vptr`条目紧随每个三个实例的`Person`对象（或子对象）的数据成员之后。`vptr`的位置与每个对象顶部的偏移量相同。这是因为所讨论的虚函数都是在层次结构的`Person`级别引入的。一些可能在`Student`类中被更合适地定义为`Student`的虚函数可能会被覆盖，但是每个引入的级别都是`Person`级别，因此`Person`对象（或子对象）下面的`vptr`将反映指向在`Person`级别引入的操作列表的指针。

顺便说一句，假设`Student`引入了全新的虚函数（而不仅仅是重新定义现有的虚函数），就像我们在前面的函数隐藏场景中看到的那样。然后，在`Student`子对象下方将有第二个`vptr`条目，其中包含这些额外的（新的虚）操作。

当每个对象被实例化时，首先将为每个实例调用适当的构造函数（按层次结构向上进行）。此外，编译器将为每个实例的`vptr`补丁分配指针，以设置为与对象类型对应的`v-table`条目。也就是说，当实例化`Person`时，其`vptr`将指向`Person`的`v-table`条目。当实例化`Student`时，其`vptr`将指向`Student`的`v-table`条目。

假设`Person`或`Student`的`v-table`条目包含一个指向该类型适当虚函数的函数指针数组。每种类型的`v-table`条目实际上嵌入了更多信息，例如该类型的实例大小等。为简化起见，我们将只查看自动执行每个类类型的动态绑定的`v-table`条目的部分。

请注意，`Person`的`v-table`条目是一个包含四个函数指针的数组。每个函数指针将指向`Person`的最合适版本的析构函数，`Print()`，`IsA()`和`Greeting()`。这些函数指针的排列顺序与这些虚函数由该类引入的顺序相对应。也就是说，`vptr[0]`将指向`Person`的析构函数，`vptr[1]`将指向`Person::Print()`，依此类推。

现在，让我们看一下`Student`的`v-table`条目。虚函数（作为函数指针）在数组中的排列顺序与`Person`类的顺序相同。这是因为基类引入了这些函数，并且指针数组中的排序是由该级别设置的。但请注意，指向的实际函数已被`Student`实例重写，大部分是由派生类`Student`重新定义的方法。也就是说，`Student`的析构函数被指定为（作为销毁的起点），然后是`Student::Print()`，然后是`Student::IsA()`，然后是`Person::Greeting()`。请注意，`vptr[3]`指向`Person::Greeting()`。这是因为`Student`没有在其类定义中重新定义这个函数；`Student`发现继承的`Person`定义是可以接受的。

将这个内存图与我们`main()`函数中的代码配对，注意在我们实例化一个`Person`和两个`Student`实例后，将每个实例存储在泛型化的`Person`指针数组中，我们通过包含多个操作的循环进行迭代。我们统一调用`people[i]->Print();`，然后是`people[i]->IsA();`，然后是`people[i]->Greeting();`，最后是`delete people[i];`（这会插入一个析构函数调用）。

因为这些函数都是虚函数，决定调用哪个函数的决定被推迟到运行时进行查找。这是通过访问每个实例的隐藏`vptr`成员来完成的，根据手头的操作索引到适当的`v-table`条目，然后解引用在该条目中找到的函数指针来调用适当的方法。编译器知道，例如`vptr[0]`将是析构函数，`vptr[1]`将是基类定义中引入的下一个虚函数，依此类推，因此可以轻松确定应该激活 v-table 中的哪个元素位置，这是多态操作的名称决定的。

想象一下，在`main()`中对`people[i]->Print();`的调用被替换为`*(people[i]->vptr[1])();`，这是解引用函数指针以调用手头的函数的语法。请注意，我们首先使用`people[i]->vptr[1]`来访问哪个函数，然后使用`*`来解引用函数指针。请注意语句末尾的括号`()`，这是传递参数给函数的地方。因为解引用函数指针的代码需要是统一的，任何这样的函数的参数也必须是统一的。这就是为什么在派生类中重写的任何虚函数都必须使用与基类指定的相同签名。当你深入了解时，这一切都是有道理的。

我们已经彻底研究了面向对象的多态思想以及在 C++中如何使用虚函数实现它。在继续前进到下一章之前，让我们简要回顾一下本章涵盖的内容。

# 总结

在本章中，我们通过理解 C++中虚函数如何直接支持面向对象的多态思想，进一步深入了解了面向对象编程。我们已经看到虚函数如何为继承层次结构中的操作提供特定方法的动态绑定。

我们已经看到，使用虚函数，基类指定的操作可以被派生类覆盖，提供更合适的实现。我们已经看到，可以使用运行时绑定选择每个对象的正确方法，无论对象是存储在其自己的类型还是在泛化类型中。

我们已经看到对象通常使用基类指针进行泛化，以及这如何允许对相关派生类类型进行统一处理。我们已经看到，无论实例是如何存储的（作为其自己的类型或作为使用指针的基类的类型），正确版本的虚函数始终会通过动态绑定应用。我们已经看到，在公共继承层次结构中，其中向上转型可能会经常进行，拥有虚析构函数是必不可少的。

我们还看到了动态绑定是如何工作的，通过检查编译器实现将 vptr 嵌入实例，以及这些指针引用与每个对象类型相关的 v 表条目（包含成员函数指针集）。

我们已经看到，虚函数允许我们利用操作的动态绑定到最合适的方法，使我们能够将 C++作为一个 OOP 语言来实现具有多态性的健壮设计，从而促进易于扩展的代码。

通过扩展我们对 OOP 知识的理解，利用虚函数，我们现在可以继续包括与继承和多态性相关的其他面向对象的概念和细节。继续到*第八章*，*掌握抽象类*，我们将学习如何应用抽象类的 OO 理想，以及围绕这一下一个面向对象概念的各种 OOP 考虑。让我们继续！

# 问题

1.  使用您的*第六章*，*使用单继承实现层次结构*，解决方案，扩展您的继承层次结构，以进一步专门化`Student`与`GraduateStudent`和`NonDegreeStudent`。

a. 为您的`GraduateStudent`类添加必要的数据成员。要考虑的数据成员可能是论文题目或研究生导师。包括适当的构造函数（默认，替代和复制），析构函数，访问成员函数和合适的公共接口。一定要将数据成员放在私有访问区域。对于`NonDegreeStudent`也是一样。

b. 根据需要为`Person`，`Student`，`GraduateStudent`和`NonDegreeStudent`添加多态操作。在`Person`级别引入虚函数`IsA()`和`Print()`。根据需要在派生类中重写`IsA()`和`Print()`。可能会在`Student`和`GraduateStudent`中重写`IsA()`，但选择仅在`Student()`类中重写`Print()`。一定要在每个类中包含虚析构函数。

c. 实例化`Student`，`GraduateStudent`，`NonDegreeStudent`和`Person`多次，并利用每个适当的`public`接口。一定要动态分配多个实例。

d. 创建一个指向`Person`的指针数组，并分配`Person`，`Student`，`GraduateStudent`和`NonDegreeStudent`的实例作为该数组的成员。一旦泛化，只调用在`Person`级别找到的多态操作（以及`Person`的其他公共方法）。一定要删除任何动态分配的实例。

e. 现在，创建一个指向`Student`的指针数组，并只分配`GraduateStudent`和`NonDegreeStudent`的实例作为该数组的成员。现在，调用在`Student`级别找到的操作，以应用于这些泛化实例。此外，利用在`Person`级别找到的操作-它们被继承并且对于泛化的`Student`实例也可用。一定要删除数组中指向的任何动态分配的实例。


# 第八章：掌握抽象类

本章将继续扩展我们对 C++面向对象编程的知识。我们将首先探讨一个强大的面向对象概念，**抽象类**，然后逐步理解这一概念如何通过*直接语言支持*在 C++中实现。

我们将使用纯虚函数实现抽象类，最终支持相关类层次结构中的细化。我们将了解抽象类如何增强和配合我们对多态性的理解。我们还将认识到本章介绍的抽象类的面向对象概念将支持强大且灵活的设计，使我们能够轻松创建可扩展的 C++代码。

在本章中，我们将涵盖以下主要主题：

+   理解抽象类的面向对象概念

+   使用纯虚函数实现抽象类

+   使用抽象类和纯虚函数创建接口

+   使用抽象类泛化派生类对象；向上转型和向下转型

通过本章结束时，您将理解抽象类的面向对象概念，以及如何通过纯虚函数在 C++中实现这一概念。您将学会仅包含纯虚函数的抽象类如何定义面向对象概念的接口。您将了解为什么抽象类和接口有助于强大的面向对象设计。

您将看到我们如何非常容易地使用一组抽象类型来泛化相关的专门对象。我们还将进一步探讨层次结构中的向上转型和向下转型，以了解何时允许以及何时合理使用此类类型转换。

通过理解 C++中抽象类的直接语言支持，使用纯虚函数，以及创建接口的有用性，您将拥有更多工具来创建相关类的可扩展层次结构。让我们通过了解这些概念在 C++中的实现来扩展我们对 C++作为面向对象编程语言的理解。

# 技术要求

完整程序示例的在线代码可在以下 GitHub 网址找到：[`github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter08`](https://github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter08)。每个完整程序示例都可以在 GitHub 存储库中的适当章节标题（子目录）下找到，文件名与所在章节编号相对应，后跟破折号，再跟所在章节中的示例编号。例如，本章的第一个完整程序可以在`Chapter08`子目录中的名为`Chp8-Ex1.cpp`的文件中找到。

本章的 CiA 视频可在以下网址观看：[`bit.ly/2Pa6XBT`](https://bit.ly/2Pa6XBT)。

# 理解抽象类的面向对象概念

在本节中，我们将介绍一个重要的面向对象概念，即抽象类。考虑到您对关键面向对象思想的知识基础不断增长，包括封装、信息隐藏、泛化、特化和多态性，您知道如何封装一个类。您还知道如何使用单继承构建继承层次结构（以及构建层次结构的各种原因，例如支持**是一个**关系或支持实现继承的较少使用的原因）。此外，您知道如何使用虚函数实现方法到操作的运行时绑定，从而实现多态性的概念。让我们通过探索**抽象类**来扩展我们不断增长的面向对象术语。

**抽象类**是一个旨在收集派生类中可能存在的共同点，以便在派生类上断言一个公共接口（即一组操作）的基类。抽象类不代表一个用于实例化的类。只有派生类类型的对象可以被实例化。

让我们首先看一下 C++语言特性，允许我们实现抽象类，即纯虚拟函数。

# 使用纯虚拟函数实现抽象类

通过在类定义中引入至少一个抽象方法（即纯虚拟函数原型）来指定抽象类。**抽象方法**的面向对象概念是指定一个仅具有其使用协议（即成员函数的*名称*和*签名*）的操作，但没有函数定义。抽象方法将是多态的，因为没有定义，它预计会被派生类重新定义。

函数参数后面的`=0`。此外，重要的是要理解关于纯虚拟函数的以下微妙之处：

+   通常不提供纯虚拟函数的定义。这相当于在基类级别指定操作（仅原型），并在派生类级别提供所有方法（成员函数定义）。

+   未为其基类引入的所有纯虚拟函数提供方法的派生类也被视为抽象类，因此不能被实例化。

+   原型中的`=0`只是向链接器指示，在创建可执行程序时，不需要链接（或解析）此函数的定义。

注意

通过在类定义中包含一个或多个纯虚拟函数原型来指定抽象类。通常不提供这些方法的可选定义。

纯虚拟函数通常不提供定义的原因是它们旨在为多态操作提供使用协议，以在派生类中实现。纯虚拟函数指定一个类为抽象；抽象类不能被实例化。因此，纯虚拟函数中提供的定义永远不会被选择为多态操作的适当方法，因为抽象类型的实例永远不会存在。也就是说，纯虚拟函数仍然可以提供一个定义，可以通过作用域解析运算符（`::`）和基类名称显式调用。也许，这种默认行为可能作为派生类实现中使用的辅助函数具有意义。

让我们首先简要概述指定抽象类所需的语法。请记住，*abstract*可能是一个用于指定抽象类的关键字。相反，仅仅通过引入一个或多个纯虚拟函数，我们已经指示该类是一个抽象类：

```cpp
class LifeForm    // Abstract class definition
{
private:
    int lifeExpectancy; // all LifeForms have a lifeExpectancy
public:
    LifeForm() { lifeExpectancy = 0; }
    LifeForm(int life) { lifeExpectancy = life; }
    LifeForm(const LifeForm &form) 
       { lifeExpectancy = form.lifeExpectancy; }
    virtual ~LifeForm() { }   // virtual destructor
    int GetLifeExpectancy() const { return lifeExpectancy; }
    virtual void Print() const = 0; // pure virtual functions 
    virtual const char *IsA() = 0;   
    virtual const char *Speak() = 0;
};
```

请注意，在抽象类定义中，我们引入了四个虚拟函数，其中三个是纯虚拟函数。虚拟析构函数没有要释放的内存，但被指定为`virtual`，以便它是多态的，并且可以应用正确的销毁顺序到存储为基类类型指针的派生类实例。

三个纯虚拟函数`Print()`、`IsA()`和`Speak()`在它们的原型中被指定为`=0`。这些操作没有定义（尽管可以选择性地提供）。纯虚拟函数可以有默认实现，但不能作为内联函数。派生类的责任是使用基类定义指定的接口（即签名）为这些操作提供方法。在这里，纯虚拟函数为多态操作提供了*接口*，这些操作将在派生类定义中定义。

注意

抽象类肯定会有派生类（因为我们不能实例化抽象类本身）。为了确保虚析构函数机制在最终层次结构中能够正常工作，请确保在抽象类定义中包含虚析构函数。这将确保所有派生类的析构函数都是`virtual`，并且可以被重写以提供对象销毁序列中的正确入口点。

现在，让我们更深入地了解从面向对象的角度来拥有接口意味着什么。

# 创建接口。

接口类是面向对象概念中的一个类，它是抽象类的进一步细化。抽象类可以包含通用属性和默认行为（通过包含数据成员和纯虚函数的默认定义，或者通过提供非虚拟成员函数），而接口类只包含抽象方法。在 C++中，一个只包含抽象方法的抽象类（即没有可选定义的纯虚函数）可以被视为接口类。

在考虑 C++中实现的接口类时，有几点需要记住：

+   抽象类不可实例化；它们通过继承提供了派生类必须提供的接口（即操作）。

+   虽然在抽象类中纯虚函数可能包含可选实现（即方法体），但如果类希望在纯面向对象的术语中被视为接口类，则不应提供此实现。

+   虽然抽象类可能有数据成员，但如果类希望被视为接口类，则不应该有数据成员。

+   在面向对象的术语中，抽象方法是没有方法的操作；它只是接口，并且在 C++中实现为纯虚函数。

+   作为提醒，请确保在接口类定义中包含虚析构函数原型；这将确保派生类的析构函数是虚拟的。析构函数定义应为空。

让我们考虑在面向对象编程实现技术中拥有接口类的各种动机。一些面向对象编程语言遵循非常严格的面向对象概念，只允许实现非常纯粹的面向对象设计。其他面向对象编程语言，如 C++，通过直接允许实现更激进的面向对象思想，提供了更多的灵活性。

例如，在纯面向对象的术语中，继承应该保留给 Is-A 关系。我们已经看到了 C++支持的实现继承，通过私有和受保护的基类。我们已经看到了一些可接受的实现继承的用法，即以另一个类的术语实现一个新类（通过使用受保护和公共基类来隐藏底层实现）。

另一个面向对象编程特性的例子是多重继承。我们将在接下来的章节中看到，C++允许一个类从多个基类派生。在某些情况下，我们确实在说派生类与许多基类可能存在 Is-A 关系，但并非总是如此。

一些面向对象编程语言不允许多重继承，而那些不允许的语言更多地依赖于接口类来混合（否则）多个基类的功能。在这些情况下，面向对象编程语言可以允许派生类实现多个接口类中指定的功能，而不实际使用多重继承。理想情况下，接口用于混合多个类的功能。这些类，不出所料，有时被称为**混入**类。在这些情况下，我们并不一定说派生类和基类之间存在 Is-A 关系。

在 C++中，当我们引入一个只有纯虚函数的抽象类时，我们可以认为创建了一个接口类。当一个新类混合了来自多个接口的功能时，我们可以在面向对象的术语中将其视为使用接口类来混合所需的行为接口。请注意，派生类必须用自己的实现重写每个纯虚函数；我们只混合所需的 API。

C++对面向对象概念中的接口的实现仅仅是一个只包含纯虚函数的抽象类。在这里，我们使用公共继承自抽象类，配合多态性来模拟面向对象概念中的接口类。请注意，其他语言（如 Java）直接在语言中实现了这个想法（但是这些语言不支持多重继承）。在 C++中，我们几乎可以做任何事情，但重要的是要理解如何以合理和有意义的方式实现面向对象理想（即使这些理想在直接语言支持中没有提供）。

让我们看一个例子来说明使用抽象类实现接口类：

```cpp
class Charitable    // interface class definition
{                   // implemented using an abstract class
public:
    virtual void Give(float) = 0; // interface for 'giving'
    virtual ~Charitable() { } // remember virtual destructor
};
class Person: public Charitable   // mix-in an 'interface'
{
    // Assume typical Person class definition w/ data members,
    // constructors, member functions exist.
public:
    virtual void Give(float amt) override
    {  // implement a means for giving here 
    }
    virtual ~Person();  // prototype
};               
class Student: public Person 
{   // Student Is-A Person which mixes-in Charitable interface
    // Assume typical Student class definition w/ data
    // members, constructors, member functions exist.
public:
    virtual void Give(float amt) override
    {  // Should a Student have little money to give,
       // perhaps they can donate their time equivalent to
       // the desired monetary amount they'd like to give
    }
    virtual ~Student();  // prototype
};
```

在上述的类定义中，我们首先注意到一个简单的接口类`Charitable`，使用受限的抽象类实现。我们不包括数据成员，一个纯虚函数来定义`virtual void Give(float) = 0;`接口，以及一个虚析构函数。

接下来，`Person`从`Charitable`派生，使用公共继承来实现`Charitable`接口。我们简单地重写`virtual void Give(float);`来为*给予*提供一个默认定义。然后我们从`Person`派生`Student`；请注意*学生是一个实现了 Charitable 接口的人*。在我们的`Student`类中，我们选择重新定义`virtual void Give(float);`来为`Student`实例提供更合适的`Give()`定义。也许`Student`实例财务有限，选择捐赠一个等同于预定货币金额的时间量。

在这里，我们在 C++中使用抽象类来模拟面向对象概念中的接口类。

让我们继续讨论关于抽象类的整体问题，通过检查派生类对象如何被抽象类类型收集。

# 将派生类对象泛化为抽象类型

我们在*第七章*中已经看到，*通过多态性利用动态绑定*，有时将相关的派生类实例分组存储在使用基类指针的集合中是合理的。这样做允许使用基类指定的多态操作对相关的派生类类型进行统一处理。我们也知道，当调用多态基类操作时，由于 C++中实现多态性的虚函数和内部虚表，将在运行时调用正确的派生类方法。

然而，你可能会思考，是否可能通过抽象类类型来收集一组相关的派生类类型？请记住，抽象类是不可实例化的，那么我们如何将一个派生类对象存储为一个不能被实例化的对象呢？解决方案是使用*指针*。虽然我们不能将派生类实例收集在一组抽象基类实例中（这些类型不能被实例化），但我们可以将派生类实例收集在抽象类类型的指针集合中。自从我们学习了多态性以来，我们一直在做这种类型的分组（使用基类指针）。

广义的专门对象组使用隐式向上转型。撤消这样的向上转型必须使用显式向下转型，并且程序员需要正确地确定先前泛化的派生类型。对错误的向下转型将导致运行时错误。

何时需要按基类类型收集派生类对象，包括抽象基类类型？答案是，当在应用程序中以更通用的方式处理相关的派生类类型时，即当基类类型中指定的操作涵盖了您想要利用的所有操作时。毫无疑问，您可能会发现同样多的情况，即保留派生类实例在其自己的类型中（以利用在派生类级别引入的专门操作）是合理的。现在您明白了可能发生的情况。

让我们继续通过检查一个全面的示例来展示抽象类的实际应用。

# 将所有部分放在一起

到目前为止，在本章中，我们已经了解了抽象类的微妙之处，包括纯虚函数，以及如何使用抽象类和纯虚函数创建接口类。始终重要的是看到我们的代码在各种组件及其各种细微差别中的运行情况。

让我们看一个更复杂的、完整的程序示例，以充分说明在 C++中使用纯虚函数实现抽象类。在这个例子中，我们不会进一步将抽象类指定为接口类，但我们将利用机会使用一组指向其抽象基类类型的指针来收集相关的派生类类型。这个例子将被分解成许多段落；完整的程序可以在以下 GitHub 位置找到：

[`github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter08/Chp8-Ex1.cpp`](https://github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter08/Chp8-Ex1.cpp)

```cpp
#include <iostream>
#include <iomanip>
#include <cstring>
using namespace std;
const int MAX = 5;
class LifeForm   // abstract class definition
{
private:
   int lifeExpectancy;
public:
   LifeForm() { lifeExpectancy = 0; }
   LifeForm(int life) { lifeExpectancy = life; }
   LifeForm(const LifeForm &form) 
       { lifeExpectancy = form.lifeExpectancy; }
   virtual ~LifeForm() { }     // virtual destructor
   int GetLifeExpectancy() const { return lifeExpectancy; }
   virtual void Print() const = 0;   // pure virtual functions 
   virtual const char *IsA() = 0;   
   virtual const char *Speak() = 0;
};
```

在上述的类定义中，我们注意到`LifeForm`是一个抽象类。它是一个抽象类，因为它包含至少一个纯虚函数定义。事实上，它包含了三个纯虚函数定义，即`Print()`、`IsA()`和`Speak()`。

现在，让我们用一个具体的派生类`Cat`来扩展`LifeForm`：

```cpp
class Cat: public LifeForm
{
private:
   int numberLivesLeft;
   char *name;
public:
   Cat() : LifeForm(15) { numberLivesLeft = 9; name = 0; }
   Cat(int lives) : LifeForm(15) { numberLivesLeft = lives; }
   Cat(const char *n);
   virtual ~Cat() { delete name; }   // virtual destructor
   const char *GetName() const { return name; }
   int GetNumberLivesLeft() const { return numberLivesLeft; }
   virtual void Print() const override; // redef pure virt fns
   virtual const char *IsA() override { return "Cat"; }
   virtual const char *Speak() override { return "Meow!"; }
};
Cat::Cat(const char *n) : LifeForm(15)
{
   name = new char [strlen(n) + 1];
   strcpy(name, n);
   numberLivesLeft = 9;
}
void Cat::Print() const
{
   cout << "\t" << name << " has " << GetNumberLivesLeft();
   cout << " lives left" << endl;
}
```

在前面的代码段中，我们看到了`Cat`的类定义。请注意，`Cat`已经重新定义了`LifeForm`的纯虚函数`Print()`、`IsA()`和`Speak()`，并为`Cat`类中的每个方法提供了定义。有了这些函数的现有方法，`Cat`的任何派生类都可以选择重新定义这些方法，使用更合适的版本（但它们不再有义务这样做）。

请注意，如果`Cat`未能重新定义`LifeForm`的任何一个纯虚函数，那么`Cat`也将被视为抽象类，因此无法实例化。

作为提醒，虚函数`IsA()`和`Speak()`虽然是内联写的以缩短代码，但编译器永远不会将虚函数内联，因为它们的正确方法必须在运行时确定。

请注意，在`Cat`构造函数中，成员初始化列表用于选择接受整数参数的`LifeForm`构造函数（即`:LifeForm(15)`）。将值`15`传递给`LifeForm`构造函数，以初始化`LifeForm`中定义的`lifeExpectancy`为`15`。

现在，让我们继续前进到`Person`的类定义，以及它的内联函数：

```cpp
class Person: public LifeForm
{
private: 
   // data members
   char *firstName;
   char *lastName;
   char middleInitial;
   char *title;  // Mr., Ms., Mrs., Miss, Dr., etc.
protected:
   void ModifyTitle(const char *);  
public:
   Person();   // default constructor
   Person(const char *, const char *, char, const char *);  
   Person(const Person &);  // copy constructor
   virtual ~Person();  // destructor
   const char *GetFirstName() const { return firstName; }  
   const char *GetLastName() const { return lastName; }    
   const char *GetTitle() const { return title; } 
   char GetMiddleInitial() const { return middleInitial; }
   virtual void Print() const override; // redef pure virt fns
   virtual const char *IsA() override;   
   virtual const char *Speak() override;
};
```

请注意，`Person`现在使用公共继承扩展了`LifeForm`。在之前的章节中，`Person`是继承层次结构顶部的基类。`Person`重新定义了来自`LifeForm`的纯虚函数，即`Print()`、`IsA()`和`Speak()`。因此，`Person`现在是一个具体类，可以被实例化。

现在，让我们回顾一下`Person`的成员函数定义：

```cpp
Person::Person(): LifeForm(80)
{
   firstName = lastName = 0;  // NULL pointer
   middleInitial = '\0';
   title = 0;
}
Person::Person(const char *fn, const char *ln, char mi, 
               const char *t): LifeForm(80)
{
   firstName = new char [strlen(fn) + 1];
   strcpy(firstName, fn);
   lastName = new char [strlen(ln) + 1];
   strcpy(lastName, ln);
   middleInitial = mi;
   title = new char [strlen(t) + 1];
   strcpy(title, t);
}
Person::Person(const Person &pers): LifeForm(pers)
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
void Person::Print() const
{
   cout << "\t" << title << " " << firstName << " ";
   cout << middleInitial << ". " << lastName << endl;
}
const char *Person::IsA() {  return "Person";  }
const char *Person::Speak() {  return "Hello!";  }   
```

在`Person`成员函数中，请注意我们为`Print()`、`IsA()`和`Speak()`实现了功能。另外，请注意在两个`Person`构造函数中，我们在它们的成员初始化列表中选择了`:LifeForm(80)`来调用`LifeForm(int)`构造函数。这个调用将在给定`Person`实例的`LifeForm`子对象中将私有继承的数据成员`LifeExpectancy`设置为`80`。

接下来，让我们回顾`Student`类的定义，以及它的内联函数定义：

```cpp
class Student: public Person
{
private: 
   // data members
   float gpa;
   char *currentCourse;
   const char *studentId;  
public:
   Student();  // default constructor
   Student(const char *, const char *, char, const char *,
           float, const char *, const char *); 
   Student(const Student &);  // copy constructor
   virtual ~Student();  // virtual destructor
   void EarnPhD();  
   float GetGpa() const { return gpa; }
   const char *GetCurrentCourse() const 
       { return currentCourse; }
   const char *GetStudentId() const { return studentId; }
   void SetCurrentCourse(const char *);
   virtual void Print() const override; // redefine not all 
   virtual const char *IsA() override;  // virtual functions
};
inline void Student::SetCurrentCourse(const char *c)
{
   delete currentCourse;   // delete existing course
   currentCourse = new char [strlen(c) + 1];
   strcpy(currentCourse, c); 
}
```

前面提到的`Student`类定义看起来很像我们以前见过的。`Student`使用公共继承扩展了`Person`，因为`Student` *是一个* `Person`。

接下来，我们将回顾非内联的`Student`类成员函数：

```cpp
Student::Student(): studentId (0)  // default constructor
{
   gpa = 0.0;
   currentCourse = 0;
}
// Alternate constructor member function definition
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
// Copy constructor definition
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
void Student::EarnPhD()  {   ModifyTitle("Dr.");  }
void Student::Print() const
{
   cout << "\t" << GetTitle() << " " << GetFirstName() << " ";
   cout << GetMiddleInitial() << ". " << GetLastName();
   cout << " with id: " << studentId << " has a gpa of: ";
   cout << setprecision(2) <<  " " << gpa << " enrolled in: ";
   cout << currentCourse << endl;
}
const char *Student::IsA() {  return "Student";  }
```

在前面列出的代码部分中，我们看到了`Student`的非内联成员函数定义。到目前为止，完整的类定义对我们来说已经非常熟悉了。

因此，让我们来审查一下`main()`函数：

```cpp
int main()
{
   // Notice that we are creating an array of POINTERS to
   // LifeForms. Since LifeForm cannot be instantiated, 
   // we could not create an array of LifeForm (s).
   LifeForm *entity[MAX];
   entity[0] = new Person("Joy", "Lin", 'M', "Ms.");
   entity[1] = new Student("Renee", "Alexander", 'Z', "Dr.",
                            3.95, "C++", "21-MIT"); 
   entity[2] = new Student("Gabby", "Doone", 'A', "Ms.", 
                            3.95, "C++", "18-GWU"); 
   entity[3] = new Cat("Katje"); 
   entity[4] = new Person("Giselle", "LeBrun", 'R', "Miss");
   for (int i = 0; i < MAX; i++)
   {
      cout << entity[i]->Speak();
      cout << " I am a " << entity[i]->IsA() << endl;
      entity[i]->Print();
      cout << "Has a life expectancy of: ";
      cout << entity[i]->GetLifeExpectancy();
      cout << "\n";
   } 
   for (int i = 0; i < MAX; i++)
      delete entity[i];
   return 0;
}
```

在`main()`中，我们声明了一个指向`LifeForm`的指针数组。回想一下，`LifeForm`是一个抽象类。我们无法创建`LifeForm`对象的数组，因为那将要求我们能够实例化一个`LifeForm`；我们不能这样做——`LifeForm`是一个抽象类。

然而，我们可以创建一个指向抽象类型的指针集合，这使我们能够收集相关类型——在这个集合中的`Person`、`Student`和`Cat`实例。当然，我们可以对以这种泛化方式存储的实例应用的唯一操作是在抽象基类`LifeForm`中找到的那些操作。

接下来，我们分配了各种`Person`、`Student`和`Cat`实例，将每个实例存储在类型为`LifeForm`的泛化指针集合的元素中。当以这种方式存储任何这些派生类实例时，将执行隐式向上转型到抽象基类类型（但实例不会以任何方式被改变——我们只是指向整个内存布局组成部分的最基类子对象）。

现在，我们通过循环来对这个泛化集合中的所有实例应用在抽象类`LifeForm`中找到的操作，比如`Speak()`、`Print()`和`IsA()`。这些操作恰好是多态的，允许通过动态绑定使用每个实例的最适当实现。我们还在每个实例上调用`GetLifeExpectancy()`，这是在`LifeForm`级别找到的非虚拟函数。这个函数只是返回了相关`LifeForm`的寿命预期。

最后，我们通过循环使用泛化的`LifeForm`指针再次删除动态分配的`Person`、`Student`和`Cat`实例。我们知道`delete()`将会调用析构函数，并且因为析构函数是虚拟的，适当的析构顺序将会开始。

在这个例子中，`LifeForm`抽象类的实用性在于它的使用允许我们将所有`LifeForm`对象的共同特征和行为概括在一个基类中（比如`lifeExpectancy`和`GetLifeExpectancy()`）。这些共同行为还扩展到一组具有所需接口的纯虚函数，所有`LifeForm`对象都应该有，即`Print()`、`IsA()`和`Speak()`。

重要提醒

抽象类是收集派生类的共同特征，但本身并不代表应该被实例化的有形实体或对象。为了将一个类指定为抽象类，它必须包含至少一个纯虚函数。

查看上述程序的输出，我们可以看到各种相关的派生类类型的对象被实例化并统一处理。在这里，我们通过它们的抽象基类类型收集了这些对象，并且在各种派生类中用有意义的定义覆盖了基类中的纯虚函数。

以下是完整程序示例的输出：

```cpp
Hello! I am a Person
        Ms. Joy M. Lin
        Has a life expectancy of: 80
Hello! I am a Student
        Dr. Renee Z. Alexander with id: 21-MIT has a gpa of:  4 enrolled in: C++
        Has a life expectancy of: 80
Hello! I am a Student
        Ms. Gabby A. Doone with id: 18-GWU has a gpa of: 4 enrolled in: C++
        Has a life expectancy of: 80
Meow! I am a Cat
        Katje has 9 lives left
        Has a life expectancy of: 15
Hello! I am a Person
        Miss Giselle R. LeBrun
        Has a life expectancy of: 80
```

我们已经彻底研究了抽象类的面向对象概念以及在 C++中如何使用纯虚函数实现，以及这些概念如何扩展到创建面向对象接口。在继续前进到下一章之前，让我们简要回顾一下本章涵盖的语言特性和面向对象概念。

# 总结

在本章中，我们继续了解面向对象编程，首先是通过理解 C++中纯虚函数如何直接支持抽象类的面向对象概念。我们探讨了没有数据成员且不包含非虚函数的抽象类如何支持接口类的面向对象理想。我们谈到了其他面向对象编程语言如何利用接口类，以及 C++如何选择支持这种范式，通过使用这种受限制的抽象类。我们将相关的派生类类型向上转换为抽象基类类型的指针存储，这是一种典型且非常有用的编程技术。

我们已经看到抽象类如何通过提供一个类来指定派生类共享的共同属性和行为，以及最重要的是为相关类提供多态行为的接口，因为抽象类本身是不可实例化的。

通过在 C++中添加抽象类和可能的面向对象接口类的概念，我们能够实现促进易于扩展的代码设计。

我们现在准备继续*第九章*，*探索多重继承*，通过学习如何以及何时适当地利用多重继承的概念，同时理解权衡和潜在的设计替代方案，来增强我们的面向对象编程技能。让我们继续前进吧！

# 问题

1.  使用以下指南创建形状的层次结构：

a. 创建一个名为`Shape`的抽象基类，它定义了计算`Shape`面积的操作。不要包括`Area()`操作的方法。提示：使用纯虚函数。

b. 使用公共继承从`Shape`派生`Rectangle`、`Circle`和`Triangle`类。可选择从`Rectangle`派生`Square`类。在每个派生类中重新定义`Shape`引入的`Area()`操作。确保在每个派生类中提供支持该操作的方法，以便稍后实例化每种`Shape`类型。

c. 根据需要添加数据成员和其他成员函数来完成新引入的类定义。记住，只有共同的属性和操作应该在`Shape`中指定 - 所有其他属性和操作都属于它们各自的派生类。不要忘记在每个类定义中实现复制构造函数和访问函数。

d. 创建一个抽象类类型`Shape`的指针数组。将该数组中的元素指向`Rectangle`、`Square`、`Circle`和`Triangle`类型的实例。由于现在你正在将派生类对象视为通用的`Shape`对象，所以循环遍历指针数组，并为每个调用`Area()`函数。确保`delete()`任何动态分配的内存。

e. 在概念上，你的抽象`Shape`类也是一个接口类吗？为什么或为什么不是？


# 第九章：探索多重继承

本章将继续扩展我们对 C++中面向对象编程的知识。我们将从检查一个有争议的面向对象概念，**多重继承**（**MI**）开始，了解为什么它有争议，如何可以合理地用于支持面向对象设计，以及何时替代设计可能更合适。

多重继承可以在 C++中通过*直接语言支持*来实现。这样做，我们将面临几个面向对象设计问题。我们将被要求对继承层次结构进行批判性评估，问自己是否使用最佳设计来表示潜在的对象关系集。多重继承可以是一个强大的面向对象编程工具；明智地使用它是至关重要的。我们将学习何时使用多重继承来合理地扩展我们的层次结构。

在本章中，我们将涵盖以下主要主题：

+   理解多重继承的机制

+   检查多重继承的合理用途

+   创建菱形层次结构并探讨由其使用引起的问题

+   使用虚基类解决菱形层次结构的重复

+   应用判别器来评估菱形层次结构和设计中多重继承的价值，以及考虑设计替代方案

在本章结束时，您将了解多重继承的面向对象概念，以及如何在 C++中实现这个想法。您将不仅了解多重继承的简单机制，还将了解其使用的原因（混入，Is-A，或有争议的 Has-A）。

您将看到为什么多重继承在面向对象编程中是有争议的。拥有多个基类可能会导致形状奇怪的层次结构，比如菱形层次结构；这些类型的层次结构带来潜在的实现问题。我们将看到 C++如何整合一种语言特性（虚基类）来解决这些难题，但解决方案并不总是理想的。

一旦我们了解了多重继承带来的复杂性，我们将使用面向对象设计度量标准，如判别器，来评估使用多重继承的设计是否是表示一组对象关系的最佳解决方案。我们将研究替代设计，然后您将更好地理解多重继承不仅是什么，还有何时最好地利用它。让我们通过多重继承继续扩展我们对 C++作为“*你可以做任何事情*”面向对象编程语言的理解。

# 技术要求

完整程序示例的在线代码可以在以下 GitHub URL 找到：[`github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter09`](https://github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter09)。每个完整程序示例都可以在 GitHub 存储库中的适当章节标题（子目录）下找到，文件名与所在章节编号相对应，后跟破折号，再跟着所在章节中的示例编号。例如，本章的第一个完整程序可以在名为`Chp9-Ex1.cpp`的文件中的子目录`Chapter09`中找到。

本章的 CiA 视频可以在以下链接观看：[`bit.ly/3f4qjDo`](https://bit.ly/3f4qjDo)。

# 理解多重继承的机制

在 C++中，一个类可以有多个直接基类。这被称为**多重继承**，在面向对象设计和面向对象编程中是一个非常有争议的话题。让我们从简单的机制开始；然后我们将在本章的进展过程中讨论多重继承的设计问题和编程逻辑。

使用多重继承，派生类在其类定义中使用基类列表指定其每个直接祖先或基类是什么。

与单一继承类似，构造函数和析构函数在整个继承结构中被调用，因为派生类类型的对象被实例化和销毁。回顾并扩展多重继承的构造和析构的微妙之处，我们想起了以下的逻辑：

+   构造函数的调用顺序从派生类开始，但立即将控制权传递给基类构造函数，依此类推，直到达到继承结构的顶部。一旦调用顺序传递控制到继承结构的顶部，执行顺序就开始了。所有最高级别的基类构造函数首先被执行，以此类推，直到我们到达派生类构造函数，在构造链中最后执行。

+   派生类的析构函数首先被调用和执行，然后是所有直接基类的析构函数，依此类推，随着我们向上继承层次结构的进展。

派生类构造函数中的成员初始化列表可以用来指定应该调用每个直接基类的构造函数。如果没有这个规定，那么将使用该基类的默认构造函数。

让我们来看一个典型的多重继承示例，以实现面向对象设计中多重继承的典型应用，并理解 C++中基本的多重继承语法。这个例子将被分成许多部分；完整的程序可以在以下 GitHub 位置找到：

[`github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter09/Chp9-Ex1.cpp`](https://github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter09/Chp9-Ex1.cpp)

```cpp
#include <iostream>
#include <cstring>
using namespace std;
class Person
{
private: 
    char *firstName;
    char *lastName;
    char middleInitial;
    char *title;  // Mr., Ms., Mrs., Miss, Dr., etc.
    Person(const Person &);  // prohibit copies 
protected:
    void ModifyTitle(const char *);  
public:
    Person();   // default constructor
    Person(const char *, const char *, char, const char *);  
    virtual ~Person();  // destructor
    const char *GetFirstName() const { return firstName; }  
    const char *GetLastName() const { return lastName; }    
    const char *GetTitle() const { return title; } 
    char GetMiddleInitial() const { return middleInitial; }
};
```

在前面的代码段中，我们有一个`Person`的预期类定义，其中包含我们习惯于定义的类元素。

接下来，让我们看看这个类的相关成员函数：

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

在之前的代码段中，`Person`的成员函数定义如预期的那样。然而，看到`Person`类的定义是有用的，因为这个类将作为一个构建块，并且它的部分将直接在接下来的代码段中被访问。

现在，让我们定义一个新的类`BillableEntity`：

```cpp
class BillableEntity
{
private:
    float invoiceAmt;
    BillableEntity(const BillableEntity &); // prohibit copies
public:
    BillableEntity() { invoiceAmt = 0.0; }
    BillableEntity(float amt) { invoiceAmt = amt; } 
    virtual ~BillableEntity() { }
    void Pay(float amt) { invoiceAmt -= amt; }
    float GetBalance() const { return invoiceAmt; }
    void Balance();
};
void BillableEntity::Balance()
{
    if (invoiceAmt)
       cout << "Owed amount: $ " << invoiceAmt << endl;
    else
       cout << "Credit: $ " << 0.0 - invoiceAmt << endl;
}
```

在之前的`BillableEntity`类中，我们定义了一个包含简单功能的类来封装一个计费结构。也就是说，我们有一个发票金额和`Pay()`、`GetBalance()`等方法。请注意，复制构造函数是私有的；这将禁止复制，考虑到这个类的性质，这似乎是合适的。

接下来，让我们将前面提到的两个基类`Person`和`BillableEntity`组合起来，作为`Student`类的基类：

```cpp
class Student: public Person, public BillableEntity
{
private: 
    float gpa;
    char *currentCourse;
    const char *studentId;  
    Student(const Student &);  // prohibit copies 
public:
    Student();  // default constructor
    Student(const char *, const char *, char, const char *,
           float, const char *, const char *, float); 
    virtual ~Student(); 
    void Print() const;
    void EarnPhD();  
    float GetGpa() const { return gpa; }
    const char *GetCurrentCourse() const
        { return currentCourse; }
    const char *GetStudentId() const { return studentId; }
    void SetCurrentCourse(const char *);
};
inline void Student::SetCurrentCourse(const char *c)
{
   delete currentCourse;   // delete existing course
   currentCourse = new char [strlen(c) + 1];
   strcpy(currentCourse, c); 
}
```

在`Student`的前面的类定义中，在`Student`的基类列表中指定了两个公共基类`Person`和`BillableEntity`。这两个基类只是在`Student`的基类列表中用逗号分隔。

让我们进一步看看在`Student`类的其余部分中必须做出哪些调整，通过检查其成员函数：

```cpp
Student::Student(): studentId (0) // call default base  
{                                  // class constructors
   gpa = 0.0;
   currentCourse = 0;
}
// The member initialization list specifies which versions
// of each base class constructor should be utilized.
Student::Student(const char *fn, const char *ln, char mi, 
       const char *t, float avg, const char *course, 
       const char *id, float amt):
       Person(fn, ln, mi, t), BillableEntity(amt)                   
{
   gpa = avg;
   currentCourse = new char [strlen(course) + 1];
   strcpy(currentCourse, course);
   char *temp = new char [strlen(id) + 1];
   strcpy (temp, id); 
   studentId = temp;
}
Student::~Student()
{
   delete currentCourse;
   delete (char *) studentId;
}
void Student::Print() const
{
    cout << GetTitle() << " " << GetFirstName() << " ";
    cout << GetMiddleInitial() << ". " << GetLastName();
    cout << " with id: " << studentId << " has a gpa of: ";
    cout << " " << gpa << " and course: " << currentCourse;
    cout << " with balance: $" << GetBalance() << endl;
}
void Student::EarnPhD() 
{  
    ModifyTitle("Dr."); 
}
```

让我们考虑前面的代码段。在`Student`的默认构造函数中，由于在成员初始化列表中缺少基类构造函数的规定，将调用`Person`和`BillableEntity`基类的默认构造函数。

然而，注意在另一个`Student`构造函数中，我们只是在成员初始化列表中用逗号分隔了我们的两个基类构造函数选择，即`Person(const char *, const char *, char, const char *)`和`BillableEntity(float)`，然后将各种参数从`Student`构造函数传递给基类构造函数。

最后，让我们来看看我们的`main()`函数：

```cpp
int main()
{
    float tuition1 = 1000.00, tuition2 = 2000.00;
    Student s1("Gabby", "Doone", 'A', "Ms.", 3.9, "C++",
               "178GWU", tuition1); 
    Student s2("Zack", "Moon", 'R', "Dr.", 3.9, "C++",
               "272MIT", tuition2); 
    // public members of Person, BillableEntity, Student are
    // accessible from any scope, including main()
    s1.Print();
    s2.Print();
    cout << s1.GetFirstName() << " paid $500.00" << endl;
    s1.Pay(500.00);
    cout << s2.GetFirstName() << " paid $750.00" << endl;
    s2.Pay(750.00);
    cout << s1.GetFirstName() << ": ";
    s1.Balance();
    cout << s2.GetFirstName() << ": ";
    s2.Balance();
    return 0;
}
```

在我们之前的代码的 `main()` 函数中，我们实例化了几个 `Student` 实例。请注意，`Student` 实例可以利用 `Student`、`Person` 或 `BillableEntity` 的公共接口中的任何方法。

让我们来看看上述程序的输出：

```cpp
Ms. Gabby A. Doone with id: 178GWU has a gpa of:  3.9 and course: C++ with balance: $1000
Dr. Zack R. Moon with id: 272MIT has a gpa of:  3.9 and course: C++ with balance: $2000
Gabby paid $500.00
Zack paid $750.00
Gabby: Owed amount: $ 500
Zack: Owed amount: $ 1250
```

我们现在已经看到了通常实现的面向对象设计中多重继承的语言机制。现在，让我们继续通过查看在面向对象设计中使用多重继承的典型原因，其中一些原因比其他原因更被广泛接受。

# 审视 MI 的合理用法

多重继承是在创建面向对象设计时出现的一个有争议的概念。许多面向对象设计避免多重继承；其他设计则严格使用它。一些面向对象编程语言，比如 Java，不明确提供直接支持多重继承的语言支持。相反，它们提供接口，就像我们在 C++ 中通过创建只包含纯虚函数的抽象类（限制为只包含纯虚函数）来建模的那样，在*第八章*中，*掌握抽象类*。

当然，在 C++ 中，从两个接口类继承仍然是多重继承的一种用法。虽然 C++ 不在语言中包括接口类，但这个概念可以通过更严格地使用多重继承来模拟。例如，我们可以通过编程方式简化抽象类，只包括纯虚函数（没有数据成员，也没有带有定义的成员函数），以模仿面向对象设计中接口类的概念。

典型的多重继承困境构成了为什么多重继承在面向对象编程中具有争议的基础。经典的多重继承困境将在本章详细介绍，并可以通过将多重继承限制为仅使用接口类，或通过重新设计来避免。这就是为什么一些面向对象编程语言只支持接口类而不支持无限制的多重继承。在 C++ 中，你可以仔细考虑每个面向对象设计，并选择何时使用多重继承，何时使用一种受限制的多重继承形式（接口类），或何时使用重新设计来消除多重继承。

C++ 是一个“你可以做任何事情”的编程语言。因此，C++ 允许无限制或保留地进行多重继承。作为一个面向对象的程序员，我们将更仔细地看待接受多重继承的典型原因。随着我们在本章的深入，我们将评估使用多重继承时出现的问题，以及 C++ 如何通过额外的语言特性解决这些问题。这些多重继承的问题将使我们能够应用度量标准，更合理地了解何时应该使用多重继承，何时应该进行重新设计。

让我们开始追求合理使用 MI 的过程，首先考虑 Is-A 和混合关系，然后再来审视使用 MI 实现 Has-A 关系的有争议的用法。

## 支持 Is-A 和混合关系

就像我们在单一继承中学到的那样，Is-A 关系最常用于描述两个继承类之间的关系。例如，`Student` *Is-A* `Person`。相同的理想继续在多重继承中，Is-A 关系是指定继承的主要动机。在纯粹的面向对象设计和编程中，继承应该只用于支持 Is-A 关系。

尽管如此，正如我们在查看接口类时所学到的（这是在 C++ 中使用抽象类模拟的概念，限制为只包含纯虚函数），混合关系通常适用于当我们从一个接口继承时。请记住，混合关系是当我们使用继承来混合另一个类的功能时，仅仅是因为这个功能对于派生类来说是有用或有意义的。基类不一定是抽象或接口类，但在理想的面向对象设计中，它应该是这样的。

混合基类代表一个不适用 Is-A 关系的类。混合存在于 MI 中更多，至少作为支持（许多）基类之一的必要性的原因。由于 C++直接支持多重继承，MI 可用于支持实现混合（而像 Java 这样的语言可能只使用接口类）。在实践中，MI 经常用于继承自一个类以支持 Is-A 关系，并且还继承自另一个类以支持混合关系。在我们的最后一个例子中，我们看到`Student` *Is-A* `Person`，并且`Student`选择*混合* `BillableEntity`的功能。

在 C++中合理使用 MI 的包括支持 Is-A 和混合关系；然而，我们的讨论将不完整，如果不考虑下一个不寻常的 MI 使用——实现 Has-A 关系。

## 支持 Has-A 关系

较少见，也更有争议的是，MI 可以用于实现 Has-A 关系。也就是说，模拟包含或整体与部分的关系。在*第十章*中，*实现关联、聚合和组合*，我们将看到 Has-A 关系的更广泛接受的实现；然而，MI 提供了一个非常简单的实现。在这里，部分作为基类。整体继承自部分，自动包含部分在其内存布局中，还自动继承部分的成员和功能。

例如，`Student` *Is-A* `Person`，`Student` *Has-A(n)* `Id`；第二个基类（`Id`）的使用是为了包含。`Id`将作为一个基类，`Student`将从`Id`派生，以考虑`Id`提供的一切。`Id`的公共接口对`Student`是立即可用的。实际上，任何从`Id`继承的类在使用其`Id`部分时都将继承一个统一的接口。这种简单性是继承有时被用来模拟包含的驱动原因。

然而，使用继承来实现 Has-A 关系可能会导致不必要的 MI 使用，从而使继承层次结构复杂化。不必要使用 MI 是使用继承来模拟 Has-A 关系非常有争议的主要原因，而且在纯 OO 设计中相当受到反对。尽管如此，我们还是提到它，因为你会看到一些 C++应用程序使用 MI 来实现 Has-A。

让我们继续探讨其他有争议的 MI 设计，即菱形层次结构。

# 创建菱形层次结构

在使用多重继承时，有时会诱人地利用兄弟（或表亲）类作为新派生类的基类。当这种情况发生时，层次结构不再是树形的，而是一个包含*菱形*的图形。

每当在这种情况下实例化派生类类型的对象时，派生类的实例中将存在两个公共基类的副本。这种重复显然浪费空间。还会通过调用重复的构造函数和析构函数以及维护两个平行的子对象的副本（很可能是不必要的）来浪费额外的时间。当尝试访问来自这个公共基类的成员时，也会产生歧义。

让我们看一个详细说明这个问题的例子，从`LifeForm`、`Horse`和`Person`的缩写类定义开始。虽然只显示了完整程序示例的部分，但整个程序可以在我们的 GitHub 上找到：

[`github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter09/Chp9-Ex2.cpp`](https://github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter09/Chp9-Ex2.cpp)

```cpp
class Lifeform
{   // abbreviated class definition
private:
    int lifeExpectancy;
public:
    LifeForm(int life) {lifeExpectancy = life; }
    int GetLifeExpectancy() const { return lifeExpectancy; }
    // additional constructors, destructor, etc …
    virtual void Print() const = 0; // pure virtual functions
    virtual const char *IsA() = 0;
    virtual const char *Speak() = 0;
};
class Horse: public LifeForm
{   // abbreviated class definition
private:
    char *name;
public:
    Horse(): LifeForm(35) { name = 0; }
    // additional constructors, destructor, etc …
    virtual void Print() const override 
        { cout << name << endl; }
    virtual const char *IsA() override { return "Horse"; }
    virtual const char *Speak() override { return "Neigh!"; }
};
class Person: public LifeForm
{   // abbreviated class definition
private: 
    char *firstName;
    char *lastName;
    // additional data members …
public:
    Person(): LifeForm(80) { firstName = lastName = 0; }
    // additional constructors, destructor, etc …
    const char *GetFirstName() const { return firstName; }
    virtual void Print() const override
        { cout << firstName << " " << lastName << endl; }
    virtual const char *IsA() override { return "Person"; }
    virtual const char *Speak() override { return "Hello!"; }
};
```

代码片段显示了`LifeForm`，`Person`和`Horse`的骨架类定义。每个类都显示了一个默认构造函数，仅仅是为了演示如何为每个类设置`lifeExpectancy`。在`Person`和`Horse`的默认构造函数中，成员初始化列表用于将值`35`或`80`传递给`LifeForm`构造函数以设置这个值。

尽管前面的类定义是缩写的（即故意不完整）以节省空间，让我们假设每个类都有适当的额外构造函数定义，适当的析构函数和其他必要的成员函数。

我们注意到`LifeForm`是一个抽象类，因为它提供了纯虚函数`Print()`，`IsA()`和`Speak()`。`Horse`和`Person`都是具体类，并且可以实例化，因为它们用虚函数重写了这些纯虚函数。这些虚函数是内联显示的，只是为了使代码紧凑以便查看。

接下来，让我们看一个新的派生类，它将在我们的层次结构中引入图形或菱形：

```cpp
class Centaur: public Person, public Horse
{   // abbreviated class definition
public:
    // constructors, destructor, etc …
    virtual void Print() const override
       { cout << GetFirstName() << endl; }
    virtual const char *IsA() override { return "Centaur"; }
    virtual const char *Speak() override
       { return "Neigh! and Hello!"; }
};
```

在前面的片段中，我们使用多重继承定义了一个新的类`Centaur`。乍一看，我们确实是要断言`Centaur`与`Person`之间的 Is-A 关系，以及`Centaur`与`Horse`之间的 Is-A 关系。然而，我们很快会挑战我们的断言，以测试它是否更像是一种组合而不是真正的 Is-A 关系。

我们将假设所有必要的构造函数、析构函数和成员函数都存在，使`Centaur`成为一个定义良好的类。

现在，让我们继续看一下我们可能会利用的潜在`main()`函数：

```cpp
int main()
{
    Centaur beast("Wild", "Man");
    cout << beast.Speak() << " I'm a " << beast.IsA() << endl;
    // Ambiguous method call – which LifeForm sub-object?
    // cout << beast.GetLifeExpectancy();  
    cout << "It is unclear how many years I will live: ";
    cout << beast.Person::GetLifeExpectancy() << " or ";
    cout << beast.Horse::GetLifeExpectancy() << endl; 
    return 0;
}
```

在`main()`中，我们实例化了一个`Centaur`；我们将实例命名为`beast`。我们轻松地在`beast`上调用了两个多态操作，即`Speak()`和`IsA()`。然后我们尝试调用公共的继承`GetLifeExpectancy()`，它在`LifeForm`中定义。它的实现包含在`Lifeform`中，因此`Person`，`Horse`和`Centaur`不需要提供定义（也不应该这样做——它不是一个虚函数，意味着要重新定义）。

不幸的是，通过`Centaur`实例调用`GetLifeExpectancy()`是模棱两可的。这是因为`beast`实例中有两个`LifeForm`子对象。记住，`Centaur`是从`Horse`派生的，`Horse`是从`LifeForm`派生的，为所有前述的基类数据成员（`Horse`和`LifeForm`）提供了内存布局。`Centaur`也是从`Person`派生的，`Person`是从`LifeForm`派生的，它也为`Centaur`提供了`Person`和`LifeForm`的内存布局。`LifeForm`部分是重复的。

继承的数据成员`lifeExpectancy`有两个副本。在`Centaur`实例中有两个`LifeForm`的子对象。因此，当我们尝试通过`Centaur`实例调用`GetLifeExpectancy()`时，方法调用是模棱两可的。我们试图初始化哪个`lifeExpectancy`？在调用`GetLifeExpectancy()`时，哪个`LifeForm`子对象将作为`this`指针？这是不清楚的，所以编译器不会为我们选择。

为了消除对`GetLifeExpectancy()`函数调用的歧义，我们必须使用作用域解析运算符。我们在`::`运算符之前加上我们希望从中获取`LifeForm`子对象的中间基类。请注意，我们调用，例如`beast.Horse::GetLifeExpectancy()`来选择`lifeExpectancy`，从`Horse`子对象的路径中包括`LifeForm`。这很尴尬，因为`Horse`和`Person`都不包括这个模棱两可的成员；`lifeExpectancy`是在`LifeForm`中找到的。

让我们考虑上述程序的输出：

```cpp
Neigh! and Hello! I'm a Centaur.
It is unclear how many years I will live: 80 or 35.
```

我们可以看到，设计一个包含菱形形状的层次结构有缺点。这些难题包括需要以尴尬的方式解决的编程歧义，重复子对象的内存重复，以及构造和销毁这些重复子对象所需的时间。

幸运的是，C++有一种语言特性来减轻这些菱形层次结构的困难。毕竟，C++是一种允许我们做任何事情的语言。知道何时以及是否应该利用这些特性是另一个问题。让我们首先看一下 C++语言解决菱形层次结构及其固有问题的解决方案，通过查看虚基类。

# 利用虚基类来消除重复

我们刚刚看到了 MI 实现中出现的问题，当一个菱形形状包含在 OO 设计中时会迅速出现内存重复的子对象，访问该子对象的歧义（即使通过继承的成员函数），以及构造和销毁的重复。因此，纯 OO 设计不会在层次结构中包括图形（即没有菱形形状）。然而，我们知道 C++是一种强大的语言，一切皆有可能。因此，C++将为我们提供解决这些问题的方法。

`virtual`被放置在访问标签和兄弟或堂兄类的基类名称之间，这些类可能*稍后*被用作同一个派生类的基类。需要注意的是，知道两个兄弟类可能稍后被合并为新派生类的共同基类可能是困难的。重要的是要注意，没有指定虚基类的兄弟类将要求它们自己的副本（否则共享的）基类。

在实现中应该谨慎使用虚基类，因为这会对具有这样一个祖先类的实例施加限制和开销。需要注意的限制包括：

+   具有虚基类的实例可能会使用比其非虚拟对应物更多的内存。

+   当虚基类在祖先层次结构中时，禁止从基类类型的对象向派生类类型进行转换。

+   最派生类的成员初始化列表必须用于指定应该用于初始化的共享对象类型的构造函数。如果忽略了这个规定，将使用默认构造函数来初始化这个子对象。

现在让我们看一个使用虚基类的完整程序示例。通常情况下，完整程序可以在我们的 GitHub 上找到，链接如下：

[`github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter09/Chp9-Ex3.cpp`](https://github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter09/Chp9-Ex3.cpp)

```cpp
#include <iostream>
#include <cstring>
using namespace std;
class LifeForm
{
private:
    int lifeExpectancy;
public:
    LifeForm() { lifeExpectancy = 0; }
    LifeForm(int life) { lifeExpectancy = life; }
    LifeForm(const LifeForm &form) 
       { lifeExpectancy = form.lifeExpectancy; }
    virtual ~LifeForm() { }
    int GetLifeExpectancy() const { return lifeExpectancy; }
    virtual void Print() const = 0; 
    virtual const char *IsA() = 0;   
    virtual const char *Speak() = 0;
};
```

在前面的代码段中，我们看到了`LifeForm`的完整类定义。请注意，具有函数体的成员函数在类定义中被内联。当然，编译器实际上不会为构造函数或析构函数进行内联替换；知道这一点，将方法写成内联以使类紧凑以便审查是方便的。

接下来，让我们看一下`Horse`的类定义：

```cpp
class Horse: public virtual LifeForm
{
private:
    char *name;
public:
    Horse() : LifeForm(35) { name = 0; }
    Horse(const char *n);
    Horse(const Horse &); 
    virtual ~Horse() { delete name; }
    const char *GetName() const { return name; }
    virtual void Print() const override 
        { cout << name << endl; }
    virtual const char *IsA() override { return "Horse"; }
    virtual const char *Speak() override { return "Neigh!"; }
};
Horse::Horse(const char *n): LifeForm(35)
{
   name = new char [strlen(n) + 1];
   strcpy(name, n);
}
Horse::Horse(const Horse &h): LifeForm (h)
{
   name = new char [strlen(h.name) + 1];
   strcpy(name, h.name); 
}
```

在前面的代码段中，我们有`Horse`的完整类定义。请记住，尽管某些方法被写成内联以节省空间，但编译器实际上永远不会内联构造函数或析构函数。虚函数也不能被内联，因为它的整个目的是在运行时确定适当的方法。

在这里，`LifeForm`是`Horse`的虚基类。这意味着如果`Horse`有一个同级（或堂兄）也使用虚基类从`LifeForm`继承的兄弟，那些兄弟将*共享*它们的`LifeForm`副本。虚基类将减少存储和额外的构造函数和析构函数调用，并消除歧义。

请注意`Horse`构造函数，在其成员初始化列表中指定了`LifeForm(35)`的构造函数规范。如果`LifeForm`实际上是一个共享的虚基类，那么这个基类初始化将被忽略，尽管这些构造函数规范对于`Horse`的实例或者`Horse`的后代的实例是有效的，其中菱形层次结构不适用。在`Horse`与一个兄弟类真正作为虚基类组合的层次结构中，`LifeForm(35)`规范将被忽略，而是将调用默认的`LifeForm`构造函数或者在层次结构中的较低（不寻常的）级别选择另一个构造函数。

接下来，让我们通过查看其他类定义来看更多关于这个程序的内容，从`Person`开始：

```cpp
class Person: public virtual LifeForm
{
private: 
    // data members
    char *firstName;
    char *lastName;
    char middleInitial;
    char *title;  // Mr., Ms., Mrs., Miss, Dr., etc.
protected:
    void ModifyTitle(const char *);  
public:
    Person();   // default constructor
    Person(const char *, const char *, char, const char *);  
    Person(const Person &);  // copy constructor
    virtual ~Person();  // destructor
    const char *GetFirstName() const { return firstName; }  
    const char *GetLastName() const { return lastName; }    
    const char *GetTitle() const { return title; } 
    char GetMiddleInitial() const { return middleInitial; }
    virtual void Print() const override;
    virtual const char *IsA() override;   
    virtual const char *Speak() override;
};
```

在之前的代码片段中，我们看到`Person`有一个公共虚基类`LifeForm`。如果`Person`和`Person`的兄弟类通过多重继承组合成一个新的派生类，那些指定`LifeForm`为虚基类的兄弟类将同意共享一个`LifeForm`的子对象。

继续前进，让我们回顾一下`Person`的成员函数：

```cpp
Person::Person(): LifeForm(80)
{
    firstName = lastName = 0;  // NULL pointer
    middleInitial = '\0';
    title = 0;
}
Person::Person(const char *fn, const char *ln, char mi, 
               const char *t): LifeForm(80)
{
    firstName = new char [strlen(fn) + 1];
    strcpy(firstName, fn);
    lastName = new char [strlen(ln) + 1];
    strcpy(lastName, ln);
    middleInitial = mi;
    title = new char [strlen(t) + 1];
    strcpy(title, t);
}
Person::Person(const Person &pers): LifeForm(pers)
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
void Person::Print() const
{
    cout << title << " " << firstName << " ";
    cout << middleInitial << ". " << lastName << endl;
}
const char *Person::IsA() {  return "Person"; }
const char *Person::Speak() {  return "Hello!"; }
```

在上述`Person`的方法中，我们看到一些让我们惊讶的细节；这些方法大部分都是预期的。然而，请注意，如果`Person`在一个菱形层次结构中与`LifeForm`子对象变为共享而不是重复，那么`Person`构造函数中成员初始化列表中的`LifeForm(80)`规范将被忽略。

接下来，让我们看看多重继承是如何发挥作用的，以`Centaur`类的定义为例：

```cpp
class Centaur: public Person, public Horse
{
private:
    // no additional data members required 
public:
    Centaur(): LifeForm(1000) { }
    Centaur(const char *, const char *, char = ' ', 
            const char * = "Mythological Creature"); 
    Centaur(const Centaur &c): 
            Person(c), Horse(c),LifeForm(1000) { }
    virtual void Print() const override;
    virtual const char *IsA() override;   
    virtual const char *Speak() override;
};
// Constructors for Centaur need to specify how the shared
// base class LifeForm will be initialized
Centaur::Centaur(const char *fn, const char *ln, char mi, 
                 const char *title): 
                 Person(fn, ln, mi, title), Horse(fn), 
                 LifeForm(1000)
{
   // All initialization has been taken care of in init. list
}
void Centaur::Print() const
{
    cout << "My name is " << GetFirstName();
    cout << ".  I am a " << GetTitle() << endl;
}
const char *Centaur::IsA() { return "Centaur"; }
const char *Centaur::Speak() 
{
    return "Neigh! and Hello! I'm a master of two languages.";
} 
```

在上述的`Centaur`类定义中，我们可以看到`Centaur`有`Horse`和`Person`的公共基类。我们暗示`Centaur` *是一个* `Horse`和`Centaur` *是一个* `Person`。

然而，请注意，在`Centaur`类定义的基类列表中没有使用关键字`virtual`。然而，`Centaur`是引入菱形形状的层次结构的级别。这意味着我们在设计阶段必须提前计划，知道在`Horse`和`Person`类定义的基类列表中利用`virtual`关键字。这是一个合适的设计会议至关重要的例子，而不是仅仅跳入实现。

同样非常不寻常的是，注意`Centaur`的替代构造函数中的`Person(fn, ln, mi, title), Horse(fn), LifeForm(1000)`的基类列表。在这里，我们不仅指定了我们的直接基类`Person`和`Horse`的首选构造函数，还指定了*它们*的共同基类`LifeForm`的首选构造函数。这是非常不寻常的。如果`LifeForm`不是`Horse`和`Person`的虚基类，`Centaur`将无法指定如何构造共享的`LifeForm`片段（即选择除了其直接基类之外的构造函数）。虚基类的使用使得`Person`和`Horse`类对于其他应用的可重用性降低。

让我们来看看我们的`main()`函数包含什么：

```cpp
int main()
{
   Centaur beast("Wild", "Man");
   cout << beast.Speak() << endl;
   cout << " I'm a " << beast.IsA() << ". ";
   beast.Print();
   cout << "I will live: ";
   cout << beast.GetLifeExpectancy();  // no longer ambiguous!
   cout << " years" << endl; 
   return 0;
}
```

与我们非虚基类示例中的`main()`函数类似，我们可以看到`Centaur`同样被实例化，并且可以轻松调用`Speak()`、`IsA()`和`Print()`等虚函数。然而，当我们通过`beast`实例调用`GetLifeExpectancy()`时，调用不再是模棱两可的。只有一个`LifeForm`的子对象，其`LifeExpectancy`已经初始化为`1000`。

以下是完整程序示例的输出：

```cpp
Neigh!!! and Hello! I'm a master of two languages.
I am a Centaur. My name is Wild. I am a Mythological Creature.
I will live: 1000 years.
```

虚基类解决了一个困难的 MI 难题。但我们也看到，为此所需的代码对于未来的扩展和重用来说不够灵活。因此，虚基类应该谨慎和节制地使用，只有当设计真正支持菱形层次结构时才使用。考虑到这一点，让我们考虑鉴别器的面向对象概念，并考虑何时备用设计可能更合适。

# 考虑鉴别器和备用设计

**鉴别器**是一个面向对象的概念，它有助于概述为什么给定类是从其基类派生的原因。**鉴别器**倾向于表征为给定基类存在的专门化类型的分组。

例如，在前面提到的具有菱形层次结构的程序示例中，我们有以下鉴别器（用括号表示），概述了我们从给定基类专门化新类的目的：

![图 9.1-显示带有鉴别器的多重继承菱形设计](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/dmst-oop-cpp/img/Figure_9.1_B15702.jpg)

图 9.1-显示带有鉴别器的多重继承菱形设计

每当诱惑导致创建菱形层次结构时，检查鉴别器可以帮助我们决定设计是否合理，或者也许备用设计会更好。以下是一些要考虑的良好设计指标：

+   如果正在重新组合的兄弟类的鉴别器相同，则最好重新设计菱形层次结构。

+   当兄弟类没有唯一的鉴别器时，它们引入的属性和行为将由于具有相似的鉴别器而产生重复。考虑将鉴别器作为一个类来容纳这些共同点。

+   如果兄弟类的鉴别器是唯一的，那么菱形层次结构可能是合理的。在这种情况下，虚基类将会很有帮助，并且应该在层次结构的适当位置添加。

在前面的例子中，详细说明`Horse`为什么专门化`LifeForm`的鉴别器是`Equine`。也就是说，我们正在用马的特征和行为（蹄，奔跑，嘶鸣等）专门化`LifeForm`。如果我们从`LifeForm`派生类，如`Donkey`或`Zebra`，这些类的鉴别器也将是`Equine`。考虑到前面提到的例子，当专门化`LifeForm`时，`Person`类将具有`Humanoid`鉴别器。如果我们从`LifeForm`派生类，如`Martian`或`Romulan`，这些类也将具有`Humanoid`作为鉴别器。

将`Horse`和`Person`作为`Centaur`的基类组合在一起，将两个具有不同鉴别器的基类`Equine`和`Humanoid`组合在一起。因此，每个基类都考虑了完全不同类型的特征和行为。虽然备用设计可能是可能的，但这种设计是可以接受的（除了面向对象设计纯粹主义者），并且可以在 C++中使用虚基类来消除否则会复制的`LifeForm`部分。将两个共享共同基类并使用不同鉴别器专门化基类的类组合在一起是 C++中 MI 和虚基类是合理的一个例子。

然而，将两个类，比如`Horse`和`Donkey`（都是从`LifeForm`派生的），放在一个派生类，比如`Mule`中，也会创建一个菱形层次结构。检查`Horse`和`Donkey`的鉴别器会发现它们都有一个`Equine`的鉴别器。在这种情况下，使用菱形设计将这两个类放在一起并不是最佳的设计选择。还有其他的设计选择是可能的，也更可取。在这种情况下，一个更可取的解决方案是将鉴别器`Equine`作为自己的类，然后从`Equine`派生`Horse`，`Donkey`和`Mule`。这将避免多重继承和菱形层次结构。让我们来看看这两种设计选项：

![图 9.2 - 重新设计的菱形多重继承，没有多重继承](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/dmst-oop-cpp/img/Figure_9.2_B15702.jpg)

图 9.2 - 重新设计的菱形多重继承，没有多重继承

提醒

在菱形层次结构中，如果*组合*类的鉴别器相同，可以有更好的设计（通过使鉴别器成为自己的类）。然而，如果鉴别器不同，考虑保持菱形多重继承层次结构，并使用虚基类来避免共同基类子对象的重复。

我们现在已经彻底研究了鉴别器的面向对象概念，并看到了鉴别器如何帮助评估设计的合理性。在许多情况下，使用菱形层次结构的设计可以重新设计，不仅消除菱形形状，还可以完全消除多重继承。在继续前进到下一章之前，让我们简要回顾一下本章涵盖的多重继承问题和面向对象概念。

# 总结

在本章中，我们继续探索了一个有争议的面向对象编程主题，即多重继承，以加深对面向对象编程的理解。首先，在本章中，我们了解了多重继承的简单机制。同样重要的是，我们回顾了构建继承层次结构的原因以及使用多重继承的可能原因（即指定 Is-A、mix-in 和 Has-A 关系）。我们被提醒使用继承来指定 Is-A 关系支持纯粹的面向对象设计。我们还看到使用多重继承来实现 mix-in 关系。我们还看了有争议的使用多重继承来快速实现 Has-A 关系；我们将在*第十章*，*实现关联、聚合和组合*中看到 Has-A 的首选实现。

我们已经看到，在我们的面向对象设计工具包中具有多重继承可能会导致菱形层次结构。我们已经看到了菱形层次结构引起的不可避免的问题，比如内存中的重复，构造/析构中的重复，以及访问复制的子对象时的歧义。我们也知道 C++提供了一种语言支持的机制来解决这些问题，使用虚基类。我们知道虚基类解决了一个繁琐的问题，但它们本身并不是完美的解决方案。

为了批评菱形层次结构，我们已经研究了鉴别器的面向对象概念，以帮助我们权衡使用菱形多重继承的面向对象设计的合理性。这也使我们了解到备选设计可以应用于一组对象；有时重新设计是一种更优雅的方法，解决方案将更容易、更长期地使用。

C++是一种“你可以做任何事情”的面向对象编程语言，多重继承是一个有争议的面向对象概念。了解何时可能需要某些多重继承设计，并理解语言特性来帮助解决这些多重继承问题将使您成为一个更好的程序员。知道何时需要重新设计也是至关重要的。

我们现在准备继续[*第十章*]（B15702_10_Final_NM_ePub.xhtml#_idTextAnchor386），*实现关联、聚合和组合*，通过学习如何用编程技术表示关联、聚合和组合，进一步提高我们的面向对象编程技能。这些即将出现的概念将*不*直接得到语言支持，但这些概念对我们的面向对象编程技能至关重要。让我们继续前进！

# 问题

1.  在本章中使用虚基类的菱形继承示例中输入（或使用在线代码）。按原样运行它。

a. 对于`Centaur`的实例，有多少个`LifeForm`子对象存在？

b. `LifeForm`构造函数（和析构函数）被调用了多少次？提示：你可能想在每个构造函数和析构函数中使用`cout`放置跟踪语句。

c. 如果在`Centaur`构造函数的成员初始化列表中省略了`LifeForm`的构造函数选择，哪个`LifeForm`构造函数会被调用？

1.  现在，从`Person`和`Horse`的基类列表中删除关键字`virtual`（也就是说，`LifeForm`将不再是`Person`和`Horse`的虚基类。`LifeForm`将只是`Person`和`Horse`的典型基类）。同时，从`Centaur`构造函数的成员初始化列表中删除`LifeForm`构造函数的选择。现在，实例化`Centaur`。

a. 对于`Centaur`的实例，有多少个`LifeForm`子对象存在？

b. 现在，`LifeForm`构造函数（和析构函数）被调用了多少次？


# 第十章：实现关联、聚合和组合

本章将继续推进我们对 C++面向对象编程的了解。我们将通过探索关联、聚合和组合的面向对象概念来增进我们对对象关系的理解。这些 OO 概念在 C++中没有直接的语言支持；相反，我们将学习多种编程技术来实现这些想法。我们还将了解对于各种概念，哪些实现技术是首选的，以及各种实践的优势和缺陷。

关联、聚合和组合在面向对象设计中经常出现。了解如何实现这些重要的对象关系是至关重要的。

在本章中，我们将涵盖以下主要主题：

+   理解聚合和组合的 OO 概念，以及各种实现

+   理解关联的 OO 概念及其实现，包括反向链接维护的重要性和引用计数的实用性

通过本章的学习，您将了解关联、聚合和组合的 OO 概念，以及如何在 C++中实现这些关系。您还将了解许多必要的维护方法，如引用计数和反向链接维护，以保持这些关系的最新状态。尽管这些概念相对简单，但您将看到为了保持这些类型的对象关系的准确性，需要大量的簿记工作。

通过探索这些核心对象关系，让我们扩展对 C++作为面向对象编程语言的理解。

# 技术要求

完整程序示例的在线代码可在以下 GitHub 链接找到：[`github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter10`](https://github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter10)。每个完整程序示例都可以在 GitHub 存储库中找到，位于相应章节标题（子目录）下的文件中，文件名与所在章节编号相对应，后跟破折号，再跟随所在章节中的示例编号。例如，本章的第一个完整程序可以在名为`Chp10-Ex1.cpp`的文件中的子目录`Chapter10`中找到，位于上述 GitHub 目录下。

本章的 CiA 视频可在以下链接观看：[`bit.ly/3sag0RY`](https://bit.ly/3sag0RY)。

# 理解聚合和组合

面向对象的聚合概念在许多面向对象设计中出现。它与继承一样频繁，用于指定对象关系。**聚合**用于指定具有-一个、整体-部分以及在某些情况下的包含关系。一个类可以包含其他对象的聚合。聚合可以分为两类——*组合*以及一种不太严格和*泛化*的聚合形式。

**泛化聚合**和**组合**都意味着具有-一个或整体-部分关系。然而，两者在两个相关对象之间的存在要求上有所不同。对于泛化聚合，对象可以独立存在；但对于组合，对象不能没有彼此存在。

让我们来看看每种聚合的变体，从组合开始。

## 定义和实现组合

**组合**是聚合的最专业形式，通常是大多数 OO 设计师和程序员在考虑聚合时所想到的。组合意味着包含，并且通常与整体-部分关系同义——即整体由一个或多个部分组成。整体*包含*部分。具有-一个关系也适用于组合。

外部对象，或*整体*，可以由*部分*组成。通过组合，部分不存在于整体之外。实现通常是一个嵌入对象 - 也就是说，一个包含对象类型的数据成员。在极少数情况下，外部对象将包含对包含对象类型的指针或引用；然而，当发生这种情况时，外部对象将负责创建和销毁内部对象。包含的对象没有其外层没有目的。同样，外层也不是*理想*的完整，没有内部的，包含的部分。

让我们看一个通常实现的组合示例。该示例将说明包含 - `Student` *有一个* `Id`。更重要的是，我们将暗示`Id`是`Student`的一个必要部分，并且没有`Student`就不会存在。`Id`对象本身没有任何目的。如果它们不是给予它们目的的主要对象的一部分，`Id`对象根本不需要存在。同样，您可能会认为`Student`没有`Id`是不完整的，尽管这有点主观！我们将使用嵌入对象在*整体*中实现*部分*。

组合示例将被分成许多部分。虽然只显示了示例的部分，完整的程序可以在以下 GitHub 位置找到：

[`github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter10/Chp10-Ex1.cpp`](https://github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter10/Chp10-Ex1.cpp)

```cpp
#include <iostream>
#include <iomanip>
#include <cstring>
using namespace std;
class Id  // the contained 'part'
{
private:
    char *idNumber;
public:
    Id() { idNumber = 0; }
    Id(const char *); 
    Id(const Id &);  
    ~Id() { delete idNumber; }
    const char *GetId() const { return idNumber; }
};
Id::Id(const char *id)
{
    idNumber = new char [strlen(id) + 1];
    strcpy(idNumber, id);
} 
Id::Id(const Id &id)
{
   idNumber = new char [strlen(id.idNumber) + 1];
   strcpy(idNumber, id.idNumber);
}
```

在前面的代码片段中，我们已经定义了一个`Id`类。`Id`将是一个可以被其他需要完全功能的`Id`的类包含的类。`Id`将成为可能选择包含它的*整体*对象的*部分*。

让我们继续构建一组最终将包含这个`Id`的类。我们将从一个我们熟悉的类`Person`开始：

```cpp
class Person
{
private:
    // data members
    char *firstName;
    char *lastName;
    char middleInitial;
    char *title;  // Mr., Ms., Mrs., Miss, Dr., etc.
protected:
    void ModifyTitle(const char *);
public:
    Person();   // default constructor
    Person(const char *, const char *, char, const char *);
    Person(const Person &);  // copy constructor
    virtual ~Person();  // virtual destructor
    const char *GetFirstName() const { return firstName; }
    const char *GetLastName() const { return lastName; }
    const char *GetTitle() const { return title; }
    char GetMiddleInitial() const { return middleInitial; }
    // virtual functions
    virtual void Print() const;   
    virtual void IsA();
    virtual void Greeting(const char *);
};
//  Assume the member functions for Person exist here
//  (they are the same as in previous chapters)
```

在先前的代码片段中，我们已经定义了`Person`类，就像我们习惯描述的那样。为了缩写这个示例，让我们假设伴随的成员函数存在于前述的类定义中。您可以在之前提供的 GitHub 链接中引用这些成员函数的在线代码。

现在，让我们定义我们的`Student`类。虽然它将包含我们习惯看到的元素，`Student`还将包含一个`Id`，作为一个嵌入对象：

```cpp
class Student: public Person  // 'whole' object
{
private:
    // data members
    float gpa;
    char *currentCourse;
    static int numStudents;  
    Id studentId;  // is composed of a 'part'
public:
    // member function prototypes
    Student();  // default constructor
    Student(const char *, const char *, char, const char *,
            float, const char *, const char *);
    Student(const Student &);  // copy constructor
    virtual ~Student();  // destructor
    void EarnPhD() { ModifyTitle("Dr."); } // various inline
    float GetGpa() const { return gpa; }         // functions
    const char *GetCurrentCourse() const
        { return currentCourse; }
    void SetCurrentCourse(const char *); // prototype only
    virtual void Print() const override;
    virtual void IsA() override { cout << "Student" << endl; }
    static int GetNumberStudents() { return numStudents; }
    // Access function for embedded Id object
    const char *GetStudentId() const;   // prototype only
};
int Student::numStudents = 0;  // static data member
inline void Student::SetCurrentCourse(const char *c)
{
    delete currentCourse;   // delete existing course
    currentCourse = new char [strlen(c) + 1];
    strcpy(currentCourse, c);
}
```

在前面的`Student`类中，我们经常注意到`Student`是从`Person`派生的。正如我们已经知道的那样，这意味着`Student`实例将包括`Person`的内存布局，作为`Person`子对象。

但是，请注意`Student`类定义中的数据成员`Id studentId;`。在这里，`studentId`是`Id`类型。它不是指针，也不是对`Id`的引用。数据成员`studentId`是一个嵌入对象。这意味着当实例化`Student`类时，不仅将包括从继承类中继承的内存，还将包括任何嵌入对象的内存。我们需要提供一种初始化嵌入对象`studentId`的方法。

让我们继续`Student`成员函数，以了解如何初始化，操作和访问嵌入对象：

```cpp
// constructor definitions
Student::Student(): studentId ("None") 
{
    gpa = 0.0;
    currentCourse = 0;
    numStudents++;
}
Student::Student(const char *fn, const char *ln, char mi,
                 const char *t, float avg, const char *course,
                 const char *id): Person(fn, ln, mi, t),
                 studentId(id)
{
    gpa = avg;
    currentCourse = new char [strlen(course) + 1];
    strcpy(currentCourse, course);
    numStudents++;
}
Student::Student(const Student &ps): Person(ps),
                 studentId(ps.studentId)
{
    gpa = ps.gpa;
    currentCourse = new char [strlen(ps.currentCourse) + 1];
    strcpy(currentCourse, ps.currentCourse);
    numStudents++;
}
Student::~Student()   // destructor definition
{
    delete currentCourse;
    numStudents--;
    // the embedded object studentId will also be destructed
}
void Student::Print() const
{
    cout << GetTitle() << " " << GetFirstName() << " ";
    cout << GetMiddleInitial() << ". " << GetLastName();
    cout << " with id: " << studentId.GetId() << " GPA: ";
    cout << setprecision(3) <<  " " << gpa;
    cout << " Course: " << currentCourse << endl;
}    
const char *GetStudentId() const 
{   
    return studentId.GetId();   
} 
```

在`Student`的先前列出的成员函数中，让我们从我们的构造函数开始。请注意，在默认构造函数中，我们利用成员初始化列表（`:`）来指定`studentId("None")`。因为`studentId`是一个成员对象，我们有机会选择（通过成员初始化列表）应该用于其初始化的构造函数。在这里，我们仅仅选择具有`Id(const char *)`签名的构造函数。

类似地，在`Student`的替代构造函数中，我们使用成员初始化列表来指定`studentId(id)`，这也将选择`Id(const char *)`构造函数，将参数`id`传递给此构造函数。

`Student`的复制构造函数还指定了如何使用成员初始化列表中的`studentId(ps.studentId)`来初始化`studentId`成员对象。在这里，我们只是调用了`Id`的复制构造函数。

在我们的`Student`析构函数中，我们不需要释放`studentId`。因为这个数据成员是一个嵌入对象，当外部对象的内存消失时，它的内存也会消失。当然，因为`studentId`本身也是一个对象，它的析构函数会在释放内存之前首先被调用。在幕后，编译器会（隐秘地）在`Student`析构函数的最后一行代码中补充一个对`studentId`的`Id`析构函数的调用。

最后，在前面的代码段中，让我们注意一下`studentId.GetId()`在`Student::Print()`和`Student::GetStudentId()`中的调用。在这里，嵌入对象`studentId`调用它自己的公共函数`Id::GetId()`来检索它在`Student`类作用域内的私有数据成员。因为`studentId`在`Student`中是私有的，所以这个嵌入对象只能在`Student`的作用域内被访问（也就是`Student`的成员函数）。然而，`Student::GetStudentId()`的添加为`Student`实例提供了一个公共的包装器，使得其他作用域中的`Student`实例可以检索这些信息。

最后，让我们来看一下我们的`main()`函数：

```cpp
int main()
{
    Student s1("Cyrus", "Bond", 'I', "Mr.", 3.65, "C++",
               "6996CU");
    Student s2("Anne", "Brennan", 'M', "Ms.", 3.95, "C++",
               "909EU");
    cout << s1.GetFirstName() << " " << s1.GetLastName();
    cout << " has id #: " << s1.GetStudentId() << endl;
    cout << s2.GetFirstName() << " " << s2.GetLastName();
    cout << " has id #: " << s2.GetStudentId() << endl;
    return 0;
}
```

在上述的`main()`函数中，我们实例化了两个`Student`实例，`s1`和`s2`。当为每个`Student`创建内存（在这种情况下，是在堆栈上）时，任何继承类的内存也将被包含为子对象。此外，任何嵌入对象的内存，比如`Id`，也将被布置为`Student`的子对象。包含对象或*部分*的内存将与外部对象或*整体*的分配一起分配。

接下来，让我们注意一下对包含的部分，即嵌入的`Id`对象的访问。我们从调用`s1.GetStudentId()`开始；`s1`访问了一个`Student`成员函数`GetStudentId()`。这个学生成员函数将利用`studentId`的成员对象来调用`Id::GetId()`，从而访问`Id`类型的这个内部对象。`Student::GetStudentId()`成员函数可以通过简单地返回`Id::GetId()`在嵌入对象上返回的值来实现这种期望的公共访问。

让我们来看上述程序的输出：

```cpp
Cyrus Bond has id #: 6996CU
Anne Brennan has id #: 909EU 
```

这个例子详细介绍了组合及其典型实现，即嵌入对象。现在让我们来看一个使用较少的、替代的实现方式——继承。

### 考虑组合的另一种实现方式

值得理解的是，组合也可以用继承来实现；然而，这是极具争议的。记住，继承通常用于实现*是一个*关系，而不是*有一个*关系。我们在*第九章*中简要描述了使用继承来实现*有一个*关系，即*探索多重继承*。

简而言之，你只需从*部分*继承，而不是将部分作为数据成员嵌入。这样做时，你就不再需要为*部分*提供*包装器*函数，就像我们在前面的程序中看到的那样，`Student::GetStudentId()`方法调用`studentId.GetId()`来提供对其嵌入部分的访问。在嵌入对象的例子中，包装器函数是必要的，因为部分（`Id`）在整体（`Student`）中是私有的。程序员无法在`Student`的作用域之外访问`Student`的私有`studentId`数据成员。当然，`Student`的成员函数（如`GetStudentId()`）可以访问它们自己类的私有数据成员，并通过这样做来实现`Student::GetStudentId()`包装器函数，以提供这种（安全的）访问。

如果使用了继承，Id::GetId()的公共接口将会被简单地继承为 Student 的公共接口，无需通过嵌入对象显式地进行访问。

尽管在某些方面继承*部分*很简单，但它大大增加了多重继承的复杂性。我们知道多重继承可能会带来许多潜在的复杂性。此外，使用继承，*整体*只能包含一个*部分*的实例，而不是多个*部分*的实例。

此外，使用继承实现整体-部分关系可能会在将实现与 OO 设计进行比较时产生混淆。请记住，继承通常意味着 Is-A 而不是 Has-A。因此，最典型和受欢迎的聚合实现是通过嵌入对象。

接下来，让我们继续看一下更一般形式的聚合。

## 定义和实现泛化聚合

我们已经看过 OO 设计中最常用的聚合形式，即组合。特别是，通过组合，我们已经看到部分没有理由在没有整体的情况下存在。尽管如此，还存在一种更一般的（但不太常见）聚合形式，并且有时会在 OO 设计中进行指定。我们现在将考虑这种不太常见的聚合形式。

在**泛化聚合**中，*部分*可以存在而不需要*整体*。部分将被单独创建，然后在以后的某个时间点附加到整体上。当*整体*消失时，*部分*可能会留下来以供与另一个外部或*整体*对象一起使用。

在泛化聚合中，Has-A 关系当然适用，整体-部分的指定也适用。不同之处在于*整体*对象不会创建也不会销毁*部分*子对象。考虑一个简单的例子，汽车*Has-A(n)*发动机。汽车对象还*Has-A*一组 4 个轮胎对象。发动机或轮胎对象可以单独制造，然后传递给汽车的构造函数，以提供这些部分给整体。然而，如果发动机被销毁，可以轻松地替换为新的发动机（使用成员函数），而无需销毁整个汽车然后重新构建。

泛化聚合等同于 Has-A 关系，但我们认为这种关系比组合更灵活，个体部分的持久性更强。我们将这种关系视为聚合，只是因为我们希望赋予对象 Has-A 的含义。在“汽车”、“发动机”、“轮胎”的例子中，Has-A 关系很强；发动机和轮胎是必要的部分，需要组成整个汽车。

在这里，实现通常是*整体*包含指向*部分*（们）的指针。重要的是要注意，部分将被传递到外部对象的构造函数（或其他成员函数）中以建立关系。关键的标志是整体不会创建（也不会销毁）部分。部分也永远不会销毁整体。

顺便说一句，泛化聚合的个体部分的持久性（和基本实现）将类似于我们下一个主题 - 关联。让我们继续前进到我们的下一节，以了解泛化聚合和关联之间的相似之处以及 OO 概念上的差异（有时是微妙的）。

# 理解关联

**关联**模拟了存在于否则无关的类类型之间的关系。关联可以提供对象相互作用以实现这些关系的方式。关联不用于 Has-A 关系；然而，在某些情况下，我们描述的是*真正的*Has-A 关系，或者我们只是因为在语言上听起来合适而使用 Has-A 短语。

关联的多重性存在：一对一，一对多，多对一，或多对多。例如，一个`学生`可能与一个`大学`相关联，而那个`大学`可能与许多`学生`实例相关联；这是一对多的关联。

相关的对象具有独立的存在。也就是说，两个或更多的对象可以在应用程序的某个部分被实例化并独立存在。在应用程序的某个时刻，一个对象可能希望断言与另一个对象的依赖或关系。在应用程序的后续部分，相关的对象可能分道扬镳，继续各自独立的路径。

例如，考虑`课程`和`教师`之间的关系。一个`课程`与一个`教师`相关联。一个`课程`需要一个`教师`；一个`教师`对`课程`是必不可少的。一个`教师`可能与许多`课程`相关联。然而，每个部分都是独立存在的 - 一个不会创造也不会摧毁另一个。教师也可以独立存在而没有课程；也许一个教师正在花时间写书，或者正在休假，或者是一位进行研究的教授。

在这个例子中，关联非常类似于广义聚合。在这两种情况下，相关的对象也是独立存在的。在这种情况下，无论是说`课程`拥有`教师`还是`课程`对`教师`有依赖都可以是灰色的。你可能会问自己 - 是不是只是口头语言让我选择了“拥有”的措辞？我是不是指两者之间存在必要的联系？也许这种关系是一种关联，它的描述性修饰（进一步描述关联的性质）是*教*。你可能有支持任何选择的论点。因此，广义聚合可以被认为是关联的专门类型；我们将看到它们的实现是相同的，使用独立存在的对象。尽管如此，我们将区分典型关联作为对象之间明确不支持真正拥有关系的关系。

例如，考虑`大学`和`教师`之间的关系。我们可以考虑这种关系不是拥有关系，而是关联关系；我们可以认为描述这种关系的修饰是*雇用*。同样，`大学`与许多`学生`对象有关系。这里的关联可以用*教育*来描述。可以区分出`大学`由`系`对象，`楼`对象和这类组件组成，以支持其通过包含的拥有关系，然而它与`教师`对象，`学生`对象等的关系是使用关联来建立的。

既然我们已经区分了典型关联和广义聚合，让我们看看如何实现关联以及涉及的一些复杂性。

## 实现关联

通常，两个或更多对象之间的关联是使用指针或指针集来实现的。*一*方使用指向相关对象的指针来实现，而关系的*多*方则以指向相关对象的指针集合的形式实现。指针集合可以是指针数组，指针链表，或者真正的任何指针集合。每种类型的集合都有其自己的优点和缺点。例如，指针数组易于使用，可以直接访问特定成员，但项目数量是固定的。指针链表可以容纳任意数量的项目，但访问特定元素需要遍历其他元素以找到所需的项目。

偶尔，引用可能被用来实现关联的*one*一侧。请记住，引用必须被初始化，并且不能在以后被重置为引用另一个对象。使用引用来建模关联意味着一个实例将与另一个特定实例相关联，而主对象存在期间不能更改。这是非常限制性的；因此，引用很少用于实现关联。

无论实现方式如何，当主对象消失时，它都不会影响（即删除）关联的对象。

让我们看一个典型的例子，说明了首选的一对多关联实现，利用*one*一侧的指针和*many*一侧的指针集合。在这个例子中，一个`University`将与许多`Student`实例相关联。而且，为了简单起见，一个`Student`将与一个`University`相关联。

为了节省空间，本程序中与上一个示例相同的部分将不会显示；但是，整个程序可以在我们的 GitHub 上找到：

[`github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter10/Chp10-Ex2.cpp`](https://github.com/PacktPublishing/Demystified-Object-Oriented-Programming-with-CPP/blob/master/Chapter10/Chp10-Ex2.cpp)

```cpp
#include <iostream>
#include <iomanip>
#include <cstring>
using namespace std;
const int MAX = 25;
// class Id and class Person are omitted here to save space.
// They will be as shown in previous example (Chp10-Ex1.cpp)
class Student; // forward declaration
class University
{
private:
    char *name;
    Student *studentBody[MAX]; // Association to many students
    int currentNumStudents;
    University(const University &);  // prohibit copies
public:
    University();
    University(const char *);
    ~University();
    void EnrollStudent(Student *);
    const char *GetName() const { return name; }
    void PrintStudents() const;
};
```

在前面的段落中，让我们首先注意`class Student;`的前向声明。这个声明允许我们的代码在`Student`类定义之前引用`Student`类型。在`University`类定义中，我们看到有一个指向`Student`的指针数组。我们还看到`EnrollStudent()`方法以`Student *`作为参数。前向声明使得在定义之前可以使用`Student`。

我们还注意到`University`具有一个简单的接口，包括构造函数、析构函数和一些成员函数。

接下来，让我们来看一下`University`成员函数的定义：

```cpp
University::University()
{
    name = 0;
    for (int i = 0; i < MAX; i++)  // the student body
       studentBody[i] = 0;         // will start out empty 
    currentNumStudents = 0;
}
University::University(const char *n)
{
    name = new char [strlen(n) + 1];
    strcpy(name, n);
    for (int i = 0; i < MAX; i++) // the student body will
       studentBody[i] = 0;        // start out empty
    currentNumStudents = 0;
}
University::~University()
{
    delete name;
    // The students will delete themselves
    for (int i = 0; i < MAX; i++)
       studentBody[i] = 0;  // only NULL out their link
}                      
void University::EnrollStudent(Student *s)
{
    // set an open slot in the studentBody to point to the
    // Student passed in as an input parameter
    studentBody[currentNumStudents++] = s;
}
void University::PrintStudents()const
{
    cout << name << " has the following students:" << endl;
    for (int i = 0; i < currentNumStudents; i++)
    {
       cout << "\t" << studentBody[i]->GetFirstName() << " ";
       cout << studentBody[i]->GetLastName() << endl;
    }
}
```

仔细观察前面的`University`方法，我们可以看到在`University`的两个构造函数中，我们只是将组成`studentBody`的指针`NULL`。同样，在析构函数中，我们也将与关联的`Students`的链接`NULL`。不久，在本节中，我们将看到还需要一些额外的反向链接维护，但现在的重点是我们不会删除关联的`Student`对象。

由于`University`对象和`Student`对象是独立存在的，因此它们之间既不会创建也不会销毁对方类型的实例。

我们还遇到了一个有趣的成员函数`EnrollStudent(Student *)`。在这个方法中，将传入一个指向特定`Student`的指针作为输入参数。我们只是索引到我们的`Student`对象指针数组`studentBody`中，并将一个未使用的数组元素指向新注册的`Student`。我们使用`currentNumStudents`计数器跟踪当前存在的`Student`对象数量，在指针分配后进行后置递增。

我们还注意到`University`有一个`Print()`方法，它打印大学的名称，然后是它当前的学生人数。它通过简单地访问`studentBody`中的每个关联的`Student`对象，并要求每个`Student`实例调用`Student::GetFirstName()`和`Student::GetLastName()`方法来实现这一点。

接下来，让我们来看一下我们的`Student`类定义，以及它的内联函数。请记住，我们假设`Person`类与本章前面看到的一样：

```cpp
class Student: public Person  
{
private:
    // data members
    float gpa;
    char *currentCourse;
    static int numStudents;
    Id studentId;  // part, Student Has-A studentId
    University *univ;  // Association to University object
public:
    // member function prototypes
    Student();  // default constructor
    Student(const char *, const char *, char, const char *,
            float, const char *, const char *, University *);
    Student(const Student &);  // copy constructor
    virtual ~Student();  // destructor
    void EarnPhD() { ModifyTitle("Dr."); }
    float GetGpa() const { return gpa; }
    const char *GetCurrentCourse() const 
        { return currentCourse; }
    void SetCurrentCourse(const char *); // prototype only
    virtual void Print() const override;
    virtual void IsA() override { cout << "Student" << endl; }
    static int GetNumberStudents() { return numStudents; }
    // Access functions for aggregate/associated objects
    const char *GetStudentId() const 
        { return studentId.GetId(); }
    const char *GetUniversity() const 
        { return univ->GetName(); }
};
int Student::numStudents = 0;  // def. of static data member
inline void Student::SetCurrentCourse(const char *c)
{
    delete currentCourse;   // delete existing course
    currentCourse = new char [strlen(c) + 1];
    strcpy(currentCourse, c);
}
```

在前面的代码段中，我们看到了`Student`类的定义。请注意，我们使用指针数据成员`University *univ;`与`University`关联。

在`Student`的类定义中，我们还可以看到有一个包装函数来封装对学生所在大学名称的访问，即`Student::GetUniversity()`。在这里，我们允许关联对象`univ`调用其公共方法`University::GetName()`，并将该值作为`Student::GetUniversity()`的结果返回。

现在，让我们来看看`Student`的非内联成员函数：

```cpp
Student::Student(): studentId ("None")
{
    gpa = 0.0;
    currentCourse = 0;  
    univ = 0;    // no current University association
    numStudents++;
}
Student::Student(const char *fn, const char *ln, char mi,
                 const char *t, float avg, const char *course,
                 const char *id, University *univ):
                 Person(fn, ln, mi, t), studentId(id)
{
    gpa = avg;
    currentCourse = new char [strlen(course) + 1];
    strcpy(currentCourse, course);
    // establish link to University, then back link
    this->univ = univ;  // required use of 'this'
    univ->EnrollStudent(this);  // another required 'this'
    numStudents++;
}
Student::Student(const Student &ps): 
                 Person(ps), studentId(ps.studentId)
{
    gpa = ps.gpa;
    currentCourse = new char [strlen(ps.currentCourse) + 1];
    strcpy(currentCourse, ps.currentCourse);
    this->univ = ps.univ;    
    univ->EnrollStudent(this);
    numStudents++;
}
Student::~Student()  // destructor
{
    delete currentCourse;
    numStudents--;
    univ = 0;  // the University will delete itself
    // the embedded object studentId will also be destructed
}
void Student::Print() const
{
    cout << GetTitle() << " " << GetFirstName() << " ";
    cout << GetMiddleInitial() << ". " << GetLastName();
    cout << " with id: " << studentId.GetId() << " GPA: ";
    cout << setprecision(3) <<  " " << gpa;
    cout << " Course: " << currentCourse << endl;
}
```

在前面的代码段中，请注意默认的`Student`构造函数和析构函数都只将它们与`University`对象的链接`NULL`。默认构造函数无法将此链接设置为现有对象，并且肯定不应该创建`University`实例来这样做。同样，`Student`析构函数不应该仅仅因为`Student`对象的寿命已经结束就删除`University`。

前面代码中最有趣的部分发生在`Student`的备用构造函数和复制构造函数中。让我们来看看备用构造函数。在这里，我们建立了与关联的`University`的链接，以及从`University`返回到`Student`的反向链接。

在代码行`this->univ = univ;`中，我们通过将数据成员`univ`（由`this`指针指向）设置为指向输入参数`univ`指向的位置来进行赋值。仔细看前面的类定义 - `University *`的标识符名为`univ`。此外，备用构造函数中`University *`的输入参数也被命名为`univ`。我们不能简单地在这个构造函数的主体中赋值`univ = univ;`。最本地范围内的`univ`标识符是输入参数`univ`。赋值`univ = univ;`会将该参数设置为自身。相反，我们使用`this`指针来消除赋值左侧的`univ`的歧义。语句`this->univ = univ;`将数据成员`univ`设置为输入参数`univ`。我们是否可以简单地将输入参数重命名为不同的名称，比如`u`？当然可以，但重要的是要理解在需要时如何消除具有相同标识符的输入参数和数据成员的歧义。

现在，让我们来看看下一行代码`univ->EnrollStudent(this);`。现在`univ`和`this->univ`指向同一个对象，无论使用哪一个来设置反向链接都没有关系。在这里，`univ`调用`EnrollStudent()`，这是`University`类中的一个公共成员函数。没有问题，`univ`的类型是`University`。`University::EnrollStudent(Student *)`期望传递一个指向`Student`的指针来完成`University`端的链接。幸运的是，在我们的`Student`备用构造函数中（调用函数的作用域），`this`指针是一个`Student *`。`this`就是我们需要创建反向链接的`Student *`。这是另一个需要显式使用`this`指针来完成手头任务的例子。

让我们继续前进到我们的`main()`函数：

```cpp
int main()
{
    University u1("The George Washington University");
    Student s1("Gabby", "Doone", 'A', "Miss", 3.85, "C++",
               "4225GWU", &u1);
    Student s2("Giselle", "LeBrun", 'A', "Ms.", 3.45, "C++",
               "1227GWU", &u1);
    Student s3("Eve", "Kendall", 'B', "Ms.", 3.71, "C++",
               "5542GWU", &u1);
    cout << s1.GetFirstName() << " " << s1.GetLastName();
    cout << " attends " << s1.GetUniversity() << endl;
    cout << s2.GetFirstName() << " " << s2.GetLastName();
    cout << " attends " << s2.GetUniversity() << endl;
    cout << s3.GetFirstName() << " " << s3.GetLastName();
    cout << " attends " << s2.GetUniversity() << endl;
    u1.PrintStudents();
    return 0;
}
```

最后，在我们的`main()`函数中的前面代码片段中，我们可以创建几个独立存在的对象，创建它们之间的关联，然后查看这种关系的实际情况。

首先，我们实例化一个`University`，即`u1`。接下来，我们实例化三个`Students`，`s1`，`s2`和`s3`，并将每个关联到`University u1`。请注意，当我们实例化一个`Student`时，可以设置这种关联，或者稍后进行设置，例如，如果`Student`类支持`SelectUniversity(University *)`接口来这样做。

然后，我们打印出每个`Student`，以及每个`Student`所就读的`University`的名称。然后我们打印出我们的`University u1`的学生人数。我们注意到，关联对象之间建立的链接在两个方向上都是完整的。

让我们来看看上述程序的输出：

```cpp
Gabby Doone attends The George Washington University
Giselle LeBrun attends The George Washington University
Eve Kendall attends The George Washington University
The George Washington University has the following students:
        Gabby Doone
        Giselle LeBrun
        Eve Kendall
```

我们已经看到了如何在相关对象之间轻松建立和利用关联。然而，从实现关联中会产生大量的维护工作。让我们继续了解引用计数和反向链接维护的必要和相关问题，这将有助于这些维护工作。

## 利用反向链接维护和引用计数

在前面的小节中，我们已经看到了如何使用指针来实现关联。我们已经看到了如何使用指向关联实例中的对象的指针来建立对象之间的关系。我们也看到了如何通过建立反向链接来完成循环的双向关系。

然而，与关联对象一样，关系是流动的，随着时间的推移会发生变化。例如，给定“大学”的“学生”群体会经常发生变化，或者“教师”将在每个学期教授的各种“课程”也会发生变化。因此，通常会删除特定对象与另一个对象的关联，并可能改为与该类的另一个实例关联。但这也意味着关联的对象必须知道如何删除与第一个提到的对象的链接。这变得复杂起来。

举例来说，考虑“学生”和“课程”的关系。一个“学生”可以注册多个“课程”实例。一个“课程”包含对多个“学生”实例的关联。这是一种多对多的关联。假设“学生”希望退出一门“课程”。仅仅让特定的“学生”实例移除指向特定“课程”实例的指针是不够的。此外，“学生”必须让特定的“课程”实例知道，应该将相关的“学生”从该“课程”的名单中移除。这被称为反向链接维护。

考虑一下，在上述情况下，如果一个“学生”简单地将其与要退出的“课程”的链接设置为`NULL`，然后不再进行任何操作，会发生什么。受影响的“学生”实例将不会有问题。然而，以前关联的“课程”实例仍将包含指向该“学生”的指针。也许这会导致“学生”在“教师”仍然认为该“学生”已注册但没有交作业的情况下获得不及格分数。最终，这位“学生”还是受到了影响，得到了不及格分数。

记住，对于关联的对象，一个对象在完成与另一个对象的交互后不会删除另一个对象。例如，当一个“学生”退出一门“课程”时，他们不会删除那门“课程” - 只是移除他们对相关“课程”的指针（并且肯定也要处理所需的反向链接维护）。

一个帮助我们进行整体链接维护的想法是考虑**引用计数**。引用计数的目的是跟踪有多少指针可能指向给定的实例。例如，如果其他对象指向给定的实例，那么该实例就不应该被删除。否则，其他对象中的指针将指向已释放的内存，这将导致大量的运行时错误。

让我们考虑一个具有多重性的关联。比如“学生”和“课程”之间的关系。一个“学生”应该跟踪有多少“课程”指针指向该“学生”，也就是说，该“学生”正在上多少门“课程”。只要有多个“课程”指向该“学生”，就不应该删除该“学生”。否则，“课程”将指向已删除的内存。处理这种情况的一种方法是在“学生”析构函数中检查对象（this）是否包含指向“课程”的非`NULL`指针。如果对象包含这样的指针，那么它需要通过每个活跃的“课程”调用一个方法，请求从每个这样的“课程”中移除对“学生”的链接。在移除每个链接之后，与“课程”实例集对应的引用计数可以递减。

同样，链接维护应该发生在`Course`类中，而不是`Student`实例中。在通知所有在该`Course`中注册的`Student`实例之前，不应删除`Course`实例。通过引用计数来跟踪有多少`Student`实例指向`Course`的特定实例是有帮助的。在这个例子中，只需维护一个变量来反映当前注册在`Course`中的`Student`实例的数量就可以了。

我们可以自己精心进行链接维护，或者选择使用智能指针来管理关联对象的生命周期。**智能指针**可以在 C++标准库中找到。它们封装了一个指针（即在类中包装一个指针）以添加智能特性，包括引用计数和内存管理。由于智能指针使用了模板，而我们直到*第十三章*，*使用模板*，我们才会涵盖，所以我们在这里只是提到了它们的潜在实用性。

我们现在已经看到了后向链接维护的重要性，以及引用计数的实用性，以充分支持关联及其成功的实现。在继续前进到下一章之前，让我们简要回顾一下本章涵盖的面向对象的概念——关联、聚合和组合。

# 总结

在本章中，我们通过探索各种对象关系——关联、聚合和组合，继续推进我们对面向对象编程的追求。我们已经理解了代表这些关系的各种面向对象设计概念，并且已经看到 C++并没有通过关键字或特定的语言特性直接提供语言支持来实现这些概念。

尽管如此，我们已经学会了几种实现这些核心面向对象关系的技术，比如使用嵌入对象来实现组合和广义聚合，或者使用指针来实现关联。我们已经研究了这些关系中对象存在的典型寿命，例如通过创建和销毁其内部部分（通过嵌入对象，或者更少见地通过分配和释放指针成员），或者通过相关对象的独立存在，它们既不创建也不销毁彼此。我们还深入研究了实现关联所需的内部工作，特别是那些具有多重性的关联，通过检查后向链接维护和引用计数。

通过理解如何实现关联、聚合和组合，我们已经为我们的面向对象编程技能增添了关键特性。我们已经看到了这些关系在面向对象设计中甚至可能比继承更为常见的例子。通过掌握这些技能，我们已经完成了在 C++中实现基本面向对象概念的核心技能组合。

我们现在准备继续到*第十一章*，*处理异常*，这将开始我们扩展 C++编程技能的探索。让我们继续前进！

# 问题

1.  在本章的`University`-`Student`示例中添加一个额外的`Student`构造函数，以接受引用而不是指针的`University`构造参数。例如，除了带有签名`Student::Student(const char *fn, const char *ln, char mi, const char *t, float avg, const char *course, const char *id, University *univ);`的构造函数外，重载此函数，但最后一个参数为`University &univ`。这如何改变对此构造函数的隐式调用？

提示：在您重载的构造函数中，您现在需要取`University`引用参数的地址（即`&`）来设置关联（存储为指针）。您可能需要切换到对象表示法（`.`）来设置后向链接（如果您使用参数`univ`，而不是数据成员`this->univ`）。

1.  编写一个 C++程序来实现“课程”类型对象和“学生”类型对象之间的多对多关联。您可以选择在之前封装“学生”的程序基础上构建。多对多关系应该按以下方式工作：

a. 给定的“学生”可以选修零到多门“课程”，而给定的“课程”将与多个“学生”实例关联。封装“课程”类，至少包含课程名称、指向关联“学生”实例的指针集，以及一个引用计数，用于跟踪在“课程”中的“学生”实例数量（这将等同于多少“学生”实例指向给定的“课程”实例）。添加适当的接口来合理封装这个类。

b. 在您的“学生”类中添加指向该“学生”注册的“课程”实例的指针集。此外，跟踪给定“学生”注册的“课程”实例数量。添加适当的成员函数来支持这种新功能。

c. 使用指针的链表（即，数据部分是指向关联对象的指针）或作为关联对象的指针数组来对多边关联进行建模。请注意，数组将对您可以拥有的关联对象数量施加限制；但是，这可能是合理的，因为给定的“课程”只能容纳最大数量的“学生”，而“学生”每学期只能注册最大数量的“课程”。如果您选择指针数组的方法，请确保您的实现包括错误检查，以适应每个数组中关联对象数量超过最大限制的情况。

d. 一定要检查简单的错误，比如尝试在已满的“课程”中添加“学生”，或者向“学生”的课程表中添加过多的“课程”（假设每学期最多有 5 门课程）。

e. 确保您的析构函数不会删除关联的实例。

f. 引入至少三个“学生”对象，每个对象都选修两门或更多门“课程”。此外，请确保每门“课程”都有多个“学生”注册。打印每个“学生”，包括他们注册的每门“课程”。同样，打印每门“课程”，显示注册在该“课程”中的每个“学生”。

1.  （可选）增强您在*练习 2*中的程序，以获得以下反向链接维护和引用计数的经验：

a. 为“学生”实现一个`DropCourse()`接口。也就是，在“学生”中创建一个“Student::DropCourse(Course *)”方法。在这里，找到“学生”希望在他们的课程列表中删除的“课程”，但在删除“课程”之前，调用该“课程”的一个方法，从该“课程”中删除前述的“学生”（即，`this`）。提示：您可以创建一个`Course::RemoveStudent(Student *)`方法来帮助删除反向链接。

b. 现在，完全实现适当的析构函数。当一个“课程”被销毁时，让“课程”析构函数首先告诉每个剩余的关联“学生”删除他们与该“课程”的链接。同样，当一个“学生”被销毁时，循环遍历“学生”的课程列表，要求那些“课程”从他们的学生列表中删除前述的“学生”（即，`this`）。您可能会发现每个类中的引用计数（即，通过检查`numStudents`或`numCourses`）有助于确定是否必须执行这些任务。
