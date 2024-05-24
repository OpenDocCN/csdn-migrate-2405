# C++ 高级编程（三）

> 原文：[`annas-archive.org/md5/5f35e0213d2f32c832c0e92fd16884c1`](https://annas-archive.org/md5/5f35e0213d2f32c832c0e92fd16884c1)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：关注点的分离 - 软件架构、函数和可变模板

## 学习目标

在本章结束时，您将能够：

+   使用 PIMPL 习惯用法来实现对象级封装

+   使用函数对象、std::function 和 lambda 表达式实现回调系统

+   使用正确的捕获技术来实现 lambda 表达式

+   开发可变模板以实现 C#风格的委托以进行事件处理。

本章将向您展示如何实现 PIMPL 习惯用法，以及如何为您自己的程序开发回调机制。

## 介绍

在上一章中，我们学习了如何实现类来正确管理资源，即使在发生异常时也是如此，使用 RAII。我们还学习了 ADL（**Argument Dependent Lookup**）以及它如何确定要调用的函数。最后，我们谈到了显式关键字如何可以防止编译器进行类型之间的自动转换，即隐式转换。

在本章中，我们将研究依赖关系，包括物理依赖关系和逻辑依赖关系，以及它们如何对构建时间产生不利影响。我们还将学习如何将可见接口类与实现细节分离，以增加构建时间的速度。然后，我们将学习如何捕获函数和上下文，以便以后可以使用“函数对象”、`std::function`和“lambda 表达式”来调用它们。最后，我们将实现可变模板以提供基于事件的回调机制。

### 指向实现的指针（PIMPL）习惯用法

随着 C++实现的项目变得越来越大，构建时间增长的速度可能会超过文件数量的增长速度。这是因为 C++构建模型使用了文本包含模型。这样做是为了让编译器能够确定类的大小和布局，导致了“调用者”和“被调用者”之间的耦合，但也允许进行优化。请记住，一切都必须在使用之前定义。未来的一个特性叫做“模块”承诺解决这个问题，但现在我们需要了解这个问题以及用来解决问题的技术。

### 逻辑和物理依赖关系

当我们希望从另一个类中访问一个类时，我们有一个逻辑依赖关系。一个类在逻辑上依赖于另一个类。如果我们考虑我们在*第 2A 章*“不允许鸭子 - 类型和推导”和*第三章*“能与应该之间的距离 - 对象、指针和继承”中开发的`Graphics`类，`Point3d`和`Matrix3d`，我们有两个逻辑独立的类`Matrix3d`和`Point3d`。然而，由于我们如何在两者之间实现了乘法运算符，我们创建了一个编译时或**物理依赖关系**。

![图 4.1：Matrix3d 和 Point3d 的物理依赖关系](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_04_01.jpg)

###### 图 4.1：Matrix3d 和 Point3d 的物理依赖关系

正如我们在这些相对简单的类中所看到的，头文件和实现文件之间的物理依赖关系很快就会变得复杂起来。正是这种复杂性导致了大型项目的构建时间增加，因为物理（和逻辑）依赖关系的数量增长到了成千上万。在前面的图表中，我们只显示了 13 个依赖关系，如箭头所示。但实际上还有更多，因为包含标准库头文件通常会引入一系列包含文件的层次结构。这意味着如果修改了一个头文件，那么直接或间接依赖于它的所有文件都需要重新编译以适应变化。如果更改是对用户甚至无法访问的私有类成员定义的，也会触发重新构建。

为了加快编译时间，我们使用了保护技术来防止头文件被多次处理：

```cpp
#if !defined(MY_HEADER_INCLUDED)
#define   MY_HEADER_INCLUDED
// definitions 
#endif // !defined(MY_HEADER_INCLUDED)
```

最近，大多数编译器现在支持`#pragma once`指令，它可以实现相同的结果。

这些实体（文件、类等）之间的关系被称为**耦合**。如果对文件/类的更改导致对其他文件/类的更改，则文件/类与另一个文件/类**高度耦合**。如果对文件/类的更改不会导致对其他文件/类的更改，则文件/类与另一个文件/类**松散耦合**。

高度耦合的代码（文件/类）会给项目带来问题。高度耦合的代码难以更改（不灵活），难以测试和难以理解。另一方面，松散耦合的代码更容易更改（只需修改一个类），更易测试（只需测试正在测试的类）并且更易阅读和理解。耦合反映并与逻辑和物理依赖相关。

### 指向实现（PIMPL）惯用法

解决这种耦合问题的一种方法是使用“Pimpl 惯用法”（即“指向实现的指针惯用法”）。这也被称为不透明指针、编译器防火墙惯用法，甚至是“切尔西猫技术”。考虑 Qt 库，特别是 Qt 平台抽象（QPA）。这是一个隐藏 Qt 应用程序所托管的操作系统和/或平台细节的抽象层。实现这样一层的方法之一是使用 PIMPL 惯用法，其中公共接口暴露给应用程序开发人员，但功能的实现方式是隐藏的。Qt 实际上使用了 PIMPL 的变体，称为 d-pointer。

例如，GUI 的一个特性是使用对话框，它是一个弹出窗口，用于显示信息或提示用户输入。可以在**dialog.hpp**中声明如下：

#### 注

有关 QT 平台抽象（QPA）的更多信息，请访问以下链接：[`doc.qt.io/qt-5/qpa.html#`](https://doc.qt.io/qt-5/qpa.html#)。

```cpp
#pragma once
class Dialog
{
public:
    Dialog();
    ~Dialog();
    void create(const char* message);
    bool show();
private:
    struct DialogImpl;
    DialogImpl* m_pImpl;
};
```

用户可以访问使用`Dialog`所需的所有函数，但不知道它是如何实现的。请注意，我们声明了`DialogImpl`但没有定义它。一般来说，我们对这样的`DialogImpl`类做不了太多事情。但有一件事是允许的，那就是声明一个指向它的指针。C++的这个特性允许我们在实现文件中隐藏实现细节。这意味着在这种简单情况下，我们不需要为这个声明包含任何包含文件。

实现文件**dialogImpl.cpp**可以实现为：

```cpp
#include "dialog.hpp"
#include <iostream>
#include <string>
struct Dialog::DialogImpl
{
    void create(const char* message)
    {
        m_message = message;
        std::cout << "Creating the Dialog\n";
    }
    bool show()
    {
        std::cout << "Showing the message: '" << m_message << "'\n";
        return true;
    }
    std::string m_message;
};
Dialog::Dialog() : m_pImpl(new DialogImpl)
{
}
Dialog::~Dialog()
{
    delete m_pImpl;
}
void Dialog::create(const char* message)
{
    m_pImpl->create(message);
}
bool Dialog::show()
{
    return m_pImpl->show();
}
```

我们从中注意到几件事：

+   在我们定义对话框所需的方法之前，我们先定义实现类`DialogImpl`。这是必要的，因为`Dialog`将需要通过`m_pImpl`来调用这些方法，这意味着它们需要首先被定义。

+   `Dialog`的构造函数和析构函数负责内存管理。

+   我们只在实现文件中包含了实现所需的所有必要头文件。这通过最小化**Dialog.hpp**文件中包含的头文件数量来减少耦合。

该程序可以按以下方式执行：

```cpp
#include <iostream>
#include "dialog.hpp"
int main()
{
    std::cout << "\n\n------ Pimpl ------\n";
    Dialog dialog;
    dialog.create("Hello World");
    if (dialog.show())
    {
        std::cout << "Dialog displayed\n";
    }
    else
    {
        std::cout << "Dialog not displayed\n";
    }
    std::cout << "Complete.\n";
    return 0;
}
```

在执行时，上述程序产生以下输出：

![图 4.2：示例 Pimpl 实现输出](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_04_02.jpg)

###### 图 4.2：示例 Pimpl 实现输出

### PIMPL 的优缺点

使用 PIMPL 的最大优势是它打破了类的客户端和其实现之间的编译时依赖关系。这样可以加快构建时间，因为 PIMPL 在定义（头）文件中消除了大量的`#include`指令，而只需要在实现文件中才是必要的。

它还将实现与客户端解耦。现在我们可以自由更改 PIMPL 类的实现，只需重新编译该文件。这可以防止编译级联，其中对隐藏成员的更改会触发客户端的重建。这被称为编译防火墙。

PIMPL 惯用法的一些其他优点如下：

+   **数据隐藏** - 实现的内部细节真正地被隔离在实现类中。如果这是库的一部分，那么它可以用来防止信息的泄露，比如知识产权。

+   `DLL`或`.so`文件），并且可以自由更改它而不影响客户端代码。

这些优点是有代价的。缺点如下：

+   **维护工作** - 可见类中有额外的代码将调用转发到实现类。这增加了一定复杂性的间接层。

+   **内存管理** - 现在添加了一个指向实现的指针，我们需要管理内存。它还需要额外的存储空间来保存指针，在内存受限的系统中（例如：物联网设备）这可能是关键的。

### 使用 unique_ptr<>实现 PIMPL

我们当前的 Dialog 实现使用原始指针来持有 PIMPL 实现引用。在*第三章*中，*能与应该之间的距离-对象、指针和继承*中，我们讨论了对象的所有权，并引入了智能指针和 RAII。PIMPL 指针指向的隐藏对象是一个需要管理的资源，应该使用`RAII`和`std::unique_ptr`来执行。正如我们将看到的，使用`std::unique_ptr`实现`PIMPL`有一些注意事项。

让我们将 Dialog 的实现改为使用智能指针。首先，头文件更改以引入`#include <memory>`行，并且可以删除析构函数，因为`unique_ptr`会自动删除实现类。

```cpp
#pragma once
#include <memory>
class Dialog
{
public:
    Dialog();
    void create(const char* message);
    bool show();
private:
    struct DialogImpl;
    std::unique_ptr<DialogImpl> m_pImpl;
};
```

显然，我们从实现文件中删除了析构函数，并修改构造函数以使用`std::make_unique`。

```cpp
Dialog::Dialog() : m_pImpl(std::make_unique<DialogImpl>())
{
}
```

重新编译我们的新版本时，**Dialog.hpp**和**DialogImpl.cpp**文件没有问题，但我们的客户端**main.cpp**报告了以下错误（使用 gcc 编译器），如下所示：

![图 4.3：使用 unique_ptr 失败的 Pimpl 编译](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_04_03.jpg)

###### 图 4.3：使用 unique_ptr 失败的 Pimpl 编译

当`main()`函数结束时，第一个错误报告了`Dialog`。正如我们在*第 2A 章*中讨论的那样，*不允许鸭子-类型和推断*编译器将为我们生成一个析构函数（因为我们删除了它）。这个生成的析构函数将调用`unique_ptr`的析构函数，这就是错误的原因。如果我们看一下`line 76`，默认`unique_ptr`使用的`deleter`的`operator()`函数（`deleter`是`unique_ptr`在销毁其指向的对象时调用的函数）：

```cpp
void
operator()(_Tp* __ptr) const
{
    static_assert(!is_void<_Tp>::value, "can't delete pointer to incomplete type");
    static_assert(sizeof(_Tp)>0, "can't delete pointer to incomplete type");
    delete __ptr;
}
```

我们的代码在第二个`static_assert()`语句上失败，这会导致编译出错。问题在于编译器试图为`std::unique_ptr<DialogImpl>`和`DialogImpl`生成析构函数，而`DialogImpl`是一个不完整的类型。因此，为了解决问题，我们控制生成析构函数的时机，使`DialogImpl`成为一个完整的类型。

为了做到这一点，我们将析构函数的声明放回类中，并将其实现添加到`DialogImpl.cpp`文件中。

```cpp
Dialog::~Dialog()
{
}
```

当我们编译并运行我们的程序时，它产生的输出与之前完全相同。实际上，如果我们只需要一个空的析构函数，我们可以用以下代码替换上面的代码：

```cpp
Dialog::~Dialog() = default;
```

如果我们编译并运行我们的程序，那么将产生以下输出：

![图 4.4：示例 unique_ptr Pimpl 实现输出](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_04_04.jpg)

###### 图 4.4：示例 unique_ptr Pimpl 实现输出

### unique_ptr<> PIMPL 特殊函数

由于 PIMPL 通常意味着可见接口类拥有实现类，因此移动语义是一个自然的选择。然而，就像编译器生成的析构函数实现是正确的一样，编译器生成的移动构造函数和移动赋值运算符将产生期望的行为，即对成员`unique_ptr`执行移动。移动操作都可能需要在分配传输值之前执行删除，因此，与不完整类型的析构函数一样，它们也会遇到相同的问题。解决方案与析构函数相同-在头文件中声明该方法，并在类型完成时实现-在实现文件中。因此，我们的头文件看起来像下面这样：

```cpp
class Dialog
{
public:
    Dialog();
    ~Dialog();
    Dialog(Dialog&& rhs);
    Dialog& operator=(Dialog&& rhs);
    void create(const char* message);
    bool show();
private:
    struct DialogImpl;
    std::unique_ptr<DialogImpl> m_pImpl;
};
```

虽然实现看起来像：

```cpp
Dialog::Dialog() : m_pImpl(std::make_unique<DialogImpl>())
{
}
Dialog::~Dialog() = default;
Dialog::Dialog(Dialog&& rhs) = default;
Dialog& Dialog::operator=(Dialog&& rhs) = default;
```

根据我们在实现类中隐藏的数据项，我们可能还希望在我们的 PIMPL 类上具有复制功能。在 Dialog 类内部使用`std::unique_ptr`可以防止自动生成复制构造函数和复制赋值运算符，因为内部成员不支持复制。此外，通过定义移动成员函数，就像我们在*第 2A 章*中看到的那样，它也阻止编译器生成复制版本。此外，如果编译器为我们生成了复制语义，它只会是**浅复制**。但由于 PIMPL 实现，我们需要**深复制**。因此，我们需要编写自己的复制特殊成员函数。同样，定义放在头文件中，实现需要在类型完成的地方完成，即在**DialogImpl.cpp**文件中。

在头文件中，我们添加以下声明：

```cpp
Dialog(const Dialog& rhs);
Dialog& operator=(const Dialog& rhs);
```

实现将如下所示：

```cpp
Dialog::Dialog(const Dialog& rhs) : m_pImpl(nullptr)
{
    if (this == &rhs)   // do nothing on copying self
    return;
    if (rhs.m_pImpl)    // rhs has something -> clone it
        m_pImpl = std::make_unique<DialogImpl>(*rhs.m_pImpl);
}
Dialog& Dialog::operator=(const Dialog& rhs)
{
    if (this == &rhs)   // do nothing on assigning to self
        return *this;
    if (!rhs.m_pImpl)   // rhs is empty -> delete ours
    {
        m_pImpl.reset();
    }
    else if (!m_pImpl)  // ours is empty -> clone rhs
    {
        m_pImpl = std::make_unique<DialogImpl>(*rhs.m_pImpl);
    }
    else // use copy of DialogImpl
    {
        *m_pImpl = *rhs.m_pImpl;
    }
}
```

注意`if(this == &rhs)`子句。这些是为了防止对象不必要地复制自身。还要注意，我们需要检查`unique_ptr`是否为空，并相应地处理复制。

#### 注意

在本章中解决任何实际问题之前，下载 GitHub 存储库[`github.com/TrainingByPackt/Advanced-CPlusPlus`](https://github.com/TrainingByPackt/Advanced-CPlusPlus)并在 Eclipse 中导入 Lesson 4 文件夹，以便您可以查看每个练习和活动的代码。

### 练习 1：使用 unique_ptr<>实现厨房

在这个练习中，我们将通过使用`unique_ptr<>`实现`Pimpl idiom`来隐藏厨房处理订单的细节。按照以下步骤来实现这个练习：

1.  在 Eclipse 中打开**Lesson4**项目，然后在**Project Explorer**中展开**Lesson4**，然后展开**Exercise01**，双击**Exercise1.cpp**以将此练习的文件打开到编辑器中。

1.  由于这是一个基于 CMake 的项目，将当前构建器更改为 CMake Build（便携式）。

1.  单击**Launch Configuration**下拉菜单，然后选择**New Launch Configuration…**。配置**L4Exercise1**以使用名称**Exercise1**运行。

1.  单击**Run**按钮。练习 1 将运行并产生以下输出：![图 4.5：练习 1 程序输出](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_04_05.jpg)

###### 图 4.5：练习 1 程序输出

1.  打开`Kitchen`。我们将把所有私有成员移到一个实现类中并隐藏细节。

1.  在`#include <memory>`指令中获得对`unique_ptr`的访问。添加析构函数`~Kitchen();`的声明，然后将以下两行添加到私有部分的顶部：

```cpp
struct Impl;
std::unique_ptr<Impl> m_impl;
```

1.  打开`#include`指令：

```cpp
struct Kitchen::Impl
{
};
Kitchen::~Kitchen() = default;
```

1.  单击**Run**按钮重新构建程序。您会看到输出仍然与以前相同。

1.  从`Kitchen`类中的`Kitchen::Impl`声明中删除除两个新成员之外的所有私有成员。`#include <vector>`，`#include "recipe.hpp"`和`#include "dessert.hpp"`：

```cpp
#pragma once
#include <string>
#include <memory>
class Kitchen
{
public:
    Kitchen(std::string chef);
    ~Kitchen();
    std::string processOrder(std::string order);
private:
    struct Impl;
    std::unique_ptr<Impl> m_impl;
};
```

1.  在`Kitchen::Impl`构造函数中：

```cpp
Kitchen::Impl::Impl(std::string chef) : m_chef{chef}
```

1.  对于原始方法的其余部分，将它们更改为作用域为`Kitchen::Impl`而不是`Kitchen::`。例如，`std::string Kitchen::processOrder(std::string order)`变为`std::string Kitchen::Impl::processOrder(std::string order)`。

1.  在`Kitchen::Impl`中，添加一个带有`std::string`参数和`processOrder()`方法的构造函数。`Kitchen::Impl`声明现在应如下所示：

```cpp
struct Kitchen::Impl
{
    Impl(std::string chef);
    std::string processOrder(std::string order);
    std::string searchForRecipe(std::string order);
    std::string searchForDessert(std::string order);
    std::string cookRecipe(std::string recipe);
    std::string serveDessert(std::string dessert);
    std::vector<Recipe>::iterator getRecipe(std::string recipe);
    std::vector<Dessert>::iterator getDessert(std::string recipe);
    std::string m_chef;
    std::vector<Recipe> m_recipes;
    std::vector<Dessert> m_desserts;
};
```

1.  在`#include <vector>`，`#include "recipe.hpp"`和`#include "dessert.hpp"`添加到文件顶部。

1.  单击`Kitchen::Kitchen`和`Kitchen::processOrder`。

1.  在`Kitchen::Impl`方法定义中，添加以下两个方法：

```cpp
Kitchen::Kitchen(std::string chef) : m_impl(std::make_unique<Kitchen::Impl>(chef))
{
}
std::string Kitchen::processOrder(std::string order)
{
    return m_impl->processOrder(order);
}
```

1.  单击**Run**按钮重新构建程序。程序将再次运行以产生原始输出。

![图 4.6：使用 Pimpl 的厨房程序输出](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_04_06.jpg)

###### 图 4.6：使用 Pimpl 的厨房程序输出

在这个练习中，我们已经将一个类中的许多细节移到了 PIMPL 类中，以隐藏细节并使用先前描述的技术将接口与实现解耦。

## 函数对象和 Lambda 表达式

在编程中常用的一种模式，特别是在实现基于事件的处理时，如异步输入和输出，是使用**回调**。客户端注册他们希望被通知事件发生的情况（例如：数据可供读取，或数据传输完成）。这种模式称为**观察者模式**或**订阅者发布者模式**。C ++支持各种技术来提供回调机制。

### 函数指针

第一种机制是使用**函数指针**。这是从 C 语言继承的传统功能。以下程序显示了函数指针的示例：

```cpp
#include <iostream>
using FnPtr = void (*)(void);
void function1()
{
    std::cout << "function1 called\n";
}
int main()
{
    std::cout << "\n\n------ Function Pointers ------\n";
    FnPtr fn{function1};
    fn();
    std::cout << "Complete.\n";
    return 0;
}
```

编译和执行此程序时，将产生以下输出：

![图 4.7：函数指针程序输出](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_04_07.jpg)

###### 图 4.7：函数指针程序输出

严格来说，代码应修改如下：

```cpp
FnPtr fn{&function1};
if(fn != nullptr)
    fn();
```

首先要注意的是应使用地址（`&`）运算符来初始化指针。其次，在调用之前应检查指针是否有效。

```cpp
#include <iostream>
using FnPtr = void (*)(void);
struct foo
{
    void bar() { std::cout << "foo:bar called\n"; }
};
int main()
{
    std::cout << "\n\n------ Function Pointers ------\n";
    foo object;
    FnPtr fn{&object.bar};
    fn();
    std::cout << "Complete.\n";
    return 0;
}
```

当我们尝试编译此程序时，会得到以下错误：

![图 4.8：编译函数指针程序时出现的错误](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_04_08.jpg)

###### 图 4.8：编译函数指针程序时出现的错误

第一个错误的文本是`this`指针。

通过将上述程序更改为以下内容：

```cpp
#include <iostream>
using FnPtr = void (*)(void);
struct foo
{
    static void bar() { std::cout << "foo:bar called\n"; }
};
int main()
{
    std::cout << "\n\n------ Function Pointers ------\n";
    FnPtr fn{&foo::bar};
    fn();
    std::cout << "Complete.\n";
    return 0;
}
```

它成功编译并运行：

![图 4.9：使用静态成员函数的函数指针程序](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_04_09.jpg)

###### 图 4.9：使用静态成员函数的函数指针程序

函数指针技术通常用于与使用回调和支持回调的操作系统通知的 C 库进行接口的情况。在这两种情况下，回调通常会接受一个`void *`参数，该参数是用户注册的数据块指针。数据块指针可以是类的`this`指针，然后对其进行解引用，并将回调转发到成员函数。

在其他语言中，如 Python 和 C＃，捕获函数指针也会捕获调用该函数所需的足够数据（例如：`self`或`this`）是语言的一部分。 C ++具有通过函数调用运算符使任何对象可调用的能力，我们将在下面介绍。

### 什么是函数对象？

C ++允许重载函数调用运算符`operator()`。这导致可以使任何对象“可调用”。可调用的对象在以下程序中称为`Scaler`类实现了`functor`。

```cpp
struct Scaler
{
    Scaler(int scale) : m_scale{scale} {};
    int operator()(int value)
    {
        return m_scale * value;
    }
    int m_scale{1};
};
int main()
{
    std::cout << "\n\n------ Functors ------\n";
    Scaler timesTwo{2};
    Scaler timesFour{4};
    std::cout << "3 scaled by 2 = " << timesTwo(3) << "\n";
    std::cout << "3 scaled by 4 = " << timesFour(3) << "\n";
    std::cout << "Complete.\n";
    return 0;
}
```

创建了两个类型为`Scaler`的对象，并且它们在生成输出的行内被用作函数。上述程序产生以下输出：

![图 4.10：functors 程序输出](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_04_10.jpg)

###### 图 4.10：函数对象程序输出

`functors`相对于函数指针的一个优点是它们可以包含状态，可以是对象或跨所有实例。另一个优点是它们可以传递给期望函数（例如`std::for_each`）或操作符（例如`std::transform`）的 STL 算法。

这样的用法示例可能如下所示：

```cpp
#include <iostream>
#include <vector>
#include <algorithm>
struct Scaler
{
    Scaler(int scale) : m_scale{scale} {};
    int operator()(int value)
    {
        return m_scale * value;
    }
    int m_scale{1};
};
void PrintVector(const char* prefix, std::vector<int>& values)
{
    const char* sep = "";
    std::cout << prefix << " = [";
    for(auto n : values)
    {
        std::cout << sep << n;
        sep = ", ";
    }
    std::cout << "]\n";
}
int main()
{
    std::cout << "\n\n------ Functors with STL ------\n";
    std::vector<int> values{1,2,3,4,5};
    PrintVector("Before transform", values);
    std::transform(values.begin(), values.end(), values.begin(), Scaler(3));
    PrintVector("After transform", values);
    std::cout << "Complete.\n";
    return 0;
}
```

如果我们运行这个程序，产生的输出将如下所示：

![图 4.11：显示标量转换向量的程序输出](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_04_11.jpg)

###### 图 4.11：显示标量转换向量的程序输出

### 练习 2：实现函数对象

在这个练习中，我们将实现两个不同的函数对象，可以与 STL 算法`for_each`一起使用。

1.  在 Eclipse 中打开**Lesson4**项目，然后在**项目资源管理器**中展开**Lesson4**，然后展开**Exercise02**，双击**Exercise2.cpp**以打开此练习的文件到编辑器中。

1.  由于这是一个基于 CMake 的项目，将当前构建器更改为 CMake Build（便携式）。

1.  点击**启动配置**下拉菜单，选择**新启动配置...**。配置**L4Exercise2**以名称**Exercise2**运行。

1.  点击**运行**按钮。练习 2 将运行并产生以下输出：![图 4.12：练习 2 的初始输出](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_04_12.jpg)

###### 图 4.12：练习 2 的初始输出

我们要做的第一件事是通过引入函数对象来修复输出的格式。

1.  在编辑器中，在`main()`函数定义之前添加以下类定义：

```cpp
struct Printer
{
    void operator()(int n)
    {
        std::cout << m_sep << n;
        m_sep = ", ";
    }
    const char* m_sep = "";
};
```

1.  在**main()**方法中替换以下代码

```cpp
std::cout << "Average of [";
for( auto n : values )
    std::cout << n << ", ";
std::cout << "] = ";
```

**带有**

```cpp
std::cout << "Average of [";
std::for_each(values.begin(), values.end(), Printer());
std::cout << "] = ";
```

1.  点击**运行**按钮。练习将运行并产生以下输出：![图 4.13：改进的输出格式的练习 2](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_04_13.jpg)

###### 图 4.13：改进的输出格式的练习 2

1.  `Printer`类的内部状态允许我们修复格式。现在，引入一个`aggregator`类，它将允许我们计算`average`。在文件顶部添加以下类定义：

```cpp
struct Averager
{
    void operator()(int n)
    {
        m_sum += n;
        m_count++;
    }
    float operator()() const
    {
        return static_cast<float>(m_sum)/(m_count==0?1:m_count);
    }
    int m_count{0};
    int m_sum{0};
};
```

1.  修改`main()`方法以使用`Averager`类如下：

```cpp
int main(int argc, char**argv)
{
    std::cout << "\n------ Exercise 2 ------\n";
    std::vector<int> values {1,2,3,4,5,6,7,8,9,10};
    Averager averager = std::for_each(values.begin(), values.end(), 
    Averager());
    std::cout << "Average of [";
    std::for_each(values.begin(), values.end(), Printer());
    std::cout << "] = ";
    std::cout << averager() << "\n";
    std::cout << "Complete.\n";
    return 0;
}
```

1.  点击**运行**按钮。练习将运行并产生以下输出：

![图 4.14：带有平均值的练习 2 输出](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_04_14.jpg)

###### 图 4.14：带有平均值的练习 2 输出

注意，`std::for_each()`返回传递给它的`Averager`的实例。这个实例被复制到变量`averager`中，然后包含了计算平均值所需的数据。在这个练习中，我们实现了两个函数对象或`functor`类：`Averager`和`Printer`，当传递给 STL 算法`for_each`时，我们可以将它们用作函数。

### std::function<>模板

C++11 引入了一个通用的多态函数包装模板，`std::function<>`，使得实现回调和其他与函数相关的功能更容易。`std::function`保存一个可调用对象，称为`std::function`将导致抛出`std::bad_function_call`异常。

函数对象可以存储、复制或调用目标，这些目标可以是以下任何可调用对象：函数、函数对象（定义了`operator()`）、成员函数指针或 lambda 表达式。我们将在主题*什么是 Lambda 表达式？*中更多地介绍它。

在实例化`std::function`对象时，只需要提供函数签名，而不需要初始化它的值，导致一个空实例。实例化如下所示：

![图 4.15：std::function 声明的结构](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_04_15.jpg)

###### 图 4.15：std::function 声明的结构

模板的参数定义了`variable`存储的目标的`function signature`。签名以返回类型开始（可以是 void），然后在括号内放置函数将被调用的类型列表。

使用自由函数和`std::function`的`functor`非常简单。只要签名与传递给`std::function`模板的参数匹配，我们就可以简单地将自由函数或`functor`等同于实例。

```cpp
void FreeFunc(int value);
struct Functor 
{
    void operator()(int value);
};
std::function<void(int)> func;
Functor functor;
func = FreeFunc;                     // Set target as FreeFunc
func(32);                            // Call FreeFunc with argument 32
func = functor;                      // set target as functor
func(42);                            // Call Functor::operator() with argument 42
```

但是，如果我们想要在对象实例上使用一个方法，那么我们需要使用另一个 STL 辅助模板`std::bind()`。如果我们运行以下程序：

```cpp
#include <iostream>
#include <functional>
struct Binder
{
    void method(int a, int b)
    {
        std::cout << "Binder::method(" << a << ", " << b << ")\n";
    }
};
int main()
{
    std::cout << "\n\n------ Member Functions using bind ------\n";
    Binder binder;
    std::function<void(int,int)> func;
    auto func1 = std::bind(&Binder::method, &binder, 1, 2);
    auto func2 = std::bind(&Binder::method, &binder, std::placeholders::_1, std::placeholders::_2);
    auto func3 = std::bind(&Binder::method, &binder, std::placeholders::_2, std::placeholders::_1);
    func = func1;
    func(34,56);
    func = func2;
    func(34,56);
    func = func3;
    func(34,56);
    std::cout << "Complete.\n";
    return 0;
}
```

然后我们得到以下输出：

![图 4.16：使用 std::bind()和 std::function 的程序输出](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_04_16.jpg)

###### 图 4.16：使用 std::bind()和 std::function 的程序输出

注意几点：

+   函数`method()`是使用类作为作用域限定符引用的；

+   `Binder`实例的地址作为第二个参数传递给`std::bind()`，这使其成为传递给`method()`的第一个参数。这是必要的，因为所有非静态成员都有一个隐式的`this`指针作为第一个参数传递。

+   使用`std::placeholders`定义，我们可以绑定调用绑定方法时使用的参数，甚至改变传递的顺序（如`func3`所示）。

C++11 引入了一些称为 lambda 表达式的语法糖，使得更容易定义匿名函数，还可以用于绑定方法并将它们分配给`std::function`实例表达式。我们将在*什么是 Lambda 表达式？*主题中更多地涵盖它。

### 练习 3：使用 std::function 实现回调

在这个练习中，我们将利用`std::function<>`模板实现函数回调。按照以下步骤实现这个练习：

1.  在 Eclipse 中打开**Lesson4**项目，然后在**Project Explorer**中展开**Lesson4**，然后展开**Exercise03**，双击**Exercise3.cpp**以将此练习的文件打开到编辑器中。

1.  由于这是一个基于 CMake 的项目，请将当前构建器更改为 CMake Build（便携式）。

1.  单击**启动配置**下拉菜单，然后选择**新启动配置…**。配置**L4Exercise3**以使用名称**Exercise3**运行。

1.  单击**运行**按钮。练习将运行并产生以下输出：![图 4.17：练习 3 输出（调用空的 std::function）](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_04_17.jpg)

###### 图 4.17：练习 3 输出（调用空的 std::function）

1.  我们要做的第一件事是防止调用空的`TestFunctionTemplate()`行`func(42);`，并用以下代码替换它：

```cpp
if (func)
{
    func(42);
}
else
{
    std::cout << "Not calling an empty func()\n";
}
```

1.  单击**运行**按钮。练习将运行并产生以下输出：![图 4.18：练习 3 输出（防止调用空的 std::function）](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_04_18.jpg)

###### 图 4.18：练习 3 输出（防止调用空的 std::function）

1.  在函数`TestFunctionTemplate()`之前的文件中添加`FreeFunction()`方法：

```cpp
void FreeFunction(int n)
{
    std::cout << "FreeFunction(" << n << ")\n";
}
```

1.  在`TestFunctionTemplate()`函数中，在`if (func)`之前立即添加以下行：

```cpp
func = FreeFunction;
```

1.  单击**运行**按钮。练习将运行并产生以下输出：![图 4.19：练习 3 输出（FreeMethod）](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_04_19.jpg)

###### 图 4.19：练习 3 输出（FreeMethod）

1.  在`TestFunctionTemplate()`函数之前添加新的类定义：

```cpp
struct FuncClass
{
    void member(int n)
    {
        std::cout << "FuncClass::member(" << n << ")\n";
    }
    void operator()(int n)
    {
    std::cout << "FuncClass object(" << n << ")\n";
    }
};
```

1.  用以下代码替换行`func = FreeFunction;`：

```cpp
FuncClass funcClass;
func = funcClass;
```

1.  单击**运行**按钮。练习将运行并产生以下输出：![4.20：练习 3 输出（对象函数调用覆盖）](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_04_20.jpg)

###### 4.20：练习 3 输出（对象函数调用覆盖）

1.  用以下代码替换行`func = funcClass;`：

```cpp
func = std::bind(&FuncClass::member, &funcClass, std::placeholders::_1);
```

1.  单击**运行**按钮。练习将运行并产生以下输出：![图 4.21：练习 3 输出（成员函数）](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_04_21.jpg)

###### 图 4.21：练习 3 输出（成员函数）

1.  用以下代码替换行`func = std::bind(…);`：

```cpp
func = [](int n) {std::cout << "lambda function(" << n << ")\n";};
```

1.  单击**运行**按钮。练习将运行并产生以下输出：

![图 4.22：练习 3 输出（lambda 函数）](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_04_22.jpg)

###### 图 4.22：练习 3 输出（lambda 函数）

在这个练习中，我们使用`std::function`模板实现了四种不同类型的函数回调-自由方法，类成员函数，类函数调用方法和 Lambda 函数（我们将在下面讨论）。

### 什么是 Lambda 表达式？

自 C++11 以来，C++支持`匿名函数`，也称为`lambda 表达式`或`lambda`。Lambda 表达式的两种最常见形式是：

![图 4.23：Lambda 表达式的最常见形式](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_04_23.jpg)

###### 图 4.23：Lambda 表达式的最常见形式

在正常情况下，编译器能够根据**function_body**中的返回语句推断 Lambda 的返回类型（如上图中的形式（1）所示）。然而，如果编译器无法确定返回类型，或者我们希望强制使用不同的类型，那么我们可以使用形式（2）。

[captures]之后的所有内容与普通函数定义相同，只是缺少名称。Lambda 是一种方便的方式，可以在将要使用的位置定义一个简短的方法（只有几行）。Lambda 通常作为参数传递，并且通常不会被重复使用。还应该注意，Lambda 可以分配给一个变量（通常使用 auto 声明）。

我们可以重新编写先前的程序，其中我们使用了`Scaler`类来使用 Lambda 来实现相同的结果：

```cpp
#include <iostream>
#include <vector>
#include <algorithm>
void PrintVector(const char* prefix, std::vector<int>& values)
{
    const char* sep = "";
    std::cout << prefix << " = [";
    for(auto n : values)
    {
        std::cout << sep << n;
        sep = ", ";
    }
    std::cout << "]\n";
}
int main()
{
    std::cout << "\n\n------ Lambdas with STL ------\n";
    std::vector<int> values{1,2,3,4,5};
    PrintVector("Before transform", values);
    std::transform(values.begin(), values.end(), values.begin(),
    [] (int n) {return 5*n;}
    );
    PrintVector("After transform", values);
    std::cout << "Complete.\n";
    return 0;
}
```

当此程序运行时，输出显示向量已被缩放了 5 倍：

![图 4.24：使用 lambda 进行缩放的转换](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_04_24.jpg)

###### 图 4.24：使用 lambda 进行缩放的转换

此程序中的 Lambda 是`[]（int n）{return 5*n;}`，并且具有空的捕获子句`[]`。空的捕获子句意味着 Lambda 函数不访问周围范围内的任何变量。如果没有参数传递给 Lambda，则参数子句`()`是可选的。

### 捕获数据到 Lambda 中

`operator()`。

捕获子句是零个或多个被捕获变量的逗号分隔列表。还有默认捕获的概念-通过引用或通过值。因此，捕获的基本语法是：

+   `[&]` - 通过引用捕获作用域内的所有自动存储期变量

+   `[=]` - 通过值捕获作用域内的所有自动存储期变量（制作副本）

+   `[&x, y]` - 通过引用捕获 x，通过值捕获 y

编译器将此转换为由匿名`functor`类的构造函数初始化的成员变量。在默认捕获（`&`和`=`）的情况下，它们必须首先出现，且仅捕获体中引用的变量。默认捕获可以通过在默认捕获后的捕获子句中放置特定变量来覆盖。例如，`[&，x]`将默认通过引用捕获除`x`之外的所有内容，它将通过值捕获`x`。

然而，默认捕获虽然方便，但并不是首选的捕获方法。这是因为它可能导致悬空引用（通过引用捕获和引用的变量在 Lambda 访问时不再存在）或悬空指针（通过值捕获，特别是 this 指针）。明确捕获变量更清晰，而且编译器能够警告您意外效果（例如尝试捕获全局或静态变量）。

C++14 引入了**init capture**到捕获子句，允许更安全的代码和一些优化。初始化捕获在捕获子句中声明一个变量，并初始化它以在 Lambda 内部使用。例如：

```cpp
int x = 5;
int y = 6;
auto fn = [z=x*x+y, x, y] ()
            {   
                std::cout << x << " * " << x << " + " << y << " = " << z << "\n"; 
            };
fn();
```

在这里，`z`在捕获子句中声明并初始化，以便可以在 Lambda 中使用。如果要在 Lambda 中使用 x 和 y，则它们必须分别捕获。如预期的那样，当调用 Lambda 时，它会产生以下输出：

```cpp
5 * 5 + 6 = 31
```

初始化捕获也可以用于将可移动对象捕获到 Lambda 中，或者如下所示复制类成员：

```cpp
struct LambdaCapture
{
  auto GetTheNameFunc ()
  {
    return [myName = myName] () { return myName.c_str(); };  
  }
  std::string myName;
};
```

这捕获了成员变量的值，并恰好给它相同的名称以在 lambda 内部使用。

默认情况下，lambda 是一个 const 函数，这意味着它不能改变按值捕获的变量的值。在需要修改值的情况下，我们需要使用下面显示的 lambda 表达式的第三种形式。

![图 4.25：另一种 lambda 表达式形式](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_04_25.jpg)

###### 图 4.25：另一种 lambda 表达式形式

在这种情况下，`specifiers`被`mutable`替换，告诉编译器我们想要修改捕获的值。如果我们不添加 mutable，并尝试修改捕获的值，那么编译器将产生错误。

### 练习 4：实现 Lambda

在这个练习中，我们将实现 lambda 以在 STL 算法的上下文中执行多个操作。按照以下步骤实现这个练习：

1.  在 Eclipse 中打开**Lesson4**项目，然后在**Project Explorer**中展开**Lesson4**，然后双击**Exercise04**，再双击**Exercise4.cpp**以将此练习的文件打开到编辑器中。

1.  由于这是一个基于 CMake 的项目，将当前构建器更改为 CMake Build（便携式）。

1.  单击**Launch Configuration**下拉菜单，选择**New Launch Configuration…**。配置**L4Exercise4**以使用名称**Exercise4**运行。

1.  单击**运行**按钮。练习将运行并产生以下输出：![图 4.26：练习 4 的初始输出](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_04_26.jpg)

###### 图 4.26：练习 4 的初始输出

1.  程序`PrintVector()`和`main()`。`PrintVector()`与我们在*什么是函数对象？*中介绍的版本相同。现在修改它以使用`std::for_each()`库函数和 lambda，而不是范围 for 循环。更新`PrintVector()`如下：

```cpp
void PrintVector(const char* prefix, std::vector<int>& values)
{
    const char* sep = "";
    std::cout << prefix << " = [";
    std::for_each(values.begin(), values.end(),
            [&sep] (int n)
            {
                std::cout << sep << n;
                sep = ", ";
            }
    );
    std::cout << "]\n";
}
```

1.  单击**运行**按钮，我们得到与之前相同的输出。

1.  检查 lambda，我们通过引用捕获了本地变量`sep`。从`sep`中删除`&`，然后单击**运行**按钮。这次编译失败，并显示以下错误：![图 4.27：由于修改只读变量而导致的编译失败](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_04_27.jpg)

###### 图 4.27：由于修改只读变量而导致的编译失败

1.  更改 lambda 声明以包括`mutable`修饰符：

```cpp
[sep] (int n) mutable
{
    std::cout << sep << n;
    sep = ", ";
}
```

1.  单击**运行**按钮，我们得到与之前相同的输出。

1.  但我们可以再进一步。从函数`PrintVector()`的声明中删除`sep`，并再次更改 lambda 以包括 init 捕获。编写以下代码来实现这一点：

```cpp
[sep = ""] (int n) mutable
{
    std::cout << sep << n;
    sep = ", ";
}
```

1.  单击`PrintVector()`，现在看起来更紧凑：

```cpp
void PrintVector(const char* prefix, std::vector<int>& values)
{
    std::cout << prefix << " = [";
    std::for_each(values.begin(), values.end(), [sep = ""] (int n) mutable
                                  { std::cout << sep << n; sep = ", ";} );
    std::cout << "]\n";
}
```

1.  在`main()`方法中调用`PrintVector()`之后，添加以下行：

```cpp
std::sort(values.begin(), values.end(), [](int a, int b) {return b<a;} );
PrintVector("After sort", values);
```

1.  单击**运行**按钮，现在的输出添加了按降序排序的值列表：![图 4.28：按降序排序 lambda 的程序输出](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_04_28.jpg)

###### 图 4.28：降序排序 lambda 的程序输出

1.  将 lambda 函数体更改为`{return a<b;}`。单击**运行**按钮，现在的输出显示值按升序排序：![图 4.29：按升序排序 lambda 的程序输出](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_04_29.jpg)

###### 图 4.29：按升序排序 lambda 的程序输出

1.  在调用`PrintVector()`函数之后，添加以下代码行：

```cpp
int threshold{25};
auto pred = [threshold] (int a) { return a > threshold; };
auto count = std::count_if(values.begin(), values.end(), pred);
std::cout << "There are " << count << " values > " << threshold << "\n";
```

1.  单击`值> 25`：![图 4.30：存储在变量中的 count_if lambda 的输出](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_04_30.jpg)

###### 图 4.30：存储在变量中的 count_if lambda 的输出

1.  在上述行之后添加以下行，并单击**运行**按钮：

```cpp
threshold = 40;
count = std::count_if(values.begin(), values.end(), pred);
std::cout << "There are " << count << " values > " << threshold << "\n";
```

以下输出将被生成：

![图 4.31：通过重用 pred lambda 产生的错误输出](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_04_31.jpg)

###### 图 4.31：通过重用 pred lambda 产生的错误输出

1.  程序错误地报告有`七（7）个值> 40`；应该是`三（3）`。问题在于当创建 lambda 并将其存储在变量`pred`中时，它捕获了阈值的当前值，即`25`。将定义`pred`的行更改为以下内容：

```cpp
auto pred = [&threshold] (int a) { return a > threshold; };
```

1.  单击**运行**按钮，现在输出正确报告计数：

![图 4.32：重用 pred lambda 的正确输出](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_04_32.jpg)

###### 图 4.32：重用 pred lambda 的正确输出

在这个练习中，我们使用 lambda 表达式语法的各种特性实现了几个 lambda，包括 init 捕获和 mutable。

#### 使用 lambda

虽然 lambda 是 C++的一个强大特性，但应该适当使用。目标始终是生成可读的代码。因此，虽然 lambda 可能很简短并且简洁，但有时将功能分解为一个命名良好的方法会更好以便于维护。

## 可变模板

在*第 2B 章*，*不允许鸭子-模板和推导*中，我们介绍了泛型编程和模板。在 C++03 之前的 C++中，模板一直是 C++的一部分。在 C++11 之前，模板的参数数量是有限的。在某些情况下，需要变量数量的参数，需要为所需参数数量的每个变体编写模板。或者，有像`printf()`这样可以接受可变数量参数的可变函数。可变函数的问题在于它们不是类型安全的，因为对参数的访问是通过`va_arg`宏进行类型转换。C++11 通过引入可变模板改变了这一切，其中一个模板可以接受任意数量的参数。C++17 通过引入`constexpr` if 结构改进了可变模板的编写，该结构允许基本情况模板与“递归”模板合并。

最好的方法是实现一个可变模板并解释它是如何工作的。

```cpp
#include <iostream>
#include <string>
template<typename T, typename... Args>
T summer(T first, Args... args) {
    if constexpr(sizeof...(args) > 0)
          return first + summer(args...);
    else
        return first;
}
int main()
{
    std::cout << "\n\n------ Variadic Templates ------\n";
    auto sum = summer(1, 3, 5, 7, 9, 11);
    std::cout << "sum = " << sum << "\n";
    std::string s1{"ab"};
    std::string s2{"cd"};
    std::string s3{"ef"};
    std::string strsum = summer(s1, s2, s3);
    std::cout << "strsum = " << strsum << "\n";
    std::cout << "Complete.\n";
    return 0;
}
```

当我们运行这个程序时，我们得到以下输出：

![图 4.33：可变模板程序输出](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_04_33.jpg)

###### 图 4.33：可变模板程序输出

那么，可变模板的部分是什么？我们如何阅读它？考虑上面程序中的模板：

```cpp
template<typename T, typename... Args>
T summer(T first, Args... args) {
    if constexpr(sizeof...(args) > 0)
        return first + summer(args...);
    else
        return first;
}
```

在上面的代码中：

+   `typename... Args` 声明 `Args` 为 `模板参数包`。

+   `Args... args`是一个`函数参数包`，其类型由`Args`给出。

+   `sizeof...(args)`返回`args`中包的元素数量。这是一种特殊形式的包扩展。

+   `args...`在对`summer()`的递归调用中展开了包。

或者，您可以将模板视为等效于：

```cpp
template<typename T, typename T1, typename T2, ..., typename Tn>
T summer(T first, T1 t1, T2, ..., Tn tn) {
    if constexpr(sizeof...( t1, t2, ..., tn) > 0)
        return first + summer(t1, t2, ..., tn);
    else
        return first;
}
```

当编译器处理样本程序中的`summer(1, 3, 5, 7, 9, 11)`时，它执行以下操作：

+   它推断`T`是 int，`Args...`是我们的参数包，带有<int, int, int, int, int>。

+   由于包中有多个参数，编译器生成了`first + summer(args...)`，省略号展开了模板参数，将`summer(args...)`转换为`summer(3,5,7,9,11)`。

+   然后编译器生成了`summer(3,5,7,9,11)`的代码。同样，应用了`first + summer(args...)`，其中`summer(5,7,9,11)`。

+   这个过程重复进行，直到编译器必须为`summer(11)`生成代码。在这种情况下，`constexpr` if 语句的 else 子句被触发，它简单地返回`first`。

由于类型由模板的参数确定，因此我们不限于参数具有相同的类型。我们已经在 STL 中遇到了一些可变模板-`std::function`和 std::bind。

还有另一种类型的可变模板，它将其参数转发到另一个函数或模板。这种类型的模板本身并不做太多事情，但提供了一种标准的方法。一个例子是`make_unique`模板，可以实现为：

```cpp
template<typename T, typename... Args>
unique_ptr<T> make_unique(Args&&... args)
{
    return unique_ptr<T>(new T(std::forward<Args>(args)...));
}
```

`make_unique`必须调用 new 运算符来分配内存，然后调用类型的适当构造函数。调用构造函数所需的参数数量可能会有很大的变化。这种形式的可变模板引入了一些额外的包扩展：

+   `Args&&...`表示我们有一系列转发引用。

+   `std::forward<Args>(args)...`包含要一起展开的参数包，必须具有相同数量的元素-Args 模板参数包和 args 函数参数包。

每当我们需要在可变参数模板中将一个函数调用转发到另一个函数调用时，就会使用这种模式。

### 活动 1：实现多播事件处理程序

1992 年，当 C++处于萌芽阶段时，微软首次引入了`Microsoft Foundation Class`（`MFC`）。这意味着许多围绕这些类的设计选择受到了限制。例如，事件的处理程序通常通过`OnEventXXX()`方法路由。这些通常使用宏配置为从 MFC 类派生的类的一部分。您的团队被要求使用模板来实现更像 C#中可用的委托的多播事件处理程序，这些模板体现了函数对象，并导致可变参数模板以实现可变参数列表。

在 C#中，您可以声明委托如下：

```cpp
delegate int Handler(int parameter);
```

这使得 Handler 成为一个可以分配值并进行调用的类型。这基本上就是 C++中`std::function<>`为我们提供的，除了能够进行多播。您的团队被要求开发一个模板类`Delegate`，可以像 C#委托一样进行操作。

+   Delegate 将接受“可变参数列表”，但只返回`void`

+   `operator+=`将用于向委托添加新的回调

+   它将使用以下语法之一进行调用：`delegate.Notify(…)`或`delegate(…)`

按照以下步骤开发 Delegate 模板：

1.  从**Lesson4/Activity01**文件夹加载准备好的项目，并为项目配置当前构建器为 CMake Build（Portable）。

1.  构建项目，配置启动器并运行单元测试（其中一个虚拟测试失败）。建议为测试运行器使用的名称是**L4delegateTests**。

1.  实现一个`Delegate`类，可以使用所有必需的方法包装单个处理程序，并支持回调的单个 int 参数。

1.  更新模板类以支持多播。

1.  将`Delegate`类转换为模板，可以接受定义回调函数使用的参数类型的单个模板参数。

1.  将`Delegate`模板转换为可变参数模板，可以接受零个或多个定义传递给回调函数的类型的参数。

按照上述步骤后，预期输出如下：

![图 4.34：Delegate 成功实现的输出](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_04_34.jpg)

###### 图 4.34：Delegate 成功实现的输出

#### 注意

此活动的解决方案可在第 673 页找到。

## 摘要

在本章中，我们实现了一种数据和方法隐藏的设计方法 PIMPL，它具有减少依赖关系和减少构建时间的附加好处。然后，我们直接将函数对象实现为自定义类，然后作为 lambda 函数。然后，我们通过深入研究可变参数模板来扩展我们的模板编程技能，最终实现了一个可用于事件回调处理的模板。在下一章中，我们将学习如何使用 C++的特性来开发具有多个线程的程序，并通过并发构造来管理它们的协作。


# 第六章：哲学家的晚餐——线程和并发

## 学习目标

在本章结束时，您将能够：

+   创建同步和异步多线程应用程序

+   应用同步处理数据危害和竞争条件

+   使用 C++线程库原语开发高效的多线程代码

+   使用移动语义创建线程以进行多线程闭包

+   使用 futures、promises 和 async 实现线程通信

在本章中，我们将澄清多线程编程中基本术语的区别，学习如何编写多线程代码，了解 C++标准库提供的数据访问同步资源，学习如何防止我们的代码遇到竞争条件和死锁。

## 介绍

在上一章中，我们涵盖了 C++中不同类型的依赖和耦合。我们看了一下如何在 C++中实现常见的 API 设计模式和习惯用法，以及标准库提供的数据结构及其效果。我们还学习了如何使用函数对象、lambda 和捕获。这些知识将帮助我们学习如何编写清晰和高效的多线程程序。

本章的标题包含了并发编程中最重要的同步问题的名称——哲学家的晚餐。简而言之，这个定义如下。

三位哲学家坐在圆桌旁，桌上有寿司碗。筷子放在每个相邻的哲学家之间。一次只有一个哲学家可以用两根筷子吃寿司。也许每个哲学家都会拿一根筷子，然后等待直到有人放弃另一根筷子。哲学家是三个工作进程的类比，筷子是共享资源。"谁会先拿起两根筷子"象征着**竞争条件**。当每个哲学家拿着一根筷子并等待另一根筷子可用时，就会导致**死锁**。这个类比解释了多线程期间出现的问题。

我们将从对主要多线程概念的简要介绍开始本章。我们将考虑同步、异步和线程执行之间的区别。通过清晰简单的例子，我们将从同步、数据危害和竞争条件开始。我们将找出它们为什么出现在我们的代码中以及我们如何管理它们。本章的下一部分专门讨论了用于线程执行的 C++标准库。通过示例，我们将学习如何以及何时使用线程库原语，以及**移动语义**如何与线程交互。我们还将练习使用**futures**、**promises**和**async**来从线程中接收结果。

本章将以一个具有挑战性的活动结束，我们将创建一个艺术画廊模拟器，通过模拟访客和画廊工作人员来工作。我们将开发一个多线程生成器，同时创建和移除艺术画廊的访客。接下来，我们将创建一个负责将访客带过画廊的多线程类。他们将使用同步技术相互交互。最后，我们将创建线程安全的存储，这些实例将从不同的线程中访问。

在下一节中，我们将澄清并发编程概念之间微妙的区别：**同步**、**异步**和**线程**执行。

## 同步、异步和线程执行

并发编程的概念之间存在微妙的区别：`同步`、`异步`和`线程执行`。为了澄清这一点，我们将从最基本的开始，从并发和并行程序的概念开始。

### 并发

`并发性`的概念不仅仅是同时执行多个任务。`并发性`并不指定如何实现同时性。它只表示在给定时间内将完成多个任务。任务可以是`依赖性的`，`并行的`，`同步的`或`异步的`。以下图表显示了并发工作的概念：

![图 5.1：并发性的抽象 - 一些人在同一台计算机上工作](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_05_01.jpg)

###### 图 5.1：并发性的抽象 - 一些人在同一台计算机上工作

在上图中，三个人同时在一台计算机上工作。我们对他们的工作方式不感兴趣，对于这个抽象层级来说并不重要。

### 并行性

**并行性**发生在多个任务同时执行时。由于硬件的能力，这些任务可以并行工作。最好的并行性示例是多核处理器。对于并行执行，任务被分成完全独立的子任务，这些子任务在不同的处理器核心上执行。之后，执行的结果可以被合并。看一下以下图表，以了解并行性的概念：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_05_02.jpg)

###### 图 5.2：并行性的抽象 - 所有任务都由不同的人执行；他们不相互交互

在上图中，有三个人同时在自己的计算机上工作 - 嗯，他们在并行工作。

#### 注意

`并发性`和`并行性`并不是一回事。`并行性`是对`并发性`的补充。它告诉我们任务是如何执行的：它们彼此独立，并在不同的计算单元上运行，也就是处理器或核心。

现在，我们将平稳地过渡到线程执行的概念。当我们谈论线程时，我们指的是执行线程。这是操作系统的一个抽象，它允许我们同时执行多个任务。请记住，整个程序在一个单独的进程中执行。操作系统分配`main()`函数。我们可以创建一个新的线程来执行，并分配一个开始函数，这将是这个线程的起始点。

#### 注意

处理器的地址空间和寄存器被称为**线程上下文**。当操作系统中断线程的工作时，它必须存储当前线程的上下文并加载下一个线程的上下文。

让我们考虑以下示例中的新线程的创建。要创建一个新线程，我们必须包含`<thread>`头文件。它包含了用于管理线程的类和函数。实际上，有几种可能的方法来创建一个`std::thread`对象和线程执行，如下所示：

+   创建一个没有显式初始化的`std::thread`对象。记住，线程需要一个启动函数来运行它的工作。我们没有指出哪个函数是这个线程的主要函数。这意味着执行线程没有被创建。让我们看一下以下代码示例，其中我们创建一个空的`std::thread`对象：

```cpp
#include <thread>
int main()
{
  std::thread myThread;  
  return 0;
}
```

+   创建一个`std::thread`对象，并将一个指向函数的指针作为构造函数参数传递。现在，执行线程将被创建，并将从我们在构造函数中传递的函数开始执行其工作。让我们看一下以下代码示例：

```cpp
#include <iostream>
#include <thread>
void printHello()
{
    std::cout << "hello" << std::endl;
}
int main()
{
  std::thread myThread(printHello);
  myThread.join();
  return 0;
}
```

在这里，我们创建了一个`std::thread`对象，并用函数指针进行了初始化。这是一个简单的返回`void`并且不带任何参数的函数。然后，我们告诉主线程等待直到新线程完成，使用`join()`函数。我们总是必须在`std::thread`对象的作用域结束之前`join()`或`detach()`一个线程。如果不这样做，我们的应用程序将被操作系统使用`std::terminate()`函数终止，该函数在`std::thread`析构函数中被调用。除了函数指针，我们还可以传递任何可调用对象，如`lambda`，`std::function`或具有重载的`operator()`的类。

#### 注意

执行线程可以在`std::thread`对象销毁之前完成其工作。它也可以在执行线程完成其工作之前被销毁。在销毁`std::thread`对象之前，始终要`join()`或`detach()`它。

现在我们知道了创建线程的主要语法，我们可以继续了解下一个重要概念。让我们找出同步、异步和多线程执行的含义。

### 同步执行

同步执行这个术语意味着每个子任务将按顺序依次执行。换句话说，这意味着如果我们有几个任务要执行，每个任务只能在前一个任务完成工作后才能开始工作。这个术语并没有指定执行任务的方式，或者它们是否将在单个线程或多个线程中执行。它只告诉我们执行顺序。让我们回到哲学家晚餐的例子。在单线程世界中，哲学家们将依次进餐。

第一个哲学家拿起两根筷子吃寿司。然后，第二个哲学家拿起两根筷子吃寿司。他们轮流进行，直到所有人都吃完寿司。看一下以下图表，它表示了在单个线程中同步执行四个任务：

![图 5.3：单线程中的同步执行](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_05_03.jpg)

###### 图 5.3：单线程中的同步执行

在这里，每个任务都等待前一个任务完成。任务也可以在多个线程中同步执行。考虑以下图表，它表示了在多个线程中同步执行四个任务。同样，每个任务都等待前一个任务完成：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_05_04.jpg)

###### 图 5.4：多线程中的同步执行

在这种情况下，每个任务在单独的线程中启动，但只有在前一个线程完成其工作后才能启动。在多线程世界中，哲学家们仍然会依次进餐，但有一个小区别。现在，每个人都有自己的筷子，但只能按严格的顺序进餐。

#### 注意

同步执行意味着每个任务的完成时间是同步的。任务的执行顺序是重点。

让我们考虑以下代码示例中的同步执行。当我们在单个线程中运行任务时，我们只需调用通常的函数。例如，我们实现了四个打印消息到终端的函数。我们以同步的单线程方式运行它们：

```cpp
#include <iostream>
void printHello1()
{
    std::cout << "Hello from printHello1()" << std::endl;    
}
void printHello2()
{
    std::cout << "Hello from printHello2()" << std::endl;    
}
void printHello3()
{
    std::cout << "Hello from printHello3()" << std::endl;    
}
void printHello4()
{
    std::cout << "Hello from printHello4()" << std::endl;    
}
int main()
{
    printHello1();
    printHello2();
    printHello3();
    printHello4();
    return 0;
}
```

在这里，我们依次调用所有函数，每个下一个函数在前一个函数执行完之后运行。现在，让我们在不同的线程中运行它们：

```cpp
#include <iostream>
#include <thread>
void printHello1()
{
    std::cout << "Hello from printHello1()" << std::endl;    
}
void printHello2()
{
    std::cout << "Hello from printHello2()" << std::endl;    
}
void printHello3()
{
    std::cout << "Hello from printHello3()" << std::endl;    
}
void printHello4()
{
    std::cout << "Hello from printHello4()" << std::endl;    
}
int main()
{
    std::thread thread1(printHello1);
    thread1.join();
    std::thread thread2(printHello2);
    thread2.join();
    std::thread thread3(printHello3);
    thread3.join();
    std::thread thread4(printHello4);
    thread4.join();
    return 0;
}
```

在前面的代码示例中，我们创建了四个线程并立即加入它们。因此，每个线程在运行之前都完成了它的工作。正如你所看到的，对于任务来说没有任何变化-它们仍然按严格的顺序执行。

### 异步执行

这是一种几个任务可以同时执行而不阻塞任何线程执行的情况。通常，主线程启动异步操作并继续执行。执行完成后，结果被发送到主线程。通常，执行异步操作与为其创建一个单独的线程无关。任务可以由其他人执行，比如另一个计算设备、远程网络服务器或外部设备。让我们回到哲学家晚餐的例子。

在`异步执行`的情况下，所有的哲学家都有自己的筷子，可以独立地进餐。当寿司准备好并且服务员端上来时，他们都开始进餐，并且可以按照自己的时间完成。

#### 注意

在`异步执行`中，所有任务相互独立工作，知道每个任务的完成时间并不重要。

看一下以下图表，它表示了在多个线程中异步执行四个任务：

![图 5.5：多线程中的异步执行](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_05_05.jpg)

###### 图 5.5：多线程中的异步执行

它们每一个都在不同的时间开始和结束。让我们用一个代码示例来考虑这种异步执行。例如，我们实现了四个打印消息到终端的函数。我们在不同的线程中运行它们：

```cpp
#include <iostream>
#include <thread>
#include <chrono>
void printHello1()
{
    std::cout << "Hello from thread: " << std::this_thread::get_id() << std::endl;    
}
void printHello2()
{
    std::cout << "Hello from thread: " << std::this_thread::get_id() << std::endl;    
}
void printHello3()
{
    std::cout << "Hello from thread: " << std::this_thread::get_id() << std::endl;    
}
void printHello4()
{
    std::cout << "Hello from thread: " << std::this_thread::get_id() << std::endl;    
}
int main()
{
    std::thread thread1(printHello1);
    std::thread thread2(printHello2);
    std::thread thread3(printHello3);
    std::thread thread4(printHello4);
    thread1.detach();
    thread2.detach();
    thread3.detach();
    thread4.detach();

    using namespace std::chrono_literals;
    std::this_thread::sleep_for(2s);
    return 0;
}
```

让我们看看这里发生了什么。我们使用了前面示例中的四个函数，但它们稍作了修改。我们通过使用`std::this_thread::get_id()`函数添加了线程的唯一 ID 的打印。这个函数返回`std::thread::id`对象，表示线程的唯一 ID。这个类有重载的操作符用于输出和比较，所以我们可以以不同的方式使用它。例如，我们可以检查线程 ID，如果是主线程的 ID，我们可以执行特殊的任务。在我们的示例中，我们可以将线程 ID 打印到终端上。接下来，我们创建了四个线程并将它们分离。这意味着没有线程会等待其他线程完成工作。从这一刻起，它们成为**守护线程**。

它们将继续它们的工作，但没有人知道。然后，我们使用了`std::this_thread::sleep_for(2s)`函数让主线程等待两秒。我们这样做是因为当主线程完成它的工作时，应用程序会停止，我们将无法在终端上查看分离线程的输出。下面的截图是终端输出的一个例子：

![图 5.6：示例执行的结果](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_05_06.jpg)

###### 图 5.6：示例执行的结果

在你的 IDE 中，输出可能会改变，因为执行顺序是不确定的。异步执行的一个现实例子可以是一个互联网浏览器，在其中你可以打开多个标签页。当打开一个新标签页时，应用程序会启动一个新线程并将它们分离。虽然线程工作是独立的，但它们可以共享一些资源，比如文件处理程序，用于写日志或执行其他操作。

#### 注意

`std::thread`有一个成员函数叫做`get_id()`，它返回`std::thread`实例的唯一 ID。如果`std::thread`实例没有初始化，或者已经加入或分离，`get_id()`会返回一个默认的`std::thread::id`对象。这意味着当前`std::thread`实例没有与任何执行线程相关联。

让我们用一些伪代码来展示一个例子，其中计算由另一个计算单元完成。例如，假设我们开发了一个应用程序，用于进行货币兑换的计算。用户输入一种货币的金额，选择另一种货币进行兑换，应用程序会显示他们在那种货币中的金额。在后台，应用程序向保存所有货币兑换率的远程服务器发送请求。

远程服务器计算给定货币的金额并将结果返回。您的应用程序在那时显示一个进度条，并允许用户执行其他操作。当它收到结果时，它会在窗口上显示它们。让我们看一下下面的代码：

```cpp
#include <thread>
void runMessageLoop()
{
    while (true)
    {
        if (message)
        {
            std::thread procRes(processResults, message);
            procRes.detach();
        }
    }
}
void processResults(Result res)
{
    display();
}
void sendRequest(Currency from, Currency to, double amount)
{
    send();
}
void displayProgress()
{
}
void getUserInput()
{
    Currency from;
    Currency to;
    double amount;
    std::thread progress(displayProgress);
    progress.detach();
    std::thread request(sendRequest, from, to, amount);
    request.detach();
}
int main()
{
    std::thread messageLoop(runMessageLoop);
    messageLoop.detach();

    std::thread userInput(getUserInput);
    userInput.detach();    
    return 0;
}
```

让我们看看这里发生了什么。在`main()`函数中，我们创建了一个名为`messageLoop`的线程，执行`runMessageLoop()`函数。可以在这个函数中放置一些代码，检查是否有来自服务器的新结果。如果收到新结果，它会创建一个新线程`procRes`，该线程将在窗口中显示结果。我们还在`main()`函数中创建了另一个线程`userInput`，它从用户那里获取货币和金额，并创建一个新线程`request`，该线程将向远程服务器发送请求。发送请求后，它创建一个新线程`progress`，该线程将显示一个进度条，直到收到结果。由于所有线程都被分离，它们能够独立工作。当然，这只是伪代码，但主要思想是清楚的-我们的应用程序向远程服务器发送请求，远程服务器为我们的应用程序执行计算。

让我们回顾一下我们通过日常生活中的一个例子学到的并发概念。这是一个背景，在这个背景中，您需要编写一个应用程序，并提供与之相关的所有文档和架构概念：

+   单线程工作：您自己编写。

+   多线程工作：您邀请朋友一起编写项目。有人编写架构概念，有人负责文档工作，您专注于编码部分。所有参与者彼此沟通，以澄清任何问题并共享文档，例如规格问题。

+   并行工作：任务被分开。有人为项目编写文档，有人设计图表，有人编写测试用例，您独立工作。参与者之间根本不沟通。

+   同步工作：在这种情况下，每个人都无法理解他们应该做什么。因此，您决定依次工作。当架构工作完成时，开发人员开始编写代码。然后，当开发工作完成时，有人开始编写文档。

+   异步工作：在这种情况下，您雇佣了一个外包公司来完成项目。当他们开发项目时，您将从事其他任务。

现在，让我们将我们学到的知识应用到实践中，并解决一个练习，看看它是如何工作的。

### 练习 1：以不同的方式创建线程

在这个练习中，我们将编写一个简单的应用程序，创建四个线程；其中两个将以同步方式工作，另外两个将以异步方式工作。它们都将向终端打印一些符号，以便我们可以看到操作系统如何切换线程执行。

#### 注意

在项目设置中添加 pthread 链接器标志，以便编译器知道您将使用线程库。对于 Eclipse IDE，您可以按照以下路径操作：`Eclipse 版本：3.8.1`，不同版本可能会有所不同。

完成此练习，执行以下步骤：

1.  包括一些用于线程支持的头文件，即`<thread>`，流支持，即`<iostream>`，和函数对象支持，即`<functional>`：

```cpp
#include <iostream>
#include <thread>
#include <functional>
```

1.  实现一个名为`printNumbers()`的自由函数，在`for`循环中打印 0 到 100 的数字：

```cpp
void printNumbers()
{
    for(int i = 0; i < 100; ++i)
    {
        std::cout << i << " ";
    }
    std::cout << std::endl;
}
```

1.  实现一个可调用对象，即一个具有重载的`operator()`的`Printer`类，它在`for`循环中从 0 到 100000 打印一个"*"符号。每 200 次迭代，打印一个新行符号，以获得更可读的输出：

```cpp
class Printer
{
    public:
    void operator()()
    {
        for(int i = 0; i < 100000; ++i)
        {
            if (!(i % 200))
            {
                std::cout << std::endl;
            }
            std::cout << "*";
        }
    }
};
```

1.  进入`main()`函数，然后创建一个名为`printRevers`的 lambda 对象，在`for`循环中打印 100 到 0 的数字：

```cpp
int main()
{
    auto printRevers = []()
    {
        for(int i = 100; i >= 0; --i)
        {
            std::cout << i << " ";
        }
        std::cout << std::endl;
    };
    return 0;
}
```

1.  实现一个名为`printOther`的`std::function`对象，它在`for`循环中从`0`到`100000`打印一个"^"符号。每 200 次迭代，打印一个新行符号，以获得更可读的输出：

```cpp
std::function<void()> printOther = []()
{
    for(int i = 0; i < 100000; ++i)
    {
        if (!(i % 200))
        {
            std::cout << std::endl;
        }
        std::cout << "^";
    }
};
```

1.  创建第一个线程`thr1`，并将`printNumbers`自由函数传递给其构造函数。加入它：

```cpp
std::thread thr1(printNumbers);
thr1.join();
```

1.  创建第二个线程`thr2`，并将`printRevers` lambda 对象传递给其构造函数。加入它：

```cpp
std::thread thr2(printRevers);
thr2.join();
```

1.  创建一个名为`print`的`Printer`类的实例。创建第三个线程`thr3`，并用`print`对象初始化它。使用`detach()`方法将其分离：

```cpp
Printer print;
std::thread thr3(print);
thr3.detach();
```

1.  创建最后一个线程`thr4`，并用`printOther`对象初始化它。分离它：

```cpp
std::thread thr4(printOther);
thr4.detach();
```

1.  在`main()`函数退出之前添加`std::getchar()`函数调用。这样可以避免关闭应用程序。我们将有可能看到分离的线程是如何工作的：

```cpp
std::getchar();
```

1.  在编辑器中运行此代码。您将看到`thr1`开始执行，程序等待。`thr1`完成后，`thr2`开始执行，程序等待。这是同步执行的一个例子。`thr2`完成工作后，线程`thr3`和`thr4`开始执行。它们被分离，所以程序可以继续执行。在下面的输出中，您将看到符号混合。这是因为操作系统执行中断，线程同时工作。

你的输出将类似于以下内容：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_05_07.jpg)

###### 图 5.7：练习执行的结果

在这个练习中，我们实现了四种不同的初始化线程的方式：使用自由函数、使用 lambda 对象、使用可调用对象和使用`std::function`对象。还有一些更多的初始化线程的方式，但我们将在下一节中考虑它们。我们还回顾了如何在多个线程中实现同步程序。我们还尝试实现了异步程序，并看到线程确实可以同时独立地工作。在下一节中，我们将学习数据危害和竞争条件，以及如何通过使用同步技术来避免它们。

## 回顾同步、数据危害和竞争条件

多线程编程的关键挑战是了解线程如何处理**共享数据**。共享数据，也称为资源，不仅是变量，还包括文件描述符和环境变量，甚至是 Windows 注册表。例如，如果线程只是读取数据，那么就没有问题，也不需要同步。但是，如果至少有一个线程编辑数据，就可能出现**竞争条件**。通常，对数据的操作不是原子的，也就是说，它们需要几个步骤。即使是对数字变量的最简单的增量操作也是在以下三个步骤中完成的：

1.  读取变量的值。

1.  增加它。

1.  写入新值。

由于操作系统的中断，线程在完成操作之前可能会被停止。例如，我们有线程 A 和 B，并且有一个等于 0 的变量。

线程 A 开始增量：

1.  读取变量的值（var = 0）。

1.  增加它（tmp = 1）。

1.  被操作系统中断。

线程 B 开始增量：

1.  读取变量的值（var = 0）。

1.  增加它（tmp = 1）。

1.  写入新值（var = 1）。

1.  被操作系统中断。

线程 A 继续增量：

1.  写入新值（var = 1）。

因此，我们期望在工作完成后变量等于 2，但实际上它等于 1。看一下下面的图表，以更好地理解这个例子：

![图 5.8：两个线程增加相同的共享变量](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_05_08.jpg)

###### 图 5.8：两个线程增加相同的共享变量

让我们回到哲学家的晚餐类比。最初的问题是一个哲学家只有一根筷子。如果他们都饿了，那么他们会赶紧抓起两根筷子。第一个抓起两根筷子的哲学家将第一个吃饭，其他人必须等待。他们会争夺筷子。

现在，让我们将我们的知识应用到实践中，并编写一些代码，看看竞争条件如何出现在我们的代码中，并且如何损害我们的数据。

### 练习 2：编写竞争条件示例

在这个练习中，我们将编写一个简单的应用程序，演示竞争条件的实际情况。我们将创建一个经典的“检查然后执行”竞争条件的例子。我们将创建一个线程，执行两个数字的除法。我们将通过引用传递这些数字。在检查后，如果被除数等于 0，我们将设置一个小的超时。此时在主线程中，我们将将被除数设置为 0。当子线程醒来时，它将执行除以 0 的操作。这将导致应用程序崩溃。我们还将添加一些日志来查看执行流程。

#### 注意

默认情况下，当变量传递给线程时，所有变量都会被复制。要将变量作为引用传递，请使用`std::ref()`函数。

首先，我们实现没有竞争条件的代码，并确保它按预期工作。执行以下步骤：

1.  包括线程支持的头文件，即`<thread>`，流支持的头文件，即`<iostream>`，和函数对象支持的头文件，即`<functional>`：

```cpp
#include <iostream>
#include <chrono>
#include <thread>
```

1.  实现一个`divide()`函数，执行两个整数的除法。通过引用传递`divisor`和`dividend`变量。检查被除数是否等于 0。然后，添加日志：

```cpp
void divide(int& divisor, int& dividend)
{
    if (0 != dividend)
    {
        std::cout << "Dividend = " << dividend << std::endl;
        std::cout << "Result: " << (divisor / dividend) << std::endl;    
    }
    else
    {
        std::cout << "Error: dividend = 0" << std::endl;
    }
}
```

1.  进入`main()`函数，创建两个名为`divisor`和`dividend`的整数，并用任意非零值初始化它们：

```cpp
int main()
{
    int divisor = 15;
    int dividend = 5;
    return 0;
}
```

1.  创建`thr1`线程，传递`divide`函数，使用引用传递`divisor`和`dividend`，然后分离线程：

```cpp
std::thread thr1(divide, std::ref(divisor), std::ref(dividend));
thr1.detach();
std::getchar();
```

#### 注意

在`std::this_thread`命名空间中有一个名为`sleep_for`的函数，它可以阻塞线程一段时间。作为参数，它采用`std::chrono::duration` - 一个表示时间间隔的模板类。

1.  在编辑器中运行此代码。您将看到`divide()`函数在`thr1`中正常工作。输出如下所示：![图 5.9：正确练习执行的结果](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_05_09.jpg)

###### 图 5.9：正确练习执行的结果

现在，我们将继续进行更改，以演示竞争条件。

1.  返回函数，并在`if`条件后为子线程设置睡眠时间为`2s`。添加日志：

```cpp
if (0 != dividend)
{
    std::cout << "Child thread goes sleep" << std::endl;
    using namespace std::chrono_literals;
    std::this_thread::sleep_for(2s);
    std::cout << "Child thread woke up" << std::endl;
    std::cout << "Dividend = " << dividend << std::endl;
    std::cout << (divisor / dividend) << std::endl;
}
```

1.  返回`main()`函数，将主线程的睡眠时间设置为`1s`。之后，将`dividend`变量设置为`0`。添加日志：

```cpp
std::cout << "Main thread goes sleep" << std::endl;
using namespace std::chrono_literals;
std::this_thread::sleep_for(1s);
std::cout << "Main thread woke up" << std::endl;
dividend = 0;   
std::cout << "Main thread set dividend to 0" << std::endl;
```

#### 注意

`std::chrono_literals`命名空间包含时间表示的字面量：``h``表示`小时`，``min``表示`分钟`，``s``表示`秒`，``ms``表示`毫秒`，``us``表示`微秒`，``ns``表示`纳秒`。要使用它们，只需将它们添加到数字的末尾，例如，1s，1min，1h 等。

1.  在`main()`函数退出之前添加`std::getchar()`函数调用。这样可以避免关闭应用程序，我们将有可能看到分离线程的工作方式：

```cpp
std::getchar();
```

1.  在编辑器中运行此代码。您将看到主线程睡眠了`1s`。然后，子线程进入`if`条件并睡眠了`2s`，这意味着它验证了`dividend`并且不等于`0`。然后，主线程醒来并将`dividend`变量设置为 0。然后，子线程醒来并执行除法。但是因为`dividend`现在等于`0`，应用程序崩溃了。如果在调试模式下运行此示例，您将看到一个带有消息“算术异常”的`SIGFPE 异常`。您将得到以下输出：

![图 5.10：带有竞争条件的练习执行结果](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_05_10.jpg)

###### 图 5.10：带有竞争条件的练习执行结果

在这个练习中，我们考虑了“检查然后执行”类型的竞争条件。我们设置了线程的睡眠时间来模拟操作系统的中断，但在现实世界的程序中，这种情况可能会发生，也可能不会。这完全取决于操作系统及其调度程序。这使得调试和修复竞争条件变得非常困难。为了避免这个例子中的竞争条件，我们可以采取一些措施：

+   将变量的副本传递给线程函数，而不是传递引用。

+   使用标准库原语在线程之间同步对共享变量的访问。

+   在主线程将“被除数”值更改为 0 之前，先加入子线程。

让我们看看修复这种竞争条件的几种方法。所有这些方法都取决于您尝试实现的任务。在下一节中，我们将考虑 C++标准库提供的同步原语。

### 数据危害

之前，我们考虑了最无害的例子，但有时会出现数据损坏的情况，这会导致未定义的程序行为或异常终止。由于竞争条件或简单的错误设计而导致的数据损坏，通常称为数据危害。一般来说，这个术语意味着一项工作的最终结果取决于线程执行的顺序。如果不同的线程使用共享数据或全局变量，可能会由于不同线程的任务执行顺序不正确，导致结果不断变化。这是由于多线程数据之间的依赖关系。这种依赖问题被有条件地分为三组：

+   一个真依赖：写入后读取（RAW）

+   一个反依赖：读取后写入（WAR）

+   一个输出依赖：写入后写入（WAW）

### 原始数据依赖

当一个线程计算另一个线程使用的值时，就会发生原始数据依赖。例如，“线程 A”应该完成其工作并将结果写入一个变量。 “线程 B”必须读取此变量的值并完成其工作。在伪代码中，这看起来如下：

```cpp
Thread A: a = doSomeStuff();
Thread B: b = a - doOtherStuff();
```

如果“线程 B”先执行，将会出现困难。这将导致“线程 B”读取无效值。线程的执行顺序应该严格保证。“线程 B”必须在“线程 A”写入变量后才能读取其值。否则，将导致未定义的行为。以下图表将帮助您澄清导致数据危害的原始数据依赖：

![图 5.11：两个线程之间的原始数据依赖](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_05_11.jpg)

###### 图 5.11：两个线程之间的原始数据依赖关系

### WAR 依赖

“线程 A”必须读取一个变量的值并完成其工作。之后，“线程 B”应该完成其工作并将结果写入一个变量。在伪代码中，这看起来如下：

```cpp
Thread A: b = a - doSomeStuff();
Thread B: a = doOtherStuff();
```

如果“线程 B”先执行，将会出现困难。这将导致“线程 B”在“线程 A”读取之前更改值。线程的执行顺序应该严格保证。“线程 B”应该在“线程 A”读取其值后才将新值写入变量。以下图表将帮助您澄清导致数据危害的原始数据依赖：

![图 5.12：两个线程之间的 WAR 数据依赖](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_05_12.jpg)

###### 图 5.12：两个线程之间的 WAR 数据依赖

### WAW 依赖

“线程 A”执行其工作并将结果写入一个变量。 “线程 B”读取变量的值并执行其工作。 “线程 C”执行其工作并将结果写入相同的变量。在伪代码中，这看起来如下：

```cpp
Thread A: a = doSomeStuff();
Thread B: b = a - doOtherStuff();
Thread C: a = doNewStuff();
```

如果“线程 C”在 A 和 B 线程之前执行，将会出现困难。这将导致“线程 B”读取不应该读取的值。线程的执行顺序应该严格保证。“线程 C”必须在“线程 A”写入其值并且“线程 B”读取其值后才能将新值写入变量。以下图表将帮助您澄清导致数据危害的 WAW 数据依赖：

![图 5.13：两个线程之间的 WAW 数据依赖](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_05_13.jpg)

###### 图 5.13：两个线程之间的 WAW 数据依赖

### 资源同步

为了防止竞争和数据危害，有一个共享数据锁定机制，其中一个流意图更改或读取这些数据。这种机制称为`临界区`。同步包括在一个线程进入临界区时阻塞临界区。也意图执行此临界区代码的其他线程将被阻塞。当执行临界区的线程离开时，锁将被释放。然后，故事将在下一个线程中重复。

考虑前面的例子，其中有一个增量，但现在是同步访问。记住我们有线程 A 和 B，并且有一个变量等于 0。

线程 A 开始增加：

1.  进入临界区并锁定它。

1.  读取变量的值（var = 0）。

1.  增加它（tmp = 1）。

1.  被操作系统中断。

线程 B 开始增加：

1.  尝试进入临界区；它被锁定，所以线程正在等待。

线程 A 继续增加：

1.  写入新值（var = 1）。

线程 B 继续增加：

1.  进入临界区并锁定它。

1.  读取变量的值（var = 1）。

1.  增加它（tmp = 2）。

1.  写入新值（var = 2）。

在两个线程完成后，变量包含正确的结果。因此，同步确保了共享数据不会被破坏。看一下以下图表，以更好地理解这个例子：

![图 5.14：两个线程以同步的方式增加相同的共享变量](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_05_14.jpg)

###### 图 5.14：两个线程以同步的方式增加相同的共享变量

突出显示临界区并预期非同步访问可能造成的后果是一项非常困难的任务。因为过度同步会否定多线程工作的本质。如果两个或三个线程在一个临界区上工作得相当快，然而，在程序中可能有数十个线程，它们都将在临界区中被阻塞。这将大大减慢程序的速度。

### 事件同步

还有另一种同步线程工作的机制-`线程 A`，它从另一个进程接收消息。它将消息写入队列并等待新消息。还有另一个线程，`线程 B`，它处理这些消息。它从队列中读取消息并对其执行一些操作。当没有消息时，`线程 B`正在睡眠。当`线程 A`接收到新消息时，它唤醒`线程 B`并处理它。以下图表清楚地说明了两个线程的事件同步：

![图 5.15：两个线程的事件同步](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_05_15.jpg)

###### 图 5.15：两个线程的事件同步

然而，即使在同步代码中也可能出现另一个竞争条件的原因-类的缺陷接口。为了理解这是什么，让我们考虑以下例子：

```cpp
class Messages
{
    public:
    Messages(const int& size)
    : ArraySize(size)
    , currentIdx(0)
    , msgArray(new std::string[ArraySize])
    {}
    void push(const std::string& msg)
    {
        msgArray[currentIdx++] = msg;
    }
    std::string pop()
    {
        auto msg = msgArray[currentIdx - 1];
        msgArray[currentIdx - 1] = "";
        --currentIdx;
        return msg;
    }
    bool full()
    {
        return ArraySize == currentIdx;
    }
    bool empty()
    {
        return 0 == currentIdx;
    }
    private:
    const int ArraySize;
    int currentIdx;
    std::string * msgArray;
};
```

在这里，我们有一个名为`Messages`的类，它有一个动态分配的字符串数组。在构造函数中，它接受数组的大小并创建给定大小的数组。它有一个名为`full()`的函数，如果数组已满则返回`true`，否则返回`false`。它还有一个名为`empty()`的函数，如果数组为空则返回`true`，否则返回`false`。在推送新值之前和弹出数组中的新值之前，用户有责任检查数组是否已满并检查数组是否为空。这是一个导致竞争条件的类的糟糕接口的例子。即使我们用锁保护`push()`和`pop()`函数，竞争条件也不会消失。让我们看一下使用`Messages`类的以下示例：

```cpp
int main()
{
    Messages msgs(10);
    std::thread thr1([&msgs](){
    while(true)
    {
        if (!msgs.full())
        {
            msgs.push("Hello");
        }
        else
        {
            break;
        }
    }});
    std::thread thr2([&msgs](){
    while(true)
    {
        if (!msgs.empty())
        {
            std::cout << msgs.pop() << std::endl;
        }
        else
        {
            break;
        }
    }});
    thr1.detach();
    thr2.detach();
    using namespace std::chrono_literals;
    std::this_thread::sleep_for(2s);
    return 0;
}
```

在这里，我们创建了一个`msgs`变量，然后创建了第一个线程，该线程将值推送到`msgs`。然后，我们创建了第二个线程，该线程从数组中弹出值并将它们分离。即使我们使用锁定机制保护了所有函数，其中一个线程仍然可以检查数组的大小，并可能被操作系统中断。此时，另一个线程可以更改数组。当第一个线程继续工作时，它可能会尝试向满数组推送或从空数组中弹出。因此，同步只在与良好设计配对时才有效。

### 死锁

还有一个同步问题。让我们回到哲学家晚餐的例子。最初的问题是一个哲学家只有一根筷子。所以，他们可以通过彼此共享筷子一个接一个地吃寿司。虽然他们要花很长时间才能吃完寿司，但他们都会吃饱。但是，如果每个人同时拿起一根筷子，又不想分享第二根筷子，他们就无法吃到寿司，因为每个人都将永远等待第二根筷子。这会导致**死锁**。当两个线程等待另一个线程继续执行时，就会发生死锁。死锁的一个原因是一个线程加入另一个线程，而另一个线程加入第一个线程。因此，当两个线程都加入对方时，它们都无法继续执行。让我们考虑以下死锁的例子：

```cpp
#include <thread>
std::thread* thr1;
std::thread* thr2;
void someStuff()
{
    thr1->join();
}
void someAnotherStuff()
{
    thr2->join();
}
int main()
{
    std::thread t1(someStuff); 
    std::thread t2(someAnotherStuff);
    thr1 = &t1;
    thr2 = &t2;
    using namespace std::chrono_literals;
    std::this_thread::sleep_for(2s);
    return 0;
}
```

在主函数中，我们有两个线程`t1`和`t2`。我们使用`someStuff()`函数初始化了`t1`线程，该函数执行一些有用的工作。我们还使用`someAnotherStuff()`函数初始化了`t2`线程，该函数执行更多有用的工作。我们有这些线程的全局指针，并且在由`t2`执行的函数中有一个指向`t1`线程的加入指针。我们还在由`t1`执行的函数中加入了一个指向`t2`线程的指针。通过这样做，它们相互加入。这导致了死锁。

在下一节中，我们将考虑 C++线程库原语用于同步和死锁的另一个原因。

### 多线程闭包的移动语义

`std::thread`类不能被复制，但是如果我们想要存储几个线程，或者可能是 10 个或 20 个呢？当然，我们可以创建这些线程的数量，然后像这样加入或分离它们：

```cpp
std::thread thr1(someFunc);
std::thread thr2(someFunc);
std::thread thr3(someFunc);
std::thread thr4(someFunc);
std::thread thr5(someFunc);
thr1.join();
thr2.join();
thr3.join();
thr4.join();
thr5.join();
```

但是更方便的是将一堆线程存储在**STL 容器**中，例如线程的向量：

```cpp
std::vector<std::thread> threads;
```

不支持`std::move()`函数的对象不能与 STL 容器一起使用。要在容器中初始化线程，我们可以像下面这样做：

```cpp
for (int i = 0; i < 10; i++) 
{
    auto t = std::thread([i]()
    {
        std::cout << "thread: " << i << "\n";
    });
    threads.push_back(std::move(t));
}
```

然后，我们可以加入或分离它们：

```cpp
for (auto& thr: threads) 
{
    if (thr.joinable())
    {
        thr.join();
    }
}
```

移动语义在我们将`std::thread`对象存储为类成员时也很有用。在这种情况下，我们应该仔细设计我们的类，删除复制构造函数和赋值运算符，并实现新的移动构造函数和移动赋值运算符。让我们考虑以下这样一个类的代码示例：

```cpp
class Handler
{
    std::thread  threadHandler;

public:
    Handler(const Handler&) = delete;
    Handler& operator=(const Handler&) = delete;
    Handler(Handler && obj)
    : threadHandler(std::move(obj.threadHandler))
    {}
    Handler & operator=(Handler && obj)
    {
        if (threadHandler.joinable())
        {
            threadHandler.join();
        }
        threadHandler = std::move(obj.threadHandler);
        return *this;
    }
    ~Handler()
    {
    if (threadHandler.joinable())
        {
            threadHandler.join();
        }
    }
};
```

在移动赋值运算符中，我们首先检查线程是否可加入。如果是，我们加入它，然后才执行赋值操作。

#### 注意

我们绝不能在没有使用`join()`或`detach()`的情况下将一个线程对象分配给另一个。这将导致`std::terminate()`函数调用。

也可以使用`std::move()`函数将对象移动到线程函数中。这对于复制大对象是有帮助的，这是不可取的。让我们执行一个练习，确保对象可以移动到线程函数中。

### 练习 3：将对象移动到线程函数

在这个练习中，我们将编写一个简单的应用程序，演示`std::move()`如何用于`std::thread`类。我们将创建一个既有复制构造函数又有移动构造函数的类，以查看将该类的对象移动到`std::thread`函数时将调用哪一个。执行以下步骤完成此练习：

1.  包括线程支持的头文件，即`<thread>`，和流支持的头文件，即`<iostream>`：

```cpp
#include <iostream>
#include <thread>
```

1.  实现`Handler`类，它具有默认构造函数、析构函数、复制构造函数、赋值运算符、移动构造函数和移动赋值运算符。它们除了打印日志外什么都不做：

```cpp
class Handler
{ 
public:
    Handler()
    {
        std::cout << "Handler()" << std::endl;
    }
    Handler(const Handler&)
    {
        std::cout << "Handler(const Handler&)" << std::endl;
    }
    Handler& operator=(const Handler&)
    {
        std::cout << "Handler& operator=(const Handler&)" << std::endl;
        return *this;
    }
    Handler(Handler && obj)
    {
        std::cout << "Handler(Handler && obj)" << std::endl;
    }
    Handler & operator=(Handler && obj)
    {
        std::cout << "Handler & operator=(Handler && obj)" << std::endl;
        return *this;
    }
    ~Handler()
    {
        std::cout << "~Handler()" << std::endl;
    }
};
```

1.  实现`doSomeJob()`函数，这里实际上什么也不做，只是打印一个日志消息：

```cpp
void doSomeJob(Handler&& h)
{
    std::cout << "I'm here" << std::endl;
}
```

1.  进入`main()`函数并创建`Handler`类型的`handler`变量。创建`thr1`，传递`doSomeJob()`函数，并移动处理程序变量：

```cpp
Handler handler;
std::thread thr1(doSomeJob, std::move(handler));
```

1.  分离`thr1`线程并为主线程添加一个小睡眠，以避免关闭应用程序。我们将能够看到来自分离线程的输出。

```cpp
thr1.detach();
using namespace std::chrono_literals; 
std::this_thread::sleep_for(5s);
```

1.  在编辑器中运行此代码。在终端日志中，从默认构造函数中，您将看到两个从移动运算符中的日志，一个从析构函数中的日志，来自`doSomeJob()`函数的消息，最后，另外两个从析构函数中的日志。我们可以看到移动构造函数被调用了两次。

您将获得以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_05_16.jpg)

###### 图 5.16：练习执行的结果

正如你所看到的，`Handler`对象被移动到线程函数中。尽管如此，所有未使用`std::ref()`函数传递的参数都被复制到线程的内存中。

让我们考虑一个有趣的问题。你可能记得，当我们初始化`std::thread`时，所有的构造函数参数都会被复制到线程内存中，包括可调用对象 - lambda、函数或 std::function。但是如果我们的可调用对象不支持复制语义怎么办？例如，我们创建了一个只有移动构造函数和移动赋值运算符的类：

```cpp
class Converter
{
    public:
    Converter(Converter&&)
    {
    }
    Converter& operator=(Converter&&)
    {
        return *this;
    }
    Converter() = default;
    Converter(const Converter&) = delete;
    Converter& operator=(const Converter&) = delete;
    void operator()(const std::string&)
    {
        // do nothing
    }
};
```

我们如何将其传递给线程构造函数？如果我们按原样传递它，将会得到一个编译器错误；例如：

```cpp
int main()
{
    Converter convert;
    std::thread convertThread(convert, "convert me");
    convertThread.join();
    return 0;
}
```

您将获得以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_05_17.jpg)

###### 图 5.17：编译错误的示例

这里有很多奇怪的错误。为了解决这个问题，我们可以使用`std::move()`函数来移动可调用对象：

```cpp
std::thread convertThread(std::move(convert), "convert me");
```

现在一切都很好 - 代码已经编译并且确实做了我们想要的事情。

现在，让我们考虑另一个有趣的例子。例如，您有一个需要捕获不可复制对象的 lambda 函数，例如`unique_ptr`：

```cpp
auto unique = std::make_unique<Converter>();
```

从 C++ 14 开始，我们可以使用`std::move()`来捕获可移动对象。因此，要捕获唯一指针，我们可以使用以下代码：

```cpp
std::thread convertThread([ unique = std::move(unique) ] { 
        unique->operator()("convert me");
});
```

正如您所看到的，通过使用`std::move`在 lambda 中捕获值非常有用。当我们不想复制某些对象时，这也可能很有用，因为它们可能需要很长时间来复制。

现在，让我们将我们的知识付诸实践，并编写一个应用程序示例，演示我们如何在线程中使用`std::move`。

### 练习 4：创建和使用 STL 线程容器

在这个练习中，我们将编写一个简单的应用程序，我们将在其中使用`std::move()`与线程。首先，我们将实现一个可移动构造的类。这个类将把小写文本转换为大写文本。然后，我们将创建一个这个类实例的向量。接下来，我们将创建一个`std::thread`对象的向量。最后，我们将用第一个向量中的对象初始化线程。

执行以下步骤以完成此练习：

1.  包括线程支持的头文件，即`<thread>`，流支持的头文件，即`<iostream>`，和`<vector>`：

```cpp
#include <iostream>
#include <thread>
#include <vector>
#include <string>
```

1.  实现`Converter`类，它具有`const std::vector<std::string>&`类型的`m_bufferIn`私有成员。这是对原始字符串向量的引用。它还具有一个用户构造函数，它接受`bufferIn`变量。然后，我们删除复制构造函数和赋值运算符。最后，我们定义重载的`operator()`，在其中将所有小写符号转换为大写。转换后，我们将结果写入结果缓冲区：

```cpp
class Converter
{
    public:
    Converter(std::vector<std::string>& bufferIn)
        : m_bufferIn(bufferIn)
    {
    }
    Converter(Converter&& rhs)
        : m_bufferIn(std::move(rhs.m_bufferIn))
    {
    }
    Converter(const Converter&) = delete;
    Converter& operator=(const Converter&) = delete;
    Converter& operator=(Converter&&) = delete;
    void operator()(const int idx, std::vector<std::string>& result)
    {
        try
        {
            std::string::const_iterator end = m_bufferIn.at(idx).end();
            std::string bufferOut;
            for (std::string::const_iterator iter = m_bufferIn.at(idx).begin(); iter != end; iter++)
            {
                if (*iter >= 97 && *iter <= 122)
                {
                    bufferOut += static_cast<char>(static_cast<int>(*iter) - 32);
                }
                else
                {
                    bufferOut += *iter;
                }
            }
            result[idx] = bufferOut;
        }
        catch(...)
        {
            std::cout << "Invalid index" << std::endl;
        }
    }
    private:
    const std::vector<std::string>& m_bufferIn;
};
```

1.  进入`main()`函数，创建一个名为`numberOfTasks`的常量值，并将其设置为`5`。然后，创建一个`Converter`对象的向量，并使用`numberOfTasks`保留其大小。然后，创建一个`std::thread`对象的向量，并使用`numberOfTasks`保留其大小：

```cpp
const int numberOfTasks = 5;
std::vector<Converter> functions;
functions.reserve(numberOfTasks);
std::vector<std::thread> threads;
threads.reserve(numberOfTasks); 
```

1.  创建字符串向量`textArr`，并推入五个不同的大字符串以进行转换：

```cpp
std::vector<std::string> textArr;
textArr.emplace_back("In the previous topics, we learned almost all that we need to work with threads. But we still have something interesting to consider – how to synchronize threads using future results. When we considered condition variables we didn't cover the second type of synchronization with future results. Now it's time to learn that.");
textArr.emplace_back("First of all, let's consider a real-life example. Imagine, you just passed the exam at the university. You were asked to wait some amount of time for results. So, you have time to coffee with your mates, and every 10-15 mins you check are results available. Then, when you finished all your other activities, you just come to the door of the lecture room and wait for results.");
textArr.emplace_back("In this exercise, we will write a simple application where we will use std::move() with threads. First of all, we will implement a class that is move constructible. This class will convert lowercase text into uppercase text. Then we will create a vector of instances of this class. Next, we will create a vector of std::thread object. Finally, we will initialize threads with an object from the first vector");
textArr.emplace_back("Let's consider one interesting issue. As you remember when we initialize std::thread all constructor arguments are copied into thread memory, including a callable object – lambda, function, std::function. But what if our callable object doesn't support copy semantic? For example, we created a class that has only move constructor and a move assignment operator:");
textArr.emplace_back("Run this code in your editor. You will see in the terminal log from the default constructor, two logs from the move operator, then one log from a destructor, then message from the doSomeJob() function and, finally two other log messages from the destructor. We see that the move constructor is called twice. You will get the output like the following:");
```

1.  实现一个`for`循环，将`Converter`对象推入函数向量：

```cpp
for (int i = 0; i < numberOfTasks; ++i)
{
    functions.push_back(Converter(textArr));
}
```

1.  创建一个字符串结果向量，并推入五个空字符串。然后，创建一个将作为数组元素索引的变量：

```cpp
std::vector<std::string> result;
for (int i = 0; i < numberOfTasks; ++i)
{
    result.push_back("");
}
int idx = 0;
```

1.  实现另一个`for`循环，将`std::thread`对象推入线程向量：

```cpp
for (auto iter = functions.begin(); iter != functions.end(); ++iter)
{
    std::thread tmp(std::move(*iter), idx, std::ref(result));        
    threads.push_back(std::move(tmp));
    from = to;
    to += step;
}
```

1.  实现第三个`for`循环，其中我们分离`std::threads`：

```cpp
for (auto iter = threads.begin(); iter != threads.end(); ++iter)
{
     (*iter).detach();
}
```

1.  为主线程添加一个小的休眠，以避免关闭应用程序。现在，我们可以看到分离的线程是如何工作的：

```cpp
using namespace std::chrono_literals; 
std::this_thread::sleep_for(5s);
```

1.  最后将结果打印到终端：

```cpp
for (const auto& str : result)
{
    std::cout << str;
}
```

1.  在编辑器中运行此代码。在终端中，您可以看到所有字符串都是大写的，这意味着所有线程都已成功移动和运行。您将得到以下输出：

![图 5.18：练习执行的结果](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_05_18.jpg)

###### 图 5.18：练习执行的结果

在这个练习中，我们练习了如何创建一个只能移动对象的 STL 容器。我们还考虑了如何将不可复制的对象传递给线程构造函数。这些知识将在下一节中帮助我们学习如何从线程中获取结果。

## 未来、承诺和异步

在前一节中，我们几乎学会了处理线程所需的所有内容。但是我们仍有一些有趣的事情要考虑，即使用未来结果同步线程。当我们考虑条件变量时，我们没有涵盖使用未来结果进行第二种类型的同步。现在，是时候学习一下了。

假设有这样一种情况，我们运行一些线程并继续进行其他工作。当我们需要结果时，我们停下来检查它是否准备好。这种情况描述了未来结果的实际工作。在 C++中，我们有一个名为`<future>`的头文件，其中包含两个模板类，表示未来结果：`std::future<>`和`std::shared_future<>`。当我们需要单个未来结果时，我们使用`std::future<>`，当我们需要多个有效副本时，我们使用`std::shared_future<>`。我们可以将它们与`std::unique_ptr`和`std::shared_ptr`进行比较。

要处理未来的结果，我们需要一个特殊的机制来在后台运行任务并稍后接收结果：`std::async()`模板函数。它以可调用对象作为参数，并且有启动模式 - 延迟或异步，当然还有可调用对象的参数。启动模式`std::launch::async`和`std::launch::deferred`表示如何执行任务。当我们传递`std::launch::async`时，我们期望该函数在单独的线程中执行。当我们传递`std::launch::deferred`时，函数调用将被延迟，直到我们要求结果。我们也可以同时传递它们，例如`std::launch::deferred|std::launch::async`。这意味着运行模式将取决于实现。

现在，让我们考虑一个使用`std::future`和`std::async`的示例。我们有一个`toUppercase()`函数，将给定的字符串转换为大写：

```cpp
std::string toUppercase(const std::string& bufIn)
{
    std::string bufferOut;
    for (std::string::const_iterator iter = bufIn.begin(); iter != bufIn.end(); iter++)
    {
        if (*iter >= 97 && *iter <= 122)
        {
            bufferOut += static_cast<char>(static_cast<int>(*iter) - 32);
        }
        else
        {
            bufferOut += *iter;
        }
    }
    return bufferOut;
}
```

然后，在`main()`函数中，创建一个名为`result`的`std::future`变量，并使用`std::async()`的返回值进行初始化。然后，我们使用结果对象的`get()`函数获取结果：

```cpp
#include <iostream>
#include <future>
int main()
{
    std::future<std::string> result = std::async(toUppercase, "please, make it uppercase");
    std::cout << "Main thread isn't locked" << std::endl;
    std::cout << "Future result = " << result.get() << std::endl;
    return 0;
}
```

实际上，在这里，我们创建了一个未来对象：

```cpp
std::future<std::string> result = std::async(toUppercase, "please, make it uppercase");
```

正如您所看到的，我们没有将启动模式传递给`std::async()`函数，这意味着将使用默认模式：`std::launch::deferred | std::launch::async`。您也可以明确这样做：

```cpp
std::future<std::string> result = std::async(std::launch::async, toUppercase, "please, make it uppercase");
```

在这里，我们正在等待结果：

```cpp
std::cout << "Future result = " << result.get() << std::endl;
```

如果我们的任务需要很长时间，线程将在这里等待直到结束。

通常，我们可以像使用`std::thread`构造函数一样使用`std::async()`函数。我们可以传递任何可调用对象。默认情况下，所有参数都会被复制，我们可以移动变量和可调用对象，也可以通过引用传递它们。

`std::future`对象不受竞争条件保护。因此，为了从不同的线程访问它并保护免受损害，我们应该使用互斥锁。但是，如果我们需要共享 future 对象，最好使用`std::shared_future`。共享的 future 结果也不是线程安全的。为了避免竞争条件，我们必须在每个线程中使用互斥锁或存储线程自己的`std::shared_future`副本。

#### 注意

`std::future`对象的竞争条件非常棘手。当线程调用`get()`函数时，future 对象变得无效。

我们可以通过将未来移动到构造函数来创建共享的未来：

```cpp
std::future<std::string> result = std::async(toUppercase, "please, make it uppercase");
std::cout << "Main thread isn't locked" << std::endl;
std::shared_future<std::string> sharedResult(std::move(result));
std::cout << "Future result = " << sharedResult.get() << std::endl;
std::shared_future<std::string> anotherSharedResult(sharedResult);
std::cout << "Future result = " << anotherSharedResult.get() << std::endl;
```

正如您所看到的，我们从`std::future`创建了一个`std::shared_future`变量并进行了复制。两个共享的 future 对象都指向相同的结果。

我们还可以使用`std::future`对象的`share()`成员函数来创建共享的 future 对象：

```cpp
std::future<std::string> result = std::async(toUppercase, "please, make it uppercase");
std::cout << "Main thread isn't locked" << std::endl;
auto sharedResult = result.share();
std::cout << "Future result = " << sharedResult.get() << std::endl;
```

请注意，在这两种情况下，`std::future`对象都会变得无效。

我们还可以使用`std::packaged_task<>`模板类从单独的线程获取未来结果的另一种方法。我们如何使用它们？

1.  我们创建一个新的`std::packaged_task`并声明可调用函数签名：

```cpp
std::packaged_task<std::string(const std::string&)> task(toUppercase);
```

1.  然后，我们将未来结果存储在`std::future`变量中：

```cpp
auto futureResult = task.get_future();
```

1.  接下来，我们在单独的线程中运行此任务或将其作为函数调用：

```cpp
std::thread thr1(std::move(task), "please, make it uppercase");
thr1.detach();
```

1.  最后，我们等待未来的结果准备就绪：

```cpp
std::cout << "Future result = " << futureResult.get() << std::endl;
```

#### 注意

`std::packaged_task`是不可复制的。因此，要在单独的线程中运行它，请使用`std::move()`函数。

还有一件重要的事情需要注意。如果您不希望从线程中获得任何结果，并且更喜欢等待线程完成工作，可以使用`std::future<void>`。现在，当您调用`future.get()`时，您的当前线程将在此处等待。让我们考虑一个例子：

```cpp
#include <iostream>
#include <future>
void toUppercase(const std::string& bufIn)
{
    std::string bufferOut;
    for (std::string::const_iterator iter = bufIn.begin(); iter != bufIn.end(); iter++)
    {
        if (*iter >= 97 && *iter <= 122)
        {
            bufferOut += static_cast<char>(static_cast<int>(*iter) - 32);
        }
        else
        {
            bufferOut += *iter;
        }
    }
    using namespace std::chrono_literals;
    std::this_thread::sleep_for(2s);
    std::cout << bufferOut << std::endl;
}
int main()
{
    std::packaged_task<void(const std::string&)> task(toUppercase);
    auto futureResult = task.get_future();
    std::thread thr1(std::move(task), "please, make it uppercase");
    thr1.detach();
    std::cout << "Main thread is not blocked here" << std::endl;
    futureResult.get();
    std::cout << "The packaged_task is done" << std::endl;
    return 0;
} 
```

正如您所看到的，通过等待另一个线程，我们正在利用诸如条件变量、未来结果和 promises 等多种技术。

现在，让我们继续讨论标准库中的下一个重要特性 - `std::promise<>`模板类。使用这个类，我们可以设置我们想要接收的类型的值，然后使用`std::future`获取它。我们如何使用它们？为此，我们需要实现一个接受`std::promise`参数的函数：

```cpp
void toUppercase(const std::string& bufIn, std::promise<std::string> result)
```

工作完成后，我们需要使用`std::promise`初始化一个新值：

```cpp
result.set_value(bufferOut);
```

为了在我们将要使用它的地方创建`std::promise`，我们需要编写以下代码：

```cpp
std::promise<std::string> stringInUpper;
```

完成后，我们必须创建`std::future`并从 promise 获取它：

```cpp
std::future<std::string> futureRes = stringInUpper.get_future();
```

我们需要在单独的线程中运行此函数：

```cpp
std::thread thr(toUppercase, "please, make it uppercase", std::move(stringInUpper));
thr.detach();
```

现在，我们需要等待直到 future 设置：

```cpp
futureRes.wait();
std::cout << "Result = " << futureRes.get() << std::endl;
```

使用 promises 获取结果的完整示例如下：

```cpp
#include <iostream>
#include <future>
void toUppercase(const std::string& bufIn, std::promise<std::string> result)
{
    std::string bufferOut;
    for (std::string::const_iterator iter = bufIn.begin(); iter != bufIn.end(); iter++)
    {
        if (*iter >= 97 && *iter <= 122)
        {
            bufferOut += static_cast<char>(static_cast<int>(*iter) - 32);
        }
        else
        {
            bufferOut += *iter;
        }
    }
    result.set_value(bufferOut);
}
int main()
{
    std::promise<std::string> stringInUpper;
    std::future<std::string> futureRes = stringInUpper.get_future();
    std::thread thr(toUppercase, "please, make it uppercase", std::move(stringInUpper));
    thr.detach();
    std::cout << "Main thread is not blocked here" << std::endl;
    futureRes.wait();
    std::cout << "Result = " << futureRes.get() << std::endl;
    return 0;
}
```

所以，我们几乎涵盖了编写多线程应用程序所需的一切，除了一个重要的事情 - 如果在单独的线程中抛出异常会发生什么？例如，您在线程中传递一个函数，它抛出异常。在这种情况下，将为该线程调用`std::terminate()`。其他线程将继续它们的工作。让我们考虑一个简单的例子。

我们有一个`getException()`函数，它生成带有线程 ID 的消息并抛出`std::runtime_error`：

```cpp
#include <sstream>
#include <exception>
#include <iostream>
#include <future>
std::string getException()
{
    std::stringstream ss;
    ss << "Exception from thread: ";
    ss << std::this_thread::get_id();
    throw std::runtime_error(ss.str());
}
```

我们还有`toUppercase()`函数。它将给定的字符串转换为大写，并调用`getException()`函数，该函数会抛出异常：

```cpp
std::string toUppercase(const std::string& bufIn)
{
    std::string bufferOut;
    for (std::string::const_iterator iter = bufIn.begin(); iter != bufIn.end(); iter++)
    {
        if (*iter >= 97 && *iter <= 122)
        {
            bufferOut += static_cast<char>(static_cast<int>(*iter) - 32);
        }
        else
        {
            bufferOut += *iter;
            getException();
        }
    }
    return bufferOut;
}
```

这是`main()`函数，我们在其中在`try-catch`块中创建一个新线程`thr`。我们捕获异常并将消息打印到终端：

```cpp
int main()
{
    try
    {
        std::thread thr(toUppercase, "please, make it uppercase");
        thr.join();
    }
    catch(const std::exception& ex)
    {
        std::cout << "Caught an exception: " << ex.what() << std::endl;
    }
    return 0;
}
```

如果您在 IDE 中运行此代码，您将看到以下输出：

![图 5.19：示例执行的结果](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_05_19.jpg)

###### 图 5.19：示例执行的结果

我们可以看到在抛出异常后调用了`std::terminate()`。当您的程序中有很多线程时，很难找到线程终止的正确位置。幸运的是，我们有一些机制可以捕获来自另一个线程的异常。让我们考虑一下它们。

未来结果中的`std::exception_ptr`并设置就绪标志。然后，当您调用`get()`时，`std::exception_ptr`被存储并重新抛出异常。我们所需要做的就是在`try-catch`块中放置一个`get()`调用。让我们考虑一个例子。我们将使用上一个例子中的两个辅助函数，即`getException()`和`toUppercase()`。它们将保持不变。在`main()`函数中，我们创建了一个名为`result`的`std::future`对象，并使用`std::async()`函数运行`toUppercase()`函数。然后，在`try-catch`块中调用`result`对象的`get()`函数并捕获异常：

```cpp
#include <iostream>
#include <future>
int main()
{
    std::future<std::string> result = std::async(toUppercase, "please, make it uppercase");
    try
    {
        std::cout << "Future result = " << result.get() << std::endl;
    }
    catch(const std::exception& ex)
    {
        std::cout << "Caught an exception: " << ex.what() << std::endl;
    }
    return 0;
}
```

如果您在 IDE 中运行上述代码，您将得到以下输出：

![图 5.20：示例执行的结果](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_05_20.jpg)

###### 图 5.20：示例执行的结果

如您所见，我们捕获了异常，现在我们可以以某种方式处理它。`std::packaged_task<>`类以相同的方式处理异常 - 它在未来结果中存储`std::exception_ptr`，设置就绪标志，然后`std::future`在`get()`调用中重新抛出异常。让我们考虑一个小例子。我们将使用上一个例子中的两个辅助函数 - `getException()`和`toUppercase()`。它们将保持不变。在`main()`函数中，我们创建了一个名为`task`的`std::packaged_task`对象。通过使用我们的`toUppercase()`函数的类型，它返回一个整数，并以两个整数作为参数。我们将`toUppercase()`函数传递给`task`对象。然后，我们创建了一个名为`result`的`std::future`对象，并使用`get_future()`函数从 task 对象获取结果。最后，我们在新线程`thr`中运行 task 对象，并在`try-catch`块中调用`result`变量的`get()`函数：

```cpp
#include <iostream>
#include <future>
int main()
{
    std::packaged_task<std::string(const std::string&)> task(toUppercase);
    auto result = task.get_future();
    std::thread thr(std::move(task), "please, make it uppercase");
    thr.detach();
    try
    {
        std::cout << "Future result = " << result.get() << std::endl;
    }
    catch(const std::exception& ex)
    {
        std::cout << "Caught an exception: " << ex.what() << std::endl;
    }
    return 0;
}
```

如果您在 IDE 中运行此代码，您将得到以下输出：

![图 5.21：此示例执行的结果](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_05_21.jpg)

###### 图 5.21：此示例执行的结果

`std::promise<>`类以另一种方式处理异常。它允许我们使用`set_exception()`或`set_exception_at_thread_exit()`函数手动存储异常。要在`std::promise`中设置异常，我们必须捕获它。如果我们不捕获异常，在`std::promise`的析构函数中将设置错误，作为未来结果中的`std::future_errc::broken_promise`。当您调用`get()`函数时，异常将被重新抛出。让我们考虑一个例子。我们将使用上一个例子中的一个辅助函数 - `getException()`。它保持不变。但是，我们将更改`toUppercase()`函数并添加第三个参数`std::promise`。现在，我们将在`try`块中调用`getException()`函数，捕获异常，并将其设置为`std::promise`的值：

```cpp
void toUppercase(const std::string& bufIn, std::promise<std::string> result)
{
    std::string bufferOut;
    try
    {
        for (std::string::const_iterator iter = bufIn.begin(); iter != bufIn.end(); iter++)
        {
            if (*iter >= 97 && *iter <= 122)
            {
                    bufferOut += static_cast<char>(static_cast<int>(*iter) - 32);
            }
            else
            {
                bufferOut += *iter;
                getException();
            }
        }
    }
    catch(const std::exception& ex)
    {
        result.set_exception(std::make_exception_ptr(ex));
    }
    result.set_value(bufferOut);
}
```

#### 注意

有几种方法可以将异常设置为 promise。首先，我们可以捕获`std::exception`并使用`std::make_exception_ptr()`函数将其转换为`std::exception_ptr`。您还可以使用`std::current_exception()`函数，它返回`std::exception_ptr`对象。

在`main()`函数中，我们创建了一个整数类型的 promise，称为`upperResult`。我们创建了一个名为`futureRes`的未来结果，并从`upperResult` promise 值中设置它。接下来，我们创建一个新线程`thr`，将`toUppercase()`函数传递给它，并移动`upperResult` promise。然后，我们调用`futureRes`对象的`wait()`函数，使调用线程等待直到结果变为可用。然后，在`try-catch`块中，我们调用`futureRes`对象的`get()`函数，它重新抛出异常：

```cpp
#include <iostream>
#include <future>
int main()
{
    std::promise<std::string> upperResult;
    std::future<std::string> futureRes = upperResult.get_future();
    std::thread thr(toUppercase, "please, make it uppercase", std::move(upperResult));
    thr.detach();
    futureRes.wait();
    try
    {
        std::cout << "Result = " << futureRes.get() << std::endl;
    }
    catch(...)
    {
        std::cout << "Caught an exception" << std::endl;
    }
    return 0;
}
```

#### 注意

当我们创建一个`std::promise<>`对象时，我们承诺我们将强制设置值或异常。如果我们没有这样做，`std::promise`的析构函数将抛出异常，即`std::future_error - std::future_errc::broken_promise`。

如果您在 IDE 中运行此代码，您将得到以下输出：

![图 5.22：此示例执行的结果](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_05_22.jpg)

###### 图 5.22：此示例执行的结果

这就是在多线程应用程序中处理异常的全部内容。正如您所看到的，这与我们在单个线程中所做的非常相似。现在，让我们将我们的知识付诸实践，并编写一个简单的应用程序示例，演示我们如何使用不同的 future 结果进行同步。

### 练习 5：使用 Future 结果进行同步

在这个练习中，我们将编写一个简单的应用程序来演示如何使用 future 结果来接收来自不同线程的值。我们将运行`ToUppercase()`可调用对象三次。我们将使用`std::async()`函数执行第一个任务，使用`std::packaged_task<>`模板类执行第二个任务，并使用`std::thread`和`std::promise`执行最后一个任务。

执行以下步骤以完成此练习：

1.  包括用于线程支持的头文件，即`<thread>`，用于流支持的头文件，即`<iostream>`，以及用于 future 结果支持的`<future>`：

```cpp
#include <iostream>
#include <thread>
#include <future>
```

1.  实现一个`ToUppercase`类，将给定的字符串转换为大写。它有两个重载的运算符，`()`。第一个`operator()`接受要转换的字符串并以大写形式返回结果值。第二个`operator()`接受要转换的字符串和一个`std::promise`，并将返回值存储在 promise 中：

```cpp
class ToUppercase
{
    public:
    std::string operator()(const std::string& bufIn)
    {
        std::string bufferOut;
        for (std::string::const_iterator iter = bufIn.begin(); iter != bufIn.end(); iter++)
        {
            if (*iter >= 97 && *iter <= 122)
            {
                bufferOut += static_cast<char>(static_cast<int>(*iter) - 32);
            }
            else
            {
                bufferOut += *iter;
            }
        }
        return bufferOut;
    }
    void operator()(const std::string& bufIn, std::promise<std::string> result)
    {
        std::string bufferOut;
        for (std::string::const_iterator iter = bufIn.begin(); iter != bufIn.end(); iter++)
        {
            if (*iter >= 97 && *iter <= 122)
            {
                bufferOut += static_cast<char>(static_cast<int>(*iter) - 32);
            }
            else
            {
                bufferOut += *iter;
            }
        }
        result.set_value(bufferOut);
    }
};
```

1.  现在，创建一个`ToUppercase`对象，即`ptConverter`，并创建一个`std::packaged_task`，即`upperCaseResult1`，它以`ptConverter`对象作为参数。创建一个`std::future`值，并从`upperCaseResult1`设置它。在一个单独的线程中运行这个任务：

```cpp
ToUppercase ptConverter;
std::packaged_task<std::string(const std::string&)> upperCaseResult1(ptConverter);
std::future<std::string> futureUpperResult1= upperCaseResult1.get_future();
std::thread thr1(std::move(ptConverter), "This is a string for the first asynchronous task");
thr1.detach(); 
```

1.  现在，创建第二个`ToUppercase`对象，即`fConverter`。创建一个名为`futureUpperResult2`的`std::future`对象，并从`std::async()`设置它：

```cpp
ToUppercase fConverter;
std::future<std::string> futureUpperResult2 = std::async(fConverter, "This is a string for the asynchronous task"); 
```

1.  现在，创建第三个`ToUppercase`对象，即`pConverter`。创建一个名为`promiseResult`的`std::promise`值。然后，创建一个名为`futureUpperResult3`的`std::future`值，并从`promiseResult`设置它。现在，在单独的线程中运行`pConverter`任务，并将`promiseResult`作为参数传递：

```cpp
ToUppercase pConverter;
std::promise<std::string> promiseResult;
std::future<std::string> futureUpperResult3 = promiseResult.get_future();
std::thread thr2(pConverter, "This is a string for the task that returns a promise", std::move(promiseResult));
thr2.detach(); 
```

1.  现在，要接收所有线程的结果，请等待`futureUpperResult3`准备就绪，然后获取所有三个结果并打印它们：

```cpp
futureUpperResult3.wait();
std::cout  << "Converted strings: "
        << futureUpperResult1.get() << std::endl
        << futureUpperResult2.get() << std::endl
        << futureUpperResult3.get() << std::endl;
```

1.  在编辑器中运行此代码。您将看到来自所有三个线程的转换后的字符串。

您将得到以下输出：

![图 5.23：此练习执行的结果](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_05_23.jpg)

###### 图 5.23：此练习执行的结果

那么，我们在这里做了什么？我们将大的计算分成小部分，并在不同的线程中运行它们。对于长时间的计算，这将提高性能。在这个练习中，我们学会了如何从线程中接收结果。在本节中，我们还学会了如何将在单独线程中抛出的异常传递给调用线程。我们还学会了如何通过事件来同步几个线程的工作，不仅可以使用条件变量，还可以使用 future 结果。

### 活动 1：创建模拟器来模拟艺术画廊的工作

在这个活动中，我们将创建一个模拟器来模拟艺术画廊的工作。我们设置了画廊的访客限制 - 只能容纳 50 人。为了实现这个模拟，我们需要创建一个`Person`类，代表艺术画廊中的人。此外，我们需要一个`Persons`类，这是一个线程安全的人员容器。我们还需要一个`Watchman`类来控制里面有多少人。如果超过了看门人的限制，我们将所有新来的人放到等待列表中。最后，我们需要一个`Generator`类，它有两个线程 - 一个用于创建新的访客，另一个用于通知我们有人必须离开画廊。因此，我们将涵盖使用线程、互斥锁、条件变量、锁保护和唯一锁。这个模拟器将允许我们利用本章中涵盖的技术。因此，在尝试此活动之前，请确保您已完成本章中的所有先前练习。

要实现此应用程序，我们需要描述我们的类。我们有以下类：

![图 5.24：在此活动中使用的类的描述](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_05_24.jpg)

###### 图 5.24：在此活动中使用的类的描述

在开始实现之前，让我们创建类图。以下图表显示了所有上述类及其关系：

![图 5.25：类图](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_05_25.jpg)

###### 图 5.25：类图

按照以下步骤实现此活动：

1.  定义并实现 Person 类，除了打印日志外什么也不做。

1.  为 Person 创建一些线程安全的存储，包装 std::vector 类。

1.  实现 PersonGenerator 类，在不同的线程中进行无限循环，创建和移除访客，并通知 Watchman 类。

1.  创建 Watchman 类，在单独的线程中进行无限循环，从 PersonGenerator 类的通知中将访问者从队列移动到另一个队列。

1.  在 main()函数中声明相应的对象以模拟艺术画廊及其工作方式。

实现这些步骤后，您应该获得以下输出，其中您可以看到所有实现类的日志。确保模拟流程如预期那样进行。预期输出应该类似于以下内容：

![图 5.26：应用程序执行的结果](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_05_26.jpg)

###### 图 5.26：应用程序执行的结果

#### 注意

此活动的解决方案可在第 681 页找到。

## 摘要

在本章中，我们学习了使用 C++标准库支持的线程。如果我们想编写健壮、快速和清晰的多线程应用程序，这是基础。

我们首先研究了关于并发的一般概念 - 什么是并行、并发、同步、异步和线程执行。对这些概念有清晰的理解使我们能够理解多线程应用程序的架构设计。

接下来，我们看了开发多线程应用程序时遇到的不同问题，如数据危害、竞争条件和死锁。了解这些问题有助于我们为项目构建清晰的同步架构。我们考虑了一些现实生活中的同步概念示例，这使我们对编程线程应用程序时可能遇到的挑战有了很好的理解。

接下来，我们尝试使用不同的标准库原语进行同步。我们试图弄清楚如何处理竞争条件，并通过事件同步和数据同步实现了示例。接下来，我们考虑了移动语义如何应用于多线程。我们了解了哪些来自线程支持库的类是不可复制但可移动的。我们还考虑了移动语义在多线程闭包中的工作方式。最后，我们学会了如何从单独的线程接收结果，以及如何使用期望、承诺和异步来同步线程。

我们通过构建一个艺术画廊模拟器来将所有这些新技能付诸实践。我们构建了一个多线程应用程序，其中包括一个主线程和四个子线程。我们通过使用条件变量之间实现了它们之间的通信。我们通过互斥锁保护了它们的共享数据。总之，我们运用了本章学到的所有内容。

在下一章中，我们将更仔细地研究 C++中的 I/O 操作和类。我们将首先查看标准库的 I/O 支持。然后，我们将继续使用流和异步 I/O 操作。接下来，我们将学习线程和 I/O 的交互。我们将编写一个活动，让我们能够掌握 C++中的 I/O 工作技能。
