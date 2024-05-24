# C++ 高级编程（二）

> 原文：[`annas-archive.org/md5/5f35e0213d2f32c832c0e92fd16884c1`](https://annas-archive.org/md5/5f35e0213d2f32c832c0e92fd16884c1)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第三章：不允许鸭子-模板和推导

## 学习目标

通过本章结束时，您将能够：

+   使用继承和多态将自己的类发挥到更大的效果

+   实现别名以使您的代码更易于阅读

+   使用 SFINAE 和 constexpr 开发模板以简化您的代码

+   使用 STL 实现自己的解决方案，以利用通用编程

+   描述类型推导的上下文和基本规则

本章将向您展示如何通过继承，多态和模板来定义和扩展您的类型。

## 介绍

在上一章中，我们学习了如何通过单元测试开发自己的类型（类），并使它们表现得像内置类型。我们介绍了函数重载，三/五法则和零法则。

在本章中，我们将学习如何进一步扩展类型系统。我们将学习如何使用模板创建函数和类，并重新讨论函数重载，因为它受到模板的影响。我们将介绍一种新技术**SFINAE**，并使用它来控制我们模板中包含在生成代码中的部分。

## 继承，多态和接口

在我们的面向对象设计和 C++的旅程中，我们已经专注于抽象和数据封装。现在我们将把注意力转向**继承**和**多态**。什么是继承？什么是多态？我们为什么需要它？考虑以下三个对象：

![图 2B.1：车辆对象](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_02B_01.jpg)

###### 图 2B.1：车辆对象

在上图中，我们可以看到有三个非常不同的对象。它们有一些共同之处。它们都有轮子（不同数量），发动机（不同大小，功率或配置），启动发动机，驾驶，刹车，停止发动机等，我们可以使用这些来做一些事情。

因此，我们可以将它们抽象成一个称为车辆的东西，展示这些属性和一般行为。如果我们将其表达为 C++类，可能会看起来像下面这样：

```cpp
class Vehicle
{
public:
  Vehicle() = default;
  Vehicle(int numberWheels, int engineSize) : 
          m_numberOfWheels{numberWheels}, m_engineSizeCC{engineSize}
  {
  }
  bool StartEngine()
  {
    std::cout << "Vehicle::StartEngine " << m_engineSizeCC << " CC\n";
    return true;
  };
  void Drive()
  {
    std::cout << "Vehicle::Drive\n";
  };
  void ApplyBrakes()
  {
    std::cout << "Vehicle::ApplyBrakes to " << m_numberOfWheels << " wheels\n";
  };
  bool StopEngine()
  {
    std::cout << "Vehicle::StopEngine\n";
    return true;
  };
private:
  int m_numberOfWheels {4};
  int m_engineSizeCC{1000};
};
```

`Vehicle`类是`Motorcycle`，`Car`和`Truck`的更一般（或抽象）表达。我们现在可以通过重用 Vehicle 类中已有的内容来创建更专业化的类型。我们将通过继承来重用 Vehicle 的属性和方法。继承的语法如下：

```cpp
class DerivedClassName : access_modifier BaseClassName
{
  // Body of DerivedClass
};
```

我们之前遇到过`public`，`protected`和`private`等访问修饰符。它们控制我们如何访问基类的成员。Motorcycle 类将派生如下：

```cpp
class Motorcycle : public Vehicle
{
public:
  Motorcycle(int engineSize) : Vehicle(2, engineSize) {};
};
```

在这种情况下，Vehicle 类被称为**基类**或**超类**，而 Motorcycle 类被称为**派生类**或**子类**。从图形上看，我们可以表示为下面的样子，箭头从派生类指向基类：

![图 2B.2：车辆类层次结构](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_02B_02.jpg)

###### 图 2B.2：车辆类层次结构

但摩托车的驾驶方式与通用车辆不同。因此，我们需要修改`Motorcycle`类，使其行为不同。更新后的代码将如下所示：

```cpp
class Motorcycle : public Vehicle
{
public:
  Motorcycle(int engineSize) : Vehicle(2, engineSize) {};
  void Drive()
  {
    std::cout << "Motorcycle::Drive\n";
  };
};
```

如果我们考虑面向对象设计，这是关于以对象协作的方式对问题空间进行建模。这些对象通过消息相互通信。现在，我们有两个类以不同的方式响应相同的消息（`Drive()`方法）。发送消息的人不知道会发生什么，也不真的在乎，这就是多态的本质。

#### 注意

多态来自希腊词 poly 和 morph，其中`poly`表示许多，`morph`表示形式。因此，多态意味着`具有多种形式`。

我们现在可以使用这些类来尝试多态：

```cpp
#include <iostream>
int main()
{
  Vehicle vehicle;
  Motorcycle cycle{1500};
  Vehicle* myVehicle{&vehicle};
  myVehicle->StartEngine();
  myVehicle->Drive();
  myVehicle->ApplyBrakes();
  myVehicle->StopEngine();
  myVehicle = &cycle;
  myVehicle->StartEngine();
  myVehicle->Drive();
  myVehicle->ApplyBrakes();
  myVehicle->StopEngine();
  return 0;
}
```

如果我们编译并运行此程序，我们会得到以下输出：

![图 2B.3：车辆程序输出](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_02B_03.jpg)

###### 图 2B.3：车辆程序输出

在前面的屏幕截图中，在`Vehicle::StartEngine 1500 cc`之后的行都与`Motorcycle`有关。但是`Drive`行仍然显示`Vehicle::Drive`，而不是预期的`Motorcycle::Drive`。出了什么问题？问题在于我们没有告诉编译器`Vehicle`类中的`Drive`方法可以被派生类修改（或覆盖）。我们需要在代码中做出一些改变：

```cpp
virtual void Drive()
{
  std::cout << "Vehicle::Drive\n";
};
```

通过在成员函数声明之前添加`virtual`关键字，我们告诉编译器派生类可以（但不一定）覆盖或替换该函数。如果我们进行此更改，然后编译并运行程序，将得到以下输出：

![图 2B.4：带有虚方法的车辆程序输出](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_02B_04.jpg)

###### 图 2B.4：带有虚方法的车辆程序输出

现在，我们已经了解了继承和多态性。我们使用`Vehicle`类的指针来控制`Motorcycle`类。作为最佳实践的一部分，应该对代码进行另一个更改。我们还应该更改`Motorcyle`中`Drive`函数的声明如下：

```cpp
void Drive() override
{
  std::cout << "Motorcycle::Drive\n";
};
```

C++11 引入了`override`关键字，作为向编译器的提示，说明特定方法应具有与其父树中某个方法相同的函数原型。如果找不到，则编译器将报告错误。这是一个非常有用的功能，可以帮助您节省数小时的调试时间。如果编译器有办法报告错误，请使用它。缺陷检测得越早，修复就越容易。最后一个变化是，每当我们向类添加虚函数时，必须声明其析构函数为`virtual`：

```cpp
class Vehicle
{
public:
  // Constructors - hidden 
  virtual ~Vehicle() = default;  // Virtual Destructor
  // Other methods and data -- hidden
};
```

在将`Drive()`函数设为虚函数之前，我们已经看到了这一点。当通过指向 Vehicle 的指针调用析构函数时，需要知道调用哪个析构函数。因此，将其设为虚函数可以实现这一点。如果未能这样做，可能会导致资源泄漏或对象被切割。

### 继承和访问说明符

正如我们之前提到的，从超类继承一个子类的一般形式如下：

```cpp
class DerivedClassName : access_modifier BaseClassName
```

当我们从 Vehicle 类派生 Motorcycle 类时，我们使用以下代码：

```cpp
class Motorcycle : public Vehicle
```

访问修饰符是可选的，是我们之前遇到的`public`、`protected`和`private`之一。在下表中，您可以看到基类成员的可访问性。如果省略 access_modifier，则编译器会假定指定了 private。

![图 2B.5：派生类中基类成员的可访问性](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_02B_05.jpg)

###### 图 2B.5：派生类中基类成员的可访问性

### 抽象类和接口

到目前为止，我们谈论过的所有类都是**具体类** - 它们可以实例化为变量的类型。还有另一种类型的类 - **抽象类** - 它包含至少一个**纯虚成员函数**。纯虚函数是一个在类中没有定义（或实现）的虚函数。由于它没有实现，该类是畸形的（或抽象的），无法实例化。如果尝试创建抽象类型的变量，则编译器将生成错误。

要声明纯虚成员函数，将函数原型声明结束为`= 0`。要将`Drive()`作为 Vehicle 类中的纯虚函数声明，我们将其声明如下：

```cpp
virtual void Drive() = 0;
```

现在，为了能够将派生类用作变量类型（例如`Motorcycle`类），它必须定义`Drive()`函数的实现。

但是，您可以声明变量为抽象类的指针或引用。在任何一种情况下，它必须指向或引用从抽象类派生的某个非抽象类。

在 Java 中，有一个关键字接口，允许你定义一个全是纯虚函数的类。在 C++中，通过声明一个只声明公共纯虚函数（和虚析构函数）的类来实现相同的效果。通过这种方式，我们定义了一个接口。

#### 注意

在本章中解决任何实际问题之前，请下载本书的 GitHub 存储库（[`github.com/TrainingByPackt/Advanced-CPlusPlus`](https://github.com/TrainingByPackt/Advanced-CPlusPlus)）并在 Eclipse 中导入 Lesson 2B 文件夹，以便查看每个练习和活动的代码。

### 练习 1：使用多态实现游戏角色

在这个练习中，我们将演示继承、接口和多态。我们将从一个临时实现的角色扮演游戏开始，然后将其演变为更通用和可扩展的形式。让我们开始吧：

1.  打开 Eclipse，并使用**Lesson2B**示例文件夹中的文件创建一个名为**Lesson2B**的新项目。

1.  由于这是一个**基于 CMake 的项目**，将当前构建器更改为**Cmake Build (portable)**。

1.  转到**项目** | **构建所有**菜单以构建所有练习。默认情况下，屏幕底部的控制台将显示**CMake 控制台[Lesson2B]**。

1.  配置一个名为**L2BExercise1**的**新启动配置**，运行**Exercise1**二进制文件，然后点击**运行**以构建和运行**Exercise 1**。你将收到以下输出：![图 2B.6：练习 1 默认输出](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_02B_06.jpg)

###### 图 2B.6：练习 1 默认输出

1.  直接打开`speak()`和`act()`。对于一个小程序来说这是可以的。但是当游戏扩大到几十甚至上百个角色时，就会变得难以管理。因此，我们需要将所有角色抽象出来。在文件顶部添加以下接口声明：

```cpp
class ICharacter
{
public:
    ~ICharacter() {
        std::cout << "Destroying Character\n";
    }
    virtual void speak() = 0;
    virtual void act() = 0;
};
```

通常，析构函数将是空的，但在这里，它有日志来显示行为。

1.  从这个接口类派生`Wizard`、`Healer`和`Warrior`类，并在每个类的`speak()`和`act()`函数声明末尾添加`override`关键字：

```cpp
class Wizard : public Icharacter { ...
```

1.  点击**运行**按钮重新构建和运行练习。现在我们将看到在派生类的析构函数之后也调用了基类的析构函数：![图 2B.7：修改后程序的输出](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_02B_07.jpg)

###### 图 2B.7：修改后程序的输出

1.  创建角色并在容器中管理它们，比如`vector`。在`main()`函数之前在文件中创建以下两个方法：

```cpp
void createCharacters(std::vector<ICharacter*>& cast)
{
    cast.push_back(new Wizard("Gandalf"));
    cast.push_back(new Healer("Glenda"));
    cast.push_back(new Warrior("Ben Grimm"));
}
void freeCharacters(std::vector<ICharacter*>& cast)
{
    for(auto* character : cast)
    {
        delete character;
    }
    cast.clear();
}
```

1.  用以下代码替换`main()`的内容：

```cpp
int main(int argc, char**argv)
{
    std::cout << "\n------ Exercise 1 ------\n";
    std::vector<ICharacter*> cast;
    createCharacters(cast);
    for(auto* character : cast)
    {
        character->speak();
    }
    for(auto* character : cast)
    {
        character->act();
    }
    freeCharacters(cast);
    std::cout << "Complete.\n";
    return 0;
}
```

1.  点击**运行**按钮重新构建和运行练习。以下是生成的输出：![图 2B.8：多态版本的输出](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_02B_08.jpg)

###### 图 2B.8：多态版本的输出

从上面的截图中可以看出，“销毁巫师”等日志已经消失了。问题在于容器保存了指向基类的指针，并且不知道如何在每种情况下调用完整的析构函数。

1.  为了解决这个问题，只需将`ICharacter`的析构函数声明为虚函数：

```cpp
virtual ~ICharacter() {
```

1.  点击**运行**按钮重新构建和运行练习。输出现在如下所示：

![图 2B.9：完整多态版本的输出](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_02B_09.jpg)

###### 图 2B.9：完整多态版本的输出

我们现在已经为我们的`ICharacter`角色实现了一个接口，并通过在容器中存储基类指针简单地调用`speak()`和`act()`方法进行了多态使用。

### 类、结构体和联合体再讨论

之前我们讨论过类和结构体的区别是默认访问修饰符 - 类的为私有，结构体的为公共。这个区别更进一步 - 如果基类没有指定任何内容，它将应用于基类：

```cpp
class DerivedC : Base  // inherits as if "class DerivedC : private Base" was used
{
};
struct DerivedS : Base // inherits as if "struct DerivedS : public Base" was used
{
};
```

应该注意的是，联合既不能是基类，也不能从基类派生。如果结构和类之间本质上没有区别，那么我们应该使用哪种类型？本质上，这是一种惯例。**结构**用于捆绑几个相关的元素，而**类**可以执行操作并具有责任。结构的一个例子如下：

```cpp
struct Point     // A point in 3D space
{
  double m_x;
  double m_y;
  double m_z;
};
```

在前面的代码中，我们可以看到它将三个坐标组合在一起，这样我们就可以推断出三维空间中的一个点。这个结构可以作为一个连贯的数据集传递给需要点的方法，而不是每个点的三个单独的参数。另一方面，类模拟了一个可以执行操作的对象。看看下面的例子：

```cpp
class Matrix
{
public:
  Matrix& operator*(const Matrix& rhs)
  {
     // nitty gritty of the multiplication
  }
private:
  // Declaration of the 2D array to store matrix.
};
```

经验法则是，如果至少有一个私有成员，则应使用类，因为这意味着实现的细节将在公共成员函数的后面。

## 可见性、生命周期和访问

我们已经讨论了创建自己的类型和声明变量和函数，主要关注简单函数和单个文件。现在我们将看看当有多个包含类和函数定义的源文件（翻译单元）时会发生什么。此外，我们将检查哪些变量和函数可以从源文件的其他部分可见，变量的生存周期有多长，并查看内部链接和外部链接之间的区别。在*第一章*，*可移植 C++软件的解剖学*中，我们看到了工具链是如何工作的，编译源文件并生成目标文件，链接器将其全部组合在一起形成可执行程序。

当编译器处理源文件时，它会生成一个包含转换后的 C++代码和足够信息的目标文件，以便链接器解析已编译源文件到另一个源文件的任何引用。在*第一章*，*可移植 C++软件的解剖学*中，`sum()`在**SumFunc.cpp**文件中定义。当编译器构建目标文件时，它创建以下段：

+   **代码段**（也称为文本）：这是 C++函数翻译成目标机器指令的结果。

+   **数据段**：这包含程序中声明的所有变量和数据结构，不是本地的或从堆栈分配的，并且已初始化。

+   **BSS 段**：这包含程序中声明的所有变量和数据结构，不是本地的或从堆栈分配的，并且未初始化（但将初始化为零）。

+   **导出符号数据库**：此对象文件中的变量和函数列表及其位置。

+   **引用符号数据库**：此对象文件需要从外部获取的变量和函数列表以及它们的使用位置。

#### 注意

BSS 用于命名未初始化的数据段，其名称历史上源自 Block Started by Symbol。

然后，链接器将所有代码段、数据段和**BSS**段收集在一起形成程序。它使用两个数据库（DB）中的信息将所有引用的符号解析为导出的符号列表，并修补代码段，使其能够正确运行。从图形上看，这可以表示如下：

![图 2B.10：目标文件和可执行文件的部分](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_02B_10.jpg)

###### 图 2B.10：目标文件和可执行文件的部分

为了后续讨论的目的，BSS 和数据段将简称为数据段（唯一的区别是 BSS 未初始化）。当程序执行时，它被加载到内存中，其内存看起来有点像可执行文件布局 - 它包含文本段、数据段、BSS 段以及主机系统分配的空闲内存，其中包含所谓的**堆栈**和**堆**。堆栈通常从内存顶部开始并向下增长，而堆从 BSS 结束的地方开始并向上增长，朝向堆栈：

![图 2B.11：CxxTemplate 运行时内存映射](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_02B_11.jpg)

###### 图 2B.11：CxxTemplate 运行时内存映射

变量或标识符可访问的程序部分称为**作用域**。作用域有两个广泛的类别：

+   `{}`). 变量可以在大括号内部访问。就像块可以嵌套一样，变量的作用域也可以嵌套。这通常包括局部变量和函数参数，这些通常存储在堆栈中。

+   **全局/文件作用域**：这适用于在普通函数或类之外声明的变量，以及普通函数。可以在文件中的任何地方访问变量，并且如果链接正确，可能还可以从其他文件（全局）访问。这些变量由链接器在数据段中分配内存。标识符被放入全局命名空间，这是默认命名空间。

### 命名空间

我们可以将命名空间看作是变量、函数和用户定义类型的名称字典。对于小型程序，使用全局命名空间是可以的，因为很少有可能创建多个具有相同名称并发生名称冲突的变量。随着程序变得更大，并且包含了更多的第三方库，名称冲突的机会增加。因此，库编写者将他们的代码放入一个命名空间（希望是唯一的）。这允许程序员控制对命名空间中标识符的访问。通过使用标准库，我们已经在使用 std 命名空间。命名空间的声明如下：

```cpp
namespace name_of_namespace {  // put declarations in here }
```

通常，name_of_namespace 很短，命名空间可以嵌套。

#### 注意

在 boost 库中可以看到命名空间的良好使用：[`www.boost.org/`](https://www.boost.org/)。

变量还有另一个属性，即**寿命**。有三种基本寿命；两种由编译器管理，一种由程序员选择：

+   **自动寿命**：局部变量在声明时创建，并在退出其所在的作用域时被销毁。这些由堆栈管理。

+   **永久寿命**：全局变量和静态局部变量。编译器在程序开始时（进入 main()函数之前）创建全局变量，并在首次访问静态局部变量时创建它们。在这两种情况下，变量在程序退出时被销毁。这些变量由链接器放置在数据段中。

+   `new`和`delete`）。这些变量的内存是从堆中分配的。

我们将考虑的变量的最终属性是**链接**。链接指示编译器和链接器在遇到具有相同名称（或标识符）的变量和函数时会执行什么操作。对于函数，实际上是所谓的重载名称 - 编译器使用函数的名称、返回类型和参数类型来生成重载名称。有三种类型的链接：

+   **无链接**：这意味着标识符只引用自身，并适用于局部变量和本地定义的用户类型（即在块内部）。

+   **内部链接**：这意味着可以在声明它的文件中的任何地方访问该标识符。这适用于静态全局变量、const 全局变量、静态函数以及文件中匿名命名空间中声明的任何变量或函数。匿名命名空间是一个没有指定名称的命名空间。

+   **外部链接**：这意味着在正确的前向声明的情况下，可以从所有文件中访问它。这包括普通函数、非静态全局变量、extern const 全局变量和用户定义类型。

虽然这些被称为链接，但只有最后一个实际上涉及链接器。其他两个是通过编译器排除导出标识符数据库中的信息来实现的。

## 模板-泛型编程

作为计算机科学家或编程爱好者，您可能在某个时候不得不编写一个（或多个）排序算法。在讨论算法时，您可能并不特别关心正在排序的数据类型，只是该类型的两个对象可以进行比较，并且该域是一个完全有序的集合（也就是说，如果一个对象与任何其他对象进行比较，您可以确定哪个排在前面）。不同的编程语言为这个问题提供了不同的解决方案：

+   `swap`函数。

+   `void 指针`。`size_t`大小定义了每个对象的大小，而`compare()`函数定义了如何比较这两个对象。

+   `std::sort()`是标准库中提供的一个函数，其中一个签名如下：

```cpp
template< class RandomIt > void sort( RandomIt first, RandomIt last );
```

在这种情况下，类型的细节被捕获在名为`RandomIt`的迭代器类型中，并在编译时传递给方法。

在下一节中，我们将简要定义泛型编程，展示 C++如何通过模板实现它们，突出语言已经提供的内容，并讨论编译器如何推断类型，以便它们可以用于模板。

### 什么是泛型编程？

当您开发排序算法时，您可能最初只关注对普通数字的排序。但一旦建立了这一点，您就可以将其抽象为任何类型，只要该类型具有某些属性，例如完全有序集（即比较运算符<在我们正在排序的域中的所有元素之间都有意义）。因此，为了以泛型编程的方式表达算法，我们在算法中为需要由该算法操作的类型定义了一个占位符。

**泛型编程**是开发一种类型不可知的通用算法。通过传递类型作为参数，可以重用该算法。这样，算法被抽象化，并允许编译器根据类型进行优化。

换句话说，泛型编程是一种编程方法，其中算法是以参数化的类型定义的，当实例化算法时指定了参数。许多语言提供了不同名称的泛型编程支持。在 C++中，泛型编程是通过模板这种语言特性来支持的。

### 介绍 C++模板

模板是 C++对泛型编程的支持。把模板想象成一个饼干模具，我们给它的类型参数就像饼干面团（可以是巧克力布朗尼、姜饼或其他美味口味）。当我们使用饼干模具时，我们得到的饼干实例形式相同，但口味不同。因此，模板捕获了泛型函数或类的定义，当指定类型参数时，编译器会根据我们手动编码的类型来为我们编写类或函数。它有几个优点，例如：

+   您只需要开发一次类或算法，然后进行演化。

+   您可以将其应用于许多类型。

+   您可以将复杂细节隐藏在简单的接口后，编译器可以根据类型对生成的代码进行优化。

那么，我们如何编写一个模板呢？让我们从一个模板开始，它允许我们将值夹在从`lo`到`hi`的范围内，并且能够在`int`、`float`、`double`或任何其他内置类型上使用它：

```cpp
template <class T>
T clamp(T val, T lo, T hi)
{
  return (val < lo) ? lo : (hi < val) ? hi : val;
}
```

让我们来分解一下：

+   `template <class T>`声明接下来是一个模板，并使用一个类型，模板中有一个`T`的占位符。

+   `T`被替换。它声明函数 clamp 接受三个类型为`T`的参数，并返回类型为`T`的值。

+   `<`运算符，然后我们可以对三个值执行 clamp，使得`lo <= val <= hi`。这个算法对所有可以排序的类型都有效。

假设我们在以下程序中使用它：

```cpp
#include <iostream>
int main()
{
    std::cout << clamp(5, 3, 10) << "\n";
    std::cout << clamp(3, 5, 10) << "\n";
    std::cout << clamp(13, 3, 10) << "\n";
    std::cout << clamp(13.0, 3.0, 10.1) << "\n";
    std::cout << clamp<double>(13.0, 3, 10.2) << "\n";
    return 0;
}
```

我们将得到以下预期输出：

![图 2B.12：Clamp 程序输出](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_02B_12.jpg)

###### 图 2B.12：Clamp 程序输出

在最后一次调用 clamp 时，我们在`<`和`>`之间传递了 double 类型的模板。但是我们没有对其他四个调用遵循相同的方式。为什么？原来编译器随着年龄的增长变得越来越聪明。随着每个标准的发布，它们改进了所谓的**类型推导**。因为编译器能够推断类型，我们不需要告诉它使用什么类型。这是因为类的三个参数没有模板参数，它们具有相同的类型 - 前三个都是 int，而第四个是 double。但是我们必须告诉编译器使用最后一个的类型，因为它有两个 double 和一个 int 作为参数，这导致编译错误说找不到函数。但是然后，它给了我们关于为什么不能使用模板的信息。这种形式，你强制类型，被称为**显式模板参数规定**。

### C++预打包模板

C++标准由两个主要部分组成：

+   语言定义，即关键字、语法、词法定义、结构等。

+   标准库，即编译器供应商提供的所有预先编写的通用函数和类。这个库的一个子集是使用模板实现的，被称为**标准模板库**（**STL**）。

STL 起源于 Ada 语言中提供的泛型，该语言由 David Musser 和 Alexander Stepanov 开发。Stepanov 是泛型编程作为软件开发基础的坚定支持者。在 90 年代，他看到了用新语言 C++来影响主流开发的机会，并建议 ISO C++委员会应该将 STL 作为语言的一部分包含进去。其余的就是历史了。

STL 由四类预定义的通用算法和类组成：

+   **容器**：通用序列（vector，list，deque）和关联容器（set，multiset，map）

+   `begin()`和`end()`）。请注意，STL 中的一个基本设计选择是`end()`指向最后一项之后的位置 - 在数学上，即`begin()`，`end()`)。

+   **算法**：涵盖排序、搜索、集合操作等 100 多种不同算法。

+   `find_if()`.

我们之前实现的 clamp 函数模板是简单的，虽然它适用于支持小于运算符的任何类型，但它可能不太高效 - 如果类型具有较大的大小，可能会导致非常大的副本。自 C++17 以来，STL 包括一个`std::clamp()`函数，声明更像这样：

```cpp
#include <cassert>
template<class T, class Compare>
const T& clamp( const T& v, const T& lo, const T& hi, Compare comp )
{
    return assert( !comp(hi, lo) ),
        comp(v, lo) ? lo : comp(hi, v) ? hi : v;
}
template<class T>
const T& clamp( const T& v, const T& lo, const T& hi )
{
    return clamp( v, lo, hi, std::less<>() );
}
```

正如我们所看到的，它使用引用作为参数和返回值。将参数更改为使用引用减少了需要传递和返回的堆栈上的内容。还要注意，设计者们努力制作了模板的更通用版本，这样我们就不会依赖于类型存在的<运算符。然而，我们可以通过传递 comp 来定义排序。

从前面的例子中，我们已经看到，像函数一样，模板可以接受多个逗号分隔的参数。

## 类型别名 - typedef 和 using

如果您使用了`std::string`类，那么您一直在使用别名。有一些与字符串相关的模板类需要实现相同的功能。但是表示字符的类型是不同的。例如，对于`std::string`，表示是`char`，而`std::wstring`使用`wchar_t`。还有一些其他的用于`char16_t`和`char32_t`。任何功能上的变化都将通过特性或模板特化来管理。

在 C++11 之前，这将从`std::basic_string`基类中进行别名处理，如下所示：

```cpp
namespace std {
  typedef basic_string<char> string;
}
```

这做了两件主要的事情：

+   减少声明变量所需的输入量。这是一个简单的情况，但是当你声明一个指向字符串到对象的映射的唯一指针时，可能会变得非常长，你会犯错误：

```cpp
typedef std::unique_ptr<std::map<std::string,myClass>> UptrMapStrToClass;
```

+   提高了可读性，因为现在你在概念上将其视为一个字符串，不需要担心细节。

但是 C++11 引入了一种更好的方式 - `别名声明` - 它利用了`using`关键字。前面的代码可以这样实现：

```cpp
namespace std {
  using string = basic_string<char>;
}
```

前面的例子很简单，别名，无论是 typedef 还是 using，都不太难理解。但是当别名涉及更复杂的表达式时，它们也可能有点难以理解 - 特别是函数指针。考虑以下代码：

```cpp
typedef int (*FunctionPointer)(const std::string&, const Point&); 
```

现在，考虑以下代码：

```cpp
using FunctionPointer = int (*)(const std::string&, const Point&);
```

C++11 中有一个新功能，即别名声明可以轻松地并入模板中 - 它们可以被模板化。`typedef`不能被模板化，虽然可以通过`typedef`实现相同的结果，但别名声明（`using`）是首选方法，因为它会导致更简单、更易于理解的模板代码。

### 练习 2：实现别名

在这个练习中，我们将使用 typedef 实现别名，并看看通过使用引用使代码变得更容易阅读和高效。按照以下步骤实现这个练习：

1.  在 Eclipse 中打开**Lesson2B**项目，然后在项目资源管理器中展开**Lesson2B**，然后展开**Exercise02**，双击**Exercise2.cpp**以在编辑器中打开此练习的文件。

1.  单击**启动配置**下拉菜单，然后选择**新启动配置...**。配置**L2BExercise2**以使用名称**Exercise2**运行。完成后，它将成为当前选择的启动配置。

1.  单击**运行**按钮。**Exercise 2**将运行并产生类似以下输出：

![图 2B.13：练习 2 输出](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_02B_13.jpg)

###### 图 2B.13：练习 2 输出 1.  

在编辑器中，在`printVector()`函数的声明之前，添加以下行：

```cpp    
typedef std::vector<int> IntVector;    
```

1.  现在，将文件中所有的`std::vector<int>`更改为`IntVector`。

1.  单击**运行**按钮。输出应与以前相同。

1.  在编辑器中，更改之前添加的行为以下内容：

```cpp    
using IntVector = std::vector<int>;    
```

1.  单击**运行**按钮。输出应与以前相同。

1.  在编辑器中，添加以下行：

```cpp    
using IntVectorIter = std::vector<int>::iterator;    
```

1.  现在，将`IntVector::iterator`的一个出现更改为`IntVectorIter`。

1.  单击**运行**按钮。输出应与以前相同。

在这个练习中，typedef 和使用别名似乎没有太大区别。在任何一种情况下，使用一个命名良好的别名使得代码更容易阅读和理解。当涉及更复杂的别名时，`using`提供了一种更容易编写别名的方法。在 C++11 中引入，`using`现在是定义别名的首选方法。它还比`typedef`有其他优点，例如能够在模板内部使用它。

## 模板 - 不仅仅是泛型

编程模板还可以提供比泛型编程更多的功能（一种带有类型的模板）。在泛型编程的情况下，模板作为一个不能更改的蓝图运行，并为指定的类型或类型提供模板的编译版本。

模板可以被编写以根据涉及的类型提供函数或算法的特化。这被称为**模板特化**，并不是我们先前使用的意义上的通用编程。只有当它使某些类型在给定上下文中表现得像我们期望它们在某个上下文中表现得一样时，它才能被称为通用编程。当用于所有类型的算法被修改时，它不能被称为通用编程。检查以下专业化代码的示例：

```cpp
#include <iostream>
#include <type_traits>
template <typename T, std::enable_if_t<sizeof(T) == 1, int> = 0>
void print(T val){
    printf("%c\n", val);
}
template <typename T, std::enable_if_t<sizeof(T) == sizeof(int), int> = 0>
void print(T val){    
    printf("%d\n", val);
}
template <typename T, std::enable_if_t<sizeof(T) == sizeof(double), int> = 0>
void print(T val){    
    printf("%f\n", val);
}
int main(int argc, char** argv){    
    print('c');    
    print(55);    
    print(32.1F);    
    print(77.3);
}
```

它定义了一个模板，根据使用`std::enable_if_t<>`和`sizeof()`的模板的特化，调用`printf()`并使用不同的格式字符串。当我们运行它时，会生成以下输出：

![图 2B.14：错误的打印模板程序输出](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_02B_14.jpg)

###### 图 2B.14：错误的打印模板程序输出

### 替换失败不是错误 - SFINAE

对于`32.1F`打印的值（`-1073741824`）与数字毫不相干。如果我们检查编译器为以下程序生成的代码，我们会发现它生成的代码就好像我们写了以下内容（以及更多）：

```cpp
template<typename int, int=0>
void print<int,0>(int val)
{
    printf("%d\n",val);
}
template<typename float, int=0>
void print<float,0>(float val)
{
    printf("%d\n", val);
}
```

为什么会生成这段代码？前面的模板使用了 C++编译器的一个特性，叫做`std::enable_if_t<>`，并访问了所谓的**类型特征**来帮助我们。首先，我们将用以下代码替换最后一个模板：

```cpp
#include <type_traits>
template <typename T, std::enable_if_t<std::is_floating_point_v<T>, int> = 0>
void print(T val)
{
    printf("%f\n", val);
}
```

这需要一些解释。首先，我们考虑`std::enable_if_t`的定义，实际上是一个类型别名：

```cpp
template<bool B, class T = void>
struct enable_if {};
template<class T>
struct enable_if<true, T> { typedef T type; };
template< bool B, class T = void >
using enable_if_t = typename enable_if<B,T>::type;
```

`enable_if`的第一个模板将导致定义一个空的结构体（或类）。`enable_if`的第二个模板是对 true 的第一个模板参数的特化，将导致具有 typedef 定义的类。`enable_if_t`的定义是一个帮助模板，它消除了我们在使用它时需要在模板末尾输入`::type`的需要。那么，这是如何工作的呢？考虑以下代码：

```cpp
template <typename T, std::enable_if_t<condition, int> = 0>
void print(T val) { … }
```

如果在编译时评估的条件导致`enable_if_t`模板将导致一个看起来像这样的模板：

```cpp
template <typename T, int = 0>
void print(T val) { … }
```

这是有效的语法，函数被添加到符号表作为候选函数。如果在编译时计算的条件导致`enable_if_t`模板将导致一个看起来像这样的模板：

```cpp
template <typename T, = 0>
void print(T val) { … }
```

这是**格式错误的代码**，现在被丢弃了 - SFINAE 在起作用。

`std::is_floating_point_v<T>`是另一个访问`std::is_floating_point<T>`模板的`::value`成员的帮助类。它的名字说明了一切 - 如果 T 是浮点类型（float、double、long double），它将为 true；否则，它将为 false。如果我们进行这个改变，那么编译器（GCC）会生成以下错误：

![图 2B.15：修改后的打印模板程序的编译器错误](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_02B_15.jpg)

###### 图 2B.15：修改后的打印模板程序的编译器错误

现在的问题是，当类型是浮点数时，我们有两个可以满足的模板：

```cpp
template <typename T, std::enable_if_t<sizeof(T) == sizeof(int), int> = 0>
void print(T val)
{
    printf("%d\n", val);
}
template <typename T, std::enable_if_t<std::is_floating_point_v<T>, int> = 0>
void print(T val)
{
    printf("%f\n", val);
}
```

事实证明，通常情况下`sizeof(float) == sizeof(int)`，所以我们需要做另一个改变。我们将用另一个类型特征`std::is_integral_v<>`替换第一个条件：

```cpp
template <typename T, std::enable_if_t<std::is_integral_v<T>, int> = 0>
void print(T val)
{
    printf("%d\n", val);
}
```

如果我们进行这个改变，那么编译器（GCC）会生成以下错误：

![图 2B.16：修改后的打印模板程序的第二个编译器错误](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_02B_16.jpg)

###### 图 2B.16：修改后的打印模板程序的第二个编译器错误

我们解决了浮点数的歧义，但这里的问题是`std::is_integral_v(char)`返回 true，再次生成了具有相同原型的模板函数。原来传递给`std::enable_if_t<>`的条件遵循标准 C++逻辑表达式。因此，为了解决这个问题，我们将添加一个额外的条件来排除字符：

```cpp
template <typename T, std::enable_if_t<std::is_integral_v<T> && sizeof(T) != 1, int> = 0>
void print(T val)
{
    printf("%d\n", val);
}
```

如果我们现在编译程序，它完成编译并链接程序。如果我们运行它，它现在会产生以下（预期的）输出：

![图 2B.17：修正的打印模板程序输出](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_02B_17.jpg)

###### 图 2B.17：修正的打印模板程序输出

### 浮点表示

`32.099998`不应该是`32.1`吗？这是传递给函数的值。在计算机上执行浮点运算的问题在于，表示自动引入了误差。实数形成一个连续（无限）的域。如果你考虑实域中的数字 1 和 2，那么它们之间有无限多个实数。不幸的是，计算机对浮点数的表示量化了这些值，并且无法表示所有无限数量的数字。用于存储数字的位数越多，值在实域上的表示就越好。因此，long double 比 double 好，double 比 float 好。对于存储数据来说，真正取决于您的问题域。回到`32.099998`。计算机将单精度数存储为 2 的幂的和，然后将它们移位一个幂因子。整数通常很容易，因为它们可以很容易地表示为`2^n`的和（n>=0）。在这种情况下的小数部分，即 0.1，必须表示为`2^(-n) (n>0)`的和。我们添加更多的 2 的幂分数，以尝试使数字更接近目标，直到我们用完了单精度浮点数中的 24 位精度。

#### 注意

如果您想了解计算机如何存储浮点数，请研究定义它的 IEEE 754 标准。

### Constexpr if 表达式

C++17 引入了`constexpr if`表达式到语言中，大大简化了模板编写。我们可以将使用 SFINAE 的前面三个模板重写为一个更简单的模板：

```cpp
#include <iostream>
#include <type_traits>
template <typename T>
void print(T val)
{
   if constexpr(sizeof(T)==1) {
      printf("%c",val);
   }
   else if constexpr(std::is_integral_v<T>) {
      printf("%d",val);
   }
   else if constexpr(std::is_floating_point_v<T>) {
      printf("%f",val);
   }
   printf("\n");
}
int main(int argc, char** argv)
{
    print('c');
    print(55);
    print(32.1F);
    print(77.3);
}
```

对于对`print(55)`的调用，编译器生成的函数调用如下：

```cpp
template<>
void print<int>(int val)
{
    printf("%d",val);
    printf("\n");
}
```

if/else if 语句发生了什么？`constexpr if`表达式的作用是，编译器在上下文中确定条件的值，并将其转换为布尔值（true/false）。如果评估的值为 true，则 if 条件和 else 子句被丢弃，只留下 true 子句生成代码。同样，如果为 false，则留下 false 子句生成代码。换句话说，只有第一个 constexpr if 条件评估为 true 时，才会生成其子句的代码，其余的都会被丢弃。

### 非类型模板参数

到目前为止，我们只看到了作为模板参数的类型。还可以将整数值作为模板参数传递。这允许我们防止函数的数组衰减。例如，考虑一个计算`sum`的模板函数：

```cpp
template <class T>
T sum(T data[], int number)
{
  T total = 0;
  for(auto i=0U ; i<number ; i++)
  {
    total += data[i];
  }
  return total;
}
```

在这种情况下，我们需要在调用中传递数组的长度：

```cpp
float data[5] = {1.1, 2.2, 3.3, 4.4, 5.5};
auto total = sum(data, 5);
```

但是，如果我们只能调用以下内容会不会更好呢？

```cpp
auto total = sum(data);
```

我们可以通过对模板进行更改来实现，就像下面的代码一样：

```cpp
template <class T, std::size_t size>
T sum(T (&data)[size])
{
  T total = 0;
  for(auto i=0U ; i< size; i++)
  {
    total += data[i];
  }
  return total;
}
```

在这里，我们将数据更改为对模板传递的特定大小的数组的引用，因此编译器会自行解决。我们不再需要函数调用的第二个参数。这个简单的例子展示了如何直接传递和使用非类型参数。我们将在*模板类型推导*部分进一步探讨这个问题。

### 练习 3：实现 Stringify - 专用与 constexpr

在这个练习中，我们将利用 constexpr 实现一个 stringify 模板，以生成一个更易读和更简单的代码版本。按照以下步骤实现这个练习：

#### 注意

可以在[`isocpp.org/wiki/faq/templates#template-specialization-example`](https://isocpp.org/wiki/faq/templates#template-specialization-example)找到 stringify 专用模板。

1.  在 Eclipse 中打开**Lesson2B**项目，然后在**项目资源管理器**中展开**Lesson2B**，然后展开**Exercise03**，双击**Exercise3.cpp**以在编辑器中打开此练习的文件。

1.  单击**启动配置**下拉菜单，选择**新启动配置...**。配置**L2BExercise3**以使用名称**Exercise3**运行。

1.  单击**运行**按钮。**练习 3**将运行并产生以下输出：![图 2B.18：练习 3 特化模板输出](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_02B_18.jpg)

###### 图 2B.18：练习 3 特化模板输出

1.  在**Exercise3.cpp**中，将 stringify 模板的所有特化模板注释掉，同时保留原始的通用模板。

1.  单击**运行**按钮。输出将更改为将布尔型打印为数字，将双精度浮点数打印为仅有两位小数：![图 2B.19：练习 3 仅通用模板输出](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_02B_19.jpg)

###### 图 2B.19：练习 3 仅通用模板输出

1.  我们现在将再次为布尔类型“特化”模板。在其他`#includes`中添加`#include <type_traits>`指令，并修改模板，使其如下所示：

```cpp
template<typename T> std::string stringify(const T& x)
{
  std::ostringstream out;
  if constexpr (std::is_same_v<T, bool>)
  {
      out << std::boolalpha;
  }
  out << x;
  return out.str();
}
```

1.  单击**运行**按钮。布尔型的 stringify 输出与以前一样：![图 2B.20：针对布尔型定制的 stringify](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_02B_20.jpg)

###### 图 2B.20：针对布尔型定制的 stringify

1.  我们现在将再次为浮点类型（`float`、`double`、`long double`）“特化”模板。修改模板，使其如下所示：

```cpp
template<typename T> std::string stringify(const T& x)
{
  std::ostringstream out;
  if constexpr (std::is_same_v<T, bool>)
  {
      out << std::boolalpha;
  }
  else if constexpr (std::is_floating_point_v<T>)
  {
      const int sigdigits = std::numeric_limits<T>::digits10;
      out << std::setprecision(sigdigits);
  }
  out << x;
  return out.str();
}
```

1.  单击**运行**按钮。输出恢复为原始状态：![图 2B.21：constexpr if 版本模板输出](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_02B_21.jpg)

###### 图 2B.21：constexpr if 版本模板输出

1.  如果您将多个模板的原始版本与最终版本进行比较，您会发现最终版本更像是一个普通函数，更易于阅读和维护。

在这个练习中，我们学习了在 C++17 中使用新的 constexpr if 结构时，模板可以变得更简单和紧凑。

### 函数重载再探讨

当我们首次讨论函数重载时，我们只考虑了函数名称来自我们手动编写的函数列表的情况。现在，我们需要更新这一点。我们还可以编写可以具有相同名称的模板函数。就像以前一样，当编译器遇到`print(55)`这一行时，它需要确定调用先前定义的函数中的哪一个。因此，它执行以下过程（大大简化）：

![图 2B.22：模板的函数重载解析（简化版）](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_02B_22.jpg)

###### 图 2B.22：模板的函数重载解析（简化版）

### 模板类型推断

当我们首次介绍模板时，我们涉及了模板类型推断。现在，我们将进一步探讨这一点。我们将从考虑函数模板的一般声明开始：

```cpp
template<typename T>
void function(ParamType parameter);
```

此调用可能如下所示：

```cpp
function(expression);              // deduce T and ParamType from expression
```

当编译器到达这一行时，它现在必须推断与模板相关的两种类型—`T`和`ParamType`。由于 T 在 ParamType 中附加了限定符和其他属性（例如指针、引用、const 等），它们通常是不同的。这些类型是相关的，但推断的过程取决于所使用的`expression`的形式。

### 显示推断类型

在我们研究不同形式之前，如果我们能让编译器告诉我们它推断出的类型，那将非常有用。我们有几种选择，包括 IDE 编辑器显示类型、编译器生成错误和运行时支持（由于 C++标准的原因，这不一定有效）。我们将使用编译器错误来帮助我们探索一些类型推断。

我们可以通过声明一个没有定义的模板来实现类型显示器。任何尝试实例化模板都将导致编译器生成错误消息，因为没有定义，以及它正在尝试实例化的类型信息：

```cpp
template<typename T>
struct TypeDisplay;
```

让我们尝试编译以下程序：

```cpp
template<typename T>
class TypeDisplay;
int main()
{
    signed int x = 1;
    unsigned int y = 2;
    TypeDisplay<decltype(x)> x_type;
    TypeDisplay<decltype(y)> y_type;
    TypeDisplay<decltype(x+y)> x_y_type;
    return 0;
}
```

编译器输出以下错误：

![图 2B.23：显示推断类型的编译器错误](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_02B_23.jpg)

###### 图 2B.23：显示推断类型的编译器错误

请注意，在每种情况下，被命名的聚合包括被推断的类型 - 对于 x，它是一个 int，对于 y，是一个 unsigned int，对于 x+y，是一个 unsigned int。还要注意，TypeDisplay 模板需要其参数的类型，因此使用`decltype()`函数来获取编译器提供括号中表达式的类型。

还可以使用内置的`typeid(T).name()`运算符在运行时显示推断的类型，它返回一个 std::string，或者使用名为 type_index 的 boost 库。

#### 注意

有关更多信息，请访问以下链接：[`www.boost.org/doc/libs/1_70_0/doc/html/boost_typeindex.html`](https://www.boost.org/doc/libs/1_70_0/doc/html/boost_typeindex.html)。

由于类型推断规则，内置运算符将为您提供类型的指示，但会丢失引用（`&`和`&&`）和任何 constness 信息（const 或 volatile）。如果需要在运行时，考虑使用`boost::type_index`，它将为所有编译器产生相同的输出。

### 模板类型推断 - 详细信息

让我们回到通用模板：

```cpp
template<typename T>
void function(ParamType parameter);
```

假设调用看起来像这样：

```cpp
function(expression);             // deduce T and ParamType from expression
```

类型推断取决于 ParamType 的形式：

+   **ParamType 是值（T）**：按值传递函数调用

+   **ParamType 是引用或指针（T&或 T*）**：按引用传递函数调用

+   **ParamType 是右值引用（T&&）**：按引用传递函数调用或其他内容

**情况 1：ParamType 是按值传递（T）**

```cpp
template<typename T>
void function(T parameter);
```

作为按值传递的调用，这意味着参数将是传入内容的副本。因为这是对象的新实例，所以以下规则适用于表达式：

+   如果表达式的类型是引用，则忽略引用部分。

+   如果在步骤 1 之后，剩下的类型是 const 和/或 volatile，则也忽略它们。

剩下的是 T。让我们尝试编译以下文件代码：

```cpp
template<typename T>
class TypeDisplay;
template<typename T>
void function(T parameter)
{
    TypeDisplay<T> type;
}
void types()
{
    int x = 42;
    function(x);
}
```

编译器产生以下错误：

![图 2B.24：显示按类型推断类型的编译器错误](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_02B_24.jpg)

###### 图 2B.24：显示按类型推断类型的编译器错误

因此，类型被推断为`int`。同样，如果我们声明以下内容，我们将得到完全相同的错误：

```cpp
const int x = 42;
function(x);
```

如果我们声明这个版本，同样的情况会发生：

```cpp
int x = 42;
const int& rx = x;
function(rx);
```

在所有三种情况下，根据先前规定的规则，推断的类型都是`int`。

**情况 2：ParamType 是按引用传递（T&）**

作为按引用传递的调用，这意味着参数将能够访问对象的原始存储位置。因此，生成的函数必须遵守我们之前忽略的 constness 和 volatileness。类型推断适用以下规则：

+   如果表达式的类型是引用，则忽略引用部分。

+   模式匹配表达式类型的剩余部分与 ParamType 以确定 T。

让我们尝试编译以下文件：

```cpp
template<typename T>
class TypeDisplay;
template<typename T>
void function(T& parameter)
{
    TypeDisplay<T> type;
}
void types()
{
    int x = 42;
    function(x);
}
```

编译器将生成以下错误：

![图 2B.25：显示按引用传递推断类型的编译器错误](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_02B_25.jpg)

###### 图 2B.25：显示按引用传递推断类型的编译器错误

从这里，我们可以看到编译器将 T 作为`int`，从 ParamType 作为`int&`。将 x 更改为 const int 不会有任何意外，因为 T 被推断为`const int`，从 ParamType 作为`const int&`：

![图 2B.26：显示按 const 引用传递推断类型的编译器错误](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_02B_26.jpg)

###### 图 2B.26：传递 const 引用时显示推断类型的编译器错误

同样，像之前一样引入 rx 作为对 const int 的引用，不会有令人惊讶的地方，因为 T 从 ParamType 作为`const int&`推断为`const int`：

```cpp
void types()
{
    const int x = 42;
    const int& rx = x;
    function(rx);
}
```

![图 2B.27：传递 const 引用时显示推断类型的编译器错误](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_02B_27.jpg)

###### 图 2B.27：传递 const 引用时显示推断类型的编译器错误

如果我们改变声明以包括一个 const，那么编译器在从模板生成函数时将遵守 constness：

```cpp
template<typename T>
void function(const T& parameter)
{
    TypeDisplay<T> type;
}
```

这次，编译器报告如下

+   `int x`：T 是 int（因为 constness 将被尊重），而参数的类型是`const int&`。

+   `const int x`：T 是 int（const 在模式中，留下 int），而参数的类型是`const int&`。

+   `const int& rx`：T 是 int（引用被忽略，const 在模式中，留下 int），而参数的类型是`const int&`。

如果我们尝试编译以下内容，我们期望会发生什么？通常，数组会衰减为指针：

```cpp
int ary[15];
function(ary);
```

编译器错误如下：

![图 2B.28：传递数组参数时显示推断类型的编译器错误传递引用时](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_02B_28.jpg)

###### 图 2B.28：传递引用时显示数组参数的推断类型的编译器错误

这次，数组被捕获为引用，并且大小也被包括在内。因此，如果 ary 声明为`ary[10]`，那么将得到一个完全不同的函数。让我们将模板恢复到以下内容：

```cpp
template<typename T>
void function(T parameter)
{
    TypeDisplay<T> type;
}
```

如果我们尝试编译数组调用，那么错误报告如下：

![图 2B.29：传递数组参数时显示推断类型的编译器错误传递值时](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_02B_29.jpg)

###### 图 2B.29：传递值时显示数组参数的推断类型的编译器错误

我们可以看到，在这种情况下，数组已经衰减为传递数组给函数时的通常行为。当我们谈论*非类型模板参数*时，我们看到了这种行为。

**情况 3：ParamType 是右值引用（T&&）**

T&&被称为右值引用，而 T&被称为左值引用。C++不仅通过类型来表征表达式，还通过一种称为**值类别**的属性来表征。这些类别控制编译器中表达式的评估，包括创建、复制和移动临时对象的规则。C++17 标准中定义了五种表达式值类别，它们具有以下关系：

![图 2B.30：C++值类别](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_02B_30.jpg)

###### 图 2B.30：C++值类别

每个的定义如下：

+   决定对象身份的表达式是`glvalue`。

+   评估初始化对象或操作数的表达式是`prvalue`。例如，文字（除了字符串文字）如 3.1415，true 或 nullptr，this 指针，后增量和后减量表达式。

+   具有资源并且可以被重用（因为它的生命周期即将结束）的 glvalue 对象是`xvalue`。例如，返回类型为对象的右值引用的函数调用，如`std::move()`。

+   不是 xvalue 的 glvalue 是`lvalue`。例如，变量的名称，函数或数据成员的名称，或字符串文字。

+   prvalue 或 xvalue 是一个`rvalue`。

不要紧，如果你不完全理解这些，因为接下来的解释需要你知道什么是左值，以及什么不是左值：

```cpp
template<typename T>
void function(T&& parameter)
{
    TypeDisplay<T> type;
}
```

这种 ParamType 形式的类型推断规则如下：

+   如果表达式是左值引用，那么 T 和 ParamType 都被推断为左值引用。这是唯一一种类型被推断为引用的情况。

+   如果表达式是一个右值引用，那么适用于情况 2 的规则。

### SFINAE 表达式和尾返回类型

C++11 引入了一个名为`尾返回类型`的功能，为模板提供了一种通用返回类型的机制。一个简单的例子如下：

```cpp
template<class T>
auto mul(T a, T b) -> decltype(a * b) 
{
    return a * b;
}
```

这里，`auto`用于指示定义尾返回类型。尾返回类型以`->`指针开始，在这种情况下，返回类型是通过将`a`和`b`相乘返回的类型。编译器将处理 decltype 的内容，如果它格式不正确，它将从函数名的查找中删除定义，与往常一样。这种能力打开了许多可能性，因为逗号运算符“`,`”可以在`decltype`内部使用来检查某些属性。

如果我们想测试一个类是否实现了一个方法或包含一个类型，那么我们可以将其放在 decltype 内部，将其转换为 void（以防逗号运算符已被重载），然后在逗号运算符的末尾定义一个真实返回类型的对象。下面的程序示例中展示了这种方法：

```cpp
#include <iostream>
#include <algorithm>
#include <utility>
#include <vector>
#include <set>
template<class C, class T>
auto contains(const C& c, const T& x) 
             -> decltype((void)(std::declval<C>().find(std::declval<T>())), true)
{
    return end(c) != c.find(x);
}
int main(int argc, char**argv)
{
    std::cout << "\n\n------ SFINAE Exercise ------\n";
    std::set<int> mySet {1,2,3,4,5};
    std::cout << std::boolalpha;
    std::cout << "Set contains 5: " << contains(mySet,5) << "\n";
    std::cout << "Set contains 15: " << contains(mySet,15) << "\n";
    std::cout << "Complete.\n";
    return 0;
}
```

当编译并执行此程序时，我们将获得以下输出：

![图 2B.31：SFINAE 表达式的输出](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_02B_31.jpg)

###### 图 2B.31：SFINAE 表达式的输出

返回类型由以下代码给出：

```cpp
decltype( (void)(std::declval<C>().find(std::declval<T>())), true)
```

让我们来分解一下：

+   `decltype`的操作数是一个逗号分隔的表达式列表。这意味着编译器将构造但不评估表达式，并使用最右边的值的类型来确定函数的返回类型。

+   `std::declval<T>()`允许我们将 T 类型转换为引用类型，然后可以使用它来访问成员函数，而无需实际构造对象。

+   与所有基于 SFINAE 的操作一样，如果逗号分隔列表中的任何表达式无效，则函数将被丢弃。如果它们都有效，则将其添加到查找函数列表中。

+   将 void 转换是为了防止用户重载逗号运算符可能引发的任何问题。

+   基本上，这是在测试`C`类是否有一个名为`find()`的成员函数，该函数以`class T`、`class T&`或`const class T&`作为参数。

这种方法适用于`std::set`，它具有一个接受一个参数的`find()`方法，但对于其他容器来说会失败，因为它们没有`find()`成员方法。

如果我们只处理一种类型，这种方法效果很好。但是，如果我们有一个需要根据类型生成不同实现的函数，就像我们以前看到的那样，`if constexpr`方法更清晰，通常更容易理解。要使用`if constexpr`方法，我们需要生成在编译时评估为`true`或`false`的模板。标准库提供了这方面的辅助类：`std::true_type`和`std::false_type`。这两个结构都有一个名为 value 的静态常量成员，分别设置为`true`和`false`。使用 SFINAE 和模板重载，我们可以创建新的检测类，这些类从这些类中派生，以给出我们想要的结果：

```cpp
template <class T, class A0>
auto test_find(long) -> std::false_type;
template <class T, class A0>
auto test_find(int) 
-> decltype(void(std::declval<T>().find(std::declval<A0>())), std::true_type{});
template <class T, class A0>
struct has_find : decltype(test_find<T,A0>(0)) {};
```

`test_find`的第一个模板创建了将返回类型设置为`std::false_type`的默认行为。注意它的参数类型是`long`。

`test_find`的第二个模板创建了一个专门测试具有名为`find()`的成员函数并具有`std::true_type`返回类型的类的特化。注意它的参数类型是`int`。

`has_find<T,A0>`模板通过从`test_find()`函数的返回类型派生自身来工作。如果 T 类没有`find()`方法，则只会生成`std::false_type`版本的`test_find()`，因此`has_find<T,A0>::value`值将为 false，并且可以在`if constexpr()`中使用。

有趣的部分是，如果 T 类具有`find()`方法，则两个`test_find()`方法都会生成。但是专门的版本使用`int`类型的参数，而默认版本使用`long`类型的参数。当我们使用零（0）“调用”函数时，它将匹配专门的版本并使用它。参数的差异很重要，因为您不能有两个具有相同参数类型但仅返回类型不同的函数。如果要检查此行为，请将参数从 0 更改为 0L 以强制使用长版本。

## 类模板

到目前为止，我们只处理了函数模板。但是模板也可以用于为类提供蓝图。模板类声明的一般结构如下：

```cpp
template<class T>
class MyClass {
   // variables and methods that use T.
};
```

而模板函数允许我们生成通用算法，模板类允许我们生成通用数据类型及其相关行为。

当我们介绍标准模板库时，我们强调它包括容器的模板-`vector`，`deque`，`stack`等。这些模板允许我们存储和管理任何我们想要的数据类型，但仍然表现得像我们期望的那样。

### 练习 4：编写类模板

在计算科学中，最常用的两种数据结构是堆栈和队列。目前，STL 中已经有了它们的实现。但是为了尝试使用模板类，我们将编写一个可以用于任何类型的堆栈模板类。让我们开始吧：

1.  在 Eclipse 中打开**Lesson2B**项目，然后在**Project Explorer**中展开**Lesson2B**，然后展开**Exercise04**，双击**Exercise4.cpp**以在编辑器中打开此练习的文件。

1.  配置一个新的**Launch Configuration**，**L2BExercise4**，以运行名称为**Exercise4**的配置。

1.  还要配置一个新的 C/C++单元运行配置，**L2BEx4Tests**，以运行**L2BEx4tests**。设置**Google Tests Runner**。

1.  单击**运行**选项以运行测试，这是我们第一次运行：![图 2B.32：堆栈的初始单元测试](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_02B_32.jpg)

###### 图 2B.32：堆栈的初始单元测试

1.  打开`#pragma once`），告诉编译器如果再次遇到此文件要被#include，它就不需要了。虽然不严格属于标准的一部分，但几乎所有现代 C++编译器都支持它。最后，请注意，为了本练习的目的，我们选择将项目存储在 STL 向量中。

1.  在编辑器中，在`Stack`类的`public`部分中添加以下声明：

```cpp
bool empty() const
{
  return m_stack.empty();
}
```

1.  在文件顶部，将**EXERCISE4_STEP**更改为值**10**。单击**运行**按钮。练习 4 的测试应该运行并失败：![图 2B.33：跳转到失败的测试](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_02B_33.jpg)

###### 图 2B.33：跳转到失败的测试

1.  单击失败测试的名称，即`empty()`报告为 false。

1.  将`ASSERT_FALSE`更改为`ASSERT_TRUE`并重新运行测试。这一次，它通过了，因为它正在测试正确的事情。

1.  我们接下来要做的是添加一些类型别名，以便在接下来的几个方法中使用。在编辑器中，在`empty()`方法的上面添加以下行：

```cpp
using value_type = T;
using reference = value_type&;
using const_reference = const value_type&;
using size_type = std::size_t;
```

1.  单击**运行**按钮重新运行测试。它们应该通过。在进行测试驱动开发时，口头禅是编写一个小测试并看到它失败，然后编写足够的代码使其通过。在这种情况下，我们实际上测试了我们是否正确获取了别名的定义，因为编译失败是一种测试失败的形式。我们现在准备添加 push 函数。

1.  在编辑器中，通过在**empty()**方法的下面添加以下代码来更改**Stack.hpp**：

```cpp
void push(const value_type& value)
{
    m_stack.push_back(value);
}
```

1.  在文件顶部，将`EXERCISE4_STEP`更改为值`15`。单击**PushOntoStackNotEmpty**，在**StackTests.cpp**中证明了 push 对使堆栈不再为空做了一些事情。我们需要添加更多方法来确保它已经完成了预期的工作。

1.  在编辑器中，更改`push()`方法并将`EXERCISE4_STEP`更改为值`16`：

```cpp
size_type size() const
{
    return m_stack.size();
}
```

1.  单击**运行**按钮运行测试。现在应该有三个通过的测试。

1.  在编辑器中，更改`push()`方法并将`EXERCISE4_STEP`更改为`18`的值：

```cpp
void pop()
{
    m_stack.pop_back();
}
```

1.  单击**运行**按钮运行测试。现在应该有四个通过的测试。

1.  在编辑器中，更改`pop()`方法并将`EXERCISE4_STEP`更改为`20`的值：

```cpp
reference top()
{
    m_stack.back();
}
const_reference top() const
{
    m_stack.back();
}
```

1.  单击**运行**按钮运行测试。现在有五个通过的测试，我们已经实现了一个堆栈。

1.  从启动配置下拉菜单中，选择**L2BExercise4**，然后单击**运行**按钮。练习 4 将运行并产生类似以下输出：

![图 2B.34：练习 4 输出](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_02B_34.jpg)

###### 图 2B.34：练习 4 输出

检查现在在`std::stack`模板中的代码，它带有两个参数，第二个参数定义要使用的容器 - vector 可以是第一个。检查**StackTests.cpp**中的测试。测试应该被命名以指示它们的测试目标，并且它们应该专注于做到这一点。

### 活动 1：开发一个通用的“contains”模板函数

编程语言 Python 有一个称为“in”的成员运算符，可以用于任何序列，即列表、序列、集合、字符串等。尽管 C++有 100 多种算法，但它没有相应的方法来实现相同的功能。C++ 20 在`std::set`上引入了`contains()`方法，但这对我们来说还不够。我们需要创建一个`contains()`模板函数，它可以与`std::set`、`std::string`、`std::vector`和任何提供迭代器的其他容器一起使用。这是通过能够在其上调用 end()来确定的。我们的目标是获得最佳性能，因此我们将在任何具有`find()`成员方法的容器上调用它（这将是最有效的），否则将退回到在容器上使用`std::end()`。我们还需要将`std::string()`区别对待，因为它的`find()`方法返回一个特殊值。

我们可以使用通用模板和两个特化来实现这一点，但是这个活动正在使用 SFINAE 和 if constexpr 的技术来使其工作。此外，这个模板必须只能在支持`end(C)`的类上工作。按照以下步骤实现这个活动：

1.  从**Lesson2B/Activity01**文件夹加载准备好的项目。

1.  定义辅助模板函数和类来检测 std:string 情况，使用`npos`成员。

1.  定义辅助模板函数和类，以检测类是否具有`find()`方法。

1.  定义包含模板函数，使用 constexpr 来在三种实现中选择一种 - 字符串情况、具有 find 方法的情况或一般情况。

在实现了上述步骤之后，预期输出应如下所示：

![图 2B.35：包含成功实现的输出](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_02B_35.jpg)

###### 图 2B.35：包含成功实现的输出

#### 注意

此活动的解决方案可在第 653 页找到。

## 总结

在本章中，我们学习了接口、继承和多态，这扩展了我们对类型的操作技能。我们首次尝试了 C++模板的泛型编程，并接触了语言从 C++标准库（包括 STL）中免费提供给我们的内容。我们探索了 C++的一个功能，即模板类型推断，它在使用模板时使我们的生活更加轻松。然后我们进一步学习了如何使用 SFINAE 和 if constexpr 控制编译器包含的模板部分。这些构成了我们进入 C++之旅的基石。在下一章中，我们将重新讨论堆栈和堆，并了解异常是什么，发生了什么，以及何时发生。我们还将学习如何在异常发生时保护我们的程序免受资源损失。


# 第四章：不允许泄漏-异常和资源

## 学习目标

在本章结束时，您将能够：

+   开发管理资源的类

+   开发异常健壮的代码，以防止资源通过 RAII 泄漏

+   实现可以通过移动语义传递资源所有权的类

+   实现控制隐式转换的类

在本章中，您将学习如何使用类来管理资源，防止泄漏，并防止复制大量数据。

## 介绍

在*第 2A 章*中，*不允许鸭子-类型和推断*，我们简要涉及了一些概念，如智能指针和移动语义。在本章中，我们将进一步探讨它们。事实证明，这些主题与资源管理和编写健壮的代码（经常运行并长时间运行而没有问题的代码）非常密切相关。

为了理解发生了什么，我们将探讨变量在内存中的放置位置，以及当它们超出范围时发生了什么。

我们将查看编译器为我们输入的汇编代码生成了什么，并探讨当异常发生时所有这些都受到了什么影响。

### 变量范围和生命周期

在*第 2B 章*中，*不允许鸭子-模板和推断*，我们讨论了变量范围和生命周期。让我们快速浏览它们的不同类型：

**范围**：

+   `{}`）。

+   **全局/文件范围**：这适用于在普通函数或类之外声明的变量，也适用于普通函数。

**寿命**：

+   **自动寿命**：在这里，局部变量在声明时创建，并在退出其所在范围时销毁。这些由堆栈管理。

+   **永久寿命**：在这里，全局和静态局部变量具有永久寿命。

+   `new`和`delete`操作符）。这些变量的内存是从堆中分配的。

我们将使用以下程序来澄清`局部变量`的行为-具有`自动寿命`和具有`动态寿命`的变量：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_03_01.jpg)

###### 图 3.1：变量范围和生命周期的测试程序

当我们运行上述程序时，将生成以下输出：

![图 3.2：生命周期测试程序的输出](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_03_02.jpg)

###### 图 3.2：生命周期测试程序的输出

在上述输出中的十六进制数字（`0xNNNNNNNN`）是正在构造或销毁的 Int 对象的地址。我们的程序从`第 46 行`进入`main()`函数开始。此时，程序已经进行了大量初始化，以便我们随时可以使用一切。下面的图表指的是两个堆栈-**PC 堆栈**和**数据堆栈**。

这些是帮助我们解释幕后发生的事情的抽象概念。`PC 堆栈`（`程序计数器堆栈`）用于记住程序计数器的值（指向需要运行的下一条指令的寄存器），而`数据堆栈`保存我们正在操作的值或地址。尽管这是两个单独的堆栈，在实际 CPU 上，它很可能会被实现为一个堆栈。让我们看看以下表格，其中我们使用缩写`OLn`来引用上述程序输出的行号：

![图 3.3：测试程序执行的详细分析（第 1 部分）](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_03_03.jpg)

###### 图 3.3：测试程序执行的详细分析（第 1 部分）

以下是测试程序执行详细分析的第二部分：

![图 3.4：测试程序执行的详细分析（第 2 部分）](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_03_04.jpg)

###### 图 3.4：测试程序执行的详细分析（第 2 部分）

以下是测试程序执行详细分析的第三部分：

![图 3.5：测试程序执行的详细分析（第 3 部分）](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_03_05.jpg)

###### 图 3.5：测试程序执行的详细分析（第 3 部分）

从这个简单的程序中，我们学到了一些重要的事实：

+   当我们按值传递时，会调用复制构造函数（就像在这种情况下所做的那样）。

+   返回类型只会调用一个构造函数（不是两个构造函数 - 一个用于创建返回对象，一个用于存储返回的数据） - C++将其称为**复制省略**，现在在标准中是强制性的。

+   在作用域终止时（闭合大括号'`}`'），任何超出作用域的变量都会调用其析构函数。如果这是真的，那么为什么地址`0x6000004d0`没有显示析构函数调用（`~Int()`）？这引出了下一个事实。

+   在`calculate()`方法的析构函数中，我们泄漏了一些内存。

了解和解决资源泄漏问题的最后两个事实是重要的。在我们处理 C++中的异常之后，我们将研究资源管理。

## C++中的异常

我们已经看到了 C++如何管理具有自动和动态生命周期的局部作用域变量。当变量超出作用域时，它调用具有自动生命周期的变量的析构函数。我们还看到了原始指针在超出作用域时被销毁。由于它不清理动态生命周期变量，我们会失去它们。这是我们后来构建**资源获取即初始化**（**RAII**）的故事的一部分。但首先，我们需要了解异常如何改变程序的流程。

### 异常的必要性

在*第 2A 章*，*不允许鸭子 - 类型和推断*中，我们介绍了枚举作为处理`check_file()`函数的魔术数字的一种方式：

```cpp
FileCheckStatus check_file(const char* name)
{
  FILE* fptr{fopen(name,"r")};
  if ( fptr == nullptr)
    return FileCheckStatus::NotFound;
  char buffer[30];
  auto numberRead = fread(buffer, 1, 30, fptr);
  fclose(fptr);
  if (numberRead != 30)
    return FileCheckStatus::IncorrectSize;
  if(is_valid(buffer))
    return FileCheckStatus::InvalidContents;
  return FileCheckStatus::Good;
}
```

前面的函数使用了一种称为**状态**或**错误代码**的技术来报告操作的结果。这是 C 风格编程中使用的方法，其中与**POSIX API**和**Windows API**相关的错误被处理。

#### 注意

`POSIX`代表`可移植操作系统接口`。这是 Unix 变体和其他操作系统之间软件兼容性的 IEEE 标准。

这意味着，方法的调用者必须检查返回值，并针对每种错误类型采取适当的操作。当您可以推断代码将生成的错误类型时，这种方法效果很好。但并非总是如此。例如，可能存在输入到程序的数据存在问题。这会导致程序中的异常状态无法处理。具有处理错误逻辑的代码部分被从检测问题的代码部分中移除。

虽然可能编写处理此类问题的代码，但这会增加处理所有错误条件的复杂性，从而使程序难以阅读，难以推断函数应该执行的操作，并因此难以维护。

对于错误处理，异常比错误代码提供以下优点：

+   错误代码可以被忽略 - 异常强制处理错误（或程序终止）。

+   异常可以沿着堆栈流向最佳方法来响应错误。错误代码需要传播到每个中间方法之外。

+   异常将错误处理与主程序流程分离，使软件易于阅读和维护。

+   异常将检测错误的代码与处理错误的代码分离。

只要遵循最佳实践并将异常用于异常条件，使用异常不会有（时间）开销。这是因为一个实现良好的编译器将提供 C++的口号 - 你不为你不使用的东西付费。它可能会消耗一些内存，你的代码可能会变得稍微庞大，但运行时间不应受影响。

C++使用异常来处理运行时异常。通过使用异常，我们可以检测错误，抛出异常，并将错误传播回可以处理它的位置。让我们修改前面的程序，引入`divide()`函数并更改`calculate()`函数以调用它。我们还将在`main()`函数中添加日志记录，以便探索异常的行为方式：

![图 3.6：用于调查异常的修改测试程序](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_03_06.jpg)

###### 图 3.6：用于调查异常的修改测试程序

当我们编译并运行前面的程序时，将生成以下输出：

![图 3.7：测试程序的输出](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_03_07.jpg)

###### 图 3.7：测试程序的输出

在前面的代码中，您可以看到注释已添加到右侧。现在，我们从程序中的`result2`行中删除注释，重新编译程序并重新运行。生成的新输出如下所示：

![图 3.8：测试程序的输出 - result2](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_03_08.jpg)

###### 图 3.8：测试程序的输出 - result2

通过比较输出，我们可以看到每个输出的前八行是相同的。前面输出的接下来两行是因为`divide()`函数被调用了两次。最后一行指示抛出了异常并且程序被终止。

第二次调用`divide()`函数尝试除以零 - 这是一种异常操作。这导致异常。如果整数被零除，那么会导致浮点异常。这与在`POSIX`系统中生成异常的方式有关 - 它使用了称为信号的东西（我们不会在这里详细介绍信号的细节）。当整数被零除时，`POSIX`系统将其映射到称为`浮点错误`的信号，但现在是更通用的`算术错误`。

#### **注意**

根据 C++标准，如果零出现为除数，无论是'/'运算符（除法）还是'%'运算符（取模），行为都是未定义的。大多数系统会选择抛出异常。

因此，我们从前面的解释中学到了一个重要的事实：未处理的异常将终止程序（在内部调用`std::terminate()`）。我们将修复`未定义行为`，捕获异常，并查看输出中的变化。为了修复`未定义行为`，我们需要在文件顶部添加`#include <stdexcept>`并修改`divide()`函数：

```cpp
Int divide(Int a, Int b )
{
    if (b.m_value == 0)
        throw std::domain_error("divide by zero error!");
    return a.m_value/b.m_value;
}
```

当我们重新编译并运行程序时，我们得到以下输出：

![图 3.9：当我们抛出异常时的输出](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_03_09.jpg)

###### 图 3.9：当我们抛出异常时的输出

从前面的输出中可以看到，没有太多变化。只是我们不再得到`浮点异常`（核心转储）- 程序仍然终止但不会转储核心。然后我们在`main()`函数中添加了一个`try/catch`块，以确保异常不再是未处理的。

![图 3.10：捕获异常](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_03_10.jpg)

###### 图 3.10：捕获异常

重新编译程序并运行以获得以下输出：

![图 3.11：捕获异常的程序输出](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_03_11.jpg)

###### 图 3.11：捕获异常的程序输出

在前面的输出中，异常在第二行抛出，注释为“**复制 a 以调用 divide**”。之后的所有输出都是异常处理的结果。

我们的代码已将程序控制转移到`main()`函数中的`catch()`语句，并执行了在`try`子句中进行调用时在堆栈上构造的所有变量的析构函数。

### 堆栈展开

C++语言所保证的销毁所有本地函数变量的过程被称为**堆栈展开**。在异常出现时，堆栈展开时，C++使用其明确定义的规则来销毁作用域中的所有对象。

当异常发生时，函数调用堆栈从当前函数开始线性搜索，直到找到与异常匹配的异常处理程序（由`catch`块表示）。

如果找到异常处理程序，则进行堆栈展开，销毁堆栈中所有函数的本地变量。对象按创建顺序的相反顺序销毁。如果找不到处理抛出异常的处理程序，则程序将终止（通常不会警告用户）。

### 练习 1：在 Fraction 和 Stack 中实现异常

在这个练习中，我们将回到*第 2A 章*和*第 2B 章*中我们所做的两个类，*不允许鸭子 - 类型和推断*和*不允许鸭子 - 模板和推断* - `Fraction`和`Stack`，它们都可能出现运行时异常。我们将更新它们的代码，以便在检测到任何问题时都能引发异常。按照以下步骤执行此练习：

1.  打开 Eclipse，并使用**Lesson3**示例文件夹中的文件创建一个名为**Lesson3**的新项目。

1.  由于这是一个**基于 CMake 的项目**，因此将当前构建器更改为**CMake Build (portable)**。

1.  转到**项目** | **构建所有**菜单以构建所有练习。默认情况下，屏幕底部的控制台将显示**CMake Console [Lesson3]**。

1.  配置一个新的**启动配置**，**L3Exercise1**，以运行名称为**Exercise1**的项目。

1.  还要配置一个新的 C/C++单元运行配置，**L3Ex1Tests**，以运行**L3Ex1tests**。设置**Google Tests Runner**。

1.  点击**运行**选项，对现有的**18**个测试进行运行和通过。![图 3.12：现有测试全部通过（运行次数：18）](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_03_12.jpg)

###### 图 3.12：现有测试全部通过（运行次数：18）

1.  在编辑器中打开**Fraction.hpp**，并更改文件顶部的行，使其读起来像这样：

```cpp
#define EXERCISE1_STEP  14
```

1.  点击`Fraction`，其中分母为零。测试期望抛出异常：![图 3.13：新的失败测试 ThrowsDomainErrorForZeroDenominator](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_03_13.jpg)

###### 图 3.13：新的失败测试 ThrowsDomainErrorForZeroDenominator

1.  点击失败的测试名称 - “预期…抛出 std::domain_error 类型的异常”，下一行显示“实际：它没有抛出任何异常”。

1.  双击消息，它将带您到以下测试：![图 3.14：失败的测试](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_03_14.jpg)

###### 图 3.14：失败的测试

`ASSERT_THROW()`宏需要两个参数。由于`Fraction 初始化器`中有一个逗号，因此需要在第一个参数的外面再加一组括号。第二个参数预期从这个构造函数中获得一个`std::domain_error`。内部的`try/catch`结构用于确认预期的字符串是否被捕获在异常对象中。如果我们不想检查这一点，那么我们可以简单地这样编写测试：

```cpp
ASSERT_THROW(({Fraction f1{1,0}; }), std::domain_error);
```

1.  在编辑器中打开文件**Fraction.cpp**。在文件顶部附近插入以下行：

```cpp
#include <stdexcept> 
```

1.  修改构造函数，如果使用零分母创建，则抛出异常：

```cpp
Fraction::Fraction(int numerator, int denominator) 
                       : m_numerator{numerator}, m_denominator{denominator}
{
    if(m_denominator == 0) 
    {
        throw std::domain_error("Zero Denominator");
    }
}
```

1.  点击**运行**按钮重新运行测试。现在有**19**个测试通过。

1.  在编辑器中打开**Fraction.hpp**，并更改文件顶部附近的行，使其读起来像这样：

```cpp
#define EXERCISE1_STEP  20
```

1.  点击`ThrowsRunTimeErrorForZeroDenominator`失败。

1.  点击失败的测试名称 - “预期…抛出 std::runtime_error 类型的异常”，下一行显示“实际：它抛出了不同类型的异常”。

1.  再次双击消息以打开失败的测试：![图 3.15：另一个失败的测试](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_03_15.jpg)

###### 图 3.15：另一个失败的测试

此测试验证除法赋值运算符对零进行除法时会抛出异常。

1.  打开`operator/=()`函数。您会看到，在这个函数内部，它实际上使用了`std::domain_error`的构造函数。

1.  现在修改`operator/=()`以在调用构造函数之前检测此问题，以便抛出带有预期消息的`std::runtime_error`。

1.  通过添加一个将检测除法运算符的域错误来修改**Fraction.cpp**：

```cpp
Fraction& Fraction::operator/=(const Fraction& rhs)
{
    if (rhs.m_numerator == 0)
    {
        throw std::runtime_error("Fraction Divide By Zero");
    }
    Fraction tmp(m_numerator*rhs.m_denominator, 
m_denominator*rhs.m_numerator);
    *this = tmp;
    return *this;
}
```

1.  点击**Run**按钮重新运行测试。所有**20**个测试通过。

1.  在编辑器中打开**Stack.hpp**并更改文件顶部附近的行，使其读起来像这样：

```cpp
#define EXERCISE1_STEP  27
```

1.  点击`FractionTest`以折叠测试列表并显示`StackTest`：![图 3.16：pop Stack 测试失败](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_03_16.jpg)

###### 图 3.16：pop Stack 测试失败

1.  在文件顶部使用`#include <stdexcept>`，然后更新`pop()`函数，使其如下所示：

```cpp
void pop()
{
    if(empty())
        throw std::underflow_error("Pop from empty stack");
    m_stack.pop_back();
} 
```

1.  点击**Run**按钮重新运行测试。现在**21**个测试通过了。

1.  在编辑器中打开**Stack.hpp**并更改文件顶部的行，使其读起来像这样：

```cpp
#define EXERCISE1_STEP  31
```

1.  点击`TopEmptyStackThrowsUnderFlowException`，失败。

1.  使用`top()`方法，使其如下所示：

```cpp
reference top()
{
    if(empty())
        throw std::underflow_error("Top from empty stack");
    return m_stack.back();
}
```

1.  点击**Run**按钮重新运行测试。**22**个测试通过。

1.  在编辑器中打开**Stack.hpp**并更改文件顶部的行，使其读起来像这样：

```cpp
#define EXERCISE1_STEP  35
```

1.  点击`TopEmptyConstStackThrowsUnderFlowException`，失败。

1.  使用`top()`方法，使其如下所示：

```cpp
const_reference top() const
{
    if(empty())
        throw std::underflow_error("Top from empty stack");
    return m_stack.back();
}
```

1.  点击**Run**按钮重新运行测试。现在所有**23**个测试都通过了。

在这个练习中，我们为使用我们的`Fraction`和`Stack`类的正常操作的前提条件添加了运行时检查。当违反前提条件之一时，此代码将仅执行以抛出异常，表明数据或程序执行方式存在问题。

### 当抛出异常时会发生什么？

在某个时刻，我们的程序执行以下语句：

```cpp
throw expression;
```

通过执行此操作，我们正在发出发生错误的条件，并且我们希望它得到处理。接下来发生的事情是一个**临时**对象，称为**异常对象**，在未指定的存储中构造，并从表达式进行复制初始化（可能调用移动构造函数，并可能受到复制省略的影响）。异常对象的类型从表达式中静态确定，去除 const 和 volatile 限定符。数组类型会衰减为指针，而函数类型会转换为函数的指针。如果表达式的类型格式不正确或抽象，则会发生编译器错误。

在异常对象构造之后，控制权连同异常对象一起转移到异常处理程序。被选择的异常处理程序是与异常对象最匹配的类型，因为堆栈展开。异常对象存在直到最后一个 catch 子句退出，除非它被重新抛出。表达式的类型必须具有可访问的`复制构造函数`和`析构函数`。

### 按值抛出还是按指针抛出

知道临时异常对象被创建，传递，然后销毁，抛出表达式应该使用什么类型？一个`值`还是一个`指针`？

我们还没有详细讨论在 catch 语句中指定类型。我们很快会做到。但是现在，请注意，要捕获指针类型（被抛出的），catch 模式也需要是指针类型。

如果抛出对象的指针，那么抛出方必须确保异常对象将指向的内容（因为它将是指针的副本）在异常处理之前保持活动，即使通过`堆栈展开`也是如此。

指针可以指向静态变量、全局变量或从堆中分配的内存，以确保在处理异常时被指向的对象仍然存在。现在，我们已经解决了保持异常对象存活的问题。但是当处理程序完成后，捕获者该怎么办？

异常的捕获者不知道异常对象的创建（`全局`，`静态`或`堆`），因此不知道是否应该删除接收到的指针。因此，通过指针抛出异常不是推荐的异常抛出方法。

被抛出的对象将被复制到创建的临时异常对象中，并交给处理程序。当异常被处理后，临时对象将被简单地销毁，程序将继续执行。对于如何处理它没有歧义。因此，最佳实践是通过值抛出异常。

### 标准库异常

C++标准库将`std::exception`定义为所有标准库异常的基类。标准定义了以下第一级层次的`异常`/`错误`（括号中的数字表示从该类派生的异常数量）：

![图 3.17：标准库异常层次结构（两级）](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_03_17.jpg)

###### 图 3.17：标准库异常层次结构（两级）

这些异常在 C++标准库中被使用，包括 STL。创建自己的异常类的最佳实践是从标准异常中派生它。接下来我们会看到，你的特殊异常可以被标准异常的处理程序捕获。

### 捕获异常

在讨论异常的需要时，我们介绍了抛出异常的概念，但并没有真正看看 C++如何支持捕获异常。异常处理的过程始于将代码段放在`try`块中以进行**异常检查**。try 块后面是一个或多个 catch 块，它们是异常处理程序。当在 try 块内执行代码时发生异常情况时，异常被抛出，控制转移到异常处理程序。如果没有抛出异常，那么所有异常处理程序都将被跳过，try 块中的代码完成，正常执行继续。让我们在代码片段中表达这些概念：

```cpp
void SomeFunction()
{
  try {
    // code under exception inspection
  }
  catch(myexception e)         // first handler – catch by value
  {
    // some error handling steps
  }
  catch(std::exception* e)     // second handler – catch by pointer
  {
    // some other error handling steps
  }
  catch(std::runtime_error& e) // third handler – catch by reference
  {
    // some other error handling steps
  }
  catch(...)                   // default exception handler – catch any exception
  {
    // some other error handling steps
  }
  // Normal programming continues from here
}
```

前面的片段展示了必要的关键字 - `try`和`catch`，并介绍了三种不同类型的捕获模式（不包括默认处理程序）：

+   **通过值捕获异常**：这是一种昂贵的机制，因为异常处理程序像任何其他函数一样被处理。通过值捕获意味着必须创建异常对象的副本，然后传递给处理程序。第二个副本的创建减慢了异常处理过程。这种类型也可能受到对象切片的影响，其中子类被抛出，而 catch 子句是超类。然后 catch 子句只会接收到失去原始异常对象属性的超类对象的副本。因此，我们应避免使用通过值捕获异常处理程序。

+   **通过指针捕获异常**：如在讨论通过值抛出时所述，通过指针抛出，这种异常处理程序只能捕获指针抛出的异常。由于我们只想通过值抛出，应避免使用通过指针捕获异常处理程序。

+   `通过值抛出`和`通过引用捕获`。

当存在多个 catch 块时，异常对象类型用于匹配按指定顺序的处理程序。一旦找到匹配的处理程序，它就会被执行，并且剩余的异常处理程序将被忽略。这与函数解析不同，编译器将找到最佳匹配的参数。因此，异常处理程序（catch 块）应该从更具体到更一般的定义。例如，默认处理程序（`catch(...)`）应该始终在定义中的最后一个。

### 练习 2：实现异常处理程序

在这个练习中，我们将实现一系列异常处理程序的层次结构，以管理异常的处理方式。按照以下步骤实现这个练习：

1.  打开`e`。该变量的作用域仅限于它声明的 catch 块。

1.  单击**启动配置**下拉菜单，然后选择**新启动配置…**。从**搜索项目**菜单配置**L3Exercise2**应用程序以使用名称**L3Exercise2**运行它。

1.  完成后，它将是当前选择的**启动配置**。

1.  点击**运行**按钮。练习 2 将运行并产生以下输出：![图 3.18：练习 2 输出-默认处理程序捕获了异常](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_03_18.jpg)

###### 图 3.18：练习 2 输出-默认处理程序捕获了异常

1.  在控制台窗口中，单击`CMake`文件设置`-fpermissive`标志，当它编译此目标时。）

1.  在编辑器中，将默认异常处理程序`catch(...)`移动到`std::domain_error`处理程序后面。点击**运行**按钮。练习 2 将运行并产生以下输出：![图 3.19：已使用 std::exception 处理程序](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_03_19.jpg)

###### 图 3.19：已使用 std::exception 处理程序

1.  在编辑器中，将`std::exception`处理程序移动到`std::domain_error`处理程序后面。点击`std::logic_error`处理程序按预期执行。

1.  在编辑器中，将`std:: logic_error`处理程序移动到`std::domain_error`处理程序后面。点击`std:: domain_error`处理程序被执行，这实际上是我们所期望的。

1.  现在将`throw`行更改为`std::logic_error`异常。点击`std::logic_error`处理程序按预期执行。

1.  现在将`throw`行更改为`std::underflow_error`异常。点击`std::exception`处理程序按预期执行。`std::exception`是所有标准库异常的基类。

在这个练习中，我们实现了一系列异常处理程序，并观察了异常处理程序的顺序如何影响异常的捕获以及异常层次结构如何被使用。

### CMake 生成器表达式

在使用`CMake`时，有时需要调整变量的值。`CMake`是一个构建生成系统，可以为许多构建工具和编译器工具链生成构建文件。由于这种灵活性，如果要在编译器中启用某些功能，只需将其应用于特定类型。这是因为不同供应商之间的命令行选项是不同的。例如，g++编译器启用 C++17 支持的命令行选项是`-std=c++17`，但对于`msvc`来说是`/std:c++17`。如果打开`add_excutable`，那么以下行将在其后：

```cpp
target_compile_options(L3Exercise2 PRIVATE $<$<CXX_COMPILER_ID:GNU>:-fpermissive>)
```

这使用`$<CXX_COMPILER_ID:GNU>`变量查询来检查它是否是 GCC 编译器。如果是，则生成 1（true），否则生成 0（false）。它还使用`$<condition:true_string>`条件表达式将`-fpermissive`添加到`target_compile_options`的编译器选项或通过一个调用。

#### 注意

有关生成器表达式的更多信息，请查看以下链接：[`cmake.org/cmake/help/v3.15/manual/cmake-generator-expressions.7.html`](https://cmake.org/cmake/help/v3.15/manual/cmake-generator-expressions.7.html)。

### 异常使用指南

在 C++代码中使用异常时，请记住以下几点：

+   口号：**按值抛出，按引用捕获**

+   **不要将异常用于正常程序流**。如果函数遇到异常情况并且无法满足其（功能性）义务，那么只有在这种情况下才抛出异常。如果函数可以解决异常情况并履行其义务，那么这不是异常。它们之所以被称为异常，是有原因的，如果不使用它们，就不会产生任何处理开销。

+   **不要在析构函数中抛出异常**。请记住，由于堆栈展开，局部变量的析构函数将被执行。如果在堆栈展开过程中调用了析构函数并抛出了异常，那么程序将终止。

+   **不要吞没异常**。不要使用默认的 catch 处理程序，也不要对异常做任何处理。异常被抛出是为了指示存在问题，你应该对此做些什么。忽视异常可能会导致以后难以排查的故障。这是因为任何有用的信息都真正丢失了。

+   **异常对象是从抛出中复制的**。

## 资源管理（在异常世界中）

到目前为止，我们已经看过局部变量作用域，以及当变量超出作用域时如何处理`自动`和`动态生命周期变量` - 自动生命周期变量（放在堆栈上的变量）将被完全析构，而`动态生命周期变量`（由程序员分配到堆上的变量）不会被析构：我们只是失去了对它们的任何访问。我们也看到，当抛出异常时，会找到最近匹配的处理程序，并且在堆栈展开过程中将析构抛出点和处理程序之间的所有局部变量。

我们可以利用这些知识编写健壮的资源管理类，这些类将使我们不必跟踪资源（动态生命周期变量、文件句柄、系统句柄等），以确保在使用完它们后将它们释放（释放到野外）。在正常操作和异常情况下管理资源的技术被称为**资源获取即初始化**（**RAII**）。

### 资源获取即初始化

RAII 是另一个命名不好的概念的好例子（另一个是`SFINAE`）。`RAII`或`Resource Acquisition is Initialization`描述了一个用于管理资源的类的行为。如果它被命名为`File`类并展示了 RAII 如何提高可读性和我们对函数操作的理解能力，可能会更好。

考虑以下代码：

```cpp
void do_something()
{
    FILE* out{};
    FILE* in = fopen("input.txt", "r");
    try 
    {
        if (in != nullptr)
        {
            // UNSAFE – an exception here will create a resource leak
            out = fopen("output.txt", "w");
            if (out != nullptr)
            {
                // Do some work
                // UNSAFE – an exception here will create resource leaks
                fclose(out);
            }
            fclose(in);
        }
    }
    catch(std::exception& e)
    {
        // Respond to the exception
    }
}
```

这段代码展示了资源管理的两个潜在问题：

+   最重要的是，在打开和关闭文件之间发生异常会导致资源泄漏。如果这是系统资源，许多这样的情况可能导致系统不稳定或应用程序性能受到不利影响，因为它会因资源匮乏而受到影响。

+   此外，在一个方法中管理多个资源可能会导致由于错误处理而产生深度嵌套的子句。这对代码的可读性有害，因此也影响了代码的理解和可维护性。很容易忘记释放资源，特别是当有多个退出点时。

那么，我们如何管理资源，以便有异常安全和更简单的代码？这个问题不仅仅是 C++独有的，不同的语言以不同的方式处理它。`Java`、`C#`和`Python`使用垃圾回收方法，在对象创建后清理它们，当它们不再被引用时。但是 C++没有垃圾回收，那么解决方案是什么呢？

考虑以下类：

```cpp
class File {
public:
    File(const char* name, const char* access) {
        m_file = fopen(name, access);
        if (m_file == nullptr) {
            throw std::ios_base::failure("failed to open file");
        }
    }
    ~File() {
        fclose(m_file);
    }
    operator FILE*() {
        return m_file;
    }
private:
    FILE* m_file{};
};
```

这个类实现了以下特征：

+   构造函数获取资源。

+   如果资源没有在构造函数中获取，那么会抛出异常。

+   当类被销毁时，资源被释放。

如果我们在`do_something()`方法中使用这个类，那么它看起来像这样：

```cpp
void do_something()
{
    try 
    {
        File in("input.txt", "r");
        File out("output.txt", "w");
        // Do some work
    }
    catch(std::exception& e)
    {
        // Respond to the exception
    }
}
```

如果在执行此操作时发生异常，那么 C++保证将调用所有基于堆栈的对象的析构函数（`堆栈展开`），从而确保文件被关闭。这解决了在发生异常时资源泄漏的问题，因为现在资源会自动清理。此外，这种方法非常容易阅读，因此我们可以理解逻辑流程，而不必担心错误处理。

这种技术利用`File`对象的生命周期来获取和释放资源，确保资源不会泄漏。资源在管理类的构造（初始化）期间获取，并在管理类的销毁期间释放。正是这种作用域绑定资源的行为导致了`Resource Acquisition Is Initialization`的名称。

前面的例子涉及管理系统资源的文件句柄。它适用于任何在使用前需要获取，然后在完成后放弃的资源。RAII 技术可以应用于各种资源 - 打开文件，打开管道，分配的堆内存，打开套接字，执行线程，数据库连接，互斥锁/临界区的锁定 - 基本上是主机系统中供应不足的任何资源，并且需要进行管理。

### 练习 3：为内存和文件句柄实现 RAII

在这个练习中，我们将实现两个不同的类，使用 RAII 技术来管理内存或文件。按照以下步骤来实现这个练习：

1.  在 Eclipse 中打开**Lesson3**项目。然后在**Project Explorer**中展开**Lesson3**，然后展开**Exercise03**，双击**Exercise3.cpp**以打开此练习的文件到编辑器中。

1.  点击**Launch Configuration**下拉菜单，选择**New Launch Configuration…**。从搜索项目菜单中配置**L3Exercise3**应用程序以使用名称**L3Exercise3**运行它。

1.  当`monitor`被析构时，点击`main()`函数，它会转储分配和释放的内存报告，以及打开但从未关闭的文件。

1.  在编辑器中，输入以下内容到`File`类中：

```cpp
class File {
public:
    File(const char* name, const char* access) {
        m_file = fopen(name, access);
        if (m_file == nullptr) {
            throw std::ios_base::failure(""failed to open file"");
        }
    }
    ~File() {
        fclose(m_file);
    }
    operator FILE*() {
        return m_file;
    }
private:
    FILE* m_file{};
};
```

1.  点击**Run**按钮运行 Exercise 3 - 它仍然泄漏文件和内存，但代码是正确的。

1.  找到`LeakFiles()`函数，并修改它以使用新的`File`类（就像前面的代码一样）以防止文件泄漏：

```cpp
void LeakFiles()
{
    File fh1{"HelloB1.txt", "w"};
    fprintf(fh1, "Hello B2\n");
    File fh2{"HelloB2.txt", "w"};
    fprintf(fh2, "Hello B1\n");
}
```

1.  正确点击`LeakFiles()`，然后输出将如下所示：![图 3.21：没有文件泄漏](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_03_21.jpg)

###### 图 3.21：没有文件泄漏

1.  现在在`CharPointer`类中：

```cpp
class CharPointer
{
public:
    void allocate(size_t size)
    {
        m_memory = new char[size];
    }
    operator char*() { return m_memory;}
private:
    char* m_memory{};
};
```

1.  修改`LeakPointers()`如下所示：

```cpp
void LeakPointers()
{
    CharPointer memory[5];
    for (auto i{0} ; i<5 ; i++)
    {
        memory[i].allocate(20); 
        std::cout << "allocated 20 bytes @ " << (void *)memory[i] << "\n";
    }
}
```

1.  点击**Run**按钮运行 Exercise 3 - 它仍然有内存泄漏，但代码是正确的。

1.  现在，向`CharPointer`添加以下析构函数。请注意，`delete`操作符使用数组`[]`语法：

```cpp
~CharPointer()
{
    delete [] m_memory;
}
```

1.  再次点击**Run**按钮运行 Exercise 3 - 这次，您应该看到监视器报告没有泄漏：

![图 3.22：没有泄漏 - 内存或文件](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_03_22.jpg)

###### 图 3.22：没有泄漏 - 内存或文件

`File`和`CharPointer`的实现符合`RAII`设计方法，但在设计这些方法时还有其他考虑因素。例如，我们是否需要复制构造函数或复制赋值函数？在这两种情况下，仅仅从一个对象复制资源到另一个对象可能会导致关闭文件句柄或删除内存的两次尝试。通常，这会导致未定义的行为。接下来，我们将重新审视特殊成员函数，以实现`File`或`CharPointer`等资源管理对象。

### 特殊编码技术

*练习 3*的代码，*为内存和文件句柄实现 RAII*，已经特别编写，以便我们可以监视内存和文件句柄的使用，并在退出时报告任何泄漏。访问**monitor.h**和**monitor.cpp**文件，并检查用于使监视器可能的两种技术：

+   如果包括`SendMessageA`或`SendMessageW`，则`SendMessage`

+   **定义我们自己的新处理程序**：这是一种高级技术，除非你编写嵌入式代码，否则你不太可能需要它。

### C++不需要最终

其他支持异常抛出机制的语言（`C#`、`Java`和`Visual Basic.NET`）具有`try/catch/finally`范式，其中`finally`块中的代码在退出 try 块时被调用 - 无论是正常退出还是异常退出。C++没有`finally`块，因为它有更好的机制，可以确保我们不会忘记释放资源 - RAII。由于资源由本地对象表示，本地对象的析构函数将释放资源。

这种设计模式的附加优势是，如果正在管理大量资源，则`finally`块的大小也相应较大。RAII 消除了对 finally 的需求，并导致更易于维护的代码。

### RAII 和 STL

标准模板库（STL）在许多模板和类中使用 RAII。例如，C++11 中引入的智能指针，即`std::unique_ptr`和`std::shared_ptr`，通过确保在使用完毕后释放内存，或者确保在其他地方使用时不释放内存，帮助避免了许多问题。STL 中的其他示例包括`std::string`（内存）、`std::vector`（内存）和`std::fstream`（文件句柄）。

### 谁拥有这个对象？

通过前面对`File`和`CharPointer`的实现，我们已经测试了使用 RAII 进行资源管理。让我们进一步探讨。首先，我们将定义一个不仅拥有一个资源的类：

```cpp
class BufferedWriter
{
public:
    BufferedWriter(const char* filename);
    ~BufferedWriter();
    bool write(const char* data, size_t length);
private:
    const size_t BufferSize{4096};
    FILE* m_file{nullptr};
    size_t m_writePos{0};
    char* m_buffer{new char[BufferSize]};
};
```

该类用于缓冲写入文件。

#### 注意

当使用 iostream 派生类时，这通常是不必要的，因为它们已经提供了缓冲。

每次调用`write()`函数都会将数据添加到分配的缓冲区，直到达到`BufferSize`，此时数据实际写入文件，并且缓冲区被重置。

但是如果我们想要将`BufferedWriter`的这个实例分配给另一个实例或复制它呢？什么是正确的行为？

如果我们只是让默认的复制构造函数/复制赋值做它们的事情，我们会得到项目的成员复制。这意味着我们有两个`BufferedWriter`的实例，它们持有相同的文件句柄和缓冲区指针。当对象的第一个实例被销毁时，作为优秀的程序员，我们将通过关闭文件和删除内存来清理文件。第二个实例现在有一个失效的文件句柄和一个指向我们已告诉操作系统为下一个用户恢复的内存的指针。任何尝试使用这些资源，包括销毁它们，都将导致未定义的行为，很可能是程序崩溃。默认的复制构造函数/复制赋值运算符执行所谓的浅复制 - 也就是说，它按位复制所有成员（但不是它们所指的内容）。

我们拥有的两个资源可以被不同对待。首先，应该只有一个类拥有`m_buffer`。在处理这个问题时有两个选择：

+   防止类的复制，因此也防止内存。

+   执行`深复制`，其中第二个实例中的缓冲区是由构造函数分配的，并且复制了第一个缓冲区的内容

其次，应该只有一个类拥有文件句柄（`m_file`）。在处理这个问题时有两个选择：

+   防止类的复制，因此也防止文件句柄的复制

+   将`所有权`从原始实例转移到第二个实例，并将原始实例标记为无效或空（无论这意味着什么）

实现深拷贝很容易，但如何转移资源的所有权呢？为了回答这个问题，我们需要再次看看临时对象和值类别。

### 临时对象

在将结果存储到变量（或者只是忘记）之前，创建临时对象来存储表达式的中间结果。表达式是任何返回值的代码，包括按值传递给函数，从函数返回值，隐式转换，文字和二进制运算符。临时对象是`rvalue 表达式`，它们有内存，为它们分配了临时位置，以放置表达式结果。正是这种创建临时对象和在它们之间复制数据导致了 C++11 之前的一些性能问题。为了解决这个问题，C++11 引入了`rvalue 引用`，以实现所谓的移动语义。

### 移动语义

一个`rvalue 引用`（用双`&&`表示）是一个只分配给`rvalue`的引用，它将延长`rvalue`的生命周期，直到`rvalue 引用`完成为止。因此，`rvalues`可以在定义它的表达式之外存在。有了`rvalue 引用`，我们现在可以通过移动构造函数和移动赋值运算符来实现移动语义。移动语义的目的是从被引用对象中窃取资源，从而避免昂贵的复制操作。当移动完成时，被引用对象必须保持在稳定状态。换句话说，被移动的对象必须保持在一个状态，不会在销毁时引起任何未定义的行为或程序崩溃，也不应该影响从中窃取的资源。

C++11 还引入了一个转换运算符`std::move()`，它将一个`lvalue`转换为一个`rvalue`，以便调用移动构造函数或移动赋值运算符来'移动'资源。`std::move()`方法实际上并不移动数据。

一个意外的事情要注意的是，在移动构造函数和移动赋值运算符中，`rvalue`引用实际上是一个`lvalue`。这意味着如果你想确保在方法内发生移动语义，那么你可能需要再次在成员变量上使用`std::move()`。

随着 C++11 引入了移动语义，它还更新了标准库以利用这种新的能力。例如，`std::string`和`std::vector`已经更新以包括移动语义。要获得移动语义的好处，你只需要用最新的 C++编译器重新编译你的代码。

### 实现智能指针

智能指针是一个资源管理类，它在资源超出范围时持有指向资源的指针并释放它。在本节中，我们将实现一个智能指针，观察它作为一个支持复制的类的行为，使其支持移动语义，最后移除其对复制操作的支持：

```cpp
#include <iostream>
template<class T>
class smart_ptr
{
public:
  smart_ptr(T* ptr = nullptr) :m_ptr(ptr)
  {
  }
  ~smart_ptr()
  {
    delete m_ptr;
  }
  // Copy constructor --> Do deep copy
  smart_ptr(const smart_ptr& a)
  {
    m_ptr = new T;
    *m_ptr = *a.m_ptr;      // use operator=() to do deep copy
  }
  // Copy assignment --> Do deep copy 
  smart_ptr& operator=(const smart_ptr& a)
  {
    // Self-assignment detection
    if (&a == this)
      return *this;
    // Release any resource we're holding
    delete m_ptr;
    // Copy the resource
    m_ptr = new T;
    *m_ptr = *a.m_ptr;
    return *this;
  }
  T& operator*() const { return *m_ptr; }
  T* operator->() const { return m_ptr; }
  bool is_null() const { return m_ptr == nullptr; }
private:
  T* m_ptr{nullptr};
};
class Resource
{
public:
  Resource() { std::cout << "Resource acquired\n"; }
  ~Resource() { std::cout << "Resource released\n"; }
};
smart_ptr<Resource> createResource()
{
    smart_ptr<Resource> res(new Resource);                       // Step 1
    return res; // return value invokes the copy constructor     // Step 2
}
int main()
{
  smart_ptr<Resource> the_res;
  the_res = createResource(); // assignment invokes the copy assignment Step 3/4

  return 0; // Step 5
}
```

当我们运行这个程序时，会生成以下输出：

![图 3.23：智能指针程序输出](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_03_23.jpg)

###### 图 3.23：智能指针程序输出

对于这样一个简单的程序，获取和释放资源的操作很多。让我们来分析一下：

1.  在`createResource()`内部的局部变量 res 是在堆上创建并初始化的（动态生命周期），导致第一个“`获取资源`”消息。

1.  编译器可能创建另一个临时对象来返回值。然而，编译器已经执行了`复制省略`来删除复制（也就是说，它能够直接在调用函数分配的堆栈位置上构建对象）。编译器有`返回值优化`（`RVO`）和`命名返回值优化`（`NRVO`）优化，它可以应用，并且在 C++17 中，在某些情况下这些优化已经成为强制性的。

1.  临时对象通过复制赋值分配给`main()`函数中的`the_res`变量。由于复制赋值正在进行深拷贝，因此会获取资源的另一个副本。

1.  当赋值完成时，临时对象超出范围，我们得到第一个"资源释放"消息。

1.  当`main()`函数返回时，`the_res`超出范围，释放第二个 Resource。

因此，如果资源很大，我们在`main()`中创建`the_res`局部变量的方法非常低效，因为我们正在创建和复制大块内存，这是由于复制赋值中的深拷贝。然而，我们知道当`createResource()`创建的临时变量不再需要时，我们将丢弃它并释放其资源。在这些情况下，将资源从临时变量转移（或移动）到类型的另一个实例中将更有效。移动语义使我们能够重写我们的`smart_ptr`模板，而不是进行深拷贝，而是转移资源。

让我们为我们的`smart_ptr`类添加移动语义：

```cpp
// Move constructor --> transfer resource
smart_ptr(smart_ptr&& a) : m_ptr(a.m_ptr)
{
  a.m_ptr = nullptr;    // Put into safe state
}
// Move assignment --> transfer resource
smart_ptr& operator=(smart_ptr&& a)
{
  // Self-assignment detection
  if (&a == this)
    return *this;
  // Release any resource we're holding
  delete m_ptr;
  // Transfer the resource
  m_ptr = a.m_ptr;
  a.m_ptr = nullptr;    // Put into safe state
  return *this;
}
```

重新运行程序后，我们得到以下输出：

![图 3.24：使用移动语义的智能指针程序输出](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_03_24.jpg)

###### 图 3.24：使用移动语义的智能指针程序输出

现在，因为移动赋值现在可用，编译器在这一行上使用它：

```cpp
the_res = createResource(); // assignment invokes the copy assignment Step 3/4
```

第 3 步现在已经被移动赋值所取代，这意味着深拷贝现在已经被移除。

`第 4 步`不再释放资源，因为带有注释“//”的行将其置于安全状态——它不再具有要释放的资源，因为其所有权已转移。

另一个需要注意的地方是`移动构造函数`和`移动赋值`的参数在它们的拷贝版本中是 const 的，而在它们的移动版本中是`非 const`的。这被称为`所有权的转移`，这意味着我们需要修改传入的参数。

移动构造函数的另一种实现可能如下所示：

```cpp
// Move constructor --> transfer resource
smart_ptr(smart_ptr&& a) 
{
  std::swap(this->m_ptr, a.m_ptr);
}
```

基本上，我们正在交换资源，C++ STL 支持许多特化的模板交换。这是因为我们使用成员初始化将`m_ptr`设置为`nullptr`。因此，我们正在交换`nullptr`和存储在`a`中的值。

现在我们已经解决了不必要的深拷贝问题，我们实际上可以从`smart_ptr()`中删除复制操作，因为实际上我们想要的是所有权的转移。如果我们将非临时`smart_ptr`的实例复制到另一个非临时`smart_ptr`实例中，那么当它们超出范围时会删除资源，这不是期望的行为。为了删除（深）复制操作，我们改变了成员函数的定义，如下所示：

```cpp
smart_ptr(const smart_ptr& a) = delete;
smart_ptr& operator=(const smart_ptr& a) = delete;
```

我们在*第 2A 章*中看到的`= delete`的后缀告诉编译器，尝试访问具有该原型的函数现在不是有效的代码，并导致错误。

### STL 智能指针

与其编写自己的`smart_ptr`，不如使用 STL 提供的类来实现我们对象的 RAII。最初的是`std::auto_ptr()`，它在 C++ 11 中被弃用，并在 C++ 17 中被移除。它是在`rvalue`引用支持之前创建的，并且因为它使用复制来实现移动语义而导致问题。C++ 11 引入了三个新模板来管理资源的生命周期和所有权：

+   通过指针管理`单个对象`，并在`unique_ptr`超出范围时销毁该对象。它有两个版本：用`new`创建的单个对象和用`new[]`创建的对象数组。`unique_ptr`与直接使用底层指针一样高效。

+   **std::shared_ptr**：通过指针保留对象的共享所有权。它通过引用计数管理资源。每个分配给 shared_ptr 的 shared_ptr 的副本都会更新引用计数。当引用计数变为零时，这意味着没有剩余所有者，资源被释放/销毁。

+   `shared_ptr`，但不修改计数器。可以检查资源是否仍然存在，但不会阻止资源被销毁。如果确定资源仍然存在，那么可以用它来获得资源的`shared_ptr`。一个使用场景是多个`shared_ptrs`最终形成循环引用的情况。循环引用会阻止资源的自动释放。`weak_ptr`用于打破循环并允许资源在应该被释放时被释放。

### std::unique_ptr

`std::unique_ptr()`在 C++ 11 中引入，以取代`std::auto_ptr()`，并为我们提供了`smart_ptr`所做的一切（以及更多）。我们可以将我们的`smart_ptr`程序重写如下：

```cpp
#include <iostream>
#include <memory>
class Resource
{
public:
  Resource() { std::cout << "Resource acquired\n"; }
  ~Resource() { std::cout << "Resource released\n"; }
};
std::unique_ptr<Resource> createResource()
{
  std::unique_ptr<Resource> res(new Resource);
  return res; 
}
int main()
{
  std::unique_ptr<Resource> the_res;
  the_res = createResource(); // assignment invokes the copy assignment
  return 0;
}
```

我们可以进一步进行，因为 C++ 14 引入了一个辅助方法，以确保在处理`unique_ptrs`时具有异常安全性：

```cpp
std::unique_ptr<Resource> createResource()
{
  return std::make_unique<Resource>(); 
}
```

*为什么这是必要的？*考虑以下函数调用：

```cpp
some_function(std::unique_ptr<T>(new T), std::unique_ptr<U>(new U));
```

问题在于编译器可以自由地以任何顺序对参数列表中的操作进行排序。它可以调用`new T`，然后`new U`，然后`std::unique_ptr<T>()`，最后`std::unique_ptr<U>()`。这个顺序的问题在于，如果`new U`抛出异常，那么由调用`new T`分配的资源就没有被放入`unique_ptr`中，并且不会自动清理。使用`std::make_unique<>()`可以保证调用的顺序，以便资源的构建和`unique_ptr`的构建将一起发生，不会泄漏资源。在 C++17 中，对这些情况下的评估顺序的规则已经得到了加强，因此不再需要`make_unique`。然而，使用`make_unique<T>()`方法仍然可能是一个好主意，因为将来转换为 shared_ptr 会更容易。

名称`unique_ptr`清楚地表明了模板的意图，即它是指向对象的唯一所有者。这在`auto_ptr`中并不明显。同样，`shared_ptr`清楚地表明了它的意图是共享资源。`unique_ptr`模板提供了对以下操作符的访问：

+   **T* get()**：返回指向托管资源的指针。

+   如果实例管理资源，则为`true`（`get() != nullptr`）。

+   对托管资源的`lvalue`引用。与`*get()`相同。

+   `get()`。

+   `unique_ptr(new [])`，它提供对托管数组的访问，就像它本来是一个数组一样。返回一个`lvalue`引用，以便可以设置和获取值。

### std::shared_ptr

当您想要共享资源的所有权时，可以使用共享指针。为什么要这样做？有几种情况适合共享资源，比如在 GUI 程序中，您可能希望共享字体对象、位图对象等。**GoF 飞行权重设计模式**就是另一个例子。

`std::shared_ptr`提供了与`std::unique_ptr`相同的所有功能，但因为现在必须为对象跟踪引用计数，所以有更多的开销。所有在`std::unique_ptr`中描述的操作符都可以用在`std::shared_ptr`上。一个区别是创建`std::shared_ptr`的推荐方法是调用`std::make_shared<>()`。

在编写库或工厂时，库的作者并不总是知道用户将如何使用已创建的对象，因此建议从工厂方法返回`unique_ptr<T>`。原因是用户可以通过赋值轻松地将`std::unique_ptr`转换为`std::shared_ptr`：

```cpp
std::unique_ptr<MyClass> unique_obj = std::make_unique<MyClass>();
std::shared_ptr<MyClass> shared_obj = unique_obj;
```

这将转移所有权并使`unique_obj`为空。

#### 注意

一旦资源被作为共享资源，就不能将其恢复为唯一对象。

### std::weak_ptr

弱指针是共享指针的一种变体，但它不持有资源的引用计数。因此，当计数降为零时，它不会阻止资源被释放。考虑以下程序结构，它可能出现在正常的图形用户界面（GUI）中：

```cpp
#include <iostream>
#include <memory>
struct ScrollBar;
struct TextWindow;
struct Panel
{
    ~Panel() {
        std::cout << "--Panel destroyed\n";
    }
    void setScroll(const std::shared_ptr<ScrollBar> sb) {
        m_scrollbar = sb;
    }
    void setText(const std::shared_ptr<TextWindow> tw) {
        m_text = tw;
    }
    std::weak_ptr<ScrollBar> m_scrollbar;
    std::shared_ptr<TextWindow> m_text;
};
struct ScrollBar
{
    ~ScrollBar() {
        std::cout << "--ScrollBar destroyed\n";
    }
    void setPanel(const std::shared_ptr<Panel> panel) {
        m_panel=panel;
    }
    std::shared_ptr<Panel> m_panel;
};
struct TextWindow
{
    ~TextWindow() {
        std::cout << "--TextWindow destroyed\n";
    }
    void setPanel(const std::shared_ptr<Panel> panel) {
        m_panel=panel;
    }
    std::shared_ptr<Panel> m_panel;
};
void run_app()
{
    std::shared_ptr<Panel> panel = std::make_shared<Panel>();
    std::shared_ptr<ScrollBar> scrollbar = std::make_shared<ScrollBar>();
    std::shared_ptr<TextWindow> textwindow = std::make_shared<TextWindow>();
    scrollbar->setPanel(panel);
    textwindow->setPanel(panel);
    panel->setScroll(scrollbar);
    panel->setText(textwindow);
}
int main()
{
    std::cout << "Starting app\n";
    run_app();
    std::cout << "Exited app\n";
    return 0;
}
```

执行时，输出如下：

![图 3.25：弱指针程序输出](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_03_25.jpg)

###### 图 3.25：弱指针程序输出

这表明当应用程序退出时，面板和`textwindow`都没有被销毁。这是因为它们彼此持有`shared_ptr`，因此两者的引用计数不会降为零并触发销毁。如果我们用图表表示结构，那么我们可以看到它有一个`shared_ptr`循环：

![图 3.26：弱指针和共享指针循环](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_03_26.jpg)

###### 图 3.26：弱指针和共享指针循环

### 智能指针和调用函数

现在我们可以管理我们的资源了，我们如何使用它们？我们传递智能指针吗？当我们有一个智能指针（`unique_ptr`或`shared_ptr`）时，在调用函数时有四个选项：

+   通过值传递智能指针

+   通过引用传递智能指针

+   通过指针传递托管资源

+   通过引用传递托管资源

这不是一个详尽的列表，但是主要考虑的。我们如何传递智能指针或其资源的答案取决于我们对函数调用的意图：

+   函数的意图是仅仅使用资源吗？

+   函数是否接管资源的所有权？

+   函数是否替换托管对象？

如果函数只是要`使用资源`，那么它甚至不需要知道它正在使用托管资源。它只需要使用它，并且应该通过指针、引用（甚至值）调用资源：

```cpp
do_something(Resource* resource);
do_something(Resource& resource);
do_something(Resource resource);
```

如果你想要将资源的所有权传递给函数，那么函数应该通过智能指针按值调用，并使用`std::move()`调用：

```cpp
do_something(std::unique_ptr<Resource> resource);
auto res = std::make_unique<Resource>();
do_something (std::move(res));
```

当`do_something()`返回时，`res`变量将为空，资源现在由`do_something()`拥有。

如果你想要`替换托管对象`（一个称为**重新安置**的过程），那么你通过引用传递智能指针：

```cpp
do_something(std::unique_ptr<Resource>& resource);
```

以下程序将所有内容整合在一起，演示了每种情况以及如何调用函数：

```cpp
#include <iostream>
#include <memory>
#include <string>
#include <sstream>
class Resource
{
public:
  Resource() { std::cout << "+++Resource acquired ["<< m_id <<"]\n"; }
  ~Resource() { std::cout << "---Resource released ["<< m_id <<"]\n"; }
  std::string name() const {
      std::ostringstream ss;
      ss << "the resource [" << m_id <<"]";
      return ss.str();
  }
  int m_id{++m_count};
  static int m_count;
};
int Resource::m_count{0};
void use_resource(Resource& res)
{
    std::cout << "Enter use_resource\n";
    std::cout << "...using " << res.name() << "\n";
    std::cout << "Exit use_resource\n";
}
void take_ownership(std::unique_ptr<Resource> res)
{
    std::cout << "Enter take_ownership\n";
    if (res)
        std::cout << "...taken " << res->name() << "\n";
    std::cout << "Exit take_ownership\n";
}
void reseat(std::unique_ptr<Resource>& res)
{
    std::cout << "Enter reseat\n";
    res.reset(new Resource);
    if (res)
        std::cout << "...reseated " << res->name() << "\n";
    std::cout << "Exit reseat\n";
}
int main()
{
  std::cout << "Starting...\n";
  auto res = std::make_unique<Resource>();
  // Use - pass resource by reference
  use_resource(*res);               
  if (res)
    std::cout << "We HAVE the resource " << res->name() << "\n\n";
  else
    std::cout << "We have LOST the resource\n\n";
  // Pass ownership - pass smart pointer by value
  take_ownership(std::move(res));    
  if (res)
    std::cout << "We HAVE the resource " << res->name() << "\n\n";
  else
    std::cout << "We have LOST the resource\n\n";
  // Replace (reseat) resource - pass smart pointer by reference
  reseat(res);                      
  if (res)
    std::cout << "We HAVE the resource " << res->name() << "\n\n";
  else
    std::cout << "We have LOST the resource\n\n";
  std::cout << "Exiting...\n";
  return 0;
}
```

当我们运行这个程序时，我们会收到以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_03_27.jpg)

###### 图 3.27：所有权传递程序输出

#### 注意

*C++核心指南*有一个完整的部分涉及*资源管理*、智能指针以及如何在这里使用它们：[`isocpp.github.io/CppCoreGuidelines/CppCoreGuidelines#S-resource`](http://isocpp.github.io/CppCoreGuidelines/CppCoreGuidelines#S-resource)。我们只触及了指南涵盖的最重要的方面。

### 练习 4：使用 STL 智能指针实现 RAII

在这个练习中，我们将实现一个传感器工厂方法，通过`unique_ptr`返回传感器资源。我们将实现一个`unique_ptr`来持有一个数组，然后开发代码将`unique_ptr`转换为共享指针，然后再分享它。按照以下步骤实现这个练习：

1.  在 Eclipse 中打开**Lesson3**项目。然后在**项目资源管理器**中展开**Lesson3**，然后**Exercise04**，双击**Exercise4.cpp**以将此练习的文件打开到编辑器中。

1.  单击**启动配置**下拉菜单，选择**新启动配置...**。从**搜索项目**菜单中配置**L3Exercise4**应用程序，以便它以名称**L3Exercise4**运行。

1.  单击**运行**按钮运行练习 4。这将产生以下输出：![图 3.28：练习 4 输出](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_03_28.jpg)

###### 图 3.28：练习 4 输出

1.  在编辑器中，检查代码，特别是工厂方法，即`createSensor(type)`。

```cpp
std::unique_ptr<ISensor>
createSensor(SensorType type)
{
    std::unique_ptr<ISensor> sensor;
    if (type == SensorType::Light)
    {
        sensor.reset(new LightSensor);
    }
    else if (type == SensorType::Temperature)
    {
        sensor.reset(new TemperatureSensor);
    }
    else if (type == SensorType::Pressure)
    {
        sensor.reset(new PressureSensor);
    }
    return sensor;
}
```

这将创建一个名为 sensor 的空 unique 指针，然后根据传入的`type`重置包含的指针以获取所需的传感器。

1.  在编辑器中打开 Exercise4.cpp，并将文件顶部附近的行更改为以下内容：

```cpp
#define EXERCISE4_STEP  5
```

1.  点击`unique_ptr`到`shared_ptr`是不允许的。

1.  找到报告错误的行，并将其更改为以下内容：

```cpp
SensorSPtr light2 = std::move(light);
```

1.  点击`light`（一个`unique_ptr`）到`light2`（一个`shared_ptr`）。问题实际上是模板方法：

```cpp
template<typename SP>
void printSharedPointer(SP sp, const char* message)
```

第一个参数是按值传递的，这意味着将创建`shared_ptr`的新副本并传递给方法进行打印。

1.  现在让我们通过将模板更改为按引用传递来修复这个问题。点击**Run**按钮编译和运行程序。生成以下输出：![图 3.31：已更正的 printSharedPointer 输出](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_03_31.jpg)

###### 图 3.31：已更正的 printSharedPointer 输出

1.  在编辑器中打开**Exercise4.cpp**，并将文件顶部附近的行更改为以下内容：

```cpp
#define EXERCISE4_STEP  12
```

1.  点击**Run**按钮编译和运行程序。生成以下输出：![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_03_32.jpg)

###### 图 3.32：Exercise 4 的注释步骤 12 输出

1.  将输出与`testSensors()`方法中的代码进行比较。我们会发现可以轻松地将空的`unique_ptr`（`light`）分配给另一个，并且可以在不需要在任何情况下使用`std::move()`的情况下从一个`shared_ptr`分配给另一个（`light3 = light2`）。

1.  在编辑器中打开**Exercise4.cpp**，并将文件顶部附近的行更改为以下内容：

```cpp
#define EXERCISE4_STEP  15
```

1.  点击**Run**按钮编译和运行程序。输出切换为以下内容：![图 3.33：在 unique_ptr 中管理数组](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_03_33.jpg)

###### 图 3.33：在 unique_ptr 中管理数组

1.  在编辑器中找到`testArrays()`方法：

```cpp
void testArrays()
{
    std::unique_ptr<int []> board = std::make_unique<int []>(8*8);
    for(int i=0  ; i<8 ; i++)
        for(int j=0 ; j<8 ; j++)
            board[i*8+j] = 10*(i+1)+j+1;
    for(int i=0  ; i<8 ; i++)
    {
        char sep{' '};
        for(int j=0 ; j<8 ; j++)
            std::cout << board[i*8+j] << sep;
        std::cout << "\n";
    }
}
```

在这段代码中有几点需要注意。首先，类型声明为`int[]`。我们在这个练习中选择了`int`，但它可以是几乎任何类型。其次，当使用`unique_ptr`（自 C++ 17 以来也是`shared_ptr`）来管理数组时，定义了`operator[]`。因此，我们通过从二维索引的`board[i*8+j]`计算出一维索引来模拟二维数组。

1.  编辑方法的第一行并声明`auto`类型：

```cpp
auto board = std::make_unique<int []>(8*8);
```

1.  点击`make_unique()`调用。

在这个练习中，我们实现了一个工厂函数，使用`unique_ptr`来管理传感器的生命周期。然后，我们实现了将其从`unique_ptr`更改为共享到多个对象。最后，我们开发了一种使用单一维数组来管理多维数组的`unique_ptr`技术。

### 零/五法则-不同的视角

当我们引入`BufferedWriter`时，它管理了两个资源：内存和文件。然后我们讨论了默认编译器生成的浅拷贝操作。我们谈到了我们可以以不同的方式管理资源-停止复制，执行深拷贝，或者转移所有权。在这些情况下我们决定如何做被称为资源管理策略。您选择的策略将影响您如何执行`零/五法则`。

在资源管理方面，一个类可以管理零个资源，管理可以复制但不能移动的资源，管理可以移动但不能复制的资源，或者管理不应复制也不应移动的资源。以下类显示了如何表达这些类别：

```cpp
struct NoResourceToManage
{
    // use compiler generated copy & move constructors and operators
};
struct CopyOnlyResource
{
    ~CopyOnlyResource()                                      {/* defined */ }
    CopyOnlyResource(const CopyOnlyResource& rhs)            {/* defined */ }
    CopyOnlyResource& operator=(const CopyOnlyResource& rhs) {/* defined */ }
    CopyOnlyResource(CopyOnlyResource&& rhs) = delete;
    CopyOnlyResource& operator=(CopyOnlyResource&& rhs) = delete;
};
struct MoveOnlyResource
{
    ~MoveOnlyResource()                                      {/* defined */ }
    MoveOnlyResource(const MoveOnlyResource& rhs)             = delete;
    MoveOnlyResource& operator=(const MoveOnlyResource& rhs)  = delete;
    MoveOnlyResource(MoveOnlyResource&& rhs)                 {/* defined */ }  
    MoveOnlyResource& operator=(MoveOnlyResource&& rhs)      {/* defined */ }
};
struct NoMoveOrCopyResource
{
    ~NoMoveOrCopyResource()                                  {/* defined */ }
    NoMoveOrCopyResource(const NoMoveOrCopyResource& rhs)             = delete;
    NoMoveOrCopyResource& operator=(const NoMoveOrCopyResource& rhs)  = delete;
    NoMoveOrCopyResource(NoMoveOrCopyResource&& rhs)                  = delete;
    NoMoveOrCopyResource& operator=(NoMoveOrCopyResource&& rhs)       = delete;
};
```

由于在所有上下文和异常下管理资源的复杂性，最佳实践是，如果一个类负责管理资源，那么该类只负责管理该资源。

### 活动 1：使用 RAII 和 Move 实现图形处理

在*第 2A 章*，*不允许鸭子-类型和推断*中，您的团队努力工作并实现了`Point3d`和`Matrix3d`。现在，您的公司希望在推出之前对库进行两项重大改进：

+   公司的类必须在一个命名空间中，即 Advanced C Plus Plus Inc.因此，图形的命名空间将是`accp::gfx`。

+   `Point3d`和`Matrix3d`中矩阵的存储是类的固有部分，因此它是从堆栈而不是堆中分配的。作为库矩阵支持的演变，我们需要从堆中分配内存。因为我们正在努力实现更大的矩阵在未来的版本中，我们还希望在我们的类中引入移动语义。

按照以下步骤实现这一点：

1.  从我们当前版本的库开始（可以在`acpp::gfx`命名空间中找到。

1.  修复所有因更改而失败的测试。（失败可能意味着编译失败，而不仅仅是运行测试。）

1.  在`Matrix3d`中，从在类中直接声明矩阵切换到堆分配的存储器。

1.  通过实现复制构造函数和复制赋值运算符的深度复制实现来修复失败的测试。进行其他必要的更改以适应新的内部表示。请注意，您不需要修改任何测试来使其通过，因为它们只访问公共接口，这意味着我们可以更改内部结构而不影响客户端。

1.  通过在`CreateTranslationMatrix()`中使用`std::move`强制调用移动构造函数来触发另一个失败。在`Matrix3d`类中引入所需的移动操作以使测试能够编译并通过。

1.  重复步骤 3 到 4，针对`Point3d`。

在实现上述步骤后，预期的输出看起来与开始时没有变化：

![图 3.34：成功转换为使用 RAII 后的活动 1 输出](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_03_34.jpg)

###### 图 3.34：成功转换为使用 RAII 后的活动 1 输出

#### 注意

此活动的解决方案可以在第 657 页找到。

### 何时调用函数？

C++程序执行的所有操作本质上都是函数调用（尽管编译器可能会将这些优化为内联操作序列）。但是，由于`a = 2 + 5`，你可能不会意识到自己在进行函数调用，实际上你在调用`operator=(&a, operator+(2, 5))`。只是语言允许我们写第一种形式，但第二种形式允许我们重载运算符并将这些功能扩展到用户定义的类型。

以下机制会导致对函数的调用：

+   显式调用函数。

+   所有运算符，如+，-，*，/，%，以及 new/delete。

+   变量的声明-如果存在初始化值，则会导致对带有参数的构造函数的调用。

+   用户定义的字面量-我们还没有处理这些，但基本上，我们为`type operator "" name(argument)`定义了一个重载。然后我们可以写诸如 10_km 之类的东西，这样可以使我们的代码更容易理解，因为它携带了语义信息。

+   从一个值转换为另一个值（`static_cast<>`，`const_cast<>`，`reinterpret_cast<>`和`dynamic_cast<>`）。再次，我们有另一个运算符重载，允许我们将一种类型转换为另一种类型。

+   在函数重载期间，可能需要将一种类型转换为另一种类型，以使其与函数原型匹配。它可以通过调用具有正确参数类型的构造函数来创建临时对象，或者通过隐式调用的转换运算符来实现。

每一个结果都会让编译器确定必须调用一个函数。确定需要调用一个函数后，必须找到与名称和参数匹配的函数。这是我们将在下一节讨论的内容。

### 调用哪个函数

在*第 2A 章*，*不允许鸭子 - 类型和推断*中，我们看到函数重载解析是按以下方式执行的：

![图 3.35：函数重载解析](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_03_35.jpg)

###### 图 3.35：函数重载解析

我们真正没有深入研究的是名称查找的概念。在某个时刻，编译器将遇到对`func`函数的以下调用：

```cpp
func(a, b);
```

当这种情况发生时，它必须将其名称与引入它的声明关联起来。这个过程称为**名称查找**。这种名称查找对程序中的所有项目（变量、命名空间、类、函数、函数模板和模板）都适用。为了使程序编译通过，变量、命名空间和类的名称查找过程必须产生一个单一的声明。然而，对于函数和函数模板，编译器可以将多个声明与相同的名称关联起来 - 主要是通过函数重载，可以通过**参数依赖查找**（**ADL**）考虑到额外的函数。

### 标识符

根据 C++标准的定义，**标识符**是一系列大写和小写拉丁字母、数字、下划线和大多数 Unicode 字符。有效的标识符必须以非数字字符开头，长度任意长且区分大小写。每个字符都是有意义的。

### 名称

**名称**用于引用实体或标签。名称可以是以下形式之一：

+   标识符

+   函数符号重载的运算符名称（例如 operator-，operator delete）

+   模板名称后跟其参数列表（vector<int>）

+   用户定义的转换函数名称（operator float）

+   用户定义的字面量运算符名称（operator ""_ms）

每个实体及其名称都是由声明引入的，而标签的名称是由**goto**语句或标记语句引入的。一个名称可以在一个文件（或翻译单元）中多次使用，以依赖于作用域而引用不同的实体。一个名称也可以用来引用跨多个文件（翻译单元）相同的实体，或者根据链接性引用不同的实体。编译器使用名称查找通过**名称查找**将引入名称的声明与程序中的未知名称关联起来。

### 名称查找

名称查找过程是两种之一，并且是根据上下文选择的：

+   `::`，或者可能在`::`之后，跟着`template`关键字。限定名可以指代命名空间成员、类成员或枚举器。`::`运算符左边的名称定义了要从中查找名称的作用域。如果没有名称，那么就使用全局命名空间。

+   **未经限定名称查找**：其他所有情况。在这种情况下，名称查找检查当前作用域和所有封闭作用域。

如果未经限定的名称位于函数调用运算符'`()`'的左侧，则使用参数依赖查找。

### 依赖参数的查找

查找未经限定的函数名的规则集称为“参数依赖查找”（简称 ADL），或者“Koenig 查找”（以 Andrew Koenig 命名，他定义了它，并且是 C++标准委员会的资深成员）。未经限定的函数名可以出现为函数调用表达式，也可以作为对重载运算符的隐式函数调用的一部分。

ADL 基本上表示，在未经限定名称查找期间考虑的作用域和命名空间之外，还考虑所有参数和模板参数的“关联命名空间”。考虑以下代码：

```cpp
#include <iostream>
#include <string>
int main()
{
    std::string welcome{"Hello there"};
    std::cout << welcome;
    endl(std::cout);
}
```

当我们编译这段代码并运行它时，输出结果如预期的那样：

```cpp
$ ./adl.exe
Hello there
$
```

这是一种不寻常的编写程序的方式。通常，它会被这样编写：

```cpp
#include <iostream>
#include <string>
int main()
{
    std::string welcome{"Hello there"};
    std::cout << welcome << std::endl;
}
```

我们使用调用`endl()`来展示 ADL 的奇怪方法。但是这里发生了两次 ADL 查找。

第一个经历 ADL 的函数调用是`std::cout << welcome`，编译器认为这是`operator<<(std::cout, welcome)`。现在，操作符<<在可用范围和其参数的命名空间`std`中被查找。这个额外的命名空间将名称解析为自由方法，即在字符串头文件中声明的`std::operator<<(ostream& os, string& s)`。

第二个调用更明显`endl(std::cout)`。同样，编译器可以访问 std 命名空间来解析这个名称查找，并在头文件`ostream`（包含在`iostream`中）中找到`std::endl`模板。

没有 ADL，编译器无法找到这两个函数，因为它们是由 iostream 和 string 包提供的自由函数。插入操作符（<<）的魔力将会丢失，如果我们被迫写`std::operator<<(std::cout, welcome)`，对程序员来说将会很繁琐。如果考虑到链式插入，情况会更糟。或者，您可以写"`using namespace std;`"。这两种选项都不理想，这就是为什么我们需要 ADL（Koenig 查找）。

### 买家当心

我们已经看到 ADL 通过包含与函数参数类型相关的命名空间，使程序员的生活更加轻松。然而，这种查找能力并非没有风险，大部分情况下我们可以将风险降到最低。考虑以下示例代码：

```cpp
#include <iostream>
namespace mylib 
{
void is_substring(std::string superstring, std::string substring)
{
    std::cout << "mylib::is_substring()\n";
}
void contains(std::string superstring, const char* substring) {
    is_substring(superstring, substring);
}
}
int main() {
    mylib::contains("Really long reference", "included");
}
```

当我们编译和运行上述程序时，我们得到了预期的输出：

![图 3.36：ADL 示例程序输出](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_03_36.jpg)

###### 图 3.36：ADL 示例程序输出

C++标准委员会随后决定引入一个`is_substring()`函数，看起来像这样：

```cpp
namespace std {
void is_substring(std::string superstring, const char* substring)
{
    std::cout << "std::is_substring()\n";
}
}
```

如果我们将其添加到文件顶部，编译并重新运行，现在我们得到以下输出：

![图 3.37：ADL 问题程序输出](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_03_37.jpg)

###### 图 3.37：ADL 问题程序输出

由于 ADL，（下一个 C++标准）编译器选择了不同的实现作为`is_substring()`的未限定函数调用的更好选择。并且由于参数的隐式转换，它不会导致歧义和编译器错误。它只是悄悄地采用了新的方法，这可能会导致细微且难以发现的错误，如果参数顺序不同。编译器只能检测类型和语法差异，而不能检测语义差异。

#### 注意

为了演示 ADL 的工作原理，我们已将我们的函数添加到 std 命名空间中。命名空间有一个分离关注点的目的，特别是添加到别人的命名空间，特别是`标准库命名空间`（`std`）是不好的做法。

那么，为什么要买家注意（买家当心）？如果您在开发中使用第三方库（包括 C++标准库），那么当您升级库时，您需要确保接口的更改不会因为 ADL 而导致问题。

### 练习 5：实现模板以防止 ADL 问题

在这个练习中，我们将演示 C++17 STL 中的一个破坏性变化，这可能会在实际中引起问题。C++11 引入了`std::begin(type)`和`std::end(type)`的模板。作为开发人员，这是一种对通用接口的吸引人的表达，您可能已经为 size(type)和 empty(type)编写了自己的版本。按照以下步骤实现这个练习：

1.  在 Eclipse 中打开**Lesson3**项目。然后在**Project Explorer**中展开**Lesson3**，然后**Exercise05**，双击**Exercise5.cpp**以将此练习的文件打开到编辑器中。

1.  单击**Launch Configuration**下拉菜单，选择**New Launch Configuration…**。从搜索项目菜单配置**L3Exercise5**应用程序，以便以**L3Exercise5**的名称运行。

1.  单击**Run**按钮运行 Exercise 5。这将产生以下输出：![图 3:38：Exercise 5 成功执行](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_03_38.jpg)

###### 图 3:38：练习 5 的成功执行

1.  代码检查发现了两个辅助模板：

```cpp
template<class T>
bool empty(const T& x)
{
    return x.empty();
}
template<class T>
int size(const T& x)
{
    return x.size();
}
```

1.  与所有其他练习不同，此练习已配置为在 C++ 14 下构建。打开**Lesson3**下的**CMakeLists.txt**文件，并找到以下行：

```cpp
set_property(TARGET L3Exercise5 PROPERTY CXX_STANDARD 14)
```

1.  将`14`改为`17`。

1.  单击**Run**按钮编译练习，现在失败：![图 3.39：C++ 17 下编译失败-模棱两可的函数调用](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_03_39.jpg)

###### 图 3.39：C++ 17 下编译失败-模棱两可的函数调用

1.  因为`empty()`和`size()`模板的参数是 std::vector，ADL 引入了新包含的 STL 版本的这些模板，破坏了我们的代码。

1.  在`empty()`和两个生成错误的`size()`出现之前，在它们（作用域限定符）之前插入两个冒号“`::`”。

1.  单击`empty()`和`size()`函数现在已经有了限定。我们也可以指定`std::`作用域。

在这个练习中，我们在全局命名空间中实现了两个模板函数，如果我们在 C++ 14 标准下编译程序，它们就可以正常工作。然而，当我们在 C++17 下编译时，我们的实现就会出问题，因为 STL 库发生了变化，我们必须改变我们的实现，以确保编译器定位并使用我们编写的模板。

### 隐式转换

在确定*图 3.36*中的函数候选集时，编译器必须查看所有在名称查找期间找到的可用函数，并确定参数数量和类型是否匹配调用点。在确定类型是否匹配时，它还将检查所有可用的转换，以确定是否有一种机制可以将类型 T1 类型（传递的参数类型）转换为 T2 类型（函数参数指定的类型）。如果它可以将所有参数从 T1 转换为 T2，那么它将把函数添加到候选集中。

从类型 T1 到类型 T2 的这种转换被称为**隐式转换**，当某种类型 T1 在不接受该类型但接受其他类型 T2 的表达式或上下文中使用时发生。这发生在以下情境中：

+   T1 作为参数传递时调用以 T2 为参数声明的函数。

+   T1 用作期望 T2 的运算符的操作数。

+   T1 用于初始化 T2 的新对象（包括返回语句）。

+   T1 在`switch`语句中使用（在这种情况下，T2 是 int）。

+   T1 在`if`语句或`do-while`或`while`循环中使用（其中 T2 为 bool）。

如果存在从 T1 到 2 的明确转换序列，则程序将编译。内置类型之间的转换通常由通常的算术转换确定。

### 显式-防止隐式转换

隐式转换是一个很好的特性，使程序员能够表达他们的意图，并且大多数时候都能正常工作。然而，编译器在程序员没有提供提示的情况下将一种类型转换为另一种类型的能力并不总是理想的。考虑以下小程序：

```cpp
#include <iostream>
class Real
{
public:
    Real(double value) : m_value{value} {}
    operator float() {return m_value;}
    float getValue() const {return m_value;}
private:
    double m_value {0.0};
};
void test(bool result)
{
    std::cout << std::boolalpha;
    std::cout << "Test => " << result << "\n";
}
int main()
{
    Real real{3.14159};
    test(real);
    if ( real ) 
    {
        std::cout << "true: " << real.getValue() << "\n";
    }
    else
    {
        std::cout << "false: " << real.getValue() << "\n";
    }
}
```

当我们编译并运行上述程序时，我们得到以下输出：

![图 3.40：隐式转换示例程序输出](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_03_40.jpg)

###### 图 3.40：隐式转换示例程序输出

嗯，这可能有点出乎意料，它编译并实际产生了输出。`real`变量是`Real`类型，它有一个到 float 的转换运算符- `operator float()`。`test()`函数以`bool`作为参数，并且`if`条件也必须产生一个`bool`。如果值为零，则编译器将任何数值类型转换为值为 false 的`boolean`类型，如果值不为零，则转换为 true。但是，如果这不是我们想要的行为，我们可以通过在函数声明前加上 explicit 关键字来阻止它。假设我们更改行，使其读起来像这样：

```cpp
explicit operator float() {return m_value;}
```

如果我们现在尝试编译它，我们会得到两个错误：

![图 3.41：因为隐式转换被移除而导致的编译错误。](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_03_41.jpg)

###### 图 3.41：因为隐式转换被移除而导致的编译错误。

两者都与无法将 Real 类型转换为 bool 有关 - 首先是对`test()`的调用位置，然后是 if 条件中。

现在，让我们引入一个 bool 转换操作符来解决这个问题。

```cpp
operator bool() {return m_value == 0.0;}
```

现在我们可以再次构建程序。我们将收到以下输出：

![图 3.42：引入 bool 运算符替换隐式转换](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_03_42.jpg)

###### 图 3.42：引入 bool 运算符替换隐式转换

`boolean`值现在为 false，而以前为 true。这是因为浮点转换返回的值的隐式转换不为零，然后转换为 true。

自 C++ 11 以来，所有构造函数（除了复制和移动构造函数）都被认为是转换构造函数。这意味着如果它们没有声明为显式，则它们可用于隐式转换。同样，任何未声明为显式的转换操作符都可用于隐式转换。

`C++核心指南`有两条与隐式转换相关的规则：

+   **C.46**：默认情况下，将单参数构造函数声明为显式

+   **C.164**：避免隐式转换操作符

### 上下文转换

如果我们现在对我们的小程序进行进一步的更改，我们就可以进入所谓的上下文转换。让我们将 bool 运算符设置为显式，并尝试编译程序：

```cpp
explicit operator bool() {return m_value == 0.0;}
```

我们将收到以下输出：

![图 3.43：使用显式 bool 运算符的编译错误](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_03_43.jpg)

###### 图 3.43：使用显式 bool 运算符的编译错误

这次我们只有一个错误，即对`test()`的调用位置，但对 if 条件没有错误。我们可以通过使用 C 风格的转换（bool）或 C++ `static_cast<bool>(real)`（这是首选方法）来修复此错误。当我们添加转换时，程序再次编译和运行。

因此，如果 bool 转换是显式的，那么为什么 if 表达式的条件不需要转换？

C++标准允许在某些情况下，如果期望`bool`类型并且存在 bool 转换的声明（无论是否标记为显式），则允许隐式转换。这被称为**上下文转换为 bool**，并且可以出现在以下上下文中：

+   `if`、`while`、`for`的条件（或控制表达式）

+   内置逻辑运算符的操作数：`!`（非）、`&&`（与）和`||`（或）

+   条件（或条件）运算符`?:`的第一个操作数。

### 练习 6：隐式和显式转换

在这个练习中，我们将尝试调用函数、隐式转换、阻止它们以及启用它们。按照以下步骤实施这个练习：

1.  在 Eclipse 中打开**Lesson3**项目。然后在**Project Explorer**中展开**Lesson3**，然后展开**Exercise06**，双击**Exercise6.cpp**以在编辑器中打开此练习的文件。

1.  单击**Launch Configuration**下拉菜单，选择**New Launch Configuration…**。从**Search Project**菜单中配置**L3Exercise6**应用程序，以便以**L3Exercise6**的名称运行。

1.  单击**Run**按钮运行练习 6。这将产生以下输出：![图 3.44：练习 6 的默认输出](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_03_44.jpg)

###### 图 3.44：练习 6 的默认输出

1.  在文本编辑器中，将`Voltage`的构造函数更改为`explicit`：

```cpp
struct Voltage
{
    explicit Voltage(float emf) : m_emf(emf) 
    {
    }
    float m_emf;
};
```

1.  单击**Run**按钮重新编译代码 - 现在我们得到以下错误：![图 3.45：int 转换为 Voltage 失败](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_03_45.jpg)

###### 图 3.45：int 转换为 Voltage 失败

1.  从构造函数中删除显式，并将`calculate`函数更改为引用：

```cpp
void calculate(Voltage& v)
```

1.  单击**Run**按钮重新编译代码 - 现在，我们得到以下错误：![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_03_46.jpg)

###### 图 3.46：将整数转换为电压&失败

同一行出现了我们之前遇到的问题，但原因不同。因此，*隐式转换仅适用于值类型*。

1.  注释掉生成错误的行，然后在调用`use_float(42)`之后，添加以下行：

```cpp
use_float(volts);
```

1.  单击**Run**按钮重新编译代码-现在我们得到以下错误：![图 3.47：电压转换为浮点数失败](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_03_47.jpg)

###### 图 3.47：电压转换为浮点数失败

1.  现在，将以下转换运算符添加到`Voltage`类中：

```cpp
operator float() const
{
    return m_emf;
}
```

1.  单击**Run**按钮重新编译代码并运行它：![图 3.48：成功将电压转换为浮点数](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_03_48.jpg)

###### 图 3.48：成功将电压转换为浮点数

1.  现在，在我们刚刚添加的转换前面放置`explicit`关键字，然后单击**Run**按钮重新编译代码。再次出现错误：![图 3.49：无法将电压转换为浮点数](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_03_49.jpg)

###### 图 3.49：无法将电压转换为浮点数

1.  通过在转换中添加显式声明，我们可以防止编译器使用转换运算符。将出错的行更改为将电压变量转换为浮点数：

```cpp
use_float(static_cast<float>(volts));
```

1.  单击**Run**按钮重新编译代码并运行它。

![图 3.50：使用转换将电压转换为浮点数再次成功](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_03_50.jpg)

###### 图 3.50：使用转换将电压转换为浮点数再次成功

在这个练习中，我们已经看到了类型（而不是引用）之间可以发生隐式转换，并且我们可以控制它们何时发生。现在我们知道如何控制这些转换，我们可以努力满足先前引用的指南`C.46`和`C.164`。

### 活动 2：实现日期计算的类

您的团队负责开发一个库，以帮助处理与日期相关的计算。特别是，我们希望能够确定两个日期之间的天数，并且给定一个日期，添加（或从中减去）一定数量的天数以获得一个新日期。此活动将开发两种新类型并增强它们，以确保程序员不能意外地使它们与内置类型交互。按照以下步骤来实现这一点：

1.  设计和实现一个`Date`类，将`day`、`month`和`year`作为整数存储。

1.  添加方法来访问内部的天、月和年值。

1.  定义一个类型`date_t`来表示自 1970 年 1 月 1 日`纪元日期`以来的天数。

1.  向`Date`类添加一个方法，将其转换为`date_t`。

1.  添加一个方法来从`date_t`值设置`Date`类。

1.  创建一个存储天数值的`Days`类。

1.  为`Date`添加一个接受`Days`作为参数的`加法`运算符。

1.  使用`explicit`来防止数字的相加。

1.  添加`减法`运算符以从两个`日期`的`差异`返回`Days`值。

在按照这些步骤之后，您应该收到以下输出：

![图 3.51：成功的日期示例应用程序输出](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_03_51.jpg)

###### 图 3.51：成功的日期示例应用程序输出

#### 注意

此活动的解决方案可在第 664 页找到。

## 总结

在本章中，我们探讨了变量的生命周期 - 包括自动变量和动态变量，它们存储在何处，以及它们何时被销毁。然后，我们利用这些信息开发了`RAII`技术，使我们几乎可以忽略资源管理，因为自动变量在被销毁时会清理它们，即使在出现异常的情况下也是如此。然后，我们研究了抛出异常和捕获异常，以便我们可以在正确的级别处理异常情况。从`RAII`开始，我们进入了关于资源所有权的讨论，以及`STL`智能指针如何帮助我们在这个领域。我们发现几乎所有东西都被视为函数调用，从而允许操作符重载和隐式转换。我们发现了“参数相关查找”（`ADL`）的奇妙（或者说糟糕？）世界，以及它如何潜在地在未来使我们陷入困境。我们现在对 C++的基本特性有了很好的理解。在下一章中，我们将开始探讨函数对象以及它们如何使用 lambda 函数实现和实现。我们将进一步深入研究 STL 的功能，并在重新访问封装时探索 PIMPLs。
