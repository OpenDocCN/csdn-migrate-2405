# C++ 游戏开发秘籍（三）

> 原文：[`zh.annas-archive.org/md5/260E2BE0C3FA0FF74505C2A10CA40511`](https://zh.annas-archive.org/md5/260E2BE0C3FA0FF74505C2A10CA40511)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：游戏开发的设计模式

在本章中，将涵盖以下示例：

+   使用单例设计模式

+   使用工厂方法

+   使用抽象工厂方法

+   使用观察者模式

+   使用享元模式

+   使用策略模式

+   使用命令设计模式

+   使用设计模式创建高级游戏

# 介绍

让我们假设我们面临某个问题。过了一段时间，我们找到了解决这个问题的方法。现在，如果问题再次发生，或者类似的问题模式再次发生，我们将知道如何通过应用解决先前问题的相同原则来解决问题。设计模式就类似于这个。已经有 23 种这样的解决方案被记录下来，它们为处理与已记录的问题具有相似模式的问题提供了微妙的解决方案。这些解决方案由作者描述，更常被称为*四人帮*。它们不是完整的解决方案，而是可以应用于类似情况的模板或框架。然而，设计模式最大的缺点之一是，如果它们没有被正确应用，它们可能会证明是灾难性的。设计模式可以被分类为结构型、行为型或创建型。我们将只研究其中一些，在游戏开发中经常使用的。

# 使用单例设计模式

单例设计模式是游戏中最常用的设计模式。不幸的是，它也是游戏中最常被滥用和错误应用的设计模式。单例设计模式有一些优点，我们将讨论。然而，它也有很多严重的后果。

## 准备工作

要完成本示例，您需要一台运行 Windows 的计算机。您还需要在 Windows 计算机上安装一个可用的 Visual Studio 副本。不需要其他先决条件。

## 如何做…

在这个示例中，我们将看到创建单例设计模式有多么容易。我们还将看到这种设计模式的常见陷阱：

1.  打开 Visual Studio。

1.  创建一个新的 C++项目。

1.  选择一个 Win32 控制台应用程序。

1.  添加一个名为`Source.cpp`的源文件。

1.  将以下代码添加到其中：

```cpp
#include <iostream>
#include <conio.h>

using namespace std;

class PhysicsManager
{
private:
  static bool bCheckFlag;
  static PhysicsManager *s_singleInstance;
  PhysicsManager()
  {
    //private constructor
  }
public:
  static PhysicsManager* getInstance();
  void GetCurrentGravity()const;

  ~PhysicsManager()
  {
    bCheckFlag = false;
  }
};

bool PhysicsManager::bCheckFlag = false;

PhysicsManager* PhysicsManager::s_singleInstance = NULL;

PhysicsManager* PhysicsManager::getInstance()
{
  if (!bCheckFlag)
  {
    s_singleInstance = new PhysicsManager();
    bCheckFlag = true;
    return s_singleInstance;
  }
  else
  {
    return s_singleInstance;
  }
}

void PhysicsManager::GetCurrentGravity() const
{
  //Some calculations for finding the current gravity
  //Probably a base variable which constantly gets updated with value
  //based on the environment
  cout << "Current gravity of the system is: " <<9.8<< endl;
}

int main()
{
  PhysicsManager *sc1, *sc2;
  sc1 = PhysicsManager::getInstance();
  sc1->GetCurrentGravity();
  sc2 = PhysicsManager::getInstance();
  sc2->GetCurrentGravity();

  _getch();
  return 0;
}
```

## 它是如何工作的…

开发人员希望使用单例类的主要原因是他们希望限制类的实例只有一个。在我们的示例中，我们使用了`PhysicsManager`类。我们将构造函数设为私有，然后分配一个静态函数来获取类的实例和其方法的句柄。我们还使用一个布尔值来检查是否已经创建了一个实例。如果是，我们不分配新实例。如果没有，我们分配一个新实例并调用相应的方法。

尽管这种设计模式看起来很聪明，但它有很多缺陷，因此在游戏设计中应尽量避免使用。首先，它是一个全局变量。这本身就是不好的。全局变量保存在全局池中，可以从任何地方访问。其次，这鼓励了糟糕的耦合，可能会出现在代码中。第三，它不友好并发。想象一下有多个线程，每个线程都可以访问这个全局变量。这是灾难的开始，死锁会发生。最后，新程序员最常犯的一个错误是为所有事物创建管理器，然后将管理器设为单例。事实上，我们可以通过有效地使用面向对象编程和引用来避免创建管理器。

上述代码显示了一种懒惰初始化单例的值，因此可以改进。然而，本示例中描述的所有基本问题仍将存在。

# 使用工厂方法

工厂本质上是创建其他类型对象的仓库。在工厂方法设计模式中，创建新类型的对象，比如敌人或建筑，是通过接口和子类决定需要实例化哪个类来实现的。这也是游戏中常用的模式，非常有用。

## 准备工作

您需要在 Windows 机器上安装一个可用的 Visual Studio 副本。

## 如何做…

在这个示例中，我们将发现实现工厂方法设计模式是多么容易：

1.  打开 Visual Studio。

1.  创建一个新的 C++项目。

1.  选择一个 Win32 控制台应用程序。

1.  添加一个名为`Source.cpp`的源文件。

1.  添加以下代码行：

```cpp
#include <iostream>
#include <conio.h>
#include <vector>

using namespace std;

class IBuilding
{
public:
  virtual void TotalHealth() = 0;
};

class Barracks : public IBuilding
{
public:
  void TotalHealth()
  {
    cout << "Health of Barrack is :" << 100;
  }
};
class Temple : public IBuilding
{
public:
  void TotalHealth()
  {
    cout << "Health of Temple is :" << 75;
  }
};
class Farmhouse : public IBuilding
{
public:
  void TotalHealth()
  {
    cout << "Health of Farmhouse is :" << 50;
  }
};

int main()
{
  vector<IBuilding*> BuildingTypes;
  int choice;

  cout << "Specify the different building types in your village" << endl;
  while (true)
  {

    cout << "Barracks(1) Temple(2) Farmhouse(3) Go(0): ";
    cin >> choice;
    if (choice == 0)
      break;
    else if (choice == 1)
      BuildingTypes.push_back(new Barracks);
    else if (choice == 2)
      BuildingTypes.push_back(new Temple);
    else
      BuildingTypes.push_back(new Farmhouse);
  }
  cout << endl;
  cout << "There are total " << BuildingTypes.size() << " buildings" << endl;
  for (int i = 0; i < BuildingTypes.size(); i++)
  {
    BuildingTypes[i]->TotalHealth();
    cout << endl;
  }

  for (int i = 0; i < BuildingTypes.size(); i++)
    delete BuildingTypes[i];

  _getch();
}
```

## 工作原理…

在这个例子中，我们创建了一个`Building`接口，其中有一个纯虚函数`TotalHealth`。这意味着所有派生类必须重写这个函数。因此，我们可以保证所有的建筑都有这个属性。我们可以通过添加更多的属性来扩展这个结构，比如生命值、总存储容量、村民生产速度等，根据游戏的性质和设计。派生类有它们自己的`TotalHealth`实现。它们也被命名为反映它们是什么类型的建筑。这种设计模式的最大优势是，客户端只需要一个对基础接口的引用。之后，我们可以在运行时创建我们需要的建筑类型。我们将这些建筑类型存储在一个向量列表中，最后使用循环来显示内容。由于我们有引用`IBuilding*`，我们可以在运行时分配任何新的派生类。无需为所有派生类创建引用，比如`Temple*`等等。下面的屏幕截图显示了用户定义村庄的输出：

![工作原理…](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-gm-dev-cb/img/4929_06_01.jpg)

# 使用抽象工厂方法

抽象工厂是创建设计模式的一部分。这是创建对象的最佳方式之一，也是游戏中常见的重复设计模式之一。它就像是一个工厂的工厂。它使用一个接口来创建一个工厂。工厂负责创建对象，而不指定它们的类类型。工厂基于工厂方法设计模式生成这些对象。然而，有人认为抽象工厂方法也可以使用原型设计模式来实现。

## 准备工作

您需要在 Windows 机器上安装一个可用的 Visual Studio 副本。

## 如何做…

在这个示例中，我们将发现实现抽象工厂模式是多么容易：

1.  打开 Visual Studio。

1.  创建一个新的 C++项目。

1.  选择一个 Win32 控制台应用程序。

1.  添加一个名为`Source.cpp`的源文件。

1.  添加以下代码行：

```cpp
#include <iostream>
#include <conio.h>
#include <string>

using namespace std;

//IFast interface
class IFast
{
public:
  virtual std::string Name() = 0;
};

//ISlow interface
class ISlow
{
public:
  virtual std::string Name() = 0;
};
class Rapter : public ISlow
{
public:
  std::string Name()
  {
    return "Rapter";
  }
};

class Cocumbi : public IFast
{
public:
  std::string Name()
  {
    return "Cocumbi";
  }
};
   . . . . .// Similar classes can be written here
class AEnemyFactory
{
public:
  enum Enemy_Factories
  {
    Land,
    Air,
    Water
  };

  virtual IFast* GetFast() = 0;
  virtual ISlow* GetSlow() = 0;

  static AEnemyFactory* CreateFactory(Enemy_Factories factory);
};

class LandFactory : public AEnemyFactory
{
public:
  IFast* GetFast()
  {
    return new Cocumbi();
  }

  ISlow* GetSlow()
  {
    return new Marzel();
  }
};

class AirFactory : public AEnemyFactory
{
public:
  IFast* GetFast()
  {
    return new Zybgry();
  }

  ISlow* GetSlow()
  {
    return new Bungindi();
  }
};

class WaterFactory : public AEnemyFactory
{
public:
  IFast* GetFast()
  {
    return new Manama();
  }

  ISlow* GetSlow()
  {
    return new Pokili();
  }
};

//CPP File
AEnemyFactory* AEnemyFactory::CreateFactory(Enemy_Factories factory)
{
  if (factory == Enemy_Factories::Land)
  {
    return new LandFactory();
  }
  else if (factory == Enemy_Factories::Air)
  {
    return new AirFactory();
  }
  else if (factory == Enemy_Factories::Water)
  {
    return new WaterFactory();
  }
}

int main(int argc, char* argv[])
{
  AEnemyFactory *factory = AEnemyFactory::CreateFactory
    (AEnemyFactory::Enemy_Factories::Land);

  cout << "Slow enemy of Land: " << factory->GetSlow()->Name() << "\n";
  delete factory->GetSlow();
  cout << "Fast enemy of Land: " << factory->GetFast()->Name() << "\n";
  delete factory->GetFast();
  delete factory;
  getchar();

  factory = AEnemyFactory::CreateFactory(AEnemyFactory::Enemy_Factories::Air);
  cout << "Slow enemy of Air: " << factory->GetSlow()->Name() << "\n";
  delete factory->GetSlow();
  cout << "Fast enemy of Air: " << factory->GetFast()->Name() << "\n";
  delete factory->GetFast();
  delete factory;
  getchar();

  factory = AEnemyFactory::CreateFactory(AEnemyFactory::Enemy_Factories::Water);
  cout << "Slow enemy of Water: " << factory->GetSlow()->Name() << "\n";
  delete factory->GetSlow();
  cout << "Fast enemy of Water: " << factory->GetFast()->Name() << "\n";
  delete factory->GetFast();
  getchar();

  return 0;
}
```

## 工作原理…

在这个例子中，我们创建了两个接口，分别是`IFast`和`ISlow`。之后，我们创建了几个敌人，并决定它们是快还是慢。最后，我们创建了一个抽象类，其中有两个虚函数来获取快速敌人和慢速敌人。这意味着所有的派生类必须重写并有自己的实现这些函数。因此，实际上我们创建了一个工厂的工厂。我们从抽象类创建的陆地、空中和水中敌人工厂都引用了慢和快的两个接口。因此，陆地、水域和空中本身也是工厂。

因此，从客户端，我们可以请求一个快速的陆地敌人或一个慢速的水域敌人，然后我们可以得到适当的敌人显示给我们。如下面的屏幕截图所示，我们可以得到如下显示的输出：

![工作原理…](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-gm-dev-cb/img/4929_06_02.jpg)

# 使用观察者模式

观察者设计模式在游戏中并不常用，但游戏开发人员应该更经常地使用它，因为这是处理通知的一种非常聪明的方式。在观察者设计模式中，一个组件与其他组件维护一对多的关系。这意味着当主要组件发生变化时，所有依赖组件也会更新。想象一个物理系统。我们希望`enemy1`和`enemy2`在物理系统更新时立即更新，所以我们应该使用这种模式。

## 准备工作

为此食谱，您需要一台装有 Visual Studio 的 Windows 机器。

## 如何做…

在这个食谱中，我们将找出实现观察者模式有多容易：

1.  打开 Visual Studio。

1.  创建一个新的 C++项目。

1.  选择一个 Win32 Windows 应用程序。

1.  添加一个名为`Source.cpp`的源文件。

1.  向其添加以下代码行：

```cpp
#include <iostream>
#include <vector>
#include <conio.h>

using namespace std;

class PhysicsSystem {

  vector < class Observer * > views;
  int value;
public:
  void attach(Observer *obs) {
    views.push_back(obs);
  }
  void setVal(int val) {
    value = val;
    notify();
  }
  int getVal() {
    return value;
  }
  void notify();
};

class Observer {

  PhysicsSystem *_attribute;
  int iScalarMultiplier;
public:
  Observer(PhysicsSystem *attribute, int value)
  {
    If(attribute)
{

_attribute = attribute;
}
    iScalarMultiplier = value;

    _attribute->attach(this);
  }
  virtual void update() = 0;
protected:
  PhysicsSystem *getPhysicsSystem() {
    return _attribute;
  }
  int getvalue()
  {
    return iScalarMultiplier;
  }
};

void PhysicsSystem::notify() {

  for (int i = 0; i < views.size(); i++)
    views[i]->update();
}

class PlayerObserver : public Observer {
public:
  PlayerObserver(PhysicsSystem *attribute, int value) : Observer(attribute, value){}
  void update() {

    int v = getPhysicsSystem()->getVal(), d = getvalue();
    cout << "Player is dependent on the Physics system" << endl;
    cout << "Player new impulse value is " << v / d << endl << endl;
  }
};

class AIObserver : public Observer {
public:
  AIObserver(PhysicsSystem *attribute, int value) : Observer(attribute, value){}
  void update() {
    int v = getPhysicsSystem()->getVal(), d = getvalue();
    cout << "AI is dependent on the Physics system" << endl;
    cout << "AI new impulse value is " << v % d << endl << endl;
  }
};

int main() {
  PhysicsSystem subj;

  PlayerObserver valueObs1(&subj, 4);
  AIObserver attributeObs3(&subj, 3);
  subj.setVal(100);

  _getch();
}
```

## 它是如何工作的…

在这个例子中，我们创建了一个不断更新其值的物理系统。依赖于物理系统的其他组件必须附加到它，这样它们就会在物理系统更新时得到通知。

我们创建的物理系统持有一个向量列表，其中包含所有正在观察的组件。除此之外，它包含了获取当前值或为其设置值的方法。它还包含一个方法，一旦物理系统中的值发生变化，就通知所有依赖组件。`Observer`类包含对物理系统的引用，以及一个纯虚函数用于更新，派生类必须覆盖这个函数。`PlayerObserver`和`AIObserver`类可以从这个类派生，并根据物理系统中的变化实现它们自己的冲量。除非它们从中分离出来，否则 AI 和玩家系统将不断地从物理系统接收更新。

这是一个非常有用的模式，在游戏中有很多实现。下面的屏幕截图显示了典型输出的样子：

![它是如何工作的…](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-gm-dev-cb/img/4929_06_03.jpg)

# 使用飞行权重模式

飞行权重设计模式在我们想要减少用于创建对象的内存量时大多被使用。当我们想要创建数百次或数千次的东西时，通常会使用这种模式。具有森林结构的游戏经常使用这种设计模式。这种设计模式属于结构设计类别。在这种模式中，对象，比如树对象，被分成两部分，一部分取决于对象的状态，一部分是独立的。独立部分存储在飞行权重对象中，而依赖部分由客户端处理，并在调用时发送到飞行权重对象。

## 准备工作

为此食谱，您需要一台装有 Visual Studio 的 Windows 机器。

## 如何做…

在这个食谱中，我们将找出实现飞行权重模式有多容易：

1.  打开 Visual Studio。

1.  创建一个新的 C++项目。

1.  选择一个 Win32 控制台应用程序。

1.  添加一个名为`Source.cpp`的源文件。

1.  向其添加以下代码行：

```cpp
#include <iostream>
#include <string>
#include <map>
#include <conio.h>

using namespace std;

class TreeType
{
public:
  virtual void Display(int size) = 0;

protected:
  //Some Model we need to assign. For relevance we are substituting this with a character symbol
  char symbol_;
  int width_;
  int height_;
  float color_;

  int Size_;
};

class TreeTypeA : public TreeType
{
public:
  TreeTypeA()
  {
    symbol_ = 'A';
    width_ = 94;
    height_ = 135;
    color_ = 0;

    Size_ = 0;
  }
  void Display(int size)
  {
    Size_ = size;
    cout << "Size of " << symbol_ << " is :" << Size_ << endl;
  }
};

class TreeTypeB : public TreeType
{
public:
  TreeTypeB()
  {
    symbol_ = 'B';
    width_ = 70;
    height_ = 25;
    color_ = 0;

    Size_ = 0;
  }
  void Display(int size)
  {
    Size_ = size;
    cout << "Size of " << symbol_ << " is :" << Size_ << endl;
  }
};

class TreeTypeZ : public TreeType
{
public:
  TreeTypeZ()
  {
    symbol_ = 'Z';
    width_ = 20;
    height_ = 40;
    color_ = 1;

    Size_ = 0;
  }
  void Display(int size)
  {
    Size_ = size;
    cout <<"Size of " << symbol_ << " is :" << Size_ << endl;
  }
};

// The 'FlyweightFactory' class
class TreeTypeFactory
{
public:
  virtual ~TreeTypeFactory()
  {
    while (!TreeTypes_.empty())
    {
      map<char, TreeType*>::iterator it = TreeTypes_.begin();
      delete it->second;
      TreeTypes_.erase(it);
    }
  }
  TreeType* GetTreeType(char key)
  {
    TreeType* TreeType = NULL;
    if (TreeTypes_.find(key) != TreeTypes_.end())
    {
      TreeType = TreeTypes_[key];
    }
    else
    {
      switch (key)
      {
      case 'A':
        TreeType = new TreeTypeA();
        break;
      case 'B':
        TreeType = new TreeTypeB();
        break;
        //…
      case 'Z':
        TreeType = new TreeTypeZ();
        break;
      default:
        cout << "Not Implemented" << endl;
        throw("Not Implemented");
      }
      TreeTypes_[key] = TreeType;
    }
    return TreeType;
  }
private:
  map<char, TreeType*> TreeTypes_;
};

//The Main method
int main()
{
  string forestType = "ZAZZBAZZBZZAZZ";
  const char* chars = forestType.c_str();

  TreeTypeFactory* factory = new TreeTypeFactory;

  // extrinsic state
  int size = 10;

  // For each TreeType use a flyweight object
  for (size_t i = 0; i < forestType.length(); i++)
  {
    size++;
    TreeType* TreeType = factory->GetTreeType(chars[i]);
    TreeType->Display(size);
  }

  //Clean memory
  delete factory;

  _getch();
  return 0;
}
```

## 它是如何工作的…

在这个例子中，我们创建了一个森林。飞行权重模式的基本原则被应用，其中结构的一部分是共享的，而另一部分由客户端决定。在这个例子中，除了大小（这可以是任何东西，大小只是选择作为一个例子），每个其他属性都被选择为共享。我们创建一个包含所有属性的树型接口。然后我们有派生类，它们有它们的属性被覆盖和一个方法来设置`size`属性。我们可以有多个这样的树。一般来说，树的种类越多，森林看起来就越详细。假设我们有 10 种不同类型的树，所以我们需要有 10 个不同的类从接口派生，并有一个方法从客户端大小分配`size`属性。

最后，我们有了树工厂，它在运行时为每棵树分配。我们创建一个对接口的引用，就像任何工厂模式一样。但是，我们不是直接实例化一个新对象，而是首先检查地图，看看树的属性是否已经存在。如果没有，我们分配一个新对象，并将属性推送到地图中。因此，下次请求类似已经分配的树结构的树时，我们可以从地图中共享属性。最后，从客户端，我们创建一个森林类型的文档，然后将其提供给工厂，它使用文档中列出的树为我们生成森林。由于大多数属性是共享的，内存占用非常低。以下屏幕截图显示了森林是如何创建的：

![它是如何工作的…](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-gm-dev-cb/img/4929_06_04.jpg)

# 使用策略模式

策略设计模式是设计代码的一种非常聪明的方式。在游戏中，这主要用于 AI 组件。在这种模式中，我们定义了大量的算法，并且所有这些算法都具有一个共同的接口签名。然后在运行时，我们可以更改算法的客户端。因此，实际上，这些算法是独立于客户端的。

## 准备工作

要完成这个示例，您需要一台运行 Windows 的机器。您还需要在 Windows 机器上安装一个可用的 Visual Studio 副本。不需要其他先决条件。

## 如何做…

在这个示例中，我们将发现实现策略模式是多么容易：

1.  打开 Visual Studio。

1.  创建一个新的 C++项目。

1.  选择一个 Win32 控制台应用程序。

1.  添加一个`Source.cpp`文件。

1.  将以下代码行添加到其中：

```cpp
#include <iostream>
#include <conio.h>

using namespace std;

class SpecialPower
{
public:
  virtual void power() = 0;
};

class Fire : public SpecialPower
{
public:
  void power()
  {
    cout << "My power is fire" << endl;
  }
};

class Invisibility : public SpecialPower
{
public:
  void power()
  {
    cout << "My power is invisibility" << endl;
  }
};

class FlyBehaviour
{
public:
  virtual void fly() = 0; 
};

class FlyWithWings : public FlyBehaviour
{
public:
  void fly()
  {
    cout << "I can fly" << endl;
  }
};

class FlyNoWay : public FlyBehaviour
{
public:
  void fly()
  {
    cout << "I can't fly!" << endl;
  }
};

class FlyWithRocket : public FlyBehaviour
{
public:
  void fly()
  {
    cout << "I have a jetpack" << endl;
  }
};

class Enemy
{

public:

  SpecialPower *specialPower;
  FlyBehaviour   *flyBehaviour;

  void performPower()
  {
    specialPower->power();
  }

  void setSpecialPower(SpecialPower *qb)
  {
    cout << "Changing special power..." << endl;
    specialPower = qb;
  }

  void performFly()
  {
    flyBehaviour->fly();
  }

  void setFlyBehaviour(FlyBehaviour *fb)
  {
    cout << "Changing fly behaviour..." << endl;
    flyBehaviour = fb;
  }

  void floatAround()
  {
    cout << "I can float." << endl;
  }

  virtual void display() = 0; // Make this an abstract class by having a pure virtual function

};

class Dragon : public Enemy
{
public:
  Dragon()
  {
    specialPower = new Fire();
    flyBehaviour = new FlyWithWings();
  }

  void display()
  {
    cout << "I'm a dragon" << endl;
  }

};

class Soldier : public Enemy
{
public:
  Soldier()
  {
    specialPower = new Invisibility();
    flyBehaviour = new FlyNoWay();
  }

  void display()
  {
    cout << "I'm a soldier" << endl;
  }
};

int main()
{
  Enemy *dragon = new Dragon();
  dragon->display();
  dragon->floatAround();
  dragon->performFly();
  dragon->performPower();

  cout << endl << endl;

  Enemy *soldier = new Soldier();
  soldier->display();
  soldier->floatAround();
  soldier->performFly();
  soldier->setFlyBehaviour(new FlyWithRocket);
  soldier->performFly();
  soldier->performPower();
  soldier->setSpecialPower(new Fire);
  soldier->performPower();

  _getch();
  return 0;
}
```

## 它是如何工作的…

在这个例子中，我们为敌人可能具有的不同属性创建了不同的接口。因此，由于我们知道特殊能力是每种敌人类型都会具有的属性，我们创建了一个名为`SpecialPower`的接口，然后从中派生了两个类，分别是`Fire`和`Invisibility`。我们可以添加任意多的特殊能力，我们只需要创建一个新的类，并从特殊能力接口派生。同样，所有的敌人类型都应该有一个飞行属性。它们要么飞行，要么不飞行，要么借助喷气背包飞行。

因此，我们创建了一个`FlyBehaviour`接口，并让不同的飞行类型类从中派生。之后，我们创建了一个敌人类型的抽象类，其中包含了这两个接口作为引用。因此，任何派生类都可以决定需要什么飞行类型和特殊能力。这也使我们能够在运行时更改特殊能力和飞行能力。下面的屏幕截图显示了这种设计模式的简要示例：

![它是如何工作的…](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-gm-dev-cb/img/4929_06_05.jpg)

# 使用命令设计模式

命令设计模式通常涉及将命令封装为对象。这在游戏网络中被广泛使用，其中玩家的移动被发送为作为命令运行的对象。命令设计模式中要记住的四个主要点是客户端、调用者、接收者和命令。命令对象了解接收者对象。接收者在接收到命令后执行工作。调用者执行命令，而不知道是谁发送了命令。客户端控制调用者，并决定在哪个阶段执行哪些命令。

## 准备工作

对于这个示例，您需要一台安装有 Visual Studio 的 Windows 机器。

## 如何做…

在这个示例中，我们将发现实现命令模式是多么容易：

1.  打开 Visual Studio。

1.  创建一个新的 C++项目控制台应用程序。

1.  添加以下代码行：

```cpp
#include <iostream>
#include <conio.h>

using namespace std;
class NetworkProtocolCommand
{
public:
  virtual void PerformAction() = 0;
};
class ServerReceiver
{
public:
  void Action()
  {
    cout << "Network Protocol Command received" <<endl;

  }
};
class ClientInvoker
{
  NetworkProtocolCommand *m_NetworkProtocolCommand;

public:
  ClientInvoker(NetworkProtocolCommand *cmd = 0) : m_NetworkProtocolCommand(cmd)
  {
  }

  void SetCommad(NetworkProtocolCommand *cmd)
  {
    m_NetworkProtocolCommand = cmd;
  }

  void Invoke()
  {
    if (0 != m_NetworkProtocolCommand)
    {
      m_NetworkProtocolCommand->PerformAction();
    }
  }
};

class MyNetworkProtocolCommand : public NetworkProtocolCommand
{
  ServerReceiver *m_ServerReceiver;

public:
  MyNetworkProtocolCommand(ServerReceiver *rcv = 0) : m_ServerReceiver(rcv)
  {
  }

  void SetServerReceiver(ServerReceiver *rcv)
  {
    m_ServerReceiver = rcv;
  }

  virtual void PerformAction()
  {
    if (0 != m_ServerReceiver)
    {
      m_ServerReceiver->Action();
    }
  }
};

int main()
{
  ServerReceiver r;
  MyNetworkProtocolCommand cmd(&r);
  ClientInvoker caller(&cmd);
  caller.Invoke();

  _getch();
  return 0;
}
```

## 它是如何工作的…

正如我们在这个例子中所看到的，我们已经设置了一个接口，通过网络协议命令发送信息。从该接口，我们可以派生多个子实例用于客户端。然后我们需要创建一个服务器接收器，用于接收来自客户端的命令。我们还需要创建一个客户端调用者，用于调用命令。该类中还应该有对网络协议命令的引用。最后，从客户端，我们需要创建一个服务器实例，并将该实例附加到我们创建的网络协议命令的子对象上。然后我们使用客户端调用者来调用命令，并通过网络协议命令将其发送到接收器。这确保了抽象的维护，并且整个消息都是通过数据包发送的。以下截图显示了部分过程：

![工作原理…](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-gm-dev-cb/img/4929_06_06.jpg)

# 使用设计模式创建高级游戏

在了解基本设计模式之后，将它们结合起来创建一个好的游戏是很重要的。需要多年的实践才能最终理解哪种架构适合游戏结构。我们经常不得不同时使用几种设计模式来编写可以应用于游戏的清晰代码。工厂模式可能是您最常用的设计模式，但这纯粹是我个人经验的一个轶事参考。

## 准备工作

对于这个示例，您需要一台安装了 Visual Studio 的 Windows 机器。

## 如何做…

在这个示例中，我们将发现如何轻松地结合设计模式来创建一个游戏：

1.  打开 Visual Studio。

1.  创建一个新的 C++项目控制台应用程序。

1.  添加以下代码行：

```cpp
#ifndef _ISPEED_H
#define _SPEED_H

class ISpeed
{
  public:
    virtual void speed() = 0;

};

#end
#ifndef _ISPECIALPOWER
#define _ISPECIALPOWER
class ISpecialPower
{
public:
  virtual void power() = 0;
};
#endif

#ifndef _IENEMY_H
#define _IENEMY_H

#include "ISpecialPower.h"
#include "ISpeed.h"

class IEnemy
{

public:

  ISpecialPower *specialPower;
  ISpeed   *speed;

  void performPower()
  {
    specialPower->power();
  }

  void setSpecialPower(ISpecialPower *qb)
  {

  }

};
#endif
#include <iostream>
#include "ISpeed.h"

#pragma once
class HighSpeed :public ISpeed
{
public:
  HighSpeed();
  ~HighSpeed();
};

#include "IEnemy.h"

class Invisibility;
class HighSpeed;

class Soldier : public IEnemy
{
public:
  Soldier()
  {

  }

};
```

## 工作原理…

上面的代码只是代码的一小部分。假设我们需要制作一个游戏，其中有不同类的敌人，以及不同类型的能力，以及一些特殊的增益或增强。对此的一种方法是将所有能力和特殊增益视为从接口派生的单独类。因此，我们需要为速度创建一个接口，它可以从`HighSpeed`类派生，依此类推。同样，我们可以创建一个`SpecialPower`接口，它可以由`Fire`类等派生。我们需要为角色可能具有的所有属性组创建接口。最后，我们需要创建一个角色（`IEnemy`）的接口，它由`Soldier`、`Archer`和`Grenadier`类等派生。`IEnemy`接口还应该持有对所有其他接口的引用，比如`ISpecialPower`和`ISpeed`。通过这种方式，`IEnemy`的子类可以决定他们想要拥有什么能力和速度。这类似于策略设计模式。如果我们想要将敌人分组到类型中，比如陆地敌人和空中敌人，我们可以进一步改进这个结构。在这种情况下，我们要么为`IType`创建一个接口，并让`Land`和`Air`类从中派生，要么我们可以创建一个工厂，根据客户端请求的类型为我们创建敌人类型。创建的每种敌人类型也将是从`IEnemy`派生的类，因此它也将具有对先前接口的引用。随着游戏的复杂性增加，我们可以添加更多的设计模式来帮助我们。


# 第七章：组织和备份

在本章中，将涵盖以下内容：

+   版本控制

+   安装一个版本控制客户端

+   选择一个主机来保存您的数据

+   为您的代码添加源代码控制-提交和更新您的代码

+   解决冲突

+   创建一个分支

# 介绍

假设我们需要在一个有很多开发人员的项目上工作。如果每个开发人员都在不同的源文件上工作，一种（相当可怕的）工作方式是通过电子邮件或 FTP 客户端获取新更新的源文件，并将其替换到您的项目中。现在如果开发人员，包括您自己，都在同一个源文件上工作。我们仍然可以遵循这种可怕的方式，并将我们已经工作过的部分添加到我们通过 FTP 收到的文件中，但很快这将变得非常繁琐，几乎不可能工作。因此，我们有一个将文件保存到某个中央仓库或分布式仓库的系统，然后有手段更新和发送代码，以便每个开发人员都使用最新的副本。有各种各样的方法来执行这个操作，通常被称为对代码进行版本控制。

# 版本控制

修订控制是跨开发人员共享文件的一种非常有效的方式。有各种版本控制系统，每种系统都有其优点和缺点。我们将看看目前最流行的三种版本控制系统。

## 准备工作

要完成这个教程，您需要一台运行 Windows 的计算机。不需要其他先决条件。

## 如何做...

在这个教程中，我们将看到可用于我们的不同类型的源代码控制：

1.  转到此链接并下载一个 SVN 客户端：[`tortoisesvn.net/downloads.html`](http://tortoisesvn.net/downloads.html)

1.  转到此链接并下载 GIT 客户端：[`desktop.github.com`](https://desktop.github.com)

1.  转到此链接并下载一个 Mercurial 客户端：[`tortoisehg.bitbucket.org/download/index.html`](http://tortoisehg.bitbucket.org/download/index.html)

## 它是如何工作的...

有各种类型的 SVN 客户端可供我们使用。每种都有其优点和缺点。

SVN 具有许多功能，可以解决与原子操作和源文件损坏相关的问题。它是免费和开源的。它有许多不同 IDE 的插件。然而，这个工具的一个主要缺点是它在操作中相对非常慢。

GIT 主要是为 Linux 而设计的，但它大大提高了操作速度。它也可以在 UNIX 系统上运行。它具有廉价的分支操作，但与 Linux 相比，它对单个开发人员的 Windows 支持有限。然而，GIT 非常受欢迎，许多人更喜欢 GIT 而不是 SVN。

# 安装一个版本控制客户端

有很多版本控制客户端。然而，我们将看看一个 SVN 客户端。Tortoise SVN 是迄今为止最受 SVN 用户欢迎的。尽管 GIT 是另一个非常受欢迎的系统，但我们将在这个教程中看看 Tortoise SVN。Tortoise SVN 提供了一个非常友好和直观的界面，因此即使是初学者也很容易掌握。在几个小时内，一个完全的新手就可以理解使用 Tortoise SVN 的基础知识。

## 准备工作

您需要一台 Windows 机器。不需要其他先决条件。

## 如何做...

在这个教程中，我们将发现安装和使用 Tortoise SVN 有多么容易：

1.  转到此链接：[`tortoisesvn.net/downloads.html`](http://tortoisesvn.net/downloads.html)

1.  根据您使用的是 32 位还是 64 位 Windows 机器，下载并安装正确的版本。

1.  在您的计算机上创建一个新文件夹。

1.  右键单击文件夹。

1.  检查一个名为**SVN Checkout…**的新命令现在可以使用。

## 它是如何工作的...

在我们转到下载站点并安装软件包后，它将安装在系统上，并添加了许多 shell 和内核命令。因此，当我们右键单击文件夹时，“**SVN Checkout…**”命令现在被添加为任何新文件夹的属性。还有另一个名为**Tortoise SVN**的命令可供我们使用，它还有更多命令。在我们检出项目后，“**SVN Checkout…**”将被替换为**SVN Update**或**SVN Commit**。我们只需要确保根据我们使用的操作系统版本向计算机添加了正确的安装程序。

# 选择托管数据的主机

在我们开始对我们的代码进行版本控制之前，我们需要决定将代码文件保存到哪里。有很多种方法可以做到这一点，但我们将讨论两种最流行的方法。第一种方法是将文件保存在本地，并将个人计算机视为托管数据的服务器。第二种方法是使用云服务来为我们托管数据文件。

## 准备工作

您需要一个可用的 Windows 计算机。

## 如何做...

在这个教程中，我们将了解如何轻松地在本地或云端托管文件。

对于保存在云端的文件，请按照以下步骤操作：

1.  转到以下链接：[`xp-dev.com`](https://xp-dev.com)。

1.  转到**计划**并选择最适合您需求的计划。还有一个免费的 10MB 计划。

1.  选择计划后，您将被重定向以为当前项目创建名称。

1.  新项目现在将显示在仪表板上。您可以根据您的计划创建多个项目。

1.  单击一个项目。这应该打开更多选项卡。目前最重要的是：

+   **存储库**

+   **项目跟踪**

+   **活动**

+   **设置**

1.  单击**存储库**以创建一个新的存储库。

1.  生成的链接现在可以用于对项目中的文件进行版本控制。

1.  要向项目添加用户，请单击**设置**并邀请用户加入项目。

对于保存在本地服务器上的文件：

1.  将新项目或空项目保存在您的计算机上。

1.  从这里下载**Visual SVN Server**：[`www.visualsvn.com/server/`](https://www.visualsvn.com/server/)。

1.  安装软件。

1.  然后从现有项目创建一个项目。

1.  您的项目现在已准备好进行版本控制。

1.  要添加用户，请单击**用户**并添加用户名和密码。

## 它是如何工作的...

当我们在`xp-dev`上创建项目时，实际上是`xp-dev`根据我们选择的计划在其服务器上为我们创建了一个云空间。之后，对于文件的每次迭代，它都会在服务器上保存一个副本。在仪表板上，一旦我们创建一个存储库，我们就可以创建一个新的存储库，生成的 URL 现在将是项目的 URL。通过这种方式，我们可以恢复到任何迭代或恢复文件，如果我们误删了它。当我们提交文件时，文件的新副本现在保存在服务器上。当我们更新项目时，服务器上的最新版本现在被推送到您的本地计算机。通过这种方式，`xp-dev`保存了所有更新和提交的整个活动历史。系统的缺点是，如果`xp-dev`客户端关闭，那么所有云服务也将关闭。因此，由于您无法进行任何更新或提交，项目将会受到影响。

托管的另一种方法是使用您自己的本地计算机。Visual SVN Server 基本上将您的计算机变成了服务器。之后，该过程与`xp-dev`处理所有更新和提交的方式非常相似。

我们还可以从亚马逊或 Azure 那里获取一些空间，并将该空间用作服务器。在这种情况下，步骤与第二种方法（本地服务器）非常相似。登录到亚马逊空间或 Azure 空间后，将其视为您的计算机，然后重复本地服务器的步骤。

# 添加源代码控制-提交和更新您的代码。

在协作项目或个人工作时，您可以对文件执行的最重要的操作之一是添加源代码控制。这样做的最大优势是文件始终有备份和版本控制。假设您进行了一些本地更改，并且发生了许多崩溃。由于这些崩溃，您将怎么做？一种选择是追溯您的步骤并将它们改回以前的状态。这是一个浪费时间的过程，也存在风险。如果您的文件有备份，您只需要对特定的修订执行还原操作，代码就会恢复到那一点。同样，如果我们错误地删除了一个文件，我们总是可以更新项目，它将从服务器中拉取最新的文件。

## 准备工作

对于这个教程，您将需要一台 Windows 机器和安装了 SVN 客户端的版本。数据托管服务现在应该已经集成，并且您应该有一个 URL。不需要其他先决条件。

## 如何做...

在这个教程中，我们将找出添加源代码控制有多么容易：

1.  在机器上创建一个新文件夹。

1.  将其重命名为您想要的任何名称。

1.  右键单击并检查 SVN 命令是否显示为其中一个选项。

1.  单击**SVN Checkout**。使用您从`xp-dev`或您的本地服务器或云服务器收到的 URL。

1.  将文件添加到新文件夹中。它可以是任何格式。

1.  右键单击文件，然后选择**Tortoise SVN** | **添加**。

1.  转到根文件夹，然后选择**SVN** | **提交**。

1.  删除文件。

1.  转到**SVN** | **更新**。

1.  对文件进行一些更改。

1.  选择**SVN** | **提交**。

1.  然后选择**Tortoise SVN**，然后**还原到此修订版**（修订版`1`）。

## 它是如何工作的...

SVN 检出成功后，项目要么从本地机器复制到服务器，要么从服务器复制到本地机器，具体取决于哪个是最新的。一旦我们将文件添加到文件夹中，我们必须记住文件仍然是本地的。只有我们可以看到它并访问它。正在处理该项目的其他人将对此一无所知。现在，一个新程序员在这个阶段可能犯的一个常见错误是忘记将文件添加到 SVN。当您提交项目时，该文件将不会显示。在提交部分有一个**显示未版本化文件**的复选框。但是，我不建议这种方法，因为在这种情况下，所有临时文件也将显示出来。一个更好的方法是右键单击文件，然后转到**Tortoise SVN** | **添加**。这将为修订添加文件。现在我们可以进行 SVN 提交，文件将存储在服务器上。

当我们删除文件时，我们必须记住我们只是在本地删除了文件。它仍然存在于服务器上。因此，当我们执行 SVN 更新时，文件将再次被恢复。我们必须小心不要执行**Tortoise SVN** | **删除和提交**。这将从服务器中删除该修订版的文件。现在，如果我们对文件进行一些更改，我们可以**SVN 提交**它。我们不再需要选择**Tortoise SVN** | **添加**。这将在服务器上创建文件的新版本。现在两个版本的文件都存在。我们可以拥有任意数量的版本。要访问任何修订版，我们需要选择根文件夹或任何特定文件，然后执行**还原到此修订版**（编号）。服务器然后查找我们请求的版本，并将正确的副本推送给我们。

# 解决冲突

让我们考虑一个由多个程序员共同处理的单个源文件。您可能有一些本地更改。当您尝试更新时，可能会发生 SVN 客户端足够智能地将文件合并在一起。但是，在大多数情况下，它将无法正确合并，我们需要有效地解决冲突。但是，SVN 客户端将显示冲突的文件。

## 准备工作

对于这个教程，您需要一台 Windows 机器和安装了 SVN 客户端的版本。还需要一个版本化的项目。

## 如何做...

在这个教程中，我们将发现解决冲突有多容易：

1.  拿一个已经版本化并提交到 SVN 的项目。

1.  在编辑器中打开文件并对文件进行更改。

1.  执行**SVN 更新**操作。

1.  文件现在显示冲突。

1.  使用**Diff 工具**或**Win Merge**查看两个文件之间的差异（您可能需要单独安装 Win Merge）。

1.  通常，左侧将是本地修订版本，右侧将是服务器上的版本。但是，这些也可以互换。

1.  查看差异后，您可以以两种方式解决冲突：

+   选择你想要从服务器和本地更改中选择的部分。

+   选择**使用“我的”解决冲突**或选择**使用“他们的”解决冲突**。

## 它是如何工作的...

冲突发生时，客户端无法决定本地副本还是服务器副本应该被视为正确的工作版本。大多数良好的客户端在更新后会显示这个错误。其他客户端会在代码中插入两个部分，通常用`r>>>>>`或`m>>>>`标记，表示哪一部分是服务器的，哪一部分是我们的。在 Tortoise SVN 上，如果我们选择忽略冲突，那么这些标记可能会显示为单独的文件或包含在文件中。更好的方法是始终解决冲突。如果我们使用诸如 Win Merge 之类的工具，它会将两个修订版本并排显示，我们可以比较并选择我们需要的部分，或整个文件。之后，一旦我们接受了更改并提交了它们，该文件将成为服务器上的更新版本。因此，更新他们的代码的其他人也会得到我们所做的更改。

# 创建一个分支

让我们假设我们正在制作一款游戏，该游戏计划在年底发布。然而，我们还需要展示一个经过精心打磨的版本供 GDC 或 E3 展示。此时，制作人可能会要求我们制作一个特定于 E3 或 GDC 的版本。这个 GDC 或 E3 版本可以被打磨并稳定下来，而主要版本可能会继续通过添加新功能进行实验。

## 准备工作

要完成本教程，您需要一台运行 Windows 的机器，并安装了 SVN 客户端的版本。还需要一个版本化的项目。不需要其他先决条件。

## 如何做...

在这个教程中，我们将发现创建一个分支有多容易：

1.  右键单击版本化项目。

1.  转到仓库浏览器。

1.  选择要创建分支的根文件夹。

1.  选择目的地。

1.  现在创建了一个分支。

1.  通过使用 URL 在机器上检出创建的分支。

## 它是如何工作的...

当我们从根文件夹创建一个分支时，会创建该文件夹及其后续子文件夹的镜像副本。从那时起，这两者可以独立工作。主根有一个 URL，分支也有自己的 URL。我们可以像为根文件夹一样更新和提交到分支。此外，所有其他功能对分支也是可用的。有时，在我们对分支进行更改后，我们可能需要将它们推回到根目录。虽然 SVN 客户端 Tortoise SVN 为我们提供了一个合并分支的工具，但它很少成功，往往我们需要手动进行合并。


# 第八章：游戏开发中的人工智能

在本章中，将涵盖以下食谱：

+   向游戏添加人工智能

+   在游戏中使用启发式

+   使用二进制空间分区树

+   创建决策制定 AI

+   添加行为动作

+   使用神经网络

+   使用遗传算法

+   使用其他航路点系统

# 介绍

**人工智能**（**AI**）可以用许多方式来定义。人工智能处理在不同情况下找到相似之处和在相似情况下找到差异。AI 可以帮助游戏变得更加真实。玩游戏的用户应该感觉到他们正在与另一个人竞争。实现这一点非常困难，可能会消耗大量的处理周期。事实上，每年都会举行*图灵测试*来确定 AI 是否能愚弄其他人相信它是人类。现在，如果我们为 AI 使用了大量的处理周期，那么以超过 40 FPS 的速度执行游戏可能会变得非常困难。因此，我们需要编写高效的算法来实现这一点。

# 向游戏添加人工智能

向游戏添加人工智能可能很容易，也可能非常困难，这取决于我们试图实现的现实水平或复杂性。在这个食谱中，我们将从添加人工智能的基础开始。

## 准备工作

要完成本食谱，您需要一台运行 Windows 的机器和一个版本的 Visual Studio。不需要其他先决条件。

## 如何做到这一点…

在这个食谱中，我们将看到向游戏添加基本人工智能有多么容易。添加一个名为`Source.cpp`的源文件。将以下代码添加到其中：

```cpp
// Basic AI : Keyword identification

#include <iostream>
#include <string>
#include <string.h>

std::string arr[] = { "Hello, what is your name ?", "My name is Siri" };

int main()
{

  std::string UserResponse;

  std::cout << "Enter your question? ";
  std::cin >> UserResponse;

  if (UserResponse == "Hi")
  {
    std::cout << arr[0] << std::endl;
    std::cout << arr[1];
  }

  int a;
  std::cin >> a;
  return 0;

}
```

## 它是如何工作的…

在上一个示例中，我们使用字符串数组来存储响应。软件的想法是创建一个智能聊天机器人，可以回答用户提出的问题并与他们交互，就像它是人类一样。因此，第一项任务是创建一个响应数组。接下来要做的事情是询问用户问题。在这个例子中，我们正在搜索一个名为`Hi`的基本关键字，并根据此显示适当的答案。当然，这是一个非常基本的实现。理想情况下，我们会有一个关键字和响应的列表，当触发任何关键字时。我们甚至可以通过询问用户的名字来个性化这一点，然后每次都将其附加到答案中。

用户还可以要求搜索某些内容。这实际上是一件非常容易的事情。如果我们正确检测到用户渴望搜索的单词，我们只需要将其输入到搜索引擎中。页面显示任何结果，我们都可以向用户报告。我们还可以使用语音命令输入问题并给出回应。在这种情况下，我们还需要实现某种**NLP**（**自然语言** **处理**）。在正确识别语音命令之后，所有其他流程都是完全相同的。

# 在游戏中使用启发式

在游戏中添加启发式意味着定义规则。我们需要为 AI 代理定义一组规则，以便它以最佳方式移动到目的地。例如，如果我们想编写一个路径规划算法，并且只定义其起始和结束位置，它可能以许多不同的方式到达那里。然而，如果我们希望代理以特定方式达到目标，我们需要为其建立一个启发式函数。

## 准备工作

您需要一台 Windows 机器和一个运行 Visual Studio 的工作副本。不需要其他先决条件。

## 如何做到这一点…

在这个食谱中，我们将发现为我们的游戏添加启发式函数进行路径规划有多么容易。添加一个名为`Source.cpp`的源文件，并将以下代码添加到其中：

```cpp
    for (auto next : graph.neighbors(current)) {
      int new_cost = cost_so_far[current] + graph.cost(current, next);
      if (!cost_so_far.count(next) || new_cost < cost_so_far[next]) {
        cost_so_far[next] = new_cost;
        int priority = new_cost + heuristic(next, goal);
        frontier.put(next, priority);
        came_from[next] = current;
      }
```

## 它是如何工作的…

定义启发式的方法有很多种。然而，最简单的思考方法是它是一个为 AI 提供提示和方向以达到指定目标的函数。假设我们的 AI 需要从点`A`到点`D`。现在，地图上还有点`B`和`C`。AI 应该如何决定要走哪条路径？这就是启发式函数提供的内容。在这个例子中，我们在称为`A*`的路径查找算法中使用了启发式。在特殊情况下，启发式函数为`0`，我们得到一个称为**Dijkstra**的算法。

让我们先考虑 Dijkstra。稍后理解`A*`会更容易。

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-gm-dev-cb/img/4929_08_01.jpg)

让我们考虑我们需要找到**s**和**x**之间的最短路径，至少遍历所有节点一次。**s**、**t**、**y**、**x**和**z**是不同的节点或不同的子目的地。从一个节点到另一个节点的数字是从一个节点到另一个节点的成本。该算法规定我们从**s**开始，值为**0**，并认为所有其他节点都是无限的。接下来要考虑的是与**s**相邻的节点。与**s**相邻的节点是**t**和**y**。到达它们的成本分别为**5**和**10**。我们注意到这一点，然后用**5**和**10**替换这些节点的无限值。现在让我们考虑节点**y**。相邻的节点是**t**、**x**和**z**。到达**x**的成本是**5**（它的当前节点值）加上**9**（路径成本值）等于*14*。同样，到达**z**的成本是*5 + 2 = 7*。因此，我们分别用**14**和**7**替换**x**和**z**的无限值。现在，到达**t**的成本是*5 + 3 = 8*。然而，它已经有一个节点值。它的值是**10**。由于*8<10*，我们将**t**替换为**8**。我们继续对所有节点进行这样的操作。之后，我们将得到遍历所有节点的最小成本。

`A*`有两个成本函数：

+   `g(x)`: 这与 Dijkstra 相同。这是到达节点**x**的实际成本。

+   `h(x)`: 这是从节点**x**到目标节点的近似成本。这是一个启发式函数。这个启发式函数不应该高估成本。这意味着从节点**x**到达目标节点的实际成本应该大于或等于`h(x)`。这被称为可接受的启发式。

每个节点的总成本使用*f(x) = g(x)+h(x)*计算。

在`A*`中，我们不需要遍历所有节点，我们只需要找到从起点到目的地的最短路径。A*搜索只会扩展一个节点，如果它看起来很有前途。它只关注从当前节点到达目标节点，而不是到达其他每个节点。如果启发式函数是可接受的，它是最优的。因此，编写启发式函数是检查是否扩展到节点的关键。在前面的例子中，我们使用相邻节点并形成一个优先列表来决定。

# 使用二进制空间分区树

有时在游戏中，我们需要处理大量的几何图形和庞大的 3D 世界。如果我们的游戏摄像头一直渲染所有内容，那么成本将非常昂贵，游戏将无法以更高的帧率平稳运行。因此，我们需要编写智能算法，以便将世界划分为更易管理的块，可以使用树结构轻松遍历。

## 准备就绪

你需要有一台运行良好的 Windows 机器和一个运行良好的 Visual Studio 副本。

## 如何做...

添加一个名为`Source.cpp`的源文件。然后将以下代码添加到其中：

```cpp
sNode(elemVec& toProcess, const T_treeAdaptor& adap)
      : m_pFront(NULL)
      , m_pBack(NULL)
    {
      // Setup
      elemVec frontVec, backVec;
      frontVec.reserve(toProcess.size());
      backVec.reserve(toProcess.size());

      // Choose which node we're going to use.
      adap.ChooseHyperplane(toProcess, &m_hp);

      // Iterate across the rest of the polygons
      elemVec::iterator iter = toProcess.begin();
      for (; iter != toProcess.end(); ++iter)
      {
        T_element front, back;
        switch (adap.Classify(m_hp, *iter))
        {
        case BSP_RELAT_IN_FRONT:
          frontVec.push_back(*iter);
          break;
       <...> 
      }

      // Now recurse if necessary
      if (!frontVec.empty())
        m_pFront = new sNode(frontVec, adap);
      if (!backVec.empty())
        m_pBack = new sNode(backVec, adap);
    }

    sNode(std::istream& in)
    {
      // First char is the child state
      // (0x1 means front child, 0x2 means back child)
      int childState;
      in >> childState;

      // Next is the hyperplane for the node
      in >> m_hp;

      // Next is the number of elements in the node
      unsigned int nElem;
      in >> nElem;
      m_contents.reserve(nElem);

      while (nElem--)
      {
        T_element elem;
        in >> elem;
        m_contents.push_back(elem);
      }

      // recurse if we have children.
      if (childState & 0x1)
        m_pFront = new sNode(in);
      else
        m_pFront = NULL;
      if (childState & 0x2)
        m_pBack = new sNode(in);
      else
        m_pBack = NULL;
    }
```

## 它是如何工作的...

**二进制空间分区**（**BSP**）树，顾名思义，是一个树结构，其中一个几何空间被分割。更准确地说，在 BSP 中，一个平面被分割成更多的超平面。一个平面是这样的，它的维度比它所在的环境空间少一个。因此，一个 3D 平面将有 2D 超平面，而一个 2D 平面将有 1D 线。这背后的想法是一旦我们以逻辑方式将平面分割成这些超平面，我们可以将形成保存到树结构中。最后，我们可以实时遍历树结构，为整个游戏提供更好的帧率。

让我们考虑一个例子，世界看起来像下面的图表。摄像机必须决定应该渲染哪些区域，哪些不应该。因此，使用逻辑算法进行划分是必要的：

![它是如何工作的…](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-gm-dev-cb/img/4929_08_02.jpg)

应用算法后，树结构应该如下所示：

![它是如何工作的…](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-gm-dev-cb/img/4929_08_03.jpg)

最后，我们像处理任何其他树结构一样遍历这个算法，使用父节点和子节点的概念，得到摄像机应该渲染的所需部分。

# 创建决策制定 AI

**决策树**是机器学习中最有用的东西之一。在大量的情景中，基于某些参数，决策是必不可少的。如果我们能够编写一个能够做出这些决定的系统，那么我们不仅可以拥有一个写得很好的算法，而且在游戏玩法方面也会有很多的不可预测性。这将为游戏增加很多变化，并有助于整体游戏的可重复性。

## 准备工作

对于这个食谱，你需要一台 Windows 机器和 Visual Studio。不需要其他先决条件。

## 如何做…

在这个食谱中，我们将发现添加源代码控制是多么容易：

```cpp
/* Decision Making AI*/

#include <iostream>
#include <ctime>

using namespace std;

class TreeNodes
{
public:
  //tree node functions
  TreeNodes(int nodeID/*, string QA*/);
  TreeNodes();

  virtual ~TreeNodes();

  int m_NodeID;

  TreeNodes* PrimaryBranch;
  TreeNodes* SecondaryBranch;
};

//constructor
TreeNodes::TreeNodes()
{
  PrimaryBranch = NULL;
  SecondaryBranch = NULL;

  m_NodeID = 0;
}

//deconstructor
TreeNodes::~TreeNodes()
{ }

//Step 3! Also step 7 hah!
TreeNodes::TreeNodes(int nodeID/*, string NQA*/)
{
  //create tree node with a specific node ID
  m_NodeID = nodeID;

  //reset nodes/make sure! that they are null. I wont have any funny business #s -_-
  PrimaryBranch = NULL;
  SecondaryBranch = NULL;
}

//the decision tree class
class DecisionTree
{
public:
  //functions
  void RemoveNode(TreeNodes* node);
  void DisplayTree(TreeNodes* CurrentNode);
  void Output();
  void Query();
  void QueryTree(TreeNodes* rootNode);
  void PrimaryNode(int ExistingNodeID, int NewNodeID);
  void SecondaryNode(int ExistingNodeID, int NewNodeID);
  void CreateRootNode(int NodeID);
  void MakeDecision(TreeNodes* node);

  bool SearchPrimaryNode(TreeNodes* CurrentNode, int ExistingNodeID, int NewNodeID);
  bool SearchSecondaryNode(TreeNodes* CurrentNode, int ExistingNodeID, int NewNodeID);

  TreeNodes* m_RootNode;

  DecisionTree();

  virtual ~DecisionTree();
};

int random(int upperLimit);

//for random variables that will effect decisions/node values/weights
int random(int upperLimit)
{
  int randNum = rand() % upperLimit;
  return randNum;
}

//constructor
//Step 1!
DecisionTree::DecisionTree()
{
  //set root node to null on tree creation
  //beginning of tree creation
  m_RootNode = NULL;
}

//destructor
//Final Step in a sense
DecisionTree::~DecisionTree()
{
  RemoveNode(m_RootNode);
}

//Step 2!
void DecisionTree::CreateRootNode(int NodeID)
{
  //create root node with specific ID
  // In MO, you may want to use thestatic creation of IDs like with entities. depends on how many nodes you plan to have
  //or have instantaneously created nodes/changing nodes
  m_RootNode = new TreeNodes(NodeID);
}

//Step 5.1!~
void DecisionTree::PrimaryNode(int ExistingNodeID, int NewNodeID)
{
  //check to make sure you have a root node. can't add another node without a root node
  if (m_RootNode == NULL)
  {
    cout << "ERROR - No Root Node";
    return;
  }

  if (SearchPrimaryNode(m_RootNode, ExistingNodeID, NewNodeID))
  {
    cout << "Added Node Type1 With ID " << NewNodeID << " onto Branch Level " << ExistingNodeID << endl;
  }
  else
  {
    //check
    cout << "Node: " << ExistingNodeID << " Not Found.";
  }
}

//Step 6.1!~ search and add new node to current node
bool DecisionTree::SearchPrimaryNode(TreeNodes *CurrentNode, int ExistingNodeID, int NewNodeID)
{
  //if there is a node
  if (CurrentNode->m_NodeID == ExistingNodeID)
  {
    //create the node
    if (CurrentNode->PrimaryBranch == NULL)
    {
      CurrentNode->PrimaryBranch = new TreeNodes(NewNodeID);
    }
    else
    {
      CurrentNode->PrimaryBranch = new TreeNodes(NewNodeID);
    }
    return true;
  }
  else
  {
    //try branch if it exists
    //for a third, add another one of these too!
    if (CurrentNode->PrimaryBranch != NULL)
    {
      if (SearchPrimaryNode(CurrentNode->PrimaryBranch, ExistingNodeID, NewNodeID))
      {
        return true;
      }
      else
      {
        //try second branch if it exists
        if (CurrentNode->SecondaryBranch != NULL)
        {
          return(SearchSecondaryNode(CurrentNode->SecondaryBranch, ExistingNodeID, NewNodeID));
        }
        else
        {
          return false;
        }
      }
    }
    return false;
  }
}

//Step 5.2!~    does same thing as node 1\.  if you wanted to have more decisions, 
//create a node 3 which would be the same as this maybe with small differences
void DecisionTree::SecondaryNode(int ExistingNodeID, int NewNodeID)
{
  if (m_RootNode == NULL)
  {
    cout << "ERROR - No Root Node";
  }

  if (SearchSecondaryNode(m_RootNode, ExistingNodeID, NewNodeID))
  {
    cout << "Added Node Type2 With ID " << NewNodeID << " onto Branch Level " << ExistingNodeID << endl;
  }
  else
  {
    cout << "Node: " << ExistingNodeID << " Not Found.";
  }
}

//Step 6.2!~ search and add new node to current node
//as stated earlier, make one for 3rd node if there was meant to be one
bool DecisionTree::SearchSecondaryNode(TreeNodes *CurrentNode, int ExistingNodeID, int NewNodeID)
{
  if (CurrentNode->m_NodeID == ExistingNodeID)
  {
    //create the node
    if (CurrentNode->SecondaryBranch == NULL)
    {
      CurrentNode->SecondaryBranch = new TreeNodes(NewNodeID);
    }
    else
    {
      CurrentNode->SecondaryBranch = new TreeNodes(NewNodeID);
    }
    return true;
  }
  else
  {
    //try branch if it exists
    if (CurrentNode->PrimaryBranch != NULL)
    {
      if (SearchSecondaryNode(CurrentNode->PrimaryBranch, ExistingNodeID, NewNodeID))
      {
        return true;
      }
      else
      {
        //try second branch if it exists
        if (CurrentNode->SecondaryBranch != NULL)
        {
          return(SearchSecondaryNode(CurrentNode->SecondaryBranch, ExistingNodeID, NewNodeID));
        }
        else
        {
          return false;
        }
      }
    }
    return false;
  }
}

//Step 11
void DecisionTree::QueryTree(TreeNodes* CurrentNode)
{
  if (CurrentNode->PrimaryBranch == NULL)
  {
    //if both branches are null, tree is at a decision outcome state
    if (CurrentNode->SecondaryBranch == NULL)
    {
      //output decision 'question'
      ///////////////////////////////////////////////////////////////////////////////////////
    }
    else
    {
      cout << "Missing Branch 1";
    }
    return;
  }
  if (CurrentNode->SecondaryBranch == NULL)
  {
    cout << "Missing Branch 2";
    return;
  }

  //otherwise test decisions at current node
  MakeDecision(CurrentNode);
}

//Step 10
void DecisionTree::Query()
{
  QueryTree(m_RootNode);
}

////////////////////////////////////////////////////////////
//debate decisions   create new function for decision logic

// cout << node->stringforquestion;

//Step 12
void DecisionTree::MakeDecision(TreeNodes *node)
{
  //should I declare variables here or inside of decisions.h
  int PHealth;
  int MHealth;
  int PStrength;
  int MStrength;
  int DistanceFBase;
  int DistanceFMonster;

  ////sets random!
  srand(time(NULL));

  //randomly create the numbers for health, strength and distance for each variable
  PHealth = random(60);
  MHealth = random(60);
  PStrength = random(50);
  MStrength = random(50);
  DistanceFBase = random(75);
  DistanceFMonster = random(75);

  //the decision to be made string example: Player health: Monster Health:  player health is lower/higher
  cout << "Player Health: " << PHealth << endl;
  cout << "Monster Health: " << MHealth << endl;
  cout << "Player Strength: " << PStrength << endl;
  cout << "Monster Strength: " << MStrength << endl;
  cout << "Distance Player is From Base: " << DistanceFBase << endl;
  cout << "Distance Player is From Monster: " << DistanceFMonster << endl;

  if (PHealth > MHealth)
  {
    std::cout << "Player health is greater than monster health";
    //Do some logic here
  }
  else
  {
    std::cout << "Monster health is greater than player health";
    //Do some logic here
  }

  if (PStrength > MStrength)
  {
    //Do some logic here
  }
  else
  {
  }

  //recursive question for next branch. Player distance from base/monster. 
  if (DistanceFBase > DistanceFMonster)
  {
  }
  else
  {
  }

}

void DecisionTree::Output()
{
  //take respective node
  DisplayTree(m_RootNode);
}

//Step 9
void DecisionTree::DisplayTree(TreeNodes* CurrentNode)
{
  //if it doesn't exist, don't display of course
  if (CurrentNode == NULL)
  {
    return;
  }

  //////////////////////////////////////////////////////////////////////////////////////////////////
  //need to make a string to display for each branch
  cout << "Node ID " << CurrentNode->m_NodeID << "Decision Display: " << endl;

  //go down branch 1
  DisplayTree(CurrentNode->PrimaryBranch);

  //go down branch 2
  DisplayTree(CurrentNode->SecondaryBranch);
}

void DecisionTree::RemoveNode(TreeNodes *node)
{

  if (node != NULL)
  {
    if (node->PrimaryBranch != NULL)
    {
      RemoveNode(node->PrimaryBranch);
    }

    if (node->SecondaryBranch != NULL)
    {
      RemoveNode(node->SecondaryBranch);
    }

    cout << "Deleting Node" << node->m_NodeID << endl;

    //delete node from memory
    delete node;
    //reset node
    node = NULL;
  }
}

int main()
{
  //create the new decision tree object
  DecisionTree* NewTree = new DecisionTree();

  //add root node   the very first 'Question' or decision to be made
  //is monster health greater than player health?
  NewTree->CreateRootNode(1);

  //add nodes depending on decisions
  //2nd decision to be made
  //is monster strength greater than player strength?
  NewTree->PrimaryNode(1, 2);

  //3rd decision
  //is the monster closer than home base?
  NewTree->SecondaryNode(1, 3);

  //depending on the weights of all three decisions, will return certain node result
  //results!
  //Run, Attack, 
  NewTree->PrimaryNode(2, 4);
  NewTree->SecondaryNode(2, 5);
  NewTree->PrimaryNode(3, 6);
  NewTree->SecondaryNode(3, 7);

  NewTree->Output();

  //ask/answer question decision making process
  NewTree->Query();

  cout << "Decision Made. Press Any Key To Quit." << endl;

  int a;
  cin >> a;

  //release memory!
  delete NewTree;

  //return random value
  //return 1;

}
```

## 它是如何工作的…

正如其名称所示，决策树是树数据结构的一个子集。因此，有一个根节点和两个子节点。根节点表示一个条件，子节点将有可能的解决方案。在下一个级别，这些解决方案节点将成为条件的一部分，这将导致另外两个解决方案节点。因此，正如前面的例子所示，整个结构是基于树结构建模的。我们有一个根节点，然后是主节点和次级节点。我们需要遍历树来不断地找到基于根节点和子节点的情况的答案。

我们还编写了一个`Query`函数，它将查询树结构，找出情况的最可能场景。这将得到一个决策函数的帮助，它将添加自己的启发式水平，结合查询的结果，生成解决方案的输出。

决策树非常快，因为对于每种情况，我们只检查了树的一半。因此，实际上我们将搜索空间减少了一半。树结构也使其更加健壮，因此我们也可以随时添加和删除节点。这给了我们很大的灵活性，游戏的整体架构也得到了改进。

# 添加行为动作

当我们谈论游戏中的人工智能时，寻路之后需要考虑的下一个最重要的事情就是移动。AI 何时决定走路、跑步、跳跃或滑行？能够快速而正确地做出这些决定将使 AI 在游戏中变得非常有竞争力，极其难以击败。我们可以通过行为动作来实现所有这些。

## 准备工作

对于这个食谱，你需要一台 Windows 机器和 Visual Studio。不需要其他先决条件。

## 如何做…

在这个例子中，你将发现创建决策树是多么容易。添加一个名为`Source.cpp`的源文件，并将以下代码添加到其中：

```cpp
/* Adding Behavorial Movements*/

#include <iostream>
using namespace std;
class Machine
{
  class State *current;
public:
  Machine();
  void setCurrent(State *s)
  {
    current = s;
  }
  void Run();
  void Walk();
};

class State
{
public:
  virtual void Run(Machine *m)
  {
    cout << "   Already Running\n";
  }
  virtual void Walk(Machine *m)
  {
    cout << "   Already Walking\n";
  }
};

void Machine::Run()
{
  current->Run(this);
}

void Machine::Walk()
{
  current->Walk(this);
}

class RUN : public State
{
public:
  RUN()
  {
    cout << "   RUN-ctor ";
  };
  ~RUN()
  {
    cout << "   dtor-RUN\n";
  };
  void Walk(Machine *m);
};

class WALK : public State
{
public:
  WALK()
  {
    cout << "   WALK-ctor ";
  };
  ~WALK()
  {
    cout << "   dtor-WALK\n";
  };
  void Run(Machine *m)
  {
    cout << " Changing behaviour from WALK to RUN";
    m->setCurrent(new RUN());
    delete this;
  }
};

void RUN::Walk(Machine *m)
{
  cout << "   Changing behaviour RUN to WALK";
  m->setCurrent(new WALK());
  delete this;
}

Machine::Machine()
{
  current = new WALK();
  cout << '\n';
}

int main()
{
  Machine m;
  m.Run();
  m.Walk();
  m.Walk(); 
  int a;
  cin >> a;

  return 0;
}
```

## 它是如何工作的…

在这个例子中，我们实现了一个简单的状态机。状态机是根据**状态机**设计模式创建的。因此，在这种情况下，状态是行走和奔跑。目标是，如果 AI 正在行走，然后需要切换到奔跑，它可以在运行时这样做。同样，如果它正在奔跑，它可以在运行时切换到行走。但是，如果它已经在行走，而请求来了要求行走，它应该通知自己不需要改变状态。

所有这些状态的变化都由一个名为 machine 的类处理，因此得名状态机模式。为什么这种结构被许多人优先于传统的状态机设计，是因为所有状态不需要在一个类中定义，然后使用 switch case 语句来改变状态。虽然这种方法是正确的，但是每增加一个步骤都需要改变和添加到相同的类结构中。这是未来可能出现错误和灾难的风险。相反，我们采用更面向对象的方法，其中每个状态都是一个独立的类。

`machine`类持有指向`StateTo`类的指针，然后将请求推送到状态的适当子类。如果我们需要添加跳跃状态，我们不需要在代码中做太多改动。我们只需要编写一个新的`jump`类并添加相应的功能。因为机器持有指向基类（状态）的指针，它将相应地将跳跃请求推送到正确的派生类。

# 使用神经网络

**人工神经网络**（**ANNs**）是一种高级的人工智能形式，用于一些游戏中。它们可能不会直接在游戏中使用；然而，在生产阶段可能会用于训练 AI 代理人。神经网络主要用作预测算法。基于某些参数和历史数据，它们计算 AI 代理人最可能的决策或属性。ANNs 不仅限于游戏；它们被用于多个不同的领域来预测可能的结果。

## 准备工作

要完成这个示例，您需要一台运行 Windows 和 Visual Studio 的计算机。

## 如何做…

看一下以下代码片段：

```cpp
class neuralNetworkTrainer
{

private:

  //network to be trained
  neuralNetwork* NN;

  //learning parameters
  double learningRate;          // adjusts the step size of the weight update  
  double momentum;            // improves performance of stochastic learning (don't use for batch)

  //epoch counter
  long epoch;
  long maxEpochs;

  //accuracy/MSE required
  double desiredAccuracy;

  //change to weights
  double** deltaInputHidden;
  double** deltaHiddenOutput;

  //error gradients
  double* hiddenErrorGradients;
  double* outputErrorGradients;

  //accuracy stats per epoch
  double trainingSetAccuracy;
  double validationSetAccuracy;
  double generalizationSetAccuracy;
  double trainingSetMSE;
  double validationSetMSE;
  double generalizationSetMSE;

  //batch learning flag
  bool useBatch;

  //log file handle
  bool loggingEnabled;
  std::fstream logFile;
  int logResolution;
  int lastEpochLogged;

public:  

  neuralNetworkTrainer( neuralNetwork* untrainedNetwork );
  void setTrainingParameters( double lR, double m, bool batch );
  void setStoppingConditions( int mEpochs, double dAccuracy);
  void useBatchLearning( bool flag ){ useBatch = flag; }
  void enableLogging( const char* filename, int resolution );

  void trainNetwork( trainingDataSet* tSet );

private:
  inline double getOutputErrorGradient( double desiredValue, double outputValue );
  double getHiddenErrorGradient( int j );
  void runTrainingEpoch( std::vector<dataEntry*> trainingSet );
  void backpropagate(double* desiredOutputs);
  void updateWeights();
};

class neuralNetwork
{

private:

  //number of neurons
  int nInput, nHidden, nOutput;

  //neurons
  double* inputNeurons;
  double* hiddenNeurons;
  double* outputNeurons;

  //weights
  double** wInputHidden;
  double** wHiddenOutput;
  friend neuralNetworkTrainer;

public:

  //constructor & destructor
  neuralNetwork(int numInput, int numHidden, int numOutput);
  ~neuralNetwork();

  //weight operations
  bool loadWeights(char* inputFilename);
  bool saveWeights(char* outputFilename);
  int* feedForwardPattern( double* pattern );
  double getSetAccuracy( std::vector<dataEntry*>& set );
  double getSetMSE( std::vector<dataEntry*>& set );

private:

  void initializeWeights();
  inline double activationFunction( double x );
  inline int clampOutput( double x );
  void feedForward( double* pattern );

};
```

## 工作原理

在这个示例片段中，我们创建了一个骨干来编写一个可以预测屏幕上绘制的字母的神经网络。许多设备和触摸屏平板电脑都具有检测您在屏幕上绘制的字母的能力。让我们以游戏设计的方式来思考这个问题。如果我们想创建一个游戏，在游戏中我们绘制形状，然后会给我们相应的武器，我们可以在战斗中使用，我们可以使用这个作为模板来训练代理人在游戏发布到市场之前识别形状。通常，这些游戏只能检测基本形状。这些可以很容易地被检测到，不需要神经网络来训练代理人。

在游戏中，ANNs 主要用于创建良好的 AI 行为。然而，在游戏进行时使用 ANNs 是不明智的，因为它们成本高，训练代理人需要很长时间。让我们看下面的例子：

| 类别 | 速度 | HP |
| --- | --- | --- |
| 近战 | 速度（4） | 25（HP） |
| 弓箭手 | 速度（7） | 22（HP） |
| 魔法 | 速度（6.4） | 20（HP） |
| ? | 速度（6.6） | 21（HP） |

根据数据，未知的最可能的类是什么？参数的数量（**类别**，**速度**和**HP**）只有三个，但实际上将超过 10 个。仅仅通过观察这些数字来预测类别将是困难的。这就是 ANN 的用武之地。它可以根据其他列的数据和以前的历史数据预测任何缺失的列数据。这对设计师来说是一个非常方便的工具，可以用来平衡游戏。

我们实现的 ANN 的一些概念是必要的。

ANN 通常由三种类型的参数定义：

+   神经元不同层之间的互连模式。

+   更新相互连接权重的学习过程。

+   将神经元加权输入转换为其输出激活的激活函数。

让我们看一下下面解释层的图表：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-gm-dev-cb/img/4929_08_04.jpg)

**输入层**是我们提供所有已知的列数据的层，包括历史数据和新数据。该过程首先涉及提供我们已经知道输出的数据。这个阶段被称为学习阶段。有两种类型的学习算法，监督和非监督。这些的解释超出了本书的范围。之后，有一个训练算法，用于最小化期望输出中的错误。反向传播是一种这样的技术，通过调整计算神经网络函数的权重，直到我们接近期望的结果。在网络设置并为已知输出提供正确结果后，我们可以提供新数据并找到未知列数据的结果。

# 使用遗传算法

**遗传算法**（**GA**）是一种**进化算法**（**EA**）的方法。当我们想要编写预测算法时，它们特别有用，其中只选择最强的，其余的被拒绝。这就是它得名的原因。因此，在每次迭代中，它会发生突变，进行交叉，并且只选择最好的进入下一代种群。遗传算法背后的想法是经过多次迭代后，只有最佳的候选者留下。

## 准备就绪

要完成这个配方，您需要一台安装了 Visual Studio 的 Windows 机器。

## 如何做...

在这个配方中，我们将发现编写遗传算法有多么容易：

```cpp
void crossover(int &seed);
void elitist();
void evaluate();
int i4_uniform_ab(int a, int b, int &seed);
void initialize(string filename, int &seed);
void keep_the_best();
void mutate(int &seed);
double r8_uniform_ab(double a, double b, int &seed);
void report(int generation);
void selector(int &seed);
void timestamp();
void Xover(int one, int two, int &seed);
```

## 它是如何工作的...

起初，遗传算法可能看起来非常难以理解或毫无意义。然而，遗传算法非常简单。让我们想象一种情况，我们有一片充满了具有不同属性的龙的土地。龙的目标是击败具有某些属性的人类玩家。

**龙（AI）**

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-gm-dev-cb/img/4929_08_06.jpg)

**人类（玩家）**

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-gm-dev-cb/img/4929_08_07.jpg)

因此，为了使龙对抗人类具有竞争力，它必须学会奔跑，防御和攻击。让我们看看遗传算法如何帮助我们做到这一点：

### 步骤 1（初始种群）

**龙（AI）：**

这是我们的初始种群。每个都有自己的属性集。我们只考虑三条龙。实际上，会有更多。

![步骤 1（初始种群）](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-gm-dev-cb/img/4929_08_08.jpg)

### 步骤 2（适应函数）

适应度函数（%）确定种群中特定龙的适应程度。100%是完美适应度。

![步骤 2（适应函数）](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-gm-dev-cb/img/4929_08_09.jpg)

### 步骤 3 交叉

基于适应函数和缺失的属性，将进行交叉或繁殖阶段，以创建具有两种属性的新龙：

**表 1**

| 适应度 | 龙 | 属性 1 | 属性 2 | 属性 3 |
| --- | --- | --- | --- | --- |
| 60% | 龙 1 | 奔跑 | 防御 | 攻击 |
| 75% | 龙 2 | 奔跑 | 防御 | 攻击 |
| 20% | 龙 3 | 奔跑 | 防御 | 攻击 |

**表 2**

![步骤 3 交叉](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-gm-dev-cb/img/4929_08_010.jpg)

适应度函数最低的龙将从种群中移除。（适者生存）。

![步骤 3 交叉](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-gm-dev-cb/img/4929_08_011.jpg)

### 步骤 4 突变

因此，我们现在有了一条新的龙，它既可以奔跑又可以攻击，并且适应度函数为*67%*：

![步骤 4 突变](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-gm-dev-cb/img/4929_08_012.jpg)

现在，我们必须重复这个过程（新一代）与种群中的其他龙，直到我们对结果满意为止。理想的种群将是当所有龙都具有以下能力时：

![步骤 4 突变](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-gm-dev-cb/img/4929_08_013.jpg)

然而，这并不总是可能的。我们需要确保它更接近目标。这里描述的所有阶段都被实现为函数，并且可以根据 AI 代理的要求进行扩展。

现在你可能会问，为什么我们不一开始就创建具有所有属性的龙呢？这就是自适应 AI 发挥作用的地方。如果我们在用户玩游戏之前就定义了龙的所有属性，随着游戏的进行，可能会很容易击败龙。然而，如果 AI 龙可以根据玩家如何击败它们来适应，那么击败 AI 可能会变得越来越困难。当玩家击败 AI 时，我们需要记录参数，并将该参数作为龙的目标属性添加，它可以在几次交叉和突变后实现。

# 使用其他航点系统

航点是编写路径规划算法的一种方式。它们非常容易编写。然而，如果没有正确考虑，它们可能会非常有 bug，AI 看起来可能非常愚蠢。许多旧游戏经常出现这种 bug，这导致了航点系统实现的革命。

## 准备工作

要完成这个配方，你需要一台运行 Windows 的机器，并安装了 Visual Studio 的版本。不需要其他先决条件。

## 如何做到...

在这个配方中，我们将发现创建航点系统有多么容易：

```cpp
#include <iostream>

using namespace std;

int main()
{
  float positionA = 4.0f; float positionB = 2.0f; float positionC = -1.0f; float positionD = 10.0f; float positionE = 0.0f;

  //Sort the points according to Djisktra's
  //A* can be used on top of this to minimise the points for traversal
  //Transform the  objects over these new points.
  return 0;
}
```

## 它是如何工作的...

在这个例子中，我们将讨论航点系统的基本实现。顾名思义，航点只是我们希望 AI 代理跟随的世界空间中的 2D/3D 点。代理所要做的就是从点**A**移动到点**B**。然而，这有复杂性。例如，让我们考虑以下图表：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-gm-dev-cb/img/4929_08_05.jpg)

从**A**到**B**很容易。现在，要从**B**到**C**，它必须遵循 A*或 Djikstra 的算法。在这种情况下，它将避开中心的障碍物，向**C**移动。现在假设它突然在旅途中看到了用户在点**A**。它应该如何反应？如果我们只提供航点，它将查看允许移动到的点的字典，并找到最接近它的点。答案将是**A**。然而，如果它开始朝**A**走去，它将被墙挡住，可能会陷入循环，不断撞墙。你可能在旧游戏中经常看到这种行为。在这种情况下，AI 必须做出决定，返回**B**，然后再到**A**。因此，我们不能单独使用航点算法。为了更好的性能和效率，我们需要编写一个决策算法和一个路径规划算法。这是大多数现代游戏中使用的技术，还有**NavMesh**等技术。
