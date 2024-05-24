# C#7 和 .NET Core 秘籍（二）

> 原文：[`zh.annas-archive.org/md5/FFE2E66D9C939D110BF0079B0B5B3BA8`](https://zh.annas-archive.org/md5/FFE2E66D9C939D110BF0079B0B5B3BA8)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第三章：C#中的面向对象编程

本章将向您介绍 C#和面向对象编程（OOP）的基础。在本章中，您将学习以下内容：

+   在 C#中使用继承

+   使用抽象

+   利用封装

+   实现多态

+   单一职责原则

+   开闭原则

+   异常处理

# 介绍

在您作为软件创建者的职业生涯中，您会多次听到 OOP 这个术语。这种设计理念允许对象独立存在，并可以被代码的不同部分重复使用。这一切都是由我们所说的 OOP 的四大支柱所实现的：继承、封装、抽象和多态。

为了理解这一点，您需要开始思考执行特定任务的对象（基本上是实例化的类）。类需要遵循 SOLID 设计原则。这个原则在这里解释：

+   单一职责原则（SRP）

+   开闭原则

+   里斯科夫替换原则（LSP）

+   接口隔离原则

+   依赖反转原则

让我们从解释 OOP 的四大支柱开始，然后我们将更详细地看一下 SOLID 原则。

# 在 C#中使用继承

在今天的世界中，继承通常与事物的结束联系在一起。然而，在 OOP 中，它与新事物的开始和改进联系在一起。当我们创建一个新类时，我们可以取一个已经存在的类，并在我们的新类上继承它。这意味着我们的新对象将具有继承类的所有特性，以及添加到新类的附加特性。这就是继承的根本。我们称从另一个类继承的类为派生类。

# 做好准备

为了说明继承的概念，我们将创建一些从另一个类继承的类，以形成新的、更具特色的对象。

# 如何做到...

1.  创建一个新的控制台应用程序，并在其中添加一个名为`SpaceShip`的类。

```cs
        public class SpaceShip 
        { 

        }

```

1.  我们的`SpaceShip`类将包含一些描述飞船基本情况的方法。继续将这些方法添加到您的`SpaceShip`类中：

```cs
        public class SpaceShip 
        { 
          public void ControlBridge() 
          { 

          } 
          public void MedicalBay(int patientCapacity) 
          { 

          } 
          public void EngineRoom(int warpDrives) 
          { 

          } 
          public void CrewQuarters(int crewCapacity) 
          { 

          } 
          public void TeleportationRoom() 
          { 

          } 
        }

```

因为`SpaceShip`类是所有其他星际飞船的一部分，它成为了每艘其他飞船的蓝图。

1.  接下来，我们想创建一个`Destroyer`类。为了实现这一点，我们将创建一个`Destroyer`类，并在类名后使用冒号表示我们想要从另一个类（`SpaceShip`类）继承。因此，在创建`Destroyer`类时需要添加以下内容：

```cs
        public class Destroyer : SpaceShip 
        { 

        }

```

我们还可以说`Destroyer`类是从`SpaceShip`类派生的。因此，`SpaceShip`类是所有其他星际飞船的基类。

1.  接下来，向`Destroyer`类添加一些仅适用于驱逐舰的方法。这些方法仅属于`Destroyer`类，而不属于`SpaceShip`类：

```cs
        public class Destroyer : SpaceShip 
        { 
          public void WarRoom() 
          { 

          } 
          public void Armory(int payloadCapacity) 
          { 

          } 

          public void WarSpecialists(int activeBattalions) 
          { 

          } 
        }

```

1.  最后，创建一个名为`Annihilator`的第三个类。这是最强大的星际飞船，用于对抗行星。通过创建该类并标记为从`Destroyer`类派生的类，让`Annihilator`类继承`Destroyer`类：

```cs
        public class Annihilator : Destroyer 
        { 

        }

```

1.  最后，向`Annihilator`类添加一些仅属于这种`SpaceShip`类的方法：

```cs
        public class Annihilator : Destroyer 
        { 
          public void TractorBeam() 
          { 

          } 

          public void PlanetDestructionCapability() 
          { 

          } 
        }

```

1.  现在我们看到，当我们在控制台应用程序中创建`SpaceShip`类的新实例时，我们只能使用该类中定义的方法。这是因为`SpaceShip`类没有继承自其他类：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_03_04.png)

1.  继续在控制台应用程序中创建`SpaceShip`类及其方法：

```cs
        SpaceShip transporter = new SpaceShip(); 
        transporter.ControlBridge(); 
        transporter.CrewQuarters(1500); 
        transporter.EngineRoom(2); 
        transporter.MedicalBay(350); 
        transporter.TeleportationRoom();

```

当我们实例化这个类的新实例时，您会看到这些是我们唯一可用的方法。

1.  接下来，在`Destroyer`类中创建一个新实例。您会注意到`Destroyer`类包含的方法比我们在创建类时定义的要多。这是因为`Destroyer`类继承了`SpaceShip`类，因此继承了`SpaceShip`类的方法：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_03_05.png)

1.  在控制台应用程序中创建`Destroyer`类及其所有方法：

```cs
        Destroyer warShip = new Destroyer(); 
        warShip.Armory(6); 
        warShip.ControlBridge(); 
        warShip.CrewQuarters(2200); 
        warShip.EngineRoom(4); 
        warShip.MedicalBay(800); 
        warShip.TeleportationRoom(); 
        warShip.WarRoom(); 
        warShip.WarSpecialists(1);

```

1.  最后，创建`Annihilator`类的新实例。这个类包含了`Destroyer`类的所有方法，以及`SpaceShip`类的方法。这是因为`Annihilator`继承自`Destroyer`，而`Destroyer`又继承自`SpaceShip`：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_03_06.png)

1.  在控制台应用程序中创建`Annihilator`类及其所有方法：

```cs
        Annihilator planetClassDestroyer = new Annihilator(); 
        planetClassDestroyer.Armory(12); 
        planetClassDestroyer.ControlBridge(); 
        planetClassDestroyer.CrewQuarters(4500); 
        planetClassDestroyer.EngineRoom(7); 
        planetClassDestroyer.MedicalBay(3500); 
        planetClassDestroyer.PlanetDestructionCapability(); 
        planetClassDestroyer.TeleportationRoom(); 
        planetClassDestroyer.TractorBeam(); 
        planetClassDestroyer.WarRoom(); 
        planetClassDestroyer.WarSpecialists(3);

```

# 工作原理...

我们可以看到继承允许我们通过重用先前创建的另一个类中已经存在的功能来轻松扩展我们的类。但是需要注意的是，对`SpaceShip`类的任何更改都将被继承，一直到最顶层的派生类。

继承是 C#的一个非常强大的特性，它允许开发人员编写更少的代码，并重用工作和经过测试的方法。

# 使用抽象

通过抽象，我们从我们想要创建的对象中提取出所有派生对象必须具有的基本功能。简单来说，我们将共同功能抽象出来，放入一个单独的类中，用于为所有继承自它的类提供这些共享功能。

# 准备工作

为了解释抽象，我们将使用抽象类。想象一下，你正在处理需要通过训练逐渐晋升的实习太空宇航员。事实上，一旦你作为实习生学会了一项新技能，那项技能就会被学会，并且会一直保留在你身上，即使你学会了更高级的做事方式。你还必须在你创建的新对象中实现所有之前学到的技能。抽象类非常好地展示了这个概念。

# 如何做...

1.  创建一个名为`SpaceCadet`的抽象类。这是在开始训练时可以获得的第一种宇航员类型。使用`abstract`关键字定义抽象类及其成员。需要注意的是，抽象类不能被实例化。成员代表`SpaceCadet`将拥有的技能，比如谈判和基本武器训练。

```cs
        public abstract class SpaceCadet 
        { 
          public abstract void ChartingStarMaps(); 
          public abstract void BasicCommunicationSkill(); 
          public abstract void BasicWeaponsTraining(); 
          public abstract void Negotiation(); 
        }

```

1.  接下来，创建另一个名为`SpacePrivate`的抽象类。这个抽象类继承自`SpaceCadet`抽象类。基本上，我们要表达的是，当一个太空学员被训练成为太空士兵时，他们仍然会拥有作为太空学员学到的所有技能：

```cs
        public abstract class SpacePrivate : SpaceCadet 
        { 
          public abstract void AdvancedCommunicationSkill(); 
          public abstract void AdvancedWeaponsTraining(); 
          public abstract void Persuader(); 
        }

```

1.  为了演示这一点，创建一个名为`LabResearcher`的类，并继承`SpaceCadet`抽象类。通过在新创建的类名后定义冒号和抽象类名，来继承抽象类。这告诉编译器`LabResearcher`类继承自`SpaceCadet`类：

```cs
        public class LabResearcher : SpaceCadet 
        { 

        }

```

因为我们继承了一个抽象类，编译器会在`LabResearcher`类名下划线，警告我们派生类没有实现`SpaceCadet`抽象类中的任何方法。

1.  如果你将鼠标悬停在波浪线上，你会发现灯泡提示会告诉我们发现的问题：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_03_09.png)

1.  Visual Studio 在发现的问题上提供了一个很好的解决方案。通过输入*Ctrl* + *.* (控制键和句点)，你可以让 Visual Studio 显示一些潜在的修复方法（在这种情况下，只有一个修复方法）：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_03_10.png)

1.  在 Visual Studio 添加了所需的方法之后，您会发现这些方法与`SpaceCadet`抽象类中定义的方法相同。因此，抽象类要求从抽象类继承的类实现抽象类中定义的方法。您还会注意到添加到`LabResearcher`类中的方法不包含任何实现，如果按原样使用，将会抛出异常：

```cs
        public class LabResearcher : SpaceCadet 
        { 
          public override void BasicCommunicationSkill() 
          { 
            thrownewNotImplementedException(); 
          } 

          publicoverridevoid BasicWeaponsTraining() 
          { 
            thrownewNotImplementedException(); 
          } 

          publicoverridevoid ChartingStarMaps() 
          { 
            thrownewNotImplementedException(); 
          } 

          publicoverridevoid Negotiation() 
          { 
            thrownewNotImplementedException(); 
          } 
        }

```

1.  接下来，创建一个名为`PlanetExplorer`的类，并使该类继承自`SpacePrivate`抽象类。您会记得`SpacePrivate`抽象类继承自`SpaceCadet`抽象类：

```cs
        public class PlanetExplorer : SpacePrivate 
        { 

        }

```

1.  Visual Studio 将再次警告您，您的新类没有实现继承的抽象类的方法。然而，在这里，您会注意到灯泡提示通知您，您没有实现`SpacePrivate`和`SpaceCadet`抽象类中的任何方法。这是因为`SpacePrivate`抽象类继承自`SpaceCadet`抽象类：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_03_11.png)

1.  与以前一样，要解决识别出的问题，输入*Ctrl* + *.*（控制键和句点），让 Visual Studio 显示一些潜在的修复方法（在这种情况下，只有一个修复方法）。

1.  在代码中添加修复后，您会发现`PlanetExplorer`类包含`SpacePrivate`和`SpaceCadet`抽象类中的所有方法：

```cs
        public class PlanetExplorer : SpacePrivate 
        { 
          public override void AdvancedCommunicationSkill() 
          { 
            throw new NotImplementedException(); 
          } 

          public override void AdvancedWeaponsTraining() 
          { 
            throw new NotImplementedException(); 
          } 

          public override void BasicCommunicationSkill() 
          { 
            throw new NotImplementedException(); 
          } 

          public override void BasicWeaponsTraining() 
          { 
            throw new NotImplementedException(); 
          } 

          public override void ChartingStarMaps() 
          { 
            throw new NotImplementedException(); 
          } 

          public override void Negotiation() 
          { 
            throw new NotImplementedException(); 
          } 

          public override void Persuader() 
          { 
            throw new NotImplementedException(); 
          } 
        }

```

# 工作原理...

抽象化使我们能够定义一组共享的功能，这些功能将在所有从抽象类派生的类之间共享。从抽象类继承和从普通类继承的区别在于，使用抽象类，您必须实现该抽象类中定义的所有方法。

这使得类易于版本控制和更改。如果需要添加新功能，可以通过将该功能添加到抽象类中而不破坏任何现有代码来实现。Visual Studio 将要求所有继承类实现抽象类中定义的新方法。

因此，您可以放心，应用的更改将在您代码中从抽象类派生的所有类中实现。

# 利用封装

封装是什么？简单来说，它是隐藏类的内部工作，这些内部工作对于该类的实现并不必要。将封装视为以下内容：拥有汽车的大多数人知道汽车是用汽油驱动的-他们不需要知道内燃机的内部工作就能使用汽车。他们只需要知道当汽车快没油时需要加油，以及需要检查机油和轮胎气压。即使这样，通常也不是由汽车所有者来做。这对于类和封装来说也是如此。

类的所有者是使用它的人。该类的内部工作不需要暴露给使用该类的开发人员。因此，该类就像一个黑匣子。只要输入正确，开发人员就知道该类的功能是一致的。开发人员并不关心类如何得到输出，只要输入正确即可。

# 准备工作

为了说明封装的概念，我们将创建一个在内部工作上有些复杂的类。我们需要计算太空飞船的**推重比**（**TWR**），以确定它是否能够垂直起飞。它需要施加比自身重量更大的推力来抵消重力并进入稳定轨道。这也取决于太空飞船从哪个行星起飞，因为不同的行星对其表面上的物体施加不同的重力。简单来说，推重比必须大于一。

# 如何做...

1.  创建一个名为`LaunchSuttle`的新类。然后，向该类添加以下私有变量，用于引擎推力、航天飞机的质量、当地的重力加速度、地球、月球和火星的重力常数（这些是常数，因为它们永远不会改变）、宇宙引力常数，以及用于处理的行星的枚举器：

```cs
        public class LaunchShuttle 
        { 
          private double _EngineThrust; 
          private double _TotalShuttleMass; 
          private double _LocalGravitationalAcceleration; 

          private const double EarthGravity = 9.81; 
          private const double MoonGravity = 1.63; 
          private const double MarsGravity = 3.75; 
          private double UniversalGravitationalConstant; 

          public enum Planet { Earth, Moon, Mars } 
        }

```

1.  对于我们的类，我们将添加三个重载的构造函数，这些函数对于根据实例化时的已知事实进行 TWR 计算至关重要（我们假设我们将始终知道发动机推力能力和航天飞机的质量）。我们将为第一个构造函数传递重力加速度。如果我们事先知道该值，这将非常有用。例如，地球的重力加速度为 9.81 m/s²。

第二个构造函数将使用`Planet`枚举器来计算使用常量变量值的 TWR。

第三个构造函数将使用行星的半径和质量来计算重力加速度，当这些值已知时，以返回 TWR：

```cs
        public LaunchShuttle(double engineThrust, 
          double totalShuttleMass, double gravitationalAcceleration) 
        { 
          _EngineThrust = engineThrust; 
          _TotalShuttleMass = totalShuttleMass; 
          _LocalGravitationalAcceleration =  gravitationalAcceleration; 

        } 

        public LaunchShuttle(double engineThrust, 
          double totalShuttleMass, Planet planet) 
        { 
          _EngineThrust = engineThrust; 
          _TotalShuttleMass = totalShuttleMass; 
          SetGraviationalAcceleration(planet); 

        } 

        public LaunchShuttle(double engineThrust, double 
          totalShuttleMass, double planetMass, double planetRadius) 
        { 
          _EngineThrust = engineThrust; 
          _TotalShuttleMass = totalShuttleMass; 
          SetUniversalGravitationalConstant(); 
          _LocalGravitationalAcceleration =  Math.Round(
            CalculateGravitationalAcceleration (
              planetRadius, planetMass), 2); 
        }

```

1.  为了使用第二个重载的构造函数，将`Planet`枚举器作为参数传递给类，我们需要创建另一个方法，将其范围设置为`private`，以计算重力加速度。我们还需要将`_LocalGravitationalAcceleration`变量设置为与枚举器值匹配的特定常数。这个方法是类的用户不需要看到的，以便使用类。因此，它被设置为`private`，以隐藏用户的功能：

```cs
        private void SetGraviationalAcceleration(Planet planet) 
        { 
          switch (planet) 
          { 
            case Planet.Earth: 
              _LocalGravitationalAcceleration = EarthGravity; 
            break; 
            case Planet.Moon: 
              _LocalGravitationalAcceleration = MoonGravity; 
            break; 
            case Planet.Mars: 
              _LocalGravitationalAcceleration = MarsGravity; 
            break; 
            default: 
            break; 
          } 
        }

```

1.  在以下方法中，只有一个被定义为公共的，因此对类的用户可见。创建私有方法来设置通用引力常数，并计算 TWR 和重力加速度。这些都被设置为私有，因为开发人员不需要知道这些方法的功能就能使用类：

```cs
        private void SetUniversalGravitationalConstant() 
        { 
          UniversalGravitationalConstant = 6.6726 * Math.Pow(10,  -11); 
        } 

        private double CalculateThrustToWeightRatio() 
        { 
          // TWR = Ft/m.g > 1 
          return _EngineThrust / (_TotalShuttleMass * 
                      _LocalGravitationalAcceleration); 
        } 

        private double CalculateGravitationalAcceleration(
                       double  radius, double mass) 
        { 
          return (UniversalGravitationalConstant * mass) / 
                                        Math.Pow(radius, 2); 
        } 

        public double TWR() 
       { 
         return Math.Round(CalculateThrustToWeightRatio(), 2); 
       }

```

1.  最后，在您的控制台应用程序中，创建以下变量及其已知的值：

```cs
        double thrust = 220; // kN 
        double shuttleMass = 16.12; // t 
        double gravitationalAccelerationEarth = 9.81; 
        double earthMass = 5.9742 * Math.Pow(10, 24); 
        double earthRadius = 6378100; 
        double thrustToWeightRatio = 0;

```

1.  创建`LaunchShuttle`类的新实例，并传递需要计算 TWR 的值：

```cs
        LaunchShuttle NasaShuttle1 = new LaunchShuttle(thrust, 
                   shuttleMass, gravitationalAccelerationEarth); 
        thrustToWeightRatio = NasaShuttle1.TWR(); 
        Console.WriteLine(thrustToWeightRatio);

```

1.  当您在`NasaShuttle1`变量上使用点运算符时，您会注意到 IntelliSense 只显示`TWR`方法。该类不会暴露出如何计算得到 TWR 值的内部工作方式。开发人员唯一知道的是，`LaunchShuttle`类将始终返回正确的 TWR 值，给定相同的输入参数：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_03_13.png)

1.  为了测试这一点，创建`LaunchShuttle`类的另外两个实例，并每次调用不同的构造函数：

```cs
        LaunchShuttle NasaShuttle2 = new LaunchShuttle(thrust, 
                       shuttleMass, LaunchShuttle.Planet.Earth); 
        thrustToWeightRatio = NasaShuttle2.TWR(); 
        Console.WriteLine(thrustToWeightRatio); 

        LaunchShuttle NasaShuttle3 = new LaunchShuttle(
           thrust,  shuttleMass, earthMass, earthRadius); 
        thrustToWeightRatio = NasaShuttle3.TWR(); 
        Console.WriteLine(thrustToWeightRatio); 

        Console.Read();

```

1.  如果运行您的控制台应用程序，您会看到 TWR 返回相同的值。该值表明，一个重 16.12 吨的航天飞机，配备产生 220 千牛的推力的火箭，将能够从地球表面起飞（即使只是刚刚）：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_03_14.png)

# 工作原理... 

该类使用作用域规则，将类内部的某些功能隐藏在开发人员使用类时。如前所述，开发人员不需要知道如何进行计算以返回 TWR 值。所有这些都有助于使类更有用且易于实现。以下是 C#中可用的各种作用域及其用途的列表：

+   `Public`：这用于变量、属性、类型和方法，可在任何地方可见。

+   `Private`：这用于变量、属性、类型和方法，仅在定义它们的块中可见。

+   `Protected`：这用于变量、属性和方法。不要将其视为公共或私有。受保护的范围仅在使用它的类内部可见，以及在任何继承的类中可见。

+   `Friend`：这用于变量、属性和方法，只能被同一项目或程序集中的代码使用。

+   `ProtectedFriend`：这用于变量、属性和方法，是受保护和友元范围的组合（正如名称所示）。

# 实现多态性

多态性是一个概念，一旦您查看并理解了面向对象编程的其他支柱，就会很容易理解。多态性字面上意味着某物可以有多种形式。这意味着从单个接口，您可以创建多个实现。

这有两个小节，即静态和动态多态性。通过**静态多态性**，您正在处理方法和函数的重载。您可以使用相同的方法，但执行许多不同的任务。

通过**动态多态性**，您正在处理抽象类的创建和实现。这些抽象类充当了告诉您派生类应该实现什么的蓝图。接下来的部分将同时查看这两者。

# 准备工作

我们将首先说明抽象类的用法，这是动态多态性的一个例子。然后，我们将创建重载构造函数作为静态多态性的一个例子。

# 如何做…

1.  创建一个名为`Shuttle`的抽象类，并给它一个名为`TWR`的成员，这是对航天飞机的推重比进行计算：

```cs
        public abstract class Shuttle 
        { 
          public abstract double TWR(); 
        }

```

1.  接下来，创建一个名为`NasaShuttle`的类，并让它继承自抽象类`Shuttle`，方法是在`NasaShuttle`类声明的末尾冒号后放置抽象类名称：

```cs
        public class NasaShuttle : Shuttle 
        { 

        }

```

1.  Visual Studio 会下划线标记`NasaShuttle`类，因为您已经告诉编译器该类继承自抽象类，但尚未实现该抽象类的成员：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_03_15.png)

1.  要解决识别出的问题，请键入*Ctrl* + *.*（控制键和句点），让 Visual Studio 为您显示一些潜在的修复方法（在这种情况下，只有一个修复方法）：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_03_16.png)

1.  然后，Visual Studio 会向`NasaShuttle`类添加缺少的实现。默认情况下，它将添加为未实现，因为您需要为抽象类中覆盖的抽象成员提供实现：

```cs
        public class NasaShuttle : Shuttle 
        { 
          public override double TWR() 
          { 
            throw new NotImplementedException(); 
          } 
        }

```

1.  创建另一个名为`RoscosmosShuttle`的类，并从相同的`Shuttle`抽象类继承：

```cs
        public class RoscosmosShuttle : Shuttle 
        { 

        }

```

1.  与以前一样，Visual Studio 会下划线标记`RoscosmosShuttle`类，因为您已经告诉编译器该类继承自抽象类，但尚未实现该抽象类的成员。

1.  要解决识别出的问题，请键入*Ctrl* + *.*（控制键和句点），让 Visual Studio 为您显示一些潜在的修复方法（在这种情况下，只有一个修复方法）。

1.  然后，重写的方法将作为未实现添加到`RoscosmosShuttle`类中。您刚刚看到了动态多态性的一个示例：

```cs
        public class RoscosmosShuttle : Shuttle 
        { 
          public override double TWR() 
          { 
            throw new NotImplementedException(); 
          } 
        }

```

1.  要查看静态多态性的示例，请为`NasaShuttle`创建以下重载构造函数。构造函数名称保持不变，但构造函数的签名发生变化，这使其成为重载：

```cs
        public NasaShuttle(double engineThrust, 
          double  totalShuttleMass, double gravitationalAcceleration) 
        { 

        } 

        public NasaShuttle(double engineThrust, 
          double  totalShuttleMass, double planetMass, 
          double planetRadius) 
        { 

        }

```

# 工作原理…

多态性是您通过将良好的面向对象原则应用于类的设计而已经在使用的东西。通过抽象的`Shuttle`类，我们看到该类在用于从其抽象中派生这些新类时，采用了`NasaShuttle`类和`RoscosmosShuttle`类的形式。然后，`NasaShuttle`类的构造函数被覆盖，以提供相同的方法名称，但使用不同的签名进行实现。

这就是多态性的核心。很可能，您一直在使用它，却不知道它。

# 单一职责原则

在谈论 SOLID 原则时，我们将从**单一职责原则**（**SRP**）开始。在这里，我们实际上是在说一个类有一个特定的任务需要完成，不应该做其他任何事情。

# 准备工作

当向星际飞船添加更多的部队时引发异常，导致其超载时，您将创建一个新的类并编写代码将错误记录到数据库中。对于此示例，请确保已将`using System.Data;`和`using System.Data.SqlClient;`命名空间添加到您的应用程序中。

# 如何做...

1.  创建一个名为`StarShip`的新类：

```cs
        public class Starship 
        { 

        }

```

1.  向您的类中添加一个新方法，该方法将设置`StarShip`类的最大部队容量：

```cs
        public void SetMaximumTroopCapacity(int capacity) 
        {             

        }

```

1.  在这个方法中，添加一个`trycatch`子句，将尝试设置最大的部队容量，但由于某种原因，它将失败。失败时，它将错误写入数据库内的日志表：

```cs
        try 
        { 
          // Read current capacity and try to add more 
        } 
        catch (Exception ex) 
        { 
          string connectionString = "connection string goes  here";
          string sql = $"INSERT INTO tblLog (error, date) VALUES
            ({ex.Message}, GetDate())";
          using (SqlConnection con = new 
                 SqlConnection(connectionString)) 
          { 
            SqlCommand cmd = new SqlCommand(sql); 
            cmd.CommandType = CommandType.Text; 
            cmd.Connection = con; 
            con.Open(); 
            cmd.ExecuteNonQuery(); 
          } 
          throw ex; 
        }

```

# 它是如何工作的...

如果您的代码看起来像前面的代码，那么您就违反了 SRP。`StarShip`类不再仅负责自身和与星际飞船有关的事物。它现在还必须履行将错误记录到数据库的角色。您在这里看到的问题是数据库记录代码不属于`SetMaximumTroopCapacity`方法的`catch`子句。更好的方法是创建一个单独的`DatabaseLogging`类，其中包含创建连接和将异常写入适当日志表的方法。您还会发现您将不得不在多个地方编写该记录代码（在每个`catch`子句中）。如果您发现自己重复编写代码（通过从其他地方复制和粘贴），那么您可能需要将该代码放入一个公共类中，并且您可能已经违反了 SRP 规则。

# 开闭原则

在创建类时，我们需要确保该类通过需要更改内部代码来禁止任何破坏性修改。我们说这样的类是封闭的。如果我们需要以某种方式更改它，我们可以通过扩展类来实现。这种可扩展性是我们说类是开放的扩展。

# 准备工作

您将创建一个类，通过查看 trooper 的类来确定 trooper 的技能。我们将向您展示许多开发人员创建这样一个类的方式，以及如何使用开闭原则创建它。

# 如何做...

1.  创建一个名为`StarTrooper`的类：

```cs
        public class StarTrooper 
        { 

        }

```

1.  在这个类中，添加一个名为`TrooperClass`的枚举器，以标识我们想要返回技能的 trooper 类型。还要创建一个`List<string>`变量，以包含特定 trooper 类的技能。最后，创建一个名为`GetSkills`的方法，返回给定 trooper 类的特定技能集。

这个类非常简单，但代码的实现是我们经常看到的。有时，您会看到一大堆`if...else`语句，而不是`switch`语句。虽然代码的功能很明确，但很难在不更改代码的情况下向`StarTrooper`类添加另一个 trooper 类。假设您现在必须向`StarTrooper`类添加一个额外的`Engineer`类。您将不得不修改`TrooperClass`枚举和`switch`语句中的代码。

代码的更改可能会导致您在先前正常工作的代码中引入错误。我们现在看到`StarTrooper`类没有关闭，无法轻松地扩展以适应其他`TrooperClass`对象：

```cs
        public enum TrooperClass { Soldier, Medic, Scientist } 
        List<string> TroopSkill; 

        public List<string> GetSkills(TrooperClass troopClass) 
        { 
          switch (troopClass) 
          { 
            case TrooperClass.Soldier: 
              return TroopSkill = new List<string>(new string[] {
                "Weaponry", "TacticalCombat",  "HandToHandCombat" }); 

            case TrooperClass.Medic: 
              return TroopSkill = new List<string>(new string[] {
                "CPR", "AdvancedLifeSupport" }); 

            case TrooperClass.Scientist: 
              return TroopSkill = new List<string>(new string[] {
                "Chemistry",  "MollecularDeconstruction", 
                "QuarkTheory" }); 

            default: 
              return TroopSkill = new List<string>(new string[]  {
                "none" }); 
          } 
        }

```

1.  这个问题的解决方案是继承。我们不需要更改代码，而是扩展它。首先，重新编写前面的`StarTrooper`类并创建一个`Trooper`类。`GetSkills`方法声明为`virtual`：

```cs
        public class Trooper 
        { 
          public virtual List<string> GetSkills() 
          { 
            return new List<string>(new string[] { "none" }); 
          } 
        }

```

1.  现在，我们可以轻松地为可用的`Soldier`、`Medic`和`Scientist`trooper 类创建派生类。创建以下继承自`Trooper`类的派生类。您可以看到在创建`GetSkills`方法时使用了`override`关键字：

```cs
        public class Soldier : Trooper 
        { 
          public override List<string> GetSkills() 
          { 
            return new List<string>(new string[] { "Weaponry", 
                         "TacticalCombat", "HandToHandCombat" }); 
          } 
        } 

        public class Medic : Trooper 
        { 
          public override List<string> GetSkills() 
          { 
            return new List<string>(new string[] { 
                   "CPR",  "AdvancedLifeSupport" }); 
          } 
        } 

        public class Scientist : Trooper 
        { 
          public override List<string> GetSkills() 
          { 
            return new List<string>(new string[] { "Chemistry",
              "MollecularDeconstruction", "QuarkTheory" }); 
          } 
        }

```

1.  当扩展类以添加`Trooper`的附加类时，代码变得非常容易实现。如果现在我们想要添加`Engineer`类，我们只需在从之前创建的`Trooper`类继承后重写`GetSkills`方法：

```cs
        public class Engineer : Trooper 
        { 
          public override List<string> GetSkills() 
          { 
            return new List<string>(new string[] {  
              "Construction", "Demolition" }); 
          } 
        }

```

# 它是如何工作的...

从`Trooper`类派生的类是`Trooper`类的扩展。我们可以说每个类都是封闭的，因为修改它不需要改变原始代码。`Trooper`类也是可扩展的，因为我们已经能够通过创建从中派生的类轻松扩展该类。

这种设计的另一个副产品是更小、更易管理的代码，更容易阅读和理解。

# 异常处理

异常处理是您作为开发人员需要了解的内容，您还必须非常擅长辨别要向最终用户显示什么信息以及要记录什么信息。信不信由你，编写良好的错误消息比看起来更难。向用户显示太多信息可能会在软件中灌输一种不信任感。为了调试目的记录的信息太少对于需要修复错误的可怜人来说也毫无用处。这就是为什么您需要有一个**异常处理策略**。

一个很好的经验法则是向用户显示一条消息，说明出了问题，但已向支持人员发送了通知。想想谷歌、Dropbox、Twitter（还记得蓝鲸吗？）和其他大公司。有趣的错误页面，上面有一个手臂掉了的小机器人，或者向用户显示一个流行的表情图，远比一个充满堆栈跟踪和红色文本的威胁性错误页面要好得多。这是一种暂时让用户从令人沮丧的情况中抽离的方式。最重要的是，它让您保持面子。

让我们首先看一下异常过滤器。这已经存在一段时间了。Visual Basic.NET（VB.NET）和 F#开发人员已经拥有了这个功能一段时间。它在 C# 6.0 中引入，并且功能远不止看上去的那么简单。乍一看，异常过滤器似乎只是指定需要捕获异常的条件。毕竟，这就是*异常过滤器*这个名字所暗示的。然而，仔细观察后，我们发现异常过滤器的作用远不止是一种语法糖。 

# 准备工作

我们将创建一个名为`Chapter3`的新类，并调用一个方法来读取 XML 文件。文件读取逻辑由设置为`true`的布尔标志确定。想象一下，还有一些其他数据库标志，当设置时，也会将我们的布尔标志设置为`true`，因此，我们的应用程序知道要读取给定的 XML 文件。

首先确保已添加以下`using`语句：

```cs
using System.IO;

```

# 如何做...

1.  创建一个名为`Chapter3`的类（如果还没有），其中包含两个方法。一个方法读取 XML 文件，第二个方法记录任何异常错误：

```cs
        public void ReadXMLFile(string fileName)
        {
          try
          {
            bool blnReadFileFlag = true;
            if (blnReadFileFlag)
            {
              File.ReadAllLines(fileName);
            }
          }
          catch (Exception ex)
          {
            Log(ex);
            throw;
          }
        }

        private void Log(Exception e)
        {
          /* Log the error */
        }

```

1.  在控制台应用程序中，添加以下代码来调用`ReadXMLFile`方法，并将文件名传递给它以进行读取：

```cs
Chapter3 ch3 = new Chapter3();
string File = @"c:tempXmlFile.xml";
ch3.ReadXMLFile(File);

```

1.  运行应用程序将生成一个错误（假设您的`temp`文件夹中实际上没有名为`XMLFile.xml`的文件）。Visual Studio 将在`throw`语句上中断：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_03_01.png)

1.  `Log(ex)`方法已记录了异常，但是看看 Watch1 窗口。我们不知道`blnReadFileFlag`的值是多少。当捕获异常时，堆栈被展开（为您的代码增加了开销）到实际的 catch 块。因此，异常发生之前的堆栈状态丢失了。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_03_02.png)

1.  修改您的`ReadXMLFile`和`Log`方法如下以包括异常过滤器：

```cs
        public void ReadXMLFile(string fileName)
        {
          try
          {
            bool blnReadFileFlag = true;
            if (blnReadFileFlag)
            {
              File.ReadAllLines(fileName);
            }
          }
          catch (Exception ex) when (Log(ex))
          {
          }
        }
        private bool Log(Exception e)
        {
          /* Log the error */
          return false;
        }

```

1.  再次运行控制台应用程序，Visual Studio 将在导致异常的实际代码行上中断：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_03_03.png)

1.  更重要的是，`blnReadFileFlag`的值仍然在作用域内。这是因为异常过滤器可以看到异常发生的地点的堆栈状态，而不是异常处理的地点。在 Visual Studio 的本地窗口中查看，您会发现变量在异常发生的地点仍然在作用域内。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_03_04.png)

# 它是如何工作的...

想象一下能够在日志文件中查看异常信息，并且所有局部变量值都可用。另一个有趣的地方要注意的是`Log(ex)`方法中的返回`false`语句。使用这种方法记录错误并返回`false`将允许应用程序继续并在其他地方处理异常。如您所知，捕获`Exception ex`将捕获一切。通过返回`false`，异常过滤器不会进入`catch`语句，并且可以使用更具体的`catch`异常（例如，在`catch (Exception ex)`语句之后的`catch (FileNotFoundException ex)`）来处理特定错误。通常，在捕获异常时，`FileNotFoundException`不会在以下代码示例中被捕获：

```cs
catch (Exception ex)
{ 
}
catch (FileNotFoundException ex)
{ 
}

```

这是因为捕获异常的顺序是错误的。传统上，开发人员必须按照特异性的顺序捕获异常，这意味着`FileNotFoundException`比`Exception`更具体，因此必须在`catch (Exception ex)`之前放置。通过调用返回`false`的方法的异常过滤器，我们可以准确检查和记录异常：

```cs
catch (Exception ex) when (Log(ex))
{ 
}
catch (FileNotFoundException ex)
{ 
}

```

前面的代码将捕获所有异常，并在这样做时准确记录异常，但不会进入异常处理程序，因为`Log(ex)`方法返回`false`。异常过滤的另一个实现是，它们可以允许开发人员在发生故障时重试代码。您可能不希望特别捕获第一个异常，而是在方法中实现一种超时元素。当错误计数器达到最大迭代次数时，您可以捕获并处理异常。您可以在这里看到基于`try`子句计数捕获异常的示例：

```cs
public void TryReadXMLFile(string fileName)
{
  bool blnFileRead = false;
  do
  {
    int iTryCount = 0;
    try
    {
      bool blnReadFileFlag = true;
      if (blnReadFileFlag)
      File.ReadAllLines(fileName);
    }
    catch (Exception ex) when (RetryRead(ex, iTryCount++) == true)
    {
    }
  } while (!blnFileRead);
}

private bool RetryRead(Exception e, int tryCount)
{
  bool blnThrowEx = tryCount <= 10 ? blnThrowEx = 
       false : blnThrowEx = true;
  /* Log the error if blnThrowEx = false */
  return blnThrowEx;
}

```

异常过滤是处理代码中异常的一种非常有用且非常强大的方式。异常过滤的幕后工作并不像人们想象的那样立即显而易见，但这就是异常过滤的实际力量所在。


# 第四章：Visual Studio 中的代码分析器

在本章中，我们将看一下代码分析器以及它们如何帮助开发人员编写更好的代码。我们将涵盖以下主题：

+   查找并安装分析器

+   创建代码分析器

+   创建自定义代码分析器

+   仅在您的组织内部部署您的代码分析器

# 介绍

从 Visual Studio 2015 开始，开发人员可以创建特定于其项目或开发团队的自定义代码分析器。一些开发团队有一套需要遵守的标准。也许您是独立开发人员，希望使您的代码符合某些最佳实践。无论您的原因是什么，代码分析器都为开发人员打开了大门。

您可以确保您或您的团队发布的代码符合特定的代码质量标准。可以从 GitHub 下载几个代码分析器。我们将看一下其中一个名为 CodeCracker for C#的代码分析器。

# 查找并安装分析器

GitHub 上有很多代码分析器。快速搜索返回了 72 个存储库结果中的 28 个可能的 C#代码分析器。其中一些似乎是学生项目。也检查一下这些；其中一些代码非常聪明。至于这个示例，我们将使用 CodeCracker for C#来演示如何从 NuGet 包中安装分析器。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_04_23.png)

# 准备工作

您要做的就是为项目下载一个 NuGet 包。除此之外，您无需做任何特别的准备。

# 如何做...

1.  首先创建一个新的控制台应用程序。您可以随意命名。在我的示例中，我只是称它为`DiagAnalyzerDemo`。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_04_01.png)

1.  从“工具”菜单中，选择 NuGet 包管理器，然后选择“解决方案的 NuGet 包管理器”。

1.  在“浏览”选项卡中，搜索`Code-Cracker`。结果应返回 codecracker.CSharp NuGet 包。选择要应用 NuGet 包的项目，然后单击“安装”按钮。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_04_03.png)

1.  Visual Studio 将允许您查看即将进行的更改。单击“确定”按钮继续。

1.  在显示许可条款时，单击“接受”。

1.  安装 NuGet 包后，结果将显示在“输出”窗口中。

1.  查看您的项目，您会注意到 CodeCracker.CSharp 分析器已添加到解决方案资源管理器中的“分析器”节点下。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_04_07.png)

1.  如果展开 CodeCracker.CSharp 分析器，您将看到 NuGet 包中包含的所有单独的分析器。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_04_08.png)

1.  然而，有一个更好的地方可以查看这些分析器。从“项目”菜单中，转到“[项目名称]”属性菜单项。在我的情况下，这是 DiagAnalyzerDemo 属性....

1.  单击“打开”按钮打开规则集。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_04_10.png)

1.  在这里，您将看到所有可用的分析器集合；从此屏幕，您可以修改特定分析器的操作。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_04_11.png)

1.  在您的代码中，添加以下类。您可以随意命名，但为简单起见，请使用以下示例。您将看到我有一个构造函数，设置了一个名为`DimensionWHL`的属性。此属性只返回一个包含“宽度”、“高度”和“长度”值的数组。确实不是很好的代码。

```cs
        public class ShippingContainer
        {
          public int Width { get; set; }
          public int Height { get; set; }
          public int Length { get; set; }
          public int[] DimensionsWHL { get; set; }
          public ShippingContainer(int width, int height, int length)
          {
            Width = width;
            Height = height;
            Length = length;

            DimensionsWHL = new int[] { width, height, length };
          }
        }

```

1.  返回到分析器屏幕并搜索单词“属性”。您将看到一个名为 CA1819 的分析器，指定属性永远不应返回数组。操作更改为警告，但如果愿意，可以通过单击“操作”列下的“警告”单词并选择“错误”来更改为错误。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_04_12-1.png)

1.  保存更改并构建您的控制台应用程序。您将看到代码分析器 CA1819 的警告显示在错误列表中。如果将操作更改为错误，构建将会因为该错误而中断。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_04_13.png)

# 工作原理...

代码分析器可以为您提供许多功能，并帮助开发人员避免常见的不良编码实践，并强制执行特定的团队准则。每个代码分析器可以设置为不同的严重程度，最严重的实际上会导致构建失败。将代码分析器保留在项目的引用中允许您将其检入源代码控制；这在构建项目时进行评估。但是，您也可以将分析器存储在每台计算机上。这些分析器将用于个人代码改进、提示和个人使用。

代码分析器非常适合现代开发人员，因为它们在开发人员的控制下，并且可以轻松集成到 Visual Studio 中。

# 创建代码分析器

有些人可能已经看到了创建自己的代码分析器的好处。能够控制特定设计实现和团队特定的编码标准对您的团队来说是非常宝贵的。这对于加入您的团队的新开发人员尤其重要。我记得几年前开始为一家公司工作时，开发经理给了我一份需要遵守的代码标准文件。当时这很棒。它向我表明他们关心代码标准。当时，开发人员当然没有代码分析器。然而，跟踪我需要实施的所有标准是相当具有挑战性的。特别是对于公司实施的特定代码标准来说，情况尤其如此。

# 准备工作

在您创建自己的代码分析器之前，您需要确保已安装.NET 编译器平台 SDK。要做到这一点，请执行以下步骤：

1.  向您的解决方案添加一个新项目，然后单击可扩展性。选择下载.NET 编译器平台 SDK，然后单击确定。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_04_14.png)

1.  这实际上将创建一个带有索引文件的项目。打开的页面将提供下载.NET 编译器平台 SDK 的链接。单击该链接开始下载。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_04_15.png)

1.  只需将下载的文件保存到硬盘上的一个目录中。然后在单击 VSIX 文件之前关闭 Visual Studio。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_04_16.png)

1.  .NET 编译器平台 SDK 安装程序现在将启动，并允许您选择要安装到的 Visual Studio 实例。

安装完成后，再次重新启动 Visual Studio。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_04_18.png)

# 如何做...

1.  向您的 Visual Studio 解决方案添加一个新项目，然后单击可扩展性，选择带有代码修复的分析器（NuGet + VSIX）模板。给它一个合适的名称，然后单击确定以创建分析器项目。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_04_19.png)

1.  您会发现 Visual Studio 已为您创建了三个项目：`Portable`，`.Test`和`.Vsix`。确保`.Vsix`项目设置为默认启动项目。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_04_20.png)

1.  在`Portable`类中，查看`DiagnosticAnalyzer.cs`文件。您将看到一个名为`AnalyzeSymbol()`的方法。这个代码分析器所做的一切就是简单地检查`namedTypeSymbol`变量上是否存在小写字母。

```cs
        private static void AnalyzeSymbol(
          SymbolAnalysisContext context)
        {
          // TODO: Replace the following code with your own 
             analysis, generating Diagnostic objects for any 
             issues you find
          var namedTypeSymbol = (INamedTypeSymbol)context.Symbol;

          // Find just those named type symbols with names 
             containing lowercase letters.
          if (namedTypeSymbol.Name.ToCharArray().Any(char.IsLower))
          {
            // For all such symbols, produce a diagnostic.
            var diagnostic = Diagnostic.Create(Rule, 
              namedTypeSymbol.Locations[0], namedTypeSymbol.Name);

            context.ReportDiagnostic(diagnostic);
          }
        }

```

1.  构建您的项目并单击*F5*开始调试。这将启动一个新的 Visual Studio 实例，具有自己的设置。这意味着您在这个实验性的 Visual Studio 实例中所做的任何更改都不会影响您当前的 Visual Studio 安装。您可以打开现有项目或创建新项目。我只是创建了一个控制台应用程序。从一开始，您会看到`Program`类名被下划线标记。将光标悬停在此处将显示 Visual Studio 的灯泡，并告诉您类型名称包含小写字母。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_04_21.png)

1.  单击*Ctrl* + *.*或在工具提示中单击“显示潜在修复”链接，将显示您可以应用以纠正错误的修复程序。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_04_22.png)

# 工作原理...

代码分析器将检查托管程序集并报告任何相关信息。这可以是违反.NET *Framework Design Guidelines*中的编程和设计规则的任何代码。代码分析器将显示其执行的检查作为警告消息，并在可能的情况下建议修复，就像我们在前面的示例中看到的那样。为此，代码分析器使用由 Microsoft 创建的规则集或您定义的自定义规则集来满足特定需求。

# 创建自定义代码分析器

当您创建一个适合特定需求的代码分析器时，代码分析器的真正魔力就会显现出来。什么样的需求会被视为特定需求呢？嗯，任何特定于您自己业务需求的东西，而这些在现有的分析器中没有涵盖。不要误会我；对开发人员可用的现有分析器确实涵盖了许多良好的编程实践。只需在 GitHub 上搜索 C#代码分析器，就可以看到。

然而，有时您可能会遇到更适合您的工作流程或公司业务方式的情况。

例如，可以确保所有公共方法的注释包含的信息不仅仅是标准的`<summary></summary>`和参数信息（如果有）。您可能希望包含一个附加的标签，例如内部任务 ID（考虑 Jira）。另一个例子是确保创建的类符合特定的 XML 结构。您是否正在开发将仓库库存信息写入数据库的软件？您是否使用非库存零件？您如何在代码中验证非库存和库存零件？代码分析器可以在这里提供解决方案。

前面的示例可能是相当独特的，可能与您或您的需求无关，但这就是代码分析器的美妙之处。您可以创建它们以满足您的需求。让我们看一个非常简单的例子。假设您组织中的开发人员需要使用特定的代码库。这个代码库是一组经常使用的代码，而且维护得很好。它包含在开发人员创建新项目时使用的 Visual Studio 模板中。我们需要确保，如果开发人员创建特定类（用于采购订单或销售订单），它实现了特定接口。这些接口存在于模板中，但类不存在。这是因为应用程序并不总是使用销售或采购订单。该接口是为了使销售和采购订单能够接收，称为 IReceivable。

# 准备工作

执行以下步骤：

1.  创建一个新的 Visual Studio 项目，命名为`PurchaseOrderAnalyzer`。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_04_24.png)

1.  确保默认情况下创建以下项目。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_04_25-1.png)

# 如何做...

1.  展开`PurchaseOrderAnalyzer (Portable)`项目并打开`DiagnosticAnalyzer.cs`文件。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_04_26.png)

1.  如前所述，您将看到您的诊断分析器类。它应该读取`public class PurchaseOrderAnalyzerAnalyzer : DiagnosticAnalyzer`。将以下代码添加到此类的顶部，替换`DiagnosticId`、`Title`、`MessageFormat`、`Description`、`Category`和`Rule`变量的代码。请注意，我在类中添加了两个名为`ClassTypesToCheck`和`MandatoryInterfaces`的枚举器。我只希望此分析器在类名为`PurchaseOrder`或`SalesOrder`时才起作用。我还希望`IReceiptable`接口在`ClassTypesToCheck`枚举中定义的类中是强制性的。

```cs
        public const string DiagnosticId = "PurchaseOrderAnalyzer";

        public enum ClassTypesToCheck { PurchaseOrder, SalesOrder }
        public enum MandatoryInterfaces { IReceiptable }

        private static readonly LocalizableString Title = 
          "Interface Implementation Available"; 
        private static readonly LocalizableString 
          MessageFormat = "IReceiptable Interface not Implemented"; 
        private static readonly LocalizableString Description = 
          "You need to implement the IReceiptable interface"; 
        private const string Category = "Naming";

        private static DiagnosticDescriptor Rule = new 
          DiagnosticDescriptor(DiagnosticId, Title, MessageFormat, 
          Category, DiagnosticSeverity.Warning, 
          isEnabledByDefault: true, description: Description);

```

1.  确保`Initialize`方法包含以下代码：

```cs
        public override void Initialize(AnalysisContext context)
        {
          context.RegisterSymbolAction(AnalyzeSymbol, 
            SymbolKind.NamedType);
        }

```

1.  创建`AnalyzeSymbol`方法。您可以将此方法命名为任何您喜欢的名称。只需确保无论您如何命名此方法，它都与`Initialize`中的`RegisterSymbolAction()`方法中的方法名称匹配。

```cs
        private static void AnalyzeSymbol(SymbolAnalysisContext context)
        {

        }

```

1.  再添加一个名为`blnInterfaceImplemented`的布尔值，它将存储接口是否已实现的`true`或`false`。我们接下来要做的检查是忽略抽象类。实际上，您可能也想检查抽象类，但我想排除它以展示代码分析器的灵活性。

```cs
        bool blnInterfaceImplemented = false;
        if (!context.Symbol.IsAbstract)
        {

        }

```

1.  现在，您需要获取您正在检查的符号的名称。为此，请创建一个名为`namedTypeSymbol`的对象，您可以在该对象上调用`Name`方法来返回符号名称。在名为`PurchaseOrder`的类上，这应该返回`PurchaseOrder`作为名称。将`ClassTypesToCheck`枚举作为名为`classesToCheck`的`List<string>`对象返回。然后，对类名进行检查，看它是否包含在`classesToCheck`列表中。通过在`Equals`检查中添加`StringComparison.OrdinalIgnoreCase`来忽略大小写是很重要的。这将确保分析器将分析名为`purchaseorder`、`PURCHASEORDER`、`PurchaseOrder`、`Purchaseorder`或`purchaseOrder`的类。将代码添加到`if`条件中，不包括抽象类。

```cs
        var namedTypeSymbol = (INamedTypeSymbol)context.Symbol;
        List<string> classesToCheck = Enum.GetNames(
          typeof(ClassTypesToCheck)).ToList();

        if (classesToCheck.Any(s => s.Equals(
          namedTypeSymbol.Name, StringComparison.OrdinalIgnoreCase)))
        {

        }

```

类名的推荐大写风格是 PascalCase。PascalCase 包括大写标识符的第一个字母和每个后续连接的单词。如果标识符有三个或更多字符，则应用此规则。这意味着在类名中使用连接的单词 purchase 和 order 时必须使用 PascalCase。这将导致**P**urchase**O**rder。请参阅 MSDN 中的 Capitalization Styles 文章。

1.  在`if`条件中，要检查类名是否为`PurchaseOrder`或`SalesOrder`，请添加以下代码。在这里，我们将检查匹配的`PurchaseOrder`或`SalesOrder`类上定义的接口。我们通过调用`AllInterfaces()`方法来实现这一点，并检查它是否与`IReceiptable`枚举的`nameof`匹配。实际上，我们可能希望检查多个接口，但出于我们的目的，我们只检查`IReceiptable`接口的实现。如果我们发现接口在之前检查中匹配了类名上的实现，我们将设置`blnInterfaceImplemented = true;`（它当前初始化为`false`）。这意味着，如果接口没有匹配，那么我们将为省略`IReceiptable`接口产生诊断。这是通过创建和报告包含先前定义的`Rule`和类名位置的诊断来完成的。

```cs
        string interfaceName = nameof(
          MandatoryInterfaces.IReceiptable);

        if (namedTypeSymbol.AllInterfaces.Any(s => s.Name.Equals(
          interfaceName, StringComparison.OrdinalIgnoreCase)))
        {
          blnInterfaceImplemented = true;
        }

        if (!blnInterfaceImplemented)
        {
          // Produce a diagnostic.
          var diagnostic = Diagnostic.Create(Rule, 
            namedTypeSymbol.Locations[0], namedTypeSymbol.Name);
          context.ReportDiagnostic(diagnostic);
        }

```

1.  如果所有代码都添加到`AnalyzeSymbol()`方法中，该方法应如下所示：

```cs
        private static void AnalyzeSymbol(SymbolAnalysisContext context)
        {
          bool blnInterfaceImplemented = false;
          if (!context.Symbol.IsAbstract)
          {
            var namedTypeSymbol = (INamedTypeSymbol)context.Symbol;
            List<string> classesToCheck = Enum.GetNames(
              typeof(ClassTypesToCheck)).ToList();

            if (classesToCheck.Any(s => s.Equals(namedTypeSymbol.Name, 
              StringComparison.OrdinalIgnoreCase)))
            {
              string interfaceName = nameof(
                MandatoryInterfaces.IReceiptable);

              if (namedTypeSymbol.AllInterfaces.Any(s => s.Name.Equals(
                interfaceName, StringComparison.OrdinalIgnoreCase)))
              {
                blnInterfaceImplemented = true;
              }

              if (!blnInterfaceImplemented)
              {
                // Produce a diagnostic.
                var diagnostic = Diagnostic.Create(Rule, 
                  namedTypeSymbol.Locations[0], namedTypeSymbol.Name);
                context.ReportDiagnostic(diagnostic);
              }
            }
          }
        }

```

1.  现在，我们需要为代码分析器创建一个修复程序。如果我们发现类没有实现我们的接口，我们希望为开发人员提供一个快速修复的灯泡功能。打开名为`CodeFixProvider.cs`的文件。您会看到其中包含一个名为`public class PurchaseOrderAnalyzerCodeFixProvider : CodeFixProvider`的类。首先要做的是找到`title`字符串常量，并将其更改为更合适的标题。这是在 Visual Studio 中单击灯泡时显示的菜单弹出窗口。

```cs
        private const string title = "Implement IReceiptable";

```

1.  我已经将大部分代码修复代码保持不变，除了执行实际修复的代码。找到名为`RegisterCodeFixesAsync()`的方法。我将该方法重命名为`ImplementRequiredInterfaceAsync()`，以在`RegisterCodeFix()`方法中调用。代码应如下所示：

```cs
        public sealed override async Task RegisterCodeFixesAsync(
          CodeFixContext context)
        {
          var root = await context.Document.GetSyntaxRootAsync(
            context.CancellationToken).ConfigureAwait(false);

          var diagnostic = context.Diagnostics.First();
          var diagnosticSpan = diagnostic.Location.SourceSpan;

          // Find the type declaration identified by the diagnostic.
          var declaration = root.FindToken(diagnosticSpan.Start)
            .Parent.AncestorsAndSelf().OfType
            <TypeDeclarationSyntax>().First();

          // Register a code action that will invoke the fix.
          context.RegisterCodeFix(
            CodeAction.Create(
              title: title,
              createChangedSolution: c => 
              ImplementRequiredInterfaceAsync(context.Document, 
                declaration, c),
            equivalenceKey: title),
          diagnostic);
        }

```

1.  您会注意到，我已经重新使用了用于将符号大写的修复程序来实现接口。其余的代码保持不变。实际上，您很可能希望检查类上是否实现了其他接口，并保持这些实现。在这个演示中，我们只是假设正在创建一个名为`PurchaseOrder`或`SalesOrder`的新类，而没有现有的接口。

```cs
        private async Task<Solution> ImplementRequiredInterfaceAsync(
          Document document, TypeDeclarationSyntax typeDecl, 
          CancellationToken cancellationToken)
        {
          // Get the text of the PurchaseOrder class and return one 
             implementing the IPurchaseOrder interface
          var identifierToken = typeDecl.Identifier;

          var newName = $"{identifierToken.Text} : IReceiptable";

          // Get the symbol representing the type to be renamed.
          var semanticModel = await document.GetSemanticModelAsync(
            cancellationToken);
          var typeSymbol = semanticModel.GetDeclaredSymbol(
            typeDecl, cancellationToken);

          // Produce a new solution that has all references to 
             that type renamed, including the declaration.
          var originalSolution = document.Project.Solution;
          var optionSet = originalSolution.Workspace.Options;
          var newSolution = await Renamer.RenameSymbolAsync(
            document.Project.Solution, typeSymbol, newName, 
            optionSet, cancellationToken).ConfigureAwait(false);

          return newSolution;
        }

```

1.  确保`PurchaseOrderAnalyzer.Vsix`项目设置为启动项目，然后单击“调试”。将启动 Visual Studio 的新实例。在这个 Visual Studio 实例中创建一个新的控制台应用程序，并将其命名为`PurchaseOrderConsole`。向该项目添加一个名为`IReceiptable`的新接口，并添加以下代码。

```cs
        interface IReceiptable
        {
          void MarkAsReceipted(int orderNumber);
        }

```

1.  现在，向项目添加一个名为`PurchaseOrder`的新类，其中包含以下代码。

```cs
        public class PurchaseOrder 
        {

        }

```

1.  完成此操作后，如果为`IReceiptable`和`PurchaseOrder`添加了单独的文件，您的项目可能如下所示。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_04_27.png)

1.  查看`PurchaseOrder`类时，您会注意到类名`PurchaseOrder`下有一个波浪线。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_04_28.png)

1.  将鼠标悬停在波浪线上，您将看到灯泡显示通知您`IReceiptable`接口未实现。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_04_29.png)

1.  当您查看潜在的修复时，您将看到我们在`CodeFixProvider.cs`文件中更改的`title`在飞出菜单文本中显示为`private const string title = "Implement IReceiptable";`。然后建议的代码显示为实现正确的接口`IReceiptable`。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_04_30.png)

1.  单击此按钮会修改我们的`PurchaseOrder`类，生成以下代码：

```cs
        public class PurchaseOrder : IReceiptable 
        {

        }

```

1.  应用代码修复后，您会看到类名下的波浪线已经消失。正如预期的那样，Visual Studio 现在告诉我们需要通过在`IReceiptable`接口名称下划线标记`IReceiptable.MarkAsReceipted(int)`来实现接口成员。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_04_31.png)

1.  将鼠标悬停在`IReceiptable`接口名称上，您将看到代码修复的灯泡。这是标准的 Visual Studio 分析器在这里起作用。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_04_32.png)

1.  单击要应用的修复程序，实现`IReceiptable`成员和`PurchaseOrder`类在代码中正确定义。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_04_33.png)

# 它的工作原理...

本示例中的示例甚至没有开始涉及代码分析器的可能性。了解可能性的一个很好方法是查看 GitHub 上的一些代码分析器。查看代码并开始编写自己的代码分析器。与编程中的大多数概念一样，学习的唯一方法就是编写代码。互联网上有大量的信息可供使用。不过，建议在开始编写自己的代码分析器之前，先看看是否已经有一个分析器可以满足您的需求（或者接近满足您的需求）。

例如，如果您需要确保方法注释包含附加信息，请尝试查找一个已经执行类似操作的分析器。例如，如果您找到一个检查公共方法是否有注释的分析器，您可以轻松地修改此分析器以满足自己的需求。学习的最佳方法是实践，但每个人都需要一个起点。站在他人的肩膀上是学习新编程概念的一部分。

# 仅在组织内部部署您的代码分析器

代码分析器是一种检查和自动纠正代码的绝妙方法。然而，您创建的分析器有时可能不适合公开使用，因为它们可能包含专有信息。通过 NuGet，您可以创建私有存储库并与同事共享。例如，您可以使用公司服务器上的共享位置，并轻松管理 NuGet 包。

# 准备工作

确保您的组织中的所有开发人员都可以访问共享位置。这可以是您的网络管理员提供的任何共享文件访问位置。您可能希望将这些包的访问权限限制为开发人员。一个不错的解决方案是在 Azure 上创建一个存储账户来共享 NuGet 包。这是我在这里使用的方法，我使用了一个名为 Acme Corporation 的虚构公司。

我不会详细介绍如何在 Azure 上设置存储账户，但我会谈谈如何从本地机器访问它。

我鼓励你和你的组织考虑使用 Azure。我不会过多扩展使用 Azure 的好处，只是说它可以节省大量时间。如果我想测试特定应用程序的特定功能在特定操作系统上，几分钟内我就能启动一个虚拟机并通过远程桌面连接到它。它立即可以使用。

在 Azure 上创建存储账户后，你会在“访问密钥”选项卡上找到访问密钥。

1.  记下密钥和存储账户名称。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_04_35.png)

1.  我还创建了一个名为`packages`的文件服务。要到达这里，点击“概述”。然后，在“服务”标题下，点击“文件”。在文件服务窗口上，选择`packages`并查看文件共享的属性信息。

你的存储账户可能与本书中的示例不同，这取决于你的命名。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_04_36.png)

1.  记下属性中指定的 URL。使用该 URL，通过将路径中的`https://`部分更改为`\\`，并将任何后续的`/`更改为`\`，映射一个网络驱动器。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_04_37.png)

1.  将此路径添加到文件夹文本框，并确保已选中使用不同凭据进行连接。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_04_38.png)

使用存储账户名称作为用户名，使用其中一个密钥作为密码。现在你已经将一个网络驱动器映射到了你的 Azure 存储账户。

# 如何做...

1.  看一下我们创建的`PurchaseOrderAnalyzer`项目。你会看到有一个包含两个名为`install.ps1`和`uninstall.ps1`的 PowerShell 脚本的`tools`文件夹。在这里，你可以指定任何特定于安装的资源或卸载软件包时要执行的操作。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_04_34.png)

1.  打开`Diagnostic.nuspec`文件，你会注意到其中包含了关于你即将部署的 NuGet 程序包的信息。务必修改此文件，因为它包含了对开发人员使用你的 NuGet 程序包很重要的信息。

```cs
        <?xml version="1.0"?>
        <package >
          <metadata>
            <id>PurchaseOrderAnalyzer</id>
            <version>1.1.1.1</version>
            <title>Purchase Order Analyzer</title>
            <authors>Dirk Strauss</authors>
            <owners>Acme Corporation</owners>
            <licenseUrl>http://www.acmecorporation.com/poanalyzer/
             license</licenseUrl>
            <projectUrl>http://www.acmecorporation.com/poanalyzer
             </projectUrl>
            <requireLicenseAcceptance>true</requireLicenseAcceptance>
            <description>Validate the creation of Purchase Order Objects 
             withing Acme Corporation's development projects
            </description>
            <releaseNotes>Initial release of the Purchase Order 
             Analyzer.</releaseNotes>
            <copyright>Copyright</copyright>
            <tags>PurchaseOrderAnalyzer, analyzers</tags>
            <frameworkAssemblies>
              <frameworkAssembly assemblyName="System" 
               targetFramework="" />
            </frameworkAssemblies>
          </metadata>
          <!-- The convention for analyzers is to put language 
           agnostic dlls in analyzersportable50 and language 
           specific analyzers in either analyzersportable50cs or 
           analyzersportable50vb -->
          <files>
            <file src="img/*.dll" target="analyzersdotnetcs" 
             exclude="**Microsoft.CodeAnalysis.*;
             **System.Collections.Immutable.*;
             **System.Reflection.Metadata.*;
             **System.Composition.*" />
            <file src="img/tools*.ps1" target="tools" />
          </files>
        </package>

```

1.  继续构建你的代码分析器。你会看到在项目的`bin`文件夹中创建了一个名为`PurchaseOrderAnalyzer.1.1.1.1.nupkg`的文件。将该文件复制到你之前在 Azure 存储账户中创建的映射驱动器。

1.  在 Visual Studio 中，添加一个新的 WinForms 应用程序。你可以随意命名。现在可以将存储账户添加为 NuGet 位置。转到工具，NuGet 程序包管理器，然后单击“解决方案的 NuGet 程序包管理器...”。你会注意到，在当前设置为 nuget.org 的包源旁边，有一个小齿轮图标。点击它。

我为这个示例在一个单独的机器上创建了 Visual Studio WinForms 应用程序，但如果你没有单独的机器，可以尝试使用虚拟机进行测试。如果你无法访问 Azure，也可以使用 VirtualBox。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_04_39.png)

1.  在“选项”屏幕上，通过单击“可用包源”下方的绿色加号图标，可以添加一个额外的 NuGet 程序包源。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_04_40-1.png)

1.  在“选项”窗口底部，输入一个适当的位置名称，并输入 Azure 存储账户的路径。这是你在映射网络驱动器时输入的相同路径。在点击“确定”之前，点击“更新”按钮。然后点击“确定”按钮。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_04_41.png)

1.  现在可以将包源更改为设置为你映射到的 Azure 存储账户位置。这样做并单击 NuGet 程序包管理器的“浏览”选项卡将显示此文件共享上的所有程序包。右侧“选项”部分中的信息是你在`Diagnostic.nuspec`文件中定义的信息。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_04_42.png)

1.  现在可以继续安装代码分析器 NuGet 包。安装完成后，代码分析器将在项目的`References`下的`Analyzers`节点下可见。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_04_43.png)

1.  代码分析器也完全按预期工作。创建一个名为`PurchaseOrder`的类，看看分析器是如何运作的。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_04_44.png)

# 它是如何工作的...

NuGet 包是将代码部署到大众或少数开发人员的最简单方式。它可以轻松实现代码和模板的共享，因此使用 NuGet 来部署代码分析器是非常合理的。使用 NuGet 设置一个私有存储库来在组织内共享代码非常简单。


# 第五章：正则表达式

**正则表达式**（**regex**）对许多开发人员来说是一种神秘。我们承认，我们经常使用它们，以至于需要更深入地了解它们的工作原理。另一方面，互联网上有许多经过验证的正则表达式模式，只需重复使用已经存在的模式比尝试自己创建一个更容易。正则表达式的主题远远超出了本书中的单一章节所能解释的范围。

因此，在本章中，我们只是介绍了一些正则表达式的概念。要更深入地了解正则表达式，需要进一步学习。然而，为了本书的目的，我们将更仔细地看看如何创建正则表达式以及如何将其应用于一些常见的编程问题。在本章中，我们将涵盖以下内容：

+   开始使用正则表达式-匹配有效日期

+   清理输入

+   动态正则表达式匹配

# 介绍

正则表达式是通过使用特殊字符描述字符串的模式，这些特殊字符表示需要匹配的特定文本。正则表达式的使用在编程中并不是一个新概念。为了使正则表达式工作，它需要使用一个执行所有繁重工作的正则表达式引擎。

在.NET Framework 中，微软提供了正则表达式的使用。要使用正则表达式，您需要将`System.Text.RegularExpressions`程序集导入到您的项目中。这将允许编译器使用您的正则表达式模式并将其应用于您需要匹配的特定文本。

其次，正则表达式有一组特殊含义的元字符，这些字符是`[ ]`, `{ }`, `( )`, `*`, `+`, , `?`, `|`, `$`, `.`, 和 `^`。

例如，使用花括号`{ }`使开发人员能够指定特定字符集需要出现的次数。另一方面，使用方括号则确切地定义了需要匹配的内容。

例如，如果我们指定了`[abc]`，那么模式将寻找小写的 A、B 和 C。因此，正则表达式还允许您定义一个范围，例如`[a-c]`，这与`[abc]`模式的解释方式完全相同。

正则表达式还允许您使用`^`字符定义要排除的字符。因此，键入`[^a-c]`将找到小写的 D 到 Z，因为模式告诉正则表达式引擎排除小写的 A、B 和 C。

正则表达式还定义了`d`和`D`作为`[0-9]`和`[⁰-9]`的一种快捷方式。因此，`d`匹配所有数字值，而`D`匹配所有非数字值。另一个快捷方式是`w`和`W`，它们匹配从小写 A 到 Z 的任何字符，不考虑大小写，从 0 到 9 的所有数字值，以及下划线字符。因此，`w`是`[a-zA-Z0-9_]`，而`W`是`[^a-zA-Z0-9_]`。

正则表达式的基础相当容易理解，但您还可以做很多其他事情。

# 开始使用正则表达式-匹配有效日期

如果您还没有这样做，请创建一个新的控制台应用程序，并在项目中添加一个名为`RegExDemo`的类。此时您的代码应该看起来像这样：

```cs
class Program
{
   static void Main(string[] args)
   {
   }
}

public class RegExDemo
{

}

```

# 准备工作

为了本书的目的，我们使用控制台应用程序来说明正则表达式的使用。实际上，您可能不会将这种逻辑混在生产代码之间，因为这将导致代码被重写。添加类似正则表达式的最佳位置是在扩展方法中的帮助类中。

# 如何做...

1.  在控制台应用程序中，添加以下`using`语句，以便我们可以在.NET 中使用正则表达式程序集：

```cs
        using System.Text.RegularExpressions;

```

1.  我们将创建一个正则表达式来验证 yyyy-mm-dd、yyyy/mm/dd 或 yyyy.mm.dd 的日期模式。一开始，正则表达式看起来可能令人生畏，但请耐心等待。当您完成代码并运行应用程序时，我们将解析这个正则表达式。希望表达式逻辑会变得清晰。

1.  在`RegExDemo`类中，创建一个名为`ValidDate()`的新方法，该方法以字符串作为参数。这个字符串将是我们想要验证的日期模式：

```cs
        public void ValidDate(string stringToMatch) 
        { 

        }

```

1.  将以下正则表达式模式添加到方法中的变量中：

```cs
        string pattern = $@"^(19|20)dd-./
                         -./$";

```

1.  最后，添加正则表达式以匹配提供的字符串参数：

```cs
        if (Regex.IsMatch(stringToMatch, pattern)) 
            Console.WriteLine($"The string {stringToMatch} 
                              contains a valid date."); 
        else 
            Console.WriteLine($"The string {stringToMatch} DOES 
                              NOT contain a valid date.");

```

1.  当您完成这些操作后，您的方法应该如下所示：

```cs
        public void ValidDate(string stringToMatch) 
        { 
          string pattern = $@"^(19|20)dd-./
                           -./$"; 

          if (Regex.IsMatch(stringToMatch, pattern)) 
              Console.WriteLine($"The string {stringToMatch} contains
                                a valid date."); 
          else 
              Console.WriteLine($"The string {stringToMatch} DOES 
              NOT contain a valid date.");             
        }

```

1.  回到您的控制台应用程序，添加以下代码并通过单击“开始”调试您的应用程序：

```cs
        RegExDemo oRecipe = new RegExDemo(); 
        oRecipe.ValidDate("1912-12-31"); 
        oRecipe.ValidDate("2018-01-01"); 
        oRecipe.ValidDate("1800-01-21"); 
        oRecipe.ValidDate($"{DateTime.Now.Year}
                          .{DateTime.Now.Month}.{DateTime.Now.Day}"); 
        oRecipe.ValidDate("2016-21-12");  
        Console.Read();

```

您会注意到，如果您添加了`using static System.Console;`命名空间，那么您只需要调用`Read()`而不是`Console.Read()`。这种新功能，您可以导入静态命名空间，是在 C# 6.0 中添加的。

1.  日期字符串被传递给正则表达式，并且模式与参数中的日期字符串匹配。输出显示在控制台应用程序中：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/image_05_008.png)

1.  仔细观察输出，您会注意到有一个错误。我们正在验证格式为 yyyy-mm-dd、yyyy/mm/dd 和 yyyy.mm.dd 的日期字符串。如果我们使用这个逻辑，我们的正则表达式错误地将一个有效的日期标记为无效。这是日期`2016.4.10`，它是 2016 年 4 月 10 日，实际上是有效的。

我们很快会解释日期`1800-01-21`为什么无效。

1.  返回到您的`ValidDate()`方法，并将正则表达式更改为如下所示：

```cs
        string pattern = $@"^(19|20)dd-./
                         -./$";

```

1.  再次运行控制台应用程序并查看输出：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/image_05_009.png)

这次正则表达式对所有给定的日期字符串都起作用了。但我们到底做了什么？它是如何工作的。

# 它是如何工作的...

让我们仔细看看前面代码示例中使用的两个表达式。将它们与彼此进行比较，您可以看到我们在黄色中所做的更改：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/image_05_010.png)

在我们了解这个变化意味着什么之前，让我们分解表达式并查看各个组件。我们的正则表达式基本上是在说，我们必须匹配所有以 19 或 20 开头并具有以下分隔符的字符串日期：

+   破折号（-）

+   小数点（.）

+   斜杠（/）

为了更好地理解表达式，我们需要了解表达式<有效年份><有效分隔符><有效月份><有效分隔符><有效日期>的以下格式。

我们还需要能够告诉正则表达式引擎考虑一个*或*另一个模式。单词*或*由`|`元字符表示。为了使正则表达式引擎在不分割整个表达式的情况下考虑*或*这个词，我们将其包装在括号`()`中。

以下是正则表达式中使用的符号：

| 条件性或描述 |
| --- |
| | 这表示*或*元字符。 |
| 年份部分描述 |
| (19 | 20)只允许 19 或 20 |
| dd 匹配 0 到 9 之间的两个个位数。要匹配 0 到 9 之间的一个数字，您将使用 d。 |
| 有效分隔符字符集描述 |
| [-./]匹配字符集中的任何一个字符。这些是我们的有效分隔符。要匹配空格日期分隔符，您可以将其更改为[- ./]，在字符集中的任何位置添加一个空格。我们在破折号和小数点之间添加了空格。 |
| 月份和日期的有效数字描述 |
| 0[1-9]匹配以零开头，后跟 1 到 9 之间的任意数字。这将匹配 01、02、03、04、05、06、07、08 和 09。 |
| 1[0-2]匹配以 1 开头，后跟 0 到 2 之间的任意数字。这将匹配 10、11 或 12。 |
| [1-9]匹配 1 到 9 之间的任意数字。 |
| [12][0-9]匹配以 1 或 2 开头，后跟 0 到 9 之间的任意数字。这将匹配所有 10 到 29 之间的数字字符串。 |
| 3[01]匹配以 3 开头，后跟 0 或 1。这将匹配 30 或 31。 |
| 字符串的开始和结束描述 |
| ^告诉正则表达式引擎从给定字符串的开头开始匹配。 |
| `$` | 告诉正则表达式引擎停止匹配给定字符串的末尾。 |

我们创建的第一个正则表达式解释如下：

+   `^`: 从字符串开头开始匹配

+   `(19|20)`: 检查字符串是否以 19 或 20 开头

+   `dd`: 检查后，跟着两个 0 到 9 之间的单个数字

+   `[-./]`: 年份部分结束，后跟日期分隔符

+   `(0[1-9]|1[0-2])`: 通过查找以 0 开头的数字，后跟 1 到 9 之间的数字，*或*以 1 开头的数字，后跟 0 到 2 之间的任意数字

+   `[-./]`: 月份逻辑结束，后跟日期分隔符

+   `(0[1-9]|[12][0-9]|3[01])`: 然后，通过查找以 0 开头的数字，后跟 1 到 9 之间的数字，或者以 1 或 2 开头的数字，后跟 0 到 9 之间的任意数字，或者匹配 3 的数字，后跟 0 到 1 之间的任意数字，找到日期逻辑

+   `$`: 这样做直到字符串的末尾

我们的第一个正则表达式是不正确的，因为我们的月份逻辑是错误的。我们的月份逻辑规定，通过查找以 0 开头的数字，后跟 1 到 9 之间的任意数字，或者以 1 开头的数字，后跟 0 到 2 之间的任意数字`(0[1-9]|1[0-2])`。

然后会找到 01、02、03、04、05、06、07、08、09 或 10、11、12。它没有匹配的日期是`2016.4.10`（日期分隔符在这里没有区别）。这是因为我们的月份是单个数字，而我们正在寻找以零开头的月份。为了解决这个问题，我们必须修改月份逻辑的表达式，以包括只有 1 到 9 之间的单个数字。我们通过在表达式末尾添加`[1-9]`来实现这一点。

修改后的正则表达式如下：

+   `^`: 从字符串开头开始匹配

+   `(19|20)`: 检查字符串是否以 19 或 20 开头

+   `dd`: 检查后，跟着两个 0 到 9 之间的单个数字

+   `[-./]`: 年份部分结束，后跟日期分隔符

+   `(0[1-9]|1[0-2])`: 通过查找以 0 开头的数字，后跟 1 到 9 之间的任意数字，或者以 1 开头的数字，后跟 0 到 2 之间的任意数字或 1 到 9 之间的任意单个数字，找到月份逻辑

+   `[-./]`: 月份逻辑结束，后跟日期分隔符

+   `(0[1-9]|[12][0-9]|3[01])`: 然后，通过查找以 0 开头的数字，后跟 1 到 9 之间的数字，或者以 1 或 2 开头的数字，后跟 0 到 9 之间的任意数字，或者匹配 3 的数字，后跟 0 到 1 之间的任意数字，找到日期逻辑

+   `$`: 这样做直到字符串的末尾

这是一个基本的正则表达式，我们说基本是因为我们可以做很多事情来使表达式更好。我们可以包含逻辑来考虑替代日期格式，如 mm-dd-yyyy 或 dd-mm-yyyy。我们可以添加逻辑来检查二月，并验证它是否只包含 28 天，除非是闰年，那么我们需要允许二月的第二十九天。此外，我们还可以扩展正则表达式，以检查一月、三月、五月、七月、八月、十月和十二月是否有 31 天，而四月、六月、九月和十一月只有 30 天。

# 清理输入

有时，您需要清理输入。这可能是为了防止 SQL 注入或确保输入的 URL 有效。在本教程中，我们将查看如何用星号替换字符串中的不良词汇。我们确信有更优雅和代码高效的方法来使用正则表达式编写清理逻辑（特别是当我们有一个大量的黑名单词汇集合时），但我们想在这里阐明一个概念。

# 准备工作

确保您已将正确的程序集添加到您的类中。在您的代码文件顶部，如果尚未这样做，请添加以下行代码：

```cs
using System.Text.RegularExpressions;

```

# 如何做...

1.  在您的`RegExDemo`类中创建一个名为`SanitizeInput()`的新方法，并让它接受一个字符串参数：

```cs
        public string SanitizeInput(string input) 
        { 

        }

```

1.  在方法中添加一个`List<string>`类型的列表，其中包含我们要从输入中删除的不良词汇：

```cs
        List<string> lstBad = new List<string>(new string[]
        {  "BadWord1", "BadWord2", "BadWord3" });

```

实际上，您可能会利用数据库调用从数据库表中读取黑名单单词。您通常不会像这样硬编码它们在一个列表中。

1.  开始构造我们将用来查找黑名单单词的正则表达式。您使用`|`（OR）元字符将单词连接起来，以便正则表达式将匹配任何一个单词。当列表完成后，您可以在正则表达式的两侧附加`b`表达式。这表示一个词边界，因此只匹配整个单词：

```cs
        string pattern = ""; 
        foreach (string badWord in lstBad) 
        pattern += pattern.Length == 0 ? $"{badWord}" 
          :  $"|{badWord}"; 

        pattern = $@"b({pattern})b";

```

1.  最后，我们将添加`Regex.Replace()`方法，该方法接受输入并查找模式中定义的单词的出现，同时忽略大小写，并用`*****`替换不良单词：

```cs
        return Regex.Replace(input, pattern, "*****", 
                             RegexOptions.IgnoreCase);

```

1.  完成后，您的`SanitizeInput()`方法将如下所示：

```cs
        public string SanitizeInput(string input) 
        { 
          List<string> lstBad = new List<string>(new string[]
          { "BadWord1", "BadWord2", "BadWord3" }); 
          string pattern = ""; 
          foreach (string badWord in lstBad) 
          pattern += pattern.Length == 0 ? $"{badWord}" : $"|{badWord}"; 

          pattern = $@"b({pattern})b"; 

          return Regex.Replace(input, pattern, "*****", 
                               RegexOptions.IgnoreCase);             
        }

```

1.  在控制台应用程序中，添加以下代码调用`SanitizeInput()`方法并运行您的应用程序（如果您已经在上一个示例中实例化了`RegExDemo`的实例，则不需要再次实例化）：

```cs
        string textToSanitize = "This is a string that contains a  
          badword1, another Badword2 and a third badWord3"; 
        RegExDemo oRecipe = new RegExDemo(); 
        textToSanitize = oRecipe.SanitizeInput(textToSanitize); 
        WriteLine(textToSanitize); 
        Read();

```

1.  运行应用程序时，您将在控制台窗口中看到以下内容：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/image_05_011.png)

让我们更仔细地看一下生成的正则表达式。

# 工作原理...

让我们逐步了解代码的执行过程。我们需要得到一个看起来像这样的正则表达式：`b(wordToMatch1|wordToMatch2|wordToMatch3)b`。

这基本上是说“找到任何单词，只有被`b`标记的整个单词”。当我们查看我们创建的列表时，我们会看到我们想要从输入字符串中删除的单词：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/image_05_012.png)

然后我们创建了一个简单的循环，使用 OR 元字符创建要匹配的单词列表。在`foreach`循环完成后，我们得到了一个`BadWord1|BadWord2|BadWord3`模式。然而，这仍然不是一个有效的正则表达式：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/image_05_013.png)

为了完成生成有效的正则表达式的模式，我们需要在模式的两侧添加`b`表达式，告诉正则表达式引擎只匹配整个单词。正如您所看到的，我们正在使用字符串插值。

然而，这里我们需要非常小心。首先编写代码，完成模式而不使用`@`符号，如下所示：

```cs
pattern = $"b({pattern})b";

```

如果运行控制台应用程序，您会看到不良单词没有被匹配和过滤掉。这是因为我们没有转义`b`之前的字符。因此，编译器解释这行代码：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/image_05_014.png)

生成的表达式`[](BadWord1| BadWord2| BadWord3)[]`不是一个有效的表达式，因此不会对输入字符串进行消毒。

要纠正这个问题，我们需要在字符串前面添加`@`符号，告诉编译器将字符串视为文字。这意味着任何转义序列都将被忽略。正确格式化的代码行如下：

```cs
pattern = $@"b({pattern})b";

```

一旦您这样做，模式的字符串将被编译器直接解释，正确的正则表达式模式将被生成：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/image_05_015.png)

有了我们正确的正则表达式模式，我们调用了`Regex.Replace()`方法。它接受要检查的输入，要匹配的正则表达式，要替换匹配单词的文本，并且可选地允许忽略大小写。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/image_05_016.png)

当字符串返回到控制台应用程序中的调用代码时，字符串将被正确消毒：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/image_05_017.png)

正则表达式可能会变得非常复杂，并且可以用于执行多种任务，以格式化和验证输入和其他文本。

# 动态正则表达式匹配

动态正则表达式匹配到底是什么意思？嗯，这不是一个官方术语，但这是一个我们用来解释在运行时使用变量生成特定表达式的正则表达式的术语。假设您正在开发一个需要为 ACME 公司实现文档版本管理的文档管理系统。为了做到这一点，系统验证文档是否具有有效的文件名。

一个业务规则规定，上传在特定日期的任何文件的文件名必须以`acm`（ACME）和今天的日期以 yyyy-mm-dd 格式为前缀。它们只能是文本文件、Word 文档（仅限`.docx`）和 Excel 文档（仅限`.xlsx`）。任何不符合此文件格式的文档都将由另一种方法处理，该方法负责存档和无效文档的处理。

您的方法需要执行的唯一任务是将新文档处理为版本一文档。

在生产系统中，可能需要进一步的逻辑来确定是否在同一天之前已经上传了相同的文档。然而，这超出了本章的范围。我们只是试图搭建场景。

# 准备工作

确保您已将正确的程序集添加到您的类中。如果还没有这样做，请在代码文件的顶部添加以下代码行：

```cs
using System.Text.RegularExpressions;

```

# 如何做...

1.  一个非常好的方法是使用扩展方法。这样，您可以直接在文件名变量上调用扩展方法并进行验证。在控制台应用程序中，首先添加一个名为`CustomRegexHelper`的新类，带有`public static`修饰符：

```cs
        public static class CustomRegexHelper 
        { 

        }

```

1.  将通常的扩展方法代码添加到`CustomRegexHelper`类中，并调用`ValidAcmeCompanyFilename`方法：

```cs
        public static bool ValidAcmeCompanyFilename(this string  value) 
        { 

        }

```

1.  在您的`ValidAcmeCompanyFilename`方法中，添加以下正则表达式。我们将在本食谱的*工作原理...*部分解释这个正则表达式的构成：

```cs
        return Regex.IsMatch(value,  $@"^acm[_]{DateTime.Now.Year}[_]
          ({DateTime.Now.Month}|0[{DateTime.Now.Month}])[_]
          ({DateTime.Now.Day}|0[{DateTime.Now.Day}])(.txt|.docx|.xlsx)$");

```

1.  完成后，您的扩展方法应该如下所示：

```cs
        public static class CustomRegexHelper 
        { 
          public static bool ValidAcmeCompanyFilename(this String value) 
          { 
            return Regex.IsMatch(value, $@"^acm[_]{DateTime.Now.Year}[_]
              ({DateTime.Now.Month}|0[{DateTime.Now.Month}])[_]
              ({DateTime.Now.Day}|0[{DateTime.Now.Day}])(.txt|.docx|.xlsx)$"); 
          } 
        }

```

1.  回到控制台应用程序，在`void`返回类型的方法中创建名为`DemoExtensionMethod()`的方法：

```cs
        public static void DemoExtensionMethod() 
        { 

        }

```

1.  添加一些输出文本，显示当前日期和有效的文件名类型：

```cs
        Console.WriteLine($"Today's date is: {DateTime.Now.Year}-
                          {DateTime.Now.Month}-{DateTime.Now.Day}");
        Console.WriteLine($"The file must match:  acm_{DateTime.Now.Year}
          _{DateTime.Now.Month}_{DateTime.Now.  Day}.txt including 
          leading month and day zeros");
        Console.WriteLine($"The file must match:  acm_{DateTime.Now.Year}
          _{DateTime.Now.Month}_{DateTime.Now.  Day}.docx including 
          leading month and day zeros");
        Console.WriteLine($"The file must match:  acm_{DateTime.Now.Year}
          _{DateTime.Now.Month}_{DateTime.Now.  Day}.xlsx including 
          leading month and day zeros");

```

1.  然后，添加文件名检查代码：

```cs
        string filename = "acm_2016_04_10.txt"; 
        if (filename.ValidAcmeCompanyFilename()) 
          Console.WriteLine($"{filename} is a valid file name"); 
        else 
          Console.WriteLine($"{filename} is not a valid file name"); 

        filename = "acm-2016_04_10.txt"; 
        if (filename.ValidAcmeCompanyFilename()) 
          Console.WriteLine($"{filename} is a valid file name"); 
        else 
          Console.WriteLine($"{filename} is not a valid file name");

```

1.  您会注意到`if`语句包含对包含文件名的变量的扩展方法的调用：

```cs
        filename.ValidAcmeCompanyFilename()

```

1.  如果您已完成此操作，您的方法应该如下所示：

```cs
        public static void DemoExtensionMethod() 
        { 
          Console.WriteLine($"Today's date is: {DateTime.Now.Year}-
          {DateTime.Now.Month}-{DateTime.Now.Day}");    
          Console.WriteLine($"The file must match: acm_{DateTime.Now.Year}
            _{DateTime.Now.Month}_{DateTime.Now.Day}.txt including leading 
            month and day zeros");    
          Console.WriteLine($"The file must match: acm_{DateTime.Now.Year}
            _{DateTime.Now.Month}_{DateTime.Now.Day}.docx including leading
            month and day zeros");    
          Console.WriteLine($"The file must match: acm_{DateTime.Now.Year}
            _{DateTime.Now.Month}_{DateTime.Now.Day}.xlsx including leading
            month and day zeros"); 

          string filename = "acm_2016_04_10.txt"; 
          if (filename.ValidAcmeCompanyFilename()) 
            Console.WriteLine($"{filename} is a valid file name"); 
          else 
            Console.WriteLine($"{filename} is not a valid file name"); 

          filename = "acm-2016_04_10.txt"; 
          if (filename.ValidAcmeCompanyFilename()) 
            Console.WriteLine($"{filename} is a valid file name"); 
          else 
            Console.WriteLine($"{filename} is not a valid file name"); 
        }

```

1.  返回到控制台应用程序，添加以下代码，简单地调用`void`方法。这只是为了模拟之前讨论的版本方法：

```cs
        DemoExtensionMethod();

```

1.  完成后，运行您的控制台应用程序：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/image_05_018.png)

# 工作原理...

让我们更仔细地看一下生成的正则表达式。我们正在看的代码行是扩展方法中的`return`语句：

```cs
return Regex.IsMatch(value,  $@"^acm[_]{DateTime.Now.Year}__(.txt|.docx|.xlsx)$");

```

为了理解发生了什么，我们需要将这个表达式分解成不同的组件：

| **条件 OR** | **描述** |
| --- | --- |
| `&#124;` | 这表示*OR*元字符。 |
| **文件前缀和分隔符** | **描述** |
| `acm` | 文件名必须以文本`acm`开头。 |
| `[_]` | 文件名中日期组件和前缀之间唯一有效的分隔符是下划线。 |
| **日期部分** | **描述** |
| `{DateTime.Now.Year}` | 文件名的日期部分的插值年份。 |
| `{DateTime.Now.Month}` | 文件名的日期部分的插值月份。 |
| `0[{DateTime.Now.Month}]` | 文件名的日期部分的插值月份，带有前导零。 |
| `{DateTime.Now.Day}` | 文件名的日期部分的插值天数。 |
| `0[{DateTime.Now.Day}]` | 文件名的日期部分的插值天数，带有前导零。 |
| **有效文件格式** | **描述** |
| `(.txt&#124;.docx&#124;.xlsx)` | 匹配这些文件扩展名中的任何一个，用于文本文档、Word 文档或 Excel 文档。 |
| **字符串的开始和结束** | **描述** |
| `^` | 告诉正则表达式引擎从给定字符串的开头开始匹配 |
| `$` | 告诉正则表达式引擎停在给定字符串的末尾进行匹配 |

以这种方式创建正则表达式允许我们始终使其保持最新。由于我们必须始终将当前日期与正在验证的文件进行匹配，这就产生了一个独特的挑战，可以很容易地通过使用字符串插值、`DateTime`和正则表达式的*OR*语句来克服。

浏览一些更有用的正则表达式，你会发现这一章甚至还没有开始探讨可以实现的内容。还有很多东西可以探索和学习。互联网上有许多资源，还有一些免费（一些在线）和商业工具可以帮助你创建正则表达式。
