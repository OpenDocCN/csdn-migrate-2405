# Unreal 游戏开发项目（二）

> 原文：[`annas-archive.org/md5/697adf25bb6fdefd7e5915903f33de14`](https://annas-archive.org/md5/697adf25bb6fdefd7e5915903f33de14)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：线性跟踪

概述

这一章将是一个名为躲避球的新游戏项目的开始，我们将从头开始创建一个基于碰撞概念的游戏。在本章中，您将修改第三人称模板项目，使其具有俯视视角。然后，您将介绍线性跟踪，这是游戏开发中的一个关键概念，并了解它们的潜力和用例。

在本章结束时，您将能够使用 UE4 内置的线性跟踪功能（在其他游戏开发工具中也称为射线投射或光线跟踪），通过执行不同类型的线性跟踪；创建自己的跟踪通道；并修改物体对每个跟踪通道的响应。

# 介绍

在之前的章节中，我们学习了如何重现虚幻引擎团队提供给我们的第三人称模板项目，以了解 UE4 工作流程和框架的一些基本概念。

在本章中，您将开始从头开始创建另一个游戏。在这个游戏中，玩家将以俯视的角度控制一个角色（*类似于《合金装备》1、2 和 3 等游戏*）。俯视视角意味着玩家控制一个角色，就好像从上方看下去一样，通常摄像机旋转是固定的（摄像机不会旋转）。在我们的游戏中，玩家角色必须从 A 点到 B 点，而不被敌人在整个关卡中投掷的躲避球击中。这个游戏的关卡将是迷宫般的，玩家将有多条路径可供选择，所有这些路径都将有敌人试图向玩家投掷躲避球。

本章我们将要涉及的具体主题包括线性跟踪（单一和多重）、扫描跟踪、跟踪通道和跟踪响应。在第一节中，我们将开始了解在视频游戏世界中*碰撞*是什么。

# 碰撞

碰撞基本上是两个物体相互接触的点（例如，两个物体碰撞，物体撞击角色，角色走进墙壁等）。大多数游戏开发工具都有自己的一套功能，允许碰撞和物理存在于游戏中。这一套功能被称为**物理引擎**，它负责与碰撞相关的一切。它负责执行线性跟踪，检查两个物体是否重叠，阻止彼此的移动，从墙壁上弹开等等。当我们要求游戏执行或通知我们这些碰撞事件时，游戏实际上是在要求物理引擎执行它，然后向我们展示这些碰撞事件的结果。

在您将要构建的`躲避球`游戏中，需要考虑碰撞的例子包括检查敌人是否能看到玩家（这将通过线性跟踪来实现，在本章中介绍），模拟物理学上的一个对象，它将表现得就像一个躲避球一样，检查是否有任何东西阻挡玩家角色的移动，等等。

碰撞是大多数游戏中最重要的方面之一，因此了解它对于开始游戏开发至关重要。

在我们开始构建基于碰撞的功能之前，我们首先需要设置我们的新`躲避球`项目，以支持我们将要实现的游戏机制。这个过程从下一节描述的步骤开始：*项目设置*。

# 项目设置

让我们通过创建我们的虚幻引擎项目开始这一章节：

1.  `启动`UE4。选择`游戏`项目类别，然后按`下一步`。

1.  选择`第三人称模板`，然后按`下一步`。

1.  确保将第一个选项设置为`C++`而不是`Blueprint`。

1.  根据您的喜好选择项目的位置，并将项目命名为`躲避球`，然后按`创建项目`。

项目生成完成后，您应该在屏幕上看到以下内容：

![图 5.1：加载的躲避球项目](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_05_01.jpg)

图 5.1：加载的躲避球项目

1.  代码生成并打开项目后，关闭 UE4 编辑器，并在 Visual Studio 中打开生成的第三人角色类`DodgeballCharacter`的文件，如下图所示：

![图 5.2：在 Visual Studio 中生成的文件](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_05_02.jpg)

图 5.2：在 Visual Studio 中生成的文件

如前所述，您的项目将具有俯视角。鉴于我们从第三人模板开始此项目，我们需要在将其转换为俯视游戏之前进行一些更改。这将主要涉及更改现有角色类中的一些代码行。

## 练习 5.01：将躲避球角色转换为俯视角

在这个练习中，您将对生成的`DodgeballCharacter`类进行必要的更改。请记住，它目前具有第三人称视角，其中角色的旋转由玩家的输入（即鼠标或右摇杆）决定。

在这个练习中，您将把它改为俯视角，不管玩家的输入如何，相机始终从上方跟随角色。

以下步骤将帮助您完成此练习：

1.  前往`DodgeballCharacter`类的构造函数，并根据以下步骤更新`CameraBoom`的属性。

1.  将`CameraBoom`的属性`TargetArmLength`更改为`900.0f`，以在相机和玩家之间增加一些距离：

```cpp
// The camera follows at this distance behind the character
CameraBoom->TargetArmLength = 900.0f;
```

1.  接下来，添加一行代码，使用`SetRelativeRotation`函数将相对俯仰设置为`-70`º，以便相机向下看玩家。`FRotator`构造函数的参数分别是*俯仰*、*偏航*和*翻滚*：

```cpp
//The camera looks down at the player
CameraBoom->SetRelativeRotation(FRotator(-70.f, 0.f, 0.f));
```

1.  将`bUsePawnControlRotation`更改为`false`，以便相机的旋转不受玩家的移动输入影响：

```cpp
// Don't rotate the arm based on the controller
CameraBoom->bUsePawnControlRotation = false;
```

1.  添加一行代码，将`bInheritPitch`、`bInheritYaw`和`bInheritRoll`设置为`false`，以便相机的旋转不受角色方向的影响：

```cpp
// Ignore pawn's pitch, yaw and roll
CameraBoom->bInheritPitch = false;
CameraBoom->bInheritYaw = false;
CameraBoom->bInheritRoll = false;
```

在我们进行了这些修改之后，我们将删除角色跳跃的能力（我们不希望玩家那么容易就躲开躲避球），以及根据玩家的旋转输入旋转相机的能力。

1.  转到`DodgeballCharacter`源文件中的`SetupPlayerInputComponent`函数，并删除以下代码行以删除跳跃的能力：

```cpp
// REMOVE THESE LINES
PlayerInputComponent->BindAction("Jump", IE_Pressed, this,   &ACharacter::Jump);
PlayerInputComponent->BindAction("Jump", IE_Released, this,   Acharacter::StopJumping);
```

1.  接下来，添加以下行以删除玩家的旋转输入：

```cpp
// REMOVE THESE LINES
PlayerInputComponent->BindAxis("Turn", this,   &APawn::AddControllerYawInput);
PlayerInputComponent->BindAxis("TurnRate", this,   &ADodgeballCharacter::TurnAtRate);
PlayerInputComponent->BindAxis("LookUp", this,   &APawn::AddControllerPitchInput);
PlayerInputComponent->BindAxis("LookUpRate", this,   &ADodgeballCharacter::LookUpAtRate);
```

这一步是可选的，但为了保持代码整洁，您应该删除`TurnAtRate`和`LookUpAtRate`函数的声明和实现。

1.  最后，在您进行了这些更改之后，从 Visual Studio 运行您的项目。

1.  编辑器加载完成后，播放关卡。相机的视角应该是这样的，并且不应根据玩家的输入或角色的旋转而旋转：![图 5.3：将相机旋转锁定到俯视角](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_05_03.jpg)

图 5.3：将相机旋转锁定到俯视角

这就结束了本章的第一个练习，也是您新项目`Dodgeball`的第一步。

接下来，您将创建`EnemyCharacter`类。这个角色将是敌人，在玩家在视野中时向玩家投掷躲避球。但在这里出现的问题是：敌人如何知道它是否能看到玩家角色呢？

这将通过**线追踪**（也称为**射线投射**或**光线追踪**）的能力来实现，您将在下一节中了解到。

# 线追踪

任何游戏开发工具的最重要功能之一是执行线追踪的能力。这些功能是通过工具使用的物理引擎提供的。

线性跟踪是一种询问游戏是否有任何东西站在游戏世界中两点之间的方式。游戏将在你指定的两点之间*发射一条射线*，并返回被击中的对象（如果有的话），它们被击中的位置，以及角度等等。

在下图中，您可以看到线性跟踪的表示，我们假设对象`1`被忽略，而对象`2`被检测到，这是由于它们的跟踪通道属性（在接下来的段落中进一步解释）：

![图 5.4：从点 A 到点 B 执行的线性跟踪](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_05_04.jpg)

图 5.4：从点 A 到点 B 执行的线性跟踪

在*图 5.4*中：

+   虚线代表线性跟踪撞击物体前的情况。

+   箭头代表线性跟踪的方向。

+   虚线代表线性跟踪撞击物体后的情况。

+   条纹圆圈代表线性跟踪的撞击点。

+   大方块代表线性跟踪路径上的两个对象（对象`1`和`2`）。

我们注意到只有对象`2`被线性跟踪击中，而对象`1`没有，尽管它也在线性跟踪的路径上。这是由于对对象`1`的跟踪通道属性所做的假设，这些将在本章后面讨论。

线性跟踪用于许多游戏功能，例如：

+   检查武器开火时是否击中物体

+   当角色看着可以与之交互的物品时进行突出显示

+   当相机自动围绕玩家角色旋转时

线性跟踪的一个常见且重要的特性是**跟踪通道**。当执行线性跟踪时，您可能只想检查特定类型的对象，这就是跟踪通道的作用。它们允许您指定在执行线性跟踪时使用的过滤器，以便它不会被不需要的对象阻挡。例如：

+   您可能只想执行线性跟踪以检查可见的对象。这些对象将阻挡`Visibility`跟踪通道。例如，不可见的墙壁，这些是游戏中用来阻挡玩家移动的不可见几何体，不可见，因此不会阻挡`Visibility`跟踪通道。

+   您可能只想执行线性跟踪以检查可以与之交互的对象。这些对象将阻挡`Interaction`跟踪通道。

+   您可能只想执行线性跟踪以检查可以在游戏世界中移动的 pawn。这些对象将阻挡`Pawn`跟踪通道。

您可以指定不同对象如何对不同的跟踪通道做出反应，以便只有一些对象阻挡特定的跟踪通道，而其他对象忽略它们。在我们的情况下，我们想知道敌人和玩家角色之间是否有任何东西，这样我们就知道敌人是否能看到玩家。我们将使用线性跟踪来实现这一目的，通过检查任何阻挡敌人对玩家角色的视线的东西，使用`Tick`事件。

在下一节中，我们将使用 C++创建`EnemyCharacter`类。

# 创建 EnemyCharacter C++类

在我们的`Dodgeball`游戏中，`EnemyCharacter`类将不断地观察玩家角色，如果他们在视野内的话。这是同一个类，稍后将向玩家投掷躲避球；但是，这将留到下一章。在本章中，我们将专注于允许我们的敌人角色观察玩家的逻辑。

那么，让我们开始吧：

1.  在编辑器内右键单击`Content Browser`，然后选择`New C++ Class`。

1.  选择`Character`类作为父类。

1.  将新类命名为`EnemyCharacter`。

在你创建了类并在 Visual Studio 中打开了它的文件之后，让我们在其`header`文件中添加`LookAtActor`函数声明。这个函数应该是`public`，不返回任何东西，只接收`AActor* TargetActor`参数，这将是它应该面对的 Actor。看一下下面的代码片段，它展示了这个函数：

```cpp
// Change the rotation of the character to face the given actor
void LookAtActor(AActor* TargetActor);
```

注意

尽管我们只希望敌人看着玩家的角色，但为了执行良好的软件开发实践，我们将稍微抽象化这个函数，并允许`EnemyCharacter`看任何 Actor，因为允许一个 Actor 看另一个 Actor 或玩家角色的逻辑将是完全相同的。

记住，在编写代码时不应该创建不必要的限制。如果你可以编写类似的代码，同时又允许更多的可能性，那么你应该这样做，只要不过于复杂化程序的逻辑。

继续前进，如果`EnemyCharacter`看不到`Target` `Actor`，它就不应该看着它。为了检查敌人是否能看到 Actor，它应该看着`LookAtActor`函数，该函数将调用另一个函数，即`CanSeeActor`函数。这就是你将在下一个练习中要做的事情。

## 练习 5.02：创建 CanSeeActor 函数，执行线性跟踪

在这个练习中，我们将创建`CanSeeActor`函数，该函数将返回敌人角色是否能看到给定的 Actor。

以下步骤将帮助你完成这个练习：

1.  在`EnemyCharacter`类的头文件中创建`CanSeeActor`函数的声明，该函数将返回一个`bool`，并接收一个`const Actor* TargetActor`参数，这是我们想要看的 Actor。这个函数将是一个`const`函数，因为它不会改变类的任何属性，参数也将是`const`，因为我们不需要修改它的任何属性；我们只需要访问它们：

```cpp
// Can we see the given actor
bool CanSeeActor(const AActor* TargetActor) const;
```

现在，让我们来到有趣的部分，即执行线性跟踪。

为了调用与线性跟踪相关的函数，我们将需要使用`GetWorld`函数获取敌人当前的世界。然而，我们还没有在这个文件中包含`World`类，所以让我们在接下来的步骤中这样做：

注意

`GetWorld`函数对任何 Actor 都是可访问的，并将返回 Actor 所属的`World`对象。请记住，为了执行线性跟踪，世界是必要的。

1.  打开`EnemyCharacter`源文件，并找到以下代码行：

```cpp
#include "EnemyCharacter.h"
```

在上一行代码的后面添加以下行：

```cpp
#include "Engine/World.h"
```

1.  接下来，在`EnemyCharacter`源文件中创建`CanSeeActor`函数的实现，你将首先检查我们的`TargetActor`是否为`nullptr`。如果是，我们将返回`false`，因为我们没有有效的 Actor 来检查我们的视线：

```cpp
bool AEnemyCharacter::CanSeeActor(const AActor * TargetActor)   const
{
  if (TargetActor == nullptr)
  {
    return false;
  }
}
```

接下来，在添加线性跟踪函数调用之前，我们需要设置一些必要的参数；我们将在接下来的步骤中实现这些参数。

1.  在前面的`if`语句之后，创建一个变量来存储与线性跟踪结果相关的所有必要数据。Unreal 已经为此提供了一个内置类型，称为`FHitResult`类型：

```cpp
// Store the results of the Line Trace
FHitResult Hit;
```

这是我们将发送到线性跟踪函数的变量，该函数将用执行的线性跟踪的相关信息填充它。

1.  创建两个`FVector`变量，用于我们线性跟踪的`Start`和`End`位置，并将它们分别设置为我们敌人当前的位置和我们目标当前的位置：

```cpp
// Where the Line Trace starts and ends
FVector Start = GetActorLocation();
FVector End = TargetActor->GetActorLocation();
```

1.  接下来，设置我们希望进行比较的跟踪通道。在我们的情况下，我们希望有一个`Visibility`跟踪通道，专门用于指示一个物体是否阻挡另一个物体的视图。幸运的是，对于我们来说，UE4 中已经存在这样一个跟踪通道，如下面的代码片段所示：

```cpp
// The trace channel we want to compare against
ECollisionChannel Channel = ECollisionChannel::ECC_Visibility;
```

`ECollisionChannel`枚举代表了所有可能的跟踪通道，我们将使用`ECC_Visibility`值，该值代表`Visibility`跟踪通道。

1.  现在我们已经设置好所有必要的参数，我们最终可以调用`LineTrace`函数，`LineTraceSingleByChannel`：

```cpp
// Execute the Line Trace
GetWorld()->LineTraceSingleByChannel(Hit, Start, End,   Channel);
```

此函数将考虑我们发送的参数，执行线性跟踪，并通过修改我们的`Hit`变量返回其结果。

在我们继续之前，还有一些事情需要考虑。

如果线性跟踪从我们的敌人角色内部开始，这在我们的情况下会发生，这意味着线性跟踪很可能会立即击中我们的敌人角色并停在那里，因为我们的角色可能会阻塞`Visibility`跟踪通道。为了解决这个问题，我们需要告诉线性跟踪忽略它。

1.  使用内置的`FCollisionQueryParams`类型，可以为我们的线性跟踪提供更多选项：

```cpp
FCollisionQueryParams QueryParams;
```

1.  现在，更新线性跟踪以忽略我们的敌人，通过将自身添加到要忽略的 Actor 列表中：

```cpp
// Ignore the actor that's executing this Line Trace
QueryParams.AddIgnoredActor(this);
```

我们还应将我们的目标添加到要忽略的 Actor 列表中，因为我们不想知道它是否阻塞了`EnemySight`通道；我们只是想知道敌人和玩家角色之间是否有东西阻塞了该通道。

1.  将目标 Actor 添加到要忽略的 Actor 列表中，如下面的代码片段所示：

```cpp
// Ignore the target we're checking for
QueryParams.AddIgnoredActor(TargetActor);
```

1.  接下来，通过将其作为`LineTraceSingleByChannel`函数的最后一个参数发送我们的`FCollisionQueryParams`：

```cpp
// Execute the Line Trace
GetWorld()->LineTraceSingleByChannel(Hit, Start, End, Channel,   QueryParams);
```

1.  通过返回线性跟踪是否击中任何东西来完成我们的`CanSeeActor`函数。我们可以通过访问我们的`Hit`变量并检查是否有阻塞命中来实现这一点，使用`bBlockingHit`属性。如果有，这意味着我们看不到我们的`TargetActor`。可以通过以下代码片段实现：

```cpp
return !Hit.bBlockingHit;
```

注意

虽然我们不需要从`Hit`结果中获取更多信息，除了是否有阻塞命中，但`Hit`变量可以为我们提供关于线性跟踪的更多信息，例如：

通过访问“Hit.GetActor（）”函数，可以获取被线性跟踪击中的 Actor 的信息（如果没有击中 Actor，则为`nullptr`）

通过访问“Hit.GetComponent（）”函数，找到被线性跟踪击中的 Actor 组件的信息（如果没有击中 Actor 组件，则为`nullptr`）

通过访问`Hit.Location`变量获取击中位置的信息

通过访问`Hit.Distance`变量找到击中的距离

通过访问`Hit.ImpactNormal`变量找到线性跟踪击中对象的角度

最后，我们的`CanSeeActor`函数已经完成。我们现在知道如何执行线性跟踪，并且可以将其用于我们敌人的逻辑。

通过完成这个练习，我们已经完成了`CanSeeActor`函数；现在我们可以回到`LookAtActor`函数。但是，首先有件事情我们应该看一下：可视化我们的线性跟踪。

# 可视化线性跟踪

在创建使用线性跟踪的新逻辑时，实际上在执行线性跟踪时可视化线性跟踪非常有用，而线性跟踪函数不允许您这样做。为了做到这一点，我们必须使用一组辅助调试函数，在运行时可以动态绘制对象，如线条、立方体、球体等。

然后让我们添加线性跟踪的可视化。为了使用调试函数，我们必须在最后一个`include`行下添加以下`include`：

```cpp
#include "DrawDebugHelpers.h"
```

我们将调用`DrawDebugLine`函数以可视化线性跟踪，该函数需要以下输入，与线性跟踪函数接收到的非常相似：

1.  当前的`World`，我们将使用`GetWorld`函数提供

1.  线的`Start`和`End`点，将与`LineTraceSingleByChannel`函数相同

1.  游戏中线的期望颜色，可以设置为“红色”

然后，我们可以在我们的线段跟踪函数调用下面添加`DrawDebugLine`函数调用，如下面的代码片段所示：

```cpp
// Execute the Line Trace
GetWorld()->LineTraceSingleByChannel(Hit, Start, End, Channel,   QueryParams);
// Show the Line Trace inside the game
DrawDebugLine(GetWorld(), Start, End, FColor::Red);
```

这将允许您在执行时可视化线段跟踪，这非常有用。

注意

如果您需要，您还可以指定更多的可视化线段跟踪属性，比如它的生命周期和厚度。

有许多可用的`DrawDebug`函数，可以绘制立方体、球体、圆锥体、甜甜圈，甚至自定义网格。

现在我们既可以执行又可以可视化我们的线段跟踪，让我们在`LookAtActor`函数内使用我们在上一个练习中创建的`CanSeeActor`函数。

## 练习 5.03：创建 LookAtActor 函数

在这个练习中，我们将创建`LookAtActor`函数的定义，该函数将改变敌人的旋转，使其面向给定的角色。

以下步骤将帮助您完成这个练习：

1.  在`EnemyCharacter`源文件中创建`LookAtActor`函数定义。

1.  首先检查我们的`TargetActor`是否为`nullptr`，如果是，则立即返回空（因为它无效），如下面的代码片段所示：

```cpp
void AEnemyCharacter::LookAtActor(AActor * TargetActor)
{
  if (TargetActor == nullptr)
  {
    return;
  }
}
```

1.  接下来，我们要检查是否能看到我们的目标角色，使用我们的`CanSeeActor`函数：

```cpp
if (CanSeeActor(TargetActor))
{
}
```

如果这个`if`语句为真，那意味着我们能看到这个角色，并且我们将设置我们的旋转，以便面向该角色。幸运的是，UE4 中已经有一个允许我们这样做的函数：`FindLookAtRotation`函数。这个函数将接收级别中的两个点作为输入，点 A（`Start`点）和点 B（`End`点），并返回起始点的对象必须具有的旋转，以便面向结束点的对象。

1.  为了使用这个函数，包括`KismetMathLibrary`，如下面的代码片段所示：

```cpp
#include "Kismet/KismetMathLibrary.h"
```

1.  `FindLookAtRotation`函数必须接收一个`Start`和`End`点，这将是我们的敌人位置和我们的目标角色位置，分别：

```cpp
FVector Start = GetActorLocation();
FVector End = TargetActor->GetActorLocation();
// Calculate the necessary rotation for the Start point to   face the End point
FRotator LookAtRotation =   UKismetMathLibrary::FindLookAtRotation(Start, End);
```

1.  最后，将敌人角色的旋转设置为与我们的`LookAtRotation`相同的值：

```cpp
//Set the enemy's rotation to that rotation
SetActorRotation(LookAtRotation);
```

这就是`LookAtActor`函数的全部内容。

现在最后一步是在 Tick 事件中调用`LookAtActor`函数，并将玩家角色作为`TargetActor`发送。

1.  为了获取当前由玩家控制的角色，我们可以使用`GameplayStatics`对象。与其他 UE4 对象一样，我们必须首先包含它们：

```cpp
#include "Kismet/GameplayStatics.h"
```

1.  接下来，转到您的 Tick 函数的主体，并从`GameplayStatics`中调用`GetPlayerCharacter`函数：

```cpp
// Fetch the character currently being controlled by the   player
ACharacter* PlayerCharacter =   UGameplayStatics::GetPlayerCharacter(this, 0);
```

此函数接收以下输入：

+   一个世界上下文对象，本质上是属于我们当前世界的对象，用于让函数知道要访问哪个世界对象。这个世界上下文对象可以简单地是`this`指针。

+   玩家索引，鉴于我们的游戏应该是单人游戏，我们可以安全地假设为`0`（第一个玩家）。

1.  接下来，调用`LookAtActor`函数，发送我们刚刚获取的玩家角色：

```cpp
// Look at the player character every frame
LookAtActor(PlayerCharacter);
```

1.  这个练习的最后一步是在 Visual Studio 中编译您的更改。

现在您已经完成了这个练习，您的`EnemyCharacter`类已经具备了面向玩家角色的必要逻辑，如果它在视野内，我们可以开始创建`EnemyCharacter`蓝图类。

# 创建 EnemyCharacter 蓝图类

现在我们已经完成了`EnemyCharacter` C++类的逻辑，我们必须创建从中派生的蓝图类：

1.  在编辑器中打开我们的项目。

1.  转到`ThirdPersonCPP`文件夹中的`Content Browser`中的`Blueprints`文件夹。

1.  *右键单击*并选择创建新的蓝图类。

1.  在`Pick Parent Class`窗口底部附近展开`All Classes`选项卡，搜索我们的`EnemyCharacter` C++类，并将其选择为父类。

1.  将蓝图类命名为`BP_EnemyCharacter`。

1.  打开蓝图类，从“组件”选项卡中选择`SkeletalMeshComponent`（称为`Mesh`），并将其“骨骼网格”属性设置为`SK_Mannequin`，将其“动画类”属性设置为`ThirdPerson_AnimBP`。

1.  将`SkeletalMeshComponent`的*Yaw*更改为`-90º`（在*z 轴*上），将其在*z 轴*上的位置更改为`-83`个单位。

1.  在设置好蓝图类之后，其网格设置应该与我们的`DodgeballCharacter`蓝图类非常相似。

1.  将`BP_EnemyCharacter`类的一个实例拖到你的关卡中，放在一个可能阻挡其视线的物体附近，比如这个位置（所选角色是`EnemyCharacter`）：![图 5.5：将 BP_EnemyCharacter 类拖入关卡](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_05_05.jpg)

图 5.5：将 BP_EnemyCharacter 类拖入关卡

1.  现在我们终于可以玩游戏，验证我们的敌人在视线范围内时确实看向我们的玩家角色：![图 5.6：敌人角色使用线扫描清晰看到玩家](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_05_06.jpg)

图 5.6：敌人角色使用线扫描清晰看到玩家

1.  我们还可以看到，敌人在视线范围之外时停止看到玩家，如*图 5.7*所示：

![图 5.7：敌人失去对玩家的视线](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_05_07.jpg)

图 5.7：敌人失去对玩家的视线

这就结束了我们的`EnemyCharacter`的逻辑。在下一节中，我们将看一下扫描轨迹。

# 扫描轨迹

在继续我们的项目之前，了解一种线扫描的变体——**扫描轨迹**是很重要的。虽然我们不会在项目中使用它们，但了解它们以及如何使用它们是很重要的。

虽然线扫描基本上是在两点之间“发射一条射线”，但扫描轨迹将模拟在直线上两点之间“抛出一个物体”。被“抛出”的物体是模拟的（实际上并不存在于游戏中），可以有各种形状。在扫描轨迹中，“击中”位置将是虚拟物体（我们将其称为**形状**）从起点到终点抛出时首次击中另一个物体的位置。扫描轨迹的形状可以是盒形、球形或胶囊形。

这是从点`A`到点`B`的扫描轨迹的表示，我们假设由于其跟踪通道属性，物体`1`被忽略，使用盒形：

![图 5.8：扫描轨迹的表示](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_05_08.jpg)

图 5.8：扫描轨迹的表示

从*图 5.8*中，我们注意到以下内容：

+   使用盒形的扫描轨迹，从点 A 到点 B 执行。

+   虚线框表示扫描轨迹在击中物体之前。

+   虚线框表示扫描轨迹击中物体后的情况。

+   条纹圆圈表示扫描轨迹与物体`2`的碰撞点，即扫描轨迹盒形的表面与物体`2`的表面相互碰撞的点。

+   大方块代表了两个物体在线扫描轨迹（物体`1`和`2`）的路径上。

+   由于其跟踪通道属性的假设，物体`1`在扫描轨迹中被忽略。

在一些情况下，扫描跟踪比普通的线性跟踪更有用。让我们以我们的敌人角色为例，它可以投掷躲避球。如果我们想要为玩家添加一种方式，让玩家不断地可视化敌人投掷的下一个躲避球将会着陆的位置，那么最好的方法是使用扫描跟踪：我们可以用我们躲避球的形状（一个球体）对玩家进行扫描跟踪，检查碰撞点，并在碰撞点显示一个球体，这样玩家就可以看到。如果扫描跟踪击中了墙壁或某个角落，玩家就会知道，如果敌人此时投掷躲避球，它会首先击中那里。你可以使用简单的线性跟踪来达到同样的目的，但是为了达到相同的结果质量，设置会变得相当复杂，这就是为什么在这种情况下扫描跟踪是更好的解决方案。

现在，让我们快速看一下如何在代码中进行扫描跟踪。

## 练习 5.04：执行扫描跟踪

在这个练习中，我们将在代码中实现扫描跟踪。虽然我们不会在项目中使用它，但通过进行这个练习，你将熟悉这样的操作。

进入前几节创建的`CanSeeActor`函数的末尾，然后按照以下步骤进行：

1.  负责扫描跟踪的函数是`SweepSingleByChannel`，它在 UE4 中可用，并需要以下参数作为输入：

一个`FHitResult`类型，用于存储扫描的结果（我们已经有了一个，所以不需要再创建另一个这种类型的变量）：

```cpp
// Store the results of the Line Trace
FHitResult Hit;
```

扫描的“起点”和“终点”（我们已经有了这两个，所以不需要再创建另一个这种类型的变量）：

```cpp
// Where the Sweep Trace starts and ends
FVector Start = GetActorLocation();
FVector End = TargetActor->GetActorLocation();
```

1.  使用形状的预期旋转，它是一个`FQuat`类型（表示四元数）。在这种情况下，它被设置为在所有轴上的旋转为`0`，通过访问`FQuat`的`Identity`属性来实现： 

```cpp
// Rotation of the shape used in the Sweep Trace
FQuat Rotation = FQuat::Identity; 
```

1.  现在，使用预期的跟踪通道进行比较（我们已经有了一个这样的变量，所以不需要再创建另一个这种类型的变量）：

```cpp
// The trace channel we want to compare against
ECollisionChannel Channel = ECollisionChannel::ECC_Visibility;
```

1.  最后，通过调用`FcollisionShape`的`MakeBox`函数并提供盒形形状在三个轴上的半径来使用盒形的形状进行扫描跟踪。这在下面的代码片段中显示：

```cpp
// Shape of the object used in the Sweep Trace
FCollisionShape Shape = FCollisionShape::MakeBox(FVector(20.f,   20.f, 20.f));
```

1.  接下来，调用`SweepSingleByChannel`函数：

```cpp
GetWorld()->SweepSingleByChannel(Hit,
                                 Start,
                                 End,
                                 Rotation,
                                 Channel,
                                 Shape);
```

完成了这些步骤后，我们完成了有关扫描跟踪的练习。鉴于我们不会在项目中使用扫描跟踪，你应该注释掉`SweepSingleByChannel`函数，这样我们的`Hit`变量就不会被修改，也不会丢失我们线性跟踪的结果。

现在我们已经完成了有关扫描跟踪的部分，让我们回到我们的“躲避球”项目，并学习如何更改对象对跟踪通道的响应。

## 更改可见性跟踪响应

在我们当前的设置中，每个可见的对象都会阻挡“可见性”跟踪通道；但是，如果我们想要改变一个对象是否完全阻挡该通道，该怎么办呢？为了做到这一点，我们必须改变一个组件对该通道的响应。看下面的例子：

1.  我们选择我们在关卡中用来阻挡敌人视线的立方体，如*图 5.9*所示：![图 5.9：角色的默认生成点](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_05_09.jpg)

图 5.9：角色的默认生成点

1.  然后，转到对象“详细面板”中的“碰撞”部分（它在“编辑器”界面中的默认位置）：![图 5.10：虚幻引擎中详细面板中的碰撞选项卡](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_05_10.jpg)

图 5.10：虚幻引擎中详细面板中的碰撞选项卡

1.  在这里，你会发现几个与碰撞相关的选项。我们现在要注意的是“碰撞预设”选项。它当前的值是“默认”，但是，我们想根据自己的喜好进行更改，所以我们将点击下拉框并将其值更改为“自定义”。

1.  一旦这样做，您会注意到一整组新选项弹出：![图 5.11：碰撞预设设置为自定义](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_05_11.jpg)

图 5.11：碰撞预设设置为自定义

这组选项允许您指定此对象对线追踪和对象碰撞的响应方式，以及它是何种类型的碰撞对象。

您应该注意的选项是“可见性”。您会注意到它设置为“阻挡”，但您也可以将其设置为“重叠”和“忽略”。

现在，立方体正在阻挡“可见性”追踪通道，这就是为什么我们的敌人在立方体后面时看不到角色。但是，如果我们将对象对“可见性”追踪通道的响应更改为“重叠”或“忽略”，则该对象将不再阻止检查可见性的线追踪（这是您刚刚在 C++中编写的线追踪的情况）。

1.  让我们将立方体对“可见性”通道的响应更改为“忽略”，然后玩游戏。您会注意到即使敌人在立方体后面时，它仍然朝向玩家角色：![图 5.12：敌人角色透过物体看玩家](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_05_12.jpg)

图 5.12：敌人角色透过物体看玩家

这是因为立方体不再阻挡“可见性”追踪通道，因此敌人执行的线追踪在试图接触玩家角色时不再击中任何东西。

现在我们已经看到如何更改对象对特定追踪通道的响应方式，让我们将立方体对“可见性”通道的响应更改回“阻挡”。

但是，值得一提的是：如果我们将立方体对“可见性”通道的响应设置为“重叠”，而不是“忽略”，结果将是相同的。但是为什么呢，这两种响应的目的是什么？为了解释这一点，我们将看看多线追踪。

## 多线追踪

在*练习 5.02*中使用`CanSeeActor`函数时，您可能会对我们使用的线追踪函数`LineTraceSingleByChannel`的名称，特别是为什么使用了“单”这个词，感到困惑。原因是因为您也可以执行`LineTraceMultiByChannel`。

但是这两种线追踪有何不同？

单线追踪在击中物体后将停止检查阻挡物体，并告诉我们击中的物体是什么，而多线追踪可以检查同一线追踪击中的任何物体。

单线追踪将：

+   忽略那些在线追踪中使用的追踪通道上设置为“忽略”或“重叠”的对象

+   找到其响应设置为“阻挡”的对象时停止

然而，多线追踪不会忽略那些在追踪通道上设置为“重叠”的对象，而是将它们添加为在线追踪期间找到的对象，并且只有在找到阻挡所需追踪通道的对象时（*或者到达终点时*）才会停止。在下一个图中，您将找到执行多线追踪的示例：

![图 5.13：从点 A 到点 B 执行的多线追踪](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_05_13.jpg)

图 5.13：从点 A 到点 B 执行的多线追踪

在*图 5.13*中，我们注意到以下内容：

+   虚线代表线追踪在击中阻挡物体之前。

+   点线代表线追踪击中阻挡物体后。

+   条纹圆圈代表线追踪的影响点，其中只有最后一个在这种情况下是阻挡击中。

`LineTraceSingleByChannel`和`LineTraceMultiByChannel`函数之间唯一的区别在于它们的输入，后者必须接收`TArray<FHitResult>`输入，而不是单个`FHitResult`。所有其他输入都是相同的。

多线跟踪在模拟具有强穿透力的子弹行为时非常有用，可以穿过多个对象后完全停止。请记住，您还可以通过调用`SweepMultiByChannel`函数进行多扫描跟踪。

注意

关于`LineTraceSingleByChannel`函数的另一件事，你可能会想知道的是`ByChannel`部分。这个区别与使用跟踪通道有关，而不是另一种选择，即对象类型。您可以通过调用`LineTraceSingleByObjectType`函数来执行使用对象类型而不是跟踪通道的线跟踪，该函数也可以从 World 对象中获得。对象类型与我们将在下一章中涵盖的主题相关，因此我们暂时不会详细介绍这个函数。

## 摄像机跟踪通道

当将我们的立方体的响应更改为`Visibility`跟踪通道时，您可能已经注意到了另一个内置的跟踪通道：`Camera`。

该通道用于指定对象是否阻挡了摄像机弹簧臂和其关联的角色之间的视线。为了看到这一点，我们可以将一个对象拖到我们的级别中，并将其放置在这样一种方式，即它将保持在摄像机和我们的玩家角色之间。

看一下以下示例；我们首先复制`floor`对象。

注意

您可以通过按住*Alt*键并沿任何方向拖动*移动工具*的箭头来轻松复制级别中的对象。

![图 5.14：选择地板对象](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_05_14.jpg)

图 5.14：选择地板对象

1.  接下来，我们更改其`Transform`值，如下图所示：![图 5.15：更新变换值](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_05_15.jpg)

图 5.15：更新变换值

1.  现在当您玩游戏时，您会注意到当角色走到我们复制的地板下方时，您不会失去对玩家角色的视线，而是弹簧臂会使摄像机向下移动，直到您能看到角色：![图 5.16：摄像机角度的变化](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_05_16.jpg)

图 5.16：摄像机角度的变化

1.  为了看到当对象不阻挡`Camera`跟踪通道时弹簧臂的行为如何不同，将我们复制的地板对`Camera`通道的响应更改为`Ignore`，然后再次播放级别。结果将是，当我们的角色走到复制的地板下方时，我们将失去对角色的视线。

完成这些步骤后，您会发现“摄像机”通道用于指定对象是否会导致弹簧臂将摄像机靠近玩家当它与该对象相交时。

现在我们知道如何使用现有的跟踪通道，那么如果我们想创建自己的跟踪通道呢？

## 练习 5.05：创建自定义 EnemySight 跟踪通道

正如我们之前讨论过的，UE4 自带两个跟踪通道：`Visibility`和`Camera`。第一个是一个通用通道，我们可以用它来指定哪些对象阻挡了对象的视线，而第二个允许我们指定对象是否阻挡了摄像机弹簧臂和其关联的角色之间的视线。

但是我们如何创建自己的跟踪通道呢？这就是我们将在本练习中探讨的内容。我们将创建一个新的`EnemySight`跟踪通道，并使用它来检查敌人是否能看到玩家角色，而不是使用内置的`Visibility`通道：

1.  通过按编辑器左上角的“编辑”按钮打开“项目设置”，然后转到“碰撞”部分。在那里，您会找到“跟踪通道”部分。它目前为空，因为我们还没有创建自己的跟踪通道。

1.  选择`New Trace Channel`选项。一个窗口应该弹出，让您可以命名您的新通道，并根据您项目中的对象设置其默认响应。将我们的新 Trace 通道命名为`EnemySight`，并将其默认响应设置为`Block`，因为我们希望大多数对象都这样做。

1.  创建新的 Trace 通道后，我们必须回到我们的`EnemyCharacter` C++类中，并更改我们在 Line Trace 中比较的 Trace：

```cpp
// The trace channel we want to compare against
ECollisionChannel Channel = ECollisionChannel::ECC_Visibility;
```

鉴于我们不再使用`Visibility`通道，我们必须引用我们的新通道，但我们该如何做呢？

在项目目录中，您会找到`Config`文件夹。该文件夹包含与您的项目相关的几个`ini`文件，如`DefaultGame.ini`，`DefaultEditor.ini`，`DefaultEngine.ini`等。每个文件都包含在加载项目时将被初始化的几个属性。这些属性以名称-值对(`property=value`)的形式设置，您可以根据需要更改它们的值。

1.  当我们创建了我们的`EnemySight`通道时，项目的`DefaultEngine.ini`文件将被更新为我们的新 Trace 通道。在那个文件的某个地方，您会找到这一行：

```cpp
+DefaultChannelResponses=(Channel=ECC_GameTraceChannel1,  DefaultResponse=ECR_Block,bTraceType=True,bStaticObject=False,  Name="EnemySight")
// The trace channel we want to compare against
ECollisionChannel Channel =   ECollisionChannel::ECC_GameTraceChannel1;
```

1.  验证我们的敌人在我们所做的所有更改之后行为是否保持不变。这意味着只要玩家角色在敌人的视野范围内，敌人就必须面对玩家角色。

通过完成这个练习，我们现在知道如何为任何所需的目的创建我们自己的 Trace 通道。

回到我们的敌人角色，还有一些方法可以改进它的逻辑。现在，当我们获取我们敌人的位置作为 Line Trace 的起点时，那个点大约在敌人的臀部附近，因为那是 Actor 的原点。然而，那通常不是人们的眼睛所在的地方，让一个类人角色从它的臀部而不是头部看会没有多大意义。

所以，让我们改变一下，让我们的敌人角色从它的眼睛开始检查是否看到玩家角色，而不是从它的臀部开始。

## 活动 5.01：创建 SightSource 属性

在这个活动中，我们将改进我们敌人的逻辑，以确定它是否应该看着玩家。目前，用于确定这一点的 Line Trace 是从我们角色的臀部附近(`0,0,0`)在我们的`BP_EnemyCharacter`蓝图中进行的，我们希望这更有意义一些，所以我们将使 Line Trace 的起点接近我们敌人的眼睛。那么，让我们开始吧。

以下步骤将帮助您完成这个活动：

1.  在我们的`EnemyCharacter` C++类中声明一个名为`SightSource`的新`SceneComponent`。确保将其声明为`UPROPERTY`，并使用`VisibleAnywhere`，`BlueprintReadOnly`，`Category = LookAt`和`meta = (AllowPrivateAccess = "true")`标签。

1.  通过使用`CreateDefaultSubobject`函数在`EnemyCharacter`构造函数中创建这个组件，并将其附加到`RootComponent`。

1.  将 Line Trace 的起始位置更改为`CanSeeActor`函数中的`SightSource`组件的位置，而不是 Actor 的位置。

1.  打开`BP_EnemyCharacter`蓝图类，并将`SightSource`组件的位置更改为敌人头部的位置`(10, 0, 80)`，就像在*创建 EnemyCharacter 蓝图类*部分中对`BP_EnemyCharacter`的`SkeletalMeshComponent`属性所做的那样。

`Editor Panel`中的`Transform`选项卡，如*图 5.17*所示。

![图 5.17：更新 SightSource 组件的值](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_05_17.jpg)

图 5.17：更新 SightSource 组件的值

预期输出：

![图 5.18：预期输出显示从臀部到眼睛的更新的 Line Trace](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_05_18.jpg)

图 5.18：预期输出显示从臀部到眼睛的更新的 Line Trace

注意

这个活动的解决方案可以在这里找到：[`packt.live/338jEBx`](https://packt.live/338jEBx)。

通过完成这个活动，我们已经更新了我们的`EnemyCharacter`的`SightSource`属性。

# 总结

通过完成这一章，你已经为自己的工具箱增添了一个新工具：线性跟踪。你现在知道如何执行线性跟踪和扫描跟踪，包括单一和多重；如何改变对象对特定跟踪通道的响应；以及如何创建自己的跟踪通道。

在接下来的章节中，你将很快意识到这些是游戏开发中必不可少的技能，并且你将在未来的项目中充分利用它们。

现在我们知道如何使用线性跟踪，我们已经准备好迈出下一步，即对象碰撞。在下一章中，你将学习如何设置对象之间的碰撞，以及如何使用碰撞事件来创建自己的游戏逻辑。你将创建躲避球角色，它将受到实时物理模拟的影响；墙角色，它将阻挡角色的移动和躲避球的移动；以及负责在玩家接触到它时结束游戏的角色。


# 第六章：碰撞对象

概述

在本章中，我们将继续在上一章介绍的基于碰撞的游戏中添加更多的机制和对象。最初，我们将继续介绍对象碰撞。您将学习如何使用碰撞框、碰撞触发器、重叠事件、击中事件和物理模拟。您还将学习如何使用定时器、投射物移动组件和物理材料。

# 介绍

在上一章中，我们了解了一些碰撞的基本概念，即线追踪和扫描追踪。我们学习了如何执行不同类型的线追踪，如何创建自定义的追踪通道，以及如何更改对象对特定通道的响应方式。在本章中，我们将使用上一章学到的许多内容，学习关于对象碰撞。

在本章中，我们将继续通过添加围绕对象碰撞的游戏机制来构建我们的顶部“躲避球”游戏。我们将创建**躲避球角色**，它将作为一个从地板和墙壁上弹开的躲避球；一个**墙壁角色**，它将阻挡所有对象；一个**幽灵墙角色**，它只会阻挡玩家，而不会阻挡敌人的视线或躲避球；以及一个**胜利箱角色**，当玩家进入胜利箱时游戏结束，代表关卡的结束。

在我们开始创建我们的“躲避球”类之前，我们将在下一节中介绍对象碰撞的基本概念。

# UE4 中的对象碰撞

每个游戏开发工具都必须有一个模拟多个对象之间碰撞的物理引擎，如前一章所述。碰撞是当今大多数游戏的基础，无论是 2D 还是 3D。在许多游戏中，这是玩家对环境进行操作的主要方式，无论是奔跑、跳跃还是射击，环境都会相应地使玩家着陆、受到打击等。毫不夸张地说，如果没有模拟碰撞，许多游戏根本无法制作。

因此，让我们了解 UE4 中对象碰撞的工作原理以及我们可以使用的方式，从碰撞组件开始。

# 碰撞组件

在 UE4 中，有两种类型的组件可以影响并受到碰撞的影响；它们如下：

+   网格

+   形状对象

**网格**可以简单到一个立方体，也可以复杂到有数万个顶点的高分辨率角色。网格的碰撞可以通过与网格一起导入 UE4 的自定义文件指定（这超出了本书的范围），也可以由 UE4 自动计算并由您自定义。

通常最好将碰撞网格保持尽可能简单（少三角形），以便物理引擎可以在运行时高效地计算碰撞。可以具有碰撞的网格类型如下：

+   静态网格

+   骨骼网格

+   程序化网格

+   以及其他

**形状对象**是简单的网格，在线框模式下表示，通过引起和接收碰撞事件来充当碰撞对象。

注意

线框模式是游戏开发中常用的可视化模式，通常用于调试目的，允许您看到没有任何面或纹理的网格 - 它们只能通过它们的边缘连接的顶点来看到。当我们向角色添加形状组件时，您将看到线框模式是什么。

请注意，形状对象本质上是不可见的网格，它们的三种类型如下：

+   盒形碰撞（C++中的盒形组件）

+   球形碰撞（C++中的球形组件）

+   胶囊碰撞器（C++中的胶囊组件）

注意

有一个类，所有提供几何和碰撞的组件都继承自它，那就是`Primitive`组件。这个组件是包含任何类型几何的所有组件的基础，这适用于网格组件和形状组件。

那么，这些组件如何发生碰撞，以及它们碰撞时会发生什么？我们将在下一节中看看这个，即碰撞事件。

# 碰撞事件

假设有两个对象相互碰撞。可能发生两种情况：

+   它们会互相重叠，好像另一个对象不存在，这种情况下会调用`Overlap`事件。

+   它们会发生碰撞并阻止对方继续前进，这种情况下会调用`Block`事件。

在前一章中，我们学习了如何将对象对特定的`Trace`通道的响应进行更改。在这个过程中，我们了解到对象的响应可以是`Block`、`Overlap`或`Ignore`。

现在，让我们看看在碰撞中每种响应发生了什么。

`Block`：

+   两个对象都会调用它们的`OnHit`事件。这个事件在两个对象在碰撞时阻止对方路径时被调用。如果其中一个对象正在模拟物理，那么该对象必须将其`SimulationGeneratesHitEvents`属性设置为`true`。

+   两个对象将互相阻止对方继续前进。

看一下下面的图，它展示了两个对象被扔出并互相弹开的例子：

![图 6.1：对象 A 和对象 B 互相阻止对方](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_06_01.jpg)

图 6.1：对象 A 和对象 B 互相阻止对方

**Overlap**：如果两个对象不会互相阻止对方，并且它们中没有一个忽略另一个，那么它们会互相重叠：

+   如果两个对象的`GenerateOverlapEvents`属性都设置为`true`，它们将调用它们的`OnBeginOverlap`和`OnEndOverlap`事件。这些重叠事件分别在一个对象开始和停止与另一个对象重叠时调用。如果它们中至少有一个没有将此属性设置为`true`，则它们都不会调用这些事件。

+   对象会表现得好像另一个对象不存在，并且会互相重叠。

举个例子，假设玩家角色走进一个只对玩家角色做出反应的关卡结束触发器。

看一下下面的图，它展示了两个对象互相重叠的例子：

![图 6.2：对象 A 和对象 B 互相重叠](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_06_02.jpg)

图 6.2：对象 A 和对象 B 互相重叠

**Ignore**：如果两个对象中至少有一个忽略另一个，它们会互相忽略：

+   任何一个对象都不会调用事件。

+   与`Overlap`响应类似，对象会表现得好像另一个对象不存在，并且会互相重叠。

两个对象互相忽略的一个例子是，当除了玩家角色以外的对象进入一个只对玩家角色做出反应的关卡结束触发器时。

注意

你可以看一下之前的图，两个对象互相重叠，以理解**Ignore**。

以下是一个表格，帮助你理解两个对象必须具有的必要响应，以触发先前描述的情况：

![图 6.3：基于 Block、Overlap 和 Ignore 的对象的响应结果](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_06_03.jpg)

图 6.3：基于 Block、Overlap 和 Ignore 的对象的响应结果

根据这个表格，考虑你有两个对象 - 对象 A 和对象 B：

+   如果对象 A 将其响应设置为对象 B 的`Block`，而对象 B 将其响应设置为对象 A 的`Block`，它们将会互相阻止对方。

+   如果对象 A 将其响应设置为对象 B 的`Block`，而对象 B 将其响应设置为对象 A 的`Overlap`，它们将会互相重叠。

+   如果物体 A 将其对物体 B 的响应设置为“忽略”，而物体 B 将其对物体 A 的响应设置为“重叠”，它们将互相“忽略”。

注意

您可以在这里找到 UE4 碰撞交互的完整参考：[`docs.unrealengine.com/en-US/Engine/Physics/Collision/Overview`](https://docs.unrealengine.com/en-US/Engine/Physics/Collision/Overview)。

物体之间的碰撞有两个方面：

物理学：所有与物理模拟相关的碰撞，比如球受重力影响并从地板和墙壁上弹开。

游戏中的碰撞的物理模拟响应，可以是：

+   两个物体继续它们的轨迹，就好像另一个物体不存在一样（没有物理碰撞）。

+   两个物体相撞并改变它们的轨迹，通常至少有一个物体继续其运动，即阻挡彼此的路径。

**查询**：查询可以分为碰撞的两个方面，如下所示：

+   与游戏中的物体碰撞相关的事件，您可以使用这些事件创建额外的逻辑。这些事件与我们之前提到的是相同的：

+   “命中”事件

+   “开始重叠”事件

+   “结束重叠”事件

+   游戏中的碰撞的物理响应，可以是：

+   两个物体继续它们的运动，就好像另一个物体不存在一样（没有物理碰撞）。

+   两个物体相撞并阻挡彼此的路径

物理方面的物理响应可能听起来与查询方面的物理响应相似；然而，尽管它们都是物理响应，但它们会导致对象的行为不同。

物理方面的物理响应（物理模拟）仅适用于物体在模拟物理时（例如受重力影响、从墙壁和地面弹开等）。当这样的物体撞到墙壁时，会弹回并继续朝另一个方向移动。

另一方面，查询方面的物理响应适用于所有不模拟物理的物体。当一个物体不模拟物理时，可以通过代码控制移动（例如使用`SetActorLocation`函数或使用角色移动组件）。在这种情况下，根据您用于移动物体的方法和其属性，当物体撞到墙壁时，它将简单地停止移动而不是弹回。这是因为您只是告诉物体朝某个方向移动，而有东西挡住了它的路径，所以物理引擎不允许该物体继续移动。

在下一节中，我们将看看碰撞通道。

# 碰撞通道

在上一章中，我们看了现有的跟踪通道（*可见性*和*相机*）并学习了如何创建自定义通道。现在您已经了解了跟踪通道，是时候谈谈对象通道，也称为对象类型了。

虽然跟踪通道仅用于线跟踪，但对象通道用于对象碰撞。您可以为每个“对象”通道指定一个“目的”，就像跟踪通道一样，比如角色、静态对象、物理对象、抛射物等等。然后，您可以指定您希望每种对象类型如何响应所有其他对象类型，即通过阻挡、重叠或忽略该类型的对象。

# 碰撞属性

现在我们已经了解了碰撞的工作原理，让我们回到上一章中选择的立方体的碰撞设置，我们在那里将其响应更改为可见性通道。

在下面的截图中可以看到立方体：

![图 6.4：立方体阻挡敌人的视觉源](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_06_04.jpg)

图 6.4：立方体阻挡敌人的视觉源

在编辑器中打开关卡，选择立方体并转到其详细面板的“碰撞”部分：

![图 6.5：关卡编辑器中的更改](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_06_05.jpg)

图 6.5：级别编辑器中的变化

在这里，我们可以看到一些对我们很重要的选项：

+   `SimulationGeneratesHitEvents`，当物体模拟物理时允许调用`OnHit`事件（我们将在本章后面讨论这个）。

+   `GenerateOverlapEvents`，允许调用`OnBeginOverlap`和`OnEndOverlap`事件。

+   `CanCharacterStepUpOn`，允许角色轻松站在这个物体上。

+   `CollisionPresets`，允许我们指定此对象如何响应每个碰撞通道。

让我们将`CollisionPresets`的值从`默认`更改为`自定义`，并查看出现的新选项：

![图 6.6：碰撞预设的变化](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_06_06.jpg)

图 6.6：碰撞预设的变化

这些选项中的第一个是`CollisionEnabled`属性。它允许您指定要考虑此对象的碰撞的哪些方面：查询、物理、两者或无。再次，物理碰撞与物理模拟相关（此物体是否会被模拟物理的其他物体考虑），而查询碰撞与碰撞事件相关，以及物体是否会阻挡彼此的移动：

![图 6.7：查询和物理的碰撞启用](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_06_07.jpg)

图 6.7：查询和物理的碰撞启用

第二个选项是`ObjectType`属性。这与跟踪通道概念非常相似，但专门用于对象碰撞，并且最重要的是决定了这是什么类型的碰撞对象。UE4 提供的对象类型值如下：

+   `WorldStatic`：不移动的物体（结构、建筑等）

+   `WorldDynamic`：可能移动的物体（由代码触发移动的物体，玩家可以拾取和移动的物体等）

+   `Pawn`：用于可以在级别中控制和移动的 Pawns

+   `PhysicsBody`：用于模拟物理的物体

+   `Vehicle`：用于车辆物体

+   `可破坏`：用于可破坏的网格

如前所述，您还可以创建自己的自定义对象类型（稍后在本章中提到），类似于您可以创建自己的跟踪通道（*在上一章中介绍过*）。

我们拥有的最后一个选项与`碰撞响应`有关。鉴于这个`Cube`对象具有默认的碰撞选项，所有响应都设置为`阻挡`，这意味着该对象将阻挡所有线跟踪和所有阻挡`WorldStatic`对象的对象，鉴于这是该对象的类型。

由于碰撞属性有很多不同的组合，UE4 允许您以碰撞预设的形式对碰撞属性值进行分组。

让我们回到`CollisionPresets`属性，它当前设置为`自定义`，并*点击*以查看所有可能的选项。一些现有的`碰撞预设`如下：

**无碰撞**：用于根本不受碰撞影响的物体：

+   `碰撞启用`：`无碰撞`

+   `物体类型`：`WorldStatic`

+   响应：无关

+   示例：纯粹是视觉和遥远的物体，如玩家永远不会接触的物体

**全部阻挡**：用于静态物体并阻挡所有其他物体：

+   `碰撞启用`：`查询`和`物理`

+   `物体类型`：`WorldStatic`

+   响应：`阻挡`所有通道

+   示例：靠近玩家角色并阻挡其移动的物体，如地板和墙壁，将始终保持静止

**重叠所有**：用于静态物体并与所有其他物体重叠：

+   `碰撞启用`：仅`查询`

+   `物体类型`：`WorldStatic`

+   响应：`重叠`所有通道

+   示例：放置在级别中的触发框，将始终保持静止

`全部阻挡`预设，但用于可能在游戏过程中改变其变换的动态物体（`物体类型`：`WorldDynamic`）

`Overlap All`预设，但对于可能在游戏过程中改变其变换的动态对象（`对象类型`：`WorldDynamic`）

**Pawn**：用于 pawns 和 characters：

+   `碰撞使能`：`Query`和`Physics`

+   `对象类型`：`Pawn`

+   响应：`Block`所有通道，`Ignore`可见性通道

+   示例：玩家角色和非玩家角色

物理演员：用于模拟物理的对象：

+   `碰撞使能`：`Query`和`Physics`

+   `对象类型`：`PhysicsBody`

+   响应：`Block`所有通道

+   示例：受物理影响的对象，比如从地板和墙壁上弹开的球

就像其他碰撞属性一样，你也可以创建自己的碰撞预设。

注意

你可以在这里找到 UE4 碰撞响应的完整参考：[`docs.unrealengine.com/en-US/Engine/Physics/Collision/Reference`](https://docs.unrealengine.com/en-US/Engine/Physics/Collision/Reference)。

现在我们了解了碰撞的基本概念，让我们继续开始创建`Dodgeball`类。下一个练习将指导你完成这个任务。

## 练习 6.01：创建 Dodgeball 类

在这个练习中，我们将创建我们的`Dodgeball`类，这个类将被敌人投掷，并且会像真正的躲避球一样从地板和墙壁上弹开。

在我们真正开始创建`Dodgeball` C++类和它的逻辑之前，我们应该为它设置所有必要的碰撞设置。

以下步骤将帮助你完成这个练习：

1.  打开我们的`Project Settings`并转到`Engine`部分中的`Collision`子部分。当前没有对象通道，所以你需要创建一个新的。

1.  点击`New Object Channel`按钮，命名为`Dodgeball`，并将其`默认响应`设置为`Block`。

1.  完成后，展开`Preset`部分。在这里，你会找到 UE4 中所有默认的预设。如果你选择其中一个并按下`Edit`选项，你可以更改该`Preset`碰撞的设置。

1.  通过按下`New`选项创建自己的`Preset`。我们希望我们的`Dodgeball` `Preset`设置如下：

+   `名称`：`Dodgeball`

+   `CollisionEnabled`：`Collision Enabled (Query and Physics)`（我们希望这也被考虑为物理模拟以及碰撞事件）

+   `对象类型`：`Dodgeball`

+   `碰撞响应`：对大多数选项选择*Block*，但对于相机和`EnemySight`选择*Ignore*（我们不希望躲避球阻挡相机或敌人的视线）

1.  一旦你选择了正确的选项，点击`Accept`。

现在`Dodgeball`类的碰撞设置已经设置好了，让我们创建`Dodgeball` C++类。

1.  在`Content Browser`中，*右键单击*并选择`New C++ Class`。

1.  选择`Actor`作为父类。

1.  选择`DodgeballProjectile`作为类的名称（我们的项目已经命名为`Dodgeball`，所以我们不能再将这个新类命名为`Dodgeball`）。

1.  在 Visual Studio 中打开`DodgeballProjectile`类文件。我们首先要做的是添加躲避球的碰撞组件，所以我们将在我们的类头文件中添加一个`SphereComponent`（*actor 组件属性通常是私有的*）：

```cpp
UPROPERTY(VisibleAnywhere, BlueprintReadOnly, Category =   Dodgeball, meta = (AllowPrivateAccess = "true"))
class USphereComponent* SphereComponent;
```

1.  接下来，在我们的源文件顶部包含`SphereComponent`类：

```cpp
#include "Components/SphereComponent.h"
```

注意

请记住，所有头文件包含都必须在`.generated.h`之前。

现在，前往`DodgeballProjectile`类的构造函数，在其源文件中执行以下步骤。

1.  创建`SphereComponent`对象：

```cpp
SphereComponent = CreateDefaultSubobject<USphereComponent>(TEXT("Sphere   Collision"));
```

1.  将其`半径`设置为`35`个单位：

```cpp
SphereComponent->SetSphereRadius(35.f);
```

1.  将其`碰撞预设`设置为我们创建的`Dodgeball`预设：

```cpp
SphereComponent->SetCollisionProfileName(FName("Dodgeball"));
```

1.  我们希望`Dodgeball`模拟物理，因此通知组件进行如下所示的设置：

```cpp
SphereComponent->SetSimulatePhysics(true);
```

1.  我们希望`Dodgeball`在模拟物理时调用`OnHit`事件，因此调用`SetNotifyRigidBodyCollision`函数以将其设置为`true`（这与我们在对象属性的`Collision`部分看到的`SimulationGeneratesHitEvents`属性相同）：

```cpp
//Simulation generates Hit events
SphereComponent->SetNotifyRigidBodyCollision(true);
```

我们还希望监听`SphereComponent`的`OnHit`事件。

1.  在`DodgeballProjectile`类的头文件中为将在`OnHit`事件触发时调用的函数创建声明。此函数应该被命名为`OnHit`。它应该是`public`，不返回任何内容（`void`），具有`UFUNCTION`宏，并按照以下顺序接收一些参数：

+   `UPrimitiveComponent* HitComp`：被击中并属于此演员的组件。原始组件是具有`Transform`属性和某种几何形状（例如`Mesh`或`Shape`组件）的演员组件。

+   `AActor* OtherActor`：碰撞中涉及的另一个演员。

+   `UPrimitiveComponent* OtherComp`：被击中并属于其他演员的组件。

+   `FVector NormalImpulse`：对象被击中后将移动的方向，以及以多大的力（通过检查向量的大小）。此参数仅对模拟物理的对象是非零的。

+   `FHitResult& Hit`：碰撞结果的数据，包括此对象与其他对象之间的碰撞。正如我们在上一章中看到的，它包含诸如`Hit`位置、法线、击中的组件和演员等属性。大部分相关信息已经通过其他参数可用，但如果需要更详细的信息，可以访问此参数：

```cpp
UFUNCTION()
void OnHit(UPrimitiveComponent* HitComp, AActor* OtherActor,   UPrimitiveComponent* OtherComp, FVector NormalImpulse, const   FHitResult& Hit);
```

将`OnHit`函数的实现添加到类的源文件中，并在该函数中，至少暂时，当它击中玩家时销毁躲避球。

1.  将`OtherActor`参数转换为我们的`DodgeballCharacter`类，并检查该值是否不是`nullptr`。如果不是，则表示我们击中的其他演员是`DodgeballCharacter`，我们将销毁此`DodgeballProjectile`演员：

```cpp
void ADodgeballProjectile::OnHit(UPrimitiveComponent *   HitComp, AActor * OtherActor, UPrimitiveComponent *   OtherComp, FVector NormalImpulse, const FHitResult & Hit)
{
  if (Cast<ADodgeballCharacter>(OtherActor) != nullptr)
  {
    Destroy();
  }
}
```

鉴于我们正在引用`DodgebalCharacter`类，我们需要在此类的源文件顶部包含它：

```cpp
#include "DodgeballCharacter.h"
```

注意

在下一章中，我们将更改此函数，使得躲避球在销毁自身之前对玩家造成伤害。我们将在讨论 Actor 组件时进行此操作。

1.  返回`DodgeballProjectile`类的构造函数，并在末尾添加以下行，以便监听`SphereComponent`的`OnHit`事件：

```cpp
// Listen to the OnComponentHit event by binding it to our   function
SphereComponent->OnComponentHit.AddDynamic(this,   &ADodgeballProjectile::OnHit);
```

这将绑定我们创建的`OnHit`函数到这个`SphereComponent`的`OnHit`事件（因为这是一个演员组件，此事件称为`OnComponentHit`），这意味着我们的函数将与该事件一起被调用。

1.  最后，将`SphereComponent`设置为该演员的`RootComponent`，如下面的代码片段所示：

```cpp
// Set this Sphere Component as the root component,
// otherwise collision won't behave properly
RootComponent = SphereComponent;
```

注意

为了使移动的演员在碰撞时正确行为，无论是否模拟物理，通常需要将演员的主要碰撞组件设置为其`RootComponent`。

例如，`Character`类的`RootComponent`是 Capsule Collider 组件，因为该演员将在周围移动，该组件是角色与环境碰撞的主要方式。

现在我们已经添加了`DodgeballProjectile`C++类的逻辑，让我们继续创建我们的蓝图类。

1.  编译更改并打开编辑器。

1.  转到内容浏览器中的`Content` > `ThirdPersonCPP` > `Blueprints`目录，右键单击，创建一个新的蓝图类。

1.  展开“所有类”部分，搜索`DodgeballProjectile`类，然后将其设置为父类。

1.  将新的蓝图类命名为`BP_DodgeballProjectile`。

1.  打开这个新的蓝图类。

1.  注意演员视口窗口中`SphereCollision`组件的线框表示（默认情况下在游戏过程中隐藏，但可以通过更改此组件的`Rendering`部分中的`HiddenInGame`属性来更改该属性）：![图 6.8：SphereCollision 组件的视觉线框表示](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_06_08.jpg)

图 6.8：SphereCollision 组件的视觉线框表示

1.  现在，添加一个新的`球体`网格作为现有的`球体碰撞`组件的子级：![图 6.9：添加一个球体网格](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_06_09.jpg)

图 6.9：添加一个球体网格

1.  将其比例更改为`0.65`，如下图所示：![图 6.10：更新比例](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_06_10.jpg)

图 6.10：更新比例

1.  将其`碰撞预设`设置为`无碰撞`：![图 6.11：更新碰撞预设为无碰撞](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_06_11.jpg)

图 6.11：更新碰撞预设为无碰撞

1.  最后，打开我们的关卡，并在玩家附近放置一个`BP_DodgeballProjectile`类的实例（这个实例放置在 600 单位的高度）：![图 6.12：躲避球在地面上弹跳](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_06_12.jpg)

图 6.12：躲避球在地面上弹跳

完成这些操作后，玩这个关卡。你会注意到躲避球会受到重力的影响，在触地几次后停止下来。

通过完成这个练习，你已经创建了一个行为像物理对象的对象。

现在你知道如何创建自己的碰撞对象类型，使用`OnHit`事件，并更改对象的碰撞属性。

注意

在上一章中，我们简要提到了`LineTraceSingleByObjectType`。现在我们知道对象碰撞是如何工作的，我们可以简要提到它的用法：当执行检查追踪通道的线追踪时，应该使用`LineTraceSingleByChannel`函数；当执行检查`对象`通道（对象类型）的线追踪时，应该使用`LineTraceSingleByObjectType`函数。应该明确指出，与`LineTraceSingleByChannel`函数不同，这个函数不会检查阻挡特定对象类型的对象，而是检查特定对象类型的对象。这两个函数具有完全相同的参数，追踪通道和对象通道都可以通过`ECollisionChannel`枚举来使用。

但是，如果你想让球在地板上弹跳更多次呢？如果你想让它更有弹性呢？那么物理材料就派上用场了。

# 物理材料

在 UE4 中，你可以通过物理材料来自定义对象在模拟物理时的行为方式。为了进入这种新类型的资产，让我们创建我们自己的：

1.  在`内容`文件夹内创建一个名为`物理`的新文件夹。

1.  *在*该文件夹内的`内容浏览器`上右键单击，并在`创建高级资产`部分下，转到`物理`子部分并选择`物理材料`。

1.  将这个新的物理材料命名为`PM_Dodgeball`。

1.  打开资产并查看可用选项。![图 6.13：资产选项](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_06_13.jpg)

图 6.13：资产选项

我们应该注意的主要选项如下：

+   `摩擦`：此属性从`0`到`1`，指定摩擦对这个对象的影响程度（`0`表示此对象会像在冰上一样滑动，而`1`表示此对象会像一块口香糖一样粘住）。

+   `弹性`（也称为*弹性*）：此属性从`0`到`1`，指定与另一个对象碰撞后保留多少速度（`0`表示此对象永远不会从地面上弹跳，而`1`表示此对象将长时间弹跳）。

+   `密度`：此属性指定这个对象有多密集（即相对于其网格有多重）。两个对象可以是相同大小的，但如果一个比另一个密度高两倍，那就意味着它会重两倍。

为了让我们的`DodgeballProjectile`对象更接近实际的躲避球，它将不得不承受相当大的摩擦（默认值为`0.7`，足够高），并且非常有弹性。让我们将这个物理材料的`弹性`属性增加到`0.95`。

完成这些操作后，打开`BP_DodgeballProjectile`蓝图类，并在其`碰撞`部分内更改球体碰撞组件的物理材料为我们刚刚创建的`PM_Dodgeball`：

![图 6.14：更新 BP_DodgeballProjectile 蓝图类](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_06_14.jpg)

图 6.14：更新 BP_DodgeballProjectile 蓝图类

注意

确保您在级别中添加的躲避球角色实例也具有这种物理材料。

如果您再次玩我们在*练习 6.01*中创建的级别，*创建躲避球类*，您会注意到我们的`BP_DodgeballProjectile`现在会在停止之前在地面上反弹几次，行为更像一个真正的躲避球。

做完所有这些之后，我们只缺少一个东西，让我们的`Dodgeball`角色行为像一个真正的躲避球。现在，我们没有办法投掷它。所以，让我们通过创建一个投射物移动组件来解决这个问题，这就是我们下一个练习要做的事情。

在之前的章节中，当我们复制第三人称模板项目时，我们了解到 UE4 自带的`Character`类具有`CharacterMovementComponent`。这个角色组件是允许角色以各种方式在级别中移动的，它有许多属性，允许您根据自己的喜好进行自定义。然而，还有另一个经常使用的移动组件：`ProjectileMovementComponent`。

`ProjectileMovementComponent`角色组件用于将投射物的行为赋予角色。它允许您设置初始速度、重力力量，甚至一些物理模拟参数，如“弹性”和“摩擦力”。然而，鉴于我们的`Dodgeball Projectile`已经在模拟物理，我们将使用的唯一属性是`InitialSpeed`。

## 练习 6.02：向 DodgeballProjectile 添加一个投射物移动组件

在这个练习中，我们将向我们的`DodgeballProjectile`添加一个`ProjectileMovementComponent`，以便它具有初始的水平速度。我们这样做是为了让我们的敌人可以投掷它，而不仅仅是垂直下落。

以下步骤将帮助您完成这个练习：

1.  在`DodgeballProjectile`类的头文件中添加一个`ProjectileMovementComponent`属性：

```cpp
UPROPERTY(VisibleAnywhere, BlueprintReadOnly, Category =   Dodgeball, meta = (AllowPrivateAccess = "true"))
class UProjectileMovementComponent* ProjectileMovement;
```

1.  在类的源文件顶部包含`ProjectileMovementComponent`类：

```cpp
#include "GameFramework/ProjectileMovementComponent.h"
```

1.  在类的构造函数末尾，创建`ProjectileMovementComponent`对象：

```cpp
ProjectileMovement = CreateDefaultSubobject<UProjectileMovementComponent>(TEXT("Pro   jectile Movement"));
```

1.  然后，将其`InitialSpeed`设置为`1500`单位：

```cpp
ProjectileMovement->InitialSpeed = 1500.f;
```

完成此操作后，编译您的项目并打开编辑器。为了演示躲避球的初始速度，将其在*Z*轴上降低，并将其放在玩家后面（*这个放置在高度为 200 单位的位置*）：

![图 6.15：躲避球沿 X 轴移动](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_06_15.jpg)

图 6.15：躲避球沿 X 轴移动

当您玩这个级别时，您会注意到躲避球开始朝着它的*X*轴移动（*红色箭头*）：

有了这个，我们可以结束我们的练习了。我们的`DodgeballProjectile`现在的行为就像一个真正的躲避球。它下落，弹跳，被投掷。

我们项目的下一步是为我们的`EnemyCharacter`添加逻辑，使其向玩家投掷这些躲避球，但在解决这个问题之前，我们必须先解决计时器的概念。

# 计时器

鉴于视频游戏的性质以及它们是强烈基于事件的，每个游戏开发工具都必须有一种方法让您在发生某事之前引起延迟或等待时间。例如，当您玩在线死亡竞赛游戏时，您的角色可以死亡然后重生，通常情况下，重生事件不会在您的角色死亡后立即发生，而是几秒钟后。有很多情况下，您希望某事发生，但只能在一定时间后发生。这将是我们的`EnemyCharacter`的情况，它将每隔几秒钟投掷一次躲避球。这种延迟或等待时间可以通过计时器实现。

**定时器**允许您在一定时间后调用一个函数。您可以选择以一定的时间间隔循环调用该函数，并在循环开始之前设置延迟。如果要停止定时器，也可以这样做。

我们将使用定时器，这样我们的敌人就可以每隔`X`时间投掷一个躲避球，只要它能看到玩家角色，并且当敌人不能再看到其目标时停止定时器。

在我们开始为`EnemyCharacter`类添加逻辑，使其向玩家投掷躲避球之前，我们应该看一下另一个主题，即如何生成演员。

# 生成演员

在*第一章*，*虚幻引擎介绍*中，您学会了如何通过编辑器在级别中放置您创建的演员，但是如果您想在游戏进行时将该演员放置在级别中呢？这就是我们现在要看的。

UE4，就像大多数其他游戏开发工具一样，允许您在游戏运行时放置一个演员。这个过程称为`SpawnActor`函数，可从`World`对象（我们可以使用之前提到的`GetWorld`函数访问）中获得。但是，`SpawnActor`函数有一些需要传递的参数，如下所示：

+   一个`UClass*`属性，让函数知道将要生成的对象的类。这个属性可以是一个 C++类，通过`NameOfC++Class::StaticClass()`函数可用，也可以是一个蓝图类，通过`TSubclassOf`属性可用。通常最好不要直接从 C++类生成演员，而是创建一个蓝图类并生成该类的实例。

+   `TSubclassOf`属性是您在 C++中引用蓝图类的一种方式。它用于在 C++代码中引用一个类，该类可能是蓝图类。您使用模板参数声明`TSubclassOf`属性，该参数是该类必须继承的 C++类。我们将在下一个练习中看一下如何在实践中使用这个属性。

+   无论是`FTransform`属性还是`FVector`和`FRotator`属性，都将指示我们想要生成的对象的位置、旋转和比例。

+   一个可选的`FActorSpawnParameters`属性，允许您指定与生成过程相关的更多属性，例如谁导致演员生成（即`Instigator`），如何处理对象生成，如果生成位置被其他对象占用，可能会导致重叠或阻塞事件等。

`SpawnActor`函数将返回从此函数生成的演员的实例。鉴于它也是一个模板函数，您可以以这样的方式调用它，以便使用模板参数直接接收到您生成的演员类型的引用：

```cpp
GetWorld()->SpawnActor<NameOfC++Class>(ClassReference,   SpawnLocation, SpawnRotation);
```

在这种情况下，正在调用`SpawnActor`函数，我们正在生成`NameOfC++Class`类的一个实例。在这里，我们使用`ClassReference`属性提供对类的引用，并使用`SpawnLocation`和`SpawnRotation`属性分别提供要生成的演员的位置和旋转。

您将在*练习 6.03*，*向 EnemyCharacter 添加投掷项目逻辑*中学习如何应用这些属性。

在继续练习之前，我想简要提一下`SpawnActor`函数的一个变体，这也可能会派上用场：`SpawnActorDeferred`函数。`SpawnActor`函数将创建您指定的对象的实例，然后将其放置在世界中，而这个新的`SpawnActorDeferred`函数将创建您想要的对象的实例，并且只有在调用演员的`FinishSpawning`函数时才将其放置在世界中。

例如，假设我们想在生成 Dodgeball 时更改其`InitialSpeed`。如果我们使用`SpawnActor`函数，Dodgeball 有可能在我们设置其`InitialSpeed`属性之前开始移动。然而，通过使用`SpawnActorDeferred`函数，我们可以创建一个 dodge ball 的实例，然后将其`InitialSpeed`设置为我们想要的任何值，然后通过调用新创建的 dodgeball 的`FinishSpawning`函数将其放置在世界中，该函数的实例由`SpawnActorDeferred`函数返回给我们。

现在我们知道如何在世界中生成一个 actor，也知道定时器的概念，我们可以在下一个练习中向我们的`EnemyCharacter`类添加负责投掷 dodge 球的逻辑。

## 练习 6.03：向 EnemyCharacter 添加投掷投射物的逻辑

在这个练习中，我们将向我们刚刚创建的`EnemyCharacter`类添加负责投掷 Dodgeball actor 的逻辑。

在 Visual Studio 中打开类的文件以开始。我们将首先修改我们的`LookAtActor`函数，以便我们可以保存告诉我们是否能看到玩家的值，并用它来管理我们的定时器。

按照以下步骤完成这个练习：

1.  在`EnemyCharacter`类的头文件中，将`LookAtActor`函数的返回类型从`void`更改为`bool`：

```cpp
// Change the rotation of the character to face the given   actor
// Returns whether the given actor can be seen
bool LookAtActor(AActor* TargetActor);
```

1.  在函数的实现中做同样的事情，在类的源文件中，同时在我们调用`CanSeeActor`函数的`if`语句结束时返回`true`。还在我们检查`TargetActor`是否为`nullptr`的第一个`if`语句中返回`false`，并在函数的结尾返回`false`：

```cpp
bool AEnemyCharacter::LookAtActor(AActor * TargetActor)
{
  if (TargetActor == nullptr) return false;
  if (CanSeeActor(TargetActor))
  {
    FVector Start = GetActorLocation();
    FVector End = TargetActor->GetActorLocation();
    // Calculate the necessary rotation for the Start point to   face the End point
    FRotator LookAtRotation = UKismetMathLibrary::FindLookAtRotation(Start, End);
    //Set the enemy's rotation to that rotation
    SetActorRotation(LookAtRotation);
    return true;
  }
  return false;
}
```

1.  接下来，在你的类头文件中添加两个`bool`属性，`bCanSeePlayer`和`bPreviousCanSeePlayer`，设置为`protected`，它们将表示敌人角色在这一帧中是否能看到玩家，以及上一帧中玩家是否能被看到：

```cpp
//Whether the enemy can see the player this frame
bool bCanSeePlayer = false;
//Whether the enemy could see the player last frame
bool bPreviousCanSeePlayer = false;
```

1.  然后，转到你的类的`Tick`函数实现，并将`bCanSeePlayer`的值设置为`LookAtActor`函数的返回值。这将替换对`LookAtActor`函数的先前调用：

```cpp
// Look at the player character every frame
bCanSeePlayer = LookAtActor(PlayerCharacter);
```

1.  然后，将`bPreviousCanSeePlayer`的值设置为`bCanSeePlayer`的值：

```cpp
bPreviousCanSeePlayer = bCanSeePlayer;
```

1.  在前两行之间添加一个`if`语句，检查`bCanSeePlayer`和`bPreviousCanSeePlayer`的值是否不同。这意味着我们上一帧看不到玩家，现在可以看到，或者我们上一帧看到玩家，现在看不到：

```cpp
bCanSeePlayer = LookAtActor(PlayerCharacter);
if (bCanSeePlayer != bPreviousCanSeePlayer)
{
}
bPreviousCanSeePlayer = bCanSeePlayer;
```

1.  在这个`if`语句中，如果我们能看到玩家，我们希望启动一个定时器，如果我们不能再看到玩家，就停止定时器：

```cpp
if (bCanSeePlayer != bPreviousCanSeePlayer)
{
  if (bCanSeePlayer)
  {
    //Start throwing dodgeballs
  }
  else
  {
    //Stop throwing dodgeballs
  }
}
```

1.  为了启动一个定时器，我们需要在类的头文件中添加以下属性，它们都可以是`protected`：

+   一个`FTimerHandle`属性，负责标识我们要启动的定时器。它基本上作为特定定时器的标识符：

```cpp
FTimerHandle ThrowTimerHandle;
```

+   一个`float`属性，表示投掷 dodgeball 之间等待的时间（间隔），以便我们可以循环定时器。我们给它一个默认值`2`秒：

```cpp
float ThrowingInterval = 2.f;
```

+   另一个`float`属性，表示定时器开始循环之前的初始延迟。让我们给它一个默认值`0.5`秒：

```cpp
float ThrowingDelay = 0.5f;
```

+   一个在定时器结束时调用的函数，我们将创建并命名为`ThrowDodgeball`。这个函数不返回任何值，也不接收任何参数：

```cpp
void ThrowDodgeball();
```

在我们的源文件中，为了调用适当的函数启动定时器，我们需要添加一个`#include`到负责这个的对象`FTimerManager`。

每个`World`都有一个定时器管理器，它可以启动和停止定时器，并访问与它们相关的相关函数，比如它们是否仍然活动，它们运行了多长时间等等：

```cpp
#include "TimerManager.h"
```

1.  现在，使用`GetWorldTimerManager`函数访问当前世界的定时器管理器：

```cpp
GetWorldTimerManager()
```

1.  接下来，如果我们能看到玩家角色，就调用定时器管理器的`SetTimer`函数，以启动负责投掷躲避球的计时器。`SetTimer`函数接收以下参数：

+   代表所需计时器的`FTimerHandle`：`ThrowTimerHandle`。

+   要调用的函数所属的对象：`this`。

+   要调用的函数，必须通过在其名称前加上`&ClassName::`来指定，得到`&AEnemyCharacter::ThrowDodgeball`。

+   计时器的速率或间隔：`ThrowingInterval`。

+   这个计时器是否会循环：`true`。

+   这个计时器开始循环之前的延迟：`ThrowingDelay`。

以下代码片段包括这些参数：

```cpp
if (bCanSeePlayer)
{
  //Start throwing dodgeballs
  GetWorldTimerManager().SetTimer(ThrowTimerHandle,this,  &AEnemyCharacter::ThrowDodgeball,ThrowingInterval,true,  ThrowingDelay);
}
```

1.  如果我们看不到玩家并且想要停止计时器，可以使用`ClearTimer`函数来实现。这个函数只需要接收一个`FTimerHandle`属性作为参数：

```cpp
else
{
  //Stop throwing dodgeballs
  GetWorldTimerManager().ClearTimer(ThrowTimerHandle);
}
```

现在唯一剩下的就是实现`ThrowDodgeball`函数。这个函数将负责生成一个新的`DodgeballProjectile`角色。为了做到这一点，我们需要一个引用要生成的类，它必须继承自`DodgeballProjectile`，所以下一步我们需要使用`TSubclassOf`对象创建适当的属性。

1.  在`EnemyCharacter`头文件中创建`TSubclassOf`属性，可以是`public`：

```cpp
//The class used to spawn a dodgeball object
UPROPERTY(EditDefaultsOnly, BlueprintReadOnly, Category =   Dodgeball)
TSubclassOf<class ADodgeballProjectile> DodgeballClass;
```

1.  因为我们将使用`DodgeballProjectile`类，所以我们还需要在`EnemyCharacter`源文件中包含它：

```cpp
#include "DodgeballProjectile.h"
```

1.  然后，在源文件中`ThrowDodgeball`函数的实现中，首先检查这个属性是否为`nullptr`。如果是，我们立即`return`：

```cpp
void AEnemyCharacter::ThrowDodgeball()
{
  if (DodgeballClass == nullptr)
  {
    return;
  }
}
```

1.  接下来，我们将从该类中生成一个新的角色。它的位置将在敌人前方`40`个单位，旋转角度与敌人相同。为了在敌人前方生成躲避球，我们需要访问敌人的`ForwardVector`属性，这是一个单位`FVector`（*意味着它的长度为 1*），表示角色面对的方向，并将其乘以我们想要生成躲避球的距离，即`40`个单位：

```cpp
FVector ForwardVector = GetActorForwardVector();
float SpawnDistance = 40.f;
FVector SpawnLocation = GetActorLocation() + (ForwardVector *   SpawnDistance);
//Spawn new dodgeball
GetWorld()->SpawnActor<ADodgeballProjectile>(DodgeballClass,   SpawnLocation, GetActorRotation());
```

这完成了我们需要对`EnemyCharacter`类进行的修改。在完成设置此逻辑的蓝图之前，让我们快速修改一下我们的`DodgeballProjectile`类。

1.  在 Visual Studio 中打开`DodgeballProjectile`类的源文件。

1.  在其`BeginPlay`事件中，将其`LifeSpan`设置为`5`秒。这个属性属于所有角色，规定了它们在游戏中还会存在多久才会被销毁。通过在`BeginPlay`事件中将我们的躲避球的`LifeSpan`设置为`5`秒，我们告诉 UE4 在它生成后 5 秒后销毁该对象（*或者，如果它已经放置在关卡中，在游戏开始后 5 秒*）。我们这样做是为了避免在一定时间后地板上充满了躲避球，这会让游戏对玩家来说变得意外困难：

```cpp
void ADodgeballProjectile::BeginPlay()
{
  Super::BeginPlay();

  SetLifeSpan(5.f);
}
```

现在我们已经完成了与`EnemyCharacter`类的躲避球投掷逻辑相关的 C++逻辑，让我们编译我们的更改，打开编辑器，然后打开我们的`BP_EnemyCharacter`蓝图。在那里，转到`Class Defaults`面板，并将`DodgeballClass`属性的值更改为`BP_DodgeballProjectile`：

![图 6.16：更新躲避球类](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_06_16.jpg)

图 6.16：更新躲避球类

完成后，如果还在的话，可以移除我们在关卡中放置的`BP_DodgeballProjectile`类的现有实例。

现在，我们可以玩我们的关卡。你会注意到敌人几乎立即开始向玩家投掷躲避球，并且只要玩家角色在视线中，它就会继续这样做：

![图 6.17：敌人角色在玩家视线中投掷躲避球](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_06_17.jpg)

图 6.17：敌人角色在玩家视线中投掷躲避球

有了这个，我们已经完成了`EnemyCharacter`的躲避球投掷逻辑。您现在知道如何使用定时器，这是任何游戏程序员的必备工具。

# 墙

我们项目的下一步将是创建`Wall`类。我们将有两种类型的墙：

+   一个普通的墙，它将阻挡敌人的视线，玩家角色和躲避球。

+   一个幽灵墙，它只会阻挡玩家角色，而不会阻挡敌人的视线和躲避球。您可能会在特定类型的益智游戏中找到这种类型的碰撞设置。

我们将在下一个练习中创建这两个 Wall 类。

## 练习 6.04：创建 Wall 类

在这个练习中，我们将创建代表普通`Wall`和`GhostWall`的`Wall`类，后者只会阻挡玩家角色的移动，而不会阻挡敌人的视线或他们投掷的躲避球。

让我们从普通的`Wall`类开始。这个 C++类基本上是空的，因为它唯一需要的是一个网格，以便反射抛射物并阻挡敌人的视线，这将通过其蓝图类添加。

以下步骤将帮助您完成此练习：

1.  打开编辑器。

1.  在内容浏览器的左上角，按绿色的`添加新`按钮。

1.  在顶部选择第一个选项；`添加功能或内容包`。

1.  将会出现一个新窗口。选择`内容包`选项卡，然后选择`Starter Content`包，然后按`添加到项目`按钮。这将向项目中添加一些基本资产，我们将在本章和一些后续章节中使用。

1.  创建一个名为`Wall`的新的 C++类，其父类为`Actor`类。

1.  接下来，在 Visual Studio 中打开类的文件，并将`SceneComponent`添加为我们的 Wall 的`RootComponent`：

+   `Header`文件将如下所示：

```cpp
private:
UPROPERTY(VisibleAnywhere, BlueprintReadOnly, Category = Wall,   meta = (AllowPrivateAccess = "true"))
class USceneComponent* RootScene;
```

+   `Source`文件将如下所示：

```cpp
AWall::AWall()
{
  // Set this actor to call Tick() every frame.  You can turn   this off to improve performance if you don't need it.
  PrimaryActorTick.bCanEverTick = true;
  RootScene = CreateDefaultSubobject<USceneComponent>(TEXT("Root"));
  RootComponent = RootScene;
}
```

1.  编译您的代码并打开编辑器。

1.  接下来，转到内容浏览器中的`Content` > `ThirdPersonCPP` >:`Blueprints`目录，创建一个新的蓝图类，该类继承自`Wall`类，命名为`BP_Wall`，然后打开该资产。

1.  添加一个静态网格组件，并将其`StaticMesh`属性设置为`Wall_400x300`。

1.  将其`Material`属性设置为`M_Metal_Steel`。

1.  将静态网格组件的位置设置在*X*轴上为`-200`单位（*以便网格相对于我们的角色原点居中*）：![图 6.18：更新静态网格组件的位置](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_06_18.jpg)

图 6.18：更新静态网格组件的位置

这是您的蓝图类的视口应该看起来的样子：

![图 6.19：蓝图类的视口墙](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_06_19.jpg)

图 6.19：蓝图类的视口墙

注意

通常最好将`SceneComponent`添加为对象的`RootComponent`，当不需要碰撞组件时，以便允许更多的灵活性与其子组件。

演员的`RootComponent`不能修改其位置或旋转，这就是为什么在我们的情况下，如果我们在 Wall C++类中创建了一个静态网格组件，并将其设置为其 Root Component，而不是使用场景组件，我们将很难对其进行偏移。

现在我们已经设置了常规的`Wall`类，让我们创建我们的`GhostWall`类。因为这些类没有设置任何逻辑，我们只是将`GhostWall`类创建为`BP_Wall`蓝图类的子类，而不是我们的 C++类。

1.  *右键单击*`BP_Wall`资产，然后选择`创建子蓝图类`。

1.  将新的蓝图命名为`BP_GhostWall`。

1.  打开它。

1.  更改静态网格组件的碰撞属性：

+   将其`CollisionPreset`设置为`Custom`。

+   将其响应更改为`EnemySight`和`Dodgeball`通道都为`Overlap`。

1.  将静态网格组件的`Material`属性更改为`M_Metal_Copper`。

您的`BP_GhostWall`的视口现在应该是这样的：

![图 6.20：创建 Ghost Wall](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_06_20.jpg)

图 6.20：创建 Ghost Wall

现在你已经创建了这两个 Wall 角色，将它们放在关卡中进行测试。将它们的变换设置为以下变换值：

+   Wall：`位置`：`(-710, 120, 130)`

+   Ghost Wall：`位置`：`(-910, -100, 130)`；`旋转`：`(0, 0, 90)`：![图 6.21：更新 Ghost Wall 的位置和旋转](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_06_21.jpg)

图 6.21：更新 Ghost Wall 的位置和旋转

最终结果应该是这样的：

![图 6.22：带有 Ghost Wall 和 Wall 的最终结果](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_06_22.jpg)

图 6.22：带有 Ghost Wall 和 Wall 的最终结果

当你把你的角色藏在普通的`Wall`（右边的那个）后面时，敌人不会向玩家扔躲避球；然而，当你试图把你的角色藏在`GhostWall`（左边的那个）后面时，即使敌人无法穿过它，敌人也会向角色扔躲避球，它们会穿过墙壁，就好像它不存在一样！

这就结束了我们的练习。我们已经制作了我们的`Wall`角色，它们将正常运作或者忽略敌人的视线和躲避球！

# 胜利宝盒

我们项目的下一步将是创建`VictoryBox`角色。这个角色将负责在玩家角色进入时结束游戏，前提是玩家已经通过了关卡。为了做到这一点，我们将使用`Overlap`事件。接下来的练习将帮助我们理解 Victory Box。

## 练习 6.05：创建 VictoryBox 类

在这个练习中，我们将创建`VictoryBox`类，当玩家角色进入时，游戏将结束。

以下步骤将帮助你完成这个练习：

1.  创建一个继承自角色的新的 C++类，并将其命名为`VictoryBox`。

1.  在 Visual Studio 中打开该类的文件。

1.  创建一个新的`SceneComponent`属性，它将被用作`RootComponent`，就像我们的`Wall`C++类一样：

+   `Header`文件：

```cpp
private:
UPROPERTY(VisibleAnywhere, BlueprintReadOnly, Category =   VictoryBox, meta = (AllowPrivateAccess = "true"))
class USceneComponent* RootScene;
```

+   `源`文件：

```cpp
AVictoryBox::AVictoryBox()
{
  // Set this actor to call Tick() every frame.  You can turn   this off to improve performance if you don't need it.
  PrimaryActorTick.bCanEverTick = true;
  RootScene =   CreateDefaultSubobject<USceneComponent>(TEXT("Root"));
  RootComponent = RootScene;
}
```

1.  在头文件中声明一个`BoxComponent`，它将检查与玩家角色的重叠事件，也应该是`private`：

```cpp
UPROPERTY(VisibleAnywhere, BlueprintReadOnly, Category =   VictoryBox, meta = (AllowPrivateAccess = "true"))
class UBoxComponent* CollisionBox;
```

1.  在类的源文件中包含`BoxComponent`文件：

```cpp
#include "Components/BoxComponent.h"
```

1.  创建`RootScene`组件后，创建`BoxComponent`，它也应该是`private`：

```cpp
RootScene = CreateDefaultSubobject<USceneComponent>(TEXT("Root"));
RootComponent = RootScene;
CollisionBox =   CreateDefaultSubobject<UBoxComponent>(TEXT("Collision Box"));
```

1.  使用`SetupAttachment`函数将其附加到`RootComponent`：

```cpp
CollisionBox->SetupAttachment(RootComponent);
```

1.  将其`BoxExtent`属性设置为所有轴上的`60`单位。这将使`BoxComponent`的大小加倍为`(120 x 120 x 120)`：

```cpp
CollisionBox->SetBoxExtent(FVector(60.0f, 60.0f, 60.0f));
```

1.  使用`SetRelativeLocation`函数将其相对位置在*Z*轴上偏移`120`单位：

```cpp
CollisionBox->SetRelativeLocation(FVector(0.0f, 0.0f,   120.0f));
```

1.  现在，你需要一个函数来监听`BoxComponent`的`OnBeginOverlap`事件。每当一个对象进入`BoxComponent`时，这个事件将被调用。这个函数必须在`UFUNCTION`宏之前，是`public`的，不返回任何内容，并具有以下参数：

```cpp
UFUNCTION()
void OnBeginOverlap(UPrimitiveComponent* OverlappedComp,   AActor* OtherActor, UPrimitiveComponent* OtherComp, int32   OtherBodyIndex, bool bFromSweep, const FHitResult&   SweepResult);
```

参数如下：

+   `UPrimitiveComponent* OverlappedComp`：被重叠并属于该角色的组件。

+   `AActor* OtherActor`：参与重叠的其他角色。

+   `UPrimitiveComponent* OtherComp`：被重叠并属于其他角色的组件。

+   `int32 OtherBodyIndex`：被击中的原始中的项目索引（通常对于实例化静态网格组件很有用）。

+   `bool bFromSweep`：重叠是否起源于扫描跟踪。

+   `FHitResult& SweepResult`：由该对象与其他对象之间的碰撞产生的扫描跟踪的数据。

注意

虽然我们在这个项目中不会使用`OnEndOverlap`事件，但你很可能以后会需要使用它，所以这是该事件的必需函数签名，它看起来与我们刚刚学到的那个函数非常相似：

`UFUNCTION()`

`void OnEndOverlap(UPrimitiveComponent* OverlappedComp, AActor* OtherActor, UPrimitiveComponent* OtherComp, int32 OtherBodyIndex);`

1.  接下来，我们需要将这个函数绑定到`BoxComponent`的`OnComponentBeginOverlap`事件上：

```cpp
CollisionBox->OnComponentBeginOverlap.AddDynamic(this,   &AVictoryBox::OnBeginOverlap);
```

1.  在我们的`OnBeginOverlap`函数实现中，我们将检查我们重叠的角色是否是`DodgeballCharacter`。因为我们将引用这个类，所以我们也需要包括它：

```cpp
#include "DodgeballCharacter.h" 
void AVictoryBox::OnBeginOverlap(UPrimitiveComponent *   OverlappedComp, AActor * OtherActor, UPrimitiveComponent *   OtherComp, int32 OtherBodyIndex, bool bFromSweep, const   FHitResult & SweepResult)
{
  if (Cast<ADodgeballCharacter>(OtherActor))
  {
  }
}
```

如果我们重叠的角色是`DodgeballCharacter`，我们想要退出游戏。

1.  我们将使用`KismetSystemLibrary`来实现这个目的。`KismetSystemLibrary`类包含了在项目中通用使用的有用函数：

```cpp
#include "Kismet/KismetSystemLibrary.h"
```

1.  为了退出游戏，我们将调用`KismetSystemLibrary`的`QuitGame`函数。这个函数接收以下内容：

```cpp
UKismetSystemLibrary::QuitGame(GetWorld(),
  nullptr,
  EQuitPreference::Quit,
  true);
```

前面代码片段中的重要参数解释如下：

+   一个`World`对象，我们可以用`GetWorld`函数访问。

+   一个`PlayerController`对象，我们将设置为`nullptr`。我们这样做是因为这个函数会自动这样找到一个。

+   一个`EQuitPreference`对象，表示我们想要结束游戏的方式，是退出还是只将其作为后台进程。我们希望实际退出游戏，而不只是将其作为后台进程。

+   一个`bool`，表示我们是否想要忽略平台的限制来退出游戏，我们将设置为`true`。

接下来，我们将创建我们的蓝图类。

1.  编译你的更改，打开编辑器，转到“内容”→`ThirdPersonCPP`→“蓝图”目录，在“内容浏览器”中创建一个继承自`VictoryBox`的新蓝图类，并命名为`BP_VictoryBox`。打开该资产并进行以下修改：

+   添加一个新的静态网格组件。

+   将其`StaticMesh`属性设置为`Floor_400x400`。

+   将其“材质”属性设置为`M_Metal_Gold`。

+   将其比例设置为所有三个轴上的`0.75`单位。

+   将其位置设置为“（-150，-150，20）”，分别在*X*、*Y*和*Z*轴上。

在你做出这些改变之后，你的蓝图的视口选项卡应该看起来像这样：

![图 6.23：胜利盒放置在蓝图的视口选项卡中](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_06_23.jpg)

图 6.23：胜利盒放置在蓝图的视口选项卡中

将蓝图放在你的关卡中以测试其功能：

![图 6.24：用于测试的胜利盒蓝图在关卡中](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_06_24.jpg)

图 6.24：用于测试的胜利盒蓝图在关卡中

如果你玩这个关卡并踏上金色的板子（并重叠碰撞箱），你会注意到游戏突然结束，这是预期的。

有了这个，我们结束了`VictoryBox`类！你现在知道如何在你自己的项目中使用重叠事件。使用这些事件，你可以创建多种游戏机制，恭喜你完成了这个练习。

我们现在非常接近完成本章的结尾，我们将完成一个新的活动，但首先，我们需要对我们的`DodgeballProjectile`类进行一些修改，即在下一个练习中添加一个 getter 函数到它的`ProjectileMovementComponent`。

一个 getter 函数是一个只返回特定属性并且不做其他事情的函数。这些函数通常被标记为内联，这意味着当代码编译时，对该函数的调用将简单地被替换为它的内容。它们通常也被标记为`const`，因为它们不修改类的任何属性。

## 练习 6.06：在 DodgeballProjectile 中添加 ProjectileMovementComponent Getter 函数

在这个练习中，我们将向`DodgeballProjectile`类的`ProjectileMovement`属性添加一个 getter 函数，以便其他类可以访问它并修改它的属性。我们将在本章的活动中做同样的事情。

为了做到这一点，你需要按照以下步骤进行：

1.  在 Visual Studio 中打开`DodgeballProjectile`类的头文件。

1.  添加一个名为`GetProjectileMovementComponent`的新`public`函数。这个函数将是一个内联函数，在 UE4 的 C++版本中用`FORCEINLINE`宏替换。该函数还应返回一个`UProjectileMovementComponent*`并且是一个`const`函数：

```cpp
FORCEINLINE class UProjectileMovementComponent*   GetProjectileMovementComponent() const
{
  return ProjectileMovement;
}
```

注意

在特定函数使用`FORCEINLINE`宏时，不能将该函数的声明添加到头文件中，然后将其实现添加到源文件中。两者必须同时在头文件中完成，如前所示。

通过这样做，我们完成了这个快速练习。在这里，我们为`DodgeballProjectile`类添加了一个简单的`getter`函数，我们将在本章的活动中使用它，在这里，我们将在`EnemyCharacter`类中用`SpawnActorDeferred`函数替换`SpawnActor`函数。这将允许我们在生成实例之前安全地编辑`DodgeballProjectile`类的属性。

## 活动 6.01：在 EnemyCharacter 中用 SpawnActorDeferred 替换 SpawnActor 函数

在这个活动中，您将更改 EnemyCharacter 的`ThrowDodgeball`函数，以便使用`SpawnActorDeferred`函数而不是`SpawnActor`函数，以便在生成之前更改`DodgeballProjectile`的`InitialSpeed`。

以下步骤将帮助您完成此活动：

1.  在 Visual Studio 中打开`EnemyCharacter`类的源文件。

1.  转到`ThrowDodgeball`函数的实现。

1.  因为`SpawnActorDeferred`函数不能只接收生成位置和旋转属性，而必须接收一个`FTransform`属性，所以我们需要在调用该函数之前创建一个。让我们称之为`SpawnTransform`，并按顺序发送生成旋转和位置作为其构造函数的输入，这将是这个敌人的旋转和`SpawnLocation`属性，分别。

1.  然后，将`SpawnActor`函数调用更新为`SpawnActorDeferred`函数调用。将生成位置和生成旋转作为其第二个和第三个参数发送，将这些替换为我们刚刚创建的`SpawnTransform`属性作为第二个参数。

1.  确保将此函数调用的返回值保存在名为`Projectile`的`ADodgeballProjectile*`属性中。

完成此操作后，您将成功创建一个新的`DodgeballProjectile`对象。但是，我们仍然需要更改其`InitialSpeed`属性并实际生成它。

1.  调用`SpawnActorDeferred`函数后，调用`Projectile`属性的`GetProjectileMovementComponent`函数，该函数返回其 Projectile Movement Component，并将其`InitialSpeed`属性更改为`2200`单位。

1.  因为我们将在`EnemyCharacter`类中访问属于 Projectile Movement Component 的属性，所以我们需要像在*Exercise 6.02*，*Adding a Projectile Movement Component to DodgeballProjectile*中那样包含该组件。

1.  在更改`InitialSpeed`属性的值后，唯一剩下的事情就是调用`Projectile`属性的`FinishSpawning`函数，该函数将接收我们创建的`SpawnTransform`属性作为参数。

1.  完成此操作后，编译更改并打开编辑器。

预期输出：

![图 6.25：向玩家投掷躲避球](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_06_25.jpg)

图 6.25：向玩家投掷躲避球

注意

此活动的解决方案可在以下网址找到：[`packt.live/338jEBx`](https://packt.live/338jEBx)。

通过完成此活动，您已巩固了`SpawnActorDeferred`函数的使用，并知道如何在将来的项目中使用它。

# 总结

在本章中，您已经学会了如何使用物理模拟影响对象，创建自己的对象类型和碰撞预设，使用`OnHit`，`OnBeginOverlap`和`OnEndOverlap`事件，更新对象的物理材料以及使用定时器。

现在你已经学会了碰撞主题的这些基本概念，你将能够想出新的创造性方式来运用它们，从而创建你自己的项目。

在下一章中，我们将看一下角色组件、接口和蓝图函数库，这些对于保持项目的复杂性可控和高度模块化非常有用，因此可以轻松地将一个项目的部分添加到另一个项目中。


# 第七章：用户界面

概述

在本章中，我们将继续我们在过去几章中一直在进行的基于躲避球的游戏的工作。我们将通过学习游戏 UI（用户界面）及其形式之一，即菜单和 HUD，来继续这个项目。到本章结束时，您将能够使用 UE4 的游戏 UI 系统 UMG 来制作一个带有可交互按钮的菜单，以及通过进度条显示玩家角色当前生命值的 HUD。

# 介绍

在上一章中，我们学习了通用工具，这些工具允许您通过使用蓝图函数库、角色组件和接口来正确结构化和组织项目中的代码和资产。

在本章中，我们将深入探讨游戏 UI 的主题，这是几乎每个视频游戏中都存在的东西。游戏 UI 是向玩家展示信息的主要方式之一，例如他们还剩下多少条命，他们的武器里有多少子弹，他们携带的武器是什么等等，并且允许玩家通过选择是否继续游戏、创建新游戏、选择要在哪个级别中玩等方式与游戏进行交互。这通常以图像和文本的形式展示给玩家。

**用户界面**或**UI**通常添加在游戏的渲染之上，这意味着它们位于游戏中您看到的所有其他内容的前面，并且行为类似于图层（您可以像在 Photoshop 中一样将它们叠加在彼此之上）。但是，也有一个例外：*直接 UI*。这种类型的 UI 不是分层到游戏的屏幕上，而是存在于游戏本身之内。一个很好的例子可以在游戏*死亡空间*中找到，在这个游戏中，您以第三人称视角控制一个角色，并且可以通过观察连接到他们背部的装置来看到他们的生命值，这是在游戏世界内部。

# 游戏 UI

通常有两种不同类型的游戏 UI：**菜单**和**HUD**。

菜单是允许玩家与之交互的 UI 面板，可以通过按下输入设备上的按钮或键来实现。

这可以通过许多不同的菜单形式来实现，包括以下内容：

+   主菜单，玩家可以选择是否继续游戏、创建新游戏、退出游戏等等

+   级别选择菜单，玩家可以选择要玩的级别

+   以及其他许多选项

HUD 是游戏过程中存在的 UI 面板，向玩家提供他们应该始终知道的信息，例如他们还剩下多少条命，他们可以使用哪些特殊能力等等。

在本章中，我们将涵盖游戏 UI，并为我们的游戏制作菜单和 HUD。

注意

我们不会在这里涵盖直接 UI，因为它超出了本书的范围。

那么我们如何在 UE4 中创建游戏 UI 呢？这样做的主要方式是使用**虚幻运动图形**（**UMG**），这是一种工具，允许您制作游戏 UI（在 UE4 术语中也称为小部件），包括菜单和 HUD，并将它们添加到屏幕上。

让我们在下一节中深入探讨这个主题。

# UMG 基础知识

在 UE4 中，创建游戏 UI 的主要方式是使用 UMG 工具。这个工具将允许您以`设计师`选项卡的形式制作游戏 UI，同时还可以通过 UMG 的`图表`选项卡为您的游戏 UI 添加功能。

小部件是 UE4 允许您表示游戏 UI 的方式。小部件可以是基本的 UI 元素，如`按钮`、`文本`元素和`图像`，但它们也可以组合在一起创建更复杂和完整的小部件，如菜单和 HUD，这正是我们将在本章中要做的。

让我们在下一个练习中使用 UMG 工具在 UE4 中创建我们的第一个小部件。

## 练习 8.01：创建小部件蓝图

在这个练习中，我们将创建我们的第一个小部件蓝图，并学习 UMG 的基本元素以及如何使用它们来创建游戏 UI。

以下步骤将帮助您完成这个练习：

1.  为了创建我们的第一个小部件，打开编辑器，转到`Content Browser`中的`ThirdPersonCPP -> Blueprints`文件夹，然后*右键单击*。

1.  转到最后一节，`用户界面`，然后选择`小部件蓝图`。

选择此选项将创建一个新的`小部件蓝图`，这是 UE4 中小部件资产的名称。

1.  将此小部件命名为`TestWidget`并打开它。您将看到用于编辑小部件蓝图的界面，在那里您将创建自己的小部件和 UI。以下是此窗口中所有选项卡的详细信息：![图 8.1：小部件蓝图编辑器分解为六个窗口](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_08_01.jpg)

图 8.1：小部件蓝图编辑器分解为六个窗口

前面图中选项卡的详细信息如下：

+   `调色板` - 此选项卡显示您可以添加到小部件的所有单独的 UI 元素。这包括`按钮`，`文本框`，`图像`，`滑块`，`复选框`等等。

+   `层次结构` - 此选项卡显示当前在您的小部件中存在的所有 UI 元素。正如您所看到的，目前我们的层次结构中只有一个`画布面板`元素。

+   `设计师` - 此选项卡显示您的小部件在视觉上的外观，根据层次结构中存在的元素以及它们的布局方式。因为我们当前小部件中唯一的元素没有视觉表示，所以此选项卡目前为空。

+   `详细信息` - 此选项卡显示当前所选 UI 元素的属性。如果选择现有的`画布面板`元素，则应出现前面截图中的所有选项。

+   因为此资产是`小部件蓝图`，这两个按钮允许您在`设计师视图`和`图形视图`之间切换，后者看起来与普通蓝图类的窗口完全相同。

+   `动画` - 这两个选项卡都与小部件动画相关。小部件蓝图允许您随时间动画 UI 元素的属性，包括它们的`位置`，`比例`，`颜色`等等。左侧选项卡允许您创建和选择要在右侧选项卡中编辑的动画，您将能够编辑它们随时间影响的属性。

1.  现在让我们看一下我们的`小部件`中一些可用的 UI 元素，首先是现有的`画布面板`。

`画布面板`通常添加到小部件蓝图的根部，因为它们允许您将 UI 元素拖动到`设计师`选项卡中的任何位置。这样，您可以按照自己的意愿布置这些元素：在屏幕中心，左上角，屏幕底部中心等等。现在让我们将另一个非常重要的 UI 元素拖到我们的小部件中：一个`按钮`。

1.  在`调色板`选项卡中，找到`按钮`元素并将其拖到我们的`设计师`选项卡中（按住鼠标左键拖动）：![图 8.2：从调色板窗口拖动按钮元素进入设计师窗口](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_08_02.jpg)

图 8.2：从调色板窗口将按钮元素拖到设计师窗口中

一旦您这样做，您就可以通过拖动周围的小白点调整按钮的大小（请记住，您只能对位于画布面板内的元素执行此操作）：

![图 8.3：使用周围的白点调整 UI 元素大小的结果](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_08_03.jpg)

图 8.3：使用周围的白点调整 UI 元素大小的结果

在`小部件`中将元素拖入彼此的另一种方法是将它们拖入`层次结构`选项卡，而不是`设计师`选项卡。

1.  现在将`文本`元素拖到我们的`按钮`中，但这次使用`层次结构`选项卡：![图 8.4：将文本元素从调色板窗口拖到层次结构窗口中](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_08_04.jpg)

图 8.4：将文本元素从调色板窗口拖到层次结构窗口中

“文本”元素可以包含您指定的文本，具有您可以在“详细信息”面板中修改的特定大小和字体。在使用“层次结构”选项卡将“文本”元素拖动到“按钮”内之后，设计师选项卡应该如下所示：

![图 8.5：在我们添加文本元素作为其子级后的设计师选项卡中的按钮元素](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_08_05.jpg)

图 8.5：在设计师选项卡中的按钮元素，在我们添加文本元素作为其子级后

让我们更改此“文本”块的一些属性。

1.  在“层次结构”选项卡或“设计师”选项卡中选择它，并查看“详细信息”面板：![图 8.6：显示我们添加的文本元素的属性的详细信息面板](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_08_06.jpg)

图 8.6：显示我们添加的文本元素的属性的详细信息面板

在这里，您会发现一些属性，您可以根据自己的喜好进行编辑。现在，我们只想专注于其中的两个：文本的“内容”和其“颜色和不透明度”。

1.  将“文本”元素的“内容”从“文本块”更新为“按钮 1”：![图 8.7：将文本元素的文本属性更改为按钮 1](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_08_07.jpg)

图 8.7：将文本元素的文本属性更改为按钮 1

接下来，让我们将其“颜色和不透明度”从“白色”更改为“黑色”。

1.  点击“颜色和不透明度”属性，看看弹出的窗口，“颜色选择器”。每当您在 UE4 中编辑“颜色”属性时，此窗口都会弹出。它允许您以许多不同的方式输入颜色，包括颜色轮、饱和度和值条、RGB 和 HSV 值滑块，以及其他几个选项。

1.  现在，通过将“值”条（从上到下从白色到黑色的条）拖动到底部，然后按“确定”，将颜色从白色更改为黑色：![图 8.8：在颜色选择器窗口中选择黑色](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_08_08.jpg)

图 8.8：在颜色选择器窗口中选择黑色

1.  在进行这些更改后，按钮应该看起来像这样：![图 8.9：更改文本元素的文本后的按钮元素属性及其颜色](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_08_09.jpg)

图 8.9：更改文本元素的文本属性和颜色后的按钮元素

有了这个，我们结束了本章的第一个练习。您现在已经了解了 UMG 的一些基本知识，比如如何向您的小部件添加“按钮”和“文本”元素。

在我们进行下一个练习之前，让我们先了解一下锚点。

# 锚点

您可能已经意识到，视频游戏在许多不同的屏幕尺寸和许多不同的分辨率上进行播放。因此，确保您创建的菜单可以有效地适应所有这些不同的分辨率非常重要。这就是**锚点**的主要目的。

锚点允许您指定 UI 元素的大小在屏幕分辨率更改时如何适应，通过指定您希望其占据屏幕比例。使用锚点，您可以始终将 UI 元素放在屏幕的左上角，或始终占据屏幕的一半，无论屏幕的大小和分辨率如何。

当屏幕大小或分辨率发生变化时，您的小部件将相对于其锚点进行缩放和移动。只有直接作为“画布面板”的子级的元素才能有锚点，您可以通过“锚点奖章”来可视化它，当您选择所述元素时，在“设计师”选项卡中会显示一个白色的花瓣形状：

![图 8.10：显示轮廓左上方的锚点奖章在设计师窗口中](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_08_10.jpg)

图 8.10：在设计师窗口中显示的轮廓的左上方的锚点奖章

默认情况下，锚点折叠到左上角，这意味着您无法控制按钮在分辨率更改时的缩放程度，因此让我们在下一个练习中更改它。

## 练习 8.02：编辑 UMG 锚点

在这个练习中，我们将改变小部件中的锚点，以便我们的按钮大小和形状能够适应各种屏幕分辨率和尺寸。

以下步骤将帮助您完成此练习：

1.  选择我们在上一个练习中创建的按钮，然后转到`Details`面板，点击您看到的第一个属性，即`Anchors`属性。在这里，您将能够看到`Anchor`预设，这将根据所示的枢轴对齐 UI 元素。

我们希望将按钮居中显示在屏幕上。

1.  点击屏幕中心的中心枢轴：![图 8.11：按钮的锚点属性，中心锚点用方框标出](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_08_11.jpg)

图 8.11：按钮的锚点属性，中心锚点用方框标出

您会看到我们的`Anchor Medallion`现在已经改变了位置：

![图 8.12：将按钮的锚点更改为中心后的锚点奖章](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_08_12.jpg)

图 8.12：将按钮的锚点更改为中心后的锚点奖章

现在`Anchor Medallion`位于屏幕中心，我们仍然无法控制按钮在不同分辨率下的缩放，但至少我们知道它会相对于屏幕中心进行缩放。

为了使我们的按钮居中显示在屏幕上，我们还需要将按钮的位置更改为屏幕中心。

1.  重复选择中心锚点的上一步，但这次，在选择它之前，按住*Ctrl*键以将按钮的位置捕捉到此锚点。点击后释放*Ctrl*键。这应该是结果：![图 8.13：按钮元素被移动到其选定的中心锚点附近](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_08_13.jpg)

图 8.13：按钮元素被移动到其选定的中心锚点附近

从前面的截图中可以看到，我们的按钮位置已经改变，但它还没有正确居中在屏幕上。这是因为它的`Alignment`。

`Alignment`属性是`Vector2D`类型（具有两个`float`属性的元组：`X`和`Y`），它决定了 UI 元素相对于其总大小的中心。默认情况下设置为`(0,0)`，意味着元素的中心是其左上角，这解释了前面截图中的结果。它可以一直到`(1,1)`，即右下角。在这种情况下，考虑到我们希望对齐按钮，我们希望它是`(0.5, 0.5)`。

1.  在选择`Anchor`点时更新 UI 元素的对齐方式，您必须按住*Shift*键并重复上一步。或者，为了同时更新按钮的位置和对齐方式，选择中心`Anchor`点时同时按住*Ctrl*和*Shift*键将完成任务。然后应该是这个结果：![图 8.14：按钮元素相对于其选定的中心位置居中居中的锚点](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_08_14.jpg)

图 8.14：按钮元素相对于其选定的锚点在中心位置

在这一点上，当改变屏幕的分辨率时，我们知道这个按钮将始终保持在屏幕中心。然而，为了保持按钮相对于分辨率的大小，我们需要进行一些修改。

1.  将`Anchor Medallion`的右下角*花瓣*拖动到按钮的右下角：![图 8.15：拖动锚点奖章的右下角花瓣更新按钮元素的锚点](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_08_15.jpg)

图 8.15：拖动锚点奖章的右下角花瓣以更新按钮元素的锚点

1.  将`Anchor Medallion`的左上角*花瓣*拖动到按钮的左上角：![图 8.16：拖动锚点奖章的左上角花瓣更新按钮元素的锚点](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_08_16.jpg)

图 8.16：拖动锚点奖章的左上角花瓣以更新按钮元素的锚点

注意

当更改“锚点”时，您在按钮周围看到的百分比是元素在屏幕上所占空间的百分比。例如，看最后一个截图，我们可以看到按钮在*X*坐标上占小部件空间的`11.9%`，在*Y*坐标上占小部件空间的`8.4%`。

通过按住*Ctrl*键移动“锚点勋章”的*花瓣*，可以将 UI 元素的大小设置为其锚点的大小。

现在，由于这些对锚点的更改，我们的按钮最终将适应不同的屏幕尺寸和分辨率。

您还可以使用“详细”面板手动编辑我们刚刚使用“锚点勋章”和移动按钮编辑的所有属性：

![图 8.17：我们使用锚点勋章更改的属性，显示在详细窗口中](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_08_17.jpg)

图 8.17：我们使用锚点勋章更改的属性，显示在详细窗口中

最后，我们需要知道如何在“设计师”选项卡中使用不同的分辨率来可视化我们的小部件。

1.  拖动设计师选项卡内部轮廓框的右下方的双箭头：![图 8.18：设计师选项卡内部轮廓框的右下方的双箭头设计师选项卡内部轮廓框的右下方](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_08_18.jpg)

图 8.18：在设计师选项卡内部轮廓框的右下方有双箭头

通过拖动双箭头，您可以将“画布”调整到任何屏幕分辨率。在下面的截图中，您将看到各种设备的最常用分辨率，并且您可以在每个分辨率下预览您的小部件：

![图 8.19：我们可以选择在设计师窗口中预览的分辨率](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_08_19.jpg)

图 8.19：我们可以选择在设计师窗口中预览的分辨率

注意

您可以在[`docs.unrealengine.com/en-US/Engine/UMG/UserGuide/Anchors`](https://docs.unrealengine.com/en-US/Engine/UMG/UserGuide/Anchors)找到 UMG 锚点的完整参考。

这就结束了我们的练习。您已经了解了锚点和如何使您的小部件适应不同的屏幕尺寸和分辨率。

现在我们已经了解了一些 UMG 的基础知识，让我们看看如何为这个小部件蓝图创建一个小部件 C++类，这是我们将在下一个练习中要做的事情。

## 练习 8.03：创建 RestartWidget C++类

在这个练习中，我们将学习如何创建一个小部件 C++类，从中我们创建的小部件蓝图将继承。在我们的“躲避球”游戏中，当玩家死亡时，它将被添加到屏幕上，以便玩家可以选择重新开始级别。这个小部件将有一个按钮，当玩家点击它时，将重新开始级别。

这个练习的第一步将是向我们的项目添加与 UMG 相关的模块。虚幻引擎包括几个不同的模块，在每个项目中，您都必须指定您要使用哪些模块。当源代码文件生成时，我们的项目已经带有一些通用模块，但我们需要添加一些更多的模块。

以下步骤将帮助您完成这个练习：

1.  打开位于项目`Source`文件夹内的 C#文件而不是 C++文件的`Dodgeball.build.cs`文件。

1.  打开文件，您会发现从`PublicDependencyModuleNames`属性调用的`AddRange`函数。这个函数告诉引擎这个项目打算使用哪些模块。作为参数，发送了一个字符串数组，其中包含项目的所有预期模块的名称。鉴于我们打算使用 UMG，我们需要添加与 UMG 相关的模块：`UMG`，`Slate`和`SlateCore`：

```cpp
PublicDependencyModuleNames.AddRange(new string[] { "Core",   "CoreUObject", "Engine", "InputCore", "HeadMountedDisplay",   "UMG", "Slate", "SlateCore" });
```

现在我们已经通知引擎我们将使用 UMG 模块，让我们创建我们的小部件 C++类：

1.  打开虚幻编辑器。

1.  右键单击内容浏览器，然后选择“新的 C++类”。

1.  将“显示所有类”复选框设置为`true`。

1.  搜索`UserWidget`类，并将其选择为新类的父类。

1.  将新的 C++类命名为`RestartWidget`。

在文件在 Visual Studio 中打开后，按照以下步骤对我们的 Widget C++类进行修改：

1.  我们将要添加到这个类的第一件事是一个名为`RestartButton`的`public` `class UButton*`属性，它代表玩家将按下以重新启动级别的按钮。您将希望它通过使用`UPROPERTY`宏和`BindWidget`元标记绑定到从该类继承的蓝图类中的按钮。这将强制 Widget 蓝图具有一个名为`RestartButton`的`Button`，我们可以通过此属性在 C++中访问它，然后自由编辑其属性，例如在蓝图中的大小和位置：

```cpp
UPROPERTY(meta = (BindWidget))
class UButton* RestartButton;
```

注意

使用`BindWidget`元标记将导致编译错误，如果从该 C++类继承的 Widget 蓝图没有具有相同类型和名称的元素。如果您不希望发生这种情况，您将不得不将`UPROPERTY`标记为可选的`BindWidget`，如下所示：`UPROPERTY(meta = (BindWidget, OptionalWidget = true))`这将使绑定此属性变为可选，并且在编译 Widget 蓝图时不会导致编译错误。

接下来，我们将添加一个函数，当玩家点击`RestartButton`时将被调用，这将重新启动级别。我们将使用`GameplayStatics`对象的`OpenLevel`函数来实现这一点，然后发送当前级别的名称。

1.  在 Widget 类的头文件中，添加一个名为`OnRestartClicked`的`protected`函数的声明，它不返回任何内容并且不接收任何参数。此函数必须标记为`UFUNCTION`：

```cpp
protected:
UFUNCTION()
void OnRestartClicked();
```

1.  在类的源文件中，添加一个`GameplayStatics`对象的`include`：

```cpp
#include "Kismet/GameplayStatics.h"
```

1.  然后，为我们的`OnRestartClicked`函数添加一个实现：

```cpp
void URestartWidget::OnRestartClicked()
{
}
```

1.  在其实现中，调用`GameplayStatics`对象的`OpenLevel`函数。此函数接收世界上下文对象作为参数，这将是`this`指针，并且级别的名称，我们将不得不使用`GameplayStatics`对象的`GetCurrentLevelName`函数来获取。这个最后的函数也必须接收一个世界上下文对象，这也将是`this`指针：

```cpp
UGameplayStatics::OpenLevel(this,   FName(*UGameplayStatics::GetCurrentLevelName(this)));
```

注意

对`GameplayStatics`对象的`GetCurrentLevelName`函数的调用必须在前面加上`*`，因为它返回一个`FString`，UE4 的字符串类型，并且必须被解引用才能传递给`FName`构造函数。

下一步将是以一种方式绑定此函数，以便在玩家按下`RestartButton`时调用它：

1.  为了做到这一点，我们将不得不重写属于`UserWidget`类的一个函数，名为`NativeOnInitialized`。这个函数只被调用一次，类似于 Actor 的`BeginPlay`函数，这使得它适合进行我们的设置。在我们的 Widget 类的头文件中，使用`virtual`和`override`关键字添加一个`public` `NativeOnInitialized`函数的声明：

```cpp
virtual void NativeOnInitialized() override;
```

1.  接下来，在类的源文件中，添加此函数的实现。在其中，调用其`Super`函数并添加一个`if`语句，检查我们的`RestartButton`是否与`nullptr`不同：

```cpp
void URestartWidget::NativeOnInitialized()
{
  Super::NativeOnInitialized();
  if (RestartButton != nullptr)
  {
  }
}
```

1.  如果`if`语句为真，我们将希望将我们的`OnRestartClicked`函数绑定到按钮的`OnClicked`事件。我们可以通过访问按钮的`OnClicked`属性并调用其`AddDynamic`函数来实现这一点，将我们想要调用该函数的对象（即`this`指针）和要调用的函数的指针（即`OnRestartClicked`函数）作为参数发送：

```cpp
if (RestartButton != nullptr)
{
  RestartButton->OnClicked.AddDynamic(this,   &URestartWidget::OnRestartClicked);
}
```

1.  因为我们正在访问与`Button`类相关的函数，所以我们还必须包含它：

```cpp
#include "Components/Button.h"
```

注意

当玩家按下并释放按钮时，按钮的`OnClicked`事件将被调用。还有其他与按钮相关的事件，包括`OnPressed`事件（当玩家按下按钮时），`OnReleased`事件（当玩家释放按钮时），以及`OnHover`和`OnUnhover`事件（当玩家分别开始和停止悬停在按钮上时）。

`AddDynamic`函数必须接收一个标记有`UFUNCTION`宏的函数的指针作为参数。如果没有，当调用该函数时会出现错误。这就是为什么我们用`UFUNCTION`宏标记了`OnRestartClicked`函数的原因。

完成这些步骤后，编译您的更改并打开编辑器。

1.  打开您之前创建的`TestWidget` Widget Blueprint。我们希望将这个 Widget Blueprint 与我们刚刚创建的`RestartWidget`类关联起来，所以我们需要重新设置其父类。

1.  从 Widget Blueprint 的`File`选项卡中，选择`Reparent Blueprint`选项，并选择`RestartWidget` C++类作为其新的父类：![图 8.20：将 TestWidget 的类重新设置为 RestartWidget](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_08_20.jpg)

图 8.20：将 TestWidget 的类重新设置为 RestartWidget

您会注意到 Widget Blueprint 现在有一个与我们在 C++类中创建的`BindWidget`元标记相关的编译错误：

![图 8.21：设置父类为 RestartWidget 类后的编译错误](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_08_21.jpg)

图 8.21：设置父类为 RestartWidget 类后的编译错误

这是由于 C++类找不到名为`RestartButton`的`Button`属性造成的。

为了解决这个问题，我们需要将 Widget Blueprint 中的`Button`元素重命名为`RestartButton`：

![图 8.22：将按钮元素重命名为 RestartButton](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_08_22.jpg)

图 8.22：将按钮元素重命名为 RestartButton

完成这些步骤后，关闭 Widget Blueprint，并将其名称从`TestWidget`更改为`BP_RestartWidget`，就像你在上一步中所做的那样。

这就完成了我们的 Widget 类的创建。您现在知道如何将 Widget C++类连接到 Widget Blueprint，这是处理 UE4 中游戏 UI 的一个非常重要的步骤。

接下来我们需要做的是创建我们的`Player Controller` C++类，它将负责实例化我们的`RestartWidget`并将其添加到屏幕上。我们将在接下来的练习中完成这个任务。

## 练习 8.04：创建将 RestartWidget 添加到屏幕的逻辑

在这个练习中，我们将创建负责将我们新创建的`RestartWidget`添加到屏幕上的逻辑。当玩家死亡时，它将出现在屏幕上，以便他们有重新开始关卡的选项。

为了做到这一点，我们需要创建一个新的`Player Controller` C++类，您可以按照以下步骤进行：

1.  打开虚幻编辑器。

1.  在`Content Browser`上*右键单击*，选择`New C++ Class`。

1.  搜索`Player Controller`类并选择它作为新类的父类。

1.  将新的 C++类命名为`DodgeballPlayerController`。

1.  在 Visual Studio 中打开类的文件。

当我们的玩家耗尽生命值时，`DodgeballCharacter`类将访问这个`Player Controller`类，并调用一个函数，该函数将在屏幕上添加`RestartWidget`。请按照以下步骤继续进行。

为了知道要添加到屏幕上的 Widget 的类（它将是一个 Widget Blueprint 而不是 Widget C++类），我们需要使用`TSubclassOf`类型。

1.  在类的头文件中，添加一个名为`BP_RestartWidget`的`public` `TSubclassOf<class URestartWidget>`属性。确保将其设置为`UPROPERTY`，并使用`EditDefaultsOnly`标记，以便我们可以在蓝图类中编辑它：

```cpp
public:
UPROPERTY(EditDefaultsOnly)
TSubclassOf<class URestartWidget> BP_RestartWidget;
```

为了实例化这个 Widget 并将其添加到屏幕上，我们需要保存一个对它的引用。

1.  添加一个`private`类型为`class URestartWidget*`的新变量，并将其命名为`RestartWidget`。确保将其设置为没有标签的`UPROPERTY`函数：

```cpp
private:
UPROPERTY()
class URestartWidget* RestartWidget;
```

注意

尽管这个属性不应该在蓝图类中可编辑，但我们必须将这个引用设置为`UPROPERTY`，否则垃圾收集器将销毁这个变量的内容。

我们需要的下一步是一个负责将我们的小部件添加到屏幕上的函数。

1.  添加一个声明为返回无内容并且不接收参数的`public`函数，名为`ShowRestartWidget`：

```cpp
void ShowRestartWidget();
```

1.  现在，转到我们类的源文件。首先，添加一个包含到`RestartWidget`类的包含：

```cpp
#include "RestartWidget.h"
```

1.  然后，添加我们的`ShowRestartWidget`函数的实现，我们将首先检查我们的`BP_RestartWidget`变量是否不是`nullptr`：

```cpp
void ADodgeballPlayerController::ShowRestartWidget()
{
  if (BP_RestartWidget != nullptr)
  {
  }
}
```

1.  如果该变量有效（不同于`nullptr`），我们希望使用`Player Controller`的`SetPause`函数暂停游戏。这将确保游戏停止，直到玩家决定做些什么（在我们的情况下，将按下重新开始关卡的按钮）：

```cpp
SetPause(true);
```

接下来要做的是改变输入模式。在 UE4 中，有三种输入模式：`仅游戏`，`游戏和 UI`和`仅 UI`。如果您的`输入`模式包括`游戏`，这意味着玩家角色和玩家控制器将通过`输入操作`接收输入。如果您的`输入`模式包括`UI`，这意味着屏幕上的小部件将接收玩家的输入。当我们在屏幕上显示此小部件时，我们不希望玩家角色接收任何输入。

1.  因此，更新为`仅 UI` `输入`模式。您可以通过调用`Player Controller`的`SetInputMode`函数，并将`FInputModeUIOnly`类型作为参数传递来实现这一点：

```cpp
SetInputMode(FInputModeUIOnly());
```

之后，我们希望显示鼠标光标，以便玩家可以看到他们悬停在哪个按钮上。

1.  我们将通过将`Player Controller`的`bShowMouseCursor`属性设置为`true`来实现这一点：

```cpp
bShowMouseCursor = true;
```

1.  现在，我们可以实例化我们的小部件，使用`Player Controller`的`CreateWidget`函数，将 C++小部件类作为模板参数传递，这在我们的情况下是`RestartWidget`，然后作为正常参数传递`Owning Player`，这是拥有此小部件的`Player Controller`，我们将使用`this`指针发送，以及小部件类，这将是我们的`BP_RestartWidget`属性：

```cpp
RestartWidget = CreateWidget<URestartWidget>(this,   BP_RestartWidget);
```

1.  在我们实例化小部件之后，我们将使用小部件的`AddToViewport`函数将其添加到屏幕上：

```cpp
RestartWidget->AddToViewport();
```

1.  这就完成了我们的`ShowRestartWidget`函数。但是，我们还需要创建一个函数，用于从屏幕上移除`RestartWidget`。在类的头文件中，添加一个声明为与`ShowRestartWidget`函数类似的函数，但这次名为`HideRestartWidget`：

```cpp
void HideRestartWidget();
```

1.  在类的源文件中，添加`HideRestartWidget`函数的实现：

```cpp
void ADodgeballPlayerController::HideRestartWidget()
{
}
```

1.  在这个函数中，我们应该首先通过调用其`RemoveFromParent`函数将小部件从屏幕上移除，并使用`Destruct`函数将其销毁：

```cpp
RestartWidget->RemoveFromParent();
RestartWidget->Destruct();
```

1.  然后，我们希望使用前一个函数中使用的`SetPause`函数取消暂停游戏：

```cpp
SetPause(false);
```

1.  最后，将`输入`模式设置为`仅游戏`，并以与前一个函数相同的方式隐藏鼠标光标（这次我们传递`FInputModeGameOnly`类型）：

```cpp
SetInputMode(FInputModeGameOnly());
bShowMouseCursor = false;
```

这就完成了我们的`Player Controller` C++类的逻辑。我们接下来应该调用一个函数，将我们的小部件添加到屏幕上。

1.  转到`DodgeballCharacter`类的源文件，并向我们新创建的`DodgeballPlayerController`添加`include`关键字：

```cpp
#include "DodgeballPlayerController.h"
```

1.  在`DodgeballCharacter`类的`OnDeath_Implementation`函数的实现中，用以下内容替换对`QuitGame`函数的调用：

+   使用`GetController`函数获取角色的玩家控制器。您将希望将结果保存在名为`PlayerController`的`DodgeballPlayerController*`类型的变量中。因为该函数将返回一个`Controller`类型的变量，您还需要将其转换为我们的`PlayerController`类：

```cpp
ADodgeballPlayerController* PlayerController = Cast<ADodgeballPlayerController>(GetController());
```

+   检查`PlayerController`变量是否有效。如果是，调用其`ShowRestartWidget`函数：

```cpp
if (PlayerController != nullptr)
{
  PlayerController->ShowRestartWidget();
}
```

在进行了这些修改之后，我们唯一剩下的事情就是调用将我们的小部件从屏幕上隐藏的函数。打开`RestartWidget`类的源文件并实现以下修改。

1.  向`DodgeballPlayerController`添加一个`include`，其中包含我们将要调用的函数：

```cpp
#include "DodgeballPlayerController.h"
```

1.  在`OnRestartClicked`函数实现中，在调用`OpenLevel`函数之前，我们必须使用`GetOwningPlayer`函数获取小部件的`OwningPlayer`，它是`PlayerController`类型的，并将其转换为`DodgeballPlayerController`类：

```cpp
ADodgeballPlayerController* PlayerController =   Cast<ADodgeballPlayerController>(GetOwningPlayer());
```

1.  然后，如果`PlayerController`变量有效，我们调用其`HideRestartWidget`函数：

```cpp
if (PlayerController != nullptr)
{
  PlayerController->HideRestartWidget();
}
```

在您完成所有这些步骤之后，关闭编辑器，编译您的更改并打开编辑器。

您现在已经完成了这个练习。我们已经添加了所有必要的逻辑，将我们的`RestartWidget`添加到屏幕上，我们唯一剩下的事情就是创建我们新创建的`DodgeballPlayerController`的蓝图类，这将在下一个练习中完成。

## 练习 8.05：设置 DodgeballPlayerController 蓝图类

在这个练习中，我们将创建我们的`DodgeballPlayerController`的蓝图类，以指定我们要添加到屏幕上的小部件，并告诉 UE4 在游戏开始时使用这个蓝图类。

为了做到这一点，请按照以下步骤进行：

1.  转到`Content Browser`中的`ThirdPersonCPP` -> `Blueprints`目录，在其中右键单击，并创建一个新的蓝图类。

1.  搜索`DodgeballPlayerController`类并将其选择为父类。

1.  将此蓝图类重命名为`BP_DodgeballPlayerController`。之后，打开此蓝图资源。

1.  转到其`Class Defaults`选项卡，并将类的`BP_RestartWidget`属性设置为我们创建的`BP_RestartWidget`小部件蓝图。

现在，我们唯一剩下的事情就是确保这个`Player Controller`蓝图类在游戏中被使用。

为了做到这一点，我们还需要遵循一些步骤。

1.  转到`Content Browser`中的`ThirdPersonCPP` -> `Blueprints`目录，在其中*右键单击*，创建一个新的蓝图类。搜索`DodgeballGameMode`类并将其选择为父类，然后将此`Blueprint`类重命名为`BP_DodgeballGameMode`。

这个类负责告诉游戏使用哪些类来处理游戏的每个元素，比如使用哪个`Player Controller`类等。

1.  打开资源，转到其`Class Defaults`选项卡，并将类的`PlayerControllerClass`属性设置为我们创建的`BP_DodgeballPlayerController`类：![图 8.23：将 PlayerControllerClass 属性设置为 BP_DodgeballPlayerController](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_08_23.jpg)

图 8.23：将 PlayerControllerClass 属性设置为 BP_DodgeballPlayerController

1.  关闭资源并在位于`Level Viewport`窗口顶部的编辑器工具栏内选择`Blueprints`下拉选项。从那里，选择`Game Mode`（当前应设置为`DodgeballGameMode`）`-> 选择 GameModeBase Class -> BP_DodgeballGameMode`。这将告诉编辑器在所有关卡中使用这个新的`Game Mode`。

现在，玩游戏，让您的角色被 Dodgeball 击中`3`次。第三次之后，您应该看到游戏被暂停，并显示`BP_RestartWidget`：

![图 8.24：在玩家耗尽生命值后将我们的 BP_RestartWidget 添加到屏幕上耗尽生命值](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_08_24.jpg)

图 8.24：在玩家耗尽生命值后将我们的 BP_RestartWidget 添加到屏幕上

当您使用鼠标点击“按钮 1”时，您应该看到关卡重置为初始状态：

![图 8.25：玩家按下按钮后关卡重新开始在前一个截图中显示](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_08_25.jpg)

图 8.25：玩家按下前一个截图中显示的按钮后，关卡重新开始

这就结束了我们的练习。您现在知道如何创建小部件并在游戏中显示它们。这是成为一名熟练游戏开发者的旅程中的又一个关键步骤。

在我们继续下一个练习之前，让我们在下一节中看一下进度条。

# 进度条

视频游戏表示角色状态（如生命值、耐力等）的一种方式是通过**进度条**，这是我们将用来向玩家传达他们的角色有多少生命值的方式。进度条本质上是一个形状，通常是矩形，可以填充和清空，以显示玩家特定状态的进展。如果您想向玩家显示他们的角色生命值只有最大值的一半，您可以通过显示进度条为一半来实现。这正是我们将在本节中要做的。这个进度条将是我们躲避球游戏 HUD 中唯一的元素。

为了创建这个“生命值条”，我们首先需要创建我们的 HUD 小部件。打开编辑器，转到内容浏览器内的`ThirdPersonCPP` -> “蓝图”目录，右键单击并创建一个新的“小部件蓝图”类别的“用户界面”类别。将这个新的小部件蓝图命名为`BP_HUDWidget`。然后打开这个新的小部件蓝图。

UE4 中的进度条只是另一个 UI 元素，就像`按钮`和`文本`元素一样，这意味着我们可以将它从`调色板`选项卡拖到我们的`设计师`选项卡中。看下面的例子：

![图 8.26：将进度条元素拖入设计师窗口](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_08_26.jpg)

图 8.26：将进度条元素拖入设计师窗口

起初，这个进度条可能看起来类似于一个按钮；然而，它包含两个对于进度条很重要的特定属性：

+   `百分比` - 允许您指定此进度条的进度，从`0`到`1`

+   `填充类型` - 允许您指定您希望此进度条如何填充（从左到右，从上到下等）：

![图 8.27：进度条的百分比和填充类型属性](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_08_27.jpg)

图 8.27：进度条的百分比和填充类型属性

如果将“百分比”属性设置为`0.5`，则应该看到进度条相应地更新以填充其长度的一半：

![图 8.28：进度条向右填充一半](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_08_28.jpg)

图 8.28：进度条向右填充一半

在继续之前，将“百分比”属性设置为`1`。

现在让我们将进度条的颜色从蓝色（默认颜色）改为红色。为了做到这一点，转到“详细信息”选项卡，在“外观”类别内，将“填充颜色和不透明度”属性设置为红色（`RGB(1,0,0)`）：

![图 8.29：进度条的颜色被更改为红色](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_08_29.jpg)

图 8.29：进度条的颜色被更改为红色

完成这些操作后，您的进度条现在应该使用红色作为填充颜色。

为了完成我们的进度条设置，让我们更新它的位置、大小和锚点。按照以下步骤来实现这一点：

1.  在`槽（Canvas Panel Slot）`类别中，展开`锚点`属性并将其属性设置为以下值：

+   `最小值`：`X`轴上的`0.052`和`Y`轴上的`0.083`

+   `最大值`：`X`轴上的`0.208`和`Y`轴上的`0.116`

1.  将“左偏移”、“顶部偏移”、“右偏移”和“底部偏移”属性设置为`0`。

您的进度条现在应该是这样的：

![图 8.30：在本节中所有修改完成后的进度条](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_08_30.jpg)

图 8.30：在本节完成所有修改后的进度条

有了这个，我们就可以结束进度条的话题了。我们的下一步是添加所有必要的逻辑，以将这个进度条作为健康条使用，通过更新玩家角色的健康状况来更新其`Percent`属性。我们将在下一个练习中做到这一点。

## 练习 8.06：创建健康条 C++逻辑

在这个练习中，我们将添加所有必要的 C++逻辑，以更新 HUD 中的进度条，因为玩家角色的健康状况会发生变化。

为了做到这一点，请按照以下步骤进行操作：

1.  打开编辑器，并创建一个新的 C++类，该类继承自`UserWidget`，类似于我们在*练习 8.03*中所做的*创建 RestartWidget C++类*，但这次将其命名为`HUDWidget`。这将是我们的 HUD Widget 所使用的 C++类。

1.  在`HUDWidget`类的头文件中，添加一个新的`public`属性，类型为`class UProgressBar*`，名为`HealthBar`。这种类型用于在 C++中表示进度条，就像我们在上一节中创建的那样。确保将此属性声明为带有`BindWidget`标记的`UPROPERTY`函数：

```cpp
UPROPERTY(meta = (BindWidget))
class UProgressBar* HealthBar;
```

1.  添加一个名为`UpdateHealthPercent`的`public`函数声明，它不返回任何内容，并接收一个`float HealthPercent`属性作为参数。这个函数将被调用以更新我们的进度条的`Percent`属性：

```cpp
void UpdateHealthPercent(float HealthPercent);
```

1.  在`HUDWidget`类的源文件中，添加`UpdateHealthPercent`函数的实现，该函数将调用`HealthBar`属性的`SetPercent`函数，并将`HealthPercent`属性作为参数传递：

```cpp
void UHUDWidget::UpdateHealthPercent(float HealthPercent)
{
  HealthBar->SetPercent(HealthPercent);
}
```

1.  因为我们将使用`ProgressBar` C++类，所以我们需要在类的源文件顶部添加一个`include`：

```cpp
#include "Components/ProgressBar.h"
```

下一步将是为我们的`Player Controller`添加负责将`HUDWidget`添加到屏幕的所有必要逻辑。按照以下步骤实现这一点：

1.  在`DodgeballPlayerController`类的头文件中，添加一个`public`属性，类型为`TSubclassOf<class UHUDWidget>`，名为`BP_HUDWidget`。确保将其标记为`UPROPERTY`函数，并使用`EditDefaultsOnly`标记。

这个属性将允许我们在`DodgeballPlayerController`蓝图类中指定我们想要用作 HUD 的 Widget：

```cpp
UPROPERTY(EditDefaultsOnly)
TSubclassOf<class UHUDWidget> BP_HUDWidget;
```

1.  添加另一个属性，这次是`private`类型为`class UHUDWidget*`，名为`HUDWidget`。将其标记为`UPROPERTY`，但不带任何标记：

```cpp
UPROPERTY()
class UHUDWidget* HUDWidget;
```

1.  添加一个`protected`声明，名为`BeginPlay`函数，并将其标记为`virtual`和`override`：

```cpp
virtual void BeginPlay() override;
```

1.  添加一个新的`public`函数声明，名为`UpdateHealthPercent`，它不返回任何内容，并接收一个`float HealthPercent`作为参数。

这个函数将被我们的玩家角色类调用，以更新 HUD 中的健康条：

```cpp
void UpdateHealthPercent(float HealthPercent);
```

1.  现在转到`DodgeballPlayerController`类的源文件。首先添加一个`include`到我们的`HUDWidget`类：

```cpp
#include "HUDWidget.h"
```

1.  然后，添加`BeginPlay`函数的实现，我们将首先调用`Super`对象的`BeginPlay`函数：

```cpp
void ADodgeballPlayerController::BeginPlay()
{
  Super::BeginPlay();
}
```

1.  在调用该函数后，检查`BP_HUDWidget`属性是否有效。如果有效，调用`CreateWidget`函数，使用`UHUDWidget`模板参数，并将`Owning Player`、`this`和 Widget 类`BP_HUDWidget`作为参数传递。确保将`HUDWidget`属性设置为此函数调用的返回值：

```cpp
if (BP_HUDWidget != nullptr)
{
  HUDWidget = CreateWidget<UHUDWidget>(this, BP_HUDWidget);
}
```

1.  设置完`HUDWidget`属性后，调用其`AddToViewport`函数：

```cpp
HUDWidget->AddToViewport();
```

1.  最后，添加`UpdateHealthPercent`函数的实现，在这里我们将检查`HUDWidget`属性是否有效，如果有效，调用其`UpdateHealthPercent`函数，并将`HealthPercent`属性作为参数传递：

```cpp
void ADodgeballPlayerController::UpdateHealthPercent(float   HealthPercent)
{
  if (HUDWidget != nullptr)
  {
    HUDWidget->UpdateHealthPercent(HealthPercent);
  }
}
```

现在我们已经添加了负责将 HUD 添加到屏幕并允许其更新的逻辑，我们需要对其他类进行一些修改。按照以下步骤进行修改。

目前，我们在上一章创建的`Health`接口只有`OnDeath`事件，当一个对象耗尽生命值时会调用该事件。为了在玩家受到伤害时每次更新我们的生命条，我们需要允许我们的`HealthInterface`类在发生这种情况时通知一个对象。

1.  打开`HealthInterface`类的头文件，并添加一个类似于我们在*练习 7.04*中为`OnDeath`事件所做的声明的声明，但这次是为`OnTakeDamage`事件。每当一个对象受到伤害时，将调用此事件：

```cpp
UFUNCTION(BlueprintNativeEvent, Category = Health)
void OnTakeDamage();
virtual void OnTakeDamage_Implementation() = 0;
```

1.  现在我们已经在我们的`Interface`类中添加了这个事件，让我们添加调用该事件的逻辑：打开`HealthComponent`类的源文件，在`LoseHealth`函数的实现中，在从`Health`属性中减去`Amount`属性之后，检查`Owner`是否实现了`Health`接口，如果是，调用它的`OnTakeDamage`事件。这与我们在同一函数中为我们的`OnDeath`事件所做的方式相同，但这次只需将事件的名称更改为`OnTakeDamage`：

```cpp
if (GetOwner()->Implements<UHealthInterface>())
{
  IHealthInterface::Execute_OnTakeDamage(GetOwner());
}
```

因为我们的生命条需要玩家角色的生命值作为百分比，我们需要做以下事情：

1.  在我们的`HealthComponent`中添加一个`public`函数，该函数返回`HealthComponent`类的头文件中的声明，添加一个`FORCEINLINE`函数的声明，该函数返回一个`float`。这个函数应该被称为`GetHealthPercent`，并且是一个`const`函数。它的实现将简单地返回`Health`属性除以`100`，我们将假设这是游戏中一个对象可以拥有的最大生命值的百分比：

```cpp
FORCEINLINE float GetHealthPercent() const { return Health /   100.f; }
```

1.  现在转到`DodgeballCharacter`类的头文件，并添加一个名为`OnTakeDamage_Implementation`的`public` `virtual`函数的声明，该函数不返回任何内容，也不接收任何参数。将其标记为`virtual`和`override`：

```cpp
virtual void OnTakeDamage_Implementation() override;
```

1.  在`DodgeballCharacter`类的源文件中，添加我们刚刚声明的`OnTakeDamage_Implementation`函数的实现。将`OnDeath_Implementation`函数的内容复制到这个新函数的实现中，但做出这个改变：不要调用`PlayerController`的`ShowRestartWidget`函数，而是调用它的`UpdateHealthPercent`函数，并将`HealthComponent`属性的`GetHealthPercent`函数的返回值作为参数传递：

```cpp
void ADodgeballCharacter::OnTakeDamage_Implementation()
{
  ADodgeballPlayerController* PlayerController =   Cast<ADodgeballPlayerController>(GetController());
  if (PlayerController != nullptr)
  {
    PlayerController->UpdateHealthPercent(HealthComponent-  >GetHealthPercent());
  }
}
```

这结束了这个练习的代码设置。在你做完这些改变之后，编译你的代码，打开编辑器，然后做以下操作：

1.  打开`BP_HUDWidget`小部件蓝图，并将其重新设置为`HUDWidget`类，就像你在*练习 8.03*中所做的那样，创建`RestartWidget C++ Class`。

1.  这应该会导致编译错误，你可以通过将我们的进度条元素重命名为`HealthBar`来修复它。

1.  关闭这个小部件蓝图，打开`BP_DodgeballPlayerController`蓝图类，并将其`BP_HUDWidget`属性设置为`BP_HUDWidget`小部件蓝图：![图 8.31：将 BP_HUDWidget 属性设置为 BP_HUDWidget](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_08_31.jpg)

图 8.31：将 BP_HUDWidget 属性设置为 BP_HUDWidget

在你做完这些改变之后，播放关卡。你应该注意到屏幕左上角的`生命条`：

![图 8.32：在屏幕左上角显示的进度条](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_08_32.jpg)

图 8.32：在屏幕左上角显示的进度条

当玩家角色被躲避球击中时，你应该注意到`生命条`被清空：

![图 8.33：随着玩家角色失去生命值，进度条被清空](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_08_33.jpg)

图 8.33：随着玩家角色失去生命值，进度条被清空

有了这些，我们结束了这个练习，你已经学会了在屏幕上添加 HUD 并在游戏过程中更新它的所有必要步骤。

## 活动 8.01：改进 RestartWidget

在本次活动中，我们将向我们的`RestartWidget`添加一个`Text`元素，显示`Game Over`，以便玩家知道他们刚刚输掉了游戏；添加一个`Exit`按钮，允许玩家退出游戏；还更新现有按钮的文本为`Restart`，以便玩家知道点击该按钮时会发生什么。

以下步骤将帮助您完成此活动：

1.  打开`BP_RestartWidget` Widget 蓝图。

1.  将一个新的`Text`元素拖放到现有的`Canvas Panel`元素中。

1.  修改`Text`元素的属性：

+   展开`Anchors`属性，并在`X`轴上将其`Minimum`设置为`0.291`，在`Y`轴上设置为`0.115`，将其`Maximum`设置为`0.708`，在`X`轴上设置为`0.255`，在`Y`轴上设置为`0.708`。

+   将`Offset Left`，`Offset Top`，`Offset Right`和`Offset Bottom`属性设置为`0`。

+   将`Text`属性设置为`GAME OVER`。

+   将`Color and Opacity`属性设置为红色：`RGBA(1.0, 0.082, 0.082, 1.0)`。

+   展开`Font`属性并将其`Size`设置为`100`。

+   将`Justification`属性设置为`Align Text Center`。

1.  选择`RestartButton`属性内的另一个`Text`元素，并将其`Text`属性更改为`Restart`。

1.  复制`RestartButton`属性并将副本的名称更改为`ExitButton`。

1.  将`ExitButton`属性中`Text`元素的`Text`属性更改为`Exit`。

1.  展开`ExitButton`属性的`Anchor`属性，并将其`Minimum`设置为`X`轴上的`0.44`，`Y`轴上的`0.615`，将其`Maximum`设置为`X`轴上的`0.558`，`Y`轴上的`0.692`。

1.  将`ExitButton`属性的`Offset Left`，`Offset Top`，`Offset Right`和`Offset Bottom`设置为`0`。

完成这些更改后，我们需要添加处理`ExitButton`属性点击的逻辑，这将退出游戏：

1.  保存对`BP_RestartWidget` Widget 蓝图所做的更改，并在 Visual Studio 中打开`RestartWidget`类的头文件。在该文件中，添加一个名为`OnExitClicked`的`protected`函数的声明，返回`void`，不接收任何参数。确保将其标记为`UFUNCTION`。

1.  复制现有的`RestartButton`属性，但将其命名为`ExitButton`。

1.  在`RestartWidget`类的源文件中，为`OnExitClicked`函数添加一个实现。将`VictoryBox`类的源文件中`OnBeginOverlap`函数的内容复制到`OnExitClicked`函数中，但删除对`DodgeballCharacter`类的转换。

1.  在`NativeOnInitialized`函数的实现中，将我们创建的`OnExitClicked`函数绑定到`ExitButton`属性的`OnClicked`事件，就像我们在*Exercise 8.03*，*Creating the RestartWidget C++ Class*中为`RestartButton`属性所做的那样。

这就结束了本次活动的代码设置。编译您的更改，打开编辑器，然后打开`BP_RestartWidget`并编译它，以确保由于`BindWidget`标签而没有编译错误。

完成后，再次玩游戏，让玩家角色被三个 Dodgeball 击中，并注意`Restart` Widget 出现了我们的新修改：

![图 8.34：玩家耗尽生命值后显示的更新后的 BP_RestartWidget 耗尽生命值](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_08_34.jpg)

图 8.34：玩家耗尽生命值后显示的更新后的 BP_RestartWidget

如果按下`Restart`按钮，您应该能够重新开始游戏，如果按下`Exit`按钮，游戏应该结束。

这就结束了我们的活动。您已经巩固了使用`Widget`蓝图和更改其元素属性的基础知识，现在可以开始制作自己的菜单了。

注意

此活动的解决方案可在以下网址找到：[`packt.live/338jEBx`](https://packt.live/338jEBx)。

# 总结

通过本章的学习，您已经学会了如何在 UE4 中制作游戏 UI，了解了诸如菜单和 HUD 等内容。您已经了解了如何操作 Widget Blueprint 的 UI 元素，包括“按钮”、“文本”元素和“进度条”；有效地使用锚点，这对于使游戏 UI 优雅地适应多个屏幕至关重要；在 C++中监听鼠标事件，如`OnClick`事件，并利用它来创建自己的游戏逻辑；以及如何将您创建的小部件添加到屏幕上，无论是在特定事件发生时还是始终存在。

在下一章中，我们将通过添加声音和粒子效果来完善我们的躲避球游戏，同时制作一个新的关卡。
