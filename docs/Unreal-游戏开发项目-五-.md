# Unreal 游戏开发项目（五）

> 原文：[`annas-archive.org/md5/697adf25bb6fdefd7e5915903f33de14`](https://annas-archive.org/md5/697adf25bb6fdefd7e5915903f33de14)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十四章：收藏品、强化道具和拾取物品

概述

在本章中，我们将为玩家创建可收藏的硬币和药水强化道具。此外，我们将使用虚幻运动图形 UI 设计师（UMG）为可收藏的硬币设计 UI。最后，我们将创建砖块，这些砖块将隐藏着这些收藏品。通过本章的学习，你将能够在关卡环境中为玩家角色实现收藏品和强化道具。

# 介绍

在上一章中，你创建了玩家投射物，并使用`Anim Notifies`在“投掷”动画期间生成玩家投射物。玩家投射物将作为玩家对抗整个关卡中的敌人的主要进攻游戏机制。由于虚幻引擎 4 提供的默认`Anim Notifies`和你自己的自定义`Anim_ProjectileNotify`类的组合，玩家投射物机制看起来感觉很棒。

我们需要开发的最后一组机制是硬币收藏品和药水强化道具。让我们简要地分析一下收藏品和强化道具是如何影响其他游戏的，以及它们将为我们的“超级横向卷轴”游戏带来什么成就。

**硬币收藏品**

收藏品给玩家一个动力去彻底探索关卡。在许多游戏中，比如《虚空骑士》，收藏品也可以作为一种货币，用来购买角色升级和物品。在其他更经典的平台游戏中，比如超级马里奥或索尼克，收藏品可以提高玩家在关卡中的得分。

在当今的游戏环境中，游戏包含成就是一种预期。收藏品是将成就融入游戏的好方法；例如，在某个关卡或整个游戏中收集所有的硬币的成就。对于“超级横向卷轴”游戏来说，硬币收藏品将成为玩家探索游戏关卡的满意手段，尽可能多地找到硬币。

**药水强化道具**

强化道具给玩家永久或临时的优势，可以对抗敌人或者玩家必须穿越的环境。有许多游戏示例使用了强化道具，其中最著名的之一就是《银河战士》系列。《银河战士》使用强化道具让玩家探索新区域并对抗更强大的敌人。

强化道具也是将成就融入游戏的另一种方式。例如，你可以设定一个成就，使用特定的强化道具摧毁一定数量的敌人。对于“超级横向卷轴”游戏来说，药水强化道具将提高玩家在关卡环境中的能力，增加他们的移动速度和跳跃高度。

在本章中，你将学习如何使用 C++创建硬币收藏品和药水强化道具，为“超级横向卷轴”游戏增加更多的游戏层次。这些游戏元素将源自你将创建的相同基础`actor`类。你还将为收藏品和强化道具添加视觉和音频元素，使它们更加精致。

为了使硬币收藏品和药水强化道具对玩家更具视觉吸引力，我们将为这些角色添加一个旋转组件，以吸引玩家的注意。这就是`URotatingMovementComponent`非常有用的地方；它允许我们以一种非常优化和直接的方式为角色添加旋转，而不是编写自己的逻辑来处理角色的不断旋转。让我们开始学习更多关于这个组件的知识。

# URotatingMovementComponent

`URotatingMovementComponent`是 Unreal Engine 4 中存在的几个移动组件之一。在`SuperSideScroller`游戏项目中，您已经熟悉了`CharacterMovementComponent`和`ProjectileMovementComponent`，而`RotatingMovementComponent`只是另一个移动组件。作为一个复习，移动组件允许不同类型的移动发生在它们所属的 actor 或角色上。

注意

`CharacterMovementComponent`允许您控制角色的移动参数，如其移动速度和跳跃高度，在*第十章*“创建 SuperSideScroller 游戏”中，当您创建`SuperSideScroller`玩家角色时进行了介绍。`ProjectileMovementComponent`允许您向 actor 添加基于抛射物的移动功能，如速度和重力，在*第十四章*“生成玩家抛射物”中，当您开发玩家抛射物时进行了介绍。

与`CharacterMovementComponent`相比，`RotatingMovementComponent`是一个非常简单的移动组件，因为它只涉及旋转`RotatingMovementComponent`所属的 actor；没有其他操作。`RotatingMovementComponent`根据定义的`Rotation Rate`、枢轴平移以及使用本地空间或世界空间中的旋转选项执行组件的连续旋转。

此外，`RotatingMovementComponent`与通过蓝图中的`Event Tick`或`Timelines`等其他旋转 actor 的方法相比要高效得多。

注意

关于移动组件的更多信息可以在这里找到：[`docs.unrealengine.com/en-US/Engine/Components/Movement/index.html#rotatingmovementcomponent`](https://docs.unrealengine.com/en-US/Engine/Components/Movement/index.html#rotatingmovementcomponent)。

我们将使用`RotatingMovementComponent`来允许硬币可收集和药水增强沿 Yaw 轴在原地旋转。这种旋转将吸引玩家的注意力，并给他们一个视觉提示，表明这个可收集物品是重要的。

现在您对`RotatingMovementComponent`有了更好的理解，让我们继续创建`PickableActor_Base`类，这是硬币可收集和药水增强将从中派生的类。

## 练习 15.01：创建 PickableActor_Base 类并添加 URotatingMovementComponent

在这个练习中，您将创建`PickableActor_Base`actor 类，这将作为可收集的硬币和药水增强的基类。您还将从这个 C++基类创建一个蓝图类，以预览`URotatingMovementComponent`的工作原理。按照以下步骤完成这个练习：

注意

在`SuperSideScroller`游戏项目中，您已经多次执行了以下许多步骤，因此将有限的图像来帮助您进行指导。只有在引入新概念时才会有相应的图像。

1.  在 Unreal Engine 4 编辑器中，*左键单击*编辑器左上角的“文件”选项，然后*左键单击*“新建 C++类”选项。

1.  从“选择父类”窗口中，选择`Actor`选项，然后*左键单击*此窗口底部的“下一步”按钮。

1.  将此类命名为`PickableActor_Base`，并将默认的“路径”目录保持不变。然后，选择此窗口底部的“创建类”按钮。

1.  选择“创建类”按钮后，Unreal Engine 4 将重新编译项目代码，并自动打开 Visual Studio，其中包含`PickableActor_Base`类的头文件和源文件。

1.  默认情况下，`Actor`类在头文件中提供了`virtual void Tick(float DeltaTime) override;`函数声明。对于`PickableActor_Base`类，我们不需要`Tick`函数，因此从`PickableActor_Base.h`头文件中删除此函数声明。

1.  接下来，您还需要从`PickableActor_Base.cpp`文件中删除该函数；否则，您将收到编译错误。在此源文件中，查找并删除以下代码：

```cpp
void PickableActor_Base::Tick(float DeltaTime)
{
  Super::Tick(DeltaTime);
}
```

注意

在许多情况下，使用`Tick()`函数进行移动更新可能会导致性能问题，因为`Tick()`函数在每一帧都会被调用。相反，尝试使用`Gameplay Timer`函数在指定的时间间隔执行某些更新，而不是在每一帧上执行。您可以在这里了解更多关于`Gameplay Timers`的信息：[`docs.unrealengine.com/en-US/Programming/UnrealArchitecture/Timers/index.html`](https://docs.unrealengine.com/en-US/Programming/UnrealArchitecture/Timers/index.html)。

1.  现在，是时候添加`PickableActor_Base`类所需的组件了。让我们从`USphereComponent`开始，您将使用它来检测与玩家的重叠碰撞。在`PickableActor_Base.h`头文件中的`Protected`访问修饰符内添加以下代码：

```cpp
UPROPERTY(VisibleDefaultsOnly, Category = PickableItem)
class USphereComponent* CollisionComp;
```

`USphereComponent`的声明现在应该对您非常熟悉；我们在以前的章节中已经做过这个，比如*第十六章*，*多人游戏基础*，当我们创建`PlayerProjectile`类时。

1.  接下来，在声明`USphereComponent`下面添加以下代码来创建一个新的`UStaticMeshComponent`。这将用于视觉上代表硬币可收集或药水提升：

```cpp
UPROPERTY(VisibleDefaultsOnly, Category = PickableItem)
class UStaticMeshComponent* MeshComp;
```

1.  最后，在声明`UStaticMeshComponent`下面添加以下代码来创建一个新的`URotatingMovementComponent`。这将用于给可收集的硬币和药水提供简单的旋转运动：

```cpp
UPROPERTY(VisibleDefaultsOnly, Category = PickableItem)
class URotatingMovementComponent* RotationComp;
```

1.  现在，您已经在`PickableActor_Base.h`头文件中声明了组件，转到`PickableActor_Base.cpp`源文件，以便为这些添加的组件添加所需的`#includes`。在源文件的顶部，在第一个`#include "PickableActor_Base.h"`之后添加以下行：

```cpp
#include "Components/SphereComponent.h"
#include "Components/StaticMeshComponent.h"
#include "GameFramework/RotatingMovementComponent.h"
```

1.  现在，您已经为组件准备好了必要的`include`文件，可以在`APickableActor_Base::APickableActor_Base()`构造函数中添加必要的代码来初始化这些组件：

```cpp
APickableActor_Base::APickableActor_Base()
{
}
```

1.  首先，通过在`APickableActor_Base::APickableActor_Base()`中添加以下代码来初始化`USphereComponent`组件变量`CollisionComp`：

```cpp
CollisionComp = CreateDefaultSubobject   <USphereComponent>(TEXT("SphereComp"));
```

1.  接下来，通过在上一步提供的代码下面添加以下代码，使用默认的球体半径`30.0f`来初始化`USphereComponent`：

```cpp
CollisionComp->InitSphereRadius(30.0f);
```

1.  由于玩家角色需要与此组件重叠，因此您需要添加以下代码，以便默认情况下，`USphereComponent`具有`Overlap All Dynamic`的碰撞设置：

```cpp
CollisionComp->BodyInstance.SetCollisionProfileName("OverlapAllDynamic");
```

1.  最后，`CollisionComp USphereComponent`应该是这个角色的根组件。添加以下代码来分配这个：

```cpp
RootComponent = CollisionComp;
```

1.  现在，`CollisionComp USphereComponent`已经初始化，让我们为`MeshComp UStaticMeshComponent`做同样的事情。添加以下代码。之后，我们将讨论代码为我们做了什么：

```cpp
MeshComp = CreateDefaultSubobject<UStaticMeshComponent>(TEXT("MeshComp"));
MeshComp->AttachToComponent(RootComponent,   FAttachmentTransformRules::KeepWorldTransform);
MeshComp->SetCollisionEnabled(ECollisionEnabled::NoCollision);
```

第一行使用`CreateDefaultSubobject()`模板函数初始化了`MeshComp UStaticMeshComponent`。接下来，您使用`AttachTo()`函数将`MeshComp`附加到您为`CollisionComp`创建的根组件。最后，`MeshComp UStaticMeshComponent`默认不应具有任何碰撞，因此您使用`SetCollisionEnabled()`函数并传入`ECollisionEnable::NoCollision`枚举值。

1.  最后，我们可以通过添加以下代码来初始化`URotatingMovementComponent RotationComp`：

```cpp
RotationComp =   CreateDefaultSubobject<URotatingMovementComponent>(TEXT("RotationComp"));
```

1.  所有组件初始化后，编译 C++代码并返回到 Unreal Engine 4 编辑器。编译成功后，您将继续为`PickableActor_Base`创建蓝图类。

1.  在`Content Browser`窗口中，通过*右键单击*`Content`文件夹并选择`New Folder`选项来创建一个名为`PickableItems`的新文件夹。

1.  在`PickableItems`文件夹中，*右键单击*并选择“蓝图类”。从“选择父类”窗口中，搜索`PickableActor_Base`类并*左键单击*“选择”以创建新的蓝图。

1.  将此蓝图命名为`BP_PickableActor_Base`并*双击*打开蓝图。

1.  在“组件”选项卡中，选择`MeshComp Static Mesh Component`并将`Shape_Cone`静态网格分配给“详细”面板中的“静态网格”参数。请参考以下截图：![图 15.1：分配给 BP_Pickable_Base actor 类的 MeshComp UStaticMeshComponent 的 Shape_Cone 网格](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_15_01.jpg)

图 15.1：分配给 BP_Pickable_Base actor 类的 MeshComp UStaticMeshComponent 的 Shape_Cone 网格

1.  接下来，选择`RotationComp` `URotatingMovementComponent`并在`详细`面板的`旋转组件`类别下找到`旋转速率`参数。

1.  将“旋转速率”设置为以下值：

```cpp
(X=100.000000,Y=100.000000,Z=100.000000)
```

这些值确定了 actor 每秒沿每个轴旋转的速度。这意味着锥形 actor 将沿每个轴以每秒 100 度的速度旋转。

1.  编译`PickableActor_Base`蓝图并将此 actor 添加到您的级别中。

1.  现在，如果您使用 PIE 并查看级别中的`PickableActor_Base` actor，您将看到它正在旋转。请参考以下截图：![图 15.2：现在，锥形网格沿所有轴旋转，根据我们添加到 URotatingMovementComponent 的旋转速率窗口的值](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_15_02.jpg)

图 15.2：现在，锥形网格沿所有轴旋转，根据我们添加到 URotatingMovementComponent 的旋转速率窗口的值

注意

您可以在此处找到此练习的资产和代码：[`packt.live/3njhwyt`](https://packt.live/3njhwyt)。

通过完成此练习，您已经创建了`PickableActor_Base`类所需的基本组件，并学会了如何实现和使用`URotatingMovementComponent`。有了准备好的`PickableActor_Base`类，并且在蓝图 actor 上实现了`URotatingMovementComponent`，我们可以通过添加重叠检测功能，销毁可收集的 actor，并在玩家拾取 actor 时产生音频效果来完成该类。在接下来的活动中，您将添加`PickableActor_Base`类所需的其余功能。

## 活动 15.01：在 PickableActor_Base 中进行玩家重叠检测和产生效果

现在`PickableActor_Base`类具有所有必需的组件，并且其构造函数初始化了这些组件，是时候添加其功能的其余部分了。这些功能将在本章后面的硬币可收集物和药水增益中继承。这些额外的功能包括玩家重叠检测，销毁可收集的 actor，并产生音频效果以向玩家提供反馈，表明它已被成功拾取。执行以下步骤以添加功能，允许`USoundBase`类对象在可收集物与玩家重叠时播放：

1.  在`PickableActor_Base`类中创建一个接受玩家引用作为输入参数的新函数。将此函数命名为`PlayerPickedUp`。

1.  创建一个名为`BeginOverlap()`的新`UFUNCTION`。在继续之前，请确保包括此函数的所有必需输入参数。请参考*第六章*，*碰撞对象*，在那里您在`VictoryBox`类内使用了此函数。

1.  为`USoundBase`类添加一个新的`UPROPERTY()`，并将其命名为`PickupSound`。

1.  在`PickableActor_Base.cpp`源文件中，为`BeginOverlap()`和`PlayerPickedUp()`函数创建定义。

1.  现在，在源文件的顶部为`SuperSideScroller_Player`类和`GameplayStatics`类添加所需的`#include`文件。

1.  在`BeginOverlap()`函数中，使用函数的`OtherActor`输入参数创建对玩家的引用。

1.  在`PlayerPickedUp()`函数中，为`GetWorld()`函数返回的`UWorld*`对象创建一个变量。

1.  使用`UGameplayStatics`库在`PickableActor_Base` actor 的位置生成`PickUpSound`。

1.  然后，调用`Destroy()`函数，以便角色被销毁并从世界中移除。

1.  最后，在`APickableActor_Base::APickableActor_Base()`构造函数中，将`CollisionComp`的`OnComponentBeginOverlap`事件绑定到`BeginOverlap()`函数。

1.  从`Epic Games Launcher`的`Learn`选项卡中下载并安装`Unreal Match 3`项目。使用您在*第十四章*中获得的知识，将`Match_Combo`声波资产从该项目迁移到您的`SuperSideScroller`项目中。

1.  将此声音应用到`BP_PickableActor_Base`蓝图的`PickupSound`参数上。

1.  编译蓝图，如果您的关卡中不存在蓝图，则现在将`BP_PickableActor_Base` actor 添加到您的关卡中。

1.  在`PIE`中，使您的角色与`BP_PickableActor_Base` actor 重叠。

预期输出：

![图 15.3：BP_PickableActor_Base 对象可以被重叠并被玩家拾取](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_15_03.jpg)

图 15.3：BP_PickableActor_Base 对象可以被玩家重叠和拾取

注意

此活动的解决方案可在以下网址找到：[`packt.live/338jEBx`](https://packt.live/338jEBx)。

完成这个活动后，您已经证明了您如何向您的角色类添加`OnBeginOverlap()`功能，并且如何使用这个功能来执行您的角色的逻辑的知识。在`PickableActor_Base`的情况下，我们添加了一个逻辑，将生成一个自定义声音并销毁该角色。

现在`PickableActor_Base`类已经设置好了，是时候开发从中派生的可收集硬币和增益药水类了。硬币可收集类将继承您刚刚创建的`PickableActor_Base`类。它将覆盖关键功能，如`PlayerPickedUp()`函数，以便我们可以在玩家拾取时实现独特的逻辑。除了从继承的父`PickableActor_Base`类中覆盖功能之外，硬币可收集类还将具有其自己独特的属性集，如当前硬币价值和独特的拾取声音。我们将在下一个练习中一起创建硬币可收集类。

## 练习 15.02：创建 PickableActor_Collectable 类

在这个练习中，您将创建`PickableActor_Collectable`类，该类将从您在*练习 15.01*中创建的`PickableActor_Base`类派生，并在*活动 15.01*中完成，*创建 PickableActor_Base 类并添加 URotatingMovement 组件*。这个类将被用作玩家可以在关卡中收集的主要可收集硬币。按照以下步骤完成这个练习：

1.  在虚幻引擎 4 编辑器中，*左键单击*编辑器左上角的`文件`选项，然后*左键单击*`新建 C++类`选项。

1.  从`Choose Parent Class`窗口中选择`PickableActor_Base`选项，然后在此窗口底部*左键单击*`Next`按钮。

1.  将此类命名为`PickableActor_Collectable`，并将默认的`Path`目录保持不变。然后，在此窗口底部选择`Create Class`按钮。

1.  选择`Create Class`按钮后，虚幻引擎 4 将重新编译项目代码，并将自动打开 Visual Studio，显示`PickableActor_Collectable`类的头文件和源文件。

1.  默认情况下，`PickableActor_Collectable.h`头文件在其类声明中没有声明的函数或变量。您需要在新的`Protected Access Modifier`下添加`BeginPlay()`函数的覆盖。添加以下代码：

```cpp
protected:
  virtual void BeginPlay() override;
```

我们覆盖“BeginPlay()`函数的原因是，`URotatingMovementComponent`需要角色初始化并使用“BeginPlay()`来正确旋转角色。因此，我们需要创建这个函数的覆盖声明，并在源文件中创建一个基本的定义。然而，首先，我们需要覆盖另一个重要的函数，来自`PickableActor_Base`父类。

1.  通过在“Protected Access Modifier”下添加以下代码，覆盖`PickableActor_Base`父类中的`PlayerPickedUp()`函数：

```cpp
virtual void PlayerPickedUp(class ASuperSideScroller_Player* Player)   override;
```

通过这样做，我们表明我们将使用并覆盖“PlayerPickedUp()`函数的功能。

1.  最后，创建一个名为`UPROPERTY()`的新整数，它将保存硬币可收集的价值；在这种情况下，它的价值将是`1`。添加以下代码来实现这一点：

```cpp
public:
  UPROPERTY(EditAnywhere, Category = Collectable)
  int32 CollectableValue = 1;
```

在这里，我们正在创建一个整数变量，该变量将在蓝图中可访问，并具有默认值为`1`。如果您愿意，可以使用“EditAnywhere UPROPERTY()`关键字来更改硬币可收集物品的价值。

1.  现在，我们可以继续在`PickableActor_Collectable.cpp`源文件中创建覆盖的“PlayerPickedUp()`函数的定义。在源文件中添加以下代码：

```cpp
void APickableActor_Collectable::PlayerPickedUp(class   ASuperSideScroller_Player* Player)
{
}
```

1.  现在，我们需要使用`Super`关键字调用“PlayerPickedUp()`父函数。将以下代码添加到“PlayerPicked()`函数中：

```cpp
Super::PlayerPickedUp(Player);
```

使用`Super::PlayerPickedUp(Player)`调用父函数，将确保您在`PickableActor_Base`类中创建的功能被调用。您可能还记得，父类中的“PlayerPickedUp()`函数调用生成`PickupSound`声音对象并销毁角色。

1.  接下来，在源文件中创建`BeginPlay()`函数的定义，添加以下代码：

```cpp
void APickableActor_Collectable::BeginPlay()
{
}
```

1.  在 C++中，最后要做的一件事是再次使用`Super`关键字调用“BeginPlay()`父函数。将以下代码添加到`PickableActor_Collectable`类中的“BeginPlay()`函数中：

```cpp
Super::BeginPlay();
```

1.  编译 C++代码并返回编辑器。

注意

您可以在以下链接找到此练习的资产和代码：[`packt.live/35fRN3E`](https://packt.live/35fRN3E)。

现在您已成功编译了`PickableActor_Collectable`类，已经为硬币可收集物品创建了所需的框架。在接下来的活动中，您将从这个类创建一个蓝图，并完成硬币可收集物品角色。

## 活动 15.02：完成 PickableActor_Collectable 角色

现在，`PickableActor_Collectable`类已经具有了所有必要的继承功能和独特属性，是时候从这个类创建蓝图，并添加一个`Static Mesh`，更新其`URotatingMovementComponent`，并将声音应用到`PickUpSound`属性。执行以下步骤来完成`PickableActor_Collectable`角色：

1.  从`Epic Games Launcher`中，在`Learn`选项卡下的`Engine Feature Samples`类别下找到`Content Examples`项目。

1.  从`Content Examples`项目中创建并安装一个新项目。

1.  将`SM_Pickup_Coin`资产及其所有引用的资产从`Content Examples`项目迁移到您的`SuperSideScroller`项目。

1.  在`Content Browser`窗口中的`Content/PickableItems`目录中创建一个名为`Collectable`的新文件夹。

1.  在这个新的`Collectable`文件夹中，从您在*练习 15.02*中创建的`PickableActor_Collectable`类创建一个新的蓝图。将这个新的蓝图命名为`BP_Collectable`。

1.  在这个蓝图中，将`MeshComp`组件的`Static Mesh`参数设置为您在本次活动中导入的`SM_Pickup_Coin`网格。

1.  接下来，将`Match_Combo`声音资源添加到可收集物品的`PickupSound`参数中。

1.  最后，更新`RotationComp`组件，使演员沿 Z 轴以每秒 90 度旋转。

1.  编译蓝图，在您的级别中放置`BP_Collectable`，并使用 PIE。

1.  将玩家角色与`BP_Collectable`演员重叠，并观察结果。

预期输出：

![图 15.4：可旋转的硬币可被玩家重叠](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_15_04.jpg)

图 15.4：可旋转的硬币可被玩家重叠

注意

此活动的解决方案可在以下位置找到：[`packt.live/338jEBx`](https://packt.live/338jEBx)。

完成此活动后，您已经证明了您知道如何将资产迁移到您的虚幻项目中，以及如何使用和更新`URotatingMovementComponent`以满足硬币收藏的需求。现在硬币收藏演员已经完成，是时候为玩家添加功能，以便玩家可以跟踪他们收集了多少硬币。

首先，我们将创建使用`UE_LOG`计算硬币数量的逻辑，然后在游戏的 UI 上使用 UMG 实现硬币计数器。

# 使用 UE_LOG 记录变量

在*第十一章*，*混合空间 1D，键绑定和状态机*中，我们使用并了解了`UE_LOG`函数，以便在玩家应该投掷抛射物时记录。然后我们在*第十三章*，*敌人人工智能*中使用`UE_LOG`函数，记录玩家抛射物击中物体的情况。`UE_LOG`是一个强大的日志记录工具，我们可以使用它将重要信息从我们的 C++函数输出到编辑器中的`输出日志`窗口中。到目前为止，我们只记录了`FStrings`，以在`输出日志`窗口中显示一般文本，以了解我们的函数是否被调用。现在是时候学习如何记录变量以调试玩家收集了多少硬币。

注意

在 Unreal Engine 4 中还有另一个有用的调试函数，称为`AddOnScreenDebugMessage`。您可以在这里了解更多关于此功能的信息：[`docs.unrealengine.com/en-US/API/Runtime/Engine/Engine/UEngine/AddOnScreenDebugMessage/1/index.html`](https://docs.unrealengine.com/en-US/API/Runtime/Engine/Engine/UEngine/AddOnScreenDebugMessage/1/index.html)。

在创建`TEXT()`宏使用的`FString`语法时，我们可以添加格式说明符以记录不同类型的变量。我们只讨论如何为整数变量添加格式说明符。

注意

您可以通过阅读以下文档找到有关如何指定其他变量类型的更多信息：[`www.ue4community.wiki/Logging#Logging_an_FString`](https://www.ue4community.wiki/Logging#Logging_an_FString)。

这是在传递`FString "Example Text"`时`UE_LOG()`的样子：

```cpp
UE_LOG(LogTemp, Warning, TEXT("Example Text"));
```

在这里，您有`Log Category`，`Log Verbose Level`和实际的`FString`，`"Example Text"`，显示在日志中。要记录整数变量，您需要在`TEXT()`宏中添加`％d`，然后在`TEXT()`宏之外添加整数变量名称，用逗号分隔。这是一个例子：

```cpp
UE_LOG(LogTemp, Warning, TEXT("My integer variable %d), MyInteger);
```

格式说明符由`％`符号标识，每种变量类型都有一个对应的字母。在整数的情况下，使用字母`d`。您将使用此方法记录整数变量，以记录玩家在下一个练习中拥有的硬币收藏数量。

## 练习 15.03：跟踪玩家的硬币数量

在这个练习中，您将创建必要的属性和函数，以便跟踪玩家在整个级别中收集的硬币数量。您将在本章后面使用此跟踪来向玩家展示。按照以下步骤完成此练习：

1.  在 Visual Studio 中，找到并打开`SuperSideScroller_Player.h`头文件。

1.  在`Private Access Modifier`下，创建一个名为`NumberofCollectables`的新`int`变量，如下所示：

```cpp
int32 NumberofCollectables;
```

这将是一个私有属性，用于跟踪玩家已收集的硬币的当前数量。您将创建一个公共函数，用于返回这个整数值。出于安全原因，我们这样做是为了确保没有其他类可以修改这个值。

1.  在现有的`public`访问修饰符下，使用`BlueprintPure`关键字创建一个新的`UFUNCTION()`，名为`GetCurrentNumberOfCollectables()`。这个函数将返回一个`int`。以下代码将其添加为内联函数：

```cpp
UFUNCTION(BlueprintPure)
int32 GetCurrentNumberofCollectables() { return NumberofCollectables; };
```

我们使用`UFUNCTION()`和`BlueprintPure`关键字将这个函数暴露给蓝图，以便我们以后在 UMG 中使用它。

1.  声明一个新的`void`函数，在`public`访问修饰符下，名为`IncrementNumberofCollectables()`，接受一个名为`Value`的整数参数：

```cpp
void IncrementNumberofCollectables(int32  Value);
```

这是您将用来跟踪玩家收集了多少硬币的主要函数。我们还将添加一些安全措施，以确保这个值永远不会是负数。

1.  声明了`IncrementNumberofCollectables()`函数，让我们在`SuperSideScroller_Player.cpp`源文件中创建这个函数的定义。

1.  编写以下代码来创建`IncrementNumberofCollectables`函数的定义：

```cpp
void ASuperSideScroller_Player::IncrementNumberofCollectables(int32 Value)
{
}
```

1.  这里需要处理的主要情况是，传递给这个函数的整数值是否小于或等于`0`。在这种情况下，我们不希望麻烦增加`NumberofCollectables`变量。在`IncrementNumberofCollectables()`函数中添加以下代码：

```cpp
if(Value== 0)
{
  return;
}
```

这个`if()`语句表示如果`value`输入参数小于或等于`0`，函数将结束。由于`IncrementNumberofCollectables()`函数返回`void`，在这种情况下使用`return`关键字是完全可以的。

我们添加了这个检查，确保传递给`IncrementNumberofCollectables()`函数的`value`参数既不是 0 也不是负数，因为建立良好的编码习惯非常重要；这保证了处理了所有可能的结果。在实际的开发环境中，可能会有设计师或其他程序员尝试使用`IncrementNumberofCollectables()`函数并尝试传递一个负值或等于 0 的值。如果函数没有考虑到这些可能性，后续开发中可能会出现 bug。

1.  现在我们已经处理了`value`小于或等于`0`的边缘情况，让我们继续使用`else()`语句来增加`NumberofCollectables`。在上一步的`if()`语句下面添加以下代码：

```cpp
else
{
  NumberofCollectables += Value;
}
```

1.  接下来，让我们使用`UE_LOG`和我们学到的关于记录变量的知识来记录`NumberofCollectables`。在`else()`语句之后添加以下代码来正确记录`NumberofCollectables`：

```cpp
UE_LOG(LogTemp, Warning, TEXT("Number of Coins: %d"), NumberofCollectables);
```

通过`UE_LOG()`，我们正在创建一个更健壮的日志来跟踪硬币的数量。这为 UI 的工作奠定了基础。这是因为我们实质上是通过 UMG 在本章后期向玩家记录相同的信息。

添加了`UE_LOG()`后，我们只需要在`PickableActor_Collectable`类中调用`IncrementNumberofCollectables()`函数。

1.  在`PickableActor_Collectable.cpp`源文件中，添加以下头文件：

```cpp
#include "SuperSideScroller_Player.h"
```

1.  接下来，在`PlayerPickedUp()`函数内，在`Super::PlayerPickedUp(Player)`行之前添加以下函数调用：

```cpp
Player->IncrementNumberofCollectables(CollectableValue);
```

1.  现在，我们的`PickableActor_Collectable`类正在调用我们玩家的`IncrementNumberofCollectables`函数，重新编译 C++代码并返回到 Unreal Engine 4 编辑器。

1.  在 UE4 编辑器中，通过*左键单击*`Window`，然后悬停在`Developer Tools`选项上，打开`Output Log`窗口。从这个额外的下拉菜单中选择`Output Log`。

1.  现在，在你的关卡中添加多个`BP_Collectable`角色，然后使用 PIE。

1.  当您重叠每个可收集的硬币时，请观察“输出日志”窗口，以找出每次收集硬币时，“输出日志”窗口将向您显示您已收集了多少枚硬币。

注意

您可以在此处找到此练习的资产和代码：[`packt.live/36t6xM5`](https://packt.live/36t6xM5)。

通过完成此练习，您现在已经完成了开发跟踪玩家收集的硬币数量的 UI 元素所需工作的一半。下半部分将使用在此活动中开发的功能在 UMG 内向玩家在屏幕上显示这些信息。为此，我们需要在虚幻引擎 4 内学习更多关于 UMG 的知识。

# UMG

UMG，或虚幻动态图形用户界面设计师，是虚幻引擎 4 用于创建菜单、游戏内 HUD 元素（如生命条）和其他用户界面的主要工具。

在`SuperSideScroller`游戏中，我们将仅使用“文本”小部件来构建我们的*练习 15.04*中的“硬币收集 UI”，*创建硬币计数器 UI HUD 元素*。我们将在下一节中更多地了解“文本”小部件。

# 文本小部件

“文本”小部件是存在的较简单的小部件之一。这是因为它只允许您向用户显示文本信息并自定义这些文本的视觉效果。几乎每个游戏都以某种方式使用文本向玩家显示信息。例如，《守望先锋》使用基于文本的用户界面向玩家显示关键的比赛数据。如果不使用文本，向玩家传达关键的统计数据，如总伤害、游戏时间总计等，可能会非常困难，甚至不可能。

“文本”小部件出现在 UMG 的“调色板”选项卡中。当您将“文本”小部件添加到“画布”面板时，它将默认显示“文本块”。您可以通过将文本添加到小部件的“文本”参数中来自定义此文本。或者，您可以使用“功能绑定”来显示更强大的文本，可以引用内部或外部变量。“功能绑定”应该在需要显示可能会改变的信息时使用；这可能是代表玩家得分、玩家拥有的金钱数量，或者在我们的情况下，玩家收集的硬币数量。

您将使用“文本”小部件的“功能绑定”功能来显示玩家使用您在*练习 15.03*中创建的“GetCurrentNumberofCollectables（）”函数收集的硬币数量，*跟踪玩家的硬币数量*。

现在我们在“画布”面板中有了“文本”小部件，是时候将这个小部件定位到我们需要的位置了。为此，我们将利用锚点。

## 锚点

锚点用于定义小部件在“画布”面板上的期望位置。一旦定义，锚点将确保小部件在不同平台设备（如手机、平板电脑和计算机）的不同屏幕尺寸上保持这个位置。没有锚点，小部件的位置可能会在不同的屏幕分辨率之间变化，这是不希望发生的。

注意

有关锚点的更多信息，请参阅以下文档：[`docs.unrealengine.com/en-US/Engine/UMG/UserGuide/Anchors/index.html`](https://docs.unrealengine.com/en-US/Engine/UMG/UserGuide/Anchors/index.html)。

为了我们的“硬币收集 UI”和您将使用的“文本”小部件，锚点将位于屏幕的左上角。您还将从此“锚点”位置添加位置偏移，以便文本对玩家更加可见和可读。在继续创建我们的“硬币收集 UI”之前，让我们了解一下“文本格式”，您将使用它来向玩家显示当前收集的硬币数量。

## 文本格式

与 C++中可用的`UE_LOG()`宏类似，蓝图提供了类似的解决方案，用于显示文本并格式化文本以允许添加自定义变量。`格式文本`函数接受一个标记为`Format`的单个文本输入，并返回`Result`文本。然后可以用于显示信息：

![图 15.5：格式文本函数允许我们使用格式化参数自定义文本](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_15_05.jpg)

图 15.5：格式文本函数允许我们使用格式化参数自定义文本

`格式文本`函数不像`UE_LOG()`那样使用`%`符号，而是使用`{}`符号来表示可以传递到字符串中的参数。在`{}`符号之间，您需要添加一个参数名称；这可以是任何你想要的东西，但它应该代表参数是什么。请参考以下截图中显示的示例：

![图 15.6：在这里，我们将一个示例整数传递到格式化文本中](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_15_06.jpg)

图 15.6：在这里，我们将一个示例整数传递到格式化文本中

`格式文本`函数仅支持`Byte`、`Integer`、`Float`、`Text`或`EText Gender`变量类型，因此，如果您尝试将任何其他类型的变量作为参数传递到函数中，您必须将其转换为受支持的类型之一。

注意

`格式文本`功能还用于`文本本地化`，您可以为游戏支持多种语言。有关如何在 C++和蓝图中执行此操作的更多信息，请访问：[`docs.unrealengine.com/en-US/Gameplay/Localization/Formatting/index.html`](https://docs.unrealengine.com/en-US/Gameplay/Localization/Formatting/index.html)。

在下一个练习中，您将在 UMG 中的`Text`小部件中与`格式文本`函数一起使用，我们将创建`Coin Counter UI`小部件，以显示玩家收集的硬币数量。您还将使用`Anchors`将`Text`小部件定位在屏幕的左上角。

## 练习 15.04：创建硬币计数器 UI HUD 元素

在这个练习中，您将创建 UMG UI 资产，用于显示和更新玩家收集的硬币数量。您将使用在*练习 15.02*中创建的`GetCurrentNumberofCollectables()`内联函数，在屏幕上使用简单的`Text`小部件显示此值。按照以下步骤完成此操作：

1.  让我们首先在`Content Browser`窗口内创建一个名为`UI`的新文件夹。在编辑器中的浏览器目录顶部的`Content`文件夹上*右键单击*，然后选择`New Folder`。

1.  在新的`/Content/UI`目录内，*右键单击*，而不是选择`Blueprint Class`，悬停在列表底部的`User Interface`选项上，然后*左键单击*`Widget Blueprint`选项。

1.  将这个新的`Widget Blueprint`命名为`BP_UI_CoinCollection`，然后*双击*该资产以打开 UMG 编辑器。

1.  默认情况下，`Widget`面板是空的，您会在左侧找到一个空的层次结构，如下截图所示：![图 15.7：Widget 面板层次结构概述了 UI 的不同元素如何相互叠加](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_15_07.jpg)

图 15.7：Widget 面板层次结构概述了 UI 的不同元素如何相互叠加

1.  在`Hierarchy`选项卡上方是`Palette`选项卡，列出了您可以在 UI 内使用的所有可用小部件。我们只关注`Text`小部件，它列在`Common`类别下。不要将此选项与 Rich Text Block 小部件混淆。

注意

有关 UMG 中所有可用`Widgets`的更详细参考，请阅读 Epic Games 的以下文档：[`docs.unrealengine.com/en-US/Engine/UMG/UserGuide/WidgetTypeReference/index.html`](https://docs.unrealengine.com/en-US/Engine/UMG/UserGuide/WidgetTypeReference/index.html)。

1.  通过*左键单击*并将`Text`小部件从`Palette`选项卡拖动到`Canvas`面板根下的`Hierarchy`选项卡，或者通过*左键单击*并将`Text`小部件直接拖放到 UMG 编辑器中间的`Canvas`面板本身中，将`Text`小部件添加到`UI`面板。

在更改此小部件的文本之前，我们需要更新其锚点、位置和字体大小，以满足我们在向玩家显示信息方面的需求。

1.  选择`Text`小部件后，您会在其`Details`面板下看到许多选项来自定义此文本。这里要做的第一件事是将`Text`小部件锚定到`Canvas`面板的左上角。*左键单击*`Anchors`下拉菜单，并选择左上角的锚定选项，如下截图所示：![图 15.8：默认情况下，有选项可以锚定小部件在屏幕的不同位置](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_15_08.jpg)

图 15.8：默认情况下，有选项可以锚定小部件在屏幕的不同位置

锚定允许小部件在`Canvas`面板内保持所需的位置，而不受不同屏幕尺寸的影响。

现在`Text`小部件已经锚定在左上角，我们需要设置它相对于此锚点的位置，以便为文本提供更好的定位和可读性的偏移量。

1.  在`Anchors`选项下的`Details`面板中，有`Position X`和`Position Y`的参数。将这两个参数都设置为`100.0f`。

1.  接下来，启用`Size To Content`参数，以便`Text`小部件的大小将根据其显示的文本大小自动调整大小，如下截图所示：![图 15.9：`Size To Content`参数将确保`Text`小部件将显示其完整内容，不会被切断](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_15_09.jpg)

图 15.9：`Size To Content`参数将确保`Text`小部件将显示其完整内容，不会被切断

1.  这里需要做的最后一件事是更新`Text`小部件使用的字体大小。在`Text`小部件的`Details`面板的`Appearance`选项卡下，您会找到`Size`参数。将此值设置为`48`。

1.  最终的`Text`小部件将如下所示：![图 15.10：现在`Text`小部件已经锚定在画布面板的左上角，具有较小的相对偏移和更大的字体，以便玩家更容易阅读](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_15_10.jpg)

图 15.10：现在`Text`小部件已经锚定在画布面板的左上角，具有较小的相对偏移和更大的字体，以便玩家更容易阅读

现在`Text`小部件已经定位和调整大小，让我们为文本添加一个新的绑定，以便它将自动更新并匹配玩家拥有的可收集物品的数量的值。

1.  选择`Text`小部件后，在其`Details`面板的`Content`类别下找到`Text`参数。在那里，您会找到`Bind`选项。

1.  *左键单击*`Bind`选项，然后选择`Create Binding`。这样做时，新的`Function Binding`将自动创建，并被命名为`GetText_0`。请参考以下截图：![图 15.11：重命名绑定函数非常重要因为它们的默认名称太通用了](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_15_11.jpg)

图 15.11：重命名绑定函数非常重要，因为它们的默认名称太通用了

1.  将此函数重命名为`获取可收集物品的数量`。

1.  在继续使用此函数之前，创建一个名为`Player`的新对象引用变量，其类型为`SuperSideScroller_Player`。通过启用变量的`Instance Editable`和`Expose on Spawn`参数，使此变量成为`Public`并在生成时可公开，如下面的截图所示：![图 15.12：现在，Player 变量应该具有 Instance Editable 并启用了 Expose on Spawn 参数](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_15_12.jpg)

图 15.12：现在，Player 变量应该具有 Instance Editable 和 Expose on Spawn 参数

通过将`Player`变量设置为`Public`并在生成时公开，您将能够在创建小部件并将其添加到屏幕时分配此变量。我们将在*练习 15.05*中执行此操作，*将硬币计数器 UI 添加到玩家屏幕*。

现在我们有一个对`SuperSideScroller_Player`的引用变量，让我们继续使用`Get Number of Collectables`绑定函数。

1.  将`Player`变量的`Getter`添加到`Get Number of Collectables`函数中。

1.  从此变量中，*左键单击* 并从上下文敏感的下拉菜单中拖动，并找到并选择`Get Current Number of Collectables`函数。请参阅下面的截图：![图 15.13：您在练习 15.03 中创建的 Get Current Numberof Collectables C++函数您在练习 15.03 中创建的](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_15_13.jpg)

图 15.13：您在练习 15.03 中创建的 Get Current Numberof Collectables C++函数

1.  接下来，*左键单击* 并拖动 `Get Number of Collectables` 的 `Return Value` 文本参数到 `Return Node`。从上下文敏感的下拉菜单中，搜索并选择 `Format Text` 选项，如下面的截图所示：![图 15.14：现在，我们可以创建自定义和格式化的文本以满足文本的需求](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_15_14.jpg)

图 15.14：现在，我们可以创建自定义和格式化的文本以满足文本的需求

1.  在`Format Text`函数中添加以下文本：

```cpp
Coins: {coins}
```

请参阅下面的截图：

![图 15.15：现在，格式化的文本有一个新的输入参数我们可以使用的文本来显示自定义信息](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_15_15.jpg)

图 15.15：现在，格式化的文本有一个新的输入参数，我们可以使用它来显示自定义信息

请记住，使用`{}`符号表示允许您将变量传递到文本中的文本参数。

1.  最后，将`GetCurrentNumberofCollectables()`函数的整数`Return Value`连接到`Format Text`函数的通配符`coins`输入引脚，如下所示：![图 15.16：现在，文本小部件将根据从 Get Current Numberof Collectables 函数返回的更新值自动更新](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_15_16.jpg)

图 15.16：现在，文本小部件将根据从 Get Current Numberof Collectables 函数返回的更新值自动更新

1.  编译并保存`BP_UI_CoinCollection`小部件蓝图。

注意

您可以在此处找到此练习的资产和代码：[`packt.live/3eQJjTU`](https://packt.live/3eQJjTU)。

完成此练习后，您已经创建了显示玩家收集的硬币当前数量所需的`UI UMG`小部件。通过使用`GetCurrentNumberofCollectables()` C++函数和`Text`小部件的绑定功能，UI 将根据收集的硬币数量始终更新其值。在下一个练习中，我们将将此 UI 添加到玩家的屏幕上，但首先，我们将简要了解如何向玩家屏幕添加和删除 UMG。

# 添加和创建 UMG 用户小部件

现在我们已经在 UMG 中创建了 Coin Collection UI，是时候学习如何将 UI 添加到玩家屏幕上并从中移除了。通过将 Coin Collection UI 添加到玩家屏幕上，UI 将对玩家可见，并且可以在玩家收集硬币时进行更新。

在蓝图中，有一个名为`Create Widget`的函数，如下面的屏幕截图所示。如果没有分配类，它将被标记为`Construct None`，但不要让这使你困惑：

![图 15.17：默认情况下的 Create 小部件，没有应用类](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_15_17.jpg)

图 15.17：默认情况下的 Create 小部件，没有应用类

此函数要求创建`User`小部件的类，并需要一个`Player Controller`作为此 UI 的拥有玩家的引用。然后，此函数将生成的用户小部件作为其`Return Value`返回，然后您可以使用`Add to Viewport`函数将其添加到玩家的视口。 `Create Widget`函数只实例化小部件对象；它不会将此小部件添加到玩家的屏幕上。正是`Add to Viewport`函数使此小部件在玩家的屏幕上可见。

![图 15.18：带有 ZOrder 的 Add to Viewport 函数](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_15_18.jpg)

图 15.18：带有 ZOrder 的 Add to Viewport 函数

视口是游戏屏幕，覆盖了你对游戏世界的视图，并且它使用所谓的`ZOrder`来确定覆盖深度，在多个 UI 元素需要在彼此上方或下方重叠的情况下。默认情况下，`Add to Viewport`函数将把`User`小部件添加到屏幕上，并使其填满整个屏幕；也就是说，除非调用`Set Desired Size In Viewport`函数来手动设置它应该填充的大小：

![图 15.19：Size 参数确定传入的 User 小部件的期望大小](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_15_19.jpg)

图 15.19：Size 参数确定传入的 User 小部件的期望大小

在 C++中，您还有一个名为“CreateWidget（）”的函数：

```cpp
template<typename WidgetT, typename OwnerT>
WidgetT * CreateWidget
(
  OwnerT * OwningObject,
  TSubclassOf < UUserWidget > UserWidgetClass,
  FName WidgetName
)
```

“CreateWidget（）”函数可通过`UserWidget`类使用，在`/Engine/Source/Runtime/UMG/Public/Blueprint/UserWidget.h`中可以找到。

可以在*第八章*“用户界面”中找到一个例子，您可以使用“CreateWidget（）”函数创建`BP_HUDWidget`：

```cpp
HUDWidget = CreateWidget<UHUDWidget>(this, BP_HUDWidget);
```

有关 C++中“CreateWidget（）”函数的更多信息，请参阅*第八章*“用户界面”和*Exercise 8.06*“创建健康条 C++逻辑”。

这个函数几乎与其蓝图对应函数的工作方式相同，因为它接受`Owning Object`参数，就像蓝图函数的`Owning Player`参数一样，并且需要创建`User Widget`类。C++的“CreateWidget（）”函数还接受一个`FName`参数来表示小部件的名称。

现在我们已经了解了用于向玩家屏幕添加 UI 的方法，让我们将这些知识付诸实践。在以下练习中，您将实现`Create Widget`和`Add to Viewport`蓝图函数，以便我们可以将我们在*Exercise 15.04*中创建的硬币收集 UI 添加到玩家屏幕上。

## 练习 15.05：将硬币计数器 UI 添加到玩家屏幕

在这个练习中，您将创建一个新的`Player Controller`类，以便您可以使用玩家控制器将`BP_UI_CoinCollection`小部件蓝图添加到玩家的屏幕上。然后，您还将创建一个新的`Game Mode`类，并将此游戏模式应用于`SuperSideScroller`项目。执行以下步骤完成此练习：

1.  在虚幻引擎 4 编辑器中，导航到“文件”，然后选择“新建 C++类”。

1.  从“选择父类”对话框中，找到并选择`Player Controller`选项。

1.  将新的`Player Controller`类命名为`SuperSideScroller_Controller`，然后*左键单击*“创建类”按钮。Visual Studio 将自动生成并打开`SuperSideScroller_Controller`类的源文件和头文件，但现在我们将留在虚幻引擎 4 编辑器内。

1.  在“内容浏览器”窗口中，在`MainCharacter`文件夹目录下，创建一个名为`PlayerController`的新文件夹。

1.  在`PlayerController`文件夹中，*右键*并使用新的`SuperSideScroller_Controller`类创建一个新的`Blueprint Class`。请参考以下截图：![图 15.20：找到新的 SuperSideScroller_Controller 类创建一个新的蓝图](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_15_20.jpg)

图 15.20：找到新的 SuperSideScroller_Controller 类以创建一个新的蓝图

1.  将这个新的蓝图命名为`BP_SuperSideScroller_PC`，然后*双击*该资产以打开它。

要将`BP_UI_CoinCollection` widget 添加到屏幕上，我们需要使用`Add to Viewport`函数和`Create Widget`函数。我们希望在玩家角色被玩家控制器`Possess`之后，将 UI 添加到玩家的屏幕上。

1.  *右键*在蓝图图表中，并从上下文敏感菜单中找到`Event On Possess`选项，*左键*将其添加到图表中。请参考以下截图：![图 15.21：每次调用 Event On Possess 选项这个控制器类拥有一个新的 pawn](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_15_21.jpg)

图 15.21：每次这个控制器类拥有一个新的 pawn 时，将调用 Event On Possess 选项

`Event On Possess`事件节点返回`Possessed Pawn`。我们将使用这个 pawn 传递给我们的`BP_UI_CoinCollection UI Widget`，但首先，我们需要`Cast To` `SuperSideScroller_Player`类。

1.  *左键*并从`Event On Possess`节点的`Possessed Pawn`参数输出中拖动。然后，搜索并找到`Cast to SuperSideScroller_Player`节点。请参考以下截图：![图 15.22：我们需要转换为 SuperSideScroller_Player 以确保我们转换到正确的玩家角色类](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_15_22.jpg)

图 15.22：我们需要转换为 SuperSideScroller_Player 以确保我们转换到正确的玩家角色类

1.  现在，*右键*并搜索`Create Widget`函数将其添加到蓝图图表中。

1.  从下拉类参数中，找到并分配在*Exercise 15.04*中创建的`BP_UI_CoinCollection`资产，*Creating the Coin Counter UI HUD Element*。请参考以下截图：![图 15.23：Create Widget 函数将创建一个新的 UI 对象使用传递给它的 UMG 类](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_15_23.jpg)

图 15.23：Create Widget 函数将使用传递给它的 UMG 类创建一个新的 UI 对象

将`Class`参数更新为`BP_UI_CoinCollection`类后，您会注意到`Create Widget`函数将更新以显示您创建的`Player`变量，设置为`Exposed on Spawn`。

1.  *右键*在蓝图图表中搜索并找到`Self`引用变量。将`Self`对象变量连接到`Create Widget`函数的`Owning Player`参数，如下图所示：![图 15.24：Owning Player 输入参数是 Player Controller 类型](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_15_24.jpg)

图 15.24：Owning Player 输入参数是 Player Controller 类型

`拥有玩家`参数是指将显示和拥有此 UI 对象的`Player Controller`类型。由于我们将此 UI 添加到`SuperSideScroller_Controller`蓝图中，我们可以直接使用`Self`引用变量传递给函数。

1.  接下来，将返回的`SuperSideScroller_Player`变量从`Cast`节点传递到`Create Widget`函数的`Player`输入节点。然后，连接`Cast`节点和`Create Widget`函数的执行引脚，如下图所示：![图 15.25：如果 Cast To SuperSideScroller_Player 有效，我们可以创建 BP_UI_CoinCollection widget 并传递被占有的玩家](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_15_25.jpg)

图 15.25：如果 Cast To SuperSideScroller_Player 有效，我们可以创建 BP_UI_CoinCollection widget 并传递被占有的玩家

注意

您可以在以下链接找到前面截图的全分辨率以获得更好的查看体验：[`packt.live/3f89m99`](https://packt.live/3f89m99)。

1.  *右键单击*蓝图图表内部再次搜索并找到`Add to Viewport`函数，以便将其放置在图表中。

1.  将`Create Widget`函数的输出`Return Value`参数连接到`Add to Viewport`函数的`Target`输入参数；不要更改`ZOrder`参数。

1.  最后，连接`Create Widget`和`Add to Viewport`函数的执行引脚，如下所示：![图 15.26：创建完 BP_UI_CoinCollection 小部件后，我们可以将其添加到玩家视口](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_15_26.jpg)

图 15.26：创建完 BP_UI_CoinCollection 小部件后，我们可以将其添加到玩家视口

注意

您可以在以下链接找到前面截图的全分辨率以获得更好的查看体验：[`packt.live/2UwufBd`](https://packt.live/2UwufBd)。

现在，玩家控制器将`BP_UI_CoinCollection`小部件添加到玩家视口，我们需要创建一个`GameMode`蓝图，并将`BP_SuperSideScroller_MainCharacter`和`BP_SuperSideScroller_PC`类应用到这个游戏模式中。

1.  在`Content Browser`窗口中，通过*右键单击*`Content`文件夹并选择`New Folder`来创建一个新文件夹。将此文件夹命名为`GameMode`。

1.  接下来，*右键单击*并选择`Blueprint Class`开始创建游戏模式蓝图。从`Pick Parent Class`对话框中搜索并找到`SuperSideScrollerGameMode`，位于`All Classes`下。

1.  将这个新的`GameMode`蓝图命名为`BP_SuperSideScroller_GameMode`。*双击*此资产以打开它。

`GameMode`蓝图包含一个类列表，您可以使用自己的类进行自定义。目前，我们只需要担心`Player Controller Class`和`Default Pawn Class`。

1.  *左键单击*`Player Controller Class`下拉菜单，找到并选择之前在此练习中创建的`BP_SuperSideScroller_PC`蓝图。

1.  然后，*左键单击*`Default Pawn Class`下拉菜单，找到并选择`BP_SuperSideScroller_MainCharacter`蓝图。

现在我们有了一个自定义的`GameMode`，它利用我们自定义的`Player Controller`和`Player Character`类，让我们将这个游戏模式添加到`Project Settings`窗口，这样在使用 PIE 和构建项目时，默认情况下会使用游戏模式。

1.  从 Unreal Engine 4 编辑器中，导航到屏幕顶部的`Edit`选项。*左键单击*此选项，并从下拉菜单中找到并选择`Project Settings`选项。

1.  在`Project Settings`窗口的左侧，您将看到一个分成几个部分的类别列表。在`Project`部分下，*左键单击*`Maps & Modes`类别。

1.  在`Maps & Modes`部分，您有一些与项目默认地图和游戏模式相关的参数。在此部分的顶部，您有`Default GameMode`选项。*左键单击*此下拉菜单，找到并选择之前在此练习中创建的`SuperSideScroller_GameMode`蓝图。

注意

对`Maps & Modes`部分的更改会自动保存并写入`DefaultEngine.ini`文件，该文件位于项目的`Config`文件夹中。可以通过更新`GameMode Override`参数来覆盖每个级别的`Default GameMode`，该参数位于级别的`World Settings`窗口中。

1.  关闭`Project Settings`窗口并返回到您的级别。使用 PIE 并开始收集硬币。观察到每次收集硬币时，`BP_UI_CoinCollection`小部件都会显示并更新，如下图所示：![图 15.27：现在，您收集的每个硬币都将显示在玩家 UI 上](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_15_27.jpg)

图 15.27：现在，您收集的每个硬币都将显示在玩家 UI 上

注意

您可以在此处找到此练习的资产和代码：[`packt.live/2JRfSFz`](https://packt.live/2JRfSFz)。

完成此练习后，您已经创建了`UI UMG`小部件，该小部件用于显示玩家收集的当前硬币数量。通过使用`GetCurrentNumberofCollectables()`C++函数和`Text`小部件的绑定功能，UI 将根据收集的硬币数量始终更新其值。

到目前为止，我们已经专注于可收集的硬币，并允许玩家收集这些硬币并将总硬币数添加到玩家的 UI 中。现在，我们将专注于药水增益，并为玩家在短时间内提供移动速度和跳跃高度增加。为了实现这个功能，我们首先需要研究计时器。

# 计时器

虚幻引擎 4 中的计时器允许您在延迟后执行操作，或者每隔 X 秒执行一次。在`SuperSideScroller`药水增益的情况下，将使用计时器在 8 秒后将玩家的移动和跳跃恢复到默认状态。

注意

在蓝图中，您可以使用延迟节点以及计时器句柄来实现相同的结果。但是，在 C++中，计时器是实现延迟和重复逻辑的最佳手段。

计时器由“计时器管理器”或`FTimerManager`管理，它存在于`UWorld`对象中。您将从`FTimerManager`类中使用的两个主要函数称为`SetTimer()`和`ClearTimer()`：

```cpp
void SetTimer
(
    FTimerHandle & InOutHandle,
    TFunction < void )> && Callback,
    float InRate,
    bool InbLoop,
    float InFirstDelay
)
void ClearTimer(FTimerHandle& InHandle)
```

您可能已经注意到，在两个函数中都需要`FTimerHandle`。此句柄用于控制您设置的计时器。使用此句柄，您可以暂停、恢复、清除甚至延长计时器。

`SetTimer()`函数还有其他参数可帮助您在最初设置计时器时自定义此“计时器”。回调函数将在“计时器”完成后调用，如果`InbLoop`参数为`True`，则它将继续无限期调用回调函数，直到计时器停止。 `InRate`参数是计时器本身的持续时间，而`InFirstDelay`是在计时器开始计时之前应用于计时器的初始延迟。

`FTimerManager`类的头文件可以在此处找到：/Engine/Source/Runtime/Engine/Public/TimerManager.h。

注意

您可以通过阅读此处的文档了解有关计时器和`FTimerHandle`的更多信息：[`docs.unrealengine.com/en-US/Programming/UnrealArchitecture/Timers/index.html`](https://docs.unrealengine.com/en-US/Programming/UnrealArchitecture/Timers/index.html)。

在接下来的练习中，您将在`SuperSideScroller_Player`类中创建自己的`FTimerHandle`，并使用它来控制药水增益对玩家的持续时间。

## 练习 15.06：将药水增益行为添加到玩家

在此练习中，您将创建药水增益背后的逻辑，以及它将如何影响玩家角色。您将利用计时器和计时器句柄，以确保增益效果只持续很短的时间。按照以下步骤完成此操作：

1.  在 Visual Studio 中，导航到并打开`SuperSideScroller_Player.h`头文件。

1.  在“我们的私有访问修饰符”下，添加一个名为`PowerupHandle`的`FTimerHandle`类型的新变量：

```cpp
FTimerHandle PowerupHandle;
```

此计时器句柄将负责跟踪自启动以来经过的时间。这将允许我们控制药水增益效果持续多长时间。

1.  接下来，在我们的“私有访问修饰符”下添加一个名为`bHasPowerupActive`的布尔变量：

```cpp
bool bHasPowerupActive;
```

在更新`Sprint()`和`StopSprinting()`函数时，我们将使用此布尔变量来确保根据增益是否激活来适当更新玩家的冲刺移动速度。

1.  接下来，在我们的“公共访问修饰符”下声明一个名为`IncreaseMovementPowerup()`的新 void 函数：

```cpp
void IncreaseMovementPowerup();
```

这是将从药水增益类调用的函数，以启用玩家的增益效果。

1.  最后，您需要创建一个处理电源增强效果结束时的函数。在`Protected Access Modifier`下创建一个名为`EndPowerup()`的函数：

```cpp
void EndPowerup();
```

有了所有必要的变量和声明的函数，现在是时候开始定义这些新函数并处理玩家的电源增强效果了。

1.  导航到`SuperSideScroller_Player.cpp`源文件。

1.  首先，在源文件的顶部添加头文件`#include "TimerManager.h"`；我们将需要这个类来使用`Timers`。

1.  通过在源文件中添加以下代码来定义`IncreaseMovementPowerup()`函数：

```cpp
void ASuperSideScroller_Player::IncreaseMovementPowerup()
{
}
```

1.  当调用此函数时，我们需要做的第一件事是将`bHasPowerupActive`变量设置为`true`。将以下代码添加到`IncreaseMovementPowerup()`函数中：

```cpp
bHasPowerupActive = true;
```

1.  接下来，添加以下代码来增加玩家角色移动组件的`MaxWalkSpeed`和`JumpZVelocity`组件：

```cpp
GetCharacterMovement()->MaxWalkSpeed = 500.0f;
GetCharacterMovement()->JumpZVelocity = 1500.0f;
```

在这里，我们将`MaxWalkSpeed`从默认值`300.0f`更改为`500.0f`。您可能还记得，默认的冲刺速度也是`500.0f`。我们将在本活动的后续部分中解决这个问题，以在电源增强状态下增加冲刺速度。

1.  利用计时器，我们需要获得对`UWorld`对象的引用。添加以下代码：

```cpp
UWorld* World = GetWorld();
if (World)
{
}
```

与项目中以前做过的许多次一样，我们使用`GetWorld()`函数来获取对`UWorld`对象的引用，并将此引用保存在其变量中。

1.  现在我们已经有了对`World`对象的引用，并且已经执行了有效性检查，可以安全地使用`TimerManager`来设置电源增强计时器。在上一步中显示的`if()`语句中添加以下代码：

```cpp
World->GetTimerManager().SetTimer(PowerupHandle, this,   &ASuperSideScroller_Player::EndPowerup, 8.0f, false);
```

在这里，您正在使用`TimerManager`类来设置计时器。`SetTimer()`函数接受要使用的`FTimerHandle`组件；在这种情况下，是您创建的`PowerupHandle`变量。接下来，我们需要通过使用`this`关键字传递对玩家类的引用。然后，我们需要提供在计时器结束后调用的回调函数，这种情况下是`&ASuperSideScroller_Player::EndPowerup`函数。`8.0f`表示计时器的持续时间；随时根据需要进行调整，但目前 8 秒是可以的。最后，还有一个参数，用于确定此计时器是否应该循环；在这种情况下，不应该循环。

1.  创建`EndPowerup()`函数的函数定义：

```cpp
void ASuperSideScroller_Player::EndPowerup()
{
}
```

1.  当调用`EndPowerup()`函数时，首先要做的是将`bHasPowerupActive`变量设置为`false`。在`EndPowerup()`函数中添加以下代码：

```cpp
bHasPowerupActive = false;
```

1.  接下来，将角色移动组件的`MaxWalkSpeed`和`JumpZVelocity`参数更改回它们的默认值。添加以下代码：

```cpp
GetCharacterMovement()->MaxWalkSpeed = 300.0f;
GetCharacterMovement()->JumpZVelocity = 1000.0f;
```

在这里，我们正在将角色移动组件的`MaxWalkSpeed`和`JumpZVelocity`参数都更改为它们的默认值。

1.  再次利用计时器并清除`PowerupHandle`的计时器处理，我们需要获得对`UWorld`对象的引用。添加以下代码：

```cpp
UWorld* World = GetWorld();
if (World)
{
}
```

1.  最后，我们可以添加代码来清除计时器句柄的`PowerupHandle`：

```cpp
World->GetTimerManager().ClearTimer(PowerupHandle);
```

通过使用`ClearTimer()`函数并传入`PowerupHandle`，我们确保此计时器不再有效，并且不再影响玩家。

现在我们已经创建了处理电源增强效果和与效果相关的计时器的函数，我们需要更新`Sprint()`和`StopSprinting()`函数，以便它们在玩家处于电源增强状态时也考虑到速度。

1.  将`Sprint()`函数更新为以下内容：

```cpp
void ASuperSideScroller_Player::Sprint()
{
  if (!bIsSprinting)
  {
    bIsSprinting = true;
    if (bHasPowerupActive)
    {
      GetCharacterMovement()->MaxWalkSpeed = 900.0f;
    }
    else
    {
      GetCharacterMovement()->MaxWalkSpeed = 500.0f;
    }
  }
}
```

在这里，我们正在更新`Sprint()`函数以考虑`bHasPowerupActive`是否为 true。如果此变量为 true，则我们在冲刺时将`MaxWalkSpeed`从`500.0f`增加到`900.0f`，如下所示：

```cpp
if (bHasPowerupActive)
{
  GetCharacterMovement()->MaxWalkSpeed = 900.0f;
}
```

如果`bHasPowerupActive`为 false，则我们将`MaxWalkSpeed`增加到`500.0f`，就像默认情况下一样。

1.  将`StopSprinting()`函数更新为以下内容：

```cpp
void ASuperSideScroller_Player::StopSprinting()
{
  if (bIsSprinting)
  {
    bIsSprinting = false;
    if (bHasPowerupActive)
    {
      GetCharacterMovement()->MaxWalkSpeed = 500.0f;
    }
    else
    {
      GetCharacterMovement()->MaxWalkSpeed = 300.0f;
    }
  }
}
```

在这里，我们更新`StopSprinting()`函数，以考虑`bHasPowerupActive`是否为真。如果这个变量为真，则将`MaxWalkSpeed`值设置为`500.0f`，而不是`300.0f`，如下所示：

```cpp
if (bHasPowerupActive)
{
  GetCharacterMovement()->MaxWalkSpeed = 500.0f;
}
```

如果`bHasPowerupActive`为假，则将`MaxWalkSpeed`设置为`300.0f`，就像默认情况下一样。

1.  最后，我们只需要重新编译 C++代码。

注意

您可以在这里找到这个练习的资产和代码：[`packt.live/3eP39yL`](https://packt.live/3eP39yL)。

完成这个练习后，您已经在玩家角色中创建了药水增益效果。增益效果增加了玩家的默认移动速度，并增加了他们的跳跃高度。此外，增益效果还增加了奔跑速度。通过使用计时器句柄，您能够控制增益效果持续的时间。

现在，是时候创建药水增益角色了，这样我们就可以在游戏中有一个这个增益的表示了。

## 活动 15.03：创建药水增益角色

现在`SuperSideScroller_Player`类处理了药水增益的效果，是时候创建药水增益类和蓝图了。这个活动的目的是创建药水增益类，继承自`PickableActor_Base`类，实现重叠功能以授予您在*练习 15.06*中实现的移动效果，*将药水增益行为添加到玩家*，并创建药水蓝图角色。执行这些步骤来创建药水增益类和创建药水蓝图角色：

1.  创建一个新的 C++类，继承自`PickableActor_Base`类，并将这个新类命名为`PickableActor_Powerup`。

1.  添加`BeginPlay()`和`PlayerPickedUp()`函数的重写函数声明。

1.  为`BeginPlay()`函数创建函数定义。在`BeginPlay()`函数中，添加对父类函数的调用。

1.  为`PlayerPickedUp()`函数创建函数定义。在`PlayerPickedUp()`函数中，添加对`PlayerPickedUp()`父类函数的调用。

1.  接下来，添加`#include`文件，引用`SuperSideScroller_Player`类，以便我们可以引用玩家类及其函数。

1.  在`PlayerPickedUp()`函数中，使用函数本身的`Player`输入参数来调用`IncreaseMovementPowerup()`函数。

1.  从`Epic Games Launcher`中，在`Learn`选项卡的`Games`类别下找到`Action RPG`项目。使用这个来创建并安装一个新项目。

1.  将`A_Character_Heal_Mana_Cue`和`SM_PotionBottle`资产以及它们所有引用的资产从`Action RPG`项目迁移到您的`SuperSideScroller`项目。

1.  在`PickableItems`目录中的`Content Browser`窗口中创建一个名为`Powerup`的新文件夹。在该目录中基于`PickableActor_Powerup`类创建一个新的蓝图，并将此资产命名为`BP_Powerup`。

1.  在`BP_Powerup`中，更新`MeshComp`组件以使用`SM_PotionBottle`静态网格。

1.  接下来，添加`A_Character_Heal_Mana_Cue`，将其导入为`Pickup Sound`参数。

1.  最后，更新`RotationComp`组件，使得角色每秒绕`Pitch`轴旋转 60 度，绕`Yaw`轴旋转 180 度。

1.  将`BP_Powerup`添加到您的级别中，并使用 PIE 观察与增益重叠时的结果。

预期输出：

![图 15.28：药水增益现在有了一个很好的视觉表示，玩家可以重叠以启用其增益效果](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_15_28.jpg)

图 15.28：药水增益现在有了一个很好的视觉表示，玩家可以重叠以启用其增益效果

注意

这个活动的解决方案可以在这里找到：[`packt.live/338jEBx`](https://packt.live/338jEBx)。

通过完成这个活动，您能够在创建一个新的 C++类方面进行知识测试，该类继承自`PickableActor_Base`类，并覆盖`PlayerPickedUp()`函数以添加自定义逻辑。通过从玩家类中添加对`IncreaseMovementPowerup()`函数的调用，您能够在与该角色重叠时为玩家添加移动增益效果。然后，通过使用自定义网格、材质和音频资产，您能够从`PickableActor_Powerup`类中为蓝图角色赋予生命。

现在我们已经创建了硬币可收集物品和药水增益，我们需要将一个新的游戏功能实现到项目中：`Brick`类。在超级马里奥等游戏中，砖块中包含玩家可以找到的隐藏硬币和增益物品。这些砖块还可以用作到达高架平台和关卡内区域的手段。在我们的`SuperSideScroller`项目中，`Brick`类将用于包含玩家的隐藏硬币可收集物品，并作为允许玩家通过使用砖块作为路径来访问难以到达位置的手段。因此，在下一节中，我们将创建需要被打破以找到隐藏硬币的`Brick`类。

## 练习 15.07：创建 Brick 类

现在我们已经创建了硬币可收集物品和药水增益，是时候创建`Brick`类了，这将为玩家包含隐藏的硬币。砖块是`SuperSideScroller`项目的最终游戏元素。在这个练习中，您将创建`Brick`类，这将作为`SuperSideScroller`游戏项目的平台机制的一部分使用，同时也作为一个容纳玩家可收集物品的手段。按照以下步骤创建`Brick`类及其蓝图：

1.  在虚幻引擎 4 编辑器中，导航到`文件`，然后选择`新建 C++类`。

1.  从`选择父类`对话框中，找到并选择`Actor`类。

1.  将此类命名为`SuperSideScroller_Brick`并*左键单击*`Create Class`。Visual Studio 和虚幻引擎将重新编译代码并为您打开此类。

默认情况下，`SuperSideScroller_Brick`类带有`Tick()`函数，但我们不需要这个函数用于`Brick`类。在继续之前，从`SuperSideScroller_Brick.h`头文件中删除`Tick()`函数声明，并从`SuperSideScroller_Brick.cpp`源文件中删除函数定义。

1.  在`SuperSideScroller_Brick.h`文件的`Private Access Modifier`下，添加以下代码来声明一个新的`UStaticMeshComponent* UPROPERTY()`函数，以表示游戏世界中的砖块：

```cpp
UPROPERTY(VisibleDefaultsOnly, Category = Brick)
class UStaticMeshComponent* BrickMesh;
```

1.  接下来，我们需要创建一个`UBoxComponent UPROPERTY()`，用于处理与玩家角色的碰撞。在我们的`Private Access Modifier`下添加以下代码来添加这个组件：

```cpp
UPROPERTY(VisibleDefaultsOnly, Category = Brick)
class UBoxComponent* BrickCollision;
```

1.  在我们的`Private Access Modifier`下创建`UFUNCTION()`声明`OnHit()`函数。这将用于确定`UBoxComponent`何时被玩家击中：

```cpp
UFUNCTION()
void OnHit(UPrimitiveComponent* HitComp, AActor* OtherActor,   UprimitiveComponent* OtherComp, FVector NormalImpulse,   const FHitResult& Hit);
```

注意

在本项目中开发`PlayerProjectile`类时，您在*第十三章* *敌人人工智能*中使用了`OnHit()`函数。请查看该章节以获取有关`OnHit()`函数的更多信息。

1.  接下来，在我们的`Private Access Modifier`下创建一个新的布尔`UPROPERTY()`，使用`EditAnywhere`关键字，命名为`bHasCollectable`：

```cpp
UPROPERTY(EditAnywhere)
bool bHasCollectable;
```

这个布尔值将确定砖块是否包含玩家的硬币可收集物品。

1.  现在，我们需要一个变量来保存此砖块中有多少硬币可收集物品供玩家使用。我们将通过创建一个名为`Collectable Value`的整数变量来实现这一点。将其放在`private access modifier`下，使用`EditAnywhere`关键字，并将其默认值设置为`1`，如下所示：

```cpp
UPROPERTY(EditAnywhere)
int32 CollectableValue = 1;
```

砖块将需要包含一个独特的声音和粒子系统，以便在玩家摧毁砖块时具有良好的光泽层。我们将在下面添加这些属性。

1.  在`SuperSideScroller_Brick.h`头文件中创建一个新的`Public Access Modifier`。

1.  接下来，使用`EditAnywhere`和`BlueprintReadOnly`关键字为`USoundBase`类的变量创建一个新的`UPROPERTY()`。将此变量命名为`HitSound`，如下所示：

```cpp
UPROPERTY(EditAnywhere, BlueprintReadOnly)
class USoundBase* HitSound;
```

1.  然后，使用`EditAnywhere`和`BlueprintReadOnly`关键字为`UParticleSystem`类的变量创建一个新的`UPROPERTY()`。确保将其放在`public access modifier`下，并将此变量命名为`Explosion`，如下所示：

```cpp
UPROPERTY(EditAnywhere, BlueprintReadOnly, Category = Brick)
class UParticleSystem* Explosion;
```

现在，我们已经为`Brick`类准备好了所有必要的属性，让我们继续进行`SuperSideScroller_Brick.cpp`源文件，在那里我们将初始化组件。

1.  让我们首先添加以下用于`StaticMeshComponent`和`BoxComponent`的`#include`目录。将以下代码添加到源文件的`#include`列表中：

```cpp
#include "Components/StaticMeshComponent.h"
#include "Components/BoxComponent.h"
```

1.  首先，通过将以下代码添加到`ASuperSideScroller_Brick::ASuperSideScroller_Brick()`构造函数来初始化`BrickMesh`组件：

```cpp
BrickMesh = CreateDefaultSubobject<UStaticMeshComponent>(TEXT("BrickMesh"));
```

1.  接下来，`BrickMesh`组件应该具有碰撞，以便玩家可以在其上行走，用于平台游戏目的。为了确保这种情况默认发生，添加以下代码将碰撞设置为`"BlockAll"`：

```cpp
BrickMesh->SetCollisionProfileName("BlockAll");
```

1.  最后，`BrickMesh`组件将作为`Brick`角色的根组件。添加以下代码来实现这一点：

```cpp
RootComponent = BrickMesh;
```

1.  现在，通过将以下代码添加到构造函数中来初始化我们的`BrickCollision UBoxComponent`：

```cpp
BrickCollision = CreateDefaultSubobject<UBoxComponent>  (TEXT("BrickCollision"));
```

1.  就像`BrickMesh`组件一样，`BrickCollision`组件也需要将其碰撞设置为`"BlockAll"`，以便在本练习的后续步骤中添加`OnHit()`回调事件。添加以下代码：

```cpp
BrickCollision->SetCollisionProfileName("BlockAll");
```

1.  接下来，需要将`BrickCollision`组件附加到`BrickMesh`组件上。我们可以通过添加以下代码来实现这一点：

```cpp
BrickCollision->AttachToComponent(RootComponent,   FAttachmentTransformRules::KeepWorldTransform);
```

1.  在完成`BrickCollision`组件的初始化之前，我们需要为`OnHit()`函数添加函数定义。将以下定义添加到源文件中：

```cpp
void ASuperSideScroller_Brick::OnHit(UPrimitiveComponent* HitComp, AActor*   OtherActor, UPrimitiveComponent* OtherComp, FVector NormalImpulse, const   FHitResult& Hit)
{
}
```

1.  现在我们已经定义了`OnHit()`函数，我们可以将`OnComponentHit`回调分配给`BrickCollision`组件。将以下代码添加到构造函数中：

```cpp
BrickCollision->OnComponentHit.AddDynamic(this,   &ASuperSideScroller_Brick::OnHit);
```

1.  编译`SuperSideScroller_Brick`类的 C++代码，并返回到 Unreal Engine 4 编辑器。

1.  在“内容浏览器”窗口中，*右键单击*“内容”文件夹，然后选择“新建文件夹”选项。将此文件夹命名为“砖块”。

1.  在`Brick`文件夹内*右键单击*，然后选择“蓝图类”。在“选择父类”对话框窗口的“所有类”搜索栏中，搜索并选择`SuperSideScroller_Brick`类。

1.  将这个新的蓝图命名为`BP_Brick`，然后*双击*该资源以打开它。

1.  从“组件”选项卡中选择`BrickMesh`组件，并将其`Static Mesh`参数设置为`Shape_Cube`网格。

1.  仍然选择`BrickMesh`组件，将`Element 0`材质参数设置为`M_Brick_Clay_Beveled`。在创建新项目时，Epic Games 默认提供了`M_Brick_Clay_Beveled`材质。它可以在“内容浏览器”窗口的`StarterContent`目录中找到。

与玩家角色的需求以及`SuperSideScroller`游戏项目的平台机制相适应，我们需要调整`BrickMesh`组件的比例。

1.  选择`BrickMesh`组件后，对其`Scale`参数进行以下更改：

```cpp
(X=0.750000,Y=0.750000,Z=0.750000)
```

现在，`BrickMesh`组件的大小为其正常大小的`75%`，当我们将角色放入游戏世界时，以及在我们在关卡中开发有趣的平台部分时，`Brick`角色将变得更易于我们作为设计者管理。

最后一步是更新`BrickCollision`组件的位置，使其只有一部分碰撞从`BrickMesh`组件的底部伸出。

1.  从`Components`选项卡中选择`BrickCollision`组件，并将其`Location`参数更新为以下值：

```cpp
(X=0.000000,Y=0.000000,Z=30.000000)
```

`BrickCollision`组件现在应该定位如下：

![图 15.29：现在，BrickCollision 组件刚好在 BrickMesh 组件之外 BrickMesh 组件](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_15_29.jpg)

图 15.29：现在，BrickCollision 组件刚好在 BrickMesh 组件之外

我们调整`BrickCollision`组件的位置，以便玩家只能在砖块下跳时击中`UBoxComponent`。通过使其略微超出`BrickMesh`组件，我们可以更好地控制这一点，并确保玩家无法以其他方式击中该组件。

注意

您可以在此处找到此练习的资产和代码：[`packt.live/3kr7rh6`](https://packt.live/3kr7rh6)。

完成这个练习后，您已经能够为`SuperSideScroller_Brick`类创建基本框架，并组合蓝图角色以在游戏世界中表示砖块。通过添加立方体网格和砖块材质，您为砖块添加了良好的视觉效果。在接下来的练习中，您将为砖块添加剩余的 C++逻辑。这将允许玩家摧毁砖块并获得可收集物品。

## 练习 15.08：添加 Brick 类 C++逻辑

在上一个练习中，通过添加必要的组件并创建`BP_Brick`蓝图角色，您为`SuperSideScroller_Brick`类创建了基本框架。在这个练习中，您将在*练习 15.07*，*创建 Brick 类*的 C++代码的基础上添加逻辑，以赋予`Brick`类逻辑。这将允许砖块给玩家金币收藏品。执行以下步骤来完成这个过程：

1.  首先，我们需要创建一个函数，将可收集物品添加到玩家。在我们的`Private Access Modifier`下，在`SuperSideScroller_Brick.h`头文件中添加以下函数声明：

```cpp
void AddCollectable(class ASuperSideScroller_Player* Player);
```

我们希望传递对`SuperSideScroller_Player`类的引用，以便我们可以从该类调用`IncrementNumberofCollectables()`函数。

1.  接下来，在我们的`Private Access Modifier`下创建一个名为`PlayHitSound()`的 void 函数声明：

```cpp
void PlayHitSound();
```

`PlayHitSound()`函数将负责生成您在*练习 15.07*，*创建 Brick 类*中创建的`HitSound`属性。

1.  最后，在我们的`Private Access Modifier`下创建另一个名为`PlayHitExplosion()`的 void 函数声明：

```cpp
void PlayHitExplosion();
```

`PlayHitExplosion()`函数将负责生成您在*练习 15.07*中创建的`Explosion`属性。

在头文件中声明了`SuperSideScroller_Brick`类所需的其余函数后，让我们继续在源文件中定义这些函数。

1.  在`SuperSideScroller_Brick.cpp`源文件的顶部，将以下`#includes`添加到已存在的`include`目录列表中：

```cpp
#include "Engine/World.h"
#include "Kismet/GameplayStatics.h"
#include "SuperSideScroller_Player.h"
```

`World`和`GameplayStatics`类的包含是必要的，以生成砖块的`HitSound`和`Explosion`效果。包括`SuperSideScroller_Player`类是为了调用`IncrementNumberofCollectables()`类函数。

1.  让我们从`AddCollectable()`函数的函数定义开始。添加以下代码：

```cpp
void ASuperSideScroller_Brick::AddCollectable(class   ASuperSideScroller_Player* Player)
{
}
```

1.  现在，通过使用`Player`函数输入参数调用`IncrementNumberofCollectables()`函数：

```cpp
Player->IncrementNumberofCollectables(CollectableValue);
```

1.  对于`PlayHitSound()`函数，您需要获取对`UWorld*`对象的引用，并在从`UGameplayStatics`类调用`SpawnSoundAtLocation`函数之前验证`HitSound`属性是否有效。这是您已经做过许多次的过程，所以这是整个函数代码：

```cpp
void ASuperSideScroller_Brick::PlayHitSound()
{
  UWorld* World = GetWorld();
  if (World)
  {
    if (HitSound)
    {
      UGameplayStatics::SpawnSoundAtLocation(World, HitSound,         GetActorLocation());
    }
  }
}
```

1.  就像`PlayHitSound()`函数一样，`PlayHitExplosion()`函数将以几乎相似的方式工作，这是您在此项目中已经做过许多次的过程。添加以下代码以创建函数定义：

```cpp
void ASuperSideScroller_Brick::PlayHitExplosion()
{
  UWorld* World = GetWorld();
  if (World)
  {
    if (Explosion)
    {
      UGameplayStatics::SpawnEmitterAtLocation(World, Explosion,         GetActorTransform());
    }
  }
}
```

有了这些函数的定义，让我们更新`OnHit()`函数，以便如果玩家确实击中了`BrickCollision`组件，我们可以生成`HitSound`和`Explosion`，并将一个硬币可收集物品添加到玩家的收集物品中。

1.  首先，在`OnHit()`函数中，创建一个名为`Player`的新变量，类型为`ASuperSideScroller_Player`，其值等于函数的`OtherActor`输入参数的`Cast`，如下所示：

```cpp
ASuperSideScroller_Player* Player =   Cast<ASuperSideScroller_Player>(OtherActor);
```

1.  接下来，我们只想在`Player`有效且`bHasCollectable`为`True`时继续执行此函数。添加以下`if()`语句：

```cpp
if (Player && bHasCollectable)
{
}
```

1.  如果`if()`语句中的条件满足，那么我们需要调用`AddCollectable()`、`PlayHitSound()`和`PlayHitExplosion()`函数。确保在`AddCollectable()`函数中也传入`Player`变量：

```cpp
AddCollectable(Player);
PlayHitSound();
PlayHitExplosion();
```

1.  最后，在`if()`语句内添加销毁砖块的函数调用：

```cpp
Destroy();
```

1.  当我们需要的`OnHit()`函数定义好了，重新编译 C++代码，但暂时不要返回到虚幻引擎 4 编辑器。

1.  对于砖块爆炸的 VFX 和 SFX，我们需要从`Epic Games Launcher`提供给我们的两个不同项目中迁移资源：`Blueprints`项目和`Content Examples`项目。

1.  利用您之前练习中的知识，使用引擎版本 4.24 下载并安装这些项目。这两个项目都可以在`Learn`选项卡的`Engine Feature Samples`类别下找到。

1.  安装完成后，打开`Content Examples`项目，并在`Content Browser`窗口中找到`P_Pixel_Explosion`资源。

1.  *右键单击*此资源，然后选择`资源操作`，然后选择`迁移`。将此资源及其所有引用的资源迁移到您的`SuperSideScroller`项目中。

1.  一旦成功迁移了此资源，关闭`Content Examples`项目，然后打开`Blueprints`项目。

1.  从`Blueprints`项目的`Content Browser`窗口中找到`Blueprints_TextPop01`资源。

1.  *右键单击*此资源，然后选择`资源操作`，然后选择`迁移`。将此资源及其所有引用的资源迁移到您的`SuperSideScroller`项目中。

将这些资源迁移到您的项目后，返回到您的`SuperSideScroller`项目的虚幻引擎 4 编辑器中。

1.  在`Content Browser`窗口中导航到`Brick`文件夹，*双击*`BP_Brick`资源以打开它。

1.  在角色的`Details`面板中，找到`Super Side Scroller Brick`部分，并将`HitSound`参数设置为您导入的`Blueprints_TextPop01`声波。

1.  接下来，将您导入的`P_Pixel_Explosion`粒子添加到`Explosion`参数中。

1.  重新编译`BP_Brick`蓝图并将两个这样的角色添加到您的关卡中。

1.  将其中一个砖块的`bHasCollectable`参数设置为`True`；将另一个设置为`False`。请参考以下截图：![图 15.30：此砖块角色设置为生成可收集物品](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_15_30.jpg)

图 15.30：此砖块角色设置为生成可收集物品

1.  使用 PIE，观察当您尝试用角色的头部跳跃击中砖块底部时，两个砖块角色之间行为的差异，如下截图所示：![图 15.31：现在，玩家可以击中砖块并将其摧毁](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_15_31.jpg)

图 15.31：现在，玩家可以击中砖块并将其摧毁

当`bHasCollectable`为`True`时，`SuperSideScroller_Brick`将播放我们的`HitSound`，生成`Explosion`粒子系统，向玩家添加一个硬币可收集物品，并被摧毁。

注意

您可以在此处找到此练习的资产和代码：[`packt.live/3pjhoAv`](https://packt.live/3pjhoAv)。

通过完成这个练习，你现在已经完成了`SuperSideScroller`游戏项目的游戏机制开发。现在，`SuperSideScroller_Brick`类可以用于平台游戏玩法和我们想要的游戏中的金币收集机制。

现在砖块可以被摧毁，隐藏的金币可以被收集，我们为`SuperSideScroller`游戏项目设定的所有游戏元素都已经完成。

# 总结

在这一章中，你将你的知识付诸实践，为`SuperSideScroller`游戏项目创建了剩余的游戏机制。通过结合 C++和蓝图，你开发了玩家可以在关卡中收集的药水能力提升和金币。此外，通过使用你在第十四章“生成玩家投射物”中学到的知识，你为这些可收集物品添加了独特的音频和视觉资产，为游戏增添了一层精美的润色。

你学习并利用了虚幻引擎 4 中的`UMG UI`系统，创建了一个简单而有效的 UI 反馈系统，用于显示玩家已经收集的金币数量。通过使用`Text`小部件的绑定功能，你能够保持 UI 与玩家当前已经收集的金币数量保持更新。最后，你使用了从`SuperSideScroller`项目中学到的知识创建了一个`Brick`类，用于为玩家隐藏金币，让他们可以收集和找到它们。

`SuperSideScroller`项目是一个庞大的项目，涵盖了虚幻引擎 4 中许多可用的工具和实践。在第十章“创建 SuperSideScroller 游戏”中，我们导入了自定义的骨骼和动画资产，用于开发玩家角色的动画蓝图。在第十一章“Blend Spaces 1D, Key Bindings, and State Machines”中，我们使用了`Blend spaces`允许玩家角色在空闲、行走和奔跑动画之间进行混合，同时使用`Animation State Machine`来处理玩家角色的跳跃和移动状态。然后，我们学习了如何使用角色移动组件来控制玩家的移动和跳跃高度。

在第十二章“Animation Blending and Montages”中，我们通过使用`Layered Blend per Bone`功能和`Saved Cached Poses`更多地了解了动画蓝图中的动画混合。通过为玩家角色的投掷动画添加一个新的`AnimSlot`，我们能够使玩家的移动动画和投掷动画平滑地混合在一起。在第十三章“Enemy Artificial Intelligence”中，我们使用了行为树和黑板的强大系统来为敌人开发 AI 行为。我们创建了自己的`Task`，使敌人 AI 能够在我们还开发的自定义蓝图中的巡逻点之间移动。

在第十四章“生成玩家投射物”中，我们学习了如何创建`Anim Notify`，以及如何在玩家角色的投掷动画中实现这个通知来生成玩家投射物。然后，我们学习了如何创建投射物，以及如何使用`Projectile Movement Component`让玩家投射物在游戏世界中移动。

最后，在这一章中，我们学习了如何使用`UMG`工具集为可收集的金币创建 UI，以及如何操纵我们的`Character Movement Component`为玩家创建药水能力提升。最后，你创建了一个`Brick`类，可以用来为玩家隐藏金币，让他们找到并收集。

这个总结只是对我们在`SuperSideScroller`项目中学到和完成的内容进行了初步的介绍。在你继续之前，这里有一些挑战供你测试知识并扩展项目：

1.  添加一个新的能力提升，降低应用于玩家角色的重力。导入自定义网格和音频资产，使这个能力提升与你制作的药水能力提升有独特的外观。

1.  当玩家角色收集到 10 个硬币时，给予玩家一个力量增强道具。

1.  实现当玩家与 AI 重叠时允许玩家被摧毁的功能。包括当发生这种情况时，能够让玩家重新生成。

1.  添加另一个能让玩家免疫的力量增强道具，这样当他们与敌人重叠时就不会被摧毁。（事实上，拥有这个力量增强道具时，与敌人重叠时可能会摧毁敌人。）

1.  利用您为`SuperSideScroller`项目开发的所有游戏元素，创建一个新的关卡，利用这些元素打造一个有趣的平台竞技场。

1.  添加多个具有有趣巡逻点的敌人，挑战玩家在导航区域时。

1.  将力量增强道具放置在难以到达的地方，以便玩家需要提高他们的平台技能来获取它们。

1.  为玩家创建危险的陷阱，使他们需要跨越，并添加功能，当玩家从地图上掉下去时会摧毁玩家。

在下一章中，您将学习关于多人游戏的基础知识，服务器-客户端架构，以及在虚幻引擎 4 中用于多人游戏的游戏框架类。您将利用这些知识来扩展虚幻引擎 4 中的多人射击游戏项目。


# 第十五章：多人游戏基础知识

概述

在本章中，您将了解一些重要的多人游戏概念，以便使用虚幻引擎 4 的网络框架为您的游戏添加多人游戏支持。

在本章结束时，您将了解基本的多人游戏概念，如服务器-客户端架构、连接和角色所有权，以及角色和变量复制。您将能够实现这些概念，创建自己的多人游戏。您还将能够制作 2D 混合空间，这允许您在 2D 网格中的动画之间进行混合。最后，您将学习如何使用`Transform (Modify) Bone`节点在运行时控制骨骼网格骨骼。

# 介绍

在上一章中，我们完成了`SuperSideScroller`游戏，并使用了 1D 混合空间、动画蓝图和动画蒙太奇。在本章中，我们将在此基础上构建，并学习如何使用虚幻引擎为游戏添加多人游戏功能。

多人游戏在过去十年里发展迅速。像 Fortnite、PUBG、英雄联盟、火箭联盟、守望先锋和 CS:GO 等游戏在游戏社区中获得了很大的流行，并取得了巨大的成功。如今，几乎所有的游戏都需要具有某种多人游戏体验，以使其更具相关性和成功。

这样做的原因是它在现有的游戏玩法之上增加了新的可能性，比如能够在合作模式（*也称为合作模式*）中与朋友一起玩，或者与来自世界各地的人对战，这大大增加了游戏的长期性和价值。

在下一个主题中，我们将讨论多人游戏的基础知识。

# 多人游戏基础知识

在游戏中，你可能经常听到多人游戏这个术语，但对于游戏开发者来说，它意味着什么呢？实际上，多人游戏只是通过网络（*互联网或局域网*）在服务器和其连接的客户端之间发送的一组指令，以给玩家产生共享世界的错觉。

为了使其工作，服务器需要能够与客户端进行通信，但客户端也需要与服务器进行通信（客户端到服务器）。这是因为客户端通常是影响游戏世界的一方，因此他们需要一种方式来告知服务器他们在玩游戏时的意图。

这种服务器和客户端之间的来回通信的一个例子是当玩家在游戏中尝试开火时。看一下下面的图，它展示了客户端和服务器的交互：

![图 16.1：玩家想要开火时的客户端-服务器交互多人游戏中的武器](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_16_01.jpg)

图 16.1：多人游戏中玩家想要开火时的客户端-服务器交互

让我们来看看*图 16.1*中显示的内容：

1.  玩家按住*鼠标左键*，并且该玩家的客户端告诉服务器它想要开火。

1.  服务器通过检查以下内容来验证玩家是否可以开火：

+   如果玩家还活着

+   如果玩家装备了武器

+   如果玩家有足够的弹药

1.  如果所有验证都有效，则服务器将执行以下操作：

+   运行逻辑以扣除弹药

+   在服务器上生成抛射物角色，自动发送到所有客户端

+   在所有客户端的角色实例上播放开火动画，以确保它们之间的某种同步性，这有助于传达它们是同一个世界的想法，尽管实际上并非如此

1.  如果任何验证失败，服务器会告诉特定的客户端该做什么：

+   玩家已经死亡-不做任何事情

+   玩家没有装备武器-不做任何事情

+   玩家没有足够的弹药-播放空击声音

请记住，如果您希望游戏支持多人游戏，则强烈建议您在开发周期的尽早阶段就这样做。如果您尝试运行启用了多人游戏的单人项目，您会注意到一些功能可能*正常工作*，但可能大多数功能都无法正常工作或达到预期效果。

这是因为当您在单人游戏中执行游戏时，代码在本地立即运行，但是当您将多人游戏加入到方程式中时，您正在添加外部因素，例如与具有延迟的网络上的客户端进行通信的权威服务器，就像您在*图 16.1*中看到的那样。

为了使一切正常运行，您需要将现有代码分解为以下部分：

+   仅在服务器上运行的代码

+   仅在客户端上运行的代码

+   在两者上运行的代码，这可能需要很长时间，具体取决于您的单人游戏的复杂性

为了为游戏添加多人游戏支持，虚幻引擎 4 已经内置了一个非常强大和带宽高效的网络框架，使用权威服务器-客户端架构。

以下是其工作原理的图表：

![图 16.2：虚幻引擎 4 中的服务器-客户端架构](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_16_02.jpg)

图 16.2：虚幻引擎 4 中的服务器-客户端架构

在*图 16.2*中，您可以看到服务器-客户端架构在虚幻引擎 4 中是如何工作的。每个玩家控制一个客户端，使用**双向连接**与服务器通信。服务器在特定级别上运行游戏模式（*仅存在于服务器中*）并控制信息流，以便客户端可以在游戏世界中看到并相互交互。

注意

多人游戏可能是一个非常复杂的话题，因此接下来的几章将作为介绍，帮助您了解基本知识，但不会深入研究。因此，出于简单起见，一些概念可能被省略。

在下一节中，我们将看看服务器。

# 服务器

服务器是架构中最关键的部分，因为它负责处理大部分工作并做出重要决策。

以下是服务器的主要责任概述：

1.  **创建和管理共享世界实例**：服务器在特定级别和游戏模式中运行其自己的游戏实例（*这将在接下来的章节中介绍*），这将成为所有连接的客户端之间的共享世界。使用的级别可以随时更改，并且如果适用，服务器可以自动带上所有连接的客户端。

1.  游戏模式中的`PostLogin`函数被调用。从那时起，客户端将进入游戏，并成为共享世界的一部分，玩家将能够看到并与其他客户端进行交互。如果客户端在任何时候断开连接，那么所有其他客户端都将收到通知，并且游戏模式中的`Logout`函数将被调用。

1.  **生成所有客户端需要了解的角色**：如果要生成所有客户端中存在的角色，则需要在服务器上执行此操作。原因是服务器具有权限，并且是唯一可以告诉每个客户端创建其自己的该角色实例的人。

这是在多人游戏中生成角色的最常见方式，因为大多数角色需要存在于所有客户端中。一个例子是能量增强，所有客户端都可以看到并与之交互。

1.  **运行关键的游戏逻辑**：为了确保游戏对所有客户端都是公平的，关键的游戏逻辑需要仅在服务器上执行。如果客户端负责处理健康扣除，那将是非常容易被利用的，因为玩家可以使用工具在内存中更改健康当前值为 100%，所以玩家在游戏中永远不会死亡。

1.  **处理变量复制**：如果您有一个复制的变量（*在本章中介绍*），那么它的值应该只在服务器上更改。这将确保所有客户端的值会自动更新。您仍然可以在客户端上更改值，但它将始终被服务器的最新值替换，以防止作弊并确保所有客户端同步。

1.  **处理来自客户端的 RPC**：服务器需要处理来自客户端发送的远程过程调用（*第十七章*，*远程过程调用*）。

现在您知道服务器的功能，我们可以讨论在虚幻引擎 4 中创建服务器的两种不同方式。

## 专用服务器

专用服务器仅运行服务器逻辑，因此您不会看到典型的游戏运行窗口，您可以在其中控制本地玩家角色。此外，如果使用`-log`命令提示符运行专用服务器，您将看到一个控制台窗口，记录有关服务器上发生的事件的相关信息，例如客户端是否已连接或断开连接等。作为开发人员，您还可以使用`UE_LOG`宏记录自己的信息。

使用专用服务器是创建多人游戏服务器的一种非常常见的方式，因为它比监听服务器更轻量级，您可以将其托管在服务器堆栈上并让其保持运行。

要在虚幻引擎 4 中启动专用服务器，可以使用以下命令参数：

+   通过快捷方式或命令提示符在编辑器中启动专用服务器，请运行以下命令：

```cpp
<UE4 Install Folder>\Engine\Binaries\Win64\UE4Editor.exe   <UProject Location> <Map Name> -server -game -log
```

以下是一个示例：

```cpp
C:\Program Files\Epic   Games\UE_4.24\Engine\Binaries\Win64\UE4Editor.exe   D:\TestProject\TestProject.uproject TestMap -server -game -log
```

+   打包项目需要专门构建的项目的特殊构建，用作专用服务器。

注意

您可以通过访问[`allarsblog.com/2015/11/06/support-dedicated-servers/`](https://allarsblog.com/2015/11/06/support-dedicated-servers/)和[`www.ue4community.wiki/Dedicated_Server_Guide_(Windows)`](https://www.ue4community.wiki/Dedicated_Server_Guide_(Windows))了解有关设置打包专用服务器的更多信息。

## 监听服务器

监听服务器同时充当服务器和客户端，因此您还将拥有一个窗口，可以以此服务器类型的客户端玩游戏。它还具有是最快启动服务器的优势，但它不像专用服务器那样轻量级，因此可以连接的客户端数量将受到限制。

要启动监听服务器，可以使用以下命令参数：

+   通过快捷方式或命令提示符在编辑器中启动专用服务器，请运行以下命令：

```cpp
<UE4 Install Folder>\Engine\Binaries\Win64\UE4Editor.exe   <UProject Location> <Map Name>?Listen -game
```

以下是一个示例：

```cpp
C:\Program Files\Epic   Games\UE_4.24\Engine\Binaries\Win64\UE4Editor.exe   D:\TestProject\TestProject.uproject TestMap?Listen -game
```

+   打包项目（仅限开发构建）需要专门构建的项目的特殊构建，用作专用服务器：

```cpp
<Project Name>.exe <Map Name>?Listen -game
```

以下是一个示例：

```cpp
D:\Packaged\TestProject\TestProject.exe TestMap?Listen –game
```

在下一节中，我们将讨论客户端。

# 客户端

客户端是架构中最简单的部分，因为大多数参与者将在服务器上拥有权限，所以在这些情况下，工作将在服务器上完成，客户端只需服从其命令。

以下是客户端的主要职责概述：

1.  **从服务器强制执行变量复制**：服务器通常对客户端知道的所有参与者具有权限，因此当复制变量的值在服务器上更改时，客户端需要强制执行该值。

1.  **处理来自服务器的 RPC**：客户端需要处理来自服务器发送的远程过程调用（在*第十七章*，*远程过程调用*中介绍）。

1.  **模拟时预测移动**：当客户端模拟参与者（*本章后面介绍*）时，它需要根据参与者的速度本地预测其位置。

1.  **生成只有客户端需要知道的参与者**：如果要生成只存在于客户端的参与者，则需要在特定客户端上执行该操作。

这是生成角色的最不常见的方法，因为很少有情况下您希望一个角色只存在于一个客户端。一个例子是多人生存游戏中的放置预览角色，玩家控制一个半透明版本的墙，其他玩家直到实际放置之前都看不到。

客户端可以以不同的方式加入服务器。以下是最常见的方法列表：

+   使用虚幻引擎 4 控制台（默认为*`*键）打开它并输入：

```cpp
Open <Server IP Address>
```

例如：

```cpp
Open 194.56.23.4
```

+   使用`Execute Console Command`蓝图节点。一个例子如下：![图 16.3：使用 Execute Console Command 节点加入具有示例 IP 的服务器](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_16_03.jpg)

图 16.3：使用 Execute Console Command 节点加入具有示例 IP 的服务器

+   使用`APlayerController`中的`ConsoleCommand`函数如下：

```cpp
PlayerController->ConsoleCommand("Open <Server IP Address>");
```

这是一个例子：

```cpp
PlayerController->ConsoleCommand("Open 194.56.23.4");
```

+   通过快捷方式或命令提示符使用编辑器可执行文件：

```cpp
<UE4 Install Folder>\Engine\Binaries\Win64\UE4Editor.exe   <UProject Location> <Server IP Address> -game
```

这是一个例子：

`C:\Program Files\Epic Games\UE_4.24\Engine\Binaries\Win64\UE4Editor.exe D:\TestProject\TestProject.uproject 194.56.23.4 -game`

+   通过快捷方式或命令提示符使用打包的开发版本：

```cpp
<Project Name>.exe  <Server IP Address>
```

这是一个例子：

`D:\Packaged\TestProject\TestProject.exe 194.56.23.4`

在下一个练习中，我们将在多人游戏中测试虚幻引擎 4 附带的第三人称模板。

## 练习 16.01：在多人游戏中测试第三人称模板

在这个练习中，我们将创建一个第三人称模板项目，并在多人游戏中进行游玩。

以下步骤将帮助您完成练习。

1.  使用蓝图创建一个名为`TestMultiplayer`的新`Third Person`模板项目，并将其保存到您选择的位置。

项目创建后，应该打开编辑器。现在我们将在多人游戏中测试项目的行为：

1.  在编辑器中，`播放`按钮右侧有一个带有向下箭头的选项。单击它，您应该看到一个选项列表。在`多人游戏选项`部分下，您可以配置要使用多少个客户端以及是否需要专用服务器。

1.  取消`运行专用服务器`的选中，将`玩家数量`更改为`3`，然后单击`新编辑器窗口（PIE）`。

1.  您应该看到三个窗口相互堆叠，代表三个客户端：![图 16.4：启动三个带有监听服务器的客户端窗口](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_16_04.jpg)

图 16.4：启动三个带有监听服务器的客户端窗口

如您所见，这有点凌乱，所以让我们改变窗口的大小。在键盘上按*Esc*停止播放。

1.  再次单击`播放`按钮旁边的向下箭头，并选择最后一个选项`高级设置`。

1.  搜索`游戏视口设置`部分。将`新视口分辨率`更改为`640x480`，然后关闭`编辑器首选项`选项卡。

1.  再次播放游戏，您应该看到以下内容：![图 16.5：使用 640x480 分辨率启动三个客户端窗口与监听服务器](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_16_05.jpg)

图 16.5：使用 640x480 分辨率启动三个客户端窗口与监听服务器

一旦开始游戏，您会注意到窗口的标题栏显示`服务器`，`客户端 1`和`客户端 2`。由于您可以在`服务器`窗口中控制一个角色，这意味着我们正在运行`服务器+客户端 0`而不仅仅是`服务器`，以避免混淆。

通过完成这个练习，您现在有了一个设置，其中您将有一个服务器和三个客户端运行（`客户端 0`，`客户端 1`和`客户端 2`）。

注意

当您同时运行多个窗口时，您会注意到一次只能在一个窗口上进行输入焦点。要将焦点转移到另一个窗口，只需按下*Shift* + *F1*以失去当前的输入焦点，然后单击要关注的新窗口。

如果您在其中一个窗口中玩游戏，您会注意到您可以四处移动和跳跃，其他客户端也能看到。

一切正常运行的原因是角色移动组件自动复制位置、旋转和下落状态（用于显示您是否在跳跃）给您。如果要添加自定义行为，如攻击动画，您不能只是告诉客户端在按键时本地播放动画，因为这在其他客户端上不起作用。这就是为什么需要服务器，作为中介，告诉所有客户端在一个客户端按下按键时播放动画。

# 打包版本

项目完成后，最好将其打包（*如前几章所述*），这样我们就会得到一个纯粹的独立版本，不需要使用虚幻引擎编辑器，运行速度更快，更轻量。

以下步骤将帮助您创建*Exercise 16.01*，*在多人游戏文件中测试第三人称模板*的打包版本：

1.  转到`文件` -> `打包项目` -> `Windows` -> `Windows（64 位）`。

1.  选择一个文件夹放置打包版本，并等待完成。

1.  转到所选文件夹，并打开其中的`WindowsNoEditor`文件夹。

1.  *右键单击*`TestMultiplayer.exe`，选择“创建快捷方式”。

1.  将新的快捷方式重命名为`运行服务器`。

1.  *右键单击*它，选择“属性”。

1.  在目标上附加`ThirdPersonExampleMap?Listen -server`，这将使用`ThirdPersonExampleMap`创建一个监听服务器。您应该得到这个：

```cpp
"<Path>\WindowsNoEditor\TestMultiplayer.exe"   ThirdPersonExampleMap?Listen -server
```

1.  点击“确定”并运行快捷方式。

1.  您应该会收到 Windows 防火墙提示，所以允许它。

1.  保持服务器运行，并返回文件夹，从`TestMultiplayer.exe`创建另一个快捷方式。

1.  将其重命名为`运行客户端`。

1.  *右键单击*它，选择“属性”。

1.  在目标上附加`127.0.0.1`，这是您本地服务器的 IP。您应该得到`"<Path>\WindowsNoEditor\TestMultiplayer.exe" 127.0.0.1`。

1.  点击“确定”并运行快捷方式。

1.  现在你已经连接到监听服务器，所以你可以看到彼此的角色。

1.  每次单击“运行客户端”快捷方式，您都会向服务器添加一个新的客户端，因此您可以在同一台机器上运行几个客户端。

在接下来的部分，我们将看看连接和所有权。

# 连接和所有权

在使用虚幻引擎进行多人游戏时，一个重要的概念是连接。当客户端加入服务器时，它将获得一个新的**玩家控制器**，并与之关联一个连接。

如果一个角色与服务器没有有效的连接，那么该角色将无法进行复制操作，如变量复制（*本章后面介绍*）或调用 RPC（在*第十七章*，*远程过程调用*中介绍）。

如果玩家控制器是唯一持有连接的角色，那么这是否意味着它是唯一可以进行复制操作的地方？不是，这就是`GetNetConnection`函数发挥作用的地方，该函数在`AActor`中定义。

在对角色进行复制操作（如变量复制或调用 RPC）时，虚幻框架将通过调用`GetNetConnection()`函数来获取角色的连接。如果连接有效，则复制操作将被处理，如果无效，则不会发生任何事情。`GetNetConnection()`的最常见实现来自`APawn`和`AActor`。

让我们看看`APawn`类如何实现`GetNetConnection()`函数，这通常用于角色：

```cpp
class UNetConnection* APawn::GetNetConnection() const
{
  // if have a controller, it has the net connection
  if ( Controller )
  {
    return Controller->GetNetConnection();
  }
  return Super::GetNetConnection();
}
```

前面的实现是虚幻引擎 4 源代码的一部分，它首先检查 pawn 是否有有效的控制器。如果控制器有效，则使用其连接。如果控制器无效，则使用`GetNetConnection()`函数的父实现，即`AActor`上的实现：

```cpp
UNetConnection* AActor::GetNetConnection() const
{
  return Owner ? Owner->GetNetConnection() : nullptr;
}
```

前面的实现也是虚幻引擎 4 源代码的一部分，它将检查角色是否有有效的所有者。如果有，它将使用所有者的连接；如果没有，它将返回一个无效的连接。那么这个`Owner`变量是什么？每个角色都有一个名为`Owner`的变量（可以通过调用`SetOwner`函数来设置其值），显示哪个角色*拥有*它，因此你可以将其视为父角色。

在这个`GetNetConnection()`的实现中使用所有者的连接将像一个层次结构一样工作。如果在所有者的层次结构中找到一个是玩家控制器或者被玩家控制器控制的所有者，那么它将有一个有效的连接，并且能够处理复制操作。看下面的例子。

注意

在监听服务器中，由其客户端控制的角色的连接将始终无效，因为该客户端已经是服务器的一部分，因此不需要连接。

想象一个武器角色被放置在世界中，它就在那里。在这种情况下，武器将没有所有者，因此如果武器尝试执行任何复制操作，如变量复制或调用 RPC，将不会发生任何事情。

然而，如果客户端拾取武器并在服务器上调用`SetOwner`并将值设置为角色，那么武器现在将有一个有效的连接。原因是武器是一个角色，因此为了获取其连接，它将使用`AActor`的`GetNetConnection()`实现，该实现返回其所有者的连接。由于所有者是客户端的角色，它将使用`APawn`的`GetNetConnection()`的实现。角色有一个有效的玩家控制器，因此这是函数返回的连接。

这里有一个图表来帮助你理解这个逻辑：

![图 16.6：武器角色的连接和所有权示例](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_16_06.jpg)

图 16.6：武器角色的连接和所有权示例

让我们了解无效所有者的元素：

+   `AWeapon`没有覆盖`GetNetConnection`函数，因此要获取武器的连接，它将调用找到的第一个实现，即`AActor::GetNetConnection`。

+   `AActor::GetNetConnection`的实现调用其所有者的`GetNetConnection`。由于没有所有者，连接是无效的。

有效的所有者将包括以下元素：

+   `AWeapon`没有覆盖`GetNetConnection`函数，因此要获取其连接，它将调用找到的第一个实现，即`AActor::GetNetConnection`。

+   `AActor::GetNetConnection`的实现调用其所有者的`GetNetConnection`。由于所有者是拾取武器的角色，它将在其上调用`GetNetConnection`。

+   `ACharacter`没有覆盖`GetNetConnection`函数，因此要获取其连接，它将调用找到的第一个实现，即`APawn::GetNetConnection`。

+   `APawn::GetNetConnection`的实现使用拥有的玩家控制器的连接。由于拥有的玩家控制器是有效的，因此它将使用该连接来处理武器。

注意

为了使`SetOwner`按预期工作，它需要在大多数情况下在服务器上执行，这意味着需要在权限上执行。如果你只在客户端执行`SetOwner`，它仍然无法执行复制操作。

# 角色

当你在服务器上生成一个角色时，将在服务器上创建一个角色的版本，并在每个客户端上创建一个版本。由于在游戏的不同实例（`服务器`，`客户端 1`，`客户端 2`等）上有相同角色的不同版本，因此知道哪个版本的角色是哪个是很重要的。这将使我们知道可以在这些实例中执行什么逻辑。

为了帮助解决这种情况，每个角色都有以下两个变量：

+   `GetLocalRole()`函数。

+   `GetRemoteRole()`函数。

`GetLocalRole()`和`GetRemoteRole()`函数的返回类型是`ENetRole`，它是一个枚举，可以具有以下可能的值：

+   `ROLE_None`：该角色没有角色，因为它没有被复制。

+   `ROLE_SimulatedProxy`：当前游戏实例对该角色没有权限，并且也没有通过玩家控制器来控制它。这意味着它的移动将通过使用角色速度的最后一个值来进行模拟/预测。

+   `ROLE_AutonomousProxy`：当前游戏实例对该角色没有权限，但它由玩家控制。这意味着我们可以根据玩家的输入向服务器发送更准确的移动信息，而不仅仅使用角色速度的最后一个值。

+   `ROLE_Authority`：当前游戏实例对该角色具有完全权限。这意味着如果该角色在服务器上，对该角色的复制变量所做的更改将被视为每个客户端需要通过变量复制强制执行的值。

让我们看一下以下示例代码片段：

```cpp
ENetRole MyLocalRole = GetLocalRole();
ENetRole MyRemoteRole = GetRemoteRole();
FString String;
if(MyLocalRole == ROLE_Authority)
{
  if(MyRemoteRole == ROLE_AutonomousProxy)
  {
    String = «This version of the actor is the authority and
    it›s being controlled by a player on its client»;
  }
  else if(MyRemoteRole == ROLE_SimulatedProxy)
  {
    String = «This version of the actor is the authority but 
    it›s not being controlled by a player on its client»;
  }
}
else String = "This version of the actor isn't the authority";
GEngine->AddOnScreenDebugMessage(-1, 0.0f, FColor::Red, String);
```

上述代码片段将将本地角色和远程角色的值分别存储到`MyLocalRole`和`MyRemoteRole`中。之后，它将根据该角色的版本是权限还是在其客户端上由玩家控制而在屏幕上打印不同的消息。

注意

重要的是要理解，如果一个角色具有`ROLE_Authority`的本地角色，这并不意味着它在服务器上；这意味着它在最初生成角色的游戏实例上，并因此对其具有权限。

如果客户端生成一个角色，即使服务器和其他客户端不知道它，它的本地角色仍将是`ROLE_Authority`。大多数多人游戏中的角色都将由服务器生成；这就是为什么很容易误解权限总是指服务器。

以下是一个表格，帮助您理解角色在不同情况下将具有的角色：

![图 16.7：角色在不同场景中可以拥有的角色](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_16_07.jpg)

图 16.7：角色在不同场景中可以拥有的角色

在上表中，您可以看到角色在不同情况下将具有的角色。

让我们分析每种情况，并解释为什么角色具有该角色：

**在服务器上生成的角色**

该角色在服务器上生成，因此服务器版本的该角色将具有`ROLE_Authority`的本地角色和`ROLE_SimulatedProxy`的远程角色，这是客户端版本的该角色的本地角色。对于该角色的客户端版本，其本地角色将是`ROLE_SimulatedProxy`，远程角色将是`ROLE_Authority`，这是服务器角色版本的本地角色。

**在客户端上生成的角色**

角色在客户端上生成，因此该角色的客户端版本将具有`ROLE_Authority`的本地角色和`ROLE_SimulatedProxy`的远程角色。由于该角色未在服务器上生成，因此它只会存在于生成它的客户端上，因此在服务器和其他客户端上不会有该角色的版本。

**在服务器上生成的玩家拥有的角色**

该角色在服务器上生成，因此服务器版本的该角色将具有`ROLE_Authority`的本地角色和`ROLE_AutonomousProxy`的远程角色，这是客户端版本的该角色的本地角色。对于该角色的客户端版本，其本地角色将是`ROLE_AutonomousProxy`，因为它由`PlayerController`控制，并且远程角色将是`ROLE_Authority`，这是服务器角色版本的本地角色。

**在客户端上生成的玩家拥有的角色**

该 pawn 在客户端上生成，因此该 pawn 的客户端版本将具有`ROLE_Authority`的本地角色和`ROLE_SimulatedProxy`的远程角色。由于 pawn 没有在服务器上生成，因此它只会存在于生成它的客户端上，因此在服务器和其他客户端上不会有这个 pawn 的版本。

## 练习 16.02：实现所有权和角色

在这个练习中，我们将创建一个使用 Third Person 模板作为基础的 C++项目。

创建一个名为`OwnershipTestActor`的新 actor，它具有静态网格组件作为根组件，并且在每次 tick 时，它将执行以下操作：

+   在权限方面，它将检查在一定半径内（由名为`OwnershipRadius`的`EditAnywhere`变量配置）哪个角色离它最近，并将该角色设置为其所有者。当半径内没有角色时，所有者将为`nullptr`。

+   显示其本地角色、远程角色、所有者和连接。

+   编辑`OwnershipRolesCharacter`并覆盖`Tick`函数，以便显示其本地角色、远程角色、所有者和连接。

+   创建一个名为`OwnershipRoles.h`的新头文件，其中包含`ROLE_TO_String`宏，将`ENetRole`转换为`Fstring`变量。

以下步骤将帮助您完成练习：

1.  使用`C++`创建一个名为`OwnershipRoles`的新`Third Person`模板项目，并将其保存到您选择的位置。

1.  项目创建完成后，应该打开编辑器以及 Visual Studio 解决方案。

1.  使用编辑器，创建一个名为`OwnershipTestActor`的新 C++类，该类派生自`Actor`。

1.  编译完成后，Visual Studio 应该弹出新创建的`.h`和`.cpp`文件。

1.  关闭编辑器，返回 Visual Studio。

1.  在 Visual Studio 中，打开`OwnershipRoles.h`文件并添加以下宏：

```cpp
#define ROLE_TO_STRING(Value) FindObject<UEnum>(ANY_PACKAGE,   TEXT("ENetRole"), true)->GetNameStringByIndex((int32)Value)
```

这个宏将把我们从`GetLocalRole()`函数和`GetRemoteRole()`获得的`ENetRole`枚举转换为`FString`。它的工作方式是通过在虚幻引擎的反射系统中找到`ENetRole`枚举类型，并从中将`Value`参数转换为`FString`变量，以便在屏幕上打印出来。

1.  现在，打开`OwnershipTestActor.h`文件。

1.  根据以下代码片段中所示，声明静态网格组件和所有权半径的受保护变量：

```cpp
UPROPERTY(VisibleAnywhere, BlueprintReadOnly, Category =   "Ownership Test Actor")
UStaticMeshComponent* Mesh;
UPROPERTY(EditAnywhere, BlueprintReadOnly, Category = "Ownership   Test Actor")
float OwnershipRadius = 400.0f;
```

在上面的代码片段中，我们声明了静态网格组件和`OwnershipRadius`变量，它允许您配置所有权的半径。

1.  接下来，删除`BeginPlay`的声明，并将构造函数和`Tick`函数的声明移到受保护的区域。

1.  现在，打开`OwnershipTestActor.cpp`文件，并根据以下代码片段中提到的添加所需的头文件：

```cpp
#include "DrawDebugHelpers.h"
#include "OwnershipRoles.h"
#include "OwnershipRolesCharacter.h"
#include "Components/StaticMeshComponent.h"
#include "Kismet/GameplayStatics.h"
```

在上面的代码片段中，我们包括了`DrawDebugHelpers.h`，因为我们将调用`DrawDebugSphere`和`DrawDebugString`函数。我们包括`OwnershipRoles.h`，`OwnershipRolesCharacter.h`和`StaticMeshComponent.h`，以便`.cpp`文件知道这些类。最后，我们包括`GameplayStatics.h`，因为我们将调用`GetAllActorsOfClass`函数。

1.  在构造函数定义中，创建静态网格组件并将其设置为根组件：

```cpp
Mesh = CreateDefaultSubobject<UStaticMeshComponent>("Mesh");
RootComponent = Mesh;
```

1.  在构造函数中，将`bReplicates`设置为`true`，告诉虚幻引擎该 actor 会复制，并且也应该存在于所有客户端中：

```cpp
bReplicates = true;
```

1.  删除`BeginPlay`函数定义。

1.  在`Tick`函数中，绘制一个调试球来帮助可视化所有权半径，如下面的代码片段所示：

```cpp
DrawDebugSphere(GetWorld(), GetActorLocation(), OwnershipRadius,   32, FColor::Yellow);
```

1.  仍然在`Tick`函数中，创建特定于权限的逻辑，该逻辑将获取所有权半径内最接近的`AOwnershipRolesCharacter`，如果与当前角色不同，则将其设置为所有者：

```cpp
if (HasAuthority())
{
  AActor* NextOwner = nullptr;
  float MinDistance = OwnershipRadius;
  TArray<AActor*> Actors;
  UGameplayStatics::GetAllActorsOfClass(this,    AOwnershipRolesCharacter::StaticClass(), Actors);
  for (AActor* Actor : Actors)
  {
const float Distance = GetDistanceTo(Actor);
    if (Distance <= MinDistance)
    {
      MinDistance = Distance;
      NextOwner = Actor;
    }
  }
  if (GetOwner() != NextOwner)
  {
    SetOwner(NextOwner);
  }
}
```

1.  仍然在`Tick`函数中，将本地/远程角色的值（使用我们之前创建的`ROLE_TO_STRING`宏），当前所有者和连接转换为字符串：

```cpp
const FString LocalRoleString = ROLE_TO_STRING(GetLocalRole());
const FString RemoteRoleString = ROLE_TO_STRING(GetRemoteRole());
const FString OwnerString = GetOwner() != nullptr ? GetOwner()-  >GetName() : TEXT("No Owner");
const FString ConnectionString = GetNetConnection() != nullptr ?   TEXT("Valid Connection") : TEXT("Invalid Connection");
```

1.  最后，使用`DrawDebugString`在屏幕上显示我们在上一步中转换的字符串：

```cpp
const FString Values = FString::Printf(TEXT("LocalRole =   %s\nRemoteRole = %s\nOwner = %s\nConnection = %s"),   *LocalRoleString, *RemoteRoleString, *OwnerString,   *ConnectionString);
DrawDebugString(GetWorld(), GetActorLocation(), Values, nullptr,   FColor::White, 0.0f, true);
```

注意

不要不断使用`GetLocalRole() == ROLE_Authority`来检查角色是否具有权限，可以使用`AActor`中定义的`HasAuthority()`辅助函数。

1.  接下来，打开`OwnershipRolesCharacter.h`并将`Tick`函数声明为受保护的：

```cpp
virtual void Tick(float DeltaTime) override;
```

1.  现在，打开`OwnershipRolesCharacter.cpp`并按照以下代码片段中所示包含头文件：

```cpp
#include "DrawDebugHelpers.h"
#include "OwnershipRoles.h"
```

1.  实现`Tick`函数：

```cpp
void AOwnershipRolesCharacter::Tick(float DeltaTime)
{
  Super::Tick(DeltaTime);
}
```

1.  将本地/远程角色的值（使用我们之前创建的`ROLE_TO_STRING`宏），当前所有者和连接转换为字符串：

```cpp
const FString LocalRoleString = ROLE_TO_STRING(GetLocalRole());
const FString RemoteRoleString = ROLE_TO_STRING(GetRemoteRole());
const FString OwnerString = GetOwner() != nullptr ? GetOwner()-  >GetName() : TEXT("No Owner");
const FString ConnectionString = GetNetConnection() != nullptr ?   TEXT("Valid Connection") : TEXT("Invalid Connection");
```

1.  使用`DrawDebugString`在屏幕上显示我们在上一步中转换的字符串：

```cpp
const FString Values = FString::Printf(TEXT("LocalRole =   %s\nRemoteRole = %s\nOwner = %s\nConnection = %s"), *LocalRoleString, *RemoteRoleString, *OwnerString,   *ConnectionString);
DrawDebugString(GetWorld(), GetActorLocation(), Values, nullptr,   FColor::White, 0.0f, true);
```

最后，我们可以测试项目。

1.  运行代码并等待编辑器完全加载。

1.  在`Content`文件夹中创建一个名为`OwnershipTestActor_BP`的新蓝图，它派生自`OwnershipTestActor`。将`Mesh`设置为使用立方体网格，并在世界中放置一个实例。

1.  转到`多人游戏选项`并将客户端数量设置为`2`。

1.  将窗口大小设置为`800x600`。

1.  使用`New Editor Window (PIE)`进行游戏。

你应该得到以下输出：

![图 16.8：服务器和 Client 1 窗口上的预期结果](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_16_08.jpg)

图 16.8：服务器和 Client 1 窗口上的预期结果

通过完成这个练习，你将更好地理解连接和所有权是如何工作的。这些是重要的概念，因为与复制相关的一切都依赖于它们。

下次当你看到一个角色没有进行复制操作时，你会知道需要首先检查它是否有**有效的连接**和**所有者**。

现在，让我们分析服务器和客户端窗口中显示的值。

## 服务器窗口

看一下上一个练习中`Server`窗口的以下输出截图：

![图 16.9：服务器窗口](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_16_09.jpg)

图 16.9：服务器窗口

注意

显示`Server Character`，`Client 1 Character`和`Ownership Test Actor`的文本不是原始截图的一部分，是为了帮助你理解哪个角色和角色是哪个而添加的。

在上面的截图中，你可以看到`Server Character`，`Client 1 Character`和`Ownership Test`立方体角色。

首先分析`Server Character`的值。

## 服务器角色

这是监听服务器正在控制的角色。与这个角色相关的值如下：

+   `LocalRole = ROLE_Authority`：因为这个角色是在服务器上生成的，这是当前的游戏实例。

+   `RemoteRole = ROLE_SimulatedProxy`：因为这个角色是在服务器上生成的，所以其他客户端只能模拟它。

+   `Owner = PlayerController_0`：因为这个角色由监听服务器的客户端控制，使用了名为`PlayerController_0`的第一个`PlayerController`实例。

+   `Connection = Invalid Connection`：因为我们是监听服务器的客户端，所以不需要连接。

接下来，我们将在同一个窗口中查看`Client 1 Character`。

## Client 1 Character

这是`Client 1`正在控制的角色。与这个角色相关的值如下：

+   `LocalRole = ROLE_Authority`：因为这个角色是在服务器上生成的，这是当前的游戏实例。

+   `RemoteRole = ROLE_AutonomousProxy`：因为这个角色是在服务器上生成的，但是由另一个客户端控制。

+   `Owner = PlayerController_1`：因为这个角色是由另一个客户端控制的，使用了名为`PlayerController_1`的第二个`PlayerController`实例。

+   `Connection = Valid Connection`：因为这个角色由另一个客户端控制，所以需要与服务器建立连接。

接下来，我们将在同一个窗口中查看`OwnershipTest`角色。

## OwnershipTest Actor

这是将其所有者设置为一定所有权半径内最近的角色的立方体演员。与该演员相关的值如下：

+   `LocalRole = ROLE_Authority`：因为这个演员被放置在级别中，并在服务器上生成，这是当前游戏实例。

+   `RemoteRole = ROLE_SimulatedProxy`：因为这个演员是在服务器中生成的，但没有被任何客户端控制。

+   `Owner`和`Connection`的值将基于最近的角色。如果在所有权半径内没有角色，则它们将具有`无所有者`和`无效连接`的值。

现在，让我们看一下`Client 1`窗口：

![图 16.10：客户端 1 窗口](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_16_10.jpg)

图 16.10：客户端 1 窗口

## 客户端 1 窗口

`Client 1`窗口的值将与`Server`窗口的值完全相同，只是`LocalRole`和`RemoteRole`的值将被颠倒，因为它们始终相对于您所在的游戏实例。

另一个例外是服务器角色没有所有者，其他连接的客户端将没有有效连接。原因是客户端不存储其他客户端的玩家控制器和连接，只有服务器才会存储，但这将在*第十八章*中更深入地介绍*多人游戏中的游戏框架类*。

在下一节中，我们将看一下变量复制。

# 变量复制

服务器可以使客户端保持同步的一种方式是使用变量复制。其工作方式是，每秒特定次数（在`AActor::NetUpdateFrequency`变量中为每个演员定义，也暴露给蓝图）服务器中的变量复制系统将检查是否有任何需要使用最新值更新的客户端中的复制变量（*在下一节中解释*）。

如果变量满足所有复制条件，那么服务器将向客户端发送更新并强制执行新值。

例如，如果您有一个复制的`Health`变量，并且客户端使用黑客工具将变量的值从`10`设置为`100`，那么复制系统将强制从服务器获取真实值并将其更改回`10`，从而使黑客无效。

只有在以下情况下才会将变量发送到客户端进行更新：

+   变量被设置为复制。

+   值已在服务器上更改。

+   客户端上的值与服务器上的值不同。

+   演员已启用复制。

+   演员是相关的，并满足所有复制条件。

需要考虑的一个重要事项是，确定变量是否应该复制的逻辑仅在每秒执行`AActor::NetUpdateFrequency`次。换句话说，服务器在更改服务器上的变量值后不会立即向客户端发送更新请求。只有在变量复制系统执行时（每秒`AActor::NetUpdateFrequency`次），并且确定客户端的值与服务器的值不同时，才会发送该请求。

例如，如果您有一个整数复制一个名为`Test`的变量，其默认值为`5`。如果您在服务器上调用一个将`Test`设置为`3`的函数，并在下一行将其更改为`8`，那么只有后者的更改会发送更新请求到客户端。原因是这两个更改是在`NetUpdateFrequency`间隔之间进行的，因此当变量复制系统执行时，当前值为`8`，因为它与客户端的值不同（仍为`5`），它将更新它们。如果您将其设置回`5`，则不会向客户端发送任何更改。

## 复制变量

在虚幻引擎中，任何可以使用`UPROPERTY`宏的变量都可以设置为复制，并且可以使用两个限定词来执行此操作。

**复制**

如果你只想说一个变量被复制，那么你使用`Replicated`修饰符。

看下面的例子：

```cpp
UPROPERTY(Replicated) 
float Health = 100.0f; 
```

在上述代码片段中，我们声明了一个名为`Health`的浮点变量，就像我们通常做的那样。不同之处在于，我们添加了`UPROPERTY(Replicated)`，告诉虚幻引擎`Health`变量将被复制。

**RepNotify**

如果你想说一个变量被复制并且每次更新时都调用一个函数，那么你使用`ReplicatedUsing=<Function Name>`修饰符。看下面的例子：

```cpp
UPROPERTY(ReplicatedUsing=OnRep_Health) 
float Health = 100.0f;
UFUNCTION() 
void OnRep_Health()
{
  UpdateHUD(); 
}
```

在上述代码片段中，我们声明了一个名为`Health`的浮点变量。不同之处在于，我们添加了`UPROPERTY(ReplicatedUsing=OnRep_Health)`，告诉虚幻引擎这个变量将被复制，并且每次更新时都会调用`OnRep_Health`函数，在这种特定情况下，它将调用一个函数来更新`HUD`。

通常，回调函数的命名方案是`OnRepNotify_<Variable Name>`或`OnRep_<Variable Name>`。

注意

在`ReplicatingUsing`修饰符中使用的函数需要标记为`UFUNCTION()`。

**GetLifetimeReplicatedProps**

除了将变量标记为复制外，您还需要在角色的`cpp`文件中实现`GetLifetimeReplicatedProps`函数。需要考虑的一件事是，一旦您至少有一个复制的变量，此函数将在内部声明，因此您不应该在角色的头文件中声明它。这个函数的目的是告诉您每个复制的变量应该如何复制。您可以通过在您想要复制的每个变量上使用`DOREPLIFETIME`宏及其变体来实现这一点。

**DOREPLIFETIME**

这个宏告诉复制系统，复制的变量（作为参数输入）将在没有复制条件的情况下复制到所有客户端。

以下是它的语法：

```cpp
DOREPLIFETIME(<Class Name>, <Replicated Variable Name>); 
```

看下面的例子：

```cpp
void AVariableReplicationActor::GetLifetimeReplicatedProps(TArray<   FLifetimeProperty >& OutLifetimeProps) const
{
  Super::GetLifetimeReplicatedProps(OutLifetimeProps);
  DOREPLIFETIME(AVariableReplicationActor, Health);
}
```

在上述代码片段中，我们使用`DOREPLIFETIME`宏告诉复制系统，`AVariableReplicationActor`类中的`Health`变量将在没有额外条件的情况下复制。

**DOREPLIFETIME_CONDITION**

这个宏告诉复制系统，复制的变量（作为参数输入）只会根据满足的条件（作为参数输入）复制给客户端。

以下是语法：

```cpp
DOREPLIFETIME_CONDITION(<Class Name>, <Replicated Variable Name>,   <Condition>); 
```

条件参数可以是以下值之一：

+   `COND_InitialOnly`：变量只会复制一次，进行初始复制。

+   `COND_OwnerOnly`：变量只会复制给角色的所有者。

+   `COND_SkipOwner`：变量不会复制给角色的所有者。

+   `COND_SimulatedOnly`：变量只会复制到正在模拟的角色。

+   `COND_AutonomousOnly`：变量只会复制给自主角色。

+   `COND_SimulatedOrPhysics`：变量只会复制到正在模拟的角色或`bRepPhysics`设置为 true 的角色。

+   `COND_InitialOrOwner`：变量只会进行初始复制，或者只会复制给角色的所有者。

+   `COND_Custom`：变量只有在其`SetCustomIsActiveOverride`布尔条件（在`AActor::PreReplication`函数中使用）为 true 时才会复制。

看下面的例子：

```cpp
void AVariableReplicationActor::GetLifetimeReplicatedProps(TArray<   FLifetimeProperty >& OutLifetimeProps) const
{
  Super::GetLifetimeReplicatedProps(OutLifetimeProps);
  DOREPLIFETIME_CONDITION(AVariableReplicationActor, Health,     COND_OwnerOnly);
}
```

在上述代码片段中，我们使用`DOREPLIFETIME_CONDITION`宏告诉复制系统，`AVariableReplicationActor`类中的`Health`变量只会为该角色的所有者复制。

注意

还有更多的`DOREPLIFETIME`宏可用，但本书不会涵盖它们。要查看所有变体，请检查虚幻引擎 4 源代码中的`UnrealNetwork.h`文件。请参阅以下说明：[`docs.unrealengine.com/en-US/GettingStarted/DownloadingUnrealEngine/index.html`](https://docs.unrealengine.com/en-US/GettingStarted/DownloadingUnrealEngine/index.html)。

## 练习 16.03：使用 Replicated、RepNotify、DOREPLIFETIME 和 DOREPLIFETIME_CONDITION 复制变量

在这个练习中，我们将创建一个 C++项目，该项目以第三人称模板为基础，并向角色添加两个以以下方式复制的变量：

+   变量`A`是一个浮点数，将使用`Replicated UPROPERTY`说明符和`DOREPLIFETIME`宏。

+   变量`B`是一个整数，将使用`ReplicatedUsing UPROPERTY`说明符和`DOREPLIFETIME_CONDITION`宏。

以下步骤将帮助您完成练习：

1.  使用 C++创建一个名为`VariableReplication`的`Third Person`模板项目，并将其保存到您选择的位置。

1.  项目创建后，应打开编辑器以及 Visual Studio 解决方案。

1.  关闭编辑器，返回 Visual Studio。

1.  打开`VariableReplicationCharacter.h`文件。

1.  然后，在`VariableReplicationCharacter.generated.h`之前包含`UnrealNetwork.h`头文件，其中包含我们将使用的`DOREPLIFETIME`宏的定义：

```cpp
#include "Net/UnrealNetwork.h"
```

1.  使用各自的复制说明符将受保护的变量`A`和`B`声明为`UPROPERTY`：

```cpp
UPROPERTY(Replicated) 
float A = 100.0f; 
UPROPERTY(ReplicatedUsing = OnRepNotify_B) 
int32 B; 
```

1.  将`Tick`函数声明为受保护：

```cpp
virtual void Tick(float DeltaTime) override;
```

1.  由于我们将变量`B`声明为`ReplicatedUsing = OnRepNotify_B`，因此我们还需要将受保护的`OnRepNotify_B`回调函数声明为`UFUNCTION`：

```cpp
UFUNCTION() 
void OnRepNotify_B(); 
```

1.  现在，打开`VariableReplicationCharacter.cpp`文件，并包括`Engine.h`头文件，这样我们就可以使用`AddOnScreenDebugMessage`函数，以及`DrawDebugHelpers.h`头文件，这样我们就可以使用`DrawDebugString`函数：

```cpp
#include "Engine/Engine.h"
#include "DrawDebugHelpers.h"
```

1.  实现`GetLifetimeReplicatedProps`函数：

```cpp
void AVariableReplicationCharacter::GetLifetimeReplicatedProps(TArray<   FLifetimeProperty >& OutLifetimeProps) const 
{
  Super::GetLifetimeReplicatedProps(OutLifetimeProps);
}
```

1.  将其设置为`A`变量，它将在没有任何额外条件的情况下复制：

```cpp
DOREPLIFETIME(AVariableReplicationCharacter, A);
```

1.  将其设置为`B`变量，这将仅复制到此角色的所有者：

```cpp
DOREPLIFETIME_CONDITION(AVariableReplicationCharacter, B,   COND_OwnerOnly);
```

1.  实现`Tick`函数：

```cpp
void AVariableReplicationCharacter::Tick(float DeltaTime) 
{
  Super::Tick(DeltaTime);
}
```

1.  接下来，运行特定权限的逻辑，将`1`添加到`A`和`B`：

```cpp
if (HasAuthority()) 
{ 
  A++; 
  B++; 
} 
```

由于此角色将在服务器上生成，因此只有服务器将执行此逻辑。

1.  在角色的位置上显示`A`和`B`的值：

```cpp
const FString Values = FString::Printf(TEXT("A = %.2f    B =   %d"), A, B); 
DrawDebugString(GetWorld(), GetActorLocation(), Values, nullptr,   FColor::White, 0.0f, true);
```

1.  实现变量`B`的`RepNotify`函数，该函数在屏幕上显示一条消息，说明`B`变量已更改为新值：

```cpp
void AVariableReplicationCharacter::OnRepNotify_B() 
{
  const FString String = FString::Printf(TEXT("B was changed by     the server and is now %d!"), B); 
  GEngine->AddOnScreenDebugMessage(-1, 0.0f, FColor::Red,String); 
}
```

最后，您可以测试项目：

1.  运行代码，等待编辑器完全加载。

1.  转到“多人游戏选项”，并将客户端数量设置为`2`。

1.  将窗口大小设置为`800x600`。

1.  使用“新编辑器窗口（PIE）”进行游戏。

完成此练习后，您将能够在每个客户端上进行游戏，并且您会注意到角色显示其各自的`A`和`B`的值。

现在，让我们分析“服务器”和“客户端 1”窗口中显示的值。

## 服务器窗口

在“服务器”窗口中，您可以看到“服务器角色”的值，这是由服务器控制的角色，在后台，您可以看到“客户端 1 角色”的值：

![图 16.11：服务器窗口](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_16_11.jpg)

图 16.11：服务器窗口

可以观察到的输出如下：

+   “服务器”“角色” - `A = 674.00 B = 574`

+   “客户端 1”“角色” - `A = 670.00 B = 570`

在特定时间点，“服务器”“角色”的`A`值为`674`，`B`值为`574`。之所以`A`和`B`有不同的值，是因为`A`从`100`开始，`B`从`0`开始，这是`574`次`A++`和`B++`后的正确值。

至于为什么“客户端 1”“角色”的值与服务器角色不同，那是因为“客户端 1”稍后创建，所以在这种情况下，`A++`和`B++`的计数将偏移 4 个滴答声。

接下来，我们将查看“客户端 1”窗口。

## 客户端 1 窗口

在“客户端 1”窗口中，您可以看到“客户端 1 角色”的值，这是由“客户端 1”控制的角色，在后台，您可以看到“服务器角色”的值：

![图 16.12：客户端 1 窗口](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_16_12.jpg)

图 16.12：客户端 1 窗口

可以观察到的输出如下：

+   `Server` `Character` – `A = 674.00 B = 0`

+   `Client 1` `Character` – `A = 670.00 B = 570`

`Client 1 Character`从服务器那里得到了正确的值，因此变量复制正常工作。如果您查看`Server Character`，`A`是`674`，这是正确的，但`B`是`0`。原因是`A`使用了`DOREPLIFETIME`，它不会添加任何额外的复制条件，因此它将复制变量并在服务器上的变量更改时每次使客户端保持最新状态。

另一方面，变量`B`使用`DOREPLIFETIME_CONDITION`和`COND_OwnerOnly`，由于`Client 1`不是拥有`Server Character`的客户端（*监听服务器的客户端是*），因此该值不会被复制，并且保持不变为`0`的默认值。

如果您返回代码并将`B`的复制条件更改为使用`COND_SimulatedOnly`而不是`COND_OwnerOnly`，您会注意到结果将在`Client 1`窗口中被颠倒。`B`的值将被复制到`Server Character`，但不会复制到自己的角色。

注意

`RepNotify`消息显示在`Server`窗口而不是客户端窗口的原因是，当在编辑器中播放时，两个窗口共享同一个进程，因此在屏幕上打印文本不准确。要获得正确的行为，您需要运行游戏的打包版本。

# 2D 混合空间

在*第二章*，*使用虚幻引擎*中，我们创建了一个 1D 混合空间，根据`Speed`轴的值来混合角色的移动状态（*空闲、行走和奔跑*）。对于这个特定的示例，它工作得相当好，因为您只需要一个轴，但是如果我们希望角色也能够斜行，那么我们实际上无法做到。

为了探索这种情况，虚幻引擎允许您创建 2D 混合空间。概念几乎完全相同；唯一的区别是您有一个额外的轴用于动画，因此您不仅可以在水平方向上混合它们，还可以在垂直方向上混合它们。

## 练习 16.04：创建移动 2D 混合空间

在这个练习中，我们将创建一个使用两个轴而不是一个轴的混合空间。垂直轴将是`Speed`，取值范围为`0`到`800`。水平轴将是`Direction`，表示角色速度和旋转/前向矢量之间的相对角度（`-180 到 180`）。

以下图将帮助您计算本练习中的方向：

![图 16.13：基于前向矢量之间角度的方向值矢量和速度](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_16_13.jpg)

图 16.13：基于前向矢量和速度之间角度的方向值

在前面的图中，您可以看到方向是如何计算的。前向矢量表示角色当前面对的方向，数字表示如果前向矢量指向该方向，则前向矢量将与速度矢量形成的角度。如果角色朝向某个方向，然后按键移动角色向右，那么速度矢量将与前向矢量垂直。这意味着角度将是 90º，这将是我们的方向。

如果我们根据这个逻辑设置我们的 2D 混合空间，我们可以根据角色的移动角度使用正确的动画。

以下步骤将帮助您完成练习：

1.  使用`Blueprints`创建一个名为`Blendspace2D`的新`Third Person`模板项目，并将其保存到您选择的位置。

1.  项目创建后，应该打开编辑器。

1.  接下来，您将导入移动动画。在编辑器中，转到`Content\Mannequin\Animations`文件夹。

1.  点击`导入`按钮。

1.  进入`Chapter16\Exercise16.04\Assets`文件夹，选择所有`fbx`文件，然后点击`打开`按钮。

1.  在导入对话框中，确保选择角色的骨架并点击`Import All`按钮。

1.  保存所有新文件到`Assets`文件夹中。

1.  点击`Add New`按钮并选择`Animation -> Blend Space`。

1.  接下来，选择角色的骨架。

1.  重命名混合空间为`BS_Movement`并打开它。

1.  创建水平`Direction`轴（-180 至 180）和垂直`Speed`轴（0 至 800），如下图所示：![图 16.14：2D 混合空间轴设置](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_16_14.jpg)

图 16.14：2D 混合空间轴设置

1.  将`Idle_Rifle_Ironsights`动画拖到`Speed`为`0`的 5 个网格条目上。

1.  将`Walk_Fwd_Rifle_Ironsights`动画拖到`Speed`为`800`，`Direction`为`0`的位置。

1.  将`Walk_Lt_Rifle_Ironsights`动画拖到`Speed`为`800`，`Direction`为`-90`的位置。

1.  将`Walk_Rt_Rifle_Ironsights`动画拖到`Speed`为`800`，`Direction`为`90`的位置。

您应该最终得到一个可以通过按住*Shift*并移动鼠标来预览的混合空间。

1.  现在，在`Asset Details`面板上，将`Target Weight Interpolation Speed Per Sec`变量设置为`5`，以使插值更加平滑。

1.  保存并关闭混合空间。

1.  现在，更新动画蓝图以使用新的混合空间。

1.  转到`Content\Mannequin\Animations`并打开随 Third Person 模板一起提供的文件–`ThirdPerson_AnimBP`。

1.  接下来，转到事件图并创建一个名为`Direction`的新浮点变量。

1.  使用`Calculate Direction`函数的结果设置`Direction`的值，该函数计算角度（-180º至 180º）在角色的`速度`和`旋转`之间：![图 16.15：计算用于 2D 混合空间的速度和方向](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_16_15.jpg)

图 16.15：计算用于 2D 混合空间的速度和方向

注意

您可以在以下链接找到前面的截图的全分辨率版本以便更好地查看：[`packt.live/3pAbbAl`](https://packt.live/3pAbbAl)。

1.  在`AnimGraph`中，转到正在使用旧的 1D 混合空间的`Idle/Run`状态，如下截图所示：![图 16.16：AnimGraph 中的空闲/奔跑状态](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_16_16.jpg)

图 16.16：AnimGraph 中的空闲/奔跑状态

1.  用`BS_Movement`替换该混合空间，并像这样使用`Direction`变量：![图 16.17：1D 混合空间已被新的 2D 混合空间替换](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_16_17.jpg)

图 16.17：1D 混合空间已被新的 2D 混合空间替换

1.  保存并关闭动画蓝图。现在您需要更新角色。

1.  转到`Content\ThirdPersonBP\Blueprints`文件夹并打开`ThirdPersonCharacter`。

1.  在角色的`Details`面板上，将`Use Controller Rotation Yaw`设置为`true`，这将使角色的`Yaw`旋转始终面向控制旋转的 Yaw。

1.  转到角色移动组件并将`Max Walk Speed`设置为`800`。

1.  将`Orient Rotation to Movement`设置为`false`，这将防止角色朝向移动方向旋转。

1.  保存并关闭角色蓝图。

如果现在使用两个客户端玩游戏并移动角色，它将向前和向后走，但也会侧移，如下面的截图所示：

![图 16.18：服务器和客户端 1 窗口上的预期输出](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_16_18.jpg)

图 16.18：服务器和客户端 1 窗口上的预期输出

通过完成这个练习，您将提高对如何创建 2D 混合空间、它们的工作原理以及它们相对于仅使用常规 1D 混合空间的优势的理解。

在下一节中，我们将看一下如何转换角色的骨骼，以便根据摄像机的俯仰旋转玩家的躯干上下。

# 转换（修改）骨骼

在我们继续之前，有一个非常有用的节点，您可以在 AnimGraph 中使用，称为`Transform (Modify) Bone`节点，它允许您在*运行时*转换骨骼的平移、旋转和缩放。

您可以通过*右键单击*空白处，在`AnimGraph`中添加它，输入`transform modify`，然后从列表中选择节点。如果单击`Transform (Modify) Bone`节点，您将在`Details`面板上有相当多的选项。

以下是每个选项的解释。

+   `Bone to Modify`选项将告诉节点将要变换的骨骼是哪个。

在该选项之后，您有三个部分，分别代表每个变换操作（`Translation`，`Rotation`和`Scale`）。在每个部分中，您可以执行以下操作：

+   `Translation，Rotation，Scale`：此选项将告诉节点您要应用多少特定变换操作。最终结果将取决于您选择的模式（*在下一节中介绍*）。

有两种方法可以设置此值：

+   设置一个常量值，比如（`X=0.0,Y=0.0,Z=0.0`）

+   使用一个变量，这样它可以在运行时更改。为了实现这一点，您需要采取以下步骤（此示例是为了`Rotation`，但相同的概念也适用于`Translation`和`Scale`）：

1.  单击常量值旁边的复选框，并确保它被选中。一旦您这样做了，常量值的文本框将消失。![图 16.19：勾选复选框](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_16_19.jpg)

图 16.19：勾选复选框

`Transform (Modify) Bone`将添加一个输入，这样您就可以插入您的变量：

![图 16.20：变量用作变换（修改）骨骼节点的输入](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_16_20.jpg)

图 16.20：变量用作变换（修改）骨骼节点的输入

**设置模式**

这将告诉节点如何处理该值。您可以从以下三个选项中选择一个：

+   `Ignore`：不对提供的值进行任何操作。

+   `Add to Existing`：获取骨骼的当前值，并将提供的值添加到其中。

+   `Replace Existing`：用提供的值替换骨骼的当前值。

**设置空间**

这将定义节点应该应用变换的空间。您可以从以下四个选项中选择一个：

+   `World Space`：变换将发生在世界空间中。

+   `Component Space`：变换将发生在骨骼网格组件空间中。

+   `Parent Bone Space`：变换将发生在所选骨骼的父骨骼空间中。

+   `Bone Space`：变换将发生在所选骨骼的空间中。

最后但同样重要的是`Alpha`，它是一个值，允许您控制要应用的变换量。例如，如果`Alpha`值为浮点数，则不同值将产生以下行为：

+   如果`Alpha`为 0.0，则不会应用任何变换。

+   如果`Alpha`为 0.5，则只会应用一半的变换。

+   如果`Alpha`为 1.0，则会应用整个变换。

在下一个练习中，我们将使用`Transform (Modify) Bone`节点来使角色能够根据摄像机的旋转从*练习 16.04*，*创建一个 2D 混合运动空间*中上下观察。

## 练习 16.05：创建一个能够上下观察的角色

在这个练习中，我们将复制*练习 16.04*中的项目，*创建一个 2D 混合运动空间*，并使角色能够根据摄像机的旋转上下观察。为了实现这一点，我们将使用`Transform (Modify) Bone`节点来根据摄像机的俯仰在组件空间中旋转`spine_03`骨骼。

以下步骤将帮助您完成练习：

1.  首先，您需要复制并重命名*练习 16.04*中的项目，*创建一个 2D 混合运动空间*。

1.  从*练习 16.04*中复制`Blendspace2D`项目文件夹，*创建一个 2D 混合运动空间*，粘贴到一个新文件夹中，并将其重命名为`TransformModifyBone`。

1.  打开新的项目文件夹，将`Blendspace2D.uproject`文件重命名为`TransformModifyBone.uproject`，然后打开它。

接下来，您将更新动画蓝图。

1.  转到`Content\Mannequin\Animations`，并打开`ThirdPerson_AnimBP`。

1.  转到“事件图”，创建一个名为“俯仰”的浮点变量，并将其设置为 pawn 旋转和基本瞄准旋转之间的减法（或 delta）的俯仰，如下图所示：![图 16.21：计算俯仰](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_16_21.jpg)

图 16.21：计算俯仰

作为使用“分解旋转器”节点的替代方法，您可以*右键单击*“返回值”，然后选择“拆分结构引脚”。

注意

“分解旋转器”节点允许您将“旋转器”变量分解为代表“俯仰”、“偏航”和“翻滚”的三个浮点变量。当您想要访问每个单独组件的值或者只想使用一个或两个组件而不是整个旋转时，这将非常有用。

请注意，“拆分结构引脚”选项只会在“返回值”未连接到任何东西时出现。一旦您进行拆分，它将创建三根分开的电线，分别代表“翻滚”、“俯仰”和“偏航”，就像一个分解但没有额外的节点。

你应该得到以下结果：

![图 16.22：使用拆分结构引脚选项计算俯仰](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_16_22.jpg)

图 16.22：使用拆分结构引脚选项计算俯仰

这个逻辑使用了 pawn 的旋转并将其减去摄像机的旋转，以获得“俯仰”的差异，如下图所示：

![图 16.23：如何计算 Delta Pitch](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_16_23.jpg)

图 16.23：如何计算 Delta Pitch

1.  接下来，转到`AnimGraph`并添加一个带有以下设置的“变换（修改）骨骼”节点：![图 16.24：变换（修改）骨骼节点的设置](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_16_24.jpg)

图 16.24：变换（修改）骨骼节点的设置

在前面的截图中，我们将“要修改的骨骼”设置为`spine_03`，因为这是我们想要旋转的骨骼。我们还将“旋转模式”设置为“添加到现有”，因为我们希望保留动画中的原始旋转并添加偏移量。其余选项需要保持默认值。

1.  将“变换（修改）骨骼”节点连接到“状态机”和“输出姿势”，如下截图所示：![图 16.25：变换（修改）骨骼连接到输出姿势](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_16_25.jpg)

图 16.25：变换（修改）骨骼连接到输出姿势

在前面的图中，您可以看到完整的`AnimGraph`，它将允许角色通过旋转`spine_03`骨骼来上下查看，基于摄像机的俯仰。 “状态机”将是起点，从那里，它将需要转换为组件空间，以便能够使用“变换（修改）骨骼”节点，然后连接到“输出姿势”节点，再转换回本地空间。

注意

我们将“俯仰”变量连接到“翻滚”的原因是骨骼在骨架内部是以这种方式旋转的。您也可以在输入参数上使用“拆分结构引脚”，这样您就不必添加“制作旋转器”节点。

如果您使用两个客户端测试项目，并在其中一个角色上*向上*和*向下*移动鼠标，您会注意到它会上下俯仰，如下截图所示：

![图 16.26：根据摄像机旋转使角色网格上下俯仰](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_16_26.jpg)

图 16.26：根据摄像机旋转使角色网格上下俯仰

通过完成这个最终练习，您将了解如何在动画蓝图中使用“变换（修改）骨骼”节点在运行时修改骨骼。这个节点可以在各种场景中使用，所以对您可能非常有用。

在下一个活动中，您将通过创建我们将在多人 FPS 项目中使用的角色来将您学到的一切付诸实践。

## 活动 16.01：为多人 FPS 项目创建角色

在此活动中，您将为我们在接下来的几章中构建的多人 FPS 项目创建角色。 角色将具有一些不同的机制，但是对于此活动，您只需要创建一个可以行走，跳跃，上下查看并具有两个复制的统计数据：生命值和护甲的角色。

以下步骤将帮助您完成此活动：

1.  创建一个名为`MultiplayerFPS`的`Blank C++`项目，不包含起始内容。

1.  从`Activity16.01\Assets`文件夹导入骨骼网格和动画，并将它们分别放置在`Content\Player\Mesh`和`Content\Player\Animations`文件夹中。

1.  从`Activity16.01\Assets`文件夹导入以下声音到`Content\Player\Sounds`：

+   `Jump.wav`：在`Jump_From_Stand_Ironsights`动画上使用`Play Sound`动画通知播放此声音。

+   `Footstep.wav`：通过使用`Play Sound`动画通知，在每次行走动画中脚踩在地板上时播放此声音。

+   `Spawn.wav`：在角色的`SpawnSound`变量上使用此音频。

1.  通过重新定位其骨骼并创建一个名为`Camera`的插座来设置骨骼网格，该插座是头骨的子级，并具有相对位置（*X=7.88, Y=4.73, Z=-10.00*）。

1.  在`Content\Player\Animations`中创建一个名为`BS_Movement`的 2D 混合空间，该空间使用导入的移动动画和`Target Weight Interpolation Speed Per Sec`为`5`。

1.  在`Project Settings`中创建输入映射，使用*第四章*中获得的知识，*Player Input*：

+   跳跃（动作映射）- *空格键*

+   向前移动（轴映射）- *W*（比例`1.0`）和*S*（比例`-1.0`）

+   向右移动（轴映射）- *A*（比例`-1.0`）和*D*（比例`1.0`）

+   转向（轴映射）- 鼠标*X*（比例`1.0`）

+   向上查看（轴映射）- 鼠标*Y*（比例`-1.0`）

1.  创建一个名为`FPSCharacter`的 C++类，执行以下操作：

+   派生自`Character`类。

+   在`Camera`插座上附加到骨骼网格上的摄像头组件，并将`pawn control rotation`设置为`true`。

+   具有仅复制到所有者的`health`和`armor`变量。

+   具有最大`health`和`armor`的变量，以及护甲吸收多少伤害的百分比。

+   具有初始化摄像头，禁用打勾，并将`Max Walk Speed`设置为`800`和`Jump Z Velocity`设置为`600`的构造函数。

+   在`BeginPlay`中，播放生成声音并在具有权限时初始化`health`为`max health`。

+   创建并绑定处理输入动作和轴的功能。

+   具有添加/删除/设置生命值的功能。 还确保角色死亡的情况。

+   具有添加/设置/吸收护甲的功能。护甲吸收根据`ArmorAbsorption`变量减少护甲，并根据以下公式更改伤害值：

*Damage = (Damage * (1 - ArmorAbsorption)) - FMath::Min(RemainingArmor, 0);*

1.  在`Content\Player\Animations`中创建名为`ABP_Player`的动画蓝图，其中包含以下状态的`State Machine`：

+   `Idle/Run`：使用具有`Speed`和`Direction`变量的`BS_Movement`

+   `Jump`：当`Is Jumping`变量为`true`时，播放跳跃动画并从`Idle/Run`状态转换

它还使用`Transform (Modify) Bone`根据相机的 Pitch 使角色上下俯仰。

1.  在`Content\UI`中创建一个名为`UI_HUD`的`UMG`小部件，以`Health: 100`和`Armor: 100`的格式显示角色的`Health`和`Armor`，使用*第十五章*中获得的知识，*Collectibles, Power-ups, and Pickups*。

1.  在`Content\Player`中创建一个名为`BP_Player`的蓝图，该蓝图派生自`FPSCharacter`，并设置网格组件具有以下值：

+   使用`SK_Mannequin`骨骼网格

+   使用`ABP_Player`动画蓝图

+   将`Location`设置为(*X=0.0, Y=0.0, Z=-88.0*)

+   将`Rotation`设置为(*X=0.0, Y=0.0, Z=-90.0*)

此外，在`Begin Play`事件中，需要创建`UI_HUD`的小部件实例并将其添加到视口中。

1.  在`Content\Blueprints`中创建一个名为`BP_GameMode`的蓝图，它派生自`MultiplayerFPSGameModeBase`，并将`BP_Player`作为`DefaultPawn`类使用。

1.  在`Content\Maps`中创建一个名为`DM-Test`的测试地图，并将其设置为`Project Settings`中的默认地图。

预期输出：

结果应该是一个项目，每个客户端都有一个第一人称角色，可以移动、跳跃和四处张望。这些动作也将被复制，因此每个客户端都能看到其他客户端角色正在做什么。

每个客户端还将拥有一个显示健康和护甲值的 HUD。

![图 16.27：预期输出](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_16_27.jpg)

图 16.27：预期输出

注意

此活动的解决方案可在以下链接找到：[`packt.live/338jEBx`](https://packt.live/338jEBx)。

最终结果应该是两个角色可以看到彼此移动、跳跃和四处张望。每个客户端还会显示其角色的健康和护甲值。

通过完成此活动，您应该对服务器-客户端架构、变量复制、角色、2D 混合空间和“变换（修改）骨骼”节点的工作原理有一个很好的了解。

# 总结

在本章中，我们学习了一些关键的多人游戏概念，比如服务器-客户端架构的工作原理，服务器和客户端的责任，监听服务器设置比专用服务器快但不够轻量级，所有权和连接，角色和变量复制。

我们还学习了一些有用的动画技巧，比如如何使用 2D 混合空间，这允许您在两轴网格之间混合动画，以及变换（修改）骨骼节点，它具有在运行时修改骨骼的能力。最后，我们创建了一个第一人称多人游戏项目，其中您可以让角色行走、观看和跳跃，这将是我们在接下来的几章中将要开发的多人第一人称射击项目的基础。

在下一章中，我们将学习如何使用 RPCs，这允许客户端和服务器在彼此上执行函数。我们还将介绍如何在编辑器中使用枚举以及如何使用双向循环数组索引，这允许您在数组中向前和向后循环，并在超出限制时循环回来。
