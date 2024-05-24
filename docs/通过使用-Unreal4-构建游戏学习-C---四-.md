# 通过使用 Unreal4 构建游戏学习 C++（四）

> 原文：[`annas-archive.org/md5/1c4190d0f9858df324374dcae7b4dd27`](https://annas-archive.org/md5/1c4190d0f9858df324374dcae7b4dd27)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十一章：怪物

在本章中，我们将为玩家添加对手。我们将创建一个新的景观供其漫游，并且当怪物足够接近以侦测到它们时，它们将开始朝玩家走去。一旦它们进入玩家的射程范围，它们还将发动攻击，为您提供一些基本的游戏玩法。

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/099dee92-144b-4d95-8154-49031935ac34.png)

让我们来看看本章涵盖的主题：

+   景观

+   创建怪物

+   怪物对玩家的攻击

# 景观

我们在本书中尚未涵盖如何雕刻景观，所以我们将在这里进行。首先，您必须有一个景观可供使用。要做到这一点，请按照以下步骤进行：

1.  通过导航到文件|新建级别...开始一个新文件。您可以选择一个空的级别或一个带有天空的级别。在这个例子中，我选择了没有天空的那个。

1.  要创建景观，我们必须从模式面板中工作。确保通过导航到窗口|模式显示模式面板：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/8a3fa3b5-85bb-480e-a634-504b05e0fe5e.png)

1.  景观可以通过三个步骤创建，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/94d517c5-c8a8-4b22-af61-ae788248c780.png)

三个步骤如下：

1.  1.  单击模式面板中的景观图标（山的图片）

1.  单击管理按钮

1.  单击屏幕右下角的创建按钮

1.  现在您应该有一个景观可以使用。它将显示为主窗口中的灰色瓷砖区域：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/7a6f7cb0-afd0-4851-ac58-07423d5fd68e.png)

您在景观场景中要做的第一件事是为其添加一些颜色。没有颜色的景观算什么？

1.  在您的灰色瓷砖景观对象的任何位置单击。在右侧的详细信息面板中，您将看到它填充了信息，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/d385810c-148a-4e9e-8c31-ac63d7f20a8b.png)

1.  向下滚动，直到看到景观材料属性。您可以选择 M_Ground_Grass 材料，使地面看起来更逼真。

1.  向场景添加光。您可能应该使用定向光，以便所有地面都有一些光线。我们在第八章中已经介绍了如何做到这一点，*演员和棋子*。

# 雕刻景观

一个平坦的景观可能会很无聊。我们至少应该在这个地方添加一些曲线和山丘。要这样做，请执行以下步骤：

1.  单击模式面板中的雕刻按钮：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/08ac4743-6ac4-4870-951b-963bf391d7e9.png)

您的刷子的强度和大小由模式窗口中的刷子大小和工具强度参数确定。

1.  单击您的景观并拖动鼠标以改变草皮的高度。

1.  一旦您对您所拥有的内容感到满意，请单击播放按钮进行尝试。结果输出如下屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/1930fd27-8065-41f2-ba2c-671e3ad97354.png)

1.  玩弄您的景观并创建一个场景。我所做的是将景观降低到一个平坦的地面平面周围，以便玩家有一个明确定义的平坦区域可以行走，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/cdb0d0a7-010b-4ffc-93f4-7aaeeed000db.png)

随意处理您的景观。如果愿意，您可以将我在这里所做的作为灵感。

我建议您从 ContentExamples 或 StrategyGame 导入资产，以便在游戏中使用它们。要做到这一点，请参考第十章中的*导入资产*部分，*库存系统和拾取物品*。导入资产完成后，我们可以继续将怪物带入我们的世界。

# 创建怪物

我们将以与我们编程 NPC 和`PickupItem`相同的方式开始编程怪物。我们将编写一个基类（通过派生自 character）来表示`Monster`类，然后为每种怪物类型派生一堆蓝图。每个怪物都将有一些共同的属性，这些属性决定了它的行为。以下是共同的属性：

+   它将有一个用于速度的`float`变量。

+   它将有一个用于`HitPoints`值的`float`变量（我通常使用浮点数来表示 HP，这样我们可以轻松地模拟 HP 流失效果，比如走过一片熔岩池）。

+   它将有一个用于击败怪物所获得的经验值的`int32`变量。

+   它将有一个用于怪物掉落的战利品的`UClass`函数。

+   它将有一个用于每次攻击造成的`BaseAttackDamage`的`float`变量。

+   它将有一个用于`AttackTimeout`的`float`变量，这是怪物在攻击之间休息的时间。

+   它将有两个`USphereComponents`对象：其中一个是`SightSphere`——怪物能看到的距离。另一个是`AttackRangeSphere`，这是它的攻击范围。`AttackRangeSphere`对象始终小于`SightSphere`。

按照以下步骤进行操作：

1.  从`Character`类派生你的`Monster`类。你可以在 UE4 中通过转到文件 | 新建 C++类...，然后从菜单中选择你的基类的 Character 选项来完成这个操作。

1.  填写`Monster`类的基本属性。

1.  确保声明`UPROPERTY(EditAnywhere, BlueprintReadWrite, Category = MonsterProperties)`，以便可以在蓝图中更改怪物的属性。这是你应该在`Monster.h`中拥有的内容：

```cpp
#pragma once

#include "CoreMinimal.h"
#include "GameFramework/Character.h"
#include "Components/SphereComponent.h"
#include "Monster.generated.h"

UCLASS()
class GOLDENEGG_API AMonster : public ACharacter
{
    GENERATED_BODY()
public:
    AMonster(const FObjectInitializer& ObjectInitializer);

        // How fast he is 
        UPROPERTY(EditAnywhere, BlueprintReadWrite, Category =
            MonsterProperties)
        float Speed;

    // The hitpoints the monster has 
    UPROPERTY(EditAnywhere, BlueprintReadWrite, Category =
        MonsterProperties)
        float HitPoints;

    // Experience gained for defeating 
    UPROPERTY(EditAnywhere, BlueprintReadWrite, Category =
        MonsterProperties)
        int32 Experience;

    // Blueprint of the type of item dropped by the monster 
    UPROPERTY(EditAnywhere, BlueprintReadWrite, Category =
        MonsterProperties)
        UClass* BPLoot;

    // The amount of damage attacks do 
    UPROPERTY(EditAnywhere, BlueprintReadWrite, Category =
        MonsterProperties)
        float BaseAttackDamage;

    // Amount of time the monster needs to rest in seconds 
    // between attacking 
    UPROPERTY(EditAnywhere, BlueprintReadWrite, Category =
        MonsterProperties)
        float AttackTimeout;

    // Time since monster's last strike, readable in blueprints 
    UPROPERTY(VisibleAnywhere, BlueprintReadOnly, Category =
        MonsterProperties)
        float TimeSinceLastStrike;

    // Range for his sight 
    UPROPERTY(VisibleDefaultsOnly, BlueprintReadOnly, Category =
        Collision)
        USph.ereComponent* SightSphere;

    // Range for his attack. Visualizes as a sphere in editor, 
    UPROPERTY(VisibleDefaultsOnly, BlueprintReadOnly, Category =
        Collision)
        USphereComponent* AttackRangeSphere;
};
```

1.  你需要在`Monster`构造函数中添加一些最基本的代码，以初始化怪物的属性。在`Monster.cpp`文件中使用以下代码（这应该替换默认构造函数）：

```cpp
AMonster::AMonster(const FObjectInitializer& ObjectInitializer)
 : Super(ObjectInitializer)
{
 Speed = 20;
 HitPoints = 20;
 Experience = 0;
 BPLoot = NULL;
 BaseAttackDamage = 1;
 AttackTimeout = 1.5f;
 TimeSinceLastStrike = 0;

 SightSphere = ObjectInitializer.CreateDefaultSubobject<USphereComponent>
 (this, TEXT("SightSphere"));
 SightSphere->AttachToComponent(RootComponent, FAttachmentTransformRules::KeepWorldTransform);

 AttackRangeSphere = ObjectInitializer.CreateDefaultSubobject
 <USphereComponent>(this, TEXT("AttackRangeSphere"));
 AttackRangeSphere->AttachToComponent(RootComponent, FAttachmentTransformRules::KeepWorldTransform);
}
```

1.  编译并运行代码。

1.  打开虚幻编辑器，并基于你的`Monster`类派生一个蓝图（称之为`BP_Monster`）。

1.  现在，我们可以开始配置我们怪物的`Monster`属性。对于骨骼网格，我们不会使用相同的模型，因为我们需要怪物能够进行近战攻击，而相同的模型没有近战攻击。然而，Mixamo 动画包文件中的一些模型具有近战攻击动画。

1.  因此，从 UE4 市场（免费）下载 Mixamo 动画包文件：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/362f9aaa-ae15-478b-b496-a3508975a84b.png)

包中有一些相当恶心的模型，我会避免使用，但其他一些模型非常好。

1.  你应该将 Mixamo 动画包文件添加到你的项目中。它已经有一段时间没有更新了，但你可以通过勾选显示所有项目并从下拉列表中选择 4.10 版本来添加它，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/0e166f02-471a-4ebc-a3ef-148acd63bdc0.png)

1.  编辑`BP_Monster`蓝图的类属性，并选择 Mixamo_Adam（实际上在包的当前版本中是 Maximo_Adam）作为骨骼网格。确保将其与胶囊组件对齐。同时，选择 MixamoAnimBP_Adam 作为动画蓝图：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/ca4ed3fc-b5ba-466d-9847-8cf08e780dae.png)

我们将稍后修改动画蓝图，以正确地包含近战攻击动画。

在编辑`BP_Monster`蓝图时，将`SightSphere`和`AttackRangeSphere`对象的大小更改为你认为合理的值。我让我的怪物的`AttackRangeSphere`对象足够大，大约是手臂长度（60 个单位），他的`SightSphere`对象是这个值的 25 倍大（大约 1500 个单位）。

记住，一旦玩家进入怪物的`SightSphere`，怪物就会开始朝玩家移动，一旦玩家进入怪物的`AttackRangeSphere`对象，怪物就会开始攻击玩家：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/ebed74f3-72a6-4d98-80f4-72c22542739a.png)

在游戏中放置一些`BP_Monster`实例；编译并运行。没有任何驱动`Monster`角色移动的代码，你的怪物应该只是闲置在那里。

# 基本怪物智能

在我们的游戏中，我们只会为`Monster`角色添加基本智能。怪物将知道如何做两件基本的事情：

+   追踪玩家并跟随他

+   攻击玩家

怪物不会做其他事情。当玩家首次被发现时，你可以让怪物嘲讽玩家，但我们会把这留给你作为练习。

# 移动怪物-转向行为

非常基本的游戏中的怪物通常没有复杂的运动行为。通常，它们只是朝着目标走去并攻击它。我们将在这个游戏中编写这种类型的怪物，但你可以通过让怪物在地形上占据有利位置进行远程攻击等方式获得更有趣的游戏体验。我们不会在这里编写，但这是值得考虑的事情。

为了让“怪物”角色朝向玩家移动，我们需要在每一帧动态更新“怪物”角色移动的方向。为了更新怪物面对的方向，我们在`Monster::Tick()`方法中编写代码。

`Tick`函数在游戏的每一帧中运行。Tick 函数的签名如下：

```cpp
virtual void Tick(float DeltaSeconds) override; 
```

你需要在`Monster.h`文件中的`AMonster`类中添加这个函数的原型。如果我们重写了`Tick`，我们可以在每一帧中放置我们自己的自定义行为，这样`Monster`角色就应该做。下面是一些基本的代码，将在每一帧中将怪物移向玩家：

```cpp
void AMonster::Tick(float DeltaSeconds) {
    Super::Tick(DeltaSeconds); 

    //basic intel : move the monster towards the player 
    AAvatar *avatar = Cast<AAvatar>(
            UGameplayStatics::GetPlayerPawn(GetWorld(), 0)); 
    if (!avatar) return;
    FVector toPlayer = avatar->GetActorLocation() - GetActorLocation(); 
    toPlayer.Normalize(); // reduce to unit vector 
                        // Actually move the monster towards the player a bit
    AddMovementInput(toPlayer, Speed*DeltaSeconds); // At least face the target
    // Gets you the rotator to turn something // that looks in the `toPlayer`direction 
    FRotator toPlayerRotation = toPlayer.Rotation();
    toPlayerRotation.Pitch = 0; // 0 off the pitch
    RootComponent->SetWorldRotation(toPlayerRotation);
}
```

你还需要在文件顶部添加以下包含：

```cpp
#include "Avatar.h"

#include "Kismet/GameplayStatics.h"
```

为了使`AddMovementInput`起作用，你必须在蓝图中的 AIController 类面板下选择一个控制器，如下图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/65466d23-e455-432a-b7e6-7cf73d2f5dd2.png)

如果你选择了`None`，对`AddMovementInput`的调用将不会产生任何效果。为了防止这种情况发生，请选择`AIController`类或`PlayerController`类作为你的 AIController 类。确保你对地图上放置的每个怪物都进行了检查。

上面的代码非常简单。它包括了敌人智能的最基本形式-每一帧向玩家移动一小部分：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/b7ef6c0c-c7db-4051-a3c5-9dd6eb8a64c8.png)

如果你的怪物面向玩家的反方向，请尝试在 Z 方向上将网格的旋转角度减少 90 度。

经过一系列帧后，怪物将跟踪并围绕关卡追随玩家。要理解这是如何工作的，你必须记住`Tick`函数平均每秒调用约 60 次。这意味着在每一帧中，怪物都会离玩家更近一点。由于怪物以非常小的步伐移动，它的动作看起来平滑而连续（实际上，它在每一帧中都在做小跳跃）：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/90504cda-d36b-4541-b6f1-7d83149666b3.png)

跟踪的离散性-怪物在三个叠加帧上的运动

怪物每秒移动约 60 次的原因是硬件限制。典型显示器的刷新率为 60 赫兹，因此它作为每秒有用的更新次数的实际限制器。以高于刷新率的帧率进行更新是可能的，但对于游戏来说并不一定有用，因为在大多数硬件上，你每 1/60 秒只能看到一张新图片。一些高级的物理建模模拟几乎每秒进行 1,000 次更新，但可以说，你不需要那种分辨率的游戏，你应该将额外的 CPU 时间保留给玩家会喜欢的东西，比如更好的 AI 算法。一些新硬件宣称刷新率高达 120 赫兹（查找游戏显示器，但不要告诉你的父母我让你把所有的钱都花在上面）。

# 怪物运动的离散性

计算机游戏是离散的。在前面的截图中，玩家被视为沿着屏幕直线移动，以微小的步骤。怪物的运动也是小步骤。在每一帧中，怪物朝玩家迈出一个小的离散步骤。怪物在移动时遵循一条明显的曲线路径，直接朝向每一帧中玩家所在的位置。

将怪物移向玩家，按照以下步骤进行：

1.  我们必须获取玩家的位置。由于玩家在全局函数`UGameplayStatics::GetPlayerPawn`中可访问，我们只需使用此函数检索指向玩家的指针。

1.  我们找到了从`Monster`函数(`GetActorLocation()`)指向玩家(`avatar->GetActorLocation()`)的向量。

1.  我们需要找到从怪物指向 avatar 的向量。为此，您必须从怪物的位置中减去 avatar 的位置，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/ba693371-ca92-4022-a37f-db4bafa740c2.png)

这是一个简单的数学规则，但往往容易出错。要获得正确的向量，始终要从目标（终点）向量中减去源（起点）向量。在我们的系统中，我们必须从`Monster`向量中减去`Avatar`向量。这是因为从系统中减去`Monster`向量会将`Monster`向量移动到原点，而`Avatar`向量将位于`Monster`向量的左下方：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/28a26f5a-99e2-4765-b5d9-d592214bbbec.png)

确保尝试你的代码。此时，怪物将朝向你的玩家奔跑并围拢在他周围。通过上述代码的设置，它们不会攻击，只会跟随他，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/57fafe09-5b16-444e-82e9-518cebc00290.png)

# Monster SightSphere

目前，怪物并未注意`SightSphere`组件。也就是说，在世界中无论玩家在哪里，怪物都会朝向他移动。我们现在想要改变这一点。

要做到这一点，我们只需要让`Monster`遵守`SightSphere`的限制。如果玩家在怪物的`SightSphere`对象内，怪物将进行追击。否则，怪物将对玩家的位置视而不见，不会追击玩家。

检查对象是否在球体内很简单。在下面的截图中，如果点**p**和中心**c**之间的距离**d**小于球体半径**r**，则点**p**在球体内：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/9cc450f6-dc51-49ea-aa6c-e85521cf4c98.png)

当 d 小于 r 时，P 在球体内

因此，在我们的代码中，前面的截图翻译成以下内容：

```cpp
void AMonster::Tick(float DeltaSeconds) 
{ 
  Super::Tick( DeltaSeconds ); 
  AAvatar *avatar = Cast<AAvatar>(  
   UGameplayStatics::GetPlayerPawn(GetWorld(), 0) ); 
  if( !avatar ) return; 
    FVector toPlayer = avatar->GetActorLocation() -  
     GetActorLocation(); 
  float distanceToPlayer = toPlayer.Size(); 
  // If the player is not in the SightSphere of the monster, 
  // go back 
  if( distanceToPlayer > SightSphere->GetScaledSphereRadius() ) 
  { 
    // If the player is out of sight, 
    // then the enemy cannot chase 
    return; 
  } 

  toPlayer /= distanceToPlayer;  // normalizes the vector 
  // Actually move the monster towards the player a bit 
  AddMovementInput(toPlayer, Speed*DeltaSeconds); 
  // (rest of function same as before (rotation)) 
} 
```

前面的代码为`Monster`角色添加了额外的智能。`Monster`角色现在可以在玩家超出怪物的`SightSphere`对象范围时停止追逐玩家。结果如下：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/5cf683b3-17bb-4e80-b390-fe36c15f53e8.png)

在这里要做的一个好事情是将距离比较封装到一个简单的内联函数中。我们可以在`Monster`头文件中提供这两个内联成员函数，如下所示：

```cpp
inline bool isInSightRange( float d ) 
{ return d < SightSphere->GetScaledSphereRadius(); } 
inline bool isInAttackRange( float d ) 
{ return d < AttackRangeSphere->GetScaledSphereRadius(); } 
```

这些函数在传递的参数`d`在相关的球体内时返回值`true`。

内联函数意味着该函数更像是一个宏而不是函数。宏被复制并粘贴到调用位置，而函数则由 C++跳转并在其位置执行。内联函数很好，因为它们能够提供良好的性能，同时保持代码易于阅读。它们是可重用的。

# 怪物对玩家的攻击

怪物可以进行几种不同类型的攻击。根据`Monster`角色的类型，怪物的攻击可能是近战或远程攻击。

`Monster`角色将在玩家进入其`AttackRangeSphere`对象时攻击玩家。如果玩家超出怪物的`AttackRangeSphere`对象的范围，但玩家在怪物的`SightSphere`对象中，则怪物将向玩家靠近，直到玩家进入怪物的`AttackRangeSphere`对象。

# 近战攻击

*melee*的词典定义是一群混乱的人。近战攻击是在近距离进行的攻击。想象一群*zerglings*与一群*ultralisks*激烈战斗（如果你是星际争霸玩家，你会知道 zerglings 和 ultralisks 都是近战单位）。近战攻击基本上是近距离的肉搏战。要进行近战攻击，您需要一个近战攻击动画，当怪物开始近战攻击时，它会打开。为此，您需要在 UE4 的动画编辑器中编辑动画蓝图。

Zak Parrish 的系列是学习在蓝图中编程动画的绝佳起点：[`www.youtube.com/watch?v=AqYmC2wn7Cg&list=PL6VDVOqa_mdNW6JEu9UAS_s40OCD_u6yp&index=8`](https://www.youtube.com/watch?v=AqYmC2wn7Cg&list=PL6VDVOqa_mdNW6JEu9UAS_s40OCD_u6yp&index=8)。

现在，我们只会编写近战攻击，然后担心以后在蓝图中修改动画。

# 定义近战武器

我们将有三个部分来定义我们的近战武器。它们如下：

+   代表它的 C++代码

+   模型

+   连接代码和模型的 UE4 蓝图

# 用 C++编写近战武器

我们将定义一个新类`AMeleeWeapon`（派生自`AActor`），代表手持战斗武器（您现在可能已经猜到，A 会自动添加到您使用的名称中）。我将附加一些蓝图可编辑的属性到`AMeleeWeapon`类，并且`AMeleeWeapon`类将如下所示：

```cpp
#include "CoreMinimal.h"
#include "GameFramework/Actor.h"
#include "Components/BoxComponent.h"
#include "MeleeWeapon.generated.h"

class AMonster;

UCLASS()
class GOLDENEGG_API AMeleeWeapon : public AActor
{
    GENERATED_BODY()

public:
    AMeleeWeapon(const FObjectInitializer& ObjectInitializer);

    // The amount of damage attacks by this weapon do 
    UPROPERTY(EditAnywhere, BlueprintReadWrite, Category =
        MeleeWeapon)
        float AttackDamage;

    // A list of things the melee weapon already hit this swing 
    // Ensures each thing sword passes thru only gets hit once 
    TArray<AActor*> ThingsHit;

    // prevents damage from occurring in frames where 
    // the sword is not swinging 
    bool Swinging;

    // "Stop hitting yourself" - used to check if the  
    // actor holding the weapon is hitting himself 
    AMonster *WeaponHolder;

    // bounding box that determines when melee weapon hit 
    UPROPERTY(VisibleDefaultsOnly, BlueprintReadOnly, Category =
        MeleeWeapon)
        UBoxComponent* ProxBox;

    UPROPERTY(VisibleDefaultsOnly, BlueprintReadOnly, Category =
        MeleeWeapon)
        UStaticMeshComponent* Mesh;

    UFUNCTION(BlueprintNativeEvent, Category = Collision)
        void Prox(UPrimitiveComponent* OverlappedComponent, AActor* OtherActor, UPrimitiveComponent* OtherComp,
            int32 OtherBodyIndex, bool bFromSweep, const FHitResult& SweepResult);

    // You shouldn't need this unless you get a compiler error that it can't find this function.
    virtual int Prox_Implementation(UPrimitiveComponent* OverlappedComponent, AActor* OtherActor, UPrimitiveComponent* OtherComp,
        int32 OtherBodyIndex, bool bFromSweep, const FHitResult& SweepResult);

    void Swing();
    void Rest();
};
```

请注意，我在`ProxBox`中使用了边界框，而不是边界球。这是因为剑和斧头更适合用盒子而不是球来近似。这个类内部还有两个成员函数`Rest()`和`Swing()`，让`MeleeWeapon`知道演员处于什么状态（休息或挥舞）。这个类内还有一个`TArray<AActor*> ThingsHit`属性，用于跟踪每次挥舞时被这个近战武器击中的演员。我们正在编程，以便武器每次挥舞只能击中每个事物一次。

`AMeleeWeapon.cpp`文件将只包含一个基本构造函数和一些简单的代码，用于在我们的剑击中`OtherActor`时发送伤害。我们还将实现`Rest()`和`Swing()`函数以清除被击中的事物列表。`MeleeWeapon.cpp`文件包含以下代码：

```cpp
#include "MeleeWeapon.h"
#include "Monster.h"

AMeleeWeapon::AMeleeWeapon(const FObjectInitializer& ObjectInitializer)
    : Super(ObjectInitializer)
{
    AttackDamage = 1;
    Swinging = false;
    WeaponHolder = NULL;

    Mesh = ObjectInitializer.CreateDefaultSubobject<UStaticMeshComponent>(this,
        TEXT("Mesh"));
    RootComponent = Mesh;

    ProxBox = ObjectInitializer.CreateDefaultSubobject<UBoxComponent>(this,
        TEXT("ProxBox"));  
    ProxBox->OnComponentBeginOverlap.AddDynamic(this,
            &AMeleeWeapon::Prox);
    ProxBox->AttachToComponent(RootComponent, FAttachmentTransformRules::KeepWorldTransform);
}

int AMeleeWeapon::Prox_Implementation(UPrimitiveComponent* OverlappedComponent, AActor* OtherActor, UPrimitiveComponent* OtherComp,
    int32 OtherBodyIndex, bool bFromSweep, const FHitResult& SweepResult)
{
    // don't hit non root components 
    if (OtherComp != OtherActor->GetRootComponent())
    {
        return -1;
    }

    // avoid hitting things while sword isn't swinging, 
    // avoid hitting yourself, and 
    // avoid hitting the same OtherActor twice 
    if (Swinging && OtherActor != (AActor *) WeaponHolder &&
        !ThingsHit.Contains(OtherActor))
    {
        OtherActor->TakeDamage(AttackDamage + WeaponHolder->BaseAttackDamage, FDamageEvent(), NULL, this);
        ThingsHit.Add(OtherActor);
    }

    return 0;
}

void AMeleeWeapon::Swing()
{
    ThingsHit.Empty();  // empty the list 
    Swinging = true;
}

void AMeleeWeapon::Rest()
{
    ThingsHit.Empty();
    Swinging = false;
}
```

# 下载一把剑

要完成这个练习，我们需要一把剑放在模型的手中。我从[Kaan Gülhan](http://tf3dm.com/3d-model/sword-95782.html)添加了一个名为*Kilic*的剑到项目中。以下是您可以获得免费模型的其他地方的列表：

+   [`www.turbosquid.com/`](http://www.turbosquid.com/)

+   [`tf3dm.com/`](http://tf3dm.com/)

+   [`archive3d.net/`](http://archive3d.net/)

+   [`www.3dtotal.com/`](http://www.3dtotal.com/)

秘诀

乍看之下，在[TurboSquid.com](http://TurboSquid.com)上似乎没有免费模型。实际上，秘诀在于您必须在价格下选择免费：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/a490b27f-7f26-432b-b5aa-42cc31a5c2f0.png)

我不得不稍微编辑 kilic 剑网格，以修复初始大小和旋转。您可以将任何**Filmbox**（**FBX**）格式的网格导入到您的游戏中。kilic 剑模型包含在本章的示例代码包中。要将您的剑导入 UE4 编辑器，请执行以下步骤：

1.  右键单击要将模型添加到的任何文件夹

1.  导航到新资产|导入到（路径）...

1.  从弹出的文件资源管理器中，选择要导入的新资产。

1.  如果 Models 文件夹不存在，您可以通过在左侧的树视图上右键单击并在内容浏览器选项卡的左侧窗格中选择新文件夹来创建一个。

我从桌面上选择了`kilic.fbx`资产：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/45784dd7-4728-40b3-9c87-5ac514e17acb.png)

# 为近战武器创建蓝图

创建近战武器蓝图的步骤如下：

1.  在 UE4 编辑器中，创建一个基于`AMeleeWeapon`的蓝图，名为`BP_MeleeSword`。

1.  配置`BP_MeleeSword`以使用 kilic 刀片模型（或您选择的任何刀片模型），如下截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/cca72232-e787-4af8-b8df-e39c6920a0e5.png)

1.  `ProxBox`类将确定武器是否击中了某物，因此我们将修改`ProxBox`类，使其仅包围剑的刀片，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/557119be-e6aa-4e96-98b5-2f2afe4b1341.png)

1.  在碰撞预设面板下，对于网格（而不是 BlockAll），选择 NoCollision 选项非常重要。如下截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/bd4c4809-0985-44e7-91bc-afe6a6e32a7d.png)

1.  如果选择 BlockAll，则游戏引擎将自动解决剑和角色之间的所有相互穿透，通过推开剑触碰到的物体。结果是，每当挥动剑时，您的角色将似乎飞起来。

# 插座

在 UE4 中，插座是一个骨骼网格上的插座，用于另一个`Actor`。您可以在骨骼网格身上的任何地方放置插座。在正确放置插座后，您可以在 UE4 代码中将另一个`Actor`连接到此插座。

例如，如果我们想要在怪物的手中放一把剑，我们只需在怪物的手上创建一个插座。我们可以通过在玩家的头上创建一个插座，将头盔连接到玩家身上。

# 在怪物的手中创建一个骨骼网格插座

要将插座连接到怪物的手上，我们必须编辑怪物正在使用的骨骼网格。由于我们使用了 Mixamo_Adam 骨骼网格用于怪物，我们必须打开并编辑此骨骼网格。为此，请执行以下步骤：

1.  双击内容浏览器选项卡中的 Mixamo_Adam 骨骼网格（这将显示为 T 形），以打开骨骼网格编辑器。

1.  如果在内容浏览器选项卡中看不到 Mixamo Adam，请确保已经从 Unreal Launcher 应用程序将 Mixamo 动画包文件导入到项目中：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/38214ed6-eb3e-41ec-9713-af15d7a21f2f.png)

1.  单击屏幕右上角的 Skeleton。

1.  在左侧面板的骨骼树中向下滚动，直到找到 RightHand 骨骼。

1.  我们将在此骨骼上添加一个插座。右键单击 RightHand 骨骼，然后选择 Add Socket，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/8804beca-cfb9-4430-b55d-a345d5a9b4fc.png)

1.  您可以保留默认名称（RightHandSocket），或者根据需要重命名插座，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/ef650814-b14d-40e9-9416-df4685a222ff.png)

接下来，我们需要将剑添加到角色的手中。

# 将剑连接到模型

连接剑的步骤如下：

1.  打开 Adam 骨骼网格，找到树视图中的 RightHandSocket 选项。由于 Adam 用右手挥舞，所以应该将剑连接到他的右手上。

1.  右键单击 RightHandSocket 选项，选择 Add Preview Asset，并在出现的窗口中找到剑的骨骼网格：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/4fef8179-57ae-4873-926e-6151ac4dd213.png)

1.  您应该在模型的图像中看到 Adam 握着剑，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/4f3f2584-be87-4dc2-9467-423e25a01453.png)

1.  现在，点击 RightHandSocket 并放大 Adam 的手。我们需要调整预览中插座的位置，以便剑能正确放入其中。

1.  使用移动和旋转操作器或手动更改详细窗口中的插座参数，使剑正确放入他的手中：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/35148bf0-82e2-46c0-9c75-6e6e48946a84.png)

一个现实世界的提示

如果您有几个剑模型，想要在同一个`RightHandSocket`中切换，您需要确保这些不同的剑之间有相当的一致性（没有异常）。

1.  您可以通过转到屏幕右上角的动画选项卡来预览手中拿着剑的动画：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/d85e7871-26ca-400d-900a-882e7f37f0df.png)

然而，如果您启动游戏，Adam 将不会拿着剑。这是因为在 Persona 中将剑添加到插槽仅用于预览目的。

# 给玩家装备剑的代码

要从代码中为玩家装备一把剑并将其永久绑定到角色，需要在怪物实例初始化后实例化一个`AMeleeWeapon`实例，并将其附加到`RightHandSocket`。我们在`PostInitializeComponents()`中执行此操作，因为在这个函数中，`Mesh`对象已经完全初始化。

在`Monster.h`文件中，添加一个选择要使用的近战武器的`Blueprint`类名称（`UClass`）的挂钩。此外，使用以下代码添加一个变量的挂钩来实际存储`MeleeWeapon`实例：

```cpp
// The MeleeWeapon class the monster uses 
// If this is not set, he uses a melee attack 
UPROPERTY(EditAnywhere, BlueprintReadWrite, Category =  
   MonsterProperties) 
UClass* BPMeleeWeapon; 

// The MeleeWeapon instance (set if the character is using 
// a melee weapon) 
AMeleeWeapon* MeleeWeapon; 
```

此外，请确保在文件顶部添加`#include "MeleeWeapon.h"`。现在，在怪物的蓝图类中选择`BP_MeleeSword`蓝图。

在 C++代码中，您需要实例化武器。为此，我们需要为`Monster`类声明和实现一个`PostInitializeComponents`函数。在`Monster.h`中，添加原型声明：

```cpp
virtual void PostInitializeComponents() override; 
```

`PostInitializeComponents`在怪物对象的构造函数完成并且对象的所有组件都初始化（包括蓝图构造）之后运行。因此，现在是检查怪物是否附加了`MeleeWeapon`蓝图的完美时机，并在有的情况下实例化这个武器。以下代码被添加到`Monster.cpp`的`AMonster::PostInitializeComponents()`实现中以实例化武器：

```cpp
void AMonster::PostInitializeComponents()
{
    Super::PostInitializeComponents();

    // instantiate the melee weapon if a bp was selected 
    if (BPMeleeWeapon)
    {
        MeleeWeapon = GetWorld()->SpawnActor<AMeleeWeapon>(
            BPMeleeWeapon, FVector(), FRotator());

        if (MeleeWeapon)
        {
            const USkeletalMeshSocket *socket = GetMesh()->GetSocketByName(
                FName("RightHandSocket")); // be sure to use correct 
                                    // socket name! 
            socket->AttachActor(MeleeWeapon, GetMesh());
            MeleeWeapon->WeaponHolder = this;
        }
    }
}
```

此外，请确保在文件顶部添加`#include "Engine/SkeletalMeshSocket.h"`。如果为怪物的蓝图选择了`BPMeleeWeapon`，那么怪物现在将会从一开始就拿着剑：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/c8ca07fb-67ea-4ec5-bc93-e6994e0512ef.png)

# 触发攻击动画

默认情况下，我们的 C++ `Monster`类与触发攻击动画之间没有连接；换句话说，`MixamoAnimBP_Adam`类无法知道怪物何时处于攻击状态。

因此，我们需要更新 Adam 骨骼的动画蓝图（`MixamoAnimBP_Adam`），以包括在`Monster`类变量列表中查询并检查怪物是否处于攻击状态。我们在本书中之前没有使用过动画蓝图（或者一般的蓝图），但是按照这些说明一步一步来，你应该能够看到它的实现。

我会在这里温和地介绍蓝图术语，但我鼓励您去看一下 Zak Parrish 的教程系列，了解蓝图的初步介绍。

# 蓝图基础知识

UE4 蓝图是代码的视觉实现（不要与有时人们说 C++类是类实例的比喻蓝图混淆）。在 UE4 蓝图中，您不需要实际编写代码，而是将元素拖放到图表上并连接它们以实现所需的播放。通过将正确的节点连接到正确的元素，您可以在游戏中编写任何您想要的东西。

本书不鼓励使用蓝图，因为我们试图鼓励您编写自己的代码。然而，动画最好使用蓝图，因为这是艺术家和设计师所熟悉的。

让我们开始编写一个示例蓝图，以了解它们的工作原理：

1.  单击顶部的蓝图菜单栏，选择“打开级别蓝图”，如下图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/30c64367-3938-4bd3-9bff-a4ab5a4d36ea.png)

级别蓝图选项在开始级别时会自动执行。打开此窗口后，您应该看到一个空白的画布，可以在上面创建游戏玩法，如下图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/69ea554d-fcca-457e-9d6c-c9918fbb4acd.png)

1.  在图纸上的任何位置右键单击。

1.  开始键入`begin`，然后从下拉列表中选择“事件开始播放”选项。

确保选中上下文敏感复选框，如下图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/09a8efff-e8c0-4d7b-a7e2-66fe5ebd1646.png)

1.  在单击“事件开始播放”选项后，屏幕上会出现一个红色框。右侧有一个白色引脚。这被称为执行引脚，如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/856e15bb-4a78-448d-a1a5-2f62f37d9da2.png)

关于动画蓝图，您需要了解的第一件事是白色引脚执行路径（白线）。如果您以前见过蓝图图表，您一定会注意到白线穿过图表，如下图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/8afd6b4b-eab7-435c-837a-957a1427358a.png)

白色引脚执行路径基本上相当于将代码排成一行并依次运行。白线确定了将执行哪些节点以及执行顺序。如果一个节点没有连接白色执行引脚，那么该节点将根本不会被执行。

1.  将白色执行引脚拖出“事件开始播放”。

1.  首先在“可执行操作”对话框中键入`draw debug box`。

1.  选择弹出的第一项（fDraw Debug Box），如下图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/44282d51-4c34-4c01-bd77-187c8efa5ab9.png)

1.  填写一些关于盒子外观的细节。在这里，我选择了蓝色的盒子，盒子的中心在（0, 0, 100），盒子的大小为（200, 200, 200），持续时间为 180 秒（请确保输入足够长的持续时间，以便您可以看到结果），如下图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/83031d3b-4f34-4633-9969-fbc4a60e86fe.png)

1.  现在，单击“播放”按钮以实现图表。请记住，您必须找到世界原点才能看到调试框。

1.  通过在（0, 0，（某个 z 值））放置一个金色蛋来找到世界原点，如下图所示，或者尝试增加线条粗细以使其更加可见：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/0847a7b9-141e-4370-828b-fffb37162f92.png)

这是在级别中盒子的样子：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/ec1eee36-0d8a-4f42-a3ad-ab2455b7b498.png)

# 修改 Mixamo Adam 的动画蓝图

要集成我们的攻击动画，我们必须修改蓝图。在内容浏览器中，打开`MixamoAnimBP_Adam`。

你会注意到的第一件事是，图表在事件通知部分上方有两个部分：

+   顶部标有“基本角色移动...”。

+   底部显示“Mixamo 示例角色动画...”。

基本角色移动负责模型的行走和奔跑动作。我们将在负责攻击动画的 Mixamo 示例角色动画部分进行工作。我们将在图表的后半部分进行工作，如下图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/ebebd7b4-e25e-4b79-859c-395edd3b50d9.png)

当您首次打开图表时，它会首先放大到靠近底部的部分。要向上滚动，右键单击鼠标并向上拖动。您还可以使用鼠标滚轮缩小，或者按住*Alt*键和右键同时向上移动鼠标来缩小。

在继续之前，您可能希望复制 MixamoAnimBP_Adam 资源，以防需要稍后返回并进行更改而损坏原始资源。这样可以让您轻松返回并纠正问题，如果发现您在修改中犯了错误，而无需重新安装整个动画包的新副本到您的项目中：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/b1e64964-84fe-4a34-8d19-cac80acc6293.png)

当从虚幻启动器向项目添加资产时，会复制原始资产，因此您现在可以在项目中修改 MixamoAnimBP_Adam，并在以后的新项目中获得原始资产的新副本。

我们要做的只是让 Adam 在攻击时挥动剑。让我们按照以下顺序进行：

1.  删除说“正在攻击”的节点：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/a854e233-ab67-4e0f-9f14-5235f6478623.png)

1.  重新排列节点，如下所示，使 Enable Attack 节点单独位于底部：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/c60e121a-d732-400c-8326-59e9c536c342.png)

1.  我们将处理此动画正在播放的怪物。向上滚动一点图表，并拖动标有 Try Get Pawn Owner 对话框中的 Return Value 的蓝点。将其放入图表中，当弹出菜单出现时，选择 Cast to Monster（确保已选中上下文敏感，否则 Cast to Monster 选项将不会出现）。Try Get Pawn Owner 选项获取拥有动画的`Monster`实例，这只是`AMonster`类对象，如下图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/af2cf342-af78-4cff-b678-654390089ac3.png)

1.  单击 Sequence 对话框中的+，并从 Sequence 组将另一个执行引脚拖动到 Cast to Monster 节点实例，如下图所示。这确保了 Cast to Monster 实例实际上被执行：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/bbee93c5-cb1f-435a-bbc1-cd9b4d36e413.png)

1.  下一步是从 Cast to Monster 节点的 As Monster 端口拉出引脚，并查找 Is in Attack Range 属性：

为了显示这一点，您需要回到`Monster.h`并在 is in Attack Range 函数之前添加以下行，并编译项目（稍后将对此进行解释）：

`UFUNCTION(BlueprintCallable, Category = Collision)`

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/17dac8e2-421b-4e46-933a-76910aa82edc.png)

1.  应该自动从左侧 Cast to Monster 节点的白色执行引脚到右侧 Is in Attack Range 节点有一条线。接下来，从 As Monster 再拖出一条线，这次查找 Get Distance To：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/d6c28419-9dd2-4087-964b-a534901f7447.png)

1.  您需要添加一个节点来获取玩家角色并将其发送到 Get Distance To 的 Other Actor 节点。只需右键单击任何位置，然后查找 Get Player Character：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/b4197cef-65b9-4ab1-a66b-2b2223366a1b.png)

1.  将 Get Player Character 的返回值节点连接到 Other Actor，将 Get Distance To 的返回值连接到 Is In Attack Range 的 D：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/a346fb6f-3da4-4e9c-baf1-ad7ef4f63973.png)

1.  将白色和红色引脚拖到 SET 节点上，如图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/35f5c1f6-8cbe-45e6-a86e-324565b2024b.png)

前面蓝图的等效伪代码类似于以下内容：

```cpp
if(   Monster.isInAttackRangeOfPlayer() )   
{   
    Monster.Animation = The Attack Animation;   
}   
```

测试您的动画。怪物应该只在玩家范围内挥动。如果不起作用并且您创建了副本，请确保将`animBP`切换到副本。此外，默认动画是射击，而不是挥动剑。我们稍后会修复这个问题。

# 挥动剑的代码

我们希望在挥动剑时添加动画通知事件：

1.  声明并向您的`Monster`类添加一个蓝图可调用的 C++函数：

```cpp
// in Monster.h: 
UFUNCTION( BlueprintCallable, Category = Collision ) 
void SwordSwung(); 
```

`BlueprintCallable`语句意味着可以从蓝图中调用此函数。换句话说，`SwordSwung()`将是一个我们可以从蓝图节点调用的 C++函数，如下所示：

```cpp
// in Monster.cpp 
void AMonster::SwordSwung() 
{ 
  if( MeleeWeapon ) 
  { 
    MeleeWeapon->Swing(); 
  } 
} 
```

1.  双击 Content Browser 中的 Mixamo_Adam_Sword_Slash 动画（应该在 MixamoAnimPack/Mixamo_Adam/Anims/Mixamo_Adam_Sword_Slash 中）打开。

1.  找到 Adam 开始挥动剑的地方。

1.  右键单击 Notifies 栏上的那一点，然后在 Add Notify...下选择 New Notify，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/b8e6713c-cf27-4651-b2d0-95376742a1e6.png)

1.  将通知命名为`SwordSwung`：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/40f7087a-a2a0-49da-99d7-7ac61a68c4d9.png)

通知名称应出现在动画的时间轴上，如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/0f5f2318-f089-4e65-abb2-28e50f1f3ce4.png)

1.  保存动画，然后再次打开您的 MixamoAnimBP_Adam 版本。

1.  在 SET 节点组下面，创建以下图表：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/e70c5fcf-6cba-47f1-bacd-2174d596cd80.png)

1.  当您右键单击图表（打开上下文敏感）并开始输入`SwordSwung`时，将出现 AnimNotify_SwordSwung 节点。Monster 节点再次从 Try Get Pawn Owner 节点中输入，就像*修改 Mixamo Adam 动画蓝图*部分的第 2 步一样。

1.  Sword Swung 是`AMonster`类中可调用的蓝图 C++函数（您需要编译项目才能显示）。

1.  您还需要进入 MaximoAnimBP_Adam 的 AnimGraph 选项卡。

1.  双击状态机以打开该图表。

1.  双击攻击状态以打开。

1.  选择左侧的 Play Mixamo_Adam Shooting。

1.  射击是默认动画，但显然这不是我们想要发生的。因此，删除它，右键单击并查找 Play Mixamo_Adam_Sword_Slash。然后，从一个人的小图标拖动到最终动画姿势的结果：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/a5be2291-79fe-4c79-946c-cbebc67ae619.png)

如果现在开始游戏，您的怪物将在实际攻击时执行它们的攻击动画。如果您还在`AAvatar`类中重写`TakeDamage`以在剑的边界框与您接触时减少 HP，您将看到您的 HP 条减少一点（请回忆，HP 条是在第八章的最后添加的，*Actors and Pawns*，作为一个练习）：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/e4885b2d-6c9b-4228-9cec-1e4a0e84cf1f.png)

# 投射或远程攻击

远程攻击通常涉及某种抛射物。抛射物可以是子弹之类的东西，但也可以包括闪电魔法攻击或火球攻击之类的东西。要编写抛射物攻击，您应该生成一个新对象，并且只有在抛射物到达玩家时才对玩家造成伤害。

要在 UE4 中实现基本的子弹，我们应该派生一个新的对象类型。我从`AActor`类派生了一个`ABullet`类，如下所示：

```cpp
#pragma once

#include "CoreMinimal.h"
#include "GameFramework/Actor.h"
#include "Components/SphereComponent.h"
#include "Bullet.generated.h"

UCLASS()
class GOLDENEGG_API ABullet : public AActor
{
 GENERATED_BODY()

public:
 // Sets default values for this actor's properties
 ABullet(const FObjectInitializer& ObjectInitializer);

 // How much damage the bullet does. 
 UPROPERTY(EditAnywhere, BlueprintReadWrite, Category =
 Properties)
 float Damage;

 // The visible Mesh for the component, so we can see 
 // the shooting object 
 UPROPERTY(VisibleDefaultsOnly, BlueprintReadOnly, Category =
 Collision)
 UStaticMeshComponent* Mesh;

 // the sphere you collide with to do impact damage 
 UPROPERTY(VisibleDefaultsOnly, BlueprintReadOnly, Category =
 Collision)
 USphereComponent* ProxSphere;

 UFUNCTION(BlueprintNativeEvent, Category = Collision)
 void Prox(UPrimitiveComponent* OverlappedComponent, AActor* OtherActor, UPrimitiveComponent* OtherComp,
 int32 OtherBodyIndex, bool bFromSweep, const FHitResult& SweepResult);

 // You shouldn't need this unless you get a compiler error that it can't find this function.
 virtual int Prox_Implementation(UPrimitiveComponent* OverlappedComponent, AActor* OtherActor, UPrimitiveComponent* OtherComp,
 int32 OtherBodyIndex, bool bFromSweep, const FHitResult& SweepResult); };
```

`ABullet`类中有一些重要的成员，如下所示：

+   一个`float`变量，用于表示子弹接触时造成的伤害

+   一个`Mesh`变量，用于表示子弹的主体

+   一个`ProxSphere`变量，用于检测子弹最终击中物体的情况

+   当`Prox`检测到靠近物体时运行的函数

`ABullet`类的构造函数应该初始化`Mesh`和`ProxSphere`变量。在构造函数中，我们将`RootComponent`设置为`Mesh`变量，然后将`ProxSphere`变量附加到`Mesh`变量上。`ProxSphere`变量将用于碰撞检查。应该关闭`Mesh`变量的碰撞检查，如下所示：

```cpp
ABullet::ABullet(const FObjectInitializer& ObjectInitializer)
    : Super(ObjectInitializer)
{
    Mesh = ObjectInitializer.CreateDefaultSubobject<UStaticMeshComponent>(this,
        TEXT("Mesh"));
    RootComponent = Mesh;

    ProxSphere = ObjectInitializer.CreateDefaultSubobject<USphereComponent>(this,
        TEXT("ProxSphere"));
    ProxSphere->AttachToComponent(RootComponent, FAttachmentTransformRules::KeepWorldTransform);

    ProxSphere->OnComponentBeginOverlap.AddDynamic(this,
        &ABullet::Prox);
    Damage = 1;
}
```

我们在构造函数中将`Damage`变量初始化为`1`，但一旦我们从`ABullet`类创建蓝图，可以在 UE4 编辑器中更改这个值。接下来，`ABullet::Prox_Implementation()`函数应该在我们与其他角色的`RootComponent`碰撞时对角色造成伤害。我们可以通过代码实现这一点：

```cpp
int ABullet::Prox_Implementation(UPrimitiveComponent* OverlappedComponent, AActor* OtherActor, UPrimitiveComponent* OtherComp,
    int32 OtherBodyIndex, bool bFromSweep, const FHitResult& SweepResult)
{
    if (OtherComp != OtherActor->GetRootComponent())
    {
        // don't collide w/ anything other than 
        // the actor's root component 
        return -1;
    }

    OtherActor->TakeDamage(Damage, FDamageEvent(), NULL, this);
    Destroy();
    return 0;
}
```

# 子弹物理

要使子弹飞过关卡，您可以使用 UE4 的物理引擎。

创建一个基于`ABullet`类的蓝图。我选择了 Shape_Sphere 作为网格，并将其缩小到更合适的大小。子弹的网格应启用碰撞物理，但子弹的包围球将用于计算伤害。

配置子弹的行为是有点棘手的，所以我们将在四个步骤中进行介绍，如下所示：

1.  在组件选项卡中选择 Mesh（继承）。`ProxSphere`变量应该在 Mesh 下面。

1.  在详细信息选项卡中，勾选模拟物理和模拟生成碰撞事件。

1.  从碰撞预设下拉列表中选择自定义....

1.  从碰撞启用下拉菜单中选择碰撞启用（查询和物理）。同时，勾选碰撞响应框，如图所示；对于大多数类型（WorldStatic、WorldDynamic 等），勾选 Block，但只对 Pawn 勾选 Overlap：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/d6763116-289f-4124-b346-e15ac551212a.png)

模拟物理复选框使`ProxSphere`属性受到重力和对其施加的冲量力的影响。冲量是瞬时的力量推动，我们将用它来驱动子弹的射击。如果不勾选模拟生成碰撞事件复选框，那么球体将掉到地板上。阻止所有碰撞的作用是确保球体不能穿过任何物体。

如果现在直接从内容浏览器选项卡将几个`BP_Bullet`对象拖放到世界中，它们将简单地掉到地板上。当它们在地板上时，你可以踢它们。下面的截图显示了地板上的球体对象：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/28db3eff-f0db-4e40-af94-d77fa0d03978.png)

然而，我们不希望子弹掉在地板上。我们希望它们被射出。因此，让我们把子弹放在`Monster`类中。

# 将子弹添加到怪物类

让我们逐步来看一下如何做到这一点：

1.  向`Monster`类添加一个接收蓝图实例引用的成员。这就是`UClass`对象类型的用途。此外，添加一个蓝图可配置的`float`属性来调整射出子弹的力量，如下所示：

```cpp
// The blueprint of the bullet class the monster uses 
UPROPERTY(EditAnywhere, BlueprintReadWrite, Category =  
   MonsterProperties) 
UClass* BPBullet; 
// Thrust behind bullet launches 
UPROPERTY(EditAnywhere, BlueprintReadWrite, Category =  
   MonsterProperties) 
float BulletLaunchImpulse; 
```

1.  编译并运行 C++项目，打开你的`BP_Monster`蓝图。

1.  现在可以在`BPBullet`下选择一个蓝图类，如下图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/7bcb73ca-41ea-41f4-8b58-b8002a16b82c.png)

1.  一旦选择了怪物射击时要实例化的蓝图类类型，就必须编写代码让怪物在玩家处于其射程范围内时进行射击。

怪物从哪里射击？实际上，它应该从一个骨骼中射击。如果你对这个术语不熟悉，骨骼只是模型网格中的参考点。模型网格通常由许多“骨骼”组成。

1.  查看一些骨骼，通过在内容浏览器选项卡中双击资产打开 Mixamo_Adam 网格，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/4bab18f9-4d0a-41ae-9488-852cb695ec28.png)

1.  转到骨架选项卡，你将在左侧看到所有怪物骨骼的树形视图列表。我们要做的是选择一个骨骼从中发射子弹。在这里，我选择了`LeftHand`选项。

艺术家通常会在模型网格中插入一个额外的骨骼来发射粒子，这可能在枪口的尖端。

从基础模型网格开始，我们可以获取`Mesh`骨骼的位置，并在代码中让怪物从该骨骼发射`Bullet`实例。

可以使用以下代码获得完整的怪物`Tick`和`Attack`函数：

```cpp
void AMonster::Tick(float DeltaSeconds) 
{ 
  Super::Tick( DeltaSeconds ); 

  // move the monster towards the player 
  AAvatar *avatar = Cast<AAvatar>(  
   UGameplayStatics::GetPlayerPawn(GetWorld(), 0) ); 
  if( !avatar ) return; 

  FVector playerPos = avatar->GetActorLocation(); 
  FVector toPlayer = playerPos - GetActorLocation(); 
  float distanceToPlayer = toPlayer.Size(); 

  // If the player is not the SightSphere of the monster, 
  // go back 
  if( distanceToPlayer > SightSphere->GetScaledSphereRadius() ) 
  { 
    // If the player is OS, then the enemy cannot chase 
    return; 
  } 

  toPlayer /= distanceToPlayer;  // normalizes the vector 

  // At least face the target 
  // Gets you the rotator to turn something 
  // that looks in the `toPlayer` direction 
  FRotator toPlayerRotation = toPlayer.Rotation(); 
  toPlayerRotation.Pitch = 0; // 0 off the pitch 
  RootComponent->SetWorldRotation( toPlayerRotation ); 

  if( isInAttackRange(distanceToPlayer) ) 
  { 
    // Perform the attack 
    if( !TimeSinceLastStrike ) 
    { 
      Attack(avatar); 
    } 

    TimeSinceLastStrike += DeltaSeconds; 
    if( TimeSinceLastStrike > AttackTimeout ) 
    { 
      TimeSinceLastStrike = 0; 
    } 

    return;  // nothing else to do 
  } 
  else 
  { 
    // not in attack range, so walk towards player 
    AddMovementInput(toPlayer, Speed*DeltaSeconds); 
  } 
} 
```

`AMonster::Attack`函数相对简单。当然，我们首先需要在`Monster.h`文件中添加原型声明，以便在`.cpp`文件中编写我们的函数：

```cpp
void Attack(AActor* thing); 
```

在`Monster.cpp`中，我们实现`Attack`函数，如下所示：

```cpp
void AMonster::Attack(AActor* thing) 
{ 
  if( MeleeWeapon ) 
  { 
    // code for the melee weapon swing, if  
    // a melee weapon is used 
    MeleeWeapon->Swing(); 
  } 
  else if( BPBullet ) 
  { 
    // If a blueprint for a bullet to use was assigned, 
    // then use that. Note we wouldn't execute this code 
    // bullet firing code if a MeleeWeapon was equipped 
    FVector fwd = GetActorForwardVector(); 
    FVector nozzle = GetMesh()->GetBoneLocation( "RightHand" ); 
    nozzle += fwd * 155;// move it fwd of the monster so it  
     doesn't 
    // collide with the monster model 
    FVector toOpponent = thing->GetActorLocation() - nozzle; 
    toOpponent.Normalize(); 
    ABullet *bullet = GetWorld()->SpawnActor<ABullet>(  
     BPBullet, nozzle, RootComponent->GetComponentRotation()); 

    if( bullet ) 
    { 
      bullet->Firer = this; 
      bullet->ProxSphere->AddImpulse(  
        toOpponent*BulletLaunchImpulse ); 
    } 
    else 
    { 
      GEngine->AddOnScreenDebugMessage( 0, 5.f,  
      FColor::Yellow, "monster: no bullet actor could be spawned.  
       is the bullet overlapping something?" ); 
    } 
  } 
} 
```

还要确保在文件顶部添加`#include "Bullet.h"`。我们将实现近战攻击的代码保持不变。假设怪物没有持有近战武器，然后我们检查`BPBullet`成员是否已设置。如果`BPBullet`成员已设置，则意味着怪物将创建并发射`BPBullet`蓝图类的实例。

特别注意以下行：

```cpp
ABullet *bullet = GetWorld()->SpawnActor<ABullet>(BPBullet,  
   nozzle, RootComponent->GetComponentRotation() );
```

这就是我们向世界添加新角色的方式。`SpawnActor()`函数将`UCLASS`的一个实例放在您传入的`spawnLoc`中，并具有一些初始方向。

在我们生成子弹之后，我们调用`AddImpulse()`函数来使其`ProxSphere`变量向前发射。

还要在 Bullet.h 中添加以下行：

```cpp
AMonster *Firer;
```

# 玩家击退

为了给玩家添加击退效果，我在`Avatar`类中添加了一个名为`knockback`的成员变量。每当 avatar 受伤时就会发生击退：

```cpp
FVector knockback; // in class AAvatar
```

为了弄清楚击中玩家时将其击退的方向，我们需要在`AAvatar::TakeDamage`中添加一些代码。这将覆盖`AActor`类中的版本，因此首先将其添加到 Avatar.h 中：

```cpp
virtual float TakeDamage(float DamageAmount, struct FDamageEvent const& DamageEvent, class AController* EventInstigator, AActor* DamageCauser) override;
```

计算从攻击者到玩家的方向向量，并将该向量存储在`knockback`变量中：

```cpp
float AAvatar::TakeDamage(float DamageAmount, struct FDamageEvent const& DamageEvent, class AController* EventInstigator, AActor* DamageCauser)
{
    // add some knockback that gets applied over a few frames 
    knockback = GetActorLocation() - DamageCauser->GetActorLocation();
    knockback.Normalize();
    knockback *= DamageAmount * 500; // knockback proportional to damage 
    return AActor::TakeDamage(DamageAmount, DamageEvent, EventInstigator, DamageCauser);
}
```

在`AAvatar::Tick`中，我们将击退应用到 avatar 的位置：

```cpp
void AAvatar::Tick( float DeltaSeconds ) 
{ 
  Super::Tick( DeltaSeconds ); 

  // apply knockback vector 
  AddMovementInput( -1*knockback, 1.f ); 

  // half the size of the knockback each frame 
  knockback *= 0.5f; 
} 
```

由于击退向量会随着每一帧而减小，所以随着时间的推移它会变得越来越弱，除非击退向量在受到另一次打击时得到更新。

为了使子弹起作用，您需要将 BPMelee Weapon 设置为 None。您还应该增加 AttackRangeSphere 的大小，并调整子弹发射冲量到一个有效的值。

# 摘要

在本章中，我们探讨了如何在屏幕上实例化怪物，让它们追逐玩家并攻击他。我们使用不同的球体来检测怪物是否在视线范围或攻击范围内，并添加了具有近战或射击攻击能力的能力，具体取决于怪物是否有近战武器。如果您想进一步实验，可以尝试更改射击动画，或者添加额外的球体，并使怪物在移动时继续射击，并在攻击范围内切换到近战。在下一章中，我们将通过研究先进的人工智能技术来进一步扩展怪物的能力。


# 第十二章：用先进的 AI 构建更聪明的怪物

到目前为止，我们所拥有的怪物并没有做很多事情。他们站在一个地方，直到他们能看到你，然后他们会朝你走去，根据你设置的情况，进行近战攻击或射击攻击。在一个真正的游戏中，你希望你的角色做的事情比这多得多，这样他们看起来更真实。这就是**人工智能**（**AI**）的作用。

AI 是一个庞大的主题，有整本书专门讨论它，但我们将介绍一些 UE4 支持的使 AI 编程更容易的方法，这样你就可以轻松地创建更真实的怪物。我们将快速概述以下主题：

+   导航 - 路径查找和 NavMesh

+   行为树

+   环境查询系统

+   群集

+   机器学习和神经网络

+   遗传算法

如果你对此感兴趣，并且想了解更多，那么有很多优秀的书籍可以供你深入了解 AI 的其他方面。

# 导航 - 路径查找和 NavMesh

目前，我们创建的怪物只能朝一个方向移动——直线朝着你的位置。但是如果有山、建筑、树木、河流或其他物体挡住了怪物的路怎么办？在许多情况下，直线是不可能的。目前，如果怪物撞到墙上，它就会停在那里，这并不是很现实。这就是路径查找的作用。

# 什么是路径查找？

路径查找是一种找到路径（通常是最短和/或最容易的路径）到达目的地的方法。将整个环境想象成一个网格，每个单元格中都有一个数字，表示导航的难度。因此，一个有墙挡住去路的单元格将具有非常高的值，而陡峭的路径可能比容易的路径具有更高的值。路径查找的目标是找到所有沿着该路径的单元格的总值最低的路径。

有不同的算法或方法来处理路径查找。最知名的是称为 A*（发音为*A 星*）的算法。

# 什么是 A*？

我们这里不会使用 A*，但是如果你打算在未来进行 AI 编程，你至少应该对它有所了解，所以我会做一个简要的概述。A*基本上搜索围绕角色的单元格，优先考虑成本最低的单元格。它计算到目前为止路径的成本（通过累加到该点的成本）加上一个启发式，即从该点到目标的成本的猜测。

有很多计算启发式的方法。它可以是直接到目标的距离（你可能会说，像乌鸦飞一样简单）。如果启发式实际上比实际成本要低，那么结果会更好，所以这样做效果很好。

一旦找到成本最低的单元格，然后再向前一步，查看周围的单元格。一直持续到达目标。如果你发现自己到达了以前去过的单元格，并且这种方式的总路径成本更低，你可以用更低成本的路径替换它。这有助于你获得更短的路径。一旦到达目标，你可以沿着路径向后走，你就会得到一条完整的通往目标的路径。

你可以在网上或人工智能书籍中找到更多关于 A*和其他路径查找算法的信息。如果你在更复杂的项目中进行这项工作，你需要了解它们，但对于这个，UE4 有一个更简单和更容易的方法：使用`NavMesh`。

# 使用 NavMesh

`NavMesh`是 UE4 中的一个对象，你可以将其放置在世界中，告诉它你希望角色能够导航的环境的哪些部分。要做到这一点，请执行以下步骤：

1.  添加一些障碍。你可以添加立方体、圆柱体或其他任何你想要添加的东西来阻挡移动，就像这样：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/4ba19b29-326b-4b73-ac0b-5da49506bf4b.png)

1.  一旦你按照自己的意愿设置了级别，在模式窗口中，转到体积，找到 Nav Mesh Bounds Volume，将其拖放到级别上，并缩放以覆盖你希望怪物能够导航的整个区域。

如果您现在尝试，您仍然会看到怪物走进墙壁然后停下来。这是因为我们需要改变移动的方式。我们将通过创建自己的`AIController`类来实现这一点。

# 创建一个 AIController 类

让我们按步骤来做这个：

1.  创建一个新的 C++类。在这种情况下，您需要勾选“显示所有类”复选框并搜索找到`AIController`：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/8be786b7-f5e5-466a-90c5-b5bef7eb9eb5.png)

1.  将类命名为`MonsterAIController`。您的`MonsterAIController.h`应该如下所示：

```cpp
UCLASS()
class GOLDENEGG_API AMonsterAIController : public AAIController
{
    GENERATED_BODY()

public:
    //Start following the player
    void StartFollowingPlayer();
};
```

`MonsterAIController.cpp`应该实现以下函数：

```cpp
void AMonsterAIController::StartFollowingPlayer()
{
    AActor *player = Cast<AActor>(
        UGameplayStatics::GetPlayerPawn(GetWorld(), 0));
    FVector playerPos = player->GetActorLocation();
    MoveToLocation(playerPos);
}
```

还要确保在文件顶部添加`#include "Kismet/GameplayStatics.h"`。

1.  返回`Monster.cpp`中的`Tick()`函数。在`else`子句中找到以下行：

```cpp
AddMovementInput(toPlayer, Speed*DeltaSeconds);
```

删除这一行，用这个替换：

```cpp

        if (GetController() != nullptr)
        {
            Cast<AMonsterAIController>(GetController())-
            >StartFollowingPlayer();
        }
```

还在文件顶部添加`#include "MonsterAIController.h"`，并进入`BP_Monster`，将 Ai Controller 类更改为`MonsterAIController`。现在怪物可以绕过墙壁找到你。如果它们不动，检查确保`NavMesh`覆盖了该区域并且足够高以覆盖角色。

# 行为树

现在，控制怪物的所有逻辑都在`Monster.cpp`的`Tick()`函数中。但到目前为止，您所做的事情相当简单。在大型复杂的游戏中，怪物将有更多的行为。它们可以在一个区域巡逻，直到看到您，甚至与您交流，只有在对话不顺利时才会攻击。所有这些逻辑将变得过于复杂，无法将所有内容都放在一个函数中，甚至在`AMonster`类中。

幸运的是，UE4 还有另一种管理复杂任务的方法，那就是行为树。行为树让您可以直观地设置一系列任务，以便更容易管理。由于我们在这里专注于 C++，我们将以这种方式创建任务本身，但总体树似乎更容易在蓝图中管理。

行为树主要由两种不同类型的节点控制：

+   **选择器**：选择器将从左到右运行其子节点，直到一个成功，然后返回树。将其视为一个“或”语句——一旦找到一个真实的参数，该“或”本身就是真的，所以它完成了。

+   **序列**：序列会从左到右依次遍历子节点，直到有一个失败为止。这更像是一个“和”语句，会一直执行直到出现假的情况，使整个语句变为假。

因此，如果您想运行多个步骤，您将使用序列，而如果您只想成功运行一个并停止，您将使用选择器。

# 设置行为树

首先，您需要进入您的库（将其放在一个有意义的文件夹名称中，这样您将记得在哪里找到它，或者蓝图也可以工作），然后从“添加新内容”中选择“人工智能|行为树”：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/45cc7752-e2b6-4b38-932b-a2cbbc892b6a.png)

我将其命名为`MonsterBT`。您还需要创建一个黑板。这将存储您将在行为树中使用的数据，并允许您在 AI Controller 和行为树之间轻松传输。您可以通过转到“添加新内容”，然后选择“人工智能|黑板”来创建它。我将其命名为`MonsterBlackboard`：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/aed7c42b-29df-495d-9c15-63837eff7415.png)

# 设置黑板值

接下来，您需要在刚刚创建的黑板中设置值。您可以通过选择新键，然后选择类型（在这种情况下是 Bool）来完成此操作。对于此操作，我添加了两个，IsInAttackRange 和 IsInFollowRange：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/bd5fe05d-6f94-4222-a2f7-ebe86f1eefe7.png)

您还可以为每个添加一个描述其用途的描述。

# 设置 BTTask

我们将创建一个 C++任务来处理跟随玩家。要做到这一点，执行以下步骤：

1.  添加一个新的 C++类，并以 BTTaskNode 为基础（您需要查看所有类并搜索它）：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/fb9cd044-3520-4c1a-b69a-dbefc762d5e9.png)

我命名了新类`BTTask_FollowPlayer`

1.  在`BTTaskFollowPlayer.h`中，添加以下内容：

```cpp
UCLASS()
class GOLDENEGG_API UBTTask_FollowPlayer : public UBTTaskNode
{
    GENERATED_BODY()

    virtual EBTNodeResult::Type ExecuteTask(UBehaviorTreeComponent& OwnerComp, uint8* NodeMemory) override;
    virtual void OnGameplayTaskActivated(UGameplayTask& Task) override {}
};
```

我们不会使用`OnGameplayTaskActivated`，但是，如果没有声明它，你的代码可能无法编译（如果你收到关于它不存在的投诉，那就是原因）

1.  在`BTTaskFollowPlayer.cpp`中，添加以下内容：

```cpp
#include "BTTask_FollowPlayer.h"
#include "MonsterAIController.h"

EBTNodeResult::Type UBTTask_FollowPlayer::ExecuteTask(UBehaviorTreeComponent& OwnerComp, uint8* NodeMemory)
{
    AMonsterAIController* Controller = Cast<AMonsterAIController>(OwnerComp.GetAIOwner());
    if (Controller == nullptr)
    {
        return EBTNodeResult::Failed;
    }

    Controller->StartFollowingPlayer();

    return EBTNodeResult::Succeeded;
}
```

一旦你做到了这一点，你可以回去创建另一个`BTTask`来处理攻击，以及你可能想要的任何其他行为。

# 设置行为树本身

一旦你设置好了任务，就该设置树本身了：

1.  双击它以打开蓝图：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/4985b890-0951-4a29-b528-09c21619402f.png)

1.  点击 Root 底部的黄色区域并拖动以创建一个新的节点（它是黑色的，但当鼠标滚动到它上面时会变成黄色）。

1.  从弹出的菜单中选择类型（我们将使用选择器）：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/f26c5c77-9cbf-4f45-a37d-4cdfc6d342bb.png)

中心标签中的选择器图标

1.  你应该有以下内容：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/0e7d45c8-0303-4cd9-ac6a-6c502be69764.png)

如前所述，选择器将按从左到右的顺序遍历节点，直到一个成功为止，然后停止。在这种情况下，我们有三种可能的状态：在攻击范围内，在视野范围内，以及两者都不满足（忽略玩家）。首先，你需要检查自己是否足够接近进行攻击，这意味着你需要在你的黑板中检查 IsInAttackRange。

不要先进行跟随，因为攻击范围在技术上仍然在跟随范围内，但你不想使用跟随功能，所以选择器在检查跟随范围后就会停止，因为这是它进行的第一个检查，所以它永远不会检查攻击范围（这才是它真正应该检查的）。

要检查它需要处于哪种状态，你需要检查黑板值，这可以通过使用装饰器来实现。为此，点击选择器的底部并向左拖动一个新的节点，就像你创建那个节点时所做的那样，并选择一个复合选择器节点。这个节点允许你右键单击；选择添加装饰器...，确保你选择了黑板类型。添加后，你可以选择顶部的蓝色装饰器。你应该能够检查 Key Query IsSet 并选择你想要检查的值，这种情况下是 IsInAttackRange（如果它没有显示出来，请确保 MonsterBlackboard 在详细信息中设置为黑板；通常情况下应该自动设置）：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/b101c01b-ea3c-4dfc-8234-78df2ae18134.png)

攻击节点最终会转到一个攻击任务，但现在，我只是放了一个等待作为占位符（一个内置任务，允许你指定等待时间（以秒为单位））。

在它的右侧，你还需要添加另一个复合节点，带有一个检查 IsInFollowRange 的装饰器。这将使用你创建的新任务（如果它没有显示出来，请确保你已经编译了你的代码，并且没有任何错误）。

在那之后，我在事件中添加了一个等待任务，以防两种情况都失败。完成后，你应该有类似这样的东西：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/195cf009-e901-4bed-a965-f8228644e407.png)

现在你可以回去修改你现有的代码来使用所有这些。

# 更新 MonsterAIController

现在你将为你的`AIController`类添加更多功能来支持行为树：

1.  你的新`MonsterAIController.h`应该是这样的：

```cpp
UCLASS()
class GOLDENEGG_API AMonsterAIController : public AAIController
{
    GENERATED_BODY()

public:
    AMonsterAIController(const FObjectInitializer& ObjectInitializer);

    virtual void Possess(class APawn* InPawn) override;

    virtual void UnPossess() override;

    UBehaviorTreeComponent* BehaviorTreeCmp;

    UBlackboardComponent* BlackboardCmp;

    //Start following the player
    void StartFollowingPlayer();
    void SetFollowRange(bool val);
    void SetAttackRange(bool val);
};
```

还要确保在文件顶部添加`#include "BehaviorTree/BehaviorTreeComponent.h"`。在这里，你重写了构造函数以及`Possess`和`UnPossess`类。`SetFollowRange`和`SetAttackRange`函数是新的，让你设置黑板值。

1.  在`MonsterAIController.cpp`中添加以下函数：

```cpp
AMonsterAIController::AMonsterAIController(const class FObjectInitializer& ObjectInitializer)
    : Super(ObjectInitializer)
{
    BehaviorTreeCmp = ObjectInitializer.CreateDefaultSubobject<UBehaviorTreeComponent>(this, TEXT("MonsterBT"));
    BlackboardCmp = ObjectInitializer.CreateDefaultSubobject<UBlackboardComponent>(this, TEXT("MonsterBlackboard"));
}

void AMonsterAIController::Possess(class APawn* InPawn)
{
    Super::Possess(InPawn);

    AMonster* Monster = Cast<AMonster>(InPawn);
    if (Monster)
    {
        if (Monster->BehaviorTree->BlackboardAsset)
        {
            BlackboardCmp->InitializeBlackboard(*Monster->BehaviorTree->BlackboardAsset);
        }

        BehaviorTreeCmp->StartTree(*Monster->BehaviorTree);
    }
}

void AMonsterAIController::UnPossess()
{
    Super::UnPossess();

    BehaviorTreeCmp->StopTree();
}

void AMonsterAIController::SetFollowRange(bool val)
{
    BlackboardCmp->SetValueAsBool("IsInFollowRange", val);
}

void AMonsterAIController::SetAttackRange(bool val)
{
    BlackboardCmp->SetValueAsBool("IsInAttackRange", val);
}
```

还要在文件顶部添加以下行：

```cpp
#include "Monster.h"
#include "BehaviorTree/BehaviorTree.h"
#include "BehaviorTree/BlackboardComponent.h"
```

`StartFollowingPlayer`保持不变，所以这里不列出来，但确保你留下它！现在是时候更新你的`Monster`类了（在这之前你无法编译）。

# 更新 Monster 类

我们将在`Monster`类中进行以下更新：

+   在`Monster.h`中，您唯一要做的更改是添加以下代码行：

```cpp
    UPROPERTY(EditDefaultsOnly, Category = "AI")
        class UBehaviorTree* BehaviorTree;
```

+   在`Monster.cpp`中，您将对`Tick()`函数进行一些重大更改，因此这是完整版本：

```cpp
// Called every frame
void AMonster::Tick(float DeltaSeconds)
{
    Super::Tick(DeltaSeconds);

    // move the monster towards the player 
    AAvatar *avatar = Cast<AAvatar>(
        UGameplayStatics::GetPlayerPawn(GetWorld(), 0));
    if (!avatar) return;

    FVector playerPos = avatar->GetActorLocation();
    FVector toPlayer = playerPos - GetActorLocation();
    float distanceToPlayer = toPlayer.Size();
    AMonsterAIController* controller = Cast<AMonsterAIController>(GetController());

    // If the player is not the SightSphere of the monster, 
    // go back 
    if (distanceToPlayer > SightSphere->GetScaledSphereRadius())
    {
        // If the player is OS, then the enemy cannot chase 
        if (controller != nullptr)
        {
            controller->SetAttackRange(false);
            controller->SetFollowRange(false);
        }
        return;
    }

    toPlayer /= distanceToPlayer;  // normalizes the vector 

                                   // At least face the target 
                                   // Gets you the rotator to turn something 
                                   // that looks in the `toPlayer` direction 
    FRotator toPlayerRotation = toPlayer.Rotation();
    toPlayerRotation.Pitch = 0; // 0 off the pitch 
    RootComponent->SetWorldRotation(toPlayerRotation);

    if (isInAttackRange(distanceToPlayer))
    {
        if (controller != nullptr)
        {
            controller->SetAttackRange(true);
        }

        // Perform the attack 
        if (!TimeSinceLastStrike)
        {
            Attack(avatar);
        }

        TimeSinceLastStrike += DeltaSeconds;
        if (TimeSinceLastStrike > AttackTimeout)
        {
            TimeSinceLastStrike = 0;
        }

        return;  // nothing else to do 
    }
    else
    {
        // not in attack range, so walk towards player 
        //AddMovementInput(toPlayer, Speed*DeltaSeconds);

        if (controller != nullptr)
        {
            controller->SetAttackRange(false);
            controller->SetFollowRange(true);
        }
    }
}
```

更改是设置攻击和跟随范围的值。攻击代码仍然存在，但是如果将 TimeSinceLastStrike 和 AttackTimeout 移入黑板，您可以使用它将所有功能移入`BTTask`。现在确保一切都编译完成。

+   一旦编译完成，您需要打开`BP_Monster`蓝图，并设置行为树如下（如果您希望它们不同，也可以在单个怪物上设置）：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/c3c7768e-704d-47e1-a96d-31ae6e04bce5.png)

还要确保 AI 控制器设置为 MonsterAIController。如果此时运行游戏，功能应该是相同的，但是行为树将控制玩家的跟随。

如果您想了解更多，请查看将`Attack`代码移入`BTTask`类，并查看在您不在范围内时怪物可以做什么（阅读下一节可能有所帮助）。

# 环境查询系统

**环境查询系统**（**EQS**）是新的，仍在试验阶段。它允许您在行为树中创建一个查询，以搜索级别中的项目，并找到最符合您设置的条件的项目。也许您希望怪物在玩家超出范围时在设置的路径点之间徘徊，而不是站在原地。您可以设置一个查询来寻找最接近的路径点，或使用其他一些条件。EQS 允许您这样做。

您需要在设置中启用此功能才能使用它们。要执行此操作，请执行以下步骤：

1.  进入编辑|编辑器首选项：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/d6395ceb-67fc-4d78-84d0-f29c8e2ee2c5.png)

1.  在实验|AI 下，勾选环境查询系统：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/e30ed859-293d-4372-8471-864a91f53b5e.png)

1.  通过转到添加新|人工智能来添加新查询。环境查询现在将出现在行为树和黑板下：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/18186d59-76d5-4cf2-bf62-995a0863e37a.png)

您还需要在蓝图中创建`上下文`和`生成器`（`生成器`将获取特定类型的所有项目，例如路径点）。要实际运行查询，您需要在行为树中创建一个运行 EQS 查询任务节点。有关环境查询系统的工作原理的更多信息，请参阅[`docs.unrealengine.com/en-us/Engine/AI/EnvironmentQuerySystem`](https://docs.unrealengine.com/en-us/Engine/AI/EnvironmentQuerySystem)中的虚幻文档。

# 集群

如果屏幕上有很多怪物同时移动，您希望它们以看起来真实的方式移动。您不希望它们互相撞到，或者朝不同的方向走开。

AI 研究人员已经研究过这个问题，并提出了处理这个问题的算法。它们被称为集群算法，因为它们基于鸟群的行为。

在一起移动时，怪物不仅要考虑到达相同目标，还要考虑与其一起移动的怪物。他们必须确保不要离其周围的怪物太近，也不应该移动得太远，否则它们会分散开来。

在许多情况下，有一个怪物被选为领导者。该怪物朝着目标前进，其他怪物专注于跟随该领导者。

在线上有很多关于集群的好参考资料。它没有内置到 UE4 中，但您可以购买扩展或编写自己的集群系统。

# 机器学习和神经网络简介

机器学习和神经网络是一个巨大的话题，所以我在这里只会做一个简要介绍。机器学习是如何教导程序去找出如何回应某事情的方法，而不仅仅是给它规则。有许多不同的算法可以做到这一点，但它们都需要大量的样本数据。

基本上，你给学习程序大量的例子（越多越好），*和*每个案例的最佳结果。你可以用不同的方式对它们进行评价。通过观察这么多案例，它可以根据它过去看到的结果对类似案例做出最佳猜测。通过足够的训练数据，结果可以非常好，尽管你仍然可能遇到它不适用的情况。

由于这需要如此多的数据（更不用说处理能力），除了在罕见的情况下，这是在游戏公司在游戏发售前完成的（如果有的话——这种事情往往会因为截止日期而被取消）。训练是离线完成的，程序已经学会了该做什么。

神经网络是一种特定类型的机器学习，旨在模拟大脑处理数据的方式。有工作像神经元的节点。可以有多层节点，每一层处理前一层的结果。

数据被发送到多个节点，每个节点根据一定的阈值调整数据。只有数据可以被传递回（或向前）到节点，然后调整这些阈值以获得更准确的训练数据结果。一旦它们被训练过，这些阈值就可以用于未来的决策。

虽然我们离真正的人工智能还有很长的路要走，但神经网络已经被用于产生有趣的结果。神经网络已经在特定流派的音乐上进行了训练，然后生成了非常令人印象深刻（和原创的）音乐，听起来类似于它接受训练的流派。我也听说过神经网络被编写来尝试写书。不过我认为我们离一个可以编写 UE4 程序的神经网络还有很长的路要走！

# 遗传算法

回想一下你高中学的生物学；你可能学过遗传学。来自两个不同父母的染色体结合在一起，创造一个结合了两个父母 DNA 的孩子，而随机的基因突变也可以引起变化。遗传算法基于相同的原则。

就像达尔文的适者生存一样，你可以在代码中做类似的事情。遗传算法有三个基本原则：

+   **选择**: 你选择那些有最佳结果的例子，它们是下一代的基础。

+   **交叉**: 选择的两个例子然后结合在一起，创造一个同时具有两者特点的孩子，就像在生物学中一样。

+   **引入随机基因突变**: 可能有一些好的特征是旧的没有的，或者被其他特征淹没了而被抛弃。这意味着你不会错过一些潜在的优秀特征，只是因为它们不在原始种群中。

# 总结

正如你所看到的，人工智能是一个巨大的话题，我们在这里只是触及了基础知识。我们已经了解了基础的寻路（使用 NavMesh）、行为树、环境查询系统、群集、机器学习和神经网络以及遗传算法。如果你想了解更多，还有整整一本书，以及许多网站，比如[`aigamedev.com/`](http://aigamedev.com/)，和[`www.gamasutra.com`](https://www.gamasutra.com)上的文章。

在下一节中，我们将学习施展咒语来保护你的玩家免受怪物的侵害。


# 第十三章：法术书

玩家目前还没有自卫手段。我们现在将为玩家配备一种非常有用和有趣的方式，称为魔法法术。玩家将使用魔法法术来影响附近的怪物，因此现在可以对它们造成伤害。

我们将从描述如何创建自己的粒子系统开始本章。然后，我们将把粒子发射器包装到一个`Spell`类中，并为角色编写一个`CastSpell`函数，以便实际`CastSpells`。

本章将涵盖以下主题：

+   什么是法术？

+   粒子系统

+   法术类角色

+   将右键单击附加到`CastSpell`

+   创建其他法术

# 什么是法术？

实际上，法术将是粒子系统与由边界体积表示的影响区域的组合。每一帧都会检查边界体积中包含的角色。当一个角色在法术的边界体积内时，那么该角色就会受到该法术的影响。

以下是暴风雪法术的截图，其中突出显示了边界体积：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/d502f3b7-aa44-4c5a-a35c-e7b0580c894d.png)

暴风雪法术有一个长方形的边界体积。在每一帧中，都会检查边界体积中包含的角色。法术边界体积中包含的任何角色在该帧中都将受到该法术的影响。如果角色移出法术的边界体积，那么该角色将不再受到该法术的影响。请记住，法术的粒子系统仅用于可视化；粒子本身不会影响游戏角色。

我们在第八章中创建的`PickupItem`类，*角色和卫兵*，可用于允许玩家拾取代表法术的物品。我们将扩展`PickupItem`类，并附加一个法术的蓝图以施放每个`PickupItem`。从 HUD 中点击法术的小部件将施放它。界面将看起来像这样：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/9ac617a8-92ec-4798-b090-495b3fcb6524.png)

# 设置粒子系统

首先，我们需要一个放置所有华丽特效的地方。为此，我们将按照以下步骤进行：

1.  在您的内容浏览器选项卡中，右键单击内容根目录，创建一个名为`ParticleSystems`的新文件夹。

1.  右键单击该新文件夹，然后选择 New Asset | Particle System，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/8dda3c34-0393-4b68-b568-3a3b14626a26.png)

查看此虚幻引擎 4 粒子系统指南，了解虚幻粒子发射器的工作原理：[`www.youtube.com/watch?v=OXK2Xbd7D9w&amp;index=1&amp;list=PLZlv_N0_O1gYDLyB3LVfjYIcbBe8NqR8t`](https://www.youtube.com/watch?v=OXK2Xbd7D9w&index=1&list=PLZlv_N0_O1gYDLyB3LVfjYIcbBe8NqR8t)。

1.  双击出现的 NewParticleSystem 图标，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/17c681be-20b8-4b94-8296-407dd2f2fda4.png)

完成上述步骤后，您将进入 Cascade，粒子编辑器。环境如下截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/173d7371-cbb2-419b-8ed1-863f44e04ebb.png)

这里有几个不同的窗格，每个窗格显示不同的信息。它们如下： 

+   左上角是视口窗格。这显示了当前发射器的动画，因为它当前正在工作。

+   右侧是`Emitters`面板。在其中，您可以看到一个名为 Particle Emitter 的单个对象（您的粒子系统中可以有多个发射器，但我们现在不需要）。粒子发射器的模块列表显示在其下。从前面的截图中，我们有`Required`、`Spawn`、`Lifetime`、`Initial Size`、`Initial Velocity`和`Color Over Life`模块。

# 更改粒子属性

默认粒子发射器会发射类似十字准星的形状。我们想要将其更改为更有趣的东西。要做到这一点，请按照以下步骤进行：

1.  单击`Emitters`面板下的黄色`Required`框，然后在`Details`面板中打开`Material`下拉菜单。

将弹出所有可用的粒子材料列表（您可以在顶部输入`particles`以便更容易找到您想要的材料）。

1.  选择 m_flare_01 选项来创建我们的第一个粒子系统，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/ac976fd3-6e9a-4358-8b5a-142353c6dba7.png)

1.  现在，让我们更改粒子系统的行为。单击发射器窗格下的 Color Over Life 条目。底部的详细信息窗格显示了不同参数的信息，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/4c64ae04-cd1d-4801-a952-deee7b5ae84d.png)

1.  在 Color Over Life 条目的详细信息窗格中，我增加了 R，但没有增加 G 和 B。这给了粒子系统一种红色的发光效果。（R 是红色，G 是绿色，B 是蓝色）。您可以在条上看到颜色。

然而，您可以通过更直观地更改粒子颜色来编辑原始数字。如果您点击发射器下的 Color Over Life 条目旁边的绿色锯齿按钮，您将看到 Color Over Life 的图表显示在曲线编辑器选项卡中，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/cf931d8b-84fa-44fb-80fa-e72bc65ea783.png)

现在我们可以更改颜色随生命周期变化的参数。在曲线编辑器选项卡中的图表显示了发射的颜色与粒子存活时间的关系。您可以通过拖动点来调整数值。按住*Ctrl*键+鼠标左键可以在线条上添加新的点（如果不起作用，请点击黄色框取消选择 AlphaOverLife，确保只选择 ColorOverLife）：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/6c416672-9b92-4de2-b9ef-882ea4895335.png)

您可以调整粒子发射器设置，创建自己的法术可视化效果。

# 暴风雪法术的设置

此时，我们应该将粒子系统从 NewParticleSystem 重命名为更具描述性的名称。让我们将其重命名为`P_Blizzard`。

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/422079ca-06d0-49ff-b57f-59b93b200da7.png)

您可以通过单击粒子系统并按下*F2 来重命名您的粒子系统，如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/adcfef39-8761-4855-be26-c1884276844b.png)

我们将调整一些设置，以获得暴风雪粒子效果法术。执行以下步骤：

1.  返回 P_Blizzard 粒子系统进行编辑。

1.  在 Spawn 模块下，将生成速率更改为`200.0`。这会增加可视化效果的密度，如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/d29f563b-55a5-4525-8a58-bad64b23d627.png)

1.  在 Lifetime 模块下，将 Max 属性从`1.0`增加到`2.0`，如下截图所示。这会使发射的粒子的存活时间产生一些变化，一些发射的粒子的存活时间会比其他的长：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/3fa2b655-864f-4888-b124-d7d2bebba71b.png)

1.  在 Initial Size 模块下，将 Min 属性大小更改为`12.5`，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/67d82c41-cf10-43b4-b50f-1e7931a51416.png)

1.  在 Initial Velocity 模块下，将 Min / Max 值更改为以下数值：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/5b14c94b-a895-4f16-a7c6-f1e890175a0f.png)

1.  我们之所以让暴风雪向+X 方向吹，是因为玩家的前进方向从+X 开始。由于法术将来自玩家的手，我们希望法术指向与玩家相同的方向。

1.  在 Color Over Life 菜单下，将蓝色（B）值更改为`100.0`。同时将 R 更改回`1.0`。您会立即看到蓝色发光的变化：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/278ad147-cb00-4705-890f-4c0866c07900.png)

现在它开始看起来有点神奇了！

1.  右键单击 Color Over Life 模块下方的黑色区域。选择 Location | Initial Location，如截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/bcf639ba-60da-462f-b93c-b2bb17afbeeb.png)

1.  按照以下截图所示，在 Start Location | Distribution 下输入数值：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/be1b38a4-0f7d-436f-8ca9-39f1822e792d.png)

1.  您应该看到一个如此的暴风雪：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/3b25a958-cb24-40c4-b82b-98475a219166.png)

1.  将相机移动到你喜欢的位置，然后点击顶部菜单栏中的缩略图选项。这将在内容浏览器选项卡中为你的粒子系统生成一个缩略图图标，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/a422433a-ec14-4068-af06-32445aa0ad80.png)

# 法术类角色

`Spell`类最终会对所有怪物造成伤害。为此，我们需要在`Spell`类角色中包含粒子系统和边界框。当角色施放`Spell`类时，`Spell`对象将被实例化到关卡中并开始`Tick()`功能。在`Spell`对象的每个`Tick()`上，任何包含在法术边界体积内的怪物都将受到影响。

`Spell`类应该看起来像以下代码：

```cpp
#include "CoreMinimal.h"
#include "GameFramework/Actor.h"
#include "Components/BoxComponent.h"
#include "Runtime/Engine/Classes/Particles/ParticleSystemComponent.h"
#include "Spell.generated.h"

UCLASS()
class GOLDENEGG_API ASpell : public AActor
{
    GENERATED_BODY()

public:    
    ASpell(const FObjectInitializer&amp; ObjectInitializer);

    // box defining volume of damage 
    UPROPERTY(VisibleDefaultsOnly, BlueprintReadOnly, Category =
        Spell)
        UBoxComponent* ProxBox;

    // the particle visualization of the spell 
    UPROPERTY(VisibleDefaultsOnly, BlueprintReadOnly, Category =
        Spell)
        UParticleSystemComponent* Particles;

    // How much damage the spell does per second 
    UPROPERTY(EditAnywhere, BlueprintReadWrite, Category = Spell)
        float DamagePerSecond;

    // How long the spell lasts 
    UPROPERTY(EditAnywhere, BlueprintReadWrite, Category = Spell)
        float Duration;

    // Length of time the spell has been alive in the level 
    float TimeAlive;

    // The original caster of the spell (so player doesn't 
    // hit self) 
    AActor* Caster;

    // Parents this spell to a caster actor 
    void SetCaster(AActor* caster);

    // Runs each frame. override the Tick function to deal damage  
    // to anything in ProxBox each frame. 
    virtual void Tick(float DeltaSeconds) override;
};
```

我们只需要担心实现三个函数，即`ASpell::ASpell()`构造函数，`ASpell::SetCaster()`函数和`ASpell::Tick()`函数。

打开`Spell.cpp`文件。在`Spell.h`的包含行下面，添加一行包括`Monster.h`文件的代码，这样我们就可以在`Spell.cpp`文件中访问`Monster`对象的定义（以及其他一些包括），如下代码所示：

```cpp
#include "Monster.h" 
#include "Kismet/GameplayStatics.h"
#include "Components/CapsuleComponent.h"
```

首先是构造函数，它设置了法术并初始化了所有组件，如下代码所示：

```cpp
ASpell::ASpell(const FObjectInitializer&amp; ObjectInitializer)
 : Super(ObjectInitializer)
{
 ProxBox = ObjectInitializer.CreateDefaultSubobject<UBoxComponent>(this,
 TEXT("ProxBox")); 
 Particles = ObjectInitializer.CreateDefaultSubobject<UParticleSystemComponent>(this,
 TEXT("ParticleSystem"));

 // The Particles are the root component, and the ProxBox 
 // is a child of the Particle system. 
 // If it were the other way around, scaling the ProxBox 
 // would also scale the Particles, which we don't want 
 RootComponent = Particles;
 ProxBox->AttachToComponent(RootComponent, FAttachmentTransformRules::KeepWorldTransform);

 Duration = 3;
 DamagePerSecond = 1;
 TimeAlive = 0;

 PrimaryActorTick.bCanEverTick = true;//required for spells to 
 // tick! 
}
```

特别重要的是这里的最后一行，`PrimaryActorTick.bCanEverTick = true`。如果你不设置它，你的`Spell`对象将永远不会调用`Tick()`。

接下来，我们有`SetCaster()`方法。这是为了让`Spell`对象知道施法者是谁。我们可以通过以下代码确保施法者不能用自己的法术伤害自己：

```cpp
void ASpell::SetCaster(AActor *caster)
{
 Caster = caster;
 RootComponent->AttachToComponent(caster->GetRootComponent(), FAttachmentTransformRules::KeepRelativeTransform);
}
```

最后，我们有`ASpell::Tick()`方法，它实际上对所有包含的角色造成伤害，如下面的代码所示：

```cpp
void ASpell::Tick(float DeltaSeconds)
{
    Super::Tick(DeltaSeconds);

    // search the proxbox for all actors in the volume. 
    TArray<AActor*> actors;
    ProxBox->GetOverlappingActors(actors);

    // damage each actor the box overlaps 
    for (int c = 0; c < actors.Num(); c++)
    {
        // don't damage the spell caster 
        if (actors[c] != Caster)
        {
            // Only apply the damage if the box is overlapping 
            // the actors ROOT component. 
            // This way damage doesn't get applied for simply  
            // overlapping the SightSphere of a monster 
            AMonster *monster = Cast<AMonster>(actors[c]);

            if (monster &amp;&amp; ProxBox->IsOverlappingComponent(Cast<UPrimitiveComponent>(monster->GetCapsuleComponent())))
            {
                monster->TakeDamage(DamagePerSecond*DeltaSeconds,
                    FDamageEvent(), 0, this);
            }

            // to damage other class types, try a checked cast  
            // here.. 
        }
    }

    TimeAlive += DeltaSeconds;
    if (TimeAlive > Duration)
    {
        Destroy();
    }
}
```

`ASpell::Tick()`函数会执行一些操作，如下所示：

+   它获取所有与`ProxBox`重叠的角色。如果组件重叠的不是施法者的根组件，那么任何角色都会受到伤害。我们必须检查与根组件的重叠，因为如果不这样做，法术可能会与怪物的`SightSphere`重叠，这意味着我们会受到很远处的攻击，这是我们不想要的。

+   请注意，如果我们有另一个应该受到伤害的东西类，我们将不得不尝试对每种对象类型进行转换。每种类别可能具有不同类型的边界体积应该进行碰撞；其他类型甚至可能没有`CapsuleComponent`（它们可能有`ProxBox`或`ProxSphere`）。

+   它增加了法术存在的时间。如果法术超过了分配的施法时间，它将从关卡中移除。

现在，让我们专注于玩家如何获得法术，通过为玩家可以拾取的每个法术对象创建一个单独的`PickupItem`。

# 蓝图化我们的法术

编译并运行刚刚添加的`Spell`类的 C++项目。我们需要为我们想要施放的每个法术创建蓝图。要做到这一点，请按照以下步骤进行：

1.  在 Class Viewer 选项卡中，开始输入`Spell`，你应该看到你的 Spell 类出现

1.  右键单击 Spell，创建一个名为 BP_Spell_Blizzard 的蓝图，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/d2c44941-90e5-47c0-bad6-063fd84cab08.png)

1.  如果它没有自动打开，请双击打开它。

1.  在法术的属性中，选择 P_Blizzard 法术作为粒子发射器，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/f1ce427a-570e-4bc1-98b5-2ee9c87c8efa.png)

如果找不到它，请尝试在组件下选择 Particles (Inherited)。

选择 BP_SpellBlizzard(self)，向下滚动直到到达法术类别，并更新每秒伤害和持续时间参数为你喜欢的值，如下截图所示。在这里，暴风雪法术将持续`3.0`秒，每秒造成`16.0`点伤害。三秒后，暴风雪将消失：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/592a8226-92ac-4099-a193-662622fa24c8.png)

在配置了默认属性之后，切换到组件选项卡进行一些进一步的修改。点击并改变`ProxBox`的形状，使其形状合理。盒子应该包裹粒子系统最强烈的部分，但不要过分扩大其大小。`ProxBox`对象不应该太大，因为那样你的暴风雪法术会影响到甚至没有被暴风雪触及的东西。如下截图所示，一些离群值是可以接受的：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/cbf2312a-6a5d-4de4-8ac3-ead61614357c.png)

你的暴风雪法术现在已经制作成蓝图，并准备好供玩家使用。

# 捡起法术

回想一下，我们之前编程使我们的库存在用户按下*I*时显示玩家拥有的捡起物品的数量。然而，我们想做的不仅仅是这样：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/0d443ba0-5008-4ed8-a000-1cfbb0a04eae.png)

用户按下 I 时显示的物品

为了让玩家捡起法术，我们将修改`PickupItem`类，包括一个用以下代码使用的法术蓝图的槽：

```cpp
// inside class APickupItem: 
// If this item casts a spell when used, set it here 
UPROPERTY(EditAnywhere, BlueprintReadWrite, Category = Item) 
UClass* Spell;
```

一旦你为`APickupItem`类添加了`UClass* Spell`属性，重新编译并重新运行你的 C++项目。现在，你可以继续为你的`Spell`对象制作`PickupItem`实例的蓝图。

# 创建施放法术的 PickupItems 的蓝图

创建一个名为 BP_Pickup_Spell_Blizzard 的 PickupItem 蓝图，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/c858650a-7e6b-496c-9855-2027dc4dd31f.png)

它应该自动打开，这样你就可以编辑它的属性。我将暴风雪物品的捡起属性设置如下：

物品的名称是暴风雪法术，每个包装中有`5`个。我拍摄了暴风雪粒子系统的截图，并将其导入到项目中，因此图标被选为该图像。在法术下，我选择了 BP_Spell_Blizzard 作为要施放的法术的名称（而不是 BP_Pickup_Spell_Blizzard），如下截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/0ef88141-1364-4dea-9d2c-904abd726f13.png)

我为`PickupItem`类的`Mesh`类选择了一个蓝色的球（你也可以使用 M_Water_Lake 材质来获得有趣的效果）。对于图标，我在粒子查看器预览中拍摄了暴风雪法术的截图，保存到磁盘，并将该图像导入到项目中，如下截图所示（在示例项目的内容浏览器选项卡中查看`images`文件夹）：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/612d25a5-142b-45fb-ba60-f7cbfd0f501f.png)

在你的关卡中放置一些`PickupItem`。如果我们捡起它们，我们的库存中将有一些暴风雪法术（如果你捡不起来，请确保你的 ProxSphere 足够大）：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/badddff5-2324-4dc4-9320-1957be5bf452.png)

现在，我们需要激活暴风雪。由于我们已经在第十章中将左键单击附加到拖动图标的*库存系统和捡起物品*，让我们将右键单击附加到施放法术。

# 将右键单击附加到 CastSpell

在调用角色的`CastSpell`方法之前，右键单击将经过多次函数调用。调用图看起来会像下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/3946b2e1-8cbb-40fe-b7aa-556f61174f31.png)

在右键单击和施法之间会发生一些事情。它们如下：

+   正如我们之前看到的，所有用户鼠标和键盘交互都通过`Avatar`对象路由。当`Avatar`对象检测到右键单击时，它将通过`AAvatar::MouseRightClicked()`将点击事件传递给`HUD`。

+   在第十章中，*库存系统和拾取物品*，我们使用了一个`struct Widget`类来跟踪玩家拾取的物品。`struct Widget`只有三个成员：

```cpp
struct Widget 
{ 
  Icon icon; 
  FVector2D pos, size; 
  ///.. and some member functions 
}; 
```

+   现在，我们需要为`struct Widget`类添加一个额外的属性来记住它施放的法术。

+   `HUD`将确定点击事件是否在`AMyHUD::MouseRightClicked()`中的`Widget`内。

+   如果点击的是施放法术的`Widget`，则`HUD`将通过调用`AAvatar::CastSpell()`向 avatar 发出施放该法术的请求。

# 编写 avatar 的 CastSpell 函数

我们将以相反的方式实现前面的调用图。我们将首先编写实际在游戏中施放法术的函数`AAvatar::CastSpell()`，如下面的代码所示：

```cpp
void AAvatar::CastSpell( UClass* bpSpell ) 
{ 
  // instantiate the spell and attach to character 
  ASpell *spell = GetWorld()->SpawnActor<ASpell>(bpSpell,  
   FVector(0), FRotator(0) ); 

  if( spell ) 
  { 
    spell->SetCaster( this ); 
  } 
  else 
  { 
    GEngine->AddOnScreenDebugMessage( 1, 5.f, FColor::Yellow,  
    FString("can't cast ") + bpSpell->GetName() ); } 
} 
```

还要确保将该函数添加到`Avatar.h`中，并在该文件的顶部添加`#include "Spell.h"`。

您可能会发现实际施放法术非常简单。施放法术有两个基本步骤：

1.  使用世界对象的`SpawnActor`函数实例化法术对象

1.  将其附加到 avatar

一旦`Spell`对象被实例化，当该法术在关卡中时，它的`Tick()`函数将在每一帧运行。在每个`Tick()`上，`Spell`对象将自动感知关卡中的怪物并对它们造成伤害。每个先前提到的代码行都会发生很多事情，因此让我们分别讨论每一行。

# 实例化法术- GetWorld()->SpawnActor()

从蓝图创建`Spell`对象，我们需要从`World`对象调用`SpawnActor()`函数。`SpawnActor()`函数可以使用任何蓝图在关卡中实例化它。幸运的是，`Avatar`对象（实际上任何`Actor`对象）可以随时通过简单调用`GetWorld()`成员函数获得`World`对象的句柄。

将`Spell`对象带入关卡的代码行如下：

```cpp
ASpell *spell = GetWorld()->SpawnActor<ASpell>( bpSpell,  
   FVector(0), FRotator(0) );
```

关于上述代码行有几件事情需要注意：

+   `bpSpell`必须是要创建的`Spell`对象的蓝图。尖括号中的`<ASpell>`对象表示期望。

+   新的`Spell`对象从原点(`0`, `0`, `0`)开始，并且没有应用额外的旋转。这是因为我们将`Spell`对象附加到`Avatar`对象，后者将为`Spell`对象提供平移和方向组件。

# if(spell)

我们始终通过检查`if( spell )`来测试对`SpawnActor<ASpell>()`的调用是否成功。如果传递给`CastSpell`对象的蓝图实际上不是基于`ASpell`类的蓝图，则`SpawnActor()`函数返回一个`NULL`指针而不是`Spell`对象。如果发生这种情况，我们会在屏幕上打印错误消息，指示在施放法术期间出现了问题。

# spell->SetCaster(this)

在实例化时，如果法术成功，则通过调用`spell->SetCaster( this )`将法术附加到`Avatar`对象。请记住，在`Avatar`类内编程的上下文中，`this`方法是对`Avatar`对象的引用。

那么，我们如何实际将 UI 输入的法术施放连接到首先调用`AAvatar::CastSpell()`函数呢？我们需要再次进行一些`HUD`编程。

# 编写 AMyHUD::MouseRightClicked()

法术施放命令最终将来自 HUD。我们需要编写一个 C++函数，遍历所有 HUD 小部件，并测试点击是否在其中任何一个上。如果点击在`widget`对象上，则该`widget`对象应该通过施放其法术来做出响应，如果它有一个已分配的话。

我们必须扩展我们的`Widget`对象以具有保存要施放的法术蓝图的变量。使用以下代码向您的`struct Widget`对象添加成员：

```cpp
struct Widget
{
    Icon icon;
    // bpSpell is the blueprint of the spell this widget casts 
    UClass *bpSpell;
    FVector2D pos, size;
    //...
};
```

现在回想一下，我们的`PickupItem`之前附有其施放的法术的蓝图。但是，当玩家从级别中拾取`PickupItem`类时，然后`PickupItem`类被销毁，如下面的代码所示：

```cpp
// From APickupItem::Prox_Implementation(): 
avatar->Pickup( this ); // give this item to the avatar 
// delete the pickup item from the level once it is picked up 
Destroy(); 
```

因此，我们需要保留每个`PickupItem`施放的法术的信息。当首次拾取`PickupItem`时，我们可以这样做。

在`AAvatar`类中，通过以下代码添加额外的映射来记住物品施放的法术的蓝图，按物品名称：

```cpp
// Put this in Avatar.h 
TMap<FString, UClass*> Spells; 
```

现在，在`AAvatar::Pickup()`中，使用以下代码记住`PickupItem`类实例化的法术类：

```cpp
// the spell associated with the item 
Spells.Add(item->Name, item->Spell); 
```

现在，在`AAvatar::ToggleInventory()`中，我们可以在屏幕上显示的`Widget`对象。通过查找`Spells`映射来记住它应该施放的法术。

找到我们创建小部件的行，并修改它以添加`Widget`施放的`bpSpell`对象的赋值，如下面的代码所示：

```cpp
// In AAvatar::ToggleInventory() 
Widget w(Icon(fs, tex));
w.bpSpell = Spells[it->Key];
hud->addWidget(w);
```

将以下函数添加到`AMyHUD`，每当在图标上单击鼠标右键时，我们将其设置为运行：

```cpp
void AMyHUD::MouseRightClicked()
{
    FVector2D mouse;
    APlayerController *PController = GetWorld()->GetFirstPlayerController();
    PController->GetMousePosition(mouse.X, mouse.Y);
    for (int c = 0; c < widgets.Num(); c++)
    {
        if (widgets[c].hit(mouse))
        {
            AAvatar *avatar = Cast<AAvatar>(
                UGameplayStatics::GetPlayerPawn(GetWorld(), 0));
            if (widgets[c].bpSpell)
                avatar->CastSpell(widgets[c].bpSpell);
        }
    }
}
```

这与我们的左键单击功能非常相似。我们只需检查点击位置是否与所有小部件相交。如果任何`Widget`被鼠标右键点击，并且该`Widget`与`Spell`对象相关联，则将通过调用角色的`CastSpell()`方法施放法术。

# 激活鼠标右键点击

要使此 HUD 功能运行，我们需要将事件处理程序附加到鼠标右键点击。我们可以通过执行以下步骤来实现：

1.  转到设置 | 项目设置；对话框弹出

1.  在引擎 - 输入下，添加一个右键鼠标按钮的操作映射，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/222a2cf3-be13-4d8d-a73c-df854a0550b4.png)

1.  在`Avatar.h`/`Avatar.cpp`中声明一个名为`MouseRightClicked()`的函数，使用以下代码：

```cpp
void AAvatar::MouseRightClicked() 
{ 
  if( inventoryShowing ) 
  { 
    APlayerController* PController = GetWorld()- 
     >GetFirstPlayerController(); 
    AMyHUD* hud = Cast<AMyHUD>( PController->GetHUD() ); 
    hud->MouseRightClicked(); 
  } 
}
```

1.  然后，在`AAvatar::SetupPlayerInputComponent()`中，我们应该将`MouseClickedRMB`事件附加到`MouseRightClicked()`函数：

```cpp
// In AAvatar::SetupPlayerInputComponent(): 
PlayerInputComponent->BindAction("MouseClickedRMB", IE_Pressed, this,
        &amp;AAvatar::MouseRightClicked);
```

我们终于连接了施法。试一试；游戏玩起来非常酷，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/28b4e241-832c-405a-85d7-b66336ffac8d.png)

# 创建其他法术

通过玩弄粒子系统，您可以创建各种不同的法术，产生不同的效果。您可以创建火焰、闪电或将敌人推开的法术。在玩其他游戏时，您可能已经遇到了许多其他可能的法术。

# 火焰法术

通过将粒子系统的颜色更改为红色，您可以轻松创建我们暴风雪法术的火焰变体。这是我们暴风雪法术的火焰变体的外观：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/1b86ad1b-7a5e-4675-b4b1-233d26ed5059.png)

颜色的输出值更改为红色

# 练习

尝试以下练习：

+   **闪电法术**：使用光束粒子创建闪电法术。按照 Zak 的教程示例，了解如何创建光束并朝一个方向发射，网址为[`www.youtube.com/watch?v=ywd3lFOuMV8&amp;list=PLZlv_N0_O1gYDLyB3LVfjYIcbBe8NqR8t&amp;index=7`](https://www.youtube.com/watch?v=ywd3lFOuMV8&list=PLZlv_N0_O1gYDLyB3LVfjYIcbBe8NqR8t&index=7)。

+   **力场法术**：力场将使攻击偏转。对于任何玩家来说都是必不可少的。建议实现：派生`ASpell`的子类称为`ASpellForceField`。向该类添加一个边界球，并在`ASpellForceField::Tick()`函数中使用它将怪物推出。

# 摘要

现在您知道如何在游戏中创建防御法术。我们使用粒子系统创建了可见的法术效果，并且可以用来对任何在其中的敌人造成伤害的区域。您可以扩展所学知识以创建更多内容。

在下一章中，我们将探讨一种更新且更容易的构建用户界面的方法。
