# 通过使用 Unreal4 构建游戏学习 C++（三）

> 原文：[`annas-archive.org/md5/1c4190d0f9858df324374dcae7b4dd27`](https://annas-archive.org/md5/1c4190d0f9858df324374dcae7b4dd27)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第八章：演员和兵

现在，我们将真正深入 UE4 代码。起初，它看起来会让人望而生畏。UE4 类框架非常庞大，但不用担心：框架很大，所以你的代码不必如此。你会发现，你可以用更少的代码完成更多的工作并将更多内容显示在屏幕上。这是因为 UE4 引擎代码如此广泛和精心编写，以至于他们使得几乎任何与游戏相关的任务都变得容易。只需调用正确的函数，你想要看到的东西就会出现在屏幕上。整个框架的概念是设计让你获得想要的游戏体验，而不必花费大量时间来处理细节。

本章的学习成果如下：

+   演员与兵

+   创建一个放置演员的世界

+   UE4 编辑器

+   从头开始

+   向场景添加一个演员

+   创建一个玩家实体

+   编写控制游戏角色的 C++代码

+   创建非玩家角色实体

+   显示每个 NPC 对话框中的引用

# 演员与兵

在本章中，我们将讨论演员和兵。虽然听起来兵会比演员更基本，但实际情况恰恰相反。UE4 演员（`Actor`类）对象是可以放置在 UE4 游戏世界中的基本类型。为了在 UE4 世界中放置任何东西，你必须从`Actor`类派生。

兵是一个代表你或计算机的**人工智能**（**AI**）可以在屏幕上控制的对象。`Pawn`类派生自`Actor`类，具有直接由玩家或 AI 脚本控制的额外能力。当一个兵或演员被控制器或 AI 控制时，就说它被该控制器或 AI 所控制。

把`Actor`类想象成一个戏剧中的角色（尽管它也可以是戏剧中的道具）。你的游戏世界将由一堆*演员*组成，它们一起行动以使游戏运行。游戏角色、**非玩家角色**（**NPC**）甚至宝箱都将是演员。

# 创建一个放置演员的世界

在这里，我们将从头开始创建一个基本的关卡，然后把我们的游戏角色放进去。UE4 团队已经很好地展示了世界编辑器如何用于创建 UE4 中的世界。我希望你花点时间按照以下步骤创建自己的世界：

1.  创建一个新的空白 UE4 项目以开始。要做到这一点，在虚幻启动器中，点击最近的引擎安装旁边的启动按钮，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/3d0f9dc1-a80e-4e54-9c15-0c8881dad25a.png)

这将启动虚幻编辑器。虚幻编辑器用于可视化编辑你的游戏世界。你将花费大量时间在虚幻编辑器中，所以请花些时间进行实验和尝试。

我只会介绍如何使用 UE4 编辑器的基础知识。然而，你需要让你的创造力流淌，并投入一些时间来熟悉编辑器。

要了解更多关于 UE4 编辑器的信息，请查看*入门：UE4 编辑器简介*播放列表，网址为[`www.youtube.com/playlist?list=PLZlv_N0_O1gasd4IcOe9Cx9wHoBB7rxFl`](https://www.youtube.com/playlist?list=PLZlv_N0_O1gasd4IcOe9Cx9wHoBB7rxFl)。

1.  你将看到项目对话框。以下截图显示了需要执行的步骤，数字对应着需要执行的顺序：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/a610e410-863d-4628-888b-504b78722746.png)

1.  执行以下步骤创建一个项目：

1.  在屏幕顶部选择新项目标签。

1.  点击 C++标签（第二个子标签）。

1.  从可用项目列表中选择基本代码。

1.  设置项目所在的目录（我的是 Y:Unreal Projects）。选择一个有很多空间的硬盘位置（最终项目大小约为 1.5GB）。

1.  命名您的项目。我把我的称为 GoldenEgg。

1.  单击“创建项目”以完成项目创建。

完成此操作后，UE4 启动器将启动 Visual Studio（或 Xcode）。这可能需要一段时间，进度条可能会出现在其他窗口后面。只有几个源文件可用，但我们现在不会去碰它们。

1.  确保从屏幕顶部的配置管理器下拉菜单中选择“开发编辑器”，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/6107dc53-907d-420b-bfdb-9b37e848dcdf.png)

如下截图所示，虚幻编辑器也已启动：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/0c5ccf1d-cd4b-4fb6-8595-b3376e98bdab.png)

# UE4 编辑器

我们将在这里探索 UE4 编辑器。我们将从控件开始，因为了解如何在虚幻中导航很重要。

# 编辑器控件

如果您以前从未使用过 3D 编辑器，那么在编辑模式下，控件可能会很难学习。这些是在编辑模式下的基本导航控件：

+   使用箭头键在场景中移动

+   按*Page Up*或*Page Down*垂直上下移动

+   左键单击+向左或向右拖动以更改您所面对的方向

+   左键单击+向上或向下拖动以*移动*（将相机向前或向后移动，与按上/下箭头键相同）

+   右键单击+拖动以更改您所面对的方向

+   中键单击+拖动以平移视图

+   右键单击和*W*、*A*、*S*和*D*键用于在场景中移动

# 播放模式控制

单击顶部工具栏中的播放按钮，如下截图所示。这将启动播放模式：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/9110d2aa-8a04-46d7-b1b4-f6520d6fdf75.png)

单击“播放”按钮后，控件会改变。在播放模式下，控件如下：

+   *W*、*A*、*S*和*D*键用于移动

+   使用左右箭头键分别向左或向右查看

+   鼠标的移动以改变您所看的方向

+   按*Esc*键退出播放模式并返回编辑模式

在这一点上，我建议您尝试向场景中添加一堆形状和对象，并尝试用不同的*材料*着色它们。

# 向场景添加对象

向场景添加对象就像从内容浏览器选项卡中拖放它们一样简单，如下所示：

1.  内容浏览器选项卡默认情况下停靠在窗口底部。如果看不到它，只需选择“窗口”，然后导航到“内容浏览器”即可使其出现：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/807f76e7-3dcc-47e5-8257-83ad5a5ef5e2.png)

确保内容浏览器可见，以便向您的级别添加对象

1.  双击`StarterContent`文件夹以打开它。

1.  双击“道具”文件夹以查找可以拖放到场景中的对象。

1.  从内容浏览器中拖放物品到游戏世界中：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/836a4d4e-0f9a-4ba5-99cf-4934c60f92ed.png)

1.  要调整对象的大小，请在键盘上按*R*（再次按*W*移动它，或按*E*旋转对象）。对象周围的操作器将显示为方框，表示调整大小模式：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/a2034959-5072-4e20-ba52-d6b7d91e2461.png)

1.  要更改用于绘制对象的材料，只需从内容浏览器窗口中的材料文件夹内拖放新材料即可：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/7eb693d2-dcc1-4c9c-a3ba-6236a1ae129f.png)

材料就像油漆。您可以通过简单地将所需的材料拖放到要涂抹的对象上，为对象涂上任何您想要的材料。材料只是表面深度；它们不会改变对象的其他属性（如重量）。

# 开始一个新级别

如果要从头开始创建级别，请执行以下步骤：

1.  单击“文件”，导航到“新建级别...”，如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/13852d6b-750d-4e72-a365-ac1071e21140.png)

1.  然后可以在默认、VR-Basic 和空级别之间进行选择。我认为选择空级别是个好主意：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/b38499e3-8b1e-46f2-a2d1-92f421a87646.png)

1.  新的级别一开始会完全黑暗。尝试再次从内容浏览器选项卡中拖放一些对象。

这次，我为地面添加了一个调整大小的形状/shape_plane（不要使用模式下的常规平面，一旦添加了玩家，你会穿过它），并用 T_ground_Moss_D 进行了纹理处理，还有一些道具/SM_Rocks 和粒子/P_Fire。

一定要保存你的地图。这是我的地图快照（你的是什么样子？）：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/f1d1b823-1c5e-422e-9501-3c2afa46821f.png)

1.  如果你想要更改编辑器启动时打开的默认级别，转到编辑 | 项目设置 | 地图和模式；然后，你会看到一个游戏默认地图和编辑器启动地图设置，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/f5069206-46dc-4fd0-af8c-7e63d548efa0.png)

一定要确保你先保存当前场景！

# 添加光源

请注意，当你尝试运行时，你的场景可能会完全（或大部分）黑暗。这是因为你还没有在其中放置光源！

在之前的场景中，P_Fire 粒子发射器充当光源，但它只发出少量光线。为了确保你的场景中的一切都看起来被照亮，你应该添加一个光源，如下所示：

1.  转到窗口，然后点击模式，确保灯光面板显示出来：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/536b5a94-2f3d-4d35-b2b3-4c7399e8ad5e.png)

1.  从模式面板中，将一个灯光对象拖入场景中：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/9e64a618-4720-4acc-a369-83b053f2b03c.png)

1.  选择灯泡和盒子图标（看起来像蘑菇，但实际上不是）。

1.  点击左侧面板中的灯光。

1.  选择你想要的灯光类型，然后将其拖入你的场景中。

如果你没有光源，当你尝试运行时（或者场景中没有物体时），你的场景将完全黑暗。

# 碰撞体积

到目前为止，你可能已经注意到，相机在播放模式下至少穿过了一些场景几何体。这不好。让我们让玩家不能只是在我们的场景中走过岩石。

有几种不同类型的碰撞体积。通常，完美的网格-网格碰撞在运行时成本太高。相反，我们使用一个近似值（边界体积）来猜测碰撞体积。

网格是对象的实际几何形状。

# 添加碰撞体积

我们首先要做的是将碰撞体积与场景中的每个岩石关联起来。

我们可以从 UE4 编辑器中这样做：

1.  点击场景中要添加碰撞体积的对象。

1.  在世界大纲选项卡中右键单击此对象（默认显示在屏幕右侧），然后选择编辑，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/cfd4d03d-80a9-4853-9685-7727f7d73ab6.png)

你会发现自己在网格编辑器中。

1.  转到碰撞菜单，然后点击添加简化碰撞胶囊：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/934c27c4-7f97-421e-8b25-4cbdb7f064d6.png)

1.  成功添加碰撞体积后，碰撞体积将显示为一堆围绕对象的线，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/ddf3cd4b-6b70-4b18-8664-c32c781dae5b.png)

默认碰撞胶囊（左）和手动调整大小的版本（右）

1.  你可以调整（R）大小，旋转（E），移动（W），并根据需要更改碰撞体积，就像你在 UE4 编辑器中操作对象一样。

1.  当你添加完碰撞网格后，保存并返回到主编辑器窗口，然后点击播放；你会注意到你再也不能穿过你的可碰撞对象了。

# 将玩家添加到场景中

现在我们已经有了一个运行中的场景，我们需要向场景中添加一个角色。让我们首先为玩家添加一个角色，包括碰撞体积。为此，我们将不得不从 UE4 的`GameFramework`类中继承，比如`Actor`或`Character`。

为了创建玩家的屏幕表示，我们需要从虚幻中的`ACharacter`类派生。

# 从 UE4 GameFramework 类继承

UE4 使得从基础框架类继承变得容易。你只需要执行以下步骤：

1.  在 UE4 编辑器中打开你的项目。

1.  转到文件，然后选择新的 C++类...：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/88ecd03a-96b4-48a8-a5b5-fc45d6c067d7.png)

导航到文件|新的 C++类...将允许你从任何 UE4 GameFramework 类中派生

1.  选择你想要派生的基类。你有 Character、Pawn、Actor 等，但现在我们将从 Character 派生：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/b2bf7b68-86ba-4a8a-a4ad-7c0c2cb7fee1.png)

1.  选择你想要派生的 UE4 类。

1.  点击下一步，会弹出对话框，你可以在其中命名类。我将我的玩家类命名为`Avatar`：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/72788a9d-a226-4aed-aac5-033641857c8d.png)

1.  点击 Create Class 在代码中创建类，如前面的截图所示。

如果需要，让 UE4 刷新你的 Visual Studio 或 Xcode 项目。从解决方案资源管理器中打开新的`Avatar.h`文件。

UE4 生成的代码看起来有点奇怪。记得我在第五章中建议你避免的宏吗，*函数和宏*？UE4 代码广泛使用宏。这些宏用于复制和粘贴样板启动代码，让你的代码与 UE4 编辑器集成。

`Avatar.h`文件的内容如下所示：

```cpp
#pragma once

#include "CoreMinimal.h"
#include "GameFramework/Character.h"
#include "Avatar.generated.h"

UCLASS()
class GOLDENEGG_API AAvatar : public ACharacter
{
    GENERATED_BODY()

public:
    // Sets default values for this character's properties
    AAvatar();

protected:
    // Called when the game starts or when spawned
    virtual void BeginPlay() override;

public:    
    // Called every frame
    virtual void Tick(float DeltaTime) override;

    // Called to bind functionality to input
    virtual void SetupPlayerInputComponent(class UInputComponent* PlayerInputComponent) override;

};
```

让我们来谈谈宏。

`UCLASS()`宏基本上使你的 C++代码类在 UE4 编辑器中可用。`GENERATED_BODY()`宏复制并粘贴了 UE4 需要的代码，以使你的类作为 UE4 类正常运行。

对于`UCLASS()`和`GENERATED_BODY()`，你不需要真正理解 UE4 是如何运作的。你只需要确保它们出现在正确的位置（在生成类时它们所在的位置）。

# 将模型与 Avatar 类关联

现在，我们需要将模型与我们的角色对象关联起来。为此，我们需要一个模型来操作。幸运的是，UE4 市场上有一整套免费的示例模型可供使用。

# 下载免费模型

要创建玩家对象，请执行以下步骤：

1.  从市场选项卡下载 Animation Starter Pack 文件（免费）。找到它的最简单方法是搜索它：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/f1073a42-b50b-4964-8013-2a20e849d90f.png)

1.  从 Unreal Launcher 中，点击市场，搜索 Animation Starter Pack，在撰写本书时是免费的。

1.  一旦你下载了 Animation Starter Pack 文件，你就可以将它添加到之前创建的任何项目中，如下图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/113956d6-bf7c-4cb6-95dd-efc546c88354.png)

1.  当你点击 Animation Starter Pack 下的 Add to project 时，会弹出这个窗口，询问要将包添加到哪个项目中：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/66f17733-1221-4546-92b5-0ed1c9e04730.png)

1.  只需选择你的项目，新的艺术作品将在你的内容浏览器中可用。

# 加载网格

一般来说，将你的资产（或游戏中使用的对象）硬编码到游戏中被认为是一种不好的做法。硬编码意味着你编写 C++代码来指定要加载的资产。然而，硬编码意味着加载的资产是最终可执行文件的一部分，这意味着在运行时更改加载的资产是不可修改的。这是一种不好的做法。最好能够在运行时更改加载的资产。

因此，我们将使用 UE4 蓝图功能来设置我们的`Avatar`类的模型网格和碰撞胶囊。

# 从我们的 C++类创建蓝图

让我们继续创建一个蓝图，这很容易：

1.  通过导航到窗口|开发者工具，然后点击 Class Viewer 来打开 Class Viewer 选项卡，如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/40fa53a9-8873-4867-b9c1-e5646dffd0d8.png)

1.  在“类查看器”对话框中，开始输入你的 C++类的名称。如果你已经正确地从 C++代码中创建并导出了这个类，它将会出现，就像下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/b5a0efe8-efa9-4f15-b014-92c290522a84.png)

如果你的`Avatar`类没有显示出来，关闭编辑器，然后在 Visual Studio 或 Xcode 中重新编译/运行 C++项目。

1.  右键点击你想要创建蓝图的类（在我的例子中，是 Avatar 类），然后选择“创建蓝图类...”。

这是我的 Avatar 类），然后选择“创建蓝图类...”。

1.  给你的蓝图起一个独特的名字。我把我的蓝图叫做 BP_Avatar。BP_ 标识它是一个蓝图，这样以后搜索起来更容易。

1.  新的蓝图应该会自动打开以供编辑。如果没有，双击 BP_Avatar 打开它（在你添加它之后，它会出现在“类查看器”选项卡下的 Avatar 之下），就像下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/3354a828-7007-4665-9e70-bfa050b3bdd7.png)

1.  你将会看到新的 BP_Avatar 对象的蓝图窗口，就像这样（确保选择“事件图”选项卡）：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/ba5ad46c-4b2b-4838-a0d3-5e2a09809db5.png)

从这个窗口，你可以在视觉上将模型附加到`Avatar`类。同样，这是推荐的模式，因为通常是艺术家设置他们的资产供游戏设计师使用。

1.  你的蓝图已经继承了一个默认的骨骼网格。要查看它的选项，点击左侧的 CapsuleComponent 下的 Mesh（Inherited）：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/82e63e31-ade0-4cf5-9b21-8e1a16aad62b.png)

1.  点击下拉菜单，为你的模型选择 SK_Mannequin：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/5ee928d3-2f02-432c-b73f-8d9336092d2a.png)

1.  如果 SK_Mannequin 没有出现在下拉菜单中，请确保你下载并将动画起始包添加到你的项目中。

1.  碰撞体积呢？你已经有一个叫做 CapsuleComponent 的了。如果你的胶囊没有包裹住你的模型，调整模型使其合适。

如果你的模型最终像我的一样，胶囊位置不对！我们需要调整它。

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/ccef727b-a32d-4679-aa96-364d28b76c57.png)

1.  点击 Avatar 模型，然后点击并按住向上的蓝色箭头，就像前面的截图所示。将他移动到合适的位置以适应胶囊。如果胶囊不够大，你可以在详细信息选项卡下调整它的大小，包括 Capsule Half-Height 和 Capsule Radius：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/6e2931d1-ffbc-460d-9b34-4cdfc41d572a.png)

你可以通过调整 Capsule Half-Height 属性来拉伸你的胶囊。

1.  让我们把这个 Avatar 添加到游戏世界中。在 UE4 编辑器中，从“类查看器”选项卡中将 BP_Avatar 模型拖放到场景中：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/47722d4b-ab9b-4455-9466-c5c85c77e8c4.png)

我们的 Avatar 类已经添加到场景中

Avatar 的姿势是默认的姿势。你想要他动起来，是吧！好吧，那很容易，只需按照以下步骤进行：

1.  在蓝图编辑器中点击你的 Mesh，你会在右侧的详细信息下看到 Animation。注意：如果你因为任何原因关闭了蓝图并重新打开它，你将看不到完整的蓝图。如果发生这种情况，点击链接打开完整的蓝图编辑器。

1.  现在你可以使用蓝图来进行动画。这样，艺术家可以根据角色的动作来正确设置动画。如果你从`AnimClass`下拉菜单中选择 UE4ASP_HeroTPP_AnimBlueprint，动画将会被蓝图（通常是由艺术家完成的）调整，以适应角色的移动：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/0904ac8d-0a09-4db4-aa81-d78268b3ed59.png)

如果你保存并编译蓝图，并在主游戏窗口中点击播放，你将会看到空闲动画。

我们无法在这里覆盖所有内容。动画蓝图在第十一章中有介绍，*怪物*。如果你对动画真的感兴趣，不妨花点时间观看一些 Gnomon Workshop 关于 IK、动画和绑定的教程，可以在[gnomonworkshop.com/tutorials](http://gnomonworkshop.com/tutorials)找到。

还有一件事：让 Avatar 的相机出现在其后面。这将为您提供第三人称视角，使您可以看到整个角色，如下截图所示，以及相应的步骤：

1.  在 BP_Avatar 蓝图编辑器中，选择 BP_Avatar（Self）并单击添加组件。

1.  向下滚动以选择添加相机。

视口中将出现一个相机。您可以单击相机并移动它。将相机定位在玩家的后方某处。确保玩家身上的蓝色箭头面向相机的方向。如果不是，请旋转 Avatar 模型网格，使其面向与其蓝色箭头相同的方向：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/98e53d3b-5ffa-429f-842b-32dbd53351ec.png)

模型网格上的蓝色箭头表示模型网格的前进方向。确保相机的开口面向与角色的前向矢量相同的方向。

# 编写控制游戏角色的 C++代码

当您启动 UE4 游戏时，您可能会注意到相机没有改变。现在我们要做的是使起始角色成为我们`Avatar`类的实例，并使用键盘控制我们的角色。

# 使玩家成为 Avatar 类的实例

让我们看看我们如何做到这一点。在虚幻编辑器中，执行以下步骤：

1.  通过导航到 文件 | 新建 C++类... 并选择 Game Mode Base 来创建 Game Mode 的子类。我命名为`GameModeGoldenEgg`：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/23a322b6-c022-43ea-97fb-9807874a5637.png)

UE4 GameMode 包含游戏规则，并描述了游戏如何在引擎中进行。我们稍后将更多地使用我们的`GameMode`类。现在，我们需要对其进行子类化。

创建类后，它应该自动编译您的 C++代码，因此您可以创建`GameModeGoldenEgg`蓝图。

1.  通过转到顶部的菜单栏中的蓝图图标，单击 GameMode New，然后选择+ Create | GameModeGoldenEgg（或者您在步骤 1 中命名的 GameMode 子类）来创建 GameMode 蓝图：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/2f3f5cc3-d6a3-453a-831f-420ff6bfba75.png)

1.  命名您的蓝图；我称之为`BP_GameModeGoldenEgg`：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/7a38f985-9ad1-419a-98be-5946eb81ea29.png)

1.  您新创建的蓝图将在蓝图编辑器中打开。如果没有打开，您可以从类查看器选项卡中打开 BP_GameModeGoldenEgg 类。

1.  从默认 Pawn Class 面板中选择 BP_Avatar 类，如下截图所示。默认 Pawn Class 面板是将用于玩家的对象类型：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/23295e1f-cf29-4e40-bc83-a00c8eef7b91.png)

1.  启动您的游戏。您可以看到一个背面视图，因为相机放置在玩家后面：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/09b890d9-96b0-43e7-bec8-5e0ef4b8b9a2.png)

您会注意到您无法移动。为什么呢？答案是因为我们还没有设置控制器输入。接下来的部分将教您如何准确地进行操作。

# 设置控制器输入

以下是设置输入的步骤：

1.  要设置控制器输入，转到 设置 | 项目设置...：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/a408251e-921d-4c48-b3aa-f05828af46dc.png)

1.  在左侧面板中，向下滚动直到在引擎下看到输入：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/513f595b-2dbe-4f82-88dc-f9881ae1a587.png)

1.  在右侧，您可以设置一些绑定。单击+以添加新的绑定，然后单击 Axis Mappings 旁边的小箭头以展开它。开始添加两个轴映射，一个称为 Forward（连接到键盘字母*W*），另一个称为 Strafe（连接到键盘字母*D*）。记住您设置的名称；我们将在 C++代码中查找它们。

1.  关闭项目设置对话框。打开您的 C++代码。在`Avatar.h`构造函数中，您需要添加两个成员函数声明，如下所示：

```cpp
UCLASS()
class GOLDENEGG_API AAvatar : public ACharacter
{
    GENERATED_BODY()

public:
    // Sets default values for this character's properties
    AAvatar();

protected:
    // Called when the game starts or when spawned
    virtual void BeginPlay() override;

public:    
    // Called every frame
    virtual void Tick(float DeltaTime) override;

    // Called to bind functionality to input
    virtual void SetupPlayerInputComponent(class UInputComponent* PlayerInputComponent) override;

    // New! These 2 new member function declarations 
    // they will be used to move our player around! 
    void MoveForward(float amount);
    void MoveRight(float amount);

}; 
```

请注意，现有的函数`SetupPlayerInputComponent`和`Tick`是虚函数的重写。`SetupPlayerInputComponent`是`APawn`基类中的虚函数。我们还将向这个函数添加代码。

1.  在`Avatar.cpp`文件中，您需要添加函数主体。在`Super::SetupPlayerInputComponent(PlayerInputComponent);`下面的`SetupPlayerInputComponent`中，添加以下行：

```cpp
  check(PlayerInputComponent);
    PlayerInputComponent->BindAxis("Forward", this,
        &AAvatar::MoveForward);
    PlayerInputComponent->BindAxis("Strafe", this, &AAvatar::MoveRight);
```

这个成员函数查找我们刚刚在虚幻编辑器中创建的前进和横向轴绑定，并将它们连接到`this`类内部的成员函数。我们应该连接到哪些成员函数呢？为什么，我们应该连接到`AAvatar::MoveForward`和`AAvatar::MoveRight`。以下是这两个函数的成员函数定义：

```cpp
void AAvatar::MoveForward( float amount ) 
{ 
  // Don't enter the body of this function if Controller is 
  // not set up yet, or if the amount to move is equal to 0 
  if( Controller && amount ) 
  { 
    FVector fwd = GetActorForwardVector(); 
    // we call AddMovementInput to actually move the 
    // player by `amount` in the `fwd` direction 
    AddMovementInput(fwd, amount); 
  } 
} 

void AAvatar::MoveRight( float amount ) 
{ 
  if( Controller && amount ) 
  { 
    FVector right = GetActorRightVector(); 
    AddMovementInput(right, amount); 
  } 
} 
```

`Controller`对象和`AddMovementInput`函数在`APawn`基类中定义。由于`Avatar`类派生自`ACharacter`，而`ACharacter`又派生自`APawn`，因此我们可以免费使用`APawn`基类中的所有成员函数。现在，您看到了继承和代码重用的美丽之处了吗？如果您测试这个功能，请确保您点击游戏窗口内部，否则游戏将无法接收键盘事件。

# 练习

添加轴绑定和 C++函数以将玩家向左和向后移动。

这里有个提示：如果你意识到向后走实际上就是向前走的负数，那么你只需要添加轴绑定。

# 解决方案

通过导航到设置|项目设置...|输入，添加两个额外的轴绑定，如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/90c0f3a9-20ee-4edf-a119-0de485d653cc.png)

通过将 S 和 A 输入乘以-1.0 来缩放。这将反转轴，因此在游戏中按下*S*键将使玩家向前移动。试试看！

或者，您可以在`AAvatar`类中定义两个完全独立的成员函数，如下所示，并将*A*和*S*键分别绑定到`AAvatar::MoveLeft`和`AAvatar::MoveBack`（并确保为这些函数添加绑定到`AAvatar::SetupPlayerInputComponent`）：

```cpp
void AAvatar::MoveLeft( float amount ) 
{ 
  if( Controller && amount ) 
  { 
    FVector left = -GetActorRightVector(); 
    AddMovementInput(left, amount); 
  } 
} 
void AAvatar::MoveBack( float amount ) 
{ 
  if( Controller && amount ) 
  { 
    FVector back = -GetActorForwardVector(); 
    AddMovementInput(back, amount); 
  } 
} 
```

# 偏航和俯仰

我们可以通过设置控制器的偏航和俯仰来改变玩家的朝向。请查看以下步骤：

1.  按照以下截图所示，为鼠标添加新的轴绑定：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/92087a57-27cd-4228-ade9-ae57c6b78825.png)

1.  从 C++中，向`AAvatar.h`添加两个新的成员函数声明：

```cpp
void Yaw( float amount ); 
void Pitch( float amount ); 
```

这些成员函数的主体将放在`AAvatar.cpp`文件中：

```cpp
void AAvatar::Yaw(float amount)
{
    AddControllerYawInput(200.f * amount * GetWorld()->GetDeltaSeconds());
}
void AAvatar::Pitch(float amount)
{
    AddControllerPitchInput(200.f * amount * GetWorld()->GetDeltaSeconds());
}
```

1.  在`SetupPlayerInputComponent`中添加两行：

```cpp
void AAvatar::SetupPlayerInputComponent(UInputComponent* PlayerInputComponent)
{ 
  // .. as before, plus: 
  PlayerInputComponent->BindAxis("Yaw", this, &AAvatar::Yaw);
  PlayerInputComponent->BindAxis("Pitch", this, &AAvatar::Pitch); 
} 
```

在这里，注意我如何将`Yaw`和`Pitch`函数中的`amount`值乘以 200。这个数字代表鼠标的灵敏度。您可以（应该）在`AAvatar`类中添加一个`float`成员，以避免硬编码这个灵敏度数字。

`GetWorld()->GetDeltaSeconds()`给出了上一帧和这一帧之间经过的时间。这不是很多；`GetDeltaSeconds()`大多数时候应该在 16 毫秒左右（如果您的游戏以 60fps 运行）。

注意：您可能会注意到现在俯仰实际上并不起作用。这是因为您正在使用第三人称摄像头。虽然对于这个摄像头可能没有意义，但您可以通过进入 BP_Avatar，选择摄像头，并在摄像头选项下勾选使用 Pawn 控制旋转来使其起作用：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/18534c33-1564-4a99-aab9-28422d145e3c.png)

因此，现在我们有了玩家输入和控制。要为您的 Avatar 添加新功能，您只需要做到这一点：

1.  通过转到设置|项目设置|输入，绑定您的键盘或鼠标操作。

1.  添加一个在按下该键时运行的成员函数。

1.  在`SetupPlayerInputComponent`中添加一行，将绑定输入的名称连接到我们希望在按下该键时运行的成员函数。

# 创建非玩家角色实体

因此，我们需要创建一些**NPC**（**非玩家角色**）。NPC 是游戏中帮助玩家的角色。一些提供特殊物品，一些是商店供应商，一些有信息要提供给玩家。在这个游戏中，他们将在玩家靠近时做出反应。让我们在一些行为中编程：

1.  创建另一个 Character 的子类。在 UE4 编辑器中，转到文件 | 新建 C++类...，并选择可以创建子类的 Character 类。将您的子类命名为`NPC`。

1.  在 Visual Studio 中编辑您的代码。每个 NPC 都会有一条消息告诉玩家，因此我们在`NPC`类中添加了一个`UPROPERTY() FString`属性。

`FString`是 UE4 中 C++的`<string>`类型。在 UE4 中编程时，应该使用`FString`对象而不是 C++ STL 的`string`对象。一般来说，应该使用 UE4 的内置类型，因为它们保证跨平台兼容性。

1.  以下是如何向`NPC`类添加`UPROPERTY() FString`属性：

```cpp
UCLASS()
class GOLDENEGG_API ANPC : public ACharacter
{
    GENERATED_BODY()

    // This is the NPC's message that he has to tell us. 
    UPROPERTY(EditAnywhere, BlueprintReadWrite, Category =
        NPCMessage)
        FString NpcMessage;
    // When you create a blueprint from this class, you want to be  
    // able to edit that message in blueprints, 
    // that's why we have the EditAnywhere and BlueprintReadWrite  
    // properties. 
public:
    // Sets default values for this character's properties
    ANPC();

protected:
    // Called when the game starts or when spawned
    virtual void BeginPlay() override;

public:    
    // Called every frame
    virtual void Tick(float DeltaTime) override;

    // Called to bind functionality to input
    virtual void SetupPlayerInputComponent(class UInputComponent* PlayerInputComponent) override;

};
```

请注意，我们将`EditAnywhere`和`BlueprintReadWrite`属性放入了`UPROPERTY`宏中。这将使`NpcMessage`在蓝图中可编辑。

所有 UE4 属性说明符的完整描述可在[`docs.unrealengine.com/latest/INT/Programming/UnrealArchitecture/Reference/Properties/index.html`](https://docs.unrealengine.com/latest/INT/Programming/UnrealArchitecture/Reference/Properties/index.html)上找到。

1.  重新编译您的项目（就像我们为`Avatar`类所做的那样）。然后，转到类查看器，在您的`NPC`类上右键单击，并从中创建蓝图类。

1.  您想要创建的每个 NPC 角色都可以是基于`NPC`类的蓝图。为每个蓝图命名一个独特的名称，因为我们将为每个出现的 NPC 选择不同的模型网格和消息，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/4e56443b-06bf-4682-ba59-640982763c4a.png)

1.  打开蓝图并选择 Mesh（继承）。然后，您可以在骨骼网格下拉菜单中更改您的新角色的材质，使其看起来与玩家不同：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/6539c287-1585-4a05-a469-3b448b3fa947.png)

通过从下拉菜单中选择每个元素，更改您的角色在网格属性中的材质

1.  在组件选项卡中选择蓝图名称（self），在详细信息选项卡中查找`NpcMessage`属性。这是我们在 C++代码和蓝图之间的连接；因为我们在`FString NpcMessage`变量上输入了`UPROPERTY()`函数，该属性在 UE4 中显示为可编辑，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/a1b93490-aa67-4b8b-bc38-7d39feb6f7e1.png)

1.  将 BP_NPC_Owen 拖入场景中。您也可以创建第二个或第三个角色，并确保为它们提供独特的名称、外观和消息：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/369f6e1e-e458-4bdd-b7ff-dcdc3605201d.png)

我已经为基于 NPC 基类的 NPC 创建了两个蓝图：BP_NPC_Jonathan 和 BP_NPC_Owen。它们对玩家有不同的外观和不同的消息：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/fc0b7f35-74e7-42fe-b77a-6cb51e93f894.png)

场景中的 Jonathan 和 Owen

# 显示每个 NPC 对话框中的引用

为了显示对话框，我们需要一个自定义的**悬浮显示**（**HUD**）。在 UE4 编辑器中，转到文件 | 新建 C++类...，并选择从中创建子类的`HUD`类（您需要向下滚动以找到它）。按您的意愿命名您的子类；我命名为`MyHUD`。

创建`MyHUD`类后，让 Visual Studio 重新加载。我们将进行一些代码编辑。

# 在 HUD 上显示消息

在`AMyHUD`类中，我们需要实现`DrawHUD()`函数，以便将我们的消息绘制到 HUD 上，并使用以下`MyHUD.h`中的代码初始化 HUD 的字体绘制：

```cpp
UCLASS()
class GOLDENEGG_API AMyHUD : public AHUD
{
    GENERATED_BODY()
public:
    // The font used to render the text in the HUD. 
    UPROPERTY(EditAnywhere, BlueprintReadWrite, Category = HUDFont)
    UFont* hudFont;
    // Add this function to be able to draw to the HUD! 
    virtual void DrawHUD() override;
};
```

HUD 字体将在`AMyHUD`类的蓝图版本中设置。`DrawHUD()`函数每帧运行一次。为了在帧内绘制，将一个函数添加到`AMyHUD.cpp`文件中：

```cpp
void AMyHUD::DrawHUD()
{
    // call superclass DrawHUD() function first 
    Super::DrawHUD();
    // then proceed to draw your stuff. 
    // we can draw lines.. 
    DrawLine(200, 300, 400, 500, FLinearColor::Blue);
    // and we can draw text! 
    const FVector2D ViewportSize = FVector2D(GEngine->GameViewport->Viewport->GetSizeXY());
    DrawText("Greetings from Unreal!", FLinearColor::White, ViewportSize.X/2, ViewportSize.Y/2, hudFont);
}
```

等等！我们还没有初始化我们的字体。让我们现在做这个：

1.  在蓝图中设置它。在编辑器中编译您的 Visual Studio 项目，然后转到顶部的蓝图菜单，导航到 GameMode | HUD | + Create | MyHUD:

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/e7338fbe-3349-4835-9170-23c3c8b968d2.png)

创建 MyHUD 类的蓝图

1.  我称我的为`BP_MyHUD`。找到`Hud Font`，选择下拉菜单，并创建一个新的字体资源。我命名为`MyHUDFont`：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/7da1c1a0-5e0a-4be6-a077-10aed0bd1e75.png)

1.  在内容浏览器中找到 MyHUDFont 并双击以编辑它：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/032d326f-aa66-45f5-bc40-e85bd4610b06.png)

在随后的窗口中，您可以点击`+ Add Font`创建一个新的默认字体系列。您可以自行命名并单击文件夹图标选择硬盘上的字体（您可以在许多网站免费找到.TTF 或 TrueType 字体 - 我使用了找到的 Blazed 字体）；当您导入字体时，它将要求您保存字体。您还需要将 MyHUDFont 中的 Legacy Font Size 更改为更大的大小（我使用了 36）。

1.  编辑您的游戏模式蓝图（BP_GameModeGoldenEgg）并选择您的新`BP_MyHUD`（而不是`MyHUD`）类作为 HUD Class 面板：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/cf43dd26-ad50-423c-be6f-7bff4f073942.png)

编译并测试您的程序！您应该在屏幕上看到打印的文本：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/f46ba1db-4910-4069-a458-cde7dad072cd.png)

# 练习

您可以看到文本并没有完全居中。这是因为位置是基于文本的左上角而不是中间的。

看看你能否修复它。这里有一个提示：获取文本的宽度和高度，然后从视口宽度和高度/2 中减去一半。您将需要使用类似以下的内容：

```cpp
    const FVector2D ViewportSize = FVector2D(GEngine->GameViewport->Viewport->GetSizeXY());
    const FString message("Greetings from Unreal!");
    float messageWidth = 0;
    float messageHeight = 0;
    GetTextSize(message, messageWidth, messageHeight, hudFont);
    DrawText(message, FLinearColor::White, (ViewportSize.X - messageWidth) / 2, (ViewportSize.Y - messageHeight) / 2, hudFont);
```

# 使用 TArray<Message>

我们要显示给玩家的每条消息都将有一些属性：

+   用于消息的`FString`变量

+   用于显示消息的时间的`float`变量

+   用于消息颜色的`FColor`变量

因此，对我们来说，写一个小的`struct`函数来包含所有这些信息是有意义的。

在`MyHUD.h`的顶部，插入以下`struct`声明：

```cpp
struct Message 
{ 
  FString message; 
  float time; 
  FColor color; 
  Message() 
  { 
    // Set the default time. 
    time = 5.f; 
    color = FColor::White; 
  } 
  Message( FString iMessage, float iTime, FColor iColor ) 
  { 
    message = iMessage; 
    time = iTime; 
    color = iColor; 
  } 
}; 
```

现在，在`AMyHUD`类内，我们要添加一个这些消息的`TArray`。`TArray`是 UE4 定义的一种特殊类型的动态增长的 C++数组。我们将在第九章中详细介绍`TArray`的使用，但这种简单的`TArray`使用应该是对游戏中数组的有用性的一个很好的介绍。这将被声明为`TArray<Message>`：

```cpp
UCLASS()
class GOLDENEGG_API AMyHUD : public AHUD
{
    GENERATED_BODY()
public:
    // The font used to render the text in the HUD. 
    UPROPERTY(EditAnywhere, BlueprintReadWrite, Category = HUDFont)
        UFont* hudFont;
    // New! An array of messages for display 
    TArray<Message> messages;
    virtual void DrawHUD() override;
    // New! A function to be able to add a message to display 
    void addMessage(Message msg);
};
```

还要在文件顶部添加**`#include "CoreMinimal.h"`**。

现在，每当 NPC 有消息要显示时，我们只需要调用`AMyHud::addMessage()`并传入我们的消息。消息将被添加到要显示的消息的`TArray`中。当消息过期（在一定时间后），它将从 HUD 中移除。

在`AMyHUD.cpp`文件内，添加以下代码：

```cpp
void AMyHUD::DrawHUD()
{
    Super::DrawHUD();
    // iterate from back to front thru the list, so if we remove 
    // an item while iterating, there won't be any problems 
    for (int c = messages.Num() - 1; c >= 0; c--)
    {
        // draw the background box the right size 
        // for the message 
        float outputWidth, outputHeight, pad = 10.f;
        GetTextSize(messages[c].message, outputWidth, outputHeight,
            hudFont, 1.f);

        float messageH = outputHeight + 2.f*pad;
        float x = 0.f, y = c * messageH;

        // black backing 
        DrawRect(FLinearColor::Black, x, y, Canvas->SizeX, messageH
        );
        // draw our message using the hudFont 
        DrawText(messages[c].message, messages[c].color, x + pad, y +
            pad, hudFont);

        // reduce lifetime by the time that passed since last  
        // frame. 
        messages[c].time -= GetWorld()->GetDeltaSeconds();

        // if the message's time is up, remove it 
        if (messages[c].time < 0)
        {
            messages.RemoveAt(c);
        }
    }
}

void AMyHUD::addMessage(Message msg)
{
    messages.Add(msg);
}
```

`AMyHUD::DrawHUD()`函数现在绘制`messages`数组中的所有消息，并根据自上一帧以来经过的时间对`messages`数组中的每条消息进行排列。一旦消息的`time`值降至 0 以下，过期的消息将从`messages`集合中移除。

# 练习

重构`DrawHUD()`函数，使将消息绘制到屏幕的代码放在一个名为`DrawMessages()`的单独函数中。您可能希望创建至少一个样本消息对象，并调用`addMessage`以便您可以看到它。

`Canvas`变量仅在`DrawHUD()`中可用，因此您将不得不将`Canvas->SizeX`和`Canvas->SizeY`保存在类级变量中。

重构意味着改变代码的内部工作方式，使其更有组织或更容易阅读，但对于运行程序的用户来说，结果看起来是一样的。重构通常是一个好的实践。重构发生的原因是因为没有人在开始编写代码时确切地知道最终的代码应该是什么样子。

# 当玩家靠近 NPC 时触发事件

要在 NPC 附近触发事件，我们需要设置一个额外的碰撞检测体积，它比默认的胶囊形状稍宽。额外的碰撞检测体积将是每个 NPC 周围的一个球体。当玩家走进 NPC 的球体时，NPC（如下所示）会做出反应并显示一条消息：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/492972ff-87a2-4db4-a813-5aa37fd55b3f.png)

我们将向 NPC 添加深红色的球体，以便它可以知道玩家是否附近。

在`NPC.h`类文件中，添加`#include "Components/SphereComponent.h"`到顶部，并添加以下代码：

```cpp
UCLASS() class GOLDENEGG_API ANPC : public ACharacter {
    GENERATED_BODY()

public:
    // The sphere that the player can collide with tob
    UPROPERTY(VisibleAnywhere, BlueprintReadOnly, Category =
        Collision)
        USphereComponent* ProxSphere;
    // This is the NPC's message that he has to tell us. 
    UPROPERTY(EditAnywhere, BlueprintReadWrite, Category =
        NPCMessage)
        FString NpcMessage; // The corresponding body of this function is 
                            // ANPC::Prox_Implementation, __not__ ANPC::Prox()! 
                            // This is a bit weird and not what you'd expect, 
                            // but it happens because this is a BlueprintNativeEvent 
    UFUNCTION(BlueprintNativeEvent, Category = "Collision")
        void Prox(UPrimitiveComponent* OverlappedComponent, AActor* OtherActor, UPrimitiveComponent* OtherComp,
            int32 OtherBodyIndex, bool bFromSweep, const FHitResult& SweepResult);
    // You shouldn't need this unless you get a compiler error that it can't find this function.
    virtual int Prox_Implementation(UPrimitiveComponent* OverlappedComponent, AActor* OtherActor, UPrimitiveComponent* OtherComp,
        int32 OtherBodyIndex, bool bFromSweep, const FHitResult& SweepResult);

    // Sets default values for this character's properties
    ANPC(const FObjectInitializer& ObjectInitializer);

protected:
    // Called when the game starts or when spawned
    virtual void BeginPlay() override;

public:
    // Called every frame
    virtual void Tick(float DeltaTime) override;

    // Called to bind functionality to input
    virtual void SetupPlayerInputComponent(class UInputComponent* PlayerInputComponent) override;
};
```

这看起来有点凌乱，但实际上并不复杂。在这里，我们声明了一个额外的边界球体积，称为`ProxSphere`，它可以检测玩家是否靠近 NPC。

在`NPC.cpp`文件中，我们需要添加以下代码以完成接近检测：

```cpp
ANPC::ANPC(const FObjectInitializer& ObjectInitializer)
 : Super(ObjectInitializer)
{
 ProxSphere = ObjectInitializer.CreateDefaultSubobject<USphereComponent>(this,
 TEXT("Proximity Sphere"));
 ProxSphere->AttachToComponent(RootComponent, FAttachmentTransformRules::KeepWorldTransform);
 ProxSphere->SetSphereRadius(32.0f);
 // Code to make ANPC::Prox() run when this proximity sphere 
 // overlaps another actor. 
 ProxSphere->OnComponentBeginOverlap.AddDynamic(this, &ANPC::Prox);
 NpcMessage = "Hi, I'm Owen";//default message, can be edited 
 // in blueprints 
}

// Note! Although this was declared ANPC::Prox() in the header, 
// it is now ANPC::Prox_Implementation here. 
int ANPC::Prox_Implementation(UPrimitiveComponent* OverlappedComponent, AActor* OtherActor, UPrimitiveComponent* OtherComp,
 int32 OtherBodyIndex, bool bFromSweep, const FHitResult& SweepResult) 
{ 
    // This is where our code will go for what happens 
    // when there is an intersection 
    return 0;
} 
```

# 当玩家附近的 NPC 向 HUD 显示内容

当玩家靠近 NPC 的球体碰撞体积时，向 HUD 显示一条消息，提醒玩家 NPC 在说什么。

这是`ANPC::Prox_Implementation`的完整实现：

```cpp
int ANPC::Prox_Implementation(UPrimitiveComponent* OverlappedComponent, AActor* OtherActor, UPrimitiveComponent* OtherComp,
    int32 OtherBodyIndex, bool bFromSweep, const FHitResult& SweepResult)
{ 
    // if the overlapped actor is not the player, 
    // you should just simply return from the function 
    if( Cast<AAvatar>( OtherActor ) == nullptr ) { 
        return -1; 
    } 
    APlayerController* PController = GetWorld()->GetFirstPlayerController(); 
    if( PController ) 
    { 
        AMyHUD * hud = Cast<AMyHUD>( PController->GetHUD() ); 
        hud->addMessage( Message( NpcMessage, 5.f, FColor::White ) ); 
    } 
    return 0;
} 
```

还要确保在文件顶部添加以下内容：

```cpp
#include "Avatar.h"
#include "MyHud.h"
```

在这个函数中，我们首先将`OtherActor`（靠近 NPC 的物体）转换为`AAvatar`。当`OtherActor`是`AAvatar`对象时，转换成功（且不为`nullptr`）。我们获取 HUD 对象（它恰好附加到玩家控制器上），并将 NPC 的消息传递给 HUD。每当玩家在 NPC 周围的红色边界球体内时，消息就会显示出来：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/92ceff6f-a598-4b30-8c21-855ab81441b3.png)

乔纳森的问候

# 练习

尝试这些以进行更多练习：

1.  为 NPC 的名称添加一个`UPROPERTY`函数名称，以便在蓝图中可编辑 NPC 的名称，类似于 NPC 对玩家的消息。在输出中显示 NPC 的名称。

1.  为 NPC 的面部纹理添加一个`UPROPERTY`函数（类型为`UTexture2D*`）。在输出中，将 NPC 的面部显示在其消息旁边。

1.  将玩家的 HP 渲染为一条条形图（填充矩形）。

# 解决方案

将以下属性添加到`ANPC`类中：

```cpp
// This is the NPC's name 
UPROPERTY(EditAnywhere, BlueprintReadWrite, Category = NPCMessage) 
FString name; 
```

然后，在`ANPC::Prox_Implementation`中，将传递给 HUD 的字符串更改为这样：

```cpp
name + FString(": ") + NpcMessage
```

这样，NPC 的名称将附加到消息上。

为`ANPC`类添加`this`属性：

```cpp
UPROPERTY(EditAnywhere, BlueprintReadWrite, Category = NPCMessage) 
UTexture2D* Face; 
```

然后，您可以在蓝图中选择要附加到 NPC 面部的面部图标。

将纹理附加到您的`struct Message`：

```cpp
UTexture2D* tex; 
```

要渲染这些图标，您需要添加一个调用`DrawTexture()`，并传入正确的纹理：

```cpp
DrawTexture( messages[c].tex, x, y, messageH, messageH, 0, 0, 1, 1  
   );
```

在渲染之前，请确保检查纹理是否有效。图标应该看起来与屏幕顶部所示的类似：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/945c32ed-8d00-47bf-84c0-c8ed6a4f0b24.png)

以下是绘制玩家剩余健康值的条形图的函数：

```cpp
void AMyHUD::DrawHealthbar()
{
    // Draw the healthbar. 
    AAvatar *avatar = Cast<AAvatar>(
b        UGameplayStatics::GetPlayerPawn(GetWorld(), 0));
    float barWidth = 200, barHeight = 50, barPad = 12, barMargin = 50;
    float percHp = avatar->Hp / avatar->MaxHp;
    const FVector2D ViewportSize = FVector2D(GEngine->GameViewport->Viewport->GetSizeXY());
    DrawRect(FLinearColor(0, 0, 0, 1), ViewportSize.X - barWidth -
        barPad - barMargin, ViewportSize.Y - barHeight - barPad -
        barMargin, barWidth + 2 * barPad, barHeight + 2 * barPad);  DrawRect(FLinearColor(1 - percHp, percHp, 0, 1), ViewportSize.X
            - barWidth - barMargin, ViewportSize.Y - barHeight - barMargin,
            barWidth*percHp, barHeight);
}
```

您还需要将`Hp`和`MaxHp`添加到 Avatar 类中（现在可以为测试设置默认值），并将以下内容添加到文件顶部：

```cpp
#include "Kismet/GameplayStatics.h"
#include "Avatar.h"
```

# 总结

在这一章中，我们涉及了很多材料。我们向您展示了如何创建一个角色并在屏幕上显示它，如何使用轴绑定来控制您的角色，以及如何创建和显示可以向 HUD 发布消息的 NPC。现在可能看起来令人生畏，但一旦您多练习就会明白。

在接下来的章节中，我们将通过添加库存系统和拾取物品来进一步开发我们的游戏，以及为玩家携带物品的代码和概念。不过，在做这些之前，下一章我们将深入探讨一些 UE4 容器类型。


# 第九章：模板和常用容器

在第七章中，*动态内存分配*，我们讨论了如果要创建一个在编译时大小未知的新数组，您将如何使用动态内存分配。动态内存分配的形式为`int * array = new int[ number_of_elements ]`。

您还看到，使用`new[]`关键字进行动态分配需要稍后调用数组上的`delete[]`，否则将会出现内存泄漏。以这种方式管理内存是一项艰巨的工作。

是否有一种方法可以创建一个动态大小的数组，并且 C++可以自动为您管理内存？答案是肯定的。有 C++对象类型（通常称为容器）可以自动处理动态内存分配和释放。UE4 提供了一些容器类型，用于在动态可调整大小的集合中存储数据。

有两组不同的模板容器。有 UE4 容器系列（以`T*`开头）和 C++ **标准模板库**（**STL**）容器系列。UE4 容器和 C++ STL 容器之间存在一些差异，但这些差异并不重大。UE4 容器集是为游戏性能而编写的。C++ STL 容器也表现良好，它们的接口更加一致（API 的一致性是您所期望的）。您可以自行选择使用哪种容器集。但是，建议您使用 UE4 容器集，因为它保证在尝试编译代码时不会出现跨平台问题。

本章将涵盖以下主题：

+   在 UE4 中调试输出

+   模板和容器

+   UE4 的 TArray

+   TSet 和 TMap

+   常用容器的 C++ STL 版本

# 在 UE4 中调试输出

本章中的所有代码（以及后面的章节）都需要您在 UE4 项目中工作。为了测试`TArray`，我创建了一个名为`TArrays`的基本代码项目。在`ATArraysGameMode::ATArraysGameMode`构造函数中，我使用调试输出功能将文本打印到控制台。

以下是`TArraysGameMode.cpp`中的代码：

```cpp
#include "TArraysGameMode.h"
#include "Engine/Engine.h"

ATArraysGameMode::ATArraysGameMode(const FObjectInitializer& ObjectInitializer) : Super(ObjectInitializer)
{
    if (GEngine)
    {
        GEngine->AddOnScreenDebugMessage(-1, 30.f, FColor::Red, 
        TEXT("Hello!"));
    }
}
```

确保您还将函数添加到`.h`文件中。如果编译并运行此项目，您将在启动游戏时在游戏窗口的左上角看到调试文本。您可以使用调试输出随时查看程序的内部。只需确保在调试输出时`GEngine`对象存在。上述代码的输出显示在以下截图中（请注意，您可能需要将其作为独立游戏运行才能看到）：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/e8c01c25-6466-44de-bba4-a0db06c1f05d.png)

# 模板和容器

模板是一种特殊类型的对象。模板对象允许您指定它应该期望的数据类型。例如，很快您将看到，您可以运行一个`TArray<T>`变量。这是一个模板的例子。

要理解`TArray<T>`变量是什么，首先必须知道尖括号之间的`<T>`选项代表什么。`<T>`选项表示数组中存储的数据类型是一个变量。您想要一个`int`数组吗？然后创建一个`TArray<int>`变量。`double`的`TArray`变量？创建一个`TArray<double>`变量。

因此，通常情况下，无论何时出现`<T>`，您都可以插入您选择的 C++数据类型。

容器是用于存储对象的不同结构。模板对此特别有用，因为它们可以用于存储许多不同类型的对象。您可能希望使用 int 或 float 存储数字，字符串或不同类型的游戏对象。想象一下，如果您必须为您想要存储的每种对象类型编写一个新类。幸运的是，您不必这样做。模板让一个类足够灵活，可以处理您想要存储在其中的任何对象。

# 你的第一个模板

创建模板是一个高级主题，您可能多年不需要创建自己的模板（尽管您会一直使用标准模板）。但是，看看一个模板是什么样子可能有助于您了解幕后发生了什么。

想象一下，您想创建一个数字模板，让您可以使用 int、float 或其他类型。您可以做类似于这样的事情：

```cpp
template <class T>
class Number {
    T value;
public:
    Number(T val)
    {
        value = val;
    }

    T getSumWith(T val2);
};

template <class T>
T Number<T>::getSumWith(T val2)
{
    T retval;
    retval = value + val2;
    return retval;
}
```

第一部分是类本身。正如您所看到的，您想在模板中的任何地方使用类型，您制作类并使用`T`而不是指定特定类型。您还可以使用模板来指定发送到函数的值。在这种情况下，最后一部分允许您添加另一个数字并返回总和。

您甚至可以通过重载+运算符来简化事情，以便您可以像使用任何标准类型一样添加这些数字。这是通过一种称为运算符重载的东西。

# UE4 的 TArray<T>

TArrays 是 UE4 的动态数组版本，使用模板构建。与我们讨论过的其他动态数组一样，您无需担心自己管理数组大小。让我们继续并通过一个示例来看看这个。

# 使用 TArray<T>的示例

`TArray<int>`变量只是一个`int`数组。`TArray<Player*>`变量将是一个`Player*`指针数组。数组是动态可调整大小的，可以在创建后在数组末尾添加元素。

要创建一个`TArray<int>`变量，您只需使用正常的变量分配语法：

```cpp
TArray<int> array; 
```

对`TArray`变量的更改是使用成员函数完成的。有几个成员函数可以在`TArray`变量上使用：

您需要了解的第一个成员函数是如何向数组添加值，如下面的代码所示：

```cpp
array.Add( 1 ); 
array.Add( 10 ); 
array.Add( 5 ); 
array.Add( 20 ); 
```

以下四行代码将产生内存中的数组值，如下图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/8f29a440-73b4-4596-9a09-342c3fad4a2e.png)

当您调用`array.Add(number)`时，新数字将添加到数组的末尾。由于我们按顺序向数组添加了数字**1**、**10**、**5**和**20**，因此它们将按照这个顺序进入数组。

如果要在数组的前面或中间插入一个数字，也是可能的。您只需使用`array.Insert(value, index)`函数，如下面的代码所示：

```cpp
array.Insert( 9, 0 ); 
```

此函数将数字`9`推入数组的位置`0`（在前面）。这意味着数组的其余元素将向右偏移，如下图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/53088c53-3664-4a96-9f42-6fa30b9713f2.png)

我们可以使用以下代码将另一个元素插入到数组的位置`2`：

```cpp
array.Insert( 30, 2 ); 
```

此函数将重新排列数组，如下图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/3b989010-02d1-4356-8a5e-e5bca807c402.png)

如果在数组中插入一个超出边界的位置的数字（它不存在），UE4 将崩溃。所以，要小心不要这样做。您可以使用`Add`来添加一个新项目。

# 迭代 TArray

您可以以两种方式迭代（遍历）`TArray`变量的元素：使用基于整数的索引或使用迭代器。我将在这里向您展示两种方法。

# 普通 for 循环和方括号表示法

使用整数来索引数组元素有时被称为普通的`for`循环。可以使用`array[index]`来访问数组的元素，其中`index`是数组中元素的数字位置：

```cpp
for( int index = 0; index < array.Num(); index++ ) 
{ 
  // print the array element to the screen using debug message 
  GEngine->AddOnScreenDebugMessage( -1, 30.f, FColor::Red,  
   FString::FromInt( array[ index ] ) ); 
} 
```

# 迭代器

您还可以使用迭代器逐个遍历数组的元素，如下面的代码所示：

```cpp
for (TArray<int>::TIterator it = array.CreateIterator(); it; ++it)
{
    GEngine->AddOnScreenDebugMessage(-1, 30.f, FColor::Green, FString::FromInt(*it));
}
```

迭代器是数组中的指针。迭代器可用于检查或更改数组中的值。迭代器的示例如下图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/47aabe5d-01fc-4220-9f22-726d1d5595db.png)

迭代器是一个外部对象，可以查看和检查数组的值。执行`++it`将迭代器移动到检查下一个元素。

迭代器必须适用于它正在遍历的集合。要遍历`TArray<int>`变量，您需要一个`TArray<int>::TIterator`类型的迭代器。

我们使用`*`来查看迭代器后面的值。在上述代码中，我们使用`(*it)`从迭代器中获取整数值。这称为解引用。解引用迭代器意味着查看其值。

`for`循环的每次迭代结束时发生的`++it`操作会递增迭代器，将其移动到指向列表中的下一个元素。

将代码插入程序并立即尝试。以下是我们迄今为止使用`TArray`创建的示例程序（全部在`ATArraysGameMode::ATArraysGameMode()`构造函数中）：

```cpp
ATArraysGameMode::ATArraysGameMode(const FObjectInitializer& ObjectInitializer) : Super(ObjectInitializer)
{
    if (GEngine)
    {
        TArray<int> array;
        array.Add(1);
        array.Add(10);
        array.Add(5);
        array.Add(20);
        array.Insert(9, 0);// put a 9 in the front 
        array.Insert(30, 2);// put a 30 at index 2 
        if (GEngine)
        {
            for (int index = 0; index < array.Num(); index++)
            {
                GEngine->AddOnScreenDebugMessage(index, 30.f, FColor::Red,
                    FString::FromInt(array[index]));
            }
        }
    }
}
```

以下是上述代码的输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/657541c8-f2fd-4aa0-ba33-285189680049.png)

# 确定元素是否在 TArray 中

搜索我们的 UE4 容器很容易。通常使用`Find`成员函数来完成。使用我们之前创建的数组，我们可以通过输入以下代码来找到值为`10`的索引：

```cpp
int index = array.Find( 10 ); // would be index 3 in image above 
```

# TSet<T>

`TSet<int>`变量存储一组整数。`TSet<FString>`变量存储一组字符串。`TSet`和`TArray`之间的主要区别在于，`TSet`不允许重复；`TSet`中的所有元素都保证是唯一的。`TArray`变量不介意相同元素的重复。

要向`TSet`添加数字，只需调用`Add`。以下是一个例子：

```cpp
TSet<int> set; 
set.Add( 1 ); 
set.Add( 2 ); 
set.Add( 3 ); 
set.Add( 1 );// duplicate! won't be added 
set.Add( 1 );// duplicate! won't be added 
```

`TSet`将如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/740b0648-f23d-4b33-887c-c11c86a96683.png)

`TSet`中相同值的重复条目将不被允许。请注意，`TSet`中的条目没有编号，就像`TArray`中一样；您不能使用方括号来访问`TSet`数组中的条目。

# 迭代 TSet

要查看`TSet`数组，必须使用迭代器。您不能使用方括号表示法来访问`TSet`的元素：

```cpp
for( TSet<int>::TIterator it = set.CreateIterator(); it; ++it ) 
{ 
  GEngine->AddOnScreenDebugMessage( -1, 30.f, FColor::Red,  
   FString::FromInt( *it ) ); 
} 
```

# 交集 TSet 数组

`TSet`数组有两个`TArray`变量没有的特殊函数。两个`TSet`数组的交集基本上是它们共有的元素。如果我们有两个`TSet`数组，比如`X`和`Y`，并且我们对它们进行交集运算，结果将是一个第三个新的`TSet`数组，其中只包含它们之间的共同元素。看下面的例子：

```cpp
TSet<int> X; 
X.Add( 1 ); 
X.Add( 2 ); 
X.Add( 3 ); 
TSet<int> Y; 
Y.Add( 2 ); 
Y.Add( 4 ); 
Y.Add( 8 ); 
TSet<int> common = X.Intersect(Y); // 2 
```

`X`和`Y`之间的共同元素将只是元素`2`。

# 并集 TSet 数组

从数学上讲，两个集合的并集是指将所有元素插入到同一个集合中。由于我们在这里讨论的是集合，所以不会有重复项。

如果我们从前面的示例中获取`X`和`Y`集合并创建一个并集，我们将得到一个新的集合，如下所示：

```cpp
TSet<int> uni = X.Union(Y); // 1, 2, 3, 4, 8 
```

# 在 TSet 数组中查找

您可以通过在集合上使用`Find()`成员函数来确定元素是否在`TSet`中。如果元素存在于`TSet`中，`TSet`将返回与您的查询匹配的`TSet`中的条目的指针，如果您要查询的元素不存在于`TSet`中，它将返回`NULL`。

# TMap<T,S>

`TMap<T,S>`在 RAM 中创建了一种表。`TMap`表示左侧键到右侧值的映射。您可以将`TMap`视为一个两列表，左列中是键，右列中是值。

# 玩家库存的物品列表

例如，假设我们想要创建一个 C++数据结构，以便存储玩家库存的物品列表。在表的左侧（键）上，我们将使用`FString`表示物品的名称。在右侧（值）上，我们将使用`int`表示该物品的数量，如下表所示：

| 项目（键） | 数量（值） |
| --- | --- |
| `apples` | `4` |
| `donuts` | `12` |
| `swords` | `1` |
| `shields` | `2` |

要在代码中执行此操作，我们只需使用以下代码：

```cpp
TMap<FString, int> items; 
items.Add( "apples", 4 ); 
items.Add( "donuts", 12 ); 
items.Add( "swords", 1 ); 
items.Add( "shields", 2 ); 
```

创建了`TMap`之后，你可以使用方括号和在方括号之间传递键来访问`TMap`中的值。例如，在前面代码中的`items`映射中，`items[ "apples" ]`是`4`。

如果你使用方括号访问地图中尚不存在的键，UE4 会崩溃，所以要小心！C++ STL 如果这样做不会崩溃。

# 迭代 TMap

为了迭代`TMap`，你也需要使用迭代器：

```cpp
for( TMap<FString, int>::TIterator it = items.CreateIterator(); it; ++it ) 
{ 
  GEngine->AddOnScreenDebugMessage( -1, 30.f, FColor::Red, 
  it->Key + FString(": ") + FString::FromInt( it->Value ) ); 
} 
```

`TMap`迭代器与`TArray`或`TSet`迭代器略有不同。`TMap`迭代器包含`Key`和`Value`。我们可以使用`it->Key`访问键，并使用`it->Value`访问`TMap`中的值。

这里有一个例子：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/1f66537a-711e-4291-aae6-4fa91483e851.png)

# TLinkedList/TDoubleLinkedList

当你使用 TArray 时，每个项目都有一个按数字顺序排列的索引，数组数据通常以相同的方式存储，因此每个条目在内存中都紧邻前一个条目。但是，如果你需要在中间某个位置放置一个新项目（例如，如果数组中填充了按字母顺序排列的字符串），该怎么办呢？

由于项目是相邻的，旁边的项目将不得不移动以腾出空间。但是为了做到这一点，旁边的那个也将不得不移动。这将一直持续到数组的末尾，当它最终到达可以在不移动其他东西的内存时。你可以想象，这可能会变得非常慢，特别是如果你经常这样做的话。

这就是链表派上用场的地方。链表没有任何索引。链表有包含项目并让你访问列表上第一个节点的节点。该节点有指向列表上下一个节点的指针，你可以通过调用`Next()`来获取。然后，你可以在那个节点上调用`Next()`来获取它后面的节点。它看起来像这样：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/d1ab445b-147b-4ff9-8f86-bbf2bdcc9859.png)

你可能会猜到，如果你在列表末尾寻找项目，这可能会变得很慢。但与此同时，你可能并不经常搜索列表，而是可能在中间添加新项目。在中间添加项目要快得多。比如，你想在**Node 1**和**Node 2**之间插入一个新节点，就像这样：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/edb6efd2-6025-4a81-b93c-aaf3f7fecc5a.png)

这次不需要在内存中移动东西来腾出空间。相反，要在另一个项目后插入一个项目，获取`Next()`指向的节点从**Node 1**（**Node 2**）开始。将新节点设置为指向该节点（**Node 2**）。然后，将 Node 1 设置为指向新节点。现在它应该看起来像这样：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/7286df8d-4f4e-498c-be18-19b9bb7fac08.png)

然后，你就完成了！

那么，如果你将花费更多时间查找列表末尾的项目怎么办？这就是`TDoubleLinkedList`派上用场的地方。双向链表可以给你列表中的第一个节点或最后一个节点。每个节点还有指向下一个节点和上一个节点的指针。你可以使用`GetNextLink()`和`GetPrevLink()`来访问这些。因此，你可以选择向前或向后遍历列表，甚至两者兼而有之，最终相遇在中间。

现在，你可能会问自己，“为什么要在我可以只使用 TArray 而不用担心它在幕后做什么的情况下？”首先，专业的游戏程序员总是要担心速度。计算机和游戏机的每一次进步都伴随着更多和更好的图形以及其他使事情变得更慢的进步。因此，优化速度总是很重要的。

另外，还有另一个实际的原因：我可以告诉你，根据我的经验，这个行业中有些人会在面试中拒绝你，如果你不使用链表。程序员都有自己偏好的做事方式，所以你应该熟悉可能出现的任何事情。

# 常用容器的 C++ STL 版本

现在，我们将介绍几种容器的 C++ STL 版本。STL 是标准模板库，大多数 C++编译器都附带。我想介绍这些 STL 版本的原因是它们的行为与相同容器的 UE4 版本有些不同。在某些方面，它们的行为非常好，但游戏程序员经常抱怨 STL 存在性能问题。特别是，我想介绍 STL 的`set`和`map`容器，但我也会介绍常用的`vector`。

如果您喜欢 STL 的接口但希望获得更好的性能，有一个由艺电重新实现的 STL 库，名为 EASTL，您可以使用。它提供与 STL 相同的功能，但实现了更好的性能（基本上是通过消除边界检查等方式）。它可以在 GitHub 上找到[`github.com/paulhodge/EASTL`](https://github.com/paulhodge/EASTL)。

# C++ STL set

C++ set 是一堆独特且排序的项目。STL `set`的好处是它保持了集合元素的排序。快速而粗糙的排序一堆值的方法实际上就是将它们塞入同一个`set`中。`set`会为您处理排序。

我们可以回到一个简单的 C++控制台应用程序来使用集合。要使用 C++ STL set，您需要包含`<set>`，如下所示：

```cpp
#include <iostream> 
#include <set> 
using namespace std; 

int main() 
{ 
  set<int> intSet; 
  intSet.insert( 7 ); 
  intSet.insert( 7 ); 
  intSet.insert( 8 ); 
  intSet.insert( 1 ); 

  for( set<int>::iterator it = intSet.begin(); it != intSet.end();  
   ++it ) 
  { 
    cout << *it << endl; 
  } 
} 
```

以下是前面代码的输出：

```cpp
1 
7 
8 
```

重复的`7`被过滤掉，并且元素在`set`中保持增序。我们遍历 STL 容器的方式类似于 UE4 的`TSet`数组。`intSet.begin()`函数返回一个指向`intSet`头部的迭代器。

停止迭代的条件是当它变为`intSet.end()`。`intSet.end()`实际上是`set`末尾的下一个位置，如下图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/2143e060-1cc8-4ded-a163-8a2aca5fb9be.png)

# 在<set>中查找元素

要在 STL `set`中查找元素，我们可以使用`find()`成员函数。如果我们要查找的项目出现在`set`中，我们将得到一个指向我们正在搜索的元素的迭代器。如果我们要查找的项目不在`set`中，我们将得到`set.end()`，如下所示：

```cpp
set<int>::iterator it = intSet.find( 7 ); 
if( it != intSet.end() ) 
{ 
  //  7  was inside intSet, and *it has its value 
  cout << "Found " << *it << endl; 
} 
```

# 练习

要求用户提供三个唯一名称的集合。逐个输入每个名称，然后按排序顺序打印它们。如果用户重复名称，请要求他们再输入一个，直到达到三个为止。

# 解决方案

前面练习的解决方案可以使用以下代码找到：

```cpp
#include <iostream> 
#include <string> 
#include <set> 
using namespace std; 
int main() 
{ 
  set<string> names; 
  // so long as we don't have 3 names yet, keep looping, 
  while( names.size() < 3 ) 
  { 
    cout << names.size() << " names so far. Enter a name" << endl; 
    string name; 
    cin >> name; 
    names.insert( name ); // won't insert if already there, 
  } 
  // now print the names. the set will have kept order 
  for( set<string>::iterator it = names.begin(); it !=  
   names.end(); ++it ) 
  { 
    cout << *it << endl; 
  } 
} 
```

# C++ STL map

C++ STL `map`对象很像 UE4 的`TMap`对象。它做的一件事是`TMap`不会在地图内部保持排序顺序。排序会引入额外的成本，但如果您希望地图排序，选择 STL 版本可能是一个不错的选择。

要使用 C++ STL `map`对象，我们包括`<map>`。在下面的示例程序中，我们使用一些键值对填充了一个项目的映射：

```cpp
#include <iostream> 
#include <string> 
#include <map> 
using namespace std; 
int main() 
{ 
  map<string, int> items; 
  items.insert( make_pair( "apple", 12 ) ); 
  items.insert( make_pair( "orange", 1 ) ); 
  items.insert( make_pair( "banana", 3 ) ); 
  // can also use square brackets to insert into an STL map 
  items[ "kiwis" ] = 44; 

  for( map<string, int>::iterator it = items.begin(); it !=  
   items.end(); ++it ) 
  { 
    cout << "items[ " << it->first << " ] = " << it->second <<  
     endl; 
  } 
} 
```

这是前面程序的输出：

```cpp
items[ apple ] = 12 
items[ banana ] = 3 
items[ kiwis ] = 44 
items[ orange ] = 1 
```

请注意，STL map 的迭代器语法与`TMap`略有不同；我们使用`it->first`访问键，使用`it->second`访问值。

请注意，C++ STL 还为`TMap`提供了一些语法糖；您可以使用方括号插入到 C++ STL `map`中。您不能使用方括号插入到`TMap`中。

# 在<map>中查找元素

您可以使用 STL map 的`find`成员函数在 map 中搜索<`key`，`value`>对。通常通过`key`进行搜索，它会给您该`key`的值。

# 练习

要求用户输入五个项目及其数量到空`map`中。以排序顺序打印结果（即按字母顺序或按数字顺序从低到高）。

# 解决方案

前面练习的解决方案使用以下代码：

```cpp
#include <iostream> 
#include <string> 
#include <map> 
using namespace std; 
int main() 
{ 
  map<string, int> items; 
  cout << "Enter 5 items, and their quantities" << endl; 
  while( items.size() < 5 ) 
  { 
    cout << "Enter item" << endl; 
    string item; 
    cin >> item; 
    cout << "Enter quantity" << endl; 
    int qty; 
    cin >> qty; 
    items[ item ] = qty; // save in map, square brackets 
    // notation 
  } 

  for( map<string, int>::iterator it = items.begin(); it !=  
   items.end(); ++it ) 
  { 
    cout << "items[ " << it->first << " ] = " << it->second <<  
     endl; 
  } 
} 
```

在这个解决方案代码中，我们首先创建`map<string, int> items`来存储我们要带入的所有物品。询问用户一个物品和数量；然后，我们使用方括号表示法将`item`保存在`items`映射中。

# C++ STL Vector

`Vector`是 STL 中`TArray`的等价物。它基本上是一个在幕后管理一切的数组，就像`TArray`一样。在使用 UE4 时可能不需要使用它，但了解它是很好的，以防其他人在项目中使用它。

# 摘要

UE4 的容器和 C++ STL 容器系列都非常适合存储游戏数据。选择合适的数据容器类型可以大大简化编程问题。

在下一章中，我们将通过跟踪玩家携带的物品并将这些信息存储在`TMap`对象中，实际开始编写游戏的开头部分。


# 第十章：库存系统和拾取物品

我们希望玩家能够从游戏世界中拾取物品。在本章中，我们将为玩家编写和设计一个背包来存放物品。当用户按下*I*键时，我们将显示玩家携带的物品。

作为数据表示，我们可以使用上一章中介绍的`TMap<FString, int>`来存储我们的物品。当玩家拾取物品时，我们将其添加到地图中。如果物品已经在地图中，我们只需增加其值，即新拾取的物品的数量。

在本章中，我们将涵盖以下主题：

+   声明背包

+   PickupItem 基类

+   绘制玩家库存

# 声明背包

我们可以将玩家的背包表示为一个简单的`TMap<FString, int>`项目。为了让我们的玩家从世界中收集物品，打开`Avatar.h`文件并添加以下`TMap`声明：

```cpp
class APickupItem; //  forward declare the APickupItem class, 
                   // since it will be "mentioned" in a member  
                    function decl below 
UCLASS() 
class GOLDENEGG_API AAvatar : public ACharacter 
{ 
  GENERATED_BODY() 
public: 
  // A map for the player's backpack 
  TMap<FString, int> Backpack; 

  // The icons for the items in the backpack, lookup by string 
  TMap<FString, UTexture2D*> Icons; 

  // A flag alerting us the UI is showing 
  bool inventoryShowing; 
  // member function for letting the avatar have an item 
  void Pickup( APickupItem *item ); 
  // ... rest of Avatar.h same as before 
}; 
```

# 前向声明

在`AAvatar`类之前，请注意我们有一个`class APickupItem`的前向声明。在代码文件中需要前向声明的情况是当提到一个类（例如`APickupItem::Pickup( APickupItem *item );`函数原型）时，但文件中实际上没有使用该类型的对象的代码。由于`Avatar.h`头文件不包含使用`APickupItem`类型对象的可执行代码，我们需要前向声明。虽然包含一个.h 文件可能更容易，但有时最好避免这样做，否则可能会出现循环依赖（两个类互相包含可能会导致问题）。

缺少前向声明将导致编译错误，因为编译器在编译`class AAvatar`中的代码之前不知道`class APickupItem`。编译器错误将出现在`APickupItem::Pickup( APickupItem *item );`函数原型声明处。

我们在`AAvatar`类中声明了两个`TMap`对象。如下表所示：

| `FString`（名称） | `int`（数量） | `UTexture2D*`（im） |
| --- | --- | --- |
| `GoldenEgg` | `2` | ![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/c3918bbc-1d30-4f56-aea2-4df86976f902.png) |
| `MetalDonut` | `1` | ![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/9b920363-321a-41c9-a215-8f472aad5bc9.png) |
| `Cow` | `2` | ![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/771da95a-5e07-4846-94f1-346279693904.png) |

在`TMap`背包中，我们存储玩家持有的物品的`FString`变量。在`图标`映射中，我们存储玩家持有物品的图像的单个引用。

在渲染时，我们可以使用两个地图一起工作，查找玩家拥有的物品数量（在他的`背包`映射中），以及该物品的纹理资产引用（在`图标`映射中）。以下屏幕截图显示了 HUD 的渲染效果：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/ead175d8-8699-48a9-88de-6c8fa1c2086b.png)

请注意，我们还可以使用一个包含`FString`变量和`UTexture2D*`的`struct`数组，而不是使用两个地图。

例如，我们可以使用`TArray<Item> Backpack;`和一个`struct`变量，如下面的代码所示：

```cpp
struct Item   
{   
  FString name;   
  int qty;   
  UTexture2D*   tex;   
};   
```

然后，当我们拾取物品时，它们将被添加到线性数组中。然而，计算我们在背包中每种物品的数量将需要通过遍历整个数组来进行不断的重新评估。例如，要查看您有多少个发夹，您需要遍历整个数组。这不如使用地图高效。

# 导入资产

您可能已经注意到前面屏幕截图中的 Cow 资产，这不是 UE4 在新项目中提供的标准资产集的一部分。为了使用 Cow 资产，您需要从内容示例项目中导入 cow。UE4 使用标准的导入过程。

在下面的屏幕截图中，我已经概述了导入 Cow 资产的过程。其他资产将使用相同的方法从 UE4 中的其他项目导入。

执行以下步骤导入 Cow 资产：

1.  下载并打开 UE4 的 Content Examples 项目。在 Epic Game Launcher 的 Learn 下找到它，如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/d6b3e574-9bbc-455d-a1aa-44ad05f4822e.png)

1.  下载 Content Examples 后，打开它并单击

创建项目：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/d191f3be-af11-46e1-b608-8255fd89edc7.png)

1.  接下来，命名您将放置`ContentExamples`的文件夹，然后单击创建。

1.  从库中打开您的`ContentExamples`项目。浏览项目中可用的资产，直到找到您喜欢的资产。按照惯例，搜索`SM_`将有所帮助，因为所有静态网格通常以`SM_`开头：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/c401500f-fb64-4339-ad53-cb369c27eed2.png)

项目中可用的资产

1.  当您找到喜欢的资产时，通过右键单击资产，然后单击 Asset Actions > Migrate...将其导入到您的项目中：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/aaf26cd5-cdb2-4f0c-9784-bd815f8f43c4.png)

1.  在 Asset Report 对话框中单击确定：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/335e3f20-4f45-4d42-b3b0-2f87a74e648b.png)

1.  从您要将 SM_Toy_Cow 文件添加到的项目的 Content 文件夹中选择。我们将把它添加到`/Documents/Unreal Projects/GoldenEgg/Content`，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/be9114fd-5243-4752-b5a0-eaa04fed5e27.png)

1.  如果导入成功完成，您将看到以下消息：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/fd127d7a-4618-45e8-9a57-66f9bca8328e.png)

1.  一旦您导入资产，您将在项目内的资产浏览器中看到它显示出来：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/2eea6f29-6e2e-4ef0-a5a5-7fc312a12e4e.png)

然后您可以在项目中正常使用该资产。

# 将动作映射附加到键

我们需要附加一个键来激活玩家库存的显示。在 UE4 编辑器中，按照以下步骤操作：

1.  添加一个名为`Inventory`的 Action Mappings+

1.  将其分配给键盘键*I*，如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/6b70bffd-3536-4c2b-b521-1103b6ba0183.png)

1.  接下来，在`Avatar.h`文件中，添加一个成员函数，以在需要显示玩家库存时运行：

```cpp
void ToggleInventory(); 
```

1.  在`Avatar.cpp`文件中，实现`ToggleInventory()`函数，如下面的代码所示：

```cpp
void AAvatar::ToggleInventory() 
{ 
  if( GEngine ) 
  { 
    GEngine->AddOnScreenDebugMessage( -1, 5.f, FColor::Red,  
     "Showing inventory..." ); 
  } 
} 
```

1.  然后，在`SetupPlayerInputComponent()`中将`"Inventory"`动作连接到`AAvatar::ToggleInventory()`：

```cpp
void AAvatar::SetupPlayerInputComponent(class UInputComponent*  
   InputComponent) 
{ 
 Super::SetupPlayerInputComponent(PlayerInputComponent);

    check(PlayerInputComponent);
    PlayerInputComponent->BindAction("Inventory", IE_Pressed, this,
        &AAvatar::ToggleInventory);
  // rest of SetupPlayerInputComponent same as before 
} 
```

# 拾取物品基类

我们需要在代码中定义拾取物品的外观。每个拾取物品将从一个共同的基类派生。现在让我们构造一个`PickupItem`类的基类。

`PickupItem`基类应该继承自`AActor`类。类似于我们如何从基础 NPC 类创建多个 NPC 蓝图，我们可以从单个`PickupItem`基类创建多个`PickupItem`蓝图，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/01cb7674-3e98-4a88-b927-5a8a3b556723.png)

此截图中的文本不重要。此图让您了解如何从单个`PickupItem`基类创建多个`PickupItem`蓝图

创建`PickupItem`类后，打开其代码在 Visual Studio 中。

`APickupItem`类将需要相当多的成员，如下所示：

+   一个用于被拾取物品名称的`FString`变量

+   一个用于被拾取物品数量的`int32`变量

+   一个用于碰撞的球体的`USphereComponent`变量，以便拾取物品

+   一个用于保存实际`Mesh`的`UStaticMeshComponent`变量

+   一个用于表示物品的图标的`UTexture2D`变量

+   一个 HUD 的指针（稍后我们将初始化）

`PickupItem.h`中的代码如下：

```cpp
// Fill out your copyright notice in the Description page of Project Settings.

#pragma once

#include "CoreMinimal.h"
#include "GameFramework/Actor.h"
#include "Components/SphereComponent.h"
#include "Components/StaticMeshComponent.h"
#include "PickupItem.generated.h"

UCLASS()
class GOLDENEGG_API APickupItem : public AActor
{
    GENERATED_BODY()

public:    
    // Sets default values for this actor's properties
    APickupItem(const FObjectInitializer& ObjectInitializer);

    // The name of the item you are getting 
    UPROPERTY(EditAnywhere, BlueprintReadWrite, Category = Item)
        FString Name;

    // How much you are getting 
    UPROPERTY(EditAnywhere, BlueprintReadWrite, Category = Item)
        int32 Quantity;

    // the sphere you collide with to pick item up 
    UPROPERTY(VisibleDefaultsOnly, BlueprintReadOnly, Category = Item)
        USphereComponent* ProxSphere;

    // The mesh of the item 
    UPROPERTY(VisibleDefaultsOnly, BlueprintReadOnly, Category = Item)
        UStaticMeshComponent* Mesh;
    // The icon that represents the object in UI/canvas 
    UPROPERTY(EditAnywhere, BlueprintReadWrite, Category = Item) 
        UTexture2D* Icon; 
    // When something comes inside ProxSphere, this function runs 
    UFUNCTION(BlueprintNativeEvent, Category = Collision) 
        void Prox(UPrimitiveComponent* OverlappedComponent, AActor* OtherActor, UPrimitiveComponent* OtherComp,
            int32 OtherBodyIndex, bool bFromSweep, const FHitResult& SweepResult);
        virtual int Prox_Implementation(UPrimitiveComponent* OverlappedComponent, AActor* OtherActor, UPrimitiveComponent* OtherComp,
        int32 OtherBodyIndex, bool bFromSweep, const FHitResult& SweepResult);

protected:
    // Called when the game starts or when spawned
    virtual void BeginPlay() override;

public:    
    // Called every frame
    virtual void Tick(float DeltaTime) override;
};
```

所有这些`UPROPERTY()`声明的目的是使`APickupItem`完全可由蓝图配置。例如，Pickup 类别中的项目将在蓝图编辑器中显示如下：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/d5a2836e-5c31-47f8-8303-68ad756e0f6d.png)

在`PickupItem.cpp`文件中，完成`APickupItem`类的构造函数，如下面的代码所示：

```cpp
APickupItem::APickupItem(const FObjectInitializer& ObjectInitializer)
    : Super(ObjectInitializer)
{
    Name = "UNKNOWN ITEM";
    Quantity = 0;

    // initialize the unreal objects 
    ProxSphere = ObjectInitializer.CreateDefaultSubobject<USphereComponent>(this,
        TEXT("ProxSphere"));  
    Mesh = ObjectInitializer.CreateDefaultSubobject<UStaticMeshComponent>(this,
            TEXT("Mesh"));

    // make the root object the Mesh 
    RootComponent = Mesh;
    Mesh->SetSimulatePhysics(true);

    // Code to make APickupItem::Prox() run when this 
    // object's proximity sphere overlaps another actor. 
    ProxSphere->OnComponentBeginOverlap.AddDynamic(this, &APickupItem::Prox);
    ProxSphere->AttachToComponent(Mesh, FAttachmentTransformRules::KeepWorldTransform); // very important!              
}
```

在前两行中，我们对`Name`和`Quantity`进行了初始化，使其值在游戏设计师看来是未初始化的。我们使用大写字母，以便设计师可以清楚地看到该变量以前从未被初始化过。

然后，我们使用`ObjectInitializer.CreateDefaultSubobject`初始化`ProxSphere`和`Mesh`组件。新初始化的对象可能已经初始化了一些默认值，但`Mesh`将为空。您将不得不稍后在蓝图中加载实际的网格。

对于网格，我们将其设置为模拟真实物理，以便如果放下或移动，捡起物品会弹跳和滚动。特别注意`ProxSphere->AttachToComponent(Mesh, FAttachmentTransformRules::KeepWorldTransform);`这一行。这行告诉您确保捡起物品的`ProxSphere`组件附加到`Mesh`根组件。这意味着当网格在级别中移动时，`ProxSphere`会跟随移动。如果忘记了这一步（或者反过来做了），那么`ProxSphere`在弹跳时将不会跟随网格。

# 根组件

在上述代码中，我们将`APickupItem`的`RootComponent`分配给了`Mesh`对象。`RootComponent`成员是`AActor`基类的一部分，因此每个`AActor`及其派生类都有一个根组件。根组件基本上是对象的核心，并且还定义了您与对象的碰撞方式。`RootComponent`对象在`Actor.h`文件中定义，如下面的代码所示：

```cpp
/** Collision primitive that defines the transform (location, rotation, scale) of this Actor. */
    UPROPERTY(BlueprintGetter=K2_GetRootComponent, Category="Utilities|Transformation")
    USceneComponent* RootComponent;
```

因此，UE4 的创建者打算`RootComponent`始终是对碰撞原语的引用。有时，碰撞原语可以是胶囊形状，其他时候可以是球形甚至是盒形，或者可以是任意形状，就像我们的情况一样，具有网格。然而，角落的盒子可能会被卡在墙上，因此很少有角色应该有盒状的根组件。通常更喜欢圆形。`RootComponent`属性显示在蓝图中，您可以在那里查看和操作它：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/3283ccec-e589-4b8e-a8b9-140c368d86d8.png)

创建基于 PickupItem 类的蓝图后，可以从其蓝图中编辑 ProxSphere 根组件

最后，`Prox_Implementation`函数得到实现，如下所示：

```cpp
int APickupItem::Prox_Implementation(UPrimitiveComponent* OverlappedComponent, AActor* OtherActor, UPrimitiveComponent* OtherComp,
    int32 OtherBodyIndex, bool bFromSweep, const FHitResult& SweepResult)
{
    // if the overlapped actor is NOT the player, 
    // you simply should return 
    if (Cast<AAvatar>(OtherActor) == nullptr)
    {
        return -1;
    }

    // Get a reference to the player avatar, to give him 
    // the item 
    AAvatar *avatar = Cast<AAvatar>(UGameplayStatics::GetPlayerPawn(GetWorld(), 0));

    // Let the player pick up item 
    // Notice use of keyword this! 
    // That is how _this_ Pickup can refer to itself. 
    avatar->Pickup(this);

    // Get a reference to the controller 
    APlayerController* PController = GetWorld()->GetFirstPlayerController();

    // Get a reference to the HUD from the controller 
    AMyHUD* hud = Cast<AMyHUD>(PController->GetHUD());
    hud->addMessage(Message(Icon, FString("Picked up ") + FString::FromInt(Quantity) + FString(" ") + Name, 5.f, FColor::White)
);

    Destroy();

    return 0;
}
```

此外，请确保在文件顶部添加以下内容：

```cpp
#include "Avatar.h"
#include "MyHUD.h"
#include "Kismet/GameplayStatics.h"
```

这里有一些非常重要的提示：首先，我们必须访问一些*全局*对象来获取我们需要的对象。通过这些函数，我们将访问三个主要对象，这些对象操作 HUD：

+   控制器 (`APlayerController`)

+   HUD (`AMyHUD`)

+   玩家本身（`AAvatar`）

游戏实例中只有这三种类型的对象中的一个。UE4 使得找到它们变得很容易。

此外，为了编译这个，您还需要在`MyHud.h`中的`Message`结构中添加另一个构造函数。您需要一个可以让您像这样传递图像的构造函数：

```cpp
Message(UTexture2D* img, FString iMessage, float iTime, FColor iColor)
    {
        tex = img;
        message = iMessage;
        time = iTime;
        color = iColor;
    }
```

要编译，您还需要向结构体添加另一个变量`UTexture2D* tex;`。您还需要在 Avatar 中实现 Pickup 函数。

# 获取 avatar

`player`类对象可以通过简单调用以下代码从代码的任何地方找到：

```cpp
AAvatar *avatar = Cast<AAvatar>( 
  UGameplayStatics::GetPlayerPawn( GetWorld(), 0 ) ); 
```

然后我们通过调用之前定义的`AAvatar::Pickup()`函数将物品传递给玩家。

因为 PlayerPawn 对象实际上是一个 AAvatar 实例，所以我们将结果转换为 AAvatar 类，使用 Cast<AAvatar>命令。UGameplayStatics 函数族可以在代码的任何地方访问，因为它们是全局函数。

# 获取玩家控制器

检索玩家控制器也可以通过全局函数完成：

```cpp
APlayerController* PController = 
  GetWorld()->GetFirstPlayerController(); 
```

`GetWorld()`函数实际上是在`UObject`基类中定义的。由于所有 UE4 对象都派生自`UObject`，因此游戏中的任何对象实际上都可以访问`world`对象。

# 获取 HUD

尽管这种组织可能一开始看起来很奇怪，但 HUD 实际上是附加到玩家的控制器上的。您可以按如下方式检索 HUD：

```cpp
AMyHUD* hud = Cast<AMyHUD>( PController->GetHUD() ); 
```

我们对 HUD 对象进行转换，因为我们之前在蓝图中将 HUD 设置为`AMyHUD`实例。由于我们将经常使用 HUD，我们实际上可以在`APickupItem`类内部存储一个永久指针指向 HUD。我们稍后会讨论这一点。

接下来，我们实现`AAvatar::Pickup`，它将一个`APickupItem`类型的对象添加到 Avatar 的背包中：

```cpp
void AAvatar::Pickup(APickupItem *item)
{
    if (Backpack.Find(item->Name))
    {
        // the item was already in the pack.. increase qty of it 
        Backpack[item->Name] += item->Quantity;
    }
    else
    {
        // the item wasn't in the pack before, add it in now 
        Backpack.Add(item->Name, item->Quantity);
        // record ref to the tex the first time it is picked up 
        Icons.Add(item->Name, item->Icon);
    }
}
```

还要确保在文件顶部添加`#include "PickupItem.h"`。

在前面的代码中，我们检查玩家刚刚获得的捡起物品是否已经在他的背包中。如果是，我们增加它的数量。如果不在他的背包中，我们将其添加到他的背包和`Icons`映射中。

要将捡起物品添加到背包中，请使用以下代码行：

```cpp
avatar->Pickup( this ); 
```

`APickupItem::Prox_Implementation`是调用该成员函数的方式。

现在，当玩家按下*I*键时，我们需要在 HUD 中显示背包的内容。

# 绘制玩家库存

像*暗黑破坏神*这样的游戏中的库存屏幕会显示一个弹出窗口，其中过去捡起的物品的图标排列在一个网格中。我们可以在 UE4 中实现这种行为。

在 UE4 中绘制 UI 有许多方法。最基本的方法是简单地使用`HUD::DrawTexture()`调用。另一种方法是使用 Slate。还有一种方法是使用最新的 UE4 UI 功能：**虚幻运动图形**（**UMG**）设计师。

Slate 使用声明性语法在 C++中布局 UI 元素。Slate 最适合菜单等。UMG 自 UE 4.5 以来一直存在，并使用基于蓝图的工作流程。由于我们这里的重点是使用 C++代码的练习，我们将坚持使用`HUD::DrawTexture()`实现，但我们将在后面的章节中介绍 UMG。这意味着我们将不得不在我们的代码中管理所有与库存有关的数据。

# 使用 HUD::DrawTexture()

`HUD::DrawTexture()`是我们将在此时用来将库存绘制到屏幕上的方法。我们将分两步实现这一点：

1.  当用户按下*I*键时，我们将库存的内容推送到 HUD。

1.  然后，我们以网格方式将图标渲染到 HUD 中。

为了保存有关小部件如何渲染的所有信息，我们声明了一个简单的结构来保存有关它使用的图标、当前位置和当前大小的信息。

这是`Icon`和`Widget`结构的样子：

```cpp
struct Icon 
{ 
  FString name; 
  UTexture2D* tex; 
  Icon(){ name = "UNKNOWN ICON"; tex = 0; } 
  Icon( FString& iName, UTexture2D* iTex ) 
  { 
    name = iName; 
    tex = iTex; 
  } 
}; 

struct Widget 
{ 
  Icon icon; 
  FVector2D pos, size; 
  Widget(Icon iicon) 
  { 
    icon = iicon; 
  } 
  float left(){ return pos.X; } 
  float right(){ return pos.X + size.X; } 
  float top(){ return pos.Y; } 
  float bottom(){ return pos.Y + size.Y; } 
}; 
```

您可以将这些结构声明添加到`MyHUD.h`的顶部，或者您可以将它们添加到一个单独的文件中，并在使用这些结构的任何地方包含该文件。

注意`Widget`结构上的四个成员函数，以获取小部件的`left()`、`right()`、`top()`和`bottom()`函数。我们稍后将使用这些函数来确定点击点是否在框内。

1.  接下来，我们在`AMyHUD`类中声明将小部件渲染到屏幕上的函数。首先，在`MyHud.h`中，添加一个数组来保存小部件，以及一个向量来保存屏幕尺寸：

```cpp
    // New! An array of widgets for display 
    TArray<Widget> widgets;
    //Hold screen dimensions
    FVector2D dims;
```

1.  还要添加一行`void DrawWidgets();`。然后，将其添加到`MyHud.cpp`中：

```cpp
void AMyHUD::DrawWidgets()
{
    for (int c = 0; c < widgets.Num(); c++)
    {
        DrawTexture(widgets[c].icon.tex, widgets[c].pos.X,
            widgets[c].pos.Y, widgets[c].size.X, widgets[c].size.Y, 0, 0,
            1, 1);    DrawText(widgets[c].icon.name, FLinearColor::Yellow,
                widgets[c].pos.X, widgets[c].pos.Y, hudFont, .6f, false);
    }
}
```

1.  应该在`DrawHUD()`函数中添加对`DrawWidgets()`函数的调用，并且您可能希望将当前的消息处理代码移动到一个单独的`DrawMessages`函数中，以便您可以随后获取这一点（或者只是保留原始代码）：

```cpp
void AMyHUD::DrawHUD()
{
    Super::DrawHUD();
    // dims only exist here in stock variable Canvas 
    // Update them so use in addWidget() 
    const FVector2D ViewportSize = FVector2D(GEngine->GameViewport->Viewport->GetSizeXY());
    dims.X = ViewportSize.X;
    dims.Y = ViewportSize.Y;
    DrawMessages();
    DrawWidgets();
}
```

1.  接下来，我们将填充`ToggleInventory()`函数。这是用户按下*I*键时运行的函数：

```cpp
void AAvatar::ToggleInventory()
{
    // Get the controller & hud 
    APlayerController* PController = GetWorld()->GetFirstPlayerController();
    AMyHUD* hud = Cast<AMyHUD>(PController->GetHUD());

    // If inventory is displayed, undisplay it. 
    if (inventoryShowing)
    {
        hud->clearWidgets();
        inventoryShowing = false;
        PController->bShowMouseCursor = false;
        return;
    }

    // Otherwise, display the player's inventory 
    inventoryShowing = true;
    PController->bShowMouseCursor = true;
    for (TMap<FString, int>::TIterator it =
        Backpack.CreateIterator(); it; ++it)
    {
        // Combine string name of the item, with qty eg Cow x 5 
        FString fs = it->Key + FString::Printf(TEXT(" x %d"), it->Value);
        UTexture2D* tex;
        if (Icons.Find(it->Key))
        {
            tex = Icons[it->Key];
            hud->addWidget(Widget(Icon(fs, tex)));
        }    
    }
}
```

1.  为了使前面的代码编译，我们需要向`AMyHUD`添加两个函数：

```cpp
void AMyHUD::addWidget( Widget widget ) 
{ 
  // find the pos of the widget based on the grid. 
  // draw the icons.. 
  FVector2D start( 200, 200 ), pad( 12, 12 ); 
  widget.size = FVector2D( 100, 100 ); 
  widget.pos = start; 
  // compute the position here 
  for( int c = 0; c < widgets.Num(); c++ ) 
  { 
    // Move the position to the right a bit. 
    widget.pos.X += widget.size.X + pad.X; 
    // If there is no more room to the right then 
    // jump to the next line 
    if( widget.pos.X + widget.size.X > dims.X ) 
    { 
      widget.pos.X = start.X; 
      widget.pos.Y += widget.size.Y + pad.Y; 
    } 
  } 
  widgets.Add( widget ); 
} 

void AMyHUD::clearWidgets()
{
    widgets.Empty();
}
```

同样，确保在`.h`文件中添加以下内容：

```cpp
    void clearWidgets();
    void addWidget(Widget widget);
```

1.  我们继续使用`inventoryShowing`中的`Boolean`变量，以告诉我们库存当前是否显示。当显示库存时，我们还显示鼠标，以便用户知道他点击的是什么。此外，当显示库存时，玩家的自由运动被禁用。禁用玩家的自由运动的最简单方法是在实际移动之前从移动函数中返回。以下代码是一个示例：

```cpp
void AAvatar::Yaw( float amount ) 
{ 
  if( inventoryShowing ) 
  { 
    return; // when my inventory is showing, 
    // player can't move 
  } 
  AddControllerYawInput(200.f*amount * GetWorld()- 
   >GetDeltaSeconds()); 
} 
```

# 练习

在每个移动函数中添加`if( inventoryShowing ) { return; }`，这样当库存显示时，它将阻止所有移动。

# 检测库存项目点击

我们可以通过简单的测试来检测是否有人点击了我们的库存项目，以查看点是否在对象的`rect`（矩形）内。通过检查点击点与包含要测试区域的`rect`的内容，可以进行此测试。

要针对`rect`进行检查，向`struct Widget`添加以下成员函数：

```cpp
struct Widget 
{ 
  // .. rest of struct same as before .. 
  bool hit( FVector2D p ) 
  { 
    // +---+ top (0) 
    // |   | 
    // +---+ bottom (2) (bottom > top) 
    // L   R 
    return p.X > left() && p.X < right() && p.Y > top() && p.Y <  
     bottom(); 
  } 
}; 
```

针对`rect`的测试如下：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/d31e3ea5-d9e9-4708-b3a0-6e15ee9f845c.png)

因此，如果`p.X`全部是命中：

+   `left() (p.X > left())`的右侧

+   `right() (p.X < right())`的左侧

+   在`top() (p.Y > top())`的下方

+   在`bottom() (p.Y < bottom())`的上方

请记住，在 UE4（以及通常的 UI 渲染中），*y*轴是反转的。换句话说，在 UE4 中，y 向下。这意味着`top()`小于`bottom()`，因为原点（`(0, 0)`点）位于屏幕的左上角。

# 拖动元素

我们可以轻松拖动元素：

1.  启用拖动的第一步是响应左鼠标按钮点击。首先，我们将编写在单击左鼠标按钮时执行的函数。在`Avatar.h`文件中，向类声明添加以下原型：

```cpp
void MouseClicked();
```

1.  在`Avatar.cpp`文件中，我们可以添加一个函数来执行鼠标点击，并将点击请求传递给 HUD，如下所示：

```cpp
void AAvatar::MouseClicked() 
{ 
  APlayerController* PController = GetWorld()- 
   >GetFirstPlayerController(); 
  AMyHUD* hud = Cast<AMyHUD>( PController->GetHUD() ); 
  hud->MouseClicked(); 
} 
```

1.  然后，在`AAvatar::SetupPlayerInputComponent`中，我们必须附加我们的响应者：

```cpp
PlayerInputComponent->BindAction( "MouseClickedLMB", IE_Pressed, this, &AAvatar::MouseClicked );
```

以下屏幕截图显示了如何设置绑定：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/4fcda832-ff9a-491d-9c16-031a2ca91188.png)

1.  向`AMyHUD`类添加一个成员，以及两个新的函数定义：

```cpp
    Widget* heldWidget;  // hold the last touched Widget in memory 

    void MouseClicked();
    void MouseMoved();
```

1.  接下来，在`AMyHUD::MouseClicked()`中，我们开始搜索命中的`Widget`：

```cpp
void AMyHUD::MouseClicked()
{
    FVector2D mouse;
    APlayerController* PController = GetWorld()->GetFirstPlayerController();
    PController->GetMousePosition(mouse.X, mouse.Y);
    heldWidget = NULL; // clear handle on last held widget 
                       // go and see if mouse xy click pos hits any widgets 
    for (int c = 0; c < widgets.Num(); c++)
    {
        if (widgets[c].hit(mouse))
        {
            heldWidget = &widgets[c];// save widget 
            return;                  // stop checking 
        }
    }
}
```

1.  在`AMyHUD::MouseClicked`函数中，我们循环遍历屏幕上的所有小部件，并检查当前鼠标位置是否命中。您可以随时通过简单查找`PController->GetMousePosition()`来获取控制器的当前鼠标位置。 

1.  每个小部件都与当前鼠标位置进行检查，鼠标点击命中的小部件将在鼠标拖动时移动。一旦确定了命中的小部件，我们就可以停止检查，所以我们从`MouseClicked()`函数中得到一个`return`值。

1.  然而，仅仅命中小部件是不够的。当鼠标移动时，我们需要拖动被命中的小部件。为此，我们需要在`AMyHUD`中实现`MouseMoved()`函数：

```cpp
void AMyHUD::MouseMoved()
{
    static FVector2D lastMouse;
    FVector2D thisMouse, dMouse;
    APlayerController* PController = GetWorld()->GetFirstPlayerController();
    PController->GetMousePosition(thisMouse.X, thisMouse.Y);
    dMouse = thisMouse - lastMouse;
    // See if the left mouse has been held down for 
    // more than 0 seconds. if it has been held down, 
    // then the drag can commence. 
    float time = PController->GetInputKeyTimeDown(
        EKeys::LeftMouseButton);
    if (time > 0.f && heldWidget)
    {
        // the mouse is being held down. 
        // move the widget by displacement amt 
        heldWidget->pos.X += dMouse.X;
        heldWidget->pos.Y += dMouse.Y; // y inverted 
    }
    lastMouse = thisMouse;
}
```

拖动函数查看鼠标位置在上一帧和本帧之间的差异，并移动所选小部件相应的距离。一个`static`变量（局部范围内的全局变量）用于在`MouseMoved()`函数调用之间记住`lastMouse`位置。

我们如何将鼠标的移动链接到在`AMyHUD`中运行`MouseMoved()`函数？如果您记得，我们已经在`Avatar`类中连接了鼠标移动。我们使用的两个函数是这些：

+   `AAvatar::Pitch()`（y 轴）

+   `AAvatar::Yaw()`（x 轴）

扩展这些函数将使您能够将鼠标输入传递给 HUD。我现在将向您展示`Yaw`函数，您可以从中推断出`Pitch`将如何工作：

```cpp
void AAvatar::Yaw( float amount ) 
{ 
  //x axis 
  if( inventoryShowing ) 
  { 
    // When the inventory is showing, 
    // pass the input to the HUD 
    APlayerController* PController = GetWorld()- 
     >GetFirstPlayerController(); 
    AMyHUD* hud = Cast<AMyHUD>( PController->GetHUD() ); 
    hud->MouseMoved(); 
    return; 
  } 
  else 
  { 
    AddControllerYawInput(200.f*amount * GetWorld()- 
     >GetDeltaSeconds()); 
  } 
} 
```

`AAvatar::Yaw()`函数首先检查库存是否显示。如果显示，输入将直接路由到 HUD，而不影响`Avatar`。如果 HUD 没有显示，输入将直接传递给`Avatar`。

确保你在文件顶部添加了`#include "MyHUD.h"`，这样才能正常工作。

# 练习

1.  完成`AAvatar::Pitch()`函数（y 轴）以将输入路由到 HUD 而不是`Avatar`。

1.  从第八章中的 NPC 角色，*角色和棋子*中获取，并在玩家靠近它们时给予玩家一个物品（比如`GoldenEgg`）。

# 把事情放在一起

现在你有了所有这些代码，你会想把它们放在一起并看到它们运行。使用你复制过来的 Meshes 创建新的蓝图，方法是在类查看器中右键单击`PickupItem`类并选择创建蓝图类，就像我们之前做的那样。设置值（包括 Mesh），然后将对象拖入游戏中。当你走进它们时，你会收到一个被拾取的消息。此时，你可以按*I*键查看你的库存。

# 总结

在本章中，我们介绍了如何为玩家设置多个拾取物品，以便在关卡中显示并拾取。我们还在屏幕上显示了它们，并添加了拖动小部件的功能。在第十一章中，*怪物*，我们将介绍怪物以及如何让它们跟随并攻击玩家。
