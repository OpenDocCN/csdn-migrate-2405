# Unreal 游戏开发项目（四）

> 原文：[`annas-archive.org/md5/697adf25bb6fdefd7e5915903f33de14`](https://annas-archive.org/md5/697adf25bb6fdefd7e5915903f33de14)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十二章：敌人人工智能

概述

本章以简要回顾《超级横向卷轴》游戏中敌人人工智能的行为方式开始。然后，你将学习虚幻引擎 4 中的控制器，并学习如何创建一个 AI 控制器。接着，你将学习如何通过在游戏的主要关卡中添加导航网格来更多地了解虚幻引擎 4 中的 AI 导航。

通过本章的学习，你将能够创建一个敌人可以移动的可导航空间。你还将能够创建一个敌人 AI 角色，并使用黑板和行为树在不同位置之间导航。最后，你将学会如何创建和实现一个玩家投射物类，并为其添加视觉元素。

# 介绍

在上一章中，你使用了动画混合、动画插槽、动画蓝图和混合函数（如每骨层混合）为玩家角色添加了分层动画。

在本章中，你将学习如何使用导航网格在游戏世界内创建一个可导航的空间，使敌人可以在其中移动。定义关卡的可导航空间对于允许人工智能访问和移动到关卡的特定区域至关重要。

接下来，你将创建一个敌人 AI 角色，使用虚幻引擎 4 中的*黑板*和*行为树*等 AI 工具在游戏世界内的巡逻点位置之间导航。

你还将学习如何使用导航网格在游戏世界内创建一个可导航的空间，使敌人可以在其中移动。定义关卡的可导航空间对于允许 AI 访问和移动到关卡的特定区域至关重要。

最后，你将学习如何在 C++中创建一个玩家投射物类，以及如何实现`OnHit()`碰撞事件函数来识别并记录投射物击中游戏世界中的物体。除了创建类之外，你还将创建这个玩家投射物类的蓝图，并为玩家投射物添加视觉元素，如静态网格。

《超级横向卷轴》游戏终于要完成了，通过本章的学习，你将在很好的位置上，可以继续学习*第十四章*《生成玩家投射物》，在那里你将处理游戏的一些细节，如音效和视觉效果。

本章的主要重点是使用人工智能使你在*第十二章*《动画混合和蒙太奇》中创建的 C++敌人类活灵活现。虚幻引擎 4 使用许多不同的工具来实现人工智能，如 AI 控制器、黑板和行为树，你将在本章中学习并使用这些工具。在你深入了解这些系统之前，让我们花一点时间了解近年来游戏中人工智能的使用方式。自从《超级马里奥兄弟》以来，人工智能显然已经发展了许多。

# 敌人人工智能

什么是人工智能？这个术语可以有很多不同的含义，取决于它所用于的领域和背景，因此让我们以一种对视频游戏主题有意义的方式来定义它。

**AI**是一个意识到自己环境并做出选择以最优化地实现其预期目的的实体。AI 使用所谓的**有限状态机**根据其从用户或环境接收到的输入切换多个状态之间。例如，视频游戏中的 AI 可以根据其当前的健康状态在攻击状态和防御状态之间切换。

在《你好邻居》和《异形：孤立》等游戏中，AI 的目标是尽可能高效地找到玩家，同时也遵循开发者定义的一些预定模式，以确保玩家可以智胜。《你好邻居》通过让 AI 从玩家过去的行为中学习并试图根据所学知识智胜玩家，为其 AI 添加了一个非常有创意的元素。

您可以在游戏发布商*TinyBuild Games*的视频中找到有关 AI 如何工作的信息：[`www.youtube.com/watch?v=Hu7Z52RaBGk`](https://www.youtube.com/watch?v=Hu7Z52RaBGk)。

有趣和有趣的 AI 对于任何游戏都至关重要，取决于您正在制作的游戏，这可能意味着非常复杂或非常简单的 AI。您将为`SuperSideScroller`游戏创建的 AI 不会像之前提到的那些那样复杂，但它将满足我们希望创建的游戏的需求。

让我们来分析一下敌人的行为方式：

+   敌人将是一个非常简单的敌人，具有基本的来回移动模式，不会支持任何攻击；只有与玩家角色碰撞，它们才能造成伤害。

+   然而，我们需要设置敌人 AI 要移动的位置。

+   接下来，我们决定 AI 是否应该改变位置，是否应该在不同位置之间不断移动，或者在选择新位置移动之间是否应该有暂停？

幸运的是，对于我们来说，虚幻引擎 4 为我们提供了一系列工具，我们可以使用这些工具来开发复杂的 AI。然而，在我们的项目中，我们将使用这些工具来创建一个简单的敌人类型。让我们首先讨论一下虚幻引擎 4 中的 AI 控制器是什么。

# AI 控制器

让我们讨论**玩家控制器**和**AI 控制器**之间的主要区别是什么。这两个角色都是从基本的**Controller 类**派生出来的，控制器用于控制一个**Pawn**或**Character**的行动。

玩家控制器依赖于实际玩家的输入，而 AI 控制器则将 AI 应用于他们所拥有的角色，并根据 AI 设置的规则对环境做出响应。通过这样做，AI 可以根据玩家和其他外部因素做出智能决策，而无需实际玩家明确告诉它这样做。多个相同的 AI pawn 实例可以共享相同的 AI 控制器，并且相同的 AI 控制器可以用于不同的 AI pawn 类。像虚幻引擎 4 中的所有角色一样，AI 是通过`UWorld`类生成的。

注意

您将在*第十四章*“生成玩家投射物”中了解更多关于`UWorld`类的信息，但作为参考，请在这里阅读更多：[`docs.unrealengine.com/en-US/API/Runtime/Engine/Engine/UWorld/index.html`](https://docs.unrealengine.com/en-US/API/Runtime/Engine/Engine/UWorld/index.html)。

玩家控制器和 AI 控制器的最重要的方面是它们将控制的 pawns。让我们更多地了解 AI 控制器如何处理这一点。

## 自动拥有 AI

像所有控制器一样，AI 控制器必须拥有一个*pawn*。在 C++中，您可以使用以下函数来拥有一个 pawn：

```cpp
void AController::Possess(APawn* InPawn)
```

您还可以使用以下功能取消拥有一个 pawn：

```cpp
void AController::UnPossess()
```

还有`void AController::OnPossess(APawn* InPawn)`和`void AController::OnUnPossess()`函数，分别在调用`Possess()`和`UnPossess()`函数时调用。

在 AI 方面，特别是在虚幻引擎 4 的背景下，AI Pawns 或 Characters 可以被 AI Controller 占有的方法有两种。让我们看看这些选项：

+   “放置在世界中”：这是您将在此项目中处理 AI 的第一种方法；一旦游戏开始，您将手动将这些敌人角色放置到游戏世界中，AI 将在游戏开始后处理其余部分。

+   “生成”：这是第二种方法，稍微复杂一些，因为它需要一个显式的函数调用，无论是在 C++还是 Blueprint 中，都需要“生成”指定类的实例。`Spawn Actor`方法需要一些参数，包括`World`对象和`Transform`参数，如`Location`和`Rotation`，以确保正确生成实例。

+   `放置在世界中或生成`：如果您不确定要使用哪种方法，一个安全的选项是`放置在世界中或生成`；这样两种方法都受支持。

为了`SuperSideScroller`游戏，您将使用`Placed In World`选项，因为您将手动放置游戏级别中的 AI。

## 练习 13.01：实现 AI 控制器

在敌人 pawn 可以执行任何操作之前，它需要被 AI 控制器占有。这也需要在 AI 执行任何逻辑之前发生。这个练习将在虚幻引擎 4 编辑器中进行。完成这个练习后，您将创建一个 AI 控制器并将其应用于您在上一章中创建的敌人。让我们开始创建 AI 控制器角色。

以下步骤将帮助您完成这个练习：

1.  转到`内容浏览器`界面，导航到`内容/Enemy`目录。

1.  *右键单击*`Enemy`文件夹，选择`新建文件夹`选项。将这个新文件夹命名为`AI`。在新的`AI`文件夹目录中，*右键单击*并选择`蓝图类`选项。

1.  从`选择父类`对话框中，展开`所有类`并手动搜索`AIController`类。

1.  *左键单击*此类选项，然后*左键单击*底部的绿色`选择`选项以从此类创建一个新的`蓝图`。请参考以下截图以了解在哪里找到`AIController`类。还要注意悬停在类选项上时出现的工具提示；它包含有关开发人员的有用信息：![图 13.1：在选择父类对话框中找到的 AIController 资产类](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_13_01.jpg)

图 13.1：在选择父类对话框中找到的 AIController 资产类

1.  创建了这个新的`AIController 蓝图`后，将此资产命名为`BP_AIControllerEnemy`。

AI 控制器已创建并命名，现在是将此资产分配给您在上一章中创建的第一个敌人蓝图的时候了。

1.  直接导航到`/Enemy/Blueprints`，找到`BP_Enemy`。*双击*打开此蓝图。

1.  在第一个敌人`蓝图`的`详细信息`面板中，有一个标有`Pawn`的部分。这是您可以设置关于`Pawn`或`Character`的 AI 功能的不同参数的地方。

1.  `AI 控制器类`参数确定了要为此敌人使用哪个 AI 控制器，*左键单击*下拉菜单以查找并选择您之前创建的 AI 控制器；即`BP_AIController_Enemy`。

完成这个练习后，敌人 AI 现在知道要使用哪个 AI 控制器。这是至关重要的，因为在 AI 控制器中，AI 将使用并执行您将在本章后面创建的行为树。

AI 控制器现在已分配给敌人，这意味着您几乎可以开始为这个 AI 开发实际的智能了。在这样做之前，还有一个重要的话题需要讨论，那就是导航网格。

# 导航网格

任何 AI 的最关键方面之一，尤其是在视频游戏中，就是以复杂的方式导航环境。在虚幻引擎 4 中，引擎有一种方法告诉 AI 哪些环境部分是可导航的，哪些部分不是。这是通过**导航网格**或**Nav Mesh**来实现的。

这里的 Mesh 一词有误导性，因为它是通过编辑器中的一个体积来实现的。我们需要在我们的级别中有一个导航网格，这样我们的 AI 才能有效地导航游戏世界的可玩范围。我们将在下面的练习中一起添加一个。

虚幻引擎 4 还支持`动态导航网格`，允许导航网格在动态对象在环境中移动时实时更新。这导致 AI 能够识别环境中的这些变化，并相应地更新它们的路径/导航。本书不会涵盖这一点，但您可以通过`项目设置 -> 导航网格 -> 运行时生成`访问配置选项。

## 练习 13.02：为 AI 敌人实现导航网格体积

在这个练习中，您将向`SideScrollerExampleMap`添加一个导航网格，并探索在虚幻引擎 4 中导航网格的工作原理。您还将学习如何为游戏的需求参数化这个体积。这个练习将在虚幻引擎 4 编辑器中进行。

通过本练习，您将更加了解导航网格。您还将能够在接下来的活动中在自己的关卡中实现这个体积。让我们开始向关卡添加导航网格体积。

以下步骤将帮助您完成这个练习：

1.  如果您尚未打开地图，请通过导航到`文件`并*左键单击*`打开级别`选项来打开`SideScrollerExampleMap`。从`打开级别`对话框，导航到`/SideScrollerCPP/Maps`找到`SideScrollerExampleMap`。用*左键单击*选择此地图，然后在底部*左键单击*`打开`以打开地图。

1.  打开地图后，导航到右侧找到`模式`面板。`模式`面板是一组易于访问的角色类型，如`体积`、`灯光`、`几何`等。在`体积`类别下，您会找到`Nav Mesh Bounds Volume`选项。

1.  *左键单击*并将此体积拖入地图/场景中。默认情况下，您将在编辑器中看到体积的轮廓。按`P`键可可视化体积所包含的`导航`区域，但请确保体积与地面几何相交，以便看到绿色可视化，如下面的屏幕截图所示：![图 13.2：引擎和 AI 感知为可导航的区域轮廓](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_13_02.jpg)

图 13.2：引擎和 AI 感知为可导航的区域轮廓

有了`Nav Mesh`体积后，让我们调整它的形状，使体积延伸到整个关卡区域。之后，您将学习如何调整`Nav Mesh`体积的参数以适应游戏的目的。

1.  *左键单击*选择`NavMeshBoundsVolume`并导航到其`详细信息`面板。有一个标有`刷设置`的部分，允许您调整体积的形状和大小。找到最适合您的值。一些建议的设置是`刷类型：添加`，`刷形状：盒子`，`X：3000.0`，`Y：3000.0`和`Z：3000.0`。

注意，当`NavMeshBoundsVolume`的形状和尺寸发生变化时，`Nav Mesh`将调整并重新计算可导航区域。这可以在下面的屏幕截图中看到。您还会注意到上层平台是不可导航的；您稍后会修复这个问题。

![图 13.3：现在，NavMeshBoundsVolume 延伸到整个可播放区域示例地图的区域](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_13_03.jpg)

图 13.3：现在，NavMeshBoundsVolume 延伸到整个可播放区域的示例地图

通过完成这个练习，您已经将第一个`NavMeshBoundsVolume`角色放入了游戏世界，并使用调试键`'P'`可视化了默认地图中的可导航区域。接下来，您将学习更多关于`RecastNavMesh`角色的知识，当将`NavMeshBoundsVolume`放入关卡时，也会创建这个角色。

# 重塑导航网格

当您添加`NavMeshBoundsVolume`时，您可能已经注意到另一个角色被自动创建：一个名为`RecastNavMesh-Default`的`RecastNavMesh`角色。这个`RecastNavMesh`充当了导航网格的“大脑”，因为它包含了调整导航网格所需的参数，直接影响 AI 在给定区域的导航。

以下截图显示了此资产，从 `World Outliner` 选项卡中看到：

![图 13.4：从世界大纲器选项卡中看到的 RecastNavMesh actor](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_13_04.jpg)

图 13.4：从世界大纲器选项卡中看到的 RecastNavMesh actor

注意

`RecastNavMesh` 中存在许多参数，我们只会在本书中涵盖重要的参数。有关更多信息，请查看 [`docs.unrealengine.com/en-US/API/Runtime/NavigationSystem/NavMesh/ARecastNavMesh/index.html`](https://docs.unrealengine.com/en-US/API/Runtime/NavigationSystem/NavMesh/ARecastNavMesh/index.html)。

现在只有两个对您重要的主要部分：

1.  `Display`：`Display` 部分，顾名思义，只包含影响 `NavMeshBoundsVolume` 生成的可导航区域的可视化调试显示的参数。建议您尝试切换此类别下的每个参数，以查看它如何影响生成的 Nav Mesh 的显示。

1.  `Generation`：`Generation` 类别包含一组值，作为 Nav Mesh 生成和确定哪些几何区域是可导航的，哪些不可导航的规则集。这里有很多选项，这可能使概念非常令人生畏，但让我们只讨论这个类别下的一些参数：

+   `Cell Size` 指的是 Nav Mesh 在区域内生成可导航空间的精度。您将在本练习的下一步中更新此值，因此您将看到这如何实时影响可导航区域。

+   `Agent Radius` 指的是将要在该区域导航的角色的半径。在您的游戏中，这里设置的半径是具有最大半径的角色的碰撞组件的半径。

+   `Agent Height` 指的是将要在该区域导航的角色的高度。在您的游戏中，这里设置的高度是具有最大 Half Height 的角色的碰撞组件的一半高度。您可以将其乘以 `2.0f` 来获得完整的高度。

+   `Agent Max Slope` 指的是游戏世界中可以存在的斜坡的坡度角度。默认情况下，该值为 `44` 度，这是一个参数，除非您的游戏需要更改，否则您将不会更改。

+   `Agent Max Step Height` 指的是 AI 可以导航的台阶的高度，关于楼梯台阶。与 `Agent Max Slope` 类似，这是一个参数，除非您的游戏明确需要更改此值，否则您很可能不会更改。

现在您已经了解了 Recast Nav Mesh 参数，让我们将这些知识付诸实践，进行下一个练习，其中将指导您更改其中一些参数。

## 练习 13.03：重新设置 Nav Mesh 体积参数

现在您在关卡中有了 `Nav Mesh` 体积，是时候改变 `Recast Nav Mesh` actor 的参数，以便 Nav Mesh 允许敌人 AI 在比其他平台更薄的平台上导航。这个练习将在虚幻引擎 4 编辑器中进行。

以下步骤将帮助您完成这个练习：

1.  您将更新 `Cell Size` 和 `Agent Height`，使其适应您的角色的需求和 Nav Mesh 所需的精度：

```cpp
Cell Size: 5.0f
Agent Height: 192.0f
```

以下截图显示了由于我们对 `Cell Size` 进行的更改，上层平台现在是可导航的：

![图 13.5：将 Cell Size 从 19.0f 更改为 5.0f，使狭窄的上层平台可导航上层平台可导航](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_13_05.jpg)

图 13.5：将 Cell Size 从 19.0f 更改为 5.0f，使狭窄的上层平台可导航

通过为 `SuperSideScrollerExampleMap` 设置自己的 `Nav Mesh`，您现在可以继续并为敌人创建 AI 逻辑。在这样做之前，完成以下活动，创建您自己的关卡，具有独特的布局和 `NavMeshBoundsVolume` actor，您可以在本项目的其余部分中使用。

## 活动 13.01：创建新级别

现在你已经在示例地图中添加了`NavMeshBoundsVolume`，是时候为`Super SideScroller`游戏的其余部分创建你自己的地图了。通过创建自己的地图，你将更好地理解`NavMeshBoundsVolume`和`RecastNavMesh`的属性如何影响它们所放置的环境。

注意

在继续解决这个活动之前，如果你需要一个可以用于`SuperSideScroller`游戏剩余章节的示例级别，那就不用担心了——本章附带了`SuperSideScroller.umap`资源，以及一个名为`SuperSideScroller_NoNavMesh`的地图，不包含`NavMeshBoundsVolume`。你可以使用`SuperSideScroller.umap`作为创建自己级别的参考，或者获取如何改进自己级别的想法。你可以在这里下载地图：[`packt.live/3lo7v2f`](https://packt.live/3lo7v2f)。

执行以下步骤创建一个简单的地图：

1.  创建一个`新级别`。

1.  将这个级别命名为`SuperSideScroller`。

1.  使用该项目的`内容浏览器`界面中默认提供的静态网格资源，创建一个有不同高度的有趣空间以导航。将你的玩家角色`Blueprint`添加到级别中，并确保它由`Player Controller 0`控制。

1.  将`NavMeshBoundsVolume` actor 添加到你的级别中，并调整其尺寸，使其适应你创建的空间。在为这个活动提供的示例地图中，设置的尺寸应分别为`1000.0`、`5000.0`和`2000.0`，分别对应*X*、*Y*和*Z*轴。

1.  确保通过按下`P`键启用`NavMeshBoundsVolume`的调试可视化。

1.  调整`RecastNavMesh` actor 的参数，使`NavMeshBoundsVolume`在你的级别中运行良好。在提供的示例地图中，`Cell Size`参数设置为`5.0f`，`Agent Radius`设置为`42.0f`，`Agent Height`设置为`192.0f`。使用这些值作为参考。

预期输出：

![图 13.6：SuperSideScroller 地图](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_13_06.jpg)

图 13.6：SuperSideScroller 地图

通过这个活动的结束，你将拥有一个包含所需的`NavMeshBoundsVolume`和`RecastNavMesh` actor 设置的级别。这将允许我们在接下来的练习中开发的 AI 能够正确运行。再次强调，如果你不确定级别应该是什么样子，请参考提供的示例地图`SuperSideScroller.umap`。现在，是时候开始开发`SuperSideScroller`游戏的 AI 了。

注意

这个活动的解决方案可以在以下网址找到：[`packt.live/338jEBx`](https://packt.live/338jEBx)。

# 行为树和黑板

行为树和黑板共同工作，允许我们的 AI 遵循不同的逻辑路径，并根据各种条件和变量做出决策。

**行为树**（**BT**）是一种可视化脚本工具，允许你根据特定因素和参数告诉一个角色该做什么。例如，一个行为树可以告诉一个 AI 根据 AI 是否能看到玩家而移动到某个位置。

为了举例说明行为树和黑板在游戏中的使用，让我们看看使用虚幻引擎 4 开发的游戏*战争机器 5*。战争机器 5 中的 AI，以及整个战争机器系列，总是试图包抄玩家，或者迫使玩家离开掩体。为了做到这一点，AI 逻辑的一个关键组成部分是知道玩家是谁，以及玩家在哪里。在黑板中存在一个对玩家的引用变量，以及一个用于存储玩家位置的位置向量。确定这些变量如何使用以及 AI 将如何使用这些信息的逻辑是在行为树中执行的。

黑板是你定义的一组变量，这些变量是行为树执行动作和使用这些值进行决策所需的。

行为树是您创建希望 AI 执行的任务的地方，例如移动到某个位置，或执行您创建的自定义任务。与 Unreal Engine 4 中的许多编辑工具一样，行为树在很大程度上是一种非常视觉化的脚本体验。

**黑板**是您定义变量的地方，也称为**键**，然后行为树将引用这些变量。您在这里创建的键可以在**任务**、**服务**和**装饰器**中使用，以根据您希望 AI 如何运行来实现不同的目的。以下截图显示了一个示例变量键集，可以被其关联的行为树引用。

没有黑板，行为树将无法在不同的任务、服务或装饰器之间传递和存储信息，因此变得无用。

![图 13.7：黑板中的一组变量示例可以在行为树中访问](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_13_07.jpg)

图 13.7：黑板中的一组变量示例，可以在行为树中访问

**行为树**由一组**对象**组成 - 即**复合体**、**任务**、**装饰器**和**服务** - 它们共同定义了 AI 根据您设置的条件和逻辑流动来行为和响应的方式。所有行为树都始于所谓的根，逻辑流从这里开始；这不能被修改，只有一个执行分支。让我们更详细地看看这些对象：

## 复合体

复合节点的功能是告诉行为树如何执行任务和其他操作。以下截图显示了 Unreal Engine 默认提供的所有复合节点的完整列表：选择器、序列和简单并行。

复合节点也可以附加装饰器和服务，以便在执行行为树分支之前应用可选条件：

![图 13.8：复合节点的完整列表 - 选择器、序列和简单并行](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_13_08.jpg)

图 13.8：复合节点的完整列表 - 选择器、序列和简单并行

+   `选择器`：选择器复合节点从左到右执行其子节点，并且当其中一个子任务成功时将停止执行。使用以下截图中显示的示例，如果`FinishWithResult`任务成功，父选择器成功，这将导致根再次执行，并且`FinishWithResult`再次执行。这种模式将持续到`FinishWithResult`失败。然后选择器将执行`MakeNoise`。如果`MakeNoise`失败，`选择器`失败，根将再次执行。如果`MakeNoise`任务成功，那么选择器将成功，根将再次执行。根据行为树的流程，如果选择器失败或成功，下一个复合分支将开始执行。在以下截图中，没有其他复合节点，因此如果选择器失败或成功，根节点将再次执行。但是，如果有一个序列复合节点，并且其下有多个选择器节点，每个选择器将尝试按顺序执行其子节点。无论成功与否，每个选择器都将依次执行：![图 13.9：选择器复合节点在行为树中的使用示例](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_13_09.jpg)

图 13.9：选择器复合节点在行为树中的使用示例

请注意，当添加任务和`复合`节点时，您会注意到每个节点的右上角有数字值。这些数字表示这些节点将被执行的顺序。模式遵循*从上到下*，*从左到右*的范式，这些值可以帮助您跟踪顺序。任何未连接的任务或`复合`节点将被赋予值`-1`，以表示未使用。

+   `序列`：`序列`组合节点从左到右执行其子节点，并且当其中一个子任务失败时将停止执行。使用下面截图中显示的示例，如果`移动到`任务成功，那么父`序列`节点将执行`等待`任务。如果`等待`任务成功，那么序列成功，`根`将再次执行。然而，如果`移动到`任务失败，序列将失败，`根`将再次执行，导致`等待`任务永远不会执行：![图 13.10：序列组合节点示例可以在行为树中使用](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_13_10.jpg)

图 13.10：序列组合节点在行为树中的使用示例

+   `简单并行`：`简单并行`组合节点允许您同时执行`任务`和一个新的独立逻辑分支。下面的截图显示了这将是什么样子的一个非常基本的示例。在这个示例中，用于等待`5`秒的任务与执行一系列新任务的`序列`同时执行：![图 13.11：选择器组合节点在行为树中的使用示例](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_13_11.jpg)

图 13.11：选择器组合节点在行为树中的使用示例

`简单并行`组合节点也是唯一在其`详细信息`面板中具有参数的`组合`节点，即`完成模式`。有两个选项：

+   `立即`：当设置为`立即`时，简单并行将在主任务完成后立即成功完成。在这种情况下，`等待`任务完成后，后台树序列将中止，整个`简单并行`将再次执行。

+   `延迟`：当设置为`延迟`时，简单并行将在后台树完成执行并且任务完成后立即成功完成。在这种情况下，`等待`任务将在`5`秒后完成，但整个`简单并行`将等待`移动到`和`播放声音`任务执行后再重新开始。

## 任务

这些是我们的 AI 可以执行的任务。虚幻引擎默认提供了内置任务供我们使用，但我们也可以在蓝图和 C++中创建自己的任务。这包括任务，如告诉我们的 AI`移动到`特定位置，`旋转到一个方向`，甚至告诉 AI 开火。还要知道，您可以使用蓝图创建自定义任务。让我们简要讨论一下您将用来开发敌人角色 AI 的两个任务：`

+   `移动到任务`：这是行为树中常用的任务之一，在本章的后续练习中将使用此任务。`移动到任务`使用导航系统告诉 AI 如何移动以及移动的位置。您将使用此任务告诉 AI 敌人要去哪里。

+   `等待任务`：这是行为树中另一个常用的任务，因为它允许在任务执行之间延迟。这可以用于允许 AI 在移动到新位置之前等待几秒钟。

## 装饰器

`装饰器`是可以添加到任务或`组合`节点（如`序列`或`选择器`）的条件，允许分支逻辑发生。例如，我们可以有一个`装饰器`来检查敌人是否知道玩家的位置。如果是，我们可以告诉敌人朝着上次已知的位置移动。如果不是，我们可以告诉我们的 AI 生成一个新位置并移动到那里。还要知道，您可以使用蓝图创建自定义装饰器。

让我们简要讨论一下您将用来开发敌人角色 AI 的装饰器——`在位置`装饰器。这确定了受控棋子是否在装饰器本身指定的位置。这对您很有用，可以确保行为树在您知道 AI 已到达给定位置之前不执行。

## 服务

`Services`与`Decorators`非常相似，因为它们可以与`Tasks`和`Composite`节点链接。主要区别在于`Service`允许我们根据服务中定义的间隔执行一系列节点。还要知道，您可以使用蓝图创建自定义服务。

## 练习 13.04：创建 AI 行为树和黑板

现在您已经对行为树和黑板有了概述，这个练习将指导您创建这些资产，告诉 AI 控制器使用您创建的行为树，并将黑板分配给行为树。您在这里创建的黑板和行为树资产将用于`SuperSideScroller`游戏。此练习将在虚幻引擎 4 编辑器中执行。

以下步骤将帮助您完成此练习：

1.  在`Content Browser`界面中，导航到`/Enemy/AI`目录。这是您创建 AI 控制器的相同目录。

1.  在此目录中，在`Content Browser`界面的空白区域*右键单击*，导航到`Artificial Intelligence`选项，并选择`Behavior Tree`以创建`Behavior Tree`资产。将此资产命名为`BT_EnemyAI`。

1.  在上一步的相同目录中，在`Content Browser`界面的空白区域再次*右键单击*，导航到`Artificial Intelligence`选项，并选择`Blackboard`以创建`Blackboard`资产。将此资产命名为`BB_EnemyAI`。

在继续告诉 AI 控制器运行这个新行为树之前，让我们首先将黑板分配给这个行为树，以便它们正确连接。

1.  通过*双击*`Content Browser`界面中的资产打开`BT_EnemyAI`。一旦打开，导航到右侧的`Details`面板，并找到`Blackboard Asset`参数。

1.  单击此参数上的下拉菜单，并找到您之前创建的`BB_EnemyAI` `Blackboard`资产。在关闭之前编译和保存行为树。

1.  接下来，通过*双击*`Content Browser`界面内的 AI 控制器`BP_AIController_Enemy`资产来打开它。在控制器内，*右键单击*并搜索`Run Behavior Tree`函数。

`Run Behavior Tree`函数非常简单：您将行为树分配给控制器，函数返回行为树是否成功开始执行。

1.  最后，将`Event BeginPlay`事件节点连接到`Run Behavior Tree`函数的执行引脚，并分配`Behavior Tree`资产`BT_EnemyAI`，这是您在此练习中创建的：

。

![图 13.12：分配 BT_EnemyAI 行为树](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_13_12.jpg)

图 13.12：分配 BT_EnemyAI 行为树

完成此练习后，敌人 AI 控制器现在知道运行`BT_EnemyAI`行为树，并且此行为树知道使用名为`BB_EnemyAI`的黑板资产。有了这一点，您可以开始使用行为树逻辑来开发 AI，以便敌人角色可以在级别中移动。

## 练习 13.05：创建新的行为树任务

此练习的目标是为敌人 AI 开发一个 AI 任务，使角色能够在您级别的`Nav Mesh`体积范围内找到一个随机点进行移动。

尽管`SuperSideScroller`游戏只允许二维移动，让我们让 AI 在您在*Activity 13.01*中创建的级别的三维空间中移动，然后努力将敌人限制在二维空间内。

按照以下步骤为敌人创建新的任务：

1.  首先，打开您在上一个练习中创建的黑板资产`BB_EnemyAI`。

1.  在`Blackboard`的左上方*左键单击*`New Key`选项，并选择`Vector`选项。将此向量命名为`MoveToLocation`。您将使用此`vector`变量来跟踪 AI 的下一个移动位置。

为了这个敌方 AI 的目的，你需要创建一个新的“任务”，因为目前在虚幻中可用的任务不符合敌方行为的需求。

1.  导航到并打开你在上一个练习中创建的“行为树”资产，`BT_EnemyAI`。随机点选择的

1.  在顶部工具栏上*左键单击*“新建任务”选项。创建新的“任务”时，它会自动为你打开任务资产。但是，如果你已经创建了一个任务，在选择“新建任务”选项时会出现一个下拉选项列表。在处理这个“任务”的逻辑之前，你需要重命名资产。

1.  关闭“任务”资产窗口，导航到`/Enemy/AI/`，这是“任务”保存的位置。默认情况下，提供的名称是`BTTask_BlueprintBase_New`。将此资产重命名为`BTTask_FindLocation`。

1.  重命名新的“任务”资产后，*双击*打开“任务编辑器”。新的任务将使它们的蓝图图完全为空，并且不会为你提供任何默认事件来在图中使用。

1.  *右键单击*图中，在上下文敏感搜索中找到“事件接收执行 AI”选项。

1.  *左键单击*“事件接收执行 AI”选项，在“任务”图中创建事件节点，如下截图所示：![图 13.13：事件接收执行 AI 返回所有者和受控角色控制器和受控角色](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_13_13.jpg)

图 13.13：事件接收执行 AI 返回所有者控制器和受控角色

注意

“事件接收执行 AI”事件将让你可以访问**所有者控制器**和**受控角色**。在接下来的步骤中，你将使用受控角色来完成这个任务。

1.  每个“任务”都需要调用“完成执行”函数，以便“行为树”资产知道何时可以继续下一个“任务”或从树上分支出去。在图中*右键单击*，通过上下文敏感搜索搜索“完成执行”。

1.  *左键单击*上下文敏感搜索中的“完成执行”选项，在你的“任务”蓝图图中创建节点，如下截图所示：![图 13.14：完成执行函数，其中包含一个布尔参数，用于确定任务是否成功](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_13_14.jpg)

图 13.14：完成执行函数，其中包含一个布尔参数，用于确定任务是否成功

你需要的下一个函数叫做“在可导航半径内获取随机位置”。这个函数，顾名思义，返回可导航区域内定义半径内的随机向量位置。这将允许敌方角色找到随机位置并移动到这些位置。

1.  *右键单击*图中，在上下文敏感搜索中搜索“在可导航半径内获取随机位置”。*左键单击*“在可导航半径内获取随机位置”选项，将此函数放置在图中。

有了这两个函数，并且准备好了“事件接收执行 AI”，现在是时候为敌方 AI 获取随机位置了。

1.  从“事件接收执行 AI”的“受控角色”输出中，通过上下文敏感搜索找到“获取角色位置”函数：![图 13.15：敌方角色的位置将作为原点](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_13_15.jpg)

图 13.15：敌方角色的位置将作为随机点选择的原点

1.  将“获取角色位置”的向量返回值连接到“获取可导航半径内随机位置”的“原点”向量输入参数，如下截图所示。现在，这个函数将使用敌方 AI 角色的位置作为确定下一个随机点的原点：![图 13.16：现在，敌方角色的位置将被用作随机点向量搜索的原点的随机点向量搜索](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_13_16.jpg)

图 13.16：现在，敌方角色的位置将被用作随机点向量搜索的原点

1.  接下来，您需要告诉`GetRandomLocationInNavigableRadius`函数要检查级别可导航区域中的随机点的“半径”。将此值设置为`1000.0f`。

剩下的参数，`Nav Data`和`Filter Class`，可以保持不变。现在，您正在从`GetRandomLocationInNavigableRadius`获取随机位置，您需要能够将此值存储在您在本练习中创建的`Blackboard`向量中。

1.  要获得对`Blackboard`向量变量的引用，您需要在此`Task`内创建一个`Blackboard Key Selector`类型的新变量。创建此新变量并命名为`NewLocation`。

1.  现在，您需要将此变量设置为`Public`变量，以便在行为树中公开。*左键单击* “眼睛”图标，使眼睛可见。

1.  有了`Blackboard Key Selector`变量准备好后，*左键单击* 并拖动此变量的`Getter`。然后，从此变量中拉出并搜索`Set Blackboard Value as Vector`，如下屏幕截图所示：![图 13.17：Set Blackboard Value 有各种不同类型，支持 Blackboard 中可能存在的不同变量](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_13_17.jpg)

图 13.17：Set Blackboard Value 有各种不同类型，支持 Blackboard 中可能存在的不同变量

1.  将`GetRandomLocationInNavigableRadius`的`RandomLocation`输出向量连接到`Set Blackboard Value as Vector`的`Value`向量输入参数。然后，连接这两个函数节点的执行引脚。结果将如下所示：![图 13.18：现在，Blackboard 向量值被分配了这个新的随机位置](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_13_18.jpg)

图 13.18：现在，Blackboard 向量值被分配了这个新的随机位置

最后，您将使用`GetRandomLocationInNavigableRadius`函数的`Return Value`布尔输出参数来确定`Task`是否成功执行。

1.  将布尔输出参数连接到`Finish Execute`函数的`Success`输入参数，并连接`Set Blackboard Value as Vector`和`Finish Execute`函数节点的执行引脚。以下屏幕截图显示了`Task`逻辑的最终结果：![图 13.19：任务的最终设置](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_13_19.jpg)

图 13.19：任务的最终设置

注

您可以在以下链接找到前面的屏幕截图的完整分辨率，以便更好地查看：[`packt.live/3lmLyk5`](https://packt.live/3lmLyk5)。

通过完成此练习，您已经使用虚幻引擎 4 中的蓝图创建了您的第一个自定义`Task`。现在，您有一个任务，可以在级别的`Nav Mesh Volume`的可导航边界内找到一个随机位置，使用敌人的 pawn 作为此搜索的起点。在下一个练习中，您将在行为树中实现这个新的`Task`，并看到敌人 AI 在您的级别周围移动。

## 练习 13.06：创建行为树逻辑

本练习的目标是在行为树中实现您在上一个练习中创建的新`Task`，以便使敌人 AI 在级别的可导航空间内找到一个随机位置，然后移动到该位置。您将使用`Composite`、`Task`和`Services`节点的组合来实现此行为。本练习将在虚幻引擎 4 编辑器中进行。

以下步骤将帮助您完成此练习：

1.  首先，打开您在“Exercise 13.04”中创建的行为树，“Creating the AI Behavior Tree and Blackboard”，即`BT_EnemyAI`。

1.  在此“行为树”中，*左键单击* 并从`Root`节点底部拖动，并从上下文敏感搜索中选择`Sequence`节点。结果将是将`Root`连接到`Sequence`复合节点。

1.  接下来，从`Sequence`节点*左键单击*并拖动以打开上下文敏感菜单。在此菜单中，搜索您在上一个任务中创建的“任务”，即`BTTask_FindLocation`。

1.  默认情况下，`BTTask_FindLocation`任务应自动将`New Location`键选择器变量分配给`Blackboard`的`MovetoLocation`向量变量。如果没有发生这种情况，您可以在任务的“详细信息”面板中手动分配此选择器。

现在，`BTTask_FindLocation`将把`NewLocation`选择器分配给`Blackboard`的`MovetoLocation`向量变量。这意味着从任务返回的随机位置将被分配给`Blackboard`变量，并且您可以在其他任务中引用此变量。

现在，您正在查找有效的随机位置并将此位置分配给`Blackboard`变量，即`MovetoLocation`，您可以使用`Move To`任务告诉 AI 移动到此位置。

1.  *左键单击*并从`Sequence`复合节点中拖动。然后，在上下文敏感搜索中找到`Move To`任务。您的“行为树”现在将如下所示：![图 13.20：选择随机位置后，移动任务将让 AI 移动到这个新位置](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_13_20.jpg)

图 13.20：选择随机位置后，移动任务将让 AI 移动到这个新位置

1.  默认情况下，`Move To`任务应将`MoveToLocation`分配为其`Blackboard Key`值。如果没有，请选择任务。在其“详细信息”面板中，您将找到`Blackboard Key`参数，您可以在其中分配变量。在“详细信息”面板中，还将“可接受半径”设置为`50.0f`。

现在，行为树使用`BTTask_FindLocation`自定义任务找到随机位置，并使用`MoveTo`任务告诉 AI 移动到该位置。这两个任务通过引用名为`MovetoLocation`的`Blackboard`向量变量相互通信位置。

这里要做的最后一件事是向`Sequence`复合节点添加一个`Decorator`，以确保敌人角色在再次执行树以查找并移动到新位置之前不处于随机位置。

1.  *右键单击*`Sequence`的顶部区域，然后选择“添加装饰者”。从下拉菜单中*左键单击*并选择“在位置”。

1.  由于您已经在`Blackboard`中有一个向量参数，`Decorator`应自动将`MovetoLocation`分配为`Blackboard Key`。通过选择`Decorator`并确保`Blackboard Key`分配给`MovetoLocation`来验证这一点。

1.  有了装饰者，您已经完成了行为树。最终结果将如下所示：![图 13.21：AI 敌人行为树的最终设置](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_13_21.jpg)

图 13.21：AI 敌人行为树的最终设置

这个行为树告诉 AI 使用`BTTask_FindLocation`找到一个随机位置，并将此位置分配给名为`MovetoLocation`的 Blackboard 值。当此任务成功时，行为树将执行`MoveTo`任务，该任务将告诉 AI 移动到这个新的随机位置。序列包含一个`Decorator`，它确保敌方 AI 在再次执行之前处于`MovetoLocation`，就像 AI 的安全网一样。

1.  在测试新的 AI 行为之前，确保将`BP_Enemy AI`放入您的级别中，如果之前的练习和活动中没有的话。

1.  现在，如果您使用`PIE`或“模拟”，您将看到敌方 AI 在`Nav Mesh Volume`内围绕地图奔跑并移动到随机位置：![图 13.22：敌方 AI 现在将从一个位置移动到另一个位置](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_13_22.jpg)

图 13.22：敌方 AI 现在将从一个位置移动到另一个位置

注意

有些情况下，敌人 AI 不会移动。这可能是由于“在可导航半径内获取随机位置”函数未返回`True`引起的。这是一个已知问题，如果发生，请重新启动编辑器并重试。

通过完成这个练习，您已经创建了一个完全功能的行为树，允许敌人 AI 在您的级别的可导航范围内找到并移动到一个随机位置。您在上一个练习中创建的任务允许您找到这个随机点，而“移动到”任务允许 AI 角色朝着这个新位置移动。

由于“序列”组合节点的工作方式，每个任务必须在继续下一个任务之前成功完成，所以首先，敌人成功找到一个随机位置，然后朝着这个位置移动。只有当“移动到”任务完成时，整个行为树才会重新开始并选择一个新的随机位置。

现在，您可以继续进行下一个活动，在这个活动中，您将添加到这个行为树，以便让 AI 在选择新的随机点之间等待，这样敌人就不会不断移动。

## 活动 13.02：AI 移动到玩家位置

在上一个练习中，您能够让 AI 敌人角色通过使用自定义“任务”和“移动到”任务一起移动到“导航网格体”范围内的随机位置。

在这个活动中，您将继续上一个练习并更新行为树。您将利用“等待”任务使用一个“装饰器”，并创建自己的新自定义任务，让 AI 跟随玩家角色并每隔几秒更新其位置。

以下步骤将帮助您完成这个活动：

1.  在您之前创建的`BT_EnemyAI`行为树中，您将继续从上次离开的地方创建一个新任务。通过从工具栏中选择“新任务”并选择`BTTask_BlueprintBase`来完成这个任务。将这个新任务命名为`BTTask_FindPlayer`。

1.  在`BTTask_FindPlayer`任务中，创建一个名为`Event Receive Execute AI`的新事件。

1.  找到“获取玩家角色”函数，以获取对玩家的引用；确保使用`Player Index 0`。

1.  从玩家角色中调用“获取角色位置”函数，以找到玩家当前的位置。

1.  在这个任务中创建一个新的黑板键“选择器”变量。将此变量命名为`NewLocation`。

1.  *左键单击*并将`NewLocation`变量拖入图表中。从该变量中，搜索“设置黑板数值”函数为“向量”。

1.  将“设置黑板数值”作为“向量”函数连接到事件“接收执行 AI”节点的执行引脚。

1.  添加“完成执行”函数，确保布尔值“成功”参数为`True`。

1.  最后，将“设置黑板数值”作为“向量”函数连接到“完成执行”函数。

1.  保存并编译任务“蓝图”，返回到`BT_EnemyAI`行为树。

1.  用新的`BTTask_FindPlayer`任务替换`BTTask_FindLocation`任务，使得这个新任务现在是“序列”组合节点下的第一个任务。

1.  通过以下自定义`BTTask_FindLocation`和`Move To`任务，在“序列”组合节点下方添加一个新的“播放声音”任务作为第三个任务。

1.  在“播放声音”参数中，添加`Explosion_Cue SoundCue`资产。

1.  在“播放声音”任务中添加一个“是否在位置”装饰器，并确保将“移动到位置”键分配给该装饰器。

1.  在“序列”组合节点下方添加一个新的“等待”任务作为第四个任务，跟随“播放声音”任务。

1.  将“等待”任务设置为等待`2.0f`秒后成功完成。

预期输出如下：

![图 13.23：敌人 AI 跟随玩家并每 2 秒更新一次玩家每 2 秒](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_13_23.jpg)

图 13.23：敌人 AI 跟随玩家并每 2 秒更新一次玩家位置

敌方 AI 角色将移动到关卡中可导航空间内玩家的最后已知位置，并在每个玩家位置之间暂停`2.0f`秒。

注意

此活动的解决方案可在以下网址找到：[`packt.live/338jEBx`](https://packt.live/338jEBx)。

完成此活动后，您已经学会了创建一个新的任务，使 AI 能够找到玩家位置并移动到玩家的最后已知位置。在进行下一组练习之前，删除`PlaySound`任务，并用您在*Exercise 13.05*中创建的`BTTask_FindLocation`任务替换`BTTask_FindPlayer`任务。请参考*Exercise 13.05*，*Creating a New Behavior Tree Task*和*Exercise 13.06*，*Creating the Behavior Tree Logic*，以确保行为树正确返回。您将在即将进行的练习中使用`BTTask_FindLocation`任务。

在下一个练习中，您将通过开发一个新的`Blueprint`角色来解决这个问题，这将允许您设置 AI 可以朝向的特定位置。

## 练习 13.07：创建敌方巡逻位置

目前 AI 敌人角色的问题在于它们可以在 3D 可导航空间中自由移动，因为行为树允许它们在该空间内找到一个随机位置。相反，AI 需要被给予您可以在编辑器中指定和更改的巡逻点。然后它将随机选择其中一个巡逻点进行移动。这就是您将为`SuperSideScroller`游戏做的事情：创建敌方 AI 可以移动到的巡逻点。本练习将向您展示如何使用简单的*Blueprint*角色创建这些巡逻点。本练习将在 Unreal Engine 4 编辑器中执行。

以下步骤将帮助您完成此练习：

1.  首先，导航到`/Enemy/Blueprints/`目录。这是您将创建用于 AI 巡逻点的新`Blueprint`角色的位置。

1.  在此目录中，*右键单击*并选择`Blueprint Class`选项，然后从菜单中*左键单击*此选项。

1.  从`Pick Parent Class`菜单提示中，*左键单击*`Actor`选项，创建一个基于`Actor`类的新`Blueprint`：![图 13.24：Actor 类是所有对象的基类可以放置或生成在游戏世界中](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_13_24.jpg)

图 13.24：Actor 类是可以放置或生成在游戏世界中的所有对象的基类

1.  将此新资产命名为`BP_AIPoints`，并通过在`Content Browser`界面中*双击*资产来打开此`Blueprint`。

注意

`Blueprints`的界面与其他系统（如`Animation Blueprints`和`Tasks`）共享许多相同的功能和布局，因此这些都应该对您来说很熟悉。

1.  在蓝图 UI 左侧的`Variables`选项卡中导航，*左键单击*`+Variable`按钮。将此变量命名为`Points`。

1.  从`Variable Type`下拉菜单中，*左键单击*并选择`Vector`选项。

1.  接下来，您需要将这个向量变量设置为`Array`，以便可以存储多个巡逻位置。*左键单击*`Vector`旁边的黄色图标，然后*左键单击*选择`Array`选项。

1.  设置`Points`向量变量的最后一步是启用`Instance Editable`和`Show 3D Widget`：

+   `Instance Editable`参数允许此向量变量在放置在级别中的角色上公开可见，使得每个此角色的实例都可以编辑此变量。

+   `Show 3D Widget`允许您使用编辑器视口中可见的 3D 变换小部件来定位向量值。您将在本练习的后续步骤中看到这意味着什么。还需要注意的是，`Show 3D Widget`选项仅适用于涉及演员变换的变量，例如`Vectors`和`Transforms`。

简单的角色设置完成后，现在是将角色放置到关卡中并开始设置*巡逻点*位置的时候了。

1.  将`BP_AIPoints` actor 蓝图添加到您的级别中，如下所示：![图 13.25：BP_AIPoints actor 现在在级别中](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_13_25.jpg)

图 13.25：BP_AIPoints actor 现在在级别中

1.  选择`BP_AIPoints` actor，导航到其`Details`面板，并找到`Points`变量。

1.  接下来，您可以通过*左键单击*`+`符号向向量数组添加新元素，如下所示：![图 13.26：数组中可以有许多元素，但数组越大，分配的内存就越多](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_13_26.jpg)

图 13.26：数组中可以有许多元素，但数组越大，分配的内存就越多

1.  当您向向量数组添加新元素时，将会出现一个 3D 小部件，您可以*左键单击*以选择并在级别中移动，如下所示：![图 13.27：第一个巡逻点向量位置](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_13_27.jpg)

图 13.27：第一个巡逻点向量位置

注意

当您更新代表向量数组元素的 3D 小部件的位置时，`Details`面板中的 3D 坐标将更新为`Points`变量。

1.  最后，将尽可能多的元素添加到向量数组中，以适应您级别的上下文。请记住，这些巡逻点的位置应该对齐，使它们沿水平轴成一条直线，与角色移动的方向平行。以下屏幕截图显示了本练习中包含的示例`SideScroller.umap`级别中的设置：![图 13.28：示例巡逻点路径，如图所示在 SideScroller.umap 示例级别中](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_13_28.jpg)

图 13.28：示例巡逻点路径，如在 SideScroller.umap 示例级别中所见

1.  继续重复最后一步，创建多个巡逻点并根据需要放置 3D 小部件。您可以使用提供的`SideScroller.umap`示例级别作为设置这些`巡逻点`的参考。

通过完成这个练习，您已经创建了一个包含`Vector`位置数组的新`Actor`蓝图，现在可以使用编辑器中的 3D 小部件手动设置这些位置。通过手动设置*巡逻点*位置的能力，您可以完全控制 AI 可以移动到的位置，但是有一个问题。目前还没有功能来从这个数组中选择一个点并将其传递给行为树，以便 AI 可以在这些*巡逻点*之间移动。在设置这个功能之前，让我们先了解更多关于向量和向量变换的知识，因为这些知识将在下一个练习中证明有用。

# 向量变换

在进行下一个练习之前，重要的是您了解一下向量变换，更重要的是了解`Transform Location`函数的作用。当涉及到角色的位置时，有两种思考其位置的方式：世界空间和本地空间。角色在世界空间中的位置是相对于世界本身的位置；更简单地说，这是您将实际角色放置到级别中的位置。角色的本地位置是相对于自身或父级角色的位置。

让我们以`BP_AIPoints` actor 作为世界空间和本地空间的示例。`Points`数组的每个位置都是本地空间向量，因为它们是相对于`BP_AIPoints` actor 本身的世界空间位置的位置。以下屏幕截图显示了`Points`数组中的向量列表，如前面的练习所示。这些值是相对于您级别中`BP_AIPoints` actor 的位置的位置：

![图 13.29：Points 数组的本地空间位置向量，相对到 BP_AIPoints actor 的世界空间位置](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_13_29.jpg)

图 13.29：相对于 BP_AIPoints actor 的世界空间位置，Points 数组的本地空间位置向量

为了使敌人 AI 移动到这些`Points`的正确世界空间位置，您需要使用一个名为`Transform Location`的函数。这个函数接受两个参数：

+   `T`：这是您用来将向量位置参数从局部空间转换为世界空间值的提供的`Transform`。

+   `位置`：这是要从局部空间转换为世界空间的`位置`。

然后将向量转换的结果作为函数的返回值。您将在下一个练习中使用此函数，从`Points`数组中返回一个随机选择的向量点，并将该值从局部空间向量转换为世界空间向量。然后，将使用这个新的世界空间向量来告诉敌人 AI 在世界中如何移动。让我们现在实现这个。

## 练习 13.08：在数组中选择一个随机点

现在您对向量和向量转换有了更多的了解，您可以继续进行这个练习，在这个练习中，您将创建一个简单的`蓝图`函数，选择一个*巡逻点*向量位置中的一个，并使用名为`Transform Location`的内置函数将其向量从局部空间值转换为世界空间值。通过返回向量位置的世界空间值，然后将这个值传递给*行为树*，使得 AI 将移动到正确的位置。这个练习将在虚幻引擎 4 编辑器中进行。

以下步骤将帮助您完成这个练习。让我们从创建新函数开始：

1.  导航回`BP_AIPoints`蓝图，并通过*左键单击*蓝图编辑器左侧的`函数`类别旁边的`+`按钮来创建一个新函数。将此函数命名为`GetNextPoint`。

1.  在为这个函数添加逻辑之前，通过*左键单击*`函数`类别下的函数来选择此函数，以访问其`详细信息`面板。

1.  在“详细信息”面板中，启用`Pure`参数，以便将此函数标记为“纯函数”。在*第十一章*中，*混合空间 1D，键绑定和状态机*中，当在玩家角色的动画蓝图中工作时，您了解了“纯函数”；在这里也是一样的。

1.  接下来，`GetNextPoint`函数需要返回一个向量，行为树可以用来告诉敌人 AI 要移动到哪里。通过*左键单击*`详细信息`函数类别下的`+`符号来添加这个新的输出。将变量类型设置为`Vector`，并将其命名为`NextPoint`，如下面的屏幕截图所示：![图 13.30：函数可以返回不同类型的多个变量，根据您的逻辑需求](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_13_30.jpg)

图 13.30：函数可以返回不同类型的多个变量，根据您的逻辑需求

1.  在添加`输出`变量时，函数将自动生成一个`Return`节点并将其放入函数图中，如下面的屏幕截图所示。您将使用这个输出来返回敌人 AI 移动到的新向量巡逻点：![图 13.31：函数的自动生成返回节点，包括 NewPoint 向量输出变量](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_13_31.jpg)

图 13.31：函数的自动生成返回节点，包括 NewPoint 向量输出变量

现在函数的基础工作已经完成，让我们开始添加逻辑。

1.  为了选择一个随机位置，首先需要找到`Points`数组的长度。创建`Points`向量的`Getter`，从这个向量变量中*左键单击*并拖动以搜索`Length`函数，如下面的屏幕截图所示：![图 13.32：Length 函数是一个纯函数，返回数组的长度](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_13_32.jpg)

图 13.32：Length 函数是一个纯函数，返回数组的长度

1.  使用`Length`函数的整数输出，*左键单击*并拖动以使用上下文敏感搜索找到`Random Integer`函数，如下截图所示。`Random Integer`函数返回一个在`0`和`最大值`之间的随机整数；在这种情况下，这是`Points`向量数组的`Length`：![图 13.33：使用随机整数将允许函数返回从`Points`向量数组中获取一个随机向量](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_13_33.jpg)

图 13.33：使用随机整数将允许函数从`Points`向量数组中返回一个随机向量

到目前为止，你正在生成一个在`Points`向量数组的长度之间的随机整数。接下来，你需要找到返回的`Random Integer`的索引位置处`Points`向量数组的元素。

1.  通过创建一个新的`Points`向量数组的`Getter`。然后，*左键单击*并拖动以搜索`Get (a copy)`函数。

1.  接下来，将`Random Integer`函数的返回值连接到`Get (a copy)`函数的输入。这将告诉函数选择一个随机整数，并使用该整数作为要从`Points`向量数组返回的索引。

现在你从`Points`向量数组中获取了一个随机向量，你需要使用`Transform Location`函数将位置从局部空间转换为世界空间向量。

正如你已经学到的那样，`Points`数组中的向量是相对于关卡中`BP_AIPoints`角色位置的局部空间位置。因此，你需要使用`Transform Location`函数将随机选择的局部空间向量转换为世界空间向量，以便 AI 敌人移动到正确的位置。

1.  *左键单击*并从`Get (a copy)`函数的向量输出处拖动，并通过上下文敏感搜索，找到`Transform Location`函数。

1.  将`Get (a copy)`函数的向量输出连接到`Transform Location`函数的`Location`输入。

1.  最后一步是使用蓝图角色本身的变换作为`Transform Location`函数的`T`参数。通过*右键单击*图表并通过上下文敏感搜索，找到`GetActorTransform`函数并将其连接到`Transform Location`参数`T`。

1.  最后，将`Transform Location`函数的`Return Value`向量连接到函数的`NewPoint`向量输出：![图 13.34：`GetNextPoint`函数的最终逻辑设置](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_13_34.jpg)

图 13.34：`GetNextPoint`函数的最终逻辑设置

注意

你可以在以下链接找到前面的截图的全分辨率以便更好地查看：[`packt.live/35jlilb`](https://packt.live/35jlilb)。

通过完成这个练习，你在`BP_AIPoints`角色内创建了一个新的蓝图函数，该函数从`Points`数组变量中获取一个随机索引，使用`Transform Location`函数将其转换为世界空间向量值，并返回这个新的向量值。你将在 AI 行为树中的`BTTask_FindLocation`任务中使用这个函数，以便敌人移动到你设置的其中一个点。在你这样做之前，敌人 AI 需要一个对`BP_AIPoints`角色的引用，以便它知道可以从哪些点中选择并移动。我们将在下一个练习中完成这个任务。

## 练习 13.09：引用巡逻点角色

现在`BP_AIPoints`角色有一个从其向量巡逻点数组中返回随机转换位置的函数，你需要让敌人 AI 在关卡中引用这个角色，以便它知道要引用哪些巡逻点。为此，你将在敌人角色蓝图中添加一个新的`Object Reference`变量，并分配之前放置在关卡中的`BP_AIPoints`角色。这个练习将在虚幻引擎 4 编辑器中进行。让我们开始添加*Object Reference*。

注意

`对象引用变量`存储对特定类对象或演员的引用。有了这个引用变量，您可以访问此类可用的公开变量、事件和函数。

以下步骤将帮助您完成此练习：

1.  导航到`/Enemy/Blueprints/`目录，并通过*双击*`内容浏览器`界面中的资产打开敌人角色蓝图`BP_Enemy`。

1.  创建一个`BP_AIPoints`类型的新变量，并确保变量类型为`对象引用`。

1.  为了引用级别中现有的`BP_AIPoints`演员，您需要通过启用`实例可编辑`参数使上一步的变量成为`公共变量`。将此变量命名为`巡逻点`。

1.  现在您已经设置了对象引用，导航到您的级别并选择您的敌人 AI。下面的截图显示了放置在提供的示例级别中的敌人 AI；即`SuperSideScroller.umap`。如果您的级别中没有放置敌人，请立即这样做：

注意

将敌人放置到级别中与 Unreal Engine 4 中的任何其他演员一样。*左键单击*并从内容浏览器界面将敌人 AI 蓝图拖放到级别中。

图 13.35：敌人 AI 放置在示例级别 SuperSideScroller.umap 中

](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_13_35.jpg)

图 13.35：敌人 AI 放置在示例级别 SuperSideScroller.umap 中

1.  从其`详细信息`面板中，在`默认`类别下找到`巡逻点`变量。这里要做的最后一件事是通过*左键单击*`巡逻点`变量的下拉菜单，并从列表中找到在*练习 13.07*中已经放置在级别中的`BP_AIPoints`演员。 

完成此练习后，您的级别中的敌人 AI 现在引用了级别中的`BP_AIPoints`演员。有了有效的引用，敌人 AI 可以使用这个演员来确定在`BTTask_FindLocation`任务中移动的点集。现在要做的就是更新`BTTask_FindLocation`任务，使其使用这些点而不是找到一个随机位置。

## 练习 13.10：更新 BTTask_FindLocation

完成敌人 AI 巡逻行为的最后一步是替换`BTTask_FindLocation`中的逻辑，使其使用`BP_AIPoints`演员的`GetNextPoint`函数，而不是在级别的可导航空间内查找随机位置。这个练习将在 Unreal Engine 4 编辑器中执行。

作为提醒，在开始之前，回顾一下*练习 13.05*结束时`BTTask_FindLocation`任务的外观。

以下步骤将帮助您完成此练习：

1.  首先要做的是从`Event Receive Execute AI`中获取返回的`Controlled Pawn`引用，并将其转换为`BP_Enemy`，如下截图所示。这样，您就可以访问上一个练习中的`巡逻点`对象引用变量：![图 13.36：转换还确保返回的 Controlled Pawn 是 BP_Enemy 类类型的](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_13_36.jpg)

图 13.36：转换还确保返回的 Controlled Pawn 是 BP_Enemy 类类型

1.  接下来，您可以通过*左键单击*并从`转换为 BP_Enemy`下的`As BP Enemy`引脚中拖动，并通过上下文敏感搜索找到`巡逻点`对象引用变量。

1.  从`巡逻点`引用中，您可以*左键单击*并拖动以搜索您在*练习 13.08*中创建的`GetNextPoint`函数，*选择数组中的随机点*。

1.  现在，您可以将`GetNextPoint`函数的`NextPoint`向量输出参数连接到`Set Blackboard Value as Vector`函数，并将执行引脚从转换连接到`Set Blackboard Value as Vector`函数。现在，每次执行`BTTask_FindLocation`任务时，都会设置一个新的随机巡逻点。

1.  最后，将`Set Blackboard Value as Vector`函数连接到`Finish Execute`函数，并手动将`Success`参数设置为`True`，以便如果转换成功，此任务将始终成功。

1.  作为备用方案，创建`Finish Execute`的副本并连接到`Cast`函数的`Cast Failed`执行引脚。然后，将`Success`参数设置为`False`。这将作为备用方案，以便如果由于任何原因`Controlled Pawn`不是`BP_Enemy`类，任务将失败。这是一个很好的调试实践，以确保任务对其预期的 AI 类的功能性：![图 13.37：在逻辑中考虑任何转换失败总是一个很好的实践](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_13_37.jpg)

图 13.37：在逻辑中考虑任何转换失败总是一个很好的实践

注意

您可以在以下链接找到前面的截图的全分辨率版本以便更好地查看：[`packt.live/3n58THA`](https://packt.live/3n58THA)。

随着`BTTask_FindLocation`任务更新为使用敌人中`BP_AIPoints`角色引用的随机巡逻点，敌人 AI 现在将在巡逻点之间随机移动。

![图 13.38：敌人 AI 现在在关卡中的巡逻点位置之间移动](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_13_38.jpg)

图 13.38：敌人 AI 现在在关卡中的巡逻点位置之间移动

完成这个练习后，敌人 AI 现在使用对关卡中`BP_AIPoints`角色的引用，以找到并移动到关卡中的巡逻点。关卡中的每个敌人角色实例都可以引用另一个唯一实例的`BP_AIPoints`角色，也可以共享相同的实例引用。由您决定每个敌人 AI 如何在关卡中移动。

# 玩家抛射物

在本章的最后一部分，您将专注于创建玩家抛射物的基础，该基础可用于摧毁敌人。目标是创建适当的角色类，引入所需的碰撞和抛射物移动组件到类中，并设置抛射物运动行为的必要参数。

为了简单起见，玩家的抛射物将不使用重力，将在一次命中时摧毁敌人，并且抛射物本身将在撞击任何表面时被摧毁；例如，它不会从墙上弹开。玩家抛射物的主要目标是让玩家可以生成并用来摧毁整个关卡中的敌人的抛射物。在本章中，您将设置基本的框架功能，而在*第十四章*中，*生成玩家抛射物*，您将添加声音和视觉效果。让我们开始创建玩家抛射物类。

## 练习 13.11：创建玩家抛射物

到目前为止，我们一直在虚幻引擎 4 编辑器中工作，创建我们的敌人 AI。对于玩家抛射物，我们将使用 C++和 Visual Studio 来创建这个新类。玩家抛射物将允许玩家摧毁放置在关卡中的敌人。这个抛射物将有一个短暂的寿命，以高速行进，并且将与敌人和环境发生碰撞。

这个练习的目标是为玩家的抛射物设置基础角色类，并开始在抛射物的头文件中概述所需的函数和组件。

以下步骤将帮助您完成这个练习：

1.  首先，您需要使用`Actor`类作为玩家抛射物的父类来创建一个新的 C++类。接下来，将这个新的 actor 类命名为`PlayerProjectile`，并*左键单击*菜单提示的底部右侧的`Create Class`选项。

创建新类后，Visual Studio 将为该类生成所需的源文件和头文件，并为您打开这些文件。actor 基类包含了一些默认函数，对于玩家抛射物来说是不需要的。

1.  在`PlayerProjectile.h`文件中找到以下代码行并删除它们：

```cpp
    protected:
      // Called when the game starts or when spawned
      virtual void BeginPlay() override;
    public:
      // Called every frame
      virtual void Tick(float DeltaTime) override;
    ```

这些代码行代表了默认情况下包含在每个基于 Actor 的类中的`Tick()`和`BeginPlay()`函数的声明。`Tick()`函数在每一帧都会被调用，允许您在每一帧上执行逻辑，这可能会变得昂贵，取决于您要做什么。`BeginPlay()`函数在此 actor 被初始化并开始播放时被调用。这可以用来在 actor 进入世界时立即执行逻辑。这些函数被删除是因为它们对于`Player Projectile`不是必需的，只会使代码混乱。

1.  在`PlayerProjectile.h`头文件中删除这些行后，您还可以从`PlayerProjectile.cpp`源文件中删除以下行：

```cpp
    // Called when the game starts or when spawned
    void APlayerProjectile::BeginPlay()
    {
      Super::BeginPlay();
    }
    // Called every frame
    void APlayerProjectile::Tick(float DeltaTime)
    {
      Super::Tick(DeltaTime);
    }
    ```

这些代码行代表了您在上一步中删除的两个函数的函数实现；也就是说，`Tick()`和`BeginPlay()`。同样，这些被删除是因为它们对于`Player Projectile`没有任何作用，只会给代码增加混乱。此外，如果没有在`PlayerProjectile.h`头文件中声明，您将无法编译这些代码。唯一剩下的函数将是抛射物类的构造函数，您将在下一个练习中用它来初始化抛射物的组件。现在您已经从`PlayerProjectile`类中删除了不必要的代码，让我们添加抛射物所需的函数和组件。

1.  在`PlayerProjectile.h`头文件中，添加以下组件。让我们详细讨论这些组件：

```cpp
    public:
      //Sphere collision component
      UPROPERTY(VisibleDefaultsOnly, Category = Projectile)
      class USphereComponent* CollisionComp;

    private:
      //Projectile movement component
      UPROPERTY(VisibleAnywhere, BlueprintReadOnly, Category = Movement, meta =   (AllowPrivateAccess = "true"))
      class UProjectileMovementComponent* ProjectileMovement;
      //Static mesh component
      UPROPERTY(VisibleDefaultsOnly, Category = Projectile)
      class UStaticMeshComponent* MeshComp;
    ```

在这里，您正在添加三个不同的组件。首先是碰撞组件，您将用它来使抛射物识别与敌人和环境资产的碰撞。接下来的组件是抛射物移动组件，您应该从上一个项目中熟悉它。这将允许抛射物表现得像一个抛射物。最后一个组件是静态网格组件。您将使用它来为这个抛射物提供一个视觉表示，以便在游戏中看到它。

1.  接下来，将以下函数签名代码添加到`PlayerProjectile.h`头文件中，在`public`访问修饰符下：

```cpp
    UFUNCTION()
    void OnHit(UPrimitiveComponent* HitComp, AActor* OtherActor,   UPrimitiveComponent* OtherComp, FVector NormalImpulse, const FHitResult&   Hit);
    ```

这个最终的事件声明将允许玩家抛射物响应您在上一步中创建的`CollisionComp`组件的`OnHit`事件。

1.  现在，为了使这段代码编译，您需要在`PlayerProjectile.cpp`源文件中实现上一步的函数。添加以下代码：

```cpp
    void APlayerProjectile::OnHit(UPrimitiveComponent* HitComp, AActor*   OtherActor, UPrimitiveComponent* OtherComp, FVector NormalImpulse, const   FHitResult& Hit)
    {
    }
    ```

`OnHit`事件为您提供了关于发生的碰撞的大量信息。您将在下一个练习中使用的最重要的参数是`OtherActor`参数。`OtherActor`参数将告诉您此`OnHit`事件响应的 actor。这将允许您知道这个其他 actor 是否是敌人。当抛射物击中它们时，您将使用这些信息来摧毁敌人。

1.  最后，返回虚幻引擎编辑器，*左键单击*`Compile`选项来编译新代码。

完成此练习后，您现在已经为`Player Projectile`类准备好了框架。该类具有`Projectile Movement`、`Collision`和`Static Mesh`所需的组件，以及为`OnHit`碰撞准备的事件签名，以便弹丸可以识别与其他角色的碰撞。

在下一个练习中，您将继续自定义并启用`Player Projectile`的参数，以使其在`SuperSideScroller`项目中按您的需求运行。

## 练习 13.12：初始化玩家投射物设置

现在`PlayerProjectile`类的框架已经就位，是时候更新该类的构造函数，以便为弹丸设置所需的默认设置，使其移动和行为符合您的要求。为此，您需要初始化`Projectile Movement`、`Collision`和`Static Mesh`组件。

以下步骤将帮助您完成此练习：

1.  打开 Visual Studio 并导航到`PlayerProjectile.cpp`源文件。

1.  在构造函数中添加任何代码之前，在`PlayerProjectile.cpp`源文件中包括以下文件：

```cpp
    #include "GameFramework/ProjectileMovementComponent.h"
    #include "Components/SphereComponent.h"
    #include "Components/StaticMeshComponent.h"
    ```

这些头文件将允许您初始化和更新弹丸移动组件、球体碰撞组件和静态网格组件的参数。如果不包括这些文件，`PlayerProjectile`类将不知道如何处理这些组件以及如何访问它们的函数和参数。

1.  默认情况下，`APlayerProjectile::APlayerProjectile()`构造函数包括以下行：

```cpp
    PrimaryActorTick.bCanEverTick = true;
    ```

这行代码可以完全删除，因为在玩家投射物中不需要。

1.  在`PlayerProjectile.cpp`源文件中，将以下行添加到`APlayerProjectile::APlayerProjectile()`构造函数中：

```cpp
    CollisionComp = CreateDefaultSubobject   <USphereComponent>(TEXT("SphereComp"));
    CollisionComp->InitSphereRadius(15.0f);
    CollisionComp->BodyInstance.SetCollisionProfileName("BlockAll");
    CollisionComp->OnComponentHit.AddDynamic(this, &APlayerProjectile::OnHit);
    ```

第一行初始化了球体碰撞组件，并将其分配给您在上一个练习中创建的`CollisionComp`变量。`Sphere Collision Component`有一个名为`InitSphereRadius`的参数。这将确定碰撞角色的大小或半径，默认情况下，值为`15.0f`效果很好。接下来，将碰撞组件的`Collision Profile Name`设置为`BlockAll`，以便将碰撞配置文件设置为`BlockAll`，这意味着当它与其他对象发生碰撞时，此碰撞组件将响应`OnHit`。最后，您添加的最后一行允许`OnComponentHit`事件使用您在上一个练习中创建的函数进行响应：

```cpp
    void APlayerProjectile::OnHit(UPrimitiveComponent* HitComp, AActor*   OtherActor, UPrimitiveComponent* OtherComp, FVector NormalImpulse, const   FHitResult& Hit)
    {
    }
    ```

这意味着当碰撞组件接收到来自碰撞事件的`OnComponentHit`事件时，它将使用该函数进行响应；但是，此函数目前为空。您将在本章后面的部分向此函数添加代码。

1.  `Collision Component`的最后一件事是将该组件设置为玩家投射物角色的`root`组件。在构造函数中，在*Step 4*的行之后添加以下代码行：

```cpp
    // Set as root component
    RootComponent = CollisionComp;
    ```

1.  碰撞组件设置好并准备好后，让我们继续进行`Projectile Movement`组件。将以下行添加到构造函数中：

```cpp
    // Use a ProjectileMovementComponent to govern this projectile's movement
    ProjectileMovement =   CreateDefaultSubobject<UProjectileMovementComponent>
    (TEXT("ProjectileComp"))  ;
    ProjectileMovement->UpdatedComponent = CollisionComp;
    ProjectileMovement->ProjectileGravityScale = 0.0f;
    ProjectileMovement->InitialSpeed = 800.0f;
    ProjectileMovement->MaxSpeed = 800.0f;
    ```

第一行初始化了`Projectile Movement Component`并将其分配给你在上一个练习中创建的`ProjectileMovement`变量。接下来，我们将`CollisionComp`设置为投射物移动组件的更新组件。我们这样做的原因是因为`Projectile Movement`组件将使用角色的`root`组件作为移动的组件。然后，你将投射物的重力比例设置为`0.0f`，因为玩家投射物不应受重力影响；其行为应该允许投射物以相同的速度、相同的高度移动，并且不受重力影响。最后，你将`InitialSpeed`和`MaxSpeed`参数都设置为`500.0f`。这将使投射物立即以这个速度开始移动，并在其寿命期间保持这个速度。玩家投射物不支持任何形式的加速运动。

1.  初始化并设置了投射物移动组件后，现在是为`Static Mesh Component`做同样的操作的时候了。在上一步的代码行之后添加以下代码：

```cpp
    MeshComp = CreateDefaultSubobject<UStaticMeshComponent>(TEXT("MeshComp"));
    MeshComp->AttachToComponent(RootComponent,   FAttachmentTransformRules::KeepWorldTransform);
    ```

第一行初始化了`Static Mesh Component`并将其分配给你在上一个练习中创建的`MeshComp`变量。然后，使用名为`FAttachmentTransformRules`的结构将这个静态网格组件附加到`RootComponent`，以确保`Static Mesh Component`在附加时保持其世界变换，这是这个练习的*步骤 5*中的`CollisionComp`。

注意

你可以在这里找到有关`FAttachmentTransformRules`结构的更多信息：[`docs.unrealengine.com/en-US/API/Runtime/Engine/Engine/FAttachmentTransformRules/index.html`](https://docs.unrealengine.com/en-US/API/Runtime/Engine/Engine/FAttachmentTransformRules/index.html)。

1.  最后，让我们给`Player Projectile`一个初始寿命为`3`秒，这样如果投射物在这段时间内没有与任何物体碰撞，它将自动销毁。在构造函数的末尾添加以下代码：

```cpp
    InitialLifeSpan = 3.0f;
    ```

1.  最后，返回虚幻引擎编辑器，*左键单击*`Compile`选项来编译新代码。

通过完成这个练习，你已经为`Player Projectile`设置了基础工作，以便它可以在编辑器中作为*Blueprint* actor 创建。所有三个必需的组件都已初始化，并包含了你想要的这个投射物的默认参数。现在我们只需要从这个类创建*Blueprint*来在关卡中看到它。

## 活动 13.03：创建玩家投射物蓝图

为了完成本章，你将从新的`PlayerProjectile`类创建`Blueprint` actor，并自定义这个 actor，使其使用一个用于调试目的的`Static Mesh Component`的占位形状。这样可以在游戏世界中查看投射物。然后，你将在`PlayerProjectile.cpp`源文件中的`APlayerProjectile::OnHit`函数中添加一个`UE_LOG()`函数，以确保当投射物与关卡中的物体接触时调用这个函数。你需要执行以下步骤：

1.  在`Content Browser`界面中，在`/MainCharacter`目录中创建一个名为`Projectile`的新文件夹。

1.  在这个目录中，从你在*练习 13.11*中创建的`PlayerProjectile`类创建一个新的蓝图，命名为`BP_PlayerProjectile`。

1.  打开`BP_PlayerProjectile`并导航到它的组件。选择`MeshComp`组件以访问其设置。

1.  将`Shape_Sphere`网格添加到`MeshComp`组件的静态网格参数中。

1.  更新`MeshComp`的变换，使其适应`CollisionComp`组件的比例和位置。使用以下值：

```cpp
    Location:(X=0.000000,Y=0.000000,Z=-10.000000)
    Scale: (X=0.200000,Y=0.200000,Z=0.200000)
    ```

1.  编译并保存`BP_PlayerProjectile`蓝图。

1.  在 Visual Studio 中导航到`PlayerProjectile.cpp`源文件，并找到`APlayerProjectile::OnHit`函数。

1.  在函数内部，实现`UE_LOG`调用，以便记录的行是`LogTemp`，`Warning log level`，并显示文本`HIT`。`UE_LOG`在*第十一章*，*Blend Spaces 1D，Key Bindings 和 State Machines*中有所涉及。

1.  编译您的代码更改并导航到您在上一个练习中放置`BP_PlayerProjectile`角色的级别。如果您还没有将此角色添加到级别中，请立即添加。

1.  在测试之前，请确保在`Window`选项中打开`Output Log`。从`Window`下拉菜单中，悬停在`Developers Tools`选项上，*左键单击*以选择`Output Log`。

1.  使用`PIE`并在抛射物与某物发生碰撞时注意`Output Log`中的日志警告。

预期输出如下：

![图 13.39：MeshComp 的比例更适合 Collision Comp 的大小](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_13_39.jpg)

图 13.39：MeshComp 的比例更适合 Collision Comp 的大小

日志警告应如下所示：

![图 13.40：当抛射物击中物体时，在输出日志中显示文本 HIT](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_13_40.jpg)

图 13.40：当抛射物击中物体时，在输出日志中显示文本 HIT

完成这最后一个活动后，`Player Projectile`已准备好进入下一章，在这一章中，当玩家使用`Throw`动作时，您将生成此抛射物。您将更新`APlayerProjectile::OnHit`函数，以便它销毁与之发生碰撞的敌人，并成为玩家用来对抗敌人的有效进攻工具。

注意

此活动的解决方案可在以下网址找到：[`packt.live/338jEBx`](https://packt.live/338jEBx)。

# 总结

在本章中，您学习了如何使用 Unreal Engine 4 提供的 AI 工具的不同方面，包括黑板、行为树和 AI 控制器。通过自定义创建的任务和 Unreal Engine 4 提供的默认任务的组合，并使用装饰器，您能够使敌人 AI 在您自己级别中添加的 Nav Mesh 的范围内导航。

除此之外，您还创建了一个新的蓝图角色，允许您使用`Vector`数组变量添加巡逻点。然后，您为此角色添加了一个新函数，该函数随机选择其中一个点，将其位置从局部空间转换为世界空间，然后返回此新值供敌人角色使用。

通过能够随机选择巡逻点，您更新了自定义的`BTTask_FindLocation`任务，以查找并移动到所选的巡逻点，使敌人能够从每个巡逻点随机移动。这将使敌人 AI 角色与玩家和环境的互动达到一个全新的水平。

最后，您创建了玩家抛射物，玩家将能够使用它来摧毁环境中的敌人。您利用了`Projectile Movement Component`和`Sphere Component`，以允许抛射物移动并识别和响应环境中的碰撞。

随着玩家抛射物处于功能状态，现在是时候进入下一章了，在这一章中，您将使用`Anim Notifies`在玩家使用`Throw`动作时生成抛射物。


# 第十三章：生成玩家投射物

概述

在本章中，你将学习`Anim Notifies`和`Anim States`，这些可以在动画蒙太奇中找到。你将使用 C++编写自己的`Anim Notify`，并在`Throw`动画蒙太奇中实现此通知。最后，你将学习视觉和音频效果，以及这些效果在游戏中的使用。

在本章结束时，你将能够在蓝图和 C++中播放动画蒙太奇，并知道如何使用 C++和`UWorld`类将对象生成到游戏世界中。这些游戏元素将被赋予音频和视觉组件作为额外的精细层，并且你的`SuperSideScroller`玩家角色将能够投掷摧毁敌人的投射物。

# 介绍

在上一章中，通过创建一个行为树，使敌人可以从你创建的`BP_AIPoints`角色中随机选择点，你在敌人角色的 AI 方面取得了很大的进展。这使得`SuperSideScroller`游戏更加生动，因为现在你可以在游戏世界中有多个敌人移动。此外，你还学会了虚幻引擎 4 中一些可用于制作各种复杂程度的人工智能的不同工具。这些工具包括`导航网格`、行为树和黑板。

现在你的游戏中有敌人在四处奔跑，你需要允许玩家用上一章末开始创建的玩家投射物来击败这些敌人。

在本章中，你将学习如何使用`UAnimNotify`类在`Throw`动画蒙太奇的特定帧生成玩家投射物。你还将学习如何将这个新的通知添加到蒙太奇本身，以及如何向主角骨骼添加一个新的`Socket`，从中投射物将生成。最后，你将学习如何使用`粒子系统`和`声音提示`为游戏添加视觉和音频层。

让我们通过学习`Anim Notifies`和`Anim Notify States`开始本章。之后，你将通过创建自己的`UAnimNotify`类来实践，以便在`Throw`动画蒙太奇期间生成玩家投射物。

# Anim Notifies 和 Anim Notify States

在创建精致和复杂的动画时，需要一种方式让动画师和程序员在动画中添加自定义事件，以允许发生额外的效果、层和功能。虚幻引擎 4 中的解决方案是使用`Anim Notifies`和`Anim Notify States`。

`Anim Notify`和`Anim Notify State`之间的主要区别在于`Anim Notify State`具有三个`Anim Notify`没有的独特事件。这些事件分别是`Notify Begin`，`Notify End`和`Notify Tick`，所有这些事件都可以在蓝图或 C++中使用。当涉及到这些事件时，虚幻引擎 4 确保以下行为：

+   `Notify State`始终以`Notify Begin Event`开始。

+   `Notify State`将始终以`Notify End Event`结束。

+   `Notify Tick Event`将始终发生在`Notify Begin`和`Notify End`事件之间。

然而，`Anim Notify`是一个更简化的版本，它只使用一个函数`Notify()`，允许程序员为通知本身添加功能。它的工作方式是“发射并忘记”，这意味着你不需要担心`Notify()`事件的开始、结束或中间发生了什么。正是由于`Anim Notify`的简单性，以及我们不需要`Anim Notify State`中包含的事件，我们将使用`Anim Notify`来为 Super Side-Scroller 游戏生成玩家投射物。

在进行下一个练习之前，你将在 C++中创建自己的自定义`Anim Notify`，让我们简要讨论一些虚幻引擎 4 默认提供的`Anim Notifies`的示例。默认`Anim Notifies`状态的完整列表可以在以下截图中看到：

![图 14.1：Unreal Engine 4 中提供的默认 Anim 通知的完整列表](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_14_01.jpg)

图 14.1：Unreal Engine 4 中提供的默认 Anim 通知的完整列表

在本章后面，您将使用两个`Anim 通知`：`播放粒子效果`和`播放声音`。让我们更详细地讨论这两个，以便在使用它们时您对它们更加熟悉：

+   `播放粒子效果`：`播放粒子效果`通知允许您在动画的某一帧生成和播放粒子系统，正如其名称所示。如下面的屏幕截图所示，您可以更改正在使用的 VFX，例如更新粒子的`位置`、`旋转`和`缩放`设置。您甚至可以将粒子附加到指定的`Socket 名称`，如果您愿意的话：![图 14.2：播放粒子效果通知的详细面板，其中允许您自定义粒子](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_14_02.jpg)

图 14.2：播放粒子效果通知的详细面板，允许您自定义粒子

注意

视觉效果，简称 VFX，对于任何游戏来说都是至关重要的元素。在 Unreal Engine 4 中，使用一个名为*Cascade*的工具在编辑器内创建视觉效果。自 Unreal Engine 版本 4.20 以来，引入了一个名为*Niagara*的新工具作为免费插件，以改进 VFX 的质量和流程。您可以在这里了解更多关于*Niagara*的信息：[`docs.unrealengine.com/en-US/Engine/Niagara/Overview/index.html`](https://docs.unrealengine.com/en-US/Engine/Niagara/Overview/index.html)。

游戏中常见的一个例子是使用这种类型的通知在玩家行走或奔跑时在玩家脚下生成泥土或其他效果。能够指定在动画的哪一帧生成这些效果非常强大，可以让您为角色创建令人信服的效果。

+   `播放声音`：`播放声音`通知允许您在动画的某一帧播放`Soundcue`或`Soundwave`。如下面的屏幕截图所示，您可以更改正在使用的声音，更新其`音量`和`音调`值，甚至通过将其附加到指定的`Socket 名称`使声音跟随声音的所有者：![图 14.3：播放声音通知的详细面板，其中](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_14_03.jpg)

图 14.3：播放声音通知的详细面板，允许您自定义声音

与`播放粒子效果`通知所示的例子类似，`播放声音`通知也可以常用于在角色移动时播放脚步声。通过精确控制在动画时间轴的哪个位置播放声音，可以创建逼真的声音效果。

虽然您将不会使用`Anim 通知状态`，但至少了解默认情况下可用的选项仍然很重要，如下面的屏幕截图所示：

![图 14.4：Unreal Engine 4 中提供给您的默认 Anim 通知状态的完整列表](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_14_04.jpg)

图 14.4：Unreal Engine 4 中提供给您的默认 Anim 通知状态的完整列表

注意

在动画序列中不可用的两个“通知”状态是*Montage 通知窗口*和*禁用根动作*状态，如前面的屏幕截图所示。有关通知的更多信息，请参阅以下文档：[docs.unrealengine.com/en-US/Engine/Animation/Sequences/Notifies/index.html](http://docs.unrealengine.com/en-US/Engine/Animation/Sequences/Notifies/index.html)。

现在您对`Anim 通知`和`Anim 通知状态`更加熟悉，让我们继续进行下一个练习，您将在 C++中创建自定义的`Anim 通知`，用于生成玩家的投射物。

## 练习 14.01：创建一个 UAnim 通知类

玩家角色在`SuperSideScroller`游戏中的主要进攻能力是玩家可以向敌人投掷的投射物。在上一章中，您设置了投射物的框架和基本功能，但现在，玩家无法使用它。为了使生成或投掷投射物对眼睛有说服力，您需要创建一个自定义的`Anim Notify`，然后将其添加到`Throw`动画蒙太奇中。这个`Anim Notify`将让玩家知道是时候生成投射物了。

执行以下操作创建新的`UAnimNotify`类：

1.  在虚幻引擎 4 中，导航到`文件`选项，*左键单击*选择`新的 C++类`选项。

1.  从“选择父类”对话框窗口中，搜索`AnimNotify`并*左键单击*`AnimNotify`选项。然后，*左键单击*“下一步”选项来命名新类。

1.  将此新类命名为`Anim_ProjectileNotify`。命名后，*左键单击*选择`创建类`选项，以便虚幻引擎 4 重新编译并在 Visual Studio 中热重载新类。一旦 Visual Studio 打开，您将可以使用头文件`Anim_ProjectileNotify.h`和源文件`Anim_ProjectileNotify.cpp`。

1.  `UAnimNotify`基类有一个函数需要在您的类中实现：

```cpp
virtual void Notify(USkeletalMeshComponent* MeshComp,   UAnimSequenceBase* Animation); 
```

当时间轴上的通知被击中时，此函数将自动调用。通过覆盖此函数，您将能够向通知添加自己的逻辑。此函数还使您能够访问拥有通知的`骨骼网格`组件以及当前正在播放的动画序列。

1.  接下来，让我们在头文件中添加此函数的覆盖声明。在头文件`Anim_ProjectileNotify.h`中，在`GENERATED_BODY()`下面添加以下代码：

```cpp
public:  virtual void Notify(USkeletalMeshComponent*   MeshComp,UAnimSequenceBase* Animation) override;
```

现在您已经将函数添加到头文件中，是时候在`Anim_ProjectileNotify`源文件中定义该函数了。

1.  在`Anim_ProjectileNotify.cpp`源文件中，定义该函数并添加一个`UE_LOG()`调用，打印文本`"Throw Notify"`，如下所示：

```cpp
void UAnim_ProjectileNotify::Notify(USkeletalMeshComponent*   MeshComp, UAnimSequenceBase* Animation)
{
  UE_LOG(LogTemp, Warning, TEXT("Throw Notify"));
}
```

目前，您将仅使用此`UE_LOG()`调试工具，以便知道在下一个练习中将此通知添加到`Throw`动画蒙太奇时，该函数是否被正确调用。

在本练习中，您通过添加以下函数创建了实现自己的`AnimNotify`类所需的基础工作：

```cpp
Notify(USkeletalMeshComponent* MeshComp, UAnimSequenceBase* Animation)
```

在此函数中，您使用`UE_LOG()`在输出日志中打印自定义文本`"Throw Notify"`，以便您知道此通知是否正常工作。

在本章后面，您将更新此函数，以便调用将生成玩家投射物的逻辑，但首先，让我们将新通知添加到`Throw`动画蒙太奇中。

## 练习 14.02：将通知添加到投掷蒙太奇

现在您有了`Anim_ProjectileNotify`通知，是时候将此通知添加到`Throw`动画蒙太奇中，以便实际为您所用。

在本练习中，您将在`Throw`蒙太奇的时间轴上的确切帧上添加`Anim_ProjectileNotify`，以便您期望投射物生成。

完成以下步骤以实现此目标：

1.  回到虚幻引擎，在`内容浏览器`界面中，转到`/MainCharacter/Animation/`目录。在此目录中，*双击*`AM_Throw`资产以打开`动画蒙太奇`编辑器。

在`动画蒙太奇`编辑器的底部，您将找到动画的时间轴。默认情况下，您会观察到*红色的条*会随着动画的播放而沿着时间轴移动。

1.  *左键单击*这个`红色`条，并手动将其移动到第 22 个`帧`，尽可能靠近，如下面的截图所示：![图 14.5：红色条允许您手动定位在时间轴的任何位置发出通知](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_14_05.jpg)

图 14.5：红色条允许您在时间轴上手动定位通知

`Throw`动画的第 22 帧是您期望玩家生成并投掷抛射物的确切时刻。以下截图显示了抛掷动画的帧，如在`Persona`编辑器中所见：

![图 14.6：玩家抛射物应该生成的确切时刻](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_14_06.jpg)

图 14.6：玩家抛射物应该生成的确切时刻

1.  现在您已经知道通知应该播放的时间轴位置，您现在可以在`Notifies`时间轴上*右键单击*细长的`红色`线。

这将显示一个弹出窗口，您可以在其中添加`Notify`或`Notify State`。在某些情况下，`Notifies`时间轴可能会被折叠并且难以找到；只需左键单击`Notifies`一词，即可在折叠和展开之间切换。

1.  选择`Add Notify`，然后从提供的选项中找到并选择`Anim Projectile Notify`。

1.  在将`Anim Projectile Notify`添加到通知时间轴后，您将看到以下内容：![图 14.7：Anim_ProjectileNotify 成功添加到 Throw 动画蒙太奇](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_14_07.jpg)

图 14.7：Anim_ProjectileNotify 成功添加到 Throw 动画蒙太奇

1.  在`Throw`动画蒙太奇时间轴上放置`Anim_ProjectileNotify`通知后，保存蒙太奇。

1.  如果`Output Log`窗口不可见，请通过导航到`Window`选项并悬停在`Developer Tools`上来重新启用窗口。找到`Output Log`选项，*左键单击*以启用它。

1.  现在，使用`PIE`，一旦进入游戏，使用*左鼠标按钮*开始播放`Throw`蒙太奇。

在您添加通知的动画位置，您现在将在输出日志中看到调试日志文本`Throw Notify`出现。

正如您可能还记得的*第十二章*，*动画混合和蒙太奇*中，您已将`Play Montage`函数添加到了玩家角色蓝图`BP_SuperSideScroller_MainCharacter`。为了在 Unreal Engine 4 的上下文中学习 C++，您将在即将进行的练习中将此逻辑从蓝图移至 C++。这样我们就不会过分依赖蓝图脚本来实现玩家角色的基本行为。

完成此练习后，您已成功将自定义的`Anim Notify`类`Anim_ProjectileNotify`添加到`Throw`动画蒙太奇中。此通知已添加到您期望从玩家手中投掷抛射物的确切帧。由于您在*第十二章*，*动画混合和蒙太奇*中为玩家角色添加了蓝图逻辑，因此当使用*左鼠标按钮*调用`InputAction`事件`ThrowProjectile`时，您可以播放此`Throw`动画蒙太奇。在从蓝图中播放 Throw 动画蒙太奇转换为从 C++中播放蒙太奇之前，让我们再讨论一下播放动画蒙太奇。

# 播放动画蒙太奇

正如您在*第十二章*，*动画混合和蒙太奇*中所学到的，这些项目对于允许动画师将单独的动画序列组合成一个完整的蒙太奇非常有用。通过将蒙太奇分割为自己独特的部分并为粒子和声音添加通知，动画师和动画程序员可以制作处理动画的所有不同方面的复杂蒙太奇集。

但是一旦动画蒙太奇准备就绪，我们如何在角色上播放这个蒙太奇？您已经熟悉第一种方法，即通过蓝图。

## 在蓝图中播放动画蒙太奇

在蓝图中，`Play Montage`函数可供您使用，如下截图所示：

![图 14.8：蓝图中的播放蒙太奇功能](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_14_08.jpg)

图 14.8：蓝图中的播放蒙太奇功能

您已经使用了播放`AM_Throw`动画 Montage 的函数。此函数需要 Montage 必须在其上播放的“骨骼网格”组件，并且需要播放的动画 Montage。

其余的参数是可选的，具体取决于 Montage 的工作方式。让我们快速看看这些参数：

+   “播放速率”： “播放速率”参数允许您增加或减少动画 Montage 的播放速度。要加快播放速度，您将增加此值；否则，您将减少值以减慢播放速度。

+   “起始位置”： “起始位置”参数允许您设置 Montage 时间轴上的起始位置（以秒为单位），从该位置开始播放 Montage。例如，在一个持续 3 秒的动画 Montage 中，您可以选择让 Montage 从`1.0f`位置开始，而不是从`0.0f`开始。

+   “起始部分”： “起始部分”参数允许您告诉动画 Montage 从特定部分开始。根据 Montage 的设置方式，您可以为 Montage 的不同部分创建多个部分。例如，霰弹枪武器重新装填动画 Montage 将包括一个用于重新装填的初始移动部分，一个用于实际子弹重新装填的循环部分，以及一个用于重新装备武器的最终部分，以便它准备好再次开火。

当涉及到`Play Montage`函数的输出时，您有几种不同的选择：

+   “完成时”： “完成时”输出在动画 Montage 完成播放并完全混合结束时调用。

+   “混合结束时”： “混合结束时”输出在动画 Montage 开始混合结束时调用。这可能发生在“混合触发时间”期间，或者如果 Montage 过早结束。

+   “中断时”： “中断时”输出在由于另一个试图在相同骨架上播放的 Montage 中断此 Montage 而开始混合结束时调用。

+   “通知开始”和“通知结束”：如果您正在使用动画 Montage 中“通知”类别下的“Montage 通知”选项，则“通知开始”和“通知结束”输出都会被调用。通过“通知名称”参数返回给 Montage 通知的名称。

## 在 C++中播放动画 Montage

在 C++方面，您只需要了解一个事情，那就是`UAnimInstance::Montage_Play()`函数。此函数需要要播放的动画 Montage，以及播放 Montage 的播放速率，EMontagePlayReturnType 类型的值，用于确定播放 Montage 的起始位置的 float 值，以及用于确定是否停止或中断所有 Montage 的布尔值。

尽管您不会更改`EMontagePlayReturnType`的默认参数，即`EMontagePlayReturnType::MontageLength`，但仍然重要知道此枚举器存在的两个值：

+   “Montage 长度”： “Montage 长度”值返回 Montage 本身的长度，以秒为单位。

+   “持续时间”： “持续时间”值返回 Montage 的播放持续时间，等于 Montage 的长度除以播放速率。

注意

有关`UAnimMontage`类的更多详细信息，请参阅以下文档：https://docs.unrealengine.com/en-US/API/Runtime/Engine/Animation/UAnimMontage/index.html。

您将在下一个练习中了解有关播放动画 Montage 的 C++实现的更多信息。

## 练习 14.03：在 C++中播放投掷动画

现在你对在虚幻引擎 4 中通过蓝图和 C++播放动画蒙太奇有了更好的理解，是时候将播放“投掷”动画蒙太奇的逻辑从蓝图迁移到 C++了。这个改变的原因是因为蓝图逻辑是作为一个占位方法放置的，这样你就可以预览“投掷”蒙太奇。这本书更加专注于 C++游戏开发，因此，学习如何在代码中实现这个逻辑是很重要的。

让我们首先从蓝图中移除逻辑，然后继续在玩家角色类中用 C++重新创建这个逻辑。

以下步骤将帮助你完成这个练习：

1.  导航到玩家角色蓝图，`BP_SuperSideScroller_MainCharacter`，可以在以下目录中找到：`/MainCharacter/Blueprints/`。*双击*这个资源来打开它。

1.  在这个蓝图中，你会找到`InputAction ThrowProjectile`事件和你创建的`Play Montage`函数，用于预览`Throw`动画蒙太奇，如下截图所示。删除这个逻辑，然后重新编译并保存玩家角色蓝图：![图 14.9：你不再需要在玩家角色蓝图中使用这个占位逻辑](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_14_09.jpg)

图 14.9：你不再需要在玩家角色蓝图中使用这个占位逻辑

1.  现在，使用`PIE`并尝试用*左鼠标按钮*让玩家角色投掷。你会发现玩家角色不再播放`Throw`动画蒙太奇。让我们通过在 C++中添加所需的逻辑来修复这个问题。

1.  在 Visual Studio 中打开玩家角色的头文件，`SuperSideScroller_Player.h`。

1.  你需要做的第一件事是创建一个新的变量，用于玩家角色的`Throw`动画。在`Private`访问修饰符下添加以下代码：

```cpp
UPROPERTY(EditAnywhere)
class UAnimMontage* ThrowMontage;
```

现在你有一个变量，它将代表“投掷”动画蒙太奇，是时候在`SuperSideScroller_Player.cpp`文件中添加播放蒙太奇的逻辑了。

1.  在你调用`UAnimInstance::Montage_Play()`之前，你需要在源文件顶部的现有列表中添加以下`include`目录，以便访问这个函数：

```cpp
#include "Animation/AnimInstance.h"
```

正如我们从*第九章*，*音频-视觉元素*中知道的，玩家角色已经有一个名为`ThrowProjectile`的函数，每当按下*左鼠标按钮*时就会调用。作为提醒，在 C++中绑定发生在这里：

```cpp
//Bind pressed action ThrowProjectile to your ThrowProjectile   function
PlayerInputComponent->BindAction("ThrowProjectile", IE_Pressed,   this, &ASuperSideScroller_Player::ThrowProjectile);
```

1.  更新`ThrowProjectile`，使其播放你在这个练习中设置的`ThrowMontage`。将以下代码添加到`ThrowProjectile()`函数中。然后，我们可以讨论这里发生了什么：

```cpp
void ASuperSideScroller_Player::ThrowProjectile()
{
  if (ThrowMontage)
  {
    bool bIsMontagePlaying = GetMesh()->GetAnimInstance()->      Montage_IsPlaying(ThrowMontage);
    if (!bIsMontagePlaying)
    {
      GetMesh()->GetAnimInstance()->Montage_Play(ThrowMontage,         2.0f);
    }
    }    }
```

第一行是检查`ThrowMontage`是否有效；如果我们没有分配有效的动画蒙太奇，继续逻辑就没有意义，而且在后续函数调用中使用 NULL 对象可能会导致崩溃，这也是很危险的。接下来，我们声明一个新的布尔变量，称为`bIsMontagePlaying`，用于确定`ThrowMontage`是否已经在玩家角色的骨骼网格上播放。这个检查是因为`Throw`动画蒙太奇在已经播放时不应该再次播放；如果玩家反复按下*左鼠标按钮*，这将导致动画中断。

接下来，有一个`If`语句，检查`ThrowMontage`是否有效，以及蒙太奇是否正在播放。只要满足这些条件，就可以安全地继续播放动画蒙太奇。

1.  在`If`语句内部，您正在告诉玩家的骨骼网格以`1.0f`的播放速率播放`ThrowMontage`动画蒙太奇。使用`1.0f`值是为了使动画蒙太奇以预期速度播放。大于`1.0f`的值将使蒙太奇以更快的速度播放，而小于`1.0f`的值将使蒙太奇以更慢的速度播放。您学到的其他参数，如起始位置或`EMontagePlayReturnType`参数，可以保持其默认值。回到虚幻引擎 4 编辑器内，进行代码重新编译，就像您以前做过的那样。

1.  代码成功重新编译后，导航回玩家角色蓝图`BP_SuperSideScroller_MainCharacter`，该蓝图可以在以下目录中找到：`/MainCharacter/Blueprints/`。*双击*此资源以打开它。

1.  在玩家角色的“详细信息”面板中，您现在将看到您添加的“投掷动画”参数。

1.  *左键单击*“投掷动画”参数的下拉菜单，找到`AM_Throw`动画。再次*左键单击*`AM_Throw`选项以选择它作为此参数。请参考以下截图，查看变量应如何设置：![图 14.10：现在，投掷动画被分配为 AM_Throw 动画](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_14_10.jpg)

图 14.10：现在，投掷动画被分配为 AM_Throw 动画

1.  重新编译并保存玩家角色蓝图。然后，使用`PIE`生成玩家角色，并使用*鼠标左键*播放“投掷动画”。以下截图显示了这一过程：![图 14.11：玩家角色现在能够再次执行投掷动画](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_14_11.jpg)

图 14.11：玩家角色现在能够再次执行投掷动画

通过完成这个练习，您已经学会了如何向玩家角色添加“动画蒙太奇”参数，以及如何在 C++中播放蒙太奇。除了在 C++中播放“投掷”动画蒙太奇之外，您还通过添加检查蒙太奇是否已经在播放来控制“投掷”动画可以播放的频率。通过这样做，您可以防止玩家不断按下“投掷”输入，导致动画中断或完全不播放。

注意

尝试将“动画蒙太奇”的播放速率从`1.0f`设置为`2.0f`，然后重新编译代码。观察增加动画播放速率如何影响玩家对动画的外观和感觉。

# 游戏世界和生成对象

当涉及将对象生成到游戏世界中时，实际上是代表您的关卡的`World`对象处理了这些对象的创建。您可以将`UWorld`类对象视为代表您的关卡的单个顶层对象。

`UWorld`类可以做很多事情，比如从世界中生成和移除对象，检测何时正在更改或流入/流出级别，甚至执行线性跟踪以帮助进行对象检测。在本章中，我们将专注于生成对象。

`UWorld`类有多种`SpawnActor()`函数的变体，取决于您希望如何生成对象，或者您在生成此对象的上下文中可以访问哪些参数。要考虑的三个一致参数是：

+   `UClass`：`UClass`参数只是您想要生成的对象的类。

+   `FActorSpawnParameters`：这是一个包含变量的结构，为生成的对象提供更多上下文和引用。有关此结构中包含的所有变量的列表，请参考虚幻引擎 4 社区维基上的这篇文章：https://www.ue4community.wiki/Actor#Spawn

让我们简要讨论`FActorSpawnParameters`中包含的一个更关键的变量：`Owner` actor。`Owner`是生成此对象的 actor，在玩家角色和投射物的情况下，您需要明确引用玩家作为投射物的所有者。尤其是在这个游戏的背景下，这是很重要的，因为您不希望投射物与其`Owner`发生碰撞；您希望这个投射物完全忽略所有者，只与敌人或关卡环境发生碰撞。

+   `Transform`：当将对象生成到世界中时，世界需要知道此 actor 的`位置`、`旋转`和`缩放`属性，然后才能生成它。在`SpawnActor()`函数的某些模板中，需要传递完整的`Transform`，而在其他模板中，需要单独传递`Location`和`Rotation`。

在继续生成玩家投射物之前，让我们设置玩家角色“骨架”中的`Socket`位置，以便在“投掷”动画期间可以从*玩家手*生成投射物。

## 练习 14.04：创建投射物生成 Socket

为了生成玩家投射物，您需要确定投射物将生成的`Transform`，主要关注`位置`和`旋转`，而不是`缩放`。

在这个练习中，您将在玩家角色的“骨架”上创建一个新的`Socket`，然后可以在代码中引用它，以便获取生成投射物的位置。

让我们开始吧：

1.  在虚幻引擎 4 中，导航到“内容浏览器”界面，找到`/MainCharacter/Mesh/`目录。

1.  在此目录中，找到“骨架”资产；即`MainCharacter_Skeleton.uasset`。*双击*打开此“骨架”。

为了确定投射物应该生成的最佳位置，我们需要将“投掷”动画剪辑添加为骨架的预览动画。

1.  在`Details`面板中，在`Animation`类别下，找到`Preview Controller`参数，并选择`Use Specific Animation`选项。

1.  接下来，*左键单击*下拉菜单，找到并选择可用动画列表中的`AM_Throw`动画剪辑。

现在，玩家角色的“骨架”将开始预览“投掷”动画剪辑，如下面的屏幕截图所示：

![图 14.12：玩家角色预览投掷动画剪辑](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_14_12.jpg)

图 14.12：玩家角色预览投掷动画剪辑

如果您还记得*练习 14.02*，*添加到投掷剪辑的通知*，您在“投掷”动画的第 22 帧添加了`Anim_ProjectileNotify`。

1.  使用“骨架”编辑器底部的时间轴，将“红色”条移动到尽可能接近第 22 帧。请参考以下屏幕截图：![图 14.13：在之前的练习中添加 Anim_ProjectileNotify i 在之前的练习中](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_14_13.jpg)

图 14.13：在之前的练习中添加了 Anim_ProjectileNotify 的第 22 帧相同的帧

在“投掷”动画的第 22 帧，玩家角色应该如下所示：

![图 14.14：在投掷动画剪辑的第 22 帧，角色的手位于释放投射物的位置](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_14_14.jpg)

图 14.14：在投掷动画剪辑的第 22 帧，角色的手位于释放投射物的位置

正如您所看到的，玩家角色将从他们的右手投掷投射物，因此新的`Socket`应该连接到*右手*。让我们看一下玩家角色的骨骼层次结构，如下面的屏幕截图所示：

![图 14.15：在层次结构中找到的 RightHand 骨骼玩家角色的骨架](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_14_15.jpg)

图 14.15：在玩家角色骨架的层次结构中找到的 RightHand 骨骼

1.  从骨骼层次结构中找到`RightHand`骨骼。这可以在`RightShoulder`骨骼层次结构下找到。

1.  *右键单击*`RightHand`骨骼，然后*左键单击*出现的选项列表中的`Add Socket`选项。将此插座命名为`ProjectileSocket`。

此外，当添加一个新的`Socket`时，整个`RightHand`的层次结构将扩展，新的插座将出现在底部。

1.  选择`ProjectileSocket`，使用`Transform`小部件小部件将此`Socket`定位到以下位置：

```cpp
Location = (X=12.961717,Y=25.448450,Z=-7.120584)
```

最终结果应该如下所示：

![图 14.16：抛射物插座在世界空间中抛出动画的第 22 帧的最终位置。](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_14_16.jpg)

图 14.16：抛射物插座在世界空间中抛出动画的第 22 帧的最终位置。

如果你的小部件看起来有点不同，那是因为上面的图像显示了世界空间中的插座位置，而不是本地空间。

1.  现在`ProjectileSocket`的位置已经就位，保存`MainCharacter_Skeleton`资产。

通过完成这个练习，你现在知道玩家抛射物将从哪个位置生成。由于你在预览中使用了`Throw`动画蒙太奇，并使用了相同的动画的第 22 帧，所以你知道这个位置将根据`Anim_ProjectileNotify`的触发时间是正确的。

现在，让我们继续在 C++中生成玩家抛射物。

## 练习 14.05：准备`SpawnProjectile()`函数

现在`ProjectileSocket`已经就位，并且现在有一个位置可以生成玩家抛射物了，让我们添加生成玩家抛射物所需的代码。

通过这个练习结束时，你将有一个准备好生成抛射物的函数，并且它将准备好从`Anim_ProjectileNotify`类中调用。

执行以下步骤：

1.  从 Visual Studio 中，导航到`SuperSideScroller_Player.h`头文件。

1.  你需要一个指向`PlayerProjectile`类的类引用变量。你可以使用名为`TSubclassOf`的变量模板类类型来实现这一点。在`Private`访问修饰符下，将以下代码添加到头文件中：

```cpp
UPROPERTY(EditAnywhere)
TSubclassOf<class APlayerProjectile> PlayerProjectile;
```

现在你已经准备好变量，是时候声明你将用来生成抛射物的函数了。

1.  在`ThrowProjectile()`函数的声明和`Public`访问修饰符下添加以下函数声明：

```cpp
void SpawnProjectile();
```

1.  在准备`SpawnProjectile()`函数的定义之前，将以下`include`目录添加到`SuperSideScroller_Player.cpp`源文件的包含列表中：

```cpp
#include "PlayerProjectile.h"
#include "Engine/World.h"
#include "Components/SphereComponent.h"
```

你需要包含`PlayerProjectile.h`，因为这是为了引用抛射物类的碰撞组件而必需的。接下来，使用`Engine/World.h`的包含是为了使用`SpawnActor()`函数和访问`FActorSpawnParameters`结构。最后，你需要使用`Components/SphereComponent.h`的包含，以便更新玩家抛射物的碰撞组件，使其忽略玩家。

1.  接下来，在`SuperSideScroller_Player.cpp`源文件的底部创建`SpawnProjectile()`函数的定义，如下所示：

```cpp
void ASuperSideScroller_Player::SpawnProjectile()
{
}
```

这个函数需要做的第一件事是检查`PlayerProjectile`类变量是否有效。如果这个对象无效，继续尝试生成它就没有意义了。

1.  更新`SpawnProjectile()`函数如下：

```cpp
void ASuperSideScroller_Player::SpawnProjectile()
{
  if(PlayerProjectile)
    {
    }
}
```

现在，如果`PlayerProjectile`对象有效，你将想要获取玩家当前存在的`UWorld`对象，并确保这个世界在继续之前是有效的。

1.  更新`SpawnProjectile()`函数如下：

```cpp
void ASuperSideScroller_Player::SpawnProjectile()
{
  if(PlayerProjectile)
    {
      UWorld* World = GetWorld();
      if (World)
        {
        }
    }
}
```

此时，你已经进行了安全检查，以确保`PlayerProjectile`和`UWorld`都是有效的，所以现在可以安全地尝试生成抛射物了。首先要做的是声明一个新的`FactorSpawnParameters`类型的变量，并将玩家指定为所有者。

1.  在最近的`if`语句中添加以下代码，使`SpawnProjectile()`函数看起来像这样：

```cpp
void ASuperSideScroller_Player::SpawnProjectile()
{
  if(PlayerProjectile)
    {
      UWorld* World = GetWorld();
      if (World)
        {
          FActorSpawnParameters SpawnParams;
          SpawnParams.Owner = this; 
        }
    }
}
```

正如你之前学到的，`UWorld`对象的`SpawnActor()`函数调用将需要`FActorSpawnParameters`结构作为生成对象的初始化的一部分。对于玩家投射物，你可以使用`this`关键字作为玩家角色类的引用，作为投射物的所有者。这在以后在这个函数中更新投射物的碰撞时会派上用场。

1.  接下来，你需要处理`SpawnActor()`函数的`Location`和`Rotation`参数。在最新的一行下面添加以下行：

```cpp
FVector SpawnLocation = this->GetMesh()-  >GetSocketLocation(FName("ProjectileSocket"));
FRotator Rotation = GetActorForwardVector().Rotation();
```

在第一行中，声明一个名为`SpawnLocation`的新`FVector`变量。这个向量使用你在上一个练习中创建的`ProjectileSocket`插座的`Socket`位置。从`GetMesh()`函数返回的`Skeletal Mesh`组件包含一个名为`GetSocketLocation()`的函数，它将返回传入的`FName`的插座位置；在这种情况下，是名为`ProjectileSocket`。

在第二行，声明一个名为`Rotation`的新`FRotator`变量。这个值设置为玩家的前向向量，转换为`Rotator`容器。这将确保玩家投射物生成的旋转，或者换句话说，方向，将在玩家的前方，并且它将远离玩家。

现在，生成项目所需的所有参数都已准备好。

1.  在上一步的代码下面添加以下行：

```cpp
APlayerProjectile* Projectile = World-  >SpawnActor<APlayerProjectile>(PlayerProjectile, SpawnLocation,   Rotation, SpawnParams);
```

`World->SpawnActor()`函数将返回你尝试生成的类的对象；在这种情况下是`APlayerProjectile`。这就是为什么在实际生成之前要添加`APlayerProjectile* Projectile`。然后，你要传入`SpawnLocation`、`Rotation`和`SpawnParams`参数，以确保项目生成在你想要的位置和方式。

1.  最后，你可以通过添加以下代码行将玩家角色添加到要忽略的演员数组中：

```cpp
if (Projectile)
{
  Projectile->CollisionComp->    MoveIgnoreActors.Add(SpawnParams.Owner);
}
```

现在你有了投射物的引用，这一行正在更新`CollisionComp`组件，以便将玩家或`SpawnParams.Owner`添加到`MoveIgnoreActors`数组中。这个演员数组将被投射物的碰撞忽略，因为这个投射物不应该与投掷它的玩家发生碰撞。

1.  返回编辑器重新编译新添加的代码。代码成功编译后，这个练习就完成了。

完成这个练习后，你现在有一个函数，可以生成分配给玩家角色内的玩家投射物类。通过为投射物和世界的有效性添加安全检查，你确保如果生成了一个对象，它是一个有效的对象在一个有效的世界内。

接下来，为`UWorld SpawnActor()`函数设置适当的`location`、`rotation`和`FActorSpawnParameters`参数，以确保玩家投射物在正确的位置生成，基于上一个练习中的插座位置，以适当的方向远离玩家，并以玩家角色作为其`Owner`。

现在是时候更新`Anim_ProjectileNotify`源文件，以便生成投射物。

## 练习 14.06：更新 Anim_ProjectileNotify 类

你已经准备好允许玩家投射物生成的函数，但是你还没有在任何地方调用这个函数。回到*练习 14.01*，*创建 UAnim Notify 类*，你创建了`Anim_ProjectileNotify`类，而在*练习 14.02*，*将通知添加到投掷动画*，你将这个通知添加到`Throw`动画蒙太奇中。

现在是时候更新`Uanim` `Notify`类，以便调用`SpawnProjectile()`函数。

要实现这一点，请执行以下操作：

1.  在 Visual Studio 中，打开`Anim_ProjectileNotify.cpp`源文件。

在源文件中，您有以下代码：

```cpp
#include "Anim_ProjectileNotify.h"
void UAnim_ProjectileNotify::Notify(USkeletalMeshComponent*   MeshComp, UAnimSequenceBase* Animation)
{
  UE_LOG(LogTemp, Warning, TEXT("Throw Notify"));
}
```

1.  从`Notify()`函数中删除`UE_LOG()`行。

1.  接下来，在`Anim_ProjectileNotify.h`下面添加以下`include`行：

```cpp
#include "Components/SkeletalMeshComponent.h"
#include "SuperSideScroller/SuperSideScroller_Player.h"
```

您需要包含`SuperSideScroller_Player.h`头文件，因为这是在调用您在上一个练习中创建的`SpawnProjectile()`函数时所需的。我们还包括了`SkeletalMeshComponent.h`，因为我们将在`Notify()`函数中引用此组件，所以最好也在这里包含它。

`Notify()`函数传入拥有的`Skeletal Mesh`的引用，标记为`MeshComp`。您可以使用骨骼网格来通过使用`GetOwner()`函数并将返回的角色转换为您的`SuperSideScroller_Player`类来获取对玩家角色的引用。我们将在下一步中执行此操作。

1.  在`Notify()`函数中，添加以下代码行：

```cpp
ASuperSideScroller_Player* Player =   Cast<ASuperSideScroller_Player>(MeshComp->GetOwner());
```

1.  现在您已经有了对玩家的引用，您需要在调用`SpawnProjectile()`函数之前对`Player`变量进行有效性检查。在上一步的行之后添加以下代码行：

```cpp
if (Player)
{
  Player->SpawnProjectile();
}
```

1.  现在`SpawnProjectile()`函数从`Notify()`函数中被调用，返回编辑器重新编译和热重载您所做的代码更改。

在您能够使用`PIE`四处奔跑并投掷玩家投射物之前，您需要从上一个练习中分配`Player Projectile`变量。

1.  在`Content Browser`界面中，导航到`/MainCharacter/Blueprints`目录，找到`BP_SuperSideScroller_MainCharacter`蓝图。 *双击*打开蓝图。

1.  在`Details`面板中，在`Throw Montage`参数下，您将找到`Player Projectile`参数。 *左键单击*此参数的下拉选项，并找到`BP_PlayerProjectile`。 *左键单击*此选项以将其分配给`Player Projectile`变量。

1.  重新编译并保存`BP_SuperSideScroller_MainCharacter`蓝图。

1.  现在，使用`PIE`并使用*鼠标左键*。玩家角色将播放`Throw`动画，玩家投射物将生成。

注意，投射物是从您创建的`ProjectileSocket`函数中生成的，并且它远离玩家。以下截图显示了这一点：

![图 14.17：玩家现在可以投掷玩家投射物](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_14_17.jpg)

图 14.17：玩家现在可以投掷玩家投射物

完成此练习后，玩家现在可以投掷玩家投射物。当前状态下的玩家投射物对敌人无效，只是在空中飞行。在`Throw`动画 Montage、`Anim_ProjectileNotify`类和玩家角色之间需要很多移动部件才能让玩家投掷投射物。

在即将进行的练习中，您将更新玩家投射物，以便销毁敌人并播放额外的效果，如粒子和声音。

# 销毁角色

到目前为止，在本章中，我们已经非常关注在游戏世界中生成或创建角色；玩家角色使用`UWorld`类来生成投射物。Unreal Engine 4 及其基本的`Actor`类带有一个默认函数，您可以使用它来销毁或移除游戏世界中的角色：

```cpp
bool AActor::Destroy( bool bNetForce, bool bShouldModifyLevel )
```

您可以在 Visual Studio 中找到此函数的完整实现，方法是在`/Source/Runtime/Engine/Actor.cpp`目录中找到`Actor.cpp`源文件。此函数存在于所有扩展自`Actor`类的类中，在 Unreal Engine 4 的情况下，它存在于所有可以在游戏世界中生成或放置的类中。更明确地说，`EnemyBase`和`PlayerProjectile`类都是`Actor`类的*子类*，因此可以被销毁。

进一步查看`AActor::Destroy()`函数，您将找到以下行：

```cpp
World->DestroyActor( this, bNetForce, bShouldModifyLevel );
```

我们不会详细讨论`UWorld`类到底如何销毁角色，但重要的是要强调`UWorld`类负责在世界中创建和销毁角色。随时深入挖掘源引擎代码，找到更多关于`UWorld`类如何处理角色的销毁和生成的信息。

现在你对 Unreal Engine 4 如何处理游戏世界中的角色的销毁和移除有了更多的上下文，我们将为敌人角色实现这一功能。

## 练习 14.07：创建 DestroyEnemy()函数

`Super SideScroller`游戏的主要玩法是玩家在关卡中移动并使用投射物来摧毁敌人。在项目的这一阶段，你已经处理了玩家移动和生成玩家投射物。然而，投射物还不能摧毁敌人。

为了实现这个功能，我们将首先向`EnemyBase`类添加一些逻辑，以便它知道如何处理自己的销毁，并在与玩家投射物碰撞时从游戏中移除它。

完成以下步骤来实现这一点：

1.  首先，转到 Visual Studio 并打开`EnemyBase.h`头文件。

1.  在头文件中，在`Public`访问修饰符下创建一个名为`DestroyEnemy()`的新函数声明，如下所示：

```cpp
public:
  void DestroyEnemy();
```

确保这个函数定义写在`GENERATED_BODY()`下面，在类定义内部。

1.  保存这些更改到头文件，并打开`EnemyBase.cpp`源文件，以添加这个函数的实现。

1.  在`#include`行下面，添加以下函数定义：

```cpp
void AEnemyBase::DestroyEnemy()
{
}
```

目前，这个函数将非常简单。你只需要调用基类`Actor`的继承`Destroy()`函数。

1.  更新`DestroyEnemy()`函数，使其看起来像这样：

```cpp
void AEnemyBase::DestroyEnemy()
{
  Destroy();
}
```

1.  完成这个函数后，保存源文件并返回编辑器，这样你就可以重新编译和热重载代码了。

完成这个练习后，敌人角色现在有一个函数，可以轻松处理角色的销毁。`DestroyEnemy()`函数是公开可访问的，因此其他类可以调用它，在处理玩家投射物的销毁时会很方便。

你创建自己独特的销毁敌人角色的函数的原因是因为你将在本章后面使用这个函数来为敌人被玩家投射物销毁时添加 VFX 和 SFX。

在进行敌人销毁的润色元素之前，让我们在玩家投射物类中实现一个类似的函数，以便它也可以被销毁。

## 练习 14.08：销毁投射物

现在敌人角色可以通过你在上一个练习中实现的新的`DestroyEnemy()`函数处理被销毁了，现在是时候为玩家投射物做同样的事情了。

通过这个练习结束时，玩家投射物将有自己独特的函数来处理自己的销毁和从游戏世界中移除。

让我们开始吧：

1.  在 Visual Studio 中，打开玩家投射物的头文件；也就是`PlayerProjectile.h`。

1.  在`Public`访问修饰符下，添加以下函数声明：

```cpp
void ExplodeProjectile();
```

1.  接下来，打开玩家投射物的源文件；也就是`PlayerProjectile.cpp`。

1.  在`APlayerProjectile::OnHit`函数下面，添加`ExplodeProjectile()`函数的定义：

```cpp
void APlayerProjectile::ExplodeProjectile()
{
}
```

目前，这个函数将与上一个练习中的`DestroyEnemy()`函数完全相同。

1.  将继承的`Destroy()`函数添加到新的`ExplodeProjectile()`函数中，如下所示：

```cpp
void APlayerProjectile::ExplodeProjectile()
{
  Destroy();
}
```

1.  完成这个函数后，保存源文件并返回编辑器，这样你就可以重新编译和热重载代码了。

完成此练习后，玩家抛射物现在具有一个可以轻松处理角色摧毁的功能。您需要创建自己独特的函数来处理摧毁玩家抛射物角色的原因与创建`DestroyEnemy()`函数的原因相同-您将在本章后面使用此函数为玩家抛射物与其他角色碰撞时添加 VFX 和 SFX。

现在您已经有了在玩家抛射物和敌人角色内部实现`Destroy()`函数的经验，是时候将这两个元素结合起来了。

在下一个活动中，您将使玩家抛射物能够在碰撞时摧毁敌人角色。

## 活动 14.01：抛射物摧毁敌人

现在玩家抛射物和敌人角色都可以处理被摧毁的情况，是时候迈出额外的一步，允许玩家抛射物在碰撞时摧毁敌人角色了。

执行以下步骤来实现这一点：

1.  在`PlayerProjectile.cpp`源文件的顶部添加`#include`语句，引用`EnemyBase.h`头文件。

1.  在`APlayerProjectile::OnHit()`函数中，创建一个`AEnemyBase*`类型的新变量，并将此变量命名为`Enemy`。

1.  将`APlayerProjectile::OnHit()`函数的`OtherActor`参数转换为`AEnemyBase*`类，并将`Enemy`变量设置为此转换的结果。

1.  使用`if()`语句检查`Enemy`变量的有效性。

1.  如果`Enemy`有效，则从此`Enemy`调用`DestroyEnemy()`函数。

1.  在`if()`块之后，调用`ExplodeProjectile()`函数。

1.  保存源文件的更改并返回到虚幻引擎 4 编辑器。

1.  使用`PIE`，然后使用玩家抛射物对抗敌人以观察结果。

预期输出如下：

![图 14.18：玩家投掷抛射物](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_14_18.jpg)

图 14.18：玩家投掷抛射物

当抛射物击中敌人时，敌人角色被摧毁，如下所示：

![图 14.19：抛射物和敌人被摧毁](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_14_19.jpg)

图 14.19：抛射物和敌人被摧毁

完成此活动后，玩家抛射物和敌人角色在碰撞时可以被摧毁。此外，每当另一个角色触发其`APlayerProjectile::OnHit()`函数时，玩家抛射物也将被摧毁。

通过这样，`Super SideScroller`游戏的一个重要元素已经完成：玩家抛射物的生成以及敌人与抛射物碰撞时的摧毁。您可以观察到摧毁这些角色非常简单，对玩家来说并不是很有趣。

因此，在本章的即将进行的练习中，您将更多地了解有关视觉和音频效果，即 VFX 和 SFX。您还将针对敌人角色和玩家抛射物实现这些元素。

现在敌人角色和玩家抛射物都可以被摧毁，让我们简要讨论一下 VFX 和 SFX 是什么，以及它们将如何影响项目。

注意

此活动的解决方案可在以下链接找到：[`packt.live/338jEBx`](https://packt.live/338jEBx)。

# 视觉和音频效果

视觉效果，如粒子系统和声音效果，如声音提示，在视频游戏中扮演着重要角色。它们在系统、游戏机制甚至基本操作之上增添了一层光泽，使这些元素更有趣或更令人愉悦。

让我们先了解视觉效果，然后是音频效果。

**视觉效果（VFX）**

在虚幻引擎 4 的上下文中，视觉效果由所谓的**粒子系统**组成。粒子系统由发射器组成，发射器由模块组成。在这些模块中，您可以使用材料、网格和数学模块来控制发射器的外观和行为。最终结果可以是从火炬、雪花、雨、灰尘等各种效果。

注意

您可以在这里了解更多信息：[`docs.unrealengine.com/en-US/Resources/Showcases/Effects/index.html`](https://docs.unrealengine.com/en-US/Resources/Showcases/Effects/index.html)。

**音频效果（SFX）**

在虚幻引擎 4 的上下文中，音频效果由声波和声音提示的组合组成：

+   声波是可以导入到虚幻引擎 4 中的`.wav`音频格式文件。

+   声音提示将声波音频文件与其他节点（如振荡器、调制器和连接器）组合在一起，为您的游戏创建独特和复杂的声音。

注意

您可以在这里了解更多信息：[`docs.unrealengine.com/en-US/Engine/Audio/SoundCues/NodeReference/index.html`](https://docs.unrealengine.com/en-US/Engine/Audio/SoundCues/NodeReference/index.html)。

让我们以 Valve 开发的游戏*Portal 2*为例。

在*Portal 2*中，玩家使用传送枪发射两个传送门：一个*橙色*和一个*蓝色*。这些传送门允许玩家穿越间隙，将物体从一个位置移动到另一个位置，并利用其他简单的机制，这些机制叠加在一起，形成复杂的谜题。使用这些传送门，传送门发射的声音效果以及这些传送门的视觉 VFX 使游戏更加有趣。如果您对这款游戏不熟悉，请观看完整的攻略视频：[`www.youtube.com/watch?v=ZFqk8aj4-PA`](https://www.youtube.com/watch?v=ZFqk8aj4-PA)。

注意

有关声音和声音设计重要性的进一步阅读，请参阅以下 Gamasutra 文章：[`www.gamasutra.com/view/news/318157/7_games_worth_studying_for_their_excellent_sound_design.php`](https://www.gamasutra.com/view/news/318157/7_games_worth_studying_for_their_excellent_sound_design.php)。

在虚幻引擎 4 的上下文中，VFX 最初是使用称为`材质`、`静态网格`和`数学`的工具创建的，以为游戏世界创建有趣和令人信服的效果。本书不会深入介绍这个工具的工作原理，但您可以在这里找到有关 Cascade 的信息：[`www.ue4community.wiki/Legacy/Introduction_to_Particles_in_UE4_-_2_-_Cascade_at_a_Glance`](https://www.ue4community.wiki/Legacy/Introduction_to_Particles_in_UE4_-_2_-_Cascade_at_a_Glance)。

在引擎的更新版本中，从 4.20 版本开始，有一个名为`Niagara`的插件，与 Cascade 不同，它使用类似蓝图的系统，您可以在其中直观地编写效果的行为，而不是使用预定义行为的模块。您可以在这里找到有关 Niagara 的更多信息：[`docs.unrealengine.com/en-US/Engine/Niagara/Overview/index.html`](https://docs.unrealengine.com/en-US/Engine/Niagara/Overview/index.html)。

在*第九章*，*音频-视觉元素*中，您了解了更多关于音频以及音频在虚幻引擎 4 中的处理。现在需要知道的是，虚幻引擎 4 使用`.wav`文件格式将音频导入到引擎中。从那里，您可以直接使用`.wav`文件，在编辑器中称为声波，或者您可以将这些资产转换为声音提示，这样可以在声波上添加音频效果。

最后，有一个重要的类需要了解，您将在即将进行的练习中引用这个类，这个类叫做`UGameplayStatics`。这是虚幻引擎中的一个静态类，可以从 C++和蓝图中使用，它提供了各种有用的与游戏相关的功能。您将在即将进行的练习中使用的两个函数如下：

```cpp
UGameplayStatics::SpawnEmitterAtLocation
UGameplayStatics:SpawnSoundAtLocation
```

这两个函数的工作方式非常相似；它们都需要一个`World`上下文对象来生成效果，要生成的粒子系统或音频，以及要生成效果的位置。您将使用这些函数来生成敌人的销毁效果。

## 练习 14.09：在敌人被摧毁时添加效果

在本练习中，您将向项目中添加本章和练习包含的新内容。这包括粒子 VFX 和声音 SFX，以及它们所需的所有资产。然后，您将更新`EnemyBase`类，以便它可以使用音频和粒子系统参数，在玩家投射物销毁敌人时添加所需的光泽层。

通过本练习结束时，您将拥有一个敌人，当它与玩家投射物碰撞时，会在视觉和听觉上被摧毁。

让我们开始：

1.  首先，我们需要从`Action RPG`项目中迁移特定资产，这些资产可以在“虚幻引擎启动器”的“学习”选项卡中找到。

1.  从`Epic Games Launcher`导航到“学习”选项卡，在“游戏”类别下，您将找到`Action RPG`：

注意

在本章后续练习中，您将从动作 RPG 项目中获取其他资产，因此应保持此项目打开，以避免重复打开项目。

1.  左键单击`Action RPG`游戏项目，然后左键单击“创建项目”选项。

1.  从这里，选择引擎版本 4.24，并选择要下载项目的目录。然后，*左键单击*“创建”按钮开始安装项目。

1.  `Action RPG`项目下载完成后，导航到`Epic Games Launcher`的“库”选项卡，找到`My Projects`部分下的`ActionRPG`。

1.  *双击*`ActionRPG`项目，以在 Unreal Engine 编辑器中打开它。

1.  在编辑器中，在“内容浏览器”界面中找到`A_Guardian_Death_Cue`音频资产。*右键单击*此资产，然后选择“资产操作”，然后选择“迁移”。

1.  选择“迁移”后，您将看到所有在`A_Guardian_Death_Cue`中引用的资产。这包括所有音频类和声波文件。从“资产报告”对话框中选择“确定”。

1.  接下来，您需要导航到`Super SideScroller`项目的“内容”文件夹，*左键单击*“选择文件夹”。

1.  迁移过程完成后，您将在编辑器中收到通知，通知您迁移已成功完成。

1.  对`P_Goblin_Death` VFX 资产执行相同的迁移步骤。您要添加到项目中的两个主要资产如下：

```cpp
A_Guardian_Death_Cue
P_Goblin_Death
```

`P_Goblin_Death`粒子系统资产引用了`Effects`目录中包含的材质和纹理等其他资产，而`A_Guardian_Death_Cue`引用了`Assets`目录中包含的其他声音波资产。

1.  将这些文件夹迁移到`SuperSideScroller`项目的“内容”目录后，打开 Unreal Engine 4 编辑器，以在项目的“内容浏览器”中找到包含在项目中的新文件夹。

您将用于敌人角色销毁的粒子称为`P_Goblin_Death`，可以在`/Effects/FX_Particle/`目录中找到。您将用于敌人角色销毁的声音称为`A_Guardian_Death_Cue`，可以在`/Assets/Sounds/Creatures/Guardian/`目录中找到。现在您需要的资产已导入到编辑器中，让我们继续进行编码。

1.  打开 Visual Studio 并导航到敌人基类的头文件；也就是`EnemyBase.h`。

1.  添加以下`UPROPERTY()`变量。这将代表敌人被销毁时的粒子系统。确保这是在`Public`访问修饰符下声明的：

```cpp
UPROPERTY(EditAnywhere, BlueprintReadOnly)
class UParticleSystem* DeathEffect;
```

1.  添加以下`UPROPERTY()`变量。这将代表敌人被销毁时的声音。确保这是在`Public`访问修饰符下声明的：

```cpp
UPROPERTY(EditAnywhere, BlueprintReadOnly)
class USoundBase* DeathSound;
```

有了这两个属性的定义，让我们继续添加所需的逻辑，以便在敌人被摧毁时生成和使用这些效果。

1.  在敌人基类的源文件`EnemyBase.cpp`中，添加以下包含`UGameplayStatics`和`UWorld`类：

```cpp
#include "Kismet/GameplayStatics.h"
#include "Engine/World.h"
```

当敌人被摧毁时，您将使用`UGameplayStatics`和`UWorld`类将声音和粒子系统生成到世界中。

1.  在`AEnemyBase::DestroyEnemy()`函数中，您有一行代码：

```cpp
Destroy();
```

1.  在`Destroy()`函数调用之前添加以下代码行：

```cpp
UWorld* World = GetWorld();
```

在尝试生成粒子系统或声音之前，有必要定义`UWorld`对象，因为需要一个`World`上下文对象。

1.  接下来，使用`if()`语句检查您刚刚定义的`World`对象的有效性：

```cpp
if(World)
{
}
```

1.  在`if()`块内，添加以下代码来检查`DeathEffect`属性的有效性，然后使用`UGameplayStatics`的`SpawnEmitterAtLocation`函数生成这个效果：

```cpp
if(DeathEffect)
{
    UGameplayStatics::SpawnEmitterAtLocation(World,       DeathEffect, GetActorTransform());
}
```

无法再次强调，在尝试生成或操作对象之前，您应该确保对象是有效的。这样做可以避免引擎崩溃。

1.  在`if(DeathEffect)`块之后，执行`DeathSound`属性的相同有效性检查，然后使用`UGameplayStatics::SpawnSoundAtLocation`函数生成声音：

```cpp
if(DeathSound)
{
    UGameplayStatics::SpawnSoundAtLocation(World,       DeathSound, GetActorLocation());
}
```

在调用`Destroy()`函数之前，您需要检查`DeathEffect`和`DeathSound`属性是否都有效，如果是，则使用适当的`UGameplayStatics`函数生成这些效果。这样无论这两个属性是否有效，敌人角色都将被摧毁。

1.  现在`AEnemyBase::DestroyEnemy()`函数已经更新以生成这些效果，返回到虚幻引擎 4 编辑器中编译和热重载这些代码更改。

1.  在`Content Browser`界面中，导航到`/Enemy/Blueprints/`目录。*双击*`BP_Enemy`资源以打开它。

1.  在敌人蓝图的`Details`面板中，您将找到`Death Effect`和`Death Sound`属性。*左键单击*`Death Effect`属性的下拉列表，并找到`P_Goblin_Death`粒子系统。

1.  接下来，在`Death Effect`参数下方，*左键单击*`Death Sound`属性的下拉列表，并找到`A_Guardian_Death_Cue`声音提示。

1.  现在这些参数已经更新并分配了正确的效果，编译并保存敌人蓝图。

1.  使用`PIE`，生成玩家角色并向敌人投掷玩家投射物。如果你的关卡中没有敌人，请添加一个。当玩家投射物与敌人碰撞时，你添加的 VFX 和 SFX 将播放，如下截图所示：![图 14.20：现在，敌人爆炸并在火光中被摧毁](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_14_20.jpg)

图 14.20：现在，敌人爆炸并在火光中被摧毁

完成此练习后，敌人角色现在在被玩家投射物摧毁时播放粒子系统和声音提示。这为游戏增添了一层精致，使得摧毁敌人更加令人满意。

在下一个练习中，您将为玩家投射物添加新的粒子系统和音频组件，使其在飞行时看起来更有趣并且听起来更有趣。

## 练习 14.10：向玩家投射物添加效果

在当前状态下，玩家投射物的功能是按预期的方式运行的；它在空中飞行，与游戏世界中的物体碰撞，并被摧毁。然而，从视觉上看，玩家投射物只是一个带有纯白色纹理的球。

在这个练习中，您将通过添加粒子系统和音频组件为玩家投射物增添一层精致，使得投射物更加愉快使用。

完成以下步骤以实现这一点：

1.  与之前的练习一样，我们需要从“动作 RPG”项目迁移资产到我们的`Super SideScroller`项目。请参考*练习 14.09*，“在敌人被销毁时添加效果”，了解如何安装和迁移来自“动作 RPG”项目的资产。

您要添加到项目中的两个主要资产如下：

```cpp
P_Env_Fire_Grate_01
A_Ambient_Fire01_Cue
```

`P_Env_Fire_Grate_01`粒子系统资产引用了其他资产，例如包含在`Effects`目录中的材质和纹理，而`A_Ambient_Fire01_Cue`引用了包含在`Assets`目录中的其他声音波和声音衰减资产。

您将用于玩家投射物的粒子是名为`P_Env_Fire_Grate_01`，可以在`/Effects/FX_Particle/`目录中找到。这是与之前练习中使用的`P_Goblin_Death` VFX 相同的目录。您将用于玩家投射物的声音是名为`A_Ambient_Fire01_Cue`，可以在`/Assets/Sounds/Ambient/`目录中找到。

1.  *右键单击*“动作 RPG”项目的“内容浏览器”界面中的每个资产，然后选择“资产操作”，然后选择“迁移”。

1.  在确认迁移之前，请确保选择`Super SideScroller`项目的“内容”文件夹目录。

现在，必需的资产已迁移到我们的项目中，让我们继续创建玩家投射物类。

1.  打开 Visual Studio，并导航到玩家投射物类的头文件；即`PlayerProjectile.h`。

1.  在`Private`访问修饰符下，在`UStaticMeshComponent* MeshComp`类组件声明下面，添加以下代码以声明玩家投射物的新音频组件：

```cpp
UPROPERTY(VisibleDefaultsOnly, Category = Sound)
class UAudioComponent* ProjectileMovementSound;
```

1.  接下来，在音频组件声明下面添加以下代码，以声明一个新的粒子系统组件：

```cpp
UPROPERTY(VisibleDefaultsOnly, Category = Projectile)
class UParticleSystemComponent* ProjectileEffect;
```

与在蓝图中可以定义的属性不同，例如在敌人角色类中，这些效果将成为玩家投射物的组件。这是因为这些效果应该附加到投射物的碰撞组件上，以便它们随着投射物在关卡中移动时移动。

1.  在头文件中声明这两个组件后，打开玩家投射物的源文件，并将以下包含添加到文件顶部的`include`行列表中：

```cpp
#include "Components/AudioComponent.h"
#include "Engine/Classes/Particles/ParticleSystemComponent.h"
```

您需要引用音频组件和粒子系统类，以便使用`CreateDefaultSubobject`函数创建这些子对象，并将这些组件附加到`RootComponent`。

1.  添加以下行以创建`ProjectileMovementSound`组件的默认子对象，并将此组件附加到`RootComponent`：

```cpp
ProjectileMovementSound = CreateDefaultSubobject<UAudioComponent>  (TEXT("ProjectileMovementSound"));
  ProjectileMovementSound->AttachToComponent(RootComponent,   FAttachmentTransformRules::KeepWorldTransform);
```

1.  接下来，添加以下行以创建`ProjectileEffect`组件的默认子对象，并将此组件附加到`RootComponent`：

```cpp
ProjectileEffect = CreateDefaultSubobject<UParticleSystemComponent>(TEXT("Projectile   Effect"));
ProjectileEffect->AttachToComponent(RootComponent,   FAttachmentTransformRules::KeepWorldTransform);
```

1.  现在，您已经创建、初始化并将这两个组件附加到`RootComponent`，返回到 Unreal Engine 4 编辑器中重新编译并热重载这些代码更改。

1.  从“内容浏览器”界面，导航到`/MainCharacter/Projectile/`目录。找到`BP_PlayerProjectile`资产，*双击*打开蓝图。

在“组件”选项卡中，您将找到使用前面的代码添加的两个新组件。请注意，这些组件附加到`CollisionComp`组件，也称为`RootComponent`。

1.  *左键单击*选择`ProjectileEffect`组件，并在“详细信息”面板中将`P_Env_Fire_Grate_01` VFX 资产分配给此参数，如下截图所示：![图 14.21：现在，您可以将 P_Env_fire_Grate_01 VFX 资产应用到您之前添加的粒子系统组件](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_14_21.jpg)

图 14.21：现在，您可以将 P_Env_fire_Grate_01 VFX 资产应用到您之前添加的粒子系统组件

1.  在分配音频组件之前，让我们调整`ProjectileEffect` VFX 资产的`Transform`。更新 VFX 的`Transform`的`Rotation`和`Scale`参数，使其与以下截图中显示的内容匹配：![图 14.22：粒子系统组件的更新变换以便它更好地适应抛射物](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_14_22.jpg)

图 14.22：粒子系统组件的更新变换，以便更好地适应抛射物

1.  导航到蓝图中的`Viewport`选项卡，查看`Transform`的这些更改。`ProjectileEffect`应该如下所示：![图 14.23：现在，火焰 VFX 已经被适当地缩放和旋转](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_14_23.jpg)

图 14.23：现在，火焰 VFX 已经被适当地缩放和旋转

1.  现在 VFX 已经设置好了，*左键单击*`ProjectileMovementSound`组件，并将`A_Ambient_Fire01_Cue`分配给该组件。

1.  保存并重新编译`BP_PlayerProjectile`蓝图。使用`PIE`并观察当你投掷抛射物时，它现在显示了 VFX 资产并播放了分配的声音：![图 14.24：玩家抛射物现在在飞行时有了 VFX 和 SFX](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_14_24.jpg)

图 14.24：玩家抛射物现在在飞行时有了 VFX 和 SFX

完成这个练习后，玩家的抛射物现在有了一个 VFX 和一个 SFX，它们在飞行时一起播放。这些元素使抛射物栩栩如生，并使其更有趣。

由于 VFX 和 SFX 是作为抛射物的组件创建的，它们在抛射物被销毁时也会被销毁。

在下一个练习中，你将向`Throw`动画蒙太奇添加一个粒子通知和一个声音通知，以便在玩家投掷抛射物时提供更多的影响。

## 练习 14.11：添加 VFX 和 SFX 通知

到目前为止，你一直在通过 C++实现游戏的抛光元素，这是一种有效的实现手段。为了增加变化，并扩展你对虚幻引擎 4 工具集的了解，这个练习将教你如何在动画蒙太奇中使用通知来添加粒子系统和音频。让我们开始吧！

和之前的练习一样，我们需要从`Action RPG`项目迁移资产到我们的`Super SideScroller`项目。请参考*练习 14.09*，*当敌人被销毁时添加特效*，学习如何从`Action RPG`项目安装和迁移资产。执行以下步骤：

1.  打开`ActionRPG`项目，并导航到`Content Browser`界面。

你添加到项目中的两个主要资产如下：

```cpp
P_Skill_001
A_Ability_FireballCast_Cue
```

`P_Skill_001`粒子系统资产引用了`Effects`目录中包含的*材质*和*纹理*等其他资产，而`A_Ability_FireballCast_Cue`引用了`Assets`目录中包含的其他*声音波*资产。

当抛射物被投掷时，玩家将使用的粒子是`P_Skill_001`，可以在`/Effects/FX_Particle/`目录中找到。这是之前练习中使用的`P_Goblin_Death`和`P_Env_Fire_Grate_01` VFX 资产所使用的相同目录。你将用于敌人角色销毁的声音称为`A_Ambient_Fire01_Cue`，可以在`/Assets/Sounds/Ambient/`目录中找到。

1.  *右键单击*`Action RPG`项目的`Content Browser`界面中的每个资产，然后选择`Asset Actions`，然后选择`Migrate`。

1.  在确认迁移之前，请确保选择`Super SideScroller`项目的`Content`文件夹的目录。

现在你需要的资产已经迁移到你的项目中，让我们继续添加所需的通知到`AM_Throw`资产。在继续进行这个练习之前，请确保返回到你的`Super SideScroller`项目。

1.  从`内容浏览器`界面，导航到`/MainCharacter/Animation/`目录。找到`AM_Throw`资产并*双击*打开它。

1.  在`动画蒙太奇`编辑器中央的预览窗口下方，找到`通知`部分。这是您在本章早些时候添加`Anim_ProjectileNotify`的相同部分。

1.  在`通知`轨道的右侧，您会找到一个`+`号，允许您使用额外的通知轨道。*左键单击*添加一个新轨道，如下图所示：![图 14.25：在时间轴上添加多个轨道以在添加多个通知时保持组织](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_14_25.jpg)

图 14.25：在时间轴上添加多个轨道以在添加多个通知时保持组织

1.  在与`Anim_ProjectileNotify`相同的帧中，在上一步创建的新轨道内*右键单击*。从`添加通知`列表中*左键单击*选择`播放粒子效果`。

1.  创建后，*左键单击*选择新通知并访问其`详细信息`面板。在`详细信息`中，将`P_Skill_001` VFX 资产添加到`粒子系统`参数中。

添加了这个新的 VFX 之后，您会注意到 VFX 几乎放在了玩家角色的脚下，但不完全是您想要的位置。这个 VFX 应该直接放在地板上，或者放在角色的底部。以下屏幕截图展示了这个位置：

![图 14.26：粒子通知的位置不在地面上](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_14_26.jpg)

图 14.26：粒子通知的位置不在地面上

为了解决这个问题，您需要向玩家角色骨架添加一个新的`插座`。

1.  导航到`/MainCharacter/Mesh/`目录。*双击*`MainCharacter_Skeleton`资产以打开它。

1.  在左侧的`骨骼`骨骼层次结构上，*右键单击*`Hips`骨骼，*左键单击*选择`添加插座`选项。将此新插座命名为`EffectSocket`。

1.  *左键单击*从骨骼层次结构中选择此插座，以查看其当前位置。默认情况下，其位置设置为与`Hips`骨骼相同的位置。以下屏幕截图显示了此位置：![图 14.27：此插座的默认位置位于玩家骨架的中心](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_14_27.jpg)

```cpp
(X=0.000000,Y=100.000000,Z=0.000000)
```

这个位置将更靠近地面和玩家角色的脚。最终位置如下图所示：

图 14.28：将插座位置移动到玩家骨架的底部

](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_14_28.jpg)

图 14.28：将插座位置移动到玩家骨架的底部

1.  现在您已经有了粒子通知的位置，请返回到`AM_Throw`动画蒙太奇。

1.  在`播放粒子效果`通知的`详细信息`面板中，有`插座名称`参数。使用`EffectSocket`作为名称。

注意

如果`EffectSocket`没有出现在自动完成中，请关闭并重新打开动画蒙太奇。重新打开后，`EffectSocket`选项应该会出现。

1.  最后，粒子效果的比例有点太大，因此调整投影物的比例，使其值如下：

```cpp
(X=0.500000,Y=0.500000,Z=0.500000)
```

现在，当通过此通知播放粒子效果时，其位置和比例将是正确的，如下所示：

![图 14.29：粒子现在在玩家角色骨架的底部播放](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_14_29.jpg)

图 14.29：粒子现在在玩家角色骨架的底部播放

1.  要添加`播放声音`通知，请在`通知`时间轴部分添加一个新轨道；现在总共应该有三个。

1.  在这个新轨道上，并且与`播放粒子效果`和`Anim_ProjectileNotify`通知的帧位置相同，*右键单击*并从`添加通知`选择中选择`播放声音`通知。以下屏幕截图显示了如何找到此通知：![图 14.30：您在本章中早些时候了解到的播放声音通知](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_14_30.jpg)

图 14.30：您在本章早些时候了解到的 Play Sound 通知

1.  接下来，*左键单击*选择`Play Sound`通知并访问其`Details`面板。

1.  从`Details`面板中找到`Sound`参数，并分配`A_Ability_FireballCast_Cue`。

分配了声音后，当播放`Throw`动画时，您将看到 VFX 播放并听到声音。`Notifies`轨道应如下所示：

![图 14.31：投掷动画蒙太奇时间轴上的最终通知设置](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_14_31.jpg)

图 14.31：投掷动画蒙太奇时间轴上的最终通知设置

1.  保存`AM_Throw`资产并使用`PIE`来投掷玩家投射物。

1.  现在，当您投掷投射物时，您将看到粒子通知播放`P_Skill_001` VFX，并听到`A_Ability_FireballCast_Cue` SFX。结果将如下所示：![图 14.32：现在，当玩家投掷投射物时，会播放强大的 VFX 和 SFX](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_14_32.jpg)

图 14.32：现在，当玩家投掷投射物时，会播放强大的 VFX 和 SFX

完成这个最后的练习后，玩家现在在投掷玩家投射物时会播放强大的 VFX 和 SFX。这使得投掷动画更有力量，感觉就像玩家角色在用很多能量来投掷投射物。

在接下来的最后一个活动中，您将利用您从最近几个练习中获得的知识，为玩家投射物在被销毁时添加 VFX 和 SFX。

## 活动 14.02：为投射物销毁时添加效果

在这个最后的活动中，您将利用您从为玩家投射物和敌人角色添加 VFX 和 SFX 元素中获得的知识，为投射物与物体碰撞时创建爆炸效果。我们添加这个额外的爆炸效果的原因是为了在销毁投射物与环境物体碰撞时增加一定的光泽度。如果玩家投射物撞击物体并在没有任何音频或视觉反馈的情况下消失，那将显得尴尬和不合时宜。

您将为玩家投射物添加粒子系统和声音提示参数，并在投射物与物体碰撞时生成这些元素。

执行以下步骤以实现预期输出：

1.  在`PlayerProjectile.h`头文件中，添加一个新的粒子系统变量和一个新的声音基础变量。

1.  将粒子系统变量命名为`DestroyEffect`，将声音基础变量命名为`DestroySound`。

1.  在`PlayerProjectile.cpp`源文件中，将`UGameplayStatics`的包含添加到包含列表中。

1.  更新`APlayerProjectile::ExplodeProjectile()`函数，使其现在生成`DestroyEffect`和`DestroySound`对象。返回虚幻引擎 4 编辑器并重新编译新的 C++代码。在`BP_PlayerProjectile`蓝图中，将默认包含在您的项目中的`P_Explosion` VFX 分配给投射物的`Destroy Effect`参数。

1.  将`Explosion_Cue` SFX 分配给投射物的`Destroy Sound`参数，该 SFX 已默认包含在您的项目中。

1.  保存并编译玩家投射蓝图。

1.  使用`PIE`观察新的玩家投射物销毁 VFX 和 SFX。

预期输出如下：

![图 14.33：投射物 VFX 和 SFX](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/gm-dev-pj-ue/img/B16183_14_33.jpg)

图 14.33：投射物 VFX 和 SFX

完成这个活动后，您现在已经有了为游戏添加光泽元素的经验。您不仅通过 C++代码添加了这些元素，还通过虚幻引擎 4 的其他工具添加了这些元素。在这一点上，您已经有足够的经验来为您的游戏添加粒子系统和音频，而不必担心如何实现这些功能。

注意

此活动的解决方案可在以下网址找到：[`packt.live/338jEBx`](https://packt.live/338jEBx)。

# 总结

在本章中，您学到了在游戏开发世界中视觉和音频效果的重要性。通过使用 C++代码和通知的组合，您能够为玩家的抛射物和敌人角色的碰撞带来游戏功能，以及通过添加 VFX 和 SFX 来提升这些功能。除此之外，您还了解了在虚幻引擎 4 中如何生成和销毁对象。

此外，您还了解了动画蒙太奇如何在蓝图和 C++中播放。通过将从蓝图播放“投掷”动画蒙太奇的逻辑迁移到 C++，您学会了两种方法的工作原理，以及如何为游戏使用这两种实现。

通过使用 C++添加新的动画通知，您能够将此通知添加到“投掷”动画蒙太奇中，从而允许玩家生成上一章中创建的玩家抛射物。通过使用`UWorld->SpawnActor()`函数，并向玩家骨骼添加新的插座，您能够在“投掷”动画的确切帧和您想要的确切位置生成玩家抛射物。

最后，您学会了如何在“投掷”动画蒙太奇中使用“播放粒子效果”和“播放声音”通知，为玩家抛射物的投掷添加 VFX 和 SFX。本章让您有机会了解虚幻引擎 4 中在游戏中使用 VFX 和 SFX 时存在的不同方法。

现在，玩家的抛射物可以被投掷并摧毁敌人角色，是时候实现游戏的最后一组机制了。在下一章中，您将创建玩家可以收集的可收集物品，并为玩家创建一个可以在短时间内改善玩家移动机制的增益道具。
