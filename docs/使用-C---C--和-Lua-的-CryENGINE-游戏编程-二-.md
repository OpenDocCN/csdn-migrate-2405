# 使用 C++、C# 和 Lua 的 CryENGINE 游戏编程（二）

> 原文：[`zh.annas-archive.org/md5/9DE4C1E310A0B5A13812B9CEED44823A`](https://zh.annas-archive.org/md5/9DE4C1E310A0B5A13812B9CEED44823A)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：创建自定义角色

使用 CryENGINE 角色系统，我们可以创建具有自定义行为的玩家或 AI 控制实体，以填充我们的游戏世界。

在本章中，我们将涵盖以下主题：

+   了解角色的目的以及实现它们背后的核心思想

+   在 C++和 C#中创建自定义角色

+   创建我们的第一个玩家摄像头处理程序

+   实现基本玩家移动

# 介绍角色系统

我们在第三章中学习了游戏对象扩展是什么，以及如何使用它们，*创建和利用自定义实体*。我们将在此基础上创建一个 C++和 C#中的自定义角色。

角色由`IActor`结构表示，它们是核心中的游戏对象扩展。这意味着每个角色都有一个支持实体和一个处理网络和`IActor`扩展的游戏对象。

角色由`IActorSystem`接口处理，该接口管理每个角色的创建、移除和注册。

## 通道标识符

在网络上下文中，每个玩家都被分配一个通道 ID 和 Net Nub 的索引，我们将在第八章中进一步介绍，*多人游戏和网络*。

## 角色生成

玩家角色应在客户端连接到游戏时生成，在`IGameRules::OnClientConnect`中。要生成角色，请使用`IActorSystem::CreateActor`如下所示：

```cs
IActorSystem *pAS = gEnv->pGameFramework->GetIActorSystem();

pAS ->CreateActor(channelId, "MyPlayerName", "MyCppActor", Vec3(0, 0, 0), Quat(IDENTITY), Vec3(1, 1, 1));
```

### 注意

请注意，先前的代码仅适用于由玩家控制的角色。非玩家角色可以随时创建。

### 移除角色

为了确保在客户端断开连接时正确删除玩家角色，我们需要通过`IGameRules::OnClientDisconnect`回调手动删除它：

```cs
pActorSystem->RemoveActor(myActorEntityId);
```

在玩家断开连接后忘记移除玩家角色可能会导致崩溃或严重的伪影。

## 视图系统

为了满足处理玩家和其他摄像头来源的视图的需求，CryENGINE 提供了视图系统，可通过`IViewSystem`接口访问。

视图系统是围绕着任意数量的视图，由`IView`接口表示，每个视图都有更新位置、方向和配置（如视野）的能力。

### 注意

请记住，一次只能激活一个视图。

可以使用`IViewSystem::CreateView`方法创建新视图，如下所示：

```cs
IViewSystem *pViewSystem = gEnv->pGame->GetIGameFramework()->GetIViewSystem();

IView *pNewView = pViewSystem->CreateView();
```

然后，我们可以使用`IViewSystem::SetActiveView`函数设置活动视图：

```cs
pViewSystem_>SetActiveView(pNewView);
```

一旦激活，视图将在每一帧更新系统相机。要修改视图的参数，我们可以调用`IView::SetCurrentParams`。例如，要更改位置，请使用以下代码片段：

```cs
SViewParams viewParams = *GetCurrentParams();
viewParams.position = Vec3(0, 0, 10);
SetCurrentParams(viewParams);
```

当前视图的位置现在是（0，0，10）。

### 将视图链接到游戏对象

每个视图还可以将自己链接到游戏对象，允许其游戏对象扩展订阅`UpdateView`和`PostUpdateView`函数。

这些函数允许每帧更新的视图的位置、方向和配置很容易地更新。例如，这用于角色，以提供为每个玩家创建自定义相机处理的可访问方式。

有关相机操作的更多信息，请参见本章后面的*相机操作*部分。

# 创建自定义角色

现在我们知道角色系统是如何工作的，我们可以继续在 C#和 C++中创建我们的第一个角色。

### 注意

默认情况下，无法仅使用 Lua 脚本创建角色。通常，角色是在 C++中创建的，并处理自定义回调以包含在`Game/Scripts/Entities/Actors`文件夹中的 Lua 脚本。

## 在 C#中创建角色

使用 CryMono，我们可以完全在 C#中创建自定义角色。为此，我们可以从`Actor`类派生，如下所示：

```cs
public class MyActor : Actor
{
}
```

上面的代码是在 CryMono 中创建演员的最低要求。然后你可以转到你的游戏规则实现，并在客户端连接时通过`Actor.Create`静态方法生成演员。

### CryMono 类层次结构

如果你对各种 CryMono/C#类感到困惑，请参阅以下继承图：

![CryMono 类层次结构](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909_05_01.jpg)

### 注意

请注意，当使用`Entity.Get`（或通过`Actor.Get`查询演员）查询实体时，你将得到一个`EntityBase`或`ActorBase`类型的对象。这是因为本地实体和演员存在于托管系统之外，当查询时返回了有限的表示。

### 同时使用本地和 CryMono 演员

如果你更喜欢在 C++中自己创建你的演员，你仍然可以通过使用`NativeActor`类在 CryMono 代码中引用它。为此，只需在 C#中创建一个新的类，名称与你注册的`IActor`实现相同，并从`NativeActor`派生，如下所示：

#### C++演员注册

演员注册是使用注册工厂完成的。这个过程可以使用`REGISTER_FACTORY`宏自动化，如下所示： 

```cs
REGISTER_FACTORY(pFramework, "Player", CPlayer, false);
```

#### C#声明

在 C#中声明基于本地的演员非常简单，只需要从`CryEngine.NativeActor`类派生，如下所示：

```cs
public class Player : NativeActor
{
}
```

这允许 C#代码仍然可以使用，但保持大部分代码在你的 C++ `IActor`实现中。

### 注意

`CryEngine.NativeActor`直接派生自`CryEngine.ActorBase`，因此不包含常见的`CryEngine.Actor`回调，比如 OnEditorReset。要获得这个额外的功能，你需要在你的`IActor`实现中创建它。

## 在 C++中创建演员

要在 C++中创建一个演员，我们依赖于`IActor`接口。由于演员是核心中的游戏对象扩展，我们不能简单地从`IActor`派生，而是必须像下面的代码中所示使用`CGameObjectExtensionHelper`模板：

```cs
class CMyCppActor
  : public CGameObjectExtensionHelper<CMyCppActor, IActor>
{
};
```

### 注意

第三个`CGameObjectExtensionHelper`参数定义了这个游戏对象支持的最大 RMI（远程机器调用）数量。我们将在第八章中进一步介绍，*多人游戏和网络*。

现在我们有了这个类，我们需要实现`IActor`结构中定义的纯虚方法。

### 注意

请注意，`IActor`派生自`IGameObjectExtension`，这意味着我们还需要实现它的纯虚方法。有关此信息，请参阅第四章中的*实现游戏规则接口*部分，*游戏规则*。

对于大多数`IActor`方法，我们可以实现虚拟方法，要么返回空，要么返回虚拟值，比如 nullptr，零，或者空字符串。以下表格列出了例外情况：

| 函数名称 | 描述 |
| --- | --- |
| `IGameObjectExtension::Init` | 用于初始化游戏对象扩展。应该调用`IGameObjectExtension::SetGameObject`和`IActorSystem::AddActor`。 |
| 类析构函数 | 应该始终调用`IActorSystem::RemoveActor`。 |
| `IActor::IsPlayer` | 用于确定演员是否由人类玩家控制。我们可以简单地返回`GetChannelId() != 0`，因为通道标识符只对玩家非零。 |
| `IActor::GetActorClassName` | 用于获取演员类的名称，例如，在我们的情况下是`CMyCppActor`。 |
| `IActor::GetEntityClassName` | 获取实体类的名称的辅助函数。我们可以简单地返回`GetEntity()->GetClass()->GetName()`。 |

当你解决了纯虚函数后，继续下一节注册你的演员。完成后，你可以在`IGameRules::OnClientConnect`中为连接的玩家创建你的演员。

### 注册演员

要在游戏框架（包含在`CryAction.dll`中）中注册一个演员，我们可以使用与在`GameFactory.cpp`中注册 C++游戏规则实现时相同的设置：

```cs
REGISTER_FACTORY(pFramework, "MyCppActor", CMyCppActor, false);
```

在执行前面的代码之后，您将能够通过`IActorSystem::CreateActor`函数生成您的演员。

# 摄像机处理

玩家控制的演员在`IActor::UpdateView(SViewParams &viewParams)`和`IActor::PostUpdateView(SViewParams &viewParams)`函数中管理视口摄像机。

`SViewParams`结构用于定义摄像机属性，如位置、旋转和视野。通过修改`UpdateView`方法中的`viewParams`引用，我们可以将摄像机移动到游戏所需的位置。

### 注意

CryMono 演员以与 C++演员相同的方式接收和处理`UpdateView(ref ViewParams viewParams)`和`PostUpdateView(ref ViewParams viewParams)`事件。

## 实现 IGameObjectView

为了获得视图事件，我们需要实现并注册一个游戏对象视图。要做到这一点，首先从`IGameObjectView`派生，并实现它包括的以下两个纯虚函数：

+   `UpdateView`：用于更新视图位置、旋转和视野

+   `PostUpdateView`：在更新视图后调用

在实现游戏对象视图之后，我们需要确保在演员扩展初始化时捕获它（在 Init 中）：

```cs
if(!GetGameObject()->CaptureView(this))
  return false;
```

您的演员现在应该接收视图更新回调，可以利用它来移动视口摄像机。不要忘记在析构函数中释放视图：

```cs
GetGameObject()->ReleaseView(this);
```

## 创建俯视摄像机

为了展示如何创建自定义摄像机，我们将扩展我们在上一章中创建的示例，添加一个自定义的俯视摄像机。简单来说，就是从上方查看角色，并从远处跟随其动作。

首先，打开您的 C#演员的`UpdateView`方法，或者在您的`.cs`源文件中实现它。

### 视图旋转

为了使视图朝向玩家的顶部，我们将使用玩家旋转的第二列来获取向上的方向。

### 注意

四元数以一种允许轻松插值和避免万向节锁的方式表示玩家的旋转。您可以获得代表每个四元数方向的三列：0（右）、1（前）、2（上）。例如，这非常有用，可以获得一个面向玩家前方的向量。

除非您自上次函数以来对演员的`UpdateView`函数进行了任何更改，否则它应该看起来与以下代码片段类似：

```cs
protected override void UpdateView(ref ViewParams viewParams)
{
  var fov = MathHelpers.DegreesToRadians(60);

  viewParams.FieldOfView = fov;
  viewParams.Position = Position;
  viewParams.Rotation = Rotation
}
```

这只是将视角摄像机放在与玩家完全相同的位置，具有相同的方向。我们需要做的第一个改变是将摄像机向上移动一点。

为此，我们将简单地将玩家旋转的第二列附加到其位置，并将摄像机放置在与玩家相同的 x 和 y 位置，但略高于玩家：

```cs
var playerRotation = Rotation;

float distanceFromPlayer = 5;
var upDir = playerRotation.Column2;

viewParams.Position = Position + upDir * distanceFromPlayer;
```

随时随地进入游戏并查看。当您准备好时，我们还必须将视图旋转为直接向下：

```cs
// Face straight down
var angles = new Vec3(MathHelpers.DegreesToRadians(-90), 0, 0);

//Convert to Quaternion
viewParams.Rotation = Quat.CreateRotationXYZ(angles);
```

完成！我们的摄像机现在应该正对着下方。

![视图旋转](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909_05_02.jpg)

这大致是您应该看到的新摄像机。

请注意视图中缺少玩家角色。这是因为我们还没有将对象加载到玩家实体中。我们可以通过在`OnSpawn`函数中调用`EntityBase.LoadObject`来快速解决这个问题：

```cs
public override void OnSpawn()
{
  // Load object
  LoadObject("Objects/default/primitive_cube.cgf");

  // Physicalize to weigh 50KG
  var physicalizationParams = new PhysicalizationParams(PhysicalizationType.Rigid);
  physicalizationParams.mass = 50;
  Physicalize(physicalizationParams);
}
```

现在您应该能够在场景中看到代表玩家角色的立方体。请注意，它也是物理化的，允许它推动或被其他物理化的对象推动。

![视图旋转](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909_05_03.jpg)

现在您应该对玩家视图功能有了基本的了解。要了解更多，为什么不尝试创建您自己的摄像机，即 RPG 风格的等距摄像机？

现在我们可以继续下一节，*玩家输入*。

# 玩家输入

当您无法控制演员时，演员往往会变得相当无聊。为了将事件映射到输入，我们可以利用以下三个系统：

| 系统名称 | 描述 |
| --- | --- |
| IHardwareMouse | 当需要直接获取鼠标事件时使用，例如 x/y 屏幕位置和鼠标滚轮增量。 |
| IActionMapManager | 允许注册与按键绑定相关的回调。这是首选的键盘和鼠标按钮输入方法，因为它允许每个玩家通过他们的行动地图配置文件自定义他们喜欢的输入方式。行动地图通常通过游戏界面公开，以简化最终用户的按键映射。 |
| IInput | 用于监听原始输入事件，例如检测空格键何时被按下或释放。除了在聊天和文本输入等极少数情况下，不建议使用原始输入，而是使用行动地图更可取。 |

## 硬件鼠标

硬件鼠标实现提供了`IHardwareMouseEventListener`结构，允许接收鼠标事件回调。在派生并实现其纯虚函数后，使用`IHardwareMouse::AddListener`来使用它：

```cs
gEnv->pHardwareMouse->AddListener(this);
```

监听器通常在构造函数或初始化函数中调用。确保不要注册两次监听器，并始终在类析构函数中移除它们以防止悬空指针。

## 行动地图

在前面的表中简要提到，行动地图允许将按键绑定到命名动作。这用于允许从不同的游戏状态简单重新映射输入。例如，如果你有一个有两种类型车辆的游戏，你可能不希望相同的按键用于两种车辆。

行动地图还允许实时更改动作映射到的按键。这允许玩家自定义他们喜欢的输入方式。

### 监听行动地图事件

默认的行动地图配置文件包含在`Game/Libs/Config/defaultProfile.xml`中。游戏发布时，默认配置文件会被复制到用户的个人文件夹（通常在`My Games/Game_Title`），用户可以修改它来重新映射按键，例如更改触发**截图**动作的按键。

![监听行动地图事件](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909_05_04.jpg)

要监听行动地图事件，我们首先要么在配置文件中创建一个新的动作，要么选择一个现有的动作并修改它。在这个例子中，我们将利用现有的截图动作。

#### IActionListener

行动地图系统提供了`IActionListener`结构来支持为需要行动地图事件的类提供回调函数。

利用监听器相对容易：

1.  派生自`IActorListener`结构。

1.  实现`OnAction`事件。

1.  注册你的监听器：

```cs
gEnv->pGameFramework->GetIActionMapManager()->AddExtraActionListener(this);
```

监听器应该只注册一次，这就是为什么注册最好在构造函数或初始化函数中进行。

确保在类实例销毁时移除你的监听器。

### 启用行动地图部分

行动地图系统允许在同一个配置文件中创建多个行动地图部分，使游戏代码能够实时切换不同的行动地图部分。这对于具有多个玩家状态的游戏非常有用，比如行走和使用车辆。在这种情况下，车辆和行走行动地图将包含在不同的部分中，然后在退出或进入车辆时启用/禁用它们。

```cs
<actionmap name="walk" version="22">
  <action name="walkBack" onPress="1" keyboard="s" />
</actionmap>

<actionmap name="drive" version="22">
  <action name="break" onPress="1" keyboard="s" />
</actionmap>
```

要启用自定义的行动地图，调用`IActionMapManager::EnableActionMap`：

```cs
gEnv->pFramework->GetIActionMapManager()->EnableActionMap("walk", true);
```

这应该在玩家应该能够接收这些新动作的确切时刻完成。在前面的例子中，当玩家退出车辆时启用“行走”动作。

# 动画角色

`IAnimatedCharacter`是一个游戏对象扩展，允许对象进行运动和物理整合。通过使用它，角色可以请求物理移动请求，利用动画图功能等。

由于该扩展是可选的，任何游戏对象都可以通过简单获取它来激活它，如第三章中所述，*创建和利用自定义实体*

```cs
m_pAnimatedCharacter = static_cast<IAnimatedCharacter*>(GetGameObject()->AcquireExtension("AnimatedCharacter"))
```

一旦获取，动画角色可以立即使用。

### 注意

动画角色功能，如移动请求，需要通过`IGameObject::EnablePhysicsEvent`启用 eEPE_OnPostStepImmediate 物理事件。

## 移动请求

当动画角色作为生物实体物理化时，可以请求移动。这本质上是 pe_action_move 物理请求的包装（有关更多信息，请参见第九章，“物理编程”）以允许更简单的使用。

处理高级机制，如玩家移动时，角色移动请求非常有用。

### 注意

请注意请求移动和直接设置玩家位置之间的区别。通过请求速度变化，我们能够使我们的实体自然地对碰撞做出反应。

## 添加移动请求

要添加移动请求，利用`IAnimatedCharacter::AddMovement`，需要一个`SCharacterMoveRequest`对象：

```cs
SCharacterMoveRequest request;

request.type = eCMT_Normal;
request.velocity = Vec3(1, 0, 0);
request.rotation = Quat(IDENTITY);

m_pAnimatedCharacter->AddMovement(request);
```

在上面的代码中看到的是一个非常基本的移动请求示例，它将目标设置为无限制地向前（世界空间）（如果连续提交）。

### 注意

移动请求必须通过物理循环添加，参见通过`IGameObjectExtension::ProcessEvent`发送的 ENTITY_EVENT_PREPHYSICSUPDATE。

# 模特动画系统

CryENGINE 3.5 引入了高级模特动画系统。该系统旨在解耦动画和游戏逻辑，有效地作为 CryAnimation 模块和游戏代码之间的附加层。

### 注意

请记住，模特可以应用于任何实体，而不仅仅是演员。但是，默认情况下，模特集成到`IAnimatedCharacter`扩展中，使演员更容易利用新的动画系统。

在开始使用之前，模特依赖一组类型，这些类型应该在开始使用之前清楚地理解：

| 名称 | 描述 |
| --- | --- |
| 片段 | 片段指的是一个状态，例如，“着陆”。每个片段可以在多个层上指定多个动画，以及一系列效果。这允许在同时处理第一人称和第三人称视图时，动画更加流畅。对于这个问题，每个片段将包含一个全身动画，一个第一人称动画，然后额外的声音，粒子和游戏事件。 |
| 片段 ID | 为了避免直接传递片段，我们可以通过它们的片段 ID 来识别它们。 |
| 范围 | 范围允许解耦角色的部分，以便保持处理，例如，上半身和下半身动画分开。在创建新的范围时，每个片段将能够向该范围添加额外的动画和效果，以扩展其行为。对于 Crysis 3，第一人称和第三人称模式被声明为单独的范围，以允许相同的片段同时处理这两种状态。 |
| 标签 | 标签是指选择标准，允许根据活动的标签选择子片段。例如，如果我们有两个名为“空闲”的片段，但一个分配给“受伤”标签，我们可以根据玩家是否受伤动态地在两个片段变化之间切换。 |
| 选项 | 如果我们最终有多个共享相同标识和标签的片段，我们有多种选择。默认行为是在查询片段时随机选择其中一个，从而有效地创建实体动画的变化。 |

## 模特编辑器

**模特编辑器**用于通过沙盒编辑器实时调整角色动画和模特配置。

### 预览设置

**模特编辑器**使用存储在`Animations/Mannequin/Preview`中的预览文件，以加载默认模型和动画数据库。启动**模特编辑器**时，我们需要通过选择**文件** | **加载预览设置**来加载我们的预览设置。

加载后，我们将得到预览设置的可视表示，如下面的截图所示：

![预览设置](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909_05_05.jpg)

我们预览文件的内容如下：

```cs
<MannequinPreview>
  <controllerDef filename="Animations/Mannequin/ADB/SNOWControllerDefinition.xml"/>
  <contexts>
    <contextData name="Char3P" enabled="1" database="Animations/Mannequin/ADB/Skiing.adb" context="Char3P" model="scripts/config/base.cdf"/>
  </contexts>
  <History StartTime="-4.3160208e+008" EndTime="-4.3160208e+008"/>
</MannequinPreview>
```

我们将在本章后面进一步介绍控制器定义、上下文数据等详细信息。

### 创建上下文

如本章前面提到的，上下文可用于根据角色状态应用不同的动画和效果。

我们可以通过选择**文件** | **上下文编辑器**在**人体模型编辑器**中访问**上下文编辑器**，来创建和修改上下文。

![创建上下文](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909_05_06.jpg)

要创建新上下文，只需单击左上角的**新建**，将打开**新上下文**对话框，如下屏幕截图所示：

![创建上下文](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909_05_07.jpg)

这使我们能够在创建之前调整上下文，包括选择要使用的动画数据库和模型。

完成后，只需单击**确定**即可查看您创建的上下文。

### 创建片段

默认情况下，我们可以在**人体模型编辑器**的左上部看到片段工具箱。这个工具是我们将用来创建和编辑片段的工具，还可以添加或编辑选项。

![创建片段](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909_05_08.jpg)

在上一个屏幕截图中，可以看到片段工具箱中打开了**BackFlip**片段，显示了两个选项。

要创建新片段，请单击**新 ID…**按钮，在新打开的消息框中输入所需的名称，然后单击**确定**。

现在您应该在**人体模型片段 ID 编辑器**对话框中看到如下屏幕截图所示：

![创建片段](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909_05_09.jpg)

现在我们将能够选择该片段应在哪些范围内运行。在我们的情况下，我们只需要检查**Char3P**并单击**确定**。

现在您应该能够在片段工具箱中看到您的片段：

![创建片段](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909_05_10.jpg)

#### 添加选项

有两种方法可以向片段添加新选项：

+   打开角色编辑器，选择您的动画，然后将其拖放到人体模型片段上。

+   在片段工具箱中单击新建按钮，然后手动修改选项。

### 创建和使用标签

如前所述，人体模型系统允许创建**标签**，允许根据标签当前是否激活来选择每个片段的特定选项。

要创建新标签，请打开人体模型编辑器，然后选择**文件 -> 标签定义编辑器**：

![创建和使用标签](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909_05_11.jpg)

一旦打开，您将看到**人体模型标签定义编辑器**。编辑器为您提供了两个部分：**标签定义**和**标签**。

我们需要做的第一件事是创建一个**标签定义**。这是一个跟踪一组标签的文件。要这样做，请在**标签定义**部分按加号（*+*）符号，然后指定您的定义的名称。

![创建和使用标签](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909_05_12.jpg)

太棒了！现在您应该在**人体模型标签定义编辑器**中看到您的标签定义。要创建新标签，请选择**MyTags.xml**，然后单击标签创建图标（在**标签**部分的第三个）。

这将为您呈现一个**标签创建**对话框，在其中您只需要指定您的标签的名称。完成后，单击**确定**，您应该立即在**标签**部分看到该标签（如下屏幕截图所示）：

![创建和使用标签](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909_05_13.jpg)

#### 向选项附加标签

现在您已经创建了自定义标签，我们可以在片段编辑器中选择任何片段选项，然后向下查找标签工具箱：

![向选项附加标签](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909_05_14.jpg)

只需在选择片段选项时简单地选中每个标签旁边的复选框，我们就告诉动画系统在指定标签激活时应优先考虑该选项。

### 保存

要保存你的**Mannequin Editor**更改，只需点击**文件** | **保存更改**，并在出现的**Mannequin 文件管理器**对话框中验证你的更改（如下截图所示）：

![Saving](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909_05_15.jpg)

当你准备好保存时，只需点击**保存**，系统将更新文件。

## 开始片段

在 C++中，片段由`IAction`接口表示，可以由每个游戏自由实现或扩展。

通过调用`IActionController::Queue`函数来排队一个片段，但在这之前，我们必须获取我们片段的`FragmentId`。

### 获取片段标识符

要获取片段标识符，我们需要获取当前的动画上下文，以便从中获取当前的控制器定义，从中获取片段 ID：

```cs
SAnimationContext *pAnimContext = GetAnimatedCharacter()->GetAnimationContext();

FragmentID fragmentId = pAnimContext->controllerDef.m_fragmentIDs.Find(name);
CRY_ASSERT(fragmentId != FRAGMENT_ID_INVALID);
```

注意我们如何调用`IAnimatedCharacter::GetAnimationContext`。正如本章前面提到的，动画角色扩展为我们实现了 Mannequin 功能。

### 排队片段

现在我们有了片段标识符，我们可以简单地创建我们选择使用的动作的新实例。在我们的情况下，我们将使用通过`TAction`模板公开的默认 Mannequin 动作：

```cs
int priority = 0;
IActionPtr pAction = new TAction<SAnimationContext>(priority, id);
```

现在我们有了优先级为 0 的动作。动画系统将比较排队动作的优先级，以确定应该使用哪个。例如，如果两个动作同时排队，一个优先级为 0，另一个优先级为 1，那么优先级为 1 的第二个动作将首先被选择。

现在要排队动作，只需调用`IActionController::Queue`：

```cs
IActionController *pActionController = GetAnimatedCharacter()->GetActionController();

pActionController->Queue(pAction);
```

## 设置标签

要在运行时启用标签，我们首先需要获取我们标签的标识符，如下所示：

```cs
SAnimationContext *pAnimationContext = pActionController->GetContext();

TagID tagId = pAnimationContext->state.GetDef().Find(name);
CRY_ASSERT(tagId != TAG_ID_INVALID);
```

现在我们只需要调用`CTagState::Set`：

```cs
SAnimationContext *pAnimContext = pActionController->GetContext();

bool enable = true;
pAnimContext->state.Set(tagId, enable);
```

完成！我们的标签现在已激活，并将在动画系统中显示为活动状态。如果你的动作设置为动态更新，它将立即选择适当的选项。

### 强制动作重新查询选项

默认的`IAction`实现在更改标签时不会自动选择相关选项。要更改这一点，我们需要创建一个从中派生的新类，并用以下代码覆盖其`Update`函数：

```cs
IAction::EStatus CUpdatedAction::Update(float timePassedSeconds)
{
  TBase::Update(timePassedSeconds);

  const IScope &rootScope = GetRootScope();
  if(rootScope.IsDifferent(m_fragmentID, m_fragTags))
  {
    SetFragment(m_fragmentID, m_fragTags);
  }

  return m_eStatus;
}
```

之前的代码所做的是检查是否有更好的选项可用，并选择那个选项。

## 调试 Mannequin

要启用 Mannequin 调试，我们需要向动作控制器附加`AC_DebugDraw`标志：

```cs
pActionController->SetFlag(AC_DebugDraw, g_pGameCVars->pl_debugMannequin != 0);
```

现在你将看到可视片段和标签选择调试信息。在使用 Mannequin 时非常有用。

## 为自定义实体设置 Mannequin

正如本章前面提到的，动画角色游戏对象扩展默认集成了 Mannequin。在使用演员时非常方便，但在某些情况下，可能需要在自定义实体上使用 Mannequin 提供的功能。

首先，我们需要在实体扩展中存储指向我们的动作控制器和动画上下文的指针，如下所示：

```cs
IActionController *m_pActionController;
SAnimationContext *m_pAnimationContext;
```

然后，我们需要初始化 Mannequin；这通常在游戏对象扩展的`PostInit`函数中完成。

### 初始化 Mannequin

首先要做的是获取 Mannequin 接口：

```cs
// Mannequin Initialization
IMannequin &mannequinInterface = gEnv->pGame->GetIGameFramework()->GetMannequinInterface();
IAnimationDatabaseManager &animationDBManager = mannequinInterface.GetAnimationDatabaseManager();
```

### 加载控制器定义

接下来，我们需要加载为我们实体创建的控制器定义：

```cs
const SControllerDef *pControllerDef = animationDBManager.LoadControllerDef("Animations/Mannequin/ADB/myControllerDefinition.xml");
```

太棒了！现在我们有了控制器定义，可以用以下代码创建我们的动画上下文：

```cs
m_pAnimationContext = new SAnimationContext(*pControllerDef);
```

现在我们可以创建我们的动作控制器：

```cs
m_pActionController = mannequinInterface.CreateActionController(pEntity, *m_pAnimationContext);
```

### 设置活动上下文

现在我们已经初始化了我们的动作控制器，我们需要设置默认的上下文。

首先，获取上下文标识符：

```cs
const TagID mainContextId = m_pAnimationContext->controllerDef.m_scopeContexts.Find("Char3P");

CRY_ASSERT(mainContextId != TAG_ID_INVALID);
```

然后加载我们将要使用的动画数据库：

```cs
const IAnimationDatabase *pAnimationDatabase = animationDBManager.Load("Animations/Mannequin/ADB/myAnimDB.adb");
```

加载后，只需调用`IActionController::SetScopeContext`：

```cs
m_pActionController->SetScopeContext(mainContextId, *pEntity, pCharacterInstance, pAnimationDatabase);
```

一旦上下文设置好，Mannequin 就初始化好了，可以处理你实体的排队片段。

记住，你可以随时使用之前使用过的`IActionController::SetScopeContext`函数来改变作用域上下文。

# 摘要

在这一章中，我们学习了演员系统的功能，并在 C＃和 C ++中创建了自定义演员。通过查看输入和摄像头系统，我们将能够处理基本的玩家输入和视图设置。

您还应该对 Mannequin 的用例有很好的理解，并知道如何设置自定义实体来利用它们。

现在，我们已经拥有了游戏所需的所有核心功能：流节点、实体、游戏规则和演员。在接下来的章节中，我们将在现有知识的基础上进行扩展，并详细介绍这些系统如何一起使用。

如果您想在继续之前继续研究演员，请随时尝试并实现自己定制的演员，以适应新的情景；例如，配备基本 RPG 玩家元素的等距摄像头。

在下一章中，我们将利用在演员身上学到的知识来创建**人工智能**（**AI**）。


# 第六章：人工智能

CryENGINE AI 系统允许创建在游戏世界中漫游的非玩家控制角色。

在本章中我们将：

+   了解 AI 系统如何与 Lua 脚本集成

+   了解目标管道是什么，以及如何创建它们

+   使用 AI 信号

+   注册自定义 AI`Actor`类

+   学习如何使用行为选择树

+   创建我们自己的 AI 行为

# 人工智能（AI）系统

CryENGINE AI 系统的设计是为了方便创建灵活到足以处理更大量的复杂和不同世界的自定义 AI 角色。

在我们开始研究 AI 系统的本地实现之前，我们必须提到一个非常重要的事实：AI 不同于角色，不应该混淆。

在 CryENGINE 中，AI 仍然依赖于底层的角色实现，通常与玩家使用的完全相同。然而，AI 本身的实现是通过 AI 系统单独完成的，该系统将移动输入等发送给角色。

## 脚本

CryENGINE 的 AI 系统的主要思想是基于大量的脚本编写。可以使用`Scripts/AI`和`Scripts/Entities/AI`目录中包含的 Lua 脚本来创建新的 AI 行为，而不是强迫程序员修改复杂的 CryAISystem 模块。

### 注意

AI 系统目前主要是硬编码为使用`.lua`脚本，因此我们将无法在 AI 开发中更大程度地使用 C#和 C++。

## AI 角色

正如我们之前提到的，角色与 AI 本身是分开的。基本上这意味着我们需要创建一个`IActor`实现，然后指定角色应该使用哪种 AI 行为。

如果您的 AI 角色应该与您的玩家行为大致相同，您应该重用角色实现。

如前一章所述，注册一个角色可以通过`REGISTER_FACTORY`宏来完成。AI 角色的唯一区别是最后一个参数应该设置为 true 而不是 false：

```cs
  REGISTER_FACTORY(pFramework, "MyAIActor", CMyAIActor, true);
```

一旦注册，AI 系统将在`Scripts/Entities/AI`中搜索以您的实体命名的 Lua 脚本。在前面的片段中，系统将尝试加载`Scripts/Entities/AI/MyAIActor.lua`。

这个脚本应该包含一个同名的表，并且与其他 Lua 实体的功能相同。例如，要添加编辑器属性，只需在 Properties 子表中添加变量。

## 目标管道

目标管道定义了一组目标操作，允许在运行时触发一组目标。例如，一个目标管道可以包括 AI，增加其移动速度，同时开始搜索玩家控制的单位。

目标操作，如 LookAt，Locate 和 Hide 是在`CryAISystem.dll`中创建的，不能在没有访问其源代码的情况下进行修改。

### 创建自定义管道

管道最初是在`PipeManager:CreateGoalPipes`函数中在`Scripts/AI/GoalPipes/PipeManager.lua`中注册的，使用`AI.LoadGoalPipes`函数：

```cs
  AI.LoadGoalPipes("Scripts/AI/GoalPipes/MyGoalPipes.xml");
```

这段代码将加载`Scripts/AI/GoalPipes/MyGoalPipes.xml`，其中可能包含以下目标管道定义：

```cs
<GoalPipes>
  <GoalPipe name="myGoalPipes_findPlayer">
    <Locate name="player" />
    <Speed id="Run"/>
    <Script code="entity.Behavior:AnalyzeSituation(entity);"
  </GoalPipe>
</GoalPipes>
```

当选择了这个管道时，分配的 AI 将开始定位玩家，切换到`Run`移动速度状态，并调用当前选定的行为脚本中包含的`AnalyzeSituation`函数。

目标管道可以非常有效地推动一组目标，例如基于前面的脚本，我们可以简单地选择`myGoalPipes_findPlayer`管道，以便 AI 寻找玩家。

### 选择管道

目标管道通常使用 Lua 中的实体函数`SelectPipe`来触发：

```cs
  myEntity:SelectPipe(0, "myGoalPipe");
```

或者也可以通过 C++触发，使用`IPipeUser::SelectPipe`函数。

## 信号

为了为 AI 实体提供直观的相互通信方式，我们可以使用信号系统。信号是可以从另一个 AI 实体或从 C++或 Lua 代码的其他地方发送到特定 AI 单元的事件。

信号可以使用 Lua 中的`AI.Signal`函数或 C++中的`IAISystem::SendSignal`发送。

## AI 行为

每个角色都需要分配行为，并且它们定义了单位的决策能力。通过在运行时使用**行为选择树**选择行为，角色可以给人一种动态调整到周围环境的印象。

使用放置在`Scripts/AI/SelectionTrees`中的 XML 文件创建行为选择树。每个树管理一组**行为叶子**，每个叶子代表一种可以根据条件启用的 AI 行为类型。

![AI 行为](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909_06_01.jpg)

### 样本

例如，如下所示，查看选择树 XML 定义的非常基本形式：

```cs
<SelectionTrees>
  <SelectionTree name="SelectionTreeSample" type="BehaviorSelectionTree">
    <Variables>
      <Variable name="IsEnemyClose"/>
    </Variables>
    <SignalVariables>
      <Signal name="OnEnemySeen" variable="IsEnemyClose" value="true"/>
      <Signal name="OnNoTarget" variable="IsEnemyClose" value="false"/>
      <Signal name="OnLostSightOfTarget" variable="IsEnemyClose" value="false"/>
    </SignalVariables>
    <LeafTranslations />
    <Priority name="Root">
      <Leaf name="BehaviorSampleCombat" condition="IsEnemyClose"/>
      <Leaf name="BehaviorSampleIdle"/>
    </Priority>
  </SelectionTree>
</SelectionTrees>
```

为了更好地理解示例，我们将对其进行一些分解：

```cs
  <SelectionTree name="SelectionTreeSample" type="BehaviorSelectionTree">
```

这个第一个片段只是定义了选择树的名称，并且在 AI 初始化期间将被 AI 系统解析。如果要重命名树，只需更改`name`属性：

```cs
<Variables>
  <Variable name="IsEnemyClose"/>
</Variables>
```

每个选择树可以定义一组变量，这些变量可以根据信号（请参见下一个片段）或在每个行为脚本内部进行设置。

变量只是可以查询的布尔条件，以确定下一个叶子或行为选择：

```cs
<SignalVariables>
  <Signal name="OnEnemySeen" variable="IsEnemyClose" value="true"/>
  <Signal name="OnNoTarget" variable="IsEnemyClose" value="false"/>
  <Signal name="OnLostSightOfTarget" variable="IsEnemyClose" value="false"/>
</SignalVariables>
```

每个行为树还可以监听诸如`OnEnemySeen`之类的信号，以便轻松设置变量的值。例如，在我们刚刚看到的片段中，当发现敌人时，`IsEnemyClose`变量将始终设置为 true，然后在目标丢失时设置为 false。

然后我们可以在查询新叶子时使用变量（请参见下面的代码片段），允许 AI 根据简单的信号事件切换到不同的行为脚本：

```cs
<Priority name="Root">
  <Leaf name="BehaviorSampleCombat" condition="IsEnemyClose"/>
  <Leaf name="BehaviorSampleIdle"/>
</Priority>
```

通过在`Priority`元素内指定叶子，我们可以根据简单的条件在运行时启用行为（叶子）。

例如，前面的片段将在敌人接近时启用`BehaviorSampleCombat`行为脚本，否则将退回到`BehaviorSampleIdle`行为。

### 注意

行为选择树系统将按顺序查询叶子，并退回到最后剩下的叶子。在这种情况下，它将首先查询`BehaviorSampleCombat`，然后在`IsEnemyClose`变量设置为 false 时退回到`BehaviorSampleIdle`。

## IAIObject

已向 AI 系统注册的实体可以调用`IEntity::GetAI`来获取它们的`IAIObject`指针。

通过访问实体的 AI 对象指针，我们可以在运行时操纵 AI，例如设置自定义信号，然后在我们的 AI 行为脚本中拦截：

```cs
if(IAIObject *pAI = pEntity->GetAI())
{
  gEnv->pAISystem->SendSignal(SIGNALFILTER_SENDER, 0, "OnMySignal", pAI);
}
```

# 创建自定义 AI

创建自定义 AI 的过程相对简单，特别是如果您对上一章介绍的角色系统感到满意。

每个角色都有两个部分；它的`IActor`实现和 AI 实体定义。

## 注册 AI 角色实现

AI 角色通常使用与玩家相同的`IActor`实现，或者至少是共享的派生。

### 在 C#中

在 C#中注册 AI 角色与我们在第五章中所做的非常相似，*创建自定义角色*。基本上，我们只需要从`CryEngine.AIActor`派生，而不是`CryEngine.Actor`。

`AIActor`类直接从`Actor`派生，因此不会牺牲任何回调和成员。但是，必须明确实现它，以使 CryENGINE 将此角色视为由 AI 控制。

```cs
public class MyCSharpAIActor
: CryEngine.AIActor
{
}
```

现在，您应该能够在 Sandbox 中的**Entity**浏览器中的**AI**类别中放置您的实体：

![在 C#中](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909_06_02.jpg)

### 在 C++中

与我们刚刚看到的 C#角色一样，注册一个角色到 AI 系统并不需要太多工作。只需从我们在上一章创建的角色实现派生即可：

```cs
class CMyAIActor
  : public CMyCppActor
{
};
```

然后打开你的 GameDLL 的`GameFactory.cpp`文件，并使用相同的设置来注册角色，只是最后一个参数应该是 true，告诉 CryENGINE 这种角色类型将由 AI 控制：

```cs
  REGISTER_FACTORY(pFramework, "MyAIActor", CMyAIActor, true);
```

在重新编译后，你的角色现在应该出现在**实体**浏览器中的**AI**实体类别中。

## 创建 AI 实体定义

当我们的 AI 角色生成时，AI 系统将搜索 AI 实体定义。这些定义用于设置角色的默认属性，例如其编辑器属性。

我们需要做的第一件事是打开`Scripts/Entities/AI`并创建一个与我们的`Actor`类同名的新的`.lua`文件。在我们的情况下，这将是为了刚刚创建的 C++实现的`MyAIActor.lua`，以及为了 C#角色的`MyCSharpAIActor.lua`。

脚本保持了最少量的代码，因为我们只需要加载基本 AI。基本 AI 是使用`Script.ReloadScript`函数加载的。

默认情况下，CryENGINE 使用`Scripts/Entities/AI/Shared/BasicAI.lua`作为基本 AI 定义。我们将使用自定义实现，`Scripts/Entities/AI/AISample_x.lua`，以减少与本章节无关的不必要代码：

```cs
  Script.ReloadScript( "SCRIPTS/Entities/AI/AISample_x.lua");
--------------------------------------------------------------

  MyCSharpAIActor = CreateAI(AISample_x);
```

就是这样！你的 AI 现在已经正确注册，现在应该可以通过编辑器放置。

### 注意

有关基本 AI 定义的更多信息，请参见本章后面的*AI 基本定义分解*部分。

## AI 行为和角色

当我们生成自定义 AI 角色时，默认情况下应该出现四个实体属性。这些属性确定 AI 应该使用哪些系统进行决策：

![AI 行为和角色](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909_06_03.jpg)

### 理解和使用行为选择树

行为选择树是我们的 AI 角色最重要的实体属性，因为它确定了角色使用哪个行为选择树。如果我们的项目包含多个行为选择树，我们可以轻松生成行为非常不同的多个 AI 角色，因为它们使用了不同的选择树。选择树系统存在是为了提供一种在运行时查询和选择行为脚本的方法。

要查看当前可用的树，或创建自己的树，请导航至`Scripts/AI/SelectionTrees`。对于我们的示例，我们将使用`Scripts/AI/SelectionTrees/FogOfWar.xml`中的`FogOfWar`选择树：

```cs
<SelectionTree name="FogOfWar" type="BehaviorSelectionTree">
  <Variables>
    <Variable name="IsFar"/>
    <Variable name="IsClose"/>
    <Variable name="AwareOfPlayer"/>
  </Variables>
  <SignalVariables>
    <Signal name="OnEnemySeen" variable="AwareOfPlayer" value="true"/>
    <Signal name="OnNoTarget" variable="AwareOfPlayer" value="false"/>
    <Signal name="OnLostSightOfTarget" variable="AwareOfPlayer" value="false"/>
  </SignalVariables>
  <LeafTranslations />
  <Priority name="Root">
    <Leaf name="FogOfWarSeekST" condition="IsFar"/>
    <Leaf name="FogOfWarEscapeST" condition="IsClose"/>
    <Leaf name="FogOfWarAttackST" condition="AwareOfPlayer"/>
    <Leaf name="FogOfWarIdleST"/>
  </Priority>
</SelectionTree>
```

#### 变量

每个选择树都公开一组可以在运行时设置的变量。叶子将查询这些变量，以确定激活哪种行为。

#### 信号变量

信号变量提供了一种在接收到信号时设置变量的简单方法。

例如，在前面的树中，我们可以看到当接收到`OnEnemySeen`信号时，`AwareOfPlayer`会动态设置。然后当 AI 失去对玩家的追踪时，这些变量将被设置为 false。

#### 叶子/行为查询

叶子确定根据变量条件播放哪种行为。

在前面的树中，我们可以看到当所有其他条件都设置为 false 时，默认情况下会激活`FogOfWarIdleST`行为。但是，假设`IsFar`变量设置为 true，系统将自动切换到`FogOfWarSeekST`行为。

### 注意

行为从`Scripts/AI/Behaviors/Personalities/`目录中加载，在我们的情况下，它将在`Scripts/AI/Behaviors/Personalities/FogOfWarST/`中找到参考行为。

### 角色

`Character`属性用于设置角色的 AI 角色。

### 注意

在我们的示例中，`Character`属性将默认为空字符串，因为自从引入行为选择树以来，该系统被视为已弃用（请查看*理解和使用行为选择树*部分）。

AI 角色包含在`Scripts/AI/Characters/Personalities`中，以`.lua`脚本的形式。例如，我们可以打开并修改`Scripts/AI/Characters/Personalities/FogOfWar.lua`以修改我们的默认个性。

您还可以通过在`Personalities`目录中添加新文件，以`FogOfWar`作为基线，来创建新的个性。

`Character`属性定义了所有适用的行为，在我们的例子中是`FogOfWarAttack`、`FogOfWarSeek`、`FogOfWarEscape`和`FogOfWarIdle`。角色将能够在运行时根据内部和外部条件在这些行为之间切换。

### 导航类型

`NavigationType`属性确定要使用哪种类型的 AI 导航。这允许系统动态确定哪些路径适用于该类型的 AI。

在我们的示例中，默认为 MediumSizedCharacter，并且可以设置为包含在`Scripts/AI/Navigation.xml`中的任何导航定义。

## 创建自定义行为

我们快要完成了！唯一剩下的步骤是理解如何创建和修改 AI 行为，使用我们之前描述的行为选择树来激活。

首先，使用您选择的文本编辑器打开`Scripts/AI/Behaviors/Personalities/FogOfWarST/FogOfWarIdleST.lua`。由于之前描述的行为树设置，这是在所有其他变量都设置为 false 时将被激活的行为。

通过调用`CreateAIBehavior`函数来创建行为，第一个参数设置为新行为的名称，第二个包含行为本身的表。

因此，行为的最低要求是：

```cs
local Behavior = CreateAIBehavior("MyBehavior",
{
  Alertness = 0,

  Constructor = function (self, entity)
  end,

  Destructor = function(self, entity)
  end,
})
```

这段代码片段会始终将 AI 的`Alertness`设置为 0，并且在行为开始（`Constructor`）和结束（`Destructor`）时什么也不做。

通过查看`FogOfWarIdleST`行为定义，我们可以看到它的作用：

```cs
  Constructor = function (self, entity)
    Log("Idling...");
    AI.SetBehaviorVariable(entity.id, "AwareOfPlayer", false);
    entity:SelectPipe(0,"fow_idle_st");
  end,
```

当激活行为时，我们应该在控制台中看到“Idling…”，假设日志详细程度足够高（使用`log_verbosity CVar`设置）。

在记录之后，该行为将通过`AI.SetBehaviorVariable`函数将`AwareOfPlayer`变量重置为 false。我们可以随时使用该函数来改变变量的值，有效地告诉行为选择树应该查询另一个行为。

将变量设置为 false 后，构造函数会选择`fow_idle_st`目标管道。

### 监听信号

要在行为中监听信号，只需创建一个新函数：

```cs
OnMySignal = function(self, entity, sender)
{
}
```

当发送`OnMySignal`信号时，将调用此函数，并附带相关的实体和行为表。

# AI 基本定义分解

在本章中，我们之前创建了依赖于`Scripts/Entities/AI/AISample_x.lua`基本定义的自定义 AI 定义。本节将描述基本定义的作用，以便更好地理解定义设置。

首先，使用您选择的文本编辑器（例如 Notepad++）打开定义。

## AISample_x 表

当打开`AISample_x.lua`时，我们将看到的第一行代码是其表定义，它定义了每个角色的默认属性。

### 注意

每个 AI 定义都可以覆盖基本定义中设置的属性。

### 属性表

属性表的工作方式与标准 Lua 实体相同，用于定义在编辑器中选择实体时出现的属性。

### 注意

我们基本 AI 定义中的默认属性是从`CryAISystem.dll`中读取的。不支持删除这些属性，否则会导致 AI 初始化失败。

### AIMovementAbility 表

`AIMovementAbility`子表定义了我们角色的移动能力，例如行走和奔跑速度。

## CreateAI 函数

`CreateAI`函数将基本 AI 表与指定子表合并。这意味着在 AI 基本定义中存在的任何表都将存在于从中派生的任何 AI 定义中。

`CreateAI`函数还使实体可生成，并通过调用 AI 的`Expose()`函数将其暴露给网络。

## RegisterAI 函数

`RegisterAI`函数在应该将角色注册到 AI 系统时调用。这在实体生成时和编辑器属性更改时会自动调用。

# 总结

在本章中，我们已经了解了 AI 系统的核心思想和实现，并创建了自定义的 AI 角色实现。

通过创建我们自己的 AI 实体定义和行为选择树，您应该了解到在 CryENGINE 中如何创建 AI 角色。

现在，您应该对如何利用 AI 系统有了很好的理解，从而可以创建巡逻游戏世界的 AI 控制单位。

如果您对 AI 还没有完全掌握，为什么不尝试利用您新获得的知识来创建自己选择的更复杂的东西呢？

在下一章中，我们将介绍创建自定义用户界面的过程，允许创建主菜单和**抬头显示**（**HUD**）。


# 第七章：用户界面

CryENGINE 集成了 Scaleform GFx，允许呈现基于 Adobe Flash 的用户界面、HUD 和动画纹理。通过在运行时使用 UI 流程图解决方案将 UI 元素直观地连接在一起，开发人员可以迅速创建和扩展用户界面。

在本章中，我们将涵盖以下主题：

+   了解 CryENGINE Scaleform 实现及其带来的好处。

+   创建我们的主菜单。

+   实施 UI 游戏事件系统

# Flash 电影剪辑和 UI 图形

为了为开发人员提供创建用户界面的解决方案，CryENGINE 集成了 Adobe Scaleform GFx，这是一个用于游戏引擎的实时 Flash 渲染器。该系统允许在 Adobe Flash 中创建用户界面，然后可以导出以立即在引擎中使用。

### 注意

还可以在材质中使用 Flash `.swf`文件，从而在游戏世界中的 3D 对象上呈现 Flash 电影剪辑。

通过 UI 流程图系统，创建模块化动态用户界面所需的工作大大简化。

UI 流程图系统基于两种类型的概念：**元素**和**动作**。每个元素代表一个 Flash 文件（`.swf`或`.gfx`），而每个动作是一个表示 UI 状态的流程图。

## 元素

UI 元素通过`Game/Libs/UI/UIElements/`中的 XML 文件进行配置，并表示每个 Flash 文件。通过修改 UI 元素的配置，我们可以更改它接收的事件和对齐模式，以及公开导出的 SWF 文件中存在的不同函数和回调。

### XML 分解

元素的最低要求可以在以下代码中看到：

```cs
<UIElements name="Menus">
  <UIElement name="MyMainMenu" mouseevents="1" keyevents="1" cursor="1" controller_input="1">

    <GFx file="Menus_Startmenu.swf" layer="3">
      <Constraints>
        <Align mode="fullscreen" scale="1"/>
      </Constraints>
    </GFx>

    <functions>
    </functions>

    <events>
    </events>
    <Arrays>
    </Arrays>

    <MovieClips>
    </MovieClips>
  </UIElement>
</UIElements>
```

前面的 XML 代码可以保存为`Game/Libs/UI/UIElements/MyMainMenu.xml`，并将 Flash 文件`Menus_Startmenu.swf`加载到`Game/Libs/UI/`文件夹中。

创建完成后，我们将能够通过流程图节点选择我们的新 UI 元素，例如**UI:Display:Config**（用于重新配置任何元素，例如在运行时启用元素的鼠标事件）。

![XML 分解](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909_07_01.jpg)

既然我们知道它是如何工作的，让我们来详细了解一下：

```cs
<UIElements name="Menus">
```

这第一个元素定义了文件的开始，并确定了我们的元素应该放在哪个类别中。

```cs
<UIElement name="MyMainMenu" mouseevents="1" keyevents="1" cursor="1" controller_input="1">
```

`UIElement` XML 元素用于决定初始配置，包括默认名称，并确定默认应接收哪些事件。

如前所述，每个元素都可以通过一组属性进行配置，允许开发人员定义要监听的事件类型：

| 属性名称 | 描述 |
| --- | --- |
| `name` | 定义元素的名称（字符串）。 |
| `mouseevents` | 确定是否将鼠标事件发送到 Flash 文件（0/1）。 |
| `cursor` | 确定在元素可见时是否显示光标（0/1）。 |
| `keyevents` | 确定是否将键事件发送到 Flash 文件（0/1）。 |
| `console_mouse` | 确定在控制台硬件上拇指杆是否应该作为光标（0/1）。 |
| `console_cursor` | 确定在控制台硬件上运行时是否显示光标（0/1）。 |
| `layer` | 定义元素显示顺序，以防多个元素存在。 |
| `alpha` | 设置元素的背景透明度（0-1）。允许在游戏中使用透明度，例如在主菜单后显示游戏关卡。 |

### 注意

请注意，先前提到的属性可以通过使用**UI:Display:Config**节点实时调整。

```cs
<GFx file="Menus_Startmenu.swf" layer="3">
```

`GFx`元素确定应加载哪个 Flash 文件用于该元素。可以加载多个 GFx 文件并将它们放入不同的层。

这允许在运行时选择要使用的元素层，例如，通过**UI:Display:Config**节点上的`layer`输入，如前面截图所示。

```cs
<Constraints>
  <Align mode="fullscreen" scale="1"/>
</Constraints>
```

`Constraints`允许配置 GFx 元素在屏幕上的显示方式，使开发人员能够调整元素在不同显示分辨率下的表现方式。

目前有三种模式如下：

| 模式名称 | 描述 | 附加属性 |
| --- | --- | --- |
| 固定 | 在固定模式下，开发人员可以使用四个属性来设置距离顶部和左侧角的像素距离，以及设置所需的分辨率。 | 顶部、左侧、宽度和高度 |
| 动态 | 在动态模式下，元素根据锚点对齐，允许水平和垂直对齐。halign 可以设置为`left`、`center`或`right`，而 valign 可以设置为`top`、`center`或`bottom`。如果比例设置为`1`，元素将按比例缩放到屏幕分辨率。如果最大设置为`1`，元素将被最大化，以确保覆盖屏幕的 100%。 | halign、valign、比例和最大 |
| 全屏 | 在此模式下激活时，元素视口将与渲染视口完全相同。如果比例设置为`1`，元素将被拉伸到屏幕分辨率。 | 比例 |

## 动作

UI 动作是 UI 流程图实现的核心。每个动作都由一个流程图表示，并定义了一个 UI 状态。例如，主菜单中的每个屏幕都将使用单独的动作来处理。

所有可用的 UI 动作都可以在**流程图**工具箱中看到，在流程图编辑器中。

![动作](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909_07_02.jpg)

要创建新的 UI 动作，导航到**文件** | **新 UI 动作**，并在新打开的**另存为**对话框中指定您的新动作的名称： 

![动作](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909_07_03.jpg)

通过使用**UI:Action:Control**节点启动动作，并在**UIAction**输入端口中指定待处理动作的名称，然后激活**Start**输入来启动动作。

![动作](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909_07_04.jpg)

一旦启动，具有指定名称的 UI 图将被激活，假设它包含一个如下所示的**UI:Action:Start**节点：

![动作](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909_07_05.jpg)

然后，图表可以通过监听**StartAction**输出端口来初始化请求的 UI。一旦动作完成，应该调用**UI:Action:End**，如下所示：

![动作](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909_07_06.jpg)

就是这样。UI 图表以 flowgraph XML 文件的形式保存在`Game/Libs/UI/UIActions/`中。初始 UI 动作称为**Sys_StateControl**，并且始终处于活动状态。状态控制器图应负责根据系统事件（如关卡加载）加载和启用菜单。

系统状态控制动作（`Sys_StateControl.xml`）始终处于活动状态，并且用于启动初始动作，例如在引擎启动时显示主菜单。

# 创建主菜单

现在我们对 UI 流程图实现有了基本的了解，让我们开始创建我们自己的主菜单吧。

## 创建菜单元素

我们需要做的第一件事是创建我们的 UI 元素定义，以便为引擎提供加载我们导出的 SWF 文件的手段。

为此，在`Game/Libs/UI/UIElements/`中创建一个名为`MainMenuSample.xml`的新 XML 文档。我们菜单所需的最低限度的代码可以在以下代码中看到：

```cs
<UIElements name="Menus">
  <UIElement name="MainMenuSample" mouseevents="1" keyevents="1" cursor="1" controller_input="1">
    <GFx file="MainMenuSample.swf" layer="3">
      <Constraints>
        <Align mode="dynamic" halign="left" valign="top" scale="1" max="1"/>
      </Constraints>
    </GFx>
  </UIElement>
</UIElements>
```

有了上面的代码，引擎就会知道在哪里加载我们的 SWF 文件，以及如何在屏幕上对齐它。

### 注意

SWF 文件可以通过使用`GFxExport.exe`（通常位于`<root>/Tools/`目录中）重新导出，以便在引擎中更高效地使用。这通常是在发布游戏之前完成的。

## 暴露 ActionScript 资产

接下来，我们需要暴露我们在 Flash 源文件中定义的函数和事件，以便允许引擎调用和接收这些函数和事件。

在暴露函数和事件时，我们创建了简单的流程图节点，可以被任何流程图使用。

创建后，函数节点可以通过导航到**UI** | **函数**来访问，如下面的截图所示：

![暴露 ActionScript 资产](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909_07_07.jpg)

通过导航到**UI** | **Events**，可以找到事件。

### 注意

还可以在 C++中创建 UI 操作和元素，有效地使用户界面能够从本机代码发送和接收事件。我们将在本章后面的*创建 UI 游戏事件系统*部分中介绍这一点。

### 函数

要公开一个方法，我们需要像以下代码中所示，在`UIElement`定义中添加一个新的`<functions>`部分：

```cs
<functions>
  <function name="SetupScreen" funcname="setupScreen" desc="Sets up screen, clearing previous movieclips and configuring settings">
    <param name="buttonX" desc="Initial x pos of buttons" type="int" />
    <param name="buttonY" desc="Initial y pos of buttons" type="int" />
    <param name="buttonDividerSize" desc="Size of the space between buttons" type="int" />
  </function>

  <function name="AddBigButton" funcname="addBigButton" desc="Adds a primary button to the screen">
    <param name="id" desc="Button Id, sent with the onBigButton event" type="string" />
    <param name="title" desc="Button text" type="string" />
  </function>
</functions>
```

使用上述代码，引擎将创建两个节点，我们可以利用这些节点来调用 UI 图表中的`setupScreen`和`addBigButton` ActionScript 方法。

### 注意

函数始终放置在相同的 flowgraph 类别中：**UI:Functions:ElementName:FunctionName**

![函数](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909_07_08.jpg)

当触发前一个截图中显示的任一节点上的**Call**端口时，将调用 ActionScript 方法并使用指定的参数。

### 注意

**instanceID**输入端口确定要在哪个元素实例上调用函数。如果值设置为`-1`（默认值），则将在所有实例上调用，否则如果设置为`-2`，则将在所有初始化的实例上调用。

### 事件

设置事件的方式与函数类似，使用`<events>`标签如下：

```cs
<events>
  <event name="OnBigButton" fscommand="onBigButton" desc="Triggered when a big button is pressed">    
    <param name="id" desc="Id of the button" type="string" />
  </event>
</events>
```

上述代码将使引擎创建**OnBigButton**节点可用，当 Flash 文件调用`onBigButton` fscommand 时触发，同时会有相关的按钮 ID。

![事件](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909_07_09.jpg)

从 Flash 中调用`fscommand`相对容易。以下代码将触发`onBigButton`事件，并附带相关的按钮 ID 字符串。

```cs
fscommand("onBigButton", buttonId);
```

### 注意

与函数类似，事件始终放置在**UI:Events:ElementName:EventName**中。

### 变量

还可以通过元素定义定义访问 Flash 源文件中存在的变量。这允许通过使用**UI:Variable:Var**节点获取和设置变量的值。

首先，在元素定义的`<variables>`块中定义数组：

```cs
<variables>
  <variable name="MyTextField" varname="_root.m_myTextField.text"/>
</variables>
```

重新启动编辑器后，放置一个新的**UI:Variable:Var**节点，并按照以下截图中所示浏览您的新变量：

![变量](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909_07_10.jpg)

然后我们可以通过 flowgraph 随时设置或获取我们的变量的值：

![变量](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909_07_11.jpg)

### 数组

在上一节中，我们在运行时设置了 Flash 变量的值。通过使用**UI:Variable:Array**节点，也可以对数组进行相同操作。

首先，按照以下方式公开元素`<arrays>`块中的数组：

```cs
<arrays>
  <array name="MyArray" varname="_root.m_myArray"/>
</arrays>
```

然后简单地重新启动数组并重复之前的过程，但使用**UI:Variable:Array**节点。要通过 UI 图表创建新数组，请使用**UI:Util:ToArray**节点：

![数组](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909_07_12.jpg)

## 将 MovieClip 实例公开给 flowgraph

与变量可以公开类似，也可以通过 UI 图表直接访问 MovieClips。这允许跳转到特定帧，更改属性等。

所有允许 MovieClip 交互的节点都可以在 Flowgraph 编辑器中的**UI** | **MovieClip**中找到，如下截图所示：

![将 MovieClip 实例公开给 flowgraph](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909_07_13.jpg)

首先，按照以下方式添加或编辑元素定义中的`<movieclips>`块：

```cs
<movieclips>
  <movieclip name="MyMovieClip" instancename="_root.m_myMovieclip"/>
</movieclips>
```

这将使 flowgraph 可以访问 Flash 文件中存在的**m_myMovieClip** MovieClip。

编辑器重新启动后，我们可以使用**UI:MovieClip:GotoAndPlay**节点，例如直接跳转到指定剪辑中的不同帧，如下截图所示：

![将 MovieClip 实例公开给 flowgraph](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909_07_14.jpg)

## 创建 UI 操作

现在我们已经配置了主菜单元素，是时候创建 UI 操作，使菜单出现在启动器应用程序中了。

### 创建状态控制图

首先打开 Sandbox 和 Flowgraph Editor。一旦打开，通过导航到**文件**|**新建 UI 动作**来创建一个新的 UI 动作。将动作命名为**Sys_StateControl**。这将是我们触发初始菜单和处理关键系统事件的主要 UI 动作。

创建动作后，我们将使用以下三个系统事件：

+   OnSystemStarted

+   OnLoadingError

+   OnUnloadComplete

这些事件一起表示我们的主菜单应该何时出现。我们将把它们绑定到一个**UI:Action:Control**节点中，该节点将激活我们稍后将创建的 MainMenu UIAction。

![创建状态控制图](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909_07_15.jpg)

### 创建 MainMenu 动作

完成后，创建另一个 UI 动作，并命名为**MainMenu**。一旦打开，放置一个**UI:Action:Start**节点。当我们之前创建的**UI:Action:Control**节点被执行时，它的**StartAction**输出端口将自动激活。

现在我们可以将**Start**节点连接到**UI:Display:Display**和**UI:Display:Config**节点，以初始化主菜单，并确保用户可以看到它。

![创建 MainMenu 动作](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909_07_16.jpg)

我们的 flash 文件现在将在游戏启动时显示，但目前还缺少来自 flowgraph 的任何额外配置。

### 添加按钮

现在我们的主菜单文件已初始化，我们需要在 Flash 文件中添加一些 ActionScript 代码，以允许从 UI 图中动态生成和处理按钮。

本节假定您有一个 MovieClip 可以在运行时实例化。在我们的示例中，我们将使用一个名为**BigButton**的自定义按钮。

![添加按钮](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909_07_17.jpg)

### 注意

我们的主菜单的 Flash 源文件（.fla）位于我们示例安装的`Game/Libs/UI/`文件夹中，可从[`github`](https://github) [.com/inkdev/CryENGINE-Game-Programming-Sample/](http://.com/inkdev/CryENGINE-Game-Programming-Sample/)下载。

本节还假定您有两个 ActionScript 函数：`SetupScreen`和`AddBigButton`。

`SetupScreen`应该配置场景的默认设置，并删除所有先前生成的对象。在我们的情况下，我们希望使用`AddBigButton`生成的按钮在调用`SetupScreen`时被移除。

`AddBigButton`应该只是一个生成预先创建的按钮实例的函数，如下所示：

```cs
var button = _root.attachMovie("BigButton", "BigButton" + m_buttons.length, _root.getNextHighestDepth());
```

当单击按钮时，它应该调用一个事件，我们在 flowgraph 中捕获：

```cs
fscommand("onBigButton", button._id);
```

有关创建功能和事件的信息，请参阅前面讨论的*公开 ActionScript 资产*部分。

完成后，将节点添加到 MainMenu 动作中，并在配置元素后调用它们：

![添加按钮](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909_07_18.jpg)

我们的主菜单现在应该在启动启动器应用程序时出现，但是对于用户与之交互没有任何反馈。

为了解决这个问题，我们可以利用前面在本章中公开的 OnBigButton 节点。该节点将在按钮被点击时发送事件，以及一个字符串标识符，我们可以用来确定点击了哪个节点：

![添加按钮](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909_07_19.jpg)

在前面的图中，我们拦截按钮事件，并使用**String:Compare**节点来检查我们需要对输入做什么。如果点击了**IDD_Quit**按钮，我们退出游戏，如果点击了**IDD_Start**节点，我们加载**Demo**关卡。

## 最终结果

假设您没有创建自己的菜单设计，现在启动启动器时应该看到以下截图：

![最终结果](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909_07_20.jpg)

现在您已经学会了创建一个简单菜单有多么容易，为什么不继续创建一个在玩家生成时显示的**HUD**（**Heads-Up Display**）呢？

# 引擎 ActionScript 回调

引擎会自动调用一些 ActionScript 回调。只需在 Flash 源文件根目录中定义这些函数，引擎就能够调用它们。

+   `cry_onSetup(isConsole:Boolean)`: 当 SWF 文件被引擎初始加载时调用此函数。

+   `cry_onShow()`: 当 SWF 文件显示时调用此函数。

+   `cry_onHide()`: 当 SWF 文件隐藏时调用此函数。

+   `cry_onResize(_iWidth:Number, _iHeight:Number)`: 当游戏分辨率更改时调用此函数。

+   `cry_onBack()`: 当用户按下返回按钮时调用此函数。

+   `cry_requestHide()`: 当元素隐藏时调用此函数。

# 创建 UI 游戏事件系统

UI 系统利用`IUIGameEventSystem`接口与流程图进行通信，允许以与公开 ActionScript 资源相同的方式定义自定义函数和事件。

这用于允许用户界面访问游戏和引擎功能，例如获取可玩关卡列表。每个游戏事件系统都指定其类别，然后在流程图编辑器中用于定义注册的函数和事件的类别。

例如，如果我们使用`IFlashUI::CreateEventSystem`创建名为 MyUI 的事件系统，可以通过导航到**UI** | **Functions** | **MyUI**找到所有函数。

## 实现`IUIGameEventSystem`

实现`IUIGameEventSystem`不需要太多工作；我们只需要分配以下三个纯虚函数：

+   `GetTypeName`: 不直接重写；而是使用`UIEVENTSYSTEM`宏。

+   `InitEventSystem`: 调用此函数初始化事件系统。

+   `UnloadEventSystem`: 调用此函数卸载事件系统。

因此，最低要求如下（以下文件保存为`MyUIGameEventSystem.h`）：

```cs
class CMyUIGameEventSystem
  : public IUIGameEventSystem
{
public:
  CMyUIGameEventSystem() {}

  // IUIGameEventSystem
  UIEVENTSYSTEM("MyUIGameEvents");
  virtual void InitEventSystem() {}
  virtual void UnloadEventSystem() {}
  // ~IUIGameEventSystem
};
```

现在我们已经解析了类定义，可以继续进行代码本身。首先创建一个名为`MyUIGameEventSystem.cpp`的新文件。

创建此文件后，使用`REGISTER_UI_EVENTSYSTEM`宏注册事件系统。这用于从`CUIManager`类内部自动创建您的类的实例。

将宏放在 CPP 文件的底部，超出方法范围，如下所示：

```cs
REGISTER_UI_EVENTSYSTEM(CMyUIGameEventSystem);
```

### 注意

请注意，`REGISTER_UI_EVENTSYSTEM`宏仅在 CryGame 项目中有效。

我们的事件系统现在应该编译，并将与 CryGame 中包含的其他事件系统一起创建。

我们的事件系统目前没有任何功能。阅读以下部分以了解如何将函数和事件公开给 UI 流程图。

## 接收事件

事件系统可以公开与我们通过主菜单元素注册的节点相同方式工作的函数。通过公开函数，我们可以允许图形与我们的游戏交互，例如请求玩家健康状况。

首先，我们需要向`CMyUIGameEventSystem`类添加两个新成员：

```cs
SUIEventReceiverDispatcher<CMyUIGameEventSystem> m_eventReceiver;
IUIEventSystem *m_pUIFunctions;
```

事件分发器将负责在流程图中触发其节点时调用函数。

要开始创建函数，请将以下代码添加到类声明中：

```cs
void OnMyUIFunction(int intParameter) 
{
  // Log indicating whether the call was successful
  CryLogAlways("OnMyUIFunction %i", intParameter);
}
```

要注册我们的函数，请在`InitEventSystem`函数中添加以下代码：

```cs
// Create and register the incoming event system
m_pUIFunctions = gEnv->pFlashUI->CreateEventSystem("MyUI", IUIEventSystem::eEST_UI_TO_SYSTEM);
m_eventReceiver.Init(m_pUIFunctions, this, "MyUIGameEvents");

// Register our function
{
  SUIEventDesc eventDesc("MyUIFunction", "description");

  eventDesc.AddParam<SUIParameterDesc::eUIPT_Int>("IntInput", "parameter description");

  m_eventReceiver.RegisterEvent(eventDesc, &CMyUIGameEventSystem::OnMyUIFunction);
}
```

重新编译并重新启动 Sandbox 后，您现在应该能够在流程图编辑器中看到您的节点。

![接收事件](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909_07_21.jpg)

## 分派事件

能够向 UI 图形公开事件非常有用，允许您处理基于事件的 UI 逻辑，例如在用户请求时显示记分牌。

首先，让我们向您的类添加以下代码：

```cs
enum EUIEvent
{
	eUIE_MyUIEvent
};

SUIEventSenderDispatcher<EUIEvent> m_eventSender;
IUIEventSystem *m_pUIEvents;
```

`EUIEvent`枚举包含我们要注册的各种事件，并且作为事件发送方知道您要发送到 UI 系统的事件的一种方式。

现在我们需要在`InitEventSystem`函数中添加一些代码来公开我们的事件，如下所示：

```cs
// Create and register the outgoing event system
m_pUIEvents = gEnv->pFlashUI->CreateEventSystem("MyUI", IUIEventSystem::eEST_SYSTEM_TO_UI);

m_eventSender.Init(m_pUIEvents);

// Register our event
{
	SUIEventDesc eventDesc("OnMyUIEvent", "description");
	eventDesc.AddParam<SUIParameterDesc::eUIPT_String>("String", "String output description");
	m_eventSender.RegisterEvent<eUIE_MyUIEvent>(eventDesc);
}
```

成功重新编译后，**OnMyUIEvent**节点现在应该出现在编辑器中：

![分派事件](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909_07_22.jpg)

### 分派事件

要分派您的 UI 事件，请使用`SUIEventSenderDispatcher::SendEvent`：

```cs
m_eventSender.SendEvent<eUIE_MyUIEvent>("MyStringParam");
```

# 摘要

在本章中，我们学习了在 CryENGINE 中创建用户界面，并利用这些知识创建了自己的主菜单。

您现在已经掌握了实现自己的 UI 和 UI 事件系统所需的基本知识。

如果您更喜欢在进入下一章之前更多地与用户界面一起工作，为什么不扩展我们之前创建的主菜单呢？一个很好的起点可能是实现一个关卡选择屏幕。

在下一章中，我们将介绍创建网络游戏的过程，以实现多人游戏功能。


# 第八章：多人游戏和网络

使用 CryENGINE 网络系统，我们可以从单人游戏转移到创建具有大量人类玩家的生动世界。

在本章中，我们将：

+   学习网络系统的基础知识

+   利用远程方法调用（RMIs）

+   使用方面在网络上序列化流动数据

# 网络系统

CryENGINE 的网络实现是一种灵活的设置，用于与游戏服务器和其他客户端通信。

所有网络消息都是从**独立的网络线程**发送的，以避免网络更新受游戏帧速率的影响。

## 网络标识符

在本地，每个实体都由实体标识符（`entityId`）表示。然而，在网络环境中，将它们传输到网络上是不可行的，因为不能保证它们指向远程客户端或服务器上的相同实体。

为了解决这个问题，每个游戏对象都被分配了一个由`SNetObjectID`结构表示的网络对象标识符，其中包含标识符及其盐的简单包装器。

在编写游戏代码时，将实体和实体 ID 序列化到网络上时，我们不必直接处理`SNetObjectID`结构，因为将`entityId`转换为`SNetObjectID`（并在远程机器上再转换为`entityId`）的过程是自动的。

要确保您的实体 ID 映射到远程机器上的相同实体，请在序列化时使用`eid`压缩策略。在本章后面的*压缩策略*部分中，了解有关策略以及如何使用它们的更多信息。

## 网络通道

CryENGINE 提供了`INetChannel`接口来表示两台机器之间的持续连接。例如，如果客户端 A 和客户端 B 需要相互通信，则在两台机器上都会创建一个网络通道来管理发送和接收的消息。

通过使用通道标识符来引用每个通道，通常可以确定哪个客户端属于哪台机器。例如，要检索连接到特定通道上的玩家角色，我们使用`IActorSystem::GetActorByChannelId`。

### 网络 nubs

所有网络通道都由`INetNub`接口处理，该接口由一个或多个用于基于数据包的通信的端口组成。

# 设置多人游戏

要设置多人游戏，我们需要两台运行相同版本游戏的计算机。

## 启动服务器

有两种方法可以创建远程客户端可以连接的服务器。如下所述：

### 专用服务器

专用服务器存在的目的是有一个不渲染或播放音频的客户端，以便完全专注于支持没有本地客户端的服务器。

要启动专用服务器，请执行以下步骤：

1.  启动`Bin32/DedicatedServer.exe`。

1.  输入`map`，然后输入要加载的级别名称，然后按*Enter*。![专用服务器](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909_08_01.jpg)

### 启动器

还可以通过启动器启动服务器，从而允许您与朋友一起玩而无需启动单独的服务器应用程序。

要通过启动器启动服务器，请按照以下步骤操作：

1.  启动您的启动器应用程序。

1.  打开控制台。

1.  输入`map <level name> s`。

### 注意

在`map`命令后添加`s`将告诉 CryENGINE 以服务器的多人游戏上下文加载级别。省略`s`仍将加载级别，但在单人状态下加载。

![启动器](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909_08_02.jpg)

## 通过控制台连接到服务器

要使用控制台连接到服务器，请使用`connect`命令：

+   `connect <ip> <port>`

### 注意

默认连接端口是 64089。

还可以通过`cl_serveraddr`控制台变量设置 IP 地址，通过`cl_serverport`设置端口，然后简单地调用`connect`。

### 注意

请记住，您可以同时运行多个启动器，这在调试多人游戏时非常有用。

## 调试网络游戏

在调试网络游戏时非常有用的一个控制台变量是`netlog 1`，这将导致网络系统在控制台中记录更多关于网络问题和事件的信息。

# 使用游戏对象扩展进行网络连接

游戏对象有两种通过网络进行通信的方法：RMIs 和通过`Aspects`进行网络序列化。基本上，RMIs 允许基于事件的数据传输，而 Aspect 则在数据失效时连续同步数据。

在能够通过网络通信之前，每个游戏对象都必须使用`IGameObject::BindToNetwork`函数绑定到网络。这可以通过`IGameObjectExtension`的`Init`实现来调用。

## 远程方法调用（RMI）

**远程方法调用**（**RMI**）用于在远程客户端或服务器上调用函数。这对于在网络上同步状态非常有用，例如，让所有客户端知道名为“Dude”的玩家刚刚生成，并且应该移动到特定位置和方向。

### RMI 结构

要声明 RMI，我们可以使用列出的宏：

+   `DECLARE_SERVER_RMI_NOATTACH`

+   `DECLARE_CLIENT_RMI_NOATTACH`

+   `DECLARE_SERVER_RMI_PREATTACH`

+   `DECLARE_CLIENT_RMI_PREATTACH`

+   `DECLARE_SERVER_RMI_POSTATTACH`

+   `DECLARE_CLIENT_RMI_POSTATTACH`

例如：

```cs
DECLARE_CLIENT_RMI_NOATTACH(ClMoveEntity, SMoveEntityParams, eNRT_ReliableUnordered);
```

### 注意

最后一个参数指定数据包的可靠性，但在最新版本的 CryENGINE 中已大部分被弃用。

在创建时要记住你正在暴露哪种类型的 RMI。例如，`DECLARE_CLIENT`仅用于将在远程客户端上调用的函数，而`DECLARE_SERVER`定义了将在服务器上调用的函数，在客户端请求后。

#### 参数

RMI 声明宏需要提供三个参数：

+   **函数名称**：这是确定方法名称的第一个参数，也是在声明函数和调用 RMI 本身时将使用的名称。

+   **RMI 参数**：RMI 必须指定一个包含将与方法一起序列化的所有成员的结构。该结构必须包含一个名为`SerializeWith`的函数，该函数接受一个`TSerialize`参数。

+   **数据包传递可靠性枚举**：这是定义数据包传递可靠性的最后一个参数。

我们刚刚看到的宏之间有三种不同之处：

#### 附加类型

附加类型定义了 RMI 在网络序列化期间何时附加：

+   `NOATTACH`：当 RMI 不依赖游戏对象数据时使用，因此可以在游戏对象数据序列化之前或之后附加。

+   `PREATTACH`：在此类型中，RMI 将在游戏对象数据序列化之前附加。当 RMI 需要准备接收的数据时使用。

+   `POSTATTACH`：在此类型中，RMI 在游戏对象数据序列化后附加。当新接收的数据与 RMI 相关时使用。

#### 服务器/客户端分离

从 RMI 声明宏中可以看出，RMI 不能同时针对客户端和服务器。

因此，我们要么决定哪个目标应该能够运行我们的函数，要么为每个目标创建一个宏。

这是一个非常有用的功能，当处理服务器授权的游戏环境时，由于可以持续区分可以在服务器和客户端上远程触发的函数。

#### 函数定义

要定义 RMI 函数，我们可以使用`IMPLEMENT_RMI`宏：

```cs
  IMPLEMENT_RMI(CGameRules, ClMoveEntity)
  {
  }
```

该宏定义了在调用 RMI 时调用的函数，具有两个参数：

+   `params`：这包含从远程机器发送的反序列化数据。

+   `pNetChannel`：这是一个`INetChannel`实例，描述了源和目标机器之间建立的连接。

### RMI 示例

为了演示如何创建基本的 RMI，我们将创建一个 RMI，允许客户端请求重新定位实体。这将导致服务器向所有客户端发送`ClMoveEntity` RMI，通知它们新实体的情况。

首先，我们需要打开我们的头文件。这是我们将定义 RMI 和我们的参数的地方。首先创建一个名为`SMoveEntityParams`的新结构。

然后我们将添加三个参数：

+   **EntityID entityId**：这是我们想要移动的实体的标识符

+   **Vec3 位置**：这确定了实体应该移动到哪个位置

+   **Quat 方向**：这用于在生成时设置实体的旋转

添加参数后，我们需要在`SMoveEntityParams`结构内定义`SerializeWith`函数。这将在发送数据到网络时调用，然后再次接收数据时调用。

```cs
  void SerializeWith(TSerialize ser)
  {
    ser.Value("entityId", entityId, 'eid');
    ser.Value("position", position, 'wrld');
    ser.Value("orientation", orientation, 'ori0');
  }
```

### 注意

`eid`压缩策略的使用需要特别注意，它确保`entityId`指向相同的实体。有关为什么需要该策略的更多信息，请参阅本章的*网络标识符*部分。

现在我们已经定义了我们的 RMI 参数，我们需要声明两个 RMI：一个用于客户端，一个用于服务器：

```cs
  DECLARE_SERVER_RMI_NOATTACH(SvRequestMoveEntity, SMoveEntityParams, eNRT_ReliableUnordered);

  DECLARE_CLIENT_RMI_NOATTACH(ClMoveEntity, SMoveEntityParams, eNRT_ReliableUnordered);
```

现在我们所要做的就是创建函数实现，我们可以在我们的 CPP 文件中使用`IMPLEMENT_RMI`宏来实现。

```cs
  IMPLEMENT_RMI(CGameRules, SvRequestMoveEntity)
  {
    IEntity *pEntity = gEnv->pEntitySystem->GetEntity(params.entityId);
    if(pEntity == nullptr)
      return true;

    pEntity->SetWorldTM(Matrix34::Create(Vec3(1, 1, 1), params.orientation, params.position));

    GetGameObject()->InvokeRMI(ClMoveEntity(), params, eRMI_ToAllClients | eRMI_NoLocalCalls);

    return true;
  }
```

这段代码定义了我们的`SvRequestMoveEntity`函数，当客户端执行以下操作时将调用该函数：

```cs
  GetGameObject()->InvokeRMI(SvRequestMoveEntity(), params, eRMI_Server);
```

尝试自己实现`ClMoveEntity`函数。它应该以与我们在`SvRequestMoveEntity`中所做的相同方式设置实体的世界变换(`IEntity::SetWorldTM`)。

## 网络方面序列化

游戏对象扩展可以实现`IGameObjectExtension::NetSerialize`函数，该函数用于在网络上序列化与扩展相关的数据。

### 方面

为了允许特定机制相关数据的分离，网络序列化过程公开了**方面**。当服务器或客户端将方面声明为“脏”（更改）时，网络将触发序列化并调用具体方面的`NetSerialize`函数。

要将您的方面标记为脏，请调用`IGameObject::ChangedNetworkState`：

```cs
  GetGameObject()->ChangedNetworkState(eEA_GameClientF);
```

这将触发`NetSerialize`来序列化您的方面，并将其数据发送到远程机器，然后在同一函数中对其进行反序列化。

### 注意

当方面的值与上次发送到远程客户端或服务器的值不同时，该方面被认为是“脏”。

例如，如果我们想序列化与玩家输入相关的一组标志，我们将创建一个新的方面，并在客户端的输入标志发生变化时将其标记为脏：

```cs
  bool CMyGameObjectExtension::NetSerialize(TSerialize ser, EEntityAspects aspect, uint8 profile, int flags)
  {
    switch(aspect)
    {
      case eEA_GameClientF:
        {
          ser.EnumValue("inputFlags", (EInputFlags &)m_inputFlags, EInputFlag_First, EInputFlag_Last);
        }
        break;
    }
  }
```

### 注意

`TSerialize::EnumValue`是`TSerialize::Value`的一种特殊形式，它计算枚举的最小值和最大值，有效地充当动态压缩策略。

`EnumValue`和压缩策略应尽可能使用，以减少带宽使用。

现在，当客户端上的`eEA_GameClientF`方面被标记为脏时，将调用`NetSerialize`函数，并将`m_inputFlags`变量值写入网络。

当数据到达远程客户端或服务器时，`NetSerialize`函数将再次被调用，但这次将值写入`m_inputFlags`变量，以便服务器知道客户端提供的新输入标志。

### 注意

方面不支持条件序列化，因此每个方面在每次运行时都必须序列化相同的变量。例如，如果在第一个方面序列化了四个浮点数，那么你将始终需要序列化四个浮点数。

仍然可以序列化复杂对象，例如，我们可以写入数组的长度，然后迭代读取/写入数组中包含的每个对象。

## 压缩策略

`TSerialize::Value`使能够传递一个额外的参数，即压缩策略。此策略用于确定在同步数据时可以使用哪些压缩机制来优化网络带宽。

压缩策略定义在`Scripts/Network/CompressionPolicy.xml`中。现有策略的示例如下：

+   `eid`：这用于在网络上序列化`entityId`标识符，并将游戏对象的`SNetObjectID`与远程客户端上的正确`entityId`进行比较。

+   `wrld`：这在序列化代表世界坐标的`Vec3`结构时使用。由于默认情况下被限制在 4095，这可能需要针对更大的级别进行调整。

+   `colr`：这用于在网络上序列化`ColorF`结构，允许浮点变量表示 0 到 1 之间的值。

+   `bool`：这是布尔值的特定实现，并且可以减少大量冗余数据。

+   `ori1`：这用于在网络上序列化`Quat`结构，用于玩家方向。

### 创建一个新的压缩策略

添加新的压缩策略就像修改`CompressionPolicy.xml`一样简单。例如，如果我们想要创建一个新的 Vec3 策略，其中 X 和 Y 轴只能达到 2048 米，而 Z 轴限制为 1024 米：

```cs
<Policy name="wrld2" impl="QuantizedVec3">
  <XParams min="0" max="2047.0" nbits="24"/>
  YParams min="0" max="2047.0" nbits="24"/>
  <ZParams min="0" max="1023.0" nbits="24"/>
</Policy>
```

# 将 Lua 实体暴露给网络

现在我们知道如何在 C++中处理网络通信，让我们看看如何将 Lua 实体暴露给网络。

## Net.Expose

为了定义 RMIs 和服务器属性，我们需要在`.lua`脚本的全局范围内调用`Net.Expose`：

```cs
Net.Expose({
  Class = MyEntity,
  ClientMethods = {
    ClRevive             = { RELIABLE_ORDERED, POST_ATTACH, ENTITYID, },
  },
  ServerMethods = {
    SvRequestRevive          = { RELIABLE_UNORDERED, POST_ATTACH, ENTITYID, },
  },
  ServerProperties = {
  },
});
```

前一个函数将定义`ClRevive`和`SvRequestRevive` RMIs，可以通过使用为实体自动创建的三个子表来调用：

+   `allClients`

+   `otherClients`

+   `server`

### 函数实现

远程函数定义在实体脚本的`Client`或`Server`子表中，以便网络系统可以快速找到它们，同时避免名称冲突。

例如，查看以下`SvRequestRevive`函数：

```cs
  function MyEntity.Server:SvRequestRevive(playerEntityId)
  end
```

### 调用 RMIs

在服务器上，我们可以触发`ClRevive`函数，以及我们之前定义的参数，对所有远程客户端进行触发。

#### 在服务器上

要在服务器上调用我们的`SvRequestRevive`函数，只需使用：

```cs
  self.server:SvRequestRevive(playerEntityId);
```

#### 在所有客户端

如果您希望所有客户端都收到`ClRevive`调用：

```cs
  self.allClients:ClRevive(playerEntityId);
```

#### 在所有其他客户端上

将`ClRevive`调用发送到除当前客户端之外的所有客户端：

```cs
  self.otherClients:ClRevive(playerEntityId);
```

## 将我们的实体绑定到网络

在能够发送和接收 RMI 之前，我们必须将我们的实体绑定到网络。这是通过为我们的实体创建一个游戏对象来完成的：

```cs
  CryAction.CreateGameObjectForEntity(self.id);
```

我们的实体现在将拥有一个功能性的游戏对象，但尚未设置为网络使用。要启用此功能，请调用`CryAction.BindGameObjectToNetwork`函数：

```cs
  CryAction.BindGameObjectToNetwork(self.id);
```

完成！我们的实体现在已绑定到网络，并且可以发送和接收 RMI。请注意，这应该在实体生成后立即进行。

# 总结

在本章中，我们已经学习了 CryENGINE 实例如何在网络上远程通信，并且还创建了我们自己的 RMI 函数。

现在您应该了解网络方面和压缩策略函数，并且对如何将实体暴露给网络有基本的了解。

如果您想在进入下一章之前继续进行多人游戏和网络游戏，为什么不创建一个基本的多人游戏示例，其中玩家可以向服务器发送生成请求，结果是玩家在所有远程客户端上生成？

在下一章中，我们将介绍物理系统以及如何利用它。
