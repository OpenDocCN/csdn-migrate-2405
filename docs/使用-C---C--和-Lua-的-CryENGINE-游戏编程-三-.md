# 使用 C++、C# 和 Lua 的 CryENGINE 游戏编程（三）

> 原文：[`zh.annas-archive.org/md5/9DE4C1E310A0B5A13812B9CEED44823A`](https://zh.annas-archive.org/md5/9DE4C1E310A0B5A13812B9CEED44823A)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第九章：物理编程

CryENGINE 物理系统是一个可扩展的物理实现，允许创建真正动态的世界。开发人员将发现，在实现物理模拟时有很大的灵活性。

在本章中，我们将：

+   了解物理系统的工作原理

+   发现如何调试我们的物理化几何体

+   学习如何进行射线投射和相交基元，以发现接触点、地面法线等

+   创建我们自己的物理化实体

+   通过模拟爆炸使事物爆炸

# CryPhysics

物理实体系统围绕物理实体的概念而设计，可以通过`IPhysicalEntity`接口访问。物理实体代表具有物理代理的几何体，可以影响和受到交叉、碰撞和其他事件的影响。

虽然可以通过`IPhysicalWorld::CreatePhysicalEntity`函数创建没有基础实体（`IEntity`）的物理实体，但通常会调用`IEntity::Physicalize`以启用当前由实体加载的模型的物理代理。

### 注意

物理代理是渲染网格的简化模型。这用于减少物理系统的负担。

当调用`IEntity::Physicalize`时，将创建一个新的实体代理，通过调用`IPhysicalWorld::CreatePhysicalEntity`来处理其物理化表示。CryENGINE 允许创建多种物理实体类型，具体取决于物理化对象的目的。

## 物理化实体类型

以下是 CryENGINE 当前实现的物理化实体类型：

+   **PE_NONE**：当实体不应物理化时使用，或者当我们想要去物理化时传递给`IEntity::Physicalize`。在未物理化时，实体将没有物理代理，因此无法与其他对象进行物理交互。

+   **PE_STATIC**：这告诉物理系统利用实体的物理代理，但永远不允许通过物理交互移动或旋转它。

+   **PE_RIGID**：将刚体类型应用于对象，允许外部对象发生碰撞并移动目标。

+   **PE_WHEELEDVEHICLE**：用于车辆的专用类型。

+   **PE_LIVING**：用于生物演员，例如需要地面对齐和地面接触查询的人类。

+   **PE_PARTICLE**：这是基于`SEntityPhysicalizeParams`中传递的粒子进行物理化的，对于避免快速移动物体（如抛射物）的问题非常有用。

+   **PE_ARTICULATED**：用于由几个刚体通过关节连接的关节结构，例如布娃娃。

+   **PE_ROPE**：用于创建可以将两个物理实体绑在一起或自由悬挂的物理化绳索对象。也用于 Sandbox 绳索工具。

+   **PE_SOFT**：这是一组连接的顶点，可以与环境进行交互，例如布料。

## 引入物理实体标识符

所有物理实体都被分配唯一的标识符，可以通过`IPhysicalWorld::GetPhysicalEntityId`检索，并用于通过`IPhysicalWorld::GetPhysicalEntityById`获取物理实体。

### 注意

物理实体 ID 被序列化为一种将数据与特定物理实体关联的方式，因此在重新加载时应保持一致。

### 绘制实体代理

我们可以利用`p_draw_helpers` CVar 来获得关卡中各种物理化对象的视觉反馈。

要绘制所有物理化对象，只需将 CVar 设置为 1。

![绘制实体代理](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909_09_01.jpg)

对于更复杂的用法，请使用`p_draw_helpers [Entity_Types]_[Helper_Types]`。

例如，要绘制地形代理几何：

```cs
  p_draw_helpers t_g
```

![绘制实体代理](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909_09_02.jpg)

#### 实体类型

以下是实体类型的列表：

+   **t**：这显示地形

+   **s**：这显示静态实体

+   **r**：这显示休眠刚体

+   **R**：这显示活动刚体

+   **l**：这显示生物实体

+   **i**：这显示独立实体

+   **g**：这显示触发器

+   **a**：这显示区域

+   **y**：这显示`RayWorldIntersection`射线

+   **e**：这显示爆炸遮挡地图

#### 辅助类型

以下是辅助类型列表：

+   **g**：这显示几何体

+   **c**：这显示接触点

+   **b**：这显示边界框

+   **l**：这显示可破碎物体的四面体晶格

+   **j**：这显示结构关节（将在主几何体上强制半透明）

+   **t(#)**：这显示直到级别#的边界体积树

+   **f(#)**：这只显示设置了此位标志的几何体（多个 f 叠加）

# 物理实体动作、参数和状态

`IPhysicalEntity`接口提供了三种改变和获取实体物理状态的方法：

## 参数

物理实体参数确定几何体的物理表示应在世界中如何行为。可以通过`IPhysicalEntity::GetParams`函数检索参数，并通过使用`IPhysicalEntity::SetParams`设置。

所有参数都作为从`pe_params`派生的结构传递。例如，要修改实体受到的重力，我们可以使用`pe_simulation_params`：

```cs
  pe_simulation_params simParams;

  simParams.gravity = Vec3(0, 0, -9.81f);
  GetEntity()->GetPhysics()->SetParams(&simParams);
```

此代码将更改应用于实体的重力加速度为-9.81f。

### 注意

大多数物理实体参数结构的默认构造函数标记某些数据为未使用；这样我们就不必担心覆盖我们未设置的参数。

## 动作

与参数类似，动作允许开发人员强制执行某些物理事件，例如脉冲或重置实体速度。

所有动作都源自`pe_action`结构，并可以通过`IPhysicalEntity::Action`函数应用。

例如，要对我们的实体施加一个简单的冲量，将其发射到空中，请使用：

```cs
  pe_action_impulse impulseAction;
  impulseAction.impulse = Vec3(0, 0, 10);

  GetEntity()->GetPhysics()->Action(&impulseAction);
```

## 状态

还可以从实体获取各种状态数据，例如确定其质心位置或获取其速度。

所有状态都源自`pe_status`结构，并可以通过`IPhysicalEntity::GetStatus`函数检索。

例如，要获取玩家等生物实体的速度，请使用：

```cs
  pe_status_living livStat;
  GetEntity()->GetPhysics()->GetStatus(&livStat);

  Vec3 velocity = livStat.vel;
```

# 物理化实体类型详细信息

默认物理化实体实现有许多参数、动作和状态。我们列出了它们最常用的类型的一些选择：

## 常见参数

+   **pe_params_pos**：用于设置物理实体的位置和方向。

+   **pe_params_bbox**：这允许将实体的边界框强制为特定值，或在与`GetParams`一起使用时查询它，以及查询交集。

+   **pe_params_outer_entity**：这允许指定外部物理实体。如果在其边界框内发生碰撞，则将忽略与外部实体的碰撞。

+   **pe_simulation_params**：为兼容实体设置模拟参数。

## 常见动作

+   **pe_action_impulse**：这对实体施加一次性冲量。

+   **pe_action_add_constraint**：用于在两个物理实体之间添加约束。例如，可以使用忽略约束使幽灵穿过墙壁。

+   **pe_action_set_velocity**：用于强制物理实体的速度。

## 常见状态

+   **pe_status_pos**：请求实体或实体部分的当前变换

+   **pe_status_dynamics**：用于获取实体运动统计数据，如加速度、角加速度和速度

# 静态

将实体物理化为静态类型会创建基本物理化实体类型，从中派生所有扩展，如刚性或生物。

静态实体是物理化的，但不会移动。例如，如果将球扔向静态物体，它将在不移动目标物体的情况下反弹回来。

# 刚性

这指的是基本的物理实体，当受到外部力的影响时可以在世界中移动。

如果我们使用相同的先前示例，向刚性物体投掷球将导致刚性物体被推开

# 轮式车辆

这代表了一个轮式车辆，简单地说，实现是一个刚体，具有车轮、刹车和 CryENGINE 等车辆功能。

## 独特参数

+   **pe_params_car**：用于获取或设置特定于车辆的参数，例如 CryENGINE 功率、RPM 和齿轮数

+   **pe_params_wheel**：用于获取或设置车辆车轮的特定参数，例如摩擦、表面 ID 和阻尼

## 独特状态

+   **pe_status_vehicle**：用于获取车辆统计信息，允许获取速度、当前档位等

+   **pe_status_wheel**：获取特定车轮的状态，例如接触法线、扭矩和表面 ID

+   **pe_status_vehicle_abilities**：这允许检查特定转弯的最大可能速度

## 独特动作

+   **pe_action_drive**：用于车辆事件，如刹车、踏板和换挡。

# 生物

生物实体实现是处理演员及其移动请求的专门设置。

生物实体有两种状态：在地面上和在空中。在地面上，玩家将被“粘”在地面上，直到尝试将其与地面分离（通过施加远离地面的显著速度）。

### 注意

还记得来自第五章*创建自定义演员*的动画角色移动请求吗？该系统在核心中使用生物实体`pe_action_move`请求。

## 独特参数

+   **pe_player_dimensions**：用于设置与生物实体的静态属性相关的参数，例如 sizeCollider，以及是否应该使用胶囊或圆柱体作为碰撞几何体

+   **pe_player_dynamics**：用于设置与生物实体相关的动态参数，例如惯性、重力和质量

## 独特状态

+   **pe_status_living**：获取当前生物实体状态，包括飞行时间、速度和地面法线等统计信息

+   **pe_status_check_stance**：用于检查新尺寸是否引起碰撞。参数的含义与 pe_player_dimensions 中的相同

## 独特动作

+   **pe_action_move**：用于提交实体的移动请求。

# 粒子

还可以使用对象的粒子表示。这通常用于应该以高速移动的对象，例如抛射物。基本上，这意味着我们实体的物理表示只是一个二维平面。

## 独特参数

+   **pe_params_particle**：用于设置特定于粒子的参数

# 关节

关节结构由几个刚体通过关节连接而成，例如布娃娃。这种方法允许设置撕裂限制等。

## 独特参数

+   **pe_params_joint**：用于在设置时在两个刚体之间创建关节，并在与`GetParams`一起使用时查询现有关节。

+   **pe_params_articulated_body**：用于设置特定于关节类型的参数。

# 绳索

当您想要创建将多个物理化对象绑在一起的绳索时，应该使用绳索。该系统允许绳索附着到动态或静态表面。

## 独特参数

+   **pe_params_rope**：用于更改或获取物理绳索参数

# 软

软是一种非刚性连接的顶点系统，可以与环境进行交互，例如布料物体。

## 独特参数

+   **pe_params_softbody**：用于配置物理软体

## 独特动作

+   **pe_action_attach_points**：用于将软实体的一些顶点附加到另一个物理实体

# 射线世界交叉

使用`IPhysicalWorld::RayWorldIntersection`函数，我们可以从世界的一个点向另一个点投射射线，以检测到特定对象的距离、表面类型、地面的法线等。

`RayWorldIntersection`很容易使用，我们可以证明它！首先，看一个射线投射的例子：

```cs
  ray_hit hit;

  Vec3 origin = pEntity->GetWorldPos();
  Vec3 dir = Vec3(0, 0, -1);

  int numHits = gEnv->pPhysicalWorld->RayWorldIntersection(origin, dir, ent_static | ent_terrain, rwi_stop_at_pierceable | rwi_colltype_any, &hit, 1);
  if(numHits > 0)
  {
    // Hit something!
  }
```

## ray_hit 结构

我们将`ray_hit hit`变量的引用传递给`RayWorldIntersection`，这是我们将能够检索有关射线命中的所有信息的地方。

### 常用的成员变量

+   **float dist**：这是从原点（在我们的例子中是实体的位置）到射线命中位置的距离。

+   **IPhysicalEntity *pCollider**：这是指向我们的射线碰撞的物理实体的指针。

+   **short surface_idx**：这是我们的射线碰撞的材料表面类型的表面标识符（请参见`IMaterialManager::GetSurfaceType`以获取其`ISurfaceType`指针）。

+   **Vec3 pt**：这是接触点的世界坐标。

+   **Vec3 n**：这是接触点的表面法线。

+   **ray_hit *next**：如果我们的射线多次命中，这将指向下一个`ray_hit`结构。有关更多信息，请参阅*允许多次射线命中*部分。

## 起点和方向

`RayWorldIntersection`函数的第一个和第二个参数定义了射线应该从哪里投射，以及在特定方向上的距离。

在我们的例子中，我们从实体的当前位置向下移动一个单位来发射射线。

## 对象类型和射线标志

请注意，在`dir`之后，我们向`RayWorldIntersection`函数传递了两种类型的标志。这些标志指示射线应该如何与对象相交，以及要忽略哪些碰撞。

### 对象类型

对象类型参数需要基于`entity_query_flags`枚举的标志，并用于确定我们希望允许射线与哪种类型的对象发生碰撞。如果射线与我们未定义的对象类型发生碰撞，它将简单地忽略并穿过。

+   **ent_static**：这指的是静态对象

+   **ent_sleeping_rigid**：这表示睡眠刚体

+   **ent_rigid**：这表示活动刚体

+   **ent_living**：这指的是生物体，例如玩家

+   **ent_independent**：这表示独立对象

+   **ent_terrain**：这表示地形

+   **ent_all**：这指的是所有类型的对象

### 射线标志

射线标志参数基于`rwi_flags`枚举，并用于确定投射应该如何行为。

## 允许多次射线命中

正如前面提到的，也可以允许射线多次命中对象。为此，我们只需创建一个`ray_hit`数组，并将其与命中次数一起传递给`RayWorldIntersection`函数：

```cs
  const int maxHits = 10;

  ray_hit rayHits[maxHits];
  int numHits = gEnv->pPhysicalWorld->RayWorldIntersection(origin, direction, ent_all, rwi_stop_at_pierceable, rayHits, maxHits);

  for(int i = 0; i < numHits; i++)
  {
    ray_hit *pRayHit = &rayHits[i];

// Process ray
  }
```

# 创建一个物理实体

现在我们知道了物理系统是如何工作的，我们可以创建自己的物理实体，可以与场景中的其他物理几何体发生碰撞：

### 注意

本节假设您已阅读了第三章，*创建和使用自定义实体*。

## 在 C++

根据我们之前学到的，我们知道可以通过`PE_STATIC`类型来使静态实体物理化：

```cs
  SEntityPhysicalizeParams physicalizeParams;
  physicalizeParams.type = PE_STATIC;

  pEntity->Physicalize(physicalizeParams);
```

假设在调用`IEntity::Physicalize`之前已为实体加载了几何体，现在其他物理化的对象将能够与我们的实体发生碰撞。

但是如果我们想要允许碰撞来移动我们的物体呢？这就是`PE_RIGID`类型发挥作用的地方：

```cs
  SEntityPhysicalizeParams physicalizeParams;
  physicalizeParams.type = PE_RIGID;
  physicalizeParams.mass = 10;

  pEntity->Physicalize(physicalizeParams);
```

现在，CryENGINE 将知道我们的对象重 10 千克，并且在与另一个物理化实体发生碰撞时将被移动。

## 在 C#

我们还可以在 C#中使用`EntityBase.Physicalize`函数以及`PhysicalizationParams`结构来做到这一点。例如，如果我们想要给一个静态对象添加物理属性，我们可以使用以下代码：

```cs
  var physType = PhysicalizationType.Static;
  var physParams = new PhysicalizationParams(physType);

  Physicalize(physParams);
```

当然，这假设通过`EntityBase.LoadObject`方法加载了一个对象。

现在，如果我们想要创建一个刚性实体，我们可以使用：

```cs
  var physType = PhysicalizationType.Rigid;

  var physParams = new PhysicalizationParams(physType);
  physParams.mass = 50;

  Physicalize(physParams);
```

我们的实体现在重 50 公斤，当与其他物理化的物体发生碰撞时可以移动。

# 模拟爆炸

我们知道你在想，“如果我们不能炸毁东西，所有这些物理知识有什么用？”，我们已经为你准备好了！

物理世界实现提供了一个简单的函数，用于在世界中模拟爆炸，具有广泛的参数范围，允许自定义爆炸区域。

为了演示，我们将创建一个最大半径为 100 的爆炸：

```cs
  pe_explosion explosion;
  explosion.rmax = 100;

  gEnv->pPhysicalWorld->SimulateExplosion(&explosion);
```

### 注意

`SimulateExplosion`函数仅仅模拟爆炸并产生一个推动实体远离的力，不会产生任何粒子效果。

# 总结

在本章中，我们已经学习了物理世界实现的基本工作原理，以及如何在视觉上调试物理代理。

有了你的新知识，你应该知道如何使用射线世界交叉点来收集关于周围游戏世界的信息。哦，我们已经炸毁了一些东西。

如果你觉得还不准备好继续前进，为什么不创建一个扩展的物理实体或物理修改器，比如重力枪或蹦床呢？

在下一章中，我们将涵盖渲染管线，包括如何编写自定义着色器，以及如何在运行时修改材质。


# 第十章：渲染编程

CryENGINE 渲染器很可能是引擎中最著名的部分，为 PC、Xbox 360 和 PlayStation 3 等平台提供高度复杂的图形功能和出色的性能。

在本章中，我们将涵盖以下主题：

+   学习渲染器的基本工作原理

+   了解每一帧如何渲染到世界中

+   学习着色器编写的基础知识

+   学习如何在运行时修改静态对象

+   在运行时修改材质

# 渲染器细节

CryENGINE 渲染器是一个模块化系统，允许绘制复杂的场景，处理着色器等。

为了方便不同的平台架构，CryENGINE 存在多个渲染器，都实现了**IRenderer**接口。我们列出了一些选择，如下所示：

+   DirectX：用于 Windows 和 Xbox

+   PSGL：用于 PlayStation 3

很可能也正在开发**OpenGL**渲染器，用于 Linux 和 Mac OS X 等平台。

## 着色器

CryENGINE 中的着色器是使用基于 HLSL 的专门语言 CryFX 编写的。该系统与 HLSL 非常相似，但专门用于核心引擎功能，如材质和着色器参数，`#include`宏等。

### 注意

请注意，本书撰写时，Free SDK 中未启用着色器编写；但这在未来可能会改变。

### 着色器排列组合

每当材质改变着色器生成参数时，基本着色器的一个排列组合将被创建。引擎还公开了将引擎变量暴露给着色器的功能，以便在运行时禁用或调整效果。

这是由于 CryFX 语言允许`#ifdef`、`#endif`和`#include`块，允许引擎在运行时剥离着色器代码的某些部分。

![着色器排列组合](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909_10_01.jpg)

### 着色器缓存

由于在运行时编译着色器在所有平台上都不可行，CryENGINE 提供了着色器缓存系统。这允许存储一系列预编译的着色器，为最终用户的设备节省了相当多的工作。

### 注意

如前一节所述，着色器可以包含大量的变体。因此，在设置缓存时，有必要确保所有所需的排列组合都已经编译。

#### PAK 文件

渲染器可以从`Engine`文件夹加载四个`.pak`文件，包含着色器定义、源文件等。

| 存档名称 | 描述 |
| --- | --- |
| `Shaders.pak` | 包含着色器源文件和`.ext`（定义）文件。在使用预编译着色器缓存时，着色器源通常被排除在此存档之外。 |
| `ShadersBin.pak` | 包含着色器源代码的二进制解析信息。 |
| `ShaderCache.pak` | 包含所有已编译的着色器；仅在当前级别的着色器缓存中找不到着色器时使用。 |
| `ShaderCacheStartup.pak` | 在启动时加载以加快启动时间；应该只包含主菜单所需的着色器。 |

# 渲染节点

提供**IRenderNode**接口，以便为 Cry3DEngine 系统提供管理对象的方法。

这允许生成对象可见性层次结构（允许轻松地剔除当前未见的对象）和对象的渲染。

# 渲染分解

游戏的渲染分为两个步骤：

1.  预更新

1.  后更新

## 预更新

渲染每一帧到场景的初始步骤发生在`IGameFramework::PreUpdate`函数中。预更新负责更新大多数游戏系统（如流程图、视图系统等），并首次调用`ISystem::RenderBegin`。

### 注意

`PreUpdate`最常从`CGame::Update`中调用，在原始的`CryGame.dll`中。请记住，这个过程只适用于启动器应用程序；编辑器处理游戏更新和渲染的方式是独特的。

RenderBegin 表示新帧的开始，并告诉渲染器设置新的帧 ID，清除缓冲区等。

## 更新后

更新游戏系统后，是时候渲染场景了。这一初始步骤通过`IGameFramework::PostUpdate`函数完成。

在渲染之前，必须更新对游戏更新中和之后从新信息中检索到的关键系统。这包括闪烁 UI、动画同步等。

完成后，`PostUpdate`将调用`ISystem::Render`，然后使用`I3DEngine::RenderWorld`函数渲染世界。

渲染世界后，系统将调用诸如`IFlashUI::Update`和`PostUpdate`等函数，最终以调用`ISystem::RenderEnd`结束。

![更新后](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909_10_02.jpg)

# 使用渲染上下文渲染新视口

渲染上下文本质上是本机窗口句柄的包装器。在 Windows 上，这允许您指定一个**HWND**，然后让渲染器直接绘制到它上面。

渲染上下文的本质是特定于平台的，因此不能保证在一个渲染模块（如 D3D）到另一个渲染模块（如 OpenGL）之间的工作方式相同。

### 注意

注意：渲染上下文目前仅在 Windows 的编辑器模式下受支持，用于在工具窗口中渲染视口。

为了使用您的窗口句柄创建新的上下文，请调用`IRenderer::CreateContext`。

### 注意

请注意，上下文在创建时会自动启用；调用`IRenderer::MakeMainContextActive`来重新启用主视图。

## 渲染

在渲染上下文时，你需要做的第一件事是激活它。这可以通过使用`IRenderer::SetCurrentContext`来完成。一旦启用，渲染器就会意识到应该传递给 DirectX 的窗口。

接下来你需要做的是使用`IRenderer::ChangeViewport`来更新上下文的分辨率。这指示渲染器关于应该渲染的区域的位置和大小。

这样做后，只需调用典型的渲染函数，如`IRenderer::BeginFrame`（参见*渲染分解*部分），最后通过`IRenderer::MakeMainContextActive`使主上下文在最后处于活动状态。

### 使用 I3DEngine::RenderWorld 函数

在某些情况下，手动调用`I3DEngine::RenderWorld`而不是依赖游戏框架的更新过程可能是有意义的。

为此，我们需要稍微改变流程。首先，调用`IRenderer::SetCurrentContext`，然后调用`IRenderer::MakeMainContextActive`如下所示：

```cs
gEnv->pRenderer->SetCurrentContext(hWnd);
// Restore context
gEnv->pRenderer->MakeMainContextActive();
```

很好，现在我们的上下文将被激活。但为了实际渲染，我们需要填补之间的空白。首先，我们必须在`SetCurrentContext`之后直接调用`IRenderer::ChangeViewport`如下所示：

```cs
gEnv->pRenderer->ChangeViewport(0, 0, width, height, true);
```

这将视口设置为`0`、`0`的坐标和我们指定的`width`和`height`变量。

设置视口大小后，您将需要根据新的分辨率配置您的摄像机，并调用`IRenderer::SetCamera`如下所示：

```cs
CCamera camera;
// Set frustrum based on width, height and field of view (60)
camera.SetFrustum(width, height, DEG2RAD(60));
// Set camera scale, orientation and position.
Vec3 scale(1, 1, 1);
Quat rotation = Quat::CreateRotationXYZ(Ang3(DEG2RAD(-45), 0, 0));
Vec3 position(0, 0, 0);
camera.SetMatrix(Matrix34::Create(scale, rotation, position));
gEnv->pRenderer->SetCamera(m_camera);
```

太好了！渲染器现在知道应该使用哪个摄像机进行渲染。我们还需要在稍后提供给`I3DEngine::RenderWorld`。但首先我们必须清除缓冲区，以删除之前的帧，使用以下代码：

```cs
// Set clear color to pure black
ColorF clearColor(0.f)

gEnv->pRenderer->SetClearColor(Vec3(clearColor.r, clearColor.g, clearColor.b));
gEnv->pRenderer->ClearBuffer(FRT_CLEAR, &clearColor);
```

然后调用`IRenderer::RenderBegin`来指示开始渲染：

```cs
gEnv->pSystem->RenderBegin();
gEnv->pSystem->SetViewCamera(m_camera);

// Insert rendering here

gEnv->pSystem->RenderEnd();
```

现在我们所要做的就是在`SetViewCamera`和`RenderEnd`调用之间渲染场景：

```cs
gEnv->pRenderer->SetViewport(0, 0, width, height);
gEnv->p3DEngine->Update();

int renderFlags = SHDF_ALLOW_AO | SHDF_ALLOWPOSTPROCESS | SHDF_ALLOW_WATER | SHDF_ALLOWHDR | SHDF_ZPASS;

gEnv->p3DEngine->RenderWorld(renderFlags, &camera, 1, __FUNCTION__);
```

完成！世界现在根据我们的摄像机设置进行渲染，并应该在通过`IRenderer::SetCurrentContext`设置的窗口中可见。

#### I3DEngine::RenderWorld 标志

渲染标志确定如何绘制世界。例如，我们可以排除`SHDF_ALLOW_WATER`来完全避免渲染水。下表列出了可用标志及其功能：

| 标志名称 | 描述 |
| --- | --- |
| `SHDF_ALLOWHDR` | 如果未设置，将不使用 HDR。 |
| `SHDF_ZPASS` | 允许 Z-Pass。 |
| `SHDF_ZPASS_ONLY` | 允许 Z-Pass，而不允许其他通道。 |
| `SHDF_DO_NOT_CLEAR_Z_BUFFER` | 如果设置，Z 缓冲区将永远不会被清除。 |
| `SHDF_ALLOWPOSTPROCESS` | 如果未设置，所有后期处理效果将被忽略。 |
| `SHDF_ALLOW_AO` | 如果设置，将使用**环境光遮蔽**。 |
| `SHDF_ALLOW_WATER` | 如果未设置，所有水体将被忽略并且不会渲染。 |
| `SHDF_NOASYNC` | 无异步绘制。 |
| `SHDF_NO_DRAWNEAR` | 排除所有在近平面的渲染。 |
| `SHDF_STREAM_SYNC` | 启用同步纹理流式传输。 |
| `SHDF_NO_DRAWCAUSTICS` | 如果设置，将不绘制水光。 |

# 着色器

在 CryENGINE 中创建自定义着色器相对容易，只需通过复制现有着色器（`.cfx`）及其扩展文件（`.ext`）即可完成。举例来说，从`Engine/Shaders`复制`Illum.ext`并命名为`MyShader.ext`。然后复制`Engine/Shaders/HWScripts/CryFX/Illum.cfx`并将其重命名为`MyShader.cfx`。

请注意，创建自定义着色器应该经过深思熟虑；如果可能的话，最好使用现有的着色器。这是因为 CryENGINE 已经接近着色器排列的可行极限。

### 注意

正如本章前面所述，本书撰写时，CryENGINE Free SDK 中未启用自定义着色器编写。

## 着色器描述

每个着色器都需要定义一个描述，以设置其选项。选项设置在全局`Script`变量中，如下面的代码所示：

```cs
float Script : STANDARDSGLOBAL
<
  string Script =        
           "Public;"
           "SupportsDeferredShading;"
           "SupportsAttrInstancing;"
           "ShaderDrawType = Light;"
           "ShaderType = General;"
>;
```

## 纹理插槽

每个材质可以在一组纹理插槽中指定纹理的文件路径，如下所示：

![纹理插槽](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909_10_03.jpg)

我们可以通过使用一组助手（如下所示）在着色器中访问这些纹理插槽，然后将其添加到自定义采样器中，然后可以使用`GetTexture2D`函数加载它们。

| 插槽名称 | 助手名称 |
| --- | --- |
| 扩散 | $扩散 |
| 光泽（高光） | $光泽 |
| 凹凸 |   |
| 凹凸高度图 | $凹凸高度 |
| 环境 | $环境 |
| 环境立方体贴图 | $环境立方体贴图 |
| 细节 | $细节 |
| 不透明度 | $不透明度 |
| 贴花 | $贴花叠加 |
| 次表面 | $次表面 |
| 自定义 | $自定义贴图 |
| 自定义次要 | $自定义次要贴图 |

## 着色器标志

通过使用`#ifdef`和`#endif`预处理器命令，可以定义在编译或运行时可以删除的代码区域。这允许使用单个超级着色器具有多个可切换的子效果，如 Illum。

例如，我们可以通过以下方式检查用户是否正在运行 DX11：

```cs
#if D3D11
// Include DX11 specific shader code here
#endif
```

### 材质标志

材质标志是通过**材质编辑器**设置的，允许每个材质使用不同的效果，如视差遮挡映射和镶嵌。材质标志在编译时进行评估。

要创建新的材质标志，请打开您的着色器的`.ext`文件，并使用以下代码创建一个新的属性：

```cs
Property
{
  Name = %MYPROPERTY
  Mask = 0x160000000
  Property    (My Property)
  Description (My property is a very good property)
}
```

现在当您重新启动编辑器时，您的属性应该出现在材质编辑器中。

以下是可能的属性数据列表：

| 属性数据 | 描述 |
| --- | --- |
| 名称 | 定义属性的内部名称，并且是您应该通过使用`#ifdef`块进行检查的名称。 |
| 掩码 | 用于识别您的属性的唯一掩码。不应与着色器定义（`.ext`）中其他属性的掩码冲突。 |
| 属性 | 属性的公共名称，在材质编辑器中显示。 |
| 描述 | 在材质编辑器中悬停在属性上时显示的公共描述。 |
| 依赖设置 | 当用户修改纹理插槽的值时，该属性被设置，材质标志将被激活。这在与隐藏标志结合使用时最常见。 |
| 依赖重置 | 当用户修改纹理插槽的值时，将清除该属性。用于避免与其他材质标志冲突。 |
| 隐藏 | 如果设置，属性将在编辑器中不可见。 |

### 引擎标志

引擎标志由引擎直接设置，并包含诸如当前支持的着色器模型或引擎当前运行的平台等信息。

### 运行时标志

运行时标志由`%_RT_`前缀定义，并且可以由引擎在运行时设置或取消设置。所有可用标志都可以在`RunTime.ext`文件中查看。

## 采样器

采样器是特定纹理类型的单个纹理的表示。通过创建自定义采样器，我们可以在着色器内引用特定纹理，例如加载包含预生成噪音的纹理。

预加载采样器的一个示例如下所示：

```cs
sampler2D mySampler = sampler_state
{
  Texture = EngineAssets/Textures/myTexture.dds;
  MinFilter = LINEAR;
  MagFilter = LINEAR;
  MipFilter = LINEAR;
  AddressU = Wrap;
  AddressV = Wrap;
  AddressW = Wrap;
}
```

我们现在可以在我们的代码中引用`mySampler`。

### 使用采样器的纹理槽

在某些情况下，最好让采样器指向材质中定义的纹理槽之一。

为此，只需用您首选的纹理槽的名称替换纹理的路径：

```cs
sampler2D mySamplerWithTextureSlot = sampler_state
{
  Texture = $Diffuse;
  MinFilter = LINEAR;
  MagFilter = LINEAR;
  MipFilter = LINEAR; 
  AddressU = Wrap;
  AddressV = Wrap;
  AddressW = Wrap;
}
```

加载后，纹理将是材质在漫反射槽中指定的纹理。

## 获取纹理

现在我们有了一个纹理，我们可以学习如何在着色器中获取纹理数据。这是通过使用`GetTexture2D`函数来完成的，如下所示：

```cs
half4 myMap = GetTexture2D(mySampler, baseTC.xy);
```

第一个参数指定要使用的采样器（在我们的情况下，我们之前创建的采样器），而第二个参数指定纹理坐标。

# 在运行时操作静态对象

在这一部分，我们将学习如何在运行时修改静态网格，从而允许在游戏过程中操纵渲染和物理网格。

为此，首先我们需要获取我们对象的`IStatObj`实例。例如，如果您正在修改一个实体，您可以使用`IEntity::GetStatObj`，如下所示：

```cs
IStatObj *pStatObj = pMyEntity->GetStatObj(0);
```

### 注意

请注意，我们将`0`作为第一个参数传递给`IEntity::GetStatObj`。这样做是为了获取具有最高**细节级别**（**LOD**）的对象。这意味着对这个静态对象所做的更改不会反映在其其他 LOD 中。

现在您有一个指向保存模型静态对象数据的接口的指针。

我们现在可以调用`IStatObj::GetIndexedMesh`或`IStatObj::GetRenderMesh`。后者很可能是最好的起点，因为它是从优化的索引网格数据构建的，如下所示：

```cs
IIndexedMesh *pIndexedMesh = pStatObj->GetIndexedMesh();
if(pIndexedMesh)
{
  IIndexedMesh::SMeshDescription meshdesc;
  pIndexedMesh->GetMesh(meshdesc);
}
```

现在我们可以访问包含有关网格信息的`meshdesc`变量。

请注意，我们需要调用`IStatObj::UpdateVertices`以传递我们对网格所做的更改。

### 注意

请记住，更改静态对象将传递更改到使用它的所有对象。在编辑之前使用`IStatObj::Clone`方法创建其副本，从而允许您只操纵场景中的一个对象。

# 在运行时修改材质

在这一部分，我们将在运行时修改材质。

### 注意

与`IStatObj`类似，我们还可以克隆我们的材质，以避免对当前使用它的所有对象进行更改。为此，请调用`IMaterialManager::CloneMaterial`，可通过`gEnv->p3DEngine->GetMaterialManager()`访问。

我们需要做的第一件事是获取我们想要编辑的材质的实例。如果附近有一个实体，我们可以使用`IEntity::GetMaterial`，如下所示：

```cs
IMaterial *pMaterial = pEntity->GetMaterial();
```

### 注意

请注意，如果没有设置自定义材质，`IEntity::GetMaterial`将返回 null。如果是这种情况，您可能希望依赖于诸如`IStatObj::GetMaterial`之类的函数。

## 克隆材质

请注意，`IMaterial`实例可以用于多个对象。这意味着修改对象的参数可能会导致检索对象之外的对象发生变化。

为了解决这个问题，我们可以简单地在通过`IMaterialManager::Clone`方法修改之前克隆材质，如下所示：

```cs
IMaterial *pNewMaterial = gEnv->p3DEngine->GetMaterialManager()->CloneMaterial(pMaterial);
```

然后我们只需将克隆应用于我们检索到原始实例的实体：

```cs
pEntity->SetMaterial(pNewMaterial);
```

现在我们可以继续修改材质的参数，或者与其分配的着色器相关的参数。

## 材料参数

在某些情况下修改我们材料的参数是很有用的。这使我们能够调整每种材料的属性，比如**不透明度**、**Alpha 测试**和**漫反射颜色**，如下截图所示：

![材料参数](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909_10_04.jpg)

要设置或获取材料参数，请使用`IMaterial::SetGetMaterialParamFloat`或`IMaterial::SetGetMaterialVec3`。

例如，要查看我们材料的 alpha 值，使用以下代码：

```cs
float newAlpha = 0.5f;
pMaterial->SetGetMaterialParamFloat("alpha",  0.5f, false);
```

材料现在应该以半强度绘制 alpha。

以下是可用参数的列表：

| 参数名称 | 类型 |
| --- | --- |
| `"alpha"` | `浮点数` |
| `"不透明度"` | `浮点数` |
| `"发光"` | `浮点数` |
| `"光泽度"` | `浮点数` |
| `"漫反射"` | `Vec3` |
| `"发光"` | `Vec3` |
| `"高光"` | `Vec3` |

## 着色器参数

正如我们之前学到的，每个着色器都可以公开一组参数，允许材料调整着色器的行为，而不会影响全局着色器。

![着色器参数](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909_10_05.jpg)

要修改我们材料的着色器参数，我们首先需要获取与该材料关联的着色器项目：

```cs
const SShaderItem& shaderItem(pMaterial->GetShaderItem());
```

现在我们有了着色器项目，我们可以使用以下代码访问`IRenderShaderResources::GetParameters`：

```cs
DynArray<SShaderParam> params = shaderItem.m_pShaderResources->GetParameters();
```

我们现在可以修改其中包含的参数，并调用`IRenderShaderResources::SetShaderParams`，如下所示：

```cs
// Iterate through the parameters to find the one we want to modify
for(auto it = params.begin(), end = params.end(); it != end; ++it)
{
  SShaderParam param = *it;

  if(!strcmp(paramName, param.m_Name))
  {
    UParamVal paramVal;
    paramVal.m_Float = 0.7f;

    // Set the value of the parameter (to 0.7f in this case)
    param.SetParam(paramName, &params, paramVal);

    SInputShaderResources res;
    shaderItem.m_pShaderResources->ConvertToInputResource(&res);

    res.m_ShaderParams = params;

    // Update the parameters in the resources.
    shaderItem.m_pShaderResources->SetShaderParams(&res,shaderItem.m_pShader);
    break;
  }
}
```

## 示例-植被动态 Alpha 测试

现在让我们来测试一下您的知识！

我们已经包含了一个树的设置，用于使用 alpha 测试属性与示例（如下截图所示）。当增加 alpha 测试时，模拟叶子掉落。

![示例-植被动态 Alpha 测试](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909_10_06.jpg)

为了展示这一点，我们将编写一小段代码，在运行时修改这些参数。

首先创建一个名为`CTreeOfTime`的新类。要么创建一个新的游戏对象扩展，要么从我们在第三章中创建的示例中派生一个。

创建后，我们需要在实体生成时加载我们的树对象，如下所示：

```cs
void CTreeOfTime::ProcessEvent(SEntityEvent& event)
{
  switch(event.event) 
  { 
    case ENTITY_EVENT_INIT:
    case ENTITY_EVENT_RESET:
    case ENTITY_EVENT_START_LEVEL:
    {
      IEntity *pEntity = GetEntity();

      pEntity->LoadGeometry(0, "Objects/nature/trees/ash/tree_ash_01.cgf");
    }
    break;
  }
}
```

我们的实体现在应该在生成时将`Objects/nature/trees/ash/tree_ash_01.cgf`对象加载到其第一个槽（索引 0）中。

接下来，我们需要重写实体的`Update`方法，以便根据当前时间更新 alpha 测试属性。完成后，添加以下代码：

```cs
if(IStatObj *pStatObj = GetEntity()->GetStatObj(0))
{
  IMaterial *pMaterial = pStatObj->GetMaterial();
  if(pMaterial == nullptr)
    return;

  IMaterial *pBranchMaterial = pMaterial->GetSubMtl(0);
  if(pBranchMaterial == nullptr)
    return;

  // Make alpha peak at 12
  float alphaTest = abs(gEnv->p3DEngine->GetTimeOfDay()->GetTime() - 12) / 12;
  pBranchMaterial->SetGetMaterialParamFloat("alpha", alphaTest, false);
}
```

您现在应该有一个时间周期，在这个周期内，您的树会失去并重新长出叶子。这是通过在运行时修改材料可能实现的众多技术之一。

![示例-植被动态 Alpha 测试](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909_10_07.jpg)

# 摘要

在本章中，我们已经学习了引擎如何使用着色器，并且已经分解了渲染过程。您现在应该知道如何使用渲染上下文，在运行时操纵静态对象，并以编程方式修改材料。

如果您还没有准备好继续下一章关于特效和声音的内容，为什么不接受一个挑战呢？例如，您可以创建一个在受到攻击时变形的自定义对象。


# 第十一章：效果和声音

CryENGINE 拥有非常模块化的效果系统，允许在运行时轻松生成效果。引擎还具有 FMOD 集成，为开发人员提供了动态播放音频、音乐和本地化对话的工具。

在本章中，我们将涵盖以下主题：

+   学习有关效果和声音系统

+   发现如何创建和触发材料效果

+   学习如何通过 FMOD Designer 导出和自定义声音

+   播放自定义声音

+   学习如何将声音集成到粒子和物理事件中

# 引入效果

没有 FX，游戏世界通常很难相信，并且被认为是没有生命的。简单地添加声音和粒子等效果有助于使世界变得生动，给玩家带来更加沉浸式的世界感。

尽管引擎中没有一个统一的系统来处理所有类型的效果，但我们将涵盖处理各种效果的多个系统。这包括材料效果、粒子效果、音效等。

## 材料效果

材料效果系统处理材料之间的反应，例如，根据岩石落在的材料播放不同的粒子和声音效果。

### 表面类型

每种材料都被分配了一个**表面类型**，表示其是什么类型的表面。例如，如果我们正在创建一个岩石材料，我们应该使用`mat_rock`表面类型。

通过分配表面类型，物理系统将能够收集有关碰撞应如何行为的信息，例如，通过获取表面类型的摩擦值。多个表面类型之间的相互作用还允许根据彼此接触的表面类型动态改变效果。

可以很容易地通过编程方式查询表面类型，从而允许各种系统创建基于表面类型触发的不同代码路径。

在 C++中，表面类型由`ISurfaceType`接口表示，可通过`IMaterial::GetSurfaceType`获得。

使用 C#，表面类型由`CryEngine.SurfaceType`类表示，并且可以通过`CryEngine.Material.SurfaceType`属性检索。

#### 添加或修改表面类型

表面类型在`Game/Libs/MaterialEffects/SurfaceTypes.xml`中定义。引擎在启动时解析该文件，允许材料使用加载的表面类型。

每种表面类型都是通过使用`SurfaceType`元素定义的，例如，如下代码所示的`mat_fabric`：

```cs
<SurfaceType name="mat_fabric">
  <Physics friction="0.80000001" elasticity="0" pierceability="7" can_shatter="1"/>
</SurfaceType>
```

当发生碰撞时，物理系统会查询物理属性。

## 粒子效果

粒子效果由`IParticleManager`接口处理，可通过`I3DEngine::GetParticleManager`访问。要获得`IParticleEffect`对象的指针，请参阅`IParticleManager::FindEffect`。

通过**Sandbox Editor**中包含的**Particle Editor**创建粒子效果，并通常保存到`Game/Libs/Particles`中。

## 音效

CryENGINE 声音系统由游戏音频内容创建工具 FMOD 提供支持。通过使用 FMOD，引擎支持轻松创建和操作声音，以立即在游戏中使用。

声音系统可以通过`ISoundSystem`接口访问，通常通过`gEnv->pSoundSystem`指针检索。声音由`ISound`接口表示，可以通过`ISoundSystem::CreateSound`或`ISoundSystem::GetSound`检索到指针。

通过访问`ISound`接口，我们可以更改语义、距离倍增器等，以及通过`ISound::Play`实际播放声音。

### FMOD Designer

设计师是我们每次想要向项目中使用的不同声音库添加更多声音时使用的工具。

![FMOD Designer](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909OT_11_01.jpg)

设计师允许创建和维护声音库，本质上是创建不同声音之间的分离的库。声音库中包括事件、声音定义和音乐。这些可以被赋予静态和动态修饰符，例如根据游戏环境给声音赋予独特的 3D 效果。

# 创建和触发材料效果

有两种触发自定义材料效果的方法，如下节所述。

## 基于物理相互作用的自动播放

当两种材料由于物理事件发生碰撞时，引擎将根据分配给材料的表面类型在`Game/Libs/MaterialEffects/MaterialEffects.xml`中查找材料效果。这允许在发生某些交互时播放各种粒子和声音。

例如，如果岩石与木材发生碰撞，我们可以播放特定的声音事件以及木屑粒子。

首先，用 Microsoft Excel 打开`MaterialEffects.xml`。

### 注意

虽然可以手动修改材料效果文档，但由于 Excel 格式的复杂性，这并不推荐。

![基于物理相互作用的自动播放](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909OT_11_02.jpg)

现在您应该在 Excel 应用程序中看到材料效果表。各种表面类型以网格形式布置，行和列的交叉点定义了要使用的效果。

例如，根据上一个屏幕截图中显示的表，如果一个具有表面类型**mat_flesh**的材料与**mat_vegetation**表面发生碰撞，引擎将加载**collision:vegetation_spruce**效果。

### 注意

可以通过`Libs/MaterialEffects/SurfaceTypes.xml`查看（或修改）完整的表面类型列表。

### 添加新的表面类型

如果需要向材料效果文档中添加新的表面类型，只需添加一个相应的行和一个带有表面类型名称的列，以便引擎加载它。

### 注意

请记住，表面类型的名称必须按照相同的顺序出现在行和列中。

### 效果定义

现在我们知道系统如何为各种表面类型的碰撞找到效果，那么我们如何找到并创建效果呢？

效果以纯 XML 文件的形式包含在`Libs/MaterialEffects/FXLibs/`中。例如，先前使用的**collision:vegetation_spruce**效果的定义包含在`Libs/MaterialEffects/FXLibs/Collision.xml`中，内容如下：

```cs
<FXLib>
  <Effect name="vegetation_spruce">
    <Particle>
      <Name>Snow.Vegetation.SpruceNeedleGroup</Name>
    </Particle>
  </Effect>
</FXLib>
```

这告诉引擎在触发效果时播放指定的粒子。例如，如前所述，如果一个具有**mat_flesh**表面类型的材料与另一个**mat_vegetation**类型的材料发生碰撞，引擎将在碰撞位置生成`Snow.Vegetation.SpruceNeedleGroup`效果。

但是声音呢？声音可以通过事件以类似的方式播放，只需用声音的名称替换`Particle`标签，如下面的代码所示：

```cs
<Sound>
  <Name>Sounds/Animals:Animals:Pig</Name>
</Sound>
```

现在当效果播放时，我们应该能够听到猪的挣扎声。这就是当你撞到植被时会发生的事情，对吧？

### 注意

值得记住的是，一个效果不必包含一种特定类型的效果，而可以在触发时同时播放多种效果。例如，根据前面的代码，我们可以创建一个新的效果，在触发时播放声音并生成粒子效果。

## 触发自定义事件

还可以触发自定义材料效果，例如，当创建应基于交互名称不同的脚步效果时非常有用。

![触发自定义事件](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909OT_11_03.jpg)

### 注意

冒号（'**:**'）代表效果类别，这是我们在`Libs/MaterialEffects/FXLibs/`文件夹中创建的效果库的名称。

上一个屏幕截图是以编程方式触发的自定义材料效果的较小选择。

要获取效果的 ID，请调用`IMaterialEffects::GetEffectId`，并提供交互名称和相关表面类型，如下所示。

```cs
IMaterialEffects *pMaterialEffects = gEnv->pGame->GetIGameFramework()->GetIMaterialEffects();

TMFXEffectId effectId = pMaterialEffects->GetEffectId("footstep_player", surfaceId);
```

### 注意

有许多获取表面标识符的方法。例如，使用`RayWorldIntersection`投射射线将允许我们通过`ray_hit::surface_idx`变量获取碰撞表面 ID。我们也可以简单地在任何材质实例上调用`IMaterial::GetSurfaceTypeId`。

现在，我们应该有`footstep_player`效果的标识符，基于我们传递给`GetEffectId`的表面类型。例如，通过与先前的截图交叉引用，并假设我们传递了`mat_metal`标识符，我们应该有`footstep_player:metal_thick`效果的 ID。

然后，我们可以通过调用`IMaterialEffects::ExecuteEffect`来执行效果，如下所示：

```cs
SMFXRunTimeEffectParams params;
params.pos = Vec3(0, 0, 10);

bool result = gEnv->pGame->GetIGameFramework()->GetIMaterialEffects()->ExecuteEffect(effectId, params);
```

还可以通过调用`IMaterialEffects::GetResources`来获取效果资源，如下所示：

```cs
if(effectId != InvalidEffectId)
{
  SMFXResourceListPtr->pList = pMaterialEffects->GetResources(effectId);

  if(pList && pList->m_particleList)
  {
    const char *particleEffectName = pList->m_particleList->m_particleParams.name;
  }
}
```

# 基于动画的事件和效果

基于动画的事件可用于在动画的特定时间触发特定效果。例如，我们可以使用这个来将声音链接到动画，以确保声音始终与其对应的动画同步播放。

首先，通过**Sandbox Editor**打开**Character Editor**，加载任何角色定义，然后选择任何动画。

![基于动画的事件和效果](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909OT_11_04.jpg)

在窗口底部中央选择**Animation Control**选项卡，并选择动画期间的任何时间，您想要播放声音的时间。

当滑块定位在应播放声音的时间上时，单击**New Event**。

事件的**Name**字段应为**sound**，并将**Parameter**字段设置为要播放的声音路径。

![基于动画的事件和效果](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909OT_11_05.jpg)

单击**Save**后，声音应该会在指定的时间与动画一起播放。

# 生成粒子发射器

如*Particle effects*部分所述，粒子效果由`IParticleEffect`接口表示。但是，粒子效果与粒子发射器不同。效果接口处理默认效果的属性，并可以生成显示游戏中的视觉效果的单个发射器。

发射器由`IParticleEmitter`接口表示，通常通过调用`IParticleEffect::Spawn`来检索。

# 通过使用 FMod 导出声音

所以你想要将一些声音导出到引擎？我们需要做的第一件事是通过**FMOD Designer**创建一个新的 FMod 项目。要这样做，首先通过`<Engine Root>/Tools/FmodDesigner/fmod_designer.exe`打开设计师。 

要创建新项目，请单击**File**菜单，选择**New Project**，然后将项目保存到您认为合适的位置。我们将保存到`Game/Sounds/Animals/Animals.fdp`。

### 注意

有关 FMOD 音频系统的更深入教程，请参阅 CryENGINE 文档[`docs.cryengine.com/display/SDKDOC3/The+FMOD+Designer`](http://docs.cryengine.com/display/SDKDOC3/The+FMOD+Designer)。

## 向项目添加声音

现在我们有一个声音项目，是时候添加一些声音了。要这样做，请确保您在**Events**菜单中，**Groups**选项卡处于激活状态，如下截图所示：

![向项目添加声音](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909OT_11_06.jpg)

现在，要添加声音，只需将`.wav`文件拖放到您选择的组中，然后它应该出现在那里。现在，您可以导航到**Project** | **Build**，或按*Ctrl* + *B*，以构建项目的波形库，这是引擎将加载以检测声音的内容。

![向项目添加声音](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909OT_11_07.jpg)

通过向事件组添加更多声音，系统将在请求组时随机选择一个声音。

通过在 FMOD 中选择事件组，我们还可以修改其属性，从而调整声音在播放时的播放方式。

![将声音添加到项目中](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909OT_11_08.jpg)

大多数属性静态影响声音，而以**随机化**结尾的属性会在运行时随机应用效果。例如，通过调整**音高随机化**，我们可以确保声音的音高会随机偏移我们选择的值，给声音增添独特的风格。

# 播放声音

在播放音频时，我们必须区分由程序员触发的动态声音和由关卡创建者触发的静态声音。

有多种触发音频事件的方式，应根据声音的目的进行评估。

## 使用 SoundSpots

声音点实体存在是为了让关卡设计师轻松地放置一个实体，以便在特定区域播放预定义的声音。声音实体支持循环声音，或者在从脚本事件触发时每次播放一次。

要使用声音点，首先通过 Rollupbar 放置一个新的**SoundSpot**实体的实例，或导航到**Sound** | **Soundspot**。放置后，您应该看到类似于以下屏幕截图的示例：

![使用 SoundSpots](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909OT_11_09.jpg)

现在我们可以分配应该在该位置播放的声音。要这样做，请单击**Source**实体属性，然后通过**Sound Browser**窗口选择一个声音，如下面的屏幕截图所示：

![使用 SoundSpots](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909OT_11_10.jpg)

然后可以设置**SoundSpot**以始终播放声音，或者通过流程图触发。例如，在下面的屏幕截图中，当玩家使用*K*键时，声音点将播放其声音。

![使用 SoundSpots](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909OT_11_11.jpg)

## 以编程方式播放声音

要以编程方式播放声音，我们首先需要通过`ISoundSystem::CreateSound`检索与我们感兴趣的特定声音相关的`ISound`指针，如下所示：

```cs
ISound *pSound = gEnv->pSoundSystem->CreateSound("Sounds/Animals:Animals:Pig", 0);
```

然后可以通过`ISound::Play`直接播放声音，或将其附加到实体的声音代理：

```cs
IEntitySoundProxy *pSoundProxy = (IEntitySoundProxy *)pEntity->CreateProxy(ENTITY_PROXY_SOUND);

if(pSoundProxy)
  pSoundProxy->PlySound(pSound);
```

通过使用实体声音代理，我们可以确保声音在游戏世界中移动时跟随该实体。

### 声音标志

通过使用`ISoundSystem::CreateSound`接口创建声音时，我们可以指定一组标志，这些标志将影响我们声音的播放。

### 注意

在使用之前，需要在 FMOD 中设置一些标志。例如，具有 3D 空间效果的声音必须在 FMOD 中设置好才能在引擎中使用。

这些标志包含在`ISound.h`中，作为带有`FLAG_SOUND_`前缀的预处理器宏。例如，我们可以在我们的声音中应用`FLAG_SOUND_DOPPLER`标志，以便在播放时模拟多普勒效应。

### 声音语义

语义本质上是应用于声音的修饰符，每个声音都需要它才能播放。

不同的声音语义可以在`ISound.h`（在 CryCommon 项目中）中查看，其中包括`ESoundSemantic`枚举。

# 摘要

在这一章中，我们已经将声音从 FMOD 导入到引擎中，并学会了如何调整它们。

现在您应该知道如何通过 Sandbox 编辑器和以编程方式触发声音，并且对材质效果有了工作知识。

如果您还没有准备好进入下一章，为什么不尝试扩展您的知识呢？一个可能的选择是深入研究粒子编辑器，并创建自己的粒子，包括自定义效果和声音。

在下一章中，我们将介绍调试和分析游戏逻辑的过程，帮助您更高效地工作。


# 第十二章：调试和性能分析

创建高效且无 bug 的代码可能很困难。因此，引擎提供了许多工具来帮助开发人员，以便轻松识别错误并可视化性能问题。

在编写游戏和引擎逻辑时，始终牢记调试和性能分析工具非常重要，以确保代码运行良好并且可以轻松地扫描问题。在解决未来问题时，添加一些游戏日志警告可能非常重要，可以节省大量时间！

在本章中，我们将涵盖以下主题：

+   学习调试 CryENGINE 应用程序的常见方法

+   利用内置性能分析工具

+   创建我们自己的控制台变量和命令

# 调试游戏逻辑

保持代码无 bug 可能非常困难，特别是如果你只依赖于调试器。即使没有连接到运行中的进程，CryENGINE 也会暴露一些系统来帮助调试代码。

始终牢记使用哪种配置构建 GameDll。在构建项目之前，可以在 Visual Studio 中更改此配置，如下面的屏幕截图所示：

![调试游戏逻辑](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909_12_01.jpg)

默认情况下，有三种主要配置，如下表所示：

| 配置名称 | 描述 |
| --- | --- |
| 配置文件 | 在开发应用程序时使用，确保生成调试数据库。 |
| 调试 | 当您需要关闭编译优化以及专门为此模式打开的额外 CryENGINE 助手时使用。 |
| 发布 | 此模式旨在用于发送给最终用户的最终构建。此配置执行一系列操作，包括禁用调试数据库的生成和多个仅用于调试的 CryENGINE 系统。CryENGINE 游戏通常会将所有库（如 CryGame）链接到一个启动器应用程序中以确保安全。 |

## 记录到控制台和文件

日志系统允许将文本打印到控制台和根文件结构中包含的`.log`文件中。日志的名称取决于启动了哪个应用程序：

| 日志名称 | 描述 |
| --- | --- |
| `Game.log` | 由启动器应用程序使用。 |
| `Editor.log` | 仅供沙盒编辑器应用程序使用。 |
| `Server.log` | 用于专用服务器。 |

日志功能通常用于非常严重的问题，或者警告设计人员不支持的行为。

记录严重错误和初始化统计信息的最大好处是，通过简单地阅读用户的游戏日志，您通常可以弄清楚为什么您的代码在最终用户的计算机上无法正常工作。

### 日志冗长度

通过使用`log_verbosity`控制台变量（用于控制台的可视部分）和`log_writeToFileVerbosity`（用于写入磁盘的日志）来设置日志冗长度。

冗长度确定应该记录/显示哪些消息，并且对于过滤掉不太严重的消息非常有用。

| 冗长度级别 | 描述 |
| --- | --- |
| `-1`（无日志记录） | 抑制所有已记录的信息，包括`CryLogAlways`。 |
| `0`（始终） | 抑制所有已记录的信息，不包括使用`CryLogAlways`记录的信息。 |
| `1`（错误） | 与级别 0 相同，但包括额外的错误。 |
| `2`（警告） | 与级别 1 相同，但包括额外的警告。 |
| `3`（消息） | 与级别 2 相同，但包括额外的消息。 |
| `4`（注释） | 最高冗长度，记录之前提到的所有内容以及额外的注释。 |

### 全局日志函数

以下是全局日志函数列表：

+   `CryLog`：此函数将消息记录到控制台和文件日志中，假设日志冗长度为 3 或更高。

```cs
CryLog("MyMessage");
```

+   `CryLogAlways`：此函数将消息记录到控制台和文件中，假设日志冗长度为 0 或更高。

```cs
CryLogAlways("This is always logged, unless log_verbosity is set to -1");
```

+   `CryWarning`：此函数向日志和控制台输出一个警告，前缀为[Warning]。它还可用于警告设计人员他们错误地使用功能。只有在日志详细程度为 2 或更高时才会记录到文件中。

```cs
CryWarning(VALIDATOR_MODULE_GAME, VALIDATOR_WARNING, "My warning!");
```

+   `CryFatalError`：此函数用于指定发生了严重错误，并导致消息框后跟程序终止。

```cs
CryFatalError("Fatal error, shutting down!");
```

+   `CryComment`：此函数输出一个注释，假设日志详细程度为 4。

```cs
CryComment("My note");
```

### 注意

注意：在 C#中，通过使用静态的`Debug`类来记录日志。例如，要记录一条消息，可以使用`Debug.Log("message");`

要使用 Lua 进行记录，可以使用`System.Log`函数，例如，`System.Log("MyMessage");`

## 持久调试

持久调试系统允许绘制持久性辅助工具，以在游戏逻辑上提供视觉反馈。例如，该系统在以下截图中用于在每一帧上绘制玩家在其世界位置面对的方向，其中每个箭头在消失之前持续了指定数量的秒数。

该系统可以带来非常有趣的效果，例如一种查看玩家旋转和物理交互的方式，如在免费游戏 SNOW 中显示的那样：

![持久调试](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909_12_02.jpg)

### C++

可以通过游戏框架访问`IPersistantDebug`接口，如下所示：

```cs
IPersistantDebug *pPersistantDebug = gEnv->pGame->GetIGameFramework()->GetIPersistantDebug();
```

在调用各种绘图函数之前，我们需要调用`IPersistantDebug::Begin`来表示应该开始新的持久调试组。

```cs
pPersistantDebug->Begin("myPersistentDebug", false);
```

最后一个布尔参数指定系统是否应清除所选范围内所有先前绘制的持久调试对象（`"myPersistentDebug"`）。

现在我们可以使用各种**Add***函数，例如`AddSphere`：

```cs
pPersistantDebug->AddSphere(Vec3(0, 0, 10), 0.3f, ColorF(1, 0, 0),2.0f);
```

在上一个片段中，系统将在游戏世界中的`0`，`0`，`10`处绘制一个半径为`0.3`的红色球体。球体将在`2`秒后消失。

### C#

在 C#中，可以通过使用静态的`Debug`类来访问持久调试接口。例如，要添加一个球体，可以使用以下代码：

```cs
Debug.DrawSphere(new Vec3(0, 0, 10), 0.3f, Color.Red, 2.0f);
```

## CryAssert

CryAssert 系统允许开发人员确保某些变量保持在边界内。通过进行仅在开发构建中编译的检查，可以不断测试系统如何与其他系统交互。这对性能和确保功能不容易出错都很有好处。

可以通过使用`sys_asserts` CVar 来切换系统，并且可能需要在`StdAfx`头文件中定义`USE_CRYASSERT`宏。

要进行断言，请使用`CRY_ASSERT`宏，如下所示：

```cs
CRY_ASSERT(pPointer != nullptr)
```

然后每次运行代码时都会进行检查，除了在发布模式下，并且当条件为假时会输出一个大的警告消息框。

# 分析

在处理实时产品（如 CryENGINE）时，程序员不断地需要考虑其代码的性能。为了帮助解决这个问题，我们可以使用`profile`控制台变量。

CVar 允许获取代码最密集部分的可视化统计信息，如下截图所示：

![分析](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909_12_03.jpg)

在上一个截图中，profile 设置为`1`，默认模式，对每一帧调用的最密集的函数进行排序。

## 使用情况分析

目前，profile 变量支持以下表中列出的 13 种不同状态：

| 值 | 描述 |
| --- | --- |
| 0 | 默认值；当设置为此值时，分析系统将处于非活动状态。 |
| 1 | 自身时间 |
| 2 | 分层时间 |
| 3 | 扩展自身时间 |
| 4 | 扩展分层时间 |
| 5 | 峰值时间 |
| 6 | 子系统信息 |
| 7 | 调用次数 |
| 8 | 标准偏差 |
| 9 | 内存分配 |
| 10 | 内存分配（以字节为单位） |
| 11 | 停顿 |
| -1 | 用于启用分析系统，而不将信息绘制到屏幕上。 |

## 在 C++中进行分析

在 C++中进行分析，我们可以利用`FUNCTION_PROFILER`预处理器宏定义，如下所示：

```cs
FUNCTION_PROFILER(GetISystem(), PROFILE_GAME);
```

该宏将设置必要的分析器对象：一个静态的`CFrameProfiler`对象，该对象保留在方法中，以及一个`CFrameProfilerSection`对象，每次运行该方法时都会创建（并在返回时销毁）。

如果分析器检测到您的代码与其他引擎功能的关系密切，它将在分析图表中显示更多，如下面的截图所示：

![C++中的分析](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909_12_04.jpg)

如果要调试代码的某个部分，还可以使用`FRAME_PROFILER`宏，其工作方式与`FUNCTION_PROFILER`相同，只是允许您指定受监视部分的名称。

`FRAME_PROFILER`的一个示例用例是在`if`块内部，因为帧分析器部分将在块完成后被销毁：

```cs
if (true)
{
  FRAME_PROFILER("MyCheck", gEnv->pSystem, PROFILE_GAME);

  auto myCharArray = new char[100000];
  for(int i = 0; i < 100000; i++)
    myCharArray[i] = 'T';

  // Frame profiler section is now destroyed
}
```

现在我们可以在游戏中对先前的代码进行分析，如下面的截图所示：

![C++中的分析](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909_12_05.jpg)

## 在 C#中进行分析

也可以以大致相同的方式对 C#代码进行分析。不同之处在于我们不能依赖托管代码中的析构函数/终结器，因此必须自己做一些工作。

我们首先要做的是创建一个`CryEngine.Profiling.FrameProfiler`对象，该对象将在实体的生命周期内持续存在。然后只需在每次需要对函数进行分析时在新的帧分析器对象上调用`FrameProfiler.CreateSection`，然后在使用以下代码时在生成的对象上调用`FrameProfilerSection.End`：

```cs
using CryEngine.Profiling;

public SpawnPoint()
{
  ReceiveUpdates = true;

  m_frameProfiler = FrameProfiler.Create("SpawnPoint.OnUpdate");
}

public override void OnUpdate()
{
  var section = m_frameProfiler.CreateSection();

  var stringArray = new string[10000];
  for(int i = 0; i < 10000; i++)
    stringArray[i] = "is it just me or is it laggy in here";

  section.End();
}

FrameProfiler m_frameProfiler;
```

然后，分析器将列出`SpawnPoint.OnUpdate`，如下面的截图所示：

![C#中的分析](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909_12_06.jpg)

# 控制台

尽管与调试没有直接关联，但 CryENGINE 控制台提供了创建命令的手段，这些命令可以直接从游戏中执行函数，并创建可以修改以改变世界行为方式的变量。

### 注意

有趣的是：通过在控制台中使用井号（`#`）符号，我们可以直接在游戏中执行 Lua，例如，`#System.Log("My message!");`

## 控制台变量

**控制台变量**，通常称为**CVars**，允许在 CryENGINE 控制台中公开代码中的变量，有效地允许在运行时或通过配置（`.cfg`）文件中调整设置。

几乎每个子系统都在运行时使用控制台变量，以便在不需要代码修改的情况下调整系统的行为。

### 注册 CVar

在注册新的 CVar 时，重要的是要区分引用变量和包装变量。

不同之处在于引用 CVar 指向您自己代码中定义的变量，当通过控制台更改值时会直接更新。

包装变量包含专门的**ICVar**（C++）实现中的变量本身，位于`CrySystem.dll`中。

引用变量最常用于 CVars，因为它们不需要每次想要知道控制台变量的值时都调用`IConsole::GetCVar`。

#### 在 C++中

要在 C++中注册引用控制台变量，请调用`IConsole::Register`，如下所示：

```cs
gEnv->pConsole->Register("g_myVariable", &m_myVariable, 3.0f, VF_CHEAT, "My variable description!");
```

现在，`g_myVariable` CVar 的默认值将是`3.0f`。如果我们通过控制台更改了值，`m_myVariable`将立即更新。

### 注意

要了解`VF_CHEAT`标志的作用，请参阅*标志*部分的进一步讨论。

要注册包装的控制台变量，请使用`IConsole::RegisterString`，`RegisterFloat`或`RegisterInt`。

#### 在 C#中

要通过 CryMono 注册引用控制台变量，请使用`CVar.RegisterFloat`或`CVar.RegisterInt`，如下面的代码所示：

```cs
float m_myVariable;

CVar.RegisterFloat("g_myCSharpCVar", ref m_myVariable, "My variable is awesome");
```

### 注意

由于 C++和 C#字符串的后端结构不同，因此无法创建引用字符串 CVars。

如果您喜欢使用包装变量，请使用`CVar.Register`。

### 标志

在注册新的 CVar 时，开发人员应指定默认标志。标志控制变量在修改或查询时的行为。

+   `VF_NULL`: 如果没有其他标志存在，则将此标志设置为零。

+   `VF_CHEAT`: 此标志用于在启用作弊时防止更改变量，例如在发布模式或多人游戏中。

+   `VF_READONLY`: 用户永远无法更改此标志。

+   `VF_REQUIRE_LEVEL_RELOAD`: 此标志警告用户更改变量将需要重新加载级别才能生效。

+   `VF_REQUIRE_APP_RESTART`: 此标志警告用户更改将需要重新启动应用程序才能生效。

+   `VF_MODIFIED`: 当变量被修改时设置此标志。

+   `VF_WASINCONFIG`: 如果变量是通过配置（.cfg）文件更改的，则设置此标志。

+   `VF_RESTRICTEDMODE`: 如果变量应在受限制（发布）的控制台模式中可见和可用，则设置此标志。

+   `VF_INVISIBLE`: 如果变量不应在控制台中对用户可见，则设置此标志。

+   `VF_ALWAYSONCHANGE`: 此标志始终接受新值，并在值保持不变时调用更改回调。

+   `VF_BLOCKFRAME`: 此标志在使用变量后阻止执行更多控制台命令一帧。

+   `VF_CONST_CVAR`: 如果变量不应通过配置（.cfg）文件进行编辑，则设置此标志。

+   `VF_CHEAT_ALWAYS_CHECK`: 如果变量非常脆弱并且应该持续检查，则设置此标志。

+   `VF_CHEAT_NOCHECK`: 此标志与`VF_CHEAT`相同，只是由于对其进行的更改是无害的，因此不会进行检查。

### 控制台变量组

为了便于创建不同的系统规格（低/中/高/非常高的图形级别），也称为**Sys Spec**，我们可以利用 CVar 组。这些组允许在更改规范时同时更改多个 CVars 的值。

### 注意

如果您不确定 Sys Specs 的作用，请阅读本章后面讨论的*系统规格*部分。

要更改系统规范，用户只需更改`sys_spec`控制台变量的值。一旦更改，引擎将解析`Engine/Config/CVarGroups/`中的链接规范文件，并设置定义的 CVar 值。

例如，如果更改了`sys_spec_GameEffects` CVar，引擎将打开`Engine/Config/CVarGroups/sys_spec_GameEffects.cfg`。

### 注意

`sys_spec_Full`组被视为根组，并且在更改`sys_spec` CVar 时触发。当更改时，它将更新所有子组，例如`sys_spec_Quality`。

#### Cfg 结构

CVar 组配置文件的结构相对容易理解。例如，查看以下`sys_spec_GameEffects`文件：

```cs
[default]
; default of this CVarGroup
= 3

i_lighteffects = 1
g_ragdollUnseenTime = 2
g_ragdollMinTime = 13
g_ragdollDistance = 30

[1]
g_ragdollMinTime = 5
g_ragdollDistance = 10

[2]
g_ragdollMinTime = 8
g_ragdollDistance = 20

[3]

[4]
g_ragdollMinTime = 15
g_ragdollDistance = 40
```

前三行定义了此配置文件的默认规范，本例中为高（`3`）。

在默认规范之后是高规范中 CVars 的默认值。除非被覆盖，否则这些值将被用作基线并应用于所有规范。

在默认规范之后是低规范（`[1]`）、中等规范（`[2]`）和非常高规范（`[4]`）。在定义之后放置的 CVars 定义了在该规范中应将变量设置为的值。

#### 系统规格

当前系统规范由`sys_spec` CVar 的值确定。更改变量的值将自动加载为该规范专门调整的着色器和 CVar 组。例如，如果游戏在您的 PC 上运行得有点糟糕，您可能想将规范更改为低（`1`）。

+   `0`: 自定义

+   `1`: 低

+   `2`: 中等

+   `3`: 高

+   `4`: 非常高

+   `5`: Xbox 360

+   `6`: PlayStation 3

## 控制台命令

**控制台命令**（通常称为**CCommands**）本质上是已映射到控制台变量的函数。但是，与将命令输入控制台时更改引用变量的值不同，调用将触发在注册命令时指定的函数。

### 注意

请注意，控制台变量还可以指定`On Change`回调，在值更改时会自动调用。当内部变量与您的意图无关时，请使用控制台命令。

### 在 C#中注册控制台命令

要在 C#中注册控制台命令，请使用`ConsoleCommand.Register`，如下面的代码所示：

```cs
public void OnMyCSharpCommand(ConsoleCommandArgs e)
{
}

ConsoleCommand.Register("MyCSharpCommand", OnMyCSharpCommand, "C# CCommands are awesome.");
```

在控制台中触发`MyCSharpCommand`现在将导致调用`OnMyCSharpCommand`函数。

#### 参数

当触发回调时，您将能够检索在命令本身之后添加的参数集。例如，如果用户通过键入`MyCommand 2`来激活命令，我们可能希望检索字符串的`2`部分。

为此，请使用`ConsoleCommandArgs.Args`数组，并指定要获取的参数的索引。对于前面的示例，代码将如下所示：

```cs
string firstArgument = null;
if(e.Args.Length >= 1)
  firstArgument = e.Args[0];
```

### 注意

要检索使用命令指定的完整命令行，请使用`ConsoleCommandArgs.FullCommandLine`。

### 在 C++中创建控制台命令

要在 C++中添加新的控制台命令，请使用`IConsole::AddCommand`，如下所示：

```cs
void MyCommandCallback(IConsoleCmdArgs *pCmdArgs)
{
}
gEnv->pConsole->AddCommand("MyCommand", MyCommandCallback, VF_NULL, "My command is great!");
```

编译并启动引擎后，您将能够在控制台中键入`MyCommand`并触发您的`MyCommandCallback`函数。

# 摘要

在本章中，我们有：

+   学会了如何使用引擎的一些调试工具

+   对我们的代码进行了性能优化

+   学习了什么是控制台变量（CVars），以及如何使用它们

+   创建自定义控制台命令

现在，您应该对如何在 CryENGINE 中进行最佳编程有了基本的了解。请确保始终牢记性能分析和调试方法，以确保您的代码运行良好。

假设您按顺序阅读了本书的章节，现在您应该了解最重要的引擎系统的运作方式。我们希望您喜欢阅读，并祝您在使用您新获得的 CryENGINE 知识时一切顺利！
