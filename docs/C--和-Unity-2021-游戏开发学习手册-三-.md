# C# 和 Unity 2021 游戏开发学习手册（三）

> 原文：[`zh.annas-archive.org/md5/D5230158773728FED97C67760D6D7EA0`](https://zh.annas-archive.org/md5/D5230158773728FED97C67760D6D7EA0)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第八章：脚本化游戏机制

在上一章中，我们专注于使用代码移动玩家和摄像机，并在旁边进行了 Unity 物理的探索。然而，控制可玩角色并不足以制作一个引人入胜的游戏；事实上，这可能是在不同游戏中保持相对恒定的一个领域。

游戏的独特魅力来自其核心机制，以及这些机制赋予玩家的力量和代理感。如果没有有趣和引人入胜的方式来影响你所创建的虚拟环境，你的游戏就没有重复玩的机会，更不用说有趣了。当我们着手实现游戏机制时，我们也将提升我们对 C#及其中级特性的了解。

本章将在*英雄诞生*原型的基础上，重点关注单独实现的游戏机制，以及系统设计和用户界面（UI）。你将深入以下主题：

+   添加跳跃

+   射击抛射物

+   创建游戏管理器

+   创建 GUI

# 添加跳跃

还记得上一章中 Rigidbody 组件为游戏对象添加了模拟真实世界物理，Collider 组件使用 Rigidbody 对象相互交互的内容。

我们在上一章没有讨论的另一个很棒的事情是，使用 Rigidbody 组件来控制玩家移动，我们可以很容易地添加依赖于施加力的不同机制，比如跳跃。在本节中，我们将让玩家跳跃，并编写我们的第一个实用函数。

实用函数是执行某种繁重工作的类方法，这样我们就不会在游戏代码中弄乱了——比如，想要检查玩家胶囊是否接触地面以进行跳跃。

在此之前，你需要熟悉一种称为枚举的新数据类型，你将在下一节中进行。

## 引入枚举

根据定义，枚举类型是属于同一变量的一组或集合命名常量。当你想要一组不同值的集合，但又希望它们都属于相同的父类型时，这些是很有用的。

枚举更容易通过展示而不是告诉来理解，所以让我们看一下以下代码片段中它们的语法。

```cs
enum PlayerAction { Attack, Defend, Flee }; 
```

让我们来分解一下它是如何工作的，如下所示：

+   `enum`关键字声明了类型，后面跟着变量名。

+   枚举可以具有的不同值写在花括号内，用逗号分隔（最后一项除外）。

+   `enum`必须以分号结尾，就像我们处理过的所有其他数据类型一样。

在这种情况下，我们声明了一个名为`PlayerAction`的变量，类型为`enum`，可以设置为三个值之一——`Attack`、`Defend`或`Flee`。

要声明一个枚举变量，我们使用以下语法：

```cs
PlayerAction CurrentAction = PlayerAction.Defend; 
```

同样，我们可以将其分解如下：

+   类型设置为`PlayerAction`，因为我们的枚举就像任何其他类型一样，比如字符串或整数。

+   变量名为`currentAction`，设置为`PlayerAction`值。

+   每个枚举常量都可以使用点表示法访问。

我们的`currentAction`变量现在设置为`Defend`，但随时可以更改为`Attack`或`Flee`。

枚举乍看起来可能很简单，但在适当的情况下它们非常强大。它们最有用的特性之一是能够存储底层类型，这也是你将要学习的下一个主题。

### 底层类型

枚举带有*底层类型*，意味着花括号内的每个常量都有一个关联值。默认的底层类型是`int`，从 0 开始，就像数组一样，每个连续的常量都得到下一个最高的数字。

并非所有类型都是平等的——枚举的底层类型限制为`byte`、`sbyte`、`short`、`ushort`、`int`、`uint`、`long`和`ulong`。这些被称为整数类型，用于指定变量可以存储的数值的大小。

这对于本书来说有点高级，但在大多数情况下，您将使用`int`。有关这些类型的更多信息可以在这里找到：[`docs.microsoft.com/en-us/dotnet/csharp/language-reference/keywords/enum`](https://docs.microsoft.com/en-us/dotnet/csharp/language-reference/keywords/enum)。

例如，我们的`PlayerAction`枚举值现在列出如下，尽管它们没有明确写出：

```cs
enum PlayerAction { Attack = 0, Defend = 1, Flee = 2 }; 
```

没有规定基础值需要从`0`开始；实际上，您只需要指定第一个值，然后 C#会为我们递增其余的值，如下面的代码片段所示：

```cs
enum PlayerAction { Attack = 5, Defend, Flee }; 
```

在上面的示例中，`Defend`等于`6`，`Flee`等于`7`。但是，如果我们希望`PlayerAction`枚举包含非连续的值，我们可以显式添加它们，就像这样：

```cs
enum PlayerAction { Attack = 10, Defend = 5, Flee = 0}; 
```

我们甚至可以通过在枚举名称后添加冒号来将`PlayerAction`的基础类型更改为任何经批准的类型，如下所示：

```cs
enum PlayerAction :  **byte** { Attack, Defend, Flee }; 
```

检索枚举的基础类型需要显式转换，但我们已经涵盖了这些内容，所以下面的语法不应该让人感到意外：

```cs
enum PlayerAction { Attack = 10, Defend = 5, Flee = 0};
PlayerAction CurrentAction = PlayerAction.Attack;
**int** ActionCost = **(****int****)**CurrentAction; 
```

由于`CurrentAction`设置为`Attack`，在上面的示例代码中，`ActionCost`将是`10`。

枚举是您编程工具中非常强大的工具。您下一个挑战是利用您对枚举的了解，从键盘上收集更具体的用户输入。

现在我们已经基本掌握了枚举类型，我们可以使用`KeyCode`枚举来捕获键盘输入。更新`PlayerBehavior`脚本，添加以下突出显示的代码，保存并点击播放：

```cs
public class PlayerBehavior : MonoBehaviour 
{
    // ... No other variable changes needed ...

    **// 1**
    **public****float** **JumpVelocity =** **5f****;**
    **private****bool** **_isJumping;**

    void Start()
    {
        _rb = GetComponent<Rigidbody>();
    }

    void Update()
    {
        **// 2**
        **_isJumping |= Input.GetKeyDown(KeyCode.Space);**
        // ... No other changes needed ...
    }

    void FixedUpdate()
    {
        **// 3**
        **if****(_isJumping)**
        **{**
            **// 4**
            **_rb.AddForce(Vector3.up * JumpVelocity, ForceMode.Impulse);**
        **}**
        **// 5**
        **_isJumping =** **false****;**
        // ... No other changes needed ...
    }
} 
```

让我们来分解这段代码：

1.  首先，我们创建两个新变量——一个公共变量来保存我们想要应用的跳跃力量的数量，一个私有布尔变量来检查我们的玩家是否应该跳跃。

1.  我们将`_isJumping`的值设置为`Input.GetKeyDown()`方法，根据指定的键是否被按下返回一个`bool`值。

+   我们使用`|=`运算符来设置`_isJumping`，这是逻辑`或`条件。该运算符确保当玩家跳跃时，连续的输入检查不会互相覆盖。

+   该方法接受一个键参数，可以是`string`或`KeyCode`，它是一个枚举类型。我们指定要检查`KeyCode.Space`。

在`FixedUpdate`中检查输入有时会导致输入丢失，甚至会导致双重输入，因为它不是每帧运行一次。这就是为什么我们在`Update`中检查输入，然后在`FixedUpdate`中应用力或设置速度。

1.  我们使用`if`语句来检查`_isJumping`是否为真，并在其为真时触发跳跃机制。

1.  由于我们已经存储了 Rigidbody 组件，我们可以将`Vector3`和`ForceMode`参数传递给`RigidBody.AddForce()`，使玩家跳跃。

+   我们指定向量（或应用的力）应该是“上”方向，乘以`JumpVelocity`。

+   `ForceMode`参数确定了如何应用力，并且也是一个枚举类型。`Impulse`会立即对物体施加力，同时考虑其质量，这非常适合跳跃机制。

其他`ForceMode`选择在不同情况下可能会有用，所有这些都在这里详细说明：[`docs.unity3d.com/ScriptReference/ForceMode.html`](https://docs.unity3d.com/ScriptReference/ForceMode.html)。

1.  在每个`FixedUpdate`帧的末尾，我们将`_isJumping`重置为 false，以便输入检查知道完成了一次跳跃和着陆循环。

如果您现在玩游戏，您将能够在按下空格键时移动和跳跃。但是，该机制允许您无限跳跃，这不是我们想要的。在下一节中，我们将通过使用称为层蒙版的东西来限制我们的跳跃机制一次跳跃。

## 使用层蒙版

将图层蒙版视为游戏对象可以属于的不可见组，由物理系统用于确定从导航到相交碰撞器组件的任何内容。虽然图层蒙版的更高级用法超出了本书的范围，但我们将创建并使用一个来执行一个简单的检查——玩家胶囊是否接触地面，以限制玩家一次只能跳一次。

在我们检查玩家胶囊是否接触地面之前，我们需要将我们级别中的所有环境对象添加到一个自定义图层蒙版中。这将让我们执行与已经附加到玩家的胶囊碰撞体组件的实际碰撞计算。操作如下：

1.  在**层次结构**中选择任何环境游戏对象，并在相应的**检视器**窗格中，单击**层** | **添加图层...**，如下截图所示：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_08_01.png)

图 8.1：在检视器窗格中选择图层

1.  通过在第一个可用的槽中输入名称来添加一个名为`Ground`的新图层，该槽是第 6 层。尽管第 3 层为空，但层 0-5 保留给 Unity 的默认层，如下截图所示：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_08_02.png)

图 8.2：在检视器窗格中添加图层

1.  在“层次结构”中选择**环境**父游戏对象，单击**层**下拉菜单，然后选择**Ground**。![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_08_03.png)

图 8.3：设置自定义图层

在选择了下图中显示的**Ground**选项后，当出现对话框询问是否要更改所有子对象时，单击**是，更改子对象**。在这里，您已经定义了一个名为**Ground**的新图层，并将**环境**的每个子对象分配到该图层。

从现在开始，所有**Ground**图层上的对象都可以被检查是否与特定对象相交。您将在接下来的挑战中使用这个功能，以确保玩家只能在地面上执行跳跃；这里没有无限跳跃的作弊。

由于我们不希望代码混乱`Update()`方法，我们将在实用函数中进行图层蒙版计算，并根据结果返回`true`或`false`值。操作如下：

1.  将以下突出显示的代码添加到`PlayerBehavior`中，然后再次播放场景：

```cs
public class PlayerBehavior : MonoBehaviour 
{
    **// 1**
    **public****float** **DistanceToGround =** **0.1f****;**
    **// 2** 
    **public** **LayerMask GroundLayer;**
    **// 3**
    **private** **CapsuleCollider _col;**
    // ... No other variable changes needed ...

    void Start()
    {
        _rb = GetComponent<Rigidbody>();

        **// 4**
        **_col = GetComponent<CapsuleCollider>();**
    }

    void Update()
    {
        // ... No changes needed ...
    }

    void FixedUpdate()
    {
        **// 5**
        if(**IsGrounded() &&** _isJumping)
        {
            _rb.AddForce(Vector3.up * JumpVelocity,
                 ForceMode.Impulse);
         }
         // ... No other changes needed ...
    }

    **// 6**
    **private****bool****IsGrounded****()**
    **{**
        **// 7**
        **Vector3 capsuleBottom =** **new** **Vector3(_col.bounds.center.x,**
             **_col.bounds.min.y, _col.bounds.center.z);**

        **// 8**
        **bool** **grounded = Physics.CheckCapsule(_col.bounds.center,**
            **capsuleBottom, DistanceToGround, GroundLayer,**
               **QueryTriggerInteraction.Ignore);**

        **// 9**
        **return** **grounded;**
    **}**
**}** 
```

1.  选择`PlayerBehavior`脚本，将**检视器**窗格中的**Ground Layer**设置为**Ground**，从**Ground Layer**下拉菜单中选择，如下截图所示：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_08_04.png)

图 8.4：设置地面图层

让我们按照以下方式分解前面的代码：

1.  我们为将检查玩家胶囊碰撞体与任何**Ground Layer**对象之间的距离创建一个新变量。

1.  我们创建一个`LayerMask`变量，可以在**检视器**中设置，并用于碰撞体检测。

1.  我们创建一个变量来存储玩家的胶囊碰撞体组件。

1.  我们使用`GetComponent()`来查找并返回附加到玩家的胶囊碰撞体。

1.  我们更新`if`语句，以检查`IsGrounded`是否返回`true`并且在执行跳跃代码之前按下了空格键。

1.  我们声明了`IsGrounded()`方法，返回类型为`bool`。

1.  我们创建一个本地的`Vector3`变量来存储玩家胶囊碰撞体底部的位置，我们将用它来检查与**Ground**图层上的任何对象的碰撞。

+   所有碰撞体组件都有一个`bounds`属性，它使我们可以访问其*x*、*y*和*z*轴的最小、最大和中心位置。

+   碰撞体的底部是 3D 点，在中心*x*，最小*y*和中心*z*。

1.  我们创建一个本地的`bool`来存储我们从`Physics`类中调用的`CheckCapsule()`方法的结果，该方法接受以下五个参数：

+   胶囊的开始，我们将其设置为胶囊碰撞体的中间，因为我们只关心底部是否接触地面。

+   胶囊的末端，即我们已经计算过的`capsuleBottom`位置。

+   胶囊体的半径，即已设置的`DistanceToGround`。

+   我们要检查碰撞的图层蒙版，设置为**检视器**中的`GroundLayer`。

+   查询触发交互，确定方法是否应忽略设置为触发器的碰撞体。由于我们想要忽略所有触发器，我们使用了`QueryTriggerInteraction.Ignore`枚举。

我们还可以使用`Vector3`类的`Distance`方法来确定我们离地面有多远，因为我们知道玩家胶囊的高度。然而，我们将继续使用`Physics`类，因为这是本章的重点。

1.  我们在计算结束时返回存储在`grounded`中的值。

我们本可以手动进行碰撞计算，但那将需要比我们在这里有时间涵盖的更复杂的 3D 数学。然而，使用内置方法总是一个好主意。

我们刚刚在`PlayerBehavior`中添加的代码是一个复杂的代码片段，但是当你分解它时，我们做的唯一新的事情就是使用了`Physics`类的一个方法。简单来说，我们向`CheckCapsule()`提供了起始点和终点、碰撞半径和图层蒙版。如果终点距离图层蒙版上的对象的碰撞半径更近，该方法将返回`true`——这意味着玩家正在接触地面。如果玩家处于跳跃中的位置，`CheckCapsule()`将返回`false`。

由于我们在`Update()`中的`if`语句中每帧检查`IsGround`，所以我们的玩家的跳跃技能只有在接触地面时才允许。

这就是你要用跳跃机制做的一切，但玩家仍然需要一种方式来与并最终占领竞技场的敌人进行互动和自卫。在接下来的部分，你将通过实现一个简单的射击机制来填补这个空白。

# 发射抛射物

射击机制是如此普遍，以至于很难想象一个没有某种变化的第一人称游戏，*Hero Born*也不例外。在本节中，我们将讨论如何在游戏运行时从预制件中实例化游戏对象，并使用我们学到的技能来利用 Unity 物理学将它们向前推进。

## 实例化对象

在游戏中实例化一个游戏对象的概念类似于实例化一个类的实例——都需要起始值，以便 C#知道我们要创建什么类型的对象以及需要在哪里创建它。为了在运行时在场景中创建对象，我们使用`Instantiate()`方法，并提供一个预制对象、一个起始位置和一个起始旋转。

基本上，我们可以告诉 Unity 在这个位置创建一个给定的对象，带有所有的组件和脚本，朝着这个方向，然后一旦它在 3D 空间中诞生，就可以根据需要对其进行操作。在我们实例化一个对象之前，你需要创建对象的预制本身，这是你的下一个任务。

在我们射击任何抛射物之前，我们需要一个预制件作为参考，所以现在让我们创建它，如下所示：

1.  在**层次结构**面板中选择**+** | **3D** **对象** | **球体**，并将其命名为`Bullet`。

+   在**Transform**组件中将其**比例**在*x*、*y*和*z*轴上更改为 0.15。

1.  在**检视器**中选择**Bullet**，并在底部使用**添加组件**按钮搜索并添加一个**刚体**组件，将所有默认属性保持不变。

1.  在`材质`文件夹中使用**创建** | **材质**创建一个新的材质，并将其命名为`Bullet_Mat`：

+   将**Albedo**属性更改为深黄色。

+   在**层次结构**面板中，将**材质**文件夹中的材质拖放到`Bullet`游戏对象上。![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_08_05.png)

图 8.5：设置抛射物属性

1.  在**层次结构**面板中选择**Bullet**，并将其拖放到**项目**面板中的`预制件`文件夹中。然后，从**层次结构**中删除它以清理场景:![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_08_06.png)

图 8.6：创建一个抛射物预制件

您创建并配置了一个可以根据需要在游戏中实例化多次并根据需要更新的**Bullet**预制体游戏对象。这意味着您已经准备好迎接下一个挑战——射击抛射物。

## 添加射击机制

现在我们有一个预制体对象可以使用，我们可以在按下鼠标左键时实例化并移动预制体的副本，以创建射击机制，如下所示：

1.  使用以下代码更新`PlayerBehavior`脚本：

```cs
public class PlayerBehavior : MonoBehaviour 
{
    **// 1**
    **public** **GameObject Bullet;**
    **public****float** **BulletSpeed =** **100f****;**

    **// 2**
    **private****bool** **_isShooting**;

    // ... No other variable changes needed ...

    void Start()
    {
        // ... No changes needed ...
    }

    void Update()
    {
        **// 3**
        **_isShooting |= Input.GetMouseButtonDown(****0****);**
        // ... No other changes needed ...
    }

    void FixedUpdate()
    {
        // ... No other changes needed ...

        **// 4**
        **if** **(_isShooting)**
        **{**
            **// 5**
            **GameObject newBullet = Instantiate(Bullet,**
                **this****.transform.position +** **new** **Vector3(****1****,** **0****,** **0****),**
                   **this****.transform.rotation);**
            **// 6**
            **Rigidbody BulletRB =** 
                 **newBullet.GetComponent<Rigidbody>();**

            **// 7**
            **BulletRB.velocity =** **this****.transform.forward *** 
                                            **BulletSpeed;**
        **}**
        **// 8**
        **_isShooting =** **false****;**
    }

    private bool IsGrounded()
    {
        // ... No changes needed ...
    }
} 
```

1.  在**检查器**中，将**Bullet**预制体从**项目**面板拖放到`PlayerBehavior`的**Bullet**属性中，如下截图所示：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_08_07.png)

图 8.7：设置子弹预制体

1.  玩游戏，并使用鼠标左键向玩家面对的方向发射抛射物！

让我们来分解这段代码，如下所示：

1.  我们创建了两个变量：一个用于存储子弹预制体，另一个用于保存子弹速度。

1.  像我们的跳跃机制一样，我们在`Update`方法中使用布尔值来检查我们的玩家是否应该射击。

1.  我们使用`or`逻辑运算符和`Input.GetMouseButtonDown()`来设置`_isShooting`的值，如果我们按下指定的按钮，则返回`true`，就像使用`Input.GetKeyDown()`一样。

+   `GetMouseButtonDown()`接受一个`int`参数来确定我们要检查哪个鼠标按钮；`0`是左键，`1`是右键，`2`是中间按钮或滚轮。

1.  然后我们检查我们的玩家是否应该使用`_isShooting`输入检查变量进行射击。

1.  每次按下鼠标左键时，我们创建一个本地的 GameObject 变量：

+   我们使用`Instantiate()`方法通过传入`Bullet`预制体来为`newBullet`分配一个 GameObject。我们还使用玩家胶囊体的位置将新的`Bullet`预制体放在玩家前面，以避免任何碰撞。

+   我们将其附加为`GameObject`，以将返回的对象显式转换为与`newBullet`相同类型的对象，这种情况下是一个 GameObject。

1.  我们调用`GetComponent()`来返回并存储`newBullet`上的 Rigidbody 组件。

1.  我们将 Rigidbody 组件的`velocity`属性设置为玩家的`transform.forward`方向乘以`BulletSpeed`：

+   改变`velocity`而不是使用`AddForce()`确保我们的子弹在被射出时不会被重力拉成弧线。

1.  最后，我们将`_isShooting`的值设置为`false`，这样我们的射击输入就会为下一个输入事件重置。

再次，您显著升级了玩家脚本正在使用的逻辑。现在，您应该能够使用鼠标射击抛射物，这些抛射物直线飞出玩家的位置。

然而，现在的问题是，您的游戏场景和层次结构中充斥着已使用的子弹对象。您的下一个任务是在它们被发射后清理这些对象，以避免任何性能问题。

## 管理对象的积累

无论您是编写完全基于代码的应用程序还是 3D 游戏，都很重要确保定期删除未使用的对象，以避免过载程序。我们的子弹在被射出后并不起重要作用；它们只是继续存在于靠近它们碰撞的墙壁或物体附近的地板上。

对于这样的射击机制，这可能导致成百上千甚至数千颗子弹，这是我们不想要的。你的下一个挑战是在设定延迟时间后销毁每颗子弹。

对于这个任务，我们可以利用已经学到的技能，让子弹自己负责其自毁行为，如下所示：

1.  在`Scripts`文件夹中创建一个新的 C#脚本，命名为`BulletBehavior`。

1.  将`BulletBehavior`脚本拖放到`Prefabs`文件夹中的`Bullet`预制体上，并添加以下代码：

```cs
using System.Collections;
using System.Collections.Generic;
using UnityEngine;
public class BulletBehavior : MonoBehaviour 
{
    // 1
    public float OnscreenDelay = 3f;

    void Start () 
    {
        // 2
        Destroy(this.gameObject, OnscreenDelay);
    }
} 
```

让我们来分解这段代码，如下所示：

1.  我们声明一个`float`变量来存储我们希望子弹预制体在被实例化后场景中保留多长时间。

1.  我们使用`Destroy()`方法来删除 GameObject。

+   `Destroy()`总是需要一个对象作为参数。在这种情况下，我们使用`this`关键字来指定脚本所附加的对象。

+   `Destroy()`可以选择以额外的`float`参数作为延迟，我们用它来让子弹在屏幕上停留一小段时间。

再次玩游戏，射击一些子弹，观察它们在特定延迟后自动从**层次结构**中删除。这意味着子弹执行了其定义的行为，而不需要另一个脚本告诉它该做什么，这是*组件*设计模式的理想应用。

现在我们的清理工作已经完成，你将学习到任何精心设计和组织的项目中的一个关键组件——管理器类。

# 创建游戏管理器

在学习编程时一个常见的误解是所有变量都应该自动设为公共的，但一般来说，这不是一个好主意。根据我的经验，变量应该从一开始就被视为受保护和私有的，只有在必要时才设为公共的。你会看到有经验的程序员通过管理器类来保护他们的数据，因为我们想养成良好的习惯，所以我们也会这样做。把管理器类看作一个漏斗，重要的变量和方法可以安全地被访问。

当我说安全时，我的意思就是这样，这在编程环境中可能看起来不熟悉。然而，当你有不同的类相互通信和更新数据时，情况可能会变得混乱。这就是为什么有一个单一的联系点，比如一个管理器类，可以将这种情况降到最低。我们将在下一节中学习如何有效地做到这一点。

## 跟踪玩家属性

*英雄诞生*是一个简单的游戏，所以我们需要跟踪的唯一两个数据点是玩家收集了多少物品和剩余多少生命值。我们希望这些变量是私有的，这样它们只能从管理器类中修改，给我们控制和安全性。你的下一个挑战是为*英雄诞生*创建一个游戏管理器，并为其添加有用的功能。

游戏管理器类将是你未来开发的任何项目中的一个不变的组成部分，所以让我们学习如何正确地创建一个，如下所示：

1.  在`Scripts`文件夹中创建一个新的 C#脚本，并命名为`GameBehavior`。

通常这个脚本会被命名为`GameManager`，但 Unity 保留了这个名称用于自己的脚本。如果你创建了一个脚本，而其名称旁边出现了齿轮图标而不是 C#文件图标，那就表示它是受限制的。

1.  使用**+** | **创建空对象**在**层次结构**中创建一个新的空游戏对象，并命名为`Game_Manager`。

1.  从**Scripts**文件夹中将`GameBehavior.cs`脚本拖放到`Game_Manager`对象上，如下截图所示：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_08_08.png)

图 8.8：附加游戏管理器脚本

管理器脚本和其他非游戏文件被设置在空对象上，尽管它们不与实际的 3D 空间交互。

1.  将以下代码添加到`GameBehavior.cs`中：

```cs
public class GameBehavior : MonoBehaviour 
{
    private int _itemsCollected = 0;
    private int _playerHP = 10;
} 
```

让我们来分解这段代码。我们添加了两个新的`private`变量来保存捡起的物品数量和玩家剩余的生命值；这些是`private`的，因为它们只能在这个类中被修改。如果它们被设为`public`，其他类可以随意改变它们，这可能导致变量存储不正确或并发数据。

将这些变量声明为`private`意味着你有责任控制它们的访问。下一个关于`get`和`set`属性的主题将向你介绍一种标准、安全的方法来完成这项任务。

## 获取和设置属性

我们已经设置好了管理器脚本和私有变量，但如果它们是私有的，我们如何从其他类中访问它们呢？虽然我们可以在`GameBehavior`中编写单独的公共方法来处理将新值传递给私有变量，但让我们看看是否有更好的方法来做这些事情。

在这种情况下，C#为所有变量提供了`get`和`set`属性，这非常适合我们的任务。将这些视为方法，无论我们是否显式调用它们，C#编译器都会自动触发它们，类似于 Unity 在场景启动时执行`Start()`和`Update()`。

`get`和`set`属性可以添加到任何变量中，无论是否有初始值，如下面的代码片段所示：

```cs
public string FirstName { get; set; };
// OR
public string LastName { get; set; } = "Smith"; 
```

然而，像这样使用它们并没有添加任何额外的好处；为此，您需要为每个属性包括一个代码块，如下面的代码片段所示：

```cs
public string FirstName
{
    get {
        // Code block executes when variable is accessed
    }
    set {
        // Code block executes when variable is updated
    }
} 
```

现在，`get`和`set`属性已经设置好，可以根据需要执行额外的逻辑。然而，我们还没有完成，因为我们仍然需要处理新逻辑。

每个`get`代码块都需要返回一个值，而每个`set`代码块都需要

分配一个值；这就是拥有一个私有变量（称为支持变量）和具有`get`和`set`属性的公共变量的组合发挥作用的地方。私有变量保持受保护状态，而公共变量允许从其他类进行受控访问，如下面的代码片段所示：

```cs
private string _firstName
public string FirstName {
    get { 
        **return** _firstName;
    }
    set {
        _firstName = **value**;
    }
} 
```

让我们来分解一下，如下所示：

+   我们可以使用`get`属性随时从私有变量中`return`值，而不实际给予外部类直接访问。

+   每当外部类分配新值给公共变量时，我们可以随时更新私有变量，使它们保持同步。

+   `value`关键字是被分配的任何新值的替代品。

如果没有实际应用，这可能看起来有点晦涩，所以让我们使用具有 getter 和 setter 属性的公共变量来更新`GameBehavior`中的私有变量。

现在我们了解了`get`和`set`属性访问器的语法，我们可以在我们的管理器类中实现它们，以提高效率和代码可读性。

根据以下方式更新`GameBehavior`中的代码：

```cs
public class GameBehavior : MonoBehaviour 
{
    private int _itemsCollected = 0; 
    private int _playerHP = 10;

    **// 1**
    **public****int** **Items**
    **{**
        **// 2**
        **get** **{** **return** **_itemsCollected; }**
        **// 3**
        **set** **{** 
               **_itemsCollected =** **value****;** 
               **Debug.LogFormat(****"Items: {0}"****, _itemsCollected);**
        **}**
    **}**
    **// 4**
    **public****int** **HP** 
    **{**
        **get** **{** **return** **_playerHP; }**
        **set** **{** 
               **_playerHP =** **value****;** 
               **Debug.LogFormat(****"Lives: {0}"****, _playerHP);**
         **}**
    **}**
} 
```

让我们来分解一下代码，如下所示：

1.  我们声明了一个名为`Items`的新`public`变量，带有`get`和`set`属性。

1.  每当从外部类访问`Items`时，我们使用`get`属性来`return`存储在`_itemsCollected`中的值。

1.  我们使用`set`属性将`_itemsCollected`分配给`Items`的新`value`，每当它更新时，还添加了`Debug.LogFormat()`调用以打印出`_itemsCollected`的修改值。

1.  我们设置了一个名为`HP`的`public`变量，带有`get`和`set`属性，以补充私有的`_playerHP`支持变量。

现在，两个私有变量都是可读的，但只能通过它们的公共对应变量进行访问；它们只能在`GameBehavior`中进行更改。通过这种设置，我们确保我们的私有数据只能从特定的接触点进行访问和修改。这使得我们更容易从其他机械脚本与`GameBehavior`进行通信，以及在本章末尾创建的简单 UI 中显示实时数据。

让我们通过在竞技场成功与物品拾取交互时更新`Items`属性来测试一下。

## 更新物品集合

现在我们在`GameBehavior`中设置了变量，我们可以在场景中每次收集一个`Item`时更新`Items`，如下所示：

1.  将以下突出显示的代码添加到`ItemBehavior`脚本中：

```cs
public class ItemBehavior : MonoBehaviour 
{
    **// 1**
    **public** **GameBehavior GameManager;**
    **void****Start****()**
    **{**
          **// 2**
          **GameManager = GameObject.Find(****"Game_Manager"****).GetComponent<GameBehavior>();**
    **}**
    void OnCollisionEnter(Collision collision)
    {
        if (collision.gameObject.name == "Player")
        {
            Destroy(this.transform.parent.gameObject);
            Debug.Log("Item collected!");
            **// 3**
            **GameManager.Items +=** **1****;**
        }
    }
} 
```

1.  点击播放并收集拾取物品，以查看经理脚本中的新控制台日志打印输出，如下面的屏幕截图所示：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_08_09.png)

图 8.9：收集拾取物品

让我们来分解一下代码，如下所示：

1.  我们创建一个新的`GameBehavior`类型变量来存储对附加脚本的引用。

1.  我们使用`Start()`来通过`Find()`在场景中查找`GameManager`并添加一个`GetComponent()`调用来初始化它。

你会经常在 Unity 文档和社区项目中看到这种代码以一行的形式完成。这是为了简单起见，但如果你更喜欢单独编写`Find()`和`GetComponent()`调用，那就尽管去做吧；清晰、明确的格式没有错。

1.  在`OnCollisionEnter()`中，在 Item Prefab 被销毁后，我们会在`GameManager`类中递增`Items`属性。

由于我们已经设置了`ItemBehavior`来处理碰撞逻辑，修改`OnCollisionEnter()`以在玩家拾取物品时与我们的管理类通信变得很容易。请记住，像这样分离功能是使代码更灵活，并且在开发过程中进行更改时不太可能出错的原因。

*英雄诞生*缺少的最后一部分是一种向玩家显示游戏数据的接口。在编程和游戏开发中，这被称为 UI。本章的最后一个任务是熟悉 Unity 如何创建和处理 UI 代码。

# 创建 GUI

在这一点上，我们有几个脚本一起工作，让玩家可以移动、跳跃、收集和射击。然而，我们仍然缺少任何一种显示或视觉提示，来显示我们玩家的统计数据，以及赢得和输掉游戏的方法。在我们结束这一节时，我们将专注于这两个主题。

## 显示玩家统计数据

UI 是任何计算机系统的视觉组件。鼠标光标、文件夹图标和笔记本电脑上的程序都是 UI 元素。对于我们的游戏，我们希望有一个简单的显示，让我们的玩家知道他们收集了多少物品，他们当前的生命值，并且在某些事件发生时给他们更新的文本框。

Unity 中的 UI 元素可以通过以下两种方式添加：

+   直接从**层次结构**面板中的**+**菜单中，就像任何其他 GameObject 一样

+   使用代码中内置的 GUI 类

我们将坚持第一种选择，因为内置的 GUI 类是 Unity 传统 UI 系统的一部分，我们希望保持最新，对吧？这并不是说你不能通过编程的方式做任何事情，但对于我们的原型来说，更新的 UI 系统更合适。

如果你对 Unity 中的程序化 UI 感兴趣，请自行查看文档：[`docs.unity3d.com/ScriptReference/GUI.html`](https://docs.unity3d.com/ScriptReference/GUI.html)。

你的下一个任务是在游戏场景中添加一个简单的 UI，显示存储在`GameBehavior.cs`中的已收集物品、玩家生命和进度信息变量。

首先，在我们的场景中创建三个文本对象。Unity 中的用户界面是基于画布的，这正是它的名字。把画布想象成一块空白的画布，你可以在上面绘画，Unity 会在游戏世界的顶部渲染它。每当你在**层次结构**面板中创建你的第一个 UI 元素时，一个**Canvas**父对象会与之一起创建。

1.  在**层次结构**面板中右键单击，选择**UI** | **Text**，并将新对象命名为**Health**。这将同时创建一个**Canvas**父对象和新的**Text**对象：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_08_10.png)

图 8.10：创建一个文本元素

1.  为了正确查看画布，请在“场景”选项卡顶部选择**2D**模式。从这个视图中，我们整个级别就是左下角的那条微小的白线。

+   即使**Canvas**和级别在场景中不重叠，当游戏运行时 Unity 会自动正确地叠加它们。![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_08_11.png)

图 8.11：Unity 编辑器中的 Canvas

1.  如果你在“层次结构”中选择**Health**对象，你会看到默认情况下新的文本对象被创建在画布的左下角，并且它有一整套可定制的属性，比如文本和颜色，在**检视器**窗格中：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_08_12.png)

图 8.12：Unity 画布上的文本元素

1.  在**Hierarchy**窗格中选择**Health**对象，单击**检视器**中**Rect Transform**组件的**Anchor**预设，选择**左上角**。

+   锚点设置了 UI 元素在画布上的参考点，这意味着无论设备屏幕的大小如何，我们的健康点始终锚定在屏幕的左上角！[](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_08_13.png)

图 8.13：设置锚点预设

1.  在**检视器**窗格中，将**Rect Transform**位置更改为**X**轴上的**100**和**Y**轴上的**-30**，以将文本定位在右上角。还将**Text**属性更改为**Player Health:**。我们将在以后的步骤中在代码中设置实际值！[](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_08_14.png)

图 8.14：设置文本属性

1.  重复步骤 1-5 以创建一个新的 UI **Text**对象，并命名为**Items**：

+   将锚点预设设置为**左上角**，**Pos X**设置为**100**，**Pos Y**设置为**-60**

+   将**Text**设置为**Items Collected:**![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_08_15.png)

图 8.15：创建另一个文本元素

1.  重复*步骤 1-5*以创建一个新的 UI **Text**对象，并命名为**Progress**：

+   将锚点预设设置为**底部中心**，**Pos X**设置为**0**，**Pos Y**设置为**15**，**Width**设置为**280**

+   将**Text**设置为**收集所有物品并赢得你的自由！**![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_08_16.png)

图 8.16：创建进度文本元素

现在我们的 UI 已经设置好了，让我们连接已经在游戏管理器脚本中拥有的变量。请按照以下步骤进行：

1.  使用以下代码更新`GameBehavior`以收集物品并在屏幕上显示文本：

```cs
// 1
using UnityEngine.UI; 
public class GameBehavior : MonoBehaviour 
{
    // 2
    public int MaxItems = 4;
    // 3
    public Text HealthText;     
    public Text ItemText;
    public Text ProgressText;
    // 4
    void Start()
    { 
        ItemText.text += _itemsCollected;
        HealthText.text += _playerHP;
    }
    private int _itemsCollected = 0;
    public int Items
    {
        get { return _itemsCollected; }
        set { 
            _itemsCollected = value; 
            **// 5**
            ItemText.text = "Items Collected: " + Items;
            // 6
            if(_itemsCollected >= MaxItems)
            {
                ProgressText.text = "You've found all the items!";
            } 
            else
            {
                ProgressText.text = "Item found, only " + (MaxItems - _itemsCollected) + " more to go!";
            }
        }
    }

    private int _playerHP = 10;
    public int HP 
    {
        get { return _playerHP; }
        set { 
            _playerHP = value;
            // 7
            HealthText.text = "Player Health: " + HP;
            Debug.LogFormat("Lives: {0}", _playerHP);
        }
    }
} 
```

1.  在**Hierarchy**中选择**Game_Manager**，并将我们的三个文本对象依次拖到**检视器**中的相应`GameBehavior`脚本字段中：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_08_17.png)

图 8.17：将文本元素拖到脚本组件

1.  运行游戏，看看我们新的屏幕 GUI 框，如下截图所示：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_08_18.png)

图 8.18：在播放模式中测试 UI 元素

让我们来分解代码，如下所示：

1.  我们添加了`UnityEngine.UI`命名空间，以便可以访问**Text**变量类型。

1.  我们为关卡中物品的最大数量创建了一个新的公共变量。

1.  我们创建了三个新的**Text**变量，将它们连接到**检视器**面板中。

1.  然后，我们使用`Start`方法使用**+=**运算符设置我们的健康和物品文本的初始值。

1.  每次收集一个物品，我们都会更新**ItemText**的`text`属性，显示更新后的`items`计数。

1.  我们在`_itemsCollected`的设置属性中声明了一个`if`语句。

+   如果玩家收集的物品数量大于或等于`MaxItems`，他们就赢了，`ProgressText.text`会更新。

+   否则，`ProgressText.text`显示还有多少物品可以收集。

1.  每当玩家的健康受到损害时，我们将在下一章中介绍，我们都会更新`HealthText`的`text`属性，显示新值。

现在玩游戏时，我们的三个 UI 元素显示出了正确的值；当收集一个物品时，`ProgressText`和`_itemsCollected`计数会更新，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_08_19.png)

图 8.19：更新 UI 文本

每个游戏都可以赢得或输掉。在本章的最后一节，您的任务是实现这些条件以及与之相关的 UI。

## 胜利和失败条件

我们已经实现了核心游戏机制和简单的 UI，但是*Hero Born*仍然缺少一个重要的游戏设计元素：胜利和失败条件。这些条件将管理玩家如何赢得或输掉游戏，并根据情况执行不同的代码。

回到*第六章*的游戏文档，*使用 Unity 忙碌起来*，我们将我们的胜利和失败条件设置如下：

+   在剩余至少 1 个健康点的情况下收集所有物品以获胜

+   从敌人那里受到伤害，直到健康点数为 0 为止

这些条件将影响我们的 UI 和游戏机制，但我们已经设置了`GameBehavior`来有效处理这一点。我们的`get`和`set`属性将处理任何与游戏相关的逻辑和 UI 更改，当玩家赢得或输掉游戏时。

我们将在本节中实现赢得游戏的逻辑，因为我们已经有了拾取系统。当我们在下一章中处理敌人 AI 行为时，我们将添加失败条件逻辑。您的下一个任务是在代码中确定游戏何时赢得。

我们始终希望给玩家清晰和即时的反馈，因此我们将首先添加赢得游戏的逻辑，如下所示：

1.  更新`GameBehavior`以匹配以下代码：

```cs
public class GameBehavior : MonoBehaviour 
{ 
    **// 1**
    **public** **Button WinButton;**
    private int _itemsCollected = 0;
    public int Items
    {
        get { return _itemsCollected; }
        set
        {
            _itemsCollected = value;
            ItemText.text = "Items Collected: " + Items;

            if (_itemsCollected >= MaxItems)
            {
                ProgressText.text = "You've found all the items!";

                **// 2**
                **WinButton.gameObject.SetActive(****true****);**
            }
            else
            {
                ProgressText.text = "Item found, only " + (MaxItems - _itemsCollected) + " more to go!";
            }
        }
    }
} 
```

1.  右键单击**Hierarchy**，然后选择**UI** | **Button**，然后将其命名为**Win Condition**：

+   选择**Win Condition**，将**Pos X**和**Pos Y**设置为**0**，将**Width**设置为**225**，将**Height**设置为**115**。![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_08_20.png)

图 8.20：创建 UI 按钮

1.  单击**Win Condition**按钮右侧的箭头以展开其文本子对象，然后更改文本为**You won!**：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_08_21.png)

图 8.21：更新按钮文本

1.  再次选择**Win Condition**父对象，然后单击**Inspector**右上角的复选标志。![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_08_22.png)

图 8.22：停用游戏对象

这将在我们赢得游戏之前隐藏按钮：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_08_23.png)

图 8.23：测试隐藏的 UI 按钮

1.  在**Hierarchy**中选择**Game_Manager**，然后将**Win Condition**按钮从**Hierarchy**拖动到**Inspector**中的**Game Behavior (Script)**，就像我们在文本对象中所做的那样！[](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_08_24.png)

图 8.24：将 UI 按钮拖动到脚本组件上

1.  在**Inspector**中将**Max Items**更改为`1`，以测试新屏幕，如下截图所示：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_08_25.png)

图 8.25：显示赢得游戏的屏幕

让我们来分解代码，如下所示：

1.  我们创建了一个 UI 按钮变量，以连接到**Hierarchy**中的**Win Condition**按钮。

1.  由于我们在游戏开始时将 Win Condition 按钮设置为**隐藏**，因此当游戏赢得时，我们会重新激活它。

将**Max Items**设置为`1`，**Win**按钮将在收集场景中唯一的`Pickup_Item`时显示出来。目前单击按钮不会产生任何效果，但我们将在下一节中解决这个问题。

## 使用指令和命名空间暂停和重新开始游戏

目前，我们的赢得条件按预期工作，但玩家仍然可以控制胶囊，并且在游戏结束后没有重新开始游戏的方法。Unity 在`Time`类中提供了一个名为`timeScale`的属性，当设置为`0`时，会冻结游戏场景。但是，要重新开始游戏，我们需要访问一个名为`SceneManagement`的**命名空间**，这在默认情况下无法从我们的类中访问。

命名空间收集并将一组类分组到特定名称下，以组织大型项目并避免可能共享相同名称的脚本之间的冲突。需要向类中添加`using`指令才能访问命名空间的类。

从 Unity 创建的所有 C#脚本都带有三个默认的`using`指令，如下面的代码片段所示：

```cs
using System.Collections;
using System.Collections.Generic;
using UnityEngine; 
```

这些允许访问常见的命名空间，但 Unity 和 C#还提供了许多其他可以使用`using`关键字后跟命名空间名称添加的命名空间。

由于我们的游戏在玩家赢或输时需要暂停和重新开始，这是一个很好的时机来使用默认情况下新的 C#脚本中不包括的命名空间。

1.  将以下代码添加到`GameBehavior`并播放：

```cs
using System.Collections;
using System.Collections.Generic;
using UnityEngine;
using UnityEngine.UI;
**// 1**
**using** **UnityEngine.SceneManagement;**
public class GameBehavior : MonoBehaviour 
{
    // ... No changes needed ...
    private int _itemsCollected = 0;
    public int Items
    {
        get { return _itemsCollected; }
        set { 
            _itemsCollected = value;

            if (_itemsCollected >= MaxItems)
            {
                ProgressText.text = "You've found all the items!";
                WinButton.gameObject.SetActive(true);

                **// 2**
                **Time.timeScale =** **0f****;**
            }
            else
            {
                ProgressText.text= "Item found, only " + (MaxItems – _itemsCollected) + " more to go!";
            }
        }
    }
    **public****void****RestartScene****()**
    **{**
        **// 3**
        **SceneManager.LoadScene(****0****);**
        **// 4**
        **Time.timeScale =** **1f****;**
    **}**

    // ... No other changes needed ...
} 
```

1.  从**Hierarchy**中选择**Win Condition**，在**Inspector**中向下滚动到**Button**组件的**OnClick**部分，然后单击加号图标：

+   每个 UI 按钮都有一个**OnClick**事件，这意味着您可以将来自脚本的方法分配给在按钮被按下时执行。

+   您可以在单击按钮时触发多个方法，但在这种情况下我们只需要一个！[](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_08_26.png)

图 8.26：按钮的 OnClick 部分

1.  从**Hierarchy**中，将**Game_Manager**拖放到**Runtime**下方的插槽中，告诉按钮我们要选择一个来自我们管理器脚本的方法在按钮被按下时触发！[](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_08_27.png)

图 8.27：在点击时设置游戏管理器对象

1.  选择**No Function**下拉菜单，选择**GameBehavior** | **RestartScene ()**来设置我们希望按钮执行的方法！[](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_08_28.png)

图 8.28：选择按钮点击的重新启动方法

1.  转到**Window** | **Rendering** | **Lighting**，并在底部选择**Generate Lighting**。确保未选择**Auto Generate**：

这一步是必要的，以解决 Unity 重新加载场景时没有任何照明的问题。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_08_29.png)

图 8.29：Unity 编辑器中的照明面板

让我们来分解代码，如下所示：

1.  我们使用`using`关键字添加了`SceneManagement`命名空间，该命名空间处理所有与场景相关的逻辑，如创建加载场景。

1.  当显示胜利屏幕时，我们将`Time.timeScale`设置为`0`，这将暂停游戏，禁用任何输入或移动。

1.  我们创建了一个名为`RestartScene`的新方法，并在单击胜利屏幕按钮时调用`LoadScene()`：

+   `LoadScene()`以`int`参数形式接受场景索引。

+   因为我们的项目中只有一个场景，所以我们使用索引`0`从头开始重新启动游戏。

1.  我们将`Time.timeScale`重置为默认值`1`，以便在场景重新启动时，所有控件和行为都能够再次执行。

现在，当您收集物品并单击胜利屏幕按钮时，关卡将重新开始，所有脚本和组件都将恢复到其原始值，并准备好进行另一轮！

# 摘要

恭喜！*英雄诞生*现在是一个可玩的原型。我们实现了跳跃和射击机制，管理了物理碰撞和生成对象，并添加了一些基本的 UI 元素来显示反馈。我们甚至已经实现了玩家赢得比赛时重置关卡的功能。

本章介绍了许多新主题，重要的是要回过头去确保您理解了我们编写的代码中包含了什么。特别注意我们对枚举、`get`和`set`属性以及命名空间的讨论。从现在开始，随着我们进一步深入 C#语言的可能性，代码将变得更加复杂。

在下一章中，我们将开始着手让我们的敌人游戏对象在我们离得太近时注意到我们的玩家，从而导致一种跟随和射击协议，这将提高我们玩家的赌注。

# 快速测验-与机械一起工作

1.  枚举类型的数据存储什么类型的数据？

1.  您将如何在活动场景中创建预制游戏对象的副本？

1.  哪些变量属性允许您在引用或修改它们的值时添加功能？

1.  哪个 Unity 方法显示场景中的所有 UI 对象？

# 加入我们的 Discord！

与其他用户一起阅读本书，与 Unity/C#专家和 Harrison Ferrone 一起阅读，通过*问我任何事*会话与作者交流，提出问题，为其他读者提供解决方案，等等。

立即加入！

[`packt.link/csharpunity2021`](https://packt.link/csharpunity2021)

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/QR_Code_9781801813945.png)


# 第九章：基本 AI 和敌人行为

虚拟场景需要冲突、后果和潜在奖励才能感觉真实。没有这三样东西，玩家就没有动力去关心他们游戏中的角色发生了什么，更不用说继续玩游戏了。虽然有很多游戏机制可以满足这些条件中的一个或多个，但没有什么能比得上一个会寻找你并试图结束你游戏的敌人。

编写一个智能敌人并不容易，并且通常需要长时间的工作和挫折。然而，Unity 内置了我们可以使用的功能、组件和类，以更用户友好的方式设计和实现 AI 系统。这些工具将推动*Hero Born*的第一个可玩版本完成，并为更高级的 C#主题提供一个跳板。

在本章中，我们将重点关注以下主题：

+   Unity 导航系统

+   静态对象和导航网格

+   导航代理

+   程序化编程和逻辑

+   承受和造成伤害

+   添加失败条件

+   重构和保持 DRY

让我们开始吧！

# 在 Unity 中导航 3D 空间

当我们谈论现实生活中的导航时，通常是关于如何从 A 点到 B 点的对话。在虚拟 3D 空间中导航基本上是一样的，但我们如何考虑自从我们第一次开始爬行以来积累的经验知识呢？从在平坦表面行走到爬楼梯和跳台阶，这些都是我们通过实践学会的技能；我们怎么可能在游戏中编程所有这些而不发疯呢？

在回答这些问题之前，您需要了解 Unity 提供了哪些导航组件。

## 导航组件

简短的答案是，Unity 花了很多时间完善其导航系统，并提供了我们可以用来控制可玩和不可玩角色如何移动的组件。以下每个组件都是 Unity 的标准组件，并且已经内置了复杂的功能：

+   **NavMesh**本质上是给定级别中可行走表面的地图；NavMesh 组件本身是从级别几何中创建的，在一个称为烘焙的过程中。将 NavMesh 烘焙到您的级别中会创建一个持有导航数据的独特项目资产。

+   如果**NavMesh**是级别地图，那么**NavMeshAgent**就是棋盘上的移动棋子。任何附有 NavMeshAgent 组件的对象都会自动避开其接触到的其他代理或障碍物。

+   导航系统需要意识到级别中任何可能导致 NavMeshAgent 改变其路线的移动或静止对象。将 NavMeshObstacle 组件添加到这些对象可以让系统知道它们需要避开。

虽然这对 Unity 导航系统的描述远非完整，但对于我们继续进行敌人行为已经足够了。在本章中，我们将专注于向我们的级别添加 NavMesh，将敌人预制件设置为 NavMeshAgent，并让敌人预制件以看似智能的方式沿着预定义路线移动。

在本章中，我们只会使用 NavMesh 和 NavMeshAgent 组件，但如果您想为您的级别增添一些趣味，可以查看如何在这里创建障碍物：[`docs.unity3d.com/Manual/nav-CreateNavMeshObstacle.html`](https://docs.unity3d.com/Manual/nav-CreateNavMeshObstacle.html)。

在设置“智能”敌人的第一个任务是在竞技场的可行走区域上创建一个 NavMesh。让我们设置和配置我们级别的 NavMesh：

1.  选择**环境**游戏对象，单击**检视器**窗口中**静态**旁边的箭头图标，并选择**导航静态**：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_09_01.png)

图 9.1：将对象设置为导航静态

1.  点击**是，更改子对象**当对话框弹出时，将所有**环境**子对象设置为**导航静态**：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_09_02.png)

图 9.2：更改所有子对象

1.  转到**窗口** | **AI** | **导航**，并选择**烘焙**选项卡。将所有设置保持为默认值，然后单击**烘焙**。烘焙完成后，你将在**场景**文件夹内看到一个新文件夹，其中包含照明、导航网格和反射探针数据：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_09_03.png)

图 9.3：烘焙导航网格

我们级别中的每个对象现在都标记为**导航静态**，这意味着我们新烘焙的 NavMesh 已根据其默认 NavMeshAgent 设置评估了它们的可访问性。在前面的屏幕截图中，你可以看到浅蓝色覆盖的地方是任何附有 NavMeshAgent 组件的对象的可行走表面，这是你的下一个任务。

## 设置敌人代理

让我们将敌人预制件注册为 NavMeshAgent：

1.  在**预制件**文件夹中选择敌人预制件，在**检视器**窗口中单击**添加组件**，并搜索**NavMesh Agent**：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_09_04.png)

图 9.4：添加 NavMeshAgent 组件

1.  从**层次结构**窗口中单击**+** **|** **创建空对象**，并将游戏对象命名为`Patrol_Route`：

+   选择`Patrol_Route`，单击**+** **|** **创建空对象**以添加一个子游戏对象，并将其命名为`Location_1`。将`Location_1`放置在级别的一个角落中：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_09_05.png)

图 9.5：创建一个空的巡逻路线对象

1.  在`Patrol_Route`中创建三个空的子对象，分别命名为`Location_2`，`Location_3`和`Location_4`，并将它们放置在级别的剩余角落，形成一个正方形：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_09_06.png)

图 9.6：创建所有空的巡逻路线对象

向敌人添加 NavMeshAgent 组件告诉 NavMesh 组件注意并将其注册为具有访问其自主导航功能的对象。在每个级别角落创建四个空游戏对象，布置我们希望敌人最终巡逻的简单路线；将它们分组在一个空的父对象中，使得在代码中更容易引用它们，并使得层次结构窗口更加有组织。现在剩下的就是编写代码让敌人走巡逻路线，这将在下一节中添加。

# 移动敌人代理

我们的巡逻地点已经设置好，敌人预制件有一个 NavMeshAgent 组件，但现在我们需要找出如何引用这些地点并让敌人自行移动。为此，我们首先需要谈论软件开发世界中的一个重要概念：程序化编程。

## 程序化编程

尽管在名称中有，但程序化编程的概念可能难以理解，直到你完全掌握它；一旦你掌握了，你就永远不会以相同的方式看待代码挑战。

任何在一个或多个连续对象上执行相同逻辑的任务都是程序化编程的完美候选者。当你调试数组、列表和字典时，已经做了一些程序化编程，使用`for`和`foreach`循环。每次执行这些循环语句时，都会对每个项目进行相同的`Debug.Log()`调用，依次迭代每个项目。现在的想法是利用这种技能获得更有用的结果。

程序化编程的最常见用途之一是将一个集合中的项目添加到另一个集合中，并在此过程中经常对其进行修改。这对我们的目的非常有效，因为我们希望引用`Patrol_Route`父对象中的每个子对象，并将它们存储在一个列表中。

## 参考巡逻地点

现在我们了解了程序化编程的基础知识，是时候获取对我们巡逻地点的引用，并将它们分配到一个可用的列表中了：

1.  将以下代码添加到`EnemyBehavior`中：

```cs
public class EnemyBehavior : MonoBehaviour
{ 
    **// 1** 
    **public** **Transform PatrolRoute;**
    **// 2** 
    **public** **List<Transform> Locations;**
    **void****Start****()** 
    **{** 
        **// 3** 
        **InitializePatrolRoute();**
    **}** 
          **// 4** 
    **void****InitializePatrolRoute****()** 
    **{** 
        **// 5** 
        **foreach****(Transform child** **in** **PatrolRoute)** 
        **{** 
            **// 6** 
            **Locations.Add(child);**
        **}** 
    **}**
    void OnTriggerEnter(Collider other) 
    { 
        // ... No changes needed ... 
    } 
    void OnTriggerExit(Collider other) 
    { 
        // ... No changes needed ... 
    } 
} 
```

1.  选择`Enemy`，并将`Patrol_Route`对象从**层次结构**窗口拖放到`EnemyBehavior`中的**Patrol Route**变量上：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_09_07.png)

图 9.7：将 Patrol_Route 拖到敌人脚本中

1.  点击**检视器**窗口中**位置**变量旁边的箭头图标，并运行游戏以查看列表填充：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_09_08.png)

图 9.8：测试过程式编程

让我们来分解一下代码：

1.  首先，声明一个变量来存储`PatrolRoute`空父级 GameObject。

1.  然后，声明一个`List`变量来保存`PatrolRoute`中所有子`Transform`组件。

1.  之后，它使用`Start()`在游戏开始时调用`InitializePatrolRoute()`方法。

1.  接下来，创建`InitializePatrolRoute()`作为一个私有的实用方法，以过程化地填充`Locations`与`Transform`值：

+   记住，不包括访问修饰符会使变量和方法默认为`private`。

1.  然后，使用`foreach`语句循环遍历`PatrolRoute`中的每个子 GameObject 并引用其 Transform 组件：

+   每个 Transform 组件都在`foreach`循环中声明的本地`child`变量中捕获。

1.  最后，通过使用`Add()`方法将每个顺序的`child` `Transform`组件添加到位置列表中，以便在`PatrolRoute`中循环遍历子对象时使用。

+   这样，无论我们在**Hierarchy**窗口中做出什么更改，`Locations`都将始终填充所有`PatrolRoute`父级下的`child`对象。

虽然我们可以通过直接从**Hierarchy**窗口将每个位置 GameObject 分配给`Locations`，通过拖放的方式，但是很容易丢失或破坏这些连接；对位置对象名称进行更改、对象的添加或删除，或项目的更新都可能导致类的初始化出现问题。通过在`Start()`方法中以过程化的方式填充 GameObject 列表或数组，更加安全和可读。

由于这个原因，我也倾向于在`Start()`方法中使用`GetComponent()`来查找并存储附加到给定类的组件引用，而不是在**Inspector**窗口中分配它们。

现在，我们需要让敌人对象按照我们制定的巡逻路线移动，这是你的下一个任务。

## 移动敌人

在`Start()`中初始化了一个巡逻位置列表后，我们可以获取敌人 NavMeshAgent 组件并设置它的第一个目的地。

更新`EnemyBehavior`使用以下代码并点击播放：

```cs
**// 1** 
**using** **UnityEngine.AI;** 
public class EnemyBehavior : MonoBehaviour  
{ 
    public Transform PatrolRoute;
    public List<Transform> Locations;
    **// 2** 
    **private****int** **_locationIndex =** **0****;** 
    **// 3** 
    **private** **NavMeshAgent _agent;** 
    void Start() 
    { 
        **// 4** 
        **_agent = GetComponent<NavMeshAgent>();** 
        InitializePatrolRoute(); 
        **// 5** 
        **MoveToNextPatrolLocation();** 
    }
    void InitializePatrolRoute()  
    { 
         // ... No changes needed ... 
    } 
    **void****MoveToNextPatrolLocation****()** 
    **{** 
        **// 6** 
        **_agent.destination = Locations[_locationIndex].position;** 
    **}** 
    void OnTriggerEnter(Collider other) 
    { 
        // ... No changes needed ... 
    } 
    void OnTriggerExit(Collider other) 
    { 
        // ... No changes needed ... 
    }
} 
```

让我们来分解一下代码：

1.  首先，添加`UnityEngine.AI`的`using`指令，以便`EnemyBehavior`可以访问 Unity 的导航类，这种情况下是`NavMeshAgent`。

1.  然后，声明一个变量来跟踪敌人当前正在向其行走的巡逻位置。由于`List`项是从零开始索引的，我们可以让 Enemy Prefab 在`Locations`中存储的顺序中移动巡逻点之间移动。

1.  接下来，声明一个变量来存储附加到 Enemy GameObject 的 NavMeshAgent 组件。这是`private`的，因为没有其他类应该能够访问或修改它。

1.  之后，它使用`GetComponent()`来查找并返回附加的 NavMeshAgent 组件给代理。

1.  然后，在`Start()`方法中调用`MoveToNextPatrolLocation()`方法。

1.  最后，声明`MoveToNextPatrolLocation()`为一个私有方法并设置`_agent.destinat``ion`：

+   `destination`是 3D 空间中的`Vector3`位置。

+   `Locations[_locationIndex]`获取`Locations`中给定索引处的 Transform 项。

+   添加`.position`引用了 Transform 组件的`Vector3`位置。

现在，当我们的场景开始时，位置被填充了巡逻点，并且`MoveToNextPatrolLocation()`被调用以将 NavMeshAgent 组件的目标位置设置为位置列表中的第一个项目`_locationIndex 0`。下一步是让敌人对象从第一个巡逻位置移动到所有其他位置。

我们的敌人移动到第一个巡逻点没问题，但然后停下了。我们希望它能够在每个顺序位置之间持续移动，这将需要在`Update()`和`MoveToNextPatrolLocation()`中添加额外的逻辑。让我们创建这个行为。

添加以下代码到`EnemyBehavior`并点击播放：

```cs
public class EnemyBehavior : MonoBehaviour  
{ 
    // ... No changes needed ... 
    **void****Update****()** 
    **{** 
        **// 1** 
        **if****(_agent.remainingDistance <** **0.2f** **&& !_agent.pathPending)** 
        **{** 
            **// 2** 
            **MoveToNextPatrolLocation();**
        **}**
    **}**
    void MoveToNextPatrolLocation() 
    { 
        **// 3** 
        **if** **(Locations.Count ==** **0****)** 
            **return****;** 

        _agent.destination = Locations[_locationIndex].position;
        **// 4** 
        **_locationIndex = (_locationIndex +** **1****) % Locations.Count;**
    }
    // ... No other changes needed ... 
} 
```

让我们来分解一下代码：

1.  首先，它声明`Update()`方法，并添加一个`if`语句来检查两个不同条件是否为真：

+   `remainingDistance`返回 NavMeshAgent 组件当前距离其设定目的地的距离，所以我们检查是否小于 0.2。

+   `pathPending`根据 Unity 是否为 NavMeshAgent 组件计算路径返回`true`或`false`布尔值。

1.  如果`_agent`非常接近目的地，并且没有其他路径正在计算，`if`语句将返回`true`并调用`MoveToNextPatrolLocation()`。

1.  在这里，我们添加了一个`if`语句来确保在执行`MoveToNextPatrolLocation()`中的其余代码之前，`Locations`不为空：

+   如果`Locations`为空，我们使用`return`关键字退出方法而不继续执行。

这被称为防御性编程，结合重构，这是在向更中级的 C#主题迈进时必不可少的技能。我们将在本章末考虑重构。

1.  然后，我们将`_locationIndex`设置为它的当前值，`+1`，然后取`Locations.Count`的模(`%`)：

+   这将使索引从 0 增加到 4，然后重新从 0 开始，这样我们的敌人预制就会沿着连续的路径移动。

+   模运算符返回两个值相除的余数——当结果为整数时，2 除以 4 的余数为 2，所以 2 % 4 = 2。同样，4 除以 4 没有余数，所以 4 % 4 = 0。

将索引除以集合中的最大项目数是一种快速找到下一个项目的方法。如果你对模运算符不熟悉，请回顾*第二章*，*编程的基本组成部分*。

现在我们需要在`Update()`中每帧检查敌人是否朝着设定的巡逻位置移动；当它靠近时，将触发`MoveToNextPatrolLocation()`，这会增加`_locationIndex`并将下一个巡逻点设置为目的地。

如果你将**Scene**视图拖到**Console**窗口旁边，如下截图所示，然后点击播放，你可以看到敌人预制在关卡的拐角处连续循环行走：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_09_09.png)

图 9.9：测试敌人巡逻路线

敌人现在沿着地图外围巡逻路线，但当它在预设范围内时，它不会寻找玩家并发动攻击。在下一节中，您将使用 NavAgent 组件来做到这一点。

# 敌人游戏机制

现在我们的敌人正在持续巡逻，是时候给它一些互动机制了；如果我们让它一直在走动而没有对抗我们的方式，那就没有太多的风险或回报了。

## 寻找并摧毁：改变代理的目的地

在本节中，我们将专注于在玩家靠近时切换敌人 NavMeshAgent 组件的目标，并在发生碰撞时造成伤害。当敌人成功降低玩家的健康时，它将返回到巡逻路线，直到下一次与玩家相遇。

然而，我们不会让我们的玩家束手无策；我们还将添加代码来跟踪敌人的健康状况，检测敌人是否成功被玩家的子弹击中，以及何时需要摧毁敌人。

现在敌人预制正在巡逻移动，我们需要获取玩家位置的引用，并在它靠近时改变 NavMeshAgent 的目的地。

1.  将以下代码添加到`EnemyBehavior`中：

```cs
public class EnemyBehavior : MonoBehaviour  
{ 
    **// 1** 
    **public** **Transform Player;**
    public Transform PatrolRoute;
    public List<Transform> Locations;
    private int _locationIndex = 0;
    private NavMeshAgent _agent;
    void Start() 
    { 
        _agent = GetComponent<NavMeshAgent>();
        **// 2** 
        **Player = GameObject.Find(****"Player"****).transform;** 
        // ... No other changes needed ... 
    } 
    /* ... No changes to Update,  
           InitializePatrolRoute, or  
           MoveToNextPatrolLocation ... */ 
    void OnTriggerEnter(Collider other) 
    { 
        if(other.name == "Player") 
        { 
            **// 3** 
            **_agent.destination = Player.position;**
            Debug.Log("Enemy detected!");
        } 
    } 
    void OnTriggerExit(Collider other)
    { 
        // .... No changes needed ... 
    }
} 
```

让我们来分解这段代码：

1.  首先，它声明一个`public`变量来保存`Player`胶囊体的`Transform`值。

1.  然后，我们使用`GameObject.Find("Player")`来返回场景中玩家对象的引用：

+   直接添加`.transform`引用了同一行中对象的`Transform`值。

1.  最后，在`OnTriggerEnter()`中，当玩家进入我们之前设置的敌人攻击区域时，我们将`_agent.destination`设置为玩家的`Vector3`位置。

如果你现在玩游戏并离巡逻的敌人太近，你会发现它会中断原来的路径直接向你走来。一旦它到达玩家，`Update()`方法中的代码将再次接管，敌人预制件将恢复巡逻。

我们仍然需要让敌人以某种方式伤害玩家，我们将在下一节中学习如何做到这一点。

## 降低玩家生命值

虽然我们的敌人机制已经取得了长足的进步，但当敌人预制件与玩家预制件发生碰撞时什么都不发生仍然让人失望。为了解决这个问题，我们将新的敌人机制与游戏管理器联系起来。

使用以下代码更新`PlayerBehavior`并点击播放：

```cs
public class PlayerBehavior : MonoBehaviour  
{ 
    // ... No changes to public variables needed ... 
    **// 1** 
    **private** **GameBehavior _gameManager;**
    void Start() 
    { 
        _rb = GetComponent<Rigidbody>();
        _col = GetComponent<CapsuleCollider>();
        **// 2** 
        **_gameManager = GameObject.Find(****"Game_Manager"****).GetComponent<GameBehavior>();**
    **}** 
    /* ... No changes to Update,  
           FixedUpdate, or  
           IsGrounded ... */ 
    **// 3** 
    **void****OnCollisionEnter****(****Collision collision****)**
    **{**
        **// 4** 
        **if****(collision.gameObject.name ==** **"Enemy"****)**
        **{**
            **// 5** 
            **_gameManager.HP -=** **1****;**
        **}**
    **}**
} 
```

让我们来分解一下代码：

1.  首先，它声明一个`private`变量来保存我们在场景中拥有的`GameBehavior`实例的引用。

1.  然后，它找到并返回附加到场景中的`Game Manager`对象的`GameBehavior`脚本：

+   在同一行上使用`GetComponent()`和`GameObject.Find()`是减少不必要的代码行的常见方法。

1.  由于我们的玩家是发生碰撞的对象，因此在`PlayerBehavior`中声明`OnCollisionEnter()`是有道理的。

1.  接下来，我们检查碰撞对象的名称；如果是敌人预制件，我们执行`if`语句的主体。

1.  最后，我们使用`_gameManager`实例从公共`HP`变量中减去`1`。

现在每当敌人跟踪并与玩家发生碰撞时，游戏管理器将触发 HP 的设置属性。UI 将使用新的玩家生命值更新，这意味着我们有机会为失败条件后期添加一些额外的逻辑。

## 检测子弹碰撞

现在我们有了失败条件，是时候为我们的玩家添加一种反击敌人攻击并幸存下来的方式了。

打开`EnemyBehavior`并使用以下代码进行修改：

```cs
public class EnemyBehavior : MonoBehaviour  
{ 
    //... No other variable changes needed ... 
    **// 1** 
    **private****int** **_lives =** **3****;** 
    **public****int** **EnemyLives** 
    **{** 
        **// 2** 
        **get** **{** **return** **_lives; }**
        **// 3** 
        **private****set** 
        **{** 
            **_lives =** **value****;** 
            **// 4** 
            **if** **(_lives <=** **0****)** 
            **{** 
                **Destroy(****this****.gameObject);** 
                **Debug.Log(****"Enemy down."****);** 
            **}**
        **}**
    **}**
    /* ... No changes to Start,  
           Update,  
           InitializePatrolRoute,  
           MoveToNextPatrolLocation,  
           OnTriggerEnter, or  
           OnTriggerExit ... */ 
    **void****OnCollisionEnter****(****Collision collision****)** 
    **{** 
        **// 5** 
        **if****(collision.gameObject.name ==** **"Bullet(Clone)"****)** 
        **{** 
            **// 6** 
            **EnemyLives -=** **1****;**
            **Debug.Log(****"Critical hit!"****);**
        **}**
    **}**
} 
```

让我们来分解一下代码：

1.  首先，它声明了一个名为`_lives`的`private int`变量，并声明了一个名为`EnemyLives`的`public`后备变量。这将使我们能够控制`EnemyLives`的引用和设置方式，就像在`GameBehavior`中一样。

1.  然后，我们将`get`属性设置为始终返回`_lives`。

1.  接下来，我们使用`private set`将`EnemyLives`的新值分配给`_lives`，以保持它们两者同步。

我们之前没有见过`private get`或`set`，但它们可以像任何其他可执行代码一样具有访问修饰符。将`get`或`set`声明为`private`意味着只有父类才能访问它们的功能。

1.  然后，我们添加一个`if`语句来检查`_lives`是否小于或等于 0，这意味着敌人应该死了：

+   在这种情况下，我们销毁`Enemy`游戏对象并在控制台上打印一条消息。

1.  因为`Enemy`是被子弹击中的对象，所以在`EnemyBehavior`中包含对这些碰撞的检查是合理的，使用`OnCollisionEnter()`。

1.  最后，如果碰撞对象的名称与子弹克隆对象匹配，我们将`EnemyLives`减少`1`并打印出另一条消息。

请注意，我们检查的名称是`Bullet(Clone)`，即使我们的子弹预制件的名称是`Bullet`。这是因为 Unity 会在使用`Instantiate()`方法创建的任何对象后添加`(Clone)`后缀，而我们的射击逻辑就是这样创建的。

你也可以检查游戏对象的标签，但由于这是 Unity 特有的功能，我们将保持代码不变，只用纯 C#来处理事情。

现在，玩家可以在敌人试图夺取其生命时进行反击，射击三次并摧毁敌人。再次，我们使用`get`和`set`属性来处理额外的逻辑，证明这是一个灵活且可扩展的解决方案。完成这些后，你的最后任务是更新游戏管理器的失败条件。

## 更新游戏管理器

要完全实现失败条件，我们需要更新管理器类：

1.  打开`GameBehavior`并添加以下代码：

```cs
public class GameBehavior : MonoBehaviour  
{ 
    // ... No other variable changes... 
    **// 1** 
    **public** **Button LossButton;** 
    private int _itemsCollected = 0; 
    public int Items 
    { 
        // ... No changes needed ... 
    } 
    private int _playerHP = 10; 
    public int HP 
    { 
        get { return _playerHP; } 
        set {  
            _playerHP = value; 
                HealthText.text = "Player Health: " + HP; 
            **// 2** 
            **if****(_playerHP <=** **0****)** 
            **{** 
                **ProgressText.text=** **"You want another life with** **that?"****;**
    **LossButton.gameObject.SetActive(****true****);** 
                **Time.timeScale =** **0****;** 
            **}** 
            **else** 
            **{** 
                **ProgressText.text =** **"Ouch... that's got hurt."****;** 
            **}**
        }
    }
} 
```

1.  在**Hierarchy**窗口中，右键单击**Win Condition**，选择**Duplicate**，并将其命名为**Loss Condition**：

+   单击**Loss Condition**左侧的箭头以展开它，选择**Text**对象，并将文本更改为**You lose...**

1.  在**Hierarchy**窗口中选择**Game_Manager**，并将**Loss Condition**拖放到**Game Behavior（Script）**组件中的**Loss Button**插槽中：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_09_11.png)

图 9.10：在检查器窗格中完成了带有文本和按钮变量的游戏行为脚本

让我们分解一下代码：

1.  首先，我们声明了一个新的按钮，当玩家输掉游戏时我们想要显示它。

1.  然后，我们添加一个`if`语句来检查`_playerHP`何时下降到`0`以下：

+   如果为`true`，则更新`ProgessText`和`Time.timeScale`，并激活失败按钮。

+   如果玩家在敌人碰撞后仍然存活，`ProgessText`会显示不同的消息：“哎呀...那一定很疼。”。

现在，在`GameBehavior.cs`中将`_playerHP`更改为 1，并让敌人预制件与您发生碰撞，观察发生了什么。

完成了！您已成功添加了一个可以对玩家造成伤害并受到反击的“智能”敌人，以及通过游戏管理器的失败界面。在我们完成本章之前，还有一个重要的主题需要讨论，那就是如何避免重复的代码。

重复的代码是所有程序员的梦魇，因此学会如何在项目中尽早避免它是有意义的！

# 重构和保持 DRY

**不要重复自己**（DRY）首字母缩写是软件开发者的良心：它告诉您何时有可能做出糟糕或可疑的决定，并在工作完成后给您一种满足感。

在实践中，重复的代码是编程生活的一部分。试图通过不断思考未来来避免它会在项目中设置许多障碍，这似乎不值得继续。处理重复代码的更有效和理智的方法是快速识别它何时何地发生，然后寻找最佳的移除方法。这个任务被称为重构，我们的`GameBehavior`类现在可以使用一些它的魔力。

您可能已经注意到我们在两个不同的地方设置了进度文本和时间刻度，但我们可以很容易地在一个地方为自己创建一个实用方法来完成这些工作。

要重构现有的代码，您需要按照以下步骤更新`GameBehavior.cs`：

```cs
public class GameBehavior: MonoBehaviour
{
    **// 1**
    **public****void****UpdateScene****(****string** **updatedText****)**
    **{**
        **ProgressText.text = updatedText;**
        **Time.timeScale =** **0f****;**
    **}**
    private int _itemsCollected = 0;
    public int Items
    {
        get { return _itemsCollected; }
        set
        {
            _itemsCollected = value;
            ItemText.text = "Items Collected: " + Items;
            if (_itemsCollected >= MaxItems)
            {
                WinButton.gameObject.SetActive(true);
                **// 2**
                **UpdateScene(****"You've found all the items!"****);**
            }
            else
            {
                ProgressText.text = "Item found, only " + (MaxItems - _itemsCollected) + " more to go!";
            }
        }
    }
    private int _playerHP = 10;
    public int HP
    {
        get { return _playerHP; }
        set
        {
            _playerHP = value;
            HealthText.text = "Player Health: " + HP;
            if (_playerHP <= 0)
            {
                LossButton.gameObject.SetActive(true);
                **// 3**
                **UpdateScene(****"You want another life with that?"****);**
            }
            else
            {
                ProgressText.text = "Ouch... that's got hurt.";
            }
            Debug.LogFormat("Lives: {0}", _playerHP);
        }
    }
} 
```

让我们分解一下代码：

1.  我们声明了一个名为`UpdateScene`的新方法，它接受一个字符串参数，我们想要将其分配给`ProgressText`，并将`Time.timeScale`设置为`0`。

1.  我们删除了重复代码的第一个实例，并使用我们的新方法在游戏获胜时更新了场景。

1.  我们删除了重复代码的第二个实例，并在游戏失败时更新了场景。

如果您在正确的地方寻找，总是有更多的重构工作可以做。

# 总结

通过这样，我们的敌人和玩家互动就完成了。我们可以造成伤害，也可以承受伤害，失去生命，并进行反击，同时更新屏幕上的 GUI。我们的敌人使用 Unity 的导航系统在竞技场周围行走，并在玩家指定范围内时切换到攻击模式。每个 GameObject 负责其行为、内部逻辑和对象碰撞，而游戏管理器则跟踪管理游戏状态的变量。最后，我们学习了简单的过程式编程，以及当重复指令被抽象成它们的方法时，代码可以变得更加清晰。

在这一点上，您应该感到有所成就，特别是如果您作为一个完全的初学者开始阅读本书。在构建一个可工作的游戏的同时熟悉一种新的编程语言并不容易。在下一章中，您将被介绍一些 C#中级主题，包括新的类型修饰符、方法重载、接口和类扩展。

# 小测验-人工智能和导航

1.  在 Unity 场景中如何创建 NavMesh 组件？

1.  什么组件将 GameObject 标识为 NavMesh？

1.  在一个或多个连续对象上执行相同的逻辑是哪种编程技术的例子？

1.  DRY 首字母缩写代表什么？

# 加入我们的 Discord！

与其他用户一起阅读这本书，与 Unity/C#专家和 Harrison Ferrone 一起阅读。提出问题，为其他读者提供解决方案，通过*问我任何事*与作者交流，以及更多内容。

立即加入！

[`packt.link/csharpunity2021`](https://packt.link/csharpunity2021)

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/QR_Code_9781801813945.png)


# 第十章：重新审视类型、方法和类

现在您已经使用 Unity 内置类编写了游戏的机制和交互，是时候扩展我们的核心 C#知识，专注于我们所奠定的基础的中级应用。我们将重新审视旧朋友——变量、类型、方法和类——但我们将针对它们的更深层次应用和相关用例。我们将要讨论的许多主题并不适用于*Hero Born*的当前状态，因此一些示例将是独立的，而不是直接应用于游戏原型。

我将向您介绍大量新信息，所以如果您在任何时候感到不知所措，请不要犹豫，重新阅读前几章以巩固这些基础知识。我们还将利用本章来摆脱游戏机制和特定于 Unity 的功能，而是专注于以下主题：

+   中级修饰符

+   方法重载

+   使用`out`和`ref`参数

+   使用接口

+   抽象类和重写

+   扩展类功能

+   命名空间冲突

+   类型别名

让我们开始吧！

# 访问修饰符

虽然我们已经习惯了将公共和私有访问修饰符与变量声明配对，就像我们对玩家健康和收集的物品所做的那样，但我们还有一长串修饰符关键字没有看到。在本章中，我们无法详细介绍每一个，但我们将专注于五个关键字，这将进一步加深您对 C#语言的理解，并提高您的编程技能。

本节将涵盖以下列表中的前三个修饰符，而剩下的两个将在*中级 OOP*部分讨论：

+   `const`

+   `readonly`

+   `静态`

+   `抽象`

+   `override`

您可以在[`docs.microsoft.com/en-us/dotnet/csharp/language-reference/keywords/modifiers`](https://docs.microsoft.com/en-us/dotnet/csharp/language-reference/keywords/modifiers)找到可用修饰符的完整列表。

让我们从前面列表中提供的前三个访问修饰符开始。

## 常量和只读属性

有时您需要创建存储常量、不变值的变量。在变量的访问修饰符后添加`const`关键字就可以做到这一点，但只适用于内置的 C#类型。例如，您不能将我们的`Character`类的实例标记为常量。`GameBehavior`类中`MaxItems`是一个常量值的好选择：

```cs
public **const** int MaxItems = 4; 
```

上面的代码本质上将`MaxItems`的值锁定为`4`，使其不可更改。常量变量的问题在于它们只能在声明时分配一个值，这意味着我们不能让`MaxItems`没有初始值。作为替代方案，我们可以使用`readonly`，它不允许您写入变量，这意味着它不能被更改：

```cs
public **readonly** int MaxItems; 
```

使用`readonly`关键字声明变量将为我们提供与常量相同的不可修改的值，同时仍然允许我们随时分配其初始值。这个关键字的一个好地方可能是我们脚本中的`Start()`或`Awake()`方法。

## 使用`static`关键字

我们已经讨论了如何从类蓝图创建对象或实例，以及所有属性和方法都属于特定的实例，就像我们的第一个`Character`类实例一样。虽然这对于面向对象的功能非常有用，但并非所有类都需要被实例化，也不是所有属性都需要属于特定的实例。但是，静态类是封闭的，这意味着它们不能用于类继承。

实用方法是这种情况的一个很好的例子，我们不一定关心实例化特定的`Utility`类实例，因为它的所有方法都不依赖于特定对象。您的任务是在一个新的脚本中创建这样一个实用方法。

让我们创建一个新的类来保存一些未来处理原始计算或重复逻辑的方法，这些方法不依赖于游戏玩法：

1.  在`Scripts`文件夹中创建一个新的 C#脚本，并将其命名为`Utilities`。

1.  打开它并添加以下代码：

```cs
using System.Collections; 
using System.Collections.Generic; 
using UnityEngine; 

// 1 
using UnityEngine.SceneManagement; 

// 2 
public static class Utilities  
{ 
    // 3 
    public static int PlayerDeaths = 0; 

    // 4 
    public static void RestartLevel() 
    { 
        SceneManager.LoadScene(0); 
        Time.timeScale = 1.0f; 
    } 
} 
```

1.  从`GameBehavior`中删除`RestartLevel()`中的代码，而是使用以下代码调用新的`utility`方法：

```cs
// 5
public void RestartScene()
{
    Utilities.RestartLevel();
} 
```

让我们来分解一下代码：

1.  首先，它添加了`using SceneManagement`指令，以便我们可以访问`LoadScene()`方法。

1.  然后，它将`Utilities`声明为一个不继承自`MonoBehavior`的公共`static`类，因为我们不需要它在游戏场景中。

1.  接下来，它创建一个公共的`static`变量来保存我们的玩家死亡并重新开始游戏的次数。

1.  然后，它声明一个公共的`static`方法来保存我们的级别重启逻辑，这目前是硬编码在`GameBehavior`中的。

1.  最后，我们在`GameBehavior`中对`RestartLevel()`的更新在赢或输按钮被按下时从静态的`Utilities`类调用。请注意，我们不需要`Utilities`类的实例来调用该方法，因为它是静态的——只需使用点符号。

我们现在已经将重启逻辑从`GameBehavior`中提取出来，并放入其静态类中，这样可以更容易地在整个代码库中重用。将其标记为`static`也将确保我们在使用其类成员之前永远不必创建或管理`Utilities`类的实例。

非静态类可以具有静态和非静态的属性和方法。但是，如果整个类标记为静态，所有属性和方法都必须遵循相同的规则。

这就结束了我们对变量和类型的第二次访问，这将使您能够在未来管理更大更复杂的项目时构建自己的一套工具和实用程序。现在是时候转向方法及其中级功能，其中包括方法重载和`ref`和`out`参数。

# 重温方法

自从我们在*第三章*学习如何使用方法以来，方法一直是我们代码的重要组成部分，但有两种中级用例我们还没有涵盖：方法重载和使用`ref`和`out`参数关键字。

## 方法重载

术语**方法重载**指的是创建多个具有相同名称但不同签名的方法。方法的签名由其名称和参数组成，这是 C#编译器识别它的方式。以以下方法为例：

```cs
public bool AttackEnemy(int damage) {} 
```

`AttackEnemy()`的方法签名如下所示：

```cs
AttackEnemy(int) 
```

现在我们知道了`AttackEnemy()`的签名，可以通过改变参数的数量或参数类型本身来重载它，同时保持其名称不变。这在您需要给定操作的多个选项时提供了额外的灵活性。

`Utilities`中的`RestartLevel()`方法是方法重载派上用场的一个很好的例子。目前，`RestartLevel()`只重新启动当前级别，但如果我们扩展游戏，使其包含多个场景会怎么样？我们可以重构`RestartLevel()`以接受参数，但这通常会导致臃肿和混乱的代码。

`RestartLevel()`方法再次是测试我们新知识的一个很好的候选项。您的任务是重载它以接受不同的参数。

让我们添加一个重载版本的`RestartLevel()`：

1.  打开`Utilities`并添加以下代码：

```cs
public static class Utilities  
{
    public static int PlayerDeaths = 0;
    public static void RestartLevel()
    {
        SceneManager.LoadScene(0);
        Time.timeScale = 1.0f;
    }
    **// 1** 
    **public****static****bool****RestartLevel****(****int** **sceneIndex****)**
    **{** 
        **// 2** 
        **SceneManager.LoadScene(sceneIndex);**
        **Time.timeScale =** **1.0f****;**
        **// 3** 
        **return****true****;**
    **}** 
} 
```

1.  打开`GameBehavior`并将对`Utilities.RestartLevel()`方法的调用更新为以下内容：

```cs
// 4
public void RestartScene()
{
    Utilities.RestartLevel(0);
} 
```

让我们来分解一下代码：

1.  首先，它声明了一个重载版本的`RestartLevel()`方法，该方法接受一个`int`参数并返回一个`bool`。

1.  然后，它调用`LoadScene()`并传入`sceneIndex`参数，而不是手动硬编码该值。

1.  接下来，在新场景加载后，它将返回`true`并且`timeScale`属性已被重置。

1.  最后，我们对`GameBehavior`的更新调用了重载的`RestartLevel()`方法，并将`0`作为`sceneIndex`传入。重载方法会被 Visual Studio 自动检测到，并按数字显示，如下所示：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_10_01.png)

图 10.1：Visual Studio 中的多个方法重载

`RestartLevel()`方法中的功能现在更加可定制，可以处理以后可能需要的其他情况。在这种情况下，它是从我们选择的任何场景重新开始游戏。

方法重载不仅限于静态方法——这只是与前面的示例一致。只要其签名与原始方法不同，任何方法都可以进行重载。

接下来，我们将介绍另外两个可以提升你的方法游戏水平的主题——`ref`和`out`参数。

## ref 参数

当我们在*第五章* *使用类、结构体和面向对象编程*中讨论类和结构体时，我们发现并非所有对象都是以相同的方式传递的：值类型是按副本传递的，而引用类型是按引用传递的。然而，我们没有讨论当对象或值作为参数传递到方法中时，它们是如何使用的。

默认情况下，所有参数都是按值传递的，这意味着传递到方法中的变量不会受到方法体内对其值所做更改的影响。当我们将它们用作方法参数时，这可以保护我们免受不需要的变量更改。虽然这对大多数情况都适用，但在某些情况下，您可能希望通过引用传递方法参数，以便可以更新它并在原始变量中反映出这种更改。在参数声明前加上`ref`或`out`关键字将标记参数为引用。

以下是使用`ref`关键字时需要牢记的几个关键点：

+   参数在传递到方法之前必须初始化。

+   在结束方法之前，您不需要初始化或分配引用参数值。

+   具有 get 或 set 访问器的属性不能用作`ref`或`out`参数。

让我们通过添加一些逻辑来跟踪玩家重新开始游戏的次数来尝试一下。

让我们创建一个方法来更新`PlayerDeaths`，以查看正在通过引用传递的方法参数的作用。

打开`Utilities`并添加以下代码：

```cs
public static class Utilities  
{ 
    public static int PlayerDeaths = 0; 
    **// 1** 
    **public****static****string****UpdateDeathCount****(****ref****int** **countReference****)** 
    **{** 
        **// 2** 
        **countReference +=** **1****;** 
        **return****"Next time you'll be at number "** **+ countReference;**
    **}**
    public static void RestartLevel()
    { 
       // ... No changes needed ...   
    } 
    public static bool RestartLevel(int sceneIndex)
    { 
        **// 3** 
        **Debug.Log(****"Player deaths: "** **+ PlayerDeaths);** 
        **string** **message = UpdateDeathCount(****ref** **PlayerDeaths);**
        **Debug.Log(****"Player deaths: "** **+ PlayerDeaths);**
        **Debug.Log(message);**
        SceneManager.LoadScene(sceneIndex);
        Time.timeScale = 1.0f;
        return true;
    }
} 
```

让我们来分解一下代码：

1.  首先，声明一个新的`static`方法，返回一个`string`并接受一个通过引用传递的`int`。

1.  然后，它直接更新引用参数，将其值增加 1，并返回一个包含新值的字符串。

1.  最后，它在将`PlayerDeaths`变量传递给`UpdateDeathCount()`之前和之后，在`RestartLevel(int sceneIndex)`中对其进行调试。我们还将`UpdateDeathCount()`返回的字符串值的引用存储在`message`变量中并打印出来。

如果你玩游戏并且失败，调试日志将显示`UpdateDeathCount()`内的`PlayerDeaths`增加了 1，因为它是通过引用而不是通过值传递的：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_10_02.png)

图 10.2：`ref`参数的示例输出

为了清晰起见，我们可以在没有`ref`参数的情况下更新玩家死亡计数，因为`UpdateDeathCount()`和`PlayerDeaths`在同一个脚本中。但是，如果情况不是这样，而你希望具有相同的功能，`ref`参数非常有用。

在这种情况下，我们使用`ref`关键字是为了举例说明，但我们也可以直接在`UpdateDeathCount()`内更新`PlayerDeaths`，或者在`RestartLevel()`内添加逻辑，只有在由于失败而重新开始时才触发`UpdateDeathCount()`。

现在我们知道如何在项目中使用`ref`参数，让我们来看看`out`参数以及它如何起到略有不同的作用。

## out 参数

`out`关键字和`ref`执行相同的工作，但有不同的规则，这意味着它们是相似的工具，但不能互换使用，每个都有自己的用例。

+   参数在传递到方法之前不需要初始化。

+   引用的参数值在调用方法中返回之前不需要初始化或赋值。

例如，我们可以在`UpdateDeathCount()`中用`out`替换`ref`，只要在方法返回之前初始化或赋值`countReference`参数：

```cs
public static string UpdateDeathCount(**out** int countReference) 
{ 
     countReference = 1;
     return "Next time you'll be at number " + countReference;
} 
```

使用`out`关键字的方法更适合需要从单个函数返回多个值的情况，而`ref`关键字在只需要修改引用值时效果最好。它也比`ref`关键字更灵活，因为在方法中使用参数之前不需要设置初始参数值。`out`关键字在需要在更改之前初始化参数值时特别有用。尽管这些关键字有点晦涩，但对于特殊用例来说，将它们放入你的 C#工具包中是很重要的。

有了这些新的方法特性，现在是重新审视**面向对象编程**（**OOP**）的时候了。这个主题涉及的内容太多，不可能在一两章中覆盖所有内容，但在你的开发生涯初期，有一些关键工具会很有用。OOP 是一个你鼓励在完成本书后继续学习的主题。

# 中级 OOP

面向对象的思维方式对于创建有意义的应用程序和理解 C#语言在幕后的工作方式至关重要。棘手的部分在于，类和结构本身并不是面向对象编程和设计对象的终点。它们始终是你的代码的构建块，但是类在单一继承方面受到限制，这意味着它们只能有一个父类或超类，而结构根本不能继承。因此，你现在应该问自己的问题很简单：“我如何才能根据特定情况创建出相同蓝图的对象，并让它们执行不同的操作？”

为了回答这个问题，我们将学习接口、抽象类和类扩展。

## 接口

将功能组合在一起的一种方法是通过接口。与类一样，接口是数据和行为的蓝图，但有一个重要的区别：它们不能有任何实际的实现逻辑或存储值。相反，它们包含了实现蓝图，由采用的类或结构填写接口中概述的值和方法。你可以在类和结构中使用接口，一个类或结构可以采用的接口数量没有上限。

记住，一个类只能有一个父类，结构根本不能有子类。将功能分解为接口可以让你像从菜单中选择食物一样构建类，选择你希望它们表现的方式。这将极大地提高你的代码库的效率，摆脱了冗长、混乱的子类层次结构。

例如，如果我们希望我们的敌人在靠近时能够还击我们的玩家，我们可以创建一个父类，玩家和敌人都可以从中派生，这将使它们都基于相同的蓝图。然而，这种方法的问题在于敌人和玩家不一定会共享相同的行为和数据。

更有效的处理方式是定义一个接口，其中包含可射击对象需要执行的蓝图，然后让敌人和玩家都采用它。这样，它们就可以自由地分开并展示不同的行为，同时仍然共享共同的功能。

将射击机制重构为接口是一个我留给你的挑战，但我们仍然需要知道如何在代码中创建和采用接口。在这个例子中，我们将创建一个所有管理器脚本可能需要实现的接口，以共享一个公共结构。

在`Scripts`文件夹中创建一个新的 C#脚本，命名为`IManager`，并更新其代码如下：

```cs
using System.Collections;
using System.Collections.Generic;
using UnityEngine; 
// 1 
public interface IManager  
{ 
    // 2 
    string State { get; set; } 
    // 3 
    void Initialize();
} 
```

让我们来分解一下代码：

1.  首先，它使用`interface`关键字声明了一个名为`IManager`的公共接口。

1.  然后，它在`IManager`中添加了一个名为`State`的`string`变量，带有`get`和`set`访问器来保存采用类的当前状态。

所有接口属性至少需要一个 get 访问器才能编译，但如果需要的话也可以有 get 和 set 访问器。

1.  最后，它定义了一个名为`Initialize()`的方法，没有返回类型，供采用类实现。但是，你绝对可以在接口内部的方法中有一个返回类型；没有规定不允许这样做。

你现在为所有管理器脚本创建了一个蓝图，这意味着采用这个接口的每个管理器脚本都需要有一个状态属性和一个初始化方法。你的下一个任务是使用`IManager`接口，这意味着它需要被另一个类采用。

为了保持简单，让游戏管理器采用我们的新接口并实现其蓝图。

使用以下代码更新`GameBehavior`：

```cs
**// 1** 
public class GameBehavior : MonoBehaviour, **IManager** 
{ 
    **// 2** 
    **private****string** **_state;** 
    **// 3** 
    **public****string** **State**  
    **{** 
        **get** **{** **return** **_state; }** 
        **set** **{ _state =** **value****; }** 
    **}**
    // ... No other changes needed ... 
    **// 4** 
    **void****Start****()** 
    **{** 
        **Initialize();** 
    **}**
    **// 5** 
    **public****void****Initialize****()**  
    **{** 
        **_state =** **"Game Manager initialized.."****;**
        **Debug.Log(_state);**
    **}**
} 
```

让我们来分解一下代码：

1.  首先，它声明了`GameBehavior`采用`IManager`接口，使用逗号和它的名称，就像子类化一样。

1.  然后，它添加了一个私有变量，我们将用它来支持我们必须从`IManager`实现的公共`State`值。

1.  接下来，它添加了在`IManager`中声明的公共`State`变量，并使用`_state`作为其私有备份变量。

1.  之后，它声明了`Start()`方法并调用了`Initialize()`方法。

1.  最后，它声明了在`IManager`中声明的`Initialize()`方法，其中包含一个设置和打印公共`State`变量的实现。

通过这样做，我们指定`GameBehavior`采用`IManager`接口，并实现其`State`和`Initialize()`成员，如下所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_10_03.png)

图 10.3：接口的示例输出

这样做的好处是，实现是特定于`GameBehavior`的；如果我们有另一个管理器类，我们可以做同样的事情，但逻辑不同。只是为了好玩，让我们设置一个新的管理器脚本来测试一下：

1.  在**Project**中，在**Scripts**文件夹内右键单击，选择**Create** | **C# Script**，然后命名为`DataManager`。

1.  使用以下代码更新新脚本并采用`IManager`接口：

```cs
using System.Collections;
using System.Collections.Generic;
using UnityEngine;
public class DataManager : MonoBehaviour, IManager
{
    private string _state;
    public string State
    {
        get { return _state; }
        set { _state = value; }
    }
    void Start()
    {
        Initialize();
    }
    public void Initialize()
    {
        _state = "Data Manager initialized..";
        Debug.Log(_state);
    }
} 
```

1.  将新脚本拖放到**Hierarchy**面板中的**Game_Manager**对象上：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_10_04.png)

图 10.4：附加到 GameObject 的数据管理器脚本

1.  然后点击播放：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_10_05.png)

图 10.5：数据管理器初始化的输出

虽然我们可以通过子类化来完成所有这些工作，但我们将受到一个父类限制，适用于所有我们的管理器。相反，我们可以选择添加新的接口。我们将在*第十二章*“保存、加载和序列化数据”中重新讨论这个新的管理器脚本。这为构建类打开了一整个新的可能性世界，其中之一是一个称为抽象类的新面向对象编程概念。

## 抽象类

另一种分离常见蓝图并在对象之间共享它们的方法是抽象类。与接口类似，抽象类不能包含任何方法的实现逻辑；但是，它们可以存储变量值。这是与接口的关键区别之一——在可能需要设置初始值的情况下，抽象类将是一种选择。

任何从抽象类继承的类都必须完全实现所有标记为`abstract`关键字的变量和方法。在想要使用类继承而不必编写基类默认实现的情况下，它们可能特别有用。

例如，让我们将刚刚编写的`IManager`接口功能作为抽象基类来看看它会是什么样子。*不要更改我们项目中的任何实际代码*，因为我们仍然希望保持事情的正常运行：

```cs
// 1 
public abstract class BaseManager  
{ 
    // 2 
    protected string _state = "Manager is not initialized...";
    public abstract string State { get; set; }
    // 3 
    public abstract void Initialize();
} 
```

让我们分解一下代码：

1.  首先，使用`abstract`关键字声明了一个名为`BaseManager`的新类。

1.  然后，它创建了两个变量：一个名为`_state`的`protected string`，只能被从`BaseManager`继承的类访问。我们还为`_state`设置了一个初始值，这是我们在接口中无法做到的。

+   我们还有一个名为`State`的抽象字符串，带有要由子类实现的`get`和`set`访问器。

1.  最后，它将`Initialize()`作为`abstract`方法添加，也要在子类中实现。

这样做，我们创建了一个与接口相同的抽象类。在这种设置中，`BaseManager`具有与`IManager`相同的蓝图，允许任何子类使用`override`关键字定义它们对`state`和`Initialize()`的实现：

```cs
// 1 
public class CombatManager: BaseManager  
{ 
    // 2 
    public override string State 
    { 
        get { return _state; } 
        set { _state = value; } 
    }
    // 3 
    public override void Initialize() 
    { 
        _state = "Combat Manager initialized..";
        Debug.Log(_state);
    }
} 
```

如果我们分解前面的代码，我们可以看到以下内容：

1.  首先，它声明了一个名为`CombatManager`的新类，该类继承自`BaseManager`抽象类。

1.  然后，它使用`override`关键字添加了从`BaseManager`中实现的`State`变量。

1.  最后，它再次使用`override`关键字从`BaseManager`中添加了`Initialize()`方法的实现，并设置了受保护的`_state`变量。

尽管这只是接口和抽象类的冰山一角，但它们的可能性应该在你的编程大脑中跳动。接口将允许您在不相关的对象之间传播和共享功能片段，从而在代码方面形成类似构建块的组装。

另一方面，抽象类将允许您保持 OOP 的单继承结构，同时将类的实现与其蓝图分离。这些方法甚至可以混合使用，因为抽象类可以像非抽象类一样采用接口。

对于复杂的主题，您的第一站应该是文档。在[`docs.microsoft.com/en-us/dotnet/csharp/language-reference/keywords/abstract`](https://docs.microsoft.com/en-us/dotnet/csharp/language-reference/keywords/abstract)和[`docs.microsoft.com/en-us/dotnet/csharp/language-reference/keywords/interface`](https://docs.microsoft.com/en-us/dotnet/csharp/language-reference/keywords/interface)上查看它。

您并不总是需要从头开始构建一个新类。有时，向现有类添加您想要的功能或逻辑就足够了，这称为类扩展。

## 类扩展

让我们远离自定义对象，谈谈如何扩展现有类，使它们符合我们自己的需求。类扩展的理念很简单：取一个现有的内置 C#类，并添加任何您需要的功能。由于我们无法访问 C#构建的底层代码，这是获取对象语言已经具有的自定义行为的唯一方法。

类只能通过方法进行修改——不允许变量或其他实体。然而，尽管这可能有所限制，但它使语法保持一致：

```cs
public **static** returnType MethodName(**this** **ExtendingClass** localVal) {} 
```

扩展方法的声明与普通方法相同，但有一些注意事项：

+   所有扩展方法都需要标记为`static`。

+   第一个参数需要是`this`关键字，后面跟着我们想要扩展的类的名称和一个本地变量名称：

+   这个特殊的参数让编译器识别该方法为扩展方法，并为我们提供了现有类的本地引用。

+   任何类方法和属性都可以通过局部变量访问。

+   将扩展方法存储在静态类中是常见的，而静态类又存储在其命名空间中。这使您可以控制其他脚本可以访问您的自定义功能。

您的下一个任务是通过向内置的 C# `String`类添加一个新方法来将类扩展付诸实践。

通过向`String`类添加自定义方法来实践扩展。在`Scripts`文件夹中创建一个新的 C#脚本，命名为`CustomExtensions`，并添加以下代码：

```cs
using System.Collections; 
using System.Collections.Generic;
using UnityEngine;  
// 1 
namespace CustomExtensions  
{ 
    // 2 
    public static class StringExtensions 
    { 
        // 3 
        public static void FancyDebug(this string str)
        { 
            // 4 
            Debug.LogFormat("This string contains {0} characters.", str.Length);
        }
    }
} 
```

让我们来分解一下代码：

1.  首先，它声明了一个名为`CustomExtensions`的命名空间，用于保存所有扩展类和方法。

1.  然后，为了组织目的，它声明了一个名为`StringExtensions`的`static`类；每组类扩展都应遵循此设置。

1.  接下来，它向`StringExtensions`类添加了一个名为`FancyDebug`的`static`方法：

+   第一个参数`this string str`标记该方法为扩展。

+   `str`参数将保存对`FancyDebug()`所调用的实际文本值的引用；我们可以在方法体内操作`str`，作为所有字符串文字的替代。

1.  最后，每当执行`FancyDebug`时，它都会打印出一个调试消息，使用`str.Length`来引用调用该方法的字符串变量。

实际上，这将允许您向现有的 C#类或甚至您自己的自定义类添加任何自定义功能。现在扩展是`String`类的一部分，让我们来测试一下。要使用我们的新自定义字符串方法，我们需要在想要访问它的任何类中包含它。

打开`GameBehavior`并使用以下代码更新类：

```cs
using System.Collections; 
using System.Collections.Generic; 
using UnityEngine; 
**// 1** 
**using** **CustomExtensions;** 

public class GameBehavior : MonoBehaviour, IManager 
{ 
    // ... No changes needed ... 
    void Start() 
    { 
        // ... No changes needed ... 
    } 
    public void Initialize()  
    { 
        _state = "Game Manager initialized..";
        **// 2** 
        **_state.FancyDebug();**
        Debug.Log(_state);
    }
} 
```

让我们来分解一下代码：

1.  首先，在文件顶部使用`using`指令添加`CustomExtensions`命名空间。

1.  然后，它在`Initialize()`内部使用点表示法在`_state`字符串变量上调用`FancyDebug`，以打印出其值具有的个体字符数。

通过`FancyDebug()`扩展整个`string`类意味着任何字符串变量都可以访问它。由于第一个扩展方法参数引用了`FancyDebug()`所调用的任何`string`值，因此其长度将被正确打印出来，如下所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/B17573_10_06.png)

图 10.6：自定义扩展的示例输出

也可以使用相同的语法扩展自定义类，但如果您控制一个类，直接将额外功能添加到类中更常见。

本章我们将探讨的最后一个主题是命名空间，我们在本书的前面简要了解过。在下一节中，您将了解命名空间在 C#中扮演的更大角色，以及如何创建您自己的类型别名。

# 命名空间冲突和类型别名

随着您的应用程序变得更加复杂，您将开始将代码分成命名空间，确保您可以控制何时何地访问它。您还将使用第三方软件工具和插件，以节省实现已经可用的功能的时间。这两种情况都表明您正在不断提高您的编程知识，但它们也可能引起命名空间冲突。

**命名空间冲突**发生在有两个或更多具有相同名称的类或类型时，这种情况比你想象的要多。

良好的命名习惯往往会产生类似的结果，不知不觉中，您将处理多个名为`Error`或`Extension`的类，而 Visual Studio 则会抛出错误。幸运的是，C#对这些情况有一个简单的解决方案：**类型别名**。

定义类型别名可以让您明确选择在给定类中要使用的冲突类型，或者为现有的冗长名称创建一个更用户友好的名称。类型别名是通过`using`指令在类文件顶部添加的，后跟别名和分配的类型：

```cs
using AliasName = type; 
```

例如，如果我们想要创建一个类型别名来引用现有的`Int64`类型，我们可以这样说：

```cs
using CustomInt = System.Int64; 
```

现在`CustomInt`是`System.Int64`类型的类型别名，编译器将把它视为`Int64`，让我们可以像使用其他类型一样使用它：

```cs
public CustomInt PlayerHealth = 100; 
```

你可以使用类型别名来使用你的自定义类型，或者使用相同的语法来使用现有的类型，只要它们在脚本文件的顶部与其他`using`指令一起声明。

有关`using`关键字和类型别名的更多信息，请查看 C#文档[`docs.microsoft.com/en-us/dotnet/csharp/language-reference/keywords/using-directive`](https://docs.microsoft.com/en-us/dotnet/csharp/language-reference/keywords/using-directive)。

# 摘要

有了新的修饰符、方法重载、类扩展和面向对象的技能，我们离 C#之旅的终点只有一步之遥。记住，这些中级主题旨在让你思考知识的更复杂应用；不要认为你在本章学到的就是这些概念的全部。把它当作一个起点，然后继续前进。

在下一章中，我们将讨论泛型编程的基础知识，获得一些委托和事件的实际经验，并最后概述异常处理。

# 小测验-升级

1.  哪个关键字会将变量标记为不可修改，但需要初始值？

1.  你会如何创建一个基本方法的重载版本？

1.  类和接口之间的主要区别是什么？

1.  你会如何解决类中的命名空间冲突？

# 加入我们的 Discord！

与其他用户、Unity/C#专家和 Harrison Ferrone 一起阅读本书。提出问题，为其他读者提供解决方案，通过*问我任何事*与作者交流等等。

立即加入！

[`packt.link/csharpunity2021`](https://packt.link/csharpunity2021)

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/lrn-cs-dev-gm-unity21/img/QR_Code_9781801813945.png)
