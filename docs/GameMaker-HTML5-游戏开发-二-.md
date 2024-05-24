# GameMaker HTML5 游戏开发（二）

> 原文：[`zh.annas-archive.org/md5/B91F6649162E9805B55AF1CE820DC361`](https://zh.annas-archive.org/md5/B91F6649162E9805B55AF1CE820DC361)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：冒险开始

在本章中，我们将创建一个有趣的小动作冒险游戏，这将建立在我们的基础知识之上。我们将从一个可以在世界中导航并具有短程近战攻击的动画玩家角色开始。游戏世界将由多个房间组成，玩家将能够从一个房间移动到另一个房间，同时保留所有他们的统计数据。我们将把所有玩家控制的代码和处理墙壁碰撞的代码放在一个脚本中，以创建一个更高效的项目。

如下截图所示，这个游戏的主题是高中的恐怖，世界里会有三个基本人工智能的敌人：一个幽灵图书管理员，一个乱斗，和一个教练。幽灵图书管理员会在玩家接近它的休息地点时出现，并追逐玩家直到距离太远，然后返回原来的位置。乱斗会在房间里漫游，如果它发现玩家，它会增加体积和速度。教练是奖杯的守护者，会独自在世界中导航。如果它看到玩家，它会追击并避开墙壁和其他教练，如果足够接近，它会对玩家进行近战攻击。

![冒险开始](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-gmkr/img/4100OT_04_16.jpg)

# 创建动画角色

到目前为止，我们创建的玩家对象非常基本。在第一章中，*与您的第一个游戏一起了解 Studio*，玩家没有动画。在第三章中，*射击游戏：创建一个横向卷轴射击游戏*，飞船有动画，但始终面向右侧。在本章中，我们将拥有一个可以朝四个方向移动并具有每个方向的动画精灵的角色。我们还将实现一个近战攻击，可以在角色面对的方向上使用。

## 简化角色移动

玩家角色的行走循环需要四个单独的精灵。我们将先介绍第一个，然后您可以创建其他三个。

1.  让我们从创建一个名为`Chapter_04`的新项目开始。

1.  创建一个精灵，命名为`spr_Player_WalkRight`。

1.  加载`第四章/精灵/Player_WalkRight.gif`，并勾选**删除背景**。

1.  将**原点**设置为**中心**。

1.  单击**修改掩码**以打开**掩码属性**编辑器，并在**边界框**下选择**完整图像**的单选按钮。这将设置碰撞框为整个精灵，如下截图所示：![简化角色移动](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-gmkr/img/4100OT_04_01.jpg)

1.  点击**确定**。重复此过程以加载`spr_Player_WalkLeft`，`spr_Player_WalkUp`和`spr_Player_WalkDown`。

1.  创建一个对象，`obj_Player`，并将`spr_Player_WalkRight`分配为精灵。实际上，在这里设置玩家精灵的哪一个并不重要，因为我们将使用代码来改变显示的精灵。

1.  我们需要设置一些初始变量，因此创建一个新脚本，`scr_Player_Create`，并编写以下代码：

```js
mySpeed = 4;
myDirection = 0;
isAttacking = false;
isWalking = false;
health = 100;
image_speed = 0.5;
```

前两个变量是玩家速度和方向的占位符。这将很有用，因为我们可以影响这些值，而不影响对象的本地`mySpeed`和`myDirection`变量，比如在对象面对一个方向移动时产生的击退效果。变量`isAttacking`将用于指示我们何时发起战斗，`isWalking`将指示玩家何时移动。接下来，我们有全局变量`health`，设置为 100%。最后，我们将动画速度设置为 50%，以便行走循环播放正确。

### 注意

要了解更多关于 GameMaker: Studio 内置变量和函数的信息，请点击**帮助** | **目录**查看 GameMaker 用户手册。

1.  现在我们可以开始玩家的移动了。我们不再为每个键创建多个脚本，而是将所有控件放入一个单独的脚本中，简化代码。创建一个新脚本，`scr_Player_Step`，并从以下代码开始：

```js
isWalking = false;
if (keyboard_check(vk_right) && place_free(x + mySpeed, y))
{
    x += mySpeed;
    myDirection = 0;
    sprite_index = spr_Player_WalkRight;
    isWalking = true;
}
```

我们首先将`isWalking`设置为`false`，使其成为玩家正在进行的默认状态。之后，我们检查键盘是否按下右箭头键（`vk_right`），并检查当前位置右侧是否有实体物体。`place_free`函数将返回指定点是否无碰撞。如果玩家能够移动并且按下了键，我们就向右移动，并将方向设置为零以表示向右。我们将精灵更改为面向右侧的行走循环，然后将`isWalking`更改为`true`，这将覆盖我们将其设置为`false`的第一行代码。

1.  重复这段代码，针对剩下的三个方向进行调整。每个方向都应该查看哪个键被按下，并查看从该位置是否有任何碰撞。

1.  在移动控件完成之前，我们还有一件事要做。如果玩家没有移动，我们希望动画停止，并在开始移动时重新开始播放。在脚本的末尾，添加以下代码：

```js
if (isWalking == true)
{
    image_speed = 0.5;
} else {
    image_speed = 0;
}
```

我们创建了变量`isWalking`来在行走和停止状态之间切换。如果玩家在移动，精灵将播放动画。如果玩家没有移动，我们也停止动画。

当代码完成时，应该如下所示：

```js
isWalking = false;
if (keyboard_check(vk_right) && place_free(x + mySpeed, y))
{
    x += mySpeed;
    myDirection = 0;
    sprite_index = spr_Player_WalkRight;
    isWalking = true;
}
if (keyboard_check(vk_up) && place_free(x, y - mySpeed))
{
    y -= mySpeed;
    myDirection = 90;
    sprite_index = spr_Player_WalkUp;
    isWalking = true;
}
if (keyboard_check(vk_left) && place_free(x - mySpeed, y))
{
    x -= mySpeed;
    myDirection = 180;
    sprite_index = spr_Player_WalkLeft;
    isWalking = true;
}
if (keyboard_check(vk_down) && place_free(x, y + mySpeed))
{
    y += mySpeed;
    myDirection = 270;
    sprite_index = spr_Player_WalkDown;
    isWalking = true;
}
if (isWalking == true)
{
    image_speed = 0.5;
} else {
    image_speed = 0;
} 
```

1.  将这些脚本应用到适当的事件中，`scr_Player_Create`的**创建**事件，以及`scr_Player_Step`的**步进**事件。

玩家已经准备好移动和正确播放动画了，但如果没有添加一些实体障碍物，我们将无法完全测试代码。让我们建一堵墙。

1.  创建一个精灵，`spr_Wall`，加载`第四章/精灵/墙.png`，并取消选中**删除背景**。我们使用 PNG 文件，因为这堵墙略微透明，这在以后装饰房间时会很有用。

1.  创建一个新对象，`obj_Wall`，并将精灵设置为`spr_Wall`。

1.  勾选**实体**框。现在这堵墙被标识为可碰撞的对象。

1.  创建一个新的房间，命名为`沙盒`。我们将使用这个房间来测试功能。

1.  在房间的中心某处放置一个`obj_Player`的实例。

1.  在房间的周边放置`obj_Wall`的实例，并添加一些额外的部分，如下屏幕截图所示：![简化角色移动](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-gmkr/img/4100OT_04_02.jpg)

1.  运行游戏。此时玩家应该能够在开放区域自由移动，并在与墙碰撞时停止。

## 实施近战攻击

现在我们已经让玩家移动正常了，我们可以开始进行攻击了。我们正在创建的攻击只需要影响玩家角色前面的物体。为了实现这一点，我们将创建一个近战攻击对象，它将在命令下生成并在游戏中自行移除。

1.  创建一个精灵，`spr_Player_Attack`，加载`第四章/精灵/Player_Attack.gif`，并选中**删除背景**。这是一个动画精灵，代表挥动的近战攻击。

1.  我们希望碰撞区域影响精灵的整个高度，但不影响整个宽度。点击**修改掩码**，在**掩码属性**编辑器中，选择**边界框**下的**手动**单选按钮。

1.  调整**边界框**的值为**左**：`0`，**右**：`24`，**顶部**：`0`和**底部**：`4`。最终结果应该看起来像以下的屏幕截图。点击**确定**。![实施近战攻击](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-gmkr/img/4100OT_04_03.jpg)

1.  我们希望这个对象始终出现在玩家的前面。确保这一点的最简单方法之一是让这个对象随着玩家一起旋转。为了实现这一点，将**原点**设置为**X:** `-16` **Y:** `24`。将 X 坐标设置为左侧意味着这个对象在生成时将有 16 像素的偏移。然后我们可以旋转攻击以匹配玩家的方向。

1.  创建一个对象，`obj_Player_Attack`，并将`spr_Player Attack`分配为其精灵。

1.  将**深度**设置为`-100`。**深度**决定了一个对象实例在屏幕上是在另一个对象的后面还是上面。将其设置为负值意味着它将在具有更高深度值的任何对象上绘制。将值设置为`-100`允许我们在默认的`0`和`-99`之间拥有其他深度的对象，而无需担心以后需要重新调整事物。

1.  创建一个新的脚本，`scr_Player_Attack_Create`，其中包含以下代码：

```js
image_angle = obj_Player.myDirection;
image_speed = 0.3;
alarm[0] = 6;
obj_Player.isAttacking = true;
```

这就是我们将图像旋转到与玩家面向相同方向的地方，结合我们设置的偏移原点，这意味着它将出现在玩家的前面。我们还会减慢动画速度，并设置一个六帧的警报。这个警报将在触发时移除攻击对象。最后，我们告诉玩家正在进行攻击。

1.  在`obj_Player_Attack`中添加一个**创建**事件，并附上这个脚本。

1.  让我们继续进行警报脚本，`scr_Player_Attack_Alarm`。它不仅需要移除攻击，还需要让玩家知道它已经消失，他们可以再次进行攻击。我们只需要两行代码就可以做到这一切：

```js
obj_Player.isAttacking = false;
instance_destroy();
```

我们可以直接与玩家的`isAttacking`变量交谈，并将其设置回`false`。然后我们销毁近战攻击的实例。将这个脚本附加到**Alarm 0**事件。

1.  现在我们只需要让玩家生成一个攻击的实例。重新打开`scr_Player_Step`，在底部添加以下代码：

```js
if (keyboard_check_pressed(ord('Z')) && isAttacking == false)
{
    instance_create(x, y, obj_Player_Attack);
}
```

`keyboard_check_pressed`函数只在按下键时激活，而不是在按下位置，而在这种情况下，我们正在检查*Z*键。键盘上的各种字母没有特殊命令，因此我们需要使用`ord`函数，它返回传递给它的字符的相应 ASCII 代码。我们还检查玩家当前是否没有进行攻击。如果一切顺利，我们生成攻击，攻击将改变`isAttacking`变量为 true，这样就只会发生一次。

### 注意

在使用`ord`函数时，始终使用大写字母，否则可能会得到错误的数字！

1.  运行游戏。你应该能够按下*Z*键，无论角色面向哪个方向，都能看到玩家面前独特的挥动动作，如下截图所示。玩家现在已经准备好战斗了！实施近战攻击

# 在房间之间导航

如果一切都发生在一个非常大的房间里，冒险游戏会变得相当无聊。这不仅效率低下，而且世界也会缺乏探索的感觉。从一个房间切换到另一个房间很容易，但确实会带来问题。

第一个问题是保留玩家的统计数据，比如健康，从一个房间到另一个房间。解决这个问题的一个方法是在玩家身上激活**持久性**。持久性意味着我们只需要在一个房间放置一个对象的单个实例，从那时起它将一直存在于游戏世界中。

第二个问题是在一个有多个入口点的房间中放置玩家。如果玩家不是持久的，我们可以将玩家放在房间里，但它总是从同一个地方开始。如果玩家是持久的，那么当他们切换房间时，他们将保持在上一个房间中的完全相同的坐标。这意味着我们需要将玩家重新定位到每个房间中我们选择的位置。

如果您的游戏将有很多房间，这可能会成为很多工作。通过创建自我感知的传送门和使用房间创建代码，有一种简单的解决方法。

## 设置房间

让我们从构建一些房间开始，首先是标题屏幕。

1.  创建一个新房间，在**设置**中命名为`TitleScreen`。

1.  创建一个新的背景，`bg_Title`，并加载`Chapter 4/Backgrounds/Title.png`，不勾选**Remove Background**。

1.  在`TitleScreen`的**Backgrounds**选项卡中，将`bg_Title`应用为**Background 0**，并勾选**Visible at Start**。

1.  创建另一个房间，命名为`C04_R01`。这里的名称代表章节和房间，如第四章，第 1 房间。

1.  将**Width**和**Height**设置为`1024`。这将允许我们有很多探索空间。

1.  我们不希望一次看到房间中的所有东西，因此我们需要限制视图。点击**Views**选项卡，勾选**Enable the Use of Views**。选择**View 0**，并勾选**Visible when room starts**。这将激活房间的摄像机系统。

1.  我们还希望视图关注玩家并随之移动。在**Views**选项卡中，选择**Object following**下的`obj_Player`，并将**Vbor:**和**Hbor:**设置为`200`。这将使摄像机跟随玩家，并在视图边缘留下 200 像素的缓冲区。查看以下截图，确保一切设置正确：![设置房间](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-gmkr/img/4100OT_04_06.jpg)

1.  使用刚才与`C04_R01`相同的设置，创建另外两个房间`C04_R02`和`C04_R03`。

1.  在资源树中，通过将`Sandbox`拖动到底部和`TitleScreen`拖动到最顶部来重新排序房间。它应该看起来像以下截图：![设置房间](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-gmkr/img/4100OT_04_05.jpg)

1.  最后，使用墙对象创建一个迷宫，包括所有三个房间。设计目前并不重要；只需确保玩家能够从一边到达另一边。可以在以下截图中看到它可能的样子：![设置房间](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-gmkr/img/4100OT_04_07.jpg)

## 创建房间传送门

为了改变房间，我们将创建可重复使用的传送门。每个传送门实际上由两个单独的对象组成，一个是**Start**对象，一个是**Exit**对象。**Start**对象将代表玩家进入房间时应该放置的着陆点。**Exit**对象是改变玩家所在房间的传送器。我们将利用四个独特的传送门，这将允许我们在地图的每一侧都有一个门。

1.  为了使房间传送系统工作，我们需要使用一些全局变量，这些变量需要在游戏开始时初始化。创建一个新脚本，`scr_Globals_StartGame`，并使用以下代码：

```js
global.portalA = 0;
global.portalB = 0;
global.portalC = 0;
global.portalD = 0;
global.lastRoom = C04_R01;
```

我们为四个传送门创建全局变量，并给它们一个零值。我们还跟踪我们上次所在的房间，这样我们就知道我们需要去新房间的哪个传送门。

1.  创建一个新对象，`obj_Globals`，添加一个**Game Start**事件，并附加此脚本。这个对象不需要精灵，因为它只是一个数据对象。

1.  将一个`obj_Globals`的实例放入`TitleScreen`。

1.  我们需要能够从标题屏幕进入游戏，因此让我们通过添加**Draw**事件并创建一个新脚本`scr_Globals_Draw`来快速修复，并使用以下代码添加以下内容：

```js
draw_set_color(c_white);
draw_set_halign(fa_center);
draw_text(room_width/2, 360, "Press ANY key");
if (keyboard_check_pressed(vk_anykey))
{
    room_goto_next();
}
```

在这里，我们只是编写一些白色的居中文本，让玩家知道他们如何开始游戏。我们使用特殊变量`vk_anykey`来查看键盘是否被按下，如果按下了，我们就按照资源树中的顺序进入下一个房间。

### 注意

您不必总是关闭脚本，因为即使打开多个脚本窗口，游戏也会运行。

1.  让我们制作一些传送门！创建一个新精灵，`spr_Portal_A_Start`，加载`Chapter 4/Sprites/Portal_A_Start.png`，并取消勾选**Remove Background**。居中原点，然后点击**OK**。

1.  创建一个新的对象，`obj_Portal_A_Start`，将精灵设置为`spr_Portal_A_Start`。这是我们将玩家移动到的着陆点，当他们进入房间时。它不需要任何代码，所以点击**确定**。

1.  创建一个新的精灵，`spr_Portal_A_Exit`，并加载`Chapter 4/Sprites/Portal_A_Exit.png`，取消**删除背景**，并将原点居中。

1.  创建一个新的对象，`obj_Portal_A_Exit`，并相应地设置精灵。这是实际的传送门，当玩家与之碰撞时，我们将改变房间。

1.  对于`obj_Player`事件，创建一个新的脚本，`scr_Portal_A_Exit_Collision`，并编写以下代码：

```js
global.lastRoom = room;
room_goto(global.portalA);
```

在我们可以传送之前，我们需要将上一个房间设置为玩家当前所在的房间。为此，我们使用内置变量`room`，它存储游戏当前显示的房间的索引号。之后，我们去到这个传送门的全局变量指示我们应该去的房间。

1.  重复步骤 5 到 9，为传送门 B、C 和 D 做同样的操作，确保更改所有适当的值以反映正确的传送门名称。

传送门已经完成，我们可以将它们添加到房间中。在每个房间中不必使用所有四个传送门；您只需要至少一个起点和一个终点。在放置这些对象时，重要的是同一类型的传送门只能有一个。起点传送门应始终放置在可玩区域，并确保只能从一个方向访问终点。您还应确保，如果一个房间的**PORTAL A**在底部，那么它要进入的房间应该在顶部有**PORTAL A**，如下面的截图所示。这将帮助玩家理解他们在世界中的位置。

![创建房间传送门](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-gmkr/img/4100OT_04_08.jpg)

现在是有趣的部分。我们需要在每个房间中更改全局传送门数值，我们不想有一个检查所有房间发生情况的大型脚本。相反，我们可以在房间本身使用**创建代码**来在玩家进入时更改这些值。让我们尝试一下，通过使`C04_R01`中的传送门 A 去到`C04_R02`，反之亦然。

1.  在`C04_R01`的**设置**选项卡中，单击**创建代码**以打开代码编辑器，并编写以下代码：

```js
global.portalA = C04_R02;
global.portalB = 0;
global.portalC = 0;
global.portalD = 0;
```

我们将**PORTAL A**设置为第二个房间。所有其他传送门都没有被使用，所以我们将变量设置为零。每个房间都需要将所有这些变量设置为某个值，要么是特定的房间，要么是零，否则可能会导致错误。

1.  在`C04_R02`的**设置**选项卡中，单击**创建代码**以打开代码编辑器，并编写以下代码：

```js
global.portalA = C04_R01;
global.portalB = 0;
global.portalC = 0;
global.portalD = 0;
```

现在我们已经将 PORTAL A 设置为第一个房间，这是有道理的。如果我们通过那个传送门，我们应该能够再次通过它回去。随意更改这些设置，以适用于您想要的所有传送门。

## 传送持久玩家

房间都已经建好，准备就绪。我们唯一需要做的就是让玩家从一个房间移动到另一个房间。让我们首先使玩家持久，这样我们在游戏中只需要一个玩家。

1.  打开`obj_Player`并勾选**持久**。

1.  接下来，我们需要将玩家重新定位到正确的传送门。我们将创建一个新的脚本，`scr_Player_RoomStart`，并在`obj_Player`的**房间开始**事件中使用以下代码。

```js
if (global.lastRoom == global.portalA)
{
    obj_Player.x = obj_Portal_A_Start.x;
    obj_Player.y = obj_Portal_A_Start.y;
} else if (global.lastRoom == global.portalB) {
    obj_Player.x = obj_Portal_B_Start.x;
    obj_Player.y = obj_Portal_B_Start.y;
} else if (global.lastRoom == global.portalC) {
    obj_Player.x = obj_Portal_C_Start.x;
    obj_Player.y = obj_Portal_C_Start.y;
} else if (global.lastRoom == global.portalD) {
    obj_Player.x = obj_Portal_D_Start.x;
    obj_Player.y = obj_Portal_D_Start.y;
} 
```

当玩家进入一个房间时，我们检查玩家刚刚离开的房间与哪个传送门相关联。然后将玩家移动到适当的着陆点。为了确保玩家被正确构建，其属性应如下截图所示：

![传送持久玩家](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-gmkr/img/4100OT_04_09.jpg)

1.  将玩家实例放入`C04_R01`。不要将玩家放入其他任何房间，否则游戏中将会出现多个玩家实例。

1.  运行游戏。我们应该能够在第一个房间四处移动，并通过 A 门，这将把我们带到第二个房间的 A 门着陆点。有了这个系统，一个游戏可以有数百个房间，只需要四个传送门来管理。

# 给敌人生命

敌人不仅仅是要避免的障碍物。好的敌人让玩家感到有一些潜在的**人工智能**（**AI**）。敌人似乎知道你何时靠近，可以在墙上追逐你，并且可以自行徘徊。在本章中，我们将创建三种生物，它们将在世界中生存，每种都有自己独特的 AI。

## 召唤幽灵图书管理员

第一个生物将由两部分组成：过期的 BookPile 和保护它的幽灵图书管理员。如果玩家靠近一个 BookPile，幽灵将生成并追逐玩家。如果玩家离幽灵太远，幽灵将返回生成它的 BookPile。如果玩家攻击幽灵，它将消失并从 BookPile 重新生成。如果玩家摧毁 BookPile，生成的幽灵也将被摧毁。

1.  让我们从 BookPile 开始。创建一个新的精灵，`spr_BookPile`，并加载`Chapter 4/Sprites/BookPile.gif`，勾选**删除背景**。

1.  将原点居中，然后点击**确定**。

1.  我们还需要一个可怕的声音来警告玩家危险。创建一个新的声音，`snd_GhostMoan`，并加载`Chapter 4/Sounds/GhostMoan.wav`。点击**确定**。

1.  创建一个新的对象，`obj_BookPile`，并分配`spr_BookPile`作为精灵。

1.  我们不希望玩家能够穿过 BookPile，所以勾选**固体**。

1.  我们需要初始化一些变量，所以创建一个新的脚本，`scr_BookPile_Create`，并编写以下代码：

```js
myRange = 100;
hasSpawned = false;
```

第一个变量设置玩家需要多接近才能变得活跃，第二个变量是布尔值，将确定这个 BookPile 是否生成了幽灵。

1.  添加一个**创建**事件并应用此脚本。

1.  接下来我们需要一个新的脚本，`scr_BookPile_Step`，它将应用于**步骤**事件，并包含以下代码：

```js
if (instance_exists(obj_Player))
{  
    if (distance_to_object(obj_Player) < myRange && hasSpawned == false)
    {
        ghost = instance_create(x, y, obj_Ghost);
        ghost.myBooks = self.id;
        sound_play(snd_GhostMoan);
        hasSpawned = true;
    }     
}
```

代码的第一行非常重要。在这里，我们首先检查玩家是否存在，然后再进行其他操作。如果玩家存在，我们检查玩家对象的距离是否在范围内，以及这个 BookPile 是否已经生成了幽灵。如果玩家在范围内并且还没有生成任何东西，我们就生成一个幽灵。我们还会将这个 BookPile 的唯一 ID 使用`self`变量发送到幽灵中，这样它就知道自己来自哪里。接下来播放幽灵的呻吟声音，确保不要循环播放。最后，我们通过将`hasSpawned`变量更改为`true`来指示我们已经生成了一个幽灵。

1.  唯一剩下的元素是添加一个`obj_Player_Attack`事件，使用一个新的脚本，`scr_BookPile_Collision`，并编写以下代码：

```js
if (instance_exists(ghost))
{
    with (ghost)
    {
        instance_destroy();
    }
}
instance_destroy();
```

再次，我们首先检查是否有幽灵从这个 BookPile 生成并且仍然存在。如果是，我们销毁那个幽灵，然后移除 BookPile 本身。BookPile 现在已经完成，应该看起来像以下截图：

![召唤幽灵图书管理员](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-gmkr/img/4100OT_04_10.jpg)

1.  现在我们需要构建幽灵。为此，我们需要引入两个精灵，一个用于生成，一个用于追逐。创建精灵时勾选**删除背景**，分别为`spr_Ghost`和`spr_Ghost_Spawn`，并加载`Chapter 4/Sprites/Ghost.gif`和`Chapter 4/Sprites/Ghost_spawn.gif`。

1.  在两个精灵中，将原点居中。

1.  将**深度：**字段设置为`-50`，这样幽灵将出现在大多数物体上方，但在玩家攻击物体下方。没有其他需要做的事情，所以点击**确定**。

1.  创建一个新的对象，`obj_Ghost`，并应用`spr_Ghost_Spawn`作为精灵。这将使生成动画成为初始精灵，然后我们将通过代码将其更改为常规幽灵。

1.  我们有几个变量需要在一个新的脚本`scr_Ghost_Create`中初始化，如下所示的代码：

```js
mySpeed = 2;
myRange = 150;
myBooks = 0;
isDissolving = false;
image_speed = 0.3; 
   alarm[0] = 6;
```

1.  我们设置了移动速度的变量，幽灵将在其中追踪的范围，生成幽灵的人（我们将通过书堆改变），以及幽灵是否已经返回到书堆的变量。请注意，幽灵的范围比书堆的范围大。这将确保幽灵立即开始追逐玩家。然后我们设置了动画速度，并设置了一个六步的警报，我们将用它来改变精灵。

1.  添加一个**Alarm0**事件，然后应用一个新的脚本，`scr_Ghost_Alarm0`，其中包含以下代码来改变精灵：

```js
sprite_index = spr_Ghost;
```

现在我们准备开始实现一些人工智能。幽灵将是最基本的敌人，会追逐玩家穿过房间，包括穿过墙壁和其他敌人，直到玩家超出范围。在那时，幽灵将漂浮回到它来自的书堆。

1.  我们将从追逐玩家开始。创建一个新的脚本，`scr_Ghost_Step`，并编写以下代码：

```js
if (instance_exists(obj_Player))
{
    targetDist = distance_to_object(obj_Player)
    if (targetDist < myRange)
    {       
        move_towards_point(obj_Player.x, obj_Player.y, mySpeed);
    }   
}
```

在确保玩家还活着之后，我们创建一个变量来保存幽灵到玩家的距离。我们创建`targetDist`变量的原因是我们将需要这个信息几次，这样可以避免每次有`if`语句时都重新检查距离。然后我们比较距离和追逐范围，如果玩家在范围内，我们就朝着玩家移动。`move_towards_point`函数会计算方向并将速度应用到该方向的对象上。

1.  添加一个**Step**事件并应用这个脚本。我们将继续向这个脚本添加代码，但它已经可以正常运行了。

1.  让我们花一点时间来测试我们到目前为止所做的一切。首先，在资源树中，将`Sandbox`移到接近顶部，这样它就是标题屏幕后的房间。打开`Sandbox`房间，并像以下截图所示，在边缘放置几个`obj_BookPile`的实例：![召唤幽灵图书管理员](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-gmkr/img/4100OT_04_11.jpg)

1.  运行游戏。如果你离书堆太近，一个幽灵会从中产生，并慢慢追逐玩家。如果玩家离幽灵太远，幽灵将继续朝着它最后的方向移动，并最终消失在屏幕外。

1.  让幽灵返回到它的书堆。在`scr_Ghost_Step`中，添加以下代码到玩家存在检查的大括号内：

```js
else if (targetDist > myRange && distance_to_point(myBooks.x, myBooks.y) > 4)
{      
move_towards_point(myBooks.x, myBooks.y, mySpeed);
}
```

首先我们检查玩家是否超出范围，而幽灵又不靠近自己的书堆。在这里，我们使用`distance_to_point`，这样我们就是检查书堆的原点而不是`distance_to_object`会寻找的碰撞区域的边缘。如果这一切都是真的，幽灵将开始向它的书堆移动。

1.  让我们再次运行游戏。和以前一样，幽灵会追逐玩家，如果玩家离得太远，幽灵将返回到它的书堆。

1.  幽灵最终会在书堆的顶部来回移动，这是一个问题。这是因为幽灵具有基于速度的速度，并且没有任何代码告诉它停下来。我们可以通过在最后的`else if`语句后添加以下代码来解决这个问题：

```js
else 
{
speed = 0;
if (isDissolving == false)
{
      myBooks.hasSpawned = false;
sprite_index = spr_Ghost_Spawn;
image_speed = -1;
alarm[1] = 6;
isDissolving = true;
}
}
```

这里有一个最终的`else`语句，如果玩家超出范围，幽灵靠近它的书堆，将执行。我们首先停止幽灵的速度。然后我们检查它是否可以溶解。如果可以，我们告诉书堆可以再次生成幽灵，我们将精灵改回生成动画，并通过将`image_speed`设置为`-1`来以相反的方式播放该动画。我们还设置了另一个警报，这样我们就可以将幽灵从世界中移除并停用溶解检查。

整个`scr_Ghost_Step`应该如下所示的代码：

```js
 if (instance_exists(obj_Player))
{
    targetDist = distance_to_object(obj_Player)
    if (targetDist < myRange)
    {       
        move_towards_point(obj_Player.x, obj_Player.y, mySpeed);
    } else if (targetDist > myRange && distance_to_point(myBooks.x, myBooks.y) > 4) {      
        move_towards_point(myBooks.x, myBooks.y, mySpeed);
    } else {
        speed = 0;
        if (isDissolving == false)
        {
            myBooks.hasSpawned = false;
            sprite_index = spr_Ghost_Spawn;
            image_speed = -1;
            alarm[1] = 6;
            isDissolving = true;
        }
    }
}
```

1.  需要一个最后的脚本，`scr_Ghost_Alarm1`，它附加在**Alarm 1**事件上，并有一行代码来移除实例：

```js
instance_destroy();
```

幽灵几乎完成了。它生成，追逐玩家，然后返回到它的 BookPile，但是如果它抓住了玩家会发生什么？对于这个幽灵，我们希望它撞到玩家，造成一些伤害，然后在一团烟雾中消失。为此，我们需要为死去的幽灵创建一个新的资源。

1.  创建一个新精灵`spr_Ghost_Dead`，并加载`Chapter 4/Sprites/Ghost_Dead.gif`，勾选**删除背景**。

1.  居中原点，然后点击**确定**。

1.  创建一个新的对象`obj_Ghost_Dead`，并应用该精灵。

1.  在一个新的脚本`scr_Ghost_Dead_AnimEnd`中，编写以下代码并将其附加到**动画结束**事件上：

```js
instance_destroy();
```

**动画结束**事件将在播放精灵的最后一帧图像时执行代码。在这种情况下，我们有一个烟雾的动画，在结束时将从游戏中移除对象。

1.  现在我们只需要重新打开`obj_Ghost`，并添加一个带有新脚本`scr_Ghost_Collision`的**obj_Player**事件，其中包含以下代码：

```js
health -= 5;
myBooks.hasSpawned = false;
instance_create(x, y, obj_Ghost_Dead);
instance_destroy();
```

我们首先减少五点生命值，然后告诉幽灵的 BookPile 它可以重新生成。接下来，我们创建幽灵死亡对象，当我们将其从游戏中移除时，它将隐藏真正的幽灵。如果一切构建正确，它应该看起来像以下截图：

![召唤幽灵图书管理员](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-gmkr/img/4100OT_04_12.jpg)

1.  运行游戏。现在，幽灵应该能够完全按照设计的方式运行。它会生成并追逐玩家。如果它抓住了玩家，它会造成伤害并消失。如果玩家逃脱，幽灵将返回到它的 BookPile 并消失。干得好！

最后一件事，由于房间是用来进行实验而不是实际游戏的一部分，我们应该清理房间，为下一个敌人做准备。

1.  打开`Sandbox`房间，并删除所有的 BookPiles 实例。

## 创建一个漫游的 Brawl

我们将创建的下一个敌人是一个 Brawl，它将在房间里漫游。如果玩家离这个敌人太近，Brawl 会变得愤怒，变得更大并移动得更快，尽管它不会离开它的路径。一旦玩家离开范围，它会恢复冷静，并缩小到原来的大小和速度。玩家无法杀死这个敌人，但是如果接触到 Brawl，它会对玩家造成伤害。

对于 Brawl，我们将利用一个路径，并且我们需要三个精灵：一个用于正常状态，一个用于状态转换，另一个用于愤怒状态。

1.  创建一个新精灵`spr_Brawl_Small`，并加载`Chapter 4/Sprites/Brawl_Small.gif`，勾选**删除背景**。这是正常状态的精灵。居中原点，然后点击**确定**。

1.  创建另一个新的精灵`spr_Brawl_Large`，并加载`Chapter 4/Sprites/Brawl_Large.gif`，勾选**删除背景**。我们需要将原点居中，以便 Brawl 能够正确缩放这个图像。愤怒状态是正常状态的两倍大小。

1.  我们还需要在这两种状态之间进行转换，因此让我们创建一个新的精灵`spr_Brawl_Change`，并加载`Chapter 4/Sprites/Brawl_Change.gif`，仍然勾选**删除背景**。不要忘记居中原点。

1.  接下来，我们需要一个 Brawl 要遵循的路径。创建一个新路径，并命名为`pth_Brawl_01`。

1.  我们希望 Brawl 移动起来更加平滑，因此在**连接类型**下勾选**平滑曲线**，并将**精度**更改为`8`。

1.  要看看我们可以用路径做些什么，让我们制作一个八字形状的路径，如下截图所示：![创建一个漫游的 Brawl](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-gmkr/img/4100OT_04_13.jpg)

1.  让我们还创建一个新声音`snd_Brawl`，并加载`Chapter 4/Sounds/Brawl.wav`。

1.  创建一个新对象`obj_Brawl`，并将`spr_Brawl_S`应用为默认精灵。

1.  我们将从一个创建事件脚本`scr_Brawl_Create`中初始化一些变量。

```js
mySpeed = 2;
canGrow = false;
isBig = false;
isAttacking = false;
image_speed = 0.5;
sound_play(snd_Brawl);
sound_loop(snd_Brawl);
path_start(pth_Brawl_01, mySpeed, 1, true);
```

第一个变量设置了 Brawl 的基本速度。接下来的三个变量是变身和愤怒状态以及是否已攻击的检查。接下来，我们设置了动画速度，然后播放了 Brawl 声音，在这种情况下，我们希望声音循环。最后，我们将 Brawl 设置到速度为 2 的路径上；当它到达路径的尽头时，它将循环，最重要的是，路径设置为绝对，这意味着它将按照路径编辑器中设计的方式运行。

1.  现在我们可以开始处理 Brawl 的人工智能。为**Step**事件创建一个名为`scr_Brawl_Step`的新脚本，我们将从使移动工作开始。

```js
image_angle = direction;
if (isBig == true)
{
    path_speed = mySpeed * 2;
} else {
    path_speed = mySpeed;
}
```

我们首先通过旋转 Sprite 本身来使其面向正确的方向。这将起作用，因为我们的 Sprite 图像面向右侧，这与零度相同。接下来，我们检查 Brawl 是否变大。如果 Brawl 是愤怒版本，我们将路径速度设置为基本速度的两倍。否则，我们将速度设置为默认的基本速度。

1.  在房间的任何位置放置一个 Brawl 实例并运行游戏。Brawl 应该围绕数字八移动，并正确面向正确的方向。

1.  接下来，我们将添加第一个变身，变得愤怒。在上一行代码之后，添加：

```js
if (instance_exists(obj_Player))
{
    if (distance_to_object(obj_Player) <= 200) 
    {
        if (canGrow == false)
        {
            if (!collision_line(x, y, obj_Player.x, obj_Player.y, obj_Wall, false, true))
            {
                sprite_index = spr_Brawl_Change;
                alarm[0] = 12;
                canGrow = true;
            }      
        }
    }
}
```

我们首先确保玩家存在，然后检查玩家是否在范围内。如果玩家在范围内，我们检查自己是否已经愤怒。如果 Brawl 还没有变大，我们使用`collision_line`函数来查看 Brawl 是否真的能看到玩家。这个函数在两个点之间绘制一条线，即 Brawl 和玩家位置，然后确定一个对象实例或墙壁是否穿过了该线。如果 Brawl 能看到玩家，我们将 Sprite 更改为变身 Sprite，设置一个警报以便我们可以完成变身，并指示 Brawl 已经变大。

1.  让我们为**Alarm 0**事件创建一个名为`scr_Brawl_Alarm0`的脚本，其中包含将切换到愤怒的 sprite 并指示 Brawl 现在已经完全大小的代码。

```js
sprite_index = spr_Brawl_Large;
isBig = true;
```

1.  运行游戏以确保代码正常工作。Brawl 应该保持小尺寸，直到能清楚看到玩家，此时它将变换为大型、愤怒的 Brawl。

1.  Brawl 正在变大，现在我们需要让它平静下来并缩小。在`scr_Brawl_Step`中，添加一个距离检查的`else`语句，该语句将位于最终大括号之前，并添加以下代码：

```js
else 
{
if (canGrow == true)
{
sprite_index = spr_Brawl_Change;
alarm[1] = 12;
canGrow = false;
}
}
```

如果玩家超出范围，这个`else`语句将变为活动状态。我们检查 Brawl 是否仍然处于愤怒状态。如果是，我们将 Sprite 更改为变身状态，设置第二个警报，并指示 Brawl 已恢复正常。

以下是完整的`scr_Brawl_Step`脚本：

```js
image_angle = direction;
if (isBig == true)
{
    path_speed = mySpeed * 2;
} else {
    path_speed = mySpeed;
}

if (instance_exists(obj_Player))
{
    if (distance_to_object(obj_Player) <= 200) 
    {
        if (canGrow == false)
        {
            if (!collision_line(x, y, obj_Player.x, obj_Player.y, obj_Wall, false, true))
            {
                sprite_index = spr_Brawl_Change;
                alarm[0] = 12;
                canGrow = true;
            }      
        }
    } 
    else 
    {
        if (canGrow == true)
        {
            sprite_index = spr_Brawl_Change;
            alarm[1] = 12;
            canGrow = false;
        }
    }
}
```

1.  复制`scr_Brawl_Alarm0`脚本，将其命名为`scr_Brawl_Alarm1`，并根据以下代码调整值。记得将其添加为**Alarm 1**事件。

```js
sprite_index = spr_Brawl_Small;
isBig = false;
```

1.  运行游戏并确认，当玩家接近并在视线范围内时，Brawl 会变得更大更快，并在超出范围时恢复正常。

1.  我们唯一剩下的就是攻击。为**obj_Player**事件创建一个名为`scr_Brawl_Collision`的新脚本，其中包含以下代码：

```js
if (isAttacking == false)
{
    health -= 10;
    alarm[2] = 60;
    isAttacking = true;
}
```

如果玩家第一次与 Brawl 碰撞，我们会减少 10 点生命值并设置一个两秒的警报，让 Brawl 可以再次攻击。

1.  为了完成 Brawl，我们只需要最终的**Alarm 2**事件和一个新的脚本`scr_Brawl_Alarm2`，其中包含以下代码行：

```js
isAttacking = false;
```

Brawl 现在已经完成并按设计进行。如果一切实现正确，对象属性应该如下截图所示：

![构建一个漫游的 Brawl](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-gmkr/img/4100OT_04_14.jpg)

1.  从`Sandbox`房间中删除任何`obj_Brawl`实例，以便我们可以为最终敌人重新开始。

## 创建教练

我们将创建的最后一个敌人，教练，将是迄今为止最具挑战性的对手。这个敌人将在房间中四处移动，随机地从一个奖杯到另一个奖杯，以确保奖杯仍在那里。如果它看到玩家，它会追逐他们，如果足够接近，它会进行近战攻击。如果玩家逃脱，它会等一会儿然后返回岗位。教练有一个身体，所以它需要绕过障碍物，甚至避开其他教练。这也意味着如果玩家能够攻击它，它可能会死亡。

1.  由于这个敌人正在守卫某物，我们将从创建奖杯开始。创建一个新的精灵，`spr_Trophy`，并加载`Chapter 4/Sprites/Trophy.gif`，勾选**移除背景**。

1.  创建一个新的对象，`obj_Trophy`，并将`scr_Trophy`应用为其精灵。

1.  由于这是一个动画精灵，我们将添加一个**创建**事件，并通过在新脚本`scr_Trophy_Create`中编写以下代码来使其不进行动画：

```js
image_speed = 0;
image_index = 0;
```

1.  现在对于奖杯来说，这就是我们需要的全部，所以点击**确定**。

与玩家一样，我们需要四个精灵，代表敌人将移动的四个方向。

1.  创建一个新的精灵，`spr_Coach_WalkRight`，并加载`Chapter 4/Sprites/Coach_WalkRight.gif`，勾选**移除背景**。

1.  将原点居中，点击**修改掩码**，并在**边界框**下勾选**完整图像**。

1.  对于`spr_Coach_LWalkLeft`、`spr_Coach_WalkDown`和`spr_Coach_WalkUp`精灵，重复此过程。

1.  创建一个新的对象，`obj_Coach`，并将`spr_Coach_WalkRight`应用为其精灵。

我们将为这个敌人动态创建路径，以便它可以自行导航到奖杯。我们还希望它避开障碍物和其他敌人。这并不难实现，但在初始化时需要进行大量设置。

1.  创建一个新的脚本，`scr_Coach_Create`，将其应用于**创建**事件，然后我们将从一些基本变量开始：

```js
mySpeed = 4;
isChasing = false;
isWaiting = false;
isAvoiding = false;
isAttacking = false;
image_speed = 0.3;
```

再次，我们首先设置对象的速度。然后我们有四个变量，表示我们需要检查的各种状态，全部设置为`false`。我们还设置了精灵的动画速度。

接下来，我们需要设置路径系统，该系统将利用 GameMaker 的一些**运动规划**功能。基本概念是我们创建一个覆盖敌人移动区域的网格。然后我们找到所有我们希望敌人避开的对象，比如墙壁，并将网格的这些区域标记为禁区。然后我们可以在自由区域中分配起点和目标位置，并在避开障碍物的情况下创建路径。

1.  在`scr_Coach_Create`中，将以下代码添加到脚本的末尾：

```js
myPath = path_add();
myPathGrid = mp_grid_create(0, 0, room_width/32, room_height/32, 32, 32);
mp_grid_add_instances(myPathGrid, obj_Wall, false);
```

首先需要一个空路径，我们可以用于所有未来的路径。接下来，我们创建一个网格，该网格将设置路径地图的尺寸。`mp_grid_create`属性有参数，用于确定其在世界中的位置，宽度和高度有多少个网格，以及每个网格单元的大小。在这种情况下，我们从左上角的网格开始，以 32 像素的增量覆盖整个房间。将房间尺寸除以 32 意味着这将适用于任何尺寸的房间，而无需调整代码。最后，我们将在房间中找到的所有墙的实例添加到网格中，作为不允许路径的区域。

1.  现在，我们需要为教练找到一个目的地。继续在脚本的末尾添加以下代码：

```js
nextLocation = irandom(instance_number(obj_Trophy)-1);
target = instance_find(obj_Trophy, nextLocation);
currentLocation = nextLocation;
```

我们首先得到一个基于房间中奖杯数量的四舍五入随机数。请注意，我们从奖杯数量中减去了一个。我们需要这样做，因为在下一行代码中，我们使用`instance_find`函数搜索特定实例。这个函数是从数组中提取的，数组中的第一项总是从零开始。最后，我们创建了第二个变量，用于当我们想要改变目的地时。

1.  现在我们所要做的就是创建路径并使用它。在脚本的末尾添加以下代码：

```js
mp_grid_path(myPathGrid, myPath, x, y, target.x, target.y, false);
path_start(myPath, mySpeed, 0, true);
```

在这里，我们选择了我们创建的网格和空路径，并创建了一个新的路径，该路径从教练的位置到目标位置，并且不会对角线移动。然后我们让教练动起来，这一次，当它到达路径的尽头时，它将停下来。`path_start`函数中的最终值将路径设置为绝对值，在这种情况下我们需要这样做，因为路径是动态创建的。

这是整个`scr_Coach_Create`脚本：

```js
mySpeed = 4;
isChasing = false;
isWaiting = false;
isAvoiding = false;
isAttacking = false;
image_speed = 0.3;

myPath = path_add();
myPathGrid = mp_grid_create(0, 0, room_width/32, room_height/32, 32, 32);
mp_grid_add_instances(myPathGrid, obj_Wall, false);

nextLocation = irandom(instance_number(obj_Trophy)-1);
target = instance_find(obj_Trophy, nextLocation);
currentLocation = nextLocation;

mp_grid_path(myPathGrid, myPath, x, y, target.x, target.y, false);
path_start(myPath, mySpeed, 0, true); 
```

1.  打开 Sandbox，在角落放置两个`obj_Coach`实例，以及三个`obj_Trophy`实例，如下截图所示：![Creating the Coach](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-gmkr/img/4100OT_04_15.jpg)

1.  运行游戏。您应该看到教练们随机选择一个奖杯并朝它移动。尝试重新启动几次，看看每个教练所采取的不同路径。

1.  基本设置完成后，我们可以继续进行 AI。我们将从根据移动方向切换精灵开始。创建一个新的脚本`scr_Coach_Step`，将其应用于**Step**事件，并编写以下代码：

```js
if (direction > 45 && direction <= 135) { sprite_index = spr_Coach_WalkUp; }
else if (direction > 135 && direction <= 225) { sprite_index = spr_Coach_WalkLeft; }
else if (direction > 225 && direction <= 315) { sprite_index = spr_Coach_WalkDown; }
else { sprite_index = spr_Coach_WalkRight; }
```

在这里，我们根据实例移动的方向更改精灵。我们可以在这里做到这一点，因为我们不允许在路径上进行对角线移动。

1.  接下来，我们将让教练观察玩家，如果被发现，他们将离开原来的路径进行追逐。在精灵更改代码之后添加以下代码：

```js
targetDist = distance_to_object(obj_Player);
if (targetDist < 150  && targetDist > 16)
{
    canSee = collision_line(x, y, obj_Player.x, obj_Player.y, obj_Wall, false, false)
    if (canSee == noone)
    {
        path_end();
        mp_potential_step(obj_Player.x, obj_Player.y, 4, all);
        isChasing = true;
    }
 }
```

我们再次使用一个变量来保存玩家距离的值，以节省编码时间并最小化函数调用。如果玩家在范围内且不在攻击距离内，我们进行视线检查。`collision_line`函数返回线穿过的任何墙实例的 ID。如果它不与任何墙实例相交，它将返回一个名为`noone`的特殊变量。如果玩家在视线中，我们结束教练正在遵循的路径，并开始朝玩家移动。`mp_potential_step`函数将使对象朝着期望的方向移动，同时避开障碍物，在这种情况下，我们避开所有实例。最后，我们指示教练正在追逐玩家。

1.  这对于开始追逐很有效，但是如果玩家逃脱了怎么办？让教练等待一会儿，然后回到巡逻。在进行视线检查的`else`语句中添加以下代码：

```js
else if (canSee != noone && isChasing == true)
{
    alarm[0] = 60;
    isWaiting = true;
    isChasing = false;
}
```

这个`else`语句表示，如果玩家看不见并且教练正在追逐，它将设置一个警报以寻找新目的地，告诉它等待，追逐结束。

1.  我们设置了一个警报，因此让我们创建一个新的脚本`scr_Coach_Alarm0`，并将其应用于**Alarm 0**事件。在脚本中写入以下代码：

```js
while (nextLocation == currentLocation)
{
    nextLocation = irandom(instance_number(obj_Trophy)-1);
}

target = instance_find(obj_Trophy, nextLocation);
currentLocation = nextLocation;

mp_grid_path(myPathGrid, myPath, x, y, target.x, target.y, false);
path_start(myPath, mySpeed, 1, false);

isWaiting = false;
```

我们首先使用一个`while`循环来检查下一个位置是否与旧位置相同。这将确保教练总是移动到另一个奖杯。就像我们在初始设置中所做的那样，我们选择一个新的目标并设置当前位置变量。我们还创建一个路径并开始在其上移动，这意味着教练不再等待。

1.  我们还需要添加一个元素到追逐序列中，即攻击。如果教练靠近玩家，它应该对玩家进行近战攻击。为此，我们首先需要创建一个新的精灵`spr_Coach_Attack`，加载`Chapter 4/Sprites/Coach_Attack.gif`并勾选**Remove Background**。

1.  就像玩家的攻击一样，将**Origin**设置为**X:**`-16`，**Y:**`24`，并调整**Bounding Box**的值为**Left:**`0`，**Right:**`24`，**Top:**`0`，和**Bottom:**`4`。

1.  创建一个新的对象`obj_Coach_Attack`，应用精灵，并将**Depth**设置为`-100`。

1.  添加一个**Create**事件，并应用一个新的脚本`scr_Coach_Attack_Create`，其中包含控制动画速度的代码，设置一个用于移除实例的警报，并一个我们可以打开的变量。

```js
image_speed = 0.3;
alarm[0] = 6;
isHit = false;
```

1.  使用新的脚本`scr_Coach_Attack_Alarm0`添加一个**Alarm 0**事件，该脚本会移除实例。

```js
instance_destroy();
```

1.  最后，添加一个**obj_Player**事件，并应用一个新的脚本`scr_Coach_Attack_Collision`，其中包含以下代码：

```js
if (isHit == false)
{
    health -= 15;
    isHit = true;
}
```

如果这是第一次碰撞，我们减少一点生命值，然后停用此检查。

1.  攻击已经完成。现在要在教练中激活它，重新打开`scr_Coach_Step`，并在最后的大括号后添加攻击代码作为`else if`语句：

```js
else if (targetDist <= 16)
{
    if (isAttacking == false)
    {
        swing = instance_create(x, y, obj_Coach_Attack);
        swing.image_angle = direction;
        alarm[1] = 90;
        isAttacking = true;
    }
}
```

如果教练靠近玩家但尚未发动攻击，我们创建一个教练攻击的实例。然后我们旋转攻击精灵，使其面向与教练相同的方向。设置一个三秒的闹钟，以便在再次运行此代码之前有时间喘口气。

1.  我们需要一个**Alarm 1**事件来重置攻击，因此创建一个新脚本，`scr_Coach_Alarm1`，并关闭攻击。

```js
isAttacking = false;
```

1.  运行游戏。现在教练会追逐玩家，如果它靠近玩家足够近，它就会发动攻击。

教练现在只完成了一半的工作，追逐玩家。我们还需要添加正常的巡逻任务。目前，如果教练看不到玩家并且到达路径的尽头，它就会停下来再次什么都不做。它应该只等几秒，然后继续移动到下一个奖杯。

1.  重新打开`scr_Coach_Step`，并在脚本的最后添加一个`else`语句，包含以下代码：

```js
else 
{
    if (isWaiting == false)
    {
        if (distance_to_object(target) <= 8) 
        {
            alarm[0] = 60;
            path_end();
            isWaiting = true;
        }
    }
}
```

这个`else`语句表示玩家超出范围。然后我们检查教练是否在等待。如果它不在等待，但距离目标奖杯不到八个像素，我们设置两秒钟的选择新目的地的闹钟，结束路径以停止移动，并声明我们现在在等待。

1.  运行游戏，你会看到教练在不追逐玩家时，停在奖杯附近，停顿片刻，然后移动到另一个奖杯。

1.  然而，如果两个教练都去同一个奖杯，就会出现问题。让我们通过在检查奖杯的距离后添加以下代码来解决这个问题：

```js
if (isAvoiding == true)
{
     mp_potential_step (target.x, target.y, 4, all);
}
```

我们需要做的第一件事是检查变量，看教练是否需要避让。如果需要，我们使用`mp_potential_step`函数，该函数将使实例朝着指定目标移动，同时尝试避开某些对象，或者在这种情况下，避开所有实例。

1.  现在，我们需要设置避让发生的条件。在最后的代码之后立即插入以下内容：

```js
 if (distance_to_object(obj_Coach) <= 32 && isAvoiding == false)
 {
     path_end();
     isAvoiding = true;
 }
 else if (distance_to_object(obj_Coach) > 32 && isAvoiding == true)
 {
     mp_grid_path(myPathGrid, myPath, x, y, target.x, target.y, false);
     path_start(myPath, mySpeed, 1, true);
     isAvoiding = false;
 }
```

首先，我们检查教练实例是否附近，且尚未尝试避让。如果是，则我们让教练脱离路径并开始避让。接着是一个`else if`语句，检查我们是否与另一个教练足够远，以便我们可以避让。如果是，我们为目的地设置一个新路径，开始移动，并结束避让。

1.  还有一个小问题尚未解决，如果你运行游戏一段时间就会发现。有时两辆教练会靠得太近，它们就会停下来。这是因为它们试图避开彼此，但实际上它们是在接触并且无法分开。在`scr_Coach_Step`脚本的最后，写入以下内容：

```js
if (place_meeting(x, y, obj_Coach))
{
    x = xprevious;
    y = yprevious;
    mp_potential_step(target.x, target.y, 4, all);
}
```

这将检查两个教练实例是否相互碰撞。如果是，我们将`x`和`y`坐标设置为特殊变量`xprevious`和`yprevious`，它们代表实例在上一步中的位置。一旦它们退后一步，我们就可以再次尝试绕过它们。

教练现在已经完成。要检查`scr_Coach_Step`的所有代码是否都写正确，这里是完整的代码：

```js
if (direction > 45 && direction <= 135) { sprite_index = spr_Coach_WalkUp; }
else if (direction > 135 && direction <= 225) { sprite_index = spr_Coach_WalkLeft; }
else if (direction > 225 && direction <= 315) { sprite_index = spr_Coach_WalkDown; }
else { sprite_index = spr_Coach_WalkRight; }

targetDist = distance_to_object(obj_Player);
if (targetDist < 150  && targetDist > 16)
{
    canSee = collision_line(x, y, obj_Player.x, obj_Player.y, obj_Wall, false, false)
    if (canSee == noone)
    {
        path_end();
        mp_potential_step(obj_Player.x, obj_Player.y, 4, all);
        isChasing = true;
    }
    else if (canSee != noone && isChasing == true)
    {
        alarm[0] = 60;
        isWaiting = true;
        isChasing = false;
    }
}
else if (targetDist <= 16)
{
    if (isAttacking == false)
    {
        swing = instance_create(x, y, obj_Coach_Attack);
        swing.image_angle = direction;
        alarm[1] = 90;
        isAttacking = true;
    }
}
else 
{
    if (isWaiting == false)
    {
        if (distance_to_object(target) <= 8)
        {
            alarm[0] = 60;
            path_end();
            isWaiting = true;
        }
        if (isAvoiding == true)
        {
            mp_potential_step(target.x, target.y, 4, all);
        }
        if (distance_to_object(obj_Coach) <= 32 && isAvoiding == false)
        {
            path_end();
            isAvoiding = true;
        }
        else if (distance_to_object(obj_Coach) > 32 && isAvoiding == true)
        {
            mp_grid_path(myPathGrid, myPath, x, y, target.x, target.y, false);
            path_start(myPath, mySpeed, 1, true);
            isAvoiding = false;
        }
    }
}
if (place_meeting(x, y, obj_Coach))
{
    x = xprevious;
    y = yprevious;
    mp_potential_step(target.x, target.y, 4, all);
}
```

# 为游戏添加最后的细节

游戏现在在功能上已经完成，但还有一些元素需要完善。首先，玩家会受到伤害，但从不会死亡，也没有**头顶显示**（**HUD**）来显示这一点。让我们快速创建一个 Overlord。

1.  创建一个新对象，`obj_Overlord`，不应用精灵并检查持久性。

1.  添加一个**Draw GUI**事件和一个新的脚本，`scr_Overlord_DrawGUI`，其中包含以下代码：

```js
draw_healthbar(0, 0, 200, 16, health, c_black, c_red, c_green, 0, true, true);

if (health <= 0)
{
    with (obj_Player) { instance_destroy(); }
    room_goto(TitleScreen);
    instance_destroy();
}
```

首先，我们使用了函数`draw_healthbar`，你可以看到它有很多参数。前四个是矩形条的大小和位置。接下来是用于控制条的满度的变量，在我们的例子中是全局健康变量。接下来的三个是背景颜色和最小/最大颜色。接下来是条应该下降的方向，零表示向左。最后两个布尔值是用于绘制我们想要的背景和边框。

之后，我们进行健康检查，如果玩家应该死了，我们移除玩家，返回前端，然后移除 Overlord 本身。移除世界中的任何持久实例是很重要的，否则它们就不会消失！

1.  将一个`obj_Overlord`的实例放入`C04_R01`中。

1.  用各种敌人填充房间。如果我们使用 Brawl，我们要么需要创建一个适用于我们创建的路径的房间，要么更好的是重新绘制路径以适应我们的房间布局。

1.  确保`Sandbox`房间被移回到资源树的底部并运行游戏。我们应该在屏幕顶部看到健康条，如果受到伤害，健康条应该下降。如果玩家受到了太多伤害，游戏将结束并返回到前端。

所有剩下的就是创建关卡，用瓷砖集来绘制世界，并添加一些背景音乐。在这一点上，你应该知道如何做了，所以我们会把它留给你。我们已经在“第四章”文件夹中提供了一些额外的资源。完成后，你应该会看到类似以下截图的东西：

![为游戏添加最后的细节](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-gmkr/img/4100OT_04_16.jpg)

# 摘要

恭喜你完成了你的第二个游戏！我们学会了通过将键盘检查和碰撞预测放入一个脚本来简化玩家控制。我们涵盖了处理精灵动画的几种方法，从旋转图像到设置应该显示哪些精灵。我们处理了全局变量，并用它们来实现了一个房间过渡系统。我们深入讨论了一些新的对象属性和持久性。然后我们花了一些时间处理人工智能，通过接近检测和路径查找。我们甚至发现了如何使一个对象在避开障碍物的同时自己导航到一个房间。

通过本章中所学的技能，你现在可以构建具有多个房间和敌人的游戏，这些敌人看起来会思考。现在轮到你通过添加更多独特的敌人、打开奖杯并生成战利品来扩展这个游戏了。玩得开心，探索你新发现的能力！

在下一章中，我们将为平台游戏构建一场史诗般的 boss 战。将会有枪支和激光，还有很多乐趣。我们将开始通过创建可重复使用的脚本，以及学习如何系统地构建我们的代码来提高代码的效率。所有这些都将帮助我们使游戏变得更快更容易，所以让我们开始吧！


# 第五章：平台乐趣

现在我们对构建游戏的基础有了很好的基础，我们准备创建更复杂和更高效的项目。在本章中，我们将开发一个经典的平台游戏，其中包括一场史诗般的 Boss 战。我们将专注于构建系统，并利用可重复使用的脚本简化我们的代码并节省时间。这也将减少游戏的总体大小，使其下载速度更快。

游戏本身将包括一个玩家角色，可以在世界中奔跑，跳上平台，并朝多个方向射击。玩家需要击败一个巨型机器 Boss，它将有三个不同的阶段。在第一阶段，玩家需要摧毁三门暴露一小段时间的强大火炮。第二阶段需要摧毁一个大型激光炮，它会上下移动，不时地发射巨大的激光束。最后一个阶段将有护盾保护 Boss 核心，偶尔打开以允许玩家消灭 Boss 的核心。所有这些都将发生在玩家试图避免被一门不可摧毁的炮塔击中的情况下。

# 构建基于系统的代码结构

制作游戏时，通常会单独构建每个组件，而不考虑它将如何影响整个游戏。开发人员将构建一个基本框架，然后在需要时添加功能，通常会使用特殊的条件语句使代码能够正常工作而不破坏游戏。这种方法最终会在软件中产生错误，需要更多的时间和精力来修复每一个错误。游戏越大，出现问题的可能性就越大。这可能是一种令人沮丧的经历。

将代码分解为单独的系统可以真正节省时间和精力。我们可以将代码的各个元素写入脚本中，以便共享，而不是为每个对象一遍又一遍地重写代码。对于这个游戏，我们将把一些更基本的组件，比如重力和动画，分离成它们自己的系统。

## 创建重力

我们要构建的第一个系统是处理重力的系统。虽然 GameMaker: Studio 确实有一个重力属性，但在平台游戏中并不需要这种复杂性。重力是一个作用于物体速度的力，这意味着物体下落的时间越长，速度就越快。我们的问题是将重力设置为零只意味着它不会移动得更快。我们需要物体完全停下来。因此，我们将创建自己的重力系统，不仅使物体下落，还将处理着陆的情况。我们将创建自己的重力系统，不仅使物体下落，还将处理着陆的情况。

我们将首先介绍**常量**。常量允许我们使用名称来表示永远不会改变的值。这不仅使我们更容易阅读代码，还有助于提高性能，与变量相比：

1.  让我们开始创建一个名为`Chapter_03`的**新项目**。

1.  打开**资源** | **定义常量**编辑器。在**名称**列中写入`MAXGRAVITY`，**值**为`16`。以这个速度，我们可以确保下落的物体不会移动得太快，以至于错过游戏中另一个物体的边界框。从现在开始，每当我们看到`MAXGRAVITY`，计算机将看到`16`。

### 注

按照惯例，将所有常量都用大写字母写出，尽管如果不遵循惯例，也不会出错。

1.  接下来，我们可以创建一个新的脚本，`scr_Gravity`，并编写以下代码来创建重力：

```js
if (place_free( x, y + vspeed + 1))
{
    vspeed  += 1;
} else {    
    move_contact_solid(direction, MAXGRAVITY);
    vspeed = 0;
}
```

首先，我们检查实例下方的区域是否没有任何可碰撞的对象以当前速度行进。如果清晰，那么我们知道我们在空中，应该施加重力。我们通过每一步增加垂直速度的小量来实现这一点。如果有可碰撞的对象，那么我们即将着地，所以我们将实例移动到对象表面，以实例当前向上行进的方向到我们的`MAXGRAVITY`，即 16 像素。在那一点，实例在地面上，所以我们将垂直速度设为零。

1.  现在我们已经让重力起作用了，但如果我们不限制实例下落的速度，它将会加速得太快。将以下代码添加到脚本的底部：

```js
vspeed = min(vspeed, MAXGRAVITY);
```

在这里，我们将`vspeed`值设置为当前`vspeed`和`MAXGRAVITY`之间的较小值。如果实例移动得太快，这段代码将使其减速到允许的最大速度。现在我们有了一个简单的重力系统，游戏中的所有对象都可以利用它。

## 构建动画系统

我们将创建的下一个系统是动画系统，它将作为状态机实现。状态机将所有对象的条件分解为不同的状态。一个对象在任何时候只能处于一个阶段，因此与之相关的代码可以更有效地被包含和管理。

为了更好地理解这个概念，想想一扇门。一扇门有几种独特的状态。可能首先想到的两种状态是门可以打开或者关闭。还有两种其他状态，即打开和关闭，如下图所示。如果门正在打开，它既不是打开的，也不是关闭的，而是处于一种独特的动作状态。这使得状态机非常适合动画。游戏中几乎每个可交互的对象都可能有一些动画或利用几个不同的图像。

![构建动画系统](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-gmkr/img/4100_05_01.jpg)

由于玩家角色通常是在不同动画方面最强大的对象，我们将首先分解其独特的状态。我们的玩家可以在空中或地面上，所以我们希望确保分开这些控制。我们还希望玩家能够朝多个方向射击并受到伤害。总共我们将有八种不同的状态：

+   空闲

+   空闲向上瞄准

+   空闲向下瞄准

+   奔跑

+   奔跑向上瞄准

+   向下瞄准

+   在空中

+   伤害

让我们首先将这些状态定义为常量：

1.  打开**资源** | **定义常量**编辑器，在**名称**列中写入`IDLE`，**值**为`0`。

1.  点击**添加**或直接按*Enter*添加新行，并写入`IDLEUP`，值为`1`。重复这个过程，为所有状态添加递增的数字，如下截图所示。然后点击**确定**。![构建动画系统](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-gmkr/img/4100_05_02.jpg)

1.  创建一个新的脚本，命名为`scr_Animation_Control`。我们将首先使用`switch`语句来控制各种状态。我们还希望这个脚本是可重用的，所以我们将使用一些通用变量来使代码更通用。让我们首先添加空闲状态的以下代码：

```js
switch (action)
{
    case IDLE :
        sprite_index = myIdle;
        image_speed = 0.1;
    break;
}
```

在这里，我们将使用一个名为`action`的变量来切换状态。如果动作恰好是`IDLE`，那么我们就改变精灵；在这种情况下，我们使用另一个变量`myIdle`，我们将在每个对象中定义它，这将允许我们重用这个脚本。我们还设置了动画速率，这将允许我们对不同的动作有不同的播放速度。

1.  我们需要将所有的情况插入到这个脚本中，并设置改变精灵和设置图像播放速度的类似设置。以下是其他状态的代码：

```js
    case IDLEUP :
        sprite_index = myIdleUp;
        image_speed = 0.1;
    break;
    case IDLEDOWN :
        sprite_index = myIdleDown;
        image_speed = 0.1;
    break;
    case RUN :
        sprite_index = myRun;
        image_speed = 0.5;
    break; 
    case RUNUP :
        sprite_index = myRunUp;
        image_speed = 0.5;
    break; 
    case RUNDOWN :
        sprite_index = myRunDown;
        image_speed = 0.5;
    break; 
    case INAIR :
        sprite_index = myInAir;
        image_speed = 0.5;
    break; 
    case DAMAGE :
        sprite_index = myDamage;
        image_speed = 0.5;
    break; 
```

1.  我们已经拥有了所有需要的状态，但是如何处理玩家面对的方向呢？这是一个平台游戏，所以他们需要向左和向右移动。为此，我们将通过以下代码在 switch 语句结束括号后翻转图像：

```js
image_xscale = facing;
```

我们再次利用一个变量`facing`，使脚本更通用。我们现在已经完成了这个脚本，动画系统已经准备好实施了。

## 创建碰撞预测系统

接下来我们要构建的系统是处理世界碰撞。我们希望摆脱使用 GameMaker: Studio 的碰撞系统，因为它需要两个实例相互交叉。这对于子弹与玩家的碰撞效果很好，但如果玩家需要陷入地面以知道何时停止，这种方法就不太有效。相反，我们希望在实例移动之前预测碰撞是否会发生：

1.  我们将从预测实例左右两侧的墙壁碰撞开始。创建一个新的脚本，`scr_Collision_Forecasting`，并写入以下代码：

```js
if (place_free(x - mySpeed, y))
{
    canGoLeft = true;
} else {
    canGoLeft = false;
    hspeed = 0;
}

if (place_free(x + mySpeed, y))
{
    canGoRight = true;
} else {
    canGoRight = false;
    hspeed = 0;
}
```

我们首先检查实例左侧的区域是否没有可碰撞的对象。我们正在查看的距离由变量`mySpeed`确定，这将允许此检查根据实例可能的移动速度进行调整。如果区域清晰，我们将`canGoLeft`变量设置为`true`，否则该区域被阻塞，我们将停止实例的水平速度。然后我们重复此检查以检查右侧的碰撞。

1.  接下来我们需要检查地面碰撞。在上一段代码之后，我们需要添加：

```js
if (!place_free(x, y+1))
{
    isOnGround = true;
    vspeed = 0;
    action = IDLE;
} else {
    isOnGround = false;
}
```

在这里，我们正在检查实例正下方是否有可碰撞的对象。如果发生碰撞，我们将变量`isOnGround`设置为`true`，以停止垂直速度，然后将实例的状态更改为`IDLE`。像这样更改状态将确保实例从`INAIR`状态中逃脱。

此时，我们已经构建了大部分碰撞检测，但我们还没有涵盖所有边缘情况。我们目前只检查实例的左侧、右侧和下方，而不是对角线。问题在于所有条件可能都成立，但当实例以角度移动时，可能导致实例被卡在可碰撞的对象内。

1.  与其为所有角度构建条件检查，我们将允许碰撞发生，然后将其弹回到正确的位置。在脚本的末尾添加下面的代码：

```js
if (!place_free(x, y)) 
{ 
    x = xprevious;
    y = yprevious;
    move_contact_solid(direction, MAXGRAVITY);
    vspeed = 0;
}
```

在这里，我们正在检查实例当前是否与可碰撞的对象相交。如果是，我们将 X 和 Y 坐标设置为上一步的位置，然后将其捕捉到移动方向的表面并将垂直速度设置为零。这将以一种现实的方式清理边缘情况。整个脚本应该如下所示：

```js
if (place_free(x - mySpeed, y))
{
    canGoLeft = true;
} else {
    canGoLeft = false;
    hspeed = 0;
}

if place_free(x + mySpeed, y)
{
    canGoRight = true;
} else {
    canGoRight = false;
    hspeed = 0;
}

if (!place_free(x, y+1))
{
    isOnGround = true;
    vspeed = 0;
    action = IDLE;
} else {
    isOnGround = false;
}

if (!place_free(x, y)) 
{ 
    x = xprevious;
    y = yprevious;
    move_contact_solid(direction, MAXGRAVITY);
    vspeed = 0;
}
```

## 检查键盘

当我们将系统分解为更可用的脚本时，我们也可以将所有键盘控件放入一个单独的脚本中。这将简化我们将来要创建的代码，并且还可以轻松更改控件或提供替代控件。

创建一个新的脚本，`scr_Keyboard_Input`，并写入以下代码：

```js
keyLeft  = keyboard_check(vk_left);
keyRight  = keyboard_check(vk_right);
keyDown  = keyboard_check(vk_down);
keyUp  = keyboard_check(vk_up);
keyJump = keyboard_check(ord('X'));
keyShoot = keyboard_check(ord('Z'));
```

我们的代码将更容易阅读，例如使用`keyJump`和`keyShoot`等变量来表示控件，而不是实际的键名。为了在键盘上使用字母键，我们需要相关的 ASCII 编号。我们可以使用`ord`函数，而不必查找每个键的编号，它将把字母转换为正确的数字。

### 注意

在使用`ord`函数时，始终使用大写字母，否则可能会得到错误的数字！

我们现在已经拥有了这个游戏所需的所有通用系统。接下来我们将实施它们。

# 构建玩家

我们正在构建的玩家角色是我们迄今为止创建的最复杂的对象。玩家不仅会奔跑和跳跃，控制本身也会因玩家是在地面上还是在空中而略有不同。玩家需要知道他们面向的方向，要播放什么动画，是否可以射击武器以及射击的角度。让我们从导入所有精灵开始构建这个：

1.  创建一个新精灵，`spr_Player_Idle`，并加载`Chapter 5/Sprites/Player_Idle.gif`，勾选**删除背景**。

1.  将**原点**设置为**X**：`32` **Y**：`63`，使其在水平中心和垂直底部休息。

1.  单击**修改蒙版**以打开**蒙版属性**编辑器，并选择**边界框**|**手动**。将值设置为**左**：`16`，**右**：`48`，**上**：`8`，**下**：`63`。

1.  重复此过程，包括以下精灵的相同**原点**和**蒙版属性**：

+   `spr_Player_IdleUp`

+   `spr_Player_IdleDown`

+   `spr_Player_Run`

+   `spr_Player_RunUp`

+   `spr_Player_RunDown`

+   `spr_Player_InAir`

+   `spr_Player_Damage`

1.  创建一个对象，`obj_Player`，并将`spr_Player_Idle`分配为**精灵**。

1.  首先，我们需要初始化玩家角色所需的所有变量，从必要的动画变量开始。创建一个新脚本，`scr_Player_Create`，并使用以下代码：

```js
myIdle = spr_Player_Idle;
myIdleUp = spr_Player_IdleUp;
myIdleDown = spr_Player_IdleDown;
myRun = spr_Player_Run;
myRunUp = spr_Player_RunUp;
myRunDown = spr_Player_RunDown;
myInAir = spr_Player_InAir;
myDamage = spr_Player_Damage;
```

在这里，我们正在确定要用于各种动画状态的精灵。我们在这里使用的变量必须与我们在`scr_Animation_Control`中声明的变量相同，以便使用我们创建的动画系统。

1.  接下来，我们将为碰撞系统添加变量，但在这之前，我们应该添加两个用于面向方向的常量。打开**资源**|**定义常量**，并添加`RIGHT`，值为`1`，和`LEFT`，值为`-1`。这些数字将代表绘制图像的比例，负值将反转精灵。

1.  在`scr_Player_Create`的末尾添加我们需要的其余变量：

```js
mySpeed = 8;
myAim = 0;
facing = RIGHT;
action = IDLE;
isDamaged = false;
canFire = true;
```

这里有玩家速度、玩家瞄准方向、玩家面向方向和玩家状态的变量。我们还添加了玩家是否能受到伤害或无敌，以及是否能射击的变量。现在我们已经初始化了所有变量。

1.  在`obj_Player`中，添加一个**创建**事件并应用`scr_Player_Create`脚本。

1.  我们已经准备好了一个碰撞预测系统，我们只需要适当地使用它。创建一个新脚本，`scr_Player_BeginStep`，并使用它来调用预测脚本和键盘检查：

```js
scr_Collision_Forecasting();
scr_Keyboard_Input();
```

您创建的每个脚本实际上都是一个可执行函数。如您在这里所见，您只需编写脚本的名称并在末尾放置括号，即可运行该代码。我们将经常使用这种方法。

1.  在`obj_Player`中添加一个**步骤**|**开始步骤**事件，并应用`scr_Player_BeginStep`。**开始步骤**事件是每个步骤中要执行的第一个事件。**步骤**事件紧随其后，**结束步骤**是在实例被绘制在屏幕上之前的最后一个事件。这使我们能够更好地控制代码的运行时间。

1.  接下来，我们需要创建控件。正如我们之前提到的，实际上有两个独立的控制系统，一个用于在地面上，一个用于在空中。我们将从后者开始，因为它最简单。创建一个新脚本，命名为`scr_Player_AirControls`，并使用以下代码：

```js
scr_Gravity();

if (keyLeft && canGoLeft) 
{
    if (hspeed > -mySpeed) { hspeed -= 1; }
    facing = LEFT;
    myAim = 180;
}
if (keyRight && canGoRight) 
{
    if (hspeed < mySpeed) { hspeed += 1; }
    facing = RIGHT;
    myAim = 0;
}
```

您应该注意到的第一件事是，我们不再在代码中使用`==`等运算符。这些变量都是布尔变量，因此它们只能是真或假。编写`keyLeft`与编写`keyLeft == true`是相同的，但更有效率。

现在，由于玩家在空中，我们首先要做的是施加重力。接下来是水平移动的控制。我们检查适当的键是否被按下，以及玩家是否能够朝着该方向移动。如果这些条件成立，我们就检查水平速度是否达到了最大速度。如果玩家能够增加速度，我们就稍微增加它。这可以防止玩家在空中太快地改变方向。然后我们设置面向和瞄准方向。

1.  现在我们可以转向更加复杂的地面控制。创建一个新的脚本，命名为`scr_Player_GroundControls`。我们将从编写空闲状态开始：

```js
if (!keyLeft && !keyRight) 
{
    if (hspeed >= 1) { hspeed -= 1; }
    if (hspeed <= -1) { hspeed += 1; }
}
```

我们首先检查左右键是否都没有被按下。如果键没有被按下而玩家正在移动，我们就检查他们的移动方向，然后相应地减少速度。这实际上意味着玩家会滑行停下来。

1.  玩家已经停下来，但还没有进入空闲状态。为了做到这一点，我们需要确定玩家是否正在使用上下键，因为这将影响玩家瞄准的方向。在最后一行代码之后，但在最后一个大括号内立即插入下一个代码：

```js
if (keyUp) 
{ 
    action = IDLEUP; 
    myAim = 45;
} else if (keyDown) {   
    action = IDLEDOWN; 
    myAim = 315;
} else { 
    action = IDLE;
    if (facing == LEFT) { myAim = 180; }
    if (facing == RIGHT) { myAim = 0; }
}
```

我们首先检查上键是否被按下，如果是，我们将动作更改为`IDLEUP`，并将瞄准设置为 45 度，这样玩家就会向上射击。如果不是，我们检查下键，如果合适的话，更改动作和瞄准。最后，如果这两个键都没有被按下，我们就进入标准的`IDLE`状态。不过，对于瞄准，我们需要先看一下玩家面对的方向。从现在开始，玩家将正确地进入空闲状态。

1.  接下来我们可以添加左右控制。在最后一个大括号之后，写下以下代码：

```js
if (keyLeft && canGoLeft)
{
    hspeed = -mySpeed;
    facing = LEFT;
    if (keyUp) 
    { 
        action = RUNUP; 
        myAim = 150; 
    } else if (keyDown) {
        action = RUNDOWN;
        myAim = 205; 
    } else { 
        action = RUN;
        myAim = 180;
    }
}
```

我们检查左键是否被按下，以及玩家是否能够向左移动。如果是，我们就设置水平速度，并将面向方向设置为向左。再次检查当前是否按下了上下键，然后将动作和瞄准设置为适当的值。

1.  使用相应的值重复上一步，为右键添加相同的检查。玩家现在可以向左和向右移动了。

1.  现在我们只需要添加跳跃。在上一个代码之后立即添加：

```js
if (keyJump && isOnGround)
{
    vspeed = -MAXGRAVITY;
    action = INAIR;
}
```

我们检查跳跃键是否被按下，以及玩家是否在地面上。如果是，我们就将垂直速度向上设置为最大重力，并将动作设置为`INAIR`。

1.  地面控制现在已经完成；这就是`scr_Player_GroundControls`应该看起来的样子：

```js
if (!keyLeft && !keyRight)
{
    if (hspeed >= 1) { hspeed -= 1; }
    if (hspeed <= -1) { hspeed += 1; }

    if (keyUp) 
    { 
        action = IDLEUP; 
        myAim = 45;
    } else if (keyDown) {   
        action = IDLEDOWN; 
        myAim = 315;
    } else { 
        action = IDLE;
        if (facing == LEFT) { myAim = 180; }
        if (facing == RIGHT) { myAim = 0; }
    }
}
if (keyLeft && canGoLeft)
{
    hspeed = -mySpeed;
    facing = LEFT;
    if (keyUp) 
    { 
        action = RUNUP; 
        myAim = 150; 
    } else if (keyDown) { 
        action = RUNDOWN; 
        myAim = 205; 
    } else { 
        action = RUN; 
        myAim = 180; 
    }
}
if (keyRight && canGoRight)
{
    hspeed = mySpeed;
    facing = RIGHT;
    if (keyUp) 
    { 
        action = RUNUP; 
        myAim = 30;
    } else if (keyDown) { 
        action = RUNDOWN; 
        myAim = 335;
    } else { 
        action = RUN; 
        myAim = 0;
    }
}
if (keyJump && isOnGround)
{
    vspeed = -MAXGRAVITY;
    action = INAIR;
}
```

1.  让我们继续进行玩家攻击。首先我们需要构建子弹，所以创建一个新的精灵，`spr_Bullet`，并加载`Chapter 5/Sprites/Bullet.gif`，勾选**去除背景**。居中**原点**，然后点击**确定**。

1.  创建一个新的对象，`obj_Bullet`，并将`spr_Bullet`应用为**精灵**。

1.  我们希望子弹始终在所有物体的前面，所以将**深度**设置为`-2000`。

1.  我们现在已经完成了子弹，可以编写攻击代码了。创建一个新的脚本，`scr_Player_Attack`，并写下以下内容：

```js
if (keyShoot && canFire)  
{
    bullet = instance_create(x + (8 * facing), y-32, obj_Bullet) 
    bullet.speed = 16;
    bullet.direction = myAim;
 bullet.image_angle = myAim;
    alarm[0] = 10;
    canFire = false;
}
```

我们首先检查攻击键是否被按下，以及玩家是否被允许射击。如果是，我们就从枪口创建一个子弹实例，并将唯一的 ID 捕获到一个变量中。这个子弹的水平位置使用面向变量来偏移它向左或向右。我们设置子弹的速度，然后设置方向和图像旋转到玩家瞄准的位置。然后我们设置一个警报，用于重置`canFire`变量，我们将其更改为`false`。

1.  此时，我们已经有了几个用于移动、攻击和动画的脚本，但还没有应用它们。为了做到这一点，我们需要另一个脚本，`scr_Player_Step`，调用其他脚本如下：

```js
if (isOnGround)
{
    scr_Player_GroundControls();
} else {
    scr_Player_AirControls();
}
scr_Player_Attack();
scr_Animation_Control();
```

首先，我们通过检查玩家是否在地面上来确定需要使用哪些控制。然后我们运行适当的控制脚本，然后是攻击脚本，最后是动画控制。

1.  在`obj_Player`中，添加一个**Step** | **Step**事件，并应用`scr_Player_Step`。

1.  在测试之前，我们仍然需要重置那个警报。创建一个新脚本，`scr_Player_Alarm0`，并将`canFire`设置为`true`。

```js
canFire = true;
```

1.  添加一个**Alarm** | **Alarm 0**事件，并应用此脚本。

玩家已经准备好测试。为了确保您已经正确设置了玩家，它应该看起来像下面的截图：

![构建玩家](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-gmkr/img/4100_05_03.jpg)

# 设置房间

我们已经有了玩家，现在我们需要一个世界来放置它。由于我们正在制作一个平台游戏，我们将使用两种类型的构建块：地面对象和平台对象。地面将对玩家不可通过，并将用于外围。平台对象将允许玩家跳过并着陆在上面：

1.  创建一个新的精灵，`spr_Ground`，并加载`Chapter 5/Sprites/Ground.gif`，不勾选**Remove Background**。点击**OK**。

1.  创建一个新对象，`obj_Ground`，并将`spr_Ground`分配为**Sprite**。

1.  勾选**Solid**框。这是必要的，因为我们的碰撞代码正在寻找实心物体。

1.  让我们来测试一下。创建一个新房间，在**Settings**选项卡下，将名称更改为`BossArena`，将**Width**更改为`800`。我们希望有一个足够大的房间来进行战斗。

1.  在房间的边界周围添加`obj_Ground`的实例。还在房间的地板附近添加一个`obj_Player`的单个实例。

1.  运行游戏。此时，玩家应该能够在房间内奔跑和跳跃，但不能穿过墙壁或地板。您还应该能够以各种方向射击武器。还要注意，动画系统正在按预期工作，精灵根据玩家的动作而改变。

1.  现在来构建平台。创建一个新的精灵，`spr_Platform`，并加载`Chapter 5/Sprites/Platform.gif`，不勾选**Remove Background**。点击**OK**。

1.  创建一个新对象，`obj_Platform`，并将`spr_Platform`分配为**Sprite**。

1.  我们希望平台只在玩家在其上方时才是实心的。为此，我们需要创建一个新脚本，`scr_Platform_EndStep`，其中包含以下代码：

```js
if (obj_Player.y < y) 
{
    solid = true;
} else {
    solid = false;
}
```

在这里，我们将玩家的 Y 坐标与实例的 Y 坐标进行比较。如果玩家在上面，那么平台应该是实心的。否则它不是实心的，玩家可以跳过它。

1.  在`obj_Platform`中，添加一个**Step** | **End Step**事件，并应用此脚本。我们在步骤结束时运行此代码，因为我们只想在玩家实际移动之后，但在它进行另一个预测之前进行更改。

1.  返回到`BossArena`并添加一些玩家可以跳上的平台。玩家只能跳大约 128 像素，因此确保平台放置得当，如下所示。![设置房间](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-gmkr/img/4100_05_04.jpg)

1.  运行游戏。玩家应该能够跳过平台并站在上面。

我们已经成功为平台游戏开发了一系列系统。这要求我们将动画系统和控制等常见元素分离为独特的脚本。如果我们停在这里，可能会感觉做了很多额外的工作却毫无意义。然而，当我们开始构建 Boss 战时，我们将开始收获这一努力的回报。

# 构建 Boss 战

Boss 战是游戏中最令人愉快的体验之一。构建一个好的 Boss 战总是一个挑战，但其背后的理论却非常简单。遵循的第一条规则是，Boss 应该由三个不断增加难度的独特阶段组成。第二条规则是，Boss 应该强调用户最新掌握的技能。第三条也是最后一条规则是，玩家应该始终有事可做。

我们的 boss 战将不是与另一个角色对抗，而是与一座堡垒对抗。第一阶段将包括三门可伸缩的大炮，它们将在房间各处发射炮弹。必须摧毁所有三门大炮才能进入第二阶段。第二阶段将有一门强大的激光炮，它将上下移动并发射全屋范围的激光束，玩家需要避开。最后一阶段将是摧毁由两个护盾保护的 boss 核心。护盾只会在短时间内打开。在整个 boss 战中，将有一把不可摧毁的枪，它将在房间中的任何位置向玩家射击子弹。随着每个阶段的进行，这把枪将射击得更加频繁，使游戏更具挑战性。让我们开始建立 boss！

## 创建不可摧毁的枪

我们将从不可摧毁的枪开始，因为它将是整个战斗中的主要 boss 攻击。枪需要旋转，以便始终指向玩家。当它射出枪子弹时，枪子弹的实例将从枪的尖端出现，并朝着枪指向的方向移动。

1.  让我们从构建枪子弹开始。创建一个新精灵，`spr_Gun_Bullet`，并加载`Chapter 5/Sprites/Gun_Bullet.gif`，勾选**删除背景**。将**原点**居中，然后点击**确定**。

1.  创建一个新对象，`obj_Gun_Bullet`，并将`spr_Gun_Bullet`分配为**精灵**。

1.  我们希望子弹始终出现在地面和平台的上方。将**深度**设置为-`2000`。

1.  枪子弹将在接触时对玩家造成伤害，所有其他抛射物也是如此。让我们再次建立一个所有武器都可以使用的单一系统。创建一个新脚本，`scr_Damage`，其中包含以下代码：

```js
if (obj_Player.action != DAMAGE)
{
    health -= myDamage;
    with (obj_Player) 
    { 
        y -= 1;
        vspeed = -MAXGRAVITY;
        hspeed = 8 * -facing;
        action = DAMAGE;
        isDamaged = true; 
    }
}
```

这个脚本专门用于敌人的武器。我们首先检查玩家是否已经受伤，以免玩家受到重复惩罚。然后我们通过变量`myDamage`减少全局生命值。通过使用这样的变量，我们可以让不同的武器造成不同数量的伤害。然后我们通过`with`语句直接影响玩家。我们想要将玩家抛入空中，但首先我们需要将玩家提高一像素以确保地面碰撞代码不会将其弹回。接下来我们施加垂直速度和水平速度，以相反的方向推开。我们将玩家的动作设置为`DAMAGE`状态，并指示发生了伤害。

1.  创建另一个新脚本，`scr_Gun_Bullet_Create`，并初始化`myDamage`变量。然后将其应用于`obj_Gun_Bullet`的**创建**事件。

```js
myDamage = 5;
```

1.  接下来让我们创建一个碰撞脚本，`scr_Gun_Bullet_Collision`，它调用伤害脚本并移除子弹。我们没有将实例的销毁放入`scr_Damage`中，这样我们就可以选择无法被摧毁的武器使用这个脚本：

```js
scr_Damage();
instance_destroy();
```

1.  现在我们可以在附有此脚本的`obj_Gun_Bullet`上添加一个**碰撞**|**obj_Player**事件。枪子弹现在已经完成。

1.  现在我们可以移动到枪本身。首先创建两个新的精灵，`spr_Gun_Idle`和`spr_Gun_Run`。加载`Chapter 5/Sprites/Gun_Idle.gif`和`Chapter 5/Sprites/Gun_Run.gif`到它们关联的精灵中，勾选**删除背景**。

1.  枪精灵的枪管朝右，所以我们需要在左侧设置原点，以便正确地进行旋转。在两个精灵上将**原点**设置为**X**:`0`和**Y**:`16`，然后点击**确定**。

1.  创建一个新对象，`obj_Gun`，并将`spr_Gun_Idle`分配为**精灵**。

1.  我们希望确保枪始终在 boss 的视觉上方，所以将**深度**设置为`-1000`。

1.  我们需要在一个新脚本`scr_Gun_Create`中初始化一些变量，然后将其添加到`obj_Gun`作为**创建**事件：

```js
action = IDLE;
facing = RIGHT;
tipOfGun = sprite_width;
canFire = false;
delay = 90;
alarm[0] = delay;

myIdle = spr_Gun_Idle;
myRun = spr_Gun_Run;
```

我们将在这里使用动画系统，因此需要设置所需的动作和面向变量的值。以下四个变量与枪的射击有关。首先是`tipOfGun`，用于确定枪口的位置，`canFire`是触发器，`delay`是射击间隔时间，警报将发射枪子弹。最后，我们有两种动画状态需要应用。除非对象使用该状态，否则我们不需要添加所有其他变量，如`myDamage`。

1.  接下来，我们将让枪跟踪玩家并确定何时射击。创建一个新的脚本，`scr_Gun_Step`，将其放置在**步骤** | **步骤**事件中。以下是我们需要的代码：

```js
scr_Animation_Control();

if (image_index > image_number-1)
{
    action = IDLE;
}

if (canFire) 
{
    action = RUN;
    alarm[1] = 5;
    canFire = false;
}

image_angle = point_direction(x, y, obj_Player.x, obj_Player.y);
```

我们首先运行动画脚本。我们希望枪只播放一次射击动画，因此我们将当前显示的图像与精灵的最后一个图像进行比较。使用`image_number`可以得到帧数，但由于动画帧从零开始，我们需要减去一。如果是最后一帧，那么枪就进入“空闲”状态。接下来，我们检查枪是否要射击。如果是，我们改变状态以播放射击动画，设置第二个警报为 5 帧，然后关闭`canFire`。最后，我们通过根据枪和玩家之间的角度旋转精灵来跟踪玩家。

1.  我们在这个对象上使用了两个警报。第一个警报开始射击动画，第二个创建枪子弹。让我们从第一个警报开始，创建一个新的脚本，`scr_Gun_Alarm0`，用于**警报** | **警报 0**事件：

```js
canFire = true;
```

1.  第二个警报包含了开枪的代码。创建一个新的脚本，`scr_Gun_Alarm1`，将其添加为**警报** | **警报 1**事件：

```js
myX = x + lengthdir_x(tipOfGun, image_angle);
myY = y + lengthdir_y(tipOfGun, image_angle); 
bullet = instance_create(myX, myY, obj_Gun_Bullet);
bullet.speed = 16;
bullet.direction = image_angle;
alarm[0] = delay;
```

由于我们需要子弹离开枪口，我们需要一些三角函数。我们可以使用正弦和余弦来计算 X 和 Y 值，但有一个更简单的方法。在这里，我们使用`lengthdir_x`和`lengthdir_y`来为我们进行数学计算。它所需要的只是径向距离和角度，然后我们可以将其添加到枪的本地坐标中。一旦我们有了这些变量，我们就可以在正确的位置创建子弹，设置其速度和方向。最后，我们重置第一个警报，以便枪再次开火。

1.  我们准备测试枪。打开 BossArena 并在房间的最右侧放置一把枪的实例。一旦测试完成，我们将从房间中移除枪，因此此时确切的放置位置并不重要。![创建不可摧毁的枪](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-gmkr/img/4100_05_05.jpg)

1.  运行游戏。枪应该会跟随玩家在房间中的任何位置，并且每三秒发射一次枪子弹。如果玩家被枪子弹击中，他们将被击飞并受到伤害动画的影响，就像在之前的截图中看到的那样。

1.  然而，玩家的伤害状态存在一个问题；玩家仍然可以移动和射击。这对于被射击并不是多大的威慑力，因此让我们解决这个问题。创建一个新的脚本，`scr_Player_Damage`，其中包含以下代码：

```js
if (isOnGround)
{
    isDamaged = false;
} else {
    scr_Gravity();
}
```

我们检查玩家是否在地面上，因为这将停用伤害状态。如果玩家在空中，我们施加重力，就这样。

1.  现在我们需要调用这个脚本。重新打开`scr_Player_Step`，并添加一个条件语句，用于判断玩家是否受伤。以下是包含新代码的整个脚本，新代码用粗体标出：

```js
if (isDamaged)
{
 scr_Player_Damage();
} else {
    if (isOnGround)
    {
        scr_Player_GroundControls();
    } else {
        scr_Player_AirControls();
    }
    scr_Player_Attack(); 
}
scr_Animation_Control();
```

我们检查玩家是否处于伤害模式，如果是，我们运行伤害脚本。否则，我们像平常一样使用所有控制系统在`else`语句中。无论是否受伤，动画脚本都会被调用。

1.  运行游戏。现在当玩家被击中时，冲击效果非常明显。

## 构建第一阶段：大炮

第一阶段的武器是一个大炮，它会隐藏自己以保护自己，只有在射击时才会暴露出来。我们将有三门大炮堆叠在一起，使玩家必须跳上平台。要摧毁大炮，玩家需要在大炮暴露时射击每门大炮：

1.  从 Cannonball 开始，创建一个新的精灵`spr_Cannonball`，并加载`Chapter 5/Sprites/Cannonball.gif`，勾选**Remove Background**。

1.  将**Origin**设置为**X**:`12`，**Y**:`32`，然后点击**OK**。

1.  创建一个新的对象`obj_Cannonball`，并将`spr_Cannonball`分配为**Sprite**。

1.  将**Depth**设置为`-900`，这样它将出现在大多数对象的前面。

1.  为了使用伤害系统，我们需要在**Create**事件中设置正确的变量，使用一个新的脚本`scr_Cannonball_Create`：

```js
myDamage = 10;
hspeed = -24;
```

这个武器很强大，会造成 10 点伤害。我们还设置了水平速度，以便它可以快速穿过房间。

1.  如果 Cannonball 接触到玩家，我们不会摧毁它，所以我们只需要在**Collision** | **obj_Player**事件中应用`scr_Damage`。Cannonball 现在已经准备好被射击。

1.  大炮将需要五个精灵，`spr_Cannon_IdleDown`，`spr_Cannon_IdleUp`，`spr_Cannon_RunDown`，`spr_Cannon_RunUp`和`spr_Cannon_Damage`。从`Chapter 5/Sprites/`文件夹加载相关文件，不勾选**Remove Background**。

1.  创建一个新的对象`obj_Cannon`，并将`spr_Cannon_IdleDown`分配为**Sprite**。

1.  将**Depth**设置为`-1000`，这样大炮将位于其他 Boss 部件的前面。

1.  像往常一样，让我们创建一个新的脚本`scr_Cannon_Create`，在**Create**事件中初始化所有变量。

```js
myHealth = 20;
action = IDLEDOWN;
facing = RIGHT;
canFire = false;

myIdleUp = spr_Cannon_IdleUp;
myIdleDown = spr_Cannon_IdleDown;
myRunUp = spr_Cannon_RunUp;
myRunDown = spr_Cannon_RunDown;
myDamage = spr_Cannon_Damage;
```

大炮在被摧毁之前需要承受多次打击，所以我们有一个`myHealth`变量来跟踪伤害。然后通过面向右侧来设置动作状态，因为我们不会翻转精灵，并建立一个射击变量。然后我们有了大炮工作所需的所有动画状态。

1.  接下来我们可以创建一个新的脚本`scr_Cannon_Step`，在**Step** | **Step**事件中实现切换状态和发射 Cannonballs 的功能：

```js
scr_Animation_Control();

if (image_index > image_number-1)
{
    if (action == RUNUP) { action = IDLEUP;}
    else if (action == RUNDOWN) { action = IDLEDOWN;} 
}

if (canFire) 
{
    action = RUNUP;
    alarm[0] = 60;
    canFire = false;
}

if (myHealth <= 0)
{
    instance_destroy();
}
```

与枪类似，我们首先调用动画系统脚本。然后检查大炮是否在动画的最后一帧。这里有两种不同的空闲状态，取决于大炮是否暴露出来。我们检查我们处于哪种状态，并设置适当的空闲状态。接下来，我们检查大炮是否应该射击，如果应该，我们就会暴露大炮，并设置一个警报，在两秒后创建 Cannonball。最后，我们进行健康检查，如果大炮没有生命力了，它就会从游戏中移除。

1.  创建一个新的脚本`scr_Cannon_Alarm0`，并将其添加到**Alarm** | **Alarm 0**事件中，使用以下代码：

```js
instance_create(x, y, obj_Cannonball);
action = RUNDOWN;
```

在这里我们只是创建一个 Cannonball，然后设置动画以收回大炮。

1.  大炮的最后一件事是承受伤害。创建一个新的脚本`scr_Cannon_Collision`，并将其应用到**Collision** | **obj_Bullet**事件中，使用以下代码：

```js
if (action == IDLEUP)
{
    myHealth -= 10;
    action = DAMAGE;
    with (other) {instance_destroy();}
}
```

我们首先确保只有在大炮暴露时才会应用伤害。如果是的话，我们就会减少它的 10 点生命值，切换到伤害动画，并移除子弹。大炮现在已经完成。

1.  在我们尝试测试大炮之前，我们将开始构建 Boss。大炮不能自行运行，而是由 Boss 控制。创建一个名为`obj_Boss`的新对象。没有精灵可分配，因为 Boss 由其他对象组成。

1.  创建一个新的脚本`scr_Boss_Create`，在**Create**事件中初始化变量：

```js
isPhase_01 = true;
isPhase_02 = false;
isPhase_03 = false;
isBossDefeated = false;

boss_X = 672;
gun = instance_create(32, 32, obj_Gun);
cannonA = instance_create(boss_X, 64, obj_Cannon);
cannonB = instance_create(boss_X, 192, obj_Cannon);
cannonC = instance_create(boss_X, 320, obj_Cannon); 
```

我们首先建立了三个阶段和 Boss 是否被击败的变量。然后创建了一个 Boss 的 X 位置变量，其中包括不可摧毁的位于房间左上角的枪和 Boss 所在位置的一堆大炮。我们为 Boss 的每个武器建立变量，以便 Boss 可以控制它们。

1.  我们希望大炮按顺序射击，而不是一起射击。为此，我们将使用时间轴。创建一个新的时间轴并命名为`tm_Boss_Phase01`。

1.  添加一个**时刻**，并将**指示时刻**设置为`180`。这将在战斗开始后的六秒钟内开始。

1.  创建一个新的脚本，`scr_Phase01_180`，并发射中间的大炮。将此脚本应用于时间轴：

```js
if (instance_exists(cannonB)) { cannonB.canFire = true;}
```

由于玩家可以摧毁大炮，我们需要检查大炮是否仍然存在。如果是，我们将大炮的`canFire`变量设置为 true，大炮的代码将处理其余部分。

1.  在`360`处添加另一个**时刻**。

1.  创建一个脚本，`scr_Phase01_360`，并激活另外两门大炮：

```js
if (instance_exists(cannonA)) { cannonA.canFire = true; }
if (instance_exists(cannonC)) { cannonC.canFire = true; }
```

我们需要分别检查两门大炮，以便如果其中一门被摧毁，另一门仍然会射击。

1.  重新打开`scr_Boss_Create`，并在代码的最后开始一个循环时间轴：

```js
timeline_index = tm_Boss_Phase01;
timeline_running = true;
timeline_loop = true;
```

1.  重新打开`BossArena`，确保如果房间内仍有枪的实例，则将其移除。

1.  在地图的右侧放置一个`obj_Boss`的实例，实际位置并不重要。

1.  Boss 的任何部分都没有**固体**属性，这意味着玩家可以穿过它们。为了解决这个问题，在 Boss 的前面创建一个障碍墙，使用`obj_Ground`的实例，如下截图所示：![构建第一阶段：大炮](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-gmkr/img/4100_05_06.jpg)

1.  运行游戏。在开始时，我们应该看到三门大炮堆叠在一起，还有一个不可摧毁的枪。枪应该瞄准玩家，并每隔几秒钟射出一颗子弹。游戏进行到第六秒时，我们应该看到中间的大炮开始充能，并很快射出一颗炮弹。再过六秒，上下两门大炮也应该做同样的动作。如果玩家被敌人的抛射物击中，他们会被击退。玩家的子弹会从大炮旁边飞过，除非它们被暴露，此时大炮将进入受损状态，子弹会消失。如果任何一门大炮被击中两次，它将消失。第一阶段现在已经完成，应该看起来像下面的截图：![构建第一阶段：大炮](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-gmkr/img/4100_05_07.jpg)

## 构建第二阶段：巨大的激光炮

一旦玩家摧毁了所有的大炮，第二阶段就会开始。在这里，我们将有一个巨大的激光炮，不断上下移动。每隔几秒钟，它将发射一道横跨整个房间的巨大激光束。玩家可以随时对激光炮造成伤害，尽管它的生命值要多得多：

1.  首先我们将创建激光束。创建一个新的精灵，`spr_LaserBeam`，并加载`Chapter 5/Sprites/LaserBeam.gif`，不勾选**移除背景**。精灵可能看起来很小，只有八个像素宽，但我们将把这个精灵拉伸到整个屏幕，这样它可以在任何房间中使用。

1.  我们需要将原点放在右侧，以便与激光炮的枪管正确对齐。将**原点**设置为**X**：`8`，**Y**：`32`。

1.  创建一个新的对象，`obj_LaserBeam`，应用`spr_LaserBeam`作为**精灵**，并将**深度**设置为`-600`。

1.  创建一个新的脚本，`scr_LaserBeam_Create`，在**创建**事件中初始化变量：

```js
myDamage = 20;
myLaserCannon = 0; 
image_xscale = room_width / 8;
```

这个武器的伤害量比其他武器高得多，这非常适合第二阶段。我们还有一个`myLaserCannon`变量，将用于使激光束与移动的激光炮保持对齐。该值已设置为零，尽管这将成为生成它的激光炮的 ID，我们稍后会讨论。最后，我们将精灵拉伸到整个房间。变量`image_xscale`是一个乘数，这就是为什么我们要将房间宽度除以八，即精灵的宽度。

1.  接下来，我们将使用一个**步骤** | **结束步骤**事件，使用一个新的脚本`scr_LaserBeam_EndStep`，使激光炮的激光束移动。

```js
x = myLaserCannon.x;
y = myLaserCannon.y;
```

我们使用创建激光束的激光炮的 X 和 Y 坐标。我们将其放入**End Step**事件中，因为激光炮将在**Step**事件中移动，这将确保它始终处于正确的位置。

1.  现在只剩下将`scr_Damage`添加到**Collision** | **obj_Player**事件中。激光束现在已经完成。

1.  接下来是激光炮，我们需要创建三个精灵：`spr_LaserCannon_Idle`，`spr_LaserCannon_Run`和`spr_LaserCannon_Damage`。从`Chapter 5/Sprites/`文件夹中加载相关文件，所有文件都需要勾选**Remove Background**。

1.  将所有三个精灵的**Origin**设置为**X**：`16`和**Y**：`56`。这将有助于将激光束放置在我们想要的位置。

1.  创建一个新对象，`obj_LaserCannon`，并将`spr_LaserCannon _Idle`分配为**Sprite**。

1.  将**Depth**设置为`-700`，以便激光炮位于炮台和枪的后面，但在激光束的前面。

1.  在**Create**事件中初始化变量，创建一个新脚本，`scr_Laser_Create`，代码如下：

```js
myHealth = 50;
mySpeed = 2;
myBuffer = 64;
action = IDLE;
facing = RIGHT;
canFire = false;

myIdle = spr_LaserCannon _Idle;
myRun = spr_LaserCannon _Run;
myDamage = spr_LaserCannon _Damage;
```

我们首先设置激光炮的健康、当前状态、面向方向和非射击的所有标准变量。然后设置激光炮的三种状态的所有动画系统变量。

1.  接下来是构建激光的功能。创建一个新脚本，`scr_LaserCannon_Step`，并将其添加到**Step** | **Step**事件中，代码如下：

```js
scr_Animation_Control();

if (image_index > image_number-1)
{
    action = IDLE;
}

if (canFire) 
{
    action = RUN;
    alarm[0] = 5;
    canFire = false;
}

if (myHealth <= 0)
{
    instance_destroy();
}
```

这应该开始看起来相当熟悉了。我们首先运行动画系统脚本。然后检查动画的最后一帧是否已播放，如果是，则将激光炮设置为待机状态。接下来，如果激光炮要射击，我们改变状态并设置一个短暂的警报，以便在射击动画播放后创建激光束。最后，我们进行健康检查，并在健康状况不佳时移除激光炮。

这个脚本还没有完成。我们仍然需要添加移动。当激光炮首次创建时，它不会移动。我们希望它在第二阶段开始后才开始移动。在那之后，我们希望激光炮负责垂直运动。

1.  为了让激光炮上下移动，我们只需要在它通过终点时发送相反方向的指令。在`scr_LaserCannon_Step`的最后一行代码之后立即添加以下代码：

```js
if (y < myBuffer)
{
    vspeed = mySpeed;
}
if (y > room_height - myBuffer)
{
    vspeed = -mySpeed;
} 
```

1.  我们将让激光炮在整个房间的高度上移动。如果 Y 坐标距离顶部小于 64 像素，我们将其向下移动。如果距离房间底部大于 64 像素，我们将其向上移动。我们将在 Boss 脚本中开始移动。

1.  让激光炮射出激光束！激光束将在**Alarm** | **Alarm 0**事件中创建，附加一个新脚本`scr_LaserCannon_Alarm0`，其中包含激光束创建的代码：

```js
beam = instance_create(x, y, obj_LaserBeam);
beam.myLaserCannon = self.id;
```

我们在激光炮的尖端创建一个激光束的实例，然后将激光束的`myLaserCannon`变量设置为创建它的激光炮的唯一 ID。这样做的好处是，如果需要，我们可以在房间中放置多个激光炮。

1.  我们需要构建的最后一个元素是伤害状态。创建一个新脚本，`scr_LaserCannon_Collision`，并将其放入**Collision** | **obj_Bullet**事件中：

```js
if (obj_Boss.isPhase_02)
{
    myHealth -= 5;
    action = DAMAGE;
    with (other) { instance_destroy(); }
}
```

由于我们不希望玩家在第二阶段之前就能摧毁激光炮，因此我们检查 Boss 当前所处的阶段，以确定是否应该施加伤害。如果 Boss 处于第二阶段，我们会减少激光炮的生命值，将其改为受损状态并移除子弹。激光炮现在已经完整，并准备好实现到 Boss 中。

1.  我们需要做的第一件事是添加一个激光炮的实例。重新打开`scr_Boss_Create`，并在运行时间轴之前插入以下代码：

```js
laser = instance_create(boss_X, 352, obj_LaserCannon);
```

1.  接下来，我们将通过创建一个新的时间轴并命名为`tm_Boss_Phase02`来构建 LaserCannon 的功能。

1.  要发射激光束，添加一个**时刻**并将**指示时刻**设置为`210`。

1.  创建一个新的脚本，`scr_Phase02_210`，并将其与激活 LaserCannon 的代码分配：

```js
laser.canFire = true;
```

1.  我们希望完全控制 LaserCannon 的持续时间，因此我们将使用时间轴来移除激光束。在`270`处添加一个**时刻**。这将给我们一个持续两秒的激光束。

1.  创建一个新的脚本，`scr_Phase02_270`，并移除激光束。

```js
with (laser.beam) { instance_destroy(); }
```

当 LaserCannon 射击时，它会创建`beam`变量，现在我们可以使用它来移除它。

1.  唯一剩下的就是让 Boss 从第一阶段变为第二阶段。为此，我们需要在`obj_Boss`上添加一个**步骤**|**步骤**事件，分配一个新的脚本`scr_Boss_Step`，其中包含以下代码：

```js
if (!instance_exists(obj_Cannon) && !isPhase_02)
{
    laser.vspeed = laser.mySpeed;
    timeline_index = tm_Boss_Phase02;
    timeline_position = 0;
    gun.delay = 45;
    isPhase_02 = true;
}
```

我们首先检查世界中是否还有 Cannon 的实例，如果它们都被摧毁了，我们检查第二阶段是否已经开始。第二阶段开始时，我们将 LaserCannon 向下移动，并切换时间轴到新阶段，并将时间轴重置到开始。我们还将通过减少 Gun 射击之间的延迟来增加挑战的难度。最后，我们将`isPhase_02`更改为 true，以便这个代码只执行一次。

1.  运行游戏。游戏玩法开始与以前相同，但在三个 Cannon 被摧毁后，我们应该看到 LaserCannon 开始上下移动，并且每七秒发射一次激光束。LaserCannon 可以在任何时候被击中，并且需要多次击中才能被摧毁。无法摧毁的 Gun 应该仍然像以前一样运行，但是射击频率增加了一倍。第二阶段现在已经完成，并且应该看起来像以下截图：![构建第二阶段：巨型 LaserCannon](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-gmkr/img/4100_05_08.jpg)

## 设置最终阶段：有护盾的 Boss Core

对于最后阶段，我们不会添加另一种武器，而是创建一个受到两个护盾保护的可摧毁的 Boss Core。护盾将每隔几秒打开一次，以暴露 Boss Core。我们还将改变 Gun，使其快速连发：

1.  我们将从 Boss Core 开始。我们需要创建两个新的精灵，`spr_BossCore_Idle`和`spr_BossCore_Damage`。勾选**移除背景**，加载`Chapter 5/Sprites/BossCore_Idle.gif`和`Chapter 5/Sprites/BossCore_Damage.gif`到相应的精灵上。

1.  将两个精灵的**原点**设置为**X**：`-32`和**Y**：`64`，这样它们将正确地位于护盾后面。

1.  创建一个新的对象，`obj_BossCore`，并将`spr_BossCore_Idle`分配为**精灵**。

1.  Boss Core 是一个简单的对象，只需要一些动画状态和生命值。创建一个新的脚本，`scr_BossCore_Create`，并初始化所需的变量如下。记得将其分配给**创建**事件：

```js
myHealth = 100;
action = IDLE;
facing = RIGHT;

myIdle = spr_BossCore_Idle;
myDamage = spr_BossCore_Damage;
```

1.  我们需要一个**步骤**|**步骤**事件来控制动画状态和处理生命值，因此创建另一个新脚本，`scr_BossCore_Step`，其中包含以下代码：

```js
scr_Animation_Control();

if (action == DAMAGE) 
{
    if (image_index > image_number-1)
    {
        action = IDLE;
    }
}

if (myHealth <= 0)
{
    instance_destroy();
}
```

1.  Boss Core 现在所需要的就是一个**碰撞**|**obj_Bullet**事件来处理伤害。创建一个新的脚本，`scr_BossCore_Collision`，并编写以下代码：

```js
if (obj_Boss.isPhase_03 && action == IDLE)
{
    myHealth -= 2;
    action = DAMAGE;
    with (other) { instance_destroy(); }
}
```

我们首先检查 Boss 是否处于最终阶段，并且 Boss Core 处于空闲状态。如果是，我们减少生命值并切换到受损动画。我们还确保子弹被移除。Boss Core 现在已经完成，我们可以转移到护盾。

1.  我们将有两个护盾，一个是上升的，另一个是下降的。让我们引入我们需要的两个精灵。创建两个新的精灵，`spr_Shield_Upper`和`spr_Shield_Lower`。加载`Chapter 5/Sprites/Shield_Upper.gif`和`Chapter 5/Sprites/Shield_Lower.gif`到相应的精灵上。记得勾选**移除背景**。

1.  将`spr_Shield_Upper`的**Origin**设置为**X**：`0`和**Y**：`269`，以便原点位于图像底部。我们不需要更改`spr_Shield_Lower`的**Origin**。

1.  创建两个新对象，`obj_Shield_Upper`和`obj_Shield_Lower`，并分配适当的精灵。

1.  在两个护盾上，将**深度**设置为`-500`，这样它们就在 Boss 核心的前面，但在 Boss 的所有其他部分的后面。

1.  我们将首先建造上层护盾，并且我们需要在一个新的脚本`scr_ShieldUpper_Create`中初始化一些变量，应用于`obj_Shield_Upper`的**Create**事件：

```js
isShielding = true;
openPosition = y-64;
mySpeed = 2;
```

第一个变量将激活护盾是上升还是下降。第二个变量设置抬起护盾的高度值；在这种情况下，它将上升 64 像素。最后，我们设置一个移动速度的变量。

1.  下层护盾几乎完全相同，只是移动方向相反。再次创建一个新脚本`scr_ShieldLower_Create`，并将其应用于`obj_Shield_Lower`的**Create**事件：

```js
isShielding = true;
openPosition = y+64;
mySpeed = 2;
```

1.  接下来，我们将在`obj_Shield_Upper`上添加一个**Step** | **Step**事件，附加一个新脚本`scr_ShieldUpper_Step`，其中包含以下代码来控制护盾的移动：

```js
if (isShielding && y < ystart) { y += mySpeed; }
if (!isShielding && y > openPosition) { y -= mySpeed; } 
```

我们首先检查护盾是否应该关闭，以及它是否完全关闭。如果没有完全关闭，我们将护盾稍微关闭一点。第二个`if`语句则相反，检查护盾是否应该打开，以及它是否完全打开。如果没有，我们将抬起护盾一点。

1.  下层护盾几乎完全相同。在`obj_Shield_Lower`的**Step** | **Step**事件中再次创建一个新脚本`scr_ShieldLower_Step`，附加以下代码：

```js
if (isShielding && y > ystart) { y -= 2; }
if (!isShielding && y < openPosition) { y += 2; }
```

1.  我们需要处理的最后一个元素是**Collision** | **obj_Bullet**事件，两个护盾都可以使用。创建一个新脚本`scr_Shield_Collision`，其中包含以下代码：

```js
if (obj_Boss.isPhase_03)
{
    with (other) { instance_destroy(); }
}
```

护盾永远不会受到伤害，但它们只应在最后阶段检测碰撞。

1.  现在所有对象都已准备就绪，是时候将它们实现到 Boss 中了。重新打开`scr_Boss_Create`，并在最后一个武器后插入以下代码：

```js
core = instance_create(boss_X, 272, obj_BossCore);
shieldUpper = instance_create(boss_X, 272, obj_Shield_Upper);
shieldLower = instance_create(boss_X, 272, obj_Shield_Lower);
```

我们在同一位置创建 Boss 核心和护盾。

1.  接下来，我们将创建一个时间轴`tm_Boss_Phase03`来处理护盾和枪的功能。

1.  在`120`处添加一个**Moment**，然后创建一个新脚本`scr_Phase03_120`，其中包含以下代码：

```js
shieldUpper.isShielding = false;
shieldLower.isShielding = false; 
gun.delay = 10;
```

在这里，我们正在设置护盾打开，并增加枪的射击速率。

1.  在`180`处添加一个**Moment**，并创建一个新脚本`scr_Phase03_180`。我们要做的就是关闭枪的警报，以便射击有一个短暂的休息。这是通过将延迟设置为-1 来实现的。

```js
gun.delay = -1;
```

1.  在`300`处添加另一个**Moment**，并创建一个新脚本`scr_Phase03_300`。现在我们重新激活枪的警报。

```js
gun.delay = 10;
```

1.  最后，我们在`360`处添加一个**Moment**，使用另一个新脚本`scr_Phase03_360`，在那里我们降低护盾并将枪的射击速率恢复正常：

```js
shieldUpper.isShielding = true;
shieldLower.isShielding = true; 
gun.delay = 45;
```

1.  现在我们需要添加从第二阶段到最后阶段的切换。重新打开`scr_Boss_Step`，并在末尾添加以下代码：

```js
if (!instance_exists(obj_LaserCannon) && !isPhase_03)
{
    timeline_index = tm_Boss_Phase03;
    timeline_position = 0;
    isPhase_03 = true;
}
```

我们检查激光炮是否被摧毁，以及我们是否应该处于最后阶段。如果是，我们需要做的就是切换`timeline`，将其设置为开始，并设置为最后阶段。

1.  现在我们只需要一个胜利条件，我们将把它添加到同一个脚本中。在`scr_Boss_Step`的末尾写上最后的条件语句：

```js
if (!instance_exists(obj_BossCore) && !isBossDefeated)
{
    timeline_running = false;
    with (gun) { instance_destroy(); }
    isBossDefeated = true;
}
```

我们检查 Boss 核心是否被摧毁，以及是否已调用胜利条件。如果 Boss 被打败，我们停止时间轴并宣布失败。

1.  运行游戏。这会花费一些时间，但前两个阶段应该与以前一样，一旦激光炮被摧毁，最后一个阶段就会激活。护盾应该会打开，枪会射出一连串的子弹。然后应该会有一个安静的时刻，玩家可以攻击 Boss 核心。几秒钟后，枪应该开始射击，护盾会关闭。这将重复，直到玩家击败 Boss。这个阶段应该看起来像下面的截图：![设置最终阶段：有护盾的 Boss 核心](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-gmkr/img/4100_05_09.jpg)

# 结束

我们正在结束这一章，还有一些未完成的元素，但你已经有能力自己完成。仍然有所有的声音、背景艺术和前端要构建。不仅如此，你可能已经注意到玩家无法被杀死。让玩家无敌使我们更容易测试 Boss 战斗，所以在添加后再试一次战斗。Boss 战斗非常困难，但也很容易改变。为什么不尝试改变每个阶段的时间或尝试调整伤害的值。为了更进一步，你可以构建导致战斗的关卡和敌人。玩得开心，它可能看起来像下面的截图！

![结束](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-gmkr/img/4100_05_10.jpg)

# 总结

恭喜，你刚刚建立了一场史诗般的 Boss 战！我们从探讨系统设计和创建一些非常有用的脚本开始这一章。我们建立了一个动画系统，游戏中的大多数对象都使用了它。我们学会了预测碰撞并在玩家身上应用我们自己的自定义重力。我们甚至创建了玩家可以跳跃和着陆的平台。我们介绍了常量，这使得代码对我们来说更容易阅读，对计算机更有效。然后，我们继续构建了一个利用我们之前的知识和新系统的三阶段 Boss 战斗。

在下一章中，我们将开始创建一个基于物理的游戏，利用 GameMaker: Studio 的 Box2D 实现。这将使用完全不同的碰撞检测和物理系统的方法。这也将允许我们拥有对世界做出反应的对象，几乎不需要编写代码！
